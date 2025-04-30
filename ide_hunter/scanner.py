"""
Core scanner class for IDE Extension Hunter
"""

import os
import logging
import asyncio
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple, Any
from concurrent.futures import ThreadPoolExecutor

from ide_hunter.models import Severity, SecurityIssue, ExtensionMetadata
from ide_hunter.analyzers.yara_analyzer import YaraAnalyzer
from ide_hunter.analyzers.pattern_analyzer import PatternAnalyzer
from ide_hunter.analyzers.manifest_analyzer import ManifestAnalyzer
from ide_hunter.analyzers.metadata_analyzer import MetadataAnalyzer
from ide_hunter.reporters.url_reporter import URLReporter
from ide_hunter.utils.file_utils import (
    get_default_extension_paths,
    is_high_risk_file,
    should_ignore_directory,
)
from ide_hunter.utils.hash_utils import compute_sha1_async
from ide_hunter.utils.progress import ScanProgress
from ide_hunter.utils.output import OutputFormatter


class IDEextensionsscanner:
    """Enhanced scanner for IDE extensions with optimized design."""

    def __init__(
        self,
        ide: str = None,
        extensions_path: Optional[str] = None,
        use_yara: bool = False,
        high_risk_patterns: Optional[Dict] = None,
        malicious_patterns: Optional[Dict] = None,
        ignore_dirs: Optional[Set[str]] = None,
        max_workers: int = 4,
    ):
        """
        Initialize the scanner with configurable components.

        Args:
            ide: IDE type ('vscode', 'pycharm', or None for both)
            extensions_path: Custom extension directory path
            use_yara: Flag to enable YARA scanning
            high_risk_patterns: Custom high-risk file patterns
            malicious_patterns: Custom malicious code patterns
            ignore_dirs: Custom directories to ignore
            max_workers: Maximum number of parallel workers
        """
        self.ide = ide.lower() if ide else "both"
        if self.ide not in ["vscode", "pycharm", "both"]:
            raise ValueError("Invalid IDE type! Use 'vscode', 'pycharm', or 'both'.")

        # Set up paths
        if extensions_path:
            self.extensions_paths = [Path(os.path.expanduser(extensions_path))]
        else:
            self.extensions_paths = get_default_extension_paths(self.ide)

        # Set up analyzers
        self.yara_analyzer = YaraAnalyzer() if use_yara else None
        self.pattern_analyzer = PatternAnalyzer(malicious_patterns)
        self.manifest_analyzer = ManifestAnalyzer()
        self.metadata_analyzer = MetadataAnalyzer()
        self.url_reporter = URLReporter()

        # Set up tracking
        self.scanned_files = set()
        self.high_risk_patterns = high_risk_patterns
        self.ignore_dirs = ignore_dirs
        self.max_workers = max_workers
        self.progress = None

        # Set up logging
        self.logger = logging.getLogger(__name__)
        self.logger.debug(f"Scanning extension directories: {self.extensions_paths}")

    async def scan_all_extensions(self) -> List[ExtensionMetadata]:
        """Scan all extensions in the specified directories."""
        # Check if any extension directories exist
        if not self.extensions_paths:
            print("No extension directories found.")
            return []

        # Check if any extensions exist in the directories
        has_extensions = False
        for path in self.extensions_paths:
            try:
                if any(ext_path.is_dir() for ext_path in path.iterdir()):
                    has_extensions = True
                    break
            except (FileNotFoundError, PermissionError) as e:
                self.logger.error(f"Error accessing directory {path}: {e}")

        if not has_extensions:
            print("Extension folder empty.")
            return []

        # Count total extensions and files for progress tracking
        total_extensions = 0
        total_files = 0
        for path in self.extensions_paths:
            try:
                for extension in os.listdir(path):
                    ext_path = path / extension
                    if ext_path.is_dir():
                        total_extensions += 1
                        # Estimate total files (will be updated during scan)
                        total_files += sum(1 for _ in ext_path.rglob("*") if _.is_file())
            except (FileNotFoundError, PermissionError) as e:
                self.logger.error(f"Error accessing directory {path}: {e}")

        # Initialize progress tracking
        self.progress = ScanProgress(total_extensions, total_files)
        
        # Create thread pool for parallel processing
        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            tasks = []
            for path in self.extensions_paths:
                try:
                    for extension in os.listdir(path):
                        ext_path = path / extension
                        if ext_path.is_dir():
                            tasks.append(self.scan_extension(ext_path))
                except (FileNotFoundError, PermissionError) as e:
                    self.logger.error(f"Error accessing directory {path}: {e}")

            # Wait for all extension scans to complete
            results = await asyncio.gather(*tasks, return_exceptions=True)

        # Filter out exceptions
        valid_results = [r for r in results if not isinstance(r, Exception)]
        exceptions = [r for r in results if isinstance(r, Exception)]

        for exc in exceptions:
            self.logger.error(f"Error during scanning: {exc}")

        # Close progress bars
        self.progress.close()

        # Print summary
        total_issues = sum(len(ext.security_issues) for ext in valid_results)
        print(OutputFormatter.format_scan_summary(
            total_extensions,
            total_files,
            self.progress.elapsed_time,
            total_issues
        ))

        return valid_results

    async def scan_extension(self, extension_path: Path) -> ExtensionMetadata:
        """Scan a single extension for security issues."""
        self.logger.debug(f"Scanning extension: {extension_path.name}")

        # Initialize extension metadata with basic info
        metadata = ExtensionMetadata(name=extension_path.name)

        # Extract metadata first
        await self.metadata_analyzer.extract_metadata(extension_path, metadata)

        # Find high-risk files
        files_to_scan = await self._find_high_risk_files(extension_path)

        # Skip if no files to scan
        if not files_to_scan:
            self.logger.warning(f"No high-risk files found in {extension_path}")
            self.progress.update_extension()
            return metadata

        # Scan files in parallel batches
        batch_size = min(10, len(files_to_scan))  # Adjust batch size based on total files
        for i in range(0, len(files_to_scan), batch_size):
            batch = files_to_scan[i : i + batch_size]
            scan_tasks = [self._scan_file(file_path, metadata) for file_path in batch]
            await asyncio.gather(*scan_tasks)
            self.progress.update_file(len(batch))

        # Update progress
        self.progress.update_extension()

        # Log summary
        self.logger.info(
            f"Completed scanning {extension_path.name}: "
            f"Found {len(metadata.security_issues)} issues in "
            f"{len(metadata.scanned_files)} files"
        )

        return metadata

    async def _find_high_risk_files(self, extension_path: Path) -> List[Path]:
        """Find high-risk files in the extension directory."""
        high_risk_files = []

        for root, dirs, files in os.walk(extension_path):
            # Filter out ignored directories
            dirs[:] = [
                d
                for d in dirs
                if not should_ignore_directory(Path(root) / d, self.ignore_dirs)
            ]

            for file in files:
                file_path = Path(root) / file

                # Skip if already scanned
                if file_path in self.scanned_files:
                    continue

                # Check if it's a high-risk file
                if is_high_risk_file(file_path, self.high_risk_patterns):
                    high_risk_files.append(file_path)

        return high_risk_files

    async def _scan_file(self, file_path: Path, metadata: ExtensionMetadata) -> None:
        """Scan a single file for security issues."""
        try:
            # Mark as scanned
            self.scanned_files.add(file_path)
            metadata.scanned_files.add(file_path)

            # Compute hash
            metadata.sha1_hashes[file_path] = await compute_sha1_async(file_path)

            # Scan based on file type
            if (
                file_path.suffix.lower() == ".json"
                and file_path.name.lower() == "package.json"
            ):
                await self._scan_package_json(file_path, metadata)
            elif file_path.name.lower() == ".vsixmanifest":
                await self._scan_vsix_manifest(file_path, metadata)
            elif file_path.suffix.lower() in (".js", ".ts"):
                await self._scan_script_file(file_path, metadata)
            elif file_path.suffix.lower() in (".xml", ".sh", ".java", ".class", ".jar"):
                await self._scan_other_file(file_path, metadata)

        except Exception as e:
            self.logger.error(f"Error scanning {file_path}: {e}")

    async def _scan_package_json(
        self, file_path: Path, metadata: ExtensionMetadata
    ) -> None:
        """Scan package.json for issues and extract metadata."""
        # First, let the metadata analyzer extract info
        await self.metadata_analyzer.extract_from_package_json(file_path, metadata)

        # Then scan for security issues
        issues = await self.pattern_analyzer.scan_file(file_path)
        metadata.security_issues.extend(issues)

    async def _scan_vsix_manifest(
        self, file_path: Path, metadata: ExtensionMetadata
    ) -> None:
        """Scan .vsixmanifest files for security issues."""
        issues = await self.manifest_analyzer.scan_manifest(file_path)
        metadata.security_issues.extend(issues)

    async def _scan_script_file(
        self, file_path: Path, metadata: ExtensionMetadata
    ) -> None:
        """Scan JavaScript/TypeScript files for malicious patterns."""
        # Regular pattern analysis
        issues = await self.pattern_analyzer.scan_file(file_path)
        metadata.security_issues.extend(issues)

        # YARA analysis if enabled
        if self.yara_analyzer:
            yara_issues = await self.yara_analyzer.scan_file(file_path)
            metadata.security_issues.extend(yara_issues)

    async def _scan_other_file(
        self, file_path: Path, metadata: ExtensionMetadata
    ) -> None:
        """Scan other types of files."""
        issues = await self.pattern_analyzer.scan_file(file_path)
        metadata.security_issues.extend(issues)

    def filter_by_severity(
        self, results: List[ExtensionMetadata], severity: Severity
    ) -> List[ExtensionMetadata]:
        """Filter results to only include issues with the specified severity."""
        filtered_results = []

        for ext in results:
            matching_issues = [
                issue for issue in ext.security_issues if issue.severity == severity
            ]

            if matching_issues:
                # Create a copy with only matching issues
                filtered_ext = ExtensionMetadata(
                    name=ext.name,
                    version=ext.version,
                    publisher=ext.publisher,
                    scanned_files=ext.scanned_files.copy(),
                    sha1_hashes=ext.sha1_hashes.copy(),
                )
                filtered_ext.security_issues = matching_issues
                filtered_results.append(filtered_ext)

        return filtered_results

    async def extract_urls_from_files(
        self, extensions: List[ExtensionMetadata], output_file: Optional[str] = None
    ) -> Dict[Path, Set[str]]:
        """Extract and report URLs from extension files."""
        # Import the patterns directly
        from ide_hunter.patterns import HIGH_RISK_FILES

        return await self.url_reporter.extract_and_report(
            extensions,
            self.high_risk_patterns or HIGH_RISK_FILES,  # Use imported patterns
            output_file,
        )

    def print_metadata(self, results: List[ExtensionMetadata]):
        """Print extension metadata without security findings."""
        print("\n=== IDE Extension Metadata Summary ===")
        print(f"Scan completed at: {asyncio.get_event_loop().time()}")
        print(f"Total extensions scanned: {len(results)}")

        if not results:
            print("No extensions found.")
            return

        # Generate metadata table
        from tabulate import tabulate

        metadata_table = []
        for ext in results:
            version = ext.version if ext.version else "Unknown"
            publisher = ext.publisher if ext.publisher else "Unknown"
            files_scanned = len(ext.scanned_files)
            metadata_table.append([ext.name, version, publisher, files_scanned])

        print(
            tabulate(
                metadata_table,
                headers=["Extension", "Version", "Publisher", "Files Scanned"],
                tablefmt="grid",
            )
        )

    def generate_reports(
        self, results: List[ExtensionMetadata], output_path: Optional[str] = None
    ):
        """Generate reports based on scan results."""
        from ide_hunter.reporters.csv_reporter import generate_csv_report
        from ide_hunter.reporters.console_reporter import print_summary

        if output_path:
            # Save to CSV file
            directory = os.path.dirname(output_path)
            if directory:
                os.makedirs(directory, exist_ok=True)

            generate_csv_report(results, output_path)
            self.logger.info(f"CSV report generated at: {output_path}")
            print(f"\n Report saved to: {output_path}")
        else:
            # Print to console
            print_summary(results, self.scanned_files)
