"""
URL extraction and reporting functionality
"""

import os
import re
import fnmatch
import logging
import aiofiles
import csv
from pathlib import Path
from typing import Dict, List, Optional, Set
from tabulate import tabulate
from ide_hunter.utils.output import OutputFormatter

from ide_hunter.models import ExtensionMetadata

logger = logging.getLogger(__name__)


class URLReporter:
    """Handles URL extraction and reporting from extension files."""

    def __init__(self):
        """Initialize URL reporter."""
        self.url_pattern = re.compile(
            r'https?://(?:[-\w.]|(?:%[\da-fA-F]{2}))+'
            r'(?::\d+)?(?:/[-\w._~:/?#[\]@!$&\'()*+,;=]*)?'
        )

    async def extract_urls_from_file(self, file_path: Path) -> Set[str]:
        """Extract URLs from a single file."""
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()
                return set(self.url_pattern.findall(content))
        except Exception:
            return set()

    async def extract_urls_from_files(
        self, extensions: List[Dict], output_file: str = None
    ) -> Dict[Path, Set[str]]:
        """Extract URLs from all scanned files."""
        url_map = {}
        
        for ext in extensions:
            for file_path in ext.get('scanned_files', []):
                urls = await self.extract_urls_from_file(file_path)
                if urls:
                    url_map[file_path] = urls

        # Format and print results
        print(OutputFormatter.format_url_summary(url_map))

        # Write to file if specified
        if output_file:
            with open(output_file, 'w', encoding='utf-8') as f:
                f.write(OutputFormatter.format_url_summary(url_map))

        return url_map

    async def extract_and_report(
        self,
        extensions: List[ExtensionMetadata],
        high_risk_patterns: Dict,
        output_file: Optional[str] = None,
    ) -> Dict[Path, Set[str]]:
        """Extract URLs from high-risk files and generate report."""
        url_pattern = re.compile(r"https?://[^\s\"'>]+")
        extracted_urls = {}

        # Import patterns if not provided
        if high_risk_patterns is None:
            from ide_hunter.patterns import HIGH_RISK_FILES

            high_risk_patterns = HIGH_RISK_FILES

        # Extract URLs from each extension's files
        for extension in extensions:
            for file_path in extension.scanned_files:
                # Check if it's a high-risk file
                if not any(
                    fnmatch.fnmatch(file_path.name, pattern)
                    for pattern in high_risk_patterns
                ):
                    continue

                try:
                    async with aiofiles.open(
                        file_path, "r", encoding="utf-8", errors="ignore"
                    ) as f:
                        content = await f.read()

                    urls = set(url_pattern.findall(content))
                    if urls:
                        extracted_urls[file_path] = urls

                except Exception as e:
                    logger.error(f"Error reading {file_path}: {e}")

        # Display results in console
        await self._display_urls(extracted_urls)

        # Save to CSV if requested
        if output_file:
            await self._save_to_csv(extracted_urls, output_file)

        return extracted_urls

    async def _display_urls(self, extracted_urls: Dict[Path, Set[str]]) -> None:
        """Display extracted URLs in the console."""
        print("\n=== Extracted Unique URLs from Extensions ===")

        if not extracted_urls:
            print("No URLs found in scanned files.")
            return

        # Create table for display
        url_table = []
        for file_path, urls in extracted_urls.items():
            # Format file path
            display_path = str(file_path)

            # Add each URL
            for url in urls:
                url_table.append([display_path, url])

        # Display table
        print(tabulate(url_table, headers=["File", "URL"], tablefmt="grid"))

    async def _save_to_csv(
        self, extracted_urls: Dict[Path, Set[str]], output_file: str
    ) -> None:
        """Save extracted URLs to a CSV file."""
        directory = os.path.dirname(output_file)
        if directory:
            os.makedirs(directory, exist_ok=True)

        with open(output_file, "w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow(["File Path", "URL"])

            for file_path, urls in extracted_urls.items():
                for url in urls:
                    writer.writerow([str(file_path), url])

        print(f"\n URLs saved to: {output_file}")
