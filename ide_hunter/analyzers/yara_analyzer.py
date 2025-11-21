"""
Enhanced YARA-based file analysis with better error handling and features
"""

import logging
import aiofiles
import asyncio
import os
from pathlib import Path
from typing import List, Dict, Optional, Set
from dataclasses import dataclass, field
from datetime import datetime

from ide_hunter.models import SecurityIssue, Severity

try:
    from ide_hunter.config import YaraConfig
except ImportError:
    YaraConfig = None

logger = logging.getLogger(__name__)


@dataclass
class YaraRuleInfo:
    """Information about a loaded YARA rule."""
    name: str
    file_path: Path
    category: str = "unknown"
    severity: Severity = Severity.MEDIUM
    description: str = ""
    author: Optional[str] = None


@dataclass
class YaraScanStats:
    """Statistics from YARA scanning."""
    total_rules_loaded: int = 0
    total_files_scanned: int = 0
    total_matches: int = 0
    rules_matched: Dict[str, int] = field(default_factory=dict)
    scan_start_time: Optional[datetime] = None
    skipped_files: int = 0
    errors: int = 0

    def get_scan_duration(self) -> float:
        """Get scan duration in seconds."""
        if self.scan_start_time:
            return (datetime.now() - self.scan_start_time).total_seconds()
        return 0.0


class YaraAnalyzerError(Exception):
    """Base exception for YARA analyzer errors."""
    pass


class NoRulesLoadedError(YaraAnalyzerError):
    """Raised when no YARA rules could be loaded."""
    pass


class YaraAnalyzer:
    """Enhanced YARA analyzer with better features and error handling."""

    def __init__(
        self,
        rule_directories: Optional[List[str]] = None,
        max_file_size_mb: int = 10,
        timeout_seconds: int = 30,
        fail_on_no_rules: bool = True,
        config: Optional['YaraConfig'] = None
    ):
        """
        Initialize the enhanced YARA analyzer.

        Args:
            rule_directories: List of directories to load rules from
            max_file_size_mb: Maximum file size to scan in MB
            timeout_seconds: Timeout for scanning a single file
            fail_on_no_rules: Raise exception if no rules loaded
            config: YaraConfig object (overrides other parameters if provided)
        """
        if config:
            self.rule_directories = config.rule_directories
            self.max_file_size_bytes = config.performance.max_file_size_mb * 1024 * 1024
            self.timeout_seconds = config.performance.timeout_seconds
            self.config = config
        else:
            self.rule_directories = rule_directories or self._get_default_directories()
            self.max_file_size_bytes = max_file_size_mb * 1024 * 1024
            self.timeout_seconds = timeout_seconds
            self.config = None

        self.rule_info: List[YaraRuleInfo] = []
        self.stats = YaraScanStats()
        self.stats.scan_start_time = datetime.now()

        self.rules = self._load_rules_from_directories()

        if not self.rules and fail_on_no_rules:
            raise NoRulesLoadedError(
                "No YARA rules loaded. Check your yara/ directory and rule files."
            )

        if self.rules:
            logger.info(
                f"YARA analyzer initialized with {len(self.rule_info)} rules "
                f"from {len(self.rule_directories)} directories"
            )
        else:
            logger.warning("YARA analyzer initialized but NO rules were loaded")

    def _get_default_directories(self) -> List[str]:
        """Get default YARA rule directories."""
        directories = []

        cwd_yara = os.path.join(os.getcwd(), "yara")
        if os.path.isdir(cwd_yara):
            directories.append(cwd_yara)

        home_yara = os.path.expanduser("~/.ide_hunter/yara")
        if os.path.isdir(home_yara):
            directories.append(home_yara)

        return directories if directories else [cwd_yara]

    def _load_rules_from_directories(self) -> List:
        """Load YARA rules from all configured directories."""
        try:
            import yara
        except ImportError:
            logger.error("YARA Python module not installed. Install: pip install yara-python")
            return []

        compiled_rules = []

        for rule_dir in self.rule_directories:
            expanded_path = Path(os.path.expanduser(rule_dir))

            if not expanded_path.exists():
                logger.debug(f"Rule directory not found: {expanded_path}")
                continue

            logger.info(f"Loading YARA rules from: {expanded_path}")

            for rule_file in expanded_path.glob('*.yar*'):
                if not rule_file.is_file():
                    continue

                if rule_file.stat().st_size == 0:
                    logger.warning(f"Skipping empty rule file: {rule_file.name}")
                    continue

                try:
                    rule = yara.compile(filepath=str(rule_file))
                    compiled_rules.append(rule)

                    self._extract_rule_metadata(rule_file)

                    logger.info(f"  Loaded: {rule_file.name}")

                except yara.SyntaxError as e:
                    logger.error(f"  Syntax error in {rule_file.name}: {e}")
                    self.stats.errors += 1
                except Exception as e:
                    logger.error(f"  Failed to load {rule_file.name}: {e}")
                    self.stats.errors += 1

        self.stats.total_rules_loaded = len(compiled_rules)

        if not compiled_rules:
            logger.warning(
                f"No YARA rules loaded from directories: {self.rule_directories}"
            )

        return compiled_rules

    def _extract_rule_metadata(self, rule_file: Path):
        """Extract metadata from YARA rule file by parsing the file."""
        try:
            with open(rule_file, 'r', encoding='utf-8') as f:
                content = f.read()

            import re

            rule_names = re.findall(r'rule\s+(\w+)', content)
            descriptions = re.findall(r'description\s*=\s*["\']([^"\']+)["\']', content)
            categories = re.findall(r'category\s*=\s*["\']([^"\']+)["\']', content)
            severities = re.findall(r'severity\s*=\s*(\d+|["\'][^"\']+["\'])', content)
            authors = re.findall(r'author\s*=\s*["\']([^"\']+)["\']', content)

            for idx, rule_name in enumerate(rule_names):
                description = descriptions[idx] if idx < len(descriptions) else rule_name
                category = categories[idx] if idx < len(categories) else "unknown"
                author = authors[idx] if idx < len(authors) else None

                severity = Severity.MEDIUM
                if idx < len(severities):
                    sev_value = severities[idx].strip('"\'')
                    if sev_value.isdigit():
                        sev_int = int(sev_value)
                        severity_map = {
                            0: Severity.INFO,
                            1: Severity.LOW,
                            2: Severity.MEDIUM,
                            3: Severity.HIGH,
                            4: Severity.CRITICAL
                        }
                        severity = severity_map.get(sev_int, Severity.MEDIUM)
                    else:
                        severity_map = {
                            'info': Severity.INFO,
                            'low': Severity.LOW,
                            'medium': Severity.MEDIUM,
                            'high': Severity.HIGH,
                            'critical': Severity.CRITICAL
                        }
                        severity = severity_map.get(sev_value.lower(), Severity.MEDIUM)

                info = YaraRuleInfo(
                    name=rule_name,
                    file_path=rule_file,
                    category=category,
                    severity=severity,
                    description=description,
                    author=author
                )
                self.rule_info.append(info)

        except Exception as e:
            logger.debug(f"Could not extract metadata from {rule_file}: {e}")

    async def scan_file(self, file_path: Path) -> List[SecurityIssue]:
        """
        Scan a file using YARA rules with size limits and timeout.

        Args:
            file_path: Path to file to scan

        Returns:
            List of security issues found
        """
        if not self.rules:
            return []

        issues = []

        try:
            file_size = file_path.stat().st_size
            if file_size > self.max_file_size_bytes:
                logger.debug(
                    f"Skipping {file_path.name}: too large "
                    f"({file_size / 1024 / 1024:.1f} MB)"
                )
                self.stats.skipped_files += 1
                return []
        except Exception as e:
            logger.warning(f"Could not check size of {file_path}: {e}")

        try:
            async with aiofiles.open(file_path, "rb") as f:
                content = await f.read()
        except Exception as e:
            logger.error(f"Error reading {file_path}: {e}")
            self.stats.errors += 1
            return []

        try:
            matches = await asyncio.wait_for(
                self._scan_with_rules(content, file_path),
                timeout=self.timeout_seconds
            )
            issues.extend(matches)

        except asyncio.TimeoutError:
            logger.warning(f"YARA scan timeout for {file_path.name}")
            self.stats.errors += 1
        except Exception as e:
            logger.error(f"Error scanning {file_path} with YARA: {e}")
            self.stats.errors += 1

        self.stats.total_files_scanned += 1
        self.stats.total_matches += len(issues)

        return issues

    async def _scan_with_rules(self, content: bytes, file_path: Path) -> List[SecurityIssue]:
        """Internal method to scan content with all loaded rules."""
        issues = []

        for rule_set in self.rules:
            matches = rule_set.match(data=content)

            for match in matches:
                if match.rule not in self.stats.rules_matched:
                    self.stats.rules_matched[match.rule] = 0
                self.stats.rules_matched[match.rule] += 1

                matched_strings = self._extract_matched_strings(match)
                severity = self._get_severity_from_match(match)
                description = self._format_description(match)
                context = self._create_context(match, matched_strings)

                issue = SecurityIssue(
                    description=description,
                    severity=severity,
                    context=context,
                    file_path=file_path
                )
                issues.append(issue)

        return issues

    def _extract_matched_strings(self, match) -> List[str]:
        """Extract matched strings from YARA match."""
        matched_strings = []

        if hasattr(match, "strings") and isinstance(match.strings, list):
            for string_match in match.strings:
                if isinstance(string_match, tuple) and len(string_match) >= 3:
                    _, identifier, data = string_match[:3]

                    if isinstance(data, bytes):
                        data_str = data.decode('utf-8', errors='ignore')[:100]
                    else:
                        data_str = str(data)[:100]

                    matched_strings.append(f"{identifier}: {data_str}")

        return matched_strings

    def _get_severity_from_match(self, match) -> Severity:
        """Extract severity from match metadata."""
        severity = Severity.HIGH

        if hasattr(match, "meta") and isinstance(match.meta, dict):
            severity_value = match.meta.get("severity", "high")

            if isinstance(severity_value, int):
                severity_map = {
                    0: Severity.INFO,
                    1: Severity.LOW,
                    2: Severity.MEDIUM,
                    3: Severity.HIGH,
                    4: Severity.CRITICAL
                }
                severity = severity_map.get(severity_value, Severity.HIGH)
            else:
                severity_str = str(severity_value).lower().strip('"\'')
                severity_map = {
                    'info': Severity.INFO,
                    'low': Severity.LOW,
                    'medium': Severity.MEDIUM,
                    'high': Severity.HIGH,
                    'critical': Severity.CRITICAL
                }
                severity = severity_map.get(severity_str, Severity.HIGH)

        return severity

    def _format_description(self, match) -> str:
        """Format issue description with metadata."""
        description = f"YARA: {match.rule}"

        if hasattr(match, "meta") and isinstance(match.meta, dict):
            meta = match.meta

            if 'description' in meta:
                desc_text = meta['description']
                if isinstance(desc_text, bytes):
                    desc_text = desc_text.decode('utf-8', errors='ignore')
                description = f"{match.rule} - {desc_text}"

            if 'reference' in meta:
                ref_text = meta['reference']
                if isinstance(ref_text, bytes):
                    ref_text = ref_text.decode('utf-8', errors='ignore')
                description += f" (Ref: {ref_text})"

        return description

    def _create_context(self, match, matched_strings: List[str]) -> str:
        """Create context string for the issue."""
        context_parts = []

        if hasattr(match, "meta") and isinstance(match.meta, dict):
            meta = match.meta
            if 'category' in meta:
                cat = meta['category']
                if isinstance(cat, bytes):
                    cat = cat.decode('utf-8', errors='ignore')
                context_parts.append(f"Category: {cat}")

        if matched_strings:
            preview = ", ".join(matched_strings[:3])
            context_parts.append(f"Matched: {preview}")
            if len(matched_strings) > 3:
                context_parts.append(f"(+{len(matched_strings) - 3} more)")
        else:
            context_parts.append("No strings extracted")

        return " | ".join(context_parts)

    def get_statistics(self) -> YaraScanStats:
        """Get scanning statistics."""
        return self.stats

    def get_rule_info(self) -> List[YaraRuleInfo]:
        """Get information about loaded rules."""
        return self.rule_info

    def print_statistics(self):
        """Print scanning statistics to console."""
        print("\n=== YARA Scan Statistics ===")
        print(f"Rules loaded: {self.stats.total_rules_loaded}")
        print(f"Files scanned: {self.stats.total_files_scanned}")
        print(f"Files skipped: {self.stats.skipped_files}")
        print(f"Total matches: {self.stats.total_matches}")
        print(f"Errors: {self.stats.errors}")
        print(f"Duration: {self.stats.get_scan_duration():.2f}s")

        if self.stats.rules_matched:
            print("\nTop matching rules:")
            sorted_rules = sorted(
                self.stats.rules_matched.items(),
                key=lambda x: x[1],
                reverse=True
            )
            for rule, count in sorted_rules[:10]:
                print(f"  {rule}: {count} matches")
