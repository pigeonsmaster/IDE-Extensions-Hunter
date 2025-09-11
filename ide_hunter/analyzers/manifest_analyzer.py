"""
VSIX manifest analysis
"""

import logging
from pathlib import Path
from typing import List
import xml.etree.ElementTree as ET

from ide_hunter.models import SecurityIssue, Severity
from ide_hunter.patterns import SUSPICIOUS_VSIX_ENTRIES

logger = logging.getLogger(__name__)


class ManifestAnalyzer:
    """Analyzes VS Code extension manifest files."""

    def __init__(self, suspicious_entries=None):
        """Initialize with optional custom suspicious entries."""
        self.suspicious_entries = suspicious_entries or SUSPICIOUS_VSIX_ENTRIES

    async def scan_manifest(self, file_path: Path) -> List[SecurityIssue]:
        """Scan a VSIX manifest file for security issues."""
        issues = []

        try:
            tree = ET.parse(file_path)
            root = tree.getroot()

            # Check for suspicious namespaces
            namespaces = root.attrib
            if any(
                suspicious in str(namespaces).lower()
                for suspicious in ["http", "ftp", "ws"]
            ):
                issues.append(
                    SecurityIssue(
                        description="Suspicious namespace definition in .vsixmanifest",
                        severity=Severity.HIGH,
                        context=str(namespaces),
                        file_path=file_path,
                    )
                )

            # Check for suspicious elements
            for elem in root.iter():
                # Handle tuple structure of suspicious entries
                entries = (
                    self.suspicious_entries[0]
                    if isinstance(self.suspicious_entries, tuple)
                    else self.suspicious_entries
                )

                if elem.tag in entries:
                    severity = entries[elem.tag]
                    issues.append(
                        SecurityIssue(
                            description=f"Suspicious `{elem.tag}` found in .vsixmanifest",
                            severity=severity,
                            context=str(ET.tostring(elem, encoding="unicode")),
                            file_path=file_path,
                        )
                    )

                # Check attributes for suspicious URLs
                for attr, value in elem.attrib.items():
                    if any(susp in value.lower() for susp in ["http:", "ftp:", "ws:"]):
                        issues.append(
                            SecurityIssue(
                                description=f"Suspicious URL in attribute {attr}",
                                severity=Severity.MEDIUM,
                                context=value[:100],
                                file_path=file_path,
                            )
                        )

        except ET.ParseError as e:
            # Try to run pattern analysis on the file content
            try:
                from ide_hunter.analyzers.pattern_analyzer import PatternAnalyzer
                pattern_analyzer = PatternAnalyzer()
                pattern_issues = await pattern_analyzer.scan_file(file_path)
                
                if pattern_issues:
                    # Use pattern detection results instead of generic "malformed"
                    issues.extend(pattern_issues)
                else:
                    # Only if no patterns found, then say it's malformed
                    issues.append(
                        SecurityIssue(
                            description="File is malformed, cannot scan the file",
                            severity=Severity.HIGH,
                            context=str(e),
                            file_path=file_path,
                        )
                    )
            except Exception as pattern_error:
                # Fallback if pattern analysis also fails
                issues.append(
                    SecurityIssue(
                        description="File is malformed, cannot scan the file",
                        severity=Severity.HIGH,
                        context=str(e),
                        file_path=file_path,
                    )
                )
        except Exception as e:
            logger.error(f"Error scanning manifest {file_path}: {e}")

        return issues
