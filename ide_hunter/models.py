"""
Data models for the IDE Extension Hunter
"""

from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Dict, Set, List, Optional


class Severity(Enum):
    CRITICAL = 4
    HIGH = 3
    MEDIUM = 2
    LOW = 1
    INFO = 0


@dataclass
class SecurityIssue:
    """Structured container for security issues."""

    description: str
    severity: Severity
    context: str
    file_path: Path
    line_number: Optional[int] = None


@dataclass
class ExtensionMetadata:
    """Structured container for extension metadata and scan results."""

    name: str
    version: Optional[str] = None
    publisher: Optional[str] = None
    urls: Dict[str, str] = None
    security_issues: List[SecurityIssue] = None
    scanned_files: Set[Path] = None
    sha1_hashes: Dict[Path, str] = None

    def __post_init__(self):
        self.urls = self.urls or {}
        self.security_issues = self.security_issues or []
        self.scanned_files = self.scanned_files or set()
        self.sha1_hashes = self.sha1_hashes or {}
