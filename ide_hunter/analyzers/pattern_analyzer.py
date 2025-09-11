"""
Regex pattern-based file analysis
"""

import re
import logging
import aiofiles
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple, Any

from ide_hunter.models import SecurityIssue, Severity
from ide_hunter.patterns import MALICIOUS_PATTERNS

logger = logging.getLogger(__name__)


class PatternAnalyzer:
    """Analyzes files using regex patterns."""

    def __init__(self, patterns=None):
        """Initialize with optional custom patterns."""
        self.patterns = patterns or MALICIOUS_PATTERNS
        # Pre-compile all regex patterns for better performance
        self._compile_patterns()

    def _compile_patterns(self):
        """Pre-compile all regex patterns for better performance."""
        self.compiled_patterns = {}
        
        # Handle nested patterns structure if it's a tuple
        patterns = (
            self.patterns[0]
            if isinstance(self.patterns, tuple)
            else self.patterns
        )

        for category, config in patterns.items():
            if not isinstance(config, dict) or "patterns" not in config:
                continue
                
            self.compiled_patterns[category] = {
                "severity": config["severity"],
                "patterns": [re.compile(pattern) for pattern in config["patterns"]]
            }

    async def scan_file(self, file_path: Path) -> List[SecurityIssue]:
        """Scan a file for malicious patterns."""
        issues = []

        try:
            async with aiofiles.open(
                file_path, "r", encoding="utf-8", errors="ignore"
            ) as f:
                content = await f.read()
                lines = content.splitlines()

                # Use pre-compiled patterns for better performance
                for category, config in self.compiled_patterns.items():
                    severity = config["severity"]
                    compiled_patterns = config["patterns"]

                    # Check each compiled pattern against each line
                    for compiled_pattern in compiled_patterns:
                        for i, line in enumerate(lines, 1):
                            match = compiled_pattern.search(line)
                            if match:
                                context = line.strip()
                                issue = SecurityIssue(
                                    description=f"{category}: {match.group(0)}",
                                    severity=severity,
                                    context=context,
                                    file_path=file_path,
                                    line_number=i,
                                )
                                issues.append(issue)

        except Exception as e:
            logger.error(f"Error pattern scanning {file_path}: {e}")

        return issues
