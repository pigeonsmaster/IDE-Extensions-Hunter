"""
YARA-based file analysis
"""

import logging
import aiofiles
from pathlib import Path
from typing import List

from ide_hunter.models import SecurityIssue, Severity

logger = logging.getLogger(__name__)

class YaraAnalyzer:
    """Analyzes files using YARA rules."""
    
    def __init__(self):
        """Initialize the YARA analyzer."""
        self.rules = self.load_rules()
        if self.rules:
            logger.info(f"YARA analyzer initialized with {len(self.rules)} rules")
        else:
            logger.warning("YARA analyzer initialized but no rules were loaded")
        
    def load_rules(self):
        """Load YARA rules from the yara directory."""
        try:
            import yara
            
            import os
            rules_dir = os.path.join(os.getcwd(), "yara")
            compiled_rules = []
            
            if os.path.isdir(rules_dir):
                for file in os.listdir(rules_dir):
                    if file.endswith(('.yar', '.yara')):
                        try:
                            rule_path = os.path.join(rules_dir, file)
                            rule = yara.compile(filepath=rule_path)
                            compiled_rules.append(rule)
                            logger.info(f"Loaded YARA rule: {rule_path}")
                        except Exception as e:
                            logger.error(f"Error loading YARA rule {file}: {e}")
                            
            if not compiled_rules:
                logger.warning("No YARA rules were loaded from the yara directory")
                return None
                
            return compiled_rules
                
        except ImportError:
            logger.error("YARA Python module not installed. Please install yara-python package.")
            return None
    
    async def scan_file(self, file_path: Path) -> List[SecurityIssue]:
        """Scan a file using YARA rules."""
        if not self.rules:
            return []
            
        issues = []
        
        try:
            async with aiofiles.open(file_path, "rb") as f:
                content = await f.read()
                
                for rule_set in self.rules:
                    matches = rule_set.match(data=content)
                    
                    for match in matches:
                        # Extract matched strings
                        matched_strings = []
                        if hasattr(match, "strings") and isinstance(match.strings, list):
                            for string_match in match.strings:
                                if isinstance(string_match, tuple) and len(string_match) == 3:
                                    _, identifier, data = string_match
                                    if isinstance(data, bytes):
                                        data_str = data.decode('utf-8', errors='ignore')
                                    else:
                                        data_str = str(data)
                                    matched_strings.append(f"{identifier}: {data_str}")
                                    
                        # Determine severity from rule metadata
                        severity = Severity.HIGH  # Default
                        if hasattr(match, "meta") and isinstance(match.meta, dict):
                            severity_value = match.meta.get("severity", "high")
                            
                            # Handle numeric severity values
                            if isinstance(severity_value, int):
                                if severity_value >= 4:
                                    severity = Severity.CRITICAL
                                elif severity_value == 3:
                                    severity = Severity.HIGH
                                elif severity_value == 2:
                                    severity = Severity.MEDIUM
                                elif severity_value == 1:
                                    severity = Severity.LOW
                                elif severity_value == 0:
                                    severity = Severity.INFO
                            else:
                                # Handle string severity values
                                severity_str = str(severity_value)
                                if isinstance(severity_str, bytes):
                                    severity_str = severity_str.decode('utf-8', errors='ignore')
                                    
                                severity_str = severity_str.lower()
                                if severity_str == "critical":
                                    severity = Severity.CRITICAL
                                elif severity_str == "high":
                                    severity = Severity.HIGH
                                elif severity_str == "medium":
                                    severity = Severity.MEDIUM
                                elif severity_str == "low":
                                    severity = Severity.LOW
                                elif severity_str == "info":
                                    severity = Severity.INFO
                        
                        # Create context from matched strings
                        context = "Matched strings: " + ", ".join(matched_strings[:5]) if matched_strings else "No strings extracted"
                        
                        # Create issue
                        issue = SecurityIssue(
                            description=f"YARA Rule Match: {match.rule}",
                            severity=severity,
                            context=context,
                            file_path=file_path
                        )
                        issues.append(issue)
                        
        except Exception as e:
            logger.error(f"Error scanning {file_path} with YARA: {e}")
            
        return issues