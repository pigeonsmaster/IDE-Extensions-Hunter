"""
Output formatting utilities for IDE Extension Hunter
"""

from typing import List, Dict, Any
from colorama import Fore, Style, init
from tabulate import tabulate
import json
from datetime import datetime
from ide_hunter.models import Severity, SecurityIssue, ExtensionMetadata

# Initialize colorama
init()

class OutputFormatter:
    """Handles formatted output with colors and styling."""
    
    @staticmethod
    def colorize_severity(severity: Severity) -> str:
        """Colorize severity levels."""
        colors = {
            Severity.INFO: Fore.BLUE,
            Severity.LOW: Fore.GREEN,
            Severity.MEDIUM: Fore.YELLOW,
            Severity.HIGH: Fore.RED,
            Severity.CRITICAL: Fore.RED + Style.BRIGHT
        }
        return f"{colors.get(severity, '')}{severity.value}{Style.RESET_ALL}"
    
    @staticmethod
    def format_metadata_summary(results: List[ExtensionMetadata]) -> str:
        """Format extension metadata summary."""
        headers = ["Extension", "Version", "Publisher", "Files Scanned"]
        rows = []
        
        for ext in results:
            rows.append([
                ext.name,
                ext.version or "Unknown",
                ext.publisher or "Unknown",
                len(ext.scanned_files)
            ])
            
        return tabulate(rows, headers=headers, tablefmt="simple")
    
    @staticmethod
    def format_security_issues(issues: List[SecurityIssue]) -> str:
        """Format security issues with colors."""
        if not issues:
            return f"{Fore.GREEN}No security issues found{Style.RESET_ALL}"
            
        headers = ["Severity", "Issue", "File", "Line", "Context"]
        rows = []
        
        for issue in issues:
            rows.append([
                OutputFormatter.colorize_severity(issue.severity),
                issue.description,
                str(issue.file_path),
                str(issue.line_number or "N/A"),
                issue.context or "N/A"
            ])
            
        return tabulate(rows, headers=headers, tablefmt="simple")
    
    @staticmethod
    def format_url_summary(urls: Dict[str, List[str]]) -> str:
        """Format URL summary with counts."""
        if not urls:
            return f"{Fore.GREEN}No URLs found{Style.RESET_ALL}"
            
        total_urls = sum(len(url_list) for url_list in urls.values())
        headers = ["File", "URLs Found", "URLs"]
        rows = []
        
        for file_path, url_list in urls.items():
            rows.append([
                str(file_path),
                len(url_list),
                "\n".join(url_list)
            ])
            
        summary = f"\nTotal URLs found: {total_urls}\n\n"
        return summary + tabulate(rows, headers=headers, tablefmt="simple")
    
    @staticmethod
    def format_scan_summary(
        total_extensions: int,
        total_files: int,
        elapsed_time: float,
        issues_found: int
    ) -> str:
        """Format scan summary with statistics."""
        return (
            f"\nScan Summary:\n"
            f"Time elapsed: {elapsed_time:.2f} seconds\n"
            f"Extensions scanned: {total_extensions}\n"
            f"Files scanned: {total_files}\n"
            f"Security issues found: {issues_found}\n"
        )

    @staticmethod
    def format_as_json(
        results: List[ExtensionMetadata],
        total_extensions: int,
        total_files: int,
        elapsed_time: float,
        issues_found: int
    ) -> str:
        """Format scan results as JSON."""
        output = {
            "scan": {
                "timestamp": datetime.now().isoformat(),
                "duration": {
                    "value": round(elapsed_time, 2),
                    "unit": "seconds"
                }
            },
            "summary": {
                "total_extensions": total_extensions,
                "total_files": total_files,
                "elapsed_time_seconds": round(elapsed_time, 2),
                "issues_found": issues_found
            },
            "extensions": []
        }

        for ext in results:
            extension_data = {
                "name": ext.name,
                "version": ext.version or "Unknown",
                "publisher": ext.publisher or "Unknown",
                "files_scanned": len(ext.scanned_files),
                "security_issues": [
                    {
                        "description": issue.description,
                        "severity": issue.severity.name,
                        "file_path": str(issue.file_path),
                        "line_number": issue.line_number,
                        "context": issue.context
                    }
                    for issue in (ext.security_issues or [])
                ],
                "urls": [
                    {
                        "type": file_path,
                        "url": url if isinstance(url, str) else url[0]
                    }
                    for file_path, url_list in (ext.urls or {}).items()
                    for url in (url_list if isinstance(url_list, list) else [url_list])
                ],
                "scanned_files": [str(path) for path in (ext.scanned_files or set())],
                "file_hashes": {
                    str(path): hash_value
                    for path, hash_value in (ext.sha1_hashes or {}).items()
                }
            }
            output["extensions"].append(extension_data)

        return json.dumps(output, indent=2) 