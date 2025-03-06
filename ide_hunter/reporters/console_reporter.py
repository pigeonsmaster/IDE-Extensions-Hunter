"""
Console output formatting
"""

from typing import List, Set
from pathlib import Path
from tabulate import tabulate

from ide_hunter.models import ExtensionMetadata, Severity


def print_summary(results: List[ExtensionMetadata], scanned_files: Set[Path]) -> None:
    """Print a summary of scan results to the console."""
    from datetime import datetime

    print("\n=== IDE Extension Security Scan Summary ===")
    print(f"Scan completed at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"Total extensions scanned: {len(results)}")
    print(f"Total unique files scanned: {len(scanned_files)}")

    if not results:
        print("No extensions found to scan.")
        return

    # Print metadata table
    metadata_table = []
    for ext in results:
        version = ext.version if ext.version else "Unknown"
        publisher = ext.publisher if ext.publisher else "Unknown"
        issues_count = len(ext.security_issues)
        files_count = len(ext.scanned_files)
        metadata_table.append([ext.name, version, publisher, issues_count, files_count])

    print("\n Extensions Overview:")
    print(
        tabulate(
            metadata_table,
            headers=[
                "Extension",
                "Version",
                "Publisher",
                "Issues Found",
                "Files Scanned",
            ],
            tablefmt="grid",
        )
    )

    # Check for findings
    total_findings = sum(len(ext.security_issues) for ext in results)
    if total_findings == 0:
        print("\n No security issues detected. ")
        return

    # Group findings by severity
    findings_by_severity = {}
    for ext in results:
        for issue in ext.security_issues:
            if issue.severity not in findings_by_severity:
                findings_by_severity[issue.severity] = []
            findings_by_severity[issue.severity].append((ext.name, issue))

    # Print issues by severity
    for severity in sorted(Severity, key=lambda x: x.value, reverse=True):
        if severity in findings_by_severity:
            issues = findings_by_severity[severity]
            print(f"\n{severity.name} Issues ({len(issues)}):")

            issues_table = []
            for ext_name, issue in issues:
                issues_table.append(
                    [
                        ext_name,
                        issue.description,
                        issue.file_path,
                        issue.line_number or "N/A",
                        (
                            issue.context[:50] + "..."
                            if len(issue.context) > 50
                            else issue.context
                        ),
                    ]
                )

            print(
                tabulate(
                    issues_table,
                    headers=["Extension", "Issue", "File", "Line", "Context"],
                    tablefmt="grid",
                )
            )
