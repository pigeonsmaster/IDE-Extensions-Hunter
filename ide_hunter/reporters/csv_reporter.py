"""
CSV report generation
"""

import csv
from typing import List
from ide_hunter.models import ExtensionMetadata


def generate_csv_report(results: List[ExtensionMetadata], output_file: str) -> None:
    """Generate a CSV report of scan results."""
    with open(output_file, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)

        # Write headers
        headers = [
            "Extension",
            "Version",
            "Publisher",
            "Issue Severity",
            "Issue Description",
            "File",
            "Line Number",
            "Context",
            "File Hash",
        ]
        writer.writerow(headers)

        # Write data for each extension
        for ext in results:
            for issue in ext.security_issues:
                file_hash = ext.sha1_hashes.get(issue.file_path, "Hash not computed")
                writer.writerow(
                    [
                        ext.name,
                        ext.version or "N/A",
                        ext.publisher or "N/A",
                        issue.severity.name,
                        issue.description,
                        issue.file_path,
                        issue.line_number or "N/A",
                        issue.context,
                        file_hash,
                    ]
                )
