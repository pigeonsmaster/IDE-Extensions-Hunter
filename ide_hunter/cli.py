"""
Command line interface for the IDE Extension Hunter
"""

import argparse
import asyncio
import logging
from typing import Optional, Dict, Any

from ide_hunter.scanner import IDEextensionsscanner
from ide_hunter.models import Severity
from ide_hunter.utils.logging_utils import setup_logging


def parse_arguments():
    """Parse command line arguments."""
    ascii_banner = """    
██╗██████╗ ███████╗    ███████╗██╗  ██╗████████╗    ██╗  ██╗██╗   ██╗███╗   ██╗████████╗███████╗██████╗ 
██║██╔══██╗██╔════╝    ██╔════╝╚██╗██╔╝╚══██╔══╝    ██║  ██║██║   ██║████╗  ██║╚══██╔══╝██╔════╝██╔══██╗
██║██║  ██║█████╗      █████╗   ╚███╔╝    ██║       ███████║██║   ██║██╔██╗ ██║   ██║   █████╗  ██████╔╝
██║██║  ██║██╔══╝      ██╔══╝   ██╔██╗    ██║       ██╔══██║██║   ██║██║╚██╗██║   ██║   ██╔══╝  ██╔══██╗
██║██████╔╝███████╗    ███████╗██╔╝ ██╗   ██║       ██║  ██║╚██████╔╝██║ ╚████║   ██║   ███████╗██║  ██║
╚═╝╚═════╝ ╚══════╝    ╚══════╝╚═╝  ╚═╝   ╚═╝       ╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═══╝   ╚═╝   ╚══════╝╚═╝  ╚═╝
══════════════════════════════════════════════════════════════════
IDE extensions Forensics
By Almog Mendelson
Scan and analyze IDE Code extensions for potential security risks.
══════════════════════════════════════════════════════════════════         
    """
    # Create parser with banner
    parser = argparse.ArgumentParser(
        description=ascii_banner,
        epilog="""
  Features

    - Detects malicious patterns embedded in IDE extension files  
    - Integrated with YARA rules for enhanced security analysis  
    - Export results in CSV format or prints them to the terminal  
    - Filters findings based on severity (INFO → CRITICAL)
    
""",
        formatter_class=argparse.RawTextHelpFormatter,
    )

    # Define arguments
    parser.add_argument(
        "--metadata",
        action="store_true",
        help="Print only extension metadata without security findings",
    )
    parser.add_argument(
        "--list-urls",
        action="store_true",
        help="Extract all URLs found in high-risk files",
    )
    parser.add_argument(
        "--ide",
        type=str,
        choices=["vscode", "pycharm"],
        help="Specify the IDE to scan ('vscode' or 'pycharm')",
    )
    parser.add_argument(
        "-o",
        "--output",
        type=str,
        help="Specify custom output CSV file path",
    )
    parser.add_argument(
        "-p",
        "--path",
        type=str,
        default=None,
        help="Custom VS Code extensions directory path",
    )
    parser.add_argument(
        "--severity",
        type=str,
        choices=["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"],
        default=None,
        help="severity level to report",
    )
    parser.add_argument(
        "--use-yara",
        action="store_true",
        help="Enable YARA-based scanning for deeper analysis",
    )
    parser.add_argument(
        "--debug",
        action="store_true",
        help="Enable debug logging",
    )

    return parser.parse_args()


async def async_run(args):
    """Run the scanner with the provided arguments."""
    logger = logging.getLogger(__name__)
    try:
        # Initialize scanner
        scanner = IDEextensionsscanner(
            ide=args.ide, extensions_path=args.path, use_yara=args.use_yara
        )

        # Scan all extensions
        all_results = await scanner.scan_all_extensions()
        results = all_results

        # Handle URL listing
        if args.list_urls:
            await scanner.extract_urls_from_files(all_results, args.output)
            return 0

        # Handle metadata-only display
        if args.metadata:
            scanner.print_metadata(all_results)
            return 0

        # Handle YARA scanning
        if args.use_yara:
            print("\nRunning YARA-based scan...")
            # Fix: Check the yara_analyzer instead of yara_rules
            if not scanner.yara_analyzer or not scanner.yara_analyzer.rules:
                print(
                    " No YARA rules found. Please add YARA rules to the 'yara' directory."
                )
                return 1

            results = [
                ext
                for ext in all_results
                if any(
                    issue.description.startswith("YARA Rule Match")
                    for issue in ext.security_issues
                )
            ]

            if not results:
                print("\n No YARA detections found.")
                return 0
        else:
            print("\n🔍 Running full security scan...")

        # Handle severity filtering
        if args.severity:
            severity_level = getattr(Severity, args.severity.upper())
            results = scanner.filter_by_severity(all_results, severity_level)

        # Generate output
        if args.output:
            scanner.generate_reports(results, args.output)
        else:
            from ide_hunter.reporters.console_reporter import print_summary

            print_summary(results, scanner.scanned_files)

        return 0

    except Exception as e:
        print(f"Error during scan: {str(e)}")
        logger.error(f"Error during scan: {str(e)}", exc_info=True)
        return 1


def run_with_args(args):
    """Run the scanner with the provided arguments."""
    setup_logging(logging.DEBUG if args.debug else logging.INFO)
    return asyncio.run(async_run(args))
