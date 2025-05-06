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
        # Validate YARA if enabled
        if args.use_yara:
            try:
                import yara
            except ImportError:
                print("Error: YARA module not found. Please install yara-python package.")
                return 1

        # Initialize scanner
        scanner = IDEextensionsscanner(
            ide=args.ide,
            extensions_path=args.path,
            use_yara=args.use_yara,
        )

        # Run scan
        print("\nStarting security scan of IDE extensions...\n")
        results = await scanner.scan_all_extensions()

        # Handle output
        if args.metadata:
            scanner.print_metadata(results)
        elif args.list_urls:
            await scanner.extract_urls_from_files(results, args.output)
        else:
            if args.output:
                scanner.generate_reports(results, args.output)
            else:
                from ide_hunter.reporters.console_reporter import print_summary
                print_summary(results, scanner.scanned_files)

        return 0

    except Exception as e:
        print(f"\nError during scan: {str(e)}")
        print("Check the log file for more details.")
        return 1


def run_with_args(args):
    """Run the scanner with the provided arguments."""
    # Set up logging based on debug flag
    if args.debug:
        setup_logging(logging.DEBUG)
    else:
        # Disable all logging except critical errors
        logging.getLogger().setLevel(logging.CRITICAL)
        # Disable specific loggers
        logging.getLogger('ide_hunter').setLevel(logging.CRITICAL)
        logging.getLogger('ide_hunter.scanner').setLevel(logging.CRITICAL)
        logging.getLogger('ide_hunter.analyzers').setLevel(logging.CRITICAL)
        logging.getLogger('ide_hunter.utils').setLevel(logging.CRITICAL)
    
    return asyncio.run(async_run(args))
