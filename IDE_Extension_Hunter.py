#!/usr/bin/env python3
"""
IDE Extension Hunter - Main entry point
"""

import sys
from ide_hunter.cli import parse_arguments, run_with_args

def main():
    """
    Main entry point for the IDE Extension Hunter tool
    """
    args = parse_arguments()
    run_with_args(args)

if __name__ == "__main__":
    sys.exit(main())