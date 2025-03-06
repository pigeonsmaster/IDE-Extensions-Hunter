"""
Module entry point for running as 'python -m ide_hunter'
"""

from ide_hunter.cli import parse_arguments, run_with_args


def main():
    """Entry point when module is run directly"""
    args = parse_arguments()
    return run_with_args(args)


if __name__ == "__main__":
    import sys

    sys.exit(main())
