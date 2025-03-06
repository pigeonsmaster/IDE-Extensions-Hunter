"""
File utilities for the IDE Extension Hunter
"""

import os
import fnmatch
from pathlib import Path
import platform
from typing import List, Set


def get_default_extension_paths(ide: str = None):
    """
    Get default extension paths based on IDE type and platform.

    Args:
        ide (str): 'vscode', 'pycharm', or None (for both)

    Returns:
        List[Path]: List of extension directory paths
    """
    default_paths = []
    os_type = platform.system().lower()  # "windows", "linux", or "darwin" (macOS)

    ide = ide or "both"

    if ide in ["vscode", "both"]:
        if os_type == "windows":
            default_paths.append(
                Path(os.path.expandvars(r"%USERPROFILE%\.vscode\extensions"))
            )
        else:  # Linux & macOS
            default_paths.append(Path(os.path.expanduser("~/.vscode/extensions")))

    if ide in ["pycharm", "both"]:
        if os_type == "windows":
            pycharm_base_path = Path(os.path.expandvars(r"%APPDATA%\JetBrains"))
        else:
            pycharm_base_path = Path(
                os.path.expanduser("~/Library/Application Support/JetBrains/")
            )

        # Add all PyCharm plugin directories
        if pycharm_base_path.exists():
            pycharm_dirs = list(pycharm_base_path.glob("PyCharm*"))
            for path in pycharm_dirs:
                plugin_path = path / "plugins"
                if plugin_path.exists():
                    default_paths.append(plugin_path)

    # Filter out non-existent paths
    return [path for path in default_paths if path.exists()]


def is_high_risk_file(file_path: Path, patterns: dict) -> bool:
    """
    Check if a file matches any of the high-risk patterns.

    Args:
        file_path: Path to the file
        patterns: Dictionary of high-risk file patterns

    Returns:
        bool: True if file matches any high-risk pattern
    """
    file_name = file_path.name

    if patterns is None:
        from ide_hunter.patterns import HIGH_RISK_FILES

        patterns = HIGH_RISK_FILES

    for pattern in patterns:
        if fnmatch.fnmatch(file_name, pattern) or file_path.match(f"**/{pattern}"):
            return True

    return False


def should_ignore_directory(dir_path: Path, ignore_dirs: Set[str]) -> bool:
    """
    Check if a directory should be ignored.

    Args:
        dir_path: Path to the directory
        ignore_dirs: Set of directory names to ignore

    Returns:
        bool: True if directory should be ignored
    """
    if ignore_dirs is None:
        from ide_hunter.patterns import IGNORE_DIRS

        ignore_dirs = IGNORE_DIRS

    for part in dir_path.parts:
        if part in ignore_dirs:
            return True
    return False
