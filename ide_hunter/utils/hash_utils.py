"""
Hash computation utilities
"""

import hashlib
import logging
import aiofiles
from pathlib import Path

logger = logging.getLogger(__name__)


async def compute_sha1_async(file_path: Path) -> str:
    """
    Asynchronously compute SHA-1 hash of a file.

    Args:
        file_path: Path to the file

    Returns:
        str: SHA-1 hash as hexadecimal string
    """
    try:
        async with aiofiles.open(file_path, "rb") as f:
            content = await f.read()
            file_hash = hashlib.sha1(content).hexdigest()
            return file_hash
    except Exception as e:
        logger.error(f"Error computing SHA-1 for {file_path}: {str(e)}")
        return "Error computing hash"
