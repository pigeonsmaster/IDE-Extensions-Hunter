"""
Logging configuration
"""

import os
import logging
from datetime import datetime


def setup_logging(log_level=logging.INFO, console_output=True):
    """Configure logging with detailed formatting."""
    log_dir = "logs"
    os.makedirs(log_dir, exist_ok=True)

    log_file = os.path.join(
        log_dir, f"extension_scanner_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log"
    )

    handlers = [logging.FileHandler(log_file, encoding="utf-8")]
    
    # Only add console handler if requested (reduces debug output spam)
    if console_output:
        handlers.append(logging.StreamHandler())

    logging.basicConfig(
        level=log_level,
        format="%(asctime)s - %(levelname)s - [%(filename)s:%(lineno)d] - %(message)s",
        handlers=handlers,
    )

    return logging.getLogger(__name__)
