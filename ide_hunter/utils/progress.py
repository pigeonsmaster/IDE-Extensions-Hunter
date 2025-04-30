"""
Progress tracking utilities for IDE Extension Hunter
"""

import sys
from typing import Optional
from tqdm import tqdm
from dataclasses import dataclass
from datetime import datetime

@dataclass
class ScanProgress:
    """Tracks scanning progress for extensions and files."""
    total_extensions: int
    total_files: int
    scanned_extensions: int = 0
    scanned_files: int = 0
    start_time: Optional[datetime] = None
    
    def __post_init__(self):
        self.start_time = datetime.now()
        self.extension_bar = tqdm(
            total=self.total_extensions,
            desc="Scanning Extensions",
            unit="ext",
            position=0,
            leave=True
        )
        self.file_bar = tqdm(
            total=self.total_files,
            desc="Scanning Files",
            unit="file",
            position=1,
            leave=True
        )
    
    def update_extension(self, count: int = 1):
        """Update extension progress."""
        self.scanned_extensions += count
        self.extension_bar.update(count)
    
    def update_file(self, count: int = 1):
        """Update file progress."""
        self.scanned_files += count
        self.file_bar.update(count)
    
    def close(self):
        """Close progress bars."""
        self.extension_bar.close()
        self.file_bar.close()
        
    @property
    def elapsed_time(self) -> float:
        """Get elapsed time in seconds."""
        return (datetime.now() - self.start_time).total_seconds()
    
    def get_summary(self) -> str:
        """Get a summary of the scan progress."""
        return (
            f"Scan completed in {self.elapsed_time:.2f} seconds\n"
            f"Scanned {self.scanned_extensions}/{self.total_extensions} extensions\n"
            f"Scanned {self.scanned_files}/{self.total_files} files"
        ) 