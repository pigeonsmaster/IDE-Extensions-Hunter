"""
Configuration management for IDE Extension Hunter
"""

from .yara_config import YaraConfig, load_yara_config

__all__ = ['YaraConfig', 'load_yara_config']
