"""
YARA configuration management
Loads and validates configuration from YAML file
"""

import os
import logging
from pathlib import Path
from typing import Dict, List, Optional, Set
from dataclasses import dataclass, field

import yaml

from ide_hunter.models import Severity

logger = logging.getLogger(__name__)


@dataclass
class YaraPerformanceConfig:
    """Performance-related configuration."""
    max_file_size_mb: int = 10
    timeout_seconds: int = 30
    fail_on_no_rules: bool = True


@dataclass
class YaraFiltersConfig:
    """Rule filtering configuration."""
    enabled_categories: Optional[List[str]] = None
    disabled_rules: List[str] = field(default_factory=list)
    min_severity: Severity = Severity.INFO


@dataclass
class YaraOutputConfig:
    """Output and reporting configuration."""
    show_rule_stats: bool = True
    show_matched_strings: bool = True
    max_matches_per_file: int = 50
    truncate_strings_at: int = 100


@dataclass
class YaraConfig:
    """Complete YARA configuration."""
    rule_directories: List[str] = field(default_factory=list)
    performance: YaraPerformanceConfig = field(default_factory=YaraPerformanceConfig)
    filters: YaraFiltersConfig = field(default_factory=YaraFiltersConfig)
    output: YaraOutputConfig = field(default_factory=YaraOutputConfig)

    @classmethod
    def from_dict(cls, config_dict: Dict) -> 'YaraConfig':
        """
        Create YaraConfig from dictionary.

        Args:
            config_dict: Configuration dictionary from YAML

        Returns:
            YaraConfig instance
        """
        yara_section = config_dict.get('yara', {})

        rule_directories = yara_section.get('rule_directories', ['./yara/'])

        perf_dict = yara_section.get('performance', {})
        performance = YaraPerformanceConfig(
            max_file_size_mb=perf_dict.get('max_file_size_mb', 10),
            timeout_seconds=perf_dict.get('timeout_seconds', 30),
            fail_on_no_rules=perf_dict.get('fail_on_no_rules', True)
        )

        filters_dict = yara_section.get('filters', {})

        min_severity_str = filters_dict.get('min_severity', 'INFO').upper()
        min_severity = Severity[min_severity_str] if min_severity_str in Severity.__members__ else Severity.INFO

        filters = YaraFiltersConfig(
            enabled_categories=filters_dict.get('enabled_categories'),
            disabled_rules=filters_dict.get('disabled_rules', []),
            min_severity=min_severity
        )

        output_dict = yara_section.get('output', {})
        output = YaraOutputConfig(
            show_rule_stats=output_dict.get('show_rule_stats', True),
            show_matched_strings=output_dict.get('show_matched_strings', True),
            max_matches_per_file=output_dict.get('max_matches_per_file', 50),
            truncate_strings_at=output_dict.get('truncate_strings_at', 100)
        )

        return cls(
            rule_directories=rule_directories,
            performance=performance,
            filters=filters,
            output=output
        )

    @classmethod
    def get_default(cls) -> 'YaraConfig':
        """
        Get default configuration.

        Returns:
            YaraConfig with default values
        """
        return cls(
            rule_directories=['./yara/'],
            performance=YaraPerformanceConfig(),
            filters=YaraFiltersConfig(),
            output=YaraOutputConfig()
        )


def load_yara_config(config_path: Optional[str] = None) -> YaraConfig:
    """
    Load YARA configuration from file or use defaults.

    Args:
        config_path: Path to yara_config.yaml (optional)

    Returns:
        YaraConfig instance
    """
    if config_path and Path(config_path).exists():
        try:
            with open(config_path, 'r', encoding='utf-8') as f:
                config_dict = yaml.safe_load(f)
                logger.info(f"Loaded YARA config from: {config_path}")
                return YaraConfig.from_dict(config_dict)
        except Exception as e:
            logger.warning(f"Error loading config from {config_path}: {e}")
            logger.warning("Using default configuration")
            return YaraConfig.get_default()

    default_config_path = Path('yara_config.yaml')
    if default_config_path.exists():
        try:
            with open(default_config_path, 'r', encoding='utf-8') as f:
                config_dict = yaml.safe_load(f)
                logger.info("Loaded YARA config from: yara_config.yaml")
                return YaraConfig.from_dict(config_dict)
        except Exception as e:
            logger.warning(f"Error loading default config: {e}")
            logger.warning("Using default configuration")

    logger.info("No config file found, using default configuration")
    return YaraConfig.get_default()
