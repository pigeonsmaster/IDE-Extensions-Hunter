<p align="center">
  <img src="https://github.com/pigeonsmaster/IDE-Extensions-Hunter/blob/main/Logo.png?raw=true" width="400"><br>
</p>



[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

A forensic security scanner for analyzing IDE extensions for malicious code and security risks.

```
██╗██████╗ ███████╗    ███████╗██╗  ██╗████████╗    ██╗  ██╗██╗   ██╗███╗   ██╗████████╗███████╗██████╗ 
██║██╔══██╗██╔════╝    ██╔════╝╚██╗██╔╝╚══██╔══╝    ██║  ██║██║   ██║████╗  ██║╚══██╔══╝██╔════╝██╔══██╗
██║██║  ██║█████╗      █████╗   ╚███╔╝    ██║       ███████║██║   ██║██╔██╗ ██║   ██║   █████╗  ██████╔╝
██║██║  ██║██╔══╝      ██╔══╝   ██╔██╗    ██║       ██╔══██║██║   ██║██║╚██╗██║   ██║   ██╔══╝  ██╔══██╗
██║██████╔╝███████╗    ███████╗██╔╝ ██╗   ██║       ██║  ██║╚██████╔╝██║ ╚████║   ██║   ███████╗██║  ██║
╚═╝╚═════╝ ╚══════╝    ╚══════╝╚═╝  ╚═╝   ╚═╝       ╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═══╝   ╚═╝   ╚══════╝╚═╝  ╚═╝
```


## Description


Scans VS Code and PyCharm extensions for suspicious code patterns, malicious behaviors, and security vulnerabilities. The tool helps developers and security professionals identify potentially harmful extensions before installation.


## Features

- **Multi-IDE Support**: Scans VS Code and PyCharm extensions(for other ide's use custom path)
- **Comprehensive Pattern Detection**: Identifies malicious patterns in code
- **YARA Integration**: 24 detection rules across 5 categories with configurable YAML configuration
- **YARA Rule Management**: List, test, validate, and create custom rules via CLI
- **Flexible Reporting**: Outputs to CSV or terminal
- **URL Extraction**: Lists all embedded URLs
- **Cross-Platform**: Works on Windows, macOS, and Linux
- **Detailed Logging**: Comprehensive logging system with different severity levels
- Virus total integration(coming soon)


## Installation

```bash
# Clone the repository
git clone https://github.com/pigeonsmaster/IDE-Extensions-Hunter.git
cd ide-extension-hunter

# Install dependencies
pip install -r requirements.txt
```

## Usage

```bash
# Basic scan
python -m ide_hunter

# Scan VS Code extensions and output to CSV
python -m ide_hunter --ide vscode -o report.csv

# List all URLs from PyCharm extensions
python -m ide_hunter --ide pycharm --list-urls

# Show only extension metadata
python -m ide_hunter --metadata

# Filter by severity (INFO, LOW, MEDIUM, HIGH, CRITICAL)
python -m ide_hunter --severity HIGH

# Scan with YARA rules
python -m ide_hunter --use-yara

# List all YARA rules
python -m ide_hunter --list-yara-rules

# Test YARA rules against a file
python -m ide_hunter --yara-test path/to/file.js

# Validate YARA rule syntax
python -m ide_hunter --validate-yara

# Create new YARA rule from template
python -m ide_hunter --create-yara-rule

# Use custom YARA configuration
python -m ide_hunter --yara-config custom_config.yaml

# Enable debug logging
python -m ide_hunter --debug
```

## Project Structure

```
IDE_Extension_Hunter/
├── IDE_Extension_Hunter.py        # Main entry point
├── ide_hunter/                    # Core package
│   ├── analyzers/                 # Analysis modules
│   ├── config/                    # Configuration system
│   ├── reporters/                 # Output formatters
│   └── utils/                     # Utility functions
├── yara/                          # YARA rules directory
│   └── templates/                 # Rule templates for custom rules
├── yara_config.yaml               # YARA configuration file
└── logs/                          # Log directory
```

## Contributing

Contributions are welcome! Here's how you can help:

1. **Setup**: Fork the repo and create a feature branch
2. **Develop**: Add your feature or fix
3. **Test**: Ensure your code works correctly
4. **Submit**: Create a pull request with a clear description

### Adding Features

- **Analyzers**: Create new detection types in `ide_hunter/analyzers/`
- **Patterns**: Add malicious patterns in `patterns.py`
- **YARA Rules**: Create custom detection rules in `yara/` directory or use templates
- **Reporters**: Add new output formats in `ide_hunter/reporters/`

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Contact&Support
Email - pigeonsmaster@proton.me

## YARA Rules

The tool includes 24 YARA detection rules organized into 5 categories:

- **obfuscation**: Detects Base64 encoding, hex encoding, and code obfuscation
- **credential_theft**: Identifies browser cookie theft, SSH key access, NPM token access
- **data_exfiltration**: Detects Discord webhooks, Telegram bots, file uploads to external servers
- **c2**: Identifies reverse shells, WebSocket C2, HTTP beaconing
- **native_abuse**: Detects suspicious native module usage, WASM execution, process forking

### Configuration

YARA scanning is configured via `yara_config.yaml`:
- Rule directories
- Performance settings (file size limits, timeouts)
- Enabled categories
- Output preferences

### Rule Management

```bash
# List all loaded rules with metadata
python -m ide_hunter --list-yara-rules

# Validate rule syntax
python -m ide_hunter --validate-yara

# Test rules against a specific file
python -m ide_hunter --yara-test suspicious_file.js
```

### Creating Custom Rules

Use the interactive rule builder:
```bash
python -m ide_hunter --create-yara-rule
```

Or manually create rules using templates in `yara/templates/`:
- `basic_template.yar` - General purpose
- `obfuscation_template.yar` - Encoding detection
- `credential_theft_template.yar` - Credential access
- `exfiltration_template.yar` - Data theft
- `c2_template.yar` - C2 communication

### Severity Levels

Severity can be specified in two ways:
1. Numeric values (0-4):
   - 0: INFO
   - 1: LOW
   - 2: MEDIUM
   - 3: HIGH
   - 4: CRITICAL
2. String values: "info", "low", "medium", "high", "critical"

Example YARA rule:
```yara
rule suspicious_network_activity {
    meta:
        description = "Detects suspicious network calls"
        severity = 3
        category = "network"
    strings:
        $network_call = "fetch("
    condition:
        $network_call
}
```

## Logging

The tool provides comprehensive logging with different severity levels:
- INFO: General information about the scanning process
- WARNING: Non-critical issues or missing configurations
- ERROR: Critical issues that may affect the scanning process

Logs are stored in the `logs/` directory with timestamps for each scan session.

## Built-in Pattern Detection

The tool comes with pre-configured patterns for detecting malicious behavior:

### High-Risk File Types
- `package.json` (HIGH severity)
- `extension.js` and `extension-web.js` (CRITICAL)
- `.vsixmanifest` (HIGH)
- `.env` files (HIGH)
- JavaScript files in `dist/` and `out/` directories (HIGH)
- Shell scripts (`.sh`) (CRITICAL)
- XML files (CRITICAL)
- Java files (`.jar`, `.class`) (CRITICAL)

### Suspicious Patterns
- Hardcoded IP addresses
- Hardcoded credentials
- Suspicious network calls
- Suspicious VSIX manifest entries
- And more...

Each pattern is associated with a severity level (INFO, LOW, MEDIUM, HIGH, CRITICAL) to help prioritize findings.

## Security Issue Model

The tool uses a structured model for reporting security issues:

```python
class SecurityIssue:
    description: str          # Description of the issue
    severity: Severity       # Severity level (INFO, LOW, MEDIUM, HIGH, CRITICAL)
    context: str            # Additional context about the finding
    file_path: Path         # Path to the file containing the issue
    line_number: Optional[int]  # Line number where the issue was found
```
