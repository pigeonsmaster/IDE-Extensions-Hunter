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
- **YARA Integration**: Uses YARA rules for deeper analysis with configurable severity levels (numeric 0-4 or string values)
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

# Enable debug logging
python -m ide_hunter --debug
```

## Project Structure

```
IDE_Extension_Hunter/
├── IDE_Extension_Hunter.py        # Main entry point
├── ide_hunter/                    # Core package
│   ├── analyzers/                 # Analysis modules
│   ├── reporters/                 # Output formatters
│   └── utils/                     # Utility functions
├── yara/                          # YARA rules directory
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
- **Reporters**: Add new output formats in `ide_hunter/reporters/`

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Contact&Support
Email - pigeonsmaster@proton.me

## YARA Rules

The tool supports YARA rules with configurable severity levels. Severity can be specified in two ways:
1. Numeric values (0-4):
   - 0: INFO
   - 1: LOW
   - 2: MEDIUM
   - 3: HIGH
   - 4: CRITICAL
2. String values: "info", "low", "medium", "high", "critical"

Example YARA rule with severity:
```yara
rule suspicious_network_activity {
    meta:
        severity = "high"  // or severity = 3
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
