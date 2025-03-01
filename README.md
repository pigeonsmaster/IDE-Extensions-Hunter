<p align="center">
  <img src="" width="400"><br>
  <b>IDE's Extensions Hunter</b>
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

IDE Extension Hunter is a forensic security tool designed to scan and analyze Visual Studio Code and PyCharm extensions for potential security risks, malicious code patterns, and suspicious behaviors. This tool is developed to help developers, security professionals, and IT administrators to vet IDE extensions for security issues before installation or as part of regular security audits.

## Features

- 🔍 Multi-IDE Support: Scans both VS Code and PyCharm extensions
- 🛡️ Comprehensive Pattern Detection: Identifies malicious patterns in extension code
- 📊 Severity-Based Analysis: Categorizes findings by severity level (INFO → CRITICAL)
- 🔬 YARA Integration: Leverages YARA rules for deeper analysis
- 📝 Flexible Reporting: Outputs to CSV or terminal with detailed context
- 🌐 URL Extraction: Lists all URLs found in high-risk files
- 💻 Cross-Platform: Works on Windows, macOS, and Linux

## Installation

```bash
# Clone the repository
git clone https://github.com/yourusername/ide-extension-hunter.git
cd ide-extension-hunter

# Install dependencies
pip install -r requirements.txt
```

## Usage

```bash
python main.py [options]
```

### Command Line Options

| Option | Description |
|--------|-------------|
| `--ide {vscode,pycharm}` | Specify which IDE extensions to scan (default: both) |
| `-p, --path PATH` | Custom extensions directory path |
| `-o, --output FILE` | Output file path for CSV report |
| `--min-severity {INFO,LOW,MEDIUM,HIGH,CRITICAL}` | Minimum severity level to report |
| `--use-yara` | Enable YARA-based scanning |
| `--list-urls` | Extract all URLs from high-risk files |

### Examples

```bash
# Scan VS Code extensions and output to CSV
python IDE_Extension_Hunter.py --ide vscode -o report.csv

# Extract all URLs from PyCharm extensions
python IDE_extensions_hunter.py --ide pycharm --list-urls

# Scan custom directory with YARA rules
python IDE_extensions_hunter.py -p /path/to/extensions --use-yara

# Only show HIGH and CRITICAL severity findings
python IDE_extensions_hunter.py --min-severity HIGH
```

## YARA Rules

The tool supports custom YARA rules for enhanced malware detection. Place your `.yar` or `.yara` files in the `yara/` directory.

## Understanding Results

Scan results are presented based on severity levels:

- **CRITICAL**: Requires immediate attention, likely malicious
- **HIGH**: Potentially dangerous behavior
- **MEDIUM**: Suspicious but requires investigation
- **LOW**: Minor concerns
- **INFO**: Informational findings

## Security Patterns Detected

The tool looks for several categories of suspicious patterns:

- Hardcoded IPs and webhooks
- Obfuscated or encoded code
- Suspicious file system operations
- System data access attempts
- Crypto targeting code
- Potential reverse shells
- Credential exposure
- Database operations on sensitive data

## Contact&Support
Email - pigeonsmaster@proton.me

## Contributing

Contributions are welcome! Please feel free to submit a PR

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

