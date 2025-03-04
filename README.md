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

IDE Extension Hunter scans VS Code and PyCharm extensions for suspicious code patterns, malicious behaviors, and security vulnerabilities. The tool helps developers and security professionals identify potentially harmful extensions before installation.

## Features

- 🔍 **Multi-IDE Support**: Scans VS Code and PyCharm extensions
- 🛡️ **Comprehensive Pattern Detection**: Identifies malicious patterns in code
- 🔬 **YARA Integration**: Uses YARA rules for deeper analysis
- 📝 **Flexible Reporting**: Outputs to CSV or terminal
- 🌐 **URL Extraction**: Lists all embedded URLs
- 💻 **Cross-Platform**: Works on Windows, macOS, and Linux

## Installation

```bash
# Clone the repository
git clone https://github.com/pigeonsmaster/ide-extension-hunter.git
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

# Filter by severity
python -m ide_hunter --severity HIGH

# Scan with YARA rules
python -m ide_hunter --use-yara
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



