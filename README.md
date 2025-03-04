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
IDE Extension Hunter is a forensic security tool designed to scan and analyze Visual Studio Code and PyCharm extensions for potential security risks, malicious code patterns, and suspicious behaviors.

    Multi-IDE Support: Scans both VS Code and PyCharm extensions
    Comprehensive Pattern Detection: Identifies malicious patterns in extension code
    Severity-Based Analysis: Categorizes findings by severity level (INFO → CRITICAL)
    YARA Integration: Leverages YARA rules for deeper analysis
    Flexible Reporting: Outputs to CSV or terminal with detailed context
    URL Extraction: Lists all URLs found in high-risk files
    Cross-Platform: Works on Windows, macOS, and Linux

Installation
bashCopy# Clone the repository
git clone https://github.com/pigeonsmaster/ide-extension-hunter.git
cd ide-extension-hunter

## Install dependencies
pip install -r requirements.txt

## Install the package in development mode
pip install -e .
Usage
Basic Usage
bashCopy# Run the scanner with default settings
python -m ide_hunter

## Or use the entry point script
python IDE_Extension_Hunter.py
Command Line Options
OptionDescription--metadataPrint only extension metadata without security findings--list-urlsExtract all URLs found in high-risk files--ide {vscode,pycharm}Specify which IDE extensions to scan (default: both)-p, --path PATHCustom extensions directory path-o, --output FILEOutput file path for CSV report--severity {INFO,LOW,MEDIUM,HIGH,CRITICAL}Specify severity level to report--use-yaraEnable YARA-based scanning
Examples
bashCopy# Scan VS Code extensions and output to CSV
python -m ide_hunter --ide vscode -o report.csv

## Extract all URLs from PyCharm extensions
python -m ide_hunter --ide pycharm --list-urls

## Scan custom directory with YARA rules
python -m ide_hunter -p /path/to/extensions --use-yara

## Only show HIGH severity findings
python -m ide_hunter --severity HIGH

## Print only metadata without security scanning
python -m ide_hunter --metadata

## Project Architecture
The project has been restructured into a modular, maintainable architecture:
CopyIDE_Extension_Hunter/
│
├── IDE_Extension_Hunter.py        # Main entry point script
├── README.md                      # Project documentation
├── requirements.txt               # Python dependencies
├── setup.py                       # Installation script
├── .gitignore                     # Git ignore configuration
├── .env.example                   # Example environment variables
│
├── ide_hunter/                    # Main package
│   ├── __init__.py                # Package initialization
│   ├── __main__.py                # Entry point for running as module
│   ├── cli.py                     # Command-line interface 
│   ├── scanner.py                 # Core scanner class
│   ├── models.py                  # Data models (SecurityIssue, etc.)
│   ├── patterns.py                # Malicious pattern definitions
│   │
│   ├── utils/                     # Utility functions
│   │   ├── __init__.py
│   │   ├── logging_utils.py       # Logging setup
│   │   ├── hash_utils.py          # File hash computation
│   │   └── file_utils.py          # File operations
│   │
│   ├── analyzers/                 # Analysis components
│   │   ├── __init__.py
│   │   ├── yara_analyzer.py       # YARA-specific scanning
│   │   ├── pattern_analyzer.py    # Regex pattern scanning
│   │   ├── manifest_analyzer.py   # VSIX manifest analysis
│   │   └── metadata_analyzer.py   # Extension metadata extraction
│   │
│   └── reporters/                 # Output formatters
│       ├── __init__.py
│       ├── csv_reporter.py        # CSV report generation
│       ├── console_reporter.py    # Console output formatting
│       └── url_reporter.py        # URL extraction and reporting
│
├── yara/                          # YARA rules directory
│   └── malicious_extension.yar    # Sample YARA rules
│
└── logs/                          # Log directory
Key Components

Models: Defines data structures used throughout the application
Scanner: Core scanning engine that orchestrates the analysis process
Analyzers: Specialized components for different types of analysis
Reporters: Components for formatting and displaying results
Utils: Helper functions and utilities

This architecture provides several benefits:

Modularity: Each component has a single responsibility
Maintainability: Easy to understand and modify individual parts
Testability: Enables writing unit tests for individual components
Extensibility: Easy to add new analyzers or reporters

##YARA Rules
The tool supports custom YARA rules for enhanced malware detection. Place your .yar or .yara files in the yara/ directory.
Security Patterns Detected

##The tool looks for several categories of suspicious patterns

Hardcoded IPs and webhooks
Obfuscated or encoded code
Suspicious file system operations
System data access attempts
Crypto targeting code
Potential reverse shells
Credential exposure
Database operations on sensitive data
And many more...

## Setting Up Development Environment

Fork the repository
Clone your fork: git clone https://github.com/YOUR_USERNAME/ide-extension-hunter.git
Create a virtual environment: python -m venv venv
Activate the environment:

Windows: venv\Scripts\activate
Unix/MacOS: source venv/bin/activate


Install dev dependencies: pip install -r requirements-dev.txt
Install the package in development mode: pip install -e .

##Development Workflow

Create a feature branch: git checkout -b feature/your-feature-name
Make your changes
Run tests to ensure everything works: pytest
Format your code: black ide_hunter
Check for linting issues: flake8 ide_hunter
Commit your changes: git commit -m "Add some feature"
Push to your fork: git push origin feature/your-feature-name
Create a Pull Request

##Code Structure and Organization
The project follows a modular architecture with clear separation of concerns:

Core Components: scanner.py contains the main scanner class that orchestrates the analysis
Analyzers: Add new detection capabilities in ide_hunter/analyzers/
Reporters: Add new output formats in ide_hunter/reporters/
Models: Define data structures in models.py
Patterns: Define malicious patterns in patterns.py

## How to Add New Features
Adding a New Analyzer
To add a new type of analysis:

Create a new file in ide_hunter/analyzers/
Define a class that implements at least a scan_file method
Add the analyzer to the scanner initialization

Example:
pythonCopy# ide_hunter/analyzers/my_analyzer.py
class MyAnalyzer:
    def __init__(self):
        # Initialize analyzer
        pass
        
    async def scan_file(self, file_path):
        # Implement analysis logic
        return []  # Return list of SecurityIssue objects
## Adding New Patterns
To add new malicious patterns:

Update ide_hunter/patterns.py with your new patterns
Group related patterns under appropriate categories
Assign appropriate severity levels

Example:
pythonCopy# In patterns.py
"My New Pattern Category": {
    "severity": Severity.HIGH,
    "patterns": [
        r"pattern1",
        r"pattern2"
    ]
}
## Adding a New Reporter
To add a new report format:

Create a new file in ide_hunter/reporters/
Implement the reporting logic
Update the scanner to use your new reporter

## Code Style
We follow these code style guidelines:

Follow PEP 8 with a line length of 100 characters
Use descriptive variable and function names
Add type hints to function signatures
Document classes and functions with docstrings
Use async/await for I/O-bound operations

## Testing
When adding new features, please include appropriate tests:

Unit tests for individual components
Integration tests for feature workflows
Place tests in the tests/ directory
Ensure tests are isolated and don't depend on external state

## Documentation
When adding new features, please update the documentation:

Add docstrings to new functions and classes
Update README.md if necessary
Add comments for complex code sections

## License
This project is licensed under the MIT License - see the LICENSE file for details.
Acknowledgments

## Contact&Support
Email - pigeonsmaster@proton.me

##Contributing
Contributions to IDE Extension Hunter are welcome! The project has been designed to be modular and extensible, making it easy to contribute new features or improvements.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

