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
- **YARA Integration**: Complete YARA framework with templates, builder, and validation tools
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

The tool provides a complete YARA integration framework without pre-made detection rules. This approach avoids false positives while giving you full control over detection logic.

### Why No Pre-Made Rules?

To avoid shipping rules that cause false positives, this tool provides the framework and templates instead. You create only the rules you need, tested against your specific use cases.

### What's Included

- **5 Rule Templates** covering common threat categories
- **Interactive Rule Builder** for guided rule creation
- **Validation Tools** to test rules before deployment
- **Configuration System** for managing YARA behavior

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

**Option 1: Interactive Builder**

```bash
python -m ide_hunter --create-yara-rule
```

This guides you through creating a rule from templates.

**Option 2: Manual Creation**

1. Copy a template from `yara/templates/` directory:
   ```bash
   cp yara/templates/credential_theft_template.yar yara/my_rule.yar
   ```

2. Edit the rule to match your specific detection needs

3. Validate the syntax:
   ```bash
   python -m ide_hunter --validate-yara
   ```

4. Test against a file:
   ```bash
   python -m ide_hunter --yara-test path/to/test_file.js
   ```

**Available Templates:**

1. **basic_template.yar** - General-purpose template for any detection rule
   - Start here if you're creating a new type of detection
   - Contains all basic YARA syntax with examples

2. **obfuscation_template.yar** - For detecting encoded or hidden malicious code
   - Base64 encoding, hex encoding, string obfuscation, character code manipulation

3. **credential_theft_template.yar** - For detecting credential access attempts
   - Browser cookies, SSH keys, API tokens, environment variables

4. **exfiltration_template.yar** - For detecting data being sent to external servers
   - Webhooks (Discord, Telegram, etc.), file uploads, data collection + network communication

5. **c2_template.yar** - For detecting command and control patterns
   - Reverse shells, WebSocket C2, HTTP beaconing, remote code execution

### Best Practices

1. **Test thoroughly** - Validate rules against both malicious and clean code
2. **Be specific** - Narrow rules reduce false positives
3. **Document intent** - Use clear descriptions in rule metadata
4. **Start simple** - Begin with basic patterns, refine as needed
5. **Version control** - Track rule changes over time

### YARA Syntax Reference

**String Modifiers:**
- `nocase` - Case-insensitive matching
- `wide` - Match UTF-16 strings
- `fullword` - Match only complete words

**Condition Operators:**
- `any of them` - At least one string matches
- `all of them` - All strings must match
- `#string > N` - String appears more than N times
- `$string at 0` - String at specific offset

**Regular Expressions:**
YARA supports basic regex:
- `\w` `\d` `\s` - Word chars, digits, whitespace
- `*` `+` `?` - Quantifiers
- `[abc]` - Character classes
- `^` `$` - Anchors

**Not supported:**
- `(?:...)` non-capturing groups (use `(...)` instead)
- Backreferences
- POSIX character classes

**Testing Workflow:**
1. Create rule from template
2. Validate: `python -m ide_hunter --validate-yara`
3. Test on malicious sample: `python -m ide_hunter --yara-test malicious.js`
4. Test on clean code: `python -m ide_hunter --yara-test clean.js`
5. Adjust to reduce false positives
6. Deploy to production

### Severity Levels

Severity can be specified in two ways:
1. Numeric values (0-4):
   - 0: INFO
   - 1: LOW
   - 2: MEDIUM
   - 3: HIGH
   - 4: CRITICAL
2. String values: "info", "low", "medium", "high", "critical"

**Example YARA Rules:**

```yara
rule Suspicious_Eval_Usage {
    meta:
        description = "Detects eval with base64 decoding"
        severity = 3
        category = "obfuscation"
        author = "Your Name"
        date = "2025-01-21"

    strings:
        $eval = "eval("
        $atob = "atob("
        $base64 = "base64"

    condition:
        $eval and ($atob or $base64)
}

rule Suspicious_API {
    strings:
        $api = "dangerousAPI("
        $import = "require('dangerous-module')"
    condition:
        $api and $import
}

rule Heavy_Obfuscation {
    strings:
        $obf = /_0x[a-f0-9]+/
    condition:
        #obf > 20
}
```

For more help, check the official YARA documentation: https://yara.readthedocs.io/

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
