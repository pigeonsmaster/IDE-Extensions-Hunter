# IDE Extensions Hunter - Project Architecture

## High-Level Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    Entry Points                             │
├─────────────────────────────────────────────────────────────┤
│  IDE_Extension_Hunter.py  │  ide_hunter/__main__.py        │
│  (Legacy entry)           │  (Module entry point)          │
└─────────────────────────────────────────────────────────────┘
                                │
                                ▼
┌─────────────────────────────────────────────────────────────┐
│                  CLI Layer                                  │
├─────────────────────────────────────────────────────────────┤
│  ide_hunter/cli.py                                          │
│  • Argument parsing                                         │
│  • Banner display                                           │
│  • Async execution coordination                             │
└─────────────────────────────────────────────────────────────┘
                                │
                                ▼
┌─────────────────────────────────────────────────────────────┐
│                 Core Scanner                                │
├─────────────────────────────────────────────────────────────┤
│  ide_hunter/scanner.py                                      │
│  • IDEextensionsscanner class                               │
│  • Parallel file processing                                 │
│  • Progress tracking                                        │
│  • Results aggregation                                      │
└─────────────────────────────────────────────────────────────┘
                                │
                                ▼
┌─────────────────────────────────────────────────────────────┐
│                Analysis Layer                               │
├─────────────────────────────────────────────────────────────┤
│  ide_hunter/analyzers/                                      │
│  ├── pattern_analyzer.py    │  Regex-based detection        │
│  ├── yara_analyzer.py       │  YARA rule engine             │
│  ├── manifest_analyzer.py   │  VSIX manifest analysis       │
│  └── metadata_analyzer.py   │  Extension metadata extraction│
└─────────────────────────────────────────────────────────────┘
                                │
                                ▼
┌─────────────────────────────────────────────────────────────┐
│                Reporting Layer                              │
├─────────────────────────────────────────────────────────────┤
│  ide_hunter/reporters/                                      │
│  ├── console_reporter.py    │  Terminal output              │
│  ├── csv_reporter.py        │  CSV file generation          │
│  └── url_reporter.py        │  URL extraction & reporting   │
└─────────────────────────────────────────────────────────────┘
                                │
                                ▼
┌─────────────────────────────────────────────────────────────┐
│                Utilities Layer                              │
├─────────────────────────────────────────────────────────────┤
│  ide_hunter/utils/                                          │
│  ├── file_utils.py          │  File system operations       │
│  ├── hash_utils.py          │  SHA1 computation             │
│  ├── logging_utils.py       │  Logging configuration        │
│  ├── output.py              │  Formatted output             │
│  └── progress.py            │  Progress tracking            │
└─────────────────────────────────────────────────────────────┘
                                │
                                ▼
┌─────────────────────────────────────────────────────────────┐
│                Data Models                                  │
├─────────────────────────────────────────────────────────────┤
│  ide_hunter/models.py                                       │
│  • SecurityIssue dataclass                                  │
│  • ExtensionMetadata dataclass                              │
│  • Severity enum                                            │
└─────────────────────────────────────────────────────────────┘
                                │
                                ▼
┌─────────────────────────────────────────────────────────────┐
│                Configuration                                │
├─────────────────────────────────────────────────────────────┤
│  ide_hunter/patterns.py     │  Detection patterns           │
│  yara/                      │  YARA rule files              │
│  ├── crypto_mining.yar      │  Crypto mining detection      │
│  └── malicious_extension.yar│  General malicious patterns   │
└─────────────────────────────────────────────────────────────┘
```

## Data Flow

1. **Entry** → CLI argument parsing
2. **Initialization** → Scanner setup with analyzers
3. **Discovery** → Find extension directories
4. **Analysis** → Parallel file scanning with multiple analyzers
5. **Aggregation** → Collect results and compute hashes
6. **Reporting** → Format and output results

## Key Components

### Core Scanner (`scanner.py`)
- **Main orchestrator** for the entire scanning process
- Handles **parallel processing** with ThreadPoolExecutor
- Manages **progress tracking** and **error handling**
- Coordinates between different analyzers

### Analysis Engines
- **PatternAnalyzer**: Regex-based malicious pattern detection
- **YaraAnalyzer**: YARA rule-based analysis (optional)
- **ManifestAnalyzer**: VSIX manifest security analysis
- **MetadataAnalyzer**: Extension metadata extraction

### Detection Patterns (`patterns.py`)
- **206 lines** of comprehensive malicious patterns
- Covers: hardcoded credentials, file manipulation, crypto mining, reverse shells, obfuscation
- **Severity levels**: INFO (0) → CRITICAL (4)

### YARA Integration
- **Crypto mining detection** with severity levels
- **Configurable severity** (numeric 0-4 or string values)
- **Optional dependency** (graceful fallback if not installed)
