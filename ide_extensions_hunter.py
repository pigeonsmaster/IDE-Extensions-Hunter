import os
import re
import json
import csv
import hashlib
import logging
import asyncio
import aiofiles
from typing import Dict, Set, List, Optional
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
import xml.etree.ElementTree as ET
from tabulate import tabulate
from enum import Enum
import argparse
import fnmatch
import sys
import yara
import requests
import itertools
from pathlib import Path
from typing import List, Dict, Optional, Set
import xml.etree.ElementTree as ET
import platform
import aiohttp


def parse_cli_arguments():

    ascii_banner = """    
██╗██████╗ ███████╗    ███████╗██╗  ██╗████████╗    ██╗  ██╗██╗   ██╗███╗   ██╗████████╗███████╗██████╗ 
██║██╔══██╗██╔════╝    ██╔════╝╚██╗██╔╝╚══██╔══╝    ██║  ██║██║   ██║████╗  ██║╚══██╔══╝██╔════╝██╔══██╗
██║██║  ██║█████╗      █████╗   ╚███╔╝    ██║       ███████║██║   ██║██╔██╗ ██║   ██║   █████╗  ██████╔╝
██║██║  ██║██╔══╝      ██╔══╝   ██╔██╗    ██║       ██╔══██║██║   ██║██║╚██╗██║   ██║   ██╔══╝  ██╔══██╗
██║██████╔╝███████╗    ███████╗██╔╝ ██╗   ██║       ██║  ██║╚██████╔╝██║ ╚████║   ██║   ███████╗██║  ██║
╚═╝╚═════╝ ╚══════╝    ╚══════╝╚═╝  ╚═╝   ╚═╝       ╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═══╝   ╚═╝   ╚══════╝╚═╝  ╚═╝
══════════════════════════════════════════════════════════════════
IDE extensions Forensics
By Almog Mendelson
Scan and analyze IDE Code extensions for potential security risks.
══════════════════════════════════════════════════════════════════         
    """
    # Argument parser with ASCII banner in description
    parser = argparse.ArgumentParser(
        description=ascii_banner,
        epilog="""
🔍IDE Extension Hunter

  Advanced Security Scanner for IDE Extension

🛡️Description

  IDE Extension Hunter is a forensic tool designed to analyze IDE extensions for malicious indicators.

⚡ Features

    - Detects malicious patterns embedded in IDE extension files  
    - Integrated with YARA rules for enhanced security analysis  
    - Export results in CSV format or prints them to the terminal  
    - Filters findings based on severity (INFO → CRITICAL)
    
""",
        formatter_class=argparse.RawTextHelpFormatter,  # Preserves ASCII formatting
    )

    parser.add_argument(
        "--list-urls",
        action="store_true",
        help="Extract all URLs found in high-risk files",
    )
    parser.add_argument(
        "--ide",
        type=str,
        choices=["vscode", "pycharm"],
        # default="vscode",
        help="Specify the IDE to scan ('vscode' or 'pycharm')",
    )

    # Output file arguments
    parser.add_argument(
        "-o",
        "--output",
        type=str,
        help="Specify custom output CSV file path",
    )

    # Scan-specific arguments
    parser.add_argument(
        "-p",
        "--path",
        type=str,
        default=None,
        help="Custom VS Code extensions directory path",
    )

    # Severity threshold
    parser.add_argument(
        "--severity",
        type=str,
        choices=["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"],
        default=None,
        help="severity level to report",
    )

    # Enable YARA scanning flag
    parser.add_argument(
        "--use-yara",
        action="store_true",
        help="Enable YARA-based scanning for deeper analysis",
    )

    return parser.parse_args()


class Severity(Enum):
    CRITICAL = 4
    HIGH = 3
    MEDIUM = 2
    LOW = 1
    INFO = 0


@dataclass
class SecurityIssue:
    """Structured container for security issues."""

    description: str
    severity: Severity
    context: str
    file_path: Path
    line_number: Optional[int] = None


@dataclass
class ExtensionMetadata:
    """Structured container for extension metadata and scan results."""

    name: str
    version: Optional[str] = None
    publisher: Optional[str] = None
    urls: Dict[str, str] = None
    security_issues: List[SecurityIssue] = None
    scanned_files: Set[Path] = None
    sha1_hashes: Dict[Path, str] = None

    def __post_init__(self):
        self.urls = self.urls or {}
        self.security_issues = self.security_issues or []
        self.scanned_files = self.scanned_files or set()
        self.sha1_hashes = self.sha1_hashes or {}


class IDEextensionsscanner:
    """Enhanced scanner for VS Code & PyCharm extensions on Windows, Linux, and macOS."""

    def __init__(
        self,
        ide: str = None,
        extensions_path: Optional[str] = None,
        use_yara: bool = False,
    ):
        """
        Initialize the scanner with paths for VS Code and PyCharm.

        Args:
            ide (str): Specify 'vscode', 'pycharm', or None (default: scan both)
            extensions_path (Optional[str]): Custom extension path to scan
            use_yara (bool): Enable YARA scanning
        """
        self.ide = ide.lower() if ide else "both"

        if self.ide not in ["vscode", "pycharm", "both"]:
            raise ValueError("Invalid IDE type! Use 'vscode', 'pycharm', or 'both'.")

        self.use_yara = use_yara
        # Intialize YARA rules if the flag is enabled
        self.yara_rules = self.load_yara_rules() if self.use_yara else None
        # Detect OS Type
        self.os_type = (
            platform.system().lower()
        )  # "windows", "linux", or "darwin" (macOS)

        default_paths = []

        if self.ide in ["vscode", "both"]:
            if self.os_type == "windows":
                default_paths.append(
                    os.path.expandvars(r"%USERPROFILE%\.vscode\extensions")
                )
            else:  # Linux & macOS
                default_paths.append(os.path.expanduser("~/.vscode/extensions"))

        if self.ide in ["pycharm", "both"]:
            if self.os_type == "windows":
                pycharm_base_path = Path(
                    os.path.expandvars(r"%APPDATA%\JetBrains")
                )  # Windows
            else:
                pycharm_base_path = Path(
                    os.path.expanduser("~/Library/Application Support/JetBrains/")
                )  # macOS/Linux

            default_paths.extend(
                str(path / "plugins") for path in pycharm_base_path.glob("PyCharm*")
            )

        # Use user-specified path if provided, otherwise use default
        if extensions_path:
            self.extensions_paths = [Path(os.path.expanduser(extensions_path))]
        else:
            # Filter out non-existent paths
            self.extensions_paths = [
                Path(path) for path in default_paths if os.path.exists(path)
            ]

        self.scanned_files = set()  # Track files that have been scanned
        self.setup_logging()

        self.logger.debug(f"Scanning extension directories: {self.extensions_paths}")

        self.SUSPICIOUS_VSIX_ENTRIES = (
            {
                "script": Severity.HIGH,
                "entryPoint": Severity.CRITICAL,
                "dependencies": Severity.MEDIUM,
                "extensionDependencies": Severity.MEDIUM,
            },
        )

        # Define high-risk files to scan
        self.HIGH_RISK_FILES = {
            "package.json": Severity.HIGH,
            "extension.js": Severity.CRITICAL,
            "extension-web.js": Severity.CRITICAL,
            ".vsixmanifest": Severity.HIGH,
            ".env": Severity.HIGH,
            "*.js": Severity.MEDIUM,  # Catch all JavaScript files
            "*tracker*.js": Severity.HIGH,  # Extra attention to files with 'tracker'
            "*network*.js": Severity.HIGH,  # Files related to network operations
            "dist/*.js": Severity.HIGH,
            "out/*.js": Severity.HIGH,
            "src/*.js": Severity.MEDIUM,
            "*.sh": Severity.CRITICAL,
            "*.xml": Severity.CRITICAL,
            "*.jar": Severity.CRITICAL,
            "*.class": Severity.HIGH,
        }

        self.MALICIOUS_PATTERNS = (
            {
                "Hardcoded IP": {
                    "severity": Severity.HIGH,
                    "patterns": [
                        # Detect IPs in HTTP/HTTPS URLs with more flexibility
                        r"https?://(?!127\.0\.0\.1)(?:\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})(?::\d+)?",
                        # Detect IPs in string contexts
                        r"['\"](https?://(?!127\.0\.0\.1)(?:\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})(?::\d+)?)['\"]",
                        # Detect potential tracking or logging of external IPs
                        r"(?:track|log|send|report).*(?:\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})",
                        # Detect axios or fetch calls to external IPs
                        r"(?:axios|fetch)\.(?:get|post).*['\"](https?://(?!127\.0\.0\.1)(?:\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}))",
                    ],
                },
                "Moc Hardcoded Credentials": {
                    "severity": Severity.CRITICAL,
                    "patterns": [
                        r"<apikey>[^<]+</apikey>",  # API keys
                        r"<password>[^<]+</password>",  # Passwords
                        r"<db_connection>[^<]+</db_connection>",  # Database connections
                    ],
                },
                "Suspicious File Manipulation": {
                    "severity": Severity.CRITICAL,
                    "patterns": [
                        r"fopen\s*\(\s*[\"']/?etc/passwd[\"']",  # Unix password file access
                        r"fopen\s*\(\s*[\"']C:\\Windows\\System32",  # Windows system file access
                        r"rmdir\s+\-rf",  # Recursive directory deletion
                        r"mv\s+.*\s+/dev/null",  # Hiding files
                        r"chmod\s*\(\s*\d{3,4}",  # Modifying file permissions
                        r"rm\s+-rf\s+/",  # Wiping the entire system
                        r"tar\s+cf\s+-\s+.*\s+\|\s+nc\s+",  # Exfiltration using Netcat
                        r"scp\s+-r\s+",  # Secure copy of files
                        r"curl\s+-o\s+",  # Downloading malicious payloads
                        r"wget\s+-q\s+",  # Quiet downloads (avoid detection)
                        r"echo\s+.*>\s+/dev/.*",  # Writing to device files
                        r"dd\s+if=.*\s+of=.*",  # Disk dumping
                        r"base64\s+-d",  # Decoding obfuscated data
                        r"gpg\s+--decrypt",  # Decrypting files
                        r"cat\s+/root/.ssh/id_rsa",  # Extracting SSH keys
                        r"cat\s+/home/\w+/\.bash_history",  # Reading command history
                        r"zip\s+-r\s+.*\s+\|",  # Compressing data for exfiltration
                        r"\b( echo\s+['\"']root::0:0:root:/root:/bin/bash['\"']\s*>\s*/etc/shadow| cat\s+/etc/shadow| cat\s+/etc/passwd| rm\s+-rf\s+/.* | wget\s+.*\.\(sh\|exe\|php\)\s+-O\s+/tmp/)\b",
                    ],
                },
                "Suspicious Database Operations": {
                    "severity": Severity.CRITICAL,
                    "patterns": [
                        r"SELECT.*FROM\s+cookies",  # Cookie database queries
                        r"sqlite3\.Database",  # SQLite operations
                        r"encrypted_value",  # Chrome cookie fields
                        r"host_key.*name.*value.*encrypted_value",  # Cookie data extraction
                    ],
                },
                "System Access Attempts": {
                    "severity": Severity.CRITICAL,
                    "patterns": [
                        r"System32\\config\\RegBac",
                        r"Chrome.*User Data.*Cookies",
                        r"AppData\\Local\\Google\\Chrome",
                    ],
                },
                "Discord Webhook": {
                    "severity": Severity.CRITICAL,
                    "patterns": [
                        r"https?://(?:ptb\.|canary\.)?discord(?:app)?\.com/api/webhooks/",
                    ],
                },
                "Obfuscation Indicators": {
                    "severity": Severity.HIGH,
                    "patterns": [
                        r"(?:['\"`;,\s])(?:TVqQ|yMjA|f0VM|UEsD|DQog|H4sI|e1xs)(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{3}=|[A-Za-z0-9+/]{2}==)?",  # Common file headers in base64
                        r"(?:atob|decodeURIComponent)\s*\(\s*[\"'][^\"']+[\"']\s*\)"
                        r"(?:btoa|atob)\s*\(\s*(?:fetch|require|exec|eval)",  # Base64 with dangerous functions
                        r"(?:eval|exec|Function)\s*\(\s*(['\"`;,\s])(?:[A-Za-z0-9+/]{100,}={0,2})\1\s*\)",  # Large encoded strings
                        r"_0x[a-f0-9]{4,}",  # Common JavaScript obfuscation pattern
                        r"\[[\"'][^\]]+[\"']\]\[[\"'][^\]]+[\"']\]",  # Chained obfuscated lookups
                        # r"(?:push|shift|unshift)\s*\(\s*[\"'][^\"']+[\"']\s*\)",  # String array shifts and pushes
                        r"atob\s*\(\s*['\"]([A-Za-z0-9+/=]+)['\"]\s*\)\s*(?:\)|;)?\s*(?:\w+\s*=\s*)?(?:eval|exec|new\s+Function|\.call|\.apply|\(\))"
                        r"const\s+_0x[a-f0-9]+\s*=\s*\[(?:\s*['\"][^'\"]{10,}['\"],?\s*){5,}\]",  # Large arrays of encoded strings
                        r"function\s+_0x[a-f0-9]+\s*\([^)]*\)\s*{\s*return\s+atob\s*\(",  # Obfuscated decoding functions
                        r"new\s+Function\s*\([^)]*atob\s*\(",  # Dynamic function creation with base64 decoding
                        r"eval\s*\(\s*String\.fromCharCode\s*\(",  # Character code obfuscation
                        # r"\\x[0-9a-f]{2}",  # Hex-encoded character obfuscation
                        r"(?:window\.|global\.)?[a-zA-Z_$]+\[[\"'][a-zA-Z_$]+[\"']\]\([^)]*\)",  # Indirect function calls typical in obfuscation
                        r"\b(?:eval\s*\(\s*(?:echo|base64|cat|sh)|echo\s+['\"']YmFzaCAtaSA+Ji9kZXYvdGNwLz|base64\s+-d\s+(?!-w|--wrap)|chmod\s+\d{3,4}\s+/bin/sh|\$\(\s*echo\s+['\"']?[A-Za-z0-9+/=]+['\"']?\s*\|\s*base64\s+-d\s*\))\b",
                        r"eval\s*\(\s*Buffer\.from\s*\(\s*['\"]([A-Za-z0-9+/=]+)['\"]\s*,\s*['\"]base64['\"]\s*\)\.toString\(['\"]utf8['\"]\)\)",
                    ],
                    "Hex Encoding Obfuscation": {
                        "severity": Severity.HIGH,
                        "patterns": [
                            r"\\x[0-9a-fA-F]{2}(\s*\\x[0-9a-fA-F]{2})+",  # Detects shellcode-like hex strings
                            r"0x[a-fA-F0-9]{8,}",  # Long hex-encoded values (common in obfuscation)
                            r"decode\([\"']?([0-9a-fA-F]{4,})[\"']?\)",  # Decode function calls with hex values
                            r"(unescape\(|eval\(|exec\()([\"']?%[0-9a-fA-F]{2})+",  # URL-encoded shellcode execution
                            r"(?:charcode|fromCharCode)\(\d{3,}\)",  # Large character encoding sequences
                            r"\\u00[a-fA-F0-9]{2}",  # Unicode encoding for obfuscation
                            r"\b(hex|base64)decode\b",  # Calls to decoding functions
                        ],
                    },
                },
                "Crypto Targeting": {
                    "severity": Severity.HIGH,
                    "patterns": [
                        r"\b(?:ethereum|solidity|blockchain|evm)\b",  # Ensures it's a standalone word
                        r"(?<!\w)(?:contract\.handler|web3)(?!\w)",  # Avoids partial matches inside words
                    ],
                },
                "Revers Shell": {
                    "severity": Severity.CRITICAL,
                    "patterns": [
                        #
                        r"\b(socket\.socket|New-Object\s+System\.Net\.Sockets\.TCPClient|net\.Dial|new\s+net\.Socket|socket\(SOCK|bash\s+-i\s+>&\s+/dev/tcp|fsockopen\(|fetch\s*\(\s*['\"]https?://(?:\d{1,3}\.){3}\d{1,3}[:/]?\d*|new\s+WebSocket\s*\(\s*['\"]wss?://(?:\d{1,3}\.){3}\d{1,3}[:/]?\d*|XMLHttpRequest\s*\(\)\.open\s*\(\s*['\"]GET['\"]\s*,\s*['\"]https?://(?:\d{1,3}\.){3}\d{1,3}[:/]?\d*|JSON\.parse\s*\(\s*(?:atob|base64_decode|str_rot13|gzinflate|gzuncompress|rawurldecode|hex2bin)\)|JSON\.stringify\s*\(\s*\{?\s*['\"]?command['\"]?\s*:\s*['\"]?(?:shell_exec|eval|exec|system)['\"]?|document\.write\s*\(\s*(?:atob|base64_decode|decodeURIComponent)\)|eval\s*\(\s*(?:JSON\.parse|atob|decodeURIComponent)\)|new\s+Function\s*\([^)]*(?:atob|base64_decode)\)|XMLHttpRequest\s*\(\)\.send\s*\(\s*(?:JSON\.stringify|JSON\.parse)\)|WebSocket\s*\(\s*['\"]wss?:\/\/(?:\d{1,3}\.){3}\d{1,3}(?::\d+)?['\"]?\))\b",
                        r"(?s)\b(bash\s+-i\s+>&\s+/dev/tcp|nc\s+-e\s+/bin/sh|base64\s+-d|curl\s+-X\s+POST).*?",
                    ],
                },
                "Malicious C Code": {
                    "severity": Severity.CRITICAL,
                    "patterns": [
                        r"system\s*\(.*\)",  # Detects system calls (`system("cmd")`)
                        r"execve\s*\(",  # Detects direct execution of shell
                        r"fork\(\)\s*&&\s*execve",  # Detects double fork technique for process hiding
                        r"socket\(AF_INET,\s*SOCK_STREAM,\s*0\)",  # Detects raw socket creation
                        r"connect\s*\(.*sockaddr_in",  # Reverse shell setup
                        r"mmap\((.*),\s*PROT_EXEC",  # Memory allocation with execution permission
                        r"VirtualAlloc\(.*PAGE_EXECUTE_READWRITE\)",  # Windows-specific memory execution permission
                        r"WriteProcessMemory\(",  # Injecting code into another process
                        r"CreateRemoteThread\(",  # Windows remote thread creation
                        r"LoadLibraryA\(",  # Dynamically loading DLLs
                        r"GetProcAddress\(",  # Retrieving function pointers dynamically
                        r"SetWindowsHookExA\(",  # Function hooking in Windows
                        r"NtQuerySystemInformation\(",  # Possible process hiding attempts
                        r"ptrace\s*\(",  # Anti-debugging detection
                        r"fork\(\)",  # Possible process daemonization
                        r"dlopen\(",  # Dynamic library loading
                        r"strcpy\s*\(.*argv",  # Potential buffer overflow using user input
                        r"memcpy\s*\(.*\bstdin\b",  # Overwriting memory with input data
                        r"fopen\s*\(\s*[\"']/?etc/passwd",  # Accessing `/etc/passwd`
                        r"fopen\s*\(\s*[\"']C:\\Windows\\System32",  # Accessing Windows system files
                        r"chmod\s*\(\s*\d{3,4}",  # Changing file permissions (could indicate privilege escalation)
                        r"setuid\(0\)",  # Privilege escalation attempt
                        r"getenv\s*\(\s*[\"']LD_PRELOAD",  # Possible **LD_PRELOAD** hijacking
                        r"(?:strcpy|strncpy|memcpy|memmove)\s*\(.*?,.*?\);",  # Common vulnerable functions
                        r"int\s+main\s*\(\s*int\s+argc,\s*char\s*\*\s*argv\[\]\s*\)",  # Entry point for execution
                    ],
                },
                "Assembly Malicious Code": {
                    "severity": Severity.CRITICAL,
                    "patterns": [
                        r"\bmov\s+eax,\s*0x[0-9a-fA-F]+\b",  # Detects suspicious immediate values in registers (syscalls)
                        r"\bint\s+0x80\b",  # Detects Linux syscall execution
                        r"\bcall\s+eax\b",  # Detects execution through register
                        r"\bpush\s+0x[0-9a-fA-F]+\s+call\b",  # Detects function calls from stack-based execution
                        r"\bpop\s+eax\b\s*\bjmp\b",  # Possible control flow manipulation
                        r"\bxor\s+(eax|ebx|ecx|edx),\s*\1\b",  # Common zeroing technique in shellcode
                        r"\b(db|dw|dd)\s+(0x[0-9a-fA-F]{2}\s*,?\s*){6,}",  # Detects inline shellcode
                        r"\bptrace\s*\(",  # Debugger detection (common anti-analysis trick)
                        r"\bcmp\s+(eax|ebx|ecx),\s*0x[0-9a-fA-F]+\b",  # Syscall number checking
                        r"\bjne\s+0x[0-9a-fA-F]+\b",  # Conditional jumps (possible anti-debugging)
                        r"\bcall\s+ptrace\b",  # Detecting ptrace-based anti-debugging
                    ],
                },
            },
        )
        self.IGNORE_DIRS = {
            "node_modules",
            "dist",
            "out",
            "build",
            "test",
            "tests",
            "coverage",
            ".git",
        }
        self.MAX_URL_LENGTH = 80

    def load_yara_rules(self):
        """Load YARA rules with enhanced error handling and multiple path support."""
        yara_rules_paths = [
            os.path.join(os.getcwd(), "yara"),  # Ensure this is your correct folder
        ]

        compiled_rules = []
        for path in yara_rules_paths:
            if os.path.isdir(path):
                for rule_file in os.listdir(path):
                    if rule_file.endswith(".yara") or rule_file.endswith(".yar"):
                        try:
                            rule_path = os.path.join(path, rule_file)
                            rule = yara.compile(filepath=rule_path)
                            compiled_rules.append(rule)
                            print(f"✅ Loaded YARA rule: {rule_path}")
                        except yara.Error as e:
                            print(f"❌ Error compiling {rule_file}: {e}")
            elif os.path.isfile(path):
                try:
                    rule = yara.compile(filepath=path)
                    compiled_rules.append(rule)
                    print(f"✅ Loaded YARA rule: {path}")
                except yara.Error as e:
                    print(f"❌ Error compiling {path}: {e}")

        if not compiled_rules:
            print("❌ No YARA rules were loaded!")

        return compiled_rules if compiled_rules else None

    async def loading_animation(stop_event):
        """Displays a loading spinner while scanning is in progress."""
        spinner = itertools.cycle(
            ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"]
        )  # Braille dots animation
        while not stop_event.is_set():
            sys.stdout.write(f"\rScanning extensions... {next(spinner)} ")
            sys.stdout.flush()
            await asyncio.sleep(0.1)  # Controls speed of animation
        sys.stdout.write("\rScanning complete! ✅\n")  # Clear animation when done
        sys.stdout.flush()

    async def scan_with_yara(self, file_path: Path) -> List[SecurityIssue]:
        """Asynchronous YARA file scanning with detailed matching."""
        yara_issues = []
        if not self.yara_rules:
            return yara_issues

        try:
            async with aiofiles.open(file_path, "rb") as f:
                content = await f.read()

                for rule_set in self.yara_rules:
                    matches = rule_set.match(data=content)

                    for match in matches:
                        matched_strings = []

                        # ✅ Debugging: Ensure YARA detected the rule
                        self.logger.debug(
                            f"🔍 YARA detected: {match.rule} in {file_path}"
                        )

                        if hasattr(match, "strings") and isinstance(
                            match.strings, list
                        ):
                            for string_match in match.strings:
                                # ✅ Ensure the structure matches expected (offset, identifier, matched_data)
                                if (
                                    isinstance(string_match, tuple)
                                    and len(string_match) == 3
                                ):
                                    offset, identifier, matched_data = string_match

                                    try:
                                        # ✅ Convert bytes to readable format
                                        if isinstance(matched_data, bytes):
                                            matched_string = matched_data.decode(
                                                "utf-8", errors="ignore"
                                            )
                                        else:
                                            matched_string = str(matched_data)

                                        matched_strings.append(
                                            f"{identifier}: {matched_string}"
                                        )

                                    except Exception as decode_error:
                                        self.logger.error(
                                            f"Error decoding matched string: {decode_error}"
                                        )

                        # ✅ Final context formatting
                        if matched_strings:
                            context = f"Matched Strings: {', '.join(matched_strings[:5])}"  # Show first 5 matches
                        else:
                            context = "⚠️ Matched, but no readable strings extracted"

                        # ✅ Debugging: Ensure correct context formatting
                        self.logger.debug(
                            f"➡ Final context for {match.rule}: {context}"
                        )

                        # ✅ Fix: Extract YARA severity metadata correctly
                        severity_map = {
                            "low": Severity.LOW,
                            "medium": Severity.MEDIUM,
                            "high": Severity.HIGH,
                            "critical": Severity.CRITICAL,
                        }

                        rule_severity = match.meta.get("severity", "high")
                        if isinstance(rule_severity, bytes):
                            rule_severity = rule_severity.decode(
                                "utf-8", errors="ignore"
                            )

                        severity = severity_map.get(
                            rule_severity.lower(), Severity.HIGH
                        )

                        yara_issues.append(
                            SecurityIssue(
                                description=f"YARA Rule Match: {match.rule}",
                                severity=severity,
                                context=context,  # ✅ FIXED: Now displays matched patterns correctly
                                file_path=file_path,
                            )
                        )

        except Exception as e:
            self.logger.error(f"YARA scanning error for {file_path}: {e}")

        return yara_issues

    def setup_logging(self):
        """Configure logging with detailed formatting."""
        log_dir = "logs"
        os.makedirs(log_dir, exist_ok=True)

        log_file = os.path.join(
            log_dir, f"extension_scanner_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log"
        )

        logging.basicConfig(
            level=logging.WARNING,
            format="%(asctime)s - %(levelname)s - [%(filename)s:%(lineno)d] - %(message)s",
            handlers=[
                logging.FileHandler(log_file, encoding="utf-8"),
                logging.StreamHandler(),
            ],
        )
        self.logger = logging.getLogger(__name__)
        self.logger.debug(f"Starting extension security scanner")
        self.logger.debug(f"Scanning extension directories: {self.extensions_paths}")

    async def compute_sha1_async(self, file_path: Path) -> str:
        """Asynchronously compute SHA-1 hash of a file."""
        try:
            async with aiofiles.open(file_path, "rb") as f:
                content = await f.read()
                file_hash = hashlib.sha1(content).hexdigest()
                return file_hash
        except Exception as e:
            self.logger.error(f"Error computing SHA-1 for {file_path}: {str(e)}")
            return "Error computing hash"

    async def extract_urls_from_files(
        self, extensions: List[ExtensionMetadata], output_file: Optional[str] = None
    ):
        """
        Extracts all unique embedded URLs from high-risk files in the scanned extensions.

        Args:
            extensions (List[ExtensionMetadata]): List of extensions scanned.
            output_file (Optional[str]): Path to save extracted URLs in CSV format (if provided).

        Returns:
            Dict[str, Set[str]]: A dictionary mapping file paths to a set of unique extracted URLs.
        """
        url_pattern = re.compile(r"https?://[^\s\"'>]+")  # Matches all HTTP/HTTPS URLs
        extracted_urls = {}

        for extension in extensions:
            for file_path in extension.scanned_files:
                # Ensure self.HIGH_RISK_FILES is accessible
                if not hasattr(self, "HIGH_RISK_FILES") or not any(
                    fnmatch.fnmatch(file_path.name, pattern)
                    for pattern in self.HIGH_RISK_FILES
                ):
                    continue

                try:
                    async with aiofiles.open(
                        file_path, "r", encoding="utf-8", errors="ignore"
                    ) as f:
                        content = await f.read()

                    urls = set(
                        url_pattern.findall(content)
                    )  # Use a set to remove duplicates
                    if urls:
                        extracted_urls[file_path] = urls

                except Exception as e:
                    self.logger.error(f"Error reading {file_path}: {e}")

        # Print extracted URLs to console
        print("\n=== Extracted Unique URLs from Extensions ===")
        if extracted_urls:
            for file, urls in extracted_urls.items():
                print(f"\n📁 File: {file}")
                for url in urls:
                    print(f"  🔗 {url}")
        else:
            print("No URLs found in scanned files.")

        # Save to CSV if output file is provided
        if output_file:
            with open(output_file, "w", newline="", encoding="utf-8") as f:
                writer = csv.writer(f)
                writer.writerow(["File Path", "Extracted URL"])
                for file, urls in extracted_urls.items():
                    for url in urls:
                        writer.writerow([file, url])
            print(f"\n✅ URLs saved to: {output_file}")

        return extracted_urls

    async def scan_vsix_manifest(self, file_path: Path) -> List[SecurityIssue]:
        """Parse and analyze .vsixmanifest files for security issues."""
        issues = []
        try:
            tree = ET.parse(file_path)
            root = tree.getroot()

            namespaces = root.attrib
            if any(
                suspicious in str(namespaces).lower()
                for suspicious in ["http", "ftp", "ws"]
            ):
                issues.append(
                    SecurityIssue(
                        description="Suspicious namespace definition in .vsixmanifest",
                        severity=Severity.HIGH,
                        context=str(namespaces),
                        file_path=file_path,
                    )
                )

            for elem in root.iter():
                if elem.tag in self.SUSPICIOUS_VSIX_ENTRIES:
                    issues.append(
                        SecurityIssue(
                            description=f"Suspicious `{elem.tag}` found in .vsixmanifest",
                            severity=self.SUSPICIOUS_VSIX_ENTRIES[elem.tag],
                            context=str(ET.tostring(elem, encoding="unicode")),
                            file_path=file_path,
                        )
                    )

                for attr, value in elem.attrib.items():
                    if any(susp in value.lower() for susp in ["http:", "ftp:", "ws:"]):
                        issues.append(
                            SecurityIssue(
                                description=f"Suspicious URL in attribute {attr}",
                                severity=Severity.MEDIUM,
                                context=value[:100],
                                file_path=file_path,
                            )
                        )

        except ET.ParseError as e:
            issues.append(
                SecurityIssue(
                    description="Malformed .vsixmanifest detected",
                    severity=Severity.HIGH,
                    context=str(e),
                    file_path=file_path,
                )
            )
        except Exception as e:
            self.logger.error(f"Error scanning {file_path}: {str(e)}")

        return issues

    async def scan_file_for_patterns(self, file_path: Path) -> List[SecurityIssue]:
        """Enhanced file scanner with better pattern matching and context."""
        issues = []
        try:
            async with aiofiles.open(
                file_path, "r", encoding="utf-8", errors="ignore"
            ) as f:
                content = await f.read()
                lines = content.splitlines()

                # Ensure MALICIOUS_PATTERNS is a dictionary, not a tuple
                malicious_patterns = (
                    self.MALICIOUS_PATTERNS[0]
                    if isinstance(self.MALICIOUS_PATTERNS, tuple)
                    else self.MALICIOUS_PATTERNS
                )

                for category, config in malicious_patterns.items():
                    severity = config["severity"]
                    for pattern in config["patterns"]:
                        for i, line in enumerate(lines, 1):
                            match = re.search(pattern, line)
                            if match:
                                context = line.strip()
                                issue = SecurityIssue(
                                    description=f"{category}: {match.group(0)}",
                                    severity=severity,
                                    context=context,
                                    file_path=file_path,
                                    line_number=i,
                                )
                                issues.append(issue)
        except Exception as e:
            self.logger.error(f"Error scanning {file_path}: {str(e)}")

        return issues

    async def scan_extension(self, extension_path: Path) -> ExtensionMetadata:
        """Scan a single extension directory, ensuring deduplication of detected patterns."""
        metadata = ExtensionMetadata(name=extension_path.name)
        self.logger.debug(f"Scanning extension: {extension_path.name}")
        # Extract metadata before scanning files
        package_json_path = extension_path / "package.json"  # VS Code extensions
        plugin_xml_path = extension_path / "plugin.xml"  # PyCharm plugins

        # Try to extract metadata from package.json (VS Code extensions)
        if package_json_path.exists():
            try:
                async with aiofiles.open(package_json_path, "r", encoding="utf-8") as f:
                    content = await f.read()
                    package_data = json.loads(content)

                    metadata.version = package_data.get("version", "Unknown")
                    metadata.publisher = package_data.get("publisher", "Unknown")

                    if metadata.publisher == "Unknown" and "author" in package_data:
                        author_data = package_data["author"]
                        if isinstance(author_data, dict):
                            metadata.publisher = author_data.get("name", "Unknown")
                        else:
                            metadata.publisher = author_data  # Sometimes it's a string

            except Exception as e:
                self.logger.error(
                    f"Error reading package.json in {extension_path}: {e}"
                )

        # Try to extract metadata from plugin.xml (PyCharm extensions)
        elif plugin_xml_path.exists():
            try:
                tree = ET.parse(plugin_xml_path)
                root = tree.getroot()

                name_element = root.find("name")
                if name_element is not None:
                    metadata.name = name_element.text

                version_element = root.find("version")
                if version_element is not None:
                    metadata.version = version_element.text

                vendor_element = root.find("vendor")
                if vendor_element is not None:
                    metadata.publisher = vendor_element.text

            except ET.ParseError as e:
                self.logger.error(f"Error parsing plugin.xml in {extension_path}: {e}")

        # Log if metadata is missing
        if metadata.version == "Unknown" or metadata.publisher == "Unknown":
            self.logger.warning(
                f"Metadata missing for {extension_path.name}. Version: {metadata.version}, Publisher: {metadata.publisher}"
            )
        # Track unique detections per file
        seen_patterns_per_file = {}  # {file_path: {unique_detected_patterns}}

        # List of files to scan
        files_to_scan = set()

        # Find high-risk files
        for root, _, files in os.walk(extension_path):
            root_path = Path(root)

            # Skip ignored directories
            if any(ignore_dir in root_path.parts for ignore_dir in self.IGNORE_DIRS):
                continue

            for file in files:
                file_path = root_path / file  # Ensure file_path is assigned

                # Check if this file matches any high-risk patterns
                for high_risk_pattern, severity in self.HIGH_RISK_FILES.items():
                    if fnmatch.fnmatch(file, high_risk_pattern) or file_path.match(
                        f"**/{high_risk_pattern}"
                    ):
                        hash_value = await self.compute_sha1_async(file_path)
                        metadata.sha1_hashes[file_path] = hash_value
                        files_to_scan.add(file_path)
                        break  # Stop checking once added

        # Exit early if no files to scan
        if not files_to_scan:
            self.logger.warning(f"No files found for scanning in {extension_path}")
            return metadata

        # Scan identified files
        for file_path in files_to_scan:
            self.logger.debug(f"Scanning file: {file_path.relative_to(extension_path)}")

            metadata.scanned_files.add(file_path)
            self.scanned_files.add(file_path)  # Mark as scanned globally

            seen_patterns_per_file[file_path] = (
                set()
            )  # Track detected patterns for this file

            # ✅ **YARA-based scanning (if enabled)**
            if self.use_yara and self.yara_rules:
                yara_issues = await self.scan_with_yara(file_path)
                for issue in yara_issues:
                    unique_key = issue.description  # Track by detection description
                    if unique_key not in seen_patterns_per_file[file_path]:
                        seen_patterns_per_file[file_path].add(unique_key)
                        metadata.security_issues.append(issue)

            # ✅ **Regex-based scanning (if --use-yara is NOT used)**
            else:
                try:
                    if file_path.name.lower() == "package.json":
                        # ✅ Step 3: Continue scanning package.json for patterns
                        issues = await self.scan_file_for_patterns(file_path)
                        for issue in issues:
                            unique_key = issue.description
                            if unique_key not in seen_patterns_per_file[file_path]:
                                seen_patterns_per_file[file_path].add(unique_key)
                                metadata.security_issues.append(issue)

                    elif file_path.suffix.lower() == ".js":
                        issues = await self.scan_file_for_patterns(file_path)
                        for issue in issues:
                            unique_key = issue.description
                            if unique_key not in seen_patterns_per_file[file_path]:
                                seen_patterns_per_file[file_path].add(unique_key)
                                metadata.security_issues.append(issue)

                    elif file_path.name.lower() == ".vsixmanifest":
                        manifest_issues = await self.scan_vsix_manifest(file_path)
                        for issue in manifest_issues:
                            unique_key = issue.description
                            if unique_key not in seen_patterns_per_file[file_path]:
                                seen_patterns_per_file[file_path].add(unique_key)
                                metadata.security_issues.append(issue)

                    elif file_path.suffix.lower() == ".sh":
                        sh_issues = await self.scan_file_for_patterns(file_path)
                        for issue in sh_issues:
                            unique_key = issue.description
                            if unique_key not in seen_patterns_per_file[file_path]:
                                seen_patterns_per_file[file_path].add(unique_key)
                                metadata.security_issues.append(issue)

                    elif file_path.suffix.lower() == ".xml":
                        xml_issues = await self.scan_file_for_patterns(file_path)
                        for issue in xml_issues:
                            unique_key = issue.description
                            if unique_key not in seen_patterns_per_file[file_path]:
                                seen_patterns_per_file[file_path].add(unique_key)
                                metadata.security_issues.append(issue)

                    elif file_path.suffix.lower() == ".jar":
                        jar_issues = await self.scan_file_for_patterns(file_path)
                        for issue in jar_issues:
                            unique_key = issue.description
                            if unique_key not in seen_patterns_per_file[file_path]:
                                seen_patterns_per_file[file_path].add(unique_key)
                                metadata.security_issues.append(issue)

                except Exception as e:
                    self.logger.error(f"Error processing {file_path}: {str(e)}")

        return metadata

    async def scan_all_extensions(self) -> List[ExtensionMetadata]:
        """Scan all installed extensions asynchronously."""
        results = []
        start_time = datetime.now()
        self.logger.debug(f"Starting scan at {start_time}")
        tasks = []

        for extensions_path in self.extensions_paths:
            for extension in os.listdir(extensions_path):
                ext_path = extensions_path / extension
                if ext_path.is_dir():
                    tasks.append(self.scan_extension(ext_path))

        # Store scanned extensions as a class attribute
        self.scanned_extensions = await asyncio.gather(*tasks)

        end_time = datetime.now()
        duration = end_time - start_time
        self.logger.debug(f"Scan completed at {end_time}. Duration: {duration}")

        return self.scanned_extensions  # Return scanned extensions

    def generate_reports(
        self, results: List[ExtensionMetadata], output_path: Optional[str] = None
    ):
        """Generate CSV report if output_path is provided, otherwise print the findings summary to the console."""

        if output_path:
            # Save results to file (no console output)
            os.makedirs(os.path.dirname(output_path), exist_ok=True)
            self._generate_csv_report(results, output_path)
            self.logger.info(f"CSV report generated at: {output_path}")
            print(f"\n✅ Report saved to: {output_path}")
        else:
            # Print the summary to the console when no output file is provided
            self._print_summary(results)

    def query_virustotal(file_hash: str) -> dict:
        """
        Queries VirusTotal Enterprise API for a given file hash.

        Args:
            file_hash (str): SHA-1, SHA-256, or MD5 hash of the file.

        Returns:
            dict: VT analysis report or an error message.
        """
        headers = {"x-apikey": VT_API_KEY}

        try:
            response = requests.get(VT_URL.format(file_hash), headers=headers)
            if response.status_code == 200:
                vt_data = response.json()

                # Extract relevant VT report details
                stats = (
                    vt_data.get("data", {})
                    .get("attributes", {})
                    .get("last_analysis_stats", {})
                )
                malicious = stats.get("malicious", 0)
                suspicious = stats.get("suspicious", 0)
                harmless = stats.get("harmless", 0)
                undetected = stats.get("undetected", 0)
                times_submitted = (
                    vt_data.get("data", {})
                    .get("attributes", {})
                    .get("times_submitted", "Unknown")
                )

                # Return a structured report
                return {
                    "status": "success",
                    "malicious": malicious,
                    "suspicious": suspicious,
                    "harmless": harmless,
                    "undetected": undetected,
                    "times_submitted": times_submitted,
                    "vt_url": f"https://www.virustotal.com/gui/file/{file_hash}",
                }

            elif response.status_code == 404:
                return {
                    "status": "not_found",
                    "message": "Hash not found in VirusTotal",
                }
            elif response.status_code == 403:
                return {
                    "status": "error",
                    "message": "Invalid API Key or quota exceeded",
                }
            else:
                return {
                    "status": "error",
                    "message": f"Unexpected response: {response.status_code}",
                }

        except requests.RequestException as e:
            logging.error(f"Error querying VirusTotal: {e}")
            return {"status": "error", "message": str(e)}

    def _generate_csv_report(self, results: List[ExtensionMetadata], output_file: str):
        """Generate detailed CSV report."""
        with open(output_file, "w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            headers = [
                "Extension",
                "Version",
                "Publisher",
                "Issue Severity",
                "Issue Description",
                "File",
                "Line Number",
                "Context",
                "File Hash",
            ]
            writer.writerow(headers)

            for ext in results:
                for issue in ext.security_issues:
                    file_hash = ext.sha1_hashes.get(
                        issue.file_path, "Hash not computed"
                    )
                    writer.writerow(
                        [
                            ext.name,
                            ext.version or "N/A",
                            ext.publisher or "N/A",
                            issue.severity.name,
                            issue.description,
                            issue.file_path,
                            issue.line_number or "N/A",
                            issue.context,
                            file_hash,
                        ]
                    )

    def _print_summary(self, results: List[ExtensionMetadata]):
        """Prints findings summary with full file paths and line numbers."""

        print("\n=== IDE Extension Security Scan Summary ===")
        print(f"Scan completed at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"Total extensions scanned: {len(results)}")
        print(f"Total unique files scanned: {len(self.scanned_files)}")

        if not results:
            print("No extensions found to scan.")
            return

        # 📦 Display scanned extensions metadata (Always show this)
        print("\n📦 Extensions Metadata:")
        for ext in results:
            version = ext.version if ext.version else "Unknown"
            publisher = ext.publisher if ext.publisher else "Unknown"
            print(f"- {ext.name} (Version {version}) - Publisher: {publisher}")

        # ✅ Check if there are findings, otherwise print a clean result message
        total_findings = sum(len(ext.security_issues) for ext in results)

        if total_findings == 0:
            print(
                "\n🛡️ No security issues detected. ✅"
            )  # Ensure a clean, informative output
            return  # Exit early if no findings

        # 🔍 Group findings by severity
        findings_by_severity = {}
        for ext in results:
            for issue in ext.security_issues:
                if issue.severity not in findings_by_severity:
                    findings_by_severity[issue.severity] = []
                findings_by_severity[issue.severity].append(
                    (
                        ext.name,
                        issue,
                        ext.sha1_hashes.get(issue.file_path, "Hash not computed"),
                    )
                )

        # 📌 Print findings summary
        print("\nFindings Summary:")
        for severity in sorted(Severity, key=lambda x: x.value, reverse=True):
            if severity in findings_by_severity:
                issues = findings_by_severity[severity]
                print(f"\n{severity.name} Issues ({len(issues)}):")

                # Group issues by file path
                issues_by_file = {}
                for ext_name, issue, file_hash in issues:
                    if issue.file_path not in issues_by_file:
                        issues_by_file[issue.file_path] = []
                    issues_by_file[issue.file_path].append((ext_name, issue, file_hash))

                # Print findings per file
                for file_path, file_issues in issues_by_file.items():
                    print(f"\n📂 File: {file_path}")  # ✅ Full file path

                    for ext_name, issue, file_hash in file_issues:
                        line_info = (
                            f"(line {issue.line_number})"
                            if issue.line_number
                            else "(line N/A)"
                        )
                        print(
                            f"   - {ext_name}: {issue.description} {line_info} | SHA1: {file_hash}"
                        )


async def main():

    ascii_banner = """
        
██╗██████╗ ███████╗    ███████╗██╗  ██╗████████╗    ██╗  ██╗██╗   ██╗███╗   ██╗████████╗███████╗██████╗ 
██║██╔══██╗██╔════╝    ██╔════╝╚██╗██╔╝╚══██╔══╝    ██║  ██║██║   ██║████╗  ██║╚══██╔══╝██╔════╝██╔══██╗
██║██║  ██║█████╗      █████╗   ╚███╔╝    ██║       ███████║██║   ██║██╔██╗ ██║   ██║   █████╗  ██████╔╝
██║██║  ██║██╔══╝      ██╔══╝   ██╔██╗    ██║       ██╔══██║██║   ██║██║╚██╗██║   ██║   ██╔══╝  ██╔══██╗
██║██████╔╝███████╗    ███████╗██╔╝ ██╗   ██║       ██║  ██║╚██████╔╝██║ ╚████║   ██║   ███████╗██║  ██║
╚═╝╚═════╝ ╚══════╝    ╚══════╝╚═╝  ╚═╝   ╚═╝       ╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═══╝   ╚═╝   ╚══════╝╚═╝  ╚═╝
════════════════════════════════════════════════════
    IDE extensions Forensics
    By Almog Mendelson
════════════════════════════════════════════════════                                                                                                
        """
    # Run with parsed arguments
    args = parse_cli_arguments()
    try:
        # Initialize scanner with optional path
        scanner = IDEextensionsscanner(
            ide=args.ide, extensions_path=args.path, use_yara=args.use_yara
        )

        # Scan all extensions
        all_results = await scanner.scan_all_extensions()
        results = all_results

        if args.list_urls:
            extracted_urls = await scanner.extract_urls_from_files(
                all_results, args.output
            )
            return  # Exit after extracting URLs
        if args.use_yara:
            print("\n🔍 Running YARA-based scan only...")
            all_results = await scanner.scan_all_extensions()

            # Filter only YARA-related results
            results = [
                ext
                for ext in all_results
                if any(
                    issue.description.startswith("YARA Rule Match")
                    for issue in ext.security_issues
                )
            ]

            if not results:
                print("\n✅ No YARA detections found.\n")
                return

        else:
            print("\n🔍 Running full security scan...")
            all_results = await scanner.scan_all_extensions()
            results = all_results

        if args.severity:
            severity_threshold = getattr(Severity, args.severity.upper())

            # Diagnostic print to understand the filtering
            print(f"\nFiltering for exact severity: {severity_threshold}")

            results = [
                ext
                for ext in all_results
                if any(
                    issue.severity.value == severity_threshold.value
                    for issue in ext.security_issues
                )
                and not any(
                    issue.severity.value > severity_threshold.value
                    for issue in ext.security_issues
                )
            ]
        if args.output:
            scanner.generate_reports(results, args.output)  # ✅ Save to file
        else:
            scanner._print_summary(results)

    except Exception as e:
        print(f"Error during scan: {str(e)}")
        logging.error(f"Error during scan: {str(e)}", exc_info=True)


if __name__ == "__main__":
    asyncio.run(main())
