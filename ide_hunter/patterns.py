"""
Pattern definitions for malicious behavior detection
"""

from ide_hunter.models import Severity

# High-risk file patterns to scan
HIGH_RISK_FILES = {
    "package.json": Severity.HIGH,
    "extension.js": Severity.CRITICAL,
    "extension-web.js": Severity.CRITICAL,
    ".vsixmanifest": Severity.HIGH,
    ".env": Severity.HIGH,
    "*.js": Severity.MEDIUM,
    "*tracker*.js": Severity.HIGH,
    "*network*.js": Severity.HIGH,
    "dist/*.js": Severity.HIGH,
    "out/*.js": Severity.HIGH,
    "src/*.js": Severity.MEDIUM,
    "*.sh": Severity.CRITICAL,
    "*.xml": Severity.CRITICAL,
    "*.jar": Severity.CRITICAL,
    "*.class": Severity.HIGH,
}

# Suspicious VSIX manifest entries
SUSPICIOUS_VSIX_ENTRIES = {
    "script": Severity.HIGH,
    "entryPoint": Severity.CRITICAL,
    "dependencies": Severity.MEDIUM,
    "extensionDependencies": Severity.MEDIUM,
}

# Malicious patterns to detect in files
MALICIOUS_PATTERNS = (
    {
        "Hardcoded IP": {
            "severity": Severity.HIGH,
            "patterns": [
                # http(s) → IP directly after scheme (no greedy hop)
                r"\bhttps?://(?!(?:127\.0\.0\.1|localhost|0\.0\.0\.0))(?:(?:\d{1,3}\.){3}\d{1,3})(?::\d{1,5})?\b",
                r"\bwss?://(?!(?:127\.0\.0\.1|localhost|0\.0\.0\.0))(?:(?:\d{1,3}\.){3}\d{1,3})(?::\d{1,5})?\b",
                # Optional: axios/fetch with an IP *immediately* in the string
                r"(?:axios|fetch)\s*\(\s*['\"]https?://(?!(?:127\.0\.0\.1|localhost|0\.0\.0\.0))(?:(?:\d{1,3}\.){3}\d{1,3})(?::\d{1,5})?\b",
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
                r"crypto\.createCipheriv\s*\(",  # Use of Node.js crypto module to create a cipher (common in file encryption)
                r"Buffer\.from\s*\(\s*['\"]?[A-Za-z0-9!@#$%^&*()_+\-={}\[\]:;\"',.<>/?\\|`~]{10,}['\"]?\s*,\s*['\"]utf8['\"]?\s*\)", # Hardcoded encryption key passed as a Buffer
                r"aes-256-cbc", # AES encryption algorithm commonly used by ransomware
                r"fs\.writeFileSync\s*\(", # Writing (potentially encrypted) data back to disk
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
        "Reverse Shell": {
            "severity": Severity.CRITICAL,
            "patterns": [
                #
                r"\b(socket\.socket|New-Object\s+System\.Net\.Sockets\.TCPClient|net\.Dial|new\s+net\.Socket|socket\(SOCK|bash\s+-i\s+>&\s+/dev/tcp|fsockopen\(|fetch\s*\(\s*['\"]https?://(?:\d{1,3}\.){3}\d{1,3}[:/]?\d*|new\s+WebSocket\s*\(\s*['\"]wss?://(?:\d{1,3}\.){3}\d{1,3}[:/]?\d*|XMLHttpRequest\s*\(\)\.open\s*\(\s*['\"]GET['\"]\s*,\s*['\"]https?://(?:\d{1,3}\.){3}\d{1,3}[:/]?\d*|JSON\.parse\s*\(\s*(?:atob|base64_decode|str_rot13|gzinflate|gzuncompress|rawurldecode|hex2bin)\)|JSON\.stringify\s*\(\s*\{?\s*['\"]?command['\"]?\s*:\s*['\"]?(?:shell_exec|eval|exec|system)['\"]?|document\.write\s*\(\s*(?:atob|base64_decode|decodeURIComponent)\)|eval\s*\(\s*(?:JSON\.parse|atob|decodeURIComponent)\)|new\s+Function\s*\([^)]*(?:atob|base64_decode)\)|XMLHttpRequest\s*\(\)\.send\s*\(\s*(?:JSON\.stringify|JSON\.parse)\)|WebSocket\s*\(\s*['\"]wss?:\/\/(?:\d{1,3}\.){3}\d{1,3}(?::\d+)?['\"]?\))\b",
                r"(?s)\b(bash\s+-i\s+>&\s+/dev/tcp|nc\s+-e\s+/bin/sh|base64\s+-d|curl\s+-X\s+POST).*?",
            ],
        },
        "Steal Data": {
            "severity": Severity.CRITICAL,
            "patterns": [
                r"\b(irm|iwr)\s+https?://[^\s]+?\s*\|\s*iex\b",
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

# Directories to ignore during scanning
IGNORE_DIRS = {
    "node_modules",
    "dist",
    "out",
    "build",
    "test",
    "tests",
    "coverage",
    ".git",
}
