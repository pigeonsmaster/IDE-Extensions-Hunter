"""
Pattern definitions for malicious behavior detection
"""

from ide_hunter.models import Severity

# High-risk file patterns to scan
# Note: Severity indicates scan priority, not that file is inherently malicious
HIGH_RISK_FILES = {
    "package.json": Severity.MEDIUM,  # Standard manifest, scan for suspicious dependencies
    "extension.js": Severity.MEDIUM,  # Standard entry point, not inherently suspicious
    "extension-web.js": Severity.MEDIUM,  # Web extension entry point
    ".vsixmanifest": Severity.MEDIUM,  # Standard manifest file
    ".env": Severity.HIGH,  # May contain credentials
    "*.js": Severity.LOW,  # Generic JS files
    "*tracker*.js": Severity.HIGH,  # Naming suggests tracking functionality
    "*network*.js": Severity.HIGH,  # Naming suggests network operations
    "src/*.js": Severity.LOW,  # Source files
    "*.sh": Severity.CRITICAL,  # Shell scripts unusual in extensions
    "*.xml": Severity.HIGH,  # May contain config or exploits
    "*.jar": Severity.CRITICAL,  # Java archives unusual in VSCode extensions
    "*.class": Severity.HIGH,  # Compiled Java unusual in extensions
    "*.wasm": Severity.HIGH,  # WebAssembly binary
    "*.node": Severity.HIGH,  # Native Node.js modules
}

# Suspicious VSIX manifest entries
SUSPICIOUS_VSIX_ENTRIES = {
    "script": Severity.HIGH,
    "entryPoint": Severity.CRITICAL,
    "dependencies": Severity.MEDIUM,
    "extensionDependencies": Severity.MEDIUM,
}

# Malicious patterns to detect in files
MALICIOUS_PATTERNS = {
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
        "Malicious Hardcoded Credentials": {
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
                r"chmod\s+(?:777|\+x)\s+(?:/etc/|/tmp/|/bin/)",  # Dangerous permissions on sensitive paths only
                r"rm\s+-rf\s+/",  # Wiping the entire system
                r"tar\s+cf\s+-\s+.*\s+\|\s+nc\s+",  # Exfiltration using Netcat
                r"scp\s+-r\s+",  # Secure copy of files
                r"(?:curl|wget).*\|\s*(?:sh|bash|eval)",  # Download piped to shell execution
                r"(?:curl|wget)\s+.*\.(?:sh|exe|php)\s+.*(?:/tmp/|/etc/|eval)",  # Download scripts to suspicious locations
                r"echo\s+.*>\s+/dev/.*",  # Writing to device files
                r"dd\s+if=.*\s+of=.*",  # Disk dumping
                r"base64\s+-d",  # Decoding obfuscated data
                r"gpg\s+--decrypt",  # Decrypting files
                r"cat\s+/root/.ssh/id_rsa",  # Extracting SSH keys
                r"cat\s+/home/\w+/\.bash_history",  # Reading command history
                r"zip\s+-r\s+.*\s+\|",  # Compressing data for exfiltration
                r"\b( echo\s+['\"']root::0:0:root:/root:/bin/bash['\"']\s*>\s*/etc/shadow| cat\s+/etc/shadow| cat\s+/etc/passwd| rm\s+-rf\s+/.* | wget\s+.*\.(sh|exe|php)\s+-O\s+/tmp/)\b",
                r"crypto\.createCipheriv\s*\(",  # Use of Node.js crypto module to create a cipher (common in file encryption)
                r"Buffer\.from\s*\(\s*['\"]?[A-Za-z0-9!@#$%^&*()_+\-={}\[\]:;\"',.<>/?\\|`~]{10,}['\"]?\s*,\s*['\"]utf8['\"]?\s*\)", # Hardcoded encryption key passed as a Buffer
                r"aes-256-cbc", # AES encryption algorithm commonly used by ransomware
                r"fs\.writeFileSync\s*\(\s*[\"'](?:\/etc\/|C:\\\\Windows|\/root\/|\/home\/[^\/]+\/\.(?:bashrc|ssh)|.*\/Startup\/|.*\/LaunchAgents\/)"  # flagging all writes, match only when the path looks sensitive
            ],
        },
        "Suspicious Database Operations": {
            "severity": Severity.CRITICAL,
            "patterns": [
                r"SELECT.*FROM\s+(?:moz_)?cookies",  # Cookie database queries (Chrome/Firefox)
                r"sqlite3\.Database.*(?:Cookies|cookies\.sqlite)",  # SQLite accessing browser cookie databases specifically
                r"(?:Chrome|Firefox|Edge).*(?:Cookies|cookies\.sqlite).*encrypted_value",  # Browser cookie theft with encrypted values
                r"host_key.*name.*value.*encrypted_value",  # Cookie data extraction pattern
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
                r"(?:atob|decodeURIComponent)\s*\(\s*[\"'][^\"']+[\"']\s*\)",  # Base64/URL decoding
                r"(?:btoa|atob)\s*\(\s*(?:fetch|require|exec|eval)",  # Base64 with dangerous functions
                r"(?:eval|exec|Function)\s*\(\s*(['\"`;,\s])(?:[A-Za-z0-9+/]{100,}={0,2})\1\s*\)",  # Large encoded strings
                r"_0x[a-f0-9]{4,}",  # Common JavaScript obfuscation pattern
                r"\[[\"'][^\]]+[\"']\]\[[\"'][^\]]+[\"']\]",  # Chained obfuscated lookups
                # r"(?:push|shift|unshift)\s*\(\s*[\"'][^\"']+[\"']\s*\)",  # String array shifts and pushes
                r"atob\s*\(\s*['\"]([A-Za-z0-9+/=]+)['\"]\s*\)\s*(?:\)|;)?\s*(?:\w+\s*=\s*)?(?:eval|exec|new\s+Function|\.call|\.apply|\(\))",  # Base64 decoding with execution
                r"const\s+_0x[a-f0-9]+\s*=\s*\[(?:\s*['\"][^'\"]{10,}['\"],?\s*){5,}\]",  # Large arrays of encoded strings
                r"function\s+_0x[a-f0-9]+\s*\([^)]*\)\s*{\s*return\s+atob\s*\(",  # Obfuscated decoding functions
                r"new\s+Function\s*\([^)]*atob\s*\(",  # Dynamic function creation with base64 decoding
                r"eval\s*\(\s*String\.fromCharCode\s*\(",  # Character code obfuscation
                # r"\\x[0-9a-f]{2}",  # Hex-encoded character obfuscation
                r"(?:window\.|global\.)?[a-zA-Z_$]+\[[\"'][a-zA-Z_$]+[\"']\]\([^)]*\)",  # Indirect function calls typical in obfuscation
                r"\b(?:eval\s*\(\s*(?:echo|base64|cat|sh)|echo\s+['\"']YmFzaCAtaSA+Ji9kZXYvdGNwLz|base64\s+-d\s+(?!-w|--wrap)|chmod\s+\d{3,4}\s+/bin/sh|\$\(\s*echo\s+['\"']?[A-Za-z0-9+/=]+['\"']?\s*\|\s*base64\s+-d\s*\))\b",
                r"eval\s*\(\s*Buffer\.from\s*\(\s*['\"]([A-Za-z0-9+/=]+)['\"]\s*,\s*['\"]base64['\"]\s*\)\.toString\(['\"]utf8['\"]\)\)",
            ],
        },
        "Hex Encoding Obfuscation": {
            "severity": Severity.HIGH,
            "patterns": [
                # JS: long \x.. then an execution sink
                r"(?:\\x[0-9A-F]{2}\s*){16,}[\s\S]{0,120}(?:(?:^|[^\w$])eval\s*\(|(?<![\w$\.])new\s+Function\s*\(|(?<![\w$\.])Function\s*\()",# noqa: E501
                # JS: percent-decoded blob then execution sink
                r"(?:unescape|decodeURIComponent)\s*\(\s*['\"](?:%[0-9A-F]{2}){16,}['\"]\s*\)\s*[\s\S]{0,120}(?:(?:^|[^\w$])eval\s*\(|document\.write\s*\(|(?<![\w$\.])new\s+Function\s*\()",# noqa: E501

                # JS (Node): Buffer.from(hex) then execute / drop
                r"(?<![\w$\.])Buffer\.from\s*\(\s*[`'\"](?:[0-9A-F]{2}[\s-]?){16,}[`'\"]\s*,\s*[`'\"]hex[`'\"]\s*\)[\s\S]{0,200}(?:(?:^|[^\w$])eval\s*\(|(?<![\w$\.])new\s+Function\s*\(|require\(['\"]child_process['\"]\)|fs\.writeFile(?:Sync)?\()",# noqa: E501

                # Python: unhexlify/fromhex/codecs→ dangerous sink
                r"(?:\b(?:binascii\.unhexlify|bytes?\.fromhex|codecs\.decode\([^,]+,\s*['\"]hex['\"]\)))\s*[\s\S]{0,200}\b(?:exec|eval|compile|ctypes\.CDLL|subprocess\.)",# noqa: E501

                # PHP: hex2bin/pack(H*) → execution sink
                r"(?:\bhex2bin\(\s*['\"][0-9A-F]{40,}['\"]\s*\)|\bpack\(\s*['\"]H\*['\"]\s*,\s*['\"][0-9A-F]{40,}['\"]\s*\))\s*[\s\S]{0,200}\b(?:eval|assert\s*\(|create_function)",# noqa: E501

                # PowerShell: FromHexString → IEX/Add-Type/WriteAllBytes
                r"\[System\.Convert\]::FromHexString\(\s*['\"][0-9A-F\s-]{40,}['\"]\s*\)\s*[\s\S]{0,200}(?:\bIEX\b|\bInvoke-Expression\b|\bAdd-Type\b|\bWriteAllBytes\()",# noqa: E501
            ],
        },
        "Crypto Targeting": {
            "severity": Severity.HIGH,
            "patterns": [
                r"\b(?:ethereum|solidity|blockchain|evm)\b[\s\S]{0,200}(?:fs\.writeFile|child_process|require\(['\"]web3|ethers\.Wallet|fetch\s*\()",  # Crypto terms with suspicious operations
                r"(?<!\w)(?:contract\.handler|web3)(?!\w)",  # Avoids partial matches inside words
            ],
        },
        "Reverse Shell": {
            "severity": Severity.CRITICAL,
            "patterns": [
                # Socket creation patterns
                r"\b(?:socket\.socket|socket\(SOCK)\b",  # Python/generic socket creation
                r"\bNew-Object\s+System\.Net\.Sockets\.TCPClient\b",  # PowerShell TCP client
                r"\bnet\.Dial\b",  # Go network dial
                r"\bnew\s+net\.Socket\b",  # JavaScript socket
                r"\bfsockopen\s*\(",  # PHP socket

                # Shell-based reverse connections
                r"\bbash\s+-i\s+>&\s+/dev/tcp/",  # Bash reverse shell
                r"\bnc\s+-e\s+/bin/sh\b",  # Netcat reverse shell

                # HTTP/WebSocket connections to IP addresses
                r"fetch\s*\(\s*['\"]https?://(?:\d{1,3}\.){3}\d{1,3}(?:[:/]\d+)?",  # Fetch to IP
                r"new\s+WebSocket\s*\(\s*['\"]wss?://(?:\d{1,3}\.){3}\d{1,3}(?::\d+)?",  # WebSocket to IP
                r"XMLHttpRequest\s*\(\)\s*\.open\s*\(\s*['\"](?:GET|POST)['\"]\s*,\s*['\"]https?://(?:\d{1,3}\.){3}\d{1,3}",  # XHR to IP

                # Obfuscated execution patterns (removed overly broad JSON.parse pattern to reduce FP)
                r"JSON\.stringify\s*\(\s*\{?\s*['\"]?command['\"]?\s*:\s*['\"]?(?:shell_exec|eval|exec|system)",  # Command execution via JSON
                r"eval\s*\(\s*(?:JSON\.parse|atob|decodeURIComponent)\s*\(",  # Eval with decoding
                r"new\s+Function\s*\([^)]*(?:atob|base64_decode)\s*\(",  # Function with decode

                # Document manipulation with decoding
                r"document\.write\s*\(\s*(?:atob|base64_decode|decodeURIComponent)\s*\(",  # Write decoded content

                # Shell commands with encoding/POST
                r"(?:base64\s+-d|curl\s+-X\s+POST)\s+.*",  # Base64 decode or curl POST
            ],
        },
        "Steal Data": {
            "severity": Severity.CRITICAL,
            "patterns": [
                r"\b(irm|iwr)\s+https?://[^\s]+?\s*\|\s*iex\b",
            ],
        },
        "Native Module Security": {
            "severity": Severity.HIGH,
            "patterns": [
                # fork() with suspicious operations (keep your improved pattern)
                r"fork\(\)[\s\S]{0,200}(?:execve|system\s*\(|mmap\(|socket\(AF_INET)",  # fork() with suspicious operations
                
                # Native module loading
                r"require\s*\(\s*['\"][^'\"]*\.node['\"]",  # Loading .node files
                r"import\s+.*\s+from\s+['\"][^'\"]*\.node['\"]",  # ES6 import of .node files
                r"loadNativeModule\s*\(",  # Explicit native module loading
                
                # Process execution (context-aware to reduce false positives)
                r"child_process\.(?:exec|execSync|spawn|fork)\s*\([^)]*(?:curl|wget|nc|netcat|bash|sh|cmd|powershell|iex)",  # Process execution with suspicious commands
                r"require\s*\(\s*['\"]child_process['\"]\s*\)[\s\S]{0,200}(?:exec|execSync|spawn|fork)\s*\([^)]*(?:curl|wget|nc|netcat|bash|sh|cmd|powershell|iex)",  # child_process with suspicious execution
                
                # File system operations to sensitive locations
                r"fs\.(?:writeFile|appendFile|createWriteStream)\s*\([^)]*(?:\/etc\/|\.ssh|bashrc|bash_profile|Startup|LaunchAgents|System32)",  # File operations to sensitive locations
                r"require\s*\(\s*['\"]fs['\"]\s*\)[\s\S]{0,200}(?:writeFile|appendFile|createWriteStream)\s*\([^)]*(?:\/etc\/|\.ssh|bashrc|bash_profile|Startup|LaunchAgents|System32)",  # fs with sensitive file operations
                
                # Network operations (exclude localhost and private IPs to reduce false positives)
                r"net\.(?:createConnection|createServer)\s*\([^)]*(?!(?:127|10|172\.(?:1[6-9]|2[0-9]|3[01])|192\.168)\.)(?:\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})",  # Network to external IPs only
                r"http\.(?:request|createServer)\s*\([^)]*(?!(?:127|10|172\.(?:1[6-9]|2[0-9]|3[01])|192\.168)\.)(?:\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})",  # HTTP to external IPs only
                r"https\.(?:request|createServer)\s*\([^)]*(?!(?:127|10|172\.(?:1[6-9]|2[0-9]|3[01])|192\.168)\.)(?:\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})",  # HTTPS to external IPs only
                r"require\s*\(\s*['\"](?:net|http|https)['\"]\s*\)[\s\S]{0,200}(?:createConnection|createServer|request)\s*\([^)]*(?!(?:127|10|172\.(?:1[6-9]|2[0-9]|3[01])|192\.168)\.)(?:\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})",  # Network modules to external IPs only
                
                # OS integration (context-aware)
                r"os\.(?:homedir|userInfo)\s*\([^)]*(?:\/etc\/|\.ssh|bashrc|bash_profile|Startup|LaunchAgents|System32)",  # OS functions accessing sensitive paths
                r"require\s*\(\s*['\"]os['\"]\s*\)[\s\S]{0,200}(?:homedir|userInfo)\s*\([^)]*(?:\/etc\/|\.ssh|bashrc|bash_profile|Startup|LaunchAgents|System32)",  # os module with sensitive path access
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

        "Credential Store Access": {
            "severity": Severity.CRITICAL,
            "patterns": [
                r"(?:exec|spawn|execSync)\s*\([^)]*git\s+config[^)]*credential",
                r"(?:exec|spawn|execSync)\s*\([^)]*npm\s+config[^)]*token",
                r"readFileSync\s*\([^)]*\.ssh[/\\]id_rsa",
                r"readFileSync\s*\([^)]*\.aws[/\\]credentials",
            ],
            # Accesses stored credentials (git, npm, ssh, aws)
            # Source: https://thehackernews.com/2025/10/phantomraven-malware-found-in-126-npm.html
            # Extensions should never access credential stores. This is a clear indicator of malicious intent.
        },
}

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
