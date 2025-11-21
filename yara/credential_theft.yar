/*
 * Credential Theft Detection Rules
 * Detects attempts to access stored credentials
 */

rule Browser_Cookie_Database_Access {
    meta:
        description = "Accesses browser cookie databases"
        severity = 4
        category = "credential_theft"
        author = "IDE Extension Hunter"
        date = "2025-11-19"

    strings:
        $sqlite = "sqlite3" nocase
        $chrome_path = "Chrome" nocase
        $cookies = "Cookies" nocase
        $encrypted = "encrypted_value"

        $fs_read1 = "readFileSync"
        $fs_read2 = "readFile("
        $fs_read3 = "createReadStream"

    condition:
        $sqlite and ($chrome_path or $cookies) and $encrypted and
        any of ($fs_read*)
}

rule SSH_Private_Key_Access {
    meta:
        description = "Attempts to read SSH private keys"
        severity = 4
        category = "credential_theft"
        author = "IDE Extension Hunter"
        date = "2025-11-19"

    strings:
        $ssh_dir = ".ssh"
        $id_rsa = "id_rsa"
        $id_ed25519 = "id_ed25519"
        $private_key = "PRIVATE KEY"

        $readFile = "readFileSync"
        $homedir1 = "os.homedir"
        $homedir2 = "process.env.HOME"

    condition:
        $ssh_dir and
        any of ($id_*, $private_key) and
        $readFile and
        any of ($homedir*)
}

rule NPM_Token_Theft {
    meta:
        description = "Accesses NPM authentication tokens"
        severity = 4
        category = "credential_theft"
        author = "IDE Extension Hunter"
        date = "2025-11-19"

    strings:
        $npmrc = ".npmrc"
        $authToken = "_authToken"
        $npm_config = "npm config"

        $readFile = "readFileSync"
        $homedir = "os.homedir"

    condition:
        ($npmrc or $authToken or $npm_config) and
        $readFile and $homedir
}

rule Git_Credential_Access {
    meta:
        description = "Accesses Git credentials"
        severity = 4
        category = "credential_theft"
        author = "IDE Extension Hunter"
        date = "2025-11-19"

    strings:
        $git_config = "git config"
        $git_credential = "git credential"
        $gitconfig = ".gitconfig"

        $exec1 = "exec("
        $exec2 = "execSync("
        $spawn = "spawn("
        $readFile = "readFileSync"

    condition:
        any of ($git*) and (any of ($exec*, $spawn) or $readFile)
}

rule AWS_Credentials_Access {
    meta:
        description = "Accesses AWS credentials"
        severity = 4
        category = "credential_theft"
        author = "IDE Extension Hunter"
        date = "2025-11-19"

    strings:
        $aws_dir = ".aws"
        $credentials = "credentials"
        $aws_key = "aws_access_key_id"
        $aws_secret = "aws_secret_access_key"

        $readFile = "readFileSync"
        $homedir = "os.homedir"

    condition:
        $aws_dir and
        any of ($credentials, $aws_key, $aws_secret) and
        $readFile and $homedir
}
