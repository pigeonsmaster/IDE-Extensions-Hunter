/*
 * Credential Theft Detection Template
 * Use this template to detect attempts to access stored credentials
 */

rule Credential_Theft_RULE_NAME {
    meta:
        description = "Detects access to [specific credential store]"
        severity = 4
        category = "credential_theft"
        author = "Your Name"
        date = "2025-11-19"

    strings:
        // Credential store location
        $cred_path1 = ".credential_location"
        $cred_path2 = "credential_file"

        // Access methods
        $readFile = "readFileSync"
        $readFile2 = "readFile("
        $fs = "require('fs')"

        // System paths
        $homedir = "os.homedir"
        $env_home = "process.env.HOME"

        // Credential keywords
        $password = "password" nocase
        $token = "token" nocase
        $secret = "secret" nocase

    condition:
        // File access + credential paths + home directory
        any of ($cred_path*) and
        any of ($readFile*) and
        any of ($homedir, $env_home) and
        any of ($password, $token, $secret)
}
