/*
 * Obfuscation Detection Template
 * Use this template to detect encoded or hidden malicious code
 */

rule Obfuscation_RULE_NAME {
    meta:
        description = "Detects [specific obfuscation technique]"
        severity = 3
        category = "obfuscation"
        author = "Your Name"
        date = "2025-11-19"

    strings:
        // Encoding indicators
        $base64 = "atob(" nocase
        $buffer_from = "Buffer.from"
        $hex_encoding = /\\x[0-9a-fA-F]{2}/

        // Execution sinks
        $eval = "eval(" nocase
        $exec = "exec("
        $function_new = "new Function("

        // Obfuscation patterns
        $obf_vars = /_0x[a-f0-9]{4,}/
        $char_code = "String.fromCharCode"

    condition:
        // Encoding + Execution
        (any of ($base64, $buffer_from, $hex_encoding)) and
        any of ($eval, $exec, $function_new)
        or
        // Heavy obfuscation
        (#obf_vars > 10 and $char_code)
}
