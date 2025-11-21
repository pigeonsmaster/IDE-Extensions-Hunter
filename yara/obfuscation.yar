/*
 * Obfuscation Detection Rules
 * Detects encoded or hidden malicious code in IDE extensions
 */

rule Base64_Encoded_Execution {
    meta:
        description = "Base64-encoded data with execution sinks"
        severity = 4
        category = "obfuscation"
        author = "IDE Extension Hunter"
        date = "2025-11-19"

    strings:
        $atob = "atob(" nocase
        $buffer_from = "Buffer.from"
        $base64 = "base64" nocase

        $eval = "eval(" nocase
        $exec = "exec(" nocase
        $function = "Function(" nocase

    condition:
        ($atob or ($buffer_from and $base64)) and
        any of ($eval, $exec, $function)
}

rule Heavy_Variable_Obfuscation {
    meta:
        description = "Heavy use of obfuscated variable names"
        severity = 3
        category = "obfuscation"
        author = "IDE Extension Hunter"
        date = "2025-11-19"

    strings:
        $obf_var = /_0x[a-f0-9]{4,}/
        $eval = "eval("
        $function = "Function("

    condition:
        #obf_var > 15 and ($eval or $function)
}

rule String_CharCode_Obfuscation {
    meta:
        description = "Character code based obfuscation"
        severity = 3
        category = "obfuscation"
        author = "IDE Extension Hunter"
        date = "2025-11-19"

    strings:
        $fromCharCode = "String.fromCharCode"
        $eval = "eval"
        $charCodeAt = "charCodeAt"

    condition:
        $fromCharCode and ($eval or #charCodeAt > 5)
}

rule Hex_Encoding_Obfuscation {
    meta:
        description = "Hex-encoded strings with execution"
        severity = 3
        category = "obfuscation"
        author = "IDE Extension Hunter"
        date = "2025-11-19"

    strings:
        $hex_pattern = /\\x[0-9a-fA-F]{2}/
        $eval = "eval("
        $exec = "exec("
        $function = "new Function("

    condition:
        #hex_pattern > 20 and any of ($eval, $exec, $function)
}
