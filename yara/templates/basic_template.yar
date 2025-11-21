/*
 * Basic YARA Rule Template
 *
 * Instructions:
 * 1. Replace RULE_NAME with your rule name (e.g., Suspicious_API_Call)
 * 2. Update the meta section with your information
 * 3. Define strings to match (use $ prefix)
 * 4. Define condition (when rule should match)
 * 5. Test with: python -m ide_hunter --yara-test <file>
 * 6. Validate with: python -m ide_hunter --validate-yara
 */

rule RULE_NAME {
    meta:
        description = "Brief description of what this detects"
        severity = 3                // 0=INFO, 1=LOW, 2=MEDIUM, 3=HIGH, 4=CRITICAL
        category = "category_name"  // e.g., "obfuscation", "c2", "credential_theft"
        author = "Your Name"
        date = "2025-11-19"

    strings:
        // Define patterns to search for
        $string1 = "exact_string_to_find"
        $string2 = "another_string" nocase  // Case-insensitive
        $pattern1 = /regex_pattern/
        $hex1 = { 4D 5A 90 00 }  // Hex pattern

    condition:
        // Define when rule should trigger
        any of ($string*) or
        all of ($pattern*) or
        $hex1
}
