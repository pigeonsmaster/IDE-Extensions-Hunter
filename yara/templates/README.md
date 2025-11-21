# YARA Rule Templates

This directory contains templates to help you create new YARA rules for detecting malicious IDE extensions.

## Available Templates

### 1. `basic_template.yar`
General-purpose template for any detection rule.
- Start here if you're creating a new type of detection
- Contains all basic YARA syntax with examples

### 2. `obfuscation_template.yar`
For detecting encoded or hidden malicious code.
- Base64 encoding
- Hex encoding
- String obfuscation
- Character code manipulation

### 3. `credential_theft_template.yar`
For detecting credential access attempts.
- Browser cookies
- SSH keys
- API tokens
- Environment variables

### 4. `exfiltration_template.yar`
For detecting data being sent to external servers.
- Webhooks (Discord, Telegram, etc.)
- File uploads
- Data collection + network communication

### 5. `c2_template.yar`
For detecting command and control patterns.
- Reverse shells
- WebSocket C2
- HTTP beaconing
- Remote code execution

## How to Use Templates

1. **Copy the appropriate template:**
   ```bash
   cp yara/templates/credential_theft_template.yar yara/my_new_rule.yar
   ```

2. **Edit the rule:**
   - Replace `RULE_NAME` with your rule name
   - Update the `meta` section
   - Modify `strings` to match what you want to detect
   - Adjust the `condition` logic

3. **Test your rule:**
   ```bash
   # Validate syntax
   python -m ide_hunter --validate-yara

   # Test against a file
   python -m ide_hunter --yara-test path/to/test_file.js
   ```

4. **Move to production:**
   - Once validated, your rule in the `yara/` directory will be automatically loaded
   - List all rules: `python -m ide_hunter --list-yara-rules`

## Rule Writing Tips

### String Modifiers
- `nocase` - Case-insensitive matching
- `wide` - Match UTF-16 strings
- `fullword` - Match only complete words

### Condition Operators
- `any of them` - At least one string matches
- `all of them` - All strings must match
- `#string > N` - String appears more than N times
- `$string at 0` - String at specific offset

### Regular Expressions
YARA supports basic regex:
- `\w` `\d` `\s` - Word chars, digits, whitespace
- `*` `+` `?` - Quantifiers
- `[abc]` - Character classes
- `^` `$` - Anchors

**Not supported:**
- `(?:...)` non-capturing groups (use `(...)` instead)
- Backreferences
- POSIX character classes

## Examples

### Detect Specific API Call
```yara
rule Suspicious_API {
    strings:
        $api = "dangerousAPI("
        $import = "require('dangerous-module')"
    condition:
        $api and $import
}
```

### Detect Multiple Indicators
```yara
rule Multi_Indicator {
    strings:
        $net = "fetch("
        $cred = "password"
        $eval = "eval("
    condition:
        all of them
}
```

### Count Occurrences
```yara
rule Heavy_Obfuscation {
    strings:
        $obf = /_0x[a-f0-9]+/
    condition:
        #obf > 20
}
```

## Testing Workflow

1. Create rule from template
2. Validate: `python -m ide_hunter --validate-yara`
3. Test on malicious sample: `python -m ide_hunter --yara-test malicious.js`
4. Test on clean code: `python -m ide_hunter --yara-test clean.js`
5. Adjust to reduce false positives
6. Deploy to production

## Need Help?

- Check official YARA documentation: https://yara.readthedocs.io/
- Review existing rules in `yara/` directory
- Test rules frequently to catch errors early
