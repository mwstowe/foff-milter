# Regex Limitations in FOFF Milter

## Overview

FOFF Milter uses Rust's `regex` crate, which has some limitations compared to other regex engines like PCRE. This document outlines the key limitations and provides alternatives.

## Unsupported Features

### 1. Lookahead and Lookbehind Assertions

**Not Supported:**
```regex
(?!pattern)     # Negative lookahead
(?=pattern)     # Positive lookahead
(?<!pattern)    # Negative lookbehind
(?<=pattern)    # Positive lookbehind
```

**Example of problematic pattern:**
```regex
.*@(?!sendgrid\.net)(outlook|gmail|yahoo|hotmail)\.(com|net)$
```

**Alternative approaches:**
1. Use multiple criteria with `And`/`Or` logic
2. Use character classes `[^...]` for simple exclusions
3. Match the positive case and handle exclusions in separate rules

### 2. YAML Escaping

**Problem:**
Double quotes in YAML require double escaping of backslashes:
```yaml
pattern: ".*\\.example\\.com"  # Error: unknown escape character
```

**Solution:**
Use single quotes for regex patterns:
```yaml
pattern: '.*\.example\.com'    # Correct
```

## Migration Examples

### Example 1: Negative Lookahead

**Before (doesn't work):**
```yaml
- name: "Block free email except trusted"
  criteria:
    type: "SenderPattern"
    pattern: ".*@(?!sendgrid\.net)(outlook|gmail|yahoo)\.(com|net)$"
```

**After (works):**
```yaml
- name: "Block suspicious free email"
  criteria:
    type: "And"
    criteria:
      - type: "SenderPattern"
        pattern: '.*@(outlook|gmail|yahoo)\.(com|net)$'
      - type: "SenderPattern"
        pattern: '.*@(?!sendgrid\.net).*'  # This still won't work!
```

**Better approach:**
```yaml
- name: "Block suspicious free email from untrusted TLDs"
  criteria:
    type: "And"
    criteria:
      - type: "SenderPattern"
        pattern: '.*@(outlook|gmail|yahoo)\.(com|net)$'
      - type: "SenderPattern"
        pattern: '.*@.*\.(tk|ml|ga|cf|cn|ru)$'
```

### Example 2: DKIM Domain Exclusion

**Before (doesn't work):**
```yaml
pattern: "d=(?!sendgrid\.net).*\.(tk|ml|ga|cf)$"
```

**After (works):**
```yaml
pattern: 'd=.*\.(tk|ml|ga|cf)$'
# Handle sendgrid.net exclusion with separate logic if needed
```

## Best Practices

### 1. Use Single Quotes for Regex Patterns
```yaml
# Good
pattern: '.*\.example\.com$'

# Bad
pattern: ".*\\.example\\.com$"
```

### 2. Test Your Configuration
Always test your configuration before deployment:
```bash
cargo run --bin foff-milter -- --test-config -c your-config.yaml
```

### 3. Use Multiple Criteria Instead of Complex Regex
```yaml
# Instead of complex negative lookahead
criteria:
  type: "And"
  criteria:
    - type: "SenderPattern"
      pattern: '.*@suspicious-domain\.com$'
    - type: "SubjectPattern"
      pattern: '(?i)(urgent|immediate)'
```

### 4. Character Classes for Simple Exclusions
```yaml
# Match domains that don't start with 'a', 'b', or 'c'
pattern: '.*@[^abc].*\.com$'
```

## Common Regex Features That Work

- Character classes: `[a-z]`, `[^0-9]`
- Quantifiers: `*`, `+`, `?`, `{n,m}`
- Anchors: `^`, `$`
- Groups: `(pattern)`
- Alternation: `pattern1|pattern2`
- Case-insensitive: `(?i)pattern`
- Word boundaries: `\b`
- Escape sequences: `\d`, `\w`, `\s`

## Error Messages

If you see errors like:
```
error: look-around, including look-ahead and look-behind, is not supported
```

This means you're using unsupported lookahead/lookbehind assertions. Replace them with alternative approaches described above.

## Resources

- [Rust regex crate documentation](https://docs.rs/regex/)
- [Regex syntax supported by Rust](https://docs.rs/regex/latest/regex/#syntax)
- [FOFF Milter configuration examples](examples/)
