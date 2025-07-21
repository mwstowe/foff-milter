# Combination Criteria in FOFF Milter

## Overview

FOFF Milter supports complex combinations of criteria using AND/OR logic, allowing you to create sophisticated filtering rules that match multiple conditions simultaneously.

## Your Specific Use Case

**Requirement**: Block emails where the mailer matches "sparkmail.com" AND the subject contains Japanese text.

**Configuration**:
```yaml
- name: "Block Sparkmail with Japanese content"
  criteria:
    type: "And"
    criteria:
      - type: "MailerPattern"
        pattern: ".*sparkmail\\.com.*"
      - type: "SubjectContainsLanguage"
        language: "japanese"
  action:
    type: "Reject"
    message: "Sparkmail with Japanese content blocked"
```

## How It Works

### AND Logic
All criteria must match for the rule to trigger:
- ✅ Sparkmail mailer + Japanese subject = **MATCH** (rule triggers)
- ❌ Sparkmail mailer + English subject = **NO MATCH**
- ❌ Gmail mailer + Japanese subject = **NO MATCH**

### OR Logic
Any criteria can match for the rule to trigger:
```yaml
criteria:
  type: "Or"
  criteria:
    - type: "MailerPattern"
      pattern: ".*sparkmail\\.com.*"
    - type: "SubjectContainsLanguage"
      language: "japanese"
```
- ✅ Sparkmail mailer + English subject = **MATCH**
- ✅ Gmail mailer + Japanese subject = **MATCH**
- ✅ Sparkmail mailer + Japanese subject = **MATCH**

## Language Detection

### Supported Languages
- **Japanese** (`japanese` or `ja`): Hiragana, Katakana, Kanji
- **Chinese** (`chinese` or `zh`): CJK Unified Ideographs
- **Korean** (`korean` or `ko`): Hangul
- **Arabic** (`arabic` or `ar`): Arabic script
- **Russian** (`russian` or `ru`): Cyrillic script
- **Thai** (`thai` or `th`): Thai script
- **Hebrew** (`hebrew` or `he`): Hebrew script

### Detection Methods
- **SubjectContainsLanguage**: Detects language in email subject
- **HeaderContainsLanguage**: Detects language in any email header

## Complex Examples

### Multiple Mailers with Language Detection
```yaml
- name: "Block suspicious mailers with Japanese"
  criteria:
    type: "And"
    criteria:
      - type: "Or"
        criteria:
          - type: "MailerPattern"
            pattern: ".*sparkmail\\.com.*"
          - type: "MailerPattern"
            pattern: ".*bulkmail\\..*"
          - type: "MailerPattern"
            pattern: ".*massmail\\..*"
      - type: "SubjectContainsLanguage"
        language: "japanese"
  action:
    type: "Reject"
    message: "Suspicious mailer with Japanese content blocked"
```

### Domain + Language + Priority
```yaml
- name: "Flag Chinese high-priority from suspicious domains"
  criteria:
    type: "And"
    criteria:
      - type: "SenderPattern"
        pattern: ".*@.*\\.(cn|tk|ml)$"
      - type: "SubjectContainsLanguage"
        language: "chinese"
      - type: "HeaderPattern"
        header: "x-priority"
        pattern: "1"
  action:
    type: "TagAsSpam"
    header_name: "X-Spam-Chinese-Priority"
    header_value: "Chinese high-priority from suspicious domain"
```

### Multi-Language Detection
```yaml
- name: "Flag emails with multiple Asian languages"
  criteria:
    type: "And"
    criteria:
      - type: "SubjectContainsLanguage"
        language: "japanese"
      - type: "Or"
        criteria:
          - type: "SubjectContainsLanguage"
            language: "chinese"
          - type: "SubjectContainsLanguage"
            language: "korean"
  action:
    type: "TagAsSpam"
    header_name: "X-Spam-Multi-Language"
    header_value: "Multiple Asian languages detected"
```

## Testing Your Rules

### Configuration Validation
```bash
./foff-milter --test-config -c your-config.yaml
```

### Unit Tests
The system includes comprehensive tests for combination criteria:
```bash
cargo test test_combination_criteria
```

### Demonstration Mode
Run the milter in demo mode to see how your rules would behave:
```bash
./foff-milter -v -c your-config.yaml
```

## Performance Considerations

1. **Regex Compilation**: All regex patterns are pre-compiled for performance
2. **Language Detection**: Unicode character range checking is fast
3. **Rule Order**: Rules are evaluated in order; put most specific rules first
4. **Complex Logic**: Deeply nested AND/OR combinations may impact performance

## Best Practices

1. **Test Thoroughly**: Use `--test-config` to validate your configuration
2. **Start Simple**: Begin with basic rules and add complexity gradually
3. **Monitor Logs**: Use verbose logging to understand rule matching
4. **Regular Review**: Periodically review and update your rules
5. **Backup Configs**: Keep backups of working configurations

## Real-World Examples

### E-commerce Spam
```yaml
- name: "Block promotional Japanese emails from non-Japanese domains"
  criteria:
    type: "And"
    criteria:
      - type: "SubjectContainsLanguage"
        language: "japanese"
      - type: "SubjectPattern"
        pattern: "(?i)(セール|割引|プロモーション|オファー)"
      - type: "SenderPattern"
        pattern: ".*@.*\\.(com|net|org)$"
  action:
    type: "Reject"
    message: "Japanese promotional content from non-Japanese domain blocked"
```

### Phishing Detection
```yaml
- name: "Detect multi-language phishing attempts"
  criteria:
    type: "And"
    criteria:
      - type: "Or"
        criteria:
          - type: "SubjectContainsLanguage"
            language: "chinese"
          - type: "SubjectContainsLanguage"
            language: "russian"
      - type: "SubjectPattern"
        pattern: "(?i)(urgent|verify|suspend|account|security)"
  action:
    type: "TagAsSpam"
    header_name: "X-Spam-Phishing"
    header_value: "Potential multi-language phishing attempt"
```

This combination criteria system gives you powerful, flexible email filtering capabilities that can adapt to sophisticated spam and phishing techniques.
