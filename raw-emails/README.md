# Raw Emails Directory

This directory contains non-anonymized email samples for testing and development purposes.

## ⚠️ IMPORTANT SECURITY NOTICE

- **This directory is NOT synchronized with GitHub**
- **Contains real email addresses and PII**
- **Files here should NEVER be committed to version control**
- **Use only for local testing and development**

## Usage

1. Place raw email files (.eml) here for testing
2. Use these files to test spam detection before anonymizing
3. Create anonymized versions in `tests/` directory for the test suite

## Workflow

1. Save raw email → `raw-emails/spam_sample.eml`
2. Test with: `./target/release/foff-milter --test-email raw-emails/spam_sample.eml`
3. Anonymize and move to appropriate `tests/positive/` or `tests/negative/` directory
4. Add to test suite

## Anonymization Rules

When moving emails from `raw-emails/` to `tests/`, apply these anonymization rules:

### Email Addresses
- Replace real recipient emails with `user@example.com` or `test@example.com`
- Replace real sender emails ONLY for generic providers (Gmail, Yahoo, etc.):
  - `realname@gmail.com` → `sender@gmail.com`
  - `john.doe@yahoo.com` → `noreply@yahoo.com`
  - Keep suspicious domains intact: `spam@suspicious-domain.tk` (no changes)
  - Keep business domains intact: `marketing@company.com` (no changes)

### Personal Information
- Replace real names with generic placeholders:
  - `<name>` or `Michael` for recipients
  - `John Smith` for generic senders
- Replace phone numbers with `<phone number>` or `(555) 123-4567`
- Replace addresses with `<address>` or generic addresses
- Replace account numbers with `<account number>` or `XXXX-XXXX-1234`

### Hostnames and Infrastructure
- Replace real hostnames with `hotel.example.com`, `juliett.example.com`
- Replace real IP addresses with RFC 5737 test IPs:
  - `192.0.2.1` (TEST-NET-1)
  - `198.51.100.1` (TEST-NET-2)
  - `203.0.113.1` (TEST-NET-3)
- Keep email infrastructure patterns for analysis (Amazon SES, SendGrid, etc.)

### URLs and Links
- Replace tracking URLs with anonymized versions
- Keep domain patterns that are relevant for spam detection
- Replace personal tracking parameters with generic ones

### Preserve for Analysis
- Keep spam content patterns intact
- Preserve suspicious domain structures
- Maintain email headers needed for detection
- Keep DKIM signatures and authentication results
- Preserve attachment structures and filenames

### Example Anonymization
```
Before: john.doe@company.com → user@example.com
Before: 192.168.1.100 → 192.0.2.1
Before: Dear John Doe → Dear Michael
Before: Account #123456789 → Account #<account number>
Before: mail.company.com → hotel.example.com
```

## Security

- Directory is protected by `.gitignore`
- Contains sensitive information - handle with care
- Delete files when no longer needed
