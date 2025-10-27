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

## Security

- Directory is protected by `.gitignore`
- Contains sensitive information - handle with care
- Delete files when no longer needed
