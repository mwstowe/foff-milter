# Raw Email Samples

This directory contains raw email samples for testing and analysis purposes.

## Purpose

These email files are used to:
- Test the FOFF Milter detection system against real-world spam
- Analyze spam patterns and techniques
- Validate detection rules and scoring
- Improve the email security system

## Usage

Test an email file:
```bash
./target/release/foff-milter --test-email raw-emails/filename.eml -c foff-milter.toml
```

## Files

- `Ozempic delivered to you.eml` - Pharmaceutical spam with non-existent domain
- Additional spam samples may be added for testing purposes

## Note

These are actual spam emails that have been sanitized for testing. They contain malicious content and should only be used for security research and testing purposes.
