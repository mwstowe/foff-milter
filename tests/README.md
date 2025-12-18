# FOFF Milter Test Suite

Comprehensive test cases for validating email security detection.

## Structure

```
tests/
├── positive/          # Emails that SHOULD be caught (spam/phishing)
├── negative/          # Emails that SHOULD pass (legitimate)
├── run_tests.sh       # Complete test runner
└── README.md          # This file
```

## Running Tests

```bash
# Build the binary first
cargo build --release

# Run complete test suite
./tests/run_tests.sh
```

## Test Categories

### Positive Tests (Should be Caught)
- **Phishing Attacks**: DocuSign, PayPal, HR document sharing
- **Brand Impersonation**: Fake emails from major brands
- **Suspicious Domains**: High-risk TLD domains (.tk, .ml, etc.)
- **BEC Attacks**: Business Email Compromise patterns

### Negative Tests (Should Pass)
- **Legitimate Business**: Normal business communications
- **Real Services**: Actual emails from legitimate providers
- **Newsletters**: Marketing emails from known platforms
- **Notifications**: System and service notifications

## Expected Results

- **Positive tests**: Should return `TAG AS SPAM` or `REJECT`
- **Negative tests**: Should return `ACCEPT`
- **Success rate**: Should be 100% for a properly configured system
