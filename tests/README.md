# FOFF Milter Test Suite

Comprehensive test cases for validating email security detection.

## Structure

```
tests/
├── positive/          # Emails that SHOULD be caught (spam/phishing)
│   ├── docusign_phishing.eml
│   ├── docusign_me_domain.eml
│   ├── suspicious_tld.eml
│   └── paypal_phishing.eml
├── negative/          # Emails that SHOULD pass (legitimate)
│   ├── legitimate_business.eml
│   ├── legitimate_docusign.eml
│   └── newsletter.eml
├── run_tests.sh       # Test runner script
└── README.md          # This file
```

## Running Tests

```bash
# Build the binary first
cargo build --release

# Run all tests
cd tests
./run_tests.sh
```

## Test Categories

### Positive Tests (Should be Caught)
- **DocuSign Phishing**: Fake DocuSign from non-official domains
- **Suspicious TLD**: Emails from high-risk TLD domains (.tk, .ml, etc.)
- **Brand Impersonation**: PayPal phishing from educational domains
- **Sender Spoofing**: From name doesn't match sender domain

### Negative Tests (Should Pass)
- **Legitimate Business**: Normal business communications
- **Real DocuSign**: Actual DocuSign emails from docusign.com
- **Newsletters**: Legitimate newsletter subscriptions

## Adding New Tests

### Positive Test (Should be caught)
```bash
# Create new test file
cat > tests/positive/new_threat.eml << 'EOF'
From: threat@suspicious.domain
Subject: Malicious content
Body content here
EOF
```

### Negative Test (Should pass)
```bash
# Create new test file
cat > tests/negative/legitimate_email.eml << 'EOF'
From: sender@legitimate.com
Subject: Normal business
Body content here
EOF
```

## Expected Results

- **Positive tests**: Should return `TAG AS SPAM` or `REJECT`
- **Negative tests**: Should return `ACCEPT`
- **Success rate**: Should be 100% for a properly configured system
