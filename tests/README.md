# FOFF Milter Test Suite

## Email Naming Convention

Test emails use this naming pattern:
- `SHOULD_PASS_*.eml` - Email should be accepted (no rules match)
- `SHOULD_FLAG_*.eml` - Email should be tagged/rejected (at least one rule matches)

## Directory Structure

```
tests/
├── emails/           # Test email files
│   ├── SHOULD_PASS_legitimate_google_groups.eml
│   ├── SHOULD_FLAG_tinnitus_spam.eml
│   └── SHOULD_FLAG_cvs_medicare_phishing.eml
├── configs/          # Test configurations
│   └── test_rules.yaml
└── run_tests.sh      # Test automation script
```

## Running Tests

```bash
# Run all tests
./tests/run_tests.sh

# Run with specific config
./tests/run_tests.sh tests/configs/test_rules.yaml
```

## Test Results

- ✅ PASS: Email behavior matches expectation
- ❌ FAIL: Email behavior doesn't match expectation
- 📊 Summary shows pass/fail counts
