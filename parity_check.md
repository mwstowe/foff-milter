# Production Parity Verification Feature

## Problem
Test environment shows different results than production for identical emails and code.

## Solution: `--parity-check` Command

### Usage
```bash
# Generate parity report for current environment
./foff-milter --parity-check production > prod_parity.json
./foff-milter --parity-check test > test_parity.json

# Compare reports
diff prod_parity.json test_parity.json
```

### Output Format
```json
{
  "environment": "production",
  "timestamp": "2025-11-09T17:43:00Z",
  "version": "0.6.9",
  "config_fingerprint": "abc123def456",
  "modules": {
    "loaded_count": 21,
    "checksums": {
      "brand-impersonation.yaml": "sha256:abc123...",
      "suspicious-domains.yaml": "sha256:def456..."
    }
  },
  "thresholds": {
    "spam_threshold": 50,
    "reject_threshold": 350,
    "reject_to_tag": true
  },
  "sample_tests": [
    {
      "name": "seo_spam_sample",
      "score": 127,
      "action": "TAG_AS_SPAM",
      "rules": ["Brand Impersonation (+55)", "Suspicious Domains (+50)"]
    }
  ]
}
```

### Key Features
1. **Module Verification** - Lists all loaded modules with checksums
2. **Configuration Fingerprint** - Detects config differences
3. **Sample Email Scoring** - Tests known spam patterns
4. **Threshold Verification** - Confirms scoring thresholds
5. **Environment Tagging** - Identifies test vs production

### Implementation Benefits
- **Immediate Detection** of environment differences
- **Automated Comparison** between test and production
- **Module Loading Verification** - catches missing modules
- **Configuration Drift Detection** - spots config changes
- **Reproducible Results** - same input = same output verification

### Usage in CI/CD
```bash
# In deployment pipeline
./foff-milter --parity-check production > /tmp/prod_parity.json
./foff-milter --parity-check test > /tmp/test_parity.json

# Fail deployment if environments differ
if ! diff -q /tmp/prod_parity.json /tmp/test_parity.json; then
  echo "❌ Production parity check failed!"
  exit 1
fi
```

This feature would have immediately identified that production was missing module files or had different configurations.
