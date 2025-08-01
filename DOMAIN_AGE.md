# Domain Age Checking Feature

The FOFF milter now includes domain age checking functionality to detect and filter emails from recently registered domains, which are commonly used in spam and phishing campaigns.

## Overview

The `DomainAge` criteria allows you to:
- Check if domains are younger than a specified threshold (in days)
- Examine multiple email sources (sender, reply-to, from header)
- Use mock data for testing or real WHOIS lookups for production
- Cache results to improve performance

## Configuration

### Basic Configuration

```yaml
- name: "Block young domains"
  criteria:
    type: "DomainAge"
    max_age_days: 90          # Block domains younger than 90 days
    check_sender: true        # Check sender domain (default: true)
    check_reply_to: false     # Check reply-to domain (default: false)
    check_from_header: false  # Check from header domain (default: false)
    timeout_seconds: 10       # WHOIS lookup timeout (default: 10)
    use_mock_data: false      # Use mock data for testing (default: false)
  action:
    type: "Reject"
    message: "Email from recently registered domain rejected"
```

### Configuration Options

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `max_age_days` | u32 | Required | Maximum age in days for domains to be considered "young" |
| `check_sender` | bool | true | Check the envelope sender domain |
| `check_reply_to` | bool | false | Check the Reply-To header domain |
| `check_from_header` | bool | false | Check the From header domain |
| `timeout_seconds` | u64 | 10 | Timeout for WHOIS API calls |
| `use_mock_data` | bool | false | Use mock data instead of real WHOIS lookups |

## Mock Data for Testing

When `use_mock_data: true`, the following domains are available for testing:

| Domain | Age (days) | Description |
|--------|------------|-------------|
| `psybook.info` | 90 | Young domain (matches your spam example) |
| `suspicious.tk` | 30 | Very young domain with suspicious TLD |
| `newdomain.info` | 45 | Young domain |
| `example.com` | 8000 | Very old, established domain |
| `google.com` | 9000 | Very old, established domain |
| `established.org` | 3650 | 10-year-old domain |

Any other domain defaults to 365 days (1 year) in mock mode.

## Example Configurations

### 1. Simple Young Domain Blocking

```yaml
- name: "Block domains under 30 days"
  criteria:
    type: "DomainAge"
    max_age_days: 30
    check_sender: true
    use_mock_data: true  # For testing
  action:
    type: "Reject"
    message: "Domain too new, blocked for security"
```

### 2. Tag Suspicious Young Domains

```yaml
- name: "Tag young domains"
  criteria:
    type: "DomainAge"
    max_age_days: 90
    check_sender: true
    check_reply_to: true
  action:
    type: "TagAsSpam"
    header_name: "X-Spam-Young-Domain"
    header_value: "Domain registered within 90 days"
```

### 3. Complex Rule: Young Domain + Brand Impersonation

```yaml
- name: "Young domain impersonating brands"
  criteria:
    type: "And"
    criteria:
      - type: "DomainAge"
        max_age_days: 120
        check_sender: true
      - type: "HeaderPattern"
        header: "from"
        pattern: "(?i)(paypal|amazon|microsoft|apple|google)"
  action:
    type: "Reject"
    message: "Young domain impersonating trusted brand blocked"
```

### 4. Young Domain + Suspicious TLD

```yaml
- name: "Young suspicious TLD domains"
  criteria:
    type: "And"
    criteria:
      - type: "DomainAge"
        max_age_days: 60
        check_sender: true
      - type: "SenderPattern"
        pattern: ".*@.*\\.(tk|ml|ga|cf|pw|top)$"
  action:
    type: "TagAsSpam"
    header_name: "X-Spam-Young-Suspicious-TLD"
    header_value: "Young domain with suspicious TLD"
```

### 5. Multi-Source Domain Age Check

```yaml
- name: "Comprehensive domain age check"
  criteria:
    type: "DomainAge"
    max_age_days: 45
    check_sender: true
    check_reply_to: true
    check_from_header: true
  action:
    type: "TagAsSpam"
    header_name: "X-Spam-Multi-Young"
    header_value: "Young domain in multiple headers"
```

## Real-World Usage

### Production Configuration

For production use, set `use_mock_data: false` (or omit it) to use real WHOIS lookups:

```yaml
- name: "Production young domain filter"
  criteria:
    type: "DomainAge"
    max_age_days: 90
    check_sender: true
    timeout_seconds: 10
  action:
    type: "TagAsSpam"
    header_name: "X-Spam-Young-Domain"
    header_value: "YES"
```

### WHOIS API Integration

The domain age checker attempts to use multiple WHOIS APIs:
1. `https://api.whoisjson.com/v1/{domain}`
2. `https://whoisjson.com/api/v1/whois?domain={domain}`

If all APIs fail, it falls back to DNS resolution checking.

### Caching

Domain information is cached for 24 hours to improve performance and reduce API calls. The cache is in-memory and will be cleared when the milter restarts.

## Testing

### Test Configuration

Use the provided example configuration:

```bash
./target/release/foff-milter --test-config -c examples/domain-age-example.yaml
```

### Test with Mock Data

The example configuration uses mock data, so you can test immediately:

```bash
# Test the configuration
./target/release/foff-milter --test-config -c examples/domain-age-example.yaml

# Run the test binary
cargo run --bin test-domain-age
```

### Expected Results

With the mock data:
- `psybook.info` (90 days) → Blocked by rules with thresholds ≥ 90 days
- `suspicious.tk` (30 days) → Blocked by most rules
- `google.com` (9000 days) → Not blocked by any domain age rules
- `newdomain.info` (45 days) → Blocked by rules with thresholds ≥ 45 days

## Performance Considerations

1. **Caching**: Domain information is cached for 24 hours
2. **Timeouts**: Configure appropriate timeouts (5-10 seconds recommended)
3. **API Limits**: Be aware of WHOIS API rate limits in production
4. **Fallback**: DNS fallback is used when WHOIS APIs fail

## Security Notes

1. **API Keys**: Some WHOIS services require API keys for higher rate limits
2. **Privacy**: WHOIS lookups may reveal information about your mail server
3. **Reliability**: Domain age checking should be one of multiple spam indicators
4. **False Positives**: Some legitimate services use young domains

## Troubleshooting

### Common Issues

1. **WHOIS API Failures**: Check network connectivity and API availability
2. **Timeout Errors**: Increase `timeout_seconds` if needed
3. **False Positives**: Adjust `max_age_days` threshold
4. **Performance**: Enable caching and use appropriate timeouts

### Debug Logging

Enable debug logging to see detailed domain age checking:

```bash
RUST_LOG=debug ./target/release/foff-milter -c config.yaml
```

This will show:
- Domain extraction from email addresses
- WHOIS API calls and responses
- Cache hits/misses
- Age calculations and decisions

## Integration with Your Spam Example

For the spam example you provided (`psybook.info` domain), this configuration would catch it:

```yaml
- name: "Block young domains like psybook.info"
  criteria:
    type: "And"
    criteria:
      - type: "DomainAge"
        max_age_days: 120  # psybook.info is ~90 days old
        check_sender: true
        use_mock_data: true
      - type: "HeaderPattern"
        header: "from"
        pattern: "(?i)state\\s*farm"  # Catches brand impersonation
  action:
    type: "Reject"
    message: "Young domain impersonating State Farm blocked"
```

This rule would:
1. Check if the sender domain is younger than 120 days
2. Check if the From header contains "State Farm"
3. Reject the email if both conditions are met

The `psybook.info` domain (90 days old in mock data) claiming to be from "State Farm" would be blocked.
