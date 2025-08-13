# FOFF Milter

A sendmail milter written in Rust for filtering emails based on configurable criteria.

## Features

- **Pattern-based filtering**: Filter emails based on mailer, sender, recipient, subject, or custom headers
- **Unsubscribe link analysis**: Validate and pattern-match unsubscribe links in emails
- **Language detection**: Detect specific languages in email content (Japanese, Chinese, Korean, etc.)
- **Flexible actions**: Reject emails or tag them as spam
- **Complex criteria**: Support for AND/OR logic combinations
- **Regex support**: Use regular expressions for pattern matching
- **YAML configuration**: Easy-to-read configuration format
- **Structured logging**: Actionable logs showing sender, recipient, and actions taken

## Installation

### Prerequisites

- Rust 1.70 or later
- sendmail or postfix with milter support

**Note:** This milter uses the `indymilter` library (v0.3) which provides a pure Rust milter implementation, so you don't need libmilter development headers.

### Building

```bash
cargo build --release
```

## Configuration

Generate a default configuration file:

```bash
./target/release/foff-milter --generate-config /etc/foff-milter.yaml
```

Test your configuration:

```bash
./target/release/foff-milter --test-config -c /etc/foff-milter.yaml
```

### Configuration Format

```yaml
socket_path: "/var/run/foff-milter.sock"
default_action: "Accept"

rules:
  - name: "Block suspicious Chinese services"
    criteria:
      MailerPattern:
        pattern: "service\\..*\\.cn"
    action:
      Reject:
        message: "Mail from suspicious service rejected"
```

### Criteria Types

- **MailerPattern**: Match against X-Mailer or User-Agent headers
- **SenderPattern**: Match against sender email address
- **RecipientPattern**: Match against any recipient email address
- **SubjectPattern**: Match against email subject
- **HeaderPattern**: Match against any email header
- **SubjectContainsLanguage**: Detect specific languages in email subject
- **HeaderContainsLanguage**: Detect specific languages in email headers
- **UnsubscribeLinkValidation**: Validate unsubscribe links in email body and headers
- **UnsubscribeLinkPattern**: Match regex patterns against unsubscribe links
- **UnsubscribeLinkIPAddress**: Detect unsubscribe links that use IP addresses instead of domain names (spam indicator)
- **UnsubscribeMailtoOnly**: Detect emails with exclusively mailto unsubscribe links (phishing indicator)
- **DomainAge**: Check if domains are younger than specified threshold (useful for detecting spam from recently registered domains)
- **InvalidUnsubscribeHeaders**: Detect emails with List-Unsubscribe-Post but no List-Unsubscribe header (RFC violation)
- **AttachmentOnlyEmail**: Detect emails consisting primarily of attachments with minimal text content (malware/phishing vector)
- **EmptyContentEmail**: Detect emails with no meaningful content (empty body, minimal text, reconnaissance emails)
- **And**: All sub-criteria must match
- **Or**: Any sub-criteria must match

### Supported Languages for Detection

- Japanese (`japanese` or `ja`)
- Chinese (`chinese` or `zh`)
- Korean (`korean` or `ko`)
- Arabic (`arabic` or `ar`)
- Russian (`russian` or `ru`)
- Thai (`thai` or `th`)
- Hebrew (`hebrew` or `he`)

### Action Types

- **Accept**: Allow the email through
- **Reject**: Reject the email with a custom message
- **TagAsSpam**: Add a header to mark the email as spam

## Usage

### Running the Milter

```bash
# Run in production mode (daemon)
sudo ./target/release/foff-milter

# Run with custom configuration
sudo ./target/release/foff-milter -c /path/to/config.yaml

# Run with verbose logging
sudo ./target/release/foff-milter -v

# Run in demonstration mode (for testing)
./target/release/foff-milter --demo -c examples/sparkmail-japanese.yaml

# Test configuration without running
./target/release/foff-milter --test-config -c config.yaml

# Run comprehensive configuration testing with regex validation and performance analysis
./target/release/foff-milter --test-comprehensive -c config.yaml
```

### Sendmail Configuration

Add to your sendmail.mc file:

```
INPUT_MAIL_FILTER(`foff-milter', `S=unix:/var/run/foff-milter.sock, F=5, T=S:30s;R:30s')
```

**Important:** The `F=5` flag enables header modifications (F=1 for add headers + F=4 for change headers).

Then rebuild and restart sendmail:

```bash
sudo make -C /etc/mail
sudo systemctl restart sendmail
```

### Postfix Configuration

Add to main.cf:

```
smtpd_milters = unix:/var/run/foff-milter.sock
non_smtpd_milters = unix:/var/run/foff-milter.sock
milter_default_action = accept
```

Then restart postfix:

```bash
sudo systemctl restart postfix
```

## Example Rules

### Production Example 1: Chinese service with Japanese content

```yaml
- name: "Block Chinese services with Japanese content"
  criteria:
    type: "And"
    criteria:
      - type: "MailerPattern"
        pattern: "service\\..*\\.cn"
      - type: "SubjectContainsLanguage"
        language: "japanese"
  action:
    type: "Reject"
    message: "Chinese service with Japanese content blocked"
```

### Production Example 2: Sparkpost to specific user

```yaml
- name: "Block Sparkpost to user@example.com"
  criteria:
    type: "And"
    criteria:
      - type: "MailerPattern"
        pattern: ".*\\.sparkpostmail\\.com"
      - type: "RecipientPattern"
        pattern: "user@example\\.com"
  action:
    type: "Reject"
    message: "Sparkpost to user@example.com blocked"
```

### Combination Criteria: Sparkmail with Japanese content

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

### Block emails from specific domains

```yaml
- name: "Block spam domains"
  criteria:
    type: "SenderPattern"
    pattern: ".*@(spam-domain|bad-domain)\\.com$"
  action:
    type: "Reject"
    message: "Sender domain blocked"
```

### Tag emails with suspicious content

```yaml
- name: "Tag pharmaceutical spam"
  criteria:
    type: "SubjectPattern"
    pattern: "(?i)(viagra|cialis|pharmacy)"
  action:
    type: "TagAsSpam"
    header_name: "X-Spam-Pharma"
    header_value: "YES"
```

### Language detection with domain filtering

```yaml
- name: "Flag Chinese content from suspicious domains"
  criteria:
    type: "And"
    criteria:
      - type: "SenderPattern"
        pattern: ".*@.*\\.(cn|tk|ml)$"
      - type: "SubjectContainsLanguage"
        language: "chinese"
  action:
    type: "TagAsSpam"
    header_name: "X-Spam-Chinese-Suspicious"
    header_value: "Chinese content from suspicious domain"
```

### Unsubscribe link validation

```yaml
- name: "Tag emails with invalid unsubscribe links"
  criteria:
    type: "UnsubscribeLinkValidation"
    timeout_seconds: 5        # Optional: timeout for validation (default: 5)
    check_dns: true          # Optional: check DNS resolution (default: true)
    check_http: false        # Optional: check HTTP accessibility (default: false)
  action:
    type: "TagAsSpam"
    header_name: "X-Spam-Invalid-Unsubscribe"
    header_value: "Unsubscribe link validation failed"
```

### Unsubscribe link pattern matching

```yaml
- name: "Tag emails with Google unsubscribe links"
  criteria:
    type: "UnsubscribeLinkPattern"
    pattern: ".*\\.google\\.com.*"
  action:
    type: "TagAsSpam"
    header_name: "X-Suspicious-Unsubscribe"
    header_value: "YES"
```

See `examples/unsubscribe-pattern-example.yaml` for more comprehensive examples of unsubscribe link pattern matching.

### Unsubscribe link IP address detection

```yaml
- name: "Block unsubscribe links with IP addresses"
  criteria:
    type: "UnsubscribeLinkIPAddress"
    check_ipv4: true
    check_ipv6: true
    allow_private_ips: false
  action:
    type: "Reject"
    message: "Unsubscribe link uses IP address instead of domain name"
```

```yaml
- name: "Block free email with IP-based unsubscribe links"
  criteria:
    type: "And"
    criteria:
      - type: "SenderPattern"
        pattern: ".*@(gmail|outlook|yahoo|hotmail)\\.(com|net)$"
      - type: "UnsubscribeLinkIPAddress"
        check_ipv4: true
        check_ipv6: true
        allow_private_ips: false
  action:
    type: "Reject"
    message: "Free email service with IP-based unsubscribe link"
```

This detects unsubscribe links that use IP addresses instead of proper domain names, which is a strong spam indicator since legitimate businesses use proper domains for their unsubscribe mechanisms.

**Configuration Options:**
- `check_ipv4`: Whether to check for IPv4 addresses (default: true)
- `check_ipv6`: Whether to check for IPv6 addresses (default: true)
- `allow_private_ips`: Whether to allow private/local IP addresses (default: false)

**Detected Patterns:**
- IPv4 addresses: `http://192.168.1.1/unsubscribe`, `https://8.8.8.8/opt-out`
- IPv6 addresses: `http://[2001:db8::1]/unsubscribe`, `https://[::1]/remove`
- Private IP filtering: Distinguishes between private (192.168.x.x, 10.x.x.x) and public IPs
- URL parsing: Handles various URL formats and protocols

See `examples/ip-address-unsubscribe-detection.yaml` for comprehensive IP address unsubscribe link detection rules.

### Mailto-only unsubscribe detection

```yaml
- name: "Block emails with mailto-only unsubscribe links"
  criteria:
    type: "UnsubscribeMailtoOnly"
    allow_mixed: false  # Flag any emails with mailto links (default)
  action:
    type: "Reject"
    message: "Suspicious email with mailto-only unsubscribe links"
```

```yaml
- name: "Tag emails with exclusively mailto unsubscribe links"
  criteria:
    type: "UnsubscribeMailtoOnly"
    allow_mixed: true   # Only flag if ALL links are mailto
  action:
    type: "TagAsSpam"
    header_name: "X-Phishing-Mailto-Only"
    header_value: "All unsubscribe links are mailto"
```

See `examples/mailto-unsubscribe-example.yaml` for comprehensive examples of mailto unsubscribe detection.

### Domain age checking

```yaml
- name: "Block young domains"
  criteria:
    type: "DomainAge"
    max_age_days: 90
    check_sender: true
    check_reply_to: false
    timeout_seconds: 10
    use_mock_data: false  # Set to true for testing
  action:
    type: "Reject"
    message: "Email from recently registered domain rejected"
```

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
        pattern: "(?i)(paypal|amazon|microsoft|state farm)"
  action:
    type: "Reject"
    message: "Young domain impersonating trusted brand blocked"
```

See `examples/domain-age-example.yaml` and `DOMAIN_AGE.md` for comprehensive domain age checking examples.

### Bulk spam detection

```yaml
- name: "Block bulk spam with undisclosed recipients from free email"
  criteria:
    type: "And"
    criteria:
      - type: "HeaderPattern"
        header: "to"
        pattern: "(?i)undisclosed.{0,15}recipients"
      - type: "SenderPattern"
        pattern: ".*@(outlook|gmail|yahoo|hotmail|aol)\\.(com|net|org)$"
  action:
    type: "Reject"
    message: "Bulk spam with undisclosed recipients from free email service blocked"
```

```yaml
- name: "Advanced bulk spam with multiple indicators"
  criteria:
    type: "And"
    criteria:
      - type: "SenderPattern"
        pattern: ".*@(outlook|gmail|yahoo|hotmail)\\.(com|net)$"
      - type: "HeaderPattern"
        header: "to"
        pattern: "(?i)undisclosed.{0,15}recipients"
      - type: "Or"
        criteria:
          - type: "SubjectPattern"
            pattern: "(?i)(congratulations|award|prize|winner|lottery)"
          - type: "SenderPattern"
            pattern: "^[a-z]{8,}@"
  action:
    type: "Reject"
    message: "Multi-indicator bulk spam detected"
```

See `examples/bulk-spam-detection.yaml` for comprehensive bulk spam detection rules.

### Invalid unsubscribe headers detection

```yaml
- name: "Block emails with invalid unsubscribe headers"
  criteria:
    type: "InvalidUnsubscribeHeaders"
  action:
    type: "Reject"
    message: "Invalid unsubscribe headers detected (RFC violation)"
```

```yaml
- name: "Enhanced spam detection with invalid unsubscribe headers"
  criteria:
    type: "And"
    criteria:
      - type: "InvalidUnsubscribeHeaders"
      - type: "SubjectPattern"
        pattern: "(?i)(weight.{0,10}loss|secret.{0,10}revealed|elon.{0,10}musk)"
  action:
    type: "Reject"
    message: "Spam with invalid unsubscribe headers and suspicious content"
```

This detects emails that have `List-Unsubscribe-Post: List-Unsubscribe=One-Click` but no actual `List-Unsubscribe` header, which is an RFC violation and common spam pattern.

See `examples/invalid-unsubscribe-headers.yaml` for comprehensive invalid unsubscribe header detection rules.

### Attachment-only email detection

```yaml
- name: "Block PDF-only emails with minimal text"
  criteria:
    type: "AttachmentOnlyEmail"
    max_text_length: 100
    ignore_whitespace: true
    suspicious_types: ["pdf"]
    min_attachment_size: 10240  # 10KB minimum
    check_disposition: true
  action:
    type: "Reject"
    message: "PDF-only email with minimal text detected"
```

```yaml
- name: "Block random Gmail addresses with attachment-only emails"
  criteria:
    type: "And"
    criteria:
      - type: "SenderPattern"
        pattern: "^[a-z]{15,}\\d*@gmail\\.com$"
      - type: "AttachmentOnlyEmail"
        max_text_length: 50
        suspicious_types: ["pdf", "doc", "docx"]
        min_attachment_size: 5120
        check_disposition: true
  action:
    type: "Reject"
    message: "Random Gmail address sending attachment-only email"
```

This detects emails that consist primarily of attachments (PDF, DOC, DOCX, etc.) with minimal text content, which is a common vector for malware delivery and phishing attacks.

**Configuration Options:**
- `max_text_length`: Maximum allowed text content (default: 100 characters)
- `ignore_whitespace`: Whether to ignore whitespace when counting text (default: true)
- `suspicious_types`: Attachment types to flag (default: ["pdf", "doc", "docx", "xls", "xlsx"])
  - Supported types: "pdf", "doc", "docx", "xls", "xlsx", "zip", "rar", "exe"
- `min_attachment_size`: Minimum attachment size to consider suspicious (default: 10KB)
- `check_disposition`: Whether to check Content-Disposition headers (default: true)

See `examples/attachment-only-detection.yaml` for comprehensive attachment-only email detection rules.

### Empty content email detection

```yaml
- name: "Block completely empty emails"
  criteria:
    type: "EmptyContentEmail"
    max_text_length: 5          # Allow up to 5 characters
    ignore_whitespace: true     # Ignore whitespace when counting
    ignore_signatures: true     # Ignore email signatures
    require_empty_subject: false # Either empty subject OR body triggers
    min_subject_length: 3       # Subject needs 3+ chars to not be empty
    ignore_html_tags: true      # Ignore HTML tags when counting
  action:
    type: "Reject"
    message: "Empty email content rejected"
```

```yaml
- name: "Block reconnaissance emails"
  criteria:
    type: "And"
    criteria:
      - type: "EmptyContentEmail"
        max_text_length: 15       # Very minimal content
        ignore_whitespace: true
        ignore_signatures: true
        require_empty_subject: false
        min_subject_length: 2
        ignore_html_tags: true
      - type: "Or"
        criteria:
          - type: "SubjectPattern"
            pattern: "(?i)^(test|hello|hi|hey)$"
          - type: "SubjectPattern"
            pattern: "^$"  # Completely empty subject
  action:
    type: "Reject"
    message: "Reconnaissance email blocked"
```

```yaml
- name: "Tag empty emails from free email services"
  criteria:
    type: "And"
    criteria:
      - type: "SenderPattern"
        pattern: ".*@(gmail|outlook|yahoo|hotmail|aol)\\.(com|net|org)$"
      - type: "EmptyContentEmail"
        max_text_length: 10
        ignore_whitespace: true
        ignore_signatures: true
        require_empty_subject: false
        min_subject_length: 5
        ignore_html_tags: true
  action:
    type: "TagAsSpam"
    header_name: "X-Spam-Empty-Content"
    header_value: "Empty email from free service"
```

This detects emails with no meaningful content, which are often used for reconnaissance, address validation, or as part of multi-stage attacks.

**Configuration Options:**
- `max_text_length`: Maximum allowed text content (default: 10 characters)
- `ignore_whitespace`: Whether to ignore whitespace when counting text (default: true)
- `ignore_signatures`: Whether to ignore common email signatures and footers (default: true)
- `require_empty_subject`: Whether to require both empty subject AND body (default: false - either is sufficient)
- `min_subject_length`: Minimum subject length to not be considered empty (default: 3 characters)
- `ignore_html_tags`: Whether to ignore HTML tags when counting content (default: true)

**Detected Patterns:**
- Completely empty emails (no subject, no body)
- Emails with only whitespace or punctuation
- Emails with only signatures/footers
- Minimal content emails ("hi", "test", "hello")
- HTML emails with no actual text content
- Reconnaissance emails with placeholder content

See `examples/empty-content-detection.yaml` for comprehensive empty content email detection rules.

### Complex rule with multiple conditions

```yaml
- name: "Suspicious foreign urgent emails"
  criteria:
    And:
      - SenderPattern:
          pattern: ".*@.*\\.(cn|ru|tk)$"
      - Or:
        - SubjectPattern:
            pattern: "(?i)(urgent|immediate|asap)"
        - HeaderPattern:
            header: "x-priority"
            pattern: "1"
  action:
    TagAsSpam:
      header_name: "X-Spam-Suspicious"
      header_value: "Foreign urgent email"
```

## Logging

The milter logs to stdout/stderr with structured, actionable log messages. You can redirect logs to a file or use systemd for log management.

### Log Format

Email processing logs show sender, recipient, and action taken:
- `ACCEPT from=sender@domain.com to=recipient@domain.com`
- `REJECT from=sender@domain.com to=recipient@domain.com reason=rejection message`
- `TAG from=sender@domain.com to=recipient@domain.com header=X-Spam-Flag:YES`

### Log Levels
- ERROR: Critical errors
- WARN: Warning messages
- INFO: General information and email processing results (default)
- DEBUG: Detailed debugging including rule evaluation (use -v flag)

## Systemd Service

Create `/etc/systemd/system/foff-milter.service`:

```ini
[Unit]
Description=FOFF Email Milter
After=network.target

[Service]
Type=simple
User=milter
Group=milter
ExecStart=/usr/local/bin/foff-milter -c /etc/foff-milter.yaml
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
```

Enable and start:

```bash
sudo systemctl enable foff-milter
sudo systemctl start foff-milter
```

## Security Considerations

- Run the milter as a non-privileged user
- Ensure the socket file has appropriate permissions
- Regularly review and update your filtering rules
- Monitor logs for potential issues
- Test configuration changes in a non-production environment

## Configuration Testing

### Basic Configuration Validation

Test your configuration file syntax and structure:

```bash
./target/release/foff-milter --test-config -c config.yaml
```

This performs basic validation:
- ✅ YAML syntax checking
- ✅ Configuration structure validation
- ✅ Rule loading verification

### Comprehensive Configuration Testing

For production deployments, use comprehensive testing that validates regex patterns against real email scenarios:

```bash
./target/release/foff-milter --test-comprehensive -c config.yaml
```

This performs advanced validation:
- ✅ **Regex compilation testing** - Ensures all patterns are valid
- ✅ **Performance analysis** - Identifies slow regex patterns
- ✅ **Email corpus testing** - Tests patterns against 20+ sample emails
- ✅ **Edge case detection** - Tests with unicode, empty fields, long content
- ✅ **Runtime safety** - Catches patterns that could panic during execution

#### Example Output

```
🔍 Running comprehensive configuration testing...

✅ Configuration validation PASSED!

📊 Test Summary:
  Total rules: 10
  Total regex patterns: 20
  Test time: 175ms

⚠️  Performance Warnings (2):
  • Rule 4 (Tag pharmaceutical spam): SubjectPattern pattern '(?i)(viagra|cialis|pharmacy)' is slow (2.09ms for 1000 iterations)
  • Rule 6 (Suspicious urgent emails): SubjectPattern pattern contains nested .* which may cause performance issues

🎉 All patterns are valid and performant!
```

#### What Gets Tested

The comprehensive testing validates patterns against:
- **Legitimate emails** (PayPal, Amazon, corporate)
- **Suspicious emails** (free email services, suspicious TLDs)
- **Phishing attempts** (spoofed domains, urgent language)
- **Language detection** (Japanese, Chinese, Korean text)
- **Unsubscribe links** (valid, IP-based, mailto-only)
- **Edge cases** (empty fields, unicode, very long content)

#### Performance Benchmarking

Patterns are benchmarked for performance:
- **Fast patterns**: < 1ms for 1000 iterations ✅
- **Slow patterns**: > 1ms for 1000 iterations ⚠️
- **Problematic patterns**: Nested `.*` or very long patterns 🚨

Use comprehensive testing before deploying to production to catch regex issues that could cause crashes or performance problems.

## Troubleshooting

### Common Issues

1. **Permission denied on socket**: Ensure the milter user can write to the socket directory
2. **Milter not receiving emails**: Check sendmail/postfix milter configuration
3. **Regex errors**: Test your patterns with the `--test-config` option
4. **Performance issues**: Consider the complexity of your regex patterns

### Debug Mode

Run with verbose logging to see detailed information:

```bash
sudo ./target/release/foff-milter -v -c /etc/foff-milter.yaml
```

## License

This project is licensed under the MIT License - see the LICENSE file for details.
