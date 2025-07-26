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
