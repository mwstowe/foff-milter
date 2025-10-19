# FOFF Milter

A comprehensive, enterprise-grade, AI-powered email security platform written in Rust for filtering emails based on advanced threat detection, machine learning, and deep inspection capabilities.

## 🚀 Complete Email Security Platform

FOFF Milter is a production-ready email security solution that provides:

- **🛡️ Comprehensive Threat Detection**: 9 specialized detection modules covering all major threat vectors
- **🤖 AI-Powered Intelligence**: Machine learning with adaptive learning and predictive capabilities  
- **🔍 Advanced Security**: Deep inspection of attachments, URLs, and images with OCR
- **📊 Enterprise Analytics**: Real-time monitoring, reporting, and business intelligence
- **🔄 Enterprise Integration**: REST API, SIEM integration, webhooks, and cloud connectivity
- **⚡ Production Performance**: Optimized for high-volume processing with caching and parallel execution
- **🌍 International Support**: Multi-language detection and encoding abuse protection
- **📈 Self-Optimizing**: Performance optimization and machine learning-driven improvements

## Features

### Core Detection Capabilities
- **Suspicious Domain Detection**: TLD risk assessment, domain reputation, and newly registered domain detection
- **Brand Impersonation Protection**: Major brand protection with authentication failure detection
- **Health & Medical Spam**: Medical misinformation, pharmaceutical spam, and health scam detection
- **Phishing & Scam Detection**: Comprehensive phishing, romance fraud, and social engineering protection
- **Adult Content Filtering**: Adult content, romance scams, and inappropriate material detection
- **E-commerce Fraud**: Shopping scams, marketplace fraud, and fake product detection
- **Financial Services Protection**: Banking phishing, cryptocurrency scams, and financial fraud detection
- **Technology Scam Prevention**: Tech support fraud, software scams, and fake security alerts
- **Multi-Language Threat Detection**: International threats, encoding abuse, and script mixing detection

### Advanced Security Features
- **Attachment Analysis**: Deep inspection of PDF, Office documents, archives, and executables
- **URL Scanning**: Real-time URL reputation, phishing detection, and redirect analysis
- **Image OCR**: Text extraction from images, QR code detection, and hidden threat analysis
- **Behavioral Sandboxing**: Dynamic analysis framework for suspicious file execution
- **Threat Intelligence**: Hash reputation, domain reputation, and YARA rule integration

### AI & Machine Learning
- **Adaptive Learning**: Continuous model updates from new email data and feedback
- **Anomaly Detection**: Statistical and ML-based outlier identification for unknown threats
- **Behavioral Analysis**: Sender reputation, domain reputation, and temporal pattern analysis
- **Predictive Detection**: Threat forecasting, campaign detection, and emerging threat identification
- **Self-Optimization**: Automatic threshold tuning, module weighting, and performance optimization

### Enterprise Integration
- **REST API**: Comprehensive HTTP API for email processing, analytics, and management
- **SIEM Integration**: Native connectors for Splunk, Elasticsearch, QRadar, and Azure Sentinel
- **Webhook Notifications**: Real-time alerts to Slack, Teams, and custom endpoints
- **Cloud Integration**: AWS, Azure, and Google Cloud service integration
- **Container Support**: Docker and Kubernetes deployment with auto-scaling

### Analytics & Monitoring
- **Real-Time Dashboard**: Live system monitoring and threat detection statistics
- **Advanced Reporting**: JSON, CSV, HTML reports with executive summaries
- **Compliance Features**: Audit logging, GDPR compliance, and regulatory reporting
- **Performance Metrics**: Comprehensive system performance and effectiveness tracking
- **Threat Intelligence**: Campaign detection, attribution analysis, and trend forecasting

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

The system uses a modular configuration approach with separate YAML files for different components:

### Core Configuration Files

```
configs/
├── suspicious-domains.yaml    # Domain reputation & TLD risk assessment
├── brand-impersonation.yaml   # Brand protection & authentication failures
├── health-spam.yaml          # Medical misinformation & pharmaceutical spam
├── phishing-scams.yaml       # Comprehensive scam & phishing detection
├── adult-content.yaml        # Adult content & romance fraud detection
├── ecommerce-scams.yaml      # Shopping fraud & marketplace scams
├── financial-services.yaml   # Banking phishing & financial fraud
├── technology-scams.yaml     # Tech support fraud & software scams
├── multi-language.yaml       # International threats & encoding abuse
├── performance.yaml          # Performance optimization & monitoring
├── analytics.yaml            # Advanced analytics & reporting
├── machine-learning.yaml     # AI-powered adaptive intelligence
├── integration.yaml          # Enterprise integration & API connectivity
└── advanced-security.yaml    # Deep inspection & threat analysis
```

### Generate Default Configuration

```bash
./target/release/foff-milter --generate-config /etc/foff-milter.yaml
```

### Test Configuration

```bash
./target/release/foff-milter --test-config -c /etc/foff-milter.yaml
```

### Basic Configuration Format

```yaml
socket_path: "/var/run/foff-milter.sock"
default_action:
  type: "Accept"

# Statistics configuration (optional)
statistics:
  enabled: true
  database_path: "/var/lib/foff-milter/stats.db"
  flush_interval_seconds: 60

# Analytics configuration (optional)
analytics:
  enabled: true
  database_path: "/var/lib/foff-milter/analytics.db"
  retention_days: 90

# Machine learning configuration (optional)
machine_learning:
  enabled: true
  adaptive_learning: true
  anomaly_detection: true

# Integration configuration (optional)
integration:
  rest_api:
    enabled: true
    port: 8080
  webhooks:
    enabled: true
  siem_integration:
    enabled: true

# Advanced security configuration (optional)
advanced_security:
  attachment_analysis: true
  url_scanning: true
  image_ocr: true

rules:
  - name: "Block suspicious domains"
    criteria:
      type: "SenderPattern"
      pattern: ".*@suspicious\\.domain$"
    action:
      type: "Reject"
      message: "Suspicious domain blocked"
```

### Criteria Types

#### Basic Pattern Matching
- **MailerPattern**: Match against X-Mailer or User-Agent headers
- **SenderPattern**: Match against sender email address
- **RecipientPattern**: Match against any recipient email address
- **SubjectPattern**: Match against email subject
- **HeaderPattern**: Match against any email header

#### Language & Content Detection
- **SubjectContainsLanguage**: Detect specific languages in email subject
- **HeaderContainsLanguage**: Detect specific languages in email headers

#### Unsubscribe & Link Analysis
- **UnsubscribeLinkValidation**: Validate unsubscribe links in email body and headers
- **UnsubscribeLinkPattern**: Match regex patterns against unsubscribe links
- **UnsubscribeLinkIPAddress**: Detect unsubscribe links that use IP addresses instead of domain names (spam indicator)
- **UnsubscribeMailtoOnly**: Detect emails with exclusively mailto unsubscribe links (phishing indicator)
- **InvalidUnsubscribeHeaders**: Detect emails with List-Unsubscribe-Post but no List-Unsubscribe header (RFC violation)

#### Domain & Reputation Analysis
- **DomainAge**: Check if domains are younger than specified threshold (useful for detecting spam from recently registered domains)

#### Content Structure Analysis
- **AttachmentOnlyEmail**: Detect emails consisting primarily of attachments with minimal text content (malware/phishing vector)
- **EmptyContentEmail**: Detect emails with no meaningful content (empty body, minimal text, reconnaissance emails)

#### Service Abuse Detection
- **EmailServiceAbuse**: Detect abuse of legitimate email services (SendGrid, Mailchimp, etc.) for phishing and brand impersonation
- **GoogleGroupsAbuse**: Detect abuse of Google Groups mailing lists for phishing campaigns and reward scams
- **DocuSignAbuse**: Detect abuse of DocuSign infrastructure for phishing campaigns

#### Advanced Threat Detection
- **SenderSpoofingExtortion**: Detect extortion attempts where attackers spoof the sender to appear as the recipient

#### Logical Operators
- **And**: All sub-criteria must match
- **Or**: Any sub-criteria must match
- **Not**: Negates the result of the nested criteria (inverts true/false)

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
- **ReportAbuse**: Report abuse to email service providers and optionally take additional action
- **UnsubscribeGoogleGroup**: Automatically unsubscribe from Google Groups and optionally take additional action

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

# Test email processing
./target/release/foff-milter --test-email email.eml -c config.yaml

# View statistics
./target/release/foff-milter --stats -c config.yaml

# Generate analytics report
./target/release/foff-milter --analytics-report json -c config.yaml
```

### API Usage

```bash
# Start REST API server (if enabled in integration.yaml)
./target/release/foff-milter --api-server -c config.yaml

# Process email via API
curl -X POST http://localhost:8080/api/v1/email/analyze \
  -H "X-API-Key: your-api-key" \
  -H "Content-Type: application/json" \
  -d '{"sender": "test@example.com", "subject": "Test", "body": "Test email"}'

# Get analytics dashboard
curl -H "X-API-Key: your-api-key" \
  http://localhost:8080/api/v1/analytics/dashboard

# Get system health
curl -H "X-API-Key: your-api-key" \
  http://localhost:8080/api/v1/health
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

### Exclude legitimate services from filtering

```yaml
- name: "Tag suspicious mailto-only unsubscribe (excluding legitimate services)"
  criteria:
    type: "And"
    criteria:
      # Detect mailto-only unsubscribe links
      - type: "UnsubscribeMailtoOnly"
        allow_mixed: true
      # Exclude legitimate business services
      - type: "Not"
        criteria:
          type: "SenderPattern"
          pattern: ".*@(signnow|docusign|hellosign|pandadoc|adobe|pdffiller)\\.com$"
  action:
    type: "TagAsSpam"
    header_name: "X-Phishing-Mailto-Only"
    header_value: "Suspicious mailto-only unsubscribe from unknown sender"
```

### Complex logic with Not criteria

```yaml
- name: "Tag suspicious emails from free services (excluding newsletters)"
  criteria:
    type: "And"
    criteria:
      # From free email services
      - type: "SenderPattern"
        pattern: ".*@(gmail|outlook|yahoo|hotmail)\\.(com|net)$"
      # NOT legitimate newsletter patterns
      - type: "Not"
        criteria:
          type: "Or"
          criteria:
            - type: "HeaderPattern"
              header: "list-unsubscribe"
              pattern: ".*"
            - type: "SubjectPattern"
              pattern: "(?i)(newsletter|digest|weekly|monthly)"
  action:
    type: "TagAsSpam"
    header_name: "X-Free-Email-Suspicious"
    header_value: "Free email without newsletter indicators"
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
  - Supported types: "pdf", "doc", "docx", "xls", "xlsx", "zip", "rar", "exe", "ics", "vcf"
- `min_attachment_size`: Minimum attachment size to consider suspicious (default: 10KB)
- `check_disposition`: Whether to check Content-Disposition headers (default: true)

**Important**: The `suspicious_types` parameter is strictly enforced. If you specify `suspicious_types: ["rar"]`, only emails with RAR attachments will be flagged. Legitimate attachments like ICS calendar files, PDFs, or other types will be ignored unless explicitly included in the list.

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

### Email service abuse detection

Detect when legitimate email services (SendGrid, Mailchimp, etc.) are being abused for phishing and brand impersonation:

```yaml
- name: "Block email service abuse with brand impersonation"
  criteria:
    type: "EmailServiceAbuse"
    # All options use defaults - detects major email services and brands
    check_reply_to_mismatch: true      # Check for free email reply-to addresses
    check_brand_impersonation: true    # Check for major brand names in From header
    check_suspicious_subjects: true    # Check for suspicious subject patterns
  action:
    type: "Reject"
    message: "Email service abuse detected - brand impersonation with reply-to mismatch"
```

```yaml
- name: "Custom email service abuse detection"
  criteria:
    type: "EmailServiceAbuse"
    legitimate_services: ["sendgrid.net", "mailchimp.com", "constantcontact.com"]
    brand_keywords: ["ebay", "paypal", "amazon", "microsoft", "apple", "google"]
    free_email_domains: ["gmail.com", "outlook.com", "yahoo.com", "hotmail.com"]
    check_reply_to_mismatch: true
    check_brand_impersonation: true
    check_suspicious_subjects: false   # Disable subject checking
  action:
    type: "TagAsSpam"
    header_name: "X-Email-Service-Abuse"
    header_value: "Brand impersonation detected"
```

```yaml
- name: "eBay impersonation via SendGrid"
  criteria:
    type: "And"
    criteria:
      - type: "EmailServiceAbuse"
        legitimate_services: ["sendgrid.net"]
        brand_keywords: ["ebay", "myebay"]
        check_reply_to_mismatch: true
        check_brand_impersonation: true
        check_suspicious_subjects: true
      - type: "SubjectPattern"
        pattern: "(?i)(received.*message|new.*message|inbox.*message)"
  action:
    type: "Reject"
    message: "eBay impersonation via SendGrid blocked"
```

This detects sophisticated phishing attacks where attackers abuse legitimate email services to send emails that impersonate major brands while using free email addresses for replies.

**Configuration Options:**
- `legitimate_services`: Email service domains to check (default: SendGrid, Mailchimp, ConstantContact, Mailgun, etc.)
- `brand_keywords`: Brand names that indicate impersonation (default: eBay, PayPal, Amazon, Microsoft, Apple, Google, etc.)
- `free_email_domains`: Free email domains for reply-to mismatch detection (default: Gmail, Outlook, Yahoo, Hotmail, etc.)
- `check_reply_to_mismatch`: Whether to check for reply-to domain mismatch (default: true)
- `check_brand_impersonation`: Whether to check for brand impersonation in From header (default: true)
- `check_suspicious_subjects`: Whether to check for suspicious subject patterns (default: true)

**Detected Patterns:**
- SendGrid emails with "myeBay" in From header and Gmail reply-to
- Mailchimp emails impersonating PayPal with Outlook reply-to
- Brand impersonation: Major brand names in From header via email services
- Reply-to hijacking: Responses redirected to attacker's free email
- Suspicious subjects: "You Received (2) new Inbox Message", "Urgent: Verify your account"

**Why This Works:**
- Legitimate brands don't use email services with free email reply-to addresses
- Attackers abuse trusted email services to bypass SPF/DKIM authentication
- Multiple indicators (service + brand + reply mismatch) reduce false positives
- Requires at least 2 abuse indicators for a match to avoid false positives

See `examples/email-service-abuse-example.yaml` for comprehensive email service abuse detection rules.

### Google Groups abuse detection

Detect when Google Groups mailing lists are being abused for phishing campaigns and reward scams:

```yaml
- name: "Block Google Groups phishing campaigns"
  criteria:
    type: "GoogleGroupsAbuse"
    # All options use defaults - detects suspicious domains and reward patterns
    check_domain_reputation: true      # Check for suspicious domain patterns
    check_reward_subjects: true        # Check for reward/prize subject patterns
    check_suspicious_senders: true     # Check for suspicious sender names
    min_indicators: 2                  # Require at least 2 abuse indicators
  action:
    type: "Reject"
    message: "Google Groups phishing campaign blocked"
```

```yaml
- name: "Custom Google Groups abuse detection"
  criteria:
    type: "GoogleGroupsAbuse"
    suspicious_domains: ["*.tk", "*.ml", "*.ga", "*.top", "*texas.com", "service.*"]
    reward_keywords: ["reward", "prize", "expires", "urgent", "emergency kit", "car kit"]
    suspicious_sender_names: ["confirmation required", "urgent", "admin", "service"]
    check_domain_reputation: true
    check_reward_subjects: true
    check_suspicious_senders: true
    min_indicators: 2
  action:
    type: "TagAsSpam"
    header_name: "X-Google-Groups-Abuse"
    header_value: "Phishing campaign detected"
```

```yaml
- name: "Car Emergency Kit reward scam"
  criteria:
    type: "And"
    criteria:
      - type: "GoogleGroupsAbuse"
        suspicious_domains: ["*texas.com", "*.tk", "*.ml"]
        reward_keywords: ["car emergency kit", "emergency kit", "reward", "expires"]
        check_domain_reputation: true
        check_reward_subjects: true
        min_indicators: 2
      - type: "SubjectPattern"
        pattern: "(?i)(expires?.*soon|car.*emergency.*kit|emergency.*car.*kit)"
  action:
    type: "Reject"
    message: "Car Emergency Kit reward scam via Google Groups blocked"
```

This detects sophisticated phishing attacks where attackers abuse Google Groups infrastructure to send reward scams and phishing emails from suspicious domains.

**Configuration Options:**
- `suspicious_domains`: Domain patterns to check (default: *.tk, *.ml, *.ga, *.top, *texas.com, service.*, etc.)
- `reward_keywords`: Keywords indicating reward/prize scams (default: reward, prize, winner, expires, urgent, etc.)
- `suspicious_sender_names`: Sender name patterns (default: confirmation required, urgent, admin, service, etc.)
- `check_domain_reputation`: Whether to check for suspicious domain patterns (default: true)
- `check_reward_subjects`: Whether to check for reward/prize subjects (default: true)
- `check_suspicious_senders`: Whether to check for suspicious sender names (default: true)
- `min_indicators`: Minimum abuse indicators required for a match (default: 2)

**Detected Patterns:**
- Google Groups with suspicious TLD domains (*.tk, *.ml, *.ga, etc.)
- Reward/prize scam subjects: "Expires soon: your Car Emergency Kit reward"
- Suspicious sender names: "Confirmation_required .", "Urgent", "Admin"
- Domain spoofing: Texas-themed domains like "slotintexas.com"
- Generic service domains: "service.*", "support.*", "noreply.*"

**Google Groups Infrastructure Detection:**
- List-ID headers containing groups.google.com
- X-Google-Group-ID headers with numeric group IDs
- Precedence: list headers
- Mailing-list headers with list patterns
- Received headers mentioning groups.google.com

**Why This Works:**
- Legitimate businesses don't use Google Groups with suspicious domains for reward campaigns
- Attackers abuse trusted Google Groups infrastructure to bypass email filters
- Multiple indicators (groups + domain + reward + sender) reduce false positives
- Configurable thresholds allow fine-tuning for different environments
- Wildcard domain matching catches variations of suspicious patterns

See `examples/google-groups-abuse-example.yaml` for comprehensive Google Groups abuse detection rules.

### Sender spoofing extortion detection

Detect extortion attempts where attackers spoof the sender to appear as if the email is coming from the recipient themselves:

```yaml
- name: "Block sender spoofing extortion attempts"
  criteria:
    type: "SenderSpoofingExtortion"
    # All options use defaults - detects common extortion patterns
    check_sender_recipient_match: true      # Check if sender equals recipient
    check_external_source: true             # Check for external IP sources
    check_missing_authentication: true      # Check for missing/failed DKIM
    require_extortion_content: true         # Require extortion keywords
    min_indicators: 2                       # Require at least 2 indicators
  action:
    type: "Reject"
    message: "Sender spoofing extortion attempt blocked"
```

```yaml
- name: "Custom extortion detection"
  criteria:
    type: "SenderSpoofingExtortion"
    extortion_keywords: ["bitcoin", "cryptocurrency", "payment", "blackmail", "compromising"]
    check_sender_recipient_match: true
    check_external_source: true
    check_missing_authentication: true
    require_extortion_content: true
    min_indicators: 2
  action:
    type: "TagAsSpam"
    header_name: "X-Sender-Spoofing-Extortion"
    header_value: "Extortion attempt detected"
```

```yaml
- name: "Bitcoin extortion detection"
  criteria:
    type: "And"
    criteria:
      - type: "SenderSpoofingExtortion"
        extortion_keywords: ["bitcoin", "btc", "cryptocurrency", "crypto", "wallet"]
        check_sender_recipient_match: true
        check_external_source: true
        min_indicators: 2
      - type: "SubjectPattern"
        pattern: "(?i)(waiting.*payment|bitcoin|cryptocurrency|pay.*now)"
  action:
    type: "Reject"
    message: "Bitcoin extortion via sender spoofing blocked"
```

This detects sophisticated extortion scams where attackers spoof the sender address to make emails appear self-sent while demanding payment or threatening exposure.

**Configuration Options:**
- `extortion_keywords`: Keywords indicating extortion content (default: payment, bitcoin, blackmail, compromising, etc.)
- `check_sender_recipient_match`: Whether to check if sender equals recipient (default: true)
- `check_external_source`: Whether to check for external IP sources, excluding private ranges (default: true)
- `check_missing_authentication`: Whether to check for missing/failed DKIM authentication (default: true)
- `require_extortion_content`: Whether to require extortion keywords in subject/body (default: true)
- `min_indicators`: Minimum abuse indicators required for a match (default: 2)

**Detected Patterns:**
- Sender-recipient address matching (perfect spoofing)
- Extortion keywords: "waiting for payment", "bitcoin", "blackmail", "compromising"
- External IP sources (excluding private IP ranges like 192.168.x.x, 10.x.x.x)
- Missing or failed DKIM authentication
- Cryptocurrency terms: "bitcoin", "btc", "cryptocurrency", "wallet"
- Threat language: "expose", "reveal", "publish", "embarrassing"

**Why This Works:**
- Legitimate emails are never self-sent with extortion content from external sources
- Combines multiple indicators (spoofing + content + source + auth) for high accuracy
- Excludes private IP ranges to avoid false positives from internal mail servers
- **Whitelists legitimate email services** (SparkPost, SendGrid, Mailchimp, etc.)
- **Smart evidence requirements**: Requires stronger evidence for forwarded/newsletter emails
- Configurable thresholds allow fine-tuning for different threat levels
- Comprehensive keyword matching catches various extortion/sextortion patterns

**Common Extortion Patterns Detected:**
- **Classic extortion**: "Waiting for the payment." from victim@domain.com to victim@domain.com
- **Bitcoin sextortion**: "I have compromising video, send bitcoin to wallet address"
- **Deadline pressure**: "You have 24 hours to pay or I will expose your secrets"
- **Social media threats**: "I will share this with your family and friends on Facebook"

See `examples/sender-spoofing-extortion-example.yaml` for comprehensive sender spoofing extortion detection rules.

### DocuSign abuse detection

Detect when legitimate DocuSign infrastructure is being abused for phishing campaigns:

```yaml
- name: "Block DocuSign phishing abuse"
  criteria:
    type: "DocuSignAbuse"
    check_reply_to_mismatch: true      # Check for non-DocuSign reply-to addresses
    check_panic_subjects: true         # Check for urgent/threatening subjects
    check_suspicious_encoding: true    # Check for suspicious base64 encoding
    min_indicators: 2                  # Require at least 2 indicators
  action:
    type: "Reject"
    message: "DocuSign infrastructure abuse detected"
```

```yaml
- name: "Conservative DocuSign abuse detection"
  criteria:
    type: "DocuSignAbuse"
    check_reply_to_mismatch: true
    check_panic_subjects: true
    check_suspicious_encoding: true
    min_indicators: 3                  # Require 3 indicators for high confidence
  action:
    type: "Reject"
    message: "High-confidence DocuSign phishing attack blocked"
```

This detects sophisticated phishing attacks where attackers abuse legitimate DocuSign infrastructure to send emails that appear to come from DocuSign but redirect responses to attacker-controlled addresses.

**Configuration Options:**
- `check_reply_to_mismatch`: Whether to check for reply-to domain mismatch (default: true)
- `check_panic_subjects`: Whether to check for panic/urgent subjects (default: true)
- `check_suspicious_encoding`: Whether to check for suspicious base64 encoding in From header (default: true)
- `min_indicators`: Minimum number of indicators required for detection (default: 2)

**Detected Patterns:**
- DocuSign infrastructure with non-DocuSign reply-to addresses
- Panic subjects: "Verify Now: Payment Suspended", "Account Suspended", etc.
- Base64 encoded From headers with suspicious content ("Remediation Unit", etc.)
- Random usernames in reply-to addresses (deloria548472@ysl.awesome47.com)
- Free email services used for replies (Gmail, Outlook, Yahoo, etc.)

**Why This Works:**
- Focuses specifically on DocuSign infrastructure abuse (avoids false positives)
- Combines multiple indicators for high accuracy (reduces false positives)
- Detects sophisticated attacks that bypass traditional SPF/DKIM filters
- Configurable thresholds allow fine-tuning for different environments
- Avoids DKIM complexity that could cause false positives

**Example Attack Detected:**
```
From: "=?utf-8?B?8J+Fv2F58J+Fv2FsIFJlbWVkaWF0aW9uIFVuaXQgdmlhIERvY3VzaWdu?=" <dse@eumail.docusign.net>
Reply-To: "deloria548472" <deloria548472@ysl.awesome47.com>
Subject: Verify Now: Payment Suspended for Verification at Our Security Center

Indicators detected:
1. Reply-to mismatch: deloria548472@ysl.awesome47.com (not DocuSign domain)
2. Panic subject: "Verify Now: Payment Suspended for Verification"
3. Suspicious encoding: Base64 encoded "Remediation Unit via DocuSign"
Result: 3 indicators >= 2 required = BLOCKED
```

See `examples/docusign-abuse-example.yaml` for comprehensive DocuSign abuse detection rules.

### Abuse reporting to email service providers

Automatically report abuse of legitimate email services (SendGrid, Mailchimp, etc.) to the service providers with **actual email sending**:

```yaml
# SMTP Configuration for sending abuse reports
smtp:
  server: "smtp.example.com"           # Your SMTP server
  port: 587                           # STARTTLS port (or 465 for SSL, 25 for plain)
  username: "abuse-reporter@example.com"  # SMTP username
  password: "your-smtp-password"      # SMTP password
  from_email: "abuse-reporter@example.com"  # From address for abuse reports
  from_name: "FOFF Milter Abuse Reporter"   # From name (optional)
  use_tls: true                       # Use STARTTLS (default: true)
  timeout_seconds: 30                 # Connection timeout (default: 30)

rules:
  - name: "Report SendGrid abuse and reject"
    criteria:
      type: "EmailServiceAbuse"
      legitimate_services: ["sendgrid.net"]
      check_reply_to_mismatch: true
      check_brand_impersonation: false
    action:
      type: "ReportAbuse"
      service_provider: "sendgrid"
      include_headers: true
      include_body: false
      report_message: "Automated detection of SendGrid infrastructure abuse"
      additional_action:
        type: "Reject"
        message: "SendGrid abuse detected and reported"
```

```yaml
- name: "Monitor suspicious activity (report only)"
  criteria:
    type: "And"
    criteria:
      - type: "HeaderPattern"
        header: "return-path"
        pattern: ".*@sendgrid\\.net$"
      - type: "SenderPattern"
        pattern: "^[a-z]+\\d+@(gmail|aol)\\.(com|net)$"
  action:
    type: "ReportAbuse"
    service_provider: "sendgrid"
    include_headers: true
    include_body: false
    report_message: "Suspicious activity - random username pattern"
    # No additional_action - just report and accept
```

**ReportAbuse Action Options:**
- `service_provider`: Email service to report to ("sendgrid", "mailchimp", "constantcontact", "mailgun")
- `additional_action`: Optional action to take after reporting (Reject, TagAsSpam, or Accept)
- `include_headers`: Whether to include email headers in report (default: true)
- `include_body`: Whether to include email body in report (default: false for privacy)
- `report_message`: Custom message to include in the abuse report

**Supported Service Providers:**
- **SendGrid**: Reports to abuse@sendgrid.com
- **Mailchimp**: Reports to abuse@mailchimp.com  
- **Constant Contact**: Reports to abuse@constantcontact.com
- **Mailgun**: Reports to abuse@mailgun.com

**SMTP Configuration Options:**
- `server`: SMTP server hostname (required)
- `port`: SMTP port (default: 587 for STARTTLS, 465 for SSL, 25 for plain)
- `username`: SMTP username (optional for anonymous SMTP)
- `password`: SMTP password (optional for anonymous SMTP)
- `from_email`: From email address for abuse reports (required)
- `from_name`: From name for abuse reports (default: "FOFF Milter")
- `use_tls`: Use STARTTLS encryption (default: true)
- `timeout_seconds`: Connection timeout (default: 30)

**Email Sending Behavior:**
- ✅ **With SMTP configured**: Automatically sends emails to service providers
- ⚠️ **Without SMTP configured**: Logs reports for manual submission
- 🔄 **Fallback on failure**: Logs report if email sending fails

**Example SMTP Configurations:**

```yaml
# Gmail SMTP (requires app password)
smtp:
  server: "smtp.gmail.com"
  port: 587
  username: "your-email@gmail.com"
  password: "your-app-password"
  from_email: "your-email@gmail.com"
  from_name: "FOFF Milter"
  use_tls: true

# Office 365 SMTP
smtp:
  server: "smtp.office365.com"
  port: 587
  username: "your-email@yourdomain.com"
  password: "your-password"
  from_email: "your-email@yourdomain.com"
  from_name: "FOFF Milter"
  use_tls: true

# Local SMTP server (no authentication)
smtp:
  server: "localhost"
  port: 25
  from_email: "noreply@yourdomain.com"
  from_name: "FOFF Milter"
  use_tls: false
```

**Generated Abuse Report Example:**
```
To: abuse@sendgrid.com
Subject: Automated abuse report for phishing email sent through SendGrid infrastructure

Automated detection of SendGrid infrastructure abuse for phishing

PHISHING EMAIL DETAILS:
========================
Sender: bounces+55266851-93ca-robert=example.com@sendgrid.net
From Header: terrysmith7987@aol.com
Recipients: victim@example.com
Subject: Order Confirmation

EMAIL HEADERS:
==============
Return-Path: <bounces+55266851-93ca-robert=example.com@sendgrid.net>
From: Terry S <terrysmith7987@aol.com>
Reply-To: terrysmith7987@aol.com
[... additional headers ...]

DETECTION INFORMATION:
=====================
This email was automatically detected as phishing/spam abuse of your infrastructure.
Please investigate and take appropriate action against the abusing account.

Report generated: 2025-08-18 22:00:00 UTC
Generated by: FOFF Milter (https://github.com/mwjohnson/foff-milter)
```

**Why This Works:**
- **Automated reporting**: Reduces manual effort in reporting abuse
- **Comprehensive reports**: Includes all necessary information for investigation
- **Privacy-conscious**: Body inclusion is optional and disabled by default
- **Flexible actions**: Can report-only, report-and-tag, or report-and-reject
- **Multiple providers**: Supports major email service providers
- **Detailed logging**: All reports are logged for audit trails

**Note**: With SMTP configured, abuse reports are automatically sent via email. Without SMTP configuration, reports are logged for manual submission.

See `examples/sendgrid-abuse-reporting.yaml` and `examples/smtp-abuse-reporting.yaml` for comprehensive abuse reporting configuration examples.

### Automatically unsubscribe from abusive Google Groups

Automatically unsubscribe from Google Groups being used for scam campaigns with **actual unsubscribe requests**:

```yaml
# Unsubscribe from specific abusive Google Group and reject the email
- name: "Unsubscribe from abusive Google Group 282548616536"
  criteria:
    type: "HeaderPattern"
    header: "x-google-group-id"
    pattern: "282548616536"
  action:
    type: "UnsubscribeGoogleGroup"
    reason: "Automated unsubscribe due to spam/scam detection"
    additional_action:
      type: "Reject"
      message: "Abusive Google Group blocked and unsubscribed"

# Unsubscribe from Google Groups with suspicious domains
- name: "Unsubscribe from Google Groups brand impersonation scams"
  criteria:
    type: "And"
    criteria:
      # Google Groups infrastructure
      - type: "HeaderPattern"
        header: "list-id"
        pattern: ".*\\.(site|tk|ml|ga|top).*"
      # Brand impersonation content
      - type: "Or"
        criteria:
          - type: "SubjectPattern"
            pattern: "(?i).*(aaa|temu|amazon|reward|prize).*"
          - type: "HeaderPattern"
            header: "from"
            pattern: "(?i).*(reward|prize|emergency.*kit).*"
  action:
    type: "UnsubscribeGoogleGroup"
    reason: "Automated unsubscribe from brand impersonation scam"
    additional_action:
      type: "TagAsSpam"
      header_name: "X-Google-Groups-Scam"
      header_value: "Unsubscribed from suspicious Google Group"

# Monitor suspicious groups (unsubscribe only, no blocking)
- name: "Monitor and unsubscribe from suspicious Google Groups"
  criteria:
    type: "And"
    criteria:
      - type: "HeaderPattern"
        header: "x-google-group-id"
        pattern: "\\d+"
      - type: "HeaderPattern"
        header: "from"
        pattern: "(?i).*(your_|reward_|urgent_).*"
  action:
    type: "UnsubscribeGoogleGroup"
    reason: "Automated unsubscribe due to suspicious patterns"
    # No additional_action - just unsubscribe and accept for analysis
```

**UnsubscribeGoogleGroup Action Options:**
- `additional_action`: Optional action to take after unsubscribing (Reject, TagAsSpam, or Accept)
- `reason`: Custom reason for unsubscribing (optional)

**How It Works:**
- **Extracts Group Info**: X-Google-Group-ID, List-ID, unsubscribe links
- **Multiple Methods**: Google Groups API, HTTP links, email requests
- **Async Processing**: Doesn't block email processing
- **Comprehensive Logging**: Full audit trail of unsubscribe attempts
- **Error Handling**: Graceful fallback if unsubscribe fails

**Real-World Use Case:**
The same Google Group ID (`282548616536`) was used for multiple scam campaigns:
- Temu reward scams: "Reminder about your Temu reward From Amazon"
- AAA car kit scams: "Reminder about your Car Emergency Kit reward From AAA"

With automatic unsubscribe, future emails from this abusive group are prevented at the source.

**Note**: With proper Google Groups API access, unsubscribe requests are automatically sent. Without API access, unsubscribe attempts are logged for manual processing.

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

## Statistics & Analytics

The milter includes a comprehensive statistics and analytics system to track email processing patterns, rule effectiveness, and system performance. Statistics persist across reboots, upgrades, and service restarts.

### Configuration

Add statistics and analytics configuration to your YAML file:

```yaml
socket_path: "/var/run/foff-milter.sock"
default_action:
  type: "Accept"

# Statistics configuration (optional)
statistics:
  enabled: true
  database_path: "/var/lib/foff-milter/stats.db"
  flush_interval_seconds: 60

# Analytics configuration (optional)
analytics:
  enabled: true
  database_path: "/var/lib/foff-milter/analytics.db"
  retention_days: 90
  real_time_dashboard:
    enabled: true
    port: 8080

# Machine learning configuration (optional)
machine_learning:
  enabled: true
  adaptive_learning: true
  anomaly_detection: true

rules:
  # Your filtering rules here...
```

### Viewing Statistics

#### Show Current Statistics

```bash
./target/release/foff-milter --stats -c /etc/foff-milter.yaml
```

Example output:
```
📊 FOFF Milter Statistics
═══════════════════════════════════════

📈 Global Statistics:
  Total Emails Processed: 15,847
  ├─ Accepted: 14,203 (89.6%)
  ├─ Rejected: 1,521 (9.6%)
  ├─ Tagged as Spam: 123 (0.8%)
  └─ No Rule Matches: 12,456 (78.6%)

  Started: 2025-08-01 10:30:15 UTC
  Last Updated: 2025-08-14 05:45:22 UTC

🎯 Rule Statistics (sorted by matches):
┌─────────────────────────────────────────────────────────────────────────┐
│ Rule Name                                    │ Matches │ Reject │   Tag │
├─────────────────────────────────────────────────────────────────────────┤
│ Block domain spoofing in From header        │     892 │    892 │     0 │
│ Block admin emails with email addresses     │     445 │    445 │     0 │
│ Block failed DKIM administrative emails     │     184 │    184 │     0 │
└─────────────────────────────────────────────────────────────────────────┘
```

#### Analytics Dashboard

```bash
./target/release/foff-milter --analytics-report json -c /etc/foff-milter.yaml
```

#### Find Unused Rules

```bash
./target/release/foff-milter --stats-unmatched -c /etc/foff-milter.yaml
```

### What Gets Tracked

#### Global Statistics
- **Total emails processed**
- **Actions taken**: Accept, Reject, TagAsSpam counts and percentages
- **No rule matches**: Emails that passed through without matching any rule
- **Time tracking**: When statistics started and last updated

#### Per-Rule Statistics
- **Match count**: How many times each rule matched
- **Action breakdown**: Reject/Tag counts per rule
- **First/last match**: When rule was first and last triggered
- **Processing time**: Total time spent evaluating each rule

#### Advanced Analytics
- **Threat Detection Rates**: Live threat detection statistics
- **Module Effectiveness**: Per-module performance and accuracy
- **Processing Metrics**: Email volume, processing times, throughput
- **System Health**: Resource usage, cache performance, error rates
- **ML Performance**: Machine learning model accuracy and predictions
- **Security Scan Results**: Attachment, URL, and image analysis results

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

Test your configuration file to ensure it's valid and all regex patterns compile correctly:

```bash
./target/release/foff-milter --test-config -c config.yaml
```

This performs comprehensive validation:
- ✅ YAML syntax checking
- ✅ Configuration structure validation
- ✅ Rule loading verification
- ✅ **Regex compilation testing** - Ensures all patterns are valid and prevents runtime panics
- ✅ **FilterEngine creation** - Tests the complete filter setup

#### Example Output

```
🔍 Testing configuration...

✅ Configuration is valid!
Socket path: /var/run/foff-milter.sock
Number of rules: 10
  Rule 1: Block domain spoofing in From header
  Rule 2: Block admin emails with email addresses in links
  Rule 3: Block failed DKIM administrative emails

All regex patterns compiled successfully.
```

**Important**: Always run `--test-config` before deploying to production to catch regex compilation errors and other configuration issues that would cause the service to panic.

## Advanced Features

### Machine Learning Integration

The system includes adaptive machine learning capabilities:

```yaml
machine_learning:
  enabled: true
  adaptive_learning: true
  anomaly_detection: true
  behavioral_analysis: true
  predictive_detection: true
```

### Advanced Security Scanning

Deep inspection of attachments, URLs, and images:

```yaml
advanced_security:
  attachment_analysis: true
  url_scanning: true
  image_ocr: true
  behavioral_sandboxing: false  # Requires external sandbox
```

### Enterprise Integration

SIEM integration and API connectivity:

```yaml
integration:
  rest_api:
    enabled: true
    port: 8080
  siem_integration:
    splunk:
      enabled: true
      hec_url: "https://splunk.example.com:8088"
  webhooks:
    enabled: true
```

## Troubleshooting

### Common Issues

1. **Permission denied on socket**: Ensure the milter user can write to the socket directory
2. **Milter not receiving emails**: Check sendmail/postfix milter configuration
3. **Regex errors**: Test your patterns with the `--test-config` option
4. **Performance issues**: Consider the complexity of your regex patterns
5. **Module loading failures**: Check configuration file paths and permissions

### Debug Mode

Run with verbose logging to see detailed information:

```bash
sudo ./target/release/foff-milter -v -c /etc/foff-milter.yaml
```

### Health Checks

Monitor system health via API:

```bash
curl -H "X-API-Key: your-api-key" http://localhost:8080/api/v1/health
```

### Performance Monitoring

View performance metrics and statistics:

```bash
./target/release/foff-milter --stats -c /etc/foff-milter.yaml
./target/release/foff-milter --analytics-report json -c /etc/foff-milter.yaml
```

## System Architecture

### Complete Configuration System

```
configs/
├── suspicious-domains.yaml    # Domain reputation & TLD risk assessment
├── brand-impersonation.yaml   # Brand protection & authentication failures
├── health-spam.yaml          # Medical misinformation & pharmaceutical spam
├── phishing-scams.yaml       # Comprehensive scam & phishing detection
├── adult-content.yaml        # Adult content & romance fraud detection
├── ecommerce-scams.yaml      # Shopping fraud & marketplace scams
├── financial-services.yaml   # Banking phishing & financial fraud
├── technology-scams.yaml     # Tech support fraud & software scams
├── multi-language.yaml       # International threats & encoding abuse
├── performance.yaml          # Performance optimization & monitoring
├── analytics.yaml            # Advanced analytics & reporting
├── machine-learning.yaml     # AI-powered adaptive intelligence
├── integration.yaml          # Enterprise integration & API connectivity
└── advanced-security.yaml    # Deep inspection & threat analysis
```

### System Capabilities

✅ **Comprehensive Threat Detection** (9 specialized modules)  
✅ **Modular Architecture** (clean, maintainable, extensible)  
✅ **International Support** (multi-language, encoding abuse)  
✅ **Smart Exclusions** (legitimate organization whitelisting)  
✅ **Performance Optimization** (parallel processing, caching)  
✅ **Production Monitoring** (metrics, logging, optimization)  
✅ **Advanced Analytics** (real-time dashboards, reporting)  
✅ **Enterprise Intelligence** (threat analysis, compliance)  
✅ **AI-Powered Learning** (adaptive detection, predictive analysis)  
✅ **Enterprise Integration** (SIEM, API, webhooks, cloud connectivity)  
✅ **Advanced Security** (deep inspection, attachment analysis, URL scanning)  

### Performance Characteristics

- **High Throughput**: Optimized for processing thousands of emails per minute
- **Low Latency**: Sub-100ms processing time per email with ML inference
- **Scalable**: Horizontal scaling with Kubernetes and container orchestration
- **Reliable**: Graceful degradation and fault tolerance
- **Efficient**: Memory-efficient with intelligent caching and resource management

### Security Features

- **Zero-Day Protection**: ML-based detection of unknown threats
- **Advanced Evasion Detection**: Deep file structure and content analysis
- **Real-Time Intelligence**: Live threat intelligence and reputation feeds
- **Behavioral Analysis**: Sender and domain behavioral profiling
- **Compliance Ready**: GDPR, SOX, HIPAA compliance features

## Production Deployment

### Container Deployment

```bash
# Build Docker image
docker build -t foff-milter:latest .

# Run with Docker
docker run -d \
  --name foff-milter \
  -v /etc/foff-milter:/etc/foff-milter \
  -v /var/run/foff-milter:/var/run/foff-milter \
  -p 8080:8080 \
  foff-milter:latest
```

### Kubernetes Deployment

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: foff-milter
spec:
  replicas: 3
  selector:
    matchLabels:
      app: foff-milter
  template:
    metadata:
      labels:
        app: foff-milter
    spec:
      containers:
      - name: foff-milter
        image: foff-milter:latest
        ports:
        - containerPort: 8080
        resources:
          limits:
            cpu: 500m
            memory: 512Mi
```

### Monitoring & Alerting

```bash
# Prometheus metrics endpoint
curl http://localhost:9090/metrics

# Health check endpoint
curl http://localhost:8080/api/v1/health

# System status
curl http://localhost:8080/api/v1/status
```

## License

This project is licensed under the MIT License - see the LICENSE file for details.

---

## 🎉 Enterprise-Grade Email Security Platform

FOFF Milter represents a complete, production-ready email security solution with:

- **16 Implementation Steps** covering all aspects of email security
- **14 Configuration Modules** for comprehensive threat coverage
- **AI-Powered Intelligence** with machine learning and predictive capabilities
- **Enterprise Integration** with SIEM, API, and cloud connectivity
- **Advanced Security** with deep inspection and behavioral analysis
- **Production Performance** optimized for high-volume email processing

Ready for deployment in enterprise environments requiring the highest levels of email security and threat protection.
