# FOFF Milter v0.6.11

A comprehensive, enterprise-grade email security platform written in Rust featuring modular threat detection, explicit sender blocking, and clean TOML configuration.

## 🚀 Complete Email Security Platform

FOFF Milter is a production-ready email security solution that provides:

- **🛡️ Modular Threat Detection**: 17+ specialized detection modules covering all major threat vectors
- **🚫 Explicit Sender Blocking**: Pattern-based sender blocking with immediate rejection or tagging
- **🔧 Clean Configuration**: TOML-based configuration with separated module system
- **🔍 Advanced Security**: Deep inspection of attachments, URLs, and content analysis
- **📊 Enterprise Analytics**: Real-time monitoring, reporting, and statistics
- **⚡ Production Performance**: Optimized for high-volume processing with parallel execution
- **🔄 Backward Compatible**: Optional legacy YAML rule support
- **🔐 Module Integrity**: Cryptographic hashing for rule version tracking and consistency verification

## Module Integrity & Version Tracking

FOFF Milter v0.6.11 includes cryptographic hashing for module integrity verification:

### Module Hash Generation
- Each module is hashed when loaded using SHA-256 of the YAML content
- Hash is truncated to 8 characters for readability
- Hash changes when module rules are modified

### Hash Integration
- Module hashes are included in `X-FOFF-Rule-Matched` headers
- Format: `Module: Rule (hostname) [hash]`
- Example: `Analytics: Generic Sender Names (server1) [29807466]`

### Production Comparison
- Compare test environment hashes with production headers
- Quickly identify module version mismatches
- Ensure consistent rule deployment across environments

```bash
# Example header comparison
Production: X-FOFF-Rule-Matched: Analytics: Generic Sender Names (prod) [29807466]
Test:       X-FOFF-Rule-Matched: Analytics: Generic Sender Names (test) [29807466]
Status:     ✅ Modules match - same rule version
```

## Configuration Reload

FOFF Milter v0.6.4 supports hot configuration and module reloading without service interruption:

```bash
# Send SIGHUP signal to reload configuration and modules
sudo kill -HUP $(pgrep foff-milter)

# Or using systemctl (Linux)
sudo systemctl reload foff-milter

# Or using service command (FreeBSD)
sudo service foff_milter reload
```

When a SIGHUP signal is received, FOFF Milter will:
- Reload the main configuration file (`foff-milter.toml`)
- Reload all detection modules from the modules directory
- Update spam detection rules and thresholds in real-time
- Apply new settings without dropping existing connections
- Log the reload status for monitoring

This allows for real-time updates to spam detection rules, configuration changes, and module modifications without service downtime.

## Media Analysis & OCR

FOFF Milter includes advanced media analysis capabilities for detecting spam in images and PDF attachments:

### PDF Text Extraction
- Automatically extracts text from PDF attachments
- Analyzes extracted text for spam patterns
- Detects invoice scams, cryptocurrency fraud, and other threats

### Image Analysis
- **Basic Mode (Default)**: Analyzes image metadata for suspicious patterns
- **OCR Mode (Optional)**: Full text extraction from images using Tesseract

### Enabling OCR
To enable full OCR capabilities, install Tesseract and build with the OCR feature:

```bash
# Install Tesseract (Ubuntu/Debian)
sudo apt-get install tesseract-ocr tesseract-ocr-eng libtesseract-dev

# Install Tesseract (CentOS/RHEL)
sudo yum install tesseract tesseract-devel tesseract-langpack-eng

# Build with OCR support
cargo build --release --features ocr
```

### Spam Detection in Media
The media analyzer detects:
- Adult content keywords
- Financial scam patterns
- Health misinformation
- Urgency and pressure tactics
- Brand impersonation attempts

## Configuration System

### Modern TOML Configuration
Main configuration file: `/etc/foff-milter.toml`

```toml
[system]
socket_path = "/var/run/foff-milter.sock"
# Convert REJECT actions to TAG actions (default: true)
# When enabled, emails that would be rejected are tagged instead
reject_to_tag = true

[modules]
enabled = true
config_dir = "/etc/foff-milter/modules"

[heuristics]
# Score thresholds for actions
reject_threshold = 350  # High threshold - most emails tagged rather than rejected
spam_threshold = 50     # Tag as spam at this score
accept_threshold = 0    # Accept below spam threshold

[sender_blocking]
# Explicit sender pattern blocking - highest priority filtering
enabled = true
# Patterns that will immediately block emails (score: 1000)
block_patterns = [
    ".*@suspicious-domain\\.com$",
    ".*spammer.*@.*",
    ".*@.*\\.tk$"
]
# Action to take: "reject" or "tag"
action = "reject"

[legacy]
enabled = false
config_file = "/etc/foff-milter/legacy-rules.yaml"

[statistics]
enabled = true
database_path = "/var/lib/foff-milter/stats.db"
flush_interval_seconds = 60

[default_action]
type = "Accept"
```

### Module Directory Structure
Each detection module has its own configuration file:

```
/etc/foff-milter/rulesets/
├── suspicious-domains.yaml      # TLD and domain reputation
├── brand-impersonation.yaml     # DocuSign, PayPal phishing
├── health-spam.yaml            # Medical misinformation
├── phishing-scams.yaml         # General phishing detection
└── [additional modules]
```

## Threat Detection Modules
- **Suspicious Domain Detection**: TLD risk assessment, domain reputation, and newly registered domain detection
- **Brand Impersonation Protection**: Major brand protection with authentication failure detection
- **Health & Medical Spam**: Medical misinformation, pharmaceutical spam, and health scam detection
- **Phishing & Scam Detection**: Comprehensive phishing, romance fraud, and social engineering protection
- **Adult Content Filtering**: Adult content, romance scams, and inappropriate material detection
- **E-commerce Fraud**: Shopping scams, marketplace fraud, and fake product detection
- **Financial Services Protection**: Banking phishing, cryptocurrency scams, and financial fraud detection
- **Technology Scam Prevention**: Tech support fraud, software scams, and fake security alerts
- **Multi-Language Threat Detection**: International threats, encoding abuse, and script mixing detection

## Installation

### Prerequisites

- **Rust 1.70 or later**
- **sendmail or postfix** with milter support
- **Linux system** (tested on Ubuntu 20.04+, CentOS 8+, RHEL 8+)
- **Root or sudo access** for system installation

### Quick Installation

```bash
# Clone the repository
git clone https://github.com/mwjohnson/foff-milter.git
cd foff-milter

# Build the release binary (with OCR support)
cargo build --release --features ocr

# Install system-wide (create your own install script)
sudo cp target/release/foff-milter /usr/local/bin/
sudo cp foff-milter.toml /etc/
sudo mkdir -p /etc/foff-milter/modules
sudo cp modules/*.yaml /etc/foff-milter/rulesets/
```

### Manual Installation

#### 1. Build the Application

```bash
# Clone and build
git clone https://github.com/mwjohnson/foff-milter.git
cd foff-milter
cargo build --release --features ocr
```

#### 2. Create System User

```bash
# Create dedicated user for the milter
sudo useradd -r -s /bin/false -d /var/lib/foff-milter foff-milter
```

#### 3. Create Directories

```bash
# Create required directories
sudo mkdir -p /etc/foff-milter/modules
sudo mkdir -p /var/lib/foff-milter
sudo mkdir -p /var/log/foff-milter
sudo mkdir -p /var/run/foff-milter

# Set ownership
sudo chown -R foff-milter:foff-milter /var/lib/foff-milter
sudo chown -R foff-milter:foff-milter /var/log/foff-milter
sudo chown -R foff-milter:foff-milter /var/run/foff-milter
sudo chown -R root:foff-milter /etc/foff-milter
sudo chmod 750 /etc/foff-milter
```

#### 4. Install Binary and Configuration

```bash
# Install binary
sudo cp target/release/foff-milter /usr/local/bin/
sudo chmod 755 /usr/local/bin/foff-milter

# Install configuration files
sudo cp foff-milter.toml /etc/
sudo cp modules/*.yaml /etc/foff-milter/rulesets/
sudo chown -R root:foff-milter /etc/foff-milter
sudo chmod 640 /etc/foff-milter/rulesets/*.yaml
```

#### 5. Create Systemd Service

```bash
# Create systemd service file
sudo cp foff-milter.service /etc/systemd/system/

# Reload systemd and enable service
sudo systemctl daemon-reload
sudo systemctl enable foff-milter
```

#### 6. Test Configuration

```bash
# Test configuration as the foff-milter user
sudo -u foff-milter /usr/local/bin/foff-milter --test-config -c /etc/foff-milter.toml
```

#### 7. Start the Service

```bash
# Start the service
sudo systemctl start foff-milter

# Check status
sudo systemctl status foff-milter

# View logs
sudo journalctl -u foff-milter -f
```

### FreeBSD Installation

For FreeBSD systems, use the provided rc.d script:

```bash
# Install the rc.d script
sudo cp foff-milter.rc /usr/local/etc/rc.d/foff_milter
sudo chmod +x /usr/local/etc/rc.d/foff_milter

# Create required directories
sudo mkdir -p /var/run/foff-milter /var/lib/foff-milter
sudo chown foff-milter:foff-milter /var/run/foff-milter /var/lib/foff-milter

# Enable the service in /etc/rc.conf
echo 'foff_milter_enable="YES"' | sudo tee -a /etc/rc.conf
echo 'foff_milter_config="/usr/local/etc/foff-milter.toml"' | sudo tee -a /etc/rc.conf

# Start the service
sudo service foff_milter start

# Reload configuration
sudo service foff_milter reload
```

## Usage

### Running the Milter

```bash
# Run in production mode
sudo ./target/release/foff-milter -c /etc/foff-milter.toml

# Run with verbose logging
sudo ./target/release/foff-milter -v -c /etc/foff-milter.toml

# Test configuration
./target/release/foff-milter --test-config -c /etc/foff-milter.toml

# Test email processing
./target/release/foff-milter --test-email email.eml -c /etc/foff-milter.toml

# View statistics
./target/release/foff-milter --stats -c /etc/foff-milter.toml
```

### Sendmail Configuration

Add to your sendmail.mc file:

```
INPUT_MAIL_FILTER(`foff-milter', `S=unix:/var/run/foff-milter.sock, F=5, T=S:30s;R:30s')
```

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

## Statistics & Analytics

The milter includes a comprehensive statistics system to track email processing patterns, rule effectiveness, and system performance.

### Viewing Statistics

```bash
./target/release/foff-milter --stats -c /etc/foff-milter.toml
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

🎯 Module Statistics:
  ├─ Suspicious Domains: 892 threats detected
  ├─ Brand Impersonation: 445 threats detected
  ├─ Health Spam: 184 threats detected
  └─ Advanced Security: 95 threats detected
```

## Configuration Testing

Test your configuration file to ensure it's valid:

```bash
./target/release/foff-milter --test-config -c /etc/foff-milter.toml
```

This performs comprehensive validation:
- ✅ TOML syntax checking
- ✅ Configuration structure validation
- ✅ Module loading verification
- ✅ System integration testing

## Troubleshooting

### Common Issues

1. **Permission denied on socket**: Ensure the milter user can write to the socket directory
2. **Milter not receiving emails**: Check sendmail/postfix milter configuration
3. **Module loading failures**: Check module file paths and permissions
4. **Performance issues**: Review module configuration and system resources

### Debug Mode

Run with verbose logging to see detailed information:

```bash
sudo ./target/release/foff-milter -v -c /etc/foff-milter.toml
```

## License

This project is licensed under the MIT License - see the LICENSE file for details.

---

## 🎉 Enterprise-Grade Email Security Platform

FOFF Milter represents a complete, production-ready email security solution with:

- **Modular Architecture** with clean TOML configuration
- **17+ Detection Modules** for comprehensive threat coverage
- **Production Performance** optimized for high-volume email processing
- **Enterprise Integration** ready for deployment in business environments

Ready for deployment in enterprise environments requiring the highest levels of email security and threat protection.
