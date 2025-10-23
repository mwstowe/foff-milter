# FOFF Milter v0.6.2

A comprehensive, enterprise-grade email security platform written in Rust featuring modular threat detection and clean TOML configuration.

## 🚀 Complete Email Security Platform

FOFF Milter is a production-ready email security solution that provides:

- **🛡️ Modular Threat Detection**: 14+ specialized detection modules covering all major threat vectors
- **🔧 Clean Configuration**: TOML-based configuration with separated module system
- **🔍 Advanced Security**: Deep inspection of attachments, URLs, and content analysis
- **📊 Enterprise Analytics**: Real-time monitoring, reporting, and statistics
- **⚡ Production Performance**: Optimized for high-volume processing with parallel execution
- **🔄 Backward Compatible**: Optional legacy YAML rule support

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
/etc/foff-milter/modules/
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

# Build the release binary
cargo build --release

# Install system-wide (create your own install script)
sudo cp target/release/foff-milter /usr/local/bin/
sudo cp foff-milter.toml /etc/
sudo mkdir -p /etc/foff-milter/modules
sudo cp modules/*.yaml /etc/foff-milter/modules/
```

### Manual Installation

#### 1. Build the Application

```bash
# Clone and build
git clone https://github.com/mwjohnson/foff-milter.git
cd foff-milter
cargo build --release
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
sudo cp modules/*.yaml /etc/foff-milter/modules/
sudo chown -R root:foff-milter /etc/foff-milter
sudo chmod 640 /etc/foff-milter/modules/*.yaml
```

#### 5. Create Systemd Service

```bash
# Create systemd service file
sudo tee /etc/systemd/system/foff-milter.service > /dev/null << 'EOF'
[Unit]
Description=FOFF Milter - Enterprise Email Security Platform
After=network.target
Wants=network.target

[Service]
Type=simple
User=foff-milter
Group=foff-milter
ExecStart=/usr/local/bin/foff-milter -c /etc/foff-milter.toml
ExecReload=/bin/kill -HUP $MAINPID
Restart=always
RestartSec=5
StandardOutput=journal
StandardError=journal
SyslogIdentifier=foff-milter

# Security settings
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/var/lib/foff-milter /var/run/foff-milter

[Install]
WantedBy=multi-user.target
EOF

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
- **14+ Detection Modules** for comprehensive threat coverage
- **Production Performance** optimized for high-volume email processing
- **Enterprise Integration** ready for deployment in business environments

Ready for deployment in enterprise environments requiring the highest levels of email security and threat protection.
