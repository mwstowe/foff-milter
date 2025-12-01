# FOFF Milter v0.7.6

A comprehensive, enterprise-grade email security platform written in Rust featuring intelligent threat detection, modular rulesets, and zero-configuration deployment.

## 🚀 Complete Email Security Platform

FOFF Milter provides production-ready email security with:

- **🛡️ Intelligent Threat Detection**: Advanced feature analysis with contextual scoring
- **📋 Modular Rulesets**: 20+ specialized detection modules covering all threat vectors
- **🔧 Zero Configuration**: Works out-of-the-box with sane platform-specific defaults
- **🔍 Advanced Analytics**: Deep inspection of attachments, URLs, and content patterns
- **📊 Enterprise Monitoring**: Real-time statistics and comprehensive reporting
- **⚡ Production Performance**: Optimized for high-volume processing with parallel execution
- **🔄 Hot Reload**: Live configuration updates without service interruption
- **🔐 Cryptographic Integrity**: Module hashing for version tracking and consistency

## 🧠 Intelligent Feature Analysis System

FOFF Milter uses advanced feature extraction instead of simple pattern matching:

### Link Analysis Engine
- **URL vs Display Text**: Detects mismatched display text and actual destinations
- **Domain Extraction**: Analyzes relationship between sender and link domains
- **Suspicious Patterns**: Identifies URL shorteners, suspicious TLDs, and phishing indicators
- **Context Scoring**: Weighs link legitimacy against sender reputation

### Sender Alignment Analysis
- **Brand Validation**: Matches claimed brands against actual sender domains
- **Domain Consistency**: Validates sender domain against email infrastructure
- **Impersonation Detection**: Identifies sophisticated brand spoofing attempts
- **Authentication Correlation**: Cross-references SPF/DKIM with claimed identity

### Context Analysis Engine
- **Urgency Detection**: Identifies pressure tactics and time-sensitive language
- **Scam Combinations**: Detects patterns combining multiple threat indicators
- **Content Structure**: Analyzes email formatting and presentation patterns
- **Legitimacy Scoring**: Balances urgency against legitimate business communications

### Evidence-Based Scoring
- **Confidence Levels**: Each feature provides confidence ratings
- **Detailed Evidence**: Comprehensive explanations for all scoring decisions
- **Transparent Analysis**: Full audit trail of detection reasoning
- **Contextual Weighting**: Intelligent combination of multiple threat indicators

## 📋 Modular Ruleset System

FOFF Milter includes 20+ specialized detection modules:

### Core Security Modules
- **Advanced Security**: Sophisticated threat detection and analysis
- **Domain Risk Assessment**: TLD reputation and newly registered domain detection
- **Link Analysis**: URL inspection and relationship validation
- **Advanced Heuristics**: Pattern-based threat identification

### Brand Protection
- **Generic Brand Impersonation**: Major brand protection with authentication validation
- **Brand Domain Validation**: Sender domain consistency checking
- **Financial Services**: Banking, cryptocurrency, and financial fraud detection

### Content Analysis
- **Health Threats**: Medical misinformation and pharmaceutical spam detection
- **Adult Content**: Inappropriate content and romance scam filtering
- **Commerce Threats**: E-commerce fraud and marketplace scam detection
- **Technology Scams**: Tech support fraud and fake security alerts

### Infrastructure & Performance
- **Email Infrastructure**: Legitimate service provider recognition
- **Analytics**: Sender pattern analysis and reputation scoring
- **Performance**: Optimization rules and processing efficiency
- **Integration**: Third-party service and platform integration

### Specialized Detection
- **Lead Generation**: Marketing and lead generation campaign analysis
- **Multi-Language**: International threats and encoding abuse detection
- **Media Content Analysis**: Image and attachment inspection
- **Rule Whitelists**: Legitimate sender and domain exceptions

## ⚙️ Configuration Architecture

FOFF Milter uses a two-tier configuration system:

### User Configuration (foff-milter.toml)
**Location**: `/etc/foff-milter.toml` (Linux) or `/usr/local/etc/foff-milter.toml` (FreeBSD)
**Purpose**: User-customizable settings and overrides
**Managed by**: System administrators

```toml
# All sections are optional - sane defaults provided
[system]
socket_path = "/var/run/foff-milter.sock"
reject_to_tag = true  # Convert rejects to tags for safety

[heuristics]
reject_threshold = 350  # High threshold for production safety
spam_threshold = 50     # Tag as spam threshold
accept_threshold = 0    # Accept below this score

[whitelist]
enabled = true
addresses = ["trusted@example.com"]
domains = ["trusted-domain.com"]
domain_patterns = [".*\\.gov$", ".*\\.edu$"]

[blocklist]
enabled = true
addresses = ["spam@badactor.com"]
domains = ["malicious.com"]
domain_patterns = [".*\\.tk$", ".*\\.ml$"]
```

### Software-Maintained Rulesets (YAML)
**Location**: `/etc/foff-milter/rulesets/` (Linux) or `/usr/local/etc/foff-milter/rulesets/` (FreeBSD)
**Purpose**: Detection rules and threat intelligence
**Managed by**: Software updates and deployment scripts

- **✅ Automatically deployed**: Updated via deployment scripts
- **✅ Version controlled**: Cryptographic hashing for integrity
- **✅ Hot reloadable**: Updated without service interruption
- **⚠️ Not user-editable**: Overwritten on software updates

## 🔧 Platform-Specific Defaults

FOFF Milter automatically configures itself based on the target platform:

### Linux Systems
```
Configuration: /etc/foff-milter.toml
Rulesets: /etc/foff-milter/rulesets/
Features: /etc/foff-milter/features/
Statistics: /var/lib/foff-milter/stats.db
Socket: /var/run/foff-milter.sock
```

### FreeBSD Systems
```
Configuration: /usr/local/etc/foff-milter.toml
Rulesets: /usr/local/etc/foff-milter/rulesets/
Features: /usr/local/etc/foff-milter/features/
Statistics: /var/lib/foff-milter/stats.db
Socket: /var/run/foff-milter.sock
```

## 📊 Configuration Options Reference

### System Configuration
```toml
[system]
socket_path = "/var/run/foff-milter.sock"  # Milter socket path
reject_to_tag = true                       # Convert rejects to tags (default: true)
```

### Detection Modules
```toml
[modules]  # Optional - uses platform defaults if omitted
enabled = true                             # Enable ruleset system (default: true)
config_dir = "/etc/foff-milter/rulesets"  # Platform-specific default
```

### Feature Analysis
```toml
[features]  # Optional - uses platform defaults if omitted
enabled = true                             # Enable feature analysis (default: true)
config_dir = "/etc/foff-milter/features"  # Platform-specific default
```

### Scoring Thresholds
```toml
[heuristics]  # Optional - uses defaults if omitted
reject_threshold = 350    # REJECT action threshold (default: 350)
spam_threshold = 50       # TAG AS SPAM threshold (default: 50)
accept_threshold = 0      # ACCEPT threshold (default: 0)
```

### Sender Blocking
```toml
[sender_blocking]  # Optional - enabled by default
enabled = true             # Enable pattern-based blocking (default: true)
action = "reject"          # Action: "reject" or "tag" (default: "reject")
block_patterns = [         # Regex patterns to block (default: empty)
    ".*@suspicious\\.com$",
    ".*spammer.*@.*"
]
```

### Global Whitelist
```toml
[whitelist]  # Optional - enabled by default
enabled = true                    # Enable whitelist (default: true)
addresses = ["safe@example.com"]  # Exact addresses (default: empty)
domains = ["trusted.com"]         # Exact domains (default: empty)
domain_patterns = [".*\\.gov$"]   # Regex patterns (default: empty)
```

### Global Blocklist
```toml
[blocklist]  # Optional - enabled by default
enabled = true                    # Enable blocklist (default: true)
addresses = ["spam@bad.com"]      # Exact addresses (default: empty)
domains = ["malicious.com"]       # Exact domains (default: empty)
domain_patterns = [".*\\.tk$"]    # Regex patterns (default: empty)
```

### Statistics & Analytics
```toml
[statistics]  # Optional - enabled by default
enabled = true                                    # Enable stats (default: true)
database_path = "/var/lib/foff-milter/stats.db"  # SQLite database path
flush_interval_seconds = 60                      # Flush interval (default: 60)
```

### Default Action
```toml
[default_action]  # Optional - defaults to Accept
type = "Accept"   # Action when no rules match (default: "Accept")

# Alternative actions:
# type = "Reject"
# message = "Message rejected by policy"
#
# type = "TagAsSpam"
# header_name = "X-Spam-Flag"
# header_value = "YES"
```

## 🔄 Hot Configuration Reload

FOFF Milter supports live configuration updates without service interruption:

```bash
# Reload all configurations
sudo kill -HUP $(pgrep foff-milter)

# Or using systemctl (Linux)
sudo systemctl reload foff-milter

# Or using service command (FreeBSD)
sudo service foff_milter reload
```

**What gets reloaded:**
- ✅ Main TOML configuration (`foff-milter.toml`)
- ✅ All ruleset modules (`rulesets/*.yaml`)
- ✅ Feature configurations (`features/*.toml`)
- ✅ Statistics settings

## 📈 Statistics & Monitoring

View real-time statistics:

```bash
./foff-milter --stats -c /etc/foff-milter.toml
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
  ├─ Advanced Security: 892 threats detected
  ├─ Brand Impersonation: 445 threats detected
  ├─ Health Threats: 184 threats detected
  └─ Financial Services: 95 threats detected
```

## 🚀 Installation

### Prerequisites
- **Rust 1.70 or later**
- **sendmail or postfix** with milter support
- **Linux or FreeBSD system**
- **Root or sudo access** for system installation

### Quick Installation

```bash
# Clone and build
git clone https://github.com/mwstowe/foff-milter.git
cd foff-milter
cargo build --release --features ocr

# Install system-wide
sudo cp target/release/foff-milter /usr/local/bin/
sudo mkdir -p /etc/foff-milter/{rulesets,features}
sudo cp rulesets/*.yaml /etc/foff-milter/rulesets/
sudo cp features/*.toml /etc/foff-milter/features/

# Create minimal config (or use empty file for all defaults)
echo "# FOFF Milter - using all defaults" | sudo tee /etc/foff-milter.toml

# Install and start service
sudo cp foff-milter.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now foff-milter
```

### Sendmail Configuration

Add to your sendmail.mc file:

```
INPUT_MAIL_FILTER(`foff-milter', `S=unix:/var/run/foff-milter.sock, F=5, T=S:30s;R:30s')
```

### Postfix Configuration

Add to main.cf:

```
smtpd_milters = unix:/var/run/foff-milter.sock
non_smtpd_milters = unix:/var/run/foff-milter.sock
milter_default_action = accept
```

## 🔧 Usage

```bash
# Run with default configuration
sudo foff-milter

# Use custom config file
sudo foff-milter -c /path/to/config.toml

# Test configuration
foff-milter --test-config -c /etc/foff-milter.toml

# Test email processing
foff-milter --test-email email.eml -c /etc/foff-milter.toml

# View statistics
foff-milter --stats -c /etc/foff-milter.toml

# Verbose logging
sudo foff-milter -v -c /etc/foff-milter.toml
```

## 🎯 Best Practices

### Production Deployment
1. **Start with defaults**: Use empty or minimal TOML configuration
2. **Monitor initially**: Set `reject_to_tag = true` for safe deployment
3. **Customize gradually**: Add specific whitelists/blocklists as needed
4. **Use hot reload**: Update configurations without service interruption
5. **Monitor statistics**: Track detection effectiveness and false positives

### Security Considerations
- **Whitelist carefully**: Government (.gov), education (.edu), and military (.mil) domains
- **Monitor thresholds**: Adjust scoring thresholds based on your environment
- **Regular updates**: Keep rulesets updated via deployment scripts
- **Audit logs**: Review detection decisions and adjust as needed

### Performance Optimization
- **Appropriate thresholds**: Higher reject thresholds reduce false positives
- **Selective blocking**: Use targeted sender blocking patterns
- **Statistics monitoring**: Track processing performance and bottlenecks

## 📄 License

This project is licensed under the MIT License - see the LICENSE file for details.

---

## 🎉 Enterprise-Grade Email Security

FOFF Milter represents a complete, production-ready email security solution with intelligent threat detection, zero-configuration deployment, and enterprise-grade performance. Ready for immediate deployment in business environments requiring the highest levels of email security and threat protection.
