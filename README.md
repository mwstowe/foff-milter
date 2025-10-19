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

### Threat Detection Modules
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
- **Threat Intelligence**: Hash reputation, domain reputation, and behavioral analysis

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
- **Performance Metrics**: Comprehensive system performance and effectiveness tracking
- **Threat Intelligence**: Campaign detection, attribution analysis, and trend forecasting

## Installation

### Prerequisites

- **Rust 1.70 or later**
- **sendmail or postfix** with milter support
- **Linux system** (tested on Ubuntu 20.04+, CentOS 8+, RHEL 8+)
- **Root or sudo access** for system installation

**Note:** This milter uses the `indymilter` library (v0.3) which provides a pure Rust milter implementation, so you don't need libmilter development headers.

### Quick Installation

```bash
# Clone the repository
git clone https://github.com/mwjohnson/foff-milter.git
cd foff-milter

# Build the release binary
cargo build --release

# Install system-wide
sudo ./install.sh
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
sudo mkdir -p /etc/foff-milter/configs
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
sudo cp foff-milter.yaml /etc/foff-milter/
sudo cp -r configs/* /etc/foff-milter/configs/
sudo chown -R root:foff-milter /etc/foff-milter
sudo chmod 640 /etc/foff-milter/*.yaml
sudo chmod 640 /etc/foff-milter/configs/*.yaml
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
ExecStart=/usr/local/bin/foff-milter -c /etc/foff-milter/foff-milter.yaml
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

#### 6. Configure Main Settings

Edit the main configuration file:

```bash
sudo nano /etc/foff-milter/foff-milter.yaml
```

Update paths if needed:
```yaml
socket_path: "/var/run/foff-milter/foff-milter.sock"
statistics:
  database_path: "/var/lib/foff-milter/stats.db"
module_config_dir: "/etc/foff-milter/configs"
```

#### 7. Test Configuration

```bash
# Test configuration as the foff-milter user
sudo -u foff-milter /usr/local/bin/foff-milter --test-config -c /etc/foff-milter/foff-milter.yaml
```

#### 8. Start the Service

```bash
# Start the service
sudo systemctl start foff-milter

# Check status
sudo systemctl status foff-milter

# View logs
sudo journalctl -u foff-milter -f
```

### Post-Installation Verification

#### 1. Verify Service Status

```bash
# Check service is running
sudo systemctl is-active foff-milter

# Check socket exists
ls -la /var/run/foff-milter/foff-milter.sock

# Check logs for errors
sudo journalctl -u foff-milter --no-pager -l
```

#### 2. Test Email Processing

```bash
# Test with sample email
echo "From: test@example.com
To: admin@yourdomain.com
Subject: Test Email

This is a test email." | sudo -u foff-milter /usr/local/bin/foff-milter --test-email /dev/stdin -c /etc/foff-milter/foff-milter.yaml
```

#### 3. Verify Statistics

```bash
# Check statistics are working
sudo -u foff-milter /usr/local/bin/foff-milter --stats -c /etc/foff-milter/foff-milter.yaml
```

### Integration with Mail Server

After installation, configure your mail server to use the milter:

## Configuration

The system uses a modular configuration approach with separate YAML files for different components:

### Modular Configuration System

```
foff-milter.yaml              # Main configuration file
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

### Main Configuration

```yaml
# foff-milter.yaml
socket_path: "/var/run/foff-milter.sock"
default_action:
  type: "Accept"

statistics:
  enabled: true
  database_path: "/var/lib/foff-milter/stats.db"
  flush_interval_seconds: 60

# System automatically loads all modules from configs/ directory
module_config_dir: "configs"
rules: []  # Legacy rules disabled - use modular system
```

### Test Configuration

```bash
./target/release/foff-milter --test-config -c foff-milter.yaml
```

## Usage

### Running the Milter

```bash
# Run in production mode
sudo ./target/release/foff-milter -c foff-milter.yaml

# Run with verbose logging
sudo ./target/release/foff-milter -v -c foff-milter.yaml

# Test configuration
./target/release/foff-milter --test-config -c foff-milter.yaml

# Test email processing
./target/release/foff-milter --test-email email.eml -c foff-milter.yaml

# View statistics
./target/release/foff-milter --stats -c foff-milter.yaml

# Generate analytics report
./target/release/foff-milter --analytics-report json -c foff-milter.yaml
```

### API Usage

```bash
# Start REST API server (if enabled in integration.yaml)
./target/release/foff-milter --api-server -c foff-milter.yaml

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

The milter includes a comprehensive statistics and analytics system to track email processing patterns, rule effectiveness, and system performance. Statistics persist across reboots, upgrades, and service restarts.

### Viewing Statistics

```bash
./target/release/foff-milter --stats -c foff-milter.yaml
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

### Analytics Dashboard

```bash
./target/release/foff-milter --analytics-report json -c foff-milter.yaml
```

## Configuration Testing

Test your configuration file to ensure it's valid:

```bash
./target/release/foff-milter --test-config -c foff-milter.yaml
```

This performs comprehensive validation:
- ✅ YAML syntax checking
- ✅ Configuration structure validation
- ✅ Module loading verification
- ✅ System integration testing

## Advanced Features

### Machine Learning Integration

The system includes adaptive machine learning capabilities configured in `configs/machine-learning.yaml`:

- **Adaptive Learning**: Continuous model updates from new email data
- **Anomaly Detection**: Statistical outlier identification for unknown threats
- **Behavioral Analysis**: Sender reputation and pattern analysis
- **Predictive Detection**: Threat forecasting and campaign detection

### Advanced Security Scanning

Deep inspection capabilities configured in `configs/advanced-security.yaml`:

- **Attachment Analysis**: PDF, Office documents, archives, executables
- **URL Scanning**: Real-time reputation checking and phishing detection
- **Image OCR**: Text extraction from images and QR code analysis
- **Threat Intelligence**: Hash reputation and behavioral analysis

### Enterprise Integration

SIEM integration and API connectivity configured in `configs/integration.yaml`:

- **REST API**: HTTP API for email processing and management
- **SIEM Integration**: Splunk, Elasticsearch, QRadar, Azure Sentinel
- **Webhook Notifications**: Slack, Teams, custom endpoints
- **Cloud Integration**: AWS, Azure, Google Cloud services

## Troubleshooting

### Common Issues

1. **Permission denied on socket**: Ensure the milter user can write to the socket directory
2. **Milter not receiving emails**: Check sendmail/postfix milter configuration
3. **Module loading failures**: Check configuration file paths and permissions
4. **Performance issues**: Review module configuration and system resources

### Debug Mode

Run with verbose logging to see detailed information:

```bash
sudo ./target/release/foff-milter -v -c foff-milter.yaml
```

### Health Checks

Monitor system health via API:

```bash
curl -H "X-API-Key: your-api-key" http://localhost:8080/api/v1/health
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
✅ **Performance Optimization** (parallel processing, caching)  
✅ **Advanced Analytics** (real-time dashboards, reporting)  
✅ **AI-Powered Learning** (adaptive detection, predictive analysis)  
✅ **Enterprise Integration** (SIEM, API, webhooks, cloud connectivity)  
✅ **Advanced Security** (deep inspection, attachment analysis, URL scanning)  

### Performance Characteristics

- **High Throughput**: Optimized for processing thousands of emails per minute
- **Low Latency**: Sub-100ms processing time per email with ML inference
- **Scalable**: Horizontal scaling with Kubernetes and container orchestration
- **Reliable**: Graceful degradation and fault tolerance
- **Efficient**: Memory-efficient with intelligent caching and resource management

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
