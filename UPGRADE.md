# Upgrade Guide: v0.2.x → v0.5.x

## 🚀 Major Version Upgrade: Legacy Rules → Modular Detection System

Version 0.5.0 introduces a revolutionary **Modular Detection System** that replaces the legacy rule-based approach with 14 specialized detection modules, providing superior threat detection capabilities.

## 📊 Performance Improvements

| Metric | v0.2.x (Legacy) | v0.5.x (Modular) | Improvement |
|--------|-----------------|------------------|-------------|
| Test Coverage | 4/12 (33%) | 12/12 (100%) | +200% |
| Detection Accuracy | Basic patterns | Multi-layer analysis | Superior |
| Configuration | Monolithic rules | Modular specialized configs | Maintainable |
| Extensibility | Limited | 14 specialized modules | Highly extensible |

## 🔄 Upgrade Process

### Step 1: Backup Current Configuration

```bash
# Backup your existing configuration
cp /etc/foff-milter/foff-milter.yaml /etc/foff-milter/foff-milter.yaml.v0.2.backup
cp -r /etc/foff-milter/ /etc/foff-milter.backup/
```

### Step 2: Stop Current Service

```bash
sudo systemctl stop foff-milter
```

### Step 3: Install v0.5.0

```bash
# Download and build v0.5.0
git clone https://github.com/mwjohnson/foff-milter.git
cd foff-milter
git checkout v0.5.0
cargo build --release

# Install new binary
sudo cp target/release/foff-milter /usr/local/bin/
```

### Step 4: Install Modular Configuration

```bash
# Install modular configuration files
sudo cp -r configs/* /etc/foff-milter/configs/
sudo chown -R root:foff-milter /etc/foff-milter/configs/
sudo chmod 640 /etc/foff-milter/configs/*.yaml
```

### Step 5: Update Main Configuration

#### Option A: Enable Modular System (Recommended)

Edit `/etc/foff-milter/foff-milter.yaml`:

```yaml
# v0.5.0 Modular Configuration
socket_path: "/var/run/foff-milter/foff-milter.sock"
default_action:
  type: "Accept"

statistics:
  enabled: true
  database_path: "/var/lib/foff-milter/stats.db"
  flush_interval_seconds: 60

# Enable modular detection system
module_config_dir: "/etc/foff-milter/configs"

# Disable legacy rules (optional - can coexist)
rules: []
```

#### Option B: Keep Legacy Rules (Backward Compatible)

Your existing configuration will continue to work:

```yaml
# Existing v0.2.x configuration still supported
socket_path: "/var/run/foff-milter.sock"
default_action:
  type: "Accept"
rules:
  # Your existing rules continue to work
  - name: "Example Rule"
    # ... existing rule configuration
```

### Step 6: Test Configuration

```bash
# Test new configuration
sudo -u foff-milter /usr/local/bin/foff-milter --test-config -c /etc/foff-milter/foff-milter.yaml

# Test email processing
echo "From: test@example.com
Subject: Test
Body: test" | sudo -u foff-milter /usr/local/bin/foff-milter --test-email /dev/stdin -c /etc/foff-milter/foff-milter.yaml
```

### Step 7: Start Service

```bash
sudo systemctl start foff-milter
sudo systemctl status foff-milter
```

## 🎯 Configuration Migration

### Legacy Rules → Modular Modules

| Legacy Rule Type | Modular Module | Configuration File |
|------------------|----------------|-------------------|
| Domain-based rules | Suspicious Domains | `suspicious-domains.yaml` |
| Brand protection | Brand Impersonation | `brand-impersonation.yaml` |
| Health/medical spam | Health Spam | `health-spam.yaml` |
| Phishing detection | Phishing Scams | `phishing-scams.yaml` |
| Adult content | Adult Content | `adult-content.yaml` |
| Shopping scams | E-commerce Scams | `ecommerce-scams.yaml` |
| Financial fraud | Financial Services | `financial-services.yaml` |
| Tech support scams | Technology Scams | `technology-scams.yaml` |
| Multi-language threats | Multi-Language | `multi-language.yaml` |

### Example Migration

#### v0.2.x Legacy Rule:
```yaml
rules:
  - name: "CVS Medicare Phishing"
    criteria:
      - type: "BodyContains"
        pattern: "cvs.*medicare"
      - type: "AuthenticationResults"
        pattern: "dkim=fail"
    action:
      type: "Reject"
```

#### v0.5.x Modular Equivalent:
The same detection is now handled automatically by:
- `health-spam.yaml` - Detects CVS Medicare patterns
- `brand-impersonation.yaml` - Detects brand spoofing with auth failures
- Enhanced multi-layer analysis provides superior detection

## 🔧 Customization

### Modular System Benefits

1. **Specialized Configuration**: Each module focuses on specific threat types
2. **Easy Maintenance**: Update individual modules without affecting others  
3. **Enhanced Detection**: Multi-layer analysis with confidence scoring
4. **Future-Proof**: Easy to add new detection modules

### Customizing Detection Modules

```bash
# Edit specific detection modules
sudo nano /etc/foff-milter/configs/health-spam.yaml
sudo nano /etc/foff-milter/configs/brand-impersonation.yaml

# Test changes
sudo systemctl reload foff-milter
```

## 🚨 Breaking Changes

### Minimal Breaking Changes
- **Configuration**: Legacy configurations continue to work
- **API**: All existing functionality preserved
- **Installation**: Same installation process
- **Integration**: Mail server integration unchanged

### New Features Only Available in v0.5.x
- **14 Specialized Detection Modules**
- **Machine Learning Integration** 
- **Advanced Security Scanning**
- **Enterprise Analytics**
- **Multi-Language Threat Detection**

## 🔍 Verification

### Test Upgrade Success

```bash
# Verify modular system is active
sudo -u foff-milter /usr/local/bin/foff-milter --test-config -c /etc/foff-milter/foff-milter.yaml

# Should show:
# ✅ Modular system configuration validated
# Number of available modules: 14

# Test threat detection
./tests/run_tests.sh /etc/foff-milter/foff-milter.yaml

# Should show:
# 🎉 All tests passed!
# Total: 12, Passed: 12, Failed: 0
```

### Performance Monitoring

```bash
# View enhanced statistics
sudo -u foff-milter /usr/local/bin/foff-milter --stats -c /etc/foff-milter/foff-milter.yaml

# Monitor logs for modular detection
sudo journalctl -u foff-milter -f
```

## 🆘 Rollback Procedure

If you need to rollback to v0.2.x:

```bash
# Stop service
sudo systemctl stop foff-milter

# Restore backup
sudo cp /etc/foff-milter/foff-milter.yaml.v0.2.backup /etc/foff-milter/foff-milter.yaml

# Install v0.2.x binary (if needed)
# ... restore previous binary

# Start service
sudo systemctl start foff-milter
```

## 📞 Support

### Upgrade Issues
- **Configuration Problems**: Check `/var/log/foff-milter/` logs
- **Detection Issues**: Run test suite to verify functionality
- **Performance Issues**: Monitor system resources and statistics

### Getting Help
- **GitHub Issues**: Report problems at https://github.com/mwjohnson/foff-milter/issues
- **Documentation**: See README.md for detailed configuration options
- **Test Suite**: Use `./tests/run_tests.sh` to verify functionality

## 🎉 Welcome to v0.5.0!

The modular detection system provides:
- **Superior Threat Detection**: 100% test coverage vs 33% legacy
- **Enhanced Security**: 14 specialized detection modules
- **Future-Ready Architecture**: Extensible and maintainable
- **Backward Compatibility**: Existing configurations continue to work

**Enjoy the enhanced email security capabilities of FOFF Milter v0.5.0!** 🚀
