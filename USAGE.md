# FOFF Milter Usage Guide

## Command Line Options

```bash
./foff-milter [OPTIONS]
```

### Options

- `-c, --config <FILE>` - Configuration file path (default: `/etc/foff-milter.yaml`)
- `--generate-config <FILE>` - Generate a default configuration file
- `--test-config` - Test configuration file and exit
- `--demo` - Run in demonstration mode (simulate email processing)
- `-v, --verbose` - Enable verbose logging
- `-h, --help` - Print help
- `-V, --version` - Print version

## Usage Modes

### 1. Production Mode (Default)

**Purpose**: Run as a daemon to filter actual emails from sendmail/postfix

```bash
# Run with default config
sudo ./foff-milter

# Run with custom config
sudo ./foff-milter -c /path/to/config.yaml

# Run with verbose logging
sudo ./foff-milter -v -c /path/to/config.yaml
```

**Behavior**:
- Starts as a daemon process
- Creates and binds to the configured Unix socket
- Sets socket permissions to 660 (rw-rw----)
- Creates parent directories if needed
- Waits for connections from sendmail/postfix
- Processes real emails according to your rules
- Runs continuously until stopped (Ctrl+C or kill signal)
- Automatically cleans up socket file on shutdown

**Output**:
```
[INFO] Starting FOFF milter...
[INFO] Starting milter daemon...
[INFO] Creating Unix socket: /tmp/foff-milter.sock
[INFO] Successfully bound to socket: /tmp/foff-milter.sock
[INFO] Set socket permissions to 660
[INFO] Milter daemon started successfully
[INFO] Waiting for email connections from sendmail/postfix...
[INFO] Press Ctrl+C to stop the milter
```

### 2. Demonstration Mode

**Purpose**: Test your rules with simulated emails to see how they would behave

```bash
# Run demo with specific config
./foff-milter --demo -c examples/sparkmail-japanese.yaml

# Run demo with verbose output
./foff-milter --demo -v -c examples/production-examples.yaml
```

**Behavior**:
- Simulates processing 6 different email scenarios
- Shows which rules would match and what actions would be taken
- Exits after demonstration is complete
- No actual email processing or daemon behavior

**Output**:
```
[INFO] Running in demonstration mode...
[INFO] === Test 1: Chinese service with Japanese content ===
[INFO] ✓ Would reject Chinese service + Japanese: Chinese service with Japanese content blocked
[INFO] === Test 2: Sparkpost to user@example.com ===
[INFO] ✓ Would reject Sparkpost to user@example.com: Sparkpost mail to user@example.com blocked
...
[INFO] === Demonstration complete ===
```

### 3. Configuration Testing

**Purpose**: Validate your configuration file without running the milter

```bash
# Test configuration
./foff-milter --test-config -c config.yaml

# Test specific example
./foff-milter --test-config -c examples/sparkmail-japanese.yaml
```

**Behavior**:
- Loads and validates the configuration file
- Checks regex patterns and language settings
- Shows summary of loaded rules
- Exits with success/failure status

**Output**:
```
Configuration file is valid!
Socket path: /var/run/foff-milter.sock
Number of rules: 4
  Rule 1: Block Chinese services with Japanese content
  Rule 2: Block Sparkpost to specific user
  Rule 3: Tag Chinese services with Japanese content
  Rule 4: Tag Sparkpost to specific user
```

### 4. Configuration Generation

**Purpose**: Create a default configuration file to start with

```bash
# Generate default config
./foff-milter --generate-config /etc/foff-milter.yaml

# Generate config in current directory
./foff-milter --generate-config my-config.yaml
```

**Behavior**:
- Creates a new configuration file with default settings
- Includes example rules and documentation
- Exits after file creation

## Typical Workflow

### 1. Development/Testing
```bash
# Generate initial config
./foff-milter --generate-config test-config.yaml

# Edit the config file with your rules
nano test-config.yaml

# Test the configuration
./foff-milter --test-config -c test-config.yaml

# Run demonstration to see behavior
./foff-milter --demo -c test-config.yaml
```

### 2. Production Deployment
```bash
# Copy config to production location
sudo cp test-config.yaml /etc/foff-milter.yaml

# Test production config
sudo ./foff-milter --test-config -c /etc/foff-milter.yaml

# Run in production mode
sudo ./foff-milter -c /etc/foff-milter.yaml
```

### 3. Troubleshooting
```bash
# Run with verbose logging
sudo ./foff-milter -v -c /etc/foff-milter.yaml

# Test specific scenarios
./foff-milter --demo -v -c /etc/foff-milter.yaml

# Validate configuration changes
./foff-milter --test-config -c /etc/foff-milter.yaml
```

## Integration with Mail Servers

### Sendmail
Add to `/etc/mail/sendmail.mc`:
```
INPUT_MAIL_FILTER(`foff-milter', `S=unix:/var/run/foff-milter.sock, T=S:30s;R:30s')
```

### Postfix
Add to `/etc/postfix/main.cf`:
```
smtpd_milters = unix:/var/run/foff-milter.sock
non_smtpd_milters = unix:/var/run/foff-milter.sock
milter_default_action = accept
```

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
sudo systemctl status foff-milter
```

## Logging

- **INFO**: General operation messages
- **DEBUG**: Detailed rule evaluation (use `-v` flag)
- **ERROR**: Critical errors and failures

View logs:
```bash
# If running manually
./foff-milter -v -c config.yaml

# If running as systemd service
sudo journalctl -u foff-milter -f
```
