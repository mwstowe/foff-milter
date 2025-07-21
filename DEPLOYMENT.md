# FOFF Milter Deployment Guide

## Quick Deployment for Sendmail

### 1. Build and Install

```bash
# Build the milter
cargo build --release

# Install binary
sudo cp target/release/foff-milter /usr/local/bin/
sudo chmod +x /usr/local/bin/foff-milter

# Install configuration
sudo cp examples/sparkmail-japanese.yaml /etc/foff-milter.yaml
```

### 2. Configure Sendmail

Add this line to your `/etc/mail/sendmail.mc` file:

```
INPUT_MAIL_FILTER(`foff-milter', `S=unix:/var/run/foff-milter.sock, T=S:30s;R:30s')
```

Rebuild sendmail configuration:

```bash
sudo make -C /etc/mail
sudo systemctl restart sendmail
```

### 3. Test the Configuration

```bash
# Test configuration file
sudo /usr/local/bin/foff-milter --test-config -c /etc/foff-milter.yaml

# Run demonstration mode
sudo /usr/local/bin/foff-milter --demo -c /etc/foff-milter.yaml
```

### 4. Start the Milter

```bash
# Start manually for testing
sudo /usr/local/bin/foff-milter -v -c /etc/foff-milter.yaml

# Or create systemd service (see below)
```

### 5. Create Systemd Service

Create `/etc/systemd/system/foff-milter.service`:

```ini
[Unit]
Description=FOFF Email Milter
After=network.target
Before=sendmail.service

[Service]
Type=simple
User=root
Group=root
ExecStart=/usr/local/bin/foff-milter -c /etc/foff-milter.yaml
Restart=always
RestartSec=5
StandardOutput=journal
StandardError=journal

# Security settings
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/var/run

[Install]
WantedBy=multi-user.target
```

Enable and start the service:

```bash
sudo systemctl daemon-reload
sudo systemctl enable foff-milter
sudo systemctl start foff-milter
sudo systemctl status foff-milter
```

### 6. Verify Operation

Check that the milter is running:

```bash
# Check service status
sudo systemctl status foff-milter

# Check socket exists
ls -la /var/run/foff-milter.sock

# Check logs
sudo journalctl -u foff-milter -f
```

Send a test email and check logs:

```bash
# Watch milter logs
sudo journalctl -u foff-milter -f

# In another terminal, send test email
echo "Test email" | mail -s "Test Subject" user@example.com
```

## Troubleshooting

### Common Issues

1. **Permission denied on socket**:
   ```bash
   sudo chown root:mail /var/run/foff-milter.sock
   sudo chmod 660 /var/run/foff-milter.sock
   ```

2. **Milter not receiving emails**:
   - Check sendmail configuration: `sudo sendmail -bt -d0.1`
   - Verify socket path in sendmail.mc matches milter config
   - Check sendmail logs: `sudo tail -f /var/log/maillog`

3. **Option negotiation errors**:
   - Ensure you're using the latest version with proper negotiation
   - Check milter logs for detailed negotiation info

4. **Service won't start**:
   ```bash
   # Check detailed error
   sudo systemctl status foff-milter -l
   
   # Run manually to see errors
   sudo /usr/local/bin/foff-milter -v -c /etc/foff-milter.yaml
   ```

### Log Analysis

Your rules in action:

```bash
# Watch for Chinese service + Japanese blocks
sudo journalctl -u foff-milter -f | grep "Chinese service"

# Watch for Sparkpost blocks  
sudo journalctl -u foff-milter -f | grep "Sparkpost"

# Watch for all rejections
sudo journalctl -u foff-milter -f | grep "Rejecting message"
```

### Testing Your Rules

Use the included test scripts:

```bash
# Test option negotiation
sudo python3 test_option_negotiation.py

# Test full protocol
sudo python3 test_milter_protocol.py

# Run comprehensive tests
sudo ./test_milter_comprehensive.sh
```

## Production Monitoring

### Log Rotation

Create `/etc/logrotate.d/foff-milter`:

```
/var/log/foff-milter.log {
    daily
    rotate 30
    compress
    delaycompress
    missingok
    notifempty
    postrotate
        systemctl reload foff-milter
    endscript
}
```

### Monitoring Commands

```bash
# Check milter performance
sudo journalctl -u foff-milter --since "1 hour ago" | grep "Accepted milter connection" | wc -l

# Check rejection rate
sudo journalctl -u foff-milter --since "1 day ago" | grep "Rejecting message" | wc -l

# Monitor specific rules
sudo journalctl -u foff-milter --since "1 day ago" | grep "Rule.*matched"
```

## Your Specific Rules

The deployed configuration includes your two specific rules:

1. **Chinese service + Japanese content**: 
   - Blocks emails where X-Mailer matches `service.*.cn` AND subject contains Japanese
   - Returns: `550 5.7.1 Chinese service with Japanese content blocked`

2. **Sparkpost to user@example.com**:
   - Blocks emails where X-Mailer matches `*.sparkpostmail.com` AND sent to `user@example.com`
   - Returns: `550 5.7.1 Sparkpost mail to user@example.com blocked`

Both rules use AND logic, so both conditions must match for the rule to trigger.

## Security Considerations

- Run as root (required for /var/run socket access)
- Socket permissions set to 660 (rw-rw----)
- Regular expression patterns are compiled once at startup
- Multi-threaded design handles concurrent connections safely
- Graceful shutdown cleans up socket file

Your FOFF milter is now ready for production use with sendmail! 🚀
