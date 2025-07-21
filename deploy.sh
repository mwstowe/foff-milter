#!/bin/bash

# FOFF Milter Deployment Script
# Builds and deploys the milter to production

set -e

echo "FOFF Milter Deployment"
echo "====================="

# Check if running as root
if [ "$EUID" -ne 0 ]; then
    echo "Please run as root (sudo ./deploy.sh)"
    exit 1
fi

# Build the milter
echo "1. Building FOFF milter..."
cargo build --release
echo "✓ Build successful"

# Stop existing service if running
echo ""
echo "2. Stopping existing service..."
if systemctl is-active --quiet foff-milter; then
    systemctl stop foff-milter
    echo "✓ Service stopped"
else
    echo "✓ Service not running"
fi

# Install binary
echo ""
echo "3. Installing binary..."
cp target/release/foff-milter /usr/local/bin/
chmod +x /usr/local/bin/foff-milter
echo "✓ Binary installed to /usr/local/bin/foff-milter"

# Install configuration if it doesn't exist
echo ""
echo "4. Installing configuration..."
if [ ! -f /etc/foff-milter.yaml ]; then
    cp examples/sparkmail-japanese.yaml /etc/foff-milter.yaml
    echo "✓ Configuration installed to /etc/foff-milter.yaml"
else
    echo "✓ Configuration already exists at /etc/foff-milter.yaml"
fi

# Create systemd service if it doesn't exist
echo ""
echo "5. Installing systemd service..."
if [ ! -f /etc/systemd/system/foff-milter.service ]; then
    cat > /etc/systemd/system/foff-milter.service << 'EOF'
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
EOF
    systemctl daemon-reload
    echo "✓ Systemd service created"
else
    echo "✓ Systemd service already exists"
fi

# Test configuration
echo ""
echo "6. Testing configuration..."
if /usr/local/bin/foff-milter --test-config -c /etc/foff-milter.yaml; then
    echo "✓ Configuration test passed"
else
    echo "✗ Configuration test failed"
    exit 1
fi

# Start and enable service
echo ""
echo "7. Starting service..."
systemctl enable foff-milter
systemctl start foff-milter

# Wait a moment for startup
sleep 2

# Check service status
if systemctl is-active --quiet foff-milter; then
    echo "✓ Service started successfully"
else
    echo "✗ Service failed to start"
    echo "Check logs: journalctl -u foff-milter -n 20"
    exit 1
fi

# Check socket exists
if [ -S /var/run/foff-milter.sock ]; then
    echo "✓ Socket created: /var/run/foff-milter.sock"
    ls -la /var/run/foff-milter.sock
else
    echo "✗ Socket not found"
    exit 1
fi

echo ""
echo "🎉 Deployment successful!"
echo ""
echo "Service status:"
systemctl status foff-milter --no-pager -l

echo ""
echo "To monitor logs:"
echo "  sudo journalctl -u foff-milter -f"
echo ""
echo "To test with real email:"
echo "  Send an email and watch the logs for rule matches"
echo ""
echo "Your FOFF milter is now running and ready to filter emails!"
