#!/bin/sh

# FOFF Milter FreeBSD Deployment Script

set -e

echo "FOFF Milter FreeBSD Deployment"
echo "=============================="

# Check if running as root
if [ "$(id -u)" -ne 0 ]; then
    echo "Please run as root"
    exit 1
fi

# Build the milter
echo "1. Building FOFF milter..."
cargo build --release
echo "✓ Build successful"

# Stop existing service if running
echo ""
echo "2. Stopping existing service..."
if service foff_milter status >/dev/null 2>&1; then
    service foff_milter stop
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

# Install configuration
echo ""
echo "4. Installing configuration..."
if [ ! -f /usr/local/etc/foff-milter.yaml ]; then
    mkdir -p /usr/local/etc
    cp examples/freebsd-config.yaml /usr/local/etc/foff-milter.yaml
    echo "✓ Configuration installed to /usr/local/etc/foff-milter.yaml"
else
    echo "✓ Configuration already exists at /usr/local/etc/foff-milter.yaml"
fi

# Install rc.d script
echo ""
echo "5. Installing rc.d service..."
cp examples/foff-milter.rc /usr/local/etc/rc.d/foff_milter
chmod +x /usr/local/etc/rc.d/foff_milter
echo "✓ Service script installed"

# Test configuration
echo ""
echo "6. Testing configuration..."
if /usr/local/bin/foff-milter --test-config -c /usr/local/etc/foff-milter.yaml; then
    echo "✓ Configuration test passed"
else
    echo "✗ Configuration test failed"
    exit 1
fi

# Enable service in rc.conf
echo ""
echo "7. Enabling service..."
if ! grep -q "foff_milter_enable" /etc/rc.conf; then
    echo 'foff_milter_enable="YES"' >> /etc/rc.conf
    echo 'foff_milter_config="/usr/local/etc/foff-milter.yaml"' >> /etc/rc.conf
    echo "✓ Service enabled in /etc/rc.conf"
else
    echo "✓ Service already enabled in /etc/rc.conf"
fi

# Start service
echo ""
echo "8. Starting service..."
service foff_milter start

# Wait a moment for startup
sleep 2

# Check service status
if service foff_milter status >/dev/null 2>&1; then
    echo "✓ Service started successfully"
else
    echo "✗ Service failed to start"
    echo "Check logs: tail -f /var/log/messages"
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
echo "🎉 FreeBSD deployment successful!"
echo ""
echo "Service commands:"
echo "  service foff_milter start"
echo "  service foff_milter stop"
echo "  service foff_milter restart"
echo "  service foff_milter status"
echo ""
echo "Manual daemon mode:"
echo "  /usr/local/bin/foff-milter --daemon -c /usr/local/etc/foff-milter.yaml"
echo ""
echo "Foreground mode (for testing):"
echo "  /usr/local/bin/foff-milter -v -c /usr/local/etc/foff-milter.yaml"
echo ""
echo "Configuration file: /usr/local/etc/foff-milter.yaml"
echo "Log monitoring: tail -f /var/log/messages"
echo ""
echo "Sendmail configuration:"
echo "Add to /etc/mail/\`hostname\`.mc:"
echo "INPUT_MAIL_FILTER(\`foff-milter', \`S=unix:/var/run/foff-milter.sock, T=S:30s;R:30s')"
echo ""
echo "Then rebuild sendmail config:"
echo "cd /etc/mail && make && make restart"
