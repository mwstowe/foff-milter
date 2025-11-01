#!/bin/bash

# Test script for configuration reload functionality
# This script demonstrates how to test the SIGHUP reload feature

echo "🧪 Testing FOFF Milter Configuration Reload"
echo "=========================================="

# Check if milter is running
if ! pgrep -f foff-milter > /dev/null; then
    echo "❌ FOFF Milter is not running. Please start it first."
    exit 1
fi

MILTER_PID=$(pgrep -f foff-milter)
echo "✅ Found FOFF Milter running with PID: $MILTER_PID"

# Test configuration validation
echo "🔍 Testing current configuration..."
if ./target/release/foff-milter --test-config -c foff-milter.toml > /dev/null 2>&1; then
    echo "✅ Current configuration is valid"
else
    echo "❌ Current configuration has errors"
    exit 1
fi

# Send SIGHUP signal
echo "📡 Sending SIGHUP signal to reload configuration and modules..."
kill -HUP $MILTER_PID

# Wait a moment for reload to complete
sleep 2

# Check if process is still running
if pgrep -f foff-milter > /dev/null; then
    echo "✅ FOFF Milter is still running after reload"
    echo "🎉 Configuration reload test completed successfully!"
    echo ""
    echo "Check the milter logs to verify the reload was successful:"
    echo "  tail -f /var/log/foff-milter.log"
    echo "  or"
    echo "  journalctl -u foff-milter -f"
else
    echo "❌ FOFF Milter stopped after reload - check configuration for errors"
    exit 1
fi
