#!/bin/bash

# Test milter setup script

echo "🔧 FOFF Milter Test Setup"
echo "=========================="
echo

# Check if running as root
if [ "$EUID" -ne 0 ]; then 
    echo "❌ This script must be run as root (for socket creation)"
    echo "   Run: sudo ./test-milter.sh"
    exit 1
fi

# Kill any existing milter
echo "1. Stopping any existing milter..."
pkill -f "foff-milter.*-c.*foff-milter.toml" 2>/dev/null
sleep 1

# Clean up old socket
echo "2. Cleaning up old socket..."
rm -f /var/run/foff-milter.sock

# Start milter
echo "3. Starting test milter..."
echo "   Config: foff-milter.toml"
echo "   Socket: /var/run/foff-milter.sock"
echo "   Logs: /tmp/foff-milter-test.log"
echo

./target/release/foff-milter -c foff-milter.toml -v > /tmp/foff-milter-test.log 2>&1 &
MILTER_PID=$!

echo "   PID: $MILTER_PID"
sleep 2

# Check if it's running
if ps -p $MILTER_PID > /dev/null; then
    echo "   ✅ Milter is running"
    
    # Check socket
    if [ -S /var/run/foff-milter.sock ]; then
        echo "   ✅ Socket created"
        ls -l /var/run/foff-milter.sock
    else
        echo "   ❌ Socket not found"
        echo "   Check logs: tail -f /tmp/foff-milter-test.log"
        exit 1
    fi
else
    echo "   ❌ Milter failed to start"
    echo "   Check logs: cat /tmp/foff-milter-test.log"
    exit 1
fi

echo
echo "✅ Test milter is ready!"
echo
echo "To test with an email:"
echo "  sendmail -v recipient@example.com < raw-emails/Memory\\ Loss\\ *.eml"
echo
echo "To view logs:"
echo "  tail -f /tmp/foff-milter-test.log"
echo
echo "To stop:"
echo "  sudo kill $MILTER_PID"
echo "  sudo rm /var/run/foff-milter.sock"
