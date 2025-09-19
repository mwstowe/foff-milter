#!/bin/sh

# FOFF Milter Startup Debug Script
# This script helps debug startup issues

echo "FOFF Milter Startup Debug"
echo "========================="

CONFIG_FILE="/usr/local/etc/foff-milter.yaml"
BINARY="/usr/local/bin/foff-milter"
SOCKET="/var/run/foff-milter.sock"
PIDFILE="/var/run/foff-milter.pid"

echo "1. Checking binary..."
if [ -x "$BINARY" ]; then
    echo "✓ Binary exists and is executable: $BINARY"
    ls -la "$BINARY"
else
    echo "✗ Binary not found or not executable: $BINARY"
    exit 1
fi

echo ""
echo "2. Checking configuration..."
if [ -f "$CONFIG_FILE" ]; then
    echo "✓ Configuration file exists: $CONFIG_FILE"
    echo "Testing configuration..."
    if "$BINARY" --test-config -c "$CONFIG_FILE"; then
        echo "✓ Configuration is valid"
    else
        echo "✗ Configuration test failed"
        exit 1
    fi
else
    echo "✗ Configuration file not found: $CONFIG_FILE"
    exit 1
fi

echo ""
echo "3. Checking for existing processes..."
EXISTING_PIDS=$(pgrep -f "foff-milter" 2>/dev/null || true)
if [ -n "$EXISTING_PIDS" ]; then
    echo "⚠ Found existing foff-milter processes: $EXISTING_PIDS"
    echo "Killing them..."
    echo "$EXISTING_PIDS" | xargs kill 2>/dev/null || true
    sleep 2
    REMAINING=$(pgrep -f "foff-milter" 2>/dev/null || true)
    if [ -n "$REMAINING" ]; then
        echo "Force killing remaining processes: $REMAINING"
        echo "$REMAINING" | xargs kill -9 2>/dev/null || true
    fi
else
    echo "✓ No existing processes found"
fi

echo ""
echo "4. Cleaning up old files..."
if [ -f "$PIDFILE" ]; then
    echo "Removing old PID file: $PIDFILE"
    rm -f "$PIDFILE"
fi

if [ -S "$SOCKET" ]; then
    echo "Removing old socket: $SOCKET"
    rm -f "$SOCKET"
fi

echo ""
echo "5. Testing foreground mode..."
echo "Starting foff-milter in foreground mode for 5 seconds..."
echo "Command: $BINARY -v -c $CONFIG_FILE"
echo ""

# Start in background and capture PID
"$BINARY" -v -c "$CONFIG_FILE" &
MILTER_PID=$!

echo "Started with PID: $MILTER_PID"
sleep 2

# Check if it's still running
if kill -0 "$MILTER_PID" 2>/dev/null; then
    echo "✓ Process is running"
    
    # Check if socket was created
    if [ -S "$SOCKET" ]; then
        echo "✓ Socket created: $SOCKET"
        ls -la "$SOCKET"
    else
        echo "✗ Socket not created"
    fi
    
    echo ""
    echo "Stopping test process..."
    kill "$MILTER_PID" 2>/dev/null || true
    sleep 1
    
    if kill -0 "$MILTER_PID" 2>/dev/null; then
        echo "Force killing..."
        kill -9 "$MILTER_PID" 2>/dev/null || true
    fi
    
    echo "✓ Test completed successfully"
else
    echo "✗ Process died immediately"
    echo "Check the logs for errors"
    exit 1
fi

echo ""
echo "6. Testing daemon mode with FreeBSD daemon(8)..."
echo "Command: /usr/sbin/daemon -f -p $PIDFILE $BINARY -c $CONFIG_FILE"

/usr/sbin/daemon -f -p "$PIDFILE" "$BINARY" -c "$CONFIG_FILE"

sleep 3

if [ -f "$PIDFILE" ]; then
    PID=$(cat "$PIDFILE")
    echo "✓ PID file created: $PIDFILE (PID: $PID)"
    
    if kill -0 "$PID" 2>/dev/null; then
        echo "✓ Daemon process is running"
        
        if [ -S "$SOCKET" ]; then
            echo "✓ Socket created: $SOCKET"
            ls -la "$SOCKET"
        else
            echo "✗ Socket not created"
        fi
        
        echo ""
        echo "Stopping daemon..."
        kill "$PID" 2>/dev/null || true
        sleep 2
        
        if kill -0 "$PID" 2>/dev/null; then
            echo "Force killing daemon..."
            kill -9 "$PID" 2>/dev/null || true
        fi
        
        # Clean up
        rm -f "$PIDFILE" "$SOCKET"
        echo "✓ Daemon test completed successfully"
    else
        echo "✗ Daemon process died"
        exit 1
    fi
else
    echo "✗ PID file not created"
    exit 1
fi

echo ""
echo "🎉 All tests passed! The milter should work with the rc.d script."
echo ""
echo "To start the service:"
echo "  service foff_milter start"
echo ""
echo "To check status:"
echo "  service foff_milter status"
echo ""
echo "To view logs:"
echo "  tail -f /var/log/messages"
