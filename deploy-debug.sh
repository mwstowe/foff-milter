#!/bin/bash

# Deploy debug version of foff-milter to production for troubleshooting
# This version includes extra logging for authentication-results header processing

set -e

echo "🔍 Deploying DEBUG version of foff-milter to production..."
echo "⚠️  This will generate extra log output for troubleshooting"

# Build debug-enabled release
echo "🔨 Building debug-enabled release..."
cargo build --release

# Create debug configuration merge
echo "🔧 Creating merged configuration..."
python3 merge-yaml.py whitelist.yaml rules-base.yaml hotel.yaml

# Test configuration
echo "🧪 Testing merged configuration..."
./target/release/foff-milter --test-config -c hotel.yaml

# Deploy to hotel.example.com first
echo "📤 Deploying to hotel.example.com..."
scp target/release/foff-milter root@hotel.example.com:/usr/local/bin/foff-milter-debug
scp hotel.yaml root@hotel.example.com:/etc/foff-milter-debug.yaml

ssh root@hotel.example.com << 'EOF'
echo "🔄 Stopping current milter..."
systemctl stop foff-milter

echo "🔄 Backing up current binary..."
cp /usr/local/bin/foff-milter /usr/local/bin/foff-milter.backup

echo "🔄 Installing debug version..."
cp /usr/local/bin/foff-milter-debug /usr/local/bin/foff-milter
cp /etc/foff-milter-debug.yaml /etc/foff-milter.yaml

echo "🔄 Starting debug milter..."
systemctl start foff-milter

echo "📊 Checking status..."
systemctl status foff-milter --no-pager -l

echo "✅ Debug deployment completed on hotel.example.com"
EOF

echo "🎉 Debug deployment completed!"
echo "📋 To monitor logs: ssh root@hotel.example.com 'journalctl -u foff-milter -f'"
echo "🔄 To rollback: ssh root@hotel.example.com 'cp /usr/local/bin/foff-milter.backup /usr/local/bin/foff-milter && systemctl restart foff-milter'"
