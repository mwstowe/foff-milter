#!/bin/bash

# FOFF Milter Complete Deployment Script
# Builds, deploys binary, configs, and modules to hotel server

set -e

SERVER="hotel"
REMOTE_DIR="/etc/foff-milter/modules"
LOCAL_MODULES_DIR="modules"

echo "🚀 Complete FOFF Milter deployment to $SERVER..."

# Build release binary
echo "🔨 Building release binary..."
cargo build --release

# Create remote directory structure
echo "📁 Creating remote directory structure..."
ssh $SERVER "sudo mkdir -p $REMOTE_DIR /var/lib/foff-milter /var/log/foff-milter /var/run/foff-milter"

# Deploy binary
echo "📦 Deploying binary..."
scp target/release/foff-milter $SERVER:/tmp/
ssh $SERVER "sudo mv /tmp/foff-milter /usr/local/bin/ && sudo chown root:root /usr/local/bin/foff-milter && sudo chmod 755 /usr/local/bin/foff-milter"

# Deploy main TOML config
echo "⚙️  Deploying main configuration..."
scp foff-milter.toml $SERVER:/tmp/
ssh $SERVER "sudo mv /tmp/foff-milter.toml /etc/foff-milter.toml && sudo chown root:root /etc/foff-milter.toml && sudo chmod 644 /etc/foff-milter.toml"

# Deploy all module files
echo "📋 Deploying module configurations..."
for module in $LOCAL_MODULES_DIR/*.yaml; do
    if [ -f "$module" ]; then
        module_name=$(basename "$module")
        echo "   → $module_name"
        scp "$module" $SERVER:/tmp/
        ssh $SERVER "sudo mv /tmp/$module_name $REMOTE_DIR/ && sudo chown root:root $REMOTE_DIR/$module_name && sudo chmod 644 $REMOTE_DIR/$module_name"
    fi
done

# Set proper ownership for runtime directories
echo "🔐 Setting permissions..."
ssh $SERVER "sudo chown -R foff-milter:foff-milter /var/lib/foff-milter /var/log/foff-milter /var/run/foff-milter"

# Test configuration
echo "🧪 Testing configuration..."
ssh $SERVER "sudo -u foff-milter /usr/local/bin/foff-milter --test-config -c /etc/foff-milter.toml"

# Restart service if it exists
echo "🔄 Restarting service..."
if ssh $SERVER "systemctl is-active --quiet foff-milter"; then
    ssh $SERVER "sudo systemctl restart foff-milter"
    echo "✅ Service restarted successfully"
else
    echo "ℹ️  Service not running - start manually with: sudo systemctl start foff-milter"
fi

# Verify deployment
echo "✅ Verifying deployment..."
echo "📁 Module files:"
ssh $SERVER "ls -la $REMOTE_DIR/"
echo ""
echo "⚙️  Configuration test:"
ssh $SERVER "sudo -u foff-milter /usr/local/bin/foff-milter --test-config -c /etc/foff-milter.toml | head -3"

echo ""
echo "🎉 Complete deployment successful!"
echo ""
echo "📊 Service status:"
ssh $SERVER "sudo systemctl status foff-milter --no-pager -l" || echo "Service not configured yet"
