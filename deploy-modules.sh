#!/bin/bash

# FOFF Milter Module Deployment Script
# Deploys all module configurations to hotel server

set -e

SERVER="hotel.example.com"
REMOTE_DIR="/etc/foff-milter/modules"
LOCAL_MODULES_DIR="modules"

echo "🚀 Deploying FOFF Milter modules to $SERVER..."

# Create remote directory if it doesn't exist
echo "📁 Creating remote directory structure..."
ssh $SERVER "sudo mkdir -p $REMOTE_DIR"

# Deploy all module files
echo "📦 Deploying module configurations..."
for module in $LOCAL_MODULES_DIR/*.yaml; do
    if [ -f "$module" ]; then
        module_name=$(basename "$module")
        echo "   → $module_name"
        scp "$module" $SERVER:/tmp/
        ssh $SERVER "sudo mv /tmp/$module_name $REMOTE_DIR/ && sudo chown root:root $REMOTE_DIR/$module_name && sudo chmod 644 $REMOTE_DIR/$module_name"
    fi
done

# Deploy main TOML config
echo "⚙️  Deploying main configuration..."
scp foff-milter.toml $SERVER:/tmp/
ssh $SERVER "sudo mv /tmp/foff-milter.toml /etc/foff-milter.toml && sudo chown root:root /etc/foff-milter.toml && sudo chmod 644 /etc/foff-milter.toml"

# Verify deployment
echo "✅ Verifying deployment..."
ssh $SERVER "ls -la $REMOTE_DIR/"

echo "🎉 Module deployment complete!"
echo ""
echo "📋 Next steps:"
echo "   1. Build and deploy the binary: cargo build --release"
echo "   2. Copy binary to server: scp target/release/foff-milter $SERVER:/usr/local/bin/"
echo "   3. Restart the service: ssh $SERVER 'sudo systemctl restart foff-milter'"
