#!/bin/bash

# FOFF Milter Module Deployment Script
# Deploys all module configurations to multiple servers

set -e

# Server configurations: hostname:config_dir
SERVERS=(
    "hotel:/etc/foff-milter"
    "juliett.example.com:/usr/local/etc/foff-milter"
)

LOCAL_MODULES_DIR="modules"

echo "🚀 Deploying FOFF Milter modules to multiple servers..."

for server_config in "${SERVERS[@]}"; do
    IFS=':' read -r server remote_base_dir <<< "$server_config"
    remote_modules_dir="$remote_base_dir/modules"
    
    echo ""
    echo "📡 Deploying to $server..."
    
    # Create remote directory structure
    echo "📁 Creating remote directory structure..."
    ssh "$server" "sudo mkdir -p $remote_modules_dir"
    
    # Deploy all module files
    echo "📦 Deploying module configurations..."
    for module in $LOCAL_MODULES_DIR/*.yaml; do
        if [ -f "$module" ]; then
            module_name=$(basename "$module")
            echo "   → $module_name"
            scp "$module" "$server:/tmp/"
            ssh "$server" "sudo mv /tmp/$module_name $remote_modules_dir/ && sudo chown root:root $remote_modules_dir/$module_name && sudo chmod 644 $remote_modules_dir/$module_name"
        fi
    done
    
    # Verify deployment
    echo "✅ Verifying deployment on $server..."
    ssh "$server" "ls -la $remote_modules_dir/"
    
    echo "🎉 Deployment to $server complete!"
done

echo ""
echo "🎯 All deployments complete!"
echo ""
echo "📋 Next steps:"
echo "   1. Build and deploy the binary: cargo build --release"
echo "   2. Copy binary to servers:"
echo "      scp target/release/foff-milter hotel:/usr/local/bin/"
echo "      scp target/release/foff-milter juliett.example.com:/usr/local/bin/"
echo "   3. Restart services:"
echo "      ssh hotel 'sudo systemctl restart foff-milter'"
echo "      ssh juliett.example.com 'sudo service foff-milter restart'"
echo ""
echo "ℹ️  Note: Main config files are NOT overwritten - manage manually"
