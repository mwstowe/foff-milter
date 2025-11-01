#!/bin/bash

# FOFF Milter Module Deployment Script
# Deploys all module configurations to multiple servers and reloads services

set -e

# Server configurations: hostname:config_dir:service_command
SERVERS=(
    "hotel.baddomain.com:/etc/foff-milter:systemctl"
    "juliett.baddomain.com:/usr/local/etc/foff-milter:service"
)

LOCAL_MODULES_DIR="modules"

echo "🚀 Deploying FOFF Milter modules to multiple servers..."

for server_config in "${SERVERS[@]}"; do
    IFS=':' read -r server remote_base_dir service_cmd <<< "$server_config"
    remote_modules_dir="$remote_base_dir/modules"
    
    echo ""
    echo "📡 Deploying to $server..."
    
    # Create remote directory structure
    echo "📁 Creating remote directory structure..."
    ssh "$server" "sudo mkdir -p $remote_modules_dir"
    
    # Deploy all module files
    echo "📦 Deploying module configurations..."
    
    # Clean up old renamed files
    echo "🧹 Cleaning up old module files..."
    ssh "$server" "sudo rm -f $remote_modules_dir/machine-learning.yaml" 2>/dev/null || true
    
    for module in $LOCAL_MODULES_DIR/*.yaml; do
        if [ -f "$module" ]; then
            module_name=$(basename "$module")
            echo "   → $module_name"
            scp "$module" "$server:/tmp/"
            ssh "$server" "sudo mv /tmp/$module_name $remote_modules_dir/ && sudo chown root $remote_modules_dir/$module_name && sudo chmod 644 $remote_modules_dir/$module_name"
        fi
    done
    
    # Reload service to apply new modules
    echo "🔄 Reloading service to apply new modules..."
    if [ "$service_cmd" = "systemctl" ]; then
        if ssh "$server" "systemctl is-active --quiet foff-milter 2>/dev/null"; then
            ssh "$server" "sudo systemctl reload foff-milter"
            echo "✅ Systemd service reloaded successfully"
        else
            echo "ℹ️  Systemd service not running - start manually with: sudo systemctl start foff-milter"
        fi
    else
        if ssh "$server" "service foff_milter status >/dev/null 2>&1"; then
            ssh "$server" "sudo service foff_milter reload"
            echo "✅ BSD service reloaded successfully"
        else
            echo "ℹ️  BSD service not running - start manually with: sudo service foff_milter start"
        fi
    fi
    
    # Verify deployment
    echo "✅ Verifying deployment on $server..."
    ssh "$server" "ls -la $remote_modules_dir/"
    
    echo "🎉 Deployment to $server complete!"
done

echo ""
echo "🎯 All deployments complete!"
echo ""
echo "📊 Service status:"
for server_config in "${SERVERS[@]}"; do
    IFS=':' read -r server remote_base_dir service_cmd <<< "$server_config"
    echo "🖥️  $server:"
    if [ "$service_cmd" = "systemctl" ]; then
        ssh "$server" "sudo systemctl status foff-milter --no-pager -l" 2>/dev/null || echo "   Service not configured yet"
    else
        ssh "$server" "sudo service foff-milter status" 2>/dev/null || echo "   Service not configured yet"
    fi
done

echo ""
echo "ℹ️  Note: Main config files are NOT overwritten - manage manually"
echo "🔄 Using reload instead of restart maintains existing connections"
