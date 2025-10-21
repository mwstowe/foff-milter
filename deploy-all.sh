#!/bin/bash

# FOFF Milter Complete Deployment Script
# Builds, deploys binary, configs, and modules to multiple servers

set -e

# Server configurations: hostname:config_dir:service_command
SERVERS=(
    "hotel:/etc/foff-milter:systemctl"
    "juliett.example.com:/usr/local/etc/foff-milter:service"
)

LOCAL_MODULES_DIR="modules"

echo "🚀 Complete FOFF Milter deployment to multiple servers..."

# Build release binary
echo "🔨 Building release binary..."
cargo build --release

for server_config in "${SERVERS[@]}"; do
    IFS=':' read -r server remote_base_dir service_cmd <<< "$server_config"
    remote_modules_dir="$remote_base_dir/modules"
    
    echo ""
    echo "📡 Deploying to $server..."
    
    # Create remote directory structure
    echo "📁 Creating remote directory structure..."
    ssh "$server" "sudo mkdir -p $remote_modules_dir /var/lib/foff-milter /var/log/foff-milter /var/run/foff-milter"
    
    # Deploy binary
    echo "📦 Deploying binary..."
    scp target/release/foff-milter "$server:/tmp/"
    ssh "$server" "sudo mv /tmp/foff-milter /usr/local/bin/ && sudo chown root:root /usr/local/bin/foff-milter && sudo chmod 755 /usr/local/bin/foff-milter"
    
    # Deploy main TOML config
    echo "⚙️  Deploying main configuration..."
    scp foff-milter.toml "$server:/tmp/"
    ssh "$server" "sudo mv /tmp/foff-milter.toml $remote_base_dir.toml && sudo chown root:root $remote_base_dir.toml && sudo chmod 644 $remote_base_dir.toml"
    
    # Deploy all module files
    echo "📋 Deploying module configurations..."
    for module in $LOCAL_MODULES_DIR/*.yaml; do
        if [ -f "$module" ]; then
            module_name=$(basename "$module")
            echo "   → $module_name"
            scp "$module" "$server:/tmp/"
            ssh "$server" "sudo mv /tmp/$module_name $remote_modules_dir/ && sudo chown root:root $remote_modules_dir/$module_name && sudo chmod 644 $remote_modules_dir/$module_name"
        fi
    done
    
    # Set proper ownership for runtime directories
    echo "🔐 Setting permissions..."
    ssh "$server" "sudo chown -R foff-milter:foff-milter /var/lib/foff-milter /var/log/foff-milter /var/run/foff-milter 2>/dev/null || true"
    
    # Test configuration
    echo "🧪 Testing configuration..."
    config_path="$remote_base_dir.toml"
    ssh "$server" "sudo -u foff-milter /usr/local/bin/foff-milter --test-config -c $config_path 2>/dev/null || /usr/local/bin/foff-milter --test-config -c $config_path"
    
    # Restart service if it exists
    echo "🔄 Restarting service..."
    if [ "$service_cmd" = "systemctl" ]; then
        if ssh "$server" "systemctl is-active --quiet foff-milter 2>/dev/null"; then
            ssh "$server" "sudo systemctl restart foff-milter"
            echo "✅ Systemd service restarted successfully"
        else
            echo "ℹ️  Systemd service not running - start manually with: sudo systemctl start foff-milter"
        fi
    else
        if ssh "$server" "service foff-milter status >/dev/null 2>&1"; then
            ssh "$server" "sudo service foff-milter restart"
            echo "✅ BSD service restarted successfully"
        else
            echo "ℹ️  BSD service not running - start manually with: sudo service foff-milter start"
        fi
    fi
    
    # Verify deployment
    echo "✅ Verifying deployment on $server..."
    echo "📁 Module files:"
    ssh "$server" "ls -la $remote_modules_dir/"
    
    echo "🎉 Deployment to $server complete!"
done

echo ""
echo "🎯 Complete deployment successful!"
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
