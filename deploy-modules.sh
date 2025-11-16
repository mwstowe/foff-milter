#!/bin/bash

# FOFF Milter Module Deployment Script
# Deploys all module configurations to multiple servers and reloads services
# Excludes main config file (foff-milter.toml) which must be managed manually

set -e

# Server configurations: hostname:config_dir:service_command
SERVERS=(
    "hotel.baddomain.com:/etc/foff-milter:systemctl"
    "juliett.baddomain.com:/usr/local/etc/foff-milter:service"
)

# Local directories to deploy
LOCAL_RULESETS_DIR="rulesets"
LOCAL_CONFIG_DIR="config"
LOCAL_FEATURES_DIR="features"

echo "🚀 Deploying FOFF Milter configurations to multiple servers..."
echo "ℹ️  Main config (foff-milter.toml) will NOT be overwritten"

for server_config in "${SERVERS[@]}"; do
    IFS=':' read -r server remote_base_dir service_cmd <<< "$server_config"
    
    echo ""
    echo "📡 Deploying to $server..."
    
    # Create remote directory structure
    echo "📁 Creating remote directory structure..."
    ssh "$server" "sudo mkdir -p $remote_base_dir/modules $remote_base_dir/config $remote_base_dir/features"
    
    # Deploy rulesets (new modular YAML files)
    if [ -d "$LOCAL_RULESETS_DIR" ]; then
        echo "📦 Deploying rulesets..."
        for ruleset in $LOCAL_RULESETS_DIR/*.yaml; do
            if [ -f "$ruleset" ]; then
                ruleset_name=$(basename "$ruleset")
                echo "   → $ruleset_name"
                scp "$ruleset" "$server:/tmp/"
                ssh "$server" "sudo mv /tmp/$ruleset_name $remote_base_dir/modules/ && sudo chown root:root $remote_base_dir/modules/$ruleset_name && sudo chmod 644 $remote_base_dir/modules/$ruleset_name"
            fi
        done
    fi
    
    # Deploy config files (feature configurations)
    if [ -d "$LOCAL_CONFIG_DIR" ]; then
        echo "📦 Deploying config files..."
        for config in $LOCAL_CONFIG_DIR/*.yaml; do
            if [ -f "$config" ]; then
                config_name=$(basename "$config")
                echo "   → $config_name"
                scp "$config" "$server:/tmp/"
                ssh "$server" "sudo mv /tmp/$config_name $remote_base_dir/config/ && sudo chown root:root $remote_base_dir/config/$config_name && sudo chmod 644 $remote_base_dir/config/$config_name"
            fi
        done
    fi
    
    # Deploy features (TOML feature configurations)
    if [ -d "$LOCAL_FEATURES_DIR" ]; then
        echo "📦 Deploying feature configurations..."
        for feature in $LOCAL_FEATURES_DIR/*.toml; do
            if [ -f "$feature" ]; then
                feature_name=$(basename "$feature")
                echo "   → $feature_name"
                scp "$feature" "$server:/tmp/"
                ssh "$server" "sudo mv /tmp/$feature_name $remote_base_dir/features/ && sudo chown root:root $remote_base_dir/features/$feature_name && sudo chmod 644 $remote_base_dir/features/$feature_name"
            fi
        done
    fi
    
    # Clean up legacy files
    echo "🧹 Cleaning up legacy module files..."
    ssh "$server" "sudo rm -f $remote_base_dir/modules/machine-learning.yaml" 2>/dev/null || true
    
    # Reload service to apply new modules
    echo "🔄 Reloading service to apply new configurations..."
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
    echo "   Rulesets:"
    ssh "$server" "ls -la $remote_base_dir/modules/ | head -5"
    echo "   Config files:"
    ssh "$server" "ls -la $remote_base_dir/config/ 2>/dev/null || echo '   (no config directory)'"
    echo "   Features:"
    ssh "$server" "ls -la $remote_base_dir/features/ 2>/dev/null || echo '   (no features directory)'"
    
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
        ssh "$server" "sudo service foff_milter status" 2>/dev/null || echo "   Service not configured yet"
    fi
done

echo ""
echo "ℹ️  Main config files (foff-milter.toml) are NOT overwritten - manage manually"
echo "🔄 Using reload instead of restart maintains existing connections"
echo "📁 Deployed: rulesets → modules/, config → config/, features → features/"
