#!/bin/bash

# FOFF Milter Binary Deployment Script
# Manages VMs and deploys binaries to production servers
# Must be run as root

set -e

# Parse command line arguments
DEPLOY_CONFIGS=true
SHOW_HELP=false

while [[ $# -gt 0 ]]; do
    case $1 in
        --no-configs)
            DEPLOY_CONFIGS=false
            shift
            ;;
        --help|-h)
            SHOW_HELP=true
            shift
            ;;
        *)
            echo "❌ Unknown option: $1"
            echo "Use --help for usage information"
            exit 1
            ;;
    esac
done

if [ "$SHOW_HELP" = true ]; then
    echo "FOFF Milter Binary Deployment Script"
    echo ""
    echo "Usage: $0 [OPTIONS]"
    echo ""
    echo "Options:"
    echo "  --no-configs    Skip configuration file deployment (binary only)"
    echo "  --help, -h      Show this help message"
    echo ""
    echo "Default behavior: Deploy binaries AND configurations (except main config)"
    exit 0
fi

# Check if running as root
if [ "$EUID" -ne 0 ]; then
    echo "❌ This script must be run as root"
    exit 1
fi

# VM configurations: vm_name:target_server:deploy_script
VMS=(
    "vegapunk:juliett.baddomain.com:/usr/tools/deploy_foff.sh"
    "AlmaLinux:hotel.baddomain.com:/usr/tools/deploy_foff.sh"
)

# Server configurations for config deployment (same as deploy-modules.sh)
SERVERS=(
    "hotel.baddomain.com:/etc/foff-milter:systemctl"
    "juliett.baddomain.com:/usr/local/etc/foff-milter:service"
)

# Local directories to deploy
LOCAL_RULESETS_DIR="rulesets"
LOCAL_CONFIG_DIR="config"
LOCAL_FEATURES_DIR="features"

VBOX_USER="vbox"
VM_DOMAIN="stowe.network"
WAIT_TIMEOUT=500

echo "🚀 FOFF Milter Binary Deployment via VMs..."
if [ "$DEPLOY_CONFIGS" = true ]; then
    echo "📦 Configuration deployment: ENABLED"
    echo "ℹ️  Main config (foff-milter.toml) will NOT be overwritten"
else
    echo "📦 Configuration deployment: DISABLED (--no-configs)"
fi

# Function to deploy configurations (copied from deploy-modules.sh)
deploy_configs() {
    echo ""
    echo "📦 Deploying configurations to all servers..."
    
    for server_config in "${SERVERS[@]}"; do
        IFS=':' read -r server remote_base_dir service_cmd <<< "$server_config"
        
        echo ""
        echo "📡 Deploying configs to $server..."
        
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
        
        echo "✅ Configuration deployment to $server complete"
    done
}

# Function to check if VM is available
check_vm_available() {
    local vm_name="$1"
    local vm_fqdn="${vm_name}.${VM_DOMAIN}"
    
    echo "🔍 Checking if $vm_fqdn is available..."
    if ping -c 1 -W 5 "$vm_fqdn" >/dev/null 2>&1; then
        if ssh -o ConnectTimeout=5 -o BatchMode=yes "$vm_fqdn" "echo 'VM ready'" >/dev/null 2>&1; then
            echo "✅ $vm_fqdn is available and accessible"
            return 0
        else
            echo "⚠️  $vm_fqdn is pingable but SSH not ready"
            return 1
        fi
    else
        echo "❌ $vm_fqdn is not available"
        return 1
    fi
}

# Function to start VM
start_vm() {
    local vm_name="$1"
    
    echo "🔄 Starting VM: $vm_name..."
    su - "$VBOX_USER" -c "VBoxManage startvm '$vm_name' --type headless"
    
    echo "⏳ Waiting for $vm_name to become available..."
    local count=0
    while [ $count -lt $WAIT_TIMEOUT ]; do
        if check_vm_available "$vm_name"; then
            echo "✅ $vm_name is ready after ${count}s"
            return 0
        fi
        sleep 5
        count=$((count + 5))
        echo "   Waiting... (${count}s/${WAIT_TIMEOUT}s)"
    done
    
    echo "❌ Timeout waiting for $vm_name to become available"
    return 1
}

# Function to deploy via VM
deploy_via_vm() {
    local vm_name="$1"
    local target_server="$2"
    local deploy_script="$3"
    local vm_fqdn="${vm_name}.${VM_DOMAIN}"
    
    echo ""
    echo "📡 Deploying binary to $target_server via $vm_name..."
    
    # Ensure VM is available
    if ! check_vm_available "$vm_name"; then
        echo "🔄 VM not available, starting it..."
        if ! start_vm "$vm_name"; then
            echo "❌ Failed to start $vm_name"
            return 1
        fi
    fi
    
    # Execute deployment script on VM
    echo "🚀 Executing deployment script on $vm_fqdn..."
    if ssh "$vm_fqdn" "$deploy_script"; then
        echo "✅ Binary deployment to $target_server completed successfully"
    else
        echo "❌ Binary deployment to $target_server failed"
        return 1
    fi
}

# Deploy configurations first (if enabled)
if [ "$DEPLOY_CONFIGS" = true ]; then
    deploy_configs
fi

# Main deployment loop for binaries
echo ""
echo "🎯 Starting binary deployments..."

for vm_config in "${VMS[@]}"; do
    IFS=':' read -r vm_name target_server deploy_script <<< "$vm_config"
    
    if ! deploy_via_vm "$vm_name" "$target_server" "$deploy_script"; then
        echo "❌ Failed to deploy binary to $target_server"
        exit 1
    fi
done

echo ""
echo "🎉 All deployments completed successfully!"
echo ""
echo "📊 Deployment Summary:"
if [ "$DEPLOY_CONFIGS" = true ]; then
    echo "   📦 Configurations deployed to all servers"
fi
echo "   ✅ juliett.baddomain.com (via vegapunk.stowe.network)"
echo "   ✅ hotel.baddomain.com (via AlmaLinux.stowe.network)"
echo ""
echo "ℹ️  VMs are left running for potential additional operations"
echo "   To stop VMs manually:"
echo "   su - vbox -c 'VBoxManage controlvm vegapunk poweroff'"
echo "   su - vbox -c 'VBoxManage controlvm AlmaLinux poweroff'"
