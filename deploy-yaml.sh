#!/bin/bash

# Deploy foff-milter configuration to hotel.example.com and juliett.example.com
# Must be run as root

set -e

# Check if running as root
if [[ $EUID -ne 0 ]]; then
   echo "This script must be run as root" 
   exit 1
fi

# Check if required files exist
if [[ ! -f "legacy-configs/whitelist.yaml" ]]; then
    echo "⚠️  whitelist.yaml not found - creating from example template..."
    if [[ ! -f "examples/whitelist-production.yaml.example" ]]; then
        echo "Error: examples/whitelist-production.yaml.example not found"
        exit 1
    fi
    mkdir -p legacy-configs
    cp examples/whitelist-production.yaml.example legacy-configs/whitelist.yaml
    echo "✅ Created legacy-configs/whitelist.yaml from template"
    echo "💡 Edit legacy-configs/whitelist.yaml to customize for your environment before next deployment"
fi

if [[ ! -f "legacy-configs/rules-base.yaml" ]]; then
    echo "Error: legacy-configs/rules-base.yaml not found"
    echo "💡 Legacy configuration files are now in the legacy-configs/ directory"
    exit 1
fi

# Check if Python 3 is installed
if ! command -v python3 &> /dev/null; then
    echo "Error: python3 is required for merging YAML files"
    exit 1
fi

# Check if merge script exists
if [[ ! -f "merge-yaml.py" ]]; then
    echo "Error: merge-yaml.py script not found"
    exit 1
fi

echo "🔧 Merging legacy-configs/whitelist.yaml and legacy-configs/rules-base.yaml..."

# Merge whitelist and base rules into hotel.yaml using Python script
python3 merge-yaml.py legacy-configs/whitelist.yaml legacy-configs/rules-base.yaml legacy-configs/hotel.yaml

if [[ ! -f "legacy-configs/hotel.yaml" ]]; then
    echo "Error: Failed to create merged legacy-configs/hotel.yaml"
    exit 1
fi

echo "🚀 Deploying foff-milter configuration to both servers..."

# Deploy to hotel.example.com (batch operations)
echo "📤 Deploying to hotel.example.com..."
sftp root@hotel.example.com << EOF
put legacy-configs/hotel.yaml /etc/foff-milter.yaml
quit
EOF

ssh root@hotel.example.com << 'EOF'
echo "🔍 Testing configuration..."
if foff-milter --test-config -c /etc/foff-milter.yaml; then
    echo "✅ Configuration test passed!"
    echo "🔄 Restarting foff-milter service..."
    systemctl restart foff-milter
    echo "📊 Checking service status..."
    systemctl status foff-milter --no-pager -l
    echo "✅ hotel.example.com deployment completed!"
else
    echo "❌ Configuration test failed on hotel.example.com!"
    exit 1
fi
EOF

if [[ $? -ne 0 ]]; then
    echo "❌ Deployment failed on hotel.example.com! Aborting."
    exit 1
fi

# Deploy to juliett.example.com (batch operations)
echo "📤 Deploying to juliett.example.com..."
sftp root@juliett.example.com << EOF
put legacy-configs/hotel.yaml /usr/local/etc/foff-milter.yaml
quit
EOF

ssh root@juliett.example.com << 'EOF'
echo "🔍 Testing configuration..."
if foff-milter --test-config -c /usr/local/etc/foff-milter.yaml; then
    echo "✅ Configuration test passed!"
    echo "🔄 Restarting foff-milter service..."
    service foff-milter restart
    echo "📊 Checking service status..."
    service foff-milter status
    echo "✅ juliett.example.com deployment completed!"
else
    echo "❌ Configuration test failed on juliett.example.com!"
    exit 1
fi
EOF

if [[ $? -ne 0 ]]; then
    echo "❌ Deployment failed on juliett.example.com! Aborting."
    exit 1
fi

echo "🎉 Deployment completed successfully on both servers!"
