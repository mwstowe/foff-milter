#!/bin/bash
# Fix production v0.5.1 modules - Deploy working DocuSign detection

set -e

echo "🚨 EMERGENCY: Fix production v0.5.1 module loading"
echo "=================================================="

# Backup existing configs
echo "📦 Backing up existing configs..."
sudo cp -r /etc/foff-milter/configs /etc/foff-milter/configs.backup.$(date +%Y%m%d-%H%M%S)

# Deploy working modules
echo "🛡️ Deploying working detection modules..."
sudo cp /tmp/test-modules/suspicious-domains.yaml /etc/foff-milter/configs/
sudo cp /tmp/test-modules/brand-impersonation.yaml /etc/foff-milter/configs/

# Set proper ownership
sudo chown -R root:foff-milter /etc/foff-milter/configs/
sudo chmod 640 /etc/foff-milter/configs/*.yaml

# Test configuration
echo "🔍 Testing configuration..."
sudo -u foff-milter /usr/local/bin/foff-milter --test-config -c /etc/foff-milter/foff-milter.yaml

# Reload service
echo "🔄 Reloading service..."
sudo systemctl reload foff-milter

echo "✅ Production modules fixed!"
echo "🧪 Test: sudo -u foff-milter /usr/local/bin/foff-milter --test-email /path/to/docusign-test.eml -c /etc/foff-milter/foff-milter.yaml"
