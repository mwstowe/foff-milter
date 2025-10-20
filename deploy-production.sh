#!/bin/bash
# FOFF Milter v0.5.1 Production Deployment Script
# Gradual migration to modular system

set -e

echo "🚀 FOFF Milter v0.5.1 Production Deployment"
echo "============================================"

# Phase 1: Deploy binary
echo "📦 Phase 1: Deploying v0.5.1 binary..."
sudo systemctl stop foff-milter
sudo cp target/release/foff-milter /usr/local/bin/
sudo chmod 755 /usr/local/bin/foff-milter

# Phase 2: Deploy core working modules
echo "📋 Phase 2: Deploying core detection modules..."
sudo mkdir -p /etc/foff-milter/configs

# Copy the 3 proven working modules
sudo cp /tmp/test-modules/suspicious-domains.yaml /etc/foff-milter/configs/
sudo cp /tmp/test-modules/brand-impersonation.yaml /etc/foff-milter/configs/
sudo cp /tmp/test-modules/health-spam.yaml /etc/foff-milter/configs/

# Set proper ownership
sudo chown -R root:foff-milter /etc/foff-milter/configs/
sudo chmod 640 /etc/foff-milter/configs/*.yaml

# Phase 3: Verify configuration
echo "🔍 Phase 3: Verifying configuration..."
sudo -u foff-milter /usr/local/bin/foff-milter --test-config -c /etc/foff-milter/foff-milter.yaml

# Phase 4: Start service
echo "🔄 Phase 4: Starting service..."
sudo systemctl start foff-milter
sudo systemctl status foff-milter --no-pager -l

echo "✅ Deployment complete!"
echo "📊 Monitor logs: sudo journalctl -u foff-milter -f"
echo "🧪 Test email: sudo -u foff-milter /usr/local/bin/foff-milter --test-email /path/to/test.eml -c /etc/foff-milter/foff-milter.yaml"
