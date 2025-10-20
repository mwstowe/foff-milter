#!/bin/bash
# FOFF Milter Rollback Script
# Rollback to previous version if needed

set -e

echo "🔄 FOFF Milter Production Rollback"
echo "=================================="

# Stop current service
echo "⏹️  Stopping current service..."
sudo systemctl stop foff-milter

# Restore previous binary (assumes backup exists)
if [ -f /usr/local/bin/foff-milter.backup ]; then
    echo "📦 Restoring previous binary..."
    sudo cp /usr/local/bin/foff-milter.backup /usr/local/bin/foff-milter
else
    echo "❌ No backup binary found at /usr/local/bin/foff-milter.backup"
    echo "   Manual intervention required"
    exit 1
fi

# Remove modules (optional - keeps legacy system)
echo "🗑️  Removing modules (optional)..."
read -p "Remove modules and use legacy system? (y/N): " -n 1 -r
echo
if [[ $REPLY =~ ^[Yy]$ ]]; then
    sudo rm -rf /etc/foff-milter/configs/
fi

# Start service
echo "🔄 Starting service..."
sudo systemctl start foff-milter
sudo systemctl status foff-milter --no-pager -l

echo "✅ Rollback complete!"
