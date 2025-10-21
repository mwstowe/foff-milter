#!/bin/bash
# Fix production v0.5.1 modules on hotel system - Deploy working DocuSign detection

set -e

HOTEL_HOST="hotel.example.com"
HOTEL_USER="root"  # Adjust as needed

echo "🚨 EMERGENCY: Fix hotel production v0.5.1 module loading"
echo "======================================================"

# Create temporary directory for modules
echo "📦 Preparing working modules for deployment..."
mkdir -p /tmp/hotel-modules
cp /tmp/test-modules/suspicious-domains.yaml /tmp/hotel-modules/
cp /tmp/test-modules/brand-impersonation.yaml /tmp/hotel-modules/

# Copy modules to hotel
echo "🚀 Copying working modules to hotel..."
scp /tmp/hotel-modules/*.yaml ${HOTEL_USER}@${HOTEL_HOST}:/tmp/

# Execute remote commands on hotel
echo "🛡️ Deploying modules on hotel..."
ssh ${HOTEL_USER}@${HOTEL_HOST} << 'EOF'
# Backup existing configs
cp -r /etc/foff-milter/configs /etc/foff-milter/configs.backup.$(date +%Y%m%d-%H%M%S)

# Deploy working modules
cp /tmp/suspicious-domains.yaml /etc/foff-milter/configs/
cp /tmp/brand-impersonation.yaml /etc/foff-milter/configs/

# Set proper ownership
chown -R root /etc/foff-milter/configs/
chmod 640 /etc/foff-milter/configs/*.yaml

# Test configuration
echo "🔍 Testing configuration..."
/usr/local/bin/foff-milter --test-config -c /etc/foff-milter/foff-milter.yaml

# Reload service
echo "🔄 Reloading service..."
systemctl restart foff-milter

echo "✅ Hotel production modules fixed!"
EOF

# Cleanup
rm -rf /tmp/hotel-modules

echo "🎯 Deployment complete!"
echo "🧪 Test on hotel: ssh ${HOTEL_USER}@${HOTEL_HOST} 'sudo -u foff-milter /usr/local/bin/foff-milter --test-email /path/to/test.eml -c /etc/foff-milter/foff-milter.yaml'"
