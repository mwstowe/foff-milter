# Emergency Hotel Production Fix

## Issue
DocuSign phishing bypassed hotel production v0.5.1 due to non-functional modules.

## Root Cause
- Hotel has old placeholder modules in `/etc/foff-milter/configs/`
- Only 1/14 modules loading (missing `name` field in module files)
- DocuSign detection not functional

## Manual Fix Steps

### 1. Copy working modules to hotel
```bash
scp /tmp/test-modules/suspicious-domains.yaml root@hotel.example.com:/tmp/
scp /tmp/test-modules/brand-impersonation.yaml root@hotel.example.com:/tmp/
```

### 2. SSH to hotel and deploy
```bash
ssh root@hotel.example.com

# Backup existing configs
cp -r /etc/foff-milter/configs /etc/foff-milter/configs.backup.$(date +%Y%m%d-%H%M%S)

# Deploy working modules
cp /tmp/suspicious-domains.yaml /etc/foff-milter/configs/
cp /tmp/brand-impersonation.yaml /etc/foff-milter/configs/

# Set permissions
chown -R root:foff-milter /etc/foff-milter/configs/
chmod 640 /etc/foff-milter/configs/*.yaml

# Test config
sudo -u foff-milter /usr/local/bin/foff-milter --test-config -c /etc/foff-milter/foff-milter.yaml

# Reload service
systemctl reload foff-milter
```

### 3. Verify fix
```bash
# Test DocuSign detection
echo 'From: "DocuSign" <fake@docusign.me>
Subject: Your document is ready
' > /tmp/test-docusign.eml

sudo -u foff-milter /usr/local/bin/foff-milter --test-email /tmp/test-docusign.eml -c /etc/foff-milter/foff-milter.yaml
```

Expected result: `TAG AS SPAM` with multiple rules matched.

## Automated Script
Run: `./fix-hotel-production.sh` (adjust HOTEL_HOST/HOTEL_USER as needed)
