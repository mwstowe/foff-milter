# Milter Mode Testing Plan

## Objective
Test our local build in milter mode to determine why Domain Reputation and TLD Risk Assessment features don't fire in production.

## Setup Steps

### 1. Start Test Milter
```bash
sudo ./test-milter.sh
```

This will:
- Kill any existing milter
- Clean up old socket
- Start milter with verbose logging
- Verify socket creation

### 2. Configure Sendmail (if needed)
Add to `/etc/mail/sendmail.mc`:
```
INPUT_MAIL_FILTER(`foff-milter', `S=unix:/var/run/foff-milter.sock, F=T, T=S:30s;R:30s')
```

Then rebuild:
```bash
sudo m4 /etc/mail/sendmail.mc > /etc/mail/sendmail.cf
sudo systemctl restart sendmail
```

### 3. Send Test Email
```bash
# Send the Memory Loss spam email through milter
cat "raw-emails/Memory Loss Starts With These 4 Warning Signs... Do You Have Them_.eml" | \
  sendmail -v test@localhost
```

### 4. Check Results

**View milter logs:**
```bash
tail -f /tmp/foff-milter-test.log
```

**Check mail log:**
```bash
tail -f /var/log/mail.log
```

**Look for:**
- Domain Reputation evidence
- TLD Risk Assessment evidence
- Feature extraction logs
- Any errors or warnings

## Expected Outcomes

### If Features Work in Milter Mode
- We'll see Domain Reputation and TLD Risk Assessment evidence in logs
- This means PROD has a configuration issue (features.enabled = false or missing config)

### If Features Don't Work in Milter Mode
- We've reproduced the PROD issue locally
- Can add debug logging to understand why get_primary_domain() returns empty
- Can step through the code to find the bug

## Comparison Points

**TEST mode (working):**
```
Domain Reputation: Suspicious domain: mail.postpeak.shop (+60 points)
TLD Risk Assessment: Suspicious TLD: .shop (+15 points)
```

**PROD mode (not working):**
```
(no Domain Reputation evidence)
(no TLD Risk Assessment evidence)
```

**Milter mode (to be tested):**
```
(will show if features work or not)
```

## Cleanup
```bash
# Stop milter
sudo pkill -f "foff-milter.*-c.*foff-milter.toml"

# Remove socket
sudo rm /var/run/foff-milter.sock

# View final logs
cat /tmp/foff-milter-test.log
```
