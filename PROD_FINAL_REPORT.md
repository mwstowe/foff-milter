# Production Investigation - Final Report

## Problem
Domain Reputation and TLD Risk Assessment features don't fire in PROD milter mode, causing spam to be missed.

## Investigation Results

### ✅ Confirmed Working
- Features work correctly in `--test-email` mode on both servers
- Binary contains the features (verified with `strings`)
- Configuration enables features
- Feature config files exist and are correct

### ❌ Not Working  
- Features don't fire when processing emails in milter mode
- Both hotel and juliett affected
- Emails processed show NO Domain Reputation or TLD Risk evidence

### Test Results
**hotel.baddomain.com:**
- Binary: v0.8.24+98a5919a (Feb 1 17:58)
- `--test-email` mode: Score 118 ✅ (with Domain Reputation and TLD Risk)
- Milter mode: Score 23 ❌ (missing both features)

**juliett.baddomain.com:**
- Binary: v0.8.24 (Feb 1 23:52) 
- Process started: 01:00 (BEFORE binary update - STALE!)
- `--test-email` mode: Score 148 ✅ (with Domain Reputation and TLD Risk)
- Milter mode: Score 43 ❌ (missing both features)

## Root Cause

**Juliett**: Running OLD binary (process started before binary was updated)
- **Fix**: Restart milter to pick up new binary

**Hotel**: Unknown - binary is current but features still don't work in milter mode
- Possible causes:
  1. MailContext not fully populated when features run
  2. Headers not available when Domain Reputation extracts domain
  3. Race condition in milter callback order
  4. Feature extraction happens before headers are processed

## Evidence

### Memory Loss Email (.shop spam)
Processed by hotel on Feb 2 03:05:55 (AFTER Feb 1 17:58 restart):
- Missing: Domain Reputation (+60 points)
- Missing: TLD Risk Assessment (+15 points)  
- Present: Product Spam (works!)
- Present: Server Role Analysis (works!)
- Present: Authentication Analysis (works!)

This proves some features work but Domain Reputation and TLD Risk specifically don't.

## Recommended Actions

### Immediate (Required)
1. **Restart juliett milter** to pick up new binary:
   ```bash
   ssh juliett.baddomain.com "sudo service foff_milter restart"
   ```

2. **Investigate hotel milter** - why doesn't it work even with current binary?
   - Add logging to Domain Reputation `get_primary_domain()` 
   - Deploy instrumented version
   - Check milter logs to see what's happening

### Short Term (Workaround)
Since we can't immediately fix the milter mode bug, enhance Product Spam feature (which DOES work):
1. Add .skin and .quest to suspicious TLD list in Product Spam
2. Increase Product Spam scoring to compensate for missing Domain Reputation
3. This will catch the spam even if Domain Reputation doesn't fire

### Long Term (Proper Fix)
1. Find and fix the milter mode bug that prevents Domain Reputation from working
2. Ensure MailContext is fully populated before features run
3. Add integration tests for milter mode (not just --test-email mode)
4. Add monitoring to detect when features stop working in production

## Code Changes Needed

### Debug Logging (Already Added)
Added logging to `src/features/domain_reputation.rs` to diagnose the issue.
Deploy this version and check logs to see why `get_primary_domain()` returns empty.

### Potential Fix
If the issue is that `context.sender` or `context.from_header` are empty in milter mode,
we need to ensure they're populated before `engine.evaluate()` is called in `src/milter.rs`.

## Next Steps
1. Get sudo access to restart juliett milter
2. Deploy instrumented version to hotel to diagnose the bug
3. Implement workaround (enhance Product Spam) while investigating root cause
4. Fix milter mode bug once identified
5. Add tests to prevent regression

## Files Modified
- `src/features/domain_reputation.rs` - Added debug logging (not yet deployed)

## Commands to Run
```bash
# Restart juliett (REQUIRED)
ssh juliett.baddomain.com "sudo service foff_milter restart"

# Restart hotel (optional, but won't fix the bug)
ssh hotel.baddomain.com "sudo systemctl restart foff-milter"

# Deploy instrumented version for debugging
scp target/release/foff-milter hotel.baddomain.com:/usr/local/bin/foff-milter.new
ssh hotel.baddomain.com "sudo mv /usr/local/bin/foff-milter.new /usr/local/bin/foff-milter"
ssh hotel.baddomain.com "sudo systemctl restart foff-milter"

# Check logs
ssh hotel.baddomain.com "sudo tail -f /var/log/messages | grep 'Domain Reputation'"
```
