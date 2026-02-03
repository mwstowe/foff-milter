# Production Investigation Findings

## Problem Statement
Domain Reputation and TLD Risk Assessment features don't fire in PROD for spam emails, but work correctly in TEST mode.

## Evidence

### Memory Loss Email (.shop spam)
- **PROD Score**: 43 points (missed spam)
- **TEST Score**: 118 points (caught spam)
- **Difference**: 75 points

**Missing in PROD:**
- Domain Reputation: Suspicious domain: mail.postpeak.shop (+60 points)
- TLD Risk Assessment: Suspicious TLD: .shop (+15 points)

**Present in PROD:**
- Product Spam: Promotional domain suffix: '.shop' ✅
- Server Role Analysis: Suspicious domain: postpeak.shop ✅
- All authentication features ✅

## Investigation Results

### ✅ Confirmed NOT the Issue
1. **Version mismatch**: PROD runs same commit as TEST (98a5919a)
2. **Header case sensitivity bug**: Already fixed in 98a5919a
3. **Features not compiled**: Both features exist in code at that commit
4. **Features not registered**: Both in feature list
5. **Conditional compilation**: No #[cfg] flags
6. **TLD matching logic**: Correctly checks `.shop` suffix
7. **Domain extraction**: Works for other features (Product Spam, Server Role)
8. **Features system disabled**: Product Spam works, proves features enabled

### ❓ Unable to Verify
1. **PROD configuration file**: Can't access `/etc/foff-milter.toml` on PROD
2. **PROD feature directory**: Can't access `/etc/foff-milter/features/` on PROD
3. **PROD runtime environment**: Can't test milter mode locally without sendmail config

## Technical Analysis

### How Domain Reputation Works
```rust
fn get_primary_domain(&self, context: &MailContext) -> String {
    // 1. Try envelope sender (Return-Path)
    // 2. Try From header
    // 3. Try context.from_header
    // 4. Try Return-Path header
    // 5. Try Reply-To header
    // Returns empty string if none found
}
```

### Why No Evidence in PROD
The feature returns empty evidence ONLY if `get_primary_domain()` returns empty string.
This means ALL of these were empty or failed in PROD:
- context.sender
- context.headers.get("from")
- context.from_header  
- context.headers.get("return-path")
- context.headers.get("reply-to")

But this seems impossible since:
- PROD shows Return-Path header in email
- PROD shows From header in email
- Other features successfully extract domains

### Most Likely Explanations

1. **Old feature configuration file on PROD**
   - PROD might have an old `/etc/foff-milter/features/` directory
   - Old config might not include Domain Reputation/TLD Risk
   - But: features are hardcoded, not config-driven

2. **PROD binary is actually older than reported**
   - Version string might be cached or incorrect
   - Binary might be from before features were added
   - But: commit 98a5919a is after features were added

3. **Feature extraction order issue**
   - Maybe features run in different order in PROD
   - Maybe Domain Reputation runs before headers are populated
   - But: Product Spam works, same feature system

## Recommendations

### Immediate Actions
1. **Access PROD server** to check:
   ```bash
   # Check actual binary version
   /usr/local/bin/foff-milter --version
   md5sum /usr/local/bin/foff-milter
   
   # Check configuration
   cat /etc/foff-milter.toml
   ls -la /etc/foff-milter/features/
   
   # Check if features are in binary
   strings /usr/local/bin/foff-milter | grep "Domain Reputation"
   strings /usr/local/bin/foff-milter | grep "TLD Risk Assessment"
   ```

2. **Add debug logging** to Domain Reputation feature:
   ```rust
   fn get_primary_domain(&self, context: &MailContext) -> String {
       log::info!("Domain Reputation: Extracting primary domain");
       log::info!("  sender: {:?}", context.sender);
       log::info!("  from_header: {:?}", context.from_header);
       // ... rest of function
   }
   ```

3. **Deploy new version** with logging and verify features work

### Alternative: Fix Without Understanding Root Cause
Since we can't determine why PROD doesn't work, we could:
1. Add the missing TLDs (.shop, .skin, .quest) to Product Spam feature (which DOES work in PROD)
2. Increase Product Spam scoring to compensate
3. This would catch the spam even if Domain Reputation doesn't fire

## Conclusion
We've exhausted local investigation options. Need PROD server access or deploy instrumented version to understand why `get_primary_domain()` returns empty in PROD.
