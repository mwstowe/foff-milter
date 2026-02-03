# Milter Mode Bug Investigation

## Problem
Domain Reputation and TLD Risk Assessment features don't work in milter mode, but work perfectly in --test-email mode.

## Confirmed Facts

### ✅ Working
- `--test-email` mode: Score 118-148 with all features
- Features compiled into binary (verified with `strings`)
- Configuration enables features
- Feature config files present and correct
- Juliett milter restarted with latest binary

### ❌ Not Working
- Milter mode: Score 23-43, missing Domain Reputation and TLD Risk
- Both hotel and juliett affected (before juliett restart)
- Some features work (Product Spam, Server Role Analysis, Authentication)
- Domain Reputation and TLD Risk specifically don't work

## Technical Analysis

### How Domain Reputation Extracts Domains
```rust
fn get_primary_domain(&self, context: &MailContext) -> String {
    // 1. Try context.sender (envelope sender)
    // 2. Try context.headers.get("from")
    // 3. Try context.from_header
    // 4. Try context.headers.get("return-path")
    // 5. Try context.headers.get("reply-to")
    // Returns empty string if none found
}
```

### Test Mode vs Milter Mode

**Test Mode** (src/main.rs:842):
```rust
let mut mail_context = MailContext {
    sender: Some(sender.clone()),  // Set from envelope
    from_header: headers.get("from").cloned(),  // Raw header value
    headers: headers.clone(),  // All headers
    ...
};
engine.evaluate(&mail_context).await;
```

**Milter Mode** (src/milter.rs):
```rust
// mail callback (line 438)
mail_ctx.sender = Some(sender_str);

// header callback (line 526)  
mail_ctx.from_header = Some(extract_email_from_header(&value_str));
mail_ctx.headers.insert(header_key, value_str);

// eom callback (line 726)
let mail_ctx_clone = state.lock().unwrap().iter()
    .max_by_key(|(k, _)| k.split('-').next_back()...)
    .map(|(_, ctx)| ctx.clone());
engine.evaluate(&mail_ctx).await;
```

### Key Difference
- **Test mode**: `from_header` = raw header like `"water hack" <water.hack@postpeak.shop>`
- **Milter mode**: `from_header` = extracted email like `water.hack@postpeak.shop`

But this shouldn't matter because `get_primary_domain()` tries `context.sender` FIRST, which should be set in both modes.

### Hypothesis
In milter mode, when `engine.evaluate()` is called in the `eom` callback:
1. The MailContext is cloned from the state HashMap
2. BUT `context.sender` might be empty
3. OR `context.headers` might be empty
4. OR we're cloning the wrong context from the HashMap

This would cause `get_primary_domain()` to return empty string, which causes Domain Reputation to return no evidence.

## Evidence

### Memory Loss Email
Processed by hotel on Feb 2 03:05:55:
- **Missing**: Domain Reputation: Suspicious domain: mail.postpeak.shop (+60)
- **Missing**: TLD Risk Assessment: Suspicious TLD: .shop (+15)
- **Present**: Product Spam: Promotional domain suffix: '.shop' ✅
- **Present**: Server Role Analysis: Suspicious domain: postpeak.shop ✅

This proves:
- Domain extraction works for some features (Product Spam, Server Role)
- But not for Domain Reputation and TLD Risk
- All features use the same MailContext
- So the data MUST be there, but Domain Reputation can't access it

### Product Spam vs Domain Reputation

**Product Spam** (works in milter mode):
```rust
let sender_domain = context
    .from_header
    .as_deref()
    .and_then(|from| from.split('@').nth(1))
    .unwrap_or("")
    .to_lowercase();
```
Uses `context.from_header` directly.

**Domain Reputation** (doesn't work in milter mode):
```rust
fn get_primary_domain(&self, context: &MailContext) -> String {
    if let Some(sender) = &context.sender {
        if let Some(domain) = self.analyzer.extract_domain(sender) {
            return domain;
        }
    }
    // ... tries other sources
}
```
Tries `context.sender` first.

### Critical Insight
Product Spam works, which means `context.from_header` IS populated in milter mode.
But Domain Reputation doesn't work, which means `context.sender` might NOT be populated.

## Root Cause (Suspected)

In milter mode, `context.sender` is not being set or is being cleared before `evaluate()` is called.

Possible causes:
1. The `mail` callback isn't being called
2. The `mail` callback is called but updates the wrong context in the HashMap
3. The context is cloned before the `mail` callback runs
4. There's a race condition between callbacks

## Instrumented Code Added

Added logging to:
1. `src/milter.rs` line 708: Log MailContext state before evaluate()
2. `src/features/domain_reputation.rs` line 350: Log get_primary_domain() execution

This will show:
- What's in `context.sender` when evaluate() is called
- What's in `context.from_header`
- What's in `context.headers`
- Which source Domain Reputation uses to extract the domain

## Next Steps

### Immediate
1. ✅ Restart juliett milter (DONE)
2. Deploy instrumented binary to hotel to capture logs
3. Send test email through hotel milter
4. Check logs to see what's in MailContext

### Deployment Challenge
- Local system has GLIBC 2.41
- Hotel has GLIBC 2.34
- Binary won't run due to version mismatch
- Need to either:
  - Build on hotel (no cargo installed)
  - Build with older toolchain
  - Use Docker to build with matching GLIBC

### Workaround (Temporary)
Enhance Product Spam feature (which DOES work in milter mode):
1. Product Spam already detects `.shop` TLD
2. Add `.skin` and `.quest` to Product Spam
3. Increase Product Spam scoring
4. This catches the spam even if Domain Reputation doesn't fire

### Proper Fix (After Diagnosis)
Once we know why `context.sender` is empty:
1. Fix the milter callback order
2. Ensure sender is set before evaluate()
3. Add integration tests for milter mode
4. Deploy fix to production

## Files Modified
- `src/milter.rs` - Added logging before evaluate()
- `src/features/domain_reputation.rs` - Added logging in get_primary_domain()

## Commands for Deployment
```bash
# Build instrumented version (requires matching GLIBC)
cargo build --release

# Deploy to hotel
scp target/release/foff-milter hotel.baddomain.com:/usr/local/bin/foff-milter.new
ssh hotel.baddomain.com "sudo systemctl stop foff-milter"
ssh hotel.baddomain.com "sudo mv /usr/local/bin/foff-milter.new /usr/local/bin/foff-milter"
ssh hotel.baddomain.com "sudo systemctl start foff-milter"

# Monitor logs
ssh hotel.baddomain.com "sudo journalctl -u foff-milter -f | grep -E 'MILTER MODE|Domain Reputation'"
```

## Conclusion
The bug is real and reproducible. Domain Reputation and TLD Risk don't work in milter mode because `get_primary_domain()` returns empty. Most likely cause is that `context.sender` is not populated when `evaluate()` is called. Need instrumented binary to confirm.
