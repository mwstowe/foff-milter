# Refactoring: Unified Email Parser for Milter/Test Parity

## Problem

Milter mode and test mode build `MailContext` through different code paths, causing feature analysis to produce different results on the same email. This manifests as score parity mismatches where prod (milter) scores differently than test on the same version.

### Example: Enbrighten email (v0.9.33)
- Prod (milter): score 63 — fires "Product Spam" and "Suspicious cross-domain links"
- Test: score -42 — neither fires
- Same version, same email file

### Root Cause

**Test mode** (src/main.rs ~line 2140-2300):
1. Reads file as text
2. Splits at first `\n\n` → headers above, body below
3. Parses headers manually (split on `:`, handle continuations by detecting leading whitespace)
4. Stores entire raw MIME body (including boundaries, part headers) as `context.body`
5. `reconstruct_raw_email()` joins headers + body for normalization
6. Headers stored with lowercase keys, values trimmed

**Milter mode** (src/milter.rs ~line 406-780):
1. MAIL FROM callback → sets `context.sender`, synthetic `return-path` header
2. Header callback (one per header) → inserts into `context.headers`
3. Body callback (chunks) → appends to `context.body` and `context.raw_body`
4. Same `reconstruct_raw_email()` → normalization

### Specific Divergences

| Aspect | Test Mode | Milter Mode |
|--------|-----------|-------------|
| Header folding | Detects continuation lines (starts with space/tab), joins with space | Each header arrives as single value from sendmail (already unfolded) |
| Duplicate headers | Concatenates with space separator | Concatenates with space (same) BUT DKIM gets indexed keys |
| DKIM signatures | Stored as `dkim-signature` (concatenated) | Stored as `dkim-signature-0`, `dkim-signature-1`, etc. |
| Return-Path | Read from file header | Synthetic from MAIL FROM envelope |
| Subject | Read from header, decoded via `decode_mime_header` | Decoded in header callback via `decode_mime_header` |
| Body content | Everything after first `\n\n` in file (full MIME including boundaries) | Raw body chunks from sendmail (should be same but may differ in edge cases) |
| ESP detection | Uses Return-Path from file (original sender) | Uses MAIL FROM (may be rewritten by sendmail) |

### Impact on Normalization

`reconstruct_raw_email()` rebuilds the email from context. Differences in header format affect how `EmailNormalizer::normalize_email()` parses the reconstructed email:
- MIME boundary detection
- Content-Transfer-Encoding per-part
- Quoted-printable decoding scope
- HTML part extraction

The normalized body (`context.normalized.body_text.normalized`) then becomes `context_with_attachments.body` which features analyze.

## Proposed Solution

### New shared function

```rust
// src/email_parser.rs (new module)

pub struct ParsedEmail {
    pub headers: HashMap<String, String>,
    pub subject: Option<String>,
    pub from_header: Option<String>,
    pub sender: Option<String>,  // envelope sender from Return-Path
    pub body: String,
    pub raw_body: String,
}

/// Single implementation of email parsing used by both test and milter modes.
/// Takes raw RFC 5322 email text and produces a consistent ParsedEmail.
pub fn parse_raw_email(raw_email: &str, envelope_sender: Option<&str>) -> ParsedEmail {
    // 1. Split headers from body at first blank line
    // 2. Parse headers:
    //    - Handle continuation lines (leading whitespace)
    //    - Lowercase keys
    //    - Index duplicate DKIM-Signature headers
    //    - Concatenate other duplicates with space
    // 3. Extract subject, decode MIME words
    // 4. Extract From header (full, including display name)
    // 5. Extract sender from Return-Path header or envelope_sender override
    // 6. Body = everything after header separator
}
```

### Integration Points

**Test mode** (src/main.rs):
```rust
let parsed = email_parser::parse_raw_email(&file_contents, None);
let mut context = MailContext {
    sender: parsed.sender,
    from_header: parsed.from_header,
    headers: parsed.headers,
    subject: parsed.subject,
    body: Some(parsed.body),
    raw_body: Some(parsed.raw_body),
    // ... other fields default
};
```

**Milter mode** (src/milter.rs):
After EOM callback, instead of using the piecemeal-built context directly:
```rust
// Reassemble raw email from milter callbacks
let raw_email = reassemble_email(&mail_ctx.headers, &mail_ctx.body);
let parsed = email_parser::parse_raw_email(&raw_email, mail_ctx.sender.as_deref());
// Replace context fields with parsed versions for feature analysis
mail_ctx.headers = parsed.headers;
mail_ctx.subject = parsed.subject;
mail_ctx.from_header = parsed.from_header;
// Keep milter-specific: sender (envelope from MAIL FROM), same-server info
```

OR simpler approach: keep milter building context from callbacks as-is, but ensure the header/body format matches what test mode produces. The key fix is making DKIM indexing and header concatenation identical.

### Simplest Effective Fix

Rather than a full refactoring, the minimum fix for the normalization parity:

1. **Make test mode index DKIM headers** the same way milter does (indexed keys)
2. **Ensure `reconstruct_raw_email` produces identical output** regardless of how headers were stored
3. **OR**: Skip `reconstruct_raw_email` entirely — have normalization work directly on `context.body` (the raw MIME body) which is the same in both modes

Option 3 is likely the least disruptive: change `normalize_email_content` to normalize `context.body` directly (parsing MIME structure from the body alone, using `context.headers` for Content-Type boundary info) rather than reconstructing the full email.

## Files to Modify

- `src/main.rs` — test_email_file function (~lines 2140-2300)
- `src/milter.rs` — header/body callbacks (~lines 500-780)
- `src/filter.rs` — `reconstruct_raw_email()` and `normalize_email_content()`
- New: `src/email_parser.rs` (if going with shared parser approach)

## Testing Strategy

1. Process the Enbrighten email through both modes, compare `context.body` byte-for-byte
2. Compare `context.normalized.body_text.normalized` between modes
3. Run full test suite (588 tests)
4. Verify the specific FPs that had parity issues (Enbrighten, earlier SendGrid emails)

## Priority

Medium-high. This is the root cause of recurring milter/test parity issues that have required individual fixes throughout the project's history. A structural fix eliminates an entire class of bugs.
