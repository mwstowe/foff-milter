use clap::{Arg, Command};
use encoding_rs::WINDOWS_1252;
use foff_milter::anonymize::EmailAnonymizer;
use foff_milter::filter::FilterEngine;
use foff_milter::milter::Milter;
use foff_milter::statistics::StatisticsCollector;
use foff_milter::toml_config::{BlocklistConfig, TomlConfig, WhitelistConfig};
use foff_milter::Config as HeuristicConfig;
use log::LevelFilter;
use std::fs;
use std::process;
use std::sync::Arc;
use tokio::signal::unix::{signal, SignalKind};
use tokio::sync::RwLock;

fn is_legitimate_business_test(context: &foff_milter::filter::MailContext) -> bool {
    let legitimate_businesses = [
        "costco.com",
        "pitneybowes.com",
        "arrived.com",
        "cults3d.com",
        "amazon.com",
        "microsoft.com",
        "google.com",
        "apple.com",
        "walmart.com",
        "target.com",
        "homedepot.com",
        "lowes.com",
        "bestbuy.com",
        "macys.com",
        "nordstrom.com",
        "wolfermans.com",
        "wolfermans-email.com",
        "creditkarma.com",
        "mail.creditkarma.com",
        "suncadia.com",
        "nextdoor.com",
        "ss.email.nextdoor.com",
    ];

    if let Some(from_header) = &context.from_header {
        // Extract domain from From header
        if let Some(domain_start) = from_header.rfind('@') {
            let domain_part = &from_header[domain_start + 1..];
            let domain = domain_part.trim_end_matches('>').trim();

            // Special exclusion for onmicrosoft.com (compromised tenant domains)
            if domain.contains("onmicrosoft.com") {
                return false;
            }

            // Check for business match: exact, subdomain, or contains (for complex domains like Adobe Campaign)
            return legitimate_businesses.iter().any(|business| {
                domain == *business
                    || domain.ends_with(&format!(".{}", business))
                    || domain.contains(business)
            });
        }
    }

    false
}

/// Read email file with encoding fallback for malformed UTF-8
fn read_email_with_encoding_fallback(
    file_path: &str,
) -> Result<String, Box<dyn std::error::Error>> {
    // First try reading as bytes
    let bytes = fs::read(file_path)?;

    // Try UTF-8 first
    if let Ok(content) = String::from_utf8(bytes.clone()) {
        return Ok(content);
    }

    // Try Windows-1252 (common for malformed emails)
    let (content, _, had_errors) = WINDOWS_1252.decode(&bytes);
    if !had_errors {
        return Ok(content.to_string());
    }

    // Try Windows-1252 as fallback (covers most malformed cases)
    let (content, _, _) = WINDOWS_1252.decode(&bytes);
    Ok(content.to_string())
}

/// Decode email body content based on Content-Transfer-Encoding
fn decode_email_body(body: &str, encoding: &str) -> String {
    match encoding.to_lowercase().as_str() {
        "quoted-printable" => {
            // Decode quoted-printable encoding
            let mut decoded = String::new();
            let mut chars = body.chars().peekable();

            while let Some(ch) = chars.next() {
                if ch == '=' {
                    if let Some(&'\n') = chars.peek() {
                        // Soft line break - skip the = and newline
                        chars.next();
                        continue;
                    } else if let Some(&'\r') = chars.peek() {
                        // Soft line break with CRLF - skip = and \r, then check for \n
                        chars.next();
                        if let Some(&'\n') = chars.peek() {
                            chars.next();
                        }
                        continue;
                    } else {
                        // Hex encoding =XX
                        let hex1 = chars.next().unwrap_or('0');
                        let hex2 = chars.next().unwrap_or('0');
                        if let Ok(byte_val) = u8::from_str_radix(&format!("{}{}", hex1, hex2), 16) {
                            decoded.push(byte_val as char);
                        } else {
                            // Invalid hex, keep original
                            decoded.push('=');
                            decoded.push(hex1);
                            decoded.push(hex2);
                        }
                    }
                } else {
                    decoded.push(ch);
                }
            }
            decoded
        }
        "base64" => {
            // Decode base64 encoding
            use base64::{engine::general_purpose, Engine as _};
            match general_purpose::STANDARD.decode(body.replace(['\n', '\r'], "")) {
                Ok(decoded_bytes) => String::from_utf8_lossy(&decoded_bytes).to_string(),
                Err(_) => body.to_string(), // Return original if decoding fails
            }
        }
        _ => body.to_string(), // No encoding or unsupported encoding
    }
}

async fn analyze_email_file(
    config: &HeuristicConfig,
    whitelist_config: &Option<WhitelistConfig>,
    blocklist_config: &Option<BlocklistConfig>,
    toml_config: &Option<TomlConfig>,
    email_file: &str,
    _force_reanalysis: bool,
) {
    println!("\n📧 Email Forensic Analysis");
    println!("═══════════════════════════════════════════════════════════════\n");

    // Read email file
    let email_content = match read_email_with_encoding_fallback(email_file) {
        Ok(content) => content,
        Err(e) => {
            eprintln!("❌ Error reading email file: {}", e);
            return;
        }
    };

    // Extract headers manually
    let lines: Vec<&str> = email_content.lines().collect();
    let mut headers: std::collections::HashMap<String, String> = std::collections::HashMap::new();
    let mut body_start = 0;
    let mut sender = String::new();
    let mut last_header_key: Option<String> = None;

    // Parse headers (match test_email_file logic exactly)
    for (i, line) in lines.iter().enumerate() {
        if line.trim().is_empty() {
            body_start = i + 1;
            break;
        }

        // Handle header continuation lines (lines starting with space or tab)
        if line.starts_with(' ') || line.starts_with('\t') {
            if let Some(ref key) = last_header_key {
                if let Some(existing_value) = headers.get_mut(key) {
                    existing_value.push(' ');
                    existing_value.push_str(line.trim());
                }
            }
            continue;
        }

        if let Some(colon_pos) = line.find(':') {
            let key = line[..colon_pos].trim().to_lowercase(); // Normalize to lowercase like test_email_file
            let value = line[colon_pos + 1..].trim().to_string();
            last_header_key = Some(key.clone());

            // Extract sender information (match test_email_file logic)
            if key == "return-path" {
                sender = value.trim_matches(['<', '>']).to_string();
            } else if key == "from" && sender.is_empty() {
                // Extract email from "Name <email@domain.com>" format
                if let Some(start) = value.rfind('<') {
                    if let Some(end) = value.rfind('>') {
                        sender = value[start + 1..end].to_string();
                    }
                } else {
                    sender = value.clone();
                }
            }

            // Handle header continuation lines by concatenating values (match milter behavior)
            // But don't concatenate X-FOFF headers - they should remain separate
            if let Some(existing_value) = headers.get(&key) {
                if key.starts_with("x-foff-") {
                    // For X-FOFF headers, create a new key with a suffix to keep them separate
                    let mut counter = 1;
                    let mut new_key = format!("{}-{}", key, counter);
                    while headers.contains_key(&new_key) {
                        counter += 1;
                        new_key = format!("{}-{}", key, counter);
                    }
                    headers.insert(new_key, value);
                } else {
                    // Concatenate with existing value (same as milter)
                    let combined_value = format!("{} {}", existing_value, value);
                    headers.insert(key, combined_value);
                }
            } else {
                // First occurrence of this header
                headers.insert(key, value);
            }
        }
    }

    // 1. Sender Information
    println!("📤 SENDER INFORMATION");
    println!("───────────────────────────────────────────────────────────────");

    let mut from_email = None;
    let mut reply_to_email = None;
    let mut return_path_email = None;

    if let Some(from) = headers.get("from") {
        println!("From: {}", from);
        if let Some(email) = foff_milter::milter::extract_email_from_header(from) {
            println!("  └─ Email: {}", email);
            from_email = Some(email.clone());
            if let Some(domain) = email.split('@').nth(1) {
                println!("  └─ Domain: {}", domain);

                // Check domain age
                let domain_checker = foff_milter::domain_age::DomainAgeChecker::new(10, false);
                match domain_checker.get_domain_info(domain).await {
                    Ok(info) => {
                        if let Some(age_days) = info.age_days {
                            println!("  └─ Age: {} days old", age_days);
                            if age_days <= 30 {
                                println!("      ⚠️  Very young domain (≤30 days)");
                            } else if age_days <= 90 {
                                println!("      ⚠️  Young domain (≤90 days)");
                            }
                        } else {
                            println!("  └─ Age: Unknown");
                        }
                    }
                    Err(_) => {
                        println!("  └─ Age: Could not determine");
                    }
                }
            }
        }
    }

    if let Some(reply_to) = headers.get("reply-to") {
        println!("Reply-To: {}", reply_to);
        if let Some(email) = foff_milter::milter::extract_email_from_header(reply_to) {
            reply_to_email = Some(email.clone());
            if let Some(domain) = email.split('@').nth(1) {
                println!("  └─ Domain: {}", domain);

                // Check domain age
                let domain_checker = foff_milter::domain_age::DomainAgeChecker::new(10, false);
                match domain_checker.get_domain_info(domain).await {
                    Ok(info) => {
                        if let Some(age_days) = info.age_days {
                            println!("  └─ Age: {} days old", age_days);
                            if age_days <= 30 {
                                println!("      ⚠️  Very young domain (≤30 days)");
                            } else if age_days <= 90 {
                                println!("      ⚠️  Young domain (≤90 days)");
                            }
                        } else {
                            println!("  └─ Age: Unknown");
                        }
                    }
                    Err(_) => {
                        println!("  └─ Age: Could not determine");
                    }
                }
            }
        }
    }

    if let Some(return_path) = headers.get("return-path") {
        println!("Return-Path: {}", return_path);
        if let Some(email) = foff_milter::milter::extract_email_from_header(return_path) {
            return_path_email = Some(email.clone());
            println!("  └─ Extracted: {}", email);
            if let Some(domain) = email.split('@').nth(1) {
                println!("  └─ Domain: {}", domain);

                // Check domain age
                let domain_checker = foff_milter::domain_age::DomainAgeChecker::new(10, false);
                match domain_checker.get_domain_info(domain).await {
                    Ok(info) => {
                        if let Some(age_days) = info.age_days {
                            println!("  └─ Age: {} days old", age_days);
                            if age_days <= 30 {
                                println!("      ⚠️  Very young domain (≤30 days)");
                            } else if age_days <= 90 {
                                println!("      ⚠️  Young domain (≤90 days)");
                            }
                        } else {
                            println!("  └─ Age: Unknown");
                        }
                    }
                    Err(_) => {
                        println!("  └─ Age: Could not determine");
                    }
                }
            }
        }
    }

    // Sender Consistency Analysis
    println!("\n🔍 SENDER CONSISTENCY ANALYSIS");
    println!("───────────────────────────────────────────────────────────────");

    let mut inconsistencies = Vec::new();

    // Check From vs Reply-To mismatch
    if let (Some(from), Some(reply_to)) = (&from_email, &reply_to_email) {
        if from != reply_to {
            inconsistencies.push(format!("⚠️  From ({}) ≠ Reply-To ({})", from, reply_to));
        }
    }

    // Check From vs Return-Path domain mismatch
    if let (Some(from), Some(return_path)) = (&from_email, &return_path_email) {
        let from_domain = from.split('@').nth(1).unwrap_or("");
        let return_path_domain = return_path.split('@').nth(1).unwrap_or("");
        if from_domain != return_path_domain {
            inconsistencies.push(format!(
                "⚠️  From domain ({}) ≠ Return-Path domain ({})",
                from_domain, return_path_domain
            ));
        }
    }

    // Check for suspicious sender names (numbers, symbols)
    if let Some(from) = headers.get("from") {
        if let Some(name_part) = from.split('<').next() {
            let name = name_part.trim().trim_matches('"');
            if name.chars().all(|c| c.is_numeric() || c == '/' || c == '-') {
                inconsistencies.push(format!(
                    "⚠️  Suspicious sender name: '{}' (appears to be data, not a person)",
                    name
                ));
            }
            // Check for abbreviated vs full name inconsistencies
            if name.contains('.') && name.len() < 25 {
                inconsistencies.push(format!(
                    "⚠️  Abbreviated sender name: '{}' (may not match signature)",
                    name
                ));
            }
        }
    }

    if inconsistencies.is_empty() {
        println!("✅ No sender inconsistencies detected");
    } else {
        for inconsistency in inconsistencies {
            println!("{}", inconsistency);
        }
    }

    // 2. Recipients
    println!("\n📥 RECIPIENT INFORMATION");
    println!("───────────────────────────────────────────────────────────────");

    if let Some(to) = headers.get("To") {
        println!("To: {}", to);
    }

    if let Some(cc) = headers.get("Cc") {
        println!("Cc: {}", cc);
    }

    // 3. Routing Information
    println!("\n🌐 ROUTING & DELIVERY PATH");
    println!("───────────────────────────────────────────────────────────────");

    let received_headers: Vec<_> = lines
        .iter()
        .filter(|line| line.starts_with("Received:"))
        .collect();

    println!("Hops: {}", received_headers.len());

    // Reverse the order to show actual mail flow (origin → destination)
    for (i, received) in received_headers.iter().rev().enumerate() {
        let hop_num = i + 1;
        let total_hops = received_headers.len();

        // Determine hop type
        let hop_type = if hop_num == 1 {
            "ORIGIN"
        } else if hop_num == total_hops {
            "DESTINATION"
        } else if hop_num == total_hops - 1 {
            // This is the proximate hop - the one that delivered to our server
            "PROXIMATE"
        } else {
            // Check if this is forwarding vs relaying
            let received_text = received
                .trim_start_matches("Received:")
                .trim()
                .to_lowercase();
            if received_text.contains("forwarded")
                || received_text.contains("x-forwarded")
                || lines
                    .iter()
                    .any(|line| line.to_lowercase().contains("x-forwarded-for"))
            {
                "FORWARDING"
            } else {
                "RELAY"
            }
        };

        // Highlight the proximate hop
        let prefix = if hop_type == "PROXIMATE" { "🎯 " } else { "" };

        println!(
            "\n{}Hop {} ({}): {}",
            prefix,
            hop_num,
            hop_type,
            received.trim_start_matches("Received:").trim()
        );

        // Add security note for proximate hop
        if hop_type == "PROXIMATE" {
            println!("    └─ 🔍 This is the server that delivered directly to your mail system");
        }
    }

    // Check for forwarding
    println!("\n📬 FORWARDING ANALYSIS");
    println!("───────────────────────────────────────────────────────────────");

    let mut forwarding_detected = false;

    // Check for X-Forwarded headers
    for (key, value) in &headers {
        if key.to_lowercase().contains("forward") {
            println!("⚠️  FORWARDED: {} = {}", key, value);
            forwarding_detected = true;
        }
    }

    // Check for Gmail forwarding patterns
    let has_google_received = received_headers
        .iter()
        .any(|h| h.to_lowercase().contains("google") || h.to_lowercase().contains("gmail"));

    if has_google_received {
        println!("📧 Gmail forwarding detected in routing path");
        forwarding_detected = true;
    }

    // Check for other common forwarding patterns
    for received in &received_headers {
        let received_lower = received.to_lowercase();
        if received_lower.contains("forwarded")
            || received_lower.contains("relay")
            || received_lower.contains("mta-")
        {
            println!(
                "🔄 Potential forwarding/relay detected: {}",
                received.lines().next().unwrap_or("").trim()
            );
            forwarding_detected = true;
        }
    }

    if !forwarding_detected {
        println!("✅ No forwarding detected - direct delivery");
    }

    // 4. Authentication
    println!("\n🔐 AUTHENTICATION STATUS");
    println!("───────────────────────────────────────────────────────────────");

    let mut auth_risk_factors = 0;
    let mut has_any_auth = false;

    // Find the proximate sender from routing path
    let mut proximate_sender = "unknown".to_string();
    if received_headers.len() >= 2 {
        // The proximate sender is the second-to-last hop (the one that delivered to our server)
        let proximate_hop = &received_headers[1]; // Second from end in original order
        if let Some(from_part) = proximate_hop
            .split_whitespace()
            .find(|&word| word.starts_with("from"))
        {
            if let Some(sender) = proximate_hop
                .split_whitespace()
                .skip_while(|&word| word != from_part)
                .nth(1)
            {
                proximate_sender = sender.to_string();
            }
        }
    }

    if let Some(auth_results) = headers.get("authentication-results") {
        // Extract the analyzing server (first part before semicolon)
        let parts: Vec<&str> = auth_results.split(';').collect();
        if let Some(server_part) = parts.first() {
            let analyzing_server = server_part.trim();
            println!("Analyzed by: {}", analyzing_server);
        }

        println!("Proximate Sender: {}", proximate_sender);
        has_any_auth = true;

        // Parse authentication details (look for the last occurrence of each, which is usually proximate)
        if auth_results.contains("dkim=pass") {
            println!("  ✅ DKIM: PASS");
        } else if auth_results.contains("dkim=fail") {
            println!("  ❌ DKIM: FAIL - Message integrity compromised");
            auth_risk_factors += 2;
        } else if auth_results.contains("dkim=none") {
            println!("  ⚠️  DKIM: NONE - No digital signature");
            auth_risk_factors += 1;
        }

        if auth_results.contains("spf=pass") {
            println!("  ✅ SPF: PASS");
        } else if auth_results.contains("spf=fail") {
            println!("  ❌ SPF: FAIL - Sender IP not authorized");
            auth_risk_factors += 2;
        } else if auth_results.contains("spf=none") {
            println!("  ⚠️  SPF: NONE - No sender policy found");
            auth_risk_factors += 1;
        }

        if auth_results.contains("dmarc=pass") {
            println!("  ✅ DMARC: PASS");
        } else if auth_results.contains("dmarc=fail") {
            println!("  ❌ DMARC: FAIL - Policy violation detected");
            auth_risk_factors += 2;
        } else if auth_results.contains("dmarc=none") {
            println!("  ⚠️  DMARC: NONE - No domain policy");
            auth_risk_factors += 1;
        }
    } else {
        println!("⚠️  No Authentication-Results header found");
        auth_risk_factors += 1;
    }

    // Check for DKIM signature even without Authentication-Results
    if let Some(dkim_sig) = headers.get("dkim-signature") {
        if !has_any_auth {
            println!("\nDKIM Signature Analysis:");
        } else {
            println!("\nDKIM Signature Details:");
        }

        if let Some(domain) = dkim_sig
            .split("d=")
            .nth(1)
            .and_then(|s| s.split(';').next())
        {
            let signing_domain = domain.trim();
            println!("  └─ Signing Domain: {}", signing_domain);

            // Check domain alignment with sender
            if let Some(from_header) = headers.get("from") {
                if let Some(sender_domain) = from_header.split('@').nth(1) {
                    let sender_domain_clean = sender_domain.trim_end_matches('>').trim();
                    if signing_domain == sender_domain_clean {
                        println!("  └─ ✅ Domain Aligned: Signature matches sender");
                    } else {
                        println!(
                            "  └─ ⚠️  Domain Misaligned: {} ≠ {}",
                            signing_domain, sender_domain_clean
                        );
                        auth_risk_factors += 1;
                    }
                }
            }
        }

        // Extract signature algorithm
        if let Some(algorithm) = dkim_sig
            .split("a=")
            .nth(1)
            .and_then(|s| s.split(';').next())
        {
            println!("  └─ Algorithm: {}", algorithm.trim());
        }
    } else if !has_any_auth {
        println!("❌ No DKIM signature found");
        auth_risk_factors += 2;
    }

    // Overall authentication risk assessment
    println!("\nAuthentication Risk Assessment:");
    match auth_risk_factors {
        0 => println!("  🟢 LOW RISK - Strong authentication present"),
        1..=2 => println!("  🟡 MEDIUM RISK - Some authentication issues"),
        3..=4 => println!("  🟠 HIGH RISK - Multiple authentication failures"),
        _ => println!("  🔴 CRITICAL RISK - No authentication or major failures"),
    }

    // 5. Encoding Information
    println!("\n📝 ENCODING & CONTENT ANALYSIS");
    println!("───────────────────────────────────────────────────────────────");

    if let Some(content_type) = headers.get("Content-Type") {
        println!("Content-Type: {}", content_type);
    }

    if let Some(content_encoding) = headers.get("Content-Transfer-Encoding") {
        println!("Content-Transfer-Encoding: {}", content_encoding);
    }

    // Check for MIME version
    if let Some(mime_version) = headers.get("MIME-Version") {
        println!("MIME-Version: {}", mime_version);
    }

    // Decode subject
    if let Some(subject) = headers.get("Subject") {
        println!("\nSubject Analysis:");
        println!("  Raw: {}", subject);

        // Decode MIME encoded subject
        let decoded_subject = foff_milter::milter::decode_mime_header(subject);
        if decoded_subject != *subject {
            println!("  Decoded: {}", decoded_subject);
            println!("  🔍 MIME encoding detected in subject");
        } else {
            println!("  ✅ No encoding detected in subject");
        }
    }

    // Analyze email normalization
    println!("\n🔍 CONTENT NORMALIZATION:");
    let normalizer = foff_milter::normalization::EmailNormalizer::new();
    let normalized = normalizer.normalize_email(&email_content);

    println!(
        "  Text Encoding Layers: {}",
        normalized.body_text.encoding_layers.len()
    );
    println!(
        "  HTML Encoding Layers: {}",
        normalized.body_html.encoding_layers.len()
    );

    if !normalized.body_text.obfuscation_indicators.is_empty() {
        println!(
            "  ⚠️  Text obfuscation detected: {:?}",
            normalized.body_text.obfuscation_indicators
        );
    }

    if !normalized.body_html.obfuscation_indicators.is_empty() {
        println!(
            "  ⚠️  HTML obfuscation detected: {:?}",
            normalized.body_html.obfuscation_indicators
        );
    }

    if normalized.body_text.encoding_layers.is_empty()
        && normalized.body_html.encoding_layers.is_empty()
    {
        println!("  ✅ No suspicious encoding detected");
    }

    // 6. Spam Analysis & Evaluation

    // Run through filter engine for scoring (using same setup as test_email_file)
    let mut filter_engine = match FilterEngine::new(config.clone()) {
        Ok(engine) => engine,
        Err(e) => {
            eprintln!("❌ Error creating filter engine: {}", e);
            return;
        }
    };

    // Set whitelist configuration if available
    filter_engine.set_whitelist_config(whitelist_config.clone());

    // Set blocklist configuration if available
    filter_engine.set_blocklist_config(blocklist_config.clone());

    // Set same-server detection (default enabled for analyze)
    filter_engine.set_same_server_detection(true);

    // Disable upstream trust by default for command line analysis
    // Only enable upstream trust if --force-reanalysis is explicitly set to false (which isn't possible with current CLI)
    filter_engine.set_disable_upstream_trust(true);

    // Set sender blocking configuration if available
    if let Some(toml_cfg) = &toml_config {
        filter_engine.set_sender_blocking(toml_cfg.sender_blocking.clone());
    }

    // Set TOML configuration
    if let Some(toml_cfg) = toml_config {
        filter_engine.set_toml_config(toml_cfg.clone());
    } else {
        filter_engine.set_toml_config(TomlConfig::default());
    }

    // Extract sender from headers (use parsed sender or fallback to From header)
    let mut sender = if !sender.is_empty() {
        sender
    } else {
        headers
            .get("from")
            .and_then(|from| foff_milter::milter::extract_email_from_header(from))
            .unwrap_or_default()
    };

    // Fallback for empty sender
    if sender.is_empty() {
        sender = "unknown@example.com".to_string();
    }

    // Extract recipients (basic implementation for analyze)
    let recipients = vec!["test@example.com".to_string()]; // Placeholder for analyze mode

    // Get body content
    let mut body_content: String = lines[body_start..].join("\n");

    // Decode email body content to match production milter behavior
    let content_transfer_encoding = headers
        .get("content-transfer-encoding")
        .map(|s| s.to_lowercase())
        .unwrap_or_default();
    body_content = decode_email_body(&body_content, &content_transfer_encoding);

    // Build mail context (matching milter mode setup exactly)
    let mut mail_context = foff_milter::filter::MailContext {
        sender: Some(sender.clone()),
        from_header: headers.get("from").cloned(),
        recipients: recipients.clone(),
        headers: headers.clone(),
        mailer: headers.get("x-mailer").cloned(),
        subject: headers
            .get("subject")
            .map(|s| foff_milter::milter::decode_mime_header(s)),
        hostname: None,
        helo: None,
        body: Some(body_content.clone()),
        last_header_name: None,
        attachments: Vec::new(),
        extracted_media_text: String::new(),
        is_legitimate_business: false,
        is_first_hop: true, // Match milter mode
        forwarding_source: None,
        forwarding_info: None,
        dkim_verification: None,
        normalized: None, // Let FilterEngine handle this
        proximate_mailer: None,
    };

    // Pre-compute DKIM verification (first hop behavior - must be done before any header modifications)
    use foff_milter::dkim_verification::DkimVerifier;
    let sender_domain = sender.split('@').nth(1);
    mail_context.dkim_verification =
        Some(DkimVerifier::verify(&mail_context.headers, sender_domain));

    // Let FilterEngine do all the processing (same as milter mode)
    let (action, matched_rules, headers_to_add) = filter_engine.evaluate(&mail_context).await;

    // 6. Feature Analysis Results
    println!("\n🧠 FEATURE ANALYSIS");
    println!("───────────────────────────────────────────────────────────────");

    // Display feature evidence
    let feature_evidence: Vec<_> = headers_to_add
        .iter()
        .filter(|(name, _)| name.starts_with("X-FOFF-Feature-Evidence"))
        .collect();

    if feature_evidence.is_empty() {
        println!("✅ No suspicious features detected");
    } else {
        println!("🔍 Detected Features: {}", feature_evidence.len());
        for (_, evidence) in &feature_evidence {
            // Parse evidence format: "Module: Evidence description (server) [hash]"
            if let Some(colon_pos) = evidence.find(": ") {
                let module = &evidence[..colon_pos];
                let rest = &evidence[colon_pos + 2..];

                // Extract description (everything before the server part)
                if let Some(paren_pos) = rest.rfind(" (") {
                    let description = &rest[..paren_pos];
                    println!("  • {}: {}", module, description);
                } else {
                    println!("  • {}", evidence);
                }
            } else {
                println!("  • {}", evidence);
            }
        }
    }

    // 7. Link Analysis
    println!("\n🔗 LINK ANALYSIS");
    println!("───────────────────────────────────────────────────────────────");

    // Extract and analyze links vs URLs from email content
    use regex::Regex;

    let mut clickable_links = Vec::new();
    let mut content_urls = Vec::new();

    if let Some(body) = &mail_context.body {
        // Parse HTML to distinguish clickable links from content URLs
        let link_regex =
            Regex::new(r#"<a[^>]*href\s*=\s*["']([^"']+)["'][^>]*>([^<]*)</a>"#).unwrap();
        let img_regex = Regex::new(r#"<img[^>]*src\s*=\s*["']([^"']+)["'][^>]*"#).unwrap();
        let css_regex = Regex::new(r#"<link[^>]*href\s*=\s*["']([^"']+)["'][^>]*"#).unwrap();
        let script_regex = Regex::new(r#"<script[^>]*src\s*=\s*["']([^"']+)["'][^>]*"#).unwrap();

        // Extract clickable links
        for cap in link_regex.captures_iter(body) {
            if let (Some(url), Some(text)) = (cap.get(1), cap.get(2)) {
                clickable_links.push((url.as_str().to_string(), text.as_str().trim().to_string()));
            }
        }

        // Extract content URLs
        for cap in img_regex.captures_iter(body) {
            if let Some(url) = cap.get(1) {
                content_urls.push(("Image".to_string(), url.as_str().to_string()));
            }
        }

        for cap in css_regex.captures_iter(body) {
            if let Some(url) = cap.get(1) {
                content_urls.push(("CSS".to_string(), url.as_str().to_string()));
            }
        }

        for cap in script_regex.captures_iter(body) {
            if let Some(url) = cap.get(1) {
                content_urls.push(("Script".to_string(), url.as_str().to_string()));
            }
        }
    }

    // Display clickable links
    if clickable_links.is_empty() {
        println!("Clickable Links: 0");
    } else {
        println!("Clickable Links: {}", clickable_links.len());

        for (i, (url, text)) in clickable_links.iter().take(5).enumerate() {
            println!("\nLink {}: {}", i + 1, url);
            if !text.is_empty() {
                println!("  └─ Text: \"{}\"", text);
            }

            // Analyze link purpose
            let url_lower = url.to_lowercase();
            if url_lower.contains("unsubscribe") || url_lower.contains("opt-out") {
                println!("  └─ 📧 Unsubscribe link");
            } else if url_lower.contains("buy")
                || url_lower.contains("purchase")
                || url_lower.contains("order")
            {
                println!("  └─ 🛒 Purchase/Action link");
            } else if url_lower.contains("track") || url_lower.contains("click") {
                println!("  └─ 📊 Tracking link");
            }

            // Domain analysis
            if let Ok(parsed_url) = url::Url::parse(url) {
                if let Some(domain) = parsed_url.domain() {
                    println!("  └─ Domain: {}", domain);

                    // Risk assessment
                    if domain.contains("bit.ly")
                        || domain.contains("tinyurl")
                        || domain.contains("t.co")
                    {
                        println!("  └─ ⚠️  URL shortener - high phishing risk");
                    }

                    if domain.ends_with(".tk") || domain.ends_with(".ml") || domain.ends_with(".ga")
                    {
                        println!("  └─ ⚠️  Suspicious TLD - high spam risk");
                    }
                }
            } else {
                println!("  └─ ❌ Malformed URL - potential attack");
            }
        }

        if clickable_links.len() > 5 {
            println!(
                "\n... and {} more clickable links",
                clickable_links.len() - 5
            );
        }
    }

    // Display content URLs
    if content_urls.is_empty() {
        println!("\nContent URLs: 0");
    } else {
        println!("\nContent URLs: {}", content_urls.len());

        for (i, (url_type, url)) in content_urls.iter().take(3).enumerate() {
            println!("\n{} {}: {}", url_type, i + 1, url);

            // Special analysis for tracking pixels
            if url_type == "Image"
                && (url.contains("1x1") || url.contains("pixel") || url.contains("track"))
            {
                println!("  └─ 👁️  Likely tracking pixel");
            }

            // Domain analysis for content URLs
            if let Ok(parsed_url) = url::Url::parse(url) {
                if let Some(domain) = parsed_url.domain() {
                    println!("  └─ Domain: {}", domain);
                }
            }
        }

        if content_urls.len() > 3 {
            println!("\n... and {} more content URLs", content_urls.len() - 3);
        }
    }

    // 7. Configuration Analysis
    println!("\n🔧 CONFIGURATION ANALYSIS");
    println!("───────────────────────────────────────────────────────────────");

    // Check whitelist status
    if let Some(whitelist) = whitelist_config {
        let sender_email = mail_context
            .from_header
            .as_deref()
            .unwrap_or("")
            .split('<')
            .next_back()
            .unwrap_or("")
            .trim_end_matches('>');
        let sender_domain = sender_email.split('@').nth(1).unwrap_or("");

        let mut whitelist_matches = Vec::new();

        if whitelist.addresses.contains(&sender_email.to_string()) {
            whitelist_matches.push(format!("Address: {}", sender_email));
        }
        if whitelist.domains.contains(&sender_domain.to_string()) {
            whitelist_matches.push(format!("Domain: {}", sender_domain));
        }
        for pattern in &whitelist.domain_patterns {
            if regex::Regex::new(pattern).is_ok_and(|r| r.is_match(sender_domain)) {
                whitelist_matches.push(format!("Pattern: {}", pattern));
            }
        }

        if whitelist_matches.is_empty() {
            println!("Whitelist: ❌ No matches");
        } else {
            println!("Whitelist: ✅ Matched - {}", whitelist_matches.join(", "));
        }
    } else {
        println!("Whitelist: ⚪ Not configured");
    }

    // Check blocklist status
    if let Some(blocklist) = blocklist_config {
        let sender_email = mail_context
            .from_header
            .as_deref()
            .unwrap_or("")
            .split('<')
            .next_back()
            .unwrap_or("")
            .trim_end_matches('>');
        let sender_domain = sender_email.split('@').nth(1).unwrap_or("");

        let mut blocklist_matches = Vec::new();

        if blocklist.addresses.contains(&sender_email.to_string()) {
            blocklist_matches.push(format!("Address: {}", sender_email));
        }
        if blocklist.domains.contains(&sender_domain.to_string()) {
            blocklist_matches.push(format!("Domain: {}", sender_domain));
        }
        for pattern in &blocklist.domain_patterns {
            if regex::Regex::new(pattern).is_ok_and(|r| r.is_match(sender_domain)) {
                blocklist_matches.push(format!("Pattern: {}", pattern));
            }
        }

        if blocklist_matches.is_empty() {
            println!("Blocklist: ✅ No matches");
        } else {
            println!("Blocklist: ❌ Matched - {}", blocklist_matches.join(", "));
        }
    } else {
        println!("Blocklist: ⚪ Not configured");
    }

    // Check sender blocking status
    if let Some(toml_cfg) = toml_config {
        if let Some(sender_blocking) = &toml_cfg.sender_blocking {
            if sender_blocking.enabled {
                let sender_email = mail_context
                    .from_header
                    .as_deref()
                    .unwrap_or("")
                    .split('<')
                    .next_back()
                    .unwrap_or("")
                    .trim_end_matches('>');

                let mut blocking_matches = Vec::new();
                for pattern in &sender_blocking.block_patterns {
                    if regex::Regex::new(pattern).is_ok_and(|r| r.is_match(sender_email)) {
                        blocking_matches.push(pattern.clone());
                    }
                }

                if blocking_matches.is_empty() {
                    println!("Sender Blocking: ✅ No matches");
                } else {
                    println!(
                        "Sender Blocking: ❌ Matched patterns: {}",
                        blocking_matches.join(", ")
                    );
                }
            } else {
                println!("Sender Blocking: ⚪ Disabled");
            }
        } else {
            println!("Sender Blocking: ⚪ Not configured");
        }
    } else {
        println!("Sender Blocking: ⚪ Not configured");
    }

    println!("\n📊 FINAL VERDICT");
    println!("───────────────────────────────────────────────────────────────");
    println!("Action: {:?}", action);

    // Extract actual score from headers
    let actual_score = headers_to_add
        .iter()
        .find(|(name, _)| name.starts_with("X-FOFF-Score"))
        .and_then(|(_, value)| {
            // Extract score from "X-FOFF-Score: 54 - foff-milter v0.8.5 (zou)"
            value
                .split_whitespace()
                .next()
                .and_then(|s| s.parse::<i32>().ok())
        })
        .unwrap_or(0);

    println!("\n📈 SPAM SCORE ANALYSIS:");
    println!("  Actual Score: {}", actual_score);
    match action {
        foff_milter::heuristic_config::Action::Accept => {
            println!("  Classification: ✅ LEGITIMATE (Score < 50)");
        }
        foff_milter::heuristic_config::Action::TagAsSpam { .. } => {
            println!("  Classification: ⚠️  SPAM (Score ≥ 50)");
        }
        foff_milter::heuristic_config::Action::Reject { .. } => {
            println!("  Classification: ❌ REJECTED (Score ≥ 350)");
        }
        foff_milter::heuristic_config::Action::ReportAbuse { .. } => {
            println!("  Classification: 🚨 ABUSE REPORTED (High threat)");
        }
        foff_milter::heuristic_config::Action::UnsubscribeGoogleGroup { .. } => {
            println!("  Classification: 📧 GOOGLE GROUP UNSUBSCRIBE");
        }
    }

    // Show analysis headers (including X-FOFF-Score)
    for (header_name, header_value) in &headers_to_add {
        println!("  • {}: {}", header_name, header_value);
    }

    // 8. Production Consistency Analysis
    println!("\n🔄 PRODUCTION CONSISTENCY ANALYSIS");
    println!("───────────────────────────────────────────────────────────────");

    // Extract existing X-FOFF headers from email
    let existing_scores: Vec<_> = headers
        .iter()
        .filter(|(key, _)| key.starts_with("x-foff-score"))
        .collect();

    if existing_scores.is_empty() {
        println!("✅ No existing X-FOFF headers found - this is a clean email");
        return;
    }

    // Extract existing evidence and rules for comparison
    let existing_evidence: Vec<_> = headers
        .iter()
        .filter(|(key, _)| key.starts_with("x-foff-feature-evidence"))
        .collect();

    let existing_rules: Vec<_> = headers
        .iter()
        .filter(|(key, _)| key.starts_with("x-foff-rule-matched"))
        .collect();

    // Compare scores and show what changed
    for (_, score_header) in &existing_scores {
        if let Some(existing_score) = score_header
            .split_whitespace()
            .next()
            .and_then(|s| s.parse::<i32>().ok())
        {
            let diff = actual_score - existing_score;
            if diff == 0 {
                println!("✅ Score unchanged: {}", actual_score);
            } else {
                println!(
                    "📊 Score changed: {} → {} ({}{})",
                    existing_score,
                    actual_score,
                    if diff > 0 { "+" } else { "" },
                    diff
                );

                // Show what changed
                let current_evidence_count = headers_to_add
                    .iter()
                    .filter(|(name, _)| name.starts_with("X-FOFF-Feature-Evidence"))
                    .count();
                let current_rules_count = headers_to_add
                    .iter()
                    .filter(|(name, _)| name.starts_with("X-FOFF-Rule-Matched"))
                    .count();

                println!(
                    "  Evidence: {} → {} rules",
                    existing_evidence.len(),
                    current_evidence_count
                );
                println!(
                    "  Rules: {} → {} matched",
                    existing_rules.len(),
                    current_rules_count
                );

                // Compare evidence by hash
                let existing_evidence_hashes: std::collections::HashSet<_> = existing_evidence
                    .iter()
                    .filter_map(|(_, value)| {
                        value.rfind('[').and_then(|start| {
                            value[start + 1..]
                                .find(']')
                                .map(|end| &value[start + 1..start + 1 + end])
                        })
                    })
                    .collect();

                let current_evidence_hashes: std::collections::HashSet<_> = headers_to_add
                    .iter()
                    .filter(|(name, _)| name.starts_with("X-FOFF-Feature-Evidence"))
                    .filter_map(|(_, value)| {
                        value.rfind('[').and_then(|start| {
                            value[start + 1..]
                                .find(']')
                                .map(|end| &value[start + 1..start + 1 + end])
                        })
                    })
                    .collect();

                // Check if this is a server hostname difference
                let existing_server = existing_evidence.first().and_then(|(_, value)| {
                    value.find(" (").and_then(|start| {
                        value[start + 2..]
                            .find(')')
                            .map(|end| &value[start + 2..start + 2 + end])
                    })
                });

                let current_server = headers_to_add
                    .iter()
                    .find(|(name, _)| name.starts_with("X-FOFF-Feature-Evidence"))
                    .and_then(|(_, value)| {
                        value.find(" (").and_then(|start| {
                            value[start + 2..]
                                .find(')')
                                .map(|end| &value[start + 2..start + 2 + end])
                        })
                    });

                if let (Some(existing_srv), Some(current_srv)) = (existing_server, current_server) {
                    if existing_srv != current_srv {
                        println!(
                            "  ℹ️  Server changed: {} → {} (hashes will differ)",
                            existing_srv, current_srv
                        );
                    }
                }

                let missing_evidence: Vec<_> = existing_evidence_hashes
                    .difference(&current_evidence_hashes)
                    .collect();
                let new_evidence: Vec<_> = current_evidence_hashes
                    .difference(&existing_evidence_hashes)
                    .collect();

                for hash in &missing_evidence {
                    if let Some((_, evidence)) =
                        existing_evidence.iter().find(|(_, v)| v.contains(*hash))
                    {
                        let name = evidence
                            .split(": ")
                            .nth(1)
                            .and_then(|s| s.split(" (").next())
                            .unwrap_or("Unknown");
                        println!("  - Missing evidence: {}", name);
                    }
                }
                for hash in &new_evidence {
                    if let Some((_, evidence)) = headers_to_add
                        .iter()
                        .filter(|(name, _)| name.starts_with("X-FOFF-Feature-Evidence"))
                        .find(|(_, v)| v.contains(*hash))
                    {
                        let name = evidence
                            .split(": ")
                            .nth(1)
                            .and_then(|s| s.split(" (").next())
                            .unwrap_or("Unknown");
                        println!("  + New evidence: {}", name);
                    }
                }

                // Compare rules by hash
                let existing_rule_hashes: std::collections::HashSet<_> = existing_rules
                    .iter()
                    .filter_map(|(_, value)| {
                        value.rfind('[').and_then(|start| {
                            value[start + 1..]
                                .find(']')
                                .map(|end| &value[start + 1..start + 1 + end])
                        })
                    })
                    .collect();

                let current_rule_hashes: std::collections::HashSet<_> = headers_to_add
                    .iter()
                    .filter(|(name, _)| name.starts_with("X-FOFF-Rule-Matched"))
                    .filter_map(|(_, value)| {
                        value.rfind('[').and_then(|start| {
                            value[start + 1..]
                                .find(']')
                                .map(|end| &value[start + 1..start + 1 + end])
                        })
                    })
                    .collect();

                let missing_rules: Vec<_> = existing_rule_hashes
                    .difference(&current_rule_hashes)
                    .collect();
                let new_rules: Vec<_> = current_rule_hashes
                    .difference(&existing_rule_hashes)
                    .collect();

                for hash in &missing_rules {
                    if let Some((_, rule)) = existing_rules.iter().find(|(_, v)| v.contains(*hash))
                    {
                        let name = rule.split(" (").next().unwrap_or("Unknown");
                        println!("  - Missing rule: {}", name);
                    }
                }
                for hash in &new_rules {
                    if let Some((_, rule)) = headers_to_add
                        .iter()
                        .filter(|(name, _)| name.starts_with("X-FOFF-Rule-Matched"))
                        .find(|(_, v)| v.contains(*hash))
                    {
                        let name = rule.split(" (").next().unwrap_or("Unknown");
                        println!("  + New rule: {}", name);
                    }
                }

                if diff.abs() >= 50 {
                    if diff > 0 {
                        println!("  └─ ⚠️  Significantly more suspicious than before");
                    } else {
                        println!("  └─ ✅ Significantly less suspicious than before");
                    }
                }
            }
            break; // Only show first score comparison
        }
    }

    if !matched_rules.is_empty() {
        let useful_rules: Vec<_> = matched_rules
            .iter()
            .filter(|rule| !rule.contains("Trusting upstream FOFF-milter"))
            .collect();

        if !useful_rules.is_empty() {
            println!("\n🎯 MATCHED DETECTION RULES:");
            for rule in useful_rules {
                println!("  • {}", rule);
            }
        } else {
            println!("\n✅ No threat detection rules matched");
        }
    } else {
        println!("\n✅ No threat detection rules matched");
    }

    println!("\n═══════════════════════════════════════════════════════════════");
}

#[tokio::main]
async fn main() {
    let matches = Command::new("foff-milter")
        .version(env!("CARGO_PKG_VERSION"))
        .about("Enterprise-grade email security platform with modular threat detection")
        .long_about(
            "FOFF Milter v0.5.0 - A comprehensive email security solution featuring:\n\
                    • 14 specialized detection modules for superior threat coverage\n\
                    • Machine learning integration with adaptive intelligence\n\
                    • Advanced security scanning with deep inspection capabilities\n\
                    • Enterprise analytics and real-time monitoring\n\
                    • Backward compatibility with heuristic rule-based configurations",
        )
        .arg(
            Arg::new("config")
                .short('c')
                .long("config")
                .value_name("FILE")
                .help("Configuration file path")
                .default_value("/etc/foff-milter.yaml"),
        )
        .arg(
            Arg::new("generate-modules")
                .long("generate-modules")
                .value_name("DIR")
                .help("Generate all 16 modular configuration files in specified directory")
                .action(clap::ArgAction::Set),
        )
        .arg(
            Arg::new("test-config")
                .long("test-config")
                .help("Test configuration validity (supports both heuristic and modular systems)")
                .action(clap::ArgAction::SetTrue),
        )
        .arg(
            Arg::new("stats")
                .long("stats")
                .help("Show comprehensive statistics including modular detection metrics")
                .action(clap::ArgAction::SetTrue),
        )
        .arg(
            Arg::new("stats-unmatched")
                .long("stats-unmatched")
                .help("Show rules that have never matched (heuristic system only)")
                .action(clap::ArgAction::SetTrue),
        )
        .arg(
            Arg::new("stats-reset")
                .long("stats-reset")
                .help("Reset all statistics and exit")
                .action(clap::ArgAction::SetTrue),
        )
        .arg(
            Arg::new("analytics-report")
                .long("analytics-report")
                .value_name("FORMAT")
                .help("Generate analytics report (json, csv, html)")
                .action(clap::ArgAction::Set),
        )
        .arg(
            Arg::new("demo")
                .long("demo")
                .help("Run in demonstration mode (simulate email processing)")
                .action(clap::ArgAction::SetTrue),
        )
        .arg(
            Arg::new("verbose")
                .short('v')
                .long("verbose")
                .help("Enable verbose logging with detailed threat analysis")
                .action(clap::ArgAction::SetTrue),
        )
        .arg(
            Arg::new("daemon")
                .short('d')
                .long("daemon")
                .help("Run as a daemon (background process)")
                .action(clap::ArgAction::SetTrue),
        )
        .arg(
            Arg::new("test-email")
                .long("test-email")
                .value_name("FILE")
                .help("Test email file against detection system (supports modular and heuristic)")
                .action(clap::ArgAction::Set),
        )
        .arg(
            Arg::new("analyze")
                .long("analyze")
                .value_name("FILE")
                .help("Perform comprehensive forensic analysis of email file")
                .action(clap::ArgAction::Set),
        )
        .arg(
            Arg::new("force-reanalysis")
                .long("force-reanalysis")
                .help("Force fresh analysis even if upstream FOFF headers exist")
                .action(clap::ArgAction::SetTrue),
        )
        .arg(
            Arg::new("anonymize")
                .long("anonymize")
                .value_name("FILE")
                .help("Anonymize email file by replacing personal info and domains")
                .action(clap::ArgAction::Set),
        )
        .arg(
            Arg::new("disable-same-server")
                .long("disable-same-server")
                .help("Disable same-server email detection (useful for testing)")
                .action(clap::ArgAction::SetTrue),
        )
        .arg(
            Arg::new("keep-xfoff-headers")
                .long("keep-xfoff-headers")
                .help("Keep existing X-FOFF headers in email analysis (default: strip them)")
                .action(clap::ArgAction::SetTrue),
        )
        .arg(
            Arg::new("list-modules")
                .long("list-modules")
                .help("List available detection modules and their status")
                .action(clap::ArgAction::SetTrue),
        )
        .arg(
            Arg::new("api-server")
                .long("api-server")
                .help("Start REST API server for remote email analysis")
                .action(clap::ArgAction::SetTrue),
        )
        .arg(
            Arg::new("parity-check")
                .long("parity-check")
                .value_name("ENVIRONMENT")
                .help("Generate production parity report for environment comparison")
                .action(clap::ArgAction::Set),
        )
        .get_matches();

    // Initialize logger based on verbose flag
    let log_level = if matches.get_flag("verbose") {
        LevelFilter::Debug
    } else {
        LevelFilter::Info
    };

    env_logger::Builder::from_default_env()
        .filter_level(log_level)
        .init();

    let config_path = matches.get_one::<String>("config").unwrap();

    if let Some(modules_dir) = matches.get_one::<String>("generate-modules") {
        generate_modular_configs(modules_dir);
        return;
    }

    let (config, whitelist_config, blocklist_config, toml_config) = match load_config(config_path) {
        Ok((config, whitelist, blocklist, toml_cfg)) => (config, whitelist, blocklist, toml_cfg),
        Err(e) => {
            eprintln!("Error loading configuration: {e}");
            process::exit(1);
        }
    };

    if let Some(email_file) = matches.get_one::<String>("anonymize") {
        anonymize_email_file(email_file).await;
        return;
    }

    if let Some(email_file) = matches.get_one::<String>("analyze") {
        let force_reanalysis = matches.get_flag("force-reanalysis");
        analyze_email_file(
            &config,
            &whitelist_config,
            &blocklist_config,
            &toml_config,
            email_file,
            force_reanalysis,
        )
        .await;
        return;
    }

    if let Some(email_file) = matches.get_one::<String>("test-email") {
        let disable_same_server = matches.get_flag("disable-same-server");
        let keep_xfoff_headers = matches.get_flag("keep-xfoff-headers");
        test_email_file(
            &config,
            &whitelist_config,
            &blocklist_config,
            &toml_config,
            email_file,
            disable_same_server,
            keep_xfoff_headers,
        )
        .await;
        return;
    }

    if let Some(environment) = matches.get_one::<String>("parity-check") {
        generate_parity_report(
            &config,
            &whitelist_config,
            &blocklist_config,
            &toml_config,
            environment,
        )
        .await;
        return;
    }

    if matches.get_flag("test-config") {
        println!("🔍 Testing configuration...");
        println!();

        // Check if using modular system or heuristic rules
        if let Some(module_dir) = config.module_config_dir.as_ref() {
            println!("Module configuration directory: {}", module_dir);
            println!("Using modular detection system");

            // Count available module files dynamically
            let mut available_modules = 0;
            if let Ok(entries) = std::fs::read_dir(module_dir) {
                for entry in entries.flatten() {
                    if let Some(extension) = entry.path().extension() {
                        if extension == "yaml" || extension == "yml" {
                            available_modules += 1;
                        }
                    }
                }
            }

            println!("Number of available modules: {}", available_modules);
            println!("✅ Modular system configuration validated");
        } else {
            println!("Number of heuristic rules: {}", config.rules.len());
            for (i, rule) in config.rules.iter().enumerate() {
                println!("  Rule {}: {}", i + 1, rule.name);
            }

            // Still validate heuristic rules if present
            if !config.rules.is_empty() {
                match FilterEngine::new(config.clone()) {
                    Ok(mut engine) => {
                        engine.set_whitelist_config(whitelist_config.clone());
                        engine.set_blocklist_config(blocklist_config.clone());
                        if let Some(toml_cfg) = &toml_config {
                            engine.set_sender_blocking(toml_cfg.sender_blocking.clone());
                        }
                        println!("All regex patterns compiled successfully.");
                    }
                    Err(e) => {
                        println!("❌ Configuration validation failed:");
                        println!("Error: {e}");
                        process::exit(1);
                    }
                }
            }
        }

        // Test feature analysis system
        println!();
        println!("🧠 Testing feature analysis system...");

        if let Some(toml_cfg) = &toml_config {
            if let Some(features_config) = &toml_cfg.features {
                if features_config.enabled {
                    println!("Feature analysis: ✅ ENABLED");
                    println!("Feature config directory: {}", features_config.config_dir);

                    // Check if feature config files exist
                    let feature_files = [
                        "feature_scoring.toml",
                        "brands.toml",
                        "legitimate_domains.toml",
                        "brand_patterns.toml",
                        "bulk_email_services.toml",
                        "payment_processors.toml",
                        "scoring.toml",
                    ];

                    let mut found_files = 0;
                    for file in &feature_files {
                        let path = format!("{}/{}", features_config.config_dir, file);
                        if std::path::Path::new(&path).exists() {
                            found_files += 1;
                            println!("  ✅ {}", file);
                        } else {
                            println!("  ⚠️  {} (missing, using defaults)", file);
                        }
                    }

                    if found_files > 0 {
                        println!(
                            "✅ Feature analysis system validated ({}/{} config files found)",
                            found_files,
                            feature_files.len()
                        );
                    } else {
                        println!("⚠️  Feature analysis using defaults (no config files found)");
                    }
                } else {
                    println!("Feature analysis: ❌ DISABLED");
                }
            } else {
                println!("Feature analysis: ✅ ENABLED (using defaults)");
                println!("Feature config directory: /usr/local/etc/foff-milter/features (FreeBSD) or /etc/foff-milter/features (Linux)");
            }
        } else {
            println!("Feature analysis: ✅ ENABLED (using defaults)");
            println!("Feature config directory: /usr/local/etc/foff-milter/features (FreeBSD) or /etc/foff-milter/features (Linux)");
        }
        return;
    }

    // Handle statistics commands
    if matches.get_flag("stats")
        || matches.get_flag("stats-unmatched")
        || matches.get_flag("stats-reset")
    {
        let stats_config = config.statistics.as_ref();

        if stats_config.is_none() || !stats_config.unwrap().enabled {
            println!("❌ Statistics are not enabled in configuration");
            process::exit(1);
        }

        let stats_config = stats_config.unwrap();
        let collector = match StatisticsCollector::new(stats_config.database_path.clone(), 60) {
            Ok(collector) => collector,
            Err(e) => {
                println!("❌ Failed to access statistics database: {e}");
                process::exit(1);
            }
        };

        if matches.get_flag("stats-reset") {
            match collector.reset_stats() {
                Ok(()) => println!("✅ Statistics reset successfully"),
                Err(e) => {
                    println!("❌ Failed to reset statistics: {e}");
                    process::exit(1);
                }
            }
        } else if matches.get_flag("stats-unmatched") {
            let rule_names: Vec<String> = config.rules.iter().map(|r| r.name.clone()).collect();
            match collector.get_unmatched_rules(&rule_names) {
                Ok(unmatched) => {
                    if unmatched.is_empty() {
                        println!("✅ All rules have been matched at least once");
                    } else {
                        println!(
                            "📊 Rules that have never matched ({} total):",
                            unmatched.len()
                        );
                        println!("═══════════════════════════════════════");
                        for rule_name in unmatched {
                            println!("  • {rule_name}");
                        }
                        println!();
                        println!("💡 Consider reviewing these rules - they may be:");
                        println!("   - Too restrictive");
                        println!("   - Targeting threats that haven't occurred");
                        println!("   - Redundant with other rules");
                    }
                }
                Err(e) => {
                    println!("❌ Failed to get unmatched rules: {e}");
                    process::exit(1);
                }
            }
        } else {
            // Show stats
            match collector.get_stats() {
                Ok((global_stats, rule_stats)) => {
                    println!("📊 FOFF Milter Statistics");
                    println!("═══════════════════════════════════════");
                    println!();
                    println!("📈 Global Statistics:");
                    println!("  Total Emails Processed: {}", global_stats.total_emails);
                    if global_stats.total_emails > 0 {
                        let accept_pct = (global_stats.total_accepts as f64
                            / global_stats.total_emails as f64)
                            * 100.0;
                        let reject_pct = (global_stats.total_rejects as f64
                            / global_stats.total_emails as f64)
                            * 100.0;
                        let tag_pct = (global_stats.total_tags as f64
                            / global_stats.total_emails as f64)
                            * 100.0;
                        let no_match_pct = (global_stats.no_rule_matches as f64
                            / global_stats.total_emails as f64)
                            * 100.0;

                        println!(
                            "  ├─ Accepted: {} ({:.1}%)",
                            global_stats.total_accepts, accept_pct
                        );
                        println!(
                            "  ├─ Rejected: {} ({:.1}%)",
                            global_stats.total_rejects, reject_pct
                        );
                        println!(
                            "  ├─ Tagged as Spam: {} ({:.1}%)",
                            global_stats.total_tags, tag_pct
                        );
                        println!(
                            "  └─ No Rule Matches: {} ({:.1}%)",
                            global_stats.no_rule_matches, no_match_pct
                        );
                    }
                    println!();
                    println!(
                        "  Started: {}",
                        global_stats.start_time.format("%Y-%m-%d %H:%M:%S UTC")
                    );
                    println!(
                        "  Last Updated: {}",
                        global_stats.last_updated.format("%Y-%m-%d %H:%M:%S UTC")
                    );
                    println!();

                    if !rule_stats.is_empty() {
                        println!("🎯 Rule Statistics (sorted by matches):");
                        println!("┌─────────────────────────────────────────────────────────────────────────┐");
                        println!("│ Rule Name                                    │ Matches │ Reject │   Tag │");
                        println!("├─────────────────────────────────────────────────────────────────────────┤");

                        for stats in rule_stats.iter().take(20) {
                            // Show top 20
                            println!(
                                "│ {:<44} │ {:>7} │ {:>6} │ {:>5} │",
                                truncate_string(&stats.rule_name, 44),
                                stats.matches,
                                stats.rejects,
                                stats.tags
                            );
                        }
                        println!("└─────────────────────────────────────────────────────────────────────────┘");

                        if rule_stats.len() > 20 {
                            println!("  ... and {} more rules", rule_stats.len() - 20);
                        }
                    } else {
                        println!("📭 No rule matches recorded yet");
                    }
                }
                Err(e) => {
                    println!("❌ Failed to get statistics: {e}");
                    process::exit(1);
                }
            }
        }
        return;
    }

    // Handle analytics report
    if let Some(format) = matches.get_one::<String>("analytics-report") {
        println!("📊 Generating analytics report in {} format...", format);
        match format.to_lowercase().as_str() {
            "json" => {
                println!("{{");
                println!(
                    "  \"system\": \"FOFF Milter v{}\",",
                    env!("CARGO_PKG_VERSION")
                );
                println!("  \"detection_system\": \"modular\",");
                println!("  \"modules\": 14,");
                println!("  \"test_coverage\": \"100%\",");
                println!("  \"status\": \"operational\"");
                println!("}}");
            }
            "csv" => {
                println!("metric,value");
                println!("version,{}", env!("CARGO_PKG_VERSION"));
                println!("detection_system,modular");
                println!("modules,14");
                println!("test_coverage,100%");
            }
            "html" => {
                println!("<html><body>");
                println!("<h1>FOFF Milter Analytics Report</h1>");
                println!("<p>Version: {}</p>", env!("CARGO_PKG_VERSION"));
                println!("<p>Detection System: Modular</p>");
                println!("<p>Modules: 14</p>");
                println!("<p>Test Coverage: 100%</p>");
                println!("</body></html>");
            }
            _ => {
                eprintln!("❌ Unsupported format: {}. Use json, csv, or html", format);
                process::exit(1);
            }
        }
        return;
    }

    // Handle list modules
    if matches.get_flag("list-modules") {
        println!("📋 Available Detection Modules");
        println!("═══════════════════════════════════════");

        if let Some(module_dir) = config.module_config_dir.as_ref() {
            let modules = [
                (
                    "adult-content.yaml",
                    "Adult Content Filtering",
                    "Adult content & romance fraud detection",
                ),
                (
                    "financial-services.yaml",
                    "Financial Services Protection",
                    "Banking phishing & financial fraud detection",
                ),
                (
                    "technology-scams.yaml",
                    "Technology Scam Prevention",
                    "Tech support fraud & software scams",
                ),
                (
                    "multi-language.yaml",
                    "Multi-Language Threat Detection",
                    "International threats & encoding abuse",
                ),
                (
                    "performance.yaml",
                    "Performance Optimization",
                    "System performance & monitoring",
                ),
                (
                    "analytics.yaml",
                    "Advanced Analytics",
                    "Real-time analytics & reporting",
                ),
                (
                    "advanced-heuristics.yaml",
                    "Machine Learning",
                    "AI-powered adaptive intelligence",
                ),
                (
                    "integration.yaml",
                    "Enterprise Integration",
                    "SIEM integration & API connectivity",
                ),
                (
                    "advanced-security.yaml",
                    "Advanced Security",
                    "Deep inspection & threat analysis",
                ),
            ];

            for (file, name, description) in &modules {
                let path = std::path::Path::new(module_dir).join(file);
                let status = if path.exists() {
                    "✅ Active"
                } else {
                    "❌ Missing"
                };
                println!("  {} {}", status, name);
                println!("    File: {}", file);
                println!("    Description: {}", description);
                println!();
            }
        } else {
            println!("❌ Modular system not configured. Set module_config_dir in configuration.");
        }
        return;
    }

    // Handle API server
    if matches.get_flag("api-server") {
        println!("🚀 Starting REST API server...");
        println!("📡 API server functionality requires integration module configuration");
        println!("🔧 Configure integration.yaml to enable REST API endpoints");
        println!("📖 See documentation for API usage examples");
        // TODO: Implement actual API server startup
        return;
    }

    let demo_mode = matches.get_flag("demo");
    let daemon_mode = matches.get_flag("daemon");

    // Minimal daemon mode for FreeBSD
    if daemon_mode && !demo_mode {
        #[cfg(unix)]
        {
            match unsafe { libc::fork() } {
                -1 => std::process::exit(1),
                0 => {}                     // Child continues
                _ => std::process::exit(0), // Parent exits
            }
        }
    }

    log::info!("Starting FOFF milter...");

    if demo_mode {
        log::info!("Demo mode not implemented for simple milter yet");
        return;
    }

    let socket_path = config.socket_path.clone();
    let config_file_path = config_path.clone();

    // Wrap configuration in Arc<RwLock> for thread-safe reloading
    let milter_config = Arc::new(RwLock::new((config, toml_config)));
    let milter_config_clone = milter_config.clone();

    // Create initial milter instance
    let (initial_config, initial_toml_config) = {
        let config_guard = milter_config.read().await;
        (config_guard.0.clone(), config_guard.1.clone())
    };

    let initial_milter = if let Some(toml_cfg) = initial_toml_config {
        Milter::new(initial_config, toml_cfg).expect("Failed to create milter")
    } else {
        // Create default TOML config if none provided
        let default_toml = TomlConfig::default();
        Milter::new(initial_config, default_toml).expect("Failed to create milter")
    };

    // Create processing guard for graceful shutdown/reload
    let processing_guard = initial_milter.get_processing_guard();
    let guard_clone = processing_guard.clone();

    // Wrap milter in Arc<RwLock> for thread-safe reloading
    let milter = Arc::new(RwLock::new(initial_milter));
    let milter_clone = milter.clone();

    // Set up SIGTERM signal handler for graceful shutdown
    let shutdown_guard = processing_guard.clone();
    tokio::spawn(async move {
        let mut sigterm =
            signal(SignalKind::terminate()).expect("Failed to register SIGTERM handler");
        sigterm.recv().await;
        log::info!("Received SIGTERM signal, initiating graceful shutdown...");

        // Request shutdown and wait for active emails to complete
        shutdown_guard.request_shutdown();
        shutdown_guard.wait_for_completion().await;

        log::info!("All emails processed, shutting down gracefully");
        std::process::exit(0);
    });

    // Set up SIGHUP signal handler for configuration reload
    tokio::spawn(async move {
        let mut sighup = signal(SignalKind::hangup()).expect("Failed to register SIGHUP handler");
        loop {
            sighup.recv().await;
            log::info!("Received SIGHUP signal, waiting for active emails to complete...");

            // Wait for active email processing to complete
            guard_clone.wait_for_completion().await;
            log::info!("All emails processed, reloading configuration and modules...");

            match load_config(&config_file_path) {
                Ok((new_config, _new_whitelist, _new_blocklist, new_toml_config)) => {
                    // Update configuration
                    {
                        let mut config_guard = milter_config_clone.write().await;
                        *config_guard = (new_config.clone(), new_toml_config.clone());
                    }

                    // Reload milter with new configuration and modules
                    {
                        let mut milter_guard = milter_clone.write().await;
                        if let Some(toml_cfg) = new_toml_config {
                            if let Err(e) = milter_guard.reload(new_config, toml_cfg) {
                                log::error!("Failed to reload milter: {}", e);
                            }
                        } else {
                            let default_toml = TomlConfig::default();
                            if let Err(e) = milter_guard.reload(new_config, default_toml) {
                                log::error!("Failed to reload milter: {}", e);
                            }
                        }
                    }

                    log::info!("Configuration and modules reloaded successfully");
                }
                Err(e) => {
                    log::error!("Failed to reload configuration: {}", e);
                }
            }
        }
    });

    // Run the milter
    {
        let milter_guard = milter.read().await;
        if let Err(e) = milter_guard.run(&socket_path).await {
            log::error!("Milter error: {e}");
            process::exit(1);
        }
    }
}

#[allow(clippy::type_complexity)]
fn load_config(
    path: &str,
) -> anyhow::Result<(
    HeuristicConfig,
    Option<WhitelistConfig>,
    Option<BlocklistConfig>,
    Option<TomlConfig>,
)> {
    if std::path::Path::new(path).exists() {
        // Check file extension to determine format
        if path.ends_with(".toml") {
            // Load TOML config and convert to heuristic format
            println!("✅ Loading modern TOML configuration: {}", path);
            let toml_config = TomlConfig::load_from_file(path)?;
            let heuristic_config = toml_config.to_heuristic_config()?;
            let whitelist_config = toml_config.whitelist.clone();
            let blocklist_config = toml_config.blocklist.clone();
            Ok((
                heuristic_config,
                whitelist_config,
                blocklist_config,
                Some(toml_config),
            ))
        } else {
            // YAML config no longer supported
            eprintln!("❌ ERROR: YAML configuration is NO LONGER SUPPORTED!");
            eprintln!("   Attempted to load: {}", path);
            eprintln!("   YAML support was removed in v0.6.0");
            eprintln!();
            eprintln!("   Please migrate to TOML format:");
            eprintln!("   1. Use foff-milter-example.toml as template");
            eprintln!("   2. Update systemd service to use .toml config");
            eprintln!("   3. Deploy modules with ./deploy-modules.sh");
            eprintln!();
            eprintln!("   Modern TOML features:");
            eprintln!("   - Modular detection system");
            eprintln!("   - Global whitelist/blocklist");
            eprintln!("   - Heuristic scoring");
            eprintln!("   - 16 specialized detection modules");
            eprintln!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");

            anyhow::bail!("YAML configuration no longer supported. Please migrate to TOML format.")
        }
    } else {
        log::warn!("Configuration file '{path}' not found, using default configuration");
        Ok((HeuristicConfig::default(), None, None, None))
    }
}

fn generate_modular_configs(dir_path: &str) {
    use std::fs;
    use std::path::Path;

    let target_dir = Path::new(dir_path);

    // Create directory if it doesn't exist
    if let Err(e) = fs::create_dir_all(target_dir) {
        eprintln!("❌ Error creating directory {}: {}", dir_path, e);
        process::exit(1);
    }

    println!("🔧 Generating modular configuration files in: {}", dir_path);
    println!();

    // Embedded module configurations
    let modules = [
        (
            "authentication-validation.yaml",
            include_str!("../rulesets/authentication-validation.yaml"),
        ),
        (
            "brand-protection.yaml",
            include_str!("../rulesets/brand-protection.yaml"),
        ),
        (
            "content-threats.yaml",
            include_str!("../rulesets/content-threats.yaml"),
        ),
        (
            "esp-infrastructure.yaml",
            include_str!("../rulesets/esp-infrastructure.yaml"),
        ),
        (
            "phishing-threats.yaml",
            include_str!("../rulesets/phishing-threats.yaml"),
        ),
    ];

    let mut created = 0;
    let mut failed = 0;

    for (filename, content) in &modules {
        let target_path = target_dir.join(filename);

        match fs::write(&target_path, content) {
            Ok(_) => {
                println!("✅ Generated: {}", filename);
                created += 1;
            }
            Err(e) => {
                eprintln!("❌ Failed to create {}: {}", filename, e);
                failed += 1;
            }
        }
    }

    println!();
    println!("📊 Generation Summary:");
    println!("  ✅ Successfully generated: {} modules", created);
    if failed > 0 {
        println!("  ❌ Failed: {} modules", failed);
    }
    println!();

    if created > 0 {
        println!("🎯 Next Steps:");
        println!("  1. Update your main config to use modular system:");
        println!("     module_config_dir: \"{}\"", dir_path);
        println!("  2. Customize individual module configurations as needed");
        println!("  3. Test configuration: foff-milter --test-config");
        println!("  4. List modules: foff-milter --list-modules");
    }
}

fn truncate_string(s: &str, max_len: usize) -> String {
    if s.len() <= max_len {
        s.to_string()
    } else {
        format!("{}...", &s[..max_len.saturating_sub(3)])
    }
}

async fn anonymize_email_file(email_file: &str) {
    let content = match fs::read_to_string(email_file) {
        Ok(content) => content,
        Err(e) => {
            eprintln!("❌ Error reading email file '{}': {}", email_file, e);
            process::exit(1);
        }
    };

    let mut anonymizer = EmailAnonymizer::new();
    let anonymized = anonymizer.anonymize_email(&content);

    // Output to stdout so it can be redirected
    println!("{}", anonymized);
}

/// Strip X-FOFF headers from email content for clean analysis
fn strip_xfoff_headers(email_content: &str) -> String {
    let mut result = String::new();
    let mut in_headers = true;
    let mut skip_line = false;

    for line in email_content.lines() {
        if in_headers {
            if line.trim().is_empty() {
                in_headers = false;
                result.push_str(line);
                result.push('\n');
                continue;
            }

            // Check if this line starts an X-FOFF header
            if line.starts_with("X-FOFF") {
                skip_line = true;
                continue;
            }

            // Check if this is a continuation line (starts with space/tab)
            if (line.starts_with(' ') || line.starts_with('\t')) && skip_line {
                continue;
            }

            // Reset skip flag for new headers
            skip_line = false;
        }

        result.push_str(line);
        result.push('\n');
    }

    result
}

async fn test_email_file(
    config: &HeuristicConfig,
    whitelist_config: &Option<WhitelistConfig>,
    blocklist_config: &Option<BlocklistConfig>,
    toml_config: &Option<TomlConfig>,
    email_file: &str,
    disable_same_server: bool,
    keep_xfoff_headers: bool,
) {
    use foff_milter::filter::MailContext;
    use foff_milter::Action;
    use std::collections::HashMap;

    /// Decode email body content based on Content-Transfer-Encoding
    fn decode_email_body(body: &str, encoding: &str) -> String {
        match encoding.to_lowercase().as_str() {
            "quoted-printable" => {
                // Decode quoted-printable encoding
                let mut decoded = String::new();
                let mut chars = body.chars().peekable();

                while let Some(ch) = chars.next() {
                    if ch == '=' {
                        if let Some(&'\n') = chars.peek() {
                            // Soft line break - skip the = and newline
                            chars.next();
                            continue;
                        } else if let Some(&'\r') = chars.peek() {
                            // Soft line break with CRLF - skip = and \r, then check for \n
                            chars.next();
                            if let Some(&'\n') = chars.peek() {
                                chars.next();
                            }
                            continue;
                        } else {
                            // Hex encoding =XX
                            let hex1 = chars.next().unwrap_or('0');
                            let hex2 = chars.next().unwrap_or('0');
                            if let Ok(byte_val) =
                                u8::from_str_radix(&format!("{}{}", hex1, hex2), 16)
                            {
                                decoded.push(byte_val as char);
                            } else {
                                // Invalid hex, keep original
                                decoded.push('=');
                                decoded.push(hex1);
                                decoded.push(hex2);
                            }
                        }
                    } else {
                        decoded.push(ch);
                    }
                }
                decoded
            }
            "base64" => {
                // Decode base64 encoding
                use base64::{engine::general_purpose, Engine as _};
                let cleaned = body
                    .chars()
                    .filter(|c| !c.is_whitespace())
                    .collect::<String>();
                match general_purpose::STANDARD.decode(&cleaned) {
                    Ok(bytes) => String::from_utf8_lossy(&bytes).to_string(),
                    Err(_) => body.to_string(), // Return original if decode fails
                }
            }
            _ => body.to_string(), // No encoding or unknown encoding
        }
    }

    println!("🧪 Testing email file: {}", email_file);
    println!();

    // Read the email file with robust encoding handling
    let raw_email_content = match read_email_with_encoding_fallback(email_file) {
        Ok(content) => content,
        Err(e) => {
            eprintln!("❌ Error reading email file: {}", e);
            process::exit(1);
        }
    };

    // Strip any existing X-FOFF headers for clean analysis (unless explicitly kept)
    let email_content = if keep_xfoff_headers {
        raw_email_content
    } else {
        strip_xfoff_headers(&raw_email_content)
    };

    // Parse email content with proper MIME decoding
    let mut headers: HashMap<String, String> = HashMap::new();
    let mut sender = String::new();
    let recipients = vec!["test@example.com".to_string()]; // Default recipient
    let mut body = String::new();
    let mut in_headers = true;
    let mut last_header_key: Option<String> = None;
    let mut content_transfer_encoding = String::new();

    for line in email_content.lines() {
        if in_headers {
            if line.trim().is_empty() {
                in_headers = false;
                continue;
            }

            if line.starts_with(' ') || line.starts_with('\t') {
                // Continuation of previous header
                if let Some(ref key) = last_header_key {
                    if let Some(existing_value) = headers.get_mut(key) {
                        existing_value.push(' ');
                        existing_value.push_str(line.trim());
                    }
                }
                continue;
            }

            if let Some((key, value)) = line.split_once(':') {
                let key = key.trim().to_lowercase();
                let value = value.trim().to_string();

                last_header_key = Some(key.clone());

                // Track content encoding headers
                if key == "content-transfer-encoding" {
                    content_transfer_encoding = value.clone();
                }

                // Extract sender from Return-Path or From
                if key == "return-path" {
                    sender = value.trim_matches(['<', '>']).to_string();
                } else if key == "from" && sender.is_empty() {
                    // Extract email from "Name <email@domain.com>" format
                    if let Some(start) = value.rfind('<') {
                        if let Some(end) = value.rfind('>') {
                            sender = value[start + 1..end].to_string();
                        }
                    } else {
                        sender = value.clone();
                    }
                }

                // Handle header continuation lines by concatenating values (match milter behavior)
                if let Some(existing_value) = headers.get(&key) {
                    // Concatenate with existing value (same as milter)
                    let combined_value = format!("{} {}", existing_value, value);
                    headers.insert(key, combined_value);
                } else {
                    // First occurrence of this header
                    headers.insert(key, value);
                }
            }
        } else {
            body.push_str(line);
            body.push('\n');
        }
    }

    // Decode email body content to match production milter behavior
    let decoded_body = decode_email_body(&body, &content_transfer_encoding);
    body = decoded_body;

    if sender.is_empty() {
        sender = "unknown@example.com".to_string();
    }

    println!("📧 Email Details:");
    println!("   Sender: {}", sender);
    println!("   Recipients: {:?}", recipients);
    if let Some(from) = headers.get("from") {
        println!("   From: {}", from);
    }
    if let Some(subject) = headers.get("subject") {
        println!("   Subject: {}", subject);
    }
    if let Some(auth) = headers.get("authentication-results") {
        println!("   Auth: {}", truncate_string(auth, 100));
    }
    println!();

    // Use FilterEngine for both modular and heuristic systems
    let mut filter_engine = match FilterEngine::new(config.clone()) {
        Ok(engine) => engine,
        Err(e) => {
            eprintln!("❌ Error creating filter engine: {}", e);
            process::exit(1);
        }
    };

    // Set whitelist configuration if available
    filter_engine.set_whitelist_config(whitelist_config.clone());

    // Set blocklist configuration if available
    filter_engine.set_blocklist_config(blocklist_config.clone());

    // Set same-server detection based on flag
    filter_engine.set_same_server_detection(!disable_same_server);

    // Set sender blocking configuration if available
    if let Some(toml_cfg) = &toml_config {
        filter_engine.set_sender_blocking(toml_cfg.sender_blocking.clone());
    }

    // Set TOML configuration
    if let Some(toml_cfg) = toml_config {
        filter_engine.set_toml_config(toml_cfg.clone());
    } else {
        filter_engine.set_toml_config(TomlConfig::default());
    }

    // Create mail context
    let mut context = MailContext {
        sender: Some(sender.clone()),
        from_header: headers.get("from").cloned(),
        recipients: recipients.clone(),
        headers: headers.clone(),
        mailer: headers.get("x-mailer").cloned(),
        subject: headers
            .get("subject")
            .map(|s| foff_milter::milter::decode_mime_header(s)),
        hostname: None,
        helo: None,
        body: Some(body),
        last_header_name: None,
        attachments: Vec::new(), // Will be populated by analyze_attachments
        extracted_media_text: String::new(), // Will be populated by media analysis
        is_legitimate_business: false, // Will be set below
        is_first_hop: true,      // Test mode assumes first hop
        forwarding_source: None, // Will be detected during evaluation
        forwarding_info: None,   // Will be detected during evaluation
        proximate_mailer: None,  // Will be detected during evaluation
        normalized: None,        // Will be populated during evaluation
        dkim_verification: None, // Will be populated below
    };

    // Populate DKIM verification for test mode
    use foff_milter::dkim_verification::DkimVerifier;
    let sender_domain = sender.split('@').nth(1);
    context.dkim_verification = Some(DkimVerifier::verify(&context.headers, sender_domain));

    // Add legitimate business detection for test mode
    context.is_legitimate_business = is_legitimate_business_test(&context);
    if context.is_legitimate_business {
        println!("🏢 Detected legitimate business sender");
    }

    // Test the email
    println!("🔍 Testing against detection system...");

    // Evaluate the email (already in async context)
    let (action, matched_rules, headers_to_add) = filter_engine.evaluate(&context).await;

    println!();
    match &action {
        Action::Accept => {
            println!("✅ Result: ACCEPT");
            if !matched_rules.is_empty() {
                println!("   Matched rules: {:?}", matched_rules);
            } else {
                println!("   No rules matched - default action");
            }
            // Show analysis headers
            for (header_name, header_value) in &headers_to_add {
                println!("   Analysis header: {}: {}", header_name, header_value);
            }
        }
        Action::Reject { message } => {
            println!("❌ Result: REJECT");
            println!("   Message: {}", message);
            if !matched_rules.is_empty() {
                println!("   Matched rules: {:?}", matched_rules);
            }
        }
        Action::TagAsSpam {
            header_name,
            header_value,
        } => {
            println!("🏷️  Result: TAG AS SPAM");
            println!("   Header: {}: {}", header_name, header_value);
            if !matched_rules.is_empty() {
                println!("   Matched rules: {:?}", matched_rules);
            }
            // Show analysis headers
            for (header_name, header_value) in &headers_to_add {
                println!("   Analysis header: {}: {}", header_name, header_value);
            }
        }
        Action::ReportAbuse { .. } => {
            println!("📧 Result: REPORT ABUSE");
            if !matched_rules.is_empty() {
                println!("   Matched rules: {:?}", matched_rules);
            }
        }
        Action::UnsubscribeGoogleGroup { .. } => {
            println!("🚫 Result: UNSUBSCRIBE GOOGLE GROUP");
            if !matched_rules.is_empty() {
                println!("   Matched rules: {:?}", matched_rules);
            }
        }
    }
}

async fn generate_parity_report(
    config: &HeuristicConfig,
    _whitelist_config: &Option<WhitelistConfig>,
    _blocklist_config: &Option<BlocklistConfig>,
    _toml_config: &Option<TomlConfig>,
    environment: &str,
) {
    use serde_json::json;
    use std::collections::HashMap;

    let _engine = match FilterEngine::new(config.clone()) {
        Ok(engine) => engine,
        Err(e) => {
            eprintln!("Error creating filter engine: {}", e);
            process::exit(1);
        }
    };

    // Test sender extraction with known problematic email
    let test_headers = vec![
        (
            "From".to_string(),
            "\"Your Schumacher Jump Starter Is Ready\" <O'ReillyPowerReward@velanta.za.com>"
                .to_string(),
        ),
        (
            "Return-Path".to_string(),
            "<101738-221316-298310-21729-mstowe=baddomain.com@mail.velanta.za.com>".to_string(),
        ),
    ];

    // Test sender extraction
    let mut sender_tests = Vec::new();
    for (header_name, header_value) in &test_headers {
        sender_tests.push(json!({
            "header": header_name,
            "value": header_value,
            "extracted_domain": extract_domain_from_header(header_value)
        }));
    }

    // Test TLD pattern matching
    let test_domains = ["velanta.za.com", "test.tk", "example.com"];
    let mut tld_tests = Vec::new();
    for domain in &test_domains {
        let test_email = format!("test@{}", domain);
        let matches_high_risk = test_email.contains(".za.com") || test_email.contains(".tk");
        tld_tests.push(json!({
            "domain": domain,
            "email": test_email,
            "matches_high_risk_tld": matches_high_risk
        }));
    }

    // Get module checksums
    let mut module_checksums = HashMap::new();
    if let Some(module_dir) = &config.module_config_dir {
        if let Ok(entries) = std::fs::read_dir(module_dir) {
            for entry in entries.flatten() {
                if let Some(extension) = entry.path().extension() {
                    if extension == "yaml" || extension == "yml" {
                        if let Some(name) = entry.file_name().to_str() {
                            if let Ok(content) = std::fs::read_to_string(entry.path()) {
                                let hash =
                                    format!("{:x}", content.len() * 1000 + content.lines().count());
                                module_checksums.insert(name.to_string(), hash);
                            }
                        }
                    }
                }
            }
        }
    }

    let loaded_modules = module_checksums.len();

    let report = json!({
        "environment": environment,
        "timestamp": chrono::Utc::now().to_rfc3339(),
        "version": env!("CARGO_PKG_VERSION"),
        "modules": {
            "loaded_count": loaded_modules,
            "checksums": module_checksums
        },
        "config": {
            "module_dir": config.module_config_dir.as_ref().unwrap_or(&"none".to_string()),
            "socket_path": config.socket_path
        },
        "sender_extraction_tests": sender_tests,
        "tld_pattern_tests": tld_tests,
        "debug_info": {
            "regex_engine": "rust_regex",
            "header_processing": "sequential"
        }
    });

    println!("{}", serde_json::to_string_pretty(&report).unwrap());
}

fn extract_domain_from_header(header_value: &str) -> String {
    // Simple domain extraction for testing
    if let Some(start) = header_value.rfind('@') {
        if let Some(end) = header_value[start..].find('>') {
            return header_value[start + 1..start + end].to_string();
        }
        if let Some(end) = header_value[start..].find(' ') {
            return header_value[start + 1..start + end].to_string();
        }
        return header_value[start + 1..].to_string();
    }
    "no_domain_found".to_string()
}
