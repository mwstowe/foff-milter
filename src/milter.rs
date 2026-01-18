use crate::filter::{FilterEngine, MailContext};
use crate::heuristic_config::{Action, Config};
use crate::statistics::{StatEvent, StatisticsCollector};
use base64::Engine;
use indymilter::{run, Actions, Callbacks, Config as IndyConfig, ContextActions, Status};
use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::net::UnixListener;

pub fn is_legitimate_business_sender(context: &MailContext) -> bool {
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
        "wolfermans.com",
        "wolfermans-email.com",
        "creditkarma.com",
        "mail.creditkarma.com",
        "suncadia.com",
        "nextdoor.com",
        "ss.email.nextdoor.com",
        "homedepot.com",
        "lowes.com",
        "bestbuy.com",
        "macys.com",
        "nordstrom.com",
    ];

    if let Some(from_header) = &context.from_header {
        log::info!(
            "Checking business detection for From header: {}",
            from_header
        );
        // Extract domain from From header
        if let Some(domain_start) = from_header.rfind('@') {
            let domain_part = &from_header[domain_start + 1..];
            let domain = domain_part.trim_end_matches('>').trim();
            log::info!("Extracted domain: {}", domain);

            // Special exclusion for onmicrosoft.com (compromised tenant domains)
            if domain.contains("onmicrosoft.com") {
                log::info!("Excluded onmicrosoft.com domain");
                return false;
            }

            // Check for business match: exact, subdomain, or contains (for complex domains like Adobe Campaign)
            let is_business = legitimate_businesses.iter().any(|business| {
                domain == *business
                    || domain.ends_with(&format!(".{}", business))
                    || domain.contains(business)
            });

            log::info!("Is legitimate business: {}", is_business);
            return is_business;
        }
    }

    log::info!("No From header found or no @ in header");
    false
}

/// Guards against shutdown/reload during email processing
#[derive(Clone)]
pub struct ProcessingGuard {
    active_emails: Arc<AtomicUsize>,
    shutdown_requested: Arc<AtomicBool>,
}

impl Default for ProcessingGuard {
    fn default() -> Self {
        Self::new()
    }
}

impl ProcessingGuard {
    pub fn new() -> Self {
        Self {
            active_emails: Arc::new(AtomicUsize::new(0)),
            shutdown_requested: Arc::new(AtomicBool::new(false)),
        }
    }

    /// Start processing an email, returns None if shutdown requested
    pub fn start_email_processing(&self) -> Option<EmailToken> {
        if self.shutdown_requested.load(Ordering::Acquire) {
            return None; // Reject new emails during shutdown
        }
        self.active_emails.fetch_add(1, Ordering::AcqRel);
        Some(EmailToken {
            guard: self.clone(),
        })
    }

    /// Wait for all active emails to complete processing
    pub async fn wait_for_completion(&self) {
        while self.active_emails.load(Ordering::Acquire) > 0 {
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    }

    /// Request graceful shutdown
    pub fn request_shutdown(&self) {
        self.shutdown_requested.store(true, Ordering::Release);
    }

    /// Check if shutdown was requested
    pub fn is_shutdown_requested(&self) -> bool {
        self.shutdown_requested.load(Ordering::Acquire)
    }
}

/// Token that tracks email processing lifetime
pub struct EmailToken {
    guard: ProcessingGuard,
}

impl Drop for EmailToken {
    fn drop(&mut self) {
        self.guard.active_emails.fetch_sub(1, Ordering::AcqRel);
    }
}

/// Decode MIME-encoded header values like =?utf-8?B?...?= or =?utf-8?Q?...?=
pub fn decode_mime_header(header_value: &str) -> String {
    let mut result = String::new();
    let mut remaining = header_value;
    let mut last_was_encoded = false;

    while let Some(start) = remaining.find("=?") {
        // Add any text before the encoded part (but skip whitespace between adjacent encoded-words per RFC 2047)
        let before_text = &remaining[..start];
        if !last_was_encoded || !before_text.trim().is_empty() {
            result.push_str(before_text);
        }

        if let Some(end) = remaining[start..].find("?=") {
            let encoded_part = &remaining[start..start + end + 2];

            // Parse =?charset?encoding?data?=
            let parts: Vec<&str> = encoded_part[2..encoded_part.len() - 2].split('?').collect();
            if parts.len() == 3 {
                let _charset = parts[0];
                let encoding = parts[1].to_uppercase();
                let data = parts[2];

                match encoding.as_str() {
                    "B" => {
                        // Base64 decode
                        if let Ok(decoded_bytes) =
                            base64::engine::general_purpose::STANDARD.decode(data)
                        {
                            if let Ok(decoded_str) = String::from_utf8(decoded_bytes) {
                                result.push_str(&decoded_str);
                                last_was_encoded = true;
                            } else {
                                result.push_str(encoded_part); // Fallback to original
                                last_was_encoded = false;
                            }
                        } else {
                            result.push_str(encoded_part); // Fallback to original
                            last_was_encoded = false;
                        }
                    }
                    "Q" => {
                        // Quoted-printable decode (simplified)
                        let decoded = data
                            .replace('_', " ")
                            .replace("=20", " ")
                            .replace("=3D", "=");
                        result.push_str(&decoded);
                        last_was_encoded = true;
                    }
                    _ => {
                        result.push_str(encoded_part); // Unknown encoding, keep original
                        last_was_encoded = false;
                    }
                }
            } else {
                result.push_str(encoded_part); // Malformed, keep original
                last_was_encoded = false;
            }

            remaining = &remaining[start + end + 2..];
        } else {
            // No closing ?=, add rest and break
            result.push_str(remaining);
            break;
        }
    }

    // Add any remaining text
    result.push_str(remaining);
    result.trim().to_string()
}

/// Extract email address from a header value like "Name <email@domain.com>" or "email@domain.com"
pub fn extract_email_from_header(header_value: &str) -> Option<String> {
    // First decode any MIME encoding
    let decoded = decode_mime_header(header_value);

    let email = if let Some(start) = decoded.find('<') {
        if let Some(end) = decoded.find('>') {
            if start < end {
                decoded[start + 1..end].to_string()
            } else {
                // Malformed - < appears after >
                return None;
            }
        } else {
            // Malformed - no closing >
            return None;
        }
    } else if decoded.contains('@') {
        // If no angle brackets, assume the whole thing is an email
        decoded.trim().to_string()
    } else {
        return None;
    };

    // Clean up the email address - remove SMTP artifacts
    let cleaned_email = email
        .split_whitespace() // Remove whitespace
        .next()? // Take first part
        .split('>') // Remove > characters
        .next()?
        .split(',') // Remove comma-separated parameters
        .next()?
        .split(';') // Remove semicolon-separated parameters
        .next()?
        .trim(); // Final cleanup

    // Basic email validation
    if cleaned_email.contains('@') && cleaned_email.len() < 320 {
        // RFC 5321 limit
        // Additional validation - email should only contain valid characters
        if cleaned_email.chars().all(|c| {
            c.is_ascii_alphanumeric() || c == '@' || c == '.' || c == '-' || c == '_' || c == '+'
        }) {
            return Some(cleaned_email.to_lowercase());
        }
    }

    None
}
pub struct Milter {
    engine: Arc<FilterEngine>,
    statistics: Option<Arc<StatisticsCollector>>,
    processing_guard: ProcessingGuard,
}

// Simple state storage with unique session IDs
type StateMap = Arc<Mutex<HashMap<String, MailContext>>>;
static SESSION_COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

impl Milter {
    pub fn new(
        config: Config,
        toml_config: crate::toml_config::TomlConfig,
    ) -> anyhow::Result<Self> {
        let mut engine = FilterEngine::new(config.clone())?;
        engine.set_toml_config(toml_config);
        let engine = Arc::new(engine);

        // Check if modules were loaded and warn if not
        if config.module_config_dir.is_none() {
            log::error!(
                "🚨 PRODUCTION WARNING: Milter started without module directory configured!"
            );
            log::error!("🚨 Email security is severely compromised - only heuristic rules active!");
            eprintln!("🚨 PRODUCTION WARNING: Milter started without module directory configured!");
            eprintln!("🚨 Email security is severely compromised - only heuristic rules active!");
        } else if let Some(module_dir) = &config.module_config_dir {
            // Check if the directory exists and has modules
            if let Ok(entries) = std::fs::read_dir(module_dir) {
                let yaml_count = entries
                    .filter_map(|e| e.ok())
                    .filter(|e| {
                        e.path()
                            .extension()
                            .is_some_and(|ext| ext == "yaml" || ext == "yml")
                    })
                    .count();

                if yaml_count == 0 {
                    log::error!(
                        "🚨 PRODUCTION WARNING: Module directory '{}' contains no YAML files!",
                        module_dir
                    );
                    log::error!("🚨 Email security is severely compromised!");
                    eprintln!(
                        "🚨 PRODUCTION WARNING: Module directory '{}' contains no YAML files!",
                        module_dir
                    );
                    eprintln!("🚨 Email security is severely compromised!");
                }
            }
        }

        // Create statistics collector if enabled
        let statistics = if let Some(stats_config) = &config.statistics {
            if stats_config.enabled {
                let collector = StatisticsCollector::new(
                    stats_config.database_path.clone(),
                    stats_config.flush_interval_seconds.unwrap_or(60),
                )?;
                Some(Arc::new(collector))
            } else {
                None
            }
        } else {
            None
        };

        Ok(Milter {
            engine,
            statistics,
            processing_guard: ProcessingGuard::new(),
        })
    }

    pub fn get_processing_guard(&self) -> ProcessingGuard {
        self.processing_guard.clone()
    }

    pub fn reload(
        &mut self,
        config: Config,
        toml_config: crate::toml_config::TomlConfig,
    ) -> anyhow::Result<()> {
        log::info!("Reloading milter configuration and modules...");

        // Reload config data
        if let Err(e) = crate::config_loader::ConfigLoader::reload() {
            log::warn!("Failed to reload config data: {}", e);
        }

        // Create new engine with updated configuration
        let mut new_engine = FilterEngine::new(config.clone())?;
        new_engine.set_toml_config(toml_config);
        self.engine = Arc::new(new_engine);

        // Update statistics collector if configuration changed
        if let Some(stats_config) = &config.statistics {
            if stats_config.enabled {
                let collector = StatisticsCollector::new(
                    stats_config.database_path.clone(),
                    stats_config.flush_interval_seconds.unwrap_or(60),
                )?;
                self.statistics = Some(Arc::new(collector));
            } else {
                self.statistics = None;
            }
        } else {
            self.statistics = None;
        }

        log::info!(
            "Milter configuration, modules, config data, and features reloaded successfully"
        );
        Ok(())
    }

    pub async fn run(&self, socket_path: &str) -> anyhow::Result<()> {
        let instance_id = std::process::id();
        log::info!("Starting milter on: {socket_path} (PID: {instance_id})");
        // Remove existing socket if it exists
        if std::path::Path::new(socket_path).exists() {
            std::fs::remove_file(socket_path)?;
        }

        let listener = UnixListener::bind(socket_path)?;
        let engine = self.engine.clone();
        let state: StateMap = Arc::new(Mutex::new(HashMap::new()));

        // Create callbacks with explicit type annotation
        let callbacks: Callbacks<()> = Callbacks {
            connect: Some(Box::new({
                let state = state.clone();
                move |_ctx: &mut indymilter::Context<()>, hostname, _addr| {
                    let state = state.clone();
                    Box::pin(async move {
                        let hostname_str = hostname.to_string_lossy().to_string();
                        let session_id = format!(
                            "{}-{}",
                            hostname_str,
                            SESSION_COUNTER.fetch_add(1, std::sync::atomic::Ordering::SeqCst)
                        );
                        log::debug!("Connection from: {hostname_str} (session: {session_id})");
                        let mail_ctx = MailContext {
                            hostname: Some(hostname_str),
                            ..Default::default()
                        };
                        match state.lock() {
                            Ok(mut guard) => {
                                guard.insert(session_id, mail_ctx);
                            }
                            Err(e) => {
                                log::error!("Mutex poisoned in connect handler: {}", e);
                                return Status::Tempfail;
                            }
                        }
                        Status::Continue
                    })
                }
            })),

            mail: Some(Box::new({
                let state = state.clone();
                move |_ctx: &mut indymilter::Context<()>, sender| {
                    let state = state.clone();
                    Box::pin(async move {
                        let sender_str = sender
                            .iter()
                            .map(|s| s.to_string_lossy())
                            .collect::<Vec<_>>()
                            .join(",");
                        log::debug!("Mail from: {sender_str}");
                        // Update the most recent context (by highest session number)
                        match state.lock() {
                            Ok(mut guard) => {
                                if let Some((_, mail_ctx)) =
                                    guard.iter_mut().max_by_key(|(k, _)| {
                                        k.split('-')
                                            .next_back()
                                            .and_then(|s| s.parse::<u64>().ok())
                                            .unwrap_or(0)
                                    })
                                {
                                    mail_ctx.sender = Some(sender_str);
                                }
                            }
                            Err(e) => {
                                log::error!("Mutex poisoned in mail handler: {}", e);
                                return Status::Tempfail;
                            }
                        }
                        Status::Continue
                    })
                }
            })),

            rcpt: Some(Box::new({
                let state = state.clone();
                move |_ctx: &mut indymilter::Context<()>, recipient| {
                    let state = state.clone();
                    Box::pin(async move {
                        let recipient_str = recipient
                            .iter()
                            .map(|s| s.to_string_lossy())
                            .collect::<Vec<_>>()
                            .join(",");
                        log::debug!("Rcpt to: {recipient_str}");
                        // Update the most recent context (by highest session number)
                        match state.lock() {
                            Ok(mut guard) => {
                                if let Some((_, mail_ctx)) =
                                    guard.iter_mut().max_by_key(|(k, _)| {
                                        k.split('-')
                                            .next_back()
                                            .and_then(|s| s.parse::<u64>().ok())
                                            .unwrap_or(0)
                                    })
                                {
                                    mail_ctx.recipients.push(recipient_str);
                                }
                            }
                            Err(e) => {
                                log::error!("Mutex poisoned in rcpt handler: {}", e);
                                return Status::Tempfail;
                            }
                        }
                        Status::Continue
                    })
                }
            })),

            header: Some(Box::new({
                let state = state.clone();
                move |_ctx: &mut indymilter::Context<()>, name, value| {
                    let state = state.clone();
                    Box::pin(async move {
                        let name_str = name.to_string_lossy().to_string();
                        let value_str = value.to_string_lossy().to_string();
                        log::debug!("Header: {name_str}: {value_str}");

                        // Special debug logging for Authentication-Results
                        if name_str.to_lowercase() == "authentication-results" {
                            log::error!("CRITICAL: Authentication-Results header received: '{name_str}: {value_str}'");
                        }

                        // Update the most recent context (by highest session number)
                        match state.lock() {
                            Ok(mut guard) => {
                                if let Some((_, mail_ctx)) =
                                    guard.iter_mut().max_by_key(|(k, _)| {
                                        k.split('-')
                                            .next_back()
                                            .and_then(|s| s.parse::<u64>().ok())
                                            .unwrap_or(0)
                                    })
                                {
                                    // Store important headers
                                    match name_str.to_lowercase().as_str() {
                                        "subject" => {
                                            // Decode MIME-encoded subject before storing
                                            let decoded_subject = decode_mime_header(&value_str);
                                            mail_ctx.subject = Some(decoded_subject);
                                        }
                                        "x-mailer" | "user-agent" => {
                                            mail_ctx.mailer = Some(value_str.clone());
                                        }
                                        "from" => {
                                            // Extract email address from From header
                                            if let Some(email) =
                                                extract_email_from_header(&value_str)
                                            {
                                                mail_ctx.from_header = Some(email);
                                            }
                                        }
                                        _ => {}
                                    }

                                    // Handle header continuation lines properly (RFC 2822)
                                    if name_str.is_empty() {
                                        // This is a continuation line (starts with whitespace)
                                        if let Some(last_header) = &mail_ctx.last_header_name {
                                            if let Some(existing_value) =
                                                mail_ctx.headers.get(last_header)
                                            {
                                                let combined_value =
                                                    format!("{}{}", existing_value, value_str);
                                                log::debug!(
                                            "Header continuation: appending '{}' to '{}' = '{}'",
                                            value_str,
                                            existing_value,
                                            combined_value
                                        );
                                                mail_ctx
                                                    .headers
                                                    .insert(last_header.clone(), combined_value);
                                            }
                                        }
                                    } else {
                                        // Regular header
                                        let header_key = name_str.to_lowercase();
                                        log::debug!("Header: '{}': '{}'", header_key, value_str);
                                        mail_ctx.headers.insert(header_key.clone(), value_str);
                                        mail_ctx.last_header_name = Some(header_key);
                                    }
                                }
                            }
                            Err(e) => {
                                log::error!("Mutex poisoned in header handler: {}", e);
                                return Status::Tempfail;
                            }
                        }
                        Status::Continue
                    })
                }
            })),

            body: Some(Box::new({
                let state = state.clone();
                move |_ctx: &mut indymilter::Context<()>, body_chunk| {
                    let state = state.clone();
                    Box::pin(async move {
                        let body_str = String::from_utf8_lossy(&body_chunk);
                        // Update the most recent context (by highest session number)
                        match state.lock() {
                            Ok(mut guard) => {
                                if let Some((_, mail_ctx)) =
                                    guard.iter_mut().max_by_key(|(k, _)| {
                                        k.split('-')
                                            .next_back()
                                            .and_then(|s| s.parse::<u64>().ok())
                                            .unwrap_or(0)
                                    })
                                {
                                    match &mut mail_ctx.body {
                                        Some(existing_body) => {
                                            existing_body.push_str(&body_str);
                                        }
                                        None => {
                                            mail_ctx.body = Some(body_str.to_string());
                                        }
                                    }
                                }
                            }
                            Err(e) => {
                                log::error!("Mutex poisoned in body handler: {}", e);
                                return Status::Tempfail;
                            }
                        }
                        Status::Continue
                    })
                }
            })),

            eom: Some(Box::new({
                let engine = engine.clone();
                let state = state.clone();
                let statistics = self.statistics.clone();
                let processing_guard = self.processing_guard.clone();
                move |ctx: &mut indymilter::EomContext<()>| {
                    let engine = engine.clone();
                    let state = state.clone();
                    let statistics = statistics.clone();
                    let processing_guard = processing_guard.clone();
                    Box::pin(async move {
                        log::debug!("EOM callback invoked");

                        // Start email processing with guard protection
                        let _email_token = match processing_guard.start_email_processing() {
                            Some(token) => token,
                            None => {
                                log::info!("Rejecting email due to shutdown in progress");
                                return Status::Tempfail;
                            }
                        };
                        // Token will automatically decrement counter when dropped

                        // Intelligent DKIM completion detection
                        let mail_ctx_for_check = state
                            .lock()
                            .unwrap()
                            .iter()
                            .max_by_key(|(k, _)| k.parse::<u32>().unwrap_or(0))
                            .map(|(_, v)| v.clone());

                        if let Some(mail_ctx) = mail_ctx_for_check {
                            // Check if DKIM processing has started (DKIM-Filter header present)
                            if mail_ctx.headers.contains_key("dkim-filter")
                                || mail_ctx.headers.contains_key("dkim-signature")
                            {
                                // Wait for Authentication-Results header to appear (up to 500ms)
                                let mut attempts = 0;
                                let max_attempts = 10; // 10 attempts * 50ms = 500ms max

                                while attempts < max_attempts {
                                    let current_ctx = state
                                        .lock()
                                        .unwrap()
                                        .iter()
                                        .max_by_key(|(k, _)| k.parse::<u32>().unwrap_or(0))
                                        .map(|(_, v)| v.clone());

                                    if let Some(ctx) = current_ctx {
                                        if ctx.headers.contains_key("authentication-results") {
                                            log::debug!(
                                                "Authentication-Results header detected after {}ms",
                                                attempts * 50
                                            );
                                            break;
                                        }
                                    }

                                    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
                                    attempts += 1;
                                }

                                if attempts >= max_attempts {
                                    log::warn!("Timeout waiting for Authentication-Results header after DKIM processing started");
                                }
                            }
                        }

                        // Clone mail context to avoid holding mutex across await (get most recent by session number)
                        let mail_ctx_clone = state
                            .lock()
                            .unwrap()
                            .iter()
                            .max_by_key(|(k, _)| {
                                k.split('-')
                                    .next_back()
                                    .and_then(|s| s.parse::<u64>().ok())
                                    .unwrap_or(0)
                            })
                            .map(|(_, ctx)| ctx.clone());

                        if let Some(mut mail_ctx) = mail_ctx_clone {
                            // Add legitimate business detection
                            mail_ctx.is_legitimate_business =
                                is_legitimate_business_sender(&mail_ctx);
                            log::info!(
                                "Business detection result: {}",
                                mail_ctx.is_legitimate_business
                            );

                            let sender = mail_ctx.sender.as_deref().unwrap_or("<unknown>");
                            let recipients = if mail_ctx.recipients.is_empty() {
                                "<unknown>".to_string()
                            } else {
                                mail_ctx.recipients.join(", ")
                            };

                            let (action, matched_rules, headers_to_add) =
                                engine.evaluate(&mail_ctx).await;
                            log::debug!(
                                "PID {} evaluated action: {:?}, matched_rules: {:?}",
                                std::process::id(),
                                &action,
                                matched_rules
                            );

                            // Record statistics if enabled
                            if let Some(stats) = &statistics {
                                // Always record that an email was processed
                                stats.record_event(StatEvent::EmailProcessed);

                                // Record rule matches or no match
                                if matched_rules.is_empty() {
                                    stats.record_event(StatEvent::NoRuleMatch);
                                } else {
                                    // Record each matched rule
                                    for rule_name in &matched_rules {
                                        let action_str = match action {
                                            Action::Accept => "Accept",
                                            Action::Reject { .. } => "Reject",
                                            Action::TagAsSpam { .. } => "TagAsSpam",
                                            Action::ReportAbuse { .. } => "ReportAbuse",
                                            Action::UnsubscribeGoogleGroup { .. } => {
                                                "UnsubscribeGoogleGroup"
                                            }
                                        };
                                        stats.record_event(StatEvent::RuleMatch {
                                            rule_name: rule_name.clone(),
                                            action: action_str.to_string(),
                                            processing_time_ms: 0, // TODO: Add timing if needed
                                        });
                                    }
                                }
                            }

                            match &action {
                                Action::Reject { message } => {
                                    log::info!(
                                        "REJECT from={sender} to={recipients} reason={message}"
                                    );
                                    // Log to syslog for maillog visibility
                                    if syslog::init(
                                        syslog::Facility::LOG_MAIL,
                                        log::LevelFilter::Info,
                                        Some("foff-milter"),
                                    )
                                    .is_ok()
                                    {
                                        log::info!("REJECTED from={sender} to={recipients} reason={message}");
                                    }
                                    return Status::Reject;
                                }
                                Action::TagAsSpam {
                                    header_name,
                                    header_value,
                                } => {
                                    log::error!("CRITICAL: TagAsSpam action triggered! from={sender} to={recipients} header={header_name}:{header_value}");

                                    // Check if the header already exists to avoid duplicates
                                    let header_exists = mail_ctx.headers.iter().any(|(k, v)| {
                                        k.to_lowercase() == header_name.to_lowercase()
                                            && v == header_value
                                    });

                                    if header_exists {
                                        log::info!("Header {header_name}={header_value} already exists, skipping duplicate");
                                    } else {
                                        log::error!(
                                            "CRITICAL: Adding header: {header_name}={header_value}"
                                        );
                                        // Add the spam header
                                        if let Err(e) = ctx
                                            .actions
                                            .add_header(header_name.clone(), header_value.clone())
                                            .await
                                        {
                                            log::error!("Failed to add header: {e}");
                                        } else {
                                            log::error!("CRITICAL: Successfully added header: {header_name}={header_value}");
                                            // Log to syslog for maillog visibility
                                            if syslog::init(
                                                syslog::Facility::LOG_MAIL,
                                                log::LevelFilter::Info,
                                                Some("foff-milter"),
                                            )
                                            .is_ok()
                                            {
                                                log::info!("TAGGED from={sender} to={recipients} header={header_name}:{header_value}");
                                            }
                                        }
                                    }

                                    // Add analysis headers for spam emails too
                                    for (analysis_header_name, analysis_header_value) in
                                        &headers_to_add
                                    {
                                        log::info!(
                                            "Adding analysis header to spam: {analysis_header_name}={analysis_header_value}"
                                        );
                                        if let Err(e) = ctx
                                            .actions
                                            .add_header(
                                                analysis_header_name.clone(),
                                                analysis_header_value.clone(),
                                            )
                                            .await
                                        {
                                            log::error!(
                                                "Failed to add analysis header to spam: {e}"
                                            );
                                        } else {
                                            log::info!("Successfully added analysis header to spam: {analysis_header_name}={analysis_header_value}");
                                        }
                                    }

                                    return Status::Accept;
                                }
                                Action::ReportAbuse {
                                    service_provider,
                                    additional_action,
                                    include_headers,
                                    include_body,
                                    report_message,
                                } => {
                                    log::info!(
                                        "REPORT_ABUSE from={sender} to={recipients} provider={service_provider}"
                                    );

                                    // Report abuse to the service provider
                                    let include_hdrs = include_headers.unwrap_or(true);
                                    let include_bdy = include_body.unwrap_or(false);

                                    // Note: We can't easily access the FilterEngine from here in the milter context
                                    // For now, we'll log the abuse report details
                                    // In a production implementation, this would need to be refactored
                                    log::warn!("🚨 ABUSE REPORT NEEDED:");
                                    log::warn!("Service Provider: {service_provider}");
                                    log::warn!("Include Headers: {include_hdrs}");
                                    log::warn!("Include Body: {include_bdy}");
                                    if let Some(msg) = report_message {
                                        log::warn!("Custom Message: {msg}");
                                    }
                                    log::warn!("Email Details: from={sender} to={recipients}");
                                    if let Some(subject) = &mail_ctx.subject {
                                        log::warn!("Subject: {subject}");
                                    }

                                    // Handle additional action if specified
                                    if let Some(additional_act) = additional_action {
                                        log::info!(
                                            "Executing additional action after abuse report"
                                        );
                                        match additional_act.as_ref() {
                                            Action::Reject { message } => {
                                                log::info!(
                                                    "REJECT (after abuse report) from={sender} to={recipients} reason={message}"
                                                );
                                                return Status::Reject;
                                            }
                                            Action::TagAsSpam {
                                                header_name,
                                                header_value,
                                            } => {
                                                log::info!(
                                                    "TAG_AS_SPAM (after abuse report) from={sender} to={recipients} header={header_name}:{header_value}"
                                                );

                                                // Add the spam header
                                                if let Err(e) = ctx
                                                    .actions
                                                    .add_header(
                                                        header_name.clone(),
                                                        header_value.clone(),
                                                    )
                                                    .await
                                                {
                                                    log::error!("Failed to add header after abuse report: {e}");
                                                } else {
                                                    log::info!("Added header after abuse report: {header_name}={header_value}");
                                                }
                                                return Status::Accept;
                                            }
                                            Action::Accept => {
                                                log::info!("ACCEPT (after abuse report) from={sender} to={recipients}");
                                                return Status::Accept;
                                            }
                                            Action::ReportAbuse { .. } => {
                                                log::warn!("Nested ReportAbuse action not supported, treating as Accept");
                                                return Status::Accept;
                                            }
                                            Action::UnsubscribeGoogleGroup { .. } => {
                                                log::warn!("Nested UnsubscribeGoogleGroup action not supported, treating as Accept");
                                                return Status::Accept;
                                            }
                                        }
                                    } else {
                                        // No additional action, just accept the email after reporting
                                        log::info!("ACCEPT (after abuse report) from={sender} to={recipients}");
                                        return Status::Accept;
                                    }
                                }
                                Action::UnsubscribeGoogleGroup {
                                    additional_action,
                                    reason,
                                } => {
                                    log::info!(
                                        "UNSUBSCRIBE_GOOGLE_GROUP from={sender} to={recipients}"
                                    );

                                    // Perform Google Groups unsubscribe
                                    let unsubscriber = crate::google_groups_unsubscriber::GoogleGroupsUnsubscriber::new();

                                    // Extract Google Group information from headers
                                    if let Some(group_info) =
                                        unsubscriber.extract_group_info(&mail_ctx.headers)
                                    {
                                        log::info!(
                                            "Attempting to unsubscribe {} from Google Group ID: {:?}, Domain: {:?}",
                                            recipients,
                                            group_info.group_id,
                                            group_info.domain
                                        );

                                        // Attempt unsubscribe for each recipient
                                        for recipient in &mail_ctx.recipients {
                                            match tokio::runtime::Handle::try_current() {
                                                Ok(handle) => {
                                                    let unsubscriber_clone = crate::google_groups_unsubscriber::GoogleGroupsUnsubscriber::new();
                                                    let group_info_clone = group_info.clone();
                                                    let recipient_clone = recipient.clone();
                                                    let reason_clone = reason.clone();

                                                    handle.spawn(async move {
                                                        match unsubscriber_clone.unsubscribe(&group_info_clone, &recipient_clone, reason_clone.as_deref()).await {
                                                            Ok(result) => {
                                                                if result.success {
                                                                    log::info!("Successfully unsubscribed {recipient_clone} from Google Group");
                                                                } else {
                                                                    log::warn!("Failed to unsubscribe {} from Google Group: {:?}", recipient_clone, result.methods);
                                                                }
                                                            }
                                                            Err(e) => {
                                                                log::error!("Error unsubscribing {recipient_clone} from Google Group: {e}");
                                                            }
                                                        }
                                                    });
                                                }
                                                Err(_) => {
                                                    // No async runtime available, log for manual processing
                                                    log::warn!(
                                                        "No async runtime available for Google Groups unsubscribe, logging for manual processing: recipient={}, group_id={:?}",
                                                        recipient,
                                                        group_info.group_id
                                                    );
                                                }
                                            }
                                        }
                                    } else {
                                        log::warn!("Could not extract Google Group information from email headers");
                                    }

                                    // Handle additional action if specified
                                    if let Some(additional_act) = additional_action {
                                        log::info!(
                                            "Executing additional action after Google Groups unsubscribe: from={sender} to={recipients}"
                                        );
                                        match additional_act.as_ref() {
                                            Action::Reject { message } => {
                                                log::info!(
                                                    "REJECT (after unsubscribe) from={sender} to={recipients} reason={message}"
                                                );
                                                return Status::Reject;
                                            }
                                            Action::TagAsSpam {
                                                header_name,
                                                header_value,
                                            } => {
                                                log::info!(
                                                    "TAG (after unsubscribe) from={sender} to={recipients} header={header_name}:{header_value}"
                                                );
                                                if let Err(e) = ctx
                                                    .actions
                                                    .add_header(
                                                        header_name.clone(),
                                                        header_value.clone(),
                                                    )
                                                    .await
                                                {
                                                    log::error!("Failed to add header after unsubscribe: {e}");
                                                }
                                                return Status::Accept;
                                            }
                                            Action::Accept => {
                                                log::info!("ACCEPT (after unsubscribe) from={sender} to={recipients}");
                                                return Status::Accept;
                                            }
                                            Action::ReportAbuse { .. } => {
                                                log::warn!("Nested ReportAbuse action not supported after unsubscribe, treating as Accept");
                                                return Status::Accept;
                                            }
                                            Action::UnsubscribeGoogleGroup { .. } => {
                                                log::warn!("Nested UnsubscribeGoogleGroup action not supported, treating as Accept");
                                                return Status::Accept;
                                            }
                                        }
                                    } else {
                                        // No additional action, just accept the email after unsubscribing
                                        log::info!("ACCEPT (after unsubscribe) from={sender} to={recipients}");
                                        return Status::Accept;
                                    }
                                }
                                Action::Accept => {
                                    log::info!("ACCEPT from={sender} to={recipients}");

                                    // Add analysis headers if any
                                    for (header_name, header_value) in &headers_to_add {
                                        log::info!(
                                            "Adding analysis header: {header_name}={header_value}"
                                        );
                                        if let Err(e) = ctx
                                            .actions
                                            .add_header(header_name.clone(), header_value.clone())
                                            .await
                                        {
                                            log::error!("Failed to add analysis header: {e}");
                                        } else {
                                            log::info!("Successfully added analysis header: {header_name}={header_value}");
                                        }
                                    }

                                    return Status::Accept;
                                }
                            }
                        }

                        Status::Accept
                    })
                }
            })),

            ..Default::default()
        };

        // Configure indymilter to enable ADD_HEADER action
        let config = IndyConfig {
            actions: Actions::ADD_HEADER,
            ..Default::default()
        };

        run(listener, callbacks, config, tokio::signal::ctrl_c()).await?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_email_from_header() {
        // Normal cases
        assert_eq!(
            extract_email_from_header("user@example.com"),
            Some("user@example.com".to_string())
        );
        assert_eq!(
            extract_email_from_header("Name <user@example.com>"),
            Some("user@example.com".to_string())
        );
        assert_eq!(
            extract_email_from_header("\"Display Name\" <user@domain.org>"),
            Some("user@domain.org".to_string())
        );

        // Malformed cases that should be cleaned up
        assert_eq!(
            extract_email_from_header("user@auth0user.net>,body=8bitmime"),
            Some("user@auth0user.net".to_string())
        );
        assert_eq!(
            extract_email_from_header("user@domain.com,param=value"),
            Some("user@domain.com".to_string())
        );
        assert_eq!(
            extract_email_from_header("user@domain.com;param=value"),
            Some("user@domain.com".to_string())
        );
        assert_eq!(
            extract_email_from_header("user@domain.com extra stuff"),
            Some("user@domain.com".to_string())
        );
        assert_eq!(
            extract_email_from_header("<user@sendgrid.net>,body=8bitmime"),
            Some("user@sendgrid.net".to_string())
        );

        // Invalid cases
        assert_eq!(extract_email_from_header("invalid"), None);
        assert_eq!(extract_email_from_header("Name Only"), None);
        assert_eq!(extract_email_from_header(""), None);
        assert_eq!(extract_email_from_header("user@invalid_chars!"), None);
    }
}
