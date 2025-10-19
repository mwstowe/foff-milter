use crate::filter::{FilterEngine, MailContext};
use crate::legacy_config::{Action, Config};
use crate::statistics::{StatEvent, StatisticsCollector};
use base64::Engine;
use indymilter::{run, Actions, Callbacks, Config as IndyConfig, ContextActions, Status};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use tokio::net::UnixListener;

/// Decode MIME-encoded header values like =?utf-8?B?...?= or =?utf-8?Q?...?=
pub fn decode_mime_header(header_value: &str) -> String {
    let mut result = String::new();
    let mut remaining = header_value;

    while let Some(start) = remaining.find("=?") {
        // Add any text before the encoded part
        result.push_str(&remaining[..start]);

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
                            } else {
                                result.push_str(encoded_part); // Fallback to original
                            }
                        } else {
                            result.push_str(encoded_part); // Fallback to original
                        }
                    }
                    "Q" => {
                        // Quoted-printable decode (simplified)
                        let decoded = data
                            .replace('_', " ")
                            .replace("=20", " ")
                            .replace("=3D", "=");
                        result.push_str(&decoded);
                    }
                    _ => {
                        result.push_str(encoded_part); // Unknown encoding, keep original
                    }
                }
            } else {
                result.push_str(encoded_part); // Malformed, keep original
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
            decoded[start + 1..end].to_string()
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
}

// Simple state storage with unique session IDs
type StateMap = Arc<Mutex<HashMap<String, MailContext>>>;
static SESSION_COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

impl Milter {
    pub fn new(config: Config) -> anyhow::Result<Self> {
        let engine = Arc::new(FilterEngine::new(config.clone())?);

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

        Ok(Milter { engine, statistics })
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
                        state.lock().unwrap().insert(session_id, mail_ctx);
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
                        if let Some((_, mail_ctx)) =
                            state.lock().unwrap().iter_mut().max_by_key(|(k, _)| {
                                k.split('-')
                                    .next_back()
                                    .and_then(|s| s.parse::<u64>().ok())
                                    .unwrap_or(0)
                            })
                        {
                            mail_ctx.sender = Some(sender_str);
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
                        if let Some((_, mail_ctx)) =
                            state.lock().unwrap().iter_mut().max_by_key(|(k, _)| {
                                k.split('-')
                                    .next_back()
                                    .and_then(|s| s.parse::<u64>().ok())
                                    .unwrap_or(0)
                            })
                        {
                            mail_ctx.recipients.push(recipient_str);
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
                        if let Some((_, mail_ctx)) =
                            state.lock().unwrap().iter_mut().max_by_key(|(k, _)| {
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
                                    if let Some(email) = extract_email_from_header(&value_str) {
                                        mail_ctx.from_header = Some(email);
                                    }
                                }
                                _ => {}
                            }

                            // Handle header continuation lines by concatenating values
                            let header_key = name_str.to_lowercase();
                            if let Some(existing_value) = mail_ctx.headers.get(&header_key) {
                                // Concatenate with existing value (continuation line)
                                let combined_value = format!("{} {}", existing_value, value_str);
                                log::error!("CRITICAL: Concatenating header '{header_key}': '{existing_value}' + '{value_str}' = '{combined_value}'");
                                mail_ctx.headers.insert(header_key, combined_value);
                            } else {
                                // First occurrence of this header
                                log::error!("CRITICAL: First occurrence of header '{header_key}': '{value_str}'");
                                mail_ctx.headers.insert(header_key, value_str);
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
                        if let Some((_, mail_ctx)) =
                            state.lock().unwrap().iter_mut().max_by_key(|(k, _)| {
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
                        Status::Continue
                    })
                }
            })),

            eom: Some(Box::new({
                let engine = engine.clone();
                let state = state.clone();
                let statistics = self.statistics.clone();
                move |ctx: &mut indymilter::EomContext<()>| {
                    let engine = engine.clone();
                    let state = state.clone();
                    let statistics = statistics.clone();
                    Box::pin(async move {
                        log::debug!("EOM callback invoked");

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

                        if let Some(mail_ctx) = mail_ctx_clone {
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
                                action,
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

                            match action {
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

                                    // Check if X-FOFF-Rule-Matched header already exists with this rule
                                    if !matched_rules.is_empty() {
                                        let rule_header_value = matched_rules.join(", ");
                                        let rule_header_exists =
                                            mail_ctx.headers.iter().any(|(k, v)| {
                                                k.to_lowercase() == "x-foff-rule-matched"
                                                    && v == &rule_header_value
                                            });

                                        if rule_header_exists {
                                            log::info!("X-FOFF-Rule-Matched header with value '{rule_header_value}' already exists, skipping duplicate");
                                        } else if let Err(e) = ctx
                                            .actions
                                            .add_header(
                                                "X-FOFF-Rule-Matched".to_string(),
                                                rule_header_value.clone(),
                                            )
                                            .await
                                        {
                                            log::error!(
                                                "Failed to add X-FOFF-Rule-Matched header: {e}"
                                            );
                                        } else {
                                            log::info!("Added X-FOFF-Rule-Matched header: {rule_header_value}");
                                            // Log to syslog for maillog visibility
                                            if syslog::init(
                                                syslog::Facility::LOG_MAIL,
                                                log::LevelFilter::Info,
                                                Some("foff-milter"),
                                            )
                                            .is_ok()
                                            {
                                                log::info!("RULE_MATCHED from={sender} to={recipients} rules={rule_header_value}");
                                            }
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
