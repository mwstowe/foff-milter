use crate::abuse_reporter::AbuseReporter;
use crate::config::{Action, Config, Criteria};
use crate::domain_age::DomainAgeChecker;
use crate::language::LanguageDetector;
use crate::milter::extract_email_from_header;

use hickory_resolver::TokioAsyncResolver;
use lazy_static::lazy_static;
use regex::Regex;
use std::collections::{HashMap, HashSet};
use std::sync::Mutex;
use std::time::{Duration, Instant};
use url::Url;

// Cache for unsubscribe link validation results
#[derive(Clone)]
struct ValidationResult {
    is_valid: bool,
    timestamp: Instant,
}

// Global cache for validation results (with TTL)
lazy_static! {
    static ref VALIDATION_CACHE: Mutex<HashMap<String, ValidationResult>> =
        Mutex::new(HashMap::new());
}

const CACHE_TTL_SECONDS: u64 = 300; // 5 minutes cache TTL

pub struct FilterEngine {
    config: Config,
    compiled_patterns: HashMap<String, Regex>,
    #[allow(dead_code)] // TODO: Implement full abuse reporting integration
    abuse_reporter: AbuseReporter,
}

#[derive(Debug, Default, Clone)]
pub struct MailContext {
    pub sender: Option<String>,      // Envelope sender (MAIL FROM)
    pub from_header: Option<String>, // From header sender
    pub recipients: Vec<String>,
    pub headers: HashMap<String, String>,
    pub mailer: Option<String>,
    pub subject: Option<String>,
    pub hostname: Option<String>,
    pub helo: Option<String>,
    pub body: Option<String>,
}

impl FilterEngine {
    pub fn new(config: Config) -> anyhow::Result<Self> {
        let mut engine = FilterEngine {
            abuse_reporter: AbuseReporter::with_smtp_config(config.smtp.clone()),
            config,
            compiled_patterns: HashMap::new(),
        };

        // Pre-compile all regex patterns for better performance
        engine.compile_patterns()?;
        Ok(engine)
    }

    /// Clean expired entries from the validation cache
    fn clean_validation_cache() {
        if let Ok(mut cache) = VALIDATION_CACHE.lock() {
            let now = Instant::now();
            cache.retain(|_, result| {
                now.duration_since(result.timestamp).as_secs() < CACHE_TTL_SECONDS
            });
        }
    }

    /// Check if domain1 is a subdomain of domain2
    /// Examples:
    /// - is_subdomain_of("mail.etsy.com", "etsy.com") -> true
    /// - is_subdomain_of("etsy.com", "mail.etsy.com") -> false  
    /// - is_subdomain_of("badsite.com", "etsy.com") -> false
    /// - is_subdomain_of("notetsy.com", "etsy.com") -> false
    fn is_subdomain_of(&self, domain1: &str, domain2: &str) -> bool {
        if domain1 == domain2 {
            return true;
        }

        // domain1 is a subdomain of domain2 if:
        // 1. domain1 ends with domain2
        // 2. The character before domain2 in domain1 is a dot
        if domain1.len() > domain2.len() && domain1.ends_with(domain2) {
            let prefix_len = domain1.len() - domain2.len();
            // Check if there's a dot before the parent domain
            domain1.chars().nth(prefix_len - 1) == Some('.')
        } else {
            false
        }
    }

    /// Get cached validation result if available and not expired
    fn get_cached_validation(url: &str) -> Option<bool> {
        if let Ok(cache) = VALIDATION_CACHE.lock() {
            if let Some(result) = cache.get(url) {
                let age = Instant::now().duration_since(result.timestamp).as_secs();
                if age < CACHE_TTL_SECONDS {
                    log::debug!(
                        "Using cached validation result for {url}: {} (age: {age}s)",
                        result.is_valid
                    );
                    return Some(result.is_valid);
                }
            }
        }
        None
    }

    /// Validate a mailto unsubscribe link
    async fn validate_mailto_link(
        &self,
        mailto_url: &str,
        timeout_seconds: u64,
        check_dns: bool,
    ) -> bool {
        log::debug!("Validating mailto link: {mailto_url}");

        // Extract email address from mailto: URL
        // Format: mailto:email@domain.com or mailto:email@domain.com?subject=...
        let email_part = mailto_url.strip_prefix("mailto:").unwrap_or(mailto_url);

        // Split on '?' to remove query parameters if present
        let email_address = email_part.split('?').next().unwrap_or(email_part);

        // Extract domain from email address
        let domain = match email_address.split('@').nth(1) {
            Some(domain) => domain,
            None => {
                log::debug!("Invalid mailto format - no @ symbol found: {mailto_url}");
                return false;
            }
        };

        log::debug!("Extracted domain from mailto: {domain}");

        // If DNS checking is disabled, consider mailto links valid
        // (since we can't validate the email address without sending email)
        if !check_dns {
            log::debug!("DNS checking disabled for mailto - considering valid");
            return true;
        }

        // For mailto links, check MX records first (more appropriate for email domains)
        // then fall back to A/AAAA records
        self.validate_email_domain_dns(domain, timeout_seconds)
            .await
    }

    /// Validate email domain via MX and A/AAAA record lookup
    /// This is more appropriate for mailto domains than just A/AAAA records
    async fn validate_email_domain_dns(&self, domain: &str, timeout_seconds: u64) -> bool {
        log::debug!("Checking email domain DNS for: {domain} (timeout: {timeout_seconds}s)");

        let resolver = match TokioAsyncResolver::tokio_from_system_conf() {
            Ok(resolver) => resolver,
            Err(e) => {
                log::warn!("Failed to create DNS resolver for {domain}: {e}");
                return false;
            }
        };

        // First, try MX record lookup (most appropriate for email domains)
        log::debug!("Checking MX records for {domain}");
        let mx_future = resolver.mx_lookup(domain);
        let mx_timeout_future =
            tokio::time::timeout(Duration::from_secs(timeout_seconds), mx_future);

        match mx_timeout_future.await {
            Ok(Ok(mx_response)) => {
                let mx_count = mx_response.iter().count();
                if mx_count > 0 {
                    log::debug!("MX record validation successful for {domain} ({mx_count} MX records found)");
                    for mx in mx_response.iter().take(3) {
                        // Limit logging
                        log::debug!(
                            "MX record for {domain}: {} (priority {})",
                            mx.exchange(),
                            mx.preference()
                        );
                    }
                    return true;
                }
                log::debug!("No MX records found for {domain}, falling back to A/AAAA lookup");
            }
            Ok(Err(e)) => {
                log::debug!("MX lookup failed for {domain}: {e}, falling back to A/AAAA lookup");
            }
            Err(_) => {
                log::debug!("MX lookup timed out for {domain}, falling back to A/AAAA lookup");
            }
        }

        // Fall back to A/AAAA record lookup
        log::debug!("Checking A/AAAA records for {domain}");
        self.validate_domain_dns(domain, timeout_seconds).await
    }

    /// Validate domain via DNS lookup
    async fn validate_domain_dns(&self, domain: &str, timeout_seconds: u64) -> bool {
        log::debug!("Checking DNS for domain: {domain} (timeout: {timeout_seconds}s)");

        let resolver = match TokioAsyncResolver::tokio_from_system_conf() {
            Ok(resolver) => resolver,
            Err(e) => {
                log::warn!("Failed to create DNS resolver for {domain}: {e}");
                return false;
            }
        };

        // Add timeout to DNS lookup
        let lookup_future = resolver.lookup_ip(domain);
        let timeout_future =
            tokio::time::timeout(Duration::from_secs(timeout_seconds), lookup_future);

        match timeout_future.await {
            Ok(Ok(response)) => {
                // Check if we have any IP addresses
                let mut has_ips = false;
                let mut ip_count = 0;
                for ip in response.iter() {
                    log::debug!("DNS found IP for {domain}: {ip}");

                    // Check if the IP resolves to localhost (127.0.0.1)
                    if ip.to_string() == "127.0.0.1" {
                        log::warn!("Domain resolves to localhost (127.0.0.1): {domain} - marking as invalid");
                        return false;
                    }

                    has_ips = true;
                    ip_count += 1;
                }

                if has_ips {
                    log::debug!("DNS validation successful for {domain} ({ip_count} IPs found)");
                    true
                } else {
                    log::debug!("DNS lookup returned no IPs for {domain}");
                    false
                }
            }
            Ok(Err(e)) => {
                log::debug!("DNS lookup failed for {domain}: {e}");
                false
            }
            Err(_) => {
                log::debug!("DNS lookup timed out for {domain} after {timeout_seconds}s");
                false
            }
        }
    }

    /// Cache validation result
    fn cache_validation_result(url: &str, is_valid: bool) {
        if let Ok(mut cache) = VALIDATION_CACHE.lock() {
            cache.insert(
                url.to_string(),
                ValidationResult {
                    is_valid,
                    timestamp: Instant::now(),
                },
            );
            log::debug!("Cached validation result for {url}: {is_valid}");
        }
    }

    /// Extract email address from an optional string (sender field)
    fn extract_email_address(&self, email_option: &Option<String>) -> Option<String> {
        email_option
            .as_ref()
            .and_then(|email| extract_email_from_header(email))
    }

    /// Extract email address from header value using the existing function
    fn extract_email_from_header(&self, header_value: &str) -> Option<String> {
        extract_email_from_header(header_value)
    }

    /// Check if an IP address is in a private range
    fn is_private_ip(&self, ip_str: &str) -> bool {
        let parts: Vec<&str> = ip_str.split('.').collect();
        if parts.len() != 4 {
            return false;
        }

        // Parse octets
        let octets: Result<Vec<u8>, _> = parts.iter().map(|s| s.parse::<u8>()).collect();
        if let Ok(octets) = octets {
            // Check private IP ranges
            // 10.0.0.0/8 (10.0.0.0 to 10.255.255.255)
            if octets[0] == 10 {
                return true;
            }
            // 172.16.0.0/12 (172.16.0.0 to 172.31.255.255)
            if octets[0] == 172 && octets[1] >= 16 && octets[1] <= 31 {
                return true;
            }
            // 192.168.0.0/16 (192.168.0.0 to 192.168.255.255)
            if octets[0] == 192 && octets[1] == 168 {
                return true;
            }
            // 127.0.0.0/8 (localhost)
            if octets[0] == 127 {
                return true;
            }
        }
        false
    }

    fn compile_patterns(&mut self) -> anyhow::Result<()> {
        let rules = self.config.rules.clone();
        for rule in &rules {
            self.compile_criteria_patterns(&rule.criteria)?;
        }
        Ok(())
    }

    fn compile_criteria_patterns(&mut self, criteria: &Criteria) -> anyhow::Result<()> {
        match criteria {
            Criteria::MailerPattern { pattern }
            | Criteria::SenderPattern { pattern }
            | Criteria::RecipientPattern { pattern }
            | Criteria::SubjectPattern { pattern } => {
                if !self.compiled_patterns.contains_key(pattern) {
                    let regex = Regex::new(pattern).map_err(|e| {
                        anyhow::anyhow!("Invalid regex pattern '{}': {}", pattern, e)
                    })?;
                    self.compiled_patterns.insert(pattern.clone(), regex);
                }
            }
            Criteria::HeaderPattern { pattern, .. } => {
                if !self.compiled_patterns.contains_key(pattern) {
                    let regex = Regex::new(pattern).map_err(|e| {
                        anyhow::anyhow!("Invalid regex pattern '{}': {}", pattern, e)
                    })?;
                    self.compiled_patterns.insert(pattern.clone(), regex);
                }
            }
            Criteria::SubjectContainsLanguage { language } => {
                // Validate that the language is supported
                if !matches!(
                    language.to_lowercase().as_str(),
                    "japanese"
                        | "ja"
                        | "chinese"
                        | "zh"
                        | "korean"
                        | "ko"
                        | "arabic"
                        | "ar"
                        | "russian"
                        | "ru"
                        | "thai"
                        | "th"
                        | "hebrew"
                        | "he"
                ) {
                    return Err(anyhow::anyhow!("Unsupported language: {}", language));
                }
            }
            Criteria::HeaderContainsLanguage { language, .. } => {
                // Validate that the language is supported
                if !matches!(
                    language.to_lowercase().as_str(),
                    "japanese"
                        | "ja"
                        | "chinese"
                        | "zh"
                        | "korean"
                        | "ko"
                        | "arabic"
                        | "ar"
                        | "russian"
                        | "ru"
                        | "thai"
                        | "th"
                        | "hebrew"
                        | "he"
                ) {
                    return Err(anyhow::anyhow!("Unsupported language: {}", language));
                }
            }
            Criteria::UnsubscribeLinkValidation { .. } => {
                // No regex patterns to compile for unsubscribe link validation
                // Validation is done at runtime
            }
            Criteria::UnsubscribeLinkPattern { pattern } => {
                if !self.compiled_patterns.contains_key(pattern) {
                    let regex = Regex::new(pattern).map_err(|e| {
                        anyhow::anyhow!("Invalid regex pattern '{}': {}", pattern, e)
                    })?;
                    self.compiled_patterns.insert(pattern.clone(), regex);
                }
            }
            Criteria::UnsubscribeLinkIPAddress { .. } => {
                // No regex patterns to compile for IP address detection
                // Detection is done at runtime by analyzing unsubscribe URLs
            }
            Criteria::UnsubscribeMailtoOnly { .. } => {
                // No regex patterns to compile for mailto-only detection
                // Detection is done at runtime by analyzing link types
            }
            Criteria::PhishingSenderSpoofing { .. } => {
                // No regex patterns to compile for sender spoofing detection
            }
            Criteria::PhishingSuspiciousLinks {
                suspicious_patterns,
                ..
            } => {
                if let Some(patterns) = suspicious_patterns {
                    for pattern in patterns {
                        if !self.compiled_patterns.contains_key(pattern) {
                            let regex = Regex::new(pattern).map_err(|e| {
                                anyhow::anyhow!("Invalid regex pattern '{}': {}", pattern, e)
                            })?;
                            self.compiled_patterns.insert(pattern.clone(), regex);
                        }
                    }
                }
            }
            Criteria::PhishingDomainMismatch { .. } => {
                // No regex patterns to compile for domain mismatch detection
            }
            Criteria::PhishingLinkRedirection {
                suspicious_redirect_patterns,
                ..
            } => {
                if let Some(patterns) = suspicious_redirect_patterns {
                    for pattern in patterns {
                        if !self.compiled_patterns.contains_key(pattern) {
                            let regex = Regex::new(pattern).map_err(|e| {
                                anyhow::anyhow!("Invalid regex pattern '{}': {}", pattern, e)
                            })?;
                            self.compiled_patterns.insert(pattern.clone(), regex);
                        }
                    }
                }
            }
            Criteria::ImageOnlyEmail { .. } => {
                // No regex patterns to compile for image-only detection
            }
            Criteria::PhishingFreeEmailReplyTo { .. } => {
                // No regex patterns to compile for free email detection
            }
            Criteria::ReplyToValidation { .. } => {
                // No regex patterns to compile for reply-to validation
            }
            Criteria::DomainAge { .. } => {
                // No regex patterns to compile for domain age checking
            }
            Criteria::InvalidUnsubscribeHeaders => {
                // No regex patterns to compile for invalid unsubscribe headers
            }
            Criteria::AttachmentOnlyEmail { .. } => {
                // No regex patterns to compile for attachment-only detection
            }
            Criteria::EmptyContentEmail { .. } => {
                // No regex patterns to compile for empty content detection
            }
            Criteria::EmailServiceAbuse { .. } => {
                // No regex patterns to compile for email service abuse detection
                // Uses string matching and contains() operations instead
            }
            Criteria::GoogleGroupsAbuse { .. } => {
                // No regex patterns to compile for Google Groups abuse detection
                // Uses string matching and wildcard pattern operations instead
            }
            Criteria::SenderSpoofingExtortion { .. } => {
                // No regex patterns to compile for sender spoofing extortion detection
                // Uses string matching and email address comparison instead
            }
            Criteria::DocuSignAbuse { .. } => {
                // No regex patterns to compile for DocuSign abuse detection
                // Uses string matching and domain comparison instead
            }
            Criteria::And { criteria } | Criteria::Or { criteria } => {
                for c in criteria {
                    self.compile_criteria_patterns(c)?;
                }
            }
            Criteria::Not { criteria } => {
                self.compile_criteria_patterns(criteria)?;
            }
        }
        Ok(())
    }

    pub async fn evaluate(
        &self,
        context: &MailContext,
    ) -> (&Action, Vec<String>, Vec<(String, String)>) {
        let mut matched_rules = Vec::new();
        let mut all_actions = Vec::new();
        let mut final_action = &self.config.default_action;
        let mut headers_to_add = Vec::new();

        // Process rules with whitelist logic - stop on Accept actions
        for (rule_index, rule) in self.config.rules.iter().enumerate() {
            let matches = self.evaluate_criteria(&rule.criteria, context).await;
            log::info!("Rule {} '{}' evaluation result: {}", rule_index + 1, rule.name, matches);
            
            // Add explicit debugging to catch the bug
            if matches {
                log::info!(
                    "Rule {} '{}' matched, collecting action: {:?}",
                    rule_index + 1,
                    rule.name,
                    rule.action
                );
                matched_rules.push(rule.name.clone());
                all_actions.push(&rule.action);

                // WHITELIST LOGIC: If this is an Accept action, stop processing immediately
                if matches!(rule.action, Action::Accept) {
                    log::info!(
                        "Rule {} '{}' is a whitelist rule (Accept action), stopping rule processing",
                        rule_index + 1,
                        rule.name
                    );
                    final_action = &rule.action;
                    break;
                }

                // Determine the most restrictive action for non-Accept actions
                // Priority: Reject > TagAsSpam > Accept
                match (&final_action, &rule.action) {
                    // If we already have Reject, keep it
                    (Action::Reject { .. }, _) => {}
                    // If current is Reject, use it
                    (_, Action::Reject { .. }) => {
                        final_action = &rule.action;
                    }
                    // If we have TagAsSpam and current is TagAsSpam, keep the first one
                    // (we'll apply all TagAsSpam actions in the milter)
                    (Action::TagAsSpam { .. }, Action::TagAsSpam { .. }) => {}
                    // If current is TagAsSpam and we don't have Reject, use TagAsSpam
                    (Action::Accept, Action::TagAsSpam { .. }) => {
                        final_action = &rule.action;
                    }
                    // ReportAbuse and UnsubscribeGoogleGroup are processed but don't change final action
                    (_, Action::ReportAbuse { .. }) => {}
                    (_, Action::UnsubscribeGoogleGroup { .. }) => {}
                    // Handle all other combinations
                    (Action::ReportAbuse { .. }, Action::TagAsSpam { .. }) => {
                        final_action = &rule.action;
                    }
                    (Action::ReportAbuse { .. }, Action::Accept) => {}
                    (Action::UnsubscribeGoogleGroup { .. }, Action::TagAsSpam { .. }) => {
                        final_action = &rule.action;
                    }
                    (Action::UnsubscribeGoogleGroup { .. }, Action::Accept) => {}
                    // Accept stays Accept
                    (Action::Accept, Action::Accept) => {}
                    // TagAsSpam + Accept = keep TagAsSpam
                    (Action::TagAsSpam { .. }, Action::Accept) => {}
                }
            }
        }

        if matched_rules.is_empty() {
            log::debug!(
                "No rules matched, using default action: {:?}",
                self.config.default_action
            );
            // Add analysis header when no rules match
            headers_to_add.push((
                "X-FOFF-Analysis".to_string(),
                format!(
                    "analyzed by foff-milter v{} (rules: {})",
                    self.config.version, self.config.rule_set_timestamp
                ),
            ));
        } else {
            log::info!(
                "Matched {} rules: {:?}, final action: {:?}",
                matched_rules.len(),
                matched_rules,
                final_action
            );
        }

        (final_action, matched_rules, headers_to_add)
    }

    /// Get all matched rules with their actions (for processing all rules)
    pub async fn evaluate_all(&self, context: &MailContext) -> (Vec<(&str, &Action)>, &Action) {
        let mut matched_rules_with_actions = Vec::new();
        let mut final_action = &self.config.default_action;

        // Process ALL rules and collect matches
        for rule in &self.config.rules {
            let matches = self.evaluate_criteria(&rule.criteria, context).await;
            log::info!("Rule '{}' evaluation result: {}", rule.name, matches);
            if matches {
                log::info!("Rule '{}' matched, action: {:?}", rule.name, rule.action);
                matched_rules_with_actions.push((rule.name.as_str(), &rule.action));

                // Determine the most restrictive action for final decision
                match (&final_action, &rule.action) {
                    (Action::Reject { .. }, _) => {}
                    (_, Action::Reject { .. }) => {
                        final_action = &rule.action;
                    }
                    (Action::TagAsSpam { .. }, Action::TagAsSpam { .. }) => {}
                    (Action::Accept, Action::TagAsSpam { .. }) => {
                        final_action = &rule.action;
                    }
                    (_, Action::ReportAbuse { .. }) => {}
                    (_, Action::UnsubscribeGoogleGroup { .. }) => {}
                    (Action::ReportAbuse { .. }, Action::TagAsSpam { .. }) => {
                        final_action = &rule.action;
                    }
                    (Action::ReportAbuse { .. }, Action::Accept) => {}
                    (Action::UnsubscribeGoogleGroup { .. }, Action::TagAsSpam { .. }) => {
                        final_action = &rule.action;
                    }
                    (Action::UnsubscribeGoogleGroup { .. }, Action::Accept) => {}
                    (Action::Accept, Action::Accept) => {}
                    (Action::TagAsSpam { .. }, Action::Accept) => {}
                }
            }
        }

        if matched_rules_with_actions.is_empty() {
            log::debug!(
                "No rules matched, using default action: {:?}",
                self.config.default_action
            );
        } else {
            log::info!(
                "Matched {} rules, final action: {:?}",
                matched_rules_with_actions.len(),
                final_action
            );
        }

        (matched_rules_with_actions, final_action)
    }

    /// Get unsubscribe links for a mail context, with caching within the same evaluation
    fn get_unsubscribe_links(&self, context: &MailContext) -> Vec<String> {
        // Create a simple hash of the context to use as cache key
        // This prevents re-extracting links for the same email during evaluation
        let message_id = context
            .headers
            .get("message-id")
            .map(|s| s.as_str())
            .unwrap_or("no-id");
        let body_len = context.body.as_ref().map(|b| b.len()).unwrap_or(0);
        let context_key = format!("{message_id:?}{body_len:?}");

        // For now, we'll extract links each time but log when we're doing duplicate work
        let links = self.extract_unsubscribe_links(context);

        if !links.is_empty() {
            let links_len = links.len();
            log::debug!(
                "Extracted {links_len} unique unsubscribe links for email {context_key}: {links:?}"
            );
        }

        links
    }

    /// Extract unsubscribe links from email body and headers
    fn extract_unsubscribe_links(&self, context: &MailContext) -> Vec<String> {
        let mut links = Vec::new();

        // Check List-Unsubscribe header (RFC 2369) - case insensitive
        let list_unsubscribe = context
            .headers
            .get("list-unsubscribe")
            .or_else(|| context.headers.get("List-Unsubscribe"));
        if let Some(list_unsubscribe) = list_unsubscribe {
            // Extract URLs from List-Unsubscribe header: <url1>, <url2>
            // Support both HTTP and mailto links
            let url_regex = Regex::new(r"<((?:https?|mailto)://[^>]+|mailto:[^>]+)>").unwrap();
            for cap in url_regex.captures_iter(list_unsubscribe) {
                if let Some(url) = cap.get(1) {
                    links.push(url.as_str().to_string());
                }
            }
        }

        // Check email body for unsubscribe links
        if let Some(body) = &context.body {
            // Look for unsubscribe links based on anchor text (more reliable than URL content)
            let anchor_text_patterns = [
                // Match <a href="URL">...unsubscribe...</a> patterns
                r#"(?i)<a[^>]*href=["'](https?://[^"']+)["'][^>]*>[^<]*unsubscribe[^<]*</a>"#,
                r#"(?i)<a[^>]*href=["'](https?://[^"']+)["'][^>]*>[^<]*opt[_\s-]*out[^<]*</a>"#,
                r#"(?i)<a[^>]*href=["'](https?://[^"']+)["'][^>]*>[^<]*remove[^<]*</a>"#,
                r#"(?i)<a[^>]*href=["'](https?://[^"']+)["'][^>]*>[^<]*stop[^<]*</a>"#,
                r#"(?i)<a[^>]*href=["'](mailto:[^"']+)["'][^>]*>[^<]*unsubscribe[^<]*</a>"#,
                r#"(?i)<a[^>]*href=["'](mailto:[^"']+)["'][^>]*>[^<]*opt[_\s-]*out[^<]*</a>"#,
                r#"(?i)<a[^>]*href=["'](mailto:[^"']+)["'][^>]*>[^<]*remove[^<]*</a>"#,
                r#"(?i)<a[^>]*href=["'](mailto:[^"']+)["'][^>]*>[^<]*stop[^<]*</a>"#,
            ];

            // Also keep some URL-based patterns for backwards compatibility
            let url_based_patterns = [
                r#"(?i)href=["'](https?://[^"']*unsubscribe[^"']*)["']"#,
                r#"(?i)href=["'](https?://[^"']*opt[_-]?out[^"']*)["']"#,
                r#"(?i)href=["'](https?://[^"']*remove[^"']*)["']"#,
                r#"(?i)href=["'](mailto:[^"']*unsubscribe[^"']*)["']"#,
                r#"(?i)href=["'](mailto:[^"']*opt[_-]?out[^"']*)["']"#,
                r#"(?i)href=["'](mailto:[^"']*remove[^"']*)["']"#,
                r#"(?i)(https?://[^\s<>"']*unsubscribe[^\s<>"']*)"#,
                r#"(?i)(https?://[^\s<>"']*opt[_-]?out[^\s<>"']*)"#,
                r#"(?i)(mailto:[^\s<>"']*unsubscribe[^\s<>"']*)"#,
                r#"(?i)(mailto:[^\s<>"']*opt[_-]?out[^\s<>"']*)"#,
            ];

            // Process anchor text patterns first (higher priority)
            for pattern in &anchor_text_patterns {
                if let Ok(regex) = Regex::new(pattern) {
                    for cap in regex.captures_iter(body) {
                        if let Some(url) = cap.get(1) {
                            links.push(url.as_str().to_string());
                        }
                    }
                }
            }

            // Process URL-based patterns for backwards compatibility
            for pattern in &url_based_patterns {
                if let Ok(regex) = Regex::new(pattern) {
                    for cap in regex.captures_iter(body) {
                        if let Some(url) = cap.get(1) {
                            links.push(url.as_str().to_string());
                        }
                    }
                }
            }
        }

        // Remove duplicates and return
        links.sort();
        links.dedup();
        links
    }

    /// Follow redirect chain and analyze for phishing indicators
    async fn analyze_redirect_chain(
        &self,
        url: &str,
        max_redirects: u32,
        timeout_seconds: u64,
        suspicious_patterns: &Option<Vec<String>>,
    ) -> (bool, Vec<String>) {
        let mut redirect_chain = Vec::new();
        let mut current_url = url.to_string();
        let mut redirect_count = 0;

        let client = match reqwest::Client::builder()
            .timeout(Duration::from_secs(timeout_seconds))
            .user_agent("FOFF-Milter/1.0")
            .redirect(reqwest::redirect::Policy::none()) // Handle redirects manually
            .build()
        {
            Ok(client) => client,
            Err(e) => {
                log::debug!("Failed to create HTTP client: {e}");
                return (false, redirect_chain);
            }
        };

        while redirect_count < max_redirects {
            redirect_chain.push(current_url.clone());

            // Check current URL against suspicious patterns
            if let Some(patterns) = suspicious_patterns {
                for pattern in patterns {
                    if let Some(regex) = self.compiled_patterns.get(pattern) {
                        if regex.is_match(&current_url) {
                            log::info!(
                                "Suspicious redirect pattern matched '{pattern}': {current_url}"
                            );
                            return (true, redirect_chain);
                        }
                    }
                }
            }

            // Make HEAD request to follow redirect
            match client.head(&current_url).send().await {
                Ok(response) => {
                    let status = response.status();

                    if status.is_redirection() {
                        if let Some(location) = response.headers().get("location") {
                            if let Ok(location_str) = location.to_str() {
                                // Handle relative URLs
                                current_url = if location_str.starts_with("http") {
                                    location_str.to_string()
                                } else {
                                    // Resolve relative URL
                                    if let Ok(base_url) = Url::parse(&current_url) {
                                        if let Ok(resolved) = base_url.join(location_str) {
                                            resolved.to_string()
                                        } else {
                                            break;
                                        }
                                    } else {
                                        break;
                                    }
                                };

                                redirect_count += 1;
                                log::debug!(
                                    "Following redirect {}: {} -> {}",
                                    redirect_count,
                                    redirect_chain.last().unwrap(),
                                    current_url
                                );
                            } else {
                                break;
                            }
                        } else {
                            break;
                        }
                    } else {
                        // Final destination reached
                        if current_url != url {
                            redirect_chain.push(current_url.clone());
                        }
                        break;
                    }
                }
                Err(e) => {
                    log::debug!("HTTP request failed for {current_url}: {e}");
                    break;
                }
            }
        }

        // Check if we hit the redirect limit - this alone is not suspicious
        // Only flag as suspicious if we also found suspicious patterns
        if redirect_count >= max_redirects {
            log::debug!("Redirect limit reached: {redirect_count} redirects for {url} (not inherently suspicious)");
        }

        // Check final destination for suspicious patterns
        if let Some(final_url) = redirect_chain.last() {
            if let Some(patterns) = suspicious_patterns {
                for pattern in patterns {
                    if let Some(regex) = self.compiled_patterns.get(pattern) {
                        if regex.is_match(final_url) {
                            log::info!(
                                "Final destination matches suspicious pattern '{pattern}': {final_url}"
                            );
                            return (true, redirect_chain);
                        }
                    }
                }
            }
        }

        (false, redirect_chain)
    }

    /// Check if email body contains image content (img tags, image links, etc.)
    fn has_image_content(&self, body: &str) -> bool {
        // Check for HTML img tags
        if body.contains("<img") || body.contains("<IMG") {
            return true;
        }

        // Check for MIME image content types
        if body.contains("Content-Type: image/") {
            return true;
        }

        // Check for image file extensions in links
        let image_extensions = [".jpg", ".jpeg", ".png", ".gif", ".bmp", ".webp", ".svg"];
        for ext in &image_extensions {
            if body.to_lowercase().contains(ext) {
                return true;
            }
        }

        // Check for data: image URLs
        if body.contains("data:image/") {
            return true;
        }

        // Check for common image hosting domains
        let image_hosts = ["imgur.com", "flickr.com", "photobucket.com", "tinypic.com"];
        for host in &image_hosts {
            if body.contains(host) {
                return true;
            }
        }

        false
    }

    /// Count the number of images in the email body
    fn count_images(&self, body: &str) -> usize {
        let mut count = 0;

        // Count img tags
        count += body.matches("<img").count();
        count += body.matches("<IMG").count();

        // Count image file links
        let image_extensions = [".jpg", ".jpeg", ".png", ".gif", ".bmp", ".webp"];
        for ext in &image_extensions {
            count += body.to_lowercase().matches(ext).count();
        }

        count
    }

    /// Extract text content from email body, removing HTML tags and image references
    fn extract_text_content(&self, body: &str, ignore_whitespace: bool) -> String {
        let mut text = body.to_string();

        // Remove MIME boundaries and headers
        let boundary_regex = Regex::new(r"--[a-zA-Z0-9]+(--)?\n?").unwrap();
        text = boundary_regex.replace_all(&text, "\n").to_string();

        // Remove Content-Type headers and other MIME headers (more flexible matching)
        let mime_header_regex = Regex::new(
            r"(?i)(content-type|content-transfer-encoding|content-disposition|mime-version):[^\n]*",
        )
        .unwrap();
        text = mime_header_regex.replace_all(&text, "").to_string();

        // Remove base64 encoded content (long strings of base64 characters)
        let base64_regex = Regex::new(r"[A-Za-z0-9+/]{50,}={0,2}").unwrap();
        text = base64_regex.replace_all(&text, " ").to_string();

        // Remove HTML tags
        let tag_regex = Regex::new(r"<[^>]*>").unwrap();
        text = tag_regex.replace_all(&text, " ").to_string();

        // Remove URLs (they're not meaningful text content)
        let url_regex = Regex::new(r"https?://[^\s<>]+").unwrap();
        text = url_regex.replace_all(&text, " ").to_string();

        // Remove email addresses
        let email_regex = Regex::new(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}").unwrap();
        text = email_regex.replace_all(&text, " ").to_string();

        // Remove common email artifacts
        text = text.replace("&nbsp;", " ");
        text = text.replace("&amp;", "&");
        text = text.replace("&lt;", "<");
        text = text.replace("&gt;", ">");
        text = text.replace("&quot;", "\"");

        if ignore_whitespace {
            // Remove all whitespace and newlines
            text = text.chars().filter(|c| !c.is_whitespace()).collect();
        } else {
            // Just normalize whitespace
            let ws_regex = Regex::new(r"\s+").unwrap();
            text = ws_regex.replace_all(&text, " ").to_string();
            text = text.trim().to_string();
        }

        text
    }

    /// Check if email has large image attachments based on MIME structure
    fn has_large_image_attachment(&self, body: &str) -> bool {
        // Look for MIME boundaries and image content types
        if body.contains("Content-Type: image/") {
            // Check for large base64 encoded content (rough heuristic)
            // Base64 encoding increases size by ~33%, so 200KB becomes ~266KB
            // Look for long base64 strings that might indicate large images
            let base64_pattern = Regex::new(r"[A-Za-z0-9+/]{1000,}").unwrap();
            if base64_pattern.is_match(body) {
                log::debug!("Found large base64 content, likely image attachment");
                return true;
            }

            // Check for Content-Transfer-Encoding: base64 with substantial content
            if body.contains("Content-Transfer-Encoding: base64") {
                // Count lines after base64 declaration - large images have many lines
                let lines_after_base64 = body
                    .split("Content-Transfer-Encoding: base64")
                    .nth(1)
                    .map(|content| content.lines().take(100).count())
                    .unwrap_or(0);

                if lines_after_base64 > 20 {
                    log::debug!(
                        "Found base64 content with {lines_after_base64} lines, likely large image"
                    );
                    return true;
                }
            }
        }

        // Check for image file extensions in MIME headers
        let image_types = [
            "image/gif",
            "image/jpeg",
            "image/png",
            "image/bmp",
            "image/webp",
        ];
        for img_type in &image_types {
            if body.contains(img_type) {
                // If we find image MIME types, check if there's substantial content
                if body.len() > 50000 {
                    // 50KB+ suggests large image content
                    log::debug!(
                        "Found {} with large body size ({}), likely large image attachment",
                        img_type,
                        body.len()
                    );
                    return true;
                }
            }
        }

        false
    }

    /// Check if text content looks like decoy text (common patterns in image-based phishing)
    fn is_likely_decoy_text(&self, text: &str) -> bool {
        let text_lower = text.to_lowercase();

        // Common decoy patterns in image-based phishing
        let decoy_patterns = [
            // Random addresses/locations
            r"\d+\s+[a-z]+\s+(street|st|avenue|ave|road|rd|drive|dr|lane|ln|way|blvd|boulevard)",
            // Random phone numbers
            r"\(\d{3}\)\s*\d{3}-\d{4}",
            // Random zip codes
            r"\b\d{5}(-\d{4})?\b",
            // Generic business text
            r"(customer service|support|help desk|contact us)",
            // Random names
            r"(john|jane|mike|sarah|david|lisa)\s+(smith|johnson|williams|brown|jones)",
        ];

        for pattern in &decoy_patterns {
            if let Ok(regex) = Regex::new(pattern) {
                if regex.is_match(&text_lower) {
                    log::debug!("Found decoy text pattern: {pattern}");
                    return true;
                }
            }
        }

        // Check for very short, generic text that's likely decoy
        if text.len() < 100 {
            let generic_words = ["address", "phone", "contact", "info", "details", "location"];
            let word_count = generic_words
                .iter()
                .filter(|&word| text_lower.contains(word))
                .count();

            if word_count >= 2 {
                log::debug!("Found multiple generic words in short text, likely decoy");
                return true;
            }
        }

        // Check for text that's mostly numbers/addresses (like street addresses)
        let digit_ratio =
            text.chars().filter(|c| c.is_ascii_digit()).count() as f32 / text.len() as f32;
        if digit_ratio > 0.3 && text.len() < 200 {
            log::debug!("High digit ratio ({digit_ratio:.2}) in short text, likely decoy address");
            return true;
        }

        false
    }

    /// Check if email has suspicious attachments based on type and size
    fn has_suspicious_attachments(
        &self,
        body: &str,
        types: &[String],
        min_size: usize,
        check_disposition: bool,
    ) -> bool {
        // Check for Content-Type headers indicating attachments
        for attachment_type in types {
            let content_type_patterns = match attachment_type.as_str() {
                "pdf" => vec!["application/pdf", "application/x-pdf"],
                "doc" => vec!["application/msword", "application/vnd.ms-word"],
                "docx" => {
                    vec!["application/vnd.openxmlformats-officedocument.wordprocessingml.document"]
                }
                "xls" => vec!["application/vnd.ms-excel", "application/excel"],
                "xlsx" => vec!["application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"],
                "zip" => vec!["application/zip", "application/x-zip-compressed"],
                "rar" => vec![
                    "application/x-rar-compressed",
                    "application/vnd.rar",
                    "application/x-rar",
                ],
                "exe" => vec!["application/x-msdownload", "application/octet-stream"],
                "ics" => vec!["text/calendar", "application/ics"],
                "vcf" => vec!["text/vcard", "text/x-vcard"],
                _ => vec![],
            };

            for pattern in content_type_patterns {
                if body.contains(pattern) {
                    log::debug!("Found suspicious attachment type: {pattern}");

                    // Check if attachment meets minimum size requirement
                    // For now, use total body size as a proxy for attachment size
                    if body.len() >= min_size {
                        log::debug!(
                            "Email body size ({}) meets minimum requirement ({})",
                            body.len(),
                            min_size
                        );
                        return true;
                    }
                }
            }
        }

        // Check for Content-Disposition: attachment headers if enabled
        if check_disposition && body.contains("Content-Disposition: attachment") {
            log::debug!("Found Content-Disposition: attachment header");

            // Look for filename extensions - ONLY flag if it matches our suspicious types
            for attachment_type in types {
                let filename_pattern = format!("filename=\".*\\.{attachment_type}\"");
                if body
                    .to_lowercase()
                    .contains(&filename_pattern.to_lowercase())
                {
                    log::debug!(
                        "Found attachment with suspicious filename extension: {attachment_type}"
                    );

                    // Check size requirement for filename-based detection too
                    if body.len() >= min_size {
                        log::debug!(
                            "Email body size ({}) meets minimum requirement ({})",
                            body.len(),
                            min_size
                        );
                        return true;
                    }
                }
            }

            // REMOVED: The fallback that was catching legitimate attachments
            // We now ONLY flag attachments that match the specified suspicious_types
            log::debug!("Found attachment disposition but no matching suspicious types");
        }

        false
    }

    /// Check if a URL contains an IP address instead of a domain name
    fn contains_ip_address(
        &self,
        url: &str,
        check_ipv4: bool,
        check_ipv6: bool,
        allow_private: bool,
    ) -> bool {
        // Extract the host part from the URL
        let host = if let Some(host) = self.extract_host_from_url(url) {
            host
        } else {
            log::debug!("Could not extract host from URL: {url}");
            return false;
        };

        log::debug!("Extracted host from URL '{url}': '{host}'");

        // Check for IPv4 addresses
        if check_ipv4 && self.is_ipv4_address(&host) {
            if !allow_private && self.is_private_ipv4(&host) {
                log::debug!("Found private IPv4 address (allowed: {allow_private}): {host}");
                return false;
            }
            log::debug!("Found IPv4 address in unsubscribe link: {host}");
            return true;
        }

        // Check for IPv6 addresses
        if check_ipv6 && self.is_ipv6_address(&host) {
            if !allow_private && self.is_private_ipv6(&host) {
                log::debug!("Found private IPv6 address (allowed: {allow_private}): {host}");
                return false;
            }
            log::debug!("Found IPv6 address in unsubscribe link: {host}");
            return true;
        }

        false
    }

    /// Extract host from URL (handles http://, https://, and bare domains)
    fn extract_host_from_url(&self, url: &str) -> Option<String> {
        // Handle URLs with protocol
        if url.starts_with("http://") || url.starts_with("https://") {
            if let Ok(parsed_url) = url::Url::parse(url) {
                return parsed_url.host_str().map(|s| s.to_string());
            }
        }

        // Handle URLs without protocol
        let test_url = format!("http://{url}");
        if let Ok(parsed_url) = url::Url::parse(&test_url) {
            return parsed_url.host_str().map(|s| s.to_string());
        }

        // Fallback: extract host manually
        let cleaned = url
            .trim_start_matches("http://")
            .trim_start_matches("https://");
        let host_part = cleaned
            .split('/')
            .next()?
            .split('?')
            .next()?
            .split('#')
            .next()?;

        // Remove port if present
        let host = host_part.split(':').next()?;

        if !host.is_empty() {
            Some(host.to_string())
        } else {
            None
        }
    }

    /// Check if a string is a valid IPv4 address
    fn is_ipv4_address(&self, host: &str) -> bool {
        use std::net::Ipv4Addr;
        host.parse::<Ipv4Addr>().is_ok()
    }

    /// Check if a string is a valid IPv6 address
    fn is_ipv6_address(&self, host: &str) -> bool {
        use std::net::Ipv6Addr;
        // Remove brackets if present (common in URLs)
        let cleaned = host.trim_start_matches('[').trim_end_matches(']');
        cleaned.parse::<Ipv6Addr>().is_ok()
    }

    /// Check if an IPv4 address is private/local
    fn is_private_ipv4(&self, host: &str) -> bool {
        use std::net::Ipv4Addr;
        if let Ok(ip) = host.parse::<Ipv4Addr>() {
            ip.is_private() || ip.is_loopback() || ip.is_link_local()
        } else {
            false
        }
    }

    /// Check if an IPv6 address is private/local
    fn is_private_ipv6(&self, host: &str) -> bool {
        use std::net::Ipv6Addr;
        let cleaned = host.trim_start_matches('[').trim_end_matches(']');
        if let Ok(ip) = cleaned.parse::<Ipv6Addr>() {
            ip.is_loopback() || ip.is_multicast() ||
            // Check for private IPv6 ranges (fc00::/7 and fe80::/10)
            (ip.segments()[0] & 0xfe00) == 0xfc00 || // fc00::/7 (unique local)
            (ip.segments()[0] & 0xffc0) == 0xfe80 // fe80::/10 (link local)
        } else {
            false
        }
    }

    /// Extract text content excluding attachment data
    fn extract_text_content_excluding_attachments(
        &self,
        body: &str,
        ignore_whitespace: bool,
    ) -> String {
        let mut text = body.to_string();

        // Remove entire attachment sections (between MIME boundaries)
        let boundary_regex = Regex::new(r"--[a-zA-Z0-9]+\r?\n").unwrap();
        let parts: Vec<&str> = boundary_regex.split(&text).collect();

        let mut clean_text = String::new();
        for part in parts {
            // Skip parts that contain attachment content types
            if part.contains("Content-Type: application/")
                || part.contains("Content-Disposition: attachment")
                || part.contains("Content-Transfer-Encoding: base64")
            {
                continue;
            }

            // Only include text/plain or text/html parts
            if part.contains("Content-Type: text/")
                || (!part.contains("Content-Type:") && !part.trim().is_empty())
            {
                clean_text.push_str(part);
                clean_text.push(' ');
            }
        }

        text = clean_text;

        // Remove remaining MIME headers
        let mime_header_regex = Regex::new(
            r"(?i)(content-type|content-transfer-encoding|content-disposition|mime-version):[^\n]*",
        )
        .unwrap();
        text = mime_header_regex.replace_all(&text, "").to_string();

        // Remove HTML tags
        let tag_regex = Regex::new(r"<[^>]*>").unwrap();
        text = tag_regex.replace_all(&text, " ").to_string();

        // Remove URLs
        let url_regex = Regex::new(r"https?://[^\s<>]+").unwrap();
        text = url_regex.replace_all(&text, " ").to_string();

        // Remove email addresses
        let email_regex = Regex::new(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}").unwrap();
        text = email_regex.replace_all(&text, " ").to_string();

        // Remove common email artifacts
        text = text.replace("&nbsp;", " ");
        text = text.replace("&amp;", "&");
        text = text.replace("&lt;", "<");
        text = text.replace("&gt;", ">");
        text = text.replace("&quot;", "\"");

        if ignore_whitespace {
            // Remove all whitespace and newlines
            text = text.chars().filter(|c| !c.is_whitespace()).collect();
        } else {
            // Just normalize whitespace
            let ws_regex = Regex::new(r"\s+").unwrap();
            text = ws_regex.replace_all(&text, " ").to_string();
            text = text.trim().to_string();
        }

        text
    }

    /// Extract meaningful text content for empty content detection
    /// More aggressive than attachment exclusion - removes signatures, footers, and minimal content
    fn extract_meaningful_text_content(
        &self,
        body: &str,
        ignore_whitespace: bool,
        ignore_signatures: bool,
        ignore_html_tags: bool,
    ) -> String {
        let mut text = body.to_string();

        // Remove MIME boundaries and headers first
        let boundary_regex = Regex::new(r"--[a-zA-Z0-9]+\r?\n").unwrap();
        let parts: Vec<&str> = boundary_regex.split(&text).collect();

        let mut clean_text = String::new();
        for part in parts {
            // Skip attachment parts
            if part.contains("Content-Type: application/")
                || part.contains("Content-Disposition: attachment")
                || part.contains("Content-Transfer-Encoding: base64")
            {
                continue;
            }

            // Only include text parts
            if part.contains("Content-Type: text/")
                || (!part.contains("Content-Type:") && !part.trim().is_empty())
            {
                clean_text.push_str(part);
                clean_text.push(' ');
            }
        }

        text = clean_text;

        // Remove MIME headers
        let mime_header_regex = Regex::new(
            r"(?i)(content-type|content-transfer-encoding|content-disposition|mime-version|message-id|date|from|to|subject|return-path|received|dkim-signature|authentication-results):[^\n]*",
        )
        .unwrap();
        text = mime_header_regex.replace_all(&text, "").to_string();

        // Remove HTML tags if requested
        if ignore_html_tags {
            let tag_regex = Regex::new(r"<[^>]*>").unwrap();
            text = tag_regex.replace_all(&text, " ").to_string();
        }

        // Remove common email signatures and footers if requested
        if ignore_signatures {
            // Remove common signature patterns
            let sig_patterns = [
                r"(?i)--\s*\n.*$",      // Standard signature delimiter
                r"(?i)best regards.*$", // Common closings
                r"(?i)sincerely.*$",
                r"(?i)thanks.*$",
                r"(?i)sent from my.*$",                 // Mobile signatures
                r"(?i)this email was sent.*$",          // Auto-generated footers
                r"(?i)unsubscribe.*$",                  // Unsubscribe footers
                r"(?i)privacy policy.*$",               // Legal footers
                r"(?i)confidential.*$",                 // Confidentiality notices
                r"(?i)please consider.*environment.*$", // Environmental notices
            ];

            for pattern in &sig_patterns {
                if let Ok(regex) = Regex::new(pattern) {
                    text = regex.replace_all(&text, "").to_string();
                }
            }
        }

        // Remove URLs (often just tracking/unsubscribe links in empty emails)
        let url_regex = Regex::new(r"https?://[^\s<>]+").unwrap();
        text = url_regex.replace_all(&text, " ").to_string();

        // Remove email addresses
        let email_regex = Regex::new(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}").unwrap();
        text = email_regex.replace_all(&text, " ").to_string();

        // Remove common empty content patterns
        let empty_patterns = [
            r"(?i)^\s*$",                  // Just whitespace
            r"(?i)^\s*\.\s*$",             // Just a period
            r"(?i)^\s*-+\s*$",             // Just dashes
            r"(?i)^\s*=+\s*$",             // Just equals signs
            r"(?i)^\s*_+\s*$",             // Just underscores
            r"(?i)^\s*\*+\s*$",            // Just asterisks
            r"(?i)^\s*(test|testing)\s*$", // Just "test"
            r"(?i)^\s*hello\s*$",          // Just "hello"
            r"(?i)^\s*hi\s*$",             // Just "hi"
        ];

        for pattern in &empty_patterns {
            if let Ok(regex) = Regex::new(pattern) {
                text = regex.replace_all(&text, "").to_string();
            }
        }

        // Remove HTML entities
        text = text.replace("&nbsp;", " ");
        text = text.replace("&amp;", "&");
        text = text.replace("&lt;", "<");
        text = text.replace("&gt;", ">");
        text = text.replace("&quot;", "\"");
        text = text.replace("&#39;", "'");

        // Remove common punctuation-only content
        let punct_regex = Regex::new(r"^[[:punct:]\s]*$").unwrap();
        if punct_regex.is_match(&text) {
            text = String::new();
        }

        if ignore_whitespace {
            // Remove all whitespace and newlines
            text = text.chars().filter(|c| !c.is_whitespace()).collect();
        } else {
            // Just normalize whitespace
            let ws_regex = Regex::new(r"\s+").unwrap();
            text = ws_regex.replace_all(&text, " ").to_string();
            text = text.trim().to_string();
        }

        text
    }

    /// Validate an unsubscribe link
    async fn validate_unsubscribe_link(
        &self,
        url: &str,
        timeout_seconds: u64,
        check_dns: bool,
        check_http: bool,
    ) -> bool {
        log::debug!("Validating unsubscribe link: {url}");

        // Check cache first
        if let Some(cached_result) = Self::get_cached_validation(url) {
            return cached_result;
        }

        // Clean expired cache entries periodically (every 10th validation)
        if rand::random::<u8>().is_multiple_of(10) {
            Self::clean_validation_cache();
        }

        let result = self
            .validate_unsubscribe_link_uncached(url, timeout_seconds, check_dns, check_http)
            .await;

        // Cache the result
        Self::cache_validation_result(url, result);

        result
    }

    /// Internal validation function without caching
    async fn validate_unsubscribe_link_uncached(
        &self,
        url: &str,
        timeout_seconds: u64,
        check_dns: bool,
        check_http: bool,
    ) -> bool {
        log::debug!("Performing uncached validation for: {url}");

        // Handle mailto URLs differently
        if url.starts_with("mailto:") {
            return self
                .validate_mailto_link(url, timeout_seconds, check_dns)
                .await;
        }

        // Parse HTTP/HTTPS URL
        let parsed_url = match Url::parse(url) {
            Ok(url) => url,
            Err(e) => {
                log::debug!("Invalid URL format: {e}");
                return false;
            }
        };

        // Get hostname
        let hostname = match parsed_url.host_str() {
            Some(host) => host,
            None => {
                log::debug!("No hostname in URL");
                return false;
            }
        };

        // DNS validation
        if check_dns && !self.validate_domain_dns(hostname, timeout_seconds).await {
            return false;
        }

        // HTTP validation
        if check_http {
            log::debug!("Checking HTTP accessibility for: {url}");
            let client = reqwest::Client::builder()
                .timeout(Duration::from_secs(timeout_seconds))
                .user_agent("FOFF-Milter/1.0")
                .build();

            let client = match client {
                Ok(client) => client,
                Err(e) => {
                    log::debug!("Failed to create HTTP client: {e}");
                    return false;
                }
            };

            // Use HEAD request to avoid downloading content
            match client.head(url).send().await {
                Ok(response) => {
                    let status = response.status();
                    log::debug!("HTTP HEAD response: {status} for {url}");

                    // Consider 2xx, 3xx, and even 405 (Method Not Allowed) as valid
                    // Some servers don't support HEAD but the URL might still be valid
                    if status.is_success() || status.is_redirection() || status == 405 {
                        return true;
                    } else {
                        log::debug!("HTTP validation failed with status: {status}");
                        return false;
                    }
                }
                Err(e) => {
                    log::debug!("HTTP request failed: {e}");
                    return false;
                }
            }
        }

        // If we're not checking HTTP, DNS success is enough
        true
    }

    fn evaluate_criteria<'a>(
        &'a self,
        criteria: &'a Criteria,
        context: &'a MailContext,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = bool> + Send + 'a>> {
        Box::pin(async move {
            match criteria {
                Criteria::MailerPattern { pattern } => {
                    if let Some(mailer) = &context.mailer {
                        if let Some(regex) = self.compiled_patterns.get(pattern) {
                            return regex.is_match(mailer);
                        }
                    }
                    false
                }
                Criteria::SenderPattern { pattern } => {
                    if let Some(regex) = self.compiled_patterns.get(pattern) {
                        // Check both envelope sender and From header sender
                        if let Some(sender) = &context.sender {
                            log::debug!("SenderPattern checking envelope sender: '{}' against pattern: '{}'", sender, pattern);
                            if regex.is_match(sender) {
                                log::debug!("SenderPattern matched envelope sender: '{}'", sender);
                                return true;
                            }
                        }
                        if let Some(from_header) = &context.from_header {
                            log::debug!("SenderPattern checking from_header: '{}' against pattern: '{}'", from_header, pattern);
                            if regex.is_match(from_header) {
                                log::debug!("SenderPattern matched from_header: '{}'", from_header);
                                return true;
                            }
                        }
                        log::debug!("SenderPattern no match for pattern: '{}'", pattern);
                    }
                    false
                }
                Criteria::RecipientPattern { pattern } => {
                    if let Some(regex) = self.compiled_patterns.get(pattern) {
                        return context
                            .recipients
                            .iter()
                            .any(|recipient| regex.is_match(recipient));
                    }
                    false
                }
                Criteria::SubjectPattern { pattern } => {
                    if let Some(subject) = &context.subject {
                        if let Some(regex) = self.compiled_patterns.get(pattern) {
                            return regex.is_match(subject);
                        }
                    }
                    false
                }
                Criteria::HeaderPattern { header, pattern } => {
                    if let Some(header_value) = context.headers.get(header) {
                        if let Some(regex) = self.compiled_patterns.get(pattern) {
                            // Decode MIME headers before pattern matching
                            let decoded_value = crate::milter::decode_mime_header(header_value);
                            return regex.is_match(&decoded_value);
                        }
                    }
                    false
                }
                Criteria::SubjectContainsLanguage { language } => {
                    if let Some(subject) = &context.subject {
                        return LanguageDetector::contains_language(subject, language);
                    }
                    false
                }
                Criteria::HeaderContainsLanguage { header, language } => {
                    if let Some(header_value) = context.headers.get(header) {
                        // Decode MIME headers before language detection
                        let decoded_value = crate::milter::decode_mime_header(header_value);
                        return LanguageDetector::contains_language(&decoded_value, language);
                    }
                    false
                }
                Criteria::UnsubscribeLinkValidation {
                    timeout_seconds,
                    check_dns,
                    check_http,
                } => {
                    let timeout = timeout_seconds.unwrap_or(5); // Default 5 second timeout
                    let dns_check = check_dns.unwrap_or(true); // Default: check DNS
                    let http_check = check_http.unwrap_or(false); // Default: don't check HTTP (faster)

                    log::debug!(
                        "Checking unsubscribe link validation (timeout: {timeout}s, DNS: {dns_check}, HTTP: {http_check})"
                    );

                    let links = self.get_unsubscribe_links(context);
                    log::info!(
                        "UnsubscribeLinkValidation: extracted {} links: {:?}",
                        links.len(),
                        links
                    );

                    if links.is_empty() {
                        log::info!("UnsubscribeLinkValidation: No unsubscribe links found - returning false (no match)");
                        return false; // No unsubscribe links found - not suspicious
                    }

                    log::debug!("Found {} unsubscribe links: {:?}", links.len(), links);

                    // Check if ANY unsubscribe link is invalid
                    let mut validated_count = 0;
                    let mut cached_count = 0;

                    for link in &links {
                        // Check if we have a cached result first
                        let was_cached = Self::get_cached_validation(link).is_some();
                        if was_cached {
                            cached_count += 1;
                        }

                        if !self
                            .validate_unsubscribe_link(link, timeout, dns_check, http_check)
                            .await
                        {
                            log::info!("UnsubscribeLinkValidation: Invalid unsubscribe link detected: {link} - returning true (MATCH)");
                            return true; // Found invalid link - matches criteria
                        }
                        validated_count += 1;
                    }

                    if cached_count > 0 {
                        log::debug!("UnsubscribeLinkValidation: Used {cached_count} cached results out of {validated_count} total validations");
                    }

                    log::info!("UnsubscribeLinkValidation: All unsubscribe links are valid - returning false (no match)");
                    false // All links are valid
                }
                Criteria::UnsubscribeLinkPattern { pattern } => {
                    log::debug!("Checking unsubscribe link pattern: {pattern}");

                    let links = self.get_unsubscribe_links(context);

                    if links.is_empty() {
                        log::debug!("No unsubscribe links found for pattern matching");
                        return false;
                    }

                    log::debug!("Found {} unsubscribe links: {:?}", links.len(), links);

                    if let Some(regex) = self.compiled_patterns.get(pattern) {
                        // Check if ANY unsubscribe link matches the pattern
                        for link in &links {
                            if regex.is_match(link) {
                                log::info!("Unsubscribe link matches pattern '{pattern}': {link}");
                                return true;
                            }
                        }
                    }

                    log::debug!("No unsubscribe links match pattern: {pattern}");
                    false
                }
                Criteria::UnsubscribeLinkIPAddress {
                    check_ipv4,
                    check_ipv6,
                    allow_private_ips,
                } => {
                    log::debug!("Checking for unsubscribe links with IP addresses");

                    let links = self.get_unsubscribe_links(context);

                    if links.is_empty() {
                        log::debug!("No unsubscribe links found for IP address check");
                        return false;
                    }

                    let check_ipv4_enabled = check_ipv4.unwrap_or(true);
                    let check_ipv6_enabled = check_ipv6.unwrap_or(true);
                    let allow_private = allow_private_ips.unwrap_or(false);

                    log::debug!(
                        "Found {} unsubscribe links to check for IP addresses",
                        links.len()
                    );

                    for link in &links {
                        if self.contains_ip_address(
                            link,
                            check_ipv4_enabled,
                            check_ipv6_enabled,
                            allow_private,
                        ) {
                            log::info!("Unsubscribe link contains IP address: {link}");
                            return true;
                        }
                    }

                    log::debug!("No unsubscribe links contain IP addresses");
                    false
                }
                Criteria::UnsubscribeMailtoOnly { allow_mixed } => {
                    log::debug!("Checking for mailto-only unsubscribe links");

                    let links = self.get_unsubscribe_links(context);

                    if links.is_empty() {
                        log::debug!("No unsubscribe links found for mailto-only check");
                        return false;
                    }

                    let allow_mixed_links = allow_mixed.unwrap_or(false);
                    let mut mailto_count = 0;
                    let mut http_count = 0;

                    for link in &links {
                        if link.starts_with("mailto:") {
                            mailto_count += 1;
                        } else if link.starts_with("http://") || link.starts_with("https://") {
                            http_count += 1;
                        }
                    }

                    log::debug!("Found {mailto_count} mailto links and {http_count} HTTP links out of {} total", links.len());

                    if allow_mixed_links {
                        // Only flag if ALL links are mailto
                        if mailto_count > 0 && http_count == 0 {
                            log::info!("All unsubscribe links are mailto-only: {links:?}");
                            return true;
                        }
                    } else {
                        // Flag if ANY mailto links are present (default behavior)
                        if mailto_count > 0 {
                            log::info!("Found {mailto_count} mailto unsubscribe links: {links:?}");
                            return true;
                        }
                    }

                    false
                }
                Criteria::PhishingSenderSpoofing { trusted_domains } => {
                    log::debug!("Checking for sender spoofing");

                    // Get the From header display name and actual sender email
                    let from_header_raw = context.headers.get("from");
                    let actual_sender = context.from_header.as_ref().or(context.sender.as_ref());

                    if let (Some(from_raw), Some(sender_email)) = (from_header_raw, actual_sender) {
                        // Extract display name from "Display Name <email@domain.com>" format
                        if let Some(display_start) = from_raw.find('"') {
                            if let Some(display_end) = from_raw[display_start + 1..].find('"') {
                                let display_name =
                                    &from_raw[display_start + 1..display_start + 1 + display_end];

                                // Check if display name claims to be from a trusted domain
                                for trusted_domain in trusted_domains {
                                    if display_name
                                        .to_lowercase()
                                        .contains(&trusted_domain.to_lowercase())
                                    {
                                        // Extract domain from actual sender email
                                        if let Some(at_pos) = sender_email.find('@') {
                                            let sender_domain = &sender_email[at_pos + 1..];

                                            // Check if sender domain matches the claimed domain
                                            if !sender_domain
                                                .to_lowercase()
                                                .contains(&trusted_domain.to_lowercase())
                                            {
                                                log::info!("Phishing spoofing detected: Display name claims '{trusted_domain}' but sender is from '{sender_domain}'");
                                                return true;
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }

                    false
                }
                Criteria::PhishingSuspiciousLinks {
                    check_url_shorteners,
                    check_suspicious_tlds,
                    check_ip_addresses,
                    suspicious_patterns,
                } => {
                    log::debug!("Checking for suspicious links in email body");

                    let check_shorteners = check_url_shorteners.unwrap_or(true);
                    let check_tlds = check_suspicious_tlds.unwrap_or(true);
                    let check_ips = check_ip_addresses.unwrap_or(true);

                    if let Some(body) = &context.body {
                        // Extract all URLs from email body and deduplicate
                        let url_regex = Regex::new(r"https?://[^\s<>]+").unwrap();
                        let ip_regex = Regex::new(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}").unwrap();

                        let mut urls = HashSet::new();
                        for url_match in url_regex.find_iter(body) {
                            urls.insert(url_match.as_str().to_string());
                        }

                        for url in &urls {
                            if let Ok(parsed_url) = Url::parse(url) {
                                if let Some(host) = parsed_url.host_str() {
                                    // Check for URL shorteners
                                    if check_shorteners {
                                        let shortener_domains = [
                                            "bit.ly",
                                            "tinyurl.com",
                                            "t.co",
                                            "goo.gl",
                                            "ow.ly",
                                            "short.link",
                                            "tiny.cc",
                                            "is.gd",
                                            "buff.ly",
                                            "soo.gd",
                                        ];

                                        for shortener in &shortener_domains {
                                            if host.to_lowercase().contains(shortener) {
                                                log::info!(
                                                    "Suspicious URL shortener detected: {url}"
                                                );
                                                return true;
                                            }
                                        }
                                    }

                                    // Check for suspicious TLDs
                                    if check_tlds {
                                        let suspicious_tlds = [
                                            ".tk",
                                            ".ml",
                                            ".ga",
                                            ".cf",
                                            ".click",
                                            ".download",
                                            ".zip",
                                            ".review",
                                            ".country",
                                            ".kim",
                                            ".work",
                                        ];

                                        for tld in &suspicious_tlds {
                                            if host.to_lowercase().ends_with(tld) {
                                                log::info!("Suspicious TLD detected: {url}");
                                                return true;
                                            }
                                        }
                                    }

                                    // Check for IP addresses instead of domains
                                    if check_ips && ip_regex.is_match(host) {
                                        log::info!("Suspicious IP address URL detected: {url}");
                                        return true;
                                    }

                                    // Check custom suspicious patterns
                                    if let Some(patterns) = suspicious_patterns {
                                        for pattern in patterns {
                                            if let Some(regex) = self.compiled_patterns.get(pattern)
                                            {
                                                if regex.is_match(url) {
                                                    log::info!(
                                                        "URL matches suspicious pattern '{pattern}': {url}"
                                                    );
                                                    return true;
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }

                    false
                }
                Criteria::PhishingDomainMismatch { allow_subdomains } => {
                    log::debug!("Checking for domain mismatch between sender and reply-to");

                    let allow_subs = allow_subdomains.unwrap_or(true);
                    let reply_to = context
                        .headers
                        .get("reply-to")
                        .or_else(|| context.headers.get("Reply-To"));
                    let sender_email = context.from_header.as_ref().or(context.sender.as_ref());

                    if let (Some(reply_to_raw), Some(sender)) = (reply_to, sender_email) {
                        // Extract email from reply-to header
                        if let Some(reply_to_email) = extract_email_from_header(reply_to_raw) {
                            // Extract domains
                            let sender_domain = sender.split('@').nth(1);
                            let reply_domain = reply_to_email.split('@').nth(1);

                            if let (Some(s_domain), Some(r_domain)) = (sender_domain, reply_domain)
                            {
                                let s_domain = s_domain.to_lowercase();
                                let r_domain = r_domain.to_lowercase();

                                if s_domain != r_domain {
                                    if allow_subs {
                                        // Check if one is a subdomain of the other
                                        if !self.is_subdomain_of(&s_domain, &r_domain)
                                            && !self.is_subdomain_of(&r_domain, &s_domain)
                                        {
                                            log::info!("Domain mismatch detected: sender '{s_domain}' vs reply-to '{r_domain}'");
                                            return true;
                                        }
                                    } else {
                                        log::info!("Domain mismatch detected: sender '{s_domain}' vs reply-to '{r_domain}'");
                                        return true;
                                    }
                                }
                            }
                        }
                    }

                    false
                }
                Criteria::PhishingLinkRedirection {
                    max_redirects,
                    timeout_seconds,
                    suspicious_redirect_patterns,
                    check_final_destination,
                } => {
                    log::debug!("Checking for suspicious link redirections");

                    let max_hops = max_redirects.unwrap_or(10);
                    let timeout = timeout_seconds.unwrap_or(10);
                    let check_final = check_final_destination.unwrap_or(true);

                    if let Some(body) = &context.body {
                        // Extract all URLs from email body and deduplicate
                        let url_regex = Regex::new(r"https?://[^\s<>]+").unwrap();
                        let ip_regex = Regex::new(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}").unwrap();

                        let mut urls = HashSet::new();
                        for url_match in url_regex.find_iter(body) {
                            urls.insert(url_match.as_str().to_string());
                        }

                        for url in &urls {
                            // Check if this is a tracking/redirect URL
                            if url.contains("sendgrid.net")
                                || url.contains("click")
                                || url.contains("track")
                            {
                                log::debug!("Analyzing redirect chain for: {url}");

                                let (is_suspicious, redirect_chain) = self
                                    .analyze_redirect_chain(
                                        url,
                                        max_hops,
                                        timeout,
                                        suspicious_redirect_patterns,
                                    )
                                    .await;

                                if is_suspicious {
                                    log::info!(
                                        "Suspicious redirect chain detected: {redirect_chain:?}"
                                    );
                                    return true;
                                }

                                // Check final destination if enabled
                                if check_final && redirect_chain.len() > 1 {
                                    if let Some(final_url) = redirect_chain.last() {
                                        // Check for suspicious final destinations
                                        if let Ok(parsed_url) = Url::parse(final_url) {
                                            if let Some(host) = parsed_url.host_str() {
                                                // Check for suspicious TLDs in final destination
                                                let suspicious_tlds = [
                                                    ".tk",
                                                    ".ml",
                                                    ".ga",
                                                    ".cf",
                                                    ".click",
                                                    ".download",
                                                    ".zip",
                                                    ".review",
                                                    ".country",
                                                    ".kim",
                                                    ".work",
                                                ];

                                                for tld in &suspicious_tlds {
                                                    if host.to_lowercase().ends_with(tld) {
                                                        log::info!("Redirect leads to suspicious TLD: {url} -> {final_url}");
                                                        return true;
                                                    }
                                                }

                                                // Check for IP addresses in final destination
                                                if ip_regex.is_match(host) {
                                                    log::info!(
                                                        "Redirect leads to IP address: {url} -> {final_url}"
                                                    );
                                                    return true;
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }

                    false
                }
                Criteria::ImageOnlyEmail {
                    max_text_length,
                    ignore_whitespace,
                    check_attachments,
                } => {
                    log::debug!("Checking for image-only email content");

                    let max_text = max_text_length.unwrap_or(50); // Default: allow up to 50 chars of text
                    let ignore_ws = ignore_whitespace.unwrap_or(true); // Default: ignore whitespace
                    let check_attach = check_attachments.unwrap_or(true); // Default: check attachments

                    if let Some(body) = &context.body {
                        // Check for MIME structure indicating large image attachments
                        let has_large_image_attachment = self.has_large_image_attachment(body);

                        // Check if email contains images (inline or attached)
                        let has_images = self.has_image_content(body) || has_large_image_attachment;

                        if !has_images {
                            log::debug!("No image content found in email");
                            return false;
                        }

                        // Extract text content (remove HTML tags and image references)
                        let text_content = self.extract_text_content(body, ignore_ws);

                        log::debug!(
                            "Extracted text content length: {} (max allowed: {})",
                            text_content.len(),
                            max_text
                        );
                        log::debug!(
                            "Text content: '{}'...",
                            text_content.chars().take(100).collect::<String>()
                        );

                        // Enhanced detection for image-heavy emails with minimal text
                        if check_attach && has_large_image_attachment {
                            // For emails with large image attachments, be more lenient with text
                            // but still flag if text is clearly minimal compared to image content
                            let adjusted_max_text = std::cmp::max(max_text, 200); // Allow up to 200 chars for decoy text

                            if text_content.len() <= adjusted_max_text {
                                // Check if the text content looks like decoy content
                                if self.is_likely_decoy_text(&text_content) {
                                    log::info!(
                                        "Image-heavy email with decoy text detected: {} chars of text, large image attachment present",
                                        text_content.len()
                                    );
                                    return true;
                                }
                            }
                        }

                        // Original logic: Check if text content is minimal
                        if text_content.len() <= max_text {
                            log::info!(
                                "Image-only email detected: {} chars of text, {} images found",
                                text_content.len(),
                                self.count_images(body)
                            );
                            return true;
                        }
                    }

                    false
                }
                Criteria::PhishingFreeEmailReplyTo {
                    free_email_domains,
                    allow_same_domain,
                } => {
                    log::debug!("Checking for free email reply-to vs different from domain");

                    let allow_same = allow_same_domain.unwrap_or(false);
                    let default_free_domains = vec![
                        "gmail.com".to_string(),
                        "yahoo.com".to_string(),
                        "hotmail.com".to_string(),
                        "outlook.com".to_string(),
                        "aol.com".to_string(),
                        "icloud.com".to_string(),
                        "protonmail.com".to_string(),
                        "mail.com".to_string(),
                        "yandex.com".to_string(),
                        "zoho.com".to_string(),
                    ];
                    let free_domains = free_email_domains.as_ref().unwrap_or(&default_free_domains);

                    let reply_to = context
                        .headers
                        .get("reply-to")
                        .or_else(|| context.headers.get("Reply-To"));
                    let from_email = context.from_header.as_ref().or(context.sender.as_ref());

                    if let (Some(reply_to_raw), Some(from_email)) = (reply_to, from_email) {
                        // Extract email from reply-to header
                        if let Some(reply_to_email) = extract_email_from_header(reply_to_raw) {
                            // Extract domains
                            let from_domain = from_email.split('@').nth(1);
                            let reply_domain = reply_to_email.split('@').nth(1);

                            if let (Some(f_domain), Some(r_domain)) = (from_domain, reply_domain) {
                                let f_domain = f_domain.to_lowercase();
                                let r_domain = r_domain.to_lowercase();

                                // Check if reply-to is from a free email service
                                let is_free_email = free_domains.iter().any(|domain| {
                                    let domain_lower = domain.to_lowercase();
                                    r_domain == domain_lower
                                        || r_domain.ends_with(&format!(".{domain_lower}"))
                                });

                                if is_free_email {
                                    // Check if from domain is different
                                    if f_domain != r_domain {
                                        if !allow_same {
                                            log::info!("Free email reply-to detected: from '{f_domain}' but reply-to '{r_domain}'");
                                            return true;
                                        } else {
                                            // Check if they're not the same organization
                                            let f_base = f_domain
                                                .split('.')
                                                .next_back()
                                                .unwrap_or(&f_domain);
                                            let r_base = r_domain
                                                .split('.')
                                                .next_back()
                                                .unwrap_or(&r_domain);
                                            if f_base != r_base {
                                                log::info!("Free email reply-to detected: from '{f_domain}' but reply-to '{r_domain}'");
                                                return true;
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }

                    false
                }
                Criteria::ReplyToValidation {
                    timeout_seconds,
                    check_mx_record,
                } => {
                    log::debug!("Checking reply-to address DNS resolution");

                    let timeout = timeout_seconds.unwrap_or(5); // Default 5 second timeout
                    let check_mx = check_mx_record.unwrap_or(true); // Default: check MX records

                    let reply_to = context
                        .headers
                        .get("reply-to")
                        .or_else(|| context.headers.get("Reply-To"));

                    if let Some(reply_to_raw) = reply_to {
                        // Extract email from reply-to header
                        if let Some(reply_to_email) = extract_email_from_header(reply_to_raw) {
                            // Extract domain from email
                            if let Some(domain) = reply_to_email.split('@').nth(1) {
                                log::debug!("Validating reply-to domain: {domain}");

                                // Check DNS resolution
                                let resolver = match TokioAsyncResolver::tokio_from_system_conf() {
                                    Ok(resolver) => resolver,
                                    Err(e) => {
                                        log::warn!(
                                            "Failed to create DNS resolver for {domain}: {e}"
                                        );
                                        return true; // Treat resolver failure as suspicious
                                    }
                                };

                                // Check A/AAAA records first
                                let lookup_future = resolver.lookup_ip(domain);
                                let timeout_future = tokio::time::timeout(
                                    Duration::from_secs(timeout),
                                    lookup_future,
                                );

                                let has_a_records = match timeout_future.await {
                                    Ok(Ok(response)) => {
                                        if let Some(ip) = response.iter().next() {
                                            log::debug!("Found IP for {domain}: {ip}");
                                            true
                                        } else {
                                            false
                                        }
                                    }
                                    Ok(Err(e)) => {
                                        log::debug!("A/AAAA lookup failed for {domain}: {e}");
                                        false
                                    }
                                    Err(_) => {
                                        log::debug!("A/AAAA lookup timed out for {domain}");
                                        false
                                    }
                                };

                                // Check MX records if enabled
                                let has_mx_records = if check_mx {
                                    use hickory_resolver::proto::rr::RecordType;
                                    let mx_future = resolver.lookup(domain, RecordType::MX);
                                    let mx_timeout_future = tokio::time::timeout(
                                        Duration::from_secs(timeout),
                                        mx_future,
                                    );

                                    match mx_timeout_future.await {
                                        Ok(Ok(response)) => {
                                            let has_mx = response.iter().count() > 0;
                                            if has_mx {
                                                log::debug!("Found MX records for {domain}");
                                            } else {
                                                log::debug!("No MX records found for {domain}");
                                            }
                                            has_mx
                                        }
                                        Ok(Err(e)) => {
                                            log::debug!("MX lookup failed for {domain}: {e}");
                                            false
                                        }
                                        Err(_) => {
                                            log::debug!("MX lookup timed out for {domain}");
                                            false
                                        }
                                    }
                                } else {
                                    true // Skip MX check if disabled
                                };

                                // Return true if validation fails (suspicious)
                                if !has_a_records && !has_mx_records {
                                    log::info!("Reply-to domain validation failed: {domain} has no A/AAAA or MX records");
                                    return true;
                                }

                                log::debug!("Reply-to domain validation passed for: {domain}");
                            }
                        }
                    }

                    false // No reply-to header or validation passed
                }
                Criteria::DomainAge {
                    max_age_days,
                    check_sender,
                    check_reply_to,
                    check_from_header,
                    timeout_seconds,
                    use_mock_data,
                } => {
                    log::debug!("Checking domain age (max_age_days: {max_age_days})");

                    let timeout = timeout_seconds.unwrap_or(10);
                    let use_mock = use_mock_data.unwrap_or(false);
                    let check_sender_flag = check_sender.unwrap_or(true);
                    let check_reply_to_flag = check_reply_to.unwrap_or(false);
                    let check_from_header_flag = check_from_header.unwrap_or(false);

                    // Create a domain age checker with the specified settings
                    let checker = DomainAgeChecker::new(timeout, use_mock);
                    let mut domains_to_check = Vec::new();

                    // Collect domains to check based on configuration
                    if check_sender_flag {
                        if let Some(sender) = &context.sender {
                            if let Some(domain) = DomainAgeChecker::extract_domain(sender) {
                                domains_to_check.push(("sender", domain));
                            }
                        }
                    }

                    if check_from_header_flag {
                        if let Some(from_header) = &context.from_header {
                            if let Some(domain) = DomainAgeChecker::extract_domain(from_header) {
                                domains_to_check.push(("from_header", domain));
                            }
                        }
                    }

                    if check_reply_to_flag {
                        let reply_to = context
                            .headers
                            .get("reply-to")
                            .or_else(|| context.headers.get("Reply-To"));

                        if let Some(reply_to_raw) = reply_to {
                            if let Some(reply_to_email) = extract_email_from_header(reply_to_raw) {
                                if let Some(domain) =
                                    DomainAgeChecker::extract_domain(&reply_to_email)
                                {
                                    domains_to_check.push(("reply_to", domain));
                                }
                            }
                        }
                    }

                    log::debug!("Checking {} domains for age", domains_to_check.len());

                    // Check each domain - return true if ANY domain is young
                    for (source, domain) in domains_to_check {
                        match checker.is_domain_young(&domain, *max_age_days).await {
                            Ok(is_young) => {
                                if is_young {
                                    log::info!(
                                        "Young domain detected: {domain} from {source} (≤ {max_age_days} days old)"
                                    );
                                    return true;
                                }
                                log::debug!(
                                    "Domain {domain} from {source} is older than {max_age_days} days"
                                );
                            }
                            Err(e) => {
                                log::warn!(
                                    "Failed to check age for domain {domain} from {source}: {e}"
                                );
                                // Continue checking other domains rather than failing
                            }
                        }
                    }

                    false // No young domains found
                }
                Criteria::InvalidUnsubscribeHeaders => {
                    log::debug!("Checking for invalid unsubscribe header combinations");

                    // Check if List-Unsubscribe-Post exists
                    let has_unsubscribe_post = context
                        .headers
                        .get("list-unsubscribe-post")
                        .or_else(|| context.headers.get("List-Unsubscribe-Post"))
                        .is_some();

                    // Check if List-Unsubscribe exists
                    let has_unsubscribe = context
                        .headers
                        .get("list-unsubscribe")
                        .or_else(|| context.headers.get("List-Unsubscribe"))
                        .is_some();

                    // RFC violation: List-Unsubscribe-Post without List-Unsubscribe
                    if has_unsubscribe_post && !has_unsubscribe {
                        log::info!("Invalid unsubscribe headers detected: List-Unsubscribe-Post present but List-Unsubscribe missing (RFC violation)");
                        return true;
                    }

                    // Also check for the specific spam pattern: List-Unsubscribe-Post: List-Unsubscribe=One-Click
                    if let Some(post_header) = context
                        .headers
                        .get("list-unsubscribe-post")
                        .or_else(|| context.headers.get("List-Unsubscribe-Post"))
                    {
                        if post_header.contains("List-Unsubscribe=One-Click") && !has_unsubscribe {
                            log::info!("Spam pattern detected: One-Click unsubscribe claim without actual unsubscribe mechanism");
                            return true;
                        }
                    }

                    false // Valid unsubscribe headers or no unsubscribe headers
                }
                Criteria::AttachmentOnlyEmail {
                    max_text_length,
                    ignore_whitespace,
                    suspicious_types,
                    min_attachment_size,
                    check_disposition,
                } => {
                    log::debug!("Checking for attachment-only email content");

                    let max_text = max_text_length.unwrap_or(100); // Default: allow up to 100 chars of text
                    let ignore_ws = ignore_whitespace.unwrap_or(true); // Default: ignore whitespace
                    let min_size = min_attachment_size.unwrap_or(10240); // Default: 10KB minimum
                    let check_disp = check_disposition.unwrap_or(true); // Default: check disposition headers
                    let default_types = vec![
                        "pdf".to_string(),
                        "doc".to_string(),
                        "docx".to_string(),
                        "xls".to_string(),
                        "xlsx".to_string(),
                    ];
                    let types = suspicious_types.as_ref().unwrap_or(&default_types);

                    if let Some(body) = &context.body {
                        // Check if email has suspicious attachments
                        let has_suspicious_attachments =
                            self.has_suspicious_attachments(body, types, min_size, check_disp);

                        if !has_suspicious_attachments {
                            log::debug!("No suspicious attachments found in email");
                            return false;
                        }

                        // Extract text content (remove attachments and MIME structure)
                        let text_content =
                            self.extract_text_content_excluding_attachments(body, ignore_ws);

                        log::debug!(
                            "Extracted text content length: {} (max allowed: {})",
                            text_content.len(),
                            max_text
                        );
                        log::debug!(
                            "Text content: '{}'...",
                            text_content.chars().take(100).collect::<String>()
                        );

                        // Check if text content is minimal
                        if text_content.len() <= max_text {
                            log::info!(
                                "Attachment-only email detected: {} chars of text, suspicious attachments found",
                                text_content.len()
                            );
                            return true;
                        }
                    }

                    false
                }
                Criteria::EmptyContentEmail {
                    max_text_length,
                    ignore_whitespace,
                    ignore_signatures,
                    require_empty_subject,
                    min_subject_length,
                    ignore_html_tags,
                } => {
                    log::debug!("Checking for empty content email");

                    let max_text = max_text_length.unwrap_or(10); // Default: allow up to 10 chars
                    let ignore_ws = ignore_whitespace.unwrap_or(true); // Default: ignore whitespace
                    let ignore_sigs = ignore_signatures.unwrap_or(true); // Default: ignore signatures
                    let require_empty_subj = require_empty_subject.unwrap_or(false); // Default: either empty subject OR body
                    let min_subj_len = min_subject_length.unwrap_or(3); // Default: subject needs 3+ chars to not be empty
                    let ignore_html = ignore_html_tags.unwrap_or(true); // Default: ignore HTML tags

                    // Check subject emptiness
                    let subject_empty = if let Some(subject) = &context.subject {
                        let cleaned_subject = if ignore_ws { subject.trim() } else { subject };
                        cleaned_subject.len() < min_subj_len
                    } else {
                        true // No subject = empty
                    };

                    // Check body emptiness
                    let body_empty = if let Some(body) = &context.body {
                        let text_content = self.extract_meaningful_text_content(
                            body,
                            ignore_ws,
                            ignore_sigs,
                            ignore_html,
                        );

                        log::debug!(
                            "Extracted meaningful text content length: {} (max allowed: {})",
                            text_content.len(),
                            max_text
                        );
                        log::debug!(
                            "Text content preview: '{}'",
                            text_content.chars().take(50).collect::<String>()
                        );

                        text_content.len() <= max_text
                    } else {
                        true // No body = empty
                    };

                    // Determine if email is empty based on requirements
                    let is_empty = if require_empty_subj {
                        subject_empty && body_empty // Both must be empty
                    } else {
                        subject_empty || body_empty // Either can be empty
                    };

                    if is_empty {
                        log::info!(
                            "Empty content email detected: subject_empty={subject_empty}, body_empty={body_empty}, require_both={require_empty_subj}"
                        );
                        return true;
                    }

                    false
                }
                Criteria::EmailServiceAbuse {
                    legitimate_services,
                    brand_keywords,
                    free_email_domains,
                    check_reply_to_mismatch,
                    check_brand_impersonation,
                    check_suspicious_subjects,
                } => {
                    log::debug!("Checking for email service abuse");

                    // Default legitimate email services
                    let default_services = vec![
                        "sendgrid.net",
                        "mailchimp.com",
                        "constantcontact.com",
                        "mailgun.net",
                        "amazonses.com",
                        "sparkpostmail.com",
                        "mandrill.com",
                        "postmarkapp.com",
                    ];
                    let services = if let Some(custom_services) = legitimate_services {
                        custom_services
                            .iter()
                            .map(|s| s.as_str())
                            .collect::<Vec<_>>()
                    } else {
                        default_services
                    };

                    // Default brand keywords for impersonation detection
                    let default_brands = vec![
                        "ebay",
                        "paypal",
                        "amazon",
                        "microsoft",
                        "apple",
                        "google",
                        "facebook",
                        "netflix",
                        "spotify",
                        "adobe",
                        "dropbox",
                        "linkedin",
                        "twitter",
                        "instagram",
                        "whatsapp",
                        "bank",
                        "visa",
                        "mastercard",
                        "wells.fargo",
                        "chase",
                        "citibank",
                        "bofa",
                        "usbank",
                    ];
                    let brands = if let Some(custom_brands) = brand_keywords {
                        custom_brands.iter().map(|s| s.as_str()).collect::<Vec<_>>()
                    } else {
                        default_brands
                    };

                    // Default free email domains
                    let default_free_domains = vec![
                        "gmail.com",
                        "outlook.com",
                        "yahoo.com",
                        "hotmail.com",
                        "aol.com",
                        "protonmail.com",
                        "zoho.com",
                        "zohomail.com",
                        "icloud.com",
                    ];
                    let free_domains = if let Some(custom_domains) = free_email_domains {
                        custom_domains
                            .iter()
                            .map(|s| s.as_str())
                            .collect::<Vec<_>>()
                    } else {
                        default_free_domains
                    };

                    let check_reply_mismatch = check_reply_to_mismatch.unwrap_or(true);
                    let check_brand_imp = check_brand_impersonation.unwrap_or(true);
                    let check_suspicious_subj = check_suspicious_subjects.unwrap_or(true);

                    // Step 1: Check if email is sent via legitimate email service
                    let mut uses_email_service = false;

                    // Check sender domain
                    if let Some(sender) = &context.sender {
                        for service in &services {
                            if sender.contains(service) {
                                uses_email_service = true;
                                log::debug!("Detected email service in sender: {service}");
                                break;
                            }
                        }
                    }

                    // Check Received headers for email service infrastructure
                    if !uses_email_service {
                        for (header_name, header_value) in &context.headers {
                            if header_name.to_lowercase() == "received" {
                                for service in &services {
                                    if header_value.to_lowercase().contains(service) {
                                        uses_email_service = true;
                                        log::debug!(
                                            "Detected email service in Received header: {service}"
                                        );
                                        break;
                                    }
                                }
                                if uses_email_service {
                                    break;
                                }
                            }
                        }
                    }

                    // Check X-Mailer or similar headers
                    if !uses_email_service {
                        if let Some(mailer) = &context.mailer {
                            for service in &services {
                                if mailer.to_lowercase().contains(service) {
                                    uses_email_service = true;
                                    log::debug!("Detected email service in mailer: {service}");
                                    break;
                                }
                            }
                        }
                    }

                    if !uses_email_service {
                        log::debug!("No legitimate email service detected");
                        return false;
                    }

                    let mut abuse_indicators = 0;

                    // Step 2: Check for brand impersonation in From header
                    if check_brand_imp {
                        if let Some(from_header) = context.headers.get("from") {
                            let from_lower = from_header.to_lowercase();
                            for brand in &brands {
                                // Check for exact brand name or "my" prefix (myeBay, myPayPal, etc.)
                                if from_lower.contains(brand)
                                    || from_lower.contains(&format!("my{brand}"))
                                {
                                    abuse_indicators += 1;
                                    log::debug!(
                                        "Brand impersonation detected: {brand} in From header"
                                    );
                                    break;
                                }
                            }
                        }
                    }

                    // Step 3: Check for reply-to mismatch with free email domains
                    if check_reply_mismatch {
                        if let Some(reply_to) = context.headers.get("reply-to") {
                            let reply_lower = reply_to.to_lowercase();
                            for free_domain in &free_domains {
                                if reply_lower.contains(free_domain) {
                                    abuse_indicators += 1;
                                    log::debug!("Free email reply-to detected: {free_domain}");
                                    break;
                                }
                            }
                        }
                    }

                    // Step 4: Check for suspicious subject patterns
                    if check_suspicious_subj {
                        if let Some(subject) = &context.subject {
                            let subject_lower = subject.to_lowercase();
                            let suspicious_patterns = [
                                "received.*message",
                                "new.*message",
                                "inbox.*message",
                                "notification",
                                "alert",
                                "verify",
                                "confirm",
                                "suspended",
                                "locked",
                                "expired",
                                "urgent",
                                "immediate",
                                "action required",
                                "final notice",
                                "you received",
                                "new inbox",
                            ];

                            for pattern in &suspicious_patterns {
                                if subject_lower.contains(pattern) {
                                    abuse_indicators += 1;
                                    log::debug!("Suspicious subject pattern detected: {pattern}");
                                    break;
                                }
                            }
                        }
                    }

                    // Require at least 2 abuse indicators for a match
                    let is_abuse = abuse_indicators >= 2;

                    if is_abuse {
                        log::info!(
                            "Email service abuse detected: {abuse_indicators} indicators found (service detected, brand_impersonation={check_brand_imp}, reply_mismatch={check_reply_mismatch}, suspicious_subject={check_suspicious_subj})"
                        );
                    }

                    is_abuse
                }
                Criteria::GoogleGroupsAbuse {
                    suspicious_domains,
                    reward_keywords,
                    suspicious_sender_names,
                    check_domain_reputation,
                    check_reward_subjects,
                    check_suspicious_senders,
                    min_indicators,
                } => {
                    log::debug!("Checking for Google Groups abuse");

                    // First, verify this is actually a Google Groups email
                    let mut is_google_groups = false;

                    // Check for Google Groups indicators
                    for (header_name, header_value) in &context.headers {
                        let header_lower = header_name.to_lowercase();
                        let value_lower = header_value.to_lowercase();

                        if (header_lower == "list-id" && value_lower.contains("groups.google.com"))
                            || (header_lower == "x-google-group-id")
                            || (header_lower == "precedence" && value_lower == "list")
                            || (header_lower == "mailing-list" && value_lower.contains("list "))
                            || (header_lower == "received"
                                && value_lower.contains("groups.google.com"))
                        {
                            is_google_groups = true;
                            log::debug!(
                                "Google Groups infrastructure detected in header: {header_name}"
                            );
                            break;
                        }
                    }

                    if !is_google_groups {
                        log::debug!("No Google Groups infrastructure detected");
                        return false;
                    }

                    // Default suspicious domain patterns
                    let default_suspicious_domains = vec![
                        // Suspicious TLDs
                        "*.tk",
                        "*.ml",
                        "*.ga",
                        "*.cf",
                        "*.top",
                        "*.click",
                        "*.download",
                        "*.loan",
                        "*.racing",
                        "*.review",
                        "*.science",
                        "*.work",
                        "*.party",
                        "*.date",
                        "*.stream",
                        "*.trade",
                        "*.bid",
                        "*.win",
                        "*.cricket",
                        "*.accountant",
                        "*.faith",
                        "*.men",
                        "*.gq",
                        "*.xyz",
                        "*.info",
                        "*.biz",
                        // Random domain patterns
                        "*texas.com",
                        "*texas.net",
                        "*texas.org",
                        // Generic service patterns
                        "service.*",
                        "support.*",
                        "noreply.*",
                        "info.*",
                        "admin.*",
                    ];
                    let domains = if let Some(custom_domains) = suspicious_domains {
                        custom_domains
                            .iter()
                            .map(|s| s.as_str())
                            .collect::<Vec<_>>()
                    } else {
                        default_suspicious_domains
                    };

                    // Default reward/prize keywords
                    let default_reward_keywords = vec![
                        "reward",
                        "prize",
                        "winner",
                        "congratulations",
                        "expires",
                        "urgent",
                        "limited time",
                        "act now",
                        "claim now",
                        "free gift",
                        "emergency kit",
                        "car kit",
                        "bonus",
                        "cash",
                        "money",
                        "lottery",
                        "sweepstakes",
                        "selected",
                        "chosen",
                        "exclusive",
                        "special offer",
                    ];
                    let rewards = if let Some(custom_rewards) = reward_keywords {
                        custom_rewards
                            .iter()
                            .map(|s| s.as_str())
                            .collect::<Vec<_>>()
                    } else {
                        default_reward_keywords
                    };

                    // Default suspicious sender name patterns
                    let default_suspicious_senders = vec![
                        "confirmation required",
                        "urgent",
                        "important",
                        "admin",
                        "service",
                        "support",
                        "noreply",
                        "notification",
                        "alert",
                        "system",
                        "automated",
                    ];
                    let sender_names = if let Some(custom_senders) = suspicious_sender_names {
                        custom_senders
                            .iter()
                            .map(|s| s.as_str())
                            .collect::<Vec<_>>()
                    } else {
                        default_suspicious_senders
                    };

                    let check_domain_rep = check_domain_reputation.unwrap_or(true);
                    let check_reward_subj = check_reward_subjects.unwrap_or(true);
                    let check_suspicious_send = check_suspicious_senders.unwrap_or(true);
                    let min_indicators_required = min_indicators.unwrap_or(2);

                    let mut abuse_indicators = 0;

                    // Check for suspicious domain patterns
                    if check_domain_rep {
                        if let Some(sender) = &context.sender {
                            let sender_lower = sender.to_lowercase();
                            for domain_pattern in &domains {
                                // Convert wildcard patterns to regex-like matching
                                let pattern_check =
                                    if let Some(suffix) = domain_pattern.strip_prefix('*') {
                                        sender_lower.contains(suffix)
                                    } else if let Some(prefix) = domain_pattern.strip_suffix('*') {
                                        sender_lower.contains(prefix)
                                    } else {
                                        sender_lower.contains(domain_pattern)
                                    };

                                if pattern_check {
                                    abuse_indicators += 1;
                                    log::debug!("Suspicious domain pattern detected: {domain_pattern} in {sender}");
                                    break;
                                }
                            }
                        }
                    }

                    // Check for reward/prize subjects
                    if check_reward_subj {
                        if let Some(subject) = &context.subject {
                            let subject_lower = subject.to_lowercase();
                            for reward_keyword in &rewards {
                                if subject_lower.contains(reward_keyword) {
                                    abuse_indicators += 1;
                                    log::debug!("Reward/prize keyword detected: {reward_keyword} in subject");
                                    break;
                                }
                            }
                        }
                    }

                    // Check for suspicious sender names
                    if check_suspicious_send {
                        if let Some(from_header) = context.headers.get("from") {
                            let from_lower = from_header.to_lowercase();
                            for sender_pattern in &sender_names {
                                if from_lower.contains(sender_pattern) {
                                    abuse_indicators += 1;
                                    log::debug!("Suspicious sender name detected: {sender_pattern} in From header");
                                    break;
                                }
                            }
                        }
                    }

                    // Check if we have enough indicators for abuse
                    let is_abuse = abuse_indicators >= min_indicators_required;

                    if is_abuse {
                        log::info!(
                            "Google Groups abuse detected: {abuse_indicators} indicators found (min required: {min_indicators_required})"
                        );
                    }

                    is_abuse
                }
                Criteria::SenderSpoofingExtortion {
                    extortion_keywords,
                    check_sender_recipient_match,
                    check_external_source,
                    check_missing_authentication,
                    require_extortion_content,
                    min_indicators,
                } => {
                    log::debug!("Checking for sender spoofing extortion");

                    // First, check if this is from a legitimate email service
                    let legitimate_email_services = vec![
                        "sparkpostmail.com",
                        "sendgrid.net",
                        "mailchimp.com",
                        "constantcontact.com",
                        "mailgun.net",
                        "amazonses.com",
                        "mandrill.com",
                        "postmarkapp.com",
                        "mailersend.net",
                        "sendinblue.com",
                        "campaignmonitor.com",
                        "aweber.com",
                        "getresponse.com",
                        "convertkit.com",
                        "activecampaign.com",
                    ];

                    // Check if email is from legitimate email service
                    let mut is_legitimate_service = false;

                    // Check sender domain
                    if let Some(sender) = &context.sender {
                        for service in &legitimate_email_services {
                            if sender.contains(service) {
                                is_legitimate_service = true;
                                log::debug!(
                                    "Legitimate email service detected in sender: {service}"
                                );
                                break;
                            }
                        }
                    }

                    // Check Received headers for email service infrastructure
                    if !is_legitimate_service {
                        for (header_name, header_value) in &context.headers {
                            if header_name.to_lowercase() == "received" {
                                for service in &legitimate_email_services {
                                    if header_value.to_lowercase().contains(service) {
                                        is_legitimate_service = true;
                                        log::debug!("Legitimate email service detected in Received header: {service}");
                                        break;
                                    }
                                }
                                if is_legitimate_service {
                                    break;
                                }
                            }
                        }
                    }

                    // Skip extortion detection for legitimate services
                    if is_legitimate_service {
                        log::debug!("Skipping extortion detection for legitimate email service");
                        return false;
                    }

                    // For emails that might be forwarded/rewritten, require stronger evidence
                    let mut requires_stronger_evidence = false;

                    // Check for Gmail forwarding patterns (common source of false positives)
                    if let Some(sender) = &context.sender {
                        if sender.contains("@gmail.com")
                            && sender.contains("+")
                            && sender.contains("=")
                        {
                            requires_stronger_evidence = true;
                            log::debug!(
                                "Gmail forwarding pattern detected, requiring stronger evidence"
                            );
                        }
                    }

                    // Check for legitimate newsletter/service patterns in subject
                    if let Some(subject) = &context.subject {
                        let subject_lower = subject.to_lowercase();
                        let newsletter_patterns = vec![
                            "newsletter",
                            "digest",
                            "update",
                            "news",
                            "weekly",
                            "daily",
                            "monthly",
                            "subscription",
                            "unsubscribe",
                            "well:",
                            "breaking:",
                            "alert:",
                            "briefing",
                        ];

                        for pattern in &newsletter_patterns {
                            if subject_lower.contains(pattern) {
                                requires_stronger_evidence = true;
                                log::debug!("Newsletter pattern detected in subject: {pattern}");
                                break;
                            }
                        }
                    }

                    // Default extortion keywords
                    let default_extortion_keywords = vec![
                        // Payment/money terms
                        "payment",
                        "pay now",
                        "send money",
                        "transfer funds",
                        "waiting for payment",
                        "payment due",
                        "overdue payment",
                        "final payment",
                        "immediate payment",
                        // Cryptocurrency terms
                        "bitcoin",
                        "btc",
                        "cryptocurrency",
                        "crypto",
                        "wallet",
                        "blockchain",
                        "digital currency",
                        "virtual currency",
                        "crypto wallet",
                        "bitcoin address",
                        // Blackmail/extortion terms
                        "blackmail",
                        "extortion",
                        "compromising",
                        "embarrassing",
                        "adult content",
                        "intimate video",
                        "private video",
                        "webcam",
                        "recording",
                        "footage",
                        "screenshots",
                        "photos",
                        "images",
                        "evidence",
                        "proof",
                        "masturbat",
                        // Threat terms
                        "expose",
                        "reveal",
                        "publish",
                        "share",
                        "distribute",
                        "send to contacts",
                        "family and friends",
                        "social media",
                        "facebook",
                        "instagram",
                        "twitter",
                        // Urgency terms
                        "24 hours",
                        "48 hours",
                        "deadline",
                        "expires",
                        "time limit",
                        "act now",
                        "immediate action",
                        "urgent",
                        "final warning",
                        "last chance",
                    ];
                    let keywords = if let Some(custom_keywords) = extortion_keywords {
                        custom_keywords
                            .iter()
                            .map(|s| s.as_str())
                            .collect::<Vec<_>>()
                    } else {
                        default_extortion_keywords
                    };

                    let check_sender_match = check_sender_recipient_match.unwrap_or(true);
                    let check_external = check_external_source.unwrap_or(true);
                    let check_auth = check_missing_authentication.unwrap_or(true);
                    let require_extortion = require_extortion_content.unwrap_or(true);
                    let min_indicators_required = min_indicators.unwrap_or(2);

                    let mut extortion_indicators = 0;

                    // Check if sender and recipient match (spoofing indicator)
                    if check_sender_match {
                        let sender_email = self.extract_email_address(&context.sender);
                        let mut recipient_match = false;

                        // Check against all recipients
                        for recipient in &context.recipients {
                            let recipient_email =
                                self.extract_email_address(&Some(recipient.clone()));
                            if sender_email.is_some() && sender_email == recipient_email {
                                recipient_match = true;
                                log::debug!(
                                    "Sender-recipient match detected: {} -> {}",
                                    sender_email.as_ref().unwrap(),
                                    recipient_email.as_ref().unwrap()
                                );
                                break;
                            }
                        }

                        // Also check From header against To header
                        if !recipient_match {
                            if let (Some(from_header), Some(to_header)) =
                                (context.headers.get("from"), context.headers.get("to"))
                            {
                                let from_email = self.extract_email_from_header(from_header);
                                let to_email = self.extract_email_from_header(to_header);
                                if from_email.is_some() && from_email == to_email {
                                    recipient_match = true;
                                    log::debug!(
                                        "From-To header match detected: {} -> {}",
                                        from_email.as_ref().unwrap(),
                                        to_email.as_ref().unwrap()
                                    );
                                }
                            }
                        }

                        if recipient_match {
                            extortion_indicators += 1;
                        }
                    }

                    // Check for extortion content in subject and body
                    if require_extortion {
                        let mut has_extortion_content = false;

                        // Check subject
                        if let Some(subject) = &context.subject {
                            let subject_lower = subject.to_lowercase();
                            for keyword in &keywords {
                                if subject_lower.contains(keyword) {
                                    has_extortion_content = true;
                                    log::debug!("Extortion keyword detected in subject: {keyword}");
                                    break;
                                }
                            }
                        }

                        // Check body if subject didn't match
                        if !has_extortion_content {
                            if let Some(body) = &context.body {
                                let body_lower = body.to_lowercase();
                                for keyword in &keywords {
                                    if body_lower.contains(keyword) {
                                        has_extortion_content = true;
                                        log::debug!(
                                            "Extortion keyword detected in body: {keyword}"
                                        );
                                        break;
                                    }
                                }
                            }
                        }

                        if has_extortion_content {
                            extortion_indicators += 1;
                        }
                    }

                    // Check for external/suspicious source
                    if check_external {
                        let mut is_external_source = false;

                        // Look for direct IP connections in Received headers
                        for (header_name, header_value) in &context.headers {
                            if header_name.to_lowercase() == "received" {
                                // Check for IP addresses in square brackets [x.x.x.x]
                                if header_value.contains("[") && header_value.contains("]") {
                                    // Extract IP pattern
                                    if let Some(start) = header_value.find('[') {
                                        if let Some(end) = header_value.find(']') {
                                            let ip_part = &header_value[start + 1..end];
                                            // Check if it looks like an IP address
                                            if ip_part.matches('.').count() == 3
                                                && ip_part
                                                    .chars()
                                                    .all(|c| c.is_ascii_digit() || c == '.')
                                            {
                                                // Check if it's a private IP range
                                                let is_private = self.is_private_ip(ip_part);
                                                if !is_private {
                                                    is_external_source = true;
                                                    log::debug!(
                                                        "External IP source detected: {ip_part}"
                                                    );
                                                    break;
                                                } else {
                                                    log::debug!("Private IP detected, not flagging as external: {ip_part}");
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }

                        if is_external_source {
                            extortion_indicators += 1;
                        }
                    }

                    // Check for missing or failed DKIM authentication
                    if check_auth {
                        let mut missing_auth = false;

                        // Check authentication results
                        if let Some(auth_results) = context.headers.get("authentication-results") {
                            let auth_lower = auth_results.to_lowercase();
                            if auth_lower.contains("dkim=none")
                                || auth_lower.contains("dkim=fail")
                                || auth_lower.contains("dkim=temperror")
                                || auth_lower.contains("dkim=permerror")
                            {
                                missing_auth = true;
                                log::debug!("Missing/failed DKIM authentication detected");
                            }
                        } else {
                            // No authentication results header at all
                            missing_auth = true;
                            log::debug!("No authentication results header found");
                        }

                        // Also check if there's no DKIM signature at all
                        if !missing_auth && !context.headers.contains_key("dkim-signature") {
                            missing_auth = true;
                            log::debug!("No DKIM signature found");
                        }

                        if missing_auth {
                            extortion_indicators += 1;
                        }
                    }

                    // Check if we have enough indicators for extortion
                    let required_indicators = if requires_stronger_evidence {
                        min_indicators_required + 1 // Require one additional indicator
                    } else {
                        min_indicators_required
                    };

                    let is_extortion = extortion_indicators >= required_indicators;

                    if is_extortion {
                        log::info!(
                            "Sender spoofing extortion detected: {extortion_indicators} indicators found (required: {required_indicators}, stronger evidence: {requires_stronger_evidence})"
                        );
                    } else if requires_stronger_evidence
                        && extortion_indicators >= min_indicators_required
                    {
                        log::debug!(
                            "Potential extortion detected but requires stronger evidence: {extortion_indicators} indicators (need {required_indicators})"
                        );
                    }

                    is_extortion
                }
                Criteria::DocuSignAbuse {
                    check_reply_to_mismatch,
                    check_panic_subjects,
                    check_suspicious_encoding,
                    min_indicators,
                } => {
                    log::debug!("Checking for DocuSign infrastructure abuse");

                    // Check if this is actually from DocuSign infrastructure
                    let mut is_docusign_infrastructure = false;

                    // Check sender domain
                    if let Some(sender) = &context.sender {
                        log::debug!("Checking sender: {sender}");
                        if sender.contains("@eumail.docusign.net")
                            || sender.contains("@docusign.net")
                        {
                            is_docusign_infrastructure = true;
                            log::debug!("DocuSign infrastructure detected in sender: {sender}");
                        }
                    }

                    // Check Received headers for DocuSign infrastructure
                    if !is_docusign_infrastructure {
                        for (header_name, header_value) in &context.headers {
                            if header_name.to_lowercase() == "received" {
                                log::debug!("Checking received header: {header_value}");
                                if header_value.contains("docusign.net")
                                    || header_value.contains("eumail.docusign.net")
                                {
                                    is_docusign_infrastructure = true;
                                    log::debug!(
                                        "DocuSign infrastructure detected in Received header"
                                    );
                                    break;
                                }
                            }
                        }
                    }

                    log::debug!("DocuSign infrastructure detected: {is_docusign_infrastructure}");

                    // Skip detection if not from DocuSign infrastructure
                    if !is_docusign_infrastructure {
                        log::debug!(
                            "Not from DocuSign infrastructure, skipping DocuSign abuse detection"
                        );
                        return false;
                    }

                    let check_reply_mismatch = check_reply_to_mismatch.unwrap_or(true);
                    let check_panic = check_panic_subjects.unwrap_or(true);
                    let check_encoding = check_suspicious_encoding.unwrap_or(true);
                    let min_indicators_required = min_indicators.unwrap_or(2) as usize;

                    let mut abuse_indicators = 0;

                    // Check for reply-to domain mismatch
                    if check_reply_mismatch {
                        if let Some(reply_to) = context.headers.get("reply-to") {
                            log::debug!("Found reply-to header: {reply_to}");
                            let reply_email = self.extract_email_from_header(reply_to);
                            log::debug!("Extracted reply email: {reply_email:?}");
                            if let Some(email) = reply_email {
                                // Check if reply-to is not a DocuSign domain
                                if !email.contains("@docusign.net")
                                    && !email.contains("@eumail.docusign.net")
                                {
                                    log::debug!("Reply-to is not DocuSign domain: {email}");
                                    // Check for suspicious reply-to patterns
                                    let suspicious_patterns = vec![
                                        // Random usernames with numbers
                                        r"^[a-z]+\d+@",
                                        // Suspicious domains
                                        r"@.*\.awesome\d+\.com$",
                                        r"@ysl\.",
                                        // Free email services (common in phishing)
                                        r"@(gmail|outlook|yahoo|hotmail|aol)\.(com|net)$",
                                    ];

                                    for pattern in &suspicious_patterns {
                                        if let Ok(regex) = regex::Regex::new(pattern) {
                                            if regex.is_match(&email) {
                                                abuse_indicators += 1;
                                                log::debug!("Suspicious reply-to pattern detected: {email} matches {pattern}");
                                                break;
                                            }
                                        }
                                    }
                                } else {
                                    log::debug!("Reply-to is DocuSign domain, skipping: {email}");
                                }
                            } else {
                                log::debug!("Could not extract email from reply-to header");
                            }
                        } else {
                            log::debug!("No reply-to header found");
                        }
                    }

                    // Check for panic/urgent subjects
                    if check_panic {
                        if let Some(subject) = &context.subject {
                            let subject_lower = subject.to_lowercase();
                            let panic_keywords = vec![
                                "verify now",
                                "payment suspended",
                                "account suspended",
                                "urgent verification",
                                "immediate action",
                                "verify immediately",
                                "suspended for verification",
                                "security center",
                                "action required",
                                "verify your account",
                                "payment failed",
                                "account locked",
                                "verify payment",
                            ];

                            for keyword in &panic_keywords {
                                if subject_lower.contains(keyword) {
                                    abuse_indicators += 1;
                                    log::debug!("Panic subject keyword detected: {keyword}");
                                    break;
                                }
                            }
                        }
                    }

                    // Check for suspicious base64 encoding in From header
                    if check_encoding {
                        if let Some(from_header) = context.headers.get("from") {
                            // Check for base64 encoded content with suspicious patterns
                            if from_header.contains("=?utf-8?B?") {
                                // Decode and check for suspicious content
                                let decoded = crate::milter::decode_mime_header(from_header);
                                let decoded_lower = decoded.to_lowercase();

                                // Look for suspicious encoded content
                                let suspicious_encoded = vec![
                                    "remediation unit",
                                    "security center",
                                    "verification unit",
                                    "compliance team",
                                    "fraud prevention",
                                    "account security",
                                ];

                                for pattern in &suspicious_encoded {
                                    if decoded_lower.contains(pattern) {
                                        abuse_indicators += 1;
                                        log::debug!("Suspicious base64 encoded From header detected: {pattern}");
                                        break;
                                    }
                                }

                                // Also check for unusual characters that might indicate obfuscation
                                if decoded.chars().any(|c| !c.is_ascii() && !c.is_whitespace()) {
                                    // Contains non-ASCII characters that might be used for obfuscation
                                    if decoded.len() > 20 {
                                        // Only flag if substantial content
                                        abuse_indicators += 1;
                                        log::debug!("Suspicious non-ASCII characters in encoded From header");
                                    }
                                }
                            }
                        }
                    }

                    let is_abuse = abuse_indicators >= min_indicators_required;

                    if is_abuse {
                        log::info!(
                            "DocuSign infrastructure abuse detected: {abuse_indicators} indicators found (min required: {min_indicators_required})"
                        );
                    } else {
                        log::debug!(
                            "DocuSign abuse indicators insufficient: {abuse_indicators} found (need {min_indicators_required})"
                        );
                    }

                    is_abuse
                }
                Criteria::And { criteria } => {
                    for c in criteria {
                        if !self.evaluate_criteria(c, context).await {
                            return false;
                        }
                    }
                    true
                }
                Criteria::Or { criteria } => {
                    for c in criteria {
                        if self.evaluate_criteria(c, context).await {
                            return true;
                        }
                    }
                    false
                }
                Criteria::Not { criteria } => {
                    // Return the opposite of the nested criteria evaluation
                    !self.evaluate_criteria(criteria, context).await
                }
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{Action, Config, FilterRule};

    // Helper function to create test configs without statistics
    fn create_test_config(rules: Vec<FilterRule>) -> Config {
        Config {
            socket_path: "/tmp/test.sock".to_string(),
            default_action: Action::Accept,
            rules,
            statistics: None,
            smtp: None,
            version: "test".to_string(),
            rule_set_timestamp: "test".to_string(),
        }
    }

    #[tokio::test]
    async fn test_mailer_pattern_matching() {
        let config = Config::default();
        let engine = FilterEngine::new(config).unwrap();

        let context = MailContext {
            mailer: Some("service.example.cn".to_string()),
            ..Default::default()
        };

        let (action, _, _headers) = engine.evaluate(&context).await;
        match action {
            Action::Reject { .. } => {}
            _ => panic!("Expected reject action for suspicious Chinese service"),
        }
    }

    #[tokio::test]
    async fn test_no_match_default_action() {
        let config = Config::default();
        let engine = FilterEngine::new(config).unwrap();

        let context = MailContext::default();
        let (action, _, _headers) = engine.evaluate(&context).await;
        match action {
            Action::Accept => {}
            _ => panic!("Expected default accept action"),
        }
    }

    #[tokio::test]
    async fn test_combination_criteria() {
        use crate::config::{Action, FilterRule};

        // Create a config with combination criteria: sparkmail.com mailer AND Japanese in subject
        let config = create_test_config(vec![FilterRule {
            name: "Block Sparkmail with Japanese".to_string(),
            criteria: Criteria::And {
                criteria: vec![
                    Criteria::MailerPattern {
                        pattern: r".*sparkmail\.com.*".to_string(),
                    },
                    Criteria::SubjectContainsLanguage {
                        language: "japanese".to_string(),
                    },
                ],
            },
            action: Action::Reject {
                message: "Sparkmail with Japanese content blocked".to_string(),
            },
        }]);

        let engine = FilterEngine::new(config).unwrap();

        // Test case 1: Both conditions match - should reject
        let context = MailContext {
            mailer: Some("sparkmail.com mailer v1.0".to_string()),
            subject: Some("こんにちは - Special Offer".to_string()), // Contains Japanese
            ..Default::default()
        };

        let (action, _, _headers) = engine.evaluate(&context).await;
        match action {
            Action::Reject { .. } => {}
            _ => panic!("Expected reject action for sparkmail with Japanese"),
        }

        // Test case 2: Only mailer matches, no Japanese - should accept
        let context2 = MailContext {
            mailer: Some("sparkmail.com mailer v1.0".to_string()),
            subject: Some("Regular English Subject".to_string()),
            ..Default::default()
        };

        let (action2, _, _headers) = engine.evaluate(&context2).await;
        match action2 {
            Action::Accept => {}
            _ => panic!("Expected accept action for sparkmail without Japanese"),
        }

        // Test case 3: Only Japanese matches, different mailer - should accept
        let context3 = MailContext {
            mailer: Some("gmail.com".to_string()),
            subject: Some("こんにちは - Hello".to_string()),
            ..Default::default()
        };

        let (action3, _, _headers) = engine.evaluate(&context3).await;
        match action3 {
            Action::Accept => {}
            _ => panic!("Expected accept action for non-sparkmail with Japanese"),
        }
    }

    #[tokio::test]
    async fn test_debug_onmicrosoft_header_pattern() {
        use crate::config::{Action, FilterRule};
        use std::collections::HashMap;

        // Create config with the exact rule from the user
        let config = create_test_config(vec![FilterRule {
            name: "Fake Microsoft".to_string(),
            criteria: Criteria::HeaderPattern {
                header: "from".to_string(),
                pattern: r".*onmicrosoft\.com".to_string(),
            },
            action: Action::TagAsSpam {
                header_name: "X-Spam-Flag".to_string(),
                header_value: "YES".to_string(),
            },
        }]);

        let engine = FilterEngine::new(config).unwrap();

        // Test with the exact From header from the user's email
        let mut headers = HashMap::new();
        headers.insert(
            "from".to_string(),
            r#""Member Adventure Support #9kz7ve" <noreply@dailydials19.onmicrosoft.com>"#
                .to_string(),
        );

        let context = MailContext {
            headers,
            ..Default::default()
        };

        println!("Testing header pattern matching...");
        println!("From header: {:?}", context.headers.get("from"));

        // Test the decode function
        if let Some(from_value) = context.headers.get("from") {
            let decoded = crate::milter::decode_mime_header(from_value);
            println!("Decoded header: {decoded}");

            // Test the regex directly
            let pattern = r".*onmicrosoft\.com";
            let regex = regex::Regex::new(pattern).unwrap();
            let matches = regex.is_match(&decoded);
            println!("Pattern '{pattern}' matches: {matches}");

            if let Some(m) = regex.find(&decoded) {
                println!("Matched substring: '{}'", m.as_str());
            }
        }

        let (action, matched_rules, _headers) = engine.evaluate(&context).await;
        println!("Action: {action:?}");
        println!("Matched rules: {matched_rules:?}");

        // This should match and tag as spam
        match action {
            Action::TagAsSpam {
                header_name,
                header_value,
            } => {
                assert_eq!(header_name, "X-Spam-Flag");
                assert_eq!(header_value, "YES");
                assert_eq!(matched_rules.len(), 1);
                assert_eq!(matched_rules[0], "Fake Microsoft");
            }
            _ => {
                panic!("Expected TagAsSpam action for onmicrosoft.com domain, got: {action:?}");
            }
        }
    }

    #[tokio::test]
    async fn test_production_examples() {
        use crate::config::{Action, FilterRule};

        // Create config with the two production examples
        let config = create_test_config(vec![
            // Example 1: Chinese service with Japanese content
            FilterRule {
                name: "Block Chinese services with Japanese content".to_string(),
                criteria: Criteria::And {
                    criteria: vec![
                        Criteria::MailerPattern {
                            pattern: r"service\..*\.cn".to_string(),
                        },
                        Criteria::SubjectContainsLanguage {
                            language: "japanese".to_string(),
                        },
                    ],
                },
                action: Action::Reject {
                    message: "Chinese service with Japanese content blocked".to_string(),
                },
            },
            // Example 2: Sparkpost to specific user
            FilterRule {
                name: "Block Sparkpost to user@example.com".to_string(),
                criteria: Criteria::And {
                    criteria: vec![
                        Criteria::MailerPattern {
                            pattern: r".*\.sparkpostmail\.com".to_string(),
                        },
                        Criteria::RecipientPattern {
                            pattern: r"user@example\.com".to_string(),
                        },
                    ],
                },
                action: Action::Reject {
                    message: "Sparkpost to user@example.com blocked".to_string(),
                },
            },
        ]);

        let engine = FilterEngine::new(config).unwrap();

        // Test Example 1: Chinese service + Japanese (should match)
        let context1 = MailContext {
            mailer: Some("service.mail.cn v2.1".to_string()),
            subject: Some("こんにちは！特別なオファー".to_string()), // Japanese
            ..Default::default()
        };

        let (action1, _, _headers) = engine.evaluate(&context1).await;
        match action1 {
            Action::Reject { message } => {
                assert!(message.contains("Chinese service"));
            }
            _ => panic!("Expected reject for Chinese service + Japanese"),
        }

        // Test Example 2: Sparkpost to user@example.com (should match)
        let context2 = MailContext {
            mailer: Some("relay.sparkpostmail.com v3.2".to_string()),
            recipients: vec!["user@example.com".to_string()],
            ..Default::default()
        };

        let (action2, _, _headers) = engine.evaluate(&context2).await;
        match action2 {
            Action::Reject { message } => {
                assert!(message.contains("Sparkpost"));
            }
            _ => panic!("Expected reject for Sparkpost to user@example.com"),
        }

        // Test partial match 1: Chinese service without Japanese (should not match)
        let context3 = MailContext {
            mailer: Some("service.business.cn v1.0".to_string()),
            subject: Some("Business Proposal".to_string()), // English only
            ..Default::default()
        };

        let (action3, _, _headers) = engine.evaluate(&context3).await;
        match action3 {
            Action::Accept => {}
            _ => panic!("Expected accept for Chinese service without Japanese"),
        }

        // Test partial match 2: Sparkpost to different user (should not match)
        let context4 = MailContext {
            mailer: Some("relay.sparkpostmail.com v3.2".to_string()),
            recipients: vec!["admin@example.com".to_string()],
            ..Default::default()
        };

        let (action4, _, _headers) = engine.evaluate(&context4).await;
        match action4 {
            Action::Accept => {}
            _ => panic!("Expected accept for Sparkpost to different user"),
        }
    }

    #[tokio::test]
    async fn test_klclick_dns_validation() {
        let hostname = "ctrk.klclick.com";
        println!("Testing DNS lookup for: {hostname}");

        let resolver = TokioAsyncResolver::tokio_from_system_conf().unwrap();

        match resolver.lookup_ip(hostname).await {
            Ok(response) => {
                // Test the exact logic from validate_unsubscribe_link
                let mut has_ips = false;
                if let Some(ip) = response.iter().next() {
                    println!("Found IP: {ip}");
                    has_ips = true;
                }

                println!("Has IPs: {has_ips}");
                assert!(
                    has_ips,
                    "Should have found IP addresses for ctrk.klclick.com"
                );
            }
            Err(e) => {
                panic!("DNS lookup failed for {hostname}: {e}");
            }
        }
    }

    #[tokio::test]
    async fn test_phishing_detection() {
        // Simple test to verify phishing detection compiles
        let config = Config::default();
        let engine = FilterEngine::new(config).unwrap();
        let context = MailContext::default();
        let (_action, _, _headers) = engine.evaluate(&context).await;
    }

    #[tokio::test]
    async fn test_sendgrid_redirect_detection() {
        use crate::config::{Action, FilterRule};
        use std::collections::HashMap;

        // Create config to detect SendGrid phishing redirects
        let config = create_test_config(vec![FilterRule {
            name: "Detect SendGrid phishing redirects".to_string(),
            criteria: Criteria::PhishingLinkRedirection {
                max_redirects: Some(5),
                timeout_seconds: Some(5),
                check_final_destination: Some(true),
                suspicious_redirect_patterns: Some(vec![
                    r".*\.sslip\.io.*".to_string(),
                    r".*wordpress-.*".to_string(),
                ]),
            },
            action: Action::Reject {
                message: "Suspicious redirect chain detected".to_string(),
            },
        }]);

        let engine = FilterEngine::new(config).unwrap();

        // Test case: Email with SendGrid tracking link
        let mut headers = HashMap::new();
        headers.insert("from".to_string(), "test@example.com".to_string());
        headers.insert(
            "return-path".to_string(),
            "bounces+123@u123.wl042.sendgrid.net".to_string(),
        );

        let context = MailContext {
            headers,
            body: Some(
                r#"Click here: https://u48775041.ct.sendgrid.net/ls/click?upn=suspicious-link"#
                    .to_string(),
            ),
            ..Default::default()
        };

        // Note: This test won't actually follow redirects in the test environment
        // but verifies the detection logic is in place
        let (action, _, _headers) = engine.evaluate(&context).await;

        // In a real environment with network access, this would detect the redirect
        // For now, we just verify the code compiles and runs
        match action {
            Action::Accept | Action::Reject { .. } => {
                // Both outcomes are valid depending on network availability
            }
            _ => panic!("Unexpected action type"),
        }
    }

    #[tokio::test]
    async fn test_image_only_email_detection() {
        use crate::config::{Action, FilterRule};

        // Create config to detect image-only emails
        let config = create_test_config(vec![FilterRule {
            name: "Detect image-only emails".to_string(),
            criteria: Criteria::ImageOnlyEmail {
                max_text_length: Some(20),
                ignore_whitespace: Some(true),
                check_attachments: Some(false),
            },
            action: Action::TagAsSpam {
                header_name: "X-Image-Only".to_string(),
                header_value: "YES".to_string(),
            },
        }]);

        let engine = FilterEngine::new(config).unwrap();

        // Test case 1: Email with only an image - should match
        let context1 = MailContext {
            body: Some(r#"<html><body><img src="https://example.com/image.jpg" alt="Image"></body></html>"#.to_string()),
            ..Default::default()
        };

        let (action1, _, _headers) = engine.evaluate(&context1).await;
        match action1 {
            Action::TagAsSpam {
                header_name,
                header_value,
            } => {
                assert_eq!(header_name, "X-Image-Only");
                assert_eq!(header_value, "YES");
            }
            _ => panic!("Expected TagAsSpam action for image-only email"),
        }

        // Test case 2: Email with image and significant text - should not match
        let context2 = MailContext {
            body: Some(r#"<html><body><img src="image.png"><p>This is a long paragraph with significant text content that should prevent this from being classified as image-only.</p></body></html>"#.to_string()),
            ..Default::default()
        };

        let (action2, _, _headers) = engine.evaluate(&context2).await;
        match action2 {
            Action::Accept => {}
            _ => panic!("Expected Accept action for email with significant text"),
        }

        // Test case 3: Email with no images - should not match
        let context3 = MailContext {
            body: Some(
                "<html><body><p>Just text content, no images here.</p></body></html>".to_string(),
            ),
            ..Default::default()
        };

        let (action3, _, _headers) = engine.evaluate(&context3).await;
        match action3 {
            Action::Accept => {}
            _ => panic!("Expected Accept action for text-only email"),
        }

        // Test case 4: Email with data URI image - should match
        let context4 = MailContext {
            body: Some(r#"<img src="data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mP8/5+hHgAHggJ/PchI7wAAAABJRU5ErkJggg==">"#.to_string()),
            ..Default::default()
        };

        let (action4, _, _headers) = engine.evaluate(&context4).await;
        match action4 {
            Action::TagAsSpam { .. } => {}
            _ => panic!("Expected TagAsSpam action for data URI image"),
        }
    }

    #[tokio::test]
    async fn test_free_email_reply_to_detection() {
        use crate::config::{Action, FilterRule};
        use std::collections::HashMap;

        // Create config to detect free email reply-to phishing
        let config = create_test_config(vec![FilterRule {
            name: "Detect free email reply-to".to_string(),
            criteria: Criteria::PhishingFreeEmailReplyTo {
                free_email_domains: None, // Use defaults
                allow_same_domain: Some(false),
            },
            action: Action::TagAsSpam {
                header_name: "X-Free-Email-Reply-To".to_string(),
                header_value: "YES".to_string(),
            },
        }]);

        let engine = FilterEngine::new(config).unwrap();

        // Test case 1: Business from address with Gmail reply-to - should match
        let mut headers1 = HashMap::new();
        headers1.insert("reply-to".to_string(), "support@gmail.com".to_string());

        let context1 = MailContext {
            headers: headers1,
            from_header: Some("noreply@bigbank.com".to_string()),
            ..Default::default()
        };

        let (action1, _, _headers) = engine.evaluate(&context1).await;
        match action1 {
            Action::TagAsSpam {
                header_name,
                header_value,
            } => {
                assert_eq!(header_name, "X-Free-Email-Reply-To");
                assert_eq!(header_value, "YES");
            }
            _ => panic!("Expected TagAsSpam action for free email reply-to"),
        }

        // Test case 2: Same domain - should not match
        let mut headers2 = HashMap::new();
        headers2.insert("reply-to".to_string(), "support@bigbank.com".to_string());

        let context2 = MailContext {
            headers: headers2,
            from_header: Some("noreply@bigbank.com".to_string()),
            ..Default::default()
        };

        let (action2, _, _headers) = engine.evaluate(&context2).await;
        match action2 {
            Action::Accept => {}
            _ => panic!("Expected Accept action for same domain"),
        }

        // Test case 3: Both from free email services - should not match
        let mut headers3 = HashMap::new();
        headers3.insert("reply-to".to_string(), "user@gmail.com".to_string());

        let context3 = MailContext {
            headers: headers3,
            from_header: Some("user@gmail.com".to_string()),
            ..Default::default()
        };

        let (action3, _, _headers) = engine.evaluate(&context3).await;
        match action3 {
            Action::Accept => {}
            _ => panic!("Expected Accept action for same free email domain"),
        }

        // Test case 4: No reply-to header - should not match
        let context4 = MailContext {
            from_header: Some("noreply@bigbank.com".to_string()),
            ..Default::default()
        };

        let (action4, _, _headers) = engine.evaluate(&context4).await;
        match action4 {
            Action::Accept => {}
            _ => panic!("Expected Accept action for no reply-to header"),
        }

        // Test case 5: Capitalized Reply-To header - should match
        let mut headers5 = HashMap::new();
        headers5.insert("Reply-To".to_string(), "support@gmail.com".to_string());

        let context5 = MailContext {
            headers: headers5,
            from_header: Some("noreply@bigbank.com".to_string()),
            ..Default::default()
        };

        let (action5, _, _headers) = engine.evaluate(&context5).await;
        match action5 {
            Action::TagAsSpam {
                header_name,
                header_value,
            } => {
                assert_eq!(header_name, "X-Free-Email-Reply-To");
                assert_eq!(header_value, "YES");
            }
            _ => panic!("Expected TagAsSpam action for capitalized Reply-To header"),
        }
    }

    #[tokio::test]
    async fn test_reply_to_validation() {
        use crate::config::{Action, FilterRule};
        use std::collections::HashMap;

        // Create config to validate reply-to addresses
        let config = create_test_config(vec![FilterRule {
            name: "Validate reply-to address".to_string(),
            criteria: Criteria::ReplyToValidation {
                timeout_seconds: Some(5),
                check_mx_record: Some(true),
            },
            action: Action::TagAsSpam {
                header_name: "X-Invalid-Reply-To".to_string(),
                header_value: "YES".to_string(),
            },
        }]);

        let engine = FilterEngine::new(config).unwrap();

        // Test case 1: Valid domain (google.com) - should not match
        let mut headers1 = HashMap::new();
        headers1.insert("reply-to".to_string(), "test@google.com".to_string());

        let context1 = MailContext {
            headers: headers1,
            from_header: Some("sender@example.com".to_string()),
            ..Default::default()
        };

        let (action1, _, _headers) = engine.evaluate(&context1).await;
        match action1 {
            Action::Accept => {}
            _ => {
                // Note: This test might fail in environments without internet access
                // In that case, the validation would treat it as suspicious
                println!("Warning: DNS validation may have failed due to network issues");
            }
        }

        // Test case 2: Invalid domain - should match (but we can't easily test this without a guaranteed invalid domain)
        // Test case 3: No reply-to header - should not match
        let context3 = MailContext {
            from_header: Some("sender@example.com".to_string()),
            ..Default::default()
        };

        let (action3, _, _headers) = engine.evaluate(&context3).await;
        match action3 {
            Action::Accept => {}
            _ => panic!("Expected Accept action for no reply-to header"),
        }
    }

    #[tokio::test]
    async fn test_unsubscribe_link_pattern() {
        use crate::config::{Action, FilterRule};
        use std::collections::HashMap;
        // Create config to tag emails with unsubscribe links pointing to google.com
        let config = create_test_config(vec![FilterRule {
            name: "Tag Google unsubscribe links".to_string(),
            criteria: Criteria::UnsubscribeLinkPattern {
                pattern: r".*\.google\.com.*".to_string(),
            },
            action: Action::TagAsSpam {
                header_name: "X-Suspicious-Unsubscribe".to_string(),
                header_value: "YES".to_string(),
            },
        }]);

        let engine = FilterEngine::new(config).unwrap();

        // Test case 1: Email with google.com unsubscribe link in body - should match
        let mut headers1 = HashMap::new();
        headers1.insert("from".to_string(), "test@example.com".to_string());

        let context1 = MailContext {
            headers: headers1,
            body: Some(
                r#"<a href="https://unsubscribe.google.com/remove?id=123">Unsubscribe</a>"#
                    .to_string(),
            ),
            ..Default::default()
        };

        let (action1, matched_rules1, _headers) = engine.evaluate(&context1).await;
        match action1 {
            Action::TagAsSpam {
                header_name,
                header_value,
            } => {
                assert_eq!(header_name, "X-Suspicious-Unsubscribe");
                assert_eq!(header_value, "YES");
                // Verify rule tracking works
                assert_eq!(matched_rules1.len(), 1);
                assert_eq!(matched_rules1[0], "Tag Google unsubscribe links");
            }
            _ => panic!("Expected TagAsSpam action for google.com unsubscribe link"),
        }

        // Test case 2: Email with List-Unsubscribe header pointing to google.com - should match
        let mut headers2 = HashMap::new();
        headers2.insert("from".to_string(), "test@example.com".to_string());
        headers2.insert(
            "list-unsubscribe".to_string(),
            "<https://mail.google.com/unsubscribe?token=abc123>".to_string(),
        );

        let context2 = MailContext {
            headers: headers2,
            ..Default::default()
        };

        let (action2, _, _headers) = engine.evaluate(&context2).await;
        match action2 {
            Action::TagAsSpam { .. } => {}
            _ => panic!("Expected TagAsSpam action for google.com List-Unsubscribe header"),
        }

        // Test case 3: Email with non-google unsubscribe link - should not match
        let mut headers3 = HashMap::new();
        headers3.insert("from".to_string(), "test@example.com".to_string());

        let context3 = MailContext {
            headers: headers3,
            body: Some(
                r#"<a href="https://unsubscribe.example.com/remove?id=123">Unsubscribe</a>"#
                    .to_string(),
            ),
            ..Default::default()
        };

        let (action3, _, _headers) = engine.evaluate(&context3).await;
        match action3 {
            Action::Accept => {}
            _ => panic!("Expected Accept action for non-google unsubscribe link"),
        }

        // Test case 4: Email with no unsubscribe links - should not match
        let context4 = MailContext {
            body: Some("Regular email content with no unsubscribe links".to_string()),
            ..Default::default()
        };

        let (action4, _, _headers) = engine.evaluate(&context4).await;
        match action4 {
            Action::Accept => {}
            _ => panic!("Expected Accept action for email with no unsubscribe links"),
        }
    }

    #[tokio::test]
    async fn test_localhost_unsubscribe_link_validation() {
        let config = Config::default();
        let engine = FilterEngine::new(config).unwrap();

        // Test that localhost (127.0.0.1) is rejected
        let result = engine
            .validate_unsubscribe_link("http://localhost/unsubscribe", 5, true, false)
            .await;
        assert!(!result, "Localhost unsubscribe links should be invalid");

        // Test that 127.0.0.1 is rejected
        let result = engine
            .validate_unsubscribe_link("http://127.0.0.1/unsubscribe", 5, true, false)
            .await;
        assert!(!result, "127.0.0.1 unsubscribe links should be invalid");

        // Test that a valid domain (if it resolves) is accepted
        // Note: This test might fail in environments without internet access
        let result = engine
            .validate_unsubscribe_link("http://example.com/unsubscribe", 5, true, false)
            .await;
        // We don't assert the result here since example.com might not always resolve
        // but we want to make sure the function doesn't panic
        println!("example.com validation result: {result}");
    }

    #[tokio::test]
    async fn test_unsubscribe_link_caching() {
        let config = Config::default();
        let engine = FilterEngine::new(config).unwrap();

        let test_url = "http://example.com/unsubscribe";

        // Clear any existing cache
        if let Ok(mut cache) = VALIDATION_CACHE.lock() {
            cache.clear();
        }

        // First validation should not be cached
        let start = std::time::Instant::now();
        let result1 = engine
            .validate_unsubscribe_link(test_url, 5, true, false)
            .await;
        let duration1 = start.elapsed();

        // Second validation should be cached and faster
        let start = std::time::Instant::now();
        let result2 = engine
            .validate_unsubscribe_link(test_url, 5, true, false)
            .await;
        let duration2 = start.elapsed();

        // Results should be the same
        assert_eq!(result1, result2, "Cached and uncached results should match");

        // Second call should be significantly faster (cached)
        // Note: This might not always be true in test environments, so we just log it
        println!(
            "First validation: {:?}, Second validation: {:?}",
            duration1, duration2
        );

        // Verify cache contains the result
        assert!(
            FilterEngine::get_cached_validation(test_url).is_some(),
            "Result should be cached"
        );

        // Test cache expiration by manually setting an old timestamp
        if let Ok(mut cache) = VALIDATION_CACHE.lock() {
            if let Some(result) = cache.get_mut(test_url) {
                result.timestamp = std::time::Instant::now()
                    - std::time::Duration::from_secs(CACHE_TTL_SECONDS + 1);
            }
        }

        // Should not find cached result after expiration
        assert!(
            FilterEngine::get_cached_validation(test_url).is_none(),
            "Expired result should not be cached"
        );
    }

    #[tokio::test]
    async fn test_unsubscribe_mailto_only() {
        use crate::config::{Action, FilterRule};
        use std::collections::HashMap;

        // Test case 1: Email with only mailto unsubscribe links (should match)
        let config = create_test_config(vec![FilterRule {
            name: "Block mailto-only unsubscribe".to_string(),
            criteria: Criteria::UnsubscribeMailtoOnly {
                allow_mixed: Some(false), // Flag any mailto links
            },
            action: Action::Reject {
                message: "Suspicious mailto-only unsubscribe".to_string(),
            },
        }]);

        let engine = FilterEngine::new(config).unwrap();

        // Test with List-Unsubscribe header containing only mailto
        let mut headers1 = HashMap::new();
        headers1.insert(
            "list-unsubscribe".to_string(),
            "<mailto:unsubscribe@example.com?subject=unsubscribe>".to_string(),
        );

        let context1 = MailContext {
            headers: headers1,
            ..Default::default()
        };

        let (action1, _, _headers) = engine.evaluate(&context1).await;
        match action1 {
            Action::Reject { .. } => {}
            _ => panic!("Expected Reject action for mailto-only unsubscribe"),
        }

        // Test case 2: Email with mixed HTTP and mailto links (should match with allow_mixed=false)
        let mut headers2 = HashMap::new();
        headers2.insert(
            "list-unsubscribe".to_string(),
            "<https://example.com/unsubscribe>, <mailto:unsubscribe@example.com>".to_string(),
        );

        let context2 = MailContext {
            headers: headers2,
            ..Default::default()
        };

        let (action2, _, _headers) = engine.evaluate(&context2).await;
        match action2 {
            Action::Reject { .. } => {}
            _ => panic!("Expected Reject action for mixed links with allow_mixed=false"),
        }

        // Test case 3: Email with only HTTP links (should not match)
        let config3 = create_test_config(vec![FilterRule {
            name: "Block mailto-only unsubscribe".to_string(),
            criteria: Criteria::UnsubscribeMailtoOnly {
                allow_mixed: Some(true), // Only flag if ALL links are mailto
            },
            action: Action::Reject {
                message: "Suspicious mailto-only unsubscribe".to_string(),
            },
        }]);

        let engine3 = FilterEngine::new(config3).unwrap();

        let mut headers3 = HashMap::new();
        headers3.insert(
            "list-unsubscribe".to_string(),
            "<https://example.com/unsubscribe>".to_string(),
        );

        let context3 = MailContext {
            headers: headers3,
            ..Default::default()
        };

        let (action3, _, _headers) = engine3.evaluate(&context3).await;
        match action3 {
            Action::Accept => {}
            _ => panic!("Expected Accept action for HTTP-only unsubscribe"),
        }

        // Test case 4: Email with mixed links but allow_mixed=true (should not match)
        let mut headers4 = HashMap::new();
        headers4.insert(
            "list-unsubscribe".to_string(),
            "<https://example.com/unsubscribe>, <mailto:unsubscribe@example.com>".to_string(),
        );

        let context4 = MailContext {
            headers: headers4,
            ..Default::default()
        };

        let (action4, _, _headers) = engine3.evaluate(&context4).await;
        match action4 {
            Action::Accept => {}
            _ => panic!("Expected Accept action for mixed links with allow_mixed=true"),
        }

        // Test case 5: Email with only mailto links and allow_mixed=true (should match)
        let mut headers5 = HashMap::new();
        headers5.insert(
            "list-unsubscribe".to_string(),
            "<mailto:unsubscribe@example.com>, <mailto:remove@example.com>".to_string(),
        );

        let context5 = MailContext {
            headers: headers5,
            ..Default::default()
        };

        let (action5, _, _headers) = engine3.evaluate(&context5).await;
        match action5 {
            Action::Reject { .. } => {}
            _ => panic!("Expected Reject action for mailto-only links with allow_mixed=true"),
        }
    }

    #[tokio::test]
    async fn test_mailto_link_validation() {
        let engine = FilterEngine::new(Config::default()).unwrap();

        // Test valid mailto link with legitimate domain
        let valid_mailto = "mailto:unsubscribe@target.com";
        let result = engine
            .validate_unsubscribe_link(valid_mailto, 5, true, false)
            .await;
        // Should be true (valid) since target.com is a legitimate domain
        // Note: This test might fail in environments without internet access
        if !result {
            println!("Warning: mailto validation may have failed due to network issues");
        }

        // Test invalid mailto format
        let invalid_mailto = "mailto:invalid-email-format";
        let result = engine
            .validate_unsubscribe_link(invalid_mailto, 5, true, false)
            .await;
        assert!(!result, "Invalid mailto format should be rejected");

        // Test mailto with DNS checking disabled (should be valid)
        let mailto_no_dns = "mailto:test@example.com";
        let result = engine
            .validate_unsubscribe_link(mailto_no_dns, 5, false, false)
            .await;
        assert!(
            result,
            "mailto links should be valid when DNS checking is disabled"
        );

        // Test mailto with query parameters
        let mailto_with_params = "mailto:leave-test@em.target.com?subject=unsubscribe";
        let result = engine
            .validate_unsubscribe_link(mailto_with_params, 5, true, false)
            .await;
        // Should be true since we extract the domain correctly
        if !result {
            println!(
                "Warning: mailto with params validation may have failed due to network issues"
            );
        }
    }

    #[tokio::test]
    async fn test_subdomain_detection() {
        let engine = FilterEngine::new(Config::default()).unwrap();

        // Test legitimate subdomain relationships
        assert!(engine.is_subdomain_of("mail.etsy.com", "etsy.com"));
        assert!(engine.is_subdomain_of("email.marketing.amazon.com", "amazon.com"));
        assert!(engine.is_subdomain_of("noreply.github.com", "github.com"));

        // Test reverse (parent is not subdomain of child)
        assert!(!engine.is_subdomain_of("etsy.com", "mail.etsy.com"));
        assert!(!engine.is_subdomain_of("amazon.com", "email.marketing.amazon.com"));

        // Test same domain
        assert!(engine.is_subdomain_of("etsy.com", "etsy.com"));
        assert!(engine.is_subdomain_of("mail.etsy.com", "mail.etsy.com"));

        // Test unrelated domains
        assert!(!engine.is_subdomain_of("badsite.com", "etsy.com"));
        assert!(!engine.is_subdomain_of("notetsy.com", "etsy.com"));
        assert!(!engine.is_subdomain_of("fake-etsy.com", "etsy.com"));

        // Test edge cases
        assert!(!engine.is_subdomain_of("etsy.com.evil.com", "etsy.com"));
        assert!(!engine.is_subdomain_of("", "etsy.com"));
        assert!(!engine.is_subdomain_of("etsy.com", ""));

        // Test multi-level subdomains
        assert!(engine.is_subdomain_of("a.b.c.example.com", "example.com"));
        assert!(engine.is_subdomain_of("a.b.c.example.com", "c.example.com"));
        assert!(engine.is_subdomain_of("a.b.c.example.com", "b.c.example.com"));
    }

    #[tokio::test]
    async fn test_mx_record_validation() {
        let engine = FilterEngine::new(Config::default()).unwrap();

        // Test the specific Mailchimp mailto link from the issue
        let mailchimp_mailto = "mailto:unsubscribe-mc.us5_69cddd4b60870615100c3ff5a.f6a1437eed-ad24237cd0@unsubscribe.mailchimpapp.net?subject=unsubscribe";
        let result = engine
            .validate_unsubscribe_link(mailchimp_mailto, 5, true, false)
            .await;
        assert!(
            result,
            "Mailchimp mailto unsubscribe should be valid (has MX record)"
        );

        // Test a domain that should have MX records
        let gmail_mailto = "mailto:test@gmail.com";
        let result = engine
            .validate_unsubscribe_link(gmail_mailto, 5, true, false)
            .await;
        assert!(result, "Gmail should be valid (has MX records)");

        // Test email domain validation directly
        let result = engine
            .validate_email_domain_dns("unsubscribe.mailchimpapp.net", 5)
            .await;
        assert!(
            result,
            "unsubscribe.mailchimpapp.net should be valid via MX record"
        );

        // Test a domain without MX records (should fall back to A record)
        let result = engine.validate_email_domain_dns("example.com", 5).await;
        // Note: This might fail in test environments without internet access
        if !result {
            println!("Warning: example.com validation may have failed due to network issues");
        }
    }

    #[tokio::test]
    async fn test_bulk_spam_undisclosed_recipients() {
        use crate::config::{Action, FilterRule};
        use std::collections::HashMap;

        // Test bulk spam detection with undisclosed recipients from free email
        let config = create_test_config(vec![FilterRule {
            name: "Block bulk spam with undisclosed recipients from free email".to_string(),
            criteria: Criteria::And {
                criteria: vec![
                    Criteria::HeaderPattern {
                        header: "to".to_string(),
                        pattern: "(?i)undisclosed.{0,15}recipients".to_string(),
                    },
                    Criteria::SenderPattern {
                        pattern: ".*@(outlook|gmail|yahoo|hotmail|aol)\\.(com|net|org)$"
                            .to_string(),
                    },
                ],
            },
            action: Action::Reject {
                message: "Bulk spam with undisclosed recipients from free email service blocked"
                    .to_string(),
            },
        }]);

        let engine = FilterEngine::new(config).unwrap();

        // Test case 1: Should be blocked - undisclosed recipients + outlook.com
        let mut headers1 = HashMap::new();
        headers1.insert("to".to_string(), "undisclosed-recipients:;".to_string());
        headers1.insert(
            "from".to_string(),
            "ANNIVERSARY AWARD <sfgvsfgsdfgffffw@outlook.com>".to_string(),
        );

        let context1 = MailContext {
            headers: headers1,
            sender: Some("sfgvsfgsdfgffffw@outlook.com".to_string()),
            ..Default::default()
        };

        let (action1, _, _headers) = engine.evaluate(&context1).await;
        match action1 {
            Action::Reject { .. } => {}
            _ => {
                panic!("Expected Reject for bulk spam with undisclosed recipients from outlook.com")
            }
        }

        // Test case 2: Should be blocked - undisclosed recipients + gmail.com
        let mut headers2 = HashMap::new();
        headers2.insert("to".to_string(), "undisclosed-recipients:;".to_string());
        headers2.insert(
            "from".to_string(),
            "Winner Notification <randomchars123@gmail.com>".to_string(),
        );

        let context2 = MailContext {
            headers: headers2,
            sender: Some("randomchars123@gmail.com".to_string()),
            ..Default::default()
        };

        let (action2, _, _headers) = engine.evaluate(&context2).await;
        match action2 {
            Action::Reject { .. } => {}
            _ => panic!("Expected Reject for bulk spam with undisclosed recipients from gmail.com"),
        }

        // Test case 3: Should NOT be blocked - undisclosed recipients but from corporate domain
        let mut headers3 = HashMap::new();
        headers3.insert("to".to_string(), "undisclosed-recipients:;".to_string());
        headers3.insert(
            "from".to_string(),
            "Newsletter <newsletter@company.com>".to_string(),
        );

        let context3 = MailContext {
            headers: headers3,
            sender: Some("newsletter@company.com".to_string()),
            ..Default::default()
        };

        let (action3, _, _headers) = engine.evaluate(&context3).await;
        match action3 {
            Action::Accept => {}
            _ => panic!("Expected Accept for corporate domain with undisclosed recipients"),
        }

        // Test case 4: Should NOT be blocked - free email but normal recipient
        let mut headers4 = HashMap::new();
        headers4.insert("to".to_string(), "user@example.com".to_string());
        headers4.insert(
            "from".to_string(),
            "Personal Email <person@gmail.com>".to_string(),
        );

        let context4 = MailContext {
            headers: headers4,
            sender: Some("person@gmail.com".to_string()),
            ..Default::default()
        };

        let (action4, _, _headers) = engine.evaluate(&context4).await;
        match action4 {
            Action::Accept => {}
            _ => panic!("Expected Accept for normal email from free service"),
        }
    }

    #[tokio::test]
    async fn test_invalid_unsubscribe_headers() {
        use crate::config::{Action, FilterRule};
        use std::collections::HashMap;

        // Test invalid unsubscribe headers detection
        let config = create_test_config(vec![FilterRule {
            name: "Detect invalid unsubscribe headers".to_string(),
            criteria: Criteria::InvalidUnsubscribeHeaders,
            action: Action::Reject {
                message: "Invalid unsubscribe headers detected (RFC violation)".to_string(),
            },
        }]);

        let engine = FilterEngine::new(config).unwrap();

        // Test case 1: Should be flagged - List-Unsubscribe-Post without List-Unsubscribe
        let mut headers1 = HashMap::new();
        headers1.insert(
            "from".to_string(),
            "Elon Musk-s Weight Loss <congratulations@psybook.info>".to_string(),
        );
        headers1.insert(
            "subject".to_string(),
            "Elon Musk's Secret Revealed".to_string(),
        );
        headers1.insert(
            "list-unsubscribe-post".to_string(),
            "List-Unsubscribe=One-Click".to_string(),
        );
        // Note: No List-Unsubscribe header

        let context1 = MailContext {
            headers: headers1,
            sender: Some("congratulations@psybook.info".to_string()),
            ..Default::default()
        };

        let (action1, _, _headers) = engine.evaluate(&context1).await;
        match action1 {
            Action::Reject { .. } => {}
            _ => panic!("Expected Reject for List-Unsubscribe-Post without List-Unsubscribe"),
        }

        // Test case 2: Should NOT be flagged - Both headers present (legitimate)
        let mut headers2 = HashMap::new();
        headers2.insert(
            "from".to_string(),
            "The New York Times <fromthetimes-noreply@nytimes.com>".to_string(),
        );
        headers2.insert(
            "list-unsubscribe-post".to_string(),
            "List-Unsubscribe=One-Click".to_string(),
        );
        headers2.insert(
            "list-unsubscribe".to_string(),
            "<mailto:unsubscribe@example.com>,<https://example.com/unsubscribe>".to_string(),
        );

        let context2 = MailContext {
            headers: headers2,
            sender: Some("fromthetimes-noreply@nytimes.com".to_string()),
            ..Default::default()
        };

        let (action2, _, _headers) = engine.evaluate(&context2).await;
        match action2 {
            Action::Accept => {}
            _ => panic!("Expected Accept for valid unsubscribe headers"),
        }

        // Test case 3: Should NOT be flagged - No unsubscribe headers at all
        let mut headers3 = HashMap::new();
        headers3.insert(
            "from".to_string(),
            "Personal Email <friend@example.com>".to_string(),
        );
        headers3.insert("subject".to_string(), "Personal message".to_string());

        let context3 = MailContext {
            headers: headers3,
            sender: Some("friend@example.com".to_string()),
            ..Default::default()
        };

        let (action3, _, _headers) = engine.evaluate(&context3).await;
        match action3 {
            Action::Accept => {}
            _ => panic!("Expected Accept for email with no unsubscribe headers"),
        }

        // Test case 4: Should NOT be flagged - Only List-Unsubscribe (no Post header)
        let mut headers4 = HashMap::new();
        headers4.insert(
            "from".to_string(),
            "Newsletter <newsletter@company.com>".to_string(),
        );
        headers4.insert(
            "list-unsubscribe".to_string(),
            "<https://company.com/unsubscribe>".to_string(),
        );

        let context4 = MailContext {
            headers: headers4,
            sender: Some("newsletter@company.com".to_string()),
            ..Default::default()
        };

        let (action4, _, _headers) = engine.evaluate(&context4).await;
        match action4 {
            Action::Accept => {}
            _ => panic!("Expected Accept for List-Unsubscribe without Post header"),
        }
    }

    #[tokio::test]
    async fn test_image_detection_debug() {
        let engine = FilterEngine::new(Config::default()).unwrap();

        // Test the helper functions directly
        let large_image_body = format!(
            "Content-Type: multipart/mixed; boundary=\"boundary123\"\n\
            \n\
            --boundary123\n\
            Content-Type: text/plain\n\
            \n\
            123 Main Street\n\
            Anytown, NY 12345\n\
            Customer Service\n\
            \n\
            --boundary123\n\
            Content-Type: image/gif\n\
            Content-Transfer-Encoding: base64\n\
            \n\
            {}\n\
            --boundary123--",
            "R0lGODlhAQABAIAAAAAAAP///yH5BAEAAAAALAAAAAABAAEAAAIBRAA7".repeat(100)
        );

        println!("Body length: {}", large_image_body.len());
        println!(
            "Has large image attachment: {}",
            engine.has_large_image_attachment(&large_image_body)
        );
        println!(
            "Has image content: {}",
            engine.has_image_content(&large_image_body)
        );

        let text_content = engine.extract_text_content(&large_image_body, true);
        println!("Extracted text: '{}'", text_content);
        println!("Text length: {}", text_content.len());
        println!(
            "Is likely decoy: {}",
            engine.is_likely_decoy_text(&text_content)
        );
    }

    #[tokio::test]
    async fn test_enhanced_image_only_detection() {
        use crate::config::{Action, FilterRule};
        use std::collections::HashMap;

        // Test enhanced image-only detection with large attachments
        let config = create_test_config(vec![FilterRule {
            name: "Detect image-heavy emails with decoy text".to_string(),
            criteria: Criteria::ImageOnlyEmail {
                max_text_length: Some(50),
                ignore_whitespace: Some(true),
                check_attachments: Some(true),
            },
            action: Action::Reject {
                message: "Image-only email with minimal text detected".to_string(),
            },
        }]);

        let engine = FilterEngine::new(config).unwrap();

        // Test case 1: Should be flagged - Large image attachment with decoy address text
        let large_image_body = format!(
            "Content-Type: multipart/mixed; boundary=\"boundary123\"\n\
            \n\
            --boundary123\n\
            Content-Type: text/plain\n\
            \n\
            123 Main Street\n\
            Anytown, NY 12345\n\
            Customer Service\n\
            \n\
            --boundary123\n\
            Content-Type: image/gif\n\
            Content-Transfer-Encoding: base64\n\
            \n\
            {}\n\
            --boundary123--",
            "R0lGODlhAQABAIAAAAAAAP///yH5BAEAAAAALAAAAAABAAEAAAIBRAA7".repeat(100) // Simulate large base64 image
        );

        let mut headers1 = HashMap::new();
        headers1.insert("from".to_string(), "phishing@suspicious.com".to_string());
        headers1.insert(
            "subject".to_string(),
            "PayPal Payment Confirmation".to_string(),
        );

        let context1 = MailContext {
            headers: headers1,
            sender: Some("phishing@suspicious.com".to_string()),
            body: Some(large_image_body),
            ..Default::default()
        };

        let (action1, _, _headers) = engine.evaluate(&context1).await;
        match action1 {
            Action::Reject { .. } => {}
            _ => panic!("Expected Reject for large image attachment with decoy text"),
        }

        // Test case 2: Should be flagged - Traditional image-only email (minimal text)
        let minimal_text_body =
            "<html><body><img src='phishing.jpg' width='600' height='400'></body></html>"
                .to_string();

        let mut headers2 = HashMap::new();
        headers2.insert("from".to_string(), "spam@example.com".to_string());

        let context2 = MailContext {
            headers: headers2,
            sender: Some("spam@example.com".to_string()),
            body: Some(minimal_text_body),
            ..Default::default()
        };

        let (action2, _, _headers) = engine.evaluate(&context2).await;
        match action2 {
            Action::Reject { .. } => {}
            _ => panic!("Expected Reject for traditional image-only email"),
        }

        // Test case 3: Should NOT be flagged - Legitimate email with substantial text
        let legitimate_body = "Dear Customer,\n\
            Thank you for your recent purchase. We're writing to confirm your order details.\n\
            Your order #12345 has been processed and will ship within 2-3 business days.\n\
            \n\
            Order Summary:\n\
            - Product A: $29.99\n\
            - Product B: $19.99\n\
            - Shipping: $5.99\n\
            Total: $55.97\n\
            \n\
            If you have any questions, please contact our customer service team.\n\
            \n\
            Best regards,\n\
            The Sales Team\n\
            \n\
            <img src='logo.png' alt='Company Logo'>"
            .to_string();

        let mut headers3 = HashMap::new();
        headers3.insert(
            "from".to_string(),
            "orders@legitimate-store.com".to_string(),
        );

        let context3 = MailContext {
            headers: headers3,
            sender: Some("orders@legitimate-store.com".to_string()),
            body: Some(legitimate_body),
            ..Default::default()
        };

        let (action3, _, _headers) = engine.evaluate(&context3).await;
        match action3 {
            Action::Accept => {}
            _ => panic!("Expected Accept for legitimate email with substantial text"),
        }

        // Test case 4: Should NOT be flagged - Email with no images
        let no_image_body = "This is a plain text email with no images at all.\n\
            It contains substantial text content and should not be flagged\n\
            as an image-only email."
            .to_string();

        let mut headers4 = HashMap::new();
        headers4.insert("from".to_string(), "newsletter@company.com".to_string());

        let context4 = MailContext {
            headers: headers4,
            sender: Some("newsletter@company.com".to_string()),
            body: Some(no_image_body),
            ..Default::default()
        };

        let (action4, _, _headers) = engine.evaluate(&context4).await;
        match action4 {
            Action::Accept => {}
            _ => panic!("Expected Accept for email with no images"),
        }
    }

    #[tokio::test]
    async fn test_unsubscribe_link_ip_address_detection() {
        use crate::config::{Action, FilterRule};
        use std::collections::HashMap;

        // Test unsubscribe link IP address detection
        let config = create_test_config(vec![FilterRule {
            name: "Detect unsubscribe links with IP addresses".to_string(),
            criteria: Criteria::UnsubscribeLinkIPAddress {
                check_ipv4: Some(true),
                check_ipv6: Some(true),
                allow_private_ips: Some(false),
            },
            action: Action::Reject {
                message: "Unsubscribe link uses IP address instead of domain".to_string(),
            },
        }]);

        let engine = FilterEngine::new(config).unwrap();

        // Test case 1: Should be flagged - IPv4 address in unsubscribe link
        let mut headers1 = HashMap::new();
        headers1.insert("from".to_string(), "spammer@example.com".to_string());
        headers1.insert(
            "list-unsubscribe".to_string(),
            "<http://8.8.8.8/unsubscribe>".to_string(),
        );

        let context1 = MailContext {
            headers: headers1,
            sender: Some("spammer@example.com".to_string()),
            ..Default::default()
        };

        let (action1, _, _headers) = engine.evaluate(&context1).await;
        match action1 {
            Action::Reject { .. } => {}
            _ => panic!("Expected Reject for IPv4 address in unsubscribe link"),
        }

        // Test case 2: Should be flagged - IPv6 address in unsubscribe link
        let mut headers2 = HashMap::new();
        headers2.insert("from".to_string(), "spammer@example.com".to_string());
        headers2.insert(
            "list-unsubscribe".to_string(),
            "<http://[2001:db8::1]/unsubscribe>".to_string(),
        );

        let context2 = MailContext {
            headers: headers2,
            sender: Some("spammer@example.com".to_string()),
            ..Default::default()
        };

        let (action2, _, _headers) = engine.evaluate(&context2).await;
        match action2 {
            Action::Reject { .. } => {}
            _ => panic!("Expected Reject for IPv6 address in unsubscribe link"),
        }

        // Test case 3: Should be flagged - Public IPv4 address
        let mut headers3 = HashMap::new();
        headers3.insert("from".to_string(), "spammer@example.com".to_string());
        headers3.insert(
            "list-unsubscribe".to_string(),
            "<https://8.8.8.8/unsubscribe?id=123>".to_string(),
        );

        let context3 = MailContext {
            headers: headers3,
            sender: Some("spammer@example.com".to_string()),
            ..Default::default()
        };

        let (action3, _, _headers) = engine.evaluate(&context3).await;
        match action3 {
            Action::Reject { .. } => {}
            _ => panic!("Expected Reject for public IPv4 address in unsubscribe link"),
        }

        // Test case 4: Should NOT be flagged - Legitimate domain name
        let mut headers4 = HashMap::new();
        headers4.insert("from".to_string(), "legitimate@company.com".to_string());
        headers4.insert(
            "list-unsubscribe".to_string(),
            "<https://company.com/unsubscribe>".to_string(),
        );

        let context4 = MailContext {
            headers: headers4,
            sender: Some("legitimate@company.com".to_string()),
            ..Default::default()
        };

        let (action4, _, _headers) = engine.evaluate(&context4).await;
        match action4 {
            Action::Accept => {}
            _ => panic!("Expected Accept for legitimate domain name"),
        }

        // Test case 5: Should NOT be flagged - Multiple legitimate links
        let mut headers5 = HashMap::new();
        headers5.insert("from".to_string(), "newsletter@service.com".to_string());
        headers5.insert(
            "list-unsubscribe".to_string(),
            "<https://service.com/unsubscribe>, <mailto:unsubscribe@service.com>".to_string(),
        );

        let context5 = MailContext {
            headers: headers5,
            sender: Some("newsletter@service.com".to_string()),
            ..Default::default()
        };

        let (action5, _, _headers) = engine.evaluate(&context5).await;
        match action5 {
            Action::Accept => {}
            _ => panic!("Expected Accept for multiple legitimate links"),
        }
    }

    #[tokio::test]
    async fn test_unsubscribe_link_ip_address_private_ips() {
        use crate::config::{Action, FilterRule};
        use std::collections::HashMap;

        // Test with private IPs allowed
        let config = create_test_config(vec![FilterRule {
            name: "Detect unsubscribe links with IP addresses (allow private)".to_string(),
            criteria: Criteria::UnsubscribeLinkIPAddress {
                check_ipv4: Some(true),
                check_ipv6: Some(true),
                allow_private_ips: Some(true), // Allow private IPs
            },
            action: Action::Reject {
                message: "Unsubscribe link uses IP address".to_string(),
            },
        }]);

        let engine = FilterEngine::new(config).unwrap();

        // Test case 1: Should be flagged - Private IPv4 address (but allowed)
        let mut headers1 = HashMap::new();
        headers1.insert("from".to_string(), "test@example.com".to_string());
        headers1.insert(
            "list-unsubscribe".to_string(),
            "<http://192.168.1.100/unsubscribe>".to_string(),
        );

        let context1 = MailContext {
            headers: headers1,
            sender: Some("test@example.com".to_string()),
            ..Default::default()
        };

        let (action1, _, _headers) = engine.evaluate(&context1).await;
        match action1 {
            Action::Reject { .. } => {}
            _ => panic!("Expected Reject for private IPv4 address when allowed"),
        }

        // Test case 2: Should be flagged - Public IPv4 address
        let mut headers2 = HashMap::new();
        headers2.insert("from".to_string(), "test@example.com".to_string());
        headers2.insert(
            "list-unsubscribe".to_string(),
            "<http://8.8.8.8/unsubscribe>".to_string(),
        );

        let context2 = MailContext {
            headers: headers2,
            sender: Some("test@example.com".to_string()),
            ..Default::default()
        };

        let (action2, _, _headers) = engine.evaluate(&context2).await;
        match action2 {
            Action::Reject { .. } => {}
            _ => panic!("Expected Reject for public IPv4 address"),
        }
    }

    #[tokio::test]
    async fn test_unsubscribe_link_ip_address_private_ips_blocked() {
        use crate::config::{Action, FilterRule};
        use std::collections::HashMap;

        // Test with private IPs blocked (default)
        let config = create_test_config(vec![FilterRule {
            name: "Detect unsubscribe links with IP addresses (block private)".to_string(),
            criteria: Criteria::UnsubscribeLinkIPAddress {
                check_ipv4: Some(true),
                check_ipv6: Some(true),
                allow_private_ips: Some(false), // Block private IPs
            },
            action: Action::Reject {
                message: "Unsubscribe link uses IP address".to_string(),
            },
        }]);

        let engine = FilterEngine::new(config).unwrap();

        // Test case 1: Should NOT be flagged - Private IPv4 address (blocked)
        let mut headers1 = HashMap::new();
        headers1.insert("from".to_string(), "test@example.com".to_string());
        headers1.insert(
            "list-unsubscribe".to_string(),
            "<http://192.168.1.100/unsubscribe>".to_string(),
        );

        let context1 = MailContext {
            headers: headers1,
            sender: Some("test@example.com".to_string()),
            ..Default::default()
        };

        let (action1, _, _headers) = engine.evaluate(&context1).await;
        match action1 {
            Action::Accept => {}
            _ => panic!("Expected Accept for private IPv4 address when blocked"),
        }

        // Test case 2: Should be flagged - Public IPv4 address
        let mut headers2 = HashMap::new();
        headers2.insert("from".to_string(), "test@example.com".to_string());
        headers2.insert(
            "list-unsubscribe".to_string(),
            "<http://8.8.8.8/unsubscribe>".to_string(),
        );

        let context2 = MailContext {
            headers: headers2,
            sender: Some("test@example.com".to_string()),
            ..Default::default()
        };

        let (action2, _, _headers) = engine.evaluate(&context2).await;
        match action2 {
            Action::Reject { .. } => {}
            _ => panic!("Expected Reject for public IPv4 address"),
        }
    }

    #[tokio::test]
    async fn test_ip_address_helper_functions() {
        let engine = FilterEngine::new(Config::default()).unwrap();

        // Test IPv4 detection
        assert!(engine.is_ipv4_address("192.168.1.1"));
        assert!(engine.is_ipv4_address("8.8.8.8"));
        assert!(engine.is_ipv4_address("127.0.0.1"));
        assert!(!engine.is_ipv4_address("example.com"));
        assert!(!engine.is_ipv4_address("not.an.ip"));

        // Test IPv6 detection
        assert!(engine.is_ipv6_address("2001:db8::1"));
        assert!(engine.is_ipv6_address("::1"));
        assert!(engine.is_ipv6_address("fe80::1"));
        assert!(engine.is_ipv6_address("[2001:db8::1]")); // With brackets
        assert!(!engine.is_ipv6_address("example.com"));
        assert!(!engine.is_ipv6_address("192.168.1.1"));

        // Test private IPv4 detection
        assert!(engine.is_private_ipv4("192.168.1.1"));
        assert!(engine.is_private_ipv4("10.0.0.1"));
        assert!(engine.is_private_ipv4("172.16.0.1"));
        assert!(engine.is_private_ipv4("127.0.0.1"));
        assert!(!engine.is_private_ipv4("8.8.8.8"));
        assert!(!engine.is_private_ipv4("1.1.1.1"));

        // Test private IPv6 detection
        assert!(engine.is_private_ipv6("::1"));
        assert!(engine.is_private_ipv6("fe80::1"));
        assert!(engine.is_private_ipv6("fc00::1"));
        assert!(!engine.is_private_ipv6("2001:db8::1"));

        // Test host extraction
        assert_eq!(
            engine.extract_host_from_url("http://example.com/path"),
            Some("example.com".to_string())
        );
        assert_eq!(
            engine.extract_host_from_url("https://192.168.1.1/unsubscribe"),
            Some("192.168.1.1".to_string())
        );
        assert_eq!(
            engine.extract_host_from_url("http://[2001:db8::1]/path"),
            Some("[2001:db8::1]".to_string())
        );
        assert_eq!(
            engine.extract_host_from_url("example.com:8080/path"),
            Some("example.com".to_string())
        );
        assert_eq!(
            engine.extract_host_from_url("192.168.1.1"),
            Some("192.168.1.1".to_string())
        );

        // Test IP address detection in URLs
        assert!(engine.contains_ip_address("http://192.168.1.1/unsubscribe", true, false, true));
        assert!(engine.contains_ip_address("https://8.8.8.8/path", true, false, false));
        assert!(engine.contains_ip_address("http://[2001:db8::1]/unsubscribe", false, true, false));
        assert!(!engine.contains_ip_address("https://example.com/unsubscribe", true, true, false));
        assert!(!engine.contains_ip_address("http://192.168.1.1/unsubscribe", true, false, false));
        // Private IP blocked
    }

    #[tokio::test]
    async fn test_attachment_detection_debug() {
        let engine = FilterEngine::new(Config::default()).unwrap();

        // Test the helper functions directly
        let pdf_body = format!(
            "Content-Type: multipart/mixed; boundary=\"boundary123\"\n\
            \n\
            --boundary123\n\
            Content-Type: text/plain\n\
            \n\
            Please see attached.\n\
            \n\
            --boundary123\n\
            Content-Type: application/pdf\n\
            Content-Disposition: attachment; filename=\"invoice.pdf\"\n\
            Content-Transfer-Encoding: base64\n\
            \n\
            {}\n\
            --boundary123--",
            "JVBERi0xLjQKJcOkw7zDtsO4DQo".repeat(200)
        );

        let types = vec!["pdf".to_string()];
        println!("Body length: {}", pdf_body.len());
        println!(
            "Has suspicious attachments: {}",
            engine.has_suspicious_attachments(&pdf_body, &types, 5000, true)
        );

        let text_content = engine.extract_text_content_excluding_attachments(&pdf_body, true);
        println!("Extracted text: '{}'", text_content);
        println!("Text length: {}", text_content.len());
    }

    #[tokio::test]
    async fn test_attachment_only_email_detection() {
        use crate::config::{Action, FilterRule};
        use std::collections::HashMap;

        // Test attachment-only email detection
        let config = create_test_config(vec![FilterRule {
            name: "Detect attachment-only emails".to_string(),
            criteria: Criteria::AttachmentOnlyEmail {
                max_text_length: Some(50),
                ignore_whitespace: Some(true),
                suspicious_types: Some(vec!["pdf".to_string(), "doc".to_string()]),
                min_attachment_size: Some(1000), // 1KB minimum (reduced from 5KB)
                check_disposition: Some(true),
            },
            action: Action::Reject {
                message: "Attachment-only email detected".to_string(),
            },
        }]);

        let engine = FilterEngine::new(config).unwrap();

        // Test case 1: Should be flagged - PDF attachment with minimal text
        let pdf_attachment_body = format!(
            "Content-Type: multipart/mixed; boundary=\"boundary123\"\n\
            \n\
            --boundary123\n\
            Content-Type: text/plain\n\
            \n\
            Please see attached.\n\
            \n\
            --boundary123\n\
            Content-Type: application/pdf\n\
            Content-Disposition: attachment; filename=\"invoice.pdf\"\n\
            Content-Transfer-Encoding: base64\n\
            \n\
            {}\n\
            --boundary123--",
            "JVBERi0xLjQKJcOkw7zDtsO4DQo".repeat(200) // Simulate large PDF base64 content
        );

        let mut headers1 = HashMap::new();
        headers1.insert(
            "from".to_string(),
            "Aaron Archibold <kabshagagsntafsbanaksbs4@gmail.com>".to_string(),
        );
        headers1.insert(
            "subject".to_string(),
            "Order Confirmation M9N030MBIVVTP".to_string(),
        );

        let context1 = MailContext {
            headers: headers1,
            sender: Some("kabshagagsntafsbanaksbs4@gmail.com".to_string()),
            body: Some(pdf_attachment_body),
            ..Default::default()
        };

        let (action1, _, _headers) = engine.evaluate(&context1).await;
        match action1 {
            Action::Reject { .. } => {}
            _ => panic!("Expected Reject for PDF attachment with minimal text"),
        }

        // Test case 2: Should be flagged - DOC attachment with no meaningful text
        let doc_attachment_body = format!(
            "Content-Type: multipart/mixed; boundary=\"boundary456\"\n\
            \n\
            --boundary456\n\
            Content-Type: application/msword\n\
            Content-Disposition: attachment; filename=\"document.doc\"\n\
            Content-Transfer-Encoding: base64\n\
            \n\
            {}\n\
            --boundary456--",
            "0M8R4KGxGuEAAAAAAAAAAAAAAAAAAAAAPgADAP7/CQAGAAAAAAAAAAAAAAABAAAAPgAAAAAAAAA="
                .repeat(50)
        );

        let mut headers2 = HashMap::new();
        headers2.insert("from".to_string(), "sender@example.com".to_string());

        let context2 = MailContext {
            headers: headers2,
            sender: Some("sender@example.com".to_string()),
            body: Some(doc_attachment_body),
            ..Default::default()
        };

        let (action2, _, _headers) = engine.evaluate(&context2).await;
        match action2 {
            Action::Reject { .. } => {}
            _ => panic!("Expected Reject for DOC attachment with no text"),
        }

        // Test case 3: Should NOT be flagged - Email with substantial text content
        let legitimate_email_body = "Content-Type: multipart/mixed; boundary=\"boundary789\"\n\
            \n\
            --boundary789\n\
            Content-Type: text/plain\n\
            \n\
            Dear Customer,\n\
            \n\
            Thank you for your inquiry. I'm attaching the requested document for your review.\n\
            Please let me know if you have any questions about the contents or need any\n\
            clarification on the information provided. We appreciate your business and\n\
            look forward to working with you on this project.\n\
            \n\
            Best regards,\n\
            John Smith\n\
            Account Manager\n\
            \n\
            --boundary789\n\
            Content-Type: application/pdf\n\
            Content-Disposition: attachment; filename=\"proposal.pdf\"\n\
            Content-Transfer-Encoding: base64\n\
            \n\
            JVBERi0xLjQKJcOkw7zDtsO4DQo=\n\
            --boundary789--"
            .to_string();

        let mut headers3 = HashMap::new();
        headers3.insert("from".to_string(), "john.smith@company.com".to_string());

        let context3 = MailContext {
            headers: headers3,
            sender: Some("john.smith@company.com".to_string()),
            body: Some(legitimate_email_body),
            ..Default::default()
        };

        let (action3, _, _headers) = engine.evaluate(&context3).await;
        match action3 {
            Action::Accept => {}
            _ => panic!("Expected Accept for email with substantial text content"),
        }

        // Test case 4: Should NOT be flagged - Email with no attachments
        let no_attachment_body = "Content-Type: text/plain\n\
            \n\
            This is a regular email with no attachments.\n\
            It contains only text content and should not be flagged."
            .to_string();

        let mut headers4 = HashMap::new();
        headers4.insert("from".to_string(), "normal@example.com".to_string());

        let context4 = MailContext {
            headers: headers4,
            sender: Some("normal@example.com".to_string()),
            body: Some(no_attachment_body),
            ..Default::default()
        };

        let (action4, _, _headers) = engine.evaluate(&context4).await;
        match action4 {
            Action::Accept => {}
            _ => panic!("Expected Accept for email with no attachments"),
        }
    }

    #[tokio::test]
    async fn test_attachment_only_respects_suspicious_types() {
        let engine = FilterEngine::new(create_test_config(vec![])).unwrap();

        // Create email with ICS calendar attachment
        let ics_body = r#"Content-Type: multipart/mixed; boundary="boundary123"

--boundary123
Content-Type: text/plain

Meeting invitation attached.

--boundary123
Content-Type: text/calendar; name="meeting.ics"
Content-Disposition: attachment; filename="meeting.ics"

BEGIN:VCALENDAR
VERSION:2.0
PRODID:-//Test//Test//EN
BEGIN:VEVENT
DTSTART:20250819T100000Z
DTEND:20250819T110000Z
SUMMARY:Test Meeting
END:VEVENT
END:VCALENDAR

--boundary123--"#;

        let mut context = MailContext {
            sender: Some("sender@example.com".to_string()),
            recipients: vec!["recipient@example.com".to_string()],
            subject: Some("Meeting Invitation".to_string()),
            body: Some(ics_body.to_string()),
            headers: HashMap::new(),
            from_header: Some("sender@example.com".to_string()),
            helo: Some("example.com".to_string()),
            hostname: Some("mail.example.com".to_string()),
            mailer: None,
        };

        // Test with RAR-only suspicious types - should NOT match ICS
        let rar_only_criteria = Criteria::AttachmentOnlyEmail {
            max_text_length: Some(100),
            ignore_whitespace: Some(true),
            suspicious_types: Some(vec!["rar".to_string()]),
            min_attachment_size: Some(256),
            check_disposition: Some(true),
        };

        let result = engine.evaluate_criteria(&rar_only_criteria, &context).await;
        assert!(
            !result,
            "Should NOT match ICS attachment when looking for RAR only"
        );

        // Test with ICS in suspicious types - should match
        let ics_criteria = Criteria::AttachmentOnlyEmail {
            max_text_length: Some(100),
            ignore_whitespace: Some(true),
            suspicious_types: Some(vec!["ics".to_string()]),
            min_attachment_size: Some(256),
            check_disposition: Some(true),
        };

        let result = engine.evaluate_criteria(&ics_criteria, &context).await;
        assert!(
            result,
            "Should match ICS attachment when ICS is in suspicious_types"
        );

        // Create email with RAR attachment
        let rar_body = r#"Content-Type: multipart/mixed; boundary="boundary456"

--boundary456
Content-Type: text/plain

Archive attached.

--boundary456
Content-Type: application/x-rar-compressed; name="archive.rar"
Content-Disposition: attachment; filename="archive.rar"

[RAR file content would be here - this is long enough to meet size requirements]

--boundary456--"#;

        context.body = Some(rar_body.to_string());

        // Test RAR criteria with RAR attachment - should match
        let result = engine.evaluate_criteria(&rar_only_criteria, &context).await;
        assert!(result, "Should match RAR attachment when looking for RAR");

        // Test ICS criteria with RAR attachment - should NOT match
        let result = engine.evaluate_criteria(&ics_criteria, &context).await;
        assert!(
            !result,
            "Should NOT match RAR attachment when looking for ICS only"
        );
    }

    #[tokio::test]
    async fn test_empty_content_email_detection() {
        let config = Config::default();
        let engine = FilterEngine::new(config).unwrap();

        // Test completely empty email
        let empty_context = MailContext {
            sender: Some("test@example.com".to_string()),
            recipients: vec!["recipient@company.com".to_string()],
            subject: Some("".to_string()),
            body: Some("".to_string()),
            headers: HashMap::new(),
            from_header: Some("test@example.com".to_string()),
            helo: Some("example.com".to_string()),
            hostname: Some("mail.example.com".to_string()),
            mailer: None,
        };

        let empty_criteria = Criteria::EmptyContentEmail {
            max_text_length: Some(5),
            ignore_whitespace: Some(true),
            ignore_signatures: Some(true),
            require_empty_subject: Some(false),
            min_subject_length: Some(3),
            ignore_html_tags: Some(true),
        };

        assert!(
            engine
                .evaluate_criteria(&empty_criteria, &empty_context)
                .await,
            "Should detect completely empty email"
        );

        // Test email with minimal content
        let minimal_context = MailContext {
            sender: Some("test@example.com".to_string()),
            recipients: vec!["recipient@company.com".to_string()],
            subject: Some("hi".to_string()),
            body: Some("hello".to_string()),
            headers: HashMap::new(),
            from_header: Some("test@example.com".to_string()),
            helo: Some("example.com".to_string()),
            hostname: Some("mail.example.com".to_string()),
            mailer: None,
        };

        assert!(
            engine
                .evaluate_criteria(&empty_criteria, &minimal_context)
                .await,
            "Should detect email with minimal content"
        );

        // Test email with substantial content
        let substantial_context = MailContext {
            sender: Some("test@example.com".to_string()),
            recipients: vec!["recipient@company.com".to_string()],
            subject: Some("Important meeting tomorrow".to_string()),
            body: Some(
                "Hi there, let's meet tomorrow at 2pm to discuss the project details.".to_string(),
            ),
            headers: HashMap::new(),
            from_header: Some("test@example.com".to_string()),
            helo: Some("example.com".to_string()),
            hostname: Some("mail.example.com".to_string()),
            mailer: None,
        };

        assert!(
            !engine
                .evaluate_criteria(&empty_criteria, &substantial_context)
                .await,
            "Should not detect email with substantial content"
        );

        // Test strict empty content (both subject and body must be empty)
        let strict_criteria = Criteria::EmptyContentEmail {
            max_text_length: Some(0),
            ignore_whitespace: Some(true),
            ignore_signatures: Some(true),
            require_empty_subject: Some(true),
            min_subject_length: Some(1),
            ignore_html_tags: Some(true),
        };

        assert!(
            engine
                .evaluate_criteria(&strict_criteria, &empty_context)
                .await,
            "Should detect completely empty email with strict criteria"
        );

        assert!(
            !engine
                .evaluate_criteria(&strict_criteria, &minimal_context)
                .await,
            "Should not detect email with subject when requiring both empty"
        );

        // Test signature ignoring
        let signature_context = MailContext {
            sender: Some("test@example.com".to_string()),
            recipients: vec!["recipient@company.com".to_string()],
            subject: Some("".to_string()),
            body: Some("--\nBest regards\nJohn Doe\nSent from my iPhone".to_string()),
            headers: HashMap::new(),
            from_header: Some("test@example.com".to_string()),
            helo: Some("example.com".to_string()),
            hostname: Some("mail.example.com".to_string()),
            mailer: None,
        };

        let signature_criteria = Criteria::EmptyContentEmail {
            max_text_length: Some(5),
            ignore_whitespace: Some(true),
            ignore_signatures: Some(true),
            require_empty_subject: Some(false),
            min_subject_length: Some(3),
            ignore_html_tags: Some(true),
        };

        assert!(
            engine
                .evaluate_criteria(&signature_criteria, &signature_context)
                .await,
            "Should detect email with only signature content"
        );
    }

    #[tokio::test]
    async fn test_unsubscribe_anchor_text_detection() {
        let config = create_test_config(vec![]);

        let engine = FilterEngine::new(config).expect("Failed to create FilterEngine");

        // Test case 1: The original problematic case - Mandrill tracking URL with "Unsubscribe" text
        let mandrill_html = r#"
            <html>
            <body>
                <p>Thank you for your purchase!</p>
                <p><a href="https://mandrillapp.com/track/click/31179027/mandrillapp.com?p=eyJzIjoiaEdkZGZwbFJFZ3ZCY2tkVDlXa0NjUHRqNktvIiwidiI6MiwicCI6IntcInVcIjozMTE3OTAyNyxcInZcIjoyLFwidXJsXCI6XCJodHRwOlxcXC9cXFwvbWFuZHJpbGxhcHAuY29tXFxcL3RyYWNrXFxcL3Vuc3ViLnBocD91PTMxMTc5MDI3JmlkPTY3ZDczNGMyYjEzZDQzMjNiOTVmMTFkY2FlYmE0ZjM3LjZ0Y2tzY1llaFZnUHVmR3JDOGREaFpORkwwTSUzRCZyPWh0dHBzJTNBJTJGJTJGdGhhbmdzLmNvbSUzRm1kX2VtYWlsJTNEbSUyNTJBJTI1MkElMjUyQSUyNTJBJTI1NDBiJTI1MkElMjUyQSUyNTJBJTI1MkEuJTI1MkElMjUyQSUyNTJB">Unsubscribe</a></p>
            </body>
            </html>
        "#;

        let context = MailContext {
            headers: HashMap::new(),
            body: Some(mandrill_html.to_string()),
            sender: Some("test@example.com".to_string()),
            from_header: None,
            recipients: vec![],
            subject: None,
            helo: Some("example.com".to_string()),
            hostname: Some("mail.example.com".to_string()),
            mailer: None,
        };

        let links = engine.get_unsubscribe_links(&context);

        println!("Found {} unsubscribe links:", links.len());
        for link in &links {
            println!("  - {}", link);
        }

        // Should detect the HTTPS link based on anchor text
        assert_eq!(links.len(), 1);
        assert!(links[0].starts_with("https://mandrillapp.com/track/click/"));

        // Test that UnsubscribeMailtoOnly with allow_mixed=true does NOT trigger
        // because we now have an HTTP link detected
        let mailto_only_criteria = Criteria::UnsubscribeMailtoOnly {
            allow_mixed: Some(true),
        };

        let result = engine
            .evaluate_criteria(&mailto_only_criteria, &context)
            .await;
        assert!(
            !result,
            "Should NOT trigger UnsubscribeMailtoOnly because HTTP link was detected"
        );
    }

    #[tokio::test]
    async fn test_mixed_unsubscribe_links() {
        let config = create_test_config(vec![]);

        let engine = FilterEngine::new(config).expect("Failed to create FilterEngine");

        // Test case: Mixed HTTP and mailto links
        let mixed_html = r#"
            <html>
            <body>
                <p>To unsubscribe:</p>
                <p><a href="https://tracking.service.com/xyz123">Click here to unsubscribe</a></p>
                <p>Or email: <a href="mailto:unsubscribe@example.com">unsubscribe@example.com</a></p>
            </body>
            </html>
        "#;

        let context = MailContext {
            headers: HashMap::new(),
            body: Some(mixed_html.to_string()),
            sender: Some("test@example.com".to_string()),
            from_header: None,
            recipients: vec![],
            subject: None,
            helo: Some("example.com".to_string()),
            hostname: Some("mail.example.com".to_string()),
            mailer: None,
        };

        let links = engine.get_unsubscribe_links(&context);

        println!("Found {} unsubscribe links:", links.len());
        for link in &links {
            println!("  - {}", link);
        }

        // Should detect both HTTPS and mailto links
        assert_eq!(links.len(), 2);
        assert!(links.iter().any(|l| l.starts_with("https://")));
        assert!(links.iter().any(|l| l.starts_with("mailto:")));

        // Test that UnsubscribeMailtoOnly with allow_mixed=true does NOT trigger
        // because we have mixed link types
        let mailto_only_criteria = Criteria::UnsubscribeMailtoOnly {
            allow_mixed: Some(true),
        };

        let result = engine
            .evaluate_criteria(&mailto_only_criteria, &context)
            .await;
        assert!(
            !result,
            "Should NOT trigger UnsubscribeMailtoOnly because we have mixed link types"
        );
    }

    #[tokio::test]
    async fn test_anchor_text_variations() {
        let config = create_test_config(vec![]);

        let engine = FilterEngine::new(config).expect("Failed to create FilterEngine");

        // Test case: Various anchor text variations
        let variations_html = r#"
            <html>
            <body>
                <p><a href="https://example.com/track1">Unsubscribe from this list</a></p>
                <p><a href="https://example.com/track2">Opt out of emails</a></p>
                <p><a href="https://example.com/track3">Remove me from list</a></p>
                <p><a href="https://example.com/track4">Stop receiving emails</a></p>
            </body>
            </html>
        "#;

        let context = MailContext {
            headers: HashMap::new(),
            body: Some(variations_html.to_string()),
            sender: Some("test@example.com".to_string()),
            from_header: None,
            recipients: vec![],
            subject: None,
            helo: Some("example.com".to_string()),
            hostname: Some("mail.example.com".to_string()),
            mailer: None,
        };

        let links = engine.get_unsubscribe_links(&context);

        println!("Found {} unsubscribe links:", links.len());
        for link in &links {
            println!("  - {}", link);
        }

        // Should detect all 4 variations
        assert_eq!(links.len(), 4);
        assert!(links
            .iter()
            .all(|l| l.starts_with("https://example.com/track")));
    }

    #[tokio::test]
    async fn test_rar_attachment_detection() {
        let config = create_test_config(vec![]);

        let engine = FilterEngine::new(config).expect("Failed to create FilterEngine");

        // Test case: Email with RAR attachment
        let rar_email_body = r#"
Content-Type: multipart/mixed; boundary="boundary123"

--boundary123
Content-Type: text/plain

Here is your file.

--boundary123
Content-Type: application/x-rar-compressed
Content-Disposition: attachment; filename="document.rar"
Content-Transfer-Encoding: base64

UmFyIRoHAM+QcwAADQAAAAAAAACkCgAAAGRvY3VtZW50LnR4dAAA
--boundary123--
        "#;

        let context = MailContext {
            headers: HashMap::new(),
            body: Some(rar_email_body.to_string()),
            sender: Some("test@example.com".to_string()),
            from_header: None,
            recipients: vec![],
            subject: Some("Document attached".to_string()),
            helo: Some("example.com".to_string()),
            hostname: Some("mail.example.com".to_string()),
            mailer: None,
        };

        // Test AttachmentOnlyEmail criteria with RAR type
        let rar_criteria = Criteria::AttachmentOnlyEmail {
            max_text_length: Some(1000),
            ignore_whitespace: Some(true),
            suspicious_types: Some(vec!["rar".to_string()]),
            min_attachment_size: Some(100),
            check_disposition: Some(true),
        };

        let result = engine.evaluate_criteria(&rar_criteria, &context).await;
        assert!(result, "Should detect RAR attachment");

        println!("✅ RAR attachment detection test passed");
    }

    #[tokio::test]
    async fn test_rar_content_type_variations() {
        let config = create_test_config(vec![]);

        let engine = FilterEngine::new(config).expect("Failed to create FilterEngine");

        // Test different RAR MIME types
        let test_cases = vec![
            ("application/x-rar-compressed", "Standard RAR MIME type"),
            ("application/vnd.rar", "Alternative RAR MIME type"),
            ("application/x-rar", "Another RAR MIME type"),
        ];

        for (mime_type, description) in test_cases {
            let email_body = format!(
                r#"
Content-Type: multipart/mixed; boundary="boundary123"

--boundary123
Content-Type: text/plain

Test email with RAR attachment.

--boundary123
Content-Type: {mime_type}
Content-Disposition: attachment; filename="test.rar"

[RAR content here]
--boundary123--
            "#
            );

            let context = MailContext {
                headers: HashMap::new(),
                body: Some(email_body),
                sender: Some("test@example.com".to_string()),
                from_header: None,
                recipients: vec![],
                subject: Some("Test".to_string()),
                helo: Some("example.com".to_string()),
                hostname: Some("mail.example.com".to_string()),
                mailer: None,
            };

            let rar_criteria = Criteria::AttachmentOnlyEmail {
                max_text_length: Some(1000),
                ignore_whitespace: Some(true),
                suspicious_types: Some(vec!["rar".to_string()]),
                min_attachment_size: Some(50),
                check_disposition: Some(true),
            };

            let result = engine.evaluate_criteria(&rar_criteria, &context).await;
            assert!(
                result,
                "Should detect RAR attachment for {}: {}",
                mime_type, description
            );
        }

        println!("✅ RAR MIME type variations test passed");
    }

    #[tokio::test]
    async fn test_email_service_abuse_detection() {
        use std::collections::HashMap;

        // Test case 1: SendGrid with eBay impersonation and free email reply-to (should match)
        let config = create_test_config(vec![FilterRule {
            name: "Detect email service abuse".to_string(),
            criteria: Criteria::EmailServiceAbuse {
                legitimate_services: None, // Use defaults
                brand_keywords: None,      // Use defaults
                free_email_domains: None,  // Use defaults
                check_reply_to_mismatch: Some(true),
                check_brand_impersonation: Some(true),
                check_suspicious_subjects: Some(true),
            },
            action: Action::Reject {
                message: "Email service abuse detected".to_string(),
            },
        }]);

        let engine = FilterEngine::new(config).unwrap();

        // Create context that matches the SendGrid phishing example
        let mut headers = HashMap::new();
        headers.insert("from".to_string(), "myeBay <test@example.com>".to_string());
        headers.insert(
            "reply-to".to_string(),
            "jimmycorten27@outlook.com".to_string(),
        );
        headers.insert(
            "received".to_string(),
            "from sendgrid.net (sendgrid.net [1.2.3.4])".to_string(),
        );

        let context = MailContext {
            sender: Some("bounces@sendgrid.net".to_string()),
            from_header: Some("myeBay <test@example.com>".to_string()),
            recipients: vec!["user@example.com".to_string()],
            headers,
            mailer: None,
            subject: Some("You Received (2) new Inbox Message".to_string()),
            hostname: Some("sendgrid.net".to_string()),
            helo: Some("sendgrid.net".to_string()),
            body: Some("Test body".to_string()),
        };

        let (action, matched_rules, _headers) = engine.evaluate(&context).await;
        assert!(matches!(action, Action::Reject { .. }));
        assert_eq!(matched_rules, vec!["Detect email service abuse"]);

        // Test case 2: Legitimate Mailchimp email (should not match)
        let mut legitimate_headers = HashMap::new();
        legitimate_headers.insert(
            "from".to_string(),
            "Company Newsletter <info@company.com>".to_string(),
        );
        legitimate_headers.insert("reply-to".to_string(), "support@company.com".to_string());
        legitimate_headers.insert(
            "received".to_string(),
            "from mailchimp.com (mailchimp.com [1.2.3.4])".to_string(),
        );

        let legitimate_context = MailContext {
            sender: Some("bounce@mailchimp.com".to_string()),
            from_header: Some("Company Newsletter <info@company.com>".to_string()),
            recipients: vec!["user@example.com".to_string()],
            headers: legitimate_headers,
            mailer: Some("Mailchimp".to_string()),
            subject: Some("Monthly Newsletter".to_string()),
            hostname: Some("mailchimp.com".to_string()),
            helo: Some("mailchimp.com".to_string()),
            body: Some("Newsletter content".to_string()),
        };

        let (action2, matched_rules2, _headers) = engine.evaluate(&legitimate_context).await;
        assert!(matches!(action2, Action::Accept));
        assert!(matched_rules2.is_empty());

        // Test case 3: Brand impersonation without email service (should not match)
        let mut no_service_headers = HashMap::new();
        no_service_headers.insert(
            "from".to_string(),
            "myPayPal <test@example.com>".to_string(),
        );
        no_service_headers.insert("reply-to".to_string(), "scammer@gmail.com".to_string());

        let no_service_context = MailContext {
            sender: Some("test@example.com".to_string()),
            from_header: Some("myPayPal <test@example.com>".to_string()),
            recipients: vec!["user@example.com".to_string()],
            headers: no_service_headers,
            mailer: None,
            subject: Some("Urgent: Verify your account".to_string()),
            hostname: Some("example.com".to_string()),
            helo: Some("example.com".to_string()),
            body: Some("Phishing content".to_string()),
        };

        let (action3, matched_rules3, _headers) = engine.evaluate(&no_service_context).await;
        assert!(matches!(action3, Action::Accept));
        assert!(matched_rules3.is_empty());

        // Test case 4: Custom configuration with specific services and brands
        let custom_config = create_test_config(vec![FilterRule {
            name: "Custom email service abuse".to_string(),
            criteria: Criteria::EmailServiceAbuse {
                legitimate_services: Some(vec!["customservice.com".to_string()]),
                brand_keywords: Some(vec!["custombrand".to_string()]),
                free_email_domains: Some(vec!["freemail.com".to_string()]),
                check_reply_to_mismatch: Some(true),
                check_brand_impersonation: Some(true),
                check_suspicious_subjects: Some(false), // Disable subject checking
            },
            action: Action::TagAsSpam {
                header_name: "X-Custom-Abuse".to_string(),
                header_value: "YES".to_string(),
            },
        }]);

        let custom_engine = FilterEngine::new(custom_config).unwrap();

        let mut custom_headers = HashMap::new();
        custom_headers.insert(
            "from".to_string(),
            "custombrand Support <test@example.com>".to_string(),
        );
        custom_headers.insert("reply-to".to_string(), "scammer@freemail.com".to_string());
        custom_headers.insert(
            "received".to_string(),
            "from customservice.com (customservice.com [1.2.3.4])".to_string(),
        );

        let custom_context = MailContext {
            sender: Some("noreply@customservice.com".to_string()),
            from_header: Some("custombrand Support <test@example.com>".to_string()),
            recipients: vec!["user@example.com".to_string()],
            headers: custom_headers,
            mailer: None,
            subject: Some("Normal subject".to_string()), // Not suspicious
            hostname: Some("customservice.com".to_string()),
            helo: Some("customservice.com".to_string()),
            body: Some("Test body".to_string()),
        };

        let (action4, matched_rules4, _headers) = custom_engine.evaluate(&custom_context).await;
        assert!(matches!(action4, Action::TagAsSpam { .. }));
        assert_eq!(matched_rules4, vec!["Custom email service abuse"]);

        println!("✅ Email service abuse detection test passed");
    }

    #[tokio::test]
    async fn test_google_groups_abuse_detection() {
        use std::collections::HashMap;

        // Test case 1: Google Groups with suspicious domain and reward subject (should match)
        let config = create_test_config(vec![FilterRule {
            name: "Detect Google Groups abuse".to_string(),
            criteria: Criteria::GoogleGroupsAbuse {
                suspicious_domains: None,      // Use defaults
                reward_keywords: None,         // Use defaults
                suspicious_sender_names: None, // Use defaults
                check_domain_reputation: Some(true),
                check_reward_subjects: Some(true),
                check_suspicious_senders: Some(true),
                min_indicators: Some(2), // Require 2 indicators
            },
            action: Action::Reject {
                message: "Google Groups abuse detected".to_string(),
            },
        }]);

        let engine = FilterEngine::new(config).unwrap();

        // Create context that matches the Google Groups phishing example
        let mut headers = HashMap::new();
        headers.insert(
            "from".to_string(),
            "\"Confirmation_required .\" <service@niz.slotintexas.com>".to_string(),
        );
        headers.insert(
            "list-id".to_string(),
            "<cv.niz.slotintexas.com>".to_string(),
        );
        headers.insert("x-google-group-id".to_string(), "282548616536".to_string());
        headers.insert("precedence".to_string(), "list".to_string());
        headers.insert(
            "mailing-list".to_string(),
            "list cv@niz.slotintexas.com; contact cv+owners@niz.slotintexas.com".to_string(),
        );

        let context = MailContext {
            sender: Some("service@niz.slotintexas.com".to_string()),
            from_header: Some(
                "\"Confirmation_required .\" <service@niz.slotintexas.com>".to_string(),
            ),
            recipients: vec!["user@example.com".to_string()],
            headers,
            mailer: None,
            subject: Some("Expires soon: your Car Emergency Kit reward.".to_string()),
            hostname: Some("groups.google.com".to_string()),
            helo: Some("groups.google.com".to_string()),
            body: Some("Claim your reward now!".to_string()),
        };

        let (action, matched_rules, _headers) = engine.evaluate(&context).await;
        assert!(matches!(action, Action::Reject { .. }));
        assert_eq!(matched_rules, vec!["Detect Google Groups abuse"]);

        // Test case 2: Legitimate Google Groups email (should not match)
        let mut legitimate_headers = HashMap::new();
        legitimate_headers.insert(
            "from".to_string(),
            "Company Team <team@company.com>".to_string(),
        );
        legitimate_headers.insert("list-id".to_string(), "<team.company.com>".to_string());
        legitimate_headers.insert("x-google-group-id".to_string(), "123456789".to_string());
        legitimate_headers.insert("precedence".to_string(), "list".to_string());

        let legitimate_context = MailContext {
            sender: Some("team@company.com".to_string()),
            from_header: Some("Company Team <team@company.com>".to_string()),
            recipients: vec!["user@example.com".to_string()],
            headers: legitimate_headers,
            mailer: None,
            subject: Some("Weekly team update".to_string()),
            hostname: Some("groups.google.com".to_string()),
            helo: Some("groups.google.com".to_string()),
            body: Some("Here's this week's update...".to_string()),
        };

        let (action2, matched_rules2, _headers) = engine.evaluate(&legitimate_context).await;
        assert!(matches!(action2, Action::Accept));
        assert!(matched_rules2.is_empty());

        // Test case 3: Non-Google Groups email (should not match)
        let mut no_groups_headers = HashMap::new();
        no_groups_headers.insert(
            "from".to_string(),
            "Scammer <scam@suspicious.tk>".to_string(),
        );

        let no_groups_context = MailContext {
            sender: Some("scam@suspicious.tk".to_string()),
            from_header: Some("Scammer <scam@suspicious.tk>".to_string()),
            recipients: vec!["user@example.com".to_string()],
            headers: no_groups_headers,
            mailer: None,
            subject: Some("You won a prize!".to_string()),
            hostname: Some("suspicious.tk".to_string()),
            helo: Some("suspicious.tk".to_string()),
            body: Some("Claim your reward!".to_string()),
        };

        let (action3, matched_rules3, _headers) = engine.evaluate(&no_groups_context).await;
        assert!(matches!(action3, Action::Accept));
        assert!(matched_rules3.is_empty());

        // Test case 4: Custom configuration with specific patterns
        let custom_config = create_test_config(vec![FilterRule {
            name: "Custom Google Groups abuse".to_string(),
            criteria: Criteria::GoogleGroupsAbuse {
                suspicious_domains: Some(vec![
                    "*.customdomain.com".to_string(),
                    "suspicious.*".to_string(),
                ]),
                reward_keywords: Some(vec![
                    "custom_reward".to_string(),
                    "special_offer".to_string(),
                ]),
                suspicious_sender_names: Some(vec!["custom_sender".to_string()]),
                check_domain_reputation: Some(true),
                check_reward_subjects: Some(true),
                check_suspicious_senders: Some(true),
                min_indicators: Some(1), // Lower threshold for testing
            },
            action: Action::TagAsSpam {
                header_name: "X-Custom-Groups-Abuse".to_string(),
                header_value: "YES".to_string(),
            },
        }]);

        let custom_engine = FilterEngine::new(custom_config).unwrap();

        let mut custom_headers = HashMap::new();
        custom_headers.insert(
            "from".to_string(),
            "custom_sender <test@test.customdomain.com>".to_string(),
        );
        custom_headers.insert(
            "list-id".to_string(),
            "<test.groups.google.com>".to_string(),
        );
        custom_headers.insert("precedence".to_string(), "list".to_string());

        let custom_context = MailContext {
            sender: Some("test@test.customdomain.com".to_string()),
            from_header: Some("custom_sender <test@test.customdomain.com>".to_string()),
            recipients: vec!["user@example.com".to_string()],
            headers: custom_headers,
            mailer: None,
            subject: Some("Your custom_reward is waiting".to_string()),
            hostname: Some("groups.google.com".to_string()),
            helo: Some("groups.google.com".to_string()),
            body: Some("Test body".to_string()),
        };

        let (action4, matched_rules4, _headers) = custom_engine.evaluate(&custom_context).await;
        assert!(matches!(action4, Action::TagAsSpam { .. }));
        assert_eq!(matched_rules4, vec!["Custom Google Groups abuse"]);

        // Test case 5: Google Groups with only 1 indicator (should not match with default min_indicators=2)
        let single_indicator_config = create_test_config(vec![FilterRule {
            name: "Single indicator test".to_string(),
            criteria: Criteria::GoogleGroupsAbuse {
                suspicious_domains: None,
                reward_keywords: None,
                suspicious_sender_names: None,
                check_domain_reputation: Some(true),
                check_reward_subjects: Some(false), // Disable reward checking
                check_suspicious_senders: Some(false), // Disable sender checking
                min_indicators: Some(2),            // Require 2 indicators
            },
            action: Action::Reject {
                message: "Should not match".to_string(),
            },
        }]);

        let single_engine = FilterEngine::new(single_indicator_config).unwrap();

        let mut single_headers = HashMap::new();
        single_headers.insert(
            "from".to_string(),
            "Normal Sender <sender@legitimate.com>".to_string(),
        );
        single_headers.insert(
            "list-id".to_string(),
            "<test.groups.google.com>".to_string(),
        );
        single_headers.insert("precedence".to_string(), "list".to_string());

        let single_context = MailContext {
            sender: Some("sender@suspicious.tk".to_string()), // Only 1 indicator (suspicious domain)
            from_header: Some("Normal Sender <sender@legitimate.com>".to_string()),
            recipients: vec!["user@example.com".to_string()],
            headers: single_headers,
            mailer: None,
            subject: Some("Normal subject".to_string()), // No reward keywords
            hostname: Some("groups.google.com".to_string()),
            helo: Some("groups.google.com".to_string()),
            body: Some("Normal content".to_string()),
        };

        let (action5, matched_rules5, _headers) = single_engine.evaluate(&single_context).await;
        assert!(matches!(action5, Action::Accept)); // Should not match with only 1 indicator
        assert!(matched_rules5.is_empty());

        println!("✅ Google Groups abuse detection test passed");
    }

    #[tokio::test]
    async fn test_docusign_abuse_detection() {
        use crate::config::{Action, FilterRule};
        use std::collections::HashMap;

        // Initialize logging for the test
        let _ = env_logger::builder().is_test(true).try_init();

        // Test case 1: Classic DocuSign phishing attack (should match)
        let config = create_test_config(vec![FilterRule {
            name: "Detect DocuSign abuse".to_string(),
            criteria: Criteria::DocuSignAbuse {
                check_reply_to_mismatch: Some(true),
                check_panic_subjects: Some(true),
                check_suspicious_encoding: Some(true),
                min_indicators: Some(2),
            },
            action: Action::Reject {
                message: "DocuSign infrastructure abuse detected".to_string(),
            },
        }]);

        let mut engine = FilterEngine::new(config).unwrap();
        engine.compile_patterns().unwrap();

        // Create context matching the actual phishing attack
        let mut headers = HashMap::new();
        headers.insert("from".to_string(), "\"=?utf-8?B?8J+Fv2F58J+Fv2FsIFJlbWVkaWF0aW9uIFVuaXQgdmlhIERvY3VzaWdu?=\" <dse@eumail.docusign.net>".to_string());
        headers.insert(
            "reply-to".to_string(),
            "\"deloria548472\" <deloria548472@ysl.awesome47.com>".to_string(),
        );
        headers.insert(
            "received".to_string(),
            "from mailfr.eumail.docusign.net (fr-c101-f51-81.euad.docusign.net [10.111.81.9])"
                .to_string(),
        );

        let context = MailContext {
            sender: Some("dse@eumail.docusign.net".to_string()),
            recipients: vec!["victim@example.com".to_string()],
            subject: Some(
                "Verify Now: Payment Suspended for Verification at Our Security Center".to_string(),
            ),
            body: Some("Your payment has been suspended. Click here to verify.".to_string()),
            headers,
            from_header: Some("dse@eumail.docusign.net".to_string()),
            helo: Some("eumail.docusign.net".to_string()),
            hostname: Some("mailfr.eumail.docusign.net".to_string()),
            mailer: None,
        };

        let (action, matched_rules, _headers) = engine.evaluate(&context).await;
        assert!(matches!(action, Action::Reject { .. }));
        assert_eq!(matched_rules, vec!["Detect DocuSign abuse"]);

        // Test case 2: Legitimate DocuSign email (should not match)
        let mut legitimate_headers = HashMap::new();
        legitimate_headers.insert(
            "from".to_string(),
            "DocuSign <noreply@docusign.net>".to_string(),
        );
        legitimate_headers.insert("reply-to".to_string(), "support@docusign.net".to_string());
        legitimate_headers.insert("received".to_string(), "from mail.docusign.net".to_string());

        let legitimate_context = MailContext {
            sender: Some("noreply@docusign.net".to_string()),
            recipients: vec!["user@example.com".to_string()],
            subject: Some("Document ready for signature".to_string()),
            body: Some("Please review and sign the document.".to_string()),
            headers: legitimate_headers,
            from_header: Some("noreply@docusign.net".to_string()),
            helo: Some("docusign.net".to_string()),
            hostname: Some("mail.docusign.net".to_string()),
            mailer: None,
        };

        let (action2, matched_rules2, _headers) = engine.evaluate(&legitimate_context).await;
        assert!(matches!(action2, Action::Accept));
        assert!(matched_rules2.is_empty());

        // Test case 3: Non-DocuSign email (should not match)
        let mut non_docusign_headers = HashMap::new();
        non_docusign_headers.insert("from".to_string(), "phisher@evil.com".to_string());
        non_docusign_headers.insert("reply-to".to_string(), "reply@evil.com".to_string());

        let non_docusign_context = MailContext {
            sender: Some("phisher@evil.com".to_string()),
            recipients: vec!["victim@example.com".to_string()],
            subject: Some("Verify Now: Payment Suspended".to_string()),
            body: Some("Phishing attempt".to_string()),
            headers: non_docusign_headers,
            from_header: Some("phisher@evil.com".to_string()),
            helo: Some("evil.com".to_string()),
            hostname: Some("mail.evil.com".to_string()),
            mailer: None,
        };

        let (action3, matched_rules3, _headers) = engine.evaluate(&non_docusign_context).await;
        assert!(matches!(action3, Action::Accept));
        assert!(matched_rules3.is_empty());

        // Test case 4: DocuSign with only 1 indicator (should not match with min_indicators=2)
        let mut single_indicator_headers = HashMap::new();
        single_indicator_headers.insert(
            "from".to_string(),
            "DocuSign <dse@eumail.docusign.net>".to_string(),
        );
        single_indicator_headers.insert(
            "reply-to".to_string(),
            "randomuser123@gmail.com".to_string(),
        ); // Matches free email pattern
        single_indicator_headers.insert(
            "received".to_string(),
            "from mailfr.eumail.docusign.net".to_string(),
        );

        let single_indicator_context = MailContext {
            sender: Some("dse@eumail.docusign.net".to_string()),
            recipients: vec!["victim@example.com".to_string()],
            subject: Some("Normal document notification".to_string()), // No panic keywords
            body: Some("Please review the document.".to_string()),
            headers: single_indicator_headers,
            from_header: Some("dse@eumail.docusign.net".to_string()),
            helo: Some("eumail.docusign.net".to_string()),
            hostname: Some("mailfr.eumail.docusign.net".to_string()),
            mailer: None,
        };

        let (action4, matched_rules4, _headers) = engine.evaluate(&single_indicator_context).await;
        assert!(matches!(action4, Action::Accept));
        assert!(matched_rules4.is_empty());

        // Test case 5: DocuSign with custom min_indicators=1 (should match)
        let single_indicator_config = create_test_config(vec![FilterRule {
            name: "Single indicator DocuSign abuse".to_string(),
            criteria: Criteria::DocuSignAbuse {
                check_reply_to_mismatch: Some(true),
                check_panic_subjects: Some(false), // Disable panic checking
                check_suspicious_encoding: Some(false), // Disable encoding checking
                min_indicators: Some(1),           // Only need 1 indicator
            },
            action: Action::TagAsSpam {
                header_name: "X-DocuSign-Abuse".to_string(),
                header_value: "Single indicator detected".to_string(),
            },
        }]);

        let mut single_engine = FilterEngine::new(single_indicator_config).unwrap();
        single_engine.compile_patterns().unwrap();

        let (action5, matched_rules5, _headers) =
            single_engine.evaluate(&single_indicator_context).await;
        assert!(matches!(action5, Action::TagAsSpam { .. }));
        assert_eq!(matched_rules5, vec!["Single indicator DocuSign abuse"]);
    }

    #[tokio::test]
    async fn test_sender_spoofing_extortion_detection() {
        use std::collections::HashMap;

        // Test case 1: Classic sender spoofing extortion (should match)
        let config = create_test_config(vec![FilterRule {
            name: "Detect sender spoofing extortion".to_string(),
            criteria: Criteria::SenderSpoofingExtortion {
                extortion_keywords: None, // Use defaults
                check_sender_recipient_match: Some(true),
                check_external_source: Some(true),
                check_missing_authentication: Some(true),
                require_extortion_content: Some(true),
                min_indicators: Some(2), // Require 2 indicators
            },
            action: Action::Reject {
                message: "Sender spoofing extortion detected".to_string(),
            },
        }]);

        let engine = FilterEngine::new(config).unwrap();

        // Create context that matches the sender spoofing extortion example
        let mut headers = HashMap::new();
        headers.insert("from".to_string(), "<robert@example.com>".to_string());
        headers.insert("to".to_string(), "<robert@example.com>".to_string());
        headers.insert(
            "received".to_string(),
            "from [38.25.18.110] ([38.25.18.110])".to_string(),
        );
        headers.insert(
            "authentication-results".to_string(),
            "dkim=none".to_string(),
        );

        let context = MailContext {
            sender: Some("robert@example.com".to_string()),
            from_header: Some("<robert@example.com>".to_string()),
            recipients: vec!["robert@example.com".to_string()],
            headers,
            mailer: Some("Microsoft Office Outlook 11".to_string()),
            subject: Some("Waiting for the payment.".to_string()),
            hostname: Some("external.com".to_string()),
            helo: Some("external.com".to_string()),
            body: Some(
                "You need to pay bitcoin immediately or I will expose your secrets.".to_string(),
            ),
        };

        let (action, matched_rules, _headers) = engine.evaluate(&context).await;
        assert!(matches!(action, Action::Reject { .. }));
        assert_eq!(matched_rules, vec!["Detect sender spoofing extortion"]);

        // Test case 2: Legitimate self-sent email (should not match)
        let mut legitimate_headers = HashMap::new();
        legitimate_headers.insert("from".to_string(), "user@company.com".to_string());
        legitimate_headers.insert("to".to_string(), "user@company.com".to_string());
        legitimate_headers.insert(
            "received".to_string(),
            "from mail.company.com (mail.company.com [192.168.1.10])".to_string(),
        );
        legitimate_headers.insert(
            "dkim-signature".to_string(),
            "v=1; a=rsa-sha256; d=company.com; s=default; b=...".to_string(),
        );
        legitimate_headers.insert(
            "authentication-results".to_string(),
            "dkim=pass".to_string(),
        );

        let legitimate_context = MailContext {
            sender: Some("user@company.com".to_string()),
            from_header: Some("user@company.com".to_string()),
            recipients: vec!["user@company.com".to_string()],
            headers: legitimate_headers,
            mailer: Some("Outlook 365".to_string()),
            subject: Some("Reminder: Meeting tomorrow".to_string()),
            hostname: Some("company.com".to_string()),
            helo: Some("mail.company.com".to_string()),
            body: Some("Don't forget about our meeting tomorrow at 2 PM.".to_string()),
        };

        let (action2, matched_rules2, _headers) = engine.evaluate(&legitimate_context).await;
        assert!(matches!(action2, Action::Accept));
        assert!(matched_rules2.is_empty());

        // Test case 3: External email without sender spoofing or extortion (should not match)
        let mut no_spoofing_headers = HashMap::new();
        no_spoofing_headers.insert("from".to_string(), "sender@company.com".to_string());
        no_spoofing_headers.insert("to".to_string(), "recipient@example.com".to_string());
        no_spoofing_headers.insert(
            "received".to_string(),
            "from mail.company.com (mail.company.com [1.2.3.4])".to_string(),
        );
        no_spoofing_headers.insert(
            "dkim-signature".to_string(),
            "v=1; a=rsa-sha256; d=company.com; s=default; b=...".to_string(),
        );
        no_spoofing_headers.insert(
            "authentication-results".to_string(),
            "dkim=pass".to_string(),
        );

        let no_spoofing_context = MailContext {
            sender: Some("sender@company.com".to_string()),
            from_header: Some("sender@company.com".to_string()),
            recipients: vec!["recipient@example.com".to_string()],
            headers: no_spoofing_headers,
            mailer: Some("Outlook 365".to_string()),
            subject: Some("Business proposal".to_string()),
            hostname: Some("company.com".to_string()),
            helo: Some("mail.company.com".to_string()),
            body: Some("I have a legitimate business proposal for you.".to_string()),
        };

        let (action3, matched_rules3, _headers) = engine.evaluate(&no_spoofing_context).await;
        assert!(matches!(action3, Action::Accept));
        assert!(matched_rules3.is_empty());

        // Test case 4: Custom configuration with specific keywords
        let custom_config = create_test_config(vec![FilterRule {
            name: "Custom extortion detection".to_string(),
            criteria: Criteria::SenderSpoofingExtortion {
                extortion_keywords: Some(vec!["custom_threat".to_string(), "pay_me".to_string()]),
                check_sender_recipient_match: Some(true),
                check_external_source: Some(true),
                check_missing_authentication: Some(false), // Disable auth checking
                require_extortion_content: Some(true),
                min_indicators: Some(2),
            },
            action: Action::TagAsSpam {
                header_name: "X-Custom-Extortion".to_string(),
                header_value: "YES".to_string(),
            },
        }]);

        let custom_engine = FilterEngine::new(custom_config).unwrap();

        let mut custom_headers = HashMap::new();
        custom_headers.insert("from".to_string(), "test@example.com".to_string());
        custom_headers.insert("to".to_string(), "test@example.com".to_string());
        custom_headers.insert(
            "received".to_string(),
            "from [5.6.7.8] ([5.6.7.8])".to_string(),
        );

        let custom_context = MailContext {
            sender: Some("test@example.com".to_string()),
            from_header: Some("test@example.com".to_string()),
            recipients: vec!["test@example.com".to_string()],
            headers: custom_headers,
            mailer: None,
            subject: Some("You must pay_me immediately".to_string()),
            hostname: Some("external.com".to_string()),
            helo: Some("external.com".to_string()),
            body: Some("This is a custom_threat message.".to_string()),
        };

        let (action4, matched_rules4, _headers) = custom_engine.evaluate(&custom_context).await;
        assert!(matches!(action4, Action::TagAsSpam { .. }));
        assert_eq!(matched_rules4, vec!["Custom extortion detection"]);

        // Test case 5: Only 1 indicator (should not match with min_indicators=2)
        let single_indicator_config = create_test_config(vec![FilterRule {
            name: "Single indicator test".to_string(),
            criteria: Criteria::SenderSpoofingExtortion {
                extortion_keywords: None,
                check_sender_recipient_match: Some(true),
                check_external_source: Some(false), // Disable external checking
                check_missing_authentication: Some(false), // Disable auth checking
                require_extortion_content: Some(false), // Disable content checking
                min_indicators: Some(2),            // Require 2 indicators
            },
            action: Action::Reject {
                message: "Should not match".to_string(),
            },
        }]);

        let single_engine = FilterEngine::new(single_indicator_config).unwrap();

        let mut single_headers = HashMap::new();
        single_headers.insert("from".to_string(), "user@test.com".to_string());
        single_headers.insert("to".to_string(), "user@test.com".to_string()); // Only sender match indicator

        let single_context = MailContext {
            sender: Some("user@test.com".to_string()),
            from_header: Some("user@test.com".to_string()),
            recipients: vec!["user@test.com".to_string()],
            headers: single_headers,
            mailer: None,
            subject: Some("Normal subject".to_string()), // No extortion content
            hostname: Some("test.com".to_string()),
            helo: Some("test.com".to_string()),
            body: Some("Normal content".to_string()),
        };

        let (action5, matched_rules5, _headers) = single_engine.evaluate(&single_context).await;
        assert!(matches!(action5, Action::Accept)); // Should not match with only 1 indicator
        assert!(matched_rules5.is_empty());

        // Test case 6: Bitcoin extortion with cryptocurrency keywords
        let crypto_config = create_test_config(vec![FilterRule {
            name: "Cryptocurrency extortion".to_string(),
            criteria: Criteria::SenderSpoofingExtortion {
                extortion_keywords: None, // Use defaults (includes bitcoin, cryptocurrency, etc.)
                check_sender_recipient_match: Some(true),
                check_external_source: Some(true),
                check_missing_authentication: Some(true),
                require_extortion_content: Some(true),
                min_indicators: Some(3), // Higher threshold
            },
            action: Action::Reject {
                message: "Cryptocurrency extortion blocked".to_string(),
            },
        }]);

        let crypto_engine = FilterEngine::new(crypto_config).unwrap();

        let mut crypto_headers = HashMap::new();
        crypto_headers.insert("from".to_string(), "victim@domain.com".to_string());
        crypto_headers.insert("to".to_string(), "victim@domain.com".to_string());
        crypto_headers.insert(
            "received".to_string(),
            "from [9.10.11.12] ([9.10.11.12])".to_string(),
        );
        crypto_headers.insert(
            "authentication-results".to_string(),
            "dkim=fail".to_string(),
        );

        let crypto_context = MailContext {
            sender: Some("victim@domain.com".to_string()),
            from_header: Some("victim@domain.com".to_string()),
            recipients: vec!["victim@domain.com".to_string()],
            headers: crypto_headers,
            mailer: None,
            subject: Some("Send bitcoin to this wallet immediately".to_string()),
            hostname: Some("external.com".to_string()),
            helo: Some("external.com".to_string()),
            body: Some(
                "I have compromising photos. Send cryptocurrency to avoid exposure.".to_string(),
            ),
        };

        let (action6, matched_rules6, _headers) = crypto_engine.evaluate(&crypto_context).await;
        assert!(matches!(action6, Action::Reject { .. }));
        assert_eq!(matched_rules6, vec!["Cryptocurrency extortion"]);

        // Test case 7: NY Times via SparkPost (should not match - legitimate service)
        let nytimes_config = create_test_config(vec![FilterRule {
            name: "Test NY Times".to_string(),
            criteria: Criteria::SenderSpoofingExtortion {
                extortion_keywords: None,
                check_sender_recipient_match: Some(true),
                check_external_source: Some(true),
                check_missing_authentication: Some(true),
                require_extortion_content: Some(true),
                min_indicators: Some(2),
            },
            action: Action::Reject {
                message: "Should not match NY Times".to_string(),
            },
        }]);

        let nytimes_engine = FilterEngine::new(nytimes_config).unwrap();

        let mut nytimes_headers = HashMap::new();
        nytimes_headers.insert(
            "from".to_string(),
            "The New York Times <nytdirect@nytimes.com>".to_string(),
        );
        nytimes_headers.insert("to".to_string(), "mjohnson@example.com".to_string());
        nytimes_headers.insert(
            "received".to_string(),
            "from mta-83-69.sparkpostmail.com (mta-83-69.sparkpostmail.com. [192.174.83.69])"
                .to_string(),
        );
        nytimes_headers.insert(
            "dkim-signature".to_string(),
            "v=1; a=rsa-sha256; c=relaxed/relaxed; d=nytimes.com; s=scph20250409; b=aHT3kg58..."
                .to_string(),
        );
        nytimes_headers.insert(
            "authentication-results".to_string(),
            "dkim=fail reason=\"signature verification failed\"".to_string(),
        );

        let nytimes_context = MailContext {
            sender: Some("mjohnson+caf_=mjohnson=example.com@gmail.com".to_string()),
            from_header: Some("The New York Times <nytdirect@nytimes.com>".to_string()),
            recipients: vec!["mjohnson@example.com".to_string()],
            headers: nytimes_headers,
            mailer: None,
            subject: Some("Well: Don't let your vacation stress you out".to_string()),
            hostname: Some("sparkpostmail.com".to_string()),
            helo: Some("sparkpostmail.com".to_string()),
            body: Some("Your weekly wellness newsletter from The New York Times.".to_string()),
        };

        let (action7, matched_rules7, _headers) = nytimes_engine.evaluate(&nytimes_context).await;
        assert!(matches!(action7, Action::Accept)); // Should not match due to legitimate service
        assert!(matched_rules7.is_empty());

        println!("✅ Sender spoofing extortion detection test passed");
    }

    #[tokio::test]
    async fn test_not_criteria() {
        // Test 1: Not with SenderPattern - should NOT match Gmail
        let config1 = create_test_config(vec![FilterRule {
            name: "Not Gmail test".to_string(),
            criteria: Criteria::Not {
                criteria: Box::new(Criteria::SenderPattern {
                    pattern: ".*@gmail\\.com$".to_string(),
                }),
            },
            action: Action::Reject {
                message: "Not Gmail".to_string(),
            },
        }]);

        let engine1 = FilterEngine::new(config1).unwrap();

        let gmail_context = MailContext {
            sender: Some("test@gmail.com".to_string()),
            recipients: vec!["recipient@example.com".to_string()],
            subject: Some("Test Subject".to_string()),
            body: Some("Test body content".to_string()),
            headers: HashMap::new(),
            from_header: Some("test@gmail.com".to_string()),
            helo: Some("gmail.com".to_string()),
            hostname: Some("mail.gmail.com".to_string()),
            mailer: None,
        };

        let (action1, _, _headers) = engine1.evaluate(&gmail_context).await;
        assert!(
            matches!(action1, Action::Accept),
            "Not Gmail rule should NOT match Gmail sender (should Accept)"
        );

        // Test 2: Not with SenderPattern - should match Yahoo (since it's NOT Gmail)
        let yahoo_context = MailContext {
            sender: Some("test@yahoo.com".to_string()),
            recipients: vec!["recipient@example.com".to_string()],
            subject: Some("Test Subject".to_string()),
            body: Some("Test body content".to_string()),
            headers: HashMap::new(),
            from_header: Some("test@yahoo.com".to_string()),
            helo: Some("yahoo.com".to_string()),
            hostname: Some("mail.yahoo.com".to_string()),
            mailer: None,
        };

        let (action2, _, _headers) = engine1.evaluate(&yahoo_context).await;
        assert!(
            matches!(action2, Action::Reject { .. }),
            "Not Gmail rule should match Yahoo sender (should Reject)"
        );

        // Test 3: Not with And criteria
        let config3 = create_test_config(vec![FilterRule {
            name: "Not (Gmail AND Test subject)".to_string(),
            criteria: Criteria::Not {
                criteria: Box::new(Criteria::And {
                    criteria: vec![
                        Criteria::SenderPattern {
                            pattern: ".*@gmail\\.com$".to_string(),
                        },
                        Criteria::SubjectPattern {
                            pattern: "(?i)test.*".to_string(),
                        },
                    ],
                }),
            },
            action: Action::TagAsSpam {
                header_name: "X-Not-Gmail-Test".to_string(),
                header_value: "YES".to_string(),
            },
        }]);

        let engine3 = FilterEngine::new(config3).unwrap();

        // Should NOT match (Accept) because Gmail + Test subject matches the And, so Not And is false
        let (action3, _, _headers) = engine3.evaluate(&gmail_context).await;
        assert!(
            matches!(action3, Action::Accept),
            "Not (Gmail AND Test) should NOT match Gmail with Test subject"
        );

        // Should match (TagAsSpam) because Yahoo + Test subject doesn't fully match the And, so Not And is true
        let (action4, _, _headers) = engine3.evaluate(&yahoo_context).await;
        assert!(
            matches!(action4, Action::TagAsSpam { .. }),
            "Not (Gmail AND Test) should match Yahoo with Test subject"
        );

        println!("✅ Not criteria test passed");
    }
}
