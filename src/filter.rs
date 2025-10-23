use crate::abuse_reporter::AbuseReporter;
use crate::domain_age::DomainAgeChecker;
use crate::language::LanguageDetector;
use crate::legacy_config::{load_modules, Action, Config, Criteria, Module};
use crate::milter::extract_email_from_header;
use crate::toml_config::{BlocklistConfig, WhitelistConfig};

use hickory_resolver::TokioAsyncResolver;
use lazy_static::lazy_static;
use regex::Regex;

fn extract_domain_from_email(email: &str) -> Option<String> {
    email.split('@').nth(1).map(|s| s.to_string())
}

fn get_hostname() -> String {
    std::env::var("HOSTNAME")
        .or_else(|_| {
            use std::process::Command;
            Command::new("hostname")
                .output()
                .ok()
                .and_then(|output| {
                    if output.status.success() {
                        String::from_utf8(output.stdout)
                            .ok()
                            .map(|s| s.trim().to_string())
                    } else {
                        None
                    }
                })
                .ok_or(())
        })
        .unwrap_or_else(|_| "unknown".to_string())
}

fn extract_dkim_domain(dkim_sig: &str) -> Option<String> {
    // Extract d= parameter from DKIM signature
    for part in dkim_sig.split(';') {
        let part = part.trim();
        if let Some(stripped) = part.strip_prefix("d=") {
            return Some(stripped.to_string());
        }
    }
    None
}

fn extract_sender_domain(context: &MailContext) -> Option<String> {
    if let Some(from) = &context.from_header {
        if let Some(email) = extract_email_from_header(from) {
            extract_domain_from_email(&email)
        } else {
            None
        }
    } else {
        None
    }
}
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
    toml_config: Option<crate::toml_config::TomlConfig>,
    modules: Vec<Module>,
    compiled_patterns: HashMap<String, Regex>,
    #[allow(dead_code)] // TODO: Implement full abuse reporting integration
    abuse_reporter: AbuseReporter,
    // Heuristic actions
    heuristic_reject: Action,
    heuristic_spam: Action,
    // Whitelist configuration
    whitelist_config: Option<WhitelistConfig>,
    // Blocklist configuration
    blocklist_config: Option<BlocklistConfig>,
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
        println!("DEBUG: FilterEngine::new called");
        println!("DEBUG: module_config_dir = {:?}", config.module_config_dir);

        // Load modules if modular system is configured
        let modules = if let Some(module_dir) = &config.module_config_dir {
            println!("DEBUG: Loading modules from: {}", module_dir);
            match load_modules(module_dir) {
                Ok(modules) => {
                    println!("DEBUG: Successfully loaded {} modules", modules.len());
                    log::info!("Loaded {} modules from {}", modules.len(), module_dir);
                    modules
                }
                Err(e) => {
                    println!("DEBUG: Failed to load modules: {}", e);
                    log::warn!("Failed to load modules from {}: {}", module_dir, e);
                    Vec::new()
                }
            }
        } else {
            println!("DEBUG: No module_config_dir configured, using legacy rules");
            Vec::new()
        };

        let mut engine = FilterEngine {
            abuse_reporter: AbuseReporter::with_smtp_config(config.smtp.clone()),
            config,
            toml_config: None,
            modules,
            compiled_patterns: HashMap::new(),
            heuristic_reject: Action::Reject {
                message: "Message rejected by heuristic analysis".to_string(),
            },
            heuristic_spam: Action::TagAsSpam {
                header_name: "X-Spam-Flag".to_string(),
                header_value: "YES".to_string(),
            },
            whitelist_config: None,
            blocklist_config: None,
        };

        // Pre-compile all regex patterns for better performance
        engine.compile_patterns()?;
        Ok(engine)
    }

    pub fn set_toml_config(&mut self, toml_config: crate::toml_config::TomlConfig) {
        self.toml_config = Some(toml_config);
    }

    pub fn set_whitelist_config(&mut self, whitelist_config: Option<WhitelistConfig>) {
        self.whitelist_config = whitelist_config;
    }

    pub fn set_blocklist_config(&mut self, blocklist_config: Option<BlocklistConfig>) {
        self.blocklist_config = blocklist_config;
    }

    fn is_blocklisted(&self, context: &MailContext) -> bool {
        if let Some(blocklist) = &self.blocklist_config {
            if !blocklist.enabled {
                return false;
            }

            // Check sender email address
            if let Some(sender) = &context.sender {
                // Check exact addresses
                if blocklist.addresses.contains(sender) {
                    log::info!("Email blocklisted by exact address: {}", sender);
                    return true;
                }

                // Extract domain from sender
                if let Some(domain) = extract_domain_from_email(sender) {
                    // Check exact domains
                    if blocklist.domains.contains(&domain) {
                        log::info!("Email blocklisted by domain: {}", domain);
                        return true;
                    }

                    // Check domain patterns
                    for pattern in &blocklist.domain_patterns {
                        if let Ok(regex) = Regex::new(pattern) {
                            if regex.is_match(&domain) {
                                log::info!(
                                    "Email blocklisted by domain pattern '{}': {}",
                                    pattern,
                                    domain
                                );
                                return true;
                            }
                        }
                    }
                }
            }

            // Check From header if different from sender
            if let Some(from_header) = &context.from_header {
                if let Some(from_email) = extract_email_from_header(from_header) {
                    // Check exact addresses
                    if blocklist.addresses.contains(&from_email) {
                        log::info!("Email blocklisted by From header address: {}", from_email);
                        return true;
                    }

                    // Extract domain from From header
                    if let Some(domain) = extract_domain_from_email(&from_email) {
                        // Check exact domains
                        if blocklist.domains.contains(&domain) {
                            log::info!("Email blocklisted by From header domain: {}", domain);
                            return true;
                        }

                        // Check domain patterns
                        for pattern in &blocklist.domain_patterns {
                            if let Ok(regex) = Regex::new(pattern) {
                                if regex.is_match(&domain) {
                                    log::info!(
                                        "Email blocklisted by From header domain pattern '{}': {}",
                                        pattern,
                                        domain
                                    );
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

    fn is_whitelisted(&self, context: &MailContext) -> bool {
        if let Some(whitelist) = &self.whitelist_config {
            if !whitelist.enabled {
                return false;
            }

            // Check sender email address
            if let Some(sender) = &context.sender {
                // Check exact addresses
                if whitelist.addresses.contains(sender) {
                    log::info!("Email whitelisted by exact address: {}", sender);
                    return true;
                }

                // Extract domain from sender
                if let Some(domain) = extract_domain_from_email(sender) {
                    // Check exact domains
                    if whitelist.domains.contains(&domain) {
                        log::info!("Email whitelisted by domain: {}", domain);
                        return true;
                    }

                    // Check domain patterns
                    for pattern in &whitelist.domain_patterns {
                        if let Ok(regex) = Regex::new(pattern) {
                            if regex.is_match(&domain) {
                                log::info!(
                                    "Email whitelisted by domain pattern '{}': {}",
                                    pattern,
                                    domain
                                );
                                return true;
                            }
                        }
                    }
                }
            }

            // Check From header if different from sender
            if let Some(from_header) = &context.from_header {
                if let Some(from_email) = extract_email_from_header(from_header) {
                    // Check exact addresses
                    if whitelist.addresses.contains(&from_email) {
                        log::info!("Email whitelisted by From header address: {}", from_email);
                        return true;
                    }

                    // Extract domain from From header
                    if let Some(domain) = extract_domain_from_email(&from_email) {
                        // Check exact domains
                        if whitelist.domains.contains(&domain) {
                            log::info!("Email whitelisted by From header domain: {}", domain);
                            return true;
                        }

                        // Check domain patterns
                        for pattern in &whitelist.domain_patterns {
                            if let Ok(regex) = Regex::new(pattern) {
                                if regex.is_match(&domain) {
                                    log::info!(
                                        "Email whitelisted by From header domain pattern '{}': {}",
                                        pattern,
                                        domain
                                    );
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
        // Compile patterns from legacy rules
        let rules = self.config.rules.clone();
        for rule in &rules {
            // Skip disabled rules during pattern compilation
            if !rule.enabled {
                continue;
            }
            self.compile_criteria_patterns(&rule.criteria)?;
        }

        // Compile patterns from modules
        let modules = self.modules.clone();
        for module in &modules {
            for rule in &module.rules {
                // Skip disabled rules during pattern compilation
                if !rule.enabled {
                    continue;
                }
                self.compile_criteria_patterns(&rule.criteria)?;
            }
        }

        Ok(())
    }

    fn compile_criteria_patterns(&mut self, criteria: &Criteria) -> anyhow::Result<()> {
        match criteria {
            Criteria::MailerPattern { pattern }
            | Criteria::SenderPattern { pattern }
            | Criteria::RecipientPattern { pattern }
            | Criteria::SubjectPattern { pattern }
            | Criteria::BodyPattern { pattern } => {
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
            Criteria::DkimAnalysis { .. } => {
                // No regex patterns to compile for DKIM analysis
                // Uses string parsing and domain extraction instead
            }
            Criteria::LanguageGeographyMismatch {
                domain_pattern,
                content_pattern,
                ..
            } => {
                self.compiled_patterns
                    .insert(domain_pattern.clone(), Regex::new(domain_pattern)?);
                self.compiled_patterns
                    .insert(content_pattern.clone(), Regex::new(content_pattern)?);
            }
            Criteria::MixedScriptDetection { .. } => {
                // No regex patterns to compile for mixed script detection
                // Uses Unicode character range analysis instead
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
    ) -> (Action, Vec<String>, Vec<(String, String)>) {
        // Check whitelist first - if whitelisted, accept immediately
        if self.is_whitelisted(context) {
            log::info!("Email whitelisted, accepting without further processing");
            return (Action::Accept, vec!["Whitelisted".to_string()], vec![]);
        }

        // Check blocklist second - if blocklisted, reject immediately
        if self.is_blocklisted(context) {
            log::info!("Email blocklisted, rejecting immediately");
            let (reject_action, headers) = if let Some(ref toml_config) = self.toml_config {
                if toml_config.system.reject_to_tag {
                    let headers = vec![
                        (
                            "X-FOFF-Reject-Converted".to_string(),
                            "WOULD-REJECT: Message rejected by blocklist".to_string(),
                        ),
                        ("X-Spam-Flag".to_string(), "YES".to_string()),
                    ];
                    (self.heuristic_spam.clone(), headers)
                } else {
                    (self.heuristic_reject.clone(), vec![])
                }
            } else {
                (self.heuristic_reject.clone(), vec![])
            };
            return (reject_action, vec!["Blocklisted".to_string()], headers);
        }

        let mut matched_rules = Vec::new();
        let mut all_actions = Vec::new();
        let mut final_action = &self.config.default_action;
        let mut headers_to_add = Vec::new();
        let mut total_score = 0i32;
        let mut scoring_rules = Vec::new();

        // Process modules first if modular system is enabled
        if !self.modules.is_empty() {
            log::info!("Processing {} modules", self.modules.len());

            for module in &self.modules {
                log::info!("Processing module: {}", module.name);

                for (rule_index, rule) in module.rules.iter().enumerate() {
                    // Skip disabled rules
                    if !rule.enabled {
                        log::debug!(
                            "Module '{}' Rule {} '{}' is disabled, skipping",
                            module.name,
                            rule_index + 1,
                            rule.name
                        );
                        continue;
                    }

                    let matches = self.evaluate_criteria(&rule.criteria, context).await;
                    log::info!(
                        "Module '{}' Rule {} '{}' evaluation result: {}",
                        module.name,
                        rule_index + 1,
                        rule.name,
                        matches
                    );

                    if matches {
                        matched_rules.push(format!("{}: {}", module.name, rule.name));

                        // Accumulate score if present
                        if let Some(score) = rule.score {
                            total_score += score;
                            scoring_rules
                                .push(format!("{}: {} (+{})", module.name, rule.name, score));
                            log::info!(
                                "Module '{}' Rule '{}' matched, score: +{}, total: {}",
                                module.name,
                                rule.name,
                                score,
                                total_score
                            );
                        } else {
                            // Fallback to action-based for rules without scores
                            all_actions.push(&rule.action);
                            log::info!(
                                "Module '{}' Rule '{}' matched, action: {:?}",
                                module.name,
                                rule.name,
                                rule.action
                            );

                            // Handle action precedence for non-scoring rules
                            match &rule.action {
                                Action::Accept => {
                                    final_action = &rule.action;
                                    break; // Stop processing on Accept
                                }
                                Action::Reject { .. } => {
                                    final_action = &rule.action;
                                }
                                Action::TagAsSpam { .. } => {
                                    if matches!(final_action, Action::Accept) {
                                        final_action = &rule.action;
                                    }
                                }
                                _ => {}
                            }
                        }

                        // Add rule-specific header (consolidated format)
                        headers_to_add.push((
                            "X-FOFF-Rule-Matched".to_string(),
                            format!("{}: {} ({})", module.name, rule.name, get_hostname()),
                        ));
                    }
                }
            }

            // Apply heuristic scoring if we have scoring rules
            if !scoring_rules.is_empty() {
                log::info!(
                    "Heuristic evaluation: total_score={}, rules: [{}]",
                    total_score,
                    scoring_rules.join(", ")
                );

                // Add score header
                headers_to_add.push((
                    "X-FOFF-Score".to_string(),
                    format!(
                        "{} - foff-milter v{} ({})",
                        total_score,
                        self.config.version,
                        get_hostname()
                    ),
                ));

                // Determine action based on thresholds
                let spam_threshold = self.toml_config
                    .as_ref()
                    .and_then(|c| c.heuristics.as_ref())
                    .map(|h| h.spam_threshold)
                    .unwrap_or(50);
                
                if total_score >= 100 {
                    final_action = &self.heuristic_reject;
                    log::info!("Heuristic result: REJECT (score {} >= 100)", total_score);
                } else if total_score >= spam_threshold {
                    final_action = &self.heuristic_spam;
                    log::info!(
                        "Heuristic result: TAG AS SPAM (score {} >= {})",
                        total_score, spam_threshold
                    );
                } else {
                    log::info!("Heuristic result: ACCEPT (score {} < {})", total_score, spam_threshold);
                }
            }

            // If modules processed, return early
            if !matched_rules.is_empty() {
                log::info!(
                    "Matched {} module rules: [{}], final action: {:?}",
                    matched_rules.len(),
                    matched_rules.join(", "),
                    final_action
                );
                // Convert REJECT to TAG if setting is enabled
                let (converted_action, mut conversion_headers) =
                    if let Some(ref toml_config) = self.toml_config {
                        if toml_config.system.reject_to_tag {
                            if let Action::Reject { message } = final_action {
                                let headers = vec![
                                    (
                                        "X-FOFF-Reject-Converted".to_string(),
                                        format!("WOULD-REJECT: {}", message),
                                    ),
                                    ("X-Spam-Flag".to_string(), "YES".to_string()),
                                ];
                                (self.heuristic_spam.clone(), headers)
                            } else {
                                (final_action.clone(), vec![])
                            }
                        } else {
                            (final_action.clone(), vec![])
                        }
                    } else {
                        (final_action.clone(), vec![])
                    };
                headers_to_add.append(&mut conversion_headers);
                return (converted_action, matched_rules, headers_to_add);
            }
        }

        // Process legacy rules if no modules or no module matches
        for (rule_index, rule) in self.config.rules.iter().enumerate() {
            // Skip disabled rules
            if !rule.enabled {
                log::debug!(
                    "Rule {} '{}' is disabled, skipping",
                    rule_index + 1,
                    rule.name
                );
                continue;
            }

            let matches = self.evaluate_criteria(&rule.criteria, context).await;
            log::info!(
                "Rule {} '{}' evaluation result: {}",
                rule_index + 1,
                rule.name,
                matches
            );

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
                    // Add whitelist analysis header
                    headers_to_add.push((
                        "X-FOFF-Whitelist".to_string(),
                        format!("whitelisted by rule: {}", rule.name),
                    ));
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
                "X-FOFF-Score".to_string(),
                format!(
                    "{} - analyzed by foff-milter v{} on {}",
                    total_score,
                    self.config.version,
                    get_hostname()
                ),
            ));
        } else {
            log::info!(
                "Matched {} rules: {:?}, final action: {:?}",
                matched_rules.len(),
                matched_rules,
                final_action
            );
            // Add analysis header when rules match (if not already added by whitelist)
            if !headers_to_add
                .iter()
                .any(|(name, _)| name == "X-FOFF-Score" || name == "X-FOFF-Whitelist")
            {
                headers_to_add.push((
                    "X-FOFF-Score".to_string(),
                    format!(
                        "{} - foff-milter v{} ({}) - matched: {}",
                        total_score,
                        self.config.version,
                        get_hostname(),
                        matched_rules.join(", ")
                    ),
                ));
            }
        }

        // Convert REJECT to TAG if setting is enabled
        let (final_action, headers_to_add) = if let Some(ref toml_config) = self.toml_config {
            if toml_config.system.reject_to_tag {
                if let Action::Reject { message } = final_action {
                    // Add both the conversion header and the standard spam flag
                    let mut headers = headers_to_add;
                    headers.push((
                        "X-FOFF-Reject-Converted".to_string(),
                        format!("WOULD-REJECT: {}", message),
                    ));
                    headers.push(("X-Spam-Flag".to_string(), "YES".to_string()));
                    (self.heuristic_spam.clone(), headers)
                } else {
                    (final_action.clone(), headers_to_add)
                }
            } else {
                (final_action.clone(), headers_to_add)
            }
        } else {
            (final_action.clone(), headers_to_add)
        };

        (final_action, matched_rules, headers_to_add)
    }

    /// Get all matched rules with their actions (for processing all rules)
    pub async fn evaluate_all(&self, context: &MailContext) -> (Vec<(&str, &Action)>, &Action) {
        let mut matched_rules_with_actions = Vec::new();
        let mut final_action = &self.config.default_action;

        // Process ALL rules and collect matches
        for rule in &self.config.rules {
            // Skip disabled rules
            if !rule.enabled {
                log::debug!("Rule '{}' is disabled, skipping", rule.name);
                continue;
            }

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
                            log::debug!(
                                "SenderPattern checking from_header: '{}' against pattern: '{}'",
                                from_header,
                                pattern
                            );
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
                Criteria::BodyPattern { pattern } => {
                    if let Some(body) = &context.body {
                        if let Some(regex) = self.compiled_patterns.get(pattern) {
                            return regex.is_match(body);
                        }
                    }
                    false
                }
                Criteria::HeaderPattern { header, pattern } => {
                    if let Some(header_value) = context.headers.get(header) {
                        // DEBUG: Log exact header value for authentication-results
                        if header == "authentication-results" {
                            log::info!(
                                "DEBUG: authentication-results header value: '{}'",
                                header_value
                            );
                            log::info!("DEBUG: pattern to match: '{}'", pattern);
                        }

                        if let Some(regex) = self.compiled_patterns.get(pattern) {
                            // Decode MIME headers before pattern matching
                            let decoded_value = crate::milter::decode_mime_header(header_value);
                            let matches = regex.is_match(&decoded_value);

                            // DEBUG: Log pattern matching result for authentication-results
                            if header == "authentication-results" {
                                log::info!("DEBUG: decoded value: '{}'", decoded_value);
                                log::info!("DEBUG: regex match result: {}", matches);
                            }

                            return matches;
                        }
                    } else if header == "authentication-results" {
                        log::info!("DEBUG: authentication-results header NOT FOUND in context");
                        log::info!(
                            "DEBUG: available headers: {:?}",
                            context.headers.keys().collect::<Vec<_>>()
                        );
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
                    allow_sender_domain,
                    allow_email_infrastructure,
                    email_infrastructure_domains,
                } => {
                    log::debug!("Checking for suspicious links in email body");

                    let check_shorteners = check_url_shorteners.unwrap_or(true);
                    let check_tlds = check_suspicious_tlds.unwrap_or(true);
                    let check_ips = check_ip_addresses.unwrap_or(true);
                    let allow_sender = allow_sender_domain.unwrap_or(false);
                    let allow_infra = allow_email_infrastructure.unwrap_or(false);

                    // Get sender domain for whitelist checking
                    let sender_domain = if allow_sender {
                        extract_sender_domain(context)
                    } else {
                        None
                    };

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
                                    // Check whitelist first - skip if domain is whitelisted
                                    let mut is_whitelisted = false;

                                    // Check sender domain whitelist
                                    if let Some(ref sender_domain) = sender_domain {
                                        if host.ends_with(sender_domain) {
                                            log::debug!(
                                                "URL {} whitelisted (sender domain: {})",
                                                url,
                                                sender_domain
                                            );
                                            is_whitelisted = true;
                                        }
                                    }

                                    // Check email infrastructure whitelist
                                    if !is_whitelisted && allow_infra {
                                        if let Some(ref infra_domains) =
                                            email_infrastructure_domains
                                        {
                                            for infra_domain in infra_domains {
                                                if host.ends_with(infra_domain) {
                                                    log::debug!("URL {} whitelisted (infrastructure domain: {})", url, infra_domain);
                                                    is_whitelisted = true;
                                                    break;
                                                }
                                            }
                                        }
                                    }

                                    // Skip suspicious checks if whitelisted
                                    if is_whitelisted {
                                        continue;
                                    }

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
                Criteria::DkimAnalysis {
                    require_signature,
                    check_domain_mismatch,
                    detect_spoofing,
                    brand_domains,
                    suspicious_domains,
                } => {
                    log::debug!("Checking DKIM analysis");

                    let require_sig = require_signature.unwrap_or(true);
                    let check_mismatch = check_domain_mismatch.unwrap_or(true);
                    let suspicious_list = suspicious_domains
                        .as_ref()
                        .map(|v| v.as_slice())
                        .unwrap_or(&[]);

                    let mut auth_failure_indicators = 0;

                    // Check for DKIM signature presence
                    let has_dkim_signature = context.headers.contains_key("dkim-signature");
                    let has_domainkey_signature =
                        context.headers.contains_key("domainkey-signature");

                    if require_sig && !has_dkim_signature && !has_domainkey_signature {
                        auth_failure_indicators += 1;
                        log::debug!("No DKIM or DomainKey signatures found");
                    }

                    // Check for domain mismatch in DKIM signature
                    if check_mismatch && has_dkim_signature {
                        if let Some(dkim_sig) = context.headers.get("dkim-signature") {
                            // Extract domain from DKIM signature (d= parameter)
                            if let Some(dkim_domain) = extract_dkim_domain(dkim_sig) {
                                // Extract domain from sender
                                if let Some(sender_domain) = extract_sender_domain(context) {
                                    if dkim_domain != sender_domain {
                                        auth_failure_indicators += 1;
                                        log::debug!(
                                            "DKIM domain mismatch: signature={}, sender={}",
                                            dkim_domain,
                                            sender_domain
                                        );
                                    }
                                }
                            }
                        }
                    }

                    // Check for suspicious domains in DKIM signature
                    if has_dkim_signature {
                        if let Some(dkim_sig) = context.headers.get("dkim-signature") {
                            if let Some(dkim_domain) = extract_dkim_domain(dkim_sig) {
                                for suspicious in suspicious_list {
                                    if dkim_domain.contains(suspicious) {
                                        auth_failure_indicators += 1;
                                        log::debug!(
                                            "Suspicious domain in DKIM signature: {}",
                                            dkim_domain
                                        );
                                        break;
                                    }
                                }
                            }
                        }
                    }

                    // Check for multi-domain DKIM spoofing
                    if detect_spoofing.unwrap_or(false) {
                        if let Some(brands) = brand_domains {
                            if self.detect_multi_domain_spoofing(context, brands).await {
                                auth_failure_indicators += 1;
                                log::debug!("Multi-domain DKIM spoofing detected");
                            }
                        }
                    }

                    let has_auth_failure = auth_failure_indicators > 0;

                    if has_auth_failure {
                        log::debug!(
                            "DKIM authentication failure detected: {} indicators",
                            auth_failure_indicators
                        );
                    }

                    has_auth_failure
                }
                Criteria::LanguageGeographyMismatch {
                    domain_pattern,
                    content_pattern,
                    ..
                } => {
                    log::debug!("Checking language/geography mismatch");

                    // Get sender domain
                    let sender_domain = extract_sender_domain(context).unwrap_or_default();

                    // Check if domain matches the pattern
                    if let Some(domain_regex) = self.compiled_patterns.get(domain_pattern) {
                        if domain_regex.is_match(&sender_domain) {
                            // Check if content matches the language pattern
                            let combined_text = format!(
                                "{} {}",
                                context.subject.as_deref().unwrap_or(""),
                                context.body.as_deref().unwrap_or("")
                            );
                            if let Some(content_regex) = self.compiled_patterns.get(content_pattern)
                            {
                                let is_match = content_regex.is_match(&combined_text);
                                log::debug!(
                                    "Language/geography mismatch check: domain={}, match={}",
                                    sender_domain,
                                    is_match
                                );
                                return is_match;
                            }
                        }
                    }
                    false
                }
                Criteria::MixedScriptDetection {
                    suspicious_combinations,
                    threshold,
                } => {
                    log::debug!("Checking mixed script detection");

                    let combined_text = format!(
                        "{} {}",
                        context.subject.as_deref().unwrap_or(""),
                        context.body.as_deref().unwrap_or("")
                    );
                    let mut detected_combinations = 0;

                    let has_latin = combined_text.chars().any(|c| c.is_ascii_alphabetic());
                    let has_cyrillic = combined_text
                        .chars()
                        .any(|c| matches!(c, '\u{0400}'..='\u{04FF}'));
                    let has_arabic = combined_text
                        .chars()
                        .any(|c| matches!(c, '\u{0600}'..='\u{06FF}'));
                    let has_cjk = combined_text.chars().any(|c| matches!(c, '\u{4E00}'..='\u{9FFF}' | '\u{3040}'..='\u{309F}' | '\u{30A0}'..='\u{30FF}' | '\u{AC00}'..='\u{D7AF}'));

                    for combination in suspicious_combinations {
                        match combination.as_str() {
                            "latin_cyrillic" if has_latin && has_cyrillic => {
                                detected_combinations += 1
                            }
                            "latin_arabic" if has_latin && has_arabic => detected_combinations += 1,
                            "latin_cjk_excessive" if has_latin && has_cjk => {
                                let latin_count = combined_text
                                    .chars()
                                    .filter(|c| c.is_ascii_alphabetic())
                                    .count();
                                let cjk_count = combined_text.chars().filter(|c| matches!(*c, '\u{4E00}'..='\u{9FFF}' | '\u{3040}'..='\u{309F}' | '\u{30A0}'..='\u{30FF}' | '\u{AC00}'..='\u{D7AF}')).count();
                                if latin_count > 10 && cjk_count > 10 {
                                    detected_combinations += 1;
                                }
                            }
                            _ => {}
                        }
                    }

                    let is_suspicious = detected_combinations >= *threshold;
                    log::debug!(
                        "Mixed script detection: combinations={}, threshold={}, suspicious={}",
                        detected_combinations,
                        threshold,
                        is_suspicious
                    );
                    is_suspicious
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

    /// Detect multi-domain DKIM spoofing by analyzing authentication results and DKIM signatures
    async fn detect_multi_domain_spoofing(
        &self,
        context: &MailContext,
        brand_domains: &[String],
    ) -> bool {
        // Get all authentication results headers
        let auth_headers: Vec<_> = context
            .headers
            .iter()
            .filter(|(key, _)| key.to_lowercase() == "authentication-results")
            .collect();

        // Check for brand domain DKIM failures
        for (_, auth_value) in &auth_headers {
            if auth_value.contains("dkim=fail") {
                // Extract domain from authentication results
                if let Some(domain) = self.extract_domain_from_auth_results(auth_value) {
                    // Check if it's a brand domain
                    for brand in brand_domains {
                        if domain.to_lowercase() == brand.to_lowercase() {
                            log::debug!("Brand domain DKIM failure detected: {}", domain);
                            return true;
                        }
                    }
                }
            }
        }

        false
    }

    /// Extract domain from authentication results header
    fn extract_domain_from_auth_results(&self, auth_results: &str) -> Option<String> {
        // Look for header.d= parameter in authentication results
        for part in auth_results.split_whitespace() {
            if part.starts_with("header.d=") {
                let domain = part.trim_start_matches("header.d=");
                return Some(domain.to_string());
            }
        }
        None
    }
}
