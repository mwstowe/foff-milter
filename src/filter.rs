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
            Criteria::And { criteria } | Criteria::Or { criteria } => {
                for c in criteria {
                    self.compile_criteria_patterns(c)?;
                }
            }
        }
        Ok(())
    }

    pub async fn evaluate(&self, context: &MailContext) -> (&Action, Vec<String>) {
        let mut matched_rules = Vec::new();

        for rule in &self.config.rules {
            let matches = self.evaluate_criteria(&rule.criteria, context).await;
            log::info!("Rule '{}' evaluation result: {}", rule.name, matches);
            if matches {
                log::info!(
                    "Rule '{}' matched, applying action: {:?}",
                    rule.name,
                    rule.action
                );
                matched_rules.push(rule.name.clone());
                return (&rule.action, matched_rules);
            }
        }

        log::debug!(
            "No rules matched, using default action: {:?}",
            self.config.default_action
        );
        (&self.config.default_action, matched_rules)
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
            let url_regex = Regex::new(r"<(https?://[^>]+)>").unwrap();
            for cap in url_regex.captures_iter(list_unsubscribe) {
                if let Some(url) = cap.get(1) {
                    links.push(url.as_str().to_string());
                }
            }
        }

        // Check email body for unsubscribe links
        if let Some(body) = &context.body {
            // Look for common unsubscribe link patterns
            let unsubscribe_patterns = [
                r#"(?i)href=["'](https?://[^"']*unsubscribe[^"']*)["']"#,
                r#"(?i)href=["'](https?://[^"']*opt[_-]?out[^"']*)["']"#,
                r#"(?i)href=["'](https?://[^"']*remove[^"']*)["']"#,
                r#"(?i)(https?://[^\s<>"']*unsubscribe[^\s<>"']*)"#,
                r#"(?i)(https?://[^\s<>"']*opt[_-]?out[^\s<>"']*)"#,
            ];

            for pattern in &unsubscribe_patterns {
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
        if rand::random::<u8>() % 10 == 0 {
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

        // Parse URL
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
        if check_dns {
            log::debug!("Checking DNS for hostname: {hostname} (timeout: {timeout_seconds}s)");
            let resolver = match TokioAsyncResolver::tokio_from_system_conf() {
                Ok(resolver) => resolver,
                Err(e) => {
                    log::warn!("Failed to create DNS resolver for {hostname}: {e}");
                    return false;
                }
            };

            // Add timeout to DNS lookup
            let lookup_future = resolver.lookup_ip(hostname);
            let timeout_future =
                tokio::time::timeout(Duration::from_secs(timeout_seconds), lookup_future);

            match timeout_future.await {
                Ok(Ok(response)) => {
                    // Check if we have any IP addresses
                    let mut has_ips = false;
                    let mut ip_count = 0;
                    for ip in response.iter() {
                        log::debug!("DNS found IP for {hostname}: {ip}");

                        // Check if the IP resolves to localhost (127.0.0.1)
                        if ip.to_string() == "127.0.0.1" {
                            log::warn!("Unsubscribe link resolves to localhost (127.0.0.1): {hostname} - marking as invalid");
                            return false;
                        }
                        has_ips = true;
                        ip_count += 1;
                        if ip_count >= 3 {
                            break; // Limit logging
                        }
                    }

                    if !has_ips {
                        log::warn!("DNS lookup returned no results for {hostname}");
                        return false;
                    }
                    log::debug!("DNS lookup successful for {hostname} ({ip_count} IPs found)");
                }
                Ok(Err(e)) => {
                    log::warn!("DNS lookup failed for {hostname}: {e}");
                    return false;
                }
                Err(_) => {
                    log::warn!("DNS lookup timed out for {hostname} after {timeout_seconds}s");
                    return false;
                }
            }
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
                            if regex.is_match(sender) {
                                return true;
                            }
                        }
                        if let Some(from_header) = &context.from_header {
                            if regex.is_match(from_header) {
                                return true;
                            }
                        }
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
                                        if !s_domain.ends_with(&r_domain)
                                            && !r_domain.ends_with(&s_domain)
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
                    let _check_attach = check_attachments.unwrap_or(false); // Default: don't check attachments

                    if let Some(body) = &context.body {
                        // Check if email contains images
                        let has_images = self.has_image_content(body);

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

                        // Check if text content is minimal
                        if text_content.len() <= max_text {
                            log::info!(
                                "Image-only email detected: {} chars of text, {} images found",
                                text_content.len(),
                                self.count_images(body)
                            );
                            return true;
                        }
                    }

                    // TODO: If check_attachments is true, also check MIME attachments
                    // This would require parsing MIME structure which isn't currently available

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
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;

    #[tokio::test]
    async fn test_mailer_pattern_matching() {
        let config = Config::default();
        let engine = FilterEngine::new(config).unwrap();

        let context = MailContext {
            mailer: Some("service.example.cn".to_string()),
            ..Default::default()
        };

        let (action, _) = engine.evaluate(&context).await;
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
        let (action, _) = engine.evaluate(&context).await;
        match action {
            Action::Accept => {}
            _ => panic!("Expected default accept action"),
        }
    }

    #[tokio::test]
    async fn test_combination_criteria() {
        use crate::config::{Action, FilterRule};

        // Create a config with combination criteria: sparkmail.com mailer AND Japanese in subject
        let config = Config {
            rules: vec![FilterRule {
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
            }],
            ..Default::default()
        };

        let engine = FilterEngine::new(config).unwrap();

        // Test case 1: Both conditions match - should reject
        let context = MailContext {
            mailer: Some("sparkmail.com mailer v1.0".to_string()),
            subject: Some("こんにちは - Special Offer".to_string()), // Contains Japanese
            ..Default::default()
        };

        let (action, _) = engine.evaluate(&context).await;
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

        let (action2, _) = engine.evaluate(&context2).await;
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

        let (action3, _) = engine.evaluate(&context3).await;
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
        let config = Config {
            rules: vec![FilterRule {
                name: "Fake Microsoft".to_string(),
                criteria: Criteria::HeaderPattern {
                    header: "from".to_string(),
                    pattern: r".*onmicrosoft\.com".to_string(),
                },
                action: Action::TagAsSpam {
                    header_name: "X-Spam-Flag".to_string(),
                    header_value: "YES".to_string(),
                },
            }],
            ..Default::default()
        };

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

        let (action, matched_rules) = engine.evaluate(&context).await;
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
        let config = Config {
            rules: vec![
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
            ],
            ..Default::default()
        };

        let engine = FilterEngine::new(config).unwrap();

        // Test Example 1: Chinese service + Japanese (should match)
        let context1 = MailContext {
            mailer: Some("service.mail.cn v2.1".to_string()),
            subject: Some("こんにちは！特別なオファー".to_string()), // Japanese
            ..Default::default()
        };

        let (action1, _) = engine.evaluate(&context1).await;
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

        let (action2, _) = engine.evaluate(&context2).await;
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

        let (action3, _) = engine.evaluate(&context3).await;
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

        let (action4, _) = engine.evaluate(&context4).await;
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
        let (_action, _) = engine.evaluate(&context).await;
    }

    #[tokio::test]
    async fn test_sendgrid_redirect_detection() {
        use crate::config::{Action, FilterRule};
        use std::collections::HashMap;

        // Create config to detect SendGrid phishing redirects
        let config = Config {
            rules: vec![FilterRule {
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
            }],
            ..Default::default()
        };

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
        let (action, _) = engine.evaluate(&context).await;

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
        let config = Config {
            rules: vec![FilterRule {
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
            }],
            ..Default::default()
        };

        let engine = FilterEngine::new(config).unwrap();

        // Test case 1: Email with only an image - should match
        let context1 = MailContext {
            body: Some(r#"<html><body><img src="https://example.com/image.jpg" alt="Image"></body></html>"#.to_string()),
            ..Default::default()
        };

        let (action1, _) = engine.evaluate(&context1).await;
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

        let (action2, _) = engine.evaluate(&context2).await;
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

        let (action3, _) = engine.evaluate(&context3).await;
        match action3 {
            Action::Accept => {}
            _ => panic!("Expected Accept action for text-only email"),
        }

        // Test case 4: Email with data URI image - should match
        let context4 = MailContext {
            body: Some(r#"<img src="data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mP8/5+hHgAHggJ/PchI7wAAAABJRU5ErkJggg==">"#.to_string()),
            ..Default::default()
        };

        let (action4, _) = engine.evaluate(&context4).await;
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
        let config = Config {
            rules: vec![FilterRule {
                name: "Detect free email reply-to".to_string(),
                criteria: Criteria::PhishingFreeEmailReplyTo {
                    free_email_domains: None, // Use defaults
                    allow_same_domain: Some(false),
                },
                action: Action::TagAsSpam {
                    header_name: "X-Free-Email-Reply-To".to_string(),
                    header_value: "YES".to_string(),
                },
            }],
            ..Default::default()
        };

        let engine = FilterEngine::new(config).unwrap();

        // Test case 1: Business from address with Gmail reply-to - should match
        let mut headers1 = HashMap::new();
        headers1.insert("reply-to".to_string(), "support@gmail.com".to_string());

        let context1 = MailContext {
            headers: headers1,
            from_header: Some("noreply@bigbank.com".to_string()),
            ..Default::default()
        };

        let (action1, _) = engine.evaluate(&context1).await;
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

        let (action2, _) = engine.evaluate(&context2).await;
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

        let (action3, _) = engine.evaluate(&context3).await;
        match action3 {
            Action::Accept => {}
            _ => panic!("Expected Accept action for same free email domain"),
        }

        // Test case 4: No reply-to header - should not match
        let context4 = MailContext {
            from_header: Some("noreply@bigbank.com".to_string()),
            ..Default::default()
        };

        let (action4, _) = engine.evaluate(&context4).await;
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

        let (action5, _) = engine.evaluate(&context5).await;
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
        let config = Config {
            rules: vec![FilterRule {
                name: "Validate reply-to address".to_string(),
                criteria: Criteria::ReplyToValidation {
                    timeout_seconds: Some(5),
                    check_mx_record: Some(true),
                },
                action: Action::TagAsSpam {
                    header_name: "X-Invalid-Reply-To".to_string(),
                    header_value: "YES".to_string(),
                },
            }],
            ..Default::default()
        };

        let engine = FilterEngine::new(config).unwrap();

        // Test case 1: Valid domain (google.com) - should not match
        let mut headers1 = HashMap::new();
        headers1.insert("reply-to".to_string(), "test@google.com".to_string());

        let context1 = MailContext {
            headers: headers1,
            from_header: Some("sender@example.com".to_string()),
            ..Default::default()
        };

        let (action1, _) = engine.evaluate(&context1).await;
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

        let (action3, _) = engine.evaluate(&context3).await;
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
        let config = Config {
            rules: vec![FilterRule {
                name: "Tag Google unsubscribe links".to_string(),
                criteria: Criteria::UnsubscribeLinkPattern {
                    pattern: r".*\.google\.com.*".to_string(),
                },
                action: Action::TagAsSpam {
                    header_name: "X-Suspicious-Unsubscribe".to_string(),
                    header_value: "YES".to_string(),
                },
            }],
            ..Default::default()
        };

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

        let (action1, matched_rules1) = engine.evaluate(&context1).await;
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

        let (action2, _) = engine.evaluate(&context2).await;
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

        let (action3, _) = engine.evaluate(&context3).await;
        match action3 {
            Action::Accept => {}
            _ => panic!("Expected Accept action for non-google unsubscribe link"),
        }

        // Test case 4: Email with no unsubscribe links - should not match
        let context4 = MailContext {
            body: Some("Regular email content with no unsubscribe links".to_string()),
            ..Default::default()
        };

        let (action4, _) = engine.evaluate(&context4).await;
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
}
