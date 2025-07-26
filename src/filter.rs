use crate::config::{Action, Config, Criteria};
use crate::language::LanguageDetector;

use hickory_resolver::TokioAsyncResolver;
use regex::Regex;
use std::collections::HashMap;
use std::time::Duration;
use url::Url;

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
            Criteria::And { criteria } | Criteria::Or { criteria } => {
                for c in criteria {
                    self.compile_criteria_patterns(c)?;
                }
            }
        }
        Ok(())
    }

    pub async fn evaluate(&self, context: &MailContext) -> &Action {
        for rule in &self.config.rules {
            let matches = self.evaluate_criteria(&rule.criteria, context).await;
            log::info!("Rule '{}' evaluation result: {}", rule.name, matches);
            if matches {
                log::info!(
                    "Rule '{}' matched, applying action: {:?}",
                    rule.name,
                    rule.action
                );
                return &rule.action;
            }
        }

        log::debug!(
            "No rules matched, using default action: {:?}",
            self.config.default_action
        );
        &self.config.default_action
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

    /// Validate an unsubscribe link
    async fn validate_unsubscribe_link(
        &self,
        url: &str,
        timeout_seconds: u64,
        check_dns: bool,
        check_http: bool,
    ) -> bool {
        log::debug!("Validating unsubscribe link: {url}");

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
                        has_ips = true;
                        ip_count += 1;
                        if ip_count >= 3 {
                            break;
                        } // Limit logging
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
                            return regex.is_match(header_value);
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
                        return LanguageDetector::contains_language(header_value, language);
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

                    let links = self.extract_unsubscribe_links(context);
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
                    for link in &links {
                        if !self
                            .validate_unsubscribe_link(link, timeout, dns_check, http_check)
                            .await
                        {
                            log::info!("UnsubscribeLinkValidation: Invalid unsubscribe link detected: {link} - returning true (MATCH)");
                            return true; // Found invalid link - matches criteria
                        }
                    }

                    log::info!("UnsubscribeLinkValidation: All unsubscribe links are valid - returning false (no match)");
                    false // All links are valid
                }
                Criteria::UnsubscribeLinkPattern { pattern } => {
                    log::debug!("Checking unsubscribe link pattern: {pattern}");

                    let links = self.extract_unsubscribe_links(context);

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
mod debug_tests {
    use crate::config::{Action, Config, Criteria, FilterRule};
    use crate::filter::{FilterEngine, MailContext};
    use std::collections::HashMap;

    #[tokio::test]
    async fn test_milter_header_extraction() {
        // Test the email extraction function
        let from_header = "=?utf-8?B?44Ki44Oh44Oq44Kr44Oz44O744Ko44Kt44K544OX44Os44K5?= <dm-hlxihj@service.gzutzc.cn>";
        let extracted = crate::milter::extract_email_from_header(from_header);
        println!("Extracted email: {:?}", extracted);
        assert_eq!(extracted, Some("dm-hlxihj@service.gzutzc.cn".to_string()));

        // Test with the actual rule
        let config = Config {
            socket_path: "/tmp/test.sock".to_string(),
            rules: vec![FilterRule {
                name: "Block Chinese services with Japanese content".to_string(),
                criteria: Criteria::And {
                    criteria: vec![
                        Criteria::Or {
                            criteria: vec![
                                Criteria::SenderPattern {
                                    pattern: r".*@service\.[^.]+\.cn$".to_string(),
                                },
                                Criteria::SenderPattern {
                                    pattern: r".*@service\..*\.cn$".to_string(),
                                },
                            ],
                        },
                        Criteria::SubjectContainsLanguage {
                            language: "japanese".to_string(),
                        },
                    ],
                },
                action: Action::Reject {
                    message: "Chinese service with Japanese content blocked".to_string(),
                },
            }],
            default_action: Action::Accept,
        };

        let engine = FilterEngine::new(config).unwrap();

        // Simulate what the milter would do: extract email from From header
        let mut headers = HashMap::new();
        headers.insert("from".to_string(), from_header.to_string());

        let context = MailContext {
            sender: Some("envelope@example.com".to_string()), // Envelope sender
            from_header: extracted,                           // From header sender
            subject: Some("限定ご招待｜大切な方と過ごすミシュランの夜".to_string()),
            headers,
            ..Default::default()
        };

        println!("Testing with extracted sender: {:?}", context.sender);

        let action = engine.evaluate(&context).await;
        println!("Milter simulation result: {:?}", action);

        match action {
            Action::Reject { .. } => {
                println!("SUCCESS: Rule matched with extracted email");
            }
            _ => {
                println!("FAILURE: Rule did not match with extracted email");
                panic!("Rule should have matched but didn't");
            }
        }
    }

    #[tokio::test]
    async fn test_exact_rule_from_user() {
        // Create the exact rule the user provided
        let config = Config {
            socket_path: "/tmp/test.sock".to_string(),
            rules: vec![FilterRule {
                name: "Block Chinese services with Japanese content".to_string(),
                criteria: Criteria::And {
                    criteria: vec![
                        Criteria::Or {
                            criteria: vec![
                                Criteria::SenderPattern {
                                    pattern: r".*@service\.[^.]+\.cn$".to_string(),
                                },
                                Criteria::SenderPattern {
                                    pattern: r".*@service\..*\.cn$".to_string(),
                                },
                            ],
                        },
                        Criteria::SubjectContainsLanguage {
                            language: "japanese".to_string(),
                        },
                    ],
                },
                action: Action::Reject {
                    message: "Chinese service with Japanese content blocked".to_string(),
                },
            }],
            default_action: Action::Accept,
        };

        let engine = FilterEngine::new(config).unwrap();

        // Create the exact email context from the headers
        let mut headers = HashMap::new();
        headers.insert("from".to_string(), "=?utf-8?B?44Ki44Oh44Oq44Kr44Oz44O744Ko44Kt44K544OX44Os44K5?= <dm-hlxihj@service.gzutzc.cn>".to_string());
        headers.insert("subject".to_string(), "=?utf-8?B?6ZmQ5a6a44GU5oub5b6F772c5aSn5YiH44Gq5pa544Go6YGO44GU44GZ44Of44K344Ol44Op44Oz44Gu?= =?utf-8?B?5aSc?=".to_string());

        let context = MailContext {
            sender: Some("dm-hlxihj@service.gzutzc.cn".to_string()),
            subject: Some("限定ご招待｜大切な方と過ごすミシュランの夜".to_string()),
            headers,
            ..Default::default()
        };

        println!("Testing sender: {:?}", context.sender);
        println!("Testing subject: {:?}", context.subject);

        let action = engine.evaluate(&context).await;
        println!("Action result: {:?}", action);

        match action {
            Action::Reject { .. } => {
                println!("SUCCESS: Rule matched as expected");
            }
            _ => {
                println!("FAILURE: Rule did not match");
                panic!("Rule should have matched but didn't");
            }
        }
    }

    #[tokio::test]
    async fn test_individual_criteria() {
        // Test each part separately

        // Test SenderPattern 1
        let config1 = Config {
            socket_path: "/tmp/test.sock".to_string(),
            rules: vec![FilterRule {
                name: "Test SenderPattern 1".to_string(),
                criteria: Criteria::SenderPattern {
                    pattern: r".*@service\.[^.]+\.cn$".to_string(),
                },
                action: Action::Reject {
                    message: "Pattern 1 matched".to_string(),
                },
            }],
            default_action: Action::Accept,
        };

        let engine1 = FilterEngine::new(config1).unwrap();

        // Debug: Print the compiled regex
        println!(
            "Compiled patterns: {:?}",
            engine1.compiled_patterns.keys().collect::<Vec<_>>()
        );
        for (pattern, regex) in &engine1.compiled_patterns {
            println!("Pattern '{}' -> Regex: {:?}", pattern, regex.as_str());
            let test_match = regex.is_match("dm-hlxihj@service.gzutzc.cn");
            println!("  Matches 'dm-hlxihj@service.gzutzc.cn': {}", test_match);
        }

        let context1 = MailContext {
            sender: Some("dm-hlxihj@service.gzutzc.cn".to_string()),
            ..Default::default()
        };

        let action1 = engine1.evaluate(&context1).await;
        println!("SenderPattern 1 result: {:?}", action1);

        // Test SenderPattern 2
        let config2 = Config {
            socket_path: "/tmp/test.sock".to_string(),
            rules: vec![FilterRule {
                name: "Test SenderPattern 2".to_string(),
                criteria: Criteria::SenderPattern {
                    pattern: r".*@service\..*\.cn$".to_string(),
                },
                action: Action::Reject {
                    message: "Pattern 2 matched".to_string(),
                },
            }],
            default_action: Action::Accept,
        };

        let engine2 = FilterEngine::new(config2).unwrap();
        let context2 = MailContext {
            sender: Some("dm-hlxihj@service.gzutzc.cn".to_string()),
            ..Default::default()
        };

        let action2 = engine2.evaluate(&context2).await;
        println!("SenderPattern 2 result: {:?}", action2);

        // Test SubjectContainsLanguage
        let config3 = Config {
            socket_path: "/tmp/test.sock".to_string(),
            rules: vec![FilterRule {
                name: "Test Japanese".to_string(),
                criteria: Criteria::SubjectContainsLanguage {
                    language: "japanese".to_string(),
                },
                action: Action::Reject {
                    message: "Japanese detected".to_string(),
                },
            }],
            default_action: Action::Accept,
        };

        let engine3 = FilterEngine::new(config3).unwrap();
        let context3 = MailContext {
            subject: Some("限定ご招待｜大切な方と過ごすミシュランの夜".to_string()),
            ..Default::default()
        };

        let action3 = engine3.evaluate(&context3).await;
        println!("Japanese detection result: {:?}", action3);
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

        let action = engine.evaluate(&context).await;
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
        let action = engine.evaluate(&context).await;

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

        let action = engine.evaluate(&context).await;
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

        let action2 = engine.evaluate(&context2).await;
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

        let action3 = engine.evaluate(&context3).await;
        match action3 {
            Action::Accept => {}
            _ => panic!("Expected accept action for non-sparkmail with Japanese"),
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

        let action1 = engine.evaluate(&context1).await;
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

        let action2 = engine.evaluate(&context2).await;
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

        let action3 = engine.evaluate(&context3).await;
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

        let action4 = engine.evaluate(&context4).await;
        match action4 {
            Action::Accept => {}
            _ => panic!("Expected accept for Sparkpost to different user"),
        }
    }

    #[tokio::test]
    async fn test_klclick_dns_validation() {
        let hostname = "ctrk.klclick.com";
        println!("Testing DNS lookup for: {}", hostname);

        let resolver = TokioAsyncResolver::tokio_from_system_conf().unwrap();

        match resolver.lookup_ip(hostname).await {
            Ok(response) => {
                // Test the exact logic from validate_unsubscribe_link
                let mut has_ips = false;
                for ip in response.iter() {
                    println!("Found IP: {}", ip);
                    has_ips = true;
                    break;
                }

                println!("Has IPs: {}", has_ips);
                assert!(
                    has_ips,
                    "Should have found IP addresses for ctrk.klclick.com"
                );
            }
            Err(e) => {
                panic!("DNS lookup failed for {}: {}", hostname, e);
            }
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

        let action1 = engine.evaluate(&context1).await;
        match action1 {
            Action::TagAsSpam {
                header_name,
                header_value,
            } => {
                assert_eq!(header_name, "X-Suspicious-Unsubscribe");
                assert_eq!(header_value, "YES");
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

        let action2 = engine.evaluate(&context2).await;
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

        let action3 = engine.evaluate(&context3).await;
        match action3 {
            Action::Accept => {}
            _ => panic!("Expected Accept action for non-google unsubscribe link"),
        }

        // Test case 4: Email with no unsubscribe links - should not match
        let context4 = MailContext {
            body: Some("Regular email content with no unsubscribe links".to_string()),
            ..Default::default()
        };

        let action4 = engine.evaluate(&context4).await;
        match action4 {
            Action::Accept => {}
            _ => panic!("Expected Accept action for email with no unsubscribe links"),
        }
    }
}
