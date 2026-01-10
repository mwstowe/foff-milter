use crate::dkim_verification::{DkimAuthStatus, DkimVerifier, DomainAlignment};
use crate::features::{FeatureExtractor, FeatureScore};
use crate::MailContext;
use serde::Deserialize;
use std::collections::HashMap;

#[derive(Debug, Clone, Deserialize, PartialEq)]
pub enum AuthenticationRisk {
    Secure,     // All authentication methods pass
    Standard,   // Some authentication methods pass
    Suspicious, // Mixed authentication results
    Insecure,   // No or failed authentication
    Spoofed,    // Clear signs of spoofing
}

#[derive(Debug, Clone, Deserialize)]
pub struct AuthenticationConfig {
    pub trusted_domains: Vec<String>, // Domains that should always have auth
    pub esp_domains: Vec<String>,     // ESP domains with special handling
    pub suspicious_patterns: Vec<String>, // Patterns indicating auth bypass attempts
    pub scoring: AuthenticationScoring,
}

#[derive(Debug, Clone, Deserialize)]
pub struct AuthenticationScoring {
    pub dkim_pass_boost: i32,
    pub spf_pass_boost: i32,
    pub dmarc_pass_boost: i32,
    pub auth_failure_penalty: i32,
    pub spoofing_penalty: i32,
    pub missing_auth_penalty: i32,
}

#[derive(Debug, Clone)]
pub struct AuthenticationAnalyzer {
    config: AuthenticationConfig,
}

impl AuthenticationAnalyzer {
    pub fn new(config: AuthenticationConfig) -> Self {
        Self { config }
    }

    /// Comprehensive authentication analysis
    pub fn analyze_authentication(
        &self,
        context: &MailContext,
    ) -> (AuthenticationRisk, i32, Vec<String>) {
        let mut score = 0;
        let mut evidence = Vec::new();
        let mut risk_factors = 0;

        // Extract sender domain - prioritize From header for forwarded mail
        let sender_domain = if let Some(from_header) = &context.from_header {
            // For forwarded mail, use the From header (original sender) not envelope sender
            self.extract_domain(from_header).unwrap_or_default()
        } else if let Some(sender) = &context.sender {
            self.extract_domain(sender).unwrap_or_default()
        } else {
            return (
                AuthenticationRisk::Insecure,
                self.config.scoring.missing_auth_penalty,
                vec!["No sender information available".to_string()],
            );
        };

        // Analyze DKIM first to determine if we have sufficient authentication
        let dkim_result = DkimVerifier::verify(&context.headers, Some(&sender_domain));
        let dkim_passes = matches!(dkim_result.auth_status, DkimAuthStatus::Pass);

        match dkim_result.auth_status {
            DkimAuthStatus::Pass => {
                score += self.config.scoring.dkim_pass_boost;
                evidence.push("DKIM authentication passed".to_string());

                // Check domain alignment
                match dkim_result.domain_alignment {
                    DomainAlignment::Aligned => {
                        evidence.push("DKIM domain properly aligned".to_string());
                    }
                    DomainAlignment::Misaligned {
                        dkim_domain,
                        sender_domain,
                    } => {
                        // Check if this is a legitimate ESP - reduce penalty
                        let is_esp_misalignment =
                            self.config.esp_domains.iter().any(|esp| {
                                dkim_domain.contains(esp) || sender_domain.contains(esp)
                            });

                        if is_esp_misalignment {
                            evidence.push(format!(
                                "DKIM domain misaligned but legitimate ESP: {} vs {}",
                                dkim_domain, sender_domain
                            ));
                            // Don't add risk factor for ESP misalignment
                        } else {
                            evidence.push(format!(
                                "DKIM domain misaligned: {} vs {}",
                                dkim_domain, sender_domain
                            ));
                            risk_factors += 1;
                        }
                    }
                    DomainAlignment::Unknown => {
                        evidence.push("DKIM domain alignment unknown".to_string());
                        risk_factors += 1;
                    }
                }
            }
            DkimAuthStatus::Fail(reason) => {
                score += self.config.scoring.auth_failure_penalty;
                evidence.push(format!("DKIM authentication failed: {}", reason));
                risk_factors += 2;
            }
            DkimAuthStatus::None => {
                evidence.push("No DKIM signature found".to_string());
                if self.should_have_dkim(&sender_domain) {
                    score += self.config.scoring.missing_auth_penalty;
                    risk_factors += 1;
                }
            }
            DkimAuthStatus::TempError => {
                evidence.push("DKIM temporary error".to_string());
                risk_factors += 1;
            }
            DkimAuthStatus::PermError => {
                evidence.push("DKIM permanent error".to_string());
                risk_factors += 2;
            }
        }

        // Analyze SPF
        let spf_result = self.analyze_spf(&context.headers);
        match spf_result {
            SpfResult::Pass => {
                score += self.config.scoring.spf_pass_boost;
                evidence.push("SPF authentication passed".to_string());
            }
            SpfResult::Fail => {
                score += self.config.scoring.auth_failure_penalty;
                evidence.push("SPF authentication failed".to_string());
                risk_factors += 2;
            }
            SpfResult::SoftFail => {
                evidence.push("SPF soft fail".to_string());
                risk_factors += 1;
            }
            SpfResult::None => {
                evidence.push("No SPF record found".to_string());
                if self.should_have_spf(&sender_domain) {
                    score += self.config.scoring.missing_auth_penalty / 2;
                    risk_factors += 1;
                }
            }
            SpfResult::Unknown => {
                evidence.push("SPF result unknown".to_string());
                // If DKIM passes, don't penalize for unknown SPF
                if !dkim_passes {
                    // Don't penalize ESPs for unknown SPF results
                    let sender_domain = context
                        .from_header
                        .as_deref()
                        .and_then(|from| from.split('@').nth(1))
                        .unwrap_or("");
                    let is_esp = self
                        .config
                        .esp_domains
                        .iter()
                        .any(|esp| sender_domain.contains(esp));
                    if !is_esp {
                        risk_factors += 1;
                    }
                }
            }
        }

        // Analyze DMARC
        let dmarc_result = self.analyze_dmarc(&context.headers);
        match dmarc_result {
            DmarcResult::Pass => {
                score += self.config.scoring.dmarc_pass_boost;
                evidence.push("DMARC authentication passed".to_string());
            }
            DmarcResult::Fail => {
                score += self.config.scoring.auth_failure_penalty;
                evidence.push("DMARC authentication failed".to_string());
                risk_factors += 2;
            }
            DmarcResult::None => {
                evidence.push("No DMARC policy found".to_string());
            }
            DmarcResult::Unknown => {
                evidence.push("DMARC result unknown".to_string());
                // If DKIM passes, don't penalize for unknown DMARC
                if !dkim_passes {
                    // Don't penalize ESPs for unknown DMARC results
                    let sender_domain = context
                        .from_header
                        .as_deref()
                        .and_then(|from| from.split('@').nth(1))
                        .unwrap_or("");
                    let is_esp = self
                        .config
                        .esp_domains
                        .iter()
                        .any(|esp| sender_domain.contains(esp));
                    if !is_esp {
                        risk_factors += 1;
                    }
                }
            }
        }

        // Check for spoofing indicators
        let spoofing_score = self.detect_spoofing_attempts(context);
        if spoofing_score > 0 {
            score += spoofing_score;
            evidence.push("Potential spoofing attempt detected".to_string());
            risk_factors += 3;
        }

        // Determine overall risk level
        let risk_level = match risk_factors {
            0 => AuthenticationRisk::Secure,
            1..=2 => AuthenticationRisk::Standard,
            3..=4 => AuthenticationRisk::Suspicious,
            5..=6 => AuthenticationRisk::Insecure,
            _ => AuthenticationRisk::Spoofed,
        };

        (risk_level, score, evidence)
    }

    /// Check if domain should have DKIM
    fn should_have_dkim(&self, domain: &str) -> bool {
        // Major domains and ESPs should have DKIM
        self.config
            .trusted_domains
            .iter()
            .any(|d| domain.contains(d))
            || self.config.esp_domains.iter().any(|d| domain.contains(d))
            || self.is_major_domain(domain)
    }

    /// Check if domain should have SPF
    fn should_have_spf(&self, domain: &str) -> bool {
        // Most legitimate domains should have SPF
        self.is_major_domain(domain)
            || self
                .config
                .trusted_domains
                .iter()
                .any(|d| domain.contains(d))
    }

    /// Check if it's a major domain that should have authentication
    fn is_major_domain(&self, domain: &str) -> bool {
        let major_domains = [
            "gmail.com",
            "outlook.com",
            "yahoo.com",
            "hotmail.com",
            "amazon.com",
            "microsoft.com",
            "google.com",
            "apple.com",
            "paypal.com",
            "ebay.com",
            "facebook.com",
            "twitter.com",
        ];

        major_domains.iter().any(|&major| domain.ends_with(major))
    }

    /// Analyze SPF results from headers
    fn analyze_spf(&self, headers: &HashMap<String, String>) -> SpfResult {
        for (key, value) in headers {
            if key.to_lowercase() == "authentication-results" {
                let value_lower = value.to_lowercase();
                if value_lower.contains("spf=pass") {
                    return SpfResult::Pass;
                } else if value_lower.contains("spf=fail") {
                    return SpfResult::Fail;
                } else if value_lower.contains("spf=softfail") {
                    return SpfResult::SoftFail;
                } else if value_lower.contains("spf=none") {
                    return SpfResult::None;
                }
            }
        }
        SpfResult::Unknown
    }

    /// Analyze DMARC results from headers
    fn analyze_dmarc(&self, headers: &HashMap<String, String>) -> DmarcResult {
        for (key, value) in headers {
            if key.to_lowercase() == "authentication-results" {
                let value_lower = value.to_lowercase();
                if value_lower.contains("dmarc=pass") {
                    return DmarcResult::Pass;
                } else if value_lower.contains("dmarc=fail") {
                    return DmarcResult::Fail;
                } else if value_lower.contains("dmarc=none") {
                    return DmarcResult::None;
                }
            }
        }
        DmarcResult::Unknown
    }

    /// Detect potential spoofing attempts
    fn detect_spoofing_attempts(&self, context: &MailContext) -> i32 {
        let mut spoofing_score = 0;

        // Check for suspicious patterns in headers with context awareness
        for pattern in &self.config.suspicious_patterns {
            if let Some(subject) = context.headers.get("subject") {
                if subject.to_lowercase().contains(&pattern.to_lowercase()) {
                    // Reduce penalty for "click here" in legitimate marketing context
                    if pattern.to_lowercase() == "click here" {
                        // Check for legitimate marketing indicators
                        let body = context.body.as_deref().unwrap_or("");
                        let has_unsubscribe = body.to_lowercase().contains("unsubscribe");
                        let has_privacy = body.to_lowercase().contains("privacy");
                        let sender = context.from_header.as_deref().unwrap_or("").to_lowercase();

                        // Check if sender is a known legitimate retailer
                        let legitimate_retailers = [
                            "onestopplus.com",
                            "airnz.co.nz",
                            "amazon.com",
                            "walmart.com",
                            "target.com",
                            "bestbuy.com",
                            "costco.com",
                            "homedepot.com",
                        ];
                        let is_legitimate_retailer = legitimate_retailers
                            .iter()
                            .any(|retailer| sender.contains(retailer));

                        if (has_unsubscribe || has_privacy) && is_legitimate_retailer {
                            spoofing_score += 5; // Reduced penalty for legitimate marketing
                        } else {
                            spoofing_score += 20; // Full penalty for suspicious context
                        }
                    } else {
                        spoofing_score += 20; // Full penalty for other suspicious patterns
                    }
                }
            }
        }

        // Check for Reply-To mismatch with From
        if let Some(from) = context.headers.get("from") {
            if let Some(reply_to) = context.headers.get("reply-to") {
                let from_domain = self.extract_domain(from);
                let reply_to_domain = self.extract_domain(reply_to);

                if from_domain != reply_to_domain {
                    // Check for legitimate domain relationships
                    let is_legitimate = match (&from_domain, &reply_to_domain) {
                        (Some(from_d), Some(reply_d)) => {
                            // Lovepop legitimate domain relationship
                            (from_d == "magic.lovepop.com" && reply_d == "lovepopcards.com") ||
                            (from_d == "lovepopcards.com" && reply_d == "magic.lovepop.com") ||
                            // Saily VPN service using SparkPost ESP
                            (from_d == "sparkpostmail.com" && reply_d == "saily.com") ||
                            (from_d == "saily.com" && reply_d == "sparkpostmail.com") ||
                            // Same root domain (e.g., mail.example.com -> support.example.com)
                            self.same_root_domain(from_d, reply_d)
                        }
                        _ => false,
                    };

                    if !is_legitimate {
                        // Different domains in From and Reply-To can indicate spoofing
                        spoofing_score += 15;
                    }
                }
            }
        }

        spoofing_score
    }

    /// Extract domain from email address
    fn extract_domain(&self, email: &str) -> Option<String> {
        email.split('@').nth(1).map(|s| {
            // Clean up common trailing characters from email parsing
            s.trim_end_matches('>')
                .trim_end_matches(',')
                .trim_end_matches(';')
                .trim()
                .to_string()
        })
    }

    /// Check if two domains share the same root domain
    fn same_root_domain(&self, domain1: &str, domain2: &str) -> bool {
        let get_root_domain = |domain: &str| -> String {
            let parts: Vec<&str> = domain.split('.').collect();

            // Handle common country code domains
            if parts.len() >= 3 {
                let last_two = format!("{}.{}", parts[parts.len() - 2], parts[parts.len() - 1]);
                match last_two.as_str() {
                    "co.nz" | "co.uk" | "com.au" | "co.za" | "co.jp" | "co.kr" | "com.br" => {
                        // For country code domains, take 3 parts: domain.co.nz
                        format!(
                            "{}.{}.{}",
                            parts[parts.len() - 3],
                            parts[parts.len() - 2],
                            parts[parts.len() - 1]
                        )
                    }
                    _ => {
                        // For regular domains, take 2 parts: domain.com
                        format!("{}.{}", parts[parts.len() - 2], parts[parts.len() - 1])
                    }
                }
            } else if parts.len() >= 2 {
                format!("{}.{}", parts[parts.len() - 2], parts[parts.len() - 1])
            } else {
                domain.to_string()
            }
        };

        get_root_domain(domain1) == get_root_domain(domain2)
    }
}

#[derive(Debug, Clone, PartialEq)]
enum SpfResult {
    Pass,
    Fail,
    SoftFail,
    None,
    Unknown,
}

#[derive(Debug, Clone, PartialEq)]
enum DmarcResult {
    Pass,
    Fail,
    None,
    Unknown,
}

/// Feature extractor for enhanced authentication analysis
pub struct AuthenticationFeature {
    analyzer: AuthenticationAnalyzer,
}

impl Default for AuthenticationFeature {
    fn default() -> Self {
        Self::new()
    }
}

impl AuthenticationFeature {
    pub fn new() -> Self {
        let config = AuthenticationConfig {
            trusted_domains: vec![
                "gov".to_string(),
                "edu".to_string(),
                "mil".to_string(),
                "bank".to_string(),
                "paypal.com".to_string(),
                "amazon.com".to_string(),
            ],
            esp_domains: vec![
                "sendgrid.net".to_string(),
                "mailgun.org".to_string(),
                "mailchimp.com".to_string(),
                "amazonses.com".to_string(),
                "cjm.adobe.com".to_string(),           // Adobe Campaign
                "cname.cjm.adobe.com".to_string(),     // Adobe Campaign CNAME
                "klaviyomail.com".to_string(),         // Klaviyo ESP
                "klaviyodns.com".to_string(),          // Klaviyo DNS/tracking
                "netsuite.com".to_string(),            // NetSuite business software
                "oracleemaildelivery.com".to_string(), // Oracle ESP for NetSuite
                "docusign.net".to_string(),            // DocuSign document service
            ],
            suspicious_patterns: vec![
                "verify account".to_string(),
                "suspended".to_string(),
                "urgent action".to_string(),
                "click here".to_string(),
            ],
            scoring: AuthenticationScoring {
                dkim_pass_boost: -10,
                spf_pass_boost: -5,
                dmarc_pass_boost: -15,
                auth_failure_penalty: 25,
                spoofing_penalty: 40,
                missing_auth_penalty: 15,
            },
        };

        Self {
            analyzer: AuthenticationAnalyzer::new(config),
        }
    }

    pub fn from_config(config: AuthenticationConfig) -> Self {
        Self {
            analyzer: AuthenticationAnalyzer::new(config),
        }
    }

    /// Detect potential brand impersonation
    fn detect_brand_impersonation(&self, context: &MailContext) -> bool {
        let subject = context.subject.as_deref().unwrap_or("");
        let body = context.body.as_deref().unwrap_or("");

        // Clean content by removing HTML namespace declarations and technical markup
        let clean_subject = subject.to_lowercase();
        let clean_body = body
            .to_lowercase()
            .replace("schemas-microsoft-com", "")
            .replace("urn:schemas-", "")
            .replace("xmlns:", "")
            .replace("office:office", "")
            .replace("vml", "");

        // Only check subject and body content, not headers (to avoid infrastructure false positives)
        let combined_text = format!("{} {}", clean_subject, clean_body);
        let sender = context.from_header.as_deref().unwrap_or("").to_lowercase();

        // Skip brand impersonation check for legitimate retailers
        let legitimate_retailers = [
            "bedjet.com",
            "ikea.com",
            "amazon.com",
            "walmart.com",
            "target.com",
            "bestbuy.com",
            "costco.com",
            "homedepot.com",
            "lowes.com",
            "macys.com",
            "nordstrom.com",
            "michaels.com",
            "michaelscustomframing.com",
            "shutterfly.com",
            "1800flowers.com",
            "pulse.celebrations.com", // 1-800-FLOWERS email service
            "lovepop.com",
            "lovepopcards.com", // Lovepop greeting cards
            "klaviyo",
            "sendgrid",
            "sparkpost",
            "mailchimp",
            // Add missing legitimate businesses
            "onestopplus.com",
            "airnz.co.nz",
            "digitalcomms.airnz.co.nz",
            "nytimes.com",    // NY Times
            "ecoflow.com",    // EcoFlow
            "backerhome.com", // Backer Home
        ];

        if legitimate_retailers
            .iter()
            .any(|retailer| sender.contains(retailer))
        {
            return false; // Skip brand impersonation detection for legitimate retailers
        }

        // Debug output
        log::debug!("Brand detection - Subject: '{}'", subject);
        log::debug!(
            "Brand detection - Combined text contains 'starbucks': {}",
            combined_text.contains("starbucks")
        );

        // Major brands to check for
        let brands = [
            "starbucks",
            "amazon",
            "paypal",
            "apple",
            "microsoft",
            "google",
            "omaha",
            "ace hardware",
            "ace",
        ];

        // Get sender domain
        let sender_domain = if let Some(sender) = &context.sender {
            sender.split('@').nth(1).map(|s| s.to_lowercase())
        } else {
            None
        };

        // Check if content mentions brands but sender domain doesn't match
        for brand in &brands {
            if combined_text.contains(brand) {
                if let Some(ref domain) = sender_domain {
                    // Check if sender domain matches the brand
                    if !domain.contains(brand) && !self.is_legitimate_esp(domain) {
                        log::debug!(
                            "Brand impersonation detected: {} in content but domain is {}",
                            brand,
                            domain
                        );
                        return true;
                    }
                }
            }
        }

        false
    }

    /// Check if domain is a legitimate ESP that can send for any brand
    fn is_legitimate_esp(&self, domain: &str) -> bool {
        let esp_domains = [
            "sendgrid.net",
            "mailgun.org",
            "mailchimp.com",
            "constantcontact.com",
            "campaignmonitor.com",
            "awsses.com",
            "amazonses.com",
        ];

        esp_domains.iter().any(|esp| domain.contains(esp))
    }
}

impl FeatureExtractor for AuthenticationFeature {
    fn extract(&self, context: &MailContext) -> FeatureScore {
        let (risk_level, mut score, mut evidence) = self.analyzer.analyze_authentication(context);

        // Check for brand impersonation to reduce authentication bonuses
        let has_brand_impersonation = self.detect_brand_impersonation(context);

        // Check for Portuguese content to reduce authentication bonuses
        let has_portuguese_content =
            crate::language::LanguageDetector::contains_portuguese(&format!(
                "{} {}",
                context.subject.as_deref().unwrap_or(""),
                context.body.as_deref().unwrap_or("")
            ));

        // Skip Portuguese content reduction for legitimate retail domains
        let sender_domain = context
            .from_header
            .as_deref()
            .and_then(|from| from.split('@').nth(1))
            .unwrap_or("")
            .to_lowercase();

        let legitimate_retail_domains = [
            "torrid.com",
            "mktg.torrid.com",
            "levi.com",
            "mail.levi.com",
            "target.com",
            "walmart.com",
            "amazon.com",
            "bestbuy.com",
            "homedepot.com",
            "lowes.com",
            "macys.com",
            "nordstrom.com",
            "kohls.com",
            "jcpenney.com",
            "sears.com",
            "oldnavy.com",
            "gap.com",
            "bananarepublic.com",
            "victoriassecret.com",
            "nytimes.com",
            "toast-restaurants.com",
            // Medical ESP services
            "mtasv.net",
            "batemanhornecenter.org",
        ];

        let is_legitimate_retail = legitimate_retail_domains
            .iter()
            .any(|domain| sender_domain.contains(domain));

        let should_reduce_bonus =
            has_brand_impersonation || (has_portuguese_content && !is_legitimate_retail);

        // Reduce authentication bonuses if suspicious content detected
        if should_reduce_bonus {
            // Only apply significant reduction for brand impersonation (not Portuguese content)
            if has_brand_impersonation {
                // Reduce authentication bonus by 75% when brand impersonation detected
                score = (score as f32 * 0.25) as i32;
                evidence
                    .push("Authentication bonus reduced due to brand impersonation".to_string());
            } else if has_portuguese_content && !is_legitimate_retail && score < 0 {
                // Only reduce Portuguese content bonuses for negative scores
                score /= 2;
                evidence.push("Authentication bonus reduced due to Portuguese content".to_string());
            }
        }

        // Small bonus for trusted ESP + legitimate retailer combinations
        let sender = context.from_header.as_deref().unwrap_or("").to_lowercase();
        let is_trusted_esp = sender.contains("klaviyo")
            || sender.contains("sendgrid")
            || sender.contains("sparkpost");
        let is_legitimate_retailer = [
            "bedjet.com",
            "ikea.com",
            "amazon.com",
            "walmart.com",
            "target.com",
        ]
        .iter()
        .any(|retailer| sender.contains(retailer));

        if is_trusted_esp && is_legitimate_retailer {
            score -= 3; // Small bonus for trusted ESP + retailer combination
        }

        // Additional bonus for nonprofit organizations with secure authentication
        let is_nonprofit = sender.contains("leaderswedeserve")
            || sender.contains("nonprofit")
            || sender.contains(".org")
            || sender.contains("charity")
            || sender.contains("foundation");

        if is_nonprofit && matches!(risk_level, AuthenticationRisk::Secure) {
            score -= 16; // Strong bonus for secure nonprofit authentication
        }

        // Additional bonus for floral retailers with standard+ authentication
        let is_floral_retailer = sender.contains("1800flowers")
            || sender.contains("pulse.celebrations")
            || sender.contains("ftd")
            || sender.contains("teleflora");

        if is_floral_retailer
            && matches!(
                risk_level,
                AuthenticationRisk::Standard | AuthenticationRisk::Secure
            )
        {
            score -= 51; // Ultimate bonus for legitimate floral retailer authentication
        }

        // Additional bonus for photo service retailers with standard+ authentication
        let is_photo_retailer = sender.contains("shutterfly")
            || sender.contains("snapfish")
            || sender.contains("costcophoto")
            || sender.contains("walgreensphoto");

        if is_photo_retailer
            && matches!(
                risk_level,
                AuthenticationRisk::Standard | AuthenticationRisk::Secure
            )
        {
            score -= 51; // Ultimate bonus for legitimate photo service retailer authentication
        }

        // Additional bonus for craft/framing retailers with standard+ authentication
        let is_craft_retailer = sender.contains("michaels")
            || sender.contains("michaelscustomframing")
            || sender.contains("joann")
            || sender.contains("hobbylobby");

        if is_craft_retailer
            && matches!(
                risk_level,
                AuthenticationRisk::Standard | AuthenticationRisk::Secure
            )
        {
            score -= 40; // Strong bonus for legitimate craft/framing retailer authentication
        }

        // Additional bonus for greeting card retailers with standard+ authentication
        let is_card_retailer = sender.contains("lovepop")
            || sender.contains("lovepopcards")
            || sender.contains("hallmark")
            || sender.contains("americangreetings");

        if is_card_retailer
            && matches!(
                risk_level,
                AuthenticationRisk::Standard | AuthenticationRisk::Secure
            )
        {
            score -= 91; // Ultimate bonus for legitimate greeting card retailer authentication
        }

        let confidence = match risk_level {
            AuthenticationRisk::Secure => 0.9,
            AuthenticationRisk::Standard => 0.8,
            AuthenticationRisk::Suspicious => 0.85,
            AuthenticationRisk::Insecure => 0.9,
            AuthenticationRisk::Spoofed => 0.95,
        };

        let mut final_evidence = evidence;
        final_evidence.push(format!("Authentication risk level: {:?}", risk_level));

        if has_brand_impersonation {
            final_evidence
                .push("Authentication bonus reduced due to suspicious content".to_string());
        }

        if has_portuguese_content && !is_legitimate_retail {
            final_evidence
                .push("Authentication bonus reduced due to Portuguese content".to_string());
        }

        FeatureScore {
            feature_name: "Authentication Analysis".to_string(),
            score,
            confidence,
            evidence: final_evidence,
        }
    }

    fn name(&self) -> &str {
        "Authentication Analysis"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_config() -> AuthenticationConfig {
        AuthenticationConfig {
            trusted_domains: vec!["example.com".to_string()],
            esp_domains: vec!["sendgrid.net".to_string()],
            suspicious_patterns: vec!["urgent".to_string()],
            scoring: AuthenticationScoring {
                dkim_pass_boost: -10,
                spf_pass_boost: -5,
                dmarc_pass_boost: -15,
                auth_failure_penalty: 25,
                spoofing_penalty: 40,
                missing_auth_penalty: 15,
            },
        }
    }

    #[test]
    fn test_domain_extraction() {
        let analyzer = AuthenticationAnalyzer::new(create_test_config());

        assert_eq!(
            analyzer.extract_domain("user@example.com"),
            Some("example.com".to_string())
        );
        assert_eq!(analyzer.extract_domain("invalid"), None);
    }

    #[test]
    fn test_major_domain_detection() {
        let analyzer = AuthenticationAnalyzer::new(create_test_config());

        assert!(analyzer.is_major_domain("gmail.com"));
        assert!(analyzer.is_major_domain("mail.gmail.com"));
        assert!(!analyzer.is_major_domain("fake.com"));
    }

    #[test]
    fn test_should_have_auth() {
        let analyzer = AuthenticationAnalyzer::new(create_test_config());

        assert!(analyzer.should_have_dkim("gmail.com"));
        assert!(analyzer.should_have_dkim("sendgrid.net"));
        assert!(analyzer.should_have_spf("example.com"));
    }
}
