use super::{FeatureExtractor, FeatureScore};
use crate::MailContext;
use regex::Regex;
use std::collections::HashMap;

pub struct SenderAlignmentAnalyzer {
    brand_patterns: HashMap<String, Vec<String>>,
    domain_regex: Regex,
}

impl Default for SenderAlignmentAnalyzer {
    fn default() -> Self {
        Self::new()
    }
}

impl SenderAlignmentAnalyzer {
    pub fn new() -> Self {
        let mut brand_patterns = HashMap::new();

        // Major brands and their expected domains
        brand_patterns.insert(
            "paypal".to_string(),
            vec!["paypal.com".to_string(), "paypal.me".to_string()],
        );

        brand_patterns.insert(
            "amazon".to_string(),
            vec![
                "amazon.com".to_string(),
                "amazon.co.uk".to_string(),
                "amazonses.com".to_string(),
            ],
        );

        brand_patterns.insert(
            "microsoft".to_string(),
            vec![
                "microsoft.com".to_string(),
                "outlook.com".to_string(),
                "live.com".to_string(),
            ],
        );

        brand_patterns.insert(
            "google".to_string(),
            vec![
                "google.com".to_string(),
                "gmail.com".to_string(),
                "googlemail.com".to_string(),
            ],
        );

        brand_patterns.insert(
            "norton".to_string(),
            vec![
                "norton.com".to_string(),
                "nortonlifelock.com".to_string(),
                "symantec.com".to_string(),
            ],
        );

        Self {
            brand_patterns,
            domain_regex: Regex::new(r"@([^>\s]+)").unwrap(),
        }
    }

    pub fn from_config(_config: &crate::config_loader::SenderAlignmentConfig) -> Self {
        Self::new()
    }

    fn extract_sender_info(&self, context: &MailContext) -> SenderInfo {
        let from_header = context.from_header.as_deref().unwrap_or_default();
        let sender_header = context.sender.as_deref().unwrap_or_default();
        let return_path = context
            .headers
            .get("Return-Path")
            .cloned()
            .unwrap_or_default();

        SenderInfo {
            from_domain: self.extract_domain(from_header),
            sender_domain: self.extract_domain(sender_header),
            return_path_domain: self.extract_domain(&return_path),
            from_display_name: self.extract_display_name(from_header),
        }
    }

    fn extract_reply_to_email(&self, headers: &str) -> Option<String> {
        let reply_to_regex =
            Regex::new(r"(?i)reply-to:.*?([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})")
                .unwrap();
        reply_to_regex
            .captures(headers)
            .and_then(|caps| caps.get(1))
            .map(|m| m.as_str().to_string())
    }

    fn is_valid_domain_format(&self, domain: &str) -> bool {
        // Basic domain format validation
        if domain.is_empty() || domain == "unknown" {
            return false;
        }
        
        // Must contain at least one dot and valid TLD
        let domain_regex = Regex::new(r"^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*\.[a-zA-Z]{2,}$").unwrap();
        domain_regex.is_match(domain)
    }

    fn extract_domain(&self, header: &str) -> String {
        // Try to extract from angle brackets first (most reliable)
        if let Some(angle_match) = Regex::new(r"<[^<>]*@([^<>\s]+)>").unwrap().captures(header) {
            if let Some(domain) = angle_match.get(1) {
                return domain.as_str().trim_end_matches('>').to_string();
            }
        }
        
        // Fallback to general @ pattern
        if let Some(cap) = self.domain_regex.captures(header) {
            if let Some(domain) = cap.get(1) {
                let domain_str = domain.as_str().trim_end_matches('>').trim_end_matches(')');
                return domain_str.to_string();
            }
        }
        "unknown".to_string()
    }

    fn extract_display_name(&self, from_header: &str) -> String {
        if let Some(lt_pos) = from_header.find('<') {
            from_header[..lt_pos].trim().trim_matches('"').to_string()
        } else {
            "".to_string()
        }
    }

    fn analyze_brand_impersonation(
        &self,
        sender_info: &SenderInfo,
        context: &MailContext,
    ) -> Vec<String> {
        let mut issues = Vec::new();
        let body = context.body.as_deref().unwrap_or("");
        let subject = context
            .headers
            .get("Subject")
            .map(|s| s.as_str())
            .unwrap_or("");

        // Skip brand impersonation detection for job-related content
        if self.is_job_related_content(subject, body) {
            return issues;
        }

        for (brand, legitimate_domains) in &self.brand_patterns {
            // Check if brand is mentioned in display name, subject, or body
            let brand_mentioned = sender_info.from_display_name.to_lowercase().contains(brand)
                || subject.to_lowercase().contains(brand)
                || body.to_lowercase().contains(brand);

            if brand_mentioned {
                // Check if sender domain is legitimate for this brand
                let domain_legitimate = legitimate_domains.iter().any(|domain| {
                    sender_info.from_domain.contains(domain)
                        || sender_info.sender_domain.contains(domain)
                        || sender_info.return_path_domain.contains(domain)
                });

                if !domain_legitimate {
                    issues.push(format!(
                        "Brand '{}' mentioned but sender domain '{}' not legitimate",
                        brand, sender_info.from_domain
                    ));
                }
            }
        }

        issues
    }

    fn analyze_domain_consistency(&self, sender_info: &SenderInfo) -> Vec<String> {
        let mut issues = Vec::new();

        // Check if From and Sender domains are consistent
        if !sender_info.sender_domain.is_empty()
            && sender_info.sender_domain != "unknown"
            && !self.domains_related(&sender_info.from_domain, &sender_info.sender_domain)
        {
            issues.push(format!(
                "From domain '{}' doesn't match Sender domain '{}'",
                sender_info.from_domain, sender_info.sender_domain
            ));
        }

        // Check Return-Path alignment
        if !sender_info.return_path_domain.is_empty()
            && sender_info.return_path_domain != "unknown"
            && !self.domains_related(&sender_info.from_domain, &sender_info.return_path_domain)
        {
            issues.push(format!(
                "From domain '{}' doesn't align with Return-Path domain '{}'",
                sender_info.from_domain, sender_info.return_path_domain
            ));
        }

        issues
    }

    fn domains_related(&self, domain1: &str, domain2: &str) -> bool {
        // Same domain
        if domain1 == domain2 {
            return true;
        }

        // Subdomain relationship
        if domain1.ends_with(domain2) || domain2.ends_with(domain1) {
            return true;
        }

        // Known legitimate relationships
        let legitimate_pairs = [
            ("amazon.com", "amazonses.com"),
            ("microsoft.com", "outlook.com"),
            ("google.com", "gmail.com"),
        ];

        for (d1, d2) in &legitimate_pairs {
            if (domain1.contains(d1) && domain2.contains(d2))
                || (domain1.contains(d2) && domain2.contains(d1))
            {
                return true;
            }
        }

        // Legitimate payment processors - don't flag as mismatched
        let payment_processors = [
            "pestconnect.com",
            "stripe.com",
            "paypal.com",
            "square.com",
            "quickbooks.com",
            "invoicecloud.com",
            "billpay.com",
            "autopay.com",
            "paymi.com",
            "epay.com",
        ];

        for processor in &payment_processors {
            if domain1.contains(processor) || domain2.contains(processor) {
                return true;
            }
        }

        false
    }

    fn analyze_display_name_spoofing(&self, sender_info: &SenderInfo) -> Vec<String> {
        let mut issues = Vec::new();
        let display_name = &sender_info.from_display_name.to_lowercase();

        // Check for suspicious display name patterns
        if display_name.contains("noreply") && !sender_info.from_domain.contains("noreply") {
            // This is often legitimate
        } else if display_name.contains("support")
            && !sender_info.from_domain.contains("support")
            && !self.is_known_support_domain(&sender_info.from_domain)
        {
            issues.push("Display name suggests support but domain doesn't match".to_string());
        }

        // Check for Unicode spoofing
        if display_name.chars().any(|c| c as u32 > 127) {
            issues.push(
                "Display name contains non-ASCII characters (potential spoofing)".to_string(),
            );
        }

        issues
    }

    fn is_known_support_domain(&self, domain: &str) -> bool {
        let support_domains = [
            "zendesk.com",
            "freshdesk.com",
            "helpscout.net",
            "intercom.io",
            "salesforce.com",
        ];
        support_domains.iter().any(|d| domain.contains(d))
    }
}

#[derive(Debug)]
struct SenderInfo {
    from_domain: String,
    sender_domain: String,
    return_path_domain: String,
    from_display_name: String,
}

impl FeatureExtractor for SenderAlignmentAnalyzer {
    fn extract(&self, context: &MailContext) -> FeatureScore {
        let sender_info = self.extract_sender_info(context);
        let mut evidence = Vec::new();
        let mut score = 0;

        // Check for invalid or missing domains (very high score) - only critical headers
        // From header MUST have a valid domain
        if sender_info.from_domain == "unknown" || sender_info.from_domain.is_empty() {
            // Only flag if we actually have a from_header but failed to extract domain
            if let Some(from_header) = context.from_header.as_deref() {
                if !from_header.is_empty() {
                    score += 120;
                    evidence.push("From header has invalid or missing domain".to_string());
                }
            }
        } else if !self.is_valid_domain_format(&sender_info.from_domain) {
            score += 100;
            evidence.push(format!("From header has malformed domain: {}", sender_info.from_domain));
        }
        
        // Return-Path should also have a valid domain (but less critical)
        if !sender_info.return_path_domain.is_empty() && sender_info.return_path_domain != "unknown" {
            if !self.is_valid_domain_format(&sender_info.return_path_domain) {
                score += 80;
                evidence.push(format!("Return-Path header has malformed domain: {}", sender_info.return_path_domain));
            }
        }

        // Check major brand impersonation (sender claiming to BE the brand)
        let brand_patterns = [
            ("ebay", vec!["ebay.com", "ebay.co.uk", "ebay.de"]),
            ("fedex", vec!["fedex.com", "fedex.co.uk"]),
            ("ups", vec!["ups.com"]),
            ("dhl", vec!["dhl.com"]),
            ("starbucks", vec!["starbucks.com"]),
            ("costco", vec!["costco.com", "costco.ca"]),
            ("walmart", vec!["walmart.com"]),
            ("target", vec!["target.com"]),
        ];

        let from_header = context.from_header.as_deref().unwrap_or("");
        let sender_domain = context.sender.as_deref().unwrap_or("");

        for (brand, official_domains) in &brand_patterns {
            // Only trigger if sender claims to BE the brand (not just mentioning it)
            let brand_claim_patterns = [
                format!("^{}", brand),     // Starts with brand name
                format!("{} -", brand),    // "eBay -" format
                format!("^\"{}\"", brand), // Quoted brand name
            ];

            let claims_brand = brand_claim_patterns.iter().any(|pattern| {
                regex::Regex::new(&format!("(?i){}", pattern))
                    .unwrap()
                    .is_match(from_header)
            });

            if claims_brand {
                let is_official = official_domains
                    .iter()
                    .any(|domain| sender_domain.contains(domain) || from_header.contains(domain));
                if !is_official {
                    score += 75;
                    evidence.push(format!(
                        "Brand impersonation: Claims {} from non-official domain",
                        brand.to_uppercase()
                    ));
                    break;
                }
            }
        }

        // Check sender mismatch (Gmail claiming business groups)
        if let Some(sender) = &context.sender {
            if sender.contains("@gmail.com") {
                if let Some(raw_headers) = context.headers.get("raw") {
                    if raw_headers.contains("@wntwhitelabelsolutions.com")
                        || raw_headers.contains("business")
                        || raw_headers.contains("group")
                    {
                        score += 30;
                        evidence
                            .push("Gmail sender claiming business/group affiliation".to_string());
                    }
                }
            }
        }

        // Check suspicious sender patterns (Brand@Non-Brand-Domain format)
        let suspicious_sender_patterns =
            [r"^(starbucks|costco|walmart|target|amazon|apple|microsoft)@.*\.(com|net|org)$"];

        for pattern in &suspicious_sender_patterns {
            let regex = Regex::new(&format!("(?i){}", pattern)).unwrap();
            if regex.is_match(from_header) {
                // Check if it's NOT from official domain
                let is_official = [
                    "starbucks.com",
                    "costco.com",
                    "walmart.com",
                    "target.com",
                    "amazon.com",
                    "apple.com",
                    "microsoft.com",
                ]
                .iter()
                .any(|domain| from_header.contains(domain));
                if !is_official {
                    score += 30;
                    evidence.push("Suspicious sender format detected".to_string());
                    break;
                }
            }
        }

        // Check suspicious domain patterns (avoid legitimate business subdomains)
        let suspicious_domain_patterns = [
            r"mystery\.box\.",
            r"[a-z]+box[0-9]+@", // Only match in email addresses
            r"dinisunnet\.com",  // Specific suspicious domain
        ];

        for pattern in &suspicious_domain_patterns {
            let regex = Regex::new(&format!("(?i){}", pattern)).unwrap();
            if regex.is_match(sender_domain) || regex.is_match(from_header) {
                score += 20;
                evidence.push("Suspicious domain pattern detected".to_string());
                break;
            }
        }

        // Check authentication failures combined with brand claims and giveaway language
        if let Some(raw_headers) = context.headers.get("raw") {
            let has_auth_failure =
                raw_headers.contains("dkim=fail") || raw_headers.contains("spf=fail");
            let claims_major_brand = [
                "ebay",
                "fedex",
                "ups",
                "dhl",
                "amazon",
                "paypal",
                "microsoft",
                "apple",
                "starbucks",
                "costco",
                "walmart",
                "target",
            ]
            .iter()
            .any(|brand| from_header.to_lowercase().contains(brand));
            let has_giveaway_language = ["giveaway", "claim", "prize", "winner", "gift", "contest"]
                .iter()
                .any(|word| {
                    from_header.to_lowercase().contains(word)
                        || context
                            .subject
                            .as_deref()
                            .unwrap_or("")
                            .to_lowercase()
                            .contains(word)
                });

            if has_auth_failure && claims_major_brand && has_giveaway_language {
                score += 40;
                evidence.push(
                    "Authentication failure with brand claim and giveaway language".to_string(),
                );
            } else if has_auth_failure && claims_major_brand {
                score += 35;
                evidence.push("Authentication failure combined with major brand claim".to_string());
            }
        }

        // Check authentication failures
        if let Some(raw_headers) = context.headers.get("raw") {
            if raw_headers.contains("dkim=fail") && raw_headers.contains("spf=fail") {
                score += 25;
                evidence.push("Multiple authentication failures (DKIM + SPF)".to_string());
            }
        }

        // Check Reply-To mismatch
        if let Some(raw_headers) = context.headers.get("raw") {
            if let Some(reply_to_email) = self.extract_reply_to_email(raw_headers) {
                let reply_to_domain = self.extract_domain(&reply_to_email);
                if !reply_to_domain.is_empty()
                    && !sender_info.from_domain.is_empty()
                    && reply_to_domain != sender_info.from_domain
                {
                    score += 40;
                    evidence.push(format!(
                        "Reply-To domain ({}) differs from From domain ({})",
                        reply_to_domain, sender_info.from_domain
                    ));
                }
            }
        }

        // Analyze brand impersonation
        let brand_issues = self.analyze_brand_impersonation(&sender_info, context);
        score += brand_issues.len() as i32 * 30;
        evidence.extend(brand_issues);

        // Analyze domain consistency
        let domain_issues = self.analyze_domain_consistency(&sender_info);
        score += domain_issues.len() as i32 * 20;
        evidence.extend(domain_issues);

        // Analyze display name spoofing
        let spoofing_issues = self.analyze_display_name_spoofing(&sender_info);
        score += spoofing_issues.len() as i32 * 15;
        evidence.extend(spoofing_issues);

        let confidence = if evidence.is_empty() { 0.9 } else { 0.85 };

        FeatureScore {
            feature_name: "Sender Alignment".to_string(),
            score,
            confidence,
            evidence,
        }
    }

    fn name(&self) -> &str {
        "sender_alignment"
    }
}

impl SenderAlignmentAnalyzer {
    fn is_job_related_content(&self, subject: &str, body: &str) -> bool {
        let job_indicators = [
            "job",
            "jobs",
            "role",
            "roles",
            "position",
            "positions",
            "career",
            "careers",
            "hiring",
            "employment",
            "opportunity",
            "opportunities",
            "recommendation",
            "recommendations",
            "available",
            "opening",
            "openings",
            "apply",
            "application",
        ];

        let combined_text = format!("{} {}", subject.to_lowercase(), body.to_lowercase());

        job_indicators
            .iter()
            .any(|&indicator| combined_text.contains(indicator))
    }
}
impl SenderAlignmentAnalyzer {}
