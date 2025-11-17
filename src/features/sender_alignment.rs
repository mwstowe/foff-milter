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
        let from_header = context.headers.get("From").cloned().unwrap_or_default();
        let sender_header = context.headers.get("Sender").cloned().unwrap_or_default();
        let return_path = context
            .headers
            .get("Return-Path")
            .cloned()
            .unwrap_or_default();

        SenderInfo {
            from_domain: self.extract_domain(&from_header),
            sender_domain: self.extract_domain(&sender_header),
            return_path_domain: self.extract_domain(&return_path),
            from_display_name: self.extract_display_name(&from_header),
        }
    }

    fn extract_domain(&self, header: &str) -> String {
        if let Some(cap) = self.domain_regex.captures(header) {
            if let Some(domain) = cap.get(1) {
                return domain.as_str().trim_end_matches('>').to_string();
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
impl SenderAlignmentAnalyzer {
}
