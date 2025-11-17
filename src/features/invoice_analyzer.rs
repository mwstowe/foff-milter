use super::{FeatureExtractor, FeatureScore};
use crate::MailContext;
use regex::Regex;

pub struct InvoiceAnalyzer {
    scam_indicators: Vec<Regex>,
    legitimate_domains: Vec<String>,
}

impl Default for InvoiceAnalyzer {
    fn default() -> Self {
        Self::new()
    }
}

impl InvoiceAnalyzer {
    pub fn new() -> Self {
        let scam_indicators = vec![
            Regex::new(r"(?i)(overdue|total amount|invoice number)").unwrap(),
            Regex::new(r"(?i)(24 hours|payment required|account suspended)").unwrap(),
            Regex::new(r"(?i)\b(click\s+here|verify\s+.*\s+account|update\s+.*\s+payment)\b").unwrap(),
        ];

        let legitimate_domains = vec![
            "iheart.com".to_string(),
            "wolfermans.com".to_string(),
            "harryandavid.com".to_string(),
            "adapthealth.com".to_string(),
            "sendgrid.net".to_string(),
            "mailchimp.com".to_string(),
            "constantcontact.com".to_string(),
        ];

        Self { scam_indicators, legitimate_domains }
    }

    pub fn from_config(config: &crate::config_loader::InvoiceAnalysisConfig) -> Self {
        let scam_indicators: Vec<Regex> = config
            .scam_indicators
            .iter()
            .filter_map(|pattern| Regex::new(&format!("(?i){}", pattern)).ok())
            .collect();

        let legitimate_domains = vec![
            "iheart.com".to_string(),
            "wolfermans.com".to_string(),
            "harryandavid.com".to_string(),
            "adapthealth.com".to_string(),
            "sendgrid.net".to_string(),
            "mailchimp.com".to_string(),
            "constantcontact.com".to_string(),
        ];

        Self { scam_indicators, legitimate_domains }
    }
}

impl FeatureExtractor for InvoiceAnalyzer {
    fn extract(&self, context: &MailContext) -> FeatureScore {
        let body = context.body.as_deref().unwrap_or("");
        let subject = context
            .headers
            .get("Subject")
            .map(|s| s.as_str())
            .unwrap_or("");
        let full_text = format!("{} {}", subject, body);

        let mut score = 0;
        let mut evidence = Vec::new();

        // Check if sender is from legitimate domain
        let sender = context.sender.as_deref().unwrap_or("");
        let from_header = context.from_header.as_deref().unwrap_or("");
        let is_legitimate = self.legitimate_domains.iter().any(|domain| {
            sender.contains(domain) || from_header.contains(domain)
        });

        // Check for invoice scam indicators with context awareness
        for pattern in &self.scam_indicators {
            if pattern.is_match(&full_text) {
                // Additional check for click here pattern to avoid URL false positives
                if pattern.as_str().contains("click\\s+here") {
                    // Only match if "click here" appears in actual text, not in URLs
                    let click_here_regex = Regex::new(r"(?i)(?<!https?://[^\s]*)\bclick\s+here\b(?![^\s]*\.[a-z]{2,})").unwrap();
                    if !click_here_regex.is_match(&full_text) {
                        continue; // Skip this match as it's likely in a URL
                    }
                }
                
                let base_score = if is_legitimate { 5 } else { 30 }; // Reduced score for legitimate senders
                score += base_score;
                evidence.push(format!(
                    "Invoice scam pattern detected: {} (legitimate sender: {})",
                    pattern.as_str(),
                    is_legitimate
                ));
            }
        }

        let confidence = if score > 0 { 0.9 } else { 0.0 };

        FeatureScore {
            feature_name: "Invoice Analysis".to_string(),
            score,
            confidence,
            evidence,
        }
    }

    fn name(&self) -> &str {
        "invoice_analyzer"
    }
}
