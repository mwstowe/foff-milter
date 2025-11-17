use super::{FeatureExtractor, FeatureScore};
use crate::MailContext;
use regex::Regex;

pub struct InvoiceAnalyzer {
    scam_indicators: Vec<Regex>,
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
            Regex::new(r"(?i)(click.*here|verify.*account|update.*payment)").unwrap(),
        ];

        Self { scam_indicators }
    }

    pub fn from_config(config: &crate::config_loader::InvoiceAnalysisConfig) -> Self {
        let scam_indicators: Vec<Regex> = config
            .scam_indicators
            .iter()
            .filter_map(|pattern| Regex::new(&format!("(?i){}", pattern)).ok())
            .collect();

        Self { scam_indicators }
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

        // Check for invoice scam indicators
        for pattern in &self.scam_indicators {
            if pattern.is_match(&full_text) {
                score += 30;
                evidence.push(format!(
                    "Invoice scam pattern detected: {}",
                    pattern.as_str()
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
