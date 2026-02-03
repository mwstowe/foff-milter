use crate::features::{FeatureExtractor, FeatureScore};
use crate::MailContext;
use regex::Regex;

pub struct DomainBusinessMismatchAnalyzer {
    educational_domains: Vec<String>,
    government_domains: Vec<String>,
    payment_patterns: Vec<Regex>,
}

impl Default for DomainBusinessMismatchAnalyzer {
    fn default() -> Self {
        Self::new()
    }
}

impl DomainBusinessMismatchAnalyzer {
    pub fn new() -> Self {
        let educational_domains = vec![
            ".edu".to_string(),
            ".ac.".to_string(),
            ".edu.".to_string(),
            "university".to_string(),
            "college".to_string(),
            "school".to_string(),
            "caehs".to_string(), // College of Agriculture, Environment and Health Sciences
            "univ".to_string(),
            "dekalb".to_string(),      // DeKalb school district
            "central.net".to_string(), // Educational networks
        ];

        let government_domains = vec![".gov".to_string(), ".mil".to_string(), ".gov.".to_string()];

        let payment_patterns = vec![
            Regex::new(r"(?i)\b(payment|billing|invoice|receipt|order)\b.*\b(status|update|statement|acknowledgement)\b").unwrap(),
            Regex::new(r"(?i)\bfind.*\b(billing|payment|invoice)\b.*\bstatement\b").unwrap(),
            Regex::new(r"(?i)\bdear\s*,\s*please\b").unwrap(),
            Regex::new(r"(?i)\border\s+worth\s+\$[\d,]+").unwrap(),
            Regex::new(r"(?i)\border.*is\s+being\s+(activated|processed)").unwrap(),
        ];

        Self {
            educational_domains,
            government_domains,
            payment_patterns,
        }
    }

    fn is_educational_domain(&self, domain: &str) -> bool {
        let domain_lower = domain.to_lowercase();
        self.educational_domains
            .iter()
            .any(|pattern| domain_lower.contains(pattern))
    }

    fn is_government_domain(&self, domain: &str) -> bool {
        let domain_lower = domain.to_lowercase();
        self.government_domains
            .iter()
            .any(|pattern| domain_lower.contains(pattern))
    }

    fn has_payment_content(&self, text: &str) -> bool {
        self.payment_patterns
            .iter()
            .any(|pattern| pattern.is_match(text))
    }

    fn has_generic_greeting(&self, text: &str) -> bool {
        let generic_patterns = [
            r"(?i)\bdear\s*,\s*please\b",
            r"(?i)\bdear\s*,\s*\w+.*find\b",
            r"(?i)\bdear\s*,\s*[^a-zA-Z]",
        ];

        generic_patterns.iter().any(|pattern| {
            Regex::new(pattern)
                .map(|r| r.is_match(text))
                .unwrap_or(false)
        })
    }

    fn extract_sender_domain(&self, context: &MailContext) -> Option<String> {
        if let Some(from) = context.from_header.as_ref() {
            if let Some(start) = from.rfind('<') {
                if let Some(end) = from.rfind('>') {
                    let email = &from[start + 1..end];
                    return email.split('@').nth(1).map(|s| s.to_lowercase());
                }
            } else if let Some(at_pos) = from.rfind('@') {
                return from[at_pos + 1..]
                    .split_whitespace()
                    .next()
                    .map(|s| s.to_lowercase());
            }
        }
        None
    }
}

impl FeatureExtractor for DomainBusinessMismatchAnalyzer {
    fn extract(&self, context: &MailContext) -> FeatureScore {
        let mut score = 0;
        let mut evidence = Vec::new();

        let combined_text = format!(
            "{} {}",
            context.subject.as_deref().unwrap_or(""),
            context.body.as_deref().unwrap_or("")
        );

        if let Some(sender_domain) = self.extract_sender_domain(context) {
            let is_edu = self.is_educational_domain(&sender_domain);
            let is_gov = self.is_government_domain(&sender_domain);
            let has_payment = self.has_payment_content(&combined_text);
            let has_generic = self.has_generic_greeting(&combined_text);

            // Educational domain sending payment content
            if is_edu && has_payment {
                score += 70; // Increased from 50 - even stronger penalty
                evidence.push("Educational domain sending payment/billing content".to_string());
            }

            // Government domain sending payment content
            if is_gov && has_payment {
                score += 60; // Increased from 30 - stronger penalty
                evidence.push("Government domain sending payment/billing content".to_string());
            }

            // Generic greeting with payment content (compromised account indicator)
            if has_generic && has_payment {
                score += 30; // Increased from 15
                evidence.push("Generic greeting with payment content detected".to_string());
            }

            // Educational/government domain with generic payment greeting (high suspicion)
            if (is_edu || is_gov) && has_generic && has_payment {
                score += 20; // Increased from 10 - Additional penalty for combination
                evidence.push("Institutional domain with suspicious payment pattern".to_string());
            }
        }

        let confidence = if score > 0 { 0.9 } else { 0.0 };

        FeatureScore {
            feature_name: "Domain Business Mismatch".to_string(),
            score,
            confidence,
            evidence,
        }
    }

    fn name(&self) -> &str {
        "Domain Business Mismatch"
    }
}
