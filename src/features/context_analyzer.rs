use super::{FeatureExtractor, FeatureScore};
use crate::MailContext;
use regex::Regex;

pub struct ContextAnalyzer {
    urgency_patterns: Vec<Regex>,
    legitimacy_indicators: Vec<Regex>,
    scam_combinations: Vec<ScamPattern>,
}

#[derive(Debug)]
struct ScamPattern {
    name: String,
    indicators: Vec<String>,
    weight: i32,
}

impl Default for ContextAnalyzer {
    fn default() -> Self {
        Self::new()
    }
}

impl ContextAnalyzer {
    pub fn new() -> Self {
        let urgency_patterns = vec![
            Regex::new(r"(?i)(urgent|immediate|act now|limited time|expires today)").unwrap(),
            Regex::new(r"(?i)(overdue|today|24 hours|don't miss|hurry|last chance)").unwrap(),
            Regex::new(r"(?i)(verify.*account.*immediately|suspend.*account)").unwrap(),
            Regex::new(r"(?i)(click.*here.*now|respond.*within.*hours)").unwrap(),
        ];

        let authority_patterns = vec![
            Regex::new(r"(?i)\b(customs?|border (patrol|protection)|immigration|homeland security)\b").unwrap(),
            Regex::new(r"(?i)\b(tax office|irs|internal revenue|fbi|police|court|legal department)\b").unwrap(),
            Regex::new(r"(?i)\b(government|federal|official|authority|enforcement)\b").unwrap(),
        ];

        let delivery_scam_patterns = vec![
            Regex::new(r"(?i)\b(package|shipment|delivery).{0,30}(arrived|pending|held|custody)\b").unwrap(),
            Regex::new(r"(?i)\b(customs? clearance|delivery.{0,20}fee|shipping.{0,20}charge)\b").unwrap(),
            Regex::new(r"(?i)\b(parcel|item).{0,20}(waiting|ready|available)\b").unwrap(),
        ];

        let info_harvesting_patterns = vec![
            Regex::new(r"(?i)\bprovide.{0,20}(your|personal).{0,20}information\b").unwrap(),
            Regex::new(r"(?i)\b(send|submit|enter).{0,20}(details|information|data)\b").unwrap(),
            Regex::new(r"(?i)\b(confirm|verify|update).{0,20}(identity|account|information)\b").unwrap(),
        ];

        let government_domains = vec![
            ".gov".to_string(),
            ".mil".to_string(),
            "irs.gov".to_string(),
            "dhs.gov".to_string(),
            "cbp.gov".to_string(),
        ];

        let legitimacy_indicators = vec![
            Regex::new(r"(?i)(unsubscribe|privacy policy|terms of service)").unwrap(),
            Regex::new(r"(?i)(customer service|support team|help center)").unwrap(),
            Regex::new(r"(?i)(©.*\d{4}|all rights reserved|trademark)").unwrap(),
        ];

        let scam_combinations = vec![
            ScamPattern {
                name: "Phishing Combo".to_string(),
                indicators: vec![
                    "urgent".to_string(),
                    "verify account".to_string(),
                    "click here".to_string(),
                    "suspend".to_string(),
                ],
                weight: 40,
            },
            ScamPattern {
                name: "Financial Scam".to_string(),
                indicators: vec![
                    "payment failed".to_string(),
                    "update billing".to_string(),
                    "immediate action".to_string(),
                    "account locked".to_string(),
                ],
                weight: 35,
            },
        ];

        Self {
            urgency_patterns,
            legitimacy_indicators,
            scam_combinations,
        }
    }

    pub fn from_config(config: &crate::config_loader::ContextAnalysisConfig) -> Self {
        let urgency_patterns: Vec<Regex> = config
            .urgency_patterns
            .iter()
            .filter_map(|pattern| Regex::new(&format!("(?i){}", pattern)).ok())
            .collect();

        // Use default legitimacy indicators and scam combinations for now
        let legitimacy_indicators = vec![
            Regex::new(r"(?i)(unsubscribe|privacy policy|terms of service)").unwrap(),
            Regex::new(r"(?i)(customer service|support team|help desk)").unwrap(),
            Regex::new(r"(?i)(official|authorized|legitimate)").unwrap(),
        ];

        let scam_combinations = vec![
            ScamPattern {
                name: "Urgent Payment Scam".to_string(),
                indicators: vec![
                    "urgent".to_string(),
                    "payment".to_string(),
                    "suspend".to_string(),
                    "verify".to_string(),
                    "click here".to_string(),
                ],
                weight: 25,
            },
            ScamPattern {
                name: "Account Security Scam".to_string(),
                indicators: vec![
                    "security".to_string(),
                    "breach".to_string(),
                    "unauthorized".to_string(),
                    "verify account".to_string(),
                    "immediate action".to_string(),
                ],
                weight: 30,
            },
            ScamPattern {
                name: "Billing Update Scam".to_string(),
                indicators: vec![
                    "billing".to_string(),
                    "expired".to_string(),
                    "update payment".to_string(),
                    "update billing".to_string(),
                    "immediate action".to_string(),
                    "account locked".to_string(),
                ],
                weight: 35,
            },
        ];

        Self {
            urgency_patterns,
            legitimacy_indicators,
            scam_combinations,
        }
    }

    fn analyze_urgency_vs_legitimacy(&self, context: &MailContext) -> (i32, Vec<String>) {
        let body = context.body.as_deref().unwrap_or("");
        let subject = context
            .headers
            .get("Subject")
            .map(|s| s.as_str())
            .unwrap_or("");
        let full_text = format!("{} {}", subject, body);

        let mut urgency_score = 0;
        let mut legitimacy_score = 0;
        let mut evidence = Vec::new();

        // Count urgency indicators
        for pattern in &self.urgency_patterns {
            if pattern.is_match(&full_text) {
                urgency_score += 10;
                evidence.push(format!("Urgency pattern detected: {}", pattern.as_str()));
            }
        }

        // Count legitimacy indicators
        for pattern in &self.legitimacy_indicators {
            if pattern.is_match(&full_text) {
                legitimacy_score += 5;
            }
        }

        // High urgency with low legitimacy is suspicious
        let score = if urgency_score > 20 && legitimacy_score < 10 {
            urgency_score - legitimacy_score
        } else {
            0
        };

        (score, evidence)
    }

    fn analyze_scam_combinations(&self, context: &MailContext) -> (i32, Vec<String>) {
        let body = context.body.as_deref().unwrap_or("");
        let subject = context
            .headers
            .get("Subject")
            .map(|s| s.as_str())
            .unwrap_or("");
        let full_text = format!("{} {}", subject, body).to_lowercase();

        let mut total_score = 0;
        let mut evidence = Vec::new();

        for pattern in &self.scam_combinations {
            let matches = pattern
                .indicators
                .iter()
                .filter(|indicator| full_text.contains(&indicator.to_lowercase()))
                .count();

            if matches >= 2 {
                let score = pattern.weight * matches as i32 / pattern.indicators.len() as i32;
                total_score += score;
                evidence.push(format!(
                    "{} pattern detected ({} indicators)",
                    pattern.name, matches
                ));
            }
        }

        (total_score, evidence)
    }

    fn analyze_content_structure(&self, context: &MailContext) -> (i32, Vec<String>) {
        let mut score = 0;
        let mut evidence = Vec::new();

        // Check for suspicious structure patterns
        if let Some(body) = &context.body {
            // Very short body with urgent action
            if body.len() < 200 && body.to_lowercase().contains("click") {
                score += 15;
                evidence.push("Very short email with action request".to_string());
            }

            // Excessive capitalization
            let caps_count = body.chars().filter(|c| c.is_uppercase()).count();
            let total_chars = body.chars().filter(|c| c.is_alphabetic()).count();
            if total_chars > 0 && caps_count * 100 / total_chars > 50 {
                score += 10;
                evidence.push("Excessive capitalization detected".to_string());
            }

            // Multiple exclamation marks
            let exclamation_count = body.matches('!').count();
            if exclamation_count > 3 {
                score += 5;
                evidence.push("Multiple exclamation marks detected".to_string());
            }
        }

        (score, evidence)
    }
}

impl FeatureExtractor for ContextAnalyzer {
    fn extract(&self, context: &MailContext) -> FeatureScore {
        let mut total_score = 0;
        let mut all_evidence = Vec::new();

        let body = context.body.as_deref().unwrap_or("");
        let subject = context.headers.get("Subject").map(|s| s.as_str()).unwrap_or("");
        let combined_text = format!("{} {}", subject, body);
        let sender = context.headers.get("From").map(|s| s.as_str()).unwrap_or("");

        // Authority impersonation detection
        let authority_regex = Regex::new(r"(?i)\b(customs? (and )?protection|border (patrol|protection)|immigration (office|department)|homeland security|tax office|irs|internal revenue service|fbi|police department|court (order|notice)|legal department|government (agency|office)|federal (agency|office)|official (notice|communication)|enforcement (agency|division))\b").unwrap();
        if authority_regex.is_match(&combined_text) && !sender.contains(".gov") && !sender.contains(".mil") {
            total_score += 60;
            all_evidence.push("Authority impersonation: Claims government/official status from non-government sender".to_string());
        }

        // Package delivery scam detection
        let delivery_regex = Regex::new(r"(?i)\b(package|shipment|delivery).{0,30}(arrived|pending|held|custody)\b").unwrap();
        if delivery_regex.is_match(&combined_text) {
            total_score += 45;
            all_evidence.push("Package delivery scam patterns detected".to_string());
        }

        // Information harvesting detection
        let harvesting_regex = Regex::new(r"(?i)\bprovide.{0,20}(your|personal).{0,20}information\b").unwrap();
        if harvesting_regex.is_match(&combined_text) {
            total_score += 35;
            all_evidence.push("Information harvesting request detected".to_string());
        }

        // Analyze urgency vs legitimacy
        let (urgency_score, mut urgency_evidence) = self.analyze_urgency_vs_legitimacy(context);
        total_score += urgency_score;
        all_evidence.append(&mut urgency_evidence);

        // Analyze scam combinations
        let (scam_score, mut scam_evidence) = self.analyze_scam_combinations(context);
        total_score += scam_score;
        all_evidence.append(&mut scam_evidence);

        // Analyze content structure
        let (structure_score, mut structure_evidence) = self.analyze_content_structure(context);
        total_score += structure_score;
        all_evidence.append(&mut structure_evidence);

        let confidence = if all_evidence.is_empty() { 0.7 } else { 0.85 };

        FeatureScore {
            feature_name: "Context Analysis".to_string(),
            score: total_score,
            confidence,
            evidence: all_evidence,
        }
    }

    fn name(&self) -> &str {
        "context_analyzer"
    }
}
