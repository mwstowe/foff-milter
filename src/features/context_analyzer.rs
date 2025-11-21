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
        let subject = context
            .headers
            .get("Subject")
            .map(|s| s.as_str())
            .unwrap_or("");
        let combined_text = format!("{} {}", subject, body);
        let sender = context
            .headers
            .get("From")
            .map(|s| s.as_str())
            .unwrap_or("");

        // Debug logging
        log::debug!("Context analyzer - Subject: '{}'", subject);
        log::debug!("Context analyzer - Sender: '{}'", sender);
        log::debug!(
            "Context analyzer - From header: '{:?}'",
            context.from_header
        );

        // Giveaway language patterns
        let giveaway_language_regex = Regex::new(r"(?i)\b(your.*(prize|gift).*awaits|claim.*your.*(prize|gift)|congratulations.*winner|you.*have.*won)\b").unwrap();
        if giveaway_language_regex.is_match(&combined_text) {
            total_score += 35;
            all_evidence.push("Giveaway language pattern detected".to_string());
        }

        // Prize notification subjects
        if let Some(subject) = context.subject.as_deref() {
            let prize_subject_regex = Regex::new(
                r"(?i)\b(awaits|claim.*from|congratulations.*[a-z]+|winner.*notification)\b",
            )
            .unwrap();
            if prize_subject_regex.is_match(subject) {
                total_score += 25;
                all_evidence.push("Prize notification subject pattern detected".to_string());
            }
        }

        // Product prize scam detection (very specific to scam contexts)
        let product_prize_regex = Regex::new(r"(?i)\b(yeti.*(rambler|tumbler).*awaits|your.*(prize|gift).*awaits|claim.*your.*(prize|gift).*from)\b").unwrap();
        if product_prize_regex.is_match(&combined_text) {
            total_score += 50;
            all_evidence.push("Product prize scam pattern detected".to_string());
        }

        // Holiday/seasonal giveaway scams
        let seasonal_giveaway_regex = Regex::new(r"(?i)\b(thanksgiving|christmas|holiday|black.*friday).*(claim.*from|giveaway.*from|gift.*from)\b").unwrap();
        if seasonal_giveaway_regex.is_match(&combined_text) {
            total_score += 45;
            all_evidence.push("Seasonal giveaway scam pattern detected".to_string());
        }

        // Exclusive opportunity language detection (scam-specific contexts)
        let exclusive_regex = Regex::new(r"(?i)\b(exclusive.*opportunity.*receive|you.*chosen.*exclusive|selected.*exclusive.*offer|exclusive.*collection.*unclaimed)\b").unwrap();
        if exclusive_regex.is_match(&combined_text) {
            total_score += 25;
            all_evidence.push("Exclusive opportunity scam language detected".to_string());
        }

        // Congratulations/prize scam detection
        let prize_scam_regex = Regex::new(r"(?i)\b(congratulations.*you.*chosen|you.*been.*selected|exclusive.*opportunity|winner.*notification)\b").unwrap();
        if prize_scam_regex.is_match(&combined_text) {
            total_score += 40;
            all_evidence.push("Prize/congratulations scam pattern detected".to_string());
        }

        // Mystery box scam detection
        let mystery_box_regex = Regex::new(r"(?i)\b(mystery box|lost items|unclaimed treasures|abandoned packages|undelivered packages)\b").unwrap();
        if mystery_box_regex.is_match(&combined_text) {
            total_score += 60;
            all_evidence.push("Mystery box scam pattern detected".to_string());
        }

        // Survey scam detection
        let survey_scam_regex = Regex::new(r"(?i)\b(complete.*survey.*unlock|survey.*special offer|quick survey.*unlock|survey.*exclusive)\b").unwrap();
        if survey_scam_regex.is_match(&combined_text) {
            total_score += 55;
            all_evidence.push("Survey scam pattern detected".to_string());
        }

        // Subject pattern analysis
        let subject_special_chars = Regex::new(r"[.?%#]{3,}").unwrap();
        let subject_text = context.subject.as_deref().unwrap_or("");
        if subject_special_chars.is_match(subject_text) {
            total_score += 25;
            all_evidence.push("Suspicious subject with excessive special characters".to_string());
        }

        // Social engineering detection
        let social_eng_regex = Regex::new(
            r"(?i)\b(screenshot of the error|would you like me to send|technical assistance)\b",
        )
        .unwrap();
        if social_eng_regex.is_match(&combined_text) {
            total_score += 40;
            all_evidence.push("Social engineering pattern detected".to_string());
        }

        // Financial spam detection (more specific patterns)
        let financial_regex = Regex::new(
            r"(?i)\b(refinance rates|lower refinance rates|lock in.{0,20}(savings|rates)|fha.{0,20}(rate|guide)|mortgage rates are here)\b",
        )
        .unwrap();
        let subject_text = context.subject.as_deref().unwrap_or("");
        let from_header = context.from_header.as_deref().unwrap_or("");
        let financial_check_text = format!("{} {} {}", subject_text, body, from_header);
        if financial_regex.is_match(&financial_check_text) {
            total_score += 45;
            all_evidence.push("Financial spam patterns detected".to_string());
        }

        // Content mismatch detection
        if let Some(body) = &context.body {
            let title_match = Regex::new(r"<title>([^<]+)</title>").unwrap();
            if let Some(title_cap) = title_match.captures(body) {
                let title = title_cap.get(1).unwrap().as_str().to_lowercase();
                let sender_lower = sender.to_lowercase();
                if (sender_lower.contains("keto") || sender_lower.contains("diet"))
                    && !title.contains("keto")
                    && !title.contains("diet")
                {
                    total_score += 50;
                    all_evidence
                        .push("Content mismatch: Health sender with unrelated content".to_string());
                }
            }
        }

        // Health spam detection
        let health_regex =
            Regex::new(r"(?i)\b(keto|diet.?miracle|weight.?loss|health.?supplement)\b").unwrap();
        let from_header = context.from_header.as_deref().unwrap_or("");
        let check_text = format!("{} {}", sender, from_header);
        if health_regex.is_match(&check_text)
            && !sender.contains("health")
            && !sender.contains("nutrition")
        {
            total_score += 40;
            all_evidence.push("Health spam from non-health domain".to_string());
        }

        // Authority impersonation detection (improved to avoid false positives from domain names)
        let authority_regex = Regex::new(r"(?i)\b(customs? (and )?protection|border (patrol|protection)|immigration (office|department)|homeland security|tax office|irs|internal revenue service|fbi|police department|court (order|notice)|legal department|government (agency|office)|federal (agency|office)|official (notice|communication)|enforcement (agency|division))\b").unwrap();

        // Additional check: exclude matches that are part of domain names or URLs
        let mut authority_match = false;
        if let Some(captures) = authority_regex.captures(&combined_text) {
            if let Some(matched) = captures.get(0) {
                let match_str = matched.as_str();
                let match_start = matched.start();

                // Check if this match is part of a domain name (has .com, .org, etc. nearby)
                let context_start = match_start.saturating_sub(20);
                let context_end = std::cmp::min(matched.end() + 20, combined_text.len());
                let context = &combined_text[context_start..context_end];

                // Skip if it's part of a domain name or URL
                if !context.contains(".com")
                    && !context.contains(".org")
                    && !context.contains(".net")
                    && !context.contains("://")
                    && !context.contains("www.")
                {
                    authority_match = true;
                    log::info!(
                        "Authority impersonation detected - pattern: '{}', context: '{}'",
                        match_str,
                        context
                    );
                } else {
                    log::info!(
                        "Authority pattern '{}' skipped - appears to be part of domain/URL: '{}'",
                        match_str,
                        context
                    );
                }
            }
        }

        if authority_match && !sender.contains(".gov") && !sender.contains(".mil") {
            total_score += 60;
            all_evidence.push("Authority impersonation: Claims government/official status from non-government sender".to_string());
        }

        // Package delivery scam detection
        let delivery_regex =
            Regex::new(r"(?i)\b(package|shipment|delivery).{0,30}(arrived|pending|held|custody)\b")
                .unwrap();
        if delivery_regex.is_match(&combined_text) {
            total_score += 45;
            all_evidence.push("Package delivery scam patterns detected".to_string());
        }

        // Information harvesting detection
        let harvesting_regex =
            Regex::new(r"(?i)\bprovide.{0,20}(your|personal).{0,20}information\b").unwrap();
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
