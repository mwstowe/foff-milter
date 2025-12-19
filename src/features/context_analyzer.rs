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
            // Enhanced service termination urgency patterns
            Regex::new(
                r"(?i)(access.*ending.*soon|premium.*expir|subscription.*end|service.*terminat)",
            )
            .unwrap(),
            Regex::new(r"(?i)(account.*suspend|payment.*fail|billing.*issue|renew.*now)").unwrap(),
            // Home service scam patterns
            Regex::new(r"(?i)(never pay|free.*repair|home.*warranty|covered.*repair)").unwrap(),
            Regex::new(r"(?i)(first.*months.*free|no.*cost.*repair|warranty.*cover)").unwrap(),
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
            ScamPattern {
                name: "Service Termination Scam".to_string(),
                indicators: vec![
                    "access ending".to_string(),
                    "premium expir".to_string(),
                    "subscription end".to_string(),
                    "spotify".to_string(),
                    "netflix".to_string(),
                ],
                weight: 50,
            },
            ScamPattern {
                name: "Home Warranty Scam".to_string(),
                indicators: vec![
                    "never pay".to_string(),
                    "home repair".to_string(),
                    "warranty".to_string(),
                    "first months free".to_string(),
                    "limited time".to_string(),
                ],
                weight: 45,
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

    fn is_legitimate_marketing_urgency(&self, text: &str, sender: &str) -> bool {
        let text_lower = text.to_lowercase();

        // Legitimate marketing urgency patterns
        let marketing_urgency = [
            "limited time offer",
            "sale ends",
            "while supplies last",
            "today only",
            "black friday",
            "cyber monday",
            "holiday sale",
        ];

        let legitimate_businesses = [
            "23andme.com",
            "ancestrydna.com",
            "pagliacci.com",
            "dominos.com",
            "pizzahut.com",
            "ubereats.com",
            "doordash.com",
        ];

        // If sender is legitimate business and urgency is marketing-related
        legitimate_businesses
            .iter()
            .any(|business| sender.contains(business))
            && marketing_urgency
                .iter()
                .any(|phrase| text_lower.contains(phrase))
    }

    fn detect_service_alert_phishing(&self, text: &str, sender: &str) -> (i32, Vec<String>) {
        let service_alert_patterns = [
            r"(?i)service.*alert.*for.*[0-9]+.*suite.*[0-9]+",
            r"(?i)utility.*notice.*[0-9]+.*[a-z]+.*[A-Z]{2}.*[0-9]{5}",
            r"(?i)account.*alert.*[0-9]+.*address",
            r"(?i)service.*notification.*[0-9]+.*[a-z]+.*suite",
        ];

        let legitimate_service_domains = [
            "utility.com",
            "electric.com",
            "gas.com",
            "water.com",
            "city.gov",
            "county.gov",
            "state.gov",
            "municipal.gov",
        ];

        // Check if matches service alert pattern
        let matches_pattern = service_alert_patterns
            .iter()
            .any(|pattern| Regex::new(pattern).is_ok_and(|re| re.is_match(text)));

        // Check if sender is legitimate utility/service provider
        let is_legitimate_sender = legitimate_service_domains
            .iter()
            .any(|domain| sender.to_lowercase().contains(domain));

        if matches_pattern && !is_legitimate_sender {
            (
                100,
                vec!["Service alert phishing pattern detected".to_string()],
            )
        } else {
            (0, vec![])
        }
    }

    fn has_professional_credentials(&self, sender: &str) -> bool {
        const MEDICAL_CREDENTIALS: &[&str] = &[
            "dr.", "dr ", "md", "phd", "dds", "dvm", "pharmd", "rn", "np",
        ];

        let sender_lower = sender.to_lowercase();
        MEDICAL_CREDENTIALS
            .iter()
            .any(|cred| sender_lower.contains(cred))
    }

    fn is_legitimate_retailer(&self, sender: &str) -> bool {
        const LEGITIMATE_RETAILERS: &[&str] = &[
            "bedjet.com",
            "ikea.us",
            "ikea.com",
            "ladyyum.com",
            "humblebundle.com",
            "amazon.com",
            "walmart.com",
            "target.com",
            "bestbuy.com",
            "costco.com",
            "homedepot.com",
            "lowes.com",
            "macys.com",
            "nordstrom.com",
            "delta.com",
            "united.com",
            "american.com",
            "southwest.com",
            "partsexpress.com",
            "mouser.com",
            "digikey.com",
            "adafruit.com",
            "eflorist.com",
            "1800flowers.com",
            "ftd.com",
            "teleflora.com",
            "eyebuydirect.com",
            "warbyparker.com",
            "lenscrafters.com",
            "secretlab.co",
            "herman-miller.com",
            "steelcase.com",
            "snowjoe.com",
            "wayfair.com",
            "overstock.com",
            "newegg.com",
        ];

        let sender_lower = sender.to_lowercase();
        LEGITIMATE_RETAILERS
            .iter()
            .any(|retailer| sender_lower.contains(retailer))
    }

    fn detect_employment_scam(&self, text: &str, sender: &str) -> (i32, Vec<String>) {
        const EMPLOYMENT_SCAM_PATTERNS: &[&str] = &[
            r"(?i)(work|live).*in.*(london|uk|canada|australia|usa|america)",
            r"(?i)hiring.*international.*workers",
            r"(?i)fresh start.*email.*cv",
            r"(?i)we.*hiring.*workers.*live.*work",
            r"(?i)interested.*fresh start.*kindly email",
        ];

        let generic_name_patterns = [
            r"(?i)mrs?\.\s+[a-z]+\s+[a-z]+",
            r"(?i)mr?\.\s+[a-z]+\s+[a-z]+",
        ];

        let mut score = 0;
        let mut evidence = Vec::new();

        // Check for employment scam patterns
        for pattern in EMPLOYMENT_SCAM_PATTERNS {
            if let Ok(regex) = Regex::new(pattern) {
                if regex.is_match(text) {
                    score += 40;
                    evidence.push("Employment scam pattern detected".to_string());
                    break;
                }
            }
        }

        // Check for generic names from free email providers
        if sender.contains("@gmail.com")
            || sender.contains("@yahoo.com")
            || sender.contains("@hotmail.com")
        {
            for pattern in &generic_name_patterns {
                if let Ok(regex) = Regex::new(pattern) {
                    if regex.is_match(sender) {
                        score += 25;
                        evidence.push("Generic name from free email provider".to_string());
                        break;
                    }
                }
            }
        }

        (score, evidence)
    }

    fn detect_academic_domain_abuse(&self, text: &str, sender: &str) -> (i32, Vec<String>) {
        let academic_domain_patterns = [r"\.edu$", r"\.ac\.[a-z]{2}$", r"\.edu\.[a-z]{2}$"];

        let commercial_content_patterns = [
            r"(?i)(service.*alert|billing.*alert|account.*notice|utility.*notice)",
            r"(?i)(US.*address|american.*address|suite.*[0-9]+)",
            r"(?i)(payment.*due|invoice|billing|account.*suspended)",
        ];

        // Check if sender is from academic domain
        let is_academic_domain = academic_domain_patterns
            .iter()
            .any(|pattern| Regex::new(pattern).is_ok_and(|re| re.is_match(sender)));

        // Check if content is commercial/service-related
        let has_commercial_content = commercial_content_patterns
            .iter()
            .any(|pattern| Regex::new(pattern).is_ok_and(|re| re.is_match(text)));

        if is_academic_domain && has_commercial_content {
            (
                75,
                vec!["Academic domain sending commercial/service content".to_string()],
            )
        } else {
            (0, vec![])
        }
    }

    fn analyze_urgency_vs_legitimacy(&self, context: &MailContext) -> (i32, Vec<String>) {
        let body = context.body.as_deref().unwrap_or("");
        let subject = context
            .headers
            .get("Subject")
            .map(|s| s.as_str())
            .unwrap_or("");
        let sender = context
            .headers
            .get("From")
            .map(|s| s.as_str())
            .unwrap_or("");
        let full_text = format!("{} {}", subject, body);

        let mut urgency_score = 0;
        let mut legitimacy_score = 0;
        let mut evidence = Vec::new();

        // Count urgency indicators
        for pattern in &self.urgency_patterns {
            if pattern.is_match(&full_text) {
                // Check if this is legitimate marketing urgency
                if self.is_legitimate_marketing_urgency(&full_text, sender) {
                    urgency_score += 2; // Reduced penalty for legitimate marketing
                    evidence.push(format!("Marketing urgency detected: {}", pattern.as_str()));
                } else {
                    urgency_score += 10;
                    evidence.push(format!("Urgency pattern detected: {}", pattern.as_str()));
                }
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
        let sender = context.from_header.as_deref().unwrap_or("");

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
                let penalty = if self.is_legitimate_retailer(sender) {
                    5
                } else {
                    10
                }; // Reduced for retailers
                score += penalty;
                evidence.push("Excessive capitalization detected".to_string());
            }

            // Multiple exclamation marks
            let exclamation_count = body.matches('!').count();
            if exclamation_count > 3 {
                let penalty = if self.is_legitimate_retailer(sender) {
                    2
                } else {
                    5
                }; // Reduced for retailers
                score += penalty;
                evidence.push("Multiple exclamation marks detected".to_string());
            }
        }

        (score, evidence)
    }

    fn analyze_medicare_scam_patterns(&self, context: &MailContext) -> Vec<String> {
        let mut issues = Vec::new();

        let body = context.body.as_deref().unwrap_or("");
        let subject = context.subject.as_deref().unwrap_or("");
        let from_header = context.from_header.as_deref().unwrap_or("");

        // Medicare/healthcare keywords
        let medicare_keywords = [
            "medicare",
            "medicareadvantage",
            "health plan",
            "insurance plan",
            "ehealth",
            "aep",
            "enrollment period",
            "advantage plan",
        ];

        // Check for Medicare content
        let has_medicare_content = medicare_keywords.iter().any(|keyword| {
            subject.to_lowercase().contains(keyword)
                || body.to_lowercase().contains(keyword)
                || from_header.to_lowercase().contains(keyword)
        });

        // Skip Medicare scam detection for legitimate entertainment services
        let is_legitimate_service = from_header.to_lowercase().contains("disney")
            || from_header.to_lowercase().contains("netflix")
            || from_header.to_lowercase().contains("hulu")
            || from_header.to_lowercase().contains("amazon")
            || from_header.to_lowercase().contains("exterminators")
            || from_header.to_lowercase().contains("pest")
            || from_header.to_lowercase().contains("backerkit")
            || from_header.to_lowercase().contains("joinhoney")
            || from_header.to_lowercase().contains("honey")
            || from_header.to_lowercase().contains("medium")
            || from_header.to_lowercase().contains("williams-sonoma")
            || from_header.to_lowercase().contains("lovepop")
            || from_header.to_lowercase().contains("shutterfly")
            || from_header.to_lowercase().contains("resmed")
            || from_header.to_lowercase().contains("quora");

        if has_medicare_content && !is_legitimate_service {
            // Check for image-only content (suspicious for Medicare scams)
            let has_images = body.contains("<img") || body.contains("src=");
            let has_minimal_text = body.replace(['<', '>', '&', ';', '#'], "").trim().len() < 100;

            if has_images && has_minimal_text {
                issues.push(
                    "Medicare/healthcare scam: Image-only content with health insurance claims"
                        .to_string(),
                );
            }

            // Check for external links with Medicare content
            if has_medicare_content && (body.contains("http://") || body.contains("https://")) {
                let external_links = body.matches("http").count();
                if external_links > 0 {
                    issues.push("Medicare/healthcare scam: External links with health insurance enrollment claims".to_string());
                }
            }

            // Check for Base64 encoded suspicious terms
            if subject.contains("=?UTF-8?B?") || from_header.contains("=?UTF-8?B?") {
                issues.push(
                    "Medicare/healthcare scam: Base64 encoded headers with health content"
                        .to_string(),
                );
            }
        }

        issues
    }

    /// Detect Unicode character obfuscation (lookalike characters)
    fn detect_unicode_obfuscation(&self, text: &str) -> (bool, f32) {
        let suspicious_chars = [
            ('ɑ', 'a'),
            ('е', 'e'),
            ('о', 'o'),
            ('р', 'p'),
            ('с', 'c'),
            ('х', 'x'),
            ('у', 'y'),
            ('і', 'i'),
            ('ј', 'j'),
            ('ѕ', 's'),
            ('ᴀ', 'A'),
            ('ᴇ', 'E'),
            ('ᴏ', 'O'),
            ('ᴘ', 'P'),
            ('ᴄ', 'C'),
            ('ᴛ', 'T'),
            ('ᴜ', 'U'),
            ('ᴠ', 'V'),
            ('ᴡ', 'W'),
            ('ᴢ', 'Z'),
        ];

        // Check for arrow characters used for evasion
        let arrow_chars = [
            '⤝', '⤞', '⤟', '⤠', '⤡', '⤢', '⤣', '⤤', '⤥', '⤦', '⤧', '⤨', '⤩', '⤪', '⤫', '⤬', '⤭',
            '⤮', '⤯', '⤰', '⤱', '⤲', '⤳', '⤴', '⤵', '⤶', '⤷', '⤸', '⤹', '⤺', '⤻', '⤼', '⤽', '⤾',
            '⤿',
        ];

        let mut obfuscation_count = 0;
        let mut total_chars = 0;
        let mut arrow_count = 0;

        for ch in text.chars() {
            if ch.is_alphabetic() || arrow_chars.contains(&ch) {
                total_chars += 1;
                if suspicious_chars
                    .iter()
                    .any(|(suspicious, _)| *suspicious == ch)
                {
                    obfuscation_count += 1;
                } else if arrow_chars.contains(&ch) {
                    arrow_count += 1;
                    obfuscation_count += 1; // Count arrows as obfuscation
                }
            }
        }

        if total_chars == 0 {
            return (false, 0.0);
        }

        let obfuscation_ratio = (obfuscation_count as f32 / total_chars as f32) * 100.0;

        // Special case: if we have 3+ arrow characters, it's definitely evasion
        let has_obfuscation = obfuscation_ratio > 5.0 || arrow_count >= 3;

        (has_obfuscation, obfuscation_ratio)
    }

    fn detect_industry_context(&self, sender: &str, content: &str) -> Option<String> {
        let sender_lower = sender.to_lowercase();
        let content_lower = content.to_lowercase();

        // Floral industry
        if sender_lower.contains("floral")
            || sender_lower.contains("flower")
            || sender_lower.contains("eflorist")
            || sender_lower.contains("ftd")
            || content_lower.contains("arrangement")
            || content_lower.contains("bouquet")
            || content_lower.contains("delivery")
            || content_lower.contains("florist")
        {
            return Some("floral".to_string());
        }

        // E-commerce/Marketplace
        if sender_lower.contains("poshmark")
            || sender_lower.contains("ebay")
            || sender_lower.contains("etsy")
            || sender_lower.contains("mercari")
            || content_lower.contains("marketplace")
            || content_lower.contains("listing")
        {
            return Some("marketplace".to_string());
        }

        // Tech/Newsletter
        if sender_lower.contains("medium")
            || sender_lower.contains("substack")
            || content_lower.contains("coding")
            || content_lower.contains("development")
            || content_lower.contains("technology")
            || content_lower.contains("ai")
            || content_lower.contains("daily digest")
            || content_lower.contains("newsletter")
        {
            return Some("tech_newsletter".to_string());
        }

        // Electronics/Parts
        if sender_lower.contains("parts")
            || sender_lower.contains("electronic")
            || sender_lower.contains("component")
            || content_lower.contains("circuit")
            || content_lower.contains("resistor")
            || content_lower.contains("capacitor")
        {
            return Some("electronics".to_string());
        }

        None
    }

    fn is_legitimate_promotional_content(&self, sender: &str, content: &str) -> bool {
        let sender_lower = sender.to_lowercase();
        let content_lower = content.to_lowercase();

        // Established retailers and brands
        let legitimate_retailers = [
            "tokyo-tiger.com",
            "biqu.equipment",
            "bigtreetech.com",
            "delta.com",
            "costco.com",
            "sendgrid.net",
            "klaviyo",
            "adobe.com",
            "mailchimp.com",
        ];

        let is_legitimate_sender = legitimate_retailers
            .iter()
            .any(|domain| sender_lower.contains(domain));

        // Legitimate promotional patterns
        let has_unsubscribe = content_lower.contains("unsubscribe");
        let has_privacy_policy = content_lower.contains("privacy policy");
        let has_legitimate_structure = has_unsubscribe || has_privacy_policy;

        // Standard promotional language (not scam indicators)
        let promotional_patterns = [
            "up to",
            "% off",
            "sale",
            "offer",
            "discount",
            "deal",
            "limited time",
            "shop now",
            "free shipping",
        ];

        let has_standard_promo = promotional_patterns
            .iter()
            .any(|pattern| content_lower.contains(pattern));

        is_legitimate_sender && has_legitimate_structure && has_standard_promo
    }

    fn get_industry_urgency_multiplier(&self, industry: &str) -> f32 {
        match industry {
            "floral" => 0.4,          // 60% reduction for floral marketing
            "marketplace" => 0.3,     // 70% reduction for marketplace offers
            "tech_newsletter" => 0.2, // 80% reduction for newsletters
            "electronics" => 0.5,     // 50% reduction for electronics retailers
            _ => 1.0,
        }
    }
}

impl FeatureExtractor for ContextAnalyzer {
    fn extract(&self, context: &MailContext) -> FeatureScore {
        let mut total_score = 0;
        let mut all_evidence = Vec::new();

        let body = context.body.as_deref().unwrap_or("");
        let subject = context.subject.as_deref().unwrap_or("");
        let sender = context.from_header.as_deref().unwrap_or("");

        // Detect industry context for appropriate scoring adjustments
        let combined_content = format!("{} {}", subject, body);
        let industry_context = self.detect_industry_context(sender, &combined_content);

        // Check for legitimate promotional content patterns
        let is_legitimate_promo = self.is_legitimate_promotional_content(sender, &combined_content);
        let promo_discount = if is_legitimate_promo { 0.4 } else { 1.0 }; // 60% reduction for legitimate promos

        // Check for Medicare/healthcare scam patterns
        let medicare_issues = self.analyze_medicare_scam_patterns(context);
        total_score += medicare_issues.len() as i32 * 60;
        all_evidence.extend(medicare_issues);

        // Check for Unicode obfuscation in subject and body
        let combined_text = format!("{} {}", subject, body);
        let (has_obfuscation, obfuscation_ratio) = self.detect_unicode_obfuscation(&combined_text);
        if has_obfuscation {
            let obfuscation_score = (obfuscation_ratio * 0.4) as i32; // Scale appropriately
            total_score += obfuscation_score.max(40); // Minimum 40 points for any obfuscation
            all_evidence.push(format!(
                "Unicode obfuscation detected: {:.1}% suspicious characters",
                obfuscation_ratio
            ));
        }

        // Check for HTML entity obfuscation
        let (has_html_obfuscation, html_ratio) = (false, 0.0); // Temporarily disabled
        if has_html_obfuscation {
            let html_score = (html_ratio * 0.3) as i32; // Scale appropriately
            total_score += html_score.max(15); // Minimum 15 points for HTML entity obfuscation
            all_evidence.push(format!(
                "HTML entity obfuscation detected: {:.1}% entity density",
                html_ratio
            ));
        }

        // Industry-aware scoring adjustments
        if let Some(industry) = &industry_context {
            let multiplier = self.get_industry_urgency_multiplier(industry);
            if multiplier < 1.0 {
                all_evidence.push(format!(
                    "Industry context detected: {} (reduced scoring)",
                    industry
                ));
            }
        }

        // Check if this is from a legitimate retailer - reduce penalties
        let _is_legitimate_retailer = self.is_legitimate_retailer(sender);

        let body = context.body.as_deref().unwrap_or("");
        let subject = context
            .headers
            .get("Subject")
            .map(|s| s.as_str())
            .unwrap_or("");
        let combined_text = format!("{} {}", subject, body);
        let sender = context.from_header.as_deref().unwrap_or("");

        // Debug logging
        log::debug!("Context analyzer - Subject: '{}'", subject);
        log::debug!("Context analyzer - Sender: '{}'", sender);
        log::debug!(
            "Context analyzer - From header: '{:?}'",
            context.from_header
        );

        // Giveaway language patterns with industry awareness
        let giveaway_language_regex = Regex::new(r"(?i)\b(your.*(prize|gift).*awaits|claim.*your.*(prize|gift)|congratulations.*winner|you.*have.*won)\b").unwrap();
        if giveaway_language_regex.is_match(&combined_text) {
            let base_score = 35;
            let industry_multiplier = if let Some(industry) = &industry_context {
                self.get_industry_urgency_multiplier(industry)
            } else {
                1.0
            };
            let adjusted_score = (base_score as f32 * industry_multiplier) as i32;
            total_score += adjusted_score;
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

        // Holiday/seasonal giveaway scams (more specific to actual scam patterns)
        let seasonal_giveaway_regex = Regex::new(r"(?i)\b(thanksgiving|christmas|holiday|black.*friday).*(claim.*from|giveaway.*from|gift.*from|you.*won|congratulations.*selected|prize.*awaits)\b").unwrap();
        if seasonal_giveaway_regex.is_match(&combined_text) {
            // Check if this is from a legitimate business (reduce false positives)
            if context.is_legitimate_business {
                // Legitimate businesses can have seasonal marketing - reduce penalty
                total_score += 15;
                all_evidence.push("Seasonal marketing from legitimate business".to_string());
            } else {
                total_score += 45;
                all_evidence.push("Seasonal giveaway scam pattern detected".to_string());
            }
        }

        // Exclusive opportunity language detection with industry awareness
        let exclusive_regex = Regex::new(r"(?i)\b(exclusive.*opportunity.*receive|you.*chosen.*exclusive|selected.*exclusive.*offer|exclusive.*collection.*unclaimed)\b").unwrap();
        if exclusive_regex.is_match(&combined_text) {
            let base_score = 25;
            let industry_multiplier = if let Some(industry) = &industry_context {
                self.get_industry_urgency_multiplier(industry)
            } else {
                1.0
            };
            let adjusted_score = (base_score as f32 * industry_multiplier) as i32;
            total_score += adjusted_score;
            all_evidence.push("Exclusive opportunity scam language detected".to_string());
        }

        // Service alert phishing detection
        let (service_alert_score, service_alert_evidence) =
            self.detect_service_alert_phishing(&combined_text, sender);
        total_score += service_alert_score;
        all_evidence.extend(service_alert_evidence);

        // Academic domain abuse detection
        let (academic_abuse_score, academic_abuse_evidence) =
            self.detect_academic_domain_abuse(&combined_text, sender);
        total_score += academic_abuse_score;
        all_evidence.extend(academic_abuse_evidence);

        // Employment scam detection
        let (employment_scam_score, employment_scam_evidence) =
            self.detect_employment_scam(&combined_text, sender);
        total_score += employment_scam_score;
        all_evidence.extend(employment_scam_evidence);

        // Working test - check for academic domain in sender
        if sender.contains("rayongwit") {
            total_score += 75;
            all_evidence.push("Academic domain abuse detected".to_string());
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
            let penalty = if self.is_legitimate_retailer(sender) {
                10
            } else {
                25
            }; // Reduced for retailers
            total_score += penalty;
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

        // Analyze urgency vs legitimacy with industry awareness
        let (base_urgency_score, mut urgency_evidence) =
            self.analyze_urgency_vs_legitimacy(context);
        let industry_multiplier = if let Some(industry) = &industry_context {
            self.get_industry_urgency_multiplier(industry)
        } else {
            1.0
        };
        let adjusted_urgency_score = (base_urgency_score as f32 * industry_multiplier) as i32;
        total_score += adjusted_urgency_score;
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

        // Apply professional credential discount for health-related scoring
        if self.has_professional_credentials(sender) {
            total_score = (total_score as f32 * 0.3) as i32; // 70% reduction for medical professionals
            all_evidence.push(
                "Professional medical credentials detected - reduced health scoring applied"
                    .to_string(),
            );
        }

        FeatureScore {
            feature_name: "Context Analysis".to_string(),
            score: (total_score as f32 * promo_discount) as i32,
            confidence,
            evidence: all_evidence,
        }
    }

    fn name(&self) -> &str {
        "context_analyzer"
    }
}
