use crate::filter::MailContext;
use regex::Regex;

#[derive(Debug, Clone, Default)]
pub struct BusinessContextScore {
    pub professional_communication: i32,
    pub business_legitimacy: i32,
    pub industry_recognition: i32,
    pub compliance_indicators: i32,
    pub total_business_score: i32,
}

pub struct BusinessContextAnalyzer {
    // Compiled regex patterns for performance
    email_signature_pattern: Regex,
    phone_pattern: Regex,
    address_pattern: Regex,
    business_terms_pattern: Regex,
    professional_closing_pattern: Regex,
}

impl BusinessContextAnalyzer {
    pub fn new() -> Self {
        Self {
            email_signature_pattern: Regex::new(r"(?i)(best\s+regards|sincerely|kind\s+regards|thank\s+you|yours\s+truly)").unwrap(),
            phone_pattern: Regex::new(r"(\+?1[-.\s]?)?\(?[0-9]{3}\)?[-.\s]?[0-9]{3}[-.\s]?[0-9]{4}").unwrap(),
            address_pattern: Regex::new(r"(?i)\d+\s+\w+\s+(street|st|avenue|ave|road|rd|boulevard|blvd|drive|dr|lane|ln|court|ct|place|pl|suite|ste|floor|fl)\b").unwrap(),
            business_terms_pattern: Regex::new(r"(?i)\b(inc|llc|corp|corporation|company|ltd|limited|enterprises|solutions|services|group|associates|partners)\b").unwrap(),
            professional_closing_pattern: Regex::new(r"(?i)(customer\s+service|support\s+team|sales\s+team|marketing\s+team|account\s+manager|representative)").unwrap(),
        }
    }

    /// Analyze business context and professional communication patterns
    pub fn analyze_business_context(&self, context: &MailContext) -> BusinessContextScore {
        let mut score = BusinessContextScore::default();

        score.professional_communication = self.analyze_professional_communication(context);
        score.business_legitimacy = self.analyze_business_legitimacy(context);
        score.industry_recognition = self.analyze_industry_recognition(context);
        score.compliance_indicators = self.analyze_compliance_indicators(context);

        // Calculate weighted total
        score.total_business_score = self.calculate_total_business_score(&score);

        score
    }

    /// Analyze professional communication patterns
    fn analyze_professional_communication(&self, context: &MailContext) -> i32 {
        let mut comm_score = 0;

        if let Some(body) = &context.body {
            // Professional email signature patterns
            if self.email_signature_pattern.is_match(body) {
                comm_score += 15;
            }

            // Professional contact information
            if self.phone_pattern.is_match(body) {
                comm_score += 10;
            }

            if self.address_pattern.is_match(body) {
                comm_score += 15;
            }

            // Business entity indicators
            if self.business_terms_pattern.is_match(body) {
                comm_score += 10;
            }

            // Professional team/role indicators
            if self.professional_closing_pattern.is_match(body) {
                comm_score += 10;
            }

            // Professional formatting indicators
            if body.contains("--") || body.contains("___") {
                comm_score += 5; // Signature separator
            }

            // Email footer patterns (privacy policy, terms of service)
            if body.to_lowercase().contains("privacy policy")
                || body.to_lowercase().contains("terms of service")
            {
                comm_score += 10;
            }

            // Professional disclaimers
            if body.to_lowercase().contains("confidential")
                || body.to_lowercase().contains("disclaimer")
            {
                comm_score += 5;
            }
        }

        // Subject line professionalism
        if let Some(subject) = &context.subject {
            let subject_lower = subject.to_lowercase();

            // Professional subject patterns
            if subject_lower.contains("newsletter")
                || subject_lower.contains("update")
                || subject_lower.contains("notification")
                || subject_lower.contains("statement")
                || subject_lower.contains("invoice")
                || subject_lower.contains("receipt")
            {
                comm_score += 10;
            }

            // Avoid excessive punctuation
            let exclamation_count = subject.matches('!').count();
            if exclamation_count == 0 {
                comm_score += 5;
            } else if exclamation_count > 2 {
                comm_score -= 10;
            }
        }

        comm_score.clamp(0, 60)
    }

    /// Analyze business legitimacy indicators
    fn analyze_business_legitimacy(&self, context: &MailContext) -> i32 {
        let mut legit_score = 0;

        // Domain-based legitimacy indicators
        if let Some(sender) = &context.sender {
            if let Some(domain) = self.extract_domain_from_email(sender) {
                // Well-known business domains
                if self.is_established_business_domain(&domain) {
                    legit_score += 25;
                }

                // Professional domain patterns (not free email)
                if !self.is_free_email_domain(&domain) {
                    legit_score += 15;
                }

                // Domain length and structure (professional domains are usually reasonable length)
                if domain.len() > 5 && domain.len() < 30 && domain.contains('.') {
                    legit_score += 5;
                }
            }
        }

        // From header consistency
        if let (Some(from_header), Some(sender)) = (&context.from_header, &context.sender) {
            if let (Some(from_domain), Some(sender_domain)) = (
                self.extract_domain_from_email(from_header),
                self.extract_domain_from_email(sender),
            ) {
                if from_domain == sender_domain {
                    legit_score += 10; // Consistent domain alignment
                }
            }
        }

        // Professional email infrastructure
        if context.headers.contains_key("List-Unsubscribe") {
            legit_score += 15;
        }

        if context.headers.contains_key("List-ID") {
            legit_score += 10;
        }

        // Message-ID professionalism
        if let Some(message_id) = context.headers.get("Message-ID") {
            if message_id.contains('@') && message_id.starts_with('<') && message_id.ends_with('>')
            {
                legit_score += 5;
            }
        }

        legit_score.clamp(0, 50)
    }

    /// Analyze industry-specific recognition patterns
    fn analyze_industry_recognition(&self, context: &MailContext) -> i32 {
        let mut industry_score = 0;

        if let Some(body) = &context.body {
            let body_lower = body.to_lowercase();

            // Financial services indicators
            if body_lower.contains("account")
                || body_lower.contains("statement")
                || body_lower.contains("balance")
                || body_lower.contains("transaction")
            {
                industry_score += 10;
            }

            // E-commerce indicators
            if body_lower.contains("order")
                || body_lower.contains("shipping")
                || body_lower.contains("delivery")
                || body_lower.contains("tracking")
            {
                industry_score += 10;
            }

            // Healthcare indicators
            if body_lower.contains("appointment")
                || body_lower.contains("prescription")
                || body_lower.contains("medical")
                || body_lower.contains("health")
            {
                industry_score += 10;
            }

            // Education indicators
            if body_lower.contains("course")
                || body_lower.contains("enrollment")
                || body_lower.contains("tuition")
                || body_lower.contains("academic")
            {
                industry_score += 10;
            }

            // Professional services indicators
            if body_lower.contains("consultation")
                || body_lower.contains("proposal")
                || body_lower.contains("contract")
                || body_lower.contains("agreement")
            {
                industry_score += 10;
            }
        }

        // Sender domain industry recognition
        if let Some(sender) = &context.sender {
            if let Some(domain) = self.extract_domain_from_email(sender) {
                if self.is_known_industry_domain(&domain) {
                    industry_score += 15;
                }
            }
        }

        industry_score.clamp(0, 40)
    }

    /// Analyze compliance and regulatory indicators
    fn analyze_compliance_indicators(&self, context: &MailContext) -> i32 {
        let mut compliance_score = 0;

        // CAN-SPAM compliance indicators
        if context.headers.contains_key("List-Unsubscribe") {
            compliance_score += 15;
        }

        if let Some(body) = &context.body {
            let body_lower = body.to_lowercase();

            // Unsubscribe mechanism
            if body_lower.contains("unsubscribe") || body_lower.contains("opt out") {
                compliance_score += 10;
            }

            // Physical address (CAN-SPAM requirement)
            if self.address_pattern.is_match(body) {
                compliance_score += 15;
            }

            // Privacy policy reference
            if body_lower.contains("privacy policy") {
                compliance_score += 10;
            }

            // Terms of service reference
            if body_lower.contains("terms of service")
                || body_lower.contains("terms and conditions")
            {
                compliance_score += 5;
            }

            // GDPR compliance indicators
            if body_lower.contains("gdpr") || body_lower.contains("data protection") {
                compliance_score += 5;
            }
        }

        compliance_score.clamp(0, 35)
    }

    /// Calculate weighted total business score
    fn calculate_total_business_score(&self, score: &BusinessContextScore) -> i32 {
        // Weighted combination emphasizing professional communication and legitimacy
        let total = (score.professional_communication as f32 * 0.35)
            + (score.business_legitimacy as f32 * 0.30)
            + (score.industry_recognition as f32 * 0.20)
            + (score.compliance_indicators as f32 * 0.15);

        total.round() as i32
    }

    /// Get business context adjustment for spam scoring
    pub fn get_business_adjustment(&self, business_score: i32) -> i32 {
        match business_score {
            60.. => -25,    // Very professional business (stricter threshold)
            45..=59 => -15, // Professional business (reduced adjustment)
            30..=44 => -8,  // Some business indicators (minimal adjustment)
            20..=29 => -3,  // Minimal business indicators (very small adjustment)
            _ => 0,         // No business context
        }
    }

    /// Extract domain from email address
    fn extract_domain_from_email(&self, email: &str) -> Option<String> {
        if let Some(at_pos) = email.rfind('@') {
            let domain = &email[at_pos + 1..];
            let clean_domain = domain.trim_matches(|c| c == '>' || c == '<' || c == ' ');
            if !clean_domain.is_empty() {
                return Some(clean_domain.to_lowercase());
            }
        }
        None
    }

    /// Check if domain is an established business domain
    fn is_established_business_domain(&self, domain: &str) -> bool {
        let established_domains = [
            "amazon.com",
            "walmart.com",
            "target.com",
            "bestbuy.com",
            "homedepot.com",
            "apple.com",
            "microsoft.com",
            "google.com",
            "adobe.com",
            "salesforce.com",
            "chase.com",
            "bankofamerica.com",
            "wellsfargo.com",
            "paypal.com",
            "fedex.com",
            "ups.com",
            "usps.com",
            "dhl.com",
            "netflix.com",
            "spotify.com",
            "hulu.com",
            "disney.com",
        ];

        established_domains
            .iter()
            .any(|&est_domain| domain.contains(est_domain))
    }

    /// Check if domain is a free email provider
    fn is_free_email_domain(&self, domain: &str) -> bool {
        let free_domains = [
            "gmail.com",
            "yahoo.com",
            "hotmail.com",
            "outlook.com",
            "aol.com",
            "icloud.com",
            "protonmail.com",
            "mail.com",
            "yandex.com",
        ];

        free_domains
            .iter()
            .any(|&free_domain| domain.contains(free_domain))
    }

    /// Check if domain belongs to a known industry
    fn is_known_industry_domain(&self, domain: &str) -> bool {
        let industry_patterns = [
            "bank",
            "credit",
            "financial",
            "insurance",
            "invest",
            "health",
            "medical",
            "hospital",
            "clinic",
            "pharma",
            "edu",
            "university",
            "college",
            "school",
            "academy",
            "shop",
            "store",
            "retail",
            "commerce",
            "market",
        ];

        industry_patterns
            .iter()
            .any(|&pattern| domain.contains(pattern))
    }
}

impl Default for BusinessContextAnalyzer {
    fn default() -> Self {
        Self::new()
    }
}
