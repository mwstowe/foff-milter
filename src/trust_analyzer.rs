use crate::filter::MailContext;

#[derive(Debug, Clone, Default)]
pub struct DomainTrustScore {
    pub authentication_score: i32,
    pub infrastructure_score: i32,
    pub behavioral_score: i32,
    pub content_score: i32,
    pub total_trust: i32,
}

pub struct TrustAnalyzer;

impl TrustAnalyzer {
    pub fn new() -> Self {
        Self
    }

    /// Analyze domain trust based on multiple signals
    pub fn analyze_domain_trust(&self, context: &MailContext) -> DomainTrustScore {
        let mut score = DomainTrustScore::default();

        // Phase 2A: Authentication Infrastructure Analysis
        score.authentication_score = self.analyze_authentication_infrastructure(context);

        // Phase 2B: Infrastructure Quality (basic implementation)
        score.infrastructure_score = self.analyze_infrastructure_quality(context);

        // Phase 2C: Behavioral Patterns (basic implementation)
        score.behavioral_score = self.analyze_behavioral_patterns(context);

        // Phase 2D: Content Professionalism (basic implementation)
        score.content_score = self.analyze_content_professionalism(context);

        // Calculate weighted total trust score
        score.total_trust = self.calculate_total_trust(&score);

        score
    }

    /// Analyze authentication infrastructure quality
    fn analyze_authentication_infrastructure(&self, context: &MailContext) -> i32 {
        let mut auth_score = 0;

        // Collect all authentication-related headers and their values
        let mut auth_content = String::new();

        for (key, value) in &context.headers {
            let key_lower = key.to_lowercase();
            if key_lower.contains("authentication-results")
                || key_lower.contains("arc-authentication-results")
            {
                auth_content.push_str(&format!("{} ", value.to_lowercase()));
            }
        }

        if auth_content.is_empty() {
            // No authentication results header is suspicious
            return -30;
        }

        // DMARC analysis
        if auth_content.contains("dmarc=pass") {
            auth_score += 40;

            // Check for strict DMARC policy indicators
            if auth_content.contains("policy.reject") || auth_content.contains("p=reject") {
                auth_score += 20; // Strict DMARC policy
            } else if auth_content.contains("policy.quarantine")
                || auth_content.contains("p=quarantine")
            {
                auth_score += 10; // Moderate DMARC policy
            }
        } else if auth_content.contains("dmarc=fail") {
            auth_score -= 20;
        }

        // SPF analysis
        if auth_content.contains("spf=pass") {
            auth_score += 25;
        } else if auth_content.contains("spf=fail") {
            auth_score -= 15;
        } else if auth_content.contains("spf=softfail") {
            auth_score -= 5;
        }

        // DKIM analysis using unified verification
        let dkim = context.dkim_verification_readonly();
        match dkim.auth_status {
            crate::dkim_verification::DkimAuthStatus::Pass => {
                auth_score += 20;

                // Multiple DKIM signatures indicate better infrastructure
                if dkim.signature_count > 1 {
                    auth_score += 10;
                }
            }
            crate::dkim_verification::DkimAuthStatus::Fail(_) => {
                auth_score -= 10;
            }
            _ => {} // No change for None, TempError, PermError
        }

        // ARC (Authenticated Received Chain) support
        if auth_content.contains("arc=pass") {
            auth_score += 15;
        }

        // Check for additional authentication headers using unified DKIM verification
        if dkim.has_signature {
            auth_score += 10;
        }

        if context
            .headers
            .keys()
            .any(|k| k.to_lowercase().contains("arc-authentication-results"))
        {
            auth_score += 5;
        }

        // Cap the authentication score
        auth_score.clamp(-50, 100)
    }

    /// Analyze infrastructure quality indicators
    fn analyze_infrastructure_quality(&self, context: &MailContext) -> i32 {
        let mut infra_score = 0;

        // Check for proper Message-ID format
        if let Some(message_id) = context.headers.get("Message-ID") {
            if message_id.contains('@') && message_id.starts_with('<') && message_id.ends_with('>')
            {
                infra_score += 10;
            }
        }

        // Check for proper Received headers structure
        let received_count = context
            .headers
            .iter()
            .filter(|(k, _)| k.to_lowercase() == "received")
            .count();

        if received_count > 0 && received_count <= 5 {
            infra_score += 10; // Reasonable hop count
        } else if received_count > 5 {
            infra_score -= 5; // Too many hops might indicate forwarding
        }

        // Check for professional email headers
        if context.headers.contains_key("List-Unsubscribe") {
            infra_score += 15;
        }

        if context.headers.contains_key("List-ID") {
            infra_score += 10;
        }

        if context.headers.contains_key("Precedence") {
            infra_score += 5;
        }

        // Check for proper Date header format
        if context.headers.contains_key("Date") {
            infra_score += 5;
        }

        infra_score.clamp(-30, 50)
    }

    /// Analyze behavioral patterns
    fn analyze_behavioral_patterns(&self, context: &MailContext) -> i32 {
        let mut behavior_score = 0;

        // Check for consistent From/Sender alignment
        if let (Some(from_header), Some(sender)) = (&context.from_header, &context.sender) {
            if let Some(from_domain) = self.extract_domain_from_email(from_header) {
                if let Some(sender_domain) = self.extract_domain_from_email(sender) {
                    if from_domain == sender_domain {
                        behavior_score += 15; // Consistent domain alignment
                    } else {
                        behavior_score -= 10; // Domain mismatch
                    }
                }
            }
        }

        // Check for proper Reply-To handling
        if let Some(reply_to) = context.headers.get("Reply-To") {
            if let Some(from_header) = &context.from_header {
                if reply_to.to_lowercase() == from_header.to_lowercase() {
                    behavior_score += 10; // Consistent reply-to
                }
            }
        }

        // Check for professional subject line patterns
        if let Some(subject) = &context.subject {
            let subject_lower = subject.to_lowercase();

            // Professional indicators
            if subject_lower.contains("newsletter")
                || subject_lower.contains("update")
                || subject_lower.contains("notification")
                || subject_lower.contains("statement")
            {
                behavior_score += 10;
            }

            // Spam indicators
            if subject_lower.contains("!!!")
                || subject_lower.contains("urgent")
                || subject_lower.contains("act now")
            {
                behavior_score -= 15;
            }
        }

        behavior_score.clamp(-30, 30)
    }

    /// Analyze content professionalism
    fn analyze_content_professionalism(&self, context: &MailContext) -> i32 {
        let mut content_score = 0;

        if let Some(body) = &context.body {
            let body_lower = body.to_lowercase();

            // Professional contact information
            if body_lower.contains("unsubscribe") {
                content_score += 10;
            }

            // Physical address indicators (basic pattern)
            if body.chars().filter(|c| c.is_ascii_digit()).count() > 5
                && (body_lower.contains("street")
                    || body_lower.contains("ave")
                    || body_lower.contains("road")
                    || body_lower.contains("suite"))
            {
                content_score += 15;
            }

            // Professional language patterns
            if body_lower.contains("sincerely")
                || body_lower.contains("regards")
                || body_lower.contains("best wishes")
            {
                content_score += 5;
            }

            // Spam language patterns
            if body_lower.contains("click here")
                || body_lower.contains("act now")
                || body_lower.contains("limited time")
            {
                content_score -= 10;
            }

            // Excessive capitalization
            let caps_ratio = body.chars().filter(|c| c.is_uppercase()).count() as f32
                / body.chars().filter(|c| c.is_alphabetic()).count().max(1) as f32;

            if caps_ratio > 0.3 {
                content_score -= 15;
            } else if caps_ratio < 0.1 {
                content_score += 5;
            }
        }

        content_score.clamp(-20, 20)
    }

    /// Calculate weighted total trust score
    fn calculate_total_trust(&self, score: &DomainTrustScore) -> i32 {
        // Weighted combination: authentication is most important
        let total = (score.authentication_score as f32 * 0.5)
            + (score.infrastructure_score as f32 * 0.25)
            + (score.behavioral_score as f32 * 0.15)
            + (score.content_score as f32 * 0.1);

        total.round() as i32
    }

    /// Extract domain from email address
    fn extract_domain_from_email(&self, email: &str) -> Option<String> {
        if let Some(at_pos) = email.rfind('@') {
            let domain = &email[at_pos + 1..];
            // Clean up domain (remove brackets, etc.)
            let clean_domain = domain.trim_matches(|c| c == '>' || c == '<' || c == ' ');
            if !clean_domain.is_empty() {
                return Some(clean_domain.to_lowercase());
            }
        }
        None
    }

    /// Get trust-based scoring adjustment
    pub fn get_trust_adjustment(&self, trust_score: i32) -> i32 {
        match trust_score {
            90.. => -40,    // Very high trust (stricter threshold)
            60..=89 => -20, // High trust (reduced adjustment)
            30..=59 => -10, // Medium trust (minimal adjustment)
            0..=29 => 0,    // Low trust (no adjustment)
            -30..=-1 => 15, // Suspicious (reduced penalty)
            _ => 30,        // Untrusted (reduced penalty)
        }
    }
}

impl Default for TrustAnalyzer {
    fn default() -> Self {
        Self::new()
    }
}
