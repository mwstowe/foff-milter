use super::DetectionResult;
use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct PhishingScamsConfig {
    pub financial_scams: FinancialScams,
    pub reward_scams: RewardScams,
    pub social_engineering: SocialEngineering,
    pub service_abuse: ServiceAbuse,
    pub authentication_spoofing: AuthenticationSpoofing,
    pub confidence_scoring: ConfidenceScoring,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct FinancialScams {
    pub cryptocurrency: Vec<String>,
    pub payment_fraud: Vec<String>,
    pub extortion: Vec<String>,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct RewardScams {
    pub emergency_kits: Vec<String>,
    pub prizes: Vec<String>,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct SocialEngineering {
    pub urgency: Vec<String>,
    pub panic: Vec<String>,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct ServiceAbuse {
    pub legitimate_services: Vec<String>,
    pub abuse_indicators: Vec<String>,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct AuthenticationSpoofing {
    pub indicators: Vec<String>,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct ConfidenceScoring {
    pub cryptocurrency_extortion: u32,
    pub payment_fraud: u32,
    pub reward_scams: u32,
    pub social_engineering: u32,
    pub service_abuse: u32,
    pub authentication_spoofing: u32,
}

pub struct PhishingScamsDetector {
    config: PhishingScamsConfig,
}

impl PhishingScamsDetector {
    pub fn new(config: PhishingScamsConfig) -> Self {
        Self { config }
    }

    pub fn load_from_file(path: &str) -> Result<Self, Box<dyn std::error::Error>> {
        let content = std::fs::read_to_string(path)?;
        let config: PhishingScamsConfig = serde_yml::from_str(&content)?;
        Ok(Self::new(config))
    }

    pub fn check_phishing_scam(&self, subject: &str, body: &str, sender: &str, from_header: &str) -> DetectionResult {
        let mut confidence = 0;
        let mut reasons = Vec::new();
        let combined_text = format!("{} {}", subject, body).to_lowercase();

        // Check cryptocurrency extortion
        if self.check_patterns(&combined_text, &self.config.financial_scams.cryptocurrency) &&
           self.check_patterns(&combined_text, &self.config.financial_scams.extortion) {
            confidence += self.config.confidence_scoring.cryptocurrency_extortion;
            reasons.push("Cryptocurrency extortion detected".to_string());
        }

        // Check payment fraud
        if self.check_patterns(&combined_text, &self.config.financial_scams.payment_fraud) {
            confidence += self.config.confidence_scoring.payment_fraud;
            reasons.push("Payment fraud patterns detected".to_string());
        }

        // Check reward scams
        if self.check_patterns(&combined_text, &self.config.reward_scams.emergency_kits) ||
           self.check_patterns(&combined_text, &self.config.reward_scams.prizes) {
            confidence += self.config.confidence_scoring.reward_scams;
            reasons.push("Reward scam patterns detected".to_string());
        }

        // Check social engineering
        if self.check_patterns(&combined_text, &self.config.social_engineering.urgency) ||
           self.check_patterns(&combined_text, &self.config.social_engineering.panic) {
            confidence += self.config.confidence_scoring.social_engineering;
            reasons.push("Social engineering patterns detected".to_string());
        }

        // Check service abuse
        if self.check_service_abuse(sender, from_header) {
            confidence += self.config.confidence_scoring.service_abuse;
            reasons.push("Service abuse detected".to_string());
        }

        // Check authentication spoofing
        if self.check_authentication_spoofing(sender, from_header) {
            confidence += self.config.confidence_scoring.authentication_spoofing;
            reasons.push("Authentication spoofing detected".to_string());
        }

        let matched = confidence > 0;
        let reason = if reasons.is_empty() {
            "No phishing/scam indicators".to_string()
        } else {
            reasons.join(", ")
        };

        DetectionResult::new(matched, confidence, reason, "PhishingScams".to_string())
    }

    fn check_patterns(&self, text: &str, patterns: &[String]) -> bool {
        patterns.iter().any(|pattern| text.contains(pattern))
    }

    fn check_service_abuse(&self, sender: &str, from_header: &str) -> bool {
        // Check if sender is from legitimate service
        let is_legitimate_service = self.config.service_abuse.legitimate_services
            .iter()
            .any(|service| sender.contains(service));

        if !is_legitimate_service {
            return false;
        }

        // Check for abuse indicators
        let from_lower = from_header.to_lowercase();
        self.config.service_abuse.abuse_indicators
            .iter()
            .any(|indicator| {
                match indicator.as_str() {
                    "reply.*mismatch" => {
                        // Simple check for different domains in sender vs from
                        let sender_domain = self.extract_domain(sender);
                        let from_domain = self.extract_domain(from_header);
                        sender_domain != from_domain
                    }
                    "free.*email.*reply" => {
                        from_lower.contains("gmail") || from_lower.contains("outlook") || 
                        from_lower.contains("yahoo") || from_lower.contains("hotmail")
                    }
                    "brand.*impersonation" => {
                        from_lower.contains("paypal") || from_lower.contains("amazon") ||
                        from_lower.contains("microsoft") || from_lower.contains("apple")
                    }
                    _ => from_lower.contains(indicator)
                }
            })
    }

    fn check_authentication_spoofing(&self, sender: &str, from_header: &str) -> bool {
        // Simple spoofing checks
        let sender_email = self.extract_email(sender);
        let from_email = self.extract_email(from_header);
        
        // Check if sender equals recipient (would need recipient info for full check)
        // For now, check if sender and from are different but similar
        sender_email != from_email && 
        (sender_email.contains(&from_email) || from_email.contains(&sender_email))
    }

    fn extract_domain(&self, email: &str) -> String {
        if let Some(at_pos) = email.rfind('@') {
            email[at_pos + 1..].trim_end_matches('>').to_string()
        } else {
            email.to_string()
        }
    }

    fn extract_email(&self, header: &str) -> String {
        // Extract email from header like "Name <email@domain.com>"
        if let Some(start) = header.rfind('<') {
            if let Some(end) = header.rfind('>') {
                return header[start + 1..end].to_string();
            }
        }
        header.to_string()
    }

    pub fn get_all_patterns(&self) -> Vec<String> {
        let mut patterns = Vec::new();
        patterns.extend(self.config.financial_scams.cryptocurrency.clone());
        patterns.extend(self.config.financial_scams.payment_fraud.clone());
        patterns.extend(self.config.financial_scams.extortion.clone());
        patterns.extend(self.config.reward_scams.emergency_kits.clone());
        patterns.extend(self.config.reward_scams.prizes.clone());
        patterns.extend(self.config.social_engineering.urgency.clone());
        patterns.extend(self.config.social_engineering.panic.clone());
        patterns.sort();
        patterns.dedup();
        patterns
    }
}
