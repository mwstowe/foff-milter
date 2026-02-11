use super::{FeatureExtractor, FeatureScore};
use crate::MailContext;

pub struct ConsumerEmailEspAnalyzer;

impl Default for ConsumerEmailEspAnalyzer {
    fn default() -> Self {
        Self::new()
    }
}

impl ConsumerEmailEspAnalyzer {
    pub fn new() -> Self {
        Self
    }
}

impl FeatureExtractor for ConsumerEmailEspAnalyzer {
    fn extract(&self, context: &MailContext) -> FeatureScore {
        let mut score = 0;
        let mut evidence = Vec::new();

        // Get From header domain
        let from_domain = context
            .from_header
            .as_deref()
            .and_then(|from| from.split('@').nth(1))
            .map(|d| d.trim_end_matches('>'))
            .unwrap_or("")
            .to_lowercase();

        // Consumer email services (not ESPs)
        let consumer_email_services = [
            "outlook.com",
            "hotmail.com",
            "live.com",
            "gmail.com",
            "yahoo.com",
            "aol.com",
            "icloud.com",
            "me.com",
            "mac.com",
            "protonmail.com",
            "proton.me",
        ];

        let is_consumer_email = consumer_email_services
            .iter()
            .any(|&service| from_domain.ends_with(service));

        if !is_consumer_email {
            return FeatureScore {
                feature_name: self.name().to_string(),
                score: 0,
                confidence: 0.0,
                evidence: Vec::new(),
            };
        }

        // Check if sent through an ESP
        let envelope_domain = context
            .sender
            .as_deref()
            .and_then(|sender| sender.split('@').nth(1))
            .unwrap_or("")
            .to_lowercase();

        let esp_domains = [
            "sendgrid.net",
            "mailgun.org",
            "amazonses.com",
            "mailchimp.com",
            "mcdlv.net",
            "klaviyomail.com",
            "exacttarget.com",
            "salesforce.com",
            "constantcontact.com",
            "awsmail.com",
        ];

        let sent_through_esp = esp_domains
            .iter()
            .any(|&esp| envelope_domain.contains(esp));

        if sent_through_esp {
            // Consumer email domain sent through ESP is highly suspicious
            score += 200;
            evidence.push(format!(
                "Consumer email domain ({}) sent through ESP ({}) - likely spoofed",
                from_domain, envelope_domain
            ));
        }

        FeatureScore {
            feature_name: self.name().to_string(),
            score,
            confidence: if score > 0 { 0.95 } else { 0.0 },
            evidence,
        }
    }

    fn name(&self) -> &str {
        "Consumer Email ESP"
    }
}
