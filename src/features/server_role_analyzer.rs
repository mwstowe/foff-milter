use crate::domain_registry::DomainRegistry;
use crate::features::{FeatureExtractor, FeatureScore};
use crate::MailContext;
use regex::Regex;

pub struct ServerRoleAnalyzer {
    suspicious_tlds: Vec<String>,
    suspicious_domain_patterns: Vec<Regex>,
}

impl Default for ServerRoleAnalyzer {
    fn default() -> Self {
        Self::new()
    }
}

impl ServerRoleAnalyzer {
    pub fn new() -> Self {
        let suspicious_tlds = vec![
            ".shop".to_string(),
            ".tk".to_string(),
            ".ml".to_string(),
            ".ga".to_string(),
            ".cf".to_string(),
            ".click".to_string(),
            ".link".to_string(),
            ".space".to_string(),
            ".name".to_string(),
            ".sbs".to_string(),
        ];

        let suspicious_domain_patterns = vec![
            Regex::new(r"^[a-z0-9]{6,10}\.(com|net|org|name)$").unwrap(), // Random alphanumeric
            Regex::new(r"^[a-z]+\d+\.(shop|space|click)$").unwrap(), // Word + numbers + suspicious TLD
            Regex::new(r"^tc\d+\.shop$").unwrap(),                   // tc25.shop pattern
            Regex::new(r"^[a-z]+zens?\.(shop|space)$").unwrap(),     // arcticzens.shop pattern
            Regex::new(r"^[a-z0-9-]+\.firebaseapp\.com$").unwrap(),  // Firebase hosting phishing
        ];

        Self {
            suspicious_tlds,
            suspicious_domain_patterns,
        }
    }

    fn is_receiving_server(&self, context: &MailContext) -> bool {
        if let Some(received_headers) = context.headers.get("Received") {
            let received_lines: Vec<&str> = received_headers.lines().collect();
            if let Some(first_received) = received_lines.first() {
                return first_received.contains("for <")
                    && (first_received.contains("juliett.") || first_received.contains("hotel."));
            }
        }
        true
    }

    fn extract_sender_domain(&self, context: &MailContext) -> Option<String> {
        if let Some(from_header) = &context.from_header {
            if let Some(email_start) = from_header.find('<') {
                if let Some(email_end) = from_header.rfind('>') {
                    if email_start + 1 < email_end {
                        let email = &from_header[email_start + 1..email_end];
                        return email.split('@').nth(1).map(|s| s.to_lowercase());
                    }
                }
            }
            if let Some(at_pos) = from_header.rfind('@') {
                let after_at = &from_header[at_pos + 1..];
                if let Some(space_pos) = after_at.find(' ') {
                    return Some(after_at[..space_pos].to_lowercase());
                } else {
                    return Some(after_at.trim_end_matches('>').to_lowercase());
                }
            }
        }
        None
    }

    fn is_suspicious_domain(&self, domain: &str, registry: Option<&DomainRegistry>) -> bool {
        let domain_lower = domain.to_lowercase();

        // Skip legitimate business domains
        if let Some(reg) = registry {
            if reg.is_legitimate(&domain_lower) {
                return false;
            }
        } else {
            let legitimate_domains = [
                "docusign.com",
                "docusign.net",
                "adobe.com",
                "microsoft.com",
                "google.com",
                "amazon.com",
                "amazonmusic.com",
                "salesforce.com",
                "hubspot.com",
                "mailchimp.com",
                "constantcontact.com",
                "sendgrid.net",
                "medium.com",
                "kiwico.com",
                "empower.com",
                "builtsquare.com",
                "sendgrid.info",
                "bcdtravel.com",
                "concurcompleat.com",
                "concur.com",
                "expensify.com",
                "netsuite.com",
                "oracle.com",
                "backerhome.com",
                "gmail.com",
                "outlook.com",
                "hotmail.com",
                "yahoo.com",
                "technews.com",
                "ecoflow.com",
                "nytimes.com",
                "salesmanago.com",
                "kickstarter.com",
                "backstage.com",
                "pbteen.com",
                "mail.instagram.com",
                "woot.com",
                "evgo.com",
                "rejuvenation.com",
                "tokyo-tiger.com",
                "waltdisneypictures.com",
                "doordash.com",
                "daburns.com",
                "blinkcharging.com",
                "oxfordclub.com",
                "disneyplus.com",
                "sparkpostmail.com",
                "suncadia.com",
                "americanmeadows.com",
                "portlandnursery.com",
                "ccsend.com",
                "consumerreports.org",
                "iheart.com",
                "hubitat.com",
                "mozilla.org",
            ];
            for legitimate in &legitimate_domains {
                if domain_lower.contains(legitimate) {
                    return false;
                }
            }
        }

        // Check suspicious TLDs
        if let Some(reg) = registry {
            if reg.has_suspicious_tld(&domain_lower) {
                return true;
            }
        } else {
            for tld in &self.suspicious_tlds {
                if domain_lower.ends_with(tld) {
                    return true;
                }
            }
        }

        // Check suspicious patterns
        for pattern in &self.suspicious_domain_patterns {
            if pattern.is_match(&domain_lower) {
                return true;
            }
        }

        // Check for spam-keyword compound domains (e.g., seniorshoppingtips.com)
        let name = domain_lower.split('.').next().unwrap_or("");
        if name.len() >= 14 {
            let spam_keywords = [
                "tips", "deals", "offer", "discount", "bargain", "cheap", "promo", "shopping",
                "senior", "savings", "bonus", "reward", "winner", "prize",
            ];
            let keyword_count = spam_keywords.iter().filter(|kw| name.contains(*kw)).count();
            if keyword_count >= 2 {
                return true;
            }
        }

        false
    }

    fn should_reduce_auth_bonus(&self, context: &MailContext) -> (bool, String) {
        let has_dkim = context
            .headers
            .get("authentication-results")
            .map(|v| v.contains("dkim=pass"))
            .unwrap_or(false);
        if has_dkim && crate::features::esp_validation::is_from_trusted_esp(context) {
            return (false, String::new());
        }
        if let Some(domain) = self.extract_sender_domain(context) {
            let registry = context.domain_registry.as_ref().map(|arc| arc.as_ref());
            if self.is_suspicious_domain(&domain, registry) {
                return (true, format!("Suspicious domain: {}", domain));
            }
        }
        (false, String::new())
    }
}

impl FeatureExtractor for ServerRoleAnalyzer {
    fn extract(&self, context: &MailContext) -> FeatureScore {
        let mut score = 0;
        let mut evidence = Vec::new();
        let mut tags: Vec<crate::features::FeatureTag> = Vec::new();
        let mut confidence = 0.0;

        let is_receiving = self.is_receiving_server(context);

        if is_receiving {
            evidence.push("Processing as receiving server".to_string());
        } else {
            evidence.push("Processing as intermediate server".to_string());
            score += 5;
            confidence += 0.2;
        }

        let (should_reduce, reason) = self.should_reduce_auth_bonus(context);
        if should_reduce {
            score += 25;
            evidence.push(format!(
                "Authentication bonus should be reduced: {}",
                reason
            ));
            tags.push(crate::features::FeatureTag::SuspiciousDomain);
            confidence += 0.7;
        }

        if !is_receiving {
            evidence.push("DKIM results may differ from receiving server".to_string());
        }

        FeatureScore {
            feature_name: "Server Role Analysis".to_string(),
            score,
            confidence,
            evidence,
            tags,
        }
    }

    fn name(&self) -> &str {
        "server_role_analyzer"
    }
}
