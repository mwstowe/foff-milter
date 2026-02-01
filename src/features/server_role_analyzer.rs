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
        ];

        let suspicious_domain_patterns = vec![
            Regex::new(r"^[a-z0-9]{6,12}\.(com|net|org)$").unwrap(), // Random alphanumeric
            Regex::new(r"^[a-z]+\d+\.(shop|space|click)$").unwrap(), // Word + numbers + suspicious TLD
            Regex::new(r"^tc\d+\.shop$").unwrap(),                   // tc25.shop pattern
            Regex::new(r"^[a-z]+zens?\.(shop|space)$").unwrap(),     // arcticzens.shop pattern
        ];

        Self {
            suspicious_tlds,
            suspicious_domain_patterns,
        }
    }

    fn is_receiving_server(&self, context: &MailContext) -> bool {
        // Check if we're the final receiving server by looking at the Received headers
        // The receiving server is typically the last one in the chain that processes "for <recipient>"

        if let Some(received_headers) = context.headers.get("Received") {
            let received_lines: Vec<&str> = received_headers.lines().collect();

            // Look for our server name in the final Received header
            if let Some(first_received) = received_lines.first() {
                // If the first Received header contains "for <recipient>" and matches our processing,
                // we're likely the receiving server
                return first_received.contains("for <")
                    && (first_received.contains("juliett.") || first_received.contains("hotel."));
            }
        }

        // Fallback: assume we're receiving server if we can't determine otherwise
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
            // Fallback: try to extract domain from the header directly
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

    fn is_suspicious_domain(&self, domain: &str) -> bool {
        let domain_lower = domain.to_lowercase();

        // Skip legitimate business domains
        let legitimate_domains = [
            "docusign.com",
            "docusign.net",
            "adobe.com",
            "microsoft.com",
            "google.com",
            "amazon.com",
            "salesforce.com",
            "hubspot.com",
            "mailchimp.com",
            "constantcontact.com",
            "sendgrid.net",
            "medium.com",      // Medium publishing platform
            "kiwico.com",      // KiwiCo educational kits
            "empower.com",     // Empower financial services
            "builtsquare.com", // Built Square construction
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
            "hotmail.com", // Microsoft consumer email
            "yahoo.com",
            "technews.com",
            "ecoflow.com",
            "nytimes.com",
            "salesmanago.com",    // Marketing automation platform
            "kickstarter.com",    // Kickstarter crowdfunding platform
            "backstage.com",      // Backstage job board
            "pbteen.com",         // Pottery Barn Teen retail
            "mail.instagram.com", // Instagram social platform
            "woot.com",           // Woot marketplace (Amazon)
            "evgo.com",           // EVgo EV charging service
            "rejuvenation.com",   // Rejuvenation retail
            "tokyo-tiger.com",    // Tokyo Tiger retail
        ];

        for legitimate in &legitimate_domains {
            if domain_lower.contains(legitimate) {
                return false;
            }
        }

        // Check suspicious TLDs
        for tld in &self.suspicious_tlds {
            if domain_lower.ends_with(tld) {
                return true;
            }
        }

        // Check suspicious patterns
        for pattern in &self.suspicious_domain_patterns {
            if pattern.is_match(&domain_lower) {
                return true;
            }
        }

        false
    }

    fn should_reduce_auth_bonus(&self, context: &MailContext) -> (bool, String) {
        if let Some(domain) = self.extract_sender_domain(context) {
            if self.is_suspicious_domain(&domain) {
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
        let mut confidence = 0.0;

        // Determine if we're the receiving server
        let is_receiving = self.is_receiving_server(context);

        if is_receiving {
            evidence.push("Processing as receiving server".to_string());
        } else {
            evidence.push("Processing as intermediate server".to_string());
            // For intermediate servers, we should be more conservative with authentication bonuses
            score += 5; // Small penalty for intermediate processing
            confidence += 0.2;
        }

        // Check if we should reduce authentication bonuses for suspicious domains
        let (should_reduce, reason) = self.should_reduce_auth_bonus(context);
        if should_reduce {
            score += 25; // Penalty for suspicious domain with good auth
            evidence.push(format!(
                "Authentication bonus should be reduced: {}",
                reason
            ));
            confidence += 0.7;
        }

        // If we're not the receiving server, note that DKIM results might be different
        if !is_receiving {
            evidence.push("DKIM results may differ from receiving server".to_string());
        }

        FeatureScore {
            feature_name: "Server Role Analysis".to_string(),
            score,
            confidence,
            evidence,
        }
    }

    fn name(&self) -> &str {
        "server_role_analyzer"
    }
}
