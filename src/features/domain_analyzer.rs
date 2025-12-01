use super::{FeatureExtractor, FeatureScore};
use crate::MailContext;
use regex::Regex;

pub struct DomainAnalyzer {
    suspicious_patterns: Vec<Regex>,
    parking_patterns: Vec<Regex>,
    suspicious_tlds: Vec<&'static str>,
}

impl Default for DomainAnalyzer {
    fn default() -> Self {
        Self::new()
    }
}

impl DomainAnalyzer {
    pub fn new() -> Self {
        let suspicious_patterns = vec![
            Regex::new(r"(?i)[0-9]{3,}").unwrap(), // Excessive numbers
            Regex::new(r"(?i)[a-z]{2,}[0-9]+[a-z]{2,}").unwrap(), // Mixed alphanumeric
            Regex::new(r"(?i)(park|temp|test|demo|sample)").unwrap(), // Parking/temp domains
            Regex::new(r"(?i)[a-z]{15,}").unwrap(), // Excessively long random strings
        ];

        let parking_patterns = vec![
            Regex::new(r"(?i)(park.*for|gacor|temp.*site|placeholder)").unwrap(),
            Regex::new(r"(?i)(domain.*sale|buy.*domain|expired)").unwrap(),
        ];

        let suspicious_tlds = vec![
            "tk", "ml", "ga", "cf", "pw", "top", "click", "download", 
            "stream", "science", "racing", "review", "faith", "accountant"
        ];

        Self {
            suspicious_patterns,
            parking_patterns,
            suspicious_tlds,
        }
    }

    fn extract_domain(&self, email: &str) -> Option<String> {
        if let Some(at_pos) = email.rfind('@') {
            let domain_part = &email[at_pos + 1..];
            // Remove angle brackets if present
            let clean_domain = domain_part.trim_end_matches('>').trim_start_matches('<');
            Some(clean_domain.to_lowercase())
        } else {
            None
        }
    }

    fn analyze_domain_reputation(&self, domain: &str) -> (i32, Vec<String>) {
        let mut score = 0;
        let mut evidence = Vec::new();

        // Check for legitimate marketing subdomains first
        let legitimate_patterns = [
            r"marketing\..*\.(com|net|org)$",
            r"mail\..*\.(com|net|org)$", 
            r"email\..*\.(com|net|org)$",
            r"news\..*\.(com|net|org)$",
            r"newsletter\..*\.(com|net|org)$",
            r"updates\..*\.(com|net|org)$",
        ];
        
        for pattern in &legitimate_patterns {
            if Regex::new(pattern).unwrap().is_match(domain) {
                // Extract base domain to check if it's a known brand
                let parts: Vec<&str> = domain.split('.').collect();
                if parts.len() >= 3 {
                    let base_domain = format!("{}.{}", parts[parts.len()-2], parts[parts.len()-1]);
                    if self.is_known_brand(&base_domain) {
                        score -= 20; // Reduce suspicion for legitimate marketing subdomains
                        evidence.push(format!("Legitimate marketing subdomain detected: {}", domain));
                        return (score, evidence);
                    }
                }
            }
        }

        // Check for suspicious patterns
        for pattern in &self.suspicious_patterns {
            if pattern.is_match(domain) {
                score += 15;
                evidence.push(format!("Suspicious domain pattern detected: {}", domain));
                break;
            }
        }

        // Check for parking domain patterns
        for pattern in &self.parking_patterns {
            if pattern.is_match(domain) {
                score += 30;
                evidence.push(format!("Parking/temporary domain detected: {}", domain));
                break;
            }
        }

        // Check TLD reputation
        if let Some(tld) = domain.split('.').last() {
            if self.suspicious_tlds.contains(&tld) {
                score += 20;
                evidence.push(format!("Suspicious TLD detected: .{}", tld));
            }
        }

        // Check domain length and structure
        let parts: Vec<&str> = domain.split('.').collect();
        if parts.len() > 4 {
            score += 10;
            evidence.push("Excessive subdomain levels detected".to_string());
        }

        if let Some(main_part) = parts.first() {
            if main_part.len() > 20 {
                score += 15;
                evidence.push("Excessively long domain name detected".to_string());
            }
        }

        (score, evidence)
    }

    fn is_known_brand(&self, domain: &str) -> bool {
        let known_brands = [
            "lyft.com", "uber.com", "delta.com", "united.com", "american.com",
            "southwest.com", "jetblue.com", "alaska.com", "spirit.com",
            "medium.com", "substack.com", "mailchimp.com", "constantcontact.com",
            "sendgrid.com", "mailgun.com", "sparkpost.com", "mandrill.com",
            "poshmark.com", "ebay.com", "etsy.com", "mercari.com",
            "usps.com", "fedex.com", "ups.com", "dhl.com",
        ];
        
        known_brands.contains(&domain)
    }
}

impl FeatureExtractor for DomainAnalyzer {
    fn name(&self) -> &str {
        "Domain Reputation"
    }

    fn extract(&self, context: &MailContext) -> FeatureScore {
        let mut total_score = 0;
        let mut all_evidence = Vec::new();

        let sender = context.from_header.as_deref().unwrap_or("");

        if let Some(domain) = self.extract_domain(sender) {
            let (score, evidence) = self.analyze_domain_reputation(&domain);
            total_score += score;
            all_evidence.extend(evidence);
        }

        FeatureScore {
            score: total_score,
            confidence: if total_score > 0 { 85.0 } else { 0.0 },
            evidence: all_evidence,
            feature_name: "Domain Reputation".to_string(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_suspicious_domain_detection() {
        let analyzer = DomainAnalyzer::new();
        
        // Test parking domain
        let (score, evidence) = analyzer.analyze_domain_reputation("parkit4gacor.com");
        assert!(score > 0);
        assert!(!evidence.is_empty());
        
        // Test legitimate domain
        let (score, _) = analyzer.analyze_domain_reputation("google.com");
        assert_eq!(score, 0);
    }

    #[test]
    fn test_domain_extraction() {
        let analyzer = DomainAnalyzer::new();
        
        assert_eq!(
            analyzer.extract_domain("test@example.com"),
            Some("example.com".to_string())
        );
        assert_eq!(
            analyzer.extract_domain("user@sub.domain.com"),
            Some("sub.domain.com".to_string())
        );
    }
}
