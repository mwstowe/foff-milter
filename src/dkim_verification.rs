use std::collections::HashMap;

#[derive(Debug, Clone, PartialEq)]
pub enum DkimAuthStatus {
    Pass,
    Fail(String),
    None,
    TempError,
    PermError,
}

#[derive(Debug, Clone)]
pub enum DomainAlignment {
    Aligned,
    Misaligned { dkim_domain: String, sender_domain: String },
    Unknown,
}

#[derive(Debug, Clone)]
pub struct DkimVerificationResult {
    pub has_signature: bool,
    pub signature_count: usize,
    pub domains: Vec<String>,
    pub auth_status: DkimAuthStatus,
    pub signature_valid: bool,
    pub domain_alignment: DomainAlignment,
    pub raw_signatures: Vec<String>,
}

impl Default for DkimVerificationResult {
    fn default() -> Self {
        Self {
            has_signature: false,
            signature_count: 0,
            domains: Vec::new(),
            auth_status: DkimAuthStatus::None,
            signature_valid: false,
            domain_alignment: DomainAlignment::Unknown,
            raw_signatures: Vec::new(),
        }
    }
}

pub struct DkimVerifier;

impl DkimVerifier {
    pub fn verify(headers: &HashMap<String, String>, sender_domain: Option<&str>) -> DkimVerificationResult {
        let mut result = DkimVerificationResult::default();
        
        // Find DKIM signatures (case-insensitive)
        let dkim_signatures: Vec<String> = headers
            .iter()
            .filter(|(key, _)| key.to_lowercase() == "dkim-signature")
            .map(|(_, value)| value.clone())
            .collect();
        
        result.has_signature = !dkim_signatures.is_empty();
        result.signature_count = dkim_signatures.len();
        result.raw_signatures = dkim_signatures.clone();
        
        // Extract domains from DKIM signatures
        for signature in &dkim_signatures {
            if let Some(domain) = Self::extract_dkim_domain(signature) {
                result.domains.push(domain);
            }
        }
        
        // Parse Authentication-Results for DKIM status
        result.auth_status = Self::parse_auth_results(headers);
        result.signature_valid = matches!(result.auth_status, DkimAuthStatus::Pass);
        
        // Check domain alignment
        if let Some(sender) = sender_domain {
            result.domain_alignment = Self::check_domain_alignment(&result.domains, sender);
        }
        
        result
    }
    
    fn extract_dkim_domain(dkim_sig: &str) -> Option<String> {
        for part in dkim_sig.split(';') {
            let part = part.trim();
            if let Some(stripped) = part.strip_prefix("d=") {
                return Some(stripped.trim().to_string());
            }
        }
        None
    }
    
    fn parse_auth_results(headers: &HashMap<String, String>) -> DkimAuthStatus {
        for (key, value) in headers {
            if key.to_lowercase() == "authentication-results" {
                let value_lower = value.to_lowercase();
                if value_lower.contains("dkim=pass") {
                    return DkimAuthStatus::Pass;
                } else if value_lower.contains("dkim=fail") {
                    // Extract failure reason if available
                    let reason = if value_lower.contains("signature verification failed") {
                        "signature verification failed".to_string()
                    } else if value_lower.contains("body hash mismatch") {
                        "body hash mismatch".to_string()
                    } else {
                        "unknown failure".to_string()
                    };
                    return DkimAuthStatus::Fail(reason);
                } else if value_lower.contains("dkim=temperror") {
                    return DkimAuthStatus::TempError;
                } else if value_lower.contains("dkim=permerror") {
                    return DkimAuthStatus::PermError;
                } else if value_lower.contains("dkim=none") {
                    return DkimAuthStatus::None;
                }
            }
        }
        
        // If no Authentication-Results but has DKIM signature, status is unknown
        if headers.iter().any(|(key, _)| key.to_lowercase() == "dkim-signature") {
            DkimAuthStatus::None
        } else {
            DkimAuthStatus::None
        }
    }
    
    fn check_domain_alignment(dkim_domains: &[String], sender_domain: &str) -> DomainAlignment {
        if dkim_domains.is_empty() {
            return DomainAlignment::Unknown;
        }
        
        let sender_lower = sender_domain.to_lowercase();
        for dkim_domain in dkim_domains {
            let dkim_lower = dkim_domain.to_lowercase();
            if dkim_lower == sender_lower {
                return DomainAlignment::Aligned;
            }
        }
        
        // Return first mismatch for reporting
        if let Some(first_domain) = dkim_domains.first() {
            DomainAlignment::Misaligned {
                dkim_domain: first_domain.clone(),
                sender_domain: sender_domain.to_string(),
            }
        } else {
            DomainAlignment::Unknown
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_dkim_domain_extraction() {
        let sig = "v=1; a=rsa-sha256; d=example.com; s=selector; h=from:to:subject";
        assert_eq!(DkimVerifier::extract_dkim_domain(sig), Some("example.com".to_string()));
    }
    
    #[test]
    fn test_auth_results_parsing() {
        let mut headers = HashMap::new();
        headers.insert("Authentication-Results".to_string(), "example.com; dkim=pass".to_string());
        
        let status = DkimVerifier::parse_auth_results(&headers);
        assert_eq!(status, DkimAuthStatus::Pass);
    }
    
    #[test]
    fn test_domain_alignment() {
        let dkim_domains = vec!["example.com".to_string()];
        let alignment = DkimVerifier::check_domain_alignment(&dkim_domains, "example.com");
        assert!(matches!(alignment, DomainAlignment::Aligned));
    }
}
