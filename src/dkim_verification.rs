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
    Misaligned {
        dkim_domain: String,
        sender_domain: String,
    },
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
    pub fn verify(
        headers: &HashMap<String, String>,
        sender_domain: Option<&str>,
    ) -> DkimVerificationResult {
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
        // Use the first Authentication-Results header chronologically (first server to analyze)
        // This ensures we use the analysis from the first server that saw the unmodified message

        if let Some((_, first_auth_result)) = headers
            .iter()
            .find(|(key, _)| key.to_lowercase() == "authentication-results")
        {
            let value_lower = first_auth_result.to_lowercase();

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

        // If no Authentication-Results found, status is none
        DkimAuthStatus::None
    }

    fn check_domain_alignment(dkim_domains: &[String], sender_domain: &str) -> DomainAlignment {
        if dkim_domains.is_empty() {
            return DomainAlignment::Unknown;
        }

        let sender_lower = sender_domain.to_lowercase();
        for dkim_domain in dkim_domains {
            let dkim_lower = dkim_domain.to_lowercase();

            // Exact match
            if dkim_lower == sender_lower {
                return DomainAlignment::Aligned;
            }

            // Check if one is a subdomain of the other
            if Self::is_subdomain_aligned(&dkim_lower, &sender_lower) {
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

    /// Check if domains are aligned considering subdomain relationships
    fn is_subdomain_aligned(dkim_domain: &str, sender_domain: &str) -> bool {
        // Extract root domains (last two parts: domain.tld)
        let dkim_root = Self::extract_root_domain(dkim_domain);
        let sender_root = Self::extract_root_domain(sender_domain);

        // If root domains match, consider aligned
        dkim_root == sender_root
    }

    /// Extract root domain (domain.tld) from a full domain
    fn extract_root_domain(domain: &str) -> String {
        let parts: Vec<&str> = domain.split('.').collect();
        if parts.len() >= 2 {
            format!("{}.{}", parts[parts.len() - 2], parts[parts.len() - 1])
        } else {
            domain.to_string()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dkim_domain_extraction() {
        let sig = "v=1; a=rsa-sha256; d=example.com; s=selector; h=from:to:subject";
        assert_eq!(
            DkimVerifier::extract_dkim_domain(sig),
            Some("example.com".to_string())
        );
    }

    #[test]
    fn test_auth_results_parsing() {
        let mut headers = HashMap::new();
        headers.insert(
            "Authentication-Results".to_string(),
            "example.com; dkim=pass".to_string(),
        );

        let status = DkimVerifier::parse_auth_results(&headers);
        assert_eq!(status, DkimAuthStatus::Pass);
    }

    #[test]
    fn test_domain_alignment() {
        let dkim_domains = vec!["example.com".to_string()];
        let alignment = DkimVerifier::check_domain_alignment(&dkim_domains, "example.com");
        assert!(matches!(alignment, DomainAlignment::Aligned));
    }

    #[test]
    fn test_subdomain_alignment() {
        // Test subdomain alignment - send.backstage.com should align with backstage.com
        let dkim_domains = vec!["send.backstage.com".to_string()];
        let alignment = DkimVerifier::check_domain_alignment(&dkim_domains, "backstage.com");
        assert!(matches!(alignment, DomainAlignment::Aligned));

        // Test reverse - backstage.com should align with send.backstage.com
        let dkim_domains = vec!["backstage.com".to_string()];
        let alignment = DkimVerifier::check_domain_alignment(&dkim_domains, "send.backstage.com");
        assert!(matches!(alignment, DomainAlignment::Aligned));

        // Test different domains should not align
        let dkim_domains = vec!["example.com".to_string()];
        let alignment = DkimVerifier::check_domain_alignment(&dkim_domains, "different.com");
        assert!(matches!(alignment, DomainAlignment::Misaligned { .. }));
    }

    #[test]
    fn test_root_domain_extraction() {
        assert_eq!(
            DkimVerifier::extract_root_domain("send.backstage.com"),
            "backstage.com"
        );
        assert_eq!(
            DkimVerifier::extract_root_domain("mail.example.org"),
            "example.org"
        );
        assert_eq!(
            DkimVerifier::extract_root_domain("example.com"),
            "example.com"
        );
        assert_eq!(
            DkimVerifier::extract_root_domain("sub.domain.example.co.uk"),
            "co.uk"
        ); // Note: this is a limitation
    }
}
