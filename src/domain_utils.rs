/// Minimal domain hierarchy utilities
pub struct DomainUtils;

impl DomainUtils {
    /// Extract domain from email address
    pub fn extract_domain(email: &str) -> Option<String> {
        email.split('@').nth(1).map(|s| s.to_lowercase())
    }

    /// Check if domain matches any in list (with hierarchy support)
    pub fn matches_domain_list(domain: &str, domain_list: &[String]) -> bool {
        let domain_lower = domain.to_lowercase();

        for pattern in domain_list {
            let pattern_lower = pattern.to_lowercase();

            // Exact match
            if domain_lower == pattern_lower {
                return true;
            }

            // Subdomain match (domain ends with .pattern)
            if domain_lower.ends_with(&format!(".{}", pattern_lower)) {
                return true;
            }
        }

        false
    }

    /// Canonicalize domain (remove www prefix)
    pub fn canonicalize_domain(domain: &str) -> String {
        let domain_lower = domain.to_lowercase();
        if let Some(stripped) = domain_lower.strip_prefix("www.") {
            stripped.to_string()
        } else {
            domain_lower
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_domain() {
        assert_eq!(
            DomainUtils::extract_domain("user@example.com"),
            Some("example.com".to_string())
        );
        assert_eq!(DomainUtils::extract_domain("invalid"), None);
    }

    #[test]
    fn test_matches_domain_list() {
        let domains = vec!["example.com".to_string(), "test.org".to_string()];

        assert!(DomainUtils::matches_domain_list("example.com", &domains));
        assert!(DomainUtils::matches_domain_list(
            "mail.example.com",
            &domains
        ));
        assert!(!DomainUtils::matches_domain_list("other.com", &domains));
    }

    #[test]
    fn test_canonicalize_domain() {
        assert_eq!(
            DomainUtils::canonicalize_domain("www.example.com"),
            "example.com"
        );
        assert_eq!(
            DomainUtils::canonicalize_domain("example.com"),
            "example.com"
        );
    }
}
