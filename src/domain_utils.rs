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

    /// Best-effort registrable ("organizational") domain.
    ///
    /// This is a lightweight approximation of the public-suffix list: it keeps
    /// the last two labels for ordinary TLDs (e.g. `a.b.example.com` ->
    /// `example.com`) and the last three labels for the common two-level
    /// public suffixes we see in practice (e.g. `foo.example.co.uk` ->
    /// `example.co.uk`). It is intentionally conservative — it is only used to
    /// decide whether two hostnames belong to the *same* organization, so an
    /// occasional over-broad grouping is safer than treating related hosts as
    /// unrelated.
    pub fn registrable_domain(host: &str) -> String {
        let host = host.trim().trim_end_matches('.').to_lowercase();
        let labels: Vec<&str> = host.split('.').filter(|l| !l.is_empty()).collect();
        if labels.len() <= 2 {
            return labels.join(".");
        }

        // Second-level public suffixes (country-code registries that sell
        // registrations one level down). Not exhaustive, but covers the
        // overwhelming majority of real-world mail.
        const SECOND_LEVEL_SUFFIXES: &[&str] = &[
            "co.uk", "org.uk", "gov.uk", "ac.uk", "me.uk", "ltd.uk", "plc.uk", "net.uk", "com.au",
            "net.au", "org.au", "edu.au", "gov.au", "co.nz", "net.nz", "org.nz", "co.jp", "or.jp",
            "ne.jp", "ac.jp", "go.jp", "com.br", "net.br", "org.br", "gov.br", "com.cn", "net.cn",
            "org.cn", "gov.cn", "co.in", "net.in", "org.in", "co.kr", "or.kr", "com.mx", "com.sg",
            "com.hk", "co.za", "com.tr",
        ];

        let last_two = labels[labels.len() - 2..].join(".");
        if SECOND_LEVEL_SUFFIXES.contains(&last_two.as_str()) && labels.len() >= 3 {
            labels[labels.len() - 3..].join(".")
        } else {
            last_two
        }
    }

    /// True if two hostnames share the same registrable (organizational) domain.
    pub fn same_registrable_domain(a: &str, b: &str) -> bool {
        let (ra, rb) = (Self::registrable_domain(a), Self::registrable_domain(b));
        !ra.is_empty() && ra == rb
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

    #[test]
    fn test_registrable_domain() {
        assert_eq!(
            DomainUtils::registrable_domain("example.com"),
            "example.com"
        );
        assert_eq!(
            DomainUtils::registrable_domain("a.b.example.com"),
            "example.com"
        );
        assert_eq!(
            DomainUtils::registrable_domain("mail218.atl221.rsgsv.net"),
            "rsgsv.net"
        );
        assert_eq!(
            DomainUtils::registrable_domain("foo.example.co.uk"),
            "example.co.uk"
        );
        // Throwaway numeric host used by the Japanese phishing sample
        assert_eq!(
            DomainUtils::registrable_domain("4ef98f50.0825114.net"),
            "0825114.net"
        );
    }

    #[test]
    fn test_same_registrable_domain() {
        // Links back to the sending organization
        assert!(DomainUtils::same_registrable_domain(
            "l.promo.newegg.com",
            "promo.newegg.com"
        ));
        // Unrelated throwaway link domain vs sender
        assert!(!DomainUtils::same_registrable_domain(
            "4ef98f50.0825114.net",
            "phuoyp.xiaofeifupin.net"
        ));
    }
}
