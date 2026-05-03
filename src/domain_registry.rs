use std::collections::{HashMap, HashSet};
use std::path::Path;

/// Shared domain registry — single source of truth for all domain classifications.
/// Loaded from domains.toml at startup and shared via Arc across all features.
#[derive(Debug, Clone)]
pub struct DomainRegistry {
    pub esp_trusted: HashSet<String>,
    pub esp_known: HashSet<String>,
    pub esp_all: HashSet<String>, // trusted + known combined
    pub esp_return_path_patterns: Vec<String>,
    pub consumer_email: HashSet<String>,
    pub brands: HashMap<String, BrandInfo>,
    pub retailers: HashSet<String>,
    pub financial: HashSet<String>,
    pub news_media: HashSet<String>,
    pub healthcare: HashSet<String>,
    pub healthcare_domain_keywords: Vec<String>,
    pub technology: HashSet<String>,
    pub social_media: HashSet<String>,
    pub shipping: HashSet<String>,
    pub entertainment: HashSet<String>,
    pub suspicious_tlds_high_risk: HashSet<String>,
    pub suspicious_tlds: HashSet<String>,
    pub suspicious_tlds_all: HashSet<String>, // high_risk + suspicious combined
    /// All known legitimate domains (union of all categories except suspicious)
    pub all_legitimate: HashSet<String>,
}

#[derive(Debug, Clone)]
pub struct BrandInfo {
    pub domains: Vec<String>,
    pub patterns: Vec<String>,
}

impl DomainRegistry {
    /// Load from a TOML file. Falls back to embedded defaults if file not found.
    pub fn load(path: &Path) -> Self {
        match std::fs::read_to_string(path) {
            Ok(content) => match Self::parse(&content) {
                Ok(registry) => {
                    log::info!(
                        "Domain registry loaded from {}: {} ESP, {} brands, {} retailers, {} total legitimate",
                        path.display(),
                        registry.esp_all.len(),
                        registry.brands.len(),
                        registry.retailers.len(),
                        registry.all_legitimate.len(),
                    );
                    registry
                }
                Err(e) => {
                    log::error!("Failed to parse domain registry {}: {}", path.display(), e);
                    Self::default()
                }
            },
            Err(_) => {
                log::warn!(
                    "Domain registry not found at {}, using embedded defaults",
                    path.display()
                );
                Self::from_embedded()
            }
        }
    }

    /// Parse from TOML string
    fn parse(content: &str) -> Result<Self, String> {
        let table: toml::Value =
            toml::from_str(content).map_err(|e| format!("TOML parse error: {}", e))?;

        let get_string_array = |path: &[&str]| -> Vec<String> {
            let mut val = &table;
            for key in path {
                match val.get(key) {
                    Some(v) => val = v,
                    None => return Vec::new(),
                }
            }
            val.as_array()
                .map(|arr| {
                    arr.iter()
                        .filter_map(|v| v.as_str().map(|s| s.to_lowercase()))
                        .collect()
                })
                .unwrap_or_default()
        };

        let to_set = |v: Vec<String>| -> HashSet<String> { v.into_iter().collect() };

        let esp_trusted = to_set(get_string_array(&["esp", "trusted"]));
        let esp_known = to_set(get_string_array(&["esp", "known"]));
        let mut esp_all = esp_trusted.clone();
        esp_all.extend(esp_known.iter().cloned());

        let esp_return_path_patterns = get_string_array(&["esp", "return_path_patterns"]);
        let consumer_email = to_set(get_string_array(&["consumer_email", "domains"]));
        let retailers = to_set(get_string_array(&["retailers", "domains"]));
        let financial = to_set(get_string_array(&["financial", "domains"]));
        let news_media = to_set(get_string_array(&["news_media", "domains"]));
        let healthcare = to_set(get_string_array(&["healthcare", "domains"]));
        let healthcare_domain_keywords = get_string_array(&["healthcare", "domain_keywords"]);
        let technology = to_set(get_string_array(&["technology", "domains"]));
        let social_media = to_set(get_string_array(&["social_media", "domains"]));
        let shipping = to_set(get_string_array(&["shipping", "domains"]));
        let entertainment = to_set(get_string_array(&["entertainment", "domains"]));

        let suspicious_tlds_high_risk = to_set(get_string_array(&["suspicious_tlds", "high_risk"]));
        let suspicious_tlds = to_set(get_string_array(&["suspicious_tlds", "suspicious"]));
        let mut suspicious_tlds_all = suspicious_tlds_high_risk.clone();
        suspicious_tlds_all.extend(suspicious_tlds.iter().cloned());

        // Parse brands
        let mut brands = HashMap::new();
        if let Some(brands_table) = table.get("brands").and_then(|v| v.as_table()) {
            for (name, val) in brands_table {
                if let Some(brand_table) = val.as_table() {
                    let domains = brand_table
                        .get("domains")
                        .and_then(|v| v.as_array())
                        .map(|arr| {
                            arr.iter()
                                .filter_map(|v| v.as_str().map(|s| s.to_lowercase()))
                                .collect()
                        })
                        .unwrap_or_default();
                    let patterns = brand_table
                        .get("patterns")
                        .and_then(|v| v.as_array())
                        .map(|arr| {
                            arr.iter()
                                .filter_map(|v| v.as_str().map(|s| s.to_string()))
                                .collect()
                        })
                        .unwrap_or_default();
                    brands.insert(name.clone(), BrandInfo { domains, patterns });
                }
            }
        }

        // Build all_legitimate union
        let mut all_legitimate = HashSet::new();
        all_legitimate.extend(esp_all.iter().cloned());
        all_legitimate.extend(consumer_email.iter().cloned());
        all_legitimate.extend(retailers.iter().cloned());
        all_legitimate.extend(financial.iter().cloned());
        all_legitimate.extend(news_media.iter().cloned());
        all_legitimate.extend(healthcare.iter().cloned());
        all_legitimate.extend(technology.iter().cloned());
        all_legitimate.extend(social_media.iter().cloned());
        all_legitimate.extend(shipping.iter().cloned());
        all_legitimate.extend(entertainment.iter().cloned());
        for brand in brands.values() {
            all_legitimate.extend(brand.domains.iter().cloned());
        }

        Ok(Self {
            esp_trusted,
            esp_known,
            esp_all,
            esp_return_path_patterns,
            consumer_email,
            brands,
            retailers,
            financial,
            news_media,
            healthcare,
            healthcare_domain_keywords,
            technology,
            social_media,
            shipping,
            entertainment,
            suspicious_tlds_high_risk,
            suspicious_tlds,
            suspicious_tlds_all,
            all_legitimate,
        })
    }

    /// Load from the embedded default (compile-time)
    fn from_embedded() -> Self {
        let content = include_str!("../domains.toml");
        Self::parse(content).unwrap_or_default()
    }

    // --- Query methods ---

    /// Check if domain matches any entry in a set (exact or subdomain match)
    fn matches_set(domain: &str, set: &HashSet<String>) -> bool {
        set.contains(domain)
            || set
                .iter()
                .any(|entry| domain.ends_with(&format!(".{}", entry)))
    }

    /// Check if domain is a known ESP (trusted or known)
    pub fn is_esp(&self, domain: &str) -> bool {
        let d = domain.to_lowercase();
        Self::matches_set(&d, &self.esp_all)
    }

    /// Check if domain is a trusted ESP (higher confidence)
    pub fn is_trusted_esp(&self, domain: &str) -> bool {
        let d = domain.to_lowercase();
        Self::matches_set(&d, &self.esp_trusted)
    }

    /// Check if Return-Path indicates ESP infrastructure
    pub fn is_esp_return_path(&self, return_path: &str) -> bool {
        let rp = return_path.to_lowercase();
        self.esp_return_path_patterns
            .iter()
            .any(|p| rp.contains(p.as_str()))
    }

    /// Check if domain is a consumer email provider
    pub fn is_consumer_email(&self, domain: &str) -> bool {
        self.consumer_email.contains(&domain.to_lowercase())
    }

    /// Check if domain is a known legitimate domain (any category)
    pub fn is_legitimate(&self, domain: &str) -> bool {
        let d = domain.to_lowercase();
        Self::matches_set(&d, &self.all_legitimate)
    }

    /// Check if domain is a known retailer
    pub fn is_retailer(&self, domain: &str) -> bool {
        let d = domain.to_lowercase();
        Self::matches_set(&d, &self.retailers)
    }

    /// Check if domain is a financial institution
    pub fn is_financial(&self, domain: &str) -> bool {
        let d = domain.to_lowercase();
        Self::matches_set(&d, &self.financial)
    }

    /// Check if domain is a news/media organization
    pub fn is_news_media(&self, domain: &str) -> bool {
        let d = domain.to_lowercase();
        Self::matches_set(&d, &self.news_media)
    }

    /// Check if domain is a healthcare organization
    pub fn is_healthcare(&self, domain: &str) -> bool {
        let d = domain.to_lowercase();
        Self::matches_set(&d, &self.healthcare)
            || self
                .healthcare_domain_keywords
                .iter()
                .any(|kw| d.contains(kw.as_str()))
    }

    /// Check if domain has a suspicious TLD
    pub fn has_suspicious_tld(&self, domain: &str) -> bool {
        let d = domain.to_lowercase();
        self.suspicious_tlds_all.iter().any(|tld| d.ends_with(tld))
    }

    /// Check if domain has a high-risk TLD
    pub fn has_high_risk_tld(&self, domain: &str) -> bool {
        let d = domain.to_lowercase();
        self.suspicious_tlds_high_risk
            .iter()
            .any(|tld| d.ends_with(tld))
    }

    /// Get brand info if domain claims to be a known brand
    pub fn get_brand_for_domain(&self, domain: &str) -> Option<(&str, &BrandInfo)> {
        let d = domain.to_lowercase();
        self.brands.iter().find_map(|(name, info)| {
            if info
                .domains
                .iter()
                .any(|bd| d == *bd || d.ends_with(&format!(".{}", bd)))
            {
                Some((name.as_str(), info))
            } else {
                None
            }
        })
    }

    /// Check if a domain is legitimate for a given brand
    pub fn is_legitimate_for_brand(&self, domain: &str, brand_name: &str) -> bool {
        let d = domain.to_lowercase();
        self.brands
            .get(brand_name)
            .map(|info| {
                info.domains
                    .iter()
                    .any(|bd| d == *bd || d.ends_with(&format!(".{}", bd)))
            })
            .unwrap_or(false)
    }
}

impl Default for DomainRegistry {
    fn default() -> Self {
        Self::from_embedded()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_load_embedded() {
        let registry = DomainRegistry::default();
        assert!(registry.is_esp("sendgrid.net"));
        assert!(registry.is_trusted_esp("sendgrid.net"));
        assert!(!registry.is_trusted_esp("constantcontact.com"));
        assert!(registry.is_esp("constantcontact.com"));
        assert!(registry.is_consumer_email("gmail.com"));
        assert!(!registry.is_consumer_email("amazon.com"));
        assert!(registry.is_retailer("amazon.com"));
        assert!(registry.is_financial("chase.com"));
        assert!(registry.is_news_media("nytimes.com"));
        assert!(registry.is_healthcare("commonspirit.org"));
        assert!(registry.has_suspicious_tld("example.tk"));
        assert!(registry.is_legitimate("sendgrid.net"));
        assert!(registry.is_legitimate("amazon.com"));
        assert!(!registry.is_legitimate("retrosnapback.com"));
        assert!(registry.brands.contains_key("amazon"));
        assert!(registry.is_legitimate_for_brand("aws.com", "amazon"));
    }

    #[test]
    fn test_subdomain_matching() {
        let registry = DomainRegistry::default();
        assert!(registry.is_esp("u161779.wl030.sendgrid.net"));
        assert!(registry.is_retailer("orders.americanmeadows.com"));
        assert!(registry.is_healthcare("mail.commonspirit.org"));
    }
}
