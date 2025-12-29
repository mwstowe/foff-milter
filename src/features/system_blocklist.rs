use crate::features::{FeatureExtractor, FeatureScore};
use crate::MailContext;
use regex::Regex;
use serde::Deserialize;

#[derive(Debug, Deserialize)]
struct SystemBlocklistConfig {
    domains: DomainsConfig,
    patterns: PatternsConfig,
}

#[derive(Debug, Deserialize)]
struct DomainsConfig {
    suspicious_tlds: Vec<String>,
    malicious_domains: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct PatternsConfig {
    suspicious_patterns: Vec<String>,
}

pub struct SystemBlocklistFeature {
    config: SystemBlocklistConfig,
}

impl Default for SystemBlocklistFeature {
    fn default() -> Self {
        Self::new()
    }
}

impl SystemBlocklistFeature {
    pub fn new() -> Self {
        let config_content = include_str!("../../features/system_blocklist.toml");
        let config: SystemBlocklistConfig =
            toml::from_str(config_content).expect("Failed to parse system_blocklist.toml");

        SystemBlocklistFeature { config }
    }
}

fn extract_domain_from_email(email: &str) -> Option<String> {
    email.split('@').nth(1).map(|s| s.to_lowercase())
}

impl FeatureExtractor for SystemBlocklistFeature {
    fn extract(&self, context: &MailContext) -> FeatureScore {
        let mut score = 0;
        let mut evidence = Vec::new();

        // Check From header (same logic as user blocklist)
        if let Some(from_header) = &context.from_header {
            if let Some(domain) = extract_domain_from_email(from_header) {
                // Check exact malicious domains
                if self.config.domains.malicious_domains.contains(&domain) {
                    score += 500;
                    evidence.push(format!("Domain {} is on system blocklist", domain));
                }

                // Check suspicious TLDs
                for tld in &self.config.domains.suspicious_tlds {
                    if domain.ends_with(tld) {
                        score += 200;
                        evidence.push(format!("Domain uses suspicious TLD: {}", tld));
                        break;
                    }
                }

                // Check domain patterns (exact same logic as user blocklist)
                for pattern in &self.config.patterns.suspicious_patterns {
                    if let Ok(regex) = Regex::new(pattern) {
                        if regex.is_match(&domain) {
                            score += 300;
                            evidence.push(format!(
                                "Domain matches suspicious pattern '{}': {}",
                                pattern, domain
                            ));
                            break;
                        }
                    }
                }
            }
        }

        // Also check sender (envelope from) like user blocklist does
        if let Some(sender) = &context.sender {
            if let Some(domain) = extract_domain_from_email(sender) {
                // Check exact malicious domains
                if self.config.domains.malicious_domains.contains(&domain) {
                    score += 500;
                    evidence.push(format!("Sender domain {} is on system blocklist", domain));
                }

                // Check suspicious TLDs
                for tld in &self.config.domains.suspicious_tlds {
                    if domain.ends_with(tld) {
                        score += 200;
                        evidence.push(format!("Sender domain uses suspicious TLD: {}", tld));
                        break;
                    }
                }

                // Check domain patterns
                for pattern in &self.config.patterns.suspicious_patterns {
                    if let Ok(regex) = Regex::new(pattern) {
                        if regex.is_match(&domain) {
                            score += 300;
                            evidence.push(format!(
                                "Sender domain matches suspicious pattern '{}': {}",
                                pattern, domain
                            ));
                            break;
                        }
                    }
                }
            }
        }

        FeatureScore {
            feature_name: "system_blocklist".to_string(),
            score,
            confidence: if score > 0 { 0.95 } else { 0.0 },
            evidence,
        }
    }

    fn name(&self) -> &str {
        "system_blocklist"
    }
}
