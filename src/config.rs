use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    pub socket_path: String,
    pub rules: Vec<FilterRule>,
    pub default_action: Action,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FilterRule {
    pub name: String,
    pub criteria: Criteria,
    pub action: Action,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum Criteria {
    MailerPattern {
        pattern: String,
    },
    SenderPattern {
        pattern: String,
    },
    RecipientPattern {
        pattern: String,
    },
    SubjectPattern {
        pattern: String,
    },
    HeaderPattern {
        header: String,
        pattern: String,
    },
    SubjectContainsLanguage {
        language: String,
    },
    HeaderContainsLanguage {
        header: String,
        language: String,
    },
    UnsubscribeLinkValidation {
        timeout_seconds: Option<u64>,
        check_dns: Option<bool>,
        check_http: Option<bool>,
    },
    UnsubscribeLinkPattern {
        pattern: String,
    },
    PhishingSenderSpoofing {
        // Detects when From header display name claims to be from a different domain than the actual sender
        trusted_domains: Vec<String>,
    },
    PhishingSuspiciousLinks {
        // Detects suspicious link patterns commonly used in phishing
        check_url_shorteners: Option<bool>,
        check_suspicious_tlds: Option<bool>,
        check_ip_addresses: Option<bool>,
        suspicious_patterns: Option<Vec<String>>,
    },
    PhishingDomainMismatch {
        // Detects when Reply-To domain differs significantly from sender domain
        allow_subdomains: Option<bool>,
    },
    And {
        criteria: Vec<Criteria>,
    },
    Or {
        criteria: Vec<Criteria>,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum Action {
    Reject {
        message: String,
    },
    TagAsSpam {
        header_name: String,
        header_value: String,
    },
    Accept,
}

impl Default for Config {
    fn default() -> Self {
        Config {
            socket_path: "/var/run/foff-milter.sock".to_string(),
            rules: vec![
                FilterRule {
                    name: "Block suspicious Chinese services".to_string(),
                    criteria: Criteria::MailerPattern {
                        pattern: r"service\..*\.cn".to_string(),
                    },
                    action: Action::Reject {
                        message: "Mail from suspicious service rejected".to_string(),
                    },
                },
                FilterRule {
                    name: "Tag potential spam".to_string(),
                    criteria: Criteria::MailerPattern {
                        pattern: r".*spam.*".to_string(),
                    },
                    action: Action::TagAsSpam {
                        header_name: "X-Spam-Flag".to_string(),
                        header_value: "YES".to_string(),
                    },
                },
            ],
            default_action: Action::Accept,
        }
    }
}

impl Config {
    pub fn from_file(path: &str) -> anyhow::Result<Self> {
        let content = std::fs::read_to_string(path)?;
        let config: Config = serde_yaml::from_str(&content)?;
        Ok(config)
    }

    pub fn to_file(&self, path: &str) -> anyhow::Result<()> {
        let content = serde_yaml::to_string(self)?;
        std::fs::write(path, content)?;
        Ok(())
    }
}
