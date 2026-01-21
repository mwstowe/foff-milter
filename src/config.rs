use crate::toml_config::TomlConfig;
use chrono;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    pub socket_path: String,
    pub module_config_dir: Option<String>,
    pub feature_config_dir: Option<String>,
    pub default_action: Action,
    pub statistics: Option<StatisticsConfig>,
    pub rules: Vec<FilterRule>,
    pub version: String,
    pub rule_set_timestamp: String,
    pub smtp: Option<SmtpConfig>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SmtpConfig {
    pub server: String,
    pub port: Option<u16>,
    pub username: Option<String>,
    pub password: Option<String>,
    pub from_name: Option<String>,
    pub from_email: String,
    pub timeout_seconds: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Action {
    Accept,
    Reject {
        message: String,
    },
    TagAsSpam {
        header_name: String,
        header_value: String,
    },
    Tag {
        tag: String,
    },
    ReportAbuse {
        smtp_config: SmtpConfig,
        report_to: String,
        subject_template: Option<String>,
        body_template: Option<String>,
    },
    UnsubscribeGoogleGroup {
        timeout_seconds: Option<u64>,
        max_retries: Option<u32>,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StatisticsConfig {
    pub enabled: bool,
    pub database_path: String,
    pub flush_interval_seconds: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Module {
    pub name: String,
    pub enabled: bool,
    pub rules: Vec<FilterRule>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FilterRule {
    pub name: String,
    pub enabled: Option<bool>,
    pub criteria: Criteria,
    pub score: i32,
    pub action: Option<Action>,
    pub description: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum Criteria {
    And {
        criteria: Vec<Criteria>,
    },
    Or {
        criteria: Vec<Criteria>,
    },
    Not {
        criteria: Box<Criteria>,
    },
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
    BodyPattern {
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
    UnsubscribeLinkIPAddress {
        check_ipv4: Option<bool>,
        check_ipv6: Option<bool>,
        allow_private_ips: Option<bool>,
    },
    UnsubscribeMailtoOnly {
        allow_mixed: Option<bool>,
    },
    PhishingSenderSpoofing {
        trusted_domains: Vec<String>,
    },
    PhishingSuspiciousLinks {
        check_url_shorteners: Option<bool>,
        check_suspicious_tlds: Option<bool>,
        check_ip_addresses: Option<bool>,
        suspicious_patterns: Option<Vec<String>>,
        allow_sender_domain: Option<bool>,
        allow_email_infrastructure: Option<bool>,
        email_infrastructure_domains: Option<Vec<String>>,
    },
    PhishingDomainMismatch {
        allow_subdomains: Option<bool>,
    },
    PhishingLinkRedirection {
        max_redirects: Option<u32>,
        timeout_seconds: Option<u64>,
        suspicious_redirect_patterns: Option<Vec<String>>,
        check_final_destination: Option<bool>,
    },
    ImageOnlyEmail {
        max_text_length: Option<usize>,
        ignore_whitespace: Option<bool>,
        check_attachments: Option<bool>,
    },
    PhishingFreeEmailReplyTo {
        free_email_domains: Option<Vec<String>>,
        allow_same_domain: Option<bool>,
    },
    ReplyToValidation {
        timeout_seconds: Option<u64>,
        check_mx_record: Option<bool>,
    },
    DomainAge {
        max_age_days: u32,
        check_sender: Option<bool>,
        check_reply_to: Option<bool>,
        check_from_header: Option<bool>,
        timeout_seconds: Option<u64>,
        use_mock_data: Option<bool>,
    },
    InvalidUnsubscribeHeaders,
    AttachmentOnlyEmail {
        max_text_length: Option<usize>,
        ignore_whitespace: Option<bool>,
        suspicious_types: Option<Vec<String>>,
        min_attachment_size: Option<usize>,
        check_disposition: Option<bool>,
    },
    EmptyContentEmail {
        max_text_length: Option<usize>,
        ignore_whitespace: Option<bool>,
        ignore_signatures: Option<bool>,
        require_empty_subject: Option<bool>,
        min_subject_length: Option<usize>,
        ignore_html_tags: Option<bool>,
    },
    EmailServiceAbuse {
        legitimate_services: Option<Vec<String>>,
        brand_keywords: Option<Vec<String>>,
        free_email_domains: Option<Vec<String>>,
        check_reply_to_mismatch: Option<bool>,
        check_brand_impersonation: Option<bool>,
        check_suspicious_subjects: Option<bool>,
    },
    GoogleGroupsAbuse {
        suspicious_domains: Option<Vec<String>>,
        reward_keywords: Option<Vec<String>>,
        suspicious_sender_names: Option<Vec<String>>,
        check_domain_reputation: Option<bool>,
        check_reward_subjects: Option<bool>,
        check_suspicious_senders: Option<bool>,
        min_indicators: Option<u32>,
    },
    SenderSpoofingExtortion {
        extortion_keywords: Option<Vec<String>>,
        check_sender_recipient_match: Option<bool>,
        check_external_source: Option<bool>,
        check_missing_authentication: Option<bool>,
        require_extortion_content: Option<bool>,
        min_indicators: Option<u32>,
    },
    DocuSignAbuse {
        check_reply_to_mismatch: Option<bool>,
        check_panic_subjects: Option<bool>,
        check_suspicious_encoding: Option<bool>,
        min_indicators: Option<u32>,
    },
    DkimAnalysis {
        require_signature: Option<bool>,
        check_domain_mismatch: Option<bool>,
        detect_spoofing: Option<bool>,
        brand_domains: Option<Vec<String>>,
        suspicious_domains: Option<Vec<String>>,
    },
    LanguageGeographyMismatch {
        domain_pattern: String,
        content_pattern: String,
        description: String,
    },
    MixedScriptDetection {
        suspicious_combinations: Vec<String>,
        threshold: u32,
    },
    EmailInfrastructure {
        infrastructure_type: String,
        domains: Option<Vec<String>>,
        tld_patterns: Option<Vec<String>>,
        check_sender: Option<bool>,
        check_reply_to: Option<bool>,
        require_auth_failure: Option<bool>,
        exclude_legitimate: Option<bool>,
    },
    FreeEmailProvider {
        check_sender: Option<bool>,
        check_reply_to: Option<bool>,
    },
    MaliciousAttachment {
        dangerous_extensions: Option<Vec<String>>,
        archive_types: Option<Vec<String>>,
        use_pattern_fallback: Option<bool>,
    },
    BrandImpersonation {
        brand_name: String,
        subject_patterns: Option<Vec<String>>,
        sender_patterns: Option<Vec<String>>,
        body_patterns: Option<Vec<String>>,
        legitimate_domains: Option<Vec<String>>,
        require_auth_failure: Option<bool>,
        suspicious_tlds: Option<Vec<String>>,
    },
}

impl Config {
    pub fn new_default() -> Self {
        Config {
            socket_path: "/var/run/foff-milter.sock".to_string(),
            module_config_dir: Some("rulesets".to_string()),
            feature_config_dir: Some("features".to_string()),
            default_action: Action::Accept,
            statistics: None,
            rules: Vec::new(),
            version: crate::version::VERSION.to_string(),
            rule_set_timestamp: chrono::Utc::now()
                .format("%Y-%m-%d %H:%M:%S UTC")
                .to_string(),
            smtp: None,
        }
    }

    pub fn from_toml_config(toml_config: &TomlConfig) -> Self {
        Config {
            socket_path: toml_config
                .system
                .as_ref()
                .map(|s| s.socket_path.clone())
                .unwrap_or_else(|| "/var/run/foff-milter.sock".to_string()),
            module_config_dir: toml_config.rulesets.as_ref().and_then(|m| {
                if m.enabled {
                    Some(m.config_dir.clone())
                } else {
                    None
                }
            }),
            feature_config_dir: toml_config.features.as_ref().and_then(|f| {
                if f.enabled {
                    Some(f.config_dir.clone())
                } else {
                    None
                }
            }),
            default_action: match toml_config
                .default_action
                .as_ref()
                .map(|da| da.action_type.as_str())
                .unwrap_or("Accept")
            {
                "Accept" => Action::Accept,
                "Reject" => Action::Reject {
                    message: "Rejected by policy".to_string(),
                },
                "TagAsSpam" => Action::TagAsSpam {
                    header_name: "X-Spam-Flag".to_string(),
                    header_value: "YES".to_string(),
                },
                _ => Action::Accept,
            },
            statistics: toml_config.statistics.as_ref().map(|s| StatisticsConfig {
                enabled: s.enabled,
                database_path: s.database_path.clone(),
                flush_interval_seconds: Some(s.flush_interval_seconds),
            }),
            rules: Vec::new(),
            version: crate::version::VERSION.to_string(),
            rule_set_timestamp: chrono::Utc::now()
                .format("%Y-%m-%d %H:%M:%S UTC")
                .to_string(),
            smtp: None,
        }
    }
}

impl Module {
    pub fn load_from_file(path: &Path) -> Result<Self, Box<dyn std::error::Error>> {
        let content = fs::read_to_string(path)?;
        let module: Module = serde_yml::from_str(&content)?;
        Ok(module)
    }
}

pub fn load_modules(module_dir: &str) -> Result<Vec<Module>, Box<dyn std::error::Error>> {
    let mut modules = Vec::new();
    let dir_path = Path::new(module_dir);

    if !dir_path.exists() {
        return Err(format!("Module directory does not exist: {}", module_dir).into());
    }

    let mut yaml_files = Vec::new();
    for entry in fs::read_dir(dir_path)? {
        let entry = entry?;
        let path = entry.path();
        if path.is_file() {
            if let Some(extension) = path.extension() {
                if extension == "yaml" || extension == "yml" {
                    yaml_files.push(path);
                }
            }
        }
    }

    yaml_files.sort();

    for yaml_file in yaml_files {
        match Module::load_from_file(&yaml_file) {
            Ok(module) => {
                if module.enabled {
                    modules.push(module);
                }
            }
            Err(e) => {
                eprintln!("Failed to load module {:?}: {}", yaml_file, e);
            }
        }
    }

    Ok(modules)
}
