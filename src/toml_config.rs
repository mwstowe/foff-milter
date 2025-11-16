use crate::legacy_config::{Action, Config as LegacyConfig};
use serde::{Deserialize, Serialize};
use std::path::Path;

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct TomlConfig {
    pub system: SystemConfig,
    pub logging: Option<LoggingConfig>,
    pub statistics: Option<StatisticsConfig>,
    pub rulesets: Option<RulesetsConfig>,
    pub features: Option<FeaturesConfig>,
    pub heuristics: Option<HeuristicsConfig>,
    pub sender_blocking: Option<SenderBlockingConfig>,
    pub whitelist: Option<WhitelistConfig>,
    pub blocklist: Option<BlocklistConfig>,
    pub legacy: Option<LegacyConfigRef>,
    pub default_action: DefaultActionConfig,
    pub performance: Option<PerformanceConfig>,
    pub domain_classifications: Option<DomainClassifications>,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct DomainClassifications {
    pub free_email_providers: Option<Vec<String>>,
    pub email_infrastructure: Option<Vec<String>>,
    pub high_risk_tlds: Option<Vec<String>>,
}

impl Default for TomlConfig {
    fn default() -> Self {
        Self {
            system: SystemConfig {
                socket_path: "/var/run/foff-milter.sock".to_string(),
                reject_to_tag: true,
            },
            logging: None,
            statistics: None,
            rulesets: Some(RulesetsConfig {
                enabled: true,
                config_dir: "rulesets".to_string(),
            }),
            features: Some(FeaturesConfig {
                enabled: true,
                config_dir: "features".to_string(),
            }),
            heuristics: Some(HeuristicsConfig {
                reject_threshold: 350,
                spam_threshold: 50,
                accept_threshold: 0,
            }),
            sender_blocking: None,
            whitelist: None,
            blocklist: None,
            legacy: None,
            default_action: DefaultActionConfig {
                action_type: "Accept".to_string(),
            },
            performance: None,
            domain_classifications: Some(DomainClassifications {
                free_email_providers: Some(vec![
                    "gmail.com".to_string(),
                    "outlook.com".to_string(),
                    "yahoo.com".to_string(),
                    "hotmail.com".to_string(),
                    "aol.com".to_string(),
                ]),
                email_infrastructure: Some(vec![
                    "mailchimp.com".to_string(),
                    "sendgrid.net".to_string(),
                    "mailgun.org".to_string(),
                ]),
                high_risk_tlds: Some(vec![
                    ".tk".to_string(),
                    ".ml".to_string(),
                    ".ga".to_string(),
                    ".cf".to_string(),
                ]),
            }),
        }
    }
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct SystemConfig {
    pub socket_path: String,
    #[serde(default = "default_reject_to_tag")]
    pub reject_to_tag: bool,
}

fn default_reject_to_tag() -> bool {
    true
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct LoggingConfig {
    pub level: String,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct StatisticsConfig {
    pub enabled: bool,
    pub database_path: String,
    pub flush_interval_seconds: u64,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct RulesetsConfig {
    pub enabled: bool,
    pub config_dir: String,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct FeaturesConfig {
    pub enabled: bool,
    pub config_dir: String,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct HeuristicsConfig {
    pub reject_threshold: i32,
    pub spam_threshold: i32,
    pub accept_threshold: i32,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct SenderBlockingConfig {
    pub enabled: bool,
    pub block_patterns: Vec<String>,
    pub action: String, // "reject" or "tag"
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct WhitelistConfig {
    pub enabled: bool,
    pub addresses: Vec<String>,
    pub domains: Vec<String>,
    pub domain_patterns: Vec<String>,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct BlocklistConfig {
    pub enabled: bool,
    pub addresses: Vec<String>,
    pub domains: Vec<String>,
    pub domain_patterns: Vec<String>,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct LegacyConfigRef {
    pub enabled: bool,
    pub config_file: String,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct DefaultActionConfig {
    #[serde(rename = "type")]
    pub action_type: String,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct PerformanceConfig {
    pub max_concurrent_emails: u32,
    pub timeout_seconds: u32,
}

impl TomlConfig {
    pub fn load_from_file<P: AsRef<Path>>(path: P) -> anyhow::Result<Self> {
        let content = std::fs::read_to_string(path)?;
        let config: TomlConfig = toml::from_str(&content)?;
        Ok(config)
    }

    pub fn default_path() -> &'static str {
        "/etc/foff-milter.toml"
    }

    pub fn to_legacy_config(&self) -> anyhow::Result<LegacyConfig> {
        let mut legacy_config = LegacyConfig {
            socket_path: self.system.socket_path.clone(),
            default_action: Action::Accept, // Will be updated below
            statistics: None,
            module_config_dir: None,
            rules: vec![],
            smtp: None,
            version: env!("CARGO_PKG_VERSION").to_string(),
            rule_set_timestamp: chrono::Utc::now()
                .format("%Y-%m-%d %H:%M:%S UTC")
                .to_string(),
        };

        // Set default action
        legacy_config.default_action = match self.default_action.action_type.as_str() {
            "Accept" => Action::Accept,
            "Reject" => Action::Reject {
                message: "Rejected by policy".to_string(),
            },
            "TagAsSpam" => Action::TagAsSpam {
                header_name: "X-Spam-Flag".to_string(),
                header_value: "YES".to_string(),
            },
            _ => Action::Accept,
        };

        // Set statistics
        if let Some(stats) = &self.statistics {
            if stats.enabled {
                legacy_config.statistics = Some(crate::legacy_config::StatisticsConfig {
                    enabled: true,
                    database_path: stats.database_path.clone(),
                    flush_interval_seconds: Some(stats.flush_interval_seconds),
                });
            }
        }

        // Set module config directory
        if let Some(rulesets) = &self.rulesets {
            if rulesets.enabled {
                legacy_config.module_config_dir = Some(rulesets.config_dir.clone());
            }
        }

        Ok(legacy_config)
    }
}
