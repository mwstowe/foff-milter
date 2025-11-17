use crate::heuristic_config::{Action, Config as HeuristicConfig};
use serde::{Deserialize, Serialize};
use std::path::Path;

#[derive(Debug, Deserialize, Serialize, Clone)]
#[serde(default)]
pub struct TomlConfig {
    pub system: Option<SystemConfig>,
    pub logging: Option<LoggingConfig>,
    pub statistics: Option<StatisticsConfig>,
    pub rulesets: Option<RulesetsConfig>,
    pub features: Option<FeaturesConfig>,
    pub heuristics: Option<HeuristicsConfig>,
    pub sender_blocking: Option<SenderBlockingConfig>,
    pub whitelist: Option<WhitelistConfig>,
    pub blocklist: Option<BlocklistConfig>,
    pub default_action: Option<DefaultActionConfig>,
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
        // Platform-specific base directory
        let base_dir = if cfg!(target_os = "freebsd") {
            "/usr/local/etc"
        } else {
            "/etc"
        };

        let foff_dir = format!("{}/foff-milter", base_dir);

        Self {
            system: Some(SystemConfig {
                socket_path: "/var/run/foff-milter.sock".to_string(),
                reject_to_tag: true,
            }),
            logging: None,
            statistics: Some(StatisticsConfig {
                enabled: true,
                database_path: "/var/lib/foff-milter/stats.db".to_string(),
                flush_interval_seconds: 60,
            }),
            rulesets: Some(RulesetsConfig {
                enabled: true,
                config_dir: format!("{}/rulesets", foff_dir),
            }),
            features: Some(FeaturesConfig {
                enabled: true,
                config_dir: format!("{}/features", foff_dir),
            }),
            heuristics: Some(HeuristicsConfig {
                reject_threshold: 350,
                spam_threshold: 50,
                accept_threshold: 0,
            }),
            sender_blocking: Some(SenderBlockingConfig {
                enabled: true,
                block_patterns: vec![],
                action: "reject".to_string(),
            }),
            whitelist: Some(WhitelistConfig {
                enabled: true,
                addresses: vec![],
                domains: vec![],
                domain_patterns: vec![],
            }),
            blocklist: Some(BlocklistConfig {
                enabled: true,
                addresses: vec![],
                domains: vec![],
                domain_patterns: vec![],
            }),
            default_action: Some(DefaultActionConfig {
                action_type: "Accept".to_string(),
            }),
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
        let config_path = path.as_ref();
        let content = std::fs::read_to_string(config_path)?;
        let mut config: TomlConfig = toml::from_str(&content)?;

        // Get config file directory for relative paths
        let config_dir = config_path.parent().unwrap_or(Path::new("."));

        // Create defaults relative to config file location
        let defaults = Self::default_relative_to(config_dir);

        if config.system.is_none() {
            config.system = defaults.system;
        }

        if config.statistics.is_none() {
            config.statistics = defaults.statistics;
        }

        if config.rulesets.is_none() {
            config.rulesets = defaults.rulesets;
        }

        if config.features.is_none() {
            config.features = defaults.features;
        }

        // Resolve relative paths in existing config values
        if let Some(ref mut rulesets) = config.rulesets {
            if !Path::new(&rulesets.config_dir).is_absolute() {
                rulesets.config_dir = config_dir.join(&rulesets.config_dir).to_string_lossy().to_string();
            }
        }

        if let Some(ref mut features) = config.features {
            if !Path::new(&features.config_dir).is_absolute() {
                features.config_dir = config_dir.join(&features.config_dir).to_string_lossy().to_string();
            }
        }

        if config.heuristics.is_none() {
            config.heuristics = defaults.heuristics;
        }

        if config.sender_blocking.is_none() {
            config.sender_blocking = defaults.sender_blocking;
        }

        if config.whitelist.is_none() {
            config.whitelist = defaults.whitelist;
        }

        if config.blocklist.is_none() {
            config.blocklist = defaults.blocklist;
        }

        if config.default_action.is_none() {
            config.default_action = defaults.default_action;
        }

        Ok(config)
    }

    fn default_relative_to(config_dir: &Path) -> Self {
        // Create foff-milter subdirectory in the config file's directory
        let foff_dir = config_dir.join("foff-milter");
        let rulesets_dir = foff_dir.join("rulesets").to_string_lossy().to_string();
        let features_dir = foff_dir.join("features").to_string_lossy().to_string();

        Self {
            system: Some(SystemConfig {
                socket_path: "/var/run/foff-milter.sock".to_string(),
                reject_to_tag: true,
            }),
            logging: None,
            statistics: Some(StatisticsConfig {
                enabled: true,
                database_path: "/var/lib/foff-milter/stats.db".to_string(),
                flush_interval_seconds: 60,
            }),
            rulesets: Some(RulesetsConfig {
                enabled: true,
                config_dir: rulesets_dir,
            }),
            features: Some(FeaturesConfig {
                enabled: true,
                config_dir: features_dir,
            }),
            heuristics: Some(HeuristicsConfig {
                reject_threshold: 350,
                spam_threshold: 50,
                accept_threshold: 0,
            }),
            sender_blocking: Some(SenderBlockingConfig {
                enabled: true,
                block_patterns: vec![],
                action: "reject".to_string(),
            }),
            whitelist: Some(WhitelistConfig {
                enabled: true,
                addresses: vec![],
                domains: vec![],
                domain_patterns: vec![],
            }),
            blocklist: Some(BlocklistConfig {
                enabled: true,
                addresses: vec![],
                domains: vec![],
                domain_patterns: vec![],
            }),
            default_action: Some(DefaultActionConfig {
                action_type: "Accept".to_string(),
            }),
            performance: None,
            domain_classifications: None,
        }
    }

    pub fn default_path() -> &'static str {
        "/etc/foff-milter.toml"
    }

    pub fn to_heuristic_config(&self) -> anyhow::Result<HeuristicConfig> {
        let default_system = SystemConfig {
            socket_path: "/var/run/foff-milter.sock".to_string(),
            reject_to_tag: true,
        };
        let system = self.system.as_ref().unwrap_or(&default_system);

        let mut heuristic_config = HeuristicConfig {
            socket_path: system.socket_path.clone(),
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
        let default_action_config = DefaultActionConfig {
            action_type: "Accept".to_string(),
        };
        let default_action = self
            .default_action
            .as_ref()
            .unwrap_or(&default_action_config);
        heuristic_config.default_action = match default_action.action_type.as_str() {
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
                heuristic_config.statistics = Some(crate::heuristic_config::StatisticsConfig {
                    enabled: true,
                    database_path: stats.database_path.clone(),
                    flush_interval_seconds: Some(stats.flush_interval_seconds),
                });
            }
        }

        // Set module config directory with platform-specific defaults
        let default_config = TomlConfig::default();
        let default_rulesets = default_config.rulesets.as_ref().unwrap();
        let rulesets = self.rulesets.as_ref().unwrap_or(default_rulesets);
        if rulesets.enabled {
            heuristic_config.module_config_dir = Some(rulesets.config_dir.clone());
        }

        Ok(heuristic_config)
    }
}
