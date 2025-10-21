use serde::{Deserialize, Serialize};
use std::path::Path;
use crate::legacy_config::{Config as LegacyConfig, Action};

#[derive(Debug, Deserialize, Serialize)]
pub struct TomlConfig {
    pub system: SystemConfig,
    pub logging: Option<LoggingConfig>,
    pub statistics: Option<StatisticsConfig>,
    pub modules: Option<ModulesConfig>,
    pub heuristics: Option<HeuristicsConfig>,
    pub whitelist: Option<WhitelistConfig>,
    pub blocklist: Option<BlocklistConfig>,
    pub legacy: Option<LegacyConfigRef>,
    pub default_action: DefaultActionConfig,
    pub performance: Option<PerformanceConfig>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct SystemConfig {
    pub socket_path: String,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct LoggingConfig {
    pub level: String,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct StatisticsConfig {
    pub enabled: bool,
    pub database_path: String,
    pub flush_interval_seconds: u64,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct ModulesConfig {
    pub enabled: bool,
    pub config_dir: String,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct HeuristicsConfig {
    pub reject_threshold: i32,
    pub spam_threshold: i32,
    pub accept_threshold: i32,
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

#[derive(Debug, Deserialize, Serialize)]
pub struct LegacyConfigRef {
    pub enabled: bool,
    pub config_file: String,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct DefaultActionConfig {
    #[serde(rename = "type")]
    pub action_type: String,
}

#[derive(Debug, Deserialize, Serialize)]
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
            rule_set_timestamp: chrono::Utc::now().format("%Y-%m-%d %H:%M:%S UTC").to_string(),
        };

        // Set default action
        legacy_config.default_action = match self.default_action.action_type.as_str() {
            "Accept" => Action::Accept,
            "Reject" => Action::Reject { message: "Rejected by policy".to_string() },
            "TagAsSpam" => Action::TagAsSpam { 
                header_name: "X-Spam-Flag".to_string(), 
                header_value: "YES".to_string() 
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
        if let Some(modules) = &self.modules {
            if modules.enabled {
                legacy_config.module_config_dir = Some(modules.config_dir.clone());
            }
        }

        Ok(legacy_config)
    }
}
