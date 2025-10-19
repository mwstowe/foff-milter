pub mod module_loader;
pub mod toml_config;

use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct Config {
    pub server: ServerConfig,
    pub detection: DetectionConfig,
    pub actions: ActionsConfig,
    pub statistics: Option<StatisticsConfig>,
    pub logging: Option<LoggingConfig>,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct ServerConfig {
    pub socket_path: String,
    pub timeout_seconds: Option<u64>,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct DetectionConfig {
    pub config_dir: String,
    pub enabled_modules: Vec<String>,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct ActionsConfig {
    pub default_action: String,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct StatisticsConfig {
    pub enabled: bool,
    pub database_path: String,
    pub flush_interval_seconds: Option<u64>,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct LoggingConfig {
    pub level: String,
    pub syslog: Option<bool>,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            server: ServerConfig {
                socket_path: "/var/run/foff-milter.sock".to_string(),
                timeout_seconds: Some(30),
            },
            detection: DetectionConfig {
                config_dir: "configs".to_string(),
                enabled_modules: vec![
                    "suspicious-domains".to_string(),
                    "brand-impersonation".to_string(),
                    "health-spam".to_string(),
                    "phishing-scams".to_string(),
                    "adult-content".to_string(),
                    "ecommerce-scams".to_string(),
                ],
            },
            actions: ActionsConfig {
                default_action: "Accept".to_string(),
            },
            statistics: Some(StatisticsConfig {
                enabled: true,
                database_path: "/var/lib/foff-milter/stats.db".to_string(),
                flush_interval_seconds: Some(60),
            }),
            logging: Some(LoggingConfig {
                level: "info".to_string(),
                syslog: Some(true),
            }),
        }
    }
}
