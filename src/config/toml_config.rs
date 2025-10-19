use super::Config;
use anyhow::{Context, Result};
use std::fs;
use std::path::Path;

pub fn load_config<P: AsRef<Path>>(path: P) -> Result<Config> {
    let content = fs::read_to_string(&path)
        .with_context(|| format!("Failed to read config file: {}", path.as_ref().display()))?;
    
    let config: Config = toml::from_str(&content)
        .with_context(|| format!("Failed to parse TOML config: {}", path.as_ref().display()))?;
    
    Ok(config)
}

pub fn load_config_or_default<P: AsRef<Path>>(path: P) -> Config {
    match load_config(&path) {
        Ok(config) => {
            log::info!("Loaded configuration from: {}", path.as_ref().display());
            config
        }
        Err(e) => {
            log::warn!("Failed to load config ({}), using defaults", e);
            Config::default()
        }
    }
}
