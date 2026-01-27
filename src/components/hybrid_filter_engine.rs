//! Hybrid Filter Engine
//!
//! Supports both original and simplified architectures with feature flag control.
//! Allows gradual rollout and A/B testing of the new component system.

use crate::components::filter_engine_v2::FilterEngineV2;
use crate::filter::FilterEngine;
use crate::heuristic_config::{Action, Config};
use crate::toml_config::TomlConfig;
use crate::MailContext;

pub struct HybridFilterEngine {
    original_engine: FilterEngine,
    simplified_engine: Option<FilterEngineV2>,
    use_simplified: bool,
}

impl HybridFilterEngine {
    pub fn new(config: Config, toml_config: Option<TomlConfig>) -> anyhow::Result<Self> {
        // Always create the original engine
        let original_engine = FilterEngine::new(config)?;

        // Check if simplified architecture is enabled
        let use_simplified = toml_config
            .as_ref()
            .and_then(|c| c.system.as_ref())
            .map(|s| s.use_simplified_architecture)
            .unwrap_or(false);

        // Create simplified engine if enabled
        let simplified_engine = if use_simplified {
            Some(FilterEngineV2::new())
        } else {
            None
        };

        log::info!(
            "HybridFilterEngine initialized - using {} architecture",
            if use_simplified {
                "simplified"
            } else {
                "original"
            }
        );

        Ok(Self {
            original_engine,
            simplified_engine,
            use_simplified,
        })
    }

    /// Evaluate email using the configured architecture
    pub async fn evaluate(
        &self,
        context: &MailContext,
    ) -> (Action, Vec<String>, Vec<(String, String)>) {
        if self.use_simplified {
            if let Some(ref simplified_engine) = self.simplified_engine {
                log::debug!("Using simplified architecture for evaluation");
                simplified_engine.evaluate_v2(context).await
            } else {
                log::warn!(
                    "Simplified architecture requested but not available, falling back to original"
                );
                self.original_engine.evaluate(context).await
            }
        } else {
            log::debug!("Using original architecture for evaluation");
            self.original_engine.evaluate(context).await
        }
    }

    /// Get architecture information for debugging
    pub fn get_architecture_info(&self) -> String {
        if self.use_simplified {
            "Simplified Component Architecture".to_string()
        } else {
            "Original Monolithic Architecture".to_string()
        }
    }

    /// Switch architecture at runtime (for testing)
    pub fn switch_architecture(&mut self, use_simplified: bool) {
        if use_simplified && self.simplified_engine.is_none() {
            self.simplified_engine = Some(FilterEngineV2::new());
        }
        self.use_simplified = use_simplified;
        log::info!(
            "Switched to {} architecture",
            if use_simplified {
                "simplified"
            } else {
                "original"
            }
        );
    }

    /// Get performance metrics for comparison
    pub fn get_performance_metrics(&self) -> PerformanceMetrics {
        PerformanceMetrics {
            architecture: self.get_architecture_info(),
            components_loaded: if self.use_simplified { 6 } else { 38 }, // Simplified has 6 components vs 38 modules
            memory_efficient: self.use_simplified,
        }
    }
}

#[derive(Debug, Clone)]
pub struct PerformanceMetrics {
    pub architecture: String,
    pub components_loaded: usize,
    pub memory_efficient: bool,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::heuristic_config::Config;
    use std::collections::HashMap;

    fn create_test_config() -> Config {
        Config {
            module_config_dir: Some("./rulesets".to_string()),
            ..Default::default()
        }
    }

    fn create_test_context() -> MailContext {
        MailContext {
            sender: Some("test@example.com".to_string()),
            from_header: Some("test@example.com".to_string()),
            recipients: vec!["recipient@example.com".to_string()],
            headers: HashMap::new(),
            mailer: None,
            subject: Some("Test".to_string()),
            hostname: None,
            helo: None,
            body: Some("Test body".to_string()),
            last_header_name: None,
            attachments: Vec::new(),
            extracted_media_text: String::new(),
            is_legitimate_business: false,
            is_first_hop: true,
            forwarding_source: None,
            forwarding_info: None,
            proximate_mailer: None,
            normalized: None,
            dkim_verification: None,
            trusted_esp: None,
        }
    }

    #[tokio::test]
    async fn test_original_architecture() {
        let config = create_test_config();
        let engine = HybridFilterEngine::new(config, None).unwrap();
        let context = create_test_context();

        let (_action, _rules, headers) = engine.evaluate(&context).await;

        // Should use original architecture
        assert_eq!(
            engine.get_architecture_info(),
            "Original Monolithic Architecture"
        );
        assert!(!headers.iter().any(|(name, _)| name == "X-FOFF-Score-V2"));
    }

    #[tokio::test]
    async fn test_simplified_architecture() {
        let config = create_test_config();
        let mut toml_config = TomlConfig::default();
        toml_config.system = Some(crate::toml_config::SystemConfig {
            socket_path: "/tmp/test.sock".to_string(),
            reject_to_tag: true,
            use_simplified_architecture: true,
        });

        let engine = HybridFilterEngine::new(config, Some(toml_config)).unwrap();
        let context = create_test_context();

        let (_action, _rules, headers) = engine.evaluate(&context).await;

        // Should use simplified architecture
        assert_eq!(
            engine.get_architecture_info(),
            "Simplified Component Architecture"
        );
        assert!(headers.iter().any(|(name, _)| name == "X-FOFF-Score-V2"));
    }

    #[test]
    fn test_architecture_switching() {
        let config = create_test_config();
        let mut engine = HybridFilterEngine::new(config, None).unwrap();

        // Start with original
        assert_eq!(
            engine.get_architecture_info(),
            "Original Monolithic Architecture"
        );

        // Switch to simplified
        engine.switch_architecture(true);
        assert_eq!(
            engine.get_architecture_info(),
            "Simplified Component Architecture"
        );

        // Switch back to original
        engine.switch_architecture(false);
        assert_eq!(
            engine.get_architecture_info(),
            "Original Monolithic Architecture"
        );
    }
}
