use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use crate::filter::FilterEngine;

#[derive(Debug, Serialize, Deserialize)]
pub struct ParityReport {
    pub environment: String,
    pub timestamp: String,
    pub version: String,
    pub config_hash: String,
    pub modules_loaded: u32,
    pub module_checksums: HashMap<String, String>,
    pub thresholds: ThresholdConfig,
    pub sample_scores: Vec<SampleScore>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ThresholdConfig {
    pub spam_threshold: i32,
    pub reject_threshold: i32,
    pub accept_threshold: i32,
    pub reject_to_tag: bool,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SampleScore {
    pub test_name: String,
    pub score: i32,
    pub rules_triggered: Vec<String>,
    pub final_action: String,
}

impl FilterEngine {
    pub fn generate_parity_report(&self, environment: &str) -> ParityReport {
        let sample_emails = [
            ("seo_spam", "Business slowing down? How are your rankings on Google?"),
            ("dating_spam", "Date Easy with English Speaking Ukrainian Girls"),
            ("jump_starter", "Today Only Free Schumacher Jump Starter"),
        ];

        let mut sample_scores = Vec::new();
        for (name, subject) in &sample_emails {
            // Create minimal test context
            let context = crate::filter::MailContext {
                subject: Some(subject.to_string()),
                sender: Some("test@example.com".to_string()),
                body: Some(format!("Test email: {}", subject)),
                ..Default::default()
            };
            
            let (action, rules, _) = self.evaluate_email(&context);
            sample_scores.push(SampleScore {
                test_name: name.to_string(),
                score: self.calculate_score(&context),
                rules_triggered: rules,
                final_action: format!("{:?}", action),
            });
        }

        ParityReport {
            environment: environment.to_string(),
            timestamp: chrono::Utc::now().to_rfc3339(),
            version: env!("CARGO_PKG_VERSION").to_string(),
            config_hash: self.get_config_hash(),
            modules_loaded: self.modules.len() as u32,
            module_checksums: self.get_module_checksums(),
            thresholds: ThresholdConfig {
                spam_threshold: self.config.heuristics.spam_threshold,
                reject_threshold: self.config.heuristics.reject_threshold,
                accept_threshold: self.config.heuristics.accept_threshold,
                reject_to_tag: self.config.system.reject_to_tag,
            },
            sample_scores,
        }
    }

    fn get_config_hash(&self) -> String {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};
        
        let mut hasher = DefaultHasher::new();
        format!("{:?}", self.config).hash(&mut hasher);
        format!("{:x}", hasher.finish())
    }

    fn get_module_checksums(&self) -> HashMap<String, String> {
        let mut checksums = HashMap::new();
        for module in &self.modules {
            checksums.insert(
                module.name.clone(),
                format!("{:x}", module.rules.len() * 1000 + module.enabled as usize)
            );
        }
        checksums
    }

    fn calculate_score(&self, context: &crate::filter::MailContext) -> i32 {
        // Simplified scoring for parity check
        let mut score = 0;
        for module in &self.modules {
            if module.enabled {
                score += module.rules.len() as i32;
            }
        }
        score
    }
}
