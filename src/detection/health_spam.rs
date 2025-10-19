use super::DetectionResult;
use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct HealthSpamConfig {
    pub patterns: HealthPatterns,
    pub legitimate_exclusions: LegitimateExclusions,
    pub severity_levels: SeverityLevels,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct HealthPatterns {
    pub respiratory: Vec<String>,
    pub pharmaceutical: Vec<String>,
    pub conspiracy: Vec<String>,
    pub general_health: Vec<String>,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct LegitimateExclusions {
    pub medical_organizations: Vec<String>,
    pub news_organizations: Vec<String>,
    pub health_services: Vec<String>,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct SeverityLevels {
    pub critical: SeverityLevel,
    pub high: SeverityLevel,
    pub medium: SeverityLevel,
    pub low: SeverityLevel,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct SeverityLevel {
    pub patterns: Vec<String>,
    pub confidence: u32,
}

pub struct HealthSpamDetector {
    config: HealthSpamConfig,
}

impl HealthSpamDetector {
    pub fn new(config: HealthSpamConfig) -> Self {
        Self { config }
    }

    pub fn load_from_file(path: &str) -> Result<Self, Box<dyn std::error::Error>> {
        let content = std::fs::read_to_string(path)?;
        let config: HealthSpamConfig = serde_yml::from_str(&content)?;
        Ok(Self::new(config))
    }

    pub fn check_health_spam(
        &self,
        subject: &str,
        body: &str,
        sender_domain: &str,
    ) -> DetectionResult {
        // Check if sender is from legitimate organization
        if self.is_legitimate_sender(sender_domain) {
            return DetectionResult::no_match("HealthSpam".to_string());
        }

        let mut confidence = 0;
        let mut reasons = Vec::new();
        let combined_text = format!("{} {}", subject, body).to_lowercase();

        // Check severity levels in order (critical first)
        let severity_checks = [
            ("critical", &self.config.severity_levels.critical),
            ("high", &self.config.severity_levels.high),
            ("medium", &self.config.severity_levels.medium),
            ("low", &self.config.severity_levels.low),
        ];

        for (severity_name, severity_level) in severity_checks.iter() {
            for pattern in &severity_level.patterns {
                if combined_text.contains(pattern) {
                    confidence += severity_level.confidence;
                    reasons.push(format!("{} severity: {}", severity_name, pattern));
                    // Only count highest severity match
                    break;
                }
            }
            if !reasons.is_empty() {
                break;
            }
        }

        // Check category patterns if no severity match
        if reasons.is_empty() {
            let categories = [
                ("respiratory", &self.config.patterns.respiratory),
                ("pharmaceutical", &self.config.patterns.pharmaceutical),
                ("conspiracy", &self.config.patterns.conspiracy),
                ("general_health", &self.config.patterns.general_health),
            ];

            for (category_name, patterns) in categories.iter() {
                for pattern in patterns.iter() {
                    if combined_text.contains(pattern) {
                        confidence += 20; // Default confidence for category matches
                        reasons.push(format!("{} pattern: {}", category_name, pattern));
                        break;
                    }
                }
            }
        }

        let matched = confidence > 0;
        let reason = if reasons.is_empty() {
            "No health spam indicators".to_string()
        } else {
            reasons.join(", ")
        };

        DetectionResult::new(matched, confidence, reason, "HealthSpam".to_string())
    }

    fn is_legitimate_sender(&self, domain: &str) -> bool {
        let all_legitimate = [
            &self.config.legitimate_exclusions.medical_organizations,
            &self.config.legitimate_exclusions.news_organizations,
            &self.config.legitimate_exclusions.health_services,
        ];

        for legitimate_list in all_legitimate.iter() {
            for legitimate_domain in legitimate_list.iter() {
                if domain.ends_with(legitimate_domain) {
                    return true;
                }
            }
        }

        false
    }

    pub fn get_all_patterns(&self) -> Vec<String> {
        let mut patterns = Vec::new();
        patterns.extend(self.config.patterns.respiratory.clone());
        patterns.extend(self.config.patterns.pharmaceutical.clone());
        patterns.extend(self.config.patterns.conspiracy.clone());
        patterns.extend(self.config.patterns.general_health.clone());

        // Add severity level patterns
        patterns.extend(self.config.severity_levels.critical.patterns.clone());
        patterns.extend(self.config.severity_levels.high.patterns.clone());
        patterns.extend(self.config.severity_levels.medium.patterns.clone());
        patterns.extend(self.config.severity_levels.low.patterns.clone());

        patterns.sort();
        patterns.dedup();
        patterns
    }
}
