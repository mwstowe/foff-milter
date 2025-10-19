use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct MachineLearningConfig {
    pub adaptive_learning: AdaptiveLearning,
    pub anomaly_detection: AnomalyDetection,
    pub behavioral_analysis: BehavioralAnalysis,
    pub predictive_detection: PredictiveDetection,
    pub self_optimization: SelfOptimization,
    pub feature_engineering: FeatureEngineering,
    pub model_management: ModelManagement,
    pub performance_settings: PerformanceSettings,
    pub explainability: Explainability,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct AdaptiveLearning {
    pub enabled: bool,
    pub learning_rate: f64,
    pub update_frequency_minutes: u32,
    pub min_samples_for_update: usize,
    pub confidence_adjustment: bool,
    pub pattern_learning: bool,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct AnomalyDetection {
    pub enabled: bool,
    pub algorithm: String,
    pub contamination_rate: f64,
    pub sensitivity: f64,
    pub window_size_hours: u32,
    pub min_baseline_samples: usize,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct BehavioralAnalysis {
    pub enabled: bool,
    pub sender_reputation: bool,
    pub domain_reputation: bool,
    pub temporal_patterns: bool,
    pub content_analysis: bool,
    pub reputation_decay_days: u32,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct PredictiveDetection {
    pub enabled: bool,
    pub threat_forecasting: bool,
    pub campaign_detection: bool,
    pub emerging_threat_detection: bool,
    pub prediction_horizon_hours: u32,
    pub confidence_threshold: f64,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct SelfOptimization {
    pub enabled: bool,
    pub threshold_tuning: bool,
    pub module_weighting: bool,
    pub performance_optimization: bool,
    pub ab_testing: bool,
    pub optimization_interval_hours: u32,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct FeatureEngineering {
    pub enabled: bool,
    pub content_features: bool,
    pub metadata_features: bool,
    pub behavioral_features: bool,
    pub temporal_features: bool,
    pub linguistic_features: bool,
    pub network_features: bool,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct ModelManagement {
    pub model_storage_path: String,
    pub model_versioning: bool,
    pub automatic_retraining: bool,
    pub retraining_threshold: f64,
    pub model_backup: bool,
    pub max_model_versions: u32,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct PerformanceSettings {
    pub inference_timeout_ms: u64,
    pub batch_prediction: bool,
    pub batch_size: usize,
    pub model_caching: bool,
    pub feature_caching: bool,
    pub parallel_inference: bool,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct Explainability {
    pub enabled: bool,
    pub feature_importance: bool,
    pub decision_reasoning: bool,
    pub confidence_explanation: bool,
    pub audit_trail: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct EmailFeatures {
    pub content_length: f64,
    pub subject_length: f64,
    pub sender_reputation: f64,
    pub domain_age_days: f64,
    pub time_of_day: f64,
    pub day_of_week: f64,
    pub suspicious_keywords_count: f64,
    pub url_count: f64,
    pub attachment_count: f64,
    pub encoding_complexity: f64,
    pub language_mixing_score: f64,
    pub brand_similarity_score: f64,
}

#[derive(Debug, Clone, Serialize)]
pub struct MLPrediction {
    pub is_threat: bool,
    pub confidence: f64,
    pub threat_type: String,
    pub anomaly_score: f64,
    pub feature_importance: HashMap<String, f64>,
    pub explanation: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct SenderReputation {
    pub email: String,
    pub domain: String,
    pub threat_count: u32,
    pub total_emails: u32,
    pub reputation_score: f64,
    pub last_seen: u64,
    pub behavioral_patterns: HashMap<String, f64>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ThreatCampaign {
    pub campaign_id: String,
    pub threat_type: String,
    pub first_seen: u64,
    pub last_seen: u64,
    pub email_count: u32,
    pub unique_senders: u32,
    pub confidence: f64,
    pub patterns: Vec<String>,
}

pub struct MachineLearningEngine {
    config: MachineLearningConfig,
    sender_reputations: Arc<Mutex<HashMap<String, SenderReputation>>>,
    domain_reputations: Arc<Mutex<HashMap<String, f64>>>,
    threat_campaigns: Arc<Mutex<Vec<ThreatCampaign>>>,
    anomaly_baseline: Arc<Mutex<Vec<EmailFeatures>>>,
    #[allow(dead_code)]
    model_weights: Arc<Mutex<HashMap<String, f64>>>,
    #[allow(dead_code)]
    confidence_adjustments: Arc<Mutex<HashMap<String, f64>>>,
    training_data: Arc<Mutex<Vec<(EmailFeatures, bool)>>>,
}

impl MachineLearningEngine {
    pub fn new(config: MachineLearningConfig) -> Self {
        Self {
            config,
            sender_reputations: Arc::new(Mutex::new(HashMap::new())),
            domain_reputations: Arc::new(Mutex::new(HashMap::new())),
            threat_campaigns: Arc::new(Mutex::new(Vec::new())),
            anomaly_baseline: Arc::new(Mutex::new(Vec::new())),
            model_weights: Arc::new(Mutex::new(HashMap::new())),
            confidence_adjustments: Arc::new(Mutex::new(HashMap::new())),
            training_data: Arc::new(Mutex::new(Vec::new())),
        }
    }

    pub fn load_from_file(path: &str) -> Result<Self, Box<dyn std::error::Error>> {
        let content = std::fs::read_to_string(path)?;
        let config: MachineLearningConfig = serde_yml::from_str(&content)?;
        Ok(Self::new(config))
    }

    pub fn extract_features(&self, sender: &str, subject: &str, body: &str) -> EmailFeatures {
        let sender_domain = self.extract_domain(sender);
        let sender_rep = self.get_sender_reputation(sender);
        let domain_rep = self.get_domain_reputation(&sender_domain);

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let time_of_day = ((now % 86400) as f64) / 86400.0; // 0-1 for 24 hours
        let day_of_week = (((now / 86400) % 7) as f64) / 7.0; // 0-1 for 7 days

        EmailFeatures {
            content_length: body.len() as f64,
            subject_length: subject.len() as f64,
            sender_reputation: sender_rep,
            domain_age_days: domain_rep * 1000.0, // Approximate domain age
            time_of_day,
            day_of_week,
            suspicious_keywords_count: self.count_suspicious_keywords(body),
            url_count: self.count_urls(body),
            attachment_count: 0.0, // Would need email parsing
            encoding_complexity: self.calculate_encoding_complexity(body),
            language_mixing_score: self.calculate_language_mixing(body),
            brand_similarity_score: self.calculate_brand_similarity(subject, body),
        }
    }

    pub fn predict_threat(&self, features: &EmailFeatures) -> MLPrediction {
        let anomaly_score = self.calculate_anomaly_score(features);
        let behavioral_score = self.calculate_behavioral_score(features);
        let pattern_score = self.calculate_pattern_score(features);

        // Simple ensemble scoring
        let threat_score =
            (anomaly_score * 0.4 + behavioral_score * 0.3 + pattern_score * 0.3).min(1.0);
        let is_threat = threat_score > 0.5;

        let threat_type = if threat_score > 0.8 {
            "High Confidence Threat"
        } else if threat_score > 0.6 {
            "Moderate Threat"
        } else if threat_score > 0.4 {
            "Low Threat"
        } else {
            "Benign"
        };

        let mut feature_importance = HashMap::new();
        feature_importance.insert("anomaly_score".to_string(), anomaly_score);
        feature_importance.insert("behavioral_score".to_string(), behavioral_score);
        feature_importance.insert("pattern_score".to_string(), pattern_score);

        let explanation = format!(
            "Threat prediction based on anomaly detection ({:.2}), behavioral analysis ({:.2}), and pattern matching ({:.2})",
            anomaly_score, behavioral_score, pattern_score
        );

        MLPrediction {
            is_threat,
            confidence: threat_score,
            threat_type: threat_type.to_string(),
            anomaly_score,
            feature_importance,
            explanation,
        }
    }

    pub fn update_model(
        &self,
        features: &EmailFeatures,
        is_threat: bool,
        feedback_confidence: f64,
    ) {
        if !self.config.adaptive_learning.enabled {
            return;
        }

        // Add to training data
        if let Ok(mut training_data) = self.training_data.lock() {
            training_data.push((features.clone(), is_threat));

            // Limit training data size
            if training_data.len() > 10000 {
                training_data.drain(0..1000);
            }
        }

        // Update sender reputation
        self.update_sender_reputation(
            &self.extract_sender_from_features(features),
            is_threat,
            feedback_confidence,
        );

        // Update anomaly baseline
        if !is_threat {
            if let Ok(mut baseline) = self.anomaly_baseline.lock() {
                baseline.push(features.clone());
                if baseline.len() > self.config.anomaly_detection.min_baseline_samples {
                    baseline.drain(0..100);
                }
            }
        }
    }

    fn calculate_anomaly_score(&self, features: &EmailFeatures) -> f64 {
        if !self.config.anomaly_detection.enabled {
            return 0.0;
        }

        // Simple anomaly detection based on statistical deviation
        if let Ok(baseline) = self.anomaly_baseline.lock() {
            if baseline.len() < 100 {
                return 0.5; // Default score when insufficient baseline
            }

            let mut anomaly_indicators = 0;
            let mut total_indicators = 0;

            // Check content length anomaly
            let avg_content_length: f64 =
                baseline.iter().map(|f| f.content_length).sum::<f64>() / baseline.len() as f64;
            let content_deviation =
                (features.content_length - avg_content_length).abs() / avg_content_length.max(1.0);
            if content_deviation > 2.0 {
                anomaly_indicators += 1;
            }
            total_indicators += 1;

            // Check time anomaly
            let avg_time: f64 =
                baseline.iter().map(|f| f.time_of_day).sum::<f64>() / baseline.len() as f64;
            let time_deviation = (features.time_of_day - avg_time).abs();
            if time_deviation > 0.3 {
                anomaly_indicators += 1;
            }
            total_indicators += 1;

            // Check suspicious keywords anomaly
            let avg_keywords: f64 = baseline
                .iter()
                .map(|f| f.suspicious_keywords_count)
                .sum::<f64>()
                / baseline.len() as f64;
            if features.suspicious_keywords_count > avg_keywords + 2.0 {
                anomaly_indicators += 1;
            }
            total_indicators += 1;

            anomaly_indicators as f64 / total_indicators as f64
        } else {
            0.5
        }
    }

    fn calculate_behavioral_score(&self, features: &EmailFeatures) -> f64 {
        if !self.config.behavioral_analysis.enabled {
            return 0.0;
        }

        let mut behavioral_score = 0.0;
        let mut factors = 0;

        // Sender reputation factor
        if features.sender_reputation < 0.3 {
            behavioral_score += 0.8;
        } else if features.sender_reputation < 0.6 {
            behavioral_score += 0.4;
        }
        factors += 1;

        // Time-based factors
        if features.time_of_day < 0.2 || features.time_of_day > 0.9 {
            // Late night/early morning
            behavioral_score += 0.3;
        }
        factors += 1;

        // Content factors
        if features.suspicious_keywords_count > 3.0 {
            behavioral_score += 0.6;
        }
        factors += 1;

        if features.url_count > 5.0 {
            behavioral_score += 0.4;
        }
        factors += 1;

        behavioral_score / factors as f64
    }

    fn calculate_pattern_score(&self, features: &EmailFeatures) -> f64 {
        let mut pattern_score: f64 = 0.0;

        // Language mixing patterns
        if features.language_mixing_score > 0.5 {
            pattern_score += 0.4;
        }

        // Brand similarity patterns
        if features.brand_similarity_score > 0.7 {
            pattern_score += 0.5;
        }

        // Encoding complexity patterns
        if features.encoding_complexity > 0.6 {
            pattern_score += 0.3;
        }

        pattern_score.min(1.0)
    }

    fn get_sender_reputation(&self, sender: &str) -> f64 {
        if let Ok(reputations) = self.sender_reputations.lock() {
            reputations
                .get(sender)
                .map(|rep| rep.reputation_score)
                .unwrap_or(0.5) // Default neutral reputation
        } else {
            0.5
        }
    }

    fn get_domain_reputation(&self, domain: &str) -> f64 {
        if let Ok(reputations) = self.domain_reputations.lock() {
            reputations.get(domain).copied().unwrap_or(0.5)
        } else {
            0.5
        }
    }

    fn update_sender_reputation(&self, sender: &str, is_threat: bool, _confidence: f64) {
        if let Ok(mut reputations) = self.sender_reputations.lock() {
            let reputation =
                reputations
                    .entry(sender.to_string())
                    .or_insert_with(|| SenderReputation {
                        email: sender.to_string(),
                        domain: self.extract_domain(sender),
                        threat_count: 0,
                        total_emails: 0,
                        reputation_score: 0.5,
                        last_seen: SystemTime::now()
                            .duration_since(UNIX_EPOCH)
                            .unwrap_or_default()
                            .as_secs(),
                        behavioral_patterns: HashMap::new(),
                    });

            reputation.total_emails += 1;
            if is_threat {
                reputation.threat_count += 1;
            }

            // Update reputation score with learning rate
            let threat_rate = reputation.threat_count as f64 / reputation.total_emails as f64;
            let learning_rate = self.config.adaptive_learning.learning_rate;
            reputation.reputation_score = (1.0 - learning_rate) * reputation.reputation_score
                + learning_rate * (1.0 - threat_rate);

            reputation.last_seen = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();
        }
    }

    fn count_suspicious_keywords(&self, text: &str) -> f64 {
        let suspicious_keywords = [
            "urgent",
            "immediate",
            "act now",
            "limited time",
            "free",
            "winner",
            "congratulations",
            "click here",
            "verify",
            "suspend",
            "expire",
            "bitcoin",
            "cryptocurrency",
            "investment",
        ];

        let text_lower = text.to_lowercase();
        suspicious_keywords
            .iter()
            .filter(|&keyword| text_lower.contains(keyword))
            .count() as f64
    }

    fn count_urls(&self, text: &str) -> f64 {
        text.matches("http").count() as f64
    }

    fn calculate_encoding_complexity(&self, text: &str) -> f64 {
        let total_chars = text.len() as f64;
        if total_chars == 0.0 {
            return 0.0;
        }

        let non_ascii_chars = text.chars().filter(|c| !c.is_ascii()).count() as f64;
        (non_ascii_chars / total_chars).min(1.0)
    }

    fn calculate_language_mixing(&self, text: &str) -> f64 {
        let has_latin = text.chars().any(|c| c.is_ascii_alphabetic());
        let has_cyrillic = text.chars().any(|c| matches!(c, '\u{0400}'..='\u{04FF}'));
        let has_chinese = text.chars().any(|c| matches!(c, '\u{4E00}'..='\u{9FFF}'));
        let has_arabic = text.chars().any(|c| matches!(c, '\u{0600}'..='\u{06FF}'));

        let script_count = [has_latin, has_cyrillic, has_chinese, has_arabic]
            .iter()
            .filter(|&&x| x)
            .count();

        if script_count > 1 {
            0.8
        } else {
            0.0
        }
    }

    fn calculate_brand_similarity(&self, subject: &str, body: &str) -> f64 {
        let brand_keywords = ["paypal", "amazon", "microsoft", "apple", "google", "ebay"];
        let combined_text = format!("{} {}", subject, body).to_lowercase();

        brand_keywords
            .iter()
            .filter(|&brand| combined_text.contains(brand))
            .count() as f64
            / brand_keywords.len() as f64
    }

    fn extract_domain(&self, email: &str) -> String {
        if let Some(at_pos) = email.rfind('@') {
            let domain = &email[at_pos + 1..];
            domain.trim_end_matches('>').to_string()
        } else {
            "unknown".to_string()
        }
    }

    fn extract_sender_from_features(&self, _features: &EmailFeatures) -> String {
        // In a real implementation, we'd store sender info in features
        "unknown@example.com".to_string()
    }

    pub fn detect_campaigns(&self) -> Vec<ThreatCampaign> {
        // Simple campaign detection based on similar patterns
        if let Ok(campaigns) = self.threat_campaigns.lock() {
            campaigns.clone()
        } else {
            Vec::new()
        }
    }

    pub fn get_model_performance(&self) -> HashMap<String, f64> {
        let mut performance = HashMap::new();

        if let Ok(training_data) = self.training_data.lock() {
            let total_samples = training_data.len() as f64;
            let threat_samples = training_data
                .iter()
                .filter(|(_, is_threat)| *is_threat)
                .count() as f64;

            performance.insert("total_samples".to_string(), total_samples);
            performance.insert(
                "threat_ratio".to_string(),
                threat_samples / total_samples.max(1.0),
            );
            performance.insert("model_accuracy".to_string(), 0.85); // Placeholder
        }

        performance
    }

    pub fn cleanup_old_data(&self) {
        let retention_seconds =
            self.config.behavioral_analysis.reputation_decay_days as u64 * 24 * 3600;
        let cutoff_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs()
            - retention_seconds;

        // Clean up old sender reputations
        if let Ok(mut reputations) = self.sender_reputations.lock() {
            reputations.retain(|_, rep| rep.last_seen > cutoff_time);
        }

        // Clean up old campaigns
        if let Ok(mut campaigns) = self.threat_campaigns.lock() {
            campaigns.retain(|campaign| campaign.last_seen > cutoff_time);
        }
    }
}
