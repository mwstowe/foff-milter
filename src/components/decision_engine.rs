//! Decision Engine Component
//!
//! Handles threshold evaluation and final action determination based on
//! accumulated scores and component recommendations.

use crate::components::{ComponentAction, ComponentResult};
use crate::heuristic_config::Action;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DecisionConfig {
    pub reject_threshold: i32,
    pub spam_threshold: i32,
    pub accept_threshold: i32,
    pub reject_to_tag: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FinalDecision {
    pub action: Action,
    pub total_score: i32,
    pub confidence: f32,
    pub reasoning: String,
    pub contributing_components: Vec<String>,
}

pub struct DecisionEngine {
    config: DecisionConfig,
}

impl DecisionEngine {
    pub fn new(config: DecisionConfig) -> Self {
        Self { config }
    }

    /// Make final decision based on component results
    pub fn make_decision(&self, component_results: &[ComponentResult]) -> FinalDecision {
        // Check for early decision recommendations
        if let Some(early_decision) = self.check_early_decisions(component_results) {
            return early_decision;
        }

        // Calculate total score and weighted confidence
        let (total_score, weighted_confidence) = self.calculate_scores(component_results);

        // Determine action based on thresholds
        let action = self.determine_action(total_score);

        // Build reasoning
        let reasoning = self.build_reasoning(total_score, &action, component_results);

        // Collect contributing components
        let contributing_components = component_results
            .iter()
            .filter(|r| r.score != 0)
            .map(|r| format!("{}: {}", r.component_name, r.score))
            .collect();

        FinalDecision {
            action,
            total_score,
            confidence: weighted_confidence,
            reasoning,
            contributing_components,
        }
    }

    /// Check for early decision recommendations from components
    fn check_early_decisions(&self, results: &[ComponentResult]) -> Option<FinalDecision> {
        // Look for high-priority definitive recommendations
        for result in results {
            if let Some(action) = &result.action_recommended {
                match action {
                    ComponentAction::Accept => {
                        if result.confidence > 0.9 && result.score < -100 {
                            return Some(FinalDecision {
                                action: Action::Accept,
                                total_score: result.score,
                                confidence: result.confidence,
                                reasoning: format!(
                                    "Early accept by {}: {}",
                                    result.component_name,
                                    result.evidence.join("; ")
                                ),
                                contributing_components: vec![result.component_name.clone()],
                            });
                        }
                    }
                    ComponentAction::Reject => {
                        if result.confidence > 0.9 && result.score > 200 {
                            let action = if self.config.reject_to_tag {
                                Action::TagAsSpam {
                                    header_name: "X-Spam-Flag".to_string(),
                                    header_value: "YES".to_string(),
                                }
                            } else {
                                Action::Reject {
                                    message: "Message rejected by security policy".to_string(),
                                }
                            };

                            return Some(FinalDecision {
                                action,
                                total_score: result.score,
                                confidence: result.confidence,
                                reasoning: format!(
                                    "Early reject by {}: {}",
                                    result.component_name,
                                    result.evidence.join("; ")
                                ),
                                contributing_components: vec![result.component_name.clone()],
                            });
                        }
                    }
                    _ => continue,
                }
            }
        }

        None
    }

    /// Calculate total score and weighted confidence
    fn calculate_scores(&self, results: &[ComponentResult]) -> (i32, f32) {
        let total_score: i32 = results.iter().map(|r| r.score).sum();

        // Calculate weighted confidence based on contributing components
        let mut total_weight = 0.0;
        let mut weighted_sum = 0.0;

        for result in results {
            if result.score != 0 {
                let weight = result.confidence * (result.score.abs() as f32);
                weighted_sum += result.confidence * weight;
                total_weight += weight;
            }
        }

        let weighted_confidence = if total_weight > 0.0 {
            weighted_sum / total_weight
        } else {
            0.5 // Default confidence when no components contribute
        };

        (total_score, weighted_confidence)
    }

    /// Determine action based on score thresholds
    fn determine_action(&self, total_score: i32) -> Action {
        if total_score >= self.config.reject_threshold {
            if self.config.reject_to_tag {
                Action::TagAsSpam {
                    header_name: "X-Spam-Flag".to_string(),
                    header_value: "YES".to_string(),
                }
            } else {
                Action::Reject {
                    message: "Message rejected due to high threat score".to_string(),
                }
            }
        } else if total_score >= self.config.spam_threshold {
            Action::TagAsSpam {
                header_name: "X-Spam-Flag".to_string(),
                header_value: "YES".to_string(),
            }
        } else {
            Action::Accept
        }
    }

    /// Build human-readable reasoning for the decision
    fn build_reasoning(
        &self,
        total_score: i32,
        action: &Action,
        results: &[ComponentResult],
    ) -> String {
        let action_str = match action {
            Action::Accept => "ACCEPT",
            Action::TagAsSpam { .. } => "TAG AS SPAM",
            Action::Reject { .. } => "REJECT",
            Action::ReportAbuse { .. } => "REPORT ABUSE",
            Action::UnsubscribeGoogleGroup { .. } => "UNSUBSCRIBE",
        };

        let threshold_info = match total_score {
            score if score >= self.config.reject_threshold => format!(
                "Score {} >= reject threshold {}",
                score, self.config.reject_threshold
            ),
            score if score >= self.config.spam_threshold => format!(
                "Score {} >= spam threshold {}",
                score, self.config.spam_threshold
            ),
            score => format!(
                "Score {} < spam threshold {}",
                score, self.config.spam_threshold
            ),
        };

        let top_contributors: Vec<String> = results
            .iter()
            .filter(|r| r.score.abs() > 10) // Only significant contributors
            .map(|r| format!("{} ({})", r.component_name, r.score))
            .collect();

        if top_contributors.is_empty() {
            format!(
                "{}: {} - No significant threats detected",
                action_str, threshold_info
            )
        } else {
            format!(
                "{}: {} - Key factors: {}",
                action_str,
                threshold_info,
                top_contributors.join(", ")
            )
        }
    }

    /// Update configuration
    pub fn update_config(&mut self, config: DecisionConfig) {
        self.config = config;
    }

    /// Get current configuration
    pub fn get_config(&self) -> &DecisionConfig {
        &self.config
    }
}

impl Default for DecisionEngine {
    fn default() -> Self {
        Self::new(DecisionConfig {
            reject_threshold: 350,
            spam_threshold: 50,
            accept_threshold: 0,
            reject_to_tag: true,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::components::ComponentAction;

    #[test]
    fn test_decision_thresholds() {
        let engine = DecisionEngine::default();

        // Test accept decision
        let low_score_result = ComponentResult {
            component_name: "Test".to_string(),
            score: 10,
            confidence: 0.8,
            evidence: vec!["Low threat".to_string()],
            action_recommended: Some(ComponentAction::Continue),
        };

        let decision = engine.make_decision(&[low_score_result]);
        assert!(matches!(decision.action, Action::Accept));

        // Test spam decision
        let medium_score_result = ComponentResult {
            component_name: "Test".to_string(),
            score: 75,
            confidence: 0.8,
            evidence: vec!["Medium threat".to_string()],
            action_recommended: Some(ComponentAction::Continue),
        };

        let decision = engine.make_decision(&[medium_score_result]);
        assert!(matches!(decision.action, Action::TagAsSpam { .. }));
    }

    #[test]
    fn test_early_decisions() {
        let engine = DecisionEngine::default();

        let early_reject_result = ComponentResult {
            component_name: "EarlyDecision".to_string(),
            score: 500,
            confidence: 0.95,
            evidence: vec!["Definitive threat".to_string()],
            action_recommended: Some(ComponentAction::Reject),
        };

        let decision = engine.make_decision(&[early_reject_result]);
        assert!(matches!(decision.action, Action::TagAsSpam { .. })); // Due to reject_to_tag
        assert_eq!(decision.contributing_components.len(), 1);
    }
}
