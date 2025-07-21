use crate::config::{Action, Config, Criteria};
use crate::language::LanguageDetector;
use regex::Regex;
use std::collections::HashMap;

pub struct FilterEngine {
    config: Config,
    compiled_patterns: HashMap<String, Regex>,
}

#[derive(Debug, Default)]
pub struct MailContext {
    pub sender: Option<String>,
    pub recipients: Vec<String>,
    pub headers: HashMap<String, String>,
    pub mailer: Option<String>,
    pub subject: Option<String>,
}

impl FilterEngine {
    pub fn new(config: Config) -> anyhow::Result<Self> {
        let mut engine = FilterEngine {
            config,
            compiled_patterns: HashMap::new(),
        };
        
        // Pre-compile all regex patterns for better performance
        engine.compile_patterns()?;
        Ok(engine)
    }

    fn compile_patterns(&mut self) -> anyhow::Result<()> {
        let rules = self.config.rules.clone();
        for rule in &rules {
            self.compile_criteria_patterns(&rule.criteria)?;
        }
        Ok(())
    }

    fn compile_criteria_patterns(&mut self, criteria: &Criteria) -> anyhow::Result<()> {
        match criteria {
            Criteria::MailerPattern { pattern } |
            Criteria::SenderPattern { pattern } |
            Criteria::RecipientPattern { pattern } |
            Criteria::SubjectPattern { pattern } => {
                if !self.compiled_patterns.contains_key(pattern) {
                    let regex = Regex::new(pattern)
                        .map_err(|e| anyhow::anyhow!("Invalid regex pattern '{}': {}", pattern, e))?;
                    self.compiled_patterns.insert(pattern.clone(), regex);
                }
            }
            Criteria::HeaderPattern { pattern, .. } => {
                if !self.compiled_patterns.contains_key(pattern) {
                    let regex = Regex::new(pattern)
                        .map_err(|e| anyhow::anyhow!("Invalid regex pattern '{}': {}", pattern, e))?;
                    self.compiled_patterns.insert(pattern.clone(), regex);
                }
            }
            Criteria::SubjectContainsLanguage { language } => {
                // Validate that the language is supported
                if !matches!(language.to_lowercase().as_str(), 
                    "japanese" | "ja" | "chinese" | "zh" | "korean" | "ko" | 
                    "arabic" | "ar" | "russian" | "ru" | "thai" | "th" | "hebrew" | "he") {
                    return Err(anyhow::anyhow!("Unsupported language: {}", language));
                }
            }
            Criteria::HeaderContainsLanguage { language, .. } => {
                // Validate that the language is supported
                if !matches!(language.to_lowercase().as_str(), 
                    "japanese" | "ja" | "chinese" | "zh" | "korean" | "ko" | 
                    "arabic" | "ar" | "russian" | "ru" | "thai" | "th" | "hebrew" | "he") {
                    return Err(anyhow::anyhow!("Unsupported language: {}", language));
                }
            }
            Criteria::And { criteria } | Criteria::Or { criteria } => {
                for c in criteria {
                    self.compile_criteria_patterns(c)?;
                }
            }
        }
        Ok(())
    }

    pub fn evaluate(&self, context: &MailContext) -> &Action {
        for rule in &self.config.rules {
            if self.evaluate_criteria(&rule.criteria, context) {
                log::info!("Rule '{}' matched, applying action: {:?}", rule.name, rule.action);
                return &rule.action;
            }
        }
        
        log::debug!("No rules matched, using default action: {:?}", self.config.default_action);
        &self.config.default_action
    }

    fn evaluate_criteria(&self, criteria: &Criteria, context: &MailContext) -> bool {
        match criteria {
            Criteria::MailerPattern { pattern } => {
                if let Some(mailer) = &context.mailer {
                    if let Some(regex) = self.compiled_patterns.get(pattern) {
                        return regex.is_match(mailer);
                    }
                }
                false
            }
            Criteria::SenderPattern { pattern } => {
                if let Some(sender) = &context.sender {
                    if let Some(regex) = self.compiled_patterns.get(pattern) {
                        return regex.is_match(sender);
                    }
                }
                false
            }
            Criteria::RecipientPattern { pattern } => {
                if let Some(regex) = self.compiled_patterns.get(pattern) {
                    return context.recipients.iter().any(|recipient| regex.is_match(recipient));
                }
                false
            }
            Criteria::SubjectPattern { pattern } => {
                if let Some(subject) = &context.subject {
                    if let Some(regex) = self.compiled_patterns.get(pattern) {
                        return regex.is_match(subject);
                    }
                }
                false
            }
            Criteria::HeaderPattern { header, pattern } => {
                if let Some(header_value) = context.headers.get(header) {
                    if let Some(regex) = self.compiled_patterns.get(pattern) {
                        return regex.is_match(header_value);
                    }
                }
                false
            }
            Criteria::SubjectContainsLanguage { language } => {
                if let Some(subject) = &context.subject {
                    return LanguageDetector::contains_language(subject, language);
                }
                false
            }
            Criteria::HeaderContainsLanguage { header, language } => {
                if let Some(header_value) = context.headers.get(header) {
                    return LanguageDetector::contains_language(header_value, language);
                }
                false
            }
            Criteria::And { criteria } => {
                criteria.iter().all(|c| self.evaluate_criteria(c, context))
            }
            Criteria::Or { criteria } => {
                criteria.iter().any(|c| self.evaluate_criteria(c, context))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;

    #[test]
    fn test_mailer_pattern_matching() {
        let config = Config::default();
        let engine = FilterEngine::new(config).unwrap();
        
        let mut context = MailContext::default();
        context.mailer = Some("service.example.cn".to_string());
        
        let action = engine.evaluate(&context);
        match action {
            Action::Reject { .. } => assert!(true),
            _ => panic!("Expected reject action for suspicious Chinese service"),
        }
    }

    #[test]
    fn test_no_match_default_action() {
        let config = Config::default();
        let engine = FilterEngine::new(config).unwrap();
        
        let context = MailContext::default();
        let action = engine.evaluate(&context);
        
        match action {
            Action::Accept => assert!(true),
            _ => panic!("Expected default accept action"),
        }
    }

    #[test]
    fn test_combination_criteria() {
        use crate::config::{FilterRule, Action};
        
        // Create a config with combination criteria: sparkmail.com mailer AND Japanese in subject
        let mut config = Config::default();
        config.rules = vec![
            FilterRule {
                name: "Block Sparkmail with Japanese".to_string(),
                criteria: Criteria::And {
                    criteria: vec![
                        Criteria::MailerPattern {
                            pattern: r".*sparkmail\.com.*".to_string(),
                        },
                        Criteria::SubjectContainsLanguage {
                            language: "japanese".to_string(),
                        },
                    ],
                },
                action: Action::Reject {
                    message: "Sparkmail with Japanese content blocked".to_string(),
                },
            },
        ];
        
        let engine = FilterEngine::new(config).unwrap();
        
        // Test case 1: Both conditions match - should reject
        let mut context = MailContext::default();
        context.mailer = Some("sparkmail.com mailer v1.0".to_string());
        context.subject = Some("こんにちは - Special Offer".to_string()); // Contains Japanese
        
        let action = engine.evaluate(&context);
        match action {
            Action::Reject { .. } => assert!(true),
            _ => panic!("Expected reject action for sparkmail with Japanese"),
        }
        
        // Test case 2: Only mailer matches, no Japanese - should accept
        let mut context2 = MailContext::default();
        context2.mailer = Some("sparkmail.com mailer v1.0".to_string());
        context2.subject = Some("Regular English Subject".to_string());
        
        let action2 = engine.evaluate(&context2);
        match action2 {
            Action::Accept => assert!(true),
            _ => panic!("Expected accept action for sparkmail without Japanese"),
        }
        
        // Test case 3: Only Japanese matches, different mailer - should accept
        let mut context3 = MailContext::default();
        context3.mailer = Some("gmail.com".to_string());
        context3.subject = Some("こんにちは - Hello".to_string());
        
        let action3 = engine.evaluate(&context3);
        match action3 {
            Action::Accept => assert!(true),
            _ => panic!("Expected accept action for non-sparkmail with Japanese"),
        }
    }

    #[test]
    fn test_production_examples() {
        use crate::config::{FilterRule, Action};
        
        // Create config with the two production examples
        let mut config = Config::default();
        config.rules = vec![
            // Example 1: Chinese service with Japanese content
            FilterRule {
                name: "Block Chinese services with Japanese content".to_string(),
                criteria: Criteria::And {
                    criteria: vec![
                        Criteria::MailerPattern {
                            pattern: r"service\..*\.cn".to_string(),
                        },
                        Criteria::SubjectContainsLanguage {
                            language: "japanese".to_string(),
                        },
                    ],
                },
                action: Action::Reject {
                    message: "Chinese service with Japanese content blocked".to_string(),
                },
            },
            // Example 2: Sparkpost to specific user
            FilterRule {
                name: "Block Sparkpost to user@example.com".to_string(),
                criteria: Criteria::And {
                    criteria: vec![
                        Criteria::MailerPattern {
                            pattern: r".*\.sparkpostmail\.com".to_string(),
                        },
                        Criteria::RecipientPattern {
                            pattern: r"user@example\.com".to_string(),
                        },
                    ],
                },
                action: Action::Reject {
                    message: "Sparkpost to user@example.com blocked".to_string(),
                },
            },
        ];
        
        let engine = FilterEngine::new(config).unwrap();
        
        // Test Example 1: Chinese service + Japanese (should match)
        let mut context1 = MailContext::default();
        context1.mailer = Some("service.mail.cn v2.1".to_string());
        context1.subject = Some("こんにちは！特別なオファー".to_string()); // Japanese
        
        let action1 = engine.evaluate(&context1);
        match action1 {
            Action::Reject { message } => {
                assert!(message.contains("Chinese service"));
            }
            _ => panic!("Expected reject for Chinese service + Japanese"),
        }
        
        // Test Example 2: Sparkpost to user@example.com (should match)
        let mut context2 = MailContext::default();
        context2.mailer = Some("relay.sparkpostmail.com v3.2".to_string());
        context2.recipients = vec!["user@example.com".to_string()];
        
        let action2 = engine.evaluate(&context2);
        match action2 {
            Action::Reject { message } => {
                assert!(message.contains("Sparkpost"));
            }
            _ => panic!("Expected reject for Sparkpost to user@example.com"),
        }
        
        // Test partial match 1: Chinese service without Japanese (should not match)
        let mut context3 = MailContext::default();
        context3.mailer = Some("service.business.cn v1.0".to_string());
        context3.subject = Some("Business Proposal".to_string()); // English only
        
        let action3 = engine.evaluate(&context3);
        match action3 {
            Action::Accept => assert!(true),
            _ => panic!("Expected accept for Chinese service without Japanese"),
        }
        
        // Test partial match 2: Sparkpost to different user (should not match)
        let mut context4 = MailContext::default();
        context4.mailer = Some("relay.sparkpostmail.com v3.2".to_string());
        context4.recipients = vec!["admin@example.com".to_string()];
        
        let action4 = engine.evaluate(&context4);
        match action4 {
            Action::Accept => assert!(true),
            _ => panic!("Expected accept for Sparkpost to different user"),
        }
    }
}
