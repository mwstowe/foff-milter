pub mod abuse_reporter;
pub mod advanced_security;
pub mod analytics;
pub mod attachment_analyzer;
pub mod config;
pub mod config_test;
pub mod detection;
pub mod domain_age;
pub mod filter;
pub mod google_groups_unsubscriber;
pub mod integration;
pub mod invoice_analyzer;
pub mod language;
pub mod legacy_config;
pub mod machine_learning;
pub mod media_analyzer;
pub mod milter;
pub mod performance;
pub mod statistics;
pub mod toml_config;

// Re-export legacy Config and related types for backward compatibility
pub use filter::{FilterEngine, MailContext};
pub use language::LanguageDetector;
pub use legacy_config::{Action, Config, Criteria, FilterRule};
pub use milter::Milter;
pub use statistics::{StatEvent, StatisticsCollector};
