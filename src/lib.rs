pub mod abuse_reporter;
pub mod analytics;
pub mod config;
pub mod config_test;
pub mod detection;
pub mod domain_age;
pub mod filter;
pub mod google_groups_unsubscriber;
pub mod integration;
pub mod language;
pub mod legacy_config;
pub mod machine_learning;
pub mod milter;
pub mod performance;
pub mod statistics;

// Re-export legacy Config and related types for backward compatibility
pub use legacy_config::{Action, Config, Criteria, FilterRule};
pub use filter::{FilterEngine, MailContext};
pub use language::LanguageDetector;
pub use milter::Milter;
pub use statistics::{StatEvent, StatisticsCollector};
