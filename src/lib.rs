/// A `&'static Regex` for a literal pattern, compiled on first use and then reused.
/// Use it instead of `Regex::new(literal).unwrap()` in code that runs per message.
#[macro_export]
macro_rules! static_regex {
    ($pattern:literal) => {{
        static RE: std::sync::LazyLock<regex::Regex> =
            std::sync::LazyLock::new(|| regex::Regex::new($pattern).unwrap());
        &*RE
    }};
}

/// `Regex::new(pattern)`, cached for the life of the process. For patterns that aren't
/// literals (pattern lists, configured brand patterns) used in code that runs per message.
pub fn cached_regex(pattern: &str) -> Result<std::sync::Arc<regex::Regex>, regex::Error> {
    use std::collections::HashMap;
    use std::sync::{Arc, LazyLock, Mutex};
    static CACHE: LazyLock<Mutex<HashMap<String, Arc<regex::Regex>>>> =
        LazyLock::new(|| Mutex::new(HashMap::new()));
    if let Some(re) = CACHE.lock().unwrap().get(pattern) {
        return Ok(Arc::clone(re));
    }
    // Compile outside the lock; a concurrent duplicate compile is harmless
    let re = Arc::new(regex::Regex::new(pattern)?);
    CACHE
        .lock()
        .unwrap()
        .insert(pattern.to_string(), Arc::clone(&re));
    Ok(re)
}

pub mod anonymize;
pub mod attachment_analyzer;
pub mod builtin_rules;
pub mod business_context;
pub mod config;
pub mod config_loader;
pub mod dkim_verification;
pub mod domain_age;
pub mod domain_registry;
pub mod domain_utils;
pub mod features;
pub mod filter;
pub mod google_groups_unsubscriber;
pub mod heuristic_config;
pub mod invoice_analyzer;
pub mod language;
pub mod media_analyzer;
pub mod milter;
pub mod normalization;
pub mod seasonal_behavioral;
pub mod statistics;
pub mod toml_config;
pub mod trust_analyzer;
pub mod url_resolver;
pub mod version;

// Re-export Config and related types for backward compatibility
pub use filter::{FilterEngine, MailContext};
pub use heuristic_config::{Action, Config, Criteria, FilterRule};
pub use language::LanguageDetector;
pub use milter::Milter;
pub use statistics::{StatEvent, StatisticsCollector};
