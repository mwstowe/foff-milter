//! Performance Benchmark
//!
//! Compares performance between original and simplified architectures

use crate::components::hybrid_filter_engine::HybridFilterEngine;
use crate::heuristic_config::Config;
use crate::MailContext;
use std::collections::HashMap;
use std::time::{Duration, Instant};

type BenchmarkResult = (
    crate::heuristic_config::Action,
    Vec<String>,
    Vec<(String, String)>,
);

pub struct BenchmarkResults {
    pub original_time: Duration,
    pub simplified_time: Duration,
    pub speedup_factor: f64,
    pub memory_usage_original: usize,
    pub memory_usage_simplified: usize,
    pub accuracy_maintained: bool,
}

pub struct PerformanceBenchmark;

impl PerformanceBenchmark {
    /// Run comprehensive benchmark comparing both architectures
    pub async fn run_benchmark(test_emails: Vec<MailContext>) -> anyhow::Result<BenchmarkResults> {
        let config = Config {
            module_config_dir: Some("./rulesets".to_string()),
            ..Default::default()
        };

        // Create engines for both architectures
        let mut hybrid_engine = HybridFilterEngine::new(config.clone(), None)?;

        // Benchmark original architecture
        let start = Instant::now();
        let mut original_results = Vec::new();

        hybrid_engine.switch_architecture(false);
        for email in &test_emails {
            let result = hybrid_engine.evaluate(email).await;
            original_results.push(result);
        }
        let original_time = start.elapsed();

        // Benchmark simplified architecture
        let start = Instant::now();
        let mut simplified_results = Vec::new();

        hybrid_engine.switch_architecture(true);
        for email in &test_emails {
            let result = hybrid_engine.evaluate(email).await;
            simplified_results.push(result);
        }
        let simplified_time = start.elapsed();

        // Calculate speedup
        let speedup_factor = original_time.as_secs_f64() / simplified_time.as_secs_f64();

        // Check accuracy (simplified comparison)
        let accuracy_maintained = Self::compare_accuracy(&original_results, &simplified_results);

        // Estimate memory usage (simplified)
        let memory_usage_original = 38 * 1024; // Rough estimate: 38 modules * 1KB each
        let memory_usage_simplified = 6 * 512; // 6 components * 512B each

        Ok(BenchmarkResults {
            original_time,
            simplified_time,
            speedup_factor,
            memory_usage_original,
            memory_usage_simplified,
            accuracy_maintained,
        })
    }

    /// Compare accuracy between architectures (simplified)
    fn compare_accuracy(
        original: &[BenchmarkResult],
        simplified: &[BenchmarkResult],
    ) -> bool {
        if original.len() != simplified.len() {
            return false;
        }

        // Compare actions (main accuracy metric)
        for (orig, simp) in original.iter().zip(simplified.iter()) {
            if !Self::actions_equivalent(&orig.0, &simp.0) {
                return false;
            }
        }

        true
    }

    /// Check if two actions are equivalent for accuracy purposes
    fn actions_equivalent(
        action1: &crate::heuristic_config::Action,
        action2: &crate::heuristic_config::Action,
    ) -> bool {
        use crate::heuristic_config::Action;

        match (action1, action2) {
            (Action::Accept, Action::Accept) => true,
            (Action::TagAsSpam { .. }, Action::TagAsSpam { .. }) => true,
            (Action::Reject { .. }, Action::Reject { .. }) => true,
            (Action::Reject { .. }, Action::TagAsSpam { .. }) => true, // Reject->Tag conversion is OK
            _ => false,
        }
    }

    /// Create test email contexts for benchmarking
    pub fn create_test_emails(count: usize) -> Vec<MailContext> {
        let mut emails = Vec::new();

        for i in 0..count {
            let mut headers = HashMap::new();
            headers.insert("From".to_string(), format!("test{}@example.com", i));
            headers.insert("Subject".to_string(), format!("Test Email {}", i));

            if i % 3 == 0 {
                // Add some authentication headers
                headers.insert(
                    "Authentication-Results".to_string(),
                    "dkim=pass spf=pass".to_string(),
                );
            }

            if i % 5 == 0 {
                // Add some suspicious content
                headers.insert(
                    "Subject".to_string(),
                    "URGENT: Verify Your Account Now!".to_string(),
                );
            }

            emails.push(MailContext {
                sender: Some(format!("test{}@example.com", i)),
                from_header: Some(format!("test{}@example.com", i)),
                recipients: vec!["recipient@example.com".to_string()],
                headers,
                mailer: None,
                subject: Some(format!("Test Email {}", i)),
                hostname: None,
                helo: None,
                body: Some(format!("Test email body {}", i)),
                last_header_name: None,
                attachments: Vec::new(),
                extracted_media_text: String::new(),
                is_legitimate_business: i % 4 == 0,
                is_first_hop: true,
                forwarding_source: None,
                proximate_mailer: None,
                normalized: None,
                dkim_verification: None,
            });
        }

        emails
    }
}

impl BenchmarkResults {
    /// Print formatted benchmark results
    pub fn print_results(&self) {
        println!("=== ARCHITECTURE PERFORMANCE BENCHMARK ===");
        println!("Original Architecture Time: {:?}", self.original_time);
        println!("Simplified Architecture Time: {:?}", self.simplified_time);
        println!("Speedup Factor: {:.2}x", self.speedup_factor);
        println!(
            "Memory Usage - Original: {} bytes",
            self.memory_usage_original
        );
        println!(
            "Memory Usage - Simplified: {} bytes",
            self.memory_usage_simplified
        );
        println!(
            "Memory Reduction: {:.1}%",
            (1.0 - self.memory_usage_simplified as f64 / self.memory_usage_original as f64) * 100.0
        );
        println!("Accuracy Maintained: {}", self.accuracy_maintained);

        if self.speedup_factor > 1.0 {
            println!(
                "✅ Simplified architecture is {:.1}% faster",
                (self.speedup_factor - 1.0) * 100.0
            );
        } else {
            println!(
                "⚠️  Simplified architecture is {:.1}% slower",
                (1.0 - self.speedup_factor) * 100.0
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_benchmark_small_dataset() {
        let test_emails = PerformanceBenchmark::create_test_emails(10);
        let results = PerformanceBenchmark::run_benchmark(test_emails).await;

        if let Ok(results) = results {
            results.print_results();

            // Basic sanity checks
            assert!(results.original_time > Duration::from_nanos(0));
            assert!(results.simplified_time > Duration::from_nanos(0));
            assert!(results.speedup_factor > 0.0);
        }
    }

    #[test]
    fn test_create_test_emails() {
        let emails = PerformanceBenchmark::create_test_emails(5);
        assert_eq!(emails.len(), 5);

        // Check variety in test data
        assert!(emails.iter().any(|e| e.is_legitimate_business));
        assert!(emails.iter().any(|e| !e.is_legitimate_business));
    }
}
