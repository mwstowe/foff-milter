use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::task::JoinHandle;

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct PerformanceConfig {
    pub parallel_processing: ParallelProcessing,
    pub caching: Caching,
    pub memory_optimization: MemoryOptimization,
    pub performance_monitoring: PerformanceMonitoring,
    pub optimization_settings: OptimizationSettings,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct ParallelProcessing {
    pub enabled: bool,
    pub max_threads: usize,
    pub thread_pool_size: usize,
    pub timeout_seconds: u64,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct Caching {
    pub enabled: bool,
    pub pattern_cache_size: usize,
    pub domain_cache_size: usize,
    pub config_cache_ttl_seconds: u64,
    pub domain_cache_ttl_seconds: u64,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct MemoryOptimization {
    pub lazy_loading: bool,
    pub pattern_deduplication: bool,
    pub memory_pool_size: usize,
    pub gc_threshold: usize,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct PerformanceMonitoring {
    pub enabled: bool,
    pub metrics_collection: bool,
    pub execution_timing: bool,
    pub resource_monitoring: bool,
    pub log_slow_operations: bool,
    pub slow_operation_threshold_ms: u64,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct OptimizationSettings {
    pub early_termination: bool,
    pub confidence_threshold: u32,
    pub max_modules_per_email: usize,
    pub skip_on_high_confidence: bool,
    pub batch_processing: bool,
}

#[derive(Debug, Clone)]
pub struct PerformanceMetrics {
    pub total_emails_processed: u64,
    pub total_processing_time_ms: u64,
    pub average_processing_time_ms: f64,
    pub module_execution_times: HashMap<String, u64>,
    pub cache_hit_rate: f64,
    pub parallel_execution_count: u64,
}

impl Default for PerformanceMetrics {
    fn default() -> Self {
        Self {
            total_emails_processed: 0,
            total_processing_time_ms: 0,
            average_processing_time_ms: 0.0,
            module_execution_times: HashMap::new(),
            cache_hit_rate: 0.0,
            parallel_execution_count: 0,
        }
    }
}

#[derive(Debug)]
pub struct CacheEntry<T> {
    pub value: T,
    pub timestamp: Instant,
    pub ttl: Duration,
}

impl<T> CacheEntry<T> {
    pub fn new(value: T, ttl: Duration) -> Self {
        Self {
            value,
            timestamp: Instant::now(),
            ttl,
        }
    }

    pub fn is_expired(&self) -> bool {
        self.timestamp.elapsed() > self.ttl
    }
}

pub struct PerformanceOptimizer {
    config: PerformanceConfig,
    metrics: Arc<Mutex<PerformanceMetrics>>,
    domain_cache: Arc<Mutex<HashMap<String, CacheEntry<String>>>>,
    pattern_cache: Arc<Mutex<HashMap<String, CacheEntry<bool>>>>,
}

impl PerformanceOptimizer {
    pub fn new(config: PerformanceConfig) -> Self {
        Self {
            config,
            metrics: Arc::new(Mutex::new(PerformanceMetrics::default())),
            domain_cache: Arc::new(Mutex::new(HashMap::new())),
            pattern_cache: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    pub fn load_from_file(path: &str) -> Result<Self, Box<dyn std::error::Error>> {
        let content = std::fs::read_to_string(path)?;
        let config: PerformanceConfig = serde_yml::from_str(&content)?;
        Ok(Self::new(config))
    }

    pub async fn execute_parallel<F, T>(&self, tasks: Vec<F>) -> Vec<T>
    where
        F: FnOnce() -> T + Send + 'static,
        T: Send + 'static,
    {
        if !self.config.parallel_processing.enabled || tasks.len() <= 1 {
            // Sequential execution fallback
            let mut results = Vec::new();
            for task in tasks {
                results.push(task());
            }
            return results;
        }

        let start_time = Instant::now();
        let timeout = Duration::from_secs(self.config.parallel_processing.timeout_seconds);

        // Create async tasks
        let handles: Vec<JoinHandle<T>> = tasks
            .into_iter()
            .map(|task| tokio::task::spawn_blocking(task))
            .collect();

        // Wait for all tasks with timeout
        let mut results = Vec::new();
        for handle in handles {
            match tokio::time::timeout(timeout, handle).await {
                Ok(Ok(result)) => results.push(result),
                Ok(Err(e)) => {
                    log::error!("Task execution error: {}", e);
                    continue;
                }
                Err(_) => {
                    log::warn!("Task timeout after {:?}", timeout);
                    continue;
                }
            }
        }

        // Update metrics
        if self.config.performance_monitoring.enabled {
            let execution_time = start_time.elapsed().as_millis() as u64;
            if let Ok(mut metrics) = self.metrics.lock() {
                metrics.parallel_execution_count += 1;
                if self.config.performance_monitoring.log_slow_operations
                    && execution_time
                        > self
                            .config
                            .performance_monitoring
                            .slow_operation_threshold_ms
                {
                    log::warn!("Slow parallel execution: {}ms", execution_time);
                }
            }
        }

        results
    }

    pub fn cache_domain_lookup(&self, domain: &str, result: String) {
        if !self.config.caching.enabled {
            return;
        }

        if let Ok(mut cache) = self.domain_cache.lock() {
            let ttl = Duration::from_secs(self.config.caching.domain_cache_ttl_seconds);
            cache.insert(domain.to_string(), CacheEntry::new(result, ttl));

            // Cleanup expired entries
            if cache.len() > self.config.caching.domain_cache_size {
                cache.retain(|_, entry| !entry.is_expired());
            }
        }
    }

    pub fn get_cached_domain_lookup(&self, domain: &str) -> Option<String> {
        if !self.config.caching.enabled {
            return None;
        }

        if let Ok(mut cache) = self.domain_cache.lock() {
            if let Some(entry) = cache.get(domain) {
                if !entry.is_expired() {
                    return Some(entry.value.clone());
                } else {
                    cache.remove(domain);
                }
            }
        }
        None
    }

    pub fn cache_pattern_result(&self, pattern: &str, result: bool) {
        if !self.config.caching.enabled {
            return;
        }

        if let Ok(mut cache) = self.pattern_cache.lock() {
            let ttl = Duration::from_secs(self.config.caching.config_cache_ttl_seconds);
            cache.insert(pattern.to_string(), CacheEntry::new(result, ttl));

            // Cleanup expired entries
            if cache.len() > self.config.caching.pattern_cache_size {
                cache.retain(|_, entry| !entry.is_expired());
            }
        }
    }

    pub fn get_cached_pattern_result(&self, pattern: &str) -> Option<bool> {
        if !self.config.caching.enabled {
            return None;
        }

        if let Ok(mut cache) = self.pattern_cache.lock() {
            if let Some(entry) = cache.get(pattern) {
                if !entry.is_expired() {
                    return Some(entry.value);
                } else {
                    cache.remove(pattern);
                }
            }
        }
        None
    }

    pub fn record_execution_time(&self, module_name: &str, duration_ms: u64) {
        if !self.config.performance_monitoring.enabled {
            return;
        }

        if let Ok(mut metrics) = self.metrics.lock() {
            *metrics
                .module_execution_times
                .entry(module_name.to_string())
                .or_insert(0) += duration_ms;

            if self.config.performance_monitoring.log_slow_operations
                && duration_ms
                    > self
                        .config
                        .performance_monitoring
                        .slow_operation_threshold_ms
            {
                log::warn!(
                    "Slow module execution: {} took {}ms",
                    module_name,
                    duration_ms
                );
            }
        }
    }

    pub fn record_email_processed(&self, total_time_ms: u64) {
        if !self.config.performance_monitoring.enabled {
            return;
        }

        if let Ok(mut metrics) = self.metrics.lock() {
            metrics.total_emails_processed += 1;
            metrics.total_processing_time_ms += total_time_ms;
            metrics.average_processing_time_ms =
                metrics.total_processing_time_ms as f64 / metrics.total_emails_processed as f64;
        }
    }

    pub fn should_skip_remaining_modules(&self, current_confidence: u32) -> bool {
        self.config.optimization_settings.skip_on_high_confidence
            && current_confidence >= self.config.optimization_settings.confidence_threshold
    }

    pub fn get_metrics(&self) -> Option<PerformanceMetrics> {
        self.metrics.lock().ok().map(|m| m.clone())
    }

    pub fn reset_metrics(&self) {
        if let Ok(mut metrics) = self.metrics.lock() {
            *metrics = PerformanceMetrics::default();
        }
    }

    pub fn cleanup_caches(&self) {
        if let Ok(mut domain_cache) = self.domain_cache.lock() {
            domain_cache.retain(|_, entry| !entry.is_expired());
        }
        if let Ok(mut pattern_cache) = self.pattern_cache.lock() {
            pattern_cache.retain(|_, entry| !entry.is_expired());
        }
    }

    pub fn get_cache_stats(&self) -> (usize, usize, f64) {
        let domain_cache_size = self.domain_cache.lock().map(|c| c.len()).unwrap_or(0);
        let pattern_cache_size = self.pattern_cache.lock().map(|c| c.len()).unwrap_or(0);

        // Simple cache hit rate calculation (would need more sophisticated tracking in production)
        let hit_rate = if let Ok(metrics) = self.metrics.lock() {
            metrics.cache_hit_rate
        } else {
            0.0
        };

        (domain_cache_size, pattern_cache_size, hit_rate)
    }
}
