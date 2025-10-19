use crate::detection::DetectionResult;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Instant, SystemTime, UNIX_EPOCH};

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct AnalyticsConfig {
    pub data_collection: DataCollection,
    pub real_time_dashboard: RealTimeDashboard,
    pub metrics_collection: MetricsCollection,
    pub trend_analysis: TrendAnalysis,
    pub reporting: Reporting,
    pub compliance: Compliance,
    pub threat_intelligence: ThreatIntelligence,
    pub alerting: Alerting,
    pub performance_tracking: PerformanceTracking,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct DataCollection {
    pub enabled: bool,
    pub storage_backend: String,
    pub database_path: String,
    pub retention_days: u32,
    pub batch_size: usize,
    pub flush_interval_seconds: u64,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct RealTimeDashboard {
    pub enabled: bool,
    pub web_interface: bool,
    pub port: u16,
    pub bind_address: String,
    pub update_interval_seconds: u64,
    pub max_connections: usize,
    pub authentication: bool,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct MetricsCollection {
    pub threat_detection_rates: bool,
    pub module_effectiveness: bool,
    pub processing_metrics: bool,
    pub system_health: bool,
    pub geographic_analysis: bool,
    pub temporal_patterns: bool,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct TrendAnalysis {
    pub enabled: bool,
    pub analysis_window_hours: u32,
    pub trend_detection_threshold: f64,
    pub pattern_recognition: bool,
    pub anomaly_detection: bool,
    pub forecasting: bool,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct Reporting {
    pub enabled: bool,
    pub report_formats: Vec<String>,
    pub scheduled_reports: bool,
    pub email_delivery: bool,
    pub report_retention_days: u32,
    pub executive_summary: bool,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct Compliance {
    pub audit_logging: bool,
    pub gdpr_compliance: bool,
    pub data_anonymization: bool,
    pub retention_policy: bool,
    pub export_capabilities: bool,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct ThreatIntelligence {
    pub enabled: bool,
    pub external_feeds: Vec<String>,
    pub ioc_tracking: bool,
    pub reputation_lookups: bool,
    pub threat_hunting: bool,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct Alerting {
    pub enabled: bool,
    pub threshold_alerts: bool,
    pub anomaly_alerts: bool,
    pub email_notifications: bool,
    pub webhook_notifications: bool,
    pub alert_cooldown_minutes: u32,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct PerformanceTracking {
    pub module_timing: bool,
    pub cache_statistics: bool,
    pub resource_usage: bool,
    pub error_tracking: bool,
    pub bottleneck_detection: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct EmailEvent {
    pub timestamp: u64,
    pub sender: String,
    pub sender_domain: String,
    pub recipient: String,
    pub subject: String,
    pub action: String,
    pub threat_types: Vec<String>,
    pub confidence_score: u32,
    pub processing_time_ms: u64,
    pub modules_triggered: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ThreatMetrics {
    pub total_emails: u64,
    pub threats_detected: u64,
    pub threats_blocked: u64,
    pub false_positives: u64,
    pub detection_rate: f64,
    pub block_rate: f64,
    pub average_confidence: f64,
    pub top_threat_types: HashMap<String, u64>,
    pub top_sender_domains: HashMap<String, u64>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ModuleMetrics {
    pub module_name: String,
    pub total_checks: u64,
    pub matches: u64,
    pub match_rate: f64,
    pub average_processing_time_ms: f64,
    pub total_processing_time_ms: u64,
    pub confidence_distribution: HashMap<String, u64>,
}

#[derive(Debug, Clone, Serialize)]
pub struct SystemMetrics {
    pub uptime_seconds: u64,
    pub emails_per_minute: f64,
    pub average_processing_time_ms: f64,
    pub cache_hit_rate: f64,
    pub memory_usage_mb: f64,
    pub cpu_usage_percent: f64,
    pub error_count: u64,
    pub alert_count: u64,
}

#[derive(Debug, Clone, Serialize)]
pub struct DashboardData {
    pub timestamp: u64,
    pub threat_metrics: ThreatMetrics,
    pub module_metrics: Vec<ModuleMetrics>,
    pub system_metrics: SystemMetrics,
    pub recent_events: Vec<EmailEvent>,
    pub alerts: Vec<String>,
}

pub struct AnalyticsEngine {
    config: AnalyticsConfig,
    events: Arc<Mutex<Vec<EmailEvent>>>,
    metrics: Arc<Mutex<ThreatMetrics>>,
    module_stats: Arc<Mutex<HashMap<String, ModuleMetrics>>>,
    system_stats: Arc<Mutex<SystemMetrics>>,
    start_time: Instant,
    alerts: Arc<Mutex<Vec<String>>>,
}

impl AnalyticsEngine {
    pub fn new(config: AnalyticsConfig) -> Self {
        Self {
            config,
            events: Arc::new(Mutex::new(Vec::new())),
            metrics: Arc::new(Mutex::new(ThreatMetrics::default())),
            module_stats: Arc::new(Mutex::new(HashMap::new())),
            system_stats: Arc::new(Mutex::new(SystemMetrics::default())),
            start_time: Instant::now(),
            alerts: Arc::new(Mutex::new(Vec::new())),
        }
    }

    pub fn load_from_file(path: &str) -> Result<Self, Box<dyn std::error::Error>> {
        let content = std::fs::read_to_string(path)?;
        let config: AnalyticsConfig = serde_yml::from_str(&content)?;
        Ok(Self::new(config))
    }

    pub fn record_email_event(
        &self,
        sender: &str,
        recipient: &str,
        subject: &str,
        results: &[DetectionResult],
        processing_time_ms: u64,
    ) {
        if !self.config.data_collection.enabled {
            return;
        }

        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let sender_domain = self.extract_domain(sender);
        let threat_types: Vec<String> = results.iter().map(|r| r.rule_name.clone()).collect();
        let confidence_score = results.iter().map(|r| r.confidence).sum();
        let modules_triggered: Vec<String> = results
            .iter()
            .filter(|r| r.matched)
            .map(|r| r.rule_name.clone())
            .collect();

        let action = if results.iter().any(|r| r.matched) {
            "BLOCKED"
        } else {
            "ALLOWED"
        };

        let event = EmailEvent {
            timestamp,
            sender: sender.to_string(),
            sender_domain,
            recipient: recipient.to_string(),
            subject: subject.to_string(),
            action: action.to_string(),
            threat_types,
            confidence_score,
            processing_time_ms,
            modules_triggered,
        };

        // Store event
        if let Ok(mut events) = self.events.lock() {
            events.push(event);

            // Limit event storage
            if events.len() > 10000 {
                events.drain(0..1000);
            }
        }

        // Update metrics
        self.update_threat_metrics(results, action == "BLOCKED");
        self.update_module_metrics(results, processing_time_ms);
        self.update_system_metrics(processing_time_ms);
    }

    fn update_threat_metrics(&self, results: &[DetectionResult], blocked: bool) {
        if let Ok(mut metrics) = self.metrics.lock() {
            metrics.total_emails += 1;

            if results.iter().any(|r| r.matched) {
                metrics.threats_detected += 1;
            }

            if blocked {
                metrics.threats_blocked += 1;
            }

            // Update rates
            metrics.detection_rate = metrics.threats_detected as f64 / metrics.total_emails as f64;
            metrics.block_rate = metrics.threats_blocked as f64 / metrics.total_emails as f64;

            // Update confidence average
            let total_confidence: u32 = results.iter().map(|r| r.confidence).sum();
            if total_confidence > 0 {
                metrics.average_confidence = total_confidence as f64 / results.len() as f64;
            }

            // Update top threat types
            for result in results.iter().filter(|r| r.matched) {
                *metrics
                    .top_threat_types
                    .entry(result.rule_name.clone())
                    .or_insert(0) += 1;
            }
        }
    }

    fn update_module_metrics(&self, results: &[DetectionResult], processing_time_ms: u64) {
        if let Ok(mut module_stats) = self.module_stats.lock() {
            for result in results {
                let stats = module_stats
                    .entry(result.rule_name.clone())
                    .or_insert_with(|| ModuleMetrics {
                        module_name: result.rule_name.clone(),
                        total_checks: 0,
                        matches: 0,
                        match_rate: 0.0,
                        average_processing_time_ms: 0.0,
                        total_processing_time_ms: 0,
                        confidence_distribution: HashMap::new(),
                    });

                stats.total_checks += 1;
                if result.matched {
                    stats.matches += 1;
                }
                stats.match_rate = stats.matches as f64 / stats.total_checks as f64;
                stats.total_processing_time_ms += processing_time_ms;
                stats.average_processing_time_ms =
                    stats.total_processing_time_ms as f64 / stats.total_checks as f64;

                // Update confidence distribution
                let confidence_range = match result.confidence {
                    0..=25 => "Low",
                    26..=50 => "Medium",
                    51..=75 => "High",
                    _ => "Critical",
                };
                *stats
                    .confidence_distribution
                    .entry(confidence_range.to_string())
                    .or_insert(0) += 1;
            }
        }
    }

    fn update_system_metrics(&self, processing_time_ms: u64) {
        if let Ok(mut system_stats) = self.system_stats.lock() {
            system_stats.uptime_seconds = self.start_time.elapsed().as_secs();

            // Simple moving average for processing time
            let alpha = 0.1; // Smoothing factor
            system_stats.average_processing_time_ms = alpha * processing_time_ms as f64
                + (1.0 - alpha) * system_stats.average_processing_time_ms;
        }
    }

    pub fn get_dashboard_data(&self) -> Option<DashboardData> {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let threat_metrics = self.metrics.lock().ok()?.clone();
        let module_metrics: Vec<ModuleMetrics> =
            self.module_stats.lock().ok()?.values().cloned().collect();
        let system_metrics = self.system_stats.lock().ok()?.clone();
        let recent_events: Vec<EmailEvent> = self
            .events
            .lock()
            .ok()?
            .iter()
            .rev()
            .take(50)
            .cloned()
            .collect();
        let alerts: Vec<String> = self.alerts.lock().ok()?.clone();

        Some(DashboardData {
            timestamp,
            threat_metrics,
            module_metrics,
            system_metrics,
            recent_events,
            alerts,
        })
    }

    pub fn generate_report(
        &self,
        format: &str,
        _time_range_hours: u32,
    ) -> Result<String, Box<dyn std::error::Error>> {
        let dashboard_data = self
            .get_dashboard_data()
            .ok_or("Failed to get dashboard data")?;

        match format {
            "json" => Ok(serde_json::to_string_pretty(&dashboard_data)?),
            "csv" => self.generate_csv_report(&dashboard_data),
            "html" => self.generate_html_report(&dashboard_data),
            _ => Err("Unsupported report format".into()),
        }
    }

    fn generate_csv_report(
        &self,
        data: &DashboardData,
    ) -> Result<String, Box<dyn std::error::Error>> {
        let mut csv = String::new();
        csv.push_str("Timestamp,Total Emails,Threats Detected,Detection Rate,Block Rate\n");
        csv.push_str(&format!(
            "{},{},{},{:.2}%,{:.2}%\n",
            data.timestamp,
            data.threat_metrics.total_emails,
            data.threat_metrics.threats_detected,
            data.threat_metrics.detection_rate * 100.0,
            data.threat_metrics.block_rate * 100.0
        ));
        Ok(csv)
    }

    fn generate_html_report(
        &self,
        data: &DashboardData,
    ) -> Result<String, Box<dyn std::error::Error>> {
        let html = format!(
            r#"
<!DOCTYPE html>
<html>
<head>
    <title>FOFF Milter Analytics Report</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; }}
        .metric {{ background: #f5f5f5; padding: 10px; margin: 10px 0; border-radius: 5px; }}
        .threat {{ color: #d32f2f; }}
        .safe {{ color: #388e3c; }}
    </style>
</head>
<body>
    <h1>FOFF Milter Analytics Report</h1>
    <div class="metric">
        <h3>Threat Detection Summary</h3>
        <p>Total Emails: {}</p>
        <p class="threat">Threats Detected: {} ({:.2}%)</p>
        <p class="threat">Threats Blocked: {} ({:.2}%)</p>
        <p>Average Confidence: {:.1}</p>
    </div>
    <div class="metric">
        <h3>System Performance</h3>
        <p>Uptime: {} seconds</p>
        <p>Average Processing Time: {:.2}ms</p>
        <p>Cache Hit Rate: {:.2}%</p>
    </div>
</body>
</html>
        "#,
            data.threat_metrics.total_emails,
            data.threat_metrics.threats_detected,
            data.threat_metrics.detection_rate * 100.0,
            data.threat_metrics.threats_blocked,
            data.threat_metrics.block_rate * 100.0,
            data.threat_metrics.average_confidence,
            data.system_metrics.uptime_seconds,
            data.system_metrics.average_processing_time_ms,
            data.system_metrics.cache_hit_rate * 100.0
        );
        Ok(html)
    }

    pub fn check_alerts(&self) -> Vec<String> {
        let mut new_alerts = Vec::new();

        if let Ok(metrics) = self.metrics.lock() {
            // High threat detection rate alert
            if metrics.detection_rate > 0.1 && metrics.total_emails > 100 {
                new_alerts.push(format!(
                    "High threat detection rate: {:.2}%",
                    metrics.detection_rate * 100.0
                ));
            }

            // Low processing performance alert
            if let Ok(system_stats) = self.system_stats.lock() {
                if system_stats.average_processing_time_ms > 1000.0 {
                    new_alerts.push(format!(
                        "Slow processing detected: {:.2}ms average",
                        system_stats.average_processing_time_ms
                    ));
                }
            }
        }

        // Store alerts
        if !new_alerts.is_empty() {
            if let Ok(mut alerts) = self.alerts.lock() {
                alerts.extend(new_alerts.clone());
                // Keep only recent alerts
                if alerts.len() > 100 {
                    alerts.drain(0..50);
                }
            }
        }

        new_alerts
    }

    fn extract_domain(&self, email: &str) -> String {
        if let Some(at_pos) = email.rfind('@') {
            let domain = &email[at_pos + 1..];
            domain.trim_end_matches('>').to_string()
        } else {
            "unknown".to_string()
        }
    }

    pub fn cleanup_old_data(&self) {
        let retention_seconds = self.config.data_collection.retention_days as u64 * 24 * 3600;
        let cutoff_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs()
            - retention_seconds;

        if let Ok(mut events) = self.events.lock() {
            events.retain(|event| event.timestamp > cutoff_time);
        }
    }
}

impl Default for ThreatMetrics {
    fn default() -> Self {
        Self {
            total_emails: 0,
            threats_detected: 0,
            threats_blocked: 0,
            false_positives: 0,
            detection_rate: 0.0,
            block_rate: 0.0,
            average_confidence: 0.0,
            top_threat_types: HashMap::new(),
            top_sender_domains: HashMap::new(),
        }
    }
}

impl Default for SystemMetrics {
    fn default() -> Self {
        Self {
            uptime_seconds: 0,
            emails_per_minute: 0.0,
            average_processing_time_ms: 0.0,
            cache_hit_rate: 0.0,
            memory_usage_mb: 0.0,
            cpu_usage_percent: 0.0,
            error_count: 0,
            alert_count: 0,
        }
    }
}
