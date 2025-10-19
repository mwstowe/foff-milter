use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};
use serde::{Deserialize, Serialize};
use crate::detection::DetectionResult;

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct IntegrationConfig {
    pub rest_api: RestApi,
    pub authentication: Authentication,
    pub siem_integration: SiemIntegration,
    pub webhooks: Webhooks,
    pub email_notifications: EmailNotifications,
    pub cloud_integration: CloudIntegration,
    pub container_support: ContainerSupport,
    pub data_export: DataExport,
    pub monitoring: Monitoring,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct RestApi {
    pub enabled: bool,
    pub bind_address: String,
    pub port: u16,
    pub max_connections: usize,
    pub request_timeout_seconds: u64,
    pub rate_limiting: bool,
    pub requests_per_minute: u32,
    pub authentication: bool,
    pub api_key_header: String,
    pub cors_enabled: bool,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct Authentication {
    pub api_keys: ApiKeys,
    pub jwt_tokens: JwtTokens,
    pub basic_auth: BasicAuth,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct ApiKeys {
    pub enabled: bool,
    pub default_key: String,
    pub key_rotation_days: u32,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct JwtTokens {
    pub enabled: bool,
    pub secret_key: String,
    pub expiration_hours: u32,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct BasicAuth {
    pub enabled: bool,
    pub username: String,
    pub password: String,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct SiemIntegration {
    pub enabled: bool,
    pub splunk: SplunkConfig,
    pub elastic: ElasticConfig,
    pub qradar: QRadarConfig,
    pub sentinel: SentinelConfig,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct SplunkConfig {
    pub enabled: bool,
    pub hec_url: String,
    pub hec_token: String,
    pub index: String,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct ElasticConfig {
    pub enabled: bool,
    pub elasticsearch_url: String,
    pub index_pattern: String,
    pub username: String,
    pub password: String,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct QRadarConfig {
    pub enabled: bool,
    pub syslog_host: String,
    pub syslog_port: u16,
    pub facility: String,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct SentinelConfig {
    pub enabled: bool,
    pub workspace_id: String,
    pub shared_key: String,
    pub log_type: String,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct Webhooks {
    pub enabled: bool,
    pub endpoints: Vec<WebhookEndpoint>,
    pub slack: SlackConfig,
    pub teams: TeamsConfig,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct WebhookEndpoint {
    pub name: String,
    pub url: String,
    pub events: Vec<String>,
    pub headers: HashMap<String, String>,
    pub retry_attempts: u32,
    pub timeout_seconds: u64,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct SlackConfig {
    pub enabled: bool,
    pub webhook_url: String,
    pub channel: String,
    pub username: String,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct TeamsConfig {
    pub enabled: bool,
    pub webhook_url: String,
    pub card_format: bool,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct EmailNotifications {
    pub enabled: bool,
    pub smtp_server: String,
    pub smtp_port: u16,
    pub username: String,
    pub password: String,
    pub from_address: String,
    pub recipients: Vec<String>,
    pub alert_templates: HashMap<String, String>,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct CloudIntegration {
    pub aws: AwsConfig,
    pub azure: AzureConfig,
    pub gcp: GcpConfig,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct AwsConfig {
    pub enabled: bool,
    pub region: String,
    pub ses_integration: bool,
    pub cloudwatch_metrics: bool,
    pub lambda_processing: bool,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct AzureConfig {
    pub enabled: bool,
    pub tenant_id: String,
    pub office365_integration: bool,
    pub sentinel_integration: bool,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct GcpConfig {
    pub enabled: bool,
    pub project_id: String,
    pub gmail_api_integration: bool,
    pub cloud_logging: bool,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct ContainerSupport {
    pub docker: DockerConfig,
    pub kubernetes: KubernetesConfig,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct DockerConfig {
    pub enabled: bool,
    pub image_name: String,
    pub tag: String,
    pub expose_ports: Vec<u16>,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct KubernetesConfig {
    pub enabled: bool,
    pub namespace: String,
    pub replicas: u32,
    pub resource_limits: HashMap<String, String>,
    pub health_checks: bool,
    pub auto_scaling: bool,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct DataExport {
    pub enabled: bool,
    pub formats: Vec<String>,
    pub compression: bool,
    pub encryption: bool,
    pub batch_size: usize,
    pub export_schedule: String,
    pub retention_days: u32,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct Monitoring {
    pub prometheus_metrics: bool,
    pub health_endpoint: bool,
    pub status_endpoint: bool,
    pub metrics_port: u16,
    pub log_level: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct ApiRequest {
    pub method: String,
    pub path: String,
    pub headers: HashMap<String, String>,
    pub body: String,
    pub timestamp: u64,
    pub client_ip: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct ApiResponse {
    pub status_code: u16,
    pub body: String,
    pub headers: HashMap<String, String>,
    pub processing_time_ms: u64,
}

#[derive(Debug, Clone, Serialize)]
pub struct WebhookEvent {
    pub event_type: String,
    pub timestamp: u64,
    pub data: serde_json::Value,
    pub severity: String,
    pub source: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct SiemEvent {
    pub timestamp: u64,
    pub event_type: String,
    pub severity: String,
    pub source_ip: String,
    pub sender: String,
    pub recipient: String,
    pub subject: String,
    pub action: String,
    pub threat_types: Vec<String>,
    pub confidence: u32,
    pub details: HashMap<String, String>,
}

pub struct IntegrationEngine {
    config: IntegrationConfig,
    api_keys: Arc<Mutex<HashMap<String, u64>>>, // key -> expiration timestamp
    webhook_queue: Arc<Mutex<Vec<WebhookEvent>>>,
    siem_queue: Arc<Mutex<Vec<SiemEvent>>>,
    api_metrics: Arc<Mutex<HashMap<String, u64>>>,
}

impl IntegrationEngine {
    pub fn new(config: IntegrationConfig) -> Self {
        Self {
            config,
            api_keys: Arc::new(Mutex::new(HashMap::new())),
            webhook_queue: Arc::new(Mutex::new(Vec::new())),
            siem_queue: Arc::new(Mutex::new(Vec::new())),
            api_metrics: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    pub fn load_from_file(path: &str) -> Result<Self, Box<dyn std::error::Error>> {
        let content = std::fs::read_to_string(path)?;
        let config: IntegrationConfig = serde_yml::from_str(&content)?;
        Ok(Self::new(config))
    }

    pub fn authenticate_request(&self, headers: &HashMap<String, String>) -> bool {
        if !self.config.rest_api.authentication {
            return true;
        }

        if self.config.authentication.api_keys.enabled {
            if let Some(api_key) = headers.get(&self.config.rest_api.api_key_header) {
                return self.validate_api_key(api_key);
            }
        }

        if self.config.authentication.basic_auth.enabled {
            if let Some(auth_header) = headers.get("Authorization") {
                return self.validate_basic_auth(auth_header);
            }
        }

        false
    }

    fn validate_api_key(&self, api_key: &str) -> bool {
        // Simple validation - in production, use secure key management
        api_key == self.config.authentication.api_keys.default_key
    }

    fn validate_basic_auth(&self, auth_header: &str) -> bool {
        // Basic auth validation - in production, use secure authentication
        if let Some(encoded) = auth_header.strip_prefix("Basic ") {
            use base64::Engine;
            let decoded = String::from_utf8(
                base64::engine::general_purpose::STANDARD.decode(encoded).unwrap_or_default()
            ).unwrap_or_default();
            let expected = format!("{}:{}", 
                self.config.authentication.basic_auth.username,
                self.config.authentication.basic_auth.password
            );
            return decoded == expected;
        }
        false
    }

    pub fn process_email_api(&self, sender: &str, subject: &str, _body: &str) -> Result<serde_json::Value, String> {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        // Simulate email processing
        let response = serde_json::json!({
            "request_id": format!("req_{}", timestamp),
            "timestamp": timestamp,
            "sender": sender,
            "subject": subject,
            "status": "processed",
            "threat_detected": false,
            "confidence": 0.1,
            "processing_time_ms": 45
        });

        // Record API metrics
        self.record_api_metric("email_analyze");

        Ok(response)
    }

    pub fn get_analytics_api(&self) -> Result<serde_json::Value, String> {
        // Simulate analytics data
        let analytics = serde_json::json!({
            "timestamp": SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs(),
            "total_emails": 10000,
            "threats_detected": 1250,
            "detection_rate": 0.125,
            "system_status": "healthy",
            "uptime_seconds": 86400
        });

        self.record_api_metric("analytics_dashboard");
        Ok(analytics)
    }

    pub fn send_webhook(&self, event_type: &str, data: serde_json::Value, severity: &str) {
        if !self.config.webhooks.enabled {
            return;
        }

        let event = WebhookEvent {
            event_type: event_type.to_string(),
            timestamp: SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs(),
            data,
            severity: severity.to_string(),
            source: "foff-milter".to_string(),
        };

        // Queue webhook for processing
        if let Ok(mut queue) = self.webhook_queue.lock() {
            queue.push(event);
            
            // Limit queue size
            if queue.len() > 1000 {
                queue.drain(0..100);
            }
        }

        // Process webhooks (in production, this would be async)
        self.process_webhooks();
    }

    fn process_webhooks(&self) {
        if let Ok(mut queue) = self.webhook_queue.lock() {
            for event in queue.drain(..) {
                for endpoint in &self.config.webhooks.endpoints {
                    if endpoint.events.contains(&event.event_type) {
                        self.send_webhook_to_endpoint(&event, endpoint);
                    }
                }

                // Send to Slack if configured
                if self.config.webhooks.slack.enabled {
                    self.send_slack_notification(&event);
                }

                // Send to Teams if configured
                if self.config.webhooks.teams.enabled {
                    self.send_teams_notification(&event);
                }
            }
        }
    }

    fn send_webhook_to_endpoint(&self, event: &WebhookEvent, endpoint: &WebhookEndpoint) {
        log::info!("Sending webhook to {}: {} - {}", endpoint.name, event.event_type, event.severity);
        // In production, implement actual HTTP POST to endpoint.url
    }

    fn send_slack_notification(&self, event: &WebhookEvent) {
        log::info!("Sending Slack notification: {} - {}", event.event_type, event.severity);
        // In production, implement Slack webhook integration
    }

    fn send_teams_notification(&self, event: &WebhookEvent) {
        log::info!("Sending Teams notification: {} - {}", event.event_type, event.severity);
        // In production, implement Teams webhook integration
    }

    pub fn send_siem_event(&self, sender: &str, recipient: &str, subject: &str, 
                          results: &[DetectionResult], action: &str) {
        if !self.config.siem_integration.enabled {
            return;
        }

        let event = SiemEvent {
            timestamp: SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs(),
            event_type: "email_analysis".to_string(),
            severity: if results.iter().any(|r| r.matched) { "high" } else { "low" }.to_string(),
            source_ip: "127.0.0.1".to_string(), // Would extract from email headers
            sender: sender.to_string(),
            recipient: recipient.to_string(),
            subject: subject.to_string(),
            action: action.to_string(),
            threat_types: results.iter().filter(|r| r.matched).map(|r| r.rule_name.clone()).collect(),
            confidence: results.iter().map(|r| r.confidence).sum(),
            details: HashMap::new(),
        };

        // Queue SIEM event for processing
        if let Ok(mut queue) = self.siem_queue.lock() {
            queue.push(event);
            
            // Limit queue size
            if queue.len() > 1000 {
                queue.drain(0..100);
            }
        }

        // Process SIEM events (in production, this would be async)
        self.process_siem_events();
    }

    fn process_siem_events(&self) {
        if let Ok(mut queue) = self.siem_queue.lock() {
            for event in queue.drain(..) {
                // Send to Splunk
                if self.config.siem_integration.splunk.enabled {
                    self.send_to_splunk(&event);
                }

                // Send to Elastic
                if self.config.siem_integration.elastic.enabled {
                    self.send_to_elastic(&event);
                }

                // Send to QRadar
                if self.config.siem_integration.qradar.enabled {
                    self.send_to_qradar(&event);
                }

                // Send to Sentinel
                if self.config.siem_integration.sentinel.enabled {
                    self.send_to_sentinel(&event);
                }
            }
        }
    }

    fn send_to_splunk(&self, event: &SiemEvent) {
        log::info!("Sending event to Splunk: {} - {}", event.event_type, event.severity);
        // In production, implement Splunk HEC integration
    }

    fn send_to_elastic(&self, event: &SiemEvent) {
        log::info!("Sending event to Elasticsearch: {} - {}", event.event_type, event.severity);
        // In production, implement Elasticsearch integration
    }

    fn send_to_qradar(&self, event: &SiemEvent) {
        log::info!("Sending event to QRadar: {} - {}", event.event_type, event.severity);
        // In production, implement QRadar syslog integration
    }

    fn send_to_sentinel(&self, event: &SiemEvent) {
        log::info!("Sending event to Sentinel: {} - {}", event.event_type, event.severity);
        // In production, implement Azure Sentinel integration
    }

    pub fn export_data(&self, format: &str, start_time: u64, end_time: u64) -> Result<String, String> {
        if !self.config.data_export.enabled {
            return Err("Data export is disabled".to_string());
        }

        if !self.config.data_export.formats.contains(&format.to_string()) {
            return Err(format!("Unsupported export format: {}", format));
        }

        match format {
            "json" => self.export_json(start_time, end_time),
            "csv" => self.export_csv(start_time, end_time),
            "cef" => self.export_cef(start_time, end_time),
            "leef" => self.export_leef(start_time, end_time),
            _ => Err(format!("Unknown export format: {}", format)),
        }
    }

    fn export_json(&self, start_time: u64, end_time: u64) -> Result<String, String> {
        let export_data = serde_json::json!({
            "export_format": "json",
            "start_time": start_time,
            "end_time": end_time,
            "events": []
        });
        Ok(serde_json::to_string_pretty(&export_data).unwrap_or_default())
    }

    fn export_csv(&self, _start_time: u64, _end_time: u64) -> Result<String, String> {
        Ok("timestamp,event_type,severity,sender,action\n".to_string())
    }

    fn export_cef(&self, _start_time: u64, _end_time: u64) -> Result<String, String> {
        Ok("CEF:0|FOFF|Milter|1.0|EmailAnalysis|Email Analysis Event|3|".to_string())
    }

    fn export_leef(&self, _start_time: u64, _end_time: u64) -> Result<String, String> {
        Ok("LEEF:2.0|FOFF|Milter|1.0|EmailAnalysis|".to_string())
    }

    fn record_api_metric(&self, endpoint: &str) {
        if let Ok(mut metrics) = self.api_metrics.lock() {
            *metrics.entry(endpoint.to_string()).or_insert(0) += 1;
        }
    }

    pub fn get_api_metrics(&self) -> HashMap<String, u64> {
        match self.api_metrics.lock() {
            Ok(metrics) => metrics.clone(),
            Err(_) => {
                log::error!("Failed to lock api_metrics mutex");
                HashMap::new()
            }
        }
    }

    pub fn get_health_status(&self) -> serde_json::Value {
        serde_json::json!({
            "status": "healthy",
            "timestamp": SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs(),
            "version": "1.0.0",
            "components": {
                "rest_api": self.config.rest_api.enabled,
                "webhooks": self.config.webhooks.enabled,
                "siem_integration": self.config.siem_integration.enabled,
                "data_export": self.config.data_export.enabled
            }
        })
    }

    pub fn cleanup_old_data(&self) {
        // Cleanup old webhook events
        if let Ok(mut queue) = self.webhook_queue.lock() {
            queue.clear();
        }

        // Cleanup old SIEM events
        if let Ok(mut queue) = self.siem_queue.lock() {
            queue.clear();
        }
    }
}
