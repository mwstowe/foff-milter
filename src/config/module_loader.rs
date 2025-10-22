use crate::advanced_security::AdvancedSecurityEngine;
use crate::analytics::AnalyticsEngine;
use crate::config::Config;
use crate::detection::{
    adult_content::AdultContentDetector, brand_impersonation::BrandImpersonationDetector,
    ecommerce_scams::EcommerceScamsDetector, financial_services::FinancialServicesDetector,
    health_spam::HealthSpamDetector, multi_language::MultiLanguageDetector,
    phishing_scams::PhishingScamsDetector, suspicious_domains::SuspiciousDomainDetector,
    technology_scams::TechnologyScamsDetector, DetectionResult,
};
use crate::integration::IntegrationEngine;
use crate::machine_learning::MachineLearningEngine;
use crate::performance::PerformanceOptimizer;
use anyhow::Result;
use std::path::Path;
use std::time::Instant;

pub struct ModuleManager {
    pub suspicious_domains: Option<SuspiciousDomainDetector>,
    pub brand_impersonation: Option<BrandImpersonationDetector>,
    pub health_spam: Option<HealthSpamDetector>,
    pub phishing_scams: Option<PhishingScamsDetector>,
    pub adult_content: Option<AdultContentDetector>,
    pub ecommerce_scams: Option<EcommerceScamsDetector>,
    pub financial_services: Option<FinancialServicesDetector>,
    pub technology_scams: Option<TechnologyScamsDetector>,
    pub multi_language: Option<MultiLanguageDetector>,
    pub performance_optimizer: Option<PerformanceOptimizer>,
    pub analytics_engine: Option<AnalyticsEngine>,
    pub ml_engine: Option<MachineLearningEngine>,
    pub integration_engine: Option<IntegrationEngine>,
    pub advanced_security: Option<AdvancedSecurityEngine>,
}

impl Default for ModuleManager {
    fn default() -> Self {
        Self::new()
    }
}

impl ModuleManager {
    pub fn new() -> Self {
        Self {
            suspicious_domains: None,
            brand_impersonation: None,
            health_spam: None,
            phishing_scams: None,
            adult_content: None,
            ecommerce_scams: None,
            financial_services: None,
            technology_scams: None,
            multi_language: None,
            performance_optimizer: None,
            analytics_engine: None,
            ml_engine: None,
            integration_engine: None,
            advanced_security: None,
        }
    }

    pub fn load_modules(config: &Config) -> Result<Self> {
        let mut manager = Self::new();
        let config_dir = &config.detection.config_dir;

        for module_name in &config.detection.enabled_modules {
            match module_name.as_str() {
                "suspicious-domains" => {
                    let path = Path::new(config_dir).join("suspicious-domains.yaml");
                    if path.exists() {
                        match SuspiciousDomainDetector::load_from_file(path.to_str().unwrap()) {
                            Ok(detector) => {
                                manager.suspicious_domains = Some(detector);
                                log::info!("Loaded suspicious-domains detection module");
                            }
                            Err(e) => {
                                log::error!("Failed to load suspicious-domains module: {}", e);
                                return Err(anyhow::anyhow!(
                                    "Failed to load suspicious-domains module: {}",
                                    e
                                ));
                            }
                        }
                    } else {
                        log::warn!("suspicious-domains.yaml not found, skipping module");
                    }
                }
                "brand-impersonation" => {
                    let path = Path::new(config_dir).join("brand-impersonation.yaml");
                    if path.exists() {
                        match BrandImpersonationDetector::load_from_file(path.to_str().unwrap()) {
                            Ok(detector) => {
                                manager.brand_impersonation = Some(detector);
                                log::info!("Loaded brand-impersonation detection module");
                            }
                            Err(e) => {
                                log::error!("Failed to load brand-impersonation module: {}", e);
                                return Err(anyhow::anyhow!(
                                    "Failed to load brand-impersonation module: {}",
                                    e
                                ));
                            }
                        }
                    } else {
                        log::warn!("brand-impersonation.yaml not found, skipping module");
                    }
                }
                "health-spam" => {
                    let path = Path::new(config_dir).join("health-spam.yaml");
                    if path.exists() {
                        match HealthSpamDetector::load_from_file(path.to_str().unwrap()) {
                            Ok(detector) => {
                                manager.health_spam = Some(detector);
                                log::info!("Loaded health-spam detection module");
                            }
                            Err(e) => {
                                log::error!("Failed to load health-spam module: {}", e);
                                return Err(anyhow::anyhow!(
                                    "Failed to load health-spam module: {}",
                                    e
                                ));
                            }
                        }
                    } else {
                        log::warn!("health-spam.yaml not found, skipping module");
                    }
                }
                "phishing-scams" => {
                    let path = Path::new(config_dir).join("phishing-scams.yaml");
                    if path.exists() {
                        match PhishingScamsDetector::load_from_file(path.to_str().unwrap()) {
                            Ok(detector) => {
                                manager.phishing_scams = Some(detector);
                                log::info!("Loaded phishing-scams detection module");
                            }
                            Err(e) => {
                                log::error!("Failed to load phishing-scams module: {}", e);
                                return Err(anyhow::anyhow!(
                                    "Failed to load phishing-scams module: {}",
                                    e
                                ));
                            }
                        }
                    } else {
                        log::warn!("phishing-scams.yaml not found, skipping module");
                    }
                }
                "adult-content" => {
                    let path = Path::new(config_dir).join("adult-content.yaml");
                    if path.exists() {
                        match AdultContentDetector::load_from_file(path.to_str().unwrap()) {
                            Ok(detector) => {
                                manager.adult_content = Some(detector);
                                log::info!("Loaded adult-content detection module");
                            }
                            Err(e) => {
                                log::error!("Failed to load adult-content module: {}", e);
                                return Err(anyhow::anyhow!(
                                    "Failed to load adult-content module: {}",
                                    e
                                ));
                            }
                        }
                    } else {
                        log::warn!("adult-content.yaml not found, skipping module");
                    }
                }
                "ecommerce-scams" => {
                    let path = Path::new(config_dir).join("ecommerce-scams.yaml");
                    if path.exists() {
                        match EcommerceScamsDetector::load_from_file(path.to_str().unwrap()) {
                            Ok(detector) => {
                                manager.ecommerce_scams = Some(detector);
                                log::info!("Loaded ecommerce-scams detection module");
                            }
                            Err(e) => {
                                log::error!("Failed to load ecommerce-scams module: {}", e);
                                return Err(anyhow::anyhow!(
                                    "Failed to load ecommerce-scams module: {}",
                                    e
                                ));
                            }
                        }
                    } else {
                        log::warn!("ecommerce-scams.yaml not found, skipping module");
                    }
                }
                "financial-services" => {
                    let path = Path::new(config_dir).join("financial-services.yaml");
                    if path.exists() {
                        match FinancialServicesDetector::load_from_file(path.to_str().unwrap()) {
                            Ok(detector) => {
                                manager.financial_services = Some(detector);
                                log::info!("Loaded financial-services detection module");
                            }
                            Err(e) => {
                                log::error!("Failed to load financial-services module: {}", e);
                                return Err(anyhow::anyhow!(
                                    "Failed to load financial-services module: {}",
                                    e
                                ));
                            }
                        }
                    } else {
                        log::warn!("financial-services.yaml not found, skipping module");
                    }
                }
                "technology-scams" => {
                    let path = Path::new(config_dir).join("technology-scams.yaml");
                    if path.exists() {
                        match TechnologyScamsDetector::load_from_file(path.to_str().unwrap()) {
                            Ok(detector) => {
                                manager.technology_scams = Some(detector);
                                log::info!("Loaded technology-scams detection module");
                            }
                            Err(e) => {
                                log::error!("Failed to load technology-scams module: {}", e);
                                return Err(anyhow::anyhow!(
                                    "Failed to load technology-scams module: {}",
                                    e
                                ));
                            }
                        }
                    } else {
                        log::warn!("technology-scams.yaml not found, skipping module");
                    }
                }
                "multi-language" => {
                    let path = Path::new(config_dir).join("multi-language.yaml");
                    if path.exists() {
                        match MultiLanguageDetector::load_from_file(path.to_str().unwrap()) {
                            Ok(detector) => {
                                manager.multi_language = Some(detector);
                                log::info!("Loaded multi-language detection module");
                            }
                            Err(e) => {
                                log::error!("Failed to load multi-language module: {}", e);
                                return Err(anyhow::anyhow!(
                                    "Failed to load multi-language module: {}",
                                    e
                                ));
                            }
                        }
                    } else {
                        log::warn!("multi-language.yaml not found, skipping module");
                    }
                }
                _ => {
                    log::warn!("Unknown detection module: {}", module_name);
                }
            }
        }

        // Load advanced security engine (always try to load for deep inspection)
        let advanced_security_path = Path::new(config_dir).join("advanced-security.yaml");
        if advanced_security_path.exists() {
            match AdvancedSecurityEngine::load_from_file(advanced_security_path.to_str().unwrap()) {
                Ok(engine) => {
                    manager.advanced_security = Some(engine);
                    log::info!("Loaded advanced security engine");
                }
                Err(e) => {
                    log::warn!(
                        "Failed to load advanced security engine: {}, advanced security disabled",
                        e
                    );
                }
            }
        } else {
            log::info!("No advanced-security.yaml found, advanced security disabled");
        }

        // Load integration engine (always try to load for API and external connectivity)
        let integration_path = Path::new(config_dir).join("integration.yaml");
        if integration_path.exists() {
            match IntegrationEngine::load_from_file(integration_path.to_str().unwrap()) {
                Ok(engine) => {
                    manager.integration_engine = Some(engine);
                    log::info!("Loaded integration engine");
                }
                Err(e) => {
                    log::warn!(
                        "Failed to load integration engine: {}, integrations disabled",
                        e
                    );
                }
            }
        } else {
            log::info!("No integration.yaml found, integrations disabled");
        }

        // Load machine learning engine (always try to load for adaptive intelligence)
        let ml_path = Path::new(config_dir).join("advanced-heuristics.yaml");
        if ml_path.exists() {
            match MachineLearningEngine::load_from_file(ml_path.to_str().unwrap()) {
                Ok(engine) => {
                    manager.ml_engine = Some(engine);
                    log::info!("Loaded machine learning engine");
                }
                Err(e) => {
                    log::warn!("Failed to load machine learning engine: {}, ML disabled", e);
                }
            }
        } else {
            log::info!("No advanced-heuristics.yaml found, ML disabled");
        }

        // Load analytics engine (always try to load for monitoring)
        let analytics_path = Path::new(config_dir).join("analytics.yaml");
        if analytics_path.exists() {
            match AnalyticsEngine::load_from_file(analytics_path.to_str().unwrap()) {
                Ok(engine) => {
                    manager.analytics_engine = Some(engine);
                    log::info!("Loaded analytics engine");
                }
                Err(e) => {
                    log::warn!("Failed to load analytics engine: {}, analytics disabled", e);
                }
            }
        } else {
            log::info!("No analytics.yaml found, analytics disabled");
        }

        // Load performance optimizer (always try to load for optimization)
        let perf_path = Path::new(config_dir).join("performance.yaml");
        if perf_path.exists() {
            match PerformanceOptimizer::load_from_file(perf_path.to_str().unwrap()) {
                Ok(optimizer) => {
                    manager.performance_optimizer = Some(optimizer);
                    log::info!("Loaded performance optimizer");
                }
                Err(e) => {
                    log::warn!(
                        "Failed to load performance optimizer: {}, using defaults",
                        e
                    );
                }
            }
        } else {
            log::info!("No performance.yaml found, using default performance settings");
        }

        Ok(manager)
    }

    pub fn check_email(&self, email_data: &EmailData) -> Vec<DetectionResult> {
        let start_time = Instant::now();
        let mut results = Vec::new();
        let _total_confidence = 0u32;

        // Check suspicious domains
        if let Some(detector) = &self.suspicious_domains {
            if let Some(domain) = extract_domain(&email_data.sender) {
                let result = detector.check_domain(&domain);
                if result.matched {
                    results.push(result);
                }
            }
        }

        // Check brand impersonation
        if let Some(detector) = &self.brand_impersonation {
            if let Some(domain) = extract_domain(&email_data.sender) {
                let result = detector.check_brand_impersonation(&email_data.from_header, &domain);
                if result.matched {
                    results.push(result);
                }
            }
        }

        // Check health spam
        if let Some(detector) = &self.health_spam {
            if let Some(domain) = extract_domain(&email_data.sender) {
                let result =
                    detector.check_health_spam(&email_data.subject, &email_data.body, &domain);
                if result.matched {
                    results.push(result);
                }
            }
        }

        // Check phishing scams
        if let Some(detector) = &self.phishing_scams {
            let result = detector.check_phishing_scam(
                &email_data.subject,
                &email_data.body,
                &email_data.sender,
                &email_data.from_header,
            );
            if result.matched {
                results.push(result);
            }
        }

        // Check adult content
        if let Some(detector) = &self.adult_content {
            if let Some(domain) = extract_domain(&email_data.sender) {
                let result = detector.check_adult_content(
                    &email_data.subject,
                    &email_data.body,
                    &email_data.sender,
                    &domain,
                );
                if result.matched {
                    results.push(result);
                }
            }
        }

        // Check ecommerce scams
        if let Some(detector) = &self.ecommerce_scams {
            if let Some(domain) = extract_domain(&email_data.sender) {
                let result = detector.check_ecommerce_scam(
                    &email_data.subject,
                    &email_data.body,
                    &email_data.sender,
                    &domain,
                );
                if result.matched {
                    results.push(result);
                }
            }
        }

        // Check financial services
        if let Some(detector) = &self.financial_services {
            if let Some(domain) = extract_domain(&email_data.sender) {
                let result = detector.check_financial_scam(
                    &email_data.subject,
                    &email_data.body,
                    &email_data.sender,
                    &domain,
                );
                if result.matched {
                    results.push(result);
                }
            }
        }

        // Check technology scams
        if let Some(detector) = &self.technology_scams {
            if let Some(domain) = extract_domain(&email_data.sender) {
                let result = detector.check_technology_scam(
                    &email_data.subject,
                    &email_data.body,
                    &email_data.sender,
                    &domain,
                );
                if result.matched {
                    results.push(result);
                }
            }
        }

        // Check multi-language threats
        if let Some(detector) = &self.multi_language {
            if let Some(domain) = extract_domain(&email_data.sender) {
                let result = detector.check_multi_language_threat(
                    &email_data.subject,
                    &email_data.body,
                    &email_data.sender,
                    &domain,
                );
                if result.matched {
                    results.push(result);
                }
            }
        }

        self.finalize_results(results, start_time)
    }

    pub fn get_total_confidence(&self, results: &[DetectionResult]) -> u32 {
        results.iter().map(|r| r.confidence).sum()
    }

    fn finalize_results(
        &self,
        results: Vec<DetectionResult>,
        start_time: Instant,
    ) -> Vec<DetectionResult> {
        // Record overall processing time
        let total_time = start_time.elapsed().as_millis() as u64;
        if let Some(optimizer) = &self.performance_optimizer {
            optimizer.record_email_processed(total_time);
        }

        // ML enhancement (placeholder - would need email data)
        if let Some(_ml_engine) = &self.ml_engine {
            // Note: In real implementation, we'd extract features and get ML prediction
            // let features = ml_engine.extract_features(sender, subject, body);
            // let prediction = ml_engine.predict_threat(&features);
            // ml_engine.update_model(&features, !results.is_empty(), prediction.confidence);
        }

        // Record analytics event (placeholder - would need email data)
        if let Some(_analytics) = &self.analytics_engine {
            // Note: In real implementation, we'd pass email data here
            // analytics.record_email_event(sender, recipient, subject, &results, total_time);
        }

        results
    }

    pub fn get_performance_metrics(&self) -> Option<crate::performance::PerformanceMetrics> {
        self.performance_optimizer
            .as_ref()
            .and_then(|opt| opt.get_metrics())
    }

    pub fn reset_performance_metrics(&self) {
        if let Some(optimizer) = &self.performance_optimizer {
            optimizer.reset_metrics();
        }
    }

    pub fn cleanup_caches(&self) {
        if let Some(optimizer) = &self.performance_optimizer {
            optimizer.cleanup_caches();
        }
    }

    pub fn record_email_analytics(
        &self,
        sender: &str,
        recipient: &str,
        subject: &str,
        results: &[DetectionResult],
        processing_time_ms: u64,
    ) {
        if let Some(analytics) = &self.analytics_engine {
            analytics.record_email_event(sender, recipient, subject, results, processing_time_ms);
        }
    }

    pub fn get_analytics_dashboard(&self) -> Option<crate::analytics::DashboardData> {
        self.analytics_engine
            .as_ref()
            .and_then(|engine| engine.get_dashboard_data())
    }

    pub fn generate_analytics_report(
        &self,
        format: &str,
        time_range_hours: u32,
    ) -> Result<String, Box<dyn std::error::Error>> {
        match &self.analytics_engine {
            Some(engine) => engine.generate_report(format, time_range_hours),
            None => Err("Analytics engine not available".into()),
        }
    }

    pub fn check_analytics_alerts(&self) -> Vec<String> {
        self.analytics_engine
            .as_ref()
            .map(|engine| engine.check_alerts())
            .unwrap_or_default()
    }

    pub fn cleanup_analytics_data(&self) {
        if let Some(analytics) = &self.analytics_engine {
            analytics.cleanup_old_data();
        }
    }

    pub fn get_ml_prediction(
        &self,
        sender: &str,
        subject: &str,
        body: &str,
    ) -> Option<crate::machine_learning::MLPrediction> {
        if let Some(ml_engine) = &self.ml_engine {
            let features = ml_engine.extract_features(sender, subject, body);
            Some(ml_engine.predict_threat(&features))
        } else {
            None
        }
    }

    pub fn update_ml_model(
        &self,
        sender: &str,
        subject: &str,
        body: &str,
        is_threat: bool,
        confidence: f64,
    ) {
        if let Some(ml_engine) = &self.ml_engine {
            let features = ml_engine.extract_features(sender, subject, body);
            ml_engine.update_model(&features, is_threat, confidence);
        }
    }

    pub fn get_ml_performance(&self) -> Option<std::collections::HashMap<String, f64>> {
        self.ml_engine
            .as_ref()
            .map(|engine| engine.get_model_performance())
    }

    pub fn detect_threat_campaigns(&self) -> Vec<crate::machine_learning::ThreatCampaign> {
        self.ml_engine
            .as_ref()
            .map(|engine| engine.detect_campaigns())
            .unwrap_or_default()
    }

    pub fn cleanup_ml_data(&self) {
        if let Some(ml_engine) = &self.ml_engine {
            ml_engine.cleanup_old_data();
        }
    }

    pub fn process_api_request(
        &self,
        method: &str,
        path: &str,
        headers: &std::collections::HashMap<String, String>,
        body: &str,
    ) -> Result<serde_json::Value, String> {
        if let Some(integration) = &self.integration_engine {
            if !integration.authenticate_request(headers) {
                return Err("Authentication failed".to_string());
            }

            match (method, path) {
                ("POST", "/api/v1/email/analyze") => {
                    // Parse email data from body (simplified)
                    integration.process_email_api("sender@example.com", "Test Subject", body)
                }
                ("GET", "/api/v1/analytics/dashboard") => integration.get_analytics_api(),
                ("GET", "/api/v1/health") => Ok(integration.get_health_status()),
                _ => Err("Endpoint not found".to_string()),
            }
        } else {
            Err("Integration engine not available".to_string())
        }
    }

    pub fn send_webhook_notification(
        &self,
        event_type: &str,
        data: serde_json::Value,
        severity: &str,
    ) {
        if let Some(integration) = &self.integration_engine {
            integration.send_webhook(event_type, data, severity);
        }
    }

    pub fn send_siem_event(
        &self,
        sender: &str,
        recipient: &str,
        subject: &str,
        results: &[DetectionResult],
        action: &str,
    ) {
        if let Some(integration) = &self.integration_engine {
            integration.send_siem_event(sender, recipient, subject, results, action);
        }
    }

    pub fn export_data(
        &self,
        format: &str,
        start_time: u64,
        end_time: u64,
    ) -> Result<String, String> {
        if let Some(integration) = &self.integration_engine {
            integration.export_data(format, start_time, end_time)
        } else {
            Err("Integration engine not available".to_string())
        }
    }

    pub fn get_api_metrics(&self) -> std::collections::HashMap<String, u64> {
        self.integration_engine
            .as_ref()
            .map(|engine| engine.get_api_metrics())
            .unwrap_or_default()
    }

    pub fn cleanup_integration_data(&self) {
        if let Some(integration) = &self.integration_engine {
            integration.cleanup_old_data();
        }
    }

    pub fn scan_attachment(
        &self,
        filename: &str,
        content: &[u8],
    ) -> Option<crate::advanced_security::AttachmentScanResult> {
        self.advanced_security
            .as_ref()
            .map(|engine| engine.scan_attachment(filename, content))
    }

    pub fn scan_url(&self, url: &str) -> Option<crate::advanced_security::UrlScanResult> {
        self.advanced_security
            .as_ref()
            .map(|engine| engine.scan_url(url))
    }

    pub fn scan_image_ocr(
        &self,
        filename: &str,
        content: &[u8],
    ) -> Option<crate::advanced_security::ImageOcrResult> {
        self.advanced_security
            .as_ref()
            .map(|engine| engine.scan_image_ocr(filename, content))
    }

    pub fn get_security_scan_statistics(&self) -> std::collections::HashMap<String, u64> {
        self.advanced_security
            .as_ref()
            .map(|engine| engine.get_scan_statistics())
            .unwrap_or_default()
    }

    pub fn cleanup_security_caches(&self) {
        if let Some(advanced_security) = &self.advanced_security {
            advanced_security.cleanup_caches();
        }
    }
}

#[derive(Debug, Clone)]
pub struct EmailData {
    pub sender: String,
    pub from_header: String,
    pub subject: String,
    pub body: String,
    pub recipients: Vec<String>,
}

impl EmailData {
    pub fn new(
        sender: String,
        from_header: String,
        subject: String,
        body: String,
        recipients: Vec<String>,
    ) -> Self {
        Self {
            sender,
            from_header,
            subject,
            body,
            recipients,
        }
    }
}

fn extract_domain(email: &str) -> Option<String> {
    if let Some(at_pos) = email.rfind('@') {
        let domain = &email[at_pos + 1..];
        // Remove angle brackets if present
        let domain = domain.trim_end_matches('>');
        Some(domain.to_string())
    } else {
        None
    }
}
