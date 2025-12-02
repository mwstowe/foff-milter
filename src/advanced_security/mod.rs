use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Instant, SystemTime, UNIX_EPOCH};

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct AdvancedSecurityConfig {
    pub attachment_analysis: AttachmentAnalysis,
    pub pdf_analysis: PdfAnalysis,
    pub office_document_analysis: OfficeDocumentAnalysis,
    pub archive_analysis: ArchiveAnalysis,
    pub executable_analysis: ExecutableAnalysis,
    pub url_scanning: UrlScanning,
    pub url_reputation: UrlReputation,
    pub phishing_url_detection: PhishingUrlDetection,
    pub image_ocr: ImageOcr,
    pub behavioral_sandboxing: BehavioralSandboxing,
    pub threat_intelligence: ThreatIntelligence,
    pub performance_settings: PerformanceSettings,
    pub security_policies: SecurityPolicies,
    pub notification_settings: NotificationSettings,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct AttachmentAnalysis {
    pub enabled: bool,
    pub max_file_size_mb: u32,
    pub timeout_seconds: u64,
    pub scan_types: Vec<String>,
    pub deep_inspection: bool,
    pub metadata_extraction: bool,
    pub embedded_content_scan: bool,
    pub macro_detection: bool,
    pub password_protected_scan: bool,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct PdfAnalysis {
    pub enabled: bool,
    pub javascript_detection: bool,
    pub embedded_file_extraction: bool,
    pub form_analysis: bool,
    pub suspicious_structure_detection: bool,
    pub metadata_analysis: bool,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct OfficeDocumentAnalysis {
    pub enabled: bool,
    pub macro_detection: bool,
    pub external_link_detection: bool,
    pub embedded_object_scan: bool,
    pub template_injection_detection: bool,
    pub vba_code_analysis: bool,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct ArchiveAnalysis {
    pub enabled: bool,
    pub max_extraction_depth: u32,
    pub max_files_per_archive: u32,
    pub nested_archive_detection: bool,
    pub suspicious_filename_detection: bool,
    pub compression_ratio_analysis: bool,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct ExecutableAnalysis {
    pub enabled: bool,
    pub pe_header_analysis: bool,
    pub digital_signature_verification: bool,
    pub entropy_analysis: bool,
    pub suspicious_section_detection: bool,
    pub packer_detection: bool,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct UrlScanning {
    pub enabled: bool,
    pub real_time_scanning: bool,
    pub reputation_checking: bool,
    pub redirect_following: bool,
    pub max_redirects: u32,
    pub timeout_seconds: u64,
    pub phishing_detection: bool,
    pub malware_detection: bool,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct UrlReputation {
    pub enabled: bool,
    pub reputation_sources: Vec<String>,
    pub cache_duration_hours: u32,
    pub min_reputation_score: f64,
    pub whitelist_domains: Vec<String>,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct PhishingUrlDetection {
    pub enabled: bool,
    pub homograph_detection: bool,
    pub typosquatting_detection: bool,
    pub suspicious_tld_detection: bool,
    pub url_shortener_detection: bool,
    pub brand_impersonation_detection: bool,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct ImageOcr {
    pub enabled: bool,
    pub supported_formats: Vec<String>,
    pub max_image_size_mb: u32,
    pub ocr_timeout_seconds: u64,
    pub text_extraction: bool,
    pub suspicious_text_detection: bool,
    pub qr_code_detection: bool,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct BehavioralSandboxing {
    pub enabled: bool,
    pub sandbox_timeout_seconds: u64,
    pub file_execution_analysis: bool,
    pub network_behavior_analysis: bool,
    pub registry_modification_detection: bool,
    pub file_system_changes: bool,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct ThreatIntelligence {
    pub enabled: bool,
    pub hash_reputation: bool,
    pub domain_reputation: bool,
    pub ip_reputation: bool,
    pub file_signature_matching: bool,
    pub yara_rules: bool,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct PerformanceSettings {
    pub parallel_scanning: bool,
    pub max_concurrent_scans: u32,
    pub scan_cache_enabled: bool,
    pub cache_size_mb: u32,
    pub scan_queue_size: u32,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct SecurityPolicies {
    pub quarantine_suspicious_files: bool,
    pub block_password_protected_archives: bool,
    pub block_executable_attachments: bool,
    pub block_suspicious_urls: bool,
    pub log_all_scans: bool,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct NotificationSettings {
    pub alert_on_malware: bool,
    pub alert_on_suspicious_attachment: bool,
    pub alert_on_phishing_url: bool,
    pub alert_on_ocr_threats: bool,
    pub detailed_scan_reports: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct AttachmentScanResult {
    pub filename: String,
    pub file_type: String,
    pub file_size: u64,
    pub scan_time_ms: u64,
    pub threat_detected: bool,
    pub threat_type: String,
    pub confidence: f64,
    pub details: HashMap<String, String>,
    pub hash_md5: String,
    pub hash_sha256: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct UrlScanResult {
    pub url: String,
    pub final_url: String,
    pub redirect_count: u32,
    pub scan_time_ms: u64,
    pub threat_detected: bool,
    pub threat_type: String,
    pub reputation_score: f64,
    pub phishing_indicators: Vec<String>,
    pub malware_indicators: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ImageOcrResult {
    pub filename: String,
    pub image_format: String,
    pub extracted_text: String,
    pub qr_codes: Vec<String>,
    pub suspicious_content: bool,
    pub threat_indicators: Vec<String>,
    pub confidence: f64,
}

#[derive(Debug, Clone, Serialize)]
pub struct SecurityScanSummary {
    pub total_attachments: u32,
    pub total_urls: u32,
    pub total_images: u32,
    pub threats_detected: u32,
    pub scan_time_ms: u64,
    pub attachment_results: Vec<AttachmentScanResult>,
    pub url_results: Vec<UrlScanResult>,
    pub image_results: Vec<ImageOcrResult>,
}

pub struct AdvancedSecurityEngine {
    config: AdvancedSecurityConfig,
    scan_cache: Arc<Mutex<HashMap<String, AttachmentScanResult>>>,
    url_cache: Arc<Mutex<HashMap<String, UrlScanResult>>>,
    reputation_cache: Arc<Mutex<HashMap<String, (f64, u64)>>>, // (score, timestamp)
    scan_statistics: Arc<Mutex<HashMap<String, u64>>>,
}

impl AdvancedSecurityEngine {
    pub fn new(config: AdvancedSecurityConfig) -> Self {
        Self {
            config,
            scan_cache: Arc::new(Mutex::new(HashMap::new())),
            url_cache: Arc::new(Mutex::new(HashMap::new())),
            reputation_cache: Arc::new(Mutex::new(HashMap::new())),
            scan_statistics: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    pub fn load_from_file(path: &str) -> Result<Self, Box<dyn std::error::Error>> {
        let content = std::fs::read_to_string(path)?;
        let config: AdvancedSecurityConfig = serde_yml::from_str(&content)?;
        Ok(Self::new(config))
    }

    pub fn scan_attachment(&self, filename: &str, content: &[u8]) -> AttachmentScanResult {
        let start_time = Instant::now();

        if !self.config.attachment_analysis.enabled {
            return AttachmentScanResult {
                filename: filename.to_string(),
                file_type: self.detect_file_type(filename, content),
                file_size: content.len() as u64,
                scan_time_ms: start_time.elapsed().as_millis() as u64,
                threat_detected: false,
                threat_type: "none".to_string(),
                confidence: 0.0,
                details: HashMap::new(),
                hash_md5: self.calculate_md5(content),
                hash_sha256: self.calculate_sha256(content),
            };
        }

        // Check cache first
        let hash = self.calculate_sha256(content);
        if let Ok(cache) = self.scan_cache.lock() {
            if let Some(cached_result) = cache.get(&hash) {
                return cached_result.clone();
            }
        }

        let file_type = self.detect_file_type(filename, content);
        let mut threat_detected = false;
        let mut threat_type = "none".to_string();
        let mut confidence = 0.0;
        let mut details = HashMap::new();

        // File size check
        if content.len() > (self.config.attachment_analysis.max_file_size_mb as usize * 1024 * 1024)
        {
            threat_detected = true;
            threat_type = "oversized_file".to_string();
            confidence = 0.8;
            details.insert(
                "reason".to_string(),
                "File exceeds maximum size limit".to_string(),
            );
        }

        // Executable detection
        if self.config.executable_analysis.enabled
            && self.is_executable(&file_type)
            && self.config.security_policies.block_executable_attachments
        {
            threat_detected = true;
            threat_type = "executable_attachment".to_string();
            confidence = 0.9;
            details.insert(
                "reason".to_string(),
                "Executable attachment blocked by policy".to_string(),
            );
        }

        // PDF analysis
        if self.config.pdf_analysis.enabled && file_type == "pdf" {
            let pdf_threats = self.analyze_pdf(content);
            if !pdf_threats.is_empty() {
                threat_detected = true;
                threat_type = "malicious_pdf".to_string();
                confidence = 0.85;
                details.insert("pdf_threats".to_string(), pdf_threats.join(", "));
            }
        }

        // Office document analysis
        if self.config.office_document_analysis.enabled && self.is_office_document(&file_type) {
            let office_threats = self.analyze_office_document(content);
            if !office_threats.is_empty() {
                threat_detected = true;
                threat_type = "malicious_office_document".to_string();
                confidence = 0.8;
                details.insert("office_threats".to_string(), office_threats.join(", "));
            }
        }

        // Archive analysis
        if self.config.archive_analysis.enabled && self.is_archive(&file_type) {
            let archive_threats = self.analyze_archive(content);
            if !archive_threats.is_empty() {
                threat_detected = true;
                threat_type = "malicious_archive".to_string();
                confidence = 0.75;
                details.insert("archive_threats".to_string(), archive_threats.join(", "));
            }
        }

        let result = AttachmentScanResult {
            filename: filename.to_string(),
            file_type,
            file_size: content.len() as u64,
            scan_time_ms: start_time.elapsed().as_millis() as u64,
            threat_detected,
            threat_type,
            confidence,
            details,
            hash_md5: self.calculate_md5(content),
            hash_sha256: hash.clone(),
        };

        // Cache result
        if let Ok(mut cache) = self.scan_cache.lock() {
            cache.insert(hash, result.clone());
            // Limit cache size
            if cache.len() > 1000 {
                let keys_to_remove: Vec<String> = cache.keys().take(100).cloned().collect();
                for key in keys_to_remove {
                    cache.remove(&key);
                }
            }
        }

        // Update statistics
        self.update_scan_statistics("attachments_scanned", 1);
        if threat_detected {
            self.update_scan_statistics("threats_detected", 1);
        }

        result
    }

    pub fn scan_url(&self, url: &str) -> UrlScanResult {
        let start_time = Instant::now();

        if !self.config.url_scanning.enabled {
            return UrlScanResult {
                url: url.to_string(),
                final_url: url.to_string(),
                redirect_count: 0,
                scan_time_ms: start_time.elapsed().as_millis() as u64,
                threat_detected: false,
                threat_type: "none".to_string(),
                reputation_score: 1.0,
                phishing_indicators: Vec::new(),
                malware_indicators: Vec::new(),
            };
        }

        // Check cache first
        if let Ok(cache) = self.url_cache.lock() {
            if let Some(cached_result) = cache.get(url) {
                return cached_result.clone();
            }
        }

        let mut threat_detected = false;
        let mut threat_type = "none".to_string();
        let mut phishing_indicators = Vec::new();
        let mut malware_indicators = Vec::new();
        let final_url = url.to_string();
        let redirect_count = 0;

        // Domain whitelist check
        if self.is_whitelisted_domain(url) {
            let result = UrlScanResult {
                url: url.to_string(),
                final_url,
                redirect_count,
                scan_time_ms: start_time.elapsed().as_millis() as u64,
                threat_detected: false,
                threat_type: "whitelisted".to_string(),
                reputation_score: 1.0,
                phishing_indicators,
                malware_indicators,
            };
            return result;
        }

        // Phishing detection
        if self.config.phishing_url_detection.enabled {
            let phishing_checks = self.detect_phishing_indicators(url);
            if !phishing_checks.is_empty() {
                threat_detected = true;
                threat_type = "phishing_url".to_string();
                phishing_indicators = phishing_checks;
            }
        }

        // URL shortener detection
        if self.config.phishing_url_detection.url_shortener_detection && self.is_url_shortener(url)
        {
            phishing_indicators.push("url_shortener".to_string());
            if !threat_detected {
                threat_detected = true;
                threat_type = "suspicious_url_shortener".to_string();
            }
        }

        // Reputation checking
        let reputation_score = if self.config.url_reputation.enabled {
            self.check_url_reputation(url)
        } else {
            1.0
        };

        if reputation_score < self.config.url_reputation.min_reputation_score {
            threat_detected = true;
            threat_type = "low_reputation_url".to_string();
            malware_indicators.push("low_reputation".to_string());
        }

        let result = UrlScanResult {
            url: url.to_string(),
            final_url,
            redirect_count,
            scan_time_ms: start_time.elapsed().as_millis() as u64,
            threat_detected,
            threat_type,
            reputation_score,
            phishing_indicators,
            malware_indicators,
        };

        // Cache result
        if let Ok(mut cache) = self.url_cache.lock() {
            cache.insert(url.to_string(), result.clone());
            // Limit cache size
            if cache.len() > 1000 {
                let keys_to_remove: Vec<String> = cache.keys().take(100).cloned().collect();
                for key in keys_to_remove {
                    cache.remove(&key);
                }
            }
        }

        // Update statistics
        self.update_scan_statistics("urls_scanned", 1);
        if threat_detected {
            self.update_scan_statistics("url_threats_detected", 1);
        }

        result
    }

    pub fn scan_image_ocr(&self, filename: &str, content: &[u8]) -> ImageOcrResult {
        if !self.config.image_ocr.enabled {
            return ImageOcrResult {
                filename: filename.to_string(),
                image_format: self.detect_image_format(filename),
                extracted_text: String::new(),
                qr_codes: Vec::new(),
                suspicious_content: false,
                threat_indicators: Vec::new(),
                confidence: 0.0,
            };
        }

        let image_format = self.detect_image_format(filename);
        if !self
            .config
            .image_ocr
            .supported_formats
            .contains(&image_format)
        {
            return ImageOcrResult {
                filename: filename.to_string(),
                image_format,
                extracted_text: String::new(),
                qr_codes: Vec::new(),
                suspicious_content: false,
                threat_indicators: Vec::new(),
                confidence: 0.0,
            };
        }

        // Simulate OCR text extraction
        let extracted_text = self.extract_text_from_image(content);
        let qr_codes = if self.config.image_ocr.qr_code_detection {
            self.extract_qr_codes(content)
        } else {
            Vec::new()
        };

        let mut suspicious_content = false;
        let mut threat_indicators = Vec::new();
        let mut confidence: f64 = 0.0;

        // Analyze extracted text for threats
        if self.config.image_ocr.suspicious_text_detection {
            let text_threats = self.analyze_extracted_text(&extracted_text);
            if !text_threats.is_empty() {
                suspicious_content = true;
                threat_indicators = text_threats;
                confidence = 0.7;
            }
        }

        // Analyze QR codes
        for qr_code in &qr_codes {
            if self.is_suspicious_qr_content(qr_code) {
                suspicious_content = true;
                threat_indicators.push("suspicious_qr_code".to_string());
                confidence = confidence.max(0.6);
            }
        }

        ImageOcrResult {
            filename: filename.to_string(),
            image_format,
            extracted_text,
            qr_codes,
            suspicious_content,
            threat_indicators,
            confidence,
        }
    }

    fn detect_file_type(&self, filename: &str, content: &[u8]) -> String {
        // Simple file type detection based on extension and magic bytes
        if let Some(ext) = filename.split('.').next_back() {
            match ext.to_lowercase().as_str() {
                "pdf" => "pdf".to_string(),
                "doc" | "docx" => "office_document".to_string(),
                "xls" | "xlsx" => "office_spreadsheet".to_string(),
                "ppt" | "pptx" => "office_presentation".to_string(),
                "zip" | "rar" | "7z" => "archive".to_string(),
                "exe" | "dll" | "scr" => "executable".to_string(),
                "jpg" | "jpeg" | "png" | "gif" | "bmp" => "image".to_string(),
                _ => "unknown".to_string(),
            }
        } else {
            // Check magic bytes
            if content.len() >= 4 {
                match &content[0..4] {
                    [0x25, 0x50, 0x44, 0x46] => "pdf".to_string(), // %PDF
                    [0x50, 0x4B, 0x03, 0x04] => "archive".to_string(), // ZIP
                    [0x4D, 0x5A, _, _] => "executable".to_string(), // MZ (PE)
                    _ => "unknown".to_string(),
                }
            } else {
                "unknown".to_string()
            }
        }
    }

    fn is_executable(&self, file_type: &str) -> bool {
        matches!(file_type, "executable")
    }

    fn is_office_document(&self, file_type: &str) -> bool {
        matches!(
            file_type,
            "office_document" | "office_spreadsheet" | "office_presentation"
        )
    }

    fn is_archive(&self, file_type: &str) -> bool {
        matches!(file_type, "archive")
    }

    fn analyze_pdf(&self, _content: &[u8]) -> Vec<String> {
        let mut threats = Vec::new();

        // Simulate PDF analysis
        if self.config.pdf_analysis.javascript_detection {
            // Check for JavaScript in PDF (simplified)
            threats.push("javascript_detected".to_string());
        }

        if self.config.pdf_analysis.suspicious_structure_detection {
            // Check for suspicious PDF structure
            threats.push("suspicious_structure".to_string());
        }

        threats
    }

    fn analyze_office_document(&self, _content: &[u8]) -> Vec<String> {
        let mut threats = Vec::new();

        // Simulate Office document analysis
        if self.config.office_document_analysis.macro_detection {
            threats.push("macro_detected".to_string());
        }

        if self.config.office_document_analysis.external_link_detection {
            threats.push("external_links_detected".to_string());
        }

        threats
    }

    fn analyze_archive(&self, _content: &[u8]) -> Vec<String> {
        let mut threats = Vec::new();

        // Simulate archive analysis
        if self.config.archive_analysis.suspicious_filename_detection {
            threats.push("suspicious_filenames".to_string());
        }

        if self.config.archive_analysis.nested_archive_detection {
            threats.push("nested_archives".to_string());
        }

        threats
    }

    fn detect_phishing_indicators(&self, url: &str) -> Vec<String> {
        let mut indicators = Vec::new();

        // Homograph detection
        if self.config.phishing_url_detection.homograph_detection
            && self.contains_homograph_characters(url)
        {
            indicators.push("homograph_characters".to_string());
        }

        // Typosquatting detection
        if self.config.phishing_url_detection.typosquatting_detection
            && self.is_typosquatting_domain(url)
        {
            indicators.push("typosquatting".to_string());
        }

        // Suspicious TLD detection
        if self.config.phishing_url_detection.suspicious_tld_detection
            && self.has_suspicious_tld(url)
        {
            indicators.push("suspicious_tld".to_string());
        }

        indicators
    }

    fn contains_homograph_characters(&self, url: &str) -> bool {
        // Check for common homograph characters used in phishing
        url.chars().any(|c| matches!(c, 'а'..='я' | 'А'..='Я')) // Cyrillic characters
    }

    fn is_typosquatting_domain(&self, url: &str) -> bool {
        // Simple typosquatting detection
        let suspicious_patterns = ["g00gle", "micr0soft", "amaz0n", "payp4l"];
        suspicious_patterns
            .iter()
            .any(|pattern| url.contains(pattern))
    }

    fn has_suspicious_tld(&self, url: &str) -> bool {
        let suspicious_tlds = [".tk", ".ml", ".ga", ".cf"];
        suspicious_tlds.iter().any(|tld| url.contains(tld))
    }

    fn is_url_shortener(&self, url: &str) -> bool {
        let shorteners = ["bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly"];
        shorteners.iter().any(|shortener| url.contains(shortener))
    }

    fn is_whitelisted_domain(&self, url: &str) -> bool {
        self.config
            .url_reputation
            .whitelist_domains
            .iter()
            .any(|domain| url.contains(domain))
    }

    fn check_url_reputation(&self, url: &str) -> f64 {
        // Check cache first
        if let Ok(cache) = self.reputation_cache.lock() {
            if let Some((score, timestamp)) = cache.get(url) {
                let cache_age_hours = (SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs()
                    - timestamp)
                    / 3600;
                if cache_age_hours < self.config.url_reputation.cache_duration_hours as u64 {
                    return *score;
                }
            }
        }

        // Simulate reputation check
        let reputation_score = if self.is_suspicious_domain(url) {
            0.3
        } else {
            0.8
        };

        // Cache result
        if let Ok(mut cache) = self.reputation_cache.lock() {
            cache.insert(
                url.to_string(),
                (
                    reputation_score,
                    SystemTime::now()
                        .duration_since(UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_secs(),
                ),
            );
        }

        reputation_score
    }

    fn is_suspicious_domain(&self, url: &str) -> bool {
        // Simple suspicious domain detection
        url.contains("suspicious") || url.contains("malware") || url.contains("phishing")
    }

    fn detect_image_format(&self, filename: &str) -> String {
        if let Some(ext) = filename.split('.').next_back() {
            ext.to_lowercase()
        } else {
            "unknown".to_string()
        }
    }

    fn extract_text_from_image(&self, content: &[u8]) -> String {
        #[cfg(feature = "ocr")]
        {
            // Try to load image and extract text with tesseract
            match image::load_from_memory(content) {
                Ok(img) => {
                    // Convert to RGB format for tesseract
                    let rgb_img = img.to_rgb8();
                    let (width, height) = rgb_img.dimensions();

                    // Initialize tesseract
                    let tesseract = tesseract_rs::TesseractAPI::new();

                    // Initialize with English language (use empty string for default datapath)
                    if tesseract.init("", "eng").is_ok() {
                        // Set image data
                        let _ = tesseract.set_image(
                            &rgb_img,
                            width as i32,
                            height as i32,
                            3,
                            (width * 3) as i32,
                        );

                        // Extract text
                        match tesseract.get_utf8_text() {
                            Ok(text) => {
                                log::debug!("OCR extracted {} characters from image", text.len());
                                text.trim().to_string()
                            }
                            Err(e) => {
                                log::warn!("OCR text extraction failed: {}", e);
                                String::new()
                            }
                        }
                    } else {
                        log::warn!("Failed to initialize tesseract with English language");
                        String::new()
                    }
                }
                Err(e) => {
                    log::warn!("Failed to load image for OCR: {}", e);
                    String::new()
                }
            }
        }

        #[cfg(not(feature = "ocr"))]
        {
            let _ = content; // Suppress unused variable warning
            log::debug!("OCR feature not enabled, skipping text extraction");
            String::new()
        }
    }

    fn extract_qr_codes(&self, content: &[u8]) -> Vec<String> {
        #[cfg(feature = "ocr")]
        {
            // For now, use OCR to detect QR-like patterns in text
            let extracted_text = self.extract_text_from_image(content);
            let mut qr_codes = Vec::new();

            // Look for URL patterns that might be from QR codes
            let url_patterns = [
                r"https?://[^\s]+",
                r"www\.[^\s]+",
                r"[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}[^\s]*",
            ];

            for pattern in &url_patterns {
                if let Ok(regex) = regex::Regex::new(pattern) {
                    for mat in regex.find_iter(&extracted_text) {
                        let url = mat.as_str().to_string();
                        if url.len() > 10 {
                            // Filter out very short matches
                            qr_codes.push(url);
                        }
                    }
                }
            }

            // Remove duplicates
            qr_codes.sort();
            qr_codes.dedup();

            if !qr_codes.is_empty() {
                log::debug!(
                    "Detected {} potential QR code URLs in image",
                    qr_codes.len()
                );
            }

            qr_codes
        }

        #[cfg(not(feature = "ocr"))]
        {
            let _ = content; // Suppress unused variable warning
            log::debug!("OCR feature not enabled, skipping QR code detection");
            Vec::new()
        }
    }

    fn analyze_extracted_text(&self, text: &str) -> Vec<String> {
        let mut threats = Vec::new();

        if text.is_empty() {
            return threats;
        }

        let text_lower = text.to_lowercase();

        // Urgency indicators
        let urgency_keywords = [
            "urgent",
            "asap",
            "immediate",
            "emergency",
            "critical",
            "act now",
            "limited time",
            "expires today",
            "final notice",
        ];

        // Financial/security threats
        let security_keywords = [
            "verify account",
            "confirm identity",
            "update payment",
            "suspended account",
            "click here",
            "login now",
            "reset password",
        ];

        // Scam indicators
        let scam_keywords = [
            "congratulations",
            "winner",
            "prize",
            "lottery",
            "inheritance",
            "tax refund",
            "government grant",
            "free money",
            "claim now",
        ];

        // Check for patterns
        for keyword in urgency_keywords {
            if text_lower.contains(keyword) {
                threats.push(format!("urgency_indicator_{}", keyword.replace(' ', "_")));
            }
        }

        for keyword in security_keywords {
            if text_lower.contains(keyword) {
                threats.push(format!("security_threat_{}", keyword.replace(' ', "_")));
            }
        }

        for keyword in scam_keywords {
            if text_lower.contains(keyword) {
                threats.push(format!("scam_indicator_{}", keyword.replace(' ', "_")));
            }
        }

        // Check for suspicious patterns
        if text_lower.contains("http")
            && (text_lower.contains("verify") || text_lower.contains("click"))
        {
            threats.push("suspicious_link_with_action".to_string());
        }

        // Check for phone numbers with urgency
        if text.contains(char::is_numeric)
            && (text_lower.contains("call") || text_lower.contains("urgent"))
        {
            threats.push("suspicious_phone_with_urgency".to_string());
        }

        log::debug!(
            "OCR text analysis found {} threat indicators in {} characters",
            threats.len(),
            text.len()
        );

        threats
    }

    fn is_suspicious_qr_content(&self, qr_content: &str) -> bool {
        qr_content.contains("suspicious") || qr_content.contains("malware")
    }

    fn calculate_md5(&self, content: &[u8]) -> String {
        // Simulate MD5 hash calculation
        format!("md5_{}", content.len())
    }

    fn calculate_sha256(&self, content: &[u8]) -> String {
        // Simulate SHA256 hash calculation
        format!("sha256_{}", content.len())
    }

    fn update_scan_statistics(&self, metric: &str, value: u64) {
        if let Ok(mut stats) = self.scan_statistics.lock() {
            *stats.entry(metric.to_string()).or_insert(0) += value;
        }
    }

    pub fn get_scan_statistics(&self) -> HashMap<String, u64> {
        match self.scan_statistics.lock() {
            Ok(stats) => stats.clone(),
            Err(_) => {
                log::error!("Failed to lock scan_statistics mutex");
                HashMap::new()
            }
        }
    }

    pub fn cleanup_caches(&self) {
        if let Ok(mut cache) = self.scan_cache.lock() {
            cache.clear();
        }
        if let Ok(mut cache) = self.url_cache.lock() {
            cache.clear();
        }
        if let Ok(mut cache) = self.reputation_cache.lock() {
            cache.clear();
        }
    }
}
