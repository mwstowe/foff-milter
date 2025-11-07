use base64::Engine;
use regex::Regex;

#[derive(Debug, Clone)]
pub struct MediaAnalyzer {
    spam_patterns: Vec<Regex>,
}

#[derive(Debug, Clone)]
pub struct MediaAnalysis {
    pub extracted_text: String,
    pub spam_score: f32,
    pub detected_patterns: Vec<String>,
}

impl Default for MediaAnalyzer {
    fn default() -> Self {
        Self::new()
    }
}

impl MediaAnalyzer {
    pub fn new() -> Self {
        Self {
            spam_patterns: vec![
                // Adult content
                Regex::new(r"(?i)(viagra|cialis|penis|enlargement|sexual|erection|adult|xxx)")
                    .unwrap(),
                // Financial scams
                Regex::new(r"(?i)(bitcoin|crypto|investment|profit|guaranteed|roi|trading)")
                    .unwrap(),
                // Health scams
                Regex::new(r"(?i)(miracle|cure|lose.*weight|doctor.*hate|breakthrough|supplement)")
                    .unwrap(),
                // Urgency patterns
                Regex::new(r"(?i)(act.*now|limited.*time|expires|urgent|immediate|offer.*ends)")
                    .unwrap(),
                // Brand impersonation
                Regex::new(r"(?i)(norton|mcafee|microsoft|apple|amazon|paypal|invoice|overdue)")
                    .unwrap(),
            ],
        }
    }

    pub fn analyze_attachment(&self, filename: &str, content: &[u8]) -> MediaAnalysis {
        let extracted_text = if filename.to_lowercase().ends_with(".pdf") {
            self.extract_pdf_text(content)
        } else if self.is_image_file(filename) {
            // For now, just detect suspicious image patterns without OCR
            self.analyze_image_metadata(content)
        } else {
            String::new()
        };

        let (spam_score, detected_patterns) = self.analyze_text(&extracted_text);

        MediaAnalysis {
            extracted_text,
            spam_score,
            detected_patterns,
        }
    }

    pub fn analyze_embedded_image(&self, base64_data: &str) -> MediaAnalysis {
        match base64::engine::general_purpose::STANDARD.decode(base64_data) {
            Ok(image_data) => {
                let extracted_text = self.analyze_image_metadata(&image_data);
                let (spam_score, detected_patterns) = self.analyze_text(&extracted_text);

                MediaAnalysis {
                    extracted_text,
                    spam_score,
                    detected_patterns,
                }
            }
            Err(_) => MediaAnalysis {
                extracted_text: String::new(),
                spam_score: 0.0,
                detected_patterns: vec![],
            },
        }
    }

    fn extract_pdf_text(&self, content: &[u8]) -> String {
        match pdf_extract::extract_text_from_mem(content) {
            Ok(text) => {
                log::debug!("Successfully extracted {} chars from PDF", text.len());
                text
            }
            Err(e) => {
                log::debug!("Failed to extract PDF text: {}", e);
                String::new()
            }
        }
    }

    fn analyze_image_metadata(&self, content: &[u8]) -> String {
        // Basic image analysis - check for suspicious patterns in metadata
        // This is a placeholder for future OCR integration
        let content_str = String::from_utf8_lossy(content);

        // Look for text-like patterns in image metadata/EXIF data
        let mut extracted_text = String::new();

        // Check for common spam keywords that might appear in image metadata
        for pattern in &self.spam_patterns {
            if pattern.is_match(&content_str) {
                extracted_text.push_str("Suspicious content detected in image metadata ");
                break;
            }
        }

        extracted_text
    }

    fn is_image_file(&self, filename: &str) -> bool {
        let lower = filename.to_lowercase();
        lower.ends_with(".jpg")
            || lower.ends_with(".jpeg")
            || lower.ends_with(".png")
            || lower.ends_with(".gif")
            || lower.ends_with(".bmp")
            || lower.ends_with(".webp")
    }

    fn analyze_text(&self, text: &str) -> (f32, Vec<String>) {
        let mut score = 0.0;
        let mut patterns = Vec::new();

        if text.is_empty() {
            return (score, patterns);
        }

        for pattern in &self.spam_patterns {
            if pattern.is_match(text) {
                score += 25.0;
                patterns.push(format!(
                    "Spam pattern in media content: {}",
                    pattern.as_str()
                ));
            }
        }

        // Additional scoring for PDF-specific spam indicators
        if text.contains("invoice") && text.contains("overdue") {
            score += 50.0;
            patterns.push("PDF invoice scam detected".to_string());
        }

        if text.contains("bitcoin") || text.contains("cryptocurrency") {
            score += 40.0;
            patterns.push("Cryptocurrency scam in PDF".to_string());
        }

        (score, patterns)
    }
}
