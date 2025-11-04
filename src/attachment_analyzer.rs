use anyhow::Result;
use base64::prelude::*;

pub struct AttachmentAnalyzer;

impl AttachmentAnalyzer {
    pub fn analyze_attachment_content(content_type: &str, base64_content: &str) -> Result<Vec<String>> {
        let mut found_files = Vec::new();
        
        if content_type.contains("application/x-rar-compressed") 
            || content_type.contains("application/zip") 
            || content_type.contains("application/x-zip") {
            found_files.extend(Self::analyze_archive_content(base64_content)?);
        }
        
        Ok(found_files)
    }
    
    fn analyze_archive_content(base64_content: &str) -> Result<Vec<String>> {
        let mut filenames = Vec::new();
        
        // Try to decode base64 content
        if let Ok(decoded) = BASE64_STANDARD.decode(base64_content) {
            // Simple pattern matching in decoded content for now
            let content_str = String::from_utf8_lossy(&decoded);
            Self::extract_filenames_from_text(&content_str, &mut filenames);
        }
        
        Ok(filenames)
    }
    
    fn extract_filenames_from_text(content: &str, filenames: &mut Vec<String>) {
        // Look for common executable extensions in the content
        let patterns = [".exe", ".scr", ".bat", ".cmd", ".com", ".pif", ".vbs", ".js"];
        
        for pattern in &patterns {
            if let Some(pos) = content.find(pattern) {
                // Extract potential filename around the extension
                let start = content[..pos].rfind(|c: char| c.is_whitespace() || c == '\0' || c == '/')
                    .map(|i| i + 1).unwrap_or(0);
                let end = pos + pattern.len();
                
                if start < pos {
                    let filename = content[start..end].trim_matches('\0').trim();
                    if !filename.is_empty() && filename.len() < 100 {
                        filenames.push(filename.to_string());
                    }
                }
            }
        }
    }
    
    pub fn has_dangerous_files(filenames: &[String]) -> bool {
        let dangerous_extensions = [
            ".exe", ".scr", ".bat", ".cmd", ".com", ".pif", 
            ".vbs", ".js", ".jar", ".app", ".msi", ".run"
        ];
        
        filenames.iter().any(|filename| {
            dangerous_extensions.iter().any(|ext| 
                filename.to_lowercase().ends_with(ext)
            )
        })
    }
}
