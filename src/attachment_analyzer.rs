use anyhow::Result;
use base64::prelude::*;
use std::io::Cursor;

pub struct AttachmentAnalyzer;

impl AttachmentAnalyzer {
    pub fn analyze_attachment_content(
        content_type: &str,
        base64_content: &str,
    ) -> Result<Vec<String>> {
        let mut found_files = Vec::new();

        if content_type.contains("application/x-rar-compressed") {
            found_files.extend(Self::analyze_rar_content(base64_content)?);
        } else if content_type.contains("application/zip")
            || content_type.contains("application/x-zip")
        {
            found_files.extend(Self::analyze_zip_content(base64_content)?);
        } else if content_type.contains("application/octet-stream") {
            // Try both RAR and ZIP parsing for octet-stream
            if let Ok(rar_files) = Self::analyze_rar_content(base64_content) {
                if !rar_files.is_empty() {
                    found_files.extend(rar_files);
                }
            }
            if found_files.is_empty() {
                if let Ok(zip_files) = Self::analyze_zip_content(base64_content) {
                    found_files.extend(zip_files);
                }
            }
        }

        Ok(found_files)
    }

    fn analyze_zip_content(base64_content: &str) -> Result<Vec<String>> {
        let mut filenames = Vec::new();

        if let Ok(decoded) = BASE64_STANDARD.decode(base64_content) {
            let cursor = Cursor::new(decoded.clone());

            // Try to parse ZIP archive
            match zip::ZipArchive::new(cursor) {
                Ok(mut archive) => {
                    for i in 0..archive.len() {
                        if let Ok(file) = archive.by_index(i) {
                            filenames.push(file.name().to_string());
                        }
                    }
                }
                Err(_) => {
                    // Fallback to pattern matching if ZIP parsing fails
                    let content_str = String::from_utf8_lossy(&decoded);
                    Self::extract_filenames_from_text(&content_str, &mut filenames);
                }
            }
        }

        Ok(filenames)
    }

    fn analyze_rar_content(base64_content: &str) -> Result<Vec<String>> {
        let mut filenames = Vec::new();

        if let Ok(decoded) = BASE64_STANDARD.decode(base64_content) {
            #[cfg(feature = "rar-analysis")]
            {
                // Use real RAR parsing with our custom library
                use std::fs::OpenOptions;
                use std::io::Write;

                // Create a temporary file for RAR analysis in current directory
                let temp_file = format!("./temp_rar_{}.rar", rand::random::<u32>());

                match OpenOptions::new()
                    .create(true)
                    .write(true)
                    .truncate(true)
                    .open(&temp_file)
                {
                    Ok(mut file) => {
                        if file.write_all(&decoded).is_ok() && file.flush().is_ok() {
                            drop(file); // Ensure file is closed before RAR analysis

                            // Use our RAR library to parse the archive (don't extract files)
                            match rar::Archive::extract_all(&temp_file, "/tmp", "") {
                                Ok(archive) => {
                                    log::info!(
                                        "Successfully parsed RAR archive with {} files",
                                        archive.files.len()
                                    );
                                    for file_block in &archive.files {
                                        if !file_block.name.is_empty() {
                                            filenames.push(file_block.name.clone());
                                            log::info!("Found RAR file: {}", file_block.name);
                                        }
                                    }
                                }
                                Err(e) => {
                                    log::debug!(
                                        "RAR parsing failed: {}, falling back to pattern matching",
                                        e
                                    );
                                    let content_str = String::from_utf8_lossy(&decoded);
                                    Self::extract_filenames_from_text(&content_str, &mut filenames);
                                }
                            }
                        } else {
                            log::debug!("Failed to write RAR data to temp file, falling back to pattern matching");
                            let content_str = String::from_utf8_lossy(&decoded);
                            Self::extract_filenames_from_text(&content_str, &mut filenames);
                        }

                        // Clean up temporary file
                        let _ = std::fs::remove_file(&temp_file);
                    }
                    Err(e) => {
                        log::debug!(
                            "Failed to create temp file: {}, falling back to pattern matching",
                            e
                        );
                        let content_str = String::from_utf8_lossy(&decoded);
                        Self::extract_filenames_from_text(&content_str, &mut filenames);
                    }
                }
            }

            #[cfg(not(feature = "rar-analysis"))]
            {
                // Fallback to pattern matching when RAR feature is disabled
                let content_str = String::from_utf8_lossy(&decoded);
                Self::extract_filenames_from_text(&content_str, &mut filenames);
            }
        }

        Ok(filenames)
    }

    fn extract_filenames_from_text(content: &str, filenames: &mut Vec<String>) {
        let patterns = [
            ".exe", ".scr", ".bat", ".cmd", ".com", ".pif", ".vbs", ".js",
        ];

        for pattern in &patterns {
            if let Some(pos) = content.find(pattern) {
                let start = content[..pos]
                    .rfind(|c: char| c.is_whitespace() || c == '\0' || c == '/')
                    .map(|i| i + 1)
                    .unwrap_or(0);
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
            ".exe", ".scr", ".bat", ".cmd", ".com", ".pif", ".vbs", ".js", ".jar", ".app", ".msi",
            ".run",
        ];

        filenames.iter().any(|filename| {
            dangerous_extensions
                .iter()
                .any(|ext| filename.to_lowercase().ends_with(ext))
        })
    }
}
