use base64::{engine::general_purpose, Engine as _};
use regex::Regex;
use std::collections::HashMap;

#[derive(Debug, Clone)]
pub struct NormalizedEmail {
    pub headers: HashMap<String, String>,
    pub subject: NormalizedText,
    pub body_text: NormalizedText,
    pub body_html: NormalizedText,
    pub sender_info: SenderInfo,
}

#[derive(Debug, Clone)]
pub struct NormalizedText {
    pub original: String,
    pub normalized: String,
    pub encoding_layers: Vec<EncodingLayer>,
    pub obfuscation_indicators: Vec<ObfuscationTechnique>,
}

#[derive(Debug, Clone)]
pub struct EncodingLayer {
    pub encoding_type: EncodingType,
    pub confidence: f32,
    pub suspicious: bool,
}

#[derive(Debug, Clone)]
pub enum EncodingType {
    Base64,
    QuotedPrintable,
    UrlEncoding,
    HtmlEntities,
    UuEncoding,
    UnicodeEscape,
}

#[derive(Debug, Clone)]
pub enum ObfuscationTechnique {
    UnicodeHomoglyphs,
    ZeroWidthCharacters,
    BidirectionalOverride,
    CombiningCharacters,
}

#[derive(Debug, Clone)]
pub struct SenderInfo {
    pub from_address: String,
    pub from_domain: String,
    pub reply_to: Option<String>,
}

pub struct EmailNormalizer {
    html_entity_regex: Regex,
    base64_regex: Regex,
    uuencoding_regex: Regex,
    homoglyph_map: HashMap<char, char>,
    zero_width_chars: Vec<char>,
}

impl EmailNormalizer {
    pub fn new() -> Self {
        let mut homoglyph_map = HashMap::new();

        // Cyrillic to Latin mappings
        homoglyph_map.insert('а', 'a'); // Cyrillic а → Latin a
        homoglyph_map.insert('е', 'e'); // Cyrillic е → Latin e
        homoglyph_map.insert('о', 'o'); // Cyrillic о → Latin o
        homoglyph_map.insert('р', 'p'); // Cyrillic р → Latin p
        homoglyph_map.insert('с', 'c'); // Cyrillic с → Latin c
        homoglyph_map.insert('х', 'x'); // Cyrillic х → Latin x

        // Greek to Latin mappings
        homoglyph_map.insert('α', 'a'); // Greek α → Latin a
        homoglyph_map.insert('ο', 'o'); // Greek ο → Latin o

        // Mathematical symbols to Latin (basic set)
        homoglyph_map.insert('𝐚', 'a');
        homoglyph_map.insert('𝐛', 'b');
        homoglyph_map.insert('𝐜', 'c');
        homoglyph_map.insert('𝐝', 'd');
        homoglyph_map.insert('𝐞', 'e');

        Self {
            html_entity_regex: Regex::new(r"&(?:#(\d+)|#x([0-9A-Fa-f]+)|([a-zA-Z][a-zA-Z0-9]*));")
                .unwrap(),
            base64_regex: Regex::new(r"[A-Za-z0-9+/]{20,}={0,2}").unwrap(),
            uuencoding_regex: Regex::new(
                r"(?m)^begin\s+\d+\s+\S+\s*\n((?:^[M-Z!-9A-L].{0,60}\s*\n)*)\s*^end\s*$",
            )
            .unwrap(),
            homoglyph_map,
            zero_width_chars: vec!['\u{200B}', '\u{200C}', '\u{200D}', '\u{FEFF}'],
        }
    }

    pub fn normalize_email(&self, raw_email: &str) -> NormalizedEmail {
        let (headers, body) = self.parse_email_structure(raw_email);
        let normalized_headers = self.normalize_headers(&headers);

        let subject = normalized_headers
            .get("subject")
            .cloned()
            .unwrap_or_default();
        let normalized_subject = self.normalize_text(&subject);

        let normalized_body_text = self.normalize_text(&body);
        let normalized_body_html = self.normalize_text(&body);

        let sender_info = self.extract_sender_info(&normalized_headers);

        NormalizedEmail {
            headers: normalized_headers,
            subject: normalized_subject,
            body_text: normalized_body_text,
            body_html: normalized_body_html,
            sender_info,
        }
    }

    fn normalize_text(&self, text: &str) -> NormalizedText {
        let mut current = text.to_string();
        let mut encoding_layers = Vec::new();
        let mut obfuscation_indicators = Vec::new();

        // Multi-pass decoding
        for _pass in 0..5 {
            let original_len = current.len();

            // HTML entity decoding
            let (decoded_html, html_layers) = self.decode_html_entities(&current);
            current = decoded_html;
            encoding_layers.extend(html_layers);

            // Base64 decoding (if it looks like base64)
            let (decoded_b64, b64_layers) = self.decode_base64_if_present(&current);
            current = decoded_b64;
            encoding_layers.extend(b64_layers);

            // URL decoding
            let (decoded_url, url_layers) = self.decode_url_encoding(&current);
            current = decoded_url;
            encoding_layers.extend(url_layers);

            // UUEncoding
            let (decoded_uu, uu_layers) = self.decode_uuencoding(&current);
            current = decoded_uu;
            encoding_layers.extend(uu_layers);

            if current.len() == original_len {
                break; // No more changes
            }
        }

        // Unicode obfuscation resolution
        let (final_text, obfuscations) = self.resolve_unicode_obfuscation(&current);
        obfuscation_indicators.extend(obfuscations);

        NormalizedText {
            original: text.to_string(),
            normalized: final_text,
            encoding_layers,
            obfuscation_indicators,
        }
    }

    fn decode_html_entities(&self, text: &str) -> (String, Vec<EncodingLayer>) {
        let mut layers = Vec::new();
        let entity_count = self.html_entity_regex.find_iter(text).count();

        if entity_count == 0 {
            return (text.to_string(), layers);
        }

        let result = self
            .html_entity_regex
            .replace_all(text, |caps: &regex::Captures| {
                if let Some(decimal) = caps.get(1) {
                    // Decimal entity &#65;
                    if let Ok(code) = decimal.as_str().parse::<u32>() {
                        if let Some(ch) = char::from_u32(code) {
                            return ch.to_string();
                        }
                    }
                } else if let Some(hex) = caps.get(2) {
                    // Hex entity &#x41;
                    if let Ok(code) = u32::from_str_radix(hex.as_str(), 16) {
                        if let Some(ch) = char::from_u32(code) {
                            return ch.to_string();
                        }
                    }
                } else if let Some(named) = caps.get(3) {
                    // Named entity &amp;
                    return match named.as_str() {
                        "amp" => "&".to_string(),
                        "lt" => "<".to_string(),
                        "gt" => ">".to_string(),
                        "quot" => "\"".to_string(),
                        "apos" => "'".to_string(),
                        _ => caps.get(0).unwrap().as_str().to_string(),
                    };
                }
                caps.get(0).unwrap().as_str().to_string()
            })
            .to_string();

        if entity_count > 0 {
            layers.push(EncodingLayer {
                encoding_type: EncodingType::HtmlEntities,
                confidence: 0.9,
                suspicious: entity_count > 100, // Raised threshold - legitimate HTML emails have many entities
            });
        }

        (result, layers)
    }

    fn decode_base64_if_present(&self, text: &str) -> (String, Vec<EncodingLayer>) {
        let mut layers = Vec::new();

        // Only decode if it looks like base64 and is substantial
        if let Some(b64_match) = self.base64_regex.find(text) {
            if b64_match.as_str().len() > 50 {
                // Substantial base64
                if let Ok(decoded) = general_purpose::STANDARD.decode(b64_match.as_str()) {
                    if let Ok(decoded_str) = String::from_utf8(decoded) {
                        let result = text.replace(b64_match.as_str(), &decoded_str);
                        layers.push(EncodingLayer {
                            encoding_type: EncodingType::Base64,
                            confidence: 0.8,
                            suspicious: b64_match.as_str().len() > 200,
                        });
                        return (result, layers);
                    }
                }
            }
        }

        (text.to_string(), layers)
    }

    fn decode_url_encoding(&self, text: &str) -> (String, Vec<EncodingLayer>) {
        let mut layers = Vec::new();
        let original_len = text.len();

        let result = urlencoding::decode(text)
            .unwrap_or_else(|_| text.into())
            .to_string();

        if result.len() != original_len {
            layers.push(EncodingLayer {
                encoding_type: EncodingType::UrlEncoding,
                confidence: 0.7,
                suspicious: false,
            });
        }

        (result, layers)
    }

    fn decode_uuencoding(&self, text: &str) -> (String, Vec<EncodingLayer>) {
        let mut layers = Vec::new();

        if self.uuencoding_regex.is_match(text) {
            // UUEncoding detected - highly suspicious in email
            layers.push(EncodingLayer {
                encoding_type: EncodingType::UuEncoding,
                confidence: 0.95,
                suspicious: true,
            });

            // For now, just remove the UUEncoded blocks
            let result = self
                .uuencoding_regex
                .replace_all(text, "[UUEncoded content removed]")
                .to_string();
            return (result, layers);
        }

        (text.to_string(), layers)
    }

    fn resolve_unicode_obfuscation(&self, text: &str) -> (String, Vec<ObfuscationTechnique>) {
        let mut result = String::new();
        let mut techniques = Vec::new();
        let mut found_homoglyphs = false;
        let mut found_zero_width = false;
        let mut found_bidi = false;
        let mut found_combining = false;

        for ch in text.chars() {
            // Check for homoglyphs
            if let Some(&replacement) = self.homoglyph_map.get(&ch) {
                result.push(replacement);
                found_homoglyphs = true;
            }
            // Check for zero-width characters
            else if self.zero_width_chars.contains(&ch) {
                found_zero_width = true;
                // Skip zero-width characters
            }
            // Check for BIDI override characters
            else if matches!(
                ch,
                '\u{202D}' | '\u{202E}' | '\u{2066}' | '\u{2067}' | '\u{2068}' | '\u{2069}'
            ) {
                found_bidi = true;
                // Skip BIDI override characters
            }
            // Check for combining characters (diacritics) - Unicode ranges 0x0300-0x036F, 0x1AB0-0x1AFF, 0x1DC0-0x1DFF
            else if matches!(ch as u32, 0x0300..=0x036F | 0x1AB0..=0x1AFF | 0x1DC0..=0x1DFF | 0x20D0..=0x20FF)
            {
                found_combining = true;
                // Skip combining characters in suspicious contexts
            } else {
                result.push(ch);
            }
        }

        if found_homoglyphs {
            techniques.push(ObfuscationTechnique::UnicodeHomoglyphs);
        }
        if found_zero_width {
            techniques.push(ObfuscationTechnique::ZeroWidthCharacters);
        }
        if found_bidi {
            techniques.push(ObfuscationTechnique::BidirectionalOverride);
        }
        if found_combining {
            techniques.push(ObfuscationTechnique::CombiningCharacters);
        }

        (result, techniques)
    }

    fn parse_email_structure(&self, email: &str) -> (String, String) {
        if let Some(header_end) = email.find("\n\n") {
            let headers = email[..header_end].to_string();
            let body = email[header_end + 2..].to_string();
            (headers, body)
        } else if let Some(header_end) = email.find("\r\n\r\n") {
            let headers = email[..header_end].to_string();
            let body = email[header_end + 4..].to_string();
            (headers, body)
        } else {
            (String::new(), email.to_string())
        }
    }

    fn normalize_headers(&self, headers: &str) -> HashMap<String, String> {
        let mut normalized = HashMap::new();

        for line in headers.lines() {
            if let Some(colon_pos) = line.find(':') {
                let key = line[..colon_pos].trim().to_lowercase();
                let value = line[colon_pos + 1..].trim().to_string();
                normalized.insert(key, value);
            }
        }

        normalized
    }

    fn extract_sender_info(&self, headers: &HashMap<String, String>) -> SenderInfo {
        let from_address = headers.get("from").cloned().unwrap_or_default();
        let from_domain = self.extract_domain_from_address(&from_address);
        let reply_to = headers.get("reply-to").cloned();

        SenderInfo {
            from_address,
            from_domain,
            reply_to,
        }
    }

    fn extract_domain_from_address(&self, address: &str) -> String {
        if let Some(at_pos) = address.rfind('@') {
            let domain_part = &address[at_pos + 1..];
            // Remove angle brackets if present
            domain_part.trim_end_matches('>').to_string()
        } else {
            String::new()
        }
    }

    pub fn calculate_evasion_score(&self, normalized: &NormalizedText) -> i32 {
        let mut score = 0;

        // Count HTML entity layers separately
        let html_entity_layers = normalized
            .encoding_layers
            .iter()
            .filter(|layer| matches!(layer.encoding_type, EncodingType::HtmlEntities))
            .count();

        let non_html_layers = normalized.encoding_layers.len() - html_entity_layers;

        // Score non-HTML encoding layers more heavily
        score += non_html_layers as i32 * 25;

        // HTML entities are only suspicious if extremely excessive (>300) or heavily mixed
        if html_entity_layers > 0 {
            if html_entity_layers > 300 {
                score += html_entity_layers as i32 * 2; // Very reduced scoring
            } else if non_html_layers > 2 {
                score += (html_entity_layers as i32) / 2; // Minimal scoring when heavily mixed
            }
            // No scoring for normal HTML entity usage or light mixing
        }

        // Penalty for suspicious encodings
        for layer in &normalized.encoding_layers {
            if layer.suspicious {
                score += 50;
            }

            score += match layer.encoding_type {
                EncodingType::UuEncoding => 75,
                EncodingType::Base64 if layer.suspicious => 40,
                EncodingType::HtmlEntities => 0, // Already scored above with context
                _ => 10,
            };
        }

        // Penalty for obfuscation techniques
        for technique in &normalized.obfuscation_indicators {
            score += match technique {
                ObfuscationTechnique::UnicodeHomoglyphs => {
                    // Check if this is likely decorative emojis vs malicious homoglyphs
                    let has_decorative_emojis = normalized.original.chars().any(|c| {
                        matches!(c, 
                            '✨' | '🌸' | '🌺' | '🌻' | '🌷' | '🌹' | '🌿' | '🍀' | '🌱' | '🌳' | '🌲' |
                            '💖' | '💕' | '💗' | '💓' | '💝' | '🎉' | '🎊' | '🎈' | '🎁' | '⭐' | '🌟' |
                            '🔥' | '💯' | '👍' | '💙' | '💚' | '💛' | '💜' | '🧡' | '🤍' | '🖤'
                        ) || c == '❤' // Handle ❤️ as separate character
                    });
                    if has_decorative_emojis { 5 } else { 25 } // Much lower penalty for decorative emojis
                }
                ObfuscationTechnique::ZeroWidthCharacters => 75,
                ObfuscationTechnique::BidirectionalOverride => 60,
                ObfuscationTechnique::CombiningCharacters => 15,
            };
        }

        score
    }
}

impl Default for EmailNormalizer {
    fn default() -> Self {
        Self::new()
    }
}
