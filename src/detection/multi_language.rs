use super::DetectionResult;
use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct MultiLanguageConfig {
    pub character_encoding_abuse: CharacterEncodingAbuse,
    pub chinese_threats: ChineseThreats,
    pub russian_cyrillic: RussianCyrillic,
    pub arabic_rtl: ArabicRtl,
    pub korean_asian: KoreanAsian,
    pub japanese_extended: JapaneseExtended,
    pub language_detection_patterns: LanguageDetectionPatterns,
    pub legitimate_exclusions: LegitimateExclusions,
    pub confidence_scoring: ConfidenceScoring,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct CharacterEncodingAbuse {
    pub unicode_tricks: Vec<String>,
    pub mixed_scripts: Vec<String>,
    pub encoding_evasion: Vec<String>,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct ChineseThreats {
    pub simplified_chinese: Vec<String>,
    pub traditional_chinese: Vec<String>,
    pub cultural_patterns: Vec<String>,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct RussianCyrillic {
    pub russian_spam: Vec<String>,
    pub cyrillic_lookalikes: Vec<String>,
    pub romance_scams: Vec<String>,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct ArabicRtl {
    pub arabic_spam: Vec<String>,
    pub rtl_attacks: Vec<String>,
    pub cultural_scams: Vec<String>,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct KoreanAsian {
    pub korean_hangul: Vec<String>,
    pub thai_script: Vec<String>,
    pub vietnamese: Vec<String>,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct JapaneseExtended {
    pub hiragana_katakana: Vec<String>,
    pub mixed_japanese: Vec<String>,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct LanguageDetectionPatterns {
    pub suspicious_mixing: Vec<String>,
    pub encoding_indicators: Vec<String>,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct LegitimateExclusions {
    pub international_companies: Vec<String>,
    pub news_organizations: Vec<String>,
    pub government_domains: Vec<String>,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct ConfidenceScoring {
    pub character_encoding_abuse: u32,
    pub chinese_threats: u32,
    pub russian_cyrillic: u32,
    pub arabic_rtl: u32,
    pub korean_asian: u32,
    pub japanese_extended: u32,
    pub language_mixing: u32,
}

pub struct MultiLanguageDetector {
    config: MultiLanguageConfig,
}

impl MultiLanguageDetector {
    pub fn new(config: MultiLanguageConfig) -> Self {
        Self { config }
    }

    pub fn load_from_file(path: &str) -> Result<Self, Box<dyn std::error::Error>> {
        let content = std::fs::read_to_string(path)?;
        let config: MultiLanguageConfig = serde_yml::from_str(&content)?;
        Ok(Self::new(config))
    }

    pub fn check_multi_language_threat(
        &self,
        subject: &str,
        body: &str,
        _sender: &str,
        sender_domain: &str,
    ) -> DetectionResult {
        // Check if sender is from legitimate international organization
        if self.is_legitimate_international_sender(sender_domain) {
            return DetectionResult::no_match("MultiLanguage".to_string());
        }

        let mut confidence = 0;
        let mut reasons = Vec::new();
        let combined_text = format!("{} {}", subject, body);

        // Check language/geography mismatches (highest priority)
        if let Some(mismatch_result) = self.check_language_geography_mismatch(&combined_text, sender_domain) {
            return mismatch_result;
        }

        // Check mixed script confusion
        if let Some(script_result) = self.check_mixed_script_confusion(&combined_text) {
            return script_result;
        }

        // Check character encoding abuse (highest priority)
        if self.check_patterns(
            &combined_text,
            &self.config.character_encoding_abuse.unicode_tricks,
        ) || self.check_patterns(
            &combined_text,
            &self.config.character_encoding_abuse.mixed_scripts,
        ) || self.check_patterns(
            &combined_text,
            &self.config.character_encoding_abuse.encoding_evasion,
        ) {
            confidence += self.config.confidence_scoring.character_encoding_abuse;
            reasons.push("Character encoding abuse detected".to_string());
        }

        // Check Chinese threats
        if self.check_unicode_patterns(
            &combined_text,
            &self.config.chinese_threats.simplified_chinese,
        ) || self.check_unicode_patterns(
            &combined_text,
            &self.config.chinese_threats.traditional_chinese,
        ) || self.check_patterns(
            &combined_text,
            &self.config.chinese_threats.cultural_patterns,
        ) {
            confidence += self.config.confidence_scoring.chinese_threats;
            reasons.push("Chinese language threat detected".to_string());
        }

        // Check Russian/Cyrillic threats
        if self.check_unicode_patterns(&combined_text, &self.config.russian_cyrillic.russian_spam)
            || self.check_unicode_patterns(
                &combined_text,
                &self.config.russian_cyrillic.cyrillic_lookalikes,
            )
            || self
                .check_unicode_patterns(&combined_text, &self.config.russian_cyrillic.romance_scams)
        {
            confidence += self.config.confidence_scoring.russian_cyrillic;
            reasons.push("Russian/Cyrillic threat detected".to_string());
        }

        // Check Arabic/RTL threats
        if self.check_unicode_patterns(&combined_text, &self.config.arabic_rtl.arabic_spam)
            || self.check_patterns(&combined_text, &self.config.arabic_rtl.rtl_attacks)
            || self.check_unicode_patterns(&combined_text, &self.config.arabic_rtl.cultural_scams)
        {
            confidence += self.config.confidence_scoring.arabic_rtl;
            reasons.push("Arabic/RTL threat detected".to_string());
        }

        // Check Korean/Asian threats
        if self.check_unicode_patterns(&combined_text, &self.config.korean_asian.korean_hangul)
            || self.check_unicode_patterns(&combined_text, &self.config.korean_asian.thai_script)
            || self.check_patterns(&combined_text, &self.config.korean_asian.vietnamese)
        {
            confidence += self.config.confidence_scoring.korean_asian;
            reasons.push("Korean/Asian language threat detected".to_string());
        }

        // Check Japanese extended patterns
        if self.check_unicode_patterns(
            &combined_text,
            &self.config.japanese_extended.hiragana_katakana,
        ) || self.check_unicode_patterns(
            &combined_text,
            &self.config.japanese_extended.mixed_japanese,
        ) {
            confidence += self.config.confidence_scoring.japanese_extended;
            reasons.push("Japanese language threat detected".to_string());
        }

        // Check language mixing patterns
        if self.check_language_mixing(&combined_text) {
            confidence += self.config.confidence_scoring.language_mixing;
            reasons.push("Suspicious language mixing detected".to_string());
        }

        let matched = confidence > 0;
        let reason = if reasons.is_empty() {
            "No multi-language threat indicators".to_string()
        } else {
            reasons.join(", ")
        };

        DetectionResult::new(matched, confidence, reason, "MultiLanguage".to_string())
    }

    fn check_language_geography_mismatch(&self, text: &str, domain: &str) -> Option<DetectionResult> {
        // Japanese text from Chinese domain
        if domain.ends_with(".cn") && self.has_japanese_text(text) {
            return Some(DetectionResult::new(
                true,
                40,
                "Japanese text from Chinese (.cn) domain".to_string(),
                "MultiLanguage".to_string(),
            ));
        }

        // Chinese text from Japanese domain
        if domain.ends_with(".jp") && self.has_chinese_text(text) {
            return Some(DetectionResult::new(
                true,
                35,
                "Chinese text from Japanese (.jp) domain".to_string(),
                "MultiLanguage".to_string(),
            ));
        }

        // Korean text from suspicious domains
        if (domain.ends_with(".cn") || domain.ends_with(".jp") || domain.ends_with(".ru") || 
            domain.ends_with(".tk") || domain.ends_with(".ml") || domain.ends_with(".ga")) 
            && self.has_korean_text(text) {
            return Some(DetectionResult::new(
                true,
                35,
                "Korean text from suspicious foreign domain".to_string(),
                "MultiLanguage".to_string(),
            ));
        }

        // Cyrillic text from Asian domains
        if (domain.ends_with(".cn") || domain.ends_with(".jp") || domain.ends_with(".kr") || 
            domain.ends_with(".tw") || domain.ends_with(".hk")) 
            && self.has_cyrillic_text(text) {
            return Some(DetectionResult::new(
                true,
                30,
                "Cyrillic text from Asian domain".to_string(),
                "MultiLanguage".to_string(),
            ));
        }

        None
    }

    fn check_mixed_script_confusion(&self, text: &str) -> Option<DetectionResult> {
        let has_latin = text.chars().any(|c| c.is_ascii_alphabetic());
        let has_cyrillic = text.chars().any(|c| matches!(c, '\u{0400}'..='\u{04FF}'));
        let has_arabic = text.chars().any(|c| matches!(c, '\u{0600}'..='\u{06FF}'));
        let has_cjk = text.chars().any(|c| matches!(c, '\u{4E00}'..='\u{9FFF}' | '\u{3040}'..='\u{309F}' | '\u{30A0}'..='\u{30FF}' | '\u{AC00}'..='\u{D7AF}'));

        let mut suspicious_combinations = 0;

        // Latin + Cyrillic (common in phishing)
        if has_latin && has_cyrillic {
            suspicious_combinations += 1;
        }

        // Latin + Arabic (suspicious mixing)
        if has_latin && has_arabic {
            suspicious_combinations += 1;
        }

        // Excessive Latin + CJK mixing (beyond normal usage)
        if has_latin && has_cjk {
            let latin_count = text.chars().filter(|c| c.is_ascii_alphabetic()).count();
            let cjk_count = text.chars().filter(|c| matches!(*c, '\u{4E00}'..='\u{9FFF}' | '\u{3040}'..='\u{309F}' | '\u{30A0}'..='\u{30FF}' | '\u{AC00}'..='\u{D7AF}')).count();
            
            // Suspicious if both scripts are heavily used (not just occasional mixing)
            if latin_count > 10 && cjk_count > 10 {
                suspicious_combinations += 1;
            }
        }

        if suspicious_combinations >= 1 {
            return Some(DetectionResult::new(
                true,
                25,
                "Suspicious mixing of different writing systems".to_string(),
                "MultiLanguage".to_string(),
            ));
        }

        None
    }

    fn has_japanese_text(&self, text: &str) -> bool {
        text.chars().any(|c| matches!(c, '\u{3040}'..='\u{309F}' | '\u{30A0}'..='\u{30FF}'))
    }

    fn has_chinese_text(&self, text: &str) -> bool {
        text.chars().any(|c| matches!(c, '\u{4E00}'..='\u{9FAF}'))
    }

    fn has_korean_text(&self, text: &str) -> bool {
        text.chars().any(|c| matches!(c, '\u{AC00}'..='\u{D7AF}' | '\u{1100}'..='\u{11FF}' | '\u{3130}'..='\u{318F}'))
    }

    fn has_cyrillic_text(&self, text: &str) -> bool {
        text.chars().any(|c| matches!(c, '\u{0400}'..='\u{04FF}' | '\u{0500}'..='\u{052F}'))
    }

    fn check_patterns(&self, text: &str, patterns: &[String]) -> bool {
        let text_lower = text.to_lowercase();
        patterns.iter().any(|pattern| text_lower.contains(pattern))
    }

    fn check_unicode_patterns(&self, text: &str, patterns: &[String]) -> bool {
        // Check for Unicode patterns without case conversion
        patterns.iter().any(|pattern| text.contains(pattern))
    }

    fn check_language_mixing(&self, text: &str) -> bool {
        // Simple heuristic for detecting mixed scripts
        let has_latin = text.chars().any(|c| c.is_ascii_alphabetic());
        let has_cyrillic = text.chars().any(|c| matches!(c, '\u{0400}'..='\u{04FF}'));
        let has_chinese = text.chars().any(|c| matches!(c, '\u{4E00}'..='\u{9FFF}'));
        let has_arabic = text.chars().any(|c| matches!(c, '\u{0600}'..='\u{06FF}'));
        let has_korean = text.chars().any(|c| matches!(c, '\u{AC00}'..='\u{D7AF}'));
        let has_japanese_hiragana = text.chars().any(|c| matches!(c, '\u{3040}'..='\u{309F}'));
        let has_japanese_katakana = text.chars().any(|c| matches!(c, '\u{30A0}'..='\u{30FF}'));

        let script_count = [
            has_latin,
            has_cyrillic,
            has_chinese,
            has_arabic,
            has_korean,
            has_japanese_hiragana,
            has_japanese_katakana,
        ]
        .iter()
        .filter(|&&x| x)
        .count();

        // Suspicious if more than 2 different scripts are mixed
        script_count > 2
    }

    fn is_legitimate_international_sender(&self, domain: &str) -> bool {
        let all_legitimate = [
            &self.config.legitimate_exclusions.international_companies,
            &self.config.legitimate_exclusions.news_organizations,
            &self.config.legitimate_exclusions.government_domains,
        ];

        for legitimate_list in all_legitimate.iter() {
            for legitimate_domain in legitimate_list.iter() {
                if domain.ends_with(legitimate_domain) {
                    return true;
                }
            }
        }

        false
    }

    pub fn get_all_patterns(&self) -> Vec<String> {
        let mut patterns = Vec::new();
        patterns.extend(self.config.character_encoding_abuse.unicode_tricks.clone());
        patterns.extend(self.config.character_encoding_abuse.mixed_scripts.clone());
        patterns.extend(
            self.config
                .character_encoding_abuse
                .encoding_evasion
                .clone(),
        );
        patterns.extend(self.config.chinese_threats.simplified_chinese.clone());
        patterns.extend(self.config.chinese_threats.traditional_chinese.clone());
        patterns.extend(self.config.chinese_threats.cultural_patterns.clone());
        patterns.extend(self.config.russian_cyrillic.russian_spam.clone());
        patterns.extend(self.config.russian_cyrillic.cyrillic_lookalikes.clone());
        patterns.extend(self.config.russian_cyrillic.romance_scams.clone());
        patterns.extend(self.config.arabic_rtl.arabic_spam.clone());
        patterns.extend(self.config.arabic_rtl.rtl_attacks.clone());
        patterns.extend(self.config.arabic_rtl.cultural_scams.clone());
        patterns.extend(self.config.korean_asian.korean_hangul.clone());
        patterns.extend(self.config.korean_asian.thai_script.clone());
        patterns.extend(self.config.korean_asian.vietnamese.clone());
        patterns.extend(self.config.japanese_extended.hiragana_katakana.clone());
        patterns.extend(self.config.japanese_extended.mixed_japanese.clone());
        patterns.extend(
            self.config
                .language_detection_patterns
                .suspicious_mixing
                .clone(),
        );
        patterns.extend(
            self.config
                .language_detection_patterns
                .encoding_indicators
                .clone(),
        );
        patterns.sort();
        patterns.dedup();
        patterns
    }
}
