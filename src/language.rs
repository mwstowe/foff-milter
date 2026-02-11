pub struct LanguageDetector;

impl LanguageDetector {
    pub fn contains_language(text: &str, language: &str) -> bool {
        match language.to_lowercase().as_str() {
            "japanese" | "ja" => Self::contains_japanese(text),
            "chinese" | "zh" => Self::contains_chinese(text),
            "korean" | "ko" => Self::contains_korean(text),
            "arabic" | "ar" => Self::contains_arabic(text),
            "russian" | "ru" => Self::contains_russian(text),
            "thai" | "th" => Self::contains_thai(text),
            "hebrew" | "he" => Self::contains_hebrew(text),
            "portuguese" | "pt" => Self::contains_portuguese(text),
            _ => {
                log::warn!("Unsupported language for detection: {language}");
                false
            }
        }
    }

    fn contains_japanese(text: &str) -> bool {
        text.chars().any(|c| {
            // Hiragana: U+3040–U+309F
            // Katakana: U+30A0–U+30FF
            // CJK Unified Ideographs (Kanji): U+4E00–U+9FAF
            // CJK Unified Ideographs Extension A: U+3400–U+4DBF
            matches!(c,
                '\u{3040}'..='\u{309F}' |  // Hiragana
                '\u{30A0}'..='\u{30FF}' |  // Katakana
                '\u{4E00}'..='\u{9FAF}' |  // CJK Unified Ideographs
                '\u{3400}'..='\u{4DBF}'    // CJK Extension A
            )
        })
    }

    fn contains_chinese(text: &str) -> bool {
        text.chars().any(|c| {
            // CJK Unified Ideographs: U+4E00–U+9FAF
            // CJK Unified Ideographs Extension A: U+3400–U+4DBF
            // CJK Unified Ideographs Extension B: U+20000–U+2A6DF
            matches!(c,
                '\u{4E00}'..='\u{9FAF}' |  // CJK Unified Ideographs
                '\u{3400}'..='\u{4DBF}' |  // CJK Extension A
                '\u{20000}'..='\u{2A6DF}'  // CJK Extension B
            )
        })
    }

    fn contains_korean(text: &str) -> bool {
        text.chars().any(|c| {
            // Hangul Syllables: U+AC00–U+D7AF
            // Hangul Jamo: U+1100–U+11FF
            // Hangul Compatibility Jamo: U+3130–U+318F
            matches!(c,
                '\u{AC00}'..='\u{D7AF}' |  // Hangul Syllables
                '\u{1100}'..='\u{11FF}' |  // Hangul Jamo
                '\u{3130}'..='\u{318F}'    // Hangul Compatibility Jamo
            )
        })
    }

    fn contains_arabic(text: &str) -> bool {
        text.chars().any(|c| {
            // Arabic: U+0600–U+06FF
            // Arabic Supplement: U+0750–U+077F
            // Arabic Extended-A: U+08A0–U+08FF
            matches!(c,
                '\u{0600}'..='\u{06FF}' |  // Arabic
                '\u{0750}'..='\u{077F}' |  // Arabic Supplement
                '\u{08A0}'..='\u{08FF}'    // Arabic Extended-A
            )
        })
    }

    fn contains_russian(text: &str) -> bool {
        text.chars().any(|c| {
            // Cyrillic: U+0400–U+04FF
            // Cyrillic Supplement: U+0500–U+052F
            matches!(c,
                '\u{0400}'..='\u{04FF}' |  // Cyrillic
                '\u{0500}'..='\u{052F}'    // Cyrillic Supplement
            )
        })
    }

    fn contains_thai(text: &str) -> bool {
        text.chars().any(|c| {
            // Thai: U+0E00–U+0E7F
            matches!(c, '\u{0E00}'..='\u{0E7F}')
        })
    }

    fn contains_hebrew(text: &str) -> bool {
        text.chars().any(|c| {
            // Hebrew: U+0590–U+05FF
            matches!(c, '\u{0590}'..='\u{05FF}')
        })
    }

    pub fn contains_portuguese(text: &str) -> bool {
        // Highly Portuguese-specific characters (ã, õ are almost exclusively Portuguese)
        let has_highly_specific_chars = text.chars().any(|c| matches!(c, 'ã' | 'õ' | 'Ã' | 'Õ'));

        // Portuguese-specific words
        let text_lower = text.to_lowercase();
        let portuguese_specific_words = [
            "validação",
            "conferência",
            "processo",
            "documento",
            "assinatura",
            "pendentes",
            "aguardando",
            "realizar",
            "notas",
            "registros",
            "concluir",
            "não",
        ];
        let has_portuguese_words = portuguese_specific_words
            .iter()
            .any(|&word| text_lower.contains(word));

        // Detect Portuguese if:
        // 1. Has highly specific characters (ã, õ) - these are almost exclusively Portuguese
        // 2. Has Portuguese-specific words - these are unambiguous
        // This prevents false positives from common accented characters (á, é, í, ó, ú, ç)
        // that appear in Spanish, French, and brand names
        has_highly_specific_chars || has_portuguese_words
    }

    pub fn detect_languages(text: &str) -> Vec<String> {
        let mut languages = Vec::new();

        if Self::contains_japanese(text) {
            languages.push("Japanese".to_string());
        }
        if Self::contains_chinese(text) {
            languages.push("Chinese".to_string());
        }
        if Self::contains_korean(text) {
            languages.push("Korean".to_string());
        }
        if Self::contains_arabic(text) {
            languages.push("Arabic".to_string());
        }
        if Self::contains_russian(text) {
            languages.push("Russian".to_string());
        }
        if Self::contains_thai(text) {
            languages.push("Thai".to_string());
        }
        if Self::contains_hebrew(text) {
            languages.push("Hebrew".to_string());
        }
        if Self::contains_portuguese(text) {
            languages.push("Portuguese".to_string());
        }

        languages
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_japanese_detection() {
        assert!(LanguageDetector::contains_japanese("こんにちは")); // Hiragana
        assert!(LanguageDetector::contains_japanese("カタカナ")); // Katakana
        assert!(LanguageDetector::contains_japanese("漢字")); // Kanji
        assert!(LanguageDetector::contains_japanese("Hello こんにちは")); // Mixed
        assert!(!LanguageDetector::contains_japanese("Hello World"));
    }

    #[test]
    fn test_chinese_detection() {
        assert!(LanguageDetector::contains_chinese("你好"));
        assert!(LanguageDetector::contains_chinese("中文"));
        assert!(!LanguageDetector::contains_chinese("Hello World"));
    }

    #[test]
    fn test_korean_detection() {
        assert!(LanguageDetector::contains_korean("안녕하세요"));
        assert!(LanguageDetector::contains_korean("한국어"));
        assert!(!LanguageDetector::contains_korean("Hello World"));
    }

    #[test]
    fn test_arabic_detection() {
        assert!(LanguageDetector::contains_arabic("مرحبا"));
        assert!(LanguageDetector::contains_arabic("العربية"));
        assert!(!LanguageDetector::contains_arabic("Hello World"));
    }

    #[test]
    fn test_russian_detection() {
        assert!(LanguageDetector::contains_russian("Привет"));
        assert!(LanguageDetector::contains_russian("русский"));
        assert!(!LanguageDetector::contains_russian("Hello World"));
    }

    #[test]
    fn test_portuguese_detection() {
        assert!(LanguageDetector::contains_portuguese("validação"));
        assert!(LanguageDetector::contains_portuguese("conferência"));
        assert!(LanguageDetector::contains_portuguese(
            "Há registros aguardando"
        ));
        assert!(LanguageDetector::contains_portuguese("não responder"));
        assert!(!LanguageDetector::contains_portuguese("Hello World"));
    }

    #[test]
    fn test_language_detection_api() {
        assert!(LanguageDetector::contains_language(
            "こんにちは",
            "japanese"
        ));
        assert!(LanguageDetector::contains_language("こんにちは", "ja"));
        assert!(LanguageDetector::contains_language("你好", "chinese"));
        assert!(LanguageDetector::contains_language("안녕하세요", "korean"));
    }

    #[test]
    fn test_multiple_language_detection() {
        let languages = LanguageDetector::detect_languages("Hello こんにちは 你好");
        assert!(languages.contains(&"Japanese".to_string()));
        assert!(languages.contains(&"Chinese".to_string()));
        assert_eq!(languages.len(), 2);
    }
}
