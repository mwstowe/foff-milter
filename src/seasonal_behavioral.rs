use crate::filter::MailContext;
use chrono::{DateTime, Datelike, Timelike, Utc};
use regex::Regex;

#[derive(Debug, Clone, Default)]
pub struct SeasonalBehavioralScore {
    pub seasonal_context: i32,
    pub behavioral_consistency: i32,
    pub sending_patterns: i32,
    pub content_timing: i32,
    pub total_seasonal_score: i32,
}

pub struct SeasonalBehavioralAnalyzer {
    // Compiled regex patterns for performance
    holiday_sales_pattern: Regex,
    back_to_school_pattern: Regex,
    tax_season_pattern: Regex,
    seasonal_greetings_pattern: Regex,
    urgent_timing_pattern: Regex,
}

impl SeasonalBehavioralAnalyzer {
    pub fn new() -> Self {
        Self {
            holiday_sales_pattern: Regex::new(r"(?i)\b(black\s+friday|cyber\s+monday|holiday\s+sale|christmas\s+sale|new\s+year\s+sale|thanksgiving\s+deal|winter\s+clearance)\b").unwrap(),
            back_to_school_pattern: Regex::new(r"(?i)\b(back\s+to\s+school|school\s+supplies|student\s+discount|college\s+prep|academic\s+year)\b").unwrap(),
            tax_season_pattern: Regex::new(r"(?i)\b(tax\s+season|tax\s+preparation|tax\s+filing|tax\s+refund|irs|w-2|1099)\b").unwrap(),
            seasonal_greetings_pattern: Regex::new(r"(?i)\b(happy\s+holidays|merry\s+christmas|happy\s+new\s+year|season's\s+greetings|thanksgiving\s+wishes)\b").unwrap(),
            urgent_timing_pattern: Regex::new(r"(?i)\b(expires\s+today|ends\s+tonight|last\s+chance|final\s+hours|act\s+now|limited\s+time)\b").unwrap(),
        }
    }

    /// Analyze seasonal context and behavioral patterns
    pub fn analyze_seasonal_behavioral(&self, context: &MailContext) -> SeasonalBehavioralScore {
        let mut score = SeasonalBehavioralScore::default();

        score.seasonal_context = self.analyze_seasonal_context(context);
        score.behavioral_consistency = self.analyze_behavioral_consistency(context);
        score.sending_patterns = self.analyze_sending_patterns(context);
        score.content_timing = self.analyze_content_timing(context);

        // Calculate weighted total
        score.total_seasonal_score = self.calculate_total_seasonal_score(&score);

        score
    }

    /// Analyze seasonal context appropriateness
    fn analyze_seasonal_context(&self, context: &MailContext) -> i32 {
        let mut seasonal_score = 0;
        let now = Utc::now();
        let month = now.month();
        let _day = now.day();

        if let Some(body) = &context.body {
            let combined_content = format!("{} {}", context.subject.as_deref().unwrap_or(""), body);

            // Holiday season (November-December)
            if month >= 11 || month == 12 {
                if self.holiday_sales_pattern.is_match(&combined_content) {
                    seasonal_score += 20; // Appropriate holiday sales
                }
                if self.seasonal_greetings_pattern.is_match(&combined_content) {
                    seasonal_score += 15; // Appropriate seasonal greetings
                }
            } else if self.holiday_sales_pattern.is_match(&combined_content) {
                seasonal_score -= 10; // Holiday sales out of season
            }

            // Back to school season (July-September)
            if (7..=9).contains(&month) {
                if self.back_to_school_pattern.is_match(&combined_content) {
                    seasonal_score += 15; // Appropriate back to school
                }
            } else if self.back_to_school_pattern.is_match(&combined_content) {
                seasonal_score -= 5; // Back to school out of season
            }

            // Tax season (January-April)
            if (1..=4).contains(&month) {
                if self.tax_season_pattern.is_match(&combined_content) {
                    seasonal_score += 15; // Appropriate tax season
                }
            } else if self.tax_season_pattern.is_match(&combined_content) {
                seasonal_score -= 10; // Tax content out of season
            }

            // Summer sales (June-August)
            if (6..=8).contains(&month)
                && (combined_content.to_lowercase().contains("summer sale")
                    || combined_content.to_lowercase().contains("summer clearance"))
            {
                seasonal_score += 10;
            }

            // Spring cleaning/sales (March-May)
            if (3..=5).contains(&month)
                && (combined_content.to_lowercase().contains("spring sale")
                    || combined_content.to_lowercase().contains("spring cleaning"))
            {
                seasonal_score += 10;
            }
        }

        seasonal_score.clamp(-20, 30)
    }

    /// Analyze behavioral consistency patterns
    fn analyze_behavioral_consistency(&self, context: &MailContext) -> i32 {
        let mut consistency_score = 0;

        // From/Reply-To consistency
        if let Some(from_header) = &context.from_header {
            if let Some(reply_to) = context.headers.get("Reply-To") {
                if self.extract_domain_from_email(from_header)
                    == self.extract_domain_from_email(reply_to)
                {
                    consistency_score += 10; // Consistent reply-to domain
                }
            } else {
                consistency_score += 5; // No reply-to manipulation
            }
        }

        // Message-ID consistency with sender domain
        if let (Some(message_id), Some(sender)) =
            (context.headers.get("Message-ID"), &context.sender)
        {
            if let Some(sender_domain) = self.extract_domain_from_email(sender) {
                if message_id.contains(&sender_domain) {
                    consistency_score += 10; // Message-ID matches sender domain
                }
            }
        }

        // Subject/body content alignment
        if let (Some(subject), Some(body)) = (&context.subject, &context.body) {
            let subject_lower = subject.to_lowercase();
            let body_lower = body.to_lowercase();

            // Check for subject-body topic consistency
            let subject_words: Vec<&str> = subject_lower
                .split_whitespace()
                .filter(|w| w.len() > 3)
                .collect();

            let matching_words = subject_words
                .iter()
                .filter(|&&word| body_lower.contains(word))
                .count();

            if matching_words > 0 {
                consistency_score += 5; // Subject matches body content
            }
        }

        // Professional header consistency
        if context.headers.contains_key("List-Unsubscribe")
            && context.headers.contains_key("List-ID")
        {
            consistency_score += 10; // Consistent mailing list headers
        }

        consistency_score.clamp(0, 25)
    }

    /// Analyze sending patterns and timing
    fn analyze_sending_patterns(&self, context: &MailContext) -> i32 {
        let mut pattern_score = 0;

        // Check for proper Date header
        if let Some(date_header) = context.headers.get("Date") {
            if let Ok(parsed_date) = DateTime::parse_from_rfc2822(date_header) {
                let now = Utc::now();
                let date_utc = parsed_date.with_timezone(&Utc);

                // Check if date is reasonable (not too far in future/past)
                let diff_hours = (now - date_utc).num_hours().abs();
                if diff_hours <= 24 {
                    pattern_score += 10; // Recent, reasonable timestamp
                } else if diff_hours <= 168 {
                    // Within a week
                    pattern_score += 5;
                } else if diff_hours > 8760 {
                    // More than a year
                    pattern_score -= 10; // Suspicious timestamp
                }

                // Business hours analysis (rough heuristic)
                let hour = date_utc.hour();
                if (8..=18).contains(&hour) {
                    pattern_score += 5; // Business hours sending
                } else if hour >= 22 || hour <= 5 {
                    pattern_score -= 5; // Late night/early morning (suspicious for business)
                }
            }
        }

        // Received header analysis for hop patterns
        let received_count = context
            .headers
            .iter()
            .filter(|(k, _)| k.to_lowercase() == "received")
            .count();

        if (2..=5).contains(&received_count) {
            pattern_score += 5; // Normal email routing
        } else if received_count > 8 {
            pattern_score -= 10; // Too many hops (suspicious)
        }

        pattern_score.clamp(-15, 20)
    }

    /// Analyze content timing and urgency appropriateness
    fn analyze_content_timing(&self, context: &MailContext) -> i32 {
        let mut timing_score = 0;

        if let Some(body) = &context.body {
            let combined_content = format!("{} {}", context.subject.as_deref().unwrap_or(""), body);

            // Check for excessive urgency
            if self.urgent_timing_pattern.is_match(&combined_content) {
                timing_score -= 15; // Excessive urgency is suspicious
            }

            // Professional timing language
            if combined_content
                .to_lowercase()
                .contains("at your convenience")
                || combined_content
                    .to_lowercase()
                    .contains("when you have time")
            {
                timing_score += 10; // Professional, non-urgent language
            }

            // Legitimate deadline language
            if combined_content.to_lowercase().contains("deadline")
                || combined_content.to_lowercase().contains("due date")
            {
                timing_score += 5; // Professional deadline language
            }

            // Account/service notifications (legitimate urgency)
            if combined_content.to_lowercase().contains("account")
                && (combined_content.to_lowercase().contains("notification")
                    || combined_content.to_lowercase().contains("alert"))
            {
                timing_score += 10; // Legitimate account notifications
            }
        }

        timing_score.clamp(-20, 15)
    }

    /// Calculate weighted total seasonal score
    fn calculate_total_seasonal_score(&self, score: &SeasonalBehavioralScore) -> i32 {
        // Weighted combination emphasizing behavioral consistency and seasonal appropriateness
        let total = (score.seasonal_context as f32 * 0.30)
            + (score.behavioral_consistency as f32 * 0.35)
            + (score.sending_patterns as f32 * 0.20)
            + (score.content_timing as f32 * 0.15);

        total.round() as i32
    }

    /// Get seasonal behavioral adjustment for spam scoring
    pub fn get_seasonal_adjustment(&self, seasonal_score: i32) -> i32 {
        match seasonal_score {
            25.. => -15,    // Excellent seasonal/behavioral patterns
            15..=24 => -10, // Good seasonal/behavioral patterns
            8..=14 => -5,   // Some positive patterns
            0..=7 => 0,     // Neutral patterns
            -10..=-1 => 5,  // Some negative patterns
            _ => 10,        // Poor patterns (suspicious timing/behavior)
        }
    }

    /// Extract domain from email address
    fn extract_domain_from_email(&self, email: &str) -> Option<String> {
        if let Some(at_pos) = email.rfind('@') {
            let domain = &email[at_pos + 1..];
            let clean_domain = domain.trim_matches(|c| c == '>' || c == '<' || c == ' ');
            if !clean_domain.is_empty() {
                return Some(clean_domain.to_lowercase());
            }
        }
        None
    }
}

impl Default for SeasonalBehavioralAnalyzer {
    fn default() -> Self {
        Self::new()
    }
}
