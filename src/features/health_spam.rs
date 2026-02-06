use crate::features::{FeatureExtractor, FeatureScore};
use crate::MailContext;

pub struct HealthSpamAnalyzer;

impl HealthSpamAnalyzer {
    pub fn new() -> Self {
        Self
    }
}

impl FeatureExtractor for HealthSpamAnalyzer {
    fn name(&self) -> &str {
        "Health Spam"
    }

    fn extract(&self, context: &MailContext) -> FeatureScore {
        let mut score = 0;
        let mut evidence = Vec::new();

        let content = format!(
            "{} {} {}",
            context.subject.as_deref().unwrap_or(""),
            context.body.as_deref().unwrap_or(""),
            context.from_header.as_deref().unwrap_or("")
        )
        .to_lowercase();

        // Health brand impersonation from non-health domains
        let health_brands = [
            "unitedhealthcare",
            "aetna",
            "cigna",
            "humana",
            "anthem",
            "bluecross",
            "kaiser",
            "medicaid",
            "medicare",
            "healthplan",
        ];

        let health_products = [
            "oral-b",
            "dental",
            "smile",
            "teeth",
            "toothbrush",
            "mouthwash",
            "vitamin",
            "supplement",
            "medicine",
            "prescription",
            "pharmacy",
            "health kit",
            "medical",
            "wellness",
            "fitness tracker",
        ];

        let sender_domain = context
            .from_header
            .as_deref()
            .and_then(|from| from.split('@').nth(1))
            .unwrap_or("")
            .to_lowercase();

        // Check for health brand impersonation
        for brand in &health_brands {
            if content.contains(brand) {
                let sender_domain_clean = sender_domain.replace(".", "").replace("-", "");
                let brand_clean = brand.replace(".", "").replace("-", "");

                // Whitelist legitimate healthcare domains
                let legitimate_health_domains = [
                    "adapthealth",
                    "adapthealthmarketplace",
                    "unitedhealthcare",
                    "aetna",
                    "cigna",
                    "humana",
                    "anthem",
                    "bluecross",
                    "kaiser",
                ];
                let is_legitimate_health = legitimate_health_domains
                    .iter()
                    .any(|domain| sender_domain.contains(domain));

                // Only flag if domain doesn't contain the brand name at all and not from legitimate health domain
                if !sender_domain_clean.contains(&brand_clean) && !is_legitimate_health {
                    score += 80;
                    evidence.push(format!(
                        "Health brand '{}' impersonation from non-health domain",
                        brand
                    ));
                    break;
                }
            }
        }

        // Hotel/travel brand impersonation
        let hotel_brands = [
            "marriott",
            "hilton",
            "hyatt",
            "sheraton",
            "westin",
            "doubletree",
            "holiday inn",
            "best western",
            "radisson",
            "intercontinental",
        ];

        for brand in &hotel_brands {
            if content.contains(brand) {
                let sender_domain_clean = sender_domain.replace(".", "").replace("-", "");
                let brand_clean = brand.replace(" ", "").replace(".", "").replace("-", "");

                if !sender_domain_clean.contains(&brand_clean) {
                    score += 100;
                    evidence.push(format!(
                        "Hotel brand '{}' impersonation from non-hotel domain",
                        brand
                    ));
                    break;
                }
            }
        }

        // Chinese domains sending Japanese content (geographic mismatch)
        if sender_domain.ends_with(".cn")
            && content.chars().any(|c| {
                ('\u{3040}'..='\u{309F}').contains(&c) || // Hiragana
            ('\u{30A0}'..='\u{30FF}').contains(&c) || // Katakana
            ('\u{4E00}'..='\u{9FAF}').contains(&c) // CJK Unified Ideographs
            })
        {
            score += 200;
            evidence
                .push("Chinese domain sending Japanese content - geographic mismatch".to_string());
        }

        // ANA airline brand impersonation from non-Japanese domains
        if ((content.contains("ana") && content.contains("マイル"))
            || content.contains("anaマイレージ"))
            && !sender_domain.contains("ana")
            && !sender_domain.ends_with(".jp")
        {
            score += 150;
            evidence.push("ANA airline brand impersonation from non-Japanese domain".to_string());
        }

        // Check for health product promotion from suspicious domains
        let suspicious_domains = ["cookfest", "fiveharvest", "foodie", "recipe", "kitchen"];
        let is_suspicious_domain = suspicious_domains.iter().any(|d| sender_domain.contains(d));

        if is_suspicious_domain {
            for product in &health_products {
                if content.contains(product) {
                    score += 60;
                    evidence.push(format!(
                        "Health product '{}' promotion from food/cooking domain",
                        product
                    ));
                    break;
                }
            }
        }

        // Pet health spam patterns (exclude legitimate news and platforms)
        let legitimate_news = [
            "nytimes",
            "washingtonpost",
            "cnn",
            "bbc",
            "reuters",
            "disney",
            "quora",
            "medium",
            "sparkpost",
            "thegadgetflow",
            "gadgetflow",
        ];
        let is_legitimate_news = legitimate_news
            .iter()
            .any(|news| sender_domain.contains(news));

        if (content.contains("dog") || content.contains("pet") || content.contains("puppy"))
            && (content.contains("add") && content.contains("years") && content.contains("life"))
            && !is_legitimate_news
        {
            score += 80;
            evidence.push("Pet health spam: 'Add years to your pet's life' claim".to_string());
        }

        // Vision health spam patterns
        if content.contains("throw away")
            && (content.contains("glasses") || content.contains("contacts"))
        {
            score += 80;
            evidence.push("Vision health spam: 'Throw away glasses' claim".to_string());
        }

        // Generic health miracle claims
        if (content.contains("miracle")
            || content.contains("breakthrough")
            || content.contains("secret"))
            && (content.contains("health")
                || content.contains("cure")
                || content.contains("treatment"))
        {
            score += 60;
            evidence.push("Health miracle claim detected".to_string());
        }

        // Memory/cognitive enhancement spam
        if (content.contains("memory")
            || content.contains("cognitive")
            || content.contains("brain"))
            && (content.contains("trick")
                || content.contains("enhance")
                || content.contains("improve")
                || content.contains("boost")
                || content.contains("sharpen"))
        {
            score += 80;
            evidence.push("Memory/cognitive enhancement spam detected".to_string());
        }

        // Fungus/toe health spam
        if (content.contains("fungus") || content.contains("toenail"))
            && (content.contains("rub")
                || content.contains("apply")
                || content.contains("treatment"))
        {
            score += 70;
            evidence.push("Fungus treatment spam detected".to_string());
        }

        // Generic phishing with vague subject from free email providers
        let subject_lower = context.subject.as_deref().unwrap_or("").to_lowercase();
        let vague_subjects = [
            "check in",
            "hello",
            "hi there",
            "hey",
            "update",
            "important",
        ];
        let free_email_providers = ["hotmail", "gmail", "yahoo", "aol", "outlook"];

        // Don't flag replies or forwards
        let is_reply_or_forward = subject_lower.starts_with("re:")
            || subject_lower.starts_with("fwd:")
            || subject_lower.starts_with("fw:");

        let is_vague_subject = vague_subjects.iter().any(|s| {
            let subject_words: Vec<&str> = subject_lower.split_whitespace().collect();
            subject_words.len() <= 3 && subject_lower.contains(s)
        });

        let is_free_email = free_email_providers
            .iter()
            .any(|provider| sender_domain.contains(provider));

        // Only flag if it's NOT a reply/forward AND has vague subject AND from free email
        if is_vague_subject && is_free_email && !is_reply_or_forward {
            score += 60;
            evidence.push("Generic phishing: vague subject from free email provider".to_string());
        }

        // Health reward/gift scams (exclude legitimate retailers)
        if (content.contains("health") || content.contains("dental") || content.contains("medical"))
            && (content.contains("free") || content.contains("gift") || content.contains("reward"))
        {
            // Exclude legitimate retailers, healthcare companies, entertainment, and ESPs
            let legitimate_retailers = [
                "1800flowers",
                "pulse.celebrations",
                "ftd",
                "teleflora",
                "proflowers",
                "adapthealth",
                "adapthealthmarketplace",
                "shutterfly",
                "disney",
                "walgreens",
                "evergreentlc",
                "sparkpost",
                // Medical organizations
                "mtasv",
                "batemanhornecenter",
                // News organizations
                "nytdirect",
                "nytimes.com",
            ];
            let is_legitimate_retailer = legitimate_retailers
                .iter()
                .any(|retailer| sender_domain.contains(retailer));

            if !is_legitimate_retailer {
                score += 40;
                evidence.push("Health-related free gift/reward offer".to_string());
            }
        }

        let confidence = if score > 0 { 0.9 } else { 0.1 };

        FeatureScore {
            feature_name: "Health Spam".to_string(),
            score,
            confidence,
            evidence,
        }
    }
}

impl Default for HealthSpamAnalyzer {
    fn default() -> Self {
        Self
    }
}
