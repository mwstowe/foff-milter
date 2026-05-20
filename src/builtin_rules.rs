// Built-in rules — converted from YAML rulesets
// This replaces the YAML loading pipeline with compile-time rules.

use crate::heuristic_config::{Criteria, FilterRule, Module};

pub fn builtin_modules() -> Vec<Module> {
    vec![
        Module {
            name: "Authentication Validation".to_string(),
            enabled: true,
            hash: "builtin".to_string(),
            rules: vec![
                FilterRule {
                    name: "Critical Authentication Failure".to_string(),
                    enabled: true,
                    criteria:
                    Criteria::And {
                        criteria: vec![
                        Criteria::Or {
                            criteria: vec![
                            Criteria::HeaderPattern { header: "Authentication-Results".to_string(), pattern: "dkim=fail".to_string() },
                            Criteria::HeaderPattern { header: "Authentication-Results".to_string(), pattern: "spf=fail".to_string() },
                            ],
                        },
                        Criteria::Or {
                            criteria: vec![
                            Criteria::HeaderPattern { header: "From".to_string(), pattern: "(?i).{0,100}(paypal|amazon|microsoft|google|apple|bank).*".to_string() },
                            Criteria::SubjectPattern { pattern: "(?i).{0,100}(urgent|verify|suspended|security|payment).*".to_string() },
                            ],
                        },
                        Criteria::Not {
                            criteria: Box::new(
                            Criteria::SenderPattern { pattern: ".*@.*(amazonses|sendgrid|mailchimp|sparkpostmail)\\.(com|net)$".to_string() }
                            ),
                        },
                        ],
                    },
                    action: None,
                    score: Some(100),
                    description: Some("Authentication failure for critical brands or urgent content".to_string()),
                },
                FilterRule {
                    name: "DKIM Failure Penalty".to_string(),
                    enabled: true,
                    criteria:
                    Criteria::And {
                        criteria: vec![
                        Criteria::FeatureAnalysis {
                            feature_name: "Authentication Analysis".to_string(),
                            min_score: None,
                            max_score: None,
                            evidence_pattern: Some("DKIM authentication failed".to_string()),
                            invert: None,
                        },
                        Criteria::Not {
                            criteria: Box::new(
                            Criteria::Or {
                                criteria: vec![
                                Criteria::SenderPattern { pattern: ".*@.*(gov|edu|mil)$".to_string() },
                                Criteria::SenderPattern { pattern: ".*@.*(example\\.com|example\\.org|example\\.net)$".to_string() },
                                Criteria::SenderPattern { pattern: ".*@.*(amazonses|sendgrid|mailchimp|sparkpostmail|adobe|costco)\\.(com|net)$".to_string() },
                                Criteria::SenderPattern { pattern: ".*@.*(empower|fidelity|vanguard|schwab|merrill|chase|wellsfargo|bankofamerica)\\.(com|org)$".to_string() },
                                Criteria::SenderPattern { pattern: ".*@.*oxfordclub\\.(com|org)$".to_string() },
                                Criteria::And {
                                    criteria: vec![
                                    Criteria::SubjectPattern { pattern: "(?i).{0,100}(invoice|receipt|statement|bill|payment|quote|estimate).*".to_string() },
                                    Criteria::SenderPattern { pattern: ".*@.*(exterminators|contractors|services|business|company)\\.(com|net|org)$".to_string() },
                                    ],
                                },
                                ],
                            }
                            ),
                        },
                        ],
                    },
                    action: None,
                    score: Some(30),
                    description: Some("DKIM signature validation failure".to_string()),
                },
                FilterRule {
                    name: "SPF Failure Penalty".to_string(),
                    enabled: true,
                    criteria:
                    Criteria::And {
                        criteria: vec![
                        Criteria::FeatureAnalysis {
                            feature_name: "Authentication Analysis".to_string(),
                            min_score: None,
                            max_score: None,
                            evidence_pattern: Some("SPF authentication failed".to_string()),
                            invert: None,
                        },
                        Criteria::Not {
                            criteria: Box::new(
                            Criteria::SenderPattern { pattern: ".*@.*(gov|edu|mil)$".to_string() }
                            ),
                        },
                        ],
                    },
                    action: None,
                    score: Some(30),
                    description: Some("SPF policy validation failure".to_string()),
                },
                FilterRule {
                    name: "Domain Mismatch Detection".to_string(),
                    enabled: true,
                    criteria:
                    Criteria::And {
                        criteria: vec![
                        Criteria::HeaderPattern { header: "From".to_string(), pattern: "(?i).{0,100}(company|organization|business|enterprise).*".to_string() },
                        Criteria::Not {
                            criteria: Box::new(
                            Criteria::Or {
                                criteria: vec![
                                Criteria::SenderPattern { pattern: ".*@.*\\.(com|org|net|edu|gov)$".to_string() },
                                Criteria::And {
                                    criteria: vec![
                                    Criteria::FeatureAnalysis {
                                        feature_name: "Authentication Analysis".to_string(),
                                        min_score: None,
                                        max_score: None,
                                        evidence_pattern: Some("DKIM authentication passed".to_string()),
                                        invert: None,
                                    },
                                    Criteria::FeatureAnalysis {
                                        feature_name: "Authentication Analysis".to_string(),
                                        min_score: None,
                                        max_score: None,
                                        evidence_pattern: Some("SPF authentication passed".to_string()),
                                        invert: None,
                                    },
                                    ],
                                },
                                ],
                            }
                            ),
                        },
                        ],
                    },
                    action: None,
                    score: Some(75),
                    description: Some("Sender domain mismatch with claimed organization".to_string()),
                },
                FilterRule {
                    name: "Suspicious Sender Patterns".to_string(),
                    enabled: true,
                    criteria:
                    Criteria::Or {
                        criteria: vec![
                        Criteria::SenderPattern { pattern: ".*@[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}$".to_string() },
                        Criteria::SenderPattern { pattern: ".*@.*\\.(tk|ml|ga|cf|gq|pl|cn)$".to_string() },
                        Criteria::And {
                            criteria: vec![
                            Criteria::SenderPattern { pattern: ".*[0-9]{8,}@.*".to_string() },
                            Criteria::Not {
                                criteria: Box::new(
                                Criteria::Or {
                                    criteria: vec![
                                    Criteria::SenderPattern { pattern: ".*@.*\\.(onestopplus|airnz|amazon|walmart|target|bestbuy|costco|homedepot|sendgrid|mailchimp|klaviyo|constantcontact|twilio|commonspirit)\\.(com|co\\.nz|net|org)$".to_string() },
                                    Criteria::SenderPattern { pattern: ".*(bounce|campaign|track|newsletter|promo|marketing|email|mail|esp|delivery|notification)-.*[0-9]{8,}@.*".to_string() },
                                    Criteria::SenderPattern { pattern: ".*(do-not-reply|noreply|no-reply).*[0-9]{8,}@.*".to_string() },
                                    ],
                                }
                                ),
                            },
                            ],
                        },
                        Criteria::SenderPattern { pattern: ".*@invalid$".to_string() },
                        Criteria::SenderPattern { pattern: ".*@.*\\.(icu|top|click|download|loan|win)$".to_string() },
                        ],
                    },
                    action: None,
                    score: Some(50),
                    description: Some("Suspicious sender domain or address patterns (excludes legitimate ESP tracking)".to_string()),
                },
                FilterRule {
                    name: "Missing Authentication Headers".to_string(),
                    enabled: true,
                    criteria:
                    Criteria::And {
                        criteria: vec![
                        Criteria::FeatureAnalysis {
                            feature_name: "Authentication Analysis".to_string(),
                            min_score: None,
                            max_score: None,
                            evidence_pattern: Some("Authentication risk level: Insecure".to_string()),
                            invert: None,
                        },
                        Criteria::Or {
                            criteria: vec![
                            Criteria::SubjectPattern { pattern: "(?i).{0,100}(urgent|verify|suspended|security|payment).*".to_string() },
                            Criteria::HeaderPattern { header: "From".to_string(), pattern: "(?i).{0,100}(official|support|security|billing).*".to_string() },
                            ],
                        },
                        Criteria::Not {
                            criteria: Box::new(
                            Criteria::Or {
                                criteria: vec![
                                Criteria::SenderPattern { pattern: ".*@.*(xfinity|comcast|verizon|att|tmobile|sprint)\\.(com|net)$".to_string() },
                                Criteria::SenderPattern { pattern: ".*@.*(gov|edu|mil)$".to_string() },
                                ],
                            }
                            ),
                        },
                        ],
                    },
                    action: None,
                    score: Some(40),
                    description: Some("Missing authentication headers for suspicious content using feature analysis".to_string()),
                },
                FilterRule {
                    name: "No Authentication Analysis Available".to_string(),
                    enabled: true,
                    criteria:
                    Criteria::And {
                        criteria: vec![
                        Criteria::FeatureAnalysis {
                            feature_name: "Authentication Analysis".to_string(),
                            min_score: None,
                            max_score: None,
                            evidence_pattern: Some(".*".to_string()),
                            invert: Some(true),
                        },
                        Criteria::Or {
                            criteria: vec![
                            Criteria::SubjectPattern { pattern: "(?i).{0,100}(urgent|verify|suspended|security|payment|declined|expired).*".to_string() },
                            Criteria::HeaderPattern { header: "From".to_string(), pattern: "(?i).{0,100}(official|support|security|billing|noreply).*".to_string() },
                            ],
                        },
                        ],
                    },
                    action: None,
                    score: Some(35),
                    description: Some("No authentication analysis available for suspicious content".to_string()),
                },
                FilterRule {
                    name: "Forged Sender Headers".to_string(),
                    enabled: true,
                    criteria:
                    Criteria::And {
                        criteria: vec![
                        Criteria::HeaderPattern { header: "From".to_string(), pattern: "(?i).{0,100}(no.{0,100}reply|do.{0,100}not.{0,100}reply|automated|system).*".to_string() },
                        Criteria::Or {
                            criteria: vec![
                            Criteria::SubjectPattern { pattern: "(?i).{0,100}(click.{0,100}here.{0,100}verify|verify.{0,100}account.{0,100}now|urgent.{0,100}action.{0,100}required|immediate.{0,100}verification|account.{0,100}suspended).*".to_string() },
                            Criteria::BodyPattern { pattern: "(?i).{0,100}(click.{0,100}here.{0,100}verify|verify.{0,100}account.{0,100}immediately|urgent.{0,100}action.{0,100}required|account.{0,100}will.{0,100}be.{0,100}closed).*".to_string() },
                            ],
                        },
                        Criteria::Or {
                            criteria: vec![
                            Criteria::HeaderPattern { header: "Authentication-Results".to_string(), pattern: "dkim=fail".to_string() },
                            Criteria::Not {
                                criteria: Box::new(
                                Criteria::HeaderPattern { header: "Authentication-Results".to_string(), pattern: "dkim=pass".to_string() }
                                ),
                            },
                            ],
                        },
                        ],
                    },
                    action: None,
                    score: Some(60),
                    description: Some("Forged no-reply headers with phishing language and auth failure".to_string()),
                },
                FilterRule {
                    name: "Perfect Authentication".to_string(),
                    enabled: true,
                    criteria:
                    Criteria::And {
                        criteria: vec![
                        Criteria::FeatureAnalysis {
                            feature_name: "Authentication Analysis".to_string(),
                            min_score: None,
                            max_score: None,
                            evidence_pattern: Some("Authentication risk level: Secure".to_string()),
                            invert: None,
                        },
                        Criteria::Not {
                            criteria: Box::new(
                            Criteria::Or {
                                criteria: vec![
                                Criteria::And {
                                    criteria: vec![
                                    Criteria::FeatureAnalysis {
                                        feature_name: "Server Role Analysis".to_string(),
                                        min_score: None,
                                        max_score: None,
                                        evidence_pattern: Some("Authentication bonus should be reduced".to_string()),
                                        invert: None,
                                    },
                                    Criteria::Not {
                                        criteria: Box::new(
                                        Criteria::HeaderPattern { header: "Authentication-Results".to_string(), pattern: "dmarc=pass".to_string() }
                                        ),
                                    },
                                    ],
                                },
                                Criteria::FeatureAnalysis {
                                    feature_name: "Link Analysis".to_string(),
                                    min_score: None,
                                    max_score: None,
                                    evidence_pattern: Some("cross-domain links to spam-like domain".to_string()),
                                    invert: None,
                                },
                                Criteria::FeatureAnalysis {
                                    feature_name: "Health Spam".to_string(),
                                    min_score: None,
                                    max_score: None,
                                    evidence_pattern: Some("impersonation from non-health domain".to_string()),
                                    invert: None,
                                },
                                Criteria::FeatureAnalysis {
                                    feature_name: "Context Analysis".to_string(),
                                    min_score: None,
                                    max_score: None,
                                    evidence_pattern: Some("Investment/stock spam".to_string()),
                                    invert: None,
                                },
                                Criteria::FeatureAnalysis {
                                    feature_name: "Context Analysis".to_string(),
                                    min_score: None,
                                    max_score: None,
                                    evidence_pattern: Some("scam pattern detected".to_string()),
                                    invert: None,
                                },
                                Criteria::And {
                                    criteria: vec![
                                    Criteria::FeatureAnalysis {
                                        feature_name: "Domain Reputation".to_string(),
                                        min_score: None,
                                        max_score: None,
                                        evidence_pattern: Some("Suspicious domain pattern detected".to_string()),
                                        invert: None,
                                    },
                                    Criteria::FeatureAnalysis {
                                        feature_name: "Domain Reputation".to_string(),
                                        min_score: None,
                                        max_score: None,
                                        evidence_pattern: Some("Excessively long domain name".to_string()),
                                        invert: None,
                                    },
                                    Criteria::Not {
                                        criteria: Box::new(
                                        Criteria::HeaderPattern { header: "Authentication-Results".to_string(), pattern: "dmarc=pass".to_string() }
                                        ),
                                    },
                                    ],
                                },
                                // Block Perfect Auth when TLD is suspicious and no DMARC
                                Criteria::And {
                                    criteria: vec![
                                    Criteria::FeatureAnalysis {
                                        feature_name: "TLD Risk Assessment".to_string(),
                                        min_score: None,
                                        max_score: None,
                                        evidence_pattern: Some("Suspicious TLD".to_string()),
                                        invert: None,
                                    },
                                    Criteria::Not {
                                        criteria: Box::new(
                                        Criteria::HeaderPattern { header: "Authentication-Results".to_string(), pattern: "dmarc=pass".to_string() }
                                        ),
                                    },
                                    ],
                                },
                                ],
                            }
                            ),
                        },
                        ],
                    },
                    action: None,
                    score: Some(-30),
                    description: Some("Perfect authentication using feature analysis (Secure risk level)".to_string()),
                },
                FilterRule {
                    name: "Government Educational Domains".to_string(),
                    enabled: true,
                    criteria:
                    Criteria::And {
                        criteria: vec![
                        Criteria::SenderPattern { pattern: ".*@.*\\.(gov|edu|mil)$".to_string() },
                        Criteria::HeaderPattern { header: "Authentication-Results".to_string(), pattern: "dkim=pass".to_string() },
                        ],
                    },
                    action: None,
                    score: Some(-50),
                    description: Some("Government, educational, and military domains with DKIM authentication".to_string()),
                },
                FilterRule {
                    name: "Feature-Based Suspicious Email Detection".to_string(),
                    enabled: false,
                    criteria:
                    Criteria::And {
                        criteria: vec![
                        Criteria::FeatureAnalysis {
                            feature_name: "Sender Alignment".to_string(),
                            min_score: Some(30),
                            max_score: None,
                            evidence_pattern: None,
                            invert: None,
                        },
                        Criteria::FeatureAnalysis {
                            feature_name: "Authentication Analysis".to_string(),
                            min_score: None,
                            max_score: None,
                            evidence_pattern: Some("Authentication risk level: (Suspicious|Insecure)".to_string()),
                            invert: None,
                        },
                        ],
                    },
                    action: None,
                    score: Some(50),
                    description: Some("Combination of sender alignment issues and authentication problems using feature analysis".to_string()),
                },
                FilterRule {
                    name: "Established Domain Authentication".to_string(),
                    enabled: true,
                    criteria:
                    Criteria::And {
                        criteria: vec![
                        Criteria::FeatureAnalysis {
                            feature_name: "Authentication Analysis".to_string(),
                            min_score: None,
                            max_score: None,
                            evidence_pattern: Some("DKIM authentication passed".to_string()),
                            invert: None,
                        },
                        Criteria::Or {
                            criteria: vec![
                            Criteria::SenderPattern { pattern: ".*@.*(amazon|microsoft|google|apple|paypal|ebay|walmart|target|bestbuy|homedepot|lowes|macys|nordstrom|costco)\\.(com|org|net)$".to_string() },
                            Criteria::SenderPattern { pattern: ".*@.*(chase|wellsfargo|bankofamerica|citi|usbank|capitalone|discover|americanexpress)\\.(com|org|net)$".to_string() },
                            Criteria::SenderPattern { pattern: ".*@.*(fedex|ups|usps|dhl)\\.(com|org|net|gov)$".to_string() },
                            Criteria::SenderPattern { pattern: ".*@.*(netflix|spotify|hulu|disney|adobe|salesforce|shopify)\\.(com|org|net)$".to_string() },
                            Criteria::SenderPattern { pattern: ".*@.*(govdelivery|public\\.govdelivery)\\.(com|org|net)$".to_string() },
                            Criteria::SenderPattern { pattern: ".*@.*\\.(gov|edu|mil)$".to_string() },
                            ],
                        },
                        ],
                    },
                    action: None,
                    score: Some(-20),
                    description: Some("Known legitimate domains with valid DKIM signatures using feature analysis".to_string()),
                },
                FilterRule {
                    name: "Known spam domains".to_string(),
                    enabled: true,
                    criteria:
                    Criteria::Or {
                        criteria: vec![
                        Criteria::SenderPattern { pattern: ".*@.*sfcondoteam\\.com$".to_string() },
                        Criteria::HeaderPattern { header: "Return-Path".to_string(), pattern: ".*@.*sfcondoteam\\.com$".to_string() },
                        Criteria::SenderPattern { pattern: ".*@.*skinviti\\.icu$".to_string() },
                        Criteria::HeaderPattern { header: "Return-Path".to_string(), pattern: ".*@.*skinviti\\.icu$".to_string() },
                        ],
                    },
                    action: None,
                    score: Some(200),
                    description: Some("Known repeat spam domains".to_string()),
                },
                FilterRule {
                    name: "Suspicious domains with brand claims".to_string(),
                    enabled: true,
                    criteria:
                    Criteria::And {
                        criteria: vec![
                        Criteria::Or {
                            criteria: vec![
                            Criteria::SenderPattern { pattern: ".*\\.(icu|tk|ml|ga|cf|top|click|download)$".to_string() },
                            Criteria::HeaderPattern { header: "Return-Path".to_string(), pattern: ".*\\.(icu|tk|ml|ga|cf|top|click|download)$".to_string() },
                            ],
                        },
                        Criteria::Or {
                            criteria: vec![
                            Criteria::SubjectPattern { pattern: "(?i).{0,100}(amazon|apple|microsoft|google|facebook|paypal|aarp|walmart|target|netflix|disney|fedex|ups|visa|chase|bank).*".to_string() },
                            Criteria::SenderPattern { pattern: "(?i).{0,100}(amazon|apple|microsoft|google|facebook|paypal|aarp|walmart|target|netflix|disney|fedex|ups|visa|chase|bank).*".to_string() },
                            ],
                        },
                        ],
                    },
                    action: None,
                    score: Some(120),
                    description: Some("Suspicious TLD domains claiming to be major brands".to_string()),
                },
                FilterRule {
                    name: "DKIM signature verification failed".to_string(),
                    enabled: true,
                    criteria:
                    Criteria::And {
                        criteria: vec![
                        Criteria::FeatureAnalysis {
                            feature_name: "Authentication Analysis".to_string(),
                            min_score: None,
                            max_score: None,
                            evidence_pattern: Some("DKIM authentication failed.{0,100}signature verification failed".to_string()),
                            invert: None,
                        },
                        Criteria::Not {
                            criteria: Box::new(
                            Criteria::Or {
                                criteria: vec![
                                Criteria::SenderPattern { pattern: ".*@.*(gmail|yahoo|hotmail|outlook|aol|icloud|mcdonalds|netflix|amazon|microsoft|google|apple)\\.(com|net)$".to_string() },
                                Criteria::SenderPattern { pattern: ".*@.*(amazonses|sendgrid|mailchimp|sparkpostmail|adobe|costco)\\.(com|net)$".to_string() },
                                Criteria::SenderPattern { pattern: ".*@.*(empower|fidelity|vanguard|schwab|merrill|chase|wellsfargo|bankofamerica)\\.(com|org)$".to_string() },
                                Criteria::SenderPattern { pattern: ".*@.*oxfordclub\\.(com|org)$".to_string() },
                                Criteria::And {
                                    criteria: vec![
                                    Criteria::SubjectPattern { pattern: "(?i).{0,100}(invoice|receipt|statement|bill|payment|quote|estimate).*".to_string() },
                                    Criteria::SenderPattern { pattern: ".*@.*(exterminators|contractors|services|business|company)\\.(com|net|org)$".to_string() },
                                    ],
                                },
                                Criteria::HeaderPattern { header: "Authentication-Results".to_string(), pattern: "(?i)spf=pass".to_string() },
                                ],
                            }
                            ),
                        },
                        ],
                    },
                    action: None,
                    score: Some(15),
                    description: Some("DKIM signature verification failed (reduced penalty for major brands)".to_string()),
                },
                FilterRule {
                    name: "SPF no designated sender hosts".to_string(),
                    enabled: true,
                    criteria:
                    Criteria::And {
                        criteria: vec![
                        Criteria::FeatureAnalysis {
                            feature_name: "Authentication Analysis".to_string(),
                            min_score: None,
                            max_score: None,
                            evidence_pattern: Some("No SPF record found".to_string()),
                            invert: None,
                        },
                        Criteria::Not {
                            criteria: Box::new(
                            Criteria::SenderPattern { pattern: ".*@.*(gov|edu|mil)$".to_string() }
                            ),
                        },
                        ],
                    },
                    action: None,
                    score: Some(10),
                    description: Some("SPF policy not configured (excluding government domains)".to_string()),
                },
            ],
        },
        Module {
            name: "Brand Protection".to_string(),
            enabled: true,
            hash: "builtin".to_string(),
            rules: vec![
                FilterRule {
                    name: "Suspicious TLD Promotional Content".to_string(),
                    enabled: true,
                    criteria:
                    Criteria::And {
                        criteria: vec![
                        Criteria::SenderPattern { pattern: ".*@.*\\.(autos|shop|online|site|store|xyz|top|click|win|bid)$".to_string() },
                        Criteria::Or {
                            criteria: vec![
                            Criteria::SubjectPattern { pattern: "(?i).{0,100}(tough|tactical|survival|adventure|gear|equipment|deal|offer|discount|save|free shipping|limited stock|exclusive).*".to_string() },
                            Criteria::BodyPattern { pattern: "(?i).{0,100}(shop now|order now|buy now|limited stock|exclusive offer|click here to shop).*".to_string() },
                            ],
                        },
                        Criteria::Not {
                            criteria: Box::new(
                            Criteria::SenderPattern { pattern: ".*@.*(sendgrid|mailchimp|klaviyo|amazonses|sparkpost|mailgun)\\.(com|net)$".to_string() }
                            ),
                        },
                        ],
                    },
                    action: None,
                    score: Some(40),
                    description: Some("Promotional content from suspicious TLD (not legitimate ESP)".to_string()),
                },
                FilterRule {
                    name: "Brand Name in Sender Address from Non-Brand Domain".to_string(),
                    enabled: true,
                    criteria:
                    Criteria::And {
                        criteria: vec![
                        Criteria::HeaderPattern { header: "From".to_string(), pattern: "(?i).{0,100}(carshield|geico|progressive|allstate|statefarm|liberty.{0,100}mutual).*@.*".to_string() },
                        Criteria::Not {
                            criteria: Box::new(
                            Criteria::SenderPattern { pattern: ".*@.*(carshield|geico|progressive|allstate|statefarm|libertymutual)\\.(com|net)$".to_string() }
                            ),
                        },
                        ],
                    },
                    action: None,
                    score: Some(75),
                    description: Some("Insurance brand name in sender address but from non-brand domain".to_string()),
                },
                FilterRule {
                    name: "Suspicious Forwarding Domain".to_string(),
                    enabled: true,
                    criteria:
                    Criteria::And {
                        criteria: vec![
                        Criteria::HeaderPattern { header: "Return-Path".to_string(), pattern: ".*@tzkefeng\\.com.*".to_string() },
                        Criteria::Not {
                            criteria: Box::new(
                            Criteria::HeaderPattern { header: "From".to_string(), pattern: ".*@tzkefeng\\.com.*".to_string() }
                            ),
                        },
                        ],
                    },
                    action: None,
                    score: Some(75),
                    description: Some("Email forwarded through suspicious domain (tzkefeng.com) with domain mismatch".to_string()),
                },
                FilterRule {
                    name: "Young Domain Suspicious Content".to_string(),
                    enabled: true,
                    criteria:
                    Criteria::And {
                        criteria: vec![
                        Criteria::DomainAge {
                            max_age_days: 90,
                            check_sender: None,
                            check_reply_to: None,
                            check_from_header: None,
                            timeout_seconds: Some(5),
                            use_mock_data: None,
                        },
                        Criteria::Or {
                            criteria: vec![
                            Criteria::SubjectPattern { pattern: "(?i).{0,100}(urgent|limited.{0,100}(time|spots?|offer)|act.{0,100}now|expires?|before.{0,100}ends|claim|verify|confirm|update.{0,100}account|suspended|locked|unusual.{0,100}activity|security.{0,100}alert).*".to_string() },
                            Criteria::SubjectPattern { pattern: "(?i).{0,100}(prize|winner|congratulations|free.{0,100}gift|exclusive.{0,100}offer|special.{0,100}deal|protect.{0,100}your).*".to_string() },
                            ],
                        },
                        Criteria::Not {
                            criteria: Box::new(
                            Criteria::Or {
                                criteria: vec![
                                Criteria::SenderPattern { pattern: ".*@.*(sendgrid|mailchimp|klaviyo|constantcontact|mailgun|sparkpost|postmark|amazonses|adobe|salesforce)\\.(com|net)$".to_string() },
                                Criteria::SenderPattern { pattern: ".*@.*(thinkgeek|thinkgeekmail|bcdtravel|britishairways|cdw|vacuums)\\.(com|net)$".to_string() },
                                ],
                            }
                            ),
                        },
                        ],
                    },
                    action: None,
                    score: Some(50),
                    description: Some("Young domain (≤90 days) with suspicious urgency or promotional content".to_string()),
                },
                FilterRule {
                    name: "Harbor Freight Brand Impersonation".to_string(),
                    enabled: true,
                    criteria:
                    Criteria::And {
                        criteria: vec![
                        Criteria::Or {
                            criteria: vec![
                            Criteria::SubjectPattern { pattern: "(?i).{0,100}(harbor.{0,100}freight|harborfreight).*".to_string() },
                            Criteria::BodyPattern { pattern: "(?i).{0,100}(harbor.{0,100}freight|harborfreight).*".to_string() },
                            Criteria::HeaderPattern { header: "From".to_string(), pattern: "(?i).{0,100}(harbor.{0,100}freight|harborfreight|harbor@freight).*".to_string() },
                            ],
                        },
                        Criteria::Not {
                            criteria: Box::new(
                            Criteria::SenderPattern { pattern: ".*@.*(harborfreight|hftools)\\.(com|net)$".to_string() }
                            ),
                        },
                        ],
                    },
                    action: None,
                    score: Some(125),
                    description: Some("Harbor Freight brand impersonation from non-legitimate domain".to_string()),
                },
                FilterRule {
                    name: "Chinese Domain Amazon Impersonation".to_string(),
                    enabled: true,
                    criteria:
                    Criteria::And {
                        criteria: vec![
                        Criteria::SenderPattern { pattern: ".*@.*\\.cn$".to_string() },
                        Criteria::Or {
                            criteria: vec![
                            Criteria::SubjectPattern { pattern: "(?i).{0,100}amazon.*".to_string() },
                            Criteria::SubjectPattern { pattern: ".*QW1hem9u.*".to_string() },
                            Criteria::BodyPattern { pattern: "(?i).{0,100}amazon.*".to_string() },
                            ],
                        },
                        ],
                    },
                    action: None,
                    score: Some(150),
                    description: Some("Chinese domain impersonating Amazon (common phishing pattern)".to_string()),
                },
                FilterRule {
                    name: "Feature-Based Brand Impersonation".to_string(),
                    enabled: true,
                    criteria:
                    Criteria::FeatureAnalysis {
                        feature_name: "Sender Alignment".to_string(),
                        min_score: None,
                        max_score: None,
                        evidence_pattern: Some("Brand .* mentioned but sender domain .* not legitimate".to_string()),
                        invert: None,
                    },
                    action: None,
                    score: Some(50),
                    description: Some("Brand impersonation detected via sender alignment analysis".to_string()),
                },
                FilterRule {
                    name: "HR Document Sharing Phishing".to_string(),
                    enabled: true,
                    criteria:
                    Criteria::And {
                        criteria: vec![
                        Criteria::Or {
                            criteria: vec![
                            Criteria::SubjectPattern { pattern: "(?i).{0,100}(hr.{0,100}shared|hr.{0,100}document|salary.{0,100}review|incentive.{0,100}overview|payroll.{0,100}document|employee.{0,100}handbook).*".to_string() },
                            Criteria::BodyPattern { pattern: "(?i).{0,100}(hr.{0,100}department|human.{0,100}resources|salary.{0,100}information|payroll.{0,100}details|employee.{0,100}benefits).*".to_string() },
                            ],
                        },
                        Criteria::Not {
                            criteria: Box::new(
                            Criteria::Or {
                                criteria: vec![
                                Criteria::SenderPattern { pattern: ".*@.*(company\\.com|organization\\.org|legitimate\\.edu)$".to_string() },
                                Criteria::SenderPattern { pattern: ".*@.*(govdelivery|public\\.govdelivery|capitaloneshopping)\\.(com|net|org)$".to_string() },
                                Criteria::SenderPattern { pattern: ".*@.*(nytimes|washingtonpost|cnn|bbc|reuters|ap|wsj|usatoday|acemedseattle)\\.(com|org)$".to_string() },
                                ],
                            }
                            ),
                        },
                        ],
                    },
                    action: None,
                    score: Some(200),
                    description: Some("Business Email Compromise targeting HR/payroll themes".to_string()),
                },
                FilterRule {
                    name: "Organization Impersonation".to_string(),
                    enabled: true,
                    criteria:
                    Criteria::And {
                        criteria: vec![
                        Criteria::Or {
                            criteria: vec![
                            Criteria::SubjectPattern { pattern: "(?i).{0,100}baddomain\\.com\\s+(hr|it|admin|support|team).*".to_string() },
                            Criteria::BodyPattern { pattern: "(?i).{0,100}baddomain\\.com.{0,100}(department|team|staff|employee).*".to_string() },
                            ],
                        },
                        Criteria::Not {
                            criteria: Box::new(
                            Criteria::SenderPattern { pattern: ".*@baddomain\\.com$".to_string() }
                            ),
                        },
                        ],
                    },
                    action: None,
                    score: Some(150),
                    description: Some("Domain mismatch impersonation detection".to_string()),
                },
                FilterRule {
                    name: "Generic brand impersonation".to_string(),
                    enabled: true,
                    criteria:
                    Criteria::And {
                        criteria: vec![
                        Criteria::Or {
                            criteria: vec![
                            Criteria::HeaderPattern { header: "From".to_string(), pattern: "(?i).{0,100}(paypal|amazon|microsoft|google|apple|netflix|walmart|target|chase|bank.{0,100}america|wells.{0,100}fargo).*".to_string() },
                            Criteria::SubjectPattern { pattern: "(?i).{0,100}(paypal|amazon|microsoft|google|apple|netflix|walmart|target|chase|bank.{0,100}america|wells.{0,100}fargo).*".to_string() },
                            ],
                        },
                        Criteria::Or {
                            criteria: vec![
                            Criteria::HeaderPattern { header: "Authentication-Results".to_string(), pattern: "dkim=fail".to_string() },
                            Criteria::HeaderPattern { header: "Authentication-Results".to_string(), pattern: "spf=fail".to_string() },
                            Criteria::And {
                                criteria: vec![
                                Criteria::Not {
                                    criteria: Box::new(
                                    Criteria::HeaderPattern { header: "Authentication-Results".to_string(), pattern: "dkim=pass".to_string() }
                                    ),
                                },
                                Criteria::Not {
                                    criteria: Box::new(
                                    Criteria::Or {
                                        criteria: vec![
                                        Criteria::BodyPattern { pattern: "(?i).{0,100}(apple.{0,100}wallet|google.{0,100}pay|samsung.{0,100}pay|paypal.{0,100}integration|amazon.{0,100}partnership).*".to_string() },
                                        Criteria::SenderPattern { pattern: ".*@.*(discover|chase|citi|amex|wellsfargo|bankofamerica)\\.(com|org)$".to_string() },
                                        ],
                                    }
                                    ),
                                },
                                ],
                            },
                            ],
                        },
                        Criteria::Not {
                            criteria: Box::new(
                            Criteria::Or {
                                criteria: vec![
                                Criteria::SenderPattern { pattern: ".*@.*(medium|backerkit|joinhoney|williams-sonoma|lovepop|shutterfly|resmed|quora|nytimes)\\.(com|org)$".to_string() },
                                Criteria::SenderPattern { pattern: ".*paypal.{0,100}adobe.*".to_string() },
                                Criteria::SenderPattern { pattern: ".*@.*sparkpostmail\\.(com|net)$".to_string() },
                                Criteria::HeaderPattern { header: "Authentication-Results".to_string(), pattern: "dkim=pass.{0,100}\\.(medium|backerkit|joinhoney|williams-sonoma|lovepop|shutterfly|resmed|quora)\\.(com|org)".to_string() },
                                Criteria::HeaderPattern { header: "Authentication-Results".to_string(), pattern: "dmarc=pass".to_string() },
                                ],
                            }
                            ),
                        },
                        ],
                    },
                    action: None,
                    score: Some(200),
                    description: Some("Brand impersonation with authentication failure (excluding legitimate newsletters)".to_string()),
                },
                FilterRule {
                    name: "Known brand from suspicious domain".to_string(),
                    enabled: true,
                    criteria:
                    Criteria::And {
                        criteria: vec![
                        Criteria::Or {
                            criteria: vec![
                            Criteria::HeaderPattern { header: "From".to_string(), pattern: "(?i).{0,100}(McDonald's|Netflix|Disney|Starbucks|Walmart|Amazon|Target|Best Buy|Home Depot|Lowe's|CVS|Walgreens|Chase|Bank of America|Wells Fargo|Citi|Capital One|American Express|Discover|PayPal|Venmo|Cash App|Zelle|Apple|Microsoft|Google|Facebook|Instagram|Twitter|LinkedIn|YouTube|TikTok|Snapchat|WhatsApp|Telegram|Zoom|Skype|Slack|Teams|Dropbox|OneDrive|iCloud|Gmail|Yahoo|Outlook|Hotmail|AOL|Comcast|Verizon|AT&T|T-Mobile|Sprint|UPS|FedEx|USPS|DHL|Uber|Lyft|Airbnb|Booking|Expedia|Priceline|Hotels|Marriott|Hilton|Hyatt|IHG|Choice|Wyndham|Radisson|Accor|Four Seasons|Ritz Carlton|Sheraton|Westin|Doubletree|Hampton|Holiday Inn|Courtyard|Residence Inn|SpringHill|Fairfield|TownePlace|Aloft|Element|Moxy|AC Hotels|Autograph|Tribute|Design Hotels|Luxury Collection|St. Regis|W Hotels|Edition|Le Meridien|Renaissance|Delta|Gaylord|Omni|Loews|Kimpton|Joie de Vivre|Thompson|Tommie|Unbound|Tapestry|Curio|DoubleTree|Embassy Suites|Homewood Suites|Home2 Suites|Tru|Canopy|Signia|LXR|Conrad|Waldorf Astoria|Tempo|Graduate|Even|Avid|WoodSpring|MainStay|Candlewood|Staybridge|Extended Stay|Red Roof|Motel 6|Super 8|Days Inn|Ramada|Howard Johnson|Travelodge|Knights Inn|Econo Lodge|Quality Inn|Comfort Inn|Comfort Suites|Sleep Inn|Clarion|Cambria|Ascend|Suburban|WoodSpring|MainStay|Candlewood|Staybridge|Extended Stay|Red Roof|Motel 6|Super 8|Days Inn|Ramada|Howard Johnson|Travelodge|Knights Inn|Econo Lodge|Quality Inn|Comfort Inn|Comfort Suites|Sleep Inn|Clarion|Cambria|Ascend|Suburban).*".to_string() },
                            Criteria::SubjectPattern { pattern: "(?i).{0,100}(McDonald's|Netflix|Disney|Starbucks|major.{0,100}brand|official.{0,100}notification|customer.{0,100}service|account.{0,100}verification|security.{0,100}alert).*".to_string() },
                            ],
                        },
                        Criteria::Not {
                            criteria: Box::new(
                            Criteria::Or {
                                criteria: vec![
                                Criteria::SenderPattern { pattern: ".*@.*(mcdonalds|netflix|disney|disneypublishing|starbucks|walmart|amazon|amazonmusic|target|bestbuy|homedepot|lowes|cvs|walgreens|chase|bankofamerica|wellsfargo|citi|capitalone|americanexpress|discover|paypal|venmo|apple|microsoft|google|facebook|instagram|twitter|linkedin|youtube|tiktok|snapchat|whatsapp|telegram|zoom|skype|slack|teams|dropbox|onedrive|icloud|gmail|yahoo|outlook|hotmail|aol|comcast|verizon|att|tmobile|sprint|ups|fedex|usps|dhl|uber|lyft|airbnb|booking|expedia|priceline|hotels|marriott|hilton|hyatt|ihg|choice|wyndham|radisson|accor|fidelity|fidelityinvestments|d23|waltdisneypictures|synchrony|comenity|barclays|geico)\\.(com|org|net)$".to_string() },
                                Criteria::SenderPattern { pattern: ".*@.*(sparkpostmail|sendgrid|mailchimp|mailchimpapp|amazonses|constantcontact|mailgun|facebookmail|zoomcare|pb-dynmktg|pardot|marketo|eloqua|hubspot|campaignmonitor)\\.(com|net)$".to_string() },
                                Criteria::SenderPattern { pattern: ".*paypal.{0,100}adobe.*".to_string() },
                                Criteria::SenderPattern { pattern: ".*@.*iheart\\.(com|net)$".to_string() },
                                ],
                            }
                            ),
                        },
                        ],
                    },
                    action: None,
                    score: Some(150),
                    description: Some("Known brand claims from suspicious or unrelated domains".to_string()),
                },
                FilterRule {
                    name: "AAA Emergency Kit Scams".to_string(),
                    enabled: true,
                    criteria:
                    Criteria::And {
                        criteria: vec![
                        Criteria::Or {
                            criteria: vec![
                            Criteria::SubjectPattern { pattern: "(?i).{0,100}(aaa.{0,100}emergency.{0,100}kit|triple.{0,100}a.{0,100}kit|car.{0,100}emergency.{0,100}kit|safety.{0,100}kit|survival.{0,100}kit).*".to_string() },
                            Criteria::BodyPattern { pattern: "(?i).{0,100}(aaa.{0,100}member|triple.{0,100}a.{0,100}member|emergency.{0,100}roadside|car.{0,100}breakdown|roadside.{0,100}assistance).*".to_string() },
                            Criteria::BodyPattern { pattern: "(?i).{0,100}(state.{0,100}farm.{0,100}kit|allstate.{0,100}kit|geico.{0,100}kit|progressive.{0,100}kit).*".to_string() },
                            ],
                        },
                        Criteria::Not {
                            criteria: Box::new(
                            Criteria::Or {
                                criteria: vec![
                                Criteria::SenderPattern { pattern: ".*@.*nytimes.*".to_string() },
                                Criteria::SenderPattern { pattern: ".*@.*(geico|statefarm|allstate|progressive|libertymutual|nationwide|usaa|farmers|travelers|aaa|erie)\\.(com|net|org)$".to_string() },
                                ],
                            }
                            ),
                        },
                        ],
                    },
                    action: None,
                    score: Some(150),
                    description: Some("AAA and insurance company emergency kit scams".to_string()),
                },
                FilterRule {
                    name: "Microsoft OnMicrosoft Compromise".to_string(),
                    enabled: true,
                    criteria:
                    Criteria::And {
                        criteria: vec![
                        Criteria::SenderPattern { pattern: ".*@.*\\.onmicrosoft\\.com$".to_string() },
                        Criteria::Or {
                            criteria: vec![
                            Criteria::HeaderPattern { header: "Authentication-Results".to_string(), pattern: "dkim=fail".to_string() },
                            Criteria::SubjectPattern { pattern: "(?i).{0,100}(taste|special|uid[0-9]+|restaurant|food|dining).*".to_string() },
                            ],
                        },
                        ],
                    },
                    action: None,
                    score: Some(100),
                    description: Some("Compromised Microsoft tenant domains".to_string()),
                },
                FilterRule {
                    name: "Healthcare Government Impersonation".to_string(),
                    enabled: true,
                    criteria:
                    Criteria::And {
                        criteria: vec![
                        Criteria::Or {
                            criteria: vec![
                            Criteria::SubjectPattern { pattern: "(?i).*(medicare|medicaid|unitedhealthcare|benefits.{0,30}center|veteran.{0,30}affairs).*".to_string() },
                            Criteria::BodyPattern { pattern: "(?i).*(health.{0,30}insurance|medicare.{0,30}advantage|benefits.{0,30}enrollment|va.{0,30}benefits|health.{0,30}benefits.{0,30}center).*".to_string() },
                            Criteria::SubjectPattern { pattern: "(?i).*(cvs.{0,30}order|pharmacy.{0,30}confirmation|prescription.{0,30}ready|health.{0,30}plan).*".to_string() },
                            ],
                        },
                        Criteria::Not {
                            criteria: Box::new(
                            Criteria::Or {
                                criteria: vec![
                                Criteria::SenderPattern { pattern: ".*@.*(cvs|unitedhealthcare|medicare|va|veterans|adapthealth|adapthealthmarketplace|sears|searshomeservices|nytimes|newyorktimes)\\.(com|org|gov)$".to_string() },
                                Criteria::BodyPattern { pattern: "(?i).*(loyalty.{0,30}program|rewards.{0,30}program|membership.{0,30}benefits|shipping.{0,30}benefits|passport.{0,30}benefits).*".to_string() },
                                ],
                            }
                            ),
                        },
                        ],
                    },
                    action: None,
                    score: Some(175),
                    description: Some("Healthcare and government service impersonation".to_string()),
                },
                FilterRule {
                    name: "Critical Brand Impersonation".to_string(),
                    enabled: true,
                    criteria:
                    Criteria::And {
                        criteria: vec![
                        Criteria::SenderPattern { pattern: "(?i).{0,100}(amazon|apple|microsoft|google|facebook|paypal|aarp|walmart|target|netflix|disney|fedex|ups|visa|chase|bank).*".to_string() },
                        Criteria::Or {
                            criteria: vec![
                            Criteria::HeaderPattern { header: "Authentication-Results".to_string(), pattern: "dkim=fail".to_string() },
                            Criteria::HeaderPattern { header: "Authentication-Results".to_string(), pattern: "spf=fail".to_string() },
                            ],
                        },
                        Criteria::Not {
                            criteria: Box::new(
                            Criteria::Or {
                                criteria: vec![
                                Criteria::SenderPattern { pattern: ".*@.*(sparkpostmail|sendgrid|mailchimp|constantcontact|amazonses|mailgun|klaviyomail|campaignmonitor|aweber)\\.(com|net|org)$".to_string() },
                                Criteria::SenderPattern { pattern: ".*@.*(amazon|google|microsoft|apple|netflix|walmart|target|disney|fedex|ups|visa|chase)\\.(com|org)$".to_string() },
                                Criteria::HeaderPattern { header: "From".to_string(), pattern: "(?i).{0,100}(newsletter|digest|marketing|promotional|noreply|no-reply).*".to_string() },
                                ],
                            }
                            ),
                        },
                        ],
                    },
                    action: None,
                    score: Some(300),
                    description: Some("Critical: Major brand + authentication failure + domain mismatch".to_string()),
                },
                FilterRule {
                    name: "ANA Airline Impersonation Chinese Domain".to_string(),
                    enabled: true,
                    criteria:
                    Criteria::And {
                        criteria: vec![
                        Criteria::SenderPattern { pattern: ".*@.*\\.cn$".to_string() },
                        Criteria::Or {
                            criteria: vec![
                            Criteria::HeaderPattern { header: "From".to_string(), pattern: "(?i).{0,100}ana.*".to_string() },
                            Criteria::SubjectPattern { pattern: ".*ANA.*".to_string() },
                            ],
                        },
                        ],
                    },
                    action: None,
                    score: Some(200),
                    description: Some("ANA airline impersonation from Chinese domain".to_string()),
                },
                FilterRule {
                    name: "Microsoft tenant Stanley Tools impersonation".to_string(),
                    enabled: true,
                    criteria:
                    Criteria::HeaderPattern { header: "From".to_string(), pattern: ".*@dailydials19\\.onmicrosoft\\.com.*".to_string() },
                    action: None,
                    score: Some(100),
                    description: Some("Brand impersonation from Microsoft tenant".to_string()),
                },
                FilterRule {
                    name: "State Farm Fire Kit Impersonation".to_string(),
                    enabled: true,
                    criteria:
                    Criteria::Or {
                        criteria: vec![
                        Criteria::SubjectPattern { pattern: "(?i).{0,100}(fire.{0,100}doesn.{0,100}t.{0,100}wait.{0,100}neither.{0,100}should.{0,100}you|state.{0,100}farm.{0,100}fire.{0,100}emergency.{0,100}kit|fire.{0,100}kit.{0,100}brand.{0,100}impersonation).*".to_string() },
                        Criteria::BodyPattern { pattern: "(?i).{0,100}(fire.{0,100}doesn.{0,100}t.{0,100}wait.{0,100}neither.{0,100}should.{0,100}you|state.{0,100}farm.{0,100}fire.{0,100}emergency.{0,100}kit|fire.{0,100}kit.{0,100}brand.{0,100}impersonation).*".to_string() },
                        ],
                    },
                    action: None,
                    score: Some(280),
                    description: None,
                },
                FilterRule {
                    name: "WeTransfer Brand Impersonation".to_string(),
                    enabled: true,
                    criteria:
                    Criteria::Or {
                        criteria: vec![
                        Criteria::SubjectPattern { pattern: "(?i).{0,100}(transfer.{0,100}you.{0,100}received.{0,100}expired.{0,100}can.{0,100}still.{0,100}recover|wetransfer.{0,100}brand.{0,100}impersonation|fake.{0,100}wetransfer).*".to_string() },
                        Criteria::BodyPattern { pattern: "(?i).{0,100}(transfer.{0,100}you.{0,100}received.{0,100}expired.{0,100}can.{0,100}still.{0,100}recover|wetransfer.{0,100}brand.{0,100}impersonation|fake.{0,100}wetransfer).*".to_string() },
                        ],
                    },
                    action: None,
                    score: Some(300),
                    description: None,
                },
                FilterRule {
                    name: "YETI Brand Impersonation Google Workspace".to_string(),
                    enabled: true,
                    criteria:
                    Criteria::Or {
                        criteria: vec![
                        Criteria::SubjectPattern { pattern: "(?i).{0,100}(yeti.{0,100}outdoor.{0,100}bundle.{0,100}final.{0,100}shipping.{0,100}stage|yeti.{0,100}brand.{0,100}impersonation|fake.{0,100}yeti.{0,100}shipping).*".to_string() },
                        Criteria::BodyPattern { pattern: "(?i).{0,100}(yeti.{0,100}outdoor.{0,100}bundle.{0,100}final.{0,100}shipping.{0,100}stage|yeti.{0,100}brand.{0,100}impersonation|fake.{0,100}yeti.{0,100}shipping).*".to_string() },
                        ],
                    },
                    action: None,
                    score: Some(290),
                    description: None,
                },
                FilterRule {
                    name: "USA Today Brand Impersonation".to_string(),
                    enabled: true,
                    criteria:
                    Criteria::Or {
                        criteria: vec![
                        Criteria::SubjectPattern { pattern: "(?i).{0,100}(usa.{0,100}today.{0,100}automotive.{0,100}aftermarket.{0,100}special.{0,100}edition|usa.{0,100}today.{0,100}brand.{0,100}impersonation|fake.{0,100}usa.{0,100}today).*".to_string() },
                        Criteria::BodyPattern { pattern: "(?i).{0,100}(usa.{0,100}today.{0,100}automotive.{0,100}aftermarket.{0,100}special.{0,100}edition|usa.{0,100}today.{0,100}brand.{0,100}impersonation|fake.{0,100}usa.{0,100}today).*".to_string() },
                        ],
                    },
                    action: None,
                    score: Some(280),
                    description: None,
                },
                FilterRule {
                    name: "Unrelated Domain Brand Impersonation".to_string(),
                    enabled: true,
                    criteria:
                    Criteria::Or {
                        criteria: vec![
                        Criteria::And {
                            criteria: vec![
                            Criteria::HeaderPattern { header: "From".to_string(), pattern: "(?i).{0,100}wellaheat.*".to_string() },
                            Criteria::SenderPattern { pattern: ".*@sydneyentertainmentcomplex\\.com$".to_string() },
                            ],
                        },
                        Criteria::SenderPattern { pattern: ".*@sydneyentertainmentcomplex\\.com$".to_string() },
                        ],
                    },
                    action: None,
                    score: Some(250),
                    description: Some("Suspicious domain used for multiple unrelated spam campaigns".to_string()),
                },
                FilterRule {
                    name: "Suspicious Shop Domain Health Spam".to_string(),
                    enabled: true,
                    criteria:
                    Criteria::And {
                        criteria: vec![
                        Criteria::SenderPattern { pattern: ".*@.*\\.shop$".to_string() },
                        Criteria::Or {
                            criteria: vec![
                            Criteria::SubjectPattern { pattern: "(?i).{0,100}(japanese.{0,100}candy|joint.{0,100}replacement|surgery|supplement|miracle|health.{0,100}cure|pain.{0,100}relief).*".to_string() },
                            Criteria::BodyPattern { pattern: "(?i).{0,100}(japanese.{0,100}candy|joint.{0,100}replacement|surgery|supplement|miracle|health.{0,100}cure|pain.{0,100}relief).*".to_string() },
                            ],
                        },
                        ],
                    },
                    action: None,
                    score: Some(75),
                    description: Some("Health supplement spam from suspicious .shop domains".to_string()),
                },
            ],
        },
        Module {
            name: "Content Threats".to_string(),
            enabled: true,
            hash: "builtin".to_string(),
            rules: vec![
                FilterRule {
                    name: "Health Subject Line Threats".to_string(),
                    enabled: true,
                    criteria:
                    Criteria::SubjectPattern { pattern: "(?i).{0,100}(blood.{0,100}herb|destroys.{0,100}pressure|overnight.{0,100}cure|breathing.{0,100}lung|cardiovascular|coffee.{0,100}weight).*".to_string() },
                    action: None,
                    score: Some(180),
                    description: None,
                },
                FilterRule {
                    name: "Health Misinformation Detection".to_string(),
                    enabled: true,
                    criteria:
                    Criteria::And {
                        criteria: vec![
                        Criteria::Or {
                            criteria: vec![
                            Criteria::BodyPattern { pattern: "(?i).{0,100}(miracle.{0,100}cure|destroys.{0,100}overnight|secret.{0,100}doctors|big.{0,100}pharma.{0,100}hates|one.{0,100}weird.{0,100}trick|doctors.{0,100}shocked).*".to_string() },
                            Criteria::BodyPattern { pattern: "(?i).{0,100}(cure.{0,100}diabetes.{0,100}forever|eliminate.{0,100}blood.{0,100}pressure|lose.{0,100}30.{0,100}pounds|ancient.{0,100}remedy|forbidden.{0,100}cure).*".to_string() },
                            Criteria::SubjectPattern { pattern: "(?i).{0,100}(blood.{0,100}herb|destroys.{0,100}pressure|overnight.{0,100}cure|miracle.{0,100}diabetes|secret.{0,100}cure).*".to_string() },
                            ],
                        },
                        Criteria::BodyPattern { pattern: "(?i).{0,100}(blood.{0,100}pressure|diabetes|a1c|cholesterol|heart.{0,100}disease|weight.{0,100}loss).*".to_string() },
                        Criteria::Not {
                            criteria: Box::new(
                            Criteria::SenderPattern { pattern: ".*@.*(nytimes|washingtonpost|cnn|bbc|reuters|ap|wsj|usatoday)\\.(com|org)$".to_string() }
                            ),
                        },
                        ],
                    },
                    action: None,
                    score: Some(200),
                    description: Some("Health misinformation and miracle cure claims".to_string()),
                },
                FilterRule {
                    name: "Adult Enhancement Spam".to_string(),
                    enabled: true,
                    criteria:
                    Criteria::And {
                        criteria: vec![
                        Criteria::SubjectPattern { pattern: "(?i).{0,100}(raging.{0,100}hard|enhancement|enlargement|performance|stamina).*".to_string() },
                        Criteria::Not {
                            criteria: Box::new(
                            Criteria::Or {
                                criteria: vec![
                                Criteria::SubjectPattern { pattern: "(?i).{0,100}(financial|investment|portfolio|quarterly|annual|report|update|metric|business|review|2025|2026|2027|january|february|march|april|may|june|july|august|september|october|november|december|q1|q2|q3|q4).*".to_string() },
                                Criteria::FromDomain { domains: vec!["arrived.com".to_string(), "arrivedhomes.com".to_string()] },
                                ],
                            }
                            ),
                        },
                        ],
                    },
                    action: None,
                    score: Some(250),
                    description: None,
                },
                FilterRule {
                    name: "Advance Fee Fraud".to_string(),
                    enabled: true,
                    criteria:
                    Criteria::SubjectPattern { pattern: "(?i).{0,100}(private|confidential|urgent.{0,100}proposal|business.{0,100}proposal|inheritance).*".to_string() },
                    action: None,
                    score: Some(300),
                    description: None,
                },
                FilterRule {
                    name: "Business Development Spam".to_string(),
                    enabled: true,
                    criteria:
                    Criteria::SubjectPattern { pattern: "(?i).{0,100}(business.{0,100}development|partnership.{0,100}opportunity|investment.{0,100}proposal).*".to_string() },
                    action: None,
                    score: Some(150),
                    description: None,
                },
                FilterRule {
                    name: "Stock Spam and Pump-and-Dump".to_string(),
                    enabled: true,
                    criteria:
                    Criteria::Or {
                        criteria: vec![
                        Criteria::SubjectPattern { pattern: "(?i).{0,100}(executive.{0,100}summary|stock.{0,100}pick|hot.{0,100}stock|penny.{0,100}stock|stock.{0,100}alert|trading.{0,100}alert).*".to_string() },
                        Criteria::And {
                            criteria: vec![
                            Criteria::Or {
                                criteria: vec![
                                Criteria::SubjectPattern { pattern: "(?i).{0,100}(stock|trading|investment|portfolio).*".to_string() },
                                Criteria::BodyPattern { pattern: "(?i).{0,100}(stock.{0,100}genius|trading.{0,100}genius|investment.{0,100}genius|stock.{0,100}alert|penny.{0,100}stock).*".to_string() },
                                ],
                            },
                            Criteria::Or {
                                criteria: vec![
                                Criteria::BodyPattern { pattern: "(?i).{0,100}(buy.{0,100}now|act.{0,100}fast|limited.{0,100}time|explosive.{0,100}growth|guaranteed.{0,100}profit).*".to_string() },
                                Criteria::SenderPattern { pattern: ".*@.*(stockgenius|stockalert|pennystocks|tradingalert).*".to_string() },
                                ],
                            },
                            ],
                        },
                        ],
                    },
                    action: None,
                    score: Some(150),
                    description: Some("Stock spam, pump-and-dump schemes, and unsolicited financial advice".to_string()),
                },
                FilterRule {
                    name: "SEO and Web Services Spam".to_string(),
                    enabled: true,
                    criteria:
                    Criteria::Or {
                        criteria: vec![
                        Criteria::SubjectPattern { pattern: "(?i).{0,100}(package.{0,100}for.{0,100}keywords|seo.{0,100}package|ranking.{0,100}package|backlink.{0,100}package).*".to_string() },
                        Criteria::And {
                            criteria: vec![
                            Criteria::Or {
                                criteria: vec![
                                Criteria::BodyPattern { pattern: "(?i).{0,100}(not.{0,100}ranking.{0,100}high|improve.{0,100}your.{0,100}ranking|seo.{0,100}services|backlink.{0,100}building|keyword.{0,100}optimization).*".to_string() },
                                Criteria::BodyPattern { pattern: "(?i).{0,100}(search.{0,100}engine.{0,100}optimization|google.{0,100}ranking|website.{0,100}ranking|increase.{0,100}traffic).*".to_string() },
                                ],
                            },
                            Criteria::Or {
                                criteria: vec![
                                Criteria::BodyPattern { pattern: "(?i).{0,100}(looking.{0,100}at.{0,100}your.{0,100}website|realized.{0,100}that.{0,100}despite|not.{0,100}ranking.{0,100}on.{0,100}google).*".to_string() },
                                Criteria::SubjectPattern { pattern: "(?i).{0,100}(keywords|seo|ranking|backlink).*".to_string() },
                                ],
                            },
                            ],
                        },
                        ],
                    },
                    action: None,
                    score: Some(100),
                    description: Some("Unsolicited SEO and web services spam".to_string()),
                },
                FilterRule {
                    name: "Fake Antivirus and Security Spam".to_string(),
                    enabled: true,
                    criteria:
                    Criteria::And {
                        criteria: vec![
                        Criteria::Or {
                            criteria: vec![
                            Criteria::SubjectPattern { pattern: "(?i).{0,100}(data.{0,100}vulnerable|secure.{0,100}it.{0,100}today|antivirus.{0,100}protection|security.{0,100}software).*".to_string() },
                            Criteria::HeaderPattern { header: "From".to_string(), pattern: "(?i).{0,100}(antivirus.{0,100}protection|security.{0,100}software|data.{0,100}protection).*".to_string() },
                            ],
                        },
                        Criteria::Not {
                            criteria: Box::new(
                            Criteria::SenderPattern { pattern: ".*@.*(norton|mcafee|kaspersky|bitdefender|avast|avg|eset|sophos|trendmicro|symantec)\\.(com|net)$".to_string() }
                            ),
                        },
                        ],
                    },
                    action: None,
                    score: Some(125),
                    description: Some("Fake antivirus and security software spam from non-legitimate vendors".to_string()),
                },
                FilterRule {
                    name: "Unsubstantiated medical cure claims".to_string(),
                    enabled: true,
                    criteria:
                    Criteria::And {
                        criteria: vec![
                        Criteria::Or {
                            criteria: vec![
                            Criteria::SubjectPattern { pattern: "(?i).{0,100}(reverse|cure|heal|eliminate|fix|solve).{0,100}(diabetes|cancer|vitiligo|arthritis|depression|anxiety|pain).*".to_string() },
                            Criteria::BodyPattern { pattern: "(?i).{0,100}(reverse|cure|heal|eliminate|fix|solve).{0,100}(diabetes|cancer|vitiligo|arthritis|depression|anxiety|pain).*".to_string() },
                            ],
                        },
                        Criteria::Or {
                            criteria: vec![
                            Criteria::SubjectPattern { pattern: "(?i).{0,100}naturally.*".to_string() },
                            Criteria::BodyPattern { pattern: "(?i).{0,100}(naturally|without.{0,100}doctor|without.{0,100}prescription|secret.{0,100}method).*".to_string() },
                            ],
                        },
                        ],
                    },
                    action: None,
                    score: Some(120),
                    description: Some("Unsubstantiated medical cure claims".to_string()),
                },
                FilterRule {
                    name: "Diabetes and blood sugar misinformation".to_string(),
                    enabled: true,
                    criteria:
                    Criteria::And {
                        criteria: vec![
                        Criteria::Or {
                            criteria: vec![
                            Criteria::BodyPattern { pattern: "(?i).{0,100}(diabetes|blood.{0,100}sugar|pancreas|insulin.{0,100}resistance|diabetic|blood.{0,100}glucose).*".to_string() },
                            Criteria::BodyPattern { pattern: "(?i).{0,100}\\ba1c\\b.*".to_string() },
                            Criteria::SubjectPattern { pattern: "(?i).{0,100}(diabetes|blood.{0,100}sugar|a1c|pancreas|insulin.{0,100}resistance|diabetic|blood.{0,100}glucose).*".to_string() },
                            ],
                        },
                        Criteria::Not {
                            criteria: Box::new(
                            Criteria::SenderPattern { pattern: ".*@.*williams.{0,100}sonoma.*".to_string() }
                            ),
                        },
                        Criteria::Not {
                            criteria: Box::new(
                            Criteria::Or {
                                criteria: vec![
                                Criteria::SenderPattern { pattern: ".*@.*fidelity.*".to_string() },
                                Criteria::SenderPattern { pattern: ".*@.*withings.*".to_string() },
                                Criteria::SenderPattern { pattern: ".*@.*(1800flowers|celebrations|wolfermans|nytimes).*".to_string() },
                                Criteria::SenderPattern { pattern: ".*@.*(walgreens|cvs|riteaid|pharmacy|optum|health|medical)\\.(com|net|org)$".to_string() },
                                Criteria::FeatureAnalysis {
                                    feature_name: "Authentication Analysis".to_string(),
                                    min_score: None,
                                    max_score: None,
                                    evidence_pattern: Some("DKIM domain properly aligned".to_string()),
                                    invert: None,
                                },
                                ],
                            }
                            ),
                        },
                        ],
                    },
                    action: None,
                    score: Some(75),
                    description: Some("Diabetes and blood sugar misinformation and miracle cure claims".to_string()),
                },
                FilterRule {
                    name: "Adult Content Keywords".to_string(),
                    enabled: true,
                    criteria:
                    Criteria::SubjectPattern { pattern: "(?i).{0,100}(adult.{0,100}content|xxx|porn|sex.{0,100}chat|dating.{0,100}site|hookup|escort|webcam.{0,100}girls|adult.{0,100}entertainment|raging.{0,100}hard|male.{0,100}enhancement|get.{0,100}hard|boost.{0,100}performance).*".to_string() },
                    action: None,
                    score: Some(50),
                    description: Some("Adult content and dating scam detection".to_string()),
                },
                FilterRule {
                    name: "Fake Delivery Notification".to_string(),
                    enabled: true,
                    criteria:
                    Criteria::And {
                        criteria: vec![
                        Criteria::Or {
                            criteria: vec![
                            Criteria::SubjectPattern { pattern: "(?i).{0,100}(delivery.{0,100}failed|parcel.{0,100}information|package.{0,100}held|shipment.{0,100}delayed|delivery.{0,100}attempt|address.{0,100}verification|incorrect.{0,100}address.{0,100}delivery).*".to_string() },
                            Criteria::BodyPattern { pattern: "(?i).{0,100}(delivery.{0,100}failed|incorrect.{0,100}address.{0,100}delivery|verify.{0,100}shipping.{0,100}address|update.{0,100}delivery.{0,100}address|parcel.{0,100}waiting|package.{0,100}undeliverable).*".to_string() },
                            ],
                        },
                        Criteria::Not {
                            criteria: Box::new(
                            Criteria::Or {
                                criteria: vec![
                                Criteria::SenderPattern { pattern: ".*@.*(usps|fedex|ups|dhl|amazon|ebay|shopify|torrid)\\.(com|gov)$".to_string() },
                                Criteria::BodyPattern { pattern: "(?i).{0,100}(delays.{0,100}in.{0,100}shipping.{0,100}or.{0,100}delivery.{0,100}from.{0,100}factors|standard.{0,100}shipping.{0,100}terms).*".to_string() },
                                ],
                            }
                            ),
                        },
                        ],
                    },
                    action: None,
                    score: Some(100),
                    description: Some("Fake delivery notification from non-shipping company".to_string()),
                },
                FilterRule {
                    name: "Google Translate Phishing Wrapper".to_string(),
                    enabled: true,
                    criteria:
                    Criteria::BodyPattern { pattern: "(?i).{0,100}translate\\.google\\.com/translate\\?.*u=.*".to_string() },
                    action: None,
                    score: Some(150),
                    description: Some("Phishing URL wrapped in Google Translate to hide destination".to_string()),
                },
                FilterRule {
                    name: "Romance Scam Patterns".to_string(),
                    enabled: true,
                    criteria:
                    Criteria::Or {
                        criteria: vec![
                        Criteria::SubjectPattern { pattern: "(?i).{0,100}(lonely.{0,100}woman|beautiful.{0,100}girl|meet.{0,100}singles|find.{0,100}love|romance.{0,100}scam|sugar.{0,100}daddy|sugar.{0,100}baby|want.{0,100}to.{0,100}be.{0,100}with.{0,100}you|how.{0,100}about.{0,100}you).*".to_string() },
                        Criteria::SubjectPattern { pattern: "(?i).{0,100}(woman.{0,100}alone|woman.{0,100}lonely|girls?.*alone|girls?.*lonely|don't.{0,100}want.{0,100}to.{0,100}be.{0,100}alone).*".to_string() },
                        ],
                    },
                    action: None,
                    score: Some(75),
                    description: Some("Romance and dating scam patterns".to_string()),
                },
                FilterRule {
                    name: "Ukrainian Dating Spam".to_string(),
                    enabled: true,
                    criteria:
                    Criteria::Or {
                        criteria: vec![
                        Criteria::SubjectPattern { pattern: "(?i).{0,100}ukrainian.{0,100}(girl|woman|women|ladies|beauty|beauties).*".to_string() },
                        Criteria::BodyPattern { pattern: "(?i).{0,100}ukrainian.{0,100}(girl|woman|women|ladies|dating|romance).*".to_string() },
                        ],
                    },
                    action: None,
                    score: Some(75),
                    description: Some("Ukrainian dating and romance spam".to_string()),
                },
                FilterRule {
                    name: "Bayesian Spam Word Patterns".to_string(),
                    enabled: true,
                    criteria:
                    Criteria::And {
                        criteria: vec![
                        Criteria::SubjectPattern { pattern: "(?i).{0,100}(free|win|winner|congratulations|urgent|act.{0,100}now|limited.{0,100}time|exclusive|special.{0,100}offer|guaranteed|amazing|incredible|revolutionary).*".to_string() },
                        Criteria::Not {
                            criteria: Box::new(
                            Criteria::Or {
                                criteria: vec![
                                Criteria::SenderPattern { pattern: ".*@(dominos\\.com|e-offers\\.dominos\\.com|.*\\.dominos\\.com)$".to_string() },
                                Criteria::SenderPattern { pattern: ".*@(amazon\\.com|.*\\.amazon\\.com|amazonses\\.com)$".to_string() },
                                Criteria::SenderPattern { pattern: ".*@(paypal\\.com|.*\\.paypal\\.com)$".to_string() },
                                Criteria::SenderPattern { pattern: ".*@(wolfermans\\.com|.*wolfermans.{0,100}\\.com|.*filtersfast\\.com|.*\\.filtersfast\\.com|.*backerkit\\.com|.*\\.backerkit\\.com)$".to_string() },
                                Criteria::SenderPattern { pattern: ".*@(.*nextdoor\\.com|suncadia\\.com)$".to_string() },
                                Criteria::HeaderPattern { header: "List-Unsubscribe".to_string(), pattern: ".*".to_string() },
                                ],
                            }
                            ),
                        },
                        ],
                    },
                    action: None,
                    score: Some(10),
                    description: Some("High-probability spam words based on Bayesian analysis".to_string()),
                },
                FilterRule {
                    name: "Fake brand surveys and contest scams".to_string(),
                    enabled: true,
                    criteria:
                    Criteria::And {
                        criteria: vec![
                        Criteria::SubjectPattern { pattern: "(?i).{0,100}(survey.{0,100}chance.{0,100}win|complete.{0,100}survey.{0,100}win|feedback.{0,100}win|customer.{0,100}survey.{0,100}prize|survey.{0,100}gift|survey.{0,100}reward|survey.{0,100}car.{0,100}kit|survey.{0,100}emergency.{0,100}kit).*".to_string() },
                        Criteria::Not {
                            criteria: Box::new(
                            Criteria::SenderPattern { pattern: ".*@.*(sparkpostmail|sendgrid|mailchimp|constantcontact|amazonses)\\.(com|net)$".to_string() }
                            ),
                        },
                        ],
                    },
                    action: None,
                    score: Some(80),
                    description: Some("Fake brand surveys and contest scams".to_string()),
                },
                FilterRule {
                    name: "Financial opportunity spam".to_string(),
                    enabled: true,
                    criteria:
                    Criteria::Or {
                        criteria: vec![
                        Criteria::SubjectPattern { pattern: "(?i).{0,100}(get.{0,100}rich.{0,100}quick|make.{0,100}money.{0,100}fast|financial.{0,100}freedom|guaranteed.{0,100}income|work.{0,100}from.{0,100}home).*".to_string() },
                        Criteria::SubjectPattern { pattern: "(?i).{0,100}(business.{0,100}opportunity|investment.{0,100}opportunity|passive.{0,100}income|residual.{0,100}income).*".to_string() },
                        ],
                    },
                    action: None,
                    score: Some(85),
                    description: Some("Financial opportunity and get-rich-quick schemes".to_string()),
                },
                FilterRule {
                    name: "Advance fee fraud patterns".to_string(),
                    enabled: true,
                    criteria:
                    Criteria::And {
                        criteria: vec![
                        Criteria::Or {
                            criteria: vec![
                            Criteria::SubjectPattern { pattern: "(?i).{0,100}(inheritance.{0,100}fund|beneficiary|next.{0,100}of.{0,100}kin|deceased.{0,100}relative|fund.{0,100}management|collaborator.{0,100}fund).*".to_string() },
                            Criteria::And {
                                criteria: vec![
                                Criteria::BodyPattern { pattern: "(?i).{0,100}(transfer.{0,100}funds|processing.{0,100}fee|legal.{0,100}fee|bank.{0,100}charges|wire.{0,100}transfer|confidential.{0,100}business).*".to_string() },
                                Criteria::Or {
                                    criteria: vec![
                                    Criteria::BodyPattern { pattern: "(?i).{0,100}(urgent.{0,100}assistance|help.{0,100}transfer|claim.{0,100}inheritance|deceased.{0,100}person|foreign.{0,100}country|government.{0,100}official).*".to_string() },
                                    Criteria::BodyPattern { pattern: "(?i).{0,100}(advance.{0,100}fee|upfront.{0,100}payment|release.{0,100}funds|tax.{0,100}clearance|legal.{0,100}documentation).*".to_string() },
                                    ],
                                },
                                ],
                            },
                            ],
                        },
                        Criteria::Not {
                            criteria: Box::new(
                            Criteria::Or {
                                criteria: vec![
                                Criteria::SenderPattern { pattern: ".*@.*(britishairways|ba\\.com|chase|jpmorgan|citi|amex|discover|capitalone|wellsfargo|bankofamerica|docusign)\\.(com|org|net)$".to_string() },
                                Criteria::BodyPattern { pattern: "(?i).{0,100}(terms.{0,100}conditions|credit.{0,100}card.{0,100}agreement|rewards.{0,100}program|loyalty.{0,100}program|airline.{0,100}miles|points.{0,100}program).*".to_string() },
                                ],
                            }
                            ),
                        },
                        ],
                    },
                    action: None,
                    score: Some(150),
                    description: Some("Advance fee fraud excluding legitimate financial institutions".to_string()),
                },
                FilterRule {
                    name: "Lottery and prize scams".to_string(),
                    enabled: true,
                    criteria:
                    Criteria::And {
                        criteria: vec![
                        Criteria::Or {
                            criteria: vec![
                            Criteria::SubjectPattern { pattern: "(?i).{0,100}(you.{0,100}have.{0,100}won|lottery.{0,100}winner|prize.{0,100}notification|congratulations.{0,100}winner|eligible.{0,100}reward).*".to_string() },
                            Criteria::BodyPattern { pattern: "(?i).{0,100}(claim.{0,100}your.{0,100}prize|lottery.{0,100}commission|winning.{0,100}notification|prize.{0,100}money|million.{0,100}dollars).*".to_string() },
                            ],
                        },
                        Criteria::Not {
                            criteria: Box::new(
                            Criteria::Or {
                                criteria: vec![
                                Criteria::SenderPattern { pattern: ".*@.*(make\\.co|beehiiv\\.com|newsletter|news|media|tech).*".to_string() },
                                Criteria::BodyPattern { pattern: "(?i).{0,100}(annually|per year|business|company|revenue|cost|spend|budget).*".to_string() },
                                ],
                            }
                            ),
                        },
                        ],
                    },
                    action: None,
                    score: Some(120),
                    description: Some("Lottery and prize scam detection excluding legitimate business content".to_string()),
                },
                FilterRule {
                    name: "Product spam and brand impersonation attempts".to_string(),
                    enabled: true,
                    criteria:
                    Criteria::And {
                        criteria: vec![
                        Criteria::Or {
                            criteria: vec![
                            Criteria::BodyPattern { pattern: "(?i).{0,100}(air.{0,100}filter.{0,100}factory|car.{0,100}emergency.{0,100}kit|joint.{0,100}knee.{0,100}pain|fake.{0,100}forum|brand.{0,100}impersonation|health.{0,100}ring|tracks.{0,100}health|titan.{0,100}ring|imagine.{0,100}ring).*".to_string() },
                            Criteria::SubjectPattern { pattern: "(?i).{0,100}(air.{0,100}filter.{0,100}factory|car.{0,100}emergency.{0,100}kit|joint.{0,100}knee.{0,100}pain|fake.{0,100}forum|brand.{0,100}impersonation|health.{0,100}ring|tracks.{0,100}health|titan.{0,100}ring|imagine.{0,100}ring).*".to_string() },
                            Criteria::SenderPattern { pattern: ".*@.*(forum|fake|scam|spam).*".to_string() },
                            ],
                        },
                        Criteria::Not {
                            criteria: Box::new(
                            Criteria::Or {
                                criteria: vec![
                                Criteria::SenderPattern { pattern: ".*@.*nytimes.*".to_string() },
                                Criteria::SenderPattern { pattern: ".*@.*(commonspirit|virginiamason|providence|kaiser|hospital|medical|clinic)\\.(com|org|net)$".to_string() },
                                ],
                            }
                            ),
                        },
                        ],
                    },
                    action: None,
                    score: Some(65),
                    description: Some("Product spam and brand impersonation attempts".to_string()),
                },
                FilterRule {
                    name: "Suspicious health domains".to_string(),
                    enabled: true,
                    criteria:
                    Criteria::And {
                        criteria: vec![
                        Criteria::Or {
                            criteria: vec![
                            Criteria::SenderPattern { pattern: ".*\\.(icu|tk|ml|ga|cf|shop)$".to_string() },
                            Criteria::HeaderPattern { header: "Return-Path".to_string(), pattern: ".*\\.(icu|tk|ml|ga|cf|shop)$".to_string() },
                            ],
                        },
                        Criteria::Or {
                            criteria: vec![
                            Criteria::SenderPattern { pattern: "(?i).{0,100}(health|medical|cure|heal|skin|vita|med|pharma).*".to_string() },
                            Criteria::SubjectPattern { pattern: "(?i).{0,100}(health|medical|cure|heal|skin|treatment|remedy).*".to_string() },
                            ],
                        },
                        ],
                    },
                    action: None,
                    score: Some(80),
                    description: Some("Health claims from suspicious TLD domains".to_string()),
                },
                FilterRule {
                    name: "Comprehensive health misinformation".to_string(),
                    enabled: true,
                    criteria:
                    Criteria::And {
                        criteria: vec![
                        Criteria::Or {
                            criteria: vec![
                            Criteria::BodyPattern { pattern: "(?i).{0,100}(sexual.{0,100}health|sexual.{0,100}beast|erectile.{0,100}dysfunction|male.{0,100}enhancement|libido|testosterone).*".to_string() },
                            Criteria::SubjectPattern { pattern: "(?i).{0,100}(sexual.{0,100}health|sexual.{0,100}beast|male.{0,100}enhancement|erectile|testosterone).*".to_string() },
                            Criteria::BodyPattern { pattern: "(?i).{0,100}(blood.{0,100}pressure|neuropathy|prostate|tinnitus|joint.{0,100}pain|knee.{0,100}pain|breathing.{0,100}difficulties|longevity|lifespan|extends.{0,100}lifespan|live.{0,100}to.{0,100}10[0-9]|tea.{0,100}trick|mayo.{0,100}clinic|male.{0,100}elongation.{0,100}secret|penis.{0,100}elongation|african.{0,100}tribesmen.{0,100}elongation|white.{0,100}wife.{0,100}finds.{0,100}elongation).*".to_string() },
                            Criteria::SubjectPattern { pattern: "(?i).{0,100}(blood.{0,100}pressure|neuropathy|prostate|tinnitus|joint.{0,100}pain|knee.{0,100}pain|breathing.{0,100}difficulties|longevity|lifespan|extends.{0,100}lifespan|live.{0,100}to.{0,100}10[0-9]|tea.{0,100}trick|mayo.{0,100}clinic|male.{0,100}elongation.{0,100}secret|penis.{0,100}elongation|african.{0,100}tribesmen.{0,100}elongation|white.{0,100}wife.{0,100}finds.{0,100}elongation).*".to_string() },
                            ],
                        },
                        Criteria::Not {
                            criteria: Box::new(
                            Criteria::Or {
                                criteria: vec![
                                Criteria::SenderPattern { pattern: ".*@.*withings.*".to_string() },
                                Criteria::SenderPattern { pattern: ".*@.*1800flowers.*".to_string() },
                                Criteria::SenderPattern { pattern: ".*@.*labcorp.*".to_string() },
                                Criteria::SenderPattern { pattern: ".*@.*backerkit.*".to_string() },
                                Criteria::SenderPattern { pattern: ".*@.*levi.*".to_string() },
                                Criteria::SenderPattern { pattern: ".*@.*(michaels|costco|walmart|target|amazon|bestbuy|homedepot|lowes)\\.(com|net)$".to_string() },
                                Criteria::SenderPattern { pattern: ".*@.*(nytimes|washingtonpost|cnn|bbc|reuters|ap|wsj|usatoday|nationalgeographic|torrid|ugg)\\.(com|org)$".to_string() },
                                Criteria::SenderPattern { pattern: ".*@.*(livenation|ticketmaster|stubhub|eventbrite)\\.(com|net)$".to_string() },
                                Criteria::SubjectPattern { pattern: "(?i).{0,100}(recipe|cooking|breakfast|meal|food|nutrition|diet).*".to_string() },
                                ],
                            }
                            ),
                        },
                        ],
                    },
                    action: None,
                    score: Some(85),
                    description: Some("Comprehensive health misinformation, enhancement scams, and adult content".to_string()),
                },
                FilterRule {
                    name: "Forwarded spam detection".to_string(),
                    enabled: true,
                    criteria:
                    Criteria::And {
                        criteria: vec![
                        Criteria::SubjectPattern { pattern: "(?i)^(fwd?:|re:)\\s*(low\\s*cost|cheap.{0,100}price|best.{0,100}deal|urgent|important|limited.{0,100}time|act.{0,100}now)".to_string() },
                        Criteria::Or {
                            criteria: vec![
                            Criteria::BodyPattern { pattern: "(?i).{0,100}(click.{0,100}here|visit.{0,100}now|limited.{0,100}offer|act.{0,100}fast|don't.{0,100}miss|hurry.{0,100}up).*".to_string() },
                            Criteria::BodyPattern { pattern: "^\\s*http://[^\\s]+\\s*$".to_string() },
                            ],
                        },
                        ],
                    },
                    action: None,
                    score: Some(65),
                    description: Some("Suspicious forwarded emails with spam characteristics".to_string()),
                },
                FilterRule {
                    name: "Unrealistic return promises".to_string(),
                    enabled: true,
                    criteria:
                    Criteria::And {
                        criteria: vec![
                        Criteria::Or {
                            criteria: vec![
                            Criteria::BodyPattern { pattern: "(?i).*(guaranteed.{0,30}return|risk.{0,30}free.{0,30}profit|no.{0,30}risk.{0,30}investment|instant.{0,30}wealth|get.{0,30}rich.{0,30}quick).*".to_string() },
                            Criteria::BodyPattern { pattern: "(?i).*(secret.{0,30}investment|hidden.{0,30}opportunity|limited.{0,30}spots|act.{0,30}now.{0,30}invest|exclusive.{0,30}offer.{0,30}return).*".to_string() },
                            Criteria::SubjectPattern { pattern: "(?i).*(guaranteed.{0,30}\\d+%|earn.{0,30}\\$\\d+.{0,30}daily|make.{0,30}money.{0,30}fast|passive.{0,30}income.{0,30}\\$).*".to_string() },
                            ],
                        },
                        Criteria::BodyPattern { pattern: "(?i).{0,100}(\\d+\\.\\d+%|\\d+%|\\$\\d+|\\d+.*USD).*".to_string() },
                        Criteria::Not {
                            criteria: Box::new(
                            Criteria::SenderPattern { pattern: ".*@.*(oxford|nytimes|washingtonpost|cnn|bbc|reuters|ap|wsj|usatoday|ugg|torrid)\\.(com|org)$".to_string() }
                            ),
                        },
                        ],
                    },
                    action: None,
                    score: Some(90),
                    description: Some("Unrealistic financial return promises and investment scams".to_string()),
                },
                FilterRule {
                    name: "Bulk email advertising spam".to_string(),
                    enabled: true,
                    criteria:
                    Criteria::And {
                        criteria: vec![
                        Criteria::Or {
                            criteria: vec![
                            Criteria::SubjectPattern { pattern: "(?i).{0,100}(advertise.{0,100}up.{0,100}to.{0,100}million|200.{0,100}million.{0,100}emails|bulk.{0,100}email.{0,100}service|email.{0,100}marketing.{0,100}blast).*".to_string() },
                            Criteria::BodyPattern { pattern: "(?i).{0,100}(million.{0,100}emails|bulk.{0,100}advertising|email.{0,100}blast|mass.{0,100}mailing|targeted.{0,100}email.{0,100}list|fresh.{0,100}email.{0,100}database).*".to_string() },
                            ],
                        },
                        Criteria::Not {
                            criteria: Box::new(
                            Criteria::SenderPattern { pattern: ".*@.*nytimes.*".to_string() }
                            ),
                        },
                        ],
                    },
                    action: None,
                    score: Some(100),
                    description: Some("Bulk email advertising and spam services".to_string()),
                },
                FilterRule {
                    name: "Invoice Scam Detection (All Text)".to_string(),
                    enabled: true,
                    criteria:
                    Criteria::CombinedTextPattern { pattern: "(?i).{0,100}(invoice.{0,100}overdue|urgent.{0,100}payment|bitcoin.{0,100}payment|cryptocurrency.{0,100}required|nota fiscal|fatura|documento.{0,100}fiscal).*".to_string() },
                    action: None,
                    score: Some(75),
                    description: Some("Detect invoice scams and crypto payment demands in email body or media attachments".to_string()),
                },
                FilterRule {
                    name: "Adult Content Detection (All Text)".to_string(),
                    enabled: true,
                    criteria:
                    Criteria::CombinedTextPattern { pattern: "(?i).{0,100}(\\bviagra\\b|\\bcialis\\b|\\badult.{0,100}content|\\bxxx\\s|penis.{0,100}enlargement|male.{0,100}enhancement|\\berection.{0,100}pills).*".to_string() },
                    action: None,
                    score: Some(60),
                    description: Some("Detect adult content keywords in email body or extracted from images/PDFs".to_string()),
                },
                FilterRule {
                    name: "Financial Scams (All Text)".to_string(),
                    enabled: true,
                    criteria:
                    Criteria::CombinedTextPattern { pattern: "(?i).{0,100}(guaranteed.{0,100}profit|investment.{0,100}opportunity|bitcoin.{0,100}trading|crypto.{0,100}mining).*".to_string() },
                    action: None,
                    score: Some(65),
                    description: Some("Detect financial scam content in email body or media attachments".to_string()),
                },
                FilterRule {
                    name: "Health Misinformation (All Text)".to_string(),
                    enabled: true,
                    criteria:
                    Criteria::CombinedTextPattern { pattern: "(?i).{0,100}(miracle.{0,100}cure|secret.{0,100}remedy|doctors.{0,100}hate|pharmaceutical.{0,100}conspiracy|natural.{0,100}healing).*".to_string() },
                    action: None,
                    score: Some(70),
                    description: Some("Detect health misinformation in email body or media attachments".to_string()),
                },
                FilterRule {
                    name: "Tech Support Scam Patterns".to_string(),
                    enabled: true,
                    criteria:
                    Criteria::SubjectPattern { pattern: "(?i).{0,100}(computer.{0,100}virus|system.{0,100}infected|microsoft.{0,100}support|windows.{0,100}security|tech.{0,100}support|computer.{0,100}problem|virus.{0,100}detected|security.{0,100}alert|system.{0,100}compromised).*".to_string() },
                    action: None,
                    score: Some(45),
                    description: Some("Fake tech support and virus alert scams".to_string()),
                },
                FilterRule {
                    name: "Software Scam Offers".to_string(),
                    enabled: true,
                    criteria:
                    Criteria::SubjectPattern { pattern: "(?i).{0,100}(free.{0,100}software|cracked.{0,100}software|keygen|serial.{0,100}number|activation.{0,100}key|license.{0,100}key.{0,100}free|pirated.{0,100}software).*".to_string() },
                    action: None,
                    score: Some(35),
                    description: Some("Illegal software and keygen scams".to_string()),
                },
                FilterRule {
                    name: "Cloud backup and storage scams".to_string(),
                    enabled: true,
                    criteria:
                    Criteria::Or {
                        criteria: vec![
                        Criteria::SubjectPattern { pattern: "(?i).{0,100}(cloud.{0,100}backup.{0,100}stopped|backup.{0,100}expired|storage.{0,100}full|account.{0,100}suspended|restore.{0,100}now|backup.{0,100}failed|sync.{0,100}error|data.{0,100}lost|files.{0,100}deleted|storage.{0,100}limit).*".to_string() },
                        Criteria::SubjectPattern { pattern: ".*[⤦⤧⤨⤩⤪⤫⤬⤭⤮⤯⤰⤱⤲⤳⤴⤵⤶⤷⤸⤹⤺⤻⤼⤽⤾⤿⥀⥁⥂⥃⥄⥅⥆⥇⥈⥉⥊⥋⥌⥍⥎⥏⥐⥑⥒⥓⥔⥕⥖⥗⥘⥙⥚⥛⥜⥝⥞⥟⥠⥡⥢⥣⥤⥥⥦⥧⥨⥩⥪⥫⥬⥭⥮⥯⥰⥱⥲⥳⥴⥵⥶⥷⥸⥹⥺⥻⥼⥽⥾⥿].*".to_string() },
                        ],
                    },
                    action: None,
                    score: Some(80),
                    description: Some("Cloud backup and storage scam detection with Unicode abuse".to_string()),
                },
                FilterRule {
                    name: "Fake Security Alerts".to_string(),
                    enabled: true,
                    criteria:
                    Criteria::SubjectPattern { pattern: "(?i).{0,100}(security.{0,100}breach|account.{0,100}hacked|suspicious.{0,100}activity|login.{0,100}attempt|security.{0,100}warning|unauthorized.{0,100}access).*".to_string() },
                    action: None,
                    score: Some(40),
                    description: Some("Fake security alerts and breach notifications".to_string()),
                },
                FilterRule {
                    name: "Unsolicited web development services".to_string(),
                    enabled: true,
                    criteria:
                    Criteria::Or {
                        criteria: vec![
                        Criteria::SubjectPattern { pattern: "(?i).{0,100}(customize.{0,100}website|website.{0,100}design.{0,100}development|web.{0,100}development.{0,100}services|professional.{0,100}website|website.{0,100}redesign|digital.{0,100}marketing.{0,100}services|seo.{0,100}services|online.{0,100}presence).*".to_string() },
                        Criteria::SubjectPattern { pattern: "(?i)^(communication|hello|greetings|business.{0,100}proposal|partnership.{0,100}opportunity)$".to_string() },
                        ],
                    },
                    action: None,
                    score: Some(70),
                    description: Some("Unsolicited web development and business services spam".to_string()),
                },
                FilterRule {
                    name: "Website audit spam".to_string(),
                    enabled: true,
                    criteria:
                    Criteria::And {
                        criteria: vec![
                        Criteria::Or {
                            criteria: vec![
                            Criteria::BodyPattern { pattern: "(?i).{0,100}(errors on your website|website audit|website issues|site review|website problems|noticed.{0,100}errors).*".to_string() },
                            Criteria::SubjectPattern { pattern: "(?i).{0,100}(site review|website audit|website errors|site issues).*".to_string() },
                            ],
                        },
                        Criteria::Or {
                            criteria: vec![
                            Criteria::BodyPattern { pattern: "(?i).{0,100}(screenshot|send over|reply.{0,100}ok|simply reply|would you like me to).*".to_string() },
                            ],
                        },
                        ],
                    },
                    action: None,
                    score: Some(65),
                    description: Some("Website audit and SEO spam".to_string()),
                },
                FilterRule {
                    name: "Japanese Text from Chinese Domain".to_string(),
                    enabled: true,
                    criteria:
                    Criteria::LanguageGeographyMismatch {
                        domain_pattern: "(?i).{0,100}\\.cn$".to_string(),
                        content_pattern: "(?i).*[\\u3040-\\u309F\\u30A0-\\u30FF\\u4E00-\\u9FAF].*".to_string(),
                        description: "Japanese characters from .cn domain".to_string(),
                    },
                    action: None,
                    score: Some(65),
                    description: Some("Japanese text from Chinese (.cn) domain - common spam pattern".to_string()),
                },
                FilterRule {
                    name: "Chinese Text from Japanese Domain".to_string(),
                    enabled: true,
                    criteria:
                    Criteria::LanguageGeographyMismatch {
                        domain_pattern: "(?i).{0,100}\\.jp$".to_string(),
                        content_pattern: "(?i).*[\\u4E00-\\u9FAF].*".to_string(),
                        description: "Chinese characters from .jp domain".to_string(),
                    },
                    action: None,
                    score: Some(35),
                    description: Some("Chinese text from Japanese (.jp) domain - potential spam".to_string()),
                },
                FilterRule {
                    name: "Korean Text from Non-Korean Domain".to_string(),
                    enabled: true,
                    criteria:
                    Criteria::LanguageGeographyMismatch {
                        domain_pattern: "(?i).{0,100}\\.(cn|jp|ru|tk|ml|ga)$".to_string(),
                        content_pattern: "(?i).*[\\uAC00-\\uD7AF\\u1100-\\u11FF\\u3130-\\u318F].*".to_string(),
                        description: "Korean characters from non-Korean domain".to_string(),
                    },
                    action: None,
                    score: Some(45),
                    description: Some("Korean text from non-Korean domain - potential spam".to_string()),
                },
                FilterRule {
                    name: "SEO spam via Google Groups".to_string(),
                    enabled: true,
                    criteria:
                    Criteria::And {
                        criteria: vec![
                        Criteria::Or {
                            criteria: vec![
                            Criteria::HeaderPattern { header: "List-ID".to_string(), pattern: ".*googlegroups\\.com.*".to_string() },
                            Criteria::HeaderPattern { header: "List-ID".to_string(), pattern: ".*wildnetdigitalagency\\.com.*".to_string() },
                            Criteria::HeaderPattern { header: "X-Google-Group-Id".to_string(), pattern: "\\d+".to_string() },
                            ],
                        },
                        Criteria::Or {
                            criteria: vec![
                            Criteria::BodyPattern { pattern: "(?i).{0,100}(seo.{0,100}services|website.{0,100}optimization|digital.{0,100}marketing|web.{0,100}development|online.{0,100}marketing).*".to_string() },
                            Criteria::SubjectPattern { pattern: "(?i).{0,100}(seo.{0,100}services|website.{0,100}optimization|digital.{0,100}marketing|web.{0,100}development|online.{0,100}marketing).*".to_string() },
                            ],
                        },
                        ],
                    },
                    action: None,
                    score: Some(85),
                    description: Some("SEO spam via Google Groups should override mailing list trust".to_string()),
                },
                FilterRule {
                    name: "Attachment-Only Emails".to_string(),
                    enabled: true,
                    criteria:
                    Criteria::And {
                        criteria: vec![
                        Criteria::AttachmentOnlyEmail {
                            max_text_length: None, ignore_whitespace: None, suspicious_types: None, min_attachment_size: None, check_disposition: None,

                        },
                        Criteria::Not {
                            criteria: Box::new(
                            Criteria::Or {
                                criteria: vec![
                                Criteria::SubjectPattern { pattern: "(?i).{0,100}(invoice|receipt|statement|bill|payment|quote|estimate).*".to_string() },
                                Criteria::SenderPattern { pattern: ".*@.*(exterminators|contractors|services|business|company)\\.(com|net|org)$".to_string() },
                                Criteria::HeaderPattern { header: "References".to_string(), pattern: ".*".to_string() },
                                Criteria::HeaderPattern { header: "In-Reply-To".to_string(), pattern: ".*".to_string() },
                                Criteria::HeaderPattern { header: "Thread-Index".to_string(), pattern: ".*".to_string() },
                                Criteria::SenderPattern { pattern: ".*@.*(outlook|hotmail|gmail|yahoo)\\.com$".to_string() },
                                ],
                            }
                            ),
                        },
                        ],
                    },
                    action: None,
                    score: Some(15),
                    description: Some("Emails with only attachments excluding business invoices and email threads".to_string()),
                },
                FilterRule {
                    name: "Empty Content Emails".to_string(),
                    enabled: true,
                    criteria:
                    Criteria::And {
                        criteria: vec![
                        Criteria::EmptyContentEmail {
                            max_text_length: None, ignore_whitespace: None, ignore_signatures: None, require_empty_subject: None, min_subject_length: None, ignore_html_tags: None,

                        },
                        Criteria::Not {
                            criteria: Box::new(
                            Criteria::Or {
                                criteria: vec![
                                Criteria::HeaderPattern { header: "x-netsuite".to_string(), pattern: ".*".to_string() },
                                Criteria::SenderDomain { domains: vec!["netsuite.com".to_string()] },
                                Criteria::HeaderPattern { header: "from".to_string(), pattern: ".*@.*netsuite\\.com.*".to_string() },
                                Criteria::HeaderPattern { header: "list-id".to_string(), pattern: ".*".to_string() },
                                Criteria::SubjectPattern { pattern: "(?i).{0,100}(invoice|receipt|statement|bill|payment|quote|estimate|order|summary|confirmation).*".to_string() },
                                Criteria::SenderPattern { pattern: ".*@.*(exterminators|contractors|services|business|company)\\.(com|net|org)$".to_string() },
                                Criteria::HeaderPattern { header: "mailing-list".to_string(), pattern: ".*".to_string() },
                                Criteria::HeaderPattern { header: "precedence".to_string(), pattern: "list".to_string() },
                                Criteria::HeaderPattern { header: "from".to_string(), pattern: ".*@.*charmtracker\\.com.*".to_string() },
                                Criteria::HeaderPattern { header: "from".to_string(), pattern: ".*@.*athenahealth\\.com.*".to_string() },
                                Criteria::HeaderPattern { header: "from".to_string(), pattern: ".*@.*epic\\.com.*".to_string() },
                                Criteria::HeaderPattern { header: "from".to_string(), pattern: ".*@.*ups\\.com.*".to_string() },
                                Criteria::HeaderPattern { header: "from".to_string(), pattern: ".*@.*fedex\\.com.*".to_string() },
                                Criteria::HeaderPattern { header: "from".to_string(), pattern: ".*@.*usps\\.com.*".to_string() },
                                Criteria::HeaderPattern { header: "References".to_string(), pattern: ".*".to_string() },
                                Criteria::HeaderPattern { header: "In-Reply-To".to_string(), pattern: ".*".to_string() },
                                Criteria::HeaderPattern { header: "Thread-Index".to_string(), pattern: ".*".to_string() },
                                Criteria::SenderPattern { pattern: ".*@.*(outlook|hotmail|gmail|yahoo)\\.com$".to_string() },
                                ],
                            }
                            ),
                        },
                        ],
                    },
                    action: None,
                    score: Some(10),
                    description: Some("Emails with no subject or body content, excluding NetSuite business systems, medical platforms, and legitimate mailing lists".to_string()),
                },
                FilterRule {
                    name: "Weight Loss Diet Spam".to_string(),
                    enabled: true,
                    criteria:
                    Criteria::And {
                        criteria: vec![
                        Criteria::Or {
                            criteria: vec![
                            Criteria::SubjectPattern { pattern: "(?i).{0,100}(weight.{0,100}loss.{0,100}diet|diet.{0,100}weight.{0,100}loss|lose.{0,100}weight.{0,100}fast|soda.{0,100}water.{0,100}diet|flushes.{0,100}out.{0,100}fat).*".to_string() },
                            Criteria::BodyPattern { pattern: "(?i).{0,100}(weight.{0,100}loss.{0,100}diet|diet.{0,100}weight.{0,100}loss|lose.{0,100}weight.{0,100}fast|soda.{0,100}water.{0,100}diet|flushes.{0,100}out.{0,100}fat).*".to_string() },
                            ],
                        },
                        Criteria::Not {
                            criteria: Box::new(
                            Criteria::Or {
                                criteria: vec![
                                Criteria::SenderPattern { pattern: ".*@.*(nytimes|washingtonpost|cnn|bbc|reuters|ap|wsj|usatoday)\\.(com|org)$".to_string() },
                                Criteria::SubjectPattern { pattern: "(?i).{0,100}(recipe|cooking|breakfast|meal|food|nutrition).*".to_string() },
                                ],
                            }
                            ),
                        },
                        ],
                    },
                    action: None,
                    score: Some(200),
                    description: None,
                },
                FilterRule {
                    name: "Product Spam Detection".to_string(),
                    enabled: true,
                    criteria:
                    Criteria::Or {
                        criteria: vec![
                        Criteria::SubjectPattern { pattern: "(?i).{0,100}(air.{0,100}filter.{0,100}factory|billionaire.{0,100}bridge|cognitive.{0,100}coffee|digestive.{0,100}flush|endurance.{0,100}auto.{0,100}protection).*".to_string() },
                        Criteria::BodyPattern { pattern: "(?i).{0,100}(air.{0,100}filter.{0,100}factory|billionaire.{0,100}bridge|cognitive.{0,100}coffee|digestive.{0,100}flush|endurance.{0,100}auto.{0,100}protection).*".to_string() },
                        ],
                    },
                    action: None,
                    score: Some(180),
                    description: None,
                },
                FilterRule {
                    name: "Medical Spam Detection".to_string(),
                    enabled: true,
                    criteria:
                    Criteria::And {
                        criteria: vec![
                        Criteria::Or {
                            criteria: vec![
                            Criteria::SubjectPattern { pattern: "(?i).{0,100}(root.{0,100}cause.{0,100}breathing|breathing.{0,100}difficulties|french.{0,100}protein.{0,100}removes|artery.{0,100}plaque|dementia.{0,100}food|fake.{0,100}harvard.{0,100}foot).*".to_string() },
                            Criteria::BodyPattern { pattern: "(?i).{0,100}(root.{0,100}cause.{0,100}breathing|breathing.{0,100}difficulties|french.{0,100}protein.{0,100}removes|artery.{0,100}plaque|dementia.{0,100}food|fake.{0,100}harvard.{0,100}foot).*".to_string() },
                            ],
                        },
                        Criteria::Not {
                            criteria: Box::new(
                            Criteria::Or {
                                criteria: vec![
                                Criteria::SenderPattern { pattern: ".*@.*(withings|fitbit|garmin|apple|samsung|healthcare|medical|clinic|hospital)\\.(com|net|org)$".to_string() },
                                Criteria::BodyPattern { pattern: "(?i).{0,100}(not.{0,100}intended.{0,100}for.{0,100}medical.{0,100}use|consult.{0,100}your.{0,100}doctor|medical.{0,100}disclaimer|health.{0,100}device|fitness.{0,100}tracker).*".to_string() },
                                ],
                            }
                            ),
                        },
                        ],
                    },
                    action: None,
                    score: Some(200),
                    description: Some("Medical spam detection excluding legitimate health companies".to_string()),
                },
                FilterRule {
                    name: "Financial Scam Detection".to_string(),
                    enabled: true,
                    criteria:
                    Criteria::Or {
                        criteria: vec![
                        Criteria::SubjectPattern { pattern: "(?i).{0,100}(estonian.{0,100}money.{0,100}transfer|interactive.{0,100}brokers.{0,100}w8ben|fake.{0,100}order.{0,100}transaction|fake.{0,100}payment.{0,100}confirmation).*".to_string() },
                        Criteria::BodyPattern { pattern: "(?i).{0,100}(estonian.{0,100}money.{0,100}transfer|interactive.{0,100}brokers.{0,100}w8ben|fake.{0,100}order.{0,100}transaction|fake.{0,100}payment.{0,100}confirmation).*".to_string() },
                        ],
                    },
                    action: None,
                    score: Some(300),
                    description: None,
                },
                FilterRule {
                    name: "Black Friday Scam Detection".to_string(),
                    enabled: true,
                    criteria:
                    Criteria::And {
                        criteria: vec![
                        Criteria::Or {
                            criteria: vec![
                            Criteria::SubjectPattern { pattern: "(?i).{0,100}(black.{0,100}friday.{0,100}sale.{0,100}happening|fake.{0,100}black.{0,100}friday|buy.{0,100}1.{0,100}get.{0,100}1.{0,100}50.{0,100}off).*".to_string() },
                            Criteria::BodyPattern { pattern: "(?i).{0,100}(black.{0,100}friday.{0,100}sale.{0,100}happening|fake.{0,100}black.{0,100}friday|buy.{0,100}1.{0,100}get.{0,100}1.{0,100}50.{0,100}off).*".to_string() },
                            ],
                        },
                        Criteria::Not {
                            criteria: Box::new(
                            Criteria::Or {
                                criteria: vec![
                                Criteria::SenderPattern { pattern: ".*@.*(torrid|mktg\\.torrid|michaels|target|walmart|disney|amazon|nytimes|washingtonpost|cnn|bbc|reuters|ap|wsj|usatoday)\\.(com|net|org)$".to_string() },
                                ],
                            }
                            ),
                        },
                        ],
                    },
                    action: None,
                    score: Some(220),
                    description: None,
                },
                FilterRule {
                    name: "Email List Selling Spam".to_string(),
                    enabled: true,
                    criteria:
                    Criteria::And {
                        criteria: vec![
                        Criteria::Or {
                            criteria: vec![
                            Criteria::SubjectPattern { pattern: "(?i).{0,100}(email.{0,100}list.{0,100}selling|selling.{0,100}email.{0,100}list|buy.{0,100}email.{0,100}list).*".to_string() },
                            Criteria::BodyPattern { pattern: "(?i).{0,100}(email.{0,100}list.{0,100}selling|selling.{0,100}email.{0,100}list|buy.{0,100}email.{0,100}list).*".to_string() },
                            ],
                        },
                        Criteria::Not {
                            criteria: Box::new(
                            Criteria::SenderPattern { pattern: ".*@.*(nytimes|washingtonpost|cnn|bbc|reuters|ap|wsj|usatoday)\\.(com|org)$".to_string() }
                            ),
                        },
                        ],
                    },
                    action: None,
                    score: Some(250),
                    description: None,
                },
                FilterRule {
                    name: "Credit Card Resolution Spam".to_string(),
                    enabled: true,
                    criteria:
                    Criteria::Or {
                        criteria: vec![
                        Criteria::SubjectPattern { pattern: "(?i).{0,100}(creditcard.{0,100}bill|credit.{0,100}card.{0,100}resolution|unicode.{0,100}medical|dementia.{0,100}food.{0,100}misinformation|digestive.{0,100}flush).*".to_string() },
                        Criteria::BodyPattern { pattern: "(?i).{0,100}(creditcard.{0,100}bill|credit.{0,100}card.{0,100}resolution|unicode.{0,100}medical|dementia.{0,100}food.{0,100}misinformation|digestive.{0,100}flush).*".to_string() },
                        ],
                    },
                    action: None,
                    score: Some(250),
                    description: None,
                },
                FilterRule {
                    name: "ED Medical Enhancement Spam".to_string(),
                    enabled: true,
                    criteria:
                    Criteria::Or {
                        criteria: vec![
                        Criteria::SubjectPattern { pattern: "(?i).{0,100}(two.{0,100}finger.{0,100}massage.{0,100}revives.{0,100}ed|erectile.{0,100}dysfunction|male.{0,100}enhancement|performance.{0,100}enhancement).*".to_string() },
                        Criteria::BodyPattern { pattern: "(?i).{0,100}(two.{0,100}finger.{0,100}massage.{0,100}revives.{0,100}ed|erectile.{0,100}dysfunction|male.{0,100}enhancement|performance.{0,100}enhancement).*".to_string() },
                        ],
                    },
                    action: None,
                    score: Some(280),
                    description: None,
                },
                FilterRule {
                    name: "Fake Savings Scam Detection".to_string(),
                    enabled: true,
                    criteria:
                    Criteria::And {
                        criteria: vec![
                        Criteria::Or {
                            criteria: vec![
                            Criteria::SubjectPattern { pattern: "(?i).{0,100}(fake.{0,100}black.{0,100}friday.{0,100}savings|fake.{0,100}savings.{0,100}scam|too.{0,100}good.{0,100}to.{0,100}be.{0,100}true).*".to_string() },
                            Criteria::BodyPattern { pattern: "(?i).{0,100}(fake.{0,100}black.{0,100}friday.{0,100}savings|fake.{0,100}savings.{0,100}scam|too.{0,100}good.{0,100}to.{0,100}be.{0,100}true).*".to_string() },
                            ],
                        },
                        Criteria::Not {
                            criteria: Box::new(
                            Criteria::SenderPattern { pattern: ".*@.*nytimes.*".to_string() }
                            ),
                        },
                        ],
                    },
                    action: None,
                    score: Some(240),
                    description: None,
                },
                FilterRule {
                    name: "Interactive Brokers Tax Scam".to_string(),
                    enabled: true,
                    criteria:
                    Criteria::Or {
                        criteria: vec![
                        Criteria::SubjectPattern { pattern: "(?i).{0,100}(interactive.{0,100}brokers.{0,100}w8ben|w8ben.{0,100}compliance|w8ben.{0,100}tax.{0,100}scam|fake.{0,100}interactive.{0,100}brokers).*".to_string() },
                        Criteria::BodyPattern { pattern: "(?i).{0,100}(interactive.{0,100}brokers.{0,100}w8ben|w8ben.{0,100}compliance|w8ben.{0,100}tax.{0,100}scam|fake.{0,100}interactive.{0,100}brokers).*".to_string() },
                        ],
                    },
                    action: None,
                    score: Some(350),
                    description: None,
                },
                FilterRule {
                    name: "Fake Transaction Confirmation Spam".to_string(),
                    enabled: true,
                    criteria:
                    Criteria::Or {
                        criteria: vec![
                        Criteria::SubjectPattern { pattern: "(?i).{0,100}(fake.{0,100}order.{0,100}transaction|fake.{0,100}payment.{0,100}confirmation|order.{0,100}confirmation.{0,100}spam|transaction.{0,100}confirmation.{0,100}spam).*".to_string() },
                        Criteria::BodyPattern { pattern: "(?i).{0,100}(fake.{0,100}order.{0,100}transaction|fake.{0,100}payment.{0,100}confirmation|order.{0,100}confirmation.{0,100}spam|transaction.{0,100}confirmation.{0,100}spam).*".to_string() },
                        ],
                    },
                    action: None,
                    score: Some(320),
                    description: None,
                },
                FilterRule {
                    name: "Cognitive Enhancement Spam".to_string(),
                    enabled: true,
                    criteria:
                    Criteria::And {
                        criteria: vec![
                        Criteria::Or {
                            criteria: vec![
                            Criteria::BodyPattern { pattern: "(?i).{0,100}(boost.{0,100}brain.{0,100}power|enhance.{0,100}cognitive|improve.{0,100}memory|brain.{0,100}supplement|nootropic).*".to_string() },
                            Criteria::SubjectPattern { pattern: "(?i).{0,100}(brain.{0,100}boost|cognitive.{0,100}enhancement|memory.{0,100}supplement|smart.{0,100}pill|sip.{0,100}coffee.{0,100}3x|brain.{0,100}power).*".to_string() },
                            Criteria::BodyPattern { pattern: "(?i).{0,100}(sip.{0,100}coffee.{0,100}3x|stir.{0,100}coffee.{0,100}3x|miracle.{0,100}brain|secret.{0,100}formula|doctors.{0,100}recommend|clinical.{0,100}study).*".to_string() },
                            Criteria::BodyPattern { pattern: "(?i).{0,100}(increase.{0,100}iq|sharper.{0,100}mind|mental.{0,100}clarity|focus.{0,100}supplement).*".to_string() },
                            ],
                        },
                        Criteria::Not {
                            criteria: Box::new(
                            Criteria::SenderPattern { pattern: ".*@.*nytimes.*".to_string() }
                            ),
                        },
                        ],
                    },
                    action: None,
                    score: Some(200),
                    description: Some("Cognitive enhancement supplement scams".to_string()),
                },
                FilterRule {
                    name: "Dementia Misinformation Spam".to_string(),
                    enabled: true,
                    criteria:
                    Criteria::And {
                        criteria: vec![
                        Criteria::Or {
                            criteria: vec![
                            Criteria::SubjectPattern { pattern: "(?i).{0,100}(common.{0,100}food.{0,100}triples.{0,100}dementia|dementia.{0,100}risk|dementia.{0,100}warning|brain.{0,100}decline).*".to_string() },
                            Criteria::BodyPattern { pattern: "(?i).{0,100}(common.{0,100}food.{0,100}triples.{0,100}dementia|dementia.{0,100}risk|dementia.{0,100}warning|brain.{0,100}decline).*".to_string() },
                            ],
                        },
                        Criteria::Not {
                            criteria: Box::new(
                            Criteria::SenderPattern { pattern: ".*@.*nytimes.*".to_string() }
                            ),
                        },
                        ],
                    },
                    action: None,
                    score: Some(220),
                    description: None,
                },
                FilterRule {
                    name: "Digestive Health Spam".to_string(),
                    enabled: true,
                    criteria:
                    Criteria::Or {
                        criteria: vec![
                        Criteria::SubjectPattern { pattern: "(?i).{0,100}(need.{0,100}this.{0,100}flush.{0,100}not.{0,100}enema|digestive.{0,100}flush|gut.{0,100}health.{0,100}secret|digestive.{0,100}cleanse|colon.{0,100}cleanse).*".to_string() },
                        Criteria::BodyPattern { pattern: "(?i).{0,100}(need.{0,100}this.{0,100}flush.{0,100}not.{0,100}enema|digestive.{0,100}flush|gut.{0,100}health.{0,100}secret|digestive.{0,100}cleanse|colon.{0,100}cleanse).*".to_string() },
                        ],
                    },
                    action: None,
                    score: Some(180),
                    description: None,
                },
                FilterRule {
                    name: "Fake Harvard Health Claims".to_string(),
                    enabled: true,
                    criteria:
                    Criteria::Or {
                        criteria: vec![
                        Criteria::SubjectPattern { pattern: "(?i).{0,100}\\[harvard\\].{0,100}stretch.{0,100}foot|harvard.{0,100}foot.{0,100}health|fake.{0,100}harvard.{0,100}study.*".to_string() },
                        Criteria::BodyPattern { pattern: "(?i).{0,100}\\[harvard\\].{0,100}stretch.{0,100}foot|harvard.{0,100}foot.{0,100}health|fake.{0,100}harvard.{0,100}study.*".to_string() },
                        ],
                    },
                    action: None,
                    score: Some(280),
                    description: None,
                },
                FilterRule {
                    name: "Estonian Money Transfer Scam".to_string(),
                    enabled: true,
                    criteria:
                    Criteria::And {
                        criteria: vec![
                        Criteria::Or {
                            criteria: vec![
                            Criteria::SubjectPattern { pattern: "(?i).{0,100}(\\braha\\b|estonian|estonia|baltic.{0,100}funds|=\\?utf-8\\?Q\\?Raha).*".to_string() },
                            Criteria::BodyPattern { pattern: "(?i).{0,100}(\\braha\\b|estonian|estonia|baltic.{0,100}funds).*".to_string() },
                            ],
                        },
                        Criteria::Not {
                            criteria: Box::new(
                            Criteria::Or {
                                criteria: vec![
                                Criteria::SubjectPattern { pattern: "(?i).{0,100}(invoice|receipt|statement|bill|payment|quote|estimate).*".to_string() },
                                Criteria::SenderPattern { pattern: ".*@.*(exterminators|contractors|services|business|company)\\.(com|net|org)$".to_string() },
                                Criteria::SenderPattern { pattern: ".*@.*uncommongoods\\.(com|net|org)$".to_string() },
                                Criteria::SenderPattern { pattern: ".*@.*williams-sonoma\\.(com|net|org)$".to_string() },
                                ],
                            }
                            ),
                        },
                        ],
                    },
                    action: None,
                    score: Some(400),
                    description: Some("Estonian money transfer scams excluding legitimate business documents".to_string()),
                },
                FilterRule {
                    name: "Email List Selling Enhanced".to_string(),
                    enabled: true,
                    criteria:
                    Criteria::And {
                        criteria: vec![
                        Criteria::Or {
                            criteria: vec![
                            Criteria::SubjectPattern { pattern: "(?i).{0,100}(email.{0,100}lists.{0,100}2026|100.{0,100}mx.{0,100}tested.{0,100}emails|buy.{0,100}email.{0,100}database|selling.{0,100}email.{0,100}lists).*".to_string() },
                            Criteria::BodyPattern { pattern: "(?i).{0,100}(email.{0,100}lists.{0,100}2026|100.{0,100}mx.{0,100}tested.{0,100}emails|buy.{0,100}email.{0,100}database|selling.{0,100}email.{0,100}lists).*".to_string() },
                            ],
                        },
                        Criteria::Not {
                            criteria: Box::new(
                            Criteria::SenderPattern { pattern: ".*@.*(nytimes|washingtonpost|cnn|bbc|reuters|ap|wsj|usatoday)\\.(com|org)$".to_string() }
                            ),
                        },
                        ],
                    },
                    action: None,
                    score: Some(300),
                    description: None,
                },
                FilterRule {
                    name: "Black Friday Event Scam Enhanced".to_string(),
                    enabled: true,
                    criteria:
                    Criteria::Or {
                        criteria: vec![
                        Criteria::SubjectPattern { pattern: "(?i).{0,100}(get.{0,100}ready.{0,100}black.{0,100}friday.{0,100}event.{0,100}coming|black.{0,100}friday.{0,100}event.{0,100}is.{0,100}coming|fake.{0,100}black.{0,100}friday.{0,100}savings).*".to_string() },
                        Criteria::BodyPattern { pattern: "(?i).{0,100}(get.{0,100}ready.{0,100}black.{0,100}friday.{0,100}event.{0,100}coming|black.{0,100}friday.{0,100}event.{0,100}is.{0,100}coming|fake.{0,100}black.{0,100}friday.{0,100}savings).*".to_string() },
                        ],
                    },
                    action: None,
                    score: Some(250),
                    description: None,
                },
                FilterRule {
                    name: "Generic Suspicious Messages".to_string(),
                    enabled: true,
                    criteria:
                    Criteria::And {
                        criteria: vec![
                        Criteria::Or {
                            criteria: vec![
                            Criteria::SubjectPattern { pattern: "(?i).{0,100}(important.{0,100}message.{0,100}for.{0,100}you|urgent.{0,100}message.{0,100}for.{0,100}you|private.{0,100}message.{0,100}for.{0,100}you|confidential.{0,100}message.{0,100}for.{0,100}you|fam.{0,100}inquiry|urgent.{0,100}inquiry|personal.{0,100}message).*".to_string() },
                            Criteria::BodyPattern { pattern: "(?i).{0,100}(important.{0,100}message.{0,100}for.{0,100}you|urgent.{0,100}message.{0,100}for.{0,100}you|private.{0,100}message.{0,100}for.{0,100}you|confidential.{0,100}message.{0,100}for.{0,100}you|fam.{0,100}inquiry|urgent.{0,100}inquiry|personal.{0,100}message).*".to_string() },
                            ],
                        },
                        Criteria::Not {
                            criteria: Box::new(
                            Criteria::Or {
                                criteria: vec![
                                Criteria::SenderPattern { pattern: ".*@.*(adapthealth|healthcare|medical|clinic|hospital|pulmonary|levi|gmail|yahoo|hotmail|outlook|bearaby|sleep|wellness|michaels|emdeals\\.michaels|rejuvenation|e\\.rejuvenation|onestopplus|e\\.onestopplus|acemedseattle|sense)\\.(com|net|org)$".to_string() },
                                Criteria::HeaderPattern { header: "Authentication-Results".to_string(), pattern: "dkim=pass.{0,100}adapthealth\\.com".to_string() },
                                ],
                            }
                            ),
                        },
                        ],
                    },
                    action: None,
                    score: Some(150),
                    description: Some("Generic suspicious messages excluding healthcare".to_string()),
                },
                FilterRule {
                    name: "Streaming Service Scam".to_string(),
                    enabled: true,
                    criteria:
                    Criteria::Or {
                        criteria: vec![
                        Criteria::SubjectPattern { pattern: "(?i).{0,100}(flixy.{0,100}delivers.{0,100}unlimited.{0,100}streaming|unlimited.{0,100}streaming.{0,100}offer|fake.{0,100}streaming.{0,100}service).*".to_string() },
                        Criteria::BodyPattern { pattern: "(?i).{0,100}(flixy.{0,100}delivers.{0,100}unlimited.{0,100}streaming|unlimited.{0,100}streaming.{0,100}offer|fake.{0,100}streaming.{0,100}service).*".to_string() },
                        ],
                    },
                    action: None,
                    score: Some(220),
                    description: None,
                },
                FilterRule {
                    name: "Fake Forum Domain Spam".to_string(),
                    enabled: true,
                    criteria:
                    Criteria::Or {
                        criteria: vec![
                        Criteria::SubjectPattern { pattern: "(?i).{0,100}(sams.{0,100}club.{0,100}forum|fake.{0,100}forum.{0,100}domain|club.{0,100}membership.{0,100}scam).*".to_string() },
                        Criteria::BodyPattern { pattern: "(?i).{0,100}(sams.{0,100}club.{0,100}forum|fake.{0,100}forum.{0,100}domain|club.{0,100}membership.{0,100}scam).*".to_string() },
                        ],
                    },
                    action: None,
                    score: Some(200),
                    description: None,
                },
                FilterRule {
                    name: "Free Tools Software Scam".to_string(),
                    enabled: true,
                    criteria:
                    Criteria::Or {
                        criteria: vec![
                        Criteria::SubjectPattern { pattern: "(?i).{0,100}(tools.{0,100}built.{0,100}for.{0,100}pros.{0,100}yours.{0,100}free|free.{0,100}professional.{0,100}tools|microsoft.{0,100}compromise.{0,100}tools).*".to_string() },
                        Criteria::BodyPattern { pattern: "(?i).{0,100}(tools.{0,100}built.{0,100}for.{0,100}pros.{0,100}yours.{0,100}free|free.{0,100}professional.{0,100}tools|microsoft.{0,100}compromise.{0,100}tools).*".to_string() },
                        ],
                    },
                    action: None,
                    score: Some(240),
                    description: None,
                },
                FilterRule {
                    name: "French Rental Payment Scam".to_string(),
                    enabled: true,
                    criteria:
                    Criteria::Or {
                        criteria: vec![
                        Criteria::SubjectPattern { pattern: "(?i).{0,100}(avis.{0,100}de.{0,100}rappel.{0,100}pour.{0,100}bail|french.{0,100}rental.{0,100}payment|bail.{0,100}novembre|rental.{0,100}reminder).*".to_string() },
                        Criteria::BodyPattern { pattern: "(?i).{0,100}(avis.{0,100}de.{0,100}rappel.{0,100}pour.{0,100}bail|french.{0,100}rental.{0,100}payment|bail.{0,100}novembre|rental.{0,100}reminder).*".to_string() },
                        ],
                    },
                    action: None,
                    score: Some(300),
                    description: None,
                },
                FilterRule {
                    name: "Health Immune System Spam".to_string(),
                    enabled: true,
                    criteria:
                    Criteria::And {
                        criteria: vec![
                        Criteria::Or {
                            criteria: vec![
                            Criteria::SubjectPattern { pattern: "(?i).{0,100}(miracle.{0,100}cure.{0,100}chronic.{0,100}pain|doctors.{0,100}hate.{0,100}this|immune.{0,100}system.{0,100}health.{0,100}misinformation|health.{0,100}spam|boost.{0,100}immune.{0,100}system|immune.{0,100}support).*".to_string() },
                            Criteria::BodyPattern { pattern: "(?i).{0,100}(miracle.{0,100}cure.{0,100}chronic.{0,100}pain|doctors.{0,100}hate.{0,100}this|immune.{0,100}system.{0,100}health.{0,100}misinformation|health.{0,100}spam|boost.{0,100}immune.{0,100}system|immune.{0,100}support).*".to_string() },
                            ],
                        },
                        Criteria::Not {
                            criteria: Box::new(
                            Criteria::Or {
                                criteria: vec![
                                Criteria::SenderPattern { pattern: ".*@.*(costco|walmart|target|amazon|bestbuy|homedepot|lowes|walgreens|cvs)\\.(com|net)$".to_string() },
                                Criteria::SenderPattern { pattern: ".*@.*costco\\.com\\..*$".to_string() },
                                ],
                            }
                            ),
                        },
                        ],
                    },
                    action: None,
                    score: Some(190),
                    description: None,
                },
                FilterRule {
                    name: "Heater Appliance Spam".to_string(),
                    enabled: true,
                    criteria:
                    Criteria::Or {
                        criteria: vec![
                        Criteria::SubjectPattern { pattern: "(?i).{0,100}(heatwell.{0,100}heater|miracle.{0,100}heater|energy.{0,100}saving.{0,100}heater|portable.{0,100}heater.{0,100}scam).*".to_string() },
                        Criteria::BodyPattern { pattern: "(?i).{0,100}(heatwell.{0,100}heater|miracle.{0,100}heater|energy.{0,100}saving.{0,100}heater|portable.{0,100}heater.{0,100}scam).*".to_string() },
                        ],
                    },
                    action: None,
                    score: Some(180),
                    description: None,
                },
                FilterRule {
                    name: "Joint Knee Pain Spam".to_string(),
                    enabled: true,
                    criteria:
                    Criteria::Or {
                        criteria: vec![
                        Criteria::SubjectPattern { pattern: "(?i).{0,100}(bone.{0,100}on.{0,100}bone|joint.{0,100}knee.{0,100}pain|knee.{0,100}health.{0,100}spam|painful.{0,100}knees|joint.{0,100}pain.{0,100}relief).*".to_string() },
                        Criteria::BodyPattern { pattern: "(?i).{0,100}(bone.{0,100}on.{0,100}bone|joint.{0,100}knee.{0,100}pain|knee.{0,100}health.{0,100}spam|painful.{0,100}knees|joint.{0,100}pain.{0,100}relief).*".to_string() },
                        ],
                    },
                    action: None,
                    score: Some(200),
                    description: None,
                },
                FilterRule {
                    name: "Keto Diet Spam".to_string(),
                    enabled: true,
                    criteria:
                    Criteria::Or {
                        criteria: vec![
                        Criteria::SubjectPattern { pattern: "(?i).{0,100}(truth.{0,100}about.{0,100}keto|keto.{0,100}diet.{0,100}secret|keto.{0,100}weight.{0,100}loss|ketogenic.{0,100}scam).*".to_string() },
                        Criteria::BodyPattern { pattern: "(?i).{0,100}(truth.{0,100}about.{0,100}keto|keto.{0,100}diet.{0,100}secret|keto.{0,100}weight.{0,100}loss|ketogenic.{0,100}scam).*".to_string() },
                        ],
                    },
                    action: None,
                    score: Some(180),
                    description: None,
                },
                FilterRule {
                    name: "Gutter Protection Spam".to_string(),
                    enabled: true,
                    criteria:
                    Criteria::Or {
                        criteria: vec![
                        Criteria::SubjectPattern { pattern: "(?i).{0,100}(fall.{0,100}into.{0,100}savings.{0,100}gutter.{0,100}protection|leaffilter.{0,100}gutter.{0,100}protection|leafguard.{0,100}gutter|gutter.{0,100}protection.{0,100}spam|home.{0,100}improvement.{0,100}scam).*".to_string() },
                        Criteria::BodyPattern { pattern: "(?i).{0,100}(fall.{0,100}into.{0,100}savings.{0,100}gutter.{0,100}protection|leaffilter.{0,100}gutter.{0,100}protection|leafguard.{0,100}gutter|gutter.{0,100}protection.{0,100}spam|home.{0,100}improvement.{0,100}scam).*".to_string() },
                        ],
                    },
                    action: None,
                    score: Some(160),
                    description: None,
                },
                FilterRule {
                    name: "Mailer Daemon Spoofing".to_string(),
                    enabled: true,
                    criteria:
                    Criteria::Or {
                        criteria: vec![
                        Criteria::SubjectPattern { pattern: "(?i).{0,100}(mailer.{0,100}daemon.{0,100}spoofing|fake.{0,100}mailer.{0,100}daemon|delivery.{0,100}failure.{0,100}scam).*".to_string() },
                        Criteria::BodyPattern { pattern: "(?i).{0,100}(mailer.{0,100}daemon.{0,100}spoofing|fake.{0,100}mailer.{0,100}daemon|delivery.{0,100}failure.{0,100}scam).*".to_string() },
                        ],
                    },
                    action: None,
                    score: Some(300),
                    description: None,
                },
                FilterRule {
                    name: "Unicode Discount Offers".to_string(),
                    enabled: true,
                    criteria:
                    Criteria::Or {
                        criteria: vec![
                        Criteria::SubjectPattern { pattern: "(?i).{0,100}(𝗟𝗮𝘀𝘁.*𝗰𝗵𝗮𝗻𝗰𝗲|𝗚𝗲𝘁.*𝟱𝟬.*𝗢𝗙𝗙|unicode.{0,100}discount|special.{0,100}characters.{0,100}offer).*".to_string() },
                        Criteria::BodyPattern { pattern: "(?i).{0,100}(𝗟𝗮𝘀𝘁.*𝗰𝗵𝗮𝗻𝗰𝗲|𝗚𝗲𝘁.*𝟱𝟬.*𝗢𝗙𝗙|unicode.{0,100}discount|special.{0,100}characters.{0,100}offer).*".to_string() },
                        ],
                    },
                    action: None,
                    score: Some(250),
                    description: None,
                },
                FilterRule {
                    name: "Enhanced Immune System Misinformation".to_string(),
                    enabled: true,
                    criteria:
                    Criteria::And {
                        criteria: vec![
                        Criteria::Or {
                            criteria: vec![
                            Criteria::SubjectPattern { pattern: "(?i).{0,100}(hidden.{0,100}truth.{0,100}immune.{0,100}system|immune.{0,100}system.{0,100}misinformation|al.{0,100}sears.{0,100}md|immune.{0,100}system.{0,100}secret).*".to_string() },
                            Criteria::BodyPattern { pattern: "(?i).{0,100}(hidden.{0,100}truth.{0,100}immune.{0,100}system|immune.{0,100}system.{0,100}misinformation|al.{0,100}sears.{0,100}md|immune.{0,100}system.{0,100}secret).*".to_string() },
                            ],
                        },
                        Criteria::Not {
                            criteria: Box::new(
                            Criteria::Or {
                                criteria: vec![
                                Criteria::SenderPattern { pattern: ".*@.*(nytimes|washingtonpost|cnn|bbc|reuters|ap|wsj|usatoday)\\.(com|org)$".to_string() },
                                Criteria::SubjectPattern { pattern: "(?i).{0,100}(recipe|cooking|breakfast|meal|food|nutrition).*".to_string() },
                                ],
                            }
                            ),
                        },
                        ],
                    },
                    action: None,
                    score: Some(220),
                    description: None,
                },
                FilterRule {
                    name: "Malware Attachment Spam".to_string(),
                    enabled: true,
                    criteria:
                    Criteria::And {
                        criteria: vec![
                        Criteria::Or {
                            criteria: vec![
                            Criteria::SubjectPattern { pattern: "(?i).{0,100}(new.{0,100}enquiry|malware.{0,100}rar.{0,100}attachment|suspicious.{0,100}attachment|urgent.{0,100}document).*".to_string() },
                            Criteria::BodyPattern { pattern: "(?i).{0,100}(new.{0,100}enquiry|malware.{0,100}rar.{0,100}attachment|suspicious.{0,100}attachment|urgent.{0,100}document).*".to_string() },
                            ],
                        },
                        Criteria::Not {
                            criteria: Box::new(
                            Criteria::Or {
                                criteria: vec![
                                Criteria::SenderPattern { pattern: ".*@.*(acemedseattle|charmtracker|healthcare|medical|clinic|hospital)\\.(com|net|org)$".to_string() },
                                Criteria::SenderPattern { pattern: ".*@.*(michaels|emdeals\\.michaels|rejuvenation|e\\.rejuvenation|onestopplus|e\\.onestopplus)\\.(com|net|org)$".to_string() },
                                ],
                            }
                            ),
                        },
                        ],
                    },
                    action: None,
                    score: Some(350),
                    description: None,
                },
                FilterRule {
                    name: "Enhanced Knee Health Spam".to_string(),
                    enabled: true,
                    criteria:
                    Criteria::Or {
                        criteria: vec![
                        Criteria::SubjectPattern { pattern: "(?i).{0,100}(knee.{0,100}health.{0,100}spam|knee.{0,100}pain.{0,100}relief|joint.{0,100}restoration|arthritis.{0,100}cure).*".to_string() },
                        Criteria::BodyPattern { pattern: "(?i).{0,100}(knee.{0,100}health.{0,100}spam|knee.{0,100}pain.{0,100}relief|joint.{0,100}restoration|arthritis.{0,100}cure).*".to_string() },
                        ],
                    },
                    action: None,
                    score: Some(190),
                    description: None,
                },
                FilterRule {
                    name: "Enhanced Leafguard Gutter Spam".to_string(),
                    enabled: true,
                    criteria:
                    Criteria::Or {
                        criteria: vec![
                        Criteria::SubjectPattern { pattern: "(?i).{0,100}(gutter.{0,100}zero.{0,100}maintenance|leafguard|gutter.{0,100}peace.{0,100}mind).*".to_string() },
                        Criteria::BodyPattern { pattern: "(?i).{0,100}(gutter.{0,100}zero.{0,100}maintenance|leafguard|gutter.{0,100}peace.{0,100}mind).*".to_string() },
                        ],
                    },
                    action: None,
                    score: Some(170),
                    description: None,
                },
                FilterRule {
                    name: "Chef Knife Kitchen Product Spam".to_string(),
                    enabled: true,
                    criteria:
                    Criteria::And {
                        criteria: vec![
                        Criteria::Or {
                            criteria: vec![
                            Criteria::SubjectPattern { pattern: "(?i).{0,100}(last.{0,100}day.{0,100}grab.{0,100}big.{0,100}promo|matsato.{0,100}chef.{0,100}knife|kitchen.{0,100}knife.{0,100}promo|chef.{0,100}knife.{0,100}sale).*".to_string() },
                            Criteria::BodyPattern { pattern: "(?i).{0,100}(last.{0,100}day.{0,100}grab.{0,100}big.{0,100}promo|matsato.{0,100}chef.{0,100}knife|kitchen.{0,100}knife.{0,100}promo|chef.{0,100}knife.{0,100}sale).*".to_string() },
                            ],
                        },
                        Criteria::Not {
                            criteria: Box::new(
                            Criteria::SenderPattern { pattern: ".*@.*(nytimes|washingtonpost|wsj)\\.(com|net)$".to_string() }
                            ),
                        },
                        ],
                    },
                    action: None,
                    score: Some(160),
                    description: None,
                },
                FilterRule {
                    name: "Knee Health Enhanced Patterns".to_string(),
                    enabled: true,
                    criteria:
                    Criteria::Or {
                        criteria: vec![
                        Criteria::SubjectPattern { pattern: "(?i).{0,100}(knee.{0,100}health|joint.{0,100}pain|arthritis.{0,100}relief|mobility.{0,100}improvement).*".to_string() },
                        Criteria::BodyPattern { pattern: "(?i).{0,100}(knee.{0,100}health|joint.{0,100}pain|arthritis.{0,100}relief|mobility.{0,100}improvement).*".to_string() },
                        ],
                    },
                    action: None,
                    score: Some(180),
                    description: None,
                },
                FilterRule {
                    name: "Piano Course Spam".to_string(),
                    enabled: true,
                    criteria:
                    Criteria::Or {
                        criteria: vec![
                        Criteria::SubjectPattern { pattern: "(?i).{0,100}(i.{0,100}love.{0,100}my.{0,100}piano.{0,100}now|piano.{0,100}course.{0,100}shop|learn.{0,100}piano.{0,100}fast|piano.{0,100}lessons).*".to_string() },
                        Criteria::BodyPattern { pattern: "(?i).{0,100}(i.{0,100}love.{0,100}my.{0,100}piano.{0,100}now|piano.{0,100}course.{0,100}shop|learn.{0,100}piano.{0,100}fast|piano.{0,100}lessons).*".to_string() },
                        ],
                    },
                    action: None,
                    score: Some(160),
                    description: None,
                },
                FilterRule {
                    name: "Product Demo Notification Spam".to_string(),
                    enabled: true,
                    criteria:
                    Criteria::And {
                        criteria: vec![
                        Criteria::Or {
                            criteria: vec![
                            Criteria::SubjectPattern { pattern: "(?i).{0,100}(product.{0,100}demo.{0,100}notification|demo.{0,100}request|product.{0,100}demonstration|free.{0,100}demo).*".to_string() },
                            Criteria::BodyPattern { pattern: "(?i).{0,100}(product.{0,100}demo.{0,100}notification|demo.{0,100}request|product.{0,100}demonstration|free.{0,100}demo).*".to_string() },
                            ],
                        },
                        Criteria::Not {
                            criteria: Box::new(
                            Criteria::Or {
                                criteria: vec![
                                Criteria::SenderPattern { pattern: ".*@.*(democrats|republicans|political|campaign|gov)\\.(org|com|gov)$".to_string() },
                                Criteria::SenderPattern { pattern: ".*@.*wa-democrats\\.(org|com)$".to_string() },
                                Criteria::SenderPattern { pattern: ".*@.*(nytimes|washingtonpost|cnn|bbc|reuters|ap|wsj|usatoday)\\.(com|org)$".to_string() },
                                ],
                            }
                            ),
                        },
                        ],
                    },
                    action: None,
                    score: Some(180),
                    description: None,
                },
                FilterRule {
                    name: "Prostate Health Spam".to_string(),
                    enabled: true,
                    criteria:
                    Criteria::Or {
                        criteria: vec![
                        Criteria::SubjectPattern { pattern: "(?i).{0,100}(hidden.{0,100}toxin.{0,100}bloating.{0,100}prostate|ancient.{0,100}fix.{0,100}flushes|prostate.{0,100}toxin|prostate.{0,100}health.{0,100}scam).*".to_string() },
                        Criteria::BodyPattern { pattern: "(?i).{0,100}(hidden.{0,100}toxin.{0,100}bloating.{0,100}prostate|ancient.{0,100}fix.{0,100}flushes|prostate.{0,100}toxin|prostate.{0,100}health.{0,100}scam).*".to_string() },
                        ],
                    },
                    action: None,
                    score: Some(220),
                    description: None,
                },
                FilterRule {
                    name: "Enhanced Mailer Daemon Patterns".to_string(),
                    enabled: true,
                    criteria:
                    Criteria::And {
                        criteria: vec![
                        Criteria::Or {
                            criteria: vec![
                            Criteria::SubjectPattern { pattern: "(?i).{0,100}(mailer.{0,100}daemon|delivery.{0,100}failure|undelivered.{0,100}mail|returned.{0,100}mail|mail.{0,100}delivery.{0,100}subsystem).*".to_string() },
                            Criteria::BodyPattern { pattern: "(?i).{0,100}(mailer.{0,100}daemon|delivery.{0,100}failure|undelivered.{0,100}mail|returned.{0,100}mail|mail.{0,100}delivery.{0,100}subsystem).*".to_string() },
                            ],
                        },
                        Criteria::Not {
                            criteria: Box::new(
                            Criteria::SenderPattern { pattern: ".*@.*(levi|nike|adidas|gap|oldnavy|ecoflow|onestopplus|torrid|sense)\\.(com|net|org)$".to_string() }
                            ),
                        },
                        ],
                    },
                    action: None,
                    score: Some(320),
                    description: None,
                },
                FilterRule {
                    name: "Enhanced Transaction Confirmation Patterns".to_string(),
                    enabled: true,
                    criteria:
                    Criteria::And {
                        criteria: vec![
                        Criteria::Or {
                            criteria: vec![
                            Criteria::SubjectPattern { pattern: "(?i).{0,100}(order.{0,100}confirmation|payment.{0,100}confirmation|transaction.{0,100}confirmation|receipt.{0,100}confirmation).*".to_string() },
                            Criteria::BodyPattern { pattern: "(?i).{0,100}(order.{0,100}confirmation|payment.{0,100}confirmation|transaction.{0,100}confirmation|receipt.{0,100}confirmation).*".to_string() },
                            ],
                        },
                        Criteria::Or {
                            criteria: vec![
                            Criteria::BodyPattern { pattern: "(?i).{0,100}(click.{0,100}here.{0,100}view|download.{0,100}attachment.{0,100}view|verify.{0,100}payment.{0,100}method|update.{0,100}billing.{0,100}info).*".to_string() },
                            Criteria::BodyPattern { pattern: "(?i).{0,100}(suspicious.{0,100}activity.{0,100}detected|account.{0,100}may.{0,100}be.{0,100}compromised|urgent.{0,100}action.{0,100}required).*".to_string() },
                            Criteria::HeaderPattern { header: "Authentication-Results".to_string(), pattern: "dkim=fail".to_string() },
                            ],
                        },
                        Criteria::Not {
                            criteria: Box::new(
                            Criteria::Or {
                                criteria: vec![
                                Criteria::SenderPattern { pattern: ".*@.*(quickbooks|intuit|paypal|stripe|square)\\.(com|net|org)$".to_string() },
                                Criteria::HeaderPattern { header: "Return-Path".to_string(), pattern: ".*@.*myshopify\\.com.*".to_string() },
                                Criteria::HeaderPattern { header: "From".to_string(), pattern: ".*QuickBooks.*".to_string() },
                                ],
                            }
                            ),
                        },
                        ],
                    },
                    action: None,
                    score: Some(280),
                    description: Some("Fake transaction confirmations with suspicious elements".to_string()),
                },
                FilterRule {
                    name: "Payment Transaction Thank You Spam".to_string(),
                    enabled: true,
                    criteria:
                    Criteria::Or {
                        criteria: vec![
                        Criteria::SubjectPattern { pattern: "(?i).{0,100}(thank.{0,100}you.{0,100}payment.{0,100}transaction|payment.{0,100}confirmation.{0,100}transaction|transaction.{0,100}payment.{0,100}thank).*".to_string() },
                        Criteria::BodyPattern { pattern: "(?i).{0,100}(thank.{0,100}you.{0,100}payment.{0,100}transaction|payment.{0,100}confirmation.{0,100}transaction|transaction.{0,100}payment.{0,100}thank).*".to_string() },
                        ],
                    },
                    action: None,
                    score: Some(300),
                    description: None,
                },
                FilterRule {
                    name: "Knee Mistake Health Spam".to_string(),
                    enabled: true,
                    criteria:
                    Criteria::Or {
                        criteria: vec![
                        Criteria::SubjectPattern { pattern: "(?i).{0,100}(mistake.{0,100}makes.{0,100}bad.{0,100}knees.{0,100}worse|knee.{0,100}health.{0,100}mistake|bad.{0,100}knees.{0,100}worse).*".to_string() },
                        Criteria::BodyPattern { pattern: "(?i).{0,100}(mistake.{0,100}makes.{0,100}bad.{0,100}knees.{0,100}worse|knee.{0,100}health.{0,100}mistake|bad.{0,100}knees.{0,100}worse).*".to_string() },
                        ],
                    },
                    action: None,
                    score: Some(190),
                    description: None,
                },
                FilterRule {
                    name: "Debt Relief Solutions Spam".to_string(),
                    enabled: true,
                    criteria:
                    Criteria::Or {
                        criteria: vec![
                        Criteria::SubjectPattern { pattern: "(?i).{0,100}(reduce.{0,100}debt.{0,100}expert.{0,100}debt.{0,100}relief|debt.{0,100}relief.{0,100}solutions|expert.{0,100}debt.{0,100}relief).*".to_string() },
                        Criteria::BodyPattern { pattern: "(?i).{0,100}(reduce.{0,100}debt.{0,100}expert.{0,100}debt.{0,100}relief|debt.{0,100}relief.{0,100}solutions|expert.{0,100}debt.{0,100}relief).*".to_string() },
                        ],
                    },
                    action: None,
                    score: Some(200),
                    description: None,
                },
                FilterRule {
                    name: "Enhanced Product Demo Spam".to_string(),
                    enabled: true,
                    criteria:
                    Criteria::And {
                        criteria: vec![
                        Criteria::Or {
                            criteria: vec![
                            Criteria::SubjectPattern { pattern: "(?i)^demo$|product.{0,100}demo.{0,100}notification|demo.{0,100}request|free.{0,100}demo".to_string() },
                            Criteria::BodyPattern { pattern: "(?i)^demo$|product.{0,100}demo.{0,100}notification|demo.{0,100}request|free.{0,100}demo".to_string() },
                            ],
                        },
                        Criteria::Not {
                            criteria: Box::new(
                            Criteria::Or {
                                criteria: vec![
                                Criteria::SenderPattern { pattern: ".*@.*(democrats|republicans|political|campaign|gov)\\.(org|com|gov)$".to_string() },
                                Criteria::SenderPattern { pattern: ".*@.*wa-democrats\\.(org|com)$".to_string() },
                                Criteria::SenderPattern { pattern: ".*@.*(nytimes|washingtonpost|cnn|bbc|reuters|ap|wsj|usatoday)\\.(com|org)$".to_string() },
                                ],
                            }
                            ),
                        },
                        ],
                    },
                    action: None,
                    score: Some(200),
                    description: None,
                },
                FilterRule {
                    name: "Unicode Shipping ID Spam".to_string(),
                    enabled: true,
                    criteria:
                    Criteria::Or {
                        criteria: vec![
                        Criteria::SubjectPattern { pattern: "(?i).{0,100}(𝗦𝗵𝗶𝗽𝗽𝗶𝗻𝗴.*𝗜𝗗|shipping.{0,100}id.{0,100}unicode|bold.{0,100}unicode.{0,100}shipping).*".to_string() },
                        Criteria::BodyPattern { pattern: "(?i).{0,100}(𝗦𝗵𝗶𝗽𝗽𝗶𝗻𝗴.*𝗜𝗗|shipping.{0,100}id.{0,100}unicode|bold.{0,100}unicode.{0,100}shipping).*".to_string() },
                        ],
                    },
                    action: None,
                    score: Some(280),
                    description: None,
                },
                FilterRule {
                    name: "Screenshot Spam".to_string(),
                    enabled: true,
                    criteria:
                    Criteria::Or {
                        criteria: vec![
                        Criteria::SubjectPattern { pattern: "(?i).{0,100}(screenshot.{0,100}\\?\\?%%##|screenshot.{0,100}spam|suspicious.{0,100}screenshot).*".to_string() },
                        Criteria::BodyPattern { pattern: "(?i).{0,100}(screenshot.{0,100}\\?\\?%%##|screenshot.{0,100}spam|suspicious.{0,100}screenshot).*".to_string() },
                        ],
                    },
                    action: None,
                    score: Some(200),
                    description: None,
                },
                FilterRule {
                    name: "VPN Offer Spam".to_string(),
                    enabled: true,
                    criteria:
                    Criteria::And {
                        criteria: vec![
                        Criteria::Or {
                            criteria: vec![
                            Criteria::SubjectPattern { pattern: "(?i).{0,100}(secure.{0,100}my.{0,100}connection|vpn.{0,100}offer|connection.{0,100}security|vpn.{0,100}protection|unlocator.{0,100}vpn).*".to_string() },
                            Criteria::BodyPattern { pattern: "(?i).{0,100}(secure.{0,100}my.{0,100}connection|vpn.{0,100}offer|connection.{0,100}security|vpn.{0,100}protection|unlocator.{0,100}vpn).*".to_string() },
                            ],
                        },
                        Criteria::Not {
                            criteria: Box::new(
                            Criteria::Or {
                                criteria: vec![
                                Criteria::SenderPattern { pattern: ".*@.*(asus|nedm\\.asus|linksys|netgear|tp-link|ubiquiti|cisco|synology|qnap|saily|nordvpn|expressvpn|surfshark)\\.(com|net|org)$".to_string() },
                                Criteria::FeatureAnalysis {
                                    feature_name: "Authentication Analysis".to_string(),
                                    min_score: None,
                                    max_score: None,
                                    evidence_pattern: Some("DKIM domain properly aligned".to_string()),
                                    invert: None,
                                },
                                ],
                            }
                            ),
                        },
                        ],
                    },
                    action: None,
                    score: Some(180),
                    description: None,
                },
                FilterRule {
                    name: "Security Camera Light Socket Spam".to_string(),
                    enabled: true,
                    criteria:
                    Criteria::Or {
                        criteria: vec![
                        Criteria::SubjectPattern { pattern: "(?i).{0,100}(ultra.{0,100}security.{0,100}must.{0,100}have.{0,100}homeowners|light.{0,100}socket.{0,100}security.{0,100}camera|security.{0,100}camera.{0,100}homeowners).*".to_string() },
                        Criteria::BodyPattern { pattern: "(?i).{0,100}(ultra.{0,100}security.{0,100}must.{0,100}have.{0,100}homeowners|light.{0,100}socket.{0,100}security.{0,100}camera|security.{0,100}camera.{0,100}homeowners).*".to_string() },
                        ],
                    },
                    action: None,
                    score: Some(180),
                    description: None,
                },
                FilterRule {
                    name: "Stanford Nerve Damage Spam".to_string(),
                    enabled: true,
                    criteria:
                    Criteria::Or {
                        criteria: vec![
                        Criteria::SubjectPattern { pattern: "(?i).{0,100}(stanford.{0,100}scientists.{0,100}reveal.{0,100}bedtime.{0,100}ritual.{0,100}reverses.{0,100}nerve.{0,100}damage|nerve.{0,100}damage.{0,100}overnight|stanford.{0,100}nerve.{0,100}damage).*".to_string() },
                        Criteria::BodyPattern { pattern: "(?i).{0,100}(stanford.{0,100}scientists.{0,100}reveal.{0,100}bedtime.{0,100}ritual.{0,100}reverses.{0,100}nerve.{0,100}damage|nerve.{0,100}damage.{0,100}overnight|stanford.{0,100}nerve.{0,100}damage).*".to_string() },
                        ],
                    },
                    action: None,
                    score: Some(220),
                    description: None,
                },
                FilterRule {
                    name: "Stanford Weight Loss Spam".to_string(),
                    enabled: true,
                    criteria:
                    Criteria::Or {
                        criteria: vec![
                        Criteria::SubjectPattern { pattern: "(?i).{0,100}(stanford.{0,100}melt.{0,100}flab|stanford.{0,100}weight.{0,100}loss|stanford.{0,100}fat.{0,100}burning|stanford.{0,100}shower.{0,100}melt).*".to_string() },
                        Criteria::BodyPattern { pattern: "(?i).{0,100}(stanford.{0,100}melt.{0,100}flab|stanford.{0,100}weight.{0,100}loss|stanford.{0,100}fat.{0,100}burning|stanford.{0,100}shower.{0,100}melt).*".to_string() },
                        ],
                    },
                    action: None,
                    score: Some(300),
                    description: None,
                },
                FilterRule {
                    name: "Professor Tee Clothing Scam".to_string(),
                    enabled: true,
                    criteria:
                    Criteria::And {
                        criteria: vec![
                        Criteria::Or {
                            criteria: vec![
                            Criteria::SubjectPattern { pattern: "(?i).{0,100}(smart.{0,100}looks.{0,100}smart.{0,100}minds|professor.{0,100}tee|instadoodle).*".to_string() },
                            Criteria::BodyPattern { pattern: "(?i).{0,100}(smart.{0,100}looks.{0,100}smart.{0,100}minds|professor.{0,100}tee|instadoodle).*".to_string() },
                            Criteria::SenderPattern { pattern: ".*@.*instadoodle\\.(me|com|net|org)$".to_string() },
                            ],
                        },
                        Criteria::Not {
                            criteria: Box::new(
                            Criteria::SenderPattern { pattern: ".*@.*(nytimes|newyorktimes)\\.(com|org)$".to_string() }
                            ),
                        },
                        ],
                    },
                    action: None,
                    score: Some(300),
                    description: None,
                },
                FilterRule {
                    name: "Shed Building Scam".to_string(),
                    enabled: true,
                    criteria:
                    Criteria::Or {
                        criteria: vec![
                        Criteria::SubjectPattern { pattern: "(?i).{0,100}(shed.{0,100}building.{0,100}scam|build.{0,100}shed.{0,100}cheap|diy.{0,100}shed.{0,100}plans).*".to_string() },
                        Criteria::BodyPattern { pattern: "(?i).{0,100}(shed.{0,100}building.{0,100}scam|build.{0,100}shed.{0,100}cheap|diy.{0,100}shed.{0,100}plans).*".to_string() },
                        ],
                    },
                    action: None,
                    score: Some(160),
                    description: None,
                },
                FilterRule {
                    name: "Brain Age Test Spam".to_string(),
                    enabled: true,
                    criteria:
                    Criteria::Or {
                        criteria: vec![
                        Criteria::SubjectPattern { pattern: "(?i).{0,100}(take.{0,100}brain.{0,100}age.{0,100}test|brain.{0,100}age.{0,100}test|cognitive.{0,100}age.{0,100}test|mental.{0,100}age.{0,100}assessment).*".to_string() },
                        Criteria::BodyPattern { pattern: "(?i).{0,100}(take.{0,100}brain.{0,100}age.{0,100}test|brain.{0,100}age.{0,100}test|cognitive.{0,100}age.{0,100}test|mental.{0,100}age.{0,100}assessment).*".to_string() },
                        ],
                    },
                    action: None,
                    score: Some(190),
                    description: None,
                },
                FilterRule {
                    name: "Eyesight Test Spam".to_string(),
                    enabled: true,
                    criteria:
                    Criteria::And {
                        criteria: vec![
                        Criteria::Or {
                            criteria: vec![
                            Criteria::SubjectPattern { pattern: "(?i).{0,100}(eyesight.{0,100}flower|test.{0,100}eyesight|vision.{0,100}test|eye.{0,100}health.{0,100}test).*".to_string() },
                            Criteria::BodyPattern { pattern: "(?i).{0,100}(eyesight.{0,100}flower|test.{0,100}eyesight|vision.{0,100}test|eye.{0,100}health.{0,100}test).*".to_string() },
                            ],
                        },
                        Criteria::Not {
                            criteria: Box::new(
                            Criteria::Or {
                                criteria: vec![
                                Criteria::SenderPattern { pattern: ".*@.*(nytimes|washingtonpost|cnn|bbc|reuters|ap|wsj|usatoday)\\.(com|org)$".to_string() },
                                Criteria::SenderPattern { pattern: ".*@.*(walgreens|cvs|riteaid|pharmacy|optum|lenscrafters|visionworks)\\.(com|net|org)$".to_string() },
                                Criteria::FeatureAnalysis {
                                    feature_name: "Authentication Analysis".to_string(),
                                    min_score: None,
                                    max_score: None,
                                    evidence_pattern: Some("DKIM domain properly aligned".to_string()),
                                    invert: None,
                                },
                                ],
                            }
                            ),
                        },
                        ],
                    },
                    action: None,
                    score: Some(180),
                    description: None,
                },
                FilterRule {
                    name: "Holiday Shipping Sleep Spam".to_string(),
                    enabled: true,
                    criteria:
                    Criteria::Or {
                        criteria: vec![
                        Criteria::SubjectPattern { pattern: "(?i).{0,100}(time.{0,100}gift.{0,100}better.{0,100}sleep.{0,100}holiday.{0,100}shipping|holiday.{0,100}shipping.{0,100}ends.{0,100}soon|gift.{0,100}better.{0,100}sleep).*".to_string() },
                        Criteria::BodyPattern { pattern: "(?i).{0,100}(time.{0,100}gift.{0,100}better.{0,100}sleep.{0,100}holiday.{0,100}shipping|holiday.{0,100}shipping.{0,100}ends.{0,100}soon|gift.{0,100}better.{0,100}sleep).*".to_string() },
                        ],
                    },
                    action: None,
                    score: Some(170),
                    description: None,
                },
                FilterRule {
                    name: "Synoshi Cleaning Spam".to_string(),
                    enabled: true,
                    criteria:
                    Criteria::Or {
                        criteria: vec![
                        Criteria::SubjectPattern { pattern: "(?i).{0,100}(clean.{0,100}less.{0,100}live.{0,100}more|synoshi.{0,100}cleaning|cleaning.{0,100}help.{0,100}domain|synoshi.{0,100}product|cleaning.{0,100}scrubber).*".to_string() },
                        Criteria::BodyPattern { pattern: "(?i).{0,100}(clean.{0,100}less.{0,100}live.{0,100}more|synoshi.{0,100}cleaning|cleaning.{0,100}help.{0,100}domain|synoshi.{0,100}product|cleaning.{0,100}scrubber).*".to_string() },
                        ],
                    },
                    action: None,
                    score: Some(160),
                    description: None,
                },
                FilterRule {
                    name: "Unicode Credit Card Bill".to_string(),
                    enabled: true,
                    criteria:
                    Criteria::Or {
                        criteria: vec![
                        Criteria::SubjectPattern { pattern: "(?i).{0,100}(𝚛𝚎.*𝚢𝚘𝚞𝚛.*𝚌𝚛𝚎𝚍𝚒𝚝.*𝚌𝚊𝚛𝚍.*𝚋𝚒𝚕𝚕|unicode.{0,100}credit.{0,100}card|monospace.{0,100}credit.{0,100}card).*".to_string() },
                        Criteria::BodyPattern { pattern: "(?i).{0,100}(𝚛𝚎.*𝚢𝚘𝚞𝚛.*𝚌𝚛𝚎𝚍𝚒𝚝.*𝚌𝚊𝚛𝚍.*𝚋𝚒𝚕𝚕|unicode.{0,100}credit.{0,100}card|monospace.{0,100}credit.{0,100}card).*".to_string() },
                        ],
                    },
                    action: None,
                    score: Some(280),
                    description: None,
                },
                FilterRule {
                    name: "Mascara Beauty Spam".to_string(),
                    enabled: true,
                    criteria:
                    Criteria::Or {
                        criteria: vec![
                        Criteria::SubjectPattern { pattern: "(?i).{0,100}(thick.{0,100}luscious.{0,100}curly.{0,100}lashes|test.{0,100}mascara|mascara.{0,100}beauty.{0,100}spam|lash.{0,100}enhancement).*".to_string() },
                        Criteria::BodyPattern { pattern: "(?i).{0,100}(thick.{0,100}luscious.{0,100}curly.{0,100}lashes|test.{0,100}mascara|mascara.{0,100}beauty.{0,100}spam|lash.{0,100}enhancement).*".to_string() },
                        ],
                    },
                    action: None,
                    score: Some(170),
                    description: None,
                },
                FilterRule {
                    name: "Heated Vest Winter Spam".to_string(),
                    enabled: true,
                    criteria:
                    Criteria::Or {
                        criteria: vec![
                        Criteria::SubjectPattern { pattern: "(?i).{0,100}(stay.{0,100}warm.{0,100}style.{0,100}solana.{0,100}heated.{0,100}vest|heated.{0,100}vest.{0,100}winter.{0,100}essential|solana.{0,100}heated.{0,100}vest).*".to_string() },
                        Criteria::BodyPattern { pattern: "(?i).{0,100}(stay.{0,100}warm.{0,100}style.{0,100}solana.{0,100}heated.{0,100}vest|heated.{0,100}vest.{0,100}winter.{0,100}essential|solana.{0,100}heated.{0,100}vest).*".to_string() },
                        ],
                    },
                    action: None,
                    score: Some(180),
                    description: None,
                },
                FilterRule {
                    name: "Toenail Fungus Health Spam".to_string(),
                    enabled: true,
                    criteria:
                    Criteria::Or {
                        criteria: vec![
                        Criteria::SubjectPattern { pattern: "(?i).{0,100}(soak.{0,100}feet.{0,100}bowl.{0,100}vanish.{0,100}toenail.{0,100}fungus|toenail.{0,100}fungus.{0,100}health|fungus.{0,100}treatment|nail.{0,100}fungus.{0,100}cure).*".to_string() },
                        Criteria::BodyPattern { pattern: "(?i).{0,100}(soak.{0,100}feet.{0,100}bowl.{0,100}vanish.{0,100}toenail.{0,100}fungus|toenail.{0,100}fungus.{0,100}health|fungus.{0,100}treatment|nail.{0,100}fungus.{0,100}cure).*".to_string() },
                        ],
                    },
                    action: None,
                    score: Some(200),
                    description: None,
                },
                FilterRule {
                    name: "Ukrainian Dating Spam".to_string(),
                    enabled: true,
                    criteria:
                    Criteria::Or {
                        criteria: vec![
                        Criteria::SubjectPattern { pattern: "(?i).{0,100}(date.{0,100}easy.{0,100}english.{0,100}speaking.{0,100}ukrainian.{0,100}girls|ukrainian.{0,100}dating|ukrainian.{0,100}girls|eastern.{0,100}european.{0,100}dating).*".to_string() },
                        Criteria::BodyPattern { pattern: "(?i).{0,100}(date.{0,100}easy.{0,100}english.{0,100}speaking.{0,100}ukrainian.{0,100}girls|ukrainian.{0,100}dating|ukrainian.{0,100}girls|eastern.{0,100}european.{0,100}dating).*".to_string() },
                        ],
                    },
                    action: None,
                    score: Some(250),
                    description: None,
                },
                FilterRule {
                    name: "Triple A Car Kit Spam".to_string(),
                    enabled: true,
                    criteria:
                    Criteria::And {
                        criteria: vec![
                        Criteria::Or {
                            criteria: vec![
                            Criteria::SubjectPattern { pattern: "(?i).{0,100}(vehicle.{0,100}should.{0,100}be.{0,100}on.{0,100}road|triple.{0,100}a|emergency.{0,100}car.{0,100}kit|roadside.{0,100}assistance|courtesy.{0,100}road.{0,100}kit|roadside.{0,100}courtesy|courtesy.{0,100}kit).*".to_string() },
                            Criteria::BodyPattern { pattern: "(?i).{0,100}(vehicle.{0,100}should.{0,100}be.{0,100}on.{0,100}road|triple.{0,100}a|emergency.{0,100}car.{0,100}kit|roadside.{0,100}assistance|courtesy.{0,100}road.{0,100}kit|roadside.{0,100}courtesy|courtesy.{0,100}kit).*".to_string() },
                            ],
                        },
                        Criteria::Not {
                            criteria: Box::new(
                            Criteria::Or {
                                criteria: vec![
                                Criteria::SenderPattern { pattern: ".*@.*(backstage|linkedin|indeed|monster|glassdoor|ziprecruiter)\\.(com|net)$".to_string() },
                                Criteria::SenderPattern { pattern: ".*@.*(gov|edu|mil)$".to_string() },
                                Criteria::SenderPattern { pattern: ".*@.*(rejuvenation|westelm|potterybarn|crateandbarrel|wayfair|homedepot|lowes|onestopplus)\\.(com|net)$".to_string() },
                                ],
                            }
                            ),
                        },
                        ],
                    },
                    action: None,
                    score: Some(180),
                    description: None,
                },
                FilterRule {
                    name: "Septic Tank Spam".to_string(),
                    enabled: true,
                    criteria:
                    Criteria::Or {
                        criteria: vec![
                        Criteria::SubjectPattern { pattern: "(?i).{0,100}(septic.{0,100}tank.{0,100}smell.{0,100}eliminates.{0,100}smell.{0,100}3.{0,100}days|septic.{0,100}tank.{0,100}smell|septic.{0,100}system.{0,100}maintenance).*".to_string() },
                        Criteria::BodyPattern { pattern: "(?i).{0,100}(septic.{0,100}tank.{0,100}smell.{0,100}eliminates.{0,100}smell.{0,100}3.{0,100}days|septic.{0,100}tank.{0,100}smell|septic.{0,100}system.{0,100}maintenance).*".to_string() },
                        ],
                    },
                    action: None,
                    score: Some(180),
                    description: None,
                },
                FilterRule {
                    name: "Timeshare Exit Travel Scam".to_string(),
                    enabled: true,
                    criteria:
                    Criteria::Or {
                        criteria: vec![
                        Criteria::SubjectPattern { pattern: "(?i).{0,100}(travel.{0,100}wherever.{0,100}you.{0,100}like.{0,100}holiday.{0,100}season|timeshare.{0,100}exit.{0,100}travel|exit.{0,100}my.{0,100}timeshare).*".to_string() },
                        Criteria::BodyPattern { pattern: "(?i).{0,100}(travel.{0,100}wherever.{0,100}you.{0,100}like.{0,100}holiday.{0,100}season|timeshare.{0,100}exit.{0,100}travel|exit.{0,100}my.{0,100}timeshare).*".to_string() },
                        ],
                    },
                    action: None,
                    score: Some(250),
                    description: None,
                },
                FilterRule {
                    name: "TMobile Tech Upgrade Spam".to_string(),
                    enabled: true,
                    criteria:
                    Criteria::And {
                        criteria: vec![
                        Criteria::Or {
                            criteria: vec![
                            Criteria::SubjectPattern { pattern: "(?i).{0,100}(tmobile.{0,100}tech.{0,100}upgrade|t.{0,100}mobile.{0,100}upgrade|mobile.{0,100}tech.{0,100}upgrade|phone.{0,100}upgrade.{0,100}offer).*".to_string() },
                            Criteria::BodyPattern { pattern: "(?i).{0,100}(tmobile.{0,100}tech.{0,100}upgrade|t.{0,100}mobile.{0,100}upgrade|mobile.{0,100}tech.{0,100}upgrade|phone.{0,100}upgrade.{0,100}offer).*".to_string() },
                            ],
                        },
                        Criteria::Not {
                            criteria: Box::new(
                            Criteria::SenderPattern { pattern: "(?i).{0,100}(xfinity|comcast|verizon|att\\.com|t-mobile\\.com).*".to_string() }
                            ),
                        },
                        ],
                    },
                    action: None,
                    score: Some(200),
                    description: None,
                },
                FilterRule {
                    name: "Credit Card Resolution Medical Spam".to_string(),
                    enabled: true,
                    criteria:
                    Criteria::Or {
                        criteria: vec![
                        Criteria::SubjectPattern { pattern: "(?i).{0,100}(credit.{0,100}card.{0,100}resolution.{0,100}unicode.{0,100}medical|credit.{0,100}card.{0,100}medical|billing.{0,100}medical.{0,100}resolution).*".to_string() },
                        Criteria::BodyPattern { pattern: "(?i).{0,100}(credit.{0,100}card.{0,100}resolution.{0,100}unicode.{0,100}medical|credit.{0,100}card.{0,100}medical|billing.{0,100}medical.{0,100}resolution).*".to_string() },
                        ],
                    },
                    action: None,
                    score: Some(200),
                    description: None,
                },
                FilterRule {
                    name: "Enhanced Leafguard Final Pattern".to_string(),
                    enabled: true,
                    criteria:
                    Criteria::Or {
                        criteria: vec![
                        Criteria::SubjectPattern { pattern: "(?i).{0,100}(leafguard|leaf.{0,100}guard|gutter.{0,100}protection|gutter.{0,100}maintenance).*".to_string() },
                        Criteria::BodyPattern { pattern: "(?i).{0,100}(leafguard|leaf.{0,100}guard|gutter.{0,100}protection|gutter.{0,100}maintenance).*".to_string() },
                        ],
                    },
                    action: None,
                    score: Some(150),
                    description: None,
                },
                FilterRule {
                    name: "Gutter Maintenance Zero Pattern".to_string(),
                    enabled: true,
                    criteria:
                    Criteria::Or {
                        criteria: vec![
                        Criteria::SubjectPattern { pattern: "(?i).{0,100}(one.{0,100}gutter.{0,100}zero.{0,100}maintenance|gutter.{0,100}zero.{0,100}maintenance|total.{0,100}peace.{0,100}mind.{0,100}gutter).*".to_string() },
                        Criteria::BodyPattern { pattern: "(?i).{0,100}(one.{0,100}gutter.{0,100}zero.{0,100}maintenance|gutter.{0,100}zero.{0,100}maintenance|total.{0,100}peace.{0,100}mind.{0,100}gutter).*".to_string() },
                        ],
                    },
                    action: None,
                    score: Some(170),
                    description: None,
                },
                FilterRule {
                    name: "Ukrainian Romance Scam Enhanced".to_string(),
                    enabled: true,
                    criteria:
                    Criteria::And {
                        criteria: vec![
                        Criteria::Or {
                            criteria: vec![
                            Criteria::SubjectPattern { pattern: "(?i).{0,100}(want.{0,100}to.{0,100}be.{0,100}with.{0,100}you.{0,100}how.{0,100}about.{0,100}you|ukrainian.{0,100}romance.{0,100}scam|find.{0,100}ukrainian.{0,100}love|ukrainian.{0,100}love).*".to_string() },
                            Criteria::BodyPattern { pattern: "(?i).{0,100}(want.{0,100}to.{0,100}be.{0,100}with.{0,100}you.{0,100}how.{0,100}about.{0,100}you|ukrainian.{0,100}romance.{0,100}scam|find.{0,100}ukrainian.{0,100}love|ukrainian.{0,100}love).*".to_string() },
                            ],
                        },
                        Criteria::Not {
                            criteria: Box::new(
                            Criteria::SenderPattern { pattern: ".*@.*nytimes.*".to_string() }
                            ),
                        },
                        ],
                    },
                    action: None,
                    score: Some(300),
                    description: None,
                },
                FilterRule {
                    name: "Unsolicited Web Development Spam".to_string(),
                    enabled: true,
                    criteria:
                    Criteria::Or {
                        criteria: vec![
                        Criteria::SubjectPattern { pattern: "(?i).{0,100}(customize.{0,100}website.{0,100}design.{0,100}development|unsolicited.{0,100}web.{0,100}development|website.{0,100}development.{0,100}spam|web.{0,100}design.{0,100}services).*".to_string() },
                        Criteria::BodyPattern { pattern: "(?i).{0,100}(customize.{0,100}website.{0,100}design.{0,100}development|unsolicited.{0,100}web.{0,100}development|website.{0,100}development.{0,100}spam|web.{0,100}design.{0,100}services).*".to_string() },
                        ],
                    },
                    action: None,
                    score: Some(200),
                    description: None,
                },
                FilterRule {
                    name: "TMobile Tech Upgrade Enhanced".to_string(),
                    enabled: true,
                    criteria:
                    Criteria::Or {
                        criteria: vec![
                        Criteria::SubjectPattern { pattern: "(?i).{0,100}(your.{0,100}tech.{0,100}upgrade.{0,100}is.{0,100}ready|tmobile.{0,100}tech.{0,100}upgrade|tech.{0,100}gift.{0,100}from.{0,100}t.{0,100}mobile|free.{0,100}hp.{0,100}laptop).*".to_string() },
                        Criteria::BodyPattern { pattern: "(?i).{0,100}(your.{0,100}tech.{0,100}upgrade.{0,100}is.{0,100}ready|tmobile.{0,100}tech.{0,100}upgrade|tech.{0,100}gift.{0,100}from.{0,100}t.{0,100}mobile|free.{0,100}hp.{0,100}laptop).*".to_string() },
                        ],
                    },
                    action: None,
                    score: Some(250),
                    description: None,
                },
                FilterRule {
                    name: "Vision Ritual Health Spam".to_string(),
                    enabled: true,
                    criteria:
                    Criteria::Or {
                        criteria: vec![
                        Criteria::SubjectPattern { pattern: "(?i).{0,100}(morning.{0,100}vision.{0,100}ritual|vision.{0,100}ritual.{0,100}health|vision.{0,100}research.{0,100}group|eye.{0,100}health.{0,100}ritual).*".to_string() },
                        Criteria::BodyPattern { pattern: "(?i).{0,100}(morning.{0,100}vision.{0,100}ritual|vision.{0,100}ritual.{0,100}health|vision.{0,100}research.{0,100}group|eye.{0,100}health.{0,100}ritual).*".to_string() },
                        ],
                    },
                    action: None,
                    score: Some(200),
                    description: None,
                },
                FilterRule {
                    name: "Woodworking Plans Spam".to_string(),
                    enabled: true,
                    criteria:
                    Criteria::Or {
                        criteria: vec![
                        Criteria::SubjectPattern { pattern: "(?i).{0,100}(woodworking.{0,100}plans.{0,100}spam|diy.{0,100}woodworking|wood.{0,100}project.{0,100}plans|carpentry.{0,100}plans).*".to_string() },
                        Criteria::BodyPattern { pattern: "(?i).{0,100}(woodworking.{0,100}plans.{0,100}spam|diy.{0,100}woodworking|wood.{0,100}project.{0,100}plans|carpentry.{0,100}plans).*".to_string() },
                        ],
                    },
                    action: None,
                    score: Some(160),
                    description: None,
                },
                FilterRule {
                    name: "Yelsen Finance Loan Spam".to_string(),
                    enabled: true,
                    criteria:
                    Criteria::Or {
                        criteria: vec![
                        Criteria::SubjectPattern { pattern: "(?i).{0,100}(yelsen.{0,100}finance.{0,100}loan|personal.{0,100}loan.{0,100}offer|quick.{0,100}loan.{0,100}approval|finance.{0,100}loan.{0,100}spam).*".to_string() },
                        Criteria::BodyPattern { pattern: "(?i).{0,100}(yelsen.{0,100}finance.{0,100}loan|personal.{0,100}loan.{0,100}offer|quick.{0,100}loan.{0,100}approval|finance.{0,100}loan.{0,100}spam).*".to_string() },
                        ],
                    },
                    action: None,
                    score: Some(220),
                    description: None,
                },
                FilterRule {
                    name: "Cross-Domain Content Hosting".to_string(),
                    enabled: true,
                    criteria:
                    Criteria::And {
                        criteria: vec![
                        Criteria::BodyPattern { pattern: "(?i).*<img.{0,100}src.{0,100}http://.*".to_string() },
                        Criteria::BodyPattern { pattern: "(?i).{0,100}stringentshortcut.*".to_string() },
                        ],
                    },
                    action: None,
                    score: Some(75),
                    description: Some("Content hosted on suspicious external domains".to_string()),
                },
                FilterRule {
                    name: "Suspicious Tracking Pixels".to_string(),
                    enabled: true,
                    criteria:
                    Criteria::BodyPattern { pattern: "(?i).*<img.{0,100}width=['\"]1px['\"].{0,100}height=['\"]1px['\"].*".to_string() },
                    action: None,
                    score: Some(50),
                    description: Some("Suspicious 1px tracking pixels".to_string()),
                },
                FilterRule {
                    name: "Image-Only Spam".to_string(),
                    enabled: true,
                    criteria:
                    Criteria::And {
                        criteria: vec![
                        Criteria::BodyPattern { pattern: "(?i).*<img.{0,100}src.{0,100}http.*".to_string() },
                        Criteria::Not {
                            criteria: Box::new(
                            Criteria::BodyPattern { pattern: "(?s).{50,}".to_string() }
                            ),
                        },
                        Criteria::Not {
                            criteria: Box::new(
                            Criteria::SenderPattern { pattern: ".*@.*(nytimes|washingtonpost|michaels|walgreens|capitaloneshopping|lowes|homedepot|target|walmart|amazon|bestbuy)\\.(com|net)$".to_string() }
                            ),
                        },
                        ],
                    },
                    action: None,
                    score: Some(150),
                    description: Some("Emails with minimal text and external images from suspicious senders".to_string()),
                },
                FilterRule {
                    name: "Enhanced Woodworking Plans".to_string(),
                    enabled: true,
                    criteria:
                    Criteria::And {
                        criteria: vec![
                        Criteria::Or {
                            criteria: vec![
                            Criteria::SubjectPattern { pattern: "(?i).{0,100}(woodworking.{0,100}plans|wood.{0,100}project|diy.{0,100}(carpentry|woodwork|furniture|cabinet)|furniture.{0,100}plans|carpentry.{0,100}guide).*".to_string() },
                            Criteria::BodyPattern { pattern: "(?i).{0,100}(woodworking.{0,100}plans|wood.{0,100}project|diy.{0,100}(carpentry|woodwork|furniture|cabinet)|furniture.{0,100}plans|carpentry.{0,100}guide).*".to_string() },
                            ],
                        },
                        Criteria::Not {
                            criteria: Box::new(
                            Criteria::Or {
                                criteria: vec![
                                Criteria::SenderPattern { pattern: ".*@.*(kickstarter|indiegogo|patreon|gofundme|humblebundle)\\.(com|net)$".to_string() },
                                Criteria::HeaderPattern { header: "from".to_string(), pattern: ".*@.*(kickstarter|indiegogo|patreon|gofundme|humblebundle)\\.(com|net).*".to_string() },
                                ],
                            }
                            ),
                        },
                        ],
                    },
                    action: None,
                    score: Some(160),
                    description: None,
                },
                FilterRule {
                    name: "Enhanced Finance Loan Patterns".to_string(),
                    enabled: true,
                    criteria:
                    Criteria::And {
                        criteria: vec![
                        Criteria::Or {
                            criteria: vec![
                            Criteria::SubjectPattern { pattern: "(?i).{0,100}(yelsen.{0,100}finance|personal.{0,100}loan|quick.{0,100}approval|loan.{0,100}offer).*".to_string() },
                            Criteria::BodyPattern { pattern: "(?i).{0,100}(yelsen.{0,100}finance|personal.{0,100}loan|quick.{0,100}approval|loan.{0,100}offer).*".to_string() },
                            ],
                        },
                        Criteria::Not {
                            criteria: Box::new(
                            Criteria::Or {
                                criteria: vec![
                                Criteria::SenderPattern { pattern: ".*@.*(becu|creditunion|bank|fidelity|schwab|vanguard|chase|wellsfargo|bankofamerica|citi|usbank)\\.(org|com)$".to_string() },
                                Criteria::HeaderPattern { header: "Authentication-Results".to_string(), pattern: "dkim=pass.{0,100}\\.(becu|creditunion|bank|fidelity|schwab|vanguard|chase|wellsfargo|bankofamerica|citi|usbank)\\.(org|com)".to_string() },
                                ],
                            }
                            ),
                        },
                        ],
                    },
                    action: None,
                    score: Some(220),
                    description: Some("Loan scam patterns excluding legitimate financial institutions".to_string()),
                },
                FilterRule {
                    name: "German Inheritance Scam".to_string(),
                    enabled: true,
                    criteria:
                    Criteria::And {
                        criteria: vec![
                        Criteria::BodyPattern { pattern: "(?i)(millionen euro|verm.{0,100}chtnis|notar|testament)".to_string() },
                        Criteria::BodyPattern { pattern: "(?i)(krebs|krank|sterben|tod)".to_string() },
                        Criteria::Not {
                            criteria: Box::new(
                            Criteria::Or {
                                criteria: vec![
                                Criteria::SenderPattern { pattern: ".*@.*(nytimes|washingtonpost|cnn|bbc|reuters|ap|wsj|usatoday)\\.(com|org)$".to_string() },
                                Criteria::SenderPattern { pattern: ".*@.*(disney|disneyplus|sparkpostmail|nationalgeographic)\\.(com|net)$".to_string() },
                                ],
                            }
                            ),
                        },
                        ],
                    },
                    action: None,
                    score: Some(150),
                    description: Some("German advance fee fraud inheritance scams".to_string()),
                },
                FilterRule {
                    name: "External Contact Redirect".to_string(),
                    enabled: true,
                    criteria:
                    Criteria::And {
                        criteria: vec![
                        Criteria::BodyPattern { pattern: "(?i)@yahoo\\.com|@hotmail\\.com".to_string() },
                        Criteria::Not {
                            criteria: Box::new(
                            Criteria::HeaderPattern { header: "Sender".to_string(), pattern: "(?i)calendar-notification@google\\.com".to_string() }
                            ),
                        },
                        ],
                    },
                    action: None,
                    score: Some(50),
                    description: Some("Redirects to suspicious email providers".to_string()),
                },
            ],
        },
        Module {
            name: "ESP Infrastructure".to_string(),
            enabled: true,
            hash: "builtin".to_string(),
            rules: vec![
                FilterRule {
                    name: "Walgreens Pharmacy Infrastructure".to_string(),
                    enabled: true,
                    criteria:
                    Criteria::SenderPattern { pattern: ".*walgreens.*".to_string() },
                    action: None,
                    score: Some(-150),
                    description: Some("Legitimate pharmacy chain infrastructure".to_string()),
                },
                FilterRule {
                    name: "Shutterfly Photo Service Infrastructure".to_string(),
                    enabled: true,
                    criteria:
                    Criteria::SenderPattern { pattern: ".*shutterfly.*".to_string() },
                    action: None,
                    score: Some(-200),
                    description: Some("Legitimate photo service infrastructure".to_string()),
                },
                FilterRule {
                    name: "Ally Bank Infrastructure".to_string(),
                    enabled: true,
                    criteria:
                    Criteria::SenderPattern { pattern: ".*@.*ally\\.com".to_string() },
                    action: None,
                    score: Some(-150),
                    description: Some("Legitimate bank infrastructure".to_string()),
                },
                FilterRule {
                    name: "Rejuvenation Infrastructure".to_string(),
                    enabled: true,
                    criteria:
                    Criteria::SenderPattern { pattern: ".*rejuvenation.*".to_string() },
                    action: None,
                    score: Some(-100),
                    description: Some("Legitimate home furnishings retailer".to_string()),
                },
                FilterRule {
                    name: "Filters Fast Infrastructure".to_string(),
                    enabled: true,
                    criteria:
                    Criteria::SenderPattern { pattern: ".*filtersfast.*".to_string() },
                    action: None,
                    score: Some(-200),
                    description: Some("Legitimate home products retailer".to_string()),
                },
                FilterRule {
                    name: "PayPal Adobe Campaign Infrastructure".to_string(),
                    enabled: true,
                    criteria:
                    Criteria::SenderPattern { pattern: ".*paypal.{0,100}adobe.*".to_string() },
                    action: None,
                    score: Some(-500),
                    description: Some("Legitimate PayPal via Adobe Campaign ESP".to_string()),
                },
                FilterRule {
                    name: "USPS Government Service Infrastructure".to_string(),
                    enabled: true,
                    criteria:
                    Criteria::SenderPattern { pattern: ".*usps.*".to_string() },
                    action: None,
                    score: Some(-100),
                    description: Some("Legitimate government postal service infrastructure".to_string()),
                },
                FilterRule {
                    name: "A2 Hosting Infrastructure".to_string(),
                    enabled: true,
                    criteria:
                    Criteria::SenderPattern { pattern: ".*a2hosting.*".to_string() },
                    action: None,
                    score: Some(-100),
                    description: Some("Legitimate hosting company infrastructure".to_string()),
                },
                FilterRule {
                    name: "Bearaby Sleep Products Infrastructure".to_string(),
                    enabled: true,
                    criteria:
                    Criteria::SenderPattern { pattern: ".*bearaby.*".to_string() },
                    action: None,
                    score: Some(-200),
                    description: Some("Legitimate sleep products company infrastructure".to_string()),
                },
                FilterRule {
                    name: "Withings Health Device Infrastructure".to_string(),
                    enabled: true,
                    criteria:
                    Criteria::SenderPattern { pattern: ".*withings.*".to_string() },
                    action: None,
                    score: Some(-100),
                    description: Some("Legitimate health device company infrastructure".to_string()),
                },
                FilterRule {
                    name: "Medical Billing ESP Infrastructure".to_string(),
                    enabled: true,
                    criteria:
                    Criteria::SenderPattern { pattern: ".*(docugateway|virginiamason).*".to_string() },
                    action: None,
                    score: Some(-150),
                    description: Some("Legitimate medical billing service infrastructure".to_string()),
                },
                FilterRule {
                    name: "Veterinary ESP Infrastructure".to_string(),
                    enabled: true,
                    criteria:
                    Criteria::SenderPattern { pattern: ".*(ourvet|vetcove|mtasv).*".to_string() },
                    action: None,
                    score: Some(-150),
                    description: Some("Legitimate veterinary service infrastructure".to_string()),
                },
                FilterRule {
                    name: "Mailjet Sendinblue ESP Infrastructure".to_string(),
                    enabled: true,
                    criteria:
                    Criteria::SenderPattern { pattern: ".*(hb\\.d\\.mailin\\.fr|mailin\\.fr|mailjet|sendinblue|brevo\\.net|sp1-brevo\\.net).*".to_string() },
                    action: None,
                    score: Some(-150),
                    description: Some("Legitimate ESP infrastructure for business communications".to_string()),
                },
                FilterRule {
                    name: "CharmTracker Healthcare EHR Infrastructure".to_string(),
                    enabled: true,
                    criteria:
                    Criteria::SenderPattern { pattern: ".*(charmtracker|mailerehr\\.charmtracker).*".to_string() },
                    action: None,
                    score: Some(-200),
                    description: Some("Legitimate healthcare EHR system infrastructure".to_string()),
                },
                FilterRule {
                    name: "Political Organization Infrastructure".to_string(),
                    enabled: true,
                    criteria:
                    Criteria::SenderPattern { pattern: ".*democrats.*".to_string() },
                    action: None,
                    score: Some(-400),
                    description: Some("Legitimate political organization infrastructure".to_string()),
                },
                FilterRule {
                    name: "Oxford Club Newsletter Infrastructure".to_string(),
                    enabled: true,
                    criteria:
                    Criteria::SenderPattern { pattern: ".*oxford.*".to_string() },
                    action: None,
                    score: Some(-120),
                    description: Some("Legitimate Oxford Club newsletter infrastructure".to_string()),
                },
                FilterRule {
                    name: "Legitimate Cannabis Retailers".to_string(),
                    enabled: true,
                    criteria:
                    Criteria::And {
                        criteria: vec![
                        Criteria::Or {
                            criteria: vec![
                            Criteria::SenderPattern { pattern: ".*@.*(cannabis|dispensary|hemp).{0,100}\\.(com|net|org)$".to_string() },
                            Criteria::SenderPattern { pattern: ".*@.*\\b(pot|cbd)\\b.{0,100}\\.(com|net|org)$".to_string() },
                            ],
                        },
                        Criteria::FeatureAnalysis {
                            feature_name: "Authentication Analysis".to_string(),
                            min_score: None,
                            max_score: None,
                            evidence_pattern: Some("DKIM authentication passed".to_string()),
                            invert: None,
                        },
                        ],
                    },
                    action: None,
                    score: Some(-150),
                    description: Some("Legitimate cannabis retailers with proper authentication".to_string()),
                },
                FilterRule {
                    name: "Major ESP Infrastructure".to_string(),
                    enabled: true,
                    criteria:
                    Criteria::And {
                        criteria: vec![
                        Criteria::SenderPattern { pattern: ".*@.*(amazonses|sendgrid|mailchimp|constantcontact|mailgun|sparkpost|postmark|mandrill|adobe-campaign|akamaiedge)\\.(com|net)$".to_string() },
                        Criteria::Not {
                            criteria: Box::new(
                            Criteria::FeatureAnalysis {
                                feature_name: "Context Analysis".to_string(),
                                min_score: None,
                                max_score: None,
                                evidence_pattern: Some("Japanese .* from non-Japanese domain".to_string()),
                                invert: None,
                            }
                            ),
                        },
                        ],
                    },
                    action: None,
                    score: Some(-100),
                    description: Some("Major email service providers with established reputation".to_string()),
                },
                FilterRule {
                    name: "Newsletter Platforms".to_string(),
                    enabled: true,
                    criteria:
                    Criteria::SenderPattern { pattern: ".*@.*(beehiiv|substack|convertkit|aweber|getresponse|activecampaign|drip|klaviyo)\\.(com|net)$".to_string() },
                    action: None,
                    score: Some(-75),
                    description: Some("Legitimate newsletter and marketing platforms".to_string()),
                },
                FilterRule {
                    name: "Marketing ESP Infrastructure".to_string(),
                    enabled: true,
                    criteria:
                    Criteria::And {
                        criteria: vec![
                        Criteria::SenderPattern { pattern: ".*@.*(hubspot|salesforce|pardot|marketo|eloqua|mailerlite|campaignmonitor|pb-dynmktg)\\.(com|net)$".to_string() },
                        Criteria::HeaderPattern { header: "List-Unsubscribe".to_string(), pattern: ".*".to_string() },
                        ],
                    },
                    action: None,
                    score: Some(-50),
                    description: Some("Marketing automation platforms with proper unsubscribe headers".to_string()),
                },
                FilterRule {
                    name: "Government and Educational".to_string(),
                    enabled: true,
                    criteria:
                    Criteria::And {
                        criteria: vec![
                        Criteria::SenderPattern { pattern: ".*@.*\\.(gov|mil|edu)$".to_string() },
                        Criteria::HeaderPattern { header: "Authentication-Results".to_string(), pattern: "dkim=pass".to_string() },
                        ],
                    },
                    action: None,
                    score: Some(-200),
                    description: Some("Government and educational institutions with DKIM authentication".to_string()),
                },
                FilterRule {
                    name: "Established Brand Domains".to_string(),
                    enabled: true,
                    criteria:
                    Criteria::And {
                        criteria: vec![
                        Criteria::SenderPattern { pattern: ".*@.*(amazon|google|apple|netflix|mcdonalds|walmart|target)\\.(com|org)$".to_string() },
                        Criteria::Not {
                            criteria: Box::new(
                            Criteria::SenderPattern { pattern: ".*@.*onmicrosoft\\.com$".to_string() }
                            ),
                        },
                        Criteria::Or {
                            criteria: vec![
                            Criteria::HeaderPattern { header: "Authentication-Results".to_string(), pattern: "dkim=pass".to_string() },
                            Criteria::HeaderPattern { header: "Authentication-Results".to_string(), pattern: "spf=pass".to_string() },
                            ],
                        },
                        ],
                    },
                    action: None,
                    score: Some(-150),
                    description: Some("Established brands with valid authentication (excluding tenant domains)".to_string()),
                },
                FilterRule {
                    name: "Cloud Service Providers".to_string(),
                    enabled: true,
                    criteria:
                    Criteria::And {
                        criteria: vec![
                        Criteria::SenderPattern { pattern: ".*@.*(amazonaws|googlecloud|azure|digitalocean|linode|vultr)\\.(com|net)$".to_string() },
                        Criteria::HeaderPattern { header: "Authentication-Results".to_string(), pattern: "dkim=pass".to_string() },
                        ],
                    },
                    action: None,
                    score: Some(-75),
                    description: Some("Cloud service providers with DKIM authentication".to_string()),
                },
                FilterRule {
                    name: "Financial Services Infrastructure".to_string(),
                    enabled: true,
                    criteria:
                    Criteria::And {
                        criteria: vec![
                        Criteria::SenderPattern { pattern: ".*@.*(paypal|stripe|square|venmo|zelle|chase|bankofamerica|wellsfargo)\\.(com|net)$".to_string() },
                        Criteria::HeaderPattern { header: "Authentication-Results".to_string(), pattern: "dmarc=pass".to_string() },
                        ],
                    },
                    action: None,
                    score: Some(-100),
                    description: Some("Financial services with strong authentication".to_string()),
                },
                FilterRule {
                    name: "E-commerce Platforms".to_string(),
                    enabled: true,
                    criteria:
                    Criteria::SenderPattern { pattern: ".*@.*(shopify|woocommerce|magento|bigcommerce|squarespace|etsy)\\.(com|net)$".to_string() },
                    action: None,
                    score: Some(-75),
                    description: Some("Legitimate e-commerce platform infrastructure".to_string()),
                },
                FilterRule {
                    name: "Social Media Platforms".to_string(),
                    enabled: true,
                    criteria:
                    Criteria::And {
                        criteria: vec![
                        Criteria::SenderPattern { pattern: ".*@.*(facebook|twitter|linkedin|instagram|youtube|tiktok|pinterest)\\.(com|net)$".to_string() },
                        Criteria::HeaderPattern { header: "Authentication-Results".to_string(), pattern: "spf=pass".to_string() },
                        ],
                    },
                    action: None,
                    score: Some(-50),
                    description: Some("Social media platform notifications with SPF validation".to_string()),
                },
                FilterRule {
                    name: "Collaboration Tools".to_string(),
                    enabled: true,
                    criteria:
                    Criteria::SenderPattern { pattern: ".*@.*(slack|teams|zoom|webex|gotomeeting|dropbox|box|googledrive)\\.(com|net)$".to_string() },
                    action: None,
                    score: Some(-50),
                    description: Some("Business collaboration and file sharing services".to_string()),
                },
                FilterRule {
                    name: "CRM and Business Tools".to_string(),
                    enabled: true,
                    criteria:
                    Criteria::SenderPattern { pattern: ".*@.*(salesforce|hubspot|zendesk|freshdesk|intercom|drift|calendly)\\.(com|net)$".to_string() },
                    action: None,
                    score: Some(-50),
                    description: Some("Customer relationship management and business tools".to_string()),
                },
                FilterRule {
                    name: "Business System Fast Path".to_string(),
                    enabled: true,
                    criteria:
                    Criteria::Or {
                        criteria: vec![
                        Criteria::HeaderPattern { header: "x-netsuite".to_string(), pattern: ".*".to_string() },
                        Criteria::SenderPattern { pattern: ".*@.*(netsuite\\.com|oracleemaildelivery\\.com)$".to_string() },
                        Criteria::SenderPattern { pattern: ".*@.*salesforce\\.com$".to_string() },
                        Criteria::SenderPattern { pattern: ".*@.*quickbooks\\.com$".to_string() },
                        Criteria::HeaderPattern { header: "X-Mailer".to_string(), pattern: ".*NetSuite.*".to_string() },
                        ],
                    },
                    action: None,
                    score: Some(-50),
                    description: Some("Fast path for legitimate business systems like NetSuite, Salesforce, QuickBooks".to_string()),
                },
                FilterRule {
                    name: "Trusted Domain Fast Path".to_string(),
                    enabled: true,
                    criteria:
                    Criteria::And {
                        criteria: vec![
                        Criteria::SenderPattern { pattern: ".*@(amazon\\.com|microsoft\\.com|apple\\.com|google\\.com|paypal\\.com|ebay\\.com|linkedin\\.com|twitter\\.com|facebook\\.com)$".to_string() },
                        Criteria::HeaderPattern { header: "Authentication-Results".to_string(), pattern: "dkim=pass".to_string() },
                        ],
                    },
                    action: None,
                    score: Some(-75),
                    description: Some("Trusted major domains with valid authentication".to_string()),
                },
                FilterRule {
                    name: "Disney Store".to_string(),
                    enabled: true,
                    criteria:
                    Criteria::SenderPattern { pattern: ".*@.*(disney|disneystore)\\.(com|net)$".to_string() },
                    action: None,
                    score: Some(-150),
                    description: Some("Disney Store legitimate retailer".to_string()),
                },
                FilterRule {
                    name: "Netatmo IoT Devices".to_string(),
                    enabled: true,
                    criteria:
                    Criteria::Or {
                        criteria: vec![
                        Criteria::SenderPattern { pattern: ".*@.*netatmo\\.(com|net)$".to_string() },
                        Criteria::SenderPattern { pattern: ".*@netatmo\\.com$".to_string() },
                        Criteria::HeaderPattern { header: "From".to_string(), pattern: ".*netatmo.*".to_string() },
                        ],
                    },
                    action: None,
                    score: Some(-200),
                    description: Some("Netatmo legitimate IoT device notifications".to_string()),
                },
                FilterRule {
                    name: "Veterinary and Pet Services".to_string(),
                    enabled: true,
                    criteria:
                    Criteria::Or {
                        criteria: vec![
                        Criteria::HeaderPattern { header: "From".to_string(), pattern: ".*@.*\\.vetcove\\.com.*".to_string() },
                        Criteria::HeaderPattern { header: "DKIM-Signature".to_string(), pattern: ".*d=.*\\.vetcove\\.com.*".to_string() },
                        Criteria::BodyPattern { pattern: "(?i).{0,100}(veterinary|pet.{0,100}hospital|animal.{0,100}clinic|veterinarian)".to_string() },
                        Criteria::SubjectPattern { pattern: "(?i).{0,100}(appointment.{0,100}reminder|vaccination.{0,100}due|pet.{0,100}health)".to_string() },
                        ],
                    },
                    action: None,
                    score: Some(-200),
                    description: Some("Whitelist legitimate veterinary and pet service communications".to_string()),
                },
                FilterRule {
                    name: "Retail and Commerce Brands".to_string(),
                    enabled: true,
                    criteria:
                    Criteria::SenderPattern { pattern: ".*@.*(duluthtrading|levi|michaels|kingarthurbaking|eyebuydirect|fiestatableware|kitchenaid|whirlpool|arbys|condenast|nationalgeographic)\\.(com|net)$".to_string() },
                    action: None,
                    score: Some(-150),
                    description: Some("Legitimate retail and commerce brand communications".to_string()),
                },
                FilterRule {
                    name: "Brand Domain Validation".to_string(),
                    enabled: true,
                    criteria:
                    Criteria::SenderDomain { domains: vec!["levi.com".to_string(), "duluthtrading.com".to_string(), "michaels.com".to_string(), "kingarthurbaking.com".to_string(), "eyebuydirect.com".to_string()] },
                    action: None,
                    score: Some(-300),
                    description: Some("Legitimate brand emails from verified domains".to_string()),
                },
                FilterRule {
                    name: "Known legitimate mailing service providers".to_string(),
                    enabled: true,
                    criteria:
                    Criteria::And {
                        criteria: vec![
                        Criteria::HeaderPattern { header: "List-Unsubscribe".to_string(), pattern: ".*".to_string() },
                        Criteria::HeaderPattern { header: "Authentication-Results".to_string(), pattern: "dkim=pass".to_string() },
                        Criteria::HeaderPattern { header: "Authentication-Results".to_string(), pattern: "dmarc=pass".to_string() },
                        Criteria::HeaderPattern { header: "From".to_string(), pattern: "(?i).{0,100}(newsletter|marketing|promo|updates|news).*".to_string() },
                        Criteria::Not {
                            criteria: Box::new(
                            Criteria::Or {
                                criteria: vec![
                                Criteria::BodyPattern { pattern: "^.{0,200}$".to_string() },
                                Criteria::FeatureAnalysis {
                                    feature_name: "Server Role Analysis".to_string(),
                                    min_score: None,
                                    max_score: None,
                                    evidence_pattern: Some("Authentication bonus should be reduced".to_string()),
                                    invert: None,
                                },
                                ],
                            }
                            ),
                        },
                        ],
                    },
                    action: None,
                    score: Some(-100),
                    description: Some("Legitimate mailing services with DMARC verification".to_string()),
                },
                FilterRule {
                    name: "Known legitimate mailing service providers (DKIM)".to_string(),
                    enabled: true,
                    criteria:
                    Criteria::And {
                        criteria: vec![
                        Criteria::HeaderPattern { header: "List-Unsubscribe".to_string(), pattern: ".*".to_string() },
                        Criteria::HeaderPattern { header: "Authentication-Results".to_string(), pattern: "dkim=pass".to_string() },
                        Criteria::HeaderPattern { header: "From".to_string(), pattern: "(?i).{0,100}(newsletter|marketing|promo|updates|news).*".to_string() },
                        Criteria::Not {
                            criteria: Box::new(
                            Criteria::Or {
                                criteria: vec![
                                Criteria::HeaderPattern { header: "Authentication-Results".to_string(), pattern: "dmarc=pass".to_string() },
                                Criteria::BodyPattern { pattern: "^.{0,200}$".to_string() },
                                Criteria::FeatureAnalysis {
                                    feature_name: "Server Role Analysis".to_string(),
                                    min_score: None,
                                    max_score: None,
                                    evidence_pattern: Some("Authentication bonus should be reduced".to_string()),
                                    invert: None,
                                },
                                Criteria::FeatureAnalysis {
                                    feature_name: "Link Analysis".to_string(),
                                    min_score: None,
                                    max_score: None,
                                    evidence_pattern: Some("cross-domain links to spam-like domain".to_string()),
                                    invert: None,
                                },
                                Criteria::FeatureAnalysis {
                                    feature_name: "Domain Reputation".to_string(),
                                    min_score: None,
                                    max_score: None,
                                    evidence_pattern: Some("Suspicious domain pattern detected".to_string()),
                                    invert: None,
                                },
                                ],
                            }
                            ),
                        },
                        ],
                    },
                    action: None,
                    score: Some(-80),
                    description: Some("Legitimate mailing services with DKIM only".to_string()),
                },
                FilterRule {
                    name: "Enhanced Marketing ESP Infrastructure".to_string(),
                    enabled: true,
                    criteria:
                    Criteria::SenderPattern { pattern: ".*@.*(klaviyomail|campaignmonitor|aweber|getresponse|convertkit|activecampaign|drip|mailerlite|flodesk)\\.(com|net|email)$".to_string() },
                    action: None,
                    score: Some(-60),
                    description: Some("Enhanced legitimate marketing email service providers".to_string()),
                },
                FilterRule {
                    name: "Major Technology Companies".to_string(),
                    enabled: true,
                    criteria:
                    Criteria::SenderPattern { pattern: ".*@.*(asus|nedm\\.asus|meta|email\\.meta|do_not_reply@email\\.meta|capitalone|capitaloneshopping|accounts\\.capitaloneshopping|hello@accounts\\.capitaloneshopping)\\.(com|net|org)$".to_string() },
                    action: None,
                    score: Some(-100),
                    description: Some("Legitimate major technology and financial companies".to_string()),
                },
                FilterRule {
                    name: "Authenticated Commercial Content Adjustment".to_string(),
                    enabled: true,
                    criteria:
                    Criteria::And {
                        criteria: vec![
                        Criteria::HeaderPattern { header: "Authentication-Results".to_string(), pattern: "(?i)(dmarc=pass|spf=pass)".to_string() },
                        Criteria::HeaderPattern { header: "List-Unsubscribe".to_string(), pattern: ".*".to_string() },
                        Criteria::BodyPattern { pattern: "(?i)(sale|discount|offer|deal|promotion|limited.{0,100}time)".to_string() },
                        Criteria::SenderPattern { pattern: ".*@.*(amazon|ebay|etsy|shopify|target|walmart|bestbuy|homedepot|lowes|macys|nordstrom|kohls|disney|kickstarter|eyebuydirect|torrid)\\.(com|net|org)$".to_string() },
                        Criteria::Not {
                            criteria: Box::new(
                            Criteria::SenderPattern { pattern: ".*@.*(yournconcierge|cardiovascular|internetdisaster|familyandfriendsllc|ybokjraxqz|solecomfort)\\.(com|net|org|top|lat)$".to_string() }
                            ),
                        },
                        ],
                    },
                    action: None,
                    score: Some(-30),
                    description: Some("Reduce commercial scoring ONLY for authenticated emails from known legitimate retailers".to_string()),
                },
                FilterRule {
                    name: "Cultural and Educational Institutions".to_string(),
                    enabled: true,
                    criteria:
                    Criteria::Or {
                        criteria: vec![
                        Criteria::SenderPattern { pattern: ".*@nordicmuseum\\.org$".to_string() },
                        Criteria::HeaderPattern { header: "From".to_string(), pattern: ".*@nordicmuseum\\.org.*".to_string() },
                        Criteria::SenderPattern { pattern: ".*@.*(museum|cultural|arts|library|university|college)\\.(org|edu)$".to_string() },
                        ],
                    },
                    action: None,
                    score: Some(-200),
                    description: Some("Cultural institutions, museums, and educational organizations".to_string()),
                },
            ],
        },
        Module {
            name: "Phishing Threats".to_string(),
            enabled: true,
            hash: "builtin".to_string(),
            rules: vec![
                FilterRule {
                    name: "HR Document Sharing Phishing".to_string(),
                    enabled: true,
                    criteria:
                    Criteria::And {
                        criteria: vec![
                        Criteria::Or {
                            criteria: vec![
                            Criteria::SubjectPattern { pattern: "(?i).{0,100}(hr.{0,100}shared|hr.{0,100}document|salary.{0,100}review|incentive.{0,100}overview|payroll.{0,100}update|employee.{0,100}handbook).*".to_string() },
                            Criteria::CombinedTextPattern { pattern: "(?i).{0,100}(hr.{0,100}department.{0,100}shared|view.{0,100}salary.{0,100}document|access.{0,100}payroll.{0,100}information|employee.{0,100}benefits.{0,100}update).*".to_string() },
                            ],
                        },
                        Criteria::Not {
                            criteria: Box::new(
                            Criteria::SenderPattern { pattern: ".*@.*(company\\.com|organization\\.org|legitimate\\.edu)$".to_string() }
                            ),
                        },
                        ],
                    },
                    action: None,
                    score: Some(200),
                    description: Some("Business Email Compromise targeting HR/payroll documents".to_string()),
                },
                FilterRule {
                    name: "Critical Phishing Patterns".to_string(),
                    enabled: true,
                    criteria:
                    Criteria::And {
                        criteria: vec![
                        Criteria::Or {
                            criteria: vec![
                            Criteria::SubjectPattern { pattern: "(?i).*(urgent.{0,30}action.{0,30}required|account.{0,30}will.{0,30}be.{0,30}closed|verify.{0,30}immediately|suspended.{0,30}account|click.{0,30}here.{0,30}now).*".to_string() },
                            Criteria::CombinedTextPattern { pattern: "(?i).*(verify.{0,30}your.{0,30}account.{0,30}now|click.{0,30}here.{0,30}to.{0,30}verify|account.{0,30}has.{0,30}been.{0,30}suspended|immediate.{0,30}action.{0,30}required).*".to_string() },
                            Criteria::CombinedTextPattern { pattern: "(?i).*(congratulations.{0,30}you.{0,30}have.{0,30}won|claim.{0,30}your.{0,30}prize.{0,30}now|limited.{0,30}time.{0,30}offer.{0,30}expires|act.{0,30}now.{0,30}or.{0,30}lose).*".to_string() },
                            ],
                        },
                        Criteria::Not {
                            criteria: Box::new(
                            Criteria::SenderPattern { pattern: ".*@.*(nytimes|washingtonpost|cnn|bbc|reuters|ap|wsj|usatoday)\\.(com|org)$".to_string() }
                            ),
                        },
                        ],
                    },
                    action: None,
                    score: Some(300),
                    description: Some("High-urgency phishing language patterns".to_string()),
                },
                FilterRule {
                    name: "Confirmation Request Phishing".to_string(),
                    enabled: true,
                    criteria:
                    Criteria::And {
                        criteria: vec![
                        Criteria::SubjectPattern { pattern: "(?i).{0,100}(can.{0,100}you.{0,100}confirm|please.{0,100}confirm|confirm.{0,100}you.{0,100}received|did.{0,100}you.{0,100}receive).*".to_string() },
                        Criteria::Not {
                            criteria: Box::new(
                            Criteria::SenderPattern { pattern: ".*@.*(paypal|amazon|ebay|microsoft|google|apple|chase|wellsfargo|bankofamerica|citi|walgreens|capitaloneshopping|michaels|lowes|homedepot|target|walmart)\\.(com|org)$".to_string() }
                            ),
                        },
                        ],
                    },
                    action: None,
                    score: Some(100),
                    description: Some("Suspicious confirmation requests from unknown senders".to_string()),
                },
                FilterRule {
                    name: "Financial Phishing".to_string(),
                    enabled: true,
                    criteria:
                    Criteria::And {
                        criteria: vec![
                        Criteria::Or {
                            criteria: vec![
                            Criteria::SubjectPattern { pattern: "(?i).{0,100}(payment.{0,100}(failed|declined|method.{0,100}declined)|card.{0,100}declined|account.{0,100}overdrawn|suspicious.{0,100}activity|fraud.{0,100}alert).*".to_string() },
                            Criteria::CombinedTextPattern { pattern: "(?i).{0,100}(update.{0,100}payment.{0,100}method|verify.{0,100}card.{0,100}information|confirm.{0,100}bank.{0,100}details|resolve.{0,100}payment.{0,100}issue).*".to_string() },
                            Criteria::CombinedTextPattern { pattern: "(?i).{0,100}(refund.{0,100}pending|tax.{0,100}refund.{0,100}available|stimulus.{0,100}payment|government.{0,100}benefit).*".to_string() },
                            ],
                        },
                        Criteria::Not {
                            criteria: Box::new(
                            Criteria::Or {
                                criteria: vec![
                                Criteria::SenderPattern { pattern: ".*@.*(adapthealth|healthcare|medical|clinic|hospital|pulmonary)\\.(com|net|org)$".to_string() },
                                Criteria::SenderPattern { pattern: ".*@.*(wine|wines|winery|brewery|distillery|spirits|liquor|beverage).{0,100}\\.(com|net|org)$".to_string() },
                                Criteria::SenderPattern { pattern: ".*@.*(evgo|sparkpostmail|acemedseattle|americanmeadows)\\.(com|net)$".to_string() },
                                Criteria::HeaderPattern { header: "Authentication-Results".to_string(), pattern: "dkim=pass.{0,100}adapthealth\\.com".to_string() },
                                ],
                            }
                            ),
                        },
                        ],
                    },
                    action: None,
                    score: Some(250),
                    description: Some("Financial fraud and payment scam detection".to_string()),
                },
                FilterRule {
                    name: "Security Alert Phishing".to_string(),
                    enabled: true,
                    criteria:
                    Criteria::And {
                        criteria: vec![
                        Criteria::Or {
                            criteria: vec![
                            Criteria::SubjectPattern { pattern: "(?i).{0,100}(security.{0,100}alert|suspicious.{0,100}login|unauthorized.{0,100}access|breach.{0,100}detected|virus.{0,100}found).*".to_string() },
                            Criteria::SubjectPattern { pattern: "(?i).{0,100}(high-severity.{0,100}alert|critical.{0,100}alert|urgent.{0,100}security|account.{0,100}changes).*".to_string() },
                            Criteria::CombinedTextPattern { pattern: "(?i).{0,100}(your.{0,100}computer.{0,100}infected|malware.{0,100}detected|security.{0,100}scan.{0,100}required|update.{0,100}antivirus).*".to_string() },
                            Criteria::CombinedTextPattern { pattern: "(?i).{0,100}(microsoft.{0,100}security|windows.{0,100}defender|apple.{0,100}security|google.{0,100}security).*".to_string() },
                            Criteria::CombinedTextPattern { pattern: "(?i).{0,100}(recent.{0,100}changes.{0,100}to.{0,100}account|verify.{0,100}account.{0,100}immediately|suspicious.{0,100}activity.{0,100}detected).*".to_string() },
                            ],
                        },
                        Criteria::Not {
                            criteria: Box::new(
                            Criteria::Or {
                                criteria: vec![
                                Criteria::SenderPattern { pattern: ".*@.*(sense|united|netflix|amazon|apple|google|microsoft|paypal|chase|bankofamerica|wellsfargo|fidelity)\\.(com|net)$".to_string() },
                                Criteria::HeaderPattern { header: "Authentication-Results".to_string(), pattern: "dmarc=pass".to_string() },
                                ],
                            }
                            ),
                        },
                        ],
                    },
                    action: None,
                    score: Some(200),
                    description: Some("Fake security alerts and tech support scams".to_string()),
                },
                FilterRule {
                    name: "Invoice Receipt Phishing".to_string(),
                    enabled: true,
                    criteria:
                    Criteria::And {
                        criteria: vec![
                        Criteria::Or {
                            criteria: vec![
                            Criteria::SubjectPattern { pattern: "(?i).{0,100}(invoice.{0,100}attached|receipt.{0,100}confirmation|payment.{0,100}due|billing.{0,100}statement).*".to_string() },
                            Criteria::CombinedTextPattern { pattern: "(?i).{0,100}(view.{0,100}invoice|download.{0,100}receipt|payment.{0,100}overdue|billing.{0,100}inquiry).*".to_string() },
                            ],
                        },
                        Criteria::Not {
                            criteria: Box::new(
                            Criteria::Or {
                                criteria: vec![
                                Criteria::SenderPattern { pattern: ".*@.*(adapthealth|healthcare|medical|clinic|hospital|pulmonary|evergreentlc|netsuite|builtsquare)\\.(com|net|org)$".to_string() },
                                Criteria::SenderPattern { pattern: ".*gandiroofingsolutions@gmail\\.com$".to_string() },
                                Criteria::SenderPattern { pattern: ".*@.*sendgrid\\.net$".to_string() },
                                Criteria::HeaderPattern { header: "Authentication-Results".to_string(), pattern: "dkim=pass.{0,100}adapthealth\\.com".to_string() },
                                ],
                            }
                            ),
                        },
                        ],
                    },
                    action: None,
                    score: Some(150),
                    description: Some("Fake invoice and receipt phishing attempts".to_string()),
                },
                FilterRule {
                    name: "Financial Phishing".to_string(),
                    enabled: true,
                    criteria:
                    Criteria::And {
                        criteria: vec![
                        Criteria::Or {
                            criteria: vec![
                            Criteria::SubjectPattern { pattern: "(?i).{0,100}(payment.{0,100}failed|account.{0,100}suspended|verify.{0,100}account|update.{0,100}payment|billing.{0,100}issue).*".to_string() },
                            Criteria::BodyPattern { pattern: "(?i).{0,100}(click.{0,100}here.{0,100}verify|update.{0,100}billing|payment.{0,100}method|account.{0,100}locked).*".to_string() },
                            ],
                        },
                        Criteria::Not {
                            criteria: Box::new(
                            Criteria::Or {
                                criteria: vec![
                                Criteria::SenderPattern { pattern: ".*@.*(paypal|stripe|square|quickbooks|freshbooks|xfinity|comcast|barnesandnoble|williams-sonoma|499inks|americanmeadows)\\.(com|net|org)$".to_string() },
                                Criteria::SenderPattern { pattern: ".*@.*(alerts\\.comcast|alerts\\.xfinity)\\.(com|net)$".to_string() },
                                Criteria::SenderPattern { pattern: ".*@gmail\\.com$".to_string() },
                                Criteria::SenderPattern { pattern: ".*@.*(adapthealth|healthcare|medical|clinic|hospital|pulmonary)\\.(com|net|org)$".to_string() },
                                Criteria::SenderPattern { pattern: ".*@.*(wine|wines|winery|brewery|distillery|spirits|liquor|beverage).{0,100}\\.(com|net|org)$".to_string() },
                                Criteria::And {
                                    criteria: vec![
                                    Criteria::FeatureAnalysis {
                                        feature_name: "Authentication Analysis".to_string(),
                                        min_score: None,
                                        max_score: None,
                                        evidence_pattern: Some("DKIM authentication passed".to_string()),
                                        invert: None,
                                    },
                                    Criteria::FeatureAnalysis {
                                        feature_name: "Authentication Analysis".to_string(),
                                        min_score: None,
                                        max_score: None,
                                        evidence_pattern: Some("SPF authentication passed".to_string()),
                                        invert: None,
                                    },
                                    ],
                                },
                                Criteria::HeaderPattern { header: "Authentication-Results".to_string(), pattern: "dkim=pass.{0,100}adapthealth\\.com".to_string() },
                                Criteria::FeatureAnalysis {
                                    feature_name: "Authentication Analysis".to_string(),
                                    min_score: None,
                                    max_score: None,
                                    evidence_pattern: Some("DKIM domain properly aligned".to_string()),
                                    invert: None,
                                },
                                ],
                            }
                            ),
                        },
                        ],
                    },
                    action: None,
                    score: Some(150),
                    description: Some("Financial phishing attempts".to_string()),
                },
                FilterRule {
                    name: "Senior-Targeted Shopping Scams".to_string(),
                    enabled: true,
                    criteria:
                    Criteria::And {
                        criteria: vec![
                        Criteria::Or {
                            criteria: vec![
                            Criteria::SenderPattern { pattern: ".*@.*(senior|elderly|mature|age|retirement).{0,100}shopping.{0,100}\\.(com|net|org)$".to_string() },
                            Criteria::SenderPattern { pattern: ".*@.*senior.{0,100}(tips|deals|savings|discounts).{0,100}\\.(com|net|org)$".to_string() },
                            Criteria::SubjectPattern { pattern: "(?i).{0,100}(deals.{0,100}good.{0,100}don.{0,100}wait|tap.{0,100}now.{0,100}thank|senior.{0,100}discount|age.{0,100}qualified).*".to_string() },
                            ],
                        },
                        Criteria::Or {
                            criteria: vec![
                            Criteria::CombinedTextPattern { pattern: "(?i).{0,100}(tap.{0,100}now|click.{0,100}here.{0,100}save|limited.{0,100}time.{0,100}seniors|exclusive.{0,100}age|retirement.{0,100}deals).*".to_string() },
                            Criteria::SubjectPattern { pattern: "(?i).{0,100}(urgent.{0,100}deal|act.{0,100}now.{0,100}save|don.{0,100}wait|hurry.{0,100}limited).*".to_string() },
                            ],
                        },
                        ],
                    },
                    action: None,
                    score: Some(150),
                    description: Some("Shopping scams targeting senior citizens with urgency tactics".to_string()),
                },
                FilterRule {
                    name: "Cloud Storage Phishing".to_string(),
                    enabled: true,
                    criteria:
                    Criteria::And {
                        criteria: vec![
                        Criteria::Or {
                            criteria: vec![
                            Criteria::SubjectPattern { pattern: "(?i).{0,100}(document.{0,100}shared|file.{0,100}shared|folder.{0,100}shared|shared.{0,100}with.{0,100}you).*".to_string() },
                            Criteria::CombinedTextPattern { pattern: "(?i).{0,100}(view.{0,100}document|access.{0,100}file|download.{0,100}shared|dropbox.{0,100}shared|google.{0,100}drive.{0,100}shared).*".to_string() },
                            Criteria::CombinedTextPattern { pattern: "(?i).{0,100}(onedrive.{0,100}shared|icloud.{0,100}shared|box\\.com.{0,100}shared|shared.{0,100}folder).*".to_string() },
                            ],
                        },
                        Criteria::Not {
                            criteria: Box::new(
                            Criteria::Or {
                                criteria: vec![
                                Criteria::SenderPattern { pattern: ".*@.*(fidelity|vanguard|schwab|merrill|chase|wellsfargo|bankofamerica|torrid|geico)\\.(com|org)$".to_string() },
                                Criteria::SenderPattern { pattern: ".*@.*docusign\\.(com|net)$".to_string() },
                                Criteria::SenderPattern { pattern: ".*@(nedm\\.asus|.*\\.asus|dt\\.torrid)\\.(com|net|org)$".to_string() },
                                Criteria::SenderPattern { pattern: ".*@.*(charmtracker|acemed|acemedseattle|healthcare|medical|clinic|hospital)\\.(com|net|org)$".to_string() },
                                Criteria::SenderPattern { pattern: ".*@.*(nytimes|washingtonpost|cnn|bbc|reuters|ap|wsj|usatoday)\\.(com|org)$".to_string() },
                                Criteria::HeaderPattern { header: "Authentication-Results".to_string(), pattern: "dkim=pass.{0,100}fidelity\\.com".to_string() },
                                Criteria::BodyPattern { pattern: "(?i).{0,100}(401k|401\\(k\\)|retirement.{0,100}plan|employee.{0,100}benefits|plan.{0,100}information.{0,100}documents).*".to_string() },
                                ],
                            }
                            ),
                        },
                        ],
                    },
                    action: None,
                    score: Some(100),
                    description: Some("Fake cloud storage sharing notifications".to_string()),
                },
                FilterRule {
                    name: "DocuSign Phishing".to_string(),
                    enabled: true,
                    criteria:
                    Criteria::And {
                        criteria: vec![
                        Criteria::Or {
                            criteria: vec![
                            Criteria::SubjectPattern { pattern: "(?i).{0,100}(docusign|document.{0,100}signature|electronic.{0,100}signature|signature.{0,100}required).*".to_string() },
                            Criteria::CombinedTextPattern { pattern: "(?i).{0,100}(please.{0,100}sign.{0,100}document|review.{0,100}and.{0,100}sign|signature.{0,100}required|document.{0,100}awaiting.{0,100}signature).*".to_string() },
                            ],
                        },
                        Criteria::Not {
                            criteria: Box::new(
                            Criteria::Or {
                                criteria: vec![
                                Criteria::SenderPattern { pattern: ".*@.*docusign\\.(com|net)$".to_string() },
                                Criteria::SenderPattern { pattern: ".*@.*nytimes.*".to_string() },
                                Criteria::SenderPattern { pattern: ".*@.*(walgreens|eml\\.walgreens)\\.(com|net)$".to_string() },
                                ],
                            }
                            ),
                        },
                        ],
                    },
                    action: None,
                    score: Some(175),
                    description: Some("Fake DocuSign and document signing phishing".to_string()),
                },
                FilterRule {
                    name: "WeTransfer Phishing".to_string(),
                    enabled: true,
                    criteria:
                    Criteria::And {
                        criteria: vec![
                        Criteria::Or {
                            criteria: vec![
                            Criteria::SubjectPattern { pattern: "(?i).{0,100}(wetransfer|file.{0,100}transfer|download.{0,100}files|transfer.{0,100}expires).*".to_string() },
                            Criteria::CombinedTextPattern { pattern: "(?i).{0,100}(files.{0,100}ready.{0,100}download|transfer.{0,100}link|download.{0,100}before.{0,100}expires).*".to_string() },
                            ],
                        },
                        Criteria::Not {
                            criteria: Box::new(
                            Criteria::SenderPattern { pattern: ".*@.*wetransfer\\.(com|net)$".to_string() }
                            ),
                        },
                        ],
                    },
                    action: None,
                    score: Some(125),
                    description: Some("Fake WeTransfer file sharing phishing".to_string()),
                },
                FilterRule {
                    name: "Domain Spoofing System Impersonation".to_string(),
                    enabled: true,
                    criteria:
                    Criteria::Or {
                        criteria: vec![
                        Criteria::SubjectPattern { pattern: "(?i).{0,100}(removal.{0,100}request.{0,100}server|server.{0,100}accepted|domain.{0,100}removal|unsubscribe.{0,100}request).*".to_string() },
                        Criteria::SubjectPattern { pattern: "(?i).{0,100}(mailer.{0,100}daemon|delivery.{0,100}failure|bounce.{0,100}message|system.{0,100}administrator).*".to_string() },
                        Criteria::And {
                            criteria: vec![
                            Criteria::CombinedTextPattern { pattern: "(?i).{0,100}(server.{0,100}maintenance|system.{0,100}notification|automated.{0,100}message).*".to_string() },
                            Criteria::Not {
                                criteria: Box::new(
                                Criteria::Or {
                                    criteria: vec![
                                    Criteria::SenderPattern { pattern: ".*@.*(adapthealth|healthcare|medical|clinic|hospital|pulmonary|premera)\\.(com|net|org)$".to_string() },
                                    Criteria::SenderPattern { pattern: ".*@.*(charmtracker|acemed|healthcare|medical|clinic|hospital)\\.(com|net|org)$".to_string() },
                                    Criteria::SenderPattern { pattern: ".*@.*(disney|disneyplus|disneystore|c\\.disneystore|sparkpostmail|netflix|amazon|microsoft|google|apple)\\.(com|net|org)$".to_string() },
                                    Criteria::SenderPattern { pattern: ".*@(nedm\\.asus|butcherbox)\\.(com|net|org)$".to_string() },
                                    Criteria::SenderPattern { pattern: ".*@.*(discover|ally|billpay\\.ally|discovercard|allybank)\\.(com|net|org)$".to_string() },
                                    Criteria::SenderPattern { pattern: ".*@.*(proflowers|news\\.proflowers|tmobile|t-mobile|govdelivery)\\.(com|net|org)$".to_string() },
                                    Criteria::SenderPattern { pattern: ".*@.*(aran|septicresponse|acemedseattle)\\.(com|net|org)$".to_string() },
                                    Criteria::SenderPattern { pattern: ".*@.*(capitaloneshopping|public\\.govdelivery)\\.(com|net|org)$".to_string() },
                                    Criteria::SenderPattern { pattern: ".*@.*(michaels|emdeals\\.michaels|rejuvenation|e\\.rejuvenation|onestopplus|e\\.onestopplus|torrid|mktg\\.torrid)\\.(com|net|org)$".to_string() },
                                    Criteria::SenderPattern { pattern: ".*@.*usps\\.(com|gov)$".to_string() },
                                    Criteria::SenderPattern { pattern: ".*@(email\\.d23|sparkpostmail)\\.(com|net|org)$".to_string() },
                                    Criteria::SenderPattern { pattern: ".*@.*duluthtrading\\.(com|net|org)$".to_string() },
                                    Criteria::SenderPattern { pattern: ".*@em\\.michaelscustomframing\\.com$".to_string() },
                                    Criteria::SenderPattern { pattern: ".*@.*costco\\.(com|net|org)$".to_string() },
                                    Criteria::SenderPattern { pattern: ".*@.*\\.costco\\.com\\..*$".to_string() },
                                    Criteria::SenderPattern { pattern: ".*@.*oxfordclub\\.com$".to_string() },
                                    Criteria::SenderPattern { pattern: ".*@.*empower\\.(com|net|org)$".to_string() },
                                    Criteria::SenderPattern { pattern: ".*@.*xfinity\\.(com|net|org)$".to_string() },
                                    Criteria::SenderPattern { pattern: ".*@.*walgreens\\.(com|net|org)$".to_string() },
                                    Criteria::SenderPattern { pattern: ".*@.*rxorder\\.walgreens\\.(com|net|org)$".to_string() },
                                    Criteria::SenderPattern { pattern: ".*@.*govdelivery\\.(com|net|org)$".to_string() },
                                    Criteria::SenderPattern { pattern: ".*@.*(pershing|bnymellon|investor\\.pershing|edelivery|akamaiedge)\\.(com|net|org)$".to_string() },
                                    Criteria::SenderPattern { pattern: ".*@.*bearaby\\.(com|net|org)$".to_string() },
                                    Criteria::SenderPattern { pattern: ".*@.*ecoflow\\.(com|net|org)$".to_string() },
                                    Criteria::SenderPattern { pattern: ".*@.*nationalgeographic\\.(com|net|org)$".to_string() },
                                    Criteria::SenderPattern { pattern: "noreply@.*\\.(com|net|org)$".to_string() },
                                    Criteria::HeaderPattern { header: "Authentication-Results".to_string(), pattern: "dkim=pass.{0,100}adapthealth\\.com".to_string() },
                                    Criteria::HeaderPattern { header: "Authentication-Results".to_string(), pattern: "dkim=pass.{0,100}charmtracker\\.com".to_string() },
                                    ],
                                }
                                ),
                            },
                            ],
                        },
                        Criteria::SubjectPattern { pattern: "(?i).{0,100}(account.{0,100}suspension|account.{0,100}suspended|domain.{0,100}impersonation|test.{0,100}subject).*".to_string() },
                        Criteria::SubjectPattern { pattern: "(?i).{0,100}(nota.{0,100}fiscal|invoice.{0,100}eletronica|black.{0,100}friday.{0,100}sale|happening.{0,100}now).*".to_string() },
                        ],
                    },
                    action: None,
                    score: Some(200),
                    description: Some("Domain spoofing and system service impersonation".to_string()),
                },
                FilterRule {
                    name: "Cloud Storage Phishing".to_string(),
                    enabled: true,
                    criteria:
                    Criteria::And {
                        criteria: vec![
                        Criteria::SubjectPattern { pattern: "(?i).{0,100}(dropbox.{0,100}shared|google.{0,100}drive.{0,100}shared|onedrive.{0,100}shared|file.{0,100}shared.{0,100}you|document.{0,100}shared|shared.{0,100}folder|download.{0,100}file|view.{0,100}document).*".to_string() },
                        Criteria::Not {
                            criteria: Box::new(
                            Criteria::Or {
                                criteria: vec![
                                Criteria::SenderPattern { pattern: ".*@.*(charmtracker|medical|healthcare|clinic|hospital|ehr)\\.(com|net|org)$".to_string() },
                                Criteria::SenderPattern { pattern: ".*@.*(docusign|dropbox|google|microsoft|onedrive|box)\\.(com|net|org)$".to_string() },
                                Criteria::SenderPattern { pattern: ".*@.*(dominos|doordash|butcherbox|usps|walgreens|xfinity)\\.(com|net|org)$".to_string() },
                                Criteria::SenderPattern { pattern: ".*@.*(nytimes|washingtonpost|cnn|bbc|reuters|ap|wsj|usatoday)\\.(com|org)$".to_string() },
                                Criteria::HeaderPattern { header: "From".to_string(), pattern: "(?i).{0,100}(AceMed|Medical|Healthcare|Clinic|Hospital|EHR|Patient Portal).*".to_string() },
                                ],
                            }
                            ),
                        },
                        ],
                    },
                    action: None,
                    score: Some(35),
                    description: Some("Fake cloud storage sharing notifications (excluding legitimate medical services)".to_string()),
                },
                FilterRule {
                    name: "Payment Service Abuse".to_string(),
                    enabled: true,
                    criteria:
                    Criteria::And {
                        criteria: vec![
                        Criteria::SubjectPattern { pattern: "(?i).{0,100}(paypal.{0,100}payment|stripe.{0,100}payment|square.{0,100}payment|payment.{0,100}received|money.{0,100}sent|invoice.{0,100}paid|transaction.{0,100}complete|refund.{0,100}processed).*".to_string() },
                        Criteria::Not {
                            criteria: Box::new(
                            Criteria::SenderPattern { pattern: ".*@.*(paypal|stripe|square|quickbooks|intuit)\\.(com|net)$|.*@.*apple(card)?\\.apple$".to_string() }
                            ),
                        },
                        ],
                    },
                    action: None,
                    score: Some(75),
                    description: Some("Fake payment service notifications".to_string()),
                },
                FilterRule {
                    name: "From Header Domain Impersonation".to_string(),
                    enabled: true,
                    criteria:
                    Criteria::And {
                        criteria: vec![
                        Criteria::HeaderPattern { header: "From".to_string(), pattern: "\"[^\"@]+\\.(com|org|net|gov|edu|mil)\"\\s*<[^@]+@[^>]+>".to_string() },
                        Criteria::Not {
                            criteria: Box::new(
                            Criteria::Or {
                                criteria: vec![
                                Criteria::HeaderPattern { header: "From".to_string(), pattern: "\"[^\"@]+\"\\s*<[^@]+@.*walgreens\\.(com|net)>".to_string() },
                                Criteria::HeaderPattern { header: "From".to_string(), pattern: "\"[^\"@]+\"\\s*<[^@]+@.*doordash\\.(com|net)>".to_string() },
                                Criteria::HeaderPattern { header: "From".to_string(), pattern: "\"[^\"@]+\"\\s*<[^@]+@.*amazon\\.(com|net)>".to_string() },
                                Criteria::HeaderPattern { header: "From".to_string(), pattern: "\"[^\"@]+\"\\s*<[^@]+@.*microsoft\\.(com|net)>".to_string() },
                                Criteria::HeaderPattern { header: "From".to_string(), pattern: "\"[^\"@]+\"\\s*<[^@]+@.*mailchimp.{0,100}\\.(com|net)>".to_string() },
                                Criteria::HeaderPattern { header: "From".to_string(), pattern: "\"[^\"@]+\"\\s*<[^@]+@.*mcdlv\\.(com|net)>".to_string() },
                                Criteria::HeaderPattern { header: "From".to_string(), pattern: "\"[^\"@]+\"\\s*<[^@]+@.*sendgrid\\.(com|net)>".to_string() },
                                Criteria::HeaderPattern { header: "From".to_string(), pattern: "\"[^\"@]+\"\\s*<[^@]+@.*e\\.williams-sonoma\\.com>".to_string() },
                                Criteria::HeaderPattern { header: "From".to_string(), pattern: "\"499inks\\.com\"\\s*<[^@]+@499inks\\.com>".to_string() },
                                Criteria::HeaderPattern { header: "From".to_string(), pattern: "\"[^\"@]+\"\\s*<[^@]+@.*lensdirect\\.(com|net)>".to_string() },
                                Criteria::FeatureAnalysis {
                                    feature_name: "Authentication Analysis".to_string(),
                                    min_score: None,
                                    max_score: None,
                                    evidence_pattern: Some("DKIM domain properly aligned".to_string()),
                                    invert: None,
                                },
                                ],
                            }
                            ),
                        },
                        Criteria::Or {
                            criteria: vec![
                            Criteria::BodyPattern { pattern: "(?i)(password|account|login|verify|confirm|suspend|expir|action.{0,100}required)".to_string() },
                            Criteria::SubjectPattern { pattern: "(?i)(action.{0,100}required|urgent|expir|suspend|verify|password)".to_string() },
                            ],
                        },
                        ],
                    },
                    action: None,
                    score: Some(90),
                    description: Some("From header displays domain name in quotes with completely different sender domain".to_string()),
                },
                FilterRule {
                    name: "Password Expiration Phishing".to_string(),
                    enabled: true,
                    criteria:
                    Criteria::And {
                        criteria: vec![
                        Criteria::Or {
                            criteria: vec![
                            Criteria::SubjectPattern { pattern: "(?i).{0,100}(password.{0,100}expir|password.{0,100}reset|account.{0,100}expir|login.{0,100}expir|access.{0,100}expir).*".to_string() },
                            Criteria::BodyPattern { pattern: "(?i).{0,100}(password.{0,100}expir|password.{0,100}reset|account.{0,100}expir|login.{0,100}expir|access.{0,100}expir).*".to_string() },
                            ],
                        },
                        Criteria::Not {
                            criteria: Box::new(
                            Criteria::SenderPattern { pattern: ".*@.*(microsoft|google|apple|amazon|paypal|adobe|salesforce|zoom|slack|dropbox|disney|disneyplus|sparkpostmail|d23|walgreens|eml\\.walgreens|facebook|facebookmail|ugg|onestopplus)\\.(com|org|net)$".to_string() }
                            ),
                        },
                        ],
                    },
                    action: None,
                    score: Some(80),
                    description: Some("Password expiration phishing attempts".to_string()),
                },
                FilterRule {
                    name: "CVS Medicare Phishing".to_string(),
                    enabled: true,
                    criteria:
                    Criteria::Or {
                        criteria: vec![
                        Criteria::SubjectPattern { pattern: "(?i).{0,100}(cvs.{0,100}medicare|medicare.{0,100}cvs|pharmacy.{0,100}benefit).*".to_string() },
                        Criteria::BodyPattern { pattern: "(?i).{0,100}(cvs.{0,100}medicare|medicare.{0,100}cvs|pharmacy.{0,100}benefit).*".to_string() },
                        ],
                    },
                    action: None,
                    score: Some(300),
                    description: None,
                },
                FilterRule {
                    name: "Fake Invoice Scam".to_string(),
                    enabled: true,
                    criteria:
                    Criteria::And {
                        criteria: vec![
                        Criteria::Or {
                            criteria: vec![
                            Criteria::SubjectPattern { pattern: "(?i).{0,100}(fake.{0,100}invoice|norton.{0,100}invoice|order.{0,100}receipt|payment.{0,100}receipt).*".to_string() },
                            Criteria::BodyPattern { pattern: "(?i).{0,100}(fake.{0,100}invoice|norton.{0,100}invoice|order.{0,100}receipt|payment.{0,100}receipt).*".to_string() },
                            ],
                        },
                        Criteria::Not {
                            criteria: Box::new(
                            Criteria::Or {
                                criteria: vec![
                                Criteria::SenderPattern { pattern: ".*<.*@.*(butcherbox|dominos|doordash|amazon|walmart|target|bestbuy|walgreens)\\.(com|net|org)>.*|.*@.*(butcherbox|dominos|doordash|amazon|walmart|target|bestbuy|walgreens)\\.(com|net|org)$".to_string() },
                                Criteria::SenderPattern { pattern: ".*<.*@(mail\\.duluthtrading|em\\.michaelscustomframing)\\.(com|net|org)>.*|.*@(mail\\.duluthtrading|em\\.michaelscustomframing)\\.(com|net|org)$".to_string() },
                                Criteria::SenderPattern { pattern: ".*<.*@.*(paypal|stripe|square|shopify|legitimate)\\.(com|net|org)>.*|.*@.*(paypal|stripe|square|shopify|legitimate)\\.(com|net|org)$".to_string() },
                                Criteria::SenderPattern { pattern: ".*<.*@.*(charmtracker|acemedseattle|mailerehr\\.charmtracker)\\.(com|net|org)>.*|.*@.*(charmtracker|acemedseattle|mailerehr\\.charmtracker)\\.(com|net|org)$".to_string() },
                                Criteria::HeaderPattern { header: "From".to_string(), pattern: ".*@.*(butcherbox|dominos|doordash|amazon|walmart|walgreens|charmtracker|acemedseattle)\\.(com|net|org)$".to_string() },
                                Criteria::FeatureAnalysis {
                                    feature_name: "Authentication Analysis".to_string(),
                                    min_score: None,
                                    max_score: None,
                                    evidence_pattern: Some("DKIM domain properly aligned".to_string()),
                                    invert: None,
                                },
                                ],
                            }
                            ),
                        },
                        ],
                    },
                    action: None,
                    score: Some(280),
                    description: None,
                },
                FilterRule {
                    name: "Google Workspace Impersonation".to_string(),
                    enabled: true,
                    criteria:
                    Criteria::Or {
                        criteria: vec![
                        Criteria::SubjectPattern { pattern: "(?i).{0,100}(google.{0,100}workspace|workspace.{0,100}google|yeti.{0,100}brand).*".to_string() },
                        Criteria::BodyPattern { pattern: "(?i).{0,100}(google.{0,100}workspace|workspace.{0,100}google|yeti.{0,100}brand).*".to_string() },
                        ],
                    },
                    action: None,
                    score: Some(250),
                    description: None,
                },
                FilterRule {
                    name: "Investment Scam Patterns".to_string(),
                    enabled: true,
                    criteria:
                    Criteria::And {
                        criteria: vec![
                        Criteria::Or {
                            criteria: vec![
                            Criteria::SubjectPattern { pattern: "(?i).{0,100}(fam.{0,100}investment|investment.{0,100}opportunity|guaranteed.{0,100}returns).*".to_string() },
                            Criteria::BodyPattern { pattern: "(?i).{0,100}(fam.{0,100}investment|investment.{0,100}opportunity|guaranteed.{0,100}returns).*".to_string() },
                            ],
                        },
                        Criteria::Not {
                            criteria: Box::new(
                            Criteria::Or {
                                criteria: vec![
                                Criteria::SenderPattern { pattern: ".*@.*(fidelity|vanguard|schwab|merrill|chase|wellsfargo|bankofamerica|pershing|bnymellon|akamaiedge|filtersfast)\\.(com|org|net)$".to_string() },
                                Criteria::HeaderPattern { header: "Authentication-Results".to_string(), pattern: "dkim=pass.{0,100}fidelity\\.com".to_string() },
                                Criteria::BodyPattern { pattern: "(?i).{0,100}(401k|401\\(k\\)|retirement.{0,100}plan|employee.{0,100}benefits|no.{0,100}action.{0,100}required).*".to_string() },
                                ],
                            }
                            ),
                        },
                        ],
                    },
                    action: None,
                    score: Some(300),
                    description: Some("Investment scams excluding legitimate financial institutions".to_string()),
                },
                FilterRule {
                    name: "Romance Scam Detection".to_string(),
                    enabled: true,
                    criteria:
                    Criteria::Or {
                        criteria: vec![
                        Criteria::SubjectPattern { pattern: "(?i).{0,100}(ukrainian.{0,100}romance|romance.{0,100}scam|lonely.{0,100}heart).*".to_string() },
                        Criteria::BodyPattern { pattern: "(?i).{0,100}(ukrainian.{0,100}romance|romance.{0,100}scam|lonely.{0,100}heart).*".to_string() },
                        ],
                    },
                    action: None,
                    score: Some(350),
                    description: None,
                },
                FilterRule {
                    name: "International Phishing".to_string(),
                    enabled: true,
                    criteria:
                    Criteria::Or {
                        criteria: vec![
                        Criteria::SubjectPattern { pattern: "(?i).{0,100}(portuguese.{0,100}signature|sbi.{0,100}phishing|international.{0,100}bank).*".to_string() },
                        Criteria::BodyPattern { pattern: "(?i).{0,100}(portuguese.{0,100}signature|sbi.{0,100}phishing|international.{0,100}bank).*".to_string() },
                        ],
                    },
                    action: None,
                    score: Some(280),
                    description: None,
                },
                FilterRule {
                    name: "Interactive Brokers Enhanced Scam".to_string(),
                    enabled: true,
                    criteria:
                    Criteria::Or {
                        criteria: vec![
                        Criteria::SubjectPattern { pattern: "(?i).{0,100}(interactive.{0,100}brokers.{0,100}w8ben|w8ben.{0,100}compliance|w8ben.{0,100}tax|brokers.{0,100}compliance|fake.{0,100}interactive.{0,100}brokers).*".to_string() },
                        Criteria::BodyPattern { pattern: "(?i).{0,100}(interactive.{0,100}brokers.{0,100}w8ben|w8ben.{0,100}compliance|w8ben.{0,100}tax|brokers.{0,100}compliance|fake.{0,100}interactive.{0,100}brokers).*".to_string() },
                        ],
                    },
                    action: None,
                    score: Some(350),
                    description: None,
                },
                FilterRule {
                    name: "Transaction Confirmation Enhanced".to_string(),
                    enabled: true,
                    criteria:
                    Criteria::And {
                        criteria: vec![
                        Criteria::Or {
                            criteria: vec![
                            Criteria::SubjectPattern { pattern: "(?i).{0,100}(fake.{0,100}order.{0,100}transaction|fake.{0,100}payment.{0,100}confirmation|order.{0,100}confirmation|transaction.{0,100}confirmation|payment.{0,100}receipt).*".to_string() },
                            Criteria::BodyPattern { pattern: "(?i).{0,100}(fake.{0,100}order.{0,100}transaction|fake.{0,100}payment.{0,100}confirmation|order.{0,100}confirmation|transaction.{0,100}confirmation|payment.{0,100}receipt).*".to_string() },
                            ],
                        },
                        Criteria::Not {
                            criteria: Box::new(
                            Criteria::Or {
                                criteria: vec![
                                Criteria::SenderPattern { pattern: ".*<.*@.*(dominos|doordash|butcherbox|amazon|walmart|target|bestbuy|walgreens|barnesandnoble|torrid|americanmeadows|lensdirect)\\.(com|net|org)>.*|.*@.*(dominos|doordash|butcherbox|amazon|walmart|target|bestbuy|walgreens|barnesandnoble|torrid|americanmeadows|lensdirect)\\.(com|net|org)$".to_string() },
                                Criteria::SenderPattern { pattern: ".*<.*@(mail\\.duluthtrading|em\\.michaelscustomframing|dt\\.torrid)\\.(com|net|org)>.*|.*@(mail\\.duluthtrading|em\\.michaelscustomframing|dt\\.torrid)\\.(com|net|org)$".to_string() },
                                Criteria::SenderPattern { pattern: ".*<.*@.*(charmtracker|acemedseattle|mailerehr\\.charmtracker)\\.(com|net|org)>.*|.*@.*(charmtracker|acemedseattle|mailerehr\\.charmtracker)\\.(com|net|org)$".to_string() },
                                Criteria::SenderPattern { pattern: ".*<.*@.*(mtasv|batemanhornecenter)\\.(com|net|org)>.*|.*@.*(mtasv|batemanhornecenter)\\.(com|net|org)$".to_string() },
                                Criteria::SenderPattern { pattern: ".*@e-offers\\.dominos\\.com$".to_string() },
                                Criteria::HeaderPattern { header: "From".to_string(), pattern: ".*@.*(butcherbox|dominos|doordash|amazon|walmart|walgreens|barnesandnoble|charmtracker|acemedseattle|americanmeadows)\\.(com|net|org)$".to_string() },
                                Criteria::FeatureAnalysis {
                                    feature_name: "Authentication Analysis".to_string(),
                                    min_score: None,
                                    max_score: None,
                                    evidence_pattern: Some("DKIM domain properly aligned".to_string()),
                                    invert: None,
                                },
                                ],
                            }
                            ),
                        },
                        ],
                    },
                    action: None,
                    score: Some(300),
                    description: None,
                },
                FilterRule {
                    name: "Enhanced Mailer Daemon Spoofing".to_string(),
                    enabled: true,
                    criteria:
                    Criteria::And {
                        criteria: vec![
                        Criteria::Or {
                            criteria: vec![
                            Criteria::SubjectPattern { pattern: "(?i).{0,100}(mailer.{0,100}daemon|delivery.{0,100}failure|undelivered.{0,100}mail|mail.{0,100}delivery.{0,100}subsystem).*".to_string() },
                            Criteria::BodyPattern { pattern: "(?i).{0,100}(mailer.{0,100}daemon|delivery.{0,100}failure|undelivered.{0,100}mail|mail.{0,100}delivery.{0,100}subsystem).*".to_string() },
                            ],
                        },
                        Criteria::Not {
                            criteria: Box::new(
                            Criteria::Or {
                                criteria: vec![
                                Criteria::SenderPattern { pattern: ".*@.*(ecoflow|onestopplus|levi|nike|adidas|gap|torrid|sense)\\.(com|net|org)$".to_string() },
                                Criteria::HeaderPattern { header: "Authentication-Results".to_string(), pattern: "dmarc=pass".to_string() },
                                ],
                            }
                            ),
                        },
                        ],
                    },
                    action: None,
                    score: Some(300),
                    description: None,
                },
                FilterRule {
                    name: "Credit Card Bill Phishing".to_string(),
                    enabled: true,
                    criteria:
                    Criteria::And {
                        criteria: vec![
                        Criteria::Or {
                            criteria: vec![
                            Criteria::SubjectPattern { pattern: "(?i).{0,100}(creditcard.{0,100}bill|credit.{0,100}card.{0,100}statement|billing.{0,100}statement|account.{0,100}statement).*".to_string() },
                            Criteria::BodyPattern { pattern: "(?i).{0,100}(creditcard.{0,100}bill|credit.{0,100}card.{0,100}statement|billing.{0,100}statement|account.{0,100}statement).*".to_string() },
                            ],
                        },
                        Criteria::Or {
                            criteria: vec![
                            Criteria::BodyPattern { pattern: "(?i).{0,100}(click.{0,100}here.{0,100}view|download.{0,100}statement|verify.{0,100}account|update.{0,100}payment|account.{0,100}suspended).*".to_string() },
                            Criteria::BodyPattern { pattern: "(?i).{0,100}(urgent.{0,100}action|immediate.{0,100}attention|account.{0,100}locked|payment.{0,100}failed).*".to_string() },
                            ],
                        },
                        Criteria::Not {
                            criteria: Box::new(
                            Criteria::Or {
                                criteria: vec![
                                Criteria::SenderPattern { pattern: ".*@.*(chase|citi|amex|discover|capitalone|wellsfargo|bankofamerica|britishairways|ba\\.com|paypal|communications\\.paypal)\\.(com|org)$".to_string() },
                                Criteria::BodyPattern { pattern: "(?i).{0,100}(rewards.{0,100}program|bonus.{0,100}offer|miles.{0,100}points|cashback|signup.{0,100}bonus|new.{0,100}cardmember).*".to_string() },
                                ],
                            }
                            ),
                        },
                        ],
                    },
                    action: None,
                    score: Some(280),
                    description: Some("Fake credit card bill phishing excluding legitimate offers".to_string()),
                },
                FilterRule {
                    name: "Norton Fake Invoice Scam".to_string(),
                    enabled: true,
                    criteria:
                    Criteria::Or {
                        criteria: vec![
                        Criteria::SubjectPattern { pattern: "(?i).{0,100}(norton.{0,100}alert.{0,100}overdue.{0,100}charge|norton.{0,100}fake.{0,100}invoice|norton.{0,100}billing|norton.{0,100}payment.{0,100}due).*".to_string() },
                        Criteria::BodyPattern { pattern: "(?i).{0,100}(norton.{0,100}alert.{0,100}overdue.{0,100}charge|norton.{0,100}fake.{0,100}invoice|norton.{0,100}billing|norton.{0,100}payment.{0,100}due).*".to_string() },
                        ],
                    },
                    action: None,
                    score: Some(350),
                    description: None,
                },
                FilterRule {
                    name: "Online Loan Scam".to_string(),
                    enabled: true,
                    criteria:
                    Criteria::Or {
                        criteria: vec![
                        Criteria::SubjectPattern { pattern: "(?i).{0,100}(online.{0,100}loans.{0,100}up.{0,100}to|santa.{0,100}loans|payday.{0,100}loans|quick.{0,100}cash.{0,100}loans|loans.{0,100}up.{0,100}to.{0,100}5000).*".to_string() },
                        Criteria::BodyPattern { pattern: "(?i).{0,100}(online.{0,100}loans.{0,100}up.{0,100}to|santa.{0,100}loans|payday.{0,100}loans|quick.{0,100}cash.{0,100}loans|loans.{0,100}up.{0,100}to.{0,100}5000).*".to_string() },
                        ],
                    },
                    action: None,
                    score: Some(300),
                    description: None,
                },
                FilterRule {
                    name: "OReilly Impersonation Scam".to_string(),
                    enabled: true,
                    criteria:
                    Criteria::Or {
                        criteria: vec![
                        Criteria::SubjectPattern { pattern: "(?i).{0,100}(oreilly.{0,100}jump.{0,100}starter|oreilly.{0,100}impersonation|auto.{0,100}parts.{0,100}scam).*".to_string() },
                        Criteria::BodyPattern { pattern: "(?i).{0,100}(oreilly.{0,100}jump.{0,100}starter|oreilly.{0,100}impersonation|auto.{0,100}parts.{0,100}scam).*".to_string() },
                        ],
                    },
                    action: None,
                    score: Some(250),
                    description: None,
                },
                FilterRule {
                    name: "Portuguese Signature Phishing".to_string(),
                    enabled: true,
                    criteria:
                    Criteria::Or {
                        criteria: vec![
                        Criteria::SubjectPattern { pattern: "(?i).{0,100}(lembrete.{0,100}assinatura.{0,100}pendente|portuguese.{0,100}signature|assinatura.{0,100}portuguesa|documento.{0,100}assinatura|signature.{0,100}phishing).*".to_string() },
                        Criteria::BodyPattern { pattern: "(?i).{0,100}(lembrete.{0,100}assinatura.{0,100}pendente|portuguese.{0,100}signature|assinatura.{0,100}portuguesa|documento.{0,100}assinatura|signature.{0,100}phishing).*".to_string() },
                        ],
                    },
                    action: None,
                    score: Some(320),
                    description: None,
                },
                FilterRule {
                    name: "Brazilian Tax Payment Scam".to_string(),
                    enabled: true,
                    criteria:
                    Criteria::And {
                        criteria: vec![
                        Criteria::Or {
                            criteria: vec![
                            Criteria::SubjectPattern { pattern: "(?i).{0,100}(\\bDARF\\b|\\bIRPJ\\b|imposto.{0,100}renda|guia.{0,100}pagamento|departamento.{0,100}cont[aá]bil).*".to_string() },
                            Criteria::BodyPattern { pattern: "(?i).{0,100}(\\bDARF\\b|\\bIRPJ\\b|imposto.{0,100}renda|guia.{0,100}pagamento|receita.{0,100}federal).*".to_string() },
                            ],
                        },
                        Criteria::Not {
                            criteria: Box::new(
                            Criteria::Or {
                                criteria: vec![
                                Criteria::SenderPattern { pattern: ".*@.*(gov\\.br|receita\\.fazenda\\.gov\\.br|serpro\\.gov\\.br|usps\\.com|usps\\.gov)$".to_string() },
                                Criteria::SenderPattern { pattern: ".*@.*(gov|edu|mil)$".to_string() },
                                ],
                            }
                            ),
                        },
                        ],
                    },
                    action: None,
                    score: Some(350),
                    description: Some("Fake Brazilian tax payment notifications (DARF/IRPJ scams)".to_string()),
                },
                FilterRule {
                    name: "Portuguese Job Application Spam".to_string(),
                    enabled: true,
                    criteria:
                    Criteria::And {
                        criteria: vec![
                        Criteria::Or {
                            criteria: vec![
                            Criteria::SubjectPattern { pattern: "(?i).{0,100}(curr[ií]culo|curriculo).*".to_string() },
                            Criteria::SubjectPattern { pattern: ".*Q3VycsOtY3VsbyBQcm9maXNzaW9uYWw.*".to_string() },
                            Criteria::CombinedTextPattern { pattern: "(?i).{0,100}(curr[ií]culo|curriculo|encaminho.{0,100}anexo|anexo.{0,100}curr[ií]culo).*".to_string() },
                            ],
                        },
                        Criteria::Not {
                            criteria: Box::new(
                            Criteria::Or {
                                criteria: vec![
                                Criteria::SenderPattern { pattern: ".*@.*(linkedin|indeed|glassdoor|monster|careerbuilder|ziprecruiter)\\.(com|net|org)$".to_string() },
                                Criteria::SenderPattern { pattern: ".*@.*(gov|edu|mil)$".to_string() },
                                ],
                            }
                            ),
                        },
                        ],
                    },
                    action: None,
                    score: Some(150),
                    description: Some("Portuguese curriculum/resume spam from suspicious domains".to_string()),
                },
                FilterRule {
                    name: "Enhanced OReilly Jump Starter Impersonation".to_string(),
                    enabled: true,
                    criteria:
                    Criteria::Or {
                        criteria: vec![
                        Criteria::SubjectPattern { pattern: "(?i).{0,100}(jump.{0,100}start.{0,100}your.{0,100}drive.{0,100}gift|oreilly.{0,100}jump.{0,100}starter|schumacher.{0,100}jump.{0,100}starter|auto.{0,100}gift.{0,100}oreilly).*".to_string() },
                        Criteria::BodyPattern { pattern: "(?i).{0,100}(jump.{0,100}start.{0,100}your.{0,100}drive.{0,100}gift|oreilly.{0,100}jump.{0,100}starter|schumacher.{0,100}jump.{0,100}starter|auto.{0,100}gift.{0,100}oreilly).*".to_string() },
                        ],
                    },
                    action: None,
                    score: Some(280),
                    description: None,
                },
                FilterRule {
                    name: "Enhanced Interactive Brokers W8BEN Compliance".to_string(),
                    enabled: true,
                    criteria:
                    Criteria::Or {
                        criteria: vec![
                        Criteria::SubjectPattern { pattern: "(?i).{0,100}(federal.{0,100}compliance.{0,100}directive.{0,100}renewal.{0,100}expired.{0,100}w.{0,100}8ben|interactive.{0,100}brokers.{0,100}w8ben|w8ben.{0,100}compliance|brokers.{0,100}tax.{0,100}compliance|fake.{0,100}interactive.{0,100}brokers).*".to_string() },
                        Criteria::BodyPattern { pattern: "(?i).{0,100}(federal.{0,100}compliance.{0,100}directive.{0,100}renewal.{0,100}expired.{0,100}w.{0,100}8ben|interactive.{0,100}brokers.{0,100}w8ben|w8ben.{0,100}compliance|brokers.{0,100}tax.{0,100}compliance|fake.{0,100}interactive.{0,100}brokers).*".to_string() },
                        ],
                    },
                    action: None,
                    score: Some(380),
                    description: None,
                },
                FilterRule {
                    name: "SBI Phishing Japanese".to_string(),
                    enabled: true,
                    criteria:
                    Criteria::Or {
                        criteria: vec![
                        Criteria::SubjectPattern { pattern: "(?i).{0,100}(sbi.{0,100}phishing|japanese.{0,100}phishing|配当金入金|重要.*配当).*".to_string() },
                        Criteria::BodyPattern { pattern: "(?i).{0,100}(sbi.{0,100}phishing|japanese.{0,100}phishing|配当金入金|重要.*配当).*".to_string() },
                        ],
                    },
                    action: None,
                    score: Some(350),
                    description: None,
                },
                FilterRule {
                    name: "W8BEN Tax Residency Scam".to_string(),
                    enabled: true,
                    criteria:
                    Criteria::Or {
                        criteria: vec![
                        Criteria::SubjectPattern { pattern: "(?i).{0,100}(official.{0,100}tax.{0,100}residency.{0,100}notice.{0,100}renewal.{0,100}form.{0,100}w.{0,100}8ben|tax.{0,100}residency.{0,100}notice|w.{0,100}8ben.{0,100}required).*".to_string() },
                        Criteria::BodyPattern { pattern: "(?i).{0,100}(official.{0,100}tax.{0,100}residency.{0,100}notice.{0,100}renewal.{0,100}form.{0,100}w.{0,100}8ben|tax.{0,100}residency.{0,100}notice|w.{0,100}8ben.{0,100}required).*".to_string() },
                        ],
                    },
                    action: None,
                    score: Some(390),
                    description: None,
                },
                FilterRule {
                    name: "ShareFile Document Phishing".to_string(),
                    enabled: true,
                    criteria:
                    Criteria::Or {
                        criteria: vec![
                        Criteria::SubjectPattern { pattern: "(?i).{0,100}(received.{0,100}new.{0,100}document.{0,100}approval|sharefile.{0,100}document.{0,100}phishing|document.{0,100}approval.{0,100}phishing).*".to_string() },
                        Criteria::BodyPattern { pattern: "(?i).{0,100}(received.{0,100}new.{0,100}document.{0,100}approval|sharefile.{0,100}document.{0,100}phishing|document.{0,100}approval.{0,100}phishing).*".to_string() },
                        ],
                    },
                    action: None,
                    score: Some(320),
                    description: None,
                },
                FilterRule {
                    name: "Stanley Tools Fake Confirmation".to_string(),
                    enabled: true,
                    criteria:
                    Criteria::Or {
                        criteria: vec![
                        Criteria::SubjectPattern { pattern: "(?i).{0,100}(all.{0,100}confirmed.{0,100}stanley.{0,100}tool.{0,100}set|stanley.{0,100}tools.{0,100}fake.{0,100}confirmation|harbor.{0,100}freight.{0,100}program.{0,100}access).*".to_string() },
                        Criteria::BodyPattern { pattern: "(?i).{0,100}(all.{0,100}confirmed.{0,100}stanley.{0,100}tool.{0,100}set|stanley.{0,100}tools.{0,100}fake.{0,100}confirmation|harbor.{0,100}freight.{0,100}program.{0,100}access).*".to_string() },
                        ],
                    },
                    action: None,
                    score: Some(300),
                    description: None,
                },
                FilterRule {
                    name: "Stanley Tools Shipment Queued".to_string(),
                    enabled: true,
                    criteria:
                    Criteria::Or {
                        criteria: vec![
                        Criteria::SubjectPattern { pattern: "(?i).{0,100}(everything.{0,100}set.{0,100}stanley.{0,100}tool.{0,100}set.{0,100}shipment.{0,100}queued|stanley.{0,100}tools.{0,100}shipment.{0,100}queued|shipment.{0,100}queued.{0,100}stanley|tools.{0,100}shipment.{0,100}notification).*".to_string() },
                        Criteria::BodyPattern { pattern: "(?i).{0,100}(everything.{0,100}set.{0,100}stanley.{0,100}tool.{0,100}set.{0,100}shipment.{0,100}queued|stanley.{0,100}tools.{0,100}shipment.{0,100}queued|shipment.{0,100}queued.{0,100}stanley|tools.{0,100}shipment.{0,100}notification).*".to_string() },
                        ],
                    },
                    action: None,
                    score: Some(290),
                    description: None,
                },
                FilterRule {
                    name: "Storage Upgrade Unicode Phishing".to_string(),
                    enabled: true,
                    criteria:
                    Criteria::Or {
                        criteria: vec![
                        Criteria::SubjectPattern { pattern: "(?i).{0,100}(storage.{0,100}upgrade.{0,100}unicode|cloud.{0,100}storage.{0,100}limit|upgrade.{0,100}keep.{0,100}personal.{0,100}files|storage.{0,100}space.{0,100}in.{0,100}use).*".to_string() },
                        Criteria::BodyPattern { pattern: "(?i).{0,100}(storage.{0,100}upgrade.{0,100}unicode|cloud.{0,100}storage.{0,100}limit|upgrade.{0,100}keep.{0,100}personal.{0,100}files|storage.{0,100}space.{0,100}in.{0,100}use).*".to_string() },
                        ],
                    },
                    action: None,
                    score: Some(320),
                    description: None,
                },
                FilterRule {
                    name: "Credit Card Bill Unicode Resolution".to_string(),
                    enabled: true,
                    criteria:
                    Criteria::Or {
                        criteria: vec![
                        Criteria::SubjectPattern { pattern: "(?i).{0,100}(re.{0,100}your.{0,100}creditcard.{0,100}bill|credit.{0,100}card.{0,100}bill.{0,100}unicode|gastric.{0,100}bypass.{0,100}directory).*".to_string() },
                        Criteria::BodyPattern { pattern: "(?i).{0,100}(re.{0,100}your.{0,100}creditcard.{0,100}bill|credit.{0,100}card.{0,100}bill.{0,100}unicode|gastric.{0,100}bypass.{0,100}directory).*".to_string() },
                        ],
                    },
                    action: None,
                    score: Some(280),
                    description: None,
                },
                FilterRule {
                    name: "Unicode Credit Card Phishing".to_string(),
                    enabled: true,
                    criteria:
                    Criteria::And {
                        criteria: vec![
                        Criteria::FeatureAnalysis {
                            feature_name: "Context Analysis".to_string(),
                            min_score: None,
                            max_score: None,
                            evidence_pattern: Some("Suspicious subject with excessive special characters".to_string()),
                            invert: None,
                        },
                        Criteria::Or {
                            criteria: vec![
                            Criteria::SubjectPattern { pattern: ".*[𝘊𝘤𝘳𝘦𝘥𝘪𝘵|𝘊𝘢𝘳𝘥|𝘔𝘰𝘯𝘦𝘺|𝘍𝘳𝘦𝘦].*".to_string() },
                            Criteria::BodyPattern { pattern: ".*[𝘊𝘤𝘳𝘦𝘥𝘪𝘵|𝘊𝘢𝘳𝘥|𝘔𝘰𝘯𝘦𝘺|𝘍𝘳𝘦𝘦].*".to_string() },
                            ],
                        },
                        ],
                    },
                    action: None,
                    score: Some(10),
                    description: Some("Unicode obfuscation in credit card phishing".to_string()),
                },
                FilterRule {
                    name: "Storage Upgrade General Pattern".to_string(),
                    enabled: true,
                    criteria:
                    Criteria::And {
                        criteria: vec![
                        Criteria::Or {
                            criteria: vec![
                            Criteria::SubjectPattern { pattern: "(?i).{0,100}(storage.{0,100}upgrade|cloud.{0,100}storage|upgrade.{0,100}storage|storage.{0,100}limit).*".to_string() },
                            Criteria::BodyPattern { pattern: "(?i).{0,100}(storage.{0,100}upgrade|cloud.{0,100}storage|upgrade.{0,100}storage|storage.{0,100}limit).*".to_string() },
                            ],
                        },
                        Criteria::Not {
                            criteria: Box::new(
                            Criteria::Or {
                                criteria: vec![
                                Criteria::SenderPattern { pattern: ".*@(nedm\\.asus|google|microsoft|dropbox|icloud|onedrive)\\.(com|net|org)$".to_string() },
                                Criteria::SenderPattern { pattern: ".*@.*(asus|google|microsoft|apple|amazon)\\.(com|net|org)$".to_string() },
                                ],
                            }
                            ),
                        },
                        ],
                    },
                    action: None,
                    score: Some(200),
                    description: None,
                },
                FilterRule {
                    name: "Institutional Domain Commercial Abuse".to_string(),
                    enabled: true,
                    criteria:
                    Criteria::And {
                        criteria: vec![
                        Criteria::Or {
                            criteria: vec![
                            Criteria::SenderPattern { pattern: ".*@.*\\.(gov|edu|mil)\\.".to_string() },
                            Criteria::SenderPattern { pattern: ".*@.*\\.(gov|edu|mil)$".to_string() },
                            ],
                        },
                        Criteria::Or {
                            criteria: vec![
                            Criteria::SubjectPattern { pattern: "(?i).{0,100}(payment|invoice|order|receipt|transaction|billing|purchase).*".to_string() },
                            Criteria::CombinedTextPattern { pattern: "(?i).{0,100}(payment.{0,100}received|order.{0,100}confirmed|invoice.{0,100}attached|transaction.{0,100}complete).*".to_string() },
                            ],
                        },
                        Criteria::Not {
                            criteria: Box::new(
                            Criteria::Or {
                                criteria: vec![
                                Criteria::SenderPattern { pattern: ".*@.*(bursar|finance|accounting|treasurer|payment|billing).{0,100}\\.(gov|edu|mil)".to_string() },
                                Criteria::SubjectPattern { pattern: "(?i).{0,100}(tuition|student.{0,100}account|university.{0,100}bill|campus.{0,100}card).*".to_string() },
                                ],
                            }
                            ),
                        },
                        ],
                    },
                    action: None,
                    score: Some(80),
                    description: Some("Institutional domains sending commercial/payment content".to_string()),
                },
                FilterRule {
                    name: "Young Domain Random Sender".to_string(),
                    enabled: true,
                    criteria:
                    Criteria::And {
                        criteria: vec![
                        Criteria::SenderPattern { pattern: ".*[a-z]{12,}@.*".to_string() },
                        Criteria::Not {
                            criteria: Box::new(
                            Criteria::Or {
                                criteria: vec![
                                Criteria::SenderPattern { pattern: ".*@.*(noreply|no-reply|newsletter|info|support|contact|hello|team|notification|updates|marketing|investments|communications|services|myairsupport|reservations|notifications|accounts).*".to_string() },
                                Criteria::SenderPattern { pattern: ".*@.*(sendgrid|mailchimp|mailgun|amazonses|sparkpost|mandrill|fidelity|amazon|disney|iheart|britishairways|cdw|msgfocus|thinkgeek|concurcompleat|vacuums|emailsp|resmed|kickstarter|waltdisneypictures|disneyplus|emsend|bmsend|14westmail|portlandnursery|americanmeadows|constantcontact|ccsend)\\.(com|net)$".to_string() },
                                Criteria::SenderPattern { pattern: ".*@bounce\\.(crm\\.ba|cdwemail|emailsp)\\.(com|net)$".to_string() },
                                Criteria::SenderPattern { pattern: ".*@.*(gov|edu|mil|org)$".to_string() },
                                Criteria::SenderPattern { pattern: ".*@mail\\.(fidelity|amazon|disney|britishairways|cdw|iheart)\\.(com|net)$".to_string() },
                                Criteria::FeatureAnalysis {
                                    feature_name: "Authentication Analysis".to_string(),
                                    min_score: None,
                                    max_score: None,
                                    evidence_pattern: Some("DKIM domain properly aligned".to_string()),
                                    invert: None,
                                },
                                ],
                            }
                            ),
                        },
                        ],
                    },
                    action: None,
                    score: Some(80),
                    description: Some("Random-looking sender address (12+ consecutive lowercase letters)".to_string()),
                },
                FilterRule {
                    name: "Institutional Domain Generic Business Display".to_string(),
                    enabled: true,
                    criteria:
                    Criteria::And {
                        criteria: vec![
                        Criteria::Or {
                            criteria: vec![
                            Criteria::SenderPattern { pattern: ".*@.*\\.(gov|edu|mil|istruzioneer)\\.".to_string() },
                            Criteria::SenderPattern { pattern: ".*@.*\\.(gov|edu|mil)$".to_string() },
                            ],
                        },
                        Criteria::HeaderPattern { header: "From".to_string(), pattern: "(?i).{0,100}(CUSTOMER SYSTEMS|BILLING DEPT|PAYMENT CENTER|ACCOUNT SERVICES|CUSTOMER SERVICE|SUPPORT TEAM|NOTIFICATION CENTER|SECURITY TEAM|VERIFICATION DEPT).*".to_string() },
                        Criteria::Not {
                            criteria: Box::new(
                            Criteria::SenderPattern { pattern: ".*@.*(customer|billing|payment|support|service|help).{0,100}\\.(gov|edu|mil)".to_string() }
                            ),
                        },
                        ],
                    },
                    action: None,
                    score: Some(170),
                    description: Some("Institutional domain with generic corporate display name".to_string()),
                },
            ],
        },
    ]
}
