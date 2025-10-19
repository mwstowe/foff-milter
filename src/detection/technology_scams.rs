use super::DetectionResult;
use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct TechnologyScamsConfig {
    pub tech_support_scams: TechSupportScams,
    pub fake_software: FakeSoftware,
    pub device_hardware_scams: DeviceHardwareScams,
    pub cloud_saas_scams: CloudSaasScams,
    pub cryptocurrency_mining: CryptocurrencyMining,
    pub system_alerts: SystemAlerts,
    pub legitimate_exclusions: LegitimateExclusions,
    pub confidence_scoring: ConfidenceScoring,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct TechSupportScams {
    pub microsoft_impersonation: Vec<String>,
    pub apple_support: Vec<String>,
    pub generic_tech_support: Vec<String>,
    pub isp_impersonation: Vec<String>,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct FakeSoftware {
    pub antivirus_scams: Vec<String>,
    pub software_downloads: Vec<String>,
    pub license_fraud: Vec<String>,
    pub browser_hijacking: Vec<String>,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct DeviceHardwareScams {
    pub fake_electronics: Vec<String>,
    pub warranty_scams: Vec<String>,
    pub repair_scams: Vec<String>,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct CloudSaasScams {
    pub fake_cloud_services: Vec<String>,
    pub saas_impersonation: Vec<String>,
    pub subscription_scams: Vec<String>,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct CryptocurrencyMining {
    pub mining_software: Vec<String>,
    pub hardware_scams: Vec<String>,
    pub wallet_scams: Vec<String>,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct SystemAlerts {
    pub fake_warnings: Vec<String>,
    pub urgency_tactics: Vec<String>,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct LegitimateExclusions {
    pub tech_companies: Vec<String>,
    pub cloud_providers: Vec<String>,
    pub software_vendors: Vec<String>,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct ConfidenceScoring {
    pub cryptocurrency_mining: u32,
    pub tech_support_scams: u32,
    pub fake_software: u32,
    pub cloud_saas_scams: u32,
    pub device_hardware_scams: u32,
    pub system_alerts: u32,
}

pub struct TechnologyScamsDetector {
    config: TechnologyScamsConfig,
}

impl TechnologyScamsDetector {
    pub fn new(config: TechnologyScamsConfig) -> Self {
        Self { config }
    }

    pub fn load_from_file(path: &str) -> Result<Self, Box<dyn std::error::Error>> {
        let content = std::fs::read_to_string(path)?;
        let config: TechnologyScamsConfig = serde_yml::from_str(&content)?;
        Ok(Self::new(config))
    }

    pub fn check_technology_scam(&self, subject: &str, body: &str, _sender: &str, sender_domain: &str) -> DetectionResult {
        // Check if sender is from legitimate tech company
        if self.is_legitimate_tech_company(sender_domain) {
            return DetectionResult::no_match("TechnologyScams".to_string());
        }

        let mut confidence = 0;
        let mut reasons = Vec::new();
        let combined_text = format!("{} {}", subject, body).to_lowercase();

        // Check cryptocurrency mining (highest priority)
        if self.check_patterns(&combined_text, &self.config.cryptocurrency_mining.mining_software) ||
           self.check_patterns(&combined_text, &self.config.cryptocurrency_mining.hardware_scams) ||
           self.check_patterns(&combined_text, &self.config.cryptocurrency_mining.wallet_scams) {
            confidence += self.config.confidence_scoring.cryptocurrency_mining;
            reasons.push("Cryptocurrency mining scam detected".to_string());
        }

        // Check tech support scams
        if self.check_patterns(&combined_text, &self.config.tech_support_scams.microsoft_impersonation) ||
           self.check_patterns(&combined_text, &self.config.tech_support_scams.apple_support) ||
           self.check_patterns(&combined_text, &self.config.tech_support_scams.generic_tech_support) ||
           self.check_patterns(&combined_text, &self.config.tech_support_scams.isp_impersonation) {
            confidence += self.config.confidence_scoring.tech_support_scams;
            reasons.push("Tech support scam detected".to_string());
        }

        // Check fake software
        if self.check_patterns(&combined_text, &self.config.fake_software.antivirus_scams) ||
           self.check_patterns(&combined_text, &self.config.fake_software.software_downloads) ||
           self.check_patterns(&combined_text, &self.config.fake_software.license_fraud) ||
           self.check_patterns(&combined_text, &self.config.fake_software.browser_hijacking) {
            confidence += self.config.confidence_scoring.fake_software;
            reasons.push("Fake software scam detected".to_string());
        }

        // Check cloud/SaaS scams
        if self.check_patterns(&combined_text, &self.config.cloud_saas_scams.fake_cloud_services) ||
           self.check_patterns(&combined_text, &self.config.cloud_saas_scams.saas_impersonation) ||
           self.check_patterns(&combined_text, &self.config.cloud_saas_scams.subscription_scams) {
            confidence += self.config.confidence_scoring.cloud_saas_scams;
            reasons.push("Cloud/SaaS scam detected".to_string());
        }

        // Check device/hardware scams
        if self.check_patterns(&combined_text, &self.config.device_hardware_scams.fake_electronics) ||
           self.check_patterns(&combined_text, &self.config.device_hardware_scams.warranty_scams) ||
           self.check_patterns(&combined_text, &self.config.device_hardware_scams.repair_scams) {
            confidence += self.config.confidence_scoring.device_hardware_scams;
            reasons.push("Device/hardware scam detected".to_string());
        }

        // Check system alerts
        if self.check_patterns(&combined_text, &self.config.system_alerts.fake_warnings) ||
           self.check_patterns(&combined_text, &self.config.system_alerts.urgency_tactics) {
            confidence += self.config.confidence_scoring.system_alerts;
            reasons.push("Fake system alert detected".to_string());
        }

        let matched = confidence > 0;
        let reason = if reasons.is_empty() {
            "No technology scam indicators".to_string()
        } else {
            reasons.join(", ")
        };

        DetectionResult::new(matched, confidence, reason, "TechnologyScams".to_string())
    }

    fn check_patterns(&self, text: &str, patterns: &[String]) -> bool {
        patterns.iter().any(|pattern| text.contains(pattern))
    }

    fn is_legitimate_tech_company(&self, domain: &str) -> bool {
        let all_legitimate = [
            &self.config.legitimate_exclusions.tech_companies,
            &self.config.legitimate_exclusions.cloud_providers,
            &self.config.legitimate_exclusions.software_vendors,
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
        patterns.extend(self.config.tech_support_scams.microsoft_impersonation.clone());
        patterns.extend(self.config.tech_support_scams.apple_support.clone());
        patterns.extend(self.config.tech_support_scams.generic_tech_support.clone());
        patterns.extend(self.config.tech_support_scams.isp_impersonation.clone());
        patterns.extend(self.config.fake_software.antivirus_scams.clone());
        patterns.extend(self.config.fake_software.software_downloads.clone());
        patterns.extend(self.config.fake_software.license_fraud.clone());
        patterns.extend(self.config.fake_software.browser_hijacking.clone());
        patterns.extend(self.config.device_hardware_scams.fake_electronics.clone());
        patterns.extend(self.config.device_hardware_scams.warranty_scams.clone());
        patterns.extend(self.config.device_hardware_scams.repair_scams.clone());
        patterns.extend(self.config.cloud_saas_scams.fake_cloud_services.clone());
        patterns.extend(self.config.cloud_saas_scams.saas_impersonation.clone());
        patterns.extend(self.config.cloud_saas_scams.subscription_scams.clone());
        patterns.extend(self.config.cryptocurrency_mining.mining_software.clone());
        patterns.extend(self.config.cryptocurrency_mining.hardware_scams.clone());
        patterns.extend(self.config.cryptocurrency_mining.wallet_scams.clone());
        patterns.extend(self.config.system_alerts.fake_warnings.clone());
        patterns.extend(self.config.system_alerts.urgency_tactics.clone());
        patterns.sort();
        patterns.dedup();
        patterns
    }
}
