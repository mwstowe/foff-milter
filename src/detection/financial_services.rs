use super::DetectionResult;
use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct FinancialServicesConfig {
    pub banking_phishing: BankingPhishing,
    pub credit_loan_scams: CreditLoanScams,
    pub investment_fraud: InvestmentFraud,
    pub government_impersonation: GovernmentImpersonation,
    pub insurance_fraud: InsuranceFraud,
    pub financial_urgency: FinancialUrgency,
    pub legitimate_exclusions: LegitimateExclusions,
    pub confidence_scoring: ConfidenceScoring,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct BankingPhishing {
    pub major_banks: Vec<String>,
    pub credit_unions: Vec<String>,
    pub online_banks: Vec<String>,
    pub payment_processors: Vec<String>,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct CreditLoanScams {
    pub credit_cards: Vec<String>,
    pub personal_loans: Vec<String>,
    pub mortgage_scams: Vec<String>,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct InvestmentFraud {
    pub stock_manipulation: Vec<String>,
    pub cryptocurrency_scams: Vec<String>,
    pub retirement_fraud: Vec<String>,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct GovernmentImpersonation {
    pub irs_scams: Vec<String>,
    pub social_security: Vec<String>,
    pub treasury_scams: Vec<String>,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct InsuranceFraud {
    pub health_insurance: Vec<String>,
    pub auto_insurance: Vec<String>,
    pub life_insurance: Vec<String>,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct FinancialUrgency {
    pub account_threats: Vec<String>,
    pub payment_demands: Vec<String>,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct LegitimateExclusions {
    pub major_banks: Vec<String>,
    pub government_agencies: Vec<String>,
    pub financial_services: Vec<String>,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct ConfidenceScoring {
    pub government_impersonation: u32,
    pub investment_fraud: u32,
    pub banking_phishing: u32,
    pub credit_loan_scams: u32,
    pub insurance_fraud: u32,
    pub financial_urgency: u32,
}

pub struct FinancialServicesDetector {
    config: FinancialServicesConfig,
}

impl FinancialServicesDetector {
    pub fn new(config: FinancialServicesConfig) -> Self {
        Self { config }
    }

    pub fn load_from_file(path: &str) -> Result<Self, Box<dyn std::error::Error>> {
        let content = std::fs::read_to_string(path)?;
        let config: FinancialServicesConfig = serde_yml::from_str(&content)?;
        Ok(Self::new(config))
    }

    pub fn check_financial_scam(
        &self,
        subject: &str,
        body: &str,
        _sender: &str,
        sender_domain: &str,
    ) -> DetectionResult {
        // Check if sender is from legitimate financial institution
        if self.is_legitimate_financial_institution(sender_domain) {
            return DetectionResult::no_match("FinancialServices".to_string());
        }

        let mut confidence = 0;
        let mut reasons = Vec::new();
        let combined_text = format!("{} {}", subject, body).to_lowercase();

        // Check government impersonation (highest priority)
        if self.check_patterns(
            &combined_text,
            &self.config.government_impersonation.irs_scams,
        ) || self.check_patterns(
            &combined_text,
            &self.config.government_impersonation.social_security,
        ) || self.check_patterns(
            &combined_text,
            &self.config.government_impersonation.treasury_scams,
        ) {
            confidence += self.config.confidence_scoring.government_impersonation;
            reasons.push("Government impersonation detected".to_string());
        }

        // Check investment fraud
        if self.check_patterns(
            &combined_text,
            &self.config.investment_fraud.stock_manipulation,
        ) || self.check_patterns(
            &combined_text,
            &self.config.investment_fraud.cryptocurrency_scams,
        ) || self.check_patterns(
            &combined_text,
            &self.config.investment_fraud.retirement_fraud,
        ) {
            confidence += self.config.confidence_scoring.investment_fraud;
            reasons.push("Investment fraud detected".to_string());
        }

        // Check banking phishing
        if self.check_patterns(&combined_text, &self.config.banking_phishing.major_banks)
            || self.check_patterns(&combined_text, &self.config.banking_phishing.credit_unions)
            || self.check_patterns(&combined_text, &self.config.banking_phishing.online_banks)
            || self.check_patterns(
                &combined_text,
                &self.config.banking_phishing.payment_processors,
            )
        {
            confidence += self.config.confidence_scoring.banking_phishing;
            reasons.push("Banking phishing detected".to_string());
        }

        // Check credit/loan scams
        if self.check_patterns(&combined_text, &self.config.credit_loan_scams.credit_cards)
            || self.check_patterns(
                &combined_text,
                &self.config.credit_loan_scams.personal_loans,
            )
            || self.check_patterns(
                &combined_text,
                &self.config.credit_loan_scams.mortgage_scams,
            )
        {
            confidence += self.config.confidence_scoring.credit_loan_scams;
            reasons.push("Credit/loan scam detected".to_string());
        }

        // Check insurance fraud
        if self.check_patterns(
            &combined_text,
            &self.config.insurance_fraud.health_insurance,
        ) || self.check_patterns(&combined_text, &self.config.insurance_fraud.auto_insurance)
            || self.check_patterns(&combined_text, &self.config.insurance_fraud.life_insurance)
        {
            confidence += self.config.confidence_scoring.insurance_fraud;
            reasons.push("Insurance fraud detected".to_string());
        }

        // Check financial urgency patterns
        if self.check_patterns(
            &combined_text,
            &self.config.financial_urgency.account_threats,
        ) || self.check_patterns(
            &combined_text,
            &self.config.financial_urgency.payment_demands,
        ) {
            confidence += self.config.confidence_scoring.financial_urgency;
            reasons.push("Financial urgency tactics detected".to_string());
        }

        let matched = confidence > 0;
        let reason = if reasons.is_empty() {
            "No financial scam indicators".to_string()
        } else {
            reasons.join(", ")
        };

        DetectionResult::new(matched, confidence, reason, "FinancialServices".to_string())
    }

    fn check_patterns(&self, text: &str, patterns: &[String]) -> bool {
        patterns.iter().any(|pattern| text.contains(pattern))
    }

    fn is_legitimate_financial_institution(&self, domain: &str) -> bool {
        let all_legitimate = [
            &self.config.legitimate_exclusions.major_banks,
            &self.config.legitimate_exclusions.government_agencies,
            &self.config.legitimate_exclusions.financial_services,
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
        patterns.extend(self.config.banking_phishing.major_banks.clone());
        patterns.extend(self.config.banking_phishing.credit_unions.clone());
        patterns.extend(self.config.banking_phishing.online_banks.clone());
        patterns.extend(self.config.banking_phishing.payment_processors.clone());
        patterns.extend(self.config.credit_loan_scams.credit_cards.clone());
        patterns.extend(self.config.credit_loan_scams.personal_loans.clone());
        patterns.extend(self.config.credit_loan_scams.mortgage_scams.clone());
        patterns.extend(self.config.investment_fraud.stock_manipulation.clone());
        patterns.extend(self.config.investment_fraud.cryptocurrency_scams.clone());
        patterns.extend(self.config.investment_fraud.retirement_fraud.clone());
        patterns.extend(self.config.government_impersonation.irs_scams.clone());
        patterns.extend(self.config.government_impersonation.social_security.clone());
        patterns.extend(self.config.government_impersonation.treasury_scams.clone());
        patterns.extend(self.config.insurance_fraud.health_insurance.clone());
        patterns.extend(self.config.insurance_fraud.auto_insurance.clone());
        patterns.extend(self.config.insurance_fraud.life_insurance.clone());
        patterns.extend(self.config.financial_urgency.account_threats.clone());
        patterns.extend(self.config.financial_urgency.payment_demands.clone());
        patterns.sort();
        patterns.dedup();
        patterns
    }
}
