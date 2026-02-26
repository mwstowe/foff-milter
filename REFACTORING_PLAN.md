# FOFF Milter Refactoring Plan

## Executive Summary

This document outlines a comprehensive plan to:
1. Move all hard-coded lists from Rust code to TOML configuration files
2. Migrate all YAML rules to feature-based detection
3. Improve maintainability and configurability

## Current State Analysis

### Hard-Coded Lists in Code
- **Total vec![] instances**: 250+ across feature files
- **Brand patterns**: 51 entries in brand_impersonation.rs
- **TLD definitions**: 28 entries in tld_risk.rs
- **Domain patterns**: 83 domain checks across features
- **Regex patterns**: 95 pattern definitions
- **Whitelist/exclusions**: 150+ entries across features

### YAML Rules
- **Total rules**: 244 rules across 5 files
  - authentication-validation.yaml: 16 rules
  - brand-protection.yaml: 23 rules
  - content-threats.yaml: 124 rules
  - esp-infrastructure.yaml: 35 rules
  - phishing-threats.yaml: 46 rules

### Files with Most Hard-Coded Data
1. brand_impersonation.rs: 52 vec![] instances
2. sender_alignment.rs: 35 vec![] instances
3. tld_risk.rs: 30 vec![] instances
4. link_analyzer.rs: 30 vec![] instances
5. esp_validation.rs: 28 vec![] instances
6. financial_validation.rs: 24 vec![] instances
7. context_analyzer.rs: 16 vec![] instances

---

## Phase 1: Move Hard-Coded Lists to TOML

### 1.1 Brand Impersonation (brand_impersonation.rs)

**Current State**: 
- 25+ brands with patterns and legitimate domains hard-coded
- Examples: Amazon, PayPal, Microsoft, Apple, Google, Coinbase, Kroger, AHS, etc.

**Target TOML Structure** (features/brand_impersonation.toml):
```toml
[[brands]]
name = "amazon"
patterns = ["(?i)\\bamazon\\b"]
legitimate_domains = ["amazon.com", "amazon.co.uk"]
score = 85

[[brands]]
name = "paypal"
patterns = ["(?i)\\bpaypal\\b", "(?i)\\bpay\\s*pal\\b"]
legitimate_domains = ["paypal.com", "paypal-communications.com"]
score = 85
```

**Benefits**:
- Easy to add new brands without code changes
- Per-brand scoring configuration
- Community contributions possible

---

### 1.2 TLD Risk Assessment (tld_risk.rs)

**Current State**:
- 28 TLD definitions with risk levels and abuse scores
- Examples: .live (85), .za.com (85), .sa.com (85), .pro (50), etc.

**Target TOML Structure** (features/tld_risk.toml):
```toml
[[tlds]]
tld = "live"
risk_level = "Suspicious"
abuse_score = 85
description = "Live domain - heavily abused for spam and phishing"
common_uses = ["Various, heavily abused for spam campaigns"]

[[tlds]]
tld = "za.com"
risk_level = "Suspicious"
abuse_score = 85
description = "South Africa commercial domain - heavily abused for spam"
common_uses = ["Various, heavily abused for adult/dating spam"]

[default]
risk_level = "Suspicious"
abuse_score = 30
```

**Benefits**:
- Easy TLD score adjustments
- Regional TLD management
- Default fallback configuration

---

### 1.3 ESP Validation (esp_validation.rs)

**Current State**:
- 28 vec![] instances with ESP domains and patterns
- Legitimate ESPs: SendGrid, MailChimp, Klaviyo, etc.
- ESP infrastructure patterns

**Target TOML Structure** (features/esp_validation.toml):
```toml
[[legitimate_esps]]
name = "SendGrid"
domains = ["sendgrid.net", "sendgrid.com"]
patterns = [".*sendgrid.*"]
trust_score = -10

[[legitimate_esps]]
name = "MailChimp"
domains = ["mailchimp.com", "mcdlv.net", "mailchimpapp.com"]
patterns = [".*mailchimp.*", ".*mcsv\\.net"]
trust_score = -10

[suspicious_patterns]
consumer_email_through_esp = ["outlook.com", "gmail.com", "yahoo.com", "hotmail.com"]
penalty_score = 200
```

**Benefits**:
- ESP trust scores configurable
- Easy to add new ESPs
- Separate consumer email patterns

---

### 1.4 Financial Validation (financial_validation.rs)

**Current State**:
- 24 vec![] instances with financial institutions
- Legitimate banks, payment processors
- Financial domain patterns

**Target TOML Structure** (features/financial_validation.toml):
```toml
[[financial_institutions]]
name = "Chase"
domains = ["chase.com", "chase.net"]
patterns = ["(?i)\\bchase\\b"]
trust_score = -15

[[payment_processors]]
name = "PayPal"
domains = ["paypal.com", "paypal-communications.com"]
trust_score = -15

[exclusions]
legitimate_retail = ["williams-sonoma", "499inks", "torrid"]
```

**Benefits**:
- Financial institution management
- Retail exclusion lists
- Configurable trust scores

---

### 1.5 Context Analyzer (context_analyzer.rs)

**Current State**:
- 16 vec![] instances with patterns
- Urgency patterns, scam patterns, legitimate indicators
- Regex patterns for various scam types

**Target TOML Structure** (features/context_patterns.toml):
```toml
[[urgency_patterns]]
pattern = "(?i)(urgent|immediate|act now|limited time|expires today)"
score = 15
description = "Urgency language"

[[scam_patterns]]
name = "gift_card_survey"
pattern = "(?i)\\b(you'?ll?\\s+receive.*\\$\\d+.*gift\\s*card)"
score = 60
description = "Gift card survey scam"

[[legitimate_indicators]]
pattern = "(?i)(unsubscribe|privacy policy|terms of service)"
score = -5
description = "Legitimate business indicators"

[whitelists]
legitimate_retailers = ["torrid", "michaels", "target", "walmart"]
nonprofit_domains = ["leaderswedeserve.com"]
```

**Benefits**:
- Pattern management without code changes
- Score tuning per pattern
- Whitelist management

---

### 1.6 Sender Alignment (sender_alignment.rs)

**Current State**:
- 35 vec![] instances
- Platform domains, legitimate senders
- Domain consistency checks

**Target TOML Structure** (features/sender_alignment.toml):
```toml
[[platform_domains]]
domain = "stackoverflow.com"
description = "Q&A platform"
skip_consistency_check = true

[[platform_domains]]
domain = "github.com"
description = "Development platform"
skip_consistency_check = true

[esp_alignment]
legitimate_esps = ["sendgrid.net", "mailchimp.com", "klaviyo.com"]
skip_return_path_check = true
```

**Benefits**:
- Platform domain management
- ESP alignment configuration
- Consistency check rules

---

### 1.7 Link Analyzer (link_analyzer.rs)

**Current State**:
- 30 vec![] instances
- Legitimate business relationships
- Cross-domain validation rules

**Target TOML Structure** (features/link_analysis.toml):
```toml
[[legitimate_relationships]]
sender_domain = "torrid.com"
allowed_link_domains = ["dt.torrid.com", "torrid.narvar.com"]

[[legitimate_relationships]]
sender_domain = "amazon.com"
allowed_link_domains = ["a.co", "amzn.to", "amazon.com"]

[exclusions]
esp_infrastructure = ["sendgrid.net", "mailchimp.com"]
```

**Benefits**:
- Business relationship management
- Link validation rules
- ESP infrastructure exclusions

---

### 1.8 Authentication Analysis (authentication_analysis.rs)

**Current State**:
- 7 vec![] instances
- Suspicious domain lists
- Authentication bonus reduction rules

**Target TOML Structure** (features/authentication_rules.toml):
```toml
[suspicious_domains]
tlds = [".shop", ".space", ".click", ".link", ".live", ".za.com", ".sa.com", ".pro", ".tk", ".ml", ".ga", ".cf"]
auth_bonus_reduction = 0.5  # 50% reduction

[legitimate_retail]
domains = ["torrid.com", "michaels.com", "target.com", "walmart.com"]
skip_portuguese_reduction = true

[trusted_esp_retailers]
esp_domains = ["klaviyo", "sendgrid", "sparkpost"]
retailer_domains = ["bedjet.com", "ikea.com", "amazon.com"]
bonus_score = -3
```

**Benefits**:
- Suspicious domain management
- Authentication bonus rules
- Retail/ESP combinations

---

### 1.9 Domain Reputation (domain_reputation.rs)

**Current State**:
- Already has TOML configuration (features/domain_reputation.toml)
- 10 vec![] instances for defaults

**Action**: 
- Verify all hard-coded defaults are in TOML
- Remove any remaining hard-coded lists

---

## Phase 2: Migrate YAML Rules to Features

### 2.1 Authentication Validation Rules (16 rules)

**Current YAML Rules**:
- Perfect Authentication
- DKIM Pass
- SPF Pass
- DMARC Pass
- Authentication combinations

**Migration Strategy**:
- Already handled by authentication_analysis.rs feature
- Move scoring thresholds to TOML
- Remove YAML file

**Target**: Fully feature-based with TOML configuration

---

### 2.2 Brand Protection Rules (23 rules)

**Current YAML Rules**:
- Brand-specific impersonation rules
- Domain validation rules
- ESP exclusions

**Migration Strategy**:
- Consolidate into brand_impersonation.rs feature
- Move all brand patterns to TOML
- Remove YAML file

**Target**: Single feature with TOML brand database

---

### 2.3 Content Threats Rules (124 rules)

**Current YAML Rules**:
- Empty content detection
- Suspicious patterns
- Scam detection
- Various content-based rules

**Migration Strategy**:
- Split into multiple features:
  - content_patterns.rs (general patterns)
  - scam_detection.rs (scam-specific)
  - suspicious_content.rs (suspicious indicators)
- Move patterns to TOML files
- Remove YAML file

**Target**: Feature-based detection with TOML patterns

---

### 2.4 ESP Infrastructure Rules (35 rules)

**Current YAML Rules**:
- ESP recognition
- Infrastructure validation
- Legitimate ESP patterns

**Migration Strategy**:
- Already handled by esp_validation.rs feature
- Move all ESP data to TOML
- Remove YAML file

**Target**: Fully feature-based with TOML ESP database

---

### 2.5 Phishing Threats Rules (46 rules)

**Current YAML Rules**:
- Financial phishing
- Password expiration
- Domain impersonation
- Various phishing patterns

**Migration Strategy**:
- Split into features:
  - financial_phishing.rs
  - credential_phishing.rs
  - domain_impersonation.rs (merge with existing)
- Move patterns to TOML
- Remove YAML file

**Target**: Feature-based with TOML pattern database

---

## Phase 3: Implementation Plan

### 3.1 Priority Order

**Phase 1 - High Priority** (Immediate Impact):
1. Brand Impersonation → TOML (most frequently updated)
2. TLD Risk → TOML (frequently updated)
3. Context Patterns → TOML (scam patterns change often)

**Phase 2 - Medium Priority** (Maintainability):
4. ESP Validation → TOML
5. Financial Validation → TOML
6. Authentication Rules → TOML

**Phase 3 - Lower Priority** (Less Frequent Changes):
7. Sender Alignment → TOML
8. Link Analysis → TOML
9. Domain Reputation → Verify TOML

**Phase 4 - YAML Migration**:
10. Migrate Content Threats rules (124 rules)
11. Migrate Phishing Threats rules (46 rules)
12. Migrate Brand Protection rules (23 rules)
13. Migrate ESP Infrastructure rules (35 rules)
14. Migrate Authentication Validation rules (16 rules)

---

### 3.2 Implementation Steps per Feature

For each feature migration:

1. **Create TOML Schema**
   - Define structure
   - Document fields
   - Set defaults

2. **Create Config Struct**
   - Rust struct matching TOML
   - Serde deserialization
   - Validation logic

3. **Update Feature Code**
   - Load from TOML
   - Remove hard-coded data
   - Add fallback defaults

4. **Create Migration Tool**
   - Extract current hard-coded data
   - Generate TOML file
   - Validate output

5. **Testing**
   - Verify all 448 tests pass
   - Test TOML loading
   - Test hot-reload

6. **Documentation**
   - Update README
   - Add TOML examples
   - Document configuration

---

### 3.3 YAML to Feature Migration Steps

For each YAML ruleset:

1. **Analyze Rules**
   - Categorize by function
   - Identify patterns
   - Map to features

2. **Create/Update Features**
   - Implement feature logic
   - Add TOML configuration
   - Match YAML behavior

3. **Parallel Testing**
   - Run both YAML and feature
   - Compare results
   - Verify parity

4. **Cutover**
   - Disable YAML rules
   - Enable features
   - Monitor production

5. **Cleanup**
   - Remove YAML files
   - Remove YAML loader code
   - Update documentation

---

## Phase 4: Benefits & Risks

### Benefits

**Maintainability**:
- No code changes for data updates
- Community contributions easier
- Version control for data changes

**Configurability**:
- Per-deployment customization
- Easy A/B testing
- Regional variations possible

**Performance**:
- Faster hot-reload (TOML vs YAML)
- Reduced rule engine overhead
- Better caching opportunities

**Simplicity**:
- Single configuration format (TOML)
- Feature-based architecture
- Clearer code organization

### Risks

**Migration Complexity**:
- 244 YAML rules to migrate
- 250+ hard-coded lists to extract
- Potential behavior changes

**Testing Burden**:
- Must maintain 100% test pass rate
- Need parallel testing period
- Regression risk

**Configuration Complexity**:
- More TOML files to manage
- Schema validation needed
- Documentation requirements

**Backward Compatibility**:
- Existing deployments affected
- Migration path needed
- Rollback strategy required

---

## Phase 5: Success Criteria

### Must Have
- ✅ All 448 tests passing
- ✅ Zero false positives maintained
- ✅ All hard-coded lists in TOML
- ✅ All YAML rules migrated to features
- ✅ Hot-reload working for all TOML files
- ✅ Documentation complete

### Should Have
- ✅ Migration tools for existing deployments
- ✅ Schema validation for TOML files
- ✅ Performance equal or better
- ✅ Configuration examples
- ✅ Rollback capability

### Nice to Have
- ✅ TOML editor/validator tool
- ✅ Configuration diff tool
- ✅ Automated TOML generation from examples
- ✅ Community contribution guidelines

---

## Phase 6: Timeline Estimate

**Phase 1 - High Priority TOML Migration**: 2-3 weeks
- Brand Impersonation: 3 days
- TLD Risk: 2 days
- Context Patterns: 4 days
- Testing & Documentation: 5 days

**Phase 2 - Medium Priority TOML Migration**: 2 weeks
- ESP Validation: 3 days
- Financial Validation: 3 days
- Authentication Rules: 2 days
- Testing & Documentation: 4 days

**Phase 3 - Lower Priority TOML Migration**: 1 week
- Sender Alignment: 2 days
- Link Analysis: 2 days
- Domain Reputation: 1 day
- Testing & Documentation: 2 days

**Phase 4 - YAML Migration**: 3-4 weeks
- Content Threats (124 rules): 1 week
- Phishing Threats (46 rules): 4 days
- Brand Protection (23 rules): 3 days
- ESP Infrastructure (35 rules): 3 days
- Authentication Validation (16 rules): 2 days
- Testing & Documentation: 1 week

**Total Estimated Time**: 8-10 weeks

---

## Next Steps

1. **Review & Approve Plan**
   - Stakeholder review
   - Priority confirmation
   - Timeline agreement

2. **Create Detailed Specs**
   - TOML schemas for each feature
   - Migration tool specifications
   - Testing strategy

3. **Prototype First Feature**
   - Brand Impersonation as pilot
   - Validate approach
   - Refine process

4. **Begin Phased Rollout**
   - Follow priority order
   - Maintain test coverage
   - Document learnings

---

## Appendix: File Inventory

### Current TOML Files
- features/domain_reputation.toml (already exists)
- foff-milter.toml (main config)

### TOML Files to Create
- features/brand_impersonation.toml
- features/tld_risk.toml
- features/esp_validation.toml
- features/financial_validation.toml
- features/context_patterns.toml
- features/sender_alignment.toml
- features/link_analysis.toml
- features/authentication_rules.toml

### YAML Files to Migrate/Remove
- rulesets/authentication-validation.yaml (16 rules)
- rulesets/brand-protection.yaml (23 rules)
- rulesets/content-threats.yaml (124 rules)
- rulesets/esp-infrastructure.yaml (35 rules)
- rulesets/phishing-threats.yaml (46 rules)

### Code Files to Refactor
- src/features/brand_impersonation.rs (52 vec![])
- src/features/sender_alignment.rs (35 vec![])
- src/features/tld_risk.rs (30 vec![])
- src/features/link_analyzer.rs (30 vec![])
- src/features/esp_validation.rs (28 vec![])
- src/features/financial_validation.rs (24 vec![])
- src/features/context_analyzer.rs (16 vec![])
- src/features/authentication_analysis.rs (7 vec![])
- src/features/domain_reputation.rs (verify TOML)

---

## Conclusion

This refactoring will significantly improve FOFF Milter's maintainability and configurability. The phased approach minimizes risk while delivering incremental value. The estimated 8-10 week timeline allows for careful implementation and thorough testing.

**Key Success Factor**: Maintaining 100% test pass rate and zero false positives throughout the migration.
