# TODO: Migrate Regex Patterns to Feature-Based Analysis

## Priority 1: High Impact (Security Critical)

### 1.1 Domain Reputation Analysis ✅ COMPLETED
- **Current**: 184+ regex patterns for domain validation
- **Target**: Centralized domain reputation feature
- **Files**: All rulesets (especially `phishing-threats.yaml`, `brand-protection.yaml`)
- **Benefit**: Eliminate hard-coded domain lists, improve accuracy
- **Status**: ✅ Implemented `DomainReputationFeature` with comprehensive domain classification
- **Impact**: +30 score for suspicious domains (e.g., `.shop` TLD), -15 for financial institutions
- **Examples**:
  ```yaml
  # Replace: pattern: ".*@.*(paypal|stripe|square)\\.(com|org)$"
  # With: feature: "domain_reputation", condition: "is_legitimate_financial"
  ```

### 1.2 Brand Impersonation Detection ✅ COMPLETED
- **Current**: 71+ regex patterns for brand names
- **Target**: Enhanced brand impersonation feature using `brands.toml`
- **Files**: `brand-protection.yaml`, `phishing-threats.yaml`
- **Benefit**: Centralized brand data, context-aware detection
- **Status**: ✅ Implemented `BrandImpersonationFeature` with domain mimicking detection
- **Impact**: +40-100 score for suspicious domains mimicking brands (e.g., fake-microsoft.com)
- **Approach**: Only flags domains that contain brand names, not content mentions
- **Examples**:
  ```yaml
  # Replace: pattern: "(?i).*(microsoft.*security|apple.*security).*"
  # With: feature: "brand_impersonation", condition: "suspicious_security_claim"
  ```

### 1.3 Financial Institution Validation ✅ COMPLETED
- **Current**: 69+ regex patterns for banks/financial services
- **Target**: Financial institution alignment feature
- **Files**: `phishing-threats.yaml`, `authentication-validation.yaml`
- **Benefit**: Prevent financial phishing, improve sender validation
- **Status**: ✅ Implemented `FinancialValidationFeature` with domain mimicking detection
- **Impact**: +50-100 score for domains mimicking financial institutions, -15 boost for legitimate ones
- **Approach**: Only flags domains that contain financial institution names, not content mentions
- **Examples**:
  ```yaml
  # Replace: pattern: "(?i).*(chase|wellsfargo|bankofamerica).*"
  # With: feature: "financial_alignment", condition: "institution_mismatch"
  ```

## Priority 2: Medium Impact (Performance & Maintainability)

### 2.1 ESP (Email Service Provider) Consolidation
- **Current**: Scattered ESP patterns across multiple files
- **Target**: Unified ESP validation feature
- **Files**: `esp-infrastructure.yaml`, scattered patterns in other files
- **Benefit**: Centralized ESP logic, better infrastructure validation
- **Status**: Partially implemented, needs consolidation

### 2.2 TLD Risk Assessment
- **Current**: Hard-coded suspicious TLD patterns
- **Target**: Dynamic TLD reputation scoring
- **Files**: `content-threats.yaml` (suspicious TLD rules)
- **Benefit**: Easier TLD list updates, risk-based scoring

### 2.3 Authentication Pattern Optimization
- **Current**: Regex patterns for DKIM/SPF validation
- **Target**: Enhanced authentication analysis feature
- **Files**: `authentication-validation.yaml`
- **Benefit**: Better authentication context analysis

## Priority 3: Low Impact (Nice to Have)

### 3.1 Content Pattern Analysis
- **Current**: Complex regex for spam content detection
- **Target**: ML-based or heuristic content analysis
- **Files**: `content-threats.yaml` (health misinformation, etc.)
- **Benefit**: More accurate content classification

### 3.2 URL/Link Analysis Enhancement
- **Current**: Basic URL regex patterns
- **Target**: Enhanced link reputation and analysis
- **Files**: Various files with URL patterns
- **Benefit**: Better phishing link detection

## Implementation Strategy

### Phase 1: Foundation (Priority 1.1)
1. Create `DomainReputationAnalyzer` feature
2. Migrate most common domain patterns
3. Test against existing test suite

### Phase 2: Security (Priority 1.2, 1.3)
1. Enhance brand impersonation detection
2. Create financial institution validator
3. Comprehensive security testing

### Phase 3: Infrastructure (Priority 2.1, 2.2)
1. Consolidate ESP validation
2. Implement dynamic TLD scoring
3. Performance optimization

### Phase 4: Advanced (Priority 2.3, 3.x)
1. Advanced authentication analysis
2. Content analysis improvements
3. Link analysis enhancements

## Success Metrics
- ✅ Reduce regex pattern count by 70%+
- ✅ Maintain 100% test compliance
- ✅ Improve performance (fewer regex operations)
- ✅ Easier maintenance (centralized data files)
- ✅ Better accuracy (context-aware analysis)

## Current Status
- **Total Regex Patterns**: ~324
- **Target Reduction**: ~227 patterns (70%)
- **Test Compliance**: 379/379 (100%) - must maintain
- **Performance Baseline**: TBD (measure before migration)
