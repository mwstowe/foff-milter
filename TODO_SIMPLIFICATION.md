# FOFF Milter Architectural Simplification TODO

## Overview
Simplify and reorganize FOFF Milter architecture while maintaining 100% test suite success.

## Phase 1: Create New Simplified Components (✅ COMPLETED)

### Core Components to Create
- [x] `src/components/mod.rs` - Component module definitions
- [x] `src/components/email_normalizer_v2.rs` - Single normalization entry point
- [x] `src/components/authentication_analyzer.rs` - Complete auth validation  
- [x] `src/components/early_decision_engine.rs` - All early exits
- [x] `src/components/context_analyzer_v2.rs` - Unified trust/business/seasonal
- [x] `src/components/mismatch_analyzer.rs` - All alignment checks
- [x] `src/components/decision_engine.rs` - Threshold evaluation and action
- [ ] `src/components/rule_engine_v2.rs` - Simplified rule processing (OPTIONAL)

### Configuration Simplification
- [ ] Create `config/simplified_modules/` directory
- [ ] `esp-infrastructure.yaml` - Merge all ESP whitelists
- [ ] `brand-protection.yaml` - Merge all brand impersonation  
- [ ] `phishing-threats.yaml` - Merge all phishing detection
- [ ] `content-threats.yaml` - Merge all content analysis
- [ ] `authentication-validation.yaml` - Merge all authentication rules

## Phase 2: Migrate Functionality Component by Component

### EmailNormalizer Migration
- [ ] Move all normalization logic to single component
- [ ] Remove duplicate normalization from FilterEngine
- [ ] Update tests to use new normalizer
- [ ] Verify 100% test suite success

### Authentication Migration  
- [ ] Extract all DKIM/SPF/DMARC logic
- [ ] Create unified authentication results structure
- [ ] Remove auth logic from individual rules
- [ ] Update rule system to consume auth results

### Mismatch Analysis Migration
- [ ] Consolidate sender alignment logic
- [ ] Merge link analysis functionality  
- [ ] Unify domain/content mismatch detection
- [ ] Remove duplicate mismatch code from rules

### Context Analysis Migration
- [ ] Merge trust_analyzer, business_analyzer, seasonal_analyzer
- [ ] Simplify to 3-4 key metrics from 12+ sub-scores
- [ ] Move to preprocessing phase
- [ ] Update rule consumption of context data

### Rule System Migration
- [ ] Merge ESP whitelist modules (5 → 1)
- [ ] Merge brand impersonation modules (3 → 1)
- [ ] Merge phishing detection modules (2 → 1)
- [ ] Consolidate content analysis modules (8 → 1)
- [ ] Remove disabled modules
- [ ] Standardize criteria types

## Phase 3: Remove Old Scattered Logic

### Code Cleanup
- [ ] Remove old normalization code from FilterEngine
- [ ] Remove duplicate authentication checks
- [ ] Remove scattered mismatch logic
- [ ] Remove old feature extractors
- [ ] Clean up unused imports and functions

### Configuration Cleanup  
- [ ] Remove old module files
- [ ] Consolidate TOML/YAML configuration
- [ ] Remove duplicate whitelist/blocklist definitions
- [ ] Standardize configuration structure

## Phase 4: Final Consolidation and Cleanup

### Architecture Finalization
- [ ] Update FilterEngine to use new components
- [ ] Implement linear processing flow
- [ ] Remove complex interdependencies
- [ ] Optimize performance paths

### Testing and Validation
- [ ] Verify 100% test suite success throughout
- [ ] Add component-level unit tests
- [ ] Performance benchmarking
- [ ] Documentation updates

### Final Cleanup
- [ ] Remove all old code paths
- [ ] Update README and documentation
- [ ] Version bump to 0.9.0
- [ ] Create migration guide

## Success Criteria

- [ ] Maintain 100% test suite success (336/336)
- [ ] Reduce module count from 38 to ~12
- [ ] Simplify component architecture (9 → 7 components)
- [ ] Eliminate code duplication
- [ ] Improve maintainability and debugging
- [ ] Preserve all current functionality

## Current Status

**Phase 1**: Starting - Creating new simplified components
**Target Completion**: Phase 1 by end of session
**Overall Timeline**: Complete simplification over multiple sessions

## Notes

- Each phase must maintain 100% test suite success
- New components created alongside existing (no breaking changes)
- Migration happens incrementally with validation at each step
- Old code removed only after new components proven stable
