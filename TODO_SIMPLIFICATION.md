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

## Phase 2: Migrate Functionality Component by Component (IN PROGRESS)

### FilterEngine V2 Integration
- [x] Create `FilterEngineV2` with new component architecture
- [x] Implement component-based evaluation pipeline
- [x] Add migration validation tests (4/4 passing)
- [x] Verify compatibility with existing MailContext structure
- [ ] Integrate with existing milter interface
- [ ] Performance benchmarking vs original FilterEngine
- [ ] Gradual rollout with feature flag

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
