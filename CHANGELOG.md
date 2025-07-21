# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - 2025-07-21

### Added
- Initial release of FOFF Milter
- Pattern-based email filtering with regex support
- Language detection for 7 languages (Japanese, Chinese, Korean, Arabic, Russian, Thai, Hebrew)
- Combination criteria with AND/OR logic
- Flexible actions: reject emails or tag as spam
- YAML configuration with validation
- Command-line interface with config generation and testing
- Comprehensive examples and documentation
- Unit tests with 100% pass rate
- Demonstration mode for testing rules
- Installation scripts for production deployment

### Features
- **MailerPattern**: Match against X-Mailer or User-Agent headers
- **SenderPattern**: Match against sender email addresses
- **RecipientPattern**: Match against recipient email addresses
- **SubjectPattern**: Match against email subjects
- **HeaderPattern**: Match against any email header
- **SubjectContainsLanguage**: Detect languages in email subjects
- **HeaderContainsLanguage**: Detect languages in email headers
- **And/Or Logic**: Complex rule combinations

### Examples
- Basic configuration with common spam patterns
- Sparkmail + Japanese content filtering (combination criteria)
- Comprehensive configuration with advanced rules
- Multi-language detection scenarios
- Domain-based filtering with language context

### Documentation
- Complete README with usage instructions
- Combination criteria guide with examples
- Contributing guidelines for developers
- Project summary and architecture overview
- Installation and configuration instructions

### CI/CD
- GitHub Actions workflow for automated testing
- Security audit integration
- Multi-platform build verification
- Configuration validation testing
