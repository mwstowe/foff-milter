# Contributing to FOFF Milter

Thank you for your interest in contributing to FOFF Milter! This document provides guidelines for contributing to the project.

## Development Setup

### Prerequisites

- Rust 1.70 or later
- Git
- A text editor or IDE with Rust support

### Getting Started

1. Fork the repository on GitHub
2. Clone your fork locally:
   ```bash
   git clone https://github.com/YOUR_USERNAME/foff-milter.git
   cd foff-milter
   ```
3. Build the project:
   ```bash
   cargo build
   ```
4. Run tests:
   ```bash
   cargo test
   ```

## Development Workflow

### Before Making Changes

1. Create a new branch for your feature/fix:
   ```bash
   git checkout -b feature/your-feature-name
   ```

2. Make sure all tests pass:
   ```bash
   ./test_config.sh
   ```

### Making Changes

1. **Code Style**: Follow Rust conventions and run `cargo fmt` before committing
2. **Testing**: Add tests for new functionality
3. **Documentation**: Update documentation for new features
4. **Configuration**: Add example configurations for new criteria types

### Testing Your Changes

1. **Unit Tests**:
   ```bash
   cargo test
   ```

2. **Configuration Validation**:
   ```bash
   cargo build --release
   ./target/release/foff-milter --test-config -c config.yaml
   ./target/release/foff-milter --test-config -c examples/sparkmail-japanese.yaml
   ```

3. **Demonstration Mode**:
   ```bash
   ./target/release/foff-milter -v -c examples/combination-criteria.yaml
   ```

4. **Linting**:
   ```bash
   cargo clippy -- -D warnings
   ```

### Submitting Changes

1. **Commit Messages**: Use clear, descriptive commit messages:
   ```
   Add support for Thai language detection
   
   - Implement Thai Unicode range detection
   - Add unit tests for Thai text recognition
   - Update documentation with Thai language support
   ```

2. **Push to Your Fork**:
   ```bash
   git push origin feature/your-feature-name
   ```

3. **Create Pull Request**: Open a pull request on GitHub with:
   - Clear description of changes
   - Reference to any related issues
   - Test results and examples

## Types of Contributions

### Bug Reports

When reporting bugs, please include:
- Rust version (`rustc --version`)
- Operating system
- Configuration file (sanitized)
- Steps to reproduce
- Expected vs actual behavior
- Log output (with `-v` flag)

### Feature Requests

For new features, please provide:
- Use case description
- Proposed configuration syntax
- Example scenarios
- Potential implementation approach

### Code Contributions

We welcome contributions in these areas:

#### New Criteria Types
- Additional language detection
- Content analysis (attachment types, etc.)
- Network-based criteria (DNS lookups, etc.)
- Time-based filtering

#### New Action Types
- Custom header modification
- Quarantine actions
- Notification systems
- Integration with external systems

#### Performance Improvements
- Regex optimization
- Caching mechanisms
- Async processing
- Memory usage optimization

#### Documentation
- Usage examples
- Configuration guides
- Integration tutorials
- API documentation

## Code Guidelines

### Rust Style

- Follow the [Rust Style Guide](https://doc.rust-lang.org/nightly/style-guide/)
- Use `cargo fmt` for formatting
- Address all `cargo clippy` warnings
- Write comprehensive tests

### Error Handling

- Use `anyhow::Result` for error propagation
- Provide meaningful error messages
- Log errors appropriately
- Handle edge cases gracefully

### Configuration

- Maintain backward compatibility when possible
- Validate configuration thoroughly
- Provide clear error messages for invalid configs
- Add examples for new features

### Testing

- Write unit tests for all new functionality
- Include integration tests for complex features
- Test error conditions and edge cases
- Maintain high test coverage

### Documentation

- Update README.md for new features
- Add examples to the `examples/` directory
- Document configuration options
- Include usage examples in code comments

## Project Structure

```
foff-milter/
├── src/
│   ├── main.rs          # CLI application
│   ├── lib.rs           # Library exports
│   ├── config.rs        # Configuration handling
│   ├── filter.rs        # Filter engine
│   ├── language.rs      # Language detection
│   └── milter.rs        # Milter implementation
├── examples/            # Configuration examples
├── .github/workflows/   # CI/CD workflows
└── docs/               # Additional documentation
```

## Release Process

1. Update version in `Cargo.toml`
2. Update `CHANGELOG.md` (if exists)
3. Create release tag
4. GitHub Actions will build and test
5. Manual verification of release artifacts

## Getting Help

- Open an issue for questions
- Check existing issues and documentation
- Review example configurations
- Run with `-v` flag for detailed logging

## Code of Conduct

- Be respectful and inclusive
- Focus on constructive feedback
- Help others learn and contribute
- Follow GitHub's community guidelines

Thank you for contributing to FOFF Milter!
