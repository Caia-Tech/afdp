# Contributing to AFDP Notary Service

Thank you for your interest in contributing to the AFDP Notary Service! This document provides guidelines for contributors.

## 🤝 Code of Conduct

We are committed to providing a welcoming and inclusive environment for all contributors. Be respectful, constructive, and professional in all interactions.

## 🚀 Getting Started

### Prerequisites

```bash
# Required tools
- Rust 1.70+ (https://rustup.rs/)
- Git
- Docker and Docker Compose
```

### Development Setup

```bash
# Clone and setup
git clone https://github.com/YOUR_USERNAME/afdp-notary-service.git
cd afdp-notary-service

# Run tests
cargo test

# Start development environment
docker-compose up -d
```

## 📝 Coding Standards

- Follow standard Rust formatting (`cargo fmt`)
- Use meaningful variable names
- Add tests for new functionality
- Update documentation for API changes
- Never log sensitive data (keys, tokens, etc.)

## 🧪 Testing

```bash
# Run all tests
cargo test

# Run integration tests
cargo test --features integration-tests

# Security audit
cargo audit
```

## 🔒 Security Guidelines

### Reporting Vulnerabilities

**DO NOT** create public issues for security vulnerabilities.

Report to: **security@caiatech.com**

Include:
- Detailed description
- Reproduction steps
- Potential impact assessment

## 🔄 Pull Request Process

1. **Fork** the repository
2. **Create** a feature branch (`git checkout -b feat/amazing-feature`)
3. **Commit** your changes (`git commit -m 'Add amazing feature'`)
4. **Test** thoroughly
5. **Push** to your branch (`git push origin feat/amazing-feature`)
6. **Create** a Pull Request

### PR Requirements

- [ ] All tests pass
- [ ] Code follows style guidelines
- [ ] Documentation updated
- [ ] Security implications considered
- [ ] No sensitive data in commits

## 📚 Documentation

- Update code comments for complex logic
- Add examples for new APIs
- Update README for significant changes
- Include security considerations

## 🏷️ Issue Labels

- `good first issue` - Perfect for newcomers
- `help wanted` - Community input needed
- `security` - Security-related issues
- `documentation` - Documentation improvements

## ⚖️ Legal

By contributing, you agree that:
- Your contributions are your original work
- You have the right to submit under the project license
- Your contributions may be distributed under the MIT License

## 📞 Getting Help

- **GitHub Issues**: Bug reports and feature requests
- **GitHub Discussions**: Design discussions
- **Email**: contributors@caiatech.com

---

**Thank you for helping make AI deployment more transparent and secure!**