# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Initial release of AFDP Notary Service
- Core cryptographic notarization functionality
- HashiCorp Vault integration for secure key management
- Rekor transparency log integration
- Evidence package schema (v1.0.0)
- Comprehensive error handling and logging
- Unit and integration test suite
- Docker containerization support
- CI/CD pipeline with GitHub Actions
- Documentation and contribution guidelines

### Features
- `NotaryClient` trait with `VaultRekorNotary` implementation
- Evidence package creation and serialization
- Cryptographic signing with Vault Transit backend
- Transparency log submission to Rekor
- Notarization receipt generation and verification
- Configurable retry logic and timeouts
- Structured logging with tracing
- Prometheus metrics (planned)

### Security
- Memory-safe Rust implementation
- Zero-trust architecture design
- Secure key management via HashiCorp Vault
- Immutable audit trails via transparency logs
- Input validation and sanitization

### Documentation
- Comprehensive README with getting started guide
- API documentation with examples
- Contributing guidelines and code of conduct
- Architecture design document
- Docker deployment guide

## [0.1.0] - 2025-07-23

### Added
- Initial project structure
- Core library implementation
- Basic example demonstrating usage
- MIT license

### Note
This is the initial release of the AFDP Notary Service. While the core functionality is implemented and tested, this should be considered alpha software. Please use caution in production environments and report any issues you encounter.

### Future Roadmap
- gRPC/REST API server implementation
- Temporal workflow integration
- Enhanced monitoring and observability
- Performance optimizations
- Additional signature algorithms
- Batch processing capabilities
- Multi-tenancy support