# Repository Analysis Service - Testing Documentation

## Overview

The Repository Analysis Service includes a comprehensive test suite covering unit tests, integration tests, and performance tests. This document describes how to run and maintain the tests.

## Test Structure

```
tests/
├── integration/
│   ├── mod.rs              # Test context and utilities
│   ├── api_tests.rs        # REST/gRPC API tests
│   ├── storage_tests.rs    # Storage layer tests
│   ├── analysis_tests.rs   # Analysis engine tests
│   ├── event_tests.rs      # Event publishing tests
│   └── forensics_tests.rs  # Forensics functionality tests
├── test_runner.rs          # Main test orchestrator
└── fixtures/               # Test data and repositories
```

## Prerequisites

### Local Development

1. **PostgreSQL** (v14+)
   ```bash
   # macOS
   brew install postgresql@14
   brew services start postgresql@14
   
   # Linux
   sudo apt-get install postgresql-14
   sudo systemctl start postgresql
   ```

2. **Qdrant** (Vector Database)
   ```bash
   docker run -p 6333:6333 -p 6334:6334 qdrant/qdrant
   ```

3. **Apache Pulsar** (Optional for event tests)
   ```bash
   docker run -it -p 6650:6650 -p 8080:8080 \
     apachepulsar/pulsar:3.0.0 bin/pulsar standalone
   ```

### Docker Environment

Use the provided docker-compose for a complete test environment:

```bash
docker-compose -f docker-compose.test.yml up -d
```

## Running Tests

### Quick Start

```bash
# Run all tests with Docker
./scripts/run-tests.sh --docker

# Run only unit tests
./scripts/run-tests.sh --mode unit

# Run with verbose output
./scripts/run-tests.sh --verbose

# Generate code coverage
./scripts/run-tests.sh --coverage
```

### Manual Test Execution

```bash
# Unit tests only
cargo test --lib

# Integration tests
cargo test --test '*' -- --test-threads=1

# Specific test suite
cargo test integration::analysis_tests

# With logging
RUST_LOG=debug cargo test -- --nocapture
```

### Performance Tests

```bash
# Run performance tests
RUN_PERF_TESTS=true cargo test --release performance

# Benchmark specific operations
cargo bench --bench analysis_benchmark
```

## Test Categories

### 1. Unit Tests

Located in `src/*/mod.rs` files, testing individual components:

- **Storage Layer**: CRUD operations, transactions
- **Analysis Components**: File analysis, security scanning, ML operations
- **Event System**: Event creation, serialization, filtering
- **Forensics**: Hashing, signatures, chain of custody

### 2. Integration Tests

#### API Tests (`api_tests.rs`)
- Job submission and status tracking
- Results retrieval
- Similarity search
- Authentication and authorization
- Rate limiting

#### Storage Tests (`storage_tests.rs`)
- PostgreSQL operations
- Object storage (S3/MinIO)
- Vector storage (Qdrant)
- Transaction consistency
- Concurrent access

#### Analysis Tests (`analysis_tests.rs`)
- File type detection and analysis
- Security vulnerability detection
- Code quality analysis
- ML-based similarity detection
- Git history analysis
- Comprehensive repository scanning

#### Event Tests (`event_tests.rs`)
- Security event publishing
- Alert broadcasting
- Event filtering and routing
- Distribution configuration
- Encryption and acknowledgment

#### Forensics Tests (`forensics_tests.rs`)
- Chain of custody tracking
- Evidence integrity verification
- Multi-algorithm hashing
- Digital signatures
- Legal hold functionality
- Evidence export

### 3. Performance Tests

- Large repository analysis (1000+ files)
- Concurrent job processing
- Memory usage under load
- Event throughput
- Storage performance

## Test Data

### Sample Repositories

The test suite creates various test repositories with:

- **Security Issues**: Hardcoded secrets, API keys, passwords
- **Vulnerabilities**: SQL injection, command injection, XSS
- **Malware Patterns**: Backdoors, suspicious network code
- **Code Quality Issues**: Complex functions, duplicated code
- **PII Data**: SSNs, credit cards, personal information

### Fixtures

Test fixtures are created dynamically in temporary directories:

```rust
let repo_path = context.create_test_repository("test-repo").await?;
```

## Continuous Integration

### GitHub Actions Workflow

```yaml
name: Test Suite
on: [push, pull_request]

jobs:
  test:
    runs-on: ubuntu-latest
    services:
      postgres:
        image: postgres:15
        env:
          POSTGRES_PASSWORD: postgres
        options: >-
          --health-cmd pg_isready
          --health-interval 10s
          --health-timeout 5s
          --health-retries 5
      
      qdrant:
        image: qdrant/qdrant
        ports:
          - 6333:6333

    steps:
      - uses: actions/checkout@v3
      - uses: actions-rs/toolchain@v1
        with:
          toolchain: stable
      
      - name: Run tests
        run: cargo test --all-features
        env:
          DATABASE_URL: postgresql://postgres:postgres@localhost/test
```

## Debugging Tests

### Enable Detailed Logging

```bash
RUST_LOG=repository_analysis_service=trace cargo test -- --nocapture
```

### Run Single Test

```bash
cargo test test_security_scanning -- --exact --nocapture
```

### Test Database Access

```bash
# Connect to test database
psql postgresql://afdp_repo:test_password@localhost:5432/afdp_repository_analysis

# View test data
\dt  # List tables
SELECT * FROM analysis_jobs LIMIT 5;
SELECT * FROM security_findings WHERE severity = 'CRITICAL';
```

### Inspect Vector Storage

```bash
# Qdrant dashboard
open http://localhost:6333/dashboard

# API check
curl http://localhost:6333/collections
```

## Common Issues

### Port Conflicts

If services fail to start due to port conflicts:

```bash
# Check what's using the ports
lsof -i :5432  # PostgreSQL
lsof -i :6333  # Qdrant
lsof -i :6650  # Pulsar

# Use different ports in docker-compose
POSTGRES_PORT=5433 docker-compose -f docker-compose.test.yml up
```

### Database Migrations

```bash
# Reset test database
dropdb afdp_repository_analysis_test
createdb afdp_repository_analysis_test

# Run migrations
cargo run -- migrate
```

### Slow Tests

For faster test execution:

```bash
# Skip integration tests
cargo test --lib

# Run tests in parallel
cargo test -- --test-threads=4

# Use test database transactions
# Tests automatically rollback changes
```

## Writing New Tests

### Test Template

```rust
#[cfg(test)]
mod tests {
    use super::*;
    
    #[tokio::test]
    async fn test_new_feature() {
        // Arrange
        let context = TestContext::new().await.unwrap();
        let test_data = create_test_data();
        
        // Act
        let result = perform_operation(&test_data).await.unwrap();
        
        // Assert
        assert_eq!(result.status, ExpectedStatus);
        assert!(result.data.contains("expected"));
        
        // Cleanup
        context.cleanup().await.unwrap();
    }
}
```

### Best Practices

1. **Isolation**: Each test should be independent
2. **Cleanup**: Always clean up test data
3. **Assertions**: Use descriptive assertion messages
4. **Timeouts**: Set reasonable timeouts for async operations
5. **Mocking**: Mock external services when appropriate

## Test Coverage

Generate coverage reports:

```bash
# Install tarpaulin
cargo install cargo-tarpaulin

# Generate HTML report
cargo tarpaulin --out Html --output-dir ./coverage

# Open report
open coverage/tarpaulin-report.html
```

Target coverage goals:
- Overall: >80%
- Critical paths: >90%
- Security components: >95%

## Performance Benchmarks

Expected performance targets:

- **Small repository (<100 files)**: <5 seconds
- **Medium repository (100-1000 files)**: <30 seconds  
- **Large repository (1000-10000 files)**: <5 minutes
- **Event publishing latency**: <100ms
- **API response time**: <200ms (p95)

## Maintenance

### Regular Tasks

1. **Update test dependencies** monthly
2. **Review and update test data** quarterly
3. **Performance baseline updates** after major changes
4. **Security audit** before releases

### Adding Test Cases

When adding new features:

1. Write unit tests first (TDD)
2. Add integration tests for API changes
3. Include performance tests for critical paths
4. Document test scenarios in PR

## Troubleshooting

### Test Failures

1. Check service logs:
   ```bash
   docker-compose -f docker-compose.test.yml logs postgres
   ```

2. Verify environment variables:
   ```bash
   env | grep -E '(DATABASE_URL|QDRANT|PULSAR)'
   ```

3. Run with debug logging:
   ```bash
   RUST_LOG=debug cargo test failing_test -- --nocapture
   ```

### Reset Test Environment

```bash
# Stop all services
docker-compose -f docker-compose.test.yml down -v

# Clean build artifacts
cargo clean

# Restart services
docker-compose -f docker-compose.test.yml up -d
```