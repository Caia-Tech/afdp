# AFDP Notary Service REST API Tests

This directory contains comprehensive test scripts for the AFDP Notary Service REST API endpoints.

## Test Scripts

### 1. Python Comprehensive Test Suite (`test-all-scenarios.py`)

A full-featured async Python test suite that provides:

- **Comprehensive Testing**: Tests all sample evidence packages
- **Load Testing**: Concurrent request testing with configurable parameters
- **Detailed Logging**: Structured JSON logging with correlation IDs
- **Performance Metrics**: Response times, throughput, success rates
- **Verification Testing**: Automatic verification of notarized evidence
- **Comprehensive Reporting**: JSON reports with detailed metrics

#### Usage

```bash
# Install dependencies
pip install -r requirements.txt

# Basic test run
python test-all-scenarios.py

# With custom parameters
python test-all-scenarios.py \
    --base-url http://localhost:3030 \
    --load-test \
    --concurrent 10 \
    --duration 60 \
    --output detailed-results.json
```

#### Command Line Options

- `--base-url`: Base URL of the notary service (default: http://localhost:3030)
- `--load-test`: Enable load testing
- `--concurrent`: Number of concurrent requests for load test (default: 5)
- `--duration`: Load test duration in seconds (default: 30)
- `--output`: Output file for results (default: rest-api-test-results.json)

### 2. Simple Bash Test Script (`simple-rest-tests.sh`)

A lightweight bash script using curl for basic testing:

- **Health Check**: Verifies service health
- **Evidence Testing**: Tests all sample evidence packages
- **Verification Testing**: Automatic verification of successful notarizations
- **Performance Testing**: Basic load testing with Apache Bench (if available)
- **Structured Output**: Saves all responses for analysis

#### Usage

```bash
# Make executable (if not already)
chmod +x simple-rest-tests.sh

# Run with default settings
./simple-rest-tests.sh

# Run with custom URL
./simple-rest-tests.sh --url http://your-service:3030

# Or use environment variable
BASE_URL=http://your-service:3030 ./simple-rest-tests.sh
```

## Test Scenarios

The test scripts automatically discover and test all evidence packages in the `../sample-data/` directory:

1. **AI Model Deployment** (`ai-model-deployment/`)
   - GPT-4 fine-tuned model production deployment
   - Vision transformer medical imaging deployment

2. **Security Scans** (`security-scan/`)
   - Critical vulnerability container scan
   - Infrastructure compliance audit

3. **Financial Algorithms** (`financial-algorithm/`)
   - High-frequency trading algorithm deployment
   - Credit risk scoring model validation

4. **Healthcare AI** (`healthcare-ai/`)
   - FDA-cleared radiology AI deployment
   - Drug discovery AI model validation

5. **Supply Chain** (`supply-chain/`)
   - Semiconductor batch provenance verification
   - Pharmaceutical cold chain validation

## API Endpoints Tested

### Notarization Endpoint
```
POST /api/v1/notarize
```

**Headers:**
- `Content-Type: application/json`
- `X-Correlation-ID: <unique-id>` (for tracing)
- `X-Request-ID: <unique-id>` (for deduplication)

**Request Body:** Evidence package JSON

**Response:** Notarization receipt with Rekor log ID and signature

### Verification Endpoint
```
GET /api/v1/verify/{evidence_hash}
```

**Headers:**
- `X-Correlation-ID: <unique-id>`

**Response:** Verification status and details

### Health Check Endpoint
```
GET /health
```

**Response:** Service health status

## Output and Reporting

### Python Test Suite Output

The Python suite generates a comprehensive JSON report with:

```json
{
  "test_summary": {
    "timestamp": "2024-01-23T14:30:00.000Z",
    "total_duration_seconds": 120.5,
    "total_tests": 25,
    "successful_tests": 24,
    "failed_tests": 1,
    "success_rate": 0.96
  },
  "performance_metrics": {
    "average_response_time_ms": 250.3,
    "min_response_time_ms": 95.2,
    "max_response_time_ms": 1205.7,
    "p95_response_time_ms": 890.4,
    "throughput_requests_per_second": 12.4
  },
  "scenarios": { ... },
  "detailed_results": [ ... ]
}
```

### Bash Script Output

The bash script saves individual responses in the `./output/` directory:

- `notarize_<scenario_name>_<timestamp>.json` - Notarization responses
- `verify_<scenario_name>_<timestamp>.json` - Verification responses
- `performance_test_<timestamp>.txt` - Performance test results

## Requirements

### For Python Suite
- Python 3.8+
- Dependencies listed in `requirements.txt`

### For Bash Script
- bash 4.0+
- curl
- jq (optional, for JSON formatting)
- uuidgen (usually available on macOS/Linux)
- Apache Bench (`ab`) for performance testing (optional)

## Environment Variables

- `BASE_URL`: Override the default base URL for the notary service

## Logging and Correlation

Both test suites generate correlation IDs for request tracing:

- **Python Suite**: Uses structured JSON logging with correlation IDs
- **Bash Script**: Includes correlation IDs in request headers

These correlation IDs can be used to trace requests through logs and monitoring systems.

## Integration with CI/CD

The test scripts can be integrated into CI/CD pipelines:

```yaml
# Example GitHub Actions step
- name: Run REST API Tests
  run: |
    cd afdp-notary-testing/test-scripts/rest-api
    pip install -r requirements.txt
    python test-all-scenarios.py --base-url ${{ env.NOTARY_SERVICE_URL }}
```

## Troubleshooting

### Common Issues

1. **Connection Refused**: Ensure the notary service is running on the specified URL
2. **Timeout Errors**: Increase timeout values or check service performance
3. **JSON Parse Errors**: Verify the service is returning valid JSON responses
4. **Permission Denied**: Ensure the bash script is executable (`chmod +x`)

### Debug Mode

For the Python suite, increase logging verbosity by modifying the log level:

```python
logger.setLevel(logging.DEBUG)
```

For the bash script, add debug output:

```bash
set -x  # Add at the beginning of the script
```