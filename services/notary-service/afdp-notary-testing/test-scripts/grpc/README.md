# AFDP Notary Service gRPC Performance Tests

This directory contains comprehensive gRPC performance test suites for the AFDP Notary Service.

## Test Tools

### 1. Python High-Performance Tester (`grpc_performance_tester.py`)

A comprehensive async Python test suite providing:

- **Full gRPC API Coverage**: Tests all service methods (SignEvidence, SignEvidenceWithApproval, SignEvidenceBatch, HealthCheck, etc.)
- **High-Performance Load Testing**: Configurable concurrency and duration
- **Protocol Buffer Integration**: Automatic conversion from JSON test data to protobuf messages
- **Detailed Metrics**: Response times, throughput, request/response sizes, error analysis
- **Structured Logging**: JSON logging with correlation IDs for distributed tracing

#### Setup

```bash
# Install Python dependencies
pip install -r requirements.txt

# Generate protobuf files
./generate_proto.sh
```

#### Usage

```bash
# Basic functionality test
python grpc_performance_tester.py

# Full performance test with custom parameters
python grpc_performance_tester.py \
    --server localhost:50051 \
    --load-test \
    --concurrent 20 \
    --duration 60 \
    --batch-size 10 \
    --output detailed-grpc-results.json
```

#### Command Line Options

- `--server`: gRPC server address (default: localhost:50051)
- `--load-test`: Enable high-concurrency load testing
- `--concurrent`: Number of concurrent connections for load test (default: 10)
- `--duration`: Load test duration in seconds (default: 30)
- `--batch-size`: Number of evidence packages per batch test (default: 5)
- `--output`: JSON output file for results (default: grpc-performance-results.json)

### 2. Simple Rust Client (`simple_grpc_client.rs`)

A native Rust client demonstrating basic gRPC usage:

- **Native Performance**: Zero-overhead Rust implementation
- **Basic Testing**: Simple workflow testing for all main endpoints
- **Performance Benchmarking**: Built-in concurrent request testing
- **JSON Integration**: Loads test data from JSON files

#### Setup

```bash
# Add to Cargo.toml dependencies (if integrating into main project):
[dependencies]
tokio = { version = "1.0", features = ["full"] }
tonic = "0.12"
prost = "0.13"
serde_json = "1.0"

# Or compile standalone:
rustc --edition 2021 simple_grpc_client.rs
```

#### Usage

```bash
# Set server address (optional)
export GRPC_SERVER="http://localhost:50051"

# Run the test client
cargo run --bin simple_grpc_client
# or if compiled standalone:
./simple_grpc_client
```

### 3. Protocol Buffer Generation (`generate_proto.sh`)

Automated script to generate Python protobuf files from the service definition.

```bash
./generate_proto.sh
```

This generates:
- `notary_pb2.py` - Protocol buffer message classes
- `notary_pb2_grpc.py` - gRPC service stubs and client classes

## gRPC Service Endpoints Tested

### Core Signing Operations

#### SignEvidence
```protobuf
rpc SignEvidence(SignEvidenceRequest) returns (SignEvidenceResponse);
```
- **Purpose**: Simple evidence package signing
- **Test Coverage**: All sample evidence packages, performance under load
- **Metrics**: Response time, success rate, message sizes

#### SignEvidenceWithApproval
```protobuf
rpc SignEvidenceWithApproval(SignEvidenceWithApprovalRequest) returns (SignEvidenceWithApprovalResponse);
```
- **Purpose**: Multi-approver workflow initiation
- **Test Coverage**: Various approver configurations, workflow status tracking
- **Metrics**: Approval workflow latency, approver response handling

#### SignEvidenceBatch
```protobuf
rpc SignEvidenceBatch(SignEvidenceBatchRequest) returns (SignEvidenceBatchResponse);
```
- **Purpose**: Efficient batch processing of multiple evidence packages
- **Test Coverage**: Various batch sizes, mixed evidence types
- **Metrics**: Batch processing efficiency, per-item vs batch overhead

### Monitoring and Status

#### HealthCheck
```protobuf
rpc HealthCheck(HealthRequest) returns (HealthResponse);
```
- **Purpose**: Service health and dependency status monitoring
- **Test Coverage**: Continuous health monitoring during load tests
- **Metrics**: Health check latency, dependency status accuracy

#### GetWorkflowStatus
```protobuf
rpc GetWorkflowStatus(GetWorkflowStatusRequest) returns (GetWorkflowStatusResponse);
```
- **Purpose**: Workflow progress tracking and status retrieval
- **Test Coverage**: Status polling for long-running workflows
- **Metrics**: Status retrieval performance, status accuracy

### Validation and Verification

#### ValidateEvidence
```protobuf
rpc ValidateEvidence(ValidateEvidenceRequest) returns (ValidateEvidenceResponse);
```
- **Purpose**: Evidence package validation and cryptographic verification
- **Test Coverage**: Valid/invalid evidence packages, edge cases
- **Metrics**: Validation performance, accuracy rates

## Test Scenarios

The test suites automatically load and test all evidence packages from `../sample-data/`:

### 1. AI Model Deployment
- **GPT-4 Fine-tuned Model**: Production ML model deployment with comprehensive metadata
- **Vision Transformer**: Medical imaging AI with regulatory compliance data
- **Test Focus**: Large metadata handling, artifact verification

### 2. Security Scans
- **Vulnerability Reports**: Container security scan results with CVSS data
- **Compliance Audits**: Infrastructure compliance scan with remediation data
- **Test Focus**: Security data integrity, compliance metadata validation

### 3. Financial Algorithms
- **Trading Algorithm**: High-frequency trading deployment with risk parameters
- **Credit Risk Model**: Basel III compliant model with validation metrics
- **Test Focus**: Regulatory compliance data, performance metrics handling

### 4. Healthcare AI
- **FDA-Cleared Diagnostic AI**: Medical device deployment with clinical validation
- **Drug Discovery Model**: Pharmaceutical AI with IP and regulatory data
- **Test Focus**: Healthcare compliance, sensitive data handling

### 5. Supply Chain
- **Semiconductor Provenance**: Manufacturing traceability with quality data
- **Cold Chain Validation**: Pharmaceutical logistics with sensor data
- **Test Focus**: Traceability data, sensor data integrity

## Performance Metrics

### Response Time Metrics
```json
{
  "performance_metrics": {
    "requests_per_second": 245.7,
    "average_response_time_ms": 67.3,
    "min_response_time_ms": 23.1,
    "max_response_time_ms": 234.7,
    "p95_response_time_ms": 156.2,
    "p99_response_time_ms": 203.8
  }
}
```

### Message Size Analysis
```json
{
  "message_analysis": {
    "average_request_size_bytes": 15420,
    "average_response_size_bytes": 2847,
    "compression_efficiency": 0.87,
    "largest_request_bytes": 45231,
    "largest_response_bytes": 8932
  }
}
```

### Error Analysis
```json
{
  "error_analysis": {
    "error_rate": 0.023,
    "error_distribution": {
      "UNAVAILABLE": 12,
      "DEADLINE_EXCEEDED": 8,
      "INVALID_ARGUMENT": 3
    }
  }
}
```

### Method-Specific Breakdown
```json
{
  "method_breakdown": {
    "SignEvidence": {
      "total_requests": 150,
      "success_rate": 0.987,
      "avg_response_time_ms": 89.4,
      "p95_response_time_ms": 187.2
    },
    "SignEvidenceBatch": {
      "total_requests": 25,
      "success_rate": 0.960,
      "avg_response_time_ms": 245.7,
      "p95_response_time_ms": 456.3
    }
  }
}
```

## Load Testing Configuration

### Concurrency Patterns
- **Low Concurrency (1-5)**: Baseline performance measurement
- **Medium Concurrency (10-20)**: Typical production load simulation
- **High Concurrency (50-100)**: Stress testing and bottleneck identification
- **Burst Testing**: Sudden load spikes simulation

### Duration Patterns
- **Short Tests (10-30s)**: Quick validation and CI/CD integration
- **Medium Tests (1-5 min)**: Stability and warm-up behavior analysis  
- **Long Tests (10+ min)**: Memory leak detection and sustained performance

### Batch Size Testing
- **Small Batches (1-5)**: Individual request optimization
- **Medium Batches (10-25)**: Typical batch processing scenarios
- **Large Batches (50-100)**: Maximum throughput testing

## Output and Reporting

### Python Test Suite Output

Comprehensive JSON report with hierarchical metrics:

```json
{
  "test_summary": {
    "timestamp": "2024-01-23T14:30:00.000Z",
    "server_address": "localhost:50051",
    "total_duration_seconds": 180.5,
    "total_tests": 275,
    "successful_tests": 268,
    "failed_tests": 7,
    "success_rate": 0.975
  },
  "performance_metrics": { ... },
  "error_analysis": { ... },
  "method_breakdown": { ... },
  "detailed_results": [ ... ]
}
```

### Rust Client Output

Console output with real-time metrics:

```
🚀 AFDP Notary Service gRPC Client Test
✅ Health check: PASS (45ms)
✅ Simple signing: PASS (123ms)
✅ Approval workflow: PASS (234ms)
✅ Batch signing: PASS (456ms)

📊 Performance Test Results:
   Total Requests: 20
   Success Rate: 95.0%
   Avg Response Time: 145.7ms
   Min Response Time: 67ms
   Max Response Time: 289ms
```

## Integration with Monitoring

### Distributed Tracing
Both test suites include correlation IDs that integrate with:
- **Jaeger**: Distributed trace visualization
- **Zipkin**: Request flow analysis
- **Custom Tracing**: Service-specific trace collection

### Metrics Integration
Performance data can be exported to:
- **Prometheus**: Time-series metrics collection
- **Grafana**: Real-time dashboard visualization
- **Custom Dashboards**: Service-specific monitoring

### Log Correlation
Structured JSON logging enables:
- **Centralized Logging**: ELK/EFK stack integration
- **Log Analysis**: Request correlation across services
- **Error Tracking**: Detailed error context and patterns

## Continuous Integration

### CI/CD Pipeline Integration

```yaml
# Example GitHub Actions workflow
- name: Run gRPC Performance Tests
  run: |
    cd afdp-notary-testing/test-scripts/grpc
    ./generate_proto.sh
    python grpc_performance_tester.py \
      --server ${{ env.GRPC_SERVER_URL }} \
      --load-test \
      --duration 30 \
      --concurrent 10
```

### Performance Regression Detection
- **Baseline Comparison**: Automated comparison with previous test runs
- **Threshold Alerts**: Configurable performance degradation alerts
- **Trend Analysis**: Long-term performance trend tracking

## Troubleshooting

### Common Issues

1. **Connection Refused**
   ```bash
   # Check if gRPC server is running
   grpc_cli ls localhost:50051
   ```

2. **Protobuf Generation Errors**
   ```bash
   # Ensure grpc-tools is installed
   pip install grpcio-tools
   ./generate_proto.sh
   ```

3. **Import Errors in Python**
   ```bash
   # Regenerate protobuf files
   rm -f notary_pb2.py notary_pb2_grpc.py
   ./generate_proto.sh
   ```

4. **Performance Issues**
   - Check server resource utilization
   - Verify network latency with `ping`
   - Review gRPC channel configuration
   - Analyze garbage collection patterns

### Debug Mode

Enable detailed logging:

```bash
# Python suite with debug logging
PYTHONPATH=. python grpc_performance_tester.py --server localhost:50051 2>&1 | jq .

# Rust client with environment variables
RUST_LOG=debug ./simple_grpc_client
```

### Network Analysis

```bash
# Capture gRPC traffic for analysis
tcpdump -i lo0 -w grpc-traffic.pcap port 50051

# Analyze with Wireshark or tshark
tshark -r grpc-traffic.pcap -Y http2
```