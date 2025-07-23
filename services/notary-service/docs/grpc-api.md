# gRPC API Reference

The AFDP Notary Service provides a high-performance gRPC API for service-to-service communication in AI deployment pipelines. This API is designed for programmatic access and supports all notary operations with strong type safety through Protocol Buffers.

## Overview

The gRPC service is defined in `proto/notary.proto` and provides the following capabilities:

- **Evidence Signing**: Sign evidence packages using simple or approval workflows
- **Batch Processing**: Sign multiple evidence packages efficiently
- **Workflow Management**: Monitor and query workflow status
- **Evidence Validation**: Verify signed evidence packages
- **Health Monitoring**: Check service and dependency health

## Service Definition

```protobuf
service NotaryService {
  rpc SignEvidence(SignEvidenceRequest) returns (SignEvidenceResponse);
  rpc SignEvidenceWithApproval(SignEvidenceWithApprovalRequest) returns (SignEvidenceWithApprovalResponse);
  rpc SignEvidenceBatch(SignEvidenceBatchRequest) returns (SignEvidenceBatchResponse);
  rpc GetWorkflowStatus(GetWorkflowStatusRequest) returns (GetWorkflowStatusResponse);
  rpc ValidateEvidence(ValidateEvidenceRequest) returns (ValidateEvidenceResponse);
  rpc GetNotarizationReceipt(GetNotarizationReceiptRequest) returns (GetNotarizationReceiptResponse);
  rpc ListWorkflows(ListWorkflowsRequest) returns (ListWorkflowsResponse);
  rpc HealthCheck(HealthRequest) returns (HealthResponse);
}
```

## Getting Started

### 1. Start the gRPC Server

```bash
# Start the gRPC server (default port: 50051)
cargo run --bin afdp-notary-grpc

# Or with custom configuration
GRPC_SERVER_ADDR=0.0.0.0:8443 cargo run --bin afdp-notary-grpc
```

### 2. Install gRPC Client Dependencies

For Rust clients:
```toml
[dependencies]
tonic = "0.12"
prost = "0.13"
tokio = { version = "1.0", features = ["full"] }
```

### 3. Generate Client Code

The service provides generated Rust client code, but you can also generate clients for other languages:

```bash
# For Go
protoc --go_out=. --go-grpc_out=. proto/notary.proto

# For Python
python -m grpc_tools.protoc -I. --python_out=. --grpc_python_out=. proto/notary.proto

# For Node.js
grpc_tools_node_protoc --js_out=import_style=commonjs,binary:. --grpc_out=grpc_js:. proto/notary.proto
```

## API Endpoints

### SignEvidence

Signs an evidence package using the simple signing workflow.

**Request:**
```protobuf
message SignEvidenceRequest {
  EvidencePackage evidence_package = 1;
}
```

**Response:**
```protobuf
message SignEvidenceResponse {
  string workflow_id = 1;
  NotarizationReceipt receipt = 2;
  WorkflowStatus status = 3;
}
```

**Example:**
```rust
let request = SignEvidenceRequest {
    evidence_package: Some(evidence_package.into()),
};

let response = client.sign_evidence(request).await?;
let sign_response = response.into_inner();
println!("Workflow ID: {}", sign_response.workflow_id);
```

### SignEvidenceWithApproval

Signs an evidence package using the approval workflow that requires multiple approvers.

**Request:**
```protobuf
message SignEvidenceWithApprovalRequest {
  EvidencePackage evidence_package = 1;
  repeated string approvers = 2;
}
```

**Response:**
```protobuf
message SignEvidenceWithApprovalResponse {
  string workflow_id = 1;
  WorkflowStatus status = 2;
  repeated ApprovalStatus approval_statuses = 3;
}
```

**Example:**
```rust
let request = SignEvidenceWithApprovalRequest {
    evidence_package: Some(evidence_package.into()),
    approvers: vec![
        "security@company.com".to_string(),
        "compliance@company.com".to_string(),
    ],
};

let response = client.sign_evidence_with_approval(request).await?;
```

### SignEvidenceBatch

Signs multiple evidence packages in a single batch operation for efficiency.

**Request:**
```protobuf
message SignEvidenceBatchRequest {
  repeated EvidencePackage evidence_packages = 1;
}
```

**Response:**
```protobuf
message SignEvidenceBatchResponse {
  string batch_workflow_id = 1;
  repeated SignEvidenceResponse results = 2;
  WorkflowStatus status = 3;
}
```

### GetWorkflowStatus

Retrieves the current status of a workflow.

**Request:**
```protobuf
message GetWorkflowStatusRequest {
  string workflow_id = 1;
}
```

**Response:**
```protobuf
message GetWorkflowStatusResponse {
  string workflow_id = 1;
  WorkflowStatus status = 2;
  google.protobuf.Timestamp created_at = 3;
  google.protobuf.Timestamp completed_at = 4;
  string error_message = 5;
  google.protobuf.Struct result = 6;
}
```

### ValidateEvidence

Validates a signed evidence package.

**Request:**
```protobuf
message ValidateEvidenceRequest {
  EvidencePackage evidence_package = 1;
  string signature = 2;
}
```

**Response:**
```protobuf
message ValidateEvidenceResponse {
  bool is_valid = 1;
  string validation_error = 2;
  ValidationResult validation_result = 3;
}
```

### GetNotarizationReceipt

Retrieves the notarization receipt for a completed workflow.

**Request:**
```protobuf
message GetNotarizationReceiptRequest {
  string workflow_id = 1;
}
```

**Response:**
```protobuf
message GetNotarizationReceiptResponse {
  NotarizationReceipt receipt = 1;
  bool found = 2;
}
```

### ListWorkflows

Lists workflows with optional filtering.

**Request:**
```protobuf
message ListWorkflowsRequest {
  int32 page_size = 1;
  string page_token = 2;
  WorkflowStatus status_filter = 3;
  google.protobuf.Timestamp start_time = 4;
  google.protobuf.Timestamp end_time = 5;
}
```

**Response:**
```protobuf
message ListWorkflowsResponse {
  repeated WorkflowSummary workflows = 1;
  string next_page_token = 2;
  int32 total_count = 3;
}
```

### HealthCheck

Checks the health of the service and its dependencies.

**Request:**
```protobuf
message HealthRequest {}
```

**Response:**
```protobuf
message HealthResponse {
  string status = 1;
  string version = 2;
  int64 uptime_seconds = 3;
  repeated DependencyStatus dependencies = 4;
}
```

## Data Types

### EvidencePackage

The core data structure representing an event to be notarized:

```protobuf
message EvidencePackage {
  string spec_version = 1;
  google.protobuf.Timestamp timestamp_utc = 2;
  string event_type = 3;
  Actor actor = 4;
  repeated Artifact artifacts = 5;
  google.protobuf.Struct metadata = 6;
}
```

### NotarizationReceipt

Cryptographic proof of notarization:

```protobuf
message NotarizationReceipt {
  string evidence_package_hash = 1;
  string rekor_log_id = 2;
  string rekor_server_url = 3;
  string signature_b64 = 4;
  string public_key_b64 = 5;
  int64 integrated_time = 6;
  int64 log_index = 7;
}
```

### WorkflowStatus

Enumeration of workflow states:

```protobuf
enum WorkflowStatus {
  WORKFLOW_STATUS_UNSPECIFIED = 0;
  WORKFLOW_STATUS_PENDING = 1;
  WORKFLOW_STATUS_RUNNING = 2;
  WORKFLOW_STATUS_COMPLETED = 3;
  WORKFLOW_STATUS_FAILED = 4;
  WORKFLOW_STATUS_CANCELLED = 5;
}
```

## Examples

The service includes comprehensive examples demonstrating common usage patterns:

### Run Examples

```bash
# Simple evidence signing
cargo run --example simple-signing

# Health check
cargo run --example health-check

# Approval workflow
cargo run --example approval-workflow
```

### Example Code Structure

```rust
use afdp_notary::grpc::notary::{
    notary_service_client::NotaryServiceClient,
    SignEvidenceRequest,
};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Connect to server
    let mut client = NotaryServiceClient::connect("http://localhost:50051").await?;
    
    // Create evidence package
    let evidence_package = create_evidence_package();
    
    // Sign evidence
    let request = SignEvidenceRequest {
        evidence_package: Some(evidence_package.into()),
    };
    
    let response = client.sign_evidence(request).await?;
    println!("Signed! Workflow ID: {}", response.into_inner().workflow_id);
    
    Ok(())
}
```

## Configuration

### Server Configuration

The gRPC server can be configured using environment variables:

```bash
# Server address (default: 0.0.0.0:50051)
export GRPC_SERVER_ADDR="0.0.0.0:8443"

# Temporal configuration
export TEMPORAL_SERVER_URL="http://localhost:7233"
export TEMPORAL_NAMESPACE="afdp-notary"
export TEMPORAL_TASK_QUEUE="notary-tasks"

# TLS configuration (optional)
export GRPC_TLS_CERT_PATH="/path/to/cert.pem"
export GRPC_TLS_KEY_PATH="/path/to/key.pem"
```

### Client Configuration

```rust
// Basic connection
let client = NotaryServiceClient::connect("http://localhost:50051").await?;

// With TLS
let tls_config = tonic::transport::ClientTlsConfig::new()
    .ca_certificate(ca_cert)
    .domain_name("notary.example.com");

let channel = tonic::transport::Channel::from_static("https://notary.example.com:443")
    .tls_config(tls_config)?
    .connect()
    .await?;

let client = NotaryServiceClient::new(channel);
```

## Error Handling

The gRPC service uses standard gRPC status codes:

- `OK` (0): Success
- `INVALID_ARGUMENT` (3): Invalid request parameters
- `NOT_FOUND` (5): Workflow or resource not found
- `ALREADY_EXISTS` (6): Resource already exists
- `PERMISSION_DENIED` (7): Authorization failed
- `RESOURCE_EXHAUSTED` (8): Rate limit exceeded
- `FAILED_PRECONDITION` (9): System state prevents operation
- `INTERNAL` (13): Internal server error
- `UNAVAILABLE` (14): Service temporarily unavailable

```rust
match client.sign_evidence(request).await {
    Ok(response) => {
        // Handle success
    }
    Err(status) => {
        match status.code() {
            tonic::Code::InvalidArgument => {
                eprintln!("Invalid request: {}", status.message());
            }
            tonic::Code::Internal => {
                eprintln!("Server error: {}", status.message());
            }
            _ => {
                eprintln!("Unexpected error: {}", status);
            }
        }
    }
}
```

## Performance Considerations

### Connection Pooling

For high-throughput applications, reuse client connections:

```rust
// Create a shared client
let client = Arc::new(Mutex::new(
    NotaryServiceClient::connect("http://localhost:50051").await?
));

// Use across multiple tasks
let client_clone = client.clone();
tokio::spawn(async move {
    let mut client = client_clone.lock().await;
    // Use client...
});
```

### Batch Operations

Use batch operations for signing multiple evidence packages:

```rust
let batch_request = SignEvidenceBatchRequest {
    evidence_packages: evidence_packages.into_iter()
        .map(Into::into)
        .collect(),
};

let response = client.sign_evidence_batch(batch_request).await?;
```

### Streaming (Future Enhancement)

While not currently implemented, the service is designed to support streaming operations for real-time status updates and large batch processing.

## Security

### Authentication

The gRPC service supports multiple authentication mechanisms:

- **mTLS**: Mutual TLS authentication
- **Token-based**: JWT or API key authentication
- **Certificate-based**: X.509 client certificates

### Authorization

Access control is enforced at the method level based on:

- Client identity
- Resource ownership
- Role-based permissions
- Policy-based access control

### Data Protection

All communications are encrypted using TLS 1.3, and sensitive data is handled according to security best practices.

## Monitoring and Observability

### Health Checks

Use the health check endpoint to monitor service status:

```bash
# CLI health check
grpc_health_probe -addr=localhost:50051

# Or via client
cargo run --example health-check
```

### Metrics

The service exposes metrics compatible with Prometheus:

- Request count and duration
- Error rates by method
- Workflow status distribution
- Dependency health status

### Tracing

Distributed tracing is supported through OpenTelemetry integration, providing end-to-end visibility across the AFDP pipeline.