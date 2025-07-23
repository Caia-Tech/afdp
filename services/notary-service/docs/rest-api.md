# AFDP Notary Service REST API

The AFDP Notary Service provides a comprehensive REST API for cryptographic notarization of evidence packages in AI deployment pipelines. This API enables secure, auditable, and verifiable signing of deployment events, model approvals, and other critical pipeline activities.

## Table of Contents

- [Getting Started](#getting-started)
- [Authentication](#authentication)
- [API Endpoints](#api-endpoints)
- [Data Models](#data-models)
- [Error Handling](#error-handling)
- [Examples](#examples)
- [OpenAPI Documentation](#openapi-documentation)

## Getting Started

### Prerequisites

- Rust 1.70+
- HashiCorp Vault server (for key management)
- Rekor server (for transparency logging)
- Optional: Temporal server (for workflow orchestration)

### Running the Server

```bash
# Start the REST API server
cargo run --bin afdp-notary-rest

# Server will start on http://localhost:8080
# Swagger UI available at http://localhost:8080/swagger-ui
# Health check at http://localhost:8080/health
```

### Configuration

The server uses the following default configuration:

```json
{
  "temporal_address": "http://localhost:7233",
  "namespace": "default", 
  "task_queue": "afdp-notary",
  "vault_address": "http://localhost:8200",
  "vault_token": "root",
  "rekor_server": "https://rekor.sigstore.dev"
}
```

Environment variables can override these defaults:
- `TEMPORAL_ADDRESS`
- `VAULT_ADDRESS` 
- `VAULT_TOKEN`
- `REKOR_SERVER_URL`

## Authentication

> **Note**: Authentication is planned for a future release. Current implementation is for development/testing only.

## API Endpoints

### Evidence Signing

#### Sign Evidence Package
Sign a single evidence package using simple signing workflow.

```http
POST /api/v1/evidence/sign
Content-Type: application/json

{
  "evidence_package": {
    "spec_version": "1.0.0",
    "timestamp_utc": "2025-07-23T10:00:00Z",
    "event_type": "model.deployment.completed",
    "actor": {
      "actor_type": "human_user",
      "id": "deployer@caiatech.com",
      "auth_provider": "oauth2"
    },
    "artifacts": [
      {
        "name": "fraud-detector-v3.pkl",
        "uri": "s3://models/fraud-detector-v3.pkl",
        "hash_sha256": "abc123def456..."
      }
    ],
    "metadata": {
      "model_id": "fraud-detector-v3",
      "version": "3.0.0",
      "environment": "production"
    }
  }
}
```

**Response:**
```json
{
  "workflow_id": "simple-signing-uuid-123",
  "receipt": {
    "evidence_package_hash": "sha256-hash-of-package",
    "rekor_log_id": "rekor-entry-uuid",
    "rekor_server_url": "https://rekor.sigstore.dev",
    "signature_b64": "base64-encoded-signature",
    "public_key_b64": "base64-encoded-public-key",
    "integrated_time": 1672531200,
    "log_index": 12345
  },
  "status": "completed"
}
```

#### Sign with Approval Workflow
Sign evidence requiring multi-party approval.

```http
POST /api/v1/evidence/sign/approval
Content-Type: application/json

{
  "evidence_package": { /* same as above */ },
  "approvers": [
    "security-lead@caiatech.com",
    "compliance-officer@caiatech.com"
  ]
}
```

**Response:**
```json
{
  "workflow_id": "approval-signing-uuid-456", 
  "status": "pending",
  "approval_statuses": [
    {
      "approver": "security-lead@caiatech.com",
      "status": "pending",
      "timestamp": "2025-07-23T10:01:00Z",
      "comment": null
    },
    {
      "approver": "compliance-officer@caiatech.com", 
      "status": "pending",
      "timestamp": "2025-07-23T10:01:00Z",
      "comment": null
    }
  ]
}
```

#### Batch Sign Evidence
Sign multiple evidence packages in a single batch operation.

```http
POST /api/v1/evidence/sign/batch
Content-Type: application/json

{
  "evidence_packages": [
    { /* evidence package 1 */ },
    { /* evidence package 2 */ },
    { /* evidence package 3 */ }
  ]
}
```

**Response:**
```json
{
  "batch_workflow_id": "batch-signing-uuid-789",
  "results": [
    {
      "workflow_id": "simple-signing-uuid-001",
      "status": "completed"
    },
    {
      "workflow_id": "simple-signing-uuid-002", 
      "status": "completed"
    }
  ],
  "status": "processing"
}
```

### Workflow Management

#### Get Workflow Status
Check the status of a running workflow.

```http
GET /api/v1/workflows/{workflow_id}/status
```

**Response:**
```json
{
  "workflow_id": "simple-signing-uuid-123",
  "status": "completed",
  "created_at": "2025-07-23T10:00:00Z",
  "completed_at": "2025-07-23T10:00:05Z",
  "error_message": null,
  "result": {
    "receipt_id": "rekor-entry-uuid"
  }
}
```

#### Get Notarization Receipt
Retrieve the notarization receipt for a completed workflow.

```http
GET /api/v1/workflows/{workflow_id}/receipt
```

**Response:**
```json
{
  "evidence_package_hash": "sha256-hash-of-package",
  "rekor_log_id": "rekor-entry-uuid",
  "rekor_server_url": "https://rekor.sigstore.dev",
  "signature_b64": "base64-encoded-signature",
  "public_key_b64": "base64-encoded-public-key", 
  "integrated_time": 1672531200,
  "log_index": 12345
}
```

#### List Workflows
List workflows with optional filtering.

```http
GET /api/v1/workflows?page_size=10&status_filter=completed
```

**Response:**
```json
{
  "workflows": [
    {
      "workflow_id": "simple-signing-uuid-123",
      "workflow_type": "simple_signing",
      "status": "completed",
      "created_at": "2025-07-23T10:00:00Z",
      "completed_at": "2025-07-23T10:00:05Z",
      "event_type": "model.deployment.completed",
      "actor_id": "deployer@caiatech.com"
    }
  ],
  "next_page_token": null,
  "total_count": 1
}
```

### Evidence Validation

#### Validate Evidence Package  
Verify the authenticity and integrity of an evidence package.

```http
POST /api/v1/evidence/validate
Content-Type: application/json

{
  "evidence_package": { /* evidence package to validate */ },
  "signature": "base64-encoded-signature"
}
```

**Response:**
```json
{
  "is_valid": true,
  "validation_error": null,
  "validation_result": {
    "signature_valid": true,
    "evidence_hash_valid": true,
    "rekor_entry_valid": true,
    "timestamp_valid": true,
    "warnings": []
  }
}
```

### Health Check

#### Service Health
Check if the service is healthy and running.

```http
GET /health
```

**Response:**
```json
{
  "status": "healthy",
  "timestamp": "2025-07-23T10:00:00Z", 
  "version": "0.1.0"
}
```

## Data Models

### EvidencePackage
Core data structure representing an event to be notarized.

```json
{
  "spec_version": "1.0.0",
  "timestamp_utc": "2025-07-23T10:00:00Z",
  "event_type": "model.deployment.completed",
  "actor": {
    "actor_type": "human_user",
    "id": "user@example.com",
    "auth_provider": "oauth2"
  },
  "artifacts": [
    {
      "name": "model.pkl",
      "uri": "s3://bucket/model.pkl", 
      "hash_sha256": "sha256-hash"
    }
  ],
  "metadata": {
    "custom_key": "custom_value"
  }
}
```

### NotarizationReceipt
Cryptographic proof of notarization.

```json
{
  "evidence_package_hash": "sha256-hash-of-package",
  "rekor_log_id": "transparency-log-entry-id",
  "rekor_server_url": "https://rekor.sigstore.dev",
  "signature_b64": "base64-encoded-signature",
  "public_key_b64": "base64-encoded-public-key",
  "integrated_time": 1672531200,
  "log_index": 12345
}
```

## Error Handling

All endpoints return structured error responses:

```json
{
  "status": 400,
  "message": "Invalid evidence package",
  "details": {
    "field": "event_type",
    "error": "Event type cannot be empty"
  },
  "request_id": "req-uuid-123"
}
```

### HTTP Status Codes

- `200 OK` - Request successful
- `400 Bad Request` - Invalid request data
- `404 Not Found` - Resource not found
- `500 Internal Server Error` - Server error
- `503 Service Unavailable` - Service dependencies unavailable

## Examples

### Complete Model Deployment Flow

1. **Sign deployment evidence:**
```bash
curl -X POST http://localhost:8080/api/v1/evidence/sign \
  -H "Content-Type: application/json" \
  -d '{
    "evidence_package": {
      "spec_version": "1.0.0",
      "timestamp_utc": "2025-07-23T10:00:00Z",
      "event_type": "model.deployment.completed",
      "actor": {
        "actor_type": "human_user", 
        "id": "deployer@caiatech.com"
      },
      "artifacts": [
        {
          "name": "fraud-detector-v3.pkl",
          "uri": "s3://models/fraud-detector-v3.pkl",
          "hash_sha256": "abc123def456"
        }
      ],
      "metadata": {
        "model_id": "fraud-detector-v3",
        "version": "3.0.0",
        "environment": "production"
      }
    }
  }'
```

2. **Check workflow status:**
```bash
curl http://localhost:8080/api/v1/workflows/simple-signing-uuid-123/status
```

3. **Get notarization receipt:**
```bash  
curl http://localhost:8080/api/v1/workflows/simple-signing-uuid-123/receipt
```

### Production Approval Workflow

For production deployments requiring approval:

```bash
curl -X POST http://localhost:8080/api/v1/evidence/sign/approval \
  -H "Content-Type: application/json" \
  -d '{
    "evidence_package": { /* same as above */ },
    "approvers": [
      "security-lead@caiatech.com",
      "compliance-officer@caiatech.com"
    ]
  }'
```

## OpenAPI Documentation

Interactive API documentation is available at:
- **Swagger UI**: `http://localhost:8080/swagger-ui`
- **OpenAPI Spec**: `http://localhost:8080/api-docs/openapi.json`

The Swagger UI provides:
- Interactive endpoint testing
- Request/response examples
- Schema documentation
- Authentication configuration (when implemented)

## Security Considerations

### Current Implementation
- **Development only**: No authentication currently implemented
- **Mock signatures**: Uses simplified signing for demonstration
- **Local dependencies**: Assumes local Vault and Rekor instances

### Production Deployment
For production use, implement:
- **Authentication**: JWT tokens, API keys, or OAuth2
- **Authorization**: Role-based access control (RBAC)
- **Rate limiting**: Prevent abuse and ensure fair usage
- **TLS termination**: HTTPS for all communications
- **Input validation**: Comprehensive request validation
- **Monitoring**: Logging, metrics, and alerting
- **High availability**: Load balancing and failover

## Integration Patterns

### CI/CD Pipeline Integration
```yaml
# GitHub Actions example
- name: Notarize Deployment
  run: |
    curl -X POST $NOTARY_URL/api/v1/evidence/sign \
      -H "Authorization: Bearer $NOTARY_TOKEN" \
      -H "Content-Type: application/json" \
      -d @deployment-evidence.json
```

### Monitoring and Alerting
```bash
# Health check for monitoring
curl -f http://localhost:8080/health || exit 1
```

### Batch Processing
For high-volume scenarios, use batch endpoints to improve efficiency and reduce API calls.

## Next Steps

1. **Implement gRPC API** for high-performance service-to-service communication
2. **Add Pulsar consumer** for event-driven pipeline integration  
3. **Implement authentication** and authorization
4. **Add monitoring** and observability features
5. **Create client SDKs** for popular programming languages

## Support

For questions, issues, or contributions:
- **GitHub Issues**: [Report bugs or request features](https://github.com/caiatech/afdp-notary/issues)
- **Documentation**: [Full documentation](https://docs.caiatech.com/afdp/)
- **Email**: [support@caiatech.com](mailto:support@caiatech.com)