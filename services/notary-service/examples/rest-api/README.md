# AFDP Notary Service REST API Examples

This directory contains comprehensive examples demonstrating how to use the AFDP Notary Service REST API for various scenarios.

## 🚀 Quick Start

1. **Start the REST API server:**
   ```bash
   cd /path/to/afdp-notary-service
   cargo run --bin afdp-notary-rest
   ```

2. **Verify the server is running:**
   ```bash
   curl http://localhost:8080/health
   ```

3. **Run the examples:**
   ```bash
   # Basic model deployment signing
   ./model-deployment.sh
   
   # Multi-party approval workflow
   ./approval-workflow.sh
   
   # Batch signing of multiple evidence packages
   ./batch-signing.sh
   ```

## 📋 Available Examples

### 1. Model Deployment (`model-deployment.sh`)
**Scenario:** Sign evidence for a completed model deployment to production.

**What it demonstrates:**
- ✅ Simple evidence signing workflow
- ✅ Evidence package structure for model deployments
- ✅ Workflow status monitoring
- ✅ Notarization receipt retrieval
- ✅ Evidence validation

**Key API endpoints used:**
- `POST /api/v1/evidence/sign`
- `GET /api/v1/workflows/{id}/status`
- `GET /api/v1/workflows/{id}/receipt`
- `POST /api/v1/evidence/validate`

**Example output:**
```
🚀 AFDP Notary Service - Model Deployment Example
=================================================
✅ Server is healthy
📝 Step 1: Signing model deployment evidence...
📋 Workflow ID: simple-signing-uuid-123
📊 Step 2: Checking workflow status...
🧾 Step 3: Retrieving notarization receipt...
🔍 Step 4: Validating signed evidence...
✅ Evidence validation passed!
🎉 Example completed successfully!
```

### 2. Approval Workflow (`approval-workflow.sh`)
**Scenario:** High-risk production deployment requiring multi-party approval.

**What it demonstrates:**
- ✅ Multi-party approval workflow initiation
- ✅ Evidence packages for high-risk deployments
- ✅ Approval status tracking
- ✅ Production deployment compliance patterns

**Key API endpoints used:**
- `POST /api/v1/evidence/sign/approval`
- `GET /api/v1/workflows/{id}/status`
- `GET /api/v1/workflows`

**Example output:**
```
🔒 AFDP Notary Service - Approval Workflow Example
==================================================
✅ Server is healthy
📝 Step 1: Initiating approval workflow for production deployment...
📋 Approval Workflow ID: approval-signing-uuid-456
📧 Notification would be sent to:
   • security-lead@caiatech.com
   • compliance-officer@caiatech.com
   • ml-architect@caiatech.com
```

### 3. Batch Signing (`batch-signing.sh`)
**Scenario:** Process multiple related events in a single batch operation.

**What it demonstrates:**
- ✅ Batch processing for efficiency
- ✅ Multiple event types in one request
- ✅ Parallel workflow execution
- ✅ Batch monitoring and status tracking

**Key API endpoints used:**
- `POST /api/v1/evidence/sign/batch`
- `GET /api/v1/workflows/{id}/status`
- `GET /api/v1/workflows`

**Example output:**
```
📦 AFDP Notary Service - Batch Signing Example
==============================================
✅ Server is healthy
📝 Step 1: Preparing batch evidence packages...
   • model.training.completed (model-a)
   • model.training.completed (model-b)
   • model.validation.completed (validation-batch-001)
   • dataset.preprocessing.completed (customer-transactions)
   • compliance.scan.completed (compliance-scan-20250723)
🚀 Step 2: Submitting batch signing request...
📋 Batch Workflow ID: batch-signing-uuid-789
```

## 🛠️ Prerequisites

### Required Services

1. **HashiCorp Vault** (for key management)
   ```bash
   # Start Vault in dev mode for testing
   vault server -dev -dev-root-token-id="root"
   ```

2. **Rekor Server** (for transparency logging)
   ```bash
   # Use public Rekor instance (default)
   # Or run locally: https://docs.sigstore.dev/rekor/installation
   ```

3. **Temporal Server** (optional, for workflow orchestration)
   ```bash
   # Start Temporal in dev mode
   temporal server start-dev
   ```

### Required Tools

- `curl` - for HTTP requests
- `jq` - for JSON processing
- `bash` - for running scripts

## 🔧 Configuration

The examples use the default configuration:

```bash
NOTARY_URL="http://localhost:8080"
```

To use a different server, set the environment variable:

```bash
export NOTARY_URL="https://your-notary-server.com"
./model-deployment.sh
```

## 📖 Understanding the API

### Evidence Package Structure

All examples use the standard AFDP evidence package format:

```json
{
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
      "hash_sha256": "abc123..."
    }
  ],
  "metadata": {
    "model_id": "fraud-detector-v3",
    "version": "3.0.0",
    "environment": "production"
  }
}
```

### Workflow Types

1. **Simple Signing** - Direct cryptographic signing
2. **Approval Workflow** - Requires multi-party approval before signing
3. **Batch Processing** - Processes multiple evidence packages efficiently

### Response Patterns

All API responses follow consistent patterns:

- **Success (200)**: Returns workflow ID and relevant data
- **Error (4xx/5xx)**: Returns structured error with details
- **Async Operations**: Return workflow ID for status tracking

## 🧪 Testing and Development

### Running Individual Examples

Each script can be run independently:

```bash
# Just test model deployment
./model-deployment.sh

# Just test approval workflow  
./approval-workflow.sh

# Just test batch processing
./batch-signing.sh
```

### Customizing Examples

Edit the scripts to test different scenarios:

```bash
# Change the model being deployed
vim model-deployment.sh
# Look for "fraud-detector-v3" and modify

# Change approval requirements
vim approval-workflow.sh  
# Modify the "approvers" array

# Change batch contents
vim batch-signing.sh
# Modify the "evidence_packages" array
```

### Mock vs Real Services

The examples work with both:

- **Mock Implementation** (default): No external dependencies required
- **Real Services**: Start Vault/Rekor/Temporal for full functionality

## 🔗 Integration Patterns

### CI/CD Pipeline Integration

```yaml
# GitHub Actions example
- name: Notarize Deployment
  run: |
    ./examples/rest-api/model-deployment.sh
  env:
    NOTARY_URL: ${{ secrets.NOTARY_URL }}
```

### Monitoring Integration

```bash
# Health check for monitoring
if ! curl -f http://localhost:8080/health; then
  echo "Notary service is down!"
  exit 1
fi
```

### Webhook Integration

```bash
# Process webhook event
EVENT_DATA=$(cat webhook-payload.json)
curl -X POST http://localhost:8080/api/v1/evidence/sign \
  -H "Content-Type: application/json" \
  -d "$EVENT_DATA"
```

## 📊 Performance Considerations

### Batch vs Individual Requests

| Scenario | Individual Requests | Batch Request | Improvement |
|----------|-------------------|---------------|-------------|
| 5 Models | 5 API calls | 1 API call | 5x fewer calls |
| Network Latency | 5 × 50ms = 250ms | 1 × 50ms = 50ms | 5x faster |
| Processing | Sequential | Parallel | Variable |

### When to Use Batch

- ✅ Multiple related events (training pipeline completion)
- ✅ Scheduled operations (daily compliance scans)
- ✅ High-volume scenarios (>10 evidence packages)
- ❌ Real-time individual events
- ❌ Different approval requirements per item

## 🔒 Security Best Practices

### Development Environment

The examples are designed for development and testing:

- ⚠️ No authentication required
- ⚠️ Mock signatures used
- ⚠️ Simplified validation

### Production Deployment

For production use, implement:

- ✅ JWT or API key authentication
- ✅ TLS encryption (HTTPS)
- ✅ Rate limiting
- ✅ Input validation
- ✅ Audit logging
- ✅ Role-based access control

## 📚 Further Reading

- **[REST API Documentation](../docs/rest-api.md)** - Complete API reference
- **[OpenAPI Spec](http://localhost:8080/swagger-ui)** - Interactive documentation  
- **[AFDP Documentation](../README.md)** - Overall project documentation
- **[Temporal Workflows](../examples/temporal_workflows.rs)** - Workflow examples

## 🆘 Troubleshooting

### Common Issues

1. **Server not responding**
   ```bash
   # Check if server is running
   ps aux | grep afdp-notary-rest
   
   # Check server logs
   cargo run --bin afdp-notary-rest
   ```

2. **Connection refused**
   ```bash
   # Verify server is listening on correct port
   netstat -an | grep 8080
   
   # Try different URL
   export NOTARY_URL="http://127.0.0.1:8080"
   ```

3. **JSON parsing errors**
   ```bash
   # Validate JSON syntax
   echo "$EVIDENCE_PAYLOAD" | jq '.'
   
   # Check content-type header
   curl -v http://localhost:8080/api/v1/evidence/sign
   ```

4. **Workflow failures**
   ```bash
   # Check workflow status
   curl http://localhost:8080/api/v1/workflows/WORKFLOW_ID/status
   
   # Check server logs for errors
   ```

### Getting Help

- **Issues**: [GitHub Issues](https://github.com/caiatech/afdp-notary/issues)
- **Discussions**: [GitHub Discussions](https://github.com/caiatech/afdp-notary/discussions)
- **Email**: [support@caiatech.com](mailto:support@caiatech.com)

---

**Happy notarizing! 🎉**