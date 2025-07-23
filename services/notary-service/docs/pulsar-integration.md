# Apache Pulsar Integration

The AFDP Notary Service integrates with Apache Pulsar to provide event-driven, scalable processing of AI deployment pipeline events. This integration enables automatic notarization workflows triggered by pipeline events, with real-time status updates and result publishing.

## Overview

The Pulsar integration follows an event-driven architecture pattern:

```text
AI Pipeline Events → Pulsar → Notary Consumer → Temporal Workflows → Results/Status
       ↓               ↓            ↓                 ↓                    ↓
   model.deploy → afdp.events → Auto Process → Sign/Approve → afdp.results
```

## Architecture Components

### Topics

The integration uses four main topics:

1. **`afdp.pipeline.events`**: Incoming events from AI deployment pipelines
2. **`afdp.notary.results`**: Notarization results and receipts
3. **`afdp.notary.status`**: Workflow status updates and notifications
4. **`afdp.notary.errors`**: Error events and processing failures

### Message Types

All messages use JSON encoding with standardized schemas:

- **PipelineEvent**: Events from AI systems requesting notarization
- **NotaryResult**: Final notarization results with receipts
- **NotaryStatus**: Real-time workflow status updates
- **NotaryError**: Error events and failure notifications

## Getting Started

### 1. Start Apache Pulsar

```bash
# Using Docker
docker run -it -p 6650:6650 -p 8080:8080 \
  --mount source=pulsardata,target=/pulsar/data \
  --mount source=pulsarconf,target=/pulsar/conf \
  apachepulsar/pulsar:latest \
  bin/pulsar standalone

# Or using Pulsar binary
bin/pulsar standalone
```

### 2. Configure the Notary Service

Set environment variables for Pulsar configuration:

```bash
# Pulsar service URL
export PULSAR_SERVICE_URL="pulsar://localhost:6650"

# Topic configuration
export PULSAR_EVENTS_TOPIC="afdp.pipeline.events"
export PULSAR_RESULTS_TOPIC="afdp.notary.results"
export PULSAR_STATUS_TOPIC="afdp.notary.status"
export PULSAR_ERRORS_TOPIC="afdp.notary.errors"

# Consumer configuration
export PULSAR_CONSUMER_NAME="afdp-notary-consumer"
export PULSAR_SUBSCRIPTION="afdp-notary-subscription"

# Authentication (optional)
export PULSAR_AUTH_METHOD="jwt"
export PULSAR_AUTH_TOKEN="your-jwt-token"

# TLS (optional)
export PULSAR_TLS_ENABLED="true"
```

### 3. Start the Pulsar Consumer

```bash
# Start the consumer
cargo run --bin afdp-notary-pulsar

# Or with custom configuration
PULSAR_SERVICE_URL=pulsar://prod-pulsar:6650 \
PULSAR_SUBSCRIPTION=prod-notary \
cargo run --bin afdp-notary-pulsar
```

### 4. Send Test Events

```bash
# Install Python Pulsar client
pip install pulsar-client

# Send a model deployment event
python examples/pulsar/send-model-deployment-event.py

# Monitor results
python examples/pulsar/monitor-results.py
```

## Event Schema

### Pipeline Event

Events sent to the `afdp.pipeline.events` topic:

```json
{
  "event_id": "deploy-uuid-123",
  "event_type": {
    "model_deployment": {
      "model_id": "fraud-detection-v2",
      "version": "2.1.0",
      "environment": "production",
      "strategy": "blue_green",
      "previous_version": "2.0.3"
    }
  },
  "timestamp": "2024-01-15T10:30:00Z",
  "source": "ci-cd-pipeline",
  "actor": {
    "actor_type": "ci_system",
    "id": "jenkins-prod-001",
    "auth_provider": "github_oauth"
  },
  "artifacts": [
    {
      "name": "fraud_model.pkl",
      "uri": "s3://ml-models/fraud_model.pkl",
      "hash_sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4..."
    }
  ],
  "metadata": {
    "deployment_id": "deploy-20240115-001",
    "pipeline_run_id": "run-456789",
    "model_accuracy": 0.94,
    "compliance_checked": true
  },
  "trace_id": "trace-uuid-456",
  "span_id": "span-uuid-789",
  "priority": "high",
  "workflow_config": {
    "workflow_type": "approval_sign",
    "approvers": [
      "security.lead@company.com",
      "ml.architect@company.com"
    ],
    "timeout": 3600,
    "retry_config": {
      "max_retries": 3,
      "initial_delay": 30,
      "backoff_multiplier": 2.0,
      "max_delay": 300
    },
    "notifications": {
      "enabled": true,
      "channels": [
        {"slack": "#ml-deployments"},
        {"email": ["devops@company.com"]}
      ],
      "events": [
        "workflow_started",
        "workflow_completed",
        "approval_required"
      ]
    }
  }
}
```

### Notary Result

Results published to the `afdp.notary.results` topic:

```json
{
  "event_id": "deploy-uuid-123",
  "workflow_id": "wf-approval-456",
  "workflow_type": "approval_sign",
  "timestamp": "2024-01-15T10:35:00Z",
  "success": true,
  "error": null,
  "receipt": {
    "evidence_package_hash": "sha256:abc123...",
    "rekor_log_id": "rekor-log-789",
    "rekor_server_url": "https://rekor.sigstore.dev",
    "signature_b64": "base64-signature...",
    "public_key_b64": "base64-public-key...",
    "integrated_time": 1705318500,
    "log_index": 12345
  },
  "processing_duration_ms": 2500,
  "trace_id": "trace-uuid-456",
  "metadata": {
    "approvers_count": 2,
    "approval_duration_ms": 1800000
  }
}
```

### Status Update

Status updates published to the `afdp.notary.status` topic:

```json
{
  "event_id": "deploy-uuid-123",
  "workflow_id": "wf-approval-456",
  "status": "pending_approval",
  "timestamp": "2024-01-15T10:32:00Z",
  "message": "Waiting for approvals from 2 approvers",
  "progress": {
    "current_step": "collecting_approvals",
    "total_steps": 4,
    "completed_steps": 2,
    "percentage": 50,
    "eta_seconds": 1200
  },
  "trace_id": "trace-uuid-456"
}
```

### Error Event

Errors published to the `afdp.notary.errors` topic:

```json
{
  "event_id": "deploy-uuid-123",
  "workflow_id": "wf-approval-456",
  "timestamp": "2024-01-15T10:33:00Z",
  "error_type": "validation",
  "message": "Invalid evidence package: missing required artifact hash",
  "details": {
    "validation_errors": [
      "artifact[0].hash_sha256 is required",
      "metadata.deployment_id is invalid"
    ]
  },
  "stack_trace": null,
  "retry_count": 1,
  "trace_id": "trace-uuid-456"
}
```

## Configuration

### Complete Configuration Example

```toml
# config/pulsar.toml
[pulsar]
service_url = "pulsar://localhost:6650"

[pulsar.consumer]
name = "afdp-notary-consumer"
subscription = "afdp-notary-subscription"
subscription_type = "Shared"
receive_queue_size = 1000
dead_letter_topic = "afdp.notary.dlq"
max_redeliveries = 3

[pulsar.consumer.batch_receive]
enabled = true
max_messages = 100
max_wait_time = "100ms"

[pulsar.producer]
name = "afdp-notary-producer"
send_timeout = "30s"
compression = "Lz4"
block_if_full = true

[pulsar.producer.batching]
enabled = true
max_messages = 100
max_bytes = 1048576  # 1MB
max_delay = "10ms"

[pulsar.topics]
events_topic = "afdp.pipeline.events"
results_topic = "afdp.notary.results"
status_topic = "afdp.notary.status"
errors_topic = "afdp.notary.errors"
tenant = "afdp"
namespace = "default"

[pulsar.auth]
method = "jwt"
token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."

[pulsar.connection]
connection_timeout = "30s"
operation_timeout = "30s"
keep_alive_interval = "30s"
max_connections_per_broker = 10
tls_enabled = false
tls_validate_hostname = true
```

### Environment Variables

All configuration can be overridden with environment variables:

```bash
# Service configuration
PULSAR_SERVICE_URL="pulsar://localhost:6650"

# Consumer settings
PULSAR_CONSUMER_NAME="afdp-notary-consumer"
PULSAR_SUBSCRIPTION="afdp-notary-subscription"
PULSAR_SUBSCRIPTION_TYPE="Shared"

# Producer settings
PULSAR_PRODUCER_NAME="afdp-notary-producer"
PULSAR_COMPRESSION="Lz4"

# Topics
PULSAR_EVENTS_TOPIC="afdp.pipeline.events"
PULSAR_RESULTS_TOPIC="afdp.notary.results"
PULSAR_STATUS_TOPIC="afdp.notary.status"
PULSAR_ERRORS_TOPIC="afdp.notary.errors"

# Authentication
PULSAR_AUTH_METHOD="jwt"
PULSAR_AUTH_TOKEN="your-jwt-token"

# TLS
PULSAR_TLS_ENABLED="true"
```

## Event Processing Flow

### 1. Event Reception

```text
Pipeline System → Pulsar Topic → Consumer → Validation → Handler
```

1. **Event Arrival**: Pipeline events arrive at `afdp.pipeline.events`
2. **Consumer Processing**: Pulsar consumer receives and deserializes messages
3. **Validation**: Event schema and business rules validation
4. **Handler Dispatch**: Routed to appropriate event handler

### 2. Workflow Execution

```text
Handler → Temporal Workflow → Activities → Vault/Rekor → Results
```

1. **Workflow Selection**: Based on `workflow_config.workflow_type`
2. **Temporal Execution**: Start appropriate Temporal workflow
3. **Activity Processing**: Execute signing, approval, or batch activities
4. **External Integration**: Interact with Vault and Rekor services
5. **Result Generation**: Create notarization receipt

### 3. Result Publishing

```text
Workflow Completion → Result Creation → Topic Publishing → Monitoring
```

1. **Status Updates**: Real-time progress published to status topic
2. **Final Results**: Completed workflows publish to results topic
3. **Error Handling**: Failed workflows publish to errors topic
4. **Monitoring**: External systems consume results for dashboards

## Advanced Features

### Event Filtering

The service supports filtering events based on various criteria:

```rust
use afdp_notary::pulsar::handlers::{FilteringEventHandler, DefaultEventHandler};

// Create filtering handler
let filter = FilteringEventHandler::new(
    Arc::new(DefaultEventHandler::new(temporal_client, producer)),
    Some(vec!["ai.model.deployment".to_string()]), // Only model deployments
    Some(vec!["production-pipeline".to_string()]), // Only from prod
    EventPriority::High, // Only high priority events
);
```

### Custom Event Handlers

Implement custom processing logic:

```rust
use afdp_notary::pulsar::handlers::EventHandler;
use async_trait::async_trait;

pub struct CustomEventHandler {
    // Custom fields
}

#[async_trait]
impl EventHandler for CustomEventHandler {
    async fn handle_event(&self, event: PipelineEvent) -> Result<()> {
        // Custom processing logic
        Ok(())
    }
}
```

### Batch Processing

Configure batch consumption for high-throughput scenarios:

```toml
[pulsar.consumer.batch_receive]
enabled = true
max_messages = 500
max_wait_time = "500ms"
```

### Dead Letter Queues

Configure DLQ for failed message handling:

```toml
[pulsar.consumer]
dead_letter_topic = "afdp.notary.dlq"
max_redeliveries = 5
```

## Monitoring and Observability

### Metrics

The Pulsar integration exposes metrics for monitoring:

- **Consumer Metrics**:
  - `pulsar_messages_received_total`
  - `pulsar_messages_processed_total`
  - `pulsar_processing_duration_seconds`
  - `pulsar_errors_total`

- **Producer Metrics**:
  - `pulsar_messages_sent_total`
  - `pulsar_send_duration_seconds`
  - `pulsar_send_errors_total`

### Health Checks

```bash
# Check consumer health
curl http://localhost:8080/health/pulsar

# Pulsar Admin API
bin/pulsar-admin topics stats persistent://afdp/default/afdp.pipeline.events
```

### Tracing

The integration supports distributed tracing:

```bash
# Enable tracing
export OTEL_EXPORTER_JAEGER_ENDPOINT="http://jaeger:14268/api/traces"
export PULSAR_TRACING_ENABLED="true"
```

## Production Deployment

### High Availability

```yaml
# docker-compose.yml
version: '3.8'
services:
  pulsar:
    image: apachepulsar/pulsar:latest
    command: bin/pulsar standalone
    ports:
      - "6650:6650"
      - "8080:8080"
    volumes:
      - pulsar-data:/pulsar/data
      - pulsar-conf:/pulsar/conf
  
  notary-consumer-1:
    image: afdp-notary:latest
    command: afdp-notary-pulsar
    environment:
      - PULSAR_SERVICE_URL=pulsar://pulsar:6650
      - PULSAR_CONSUMER_NAME=afdp-notary-consumer-1
    depends_on:
      - pulsar
  
  notary-consumer-2:
    image: afdp-notary:latest
    command: afdp-notary-pulsar
    environment:
      - PULSAR_SERVICE_URL=pulsar://pulsar:6650
      - PULSAR_CONSUMER_NAME=afdp-notary-consumer-2
    depends_on:
      - pulsar
```

### Security

```bash
# TLS Configuration
export PULSAR_TLS_ENABLED="true"
export PULSAR_TLS_CERT_PATH="/etc/ssl/certs/pulsar.crt"
export PULSAR_TLS_KEY_PATH="/etc/ssl/private/pulsar.key"

# Authentication
export PULSAR_AUTH_METHOD="jwt"
export PULSAR_AUTH_TOKEN="$(cat /etc/pulsar/jwt-token)"
```

### Performance Tuning

```toml
# High-throughput configuration
[pulsar.consumer]
receive_queue_size = 5000

[pulsar.consumer.batch_receive]
enabled = true
max_messages = 1000
max_wait_time = "50ms"

[pulsar.producer.batching]
enabled = true
max_messages = 1000
max_bytes = 5242880  # 5MB
max_delay = "5ms"
```

## Troubleshooting

### Common Issues

1. **Connection Failed**:
   ```bash
   # Check Pulsar status
   curl http://localhost:8080/admin/v2/clusters
   
   # Verify network connectivity
   telnet localhost 6650
   ```

2. **Messages Not Consuming**:
   ```bash
   # Check subscription status
   bin/pulsar-admin topics subscriptions persistent://afdp/default/afdp.pipeline.events
   
   # Reset subscription
   bin/pulsar-admin topics reset-cursor -s afdp-notary-subscription -p latest
   ```

3. **High Memory Usage**:
   ```toml
   # Reduce queue sizes
   [pulsar.consumer]
   receive_queue_size = 100
   
   [pulsar.consumer.batch_receive]
   max_messages = 50
   ```

### Debug Mode

```bash
# Enable debug logging
export RUST_LOG="afdp_notary::pulsar=debug,pulsar=debug"
cargo run --bin afdp-notary-pulsar
```

### Message Inspection

```python
# Inspect messages in topic
import pulsar

client = pulsar.Client('pulsar://localhost:6650')
reader = client.create_reader('persistent://afdp/default/afdp.pipeline.events', 
                             pulsar.MessageId.earliest)

while True:
    msg = reader.read_next()
    print(f"Message: {msg.data()}")
    print(f"Properties: {msg.properties()}")
```

## Integration Examples

### CI/CD Pipeline Integration

```yaml
# .github/workflows/deploy.yml
- name: Send Deployment Event
  run: |
    python -c "
    import pulsar, json, uuid
    client = pulsar.Client('pulsar://pulsar:6650')
    producer = client.create_producer('persistent://afdp/default/afdp.pipeline.events')
    event = {
      'event_id': str(uuid.uuid4()),
      'event_type': {'model_deployment': {
        'model_id': '${{ github.repository }}',
        'version': '${{ github.sha }}',
        'environment': 'production'
      }},
      'source': 'github-actions',
      'actor': {'actor_type': 'ci_system', 'id': 'github-actions'},
      'artifacts': [{'name': 'model.pkl', 'hash_sha256': '${{ steps.hash.outputs.hash }}'}],
      'workflow_config': {'workflow_type': 'simple_sign'}
    }
    producer.send(json.dumps(event))
    "
```

### Kubernetes Deployment

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: afdp-notary-pulsar
spec:
  replicas: 3
  selector:
    matchLabels:
      app: afdp-notary-pulsar
  template:
    metadata:
      labels:
        app: afdp-notary-pulsar
    spec:
      containers:
      - name: notary-consumer
        image: afdp-notary:latest
        command: ["afdp-notary-pulsar"]
        env:
        - name: PULSAR_SERVICE_URL
          value: "pulsar://pulsar-broker:6650"
        - name: PULSAR_SUBSCRIPTION
          value: "afdp-notary-k8s"
        resources:
          requests:
            memory: "256Mi"
            cpu: "250m"
          limits:
            memory: "512Mi"
            cpu: "500m"
```

The Apache Pulsar integration provides a robust, scalable foundation for event-driven notarization workflows in the AFDP ecosystem. It supports high-throughput processing, reliable message delivery, and comprehensive monitoring for production deployments.