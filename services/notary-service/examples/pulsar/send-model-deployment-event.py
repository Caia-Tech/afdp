#!/usr/bin/env python3
"""
Example: Send model deployment event to Pulsar

This script demonstrates how to send a model deployment event to the
AFDP Notary Service via Apache Pulsar for automatic notarization.

Prerequisites:
- Apache Pulsar running on localhost:6650
- Python pulsar-client library: pip install pulsar-client
- AFDP Notary Pulsar consumer running

Usage:
    python send-model-deployment-event.py
    
Configuration:
    Set environment variables:
    - PULSAR_SERVICE_URL (default: pulsar://localhost:6650)
    - PULSAR_EVENTS_TOPIC (default: afdp.pipeline.events)
"""

import json
import os
import uuid
from datetime import datetime, timezone
import pulsar

def create_model_deployment_event():
    """Create a sample model deployment event"""
    return {
        "event_id": f"deploy-{uuid.uuid4()}",
        "event_type": {
            "model_deployment": {
                "model_id": "fraud-detection-v2",
                "version": "2.1.0",
                "environment": "production",
                "strategy": "blue_green",
                "previous_version": "2.0.3"
            }
        },
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "source": "ci-cd-pipeline",
        "actor": {
            "actor_type": "ci_system",
            "id": "jenkins-prod-001",
            "auth_provider": "github_oauth"
        },
        "artifacts": [
            {
                "name": "fraud_model.pkl",
                "uri": "s3://ml-models-prod/fraud-detection/v2.1.0/fraud_model.pkl",
                "hash_sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
            },
            {
                "name": "model_config.json",
                "uri": "s3://ml-models-prod/fraud-detection/v2.1.0/model_config.json",
                "hash_sha256": "d4735e3a265e16eee03f59718b9b5d03019c07d8b6c51f90da3a666eec13ab35"
            },
            {
                "name": "validation_report.pdf",
                "uri": "s3://ml-reports/fraud-detection/v2.1.0/validation_report.pdf",
                "hash_sha256": "4e07408562bedb8b60ce05c1decfe3ad16b72230967de01f640b7e4729b49fce"
            }
        ],
        "metadata": {
            "deployment_id": "deploy-20240115-001",
            "pipeline_run_id": "run-456789",
            "model_accuracy": 0.94,
            "dataset_version": "fraud-data-v3.2",
            "compliance_checked": True,
            "performance_validated": True,
            "security_scanned": True
        },
        "trace_id": f"trace-{uuid.uuid4()}",
        "span_id": f"span-{uuid.uuid4()}",
        "priority": "high",
        "workflow_config": {
            "workflow_type": "approval_sign",
            "approvers": [
                "security.lead@company.com",
                "ml.architect@company.com",
                "compliance.officer@company.com"
            ],
            "timeout": 3600,
            "retry_config": {
                "max_retries": 3,
                "initial_delay": 30,
                "backoff_multiplier": 2.0,
                "max_delay": 300
            },
            "notifications": {
                "enabled": True,
                "channels": [
                    {"slack": "#ml-deployments"},
                    {"email": ["devops@company.com"]}
                ],
                "events": [
                    "workflow_started",
                    "workflow_completed",
                    "workflow_failed",
                    "approval_required"
                ]
            }
        }
    }

def main():
    # Configuration
    service_url = os.getenv('PULSAR_SERVICE_URL', 'pulsar://localhost:6650')
    topic = os.getenv('PULSAR_EVENTS_TOPIC', 'persistent://afdp/default/afdp.pipeline.events')
    
    print("🚀 AFDP Notary Service - Pulsar Event Publisher")
    print("=" * 50)
    print(f"Service URL: {service_url}")
    print(f"Topic: {topic}")
    print()
    
    try:
        # Create Pulsar client
        print("📡 Connecting to Pulsar...")
        client = pulsar.Client(service_url)
        
        # Create producer
        producer = client.create_producer(
            topic,
            producer_name="afdp-event-publisher",
            compression_type=pulsar.CompressionType.LZ4,
            batching_enabled=True,
            batching_max_messages=10,
            batching_max_publish_delay_ms=100
        )
        
        print("✅ Connected to Pulsar successfully")
        
        # Create model deployment event
        event = create_model_deployment_event()
        
        print("📦 Created model deployment event:")
        print(f"   Event ID: {event['event_id']}")
        print(f"   Model: {event['event_type']['model_deployment']['model_id']}")
        print(f"   Version: {event['event_type']['model_deployment']['version']}")
        print(f"   Environment: {event['event_type']['model_deployment']['environment']}")
        print(f"   Artifacts: {len(event['artifacts'])} files")
        print(f"   Workflow: {event['workflow_config']['workflow_type']}")
        print(f"   Approvers: {len(event['workflow_config']['approvers'])} required")
        print()
        
        # Send event
        print("📤 Sending event to Pulsar...")
        message_data = json.dumps(event, indent=None).encode('utf-8')
        
        # Add message properties for routing and filtering
        properties = {
            'event_id': event['event_id'],
            'event_type': 'model_deployment',
            'source': event['source'],
            'priority': event['priority'],
            'workflow_type': event['workflow_config']['workflow_type'],
            'trace_id': event['trace_id']
        }
        
        message_id = producer.send(
            message_data,
            properties=properties,
            partition_key=event['event_type']['model_deployment']['model_id']
        )
        
        print(f"✅ Event sent successfully!")
        print(f"   Message ID: {message_id}")
        print(f"   Partition Key: {event['event_type']['model_deployment']['model_id']}")
        print()
        
        print("📋 Next Steps:")
        print("   1. The AFDP Notary consumer will receive this event")
        print("   2. An approval workflow will be started automatically")
        print("   3. Approvers will be notified to review the deployment")
        print("   4. Once approved, the evidence will be cryptographically signed")
        print("   5. Results will be published to the results topic")
        print()
        
        print("🔍 Monitor Progress:")
        print("   - Check notary service logs for processing updates")
        print("   - Monitor Pulsar topics for status and result messages")
        print("   - Use Temporal Web UI to track workflow progress")
        print()
        
        print(f"🎉 Model deployment event published successfully!")
        print(f"   Track with Event ID: {event['event_id']}")
        print(f"   Trace ID: {event['trace_id']}")
        
    except Exception as e:
        print(f"❌ Error: {str(e)}")
        return 1
        
    finally:
        # Cleanup
        if 'producer' in locals():
            producer.close()
        if 'client' in locals():
            client.close()
    
    return 0

if __name__ == "__main__":
    exit(main())