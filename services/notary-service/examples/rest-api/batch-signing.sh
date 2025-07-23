#!/bin/bash

# AFDP Notary Service REST API Example: Batch Signing
# This script demonstrates batch signing of multiple evidence packages

set -e

# Configuration
NOTARY_URL="http://localhost:8080"
BATCH_WORKFLOW_ID=""

echo "📦 AFDP Notary Service - Batch Signing Example"
echo "=============================================="

# Check if server is running
echo "🔍 Checking server health..."
if ! curl -f "$NOTARY_URL/health" > /dev/null 2>&1; then
    echo "❌ Notary service is not running at $NOTARY_URL"
    echo "   Please start the server with: cargo run --bin afdp-notary-rest"
    exit 1
fi
echo "✅ Server is healthy"

# Step 1: Prepare batch evidence packages
echo ""
echo "📝 Step 1: Preparing batch evidence packages..."

TIMESTAMP=$(date -u +%Y-%m-%dT%H:%M:%SZ)

BATCH_PAYLOAD=$(cat <<EOF
{
  "evidence_packages": [
    {
      "spec_version": "1.0.0",
      "timestamp_utc": "$TIMESTAMP",
      "event_type": "model.training.completed",
      "actor": {
        "actor_type": "service",
        "id": "training-pipeline-v2",
        "auth_provider": "kubernetes"
      },
      "artifacts": [
        {
          "name": "model-a-v1.pkl",
          "uri": "s3://afdp-models/model-a-v1.pkl",
          "hash_sha256": "1a2b3c4d5e6f7890abcdef1234567890abcdef1234567890abcdef1234567890"
        }
      ],
      "metadata": {
        "model_id": "model-a",
        "version": "1.0.0",
        "training_duration_minutes": 120,
        "dataset_version": "v2.1",
        "accuracy": 0.92
      }
    },
    {
      "spec_version": "1.0.0", 
      "timestamp_utc": "$TIMESTAMP",
      "event_type": "model.training.completed",
      "actor": {
        "actor_type": "service",
        "id": "training-pipeline-v2",
        "auth_provider": "kubernetes"
      },
      "artifacts": [
        {
          "name": "model-b-v1.pkl",
          "uri": "s3://afdp-models/model-b-v1.pkl",
          "hash_sha256": "2b3c4d5e6f7890abcdef1234567890abcdef1234567890abcdef1234567890ab"
        }
      ],
      "metadata": {
        "model_id": "model-b",
        "version": "1.0.0",
        "training_duration_minutes": 85,
        "dataset_version": "v1.8", 
        "accuracy": 0.89
      }
    },
    {
      "spec_version": "1.0.0",
      "timestamp_utc": "$TIMESTAMP", 
      "event_type": "model.validation.completed",
      "actor": {
        "actor_type": "service",
        "id": "validation-service",
        "auth_provider": "kubernetes"
      },
      "artifacts": [
        {
          "name": "validation-report-batch-001.json",
          "uri": "s3://afdp-reports/validation-batch-001.json",
          "hash_sha256": "3c4d5e6f7890abcdef1234567890abcdef1234567890abcdef1234567890abcd"
        }
      ],
      "metadata": {
        "batch_id": "validation-batch-001",
        "models_validated": ["model-a-v1", "model-b-v1"],
        "validation_type": "cross_validation",
        "passed": true
      }
    },
    {
      "spec_version": "1.0.0",
      "timestamp_utc": "$TIMESTAMP",
      "event_type": "dataset.preprocessing.completed", 
      "actor": {
        "actor_type": "service",
        "id": "data-pipeline-v3",
        "auth_provider": "kubernetes" 
      },
      "artifacts": [
        {
          "name": "processed-dataset-v2.2.parquet",
          "uri": "s3://afdp-datasets/processed-dataset-v2.2.parquet",
          "hash_sha256": "4d5e6f7890abcdef1234567890abcdef1234567890abcdef1234567890abcdef"
        }
      ],
      "metadata": {
        "dataset_id": "customer-transactions",
        "version": "2.2",
        "rows_processed": 1250000,
        "preprocessing_steps": ["normalization", "feature_engineering", "outlier_removal"],
        "data_quality_score": 0.97
      }
    },
    {
      "spec_version": "1.0.0",
      "timestamp_utc": "$TIMESTAMP",
      "event_type": "compliance.scan.completed",
      "actor": {
        "actor_type": "service", 
        "id": "compliance-scanner-v1",
        "auth_provider": "kubernetes"
      },
      "artifacts": [
        {
          "name": "compliance-scan-results.json",
          "uri": "s3://afdp-compliance/scan-results-$(date +%Y%m%d).json",
          "hash_sha256": "5e6f7890abcdef1234567890abcdef1234567890abcdef1234567890abcdef12"
        }
      ],
      "metadata": {
        "scan_id": "compliance-scan-$(date +%Y%m%d)",
        "framework": "GDPR",
        "models_scanned": ["model-a-v1", "model-b-v1"],
        "compliance_status": "compliant",
        "issues_found": 0
      }
    }
  ]
}
EOF
)

echo "Prepared $(echo "$BATCH_PAYLOAD" | jq '.evidence_packages | length') evidence packages for batch signing:"
echo "$BATCH_PAYLOAD" | jq -r '.evidence_packages[] | "   • \(.event_type) (\(.metadata.model_id // .metadata.dataset_id // .metadata.batch_id // .metadata.scan_id))"'

# Step 2: Submit batch signing request
echo ""
echo "🚀 Step 2: Submitting batch signing request..."

RESPONSE=$(curl -s -X POST "$NOTARY_URL/api/v1/evidence/sign/batch" \
  -H "Content-Type: application/json" \
  -d "$BATCH_PAYLOAD")

echo "Batch response:"
echo "$RESPONSE" | jq '.'

# Extract batch workflow ID
BATCH_WORKFLOW_ID=$(echo "$RESPONSE" | jq -r '.batch_workflow_id')
echo "📋 Batch Workflow ID: $BATCH_WORKFLOW_ID"

# Step 3: Monitor batch processing status
echo ""
echo "📊 Step 3: Monitoring batch processing status..."

# Check batch workflow status
BATCH_STATUS_RESPONSE=$(curl -s "$NOTARY_URL/api/v1/workflows/$BATCH_WORKFLOW_ID/status")
echo "Batch workflow status:"
echo "$BATCH_STATUS_RESPONSE" | jq '.'

BATCH_STATUS=$(echo "$BATCH_STATUS_RESPONSE" | jq -r '.status')
echo "Batch status: $BATCH_STATUS"

# Step 4: Check individual workflow results
echo ""
echo "🔍 Step 4: Checking individual workflow results..."

INDIVIDUAL_WORKFLOWS=$(echo "$RESPONSE" | jq -r '.results[].workflow_id')
echo "Individual workflows created:"

for workflow_id in $INDIVIDUAL_WORKFLOWS; do
    if [ -n "$workflow_id" ] && [ "$workflow_id" != "null" ]; then
        echo "   • Workflow ID: $workflow_id"
        
        # Get status for each individual workflow
        INDIVIDUAL_STATUS=$(curl -s "$NOTARY_URL/api/v1/workflows/$workflow_id/status")
        STATUS=$(echo "$INDIVIDUAL_STATUS" | jq -r '.status')
        EVENT_TYPE=$(echo "$INDIVIDUAL_STATUS" | jq -r '.result.event_type // "unknown"')
        
        echo "     Status: $STATUS"
        
        # If completed, get the receipt
        if [ "$STATUS" = "completed" ]; then
            RECEIPT_RESPONSE=$(curl -s "$NOTARY_URL/api/v1/workflows/$workflow_id/receipt")
            REKOR_LOG_ID=$(echo "$RECEIPT_RESPONSE" | jq -r '.rekor_log_id')
            echo "     Receipt: $REKOR_LOG_ID"
        fi
        echo ""
    fi
done

# Step 6: Show batch processing summary
echo ""
echo "📈 Step 5: Batch processing summary..."

TOTAL_PACKAGES=$(echo "$BATCH_PAYLOAD" | jq '.evidence_packages | length')
COMPLETED_WORKFLOWS=$(echo "$RESPONSE" | jq '[.results[] | select(.status == "completed")] | length')
PROCESSING_WORKFLOWS=$(echo "$RESPONSE" | jq '[.results[] | select(.status == "processing")] | length')

echo "Batch Summary:"
echo "   • Total packages: $TOTAL_PACKAGES"
echo "   • Completed workflows: $COMPLETED_WORKFLOWS"
echo "   • Processing workflows: $PROCESSING_WORKFLOWS"
echo "   • Batch workflow ID: $BATCH_WORKFLOW_ID"

# Step 6: List all recent workflows
echo ""
echo "📋 Step 6: Recent workflows overview..."
RECENT_WORKFLOWS=$(curl -s "$NOTARY_URL/api/v1/workflows?page_size=10")
echo "Recent workflows:"
echo "$RECENT_WORKFLOWS" | jq -r '.workflows[] | "   • \(.workflow_id) - \(.status) - \(.event_type)"'

echo ""
echo "✅ Batch signing example completed!"
echo ""
echo "📊 Performance Benefits of Batch Signing:"
echo "   • Reduced API calls: 1 batch request vs $TOTAL_PACKAGES individual requests"
echo "   • Improved throughput: Parallel processing of evidence packages"
echo "   • Better resource utilization: Optimized Temporal workflow execution"
echo "   • Simplified monitoring: Single batch workflow ID to track"

echo ""
echo "💡 Use Cases for Batch Signing:"
echo "   • End-of-pipeline processing (multiple models trained together)"
echo "   • Scheduled compliance scans (daily/weekly batch operations)"
echo "   • Data pipeline completions (multiple dataset transformations)"
echo "   • Bulk model validations (testing multiple model versions)"
echo "   • Audit trail consolidation (grouping related events)"

echo ""
echo "🔗 Monitoring endpoints:"
echo "   • Batch status: $NOTARY_URL/api/v1/workflows/$BATCH_WORKFLOW_ID/status"
echo "   • All workflows: $NOTARY_URL/api/v1/workflows"
echo "   • Server health: $NOTARY_URL/health"
echo "   • API docs: $NOTARY_URL/swagger-ui"