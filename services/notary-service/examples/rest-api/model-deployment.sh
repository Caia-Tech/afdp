#!/bin/bash

# AFDP Notary Service REST API Example: Model Deployment
# This script demonstrates signing evidence for a model deployment event

set -e

# Configuration
NOTARY_URL="http://localhost:8080"
WORKFLOW_ID=""

echo "🚀 AFDP Notary Service - Model Deployment Example"
echo "================================================="

# Check if server is running
echo "🔍 Checking server health..."
if ! curl -f "$NOTARY_URL/health" > /dev/null 2>&1; then
    echo "❌ Notary service is not running at $NOTARY_URL"
    echo "   Please start the server with: cargo run --bin afdp-notary-rest"
    exit 1
fi
echo "✅ Server is healthy"

# Step 1: Sign evidence for model deployment
echo ""
echo "📝 Step 1: Signing model deployment evidence..."

EVIDENCE_PAYLOAD=$(cat <<EOF
{
  "evidence_package": {
    "spec_version": "1.0.0",
    "timestamp_utc": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
    "event_type": "model.deployment.completed",
    "actor": {
      "actor_type": "human_user",
      "id": "deployer@caiatech.com",
      "auth_provider": "oauth2"
    },
    "artifacts": [
      {
        "name": "fraud-detector-v3.pkl",
        "uri": "s3://afdp-models/fraud-detector-v3.pkl",
        "hash_sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
      },
      {
        "name": "model-config.yaml",
        "uri": "s3://afdp-models/fraud-detector-v3-config.yaml", 
        "hash_sha256": "2c26b46b68ffc68ff99b453c1d30413413422d706483bfa0f98a5e886266e7ae"
      }
    ],
    "metadata": {
      "model_id": "fraud-detector-v3",
      "version": "3.0.0",
      "environment": "production",
      "deployment_method": "kubernetes",
      "replicas": 3,
      "resource_requirements": {
        "cpu": "2",
        "memory": "4Gi"
      },
      "approval_checklist_id": "checklist-2025-001"
    }
  }
}
EOF
)

echo "Sending signing request..."
RESPONSE=$(curl -s -X POST "$NOTARY_URL/api/v1/evidence/sign" \
  -H "Content-Type: application/json" \
  -d "$EVIDENCE_PAYLOAD")

echo "Response:"
echo "$RESPONSE" | jq '.'

# Extract workflow ID
WORKFLOW_ID=$(echo "$RESPONSE" | jq -r '.workflow_id')
echo "📋 Workflow ID: $WORKFLOW_ID"

# Step 2: Check workflow status
echo ""
echo "📊 Step 2: Checking workflow status..."
STATUS_RESPONSE=$(curl -s "$NOTARY_URL/api/v1/workflows/$WORKFLOW_ID/status")
echo "$STATUS_RESPONSE" | jq '.'

# Step 3: Get notarization receipt
echo ""
echo "🧾 Step 3: Retrieving notarization receipt..."
RECEIPT_RESPONSE=$(curl -s "$NOTARY_URL/api/v1/workflows/$WORKFLOW_ID/receipt")
echo "$RECEIPT_RESPONSE" | jq '.'

# Extract key information
REKOR_LOG_ID=$(echo "$RECEIPT_RESPONSE" | jq -r '.rekor_log_id')
EVIDENCE_HASH=$(echo "$RECEIPT_RESPONSE" | jq -r '.evidence_package_hash')

echo ""
echo "✅ Model deployment successfully notarized!"
echo "📋 Summary:"
echo "   • Workflow ID: $WORKFLOW_ID"
echo "   • Rekor Log ID: $REKOR_LOG_ID"
echo "   • Evidence Hash: $EVIDENCE_HASH"
echo "   • Rekor Entry: https://search.sigstore.dev/?logIndex=$(echo "$RECEIPT_RESPONSE" | jq -r '.log_index')"

# Step 4: Validate the evidence (optional)
echo ""
echo "🔍 Step 4: Validating signed evidence..."
VALIDATION_PAYLOAD=$(cat <<EOF
{
  "evidence_package": $(echo "$EVIDENCE_PAYLOAD" | jq '.evidence_package'),
  "signature": "$(echo "$RECEIPT_RESPONSE" | jq -r '.signature_b64')"  
}
EOF
)

VALIDATION_RESPONSE=$(curl -s -X POST "$NOTARY_URL/api/v1/evidence/validate" \
  -H "Content-Type: application/json" \
  -d "$VALIDATION_PAYLOAD")

echo "Validation result:"
echo "$VALIDATION_RESPONSE" | jq '.'

IS_VALID=$(echo "$VALIDATION_RESPONSE" | jq -r '.is_valid')
if [ "$IS_VALID" = "true" ]; then
    echo "✅ Evidence validation passed!"
else
    echo "❌ Evidence validation failed!"
fi

echo ""
echo "🎉 Example completed successfully!"
echo ""
echo "💡 Next steps:"
echo "   • View all workflows at: $NOTARY_URL/api/v1/workflows"
echo "   • Explore API docs at: $NOTARY_URL/swagger-ui"
echo "   • Check server health at: $NOTARY_URL/health"