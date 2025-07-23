#!/bin/bash

# AFDP Notary Service REST API Example: Approval Workflow
# This script demonstrates signing evidence requiring multi-party approval

set -e

# Configuration
NOTARY_URL="http://localhost:8080"
WORKFLOW_ID=""

echo "🔒 AFDP Notary Service - Approval Workflow Example"
echo "=================================================="

# Check if server is running
echo "🔍 Checking server health..."
if ! curl -f "$NOTARY_URL/health" > /dev/null 2>&1; then
    echo "❌ Notary service is not running at $NOTARY_URL"
    echo "   Please start the server with: cargo run --bin afdp-notary-rest"
    exit 1
fi
echo "✅ Server is healthy"

# Step 1: Initiate approval workflow for production deployment
echo ""
echo "📝 Step 1: Initiating approval workflow for production deployment..."

APPROVAL_PAYLOAD=$(cat <<EOF
{
  "evidence_package": {
    "spec_version": "1.0.0",
    "timestamp_utc": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
    "event_type": "model.deployment.production.approval_required",
    "actor": {
      "actor_type": "human_user",
      "id": "developer@caiatech.com",
      "auth_provider": "oauth2"
    },
    "artifacts": [
      {
        "name": "critical-fraud-model-v4.pkl",
        "uri": "s3://afdp-models/critical-fraud-model-v4.pkl",
        "hash_sha256": "a665a45920422f9d417e4867efdc4fb8a04a1f3fff1fa07e998e86f7f7a27ae3"
      },
      {
        "name": "model-performance-report.pdf",
        "uri": "s3://afdp-reports/critical-fraud-model-v4-performance.pdf",
        "hash_sha256": "b5d4045c3f466fa91fe2cc6abe79232a1a57cdf104f7a26e716e0a1e2789df78"
      },
      {
        "name": "security-scan-results.json",
        "uri": "s3://afdp-security/critical-fraud-model-v4-scan.json",
        "hash_sha256": "c3499c2729c4f8e4d6f7c8dc5e5a3a3a0a1b2c3d4e5f6789abcdef0123456789"
      }
    ],
    "metadata": {
      "model_id": "critical-fraud-model-v4",
      "version": "4.0.0",
      "environment": "production",
      "risk_level": "high",
      "compliance_framework": "SOX",
      "deployment_urgency": "standard",
      "performance_metrics": {
        "accuracy": 0.97,
        "precision": 0.95,
        "recall": 0.94,
        "f1_score": 0.945
      },
      "security_scan": {
        "passed": true,
        "vulnerabilities": 0,
        "scan_date": "2025-07-23"
      }
    }
  },
  "approvers": [
    "security-lead@caiatech.com",
    "compliance-officer@caiatech.com", 
    "ml-architect@caiatech.com"
  ]
}
EOF
)

echo "Sending approval request..."
RESPONSE=$(curl -s -X POST "$NOTARY_URL/api/v1/evidence/sign/approval" \
  -H "Content-Type: application/json" \
  -d "$APPROVAL_PAYLOAD")

echo "Response:"
echo "$RESPONSE" | jq '.'

# Extract workflow ID
WORKFLOW_ID=$(echo "$RESPONSE" | jq -r '.workflow_id')
echo "📋 Approval Workflow ID: $WORKFLOW_ID"

# Step 2: Check initial workflow status
echo ""
echo "📊 Step 2: Checking initial workflow status..."
STATUS_RESPONSE=$(curl -s "$NOTARY_URL/api/v1/workflows/$WORKFLOW_ID/status")
echo "$STATUS_RESPONSE" | jq '.'

STATUS=$(echo "$STATUS_RESPONSE" | jq -r '.status')
echo "Current status: $STATUS"

# Step 3: Show approval status breakdown
echo ""
echo "🔍 Step 3: Approval status breakdown..."
APPROVAL_STATUSES=$(echo "$RESPONSE" | jq '.approval_statuses[]')
echo "Required approvals:"

echo "$RESPONSE" | jq -r '.approval_statuses[] | "   • \(.approver): \(.status) (as of \(.timestamp))"'

# Step 4: Simulate approval workflow monitoring
echo ""
echo "⌛ Step 4: Monitoring approval workflow..."
echo "In a real scenario, this workflow would:"
echo "   1. Send notifications to all required approvers"
echo "   2. Wait for approvals through the approval interface"
echo "   3. Proceed with signing once all approvals are received"
echo "   4. Generate the final notarization receipt"

echo ""
echo "📧 Notification would be sent to:"
echo "$APPROVAL_PAYLOAD" | jq -r '.approvers[] | "   • \(.)"'

# Step 5: Show how to check for updates
echo ""
echo "🔄 Step 5: Checking for workflow updates..."
echo "To monitor approval progress, you would periodically check:"
echo "   GET $NOTARY_URL/api/v1/workflows/$WORKFLOW_ID/status"

# Simulate checking after some time
echo ""
echo "📊 Checking status again (simulated after approvals)..."
UPDATED_STATUS=$(curl -s "$NOTARY_URL/api/v1/workflows/$WORKFLOW_ID/status")
echo "$UPDATED_STATUS" | jq '.'

# Step 6: List all workflows to show in context
echo ""
echo "📋 Step 6: Viewing all workflows..."
WORKFLOWS_RESPONSE=$(curl -s "$NOTARY_URL/api/v1/workflows?status_filter=pending")
echo "Pending workflows:"
echo "$WORKFLOWS_RESPONSE" | jq '.'

echo ""
echo "✅ Approval workflow example completed!"
echo ""
echo "📋 Summary:"
echo "   • Approval Workflow ID: $WORKFLOW_ID"
echo "   • Required Approvers: 3"
echo "   • Current Status: $STATUS"
echo "   • Model: critical-fraud-model-v4 (High Risk)"

echo ""
echo "💡 In a production system:"
echo "   • Approvers would receive email/Slack notifications"
echo "   • Approval interface would be integrated with your identity provider"
echo "   • Workflow would automatically progress based on approval rules"
echo "   • Audit logs would track all approval actions"
echo "   • Timeout policies would handle stale approval requests"

echo ""
echo "🔗 Useful endpoints:"
echo "   • Workflow status: $NOTARY_URL/api/v1/workflows/$WORKFLOW_ID/status"
echo "   • All workflows: $NOTARY_URL/api/v1/workflows"
echo "   • API documentation: $NOTARY_URL/swagger-ui"