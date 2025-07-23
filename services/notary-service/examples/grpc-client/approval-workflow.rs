//! Example: Approval workflow via gRPC
//!
//! This example demonstrates how to use the AFDP Notary Service gRPC client
//! to sign an evidence package using the approval workflow that requires
//! multiple approvers before the evidence can be notarized.
//!
//! Usage:
//!   cargo run --example approval-workflow
//!
//! Prerequisites:
//! - gRPC server running on localhost:50051
//! - Temporal server running (mock implementation used for this example)

use afdp_notary::{
    evidence::{Actor, Artifact, EvidencePackage},
    grpc::notary::{
        notary_service_client::NotaryServiceClient,
        SignEvidenceWithApprovalRequest,
        GetWorkflowStatusRequest,
    },
};
use std::collections::HashMap;
use tonic::Request;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("👥 AFDP Notary Service - gRPC Approval Workflow Example");
    println!("======================================================\n");

    // Connect to the gRPC server
    let mut client = NotaryServiceClient::connect("http://localhost:50051").await?;
    println!("✅ Connected to gRPC server");

    // Create an actor representing the entity requesting approval
    let actor = Actor {
        actor_type: "data_scientist".to_string(),
        id: "alice.smith@company.com".to_string(),
        auth_provider: Some("corporate_sso".to_string()),
    };

    // Create artifacts for a high-risk model deployment
    let model_artifact = Artifact {
        name: "high_risk_model.pkl".to_string(),
        uri: Some("s3://ml-models/high_risk_model.pkl".to_string()),
        hash_sha256: "a1b2c3d4e5f6789012345678901234567890abcdef".to_string(),
    };

    let validation_report = Artifact {
        name: "validation_report.pdf".to_string(),
        uri: Some("s3://ml-reports/validation_report.pdf".to_string()),
        hash_sha256: "9876543210abcdef9876543210abcdef".to_string(),
    };

    // Create metadata indicating this is a high-risk deployment
    let mut metadata = HashMap::new();
    metadata.insert("risk_level".to_string(), serde_json::json!("high"));
    metadata.insert("compliance_required".to_string(), serde_json::json!(true));
    metadata.insert("deployment_environment".to_string(), serde_json::json!("production"));
    metadata.insert("business_impact".to_string(), serde_json::json!("critical"));
    metadata.insert("data_classification".to_string(), serde_json::json!("sensitive"));

    // Create the evidence package
    let evidence_package = EvidencePackage {
        spec_version: "1.0.0".to_string(),
        timestamp_utc: chrono::Utc::now(),
        event_type: "ai.model.deployment.high_risk".to_string(),
        actor,
        artifacts: vec![model_artifact, validation_report],
        metadata,
    };

    // Define required approvers for high-risk deployments
    let approvers = vec![
        "security.lead@company.com".to_string(),
        "compliance.officer@company.com".to_string(),
        "ml.architect@company.com".to_string(),
    ];

    println!("📦 Created high-risk evidence package:");
    println!("   Event Type: {}", evidence_package.event_type);
    println!("   Requester: {} ({})", evidence_package.actor.id, evidence_package.actor.actor_type);
    println!("   Artifacts: {} files", evidence_package.artifacts.len());
    println!("   Required Approvers: {}", approvers.len());
    for approver in &approvers {
        println!("     - {}", approver);
    }
    println!("   Timestamp: {}\n", evidence_package.timestamp_utc.format("%Y-%m-%d %H:%M:%S UTC"));

    // Create the approval workflow request
    let request = Request::new(SignEvidenceWithApprovalRequest {
        evidence_package: Some(evidence_package.into()),
        approvers: approvers.clone(),
    });

    println!("🚀 Starting approval workflow...");

    // Start the approval workflow
    match client.sign_evidence_with_approval(request).await {
        Ok(response) => {
            let approval_response = response.into_inner();
            
            println!("✅ Approval workflow started successfully!");
            println!("   Workflow ID: {}", approval_response.workflow_id);
            println!("   Status: {:?}", approval_response.status);
            
            println!("\n👥 Approval Status:");
            for approval in &approval_response.approval_statuses {
                let status_icon = match approval.status {
                    1 => "⏳", // Pending
                    2 => "✅", // Approved
                    3 => "❌", // Rejected
                    _ => "❓", // Unknown
                };
                
                let status_text = match approval.status {
                    1 => "Pending",
                    2 => "Approved", 
                    3 => "Rejected",
                    _ => "Unknown",
                };
                
                println!("   {} {}: {}", status_icon, approval.approver, status_text);
            }

            // Simulate checking workflow status
            println!("\n🔍 Checking workflow status...");
            let status_request = Request::new(GetWorkflowStatusRequest {
                workflow_id: approval_response.workflow_id.clone(),
            });

            match client.get_workflow_status(status_request).await {
                Ok(status_response) => {
                    let status = status_response.into_inner();
                    println!("   Workflow Status: {:?}", status.status);
                    
                    if let Some(created_at) = status.created_at {
                        println!("   Created: {}", 
                            chrono::DateTime::from_timestamp(created_at.seconds, created_at.nanos as u32)
                                .unwrap_or_default()
                                .format("%Y-%m-%d %H:%M:%S UTC"));
                    }
                }
                Err(e) => {
                    eprintln!("⚠️  Failed to get workflow status: {}", e);
                }
            }

            println!("\n📋 Next Steps:");
            println!("   1. Approvers will receive notifications to review the deployment");
            println!("   2. Each approver must explicitly approve or reject the request");
            println!("   3. Once all approvers approve, the evidence will be automatically signed");
            println!("   4. Use GetWorkflowStatus to monitor progress");
            println!("   5. Use GetNotarizationReceipt to retrieve the final receipt");
            
            println!("\n🎉 Approval workflow initiated successfully!");
            println!("   Monitor workflow ID: {}", approval_response.workflow_id);
        }
        Err(e) => {
            eprintln!("❌ Failed to start approval workflow: {}", e);
            std::process::exit(1);
        }
    }

    Ok(())
}