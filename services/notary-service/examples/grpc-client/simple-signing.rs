//! Example: Simple evidence signing via gRPC
//!
//! This example demonstrates how to use the AFDP Notary Service gRPC client
//! to sign an evidence package using the simple signing workflow.
//!
//! Usage:
//!   cargo run --example simple-signing
//!
//! Prerequisites:
//! - gRPC server running on localhost:50051
//! - Temporal server running (mock implementation used for this example)

use afdp_notary::{
    evidence::{Actor, Artifact, EvidencePackage},
    grpc::notary::{notary_service_client::NotaryServiceClient, SignEvidenceRequest},
};
use std::collections::HashMap;
use tonic::Request;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("🔐 AFDP Notary Service - gRPC Simple Signing Example");
    println!("===================================================\n");

    // Connect to the gRPC server
    let mut client = NotaryServiceClient::connect("http://localhost:50051").await?;
    println!("✅ Connected to gRPC server");

    // Create an actor representing the signing entity
    let actor = Actor {
        actor_type: "ci_system".to_string(),
        id: "github-actions-runner-001".to_string(),
        auth_provider: Some("github_oauth".to_string()),
    };

    // Create artifacts representing the files to be notarized
    let model_artifact = Artifact {
        name: "pytorch_model.pth".to_string(),
        uri: Some("s3://ai-models/pytorch_model.pth".to_string()),
        hash_sha256: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855".to_string(),
    };

    let config_artifact = Artifact {
        name: "model_config.json".to_string(),
        uri: Some("s3://ai-models/model_config.json".to_string()),
        hash_sha256: "d3b07384d113edec49eaa6238ad5ff00".to_string(),
    };

    // Create metadata about the deployment event
    let mut metadata = HashMap::new();
    metadata.insert("deployment_id".to_string(), serde_json::json!("deploy-20240115-001"));
    metadata.insert("environment".to_string(), serde_json::json!("production"));
    metadata.insert("model_version".to_string(), serde_json::json!("v2.1.0"));
    metadata.insert("deployment_strategy".to_string(), serde_json::json!("blue_green"));

    // Create the evidence package
    let evidence_package = EvidencePackage {
        spec_version: "1.0.0".to_string(),
        timestamp_utc: chrono::Utc::now(),
        event_type: "ai.model.deployment.completed".to_string(),
        actor,
        artifacts: vec![model_artifact, config_artifact],
        metadata,
    };

    println!("📦 Created evidence package:");
    println!("   Event Type: {}", evidence_package.event_type);
    println!("   Actor: {} ({})", evidence_package.actor.id, evidence_package.actor.actor_type);
    println!("   Artifacts: {} files", evidence_package.artifacts.len());
    println!("   Timestamp: {}\n", evidence_package.timestamp_utc.format("%Y-%m-%d %H:%M:%S UTC"));

    // Create the gRPC request
    let request = Request::new(SignEvidenceRequest {
        evidence_package: Some(evidence_package.into()),
    });

    println!("🚀 Sending evidence package to notary service...");

    // Call the gRPC service
    match client.sign_evidence(request).await {
        Ok(response) => {
            let sign_response = response.into_inner();
            
            println!("✅ Evidence package signed successfully!");
            println!("   Workflow ID: {}", sign_response.workflow_id);
            println!("   Status: {:?}", sign_response.status);
            
            if let Some(receipt) = sign_response.receipt {
                println!("\n🧾 Notarization Receipt:");
                println!("   Evidence Hash: {}", receipt.evidence_package_hash);
                println!("   Rekor Log ID: {}", receipt.rekor_log_id);
                println!("   Rekor Server: {}", receipt.rekor_server_url);
                println!("   Log Index: {}", receipt.log_index);
                println!("   Integration Time: {}", 
                    chrono::DateTime::from_timestamp(receipt.integrated_time, 0)
                        .unwrap_or_default()
                        .format("%Y-%m-%d %H:%M:%S UTC"));
            }

            println!("\n🎉 Simple signing workflow completed successfully!");
        }
        Err(e) => {
            eprintln!("❌ Failed to sign evidence package: {}", e);
            std::process::exit(1);
        }
    }

    Ok(())
}