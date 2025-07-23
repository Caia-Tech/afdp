//! Example of basic notarization using the AFDP Notary Service

use afdp_notary::{Actor, EvidencePackage};
use serde_json::json;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Initialize logging
    tracing_subscriber::fmt::init();

    // Create an actor representing a CI/CD workflow
    let actor = Actor {
        actor_type: "workflow".to_string(),
        id: "github-actions-deploy-123".to_string(),
        auth_provider: Some("github".to_string()),
    };

    // Create an evidence package for a model deployment
    let package = EvidencePackage::new("ai.model.deployment.completed".to_string(), actor)
        .add_metadata("model_name".to_string(), json!("fraud_detector_v2"))
        .add_metadata("environment".to_string(), json!("production"))
        .add_metadata("version".to_string(), json!("2.3.1"))
        .add_metadata("accuracy".to_string(), json!(0.987))
        .add_metadata("deployed_by".to_string(), json!("marvin.tutt@caiatech.com"));

    // Print the evidence package
    println!("Evidence Package:");
    println!("{}", serde_json::to_string_pretty(&package)?);

    // Calculate and print the hash
    let hash = package.calculate_hash()?;
    println!("\nEvidence Package Hash: {}", hash);

    // In a real scenario, you would now:
    // 1. Initialize the VaultRekorNotary with proper configuration
    // 2. Call notary.notarize(package) to get a receipt
    // 3. Store the receipt alongside your artifact (e.g., in Git)

    println!("\nTo complete notarization, run with Vault and Rekor configured.");

    Ok(())
}