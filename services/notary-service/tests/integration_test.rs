//! Integration tests for the AFDP Notary Service

use afdp_notary::{Actor, Artifact, EvidencePackage};
use serde_json::json;

#[test]
fn test_evidence_package_complete_flow() {
    // Create an actor
    let actor = Actor {
        actor_type: "workflow".to_string(),
        id: "temporal-wf-123".to_string(),
        auth_provider: Some("keycloak".to_string()),
    };

    // Create an evidence package
    let package = EvidencePackage::new("ai.model.deployment.approved".to_string(), actor)
        .add_artifact(Artifact {
            name: "fraud_detection_model.v2.onnx".to_string(),
            uri: Some("s3://afdp-models/fraud_detection_model.v2.onnx".to_string()),
            hash_sha256: "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2".to_string(),
        })
        .add_metadata("approved_for".to_string(), json!("production/us-east-1"))
        .add_metadata("compliance_checklist_id".to_string(), json!("chk-9876"))
        .add_metadata("review_ticket".to_string(), json!("JIRA-456"));

    // Verify serialization
    let json_str = serde_json::to_string_pretty(&package).unwrap();
    println!("Evidence Package JSON:\n{}", json_str);

    // Verify hash calculation
    let hash = package.calculate_hash().unwrap();
    println!("Evidence Package Hash: {}", hash);
    
    // Verify the package structure
    assert_eq!(package.spec_version, "1.0.0");
    assert_eq!(package.event_type, "ai.model.deployment.approved");
    assert_eq!(package.artifacts.len(), 1);
    assert_eq!(package.metadata.len(), 3);
}

// Note: Full integration test with Vault and Rekor requires running instances
// This would be enabled with the "integration-tests" feature flag
#[cfg(feature = "integration-tests")]
#[tokio::test]
async fn test_notarization_with_vault_and_rekor() {
    use afdp_notary::{NotaryClient, VaultRekorNotary};
    use afdp_notary::notary::NotaryConfig;
    use afdp_notary::vault::VaultConfig;
    use afdp_notary::rekor::RekorConfig;

    // This test requires:
    // 1. Vault running in dev mode
    // 2. Transit key created: vault write -f transit/keys/afdp-notary-key
    // 3. VAULT_ADDR and VAULT_TOKEN environment variables set

    let vault_config = VaultConfig {
        address: std::env::var("VAULT_ADDR").unwrap_or_else(|_| "http://127.0.0.1:8200".to_string()),
        token: std::env::var("VAULT_TOKEN").unwrap_or_else(|_| "root".to_string()),
        transit_key_name: "afdp-notary-key".to_string(),
    };

    let rekor_config = RekorConfig::default();

    let config = NotaryConfig {
        vault_config,
        rekor_config,
    };

    // Create notary client
    let notary = VaultRekorNotary::new(config).await.unwrap();

    // Create test evidence package
    let actor = Actor {
        actor_type: "test".to_string(),
        id: "integration-test".to_string(),
        auth_provider: None,
    };

    let package = EvidencePackage::new("test.integration.event".to_string(), actor)
        .add_metadata("test_run".to_string(), json!(true));

    // Notarize the package
    let receipt = notary.notarize(package).await.unwrap();
    
    println!("Notarization Receipt:");
    println!("  Rekor Log ID: {}", receipt.rekor_log_id);
    println!("  Log Index: {}", receipt.log_index);
    println!("  Integrated Time: {}", receipt.integrated_time);

    // Verify the receipt
    let is_valid = notary.verify(&receipt).await.unwrap();
    assert!(is_valid);
}