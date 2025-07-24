use anyhow::Result;
use repository_analysis_service::*;
use super::TestContext;
use sha2::{Sha256, Digest};
use std::io::Write;

pub async fn run_tests() -> Result<()> {
    println!("\n🔐 Forensics Integration Tests");
    println!("-" .repeat(40));
    
    test_chain_of_custody().await?;
    test_evidence_integrity().await?;
    test_hash_verification().await?;
    test_digital_signatures().await?;
    test_legal_hold().await?;
    test_evidence_export().await?;
    
    println!("✅ All forensics tests passed");
    Ok(())
}

async fn test_chain_of_custody() -> Result<()> {
    print!("Testing chain of custody... ");
    
    let context = TestContext::new().await?;
    let evidence_id = format!("EVD-{}", uuid::Uuid::new_v4());
    
    // Create initial custody record
    let initial_record = storage::CustodyRecord {
        id: uuid::Uuid::new_v4(),
        evidence_id: evidence_id.clone(),
        timestamp: chrono::Utc::now(),
        action: storage::CustodyAction::Created,
        actor: storage::CustodyActor::System,
        location: "repository-analysis-service".to_string(),
        hash_before: None,
        hash_after: Some("initial-hash-12345".to_string()),
        signature: "system-signature".to_string(),
        metadata: serde_json::json!({
            "source": "integration_test",
            "job_id": uuid::Uuid::new_v4(),
        }),
    };
    
    context.storage.postgres.create_custody_record(&initial_record).await?;
    
    // Add access record
    let access_record = storage::CustodyRecord {
        id: uuid::Uuid::new_v4(),
        evidence_id: evidence_id.clone(),
        timestamp: chrono::Utc::now(),
        action: storage::CustodyAction::Accessed,
        actor: storage::CustodyActor::User("test-analyst".to_string()),
        location: "analysis-workstation-01".to_string(),
        hash_before: Some("initial-hash-12345".to_string()),
        hash_after: Some("initial-hash-12345".to_string()), // No modification
        signature: "analyst-signature".to_string(),
        metadata: serde_json::json!({
            "purpose": "security_analysis",
            "duration_seconds": 300,
        }),
    };
    
    context.storage.postgres.create_custody_record(&access_record).await?;
    
    // Add analysis record
    let analysis_record = storage::CustodyRecord {
        id: uuid::Uuid::new_v4(),
        evidence_id: evidence_id.clone(),
        timestamp: chrono::Utc::now(),
        action: storage::CustodyAction::Analyzed,
        actor: storage::CustodyActor::System,
        location: "analysis-engine".to_string(),
        hash_before: Some("initial-hash-12345".to_string()),
        hash_after: Some("initial-hash-12345".to_string()),
        signature: "engine-signature".to_string(),
        metadata: serde_json::json!({
            "analysis_type": "comprehensive",
            "findings_count": 5,
        }),
    };
    
    context.storage.postgres.create_custody_record(&analysis_record).await?;
    
    // Retrieve full chain
    let chain = context.storage.postgres.get_custody_chain(&evidence_id).await?;
    assert_eq!(chain.len(), 3, "Should have 3 custody records");
    
    // Verify chain integrity
    assert_eq!(chain[0].action, storage::CustodyAction::Created);
    assert_eq!(chain[1].action, storage::CustodyAction::Accessed);
    assert_eq!(chain[2].action, storage::CustodyAction::Analyzed);
    
    // Verify chronological order
    assert!(chain[0].timestamp <= chain[1].timestamp);
    assert!(chain[1].timestamp <= chain[2].timestamp);
    
    context.cleanup().await?;
    println!("✓");
    Ok(())
}

async fn test_evidence_integrity() -> Result<()> {
    print!("Testing evidence integrity... ");
    
    let context = TestContext::new().await?;
    let job_id = uuid::Uuid::new_v4();
    
    // Create evidence file
    let evidence_content = b"This is critical evidence data that must maintain integrity";
    let evidence_path = "evidence/critical_file.dat";
    
    // Calculate hash before storage
    let mut hasher = Sha256::new();
    hasher.update(evidence_content);
    let original_hash = format!("{:x}", hasher.finalize());
    
    // Store with forensics manager
    let stored_path = context.forensics_manager.store_evidence(
        job_id,
        evidence_path,
        evidence_content.to_vec(),
        Some("Critical evidence from security incident".to_string()),
    ).await?;
    
    // Retrieve and verify
    let retrieved_data = context.forensics_manager.retrieve_evidence(&stored_path).await?;
    
    // Calculate hash of retrieved data
    let mut verifier = Sha256::new();
    verifier.update(&retrieved_data);
    let retrieved_hash = format!("{:x}", verifier.finalize());
    
    // Verify integrity
    assert_eq!(original_hash, retrieved_hash, "Evidence integrity compromised");
    assert_eq!(evidence_content.to_vec(), retrieved_data, "Evidence content mismatch");
    
    context.cleanup().await?;
    println!("✓");
    Ok(())
}

async fn test_hash_verification() -> Result<()> {
    print!("Testing multi-algorithm hash verification... ");
    
    let context = TestContext::new().await?;
    
    // Test data
    let test_data = b"Important forensic evidence requiring multiple hash algorithms";
    
    // Calculate hashes using different algorithms
    let hashes = context.forensics_manager.calculate_hashes(test_data).await?;
    
    // Verify we have multiple hash algorithms
    assert!(hashes.contains_key("sha256"), "Should have SHA256 hash");
    assert!(hashes.contains_key("sha512"), "Should have SHA512 hash");
    if context.config.forensics.hash_algorithms.contains(&"blake3".to_string()) {
        assert!(hashes.contains_key("blake3"), "Should have BLAKE3 hash");
    }
    
    // Verify hash format and length
    if let Some(sha256) = hashes.get("sha256") {
        assert_eq!(sha256.len(), 64, "SHA256 should be 64 hex characters");
    }
    
    if let Some(sha512) = hashes.get("sha512") {
        assert_eq!(sha512.len(), 128, "SHA512 should be 128 hex characters");
    }
    
    // Test hash verification
    let verification_result = context.forensics_manager.verify_hashes(test_data, &hashes).await?;
    assert!(verification_result, "Hash verification should pass");
    
    // Test tampered data detection
    let tampered_data = b"Tampered forensic evidence";
    let tampered_result = context.forensics_manager.verify_hashes(tampered_data, &hashes).await?;
    assert!(!tampered_result, "Should detect tampered data");
    
    context.cleanup().await?;
    println!("✓");
    Ok(())
}

async fn test_digital_signatures() -> Result<()> {
    print!("Testing digital signatures... ");
    
    let context = TestContext::new().await?;
    
    // Create evidence package
    let evidence = forensics::EvidencePackage {
        id: uuid::Uuid::new_v4(),
        job_id: uuid::Uuid::new_v4(),
        timestamp: chrono::Utc::now(),
        description: "Test evidence package".to_string(),
        files: vec![
            forensics::EvidenceFile {
                path: "test/file1.txt".to_string(),
                hash: "abc123".to_string(),
                size: 1024,
                mime_type: "text/plain".to_string(),
            },
        ],
        metadata: serde_json::json!({
            "case_number": "TEST-001",
            "investigator": "Test User",
        }),
    };
    
    // Sign evidence package
    let signature = context.forensics_manager.sign_evidence(&evidence).await?;
    assert!(!signature.is_empty(), "Should generate signature");
    
    // Verify signature
    let verification = context.forensics_manager.verify_signature(&evidence, &signature).await?;
    assert!(verification, "Signature verification should pass");
    
    // Test tampered evidence detection
    let mut tampered_evidence = evidence.clone();
    tampered_evidence.files[0].hash = "tampered123".to_string();
    
    let tampered_verification = context.forensics_manager.verify_signature(&tampered_evidence, &signature).await?;
    assert!(!tampered_verification, "Should detect tampered evidence");
    
    context.cleanup().await?;
    println!("✓");
    Ok(())
}

async fn test_legal_hold() -> Result<()> {
    print!("Testing legal hold functionality... ");
    
    let context = TestContext::new().await?;
    let job_id = uuid::Uuid::new_v4();
    
    // Create evidence under legal hold
    let evidence_content = b"Evidence subject to legal hold";
    let evidence_path = "legal/document.pdf";
    
    // Store evidence
    let stored_path = context.forensics_manager.store_evidence(
        job_id,
        evidence_path,
        evidence_content.to_vec(),
        Some("Legal hold evidence".to_string()),
    ).await?;
    
    // Apply legal hold
    context.forensics_manager.apply_legal_hold(
        job_id,
        "CASE-2024-001",
        "Court order #12345",
    ).await?;
    
    // Verify legal hold status
    let hold_status = context.forensics_manager.get_legal_hold_status(job_id).await?;
    assert!(hold_status.is_some(), "Should have legal hold status");
    
    if let Some(status) = hold_status {
        assert_eq!(status.case_reference, "CASE-2024-001");
        assert!(status.active);
    }
    
    // Test that evidence cannot be deleted while under legal hold
    let delete_result = context.forensics_manager.delete_evidence(&stored_path).await;
    assert!(delete_result.is_err(), "Should not allow deletion under legal hold");
    
    // Release legal hold
    context.forensics_manager.release_legal_hold(job_id, "Court approval #67890").await?;
    
    // Now deletion should succeed
    let delete_result2 = context.forensics_manager.delete_evidence(&stored_path).await;
    assert!(delete_result2.is_ok(), "Should allow deletion after legal hold release");
    
    context.cleanup().await?;
    println!("✓");
    Ok(())
}

async fn test_evidence_export() -> Result<()> {
    print!("Testing evidence export... ");
    
    let context = TestContext::new().await?;
    let job_id = uuid::Uuid::new_v4();
    
    // Create multiple evidence files
    let evidence_files = vec![
        ("evidence1.txt", b"Evidence file 1"),
        ("evidence2.log", b"Evidence file 2"),
        ("evidence3.dat", b"Evidence file 3"),
    ];
    
    for (path, content) in &evidence_files {
        context.forensics_manager.store_evidence(
            job_id,
            path,
            content.to_vec(),
            None,
        ).await?;
    }
    
    // Export evidence package
    let export_path = context.temp_dir.path().join("evidence_export.zip");
    let export_result = context.forensics_manager.export_evidence_package(
        job_id,
        &export_path,
        forensics::ExportFormat::Zip,
        Some("Test export for court proceedings".to_string()),
    ).await?;
    
    // Verify export
    assert!(export_path.exists(), "Export file should exist");
    assert!(export_result.manifest.files.len() >= 3, "Should include all evidence files");
    assert!(!export_result.manifest.chain_of_custody.is_empty(), "Should include custody chain");
    assert!(!export_result.signature.is_empty(), "Should be digitally signed");
    
    // Verify export integrity
    let metadata = tokio::fs::metadata(&export_path).await?;
    assert!(metadata.len() > 0, "Export should not be empty");
    
    context.cleanup().await?;
    println!("✓");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[tokio::test]
    async fn test_forensics_integration() {
        run_tests().await.unwrap();
    }
}