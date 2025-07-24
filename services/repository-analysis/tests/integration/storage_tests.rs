use anyhow::Result;
use repository_analysis_service::*;
use super::TestContext;
use uuid::Uuid;
use chrono::Utc;

pub async fn run_tests() -> Result<()> {
    println!("\n💾 Storage Integration Tests");
    println!("-" .repeat(40));
    
    test_postgres_operations().await?;
    test_object_storage_operations().await?;
    test_vector_storage_operations().await?;
    test_transaction_consistency().await?;
    test_concurrent_access().await?;
    
    println!("✅ All storage tests passed");
    Ok(())
}

async fn test_postgres_operations() -> Result<()> {
    print!("Testing PostgreSQL operations... ");
    
    let context = TestContext::new().await?;
    
    // Test job CRUD operations
    let job = context.create_test_job("https://github.com/test/repo".to_string());
    
    // Create
    context.storage.postgres.create_job(&job).await?;
    
    // Read
    let retrieved = context.storage.postgres.get_job(job.id).await?;
    assert!(retrieved.is_some());
    let retrieved_job = retrieved.unwrap();
    assert_eq!(retrieved_job.id, job.id);
    assert_eq!(retrieved_job.repository_url, job.repository_url);
    
    // Update
    context.storage.postgres.update_job_status(
        job.id,
        storage::JobStatus::Running,
        Some(75),
        Some("processing".to_string()),
        None,
    ).await?;
    
    let updated = context.storage.postgres.get_job(job.id).await?.unwrap();
    assert_eq!(updated.status, storage::JobStatus::Running);
    assert_eq!(updated.progress_percentage, 75);
    
    // Test security findings
    let finding = storage::SecurityFinding {
        id: Uuid::new_v4(),
        job_id: job.id,
        finding_type: storage::FindingType::SecretExposure,
        severity: storage::Severity::High,
        confidence: 0.95,
        title: "API Key Exposed".to_string(),
        description: "Found hardcoded API key in source code".to_string(),
        file_path: Some("config/secrets.json".to_string()),
        line_number: Some(5),
        evidence: serde_json::json!({
            "pattern": "AKIA[0-9A-Z]{16}",
            "match": "AKIAIOSFODNN7EXAMPLE"
        }),
        recommendation: Some("Remove hardcoded secrets and use environment variables".to_string()),
        false_positive: false,
        reviewed: false,
        reviewer_notes: None,
        cve_id: None,
        created_at: Utc::now(),
        updated_at: Utc::now(),
    };
    
    context.storage.postgres.create_security_finding(&finding).await?;
    
    // Retrieve findings
    let findings = context.storage.postgres.get_job_findings(job.id).await?;
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].id, finding.id);
    
    // Test repository metadata
    let repo = storage::Repository {
        id: Uuid::new_v4(),
        url: job.repository_url.clone(),
        repository_type: "git".to_string(),
        size_bytes: 1024 * 1024,
        file_count: 42,
        commit_count: Some(100),
        contributors: serde_json::json!(["alice", "bob"]),
        languages: serde_json::json!({"rust": 60, "python": 40}),
        last_commit: Some(Utc::now()),
        branch: Some("main".to_string()),
        tags: serde_json::json!(["v1.0", "v1.1"]),
        first_analyzed: Utc::now(),
        last_analyzed: Utc::now(),
        analysis_count: 1,
        risk_score: 3.5,
        classification: storage::Classification::Internal,
        metadata: serde_json::json!({}),
    };
    
    context.storage.postgres.upsert_repository(&repo).await?;
    
    context.cleanup().await?;
    println!("✓");
    Ok(())
}

async fn test_object_storage_operations() -> Result<()> {
    print!("Testing object storage operations... ");
    
    let context = TestContext::new().await?;
    let job_id = Uuid::new_v4();
    
    // Test file storage
    let test_content = b"This is test file content for object storage";
    let file_path = "test-file.txt";
    
    // Store file
    let stored_path = context.storage.object.store_file(
        job_id,
        file_path,
        test_content.to_vec(),
    ).await?;
    
    // Retrieve file
    let retrieved_content = context.storage.object.retrieve_file(&stored_path).await?;
    assert_eq!(retrieved_content, test_content);
    
    // Test analysis report storage
    let report = serde_json::json!({
        "job_id": job_id,
        "summary": "Test analysis report",
        "findings": {
            "total": 5,
            "critical": 1,
            "high": 2,
            "medium": 2,
            "low": 0
        },
        "risk_score": 7.5,
    });
    
    let report_bytes = serde_json::to_vec_pretty(&report)?;
    context.storage.object.store_analysis_report(
        job_id,
        report_bytes.clone(),
        "json",
    ).await?;
    
    // List files for job
    let files = context.storage.object.list_job_files(job_id).await?;
    assert!(!files.is_empty());
    assert!(files.iter().any(|f| f.contains("test-file.txt")));
    assert!(files.iter().any(|f| f.contains("report") && f.contains(".json")));
    
    // Test file deletion
    context.storage.object.delete_file(&stored_path).await?;
    
    // Verify deletion
    let delete_result = context.storage.object.retrieve_file(&stored_path).await;
    assert!(delete_result.is_err());
    
    context.cleanup().await?;
    println!("✓");
    Ok(())
}

async fn test_vector_storage_operations() -> Result<()> {
    print!("Testing vector storage operations... ");
    
    let context = TestContext::new().await?;
    let job_id = Uuid::new_v4();
    
    // Test embedding storage
    let file_embedding = storage::vector::FileEmbedding {
        job_id,
        file_path: "test/example.py".to_string(),
        embedding: vec![0.1; 768], // Mock embedding
        metadata: storage::vector::FileEmbeddingMetadata {
            file_type: "python".to_string(),
            size_bytes: 1024,
            chunk_index: 0,
            total_chunks: 1,
        },
    };
    
    context.storage.vector.store_file_embedding(
        job_id,
        &file_embedding.file_path,
        file_embedding.embedding.clone(),
        file_embedding.metadata.clone(),
    ).await?;
    
    // Test code pattern storage
    let pattern = storage::vector::CodePattern {
        pattern_id: Uuid::new_v4(),
        pattern_type: "security_vulnerability".to_string(),
        embedding: vec![0.2; 768], // Mock embedding
        metadata: serde_json::json!({
            "vulnerability": "sql_injection",
            "severity": "high",
            "language": "javascript"
        }),
    };
    
    context.storage.vector.store_code_pattern(
        &pattern.pattern_type,
        pattern.embedding.clone(),
        pattern.metadata.clone(),
    ).await?;
    
    // Test similarity search
    let query_embedding = vec![0.15; 768]; // Similar to file embedding
    let results = context.storage.vector.search_similar_files(
        "test query",
        0.5,
        10,
        Some(job_id),
    ).await?;
    
    // Should find our test file
    assert!(!results.is_empty());
    
    // Test anomaly detection
    let anomaly_result = context.storage.vector.detect_anomalies(
        job_id,
        0.3,
    ).await?;
    
    // Clean up collections
    context.storage.vector.delete_job_embeddings(job_id).await?;
    
    context.cleanup().await?;
    println!("✓");
    Ok(())
}

async fn test_transaction_consistency() -> Result<()> {
    print!("Testing transaction consistency... ");
    
    let context = TestContext::new().await?;
    
    // Test that related data stays consistent
    let job = context.create_test_job("https://github.com/test/transactional".to_string());
    context.storage.postgres.create_job(&job).await?;
    
    // Create multiple related findings
    let mut findings = Vec::new();
    for i in 0..5 {
        let finding = storage::SecurityFinding {
            id: Uuid::new_v4(),
            job_id: job.id,
            finding_type: storage::FindingType::Vulnerability,
            severity: storage::Severity::Medium,
            confidence: 0.8,
            title: format!("Test Finding {}", i),
            description: "Test".to_string(),
            file_path: Some(format!("file{}.js", i)),
            line_number: Some(10 + i),
            evidence: serde_json::json!({}),
            recommendation: None,
            false_positive: false,
            reviewed: false,
            reviewer_notes: None,
            cve_id: None,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };
        findings.push(finding);
    }
    
    // Insert all findings
    for finding in &findings {
        context.storage.postgres.create_security_finding(finding).await?;
    }
    
    // Verify all were inserted
    let retrieved_findings = context.storage.postgres.get_job_findings(job.id).await?;
    assert_eq!(retrieved_findings.len(), 5);
    
    // Update job to failed status - findings should still be accessible
    context.storage.postgres.update_job_status(
        job.id,
        storage::JobStatus::Failed,
        Some(50),
        Some("error_occurred".to_string()),
        Some("Test error".to_string()),
    ).await?;
    
    let findings_after_failure = context.storage.postgres.get_job_findings(job.id).await?;
    assert_eq!(findings_after_failure.len(), 5);
    
    context.cleanup().await?;
    println!("✓");
    Ok(())
}

async fn test_concurrent_access() -> Result<()> {
    print!("Testing concurrent storage access... ");
    
    let context = TestContext::new().await?;
    let job_id = Uuid::new_v4();
    
    // Spawn multiple tasks that access storage concurrently
    let mut handles = Vec::new();
    
    for i in 0..10 {
        let storage = context.storage.clone();
        let task_job_id = job_id;
        
        let handle = tokio::spawn(async move {
            // Each task stores a file
            let content = format!("Concurrent test file {}", i);
            let file_path = format!("concurrent-{}.txt", i);
            
            storage.object.store_file(
                task_job_id,
                &file_path,
                content.into_bytes(),
            ).await
        });
        
        handles.push(handle);
    }
    
    // Wait for all tasks to complete
    let mut results = Vec::new();
    for handle in handles {
        results.push(handle.await??);
    }
    
    // Verify all files were stored
    let files = context.storage.object.list_job_files(job_id).await?;
    assert_eq!(files.len(), 10);
    
    context.cleanup().await?;
    println!("✓");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[tokio::test]
    async fn test_storage_integration() {
        run_tests().await.unwrap();
    }
}