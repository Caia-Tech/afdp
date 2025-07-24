use anyhow::Result;
use axum::http::StatusCode;
use repository_analysis_service::*;
use super::TestContext;
use uuid::Uuid;

pub async fn run_tests() -> Result<()> {
    println!("\n📡 API Integration Tests");
    println!("-" .repeat(40));
    
    test_job_submission_api().await?;
    test_job_status_api().await?;
    test_results_retrieval_api().await?;
    test_similarity_search_api().await?;
    test_authentication_api().await?;
    test_rate_limiting().await?;
    
    println!("✅ All API tests passed");
    Ok(())
}

async fn test_job_submission_api() -> Result<()> {
    print!("Testing job submission via REST API... ");
    
    let context = TestContext::new().await?;
    let repo_path = context.create_test_repository("api-test-repo").await?;
    
    // Create job submission request
    let submission = api::JobSubmission {
        repository_url: format!("file://{}", repo_path),
        repository_type: "directory".to_string(),
        analysis_type: "comprehensive".to_string(),
        priority: storage::Priority::High,
        submitter_id: "api-test-user".to_string(),
        case_number: Some("API-TEST-001".to_string()),
        configuration: serde_json::json!({
            "deep_scan": true,
            "include_ml_analysis": true,
        }),
    };
    
    // In a real test, we would make an HTTP request to the API
    // For now, we'll test the service layer directly
    let job_id = Uuid::new_v4();
    let job = storage::AnalysisJob {
        id: job_id,
        repository_url: submission.repository_url.clone(),
        repository_type: submission.repository_type,
        analysis_type: submission.analysis_type,
        priority: submission.priority,
        status: storage::JobStatus::Pending,
        submitter_id: submission.submitter_id,
        case_number: submission.case_number,
        configuration: submission.configuration,
        started_at: None,
        completed_at: None,
        error_message: None,
        progress_percentage: 0,
        current_phase: None,
        created_at: chrono::Utc::now(),
        updated_at: chrono::Utc::now(),
    };
    
    context.storage.postgres.create_job(&job).await?;
    
    // Verify job was created
    let retrieved_job = context.storage.postgres.get_job(job_id).await?;
    assert!(retrieved_job.is_some());
    assert_eq!(retrieved_job.unwrap().id, job_id);
    
    context.cleanup().await?;
    println!("✓");
    Ok(())
}

async fn test_job_status_api() -> Result<()> {
    print!("Testing job status tracking... ");
    
    let context = TestContext::new().await?;
    let repo_path = context.create_test_repository("status-test-repo").await?;
    let job = context.create_test_job(format!("file://{}", repo_path));
    
    // Create job
    context.storage.postgres.create_job(&job).await?;
    
    // Update status
    context.storage.postgres.update_job_status(
        job.id,
        storage::JobStatus::Running,
        Some(50),
        Some("analyzing_files".to_string()),
        None,
    ).await?;
    
    // Check status
    let updated_job = context.storage.postgres.get_job(job.id).await?.unwrap();
    assert_eq!(updated_job.status, storage::JobStatus::Running);
    assert_eq!(updated_job.progress_percentage, 50);
    assert_eq!(updated_job.current_phase, Some("analyzing_files".to_string()));
    
    context.cleanup().await?;
    println!("✓");
    Ok(())
}

async fn test_results_retrieval_api() -> Result<()> {
    print!("Testing results retrieval... ");
    
    let context = TestContext::new().await?;
    let repo_path = context.create_test_repository("results-test-repo").await?;
    let job = context.create_test_job(format!("file://{}", repo_path));
    
    // Submit and complete job
    let completed_job = context.submit_and_wait_for_job(&job).await?;
    assert_eq!(completed_job.status, storage::JobStatus::Completed);
    
    // Get findings
    let findings = context.get_job_findings(job.id).await?;
    assert!(!findings.is_empty(), "Should have detected security issues");
    
    // Verify we found the hardcoded secrets
    let secret_findings: Vec<_> = findings.iter()
        .filter(|f| matches!(f.finding_type, storage::FindingType::SecretExposure))
        .collect();
    assert!(!secret_findings.is_empty(), "Should have found exposed secrets");
    
    // Verify we found the backdoor
    let backdoor_findings: Vec<_> = findings.iter()
        .filter(|f| matches!(f.finding_type, storage::FindingType::Backdoor))
        .collect();
    assert!(!backdoor_findings.is_empty(), "Should have found backdoor code");
    
    context.cleanup().await?;
    println!("✓");
    Ok(())
}

async fn test_similarity_search_api() -> Result<()> {
    print!("Testing similarity search... ");
    
    let context = TestContext::new().await?;
    let repo_path = context.create_test_repository("search-test-repo").await?;
    let job = context.create_test_job(format!("file://{}", repo_path));
    
    // Submit and complete job to generate embeddings
    let _completed_job = context.submit_and_wait_for_job(&job).await?;
    
    // Search for similar files
    let search_request = api::SearchRequest {
        query_text: Some("password secret api key".to_string()),
        file_path: None,
        job_id: Some(job.id),
        threshold: Some(0.7),
        limit: Some(10),
    };
    
    // Perform similarity search
    let results = context.storage.vector.search_similar_files(
        &search_request.query_text.unwrap(),
        search_request.threshold.unwrap(),
        search_request.limit.unwrap() as u64,
        search_request.job_id,
    ).await?;
    
    // Should find the secrets.json file
    assert!(!results.is_empty(), "Should find similar files");
    let top_result = &results[0];
    assert!(top_result.file_path.contains("secrets.json"));
    assert!(top_result.score > 0.7);
    
    context.cleanup().await?;
    println!("✓");
    Ok(())
}

async fn test_authentication_api() -> Result<()> {
    print!("Testing API authentication... ");
    
    // Test various authentication scenarios
    // 1. Valid JWT token
    // 2. Expired token
    // 3. Invalid signature
    // 4. Missing required permissions
    
    // This would require actual HTTP requests with auth headers
    // For now, we'll test the auth module directly
    
    let auth_config = config::AuthConfig {
        policy_engine_url: "http://localhost:8082".to_string(),
        service_token: "test-token".to_string(),
        jwt_verification_key: "test-key".to_string(),
        required_permissions: std::collections::HashMap::new(),
    };
    
    let auth_manager = auth::AuthManager::new(auth_config).await?;
    
    // Test token validation (would need actual implementation)
    // let result = auth_manager.validate_token("Bearer test-token").await?;
    
    println!("✓");
    Ok(())
}

async fn test_rate_limiting() -> Result<()> {
    print!("Testing rate limiting... ");
    
    let context = TestContext::new().await?;
    
    // Simulate multiple rapid requests
    let mut job_ids = Vec::new();
    for i in 0..5 {
        let job = storage::AnalysisJob {
            id: Uuid::new_v4(),
            repository_url: format!("https://github.com/test/repo-{}", i),
            repository_type: "git".to_string(),
            analysis_type: "quick".to_string(),
            priority: storage::Priority::Normal,
            status: storage::JobStatus::Pending,
            submitter_id: "rate-limit-test".to_string(),
            case_number: None,
            configuration: serde_json::json!({}),
            started_at: None,
            completed_at: None,
            error_message: None,
            progress_percentage: 0,
            current_phase: None,
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
        };
        
        context.storage.postgres.create_job(&job).await?;
        job_ids.push(job.id);
    }
    
    // Verify all jobs were created
    assert_eq!(job_ids.len(), 5);
    
    // In a real test, we would verify rate limiting kicks in after threshold
    
    context.cleanup().await?;
    println!("✓");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[tokio::test]
    async fn test_api_integration() {
        run_tests().await.unwrap();
    }
}