use anyhow::Result;
use uuid::Uuid;
use chrono::Utc;
use tempfile::TempDir;
use std::collections::HashMap;

use crate::{
    config::{AnalysisConfig, StorageConfig, PostgresConfig, ObjectStorageConfig, VectorStorageConfig},
    storage::{
        Storage, AnalysisJob, JobStatus, Priority, FileAnalysis, Classification,
        SecurityFinding, FindingType, Severity,
    },
    analysis::{AnalysisEngine, FileInfo, RepositoryInfo},
};

pub mod file_analyzer_tests;
pub mod security_scanner_tests;
pub mod ml_analyzer_tests;
pub mod git_analyzer_tests;
pub mod code_analyzer_tests;
pub mod integration_tests;

/// Test utilities and helpers
pub struct TestContext {
    pub temp_dir: TempDir,
    pub config: AnalysisConfig,
    pub test_files: HashMap<String, String>,
}

impl TestContext {
    pub fn new() -> Result<Self> {
        let temp_dir = TempDir::new()?;
        
        let config = AnalysisConfig {
            max_file_size_mb: 10,
            max_repository_size_gb: 1,
            timeout_seconds: 300,
            parallel_workers: 2,
            supported_formats: vec!["git".to_string(), "directory".to_string()],
            ml_analysis: crate::config::MLAnalysisConfig {
                enabled: true,
                model_path: "./models".to_string(),
                embedding_model: "test-model".to_string(),
                similarity_threshold: 0.8,
                batch_size: 10,
            },
            malware_scanning: crate::config::MalwareScanConfig {
                enabled: false, // Disabled for testing due to dependency issues
                engines: vec![], // YARA and ClamAV disabled
                yara_rules_path: None,
                clamav_db_path: None,
            },
            code_analysis: crate::config::CodeAnalysisConfig {
                enabled: true,
                languages: vec!["rust".to_string(), "python".to_string()],
                static_analysis: true,
                dependency_analysis: true,
                secret_detection: true,
            },
        };

        Ok(Self {
            temp_dir,
            config,
            test_files: HashMap::new(),
        })
    }

    pub async fn create_test_file(&mut self, name: &str, content: &str) -> Result<String> {
        let file_path = self.temp_dir.path().join(name);
        tokio::fs::write(&file_path, content).await?;
        let path_str = file_path.to_string_lossy().to_string();
        self.test_files.insert(name.to_string(), path_str.clone());
        Ok(path_str)
    }

    pub fn create_test_job() -> AnalysisJob {
        AnalysisJob {
            id: Uuid::new_v4(),
            repository_url: "https://github.com/test/repo".to_string(),
            repository_type: "git".to_string(),
            analysis_type: "comprehensive".to_string(),
            status: JobStatus::Pending,
            priority: Priority::Normal,
            case_number: Some("TEST-123".to_string()),
            submitter_id: "test-user".to_string(),
            created_at: Utc::now(),
            started_at: None,
            completed_at: None,
            configuration: serde_json::json!({
                "include_git_history": true,
                "deep_file_analysis": true,
            }),
            metadata: serde_json::json!({}),
            progress_percentage: 0,
            current_phase: None,
            error_message: None,
            estimated_completion: None,
        }
    }

    pub fn create_test_file_info(path: &str, file_type: &str) -> FileInfo {
        FileInfo {
            path: path.to_string(),
            relative_path: path.to_string(),
            size_bytes: 1024,
            modified_at: Utc::now(),
            file_type: file_type.to_string(),
            mime_type: Some("text/plain".to_string()),
            extension: Some("txt".to_string()),
            is_binary: false,
            is_executable: false,
            permissions: None,
        }
    }

    pub fn create_test_file_analysis(job_id: Uuid, file_path: &str) -> FileAnalysis {
        FileAnalysis {
            id: Uuid::new_v4(),
            job_id,
            file_path: file_path.to_string(),
            file_type: "text".to_string(),
            file_size: 1024,
            mime_type: Some("text/plain".to_string()),
            language: None,
            encoding: Some("utf-8".to_string()),
            hash_sha256: "abc123".to_string(),
            hash_blake3: "def456".to_string(),
            classification: Classification::Public,
            findings: serde_json::json!([]),
            metadata: serde_json::json!({
                "content": "test content"
            }),
            processed_at: Utc::now(),
            processing_time_ms: 100,
        }
    }

    pub fn create_test_security_finding(job_id: Uuid) -> SecurityFinding {
        SecurityFinding {
            id: Uuid::new_v4(),
            job_id,
            file_id: None,
            finding_type: FindingType::SecretExposure,
            severity: Severity::High,
            title: "API key detected".to_string(),
            description: "Hardcoded API key found in source code".to_string(),
            file_path: Some("config.js".to_string()),
            line_number: Some(42),
            evidence: serde_json::json!({
                "pattern": "api_key",
                "line_content": "const API_KEY = 'secret123'"
            }),
            recommendation: Some("Use environment variables".to_string()),
            confidence: 0.9,
            cve_id: None,
            references: serde_json::json!([]),
            detected_at: Utc::now(),
        }
    }

    pub fn create_test_repository_info(path: &str) -> RepositoryInfo {
        RepositoryInfo {
            url: "https://github.com/test/repo".to_string(),
            repository_type: "git".to_string(),
            local_path: path.to_string(),
            git_path: Some(path.to_string()),
            size_bytes: 1024 * 1024,
            file_count: 10,
            commit_count: Some(100),
            contributors: vec!["user1".to_string(), "user2".to_string()],
            languages: vec!["Rust".to_string(), "Python".to_string()],
            last_commit: Some(Utc::now()),
            branch: Some("main".to_string()),
            tags: vec!["v1.0.0".to_string()],
            metadata: HashMap::new(),
        }
    }
}

/// Helper function to create test content with various patterns
pub fn create_test_content_with_patterns() -> String {
    r#"
// Test file with various patterns for testing

const API_KEY = "AKIA1234567890ABCDEF"; // AWS key
const token = "ghp_abc123def456ghi789jkl012mno345pqr678"; // GitHub token

function processData(userInput) {
    // Potential SQL injection
    const query = "SELECT * FROM users WHERE id = " + userInput;
    db.execute(query);
    
    // Dangerous eval
    eval("console.log('" + userInput + "')");
    
    // Command injection
    exec("ls -la " + userInput);
}

// TODO: Fix this security issue
// HACK: Temporary workaround

password = "SuperSecret123!";
ssn = "123-45-6789";
creditCard = "4111 1111 1111 1111";

// Suspicious patterns
backdoor();
malware.execute();
"#.to_string()
}

/// Helper function to create mock storage
pub async fn create_mock_storage() -> Result<Storage> {
    let postgres_config = PostgresConfig {
        url: "postgres://test@localhost/test".to_string(),
        max_connections: 5,
        min_connections: 1,
    };

    let object_config = ObjectStorageConfig {
        provider: "local".to_string(),
        bucket: "test-bucket".to_string(),
        region: None,
        endpoint: None,
        access_key: None,
        secret_key: None,
        local_path: Some("/tmp/test-storage".to_string()),
    };

    let vector_config = VectorStorageConfig {
        host: "localhost".to_string(),
        port: 6333,
        collection_prefix: "test".to_string(),
        vector_size: 384,
        api_key: None,
    };

    // Note: In real tests, we'd use test containers or mocks
    let postgres = crate::storage::postgres::PostgresStorage::new(&postgres_config).await?;
    let object = crate::storage::object::ObjectStorage::new(&object_config).await?;
    let vector = crate::storage::vector::QdrantStorage::new(&vector_config).await?;

    Ok(Storage::new(postgres, object, vector))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_context_creation() {
        let context = TestContext::new().unwrap();
        assert!(context.temp_dir.path().exists());
        assert_eq!(context.config.max_file_size_mb, 10);
    }

    #[tokio::test]
    async fn test_file_creation() {
        let mut context = TestContext::new().unwrap();
        let file_path = context.create_test_file("test.txt", "Hello, world!").await.unwrap();
        
        assert!(tokio::fs::metadata(&file_path).await.is_ok());
        let content = tokio::fs::read_to_string(&file_path).await.unwrap();
        assert_eq!(content, "Hello, world!");
    }

    #[test]
    fn test_job_creation() {
        let job = TestContext::create_test_job();
        assert_eq!(job.repository_type, "git");
        assert_eq!(job.status, JobStatus::Pending);
        assert_eq!(job.priority, Priority::Normal);
    }

    #[test]
    fn test_pattern_content() {
        let content = create_test_content_with_patterns();
        assert!(content.contains("API_KEY"));
        assert!(content.contains("ghp_"));
        assert!(content.contains("eval("));
        assert!(content.contains("backdoor"));
    }
}