pub mod rest;
pub mod grpc;
pub mod pulsar;

use anyhow::Result;
use std::sync::Arc;
use uuid::Uuid;

use crate::{
    storage::{Storage, AnalysisJob, JobStatus, Priority},
    analysis::AnalysisEngine,
};

/// Common API functionality shared between REST, gRPC, and Pulsar
#[derive(Clone)]
pub struct ApiService {
    storage: Arc<Storage>,
    analysis_engine: Arc<AnalysisEngine>,
}

impl ApiService {
    pub fn new(storage: Arc<Storage>, analysis_engine: Arc<AnalysisEngine>) -> Self {
        Self {
            storage,
            analysis_engine,
        }
    }

    /// Submit a new analysis job
    pub async fn submit_job(
        &self,
        repository_url: String,
        repository_type: String,
        analysis_type: String,
        priority: Priority,
        submitter_id: String,
        case_number: Option<String>,
        configuration: serde_json::Value,
    ) -> Result<AnalysisJob> {
        let job = AnalysisJob {
            id: Uuid::new_v4(),
            repository_url,
            repository_type,
            analysis_type,
            status: JobStatus::Pending,
            priority,
            case_number,
            submitter_id,
            created_at: chrono::Utc::now(),
            started_at: None,
            completed_at: None,
            configuration,
            metadata: serde_json::json!({}),
            progress_percentage: 0,
            current_phase: None,
            error_message: None,
            estimated_completion: None,
        };

        // Store job in database
        self.storage.postgres.create_job(&job).await?;

        // Queue job for processing (would integrate with Temporal in production)
        tokio::spawn({
            let analysis_engine = self.analysis_engine.clone();
            let job = job.clone();
            async move {
                if let Err(e) = analysis_engine.start_analysis(&job).await {
                    tracing::error!("Analysis failed for job {}: {}", job.id, e);
                }
            }
        });

        Ok(job)
    }

    /// Get job status
    pub async fn get_job(&self, job_id: Uuid) -> Result<Option<AnalysisJob>> {
        self.storage.postgres.get_job(job_id).await
    }

    /// Cancel a running job
    pub async fn cancel_job(&self, job_id: Uuid) -> Result<bool> {
        // Update job status to cancelled
        self.storage.postgres.update_job_status(
            job_id,
            JobStatus::Cancelled,
            None,
            None,
            Some("Job cancelled by user".to_string()),
        ).await?;

        // In production, would also cancel Temporal workflow
        Ok(true)
    }

    /// Get analysis results
    pub async fn get_results(&self, job_id: Uuid) -> Result<Option<serde_json::Value>> {
        // Check if job is completed
        if let Some(job) = self.get_job(job_id).await? {
            if job.status == JobStatus::Completed {
                // Retrieve results from storage
                let report_key = format!("reports/{}/report.json", job_id);
                match self.storage.object.get_file(&report_key).await {
                    Ok(data) => {
                        let report: serde_json::Value = serde_json::from_slice(&data)?;
                        Ok(Some(report))
                    }
                    Err(_) => Ok(None),
                }
            } else {
                Ok(None)
            }
        } else {
            Ok(None)
        }
    }

    /// Search for similar content
    pub async fn search_similar(
        &self,
        query_text: Option<String>,
        file_path: Option<String>,
        job_id: Option<Uuid>,
        threshold: f32,
        limit: usize,
    ) -> Result<Vec<crate::storage::SimilarityResult>> {
        let query = crate::storage::SimilarityQuery {
            collection_name: Some("file_content".to_string()),
            query_text,
            query_vector: None,
            file_path,
            job_id,
            similarity_threshold: threshold,
            limit,
            include_metadata: true,
        };

        self.storage.vector.search_similar(&query).await
    }

    /// Get storage statistics
    pub async fn get_statistics(&self) -> Result<serde_json::Value> {
        let job_stats = self.storage.postgres.get_job_statistics().await?;
        let storage_stats = self.storage.object.get_statistics("").await?;
        let vector_stats = self.storage.vector.get_collection_stats("file_content").await?;

        Ok(serde_json::json!({
            "jobs": job_stats,
            "storage": {
                "file_count": storage_stats.file_count,
                "total_size_bytes": storage_stats.total_size_bytes,
            },
            "vectors": {
                "points_count": vector_stats.points_count,
                "indexed_vectors_count": vector_stats.indexed_vectors_count,
            },
        }))
    }

    /// Health check
    pub async fn health_check(&self) -> Result<HealthStatus> {
        let postgres_healthy = self.storage.postgres.health_check().await.unwrap_or(false);
        let object_healthy = self.storage.object.health_check().await.unwrap_or(false);
        let vector_healthy = self.storage.vector.health_check().await.unwrap_or(false);

        let all_healthy = postgres_healthy && object_healthy && vector_healthy;

        Ok(HealthStatus {
            healthy: all_healthy,
            postgres: postgres_healthy,
            object_storage: object_healthy,
            vector_storage: vector_healthy,
            timestamp: chrono::Utc::now(),
        })
    }
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct HealthStatus {
    pub healthy: bool,
    pub postgres: bool,
    pub object_storage: bool,
    pub vector_storage: bool,
    pub timestamp: chrono::DateTime<chrono::Utc>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct JobSubmission {
    pub repository_url: String,
    pub repository_type: String,
    pub analysis_type: String,
    pub priority: Priority,
    pub submitter_id: String,
    pub case_number: Option<String>,
    pub configuration: serde_json::Value,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct JobResponse {
    pub job_id: Uuid,
    pub status: JobStatus,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub estimated_completion: Option<chrono::DateTime<chrono::Utc>>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct SearchRequest {
    pub query_text: Option<String>,
    pub file_path: Option<String>,
    pub job_id: Option<Uuid>,
    pub threshold: Option<f32>,
    pub limit: Option<usize>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{Config, StorageConfig, PostgresConfig, ObjectStorageConfig, VectorStorageConfig};

    async fn create_test_service() -> ApiService {
        let config = Config {
            server: Default::default(),
            storage: StorageConfig {
                postgres: PostgresConfig {
                    url: "postgres://test@localhost/test".to_string(),
                    max_connections: 5,
                    min_connections: 1,
                },
                object: ObjectStorageConfig {
                    provider: "local".to_string(),
                    bucket: "test".to_string(),
                    region: None,
                    endpoint: None,
                    access_key: None,
                    secret_key: None,
                    local_path: Some("/tmp/test".to_string()),
                },
                vector: VectorStorageConfig {
                    host: "localhost".to_string(),
                    port: 6333,
                    collection_prefix: "test".to_string(),
                    vector_size: 384,
                    api_key: None,
                },
            },
            analysis: Default::default(),
            security: Default::default(),
            distributed_networks: vec![],
            forensic: Default::default(),
            temporal: None,
            pulsar: None,
        };

        // Note: In real tests, we'd use mocks or test databases
        let storage = Arc::new(Storage::new(
            crate::storage::postgres::PostgresStorage::new(&config.storage.postgres).await.unwrap(),
            crate::storage::object::ObjectStorage::new(&config.storage.object).await.unwrap(),
            crate::storage::vector::QdrantStorage::new(&config.storage.vector).await.unwrap(),
        ));

        let analysis_engine = Arc::new(
            crate::analysis::AnalysisEngine::new(config.analysis.clone(), storage.clone()).await.unwrap()
        );

        ApiService::new(storage, analysis_engine)
    }

    #[tokio::test]
    async fn test_job_submission() {
        // This test would need proper mocking in a real implementation
        // For now, it's a placeholder showing the structure
        
        let submission = JobSubmission {
            repository_url: "https://github.com/example/repo".to_string(),
            repository_type: "git".to_string(),
            analysis_type: "comprehensive".to_string(),
            priority: Priority::Normal,
            submitter_id: "test-user".to_string(),
            case_number: Some("CASE-123".to_string()),
            configuration: serde_json::json!({
                "include_git_history": true,
                "deep_file_analysis": true,
            }),
        };

        assert_eq!(submission.repository_type, "git");
        assert_eq!(submission.priority, Priority::Normal);
    }

    #[test]
    fn test_health_status() {
        let health = HealthStatus {
            healthy: true,
            postgres: true,
            object_storage: true,
            vector_storage: true,
            timestamp: chrono::Utc::now(),
        };

        assert!(health.healthy);
        assert!(health.postgres);
        assert!(health.object_storage);
        assert!(health.vector_storage);
    }
}