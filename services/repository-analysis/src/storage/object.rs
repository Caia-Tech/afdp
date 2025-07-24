use anyhow::Result;
use object_store::{
    ObjectStore, PutPayload, GetResult, ListResult,
    local::LocalFileSystem,
    aws::AmazonS3Builder,
    gcp::GoogleCloudStorageBuilder,
    azure::MicrosoftAzureBuilder,
};
use std::sync::Arc;
use std::path::Path;
use tokio::io::AsyncReadExt;
use tracing::{info, warn, error};
use uuid::Uuid;

use crate::config::ObjectStorageConfig;

#[derive(Clone)]
pub struct ObjectStorage {
    store: Arc<dyn ObjectStore>,
    bucket: String,
}

impl ObjectStorage {
    pub async fn new(config: &ObjectStorageConfig) -> Result<Self> {
        let store: Arc<dyn ObjectStore> = match config.provider.as_str() {
            "local" => {
                let path = config.local_path.as_ref()
                    .ok_or_else(|| anyhow::anyhow!("Local path required for local storage"))?;
                
                // Ensure directory exists
                tokio::fs::create_dir_all(path).await?;
                
                Arc::new(LocalFileSystem::new_with_prefix(path)?)
            }
            "s3" => {
                let mut builder = AmazonS3Builder::new()
                    .with_bucket_name(&config.bucket);
                
                if let Some(region) = &config.region {
                    builder = builder.with_region(region);
                }
                
                if let Some(endpoint) = &config.endpoint {
                    builder = builder.with_endpoint(endpoint);
                }
                
                if let Some(access_key) = &config.access_key {
                    builder = builder.with_access_key_id(access_key);
                }
                
                if let Some(secret_key) = &config.secret_key {
                    builder = builder.with_secret_access_key(secret_key);
                }
                
                Arc::new(builder.build()?)
            }
            "gcs" => {
                let mut builder = GoogleCloudStorageBuilder::new()
                    .with_bucket_name(&config.bucket);
                
                if let Some(service_account_path) = &config.access_key {
                    builder = builder.with_service_account_path(service_account_path);
                }
                
                Arc::new(builder.build()?)
            }
            "azure" => {
                let mut builder = MicrosoftAzureBuilder::new()
                    .with_container_name(&config.bucket);
                
                if let Some(account) = &config.access_key {
                    builder = builder.with_account(account);
                }
                
                if let Some(access_key) = &config.secret_key {
                    builder = builder.with_access_key(access_key);
                }
                
                Arc::new(builder.build()?)
            }
            _ => {
                return Err(anyhow::anyhow!("Unsupported storage provider: {}", config.provider));
            }
        };

        info!("Initialized {} object storage", config.provider);

        Ok(Self {
            store,
            bucket: config.bucket.clone(),
        })
    }

    /// Store a file with a generated key
    pub async fn store_file(&self, data: Vec<u8>, prefix: &str, extension: Option<&str>) -> Result<String> {
        let key = self.generate_key(prefix, extension);
        self.store_with_key(&key, data).await?;
        Ok(key)
    }

    /// Store a file with a specific key
    pub async fn store_with_key(&self, key: &str, data: Vec<u8>) -> Result<()> {
        let path = object_store::path::Path::from(key);
        let payload = PutPayload::from_bytes(data.into());
        
        self.store.put(&path, payload).await?;
        
        info!("Stored object at key: {}", key);
        Ok(())
    }

    /// Retrieve a file by key
    pub async fn get_file(&self, key: &str) -> Result<Vec<u8>> {
        let path = object_store::path::Path::from(key);
        let result = self.store.get(&path).await?;
        
        let bytes = result.bytes().await?;
        Ok(bytes.to_vec())
    }

    /// Get file as a stream
    pub async fn get_file_stream(&self, key: &str) -> Result<GetResult> {
        let path = object_store::path::Path::from(key);
        let result = self.store.get(&path).await?;
        Ok(result)
    }

    /// Check if a file exists
    pub async fn file_exists(&self, key: &str) -> Result<bool> {
        let path = object_store::path::Path::from(key);
        match self.store.head(&path).await {
            Ok(_) => Ok(true),
            Err(object_store::Error::NotFound { .. }) => Ok(false),
            Err(e) => Err(e.into()),
        }
    }

    /// Delete a file
    pub async fn delete_file(&self, key: &str) -> Result<()> {
        let path = object_store::path::Path::from(key);
        self.store.delete(&path).await?;
        
        info!("Deleted object at key: {}", key);
        Ok(())
    }

    /// List files with a prefix
    pub async fn list_files(&self, prefix: &str) -> Result<Vec<String>> {
        let prefix_path = Some(&object_store::path::Path::from(prefix));
        let list_result = self.store.list(prefix_path).await?;
        
        let mut files = Vec::new();
        for object_meta in list_result {
            files.push(object_meta.location.to_string());
        }
        
        Ok(files)
    }

    /// Copy a file to a new location
    pub async fn copy_file(&self, source_key: &str, dest_key: &str) -> Result<()> {
        let source_path = object_store::path::Path::from(source_key);
        let dest_path = object_store::path::Path::from(dest_key);
        
        self.store.copy(&source_path, &dest_path).await?;
        
        info!("Copied object from {} to {}", source_key, dest_key);
        Ok(())
    }

    /// Get file metadata
    pub async fn get_metadata(&self, key: &str) -> Result<FileMetadata> {
        let path = object_store::path::Path::from(key);
        let meta = self.store.head(&path).await?;
        
        Ok(FileMetadata {
            key: key.to_string(),
            size: meta.size,
            last_modified: meta.last_modified,
            etag: meta.e_tag,
            content_type: meta.content_type,
        })
    }

    /// Generate a unique key for storing files
    fn generate_key(&self, prefix: &str, extension: Option<&str>) -> String {
        let uuid = Uuid::new_v4();
        let base_key = format!("{}/{}", prefix, uuid);
        
        if let Some(ext) = extension {
            format!("{}.{}", base_key, ext)
        } else {
            base_key
        }
    }

    /// Store repository archive
    pub async fn store_repository_archive(
        &self,
        job_id: Uuid,
        archive_data: Vec<u8>,
        format: &str,
    ) -> Result<String> {
        let key = format!("repositories/{}/archive.{}", job_id, format);
        self.store_with_key(&key, archive_data).await?;
        Ok(key)
    }

    /// Store individual file from repository
    pub async fn store_repository_file(
        &self,
        job_id: Uuid,
        file_path: &str,
        file_data: Vec<u8>,
    ) -> Result<String> {
        // Sanitize file path for object storage
        let sanitized_path = file_path.replace("../", "").replace("\\", "/");
        let key = format!("repositories/{}/files/{}", job_id, sanitized_path);
        
        self.store_with_key(&key, file_data).await?;
        Ok(key)
    }

    /// Store analysis report
    pub async fn store_analysis_report(
        &self,
        job_id: Uuid,
        report_data: Vec<u8>,
        format: &str,
    ) -> Result<String> {
        let key = format!("reports/{}/report.{}", job_id, format);
        self.store_with_key(&key, report_data).await?;
        Ok(key)
    }

    /// Store evidence package
    pub async fn store_evidence_package(
        &self,
        job_id: Uuid,
        evidence_data: Vec<u8>,
    ) -> Result<String> {
        let key = format!("evidence/{}/package.zip", job_id);
        self.store_with_key(&key, evidence_data).await?;
        Ok(key)
    }

    /// Store forensic hash
    pub async fn store_forensic_hash(
        &self,
        job_id: Uuid,
        hash_data: Vec<u8>,
        algorithm: &str,
    ) -> Result<String> {
        let key = format!("forensics/{}/hash.{}", job_id, algorithm);
        self.store_with_key(&key, hash_data).await?;
        Ok(key)
    }

    /// Store malware sample (in isolated location)
    pub async fn store_malware_sample(
        &self,
        job_id: Uuid,
        sample_data: Vec<u8>,
        filename: &str,
    ) -> Result<String> {
        // Store malware samples in isolated quarantine area
        let sanitized_filename = filename.replace("../", "").replace("\\", "/");
        let key = format!("quarantine/{}/samples/{}", job_id, sanitized_filename);
        
        self.store_with_key(&key, sample_data).await?;
        
        warn!("Malware sample stored in quarantine: {}", key);
        Ok(key)
    }

    /// Store ML model artifacts
    pub async fn store_ml_model(
        &self,
        model_name: &str,
        model_data: Vec<u8>,
        version: &str,
    ) -> Result<String> {
        let key = format!("models/{}/{}/model.bin", model_name, version);
        self.store_with_key(&key, model_data).await?;
        Ok(key)
    }

    /// Store embeddings cache
    pub async fn store_embeddings(
        &self,
        job_id: Uuid,
        embeddings_data: Vec<u8>,
    ) -> Result<String> {
        let key = format!("embeddings/{}/vectors.bin", job_id);
        self.store_with_key(&key, embeddings_data).await?;
        Ok(key)
    }

    /// Get storage statistics
    pub async fn get_statistics(&self, prefix: &str) -> Result<StorageStatistics> {
        let files = self.list_files(prefix).await?;
        let mut total_size = 0u64;
        let mut file_count = 0u64;

        for file_key in &files {
            if let Ok(metadata) = self.get_metadata(file_key).await {
                total_size += metadata.size as u64;
                file_count += 1;
            }
        }

        Ok(StorageStatistics {
            file_count,
            total_size_bytes: total_size,
            prefix: prefix.to_string(),
        })
    }

    /// Cleanup old files based on retention policy
    pub async fn cleanup_old_files(&self, prefix: &str, retention_days: u32) -> Result<u64> {
        let files = self.list_files(prefix).await?;
        let retention_duration = chrono::Duration::days(retention_days as i64);
        let cutoff_time = chrono::Utc::now() - retention_duration;
        
        let mut deleted_count = 0u64;

        for file_key in files {
            if let Ok(metadata) = self.get_metadata(&file_key).await {
                if metadata.last_modified < cutoff_time {
                    if let Ok(_) = self.delete_file(&file_key).await {
                        deleted_count += 1;
                        info!("Deleted old file: {}", file_key);
                    }
                }
            }
        }

        info!("Cleanup completed: {} files deleted from {}", deleted_count, prefix);
        Ok(deleted_count)
    }

    /// Health check for object storage
    pub async fn health_check(&self) -> Result<bool> {
        // Try to list objects to test connectivity
        match self.list_files("health").await {
            Ok(_) => Ok(true),
            Err(e) => {
                error!("Object storage health check failed: {}", e);
                Ok(false)
            }
        }
    }
}

#[derive(Debug, Clone)]
pub struct FileMetadata {
    pub key: String,
    pub size: usize,
    pub last_modified: chrono::DateTime<chrono::Utc>,
    pub etag: Option<String>,
    pub content_type: Option<String>,
}

#[derive(Debug, Clone)]
pub struct StorageStatistics {
    pub file_count: u64,
    pub total_size_bytes: u64,
    pub prefix: String,
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[tokio::test]
    async fn test_local_storage() {
        let temp_dir = tempdir().unwrap();
        let config = ObjectStorageConfig {
            provider: "local".to_string(),
            bucket: "test-bucket".to_string(),
            region: None,
            endpoint: None,
            access_key: None,
            secret_key: None,
            local_path: Some(temp_dir.path().to_string_lossy().to_string()),
        };

        let storage = ObjectStorage::new(&config).await.unwrap();

        // Test store and retrieve
        let test_data = b"Hello, World!".to_vec();
        let key = storage.store_file(test_data.clone(), "test", Some("txt")).await.unwrap();
        
        let retrieved_data = storage.get_file(&key).await.unwrap();
        assert_eq!(test_data, retrieved_data);

        // Test file exists
        assert!(storage.file_exists(&key).await.unwrap());

        // Test delete
        storage.delete_file(&key).await.unwrap();
        assert!(!storage.file_exists(&key).await.unwrap());
    }

    #[tokio::test]
    async fn test_key_generation() {
        let temp_dir = tempdir().unwrap();
        let config = ObjectStorageConfig {
            provider: "local".to_string(),
            bucket: "test-bucket".to_string(),
            region: None,
            endpoint: None,
            access_key: None,
            secret_key: None,
            local_path: Some(temp_dir.path().to_string_lossy().to_string()),
        };

        let storage = ObjectStorage::new(&config).await.unwrap();

        let key1 = storage.generate_key("test", Some("txt"));
        let key2 = storage.generate_key("test", Some("txt"));

        // Keys should be unique
        assert_ne!(key1, key2);
        assert!(key1.starts_with("test/"));
        assert!(key1.ends_with(".txt"));
    }
}