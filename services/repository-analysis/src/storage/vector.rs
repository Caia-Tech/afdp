use anyhow::Result;
use qdrant_client::{
    Qdrant, QdrantClient,
    qdrant::{
        CreateCollection, Distance, VectorParams, CollectionOperationResponse,
        PointStruct, SearchPoints, Filter, Condition, FieldCondition,
        Range, Match, Value, SearchResponse, ScoredPoint,
        UpsertPoints, DeletePoints, PointsSelector, PointId,
        WithPayloadSelector, PayloadSelector,
    },
};
use std::collections::HashMap;
use serde_json::{json, Value as JsonValue};
use tracing::{info, warn, error};
use uuid::Uuid;

use crate::config::VectorStorageConfig;
use super::{SimilarityQuery, SimilarityResult, Classification, FindingType};

#[derive(Clone)]
pub struct QdrantStorage {
    client: QdrantClient,
    collection_prefix: String,
    vector_size: usize,
}

impl QdrantStorage {
    pub async fn new(config: &VectorStorageConfig) -> Result<Self> {
        let mut client_builder = QdrantClient::from_url(&format!("http://{}:{}", config.host, config.port));
        
        if let Some(api_key) = &config.api_key {
            client_builder = client_builder.with_api_key(api_key);
        }
        
        let client = client_builder.build()?;

        info!("Connected to Qdrant vector database at {}:{}", config.host, config.port);

        Ok(Self {
            client,
            collection_prefix: config.collection_prefix.clone(),
            vector_size: config.vector_size,
        })
    }

    pub async fn initialize_collections(&self) -> Result<()> {
        info!("Initializing Qdrant collections");

        // Create collections for different types of vectors
        self.create_collection_if_not_exists("file_content").await?;
        self.create_collection_if_not_exists("code_snippets").await?;
        self.create_collection_if_not_exists("security_patterns").await?;
        self.create_collection_if_not_exists("malware_signatures").await?;
        self.create_collection_if_not_exists("document_content").await?;

        info!("Qdrant collections initialized");
        Ok(())
    }

    async fn create_collection_if_not_exists(&self, collection_name: &str) -> Result<()> {
        let full_name = format!("{}_{}", self.collection_prefix, collection_name);
        
        // Check if collection exists
        match self.client.collection_info(&full_name).await {
            Ok(_) => {
                info!("Collection {} already exists", full_name);
                return Ok(());
            }
            Err(_) => {
                // Collection doesn't exist, create it
            }
        }

        let create_collection = CreateCollection {
            collection_name: full_name.clone(),
            vectors_config: Some(qdrant_client::qdrant::VectorsConfig {
                config: Some(qdrant_client::qdrant::vectors_config::Config::Params(
                    VectorParams {
                        size: self.vector_size as u64,
                        distance: Distance::Cosine.into(),
                        hnsw_config: None,
                        quantization_config: None,
                        on_disk: None,
                    }
                )),
            }),
            hnsw_config: None,
            wal_config: None,
            optimizers_config: None,
            shard_number: None,
            on_disk_payload: None,
            timeout: None,
            replication_factor: None,
            write_consistency_factor: None,
            init_from_collection: None,
            quantization_config: None,
        };

        match self.client.create_collection(&create_collection).await {
            Ok(_) => {
                info!("Created collection: {}", full_name);
                Ok(())
            }
            Err(e) => {
                error!("Failed to create collection {}: {}", full_name, e);
                Err(e.into())
            }
        }
    }

    /// Store file content embeddings
    pub async fn store_file_embedding(
        &self,
        job_id: Uuid,
        file_path: &str,
        embedding: Vec<f32>,
        metadata: FileEmbeddingMetadata,
    ) -> Result<()> {
        let collection_name = format!("{}_file_content", self.collection_prefix);
        let point_id = Uuid::new_v4().to_string();

        let payload = json!({
            "job_id": job_id.to_string(),
            "file_path": file_path,
            "file_type": metadata.file_type,
            "language": metadata.language,
            "classification": metadata.classification,
            "content_hash": metadata.content_hash,
            "content_snippet": metadata.content_snippet,
            "line_count": metadata.line_count,
            "char_count": metadata.char_count,
            "timestamp": chrono::Utc::now().to_rfc3339(),
        }).as_object().unwrap().clone();

        let point = PointStruct::new(
            point_id,
            embedding,
            payload,
        );

        let upsert_points = UpsertPoints {
            collection_name: collection_name.clone(),
            points: vec![point],
            wait: Some(true),
            ordering: None,
        };

        match self.client.upsert_points(&upsert_points).await {
            Ok(_) => {
                info!("Stored file embedding for {} in job {}", file_path, job_id);
                Ok(())
            }
            Err(e) => {
                error!("Failed to store file embedding: {}", e);
                Err(e.into())
            }
        }
    }

    /// Store code snippet embeddings for similarity detection
    pub async fn store_code_embedding(
        &self,
        job_id: Uuid,
        file_path: &str,
        line_start: u32,
        line_end: u32,
        embedding: Vec<f32>,
        code_snippet: &str,
        language: &str,
    ) -> Result<()> {
        let collection_name = format!("{}_code_snippets", self.collection_prefix);
        let point_id = format!("{}:{}:{}-{}", job_id, file_path, line_start, line_end);

        let payload = json!({
            "job_id": job_id.to_string(),
            "file_path": file_path,
            "line_start": line_start,
            "line_end": line_end,
            "language": language,
            "code_snippet": code_snippet,
            "snippet_hash": blake3::hash(code_snippet.as_bytes()).to_hex().to_string(),
            "timestamp": chrono::Utc::now().to_rfc3339(),
        }).as_object().unwrap().clone();

        let point = PointStruct::new(
            point_id,
            embedding,
            payload,
        );

        let upsert_points = UpsertPoints {
            collection_name: collection_name.clone(),
            points: vec![point],
            wait: Some(true),
            ordering: None,
        };

        self.client.upsert_points(&upsert_points).await?;
        Ok(())
    }

    /// Store security pattern embeddings
    pub async fn store_security_pattern(
        &self,
        pattern_id: &str,
        embedding: Vec<f32>,
        pattern_metadata: SecurityPatternMetadata,
    ) -> Result<()> {
        let collection_name = format!("{}_security_patterns", self.collection_prefix);

        let payload = json!({
            "pattern_id": pattern_id,
            "pattern_type": pattern_metadata.pattern_type,
            "severity": pattern_metadata.severity,
            "description": pattern_metadata.description,
            "cve_ids": pattern_metadata.cve_ids,
            "languages": pattern_metadata.languages,
            "tags": pattern_metadata.tags,
            "created_at": chrono::Utc::now().to_rfc3339(),
        }).as_object().unwrap().clone();

        let point = PointStruct::new(
            pattern_id.to_string(),
            embedding,
            payload,
        );

        let upsert_points = UpsertPoints {
            collection_name: collection_name.clone(),
            points: vec![point],
            wait: Some(true),
            ordering: None,
        };

        self.client.upsert_points(&upsert_points).await?;
        Ok(())
    }

    /// Search for similar content
    pub async fn search_similar(&self, query: &SimilarityQuery) -> Result<Vec<SimilarityResult>> {
        let collection_name = if let Some(collection) = &query.collection_name {
            format!("{}_{}", self.collection_prefix, collection)
        } else {
            format!("{}_file_content", self.collection_prefix)
        };

        // Determine query vector
        let query_vector = if let Some(vector) = &query.query_vector {
            vector.clone()
        } else if let Some(text) = &query.query_text {
            // In a real implementation, you would generate embeddings for the query text
            // For now, return empty results
            return Ok(vec![]);
        } else {
            return Err(anyhow::anyhow!("Either query_text or query_vector must be provided"));
        };

        // Build filter conditions
        let mut conditions = Vec::new();

        if let Some(job_id) = &query.job_id {
            conditions.push(Condition {
                condition_one_of: Some(qdrant_client::qdrant::condition::ConditionOneOf::Field(
                    FieldCondition {
                        key: "job_id".to_string(),
                        r#match: Some(Match {
                            match_value: Some(qdrant_client::qdrant::r#match::MatchValue::Keyword(
                                job_id.to_string()
                            )),
                        }),
                        range: None,
                        geo_bounding_box: None,
                        geo_radius: None,
                        values_count: None,
                    }
                )),
            });
        }

        if let Some(file_path) = &query.file_path {
            conditions.push(Condition {
                condition_one_of: Some(qdrant_client::qdrant::condition::ConditionOneOf::Field(
                    FieldCondition {
                        key: "file_path".to_string(),
                        r#match: Some(Match {
                            match_value: Some(qdrant_client::qdrant::r#match::MatchValue::Text(
                                file_path.clone()
                            )),
                        }),
                        range: None,
                        geo_bounding_box: None,
                        geo_radius: None,
                        values_count: None,
                    }
                )),
            });
        }

        let filter = if !conditions.is_empty() {
            Some(Filter {
                should: vec![],
                must: conditions,
                must_not: vec![],
            })
        } else {
            None
        };

        let search_points = SearchPoints {
            collection_name: collection_name.clone(),
            vector: query_vector,
            limit: query.limit as u64,
            offset: Some(0),
            with_payload: Some(WithPayloadSelector {
                selector_options: Some(qdrant_client::qdrant::with_payload_selector::SelectorOptions::Enable(true)),
            }),
            with_vectors: None,
            filter,
            score_threshold: Some(query.similarity_threshold),
            params: None,
            read_consistency: None,
            timeout: None,
        };

        let search_response = self.client.search_points(&search_points).await?;
        
        let mut results = Vec::new();
        for scored_point in search_response.result {
            if let Some(result) = self.convert_scored_point_to_similarity_result(scored_point) {
                results.push(result);
            }
        }

        Ok(results)
    }

    fn convert_scored_point_to_similarity_result(&self, point: ScoredPoint) -> Option<SimilarityResult> {
        let payload = point.payload;
        
        // Extract required fields from payload
        let job_id_str = payload.get("job_id")?.as_str()?;
        let job_id = Uuid::parse_str(job_id_str).ok()?;
        
        let file_path = payload.get("file_path")?.as_str()?.to_string();
        let content_snippet = payload.get("content_snippet")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        
        // Parse classification (with default)
        let classification = payload.get("classification")
            .and_then(|v| v.as_str())
            .and_then(|s| match s {
                "public" => Some(Classification::Public),
                "internal" => Some(Classification::Internal),
                "confidential" => Some(Classification::Confidential),
                "restricted" => Some(Classification::Restricted),
                "top_secret" => Some(Classification::TopSecret),
                _ => None,
            })
            .unwrap_or(Classification::Public);

        // Extract finding types
        let finding_types = payload.get("finding_types")
            .and_then(|v| v.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|v| v.as_str())
                    .filter_map(|s| match s {
                        "secret_exposure" => Some(FindingType::SecretExposure),
                        "vulnerability" => Some(FindingType::Vulnerability),
                        "malware" => Some(FindingType::Malware),
                        "suspicious_code" => Some(FindingType::SuspiciousCode),
                        "license_violation" => Some(FindingType::LicenseViolation),
                        "compliance_violation" => Some(FindingType::ComplianceViolation),
                        "data_leak" => Some(FindingType::DataLeak),
                        "backdoor" => Some(FindingType::Backdoor),
                        "anomaly" => Some(FindingType::Anomaly),
                        _ => None,
                    })
                    .collect()
            })
            .unwrap_or_default();

        // Create metadata from remaining payload
        let mut metadata = serde_json::Map::new();
        for (key, value) in payload {
            if !["job_id", "file_path", "content_snippet", "classification", "finding_types"].contains(&key.as_str()) {
                metadata.insert(key, value);
            }
        }

        Some(SimilarityResult {
            score: point.score,
            job_id,
            file_path,
            content_snippet,
            classification,
            finding_types,
            metadata: serde_json::Value::Object(metadata),
        })
    }

    /// Search for code similarities across jobs
    pub async fn search_code_similarities(
        &self,
        code_embedding: Vec<f32>,
        language: Option<&str>,
        exclude_job_id: Option<Uuid>,
        threshold: f32,
        limit: usize,
    ) -> Result<Vec<CodeSimilarityResult>> {
        let collection_name = format!("{}_code_snippets", self.collection_prefix);

        let mut conditions = Vec::new();

        if let Some(lang) = language {
            conditions.push(Condition {
                condition_one_of: Some(qdrant_client::qdrant::condition::ConditionOneOf::Field(
                    FieldCondition {
                        key: "language".to_string(),
                        r#match: Some(Match {
                            match_value: Some(qdrant_client::qdrant::r#match::MatchValue::Keyword(
                                lang.to_string()
                            )),
                        }),
                        range: None,
                        geo_bounding_box: None,
                        geo_radius: None,
                        values_count: None,
                    }
                )),
            });
        }

        if let Some(exclude_id) = exclude_job_id {
            conditions.push(Condition {
                condition_one_of: Some(qdrant_client::qdrant::condition::ConditionOneOf::Field(
                    FieldCondition {
                        key: "job_id".to_string(),
                        r#match: Some(Match {
                            match_value: Some(qdrant_client::qdrant::r#match::MatchValue::Keyword(
                                exclude_id.to_string()
                            )),
                        }),
                        range: None,
                        geo_bounding_box: None,
                        geo_radius: None,
                        values_count: None,
                    }
                )),
            });
        }

        let filter = if !conditions.is_empty() {
            Some(Filter {
                should: vec![],
                must: if exclude_job_id.is_some() {
                    conditions[..conditions.len()-1].to_vec()
                } else {
                    conditions.clone()
                },
                must_not: if exclude_job_id.is_some() {
                    vec![conditions[conditions.len()-1].clone()]
                } else {
                    vec![]
                },
            })
        } else {
            None
        };

        let search_points = SearchPoints {
            collection_name,
            vector: code_embedding,
            limit: limit as u64,
            offset: Some(0),
            with_payload: Some(WithPayloadSelector {
                selector_options: Some(qdrant_client::qdrant::with_payload_selector::SelectorOptions::Enable(true)),
            }),
            with_vectors: None,
            filter,
            score_threshold: Some(threshold),
            params: None,
            read_consistency: None,
            timeout: None,
        };

        let search_response = self.client.search_points(&search_points).await?;
        
        let mut results = Vec::new();
        for scored_point in search_response.result {
            if let Some(result) = self.convert_to_code_similarity_result(scored_point) {
                results.push(result);
            }
        }

        Ok(results)
    }

    fn convert_to_code_similarity_result(&self, point: ScoredPoint) -> Option<CodeSimilarityResult> {
        let payload = point.payload;
        
        let job_id_str = payload.get("job_id")?.as_str()?;
        let job_id = Uuid::parse_str(job_id_str).ok()?;
        
        let file_path = payload.get("file_path")?.as_str()?.to_string();
        let line_start = payload.get("line_start")?.as_u64()? as u32;
        let line_end = payload.get("line_end")?.as_u64()? as u32;
        let language = payload.get("language")?.as_str()?.to_string();
        let code_snippet = payload.get("code_snippet")?.as_str()?.to_string();

        Some(CodeSimilarityResult {
            score: point.score,
            job_id,
            file_path,
            line_start,
            line_end,
            language,
            code_snippet,
        })
    }

    /// Delete embeddings for a specific job
    pub async fn delete_job_embeddings(&self, job_id: Uuid) -> Result<()> {
        let collections = [
            format!("{}_file_content", self.collection_prefix),
            format!("{}_code_snippets", self.collection_prefix),
        ];

        for collection_name in &collections {
            let filter = Filter {
                should: vec![],
                must: vec![Condition {
                    condition_one_of: Some(qdrant_client::qdrant::condition::ConditionOneOf::Field(
                        FieldCondition {
                            key: "job_id".to_string(),
                            r#match: Some(Match {
                                match_value: Some(qdrant_client::qdrant::r#match::MatchValue::Keyword(
                                    job_id.to_string()
                                )),
                            }),
                            range: None,
                            geo_bounding_box: None,
                            geo_radius: None,
                            values_count: None,
                        }
                    )),
                }],
                must_not: vec![],
            };

            let delete_points = DeletePoints {
                collection_name: collection_name.clone(),
                points: Some(PointsSelector {
                    points_selector_one_of: Some(
                        qdrant_client::qdrant::points_selector::PointsSelectorOneOf::Filter(filter)
                    ),
                }),
                wait: Some(true),
                ordering: None,
            };

            match self.client.delete_points(&delete_points).await {
                Ok(_) => info!("Deleted embeddings for job {} from {}", job_id, collection_name),
                Err(e) => warn!("Failed to delete embeddings from {}: {}", collection_name, e),
            }
        }

        Ok(())
    }

    /// Get collection statistics
    pub async fn get_collection_stats(&self, collection_type: &str) -> Result<CollectionStats> {
        let collection_name = format!("{}_{}", self.collection_prefix, collection_type);
        
        let info = self.client.collection_info(&collection_name).await?;
        
        Ok(CollectionStats {
            collection_name: collection_name.clone(),
            points_count: info.result.and_then(|r| r.points_count).unwrap_or(0),
            indexed_vectors_count: info.result.and_then(|r| r.indexed_vectors_count).unwrap_or(0),
            segments_count: info.result.and_then(|r| r.segments_count).unwrap_or(0),
        })
    }

    /// Health check for vector storage
    pub async fn health_check(&self) -> Result<bool> {
        match self.client.health_check().await {
            Ok(_) => Ok(true),
            Err(e) => {
                error!("Vector storage health check failed: {}", e);
                Ok(false)
            }
        }
    }
}

#[derive(Debug, Clone)]
pub struct FileEmbeddingMetadata {
    pub file_type: String,
    pub language: Option<String>,
    pub classification: Classification,
    pub content_hash: String,
    pub content_snippet: String,
    pub line_count: u32,
    pub char_count: u32,
}

#[derive(Debug, Clone)]
pub struct SecurityPatternMetadata {
    pub pattern_type: String,
    pub severity: String,
    pub description: String,
    pub cve_ids: Vec<String>,
    pub languages: Vec<String>,
    pub tags: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct CodeSimilarityResult {
    pub score: f32,
    pub job_id: Uuid,
    pub file_path: String,
    pub line_start: u32,
    pub line_end: u32,
    pub language: String,
    pub code_snippet: String,
}

#[derive(Debug, Clone)]
pub struct CollectionStats {
    pub collection_name: String,
    pub points_count: u64,
    pub indexed_vectors_count: u64,
    pub segments_count: u64,
}

// Extend SimilarityQuery to include collection name
impl SimilarityQuery {
    pub fn with_collection(mut self, collection: &str) -> Self {
        self.collection_name = Some(collection.to_string());
        self
    }
}

#[derive(Debug, Clone)]
pub struct SimilarityQueryExtended {
    pub collection_name: Option<String>,
    pub query_text: Option<String>,
    pub query_vector: Option<Vec<f32>>,
    pub file_path: Option<String>,
    pub job_id: Option<Uuid>,
    pub similarity_threshold: f32,
    pub limit: usize,
    pub include_metadata: bool,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_similarity_query_builder() {
        let query = SimilarityQuery {
            query_text: Some("test query".to_string()),
            query_vector: None,
            file_path: None,
            job_id: None,
            similarity_threshold: 0.8,
            limit: 10,
            include_metadata: true,
        };

        assert_eq!(query.similarity_threshold, 0.8);
        assert_eq!(query.limit, 10);
        assert!(query.include_metadata);
    }

    #[test]
    fn test_file_embedding_metadata() {
        let metadata = FileEmbeddingMetadata {
            file_type: "rust".to_string(),
            language: Some("rust".to_string()),
            classification: Classification::Public,
            content_hash: "abc123".to_string(),
            content_snippet: "fn main() {}".to_string(),
            line_count: 1,
            char_count: 12,
        };

        assert_eq!(metadata.file_type, "rust");
        assert_eq!(metadata.line_count, 1);
    }
}