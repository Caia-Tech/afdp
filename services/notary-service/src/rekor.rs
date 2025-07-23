//! Rekor transparency log integration

use crate::error::{NotaryError, Result};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use tracing::{debug, info};

/// Configuration for Rekor client
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct RekorConfig {
    /// Rekor server URL
    pub server_url: String,
    /// Request timeout in seconds
    pub timeout_secs: u64,
}

impl Default for RekorConfig {
    fn default() -> Self {
        Self {
            server_url: "https://rekor.sigstore.dev".to_string(),
            timeout_secs: 30,
        }
    }
}

/// Client for interacting with Rekor transparency log
pub struct RekorClient {
    client: Client,
    config: RekorConfig,
}

impl std::fmt::Debug for RekorClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RekorClient")
            .field("config", &self.config)
            .finish_non_exhaustive()
    }
}

/// Rekor log entry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogEntry {
    /// UUID of the log entry
    pub uuid: String,
    /// The body of the log entry
    pub body: String,
    /// Integration time (Unix timestamp)
    pub integrated_time: i64,
    /// Log ID
    pub log_id: String,
    /// Log index
    pub log_index: i64,
    /// Verification data
    pub verification: VerificationData,
}

/// Verification data for a log entry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerificationData {
    /// Inclusion proof
    pub inclusion_proof: Option<InclusionProof>,
    /// Signed entry timestamp
    pub signed_entry_timestamp: String,
}

/// Inclusion proof for verifying log entry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InclusionProof {
    /// Checkpoint
    pub checkpoint: String,
    /// Hashes for proof
    pub hashes: Vec<String>,
    /// Log index
    pub log_index: i64,
    /// Root hash
    pub root_hash: String,
    /// Tree size
    pub tree_size: i64,
}

/// Request body for creating a log entry
#[derive(Debug, Serialize)]
struct CreateLogEntryRequest {
    #[serde(rename = "apiVersion")]
    api_version: String,
    kind: String,
    spec: LogEntrySpec,
}

/// Specification for a log entry
#[derive(Debug, Serialize)]
struct LogEntrySpec {
    data: LogEntryData,
    signature: LogEntrySignature,
}

/// Data portion of log entry
#[derive(Debug, Serialize)]
struct LogEntryData {
    hash: HashData,
}

/// Hash data for log entry
#[derive(Debug, Serialize)]
struct HashData {
    algorithm: String,
    value: String,
}

/// Signature portion of log entry
#[derive(Debug, Serialize)]
struct LogEntrySignature {
    content: String,
    format: String,
    #[serde(rename = "publicKey")]
    public_key: PublicKeyData,
}

/// Public key data
#[derive(Debug, Serialize)]
struct PublicKeyData {
    content: String,
}

impl RekorClient {
    /// Creates a new Rekor client
    pub fn new(config: RekorConfig) -> Result<Self> {
        let client = Client::builder()
            .timeout(std::time::Duration::from_secs(config.timeout_secs))
            .build()
            .map_err(|e| NotaryError::RekorError(format!("Failed to build HTTP client: {}", e)))?;

        Ok(Self { client, config })
    }

    /// Creates a new log entry in Rekor
    pub async fn create_log_entry(
        &self,
        data_hash: &str,
        signature: &[u8],
        public_key: &str,
    ) -> Result<LogEntry> {
        info!("Creating Rekor log entry");

        let entry_request = CreateLogEntryRequest {
            api_version: "0.0.1".to_string(),
            kind: "hashedrekord".to_string(),
            spec: LogEntrySpec {
                data: LogEntryData {
                    hash: HashData {
                        algorithm: "sha256".to_string(),
                        value: data_hash.to_string(),
                    },
                },
                signature: LogEntrySignature {
                    content: BASE64.encode(signature),
                    format: "x509".to_string(),
                    public_key: PublicKeyData {
                        content: public_key.to_string(),
                    },
                },
            },
        };

        let url = format!("{}/api/v1/log/entries", self.config.server_url);
        debug!("Sending request to: {}", url);

        let response = self
            .client
            .post(&url)
            .json(&entry_request)
            .send()
            .await
            .map_err(|e| NotaryError::RekorError(format!("Request failed: {}", e)))?;

        if !response.status().is_success() {
            let status = response.status();
            let error_text = response.text().await.unwrap_or_default();
            return Err(NotaryError::RekorError(format!(
                "Rekor returned error {}: {}",
                status, error_text
            )));
        }

        let entry_response: serde_json::Value = response
            .json()
            .await
            .map_err(|e| NotaryError::RekorError(format!("Failed to parse response: {}", e)))?;

        // The response is a map with the UUID as key
        let (uuid, entry_data) = entry_response
            .as_object()
            .and_then(|obj| obj.iter().next())
            .ok_or_else(|| NotaryError::RekorError("Invalid response format".to_string()))?;

        let mut log_entry: LogEntry = serde_json::from_value(entry_data.clone())
            .map_err(|e| NotaryError::RekorError(format!("Failed to parse log entry: {}", e)))?;

        log_entry.uuid = uuid.clone();

        info!("Successfully created Rekor log entry: {}", uuid);
        Ok(log_entry)
    }

    /// Retrieves a log entry by UUID
    pub async fn get_log_entry(&self, uuid: &str) -> Result<LogEntry> {
        info!("Retrieving Rekor log entry: {}", uuid);

        let url = format!("{}/api/v1/log/entries/{}", self.config.server_url, uuid);

        let response = self
            .client
            .get(&url)
            .send()
            .await
            .map_err(|e| NotaryError::RekorError(format!("Request failed: {}", e)))?;

        if !response.status().is_success() {
            let status = response.status();
            let error_text = response.text().await.unwrap_or_default();
            return Err(NotaryError::RekorError(format!(
                "Rekor returned error {}: {}",
                status, error_text
            )));
        }

        let mut log_entry: LogEntry = response
            .json()
            .await
            .map_err(|e| NotaryError::RekorError(format!("Failed to parse response: {}", e)))?;

        log_entry.uuid = uuid.to_string();

        debug!("Successfully retrieved log entry");
        Ok(log_entry)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use wiremock::{
        matchers::{method, path},
        Mock, MockServer, ResponseTemplate,
    };

    #[test]
    fn test_rekor_config_default() {
        let config = RekorConfig::default();
        assert_eq!(config.server_url, "https://rekor.sigstore.dev");
        assert_eq!(config.timeout_secs, 30);
    }

    #[test]
    fn test_rekor_config_custom() {
        let config = RekorConfig {
            server_url: "https://rekor.example.com".to_string(),
            timeout_secs: 60,
        };
        
        assert_eq!(config.server_url, "https://rekor.example.com");
        assert_eq!(config.timeout_secs, 60);
    }

    #[test]
    fn test_rekor_config_serialization() {
        let config = RekorConfig {
            server_url: "https://custom.rekor.dev".to_string(),
            timeout_secs: 45,
        };
        
        let json = serde_json::to_string(&config).unwrap();
        assert!(json.contains("\"server_url\":\"https://custom.rekor.dev\""));
        assert!(json.contains("\"timeout_secs\":45"));
    }

    #[test]
    fn test_rekor_config_deserialization() {
        let json = r#"{
            "server_url": "https://private.rekor.org",
            "timeout_secs": 120
        }"#;
        
        let config: RekorConfig = serde_json::from_str(json).unwrap();
        assert_eq!(config.server_url, "https://private.rekor.org");
        assert_eq!(config.timeout_secs, 120);
    }

    #[test]
    fn test_log_entry_serialization() {
        let entry = LogEntry {
            uuid: "abc123".to_string(),
            body: "test body".to_string(),
            integrated_time: 1234567890,
            log_id: "log123".to_string(),
            log_index: 42,
            verification: VerificationData {
                inclusion_proof: None,
                signed_entry_timestamp: "timestamp".to_string(),
            },
        };
        
        let json = serde_json::to_string(&entry).unwrap();
        assert!(json.contains("\"uuid\":\"abc123\""));
        assert!(json.contains("\"integrated_time\":1234567890"));
        assert!(json.contains("\"log_index\":42"));
    }

    #[test]
    fn test_inclusion_proof_serialization() {
        let proof = InclusionProof {
            checkpoint: "checkpoint-data".to_string(),
            hashes: vec!["hash1".to_string(), "hash2".to_string()],
            log_index: 100,
            root_hash: "root-hash".to_string(),
            tree_size: 1000,
        };
        
        let json = serde_json::to_string(&proof).unwrap();
        assert!(json.contains("\"checkpoint\":\"checkpoint-data\""));
        assert!(json.contains("\"hashes\":[\"hash1\",\"hash2\"]"));
        assert!(json.contains("\"tree_size\":1000"));
    }

    #[test]
    fn test_create_log_entry_request_structure() {
        let request = CreateLogEntryRequest {
            api_version: "0.0.1".to_string(),
            kind: "hashedrekord".to_string(),
            spec: LogEntrySpec {
                data: LogEntryData {
                    hash: HashData {
                        algorithm: "sha256".to_string(),
                        value: "deadbeef".to_string(),
                    },
                },
                signature: LogEntrySignature {
                    content: "signature-content".to_string(),
                    format: "x509".to_string(),
                    public_key: PublicKeyData {
                        content: "public-key".to_string(),
                    },
                },
            },
        };
        
        let json = serde_json::to_string(&request).unwrap();
        assert!(json.contains("\"apiVersion\":\"0.0.1\""));
        assert!(json.contains("\"kind\":\"hashedrekord\""));
        assert!(json.contains("\"algorithm\":\"sha256\""));
        assert!(json.contains("\"value\":\"deadbeef\""));
        assert!(json.contains("\"format\":\"x509\""));
    }

    #[test]
    fn test_base64_signature_encoding() {
        let signature = b"test signature data";
        let encoded = BASE64.encode(signature);
        
        assert!(!encoded.is_empty());
        assert!(encoded.len() > signature.len()); // Base64 is larger
        
        // Verify it can be decoded back
        let decoded = BASE64.decode(&encoded).unwrap();
        assert_eq!(decoded, signature);
    }

    #[test]
    fn test_rekor_client_new() {
        let config = RekorConfig::default();
        let client = RekorClient::new(config.clone());
        
        assert!(client.is_ok());
        let client = client.unwrap();
        assert_eq!(client.config.server_url, config.server_url);
        assert_eq!(client.config.timeout_secs, config.timeout_secs);
    }

    #[test]
    fn test_verification_data_with_proof() {
        let data = VerificationData {
            inclusion_proof: Some(InclusionProof {
                checkpoint: "cp".to_string(),
                hashes: vec!["h1".to_string()],
                log_index: 1,
                root_hash: "rh".to_string(),
                tree_size: 10,
            }),
            signed_entry_timestamp: "ts".to_string(),
        };
        
        let json = serde_json::to_string(&data).unwrap();
        assert!(json.contains("inclusion_proof"));
        assert!(json.contains("checkpoint"));
    }

    #[test]
    fn test_verification_data_without_proof() {
        let data = VerificationData {
            inclusion_proof: None,
            signed_entry_timestamp: "ts".to_string(),
        };
        
        let json = serde_json::to_string(&data).unwrap();
        assert!(json.contains("null"));
        assert!(json.contains("signed_entry_timestamp"));
    }

    #[test]
    fn test_log_entry_full_deserialization() {
        let json = r#"{
            "uuid": "test-uuid",
            "body": "test-body",
            "integrated_time": 1234567890,
            "log_id": "test-log-id",
            "log_index": 999,
            "verification": {
                "inclusion_proof": {
                    "checkpoint": "test-checkpoint",
                    "hashes": ["hash1", "hash2", "hash3"],
                    "log_index": 999,
                    "root_hash": "root-hash-value",
                    "tree_size": 10000
                },
                "signed_entry_timestamp": "2024-01-01T00:00:00Z"
            }
        }"#;
        
        let entry: LogEntry = serde_json::from_str(json).unwrap();
        
        assert_eq!(entry.uuid, "test-uuid");
        assert_eq!(entry.body, "test-body");
        assert_eq!(entry.integrated_time, 1234567890);
        assert_eq!(entry.log_id, "test-log-id");
        assert_eq!(entry.log_index, 999);
        
        let proof = entry.verification.inclusion_proof.unwrap();
        assert_eq!(proof.checkpoint, "test-checkpoint");
        assert_eq!(proof.hashes.len(), 3);
        assert_eq!(proof.tree_size, 10000);
    }

    #[test]
    fn test_rekor_config_clone() {
        let original = RekorConfig {
            server_url: "https://test.rekor.dev".to_string(),
            timeout_secs: 90,
        };
        
        let cloned = original.clone();
        
        assert_eq!(original.server_url, cloned.server_url);
        assert_eq!(original.timeout_secs, cloned.timeout_secs);
    }

    #[test]
    fn test_log_entry_clone() {
        let original = LogEntry {
            uuid: "uuid".to_string(),
            body: "body".to_string(),
            integrated_time: 123,
            log_id: "log".to_string(),
            log_index: 456,
            verification: VerificationData {
                inclusion_proof: None,
                signed_entry_timestamp: "ts".to_string(),
            },
        };
        
        let cloned = original.clone();
        
        assert_eq!(original.uuid, cloned.uuid);
        assert_eq!(original.body, cloned.body);
        assert_eq!(original.integrated_time, cloned.integrated_time);
    }

    #[tokio::test]
    async fn test_create_log_entry_success() {
        let mock_server = MockServer::start().await;
        
        let mock_response = serde_json::json!({
            "test-uuid-123": {
                "uuid": "",  // This will be overridden after parsing
                "body": "test-body-content",
                "integrated_time": 1640995200,
                "log_id": "test-log-id",
                "log_index": 42,
                "verification": {
                    "inclusion_proof": {
                        "checkpoint": "test-checkpoint",
                        "hashes": ["hash1", "hash2"],
                        "log_index": 42,
                        "root_hash": "test-root-hash",
                        "tree_size": 100
                    },
                    "signed_entry_timestamp": "2022-01-01T00:00:00Z"
                }
            }
        });

        Mock::given(method("POST"))
            .and(path("/api/v1/log/entries"))
            .respond_with(ResponseTemplate::new(201).set_body_json(&mock_response))
            .mount(&mock_server)
            .await;

        let config = RekorConfig {
            server_url: mock_server.uri(),
            timeout_secs: 30,
        };

        let client = RekorClient::new(config).unwrap();
        
        let data_hash = "abc123def456";
        let signature = b"test signature";
        let public_key = "test-public-key";

        let result = client.create_log_entry(data_hash, signature, public_key).await.unwrap();

        assert_eq!(result.uuid, "test-uuid-123");
        assert_eq!(result.body, "test-body-content");
        assert_eq!(result.integrated_time, 1640995200);
        assert_eq!(result.log_id, "test-log-id");
        assert_eq!(result.log_index, 42);
        assert!(result.verification.inclusion_proof.is_some());
    }

    #[tokio::test]
    async fn test_create_log_entry_server_error() {
        let mock_server = MockServer::start().await;
        
        Mock::given(method("POST"))
            .and(path("/api/v1/log/entries"))
            .respond_with(ResponseTemplate::new(500).set_body_string("Internal Server Error"))
            .mount(&mock_server)
            .await;

        let config = RekorConfig {
            server_url: mock_server.uri(),
            timeout_secs: 30,
        };

        let client = RekorClient::new(config).unwrap();
        
        let data_hash = "abc123def456";
        let signature = b"test signature";
        let public_key = "test-public-key";

        let result = client.create_log_entry(data_hash, signature, public_key).await;
        
        assert!(result.is_err());
        let error = result.unwrap_err();
        assert!(matches!(error, NotaryError::RekorError(_)));
        if let NotaryError::RekorError(msg) = error {
            assert!(msg.contains("500"));
            assert!(msg.contains("Internal Server Error"));
        }
    }

    #[tokio::test]
    async fn test_create_log_entry_invalid_response_format() {
        let mock_server = MockServer::start().await;
        
        // Response that's not in the expected format (not an object with UUID key)
        let invalid_response = serde_json::json!([]);

        Mock::given(method("POST"))
            .and(path("/api/v1/log/entries"))
            .respond_with(ResponseTemplate::new(201).set_body_json(&invalid_response))
            .mount(&mock_server)
            .await;

        let config = RekorConfig {
            server_url: mock_server.uri(),
            timeout_secs: 30,
        };

        let client = RekorClient::new(config).unwrap();
        
        let data_hash = "abc123def456";
        let signature = b"test signature";
        let public_key = "test-public-key";

        let result = client.create_log_entry(data_hash, signature, public_key).await;
        
        assert!(result.is_err());
        let error = result.unwrap_err();
        assert!(matches!(error, NotaryError::RekorError(_)));
        if let NotaryError::RekorError(msg) = error {
            assert!(msg.contains("Invalid response format"));
        }
    }

    #[tokio::test]
    async fn test_create_log_entry_malformed_json_response() {
        let mock_server = MockServer::start().await;
        
        Mock::given(method("POST"))
            .and(path("/api/v1/log/entries"))
            .respond_with(ResponseTemplate::new(201).set_body_string("invalid json"))
            .mount(&mock_server)
            .await;

        let config = RekorConfig {
            server_url: mock_server.uri(),
            timeout_secs: 30,
        };

        let client = RekorClient::new(config).unwrap();
        
        let data_hash = "abc123def456";
        let signature = b"test signature";
        let public_key = "test-public-key";

        let result = client.create_log_entry(data_hash, signature, public_key).await;
        
        assert!(result.is_err());
        let error = result.unwrap_err();
        assert!(matches!(error, NotaryError::RekorError(_)));
        if let NotaryError::RekorError(msg) = error {
            assert!(msg.contains("Failed to parse response"));
        }
    }

    #[tokio::test]
    async fn test_create_log_entry_malformed_log_entry() {
        let mock_server = MockServer::start().await;
        
        // Response with correct UUID structure but invalid log entry data
        let mock_response = serde_json::json!({
            "test-uuid-123": {
                "invalid_field": "value"
                // Missing required fields for LogEntry
            }
        });

        Mock::given(method("POST"))
            .and(path("/api/v1/log/entries"))
            .respond_with(ResponseTemplate::new(201).set_body_json(&mock_response))
            .mount(&mock_server)
            .await;

        let config = RekorConfig {
            server_url: mock_server.uri(),
            timeout_secs: 30,
        };

        let client = RekorClient::new(config).unwrap();
        
        let data_hash = "abc123def456";
        let signature = b"test signature";
        let public_key = "test-public-key";

        let result = client.create_log_entry(data_hash, signature, public_key).await;
        
        assert!(result.is_err());
        let error = result.unwrap_err();
        assert!(matches!(error, NotaryError::RekorError(_)));
        if let NotaryError::RekorError(msg) = error {
            assert!(msg.contains("Failed to parse log entry"));
        }
    }

    #[tokio::test]
    async fn test_get_log_entry_success() {
        let mock_server = MockServer::start().await;
        
        let mock_entry = LogEntry {
            uuid: "test-uuid-456".to_string(),
            body: "retrieved-body-content".to_string(),
            integrated_time: 1641081600,
            log_id: "retrieved-log-id".to_string(),
            log_index: 99,
            verification: VerificationData {
                inclusion_proof: Some(InclusionProof {
                    checkpoint: "retrieved-checkpoint".to_string(),
                    hashes: vec!["rhash1".to_string(), "rhash2".to_string()],
                    log_index: 99,
                    root_hash: "retrieved-root-hash".to_string(),
                    tree_size: 200,
                }),
                signed_entry_timestamp: "2022-01-02T00:00:00Z".to_string(),
            },
        };

        Mock::given(method("GET"))
            .and(path("/api/v1/log/entries/test-uuid-456"))
            .respond_with(ResponseTemplate::new(200).set_body_json(&mock_entry))
            .mount(&mock_server)
            .await;

        let config = RekorConfig {
            server_url: mock_server.uri(),
            timeout_secs: 30,
        };

        let client = RekorClient::new(config).unwrap();
        
        let result = client.get_log_entry("test-uuid-456").await.unwrap();

        assert_eq!(result.uuid, "test-uuid-456");
        assert_eq!(result.body, "retrieved-body-content");
        assert_eq!(result.integrated_time, 1641081600);
        assert_eq!(result.log_id, "retrieved-log-id");
        assert_eq!(result.log_index, 99);
        assert!(result.verification.inclusion_proof.is_some());
        
        let proof = result.verification.inclusion_proof.unwrap();
        assert_eq!(proof.checkpoint, "retrieved-checkpoint");
        assert_eq!(proof.hashes.len(), 2);
        assert_eq!(proof.tree_size, 200);
    }

    #[tokio::test]
    async fn test_get_log_entry_not_found() {
        let mock_server = MockServer::start().await;
        
        Mock::given(method("GET"))
            .and(path("/api/v1/log/entries/nonexistent-uuid"))
            .respond_with(ResponseTemplate::new(404).set_body_string("Entry not found"))
            .mount(&mock_server)
            .await;

        let config = RekorConfig {
            server_url: mock_server.uri(),
            timeout_secs: 30,
        };

        let client = RekorClient::new(config).unwrap();
        
        let result = client.get_log_entry("nonexistent-uuid").await;
        
        assert!(result.is_err());
        let error = result.unwrap_err();
        assert!(matches!(error, NotaryError::RekorError(_)));
        if let NotaryError::RekorError(msg) = error {
            assert!(msg.contains("404"));
            assert!(msg.contains("Entry not found"));
        }
    }

    #[tokio::test]
    async fn test_get_log_entry_malformed_response() {
        let mock_server = MockServer::start().await;
        
        Mock::given(method("GET"))
            .and(path("/api/v1/log/entries/test-uuid"))
            .respond_with(ResponseTemplate::new(200).set_body_string("invalid json"))
            .mount(&mock_server)
            .await;

        let config = RekorConfig {
            server_url: mock_server.uri(),
            timeout_secs: 30,
        };

        let client = RekorClient::new(config).unwrap();
        
        let result = client.get_log_entry("test-uuid").await;
        
        assert!(result.is_err());
        let error = result.unwrap_err();
        assert!(matches!(error, NotaryError::RekorError(_)));
        if let NotaryError::RekorError(msg) = error {
            assert!(msg.contains("Failed to parse response"));
        }
    }

    #[tokio::test]
    async fn test_create_log_entry_with_different_signature_formats() {
        let mock_server = MockServer::start().await;
        
        let mock_response = serde_json::json!({
            "sig-format-test": {
                "uuid": "",  // This will be overridden after parsing
                "body": "sig-format-body",
                "integrated_time": 1642168000,
                "log_id": "sig-format-log",
                "log_index": 123,
                "verification": {
                    "inclusion_proof": null,
                    "signed_entry_timestamp": "2022-01-14T12:00:00Z"
                }
            }
        });

        Mock::given(method("POST"))
            .and(path("/api/v1/log/entries"))
            .respond_with(ResponseTemplate::new(201).set_body_json(&mock_response))
            .mount(&mock_server)
            .await;

        let config = RekorConfig {
            server_url: mock_server.uri(),
            timeout_secs: 30,
        };

        let client = RekorClient::new(config).unwrap();
        
        // Test with different signature sizes and content
        let test_cases = vec![
            (b"short".to_vec(), "short signature"),
            (b"this is a much longer signature that should still work properly".to_vec(), "longer signature"),
            (vec![0u8; 256], "binary signature with null bytes"),
            (b"\xFF\xFE\xFD\xFC".to_vec(), "binary signature with high bytes"),
        ];

        for (signature, description) in test_cases {
            let result = client.create_log_entry("test-hash", &signature, "test-key").await.unwrap();
            assert_eq!(result.uuid, "sig-format-test", "Failed for: {}", description);
            assert_eq!(result.log_index, 123);
        }
    }

    #[tokio::test]
    async fn test_rekor_client_with_custom_timeout() {
        let config = RekorConfig {
            server_url: "https://custom.rekor.test".to_string(),
            timeout_secs: 5, // Short timeout
        };

        let client = RekorClient::new(config).unwrap();
        
        // Verify the client was created with custom config
        assert_eq!(client.config.server_url, "https://custom.rekor.test");
        assert_eq!(client.config.timeout_secs, 5);
    }

    #[test]
    fn test_log_entry_debug_format() {
        let entry = LogEntry {
            uuid: "debug-test".to_string(),
            body: "debug-body".to_string(),
            integrated_time: 1640995200,
            log_id: "debug-log".to_string(),
            log_index: 1,
            verification: VerificationData {
                inclusion_proof: None,
                signed_entry_timestamp: "debug-ts".to_string(),
            },
        };
        
        let debug_str = format!("{:?}", entry);
        assert!(debug_str.contains("LogEntry"));
        assert!(debug_str.contains("debug-test"));
        assert!(debug_str.contains("debug-body"));
        assert!(debug_str.contains("1640995200"));
    }

    #[test]
    fn test_create_log_entry_request_serialization_edge_cases() {
        // Test with empty values
        let request = CreateLogEntryRequest {
            api_version: "".to_string(),
            kind: "".to_string(),
            spec: LogEntrySpec {
                data: LogEntryData {
                    hash: HashData {
                        algorithm: "".to_string(),
                        value: "".to_string(),
                    },
                },
                signature: LogEntrySignature {
                    content: "".to_string(),
                    format: "".to_string(),
                    public_key: PublicKeyData {
                        content: "".to_string(),
                    },
                },
            },
        };
        
        let json = serde_json::to_string(&request).unwrap();
        assert!(json.contains("\"apiVersion\":\"\""));
        assert!(json.contains("\"kind\":\"\""));
        assert!(json.contains("\"algorithm\":\"\""));
        assert!(json.contains("\"value\":\"\""));
        assert!(json.contains("\"format\":\"\""));
        assert!(json.contains("\"publicKey\":{\"content\":\"\"}"));
    }

    #[test]
    fn test_rekor_config_validation() {
        let config = RekorConfig {
            server_url: "https://valid.rekor.url".to_string(),
            timeout_secs: 120,
        };
        
        // Validate fields are accessible and correct
        assert!(config.server_url.starts_with("https://"));
        assert!(config.timeout_secs > 0);
        assert!(config.timeout_secs < 3600); // Less than 1 hour is reasonable
    }

    #[test]
    fn test_inclusion_proof_edge_cases() {
        // Test with empty hashes
        let proof = InclusionProof {
            checkpoint: "empty-hashes".to_string(),
            hashes: vec![],
            log_index: 0,
            root_hash: "root".to_string(),
            tree_size: 1,
        };
        
        let json = serde_json::to_string(&proof).unwrap();
        assert!(json.contains("\"hashes\":[]"));
        assert!(json.contains("\"tree_size\":1"));
        
        // Test with many hashes
        let many_hashes: Vec<String> = (0..100).map(|i| format!("hash{}", i)).collect();
        let proof_many = InclusionProof {
            checkpoint: "many-hashes".to_string(),
            hashes: many_hashes.clone(),
            log_index: 99,
            root_hash: "many-root".to_string(),
            tree_size: 1000,
        };
        
        let json_many = serde_json::to_string(&proof_many).unwrap();
        assert!(json_many.contains("hash0"));
        assert!(json_many.contains("hash99"));
        assert!(json_many.contains("\"tree_size\":1000"));
    }

    #[test]
    fn test_verification_data_structure_completeness() {
        // Test with complete inclusion proof
        let complete_data = VerificationData {
            inclusion_proof: Some(InclusionProof {
                checkpoint: "complete".to_string(),
                hashes: vec!["h1".to_string(), "h2".to_string()],
                log_index: 42,
                root_hash: "complete-root".to_string(),
                tree_size: 100,
            }),
            signed_entry_timestamp: "2024-01-01T12:00:00Z".to_string(),
        };
        
        assert!(complete_data.inclusion_proof.is_some());
        assert_eq!(complete_data.signed_entry_timestamp, "2024-01-01T12:00:00Z");
        
        let proof = complete_data.inclusion_proof.unwrap();
        assert_eq!(proof.hashes.len(), 2);
        assert_eq!(proof.tree_size, 100);
    }
}