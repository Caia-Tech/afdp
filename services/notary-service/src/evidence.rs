//! Evidence package data structures

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Represents the evidence package to be signed
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvidencePackage {
    /// The version of the evidence schema
    pub spec_version: String,
    
    /// ISO 8601 timestamp of event creation
    pub timestamp_utc: DateTime<Utc>,
    
    /// A dot-notation string describing the event
    pub event_type: String,
    
    /// Describes who or what initiated the event
    pub actor: Actor,
    
    /// A list of digital artifacts related to the event
    pub artifacts: Vec<Artifact>,
    
    /// Custom, user-defined key-value pairs
    #[serde(default)]
    pub metadata: HashMap<String, serde_json::Value>,
}

/// Represents an actor (user, service, or workflow) that initiated an event
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Actor {
    /// Type of actor (e.g., "workflow", "human_user", "service")
    #[serde(rename = "type")]
    pub actor_type: String,
    
    /// Unique identifier for the actor
    pub id: String,
    
    /// Authentication provider (optional)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub auth_provider: Option<String>,
}

/// Represents a digital artifact associated with an event
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Artifact {
    /// Name of the artifact
    pub name: String,
    
    /// URI where the artifact can be found (optional)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub uri: Option<String>,
    
    /// SHA256 hash of the artifact
    pub hash_sha256: String,
}

impl EvidencePackage {
    /// Creates a new evidence package with current timestamp
    pub fn new(event_type: String, actor: Actor) -> Self {
        Self {
            spec_version: "1.0.0".to_string(),
            timestamp_utc: Utc::now(),
            event_type,
            actor,
            artifacts: Vec::new(),
            metadata: HashMap::new(),
        }
    }

    /// Adds an artifact to the evidence package
    pub fn add_artifact(mut self, artifact: Artifact) -> Self {
        self.artifacts.push(artifact);
        self
    }

    /// Adds metadata to the evidence package
    pub fn add_metadata(mut self, key: String, value: serde_json::Value) -> Self {
        self.metadata.insert(key, value);
        self
    }

    /// Calculates the SHA256 hash of the evidence package
    pub fn calculate_hash(&self) -> crate::Result<String> {
        let json_bytes = serde_json::to_vec(self)?;
        let hash = ring::digest::digest(&ring::digest::SHA256, &json_bytes);
        use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
        Ok(BASE64.encode(hash.as_ref()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn test_evidence_package_creation() {
        let actor = Actor {
            actor_type: "human_user".to_string(),
            id: "test@example.com".to_string(),
            auth_provider: Some("keycloak".to_string()),
        };

        let package = EvidencePackage::new("test.event".to_string(), actor)
            .add_artifact(Artifact {
                name: "test.file".to_string(),
                uri: Some("s3://bucket/test.file".to_string()),
                hash_sha256: "abc123".to_string(),
            })
            .add_metadata("key".to_string(), json!("value"));

        assert_eq!(package.spec_version, "1.0.0");
        assert_eq!(package.event_type, "test.event");
        assert_eq!(package.artifacts.len(), 1);
        assert_eq!(package.metadata.get("key").unwrap(), "value");
    }

    #[test]
    fn test_evidence_package_serialization() {
        let actor = Actor {
            actor_type: "workflow".to_string(),
            id: "temporal-wf-123".to_string(),
            auth_provider: None,
        };

        let package = EvidencePackage::new("ai.model.deployment.approved".to_string(), actor);
        
        let json = serde_json::to_string_pretty(&package).unwrap();
        assert!(json.contains("\"spec_version\": \"1.0.0\""));
        assert!(json.contains("\"event_type\": \"ai.model.deployment.approved\""));
    }

    #[test]
    fn test_evidence_package_hash_consistency() {
        let actor = Actor {
            actor_type: "service".to_string(),
            id: "notary-service".to_string(),
            auth_provider: Some("oauth2".to_string()),
        };

        let package = EvidencePackage::new("system.health.check".to_string(), actor);
        
        // Calculate hash multiple times - should be consistent
        let hash1 = package.calculate_hash().unwrap();
        let hash2 = package.calculate_hash().unwrap();
        
        assert_eq!(hash1, hash2, "Hash should be deterministic");
        assert!(!hash1.is_empty(), "Hash should not be empty");
    }

    #[test]
    fn test_evidence_package_hash_changes_with_content() {
        let actor = Actor {
            actor_type: "service".to_string(),
            id: "test-service".to_string(),
            auth_provider: None,
        };

        let package1 = EvidencePackage::new("event.one".to_string(), actor.clone());
        let package2 = EvidencePackage::new("event.two".to_string(), actor);
        
        let hash1 = package1.calculate_hash().unwrap();
        let hash2 = package2.calculate_hash().unwrap();
        
        assert_ne!(hash1, hash2, "Different content should produce different hashes");
    }

    #[test]
    fn test_actor_serialization_with_optional_fields() {
        let actor_with_auth = Actor {
            actor_type: "human_user".to_string(),
            id: "user123".to_string(),
            auth_provider: Some("github".to_string()),
        };

        let actor_without_auth = Actor {
            actor_type: "automated".to_string(),
            id: "bot456".to_string(),
            auth_provider: None,
        };

        let json_with = serde_json::to_string(&actor_with_auth).unwrap();
        let json_without = serde_json::to_string(&actor_without_auth).unwrap();

        assert!(json_with.contains("auth_provider"));
        assert!(!json_without.contains("auth_provider"), "Should skip None fields");
    }

    #[test]
    fn test_artifact_with_optional_uri() {
        let artifact_with_uri = Artifact {
            name: "model.onnx".to_string(),
            uri: Some("s3://models/model.onnx".to_string()),
            hash_sha256: "deadbeef".to_string(),
        };

        let artifact_without_uri = Artifact {
            name: "inline-config".to_string(),
            uri: None,
            hash_sha256: "cafebabe".to_string(),
        };

        let json_with = serde_json::to_string(&artifact_with_uri).unwrap();
        let json_without = serde_json::to_string(&artifact_without_uri).unwrap();

        assert!(json_with.contains("uri"));
        assert!(!json_without.contains("uri"), "Should skip None uri");
    }

    #[test]
    fn test_evidence_package_builder_pattern() {
        let actor = Actor {
            actor_type: "ci_pipeline".to_string(),
            id: "github-actions-123".to_string(),
            auth_provider: Some("github".to_string()),
        };

        let package = EvidencePackage::new("ci.build.completed".to_string(), actor)
            .add_artifact(Artifact {
                name: "app.jar".to_string(),
                uri: Some("s3://artifacts/app.jar".to_string()),
                hash_sha256: "hash1".to_string(),
            })
            .add_artifact(Artifact {
                name: "app.pom".to_string(),
                uri: Some("s3://artifacts/app.pom".to_string()),
                hash_sha256: "hash2".to_string(),
            })
            .add_metadata("build_number".to_string(), json!(42))
            .add_metadata("branch".to_string(), json!("main"))
            .add_metadata("commit".to_string(), json!("abc123"));

        assert_eq!(package.artifacts.len(), 2);
        assert_eq!(package.metadata.len(), 3);
        assert_eq!(package.metadata.get("build_number").unwrap(), 42);
    }

    #[test]
    fn test_evidence_package_deserialization() {
        let json_str = r#"{
            "spec_version": "1.0.0",
            "timestamp_utc": "2024-01-01T00:00:00Z",
            "event_type": "test.event",
            "actor": {
                "type": "human_user",
                "id": "test@example.com",
                "auth_provider": "okta"
            },
            "artifacts": [
                {
                    "name": "test.file",
                    "uri": "s3://bucket/test.file",
                    "hash_sha256": "abc123"
                }
            ],
            "metadata": {
                "custom_field": "custom_value",
                "numeric_field": 123,
                "boolean_field": true
            }
        }"#;

        let package: EvidencePackage = serde_json::from_str(json_str).unwrap();
        
        assert_eq!(package.spec_version, "1.0.0");
        assert_eq!(package.event_type, "test.event");
        assert_eq!(package.actor.actor_type, "human_user");
        assert_eq!(package.actor.id, "test@example.com");
        assert_eq!(package.actor.auth_provider, Some("okta".to_string()));
        assert_eq!(package.artifacts.len(), 1);
        assert_eq!(package.metadata.len(), 3);
    }

    #[test]
    fn test_evidence_package_empty_collections() {
        let actor = Actor {
            actor_type: "system".to_string(),
            id: "heartbeat".to_string(),
            auth_provider: None,
        };

        let package = EvidencePackage::new("system.heartbeat".to_string(), actor);
        
        assert_eq!(package.artifacts.len(), 0);
        assert_eq!(package.metadata.len(), 0);
        
        // Should still serialize correctly
        let json = serde_json::to_string(&package).unwrap();
        assert!(json.contains("artifacts"));
        assert!(json.contains("metadata"));
    }

    #[test]
    fn test_timestamp_precision() {
        let actor = Actor {
            actor_type: "test".to_string(),
            id: "test".to_string(),
            auth_provider: None,
        };

        let package = EvidencePackage::new("test.event".to_string(), actor);
        
        // Verify timestamp is recent (within last second)
        let now = Utc::now();
        let diff = now.signed_duration_since(package.timestamp_utc);
        assert!(diff.num_seconds() < 1, "Timestamp should be recent");
        
        // Verify serialization includes proper ISO format
        let json = serde_json::to_string(&package).unwrap();
        assert!(json.contains("timestamp_utc"));
        // Should contain 'T' and 'Z' for ISO format
        assert!(json.contains("T"));
        assert!(json.contains("Z"));
    }

    #[test]
    fn test_metadata_value_types() {
        let actor = Actor {
            actor_type: "test".to_string(),
            id: "test".to_string(),
            auth_provider: None,
        };

        let package = EvidencePackage::new("test.event".to_string(), actor)
            .add_metadata("string_value".to_string(), json!("hello"))
            .add_metadata("number_value".to_string(), json!(42))
            .add_metadata("float_value".to_string(), json!(std::f64::consts::PI))
            .add_metadata("bool_value".to_string(), json!(true))
            .add_metadata("null_value".to_string(), json!(null))
            .add_metadata("array_value".to_string(), json!(["a", "b", "c"]))
            .add_metadata("object_value".to_string(), json!({"nested": "value"}));

        assert_eq!(package.metadata.len(), 7);
        assert_eq!(package.metadata.get("string_value").unwrap(), "hello");
        assert_eq!(package.metadata.get("number_value").unwrap(), 42);
        assert_eq!(package.metadata.get("float_value").unwrap(), std::f64::consts::PI);
        assert_eq!(package.metadata.get("bool_value").unwrap(), true);
        assert!(package.metadata.get("null_value").unwrap().is_null());
        assert!(package.metadata.get("array_value").unwrap().is_array());
        assert!(package.metadata.get("object_value").unwrap().is_object());
    }
}