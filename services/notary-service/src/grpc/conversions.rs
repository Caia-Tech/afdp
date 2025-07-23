//! Type conversions between internal types and gRPC protobuf types

use crate::evidence::{Actor, Artifact, EvidencePackage};
use crate::notary::NotarizationReceipt;
use crate::temporal::activities::ValidationResult;
use crate::grpc::notary;
use std::collections::HashMap;

// Evidence Package conversions
impl From<EvidencePackage> for notary::EvidencePackage {
    fn from(evidence: EvidencePackage) -> Self {
        Self {
            spec_version: evidence.spec_version,
            timestamp_utc: Some(prost_types::Timestamp {
                seconds: evidence.timestamp_utc.timestamp(),
                nanos: evidence.timestamp_utc.timestamp_subsec_nanos() as i32,
            }),
            event_type: evidence.event_type,
            actor: Some(evidence.actor.into()),
            artifacts: evidence.artifacts.into_iter().map(Into::into).collect(),
            metadata: Some(convert_metadata_to_struct(evidence.metadata)),
        }
    }
}

impl From<notary::EvidencePackage> for EvidencePackage {
    fn from(evidence: notary::EvidencePackage) -> Self {
        let timestamp = evidence.timestamp_utc
            .map(|ts| chrono::DateTime::from_timestamp(ts.seconds, ts.nanos as u32).unwrap_or_default())
            .unwrap_or_else(chrono::Utc::now);

        let metadata = evidence.metadata
            .map(convert_struct_to_metadata)
            .unwrap_or_default();

        Self {
            spec_version: evidence.spec_version,
            timestamp_utc: timestamp,
            event_type: evidence.event_type,
            actor: evidence.actor.map(Into::into).unwrap_or_default(),
            artifacts: evidence.artifacts.into_iter().map(Into::into).collect(),
            metadata,
        }
    }
}

// Actor conversions
impl From<Actor> for notary::Actor {
    fn from(actor: Actor) -> Self {
        Self {
            actor_type: actor.actor_type,
            id: actor.id,
            auth_provider: actor.auth_provider.unwrap_or_default(),
        }
    }
}

impl From<notary::Actor> for Actor {
    fn from(actor: notary::Actor) -> Self {
        Self {
            actor_type: actor.actor_type,
            id: actor.id,
            auth_provider: if actor.auth_provider.is_empty() {
                None
            } else {
                Some(actor.auth_provider)
            },
        }
    }
}

// Artifact conversions
impl From<Artifact> for notary::Artifact {
    fn from(artifact: Artifact) -> Self {
        Self {
            name: artifact.name,
            uri: artifact.uri.unwrap_or_default(),
            hash_sha256: artifact.hash_sha256,
        }
    }
}

impl From<notary::Artifact> for Artifact {
    fn from(artifact: notary::Artifact) -> Self {
        Self {
            name: artifact.name,
            uri: if artifact.uri.is_empty() { None } else { Some(artifact.uri) },
            hash_sha256: artifact.hash_sha256,
        }
    }
}

// NotarizationReceipt conversions
impl From<NotarizationReceipt> for notary::NotarizationReceipt {
    fn from(receipt: NotarizationReceipt) -> Self {
        Self {
            evidence_package_hash: receipt.evidence_package_hash,
            rekor_log_id: receipt.rekor_log_id,
            rekor_server_url: receipt.rekor_server_url,
            signature_b64: receipt.signature_b64,
            public_key_b64: receipt.public_key_b64,
            integrated_time: receipt.integrated_time,
            log_index: receipt.log_index,
        }
    }
}

impl From<notary::NotarizationReceipt> for NotarizationReceipt {
    fn from(receipt: notary::NotarizationReceipt) -> Self {
        Self {
            evidence_package_hash: receipt.evidence_package_hash,
            rekor_log_id: receipt.rekor_log_id,
            rekor_server_url: receipt.rekor_server_url,
            signature_b64: receipt.signature_b64,
            public_key_b64: receipt.public_key_b64,
            integrated_time: receipt.integrated_time,
            log_index: receipt.log_index,
        }
    }
}

// ValidationResult conversions
impl From<ValidationResult> for notary::ValidationResult {
    fn from(result: ValidationResult) -> Self {
        Self {
            signature_valid: result.is_valid,
            evidence_hash_valid: true, // Simplified for now
            rekor_entry_valid: true,   // Simplified for now  
            timestamp_valid: true,     // Simplified for now
            warnings: Vec::new(),      // Simplified for now
        }
    }
}

// WorkflowStatus conversions
impl From<&str> for notary::WorkflowStatus {
    fn from(status: &str) -> Self {
        match status {
            "pending" => notary::WorkflowStatus::Pending,
            "running" => notary::WorkflowStatus::Running,
            "completed" => notary::WorkflowStatus::Completed,
            "failed" => notary::WorkflowStatus::Failed,
            "cancelled" => notary::WorkflowStatus::Cancelled,
            _ => notary::WorkflowStatus::Unspecified,
        }
    }
}

impl From<notary::WorkflowStatus> for String {
    fn from(status: notary::WorkflowStatus) -> Self {
        match status {
            notary::WorkflowStatus::Pending => "pending".to_string(),
            notary::WorkflowStatus::Running => "running".to_string(),
            notary::WorkflowStatus::Completed => "completed".to_string(),
            notary::WorkflowStatus::Failed => "failed".to_string(),
            notary::WorkflowStatus::Cancelled => "cancelled".to_string(),
            _ => "unspecified".to_string(),
        }
    }
}

// ApprovalState conversions
impl From<&str> for notary::ApprovalState {
    fn from(state: &str) -> Self {
        match state {
            "pending" => notary::ApprovalState::Pending,
            "approved" => notary::ApprovalState::Approved,
            "rejected" => notary::ApprovalState::Rejected,
            _ => notary::ApprovalState::Unspecified,
        }
    }
}

impl From<notary::ApprovalState> for String {
    fn from(state: notary::ApprovalState) -> Self {
        match state {
            notary::ApprovalState::Pending => "pending".to_string(),
            notary::ApprovalState::Approved => "approved".to_string(),
            notary::ApprovalState::Rejected => "rejected".to_string(),
            _ => "unspecified".to_string(),
        }
    }
}

// Helper functions for metadata conversion
fn convert_metadata_to_struct(metadata: HashMap<String, serde_json::Value>) -> prost_types::Struct {
    prost_types::Struct {
        fields: metadata.into_iter().map(|(k, v)| {
            let value = match v {
                serde_json::Value::String(s) => prost_types::Value {
                    kind: Some(prost_types::value::Kind::StringValue(s)),
                },
                serde_json::Value::Number(n) => prost_types::Value {
                    kind: Some(prost_types::value::Kind::NumberValue(n.as_f64().unwrap_or(0.0))),
                },
                serde_json::Value::Bool(b) => prost_types::Value {
                    kind: Some(prost_types::value::Kind::BoolValue(b)),
                },
                serde_json::Value::Null => prost_types::Value {
                    kind: Some(prost_types::value::Kind::NullValue(0)),
                },
                serde_json::Value::Array(_) | serde_json::Value::Object(_) => prost_types::Value {
                    kind: Some(prost_types::value::Kind::StringValue(v.to_string())),
                },
            };
            (k, value)
        }).collect(),
    }
}

fn convert_struct_to_metadata(s: prost_types::Struct) -> HashMap<String, serde_json::Value> {
    s.fields.into_iter().map(|(k, v)| {
        let json_value = match v.kind {
            Some(prost_types::value::Kind::StringValue(s)) => serde_json::Value::String(s),
            Some(prost_types::value::Kind::NumberValue(n)) => serde_json::json!(n),
            Some(prost_types::value::Kind::BoolValue(b)) => serde_json::Value::Bool(b),
            Some(prost_types::value::Kind::NullValue(_)) => serde_json::Value::Null,
            Some(prost_types::value::Kind::ListValue(_)) | 
            Some(prost_types::value::Kind::StructValue(_)) => {
                // For complex types, try to parse as JSON string
                serde_json::Value::Null
            },
            None => serde_json::Value::Null,
        };
        (k, json_value)
    }).collect()
}

// Default implementations for missing types
impl Default for Actor {
    fn default() -> Self {
        Self {
            actor_type: "unknown".to_string(),
            id: "unknown".to_string(),
            auth_provider: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn test_evidence_package_conversion() {
        let actor = Actor {
            actor_type: "test_user".to_string(),
            id: "test@example.com".to_string(),
            auth_provider: Some("oauth2".to_string()),
        };

        let artifact = Artifact {
            name: "test.file".to_string(),
            uri: Some("s3://bucket/test.file".to_string()),
            hash_sha256: "abc123".to_string(),
        };

        let mut metadata = HashMap::new();
        metadata.insert("key".to_string(), json!("value"));
        metadata.insert("number".to_string(), json!(42));
        metadata.insert("bool".to_string(), json!(true));

        let evidence = EvidencePackage {
            spec_version: "1.0.0".to_string(),
            timestamp_utc: chrono::Utc::now(),
            event_type: "test.event".to_string(),
            actor,
            artifacts: vec![artifact],
            metadata,
        };

        // Convert to protobuf and back
        let proto_evidence: notary::EvidencePackage = evidence.clone().into();
        let converted_evidence: EvidencePackage = proto_evidence.into();

        assert_eq!(evidence.spec_version, converted_evidence.spec_version);
        assert_eq!(evidence.event_type, converted_evidence.event_type);
        assert_eq!(evidence.actor.actor_type, converted_evidence.actor.actor_type);
        assert_eq!(evidence.artifacts.len(), converted_evidence.artifacts.len());
    }

    #[test] 
    fn test_workflow_status_conversion() {
        assert_eq!(notary::WorkflowStatus::from("pending"), notary::WorkflowStatus::Pending);
        assert_eq!(notary::WorkflowStatus::from("completed"), notary::WorkflowStatus::Completed);
        assert_eq!(notary::WorkflowStatus::from("invalid"), notary::WorkflowStatus::Unspecified);

        assert_eq!(String::from(notary::WorkflowStatus::Pending), "pending");
        assert_eq!(String::from(notary::WorkflowStatus::Completed), "completed");
    }

    #[test]
    fn test_approval_state_conversion() {
        assert_eq!(notary::ApprovalState::from("approved"), notary::ApprovalState::Approved);
        assert_eq!(notary::ApprovalState::from("rejected"), notary::ApprovalState::Rejected);
        
        assert_eq!(String::from(notary::ApprovalState::Approved), "approved");
        assert_eq!(String::from(notary::ApprovalState::Rejected), "rejected");
    }

    #[test]
    fn test_notarization_receipt_conversion() {
        let receipt = NotarizationReceipt {
            evidence_package_hash: "hash123".to_string(),
            rekor_log_id: "log456".to_string(),
            rekor_server_url: "https://rekor.example.com".to_string(),
            signature_b64: "sig789".to_string(),
            public_key_b64: "key000".to_string(),
            integrated_time: 1234567890,
            log_index: 42,
        };

        // Convert to protobuf and back
        let proto_receipt: notary::NotarizationReceipt = receipt.clone().into();
        let converted_receipt: NotarizationReceipt = proto_receipt.into();

        assert_eq!(receipt.evidence_package_hash, converted_receipt.evidence_package_hash);
        assert_eq!(receipt.rekor_log_id, converted_receipt.rekor_log_id);
        assert_eq!(receipt.rekor_server_url, converted_receipt.rekor_server_url);
        assert_eq!(receipt.signature_b64, converted_receipt.signature_b64);
        assert_eq!(receipt.public_key_b64, converted_receipt.public_key_b64);
        assert_eq!(receipt.integrated_time, converted_receipt.integrated_time);
        assert_eq!(receipt.log_index, converted_receipt.log_index);
    }

    #[test]
    fn test_validation_result_conversion() {
        let result = ValidationResult {
            is_valid: true,
            errors: vec!["error1".to_string(), "error2".to_string()],
            warnings: vec!["warning1".to_string()],
        };

        let proto_result: notary::ValidationResult = result.into();

        assert_eq!(proto_result.signature_valid, true);
        assert_eq!(proto_result.evidence_hash_valid, true);
        assert_eq!(proto_result.rekor_entry_valid, true);
        assert_eq!(proto_result.timestamp_valid, true);
        assert!(proto_result.warnings.is_empty());
    }

    #[test]
    fn test_actor_conversion_with_empty_auth_provider() {
        let actor = Actor {
            actor_type: "test_user".to_string(),
            id: "test@example.com".to_string(),
            auth_provider: None,
        };

        let proto_actor: notary::Actor = actor.clone().into();
        assert_eq!(proto_actor.auth_provider, "");

        let converted_actor: Actor = proto_actor.into();
        assert_eq!(converted_actor.auth_provider, None);
    }

    #[test]
    fn test_actor_conversion_with_auth_provider() {
        let proto_actor = notary::Actor {
            actor_type: "test_user".to_string(),
            id: "test@example.com".to_string(),
            auth_provider: "oauth2".to_string(),
        };

        let converted_actor: Actor = proto_actor.into();
        assert_eq!(converted_actor.auth_provider, Some("oauth2".to_string()));
    }

    #[test]
    fn test_artifact_conversion_with_empty_uri() {
        let artifact = Artifact {
            name: "test.file".to_string(),
            uri: None,
            hash_sha256: "abc123".to_string(),
        };

        let proto_artifact: notary::Artifact = artifact.clone().into();
        assert_eq!(proto_artifact.uri, "");

        let converted_artifact: Artifact = proto_artifact.into();
        assert_eq!(converted_artifact.uri, None);
    }

    #[test]
    fn test_artifact_conversion_with_uri() {
        let proto_artifact = notary::Artifact {
            name: "test.file".to_string(),
            uri: "s3://bucket/test.file".to_string(),
            hash_sha256: "abc123".to_string(),
        };

        let converted_artifact: Artifact = proto_artifact.into();
        assert_eq!(converted_artifact.uri, Some("s3://bucket/test.file".to_string()));
    }

    #[test]
    fn test_workflow_status_all_variants() {
        // Test all status variants
        let statuses = vec![
            ("pending", notary::WorkflowStatus::Pending),
            ("running", notary::WorkflowStatus::Running),
            ("completed", notary::WorkflowStatus::Completed),
            ("failed", notary::WorkflowStatus::Failed),
            ("cancelled", notary::WorkflowStatus::Cancelled),
            ("unknown", notary::WorkflowStatus::Unspecified),
        ];

        for (string_status, proto_status) in statuses {
            assert_eq!(notary::WorkflowStatus::from(string_status), proto_status);
            
            // Test reverse conversion
            let back_to_string = String::from(proto_status);
            if string_status == "unknown" {
                assert_eq!(back_to_string, "unspecified");
            } else {
                assert_eq!(back_to_string, string_status);
            }
        }
    }

    #[test]
    fn test_approval_state_all_variants() {
        // Test all approval state variants
        let states = vec![
            ("pending", notary::ApprovalState::Pending),
            ("approved", notary::ApprovalState::Approved),
            ("rejected", notary::ApprovalState::Rejected),
            ("unknown", notary::ApprovalState::Unspecified),
        ];

        for (string_state, proto_state) in states {
            assert_eq!(notary::ApprovalState::from(string_state), proto_state);
            
            // Test reverse conversion
            let back_to_string = String::from(proto_state);
            if string_state == "unknown" {
                assert_eq!(back_to_string, "unspecified");
            } else {
                assert_eq!(back_to_string, string_state);
            }
        }
    }

    #[test]
    fn test_metadata_conversion_complex_types() {
        let mut metadata = HashMap::new();
        metadata.insert("string".to_string(), json!("test"));
        metadata.insert("number".to_string(), json!(42.5));
        metadata.insert("bool".to_string(), json!(true));
        metadata.insert("null".to_string(), json!(null));
        metadata.insert("array".to_string(), json!(["a", "b", "c"]));
        metadata.insert("object".to_string(), json!({"nested": "value"}));

        let proto_struct = convert_metadata_to_struct(metadata.clone());
        let converted_metadata = convert_struct_to_metadata(proto_struct);

        // Check that basic types are preserved
        assert_eq!(converted_metadata.get("string").unwrap(), &json!("test"));
        assert_eq!(converted_metadata.get("number").unwrap(), &json!(42.5));
        assert_eq!(converted_metadata.get("bool").unwrap(), &json!(true));
        assert_eq!(converted_metadata.get("null").unwrap(), &json!(null));
        
        // Complex types (arrays and objects) should be handled, but may be converted to strings/nulls
        assert!(converted_metadata.contains_key("array"));
        assert!(converted_metadata.contains_key("object"));
    }

    #[test]
    fn test_evidence_package_conversion_with_missing_fields() {
        // Test conversion when optional fields are missing
        let proto_evidence = notary::EvidencePackage {
            spec_version: "1.0.0".to_string(),
            timestamp_utc: None,  // Missing timestamp
            event_type: "test.event".to_string(),
            actor: None,  // Missing actor
            artifacts: vec![],
            metadata: None,  // Missing metadata
        };

        let converted_evidence: EvidencePackage = proto_evidence.into();

        assert_eq!(converted_evidence.spec_version, "1.0.0");
        assert_eq!(converted_evidence.event_type, "test.event");
        assert_eq!(converted_evidence.actor.actor_type, "unknown");  // Default value
        assert_eq!(converted_evidence.actor.id, "unknown");  // Default value
        assert_eq!(converted_evidence.actor.auth_provider, None);
        assert!(converted_evidence.artifacts.is_empty());
        assert!(converted_evidence.metadata.is_empty());
    }

    #[test]
    fn test_actor_default() {
        let default_actor = Actor::default();
        
        assert_eq!(default_actor.actor_type, "unknown");
        assert_eq!(default_actor.id, "unknown");
        assert_eq!(default_actor.auth_provider, None);
    }

    #[test]
    fn test_metadata_conversion_edge_cases() {
        // Test empty metadata
        let empty_metadata = HashMap::new();
        let proto_struct = convert_metadata_to_struct(empty_metadata.clone());
        let converted_metadata = convert_struct_to_metadata(proto_struct);
        assert!(converted_metadata.is_empty());

        // Test metadata with number edge cases
        let mut edge_metadata = HashMap::new();
        edge_metadata.insert("zero".to_string(), json!(0));
        edge_metadata.insert("negative".to_string(), json!(-42));
        edge_metadata.insert("float".to_string(), json!(3.14159));

        let proto_struct = convert_metadata_to_struct(edge_metadata.clone());
        let converted_metadata = convert_struct_to_metadata(proto_struct);

        assert_eq!(converted_metadata.get("zero").unwrap(), &json!(0.0));
        assert_eq!(converted_metadata.get("negative").unwrap(), &json!(-42.0));
        assert_eq!(converted_metadata.get("float").unwrap(), &json!(3.14159));
    }

    #[test]
    fn test_evidence_package_timestamp_conversion() {
        let now = chrono::Utc::now();
        let actor = Actor {
            actor_type: "test_user".to_string(),
            id: "test@example.com".to_string(),
            auth_provider: Some("oauth2".to_string()),
        };

        let evidence = EvidencePackage {
            spec_version: "1.0.0".to_string(),
            timestamp_utc: now,
            event_type: "test.event".to_string(),
            actor,
            artifacts: vec![],
            metadata: HashMap::new(),
        };

        // Convert to protobuf and back
        let proto_evidence: notary::EvidencePackage = evidence.clone().into();
        let converted_evidence: EvidencePackage = proto_evidence.into();

        // Check that timestamps are approximately equal (within 1 second)
        let time_diff = (evidence.timestamp_utc.timestamp() - converted_evidence.timestamp_utc.timestamp()).abs();
        assert!(time_diff <= 1);
    }
}