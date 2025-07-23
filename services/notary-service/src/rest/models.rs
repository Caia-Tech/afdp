//! REST API models with OpenAPI documentation

use crate::evidence::{Actor, Artifact, EvidencePackage};
use crate::notary::NotarizationReceipt;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use utoipa::ToSchema;

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct SignEvidenceRequest {
    /// Evidence package to be notarized
    pub evidence_package: EvidencePackageDto,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct SignEvidenceResponse {
    /// Workflow ID for tracking the signing process
    pub workflow_id: String,
    /// Notarization receipt (if completed synchronously)
    pub receipt: Option<NotarizationReceiptDto>,
    /// Current status of the signing process
    pub status: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct SignEvidenceWithApprovalRequest {
    /// Evidence package to be notarized
    pub evidence_package: EvidencePackageDto,
    /// List of required approvers
    pub approvers: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct SignEvidenceWithApprovalResponse {
    /// Workflow ID for tracking the approval process
    pub workflow_id: String,
    /// Current status of the approval process
    pub status: String,
    /// Status of each required approval
    pub approval_statuses: Vec<ApprovalStatusDto>,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct BatchSignRequest {
    /// Multiple evidence packages to be notarized in a batch
    pub evidence_packages: Vec<EvidencePackageDto>,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct BatchSignResponse {
    /// Batch workflow ID for tracking the entire batch
    pub batch_workflow_id: String,
    /// Individual results for each evidence package
    pub results: Vec<SignEvidenceResponse>,
    /// Overall batch status
    pub status: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct WorkflowStatusResponse {
    /// Workflow ID
    pub workflow_id: String,
    /// Current workflow status
    pub status: String,
    /// When the workflow was created
    pub created_at: DateTime<Utc>,
    /// When the workflow completed (if applicable)
    pub completed_at: Option<DateTime<Utc>>,
    /// Error message (if failed)
    pub error_message: Option<String>,
    /// Workflow result data
    pub result: Option<serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct ValidateEvidenceRequest {
    /// Evidence package to validate
    pub evidence_package: EvidencePackageDto,
    /// Signature to validate against
    pub signature: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct ValidateEvidenceResponse {
    /// Whether the evidence package is valid
    pub is_valid: bool,
    /// Validation error message (if invalid)
    pub validation_error: Option<String>,
    /// Detailed validation results
    pub validation_result: ValidationResultDto,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct ListWorkflowsResponse {
    /// List of workflow summaries
    pub workflows: Vec<WorkflowSummaryDto>,
    /// Token for the next page of results
    pub next_page_token: Option<String>,
    /// Total number of workflows matching the criteria
    pub total_count: i32,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct EvidencePackageDto {
    /// Evidence package specification version
    pub spec_version: String,
    /// UTC timestamp when the evidence was created
    pub timestamp_utc: DateTime<Utc>,
    /// Type of event being notarized
    pub event_type: String,
    /// Actor who initiated the event
    pub actor: ActorDto,
    /// Artifacts associated with the event
    pub artifacts: Vec<ArtifactDto>,
    /// Additional metadata about the event
    pub metadata: HashMap<String, serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct ActorDto {
    /// Type of actor (user, service, system, etc.)
    pub actor_type: String,
    /// Unique identifier for the actor
    pub id: String,
    /// Authentication provider used (optional)
    pub auth_provider: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct ArtifactDto {
    /// Human-readable name of the artifact
    pub name: String,
    /// URI where the artifact can be accessed (optional)
    pub uri: Option<String>,
    /// SHA256 hash of the artifact
    pub hash_sha256: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct NotarizationReceiptDto {
    /// Hash of the evidence package that was signed
    pub evidence_package_hash: String,
    /// Rekor transparency log entry ID
    pub rekor_log_id: String,
    /// The URL of the Rekor server where this was logged
    pub rekor_server_url: String,
    /// The base64-encoded signature from the Notary Service
    pub signature_b64: String,
    /// The base64-encoded public key used for signing
    pub public_key_b64: String,
    /// Integration timestamp from Rekor
    pub integrated_time: i64,
    /// Log index in Rekor
    pub log_index: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct ApprovalStatusDto {
    /// Email or ID of the approver
    pub approver: String,
    /// Current approval status (pending, approved, rejected)
    pub status: String,
    /// Timestamp of the approval action
    pub timestamp: DateTime<Utc>,
    /// Optional comment from the approver
    pub comment: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct ValidationResultDto {
    /// Whether the cryptographic signature is valid
    pub signature_valid: bool,
    /// Whether the evidence package hash is valid
    pub evidence_hash_valid: bool,
    /// Whether the Rekor transparency log entry is valid
    pub rekor_entry_valid: bool,
    /// Whether the timestamp is valid
    pub timestamp_valid: bool,
    /// Any validation warnings
    pub warnings: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct WorkflowSummaryDto {
    /// Workflow ID
    pub workflow_id: String,
    /// Type of workflow
    pub workflow_type: String,
    /// Current workflow status
    pub status: String,
    /// When the workflow was created
    pub created_at: DateTime<Utc>,
    /// When the workflow completed (if applicable)
    pub completed_at: Option<DateTime<Utc>>,
    /// Type of event being processed
    pub event_type: String,
    /// ID of the actor who initiated the workflow
    pub actor_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct ErrorResponse {
    /// HTTP status code
    pub status: u16,
    /// Error message
    pub message: String,
    /// Error details (optional)
    pub details: Option<serde_json::Value>,
    /// Request ID for tracking
    pub request_id: String,
}

// Type conversions
impl From<EvidencePackage> for EvidencePackageDto {
    fn from(evidence: EvidencePackage) -> Self {
        Self {
            spec_version: evidence.spec_version,
            timestamp_utc: evidence.timestamp_utc,
            event_type: evidence.event_type,
            actor: evidence.actor.into(),
            artifacts: evidence.artifacts.into_iter().map(Into::into).collect(),
            metadata: evidence.metadata,
        }
    }
}

impl From<EvidencePackageDto> for EvidencePackage {
    fn from(dto: EvidencePackageDto) -> Self {
        Self {
            spec_version: dto.spec_version,
            timestamp_utc: dto.timestamp_utc,
            event_type: dto.event_type,
            actor: dto.actor.into(),
            artifacts: dto.artifacts.into_iter().map(Into::into).collect(),
            metadata: dto.metadata,
        }
    }
}

impl From<Actor> for ActorDto {
    fn from(actor: Actor) -> Self {
        Self {
            actor_type: actor.actor_type,
            id: actor.id,
            auth_provider: actor.auth_provider,
        }
    }
}

impl From<ActorDto> for Actor {
    fn from(dto: ActorDto) -> Self {
        Self {
            actor_type: dto.actor_type,
            id: dto.id,
            auth_provider: dto.auth_provider,
        }
    }
}

impl From<Artifact> for ArtifactDto {
    fn from(artifact: Artifact) -> Self {
        Self {
            name: artifact.name,
            uri: artifact.uri,
            hash_sha256: artifact.hash_sha256,
        }
    }
}

impl From<ArtifactDto> for Artifact {
    fn from(dto: ArtifactDto) -> Self {
        Self {
            name: dto.name,
            uri: dto.uri,
            hash_sha256: dto.hash_sha256,
        }
    }
}

impl From<NotarizationReceipt> for NotarizationReceiptDto {
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

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use serde_json::json;

    fn test_evidence_package() -> EvidencePackage {
        let actor = Actor {
            actor_type: "test_user".to_string(),
            id: "test@example.com".to_string(),
            auth_provider: Some("test_auth".to_string()),
        };

        EvidencePackage::new("test.event".to_string(), actor)
            .add_artifact(Artifact {
                name: "test.file".to_string(),
                uri: Some("s3://bucket/test.file".to_string()),
                hash_sha256: "abc123".to_string(),
            })
            .add_metadata("key".to_string(), json!("value"))
    }

    fn test_notarization_receipt() -> NotarizationReceipt {
        NotarizationReceipt {
            evidence_package_hash: "hash123".to_string(),
            rekor_log_id: "uuid-123".to_string(),
            rekor_server_url: "https://rekor.sigstore.dev".to_string(),
            signature_b64: "sig123".to_string(),
            public_key_b64: "key123".to_string(),
            integrated_time: 1234567890,
            log_index: 100,
        }
    }

    #[test]
    fn test_sign_evidence_request_serialization() {
        let evidence = test_evidence_package();
        let request = SignEvidenceRequest {
            evidence_package: evidence.into(),
        };

        let json = serde_json::to_string(&request).unwrap();
        assert!(json.contains("evidence_package"));
        assert!(json.contains("test.event"));
    }

    #[test]
    fn test_sign_evidence_response_serialization() {
        let receipt = test_notarization_receipt();
        let response = SignEvidenceResponse {
            workflow_id: "wf-123".to_string(),
            receipt: Some(receipt.into()),
            status: "completed".to_string(),
        };

        let json = serde_json::to_string(&response).unwrap();
        assert!(json.contains("\"workflow_id\":\"wf-123\""));
        assert!(json.contains("\"status\":\"completed\""));
        assert!(json.contains("receipt"));
    }

    #[test]
    fn test_evidence_package_dto_conversion() {
        let original = test_evidence_package();
        let dto: EvidencePackageDto = original.clone().into();
        let converted: EvidencePackage = dto.into();

        assert_eq!(original.spec_version, converted.spec_version);
        assert_eq!(original.event_type, converted.event_type);
        assert_eq!(original.actor.actor_type, converted.actor.actor_type);
        assert_eq!(original.artifacts.len(), converted.artifacts.len());
        assert_eq!(original.metadata.len(), converted.metadata.len());
    }

    #[test]
    fn test_actor_dto_conversion() {
        let original = Actor {
            actor_type: "human_user".to_string(),
            id: "user@example.com".to_string(),
            auth_provider: Some("oauth2".to_string()),
        };

        let dto: ActorDto = original.clone().into();
        let converted: Actor = dto.into();

        assert_eq!(original.actor_type, converted.actor_type);
        assert_eq!(original.id, converted.id);
        assert_eq!(original.auth_provider, converted.auth_provider);
    }

    #[test]
    fn test_notarization_receipt_dto_conversion() {
        let original = test_notarization_receipt();
        let dto: NotarizationReceiptDto = original.clone().into();

        assert_eq!(original.evidence_package_hash, dto.evidence_package_hash);
        assert_eq!(original.rekor_log_id, dto.rekor_log_id);
        assert_eq!(original.signature_b64, dto.signature_b64);
        assert_eq!(original.integrated_time, dto.integrated_time);
    }

    #[test]
    fn test_error_response_serialization() {
        let error = ErrorResponse {
            status: 400,
            message: "Bad Request".to_string(),
            details: Some(json!({"field": "evidence_package"})),
            request_id: "req-123".to_string(),
        };

        let json = serde_json::to_string(&error).unwrap();
        assert!(json.contains("\"status\":400"));
        assert!(json.contains("\"message\":\"Bad Request\""));
        assert!(json.contains("\"request_id\":\"req-123\""));
    }
}