//! Simplified Temporal workflows for AFDP operations
//! This provides the interface structure that would be used with real Temporal

use crate::{
    evidence::EvidencePackage,
    notary::NotarizationReceipt,
    temporal::activities::{ValidationResult, AuditLogEntry},
};
use serde::{Deserialize, Serialize};
use tracing::info;

/// High-level interface for AFDP workflows
pub struct AFDPWorkflows;

impl AFDPWorkflows {
    /// Start a simple signing workflow
    pub async fn start_simple_signing(
        evidence_package: EvidencePackage,
    ) -> crate::Result<String> {
        let workflow_id = format!("simple-signing-{}", uuid::Uuid::new_v4());
        
        info!(
            workflow_id = %workflow_id,
            event_type = %evidence_package.event_type,
            "Starting simple signing workflow (mock implementation)"
        );

        Ok(workflow_id)
    }

    /// Start an approval-based signing workflow
    pub async fn start_approval_signing(
        evidence_package: EvidencePackage,
        approvers: Vec<String>,
    ) -> crate::Result<String> {
        let workflow_id = format!("approval-signing-{}", uuid::Uuid::new_v4());
        
        info!(
            workflow_id = %workflow_id,
            event_type = %evidence_package.event_type,
            approvers = ?approvers,
            "Starting approval signing workflow (mock implementation)"
        );

        Ok(workflow_id)
    }

    /// Start a batch signing workflow
    pub async fn start_batch_signing(
        evidence_packages: Vec<EvidencePackage>,
    ) -> crate::Result<String> {
        let workflow_id = format!("batch-signing-{}", uuid::Uuid::new_v4());
        
        info!(
            workflow_id = %workflow_id,
            package_count = evidence_packages.len(),
            "Starting batch signing workflow (mock implementation)"
        );

        Ok(workflow_id)
    }
}

/// Simple signing workflow result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SimpleSigningResult {
    pub receipt: NotarizationReceipt,
    pub validation_result: ValidationResult,
    pub audit_log_id: String,
}

/// Approval signing workflow result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApprovalSigningResult {
    pub receipt: NotarizationReceipt,
    pub approvals: Vec<Approval>,
    pub audit_log_id: String,
}

/// Approval record
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Approval {
    pub approver: String,
    pub approved_at: chrono::DateTime<chrono::Utc>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub comments: Option<String>,
}

/// Batch signing workflow result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BatchSigningResult {
    pub successful_receipts: Vec<NotarizationReceipt>,
    pub failed_packages: Vec<BatchFailure>,
    pub audit_log_id: String,
}

/// Batch processing failure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BatchFailure {
    pub evidence_package: EvidencePackage,
    pub error: String,
}

/// Execute a simple signing workflow synchronously (for development/testing)
pub async fn execute_simple_signing_workflow(
    evidence_package: EvidencePackage,
) -> crate::Result<SimpleSigningResult> {
    info!(
        event_type = %evidence_package.event_type,
        "Executing simple signing workflow"
    );

    // Step 1: Validate evidence package
    let validation_result = crate::temporal::activities::validate_evidence_activity(
        evidence_package.clone()
    ).await?;

    if !validation_result.is_valid {
        return Err(crate::error::NotaryError::ValidationError(
            format!("Validation failed: {:?}", validation_result.errors)
        ));
    }

    // Step 2: Notarize evidence package
    let notarize_input = crate::temporal::activities::NotarizeEvidenceInput {
        evidence_package: evidence_package.clone(),
        options: Some(crate::temporal::activities::NotarizeOptions::default()),
    };

    let receipt = crate::temporal::activities::notarize_evidence_activity(notarize_input).await?;

    // Step 3: Create audit log entry
    let audit_entry = AuditLogEntry {
        event_type: "evidence.notarized".to_string(),
        actor: evidence_package.actor.id.clone(),
        timestamp: chrono::Utc::now(),
        evidence_package_id: Some(receipt.evidence_package_hash.clone()),
        receipt_id: Some(receipt.rekor_log_id.clone()),
        context: std::collections::HashMap::new(),
    };

    let audit_log_id = crate::temporal::activities::create_audit_log_activity(audit_entry).await?;

    info!(
        rekor_log_id = %receipt.rekor_log_id,
        audit_log_id = %audit_log_id,
        "Simple signing workflow completed"
    );

    Ok(SimpleSigningResult {
        receipt,
        validation_result,
        audit_log_id,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Actor, Artifact};
    use serde_json::json;

    fn create_test_evidence_package() -> EvidencePackage {
        let actor = Actor {
            actor_type: "test_user".to_string(),
            id: "test@example.com".to_string(),
            auth_provider: Some("test_auth".to_string()),
        };

        EvidencePackage::new("test.workflow.event".to_string(), actor)
            .add_artifact(Artifact {
                name: "test.file".to_string(),
                uri: Some("s3://bucket/test.file".to_string()),
                hash_sha256: "abc123".to_string(),
            })
            .add_metadata("workflow_test".to_string(), json!("value"))
    }

    #[tokio::test]
    async fn test_start_simple_signing_workflow() {
        let evidence = create_test_evidence_package();
        
        let result = AFDPWorkflows::start_simple_signing(evidence).await;
        
        assert!(result.is_ok());
        let workflow_id = result.unwrap();
        assert!(workflow_id.starts_with("simple-signing-"));
        assert!(workflow_id.contains("-")); // UUID format
    }

    #[tokio::test]
    async fn test_start_approval_signing_workflow() {
        let evidence = create_test_evidence_package();
        let approvers = vec!["approver1@example.com".to_string(), "approver2@example.com".to_string()];
        
        let result = AFDPWorkflows::start_approval_signing(evidence, approvers).await;
        
        assert!(result.is_ok());
        let workflow_id = result.unwrap();
        assert!(workflow_id.starts_with("approval-signing-"));
        assert!(workflow_id.contains("-")); // UUID format
    }

    #[tokio::test]
    async fn test_start_batch_signing_workflow() {
        let evidence1 = create_test_evidence_package();
        let evidence2 = create_test_evidence_package();
        let evidence_packages = vec![evidence1, evidence2];
        
        let result = AFDPWorkflows::start_batch_signing(evidence_packages).await;
        
        assert!(result.is_ok());
        let workflow_id = result.unwrap();
        assert!(workflow_id.starts_with("batch-signing-"));
        assert!(workflow_id.contains("-")); // UUID format
    }

    #[tokio::test]
    async fn test_start_simple_signing_with_different_event_types() {
        let event_types = vec![
            "ai.model.deployment",
            "security.scan.completed", 
            "code.review.approved",
            "artifact.published"
        ];

        for event_type in event_types {
            let actor = Actor {
                actor_type: "ci_system".to_string(),
                id: "github-actions".to_string(),
                auth_provider: Some("github".to_string()),
            };

            let evidence = EvidencePackage::new(event_type.to_string(), actor);
            let result = AFDPWorkflows::start_simple_signing(evidence).await;
            
            assert!(result.is_ok(), "Failed for event type: {}", event_type);
            let workflow_id = result.unwrap();
            assert!(workflow_id.starts_with("simple-signing-"));
        }
    }

    #[tokio::test]
    async fn test_start_approval_signing_with_empty_approvers() {
        let evidence = create_test_evidence_package();
        let approvers = vec![];
        
        let result = AFDPWorkflows::start_approval_signing(evidence, approvers).await;
        
        assert!(result.is_ok());
        let workflow_id = result.unwrap();
        assert!(workflow_id.starts_with("approval-signing-"));
    }

    #[tokio::test]
    async fn test_start_approval_signing_with_many_approvers() {
        let evidence = create_test_evidence_package();
        let approvers = (1..=10)
            .map(|i| format!("approver{}@example.com", i))
            .collect();
        
        let result = AFDPWorkflows::start_approval_signing(evidence, approvers).await;
        
        assert!(result.is_ok());
        let workflow_id = result.unwrap();
        assert!(workflow_id.starts_with("approval-signing-"));
    }

    #[tokio::test]
    async fn test_start_batch_signing_with_empty_packages() {
        let evidence_packages = vec![];
        
        let result = AFDPWorkflows::start_batch_signing(evidence_packages).await;
        
        assert!(result.is_ok());
        let workflow_id = result.unwrap();
        assert!(workflow_id.starts_with("batch-signing-"));
    }

    #[tokio::test]
    async fn test_start_batch_signing_with_large_batch() {
        let evidence_packages: Vec<EvidencePackage> = (0..50)
            .map(|i| {
                let actor = Actor {
                    actor_type: "batch_processor".to_string(),
                    id: format!("processor-{}", i),
                    auth_provider: None,
                };
                EvidencePackage::new(format!("batch.item.{}", i), actor)
            })
            .collect();
        
        let result = AFDPWorkflows::start_batch_signing(evidence_packages).await;
        
        assert!(result.is_ok());
        let workflow_id = result.unwrap();
        assert!(workflow_id.starts_with("batch-signing-"));
    }

    #[test]
    fn test_simple_signing_result_serialization() {
        let receipt = NotarizationReceipt {
            evidence_package_hash: "hash123".to_string(),
            rekor_log_id: "uuid-123".to_string(),
            rekor_server_url: "https://rekor.sigstore.dev".to_string(),
            signature_b64: "sig123".to_string(),
            public_key_b64: "key123".to_string(),
            integrated_time: 1234567890,
            log_index: 100,
        };

        let validation_result = ValidationResult {
            is_valid: true,
            errors: vec![],
            warnings: vec![],
        };

        let result = SimpleSigningResult {
            receipt,
            validation_result,
            audit_log_id: "audit-123".to_string(),
        };

        let json = serde_json::to_string(&result).unwrap();
        assert!(json.contains("\"receipt\""));
        assert!(json.contains("\"validation_result\""));
        assert!(json.contains("\"audit_log_id\":\"audit-123\""));

        let parsed: SimpleSigningResult = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.audit_log_id, "audit-123");
    }

    #[test]
    fn test_approval_signing_result_serialization() {
        let receipt = NotarizationReceipt {
            evidence_package_hash: "hash123".to_string(),
            rekor_log_id: "uuid-123".to_string(),
            rekor_server_url: "https://rekor.sigstore.dev".to_string(),
            signature_b64: "sig123".to_string(),
            public_key_b64: "key123".to_string(),
            integrated_time: 1234567890,
            log_index: 100,
        };

        let approval = Approval {
            approver: "approver@example.com".to_string(),
            approved_at: chrono::Utc::now(),
            comments: Some("Looks good to me".to_string()),
        };

        let result = ApprovalSigningResult {
            receipt,
            approvals: vec![approval],
            audit_log_id: "audit-456".to_string(),
        };

        let json = serde_json::to_string(&result).unwrap();
        assert!(json.contains("\"receipt\""));
        assert!(json.contains("\"approvals\""));
        assert!(json.contains("\"audit_log_id\":\"audit-456\""));

        let parsed: ApprovalSigningResult = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.approvals.len(), 1);
        assert_eq!(parsed.approvals[0].approver, "approver@example.com");
    }

    #[test]
    fn test_batch_signing_result_serialization() {
        let receipt = NotarizationReceipt {
            evidence_package_hash: "hash123".to_string(),
            rekor_log_id: "uuid-123".to_string(),
            rekor_server_url: "https://rekor.sigstore.dev".to_string(),
            signature_b64: "sig123".to_string(),
            public_key_b64: "key123".to_string(),
            integrated_time: 1234567890,
            log_index: 100,
        };

        let evidence = create_test_evidence_package();
        let failure = BatchFailure {
            evidence_package: evidence,
            error: "Validation failed".to_string(),
        };

        let result = BatchSigningResult {
            successful_receipts: vec![receipt],
            failed_packages: vec![failure],
            audit_log_id: "audit-789".to_string(),
        };

        let json = serde_json::to_string(&result).unwrap();
        assert!(json.contains("\"successful_receipts\""));
        assert!(json.contains("\"failed_packages\""));
        assert!(json.contains("\"audit_log_id\":\"audit-789\""));

        let parsed: BatchSigningResult = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.successful_receipts.len(), 1);
        assert_eq!(parsed.failed_packages.len(), 1);
        assert_eq!(parsed.failed_packages[0].error, "Validation failed");
    }

    #[test]
    fn test_approval_structure() {
        let now = chrono::Utc::now();
        let approval = Approval {
            approver: "security-team@company.com".to_string(),
            approved_at: now,
            comments: Some("Security review passed".to_string()),
        };

        assert_eq!(approval.approver, "security-team@company.com");
        assert_eq!(approval.approved_at, now);
        assert_eq!(approval.comments, Some("Security review passed".to_string()));

        let json = serde_json::to_string(&approval).unwrap();
        let parsed: Approval = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.approver, approval.approver);
        assert_eq!(parsed.comments, approval.comments);
    }

    #[test]
    fn test_approval_without_comments() {
        let approval = Approval {
            approver: "quick-approver@company.com".to_string(),
            approved_at: chrono::Utc::now(),
            comments: None,
        };

        let json = serde_json::to_string(&approval).unwrap();
        assert!(json.contains("\"approver\""));
        assert!(json.contains("\"approved_at\""));
        assert!(!json.contains("\"comments\""));

        let parsed: Approval = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.approver, "quick-approver@company.com");
        assert_eq!(parsed.comments, None);
    }

    #[test]
    fn test_batch_failure_structure() {
        let evidence = create_test_evidence_package();
        let failure = BatchFailure {
            evidence_package: evidence.clone(),
            error: "Signature verification failed".to_string(),
        };

        assert_eq!(failure.evidence_package.event_type, evidence.event_type);
        assert_eq!(failure.error, "Signature verification failed");

        let json = serde_json::to_string(&failure).unwrap();
        let parsed: BatchFailure = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.evidence_package.event_type, evidence.event_type);
        assert_eq!(parsed.error, "Signature verification failed");
    }

    #[test]
    fn test_workflow_result_structures_clone() {
        let receipt = NotarizationReceipt {
            evidence_package_hash: "hash123".to_string(),
            rekor_log_id: "uuid-123".to_string(),
            rekor_server_url: "https://rekor.sigstore.dev".to_string(),
            signature_b64: "sig123".to_string(),
            public_key_b64: "key123".to_string(),
            integrated_time: 1234567890,
            log_index: 100,
        };

        let validation_result = ValidationResult {
            is_valid: true,
            errors: vec![],
            warnings: vec![],
        };

        let original = SimpleSigningResult {
            receipt: receipt.clone(),
            validation_result: validation_result.clone(),
            audit_log_id: "audit-123".to_string(),
        };

        let cloned = original.clone();
        assert_eq!(original.audit_log_id, cloned.audit_log_id);
        assert_eq!(original.receipt.rekor_log_id, cloned.receipt.rekor_log_id);
        assert_eq!(original.validation_result.is_valid, cloned.validation_result.is_valid);
    }

    #[test]
    fn test_workflow_result_structures_debug() {
        let receipt = NotarizationReceipt {
            evidence_package_hash: "hash123".to_string(),
            rekor_log_id: "uuid-123".to_string(),
            rekor_server_url: "https://rekor.sigstore.dev".to_string(),
            signature_b64: "sig123".to_string(),
            public_key_b64: "key123".to_string(),
            integrated_time: 1234567890,
            log_index: 100,
        };

        let validation_result = ValidationResult {
            is_valid: true,
            errors: vec![],
            warnings: vec![],
        };

        let result = SimpleSigningResult {
            receipt,
            validation_result,
            audit_log_id: "audit-123".to_string(),
        };

        let debug_str = format!("{:?}", result);
        assert!(debug_str.contains("SimpleSigningResult"));
        assert!(debug_str.contains("audit_log_id"));
        assert!(debug_str.contains("receipt"));
        assert!(debug_str.contains("validation_result"));
    }

    #[tokio::test]
    async fn test_execute_simple_signing_workflow_success() {
        let evidence = create_test_evidence_package();
        
        let result = execute_simple_signing_workflow(evidence.clone()).await;
        
        assert!(result.is_ok());
        let signing_result = result.unwrap();
        
        // Check receipt
        assert!(signing_result.receipt.evidence_package_hash.starts_with("test-hash-"));
        assert!(signing_result.receipt.rekor_log_id.starts_with("test-rekor-"));
        assert_eq!(signing_result.receipt.rekor_server_url, "https://rekor.sigstore.dev");
        assert_eq!(signing_result.receipt.signature_b64, "test-signature-base64");
        assert_eq!(signing_result.receipt.public_key_b64, "test-public-key-base64");
        assert_eq!(signing_result.receipt.log_index, 12345);
        
        // Check validation result
        assert!(signing_result.validation_result.is_valid);
        assert!(signing_result.validation_result.errors.is_empty());
        
        // Check audit log ID
        assert!(!signing_result.audit_log_id.is_empty());
    }

    #[tokio::test]
    async fn test_execute_simple_signing_workflow_validation_failure() {
        let mut evidence = create_test_evidence_package();
        evidence.event_type = "".to_string(); // This will cause validation to fail
        
        let result = execute_simple_signing_workflow(evidence).await;
        
        assert!(result.is_err());
        if let Err(e) = result {
            match e {
                crate::error::NotaryError::ValidationError(msg) => {
                    assert!(msg.contains("Validation failed"));
                }
                _ => panic!("Expected ValidationError"),
            }
        }
    }

    #[tokio::test]
    async fn test_execute_simple_signing_workflow_with_artifacts() {
        let mut evidence = create_test_evidence_package();
        
        // Add multiple artifacts
        evidence = evidence.add_artifact(Artifact {
            name: "second.file".to_string(),
            uri: Some("s3://bucket/second.file".to_string()),
            hash_sha256: "def456".to_string(),
        });
        
        evidence = evidence.add_artifact(Artifact {
            name: "third.file".to_string(),
            uri: None,
            hash_sha256: "ghi789".to_string(),
        });
        
        let result = execute_simple_signing_workflow(evidence).await;
        
        assert!(result.is_ok());
        let signing_result = result.unwrap();
        assert!(signing_result.validation_result.is_valid);
        assert!(!signing_result.audit_log_id.is_empty());
    }

    #[tokio::test]
    async fn test_execute_simple_signing_workflow_with_metadata() {
        let mut evidence = create_test_evidence_package();
        
        // Add additional metadata
        evidence = evidence
            .add_metadata("deployment_id".to_string(), json!("deploy-123"))
            .add_metadata("environment".to_string(), json!("production"))
            .add_metadata("version".to_string(), json!("v1.2.3"));
        
        let result = execute_simple_signing_workflow(evidence).await;
        
        assert!(result.is_ok());
        let signing_result = result.unwrap();
        assert!(signing_result.validation_result.is_valid);
        assert!(!signing_result.audit_log_id.is_empty());
    }

    #[tokio::test]
    async fn test_execute_simple_signing_workflow_different_actors() {
        let actors = vec![
            Actor {
                actor_type: "ci_system".to_string(),
                id: "jenkins@company.com".to_string(),
                auth_provider: Some("ldap".to_string()),
            },
            Actor {
                actor_type: "human".to_string(),
                id: "developer@company.com".to_string(),
                auth_provider: Some("oauth2".to_string()),
            },
            Actor {
                actor_type: "automated_scanner".to_string(),
                id: "security-scanner".to_string(),
                auth_provider: None,
            },
        ];
        
        for actor in actors {
            let evidence = EvidencePackage::new("test.signing.workflow".to_string(), actor.clone());
            let result = execute_simple_signing_workflow(evidence).await;
            
            assert!(result.is_ok(), "Failed for actor: {:?}", actor);
            let signing_result = result.unwrap();
            assert!(signing_result.receipt.evidence_package_hash.starts_with("test-hash-"));
        }
    }

    #[tokio::test]
    async fn test_batch_signing_result_with_mixed_results() {
        let receipt1 = NotarizationReceipt {
            evidence_package_hash: "success-hash-1".to_string(),
            rekor_log_id: "success-uuid-1".to_string(),
            rekor_server_url: "https://rekor.sigstore.dev".to_string(),
            signature_b64: "sig1".to_string(),
            public_key_b64: "key1".to_string(),
            integrated_time: 1234567890,
            log_index: 100,
        };

        let receipt2 = NotarizationReceipt {
            evidence_package_hash: "success-hash-2".to_string(),
            rekor_log_id: "success-uuid-2".to_string(),
            rekor_server_url: "https://rekor.sigstore.dev".to_string(),
            signature_b64: "sig2".to_string(),
            public_key_b64: "key2".to_string(),
            integrated_time: 1234567891,
            log_index: 101,
        };

        let failed_evidence1 = create_test_evidence_package();
        let failed_evidence2 = create_test_evidence_package();

        let result = BatchSigningResult {
            successful_receipts: vec![receipt1, receipt2],
            failed_packages: vec![
                BatchFailure {
                    evidence_package: failed_evidence1,
                    error: "Network timeout".to_string(),
                },
                BatchFailure {
                    evidence_package: failed_evidence2,
                    error: "Invalid signature".to_string(),
                },
            ],
            audit_log_id: "batch-audit-123".to_string(),
        };

        assert_eq!(result.successful_receipts.len(), 2);
        assert_eq!(result.failed_packages.len(), 2);
        assert_eq!(result.failed_packages[0].error, "Network timeout");
        assert_eq!(result.failed_packages[1].error, "Invalid signature");
    }

    #[test]
    fn test_approval_signing_result_multiple_approvals() {
        let receipt = NotarizationReceipt {
            evidence_package_hash: "approved-hash".to_string(),
            rekor_log_id: "approved-uuid".to_string(),
            rekor_server_url: "https://rekor.sigstore.dev".to_string(),
            signature_b64: "approved-sig".to_string(),
            public_key_b64: "approved-key".to_string(),
            integrated_time: 1234567890,
            log_index: 100,
        };

        let approvals = vec![
            Approval {
                approver: "security-team@company.com".to_string(),
                approved_at: chrono::Utc::now() - chrono::Duration::hours(2),
                comments: Some("Security review passed".to_string()),
            },
            Approval {
                approver: "compliance@company.com".to_string(),
                approved_at: chrono::Utc::now() - chrono::Duration::hours(1),
                comments: Some("Compliance requirements met".to_string()),
            },
            Approval {
                approver: "manager@company.com".to_string(),
                approved_at: chrono::Utc::now(),
                comments: None, // No comments
            },
        ];

        let result = ApprovalSigningResult {
            receipt,
            approvals: approvals.clone(),
            audit_log_id: "approval-audit-456".to_string(),
        };

        assert_eq!(result.approvals.len(), 3);
        assert_eq!(result.approvals[0].approver, "security-team@company.com");
        assert!(result.approvals[0].comments.is_some());
        assert_eq!(result.approvals[2].approver, "manager@company.com");
        assert!(result.approvals[2].comments.is_none());
    }
}