//! Simplified Temporal client for AFDP Notary Service

use crate::{
    error::Result,
    evidence::EvidencePackage,
    notary::NotaryConfig,
    temporal::workflows::{
        SimpleSigningResult, ApprovalSigningResult, BatchSigningResult,
        AFDPWorkflows, execute_simple_signing_workflow,
    },
};
use serde::{Deserialize, Serialize};
use tracing::{info, warn};

/// Configuration for Temporal Notary Client
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TemporalNotaryConfig {
    /// Temporal server address
    pub temporal_address: String,
    /// Temporal namespace
    pub namespace: String,
    /// Task queue name
    pub task_queue: String,
    /// Notary service configuration
    pub notary_config: NotaryConfig,
    /// Default workflow timeout
    pub default_timeout_seconds: u64,
}

impl Default for TemporalNotaryConfig {
    fn default() -> Self {
        Self {
            temporal_address: "http://localhost:7233".to_string(),
            namespace: "default".to_string(),
            task_queue: "afdp-notary".to_string(),
            notary_config: NotaryConfig {
                vault_config: crate::vault::VaultConfig {
                    address: "http://localhost:8200".to_string(),
                    token: "root".to_string(),
                    transit_key_name: "afdp-notary-key".to_string(),
                },
                rekor_config: crate::rekor::RekorConfig::default(),
            },
            default_timeout_seconds: 300,
        }
    }
}

/// High-level Temporal client for notary operations
pub struct TemporalNotaryClient {
    config: TemporalNotaryConfig,
}

impl TemporalNotaryClient {
    /// Create a new Temporal notary client
    pub async fn new(config: TemporalNotaryConfig) -> Result<Self> {
        info!(
            temporal_address = %config.temporal_address,
            namespace = %config.namespace,
            "Creating Temporal notary client (mock implementation)"
        );

        warn!("Using mock Temporal implementation - no actual Temporal server required");

        Ok(Self { config })
    }

    /// Submit evidence package for simple signing
    pub async fn sign_evidence(
        &self,
        evidence_package: EvidencePackage,
    ) -> Result<WorkflowExecution<SimpleSigningResult>> {
        info!(
            event_type = %evidence_package.event_type,
            "Starting simple signing workflow"
        );

        let workflow_id = AFDPWorkflows::start_simple_signing(evidence_package).await?;

        Ok(WorkflowExecution {
            workflow_id,
            config: self.config.clone(),
            _phantom: std::marker::PhantomData,
        })
    }

    /// Submit evidence package for approval-based signing
    pub async fn sign_evidence_with_approval(
        &self,
        evidence_package: EvidencePackage,
        approvers: Vec<String>,
    ) -> Result<WorkflowExecution<ApprovalSigningResult>> {
        info!(
            event_type = %evidence_package.event_type,
            approvers = ?approvers,
            "Starting approval signing workflow"
        );

        let workflow_id = AFDPWorkflows::start_approval_signing(evidence_package, approvers).await?;

        Ok(WorkflowExecution {
            workflow_id,
            config: self.config.clone(),
            _phantom: std::marker::PhantomData,
        })
    }

    /// Submit multiple evidence packages for batch signing
    pub async fn sign_evidence_batch(
        &self,
        evidence_packages: Vec<EvidencePackage>,
    ) -> Result<WorkflowExecution<BatchSigningResult>> {
        info!(
            package_count = evidence_packages.len(),
            "Starting batch signing workflow"
        );

        let workflow_id = AFDPWorkflows::start_batch_signing(evidence_packages).await?;

        Ok(WorkflowExecution {
            workflow_id,
            config: self.config.clone(),
            _phantom: std::marker::PhantomData,
        })
    }

    /// Sign evidence and wait for completion (convenience method)
    pub async fn sign_evidence_sync(
        &self,
        evidence_package: EvidencePackage,
    ) -> Result<SimpleSigningResult> {
        info!(
            event_type = %evidence_package.event_type,
            "Executing simple signing workflow synchronously"
        );

        execute_simple_signing_workflow(evidence_package).await
    }
}

/// Represents a running workflow execution
pub struct WorkflowExecution<T> {
    pub workflow_id: String,
    #[allow(dead_code)]
    config: TemporalNotaryConfig,
    _phantom: std::marker::PhantomData<T>,
}

impl<T> WorkflowExecution<T> {
    /// Get the workflow ID
    pub fn workflow_id(&self) -> &str {
        &self.workflow_id
    }

    /// Wait for the workflow to complete (mock implementation)
    pub async fn wait_for_result(self) -> Result<T>
    where
        T: Default,
    {
        info!(
            workflow_id = %self.workflow_id,
            "Waiting for workflow completion (mock implementation)"
        );

        warn!("Mock implementation: returning default result");

        // In a real implementation, this would wait for the workflow to complete
        Ok(T::default())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{evidence::Actor, Artifact};
    use serde_json::json;

    fn create_test_actor() -> Actor {
        Actor {
            actor_type: "test_user".to_string(),
            id: "test@example.com".to_string(),
            auth_provider: Some("test_auth".to_string()),
        }
    }

    fn create_test_evidence_package() -> EvidencePackage {
        let actor = create_test_actor();
        EvidencePackage::new("test.temporal.event".to_string(), actor)
            .add_artifact(Artifact {
                name: "test.file".to_string(),
                uri: Some("s3://bucket/test.file".to_string()),
                hash_sha256: "abc123def456".to_string(),
            })
            .add_metadata("client_test".to_string(), json!("value"))
    }

    #[test]
    fn test_temporal_config_default() {
        let config = TemporalNotaryConfig::default();
        assert_eq!(config.temporal_address, "http://localhost:7233");
        assert_eq!(config.namespace, "default");
        assert_eq!(config.task_queue, "afdp-notary");
        assert_eq!(config.default_timeout_seconds, 300);
        
        // Test notary config defaults
        assert_eq!(config.notary_config.vault_config.address, "http://localhost:8200");
        assert_eq!(config.notary_config.vault_config.token, "root");
        assert_eq!(config.notary_config.vault_config.transit_key_name, "afdp-notary-key");
        assert_eq!(config.notary_config.rekor_config.server_url, "https://rekor.sigstore.dev");
        assert_eq!(config.notary_config.rekor_config.timeout_secs, 30);
    }

    #[test]
    fn test_temporal_config_custom() {
        let custom_notary_config = NotaryConfig {
            vault_config: crate::vault::VaultConfig {
                address: "https://custom.vault.com".to_string(),
                token: "custom-token".to_string(),
                transit_key_name: "custom-key".to_string(),
            },
            rekor_config: crate::rekor::RekorConfig {
                server_url: "https://custom.rekor.com".to_string(),
                timeout_secs: 60,
            },
        };

        let config = TemporalNotaryConfig {
            temporal_address: "https://temporal.example.com:7233".to_string(),
            namespace: "custom-namespace".to_string(),
            task_queue: "custom-task-queue".to_string(),
            notary_config: custom_notary_config.clone(),
            default_timeout_seconds: 600,
        };

        assert_eq!(config.temporal_address, "https://temporal.example.com:7233");
        assert_eq!(config.namespace, "custom-namespace");
        assert_eq!(config.task_queue, "custom-task-queue");
        assert_eq!(config.default_timeout_seconds, 600);
        assert_eq!(config.notary_config.vault_config.address, custom_notary_config.vault_config.address);
    }

    #[test]
    fn test_temporal_config_serialization() {
        let config = TemporalNotaryConfig::default();
        
        let json = serde_json::to_string(&config).unwrap();
        assert!(json.contains("\"temporal_address\":\"http://localhost:7233\""));
        assert!(json.contains("\"namespace\":\"default\""));
        assert!(json.contains("\"task_queue\":\"afdp-notary\""));
        assert!(json.contains("\"default_timeout_seconds\":300"));
        
        let deserialized: TemporalNotaryConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(config.temporal_address, deserialized.temporal_address);
        assert_eq!(config.namespace, deserialized.namespace);
        assert_eq!(config.task_queue, deserialized.task_queue);
        assert_eq!(config.default_timeout_seconds, deserialized.default_timeout_seconds);
    }

    #[test]
    fn test_temporal_config_clone() {
        let original = TemporalNotaryConfig::default();
        let cloned = original.clone();
        
        assert_eq!(original.temporal_address, cloned.temporal_address);
        assert_eq!(original.namespace, cloned.namespace);
        assert_eq!(original.task_queue, cloned.task_queue);
        assert_eq!(original.default_timeout_seconds, cloned.default_timeout_seconds);
    }

    #[test]
    fn test_temporal_config_debug() {
        let config = TemporalNotaryConfig::default();
        let debug_str = format!("{:?}", config);
        
        assert!(debug_str.contains("TemporalNotaryConfig"));
        assert!(debug_str.contains("temporal_address"));
        assert!(debug_str.contains("namespace"));
        assert!(debug_str.contains("task_queue"));
        assert!(debug_str.contains("default_timeout_seconds"));
    }

    #[tokio::test]
    async fn test_temporal_client_creation() {
        let config = TemporalNotaryConfig::default();
        let client = TemporalNotaryClient::new(config.clone()).await.unwrap();
        
        // Verify client was created with the correct config
        assert_eq!(client.config.temporal_address, config.temporal_address);
        assert_eq!(client.config.namespace, config.namespace);
        assert_eq!(client.config.task_queue, config.task_queue);
    }

    #[tokio::test]
    async fn test_sign_evidence_workflow() {
        let config = TemporalNotaryConfig::default();
        let client = TemporalNotaryClient::new(config).await.unwrap();
        
        let package = create_test_evidence_package();
        let execution = client.sign_evidence(package).await.unwrap();
        
        assert!(execution.workflow_id().starts_with("simple-signing-"));
        assert!(!execution.workflow_id().is_empty());
    }

    #[tokio::test]
    async fn test_sign_evidence_with_approval_workflow() {
        let config = TemporalNotaryConfig::default();
        let client = TemporalNotaryClient::new(config).await.unwrap();
        
        let package = create_test_evidence_package();
        let approvers = vec!["approver1@example.com".to_string(), "approver2@example.com".to_string()];
        
        let execution = client.sign_evidence_with_approval(package, approvers).await.unwrap();
        
        assert!(execution.workflow_id().starts_with("approval-signing-"));
        assert!(!execution.workflow_id().is_empty());
    }

    #[tokio::test]
    async fn test_sign_evidence_with_approval_empty_approvers() {
        let config = TemporalNotaryConfig::default();
        let client = TemporalNotaryClient::new(config).await.unwrap();
        
        let package = create_test_evidence_package();
        let approvers = vec![];
        
        let execution = client.sign_evidence_with_approval(package, approvers).await.unwrap();
        
        assert!(execution.workflow_id().starts_with("approval-signing-"));
        assert!(!execution.workflow_id().is_empty());
    }

    #[tokio::test]
    async fn test_sign_evidence_batch_workflow() {
        let config = TemporalNotaryConfig::default();
        let client = TemporalNotaryClient::new(config).await.unwrap();
        
        let package1 = create_test_evidence_package();
        let package2 = create_test_evidence_package();
        let packages = vec![package1, package2];
        
        let execution = client.sign_evidence_batch(packages).await.unwrap();
        
        assert!(execution.workflow_id().starts_with("batch-signing-"));
        assert!(!execution.workflow_id().is_empty());
    }

    #[tokio::test]
    async fn test_sign_evidence_batch_empty() {
        let config = TemporalNotaryConfig::default();
        let client = TemporalNotaryClient::new(config).await.unwrap();
        
        let packages = vec![];
        
        let execution = client.sign_evidence_batch(packages).await.unwrap();
        
        assert!(execution.workflow_id().starts_with("batch-signing-"));
        assert!(!execution.workflow_id().is_empty());
    }

    #[tokio::test]
    async fn test_sign_evidence_batch_large() {
        let config = TemporalNotaryConfig::default();
        let client = TemporalNotaryClient::new(config).await.unwrap();
        
        let packages: Vec<EvidencePackage> = (0..50).map(|i| {
            let actor = Actor {
                actor_type: "batch_test".to_string(),
                id: format!("user{}@example.com", i),
                auth_provider: None,
            };
            EvidencePackage::new(format!("batch.event.{}", i), actor)
        }).collect();
        
        let execution = client.sign_evidence_batch(packages).await.unwrap();
        
        assert!(execution.workflow_id().starts_with("batch-signing-"));
        assert!(!execution.workflow_id().is_empty());
    }

    #[tokio::test]
    async fn test_sign_evidence_sync() {
        let config = TemporalNotaryConfig::default();
        let client = TemporalNotaryClient::new(config).await.unwrap();
        
        let package = create_test_evidence_package();
        let result = client.sign_evidence_sync(package).await.unwrap();
        
        // Test the default result structure
        assert!(!result.receipt.evidence_package_hash.is_empty());
        assert!(!result.receipt.rekor_log_id.is_empty());
        assert!(!result.audit_log_id.is_empty());
        assert!(result.validation_result.is_valid);
    }

    #[tokio::test]
    async fn test_workflow_execution_workflow_id() {
        let config = TemporalNotaryConfig::default();
        let client = TemporalNotaryClient::new(config).await.unwrap();
        
        let package = create_test_evidence_package();
        let execution = client.sign_evidence(package).await.unwrap();
        
        let workflow_id = execution.workflow_id();
        assert!(!workflow_id.is_empty());
        assert!(workflow_id.starts_with("simple-signing-"));
        
        // Test that workflow_id() returns a reference to the same string
        let workflow_id2 = execution.workflow_id();
        assert_eq!(workflow_id, workflow_id2);
    }

    #[tokio::test]
    async fn test_workflow_execution_wait_for_result_simple() {
        let config = TemporalNotaryConfig::default();
        let client = TemporalNotaryClient::new(config).await.unwrap();
        
        let package = create_test_evidence_package();
        let execution = client.sign_evidence(package).await.unwrap();
        
        let result = execution.wait_for_result().await.unwrap();
        
        // Test the default SimpleSigningResult
        assert!(!result.receipt.evidence_package_hash.is_empty());
        assert!(!result.receipt.rekor_log_id.is_empty());
        assert!(!result.audit_log_id.is_empty());
        assert!(result.validation_result.is_valid);
    }

    #[tokio::test]
    async fn test_workflow_execution_wait_for_result_approval() {
        let config = TemporalNotaryConfig::default();
        let client = TemporalNotaryClient::new(config).await.unwrap();
        
        let package = create_test_evidence_package();
        let approvers = vec!["approver@example.com".to_string()];
        let execution = client.sign_evidence_with_approval(package, approvers).await.unwrap();
        
        let result = execution.wait_for_result().await.unwrap();
        
        // Test the default ApprovalSigningResult
        assert!(!result.receipt.evidence_package_hash.is_empty());
        assert!(!result.receipt.rekor_log_id.is_empty());
        assert!(!result.audit_log_id.is_empty());
        assert_eq!(result.approvals.len(), 1); // Default has one mock approval
        assert_eq!(result.approvals[0].approver, "mock-approver");
    }

    #[tokio::test]
    async fn test_workflow_execution_wait_for_result_batch() {
        let config = TemporalNotaryConfig::default();
        let client = TemporalNotaryClient::new(config).await.unwrap();
        
        let packages = vec![create_test_evidence_package()];
        let execution = client.sign_evidence_batch(packages).await.unwrap();
        
        let result = execution.wait_for_result().await.unwrap();
        
        // Test the default BatchSigningResult
        assert!(!result.audit_log_id.is_empty());
        assert!(result.successful_receipts.is_empty()); // Default has empty receipts
        assert!(result.failed_packages.is_empty()); // Default has empty failures
    }

    #[tokio::test]
    async fn test_multiple_clients() {
        let config1 = TemporalNotaryConfig {
            temporal_address: "http://temporal1:7233".to_string(),
            namespace: "namespace1".to_string(),
            task_queue: "queue1".to_string(),
            notary_config: NotaryConfig {
                vault_config: crate::vault::VaultConfig {
                    address: "http://vault1:8200".to_string(),
                    token: "token1".to_string(),
                    transit_key_name: "key1".to_string(),
                },
                rekor_config: crate::rekor::RekorConfig::default(),
            },
            default_timeout_seconds: 300,
        };

        let config2 = TemporalNotaryConfig {
            temporal_address: "http://temporal2:7233".to_string(),
            namespace: "namespace2".to_string(),
            task_queue: "queue2".to_string(),
            notary_config: NotaryConfig {
                vault_config: crate::vault::VaultConfig {
                    address: "http://vault2:8200".to_string(),
                    token: "token2".to_string(),
                    transit_key_name: "key2".to_string(),
                },
                rekor_config: crate::rekor::RekorConfig::default(),
            },
            default_timeout_seconds: 600,
        };

        let client1 = TemporalNotaryClient::new(config1.clone()).await.unwrap();
        let client2 = TemporalNotaryClient::new(config2.clone()).await.unwrap();

        assert_eq!(client1.config.namespace, "namespace1");
        assert_eq!(client2.config.namespace, "namespace2");
        
        assert_eq!(client1.config.default_timeout_seconds, 300);
        assert_eq!(client2.config.default_timeout_seconds, 600);
    }

    #[tokio::test]
    async fn test_workflow_execution_with_different_evidence_types() {
        let config = TemporalNotaryConfig::default();
        let client = TemporalNotaryClient::new(config).await.unwrap();
        
        let event_types = vec![
            "model.deployment",
            "model.training", 
            "security.incident",
            "compliance.scan",
            "data.access",
        ];

        for event_type in event_types {
            let actor = create_test_actor();
            let package = EvidencePackage::new(event_type.to_string(), actor);
            
            let execution = client.sign_evidence(package).await.unwrap();
            assert!(execution.workflow_id().starts_with("simple-signing-"));
        }
    }

    #[tokio::test]
    async fn test_config_with_different_timeouts() {
        let timeouts = vec![30, 60, 300, 600, 1800, 3600];
        
        for timeout in timeouts {
            let mut config = TemporalNotaryConfig::default();
            config.default_timeout_seconds = timeout;
            
            let client = TemporalNotaryClient::new(config.clone()).await.unwrap();
            assert_eq!(client.config.default_timeout_seconds, timeout);
        }
    }

    #[test]
    fn test_workflow_execution_phantom_data() {
        // Test that WorkflowExecution can be created with different types
        let config = TemporalNotaryConfig::default();
        
        let execution_simple: WorkflowExecution<SimpleSigningResult> = WorkflowExecution {
            workflow_id: "test-simple".to_string(),
            config: config.clone(),
            _phantom: std::marker::PhantomData,
        };
        
        let execution_approval: WorkflowExecution<ApprovalSigningResult> = WorkflowExecution {
            workflow_id: "test-approval".to_string(),
            config: config.clone(),
            _phantom: std::marker::PhantomData,
        };
        
        let execution_batch: WorkflowExecution<BatchSigningResult> = WorkflowExecution {
            workflow_id: "test-batch".to_string(),
            config: config.clone(),
            _phantom: std::marker::PhantomData,
        };
        
        assert_eq!(execution_simple.workflow_id(), "test-simple");
        assert_eq!(execution_approval.workflow_id(), "test-approval");
        assert_eq!(execution_batch.workflow_id(), "test-batch");
    }
}