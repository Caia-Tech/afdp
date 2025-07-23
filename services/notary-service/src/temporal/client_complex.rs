//! Temporal client for AFDP Notary Service

use crate::{
    error::{NotaryError, Result},
    evidence::EvidencePackage,
    notary::{NotaryConfig, NotarizationReceipt},
    temporal::workflows::{
        SimpleSigningResult, ApprovalSigningResult, BatchSigningResult,
        AFDPWorkflows,
    },
};
use serde::{Deserialize, Serialize};
use tracing::{info, warn};
use std::time::Duration;

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

    /// Start a worker to process workflows and activities
    pub async fn start_worker(&self) -> Result<()> {
        info!(
            task_queue = %self.config.task_queue,
            "Starting Temporal worker"
        );

        let mut worker = WorkerBuilder::new(&self.client, &self.config.task_queue)
            .register_workflow::<crate::temporal::workflows::simple_signing_workflow>()
            .register_workflow::<crate::temporal::workflows::approval_signing_workflow>()
            .register_workflow::<crate::temporal::workflows::batch_signing_workflow>()
            .register_activity::<crate::temporal::activities::notarize_evidence_activity>()
            .register_activity::<crate::temporal::activities::validate_evidence_activity>()
            .register_activity::<crate::temporal::activities::create_audit_log_activity>()
            .register_activity::<crate::temporal::activities::send_notification_activity>()
            .build()
            .map_err(|e| NotaryError::Unknown(format!("Failed to build worker: {}", e)))?;

        worker.run().await
            .map_err(|e| NotaryError::Unknown(format!("Worker failed: {}", e)))?;

        Ok(())
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

        let workflow_id = AFDPWorkflows::start_simple_signing(evidence_package)
            .await
            .map_err(|e| NotaryError::Unknown(format!("Failed to start workflow: {}", e)))?;

        Ok(WorkflowExecution {
            workflow_id,
            client: self.client.clone(),
            timeout: Duration::from_secs(self.config.default_timeout_seconds),
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

        let workflow_id = AFDPWorkflows::start_approval_signing(evidence_package, approvers)
            .await
            .map_err(|e| NotaryError::Unknown(format!("Failed to start workflow: {}", e)))?;

        Ok(WorkflowExecution {
            workflow_id,
            client: self.client.clone(),
            timeout: Duration::from_secs(self.config.default_timeout_seconds),
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

        let workflow_id = AFDPWorkflows::start_batch_signing(evidence_packages)
            .await
            .map_err(|e| NotaryError::Unknown(format!("Failed to start workflow: {}", e)))?;

        Ok(WorkflowExecution {
            workflow_id,
            client: self.client.clone(),
            timeout: Duration::from_secs(self.config.default_timeout_seconds * 10), // Longer timeout for batch
        })
    }

    /// Get the status of a workflow
    pub async fn get_workflow_status(&self, workflow_id: &str) -> Result<WorkflowStatus> {
        // In a real implementation, this would query Temporal for workflow status
        // For now, return a placeholder
        Ok(WorkflowStatus {
            workflow_id: workflow_id.to_string(),
            status: "RUNNING".to_string(),
            started_at: chrono::Utc::now(),
            completed_at: None,
        })
    }

    /// Cancel a running workflow
    pub async fn cancel_workflow(&self, workflow_id: &str) -> Result<()> {
        info!(
            workflow_id = %workflow_id,
            "Cancelling workflow"
        );

        // In a real implementation, this would cancel the Temporal workflow
        Ok(())
    }
}

/// Represents a running workflow execution
pub struct WorkflowExecution<T> {
    pub workflow_id: String,
    client: Client,
    timeout: Duration,
    _phantom: std::marker::PhantomData<T>,
}

impl<T> WorkflowExecution<T>
where
    T: serde::de::DeserializeOwned,
{
    /// Wait for the workflow to complete and get the result
    pub async fn wait_for_result(self) -> Result<T> {
        info!(
            workflow_id = %self.workflow_id,
            "Waiting for workflow completion"
        );

        // In a real implementation, this would wait for the workflow to complete
        // and return the actual result. For now, we'll return an error.
        Err(NotaryError::Unknown(
            "Workflow waiting not implemented yet".to_string()
        ))
    }

    /// Get the workflow ID
    pub fn workflow_id(&self) -> &str {
        &self.workflow_id
    }
}

/// Workflow status information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkflowStatus {
    pub workflow_id: String,
    pub status: String,
    pub started_at: chrono::DateTime<chrono::Utc>,
    pub completed_at: Option<chrono::DateTime<chrono::Utc>>,
}

/// High-level convenience functions for common AFDP operations
impl TemporalNotaryClient {
    /// Sign evidence and wait for completion (convenience method)
    pub async fn sign_evidence_sync(
        &self,
        evidence_package: EvidencePackage,
    ) -> Result<SimpleSigningResult> {
        let execution = self.sign_evidence(evidence_package).await?;
        execution.wait_for_result().await
    }

    /// Sign with approval and wait for completion (convenience method)
    pub async fn sign_evidence_with_approval_sync(
        &self,
        evidence_package: EvidencePackage,
        approvers: Vec<String>,
    ) -> Result<ApprovalSigningResult> {
        let execution = self.sign_evidence_with_approval(evidence_package, approvers).await?;
        execution.wait_for_result().await
    }

    /// Batch sign and wait for completion (convenience method)
    pub async fn sign_evidence_batch_sync(
        &self,
        evidence_packages: Vec<EvidencePackage>,
    ) -> Result<BatchSigningResult> {
        let execution = self.sign_evidence_batch(evidence_packages).await?;
        execution.wait_for_result().await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::evidence::Actor;

    #[test]
    fn test_temporal_config_default() {
        let config = TemporalNotaryConfig::default();
        assert_eq!(config.temporal_address, "http://localhost:7233");
        assert_eq!(config.namespace, "default");
        assert_eq!(config.task_queue, "afdp-notary");
    }

    #[tokio::test]
    async fn test_workflow_execution() {
        // This would test actual workflow execution with a running Temporal server
        // For now, just test that we can create the client configuration
        
        let config = TemporalNotaryConfig::default();
        assert!(!config.temporal_address.is_empty());
    }
}