//! Mock Temporal implementation for development and testing
//! 
//! This module provides a simplified implementation of Temporal concepts
//! that can be used when the actual Temporal SDK is not available.

use crate::{
    error::Result,
    evidence::EvidencePackage,
    notary::NotarizationReceipt,
};
use serde::{Deserialize, Serialize};
use std::time::Duration;
use tracing::{info, warn};

/// Mock workflow execution result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MockWorkflowExecution<T> {
    pub workflow_id: String,
    pub status: String,
    pub result: Option<T>,
    pub error: Option<String>,
}

/// Mock Temporal client for development
pub struct MockTemporalClient {
    pub namespace: String,
    pub task_queue: String,
}

impl MockTemporalClient {
    pub fn new(namespace: String, task_queue: String) -> Self {
        Self {
            namespace,
            task_queue,
        }
    }

    /// Mock workflow execution
    pub async fn execute_workflow<T>(
        &self,
        workflow_name: &str,
        input: &EvidencePackage,
    ) -> Result<MockWorkflowExecution<T>>
    where
        T: Default + Clone,
    {
        info!(
            workflow_name = %workflow_name,
            event_type = %input.event_type,
            "Executing mock workflow"
        );

        warn!("Using mock Temporal implementation - no actual Temporal server required");

        // Simulate workflow execution delay
        tokio::time::sleep(Duration::from_millis(100)).await;

        Ok(MockWorkflowExecution {
            workflow_id: format!("mock-{}", uuid::Uuid::new_v4()),
            status: "COMPLETED".to_string(),
            result: Some(T::default()),
            error: None,
        })
    }

    /// Mock activity execution
    pub async fn execute_activity<I, O>(
        &self,
        activity_name: &str,
        input: I,
    ) -> Result<O>
    where
        I: std::fmt::Debug,
        O: Default,
    {
        info!(
            activity_name = %activity_name,
            input = ?input,
            "Executing mock activity"
        );

        // Simulate activity execution delay
        tokio::time::sleep(Duration::from_millis(50)).await;

        Ok(O::default())
    }
}

/// Mock implementations for workflow results
impl Default for crate::temporal::workflows::SimpleSigningResult {
    fn default() -> Self {
        Self {
            receipt: NotarizationReceipt {
                evidence_package_hash: "mock-hash".to_string(),
                rekor_log_id: "mock-rekor-id".to_string(),
                rekor_server_url: "https://rekor.sigstore.dev".to_string(),
                signature_b64: "mock-signature".to_string(),
                public_key_b64: "mock-public-key".to_string(),
                integrated_time: chrono::Utc::now().timestamp(),
                log_index: 0,
            },
            validation_result: crate::temporal::activities::ValidationResult {
                is_valid: true,
                errors: Vec::new(),
                warnings: Vec::new(),
            },
            audit_log_id: "mock-audit-id".to_string(),
        }
    }
}

impl Default for crate::temporal::workflows::ApprovalSigningResult {
    fn default() -> Self {
        Self {
            receipt: NotarizationReceipt {
                evidence_package_hash: "mock-hash".to_string(),
                rekor_log_id: "mock-rekor-id".to_string(),
                rekor_server_url: "https://rekor.sigstore.dev".to_string(),
                signature_b64: "mock-signature".to_string(),
                public_key_b64: "mock-public-key".to_string(),
                integrated_time: chrono::Utc::now().timestamp(),
                log_index: 0,
            },
            approvals: vec![crate::temporal::workflows::Approval {
                approver: "mock-approver".to_string(),
                approved_at: chrono::Utc::now(),
                comments: Some("Mock approval".to_string()),
            }],
            audit_log_id: "mock-audit-id".to_string(),
        }
    }
}

impl Default for crate::temporal::workflows::BatchSigningResult {
    fn default() -> Self {
        Self {
            successful_receipts: Vec::new(),
            failed_packages: Vec::new(),
            audit_log_id: "mock-audit-id".to_string(),
        }
    }
}

impl Default for crate::temporal::activities::ValidationResult {
    fn default() -> Self {
        Self {
            is_valid: true,
            errors: Vec::new(),
            warnings: Vec::new(),
        }
    }
}

impl Default for crate::temporal::activities::NotificationResult {
    fn default() -> Self {
        Self {
            notification_id: "mock-notification-id".to_string(),
            status: "sent".to_string(),
            delivered_at: chrono::Utc::now(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::evidence::Actor;

    #[test]
    fn test_mock_temporal_client_creation() {
        let client = MockTemporalClient::new(
            "test-namespace".to_string(),
            "test-task-queue".to_string(),
        );

        assert_eq!(client.namespace, "test-namespace");
        assert_eq!(client.task_queue, "test-task-queue");
    }

    #[tokio::test]
    async fn test_mock_temporal_client_execute_workflow() {
        let client = MockTemporalClient::new(
            "default".to_string(),
            "afdp-notary".to_string(),
        );

        let actor = Actor {
            actor_type: "test".to_string(),
            id: "test@example.com".to_string(),
            auth_provider: None,
        };

        let package = EvidencePackage::new("test.event".to_string(), actor);

        let result: MockWorkflowExecution<crate::temporal::workflows::SimpleSigningResult> = 
            client.execute_workflow("simple_signing", &package).await.unwrap();

        assert_eq!(result.status, "COMPLETED");
        assert!(result.workflow_id.starts_with("mock-"));
        assert!(result.result.is_some());
        assert!(result.error.is_none());
    }

    #[tokio::test]
    async fn test_mock_temporal_client_execute_workflow_approval() {
        let client = MockTemporalClient::new(
            "approval-namespace".to_string(),
            "approval-queue".to_string(),
        );

        let actor = Actor {
            actor_type: "approver".to_string(),
            id: "approver@example.com".to_string(),
            auth_provider: Some("oauth2".to_string()),
        };

        let package = EvidencePackage::new("test.approval.workflow".to_string(), actor);

        let result: MockWorkflowExecution<crate::temporal::workflows::ApprovalSigningResult> = 
            client.execute_workflow("approval_signing", &package).await.unwrap();

        assert_eq!(result.status, "COMPLETED");
        assert!(result.workflow_id.starts_with("mock-"));
        assert!(result.result.is_some());
        assert!(result.error.is_none());
    }

    #[tokio::test]
    async fn test_mock_temporal_client_execute_workflow_batch() {
        let client = MockTemporalClient::new(
            "batch-namespace".to_string(),
            "batch-queue".to_string(),
        );

        let actor = Actor {
            actor_type: "batch_user".to_string(),
            id: "batch@example.com".to_string(),
            auth_provider: None,
        };

        let package = EvidencePackage::new("test.batch.workflow".to_string(), actor);

        let result: MockWorkflowExecution<crate::temporal::workflows::BatchSigningResult> = 
            client.execute_workflow("batch_signing", &package).await.unwrap();

        assert_eq!(result.status, "COMPLETED");
        assert!(result.workflow_id.starts_with("mock-"));
        assert!(result.result.is_some());
        assert!(result.error.is_none());
    }

    #[tokio::test]
    async fn test_mock_temporal_client_execute_activity() {
        let client = MockTemporalClient::new(
            "activity-namespace".to_string(),
            "activity-queue".to_string(),
        );

        let input = "test activity input";
        let result: String = client.execute_activity("test_activity", input).await.unwrap();

        // String::default() returns an empty string
        assert_eq!(result, "");
    }

    #[tokio::test]
    async fn test_mock_temporal_client_execute_activity_with_complex_input() {
        let client = MockTemporalClient::new(
            "complex-namespace".to_string(),
            "complex-queue".to_string(),
        );

        let actor = Actor {
            actor_type: "activity_test".to_string(),
            id: "activity@example.com".to_string(),
            auth_provider: Some("test".to_string()),
        };

        let package = EvidencePackage::new("test.activity.input".to_string(), actor);
        let result: crate::temporal::activities::ValidationResult = 
            client.execute_activity("validate_activity", package).await.unwrap();

        assert!(result.is_valid);
        assert!(result.errors.is_empty());
        assert!(result.warnings.is_empty());
    }

    #[tokio::test]
    async fn test_mock_temporal_client_execute_activity_notification_result() {
        let client = MockTemporalClient::new(
            "notification-namespace".to_string(),
            "notification-queue".to_string(),
        );

        let input = 42i32;
        let result: crate::temporal::activities::NotificationResult = 
            client.execute_activity("notification_activity", input).await.unwrap();

        assert_eq!(result.notification_id, "mock-notification-id");
        assert_eq!(result.status, "sent");
        assert!(result.delivered_at <= chrono::Utc::now());
    }

    #[test]
    fn test_mock_workflow_execution_creation() {
        let execution: MockWorkflowExecution<String> = MockWorkflowExecution {
            workflow_id: "test-workflow-123".to_string(),
            status: "RUNNING".to_string(),
            result: Some("test result".to_string()),
            error: None,
        };

        assert_eq!(execution.workflow_id, "test-workflow-123");
        assert_eq!(execution.status, "RUNNING");
        assert_eq!(execution.result, Some("test result".to_string()));
        assert!(execution.error.is_none());
    }

    #[test]
    fn test_mock_workflow_execution_with_error() {
        let execution: MockWorkflowExecution<String> = MockWorkflowExecution {
            workflow_id: "failed-workflow-456".to_string(),
            status: "FAILED".to_string(),
            result: None,
            error: Some("Workflow failed".to_string()),
        };

        assert_eq!(execution.workflow_id, "failed-workflow-456");
        assert_eq!(execution.status, "FAILED");
        assert!(execution.result.is_none());
        assert_eq!(execution.error, Some("Workflow failed".to_string()));
    }

    #[test]
    fn test_mock_workflow_execution_serialization() {
        let execution: MockWorkflowExecution<i32> = MockWorkflowExecution {
            workflow_id: "serialization-test".to_string(),
            status: "COMPLETED".to_string(),
            result: Some(42),
            error: None,
        };

        let json = serde_json::to_string(&execution).unwrap();
        assert!(json.contains("\"workflow_id\":\"serialization-test\""));
        assert!(json.contains("\"status\":\"COMPLETED\""));
        assert!(json.contains("\"result\":42"));

        let deserialized: MockWorkflowExecution<i32> = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.workflow_id, execution.workflow_id);
        assert_eq!(deserialized.status, execution.status);
        assert_eq!(deserialized.result, execution.result);
    }

    #[test]
    fn test_mock_workflow_execution_clone() {
        let original: MockWorkflowExecution<String> = MockWorkflowExecution {
            workflow_id: "clone-test".to_string(),
            status: "COMPLETED".to_string(),
            result: Some("cloned result".to_string()),
            error: None,
        };

        let cloned = original.clone();
        assert_eq!(original.workflow_id, cloned.workflow_id);
        assert_eq!(original.status, cloned.status);
        assert_eq!(original.result, cloned.result);
        assert_eq!(original.error, cloned.error);
    }

    #[test]
    fn test_simple_signing_result_default() {
        let result = crate::temporal::workflows::SimpleSigningResult::default();
        
        assert_eq!(result.receipt.evidence_package_hash, "mock-hash");
        assert_eq!(result.receipt.rekor_log_id, "mock-rekor-id");
        assert_eq!(result.receipt.rekor_server_url, "https://rekor.sigstore.dev");
        assert_eq!(result.receipt.signature_b64, "mock-signature");
        assert_eq!(result.receipt.public_key_b64, "mock-public-key");
        assert_eq!(result.receipt.log_index, 0);
        assert!(result.receipt.integrated_time > 0);
        
        assert!(result.validation_result.is_valid);
        assert!(result.validation_result.errors.is_empty());
        assert!(result.validation_result.warnings.is_empty());
        
        assert_eq!(result.audit_log_id, "mock-audit-id");
    }

    #[test]
    fn test_approval_signing_result_default() {
        let result = crate::temporal::workflows::ApprovalSigningResult::default();
        
        assert_eq!(result.receipt.evidence_package_hash, "mock-hash");
        assert_eq!(result.receipt.rekor_log_id, "mock-rekor-id");
        assert_eq!(result.receipt.rekor_server_url, "https://rekor.sigstore.dev");
        assert_eq!(result.receipt.signature_b64, "mock-signature");
        assert_eq!(result.receipt.public_key_b64, "mock-public-key");
        assert_eq!(result.receipt.log_index, 0);
        assert!(result.receipt.integrated_time > 0);
        
        assert_eq!(result.approvals.len(), 1);
        assert_eq!(result.approvals[0].approver, "mock-approver");
        assert_eq!(result.approvals[0].comments, Some("Mock approval".to_string()));
        assert!(result.approvals[0].approved_at <= chrono::Utc::now());
        
        assert_eq!(result.audit_log_id, "mock-audit-id");
    }

    #[test]
    fn test_batch_signing_result_default() {
        let result = crate::temporal::workflows::BatchSigningResult::default();
        
        assert!(result.successful_receipts.is_empty());
        assert!(result.failed_packages.is_empty());
        assert_eq!(result.audit_log_id, "mock-audit-id");
    }

    #[test]
    fn test_validation_result_default() {
        let result = crate::temporal::activities::ValidationResult::default();
        
        assert!(result.is_valid);
        assert!(result.errors.is_empty());
        assert!(result.warnings.is_empty());
    }

    #[test]
    fn test_notification_result_default() {
        let result = crate::temporal::activities::NotificationResult::default();
        
        assert_eq!(result.notification_id, "mock-notification-id");
        assert_eq!(result.status, "sent");
        assert!(result.delivered_at <= chrono::Utc::now());
    }

    #[test]
    fn test_mock_workflow_execution_debug() {
        let execution: MockWorkflowExecution<String> = MockWorkflowExecution {
            workflow_id: "debug-test".to_string(),
            status: "COMPLETED".to_string(),
            result: Some("debug result".to_string()),
            error: None,
        };

        let debug_str = format!("{:?}", execution);
        assert!(debug_str.contains("MockWorkflowExecution"));
        assert!(debug_str.contains("debug-test"));
        assert!(debug_str.contains("COMPLETED"));
        assert!(debug_str.contains("debug result"));
    }

    #[tokio::test]
    async fn test_multiple_activity_executions() {
        let client = MockTemporalClient::new(
            "multi-namespace".to_string(),
            "multi-queue".to_string(),
        );

        // Test multiple activity executions with different types
        let result1: String = client.execute_activity("activity1", "input1").await.unwrap();
        let result2: i32 = client.execute_activity("activity2", 123).await.unwrap();
        let result3: bool = client.execute_activity("activity3", true).await.unwrap();

        assert_eq!(result1, ""); // String::default()
        assert_eq!(result2, 0); // i32::default()
        assert_eq!(result3, false); // bool::default()
    }

    #[tokio::test]
    async fn test_workflow_execution_with_different_types() {
        let client = MockTemporalClient::new(
            "types-namespace".to_string(),
            "types-queue".to_string(),
        );

        let actor = Actor {
            actor_type: "types_test".to_string(),
            id: "types@example.com".to_string(),
            auth_provider: None,
        };

        let package = EvidencePackage::new("test.types.workflow".to_string(), actor);

        // Test with different result types
        let result1: MockWorkflowExecution<String> = 
            client.execute_workflow("string_workflow", &package).await.unwrap();
        let result2: MockWorkflowExecution<i32> = 
            client.execute_workflow("int_workflow", &package).await.unwrap();

        assert_eq!(result1.status, "COMPLETED");
        assert_eq!(result1.result, Some(String::default()));
        
        assert_eq!(result2.status, "COMPLETED");
        assert_eq!(result2.result, Some(i32::default()));
    }
}