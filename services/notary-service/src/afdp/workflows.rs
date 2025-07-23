//! Simplified AFDP-specific workflow compositions

use crate::{
    evidence::EvidencePackage,
    temporal::{TemporalNotaryClient, TemporalNotaryConfig},
    afdp::evidence::{AFDPEvidencePackage},
    error::Result,
};

/// High-level AFDP workflow orchestrator
pub struct AFDPWorkflows {
    temporal_client: TemporalNotaryClient,
}

impl AFDPWorkflows {
    /// Create a new AFDP workflows instance
    pub async fn new(config: TemporalNotaryConfig) -> Result<Self> {
        let temporal_client = TemporalNotaryClient::new(config).await?;
        Ok(Self { temporal_client })
    }

    /// Complete model deployment workflow
    pub async fn deploy_model_workflow(
        &self,
        model_id: &str,
        model_version: &str,
        environment: &str,
        deployed_by: &str,
    ) -> Result<String> {
        // Step 1: Create deployment evidence
        let evidence = AFDPEvidencePackage::model_deployment(
            model_id,
            model_version,
            environment,
            deployed_by,
        );

        // Step 2: Sign evidence (simple signing for now)
        let workflow_execution = self.temporal_client.sign_evidence(evidence).await?;
        Ok(workflow_execution.workflow_id().to_string())
    }

    /// Model training completion workflow
    pub async fn complete_model_training_workflow(
        &self,
        model_id: &str,
        training_job_id: &str,
        dataset_version: &str,
        accuracy: f64,
        trained_by: &str,
    ) -> Result<String> {
        let evidence = AFDPEvidencePackage::model_training(
            model_id,
            training_job_id,
            dataset_version,
            accuracy,
            trained_by,
        );

        let workflow_execution = self.temporal_client.sign_evidence(evidence).await?;
        Ok(workflow_execution.workflow_id().to_string())
    }

    /// Model approval workflow
    pub async fn approve_model_workflow(
        &self,
        model_id: &str,
        model_version: &str,
        approver: &str,
        compliance_checklist_id: &str,
        approved_environments: Vec<&str>,
    ) -> Result<String> {
        let evidence = AFDPEvidencePackage::model_approval(
            model_id,
            model_version,
            approver,
            compliance_checklist_id,
            approved_environments,
        );

        // Model approvals require multi-party signing
        let approvers = vec![
            approver.to_string(),
            "compliance-officer@caiatech.com".to_string(),
        ];

        let workflow_execution = self
            .temporal_client
            .sign_evidence_with_approval(evidence, approvers)
            .await?;

        Ok(workflow_execution.workflow_id().to_string())
    }

    /// Batch processing workflow for multiple evidence packages
    pub async fn batch_evidence_workflow(
        &self,
        evidence_packages: Vec<EvidencePackage>,
    ) -> Result<String> {
        let workflow_execution = self
            .temporal_client
            .sign_evidence_batch(evidence_packages)
            .await?;

        Ok(workflow_execution.workflow_id().to_string())
    }

    /// Sign evidence synchronously (for testing/development)
    pub async fn sign_evidence_sync(
        &self,
        evidence_package: EvidencePackage,
    ) -> Result<crate::temporal::workflows::SimpleSigningResult> {
        self.temporal_client.sign_evidence_sync(evidence_package).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_afdp_workflows_creation() {
        let config = TemporalNotaryConfig::default();
        let workflows = AFDPWorkflows::new(config).await.unwrap();
        
        // Test basic model deployment workflow
        let workflow_id = workflows.deploy_model_workflow(
            "test-model",
            "1.0.0", 
            "staging",
            "test@example.com"
        ).await.unwrap();
        
        assert!(workflow_id.starts_with("simple-signing-"));
    }

    #[tokio::test]
    async fn test_complete_model_training_workflow() {
        let config = TemporalNotaryConfig::default();
        let workflows = AFDPWorkflows::new(config).await.unwrap();
        
        let workflow_id = workflows.complete_model_training_workflow(
            "training-model-v2",
            "job-12345",
            "dataset-v3.1",
            0.95,
            "ml-engineer@example.com"
        ).await.unwrap();
        
        assert!(workflow_id.starts_with("simple-signing-"));
    }

    #[tokio::test]
    async fn test_approve_model_workflow() {
        let config = TemporalNotaryConfig::default();
        let workflows = AFDPWorkflows::new(config).await.unwrap();
        
        let workflow_id = workflows.approve_model_workflow(
            "approval-model-v1",
            "v2.0.0",
            "approver@example.com",
            "checklist-abc123",
            vec!["production", "staging"]
        ).await.unwrap();
        
        assert!(workflow_id.starts_with("approval-signing-"));
    }

    #[tokio::test]
    async fn test_approve_model_workflow_single_environment() {
        let config = TemporalNotaryConfig::default();
        let workflows = AFDPWorkflows::new(config).await.unwrap();
        
        let workflow_id = workflows.approve_model_workflow(
            "single-env-model",
            "v1.0.0",
            "lead@example.com",
            "checklist-xyz789",
            vec!["development"]
        ).await.unwrap();
        
        assert!(workflow_id.starts_with("approval-signing-"));
    }

    #[tokio::test]
    async fn test_batch_evidence_workflow() {
        use crate::{Actor, EvidencePackage};
        
        let config = TemporalNotaryConfig::default();
        let workflows = AFDPWorkflows::new(config).await.unwrap();
        
        // Create multiple evidence packages
        let actor1 = Actor {
            actor_type: "batch_user".to_string(),
            id: "user1@example.com".to_string(),
            auth_provider: Some("keycloak".to_string()),
        };
        let actor2 = Actor {
            actor_type: "batch_user".to_string(),
            id: "user2@example.com".to_string(),
            auth_provider: Some("keycloak".to_string()),
        };
        
        let evidence1 = EvidencePackage::new("batch.event.1".to_string(), actor1);
        let evidence2 = EvidencePackage::new("batch.event.2".to_string(), actor2);
        
        let workflow_id = workflows.batch_evidence_workflow(
            vec![evidence1, evidence2]
        ).await.unwrap();
        
        assert!(workflow_id.starts_with("batch-signing-"));
    }

    #[tokio::test]
    async fn test_batch_evidence_workflow_empty() {
        let config = TemporalNotaryConfig::default();
        let workflows = AFDPWorkflows::new(config).await.unwrap();
        
        let workflow_id = workflows.batch_evidence_workflow(vec![]).await.unwrap();
        
        assert!(workflow_id.starts_with("batch-signing-"));
    }

    #[tokio::test]
    async fn test_batch_evidence_workflow_large_batch() {
        use crate::{Actor, EvidencePackage};
        
        let config = TemporalNotaryConfig::default();
        let workflows = AFDPWorkflows::new(config).await.unwrap();
        
        // Create 10 evidence packages
        let evidence_packages: Vec<EvidencePackage> = (0..10)
            .map(|i| {
                let actor = Actor {
                    actor_type: "batch_test".to_string(),
                    id: format!("batch-user-{}@example.com", i),
                    auth_provider: None,
                };
                EvidencePackage::new(format!("batch.large.event.{}", i), actor)
            })
            .collect();
        
        let workflow_id = workflows.batch_evidence_workflow(evidence_packages).await.unwrap();
        
        assert!(workflow_id.starts_with("batch-signing-"));
    }

    #[tokio::test]
    async fn test_sign_evidence_sync() {
        use crate::{Actor, EvidencePackage};
        
        let config = TemporalNotaryConfig::default();
        let workflows = AFDPWorkflows::new(config).await.unwrap();
        
        let actor = Actor {
            actor_type: "sync_test".to_string(),
            id: "sync@example.com".to_string(),
            auth_provider: Some("test_auth".to_string()),
        };
        
        let evidence = EvidencePackage::new("sync.test.event".to_string(), actor)
            .add_metadata("test_key".to_string(), serde_json::json!("test_value"));
        
        let result = workflows.sign_evidence_sync(evidence).await.unwrap();
        
        assert!(result.receipt.evidence_package_hash.len() > 0);
        assert!(result.receipt.rekor_log_id.len() > 0);
        assert!(result.receipt.signature_b64.len() > 0);
    }

    #[tokio::test]
    async fn test_deploy_model_workflow_different_environments() {
        let config = TemporalNotaryConfig::default();
        let workflows = AFDPWorkflows::new(config).await.unwrap();
        
        let environments = vec!["development", "staging", "production", "testing"];
        
        for env in environments {
            let workflow_id = workflows.deploy_model_workflow(
                "multi-env-model",
                "v1.0.0",
                env,
                "devops@example.com"
            ).await.unwrap();
            
            assert!(workflow_id.starts_with("simple-signing-"));
        }
    }

    #[tokio::test]
    async fn test_complete_model_training_workflow_different_accuracies() {
        let config = TemporalNotaryConfig::default();
        let workflows = AFDPWorkflows::new(config).await.unwrap();
        
        let accuracies = vec![0.75, 0.85, 0.95, 0.99, 1.0];
        
        for accuracy in accuracies {
            let workflow_id = workflows.complete_model_training_workflow(
                "accuracy-test-model",
                "accuracy-job",
                "accuracy-dataset",
                accuracy,
                "accuracy-tester@example.com"
            ).await.unwrap();
            
            assert!(workflow_id.starts_with("simple-signing-"));
        }
    }

    #[tokio::test]
    async fn test_approve_model_workflow_multiple_environments() {
        let config = TemporalNotaryConfig::default();
        let workflows = AFDPWorkflows::new(config).await.unwrap();
        
        let environments = vec![
            vec!["development"],
            vec!["staging", "production"],
            vec!["development", "staging", "production"],
            vec!["testing", "qa", "pre-prod", "production"],
        ];
        
        for (i, envs) in environments.into_iter().enumerate() {
            let workflow_id = workflows.approve_model_workflow(
                &format!("multi-env-approval-{}", i),
                "v1.0.0",
                "multi-approver@example.com",
                &format!("checklist-{}", i),
                envs
            ).await.unwrap();
            
            assert!(workflow_id.starts_with("approval-signing-"));
        }
    }

    #[tokio::test]
    async fn test_afdp_workflows_different_users() {
        let config = TemporalNotaryConfig::default();
        let workflows = AFDPWorkflows::new(config).await.unwrap();
        
        let users = vec![
            "alice@example.com",
            "bob@caiatech.com", 
            "charlie@test.org",
            "diana.smith@company.com",
        ];
        
        for user in users {
            let workflow_id = workflows.deploy_model_workflow(
                "user-specific-model",
                "v1.0.0",
                "staging",
                user
            ).await.unwrap();
            
            assert!(workflow_id.starts_with("simple-signing-"));
        }
    }

    #[tokio::test]
    async fn test_workflow_methods_with_special_characters() {
        let config = TemporalNotaryConfig::default();
        let workflows = AFDPWorkflows::new(config).await.unwrap();
        
        // Test with model IDs containing special characters
        let workflow_id = workflows.deploy_model_workflow(
            "model-with-hyphens_and_underscores.v2",
            "1.0.0-beta.1",
            "staging-env",
            "user.name+tag@example.com"
        ).await.unwrap();
        
        assert!(workflow_id.starts_with("simple-signing-"));
    }

    #[tokio::test]
    async fn test_batch_evidence_workflow_mixed_evidence_types() {
        use crate::{Actor, EvidencePackage, Artifact};
        
        let config = TemporalNotaryConfig::default();
        let workflows = AFDPWorkflows::new(config).await.unwrap();
        
        // Create evidence packages with different types
        let actor1 = Actor {
            actor_type: "deployment_system".to_string(),
            id: "deploy@example.com".to_string(),
            auth_provider: Some("afdp".to_string()),
        };
        let actor2 = Actor {
            actor_type: "human_user".to_string(),
            id: "approver@example.com".to_string(),
            auth_provider: Some("keycloak".to_string()),
        };
        
        let evidence1 = EvidencePackage::new("ai.model.deployment.completed".to_string(), actor1)
            .add_metadata("model_id".to_string(), serde_json::json!("model-1"));
        
        let evidence2 = EvidencePackage::new("ai.model.approval.granted".to_string(), actor2)
            .add_metadata("model_id".to_string(), serde_json::json!("model-2"))
            .add_artifact(Artifact {
                name: "approval-doc.pdf".to_string(),
                uri: Some("s3://bucket/approval.pdf".to_string()),
                hash_sha256: "abc123def456".to_string(),
            });
        
        let workflow_id = workflows.batch_evidence_workflow(
            vec![evidence1, evidence2]
        ).await.unwrap();
        
        assert!(workflow_id.starts_with("batch-signing-"));
    }
}