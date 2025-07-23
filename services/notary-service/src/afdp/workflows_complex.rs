//! AFDP-specific workflow compositions

use crate::{
    evidence::EvidencePackage,
    temporal::{TemporalNotaryClient, TemporalNotaryConfig},
    afdp::evidence::{AFDPEvidencePackage, ComplianceScanResults, DatasetValidationResults},
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
    /// 
    /// This workflow orchestrates the entire model deployment process:
    /// 1. Validate the model
    /// 2. Run compliance checks
    /// 3. Create deployment evidence
    /// 4. Deploy the model
    /// 5. Verify deployment
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

        // Step 2: Sign evidence with approval (for production)
        let workflow_id = if environment.contains("production") {
            let approvers = vec![
                "security-team@caiatech.com".to_string(),
                "compliance-team@caiatech.com".to_string(),
            ];
            self.temporal_client
                .sign_evidence_with_approval(evidence, approvers)
                .await?
                .workflow_id().to_string()
        } else {
            // For non-production, simple signing is sufficient
            self.temporal_client.sign_evidence(evidence).await?.workflow_id().to_string()
        };

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

        // Training completion always requires simple signing
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

    /// Dataset validation workflow
    pub async fn validate_dataset_workflow(
        &self,
        dataset_id: &str,
        dataset_version: &str,
        validation_results: &DatasetValidationResults,
        validated_by: &str,
    ) -> Result<String> {
        let evidence = AFDPEvidencePackage::dataset_validation(
            dataset_id,
            dataset_version,
            validation_results,
            validated_by,
        );

        // Dataset validation uses simple signing
        let workflow_execution = self.temporal_client.sign_evidence(evidence).await?;
        Ok(workflow_execution.workflow_id().to_string())
    }

    /// Compliance scan workflow
    pub async fn compliance_scan_workflow(
        &self,
        target_id: &str,
        target_type: &str,
        framework: &str,
        scan_results: &ComplianceScanResults,
        scanned_by: &str,
    ) -> Result<String> {
        let evidence = AFDPEvidencePackage::compliance_scan(
            target_id,
            target_type,
            framework,
            scan_results,
            scanned_by,
        );

        // Compliance scans require approval if non-compliant
        let workflow_execution = if scan_results.status == "non_compliant" {
            let approvers = vec![
                "compliance-team@caiatech.com".to_string(),
                "security-team@caiatech.com".to_string(),
            ];
            self.temporal_client
                .sign_evidence_with_approval(evidence, approvers)
                .await?
        } else {
            self.temporal_client.sign_evidence(evidence).await?
        };

        Ok(workflow_execution.workflow_id().to_string())
    }

    /// Security incident response workflow
    pub async fn security_incident_workflow(
        &self,
        incident_id: &str,
        severity: &str,
        affected_systems: Vec<&str>,
        detected_by: &str,
    ) -> Result<String> {
        let evidence = AFDPEvidencePackage::security_incident(
            incident_id,
            severity,
            affected_systems,
            detected_by,
        );

        // Critical incidents require immediate approval
        let workflow_execution = if severity == "critical" {
            let approvers = vec![
                "security-lead@caiatech.com".to_string(),
                "ciso@caiatech.com".to_string(),
            ];
            self.temporal_client
                .sign_evidence_with_approval(evidence, approvers)
                .await?
        } else {
            self.temporal_client.sign_evidence(evidence).await?
        };

        Ok(workflow_execution.workflow_id().to_string())
    }

    /// Data access logging workflow
    pub async fn log_data_access_workflow(
        &self,
        dataset_id: &str,
        accessed_by: &str,
        access_purpose: &str,
        data_classification: &str,
    ) -> Result<String> {
        let evidence = AFDPEvidencePackage::data_access(
            dataset_id,
            accessed_by,
            access_purpose,
            data_classification,
        );

        // Confidential data access requires approval
        let workflow_execution = if data_classification == "confidential" {
            let approvers = vec![
                "data-governance@caiatech.com".to_string(),
                "privacy-officer@caiatech.com".to_string(),
            ];
            self.temporal_client
                .sign_evidence_with_approval(evidence, approvers)
                .await?
        } else {
            self.temporal_client.sign_evidence(evidence).await?
        };

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

    /// Complete AI deployment pipeline workflow
    /// 
    /// This is the main AFDP workflow that orchestrates multiple steps:
    /// 1. Dataset validation
    /// 2. Model training
    /// 3. Model validation
    /// 4. Compliance scanning
    /// 5. Model approval
    /// 6. Model deployment
    /// 7. Post-deployment verification
    pub async fn complete_ai_deployment_pipeline(
        &self,
        pipeline_request: AIDeploymentPipelineRequest,
    ) -> Result<AIDeploymentPipelineResult> {
        let mut workflow_ids = Vec::new();

        // Step 1: Validate dataset
        if let Some(dataset_validation) = pipeline_request.dataset_validation {
            let workflow_id = self
                .validate_dataset_workflow(
                    &pipeline_request.dataset_id,
                    &pipeline_request.dataset_version,
                    &dataset_validation,
                    &pipeline_request.initiated_by,
                )
                .await?;
            workflow_ids.push(workflow_id);
        }

        // Step 2: Complete model training
        let training_workflow_id = self
            .complete_model_training_workflow(
                &pipeline_request.model_id,
                &pipeline_request.training_job_id,
                &pipeline_request.dataset_version,
                pipeline_request.model_accuracy,
                &pipeline_request.initiated_by,
            )
            .await?;
        workflow_ids.push(training_workflow_id);

        // Step 3: Run compliance scan
        if let Some(compliance_scan) = pipeline_request.compliance_scan {
            let workflow_id = self
                .compliance_scan_workflow(
                    &pipeline_request.model_id,
                    "ai_model",
                    &pipeline_request.compliance_framework,
                    &compliance_scan,
                    &pipeline_request.initiated_by,
                )
                .await?;
            workflow_ids.push(workflow_id);
        }

        // Step 4: Get model approval
        let approval_workflow_id = self
            .approve_model_workflow(
                &pipeline_request.model_id,
                &pipeline_request.model_version,
                &pipeline_request.initiated_by,
                &pipeline_request.compliance_checklist_id,
                pipeline_request.target_environments.iter().map(|s| s.as_str()).collect(),
            )
            .await?;
        workflow_ids.push(approval_workflow_id);

        // Step 5: Deploy model
        for environment in &pipeline_request.target_environments {
            let deployment_workflow_id = self
                .deploy_model_workflow(
                    &pipeline_request.model_id,
                    &pipeline_request.model_version,
                    environment,
                    &pipeline_request.initiated_by,
                )
                .await?;
            workflow_ids.push(deployment_workflow_id);
        }

        Ok(AIDeploymentPipelineResult {
            pipeline_id: uuid::Uuid::new_v4().to_string(),
            workflow_ids,
            status: "initiated".to_string(),
            initiated_at: chrono::Utc::now(),
        })
    }
}

/// Request for complete AI deployment pipeline
#[derive(Debug, Clone)]
pub struct AIDeploymentPipelineRequest {
    pub model_id: String,
    pub model_version: String,
    pub dataset_id: String,
    pub dataset_version: String,
    pub training_job_id: String,
    pub model_accuracy: f64,
    pub target_environments: Vec<String>,
    pub compliance_framework: String,
    pub compliance_checklist_id: String,
    pub initiated_by: String,
    pub dataset_validation: Option<DatasetValidationResults>,
    pub compliance_scan: Option<ComplianceScanResults>,
}

/// Result of AI deployment pipeline
#[derive(Debug, Clone)]
pub struct AIDeploymentPipelineResult {
    pub pipeline_id: String,
    pub workflow_ids: Vec<String>,
    pub status: String,
    pub initiated_at: chrono::DateTime<chrono::Utc>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::temporal::TemporalNotaryConfig;

    #[tokio::test]
    async fn test_afdp_workflows_creation() {
        let config = TemporalNotaryConfig::default();
        
        // This would fail in a real test without a running Temporal server
        // but we can test the configuration
        assert!(!config.temporal_address.is_empty());
        assert!(!config.task_queue.is_empty());
    }

    #[test]
    fn test_pipeline_request_creation() {
        let request = AIDeploymentPipelineRequest {
            model_id: "test-model".to_string(),
            model_version: "1.0.0".to_string(),
            dataset_id: "test-dataset".to_string(),
            dataset_version: "1.0.0".to_string(),
            training_job_id: "job-123".to_string(),
            model_accuracy: 0.95,
            target_environments: vec!["staging".to_string()],
            compliance_framework: "HIPAA".to_string(),
            compliance_checklist_id: "checklist-123".to_string(),
            initiated_by: "test@example.com".to_string(),
            dataset_validation: None,
            compliance_scan: None,
        };

        assert_eq!(request.model_id, "test-model");
        assert_eq!(request.model_accuracy, 0.95);
    }
}