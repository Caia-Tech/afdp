//! AFDP-specific evidence package types and builders

use crate::{
    evidence::{Actor, Artifact, EvidencePackage},
    error::Result,
};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// AFDP-specific evidence package builder with predefined event types
pub struct AFDPEvidencePackage;

impl AFDPEvidencePackage {
    /// Create evidence for AI model deployment
    pub fn model_deployment(
        model_id: &str,
        model_version: &str,
        environment: &str,
        deployed_by: &str,
    ) -> EvidencePackage {
        let actor = Actor {
            actor_type: "deployment_system".to_string(),
            id: deployed_by.to_string(),
            auth_provider: Some("afdp".to_string()),
        };

        EvidencePackage::new("ai.model.deployment.completed".to_string(), actor)
            .add_metadata("model_id".to_string(), serde_json::json!(model_id))
            .add_metadata("model_version".to_string(), serde_json::json!(model_version))
            .add_metadata("environment".to_string(), serde_json::json!(environment))
            .add_metadata("deployment_type".to_string(), serde_json::json!("production"))
    }

    /// Create evidence for model training completion
    pub fn model_training(
        model_id: &str,
        training_job_id: &str,
        dataset_version: &str,
        accuracy: f64,
        trained_by: &str,
    ) -> EvidencePackage {
        let actor = Actor {
            actor_type: "training_system".to_string(),
            id: trained_by.to_string(),
            auth_provider: Some("afdp".to_string()),
        };

        EvidencePackage::new("ai.model.training.completed".to_string(), actor)
            .add_metadata("model_id".to_string(), serde_json::json!(model_id))
            .add_metadata("training_job_id".to_string(), serde_json::json!(training_job_id))
            .add_metadata("dataset_version".to_string(), serde_json::json!(dataset_version))
            .add_metadata("accuracy".to_string(), serde_json::json!(accuracy))
            .add_metadata("training_duration_seconds".to_string(), serde_json::json!(0))
    }

    /// Create evidence for model approval
    pub fn model_approval(
        model_id: &str,
        model_version: &str,
        approver: &str,
        compliance_checklist_id: &str,
        approved_environments: Vec<&str>,
    ) -> EvidencePackage {
        let actor = Actor {
            actor_type: "human_user".to_string(),
            id: approver.to_string(),
            auth_provider: Some("keycloak".to_string()),
        };

        EvidencePackage::new("ai.model.approval.granted".to_string(), actor)
            .add_metadata("model_id".to_string(), serde_json::json!(model_id))
            .add_metadata("model_version".to_string(), serde_json::json!(model_version))
            .add_metadata("compliance_checklist_id".to_string(), serde_json::json!(compliance_checklist_id))
            .add_metadata("approved_environments".to_string(), serde_json::json!(approved_environments))
            .add_metadata("approval_reason".to_string(), serde_json::json!("passed all compliance checks"))
    }

    /// Create evidence for dataset validation
    pub fn dataset_validation(
        dataset_id: &str,
        dataset_version: &str,
        validation_results: &DatasetValidationResults,
        validated_by: &str,
    ) -> EvidencePackage {
        let actor = Actor {
            actor_type: "validation_system".to_string(),
            id: validated_by.to_string(),
            auth_provider: Some("afdp".to_string()),
        };

        EvidencePackage::new("ai.dataset.validation.completed".to_string(), actor)
            .add_metadata("dataset_id".to_string(), serde_json::json!(dataset_id))
            .add_metadata("dataset_version".to_string(), serde_json::json!(dataset_version))
            .add_metadata("validation_results".to_string(), serde_json::json!(validation_results))
            .add_metadata("is_valid".to_string(), serde_json::json!(validation_results.is_valid))
    }

    /// Create evidence for compliance scan
    pub fn compliance_scan(
        target_id: &str,
        target_type: &str,
        framework: &str,
        scan_results: &ComplianceScanResults,
        scanned_by: &str,
    ) -> EvidencePackage {
        let actor = Actor {
            actor_type: "compliance_system".to_string(),
            id: scanned_by.to_string(),
            auth_provider: Some("afdp".to_string()),
        };

        EvidencePackage::new("compliance.scan.completed".to_string(), actor)
            .add_metadata("target_id".to_string(), serde_json::json!(target_id))
            .add_metadata("target_type".to_string(), serde_json::json!(target_type))
            .add_metadata("compliance_framework".to_string(), serde_json::json!(framework))
            .add_metadata("scan_results".to_string(), serde_json::json!(scan_results))
            .add_metadata("compliance_status".to_string(), serde_json::json!(scan_results.status))
    }

    /// Create evidence for security incident
    pub fn security_incident(
        incident_id: &str,
        severity: &str,
        affected_systems: Vec<&str>,
        detected_by: &str,
    ) -> EvidencePackage {
        let actor = Actor {
            actor_type: "security_system".to_string(),
            id: detected_by.to_string(),
            auth_provider: Some("afdp".to_string()),
        };

        EvidencePackage::new("security.incident.detected".to_string(), actor)
            .add_metadata("incident_id".to_string(), serde_json::json!(incident_id))
            .add_metadata("severity".to_string(), serde_json::json!(severity))
            .add_metadata("affected_systems".to_string(), serde_json::json!(affected_systems))
            .add_metadata("detection_time".to_string(), serde_json::json!(chrono::Utc::now()))
            .add_metadata("requires_immediate_action".to_string(), serde_json::json!(severity == "critical"))
    }

    /// Create evidence for data access
    pub fn data_access(
        dataset_id: &str,
        accessed_by: &str,
        access_purpose: &str,
        data_classification: &str,
    ) -> EvidencePackage {
        let actor = Actor {
            actor_type: "human_user".to_string(),
            id: accessed_by.to_string(),
            auth_provider: Some("keycloak".to_string()),
        };

        EvidencePackage::new("data.access.granted".to_string(), actor)
            .add_metadata("dataset_id".to_string(), serde_json::json!(dataset_id))
            .add_metadata("access_purpose".to_string(), serde_json::json!(access_purpose))
            .add_metadata("data_classification".to_string(), serde_json::json!(data_classification))
            .add_metadata("access_granted_at".to_string(), serde_json::json!(chrono::Utc::now()))
            .add_metadata("requires_audit".to_string(), serde_json::json!(data_classification == "confidential"))
    }

    /// Create evidence for configuration change
    pub fn configuration_change(
        component: &str,
        change_type: &str,
        changed_by: &str,
        change_details: &HashMap<String, serde_json::Value>,
    ) -> EvidencePackage {
        let actor = Actor {
            actor_type: "human_user".to_string(),
            id: changed_by.to_string(),
            auth_provider: Some("keycloak".to_string()),
        };

        let mut package = EvidencePackage::new("system.configuration.changed".to_string(), actor)
            .add_metadata("component".to_string(), serde_json::json!(component))
            .add_metadata("change_type".to_string(), serde_json::json!(change_type))
            .add_metadata("changed_at".to_string(), serde_json::json!(chrono::Utc::now()));

        // Add all change details as metadata
        for (key, value) in change_details {
            package = package.add_metadata(key.clone(), value.clone());
        }

        package
    }
}

/// Dataset validation results
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DatasetValidationResults {
    pub is_valid: bool,
    pub schema_validation: bool,
    pub data_quality_score: f64,
    pub missing_values_percentage: f64,
    pub duplicate_records_count: u64,
    pub validation_errors: Vec<String>,
    pub validation_warnings: Vec<String>,
}

/// Compliance scan results
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComplianceScanResults {
    pub status: String, // "compliant", "non_compliant", "warning"
    pub framework_version: String,
    pub scan_duration_seconds: u64,
    pub checks_passed: u32,
    pub checks_failed: u32,
    pub checks_skipped: u32,
    pub violations: Vec<ComplianceViolation>,
    pub recommendations: Vec<String>,
}

/// Individual compliance violation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComplianceViolation {
    pub rule_id: String,
    pub severity: String,
    pub description: String,
    pub remediation: String,
    pub affected_components: Vec<String>,
}

/// Builder for complex AFDP evidence packages
pub struct AFDPEvidenceBuilder {
    package: EvidencePackage,
}

impl AFDPEvidenceBuilder {
    /// Start building a custom AFDP evidence package
    pub fn new(event_type: &str, actor: Actor) -> Self {
        Self {
            package: EvidencePackage::new(event_type.to_string(), actor),
        }
    }

    /// Add an artifact to the evidence package
    pub fn with_artifact(mut self, name: &str, uri: Option<&str>, hash: &str) -> Self {
        let artifact = Artifact {
            name: name.to_string(),
            uri: uri.map(|s| s.to_string()),
            hash_sha256: hash.to_string(),
        };
        self.package = self.package.add_artifact(artifact);
        self
    }

    /// Add metadata to the evidence package
    pub fn with_metadata(mut self, key: &str, value: serde_json::Value) -> Self {
        self.package = self.package.add_metadata(key.to_string(), value);
        self
    }

    /// Add compliance information
    pub fn with_compliance_framework(self, framework: &str) -> Self {
        self.with_metadata("compliance_framework", serde_json::json!(framework))
    }

    /// Add risk assessment information
    pub fn with_risk_level(self, risk_level: &str) -> Self {
        self.with_metadata("risk_level", serde_json::json!(risk_level))
    }

    /// Add business justification
    pub fn with_business_justification(self, justification: &str) -> Self {
        self.with_metadata("business_justification", serde_json::json!(justification))
    }

    /// Add approval chain information
    pub fn with_approval_chain(self, approvers: Vec<&str>) -> Self {
        self.with_metadata("approval_chain", serde_json::json!(approvers))
    }

    /// Build the final evidence package
    pub fn build(self) -> EvidencePackage {
        self.package
    }
}

/// Trait for converting domain objects to evidence packages
pub trait ToEvidencePackage {
    fn to_evidence_package(&self, actor: Actor) -> Result<EvidencePackage>;
}

/// Example: Deploy a model and create evidence
pub fn example_model_deployment() -> EvidencePackage {
    AFDPEvidencePackage::model_deployment(
        "fraud-detector-v2",
        "2.1.0",
        "production-us-east-1",
        "marvin.tutt@caiatech.com",
    )
    .add_artifact(Artifact {
        name: "fraud_detector_v2.onnx".to_string(),
        uri: Some("s3://afdp-models/fraud_detector_v2.onnx".to_string()),
        hash_sha256: "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2".to_string(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_model_deployment_evidence() {
        let evidence = AFDPEvidencePackage::model_deployment(
            "test-model",
            "1.0.0",
            "staging",
            "test@example.com",
        );

        assert_eq!(evidence.event_type, "ai.model.deployment.completed");
        assert_eq!(evidence.actor.id, "test@example.com");
        assert!(evidence.metadata.contains_key("model_id"));
        assert!(evidence.metadata.contains_key("environment"));
    }

    #[test]
    fn test_evidence_builder() {
        let actor = Actor {
            actor_type: "test".to_string(),
            id: "test@example.com".to_string(),
            auth_provider: None,
        };

        let evidence = AFDPEvidenceBuilder::new("test.event", actor)
            .with_metadata("test_key", serde_json::json!("test_value"))
            .with_compliance_framework("HIPAA")
            .with_risk_level("medium")
            .build();

        assert_eq!(evidence.event_type, "test.event");
        assert!(evidence.metadata.contains_key("test_key"));
        assert!(evidence.metadata.contains_key("compliance_framework"));
        assert!(evidence.metadata.contains_key("risk_level"));
    }

    #[test]
    fn test_model_training_evidence() {
        let evidence = AFDPEvidencePackage::model_training(
            "neural-net-v1",
            "job-12345",
            "dataset-v2.1",
            0.95,
            "ml-engineer@example.com",
        );

        assert_eq!(evidence.event_type, "ai.model.training.completed");
        assert_eq!(evidence.actor.actor_type, "training_system");
        assert_eq!(evidence.actor.id, "ml-engineer@example.com");
        assert_eq!(evidence.actor.auth_provider, Some("afdp".to_string()));
        
        // Check metadata
        assert_eq!(evidence.metadata.get("model_id").unwrap(), &serde_json::json!("neural-net-v1"));
        assert_eq!(evidence.metadata.get("training_job_id").unwrap(), &serde_json::json!("job-12345"));
        assert_eq!(evidence.metadata.get("dataset_version").unwrap(), &serde_json::json!("dataset-v2.1"));
        assert_eq!(evidence.metadata.get("accuracy").unwrap(), &serde_json::json!(0.95));
    }

    #[test]
    fn test_model_approval_evidence() {
        let evidence = AFDPEvidencePackage::model_approval(
            "risk-model-v3",
            "v1.2.0",
            "alice@example.com",
            "checklist-123",
            vec!["production", "staging"],
        );

        assert_eq!(evidence.event_type, "ai.model.approval.granted");
        assert_eq!(evidence.actor.actor_type, "human_user");
        assert_eq!(evidence.actor.id, "alice@example.com");
        assert_eq!(evidence.actor.auth_provider, Some("keycloak".to_string()));
        
        assert_eq!(evidence.metadata.get("model_id").unwrap(), &serde_json::json!("risk-model-v3"));
        assert_eq!(evidence.metadata.get("model_version").unwrap(), &serde_json::json!("v1.2.0"));
        assert_eq!(evidence.metadata.get("compliance_checklist_id").unwrap(), &serde_json::json!("checklist-123"));
        assert_eq!(evidence.metadata.get("approved_environments").unwrap(), &serde_json::json!(vec!["production", "staging"]));
        assert_eq!(evidence.metadata.get("approval_reason").unwrap(), &serde_json::json!("passed all compliance checks"));
    }

    #[test]
    fn test_model_approval_evidence_single_environment() {
        let evidence = AFDPEvidencePackage::model_approval(
            "simple-model",
            "v0.1.0",
            "bob@example.com",
            "checklist-456",
            vec!["development"],
        );

        assert_eq!(evidence.event_type, "ai.model.approval.granted");
        assert_eq!(evidence.metadata.get("model_id").unwrap(), &serde_json::json!("simple-model"));
        assert_eq!(evidence.metadata.get("approved_environments").unwrap(), &serde_json::json!(vec!["development"]));
    }

    #[test]
    fn test_dataset_validation_evidence() {
        let validation_results = DatasetValidationResults {
            is_valid: true,
            schema_validation: true,
            data_quality_score: 0.95,
            missing_values_percentage: 2.1,
            duplicate_records_count: 5,
            validation_errors: vec![],
            validation_warnings: vec!["Minor data quality issues detected".to_string()],
        };

        let evidence = AFDPEvidencePackage::dataset_validation(
            "customer-data-v4",
            "v4.2",
            &validation_results,
            "data-team@example.com",
        );

        assert_eq!(evidence.event_type, "ai.dataset.validation.completed");
        assert_eq!(evidence.actor.actor_type, "validation_system");
        assert_eq!(evidence.actor.id, "data-team@example.com");
        
        assert_eq!(evidence.metadata.get("dataset_id").unwrap(), &serde_json::json!("customer-data-v4"));
        assert_eq!(evidence.metadata.get("dataset_version").unwrap(), &serde_json::json!("v4.2"));
        assert_eq!(evidence.metadata.get("is_valid").unwrap(), &serde_json::json!(true));
        
        // Check that validation results are serialized properly
        let results_value = evidence.metadata.get("validation_results").unwrap();
        assert!(results_value.is_object());
    }

    #[test]
    fn test_compliance_scan_evidence() {
        let scan_results = ComplianceScanResults {
            status: "compliant".to_string(),
            framework_version: "GDPR-2018".to_string(),
            scan_duration_seconds: 1200,
            checks_passed: 45,
            checks_failed: 0,
            checks_skipped: 2,
            violations: vec![],
            recommendations: vec!["Consider implementing additional data encryption".to_string()],
        };

        let evidence = AFDPEvidencePackage::compliance_scan(
            "user-service-v2",
            "microservice",
            "GDPR",
            &scan_results,
            "compliance@example.com",
        );

        assert_eq!(evidence.event_type, "compliance.scan.completed");
        assert_eq!(evidence.actor.actor_type, "compliance_system");
        assert_eq!(evidence.actor.id, "compliance@example.com");
        
        assert_eq!(evidence.metadata.get("target_id").unwrap(), &serde_json::json!("user-service-v2"));
        assert_eq!(evidence.metadata.get("target_type").unwrap(), &serde_json::json!("microservice"));
        assert_eq!(evidence.metadata.get("compliance_framework").unwrap(), &serde_json::json!("GDPR"));
        assert_eq!(evidence.metadata.get("compliance_status").unwrap(), &serde_json::json!("compliant"));
        
        // Check that scan results are serialized properly
        let results_value = evidence.metadata.get("scan_results").unwrap();
        assert!(results_value.is_object());
    }

    #[test]
    fn test_security_incident_evidence() {
        let evidence = AFDPEvidencePackage::security_incident(
            "INCIDENT-2024-001",
            "critical",
            vec!["user-service", "database-server"],
            "security-team@example.com",
        );

        assert_eq!(evidence.event_type, "security.incident.detected");
        assert_eq!(evidence.actor.actor_type, "security_system");
        assert_eq!(evidence.actor.id, "security-team@example.com");
        
        assert_eq!(evidence.metadata.get("incident_id").unwrap(), &serde_json::json!("INCIDENT-2024-001"));
        assert_eq!(evidence.metadata.get("severity").unwrap(), &serde_json::json!("critical"));
        assert_eq!(evidence.metadata.get("affected_systems").unwrap(), &serde_json::json!(vec!["user-service", "database-server"]));
        assert_eq!(evidence.metadata.get("requires_immediate_action").unwrap(), &serde_json::json!(true));
        
        // Check that detection_time was set
        assert!(evidence.metadata.contains_key("detection_time"));
    }

    #[test]
    fn test_data_access_evidence() {
        let evidence = AFDPEvidencePackage::data_access(
            "customer_pii_database",
            "analyst@example.com",
            "fraud_investigation",
            "confidential",
        );

        assert_eq!(evidence.event_type, "data.access.granted");
        assert_eq!(evidence.actor.actor_type, "human_user");
        assert_eq!(evidence.actor.id, "analyst@example.com");
        assert_eq!(evidence.actor.auth_provider, Some("keycloak".to_string()));
        
        assert_eq!(evidence.metadata.get("dataset_id").unwrap(), &serde_json::json!("customer_pii_database"));
        assert_eq!(evidence.metadata.get("access_purpose").unwrap(), &serde_json::json!("fraud_investigation"));
        assert_eq!(evidence.metadata.get("data_classification").unwrap(), &serde_json::json!("confidential"));
        assert_eq!(evidence.metadata.get("requires_audit").unwrap(), &serde_json::json!(true));
        
        // Check that access_granted_at was set
        assert!(evidence.metadata.contains_key("access_granted_at"));
    }

    #[test]
    fn test_configuration_change_evidence() {
        use std::collections::HashMap;
        
        let mut change_details = HashMap::new();
        change_details.insert("parameter_name".to_string(), serde_json::json!("feature_flags.enable_new_model"));
        change_details.insert("previous_value".to_string(), serde_json::json!("false"));
        change_details.insert("new_value".to_string(), serde_json::json!("true"));
        change_details.insert("change_reason".to_string(), serde_json::json!("Enable new ML model"));

        let evidence = AFDPEvidencePackage::configuration_change(
            "ml-pipeline-config",
            "feature_flag_update",
            "devops@example.com",
            &change_details,
        );

        assert_eq!(evidence.event_type, "system.configuration.changed");
        assert_eq!(evidence.actor.actor_type, "human_user");
        assert_eq!(evidence.actor.id, "devops@example.com");
        assert_eq!(evidence.actor.auth_provider, Some("keycloak".to_string()));
        
        assert_eq!(evidence.metadata.get("component").unwrap(), &serde_json::json!("ml-pipeline-config"));
        assert_eq!(evidence.metadata.get("change_type").unwrap(), &serde_json::json!("feature_flag_update"));
        
        // Check that individual change details were added as metadata
        assert_eq!(evidence.metadata.get("parameter_name").unwrap(), &serde_json::json!("feature_flags.enable_new_model"));
        assert_eq!(evidence.metadata.get("previous_value").unwrap(), &serde_json::json!("false"));
        assert_eq!(evidence.metadata.get("new_value").unwrap(), &serde_json::json!("true"));
        assert_eq!(evidence.metadata.get("change_reason").unwrap(), &serde_json::json!("Enable new ML model"));
        
        // Check that changed_at timestamp was set
        assert!(evidence.metadata.contains_key("changed_at"));
    }

    #[test]
    fn test_evidence_builder_with_artifact() {
        let actor = Actor {
            actor_type: "test".to_string(),
            id: "test@example.com".to_string(),
            auth_provider: None,
        };

        let evidence = AFDPEvidenceBuilder::new("artifact.test", actor)
            .with_artifact("model.pkl", Some("s3://bucket/model.pkl"), "abc123def456")
            .build();

        assert_eq!(evidence.artifacts.len(), 1);
        assert_eq!(evidence.artifacts[0].name, "model.pkl");
        assert_eq!(evidence.artifacts[0].uri, Some("s3://bucket/model.pkl".to_string()));
        assert_eq!(evidence.artifacts[0].hash_sha256, "abc123def456");
    }

    #[test]
    fn test_evidence_builder_with_artifact_no_uri() {
        let actor = Actor {
            actor_type: "test".to_string(),
            id: "test@example.com".to_string(),
            auth_provider: None,
        };

        let evidence = AFDPEvidenceBuilder::new("artifact.test", actor)
            .with_artifact("local_file.txt", None, "def456ghi789")
            .build();

        assert_eq!(evidence.artifacts.len(), 1);
        assert_eq!(evidence.artifacts[0].name, "local_file.txt");
        assert_eq!(evidence.artifacts[0].uri, None);
        assert_eq!(evidence.artifacts[0].hash_sha256, "def456ghi789");
    }

    #[test]
    fn test_evidence_builder_chaining() {
        let actor = Actor {
            actor_type: "test".to_string(),
            id: "test@example.com".to_string(),
            auth_provider: Some("auth_provider".to_string()),
        };

        let evidence = AFDPEvidenceBuilder::new("complex.test", actor)
            .with_metadata("key1", serde_json::json!("value1"))
            .with_metadata("key2", serde_json::json!(42))
            .with_compliance_framework("SOX")
            .with_risk_level("high")
            .with_business_justification("Required for financial reporting")
            .with_approval_chain(vec!["manager@example.com", "director@example.com"])
            .with_artifact("report.pdf", Some("file://reports/report.pdf"), "fedcba987654")
            .build();

        // Test all metadata was set
        assert_eq!(evidence.metadata.get("key1").unwrap(), &serde_json::json!("value1"));
        assert_eq!(evidence.metadata.get("key2").unwrap(), &serde_json::json!(42));
        assert_eq!(evidence.metadata.get("compliance_framework").unwrap(), &serde_json::json!("SOX"));
        assert_eq!(evidence.metadata.get("risk_level").unwrap(), &serde_json::json!("high"));
        assert_eq!(evidence.metadata.get("business_justification").unwrap(), &serde_json::json!("Required for financial reporting"));
        assert_eq!(evidence.metadata.get("approval_chain").unwrap(), 
                  &serde_json::json!(vec!["manager@example.com", "director@example.com"]));
        
        // Test artifact was added
        assert_eq!(evidence.artifacts.len(), 1);
        assert_eq!(evidence.artifacts[0].name, "report.pdf");
        assert_eq!(evidence.artifacts[0].uri, Some("file://reports/report.pdf".to_string()));
        assert_eq!(evidence.artifacts[0].hash_sha256, "fedcba987654");
    }

    #[test]
    fn test_example_model_deployment() {
        let evidence = example_model_deployment();

        assert_eq!(evidence.event_type, "ai.model.deployment.completed");
        assert_eq!(evidence.actor.id, "marvin.tutt@caiatech.com");
        assert_eq!(evidence.metadata.get("model_id").unwrap(), &serde_json::json!("fraud-detector-v2"));
        assert_eq!(evidence.metadata.get("model_version").unwrap(), &serde_json::json!("2.1.0"));
        assert_eq!(evidence.metadata.get("environment").unwrap(), &serde_json::json!("production-us-east-1"));
        
        // Should have the artifact
        assert_eq!(evidence.artifacts.len(), 1);
        assert_eq!(evidence.artifacts[0].name, "fraud_detector_v2.onnx");
        assert_eq!(evidence.artifacts[0].uri, Some("s3://afdp-models/fraud_detector_v2.onnx".to_string()));
    }

    #[test]
    fn test_evidence_builder_multiple_artifacts() {
        let actor = Actor {
            actor_type: "test".to_string(),
            id: "test@example.com".to_string(),
            auth_provider: None,
        };

        let evidence = AFDPEvidenceBuilder::new("multi.artifact.test", actor)
            .with_artifact("file1.txt", Some("s3://bucket/file1.txt"), "hash1")
            .with_artifact("file2.pdf", Some("s3://bucket/file2.pdf"), "hash2")
            .with_artifact("file3.json", None, "hash3")
            .build();

        assert_eq!(evidence.artifacts.len(), 3);
        assert_eq!(evidence.artifacts[0].name, "file1.txt");
        assert_eq!(evidence.artifacts[1].name, "file2.pdf");
        assert_eq!(evidence.artifacts[2].name, "file3.json");
        assert_eq!(evidence.artifacts[2].uri, None);
    }

    #[test]
    fn test_evidence_with_complex_metadata() {
        let actor = Actor {
            actor_type: "test".to_string(),
            id: "test@example.com".to_string(),
            auth_provider: None,
        };

        let complex_metadata = serde_json::json!({
            "nested": {
                "key": "value",
                "number": 123,
                "array": [1, 2, 3]
            },
            "boolean": true
        });

        let evidence = AFDPEvidenceBuilder::new("complex.metadata.test", actor)
            .with_metadata("complex_data", complex_metadata.clone())
            .build();

        assert_eq!(evidence.metadata.get("complex_data").unwrap(), &complex_metadata);
    }

    #[test]
    fn test_all_event_types() {
        use std::collections::HashMap;
        
        // Test that all AFDP evidence package methods create the correct event types
        let test_cases = vec![
            ("model_deployment", "ai.model.deployment.completed"),
            ("model_training", "ai.model.training.completed"),
            ("model_approval", "ai.model.approval.granted"),
            ("dataset_validation", "ai.dataset.validation.completed"),
            ("compliance_scan", "compliance.scan.completed"),
            ("security_incident", "security.incident.detected"),
            ("data_access", "data.access.granted"),
            ("configuration_change", "system.configuration.changed"),
        ];

        // Create test data structures
        let validation_results = DatasetValidationResults {
            is_valid: true,
            schema_validation: true,
            data_quality_score: 0.9,
            missing_values_percentage: 1.0,
            duplicate_records_count: 0,
            validation_errors: vec![],
            validation_warnings: vec![],
        };

        let scan_results = ComplianceScanResults {
            status: "compliant".to_string(),
            framework_version: "v1.0".to_string(),
            scan_duration_seconds: 60,
            checks_passed: 10,
            checks_failed: 0,
            checks_skipped: 0,
            violations: vec![],
            recommendations: vec![],
        };

        let mut change_details = HashMap::new();
        change_details.insert("test".to_string(), serde_json::json!("value"));

        for (method_name, expected_event_type) in test_cases {
            let evidence = match method_name {
                "model_deployment" => AFDPEvidencePackage::model_deployment("model", "1.0", "env", "user"),
                "model_training" => AFDPEvidencePackage::model_training("model", "job", "dataset", 0.9, "user"),
                "model_approval" => AFDPEvidencePackage::model_approval("model", "v1.0", "user", "checklist", vec!["env"]),
                "dataset_validation" => AFDPEvidencePackage::dataset_validation("dataset", "v1.0", &validation_results, "user"),
                "compliance_scan" => AFDPEvidencePackage::compliance_scan("system", "type", "framework", &scan_results, "user"),
                "security_incident" => AFDPEvidencePackage::security_incident("id", "high", vec!["system"], "user"),
                "data_access" => AFDPEvidencePackage::data_access("resource", "user", "purpose", "public"),
                "configuration_change" => AFDPEvidencePackage::configuration_change("target", "change", "user", &change_details),
                _ => panic!("Unknown method: {}", method_name),
            };
            
            assert_eq!(evidence.event_type, expected_event_type, "Method {} should create event type {}", method_name, expected_event_type);
        }
    }

    #[test]
    fn test_evidence_builder_empty_approval_chain() {
        let actor = Actor {
            actor_type: "test".to_string(),
            id: "test@example.com".to_string(),
            auth_provider: None,
        };

        let evidence = AFDPEvidenceBuilder::new("empty.approval.test", actor)
            .with_approval_chain(vec![])
            .build();

        assert_eq!(evidence.metadata.get("approval_chain").unwrap(), &serde_json::json!(Vec::<String>::new()));
    }
}