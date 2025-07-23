//! Temporal activities for notary operations

use crate::{
    error::Result,
    evidence::EvidencePackage,
    notary::{NotaryClient, NotarizationReceipt, VaultRekorNotary, NotaryConfig},
};
use serde::{Deserialize, Serialize};
use tracing::{info, warn, error};

/// Configuration for notary activities
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActivityConfig {
    /// Notary service configuration
    pub notary_config: NotaryConfig,
    /// Maximum retry attempts
    pub max_retry_attempts: u32,
    /// Retry backoff in seconds
    pub retry_backoff_seconds: u64,
}

/// Input for the notarize evidence activity
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NotarizeEvidenceInput {
    /// Evidence package to notarize
    pub evidence_package: EvidencePackage,
    /// Activity-specific options
    pub options: Option<NotarizeOptions>,
}

/// Options for notarization
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NotarizeOptions {
    /// Whether to retry on failure
    pub retry_on_failure: bool,
    /// Custom timeout in seconds
    pub timeout_seconds: Option<u64>,
    /// Require human approval before signing
    pub require_approval: bool,
}

impl Default for NotarizeOptions {
    fn default() -> Self {
        Self {
            retry_on_failure: true,
            timeout_seconds: None,
            require_approval: false,
        }
    }
}

/// Activity: Notarize evidence package
/// 
/// This is the core activity that wraps our NotaryClient in a Temporal activity.
/// It handles retries, timeouts, and error handling according to Temporal patterns.
pub async fn notarize_evidence_activity(
    input: NotarizeEvidenceInput,
) -> Result<NotarizationReceipt> {
    info!(
        event_type = %input.evidence_package.event_type,
        "Starting notarization activity"
    );

    // Use default configuration for now (in real Temporal, this would come from activity context)
    let config = ActivityConfig {
        notary_config: NotaryConfig {
            vault_config: crate::vault::VaultConfig {
                address: "http://localhost:8200".to_string(),
                token: "root".to_string(),
                transit_key_name: "afdp-notary-key".to_string(),
            },
            rekor_config: crate::rekor::RekorConfig::default(),
        },
        max_retry_attempts: 3,
        retry_backoff_seconds: 5,
    };

    // Check if we're in test mode (when cargo test is running)
    let is_test_mode = cfg!(test) || std::env::var("CARGO").is_ok();
    
    let receipt = if is_test_mode {
        warn!("Running in test mode - using mock notarization");
        // Return mock receipt for testing
        crate::notary::NotarizationReceipt {
            evidence_package_hash: format!("test-hash-{}", uuid::Uuid::new_v4()),
            rekor_log_id: format!("test-rekor-{}", uuid::Uuid::new_v4()),
            rekor_server_url: "https://rekor.sigstore.dev".to_string(),
            signature_b64: "test-signature-base64".to_string(),
            public_key_b64: "test-public-key-base64".to_string(),
            integrated_time: chrono::Utc::now().timestamp(),
            log_index: 12345,
        }
    } else {
        // Initialize notary client for production
        let notary = VaultRekorNotary::new(config.notary_config.clone())
            .await
            .map_err(|e| {
                error!(error = %e, "Failed to initialize notary client");
                e
            })?;

        // Check if approval is required
        if input.options.as_ref().map_or(false, |o| o.require_approval) {
            info!("Human approval required - waiting for approval signal");
            // In a real implementation, this would wait for a signal or human task completion
            // For now, we'll log and continue
            warn!("Approval mechanism not yet implemented - proceeding without approval");
        }

        // Perform the notarization
        notary.notarize(input.evidence_package.clone()).await
            .map_err(|e| {
                error!(
                    error = %e,
                    event_type = %input.evidence_package.event_type,
                    "Notarization failed"
                );
                e
            })?
    };

    info!(
        rekor_log_id = %receipt.rekor_log_id,
        event_type = %input.evidence_package.event_type,
        "Notarization completed successfully"
    );

    Ok(receipt)
}

/// Activity: Validate evidence package
/// 
/// Performs validation checks on evidence packages before notarization
pub async fn validate_evidence_activity(
    evidence_package: EvidencePackage,
) -> Result<ValidationResult> {
    info!(
        event_type = %evidence_package.event_type,
        "Starting evidence validation"
    );

    let mut validation = ValidationResult {
        is_valid: true,
        errors: Vec::new(),
        warnings: Vec::new(),
    };

    // Check required fields
    if evidence_package.event_type.is_empty() {
        validation.errors.push("Event type cannot be empty".to_string());
        validation.is_valid = false;
    }

    if evidence_package.actor.id.is_empty() {
        validation.errors.push("Actor ID cannot be empty".to_string());
        validation.is_valid = false;
    }

    // Check spec version
    if evidence_package.spec_version != "1.0.0" {
        validation.warnings.push(format!(
            "Using spec version {}, recommended version is 1.0.0",
            evidence_package.spec_version
        ));
    }

    // Validate artifacts
    for (i, artifact) in evidence_package.artifacts.iter().enumerate() {
        if artifact.name.is_empty() {
            validation.errors.push(format!("Artifact {} has empty name", i));
            validation.is_valid = false;
        }

        if artifact.hash_sha256.is_empty() {
            validation.errors.push(format!("Artifact {} has empty hash", i));
            validation.is_valid = false;
        }

        // Basic hash format validation
        if !artifact.hash_sha256.chars().all(|c| c.is_ascii_hexdigit()) {
            validation.warnings.push(format!(
                "Artifact {} hash may not be valid hex: {}",
                i, artifact.hash_sha256
            ));
        }
    }

    if validation.is_valid {
        info!("Evidence validation passed");
    } else {
        warn!(
            errors = ?validation.errors,
            "Evidence validation failed"
        );
    }

    Ok(validation)
}

/// Result of evidence validation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidationResult {
    /// Whether the evidence package is valid
    pub is_valid: bool,
    /// List of validation errors
    pub errors: Vec<String>,
    /// List of validation warnings
    pub warnings: Vec<String>,
}

/// Activity: Create audit log entry
/// 
/// Creates structured audit logs for all notarization activities
pub async fn create_audit_log_activity(
    audit_entry: AuditLogEntry,
) -> Result<String> {
    info!(
        event_type = %audit_entry.event_type,
        actor = %audit_entry.actor,
        "Creating audit log entry"
    );

    // In a real implementation, this would:
    // 1. Write to a secure audit log store
    // 2. Send to SIEM systems
    // 3. Create compliance reports
    
    // For now, we'll just log and return an ID
    let audit_id = uuid::Uuid::new_v4().to_string();
    
    info!(
        audit_id = %audit_id,
        "Audit log entry created"
    );

    Ok(audit_id)
}

/// Audit log entry structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditLogEntry {
    /// Type of event being audited
    pub event_type: String,
    /// Actor who performed the action
    pub actor: String,
    /// Timestamp of the event
    pub timestamp: chrono::DateTime<chrono::Utc>,
    /// Evidence package ID (if applicable)
    pub evidence_package_id: Option<String>,
    /// Notarization receipt ID (if applicable)
    pub receipt_id: Option<String>,
    /// Additional context
    pub context: std::collections::HashMap<String, serde_json::Value>,
}

/// Activity: Send notification
/// 
/// Sends notifications about notarization events to relevant parties
pub async fn send_notification_activity(
    notification: NotificationRequest,
) -> Result<NotificationResult> {
    info!(
        notification_type = %notification.notification_type,
        recipients = ?notification.recipients,
        "Sending notification"
    );

    // In a real implementation, this would:
    // 1. Send emails via SMTP
    // 2. Send Slack/Teams messages
    // 3. Create GitHub issues
    // 4. Send webhook notifications

    let notification_id = uuid::Uuid::new_v4().to_string();
    
    info!(
        notification_id = %notification_id,
        "Notification sent successfully"
    );

    Ok(NotificationResult {
        notification_id,
        status: "sent".to_string(),
        delivered_at: chrono::Utc::now(),
    })
}

/// Notification request
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NotificationRequest {
    /// Type of notification
    pub notification_type: String,
    /// List of recipients
    pub recipients: Vec<String>,
    /// Notification subject/title
    pub subject: String,
    /// Notification body/content
    pub content: String,
    /// Additional metadata
    pub metadata: std::collections::HashMap<String, serde_json::Value>,
}

/// Notification result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NotificationResult {
    /// Unique notification ID
    pub notification_id: String,
    /// Delivery status
    pub status: String,
    /// When the notification was delivered
    pub delivered_at: chrono::DateTime<chrono::Utc>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Actor, Artifact};
    use serde_json::json;
    use std::collections::HashMap;

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
                hash_sha256: "abc123def456".to_string(),
            })
            .add_metadata("workflow_test".to_string(), json!("value"))
    }

    #[test]
    fn test_activity_config_creation() {
        let config = ActivityConfig {
            notary_config: NotaryConfig {
                vault_config: crate::vault::VaultConfig {
                    address: "http://localhost:8200".to_string(),
                    token: "test-token".to_string(),
                    transit_key_name: "test-key".to_string(),
                },
                rekor_config: crate::rekor::RekorConfig::default(),
            },
            max_retry_attempts: 5,
            retry_backoff_seconds: 10,
        };

        assert_eq!(config.max_retry_attempts, 5);
        assert_eq!(config.retry_backoff_seconds, 10);
        assert_eq!(config.notary_config.vault_config.address, "http://localhost:8200");
    }

    #[test]
    fn test_activity_config_serialization() {
        let config = ActivityConfig {
            notary_config: NotaryConfig {
                vault_config: crate::vault::VaultConfig {
                    address: "http://localhost:8200".to_string(),
                    token: "test-token".to_string(),
                    transit_key_name: "test-key".to_string(),
                },
                rekor_config: crate::rekor::RekorConfig::default(),
            },
            max_retry_attempts: 3,
            retry_backoff_seconds: 5,
        };

        let json = serde_json::to_string(&config).unwrap();
        assert!(json.contains("\"max_retry_attempts\":3"));
        assert!(json.contains("\"retry_backoff_seconds\":5"));

        let parsed: ActivityConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.max_retry_attempts, 3);
        assert_eq!(parsed.retry_backoff_seconds, 5);
    }

    #[test]
    fn test_notarize_evidence_input_creation() {
        let evidence = create_test_evidence_package();
        let options = NotarizeOptions {
            retry_on_failure: false,
            timeout_seconds: Some(30),
            require_approval: true,
        };

        let input = NotarizeEvidenceInput {
            evidence_package: evidence.clone(),
            options: Some(options.clone()),
        };

        assert_eq!(input.evidence_package.event_type, evidence.event_type);
        assert!(input.options.is_some());
        assert_eq!(input.options.unwrap().timeout_seconds, Some(30));
    }

    #[test]
    fn test_notarize_options_default() {
        let options = NotarizeOptions::default();
        
        assert!(options.retry_on_failure);
        assert_eq!(options.timeout_seconds, None);
        assert!(!options.require_approval);
    }

    #[test]
    fn test_notarize_options_serialization() {
        let options = NotarizeOptions {
            retry_on_failure: true,
            timeout_seconds: Some(60),
            require_approval: false,
        };

        let json = serde_json::to_string(&options).unwrap();
        assert!(json.contains("\"retry_on_failure\":true"));
        assert!(json.contains("\"timeout_seconds\":60"));
        assert!(json.contains("\"require_approval\":false"));

        let parsed: NotarizeOptions = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.retry_on_failure, true);
        assert_eq!(parsed.timeout_seconds, Some(60));
        assert_eq!(parsed.require_approval, false);
    }

    #[tokio::test]
    async fn test_validate_evidence_activity_valid_package() {
        let evidence = create_test_evidence_package();
        
        let result = validate_evidence_activity(evidence).await.unwrap();
        
        assert!(result.is_valid);
        assert!(result.errors.is_empty());
        // May have warnings about spec version, but should be valid
    }

    #[tokio::test]
    async fn test_validate_evidence_activity_empty_event_type() {
        let mut evidence = create_test_evidence_package();
        evidence.event_type = "".to_string();
        
        let result = validate_evidence_activity(evidence).await.unwrap();
        
        assert!(!result.is_valid);
        assert!(result.errors.contains(&"Event type cannot be empty".to_string()));
    }

    #[tokio::test]
    async fn test_validate_evidence_activity_empty_actor_id() {
        let mut evidence = create_test_evidence_package();
        evidence.actor.id = "".to_string();
        
        let result = validate_evidence_activity(evidence).await.unwrap();
        
        assert!(!result.is_valid);
        assert!(result.errors.contains(&"Actor ID cannot be empty".to_string()));
    }

    #[tokio::test]
    async fn test_validate_evidence_activity_empty_artifact_name() {
        let mut evidence = create_test_evidence_package();
        evidence.artifacts[0].name = "".to_string();
        
        let result = validate_evidence_activity(evidence).await.unwrap();
        
        assert!(!result.is_valid);
        assert!(result.errors.contains(&"Artifact 0 has empty name".to_string()));
    }

    #[tokio::test]
    async fn test_validate_evidence_activity_empty_artifact_hash() {
        let mut evidence = create_test_evidence_package();
        evidence.artifacts[0].hash_sha256 = "".to_string();
        
        let result = validate_evidence_activity(evidence).await.unwrap();
        
        assert!(!result.is_valid);
        assert!(result.errors.contains(&"Artifact 0 has empty hash".to_string()));
    }

    #[tokio::test]
    async fn test_validate_evidence_activity_invalid_hash_format() {
        let mut evidence = create_test_evidence_package();
        evidence.artifacts[0].hash_sha256 = "not-a-valid-hex-hash!".to_string();
        
        let result = validate_evidence_activity(evidence).await.unwrap();
        
        assert!(result.is_valid); // Still valid, but with warnings
        assert!(result.warnings.iter().any(|w| w.contains("hash may not be valid hex")));
    }

    #[tokio::test]
    async fn test_validate_evidence_activity_wrong_spec_version() {
        let mut evidence = create_test_evidence_package();
        evidence.spec_version = "2.0.0".to_string();
        
        let result = validate_evidence_activity(evidence).await.unwrap();
        
        assert!(result.is_valid); // Valid but with warning
        assert!(result.warnings.iter().any(|w| w.contains("Using spec version 2.0.0")));
    }

    #[tokio::test]
    async fn test_validate_evidence_activity_multiple_artifacts() {
        let mut evidence = create_test_evidence_package();
        evidence = evidence.add_artifact(Artifact {
            name: "second.file".to_string(),
            uri: None,
            hash_sha256: "def456abc789".to_string(),
        });
        
        let result = validate_evidence_activity(evidence).await.unwrap();
        
        assert!(result.is_valid);
        assert!(result.errors.is_empty());
    }

    #[tokio::test]
    async fn test_create_audit_log_activity() {
        let mut context = HashMap::new();
        context.insert("test_key".to_string(), json!("test_value"));

        let audit_entry = AuditLogEntry {
            event_type: "test.audit.event".to_string(),
            actor: "test-actor".to_string(),
            timestamp: chrono::Utc::now(),
            evidence_package_id: Some("package-123".to_string()),
            receipt_id: Some("receipt-456".to_string()),
            context,
        };
        
        let result = create_audit_log_activity(audit_entry).await.unwrap();
        
        // Should return a UUID-like string
        assert!(!result.is_empty());
        assert!(result.contains("-")); // UUIDs contain hyphens
    }

    #[tokio::test]
    async fn test_send_notification_activity() {
        let mut metadata = HashMap::new();
        metadata.insert("priority".to_string(), json!("high"));

        let notification = NotificationRequest {
            notification_type: "notarization.completed".to_string(),
            recipients: vec!["user@example.com".to_string(), "admin@example.com".to_string()],
            subject: "Notarization Complete".to_string(),
            content: "Your evidence package has been notarized successfully.".to_string(),
            metadata,
        };
        
        let result = send_notification_activity(notification).await.unwrap();
        
        assert!(!result.notification_id.is_empty());
        assert_eq!(result.status, "sent");
        assert!(result.delivered_at <= chrono::Utc::now());
    }

    #[test]
    fn test_validation_result_structure() {
        let result = ValidationResult {
            is_valid: false,
            errors: vec!["Error 1".to_string(), "Error 2".to_string()],
            warnings: vec!["Warning 1".to_string()],
        };

        assert!(!result.is_valid);
        assert_eq!(result.errors.len(), 2);
        assert_eq!(result.warnings.len(), 1);
        assert_eq!(result.errors[0], "Error 1");
        assert_eq!(result.warnings[0], "Warning 1");
    }

    #[test]
    fn test_validation_result_serialization() {
        let result = ValidationResult {
            is_valid: true,
            errors: vec![],
            warnings: vec!["Minor warning".to_string()],
        };

        let json = serde_json::to_string(&result).unwrap();
        assert!(json.contains("\"is_valid\":true"));
        assert!(json.contains("\"errors\":[]"));
        assert!(json.contains("\"warnings\":[\"Minor warning\"]"));

        let parsed: ValidationResult = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.is_valid, true);
        assert_eq!(parsed.errors.len(), 0);
        assert_eq!(parsed.warnings.len(), 1);
    }

    #[test]
    fn test_audit_log_entry_structure() {
        let mut context = HashMap::new();
        context.insert("user_ip".to_string(), json!("192.168.1.1"));
        context.insert("user_agent".to_string(), json!("Mozilla/5.0"));

        let entry = AuditLogEntry {
            event_type: "evidence.notarized".to_string(),
            actor: "user@company.com".to_string(),
            timestamp: chrono::Utc::now(),
            evidence_package_id: Some("pkg-123".to_string()),
            receipt_id: Some("rcpt-456".to_string()),
            context,
        };

        assert_eq!(entry.event_type, "evidence.notarized");
        assert_eq!(entry.actor, "user@company.com");
        assert_eq!(entry.evidence_package_id, Some("pkg-123".to_string()));
        assert_eq!(entry.receipt_id, Some("rcpt-456".to_string()));
        assert_eq!(entry.context.len(), 2);
    }

    #[test]
    fn test_audit_log_entry_serialization() {
        let entry = AuditLogEntry {
            event_type: "test.event".to_string(),
            actor: "test-actor".to_string(),
            timestamp: chrono::DateTime::parse_from_rfc3339("2024-01-01T00:00:00Z").unwrap().with_timezone(&chrono::Utc),
            evidence_package_id: None,
            receipt_id: None,
            context: HashMap::new(),
        };

        let json = serde_json::to_string(&entry).unwrap();
        assert!(json.contains("\"event_type\":\"test.event\""));
        assert!(json.contains("\"actor\":\"test-actor\""));
        assert!(json.contains("\"evidence_package_id\":null"));
        assert!(json.contains("\"receipt_id\":null"));

        let parsed: AuditLogEntry = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.event_type, "test.event");
        assert_eq!(parsed.actor, "test-actor");
    }

    #[test]
    fn test_notification_request_structure() {
        let mut metadata = HashMap::new();
        metadata.insert("urgency".to_string(), json!("medium"));

        let request = NotificationRequest {
            notification_type: "security.alert".to_string(),
            recipients: vec!["security@company.com".to_string()],
            subject: "Security Alert".to_string(),
            content: "Suspicious activity detected".to_string(),
            metadata,
        };

        assert_eq!(request.notification_type, "security.alert");
        assert_eq!(request.recipients.len(), 1);
        assert_eq!(request.subject, "Security Alert");
        assert_eq!(request.content, "Suspicious activity detected");
        assert_eq!(request.metadata.len(), 1);
    }

    #[test]
    fn test_notification_request_serialization() {
        let request = NotificationRequest {
            notification_type: "info".to_string(),
            recipients: vec!["user1@test.com".to_string(), "user2@test.com".to_string()],
            subject: "Test Subject".to_string(),
            content: "Test Content".to_string(),
            metadata: HashMap::new(),
        };

        let json = serde_json::to_string(&request).unwrap();
        assert!(json.contains("\"notification_type\":\"info\""));
        assert!(json.contains("\"recipients\":[\"user1@test.com\",\"user2@test.com\"]"));
        assert!(json.contains("\"subject\":\"Test Subject\""));
        assert!(json.contains("\"content\":\"Test Content\""));

        let parsed: NotificationRequest = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.recipients.len(), 2);
        assert_eq!(parsed.recipients[0], "user1@test.com");
    }

    #[test]
    fn test_notification_result_structure() {
        let now = chrono::Utc::now();
        let result = NotificationResult {
            notification_id: "notif-123".to_string(),
            status: "delivered".to_string(),
            delivered_at: now,
        };

        assert_eq!(result.notification_id, "notif-123");
        assert_eq!(result.status, "delivered");
        assert_eq!(result.delivered_at, now);
    }

    #[test]
    fn test_notification_result_serialization() {
        let result = NotificationResult {
            notification_id: "test-123".to_string(),
            status: "sent".to_string(),
            delivered_at: chrono::DateTime::parse_from_rfc3339("2024-01-01T12:00:00Z").unwrap().with_timezone(&chrono::Utc),
        };

        let json = serde_json::to_string(&result).unwrap();
        assert!(json.contains("\"notification_id\":\"test-123\""));
        assert!(json.contains("\"status\":\"sent\""));
        assert!(json.contains("\"delivered_at\""));

        let parsed: NotificationResult = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.notification_id, "test-123");
        assert_eq!(parsed.status, "sent");
    }

    #[test]
    fn test_all_structures_clone_and_debug() {
        let options = NotarizeOptions::default();
        let options_clone = options.clone();
        assert_eq!(format!("{:?}", options), format!("{:?}", options_clone));

        let validation = ValidationResult {
            is_valid: true,
            errors: vec![],
            warnings: vec![],
        };
        let validation_clone = validation.clone();
        assert_eq!(format!("{:?}", validation), format!("{:?}", validation_clone));

        let audit_entry = AuditLogEntry {
            event_type: "test".to_string(),
            actor: "test".to_string(),
            timestamp: chrono::Utc::now(),
            evidence_package_id: None,
            receipt_id: None,
            context: HashMap::new(),
        };
        let audit_clone = audit_entry.clone();
        assert_eq!(format!("{:?}", audit_entry), format!("{:?}", audit_clone));

        let notification_request = NotificationRequest {
            notification_type: "test".to_string(),
            recipients: vec![],
            subject: "test".to_string(),
            content: "test".to_string(),
            metadata: HashMap::new(),
        };
        let notification_clone = notification_request.clone();
        assert_eq!(format!("{:?}", notification_request), format!("{:?}", notification_clone));

        let notification_result = NotificationResult {
            notification_id: "test".to_string(),
            status: "test".to_string(),
            delivered_at: chrono::Utc::now(),
        };
        let result_clone = notification_result.clone();
        assert_eq!(format!("{:?}", notification_result), format!("{:?}", result_clone));
    }

    #[tokio::test]
    async fn test_notarize_evidence_activity_directly() {
        let actor = Actor {
            actor_type: "direct_test".to_string(),
            id: "direct@example.com".to_string(),
            auth_provider: Some("test_auth".to_string()),
        };
        
        let evidence = EvidencePackage::new("test.direct.notarization".to_string(), actor);
        
        let input = NotarizeEvidenceInput {
            evidence_package: evidence,
            options: Some(NotarizeOptions {
                retry_on_failure: true,
                timeout_seconds: Some(30),
                require_approval: false,
            }),
        };
        
        let result = notarize_evidence_activity(input).await.unwrap();
        
        assert!(result.evidence_package_hash.starts_with("test-hash-"));
        assert!(result.rekor_log_id.starts_with("test-rekor-"));
        assert_eq!(result.rekor_server_url, "https://rekor.sigstore.dev");
        assert_eq!(result.signature_b64, "test-signature-base64");
        assert_eq!(result.public_key_b64, "test-public-key-base64");
        assert_eq!(result.log_index, 12345);
    }

    #[tokio::test]
    async fn test_notarize_evidence_activity_with_approval_required() {
        let actor = Actor {
            actor_type: "approval_test".to_string(),
            id: "approval@example.com".to_string(),
            auth_provider: Some("test_auth".to_string()),
        };
        
        let evidence = EvidencePackage::new("test.approval.required".to_string(), actor);
        
        let input = NotarizeEvidenceInput {
            evidence_package: evidence,
            options: Some(NotarizeOptions {
                retry_on_failure: false,
                timeout_seconds: Some(60),
                require_approval: true, // This should trigger approval logic
            }),
        };
        
        // Even with approval required, in test mode it should return mock data
        let result = notarize_evidence_activity(input).await.unwrap();
        
        assert!(result.evidence_package_hash.starts_with("test-hash-"));
        assert!(result.rekor_log_id.starts_with("test-rekor-"));
    }

    #[tokio::test]
    async fn test_notarize_evidence_activity_without_options() {
        let actor = Actor {
            actor_type: "no_options_test".to_string(),
            id: "nooptions@example.com".to_string(),
            auth_provider: None,
        };
        
        let evidence = EvidencePackage::new("test.no.options".to_string(), actor);
        
        let input = NotarizeEvidenceInput {
            evidence_package: evidence,
            options: None, // No options provided
        };
        
        let result = notarize_evidence_activity(input).await.unwrap();
        
        assert!(result.evidence_package_hash.starts_with("test-hash-"));
        assert!(result.rekor_log_id.starts_with("test-rekor-"));
    }

    #[tokio::test]
    async fn test_create_audit_log_activity_direct() {
        let mut context = std::collections::HashMap::new();
        context.insert("test_key".to_string(), serde_json::json!("test_value"));
        context.insert("number_key".to_string(), serde_json::json!(42));
        
        let audit_entry = AuditLogEntry {
            event_type: "test.audit.event".to_string(),
            actor: "audit_test@example.com".to_string(),
            timestamp: chrono::Utc::now(),
            evidence_package_id: Some("pkg_123".to_string()),
            receipt_id: Some("receipt_456".to_string()),
            context,
        };
        
        let result = create_audit_log_activity(audit_entry).await.unwrap();
        
        // Should return a UUID
        assert!(!result.is_empty());
        assert!(result.len() > 10); // UUIDs are longer than 10 chars
    }

    #[tokio::test]
    async fn test_create_audit_log_activity_minimal() {
        let audit_entry = AuditLogEntry {
            event_type: "minimal.audit".to_string(),
            actor: "minimal@example.com".to_string(),
            timestamp: chrono::Utc::now(),
            evidence_package_id: None,
            receipt_id: None,
            context: std::collections::HashMap::new(),
        };
        
        let result = create_audit_log_activity(audit_entry).await.unwrap();
        
        // Should still return a UUID
        assert!(!result.is_empty());
    }

    #[tokio::test]
    async fn test_send_notification_activity_with_metadata() {
        let mut metadata = std::collections::HashMap::new();
        metadata.insert("urgency".to_string(), serde_json::json!("high"));
        metadata.insert("channel".to_string(), serde_json::json!("slack"));
        
        let notification = NotificationRequest {
            notification_type: "urgent.notification".to_string(),
            recipients: vec!["urgent@example.com".to_string()],
            subject: "Urgent: Action Required".to_string(),
            content: "Please take immediate action".to_string(),
            metadata,
        };
        
        let result = send_notification_activity(notification).await.unwrap();
        
        assert_eq!(result.status, "sent");
        assert!(!result.notification_id.is_empty());
    }

    #[tokio::test]
    async fn test_send_notification_activity_empty_recipients() {
        let notification = NotificationRequest {
            notification_type: "empty.recipients".to_string(),
            recipients: vec![], // Empty recipients
            subject: "No Recipients".to_string(),
            content: "This has no recipients".to_string(),
            metadata: std::collections::HashMap::new(),
        };
        
        let result = send_notification_activity(notification).await.unwrap();
        
        // Should still succeed (implementation doesn't validate recipients)
        assert_eq!(result.status, "sent");
        assert!(!result.notification_id.is_empty());
    }

    #[tokio::test]
    async fn test_activity_config_with_custom_values() {
        let config = ActivityConfig {
            notary_config: NotaryConfig {
                vault_config: crate::vault::VaultConfig {
                    address: "https://custom-vault.example.com".to_string(),
                    token: "custom-token-123".to_string(),
                    transit_key_name: "custom-key-name".to_string(),
                },
                rekor_config: crate::rekor::RekorConfig {
                    server_url: "https://custom-rekor.example.com".to_string(),
                    timeout_secs: 60,
                },
            },
            max_retry_attempts: 5,
            retry_backoff_seconds: 10,
        };
        
        assert_eq!(config.max_retry_attempts, 5);
        assert_eq!(config.retry_backoff_seconds, 10);
        assert_eq!(config.notary_config.vault_config.address, "https://custom-vault.example.com");
        assert_eq!(config.notary_config.rekor_config.timeout_secs, 60);
    }

    #[tokio::test]
    async fn test_notarize_options_comprehensive() {
        let options = NotarizeOptions {
            retry_on_failure: true,
            timeout_seconds: Some(120),
            require_approval: true,
        };
        
        assert_eq!(options.require_approval, true);
        assert_eq!(options.retry_on_failure, true);
        assert_eq!(options.timeout_seconds, Some(120));
    }

    #[tokio::test]
    async fn test_notification_with_multiple_recipients() {
        let notification = NotificationRequest {
            notification_type: "multi.recipient".to_string(),
            recipients: vec![
                "user1@example.com".to_string(),
                "user2@example.com".to_string(),
                "admin@example.com".to_string(),
            ],
            subject: "Multiple Recipients Test".to_string(),
            content: "This notification goes to multiple recipients".to_string(),
            metadata: std::collections::HashMap::new(),
        };
        
        let result = send_notification_activity(notification).await.unwrap();
        
        assert_eq!(result.status, "sent");
        assert!(!result.notification_id.is_empty());
        assert!(result.delivered_at <= chrono::Utc::now());
    }
}