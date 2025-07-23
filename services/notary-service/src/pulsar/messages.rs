//! Message types for Pulsar integration

use crate::evidence::{Actor, Artifact, EvidencePackage};
use crate::notary::NotarizationReceipt;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Pipeline event received from AI deployment systems
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PipelineEvent {
    /// Unique event identifier
    pub event_id: String,
    
    /// Event type (e.g., "model.deployment.completed")
    pub event_type: EventType,
    
    /// Timestamp when the event occurred
    pub timestamp: DateTime<Utc>,
    
    /// Source system that generated the event
    pub source: String,
    
    /// Actor responsible for the event
    pub actor: Actor,
    
    /// Artifacts associated with this event
    pub artifacts: Vec<Artifact>,
    
    /// Additional event metadata
    pub metadata: HashMap<String, serde_json::Value>,
    
    /// Tracing information for distributed systems
    pub trace_id: Option<String>,
    
    /// Span ID for tracing
    pub span_id: Option<String>,
    
    /// Priority level for processing
    pub priority: EventPriority,
    
    /// Workflow configuration for this event
    pub workflow_config: WorkflowConfig,
}

/// Types of events that can trigger notarization
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EventType {
    /// Model deployment events
    ModelDeployment(ModelDeploymentEvent),
    
    /// Data pipeline events
    DataPipeline(DataPipelineEvent),
    
    /// Inference events
    Inference(InferenceEvent),
    
    /// Compliance and audit events
    Compliance(ComplianceEvent),
    
    /// Custom event types
    Custom(String),
}

/// Model deployment specific event data
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModelDeploymentEvent {
    /// Model identifier
    pub model_id: String,
    
    /// Model version
    pub version: String,
    
    /// Deployment environment
    pub environment: String,
    
    /// Deployment strategy
    pub strategy: String,
    
    /// Previous version (for rollbacks)
    pub previous_version: Option<String>,
}

/// Data pipeline event data
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DataPipelineEvent {
    /// Pipeline identifier
    pub pipeline_id: String,
    
    /// Pipeline run ID
    pub run_id: String,
    
    /// Data sources processed
    pub data_sources: Vec<String>,
    
    /// Output datasets
    pub outputs: Vec<String>,
}

/// Inference event data
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InferenceEvent {
    /// Model used for inference
    pub model_id: String,
    
    /// Inference request ID
    pub request_id: String,
    
    /// Input data hash
    pub input_hash: String,
    
    /// Prediction result hash
    pub prediction_hash: String,
}

/// Compliance event data
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComplianceEvent {
    /// Compliance check type
    pub check_type: String,
    
    /// Compliance status
    pub status: String,
    
    /// Audit trail reference
    pub audit_ref: String,
}

/// Event processing priority
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum EventPriority {
    /// Low priority, can be processed when resources are available
    Low,
    /// Normal priority, processed in order
    Normal,
    /// High priority, expedited processing
    High,
    /// Critical priority, immediate processing required
    Critical,
}

/// Workflow configuration for event processing
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkflowConfig {
    /// Workflow type to use
    pub workflow_type: WorkflowType,
    
    /// Required approvers (for approval workflows)
    pub approvers: Vec<String>,
    
    /// Timeout for workflow completion
    pub timeout: Option<u64>,
    
    /// Retry configuration
    pub retry_config: RetryConfig,
    
    /// Notification settings
    pub notifications: NotificationConfig,
}

/// Types of workflows available
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WorkflowType {
    /// Simple signing workflow
    SimpleSign,
    
    /// Approval-based signing workflow
    ApprovalSign,
    
    /// Batch processing workflow
    BatchSign,
    
    /// Custom workflow
    Custom(String),
}

/// Retry configuration for failed workflows
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RetryConfig {
    /// Maximum number of retries
    pub max_retries: u32,
    
    /// Initial retry delay in seconds
    pub initial_delay: u64,
    
    /// Backoff multiplier
    pub backoff_multiplier: f64,
    
    /// Maximum retry delay in seconds
    pub max_delay: u64,
}

/// Notification configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NotificationConfig {
    /// Enable notifications
    pub enabled: bool,
    
    /// Notification channels
    pub channels: Vec<NotificationChannel>,
    
    /// Events that trigger notifications
    pub events: Vec<NotificationEvent>,
}

/// Notification channels
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NotificationChannel {
    /// Email notifications
    Email(Vec<String>),
    
    /// Slack notifications
    Slack(String),
    
    /// Webhook notifications
    Webhook(String),
    
    /// SMS notifications
    Sms(Vec<String>),
}

/// Events that can trigger notifications
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NotificationEvent {
    /// Workflow started
    WorkflowStarted,
    
    /// Workflow completed
    WorkflowCompleted,
    
    /// Workflow failed
    WorkflowFailed,
    
    /// Approval required
    ApprovalRequired,
    
    /// Approval received
    ApprovalReceived,
}

/// Notarization result published after workflow completion
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NotaryResult {
    /// Original event ID
    pub event_id: String,
    
    /// Workflow ID
    pub workflow_id: String,
    
    /// Workflow type used
    pub workflow_type: WorkflowType,
    
    /// Processing timestamp
    pub timestamp: DateTime<Utc>,
    
    /// Success status
    pub success: bool,
    
    /// Error message (if failed)
    pub error: Option<String>,
    
    /// Notarization receipt (if successful)
    pub receipt: Option<NotarizationReceipt>,
    
    /// Processing duration in milliseconds
    pub processing_duration_ms: u64,
    
    /// Tracing information
    pub trace_id: Option<String>,
    
    /// Additional result metadata
    pub metadata: HashMap<String, serde_json::Value>,
}

/// Workflow status update message
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NotaryStatus {
    /// Event ID
    pub event_id: String,
    
    /// Workflow ID
    pub workflow_id: String,
    
    /// Current status
    pub status: WorkflowStatusUpdate,
    
    /// Status timestamp
    pub timestamp: DateTime<Utc>,
    
    /// Status message
    pub message: String,
    
    /// Progress information
    pub progress: Option<WorkflowProgress>,
    
    /// Tracing information
    pub trace_id: Option<String>,
}

/// Workflow status types
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WorkflowStatusUpdate {
    /// Workflow received and queued
    Received,
    
    /// Workflow started processing
    Started,
    
    /// Waiting for approvals
    PendingApproval,
    
    /// Currently processing
    Processing,
    
    /// Waiting for external dependency
    Waiting,
    
    /// Successfully completed
    Completed,
    
    /// Failed with error
    Failed,
    
    /// Cancelled by user
    Cancelled,
    
    /// Timeout occurred
    Timeout,
}

/// Workflow progress information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkflowProgress {
    /// Current step
    pub current_step: String,
    
    /// Total steps
    pub total_steps: u32,
    
    /// Completed steps
    pub completed_steps: u32,
    
    /// Progress percentage (0-100)
    pub percentage: u8,
    
    /// Estimated time remaining (seconds)
    pub eta_seconds: Option<u64>,
}

/// Error event for failed processing
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NotaryError {
    /// Original event ID
    pub event_id: String,
    
    /// Workflow ID (if workflow was started)
    pub workflow_id: Option<String>,
    
    /// Error timestamp
    pub timestamp: DateTime<Utc>,
    
    /// Error type
    pub error_type: ErrorType,
    
    /// Error message
    pub message: String,
    
    /// Error details
    pub details: HashMap<String, serde_json::Value>,
    
    /// Stack trace (if available)
    pub stack_trace: Option<String>,
    
    /// Retry count
    pub retry_count: u32,
    
    /// Tracing information
    pub trace_id: Option<String>,
}

/// Types of errors that can occur
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ErrorType {
    /// Validation error in input data
    Validation,
    
    /// Authentication/authorization error
    Authentication,
    
    /// Temporal workflow error
    Workflow,
    
    /// Vault signing error
    Signing,
    
    /// Rekor integration error
    Transparency,
    
    /// Network/connectivity error
    Network,
    
    /// Configuration error
    Configuration,
    
    /// Internal system error
    Internal,
    
    /// Timeout error
    Timeout,
    
    /// Resource exhaustion
    Resource,
}

impl Default for EventPriority {
    fn default() -> Self {
        Self::Normal
    }
}

impl Default for WorkflowConfig {
    fn default() -> Self {
        Self {
            workflow_type: WorkflowType::SimpleSign,
            approvers: Vec::new(),
            timeout: Some(3600), // 1 hour default
            retry_config: RetryConfig::default(),
            notifications: NotificationConfig::default(),
        }
    }
}

impl Default for RetryConfig {
    fn default() -> Self {
        Self {
            max_retries: 3,
            initial_delay: 30,
            backoff_multiplier: 2.0,
            max_delay: 300, // 5 minutes
        }
    }
}

impl Default for NotificationConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            channels: Vec::new(),
            events: vec![
                NotificationEvent::WorkflowCompleted,
                NotificationEvent::WorkflowFailed,
            ],
        }
    }
}

impl PipelineEvent {
    /// Convert pipeline event to evidence package
    pub fn to_evidence_package(&self) -> EvidencePackage {
        EvidencePackage {
            spec_version: "1.0.0".to_string(),
            timestamp_utc: self.timestamp,
            event_type: self.event_type_string(),
            actor: self.actor.clone(),
            artifacts: self.artifacts.clone(),
            metadata: self.metadata.clone(),
        }
    }
    
    /// Get event type as string
    pub fn event_type_string(&self) -> String {
        match &self.event_type {
            EventType::ModelDeployment(_) => "ai.model.deployment".to_string(),
            EventType::DataPipeline(_) => "ai.data.pipeline".to_string(),
            EventType::Inference(_) => "ai.inference".to_string(),
            EventType::Compliance(_) => "ai.compliance".to_string(),
            EventType::Custom(name) => format!("ai.custom.{}", name),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pipeline_event_serialization() {
        let event = PipelineEvent {
            event_id: "test-123".to_string(),
            event_type: EventType::Custom("test".to_string()),
            timestamp: Utc::now(),
            source: "test-system".to_string(),
            actor: Actor {
                actor_type: "system".to_string(),
                id: "test-system".to_string(),
                auth_provider: None,
            },
            artifacts: Vec::new(),
            metadata: HashMap::new(),
            trace_id: None,
            span_id: None,
            priority: EventPriority::Normal,
            workflow_config: WorkflowConfig::default(),
        };
        
        let json = serde_json::to_string(&event).unwrap();
        let deserialized: PipelineEvent = serde_json::from_str(&json).unwrap();
        
        assert_eq!(event.event_id, deserialized.event_id);
        assert_eq!(event.source, deserialized.source);
    }
    
    #[test]
    fn test_event_type_string() {
        let mut event = PipelineEvent {
            event_id: "test".to_string(),
            event_type: EventType::ModelDeployment(ModelDeploymentEvent {
                model_id: "model-1".to_string(),
                version: "v1.0".to_string(),
                environment: "prod".to_string(),
                strategy: "blue-green".to_string(),
                previous_version: None,
            }),
            timestamp: Utc::now(),
            source: "test".to_string(),
            actor: Actor {
                actor_type: "system".to_string(),
                id: "test".to_string(),
                auth_provider: None,
            },
            artifacts: Vec::new(),
            metadata: HashMap::new(),
            trace_id: None,
            span_id: None,
            priority: EventPriority::Normal,
            workflow_config: WorkflowConfig::default(),
        };
        
        assert_eq!(event.event_type_string(), "ai.model.deployment");
        
        event.event_type = EventType::Custom("custom_event".to_string());
        assert_eq!(event.event_type_string(), "ai.custom.custom_event");
    }
}