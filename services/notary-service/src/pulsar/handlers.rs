//! Event handlers for processing Pulsar messages

use crate::error::Result;
use crate::pulsar::messages::{
    PipelineEvent, NotaryResult, NotaryStatus, NotaryError,
    WorkflowType, WorkflowStatusUpdate, ErrorType,
};
use crate::temporal::TemporalNotaryClient;
use async_trait::async_trait;
use std::sync::Arc;
use tracing::{info, error, debug};
use mockall::automock;

/// Event handler trait for processing pipeline events
#[automock]
#[async_trait]
pub trait EventHandler {
    /// Handle a pipeline event
    async fn handle_event(&self, event: PipelineEvent) -> Result<()>;
}

/// Default event handler implementation
pub struct DefaultEventHandler {
    /// Temporal client for workflow execution
    temporal_client: Arc<TemporalNotaryClient>,
    
    /// Pulsar producer for publishing results (optional)
    producer: Option<Arc<tokio::sync::Mutex<crate::pulsar::PulsarProducer>>>,
}

impl DefaultEventHandler {
    /// Create a new default event handler
    pub fn new(
        temporal_client: Arc<TemporalNotaryClient>,
        producer: Option<Arc<tokio::sync::Mutex<crate::pulsar::PulsarProducer>>>,
    ) -> Self {
        Self {
            temporal_client,
            producer,
        }
    }
    
    /// Process event based on workflow configuration
    async fn process_workflow(&self, event: &PipelineEvent) -> Result<String> {
        let evidence_package = event.to_evidence_package();
        
        match event.workflow_config.workflow_type {
            WorkflowType::SimpleSign => {
                info!("Starting simple signing workflow for event: {}", event.event_id);
                
                let result = self.temporal_client
                    .sign_evidence_sync(evidence_package)
                    .await?;
                
                Ok(format!("simple-signing-{}", uuid::Uuid::new_v4()))
            }
            
            WorkflowType::ApprovalSign => {
                info!("Starting approval signing workflow for event: {}", event.event_id);
                
                let execution = self.temporal_client
                    .sign_evidence_with_approval(
                        evidence_package,
                        event.workflow_config.approvers.clone(),
                    )
                    .await?;
                
                Ok(execution.workflow_id().to_string())
            }
            
            WorkflowType::BatchSign => {
                info!("Starting batch signing workflow for event: {}", event.event_id);
                
                // For single event, create a batch with one item
                let execution = self.temporal_client
                    .sign_evidence_batch(vec![evidence_package])
                    .await?;
                
                Ok(execution.workflow_id().to_string())
            }
            
            WorkflowType::Custom(workflow_name) => {
                error!("Custom workflow not implemented: {}", workflow_name);
                return Err(crate::error::NotaryError::ValidationError(
                    format!("Custom workflow not supported: {}", workflow_name)
                ));
            }
        }
    }
    
    /// Publish workflow status update
    async fn publish_status_update(
        &self,
        event_id: &str,
        workflow_id: &str,
        status: WorkflowStatusUpdate,
        message: String,
        trace_id: Option<String>,
    ) -> Result<()> {
        if let Some(producer) = &self.producer {
            let status_update = NotaryStatus {
                event_id: event_id.to_string(),
                workflow_id: workflow_id.to_string(),
                status,
                timestamp: chrono::Utc::now(),
                message,
                progress: None, // Could be enhanced to track actual progress
                trace_id,
            };
            
            let mut producer_guard = producer.lock().await;
            producer_guard.publish_status(&status_update).await?;
        }
        
        Ok(())
    }
    
    /// Publish error event
    async fn publish_error(
        &self,
        event_id: &str,
        workflow_id: Option<String>,
        error_type: ErrorType,
        message: String,
        trace_id: Option<String>,
    ) -> Result<()> {
        if let Some(producer) = &self.producer {
            let error_event = NotaryError {
                event_id: event_id.to_string(),
                workflow_id,
                timestamp: chrono::Utc::now(),
                error_type,
                message,
                details: std::collections::HashMap::new(),
                stack_trace: None,
                retry_count: 0,
                trace_id,
            };
            
            let mut producer_guard = producer.lock().await;
            producer_guard.publish_error(&error_event).await?;
        }
        
        Ok(())
    }
    
    /// Validate pipeline event
    fn validate_event(&self, event: &PipelineEvent) -> Result<()> {
        // Validate required fields
        if event.event_id.is_empty() {
            return Err(crate::error::NotaryError::ValidationError(
                "Event ID is required".to_string()
            ));
        }
        
        if event.source.is_empty() {
            return Err(crate::error::NotaryError::ValidationError(
                "Event source is required".to_string()
            ));
        }
        
        if event.actor.id.is_empty() {
            return Err(crate::error::NotaryError::ValidationError(
                "Actor ID is required".to_string()
            ));
        }
        
        // Validate workflow configuration
        match event.workflow_config.workflow_type {
            WorkflowType::ApprovalSign => {
                if event.workflow_config.approvers.is_empty() {
                    return Err(crate::error::NotaryError::ValidationError(
                        "Approval workflow requires at least one approver".to_string()
                    ));
                }
            }
            _ => {} // Other workflows don't need special validation
        }
        
        // Validate artifacts
        for artifact in &event.artifacts {
            if artifact.name.is_empty() {
                return Err(crate::error::NotaryError::ValidationError(
                    "Artifact name is required".to_string()
                ));
            }
            
            if artifact.hash_sha256.is_empty() {
                return Err(crate::error::NotaryError::ValidationError(
                    "Artifact hash is required".to_string()
                ));
            }
        }
        
        Ok(())
    }
}

#[async_trait]
impl EventHandler for DefaultEventHandler {
    async fn handle_event(&self, event: PipelineEvent) -> Result<()> {
        debug!("Handling pipeline event: {}", event.event_id);
        
        // Validate the event
        if let Err(validation_error) = self.validate_event(&event) {
            error!("Event validation failed for {}: {}", event.event_id, validation_error);
            
            self.publish_error(
                &event.event_id,
                None,
                ErrorType::Validation,
                format!("Event validation failed: {}", validation_error),
                event.trace_id.clone(),
            ).await?;
            
            return Err(validation_error);
        }
        
        // Publish status: received
        self.publish_status_update(
            &event.event_id,
            "pending",
            WorkflowStatusUpdate::Received,
            "Event received and validated".to_string(),
            event.trace_id.clone(),
        ).await?;
        
        // Process the workflow
        let start_time = std::time::Instant::now();
        
        match self.process_workflow(&event).await {
            Ok(workflow_id) => {
                let duration = start_time.elapsed();
                
                info!(
                    "Successfully started workflow {} for event {} ({}ms)",
                    workflow_id,
                    event.event_id,
                    duration.as_millis()
                );
                
                // Publish status: started
                self.publish_status_update(
                    &event.event_id,
                    &workflow_id,
                    WorkflowStatusUpdate::Started,
                    "Workflow started successfully".to_string(),
                    event.trace_id.clone(),
                ).await?;
                
                // For simple workflows, we can publish completion immediately
                // For approval workflows, status updates would come from Temporal
                if matches!(event.workflow_config.workflow_type, WorkflowType::SimpleSign) {
                    // Simulate processing time for demo
                    tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
                    
                    self.publish_status_update(
                        &event.event_id,
                        &workflow_id,
                        WorkflowStatusUpdate::Completed,
                        "Workflow completed successfully".to_string(),
                        event.trace_id.clone(),
                    ).await?;
                    
                    // Could also publish the final result here
                    if let Some(producer) = &self.producer {
                        let result = NotaryResult {
                            event_id: event.event_id.clone(),
                            workflow_id: workflow_id.clone(),
                            workflow_type: event.workflow_config.workflow_type.clone(),
                            timestamp: chrono::Utc::now(),
                            success: true,
                            error: None,
                            receipt: None, // Would be populated with actual receipt
                            processing_duration_ms: duration.as_millis() as u64,
                            trace_id: event.trace_id.clone(),
                            metadata: std::collections::HashMap::new(),
                        };
                        
                        let mut producer_guard = producer.lock().await;
                        producer_guard.publish_result(&result).await?;
                    }
                }
                
                Ok(())
            }
            
            Err(workflow_error) => {
                let duration = start_time.elapsed();
                
                error!(
                    "Failed to process workflow for event {} ({}ms): {}",
                    event.event_id,
                    duration.as_millis(),
                    workflow_error
                );
                
                // Publish status: failed
                self.publish_status_update(
                    &event.event_id,
                    "failed",
                    WorkflowStatusUpdate::Failed,
                    format!("Workflow failed: {}", workflow_error),
                    event.trace_id.clone(),
                ).await?;
                
                // Publish error event
                let error_type = match workflow_error {
                    crate::error::NotaryError::ValidationError(_) => ErrorType::Validation,
                    crate::error::NotaryError::AuthenticationError(_) => ErrorType::Authentication,
                    crate::error::NotaryError::VaultError(_) => ErrorType::Signing,
                    crate::error::NotaryError::RekorError(_) => ErrorType::Transparency,
                    crate::error::NotaryError::TemporalError(_) => ErrorType::Workflow,
                    crate::error::NotaryError::TransportError(_) => ErrorType::Network,
                    _ => ErrorType::Internal,
                };
                
                self.publish_error(
                    &event.event_id,
                    None,
                    error_type,
                    format!("Workflow processing failed: {}", workflow_error),
                    event.trace_id.clone(),
                ).await?;
                
                Err(workflow_error)
            }
        }
    }
}

/// Event handler that filters events based on criteria
pub struct FilteringEventHandler {
    /// Inner handler to delegate to
    inner: Arc<dyn EventHandler + Send + Sync>,
    
    /// Event types to process (None means all)
    allowed_event_types: Option<Vec<String>>,
    
    /// Sources to process (None means all)
    allowed_sources: Option<Vec<String>>,
    
    /// Minimum priority level
    min_priority: crate::pulsar::messages::EventPriority,
}

impl FilteringEventHandler {
    /// Create a new filtering event handler
    pub fn new(
        inner: Arc<dyn EventHandler + Send + Sync>,
        allowed_event_types: Option<Vec<String>>,
        allowed_sources: Option<Vec<String>>,
        min_priority: crate::pulsar::messages::EventPriority,
    ) -> Self {
        Self {
            inner,
            allowed_event_types,
            allowed_sources,
            min_priority,
        }
    }
    
    /// Check if event should be processed
    fn should_process(&self, event: &PipelineEvent) -> bool {
        // Check event type filter
        if let Some(allowed_types) = &self.allowed_event_types {
            let event_type_str = event.event_type_string();
            if !allowed_types.contains(&event_type_str) {
                debug!("Event {} filtered out by event type: {}", event.event_id, event_type_str);
                return false;
            }
        }
        
        // Check source filter
        if let Some(allowed_sources) = &self.allowed_sources {
            if !allowed_sources.contains(&event.source) {
                debug!("Event {} filtered out by source: {}", event.event_id, event.source);
                return false;
            }
        }
        
        // Check priority filter
        let priority_level = match event.priority {
            crate::pulsar::messages::EventPriority::Low => 1,
            crate::pulsar::messages::EventPriority::Normal => 2,
            crate::pulsar::messages::EventPriority::High => 3,
            crate::pulsar::messages::EventPriority::Critical => 4,
        };
        
        let min_level = match self.min_priority {
            crate::pulsar::messages::EventPriority::Low => 1,
            crate::pulsar::messages::EventPriority::Normal => 2,
            crate::pulsar::messages::EventPriority::High => 3,
            crate::pulsar::messages::EventPriority::Critical => 4,
        };
        
        if priority_level < min_level {
            debug!("Event {} filtered out by priority: {:?}", event.event_id, event.priority);
            return false;
        }
        
        true
    }
}

#[async_trait]
impl EventHandler for FilteringEventHandler {
    async fn handle_event(&self, event: PipelineEvent) -> Result<()> {
        if self.should_process(&event) {
            self.inner.handle_event(event).await
        } else {
            debug!("Event {} filtered out, skipping processing", event.event_id);
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pulsar::messages::{EventType, EventPriority, WorkflowConfig};
    use crate::evidence::Actor;
    use crate::temporal::TemporalNotaryConfig;
    use std::collections::HashMap;

    #[tokio::test]
    async fn test_default_handler_validation() {
        let temporal_config = TemporalNotaryConfig::default();
        let temporal_client = Arc::new(TemporalNotaryClient::new(temporal_config).await.unwrap());
        
        let handler = DefaultEventHandler::new(temporal_client, None);
        
        // Test valid event
        let valid_event = PipelineEvent {
            event_id: "test-123".to_string(),
            event_type: EventType::Custom("test".to_string()),
            timestamp: chrono::Utc::now(),
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
        
        assert!(handler.validate_event(&valid_event).is_ok());
        
        // Test invalid event (empty ID)
        let mut invalid_event = valid_event.clone();
        invalid_event.event_id = String::new();
        
        assert!(handler.validate_event(&invalid_event).is_err());
    }
    
    #[test]
    fn test_filtering_handler() {
        use mockall::predicate::*;
        
        let mut mock_handler = MockEventHandler::new();
        mock_handler
            .expect_handle_event()
            .with(always())
            .returning(|_| Ok(()));
        
        let filter = FilteringEventHandler::new(
            Arc::new(mock_handler),
            Some(vec!["ai.model.deployment".to_string()]),
            None,
            EventPriority::Normal,
        );
        
        let event = PipelineEvent {
            event_id: "test-123".to_string(),
            event_type: EventType::Custom("test".to_string()),
            timestamp: chrono::Utc::now(),
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
            priority: EventPriority::Low,
            workflow_config: WorkflowConfig::default(),
        };
        
        // This event should be filtered out due to priority
        assert!(!filter.should_process(&event));
    }
}