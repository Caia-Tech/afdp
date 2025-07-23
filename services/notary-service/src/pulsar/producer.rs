//! Pulsar producer implementation for AFDP Notary Service

use crate::error::{NotaryError, Result};
use crate::pulsar::{
    config::{PulsarConfig, CompressionType},
    messages::{NotaryResult, NotaryStatus, NotaryError as NotaryErrorMessage},
};
use pulsar::{Producer, Pulsar, TokioExecutor, SerializeMessage, Payload};
use serde_json;
use std::collections::HashMap;
use tracing::{info, error, debug};

/// Pulsar producer for publishing notary results and status updates
pub struct PulsarProducer {
    /// Pulsar client
    pulsar: Pulsar<TokioExecutor>,
    
    /// Producer configuration
    config: PulsarConfig,
    
    /// Producer for results topic
    results_producer: Option<Producer<TokioExecutor>>,
    
    /// Producer for status topic
    status_producer: Option<Producer<TokioExecutor>>,
    
    /// Producer for errors topic
    errors_producer: Option<Producer<TokioExecutor>>,
}

impl PulsarProducer {
    /// Create a new Pulsar producer
    pub async fn new(config: PulsarConfig) -> Result<Self> {
        info!("Initializing Pulsar producer with service URL: {}", config.service_url);
        
        // Create Pulsar client
        let mut builder = Pulsar::builder(&config.service_url, TokioExecutor);
        
        // Configure authentication if provided
        if let Some(auth_config) = &config.auth {
            builder = crate::pulsar::consumer::configure_authentication(builder, auth_config)?;
        }
        
        // Configure TLS if enabled
        if config.connection.tls_enabled {
            builder = builder.with_allow_insecure_connection(false);
        }
        
        let pulsar = builder.build().await
            .map_err(|e| NotaryError::TransportError(format!("Failed to create Pulsar client: {}", e)))?;
        
        info!("Pulsar producer client created successfully");
        
        Ok(Self {
            pulsar,
            config,
            results_producer: None,
            status_producer: None,
            errors_producer: None,
        })
    }
    
    /// Initialize all producers
    pub async fn initialize(&mut self) -> Result<()> {
        info!("Initializing Pulsar producers");
        
        // Create results producer
        let results_topic = self.config.full_topic_name(&self.config.topics.results_topic);
        self.results_producer = Some(self.create_producer(&results_topic, "results").await?);
        
        // Create status producer
        let status_topic = self.config.full_topic_name(&self.config.topics.status_topic);
        self.status_producer = Some(self.create_producer(&status_topic, "status").await?);
        
        // Create errors producer
        let errors_topic = self.config.full_topic_name(&self.config.topics.errors_topic);
        self.errors_producer = Some(self.create_producer(&errors_topic, "errors").await?);
        
        info!("All Pulsar producers initialized successfully");
        Ok(())
    }
    
    /// Publish a notarization result
    pub async fn publish_result(&mut self, result: &NotaryResult) -> Result<()> {
        debug!("Publishing notary result for event: {}", result.event_id);
        
        let producer = self.results_producer.as_mut()
            .ok_or_else(|| NotaryError::Configuration("Results producer not initialized".to_string()))?;
        
        let message = NotaryResultMessage::new(result.clone())?;
        
        producer.send(message).await
            .map_err(|e| NotaryError::TransportError(format!("Failed to publish result: {}", e)))?;
        
        info!("Published notary result for event: {}", result.event_id);
        Ok(())
    }
    
    /// Publish a workflow status update
    pub async fn publish_status(&mut self, status: &NotaryStatus) -> Result<()> {
        debug!("Publishing status update for workflow: {}", status.workflow_id);
        
        let producer = self.status_producer.as_mut()
            .ok_or_else(|| NotaryError::Configuration("Status producer not initialized".to_string()))?;
        
        let message = NotaryStatusMessage::new(status.clone())?;
        
        producer.send(message).await
            .map_err(|e| NotaryError::TransportError(format!("Failed to publish status: {}", e)))?;
        
        debug!("Published status update for workflow: {}", status.workflow_id);
        Ok(())
    }
    
    /// Publish an error event
    pub async fn publish_error(&mut self, error: &NotaryErrorMessage) -> Result<()> {
        debug!("Publishing error event for event: {}", error.event_id);
        
        let producer = self.errors_producer.as_mut()
            .ok_or_else(|| NotaryError::Configuration("Errors producer not initialized".to_string()))?;
        
        let message = NotaryErrorMessageWrapper::new(error.clone())?;
        
        producer.send(message).await
            .map_err(|e| NotaryError::TransportError(format!("Failed to publish error: {}", e)))?;
        
        debug!("Published error event for event: {}", error.event_id);
        Ok(())
    }
    
    /// Create a producer for the specified topic
    async fn create_producer(&self, topic: &str, producer_type: &str) -> Result<Producer<TokioExecutor>> {
        let producer_name = format!("{}-{}", self.config.producer.name, producer_type);
        
        let mut producer_builder = self.pulsar
            .producer()
            .with_topic(topic)
            .with_name(&producer_name);
        
        // Configure compression
        let compression = match self.config.producer.compression {
            CompressionType::None => pulsar::producer::CompressionType::None,
            CompressionType::Lz4 => pulsar::producer::CompressionType::Lz4,
            CompressionType::Zlib => pulsar::producer::CompressionType::Zlib,
            CompressionType::Zstd => pulsar::producer::CompressionType::Zstd,
            CompressionType::Snappy => pulsar::producer::CompressionType::Snappy,
        };
        producer_builder = producer_builder.with_compression(compression);
        
        // Configure batching if enabled
        if self.config.producer.batching.enabled {
            producer_builder = producer_builder
                .with_batch_size(Some(self.config.producer.batching.max_messages))
                .with_max_delay_ms(Some(self.config.producer.batching.max_delay.as_millis() as u64));
        }
        
        let producer = producer_builder.build().await
            .map_err(|e| NotaryError::TransportError(format!("Failed to create {} producer: {}", producer_type, e)))?;
        
        info!("Created {} producer for topic: {}", producer_type, topic);
        Ok(producer)
    }
    
    /// Close all producers gracefully
    pub async fn close(&mut self) -> Result<()> {
        info!("Closing Pulsar producers");
        
        // Close individual producers
        if let Some(mut producer) = self.results_producer.take() {
            producer.close().await
                .map_err(|e| NotaryError::TransportError(format!("Failed to close results producer: {}", e)))?;
        }
        
        if let Some(mut producer) = self.status_producer.take() {
            producer.close().await
                .map_err(|e| NotaryError::TransportError(format!("Failed to close status producer: {}", e)))?;
        }
        
        if let Some(mut producer) = self.errors_producer.take() {
            producer.close().await
                .map_err(|e| NotaryError::TransportError(format!("Failed to close errors producer: {}", e)))?;
        }
        
        info!("All Pulsar producers closed");
        Ok(())
    }
}

/// Wrapper for NotaryResult to implement SerializeMessage
#[derive(Debug, Clone)]
struct NotaryResultMessage {
    data: NotaryResult,
    json: String,
}

impl NotaryResultMessage {
    fn new(data: NotaryResult) -> Result<Self> {
        let json = serde_json::to_string(&data)
            .map_err(NotaryError::SerializationError)?;
        
        Ok(Self { data, json })
    }
}

impl SerializeMessage for NotaryResultMessage {
    fn serialize_message(input: Self) -> Result<Payload, pulsar::Error> {
        let mut properties = HashMap::new();
        properties.insert("event_id".to_string(), input.data.event_id.clone());
        properties.insert("workflow_id".to_string(), input.data.workflow_id.clone());
        properties.insert("success".to_string(), input.data.success.to_string());
        properties.insert("message_type".to_string(), "notary_result".to_string());
        
        if let Some(trace_id) = &input.data.trace_id {
            properties.insert("trace_id".to_string(), trace_id.clone());
        }
        
        Ok(Payload {
            data: input.json.into_bytes(),
            metadata: properties,
            ..Default::default()
        })
    }
}

/// Wrapper for NotaryStatus to implement SerializeMessage
#[derive(Debug, Clone)]
struct NotaryStatusMessage {
    data: NotaryStatus,
    json: String,
}

impl NotaryStatusMessage {
    fn new(data: NotaryStatus) -> Result<Self> {
        let json = serde_json::to_string(&data)
            .map_err(NotaryError::SerializationError)?;
        
        Ok(Self { data, json })
    }
}

impl SerializeMessage for NotaryStatusMessage {
    fn serialize_message(input: Self) -> Result<Payload, pulsar::Error> {
        let mut properties = HashMap::new();
        properties.insert("event_id".to_string(), input.data.event_id.clone());
        properties.insert("workflow_id".to_string(), input.data.workflow_id.clone());
        properties.insert("status".to_string(), format!("{:?}", input.data.status));
        properties.insert("message_type".to_string(), "notary_status".to_string());
        
        if let Some(trace_id) = &input.data.trace_id {
            properties.insert("trace_id".to_string(), trace_id.clone());
        }
        
        Ok(Payload {
            data: input.json.into_bytes(),
            metadata: properties,
            ..Default::default()
        })
    }
}

/// Wrapper for NotaryError to implement SerializeMessage
#[derive(Debug, Clone)]
struct NotaryErrorMessageWrapper {
    data: NotaryErrorMessage,
    json: String,
}

impl NotaryErrorMessageWrapper {
    fn new(data: NotaryErrorMessage) -> Result<Self> {
        let json = serde_json::to_string(&data)
            .map_err(NotaryError::SerializationError)?;
        
        Ok(Self { data, json })
    }
}

impl SerializeMessage for NotaryErrorMessageWrapper {
    fn serialize_message(input: Self) -> Result<Payload, pulsar::Error> {
        let mut properties = HashMap::new();
        properties.insert("event_id".to_string(), input.data.event_id.clone());
        properties.insert("error_type".to_string(), format!("{:?}", input.data.error_type));
        properties.insert("retry_count".to_string(), input.data.retry_count.to_string());
        properties.insert("message_type".to_string(), "notary_error".to_string());
        
        if let Some(workflow_id) = &input.data.workflow_id {
            properties.insert("workflow_id".to_string(), workflow_id.clone());
        }
        
        if let Some(trace_id) = &input.data.trace_id {
            properties.insert("trace_id".to_string(), trace_id.clone());
        }
        
        Ok(Payload {
            data: input.json.into_bytes(),
            metadata: properties,
            ..Default::default()
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pulsar::messages::{WorkflowType, WorkflowStatusUpdate};
    use chrono::Utc;

    #[test]
    fn test_notary_result_message_serialization() {
        let result = NotaryResult {
            event_id: "test-123".to_string(),
            workflow_id: "wf-456".to_string(),
            workflow_type: WorkflowType::SimpleSign,
            timestamp: Utc::now(),
            success: true,
            error: None,
            receipt: None,
            processing_duration_ms: 1500,
            trace_id: Some("trace-789".to_string()),
            metadata: HashMap::new(),
        };
        
        let message = NotaryResultMessage::new(result).unwrap();
        assert!(message.json.contains("test-123"));
        assert!(message.json.contains("wf-456"));
    }
    
    #[test]
    fn test_notary_status_message_serialization() {
        let status = NotaryStatus {
            event_id: "test-123".to_string(),
            workflow_id: "wf-456".to_string(),
            status: WorkflowStatusUpdate::Processing,
            timestamp: Utc::now(),
            message: "Processing evidence".to_string(),
            progress: None,
            trace_id: Some("trace-789".to_string()),
        };
        
        let message = NotaryStatusMessage::new(status).unwrap();
        assert!(message.json.contains("test-123"));
        assert!(message.json.contains("Processing evidence"));
    }
    
    #[tokio::test]
    async fn test_producer_creation() {
        let config = PulsarConfig::default();
        
        // This test would require a running Pulsar instance
        // In practice, you'd use testcontainers or similar for integration tests
        
        assert_eq!(config.service_url, "pulsar://localhost:6650");
        assert_eq!(config.producer.name, "afdp-notary-producer");
    }
}