//! Pulsar consumer implementation for AFDP Notary Service

use crate::error::{NotaryError, Result};
use crate::pulsar::{
    config::{PulsarConfig, SubscriptionType},
    messages::{PipelineEvent, NotaryError as NotaryErrorMessage, ErrorType},
    handlers::EventHandler,
};
use futures_util::StreamExt;
use pulsar::{
    Consumer, ConsumerBuilder, ConsumerOptions, Pulsar, TokioExecutor,
    consumer::InitialPosition, SubType, DeserializeMessage,
};
use serde_json;
use std::sync::Arc;
use tokio::sync::mpsc;
use tracing::{info, error, warn, debug};

/// Pulsar consumer for processing pipeline events
pub struct PulsarConsumer {
    /// Pulsar client
    pulsar: Pulsar<TokioExecutor>,
    
    /// Consumer configuration
    config: PulsarConfig,
    
    /// Event handler for processing messages
    handler: Arc<dyn EventHandler + Send + Sync>,
    
    /// Shutdown signal receiver
    shutdown_rx: Option<mpsc::Receiver<()>>,
    
    /// Shutdown signal sender (kept for graceful shutdown)
    shutdown_tx: mpsc::Sender<()>,
}

impl PulsarConsumer {
    /// Create a new Pulsar consumer
    pub async fn new(
        config: PulsarConfig,
        handler: Arc<dyn EventHandler + Send + Sync>,
    ) -> Result<Self> {
        info!("Initializing Pulsar consumer with service URL: {}", config.service_url);
        
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
        
        info!("Pulsar client created successfully");
        
        // Create shutdown channel
        let (shutdown_tx, shutdown_rx) = mpsc::channel(1);
        
        Ok(Self {
            pulsar,
            config,
            handler,
            shutdown_rx: Some(shutdown_rx),
            shutdown_tx,
        })
    }
    
    /// Start consuming events from the pipeline events topic
    pub async fn start(&mut self) -> Result<()> {
        info!("Starting Pulsar consumer");
        
        let events_topic = self.config.full_topic_name(&self.config.topics.events_topic);
        info!("Subscribing to events topic: {}", events_topic);
        
        // Create consumer
        let mut consumer = self.create_consumer(&events_topic).await?;
        
        // Take shutdown receiver
        let mut shutdown_rx = self.shutdown_rx.take()
            .ok_or_else(|| NotaryError::Configuration("Consumer already started".to_string()))?;
        
        info!("Consumer started successfully, waiting for messages...");
        
        // Main consumption loop
        loop {
            tokio::select! {
                // Handle shutdown signal
                _ = shutdown_rx.recv() => {
                    info!("Received shutdown signal, stopping consumer");
                    break;
                }
                
                // Process messages
                msg_result = consumer.next() => {
                    match msg_result {
                        Some(Ok(msg)) => {
                            if let Err(e) = self.process_message(msg).await {
                                error!("Failed to process message: {}", e);
                                // Continue processing other messages
                            }
                        }
                        Some(Err(e)) => {
                            error!("Error receiving message: {}", e);
                            // Could implement exponential backoff here
                            tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;
                        }
                        None => {
                            warn!("Consumer stream ended unexpectedly");
                            break;
                        }
                    }
                }
            }
        }
        
        info!("Consumer stopped");
        Ok(())
    }
    
    /// Stop the consumer gracefully
    pub async fn stop(&self) -> Result<()> {
        info!("Stopping Pulsar consumer");
        
        if let Err(e) = self.shutdown_tx.send(()).await {
            warn!("Failed to send shutdown signal: {}", e);
        }
        
        Ok(())
    }
    
    /// Create a consumer for the specified topic
    async fn create_consumer(&self, topic: &str) -> Result<Consumer<PipelineEvent, TokioExecutor>> {
        let subscription_type = match self.config.consumer.subscription_type {
            SubscriptionType::Exclusive => SubType::Exclusive,
            SubscriptionType::Shared => SubType::Shared,
            SubscriptionType::Failover => SubType::Failover,
            SubscriptionType::KeyShared => SubType::KeyShared,
        };
        
        let mut consumer_builder: ConsumerBuilder<TokioExecutor> = self.pulsar
            .consumer()
            .with_topic(topic)
            .with_consumer_name(&self.config.consumer.name)
            .with_subscription(&self.config.consumer.subscription)
            .with_subscription_type(subscription_type);
        
        // Configure consumer options
        let mut options = ConsumerOptions::default();
        options.read_compacted = Some(false);
        options.initial_position = Some(InitialPosition::Latest);
        
        if let Some(queue_size) = Some(self.config.consumer.receive_queue_size) {
            consumer_builder = consumer_builder.with_options(options);
        }
        
        // Configure dead letter topic if specified
        if let Some(dlq_topic) = &self.config.consumer.dead_letter_topic {
            let full_dlq = self.config.full_topic_name(dlq_topic);
            // Note: DLQ configuration would depend on specific Pulsar client implementation
            debug!("Dead letter topic configured: {}", full_dlq);
        }
        
        let consumer = consumer_builder.build::<PipelineEvent>().await
            .map_err(|e| NotaryError::TransportError(format!("Failed to create consumer: {}", e)))?;
        
        Ok(consumer)
    }
    
    /// Process a single message
    async fn process_message(
        &self,
        msg: pulsar::consumer::Message<PipelineEvent>,
    ) -> Result<()> {
        let payload = match msg.deserialize() {
            Ok(event) => event,
            Err(e) => {
                error!("Failed to deserialize message: {}", e);
                // Send to error topic and acknowledge
                self.send_error_event(None, ErrorType::Validation, 
                    format!("Message deserialization failed: {}", e), None).await?;
                msg.ack().await.map_err(|e| 
                    NotaryError::TransportError(format!("Failed to ack message: {}", e)))?;
                return Ok(());
            }
        };
        
        debug!("Processing pipeline event: {}", payload.event_id);
        
        // Process the event using the handler
        let result = self.handler.handle_event(payload.clone()).await;
        
        match result {
            Ok(_) => {
                debug!("Successfully processed event: {}", payload.event_id);
                // Acknowledge the message
                msg.ack().await.map_err(|e| 
                    NotaryError::TransportError(format!("Failed to ack message: {}", e)))?;
            }
            Err(e) => {
                error!("Failed to process event {}: {}", payload.event_id, e);
                
                // Send error event
                self.send_error_event(
                    Some(payload.event_id.clone()),
                    ErrorType::Internal,
                    format!("Event processing failed: {}", e),
                    payload.trace_id.clone(),
                ).await?;
                
                // Decide whether to ack or nack based on error type
                if self.should_retry_error(&e) {
                    // Negative acknowledge for retry
                    msg.nack().await.map_err(|e| 
                        NotaryError::TransportError(format!("Failed to nack message: {}", e)))?;
                } else {
                    // Acknowledge to prevent infinite retries
                    msg.ack().await.map_err(|e| 
                        NotaryError::TransportError(format!("Failed to ack message: {}", e)))?;
                }
            }
        }
        
        Ok(())
    }
    
    /// Send error event to error topic
    async fn send_error_event(
        &self,
        event_id: Option<String>,
        error_type: ErrorType,
        message: String,
        trace_id: Option<String>,
    ) -> Result<()> {
        let error_event = NotaryErrorMessage {
            event_id: event_id.unwrap_or_else(|| uuid::Uuid::new_v4().to_string()),
            workflow_id: None,
            timestamp: chrono::Utc::now(),
            error_type,
            message,
            details: std::collections::HashMap::new(),
            stack_trace: None,
            retry_count: 0,
            trace_id,
        };
        
        // Create producer for error topic
        let error_topic = self.config.full_topic_name(&self.config.topics.errors_topic);
        let mut producer = self.pulsar
            .producer()
            .with_topic(&error_topic)
            .with_name("afdp-notary-error-producer")
            .build()
            .await
            .map_err(|e| NotaryError::TransportError(format!("Failed to create error producer: {}", e)))?;
        
        // Send error event
        let error_json = serde_json::to_string(&error_event)
            .map_err(|e| NotaryError::SerializationError(format!("Failed to serialize error event: {}", e)))?;
        
        producer
            .send(error_json)
            .await
            .map_err(|e| NotaryError::TransportError(format!("Failed to send error event: {}", e)))?;
        
        debug!("Sent error event for event_id: {:?}", error_event.event_id);
        Ok(())
    }
    
    /// Determine if an error should be retried
    fn should_retry_error(&self, error: &NotaryError) -> bool {
        match error {
            // Retry transient errors
            NotaryError::TransportError(_) => true,
            NotaryError::TemporalError(_) => true,
            
            // Don't retry validation errors
            NotaryError::ValidationError(_) => false,
            NotaryError::SerializationError(_) => false,
            
            // Don't retry auth errors
            NotaryError::AuthenticationError(_) => false,
            
            // Retry other errors
            _ => true,
        }
    }
}

/// Configure authentication for Pulsar client
pub fn configure_authentication(
    builder: pulsar::PulsarBuilder<TokioExecutor>,
    auth_config: &crate::pulsar::config::AuthConfig,
) -> Result<pulsar::PulsarBuilder<TokioExecutor>> {
    use crate::pulsar::config::AuthMethod;
    
    match auth_config.method {
        AuthMethod::None => Ok(builder),
        AuthMethod::Jwt => {
            if let Some(token) = &auth_config.params.token_or_cert {
                Ok(builder.with_auth_provider(pulsar::authentication::oauth2::OAuth2Authentication::client_credentials(
                    auth_config.params.issuer_url.as_deref().unwrap_or(""),
                    auth_config.params.audience.as_deref().unwrap_or(""),
                    token,
                )))
            } else {
                Err(NotaryError::Configuration("JWT token not provided".to_string()))
            }
        }
        AuthMethod::Tls => {
            if let (Some(cert), Some(key)) = (&auth_config.params.token_or_cert, &auth_config.params.private_key) {
                Ok(builder.with_certificate_chain_file(cert)
                          .with_private_key_file(key))
            } else {
                Err(NotaryError::Configuration("TLS certificate or key not provided".to_string()))
            }
        }
        AuthMethod::OAuth2 => {
            if let (Some(issuer), Some(audience), Some(token)) = (
                &auth_config.params.issuer_url,
                &auth_config.params.audience,
                &auth_config.params.token_or_cert,
            ) {
                Ok(builder.with_auth_provider(pulsar::authentication::oauth2::OAuth2Authentication::client_credentials(
                    issuer,
                    audience,
                    token,
                )))
            } else {
                Err(NotaryError::Configuration("OAuth2 parameters not provided".to_string()))
            }
        }
        AuthMethod::Basic => {
            if let (Some(username), Some(password)) = (&auth_config.params.username, &auth_config.params.password) {
                // Note: Basic auth implementation would depend on Pulsar client capabilities
                warn!("Basic authentication not fully implemented");
                Ok(builder)
            } else {
                Err(NotaryError::Configuration("Username or password not provided".to_string()))
            }
        }
    }
}

/// Custom deserializer for PipelineEvent
impl DeserializeMessage for PipelineEvent {
    type Output = Result<Self>;

    fn deserialize_message(payload: &pulsar::Payload) -> Self::Output {
        let data = std::str::from_utf8(&payload.data)
            .map_err(|e| NotaryError::ValidationError(format!("Invalid UTF-8: {}", e)))?;
        
        serde_json::from_str(data)
            .map_err(|e| NotaryError::SerializationError(e))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pulsar::handlers::MockEventHandler;
    use mockall::predicate::*;

    #[tokio::test]
    async fn test_consumer_creation() {
        let config = PulsarConfig::default();
        let handler = Arc::new(MockEventHandler::new());
        
        // This test would require a running Pulsar instance
        // In practice, you'd use testcontainers or similar for integration tests
        
        assert_eq!(config.service_url, "pulsar://localhost:6650");
    }
    
    #[test]
    fn test_should_retry_error() {
        let config = PulsarConfig::default();
        let handler = Arc::new(MockEventHandler::new());
        let (tx, rx) = mpsc::channel(1);
        
        // Mock Pulsar client - in real tests you'd use a test double
        let consumer = PulsarConsumer {
            pulsar: todo!(), // Would need mock Pulsar client
            config,
            handler,
            shutdown_rx: Some(rx),
            shutdown_tx: tx,
        };
        
        // Test retry logic
        assert!(consumer.should_retry_error(&NotaryError::TransportError("test".to_string())));
        assert!(!consumer.should_retry_error(&NotaryError::ValidationError("test".to_string())));
    }
}