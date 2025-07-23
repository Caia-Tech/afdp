//! Pulsar configuration for AFDP Notary Service

use serde::{Deserialize, Serialize};
use std::time::Duration;

/// Configuration for Apache Pulsar integration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PulsarConfig {
    /// Pulsar service URL (e.g., "pulsar://localhost:6650")
    pub service_url: String,
    
    /// Consumer configuration
    pub consumer: ConsumerConfig,
    
    /// Producer configuration
    pub producer: ProducerConfig,
    
    /// Topic configuration
    pub topics: TopicConfig,
    
    /// Authentication configuration (optional)
    pub auth: Option<AuthConfig>,
    
    /// Connection settings
    pub connection: ConnectionConfig,
}

/// Consumer-specific configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConsumerConfig {
    /// Consumer name for identification
    pub name: String,
    
    /// Subscription name for the consumer group
    pub subscription: String,
    
    /// Subscription type (Exclusive, Shared, Failover, KeyShared)
    pub subscription_type: SubscriptionType,
    
    /// Consumer receive queue size
    pub receive_queue_size: u32,
    
    /// Batch receive configuration
    pub batch_receive: BatchReceiveConfig,
    
    /// Dead letter topic configuration
    pub dead_letter_topic: Option<String>,
    
    /// Maximum number of redeliveries before moving to DLQ
    pub max_redeliveries: Option<u32>,
}

/// Producer-specific configuration  
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProducerConfig {
    /// Producer name for identification
    pub name: String,
    
    /// Send timeout duration
    pub send_timeout: Duration,
    
    /// Batch configuration
    pub batching: BatchingConfig,
    
    /// Compression type
    pub compression: CompressionType,
    
    /// Block if queue is full
    pub block_if_full: bool,
}

/// Topic configuration for AFDP integration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TopicConfig {
    /// Topic for incoming pipeline events
    pub events_topic: String,
    
    /// Topic for notarization results
    pub results_topic: String,
    
    /// Topic for workflow status updates
    pub status_topic: String,
    
    /// Topic for error events
    pub errors_topic: String,
    
    /// Topic tenant (optional)
    pub tenant: Option<String>,
    
    /// Topic namespace (optional)
    pub namespace: Option<String>,
}

/// Authentication configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthConfig {
    /// Authentication method
    pub method: AuthMethod,
    
    /// Authentication parameters
    pub params: AuthParams,
}

/// Authentication methods supported by Pulsar
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuthMethod {
    /// No authentication
    None,
    /// JWT token authentication
    Jwt,
    /// TLS certificate authentication
    Tls,
    /// OAuth2 authentication
    OAuth2,
    /// Basic authentication (username/password)
    Basic,
}

/// Authentication parameters
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthParams {
    /// Token or certificate path
    pub token_or_cert: Option<String>,
    
    /// Private key path (for TLS)
    pub private_key: Option<String>,
    
    /// Username (for basic auth)
    pub username: Option<String>,
    
    /// Password (for basic auth) 
    pub password: Option<String>,
    
    /// OAuth2 issuer URL
    pub issuer_url: Option<String>,
    
    /// OAuth2 audience
    pub audience: Option<String>,
}

/// Connection configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConnectionConfig {
    /// Connection timeout
    pub connection_timeout: Duration,
    
    /// Operation timeout
    pub operation_timeout: Duration,
    
    /// Keep alive interval
    pub keep_alive_interval: Duration,
    
    /// Maximum number of connections per broker
    pub max_connections_per_broker: u32,
    
    /// Enable TLS
    pub tls_enabled: bool,
    
    /// TLS certificate validation
    pub tls_validate_hostname: bool,
}

/// Subscription types
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub enum SubscriptionType {
    /// Only one consumer can receive messages
    Exclusive,
    /// Multiple consumers share message processing
    Shared,
    /// Active/standby consumer pattern
    Failover,
    /// Messages with same key go to same consumer
    KeyShared,
}

/// Batch receive configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BatchReceiveConfig {
    /// Maximum number of messages in a batch
    pub max_messages: u32,
    
    /// Maximum wait time for batch completion
    pub max_wait_time: Duration,
    
    /// Enable batch receive
    pub enabled: bool,
}

/// Batching configuration for producer
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BatchingConfig {
    /// Enable batching
    pub enabled: bool,
    
    /// Maximum number of messages in a batch
    pub max_messages: u32,
    
    /// Maximum batch size in bytes
    pub max_bytes: u32,
    
    /// Maximum delay before sending partial batch
    pub max_delay: Duration,
}

/// Compression types supported by Pulsar
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum CompressionType {
    /// No compression
    None,
    /// LZ4 compression
    Lz4,
    /// Zlib compression
    Zlib,
    /// Zstd compression
    Zstd,
    /// Snappy compression
    Snappy,
}

impl Default for PulsarConfig {
    fn default() -> Self {
        Self {
            service_url: "pulsar://localhost:6650".to_string(),
            consumer: ConsumerConfig::default(),
            producer: ProducerConfig::default(),
            topics: TopicConfig::default(),
            auth: None,
            connection: ConnectionConfig::default(),
        }
    }
}

impl Default for ConsumerConfig {
    fn default() -> Self {
        Self {
            name: "afdp-notary-consumer".to_string(),
            subscription: "afdp-notary-subscription".to_string(),
            subscription_type: SubscriptionType::Shared,
            receive_queue_size: 1000,
            batch_receive: BatchReceiveConfig::default(),
            dead_letter_topic: Some("afdp.notary.dlq".to_string()),
            max_redeliveries: Some(3),
        }
    }
}

impl Default for ProducerConfig {
    fn default() -> Self {
        Self {
            name: "afdp-notary-producer".to_string(),
            send_timeout: Duration::from_secs(30),
            batching: BatchingConfig::default(),
            compression: CompressionType::Lz4,
            block_if_full: true,
        }
    }
}

impl Default for TopicConfig {
    fn default() -> Self {
        Self {
            events_topic: "afdp.pipeline.events".to_string(),
            results_topic: "afdp.notary.results".to_string(),
            status_topic: "afdp.notary.status".to_string(),
            errors_topic: "afdp.notary.errors".to_string(),
            tenant: Some("afdp".to_string()),
            namespace: Some("default".to_string()),
        }
    }
}

impl Default for ConnectionConfig {
    fn default() -> Self {
        Self {
            connection_timeout: Duration::from_secs(30),
            operation_timeout: Duration::from_secs(30),
            keep_alive_interval: Duration::from_secs(30),
            max_connections_per_broker: 10,
            tls_enabled: false,
            tls_validate_hostname: true,
        }
    }
}

impl Default for BatchReceiveConfig {
    fn default() -> Self {
        Self {
            max_messages: 100,
            max_wait_time: Duration::from_millis(100),
            enabled: true,
        }
    }
}

impl Default for BatchingConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            max_messages: 100,
            max_bytes: 1024 * 1024, // 1MB
            max_delay: Duration::from_millis(10),
        }
    }
}

impl PulsarConfig {
    /// Load configuration from environment variables
    pub fn from_env() -> crate::Result<Self> {
        let mut config = Self::default();
        
        // Service URL
        if let Ok(url) = std::env::var("PULSAR_SERVICE_URL") {
            config.service_url = url;
        }
        
        // Topics
        if let Ok(events_topic) = std::env::var("PULSAR_EVENTS_TOPIC") {
            config.topics.events_topic = events_topic;
        }
        
        if let Ok(results_topic) = std::env::var("PULSAR_RESULTS_TOPIC") {
            config.topics.results_topic = results_topic;
        }
        
        if let Ok(status_topic) = std::env::var("PULSAR_STATUS_TOPIC") {
            config.topics.status_topic = status_topic;
        }
        
        if let Ok(errors_topic) = std::env::var("PULSAR_ERRORS_TOPIC") {
            config.topics.errors_topic = errors_topic;
        }
        
        // Consumer configuration
        if let Ok(consumer_name) = std::env::var("PULSAR_CONSUMER_NAME") {
            config.consumer.name = consumer_name;
        }
        
        if let Ok(subscription) = std::env::var("PULSAR_SUBSCRIPTION") {
            config.consumer.subscription = subscription;
        }
        
        // Authentication
        if let Ok(auth_method) = std::env::var("PULSAR_AUTH_METHOD") {
            let method = match auth_method.to_lowercase().as_str() {
                "jwt" => AuthMethod::Jwt,
                "tls" => AuthMethod::Tls,
                "oauth2" => AuthMethod::OAuth2,
                "basic" => AuthMethod::Basic,
                _ => AuthMethod::None,
            };
            
            let mut params = AuthParams {
                token_or_cert: std::env::var("PULSAR_AUTH_TOKEN").ok(),
                private_key: std::env::var("PULSAR_AUTH_PRIVATE_KEY").ok(),
                username: std::env::var("PULSAR_AUTH_USERNAME").ok(),
                password: std::env::var("PULSAR_AUTH_PASSWORD").ok(),
                issuer_url: std::env::var("PULSAR_AUTH_ISSUER_URL").ok(),
                audience: std::env::var("PULSAR_AUTH_AUDIENCE").ok(),
            };
            
            config.auth = Some(AuthConfig { method, params });
        }
        
        // TLS configuration
        if let Ok(tls_enabled) = std::env::var("PULSAR_TLS_ENABLED") {
            config.connection.tls_enabled = tls_enabled.parse().unwrap_or(false);
        }
        
        Ok(config)
    }
    
    /// Build full topic name with tenant and namespace
    pub fn full_topic_name(&self, topic: &str) -> String {
        match (&self.topics.tenant, &self.topics.namespace) {
            (Some(tenant), Some(namespace)) => {
                format!("persistent://{}/{}/{}", tenant, namespace, topic)
            }
            (Some(tenant), None) => {
                format!("persistent://{}/default/{}", tenant, topic)
            }
            (None, Some(namespace)) => {
                format!("persistent://public/{}/{}", namespace, topic)
            }
            (None, None) => {
                format!("persistent://public/default/{}", topic)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = PulsarConfig::default();
        assert_eq!(config.service_url, "pulsar://localhost:6650");
        assert_eq!(config.consumer.name, "afdp-notary-consumer");
        assert_eq!(config.topics.events_topic, "afdp.pipeline.events");
    }
    
    #[test]
    fn test_full_topic_name() {
        let config = PulsarConfig::default();
        
        let full_name = config.full_topic_name("test.topic");
        assert_eq!(full_name, "persistent://afdp/default/test.topic");
    }
    
    #[test]
    fn test_config_serialization() {
        let config = PulsarConfig::default();
        let json = serde_json::to_string(&config).unwrap();
        let deserialized: PulsarConfig = serde_json::from_str(&json).unwrap();
        
        assert_eq!(config.service_url, deserialized.service_url);
        assert_eq!(config.consumer.name, deserialized.consumer.name);
    }
}