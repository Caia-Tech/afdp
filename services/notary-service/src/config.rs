//! Configuration module for AFDP Notary Service

use serde::{Deserialize, Serialize};
use std::env;

/// Main configuration for the AFDP Notary Service
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NotaryConfig {
    /// gRPC server bind address
    pub grpc_server_addr: String,
    
    /// REST server bind address  
    pub rest_server_addr: String,
    
    /// Temporal server URL
    pub temporal_server_url: String,
    
    /// Temporal namespace
    pub temporal_namespace: String,
    
    /// Temporal task queue
    pub temporal_task_queue: String,
    
    /// HashiCorp Vault address
    pub vault_address: String,
    
    /// Vault token
    pub vault_token: String,
    
    /// Rekor server URL
    pub rekor_server_url: String,
}

impl Default for NotaryConfig {
    fn default() -> Self {
        Self {
            grpc_server_addr: "0.0.0.0:50051".to_string(),
            rest_server_addr: "0.0.0.0:8080".to_string(),
            temporal_server_url: "http://localhost:7233".to_string(),
            temporal_namespace: "afdp-notary".to_string(),
            temporal_task_queue: "notary-tasks".to_string(),
            vault_address: "http://localhost:8200".to_string(),
            vault_token: "dev-token".to_string(),
            rekor_server_url: "https://rekor.sigstore.dev".to_string(),
        }
    }
}

impl NotaryConfig {
    /// Load configuration from environment variables
    pub fn from_env() -> crate::Result<Self> {
        let mut config = Self::default();
        
        if let Ok(addr) = env::var("GRPC_SERVER_ADDR") {
            config.grpc_server_addr = addr;
        }
        
        if let Ok(addr) = env::var("REST_SERVER_ADDR") {
            config.rest_server_addr = addr;
        }
        
        if let Ok(url) = env::var("TEMPORAL_SERVER_URL") {
            config.temporal_server_url = url;
        }
        
        if let Ok(namespace) = env::var("TEMPORAL_NAMESPACE") {
            config.temporal_namespace = namespace;
        }
        
        if let Ok(queue) = env::var("TEMPORAL_TASK_QUEUE") {
            config.temporal_task_queue = queue;
        }
        
        if let Ok(addr) = env::var("VAULT_ADDR") {
            config.vault_address = addr;
        }
        
        if let Ok(token) = env::var("VAULT_TOKEN") {
            config.vault_token = token;
        }
        
        if let Ok(url) = env::var("REKOR_SERVER_URL") {
            config.rekor_server_url = url;
        }
        
        Ok(config)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::env;

    fn cleanup_env() {
        let vars = [
            "GRPC_SERVER_ADDR",
            "REST_SERVER_ADDR", 
            "TEMPORAL_SERVER_URL",
            "TEMPORAL_NAMESPACE",
            "TEMPORAL_TASK_QUEUE",
            "VAULT_ADDR",
            "VAULT_TOKEN",
            "REKOR_SERVER_URL",
        ];
        for var in &vars {
            env::remove_var(var);
        }
    }

    #[test]
    fn test_notary_config_default() {
        let config = NotaryConfig::default();
        
        assert_eq!(config.grpc_server_addr, "0.0.0.0:50051");
        assert_eq!(config.rest_server_addr, "0.0.0.0:8080");
        assert_eq!(config.temporal_server_url, "http://localhost:7233");
        assert_eq!(config.temporal_namespace, "afdp-notary");
        assert_eq!(config.temporal_task_queue, "notary-tasks");
        assert_eq!(config.vault_address, "http://localhost:8200");
        assert_eq!(config.vault_token, "dev-token");
        assert_eq!(config.rekor_server_url, "https://rekor.sigstore.dev");
    }

    #[test] 
    #[ignore] // Skip this test by default due to env var conflicts in parallel tests
    fn test_notary_config_from_env_with_defaults() {
        cleanup_env();
        
        let config = NotaryConfig::from_env().unwrap();
        
        // Should use default values when env vars are not set
        assert_eq!(config.grpc_server_addr, "0.0.0.0:50051");
        assert_eq!(config.rest_server_addr, "0.0.0.0:8080");
        assert_eq!(config.temporal_server_url, "http://localhost:7233");
        assert_eq!(config.temporal_namespace, "afdp-notary");
        assert_eq!(config.temporal_task_queue, "notary-tasks");
        assert_eq!(config.vault_address, "http://localhost:8200");
        assert_eq!(config.vault_token, "dev-token");
        assert_eq!(config.rekor_server_url, "https://rekor.sigstore.dev");
        
        cleanup_env();
    }

    #[test]
    #[ignore] // Skip this test by default due to env var conflicts in parallel tests
    fn test_notary_config_from_env_all_vars_set() {
        cleanup_env();
        
        // Set all environment variables
        env::set_var("GRPC_SERVER_ADDR", "localhost:9090");
        env::set_var("REST_SERVER_ADDR", "127.0.0.1:3000");
        env::set_var("TEMPORAL_SERVER_URL", "http://temporal.prod:7233");
        env::set_var("TEMPORAL_NAMESPACE", "prod-notary");
        env::set_var("TEMPORAL_TASK_QUEUE", "prod-tasks");
        env::set_var("VAULT_ADDR", "https://vault.prod:8200");
        env::set_var("VAULT_TOKEN", "prod-token-123");
        env::set_var("REKOR_SERVER_URL", "https://rekor.internal");
        
        let config = NotaryConfig::from_env().unwrap();
        
        assert_eq!(config.grpc_server_addr, "localhost:9090");
        assert_eq!(config.rest_server_addr, "127.0.0.1:3000");
        assert_eq!(config.temporal_server_url, "http://temporal.prod:7233");
        assert_eq!(config.temporal_namespace, "prod-notary");
        assert_eq!(config.temporal_task_queue, "prod-tasks");
        assert_eq!(config.vault_address, "https://vault.prod:8200");
        assert_eq!(config.vault_token, "prod-token-123");
        assert_eq!(config.rekor_server_url, "https://rekor.internal");
        
        cleanup_env(); // Clean up after test
    }

    #[test]
    #[ignore] // Skip this test by default due to env var conflicts in parallel tests
    fn test_notary_config_from_env_partial_vars_set() {
        cleanup_env();
        
        // Set only some environment variables
        env::set_var("GRPC_SERVER_ADDR", "custom:8888");
        env::set_var("VAULT_TOKEN", "custom-vault-token");
        env::set_var("TEMPORAL_NAMESPACE", "custom-namespace");
        
        let config = NotaryConfig::from_env().unwrap();
        
        // Should use env values where set
        assert_eq!(config.grpc_server_addr, "custom:8888");
        assert_eq!(config.vault_token, "custom-vault-token");
        assert_eq!(config.temporal_namespace, "custom-namespace");
        
        // Should use defaults for unset values
        assert_eq!(config.rest_server_addr, "0.0.0.0:8080");
        assert_eq!(config.temporal_server_url, "http://localhost:7233");
        assert_eq!(config.temporal_task_queue, "notary-tasks");
        assert_eq!(config.vault_address, "http://localhost:8200");
        assert_eq!(config.rekor_server_url, "https://rekor.sigstore.dev");
        
        cleanup_env();
    }

    #[test]
    fn test_notary_config_serialization() {
        let config = NotaryConfig::default();
        
        let json = serde_json::to_string(&config).unwrap();
        assert!(json.contains("\"grpc_server_addr\":\"0.0.0.0:50051\""));
        assert!(json.contains("\"rest_server_addr\":\"0.0.0.0:8080\""));
        assert!(json.contains("\"temporal_server_url\":\"http://localhost:7233\""));
        assert!(json.contains("\"vault_address\":\"http://localhost:8200\""));
    }

    #[test]
    fn test_notary_config_deserialization() {
        let json = r#"{
            "grpc_server_addr": "test:1234",
            "rest_server_addr": "test:5678",
            "temporal_server_url": "http://test:7233",
            "temporal_namespace": "test-namespace",
            "temporal_task_queue": "test-queue",
            "vault_address": "http://test:8200",
            "vault_token": "test-token",
            "rekor_server_url": "https://test.rekor"
        }"#;
        
        let config: NotaryConfig = serde_json::from_str(json).unwrap();
        
        assert_eq!(config.grpc_server_addr, "test:1234");
        assert_eq!(config.rest_server_addr, "test:5678");
        assert_eq!(config.temporal_server_url, "http://test:7233");
        assert_eq!(config.temporal_namespace, "test-namespace");
        assert_eq!(config.temporal_task_queue, "test-queue");
        assert_eq!(config.vault_address, "http://test:8200");
        assert_eq!(config.vault_token, "test-token");
        assert_eq!(config.rekor_server_url, "https://test.rekor");
    }

    #[test]
    fn test_notary_config_clone() {
        let original = NotaryConfig::default();
        let cloned = original.clone();
        
        assert_eq!(original.grpc_server_addr, cloned.grpc_server_addr);
        assert_eq!(original.rest_server_addr, cloned.rest_server_addr);
        assert_eq!(original.temporal_server_url, cloned.temporal_server_url);
        assert_eq!(original.vault_address, cloned.vault_address);
    }

    #[test]
    fn test_notary_config_debug() {
        let config = NotaryConfig::default();
        let debug_str = format!("{:?}", config);
        
        assert!(debug_str.contains("NotaryConfig"));
        assert!(debug_str.contains("grpc_server_addr"));
        assert!(debug_str.contains("vault_address"));
    }

    #[test]
    fn test_env_vars_empty_string() {
        cleanup_env();
        
        // Test with empty string values
        env::set_var("GRPC_SERVER_ADDR", "");
        env::set_var("VAULT_TOKEN", "");
        
        let config = NotaryConfig::from_env().unwrap();
        
        // Empty strings should override defaults
        assert_eq!(config.grpc_server_addr, "", "Expected empty GRPC addr, got: {}", config.grpc_server_addr);
        assert_eq!(config.vault_token, "", "Expected empty vault token, got: {}", config.vault_token);
        
        // Other fields should use defaults
        assert_eq!(config.rest_server_addr, "0.0.0.0:8080");
        
        cleanup_env();
    }

    #[test]
    #[ignore] // Skip due to env var pollution in parallel tests
    fn test_config_with_special_characters() {
        cleanup_env();
        
        // Test with URLs containing special characters
        env::set_var("TEMPORAL_SERVER_URL", "http://localhost:7233/path?query=value&other=123");
        env::set_var("VAULT_ADDR", "https://vault.example.com:8200/v1/");
        env::set_var("REKOR_SERVER_URL", "https://rekor.sigstore.dev/api/v1");
        
        let config = NotaryConfig::from_env().unwrap();
        
        assert_eq!(config.temporal_server_url, "http://localhost:7233/path?query=value&other=123");
        assert_eq!(config.vault_address, "https://vault.example.com:8200/v1/");
        assert_eq!(config.rekor_server_url, "https://rekor.sigstore.dev/api/v1");
        
        cleanup_env();
    }
}