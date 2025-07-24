use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use url::Url;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    pub server: ServerConfig,
    pub storage: StorageConfig,
    pub analysis: AnalysisConfig,
    pub forensics: ForensicsConfig,
    pub auth: AuthConfig,
    pub events: EventsConfig,
    pub pulsar: PulsarConfig,
    pub distributed_networks: Vec<DistributedNetworkConfig>,
    pub temporal: TemporalConfig,
    pub logging: LoggingConfig,
    pub metrics: MetricsConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerConfig {
    pub bind_address: String,
    pub port: u16,
    pub tls: Option<TlsConfig>,
    pub cors: CorsConfig,
    pub rate_limiting: RateLimitConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TlsConfig {
    pub cert_path: String,
    pub key_path: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CorsConfig {
    pub enabled: bool,
    pub allowed_origins: Vec<String>,
    pub allowed_methods: Vec<String>,
    pub allowed_headers: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RateLimitConfig {
    pub enabled: bool,
    pub requests_per_minute: u32,
    pub burst_size: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StorageConfig {
    pub postgres: PostgresConfig,
    pub object: ObjectStorageConfig,
    pub vector: VectorStorageConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PostgresConfig {
    pub host: String,
    pub port: u16,
    pub username: String,
    pub password: String,
    pub database: String,
    pub ssl_mode: String,
    pub max_connections: u32,
    pub min_connections: u32,
    pub connection_timeout_seconds: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ObjectStorageConfig {
    pub provider: String, // "s3", "gcs", "azure", "local"
    pub bucket: String,
    pub region: Option<String>,
    pub endpoint: Option<String>,
    pub access_key: Option<String>,
    pub secret_key: Option<String>,
    pub local_path: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VectorStorageConfig {
    pub host: String,
    pub port: u16,
    pub api_key: Option<String>,
    pub collection_prefix: String,
    pub vector_size: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnalysisConfig {
    pub max_file_size_mb: u64,
    pub max_repository_size_gb: u64,
    pub timeout_seconds: u64,
    pub parallel_workers: usize,
    pub supported_formats: Vec<String>,
    pub malware_scanning: MalwareScanConfig,
    pub code_analysis: CodeAnalysisConfig,
    pub ml_analysis: MLAnalysisConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MalwareScanConfig {
    pub enabled: bool,
    pub engines: Vec<String>, // ["yara", "clamav"]
    pub yara_rules_path: Option<String>,
    pub clamav_db_path: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CodeAnalysisConfig {
    pub enabled: bool,
    pub languages: Vec<String>,
    pub static_analysis: bool,
    pub dependency_analysis: bool,
    pub secret_detection: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MLAnalysisConfig {
    pub enabled: bool,
    pub model_path: String,
    pub embedding_model: String,
    pub similarity_threshold: f32,
    pub batch_size: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ForensicsConfig {
    pub chain_of_custody: bool,
    pub evidence_encryption: bool,
    pub hash_algorithms: Vec<String>,
    pub signature_algorithm: String,
    pub retention_days: u32,
    pub legal_hold_enabled: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthConfig {
    pub policy_engine_url: String,
    pub service_token: String,
    pub jwt_verification_key: String,
    pub required_permissions: HashMap<String, Vec<String>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EventsConfig {
    pub pulsar: PulsarConfig,
    pub topics: TopicsConfig,
    pub distributed_networks: HashMap<String, DistributionNetwork>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PulsarConfig {
    pub broker_url: String,
    pub auth_token: Option<String>,
    pub topics: Vec<String>,
    pub subscription_name: String,
    pub consumer_name: String,
    pub batch_size: usize,
    pub compression_type: String,
    pub encryption_enabled: bool,
    pub connection_timeout_ms: u64,
    pub operation_timeout_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DistributedNetworkConfig {
    pub name: String,
    pub description: String,
    pub topics: Vec<String>,
    pub priority: String,
    pub filter_rules: Vec<String>,
    pub encryption_required: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TopicsConfig {
    pub analysis_submitted: String,
    pub analysis_started: String,
    pub analysis_progress: String,
    pub violation_detected: String,
    pub anomaly_identified: String,
    pub analysis_completed: String,
    pub evidence_discovered: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DistributionNetwork {
    pub name: String,
    pub recipients: Vec<Recipient>,
    pub trigger_conditions: Vec<String>,
    pub priority: String,
    pub encryption_required: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Recipient {
    pub id: String,
    pub name: String,
    pub endpoint: String,
    pub auth_token: Option<String>,
    pub recipient_type: String, // "legal", "law_enforcement", "insurance", "partner"
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TemporalConfig {
    pub host: String,
    pub port: u16,
    pub namespace: String,
    pub task_queue: String,
    pub workflow_timeout_seconds: u64,
    pub activity_timeout_seconds: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoggingConfig {
    pub level: String,
    pub format: String, // "json" or "text"
    pub file_path: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MetricsConfig {
    pub enabled: bool,
    pub bind_address: String,
    pub port: u16,
    pub path: String,
}

impl Config {
    pub async fn load(path: &str) -> Result<Self> {
        let content = tokio::fs::read_to_string(path).await?;
        let config: Config = serde_yaml::from_str(&content)?;
        config.validate()?;
        Ok(config)
    }
    
    pub fn validate(&self) -> Result<()> {
        // Validate server configuration
        if self.server.port == 0 {
            anyhow::bail!("Server port must be greater than 0");
        }
        
        // Validate storage configuration
        if self.storage.postgres.host.is_empty() {
            anyhow::bail!("PostgreSQL host is required");
        }
        
        if self.storage.object.bucket.is_empty() {
            anyhow::bail!("Object storage bucket is required");
        }
        
        // Validate Pulsar URL
        if let Err(_) = Url::parse(&self.pulsar.broker_url) {
            anyhow::bail!("Invalid Pulsar broker URL");
        }
        
        // Validate auth configuration
        if let Err(_) = Url::parse(&self.auth.policy_engine_url) {
            anyhow::bail!("Invalid policy engine URL");
        }
        
        Ok(())
    }
}

impl Default for PulsarConfig {
    fn default() -> Self {
        Self {
            broker_url: "pulsar://localhost:6650".to_string(),
            auth_token: None,
            topics: vec!["security-alerts".to_string()],
            subscription_name: "repo-analysis-sub".to_string(),
            consumer_name: "repo-analysis-consumer".to_string(),
            batch_size: 100,
            compression_type: "zstd".to_string(),
            encryption_enabled: false,
            connection_timeout_ms: 5000,
            operation_timeout_ms: 30000,
        }
    }
}

impl Default for Config {
    fn default() -> Self {
        Self {
            server: ServerConfig {
                bind_address: "0.0.0.0".to_string(),
                port: 8080,
                tls: None,
                cors: CorsConfig {
                    enabled: true,
                    allowed_origins: vec!["*".to_string()],
                    allowed_methods: vec![
                        "GET".to_string(),
                        "POST".to_string(),
                        "PUT".to_string(),
                        "DELETE".to_string(),
                        "OPTIONS".to_string(),
                    ],
                    allowed_headers: vec![
                        "Authorization".to_string(),
                        "Content-Type".to_string(),
                        "X-Request-ID".to_string(),
                    ],
                },
                rate_limiting: RateLimitConfig {
                    enabled: true,
                    requests_per_minute: 100,
                    burst_size: 20,
                },
            },
            storage: StorageConfig {
                postgres: PostgresConfig {
                    host: "localhost".to_string(),
                    port: 5432,
                    username: "afdp_repo".to_string(),
                    password: "secure_password".to_string(),
                    database: "afdp_repository_analysis".to_string(),
                    ssl_mode: "require".to_string(),
                    max_connections: 50,
                    min_connections: 5,
                    connection_timeout_seconds: 30,
                },
                object: ObjectStorageConfig {
                    provider: "local".to_string(),
                    bucket: "afdp-repository-analysis".to_string(),
                    region: None,
                    endpoint: None,
                    access_key: None,
                    secret_key: None,
                    local_path: Some("./storage/objects".to_string()),
                },
                vector: VectorStorageConfig {
                    host: "localhost".to_string(),
                    port: 6333,
                    api_key: None,
                    collection_prefix: "afdp_repo".to_string(),
                    vector_size: 384,
                },
            },
            analysis: AnalysisConfig {
                max_file_size_mb: 100,
                max_repository_size_gb: 10,
                timeout_seconds: 3600,
                parallel_workers: 4,
                supported_formats: vec![
                    "git".to_string(),
                    "zip".to_string(),
                    "tar".to_string(),
                    "directory".to_string(),
                ],
                malware_scanning: MalwareScanConfig {
                    enabled: false, // Disabled due to YARA and ClamAV dependency issues
                    engines: vec![], // ["yara", "clamav"] disabled
                    yara_rules_path: Some("./rules/yara".to_string()), // Not used when disabled
                    clamav_db_path: None,
                },
                code_analysis: CodeAnalysisConfig {
                    enabled: true,
                    languages: vec![
                        "rust".to_string(),
                        "go".to_string(),
                        "python".to_string(),
                        "javascript".to_string(),
                        "java".to_string(),
                        "c".to_string(),
                        "cpp".to_string(),
                    ],
                    static_analysis: true,
                    dependency_analysis: true,
                    secret_detection: true,
                },
                ml_analysis: MLAnalysisConfig {
                    enabled: true,
                    model_path: "./models".to_string(),
                    embedding_model: "sentence-transformers/all-MiniLM-L6-v2".to_string(),
                    similarity_threshold: 0.8,
                    batch_size: 32,
                },
            },
            forensics: ForensicsConfig {
                chain_of_custody: true,
                evidence_encryption: true,
                hash_algorithms: vec!["sha256".to_string(), "blake3".to_string()],
                signature_algorithm: "ed25519".to_string(),
                retention_days: 2555, // 7 years
                legal_hold_enabled: true,
            },
            auth: AuthConfig {
                policy_engine_url: "http://localhost:8081".to_string(),
                service_token: "afdp_service_token".to_string(),
                jwt_verification_key: "-----BEGIN PUBLIC KEY-----\n...\n-----END PUBLIC KEY-----".to_string(),
                required_permissions: {
                    let mut perms = HashMap::new();
                    perms.insert("repository:analyze".to_string(), vec!["analyst".to_string(), "admin".to_string()]);
                    perms.insert("repository:read".to_string(), vec!["user".to_string(), "analyst".to_string(), "admin".to_string()]);
                    perms.insert("evidence:access".to_string(), vec!["investigator".to_string(), "admin".to_string()]);
                    perms
                },
            },
            events: EventsConfig {
                pulsar: PulsarConfig {
                    broker_url: "pulsar://localhost:6650".to_string(),
                    auth_token: None,
                    topics: vec!["security-alerts".to_string()],
                    subscription_name: "repo-analysis-sub".to_string(),
                    consumer_name: "repo-analysis-consumer".to_string(),
                    batch_size: 100,
                    compression_type: "zstd".to_string(),
                    encryption_enabled: false,
                    connection_timeout_ms: 5000,
                    operation_timeout_ms: 30000,
                },
                topics: TopicsConfig {
                    analysis_submitted: "afdp.repository.analysis.submitted".to_string(),
                    analysis_started: "afdp.repository.analysis.started".to_string(),
                    analysis_progress: "afdp.repository.analysis.progress".to_string(),
                    violation_detected: "afdp.repository.violation.detected".to_string(),
                    anomaly_identified: "afdp.repository.anomaly.identified".to_string(),
                    analysis_completed: "afdp.repository.analysis.completed".to_string(),
                    evidence_discovered: "afdp.repository.evidence.discovered".to_string(),
                },
                distributed_networks: {
                    let mut networks = HashMap::new();
                    
                    // Critical intelligence network
                    networks.insert("critical_intelligence".to_string(), DistributionNetwork {
                        name: "Critical Intelligence Network".to_string(),
                        recipients: vec![
                            Recipient {
                                id: "fusion_center_1".to_string(),
                                name: "Regional Fusion Center".to_string(),
                                endpoint: "https://fusion.center.gov/api/intelligence".to_string(),
                                auth_token: Some("fc_token_123".to_string()),
                                recipient_type: "law_enforcement".to_string(),
                            },
                            Recipient {
                                id: "legal_team".to_string(),
                                name: "Legal Counsel".to_string(),
                                endpoint: "https://legal.company.com/api/evidence".to_string(),
                                auth_token: Some("legal_token_456".to_string()),
                                recipient_type: "legal".to_string(),
                            },
                        ],
                        trigger_conditions: vec![
                            "threat_level:critical".to_string(),
                            "violation_type:security".to_string(),
                            "classification:secret".to_string(),
                        ],
                        priority: "immediate".to_string(),
                        encryption_required: true,
                    });
                    
                    // Business intelligence network
                    networks.insert("business_intelligence".to_string(), DistributionNetwork {
                        name: "Business Intelligence Network".to_string(),
                        recipients: vec![
                            Recipient {
                                id: "insurance_carrier".to_string(),
                                name: "Cyber Insurance Provider".to_string(),
                                endpoint: "https://insurance.company.com/api/claims".to_string(),
                                auth_token: Some("ins_token_789".to_string()),
                                recipient_type: "insurance".to_string(),
                            },
                        ],
                        trigger_conditions: vec![
                            "risk_level:medium".to_string(),
                            "compliance_violation:true".to_string(),
                        ],
                        priority: "normal".to_string(),
                        encryption_required: false,
                    });
                    
                    networks
                },
            },
            pulsar: PulsarConfig {
                broker_url: "pulsar://localhost:6650".to_string(),
                auth_token: None,
                topics: vec!["security-alerts".to_string()],
                subscription_name: "repo-analysis-sub".to_string(),
                consumer_name: "repo-analysis-consumer".to_string(),
                batch_size: 100,
                compression_type: "zstd".to_string(),
                encryption_enabled: false,
                connection_timeout_ms: 5000,
                operation_timeout_ms: 30000,
            },
            distributed_networks: vec![
                DistributedNetworkConfig {
                    name: "security-team".to_string(),
                    description: "Internal security team network".to_string(),
                    topics: vec!["security-alerts".to_string(), "incident-response".to_string()],
                    priority: "high".to_string(),
                    filter_rules: vec!["severity:high".to_string(), "severity:critical".to_string()],
                    encryption_required: true,
                },
                DistributedNetworkConfig {
                    name: "legal-team".to_string(),
                    description: "Legal and compliance network".to_string(),
                    topics: vec!["data-protection".to_string(), "legal-alerts".to_string()],
                    priority: "medium".to_string(),
                    filter_rules: vec!["type:data_leak".to_string(), "type:compliance".to_string()],
                    encryption_required: true,
                },
            ],
            temporal: TemporalConfig {
                host: "localhost".to_string(),
                port: 7233,
                namespace: "afdp-repository-analysis".to_string(),
                task_queue: "repository-analysis-tasks".to_string(),
                workflow_timeout_seconds: 3600,
                activity_timeout_seconds: 300,
            },
            logging: LoggingConfig {
                level: "info".to_string(),
                format: "json".to_string(),
                file_path: Some("./logs/repository-analysis.log".to_string()),
            },
            metrics: MetricsConfig {
                enabled: true,
                bind_address: "0.0.0.0".to_string(),
                port: 8081,
                path: "/metrics".to_string(),
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_default_config() {
        let config = Config::default();
        assert!(config.validate().is_ok());
    }
    
    #[test]
    fn test_config_serialization() {
        let config = Config::default();
        let yaml = serde_yaml::to_string(&config).unwrap();
        let deserialized: Config = serde_yaml::from_str(&yaml).unwrap();
        assert_eq!(config.server.port, deserialized.server.port);
    }
}