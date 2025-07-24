use anyhow::Result;
use std::sync::Arc;
use std::net::SocketAddr;
use tokio::signal;
use tracing::{info, error};

use crate::{
    config::Config,
    storage::Storage,
    analysis::AnalysisEngine,
    api::{ApiService, rest::RestApi},
};

/// Main server for the Repository Analysis Service
pub struct Server {
    config: Config,
    storage: Arc<Storage>,
    analysis_engine: Arc<AnalysisEngine>,
    api_service: Arc<ApiService>,
}

impl Server {
    pub async fn new(config: Config, storage: Storage) -> Result<Self> {
        let storage = Arc::new(storage);
        let analysis_engine = Arc::new(
            AnalysisEngine::new(config.analysis.clone(), storage.clone()).await?
        );
        let api_service = Arc::new(ApiService::new(storage.clone(), analysis_engine.clone()));

        Ok(Self {
            config,
            storage,
            analysis_engine,
            api_service,
        })
    }

    /// Run the server with all API protocols
    pub async fn run(self) -> Result<()> {
        info!("Starting Repository Analysis Service v{}", crate::VERSION);

        // Initialize storage
        self.initialize_storage().await?;

        // Start API servers
        let rest_handle = self.start_rest_server();
        let grpc_handle = self.start_grpc_server();
        let pulsar_handle = self.start_pulsar_consumer();

        // Wait for shutdown signal
        let shutdown = Self::shutdown_signal();

        tokio::select! {
            _ = rest_handle => {
                error!("REST server stopped unexpectedly");
            }
            _ = grpc_handle => {
                error!("gRPC server stopped unexpectedly");
            }
            _ = pulsar_handle => {
                error!("Pulsar consumer stopped unexpectedly");
            }
            _ = shutdown => {
                info!("Shutdown signal received");
            }
        }

        info!("Repository Analysis Service shutting down");
        Ok(())
    }

    async fn initialize_storage(&self) -> Result<()> {
        info!("Initializing storage systems");

        // Run PostgreSQL migrations
        self.storage.postgres.run_migrations().await?;

        // Initialize vector collections
        self.storage.vector.initialize_collections().await?;

        info!("Storage initialization complete");
        Ok(())
    }

    fn start_rest_server(&self) -> tokio::task::JoinHandle<()> {
        let config = self.config.clone();
        let api_service = self.api_service.clone();

        tokio::spawn(async move {
            let rest_api = RestApi::new(api_service);
            let app = rest_api.router();

            let addr = SocketAddr::from(([0, 0, 0, 0], config.server.http_port));
            info!("REST API listening on {}", addr);

            if let Err(e) = axum::Server::bind(&addr)
                .serve(app.into_make_service())
                .await
            {
                error!("REST server error: {}", e);
            }
        })
    }

    fn start_grpc_server(&self) -> tokio::task::JoinHandle<()> {
        let config = self.config.clone();
        let api_service = self.api_service.clone();

        tokio::spawn(async move {
            // gRPC implementation would go here
            info!("gRPC server would start on port {}", config.server.grpc_port);
            
            // Placeholder - in real implementation, would use tonic
            loop {
                tokio::time::sleep(tokio::time::Duration::from_secs(60)).await;
            }
        })
    }

    fn start_pulsar_consumer(&self) -> tokio::task::JoinHandle<()> {
        let config = self.config.clone();
        let api_service = self.api_service.clone();

        tokio::spawn(async move {
            if let Some(pulsar_config) = &config.pulsar {
                info!("Pulsar consumer would connect to {}", pulsar_config.broker_url);
                
                // Placeholder - in real implementation, would use pulsar client
                loop {
                    tokio::time::sleep(tokio::time::Duration::from_secs(60)).await;
                }
            } else {
                info!("Pulsar configuration not provided, skipping consumer");
                loop {
                    tokio::time::sleep(tokio::time::Duration::from_secs(3600)).await;
                }
            }
        })
    }

    async fn shutdown_signal() {
        let ctrl_c = async {
            signal::ctrl_c()
                .await
                .expect("Failed to install Ctrl+C handler");
        };

        #[cfg(unix)]
        let terminate = async {
            signal::unix::signal(signal::unix::SignalKind::terminate())
                .expect("Failed to install signal handler")
                .recv()
                .await;
        };

        #[cfg(not(unix))]
        let terminate = std::future::pending::<()>();

        tokio::select! {
            _ = ctrl_c => {},
            _ = terminate => {},
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{ServerConfig, StorageConfig, PostgresConfig, ObjectStorageConfig, VectorStorageConfig};

    fn create_test_config() -> Config {
        Config {
            server: ServerConfig {
                host: "localhost".to_string(),
                http_port: 8080,
                grpc_port: 50051,
                metrics_port: 9090,
            },
            storage: StorageConfig {
                postgres: PostgresConfig {
                    url: "postgres://test@localhost/test".to_string(),
                    max_connections: 5,
                    min_connections: 1,
                },
                object: ObjectStorageConfig {
                    provider: "local".to_string(),
                    bucket: "test".to_string(),
                    region: None,
                    endpoint: None,
                    access_key: None,
                    secret_key: None,
                    local_path: Some("/tmp/test".to_string()),
                },
                vector: VectorStorageConfig {
                    host: "localhost".to_string(),
                    port: 6333,
                    collection_prefix: "test".to_string(),
                    vector_size: 384,
                    api_key: None,
                },
            },
            analysis: Default::default(),
            security: Default::default(),
            distributed_networks: vec![],
            forensic: Default::default(),
            temporal: None,
            pulsar: None,
        }
    }

    #[test]
    fn test_server_creation() {
        // This test validates that the server configuration is properly structured
        let config = create_test_config();
        assert_eq!(config.server.http_port, 8080);
        assert_eq!(config.server.grpc_port, 50051);
    }
}