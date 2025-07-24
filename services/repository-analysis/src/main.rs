use anyhow::Result;
use clap::Parser;
use std::sync::Arc;
use tracing::{info, warn};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

mod config;
mod server;
mod storage;
mod analysis;
mod forensics;
mod auth;
mod events;
mod temporal;
mod proto;

use crate::{
    config::Config,
    server::Server,
    storage::{Storage, postgres::PostgresStorage, object::ObjectStorage, vector::QdrantStorage},
    analysis::AnalysisEngine,
    forensics::ForensicsManager,
    auth::AuthManager,
    events::publisher::EventPublisher,
    temporal::TemporalClient,
};

#[derive(Parser)]
#[command(name = "afdp-repository-analysis")]
#[command(about = "AFDP Repository Analysis Service - Universal forensic analysis")]
struct Cli {
    /// Configuration file path
    #[arg(short, long, default_value = "config.yaml")]
    config: String,
    
    /// Log level
    #[arg(short, long, default_value = "info")]
    log_level: String,
    
    /// Server bind address
    #[arg(short, long, default_value = "0.0.0.0:8080")]
    bind: String,
    
    /// Enable development mode
    #[arg(long)]
    dev: bool,
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    
    // Initialize tracing
    init_tracing(&cli.log_level)?;
    
    info!("Starting AFDP Repository Analysis Service");
    info!("Version: {}", env!("CARGO_PKG_VERSION"));
    info!("Configuration: {}", cli.config);
    
    // Load configuration
    let config = Config::load(&cli.config).await?;
    info!("Configuration loaded successfully");
    
    // Initialize storage systems
    let storage = Arc::new(init_storage(&config).await?);
    info!("Storage systems initialized");
    
    // Initialize event publisher for distributed intelligence
    let events = Arc::new(EventPublisher::new(&config.pulsar, config.distributed_networks.clone()).await?);
    info!("Distributed intelligence event publisher initialized");
    
    // Initialize analysis engine
    let analysis_engine = Arc::new(AnalysisEngine::new(config.analysis.clone(), storage.clone(), events.clone()).await?);
    info!("Analysis engine initialized");
    
    // Initialize forensics manager
    let forensics = Arc::new(ForensicsManager::new(config.forensics.clone(), storage.clone()).await?);
    info!("Forensics manager initialized");
    
    // Initialize authentication
    let auth = Arc::new(AuthManager::new(config.auth.clone()).await?);
    info!("Authentication manager initialized");
    
    // Initialize Temporal client
    let temporal = Arc::new(TemporalClient::new(config.temporal.clone()).await?);
    info!("Temporal client initialized");
    
    // Create server with all dependencies
    let server = Server::new(
        cli.bind,
        config,
        storage,
        analysis_engine,
        forensics,
        auth,
        events,
        temporal,
    ).await?;
    
    info!("Starting server on {}", cli.bind);
    
    // Start server
    server.run().await?;
    
    Ok(())
}

fn init_tracing(level: &str) -> Result<()> {
    let filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| format!("afdp_repository_analysis={level},tower_http=debug").into());
    
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::fmt::layer()
                .with_target(false)
                .json()
        )
        .with(filter)
        .init();
    
    Ok(())
}

async fn init_storage(config: &Config) -> Result<Storage> {
    // Initialize PostgreSQL for metadata
    let postgres = PostgresStorage::new(&config.storage.postgres).await?;
    postgres.migrate().await?;
    
    // Initialize object storage for files
    let object_storage = ObjectStorage::new(&config.storage.object).await?;
    
    // Initialize Qdrant for vector search
    let vector_storage = QdrantStorage::new(&config.storage.vector).await?;
    vector_storage.initialize_collections().await?;
    
    Ok(Storage::new(postgres, object_storage, vector_storage))
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[tokio::test]
    async fn test_config_loading() {
        // Test configuration loading with default values
        let config = Config::default();
        assert!(!config.server.bind_address.is_empty());
        assert!(config.server.port > 0);
    }
    
    #[tokio::test]
    async fn test_storage_initialization() {
        // Test storage system initialization
        let config = Config::default();
        
        // This would require running databases, so just test the config
        assert!(!config.storage.postgres.host.is_empty());
        assert!(config.storage.postgres.port > 0);
    }
}