//! gRPC server binary for AFDP Notary Service
//!
//! This binary starts a gRPC server that provides high-performance
//! service-to-service communication for AFDP notary operations.

use afdp_notary::{
    config::NotaryConfig,
    grpc::NotaryGrpcServer,
    temporal::TemporalNotaryConfig,
    notary, vault, rekor,
};
use std::net::SocketAddr;
use tracing::{info, error};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize tracing
    tracing_subscriber::fmt::init();

    // Load configuration
    let config = NotaryConfig::from_env()?;
    let temporal_config = TemporalNotaryConfig {
        temporal_address: config.temporal_server_url.clone(),
        namespace: config.temporal_namespace.clone(),
        task_queue: config.temporal_task_queue.clone(),
        notary_config: notary::NotaryConfig {
            vault_config: vault::VaultConfig {
                address: config.vault_address.clone(),
                token: config.vault_token.clone(),
                transit_key_name: "afdp-notary-key".to_string(),
            },
            rekor_config: rekor::RekorConfig {
                server_url: config.rekor_server_url.clone(),
                ..Default::default()
            },
        },
        default_timeout_seconds: 300,
    };

    // Parse server address
    let addr: SocketAddr = config.grpc_server_addr
        .parse()
        .expect("Invalid gRPC server address");

    info!("Starting AFDP Notary gRPC server on {}", addr);
    info!("Temporal server: {}", temporal_config.temporal_address);
    info!("Temporal namespace: {}", temporal_config.namespace);

    // Create and start the gRPC server
    match NotaryGrpcServer::new(temporal_config).await {
        Ok(server) => {
            info!("gRPC server initialized successfully");
            
            if let Err(e) = server.serve(addr).await {
                error!("gRPC server error: {}", e);
                std::process::exit(1);
            }
        }
        Err(e) => {
            error!("Failed to create gRPC server: {}", e);
            std::process::exit(1);
        }
    }

    Ok(())
}