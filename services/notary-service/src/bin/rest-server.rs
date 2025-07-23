//! AFDP Notary Service REST API Server
//! 
//! This binary starts the REST API server for the AFDP Notary Service.
//! It provides HTTP endpoints for notarizing evidence packages, managing workflows,
//! and accessing notarization receipts.

use afdp_notary::{NotaryRestServer, TemporalNotaryConfig};
use std::net::SocketAddr;
use tracing::{info, error};
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Initialize logging
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env().add_directive(tracing::Level::INFO.into()))
        .init();

    info!("🚀 Starting AFDP Notary Service REST API Server");
    
    // Load configuration (in production, this would come from environment variables or config file)
    let temporal_config = TemporalNotaryConfig::default();
    
    info!("📋 Configuration:");
    info!("  Temporal Address: {}", temporal_config.temporal_address);
    info!("  Namespace: {}", temporal_config.namespace);
    info!("  Task Queue: {}", temporal_config.task_queue);
    info!("  Vault Address: {}", temporal_config.notary_config.vault_config.address);
    info!("  Rekor Server: {}", temporal_config.notary_config.rekor_config.server_url);

    // Create the REST server
    let server = match NotaryRestServer::new(temporal_config).await {
        Ok(server) => {
            info!("✅ REST server initialized successfully");
            server
        }
        Err(e) => {
            error!("❌ Failed to initialize REST server: {}", e);
            return Err(e.into());
        }
    };

    // Start the server
    let addr: SocketAddr = "0.0.0.0:8080".parse()?;
    info!("🌐 Starting REST API server on {}", addr);
    info!("📖 API Documentation available at http://{}/swagger-ui", addr);
    info!("🏥 Health check available at http://{}/health", addr);
    
    println!("\n🎉 AFDP Notary Service REST API is ready!");
    println!("┌─────────────────────────────────────────────────────────────┐");
    println!("│ REST API Endpoints:                                         │");
    println!("│                                                             │");
    println!("│ • POST /api/v1/evidence/sign                               │");
    println!("│   Sign evidence package                                     │");
    println!("│                                                             │");
    println!("│ • POST /api/v1/evidence/sign/approval                      │");
    println!("│   Sign evidence with approval workflow                     │");
    println!("│                                                             │");
    println!("│ • POST /api/v1/evidence/sign/batch                         │");
    println!("│   Batch sign multiple evidence packages                    │");
    println!("│                                                             │");
    println!("│ • GET /api/v1/workflows/{{workflow_id}}/status              │");
    println!("│   Get workflow status                                       │");
    println!("│                                                             │");
    println!("│ • GET /api/v1/workflows/{{workflow_id}}/receipt             │");
    println!("│   Get notarization receipt                                  │");
    println!("│                                                             │");
    println!("│ • GET /api/v1/workflows                                     │");
    println!("│   List workflows                                            │");
    println!("│                                                             │");
    println!("│ • POST /api/v1/evidence/validate                           │");
    println!("│   Validate evidence package                                 │");
    println!("│                                                             │");
    println!("│ • GET /health                                               │");
    println!("│   Health check                                              │");
    println!("│                                                             │");
    println!("│ • GET /swagger-ui                                           │");
    println!("│   Interactive API documentation                             │");
    println!("└─────────────────────────────────────────────────────────────┘");
    
    // This will block until the server is shut down
    if let Err(e) = server.serve(addr).await {
        error!("❌ Server error: {}", e);
        return Err(e.into());
    }

    Ok(())
}