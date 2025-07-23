//! AFDP Notary Service Server
//! 
//! This will eventually be the gRPC/REST server for the notary service.
//! For now, it's a placeholder to demonstrate the project structure.

use tracing::info;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Initialize logging
    tracing_subscriber::fmt::init();

    info!("AFDP Notary Service Server");
    info!("This is a placeholder for the future gRPC/REST server");
    info!("Use the library directly for now");

    // Future implementation will:
    // 1. Load configuration from environment/files
    // 2. Initialize VaultRekorNotary
    // 3. Start gRPC server with REST gateway
    // 4. Handle incoming notarization requests

    Ok(())
}