//! Example: Health check via gRPC
//!
//! This example demonstrates how to check the health status of the
//! AFDP Notary Service using the gRPC health check endpoint.
//!
//! Usage:
//!   cargo run --example health-check
//!
//! Prerequisites:
//! - gRPC server running on localhost:50051

use afdp_notary::grpc::notary::{
    notary_service_client::NotaryServiceClient,
    HealthRequest,
};
use tonic::Request;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("🏥 AFDP Notary Service - gRPC Health Check Example");
    println!("================================================\n");

    // Connect to the gRPC server
    println!("🔗 Connecting to gRPC server at localhost:50051...");
    
    match NotaryServiceClient::connect("http://localhost:50051").await {
        Ok(mut client) => {
            println!("✅ Connected successfully");
            
            // Make health check request
            let request = Request::new(HealthRequest {});
            
            println!("🩺 Checking service health...");
            
            match client.health_check(request).await {
                Ok(response) => {
                    let health = response.into_inner();
                    
                    println!("✅ Health check successful!");
                    println!("   Status: {}", health.status);
                    println!("   Version: {}", health.version);
                    println!("   Uptime: {} seconds", health.uptime_seconds);
                    
                    println!("\n🔧 Dependencies:");
                    for dep in health.dependencies {
                        let status_icon = if dep.healthy { "✅" } else { "❌" };
                        println!("   {} {}: {} ({}ms)", 
                            status_icon, 
                            dep.name, 
                            if dep.healthy { "healthy" } else { "unhealthy" },
                            dep.response_time_ms);
                        
                        if !dep.error.is_empty() {
                            println!("      Error: {}", dep.error);
                        }
                    }
                    
                    println!("\n🎉 Service is healthy and ready to handle requests!");
                }
                Err(e) => {
                    eprintln!("❌ Health check failed: {}", e);
                    std::process::exit(1);
                }
            }
        }
        Err(e) => {
            eprintln!("❌ Failed to connect to gRPC server: {}", e);
            eprintln!("   Make sure the server is running on localhost:50051");
            std::process::exit(1);
        }
    }

    Ok(())
}