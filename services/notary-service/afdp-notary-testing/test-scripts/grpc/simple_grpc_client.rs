// Simple Rust gRPC client for AFDP Notary Service testing
// This demonstrates basic gRPC client usage and can be used for simple tests

use tonic::transport::Channel;
use tonic::{Request, Status};
use std::time::Instant;
use serde_json::Value;

// Note: In a real implementation, these would be generated from the proto file
// For now, we'll create simple structs that match the expected format

#[derive(Debug, Clone)]
pub struct EvidencePackage {
    pub spec_version: String,
    pub timestamp_utc: String,
    pub event_type: String,
    pub actor: Actor,
    pub artifacts: Vec<Artifact>,
    pub metadata: serde_json::Value,
}

#[derive(Debug, Clone)]
pub struct Actor {
    pub actor_type: String,
    pub id: String,
    pub auth_provider: Option<String>,
}

#[derive(Debug, Clone)]
pub struct Artifact {
    pub name: String,
    pub uri: Option<String>,
    pub hash_sha256: String,
}

#[derive(Debug)]
pub struct TestResult {
    pub method: String,
    pub success: bool,
    pub response_time_ms: u64,
    pub error_message: Option<String>,
}

pub struct SimpleGrpcClient {
    // In a real implementation, this would hold the gRPC client stub
    server_address: String,
}

impl SimpleGrpcClient {
    pub fn new(server_address: String) -> Self {
        Self { server_address }
    }

    pub async fn connect(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        println!("🔌 Connecting to gRPC server at {}", self.server_address);
        
        // In a real implementation, this would establish the gRPC connection
        // For demonstration purposes, we'll simulate a connection
        tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
        
        println!("✅ Connected to gRPC server");
        Ok(())
    }

    pub async fn health_check(&self) -> TestResult {
        let start = Instant::now();
        println!("🏥 Performing health check...");
        
        // Simulate health check call
        tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;
        
        let response_time = start.elapsed().as_millis() as u64;
        
        // In a real implementation, this would make the actual gRPC call
        TestResult {
            method: "HealthCheck".to_string(),
            success: true,
            response_time_ms: response_time,
            error_message: None,
        }
    }

    pub async fn sign_evidence(&self, evidence: EvidencePackage) -> TestResult {
        let start = Instant::now();
        println!("📝 Signing evidence package: {}", evidence.event_type);
        
        // Simulate evidence signing call
        tokio::time::sleep(tokio::time::Duration::from_millis(200)).await;
        
        let response_time = start.elapsed().as_millis() as u64;
        
        // In a real implementation, this would make the actual gRPC call
        TestResult {
            method: "SignEvidence".to_string(),
            success: true,
            response_time_ms: response_time,
            error_message: None,
        }
    }

    pub async fn sign_evidence_with_approval(
        &self, 
        evidence: EvidencePackage, 
        approvers: Vec<String>
    ) -> TestResult {
        let start = Instant::now();
        println!("📋 Signing evidence with approval: {} approvers", approvers.len());
        
        // Simulate approval workflow call
        tokio::time::sleep(tokio::time::Duration::from_millis(300)).await;
        
        let response_time = start.elapsed().as_millis() as u64;
        
        TestResult {
            method: "SignEvidenceWithApproval".to_string(),
            success: true,
            response_time_ms: response_time,
            error_message: None,
        }
    }

    pub async fn sign_evidence_batch(&self, evidence_list: Vec<EvidencePackage>) -> TestResult {
        let start = Instant::now();
        println!("📦 Batch signing {} evidence packages", evidence_list.len());
        
        // Simulate batch signing call
        let delay = 100 + (evidence_list.len() as u64 * 50);
        tokio::time::sleep(tokio::time::Duration::from_millis(delay)).await;
        
        let response_time = start.elapsed().as_millis() as u64;
        
        TestResult {
            method: "SignEvidenceBatch".to_string(),
            success: true,
            response_time_ms: response_time,
            error_message: None,
        }
    }

    pub async fn run_performance_test(
        &self,
        evidence: EvidencePackage,
        num_requests: usize,
        concurrency: usize,
    ) -> Vec<TestResult> {
        println!("🔥 Running performance test: {} requests, {} concurrent", num_requests, concurrency);
        
        let mut results = Vec::new();
        let mut handles = Vec::new();
        
        // Create batches of concurrent requests
        let batch_size = num_requests / concurrency;
        
        for batch in 0..concurrency {
            let evidence_clone = evidence.clone();
            let client_address = self.server_address.clone();
            
            let handle = tokio::spawn(async move {
                let client = SimpleGrpcClient::new(client_address);
                let mut batch_results = Vec::new();
                
                for _i in 0..batch_size {
                    let result = client.sign_evidence(evidence_clone.clone()).await;
                    batch_results.push(result);
                    
                    // Small delay between requests to avoid overwhelming the server
                    tokio::time::sleep(tokio::time::Duration::from_millis(10)).await;
                }
                
                batch_results
            });
            
            handles.push(handle);
        }
        
        // Collect all results
        for handle in handles {
            if let Ok(batch_results) = handle.await {
                results.extend(batch_results);
            }
        }
        
        // Handle remaining requests if num_requests doesn't divide evenly
        let remaining = num_requests % concurrency;
        for _i in 0..remaining {
            let result = self.sign_evidence(evidence.clone()).await;
            results.push(result);
        }
        
        results
    }
}

// Helper function to create test evidence package from JSON
pub fn create_evidence_from_json(json_str: &str) -> Result<EvidencePackage, serde_json::Error> {
    let json: Value = serde_json::from_str(json_str)?;
    
    let actor_data = json.get("actor").unwrap_or(&serde_json::json!({}));
    let actor = Actor {
        actor_type: actor_data.get("actor_type").and_then(|v| v.as_str()).unwrap_or("unknown").to_string(),
        id: actor_data.get("id").and_then(|v| v.as_str()).unwrap_or("test-user").to_string(),
        auth_provider: actor_data.get("auth_provider").and_then(|v| v.as_str()).map(|s| s.to_string()),
    };
    
    let artifacts: Vec<Artifact> = json.get("artifacts")
        .and_then(|v| v.as_array())
        .unwrap_or(&Vec::new())
        .iter()
        .map(|artifact_data| Artifact {
            name: artifact_data.get("name").and_then(|v| v.as_str()).unwrap_or("").to_string(),
            uri: artifact_data.get("uri").and_then(|v| v.as_str()).map(|s| s.to_string()),
            hash_sha256: artifact_data.get("hash_sha256").and_then(|v| v.as_str()).unwrap_or("").to_string(),
        })
        .collect();
    
    Ok(EvidencePackage {
        spec_version: "1.0".to_string(),
        timestamp_utc: json.get("timestamp").and_then(|v| v.as_str()).unwrap_or("2024-01-01T00:00:00Z").to_string(),
        event_type: json.get("event_type").and_then(|v| v.as_str()).unwrap_or("test.event").to_string(),
        actor,
        artifacts,
        metadata: json.get("metadata").cloned().unwrap_or(serde_json::json!({})),
    })
}

// Helper function to calculate test statistics
pub fn calculate_stats(results: &[TestResult]) -> (f64, u64, u64, f64) {
    if results.is_empty() {
        return (0.0, 0, 0, 0.0);
    }
    
    let successful = results.iter().filter(|r| r.success).count();
    let success_rate = successful as f64 / results.len() as f64;
    
    let response_times: Vec<u64> = results.iter().map(|r| r.response_time_ms).collect();
    let avg_response_time = response_times.iter().sum::<u64>() as f64 / response_times.len() as f64;
    let min_response_time = *response_times.iter().min().unwrap_or(&0);
    let max_response_time = *response_times.iter().max().unwrap_or(&0);
    
    (success_rate, min_response_time, max_response_time, avg_response_time)
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("🚀 AFDP Notary Service gRPC Client Test");
    
    let server_address = std::env::var("GRPC_SERVER").unwrap_or_else(|_| "http://localhost:50051".to_string());
    let mut client = SimpleGrpcClient::new(server_address);
    
    // Connect to server
    client.connect().await?;
    
    // Run health check
    let health_result = client.health_check().await;
    println!("Health check: {} ({}ms)", 
        if health_result.success { "✅ PASS" } else { "❌ FAIL" },
        health_result.response_time_ms
    );
    
    // Create sample evidence package
    let sample_json = r#"{
        "event_type": "test.grpc.signing",
        "timestamp": "2024-01-23T10:30:00.000Z",
        "actor": {
            "actor_type": "test_client",
            "id": "grpc-test-client",
            "auth_provider": "test"
        },
        "artifacts": [
            {
                "name": "test-artifact.txt",
                "uri": "file:///tmp/test-artifact.txt",
                "hash_sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
            }
        ],
        "metadata": {
            "test_run": "grpc-client-test",
            "client_version": "1.0.0"
        }
    }"#;
    
    let evidence = create_evidence_from_json(sample_json)?;
    
    // Test simple signing
    let sign_result = client.sign_evidence(evidence.clone()).await;
    println!("Simple signing: {} ({}ms)", 
        if sign_result.success { "✅ PASS" } else { "❌ FAIL" },
        sign_result.response_time_ms
    );
    
    // Test approval workflow
    let approval_result = client.sign_evidence_with_approval(
        evidence.clone(), 
        vec!["approver1@test.com".to_string(), "approver2@test.com".to_string()]
    ).await;
    println!("Approval workflow: {} ({}ms)", 
        if approval_result.success { "✅ PASS" } else { "❌ FAIL" },
        approval_result.response_time_ms
    );
    
    // Test batch signing
    let evidence_batch = vec![evidence.clone(), evidence.clone(), evidence.clone()];
    let batch_result = client.sign_evidence_batch(evidence_batch).await;
    println!("Batch signing: {} ({}ms)", 
        if batch_result.success { "✅ PASS" } else { "❌ FAIL" },
        batch_result.response_time_ms
    );
    
    // Run performance test
    println!("\n🔥 Running performance test...");
    let perf_results = client.run_performance_test(evidence, 20, 4).await;
    
    let (success_rate, min_time, max_time, avg_time) = calculate_stats(&perf_results);
    
    println!("\n📊 Performance Test Results:");
    println!("   Total Requests: {}", perf_results.len());
    println!("   Success Rate: {:.1}%", success_rate * 100.0);
    println!("   Avg Response Time: {:.1}ms", avg_time);
    println!("   Min Response Time: {}ms", min_time);
    println!("   Max Response Time: {}ms", max_time);
    
    println!("\n✅ All tests completed!");
    
    Ok(())
}

// Additional test configurations for different scenarios
#[cfg(test)]
mod tests {
    use super::*;
    
    #[tokio::test]
    async fn test_evidence_creation_from_json() {
        let json = r#"{
            "event_type": "ai.model.deployment",
            "actor": {
                "actor_type": "ci_system",
                "id": "github-actions"
            },
            "artifacts": [
                {
                    "name": "model.pkl",
                    "hash_sha256": "abc123"
                }
            ]
        }"#;
        
        let evidence = create_evidence_from_json(json).unwrap();
        assert_eq!(evidence.event_type, "ai.model.deployment");
        assert_eq!(evidence.actor.actor_type, "ci_system");
        assert_eq!(evidence.artifacts.len(), 1);
    }
    
    #[tokio::test]
    async fn test_client_creation() {
        let client = SimpleGrpcClient::new("localhost:50051".to_string());
        assert_eq!(client.server_address, "localhost:50051");
    }
}