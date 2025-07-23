//! Example of using AFDP Temporal workflows

use afdp_notary::{
    TemporalNotaryClient, TemporalNotaryConfig,
    afdp::{AFDPWorkflows, AFDPEvidencePackage},
    Actor, EvidencePackage,
};
use serde_json::json;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Initialize logging
    tracing_subscriber::fmt::init();

    println!("🚀 AFDP Temporal Workflows Example");
    println!("===================================");

    // Create Temporal notary configuration
    let temporal_config = TemporalNotaryConfig::default();
    
    println!("📋 Configuration:");
    println!("  Temporal Address: {}", temporal_config.temporal_address);
    println!("  Namespace: {}", temporal_config.namespace);
    println!("  Task Queue: {}", temporal_config.task_queue);

    // Initialize AFDP workflows
    let workflows = AFDPWorkflows::new(temporal_config).await?;
    println!("\n✅ AFDP Workflows initialized (mock implementation)");

    // Example 1: Model Training Workflow
    println!("\n🧠 Example 1: Model Training Workflow");
    println!("-------------------------------------");
    
    let training_workflow_id = workflows.complete_model_training_workflow(
        "fraud-detector-v3",
        "training-job-20250723-001", 
        "customer-data-v5.2",
        0.94,
        "ml-engineer@caiatech.com"
    ).await?;
    
    println!("  Training Workflow ID: {}", training_workflow_id);

    // Example 2: Model Approval Workflow
    println!("\n✅ Example 2: Model Approval Workflow");
    println!("------------------------------------");
    
    let approval_workflow_id = workflows.approve_model_workflow(
        "fraud-detector-v3",
        "3.0.0",
        "marvin.tutt@caiatech.com",
        "compliance-checklist-2025-001",
        vec!["staging", "production"]
    ).await?;
    
    println!("  Approval Workflow ID: {}", approval_workflow_id);

    // Example 3: Model Deployment Workflow
    println!("\n🚀 Example 3: Model Deployment Workflow");
    println!("--------------------------------------");
    
    let deployment_workflow_id = workflows.deploy_model_workflow(
        "fraud-detector-v3",
        "3.0.0",
        "production-us-east-1",
        "devops@caiatech.com"
    ).await?;
    
    println!("  Deployment Workflow ID: {}", deployment_workflow_id);

    // Example 4: Batch Evidence Processing
    println!("\n📦 Example 4: Batch Evidence Processing");
    println!("--------------------------------------");
    
    let evidence_packages = vec![
        AFDPEvidencePackage::model_deployment(
            "model-a", "1.0.0", "staging", "user1@caiatech.com"
        ),
        AFDPEvidencePackage::model_deployment(
            "model-b", "2.1.0", "staging", "user2@caiatech.com"
        ),
        AFDPEvidencePackage::model_training(
            "model-c", "training-123", "dataset-v1", 0.89, "trainer@caiatech.com"
        ),
    ];
    
    let batch_workflow_id = workflows.batch_evidence_workflow(evidence_packages).await?;
    println!("  Batch Workflow ID: {}", batch_workflow_id);

    // Example 5: Synchronous Evidence Signing
    println!("\n⚡ Example 5: Synchronous Evidence Signing");
    println!("------------------------------------------");
    
    let actor = Actor {
        actor_type: "demo_user".to_string(),
        id: "demo@caiatech.com".to_string(),
        auth_provider: Some("demo".to_string()),
    };

    let evidence = EvidencePackage::new("demo.event.completed".to_string(), actor)
        .add_metadata("demo_purpose".to_string(), json!("show temporal integration"))
        .add_metadata("timestamp".to_string(), json!(chrono::Utc::now()));

    let result = workflows.sign_evidence_sync(evidence).await?;
    
    println!("  ✅ Evidence signed successfully!");
    println!("  📝 Rekor Log ID: {}", result.receipt.rekor_log_id);
    println!("  🔍 Evidence Hash: {}", result.receipt.evidence_package_hash);
    println!("  📋 Audit Log ID: {}", result.audit_log_id);
    println!("  ✅ Validation Passed: {}", result.validation_result.is_valid);

    // Example 6: Using Direct Temporal Client
    println!("\n🔧 Example 6: Direct Temporal Client Usage");
    println!("------------------------------------------");
    
    let temporal_client = TemporalNotaryClient::new(TemporalNotaryConfig::default()).await?;
    
    let custom_evidence = AFDPEvidencePackage::model_approval(
        "critical-model",
        "1.0.0",
        "security-lead@caiatech.com",
        "security-checklist-001",
        vec!["production"]
    );

    let execution = temporal_client.sign_evidence(custom_evidence).await?;
    println!("  🆔 Workflow ID: {}", execution.workflow_id());
    
    // In a real implementation, you could:
    // let result = execution.wait_for_result().await?;
    println!("  ⏳ (In real implementation, would wait for workflow completion)");

    println!("\n🎉 All examples completed successfully!");
    println!("\n💡 Next Steps:");
    println!("  1. Set up actual Temporal server for production use");
    println!("  2. Configure real Vault and Rekor instances");
    println!("  3. Implement proper approval mechanisms");
    println!("  4. Add monitoring and alerting");
    println!("  5. Integrate with your CI/CD pipeline");

    Ok(())
}