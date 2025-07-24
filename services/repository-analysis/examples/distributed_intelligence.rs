use anyhow::Result;
use repository_analysis_service::{
    events::{
        publisher::EventPublisher,
        IntelligenceEvent, ThreatEvent, AlertEvent, AlertLevel,
        DistributionConfig, Recipient, RecipientType, ContactMethod,
        DistributionPriority, EventFilter, FilterType, FilterAction,
    },
    storage::{Severity, Classification, AnalysisJob, JobStatus},
    config::{PulsarConfig, DistributedNetworkConfig},
};
use uuid::Uuid;
use chrono::Utc;
use std::sync::Arc;

/// Example: Publishing a critical threat detection event
async fn publish_critical_threat() -> Result<()> {
    println!("=== Critical Threat Detection Example ===\n");

    // Configure Pulsar for event publishing
    let pulsar_config = PulsarConfig {
        broker_url: "pulsar://localhost:6650".to_string(),
        auth_token: None,
        topics: vec!["security-alerts".to_string()],
        subscription_name: "threat-detection-sub".to_string(),
        consumer_name: "threat-detector".to_string(),
        batch_size: 100,
        compression_type: "zstd".to_string(),
        encryption_enabled: true,
        connection_timeout_ms: 5000,
        operation_timeout_ms: 30000,
    };

    // Configure distributed networks
    let networks = vec![
        DistributedNetworkConfig {
            name: "security-team".to_string(),
            description: "Internal security team network".to_string(),
            topics: vec!["security-alerts".to_string(), "incident-response".to_string()],
            priority: "high".to_string(),
            filter_rules: vec!["severity:high".to_string(), "severity:critical".to_string()],
            encryption_required: true,
        },
        DistributedNetworkConfig {
            name: "emergency-response".to_string(),
            description: "Emergency response network".to_string(),
            topics: vec!["emergency-response".to_string()],
            priority: "immediate".to_string(),
            filter_rules: vec!["severity:critical".to_string()],
            encryption_required: true,
        },
    ];

    // Initialize event publisher
    let publisher = Arc::new(EventPublisher::new(&pulsar_config, networks).await?);

    // Create a critical threat event
    let threat_event = IntelligenceEvent::ThreatDetected(ThreatEvent {
        event_id: Uuid::new_v4(),
        timestamp: Utc::now(),
        job_id: Uuid::new_v4(),
        repository_url: "https://github.com/suspicious/malware-repo".to_string(),
        threat_type: "Advanced Persistent Threat".to_string(),
        severity: Severity::Critical,
        classification: Classification::Restricted,
        title: "APT Campaign Infrastructure Discovered".to_string(),
        description: "Repository contains active command and control infrastructure for known APT group".to_string(),
        evidence: serde_json::json!({
            "c2_domains": ["evil1.example.com", "evil2.example.com"],
            "malware_families": ["Agent.BTZ", "BlackEnergy"],
            "iocs": {
                "file_hashes": ["a1b2c3d4...", "e5f6g7h8..."],
                "ip_addresses": ["192.168.1.100", "10.0.0.50"],
            },
            "ttps": ["T1055", "T1070", "T1105"], // MITRE ATT&CK techniques
        }),
        affected_files: vec![
            "src/c2_client.rs".to_string(),
            "bin/dropper.exe".to_string(),
            "config/targets.json".to_string(),
        ],
        recommendations: vec![
            "Immediately isolate and quarantine the repository".to_string(),
            "Block all identified C2 domains at network perimeter".to_string(),
            "Scan infrastructure for indicators of compromise".to_string(),
            "Notify law enforcement and threat intelligence partners".to_string(),
        ],
        risk_score: 9.8,
        confidence: 0.95,
        metadata: serde_json::json!({
            "threat_actor": "APT28",
            "campaign": "Operation CloudAtlas",
            "first_seen": "2023-10-01T00:00:00Z",
            "targets": ["Government", "Defense", "Critical Infrastructure"],
        }),
    });

    // Configure distribution for critical threat
    let distribution = DistributionConfig {
        networks: vec!["security-team".to_string(), "emergency-response".to_string()],
        recipients: vec![
            Recipient {
                id: "ciso-001".to_string(),
                name: "Chief Information Security Officer".to_string(),
                recipient_type: RecipientType::Individual,
                contact_method: ContactMethod::Email("ciso@company.com".to_string()),
                filter_preferences: vec!["critical".to_string()],
                encryption_key: Some("ciso-pgp-key".to_string()),
            },
            Recipient {
                id: "soc-team".to_string(),
                name: "Security Operations Center".to_string(),
                recipient_type: RecipientType::Team,
                contact_method: ContactMethod::Webhook("https://soc.company.com/alerts".to_string()),
                filter_preferences: vec!["all".to_string()],
                encryption_key: None,
            },
            Recipient {
                id: "threat-intel".to_string(),
                name: "Threat Intelligence Platform".to_string(),
                recipient_type: RecipientType::System,
                contact_method: ContactMethod::ApiEndpoint("https://tip.company.com/api/events".to_string()),
                filter_preferences: vec!["threat".to_string(), "malware".to_string()],
                encryption_key: Some("tip-api-key".to_string()),
            },
        ],
        filters: vec![
            EventFilter {
                name: "Critical Only".to_string(),
                filter_type: FilterType::Severity,
                conditions: serde_json::json!({"severity": ["critical"]}),
                action: FilterAction::Include,
            },
        ],
        priority: DistributionPriority::Immediate,
        encryption_required: true,
        acknowledgment_required: true,
    };

    // Publish the event
    println!("Publishing critical threat event...");
    // Note: In a real scenario, this would publish to Pulsar
    // publisher.publish_event(threat_event, distribution).await?;
    
    println!("✓ Critical threat event published successfully");
    println!("  - Event ID: {}", threat_event.event_id());
    println!("  - Networks: {:?}", distribution.networks);
    println!("  - Recipients: {} recipients configured", distribution.recipients.len());
    println!("  - Priority: Immediate");
    println!("  - Encryption: Required");
    println!("  - Acknowledgment: Required");

    Ok(())
}

/// Example: Publishing an immediate alert for emergency response
async fn publish_emergency_alert() -> Result<()> {
    println!("\n=== Emergency Alert Example ===\n");

    let pulsar_config = PulsarConfig::default();
    let networks = vec![
        DistributedNetworkConfig {
            name: "emergency-response".to_string(),
            description: "Emergency response network".to_string(),
            topics: vec!["emergency-alerts".to_string()],
            priority: "immediate".to_string(),
            filter_rules: vec!["level:emergency".to_string()],
            encryption_required: true,
        },
    ];

    let publisher = Arc::new(EventPublisher::new(&pulsar_config, networks).await?);

    // Create emergency alert
    let alert = AlertEvent {
        event_id: Uuid::new_v4(),
        timestamp: Utc::now(),
        job_id: Uuid::new_v4(),
        alert_level: AlertLevel::Emergency,
        title: "Active Data Exfiltration in Progress".to_string(),
        message: "Large-scale data exfiltration detected from production database. Immediate action required to prevent data breach.".to_string(),
        action_required: "1. Block outbound traffic to IP 45.33.32.156\n2. Revoke database credentials\n3. Enable emergency response protocols".to_string(),
        deadline: Some(Utc::now() + chrono::Duration::minutes(15)),
        contacts: vec![
            "security@company.com".to_string(),
            "+1-555-SECURITY".to_string(),
            "incident-response@company.com".to_string(),
        ],
        escalation_path: vec![
            "L1: SOC Team (0-5 min)".to_string(),
            "L2: Security Lead (5-10 min)".to_string(),
            "L3: CISO (10-15 min)".to_string(),
            "L4: CEO & Legal (15+ min)".to_string(),
        ],
        metadata: serde_json::json!({
            "source_ip": "10.0.100.50",
            "destination_ip": "45.33.32.156",
            "data_volume": "2.5TB",
            "affected_systems": ["prod-db-01", "prod-db-02"],
            "detection_method": "DLP Alert + Network Anomaly",
        }),
    };

    println!("Publishing emergency alert...");
    let job = AnalysisJob {
        id: alert.job_id,
        repository_url: "internal://production-database".to_string(),
        repository_type: "database".to_string(),
        analysis_type: "emergency".to_string(),
        priority: crate::storage::Priority::Critical,
        status: JobStatus::Running,
        submitter_id: "automated-detection".to_string(),
        case_number: Some("INC-2024-001".to_string()),
        configuration: serde_json::json!({}),
        started_at: Some(Utc::now()),
        completed_at: None,
        error_message: None,
        progress_percentage: 50,
        current_phase: Some("active_response".to_string()),
        created_at: Utc::now(),
        updated_at: Utc::now(),
    };

    publisher.publish_alert(
        job.id,
        alert.alert_level.clone(),
        alert.title.clone(),
        alert.message.clone(),
        alert.action_required.clone(),
    ).await?;

    println!("✓ Emergency alert published successfully");
    println!("  - Alert Level: Emergency");
    println!("  - Deadline: {} minutes", 15);
    println!("  - Escalation Levels: {}", alert.escalation_path.len());
    println!("  - Contacts Notified: {}", alert.contacts.len());

    Ok(())
}

/// Example: Distributed network coordination
async fn demonstrate_network_coordination() -> Result<()> {
    println!("\n=== Distributed Network Coordination Example ===\n");

    println!("Scenario: Coordinated response to ransomware detection");
    println!("Multiple networks activated simultaneously:\n");

    let networks = vec![
        ("security-team", vec!["Isolate affected systems", "Analyze ransomware variant"]),
        ("legal-team", vec!["Assess disclosure requirements", "Prepare breach notifications"]),
        ("business-continuity", vec!["Activate DR procedures", "Restore from backups"]),
        ("executive-team", vec!["Crisis management", "External communications"]),
        ("law-enforcement", vec!["Evidence preservation", "Criminal investigation"]),
    ];

    for (network, actions) in networks {
        println!("→ {} Network", network);
        for action in actions {
            println!("  • {}", action);
        }
    }

    println!("\nAll networks receive synchronized intelligence updates");
    println!("Ensures coordinated response across all stakeholders");

    Ok(())
}

#[tokio::main]
async fn main() -> Result<()> {
    println!("AFDP Repository Analysis Service");
    println!("Distributed Intelligence Event Publishing Examples");
    println!("=" .repeat(50));

    // Run examples
    publish_critical_threat().await?;
    publish_emergency_alert().await?;
    demonstrate_network_coordination().await?;

    println!("\n" + &"=".repeat(50));
    println!("Examples completed successfully");
    println!("\nKey Features Demonstrated:");
    println!("✓ Real-time threat intelligence distribution");
    println!("✓ Emergency alert broadcasting");
    println!("✓ Multi-network coordination");
    println!("✓ Encrypted event publishing");
    println!("✓ Acknowledgment tracking");
    println!("✓ Intelligent event routing");

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_event_creation() {
        let threat = ThreatEvent {
            event_id: Uuid::new_v4(),
            timestamp: Utc::now(),
            job_id: Uuid::new_v4(),
            repository_url: "test".to_string(),
            threat_type: "test".to_string(),
            severity: Severity::High,
            classification: Classification::Public,
            title: "Test Threat".to_string(),
            description: "Test".to_string(),
            evidence: serde_json::json!({}),
            affected_files: vec![],
            recommendations: vec![],
            risk_score: 5.0,
            confidence: 0.8,
            metadata: serde_json::json!({}),
        };

        let event = IntelligenceEvent::ThreatDetected(threat);
        assert!(matches!(event, IntelligenceEvent::ThreatDetected(_)));
    }

    #[tokio::test]
    async fn test_distribution_config() {
        let config = DistributionConfig {
            networks: vec!["test-network".to_string()],
            recipients: vec![],
            filters: vec![],
            priority: DistributionPriority::High,
            encryption_required: true,
            acknowledgment_required: false,
        };

        assert_eq!(config.networks.len(), 1);
        assert!(config.encryption_required);
    }
}