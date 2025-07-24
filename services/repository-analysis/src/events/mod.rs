pub mod publisher;
pub mod schemas;
pub mod distribution;

use serde::{Deserialize, Serialize};
use uuid::Uuid;
use chrono::{DateTime, Utc};

use crate::storage::{Severity, Classification, FindingType};

/// Event types for distributed intelligence
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "event_type")]
pub enum IntelligenceEvent {
    /// Critical security threat detected
    ThreatDetected(ThreatEvent),
    
    /// Malware or backdoor discovered
    MalwareDiscovered(MalwareEvent),
    
    /// Data leak or exposure detected
    DataLeakDetected(DataLeakEvent),
    
    /// Suspicious activity patterns
    AnomalyDetected(AnomalyEvent),
    
    /// Vulnerable dependency found
    VulnerabilityDiscovered(VulnerabilityEvent),
    
    /// Repository analysis completed
    AnalysisCompleted(AnalysisCompletedEvent),
    
    /// Real-time alert for immediate action
    ImmediateAlert(AlertEvent),
}

/// Threat event for critical security issues
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatEvent {
    pub event_id: Uuid,
    pub timestamp: DateTime<Utc>,
    pub job_id: Uuid,
    pub repository_url: String,
    pub threat_type: String,
    pub severity: Severity,
    pub classification: Classification,
    pub title: String,
    pub description: String,
    pub evidence: serde_json::Value,
    pub affected_files: Vec<String>,
    pub recommendations: Vec<String>,
    pub risk_score: f32,
    pub confidence: f32,
    pub metadata: serde_json::Value,
}

/// Malware discovery event
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MalwareEvent {
    pub event_id: Uuid,
    pub timestamp: DateTime<Utc>,
    pub job_id: Uuid,
    pub repository_url: String,
    pub malware_type: String,
    pub file_path: String,
    pub file_hash: String,
    pub signature_matches: Vec<String>,
    pub behavior_indicators: Vec<String>,
    pub severity: Severity,
    pub quarantine_status: QuarantineStatus,
    pub metadata: serde_json::Value,
}

/// Data leak detection event
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DataLeakEvent {
    pub event_id: Uuid,
    pub timestamp: DateTime<Utc>,
    pub job_id: Uuid,
    pub repository_url: String,
    pub leak_type: DataLeakType,
    pub severity: Severity,
    pub exposed_data_types: Vec<String>,
    pub affected_files: Vec<String>,
    pub exposure_scope: ExposureScope,
    pub remediation_required: bool,
    pub metadata: serde_json::Value,
}

/// Anomaly detection event
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnomalyEvent {
    pub event_id: Uuid,
    pub timestamp: DateTime<Utc>,
    pub job_id: Uuid,
    pub repository_url: String,
    pub anomaly_type: String,
    pub description: String,
    pub severity: Severity,
    pub indicators: Vec<String>,
    pub baseline_deviation: f32,
    pub confidence: f32,
    pub metadata: serde_json::Value,
}

/// Vulnerability discovery event
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VulnerabilityEvent {
    pub event_id: Uuid,
    pub timestamp: DateTime<Utc>,
    pub job_id: Uuid,
    pub repository_url: String,
    pub vulnerability_type: String,
    pub severity: Severity,
    pub cve_ids: Vec<String>,
    pub affected_components: Vec<AffectedComponent>,
    pub exploitability_score: f32,
    pub patch_available: bool,
    pub recommendations: Vec<String>,
    pub metadata: serde_json::Value,
}

/// Analysis completion event
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnalysisCompletedEvent {
    pub event_id: Uuid,
    pub timestamp: DateTime<Utc>,
    pub job_id: Uuid,
    pub repository_url: String,
    pub analysis_duration_ms: i64,
    pub total_files_analyzed: i32,
    pub findings_summary: FindingsSummary,
    pub risk_score: f32,
    pub classification: Classification,
    pub report_url: Option<String>,
    pub metadata: serde_json::Value,
}

/// Immediate alert for critical issues
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AlertEvent {
    pub event_id: Uuid,
    pub timestamp: DateTime<Utc>,
    pub job_id: Uuid,
    pub alert_level: AlertLevel,
    pub title: String,
    pub message: String,
    pub action_required: String,
    pub deadline: Option<DateTime<Utc>>,
    pub contacts: Vec<String>,
    pub escalation_path: Vec<String>,
    pub metadata: serde_json::Value,
}

/// Distribution configuration for events
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DistributionConfig {
    pub networks: Vec<String>,
    pub recipients: Vec<Recipient>,
    pub filters: Vec<EventFilter>,
    pub priority: DistributionPriority,
    pub encryption_required: bool,
    pub acknowledgment_required: bool,
}

/// Event recipient configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Recipient {
    pub id: String,
    pub name: String,
    pub recipient_type: RecipientType,
    pub contact_method: ContactMethod,
    pub filter_preferences: Vec<String>,
    pub encryption_key: Option<String>,
}

/// Event filtering rules
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EventFilter {
    pub name: String,
    pub filter_type: FilterType,
    pub conditions: serde_json::Value,
    pub action: FilterAction,
}

// Enums for event properties

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum QuarantineStatus {
    Quarantined,
    PendingQuarantine,
    NotQuarantined,
    Failed,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum DataLeakType {
    Credentials,
    PersonalData,
    FinancialData,
    HealthData,
    IntellectualProperty,
    Other(String),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ExposureScope {
    Public,
    Internal,
    Limited,
    Unknown,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AffectedComponent {
    pub name: String,
    pub version: String,
    pub component_type: String,
    pub file_path: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FindingsSummary {
    pub total_findings: i32,
    pub critical: i32,
    pub high: i32,
    pub medium: i32,
    pub low: i32,
    pub by_type: HashMap<String, i32>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum AlertLevel {
    Emergency,
    Critical,
    Warning,
    Info,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum RecipientType {
    Individual,
    Team,
    Organization,
    System,
    Service,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ContactMethod {
    PulsarTopic(String),
    Webhook(String),
    Email(String),
    Sms(String),
    ApiEndpoint(String),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum FilterType {
    Severity,
    EventType,
    Repository,
    Classification,
    Custom,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum FilterAction {
    Include,
    Exclude,
    Transform,
    Aggregate,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum DistributionPriority {
    Immediate,
    High,
    Normal,
    Low,
}

/// Event metadata for tracking and auditing
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EventMetadata {
    pub event_id: Uuid,
    pub correlation_id: Option<Uuid>,
    pub source: String,
    pub version: String,
    pub timestamp: DateTime<Utc>,
    pub ttl_seconds: Option<i64>,
    pub retry_count: i32,
    pub distribution_list: Vec<String>,
}

impl IntelligenceEvent {
    pub fn event_id(&self) -> Uuid {
        match self {
            IntelligenceEvent::ThreatDetected(e) => e.event_id,
            IntelligenceEvent::MalwareDiscovered(e) => e.event_id,
            IntelligenceEvent::DataLeakDetected(e) => e.event_id,
            IntelligenceEvent::AnomalyDetected(e) => e.event_id,
            IntelligenceEvent::VulnerabilityDiscovered(e) => e.event_id,
            IntelligenceEvent::AnalysisCompleted(e) => e.event_id,
            IntelligenceEvent::ImmediateAlert(e) => e.event_id,
        }
    }

    pub fn timestamp(&self) -> DateTime<Utc> {
        match self {
            IntelligenceEvent::ThreatDetected(e) => e.timestamp,
            IntelligenceEvent::MalwareDiscovered(e) => e.timestamp,
            IntelligenceEvent::DataLeakDetected(e) => e.timestamp,
            IntelligenceEvent::AnomalyDetected(e) => e.timestamp,
            IntelligenceEvent::VulnerabilityDiscovered(e) => e.timestamp,
            IntelligenceEvent::AnalysisCompleted(e) => e.timestamp,
            IntelligenceEvent::ImmediateAlert(e) => e.timestamp,
        }
    }

    pub fn severity(&self) -> Option<Severity> {
        match self {
            IntelligenceEvent::ThreatDetected(e) => Some(e.severity.clone()),
            IntelligenceEvent::MalwareDiscovered(e) => Some(e.severity.clone()),
            IntelligenceEvent::DataLeakDetected(e) => Some(e.severity.clone()),
            IntelligenceEvent::AnomalyDetected(e) => Some(e.severity.clone()),
            IntelligenceEvent::VulnerabilityDiscovered(e) => Some(e.severity.clone()),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_event_creation() {
        let threat_event = ThreatEvent {
            event_id: Uuid::new_v4(),
            timestamp: Utc::now(),
            job_id: Uuid::new_v4(),
            repository_url: "https://github.com/test/repo".to_string(),
            threat_type: "Backdoor".to_string(),
            severity: Severity::Critical,
            classification: Classification::Restricted,
            title: "Backdoor detected".to_string(),
            description: "Suspicious backdoor pattern found".to_string(),
            evidence: serde_json::json!({"pattern": "backdoor"}),
            affected_files: vec!["malicious.js".to_string()],
            recommendations: vec!["Remove backdoor code".to_string()],
            risk_score: 9.5,
            confidence: 0.95,
            metadata: serde_json::json!({}),
        };

        let event = IntelligenceEvent::ThreatDetected(threat_event);
        assert!(matches!(event, IntelligenceEvent::ThreatDetected(_)));
    }

    #[test]
    fn test_event_serialization() {
        let alert = AlertEvent {
            event_id: Uuid::new_v4(),
            timestamp: Utc::now(),
            job_id: Uuid::new_v4(),
            alert_level: AlertLevel::Critical,
            title: "Immediate action required".to_string(),
            message: "Critical security breach detected".to_string(),
            action_required: "Isolate affected systems".to_string(),
            deadline: Some(Utc::now() + chrono::Duration::hours(1)),
            contacts: vec!["security@example.com".to_string()],
            escalation_path: vec!["Level 1".to_string(), "Level 2".to_string()],
            metadata: serde_json::json!({}),
        };

        let event = IntelligenceEvent::ImmediateAlert(alert);
        
        // Test serialization
        let serialized = serde_json::to_string(&event).unwrap();
        assert!(serialized.contains("ImmediateAlert"));
        
        // Test deserialization
        let deserialized: IntelligenceEvent = serde_json::from_str(&serialized).unwrap();
        assert!(matches!(deserialized, IntelligenceEvent::ImmediateAlert(_)));
    }

    #[test]
    fn test_distribution_config() {
        let config = DistributionConfig {
            networks: vec!["security-team".to_string(), "incident-response".to_string()],
            recipients: vec![
                Recipient {
                    id: "sec-001".to_string(),
                    name: "Security Team".to_string(),
                    recipient_type: RecipientType::Team,
                    contact_method: ContactMethod::PulsarTopic("security-alerts".to_string()),
                    filter_preferences: vec!["critical".to_string(), "high".to_string()],
                    encryption_key: Some("public-key-123".to_string()),
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

        assert_eq!(config.networks.len(), 2);
        assert_eq!(config.priority, DistributionPriority::Immediate);
        assert!(config.encryption_required);
    }
}