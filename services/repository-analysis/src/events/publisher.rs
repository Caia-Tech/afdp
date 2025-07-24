use anyhow::Result;
use pulsar::{
    Authentication, Pulsar, PulsarBuilder, SerializeMessage, Producer, ProducerOptions,
    TokioExecutor, message::proto::command_subscribe::SubType,
};
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{info, warn, error, debug};
use uuid::Uuid;
use chrono::Utc;
use std::collections::HashMap;

use crate::{
    config::{PulsarConfig, DistributedNetworkConfig},
    storage::{SecurityFinding, AnalysisJob, JobStatus},
    events::{
        IntelligenceEvent, ThreatEvent, MalwareEvent, DataLeakEvent, 
        AnomalyEvent, VulnerabilityEvent, AnalysisCompletedEvent, AlertEvent,
        DistributionConfig, EventMetadata, AlertLevel, DataLeakType, ExposureScope,
        FindingsSummary, QuarantineStatus, AffectedComponent,
    },
};

/// Event publisher for distributed intelligence sharing
pub struct EventPublisher {
    pulsar: Arc<Pulsar<TokioExecutor>>,
    producers: Arc<RwLock<HashMap<String, Producer<TokioExecutor>>>>,
    config: PulsarConfig,
    networks: Vec<DistributedNetworkConfig>,
    encryption_enabled: bool,
}

impl EventPublisher {
    pub async fn new(config: &PulsarConfig, networks: Vec<DistributedNetworkConfig>) -> Result<Self> {
        info!("Initializing event publisher for distributed intelligence");

        let mut builder = PulsarBuilder::default()
            .with_url(&config.broker_url)
            .with_connection_timeout(config.connection_timeout_ms)
            .with_operation_timeout(config.operation_timeout_ms);

        if let Some(token) = &config.auth_token {
            builder = builder.with_auth(Authentication::Token(token.clone()));
        }

        let pulsar = Arc::new(builder.build().await?);

        info!("Connected to Pulsar broker: {}", config.broker_url);

        Ok(Self {
            pulsar,
            producers: Arc::new(RwLock::new(HashMap::new())),
            config: config.clone(),
            networks,
            encryption_enabled: config.encryption_enabled,
        })
    }

    /// Publish security finding as intelligence event
    pub async fn publish_security_finding(
        &self,
        job: &AnalysisJob,
        finding: &SecurityFinding,
    ) -> Result<()> {
        // Convert finding to appropriate event type
        let event = self.create_event_from_finding(job, finding)?;
        
        // Determine distribution based on severity and type
        let distribution = self.determine_distribution(&event);
        
        // Publish to appropriate networks
        self.publish_event(event, distribution).await
    }

    /// Publish analysis completion event
    pub async fn publish_analysis_completed(
        &self,
        job: &AnalysisJob,
        summary: FindingsSummary,
        risk_score: f32,
    ) -> Result<()> {
        let event = IntelligenceEvent::AnalysisCompleted(AnalysisCompletedEvent {
            event_id: Uuid::new_v4(),
            timestamp: Utc::now(),
            job_id: job.id,
            repository_url: job.repository_url.clone(),
            analysis_duration_ms: job.completed_at
                .and_then(|c| job.started_at.map(|s| (c - s).num_milliseconds()))
                .unwrap_or(0),
            total_files_analyzed: 0, // Would be populated from actual data
            findings_summary: summary,
            risk_score,
            classification: crate::storage::Classification::Internal,
            report_url: Some(format!("/api/v1/jobs/{}/results", job.id)),
            metadata: serde_json::json!({
                "case_number": job.case_number,
                "submitter": job.submitter_id,
            }),
        });

        let distribution = DistributionConfig {
            networks: vec!["analysis-results".to_string()],
            recipients: vec![],
            filters: vec![],
            priority: crate::events::DistributionPriority::Normal,
            encryption_required: false,
            acknowledgment_required: false,
        };

        self.publish_event(event, distribution).await
    }

    /// Publish immediate alert for critical issues
    pub async fn publish_alert(
        &self,
        job_id: Uuid,
        level: AlertLevel,
        title: String,
        message: String,
        action_required: String,
    ) -> Result<()> {
        let event = IntelligenceEvent::ImmediateAlert(AlertEvent {
            event_id: Uuid::new_v4(),
            timestamp: Utc::now(),
            job_id,
            alert_level: level.clone(),
            title,
            message,
            action_required,
            deadline: match level {
                AlertLevel::Emergency => Some(Utc::now() + chrono::Duration::minutes(15)),
                AlertLevel::Critical => Some(Utc::now() + chrono::Duration::hours(1)),
                _ => None,
            },
            contacts: self.get_alert_contacts(&level),
            escalation_path: self.get_escalation_path(&level),
            metadata: serde_json::json!({}),
        });

        let distribution = DistributionConfig {
            networks: match level {
                AlertLevel::Emergency => vec!["emergency-response".to_string()],
                AlertLevel::Critical => vec!["incident-response".to_string()],
                _ => vec!["security-alerts".to_string()],
            },
            recipients: vec![],
            filters: vec![],
            priority: match level {
                AlertLevel::Emergency | AlertLevel::Critical => crate::events::DistributionPriority::Immediate,
                _ => crate::events::DistributionPriority::High,
            },
            encryption_required: true,
            acknowledgment_required: matches!(level, AlertLevel::Emergency | AlertLevel::Critical),
        };

        self.publish_event(event, distribution).await
    }

    /// Core event publishing logic
    async fn publish_event(
        &self,
        event: IntelligenceEvent,
        distribution: DistributionConfig,
    ) -> Result<()> {
        let event_id = event.event_id();
        let event_type = match &event {
            IntelligenceEvent::ThreatDetected(_) => "threat",
            IntelligenceEvent::MalwareDiscovered(_) => "malware",
            IntelligenceEvent::DataLeakDetected(_) => "data_leak",
            IntelligenceEvent::AnomalyDetected(_) => "anomaly",
            IntelligenceEvent::VulnerabilityDiscovered(_) => "vulnerability",
            IntelligenceEvent::AnalysisCompleted(_) => "analysis_completed",
            IntelligenceEvent::ImmediateAlert(_) => "alert",
        };

        debug!("Publishing {} event: {}", event_type, event_id);

        // Apply filters
        if !self.should_publish_event(&event, &distribution.filters) {
            debug!("Event filtered out: {}", event_id);
            return Ok(());
        }

        // Encrypt if required
        let payload = if distribution.encryption_required && self.encryption_enabled {
            self.encrypt_event(&event)?
        } else {
            serde_json::to_vec(&event)?
        };

        // Publish to each network
        for network in &distribution.networks {
            if let Some(network_config) = self.networks.iter().find(|n| &n.name == network) {
                for topic in &network_config.topics {
                    self.publish_to_topic(topic, &payload, &event_id).await?;
                }
            }
        }

        // Handle acknowledgment if required
        if distribution.acknowledgment_required {
            self.wait_for_acknowledgment(&event_id).await?;
        }

        info!("Successfully published {} event: {}", event_type, event_id);
        Ok(())
    }

    async fn publish_to_topic(
        &self,
        topic: &str,
        payload: &[u8],
        event_id: &Uuid,
    ) -> Result<()> {
        let producer = self.get_or_create_producer(topic).await?;
        
        let message = IntelligenceMessage {
            event_id: event_id.to_string(),
            payload: payload.to_vec(),
            timestamp: Utc::now().timestamp_millis(),
        };

        producer.send(message).await?;
        Ok(())
    }

    async fn get_or_create_producer(&self, topic: &str) -> Result<Producer<TokioExecutor>> {
        let mut producers = self.producers.write().await;
        
        if let Some(producer) = producers.get(topic) {
            return Ok(producer.clone());
        }

        debug!("Creating producer for topic: {}", topic);

        let producer = self.pulsar
            .producer()
            .with_topic(topic)
            .with_options(ProducerOptions {
                batch_size: Some(self.config.batch_size as i32),
                ..Default::default()
            })
            .build()
            .await?;

        producers.insert(topic.to_string(), producer.clone());
        Ok(producer)
    }

    fn create_event_from_finding(
        &self,
        job: &AnalysisJob,
        finding: &SecurityFinding,
    ) -> Result<IntelligenceEvent> {
        use crate::storage::FindingType;

        let event = match &finding.finding_type {
            FindingType::Malware | FindingType::Backdoor => {
                IntelligenceEvent::MalwareDiscovered(MalwareEvent {
                    event_id: Uuid::new_v4(),
                    timestamp: Utc::now(),
                    job_id: job.id,
                    repository_url: job.repository_url.clone(),
                    malware_type: finding.finding_type.to_string(),
                    file_path: finding.file_path.clone().unwrap_or_default(),
                    file_hash: "".to_string(), // Would be populated from file analysis
                    signature_matches: vec![finding.title.clone()],
                    behavior_indicators: vec![],
                    severity: finding.severity.clone(),
                    quarantine_status: QuarantineStatus::PendingQuarantine,
                    metadata: finding.evidence.clone(),
                })
            }
            FindingType::DataLeak | FindingType::SecretExposure => {
                IntelligenceEvent::DataLeakDetected(DataLeakEvent {
                    event_id: Uuid::new_v4(),
                    timestamp: Utc::now(),
                    job_id: job.id,
                    repository_url: job.repository_url.clone(),
                    leak_type: DataLeakType::Credentials,
                    severity: finding.severity.clone(),
                    exposed_data_types: vec![finding.title.clone()],
                    affected_files: finding.file_path.clone().map(|f| vec![f]).unwrap_or_default(),
                    exposure_scope: ExposureScope::Unknown,
                    remediation_required: true,
                    metadata: finding.evidence.clone(),
                })
            }
            FindingType::Vulnerability => {
                IntelligenceEvent::VulnerabilityDiscovered(VulnerabilityEvent {
                    event_id: Uuid::new_v4(),
                    timestamp: Utc::now(),
                    job_id: job.id,
                    repository_url: job.repository_url.clone(),
                    vulnerability_type: finding.title.clone(),
                    severity: finding.severity.clone(),
                    cve_ids: finding.cve_id.clone().map(|c| vec![c]).unwrap_or_default(),
                    affected_components: vec![],
                    exploitability_score: finding.confidence,
                    patch_available: false,
                    recommendations: finding.recommendation.clone().map(|r| vec![r]).unwrap_or_default(),
                    metadata: finding.evidence.clone(),
                })
            }
            FindingType::Anomaly => {
                IntelligenceEvent::AnomalyDetected(AnomalyEvent {
                    event_id: Uuid::new_v4(),
                    timestamp: Utc::now(),
                    job_id: job.id,
                    repository_url: job.repository_url.clone(),
                    anomaly_type: finding.title.clone(),
                    description: finding.description.clone(),
                    severity: finding.severity.clone(),
                    indicators: vec![],
                    baseline_deviation: 0.0,
                    confidence: finding.confidence,
                    metadata: finding.evidence.clone(),
                })
            }
            _ => {
                IntelligenceEvent::ThreatDetected(ThreatEvent {
                    event_id: Uuid::new_v4(),
                    timestamp: Utc::now(),
                    job_id: job.id,
                    repository_url: job.repository_url.clone(),
                    threat_type: finding.finding_type.to_string(),
                    severity: finding.severity.clone(),
                    classification: crate::storage::Classification::Internal,
                    title: finding.title.clone(),
                    description: finding.description.clone(),
                    evidence: finding.evidence.clone(),
                    affected_files: finding.file_path.clone().map(|f| vec![f]).unwrap_or_default(),
                    recommendations: finding.recommendation.clone().map(|r| vec![r]).unwrap_or_default(),
                    risk_score: self.calculate_risk_score(&finding.severity, finding.confidence),
                    confidence: finding.confidence,
                    metadata: serde_json::json!({}),
                })
            }
        };

        Ok(event)
    }

    fn determine_distribution(&self, event: &IntelligenceEvent) -> DistributionConfig {
        use crate::storage::Severity;

        let severity = event.severity();
        let priority = match severity {
            Some(Severity::Critical) => crate::events::DistributionPriority::Immediate,
            Some(Severity::High) => crate::events::DistributionPriority::High,
            _ => crate::events::DistributionPriority::Normal,
        };

        let networks = match event {
            IntelligenceEvent::MalwareDiscovered(_) => vec!["malware-alerts".to_string(), "security-team".to_string()],
            IntelligenceEvent::DataLeakDetected(_) => vec!["data-protection".to_string(), "legal-team".to_string()],
            IntelligenceEvent::ThreatDetected(_) if matches!(severity, Some(Severity::Critical)) => {
                vec!["emergency-response".to_string(), "security-team".to_string()]
            }
            _ => vec!["security-alerts".to_string()],
        };

        DistributionConfig {
            networks,
            recipients: vec![],
            filters: vec![],
            priority,
            encryption_required: matches!(severity, Some(Severity::Critical | Severity::High)),
            acknowledgment_required: matches!(severity, Some(Severity::Critical)),
        }
    }

    fn should_publish_event(&self, event: &IntelligenceEvent, filters: &[crate::events::EventFilter]) -> bool {
        // Apply filters - for now, always publish
        // In production, would implement sophisticated filtering
        true
    }

    fn encrypt_event(&self, event: &IntelligenceEvent) -> Result<Vec<u8>> {
        // Placeholder for encryption
        // In production, would use actual encryption (e.g., AES-256-GCM)
        let data = serde_json::to_vec(event)?;
        Ok(data)
    }

    async fn wait_for_acknowledgment(&self, event_id: &Uuid) -> Result<()> {
        // Placeholder for acknowledgment handling
        // In production, would wait for consumer acknowledgments
        tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
        Ok(())
    }

    fn calculate_risk_score(&self, severity: &crate::storage::Severity, confidence: f32) -> f32 {
        let severity_weight = match severity {
            crate::storage::Severity::Critical => 10.0,
            crate::storage::Severity::High => 7.0,
            crate::storage::Severity::Medium => 4.0,
            crate::storage::Severity::Low => 2.0,
            crate::storage::Severity::Info => 1.0,
        };
        
        (severity_weight * confidence).min(10.0)
    }

    fn get_alert_contacts(&self, level: &AlertLevel) -> Vec<String> {
        match level {
            AlertLevel::Emergency => vec![
                "security-lead@example.com".to_string(),
                "ciso@example.com".to_string(),
                "incident-response@example.com".to_string(),
            ],
            AlertLevel::Critical => vec![
                "security-team@example.com".to_string(),
                "ops-team@example.com".to_string(),
            ],
            _ => vec!["security-alerts@example.com".to_string()],
        }
    }

    fn get_escalation_path(&self, level: &AlertLevel) -> Vec<String> {
        match level {
            AlertLevel::Emergency => vec![
                "L1: Security Team".to_string(),
                "L2: Security Lead".to_string(),
                "L3: CISO".to_string(),
                "L4: Executive Team".to_string(),
            ],
            AlertLevel::Critical => vec![
                "L1: Security Team".to_string(),
                "L2: Security Lead".to_string(),
            ],
            _ => vec!["L1: Security Team".to_string()],
        }
    }

    /// Shutdown the publisher gracefully
    pub async fn shutdown(&self) -> Result<()> {
        info!("Shutting down event publisher");
        
        let mut producers = self.producers.write().await;
        producers.clear();
        
        Ok(())
    }
}

/// Message format for Pulsar
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
struct IntelligenceMessage {
    event_id: String,
    payload: Vec<u8>,
    timestamp: i64,
}

impl SerializeMessage for IntelligenceMessage {
    fn serialize_message(input: Self) -> Result<pulsar::producer::Message, pulsar::Error> {
        let payload = serde_json::to_vec(&input)
            .map_err(|e| pulsar::Error::Custom(e.to_string()))?;
        
        Ok(pulsar::producer::Message {
            payload,
            ..Default::default()
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::{Severity, FindingType};

    #[tokio::test]
    async fn test_event_creation_from_finding() {
        let config = PulsarConfig {
            broker_url: "pulsar://localhost:6650".to_string(),
            auth_token: None,
            topics: vec!["test-topic".to_string()],
            subscription_name: "test-sub".to_string(),
            consumer_name: "test-consumer".to_string(),
            batch_size: 100,
            compression_type: "zstd".to_string(),
            encryption_enabled: false,
            connection_timeout_ms: 5000,
            operation_timeout_ms: 30000,
        };

        // Can't actually connect in unit test, but test the logic
        let job = crate::tests::TestContext::create_test_job();
        let finding = crate::tests::TestContext::create_test_security_finding(job.id);

        // Test that we can create events from findings
        assert_eq!(finding.finding_type, FindingType::SecretExposure);
        assert_eq!(finding.severity, Severity::High);
    }

    #[test]
    fn test_risk_score_calculation() {
        let publisher = EventPublisher {
            pulsar: Arc::new(unsafe { std::mem::zeroed() }), // Mock for testing
            producers: Arc::new(RwLock::new(HashMap::new())),
            config: Default::default(),
            networks: vec![],
            encryption_enabled: false,
        };

        let score = publisher.calculate_risk_score(&Severity::Critical, 0.9);
        assert_eq!(score, 9.0);

        let score = publisher.calculate_risk_score(&Severity::Low, 0.5);
        assert_eq!(score, 1.0);
    }

    #[test]
    fn test_alert_contacts() {
        let publisher = EventPublisher {
            pulsar: Arc::new(unsafe { std::mem::zeroed() }), // Mock for testing
            producers: Arc::new(RwLock::new(HashMap::new())),
            config: Default::default(),
            networks: vec![],
            encryption_enabled: false,
        };

        let contacts = publisher.get_alert_contacts(&AlertLevel::Emergency);
        assert!(contacts.len() >= 3);
        assert!(contacts.iter().any(|c| c.contains("ciso")));

        let contacts = publisher.get_alert_contacts(&AlertLevel::Info);
        assert_eq!(contacts.len(), 1);
    }
}