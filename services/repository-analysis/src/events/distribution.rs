use anyhow::Result;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{info, warn, debug, error};
use chrono::{DateTime, Utc};

use crate::{
    config::DistributedNetworkConfig,
    events::{
        IntelligenceEvent, DistributionConfig, Recipient, EventFilter,
        FilterType, FilterAction, RecipientType, ContactMethod,
        EventMetadata, DistributionPriority,
    },
    storage::Severity,
};

/// Manages intelligent distribution of events to appropriate stakeholders
pub struct DistributionManager {
    networks: HashMap<String, NetworkChannel>,
    recipients: Arc<RwLock<HashMap<String, Recipient>>>,
    routing_rules: Vec<RoutingRule>,
    rate_limiters: Arc<RwLock<HashMap<String, RateLimiter>>>,
}

impl DistributionManager {
    pub async fn new(networks: Vec<DistributedNetworkConfig>) -> Result<Self> {
        let mut network_channels = HashMap::new();
        
        for network in networks {
            let channel = NetworkChannel::new(network).await?;
            network_channels.insert(channel.name.clone(), channel);
        }

        let routing_rules = Self::load_default_routing_rules();

        Ok(Self {
            networks: network_channels,
            recipients: Arc::new(RwLock::new(HashMap::new())),
            routing_rules,
            rate_limiters: Arc::new(RwLock::new(HashMap::new())),
        })
    }

    /// Register a recipient for event distribution
    pub async fn register_recipient(&self, recipient: Recipient) -> Result<()> {
        let mut recipients = self.recipients.write().await;
        recipients.insert(recipient.id.clone(), recipient);
        info!("Registered recipient: {}", recipients.len());
        Ok(())
    }

    /// Route an event to appropriate recipients
    pub async fn route_event(&self, event: &IntelligenceEvent, config: &DistributionConfig) -> Result<Vec<DeliveryResult>> {
        debug!("Routing event {} to {} networks", event.event_id(), config.networks.len());

        let mut delivery_results = Vec::new();

        // Apply routing rules
        let effective_recipients = self.apply_routing_rules(event, config).await?;

        // Group recipients by delivery method
        let delivery_groups = self.group_by_delivery_method(&effective_recipients);

        // Deliver to each group
        for (method, recipients) in delivery_groups {
            match method {
                DeliveryMethod::Network(network) => {
                    if let Some(channel) = self.networks.get(&network) {
                        let result = self.deliver_to_network(channel, event, &recipients).await?;
                        delivery_results.push(result);
                    }
                }
                DeliveryMethod::Direct(contact) => {
                    let result = self.deliver_direct(contact, event, &recipients).await?;
                    delivery_results.push(result);
                }
            }
        }

        // Record distribution metrics
        self.record_distribution_metrics(&delivery_results).await;

        Ok(delivery_results)
    }

    /// Apply routing rules to determine effective recipients
    async fn apply_routing_rules(
        &self,
        event: &IntelligenceEvent,
        config: &DistributionConfig,
    ) -> Result<Vec<Recipient>> {
        let mut effective_recipients = Vec::new();

        // Get all registered recipients
        let recipients = self.recipients.read().await;

        // Apply global routing rules
        for rule in &self.routing_rules {
            if rule.matches(event) {
                for recipient_id in &rule.recipient_ids {
                    if let Some(recipient) = recipients.get(recipient_id) {
                        effective_recipients.push(recipient.clone());
                    }
                }
            }
        }

        // Add explicitly configured recipients
        for recipient in &config.recipients {
            effective_recipients.push(recipient.clone());
        }

        // Apply filters
        effective_recipients = self.apply_filters(effective_recipients, &config.filters, event).await?;

        // Apply rate limiting
        effective_recipients = self.apply_rate_limiting(effective_recipients).await?;

        // Deduplicate
        effective_recipients.sort_by(|a, b| a.id.cmp(&b.id));
        effective_recipients.dedup_by(|a, b| a.id == b.id);

        Ok(effective_recipients)
    }

    /// Apply event filters
    async fn apply_filters(
        &self,
        recipients: Vec<Recipient>,
        filters: &[EventFilter],
        event: &IntelligenceEvent,
    ) -> Result<Vec<Recipient>> {
        let mut filtered = recipients;

        for filter in filters {
            filtered = match filter.action {
                FilterAction::Include => {
                    filtered.into_iter()
                        .filter(|r| self.filter_matches(&filter, event, r))
                        .collect()
                }
                FilterAction::Exclude => {
                    filtered.into_iter()
                        .filter(|r| !self.filter_matches(&filter, event, r))
                        .collect()
                }
                _ => filtered, // Transform and Aggregate not implemented in this example
            };
        }

        Ok(filtered)
    }

    /// Check if a filter matches
    fn filter_matches(&self, filter: &EventFilter, event: &IntelligenceEvent, recipient: &Recipient) -> bool {
        match filter.filter_type {
            FilterType::Severity => {
                if let Some(severity) = event.severity() {
                    // Check if recipient wants this severity level
                    recipient.filter_preferences.iter().any(|pref| {
                        pref.to_lowercase() == format!("{:?}", severity).to_lowercase()
                    })
                } else {
                    false
                }
            }
            FilterType::EventType => {
                let event_type = match event {
                    IntelligenceEvent::ThreatDetected(_) => "threat",
                    IntelligenceEvent::MalwareDiscovered(_) => "malware",
                    IntelligenceEvent::DataLeakDetected(_) => "data_leak",
                    IntelligenceEvent::AnomalyDetected(_) => "anomaly",
                    IntelligenceEvent::VulnerabilityDiscovered(_) => "vulnerability",
                    IntelligenceEvent::AnalysisCompleted(_) => "analysis_completed",
                    IntelligenceEvent::ImmediateAlert(_) => "alert",
                };
                recipient.filter_preferences.contains(&event_type.to_string())
            }
            _ => true, // Other filter types not implemented
        }
    }

    /// Apply rate limiting to prevent recipient overload
    async fn apply_rate_limiting(&self, recipients: Vec<Recipient>) -> Result<Vec<Recipient>> {
        let mut rate_limiters = self.rate_limiters.write().await;
        let mut allowed_recipients = Vec::new();

        for recipient in recipients {
            let limiter = rate_limiters.entry(recipient.id.clone())
                .or_insert_with(|| RateLimiter::new(100, 3600)); // 100 events per hour

            if limiter.check_and_update() {
                allowed_recipients.push(recipient);
            } else {
                warn!("Rate limit exceeded for recipient: {}", recipient.id);
            }
        }

        Ok(allowed_recipients)
    }

    /// Group recipients by delivery method
    fn group_by_delivery_method(&self, recipients: &[Recipient]) -> HashMap<DeliveryMethod, Vec<Recipient>> {
        let mut groups: HashMap<DeliveryMethod, Vec<Recipient>> = HashMap::new();

        for recipient in recipients {
            let method = match &recipient.contact_method {
                ContactMethod::PulsarTopic(topic) => {
                    DeliveryMethod::Network(self.topic_to_network(topic))
                }
                ContactMethod::Webhook(url) => DeliveryMethod::Direct(url.clone()),
                ContactMethod::Email(email) => DeliveryMethod::Direct(format!("email:{}", email)),
                ContactMethod::Sms(phone) => DeliveryMethod::Direct(format!("sms:{}", phone)),
                ContactMethod::ApiEndpoint(endpoint) => DeliveryMethod::Direct(endpoint.clone()),
            };

            groups.entry(method).or_insert_with(Vec::new).push(recipient.clone());
        }

        groups
    }

    /// Map topic to network
    fn topic_to_network(&self, topic: &str) -> String {
        // Extract network from topic name
        topic.split('-').next().unwrap_or("default").to_string()
    }

    /// Deliver event to a network channel
    async fn deliver_to_network(
        &self,
        channel: &NetworkChannel,
        event: &IntelligenceEvent,
        recipients: &[Recipient],
    ) -> Result<DeliveryResult> {
        let start_time = Utc::now();
        
        // Simulate network delivery
        // In production, this would publish to Pulsar topics
        tokio::time::sleep(tokio::time::Duration::from_millis(10)).await;

        let delivery_time = (Utc::now() - start_time).num_milliseconds();

        Ok(DeliveryResult {
            event_id: event.event_id(),
            delivery_method: DeliveryMethod::Network(channel.name.clone()),
            recipients: recipients.iter().map(|r| r.id.clone()).collect(),
            success: true,
            delivery_time_ms: delivery_time,
            error: None,
            timestamp: Utc::now(),
        })
    }

    /// Deliver event directly to recipient
    async fn deliver_direct(
        &self,
        contact: String,
        event: &IntelligenceEvent,
        recipients: &[Recipient],
    ) -> Result<DeliveryResult> {
        let start_time = Utc::now();

        // Simulate direct delivery (webhook, email, etc.)
        // In production, this would make actual HTTP/SMTP calls
        tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;

        let delivery_time = (Utc::now() - start_time).num_milliseconds();

        Ok(DeliveryResult {
            event_id: event.event_id(),
            delivery_method: DeliveryMethod::Direct(contact),
            recipients: recipients.iter().map(|r| r.id.clone()).collect(),
            success: true,
            delivery_time_ms: delivery_time,
            error: None,
            timestamp: Utc::now(),
        })
    }

    /// Record distribution metrics
    async fn record_distribution_metrics(&self, results: &[DeliveryResult]) {
        let total = results.len();
        let successful = results.iter().filter(|r| r.success).count();
        let average_time = if total > 0 {
            results.iter().map(|r| r.delivery_time_ms).sum::<i64>() / total as i64
        } else {
            0
        };

        info!(
            "Distribution complete: {}/{} successful, avg time: {}ms",
            successful, total, average_time
        );
    }

    /// Load default routing rules
    fn load_default_routing_rules() -> Vec<RoutingRule> {
        vec![
            RoutingRule {
                name: "Critical Threats".to_string(),
                condition: RoutingCondition::SeverityLevel(vec![Severity::Critical]),
                recipient_ids: vec!["security-lead".to_string(), "incident-response".to_string()],
                priority: DistributionPriority::Immediate,
            },
            RoutingRule {
                name: "Malware Alerts".to_string(),
                condition: RoutingCondition::EventType(vec!["malware".to_string()]),
                recipient_ids: vec!["malware-team".to_string(), "security-ops".to_string()],
                priority: DistributionPriority::High,
            },
            RoutingRule {
                name: "Data Protection".to_string(),
                condition: RoutingCondition::EventType(vec!["data_leak".to_string()]),
                recipient_ids: vec!["data-protection-officer".to_string(), "legal-team".to_string()],
                priority: DistributionPriority::High,
            },
        ]
    }
}

/// Network channel for event distribution
struct NetworkChannel {
    name: String,
    config: DistributedNetworkConfig,
    active: bool,
}

impl NetworkChannel {
    async fn new(config: DistributedNetworkConfig) -> Result<Self> {
        Ok(Self {
            name: config.name.clone(),
            config,
            active: true,
        })
    }
}

/// Routing rule for automatic event distribution
#[derive(Debug, Clone)]
struct RoutingRule {
    name: String,
    condition: RoutingCondition,
    recipient_ids: Vec<String>,
    priority: DistributionPriority,
}

impl RoutingRule {
    fn matches(&self, event: &IntelligenceEvent) -> bool {
        match &self.condition {
            RoutingCondition::SeverityLevel(severities) => {
                if let Some(severity) = event.severity() {
                    severities.contains(&severity)
                } else {
                    false
                }
            }
            RoutingCondition::EventType(types) => {
                let event_type = match event {
                    IntelligenceEvent::ThreatDetected(_) => "threat",
                    IntelligenceEvent::MalwareDiscovered(_) => "malware",
                    IntelligenceEvent::DataLeakDetected(_) => "data_leak",
                    IntelligenceEvent::AnomalyDetected(_) => "anomaly",
                    IntelligenceEvent::VulnerabilityDiscovered(_) => "vulnerability",
                    IntelligenceEvent::AnalysisCompleted(_) => "analysis_completed",
                    IntelligenceEvent::ImmediateAlert(_) => "alert",
                };
                types.iter().any(|t| t == event_type)
            }
            RoutingCondition::Custom(_) => true, // Custom conditions not implemented
        }
    }
}

#[derive(Debug, Clone)]
enum RoutingCondition {
    SeverityLevel(Vec<Severity>),
    EventType(Vec<String>),
    Custom(serde_json::Value),
}

/// Delivery method for events
#[derive(Debug, Clone, Hash, Eq, PartialEq)]
enum DeliveryMethod {
    Network(String),
    Direct(String),
}

/// Result of event delivery
#[derive(Debug, Clone)]
pub struct DeliveryResult {
    pub event_id: uuid::Uuid,
    pub delivery_method: DeliveryMethod,
    pub recipients: Vec<String>,
    pub success: bool,
    pub delivery_time_ms: i64,
    pub error: Option<String>,
    pub timestamp: DateTime<Utc>,
}

/// Rate limiter for recipient protection
struct RateLimiter {
    max_events: usize,
    window_seconds: u64,
    events: Vec<DateTime<Utc>>,
}

impl RateLimiter {
    fn new(max_events: usize, window_seconds: u64) -> Self {
        Self {
            max_events,
            window_seconds,
            events: Vec::new(),
        }
    }

    fn check_and_update(&mut self) -> bool {
        let now = Utc::now();
        let window_start = now - chrono::Duration::seconds(self.window_seconds as i64);

        // Remove old events
        self.events.retain(|&event_time| event_time > window_start);

        // Check if we can add another event
        if self.events.len() < self.max_events {
            self.events.push(now);
            true
        } else {
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::events::{AlertEvent, AlertLevel};

    #[tokio::test]
    async fn test_recipient_registration() {
        let manager = DistributionManager::new(vec![]).await.unwrap();

        let recipient = Recipient {
            id: "test-001".to_string(),
            name: "Test Recipient".to_string(),
            recipient_type: RecipientType::Individual,
            contact_method: ContactMethod::Email("test@example.com".to_string()),
            filter_preferences: vec!["critical".to_string()],
            encryption_key: None,
        };

        manager.register_recipient(recipient.clone()).await.unwrap();

        let recipients = manager.recipients.read().await;
        assert_eq!(recipients.len(), 1);
        assert!(recipients.contains_key("test-001"));
    }

    #[test]
    fn test_routing_rule_matching() {
        let rule = RoutingRule {
            name: "Critical Alerts".to_string(),
            condition: RoutingCondition::SeverityLevel(vec![Severity::Critical]),
            recipient_ids: vec!["team-1".to_string()],
            priority: DistributionPriority::Immediate,
        };

        let alert = IntelligenceEvent::ImmediateAlert(AlertEvent {
            event_id: uuid::Uuid::new_v4(),
            timestamp: Utc::now(),
            job_id: uuid::Uuid::new_v4(),
            alert_level: AlertLevel::Critical,
            title: "Test".to_string(),
            message: "Test".to_string(),
            action_required: "Test".to_string(),
            deadline: None,
            contacts: vec![],
            escalation_path: vec![],
            metadata: serde_json::json!({}),
        });

        // Alert events don't have severity, so this should not match
        assert!(!rule.matches(&alert));
    }

    #[test]
    fn test_rate_limiter() {
        let mut limiter = RateLimiter::new(5, 60);

        // Should allow first 5 events
        for _ in 0..5 {
            assert!(limiter.check_and_update());
        }

        // 6th event should be blocked
        assert!(!limiter.check_and_update());
    }

    #[test]
    fn test_delivery_method_grouping() {
        let recipients = vec![
            Recipient {
                id: "1".to_string(),
                name: "R1".to_string(),
                recipient_type: RecipientType::Individual,
                contact_method: ContactMethod::PulsarTopic("security-alerts".to_string()),
                filter_preferences: vec![],
                encryption_key: None,
            },
            Recipient {
                id: "2".to_string(),
                name: "R2".to_string(),
                recipient_type: RecipientType::Team,
                contact_method: ContactMethod::Webhook("https://example.com/hook".to_string()),
                filter_preferences: vec![],
                encryption_key: None,
            },
        ];

        let manager = DistributionManager {
            networks: HashMap::new(),
            recipients: Arc::new(RwLock::new(HashMap::new())),
            routing_rules: vec![],
            rate_limiters: Arc::new(RwLock::new(HashMap::new())),
        };

        let groups = manager.group_by_delivery_method(&recipients);
        assert_eq!(groups.len(), 2);
    }
}