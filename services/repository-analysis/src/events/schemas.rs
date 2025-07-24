use serde::{Deserialize, Serialize};
use serde_json::Value as JsonValue;
use std::collections::HashMap;

/// Schema definitions for event validation and documentation
pub mod schemas {
    use super::*;

    /// Schema registry for all event types
    pub struct SchemaRegistry {
        schemas: HashMap<String, EventSchema>,
    }

    impl SchemaRegistry {
        pub fn new() -> Self {
            let mut registry = Self {
                schemas: HashMap::new(),
            };
            registry.register_default_schemas();
            registry
        }

        fn register_default_schemas(&mut self) {
            // ThreatEvent schema
            self.schemas.insert(
                "ThreatEvent".to_string(),
                EventSchema {
                    name: "ThreatEvent".to_string(),
                    version: "1.0.0".to_string(),
                    description: "Security threat detection event".to_string(),
                    fields: vec![
                        SchemaField {
                            name: "event_id".to_string(),
                            field_type: FieldType::Uuid,
                            required: true,
                            description: "Unique event identifier".to_string(),
                        },
                        SchemaField {
                            name: "timestamp".to_string(),
                            field_type: FieldType::DateTime,
                            required: true,
                            description: "Event timestamp".to_string(),
                        },
                        SchemaField {
                            name: "job_id".to_string(),
                            field_type: FieldType::Uuid,
                            required: true,
                            description: "Analysis job identifier".to_string(),
                        },
                        SchemaField {
                            name: "repository_url".to_string(),
                            field_type: FieldType::String,
                            required: true,
                            description: "Repository URL".to_string(),
                        },
                        SchemaField {
                            name: "threat_type".to_string(),
                            field_type: FieldType::String,
                            required: true,
                            description: "Type of threat detected".to_string(),
                        },
                        SchemaField {
                            name: "severity".to_string(),
                            field_type: FieldType::Enum(vec![
                                "Info".to_string(),
                                "Low".to_string(),
                                "Medium".to_string(),
                                "High".to_string(),
                                "Critical".to_string(),
                            ]),
                            required: true,
                            description: "Threat severity level".to_string(),
                        },
                        SchemaField {
                            name: "risk_score".to_string(),
                            field_type: FieldType::Float,
                            required: true,
                            description: "Risk score (0-10)".to_string(),
                        },
                        SchemaField {
                            name: "confidence".to_string(),
                            field_type: FieldType::Float,
                            required: true,
                            description: "Detection confidence (0-1)".to_string(),
                        },
                    ],
                    examples: vec![
                        serde_json::json!({
                            "event_id": "550e8400-e29b-41d4-a716-446655440000",
                            "timestamp": "2023-10-15T14:30:00Z",
                            "job_id": "660e8400-e29b-41d4-a716-446655440001",
                            "repository_url": "https://github.com/example/repo",
                            "threat_type": "Backdoor",
                            "severity": "Critical",
                            "classification": "Restricted",
                            "title": "Backdoor detected in authentication module",
                            "description": "Suspicious code pattern detected that bypasses authentication",
                            "evidence": {
                                "file": "auth.js",
                                "line": 42,
                                "code": "if (user === 'admin' || DEBUG_MODE) { return true; }"
                            },
                            "affected_files": ["auth.js", "login.js"],
                            "recommendations": ["Remove backdoor code", "Review authentication flow"],
                            "risk_score": 9.5,
                            "confidence": 0.95
                        }),
                    ],
                },
            );

            // MalwareEvent schema
            self.schemas.insert(
                "MalwareEvent".to_string(),
                EventSchema {
                    name: "MalwareEvent".to_string(),
                    version: "1.0.0".to_string(),
                    description: "Malware discovery event".to_string(),
                    fields: vec![
                        SchemaField {
                            name: "malware_type".to_string(),
                            field_type: FieldType::String,
                            required: true,
                            description: "Type of malware detected".to_string(),
                        },
                        SchemaField {
                            name: "file_hash".to_string(),
                            field_type: FieldType::String,
                            required: true,
                            description: "SHA256 hash of malicious file".to_string(),
                        },
                        SchemaField {
                            name: "signature_matches".to_string(),
                            field_type: FieldType::Array(Box::new(FieldType::String)),
                            required: true,
                            description: "Matched malware signatures".to_string(),
                        },
                        SchemaField {
                            name: "quarantine_status".to_string(),
                            field_type: FieldType::Enum(vec![
                                "Quarantined".to_string(),
                                "PendingQuarantine".to_string(),
                                "NotQuarantined".to_string(),
                                "Failed".to_string(),
                            ]),
                            required: true,
                            description: "Current quarantine status".to_string(),
                        },
                    ],
                    examples: vec![
                        serde_json::json!({
                            "event_id": "770e8400-e29b-41d4-a716-446655440002",
                            "timestamp": "2023-10-15T14:45:00Z",
                            "job_id": "660e8400-e29b-41d4-a716-446655440001",
                            "repository_url": "https://github.com/example/repo",
                            "malware_type": "Trojan",
                            "file_path": "bin/helper.exe",
                            "file_hash": "a665a45920422f9d417e4867efdc4fb8a04a1f3fff1fa07e998e86f7f7a27ae3",
                            "signature_matches": ["TROJAN.Generic", "Win32.Suspicious"],
                            "behavior_indicators": ["Process injection", "Registry modification"],
                            "severity": "Critical",
                            "quarantine_status": "Quarantined"
                        }),
                    ],
                },
            );

            // DataLeakEvent schema
            self.schemas.insert(
                "DataLeakEvent".to_string(),
                EventSchema {
                    name: "DataLeakEvent".to_string(),
                    version: "1.0.0".to_string(),
                    description: "Data leak detection event".to_string(),
                    fields: vec![
                        SchemaField {
                            name: "leak_type".to_string(),
                            field_type: FieldType::Enum(vec![
                                "Credentials".to_string(),
                                "PersonalData".to_string(),
                                "FinancialData".to_string(),
                                "HealthData".to_string(),
                                "IntellectualProperty".to_string(),
                                "Other".to_string(),
                            ]),
                            required: true,
                            description: "Type of data leaked".to_string(),
                        },
                        SchemaField {
                            name: "exposed_data_types".to_string(),
                            field_type: FieldType::Array(Box::new(FieldType::String)),
                            required: true,
                            description: "Specific types of exposed data".to_string(),
                        },
                        SchemaField {
                            name: "exposure_scope".to_string(),
                            field_type: FieldType::Enum(vec![
                                "Public".to_string(),
                                "Internal".to_string(),
                                "Limited".to_string(),
                                "Unknown".to_string(),
                            ]),
                            required: true,
                            description: "Scope of data exposure".to_string(),
                        },
                        SchemaField {
                            name: "remediation_required".to_string(),
                            field_type: FieldType::Boolean,
                            required: true,
                            description: "Whether immediate remediation is required".to_string(),
                        },
                    ],
                    examples: vec![
                        serde_json::json!({
                            "event_id": "880e8400-e29b-41d4-a716-446655440003",
                            "timestamp": "2023-10-15T15:00:00Z",
                            "job_id": "660e8400-e29b-41d4-a716-446655440001",
                            "repository_url": "https://github.com/example/repo",
                            "leak_type": "Credentials",
                            "severity": "High",
                            "exposed_data_types": ["AWS Access Keys", "Database Passwords"],
                            "affected_files": [".env", "config/database.yml"],
                            "exposure_scope": "Public",
                            "remediation_required": true
                        }),
                    ],
                },
            );

            // AlertEvent schema
            self.schemas.insert(
                "AlertEvent".to_string(),
                EventSchema {
                    name: "AlertEvent".to_string(),
                    version: "1.0.0".to_string(),
                    description: "Immediate alert requiring action".to_string(),
                    fields: vec![
                        SchemaField {
                            name: "alert_level".to_string(),
                            field_type: FieldType::Enum(vec![
                                "Emergency".to_string(),
                                "Critical".to_string(),
                                "Warning".to_string(),
                                "Info".to_string(),
                            ]),
                            required: true,
                            description: "Alert urgency level".to_string(),
                        },
                        SchemaField {
                            name: "action_required".to_string(),
                            field_type: FieldType::String,
                            required: true,
                            description: "Required action to address the alert".to_string(),
                        },
                        SchemaField {
                            name: "deadline".to_string(),
                            field_type: FieldType::DateTime,
                            required: false,
                            description: "Action deadline".to_string(),
                        },
                        SchemaField {
                            name: "escalation_path".to_string(),
                            field_type: FieldType::Array(Box::new(FieldType::String)),
                            required: true,
                            description: "Escalation hierarchy".to_string(),
                        },
                    ],
                    examples: vec![
                        serde_json::json!({
                            "event_id": "990e8400-e29b-41d4-a716-446655440004",
                            "timestamp": "2023-10-15T15:15:00Z",
                            "job_id": "660e8400-e29b-41d4-a716-446655440001",
                            "alert_level": "Emergency",
                            "title": "Active exploitation detected",
                            "message": "Repository contains code being actively exploited in the wild",
                            "action_required": "Immediately remove repository from public access",
                            "deadline": "2023-10-15T15:30:00Z",
                            "contacts": ["security@example.com", "+1-555-0123"],
                            "escalation_path": ["Security Team", "Security Lead", "CISO", "CEO"]
                        }),
                    ],
                },
            );
        }

        pub fn get_schema(&self, event_type: &str) -> Option<&EventSchema> {
            self.schemas.get(event_type)
        }

        pub fn validate_event(&self, event_type: &str, event_data: &JsonValue) -> ValidationResult {
            if let Some(schema) = self.get_schema(event_type) {
                schema.validate(event_data)
            } else {
                ValidationResult {
                    valid: false,
                    errors: vec![format!("Unknown event type: {}", event_type)],
                }
            }
        }

        pub fn generate_documentation(&self) -> String {
            let mut doc = String::from("# Repository Analysis Service Event Schemas\n\n");
            
            for (event_type, schema) in &self.schemas {
                doc.push_str(&format!("## {}\n\n", event_type));
                doc.push_str(&format!("**Version:** {}\n\n", schema.version));
                doc.push_str(&format!("**Description:** {}\n\n", schema.description));
                
                doc.push_str("### Fields\n\n");
                doc.push_str("| Field | Type | Required | Description |\n");
                doc.push_str("|-------|------|----------|-------------|\n");
                
                for field in &schema.fields {
                    doc.push_str(&format!(
                        "| {} | {} | {} | {} |\n",
                        field.name,
                        field.field_type.to_string(),
                        if field.required { "Yes" } else { "No" },
                        field.description
                    ));
                }
                
                if !schema.examples.is_empty() {
                    doc.push_str("\n### Example\n\n```json\n");
                    doc.push_str(&serde_json::to_string_pretty(&schema.examples[0]).unwrap());
                    doc.push_str("\n```\n\n");
                }
            }
            
            doc
        }
    }

    #[derive(Debug, Clone)]
    pub struct EventSchema {
        pub name: String,
        pub version: String,
        pub description: String,
        pub fields: Vec<SchemaField>,
        pub examples: Vec<JsonValue>,
    }

    impl EventSchema {
        pub fn validate(&self, data: &JsonValue) -> ValidationResult {
            let mut errors = Vec::new();
            
            if let Some(obj) = data.as_object() {
                // Check required fields
                for field in &self.fields {
                    if field.required && !obj.contains_key(&field.name) {
                        errors.push(format!("Missing required field: {}", field.name));
                    } else if let Some(value) = obj.get(&field.name) {
                        // Validate field type
                        if !field.field_type.validate(value) {
                            errors.push(format!(
                                "Invalid type for field '{}': expected {}, got {}",
                                field.name,
                                field.field_type.to_string(),
                                value_type_name(value)
                            ));
                        }
                    }
                }
            } else {
                errors.push("Event data must be an object".to_string());
            }
            
            ValidationResult {
                valid: errors.is_empty(),
                errors,
            }
        }
    }

    #[derive(Debug, Clone)]
    pub struct SchemaField {
        pub name: String,
        pub field_type: FieldType,
        pub required: bool,
        pub description: String,
    }

    #[derive(Debug, Clone)]
    pub enum FieldType {
        String,
        Integer,
        Float,
        Boolean,
        DateTime,
        Uuid,
        Object,
        Array(Box<FieldType>),
        Enum(Vec<String>),
        Any,
    }

    impl FieldType {
        pub fn validate(&self, value: &JsonValue) -> bool {
            match self {
                FieldType::String => value.is_string(),
                FieldType::Integer => value.is_i64() || value.is_u64(),
                FieldType::Float => value.is_f64() || value.is_i64(),
                FieldType::Boolean => value.is_boolean(),
                FieldType::DateTime => {
                    if let Some(s) = value.as_str() {
                        chrono::DateTime::parse_from_rfc3339(s).is_ok()
                    } else {
                        false
                    }
                }
                FieldType::Uuid => {
                    if let Some(s) = value.as_str() {
                        uuid::Uuid::parse_str(s).is_ok()
                    } else {
                        false
                    }
                }
                FieldType::Object => value.is_object(),
                FieldType::Array(inner_type) => {
                    if let Some(arr) = value.as_array() {
                        arr.iter().all(|v| inner_type.validate(v))
                    } else {
                        false
                    }
                }
                FieldType::Enum(values) => {
                    if let Some(s) = value.as_str() {
                        values.contains(&s.to_string())
                    } else {
                        false
                    }
                }
                FieldType::Any => true,
            }
        }
    }

    impl std::fmt::Display for FieldType {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            match self {
                FieldType::String => write!(f, "string"),
                FieldType::Integer => write!(f, "integer"),
                FieldType::Float => write!(f, "float"),
                FieldType::Boolean => write!(f, "boolean"),
                FieldType::DateTime => write!(f, "datetime"),
                FieldType::Uuid => write!(f, "uuid"),
                FieldType::Object => write!(f, "object"),
                FieldType::Array(inner) => write!(f, "array<{}>", inner),
                FieldType::Enum(values) => write!(f, "enum({})", values.join(", ")),
                FieldType::Any => write!(f, "any"),
            }
        }
    }

    #[derive(Debug, Clone)]
    pub struct ValidationResult {
        pub valid: bool,
        pub errors: Vec<String>,
    }

    fn value_type_name(value: &JsonValue) -> &'static str {
        match value {
            JsonValue::Null => "null",
            JsonValue::Bool(_) => "boolean",
            JsonValue::Number(_) => "number",
            JsonValue::String(_) => "string",
            JsonValue::Array(_) => "array",
            JsonValue::Object(_) => "object",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::schemas::*;

    #[test]
    fn test_schema_validation() {
        let registry = SchemaRegistry::new();
        
        // Valid ThreatEvent
        let valid_event = serde_json::json!({
            "event_id": "550e8400-e29b-41d4-a716-446655440000",
            "timestamp": "2023-10-15T14:30:00Z",
            "job_id": "660e8400-e29b-41d4-a716-446655440001",
            "repository_url": "https://github.com/example/repo",
            "threat_type": "Backdoor",
            "severity": "Critical",
            "risk_score": 9.5,
            "confidence": 0.95
        });
        
        let result = registry.validate_event("ThreatEvent", &valid_event);
        assert!(result.valid);
        assert!(result.errors.is_empty());
        
        // Invalid event - missing required field
        let invalid_event = serde_json::json!({
            "event_id": "550e8400-e29b-41d4-a716-446655440000",
            "timestamp": "2023-10-15T14:30:00Z"
        });
        
        let result = registry.validate_event("ThreatEvent", &invalid_event);
        assert!(!result.valid);
        assert!(!result.errors.is_empty());
    }

    #[test]
    fn test_field_type_validation() {
        // String
        assert!(FieldType::String.validate(&serde_json::json!("test")));
        assert!(!FieldType::String.validate(&serde_json::json!(123)));
        
        // Integer
        assert!(FieldType::Integer.validate(&serde_json::json!(123)));
        assert!(!FieldType::Integer.validate(&serde_json::json!("123")));
        
        // UUID
        assert!(FieldType::Uuid.validate(&serde_json::json!("550e8400-e29b-41d4-a716-446655440000")));
        assert!(!FieldType::Uuid.validate(&serde_json::json!("not-a-uuid")));
        
        // DateTime
        assert!(FieldType::DateTime.validate(&serde_json::json!("2023-10-15T14:30:00Z")));
        assert!(!FieldType::DateTime.validate(&serde_json::json!("not-a-date")));
        
        // Enum
        let severity_enum = FieldType::Enum(vec!["Low".to_string(), "Medium".to_string(), "High".to_string()]);
        assert!(severity_enum.validate(&serde_json::json!("High")));
        assert!(!severity_enum.validate(&serde_json::json!("VeryHigh")));
        
        // Array
        let string_array = FieldType::Array(Box::new(FieldType::String));
        assert!(string_array.validate(&serde_json::json!(["a", "b", "c"])));
        assert!(!string_array.validate(&serde_json::json!([1, 2, 3])));
    }

    #[test]
    fn test_documentation_generation() {
        let registry = SchemaRegistry::new();
        let doc = registry.generate_documentation();
        
        assert!(doc.contains("# Repository Analysis Service Event Schemas"));
        assert!(doc.contains("ThreatEvent"));
        assert!(doc.contains("MalwareEvent"));
        assert!(doc.contains("DataLeakEvent"));
        assert!(doc.contains("AlertEvent"));
    }
}