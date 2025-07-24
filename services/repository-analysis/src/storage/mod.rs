use anyhow::Result;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use uuid::Uuid;

pub mod postgres;
pub mod object;
pub mod vector;

use postgres::PostgresStorage;
use object::ObjectStorage;
use vector::QdrantStorage;

/// Combined storage interface for the repository analysis service
#[derive(Clone)]
pub struct Storage {
    pub postgres: PostgresStorage,
    pub object: ObjectStorage,
    pub vector: QdrantStorage,
}

impl Storage {
    pub fn new(
        postgres: PostgresStorage,
        object: ObjectStorage,
        vector: QdrantStorage,
    ) -> Self {
        Self {
            postgres,
            object,
            vector,
        }
    }
}

/// Analysis job metadata stored in PostgreSQL
#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct AnalysisJob {
    pub id: Uuid,
    pub repository_url: String,
    pub repository_type: String,
    pub analysis_type: String,
    pub status: JobStatus,
    pub priority: Priority,
    pub case_number: Option<String>,
    pub submitter_id: String,
    pub created_at: DateTime<Utc>,
    pub started_at: Option<DateTime<Utc>>,
    pub completed_at: Option<DateTime<Utc>>,
    pub configuration: serde_json::Value,
    pub metadata: serde_json::Value,
    pub progress_percentage: i32,
    pub current_phase: Option<String>,
    pub error_message: Option<String>,
    pub estimated_completion: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::Type)]
#[sqlx(type_name = "job_status", rename_all = "snake_case")]
pub enum JobStatus {
    Pending,
    Running,
    Completed,
    Failed,
    Cancelled,
}

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::Type)]
#[sqlx(type_name = "priority", rename_all = "snake_case")]
pub enum Priority {
    Low,
    Normal,
    High,
    Urgent,
}

/// File analysis results stored in PostgreSQL
#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct FileAnalysis {
    pub id: Uuid,
    pub job_id: Uuid,
    pub file_path: String,
    pub file_type: String,
    pub file_size: i64,
    pub mime_type: Option<String>,
    pub language: Option<String>,
    pub encoding: Option<String>,
    pub hash_sha256: String,
    pub hash_blake3: String,
    pub classification: Classification,
    pub findings: serde_json::Value,
    pub metadata: serde_json::Value,
    pub processed_at: DateTime<Utc>,
    pub processing_time_ms: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::Type)]
#[sqlx(type_name = "classification", rename_all = "snake_case")]
pub enum Classification {
    Public,
    Internal,
    Confidential,
    Restricted,
    TopSecret,
}

/// Security findings and violations
#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct SecurityFinding {
    pub id: Uuid,
    pub job_id: Uuid,
    pub file_id: Option<Uuid>,
    pub finding_type: FindingType,
    pub severity: Severity,
    pub title: String,
    pub description: String,
    pub file_path: Option<String>,
    pub line_number: Option<i32>,
    pub evidence: serde_json::Value,
    pub recommendation: Option<String>,
    pub confidence: f32,
    pub cve_id: Option<String>,
    pub references: serde_json::Value,
    pub detected_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::Type)]
#[sqlx(type_name = "finding_type", rename_all = "snake_case")]
pub enum FindingType {
    SecretExposure,
    Vulnerability,
    Malware,
    SuspiciousCode,
    LicenseViolation,
    ComplianceViolation,
    DataLeak,
    Backdoor,
    Anomaly,
}

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::Type)]
#[sqlx(type_name = "severity", rename_all = "snake_case")]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

/// Chain of custody records for forensic integrity
#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct CustodyRecord {
    pub id: Uuid,
    pub evidence_id: String,
    pub timestamp: DateTime<Utc>,
    pub action: CustodyAction,
    pub actor: CustodyActor,
    pub location: String,
    pub hash_before: Option<String>,
    pub hash_after: Option<String>,
    pub signature: String,
    pub metadata: serde_json::Value,
}

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::Type)]
#[sqlx(type_name = "custody_action", rename_all = "snake_case")]
pub enum CustodyAction {
    Created,
    Accessed,
    Analyzed,
    Transferred,
    Copied,
    Modified,
    Deleted,
    Archived,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum CustodyActor {
    User(String),
    System,
    Service(String),
    External(String),
}

/// Repository metadata and analysis summary
#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct Repository {
    pub id: Uuid,
    pub url: String,
    pub repository_type: String,
    pub size_bytes: i64,
    pub file_count: i32,
    pub commit_count: Option<i32>,
    pub contributors: serde_json::Value,
    pub languages: serde_json::Value,
    pub last_commit: Option<DateTime<Utc>>,
    pub branch: Option<String>,
    pub tags: serde_json::Value,
    pub first_analyzed: DateTime<Utc>,
    pub last_analyzed: DateTime<Utc>,
    pub analysis_count: i32,
    pub risk_score: f32,
    pub classification: Classification,
    pub metadata: serde_json::Value,
}

/// Analysis pipeline configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnalysisConfig {
    pub include_git_history: bool,
    pub deep_file_analysis: bool,
    pub malware_scanning: bool,
    pub pii_detection: bool,
    pub similarity_analysis: bool,
    pub max_file_size_mb: u64,
    pub timeout_hours: u64,
    pub custom_rules: HashMap<String, serde_json::Value>,
}

impl Default for AnalysisConfig {
    fn default() -> Self {
        Self {
            include_git_history: true,
            deep_file_analysis: true,
            malware_scanning: true,
            pii_detection: true,
            similarity_analysis: true,
            max_file_size_mb: 100,
            timeout_hours: 24,
            custom_rules: HashMap::new(),
        }
    }
}

/// Search query for finding similar content
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SimilarityQuery {
    pub collection_name: Option<String>,
    pub query_text: Option<String>,
    pub query_vector: Option<Vec<f32>>,
    pub file_path: Option<String>,
    pub job_id: Option<Uuid>,
    pub similarity_threshold: f32,
    pub limit: usize,
    pub include_metadata: bool,
}

/// Result of similarity search
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SimilarityResult {
    pub score: f32,
    pub job_id: Uuid,
    pub file_path: String,
    pub content_snippet: String,
    pub classification: Classification,
    pub finding_types: Vec<FindingType>,
    pub metadata: serde_json::Value,
}

/// Distributed intelligence event
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IntelligenceEvent {
    pub id: Uuid,
    pub event_type: String,
    pub timestamp: DateTime<Utc>,
    pub source: String,
    pub priority: Priority,
    pub classification: Classification,
    pub data: serde_json::Value,
    pub distribution_networks: Vec<String>,
    pub recipients: Vec<String>,
}

/// Analysis report summary
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnalysisReport {
    pub job_id: Uuid,
    pub repository_info: Repository,
    pub summary: AnalysisSummary,
    pub findings: Vec<SecurityFinding>,
    pub file_analysis: FileAnalysisSummary,
    pub git_analysis: Option<GitAnalysisSummary>,
    pub similarity_analysis: Option<SimilarityAnalysisSummary>,
    pub compliance_analysis: ComplianceAnalysisSummary,
    pub forensic_metadata: ForensicMetadata,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnalysisSummary {
    pub risk_score: f32,
    pub classification: Classification,
    pub total_findings: i32,
    pub critical_findings: i32,
    pub high_findings: i32,
    pub medium_findings: i32,
    pub low_findings: i32,
    pub pii_instances: i32,
    pub secrets_found: i32,
    pub malware_detected: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileAnalysisSummary {
    pub total_files: i32,
    pub analyzed_files: i32,
    pub skipped_files: i32,
    pub by_type: HashMap<String, i32>,
    pub classification_summary: HashMap<Classification, i32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GitAnalysisSummary {
    pub suspicious_commits: Vec<SuspiciousCommit>,
    pub deleted_files: Vec<DeletedFile>,
    pub contributor_analysis: Vec<ContributorInfo>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SuspiciousCommit {
    pub commit_hash: String,
    pub author: String,
    pub timestamp: DateTime<Utc>,
    pub message: String,
    pub risk_indicators: Vec<String>,
    pub files_changed: i32,
    pub lines_added: i32,
    pub lines_removed: i32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeletedFile {
    pub file_path: String,
    pub deleted_in_commit: String,
    pub recovery_possible: bool,
    pub deletion_reason: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContributorInfo {
    pub name: String,
    pub email: String,
    pub commits: i32,
    pub first_commit: DateTime<Utc>,
    pub last_commit: DateTime<Utc>,
    pub risk_score: f32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SimilarityAnalysisSummary {
    pub potential_duplicates: Vec<DuplicateFile>,
    pub external_matches: Vec<ExternalMatch>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DuplicateFile {
    pub similarity_score: f32,
    pub files: Vec<String>,
    pub match_type: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExternalMatch {
    pub file_path: String,
    pub matched_repository: String,
    pub similarity_score: f32,
    pub risk_level: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComplianceAnalysisSummary {
    pub gdpr_compliance: ComplianceStatus,
    pub license_compliance: ComplianceStatus,
    pub security_compliance: ComplianceStatus,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComplianceStatus {
    pub status: String,
    pub issues: Vec<String>,
    pub recommendations: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ForensicMetadata {
    pub chain_of_custody_id: String,
    pub evidence_hash: String,
    pub collection_timestamp: DateTime<Utc>,
    pub analyst: String,
    pub integrity_verified: bool,
    pub legal_hold: bool,
}

/// Query parameters for listing analysis jobs
#[derive(Debug, Clone, Default)]
pub struct ListJobsQuery {
    pub status: Option<JobStatus>,
    pub priority: Option<Priority>,
    pub submitter_id: Option<String>,
    pub case_number: Option<String>,
    pub created_after: Option<DateTime<Utc>>,
    pub created_before: Option<DateTime<Utc>>,
    pub limit: Option<i64>,
    pub offset: Option<i64>,
}

/// Paginated response for analysis jobs
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JobListResponse {
    pub jobs: Vec<AnalysisJob>,
    pub total: i64,
    pub limit: i64,
    pub offset: i64,
    pub has_more: bool,
}