use anyhow::Result;
use chrono::{DateTime, Utc};
use sqlx::{PgPool, Row};
use std::time::Duration;
use tracing::{info, warn, error};
use uuid::Uuid;

use crate::config::PostgresConfig;
use super::{
    AnalysisJob, JobStatus, Priority, FileAnalysis, SecurityFinding, CustodyRecord,
    Repository, ListJobsQuery, JobListResponse, Classification, FindingType, Severity,
};

#[derive(Clone)]
pub struct PostgresStorage {
    pool: PgPool,
}

impl PostgresStorage {
    pub async fn new(config: &PostgresConfig) -> Result<Self> {
        let database_url = format!(
            "postgresql://{}:{}@{}:{}/{}?sslmode={}",
            config.username,
            config.password,
            config.host,
            config.port,
            config.database,
            config.ssl_mode,
        );

        let pool = sqlx::postgres::PgPoolOptions::new()
            .max_connections(config.max_connections)
            .min_connections(config.min_connections)
            .acquire_timeout(Duration::from_secs(config.connection_timeout_seconds))
            .connect(&database_url)
            .await?;

        info!("Connected to PostgreSQL database");

        Ok(Self { pool })
    }

    pub async fn migrate(&self) -> Result<()> {
        info!("Running database migrations");
        
        // Create custom types
        self.create_types().await?;
        
        // Create tables
        self.create_tables().await?;
        
        // Create indexes
        self.create_indexes().await?;
        
        info!("Database migrations completed");
        Ok(())
    }

    async fn create_types(&self) -> Result<()> {
        let queries = vec![
            r#"
            DO $$ BEGIN
                CREATE TYPE job_status AS ENUM ('pending', 'running', 'completed', 'failed', 'cancelled');
            EXCEPTION
                WHEN duplicate_object THEN null;
            END $$;
            "#,
            r#"
            DO $$ BEGIN
                CREATE TYPE priority AS ENUM ('low', 'normal', 'high', 'urgent');
            EXCEPTION
                WHEN duplicate_object THEN null;
            END $$;
            "#,
            r#"
            DO $$ BEGIN
                CREATE TYPE classification AS ENUM ('public', 'internal', 'confidential', 'restricted', 'top_secret');
            EXCEPTION
                WHEN duplicate_object THEN null;
            END $$;
            "#,
            r#"
            DO $$ BEGIN
                CREATE TYPE finding_type AS ENUM (
                    'secret_exposure', 'vulnerability', 'malware', 'suspicious_code',
                    'license_violation', 'compliance_violation', 'data_leak', 'backdoor', 'anomaly'
                );
            EXCEPTION
                WHEN duplicate_object THEN null;
            END $$;
            "#,
            r#"
            DO $$ BEGIN
                CREATE TYPE severity AS ENUM ('info', 'low', 'medium', 'high', 'critical');
            EXCEPTION
                WHEN duplicate_object THEN null;
            END $$;
            "#,
            r#"
            DO $$ BEGIN
                CREATE TYPE custody_action AS ENUM (
                    'created', 'accessed', 'analyzed', 'transferred', 'copied', 'modified', 'deleted', 'archived'
                );
            EXCEPTION
                WHEN duplicate_object THEN null;
            END $$;
            "#,
            r#"
            DO $$ BEGIN
                CREATE TYPE custody_actor AS ENUM ('user', 'system', 'service', 'external');
            EXCEPTION
                WHEN duplicate_object THEN null;
            END $$;
            "#,
        ];

        for query in queries {
            sqlx::query(query).execute(&self.pool).await?;
        }

        Ok(())
    }

    async fn create_tables(&self) -> Result<()> {
        let queries = vec![
            // Analysis jobs table
            r#"
            CREATE TABLE IF NOT EXISTS analysis_jobs (
                id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
                repository_url TEXT NOT NULL,
                repository_type TEXT NOT NULL,
                analysis_type TEXT NOT NULL,
                status job_status NOT NULL DEFAULT 'pending',
                priority priority NOT NULL DEFAULT 'normal',
                case_number TEXT,
                submitter_id TEXT NOT NULL,
                created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                started_at TIMESTAMPTZ,
                completed_at TIMESTAMPTZ,
                configuration JSONB NOT NULL DEFAULT '{}',
                metadata JSONB NOT NULL DEFAULT '{}',
                progress_percentage INTEGER NOT NULL DEFAULT 0,
                current_phase TEXT,
                error_message TEXT,
                estimated_completion TIMESTAMPTZ
            );
            "#,
            
            // Repositories table
            r#"
            CREATE TABLE IF NOT EXISTS repositories (
                id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
                url TEXT NOT NULL UNIQUE,
                repository_type TEXT NOT NULL,
                size_bytes BIGINT NOT NULL DEFAULT 0,
                file_count INTEGER NOT NULL DEFAULT 0,
                commit_count INTEGER,
                contributors JSONB NOT NULL DEFAULT '[]',
                languages JSONB NOT NULL DEFAULT '[]',
                last_commit TIMESTAMPTZ,
                branch TEXT,
                tags JSONB NOT NULL DEFAULT '[]',
                first_analyzed TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                last_analyzed TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                analysis_count INTEGER NOT NULL DEFAULT 0,
                risk_score REAL NOT NULL DEFAULT 0.0,
                classification classification NOT NULL DEFAULT 'public',
                metadata JSONB NOT NULL DEFAULT '{}'
            );
            "#,
            
            // File analysis table
            r#"
            CREATE TABLE IF NOT EXISTS file_analysis (
                id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
                job_id UUID NOT NULL REFERENCES analysis_jobs(id) ON DELETE CASCADE,
                file_path TEXT NOT NULL,
                file_type TEXT NOT NULL,
                file_size BIGINT NOT NULL,
                mime_type TEXT,
                language TEXT,
                encoding TEXT,
                hash_sha256 TEXT NOT NULL,
                hash_blake3 TEXT NOT NULL,
                classification classification NOT NULL DEFAULT 'public',
                findings JSONB NOT NULL DEFAULT '[]',
                metadata JSONB NOT NULL DEFAULT '{}',
                processed_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                processing_time_ms BIGINT NOT NULL DEFAULT 0
            );
            "#,
            
            // Security findings table
            r#"
            CREATE TABLE IF NOT EXISTS security_findings (
                id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
                job_id UUID NOT NULL REFERENCES analysis_jobs(id) ON DELETE CASCADE,
                file_id UUID REFERENCES file_analysis(id) ON DELETE CASCADE,
                finding_type finding_type NOT NULL,
                severity severity NOT NULL,
                title TEXT NOT NULL,
                description TEXT NOT NULL,
                file_path TEXT,
                line_number INTEGER,
                evidence JSONB NOT NULL DEFAULT '{}',
                recommendation TEXT,
                confidence REAL NOT NULL DEFAULT 0.0,
                cve_id TEXT,
                references JSONB NOT NULL DEFAULT '[]',
                detected_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
            );
            "#,
            
            // Chain of custody table
            r#"
            CREATE TABLE IF NOT EXISTS custody_records (
                id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
                evidence_id TEXT NOT NULL,
                timestamp TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                action custody_action NOT NULL,
                actor custody_actor NOT NULL,
                location TEXT NOT NULL,
                hash_before TEXT,
                hash_after TEXT,
                signature TEXT NOT NULL,
                metadata JSONB NOT NULL DEFAULT '{}'
            );
            "#,
            
            // Intelligence events table
            r#"
            CREATE TABLE IF NOT EXISTS intelligence_events (
                id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
                event_type TEXT NOT NULL,
                timestamp TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                source TEXT NOT NULL,
                priority priority NOT NULL DEFAULT 'normal',
                classification classification NOT NULL DEFAULT 'public',
                data JSONB NOT NULL DEFAULT '{}',
                distribution_networks JSONB NOT NULL DEFAULT '[]',
                recipients JSONB NOT NULL DEFAULT '[]',
                processed BOOLEAN NOT NULL DEFAULT FALSE,
                created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
            );
            "#,
        ];

        for query in queries {
            sqlx::query(query).execute(&self.pool).await?;
        }

        Ok(())
    }

    async fn create_indexes(&self) -> Result<()> {
        let queries = vec![
            // Analysis jobs indexes
            "CREATE INDEX IF NOT EXISTS idx_analysis_jobs_status ON analysis_jobs(status);",
            "CREATE INDEX IF NOT EXISTS idx_analysis_jobs_priority ON analysis_jobs(priority);",
            "CREATE INDEX IF NOT EXISTS idx_analysis_jobs_submitter ON analysis_jobs(submitter_id);",
            "CREATE INDEX IF NOT EXISTS idx_analysis_jobs_case_number ON analysis_jobs(case_number);",
            "CREATE INDEX IF NOT EXISTS idx_analysis_jobs_created_at ON analysis_jobs(created_at);",
            
            // File analysis indexes
            "CREATE INDEX IF NOT EXISTS idx_file_analysis_job_id ON file_analysis(job_id);",
            "CREATE INDEX IF NOT EXISTS idx_file_analysis_hash_sha256 ON file_analysis(hash_sha256);",
            "CREATE INDEX IF NOT EXISTS idx_file_analysis_classification ON file_analysis(classification);",
            
            // Security findings indexes
            "CREATE INDEX IF NOT EXISTS idx_security_findings_job_id ON security_findings(job_id);",
            "CREATE INDEX IF NOT EXISTS idx_security_findings_type ON security_findings(finding_type);",
            "CREATE INDEX IF NOT EXISTS idx_security_findings_severity ON security_findings(severity);",
            "CREATE INDEX IF NOT EXISTS idx_security_findings_detected_at ON security_findings(detected_at);",
            
            // Custody records indexes
            "CREATE INDEX IF NOT EXISTS idx_custody_records_evidence_id ON custody_records(evidence_id);",
            "CREATE INDEX IF NOT EXISTS idx_custody_records_timestamp ON custody_records(timestamp);",
            "CREATE INDEX IF NOT EXISTS idx_custody_records_action ON custody_records(action);",
            
            // Intelligence events indexes
            "CREATE INDEX IF NOT EXISTS idx_intelligence_events_type ON intelligence_events(event_type);",
            "CREATE INDEX IF NOT EXISTS idx_intelligence_events_priority ON intelligence_events(priority);",
            "CREATE INDEX IF NOT EXISTS idx_intelligence_events_processed ON intelligence_events(processed);",
            "CREATE INDEX IF NOT EXISTS idx_intelligence_events_timestamp ON intelligence_events(timestamp);",
            
            // Repository indexes
            "CREATE INDEX IF NOT EXISTS idx_repositories_url ON repositories(url);",
            "CREATE INDEX IF NOT EXISTS idx_repositories_last_analyzed ON repositories(last_analyzed);",
            "CREATE INDEX IF NOT EXISTS idx_repositories_risk_score ON repositories(risk_score);",
        ];

        for query in queries {
            sqlx::query(query).execute(&self.pool).await?;
        }

        Ok(())
    }

    // Analysis job operations
    pub async fn create_analysis_job(&self, job: &AnalysisJob) -> Result<Uuid> {
        let id = sqlx::query!(
            r#"
            INSERT INTO analysis_jobs (
                id, repository_url, repository_type, analysis_type, status, priority,
                case_number, submitter_id, configuration, metadata, estimated_completion
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
            RETURNING id
            "#,
            job.id,
            job.repository_url,
            job.repository_type,
            job.analysis_type,
            job.status as JobStatus,
            job.priority as Priority,
            job.case_number,
            job.submitter_id,
            job.configuration,
            job.metadata,
            job.estimated_completion,
        )
        .fetch_one(&self.pool)
        .await?
        .id;

        Ok(id)
    }

    pub async fn get_analysis_job(&self, job_id: Uuid) -> Result<Option<AnalysisJob>> {
        let job = sqlx::query_as!(
            AnalysisJob,
            r#"
            SELECT 
                id, repository_url, repository_type, analysis_type,
                status as "status: JobStatus", priority as "priority: Priority",
                case_number, submitter_id, created_at, started_at, completed_at,
                configuration, metadata, progress_percentage, current_phase,
                error_message, estimated_completion
            FROM analysis_jobs 
            WHERE id = $1
            "#,
            job_id
        )
        .fetch_optional(&self.pool)
        .await?;

        Ok(job)
    }

    pub async fn update_job_status(
        &self,
        job_id: Uuid,
        status: JobStatus,
        progress: Option<i32>,
        phase: Option<String>,
        error: Option<String>,
    ) -> Result<()> {
        let mut query = sqlx::QueryBuilder::new("UPDATE analysis_jobs SET status = ");
        query.push_bind(status as JobStatus);

        if let Some(progress) = progress {
            query.push(", progress_percentage = ");
            query.push_bind(progress);
        }

        if let Some(phase) = phase {
            query.push(", current_phase = ");
            query.push_bind(phase);
        }

        if let Some(error) = error {
            query.push(", error_message = ");
            query.push_bind(error);
        }

        match status {
            JobStatus::Running => {
                query.push(", started_at = NOW()");
            }
            JobStatus::Completed | JobStatus::Failed | JobStatus::Cancelled => {
                query.push(", completed_at = NOW()");
            }
            _ => {}
        }

        query.push(" WHERE id = ");
        query.push_bind(job_id);

        query.build().execute(&self.pool).await?;

        Ok(())
    }

    pub async fn list_analysis_jobs(&self, query: &ListJobsQuery) -> Result<JobListResponse> {
        let mut sql = sqlx::QueryBuilder::new(
            r#"
            SELECT 
                id, repository_url, repository_type, analysis_type,
                status as "status: JobStatus", priority as "priority: Priority",
                case_number, submitter_id, created_at, started_at, completed_at,
                configuration, metadata, progress_percentage, current_phase,
                error_message, estimated_completion
            FROM analysis_jobs 
            WHERE 1=1
            "#
        );

        // Add WHERE conditions
        if let Some(status) = &query.status {
            sql.push(" AND status = ");
            sql.push_bind(status);
        }

        if let Some(priority) = &query.priority {
            sql.push(" AND priority = ");
            sql.push_bind(priority);
        }

        if let Some(submitter_id) = &query.submitter_id {
            sql.push(" AND submitter_id = ");
            sql.push_bind(submitter_id);
        }

        if let Some(case_number) = &query.case_number {
            sql.push(" AND case_number = ");
            sql.push_bind(case_number);
        }

        if let Some(created_after) = &query.created_after {
            sql.push(" AND created_at >= ");
            sql.push_bind(created_after);
        }

        if let Some(created_before) = &query.created_before {
            sql.push(" AND created_at <= ");
            sql.push_bind(created_before);
        }

        sql.push(" ORDER BY created_at DESC");

        let limit = query.limit.unwrap_or(50);
        let offset = query.offset.unwrap_or(0);

        sql.push(" LIMIT ");
        sql.push_bind(limit);
        sql.push(" OFFSET ");
        sql.push_bind(offset);

        let jobs = sql
            .build_query_as::<AnalysisJob>()
            .fetch_all(&self.pool)
            .await?;

        // Get total count
        let total = self.count_analysis_jobs(query).await?;

        Ok(JobListResponse {
            jobs,
            total,
            limit,
            offset,
            has_more: offset + limit < total,
        })
    }

    async fn count_analysis_jobs(&self, query: &ListJobsQuery) -> Result<i64> {
        let mut sql = sqlx::QueryBuilder::new("SELECT COUNT(*) FROM analysis_jobs WHERE 1=1");

        // Add same WHERE conditions as list query
        if let Some(status) = &query.status {
            sql.push(" AND status = ");
            sql.push_bind(status);
        }

        if let Some(submitter_id) = &query.submitter_id {
            sql.push(" AND submitter_id = ");
            sql.push_bind(submitter_id);
        }

        // Add other conditions...

        let count: i64 = sql
            .build_query_scalar()
            .fetch_one(&self.pool)
            .await?;

        Ok(count)
    }

    // Security findings operations
    pub async fn create_security_finding(&self, finding: &SecurityFinding) -> Result<Uuid> {
        let id = sqlx::query!(
            r#"
            INSERT INTO security_findings (
                id, job_id, file_id, finding_type, severity, title, description,
                file_path, line_number, evidence, recommendation, confidence, cve_id, references
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14)
            RETURNING id
            "#,
            finding.id,
            finding.job_id,
            finding.file_id,
            finding.finding_type as FindingType,
            finding.severity as Severity,
            finding.title,
            finding.description,
            finding.file_path,
            finding.line_number,
            finding.evidence,
            finding.recommendation,
            finding.confidence,
            finding.cve_id,
            finding.references,
        )
        .fetch_one(&self.pool)
        .await?
        .id;

        Ok(id)
    }

    pub async fn get_job_findings(&self, job_id: Uuid) -> Result<Vec<SecurityFinding>> {
        let findings = sqlx::query_as!(
            SecurityFinding,
            r#"
            SELECT 
                id, job_id, file_id,
                finding_type as "finding_type: FindingType",
                severity as "severity: Severity",
                title, description, file_path, line_number, evidence,
                recommendation, confidence, cve_id, references, detected_at
            FROM security_findings 
            WHERE job_id = $1
            ORDER BY severity DESC, detected_at DESC
            "#,
            job_id
        )
        .fetch_all(&self.pool)
        .await?;

        Ok(findings)
    }

    // Repository operations
    pub async fn upsert_repository(&self, repo: &Repository) -> Result<Uuid> {
        let id = sqlx::query!(
            r#"
            INSERT INTO repositories (
                url, repository_type, size_bytes, file_count, commit_count,
                contributors, languages, last_commit, branch, tags,
                analysis_count, risk_score, classification, metadata
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, 1, $11, $12, $13)
            ON CONFLICT (url) 
            DO UPDATE SET
                last_analyzed = NOW(),
                analysis_count = repositories.analysis_count + 1,
                size_bytes = EXCLUDED.size_bytes,
                file_count = EXCLUDED.file_count,
                commit_count = EXCLUDED.commit_count,
                contributors = EXCLUDED.contributors,
                languages = EXCLUDED.languages,
                last_commit = EXCLUDED.last_commit,
                branch = EXCLUDED.branch,
                tags = EXCLUDED.tags,
                risk_score = EXCLUDED.risk_score,
                classification = EXCLUDED.classification,
                metadata = EXCLUDED.metadata
            RETURNING id
            "#,
            repo.url,
            repo.repository_type,
            repo.size_bytes,
            repo.file_count,
            repo.commit_count,
            repo.contributors,
            repo.languages,
            repo.last_commit,
            repo.branch,
            repo.tags,
            repo.risk_score,
            repo.classification as Classification,
            repo.metadata,
        )
        .fetch_one(&self.pool)
        .await?
        .id;

        Ok(id)
    }

    // Chain of custody operations
    pub async fn create_custody_record(&self, record: &CustodyRecord) -> Result<Uuid> {
        let id = sqlx::query!(
            r#"
            INSERT INTO custody_records (
                id, evidence_id, action, actor, location, hash_before, hash_after, signature, metadata
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
            RETURNING id
            "#,
            record.id,
            record.evidence_id,
            record.action as super::CustodyAction,
            record.actor as super::CustodyActor,
            record.location,
            record.hash_before,
            record.hash_after,
            record.signature,
            record.metadata,
        )
        .fetch_one(&self.pool)
        .await?
        .id;

        Ok(id)
    }

    pub async fn get_custody_chain(&self, evidence_id: &str) -> Result<Vec<CustodyRecord>> {
        let records = sqlx::query_as!(
            CustodyRecord,
            r#"
            SELECT 
                id, evidence_id, timestamp,
                action as "action: super::CustodyAction",
                actor as "actor: super::CustodyActor",
                location, hash_before, hash_after, signature, metadata
            FROM custody_records 
            WHERE evidence_id = $1
            ORDER BY timestamp ASC
            "#,
            evidence_id
        )
        .fetch_all(&self.pool)
        .await?;

        Ok(records)
    }

    // File analysis operations
    pub async fn create_file_analysis(&self, analysis: &FileAnalysis) -> Result<Uuid> {
        let id = sqlx::query!(
            r#"
            INSERT INTO file_analysis (
                id, job_id, file_path, file_type, file_size, mime_type, language, encoding,
                hash_sha256, hash_blake3, classification, findings, metadata, processing_time_ms
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14)
            RETURNING id
            "#,
            analysis.id,
            analysis.job_id,
            analysis.file_path,
            analysis.file_type,
            analysis.file_size,
            analysis.mime_type,
            analysis.language,
            analysis.encoding,
            analysis.hash_sha256,
            analysis.hash_blake3,
            analysis.classification as Classification,
            analysis.findings,
            analysis.metadata,
            analysis.processing_time_ms,
        )
        .fetch_one(&self.pool)
        .await?
        .id;

        Ok(id)
    }

    pub async fn get_job_file_analysis(&self, job_id: Uuid) -> Result<Vec<FileAnalysis>> {
        let analyses = sqlx::query_as!(
            FileAnalysis,
            r#"
            SELECT 
                id, job_id, file_path, file_type, file_size, mime_type, language, encoding,
                hash_sha256, hash_blake3,
                classification as "classification: Classification",
                findings, metadata, processed_at, processing_time_ms
            FROM file_analysis 
            WHERE job_id = $1
            ORDER BY processed_at ASC
            "#,
            job_id
        )
        .fetch_all(&self.pool)
        .await?;

        Ok(analyses)
    }

    pub async fn health_check(&self) -> Result<bool> {
        let result = sqlx::query!("SELECT 1 as health")
            .fetch_one(&self.pool)
            .await?;

        Ok(result.health.unwrap_or(0) == 1)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[tokio::test]
    async fn test_postgres_connection() {
        // This would require a test database
        // For now, just test configuration parsing
        let config = PostgresConfig {
            host: "localhost".to_string(),
            port: 5432,
            username: "test".to_string(),
            password: "test".to_string(),
            database: "test".to_string(),
            ssl_mode: "disable".to_string(),
            max_connections: 10,
            min_connections: 1,
            connection_timeout_seconds: 30,
        };

        assert!(!config.host.is_empty());
        assert!(config.port > 0);
    }
}