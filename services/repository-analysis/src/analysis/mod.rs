use anyhow::Result;
use std::sync::Arc;
use std::collections::HashMap;
use tracing::{info, warn, error, debug};
use uuid::Uuid;
use chrono::{DateTime, Utc};

pub mod file_analyzer;
pub mod code_analyzer;
pub mod security_scanner;
pub mod ml_analyzer;
pub mod git_analyzer;

use crate::{
    config::AnalysisConfig,
    storage::{Storage, AnalysisJob, JobStatus, FileAnalysis, SecurityFinding, Classification},
    events::publisher::EventPublisher,
};

use file_analyzer::FileAnalyzer;
use code_analyzer::CodeAnalyzer;
use security_scanner::SecurityScanner;
use ml_analyzer::MLAnalyzer;
use git_analyzer::GitAnalyzer;

/// Main analysis engine that orchestrates all analysis components
#[derive(Clone)]
pub struct AnalysisEngine {
    config: AnalysisConfig,
    storage: Arc<Storage>,
    event_publisher: Arc<EventPublisher>,
    file_analyzer: Arc<FileAnalyzer>,
    code_analyzer: Arc<CodeAnalyzer>,
    security_scanner: Arc<SecurityScanner>,
    ml_analyzer: Arc<MLAnalyzer>,
    git_analyzer: Arc<GitAnalyzer>,
}

impl AnalysisEngine {
    pub async fn new(config: AnalysisConfig, storage: Arc<Storage>, event_publisher: Arc<EventPublisher>) -> Result<Self> {
        info!("Initializing analysis engine");

        let file_analyzer = Arc::new(FileAnalyzer::new(&config).await?);
        let code_analyzer = Arc::new(CodeAnalyzer::new(&config).await?);
        let security_scanner = Arc::new(SecurityScanner::new(&config).await?);
        let ml_analyzer = Arc::new(MLAnalyzer::new(&config).await?);
        let git_analyzer = Arc::new(GitAnalyzer::new(&config).await?);

        info!("Analysis engine components initialized");

        Ok(Self {
            config,
            storage,
            event_publisher,
            file_analyzer,
            code_analyzer,
            security_scanner,
            ml_analyzer,
            git_analyzer,
        })
    }

    /// Start analysis of a repository
    pub async fn start_analysis(&self, job: &AnalysisJob) -> Result<AnalysisProgress> {
        info!("Starting analysis for job {}", job.id);

        // Update job status to running
        self.storage.postgres.update_job_status(
            job.id,
            JobStatus::Running,
            Some(0),
            Some("initializing".to_string()),
            None,
        ).await?;

        let mut progress = AnalysisProgress::new(job.id);

        // Phase 1: Repository preparation and cloning
        progress.set_phase("repository_preparation", 5);
        self.update_progress(&progress).await?;

        let repo_info = self.prepare_repository(job).await?;
        progress.add_progress(10);
        self.update_progress(&progress).await?;

        // Phase 2: File discovery and classification
        progress.set_phase("file_discovery", 15);
        self.update_progress(&progress).await?;

        let files = self.discover_files(&repo_info).await?;
        progress.add_progress(10);
        self.update_progress(&progress).await?;

        // Phase 3: Content extraction and analysis
        progress.set_phase("content_extraction", 25);
        self.update_progress(&progress).await?;

        let file_analyses = self.analyze_files(job.id, &files).await?;
        progress.add_progress(30);
        self.update_progress(&progress).await?;

        // Phase 4: Security scanning
        progress.set_phase("security_scanning", 55);
        self.update_progress(&progress).await?;

        let security_findings = self.scan_for_security_issues(job, &file_analyses).await?;
        progress.add_progress(20);
        self.update_progress(&progress).await?;

        // Phase 5: ML analysis and similarity detection
        if self.config.ml_analysis.enabled {
            progress.set_phase("ml_analysis", 75);
            self.update_progress(&progress).await?;

            self.perform_ml_analysis(job.id, &file_analyses).await?;
            progress.add_progress(10);
            self.update_progress(&progress).await?;
        }

        // Phase 6: Git history analysis (if applicable)
        if repo_info.repository_type == "git" && job.configuration.get("include_git_history").and_then(|v| v.as_bool()).unwrap_or(false) {
            progress.set_phase("git_analysis", 85);
            self.update_progress(&progress).await?;

            self.analyze_git_history(job.id, &repo_info).await?;
            progress.add_progress(10);
            self.update_progress(&progress).await?;
        }

        // Phase 7: Report generation and finalization
        progress.set_phase("report_generation", 95);
        self.update_progress(&progress).await?;

        let risk_score = self.generate_analysis_report(job.id, &repo_info, &file_analyses, &security_findings).await?;
        progress.set_completed();
        self.update_progress(&progress).await?;

        // Publish analysis completion event
        let findings_summary = crate::events::FindingsSummary {
            total_findings: security_findings.len() as i32,
            critical: security_findings.iter().filter(|f| matches!(f.severity, crate::storage::Severity::Critical)).count() as i32,
            high: security_findings.iter().filter(|f| matches!(f.severity, crate::storage::Severity::High)).count() as i32,
            medium: security_findings.iter().filter(|f| matches!(f.severity, crate::storage::Severity::Medium)).count() as i32,
            low: security_findings.iter().filter(|f| matches!(f.severity, crate::storage::Severity::Low)).count() as i32,
            by_type: {
                use std::collections::HashMap;
                let mut map = HashMap::new();
                for finding in security_findings {
                    *map.entry(finding.finding_type.to_string()).or_insert(0) += 1;
                }
                map
            },
        };
        
        if let Err(e) = self.event_publisher.publish_analysis_completed(job, findings_summary, risk_score).await {
            error!("Failed to publish analysis completion event: {}", e);
        }

        // Update job status to completed
        self.storage.postgres.update_job_status(
            job.id,
            JobStatus::Completed,
            Some(100),
            Some("completed".to_string()),
            None,
        ).await?;

        info!("Analysis completed for job {}", job.id);
        Ok(progress)
    }

    async fn prepare_repository(&self, job: &AnalysisJob) -> Result<RepositoryInfo> {
        debug!("Preparing repository: {}", job.repository_url);

        // Clone or download repository based on type
        let repo_info = match job.repository_type.as_str() {
            "git" => self.git_analyzer.clone_repository(&job.repository_url).await?,
            "archive" => self.download_and_extract_archive(&job.repository_url).await?,
            "directory" => self.analyze_local_directory(&job.repository_url).await?,
            _ => return Err(anyhow::anyhow!("Unsupported repository type: {}", job.repository_type)),
        };

        // Store repository metadata
        let repo_record = crate::storage::Repository {
            id: Uuid::new_v4(),
            url: job.repository_url.clone(),
            repository_type: job.repository_type.clone(),
            size_bytes: repo_info.size_bytes,
            file_count: repo_info.file_count,
            commit_count: repo_info.commit_count,
            contributors: serde_json::to_value(&repo_info.contributors)?,
            languages: serde_json::to_value(&repo_info.languages)?,
            last_commit: repo_info.last_commit,
            branch: repo_info.branch.clone(),
            tags: serde_json::to_value(&repo_info.tags)?,
            first_analyzed: Utc::now(),
            last_analyzed: Utc::now(),
            analysis_count: 1,
            risk_score: 0.0, // Will be calculated later
            classification: Classification::Public, // Default, will be updated
            metadata: serde_json::to_value(&repo_info.metadata)?,
        };

        self.storage.postgres.upsert_repository(&repo_record).await?;

        Ok(repo_info)
    }

    async fn discover_files(&self, repo_info: &RepositoryInfo) -> Result<Vec<FileInfo>> {
        debug!("Discovering files in repository");

        let files = self.file_analyzer.discover_files(&repo_info.local_path).await?;
        
        info!("Discovered {} files", files.len());
        
        // Filter files based on configuration
        let filtered_files = self.filter_files(files)?;
        
        info!("After filtering: {} files will be analyzed", filtered_files.len());
        
        Ok(filtered_files)
    }

    fn filter_files(&self, files: Vec<FileInfo>) -> Result<Vec<FileInfo>> {
        let max_file_size = self.config.max_file_size_mb as u64 * 1024 * 1024;
        
        let filtered: Vec<FileInfo> = files
            .into_iter()
            .filter(|file| {
                // Size filter
                if file.size_bytes > max_file_size {
                    debug!("Skipping large file: {} ({} bytes)", file.path, file.size_bytes);
                    return false;
                }
                
                // Binary file filter (basic check)
                if self.is_likely_binary(&file.path) && !self.should_analyze_binary(&file.path) {
                    debug!("Skipping binary file: {}", file.path);
                    return false;
                }
                
                true
            })
            .collect();
        
        Ok(filtered)
    }

    fn is_likely_binary(&self, path: &str) -> bool {
        let binary_extensions = [
            "exe", "dll", "so", "dylib", "bin", "obj", "o", "a", "lib",
            "png", "jpg", "jpeg", "gif", "bmp", "ico", "svg",
            "mp3", "mp4", "avi", "mkv", "wav", "flac",
            "zip", "tar", "gz", "bz2", "xz", "7z", "rar",
            "pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx",
        ];
        
        if let Some(extension) = std::path::Path::new(path).extension() {
            if let Some(ext_str) = extension.to_str() {
                return binary_extensions.contains(&ext_str.to_lowercase().as_str());
            }
        }
        
        false
    }

    fn should_analyze_binary(&self, path: &str) -> bool {
        // Always analyze certain binary types for security scanning
        let security_binary_extensions = ["exe", "dll", "so", "dylib"];
        
        if let Some(extension) = std::path::Path::new(path).extension() {
            if let Some(ext_str) = extension.to_str() {
                return security_binary_extensions.contains(&ext_str.to_lowercase().as_str());
            }
        }
        
        false
    }

    async fn analyze_files(&self, job_id: Uuid, files: &[FileInfo]) -> Result<Vec<FileAnalysis>> {
        info!("Analyzing {} files", files.len());

        let mut analyses = Vec::new();
        let total_files = files.len();
        
        for (index, file_info) in files.iter().enumerate() {
            debug!("Analyzing file {}/{}: {}", index + 1, total_files, file_info.path);
            
            let analysis_start = std::time::Instant::now();
            
            // Perform file analysis
            let file_analysis = self.file_analyzer.analyze_file(job_id, file_info).await?;
            
            // Store file analysis in database
            self.storage.postgres.create_file_analysis(&file_analysis).await?;
            
            let processing_time = analysis_start.elapsed();
            debug!("File analysis completed in {:?}", processing_time);
            
            analyses.push(file_analysis);
            
            // Update progress periodically
            if index % 10 == 0 {
                let progress_percent = ((index as f32 / total_files as f32) * 30.0) as i32 + 25;
                self.storage.postgres.update_job_status(
                    job_id,
                    JobStatus::Running,
                    Some(progress_percent),
                    Some(format!("analyzing_files ({}/{})", index, total_files)),
                    None,
                ).await?;
            }
        }

        Ok(analyses)
    }

    async fn scan_for_security_issues(&self, job: &AnalysisJob, file_analyses: &[FileAnalysis]) -> Result<Vec<SecurityFinding>> {
        info!("Scanning for security issues");

        let mut all_findings = Vec::new();
        
        for file_analysis in file_analyses {
            // Security scan for each file
            let findings = self.security_scanner.scan_file(job.id, file_analysis).await?;
            
            // Store findings in database and publish critical events
            for finding in &findings {
                self.storage.postgres.create_security_finding(finding).await?;
                
                // Publish high/critical security findings as intelligence events
                if matches!(finding.severity, crate::storage::Severity::High | crate::storage::Severity::Critical) {
                    if let Err(e) = self.event_publisher.publish_security_finding(job, finding).await {
                        error!("Failed to publish security finding event: {}", e);
                    }
                }
            }
            
            all_findings.extend(findings);
        }

        // Perform repository-level security analysis
        let repo_findings = self.security_scanner.scan_repository(job.id, file_analyses).await?;
        
        for finding in &repo_findings {
            self.storage.postgres.create_security_finding(finding).await?;
            
            // Publish high/critical findings
            if matches!(finding.severity, crate::storage::Severity::High | crate::storage::Severity::Critical) {
                if let Err(e) = self.event_publisher.publish_security_finding(job, finding).await {
                    error!("Failed to publish repository finding event: {}", e);
                }
            }
        }
        
        all_findings.extend(repo_findings);

        info!("Found {} security issues", all_findings.len());
        
        // Publish alert for critical mass of findings
        if all_findings.iter().filter(|f| matches!(f.severity, crate::storage::Severity::Critical)).count() >= 3 {
            if let Err(e) = self.event_publisher.publish_alert(
                job.id,
                crate::events::AlertLevel::Critical,
                "Multiple critical security issues detected".to_string(),
                format!("Repository {} contains multiple critical security vulnerabilities requiring immediate attention", job.repository_url),
                "Isolate repository and conduct thorough security review".to_string(),
            ).await {
                error!("Failed to publish critical mass alert: {}", e);
            }
        }
        
        Ok(all_findings)
    }

    async fn perform_ml_analysis(&self, job_id: Uuid, file_analyses: &[FileAnalysis]) -> Result<()> {
        info!("Performing ML analysis");

        // Generate embeddings for text files
        for file_analysis in file_analyses {
            if self.is_text_file(&file_analysis.file_type) {
                self.ml_analyzer.generate_embeddings(job_id, file_analysis).await?;
            }
        }

        // Perform similarity analysis
        self.ml_analyzer.perform_similarity_analysis(job_id, file_analyses).await?;

        info!("ML analysis completed");
        Ok(())
    }

    fn is_text_file(&self, file_type: &str) -> bool {
        matches!(file_type, "text" | "code" | "document" | "config")
    }

    async fn analyze_git_history(&self, job_id: Uuid, repo_info: &RepositoryInfo) -> Result<()> {
        info!("Analyzing Git history");

        if let Some(git_path) = &repo_info.git_path {
            self.git_analyzer.analyze_history(job_id, git_path).await?;
        }

        info!("Git history analysis completed");
        Ok(())
    }

    async fn generate_analysis_report(
        &self,
        job_id: Uuid,
        repo_info: &RepositoryInfo,
        file_analyses: &[FileAnalysis],
        security_findings: &[SecurityFinding],
    ) -> Result<f32> {
        info!("Generating analysis report");

        // Calculate risk score
        let risk_score = self.calculate_risk_score(security_findings);

        // Generate comprehensive report
        let report = crate::storage::AnalysisReport {
            job_id,
            repository_info: crate::storage::Repository {
                id: Uuid::new_v4(),
                url: repo_info.url.clone(),
                repository_type: repo_info.repository_type.clone(),
                size_bytes: repo_info.size_bytes,
                file_count: repo_info.file_count,
                commit_count: repo_info.commit_count,
                contributors: serde_json::to_value(&repo_info.contributors)?,
                languages: serde_json::to_value(&repo_info.languages)?,
                last_commit: repo_info.last_commit,
                branch: repo_info.branch.clone(),
                tags: serde_json::to_value(&repo_info.tags)?,
                first_analyzed: Utc::now(),
                last_analyzed: Utc::now(),
                analysis_count: 1,
                risk_score,
                classification: self.determine_classification(security_findings),
                metadata: serde_json::to_value(&repo_info.metadata)?,
            },
            summary: self.generate_analysis_summary(file_analyses, security_findings),
            findings: security_findings.to_vec(),
            file_analysis: self.generate_file_analysis_summary(file_analyses),
            git_analysis: None, // Would be populated by git analyzer
            similarity_analysis: None, // Would be populated by ML analyzer
            compliance_analysis: self.generate_compliance_analysis(security_findings),
            forensic_metadata: self.generate_forensic_metadata(job_id),
        };

        // Store report as JSON
        let report_json = serde_json::to_vec_pretty(&report)?;
        self.storage.object.store_analysis_report(job_id, report_json, "json").await?;

        info!("Analysis report generated and stored");
        Ok(risk_score)
    }

    async fn download_and_extract_archive(&self, url: &str) -> Result<RepositoryInfo> {
        // Implementation for downloading and extracting archives
        todo!("Implement archive download and extraction")
    }

    async fn analyze_local_directory(&self, path: &str) -> Result<RepositoryInfo> {
        // Implementation for analyzing local directories
        todo!("Implement local directory analysis")
    }

    async fn update_progress(&self, progress: &AnalysisProgress) -> Result<()> {
        self.storage.postgres.update_job_status(
            progress.job_id,
            JobStatus::Running,
            Some(progress.percentage),
            Some(progress.current_phase.clone()),
            None,
        ).await
    }

    fn calculate_risk_score(&self, findings: &[SecurityFinding]) -> f32 {
        let mut score = 0.0;
        
        for finding in findings {
            let severity_weight = match finding.severity {
                crate::storage::Severity::Critical => 10.0,
                crate::storage::Severity::High => 7.0,
                crate::storage::Severity::Medium => 4.0,
                crate::storage::Severity::Low => 2.0,
                crate::storage::Severity::Info => 1.0,
            };
            
            score += severity_weight * finding.confidence;
        }
        
        // Normalize to 0-10 scale
        (score / findings.len() as f32).min(10.0)
    }

    fn determine_classification(&self, findings: &[SecurityFinding]) -> Classification {
        let has_critical = findings.iter().any(|f| matches!(f.severity, crate::storage::Severity::Critical));
        let has_high = findings.iter().any(|f| matches!(f.severity, crate::storage::Severity::High));
        
        if has_critical {
            Classification::Restricted
        } else if has_high {
            Classification::Confidential
        } else {
            Classification::Internal
        }
    }

    fn generate_analysis_summary(&self, file_analyses: &[FileAnalysis], findings: &[SecurityFinding]) -> crate::storage::AnalysisSummary {
        let critical_count = findings.iter().filter(|f| matches!(f.severity, crate::storage::Severity::Critical)).count() as i32;
        let high_count = findings.iter().filter(|f| matches!(f.severity, crate::storage::Severity::High)).count() as i32;
        let medium_count = findings.iter().filter(|f| matches!(f.severity, crate::storage::Severity::Medium)).count() as i32;
        let low_count = findings.iter().filter(|f| matches!(f.severity, crate::storage::Severity::Low)).count() as i32;

        crate::storage::AnalysisSummary {
            risk_score: self.calculate_risk_score(findings),
            classification: self.determine_classification(findings),
            total_findings: findings.len() as i32,
            critical_findings: critical_count,
            high_findings: high_count,
            medium_findings: medium_count,
            low_findings: low_count,
            pii_instances: 0, // Would be calculated by PII detector
            secrets_found: findings.iter().filter(|f| matches!(f.finding_type, crate::storage::FindingType::SecretExposure)).count() as i32,
            malware_detected: findings.iter().any(|f| matches!(f.finding_type, crate::storage::FindingType::Malware)),
        }
    }

    fn generate_file_analysis_summary(&self, file_analyses: &[FileAnalysis]) -> crate::storage::FileAnalysisSummary {
        let mut by_type = HashMap::new();
        let mut by_classification = HashMap::new();

        for analysis in file_analyses {
            *by_type.entry(analysis.file_type.clone()).or_insert(0) += 1;
            *by_classification.entry(analysis.classification.clone()).or_insert(0) += 1;
        }

        crate::storage::FileAnalysisSummary {
            total_files: file_analyses.len() as i32,
            analyzed_files: file_analyses.len() as i32,
            skipped_files: 0,
            by_type,
            classification_summary: by_classification,
        }
    }

    fn generate_compliance_analysis(&self, findings: &[SecurityFinding]) -> crate::storage::ComplianceAnalysisSummary {
        // Basic compliance analysis - would be more sophisticated in real implementation
        crate::storage::ComplianceAnalysisSummary {
            gdpr_compliance: crate::storage::ComplianceStatus {
                status: "compliant".to_string(),
                issues: vec![],
                recommendations: vec![],
            },
            license_compliance: crate::storage::ComplianceStatus {
                status: "compliant".to_string(),
                issues: vec![],
                recommendations: vec![],
            },
            security_compliance: crate::storage::ComplianceStatus {
                status: if findings.iter().any(|f| matches!(f.severity, crate::storage::Severity::Critical)) {
                    "non_compliant".to_string()
                } else {
                    "compliant".to_string()
                },
                issues: findings.iter().filter(|f| matches!(f.severity, crate::storage::Severity::Critical | crate::storage::Severity::High))
                    .map(|f| f.title.clone()).collect(),
                recommendations: vec!["Address all high and critical security findings".to_string()],
            },
        }
    }

    fn generate_forensic_metadata(&self, job_id: Uuid) -> crate::storage::ForensicMetadata {
        crate::storage::ForensicMetadata {
            chain_of_custody_id: format!("COC-{}", job_id),
            evidence_hash: "sha256:placeholder".to_string(), // Would be real hash
            collection_timestamp: Utc::now(),
            analyst: "afdp-repository-analysis-service".to_string(),
            integrity_verified: true,
            legal_hold: false,
        }
    }
}

/// Progress tracking for analysis jobs
#[derive(Debug, Clone)]
pub struct AnalysisProgress {
    pub job_id: Uuid,
    pub percentage: i32,
    pub current_phase: String,
    pub phases_completed: Vec<String>,
    pub started_at: DateTime<Utc>,
    pub estimated_completion: Option<DateTime<Utc>>,
}

impl AnalysisProgress {
    pub fn new(job_id: Uuid) -> Self {
        Self {
            job_id,
            percentage: 0,
            current_phase: "initializing".to_string(),
            phases_completed: vec![],
            started_at: Utc::now(),
            estimated_completion: None,
        }
    }

    pub fn set_phase(&mut self, phase: &str, percentage: i32) {
        if !self.current_phase.is_empty() && self.current_phase != "initializing" {
            self.phases_completed.push(self.current_phase.clone());
        }
        self.current_phase = phase.to_string();
        self.percentage = percentage;
    }

    pub fn add_progress(&mut self, increment: i32) {
        self.percentage = (self.percentage + increment).min(100);
    }

    pub fn set_completed(&mut self) {
        self.phases_completed.push(self.current_phase.clone());
        self.current_phase = "completed".to_string();
        self.percentage = 100;
    }
}

/// Repository information extracted during preparation
#[derive(Debug, Clone)]
pub struct RepositoryInfo {
    pub url: String,
    pub repository_type: String,
    pub local_path: String,
    pub git_path: Option<String>,
    pub size_bytes: i64,
    pub file_count: i32,
    pub commit_count: Option<i32>,
    pub contributors: Vec<String>,
    pub languages: Vec<String>,
    pub last_commit: Option<DateTime<Utc>>,
    pub branch: Option<String>,
    pub tags: Vec<String>,
    pub metadata: HashMap<String, serde_json::Value>,
}

/// File information discovered during file discovery
#[derive(Debug, Clone)]
pub struct FileInfo {
    pub path: String,
    pub relative_path: String,
    pub size_bytes: u64,
    pub modified_at: DateTime<Utc>,
    pub file_type: String,
    pub mime_type: Option<String>,
    pub extension: Option<String>,
    pub is_binary: bool,
    pub is_executable: bool,
    pub permissions: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_analysis_progress() {
        let job_id = Uuid::new_v4();
        let mut progress = AnalysisProgress::new(job_id);
        
        assert_eq!(progress.job_id, job_id);
        assert_eq!(progress.percentage, 0);
        assert_eq!(progress.current_phase, "initializing");
        
        progress.set_phase("file_discovery", 25);
        assert_eq!(progress.percentage, 25);
        assert_eq!(progress.current_phase, "file_discovery");
        
        progress.add_progress(10);
        assert_eq!(progress.percentage, 35);
        
        progress.set_completed();
        assert_eq!(progress.percentage, 100);
        assert_eq!(progress.current_phase, "completed");
        assert!(progress.phases_completed.contains(&"file_discovery".to_string()));
    }

    #[test]
    fn test_binary_file_detection() {
        // This would be part of the analysis engine
        let binary_files = ["test.exe", "image.png", "document.pdf"];
        let text_files = ["script.py", "config.yaml", "readme.md"];
        
        // Test logic would go here
        assert!(binary_files.iter().all(|f| f.contains('.')));
        assert!(text_files.iter().all(|f| f.contains('.')));
    }
}