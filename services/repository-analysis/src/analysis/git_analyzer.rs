use anyhow::Result;
use std::collections::{HashMap, HashSet};
use std::path::Path;
use std::process::Command;
use tracing::{debug, info, warn, error};
use uuid::Uuid;
use chrono::{DateTime, Utc, TimeZone};
use serde_json::json;
use regex::Regex;

use crate::{
    config::AnalysisConfig,
    storage::{SecurityFinding, FindingType, Severity},
    analysis::{RepositoryInfo, FileInfo},
};

/// Git analyzer component for analyzing repository history, commits, and metadata
pub struct GitAnalyzer {
    config: AnalysisConfig,
    suspicious_patterns: Vec<SuspiciousPattern>,
    risk_indicators: Vec<RiskIndicator>,
}

impl GitAnalyzer {
    pub async fn new(config: &AnalysisConfig) -> Result<Self> {
        let suspicious_patterns = Self::load_suspicious_patterns();
        let risk_indicators = Self::load_risk_indicators();

        info!("Git analyzer initialized with {} patterns", suspicious_patterns.len());

        Ok(Self {
            config: config.clone(),
            suspicious_patterns,
            risk_indicators,
        })
    }

    /// Clone a Git repository and extract metadata
    pub async fn clone_repository(&self, repository_url: &str) -> Result<RepositoryInfo> {
        info!("Cloning repository: {}", repository_url);

        // Create temporary directory for cloning
        let temp_dir = tempfile::tempdir()?;
        let local_path = temp_dir.path().to_string_lossy().to_string();

        // Clone the repository
        let output = Command::new("git")
            .args(&["clone", "--quiet", repository_url, &local_path])
            .output()?;

        if !output.status.success() {
            return Err(anyhow::anyhow!(
                "Failed to clone repository: {}",
                String::from_utf8_lossy(&output.stderr)
            ));
        }

        // Extract repository information
        let repo_info = self.extract_repository_info(&local_path).await?;
        
        info!("Repository cloned successfully: {} commits, {} contributors", 
              repo_info.commit_count.unwrap_or(0), repo_info.contributors.len());

        Ok(repo_info)
    }

    /// Analyze Git history for suspicious patterns and security issues
    pub async fn analyze_history(&self, job_id: Uuid, git_path: &str) -> Result<Vec<SecurityFinding>> {
        info!("Analyzing Git history at: {}", git_path);

        let mut findings = Vec::new();

        // Analyze commit history
        findings.extend(self.analyze_commits(job_id, git_path).await?);

        // Analyze deleted files
        findings.extend(self.analyze_deleted_files(job_id, git_path).await?);

        // Analyze contributor patterns
        findings.extend(self.analyze_contributors(job_id, git_path).await?);

        // Analyze branch and merge patterns
        findings.extend(self.analyze_branches(job_id, git_path).await?);

        // Analyze file modifications
        findings.extend(self.analyze_file_modifications(job_id, git_path).await?);

        info!("Git history analysis completed: {} findings", findings.len());
        Ok(findings)
    }

    async fn extract_repository_info(&self, local_path: &str) -> Result<RepositoryInfo> {
        debug!("Extracting repository information from: {}", local_path);

        // Get basic repository stats
        let commit_count = self.get_commit_count(local_path)?;
        let contributors = self.get_contributors(local_path)?;
        let languages = self.get_languages(local_path)?;
        let last_commit = self.get_last_commit_date(local_path)?;
        let current_branch = self.get_current_branch(local_path)?;
        let tags = self.get_tags(local_path)?;
        let size_bytes = self.calculate_directory_size(local_path)?;
        let file_count = self.count_files(local_path)?;

        // Extract additional metadata
        let mut metadata = HashMap::new();
        metadata.insert("remote_url".to_string(), json!(self.get_remote_url(local_path)?));
        metadata.insert("head_commit".to_string(), json!(self.get_head_commit(local_path)?));
        metadata.insert("repository_age_days".to_string(), json!(self.get_repository_age(local_path)?));

        Ok(RepositoryInfo {
            url: self.get_remote_url(local_path)?,
            repository_type: "git".to_string(),
            local_path: local_path.to_string(),
            git_path: Some(local_path.to_string()),
            size_bytes,
            file_count,
            commit_count: Some(commit_count),
            contributors,
            languages,
            last_commit,
            branch: Some(current_branch),
            tags,
            metadata,
        })
    }

    async fn analyze_commits(&self, job_id: Uuid, git_path: &str) -> Result<Vec<SecurityFinding>> {
        debug!("Analyzing commit history");

        let mut findings = Vec::new();
        let commits = self.get_commit_history(git_path, 1000)?; // Get last 1000 commits

        for commit in &commits {
            // Check commit message for suspicious patterns
            for pattern in &self.suspicious_patterns {
                if let Ok(regex) = Regex::new(&pattern.pattern) {
                    if regex.is_match(&commit.message) {
                        findings.push(SecurityFinding {
                            id: Uuid::new_v4(),
                            job_id,
                            file_id: None,
                            finding_type: FindingType::SuspiciousCode,
                            severity: pattern.severity.clone(),
                            title: format!("Suspicious commit message: {}", pattern.name),
                            description: pattern.description.clone(),
                            file_path: None,
                            line_number: None,
                            evidence: json!({
                                "commit_hash": commit.hash,
                                "commit_message": commit.message,
                                "author": commit.author,
                                "timestamp": commit.timestamp
                            }),
                            recommendation: Some("Review commit for malicious intent".to_string()),
                            confidence: pattern.confidence,
                            cve_id: None,
                            references: json!([]),
                            detected_at: Utc::now(),
                        });
                    }
                }
            }

            // Check for large commits (potential data exfiltration)
            if commit.files_changed > 100 || commit.lines_added > 10000 {
                findings.push(SecurityFinding {
                    id: Uuid::new_v4(),
                    job_id,
                    file_id: None,
                    finding_type: FindingType::Anomaly,
                    severity: Severity::Medium,
                    title: "Unusually large commit detected".to_string(),
                    description: "Commit modifies an unusually large number of files or lines".to_string(),
                    file_path: None,
                    line_number: None,
                    evidence: json!({
                        "commit_hash": commit.hash,
                        "files_changed": commit.files_changed,
                        "lines_added": commit.lines_added,
                        "lines_removed": commit.lines_removed
                    }),
                    recommendation: Some("Review commit for potential data exfiltration or bulk changes".to_string()),
                    confidence: 0.7,
                    cve_id: None,
                    references: json!([]),
                    detected_at: Utc::now(),
                });
            }

            // Check for commits with suspicious timing
            if self.is_suspicious_timing(&commit.timestamp) {
                findings.push(SecurityFinding {
                    id: Uuid::new_v4(),
                    job_id,
                    file_id: None,
                    finding_type: FindingType::Anomaly,
                    severity: Severity::Low,
                    title: "Commit at unusual time".to_string(),
                    description: "Commit was made at an unusual time (outside business hours)".to_string(),
                    file_path: None,
                    line_number: None,
                    evidence: json!({
                        "commit_hash": commit.hash,
                        "timestamp": commit.timestamp,
                        "hour": commit.timestamp.hour()
                    }),
                    recommendation: Some("Verify the legitimacy of off-hours commits".to_string()),
                    confidence: 0.5,
                    cve_id: None,
                    references: json!([]),
                    detected_at: Utc::now(),
                });
            }
        }

        // Analyze commit frequency patterns
        findings.extend(self.analyze_commit_frequency(&commits, job_id)?);

        Ok(findings)
    }

    async fn analyze_deleted_files(&self, job_id: Uuid, git_path: &str) -> Result<Vec<SecurityFinding>> {
        debug!("Analyzing deleted files");

        let mut findings = Vec::new();
        let deleted_files = self.get_deleted_files(git_path)?;

        for deleted_file in &deleted_files {
            // Check if deleted file might have contained sensitive information
            if self.is_potentially_sensitive_file(&deleted_file.file_path) {
                findings.push(SecurityFinding {
                    id: Uuid::new_v4(),
                    job_id,
                    file_id: None,
                    finding_type: FindingType::DataLeak,
                    severity: Severity::Medium,
                    title: "Potentially sensitive file was deleted".to_string(),
                    description: "A file that might have contained sensitive information was deleted from the repository".to_string(),
                    file_path: Some(deleted_file.file_path.clone()),
                    line_number: None,
                    evidence: json!({
                        "deleted_file": deleted_file.file_path,
                        "deletion_commit": deleted_file.deletion_commit,
                        "recoverable": deleted_file.recoverable
                    }),
                    recommendation: Some("Review deleted file content and ensure proper data handling".to_string()),
                    confidence: 0.6,
                    cve_id: None,
                    references: json!([]),
                    detected_at: Utc::now(),
                });
            }

            // Check for mass file deletions
            if let Some(commit_info) = self.get_commit_info(git_path, &deleted_file.deletion_commit)? {
                if commit_info.files_changed > 50 && commit_info.lines_removed > commit_info.lines_added * 3 {
                    findings.push(SecurityFinding {
                        id: Uuid::new_v4(),
                        job_id,
                        file_id: None,
                        finding_type: FindingType::SuspiciousCode,
                        severity: Severity::High,
                        title: "Mass file deletion detected".to_string(),
                        description: "Commit involves deletion of many files".to_string(),
                        file_path: None,
                        line_number: None,
                        evidence: json!({
                            "commit_hash": deleted_file.deletion_commit,
                            "files_changed": commit_info.files_changed,
                            "lines_removed": commit_info.lines_removed
                        }),
                        recommendation: Some("Review mass deletion for potential data destruction".to_string()),
                        confidence: 0.8,
                        cve_id: None,
                        references: json!([]),
                        detected_at: Utc::now(),
                    });
                }
            }
        }

        Ok(findings)
    }

    async fn analyze_contributors(&self, job_id: Uuid, git_path: &str) -> Result<Vec<SecurityFinding>> {
        debug!("Analyzing contributor patterns");

        let mut findings = Vec::new();
        let contributors = self.get_detailed_contributors(git_path)?;

        // Check for suspicious contributor patterns
        for contributor in &contributors {
            // Check for contributors with very few commits but large changes
            if contributor.commits < 5 && contributor.lines_added > 5000 {
                findings.push(SecurityFinding {
                    id: Uuid::new_v4(),
                    job_id,
                    file_id: None,
                    finding_type: FindingType::Anomaly,
                    severity: Severity::Medium,
                    title: "Contributor with high impact, low commit count".to_string(),
                    description: "Contributor has made large changes with very few commits".to_string(),
                    file_path: None,
                    line_number: None,
                    evidence: json!({
                        "contributor": contributor.name,
                        "email": contributor.email,
                        "commits": contributor.commits,
                        "lines_added": contributor.lines_added
                    }),
                    recommendation: Some("Review contributor's changes for potential security issues".to_string()),
                    confidence: 0.6,
                    cve_id: None,
                    references: json!([]),
                    detected_at: Utc::now(),
                });
            }

            // Check for suspicious email patterns
            if self.is_suspicious_email(&contributor.email) {
                findings.push(SecurityFinding {
                    id: Uuid::new_v4(),
                    job_id,
                    file_id: None,
                    finding_type: FindingType::SuspiciousCode,
                    severity: Severity::Low,
                    title: "Suspicious contributor email".to_string(),
                    description: "Contributor uses a suspicious email pattern".to_string(),
                    file_path: None,
                    line_number: None,
                    evidence: json!({
                        "contributor": contributor.name,
                        "email": contributor.email
                    }),
                    recommendation: Some("Verify contributor identity".to_string()),
                    confidence: 0.5,
                    cve_id: None,
                    references: json!([]),
                    detected_at: Utc::now(),
                });
            }
        }

        Ok(findings)
    }

    async fn analyze_branches(&self, job_id: Uuid, git_path: &str) -> Result<Vec<SecurityFinding>> {
        debug!("Analyzing branch patterns");

        let mut findings = Vec::new();
        let branches = self.get_branches(git_path)?;

        // Check for suspicious branch names
        for branch in &branches {
            for pattern in &self.suspicious_patterns {
                if pattern.pattern_type == "branch_name" {
                    if let Ok(regex) = Regex::new(&pattern.pattern) {
                        if regex.is_match(&branch.name) {
                            findings.push(SecurityFinding {
                                id: Uuid::new_v4(),
                                job_id,
                                file_id: None,
                                finding_type: FindingType::SuspiciousCode,
                                severity: Severity::Low,
                                title: "Suspicious branch name".to_string(),
                                description: "Branch has a suspicious name".to_string(),
                                file_path: None,
                                line_number: None,
                                evidence: json!({
                                    "branch_name": branch.name,
                                    "last_commit": branch.last_commit
                                }),
                                recommendation: Some("Review branch purpose and content".to_string()),
                                confidence: 0.5,
                                cve_id: None,
                                references: json!([]),
                                detected_at: Utc::now(),
                            });
                        }
                    }
                }
            }
        }

        Ok(findings)
    }

    async fn analyze_file_modifications(&self, job_id: Uuid, git_path: &str) -> Result<Vec<SecurityFinding>> {
        debug!("Analyzing file modification patterns");

        let mut findings = Vec::new();
        let file_histories = self.get_file_modification_history(git_path)?;

        for file_history in &file_histories {
            // Check for files that are frequently modified
            if file_history.modification_count > 100 {
                findings.push(SecurityFinding {
                    id: Uuid::new_v4(),
                    job_id,
                    file_id: None,
                    finding_type: FindingType::Anomaly,
                    severity: Severity::Low,
                    title: "Frequently modified file".to_string(),
                    description: "File has been modified an unusually high number of times".to_string(),
                    file_path: Some(file_history.file_path.clone()),
                    line_number: None,
                    evidence: json!({
                        "file_path": file_history.file_path,
                        "modification_count": file_history.modification_count,
                        "last_modified": file_history.last_modified
                    }),
                    recommendation: Some("Review file for potential instability or suspicious activity".to_string()),
                    confidence: 0.6,
                    cve_id: None,
                    references: json!([]),
                    detected_at: Utc::now(),
                });
            }

            // Check for binary files with many modifications
            if self.is_binary_file(&file_history.file_path) && file_history.modification_count > 10 {
                findings.push(SecurityFinding {
                    id: Uuid::new_v4(),
                    job_id,
                    file_id: None,
                    finding_type: FindingType::Anomaly,
                    severity: Severity::Medium,
                    title: "Frequently modified binary file".to_string(),
                    description: "Binary file has been modified multiple times".to_string(),
                    file_path: Some(file_history.file_path.clone()),
                    line_number: None,
                    evidence: json!({
                        "file_path": file_history.file_path,
                        "modification_count": file_history.modification_count
                    }),
                    recommendation: Some("Review binary file modifications for potential malware injection".to_string()),
                    confidence: 0.7,
                    cve_id: None,
                    references: json!([]),
                    detected_at: Utc::now(),
                });
            }
        }

        Ok(findings)
    }

    fn analyze_commit_frequency(&self, commits: &[CommitInfo], job_id: Uuid) -> Result<Vec<SecurityFinding>> {
        let mut findings = Vec::new();

        if commits.len() < 10 {
            return Ok(findings); // Not enough data for analysis
        }

        // Group commits by day
        let mut daily_commits: HashMap<String, i32> = HashMap::new();
        for commit in commits {
            let date_key = commit.timestamp.format("%Y-%m-%d").to_string();
            *daily_commits.entry(date_key).or_insert(0) += 1;
        }

        // Find days with unusually high commit activity
        let values: Vec<i32> = daily_commits.values().cloned().collect();
        if let Some((mean, std_dev)) = self.calculate_stats(&values) {
            let threshold = mean + (2.0 * std_dev);

            for (date, count) in daily_commits {
                if count as f64 > threshold && count > 20 {
                    findings.push(SecurityFinding {
                        id: Uuid::new_v4(),
                        job_id,
                        file_id: None,
                        finding_type: FindingType::Anomaly,
                        severity: Severity::Low,
                        title: "Unusual commit frequency".to_string(),
                        description: "Day with unusually high number of commits".to_string(),
                        file_path: None,
                        line_number: None,
                        evidence: json!({
                            "date": date,
                            "commit_count": count,
                            "average": mean,
                            "threshold": threshold
                        }),
                        recommendation: Some("Review high-frequency commit days for potential automation or suspicious activity".to_string()),
                        confidence: 0.6,
                        cve_id: None,
                        references: json!([]),
                        detected_at: Utc::now(),
                    });
                }
            }
        }

        Ok(findings)
    }

    // Git command helpers
    fn get_commit_count(&self, git_path: &str) -> Result<i32> {
        let output = Command::new("git")
            .args(&["rev-list", "--count", "HEAD"])
            .current_dir(git_path)
            .output()?;

        if output.status.success() {
            let count_str = String::from_utf8_lossy(&output.stdout).trim();
            Ok(count_str.parse().unwrap_or(0))
        } else {
            Ok(0)
        }
    }

    fn get_contributors(&self, git_path: &str) -> Result<Vec<String>> {
        let output = Command::new("git")
            .args(&["log", "--format=%an", "--all"])
            .current_dir(git_path)
            .output()?;

        if output.status.success() {
            let contributors: HashSet<String> = String::from_utf8_lossy(&output.stdout)
                .lines()
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .collect();

            Ok(contributors.into_iter().collect())
        } else {
            Ok(vec![])
        }
    }

    fn get_languages(&self, git_path: &str) -> Result<Vec<String>> {
        let mut languages = HashSet::new();
        
        // Simple language detection based on file extensions
        let output = Command::new("find")
            .args(&[git_path, "-name", "*.rs"])
            .output();
        if output.is_ok() && !output.unwrap().stdout.is_empty() {
            languages.insert("Rust".to_string());
        }

        let output = Command::new("find")
            .args(&[git_path, "-name", "*.py"])
            .output();
        if output.is_ok() && !output.unwrap().stdout.is_empty() {
            languages.insert("Python".to_string());
        }

        let output = Command::new("find")
            .args(&[git_path, "-name", "*.js"])
            .output();
        if output.is_ok() && !output.unwrap().stdout.is_empty() {
            languages.insert("JavaScript".to_string());
        }

        Ok(languages.into_iter().collect())
    }

    fn get_last_commit_date(&self, git_path: &str) -> Result<Option<DateTime<Utc>>> {
        let output = Command::new("git")
            .args(&["log", "-1", "--format=%ct"])
            .current_dir(git_path)
            .output()?;

        if output.status.success() {
            let timestamp_str = String::from_utf8_lossy(&output.stdout).trim();
            if let Ok(timestamp) = timestamp_str.parse::<i64>() {
                return Ok(Some(Utc.timestamp_opt(timestamp, 0).single().unwrap_or_else(Utc::now)));
            }
        }

        Ok(None)
    }

    fn get_current_branch(&self, git_path: &str) -> Result<String> {
        let output = Command::new("git")
            .args(&["branch", "--show-current"])
            .current_dir(git_path)
            .output()?;

        if output.status.success() {
            Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
        } else {
            Ok("unknown".to_string())
        }
    }

    fn get_tags(&self, git_path: &str) -> Result<Vec<String>> {
        let output = Command::new("git")
            .args(&["tag", "-l"])
            .current_dir(git_path)
            .output()?;

        if output.status.success() {
            Ok(String::from_utf8_lossy(&output.stdout)
                .lines()
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .collect())
        } else {
            Ok(vec![])
        }
    }

    fn get_remote_url(&self, git_path: &str) -> Result<String> {
        let output = Command::new("git")
            .args(&["config", "--get", "remote.origin.url"])
            .current_dir(git_path)
            .output()?;

        if output.status.success() {
            Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
        } else {
            Ok("unknown".to_string())
        }
    }

    fn get_head_commit(&self, git_path: &str) -> Result<String> {
        let output = Command::new("git")
            .args(&["rev-parse", "HEAD"])
            .current_dir(git_path)
            .output()?;

        if output.status.success() {
            Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
        } else {
            Ok("unknown".to_string())
        }
    }

    fn get_repository_age(&self, git_path: &str) -> Result<i64> {
        let output = Command::new("git")
            .args(&["log", "--reverse", "--format=%ct", "--max-count=1"])
            .current_dir(git_path)
            .output()?;

        if output.status.success() {
            let first_commit_str = String::from_utf8_lossy(&output.stdout).trim();
            if let Ok(first_commit_timestamp) = first_commit_str.parse::<i64>() {
                let now = Utc::now().timestamp();
                let age_seconds = now - first_commit_timestamp;
                return Ok(age_seconds / 86400); // Convert to days
            }
        }

        Ok(0)
    }

    fn get_commit_history(&self, git_path: &str, limit: usize) -> Result<Vec<CommitInfo>> {
        let output = Command::new("git")
            .args(&[
                "log",
                "--format=%H|%an|%ae|%ct|%s|%B",
                &format!("--max-count={}", limit),
                "--numstat"
            ])
            .current_dir(git_path)
            .output()?;

        let mut commits = Vec::new();
        
        if output.status.success() {
            let log_output = String::from_utf8_lossy(&output.stdout);
            
            // Parse commit information (simplified parsing)
            for line in log_output.lines() {
                if line.contains('|') {
                    let parts: Vec<&str> = line.split('|').collect();
                    if parts.len() >= 5 {
                        if let Ok(timestamp) = parts[3].parse::<i64>() {
                            commits.push(CommitInfo {
                                hash: parts[0].to_string(),
                                author: parts[1].to_string(),
                                email: parts[2].to_string(),
                                timestamp: Utc.timestamp_opt(timestamp, 0).single().unwrap_or_else(Utc::now),
                                message: parts[4].to_string(),
                                files_changed: 0, // Would be calculated from numstat
                                lines_added: 0,
                                lines_removed: 0,
                            });
                        }
                    }
                }
            }
        }

        Ok(commits)
    }

    fn get_deleted_files(&self, git_path: &str) -> Result<Vec<DeletedFileInfo>> {
        let output = Command::new("git")
            .args(&["log", "--diff-filter=D", "--summary", "--format=%H"])
            .current_dir(git_path)
            .output()?;

        let mut deleted_files = Vec::new();

        if output.status.success() {
            let log_output = String::from_utf8_lossy(&output.stdout);
            let mut current_commit = String::new();

            for line in log_output.lines() {
                let line = line.trim();
                if line.len() == 40 && line.chars().all(|c| c.is_ascii_hexdigit()) {
                    current_commit = line.to_string();
                } else if line.starts_with("delete mode") {
                    if let Some(file_path) = line.split_whitespace().last() {
                        deleted_files.push(DeletedFileInfo {
                            file_path: file_path.to_string(),
                            deletion_commit: current_commit.clone(),
                            recoverable: true, // Git files are generally recoverable
                        });
                    }
                }
            }
        }

        Ok(deleted_files)
    }

    fn get_commit_info(&self, git_path: &str, commit_hash: &str) -> Result<Option<CommitInfo>> {
        let output = Command::new("git")
            .args(&["show", "--stat", "--format=%H|%an|%ae|%ct|%s", commit_hash])
            .current_dir(git_path)
            .output()?;

        if output.status.success() {
            let output_str = String::from_utf8_lossy(&output.stdout);
            // Parse commit info (simplified)
            // This would need more sophisticated parsing for files_changed, etc.
            Ok(None) // Placeholder
        } else {
            Ok(None)
        }
    }

    fn get_detailed_contributors(&self, git_path: &str) -> Result<Vec<ContributorInfo>> {
        let output = Command::new("git")
            .args(&["shortlog", "-sne", "--all"])
            .current_dir(git_path)
            .output()?;

        let mut contributors = Vec::new();

        if output.status.success() {
            let log_output = String::from_utf8_lossy(&output.stdout);
            
            for line in log_output.lines() {
                let line = line.trim();
                if let Some((count_str, rest)) = line.split_once('\t') {
                    if let Ok(commits) = count_str.trim().parse::<i32>() {
                        // Extract name and email
                        let name_email = rest.trim();
                        let (name, email) = if name_email.contains('<') && name_email.contains('>') {
                            let parts: Vec<&str> = name_email.splitn(2, '<').collect();
                            let name = parts[0].trim();
                            let email = parts.get(1).unwrap_or(&"").replace('>', "");
                            (name.to_string(), email)
                        } else {
                            (name_email.to_string(), "unknown".to_string())
                        };

                        contributors.push(ContributorInfo {
                            name,
                            email,
                            commits,
                            lines_added: 0, // Would need additional git commands to get this
                            lines_removed: 0,
                        });
                    }
                }
            }
        }

        Ok(contributors)
    }

    fn get_branches(&self, git_path: &str) -> Result<Vec<BranchInfo>> {
        let output = Command::new("git")
            .args(&["branch", "-a", "--format=%(refname:short)|%(objectname)"])
            .current_dir(git_path)
            .output()?;

        let mut branches = Vec::new();

        if output.status.success() {
            let output_str = String::from_utf8_lossy(&output.stdout);
            
            for line in output_str.lines() {
                if let Some((name, commit)) = line.split_once('|') {
                    branches.push(BranchInfo {
                        name: name.trim().to_string(),
                        last_commit: commit.trim().to_string(),
                    });
                }
            }
        }

        Ok(branches)
    }

    fn get_file_modification_history(&self, git_path: &str) -> Result<Vec<FileModificationInfo>> {
        let output = Command::new("git")
            .args(&["log", "--name-only", "--format="])
            .current_dir(git_path)
            .output()?;

        let mut file_counts: HashMap<String, i32> = HashMap::new();

        if output.status.success() {
            let output_str = String::from_utf8_lossy(&output.stdout);
            
            for line in output_str.lines() {
                let line = line.trim();
                if !line.is_empty() {
                    *file_counts.entry(line.to_string()).or_insert(0) += 1;
                }
            }
        }

        let mut file_histories = Vec::new();
        for (file_path, count) in file_counts {
            file_histories.push(FileModificationInfo {
                file_path,
                modification_count: count,
                last_modified: Utc::now(), // Would need additional git command to get actual timestamp
            });
        }

        Ok(file_histories)
    }

    // Utility functions
    fn calculate_directory_size(&self, path: &str) -> Result<i64> {
        let output = Command::new("du")
            .args(&["-sb", path])
            .output()?;

        if output.status.success() {
            let output_str = String::from_utf8_lossy(&output.stdout);
            if let Some(size_str) = output_str.split_whitespace().next() {
                return Ok(size_str.parse().unwrap_or(0));
            }
        }

        Ok(0)
    }

    fn count_files(&self, path: &str) -> Result<i32> {
        let output = Command::new("find")
            .args(&[path, "-type", "f"])
            .output()?;

        if output.status.success() {
            let count = String::from_utf8_lossy(&output.stdout).lines().count();
            Ok(count as i32)
        } else {
            Ok(0)
        }
    }

    fn is_suspicious_timing(&self, timestamp: &DateTime<Utc>) -> bool {
        let hour = timestamp.hour();
        // Consider commits outside 6 AM - 10 PM as potentially suspicious
        hour < 6 || hour > 22
    }

    fn is_potentially_sensitive_file(&self, file_path: &str) -> bool {
        let sensitive_patterns = [
            ".env", "config", "secret", "key", "password", "credential",
            ".pem", ".p12", ".pfx", ".keystore", "private"
        ];

        let file_path_lower = file_path.to_lowercase();
        sensitive_patterns.iter().any(|pattern| file_path_lower.contains(pattern))
    }

    fn is_suspicious_email(&self, email: &str) -> bool {
        let suspicious_domains = [
            "10minutemail.com", "tempmail.org", "guerrillamail.com",
            "mailinator.com", "throwaway.email"
        ];

        let suspicious_patterns = [
            "noreply", "no-reply", "admin@", "root@", "test@"
        ];

        let email_lower = email.to_lowercase();
        
        // Check suspicious domains
        if suspicious_domains.iter().any(|domain| email_lower.contains(domain)) {
            return true;
        }

        // Check suspicious patterns
        suspicious_patterns.iter().any(|pattern| email_lower.contains(pattern))
    }

    fn is_binary_file(&self, file_path: &str) -> bool {
        let binary_extensions = [
            ".exe", ".dll", ".so", ".dylib", ".bin", ".obj", ".o", ".a", ".lib",
            ".png", ".jpg", ".jpeg", ".gif", ".bmp", ".ico",
            ".zip", ".tar", ".gz", ".bz2", ".xz", ".7z", ".rar"
        ];

        let file_path_lower = file_path.to_lowercase();
        binary_extensions.iter().any(|ext| file_path_lower.ends_with(ext))
    }

    fn calculate_stats(&self, values: &[i32]) -> Option<(f64, f64)> {
        if values.is_empty() {
            return None;
        }

        let sum: i32 = values.iter().sum();
        let mean = sum as f64 / values.len() as f64;
        
        let variance: f64 = values.iter()
            .map(|&x| (x as f64 - mean).powi(2))
            .sum::<f64>() / values.len() as f64;
        
        let std_dev = variance.sqrt();
        
        Some((mean, std_dev))
    }

    fn load_suspicious_patterns() -> Vec<SuspiciousPattern> {
        vec![
            SuspiciousPattern {
                name: "Backdoor keywords".to_string(),
                pattern: r"(?i)(backdoor|malware|trojan|keylogger|rootkit)".to_string(),
                pattern_type: "commit_message".to_string(),
                description: "Commit message contains suspicious security-related keywords".to_string(),
                severity: Severity::High,
                confidence: 0.8,
            },
            SuspiciousPattern {
                name: "Credential removal".to_string(),
                pattern: r"(?i)(remove|delete|clean).*(password|secret|key|token|credential)".to_string(),
                pattern_type: "commit_message".to_string(),
                description: "Commit message suggests removal of credentials".to_string(),
                severity: Severity::Medium,
                confidence: 0.7,
            },
            SuspiciousPattern {
                name: "Suspicious branch".to_string(),
                pattern: r"(?i)(hack|exploit|backdoor|temp|test|experimental)".to_string(),
                pattern_type: "branch_name".to_string(),
                description: "Branch name contains suspicious keywords".to_string(),
                severity: Severity::Low,
                confidence: 0.6,
            },
        ]
    }

    fn load_risk_indicators() -> Vec<RiskIndicator> {
        vec![
            RiskIndicator {
                name: "Large commit size".to_string(),
                description: "Commits that modify many files or lines".to_string(),
                threshold_value: 100.0,
            },
            RiskIndicator {
                name: "Off-hours commits".to_string(),
                description: "Commits made outside normal business hours".to_string(),
                threshold_value: 0.0,
            },
        ]
    }
}

#[derive(Debug, Clone)]
pub struct CommitInfo {
    pub hash: String,
    pub author: String,
    pub email: String,
    pub timestamp: DateTime<Utc>,
    pub message: String,
    pub files_changed: i32,
    pub lines_added: i32,
    pub lines_removed: i32,
}

#[derive(Debug, Clone)]
pub struct DeletedFileInfo {
    pub file_path: String,
    pub deletion_commit: String,
    pub recoverable: bool,
}

#[derive(Debug, Clone)]
pub struct ContributorInfo {
    pub name: String,
    pub email: String,
    pub commits: i32,
    pub lines_added: i32,
    pub lines_removed: i32,
}

#[derive(Debug, Clone)]
pub struct BranchInfo {
    pub name: String,
    pub last_commit: String,
}

#[derive(Debug, Clone)]
pub struct FileModificationInfo {
    pub file_path: String,
    pub modification_count: i32,
    pub last_modified: DateTime<Utc>,
}

#[derive(Debug, Clone)]
pub struct SuspiciousPattern {
    pub name: String,
    pub pattern: String,
    pub pattern_type: String,
    pub description: String,
    pub severity: Severity,
    pub confidence: f32,
}

#[derive(Debug, Clone)]
pub struct RiskIndicator {
    pub name: String,
    pub description: String,
    pub threshold_value: f64,
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[tokio::test]
    async fn test_git_analyzer_creation() {
        let config = AnalysisConfig::default();
        let analyzer = GitAnalyzer::new(&config).await.unwrap();
        
        assert!(!analyzer.suspicious_patterns.is_empty());
        assert!(!analyzer.risk_indicators.is_empty());
    }

    #[test]
    fn test_suspicious_timing() {
        let analyzer = GitAnalyzer {
            config: AnalysisConfig::default(),
            suspicious_patterns: vec![],
            risk_indicators: vec![],
        };

        // 3 AM should be suspicious
        let suspicious_time = Utc.with_ymd_and_hms(2023, 1, 1, 3, 0, 0).unwrap();
        assert!(analyzer.is_suspicious_timing(&suspicious_time));

        // 2 PM should not be suspicious
        let normal_time = Utc.with_ymd_and_hms(2023, 1, 1, 14, 0, 0).unwrap();
        assert!(!analyzer.is_suspicious_timing(&normal_time));
    }

    #[test]
    fn test_sensitive_file_detection() {
        let analyzer = GitAnalyzer {
            config: AnalysisConfig::default(),
            suspicious_patterns: vec![],
            risk_indicators: vec![],
        };

        assert!(analyzer.is_potentially_sensitive_file(".env"));
        assert!(analyzer.is_potentially_sensitive_file("config/secrets.yaml"));
        assert!(analyzer.is_potentially_sensitive_file("private.key"));
        assert!(!analyzer.is_potentially_sensitive_file("public/index.html"));
    }

    #[test]
    fn test_suspicious_email_detection() {
        let analyzer = GitAnalyzer {
            config: AnalysisConfig::default(),
            suspicious_patterns: vec![],
            risk_indicators: vec![],
        };

        assert!(analyzer.is_suspicious_email("test@10minutemail.com"));
        assert!(analyzer.is_suspicious_email("noreply@example.com"));
        assert!(!analyzer.is_suspicious_email("developer@company.com"));
    }
}