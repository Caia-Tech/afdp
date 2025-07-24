use anyhow::Result;
use std::collections::{HashMap, HashSet};
use std::path::Path;
use regex::Regex;
use tracing::{debug, warn, info};
use uuid::Uuid;
use chrono::Utc;
use sha2::{Sha256, Digest};

use crate::{
    config::AnalysisConfig,
    storage::{FileAnalysis, SecurityFinding, FindingType, Severity, Classification},
};

/// Security scanner component for detecting vulnerabilities, malware, and security issues
pub struct SecurityScanner {
    config: AnalysisConfig,
    secret_patterns: Vec<SecretPattern>,
    vulnerability_patterns: Vec<VulnerabilityPattern>,
    malware_signatures: Vec<MalwareSignature>,
    suspicious_file_patterns: Vec<String>,
}

impl SecurityScanner {
    pub async fn new(config: &AnalysisConfig) -> Result<Self> {
        let secret_patterns = Self::load_secret_patterns();
        let vulnerability_patterns = Self::load_vulnerability_patterns();
        let malware_signatures = Self::load_malware_signatures();
        let suspicious_file_patterns = Self::load_suspicious_file_patterns();

        info!("Security scanner initialized with {} secret patterns, {} vulnerability patterns, {} malware signatures", 
              secret_patterns.len(), vulnerability_patterns.len(), malware_signatures.len());

        Ok(Self {
            config: config.clone(),
            secret_patterns,
            vulnerability_patterns,
            malware_signatures,
            suspicious_file_patterns,
        })
    }

    /// Scan a single file for security issues
    pub async fn scan_file(&self, job_id: Uuid, file_analysis: &FileAnalysis) -> Result<Vec<SecurityFinding>> {
        debug!("Security scanning file: {}", file_analysis.file_path);

        let mut findings = Vec::new();

        // Skip scanning if file is too large or binary (unless specifically configured)
        if file_analysis.file_size > (self.config.max_file_size_mb as i64 * 1024 * 1024) {
            debug!("Skipping large file: {} ({} bytes)", file_analysis.file_path, file_analysis.file_size);
            return Ok(findings);
        }

        // Check for suspicious file names/paths
        findings.extend(self.scan_file_path(&file_analysis.file_path, job_id).await?);

        // Check for secrets exposure
        if self.config.pii_detection {
            findings.extend(self.scan_for_secrets(job_id, file_analysis).await?);
        }

        // Check for vulnerability patterns
        findings.extend(self.scan_for_vulnerabilities(job_id, file_analysis).await?);

        // Check for malware signatures (if enabled)
        // TODO: Malware scanning is currently disabled due to YARA and ClamAV dependency issues
        // if self.config.malware_scanning {
        //     findings.extend(self.scan_for_malware(job_id, file_analysis).await?);
        // }

        // Check for suspicious code patterns
        findings.extend(self.scan_for_suspicious_code(job_id, file_analysis).await?);

        debug!("Security scan completed for {}: {} findings", file_analysis.file_path, findings.len());
        Ok(findings)
    }

    /// Perform repository-level security analysis
    pub async fn scan_repository(&self, job_id: Uuid, file_analyses: &[FileAnalysis]) -> Result<Vec<SecurityFinding>> {
        info!("Performing repository-level security analysis");

        let mut findings = Vec::new();

        // Analyze file distribution patterns
        findings.extend(self.analyze_file_distribution(job_id, file_analyses).await?);

        // Look for configuration security issues
        findings.extend(self.analyze_configurations(job_id, file_analyses).await?);

        // Check for exposed sensitive files
        findings.extend(self.check_exposed_files(job_id, file_analyses).await?);

        // Analyze permissions and access patterns
        findings.extend(self.analyze_permissions(job_id, file_analyses).await?);

        info!("Repository-level security analysis completed: {} findings", findings.len());
        Ok(findings)
    }

    async fn scan_file_path(&self, file_path: &str, job_id: Uuid) -> Result<Vec<SecurityFinding>> {
        let mut findings = Vec::new();

        // Check against suspicious file patterns
        for pattern in &self.suspicious_file_patterns {
            if file_path.to_lowercase().contains(pattern) {
                findings.push(SecurityFinding {
                    id: Uuid::new_v4(),
                    job_id,
                    file_id: None,
                    finding_type: FindingType::SuspiciousCode,
                    severity: Severity::Medium,
                    title: "Suspicious file path detected".to_string(),
                    description: format!("File path contains suspicious pattern: {}", pattern),
                    file_path: Some(file_path.to_string()),
                    line_number: None,
                    evidence: serde_json::json!({
                        "pattern": pattern,
                        "file_path": file_path
                    }),
                    recommendation: Some("Review file purpose and ensure it's legitimate".to_string()),
                    confidence: 0.7,
                    cve_id: None,
                    references: serde_json::json!([]),
                    detected_at: Utc::now(),
                });
            }
        }

        // Check for hidden directories that might contain malware
        if file_path.contains("/.") && !file_path.contains("/.git/") && !file_path.contains("/.github/") {
            findings.push(SecurityFinding {
                id: Uuid::new_v4(),
                job_id,
                file_id: None,
                finding_type: FindingType::SuspiciousCode,
                severity: Severity::Low,
                title: "Hidden directory detected".to_string(),
                description: "File located in hidden directory".to_string(),
                file_path: Some(file_path.to_string()),
                line_number: None,
                evidence: serde_json::json!({
                    "file_path": file_path
                }),
                recommendation: Some("Verify the purpose of files in hidden directories".to_string()),
                confidence: 0.5,
                cve_id: None,
                references: serde_json::json!([]),
                detected_at: Utc::now(),
            });
        }

        Ok(findings)
    }

    async fn scan_for_secrets(&self, job_id: Uuid, file_analysis: &FileAnalysis) -> Result<Vec<SecurityFinding>> {
        let mut findings = Vec::new();

        // Parse file content from findings JSON
        let content = self.extract_file_content(file_analysis)?;
        if content.is_empty() {
            return Ok(findings);
        }

        for (line_num, line) in content.lines().enumerate() {
            for pattern in &self.secret_patterns {
                if let Ok(regex) = Regex::new(&pattern.pattern) {
                    if regex.is_match(line) {
                        let severity = match pattern.confidence_level {
                            0.9..=1.0 => Severity::Critical,
                            0.7..=0.89 => Severity::High,
                            0.5..=0.69 => Severity::Medium,
                            _ => Severity::Low,
                        };

                        findings.push(SecurityFinding {
                            id: Uuid::new_v4(),
                            job_id,
                            file_id: Some(file_analysis.id),
                            finding_type: FindingType::SecretExposure,
                            severity,
                            title: format!("{} detected", pattern.name),
                            description: pattern.description.clone(),
                            file_path: Some(file_analysis.file_path.clone()),
                            line_number: Some(line_num as i32 + 1),
                            evidence: serde_json::json!({
                                "pattern_name": pattern.name,
                                "line_content": Self::redact_sensitive_content(line),
                                "detection_method": "regex_pattern"
                            }),
                            recommendation: Some(pattern.remediation.clone()),
                            confidence: pattern.confidence_level,
                            cve_id: None,
                            references: serde_json::json!(pattern.references),
                            detected_at: Utc::now(),
                        });
                    }
                }
            }
        }

        Ok(findings)
    }

    async fn scan_for_vulnerabilities(&self, job_id: Uuid, file_analysis: &FileAnalysis) -> Result<Vec<SecurityFinding>> {
        let mut findings = Vec::new();

        let content = self.extract_file_content(file_analysis)?;
        if content.is_empty() {
            return Ok(findings);
        }

        // Check language-specific vulnerability patterns
        let language = file_analysis.language.as_deref().unwrap_or("unknown");
        
        for pattern in &self.vulnerability_patterns {
            if pattern.languages.contains(&language.to_string()) || pattern.languages.contains(&"*".to_string()) {
                if let Ok(regex) = Regex::new(&pattern.pattern) {
                    for (line_num, line) in content.lines().enumerate() {
                        if regex.is_match(line) {
                            findings.push(SecurityFinding {
                                id: Uuid::new_v4(),
                                job_id,
                                file_id: Some(file_analysis.id),
                                finding_type: FindingType::Vulnerability,
                                severity: pattern.severity.clone(),
                                title: pattern.title.clone(),
                                description: pattern.description.clone(),
                                file_path: Some(file_analysis.file_path.clone()),
                                line_number: Some(line_num as i32 + 1),
                                evidence: serde_json::json!({
                                    "vulnerability_type": pattern.vulnerability_type,
                                    "line_content": line.trim(),
                                    "language": language
                                }),
                                recommendation: Some(pattern.remediation.clone()),
                                confidence: pattern.confidence_level,
                                cve_id: pattern.cve_id.clone(),
                                references: serde_json::json!(pattern.references),
                                detected_at: Utc::now(),
                            });
                        }
                    }
                }
            }
        }

        Ok(findings)
    }

    async fn scan_for_malware(&self, job_id: Uuid, file_analysis: &FileAnalysis) -> Result<Vec<SecurityFinding>> {
        // TODO: Malware scanning is currently disabled due to YARA and ClamAV dependency issues
        // This is a stub implementation that only performs basic entropy analysis
        let mut findings = Vec::new();

        // Calculate file entropy (high entropy might indicate encryption/packing)
        let entropy = self.calculate_file_entropy(file_analysis)?;
        if entropy > 7.5 {
            findings.push(SecurityFinding {
                id: Uuid::new_v4(),
                job_id,
                file_id: Some(file_analysis.id),
                finding_type: FindingType::Malware,
                severity: Severity::Medium,
                title: "High entropy file detected".to_string(),
                description: "File has high entropy, possibly indicating encryption or packing (basic analysis only - advanced malware scanning disabled)".to_string(),
                file_path: Some(file_analysis.file_path.clone()),
                line_number: None,
                evidence: serde_json::json!({
                    "entropy": entropy,
                    "threshold": 7.5,
                    "note": "Advanced malware scanning with YARA/ClamAV disabled"
                }),
                recommendation: Some("Analyze file for potential malware or review encryption usage. Note: Advanced malware scanning is currently unavailable.".to_string()),
                confidence: 0.4, // Lower confidence due to limited analysis
                cve_id: None,
                references: serde_json::json!([]),
                detected_at: Utc::now(),
            });
        }

        // TODO: Re-enable when YARA and ClamAV dependencies are available
        // Check for known malware signatures
        // let content = self.extract_file_content(file_analysis)?;
        // for signature in &self.malware_signatures {
        //     if content.contains(&signature.signature) {
        //         findings.push(SecurityFinding { ... });
        //     }
        // }

        Ok(findings)
    }

    async fn scan_for_suspicious_code(&self, job_id: Uuid, file_analysis: &FileAnalysis) -> Result<Vec<SecurityFinding>> {
        let mut findings = Vec::new();

        let content = self.extract_file_content(file_analysis)?;
        if content.is_empty() {
            return Ok(findings);
        }

        // Look for obfuscated code patterns
        if self.is_likely_obfuscated(&content) {
            findings.push(SecurityFinding {
                id: Uuid::new_v4(),
                job_id,
                file_id: Some(file_analysis.id),
                finding_type: FindingType::SuspiciousCode,
                severity: Severity::Medium,
                title: "Potentially obfuscated code detected".to_string(),
                description: "Code appears to be obfuscated or minified".to_string(),
                file_path: Some(file_analysis.file_path.clone()),
                line_number: None,
                evidence: serde_json::json!({
                    "indicators": ["high_density", "unusual_patterns", "low_readability"]
                }),
                recommendation: Some("Review code for legitimate obfuscation or potential malicious intent".to_string()),
                confidence: 0.6,
                cve_id: None,
                references: serde_json::json!([]),
                detected_at: Utc::now(),
            });
        }

        // Look for backdoor indicators
        let backdoor_patterns = [
            r"(?i)backdoor",
            r"(?i)keylogger",
            r"(?i)rootkit",
            r"(?i)trojan",
            r"eval\s*\(",
            r"exec\s*\(",
            r"system\s*\(",
            r"shell_exec\s*\(",
        ];

        for (line_num, line) in content.lines().enumerate() {
            for pattern in &backdoor_patterns {
                if let Ok(regex) = Regex::new(pattern) {
                    if regex.is_match(line) {
                        findings.push(SecurityFinding {
                            id: Uuid::new_v4(),
                            job_id,
                            file_id: Some(file_analysis.id),
                            finding_type: FindingType::Backdoor,
                            severity: Severity::High,
                            title: "Potential backdoor pattern detected".to_string(),
                            description: "Code contains patterns commonly associated with backdoors".to_string(),
                            file_path: Some(file_analysis.file_path.clone()),
                            line_number: Some(line_num as i32 + 1),
                            evidence: serde_json::json!({
                                "pattern": pattern,
                                "line_content": line.trim()
                            }),
                            recommendation: Some("Carefully review code for malicious intent".to_string()),
                            confidence: 0.7,
                            cve_id: None,
                            references: serde_json::json!([]),
                            detected_at: Utc::now(),
                        });
                    }
                }
            }
        }

        Ok(findings)
    }

    async fn analyze_file_distribution(&self, job_id: Uuid, file_analyses: &[FileAnalysis]) -> Result<Vec<SecurityFinding>> {
        let mut findings = Vec::new();

        // Count files by type and classification
        let mut type_counts = HashMap::new();
        let mut classification_counts = HashMap::new();

        for analysis in file_analyses {
            *type_counts.entry(analysis.file_type.clone()).or_insert(0) += 1;
            *classification_counts.entry(analysis.classification.clone()).or_insert(0) += 1;
        }

        // Check for unusual distributions
        let total_files = file_analyses.len();
        
        // Too many executables might indicate malware
        if let Some(&executable_count) = type_counts.get("executable") {
            let executable_ratio = executable_count as f64 / total_files as f64;
            if executable_ratio > 0.3 {
                findings.push(SecurityFinding {
                    id: Uuid::new_v4(),
                    job_id,
                    file_id: None,
                    finding_type: FindingType::Anomaly,
                    severity: Severity::Medium,
                    title: "Unusually high number of executable files".to_string(),
                    description: format!("Repository contains {}% executable files ({}/{})", 
                                       (executable_ratio * 100.0) as i32, executable_count, total_files),
                    file_path: None,
                    line_number: None,
                    evidence: serde_json::json!({
                        "executable_count": executable_count,
                        "total_files": total_files,
                        "ratio": executable_ratio
                    }),
                    recommendation: Some("Review the purpose of executable files in the repository".to_string()),
                    confidence: 0.6,
                    cve_id: None,
                    references: serde_json::json!([]),
                    detected_at: Utc::now(),
                });
            }
        }

        Ok(findings)
    }

    async fn analyze_configurations(&self, job_id: Uuid, file_analyses: &[FileAnalysis]) -> Result<Vec<SecurityFinding>> {
        let mut findings = Vec::new();

        for analysis in file_analyses {
            if analysis.file_type == "config" {
                let content = self.extract_file_content(analysis)?;
                
                // Check for hardcoded credentials in config files
                if self.contains_hardcoded_credentials(&content) {
                    findings.push(SecurityFinding {
                        id: Uuid::new_v4(),
                        job_id,
                        file_id: Some(analysis.id),
                        finding_type: FindingType::SecretExposure,
                        severity: Severity::High,
                        title: "Hardcoded credentials in configuration".to_string(),
                        description: "Configuration file contains what appears to be hardcoded credentials".to_string(),
                        file_path: Some(analysis.file_path.clone()),
                        line_number: None,
                        evidence: serde_json::json!({
                            "file_type": "config",
                            "detection_method": "credential_pattern_matching"
                        }),
                        recommendation: Some("Use environment variables or secure credential management".to_string()),
                        confidence: 0.8,
                        cve_id: None,
                        references: serde_json::json!([]),
                        detected_at: Utc::now(),
                    });
                }
            }
        }

        Ok(findings)
    }

    async fn check_exposed_files(&self, job_id: Uuid, file_analyses: &[FileAnalysis]) -> Result<Vec<SecurityFinding>> {
        let mut findings = Vec::new();

        let sensitive_files = [
            ".env", ".env.local", ".env.production",
            "config.yaml", "config.yml", "settings.json",
            "private.key", "id_rsa", "id_ed25519",
            "credentials.json", "secrets.yaml",
            "database.yml", "db.config",
        ];

        for analysis in file_analyses {
            let filename = Path::new(&analysis.file_path)
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or("");

            if sensitive_files.contains(&filename) {
                findings.push(SecurityFinding {
                    id: Uuid::new_v4(),
                    job_id,
                    file_id: Some(analysis.id),
                    finding_type: FindingType::DataLeak,
                    severity: Severity::High,
                    title: "Potentially sensitive file exposed".to_string(),
                    description: format!("File '{}' may contain sensitive information", filename),
                    file_path: Some(analysis.file_path.clone()),
                    line_number: None,
                    evidence: serde_json::json!({
                        "filename": filename,
                        "file_type": analysis.file_type
                    }),
                    recommendation: Some("Ensure sensitive files are properly secured and not exposed".to_string()),
                    confidence: 0.8,
                    cve_id: None,
                    references: serde_json::json!([]),
                    detected_at: Utc::now(),
                });
            }
        }

        Ok(findings)
    }

    async fn analyze_permissions(&self, _job_id: Uuid, _file_analyses: &[FileAnalysis]) -> Result<Vec<SecurityFinding>> {
        // Placeholder for permission analysis - would be implemented based on platform
        Ok(vec![])
    }

    fn extract_file_content(&self, file_analysis: &FileAnalysis) -> Result<String> {
        // Extract content from metadata or findings
        if let Some(metadata) = file_analysis.metadata.as_object() {
            if let Some(content) = metadata.get("content") {
                if let Some(content_str) = content.as_str() {
                    return Ok(content_str.to_string());
                }
            }
        }
        Ok(String::new())
    }

    fn calculate_file_entropy(&self, file_analysis: &FileAnalysis) -> Result<f64> {
        let content = self.extract_file_content(file_analysis)?;
        let data = content.as_bytes();
        
        if data.is_empty() {
            return Ok(0.0);
        }

        let mut counts = [0u32; 256];
        for &byte in data {
            counts[byte as usize] += 1;
        }

        let len = data.len() as f64;
        let mut entropy = 0.0;

        for &count in &counts {
            if count > 0 {
                let probability = count as f64 / len;
                entropy -= probability * probability.log2();
            }
        }

        Ok(entropy)
    }

    fn is_likely_obfuscated(&self, content: &str) -> bool {
        let lines: Vec<&str> = content.lines().collect();
        if lines.is_empty() {
            return false;
        }

        // Calculate average line length
        let total_chars: usize = lines.iter().map(|l| l.len()).sum();
        let avg_line_length = total_chars as f64 / lines.len() as f64;

        // Check for very long lines (common in obfuscated code)
        let long_line_count = lines.iter().filter(|l| l.len() > 200).count();
        let long_line_ratio = long_line_count as f64 / lines.len() as f64;

        // Check character density (ratio of non-whitespace to total)
        let non_whitespace: usize = content.chars().filter(|c| !c.is_whitespace()).count();
        let density = non_whitespace as f64 / content.len() as f64;

        avg_line_length > 100.0 || long_line_ratio > 0.1 || density > 0.8
    }

    fn contains_hardcoded_credentials(&self, content: &str) -> bool {
        let patterns = [
            r"(?i)password\s*[=:]\s*['\"][^'\"]{6,}['\"]",
            r"(?i)api[_-]?key\s*[=:]\s*['\"][^'\"]{10,}['\"]",
            r"(?i)secret\s*[=:]\s*['\"][^'\"]{8,}['\"]",
            r"(?i)token\s*[=:]\s*['\"][^'\"]{10,}['\"]",
        ];

        for pattern in &patterns {
            if let Ok(regex) = Regex::new(pattern) {
                if regex.is_match(content) {
                    return true;
                }
            }
        }

        false
    }

    fn redact_sensitive_content(content: &str) -> String {
        // Redact potential sensitive information for evidence
        let patterns = [
            (r"(['\"])[^'\"]*(['\"])", "${1}***REDACTED***${2}"),
            (r"(\w+\s*[=:]\s*)[\w\d]+", "${1}***REDACTED***"),
        ];

        let mut redacted = content.to_string();
        for (pattern, replacement) in &patterns {
            if let Ok(regex) = Regex::new(pattern) {
                redacted = regex.replace_all(&redacted, *replacement).to_string();
            }
        }

        redacted
    }

    fn load_secret_patterns() -> Vec<SecretPattern> {
        vec![
            SecretPattern {
                name: "AWS Access Key".to_string(),
                pattern: r"AKIA[0-9A-Z]{16}".to_string(),
                description: "AWS Access Key ID detected".to_string(),
                confidence_level: 0.9,
                remediation: "Remove AWS credentials and use IAM roles or environment variables".to_string(),
                references: vec!["https://aws.amazon.com/security/".to_string()],
            },
            SecretPattern {
                name: "GitHub Token".to_string(),
                pattern: r"ghp_[a-zA-Z0-9]{36}|github_pat_[a-zA-Z0-9]{22}_[a-zA-Z0-9]{59}".to_string(),
                description: "GitHub Personal Access Token detected".to_string(),
                confidence_level: 0.95,
                remediation: "Revoke the token and use secure token management".to_string(),
                references: vec!["https://github.com/settings/tokens".to_string()],
            },
            SecretPattern {
                name: "Generic API Key".to_string(),
                pattern: r"(?i)api[_-]?key['\"\s]*[=:]['\"\s]*[a-zA-Z0-9]{20,}".to_string(),
                description: "Generic API key pattern detected".to_string(),
                confidence_level: 0.7,
                remediation: "Use environment variables or secure credential storage".to_string(),
                references: vec![],
            },
            SecretPattern {
                name: "Private Key".to_string(),
                pattern: r"-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----".to_string(),
                description: "Private key detected".to_string(),
                confidence_level: 0.95,
                remediation: "Remove private keys from code and use secure key management".to_string(),
                references: vec![],
            },
            SecretPattern {
                name: "JWT Token".to_string(),
                pattern: r"eyJ[A-Za-z0-9_-]*\.eyJ[A-Za-z0-9_-]*\.[A-Za-z0-9_-]*".to_string(),
                description: "JSON Web Token detected".to_string(),
                confidence_level: 0.8,
                remediation: "Ensure JWT tokens are not hardcoded in source code".to_string(),
                references: vec!["https://jwt.io/".to_string()],
            },
        ]
    }

    fn load_vulnerability_patterns() -> Vec<VulnerabilityPattern> {
        vec![
            VulnerabilityPattern {
                title: "SQL Injection Vulnerability".to_string(),
                pattern: r"(?i)(SELECT|INSERT|UPDATE|DELETE).*(\+|\|\||CONCAT).*['\"]".to_string(),
                description: "Potential SQL injection vulnerability detected".to_string(),
                vulnerability_type: "sql_injection".to_string(),
                severity: Severity::High,
                confidence_level: 0.7,
                languages: vec!["php".to_string(), "python".to_string(), "java".to_string(), "*".to_string()],
                remediation: "Use parameterized queries or prepared statements".to_string(),
                cve_id: None,
                references: vec!["https://owasp.org/www-community/attacks/SQL_Injection".to_string()],
            },
            VulnerabilityPattern {
                title: "Command Injection".to_string(),
                pattern: r"(?i)(system|exec|shell_exec|passthru|popen)\s*\(.*\$".to_string(),
                description: "Potential command injection vulnerability".to_string(),
                vulnerability_type: "command_injection".to_string(),
                severity: Severity::Critical,
                confidence_level: 0.8,
                languages: vec!["php".to_string(), "python".to_string(), "ruby".to_string()],
                remediation: "Validate and sanitize all user input before executing commands".to_string(),
                cve_id: None,
                references: vec!["https://owasp.org/www-community/attacks/Command_Injection".to_string()],
            },
            VulnerabilityPattern {
                title: "Path Traversal".to_string(),
                pattern: r"\.\.\/|\.\.\\".to_string(),
                description: "Potential path traversal vulnerability".to_string(),
                vulnerability_type: "path_traversal".to_string(),
                severity: Severity::Medium,
                confidence_level: 0.6,
                languages: vec!["*".to_string()],
                remediation: "Validate file paths and use secure file handling methods".to_string(),
                cve_id: None,
                references: vec!["https://owasp.org/www-community/attacks/Path_Traversal".to_string()],
            },
        ]
    }

    fn load_malware_signatures() -> Vec<MalwareSignature> {
        vec![
            MalwareSignature {
                name: "Generic Backdoor".to_string(),
                signature: "backdoor".to_string(),
                signature_type: "string".to_string(),
                description: "Generic backdoor signature detected".to_string(),
                references: vec![],
            },
            MalwareSignature {
                name: "Keylogger Pattern".to_string(),
                signature: "keylogger".to_string(),
                signature_type: "string".to_string(),
                description: "Potential keylogger code detected".to_string(),
                references: vec![],
            },
        ]
    }

    fn load_suspicious_file_patterns() -> Vec<String> {
        vec![
            "hack".to_string(),
            "crack".to_string(),
            "exploit".to_string(),
            "backdoor".to_string(),
            "malware".to_string(),
            "virus".to_string(),
            "trojan".to_string(),
            "keylog".to_string(),
            "stealer".to_string(),
            "botnet".to_string(),
        ]
    }
}

#[derive(Debug, Clone)]
pub struct SecretPattern {
    pub name: String,
    pub pattern: String,
    pub description: String,
    pub confidence_level: f32,
    pub remediation: String,
    pub references: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct VulnerabilityPattern {
    pub title: String,
    pub pattern: String,
    pub description: String,
    pub vulnerability_type: String,
    pub severity: Severity,
    pub confidence_level: f32,
    pub languages: Vec<String>,
    pub remediation: String,
    pub cve_id: Option<String>,
    pub references: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct MalwareSignature {
    pub name: String,
    pub signature: String,
    pub signature_type: String,
    pub description: String,
    pub references: Vec<String>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::AnalysisConfig;

    #[tokio::test]
    async fn test_secret_detection() {
        let scanner = SecurityScanner::new(&AnalysisConfig::default()).await.unwrap();
        
        // Test AWS key detection
        let aws_content = "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE";
        assert!(scanner.contains_hardcoded_credentials(aws_content));
    }

    #[tokio::test]
    async fn test_obfuscation_detection() {
        let scanner = SecurityScanner::new(&AnalysisConfig::default()).await.unwrap();
        
        // Test obfuscated code detection
        let obfuscated = "a=''.join(chr(ord(c)^0x20)for c in 'HELLO WORLD');exec(a)";
        assert!(scanner.is_likely_obfuscated(obfuscated));
        
        let normal = "def hello_world():\n    print('Hello, World!')";
        assert!(!scanner.is_likely_obfuscated(normal));
    }

    #[test]
    fn test_entropy_calculation() {
        // This would test entropy calculation for malware detection
        // Placeholder for actual implementation
        assert!(true);
    }
}