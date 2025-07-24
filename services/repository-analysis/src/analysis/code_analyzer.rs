use anyhow::Result;
use std::collections::{HashMap, HashSet};
use tracing::{debug, info, warn};
use uuid::Uuid;
use regex::Regex;
use serde_json::json;

use crate::{
    config::AnalysisConfig,
    storage::{FileAnalysis, SecurityFinding, FindingType, Severity, Classification},
};

/// Code analyzer component for language-specific analysis and code quality assessment
pub struct CodeAnalyzer {
    config: AnalysisConfig,
    language_analyzers: HashMap<String, LanguageAnalyzer>,
    code_quality_rules: Vec<CodeQualityRule>,
    dependency_analyzers: HashMap<String, DependencyAnalyzer>,
}

impl CodeAnalyzer {
    pub async fn new(config: &AnalysisConfig) -> Result<Self> {
        let mut language_analyzers = HashMap::new();
        
        // Initialize language-specific analyzers
        language_analyzers.insert("rust".to_string(), LanguageAnalyzer::new_rust());
        language_analyzers.insert("python".to_string(), LanguageAnalyzer::new_python());
        language_analyzers.insert("javascript".to_string(), LanguageAnalyzer::new_javascript());
        language_analyzers.insert("typescript".to_string(), LanguageAnalyzer::new_typescript());
        language_analyzers.insert("go".to_string(), LanguageAnalyzer::new_go());
        language_analyzers.insert("java".to_string(), LanguageAnalyzer::new_java());
        language_analyzers.insert("c".to_string(), LanguageAnalyzer::new_c());
        language_analyzers.insert("cpp".to_string(), LanguageAnalyzer::new_cpp());
        language_analyzers.insert("csharp".to_string(), LanguageAnalyzer::new_csharp());

        let code_quality_rules = Self::load_code_quality_rules();
        
        let mut dependency_analyzers = HashMap::new();
        dependency_analyzers.insert("rust".to_string(), DependencyAnalyzer::new_rust());
        dependency_analyzers.insert("python".to_string(), DependencyAnalyzer::new_python());
        dependency_analyzers.insert("javascript".to_string(), DependencyAnalyzer::new_javascript());
        dependency_analyzers.insert("go".to_string(), DependencyAnalyzer::new_go());
        dependency_analyzers.insert("java".to_string(), DependencyAnalyzer::new_java());

        info!("Code analyzer initialized with {} language analyzers", language_analyzers.len());

        Ok(Self {
            config: config.clone(),
            language_analyzers,
            code_quality_rules,
            dependency_analyzers,
        })
    }

    /// Analyze code file for language-specific issues, quality, and security concerns
    pub async fn analyze_code_file(&self, job_id: Uuid, file_analysis: &FileAnalysis) -> Result<Vec<SecurityFinding>> {
        if file_analysis.file_type != "code" {
            return Ok(vec![]);
        }

        debug!("Analyzing code file: {}", file_analysis.file_path);

        let mut findings = Vec::new();
        let content = self.extract_file_content(file_analysis)?;
        
        if content.is_empty() {
            return Ok(findings);
        }

        // Get language-specific analyzer
        if let Some(language) = &file_analysis.language {
            if let Some(analyzer) = self.language_analyzers.get(language) {
                // Perform language-specific analysis
                findings.extend(self.analyze_with_language_analyzer(job_id, file_analysis, &content, analyzer).await?);
                
                // Analyze dependencies if applicable
                if let Some(dep_analyzer) = self.dependency_analyzers.get(language) {
                    findings.extend(self.analyze_dependencies(job_id, file_analysis, &content, dep_analyzer).await?);
                }
            }
        }

        // Generic code quality analysis
        findings.extend(self.analyze_code_quality(job_id, file_analysis, &content).await?);

        // Analyze code complexity
        findings.extend(self.analyze_complexity(job_id, file_analysis, &content).await?);

        // Analyze code patterns and anti-patterns
        findings.extend(self.analyze_code_patterns(job_id, file_analysis, &content).await?);

        debug!("Code analysis completed for {}: {} findings", file_analysis.file_path, findings.len());
        Ok(findings)
    }

    /// Analyze repository-level code patterns and architecture
    pub async fn analyze_repository_code(&self, job_id: Uuid, file_analyses: &[FileAnalysis]) -> Result<Vec<SecurityFinding>> {
        info!("Analyzing repository-level code patterns");

        let mut findings = Vec::new();
        let code_files: Vec<&FileAnalysis> = file_analyses.iter()
            .filter(|f| f.file_type == "code")
            .collect();

        // Analyze code architecture
        findings.extend(self.analyze_architecture(job_id, &code_files).await?);

        // Analyze dependency patterns
        findings.extend(self.analyze_dependency_patterns(job_id, &code_files).await?);

        // Analyze code duplication
        findings.extend(self.analyze_code_duplication(job_id, &code_files).await?);

        // Analyze API usage patterns
        findings.extend(self.analyze_api_usage(job_id, &code_files).await?);

        info!("Repository-level code analysis completed: {} findings", findings.len());
        Ok(findings)
    }

    async fn analyze_with_language_analyzer(
        &self,
        job_id: Uuid,
        file_analysis: &FileAnalysis,
        content: &str,
        analyzer: &LanguageAnalyzer,
    ) -> Result<Vec<SecurityFinding>> {
        let mut findings = Vec::new();

        // Check for language-specific security patterns
        for pattern in &analyzer.security_patterns {
            if let Ok(regex) = Regex::new(&pattern.pattern) {
                for (line_num, line) in content.lines().enumerate() {
                    if regex.is_match(line) {
                        findings.push(SecurityFinding {
                            id: Uuid::new_v4(),
                            job_id,
                            file_id: Some(file_analysis.id),
                            finding_type: pattern.finding_type.clone(),
                            severity: pattern.severity.clone(),
                            title: pattern.title.clone(),
                            description: pattern.description.clone(),
                            file_path: Some(file_analysis.file_path.clone()),
                            line_number: Some(line_num as i32 + 1),
                            evidence: json!({
                                "pattern_name": pattern.name,
                                "line_content": line.trim(),
                                "language": file_analysis.language
                            }),
                            recommendation: Some(pattern.recommendation.clone()),
                            confidence: pattern.confidence,
                            cve_id: pattern.cve_id.clone(),
                            references: json!(pattern.references),
                            detected_at: chrono::Utc::now(),
                        });
                    }
                }
            }
        }

        // Check for language-specific best practices
        for practice in &analyzer.best_practices {
            if !self.follows_best_practice(content, practice) {
                findings.push(SecurityFinding {
                    id: Uuid::new_v4(),
                    job_id,
                    file_id: Some(file_analysis.id),
                    finding_type: FindingType::ComplianceViolation,
                    severity: Severity::Low,
                    title: format!("Best practice violation: {}", practice.name),
                    description: practice.description.clone(),
                    file_path: Some(file_analysis.file_path.clone()),
                    line_number: None,
                    evidence: json!({
                        "practice": practice.name,
                        "language": file_analysis.language
                    }),
                    recommendation: Some(practice.recommendation.clone()),
                    confidence: 0.7,
                    cve_id: None,
                    references: json!([]),
                    detected_at: chrono::Utc::now(),
                });
            }
        }

        // Analyze syntax and structure
        if let Some(syntax_issues) = self.analyze_syntax(content, &analyzer.language).await? {
            for issue in syntax_issues {
                findings.push(SecurityFinding {
                    id: Uuid::new_v4(),
                    job_id,
                    file_id: Some(file_analysis.id),
                    finding_type: FindingType::Anomaly,
                    severity: Severity::Low,
                    title: "Syntax issue detected".to_string(),
                    description: issue.description,
                    file_path: Some(file_analysis.file_path.clone()),
                    line_number: issue.line_number,
                    evidence: json!({
                        "issue_type": issue.issue_type,
                        "language": file_analysis.language
                    }),
                    recommendation: Some("Review and fix syntax issues".to_string()),
                    confidence: 0.9,
                    cve_id: None,
                    references: json!([]),
                    detected_at: chrono::Utc::now(),
                });
            }
        }

        Ok(findings)
    }

    async fn analyze_dependencies(
        &self,
        job_id: Uuid,
        file_analysis: &FileAnalysis,
        content: &str,
        dep_analyzer: &DependencyAnalyzer,
    ) -> Result<Vec<SecurityFinding>> {
        let mut findings = Vec::new();

        // Extract dependencies from file
        let dependencies = dep_analyzer.extract_dependencies(content);

        for dependency in dependencies {
            // Check against known vulnerable dependencies
            if dep_analyzer.is_vulnerable_dependency(&dependency) {
                findings.push(SecurityFinding {
                    id: Uuid::new_v4(),
                    job_id,
                    file_id: Some(file_analysis.id),
                    finding_type: FindingType::Vulnerability,
                    severity: Severity::High,
                    title: "Vulnerable dependency detected".to_string(),
                    description: format!("Dependency '{}' has known vulnerabilities", dependency.name),
                    file_path: Some(file_analysis.file_path.clone()),
                    line_number: dependency.line_number,
                    evidence: json!({
                        "dependency_name": dependency.name,
                        "version": dependency.version,
                        "vulnerabilities": dependency.vulnerabilities
                    }),
                    recommendation: Some("Update to a secure version of the dependency".to_string()),
                    confidence: 0.9,
                    cve_id: dependency.vulnerabilities.first().cloned(),
                    references: json!(dependency.references),
                    detected_at: chrono::Utc::now(),
                });
            }

            // Check for outdated dependencies
            if dependency.is_outdated {
                findings.push(SecurityFinding {
                    id: Uuid::new_v4(),
                    job_id,
                    file_id: Some(file_analysis.id),
                    finding_type: FindingType::ComplianceViolation,
                    severity: Severity::Medium,
                    title: "Outdated dependency".to_string(),
                    description: format!("Dependency '{}' is outdated", dependency.name),
                    file_path: Some(file_analysis.file_path.clone()),
                    line_number: dependency.line_number,
                    evidence: json!({
                        "dependency_name": dependency.name,
                        "current_version": dependency.version,
                        "latest_version": dependency.latest_version
                    }),
                    recommendation: Some("Update to the latest version".to_string()),
                    confidence: 0.8,
                    cve_id: None,
                    references: json!([]),
                    detected_at: chrono::Utc::now(),
                });
            }
        }

        Ok(findings)
    }

    async fn analyze_code_quality(
        &self,
        job_id: Uuid,
        file_analysis: &FileAnalysis,
        content: &str,
    ) -> Result<Vec<SecurityFinding>> {
        let mut findings = Vec::new();

        for rule in &self.code_quality_rules {
            if let Ok(regex) = Regex::new(&rule.pattern) {
                for (line_num, line) in content.lines().enumerate() {
                    if regex.is_match(line) {
                        findings.push(SecurityFinding {
                            id: Uuid::new_v4(),
                            job_id,
                            file_id: Some(file_analysis.id),
                            finding_type: FindingType::ComplianceViolation,
                            severity: rule.severity.clone(),
                            title: rule.title.clone(),
                            description: rule.description.clone(),
                            file_path: Some(file_analysis.file_path.clone()),
                            line_number: Some(line_num as i32 + 1),
                            evidence: json!({
                                "rule_name": rule.name,
                                "line_content": line.trim()
                            }),
                            recommendation: Some(rule.recommendation.clone()),
                            confidence: 0.8,
                            cve_id: None,
                            references: json!([]),
                            detected_at: chrono::Utc::now(),
                        });
                    }
                }
            }
        }

        Ok(findings)
    }

    async fn analyze_complexity(&self, job_id: Uuid, file_analysis: &FileAnalysis, content: &str) -> Result<Vec<SecurityFinding>> {
        let mut findings = Vec::new();

        // Calculate cyclomatic complexity
        let complexity = self.calculate_cyclomatic_complexity(content);
        if complexity > 20 {
            findings.push(SecurityFinding {
                id: Uuid::new_v4(),
                job_id,
                file_id: Some(file_analysis.id),
                finding_type: FindingType::Anomaly,
                severity: Severity::Medium,
                title: "High cyclomatic complexity".to_string(),
                description: "File has high cyclomatic complexity, making it difficult to maintain and test".to_string(),
                file_path: Some(file_analysis.file_path.clone()),
                line_number: None,
                evidence: json!({
                    "complexity": complexity,
                    "threshold": 20
                }),
                recommendation: Some("Refactor code to reduce complexity".to_string()),
                confidence: 0.9,
                cve_id: None,
                references: json!([]),
                detected_at: chrono::Utc::now(),
            });
        }

        // Check function length
        let long_functions = self.find_long_functions(content);
        for long_function in long_functions {
            findings.push(SecurityFinding {
                id: Uuid::new_v4(),
                job_id,
                file_id: Some(file_analysis.id),
                finding_type: FindingType::Anomaly,
                severity: Severity::Low,
                title: "Long function detected".to_string(),
                description: "Function is too long and should be refactored".to_string(),
                file_path: Some(file_analysis.file_path.clone()),
                line_number: Some(long_function.line_number),
                evidence: json!({
                    "function_name": long_function.name,
                    "length": long_function.length,
                    "threshold": 50
                }),
                recommendation: Some("Break down long functions into smaller, more manageable pieces".to_string()),
                confidence: 0.8,
                cve_id: None,
                references: json!([]),
                detected_at: chrono::Utc::now(),
            });
        }

        Ok(findings)
    }

    async fn analyze_code_patterns(&self, job_id: Uuid, file_analysis: &FileAnalysis, content: &str) -> Result<Vec<SecurityFinding>> {
        let mut findings = Vec::new();

        // Check for anti-patterns
        let anti_patterns = [
            (r"(?i)goto\s+\w+", "Use of goto statement", "Avoid goto statements as they make code hard to follow"),
            (r"(?i)eval\s*\(", "Use of eval function", "Avoid eval() as it can execute arbitrary code"),
            (r"(?i)exec\s*\(", "Use of exec function", "Avoid exec() as it can execute arbitrary code"),
            (r"(?i)TODO|FIXME|HACK", "TODO/FIXME comments", "Address TODO and FIXME comments"),
        ];

        for (pattern, title, recommendation) in &anti_patterns {
            if let Ok(regex) = Regex::new(pattern) {
                for (line_num, line) in content.lines().enumerate() {
                    if regex.is_match(line) {
                        findings.push(SecurityFinding {
                            id: Uuid::new_v4(),
                            job_id,
                            file_id: Some(file_analysis.id),
                            finding_type: FindingType::SuspiciousCode,
                            severity: Severity::Medium,
                            title: title.to_string(),
                            description: format!("Anti-pattern detected: {}", title),
                            file_path: Some(file_analysis.file_path.clone()),
                            line_number: Some(line_num as i32 + 1),
                            evidence: json!({
                                "pattern": pattern,
                                "line_content": line.trim()
                            }),
                            recommendation: Some(recommendation.to_string()),
                            confidence: 0.7,
                            cve_id: None,
                            references: json!([]),
                            detected_at: chrono::Utc::now(),
                        });
                    }
                }
            }
        }

        Ok(findings)
    }

    async fn analyze_architecture(&self, _job_id: Uuid, _code_files: &[&FileAnalysis]) -> Result<Vec<SecurityFinding>> {
        // Placeholder for architecture analysis
        // Would analyze things like:
        // - Circular dependencies
        // - Layer violations
        // - Coupling metrics
        // - Module organization
        Ok(vec![])
    }

    async fn analyze_dependency_patterns(&self, _job_id: Uuid, _code_files: &[&FileAnalysis]) -> Result<Vec<SecurityFinding>> {
        // Placeholder for dependency pattern analysis
        // Would analyze things like:
        // - Dependency graphs
        // - Unused dependencies
        // - Conflicting versions
        // - License compatibility
        Ok(vec![])
    }

    async fn analyze_code_duplication(&self, job_id: Uuid, code_files: &[&FileAnalysis]) -> Result<Vec<SecurityFinding>> {
        let mut findings = Vec::new();

        // Simple duplication detection based on exact line matches
        let mut line_occurrences: HashMap<String, Vec<(String, usize)>> = HashMap::new();

        for file_analysis in code_files {
            if let Ok(content) = self.extract_file_content(file_analysis) {
                for (line_num, line) in content.lines().enumerate() {
                    let trimmed = line.trim();
                    if trimmed.len() > 20 && !trimmed.starts_with("//") && !trimmed.starts_with('#') {
                        line_occurrences
                            .entry(trimmed.to_string())
                            .or_insert_with(Vec::new)
                            .push((file_analysis.file_path.clone(), line_num + 1));
                    }
                }
            }
        }

        // Find duplicated lines
        for (line, occurrences) in line_occurrences {
            if occurrences.len() > 2 { // Same line appears in more than 2 places
                findings.push(SecurityFinding {
                    id: Uuid::new_v4(),
                    job_id,
                    file_id: None,
                    finding_type: FindingType::Anomaly,
                    severity: Severity::Low,
                    title: "Code duplication detected".to_string(),
                    description: "Identical code found in multiple locations".to_string(),
                    file_path: None,
                    line_number: None,
                    evidence: json!({
                        "duplicated_line": line,
                        "occurrences": occurrences.len(),
                        "locations": occurrences
                    }),
                    recommendation: Some("Consider extracting duplicated code into a shared function or module".to_string()),
                    confidence: 0.8,
                    cve_id: None,
                    references: json!([]),
                    detected_at: chrono::Utc::now(),
                });
            }
        }

        Ok(findings)
    }

    async fn analyze_api_usage(&self, _job_id: Uuid, _code_files: &[&FileAnalysis]) -> Result<Vec<SecurityFinding>> {
        // Placeholder for API usage analysis
        // Would analyze things like:
        // - Deprecated API usage
        // - Insecure API calls
        // - Rate limiting patterns
        // - Error handling around API calls
        Ok(vec![])
    }

    // Helper methods
    fn extract_file_content(&self, file_analysis: &FileAnalysis) -> Result<String> {
        if let Some(metadata) = file_analysis.metadata.as_object() {
            if let Some(content) = metadata.get("content") {
                if let Some(content_str) = content.as_str() {
                    return Ok(content_str.to_string());
                }
            }
        }
        Ok(String::new())
    }

    fn follows_best_practice(&self, content: &str, practice: &BestPractice) -> bool {
        if let Ok(regex) = Regex::new(&practice.pattern) {
            practice.should_match == regex.is_match(content)
        } else {
            true // If regex is invalid, assume practice is followed
        }
    }

    async fn analyze_syntax(&self, content: &str, language: &str) -> Result<Option<Vec<SyntaxIssue>>> {
        // Basic syntax analysis - in a real implementation, this would use language parsers
        let mut issues = Vec::new();

        match language {
            "python" => {
                // Check for basic Python syntax issues
                for (line_num, line) in content.lines().enumerate() {
                    if line.trim().ends_with('\\') && !line.trim_end_matches('\\').trim().is_empty() {
                        // Line continuation without proper indentation
                        issues.push(SyntaxIssue {
                            issue_type: "line_continuation".to_string(),
                            description: "Potential line continuation issue".to_string(),
                            line_number: Some(line_num as i32 + 1),
                        });
                    }
                }
            }
            "javascript" => {
                // Check for missing semicolons (simplified)
                for (line_num, line) in content.lines().enumerate() {
                    let trimmed = line.trim();
                    if !trimmed.is_empty() && 
                       !trimmed.ends_with(';') && 
                       !trimmed.ends_with('{') && 
                       !trimmed.ends_with('}') &&
                       !trimmed.starts_with("//") {
                        issues.push(SyntaxIssue {
                            issue_type: "missing_semicolon".to_string(),
                            description: "Potential missing semicolon".to_string(),
                            line_number: Some(line_num as i32 + 1),
                        });
                    }
                }
            }
            _ => {
                // Generic syntax checks
            }
        }

        if issues.is_empty() {
            Ok(None)
        } else {
            Ok(Some(issues))
        }
    }

    fn calculate_cyclomatic_complexity(&self, content: &str) -> u32 {
        // Simplified cyclomatic complexity calculation
        let decision_points = [
            "if", "else if", "while", "for", "case", "catch", "&&", "||", "?", ":"
        ];

        let mut complexity = 1; // Base complexity

        for line in content.lines() {
            for decision_point in &decision_points {
                complexity += line.matches(decision_point).count() as u32;
            }
        }

        complexity
    }

    fn find_long_functions(&self, content: &str) -> Vec<LongFunction> {
        let mut long_functions = Vec::new();
        let lines: Vec<&str> = content.lines().collect();
        
        let mut current_function: Option<(String, usize)> = None;
        let mut brace_count = 0;

        for (line_num, line) in lines.iter().enumerate() {
            let trimmed = line.trim();
            
            // Detect function start (simplified)
            if (trimmed.contains("function ") || trimmed.contains("def ") || 
                trimmed.contains("fn ") || trimmed.contains("func ")) &&
               trimmed.contains("(") {
                current_function = Some((
                    trimmed.split('(').next().unwrap_or("unknown").to_string(),
                    line_num + 1
                ));
                brace_count = 0;
            }

            // Track braces for function end detection
            brace_count += trimmed.matches('{').count() as i32;
            brace_count -= trimmed.matches('}').count() as i32;

            // Function end detected
            if let Some((name, start_line)) = &current_function {
                if brace_count <= 0 && line_num > *start_line {
                    let length = line_num - start_line + 1;
                    if length > 50 { // Threshold for long functions
                        long_functions.push(LongFunction {
                            name: name.clone(),
                            line_number: *start_line as i32,
                            length: length as i32,
                        });
                    }
                    current_function = None;
                }
            }
        }

        long_functions
    }

    fn load_code_quality_rules() -> Vec<CodeQualityRule> {
        vec![
            CodeQualityRule {
                name: "Long line".to_string(),
                pattern: r".{120,}".to_string(),
                title: "Line too long".to_string(),
                description: "Line exceeds recommended length of 120 characters".to_string(),
                severity: Severity::Low,
                recommendation: "Break long lines for better readability".to_string(),
            },
            CodeQualityRule {
                name: "Magic number".to_string(),
                pattern: r"\b\d{3,}\b".to_string(),
                title: "Magic number detected".to_string(),
                description: "Numeric literal should be replaced with a named constant".to_string(),
                severity: Severity::Low,
                recommendation: "Replace magic numbers with named constants".to_string(),
            },
            CodeQualityRule {
                name: "Empty catch block".to_string(),
                pattern: r"catch\s*\([^)]*\)\s*\{\s*\}".to_string(),
                title: "Empty catch block".to_string(),
                description: "Empty catch block swallows exceptions".to_string(),
                severity: Severity::Medium,
                recommendation: "Add proper error handling in catch blocks".to_string(),
            },
        ]
    }
}

#[derive(Debug, Clone)]
pub struct LanguageAnalyzer {
    pub language: String,
    pub security_patterns: Vec<SecurityPattern>,
    pub best_practices: Vec<BestPractice>,
    pub file_extensions: Vec<String>,
}

impl LanguageAnalyzer {
    pub fn new_rust() -> Self {
        Self {
            language: "rust".to_string(),
            security_patterns: vec![
                SecurityPattern {
                    name: "Unsafe block".to_string(),
                    pattern: r"unsafe\s*\{".to_string(),
                    finding_type: FindingType::SuspiciousCode,
                    severity: Severity::Medium,
                    title: "Unsafe Rust code detected".to_string(),
                    description: "Unsafe block bypasses Rust's safety guarantees".to_string(),
                    recommendation: "Review unsafe code for memory safety issues".to_string(),
                    confidence: 0.9,
                    cve_id: None,
                    references: vec!["https://doc.rust-lang.org/book/ch19-01-unsafe-rust.html".to_string()],
                },
                SecurityPattern {
                    name: "Transmute usage".to_string(),
                    pattern: r"std::mem::transmute".to_string(),
                    finding_type: FindingType::SuspiciousCode,
                    severity: Severity::High,
                    title: "Transmute usage detected".to_string(),
                    description: "Transmute can bypass type safety".to_string(),
                    recommendation: "Use safer alternatives to transmute when possible".to_string(),
                    confidence: 0.9,
                    cve_id: None,
                    references: vec![],
                },
            ],
            best_practices: vec![
                BestPractice {
                    name: "Error handling".to_string(),
                    pattern: r"\?|\.unwrap\(\)|\.expect\(|Result<".to_string(),
                    should_match: true,
                    description: "Proper error handling using Result types".to_string(),
                    recommendation: "Use Result types and proper error propagation".to_string(),
                },
            ],
            file_extensions: vec!["rs".to_string()],
        }
    }

    pub fn new_python() -> Self {
        Self {
            language: "python".to_string(),
            security_patterns: vec![
                SecurityPattern {
                    name: "Eval usage".to_string(),
                    pattern: r"eval\s*\(".to_string(),
                    finding_type: FindingType::Vulnerability,
                    severity: Severity::Critical,
                    title: "Dangerous eval() usage".to_string(),
                    description: "eval() can execute arbitrary code".to_string(),
                    recommendation: "Avoid eval() or use ast.literal_eval() for safe evaluation".to_string(),
                    confidence: 0.95,
                    cve_id: None,
                    references: vec!["https://docs.python.org/3/library/functions.html#eval".to_string()],
                },
                SecurityPattern {
                    name: "SQL injection".to_string(),
                    pattern: r"cursor\.execute\s*\(\s*[\"'].*%.*[\"']".to_string(),
                    finding_type: FindingType::Vulnerability,
                    severity: Severity::High,
                    title: "Potential SQL injection".to_string(),
                    description: "String formatting in SQL queries can lead to injection".to_string(),
                    recommendation: "Use parameterized queries or prepared statements".to_string(),
                    confidence: 0.8,
                    cve_id: None,
                    references: vec!["https://owasp.org/www-community/attacks/SQL_Injection".to_string()],
                },
            ],
            best_practices: vec![
                BestPractice {
                    name: "Exception handling".to_string(),
                    pattern: r"try:|except:|finally:".to_string(),
                    should_match: true,
                    description: "Proper exception handling".to_string(),
                    recommendation: "Use try-except blocks for error handling".to_string(),
                },
            ],
            file_extensions: vec!["py".to_string()],
        }
    }

    pub fn new_javascript() -> Self {
        Self {
            language: "javascript".to_string(),
            security_patterns: vec![
                SecurityPattern {
                    name: "Eval usage".to_string(),
                    pattern: r"eval\s*\(".to_string(),
                    finding_type: FindingType::Vulnerability,
                    severity: Severity::Critical,
                    title: "Dangerous eval() usage".to_string(),
                    description: "eval() can execute arbitrary JavaScript code".to_string(),
                    recommendation: "Avoid eval() or use JSON.parse() for safe parsing".to_string(),
                    confidence: 0.95,
                    cve_id: None,
                    references: vec![],
                },
                SecurityPattern {
                    name: "innerHTML usage".to_string(),
                    pattern: r"\.innerHTML\s*=".to_string(),
                    finding_type: FindingType::Vulnerability,
                    severity: Severity::Medium,
                    title: "Potential XSS via innerHTML".to_string(),
                    description: "innerHTML can introduce XSS vulnerabilities".to_string(),
                    recommendation: "Use textContent or properly sanitize HTML".to_string(),
                    confidence: 0.7,
                    cve_id: None,
                    references: vec!["https://owasp.org/www-community/attacks/xss/".to_string()],
                },
            ],
            best_practices: vec![
                BestPractice {
                    name: "Strict mode".to_string(),
                    pattern: r"[\"']use strict[\"']".to_string(),
                    should_match: true,
                    description: "Use strict mode for better error detection".to_string(),
                    recommendation: "Add 'use strict' at the beginning of files or functions".to_string(),
                },
            ],
            file_extensions: vec!["js".to_string(), "mjs".to_string()],
        }
    }

    pub fn new_typescript() -> Self {
        let mut analyzer = Self::new_javascript();
        analyzer.language = "typescript".to_string();
        analyzer.file_extensions = vec!["ts".to_string(), "tsx".to_string()];
        analyzer
    }

    pub fn new_go() -> Self {
        Self {
            language: "go".to_string(),
            security_patterns: vec![
                SecurityPattern {
                    name: "Command injection".to_string(),
                    pattern: r"exec\.Command\s*\([^)]*\+".to_string(),
                    finding_type: FindingType::Vulnerability,
                    severity: Severity::High,
                    title: "Potential command injection".to_string(),
                    description: "String concatenation in exec.Command can lead to injection".to_string(),
                    recommendation: "Use properly escaped arguments for exec.Command".to_string(),
                    confidence: 0.8,
                    cve_id: None,
                    references: vec![],
                },
            ],
            best_practices: vec![
                BestPractice {
                    name: "Error handling".to_string(),
                    pattern: r"if err != nil".to_string(),
                    should_match: true,
                    description: "Proper error handling in Go".to_string(),
                    recommendation: "Always check and handle errors".to_string(),
                },
            ],
            file_extensions: vec!["go".to_string()],
        }
    }

    pub fn new_java() -> Self {
        Self {
            language: "java".to_string(),
            security_patterns: vec![
                SecurityPattern {
                    name: "SQL injection".to_string(),
                    pattern: r"Statement\.executeQuery\s*\([^)]*\+".to_string(),
                    finding_type: FindingType::Vulnerability,
                    severity: Severity::High,
                    title: "Potential SQL injection".to_string(),
                    description: "String concatenation in SQL queries can lead to injection".to_string(),
                    recommendation: "Use PreparedStatement with parameterized queries".to_string(),
                    confidence: 0.8,
                    cve_id: None,
                    references: vec![],
                },
            ],
            best_practices: vec![
                BestPractice {
                    name: "Exception handling".to_string(),
                    pattern: r"try\s*\{|catch\s*\(|finally\s*\{".to_string(),
                    should_match: true,
                    description: "Proper exception handling".to_string(),
                    recommendation: "Use try-catch-finally blocks for error handling".to_string(),
                },
            ],
            file_extensions: vec!["java".to_string()],
        }
    }

    pub fn new_c() -> Self {
        Self {
            language: "c".to_string(),
            security_patterns: vec![
                SecurityPattern {
                    name: "Buffer overflow".to_string(),
                    pattern: r"strcpy|strcat|sprintf|gets".to_string(),
                    finding_type: FindingType::Vulnerability,
                    severity: Severity::High,
                    title: "Unsafe string function".to_string(),
                    description: "Function can cause buffer overflow".to_string(),
                    recommendation: "Use safe alternatives like strncpy, strncat, snprintf".to_string(),
                    confidence: 0.9,
                    cve_id: None,
                    references: vec!["https://cwe.mitre.org/data/definitions/120.html".to_string()],
                },
            ],
            best_practices: vec![],
            file_extensions: vec!["c".to_string(), "h".to_string()],
        }
    }

    pub fn new_cpp() -> Self {
        let mut analyzer = Self::new_c();
        analyzer.language = "cpp".to_string();
        analyzer.file_extensions = vec!["cpp".to_string(), "cc".to_string(), "cxx".to_string(), "hpp".to_string()];
        analyzer
    }

    pub fn new_csharp() -> Self {
        Self {
            language: "csharp".to_string(),
            security_patterns: vec![
                SecurityPattern {
                    name: "SQL injection".to_string(),
                    pattern: r"SqlCommand\s*\([^)]*\+".to_string(),
                    finding_type: FindingType::Vulnerability,
                    severity: Severity::High,
                    title: "Potential SQL injection".to_string(),
                    description: "String concatenation in SQL commands can lead to injection".to_string(),
                    recommendation: "Use parameterized queries".to_string(),
                    confidence: 0.8,
                    cve_id: None,
                    references: vec![],
                },
            ],
            best_practices: vec![],
            file_extensions: vec!["cs".to_string()],
        }
    }
}

#[derive(Debug, Clone)]
pub struct DependencyAnalyzer {
    pub language: String,
    pub dependency_files: Vec<String>,
    pub vulnerability_database: HashMap<String, Vec<String>>, // Package -> CVEs
}

impl DependencyAnalyzer {
    pub fn new_rust() -> Self {
        Self {
            language: "rust".to_string(),
            dependency_files: vec!["Cargo.toml".to_string(), "Cargo.lock".to_string()],
            vulnerability_database: HashMap::new(), // Would be populated from security advisories
        }
    }

    pub fn new_python() -> Self {
        Self {
            language: "python".to_string(),
            dependency_files: vec!["requirements.txt".to_string(), "Pipfile".to_string(), "pyproject.toml".to_string()],
            vulnerability_database: HashMap::new(),
        }
    }

    pub fn new_javascript() -> Self {
        Self {
            language: "javascript".to_string(),
            dependency_files: vec!["package.json".to_string(), "package-lock.json".to_string(), "yarn.lock".to_string()],
            vulnerability_database: HashMap::new(),
        }
    }

    pub fn new_go() -> Self {
        Self {
            language: "go".to_string(),
            dependency_files: vec!["go.mod".to_string(), "go.sum".to_string()],
            vulnerability_database: HashMap::new(),
        }
    }

    pub fn new_java() -> Self {
        Self {
            language: "java".to_string(),
            dependency_files: vec!["pom.xml".to_string(), "build.gradle".to_string()],
            vulnerability_database: HashMap::new(),
        }
    }

    pub fn extract_dependencies(&self, content: &str) -> Vec<Dependency> {
        // Simplified dependency extraction - would be more sophisticated in reality
        let mut dependencies = Vec::new();

        match self.language.as_str() {
            "rust" => {
                // Parse Cargo.toml format
                for (line_num, line) in content.lines().enumerate() {
                    if line.contains(" = ") && !line.trim().starts_with('#') {
                        let parts: Vec<&str> = line.split('=').collect();
                        if parts.len() == 2 {
                            let name = parts[0].trim().trim_matches('"');
                            let version = parts[1].trim().trim_matches('"');
                            dependencies.push(Dependency {
                                name: name.to_string(),
                                version: Some(version.to_string()),
                                line_number: Some(line_num as i32 + 1),
                                is_outdated: false,
                                latest_version: None,
                                vulnerabilities: vec![],
                                references: vec![],
                            });
                        }
                    }
                }
            }
            "javascript" => {
                // Parse package.json format
                if content.contains("\"dependencies\"") || content.contains("\"devDependencies\"") {
                    // Would use proper JSON parsing in reality
                }
            }
            _ => {}
        }

        dependencies
    }

    pub fn is_vulnerable_dependency(&self, dependency: &Dependency) -> bool {
        self.vulnerability_database.contains_key(&dependency.name)
    }
}

#[derive(Debug, Clone)]
pub struct SecurityPattern {
    pub name: String,
    pub pattern: String,
    pub finding_type: FindingType,
    pub severity: Severity,
    pub title: String,
    pub description: String,
    pub recommendation: String,
    pub confidence: f32,
    pub cve_id: Option<String>,
    pub references: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct BestPractice {
    pub name: String,
    pub pattern: String,
    pub should_match: bool,
    pub description: String,
    pub recommendation: String,
}

#[derive(Debug, Clone)]
pub struct CodeQualityRule {
    pub name: String,
    pub pattern: String,
    pub title: String,
    pub description: String,
    pub severity: Severity,
    pub recommendation: String,
}

#[derive(Debug, Clone)]
pub struct Dependency {
    pub name: String,
    pub version: Option<String>,
    pub line_number: Option<i32>,
    pub is_outdated: bool,
    pub latest_version: Option<String>,
    pub vulnerabilities: Vec<String>,
    pub references: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct SyntaxIssue {
    pub issue_type: String,
    pub description: String,
    pub line_number: Option<i32>,
}

#[derive(Debug, Clone)]
pub struct LongFunction {
    pub name: String,
    pub line_number: i32,
    pub length: i32,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_code_analyzer_creation() {
        let config = AnalysisConfig::default();
        let analyzer = CodeAnalyzer::new(&config).await.unwrap();
        
        assert!(analyzer.language_analyzers.contains_key("rust"));
        assert!(analyzer.language_analyzers.contains_key("python"));
        assert!(!analyzer.code_quality_rules.is_empty());
    }

    #[test]
    fn test_cyclomatic_complexity() {
        let analyzer = CodeAnalyzer {
            config: AnalysisConfig::default(),
            language_analyzers: HashMap::new(),
            code_quality_rules: vec![],
            dependency_analyzers: HashMap::new(),
        };

        let simple_code = "print('hello')";
        assert_eq!(analyzer.calculate_cyclomatic_complexity(simple_code), 1);

        let complex_code = "if x > 0:\n    if y > 0:\n        while z > 0:\n            z -= 1";
        assert!(analyzer.calculate_cyclomatic_complexity(complex_code) > 1);
    }

    #[test]
    fn test_rust_analyzer() {
        let analyzer = LanguageAnalyzer::new_rust();
        assert_eq!(analyzer.language, "rust");
        assert!(!analyzer.security_patterns.is_empty());
        assert!(analyzer.file_extensions.contains(&"rs".to_string()));
    }

    #[test]
    fn test_dependency_extraction() {
        let dep_analyzer = DependencyAnalyzer::new_rust();
        let cargo_content = r#"
[dependencies]
serde = "1.0"
tokio = "1.0"
"#;
        
        let dependencies = dep_analyzer.extract_dependencies(cargo_content);
        assert!(!dependencies.is_empty());
    }
}