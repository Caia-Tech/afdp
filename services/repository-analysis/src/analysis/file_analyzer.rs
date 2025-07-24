use anyhow::Result;
use std::path::Path;
use std::collections::HashMap;
use walkdir::WalkDir;
use mime_guess::from_path;
use tokio::fs;
use tokio::io::AsyncReadExt;
use tracing::{debug, warn};
use uuid::Uuid;
use chrono::{DateTime, Utc};
use sha2::{Sha256, Digest};
use blake3;

use crate::{
    config::AnalysisConfig,
    storage::{FileAnalysis, Classification},
    analysis::{FileInfo, RepositoryInfo},
};

/// File analyzer component responsible for file discovery, classification, and basic analysis
pub struct FileAnalyzer {
    config: AnalysisConfig,
    supported_text_extensions: Vec<String>,
    supported_code_extensions: Vec<String>,
}

impl FileAnalyzer {
    pub async fn new(config: &AnalysisConfig) -> Result<Self> {
        let supported_text_extensions = vec![
            "txt".to_string(), "md".to_string(), "rst".to_string(), "doc".to_string(),
            "docx".to_string(), "pdf".to_string(), "rtf".to_string(), "odt".to_string(),
        ];

        let supported_code_extensions = vec![
            "rs".to_string(), "go".to_string(), "py".to_string(), "js".to_string(),
            "ts".to_string(), "java".to_string(), "c".to_string(), "cpp".to_string(),
            "cc".to_string(), "cxx".to_string(), "h".to_string(), "hpp".to_string(),
            "cs".to_string(), "php".to_string(), "rb".to_string(), "swift".to_string(),
            "kt".to_string(), "scala".to_string(), "clj".to_string(), "hs".to_string(),
            "elm".to_string(), "lua".to_string(), "perl".to_string(), "r".to_string(),
            "m".to_string(), "mm".to_string(), "vb".to_string(), "pas".to_string(),
            "ada".to_string(), "f90".to_string(), "for".to_string(), "cob".to_string(),
            "asm".to_string(), "s".to_string(), "sh".to_string(), "bash".to_string(),
            "zsh".to_string(), "fish".to_string(), "ps1".to_string(), "bat".to_string(),
            "cmd".to_string(), "sql".to_string(), "html".to_string(), "htm".to_string(),
            "xml".to_string(), "xhtml".to_string(), "css".to_string(), "scss".to_string(),
            "sass".to_string(), "less".to_string(), "json".to_string(), "yaml".to_string(),
            "yml".to_string(), "toml".to_string(), "ini".to_string(), "cfg".to_string(),
            "conf".to_string(), "properties".to_string(), "env".to_string(),
        ];

        Ok(Self {
            config: config.clone(),
            supported_text_extensions,
            supported_code_extensions,
        })
    }

    /// Discover all files in a repository directory
    pub async fn discover_files(&self, repo_path: &str) -> Result<Vec<FileInfo>> {
        debug!("Discovering files in: {}", repo_path);

        let mut files = Vec::new();
        let base_path = Path::new(repo_path);

        for entry in WalkDir::new(repo_path)
            .follow_links(false)
            .into_iter()
            .filter_map(|e| e.ok())
        {
            if entry.file_type().is_file() {
                let file_path = entry.path();
                let relative_path = file_path.strip_prefix(base_path)
                    .unwrap_or(file_path)
                    .to_string_lossy()
                    .to_string();

                // Skip hidden files and directories (configurable)
                if self.should_skip_file(&relative_path) {
                    continue;
                }

                let metadata = fs::metadata(file_path).await?;
                let modified_at = metadata.modified()
                    .map(|t| DateTime::<Utc>::from(t))
                    .unwrap_or_else(|_| Utc::now());

                let file_info = FileInfo {
                    path: file_path.to_string_lossy().to_string(),
                    relative_path,
                    size_bytes: metadata.len(),
                    modified_at,
                    file_type: self.classify_file_type(file_path),
                    mime_type: from_path(file_path).first().map(|m| m.to_string()),
                    extension: file_path.extension()
                        .and_then(|ext| ext.to_str())
                        .map(|s| s.to_lowercase()),
                    is_binary: self.is_binary_file(file_path),
                    is_executable: self.is_executable_file(file_path),
                    permissions: self.get_file_permissions(&metadata),
                };

                files.push(file_info);
            }
        }

        debug!("Discovered {} files", files.len());
        Ok(files)
    }

    /// Analyze a single file and extract metadata and content
    pub async fn analyze_file(&self, job_id: Uuid, file_info: &FileInfo) -> Result<FileAnalysis> {
        debug!("Analyzing file: {}", file_info.relative_path);

        let analysis_start = std::time::Instant::now();

        // Read file content
        let content = self.read_file_content(&file_info.path, file_info.size_bytes).await?;

        // Generate hashes
        let hash_sha256 = self.calculate_sha256(&content);
        let hash_blake3 = self.calculate_blake3(&content);

        // Detect encoding and language
        let encoding = self.detect_encoding(&content);
        let language = self.detect_language(file_info, &content);

        // Extract content metadata
        let content_metadata = self.extract_content_metadata(&content, &file_info.file_type);

        // Classify content sensitivity
        let classification = self.classify_content_sensitivity(&content, &content_metadata);

        // Perform basic content analysis
        let findings = self.analyze_content(&content, file_info).await?;

        let processing_time = analysis_start.elapsed();

        let file_analysis = FileAnalysis {
            id: Uuid::new_v4(),
            job_id,
            file_path: file_info.relative_path.clone(),
            file_type: file_info.file_type.clone(),
            file_size: file_info.size_bytes as i64,
            mime_type: file_info.mime_type.clone(),
            language,
            encoding,
            hash_sha256,
            hash_blake3,
            classification,
            findings: serde_json::to_value(&findings)?,
            metadata: serde_json::to_value(&content_metadata)?,
            processed_at: Utc::now(),
            processing_time_ms: processing_time.as_millis() as i64,
        };

        Ok(file_analysis)
    }

    fn should_skip_file(&self, relative_path: &str) -> bool {
        let skip_patterns = [
            ".git/", ".svn/", ".hg/", ".bzr/",
            "node_modules/", "target/", "build/", "dist/",
            ".DS_Store", "Thumbs.db", ".gitignore", ".gitkeep",
            "__pycache__/", ".pytest_cache/", ".coverage",
            ".idea/", ".vscode/", ".vs/",
        ];

        for pattern in &skip_patterns {
            if relative_path.starts_with(pattern) || relative_path.contains(pattern) {
                return true;
            }
        }

        // Skip very large files unless specifically configured
        false
    }

    fn classify_file_type(&self, file_path: &Path) -> String {
        if let Some(extension) = file_path.extension().and_then(|ext| ext.to_str()) {
            let ext_lower = extension.to_lowercase();
            
            if self.supported_code_extensions.contains(&ext_lower) {
                return "code".to_string();
            }
            
            if self.supported_text_extensions.contains(&ext_lower) {
                return "document".to_string();
            }
            
            match ext_lower.as_str() {
                "json" | "yaml" | "yml" | "toml" | "ini" | "cfg" | "conf" | "properties" | "env" => "config".to_string(),
                "png" | "jpg" | "jpeg" | "gif" | "bmp" | "svg" | "ico" | "tiff" | "webp" => "image".to_string(),
                "mp3" | "wav" | "flac" | "ogg" | "m4a" | "aac" => "audio".to_string(),
                "mp4" | "avi" | "mkv" | "mov" | "wmv" | "flv" | "webm" => "video".to_string(),
                "zip" | "tar" | "gz" | "bz2" | "xz" | "7z" | "rar" | "dmg" | "iso" => "archive".to_string(),
                "exe" | "dll" | "so" | "dylib" | "app" | "deb" | "rpm" | "msi" => "executable".to_string(),
                "pdf" | "doc" | "docx" | "xls" | "xlsx" | "ppt" | "pptx" | "odt" | "ods" | "odp" => "office_document".to_string(),
                "crt" | "pem" | "key" | "p12" | "pfx" | "jks" | "keystore" => "certificate".to_string(),
                _ => "unknown".to_string(),
            }
        } else {
            // Files without extension
            if let Some(filename) = file_path.file_name().and_then(|name| name.to_str()) {
                match filename {
                    "Dockerfile" | "Makefile" | "Rakefile" | "Gemfile" | "Pipfile" => "code".to_string(),
                    "README" | "LICENSE" | "CHANGELOG" | "AUTHORS" | "CONTRIBUTORS" => "document".to_string(),
                    _ => "unknown".to_string(),
                }
            } else {
                "unknown".to_string()
            }
        }
    }

    fn is_binary_file(&self, file_path: &Path) -> bool {
        // Basic heuristic - would be more sophisticated in real implementation
        if let Some(extension) = file_path.extension().and_then(|ext| ext.to_str()) {
            let binary_extensions = [
                "exe", "dll", "so", "dylib", "o", "obj", "bin", "lib", "a",
                "png", "jpg", "jpeg", "gif", "bmp", "ico", "svg", "tiff",
                "mp3", "wav", "mp4", "avi", "mov", "wmv",
                "zip", "tar", "gz", "bz2", "xz", "7z", "rar",
                "pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx",
            ];
            
            binary_extensions.contains(&extension.to_lowercase().as_str())
        } else {
            false
        }
    }

    fn is_executable_file(&self, file_path: &Path) -> bool {
        if let Some(extension) = file_path.extension().and_then(|ext| ext.to_str()) {
            let executable_extensions = ["exe", "app", "com", "bat", "cmd", "sh", "bash", "zsh", "fish"];
            executable_extensions.contains(&extension.to_lowercase().as_str())
        } else {
            // Check if file has executable permission (Unix-like systems)
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                if let Ok(metadata) = std::fs::metadata(file_path) {
                    let permissions = metadata.permissions();
                    return permissions.mode() & 0o111 != 0;
                }
            }
            false
        }
    }

    fn get_file_permissions(&self, metadata: &std::fs::Metadata) -> Option<String> {
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = metadata.permissions().mode();
            Some(format!("{:o}", mode & 0o777))
        }
        #[cfg(not(unix))]
        {
            None
        }
    }

    async fn read_file_content(&self, file_path: &str, size_bytes: u64) -> Result<Vec<u8>> {
        let max_read_size = self.config.max_file_size_mb as u64 * 1024 * 1024;
        
        if size_bytes > max_read_size {
            warn!("File {} is too large ({} bytes), truncating to {} bytes", 
                  file_path, size_bytes, max_read_size);
        }

        let mut file = fs::File::open(file_path).await?;
        let read_size = size_bytes.min(max_read_size) as usize;
        
        let mut content = vec![0u8; read_size];
        let bytes_read = file.read_exact(&mut content).await.unwrap_or_else(|_| {
            // Handle partial reads
            content.truncate(0);
            0
        });
        
        content.truncate(bytes_read);
        Ok(content)
    }

    fn calculate_sha256(&self, content: &[u8]) -> String {
        let mut hasher = Sha256::new();
        hasher.update(content);
        format!("{:x}", hasher.finalize())
    }

    fn calculate_blake3(&self, content: &[u8]) -> String {
        blake3::hash(content).to_hex().to_string()
    }

    fn detect_encoding(&self, content: &[u8]) -> Option<String> {
        // Basic encoding detection - would use a proper library in real implementation
        if content.is_empty() {
            return Some("empty".to_string());
        }

        // Check for UTF-8 BOM
        if content.starts_with(&[0xEF, 0xBB, 0xBF]) {
            return Some("utf-8-bom".to_string());
        }

        // Check for UTF-16 BOM
        if content.starts_with(&[0xFF, 0xFE]) || content.starts_with(&[0xFE, 0xFF]) {
            return Some("utf-16".to_string());
        }

        // Try to validate as UTF-8
        match std::str::from_utf8(content) {
            Ok(_) => Some("utf-8".to_string()),
            Err(_) => {
                // Check if it looks like ASCII
                if content.iter().all(|&b| b < 128) {
                    Some("ascii".to_string())
                } else {
                    Some("binary".to_string())
                }
            }
        }
    }

    fn detect_language(&self, file_info: &FileInfo, content: &[u8]) -> Option<String> {
        // Language detection based on file extension
        if let Some(extension) = &file_info.extension {
            let language = match extension.as_str() {
                "rs" => "rust",
                "go" => "go",
                "py" => "python",
                "js" | "mjs" => "javascript",
                "ts" => "typescript",
                "java" => "java",
                "c" => "c",
                "cpp" | "cc" | "cxx" => "cpp",
                "h" | "hpp" => "c_header",
                "cs" => "csharp",
                "php" => "php",
                "rb" => "ruby",
                "swift" => "swift",
                "kt" => "kotlin",
                "scala" => "scala",
                "clj" => "clojure",
                "hs" => "haskell",
                "elm" => "elm",
                "lua" => "lua",
                "perl" | "pl" => "perl",
                "r" => "r",
                "sh" | "bash" => "shell",
                "ps1" => "powershell",
                "bat" | "cmd" => "batch",
                "sql" => "sql",
                "html" | "htm" => "html",
                "xml" | "xhtml" => "xml",
                "css" => "css",
                "scss" => "scss",
                "sass" => "sass",
                "less" => "less",
                "json" => "json",
                "yaml" | "yml" => "yaml",
                "toml" => "toml",
                "ini" | "cfg" | "conf" => "ini",
                "md" => "markdown",
                "rst" => "restructuredtext",
                "tex" => "latex",
                _ => return None,
            };
            return Some(language.to_string());
        }

        // Content-based detection for files without extensions
        if let Ok(text) = std::str::from_utf8(content) {
            if text.starts_with("#!/bin/bash") || text.starts_with("#!/bin/sh") {
                return Some("shell".to_string());
            }
            if text.starts_with("#!/usr/bin/env python") || text.starts_with("#!/usr/bin/python") {
                return Some("python".to_string());
            }
            if text.starts_with("<?php") {
                return Some("php".to_string());
            }
            if text.starts_with("<?xml") {
                return Some("xml".to_string());
            }
        }

        None
    }

    fn extract_content_metadata(&self, content: &[u8], file_type: &str) -> ContentMetadata {
        let mut metadata = ContentMetadata::default();

        if let Ok(text) = std::str::from_utf8(content) {
            metadata.line_count = text.lines().count();
            metadata.char_count = text.chars().count();
            metadata.word_count = text.split_whitespace().count();
            
            // Extract basic statistics
            metadata.blank_lines = text.lines().filter(|line| line.trim().is_empty()).count();
            metadata.comment_lines = self.count_comment_lines(text, file_type);
            
            // Check for common patterns
            metadata.contains_urls = self.contains_urls(text);
            metadata.contains_emails = self.contains_emails(text);
            metadata.contains_ip_addresses = self.contains_ip_addresses(text);
            metadata.contains_secrets = self.contains_potential_secrets(text);
        } else {
            // Binary file metadata
            metadata.is_binary = true;
            metadata.entropy = self.calculate_entropy(content);
        }

        metadata.file_size = content.len();
        metadata
    }

    fn count_comment_lines(&self, text: &str, file_type: &str) -> usize {
        let comment_prefixes = match file_type {
            "code" => vec!["//", "#", "/*", "*", "<!--"],
            "config" => vec!["#", ";", "//"],
            _ => vec!["#"],
        };

        text.lines()
            .filter(|line| {
                let trimmed = line.trim();
                comment_prefixes.iter().any(|prefix| trimmed.starts_with(prefix))
            })
            .count()
    }

    fn contains_urls(&self, text: &str) -> bool {
        text.contains("http://") || text.contains("https://") || text.contains("ftp://")
    }

    fn contains_emails(&self, text: &str) -> bool {
        text.contains("@") && text.matches("@").count() < 50 // Basic heuristic
    }

    fn contains_ip_addresses(&self, text: &str) -> bool {
        // Very basic IPv4 detection
        use regex::Regex;
        let ip_regex = Regex::new(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b").unwrap();
        ip_regex.is_match(text)
    }

    fn contains_potential_secrets(&self, text: &str) -> bool {
        let secret_indicators = [
            "password", "passwd", "pwd", "secret", "key", "token", "api_key",
            "access_key", "private_key", "auth", "credential", "bearer",
        ];

        let text_lower = text.to_lowercase();
        secret_indicators.iter().any(|indicator| text_lower.contains(indicator))
    }

    fn calculate_entropy(&self, data: &[u8]) -> f64 {
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

        entropy
    }

    fn classify_content_sensitivity(&self, content: &[u8], metadata: &ContentMetadata) -> Classification {
        if metadata.contains_secrets {
            return Classification::Confidential;
        }

        if let Ok(text) = std::str::from_utf8(content) {
            let sensitive_patterns = [
                "confidential", "secret", "private", "internal",
                "ssn", "social security", "credit card", "passport",
                "private key", "certificate", "password",
            ];

            let text_lower = text.to_lowercase();
            if sensitive_patterns.iter().any(|pattern| text_lower.contains(pattern)) {
                return Classification::Restricted;
            }

            // Check for PII patterns
            if self.contains_pii(text) {
                return Classification::Confidential;
            }
        }

        Classification::Internal
    }

    fn contains_pii(&self, text: &str) -> bool {
        // Basic PII detection - would be more sophisticated in real implementation
        use regex::Regex;
        
        // SSN pattern
        let ssn_regex = Regex::new(r"\b\d{3}-\d{2}-\d{4}\b").unwrap();
        if ssn_regex.is_match(text) {
            return true;
        }

        // Credit card pattern (basic)
        let cc_regex = Regex::new(r"\b\d{4}[- ]?\d{4}[- ]?\d{4}[- ]?\d{4}\b").unwrap();
        if cc_regex.is_match(text) {
            return true;
        }

        false
    }

    async fn analyze_content(&self, content: &[u8], file_info: &FileInfo) -> Result<Vec<ContentFinding>> {
        let mut findings = Vec::new();

        if let Ok(text) = std::str::from_utf8(content) {
            // Look for hardcoded secrets
            if self.contains_potential_secrets(text) {
                findings.push(ContentFinding {
                    finding_type: "potential_secret".to_string(),
                    description: "File contains potential secrets or credentials".to_string(),
                    severity: "medium".to_string(),
                    line_number: None,
                    context: None,
                });
            }

            // Look for suspicious patterns
            if text.to_lowercase().contains("backdoor") || text.to_lowercase().contains("malware") {
                findings.push(ContentFinding {
                    finding_type: "suspicious_content".to_string(),
                    description: "File contains suspicious keywords".to_string(),
                    severity: "high".to_string(),
                    line_number: None,
                    context: None,
                });
            }

            // Look for TODO/FIXME comments in code
            if file_info.file_type == "code" {
                for (line_num, line) in text.lines().enumerate() {
                    let line_lower = line.to_lowercase();
                    if line_lower.contains("todo") || line_lower.contains("fixme") || line_lower.contains("hack") {
                        findings.push(ContentFinding {
                            finding_type: "code_comment".to_string(),
                            description: "Code contains TODO/FIXME comment".to_string(),
                            severity: "low".to_string(),
                            line_number: Some(line_num + 1),
                            context: Some(line.trim().to_string()),
                        });
                    }
                }
            }
        }

        Ok(findings)
    }
}

#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct ContentMetadata {
    pub file_size: usize,
    pub line_count: usize,
    pub char_count: usize,
    pub word_count: usize,
    pub blank_lines: usize,
    pub comment_lines: usize,
    pub is_binary: bool,
    pub entropy: f64,
    pub contains_urls: bool,
    pub contains_emails: bool,
    pub contains_ip_addresses: bool,
    pub contains_secrets: bool,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ContentFinding {
    pub finding_type: String,
    pub description: String,
    pub severity: String,
    pub line_number: Option<usize>,
    pub context: Option<String>,
}

impl FileAnalyzer {
    /// Extract text content from PDF files
    /// TODO: This is a stub implementation - actual PDF extraction disabled due to pdf-extract dependency issues
    fn extract_pdf_text(&self, _content: &[u8]) -> Result<String> {
        // TODO: Re-enable when pdf-extract dependency is available
        // let extracted_text = pdf_extract::extract_text_from_mem(content)?;
        // Ok(extracted_text)
        
        // Stub implementation
        warn!("PDF text extraction is disabled due to dependency issues");
        Ok("PDF content extraction is currently unavailable due to disabled pdf-extract dependency".to_string())
    }

    /// Extract text content from DOCX files  
    /// TODO: This is a stub implementation - actual DOCX extraction disabled due to docx-rs dependency issues
    fn extract_docx_text(&self, _content: &[u8]) -> Result<String> {
        // TODO: Re-enable when docx-rs dependency is available
        // let docx = docx_rs::read_docx(content)?;
        // let text = docx.document.body.extract_text();
        // Ok(text)
        
        // Stub implementation
        warn!("DOCX text extraction is disabled due to dependency issues");
        Ok("DOCX content extraction is currently unavailable due to disabled docx-rs dependency".to_string())
    }

    /// Extract text from office documents based on file type
    /// TODO: This method provides stub implementations for document processing
    fn extract_office_document_text(&self, content: &[u8], file_extension: &str) -> Result<Option<String>> {
        match file_extension.to_lowercase().as_str() {
            "pdf" => {
                let text = self.extract_pdf_text(content)?;
                Ok(Some(text))
            }
            "docx" => {
                let text = self.extract_docx_text(content)?;
                Ok(Some(text))
            }
            "doc" | "xls" | "xlsx" | "ppt" | "pptx" => {
                // TODO: Add support for other office formats when dependencies are available
                warn!("Office document format '{}' extraction is not implemented", file_extension);
                Ok(Some(format!("Extraction for {} files is currently unavailable", file_extension.to_uppercase())))
            }
            _ => Ok(None)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;
    use tokio::fs::write;

    #[tokio::test]
    async fn test_file_type_classification() {
        let analyzer = FileAnalyzer::new(&AnalysisConfig::default()).await.unwrap();
        
        assert_eq!(analyzer.classify_file_type(Path::new("test.rs")), "code");
        assert_eq!(analyzer.classify_file_type(Path::new("README.md")), "document");
        assert_eq!(analyzer.classify_file_type(Path::new("config.yaml")), "config");
        assert_eq!(analyzer.classify_file_type(Path::new("image.png")), "image");
        assert_eq!(analyzer.classify_file_type(Path::new("unknown.xyz")), "unknown");
    }

    #[tokio::test]
    async fn test_binary_detection() {
        let analyzer = FileAnalyzer::new(&AnalysisConfig::default()).await.unwrap();
        
        assert!(analyzer.is_binary_file(Path::new("test.exe")));
        assert!(analyzer.is_binary_file(Path::new("image.png")));
        assert!(!analyzer.is_binary_file(Path::new("script.py")));
        assert!(!analyzer.is_binary_file(Path::new("config.yaml")));
    }

    #[tokio::test]
    async fn test_content_analysis() {
        let analyzer = FileAnalyzer::new(&AnalysisConfig::default()).await.unwrap();
        
        let content = b"password = 'secret123'\n// TODO: fix this hack\nprint('hello world')";
        let file_info = FileInfo {
            path: "test.py".to_string(),
            relative_path: "test.py".to_string(),
            size_bytes: content.len() as u64,
            modified_at: Utc::now(),
            file_type: "code".to_string(),
            mime_type: Some("text/x-python".to_string()),
            extension: Some("py".to_string()),
            is_binary: false,
            is_executable: false,
            permissions: None,
        };

        let findings = analyzer.analyze_content(content, &file_info).await.unwrap();
        
        assert!(!findings.is_empty());
        assert!(findings.iter().any(|f| f.finding_type == "potential_secret"));
        assert!(findings.iter().any(|f| f.finding_type == "code_comment"));
    }

    #[tokio::test]
    async fn test_file_discovery() {
        let temp_dir = tempdir().unwrap();
        let temp_path = temp_dir.path();

        // Create test files
        write(temp_path.join("test.py"), "print('hello')").await.unwrap();
        write(temp_path.join("config.yaml"), "key: value").await.unwrap();
        write(temp_path.join("README.md"), "# Test").await.unwrap();

        let analyzer = FileAnalyzer::new(&AnalysisConfig::default()).await.unwrap();
        let files = analyzer.discover_files(&temp_path.to_string_lossy()).await.unwrap();

        assert_eq!(files.len(), 3);
        assert!(files.iter().any(|f| f.relative_path == "test.py"));
        assert!(files.iter().any(|f| f.relative_path == "config.yaml"));
        assert!(files.iter().any(|f| f.relative_path == "README.md"));
    }
}