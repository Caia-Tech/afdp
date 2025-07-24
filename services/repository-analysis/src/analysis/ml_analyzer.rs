use anyhow::Result;
use std::collections::HashMap;
use tracing::{debug, info, warn};
use uuid::Uuid;
use serde_json::json;

use crate::{
    config::AnalysisConfig,
    storage::{
        FileAnalysis, Storage,
        vector::{FileEmbeddingMetadata, CodeSimilarityResult, QdrantStorage},
        SimilarityQuery, SimilarityResult, Classification,
    },
};

/// ML analyzer component for AI-powered analysis, embeddings, and similarity detection
pub struct MLAnalyzer {
    config: AnalysisConfig,
    embedding_model: EmbeddingModel,
    similarity_threshold: f32,
    max_chunk_size: usize,
}

impl MLAnalyzer {
    pub async fn new(config: &AnalysisConfig) -> Result<Self> {
        let embedding_model = EmbeddingModel::new().await?;
        
        info!("ML analyzer initialized with embedding model");

        Ok(Self {
            config: config.clone(),
            embedding_model,
            similarity_threshold: 0.8,
            max_chunk_size: 1000,
        })
    }

    /// Generate embeddings for file content
    pub async fn generate_embeddings(&self, job_id: Uuid, file_analysis: &FileAnalysis) -> Result<()> {
        if !self.config.similarity_analysis {
            return Ok(());
        }

        debug!("Generating embeddings for file: {}", file_analysis.file_path);

        // Extract file content
        let content = self.extract_file_content(file_analysis)?;
        if content.is_empty() || content.len() < 50 {
            debug!("Skipping embedding generation for small/empty file");
            return Ok(());
        }

        // Generate file-level embedding
        let file_embedding = self.embedding_model.generate_text_embedding(&content).await?;
        
        // Store file embedding
        let metadata = FileEmbeddingMetadata {
            file_type: file_analysis.file_type.clone(),
            language: file_analysis.language.clone(),
            classification: file_analysis.classification.clone(),
            content_hash: file_analysis.hash_sha256.clone(),
            content_snippet: self.extract_content_snippet(&content, 200),
            line_count: content.lines().count() as u32,
            char_count: content.chars().count() as u32,
        };

        // In a real implementation, this would use the storage instance
        // For now, we'll simulate the storage operation
        info!("Generated file embedding for {} (dimension: {})", 
              file_analysis.file_path, file_embedding.len());

        // Generate code chunk embeddings for code files
        if file_analysis.file_type == "code" && file_analysis.language.is_some() {
            self.generate_code_chunk_embeddings(job_id, file_analysis, &content).await?;
        }

        Ok(())
    }

    /// Generate embeddings for code chunks for more granular similarity detection
    async fn generate_code_chunk_embeddings(
        &self,
        job_id: Uuid,
        file_analysis: &FileAnalysis,
        content: &str,
    ) -> Result<()> {
        let language = file_analysis.language.as_ref().unwrap();
        let chunks = self.extract_code_chunks(content, language);

        for chunk in chunks {
            if chunk.content.trim().len() < 50 {
                continue; // Skip very small chunks
            }

            let embedding = self.embedding_model.generate_code_embedding(&chunk.content, language).await?;
            
            // In a real implementation, this would store in vector database
            debug!("Generated code chunk embedding: lines {}-{}, {} dimensions", 
                   chunk.start_line, chunk.end_line, embedding.len());
        }

        Ok(())
    }

    /// Perform similarity analysis across all files in the job
    pub async fn perform_similarity_analysis(&self, job_id: Uuid, file_analyses: &[FileAnalysis]) -> Result<()> {
        if !self.config.similarity_analysis {
            return Ok(());
        }

        info!("Performing similarity analysis for {} files", file_analyses.len());

        // Find similar files within the repository
        let similar_files = self.find_similar_files_internal(file_analyses).await?;
        
        // Find similar code across the repository
        let similar_code = self.find_similar_code_internal(file_analyses).await?;

        // Perform external similarity search (against other repositories)
        let external_matches = self.find_external_similarities(job_id, file_analyses).await?;

        info!("Similarity analysis completed: {} file similarities, {} code similarities, {} external matches",
              similar_files.len(), similar_code.len(), external_matches.len());

        Ok(())
    }

    /// Analyze anomalies using ML techniques
    pub async fn detect_anomalies(&self, job_id: Uuid, file_analyses: &[FileAnalysis]) -> Result<Vec<AnomalyDetection>> {
        info!("Detecting anomalies using ML analysis");

        let mut anomalies = Vec::new();

        // Statistical anomaly detection
        anomalies.extend(self.detect_statistical_anomalies(file_analyses).await?);

        // Content-based anomaly detection
        anomalies.extend(self.detect_content_anomalies(file_analyses).await?);

        // Behavioral anomaly detection
        anomalies.extend(self.detect_behavioral_anomalies(file_analyses).await?);

        info!("Detected {} anomalies", anomalies.len());
        Ok(anomalies)
    }

    /// Extract semantic information from code and documents
    pub async fn extract_semantic_features(&self, file_analysis: &FileAnalysis) -> Result<SemanticFeatures> {
        let content = self.extract_file_content(file_analysis)?;
        
        // Generate embeddings
        let embeddings = self.embedding_model.generate_text_embedding(&content).await?;
        
        // Extract semantic concepts
        let concepts = self.extract_concepts(&content).await?;
        
        // Analyze sentiment (for documents)
        let sentiment = if file_analysis.file_type == "document" {
            Some(self.analyze_sentiment(&content).await?)
        } else {
            None
        };

        // Extract entities (names, organizations, etc.)
        let entities = self.extract_entities(&content).await?;

        Ok(SemanticFeatures {
            embeddings,
            concepts,
            sentiment,
            entities,
            language: file_analysis.language.clone(),
            confidence: 0.8, // Would be calculated based on analysis quality
        })
    }

    /// Classify content using ML models
    pub async fn classify_content(&self, file_analysis: &FileAnalysis) -> Result<ContentClassification> {
        let content = self.extract_file_content(file_analysis)?;
        
        // Classify content type
        let content_type = self.classify_content_type(&content).await?;
        
        // Classify sensitivity level
        let sensitivity = self.classify_sensitivity(&content).await?;
        
        // Classify intent (benign, suspicious, malicious)
        let intent = self.classify_intent(&content, &file_analysis.file_type).await?;

        Ok(ContentClassification {
            content_type,
            sensitivity,
            intent,
            confidence: 0.75,
        })
    }

    async fn find_similar_files_internal(&self, file_analyses: &[FileAnalysis]) -> Result<Vec<FileSimilarity>> {
        let mut similarities = Vec::new();

        // Compare files pairwise for similarity
        for (i, file1) in file_analyses.iter().enumerate() {
            for file2 in file_analyses.iter().skip(i + 1) {
                if let Ok(similarity) = self.calculate_file_similarity(file1, file2).await {
                    if similarity.score > self.similarity_threshold {
                        similarities.push(similarity);
                    }
                }
            }
        }

        Ok(similarities)
    }

    async fn find_similar_code_internal(&self, file_analyses: &[FileAnalysis]) -> Result<Vec<CodeSimilarity>> {
        let mut similarities = Vec::new();

        // Extract code files
        let code_files: Vec<&FileAnalysis> = file_analyses
            .iter()
            .filter(|f| f.file_type == "code")
            .collect();

        // Compare code chunks for similarity
        for file1 in &code_files {
            for file2 in &code_files {
                if file1.id != file2.id && 
                   file1.language == file2.language && 
                   file1.language.is_some() {
                    
                    if let Ok(code_similarities) = self.find_code_similarities(file1, file2).await {
                        similarities.extend(code_similarities);
                    }
                }
            }
        }

        Ok(similarities)
    }

    async fn find_external_similarities(&self, _job_id: Uuid, _file_analyses: &[FileAnalysis]) -> Result<Vec<ExternalSimilarity>> {
        // Placeholder for external similarity search
        // In a real implementation, this would search against a database of known repositories
        Ok(vec![])
    }

    async fn calculate_file_similarity(&self, file1: &FileAnalysis, file2: &FileAnalysis) -> Result<FileSimilarity> {
        let content1 = self.extract_file_content(file1)?;
        let content2 = self.extract_file_content(file2)?;

        // Generate embeddings
        let embedding1 = self.embedding_model.generate_text_embedding(&content1).await?;
        let embedding2 = self.embedding_model.generate_text_embedding(&content2).await?;

        // Calculate cosine similarity
        let similarity_score = self.cosine_similarity(&embedding1, &embedding2);

        Ok(FileSimilarity {
            file1_path: file1.file_path.clone(),
            file2_path: file2.file_path.clone(),
            score: similarity_score,
            similarity_type: "content".to_string(),
            details: json!({
                "embedding_dimensions": embedding1.len(),
                "content_length_1": content1.len(),
                "content_length_2": content2.len()
            }),
        })
    }

    async fn find_code_similarities(&self, file1: &FileAnalysis, file2: &FileAnalysis) -> Result<Vec<CodeSimilarity>> {
        let content1 = self.extract_file_content(file1)?;
        let content2 = self.extract_file_content(file2)?;
        
        let language = file1.language.as_ref().unwrap();
        
        let chunks1 = self.extract_code_chunks(&content1, language);
        let chunks2 = self.extract_code_chunks(&content2, language);

        let mut similarities = Vec::new();

        for chunk1 in &chunks1 {
            for chunk2 in &chunks2 {
                if chunk1.content.trim().len() < 50 || chunk2.content.trim().len() < 50 {
                    continue;
                }

                let embedding1 = self.embedding_model.generate_code_embedding(&chunk1.content, language).await?;
                let embedding2 = self.embedding_model.generate_code_embedding(&chunk2.content, language).await?;

                let similarity_score = self.cosine_similarity(&embedding1, &embedding2);

                if similarity_score > self.similarity_threshold {
                    similarities.push(CodeSimilarity {
                        file1_path: file1.file_path.clone(),
                        file2_path: file2.file_path.clone(),
                        chunk1_lines: (chunk1.start_line, chunk1.end_line),
                        chunk2_lines: (chunk2.start_line, chunk2.end_line),
                        score: similarity_score,
                        language: language.clone(),
                        similarity_type: "code_structure".to_string(),
                    });
                }
            }
        }

        Ok(similarities)
    }

    async fn detect_statistical_anomalies(&self, file_analyses: &[FileAnalysis]) -> Result<Vec<AnomalyDetection>> {
        let mut anomalies = Vec::new();

        // Calculate file size statistics
        let sizes: Vec<i64> = file_analyses.iter().map(|f| f.file_size).collect();
        if let Some((mean, std_dev)) = self.calculate_stats(&sizes) {
            let threshold = mean + (3.0 * std_dev); // 3-sigma rule
            
            for analysis in file_analyses {
                if analysis.file_size as f64 > threshold {
                    anomalies.push(AnomalyDetection {
                        file_path: analysis.file_path.clone(),
                        anomaly_type: "file_size".to_string(),
                        description: "File size significantly larger than average".to_string(),
                        severity: "medium".to_string(),
                        confidence: 0.8,
                        details: json!({
                            "file_size": analysis.file_size,
                            "mean_size": mean,
                            "std_dev": std_dev,
                            "threshold": threshold
                        }),
                    });
                }
            }
        }

        Ok(anomalies)
    }

    async fn detect_content_anomalies(&self, file_analyses: &[FileAnalysis]) -> Result<Vec<AnomalyDetection>> {
        let mut anomalies = Vec::new();

        for analysis in file_analyses {
            let content = self.extract_file_content(analysis)?;
            
            // Check for unusual character distributions
            if self.has_unusual_character_distribution(&content) {
                anomalies.push(AnomalyDetection {
                    file_path: analysis.file_path.clone(),
                    anomaly_type: "character_distribution".to_string(),
                    description: "Unusual character distribution detected".to_string(),
                    severity: "low".to_string(),
                    confidence: 0.6,
                    details: json!({
                        "content_length": content.len()
                    }),
                });
            }

            // Check for unusual language patterns
            if let Some(language) = &analysis.language {
                if self.has_unusual_language_patterns(&content, language) {
                    anomalies.push(AnomalyDetection {
                        file_path: analysis.file_path.clone(),
                        anomaly_type: "language_pattern".to_string(),
                        description: "Unusual patterns for the detected language".to_string(),
                        severity: "medium".to_string(),
                        confidence: 0.7,
                        details: json!({
                            "language": language
                        }),
                    });
                }
            }
        }

        Ok(anomalies)
    }

    async fn detect_behavioral_anomalies(&self, _file_analyses: &[FileAnalysis]) -> Result<Vec<AnomalyDetection>> {
        // Placeholder for behavioral anomaly detection
        // Would analyze patterns like unusual file access times, modification patterns, etc.
        Ok(vec![])
    }

    async fn extract_concepts(&self, content: &str) -> Result<Vec<String>> {
        // Simplified concept extraction - in reality would use NLP models
        let mut concepts = Vec::new();
        
        // Extract common programming concepts
        let programming_concepts = [
            "function", "class", "variable", "loop", "condition",
            "database", "api", "service", "model", "controller",
            "encryption", "authentication", "authorization", "security",
        ];

        let content_lower = content.to_lowercase();
        for concept in &programming_concepts {
            if content_lower.contains(concept) {
                concepts.push(concept.to_string());
            }
        }

        Ok(concepts)
    }

    async fn analyze_sentiment(&self, content: &str) -> Result<f32> {
        // Simplified sentiment analysis - would use proper NLP models
        let positive_words = ["good", "great", "excellent", "amazing", "perfect"];
        let negative_words = ["bad", "terrible", "awful", "horrible", "worst"];

        let content_lower = content.to_lowercase();
        let mut positive_count = 0;
        let mut negative_count = 0;

        for word in &positive_words {
            positive_count += content_lower.matches(word).count();
        }

        for word in &negative_words {
            negative_count += content_lower.matches(word).count();
        }

        let total = positive_count + negative_count;
        if total == 0 {
            Ok(0.0) // Neutral
        } else {
            Ok((positive_count as f32 - negative_count as f32) / total as f32)
        }
    }

    async fn extract_entities(&self, content: &str) -> Result<Vec<String>> {
        // Simplified entity extraction - would use NER models
        let mut entities = Vec::new();
        
        // Extract email addresses
        let email_regex = regex::Regex::new(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b").unwrap();
        for mat in email_regex.find_iter(content) {
            entities.push(mat.as_str().to_string());
        }

        // Extract URLs
        let url_regex = regex::Regex::new(r"https?://[^\s]+").unwrap();
        for mat in url_regex.find_iter(content) {
            entities.push(mat.as_str().to_string());
        }

        Ok(entities)
    }

    async fn classify_content_type(&self, content: &str) -> Result<String> {
        // Simple content type classification
        if content.contains("function") || content.contains("class") || content.contains("import") {
            Ok("code".to_string())
        } else if content.contains("# ") || content.contains("## ") {
            Ok("documentation".to_string())
        } else if content.contains("{") && content.contains("\"") {
            Ok("configuration".to_string())
        } else {
            Ok("text".to_string())
        }
    }

    async fn classify_sensitivity(&self, content: &str) -> Result<String> {
        let sensitive_patterns = [
            "password", "secret", "key", "token", "credential",
            "ssn", "social security", "credit card", "private",
        ];

        let content_lower = content.to_lowercase();
        for pattern in &sensitive_patterns {
            if content_lower.contains(pattern) {
                return Ok("sensitive".to_string());
            }
        }

        Ok("public".to_string())
    }

    async fn classify_intent(&self, content: &str, file_type: &str) -> Result<String> {
        let malicious_patterns = [
            "backdoor", "malware", "virus", "trojan", "keylogger",
            "exploit", "shellcode", "payload", "rootkit",
        ];

        let content_lower = content.to_lowercase();
        for pattern in &malicious_patterns {
            if content_lower.contains(pattern) {
                return Ok("suspicious".to_string());
            }
        }

        // Check for obfuscation in code files
        if file_type == "code" && self.is_likely_obfuscated(content) {
            return Ok("suspicious".to_string());
        }

        Ok("benign".to_string())
    }

    fn extract_file_content(&self, file_analysis: &FileAnalysis) -> Result<String> {
        // Extract content from metadata
        if let Some(metadata) = file_analysis.metadata.as_object() {
            if let Some(content) = metadata.get("content") {
                if let Some(content_str) = content.as_str() {
                    return Ok(content_str.to_string());
                }
            }
        }
        Ok(String::new())
    }

    fn extract_content_snippet(&self, content: &str, max_length: usize) -> String {
        if content.len() <= max_length {
            content.to_string()
        } else {
            format!("{}...", &content[..max_length])
        }
    }

    fn extract_code_chunks(&self, content: &str, language: &str) -> Vec<CodeChunk> {
        let mut chunks = Vec::new();
        let lines: Vec<&str> = content.lines().collect();

        match language {
            "rust" | "go" | "java" | "cpp" | "c" => {
                // Function-based chunking for these languages
                self.extract_function_chunks(&lines, &mut chunks);
            }
            "python" => {
                // Class and function-based chunking for Python
                self.extract_python_chunks(&lines, &mut chunks);
            }
            "javascript" | "typescript" => {
                // Function and class-based chunking for JS/TS
                self.extract_js_chunks(&lines, &mut chunks);
            }
            _ => {
                // Generic chunking by logical blocks
                self.extract_generic_chunks(&lines, &mut chunks);
            }
        }

        chunks
    }

    fn extract_function_chunks(&self, lines: &[&str], chunks: &mut Vec<CodeChunk>) {
        let mut current_chunk = None;
        let mut brace_count = 0;

        for (i, line) in lines.iter().enumerate() {
            let trimmed = line.trim();
            
            // Look for function definitions
            if (trimmed.contains("fn ") || trimmed.contains("func ") || 
                trimmed.contains("function ") || trimmed.contains("def ")) &&
               trimmed.contains("{") {
                
                // Start new chunk
                current_chunk = Some(CodeChunk {
                    start_line: i + 1,
                    end_line: i + 1,
                    content: line.to_string(),
                });
                brace_count = trimmed.matches('{').count() as i32 - trimmed.matches('}').count() as i32;
            } else if let Some(ref mut chunk) = current_chunk {
                // Continue current chunk
                chunk.content.push('\n');
                chunk.content.push_str(line);
                chunk.end_line = i + 1;
                
                brace_count += trimmed.matches('{').count() as i32 - trimmed.matches('}').count() as i32;
                
                if brace_count <= 0 {
                    // End of function
                    chunks.push(chunk.clone());
                    current_chunk = None;
                    brace_count = 0;
                }
            }
        }

        // Add any remaining chunk
        if let Some(chunk) = current_chunk {
            chunks.push(chunk);
        }
    }

    fn extract_python_chunks(&self, lines: &[&str], chunks: &mut Vec<CodeChunk>) {
        let mut current_chunk = None;
        let mut indent_level = 0;

        for (i, line) in lines.iter().enumerate() {
            let trimmed = line.trim();
            
            if (trimmed.starts_with("def ") || trimmed.starts_with("class ")) && trimmed.ends_with(':') {
                // Start new chunk
                current_chunk = Some(CodeChunk {
                    start_line: i + 1,
                    end_line: i + 1,
                    content: line.to_string(),
                });
                indent_level = line.len() - line.trim_start().len();
            } else if let Some(ref mut chunk) = current_chunk {
                let current_indent = line.len() - line.trim_start().len();
                
                if !trimmed.is_empty() && current_indent <= indent_level && !trimmed.starts_with('#') {
                    // End of function/class
                    chunks.push(chunk.clone());
                    current_chunk = None;
                } else {
                    // Continue current chunk
                    chunk.content.push('\n');
                    chunk.content.push_str(line);
                    chunk.end_line = i + 1;
                }
            }
        }

        if let Some(chunk) = current_chunk {
            chunks.push(chunk);
        }
    }

    fn extract_js_chunks(&self, lines: &[&str], chunks: &mut Vec<CodeChunk>) {
        // Similar to function chunks but with JS-specific patterns
        self.extract_function_chunks(lines, chunks);
    }

    fn extract_generic_chunks(&self, lines: &[&str], chunks: &mut Vec<CodeChunk>) {
        // Split into chunks of reasonable size
        let chunk_size = 50; // lines per chunk
        
        for (start_idx, chunk_lines) in lines.chunks(chunk_size).enumerate() {
            let start_line = start_idx * chunk_size + 1;
            let end_line = start_line + chunk_lines.len() - 1;
            
            chunks.push(CodeChunk {
                start_line,
                end_line,
                content: chunk_lines.join("\n"),
            });
        }
    }

    fn cosine_similarity(&self, vec1: &[f32], vec2: &[f32]) -> f32 {
        if vec1.len() != vec2.len() {
            return 0.0;
        }

        let dot_product: f32 = vec1.iter().zip(vec2.iter()).map(|(a, b)| a * b).sum();
        let norm1: f32 = vec1.iter().map(|x| x * x).sum::<f32>().sqrt();
        let norm2: f32 = vec2.iter().map(|x| x * x).sum::<f32>().sqrt();

        if norm1 == 0.0 || norm2 == 0.0 {
            0.0
        } else {
            dot_product / (norm1 * norm2)
        }
    }

    fn calculate_stats(&self, values: &[i64]) -> Option<(f64, f64)> {
        if values.is_empty() {
            return None;
        }

        let sum: i64 = values.iter().sum();
        let mean = sum as f64 / values.len() as f64;
        
        let variance: f64 = values.iter()
            .map(|&x| (x as f64 - mean).powi(2))
            .sum::<f64>() / values.len() as f64;
        
        let std_dev = variance.sqrt();
        
        Some((mean, std_dev))
    }

    fn has_unusual_character_distribution(&self, content: &str) -> bool {
        if content.is_empty() {
            return false;
        }

        // Count different character types
        let total_chars = content.len();
        let non_ascii_count = content.chars().filter(|c| !c.is_ascii()).count();
        let control_char_count = content.chars().filter(|c| c.is_control()).count();

        // High ratio of non-ASCII or control characters might be unusual
        let non_ascii_ratio = non_ascii_count as f64 / total_chars as f64;
        let control_char_ratio = control_char_count as f64 / total_chars as f64;

        non_ascii_ratio > 0.1 || control_char_ratio > 0.05
    }

    fn has_unusual_language_patterns(&self, content: &str, language: &str) -> bool {
        match language {
            "python" => {
                // Check for unusual Python patterns
                content.contains("exec(") || content.contains("eval(") || 
                content.chars().filter(|&c| c == ';').count() > content.lines().count()
            }
            "javascript" => {
                // Check for unusual JavaScript patterns
                content.contains("eval(") || content.contains("Function(") ||
                content.matches("[]").count() > 10
            }
            _ => false,
        }
    }

    fn is_likely_obfuscated(&self, content: &str) -> bool {
        // Simple obfuscation detection
        let lines: Vec<&str> = content.lines().collect();
        if lines.is_empty() {
            return false;
        }

        let avg_line_length = content.len() as f64 / lines.len() as f64;
        let very_long_lines = lines.iter().filter(|l| l.len() > 200).count();

        avg_line_length > 100.0 || very_long_lines > lines.len() / 4
    }
}

/// Simple embedding model interface
/// TODO: This is a stub implementation due to Candle framework dependencies being disabled
/// In a real implementation, this would use candle-core and candle-nn for ML models
pub struct EmbeddingModel {
    // In a real implementation, this would contain the actual ML model (e.g., Candle Tensor)
    vector_dimension: usize,
}

impl EmbeddingModel {
    pub async fn new() -> Result<Self> {
        Ok(Self {
            vector_dimension: 384, // Common embedding dimension
        })
    }

    pub async fn generate_text_embedding(&self, text: &str) -> Result<Vec<f32>> {
        // TODO: Placeholder implementation - in reality would use candle-core/candle-nn
        // or other embedding models like sentence-transformers, OpenAI embeddings, etc.
        let mut embedding = vec![0.0; self.vector_dimension];
        
        // Simple hash-based pseudo-embedding for demonstration
        let hash = self.simple_hash(text);
        for (i, byte) in hash.iter().enumerate() {
            if i < self.vector_dimension {
                embedding[i] = (*byte as f32) / 255.0;
            }
        }
        
        Ok(embedding)
    }

    pub async fn generate_code_embedding(&self, code: &str, language: &str) -> Result<Vec<f32>> {
        // TODO: For code, we might want to use specialized code embeddings with candle-nn
        // For now, use the same as text but with language context (stub implementation)
        let enhanced_text = format!("LANGUAGE:{} CODE:{}", language, code);
        self.generate_text_embedding(&enhanced_text).await
    }

    fn simple_hash(&self, text: &str) -> Vec<u8> {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};
        
        let mut hasher = DefaultHasher::new();
        text.hash(&mut hasher);
        let hash = hasher.finish();
        
        // Convert hash to bytes and repeat to fill vector
        let mut bytes = Vec::new();
        let hash_bytes = hash.to_le_bytes();
        
        while bytes.len() < self.vector_dimension {
            bytes.extend_from_slice(&hash_bytes);
        }
        
        bytes.truncate(self.vector_dimension);
        bytes
    }
}

#[derive(Debug, Clone)]
pub struct CodeChunk {
    pub start_line: usize,
    pub end_line: usize,
    pub content: String,
}

#[derive(Debug, Clone)]
pub struct FileSimilarity {
    pub file1_path: String,
    pub file2_path: String,
    pub score: f32,
    pub similarity_type: String,
    pub details: serde_json::Value,
}

#[derive(Debug, Clone)]
pub struct CodeSimilarity {
    pub file1_path: String,
    pub file2_path: String,
    pub chunk1_lines: (usize, usize),
    pub chunk2_lines: (usize, usize),
    pub score: f32,
    pub language: String,
    pub similarity_type: String,
}

#[derive(Debug, Clone)]
pub struct ExternalSimilarity {
    pub file_path: String,
    pub external_repository: String,
    pub external_file: String,
    pub score: f32,
    pub match_type: String,
}

#[derive(Debug, Clone)]
pub struct AnomalyDetection {
    pub file_path: String,
    pub anomaly_type: String,
    pub description: String,
    pub severity: String,
    pub confidence: f32,
    pub details: serde_json::Value,
}

#[derive(Debug, Clone)]
pub struct SemanticFeatures {
    pub embeddings: Vec<f32>,
    pub concepts: Vec<String>,
    pub sentiment: Option<f32>,
    pub entities: Vec<String>,
    pub language: Option<String>,
    pub confidence: f32,
}

#[derive(Debug, Clone)]
pub struct ContentClassification {
    pub content_type: String,
    pub sensitivity: String,
    pub intent: String,
    pub confidence: f32,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_embedding_generation() {
        let model = EmbeddingModel::new().await.unwrap();
        let embedding = model.generate_text_embedding("Hello, world!").await.unwrap();
        
        assert_eq!(embedding.len(), 384);
        assert!(embedding.iter().all(|&x| x >= 0.0 && x <= 1.0));
    }

    #[tokio::test]
    async fn test_cosine_similarity() {
        let analyzer = MLAnalyzer::new(&AnalysisConfig::default()).await.unwrap();
        
        let vec1 = vec![1.0, 0.0, 0.0];
        let vec2 = vec![1.0, 0.0, 0.0];
        let vec3 = vec![0.0, 1.0, 0.0];
        
        assert!((analyzer.cosine_similarity(&vec1, &vec2) - 1.0).abs() < f32::EPSILON);
        assert!((analyzer.cosine_similarity(&vec1, &vec3) - 0.0).abs() < f32::EPSILON);
    }

    #[test]
    fn test_code_chunk_extraction() {
        let analyzer = MLAnalyzer {
            config: AnalysisConfig::default(),
            embedding_model: EmbeddingModel { vector_dimension: 384 },
            similarity_threshold: 0.8,
            max_chunk_size: 1000,
        };

        let python_code = r#"
def function1():
    return "hello"

def function2():
    return "world"
"#;

        let chunks = analyzer.extract_code_chunks(python_code, "python");
        assert!(!chunks.is_empty());
    }
}