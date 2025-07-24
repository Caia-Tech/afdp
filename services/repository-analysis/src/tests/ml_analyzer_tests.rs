use super::*;
use crate::analysis::ml_analyzer::{MLAnalyzer, EmbeddingModel, SemanticFeatures, ContentClassification};

#[tokio::test]
async fn test_embedding_generation() {
    let analyzer = MLAnalyzer::new(&AnalysisConfig::default()).await.unwrap();
    let job_id = Uuid::new_v4();
    
    let file_analysis = FileAnalysis {
        id: Uuid::new_v4(),
        job_id,
        file_path: "test.py".to_string(),
        file_type: "code".to_string(),
        file_size: 1024,
        mime_type: Some("text/x-python".to_string()),
        language: Some("python".to_string()),
        encoding: Some("utf-8".to_string()),
        hash_sha256: "test".to_string(),
        hash_blake3: "test".to_string(),
        classification: Classification::Internal,
        findings: serde_json::json!([]),
        metadata: serde_json::json!({
            "content": "def hello_world():\n    print('Hello, World!')"
        }),
        processed_at: Utc::now(),
        processing_time_ms: 100,
    };
    
    // This should complete without errors
    analyzer.generate_embeddings(job_id, &file_analysis).await.unwrap();
}

#[tokio::test]
async fn test_cosine_similarity() {
    let analyzer = MLAnalyzer::new(&AnalysisConfig::default()).await.unwrap();
    
    // Test identical vectors
    let vec1 = vec![1.0, 0.0, 0.0];
    let vec2 = vec![1.0, 0.0, 0.0];
    let similarity = analyzer.cosine_similarity(&vec1, &vec2);
    assert!((similarity - 1.0).abs() < f32::EPSILON);
    
    // Test orthogonal vectors
    let vec3 = vec![0.0, 1.0, 0.0];
    let similarity = analyzer.cosine_similarity(&vec1, &vec3);
    assert!((similarity - 0.0).abs() < f32::EPSILON);
    
    // Test opposite vectors
    let vec4 = vec![-1.0, 0.0, 0.0];
    let similarity = analyzer.cosine_similarity(&vec1, &vec4);
    assert!((similarity - -1.0).abs() < f32::EPSILON);
    
    // Test different length vectors
    let vec5 = vec![1.0, 0.0];
    let similarity = analyzer.cosine_similarity(&vec1, &vec5);
    assert_eq!(similarity, 0.0);
}

#[tokio::test]
async fn test_code_chunk_extraction() {
    let analyzer = MLAnalyzer::new(&AnalysisConfig::default()).await.unwrap();
    
    // Test Rust code chunking
    let rust_code = r#"
fn function1() {
    println!("Function 1");
}

fn function2() {
    println!("Function 2");
}
"#;
    
    let chunks = analyzer.extract_code_chunks(rust_code, "rust");
    assert_eq!(chunks.len(), 2);
    assert!(chunks[0].content.contains("function1"));
    assert!(chunks[1].content.contains("function2"));
    
    // Test Python code chunking
    let python_code = r#"
def function1():
    print("Function 1")
    return 1

def function2():
    print("Function 2")
    return 2

class MyClass:
    def method1(self):
        pass
"#;
    
    let chunks = analyzer.extract_code_chunks(python_code, "python");
    assert!(chunks.len() >= 3);
    assert!(chunks.iter().any(|c| c.content.contains("function1")));
    assert!(chunks.iter().any(|c| c.content.contains("function2")));
    assert!(chunks.iter().any(|c| c.content.contains("MyClass")));
}

#[tokio::test]
async fn test_anomaly_detection() {
    let analyzer = MLAnalyzer::new(&AnalysisConfig::default()).await.unwrap();
    let job_id = Uuid::new_v4();
    
    let mut file_analyses = vec![];
    
    // Normal files
    for i in 0..10 {
        file_analyses.push(FileAnalysis {
            id: Uuid::new_v4(),
            job_id,
            file_path: format!("normal{}.txt", i),
            file_type: "text".to_string(),
            file_size: 1024, // Normal size
            mime_type: Some("text/plain".to_string()),
            language: None,
            encoding: Some("utf-8".to_string()),
            hash_sha256: format!("hash{}", i),
            hash_blake3: format!("blake{}", i),
            classification: Classification::Public,
            findings: serde_json::json!([]),
            metadata: serde_json::json!({
                "content": "Normal file content"
            }),
            processed_at: Utc::now(),
            processing_time_ms: 100,
        });
    }
    
    // Anomalous file (very large)
    file_analyses.push(FileAnalysis {
        id: Uuid::new_v4(),
        job_id,
        file_path: "anomaly.txt".to_string(),
        file_type: "text".to_string(),
        file_size: 1024 * 1024 * 100, // 100MB - anomalous
        mime_type: Some("text/plain".to_string()),
        language: None,
        encoding: Some("utf-8".to_string()),
        hash_sha256: "anomaly_hash".to_string(),
        hash_blake3: "anomaly_blake".to_string(),
        classification: Classification::Public,
        findings: serde_json::json!([]),
        metadata: serde_json::json!({
            "content": "Anomalous content"
        }),
        processed_at: Utc::now(),
        processing_time_ms: 100,
    });
    
    let anomalies = analyzer.detect_anomalies(job_id, &file_analyses).await.unwrap();
    
    // Should detect the anomalous file
    assert!(!anomalies.is_empty());
    let size_anomaly = anomalies.iter().find(|a| a.anomaly_type == "file_size");
    assert!(size_anomaly.is_some());
    assert_eq!(size_anomaly.unwrap().file_path, "anomaly.txt");
}

#[tokio::test]
async fn test_semantic_feature_extraction() {
    let analyzer = MLAnalyzer::new(&AnalysisConfig::default()).await.unwrap();
    
    let file_analysis = FileAnalysis {
        id: Uuid::new_v4(),
        job_id: Uuid::new_v4(),
        file_path: "test.py".to_string(),
        file_type: "code".to_string(),
        file_size: 1024,
        mime_type: Some("text/x-python".to_string()),
        language: Some("python".to_string()),
        encoding: Some("utf-8".to_string()),
        hash_sha256: "test".to_string(),
        hash_blake3: "test".to_string(),
        classification: Classification::Internal,
        findings: serde_json::json!([]),
        metadata: serde_json::json!({
            "content": r#"
class DatabaseConnection:
    def __init__(self):
        self.connection = None
    
    def connect(self):
        # Connect to database
        pass
    
    def authenticate(self, user, password):
        # Authentication logic
        pass

# Send email to user@example.com
# Visit https://example.com for more info
"#
        }),
        processed_at: Utc::now(),
        processing_time_ms: 100,
    };
    
    let features = analyzer.extract_semantic_features(&file_analysis).await.unwrap();
    
    // Check embeddings
    assert_eq!(features.embeddings.len(), 384);
    
    // Check concepts
    assert!(features.concepts.contains(&"class".to_string()));
    assert!(features.concepts.contains(&"database".to_string()));
    assert!(features.concepts.contains(&"authentication".to_string()));
    
    // Check entities
    assert!(features.entities.iter().any(|e| e.contains("@example.com")));
    assert!(features.entities.iter().any(|e| e.contains("https://example.com")));
    
    assert_eq!(features.language, Some("python".to_string()));
}

#[tokio::test]
async fn test_content_classification() {
    let analyzer = MLAnalyzer::new(&AnalysisConfig::default()).await.unwrap();
    
    // Test code classification
    let code_analysis = FileAnalysis {
        id: Uuid::new_v4(),
        job_id: Uuid::new_v4(),
        file_path: "code.py".to_string(),
        file_type: "code".to_string(),
        file_size: 1024,
        mime_type: Some("text/x-python".to_string()),
        language: Some("python".to_string()),
        encoding: Some("utf-8".to_string()),
        hash_sha256: "test".to_string(),
        hash_blake3: "test".to_string(),
        classification: Classification::Internal,
        findings: serde_json::json!([]),
        metadata: serde_json::json!({
            "content": "def main():\n    import os\n    print('Hello')"
        }),
        processed_at: Utc::now(),
        processing_time_ms: 100,
    };
    
    let classification = analyzer.classify_content(&code_analysis).await.unwrap();
    assert_eq!(classification.content_type, "code");
    assert_eq!(classification.intent, "benign");
    
    // Test sensitive content
    let sensitive_analysis = FileAnalysis {
        id: Uuid::new_v4(),
        job_id: Uuid::new_v4(),
        file_path: "secrets.txt".to_string(),
        file_type: "text".to_string(),
        file_size: 1024,
        mime_type: Some("text/plain".to_string()),
        language: None,
        encoding: Some("utf-8".to_string()),
        hash_sha256: "test".to_string(),
        hash_blake3: "test".to_string(),
        classification: Classification::Confidential,
        findings: serde_json::json!([]),
        metadata: serde_json::json!({
            "content": "password: secret123\napi_key: sk-1234567890"
        }),
        processed_at: Utc::now(),
        processing_time_ms: 100,
    };
    
    let classification = analyzer.classify_content(&sensitive_analysis).await.unwrap();
    assert_eq!(classification.sensitivity, "sensitive");
    
    // Test suspicious content
    let suspicious_analysis = FileAnalysis {
        id: Uuid::new_v4(),
        job_id: Uuid::new_v4(),
        file_path: "malware.js".to_string(),
        file_type: "code".to_string(),
        file_size: 1024,
        mime_type: Some("text/javascript".to_string()),
        language: Some("javascript".to_string()),
        encoding: Some("utf-8".to_string()),
        hash_sha256: "test".to_string(),
        hash_blake3: "test".to_string(),
        classification: Classification::Restricted,
        findings: serde_json::json!([]),
        metadata: serde_json::json!({
            "content": "function backdoor() { eval(atob('...')); }"
        }),
        processed_at: Utc::now(),
        processing_time_ms: 100,
    };
    
    let classification = analyzer.classify_content(&suspicious_analysis).await.unwrap();
    assert_eq!(classification.intent, "suspicious");
}

#[tokio::test]
async fn test_similarity_analysis() {
    let analyzer = MLAnalyzer::new(&AnalysisConfig::default()).await.unwrap();
    let job_id = Uuid::new_v4();
    
    let file1 = FileAnalysis {
        id: Uuid::new_v4(),
        job_id,
        file_path: "file1.py".to_string(),
        file_type: "code".to_string(),
        file_size: 1024,
        mime_type: Some("text/x-python".to_string()),
        language: Some("python".to_string()),
        encoding: Some("utf-8".to_string()),
        hash_sha256: "test1".to_string(),
        hash_blake3: "test1".to_string(),
        classification: Classification::Internal,
        findings: serde_json::json!([]),
        metadata: serde_json::json!({
            "content": "def calculate_sum(a, b):\n    return a + b"
        }),
        processed_at: Utc::now(),
        processing_time_ms: 100,
    };
    
    let file2 = FileAnalysis {
        id: Uuid::new_v4(),
        job_id,
        file_path: "file2.py".to_string(),
        file_type: "code".to_string(),
        file_size: 1024,
        mime_type: Some("text/x-python".to_string()),
        language: Some("python".to_string()),
        encoding: Some("utf-8".to_string()),
        hash_sha256: "test2".to_string(),
        hash_blake3: "test2".to_string(),
        classification: Classification::Internal,
        findings: serde_json::json!([]),
        metadata: serde_json::json!({
            "content": "def calculate_sum(x, y):\n    return x + y"  // Very similar
        }),
        processed_at: Utc::now(),
        processing_time_ms: 100,
    };
    
    let files = vec![file1, file2];
    
    // This should find similar files
    analyzer.perform_similarity_analysis(job_id, &files).await.unwrap();
}

#[tokio::test]
async fn test_character_distribution_anomaly() {
    let analyzer = MLAnalyzer::new(&AnalysisConfig::default()).await.unwrap();
    
    // Normal text
    let normal_text = "This is normal English text with proper distribution.";
    assert!(!analyzer.has_unusual_character_distribution(normal_text));
    
    // High non-ASCII content
    let non_ascii_text = "这是中文文本 with some English mixed in 包含很多非ASCII字符";
    assert!(analyzer.has_unusual_character_distribution(non_ascii_text));
    
    // High control characters
    let control_chars = "Text\0with\x01many\x02control\x03characters\x04\x05\x06";
    assert!(analyzer.has_unusual_character_distribution(control_chars));
}

#[tokio::test]
async fn test_language_pattern_anomaly() {
    let analyzer = MLAnalyzer::new(&AnalysisConfig::default()).await.unwrap();
    
    // Normal Python
    let normal_python = "def function():\n    return 42\n";
    assert!(!analyzer.has_unusual_language_patterns(normal_python, "python"));
    
    // Python with unusual patterns (too many semicolons)
    let unusual_python = "x = 1; y = 2; z = 3; a = 4; b = 5; c = 6;";
    assert!(analyzer.has_unusual_language_patterns(unusual_python, "python"));
    
    // JavaScript with eval
    let suspicious_js = "eval('alert(1)')";
    assert!(analyzer.has_unusual_language_patterns(suspicious_js, "javascript"));
}

#[test]
fn test_embedding_model() {
    tokio::runtime::Runtime::new().unwrap().block_on(async {
        let model = EmbeddingModel::new().await.unwrap();
        
        // Test text embedding
        let text = "Hello, world!";
        let embedding = model.generate_text_embedding(text).await.unwrap();
        assert_eq!(embedding.len(), 384);
        assert!(embedding.iter().all(|&x| x >= 0.0 && x <= 1.0));
        
        // Test code embedding
        let code = "fn main() { println!(\"Hello\"); }";
        let code_embedding = model.generate_code_embedding(code, "rust").await.unwrap();
        assert_eq!(code_embedding.len(), 384);
        
        // Different texts should produce different embeddings
        let text2 = "Goodbye, world!";
        let embedding2 = model.generate_text_embedding(text2).await.unwrap();
        assert_ne!(embedding, embedding2);
    });
}