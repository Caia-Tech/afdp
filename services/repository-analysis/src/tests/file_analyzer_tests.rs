use super::*;
use crate::analysis::file_analyzer::{FileAnalyzer, ContentMetadata};

#[tokio::test]
async fn test_file_discovery() {
    let mut context = TestContext::new().unwrap();
    
    // Create test files
    context.create_test_file("src/main.rs", "fn main() {}").await.unwrap();
    context.create_test_file("src/lib.rs", "pub mod test;").await.unwrap();
    context.create_test_file("README.md", "# Test Project").await.unwrap();
    context.create_test_file(".gitignore", "target/").await.unwrap();
    
    let analyzer = FileAnalyzer::new(&context.config).await.unwrap();
    let files = analyzer.discover_files(context.temp_dir.path().to_str().unwrap()).await.unwrap();
    
    assert!(files.len() >= 3); // Should find at least 3 files (gitignore might be filtered)
    
    // Check that files have correct metadata
    let readme = files.iter().find(|f| f.relative_path.contains("README.md")).unwrap();
    assert_eq!(readme.file_type, "document");
    assert!(!readme.is_binary);
    
    let rust_file = files.iter().find(|f| f.relative_path.contains("main.rs")).unwrap();
    assert_eq!(rust_file.file_type, "code");
    assert_eq!(rust_file.extension, Some("rs".to_string()));
}

#[tokio::test]
async fn test_file_type_classification() {
    let analyzer = FileAnalyzer::new(&AnalysisConfig::default()).await.unwrap();
    
    let test_cases = vec![
        ("test.rs", "code"),
        ("test.py", "code"),
        ("test.js", "code"),
        ("README.md", "document"),
        ("config.yaml", "config"),
        ("image.png", "image"),
        ("video.mp4", "video"),
        ("archive.zip", "archive"),
        ("binary.exe", "executable"),
        ("cert.pem", "certificate"),
        ("unknown.xyz", "unknown"),
        ("Dockerfile", "code"),
        ("LICENSE", "document"),
    ];
    
    for (filename, expected_type) in test_cases {
        let path = std::path::Path::new(filename);
        let file_type = analyzer.classify_file_type(path);
        assert_eq!(file_type, expected_type, "Failed for {}", filename);
    }
}

#[tokio::test]
async fn test_file_analysis() {
    let mut context = TestContext::new().unwrap();
    let job_id = Uuid::new_v4();
    
    let test_content = r#"
fn main() {
    let password = "secret123";
    println!("Hello, world!");
}
"#;
    
    let file_path = context.create_test_file("test.rs", test_content).await.unwrap();
    let file_info = FileInfo {
        path: file_path.clone(),
        relative_path: "test.rs".to_string(),
        size_bytes: test_content.len() as u64,
        modified_at: Utc::now(),
        file_type: "code".to_string(),
        mime_type: Some("text/x-rust".to_string()),
        extension: Some("rs".to_string()),
        is_binary: false,
        is_executable: false,
        permissions: None,
    };
    
    let analyzer = FileAnalyzer::new(&context.config).await.unwrap();
    let analysis = analyzer.analyze_file(job_id, &file_info).await.unwrap();
    
    assert_eq!(analysis.job_id, job_id);
    assert_eq!(analysis.file_path, "test.rs");
    assert_eq!(analysis.file_type, "code");
    assert_eq!(analysis.language, Some("rust".to_string()));
    assert_eq!(analysis.encoding, Some("utf-8".to_string()));
    assert_eq!(analysis.classification, Classification::Internal);
    
    // Check that password was detected
    let findings = serde_json::from_value::<Vec<serde_json::Value>>(analysis.findings).unwrap();
    assert!(!findings.is_empty());
    assert!(findings.iter().any(|f| 
        f.get("finding_type").and_then(|v| v.as_str()) == Some("potential_secret")
    ));
}

#[tokio::test]
async fn test_encoding_detection() {
    let analyzer = FileAnalyzer::new(&AnalysisConfig::default()).await.unwrap();
    
    // UTF-8 with BOM
    let utf8_bom = vec![0xEF, 0xBB, 0xBF, b'h', b'e', b'l', b'l', b'o'];
    assert_eq!(analyzer.detect_encoding(&utf8_bom), Some("utf-8-bom".to_string()));
    
    // UTF-16
    let utf16 = vec![0xFF, 0xFE, 0x68, 0x00, 0x65, 0x00];
    assert_eq!(analyzer.detect_encoding(&utf16), Some("utf-16".to_string()));
    
    // Regular UTF-8
    let utf8 = "hello world".as_bytes();
    assert_eq!(analyzer.detect_encoding(utf8), Some("utf-8".to_string()));
    
    // ASCII
    let ascii: Vec<u8> = (0..127).collect();
    assert_eq!(analyzer.detect_encoding(&ascii), Some("ascii".to_string()));
    
    // Binary
    let binary = vec![0xFF, 0xFE, 0xFD, 0xFC];
    assert_eq!(analyzer.detect_encoding(&binary), Some("binary".to_string()));
}

#[tokio::test]
async fn test_language_detection() {
    let analyzer = FileAnalyzer::new(&AnalysisConfig::default()).await.unwrap();
    
    let test_cases = vec![
        (FileInfo { extension: Some("rs".to_string()), ..Default::default() }, Some("rust")),
        (FileInfo { extension: Some("py".to_string()), ..Default::default() }, Some("python")),
        (FileInfo { extension: Some("js".to_string()), ..Default::default() }, Some("javascript")),
        (FileInfo { extension: Some("go".to_string()), ..Default::default() }, Some("go")),
        (FileInfo { extension: Some("java".to_string()), ..Default::default() }, Some("java")),
        (FileInfo { extension: Some("md".to_string()), ..Default::default() }, Some("markdown")),
    ];
    
    for (file_info, expected_lang) in test_cases {
        let language = analyzer.detect_language(&file_info, b"");
        assert_eq!(language.as_deref(), expected_lang);
    }
}

#[tokio::test]
async fn test_content_metadata_extraction() {
    let analyzer = FileAnalyzer::new(&AnalysisConfig::default()).await.unwrap();
    
    let test_content = r#"
// This is a test file
// TODO: Add more tests

fn calculate_sum(a: i32, b: i32) -> i32 {
    // Calculate the sum
    a + b
}

fn main() {
    let result = calculate_sum(5, 3);
    println!("Result: {}", result);
    
    // Check URL: https://example.com
    // Email: test@example.com
    // IP: 192.168.1.1
}

const API_KEY = "secret_key_123";
"#;
    
    let metadata = analyzer.extract_content_metadata(test_content.as_bytes(), "code");
    
    assert_eq!(metadata.line_count, 19);
    assert!(metadata.char_count > 0);
    assert!(metadata.word_count > 0);
    assert_eq!(metadata.blank_lines, 3);
    assert!(metadata.comment_lines > 0);
    assert!(metadata.contains_urls);
    assert!(metadata.contains_emails);
    assert!(metadata.contains_ip_addresses);
    assert!(metadata.contains_secrets);
}

#[tokio::test]
async fn test_pii_detection() {
    let analyzer = FileAnalyzer::new(&AnalysisConfig::default()).await.unwrap();
    
    // Test SSN pattern
    assert!(analyzer.contains_pii("My SSN is 123-45-6789"));
    
    // Test credit card pattern
    assert!(analyzer.contains_pii("Card: 4111 1111 1111 1111"));
    assert!(analyzer.contains_pii("Card: 4111-1111-1111-1111"));
    
    // Test no PII
    assert!(!analyzer.contains_pii("This is just normal text"));
}

#[tokio::test]
async fn test_entropy_calculation() {
    let analyzer = FileAnalyzer::new(&AnalysisConfig::default()).await.unwrap();
    
    // Low entropy (repeated characters)
    let low_entropy_data = "aaaaaaaaaa".as_bytes();
    let low_entropy = analyzer.calculate_entropy(low_entropy_data);
    assert!(low_entropy < 1.0);
    
    // High entropy (random-looking)
    let high_entropy_data = "aB3$xY9#mQ2@pL7!".as_bytes();
    let high_entropy = analyzer.calculate_entropy(high_entropy_data);
    assert!(high_entropy > 3.0);
    
    // Empty data
    let empty_data = b"";
    let empty_entropy = analyzer.calculate_entropy(empty_data);
    assert_eq!(empty_entropy, 0.0);
}

#[tokio::test]
async fn test_skip_patterns() {
    let analyzer = FileAnalyzer::new(&AnalysisConfig::default()).await.unwrap();
    
    assert!(analyzer.should_skip_file(".git/config"));
    assert!(analyzer.should_skip_file("node_modules/package/index.js"));
    assert!(analyzer.should_skip_file("target/debug/build"));
    assert!(analyzer.should_skip_file(".DS_Store"));
    assert!(analyzer.should_skip_file("__pycache__/module.pyc"));
    
    assert!(!analyzer.should_skip_file("src/main.rs"));
    assert!(!analyzer.should_skip_file("README.md"));
}

impl Default for FileInfo {
    fn default() -> Self {
        FileInfo {
            path: String::new(),
            relative_path: String::new(),
            size_bytes: 0,
            modified_at: Utc::now(),
            file_type: String::new(),
            mime_type: None,
            extension: None,
            is_binary: false,
            is_executable: false,
            permissions: None,
        }
    }
}