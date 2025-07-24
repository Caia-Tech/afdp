use super::*;
use crate::analysis::code_analyzer::{CodeAnalyzer, LanguageAnalyzer, DependencyAnalyzer};

#[tokio::test]
async fn test_language_specific_analysis() {
    let analyzer = CodeAnalyzer::new(&AnalysisConfig::default()).await.unwrap();
    let job_id = Uuid::new_v4();
    
    // Test Rust unsafe code detection
    let rust_code = r#"
fn safe_function() {
    println!("Safe code");
}

fn dangerous_function() {
    unsafe {
        let raw_ptr = 0x1234 as *mut i32;
        *raw_ptr = 42;
    }
    
    let result = std::mem::transmute::<i32, f32>(42);
}
"#;
    
    let rust_analysis = FileAnalysis {
        id: Uuid::new_v4(),
        job_id,
        file_path: "dangerous.rs".to_string(),
        file_type: "code".to_string(),
        file_size: rust_code.len() as i64,
        mime_type: Some("text/x-rust".to_string()),
        language: Some("rust".to_string()),
        encoding: Some("utf-8".to_string()),
        hash_sha256: "test".to_string(),
        hash_blake3: "test".to_string(),
        classification: Classification::Internal,
        findings: serde_json::json!([]),
        metadata: serde_json::json!({
            "content": rust_code
        }),
        processed_at: Utc::now(),
        processing_time_ms: 100,
    };
    
    let findings = analyzer.analyze_code_file(job_id, &rust_analysis).await.unwrap();
    
    // Should detect unsafe block
    assert!(findings.iter().any(|f| f.title.contains("Unsafe Rust")));
    
    // Should detect transmute usage
    assert!(findings.iter().any(|f| f.title.contains("Transmute")));
}

#[tokio::test]
async fn test_vulnerability_patterns() {
    let analyzer = CodeAnalyzer::new(&AnalysisConfig::default()).await.unwrap();
    let job_id = Uuid::new_v4();
    
    // Test Python vulnerabilities
    let python_code = r#"
import os
import subprocess

def process_user_input(user_input):
    # SQL injection vulnerability
    query = "SELECT * FROM users WHERE name = '" + user_input + "'"
    cursor.execute(query)
    
    # Dangerous eval
    result = eval(user_input)
    
    # Command injection
    os.system("echo " + user_input)
"#;
    
    let python_analysis = FileAnalysis {
        id: Uuid::new_v4(),
        job_id,
        file_path: "vulnerable.py".to_string(),
        file_type: "code".to_string(),
        file_size: python_code.len() as i64,
        mime_type: Some("text/x-python".to_string()),
        language: Some("python".to_string()),
        encoding: Some("utf-8".to_string()),
        hash_sha256: "test".to_string(),
        hash_blake3: "test".to_string(),
        classification: Classification::Internal,
        findings: serde_json::json!([]),
        metadata: serde_json::json!({
            "content": python_code
        }),
        processed_at: Utc::now(),
        processing_time_ms: 100,
    };
    
    let findings = analyzer.analyze_code_file(job_id, &python_analysis).await.unwrap();
    
    // Should detect eval usage
    assert!(findings.iter().any(|f| 
        f.title.contains("eval") && f.severity == Severity::Critical
    ));
    
    // Should detect SQL injection pattern
    assert!(findings.iter().any(|f| 
        f.title.contains("SQL injection")
    ));
}

#[tokio::test]
async fn test_code_quality_rules() {
    let analyzer = CodeAnalyzer::new(&AnalysisConfig::default()).await.unwrap();
    let job_id = Uuid::new_v4();
    
    let poor_quality_code = r#"
function processData(data) {
    // Very long line that exceeds the recommended 120 character limit and should be broken up into multiple lines for better readability and maintainability
    
    var magicNumber = 999999;  // Magic number
    
    try {
        doSomething();
    } catch (e) {
        // Empty catch block
    }
}
"#;
    
    let analysis = FileAnalysis {
        id: Uuid::new_v4(),
        job_id,
        file_path: "poor_quality.js".to_string(),
        file_type: "code".to_string(),
        file_size: poor_quality_code.len() as i64,
        mime_type: Some("text/javascript".to_string()),
        language: Some("javascript".to_string()),
        encoding: Some("utf-8".to_string()),
        hash_sha256: "test".to_string(),
        hash_blake3: "test".to_string(),
        classification: Classification::Internal,
        findings: serde_json::json!([]),
        metadata: serde_json::json!({
            "content": poor_quality_code
        }),
        processed_at: Utc::now(),
        processing_time_ms: 100,
    };
    
    let findings = analyzer.analyze_code_file(job_id, &analysis).await.unwrap();
    
    // Should detect long line
    assert!(findings.iter().any(|f| f.title.contains("Line too long")));
    
    // Should detect magic number
    assert!(findings.iter().any(|f| f.title.contains("Magic number")));
    
    // Should detect empty catch block
    assert!(findings.iter().any(|f| f.title.contains("Empty catch block")));
}

#[tokio::test]
async fn test_complexity_analysis() {
    let analyzer = CodeAnalyzer::new(&AnalysisConfig::default()).await.unwrap();
    let job_id = Uuid::new_v4();
    
    let complex_code = r#"
function veryComplexFunction(a, b, c, d, e) {
    if (a > 0) {
        if (b > 0) {
            if (c > 0) {
                if (d > 0) {
                    if (e > 0) {
                        while (a > 0) {
                            for (let i = 0; i < 10; i++) {
                                if (i % 2 === 0) {
                                    switch (i) {
                                        case 0: console.log("0"); break;
                                        case 2: console.log("2"); break;
                                        case 4: console.log("4"); break;
                                        case 6: console.log("6"); break;
                                        case 8: console.log("8"); break;
                                    }
                                } else {
                                    try {
                                        doSomething();
                                    } catch (e) {
                                        handleError(e);
                                    }
                                }
                            }
                            a--;
                        }
                    }
                }
            }
        }
    }
    
    // This function is also very long and continues for many more lines...
    // Adding more lines to make it exceed the length threshold
    console.log("Line 1");
    console.log("Line 2");
    console.log("Line 3");
    console.log("Line 4");
    console.log("Line 5");
    console.log("Line 6");
    console.log("Line 7");
    console.log("Line 8");
    console.log("Line 9");
    console.log("Line 10");
    console.log("Line 11");
    console.log("Line 12");
    console.log("Line 13");
    console.log("Line 14");
    console.log("Line 15");
    console.log("Line 16");
    console.log("Line 17");
    console.log("Line 18");
    console.log("Line 19");
    console.log("Line 20");
    console.log("Line 21");
    console.log("Line 22");
    console.log("Line 23");
    console.log("Line 24");
    console.log("Line 25");
}
"#;
    
    let analysis = FileAnalysis {
        id: Uuid::new_v4(),
        job_id,
        file_path: "complex.js".to_string(),
        file_type: "code".to_string(),
        file_size: complex_code.len() as i64,
        mime_type: Some("text/javascript".to_string()),
        language: Some("javascript".to_string()),
        encoding: Some("utf-8".to_string()),
        hash_sha256: "test".to_string(),
        hash_blake3: "test".to_string(),
        classification: Classification::Internal,
        findings: serde_json::json!([]),
        metadata: serde_json::json!({
            "content": complex_code
        }),
        processed_at: Utc::now(),
        processing_time_ms: 100,
    };
    
    let findings = analyzer.analyze_code_file(job_id, &analysis).await.unwrap();
    
    // Should detect high complexity
    assert!(findings.iter().any(|f| 
        f.title.contains("cyclomatic complexity") && f.severity == Severity::Medium
    ));
    
    // Should detect long function
    assert!(findings.iter().any(|f| 
        f.title.contains("Long function")
    ));
}

#[tokio::test]
async fn test_anti_pattern_detection() {
    let analyzer = CodeAnalyzer::new(&AnalysisConfig::default()).await.unwrap();
    let job_id = Uuid::new_v4();
    
    let anti_pattern_code = r#"
function badCode() {
    // TODO: Fix this hack
    // FIXME: This is broken
    // HACK: Temporary workaround
    
    var x = 10;
    goto_label:
    x++;
    if (x < 20) goto goto_label;
    
    eval("console.log('dangerous')");
    exec("rm -rf /");
}
"#;
    
    let analysis = FileAnalysis {
        id: Uuid::new_v4(),
        job_id,
        file_path: "antipatterns.js".to_string(),
        file_type: "code".to_string(),
        file_size: anti_pattern_code.len() as i64,
        mime_type: Some("text/javascript".to_string()),
        language: Some("javascript".to_string()),
        encoding: Some("utf-8".to_string()),
        hash_sha256: "test".to_string(),
        hash_blake3: "test".to_string(),
        classification: Classification::Internal,
        findings: serde_json::json!([]),
        metadata: serde_json::json!({
            "content": anti_pattern_code
        }),
        processed_at: Utc::now(),
        processing_time_ms: 100,
    };
    
    let findings = analyzer.analyze_code_file(job_id, &analysis).await.unwrap();
    
    // Should detect goto statement
    assert!(findings.iter().any(|f| f.title.contains("goto")));
    
    // Should detect eval
    assert!(findings.iter().any(|f| f.title.contains("eval")));
    
    // Should detect TODO/FIXME comments
    assert!(findings.iter().any(|f| f.title.contains("TODO/FIXME")));
}

#[tokio::test]
async fn test_dependency_analysis() {
    let analyzer = CodeAnalyzer::new(&AnalysisConfig::default()).await.unwrap();
    let job_id = Uuid::new_v4();
    
    // Test Rust dependencies
    let cargo_toml = r#"
[package]
name = "test-project"
version = "0.1.0"

[dependencies]
tokio = "1.0"
serde = "1.0"
old-crate = "0.1.0"  # This would be flagged as outdated
vulnerable-lib = "2.3.4"  # This would be flagged if in vulnerability DB
"#;
    
    let analysis = FileAnalysis {
        id: Uuid::new_v4(),
        job_id,
        file_path: "Cargo.toml".to_string(),
        file_type: "config".to_string(),
        file_size: cargo_toml.len() as i64,
        mime_type: Some("text/toml".to_string()),
        language: Some("rust".to_string()),
        encoding: Some("utf-8".to_string()),
        hash_sha256: "test".to_string(),
        hash_blake3: "test".to_string(),
        classification: Classification::Internal,
        findings: serde_json::json!([]),
        metadata: serde_json::json!({
            "content": cargo_toml
        }),
        processed_at: Utc::now(),
        processing_time_ms: 100,
    };
    
    let findings = analyzer.analyze_code_file(job_id, &analysis).await.unwrap();
    
    // The basic implementation should at least parse dependencies
    // In a real implementation, it would check against vulnerability databases
}

#[tokio::test]
async fn test_code_duplication() {
    let analyzer = CodeAnalyzer::new(&AnalysisConfig::default()).await.unwrap();
    let job_id = Uuid::new_v4();
    
    let file1 = FileAnalysis {
        id: Uuid::new_v4(),
        job_id,
        file_path: "file1.js".to_string(),
        file_type: "code".to_string(),
        file_size: 1024,
        mime_type: Some("text/javascript".to_string()),
        language: Some("javascript".to_string()),
        encoding: Some("utf-8".to_string()),
        hash_sha256: "test1".to_string(),
        hash_blake3: "test1".to_string(),
        classification: Classification::Internal,
        findings: serde_json::json!([]),
        metadata: serde_json::json!({
            "content": r#"
function calculateTotalPrice(items) {
    let total = 0;
    for (let item of items) {
        total += item.price * item.quantity;
    }
    return total;
}
"#
        }),
        processed_at: Utc::now(),
        processing_time_ms: 100,
    };
    
    let file2 = FileAnalysis {
        id: Uuid::new_v4(),
        job_id,
        file_path: "file2.js".to_string(),
        file_type: "code".to_string(),
        file_size: 1024,
        mime_type: Some("text/javascript".to_string()),
        language: Some("javascript".to_string()),
        encoding: Some("utf-8".to_string()),
        hash_sha256: "test2".to_string(),
        hash_blake3: "test2".to_string(),
        classification: Classification::Internal,
        findings: serde_json::json!([]),
        metadata: serde_json::json!({
            "content": r#"
function computeTotalCost(products) {
    let total = 0;
    for (let item of items) {
        total += item.price * item.quantity;
    }
    return total;
}
"#
        }),
        processed_at: Utc::now(),
        processing_time_ms: 100,
    };
    
    let file3 = FileAnalysis {
        id: Uuid::new_v4(),
        job_id,
        file_path: "file3.js".to_string(),
        file_type: "code".to_string(),
        file_size: 1024,
        mime_type: Some("text/javascript".to_string()),
        language: Some("javascript".to_string()),
        encoding: Some("utf-8".to_string()),
        hash_sha256: "test3".to_string(),
        hash_blake3: "test3".to_string(),
        classification: Classification::Internal,
        findings: serde_json::json!([]),
        metadata: serde_json::json!({
            "content": r#"
function getOrderTotal(orders) {
    let total = 0;
    for (let item of items) {
        total += item.price * item.quantity;
    }
    return total;
}
"#
        }),
        processed_at: Utc::now(),
        processing_time_ms: 100,
    };
    
    let file_refs = vec![&file1, &file2, &file3];
    let findings = analyzer.analyze_code_duplication(job_id, &file_refs).await.unwrap();
    
    // Should detect the duplicated line
    assert!(!findings.is_empty());
    assert!(findings.iter().any(|f| 
        f.title.contains("Code duplication") &&
        f.evidence.get("duplicated_line").is_some()
    ));
}

#[test]
fn test_language_analyzer_creation() {
    let rust_analyzer = LanguageAnalyzer::new_rust();
    assert_eq!(rust_analyzer.language, "rust");
    assert!(!rust_analyzer.security_patterns.is_empty());
    assert!(rust_analyzer.file_extensions.contains(&"rs".to_string()));
    
    let python_analyzer = LanguageAnalyzer::new_python();
    assert_eq!(python_analyzer.language, "python");
    assert!(python_analyzer.security_patterns.iter().any(|p| p.name.contains("Eval")));
    
    let js_analyzer = LanguageAnalyzer::new_javascript();
    assert_eq!(js_analyzer.language, "javascript");
    assert!(js_analyzer.security_patterns.iter().any(|p| p.name.contains("innerHTML")));
}

#[test]
fn test_dependency_analyzer() {
    let rust_deps = DependencyAnalyzer::new_rust();
    let cargo_content = r#"
[dependencies]
serde = "1.0"
tokio = { version = "1.0", features = ["full"] }
"#;
    
    let dependencies = rust_deps.extract_dependencies(cargo_content);
    assert_eq!(dependencies.len(), 2);
    assert!(dependencies.iter().any(|d| d.name == "serde"));
    assert!(dependencies.iter().any(|d| d.name == "tokio"));
}

#[tokio::test]
async fn test_syntax_analysis() {
    let analyzer = CodeAnalyzer::new(&AnalysisConfig::default()).await.unwrap();
    
    // Test Python syntax issues
    let python_with_issues = r#"
def function1():
    x = 1 \
    y = 2  # Line continuation issue
"#;
    
    let issues = analyzer.analyze_syntax(python_with_issues, "python").await.unwrap();
    assert!(issues.is_some());
    
    // Test JavaScript missing semicolons
    let js_with_issues = r#"
let x = 1
let y = 2
console.log(x + y)
"#;
    
    let issues = analyzer.analyze_syntax(js_with_issues, "javascript").await.unwrap();
    assert!(issues.is_some());
    let issues = issues.unwrap();
    assert!(issues.iter().any(|i| i.issue_type == "missing_semicolon"));
}

#[test]
fn test_cyclomatic_complexity_calculation() {
    let analyzer = CodeAnalyzer {
        config: AnalysisConfig::default(),
        language_analyzers: HashMap::new(),
        code_quality_rules: vec![],
        dependency_analyzers: HashMap::new(),
    };
    
    let simple_code = "function add(a, b) { return a + b; }";
    assert_eq!(analyzer.calculate_cyclomatic_complexity(simple_code), 1);
    
    let complex_code = r#"
    if (a) {
        if (b) {
            while (c) {
                for (let i = 0; i < 10; i++) {
                    if (i % 2 === 0) {
                        x = y || z;
                        w = p && q;
                    }
                }
            }
        }
    }
    "#;
    
    let complexity = analyzer.calculate_cyclomatic_complexity(complex_code);
    assert!(complexity > 5);
}