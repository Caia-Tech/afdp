use super::*;
use crate::analysis::security_scanner::SecurityScanner;

#[tokio::test]
async fn test_secret_detection() {
    let scanner = SecurityScanner::new(&AnalysisConfig::default()).await.unwrap();
    let job_id = Uuid::new_v4();
    
    // Test file with various secrets
    let content = r#"
# Configuration file
AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE
AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY

# GitHub token
GITHUB_TOKEN=ghp_abc123def456ghi789jkl012mno345pqr678

# Generic API key
api_key = "sk-1234567890abcdef1234567890abcdef"

# Private key
-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEA...
-----END RSA PRIVATE KEY-----

# JWT token
token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
"#;
    
    let file_analysis = FileAnalysis {
        id: Uuid::new_v4(),
        job_id,
        file_path: "config.env".to_string(),
        file_type: "config".to_string(),
        file_size: content.len() as i64,
        mime_type: None,
        language: None,
        encoding: Some("utf-8".to_string()),
        hash_sha256: "test".to_string(),
        hash_blake3: "test".to_string(),
        classification: Classification::Internal,
        findings: serde_json::json!([]),
        metadata: serde_json::json!({
            "content": content
        }),
        processed_at: Utc::now(),
        processing_time_ms: 100,
    };
    
    let findings = scanner.scan_for_secrets(job_id, &file_analysis).await.unwrap();
    
    // Should find multiple secrets
    assert!(findings.len() >= 4);
    
    // Check specific findings
    let aws_finding = findings.iter().find(|f| f.title.contains("AWS")).unwrap();
    assert_eq!(aws_finding.finding_type, FindingType::SecretExposure);
    assert_eq!(aws_finding.severity, Severity::Critical);
    
    let github_finding = findings.iter().find(|f| f.title.contains("GitHub")).unwrap();
    assert_eq!(github_finding.finding_type, FindingType::SecretExposure);
    assert_eq!(github_finding.severity, Severity::Critical);
    
    let jwt_finding = findings.iter().find(|f| f.title.contains("JWT")).unwrap();
    assert_eq!(jwt_finding.finding_type, FindingType::SecretExposure);
}

#[tokio::test]
async fn test_vulnerability_detection() {
    let scanner = SecurityScanner::new(&AnalysisConfig::default()).await.unwrap();
    let job_id = Uuid::new_v4();
    
    let vulnerable_code = r#"
import mysql.connector

def get_user(user_id):
    # SQL injection vulnerability
    query = "SELECT * FROM users WHERE id = " + user_id
    cursor.execute(query)
    
    # Command injection
    import os
    filename = input("Enter filename: ")
    os.system("cat " + filename)
    
    # Path traversal
    with open("../../etc/passwd", "r") as f:
        data = f.read()
"#;
    
    let file_analysis = FileAnalysis {
        id: Uuid::new_v4(),
        job_id,
        file_path: "vulnerable.py".to_string(),
        file_type: "code".to_string(),
        file_size: vulnerable_code.len() as i64,
        mime_type: Some("text/x-python".to_string()),
        language: Some("python".to_string()),
        encoding: Some("utf-8".to_string()),
        hash_sha256: "test".to_string(),
        hash_blake3: "test".to_string(),
        classification: Classification::Internal,
        findings: serde_json::json!([]),
        metadata: serde_json::json!({
            "content": vulnerable_code
        }),
        processed_at: Utc::now(),
        processing_time_ms: 100,
    };
    
    let findings = scanner.scan_for_vulnerabilities(job_id, &file_analysis).await.unwrap();
    
    assert!(!findings.is_empty());
    
    // Check for SQL injection
    let sql_injection = findings.iter().find(|f| 
        f.title.contains("SQL") && f.finding_type == FindingType::Vulnerability
    );
    assert!(sql_injection.is_some());
    
    // Check for command injection
    let cmd_injection = findings.iter().find(|f| 
        f.title.contains("Command") && f.finding_type == FindingType::Vulnerability
    );
    assert!(cmd_injection.is_some());
    
    // Check for path traversal
    let path_traversal = findings.iter().find(|f| 
        f.title.contains("Path") && f.finding_type == FindingType::Vulnerability
    );
    assert!(path_traversal.is_some());
}

#[tokio::test]
async fn test_malware_detection() {
    let scanner = SecurityScanner::new(&AnalysisConfig::default()).await.unwrap();
    let job_id = Uuid::new_v4();
    
    // High entropy content (simulating encrypted/packed file)
    let high_entropy_content = "aB3$xY9#mQ2@pL7!zK5&nH8*wE4^tG6%".repeat(100);
    
    let file_analysis = FileAnalysis {
        id: Uuid::new_v4(),
        job_id,
        file_path: "suspicious.bin".to_string(),
        file_type: "unknown".to_string(),
        file_size: high_entropy_content.len() as i64,
        mime_type: None,
        language: None,
        encoding: Some("binary".to_string()),
        hash_sha256: "test".to_string(),
        hash_blake3: "test".to_string(),
        classification: Classification::Internal,
        findings: serde_json::json!([]),
        metadata: serde_json::json!({
            "content": high_entropy_content
        }),
        processed_at: Utc::now(),
        processing_time_ms: 100,
    };
    
    let findings = scanner.scan_for_malware(job_id, &file_analysis).await.unwrap();
    
    // Should detect high entropy
    let entropy_finding = findings.iter().find(|f| 
        f.title.contains("entropy") && f.finding_type == FindingType::Malware
    );
    assert!(entropy_finding.is_some());
}

#[tokio::test]
async fn test_suspicious_code_detection() {
    let scanner = SecurityScanner::new(&AnalysisConfig::default()).await.unwrap();
    let job_id = Uuid::new_v4();
    
    let suspicious_code = r#"
// Suspicious patterns
function installBackdoor() {
    // backdoor code
}

const keylogger = require('keylogger');
keylogger.start();

// Obfuscated code
eval(String.fromCharCode(97,108,101,114,116,40,39,72,101,108,108,111,39,41));

// System commands
exec("rm -rf /");
system("format c:");
"#;
    
    let file_analysis = FileAnalysis {
        id: Uuid::new_v4(),
        job_id,
        file_path: "malicious.js".to_string(),
        file_type: "code".to_string(),
        file_size: suspicious_code.len() as i64,
        mime_type: Some("text/javascript".to_string()),
        language: Some("javascript".to_string()),
        encoding: Some("utf-8".to_string()),
        hash_sha256: "test".to_string(),
        hash_blake3: "test".to_string(),
        classification: Classification::Internal,
        findings: serde_json::json!([]),
        metadata: serde_json::json!({
            "content": suspicious_code
        }),
        processed_at: Utc::now(),
        processing_time_ms: 100,
    };
    
    let findings = scanner.scan_for_suspicious_code(job_id, &file_analysis).await.unwrap();
    
    assert!(!findings.is_empty());
    
    // Should detect backdoor patterns
    let backdoor_finding = findings.iter().find(|f| 
        f.finding_type == FindingType::Backdoor
    );
    assert!(backdoor_finding.is_some());
}

#[tokio::test]
async fn test_file_path_scanning() {
    let scanner = SecurityScanner::new(&AnalysisConfig::default()).await.unwrap();
    let job_id = Uuid::new_v4();
    
    let suspicious_paths = vec![
        "malware/payload.exe",
        "hack/exploit.sh",
        ".hidden/backdoor.py",
        "trojan.js",
        "keylogger.dll",
    ];
    
    for path in suspicious_paths {
        let findings = scanner.scan_file_path(path, job_id).await.unwrap();
        assert!(!findings.is_empty(), "Should detect suspicious path: {}", path);
        assert_eq!(findings[0].finding_type, FindingType::SuspiciousCode);
    }
    
    // Normal paths should not trigger findings
    let normal_paths = vec!["src/main.rs", "README.md", "package.json"];
    for path in normal_paths {
        let findings = scanner.scan_file_path(path, job_id).await.unwrap();
        assert!(findings.is_empty(), "Should not flag normal path: {}", path);
    }
}

#[tokio::test]
async fn test_repository_level_analysis() {
    let scanner = SecurityScanner::new(&AnalysisConfig::default()).await.unwrap();
    let job_id = Uuid::new_v4();
    
    // Create file analyses with different types
    let mut file_analyses = vec![];
    
    // Add many executables (suspicious)
    for i in 0..40 {
        file_analyses.push(FileAnalysis {
            id: Uuid::new_v4(),
            job_id,
            file_path: format!("bin/tool{}.exe", i),
            file_type: "executable".to_string(),
            file_size: 1024,
            mime_type: None,
            language: None,
            encoding: None,
            hash_sha256: format!("hash{}", i),
            hash_blake3: format!("blake{}", i),
            classification: Classification::Internal,
            findings: serde_json::json!([]),
            metadata: serde_json::json!({}),
            processed_at: Utc::now(),
            processing_time_ms: 100,
        });
    }
    
    // Add some normal files
    for i in 0..60 {
        file_analyses.push(FileAnalysis {
            id: Uuid::new_v4(),
            job_id,
            file_path: format!("src/file{}.rs", i),
            file_type: "code".to_string(),
            file_size: 1024,
            mime_type: Some("text/x-rust".to_string()),
            language: Some("rust".to_string()),
            encoding: Some("utf-8".to_string()),
            hash_sha256: format!("hash{}", i),
            hash_blake3: format!("blake{}", i),
            classification: Classification::Internal,
            findings: serde_json::json!([]),
            metadata: serde_json::json!({}),
            processed_at: Utc::now(),
            processing_time_ms: 100,
        });
    }
    
    let findings = scanner.scan_repository(job_id, &file_analyses).await.unwrap();
    
    // Should detect high ratio of executables
    let executable_anomaly = findings.iter().find(|f| 
        f.title.contains("executable") && f.finding_type == FindingType::Anomaly
    );
    assert!(executable_anomaly.is_some());
}

#[tokio::test]
async fn test_configuration_analysis() {
    let scanner = SecurityScanner::new(&AnalysisConfig::default()).await.unwrap();
    let job_id = Uuid::new_v4();
    
    let config_with_creds = r#"
database:
  host: localhost
  user: admin
  password: "SuperSecret123!"
  
api:
  endpoint: https://api.example.com
  key: "sk-1234567890abcdef"
  secret: "my-api-secret-key"
"#;
    
    let file_analysis = FileAnalysis {
        id: Uuid::new_v4(),
        job_id,
        file_path: "config.yaml".to_string(),
        file_type: "config".to_string(),
        file_size: config_with_creds.len() as i64,
        mime_type: Some("text/yaml".to_string()),
        language: None,
        encoding: Some("utf-8".to_string()),
        hash_sha256: "test".to_string(),
        hash_blake3: "test".to_string(),
        classification: Classification::Internal,
        findings: serde_json::json!([]),
        metadata: serde_json::json!({
            "content": config_with_creds
        }),
        processed_at: Utc::now(),
        processing_time_ms: 100,
    };
    
    let findings = scanner.analyze_configurations(job_id, &[file_analysis]).await.unwrap();
    
    assert!(!findings.is_empty());
    assert!(findings.iter().any(|f| 
        f.finding_type == FindingType::SecretExposure && 
        f.title.contains("Hardcoded credentials")
    ));
}

#[tokio::test]
async fn test_exposed_files_detection() {
    let scanner = SecurityScanner::new(&AnalysisConfig::default()).await.unwrap();
    let job_id = Uuid::new_v4();
    
    let sensitive_files = vec![
        ".env",
        "private.key",
        "id_rsa",
        "credentials.json",
        "secrets.yaml",
    ];
    
    let mut file_analyses = vec![];
    for filename in sensitive_files {
        file_analyses.push(FileAnalysis {
            id: Uuid::new_v4(),
            job_id,
            file_path: filename.to_string(),
            file_type: "config".to_string(),
            file_size: 1024,
            mime_type: None,
            language: None,
            encoding: Some("utf-8".to_string()),
            hash_sha256: "test".to_string(),
            hash_blake3: "test".to_string(),
            classification: Classification::Confidential,
            findings: serde_json::json!([]),
            metadata: serde_json::json!({}),
            processed_at: Utc::now(),
            processing_time_ms: 100,
        });
    }
    
    let findings = scanner.check_exposed_files(job_id, &file_analyses).await.unwrap();
    
    assert_eq!(findings.len(), file_analyses.len());
    assert!(findings.iter().all(|f| 
        f.finding_type == FindingType::DataLeak &&
        f.severity == Severity::High
    ));
}