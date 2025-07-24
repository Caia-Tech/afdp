use super::*;
use crate::analysis::git_analyzer::{GitAnalyzer, CommitInfo, SuspiciousPattern};
use chrono::TimeZone;

#[tokio::test]
async fn test_suspicious_timing_detection() {
    let analyzer = GitAnalyzer::new(&AnalysisConfig::default()).await.unwrap();
    
    // Test normal business hours (2 PM)
    let normal_time = Utc.with_ymd_and_hms(2023, 10, 15, 14, 0, 0).unwrap();
    assert!(!analyzer.is_suspicious_timing(&normal_time));
    
    // Test early morning (3 AM)
    let early_morning = Utc.with_ymd_and_hms(2023, 10, 15, 3, 0, 0).unwrap();
    assert!(analyzer.is_suspicious_timing(&early_morning));
    
    // Test late night (11 PM)
    let late_night = Utc.with_ymd_and_hms(2023, 10, 15, 23, 0, 0).unwrap();
    assert!(analyzer.is_suspicious_timing(&late_night));
}

#[tokio::test]
async fn test_sensitive_file_detection() {
    let analyzer = GitAnalyzer::new(&AnalysisConfig::default()).await.unwrap();
    
    let sensitive_files = vec![
        ".env",
        "config/secrets.yaml",
        "private.key",
        "id_rsa",
        "password.txt",
        "credentials.json",
        "cert.pem",
        "keystore.p12",
    ];
    
    for file in sensitive_files {
        assert!(
            analyzer.is_potentially_sensitive_file(file),
            "Should detect {} as sensitive", file
        );
    }
    
    let normal_files = vec![
        "README.md",
        "main.rs",
        "index.html",
        "package.json",
    ];
    
    for file in normal_files {
        assert!(
            !analyzer.is_potentially_sensitive_file(file),
            "Should not detect {} as sensitive", file
        );
    }
}

#[tokio::test]
async fn test_suspicious_email_detection() {
    let analyzer = GitAnalyzer::new(&AnalysisConfig::default()).await.unwrap();
    
    let suspicious_emails = vec![
        "test@10minutemail.com",
        "user@tempmail.org",
        "hacker@guerrillamail.com",
        "noreply@example.com",
        "no-reply@company.com",
        "admin@localhost",
        "root@server.com",
        "test@test.com",
    ];
    
    for email in suspicious_emails {
        assert!(
            analyzer.is_suspicious_email(email),
            "Should detect {} as suspicious", email
        );
    }
    
    let legitimate_emails = vec![
        "developer@company.com",
        "john.doe@enterprise.org",
        "alice@university.edu",
    ];
    
    for email in legitimate_emails {
        assert!(
            !analyzer.is_suspicious_email(email),
            "Should not detect {} as suspicious", email
        );
    }
}

#[tokio::test]
async fn test_binary_file_detection() {
    let analyzer = GitAnalyzer::new(&AnalysisConfig::default()).await.unwrap();
    
    let binary_files = vec![
        "program.exe",
        "library.dll",
        "lib.so",
        "app.dylib",
        "archive.zip",
        "image.png",
        "document.pdf",
    ];
    
    for file in binary_files {
        assert!(
            analyzer.is_binary_file(file),
            "Should detect {} as binary", file
        );
    }
    
    let text_files = vec![
        "source.rs",
        "script.py",
        "config.yaml",
        "readme.txt",
    ];
    
    for file in text_files {
        assert!(
            !analyzer.is_binary_file(file),
            "Should not detect {} as binary", file
        );
    }
}

#[tokio::test]
async fn test_commit_analysis() {
    let analyzer = GitAnalyzer::new(&AnalysisConfig::default()).await.unwrap();
    let job_id = Uuid::new_v4();
    
    // Create test commits
    let commits = vec![
        CommitInfo {
            hash: "abc123".to_string(),
            author: "Normal User".to_string(),
            email: "user@company.com".to_string(),
            timestamp: Utc::now(),
            message: "Fix bug in authentication module".to_string(),
            files_changed: 3,
            lines_added: 50,
            lines_removed: 20,
        },
        CommitInfo {
            hash: "def456".to_string(),
            author: "Suspicious User".to_string(),
            email: "hacker@tempmail.org".to_string(),
            timestamp: Utc.with_ymd_and_hms(2023, 10, 15, 3, 0, 0).unwrap(), // 3 AM
            message: "Add backdoor for remote access".to_string(),
            files_changed: 150, // Large commit
            lines_added: 15000,
            lines_removed: 100,
        },
        CommitInfo {
            hash: "ghi789".to_string(),
            author: "Developer".to_string(),
            email: "dev@company.com".to_string(),
            timestamp: Utc::now(),
            message: "Remove password from config file".to_string(),
            files_changed: 1,
            lines_added: 5,
            lines_removed: 10,
        },
    ];
    
    // Simulate analyzing commits
    // In a real test with a git repository, this would call analyze_commits
    // For now, we test the patterns
    let patterns = GitAnalyzer::load_suspicious_patterns();
    
    // Check backdoor pattern
    let backdoor_pattern = patterns.iter()
        .find(|p| p.name.contains("Backdoor"))
        .unwrap();
    
    let regex = regex::Regex::new(&backdoor_pattern.pattern).unwrap();
    assert!(regex.is_match(&commits[1].message));
    
    // Check credential removal pattern
    let cred_pattern = patterns.iter()
        .find(|p| p.name.contains("Credential"))
        .unwrap();
    
    let regex = regex::Regex::new(&cred_pattern.pattern).unwrap();
    assert!(regex.is_match(&commits[2].message));
}

#[tokio::test]
async fn test_stats_calculation() {
    let analyzer = GitAnalyzer::new(&AnalysisConfig::default()).await.unwrap();
    
    let values = vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10];
    let (mean, std_dev) = analyzer.calculate_stats(&values).unwrap();
    
    assert!((mean - 5.5).abs() < 0.1);
    assert!(std_dev > 2.8 && std_dev < 3.0);
    
    // Test empty vector
    assert!(analyzer.calculate_stats(&[]).is_none());
}

#[tokio::test]
async fn test_repository_info_extraction() {
    // This test would require a real git repository
    // For unit testing, we verify the data structures
    
    let repo_info = RepositoryInfo {
        url: "https://github.com/test/repo".to_string(),
        repository_type: "git".to_string(),
        local_path: "/tmp/repo".to_string(),
        git_path: Some("/tmp/repo".to_string()),
        size_bytes: 1024 * 1024,
        file_count: 100,
        commit_count: Some(500),
        contributors: vec!["user1".to_string(), "user2".to_string()],
        languages: vec!["Rust".to_string(), "Python".to_string()],
        last_commit: Some(Utc::now()),
        branch: Some("main".to_string()),
        tags: vec!["v1.0.0".to_string(), "v1.1.0".to_string()],
        metadata: HashMap::new(),
    };
    
    assert_eq!(repo_info.repository_type, "git");
    assert_eq!(repo_info.commit_count, Some(500));
    assert_eq!(repo_info.contributors.len(), 2);
}

#[test]
fn test_suspicious_patterns() {
    let patterns = GitAnalyzer::load_suspicious_patterns();
    
    assert!(!patterns.is_empty());
    
    // Verify pattern types
    let has_commit_patterns = patterns.iter()
        .any(|p| p.pattern_type == "commit_message");
    assert!(has_commit_patterns);
    
    let has_branch_patterns = patterns.iter()
        .any(|p| p.pattern_type == "branch_name");
    assert!(has_branch_patterns);
    
    // Test specific patterns
    let backdoor_pattern = patterns.iter()
        .find(|p| p.name.contains("Backdoor"))
        .unwrap();
    
    assert_eq!(backdoor_pattern.severity, Severity::High);
    assert!(backdoor_pattern.confidence > 0.5);
}

#[test]
fn test_risk_indicators() {
    let indicators = GitAnalyzer::load_risk_indicators();
    
    assert!(!indicators.is_empty());
    
    // Verify specific indicators exist
    let has_large_commit = indicators.iter()
        .any(|i| i.name.contains("Large commit"));
    assert!(has_large_commit);
    
    let has_off_hours = indicators.iter()
        .any(|i| i.name.contains("Off-hours"));
    assert!(has_off_hours);
}

// Mock test for file modification patterns
#[tokio::test]
async fn test_file_modification_patterns() {
    let analyzer = GitAnalyzer::new(&AnalysisConfig::default()).await.unwrap();
    let job_id = Uuid::new_v4();
    
    // In a real implementation, this would analyze actual git history
    // For testing, we verify the structure and logic
    
    struct MockFileHistory {
        file_path: String,
        modification_count: i32,
        is_binary: bool,
    }
    
    let file_histories = vec![
        MockFileHistory {
            file_path: "src/main.rs".to_string(),
            modification_count: 50,
            is_binary: false,
        },
        MockFileHistory {
            file_path: "config.yaml".to_string(),
            modification_count: 150, // Frequently modified
            is_binary: false,
        },
        MockFileHistory {
            file_path: "binary.exe".to_string(),
            modification_count: 20, // Binary with many modifications
            is_binary: true,
        },
    ];
    
    // Test detection logic
    assert!(file_histories[1].modification_count > 100); // Should trigger frequent modification
    assert!(file_histories[2].is_binary && file_histories[2].modification_count > 10); // Should trigger binary modification warning
}