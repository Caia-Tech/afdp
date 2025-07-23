# Forensic Procedures and Chain of Custody

## Table of Contents
- [Overview](#overview)
- [Chain of Custody](#chain-of-custody)
- [Evidence Collection](#evidence-collection)
- [Data Integrity](#data-integrity)
- [Legal Admissibility](#legal-admissibility)
- [Incident Response](#incident-response)
- [Compliance Requirements](#compliance-requirements)

## Overview

The Repository Analysis Service implements comprehensive forensic procedures to ensure that all analysis activities maintain legal admissibility and forensic integrity. These procedures are essential for investigations that may result in legal proceedings, regulatory compliance, or internal disciplinary actions.

## Chain of Custody

### Definition and Importance

Chain of custody is the chronological documentation of evidence handling from collection through presentation in legal proceedings. For digital evidence, this includes:

- **Source Authentication**: Verifying the authenticity of the original repository
- **Integrity Preservation**: Ensuring data remains unaltered during analysis
- **Access Logging**: Recording all interactions with evidence
- **Storage Security**: Maintaining secure, tamper-evident storage

### Implementation

#### Custody Record Structure
```rust
#[derive(Debug, Serialize, Deserialize)]
pub struct CustodyRecord {
    pub id: Uuid,
    pub evidence_id: String,
    pub timestamp: DateTime<Utc>,
    pub action: CustodyAction,
    pub actor: CustodyActor,
    pub location: String,
    pub hash_before: Option<String>,
    pub hash_after: Option<String>,
    pub signature: String,
    pub witness: Option<String>,
    pub metadata: HashMap<String, Value>,
}

#[derive(Debug, Serialize, Deserialize)]
pub enum CustodyAction {
    Collected,
    Transferred,
    Analyzed,
    Copied,
    Stored,
    Retrieved,
    Returned,
    Destroyed,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct CustodyActor {
    pub user_id: String,
    pub name: String,
    pub role: String,
    pub organization: String,
    pub badge_number: Option<String>,
    pub certification: Option<String>,
}
```

#### Custody Transfer Protocol
```rust
pub async fn transfer_custody(
    evidence_id: &str,
    from_actor: &CustodyActor,
    to_actor: &CustodyActor,
    reason: &str,
    witness: Option<&CustodyActor>,
) -> Result<CustodyRecord> {
    // Verify current custody holder
    let current_custody = get_current_custody(evidence_id).await?;
    if current_custody.actor.user_id != from_actor.user_id {
        return Err(ForensicError::InvalidCustodyTransfer);
    }
    
    // Generate integrity hash
    let evidence_hash = calculate_evidence_hash(evidence_id).await?;
    
    // Create transfer record
    let transfer_record = CustodyRecord {
        id: Uuid::new_v4(),
        evidence_id: evidence_id.to_string(),
        timestamp: Utc::now(),
        action: CustodyAction::Transferred,
        actor: to_actor.clone(),
        location: get_current_location(),
        hash_before: Some(evidence_hash.clone()),
        hash_after: Some(evidence_hash),
        signature: generate_custody_signature(&transfer_data).await?,
        witness: witness.map(|w| w.name.clone()),
        metadata: HashMap::from([
            ("from_actor".to_string(), json!(from_actor)),
            ("reason".to_string(), json!(reason)),
        ]),
    };
    
    // Store in tamper-evident log
    store_custody_record(&transfer_record).await?;
    
    // Update current custody
    update_current_custody(evidence_id, &transfer_record).await?;
    
    Ok(transfer_record)
}
```

## Evidence Collection

### Repository Acquisition

#### Forensic Cloning Process
```rust
pub async fn forensic_clone_repository(
    repository_url: &str,
    acquisition_context: &AcquisitionContext,
) -> Result<ForensicImage> {
    // Create acquisition record
    let acquisition = EvidenceAcquisition {
        id: Uuid::new_v4(),
        repository_url: repository_url.to_string(),
        timestamp: Utc::now(),
        method: AcquisitionMethod::GitClone,
        tool_version: env!("CARGO_PKG_VERSION").to_string(),
        operator: acquisition_context.operator.clone(),
        case_number: acquisition_context.case_number.clone(),
    };
    
    // Create working directory with chain of custody
    let work_dir = create_forensic_workspace(&acquisition.id).await?;
    
    // Clone repository with full history
    let clone_result = Command::new("git")
        .args(&["clone", "--mirror", repository_url, &work_dir.path])
        .output()
        .await?;
    
    if !clone_result.status.success() {
        return Err(ForensicError::AcquisitionFailed(
            String::from_utf8_lossy(&clone_result.stderr).to_string()
        ));
    }
    
    // Calculate cryptographic hashes
    let hashes = calculate_repository_hashes(&work_dir.path).await?;
    
    // Create forensic image metadata
    let image = ForensicImage {
        id: Uuid::new_v4(),
        acquisition,
        path: work_dir.path.clone(),
        size_bytes: calculate_directory_size(&work_dir.path).await?,
        file_count: count_files(&work_dir.path).await?,
        hashes,
        timestamp: Utc::now(),
    };
    
    // Store image metadata
    store_forensic_image(&image).await?;
    
    // Create initial custody record
    create_initial_custody_record(&image).await?;
    
    Ok(image)
}
```

#### Hash Verification
```rust
#[derive(Debug, Serialize, Deserialize)]
pub struct HashSet {
    pub md5: String,
    pub sha1: String,
    pub sha256: String,
    pub sha512: String,
}

pub async fn calculate_repository_hashes(path: &str) -> Result<HashSet> {
    use tokio::process::Command;
    
    // Calculate multiple hash algorithms for verification
    let md5_output = Command::new("find")
        .args(&[path, "-type", "f", "-exec", "md5sum", "{}", "+"])
        .output()
        .await?;
    
    let sha256_output = Command::new("find")
        .args(&[path, "-type", "f", "-exec", "sha256sum", "{}", "+"])
        .output()
        .await?;
    
    // Combine all file hashes into repository hash
    let md5_combined = hash_file_list(&md5_output.stdout);
    let sha256_combined = hash_file_list(&sha256_output.stdout);
    
    Ok(HashSet {
        md5: md5_combined,
        sha1: calculate_sha1_hash(path).await?,
        sha256: sha256_combined,
        sha512: calculate_sha512_hash(path).await?,
    })
}
```

### File-Level Evidence

#### Individual File Processing
```rust
#[derive(Debug, Serialize, Deserialize)]
pub struct FileEvidence {
    pub id: Uuid,
    pub path: String,
    pub size: u64,
    pub created: Option<DateTime<Utc>>,
    pub modified: DateTime<Utc>,
    pub accessed: Option<DateTime<Utc>>,
    pub permissions: String,
    pub owner: Option<String>,
    pub mime_type: String,
    pub hashes: HashSet,
    pub metadata: FileMetadata,
    pub chain_of_custody: Vec<CustodyRecord>,
}

pub async fn process_file_evidence(
    file_path: &Path,
    parent_acquisition: &EvidenceAcquisition,
) -> Result<FileEvidence> {
    // Gather file system metadata
    let metadata = fs::metadata(file_path).await?;
    let file_metadata = extract_file_metadata(file_path).await?;
    
    // Calculate file hashes
    let hashes = calculate_file_hashes(file_path).await?;
    
    // Detect MIME type
    let mime_type = detect_mime_type(file_path).await?;
    
    // Create evidence record
    let evidence = FileEvidence {
        id: Uuid::new_v4(),
        path: file_path.to_string_lossy().to_string(),
        size: metadata.len(),
        created: metadata.created().ok().map(|t| t.into()),
        modified: metadata.modified().unwrap().into(),
        accessed: metadata.accessed().ok().map(|t| t.into()),
        permissions: format!("{:o}", metadata.permissions().mode()),
        owner: get_file_owner(file_path).await?,
        mime_type,
        hashes,
        metadata: file_metadata,
        chain_of_custody: vec![],
    };
    
    // Store evidence record
    store_file_evidence(&evidence).await?;
    
    Ok(evidence)
}
```

## Data Integrity

### Cryptographic Verification

#### Hash Chain Implementation
```rust
pub struct HashChain {
    blocks: Vec<HashBlock>,
    current_hash: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct HashBlock {
    pub index: u64,
    pub timestamp: DateTime<Utc>,
    pub data_hash: String,
    pub previous_hash: String,
    pub block_hash: String,
    pub nonce: u64,
}

impl HashChain {
    pub fn new() -> Self {
        let genesis_block = HashBlock {
            index: 0,
            timestamp: Utc::now(),
            data_hash: "0".repeat(64),
            previous_hash: "0".repeat(64),
            block_hash: String::new(),
            nonce: 0,
        };
        
        let mut chain = HashChain {
            blocks: vec![genesis_block],
            current_hash: String::new(),
        };
        
        chain.blocks[0].block_hash = chain.calculate_block_hash(&chain.blocks[0]);
        chain.current_hash = chain.blocks[0].block_hash.clone();
        
        chain
    }
    
    pub fn add_evidence(&mut self, evidence_hash: &str) -> Result<()> {
        let new_block = HashBlock {
            index: self.blocks.len() as u64,
            timestamp: Utc::now(),
            data_hash: evidence_hash.to_string(),
            previous_hash: self.current_hash.clone(),
            block_hash: String::new(),
            nonce: 0,
        };
        
        let block_hash = self.calculate_block_hash(&new_block);
        let mut final_block = new_block;
        final_block.block_hash = block_hash.clone();
        
        self.blocks.push(final_block);
        self.current_hash = block_hash;
        
        Ok(())
    }
    
    pub fn verify_integrity(&self) -> Result<bool> {
        for (i, block) in self.blocks.iter().enumerate() {
            // Verify block hash
            let calculated_hash = self.calculate_block_hash(block);
            if calculated_hash != block.block_hash {
                return Ok(false);
            }
            
            // Verify chain linkage (except genesis block)
            if i > 0 {
                let previous_block = &self.blocks[i - 1];
                if block.previous_hash != previous_block.block_hash {
                    return Ok(false);
                }
            }
        }
        
        Ok(true)
    }
    
    fn calculate_block_hash(&self, block: &HashBlock) -> String {
        use sha2::{Sha256, Digest};
        
        let mut hasher = Sha256::new();
        hasher.update(block.index.to_be_bytes());
        hasher.update(block.timestamp.timestamp().to_be_bytes());
        hasher.update(&block.data_hash);
        hasher.update(&block.previous_hash);
        hasher.update(block.nonce.to_be_bytes());
        
        format!("{:x}", hasher.finalize())
    }
}
```

### Digital Signatures

#### Evidence Signing
```rust
use ring::{rand, signature};
use ring::signature::{Ed25519KeyPair, UnparsedPublicKey, ED25519};

pub struct ForensicSigner {
    key_pair: Ed25519KeyPair,
    public_key: Vec<u8>,
}

impl ForensicSigner {
    pub fn new() -> Result<Self> {
        let rng = rand::SystemRandom::new();
        let pkcs8_bytes = signature::Ed25519KeyPair::generate_pkcs8(&rng)?;
        let key_pair = signature::Ed25519KeyPair::from_pkcs8(pkcs8_bytes.as_ref())?;
        let public_key = key_pair.public_key().as_ref().to_vec();
        
        Ok(ForensicSigner {
            key_pair,
            public_key,
        })
    }
    
    pub fn sign_evidence(&self, evidence: &FileEvidence) -> Result<String> {
        // Create canonical representation for signing
        let evidence_json = serde_json::to_string(evidence)?;
        let signature = self.key_pair.sign(evidence_json.as_bytes());
        
        // Encode signature as base64
        Ok(base64::encode(signature.as_ref()))
    }
    
    pub fn verify_signature(
        &self,
        evidence: &FileEvidence,
        signature: &str,
    ) -> Result<bool> {
        let signature_bytes = base64::decode(signature)?;
        let evidence_json = serde_json::to_string(evidence)?;
        
        let public_key = UnparsedPublicKey::new(&ED25519, &self.public_key);
        
        match public_key.verify(evidence_json.as_bytes(), &signature_bytes) {
            Ok(_) => Ok(true),
            Err(_) => Ok(false),
        }
    }
}
```

### Tamper Detection

#### File System Monitoring
```rust
use notify::{Watcher, RecursiveMode, Event, EventKind};

pub struct TamperDetector {
    watcher: RecommendedWatcher,
    baseline_hashes: HashMap<String, String>,
    alert_sender: mpsc::Sender<TamperAlert>,
}

#[derive(Debug)]
pub struct TamperAlert {
    pub file_path: String,
    pub alert_type: TamperAlertType,
    pub timestamp: DateTime<Utc>,
    pub details: String,
}

#[derive(Debug)]
pub enum TamperAlertType {
    FileModified,
    FileDeleted,
    FileAdded,
    PermissionsChanged,
    TimestampModified,
}

impl TamperDetector {
    pub fn new(evidence_path: &str) -> Result<Self> {
        let (tx, rx) = mpsc::channel();
        
        let mut watcher = notify::recommended_watcher(move |res| {
            match res {
                Ok(event) => {
                    if let Err(e) = tx.send(event) {
                        error!("Failed to send file system event: {}", e);
                    }
                }
                Err(e) => error!("File system watch error: {:?}", e),
            }
        })?;
        
        // Start watching the evidence directory
        watcher.watch(Path::new(evidence_path), RecursiveMode::Recursive)?;
        
        // Calculate baseline hashes
        let baseline_hashes = calculate_baseline_hashes(evidence_path).await?;
        
        let (alert_tx, alert_rx) = mpsc::channel();
        
        // Spawn event processing task
        let detector = TamperDetector {
            watcher,
            baseline_hashes,
            alert_sender: alert_tx,
        };
        
        tokio::spawn(async move {
            while let Ok(event) = rx.recv() {
                if let Err(e) = process_file_event(event, &detector).await {
                    error!("Error processing file event: {}", e);
                }
            }
        });
        
        Ok(detector)
    }
    
    async fn process_file_event(&self, event: Event) -> Result<()> {
        match event.kind {
            EventKind::Modify(_) => {
                for path in event.paths {
                    if let Some(path_str) = path.to_str() {
                        let current_hash = calculate_file_hash(&path).await?;
                        
                        if let Some(baseline_hash) = self.baseline_hashes.get(path_str) {
                            if current_hash != *baseline_hash {
                                let alert = TamperAlert {
                                    file_path: path_str.to_string(),
                                    alert_type: TamperAlertType::FileModified,
                                    timestamp: Utc::now(),
                                    details: format!(
                                        "Hash changed from {} to {}",
                                        baseline_hash, current_hash
                                    ),
                                };
                                
                                self.alert_sender.send(alert)?;
                            }
                        }
                    }
                }
            }
            EventKind::Remove(_) => {
                for path in event.paths {
                    if let Some(path_str) = path.to_str() {
                        let alert = TamperAlert {
                            file_path: path_str.to_string(),
                            alert_type: TamperAlertType::FileDeleted,
                            timestamp: Utc::now(),
                            details: "File was deleted".to_string(),
                        };
                        
                        self.alert_sender.send(alert)?;
                    }
                }
            }
            _ => {}
        }
        
        Ok(())
    }
}
```

## Legal Admissibility

### Requirements for Legal Proceedings

#### Federal Rules of Evidence (US)
The Repository Analysis Service implements procedures to comply with Federal Rules of Evidence:

**Rule 901 - Authentication and Identification**
- Digital evidence must be authenticated to show it is what it claims to be
- Implemented through cryptographic hashing and digital signatures
- Chain of custody documentation proves evidence integrity

**Rule 902 - Evidence That Is Self-Authenticating**
- Digital signatures and hash verification provide self-authentication
- Automated logging creates admissible business records

#### Implementation
```rust
#[derive(Debug, Serialize, Deserialize)]
pub struct LegalAdmissibilityReport {
    pub evidence_id: String,
    pub case_number: String,
    pub jurisdiction: String,
    pub collection_date: DateTime<Utc>,
    pub collection_method: String,
    pub collection_tool: String,
    pub collection_version: String,
    pub custodian: CustodyActor,
    pub integrity_verification: IntegrityVerification,
    pub chain_of_custody: Vec<CustodyRecord>,
    pub authentication_methods: Vec<AuthenticationMethod>,
    pub expert_certification: Option<ExpertCertification>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct IntegrityVerification {
    pub original_hash: String,
    pub current_hash: String,
    pub verification_date: DateTime<Utc>,
    pub hash_algorithm: String,
    pub verification_tool: String,
    pub matches: bool,
}

pub async fn generate_admissibility_report(
    evidence_id: &str,
    case_context: &CaseContext,
) -> Result<LegalAdmissibilityReport> {
    let evidence = get_evidence_by_id(evidence_id).await?;
    let custody_records = get_custody_records(evidence_id).await?;
    
    // Verify current integrity
    let current_hash = calculate_evidence_hash(evidence_id).await?;
    let integrity_verification = IntegrityVerification {
        original_hash: evidence.hashes.sha256.clone(),
        current_hash: current_hash.clone(),
        verification_date: Utc::now(),
        hash_algorithm: "SHA-256".to_string(),
        verification_tool: "AFDP Repository Analysis Service".to_string(),
        matches: current_hash == evidence.hashes.sha256,
    };
    
    let report = LegalAdmissibilityReport {
        evidence_id: evidence_id.to_string(),
        case_number: case_context.case_number.clone(),
        jurisdiction: case_context.jurisdiction.clone(),
        collection_date: evidence.acquisition.timestamp,
        collection_method: "Forensic Git Clone".to_string(),
        collection_tool: "AFDP Repository Analysis Service".to_string(),
        collection_version: env!("CARGO_PKG_VERSION").to_string(),
        custodian: evidence.acquisition.operator,
        integrity_verification,
        chain_of_custody: custody_records,
        authentication_methods: vec![
            AuthenticationMethod::CryptographicHash,
            AuthenticationMethod::DigitalSignature,
            AuthenticationMethod::ChainOfCustody,
        ],
        expert_certification: get_expert_certification(&case_context.expert_id).await?,
    };
    
    Ok(report)
}
```

### Expert Witness Support

#### Automated Report Generation
```rust
pub async fn generate_expert_witness_report(
    analysis_id: &str,
    expert_profile: &ExpertProfile,
) -> Result<ExpertWitnessReport> {
    let analysis = get_analysis_by_id(analysis_id).await?;
    
    let report = ExpertWitnessReport {
        expert_qualifications: expert_profile.qualifications.clone(),
        methodology: describe_analysis_methodology(&analysis).await?,
        tools_used: list_analysis_tools(&analysis).await?,
        findings_summary: summarize_findings(&analysis).await?,
        detailed_findings: analysis.detailed_results.clone(),
        reliability_assessment: assess_reliability(&analysis).await?,
        limitations: identify_limitations(&analysis).await?,
        conclusions: generate_conclusions(&analysis).await?,
        exhibits: prepare_exhibits(&analysis).await?,
        bibliography: generate_bibliography().await?,
    };
    
    Ok(report)
}
```

## Incident Response

### Automated Response Procedures

#### Security Incident Detection
```rust
#[derive(Debug, Serialize, Deserialize)]
pub struct SecurityIncident {
    pub id: Uuid,
    pub incident_type: IncidentType,
    pub severity: IncidentSeverity,
    pub detected_at: DateTime<Utc>,
    pub description: String,
    pub affected_evidence: Vec<String>,
    pub indicators: Vec<Indicator>,
    pub response_actions: Vec<ResponseAction>,
    pub status: IncidentStatus,
}

#[derive(Debug, Serialize, Deserialize)]
pub enum IncidentType {
    UnauthorizedAccess,
    DataTampering,
    EvidenceDestruction,
    SystemCompromise,
    PolicyViolation,
    MalwareDetection,
}

pub async fn handle_security_incident(
    incident: SecurityIncident,
) -> Result<IncidentResponse> {
    // Immediate containment
    let containment_actions = execute_containment_procedures(&incident).await?;
    
    // Preserve evidence
    let evidence_preservation = preserve_incident_evidence(&incident).await?;
    
    // Notify stakeholders
    notify_incident_stakeholders(&incident).await?;
    
    // Begin investigation
    let investigation_id = initiate_incident_investigation(&incident).await?;
    
    // Document response
    let response = IncidentResponse {
        incident_id: incident.id,
        response_timestamp: Utc::now(),
        containment_actions,
        evidence_preservation,
        investigation_id,
        next_steps: generate_incident_next_steps(&incident).await?,
    };
    
    store_incident_response(&response).await?;
    
    Ok(response)
}
```

### Evidence Preservation During Incidents

#### Emergency Evidence Protection
```rust
pub async fn emergency_evidence_protection(
    evidence_ids: &[String],
    incident_context: &IncidentContext,
) -> Result<ProtectionResponse> {
    let mut protected_evidence = Vec::new();
    
    for evidence_id in evidence_ids {
        // Create emergency backup
        let backup_location = create_emergency_backup(evidence_id).await?;
        
        // Calculate verification hash
        let protection_hash = calculate_evidence_hash(evidence_id).await?;
        
        // Lock evidence from modification
        apply_evidence_write_lock(evidence_id).await?;
        
        // Create protection record
        let protection_record = EvidenceProtection {
            evidence_id: evidence_id.clone(),
            protection_timestamp: Utc::now(),
            incident_id: incident_context.incident_id.clone(),
            backup_location,
            protection_hash,
            protection_level: ProtectionLevel::Emergency,
            expiry: incident_context.protection_expiry,
        };
        
        store_protection_record(&protection_record).await?;
        protected_evidence.push(protection_record);
    }
    
    Ok(ProtectionResponse {
        protected_count: protected_evidence.len(),
        protected_evidence,
        protection_timestamp: Utc::now(),
    })
}
```

## Compliance Requirements

### Regulatory Framework Support

#### GDPR Compliance
```rust
pub struct GDPRComplianceManager {
    data_processor: DataProcessor,
    consent_manager: ConsentManager,
    retention_policy: RetentionPolicy,
}

impl GDPRComplianceManager {
    pub async fn process_data_subject_request(
        &self,
        request: DataSubjectRequest,
    ) -> Result<DataSubjectResponse> {
        match request.request_type {
            DataSubjectRequestType::Access => {
                self.handle_access_request(&request).await
            }
            DataSubjectRequestType::Rectification => {
                self.handle_rectification_request(&request).await
            }
            DataSubjectRequestType::Erasure => {
                self.handle_erasure_request(&request).await
            }
            DataSubjectRequestType::Portability => {
                self.handle_portability_request(&request).await
            }
            DataSubjectRequestType::Objection => {
                self.handle_objection_request(&request).await
            }
        }
    }
    
    async fn handle_erasure_request(
        &self,
        request: &DataSubjectRequest,
    ) -> Result<DataSubjectResponse> {
        // Identify all data related to the subject
        let related_data = self.find_data_subject_data(&request.subject_id).await?;
        
        // Check legal basis for retention
        let retention_requirements = self.check_retention_requirements(&related_data).await?;
        
        // Erase data where legally permissible
        let erasure_results = self.perform_secure_erasure(&related_data, &retention_requirements).await?;
        
        // Update audit logs
        self.log_erasure_action(request, &erasure_results).await?;
        
        Ok(DataSubjectResponse {
            request_id: request.id.clone(),
            status: ResponseStatus::Completed,
            completion_date: Utc::now(),
            details: format!("Erased {} data items, retained {} items due to legal requirements", 
                           erasure_results.erased_count, 
                           erasure_results.retained_count),
            evidence: erasure_results.evidence_hash,
        })
    }
}
```

#### SOX Compliance (Financial Records)
```rust
pub struct SOXComplianceValidator {
    retention_rules: HashMap<String, Duration>,
    access_controls: AccessControlMatrix,
    audit_logger: AuditLogger,
}

impl SOXComplianceValidator {
    pub async fn validate_financial_analysis(
        &self,
        analysis: &AnalysisResult,
    ) -> Result<SOXComplianceReport> {
        let mut violations = Vec::new();
        
        // Check data retention requirements
        if let Some(violation) = self.check_retention_compliance(analysis).await? {
            violations.push(violation);
        }
        
        // Verify access controls
        if let Some(violation) = self.check_access_controls(analysis).await? {
            violations.push(violation);
        }
        
        // Validate audit trail completeness
        if let Some(violation) = self.check_audit_trail(analysis).await? {
            violations.push(violation);
        }
        
        // Check for conflicts of interest
        if let Some(violation) = self.check_conflicts_of_interest(analysis).await? {
            violations.push(violation);
        }
        
        let compliance_status = if violations.is_empty() {
            ComplianceStatus::Compliant
        } else {
            ComplianceStatus::NonCompliant
        };
        
        Ok(SOXComplianceReport {
            analysis_id: analysis.id.clone(),
            validation_date: Utc::now(),
            status: compliance_status,
            violations,
            recommendations: generate_compliance_recommendations(&violations).await?,
            next_review_date: Utc::now() + Duration::days(90),
        })
    }
}
```

### Audit Trail Requirements

#### Comprehensive Audit Logging
```rust
#[derive(Debug, Serialize, Deserialize)]
pub struct AuditLogEntry {
    pub id: Uuid,
    pub timestamp: DateTime<Utc>,
    pub event_type: AuditEventType,
    pub actor: AuditActor,
    pub resource: String,
    pub action: String,
    pub outcome: AuditOutcome,
    pub details: HashMap<String, Value>,
    pub ip_address: Option<String>,
    pub user_agent: Option<String>,
    pub session_id: Option<String>,
    pub risk_score: Option<u8>,
}

pub struct ComprehensiveAuditor {
    storage: AuditStorage,
    encryptor: AuditEncryptor,
    integrity_checker: IntegrityChecker,
}

impl ComprehensiveAuditor {
    pub async fn log_evidence_access(
        &self,
        evidence_id: &str,
        actor: &AuditActor,
        context: &AccessContext,
    ) -> Result<()> {
        let entry = AuditLogEntry {
            id: Uuid::new_v4(),
            timestamp: Utc::now(),
            event_type: AuditEventType::EvidenceAccess,
            actor: actor.clone(),
            resource: evidence_id.to_string(),
            action: "read".to_string(),
            outcome: AuditOutcome::Success,
            details: HashMap::from([
                ("access_method".to_string(), json!(context.access_method)),
                ("purpose".to_string(), json!(context.purpose)),
                ("case_number".to_string(), json!(context.case_number)),
            ]),
            ip_address: context.ip_address.clone(),
            user_agent: context.user_agent.clone(),
            session_id: context.session_id.clone(),
            risk_score: self.calculate_risk_score(actor, context).await?,
        };
        
        // Encrypt sensitive audit data
        let encrypted_entry = self.encryptor.encrypt_audit_entry(&entry).await?;
        
        // Store with integrity protection
        self.storage.store_entry(&encrypted_entry).await?;
        
        // Update integrity chain
        self.integrity_checker.add_entry_to_chain(&entry).await?;
        
        Ok(())
    }
}
```

This comprehensive forensic procedures document ensures that the Repository Analysis Service maintains the highest standards of evidence handling, legal admissibility, and regulatory compliance throughout the investigation lifecycle.