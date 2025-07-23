# AFDP Repository Analysis Service

## Overview

The **Repository Analysis Service** is a comprehensive forensic investigation platform designed to analyze any type of repository for security violations, compliance issues, evidence discovery, and anomaly detection. Unlike traditional code analysis tools, this service handles diverse repository types including source code, legal evidence, financial records, communication logs, security incidents, research data, and compliance files.

## 🎯 Mission Statement

Provide enterprise-grade forensic analysis capabilities across all repository types, enabling organizations to:
- **Investigate Security Incidents** - Detect backdoors, data exfiltration, and malicious activities
- **Ensure Compliance** - Automatically identify policy violations and regulatory breaches  
- **Discover Evidence** - Semantic search and correlation across disparate data sources
- **Maintain Chain of Custody** - Full audit trails for legal admissibility
- **Detect Anomalies** - AI-powered pattern recognition for suspicious activities
- **Distribute Intelligence** - Real-time selective sharing with stakeholders (legal, insurance, allies)

## 🌐 Distributed Network Intelligence

**What makes this revolutionary:** You control exactly what gets logged and who receives findings in real-time. Whether it's legal teams, insurance providers, law enforcement partners, or regulatory bodies - the intelligence goes where you need it, when you need it there.

This creates unprecedented coordination capabilities:
- **Legal teams** get evidence as it's discovered, not months later
- **Insurance carriers** receive proactive risk reports for premium negotiations  
- **Law enforcement** gets threat intelligence in real-time for coordinated response
- **Regulatory bodies** receive compliance reports demonstrating good faith efforts
- **Business partners** get selective transparency to build trust

## 🏗️ Architecture

### Service Design Philosophy
- **Universal Analysis** - Handle any file type with appropriate parsers
- **Forensic Integrity** - Immutable audit trails and chain of custody
- **Scalable Processing** - Temporal workflows for long-running analysis jobs
- **Multi-Protocol Access** - REST, gRPC, and Pulsar interfaces
- **AI-Enhanced Discovery** - Semantic search and similarity detection
- **Selective Distribution** - Real-time intelligence sharing to chosen stakeholder networks
- **Configurable Logging** - You control what gets recorded and who receives it

### Core Components

```
┌─────────────────────────────────────────────────────────────┐
│                  Repository Analysis Service                │
├─────────────────────────────────────────────────────────────┤
│  REST API     │  gRPC Server  │  Pulsar Producer/Consumer   │
├─────────────────────────────────────────────────────────────┤
│              Analysis Engine & Workflow Orchestrator        │
├─────────────────────────────────────────────────────────────┤
│  File Parser  │  Content      │  Forensic     │  AI/ML      │
│  Registry     │  Classifier   │  Validator    │  Engine     │
├─────────────────────────────────────────────────────────────┤
│  PostgreSQL   │  Object       │  Qdrant       │  Temporal   │
│  (Metadata)   │  Storage      │  (Vectors)    │  (Workflows)│
└─────────────────────────────────────────────────────────────┘
```

## 📊 Supported Repository Types

### 1. Source Code Repositories
- **Languages**: All major programming languages
- **Analysis**: Security vulnerabilities, backdoors, IP theft, code quality
- **Formats**: Git, SVN, Mercurial, Perforce
- **Outputs**: SAST findings, dependency analysis, secret detection

### 2. Legal Evidence Repositories  
- **Documents**: PDFs, Word docs, emails, depositions
- **Analysis**: Privilege detection, PII identification, case correlation
- **Formats**: EDRM, PST, EML, legal XML standards
- **Outputs**: Discovery reports, privilege logs, redacted documents

### 3. Financial Records
- **Data**: Transaction logs, accounting files, audit trails
- **Analysis**: Fraud detection, compliance violations, anomaly patterns
- **Formats**: CSV, Excel, PDF statements, database exports
- **Outputs**: Risk scores, violation reports, audit summaries

### 4. Communication Logs
- **Sources**: Email, Slack, Teams, phone records, meeting transcripts
- **Analysis**: Sentiment analysis, threat detection, policy violations
- **Formats**: MBOX, JSON exports, call detail records
- **Outputs**: Communication timelines, relationship graphs, alert summaries

### 5. Security Incident Files
- **Artifacts**: Malware samples, network captures, forensic images
- **Analysis**: IOC extraction, attack vector identification, impact assessment
- **Formats**: PCAP, memory dumps, disk images, YARA rules
- **Outputs**: Incident reports, IOC feeds, remediation recommendations

### 6. Research Data
- **Content**: Datasets, publications, experimental results, notebooks
- **Analysis**: Data integrity, academic misconduct, IP protection
- **Formats**: CSV, HDF5, Jupyter notebooks, research papers
- **Outputs**: Integrity reports, similarity analysis, plagiarism detection

## 🔧 Technical Specifications

### Technology Stack
- **Language**: Rust (primary) with Go compatibility layer
- **Workflow Engine**: Temporal (for long-running analysis jobs)
- **APIs**: REST (HTTP), gRPC, Apache Pulsar
- **Storage**: PostgreSQL (metadata), Object Storage (files), Qdrant (vectors)
- **Security**: Integration with AFDP Policy Engine for access control

### Performance Requirements
- **Throughput**: Process 10GB+ repositories within 1 hour
- **Concurrency**: Handle 50+ simultaneous analysis jobs
- **Scalability**: Horizontal scaling via Kubernetes
- **Availability**: 99.9% uptime with graceful degradation

### Security & Compliance
- **Encryption**: AES-256 at rest, TLS 1.3 in transit
- **Authentication**: JWT tokens via AFDP Policy Engine
- **Authorization**: RBAC with fine-grained permissions
- **Audit**: Complete chain of custody for all operations
- **Compliance**: SOC 2, FedRAMP, GDPR ready

## 🚀 Key Features

### Universal File Analysis
- **Smart Parsing**: Automatic file type detection and appropriate parser selection
- **Content Extraction**: Text, metadata, and structured data from any format
- **Binary Analysis**: Malware detection, executable analysis, embedded artifacts
- **Archive Support**: ZIP, TAR, 7z with recursive analysis

### Forensic Investigation
- **Timeline Reconstruction**: Git history analysis, file lifecycle tracking
- **Tampering Detection**: Hash verification, timestamp validation, signature checks
- **Cross-Repository Analysis**: Data correlation across multiple sources
- **Chain of Custody**: Immutable audit trails with cryptographic signatures

### AI-Powered Discovery
- **Semantic Search**: Find conceptually similar documents across repositories
- **Anomaly Detection**: ML models for suspicious pattern identification
- **Classification**: Automatic content categorization and sensitivity labeling
- **Relationship Mapping**: Entity extraction and connection analysis

### Multi-Modal Analysis
- **Text Analysis**: NLP for sentiment, topics, entities, and relationships
- **Image Analysis**: OCR, facial recognition, metadata extraction
- **Code Analysis**: AST parsing, dependency graphs, vulnerability scanning
- **Network Analysis**: Communication pattern detection, graph analytics

## 📋 API Interfaces

### REST API
```
POST   /api/v1/analysis/submit      # Submit repository for analysis
GET    /api/v1/analysis/{id}/status # Check analysis status
GET    /api/v1/analysis/{id}/report # Download analysis report
POST   /api/v1/search/semantic      # Semantic search across results
GET    /api/v1/health               # Service health check
```

### gRPC Interface
```protobuf
service RepositoryAnalysis {
  rpc SubmitAnalysis(AnalysisRequest) returns (AnalysisResponse);
  rpc GetAnalysisStatus(StatusRequest) returns (StatusResponse);
  rpc StreamAnalysisResults(StatusRequest) returns (stream AnalysisResult);
  rpc SearchSimilarContent(SearchRequest) returns (SearchResponse);
}
```

### Pulsar Events
```
Topics:
- repo.analysis.submitted    # New analysis job created
- repo.analysis.started      # Analysis job began processing
- repo.violation.detected    # Policy/compliance violation found
- repo.anomaly.identified    # Suspicious pattern detected
- repo.analysis.completed    # Analysis job finished
- repo.evidence.discovered   # Potential evidence artifact found
```

## 🔄 Workflow Architecture

### Analysis Pipeline
```
Repository Submission → Validation → Cloning → File Discovery
         ↓
Content Extraction → Classification → Security Scanning → AI Analysis
         ↓
Correlation Analysis → Report Generation → Evidence Packaging → Storage
```

### Temporal Workflows
- **Repository Ingestion**: Clone, validate, and catalog repository contents
- **Content Analysis**: Parse files, extract metadata, classify content
- **Security Scanning**: Vulnerability detection, secret scanning, malware analysis
- **Forensic Analysis**: Timeline reconstruction, tampering detection
- **Report Generation**: Compile findings, generate visualizations, package evidence

## 📈 Use Cases

### Enterprise Security
- **Insider Threat Detection**: Analyze code commits for malicious modifications
- **Data Loss Prevention**: Detect unauthorized data exfiltration attempts
- **Supply Chain Security**: Verify third-party code integrity and licensing
- **Incident Response**: Rapid forensic analysis of compromised repositories

### Legal & Compliance
- **eDiscovery**: Automated document review and privilege identification
- **Regulatory Compliance**: Continuous monitoring for policy violations
- **Intellectual Property**: Code similarity analysis for IP protection
- **Audit Preparation**: Automated evidence collection and documentation

### Research & Academia
- **Academic Integrity**: Plagiarism detection across research outputs
- **Data Governance**: Ensure research data meets institutional policies
- **Collaboration Analysis**: Study patterns in academic collaboration
- **Grant Compliance**: Verify deliverables meet funding requirements

## 🛡️ Security Considerations

### Threat Model
- **Malicious Repositories**: Sandboxed analysis environment
- **Data Exfiltration**: Network isolation and monitoring
- **Privilege Escalation**: Least-privilege execution model
- **Supply Chain Attacks**: Verification of analysis tool integrity

### Privacy Protection
- **PII Detection**: Automatic identification and redaction
- **Consent Management**: Respect data subject rights and preferences
- **Data Minimization**: Process only necessary information
- **Retention Policies**: Automated deletion based on legal requirements

## 📊 Metrics & Monitoring

### Performance Metrics
- Analysis throughput (repos/hour)
- Average processing time per repository size
- Resource utilization (CPU, memory, storage)
- Queue depth and processing latency

### Quality Metrics
- False positive/negative rates for security findings
- Coverage percentage by file type
- Accuracy of content classification
- User satisfaction scores

### Security Metrics
- Failed authentication attempts
- Unauthorized access attempts
- Data integrity violations
- Compliance audit results

## 🔧 Configuration

### Environment Variables
```bash
# Service Configuration
REPO_ANALYSIS_PORT=8080
REPO_ANALYSIS_LOG_LEVEL=info
REPO_ANALYSIS_WORKER_COUNT=10

# Storage Configuration
POSTGRES_URL=postgresql://user:pass@localhost/repo_analysis
OBJECT_STORAGE_URL=s3://bucket/repo-analysis
QDRANT_URL=http://localhost:6333

# Integration Configuration
AFDP_POLICY_ENGINE_URL=http://localhost:8081
TEMPORAL_HOST=localhost:7233
PULSAR_URL=pulsar://localhost:6650

# Security Configuration
JWT_SECRET_KEY=your-secret-key
ENCRYPTION_KEY=your-encryption-key
SANDBOX_ENABLED=true
```

### Analysis Configuration
```yaml
analysis:
  timeout: "2h"
  max_file_size: "100MB"
  max_repo_size: "10GB"
  parallel_workers: 5
  
parsers:
  - name: "code"
    types: [".go", ".rs", ".py", ".js", ".java"]
    enabled: true
  - name: "documents"
    types: [".pdf", ".docx", ".txt"]
    enabled: true
  - name: "archives"
    types: [".zip", ".tar", ".gz"]
    enabled: true
    
security:
  sandbox_timeout: "30m"
  network_isolation: true
  resource_limits:
    cpu: "2"
    memory: "4Gi"
    disk: "10Gi"
```

## 🚀 Getting Started

### Prerequisites
- Rust 1.70+ or Go 1.21+
- PostgreSQL 14+
- Temporal Cluster
- Apache Pulsar
- Qdrant Vector Database

### Quick Start
```bash
# Clone the repository
git clone https://github.com/caia-tech/afdp-repository-analysis
cd afdp-repository-analysis

# Start dependencies
docker-compose up -d postgres temporal pulsar qdrant

# Configure environment
cp .env.example .env
# Edit .env with your configuration

# Build and run
cargo build --release
./target/release/repo-analysis-server

# Submit test analysis
curl -X POST http://localhost:8080/api/v1/analysis/submit \
  -H "Content-Type: application/json" \
  -d '{
    "repository_url": "https://github.com/example/repo",
    "analysis_type": "security",
    "notify_webhook": "https://your-webhook.com/analysis-complete"
  }'
```

## 📚 Documentation

- [API Reference](docs/api-reference.md)
- [Architecture](docs/architecture.md)
- [Forensic Procedures](docs/forensic-procedures.md)
- [Security Architecture](docs/security.md)
- [Integration Guide](docs/integration.md)

## 🌍 Real-World Applications

**See comprehensive use cases:**
- **[Public Safety Usage](../../PUBLIC-SAFETY-USAGE.md)** - Law enforcement, terrorism prevention, threat analysis
- **[Business Usage](../../BUSINESS-USAGE.md)** - Litigation prevention, compliance monitoring, risk management

## 🤝 Contributing

We welcome contributions! Please see our [Contributing Guide](CONTRIBUTING.md) for details on:
- Code style and standards
- Testing requirements
- Security review process
- Documentation standards

## 📄 License

This project is licensed under the Apache License 2.0 - see the [LICENSE](LICENSE) file for details.


---

*Part of the AFDP (Autonomous Forensic Data Platform) ecosystem by Caia Tech*
