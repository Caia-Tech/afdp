# API Reference

## Table of Contents
- [REST API](#rest-api)
- [gRPC API](#grpc-api)
- [Pulsar Events](#pulsar-events)
- [Authentication](#authentication)
- [Error Handling](#error-handling)
- [Rate Limiting](#rate-limiting)
- [Examples](#examples)

## REST API

### Base URL
```
https://api.afdp.caia.tech/repository-analysis/v1
```

### Authentication
All requests require a valid JWT token in the Authorization header:
```
Authorization: Bearer <jwt_token>
```

### Content Type
```
Content-Type: application/json
```

---

## Analysis Endpoints

### Submit Repository Analysis

Submit a repository for comprehensive forensic analysis.

**Endpoint:** `POST /analysis/submit`

**Request Body:**
```json
{
  "repository_url": "https://github.com/example/repo.git",
  "repository_type": "git",
  "analysis_type": "comprehensive",
  "priority": "high",
  "case_number": "CASE-2024-001",
  "notify_webhook": "https://your-system.com/webhook",
  "configuration": {
    "include_git_history": true,
    "deep_file_analysis": true,
    "malware_scanning": true,
    "pii_detection": true,
    "similarity_analysis": true,
    "max_file_size_mb": 100,
    "timeout_hours": 24
  },
  "metadata": {
    "investigator": "jane.doe@company.com",
    "legal_hold": true,
    "retention_days": 2555
  }
}
```

**Response:**
```json
{
  "job_id": "550e8400-e29b-41d4-a716-446655440000",
  "status": "submitted",
  "estimated_completion": "2024-07-24T10:30:00Z",
  "repository_url": "https://github.com/example/repo.git",
  "analysis_type": "comprehensive",
  "created_at": "2024-07-23T10:00:00Z",
  "configuration": {
    "include_git_history": true,
    "deep_file_analysis": true,
    "malware_scanning": true,
    "pii_detection": true,
    "similarity_analysis": true
  }
}
```

**HTTP Status Codes:**
- `201 Created` - Analysis job created successfully
- `400 Bad Request` - Invalid request parameters
- `401 Unauthorized` - Invalid or missing authentication
- `403 Forbidden` - Insufficient permissions
- `409 Conflict` - Repository already being analyzed
- `422 Unprocessable Entity` - Repository cannot be accessed

---

### Get Analysis Status

Retrieve the current status and progress of an analysis job.

**Endpoint:** `GET /analysis/{job_id}/status`

**Response:**
```json
{
  "job_id": "550e8400-e29b-41d4-a716-446655440000",
  "status": "in_progress",
  "progress_percentage": 65,
  "current_phase": "security_scanning",
  "started_at": "2024-07-23T10:05:00Z",
  "estimated_completion": "2024-07-23T12:30:00Z",
  "files_processed": 1250,
  "total_files": 1923,
  "phases_completed": [
    "repository_cloning",
    "file_discovery",
    "content_extraction",
    "classification"
  ],
  "current_phase_details": {
    "phase": "security_scanning",
    "progress": "Running SAST analysis",
    "files_scanned": 850,
    "vulnerabilities_found": 12
  },
  "errors": [],
  "warnings": [
    {
      "message": "Large binary file skipped",
      "file_path": "assets/video.mp4",
      "timestamp": "2024-07-23T11:15:00Z"
    }
  ]
}
```

**HTTP Status Codes:**
- `200 OK` - Status retrieved successfully
- `404 Not Found` - Job not found
- `403 Forbidden` - Access denied to job

---

### Get Analysis Results

Retrieve the complete analysis results and findings.

**Endpoint:** `GET /analysis/{job_id}/results`

**Query Parameters:**
- `format` - Response format: `json`, `html`, `pdf` (default: `json`)
- `include_raw_data` - Include raw scan outputs: `true`, `false` (default: `false`)
- `classification_filter` - Filter by classification: `pii`, `confidential`, `malware`, etc.

**Response:**
```json
{
  "job_id": "550e8400-e29b-41d4-a716-446655440000",
  "analysis_completed_at": "2024-07-23T12:28:00Z",
  "duration_seconds": 8280,
  "repository_info": {
    "url": "https://github.com/example/repo.git",
    "size_bytes": 52428800,
    "file_count": 1923,
    "commit_count": 456,
    "contributors": 23,
    "languages": ["Python", "JavaScript", "Go", "Shell"],
    "last_commit": "2024-07-20T14:30:00Z"
  },
  "summary": {
    "risk_score": 7.2,
    "classification": "medium_risk",
    "total_findings": 45,
    "critical_findings": 2,
    "high_findings": 8,
    "medium_findings": 15,
    "low_findings": 20,
    "pii_instances": 12,
    "secrets_found": 3,
    "malware_detected": false
  },
  "findings": [
    {
      "id": "finding-001",
      "type": "secret_exposure",
      "severity": "critical",
      "title": "API Key Exposed in Source Code",
      "description": "AWS API key found in plaintext in configuration file",
      "file_path": "config/production.yaml",
      "line_number": 42,
      "evidence": "aws_access_key_id: AKIA...",
      "recommendation": "Remove hardcoded credentials and use environment variables",
      "confidence": 0.95
    },
    {
      "id": "finding-002",
      "type": "vulnerability",
      "severity": "high",
      "title": "SQL Injection Vulnerability",
      "description": "Potential SQL injection in user input handling",
      "file_path": "src/database/queries.py",
      "line_number": 156,
      "cve_id": "CWE-89",
      "recommendation": "Use parameterized queries",
      "confidence": 0.87
    }
  ],
  "file_analysis": {
    "total_files": 1923,
    "analyzed_files": 1890,
    "skipped_files": 33,
    "by_type": {
      "source_code": 1456,
      "documentation": 234,
      "configuration": 89,
      "binary": 144
    },
    "classification_summary": {
      "public": 1678,
      "internal": 189,
      "confidential": 23,
      "restricted": 0
    }
  },
  "git_analysis": {
    "suspicious_commits": [
      {
        "commit_hash": "a1b2c3d4e5f6",
        "author": "unknown@example.com",
        "timestamp": "2024-07-15T02:30:00Z",
        "message": "Quick fix",
        "risk_indicators": ["unusual_time", "vague_message", "large_changes"]
      }
    ],
    "deleted_files": [
      {
        "file_path": "secrets/api_keys.txt",
        "deleted_in_commit": "b2c3d4e5f6a1",
        "recovery_possible": true
      }
    ]
  },
  "similarity_analysis": {
    "potential_duplicates": [
      {
        "similarity_score": 0.94,
        "files": [
          "src/utils/crypto.py",
          "lib/encryption/aes.py"
        ],
        "type": "code_duplication"
      }
    ],
    "external_matches": [
      {
        "file_path": "src/third_party/library.js",
        "matched_repository": "https://github.com/known/malware-repo",
        "similarity_score": 0.89,
        "risk_level": "high"
      }
    ]
  },
  "compliance_analysis": {
    "gdpr_compliance": {
      "status": "non_compliant",
      "issues": [
        "PII detected without consent mechanism",
        "Data retention policy not implemented"
      ]
    },
    "license_compliance": {
      "status": "compliant",
      "licenses_found": ["MIT", "Apache-2.0", "GPL-3.0"],
      "license_conflicts": []
    }
  },
  "forensic_metadata": {
    "chain_of_custody_id": "coc-2024-001",
    "evidence_hash": "sha256:a1b2c3d4...",
    "collection_timestamp": "2024-07-23T10:05:00Z",
    "analyst": "system.analyzer.v1.2.0",
    "integrity_verified": true
  }
}
```

---

### Get Analysis Report

Download a formatted analysis report.

**Endpoint:** `GET /analysis/{job_id}/report`

**Query Parameters:**
- `format` - Report format: `html`, `pdf`, `docx`, `json` (default: `html`)
- `template` - Report template: `executive`, `technical`, `legal`, `compliance`
- `include_evidence` - Include evidence package: `true`, `false` (default: `false`)

**Response:** Binary file download with appropriate content type.

---

### Cancel Analysis

Cancel a running analysis job.

**Endpoint:** `POST /analysis/{job_id}/cancel`

**Request Body:**
```json
{
  "reason": "No longer needed",
  "preserve_partial_results": true
}
```

**Response:**
```json
{
  "job_id": "550e8400-e29b-41d4-a716-446655440000",
  "status": "cancelled",
  "cancelled_at": "2024-07-23T11:45:00Z",
  "partial_results_preserved": true,
  "cancellation_reason": "No longer needed"
}
```

---

## Search Endpoints

### Semantic Search

Search across analyzed repositories using natural language queries.

**Endpoint:** `POST /search/semantic`

**Request Body:**
```json
{
  "query": "find files containing API keys or passwords",
  "filters": {
    "job_ids": ["550e8400-e29b-41d4-a716-446655440000"],
    "file_types": ["python", "javascript", "yaml"],
    "classification": ["confidential", "restricted"],
    "date_range": {
      "start": "2024-07-01T00:00:00Z",
      "end": "2024-07-23T23:59:59Z"
    }
  },
  "limit": 50,
  "threshold": 0.7
}
```

**Response:**
```json
{
  "query": "find files containing API keys or passwords",
  "total_results": 23,
  "results": [
    {
      "score": 0.94,
      "job_id": "550e8400-e29b-41d4-a716-446655440000",
      "file_path": "config/secrets.yaml",
      "content_snippet": "database_password: super_secret_123",
      "classification": "confidential",
      "finding_types": ["secret_exposure"],
      "highlighted_text": "database_<mark>password</mark>: super_secret_123"
    }
  ],
  "aggregations": {
    "by_file_type": {
      "yaml": 12,
      "python": 8,
      "javascript": 3
    },
    "by_classification": {
      "confidential": 15,
      "restricted": 8
    }
  }
}
```

---

### Similarity Search

Find files similar to a given file or content.

**Endpoint:** `POST /search/similarity`

**Request Body:**
```json
{
  "reference": {
    "type": "file_path",
    "value": "config/database.yaml",
    "job_id": "550e8400-e29b-41d4-a716-446655440000"
  },
  "similarity_threshold": 0.8,
  "search_scope": {
    "job_ids": ["all"],
    "include_external_matches": true
  },
  "limit": 20
}
```

**Response:**
```json
{
  "reference_file": "config/database.yaml",
  "total_matches": 15,
  "matches": [
    {
      "similarity_score": 0.92,
      "job_id": "660f9511-f3ac-52e5-b827-557766551111",
      "file_path": "settings/db_config.yaml",
      "match_type": "structural_similarity",
      "shared_elements": ["database_host", "port", "credentials"]
    }
  ]
}
```

---

## Management Endpoints

### List Analysis Jobs

Retrieve a paginated list of analysis jobs.

**Endpoint:** `GET /analysis/jobs`

**Query Parameters:**
- `status` - Filter by status: `pending`, `running`, `completed`, `failed`, `cancelled`
- `created_after` - ISO 8601 timestamp
- `created_before` - ISO 8601 timestamp
- `repository_url` - Filter by repository URL
- `case_number` - Filter by case number
- `limit` - Results per page (default: 50, max: 100)
- `offset` - Pagination offset (default: 0)

**Response:**
```json
{
  "total": 156,
  "limit": 50,
  "offset": 0,
  "jobs": [
    {
      "job_id": "550e8400-e29b-41d4-a716-446655440000",
      "repository_url": "https://github.com/example/repo.git",
      "status": "completed",
      "created_at": "2024-07-23T10:00:00Z",
      "completed_at": "2024-07-23T12:28:00Z",
      "case_number": "CASE-2024-001",
      "risk_score": 7.2,
      "findings_count": 45
    }
  ]
}
```

---

### Health Check

Check service health and status.

**Endpoint:** `GET /health`

**Response:**
```json
{
  "status": "healthy",
  "timestamp": "2024-07-23T15:30:00Z",
  "version": "1.2.0",
  "uptime_seconds": 86400,
  "checks": {
    "database": {
      "status": "healthy",
      "response_time_ms": 12
    },
    "temporal": {
      "status": "healthy",
      "workers_active": 10
    },
    "object_storage": {
      "status": "healthy",
      "space_available_gb": 1024
    },
    "qdrant": {
      "status": "healthy",
      "collections": 3,
      "total_vectors": 1500000
    }
  },
  "metrics": {
    "active_analyses": 5,
    "queued_analyses": 12,
    "completed_today": 34,
    "average_processing_time_minutes": 125
  }
}
```

---

## gRPC API

### Proto Definition

```protobuf
syntax = "proto3";

package afdp.repository_analysis.v1;

import "google/protobuf/timestamp.proto";
import "google/protobuf/struct.proto";

service RepositoryAnalysisService {
  // Submit a repository for analysis
  rpc SubmitAnalysis(SubmitAnalysisRequest) returns (SubmitAnalysisResponse);
  
  // Get analysis status with streaming updates
  rpc GetAnalysisStatus(GetAnalysisStatusRequest) returns (GetAnalysisStatusResponse);
  
  // Stream real-time analysis progress
  rpc StreamAnalysisProgress(StreamAnalysisProgressRequest) returns (stream AnalysisProgressEvent);
  
  // Get analysis results
  rpc GetAnalysisResults(GetAnalysisResultsRequest) returns (GetAnalysisResultsResponse);
  
  // Perform semantic search
  rpc SemanticSearch(SemanticSearchRequest) returns (SemanticSearchResponse);
  
  // Batch operations
  rpc BatchSubmitAnalysis(BatchSubmitAnalysisRequest) returns (BatchSubmitAnalysisResponse);
  
  // Health check
  rpc HealthCheck(HealthCheckRequest) returns (HealthCheckResponse);
}

message SubmitAnalysisRequest {
  string repository_url = 1;
  RepositoryType repository_type = 2;
  AnalysisType analysis_type = 3;
  Priority priority = 4;
  string case_number = 5;
  string notify_webhook = 6;
  AnalysisConfiguration configuration = 7;
  google.protobuf.Struct metadata = 8;
}

message SubmitAnalysisResponse {
  string job_id = 1;
  AnalysisStatus status = 2;
  google.protobuf.Timestamp estimated_completion = 3;
  google.protobuf.Timestamp created_at = 4;
}

message AnalysisProgressEvent {
  string job_id = 1;
  AnalysisStatus status = 2;
  int32 progress_percentage = 3;
  string current_phase = 4;
  google.protobuf.Timestamp timestamp = 5;
  string message = 6;
  repeated AnalysisError errors = 7;
  repeated AnalysisWarning warnings = 8;
}

enum RepositoryType {
  REPOSITORY_TYPE_UNSPECIFIED = 0;
  REPOSITORY_TYPE_GIT = 1;
  REPOSITORY_TYPE_SVN = 2;
  REPOSITORY_TYPE_ARCHIVE = 3;
  REPOSITORY_TYPE_FILE_SYSTEM = 4;
}

enum AnalysisType {
  ANALYSIS_TYPE_UNSPECIFIED = 0;
  ANALYSIS_TYPE_SECURITY = 1;
  ANALYSIS_TYPE_COMPLIANCE = 2;
  ANALYSIS_TYPE_FORENSIC = 3;
  ANALYSIS_TYPE_COMPREHENSIVE = 4;
}

enum Priority {
  PRIORITY_UNSPECIFIED = 0;
  PRIORITY_LOW = 1;
  PRIORITY_NORMAL = 2;
  PRIORITY_HIGH = 3;
  PRIORITY_URGENT = 4;
}

enum AnalysisStatus {
  ANALYSIS_STATUS_UNSPECIFIED = 0;
  ANALYSIS_STATUS_PENDING = 1;
  ANALYSIS_STATUS_RUNNING = 2;
  ANALYSIS_STATUS_COMPLETED = 3;
  ANALYSIS_STATUS_FAILED = 4;
  ANALYSIS_STATUS_CANCELLED = 5;
}
```

### gRPC Client Examples

#### Go Client
```go
package main

import (
    "context"
    "log"
    
    "google.golang.org/grpc"
    pb "github.com/caia-tech/afdp/proto/repository-analysis/v1"
)

func main() {
    conn, err := grpc.Dial("localhost:9090", grpc.WithInsecure())
    if err != nil {
        log.Fatal(err)
    }
    defer conn.Close()
    
    client := pb.NewRepositoryAnalysisServiceClient(conn)
    
    // Submit analysis
    req := &pb.SubmitAnalysisRequest{
        RepositoryUrl:    "https://github.com/example/repo.git",
        RepositoryType:   pb.RepositoryType_REPOSITORY_TYPE_GIT,
        AnalysisType:     pb.AnalysisType_ANALYSIS_TYPE_COMPREHENSIVE,
        Priority:         pb.Priority_PRIORITY_HIGH,
        CaseNumber:       "CASE-2024-001",
    }
    
    resp, err := client.SubmitAnalysis(context.Background(), req)
    if err != nil {
        log.Fatal(err)
    }
    
    log.Printf("Analysis submitted: %s", resp.JobId)
    
    // Stream progress
    stream, err := client.StreamAnalysisProgress(context.Background(), &pb.StreamAnalysisProgressRequest{
        JobId: resp.JobId,
    })
    if err != nil {
        log.Fatal(err)
    }
    
    for {
        event, err := stream.Recv()
        if err != nil {
            break
        }
        log.Printf("Progress: %d%% - %s", event.ProgressPercentage, event.CurrentPhase)
    }
}
```

#### Rust Client
```rust
use tonic::Request;
use afdp_proto::repository_analysis::v1::{
    repository_analysis_service_client::RepositoryAnalysisServiceClient,
    SubmitAnalysisRequest, RepositoryType, AnalysisType, Priority,
};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut client = RepositoryAnalysisServiceClient::connect("http://localhost:9090").await?;
    
    let request = Request::new(SubmitAnalysisRequest {
        repository_url: "https://github.com/example/repo.git".to_string(),
        repository_type: RepositoryType::Git as i32,
        analysis_type: AnalysisType::Comprehensive as i32,
        priority: Priority::High as i32,
        case_number: "CASE-2024-001".to_string(),
        notify_webhook: String::new(),
        configuration: None,
        metadata: None,
    });
    
    let response = client.submit_analysis(request).await?;
    let job_id = response.into_inner().job_id;
    
    println!("Analysis submitted: {}", job_id);
    
    Ok(())
}
```

---

## Pulsar Events

### Event Topics

The service publishes events to the following Pulsar topics:

- `afdp.repository.analysis.submitted`
- `afdp.repository.analysis.started`
- `afdp.repository.analysis.progress`
- `afdp.repository.violation.detected`
- `afdp.repository.anomaly.identified`
- `afdp.repository.analysis.completed`
- `afdp.repository.analysis.failed`
- `afdp.repository.evidence.discovered`

### Event Schema

#### Analysis Submitted Event
```json
{
  "event_id": "evt-550e8400-e29b-41d4-a716-446655440000",
  "timestamp": "2024-07-23T10:00:00Z",
  "event_type": "analysis_submitted",
  "job_id": "550e8400-e29b-41d4-a716-446655440000",
  "repository_url": "https://github.com/example/repo.git",
  "analysis_type": "comprehensive",
  "priority": "high",
  "case_number": "CASE-2024-001",
  "submitter": {
    "user_id": "user-123",
    "email": "investigator@company.com"
  },
  "metadata": {
    "estimated_duration_hours": 2,
    "repository_size_mb": 50
  }
}
```

#### Violation Detected Event
```json
{
  "event_id": "evt-660f9511-f3ac-52e5-b827-557766551111",
  "timestamp": "2024-07-23T11:30:00Z",
  "event_type": "violation_detected",
  "job_id": "550e8400-e29b-41d4-a716-446655440000",
  "violation": {
    "id": "violation-001",
    "type": "secret_exposure",
    "severity": "critical",
    "title": "API Key Exposed in Source Code",
    "file_path": "config/production.yaml",
    "line_number": 42,
    "confidence": 0.95
  },
  "repository_info": {
    "url": "https://github.com/example/repo.git",
    "commit_hash": "a1b2c3d4e5f6"
  },
  "case_number": "CASE-2024-001"
}
```

#### Analysis Completed Event
```json
{
  "event_id": "evt-770f0622-04bd-63f6-c938-668877662222",
  "timestamp": "2024-07-23T12:28:00Z",
  "event_type": "analysis_completed",
  "job_id": "550e8400-e29b-41d4-a716-446655440000",
  "duration_seconds": 8280,
  "summary": {
    "risk_score": 7.2,
    "total_findings": 45,
    "critical_findings": 2,
    "files_analyzed": 1890
  },
  "outputs": {
    "report_url": "https://storage.afdp.caia.tech/reports/550e8400-e29b-41d4-a716-446655440000/summary.html",
    "evidence_package_url": "https://storage.afdp.caia.tech/evidence/550e8400-e29b-41d4-a716-446655440000.zip"
  }
}
```

### Pulsar Consumer Example

#### Python Consumer
```python
import pulsar
import json
from typing import Dict, Any

class AnalysisEventConsumer:
    def __init__(self, pulsar_url: str, subscription_name: str):
        self.client = pulsar.Client(pulsar_url)
        self.consumer = self.client.subscribe(
            topic="afdp.repository.analysis.*",
            subscription_name=subscription_name,
            consumer_type=pulsar.ConsumerType.Shared,
            message_listener=self.on_message
        )
    
    def on_message(self, consumer, message):
        try:
            event_data = json.loads(message.data().decode('utf-8'))
            self.handle_event(event_data)
            consumer.acknowledge(message)
        except Exception as e:
            print(f"Error processing message: {e}")
            consumer.negative_acknowledge(message)
    
    def handle_event(self, event: Dict[str, Any]):
        event_type = event.get('event_type')
        
        if event_type == 'violation_detected':
            self.handle_violation_detected(event)
        elif event_type == 'analysis_completed':
            self.handle_analysis_completed(event)
        # Handle other event types...
    
    def handle_violation_detected(self, event: Dict[str, Any]):
        violation = event['violation']
        if violation['severity'] == 'critical':
            # Send immediate alert
            self.send_critical_alert(event)
    
    def handle_analysis_completed(self, event: Dict[str, Any]):
        # Generate summary report
        # Update case management system
        # Notify stakeholders
        pass

# Usage
consumer = AnalysisEventConsumer(
    pulsar_url="pulsar://localhost:6650",
    subscription_name="case-management-system"
)

# Keep the consumer running
try:
    while True:
        time.sleep(1)
finally:
    consumer.close()
```

---

## Authentication

The Repository Analysis Service integrates with the AFDP Policy Engine for authentication and authorization.

### JWT Token Requirements

All API requests must include a valid JWT token with the following claims:

```json
{
  "iss": "afdp-policy-engine",
  "sub": "user-550e8400-e29b-41d4-a716-446655440000",
  "aud": "repository-analysis-service",
  "exp": 1690372800,
  "iat": 1690286400,
  "user_id": "user-123",
  "email": "investigator@company.com",
  "roles": ["forensic_analyst", "investigator"],
  "permissions": [
    "repository:analyze",
    "repository:read",
    "evidence:access",
    "report:generate"
  ],
  "organization_id": "org-456",
  "clearance_level": "secret"
}
```

### Permission Requirements

Different endpoints require specific permissions:

| Endpoint | Required Permission |
|----------|-------------------|
| `POST /analysis/submit` | `repository:analyze` |
| `GET /analysis/{id}/status` | `repository:read` |
| `GET /analysis/{id}/results` | `evidence:access` |
| `GET /analysis/{id}/report` | `report:generate` |
| `POST /search/semantic` | `evidence:search` |
| `GET /analysis/jobs` | `repository:list` |

### Example Authentication Header
```
Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJhZmRwLXBvbGljeS1lbmdpbmUiLCJzdWIiOiJ1c2VyLTU1MGU4NDAwLWUyOWItNDFkNC1hNzE2LTQ0NjY1NTQ0MDAwMCIsImF1ZCI6InJlcG9zaXRvcnktYW5hbHlzaXMtc2VydmljZSIsImV4cCI6MTY5MDM3MjgwMCwiaWF0IjoxNjkwMjg2NDAwLCJ1c2VyX2lkIjoidXNlci0xMjMiLCJlbWFpbCI6ImludmVzdGlnYXRvckBjb21wYW55LmNvbSIsInJvbGVzIjpbImZvcmVuc2ljX2FuYWx5c3QiLCJpbnZlc3RpZ2F0b3IiXSwicGVybWlzc2lvbnMiOlsicmVwb3NpdG9yeTphbmFseXplIiwicmVwb3NpdG9yeTpyZWFkIiwiZXZpZGVuY2U6YWNjZXNzIiwicmVwb3J0OmdlbmVyYXRlIl0sIm9yZ2FuaXphdGlvbl9pZCI6Im9yZy00NTYiLCJjbGVhcmFuY2VfbGV2ZWwiOiJzZWNyZXQifQ...
```

---

## Error Handling

### Error Response Format

All error responses follow a consistent format:

```json
{
  "error": {
    "code": "INVALID_REPOSITORY_URL",
    "message": "The provided repository URL is not accessible",
    "details": {
      "repository_url": "https://github.com/invalid/repo.git",
      "error_type": "connection_timeout",
      "retry_after_seconds": 300
    },
    "request_id": "req-550e8400-e29b-41d4-a716-446655440000",
    "timestamp": "2024-07-23T10:00:00Z"
  }
}
```

### Common Error Codes

| HTTP Status | Error Code | Description |
|-------------|------------|-------------|
| 400 | `INVALID_REQUEST` | Request validation failed |
| 400 | `INVALID_REPOSITORY_URL` | Repository URL is malformed or inaccessible |
| 401 | `AUTHENTICATION_REQUIRED` | Valid authentication token required |
| 401 | `TOKEN_EXPIRED` | Authentication token has expired |
| 403 | `INSUFFICIENT_PERMISSIONS` | User lacks required permissions |
| 403 | `CLEARANCE_LEVEL_REQUIRED` | Higher security clearance required |
| 404 | `JOB_NOT_FOUND` | Analysis job does not exist |
| 409 | `ANALYSIS_IN_PROGRESS` | Repository is already being analyzed |
| 422 | `REPOSITORY_TOO_LARGE` | Repository exceeds size limits |
| 422 | `UNSUPPORTED_REPOSITORY_TYPE` | Repository type not supported |
| 429 | `RATE_LIMIT_EXCEEDED` | Too many requests |
| 500 | `INTERNAL_SERVER_ERROR` | Unexpected server error |
| 503 | `SERVICE_UNAVAILABLE` | Service temporarily unavailable |

---

## Rate Limiting

### Rate Limit Headers

All responses include rate limiting headers:

```
X-RateLimit-Limit: 100
X-RateLimit-Remaining: 95
X-RateLimit-Reset: 1690287000
X-RateLimit-Reset-After: 3600
```

### Rate Limits by Endpoint

| Endpoint Pattern | Rate Limit | Window |
|------------------|------------|---------|
| `POST /analysis/submit` | 10 requests | 1 hour |
| `GET /analysis/*/status` | 100 requests | 5 minutes |
| `GET /analysis/*/results` | 50 requests | 1 hour |
| `POST /search/*` | 50 requests | 5 minutes |
| `GET /health` | 1000 requests | 1 minute |

### Rate Limit Exceeded Response

```json
{
  "error": {
    "code": "RATE_LIMIT_EXCEEDED",
    "message": "Rate limit exceeded. Try again in 3600 seconds.",
    "details": {
      "limit": 10,
      "window_seconds": 3600,
      "retry_after_seconds": 3600
    },
    "request_id": "req-550e8400-e29b-41d4-a716-446655440000",
    "timestamp": "2024-07-23T10:00:00Z"
  }
}
```

---

## Examples

### Complete Analysis Workflow

#### 1. Submit Analysis
```bash
curl -X POST "https://api.afdp.caia.tech/repository-analysis/v1/analysis/submit" \
  -H "Authorization: Bearer $JWT_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "repository_url": "https://github.com/example/suspicious-repo.git",
    "analysis_type": "comprehensive",
    "priority": "high",
    "case_number": "SEC-2024-001",
    "configuration": {
      "include_git_history": true,
      "malware_scanning": true,
      "pii_detection": true
    }
  }'
```

#### 2. Monitor Progress
```bash
JOB_ID="550e8400-e29b-41d4-a716-446655440000"

while true; do
  STATUS=$(curl -s "https://api.afdp.caia.tech/repository-analysis/v1/analysis/$JOB_ID/status" \
    -H "Authorization: Bearer $JWT_TOKEN" | jq -r '.status')
  
  if [ "$STATUS" = "completed" ] || [ "$STATUS" = "failed" ]; then
    break
  fi
  
  echo "Status: $STATUS"
  sleep 30
done
```

#### 3. Retrieve Results
```bash
curl "https://api.afdp.caia.tech/repository-analysis/v1/analysis/$JOB_ID/results" \
  -H "Authorization: Bearer $JWT_TOKEN" \
  -o analysis_results.json
```

#### 4. Download Report
```bash
curl "https://api.afdp.caia.tech/repository-analysis/v1/analysis/$JOB_ID/report?format=pdf&template=legal" \
  -H "Authorization: Bearer $JWT_TOKEN" \
  -o forensic_report.pdf
```

### Search Examples

#### Semantic Search for Secrets
```bash
curl -X POST "https://api.afdp.caia.tech/repository-analysis/v1/search/semantic" \
  -H "Authorization: Bearer $JWT_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "query": "API keys, passwords, or authentication tokens",
    "filters": {
      "classification": ["confidential", "restricted"],
      "file_types": ["yaml", "json", "python"]
    },
    "limit": 20,
    "threshold": 0.8
  }'
```

#### Find Similar Malicious Files
```bash
curl -X POST "https://api.afdp.caia.tech/repository-analysis/v1/search/similarity" \
  -H "Authorization: Bearer $JWT_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "reference": {
      "type": "file_path",
      "value": "suspicious/malware.js",
      "job_id": "550e8400-e29b-41d4-a716-446655440000"
    },
    "similarity_threshold": 0.7,
    "search_scope": {
      "include_external_matches": true
    }
  }'
```

This comprehensive API reference provides everything needed to integrate with the Repository Analysis Service across all supported protocols and use cases.