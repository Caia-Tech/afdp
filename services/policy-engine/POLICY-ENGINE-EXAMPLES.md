# AFDP Policy Engine - Working Examples

## Quick Start

### 1. Start the Policy Engine

```bash
# Build and run the example server
go run example-server.go
```

The server will start on `http://localhost:8080` with:
- Default admin user: `admin` / `admin123`
- Default regular user: `user1` / `user123`
- Pre-loaded example policies for AFDP Repository Analysis

### 2. Authenticate

```bash
# Login as admin
curl -X POST http://localhost:8080/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{
    "method": "password",
    "credentials": {
      "username": "admin",
      "password": "admin123"
    }
  }'
```

Response:
```json
{
  "success": true,
  "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "expires_at": "2024-07-23T15:30:00Z",
  "user_info": {
    "id": "user-admin-123",
    "username": "admin",
    "email": "admin@afdp.local",
    "roles": ["admin", "user"]
  }
}
```

### 3. Evaluate Policies

#### Basic Policy Evaluation

```bash
# Set the JWT token from login response
TOKEN="eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."

# Evaluate repository access policy
curl -X POST http://localhost:8080/api/v1/evaluate \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "policy_id": "repository_access",
    "input": {
      "action": "repository:analyze",
      "user": {
        "id": "user-admin-123",
        "roles": ["admin"],
        "clearance": "secret"
      },
      "resource": {
        "type": "repository",
        "classification": "secret"
      }
    },
    "context": {
      "timestamp": "2024-07-23T10:00:00Z",
      "request_id": "req-123"
    }
  }'
```

Response:
```json
{
  "result": "allow",
  "approvers": [],
  "conditions": [],
  "metadata": {
    "evaluated_at": "2024-07-23T10:00:00Z"
  }
}
```

#### Repository Analysis Authorization Example

```bash
# Example: User trying to analyze a repository
curl -X POST http://localhost:8080/api/v1/evaluate \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "policy_id": "repository_access",
    "input": {
      "action": "repository:analyze",
      "user": {
        "id": "user-analyst-456",
        "roles": ["analyst"],
        "clearance": "secret"
      },
      "resource": {
        "type": "repository",
        "url": "https://github.com/example/suspicious-repo",
        "classification": "secret",
        "case_number": "CASE-2024-001"
      }
    }
  }'
```

#### Batch Policy Evaluation

```bash
# Evaluate multiple policies at once
curl -X POST http://localhost:8080/api/v1/evaluate/batch \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "requests": [
      {
        "policy_id": "repository_access",
        "input": {
          "action": "repository:read",
          "user": {"id": "user-123", "roles": ["user"]},
          "resource": {"owner": "user-123"}
        }
      },
      {
        "policy_id": "basic_rbac",
        "input": {
          "action": "create",
          "user": {"id": "user-123", "roles": ["user"]},
          "resource": {"type": "analysis_job"}
        }
      }
    ]
  }'
```

### 4. Policy Management

#### List Policies

```bash
curl -X GET http://localhost:8080/api/v1/policies \
  -H "Authorization: Bearer $TOKEN"
```

#### Create New Policy

```bash
curl -X POST http://localhost:8080/api/v1/policies \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "policy_id": "evidence_access",
    "policy": "package evidence\n\ndefault allow = false\n\nallow {\n  input.user.roles[_] == \"investigator\"\n  input.action == \"evidence:read\"\n}",
    "query": "data.evidence.allow"
  }'
```

#### Delete Policy

```bash
curl -X DELETE http://localhost:8080/api/v1/policies/evidence_access \
  -H "Authorization: Bearer $TOKEN"
```

### 5. User and Role Management

#### Get Current User

```bash
curl -X GET http://localhost:8080/api/v1/users/me \
  -H "Authorization: Bearer $TOKEN"
```

#### List Available Roles

```bash
curl -X GET http://localhost:8080/api/v1/roles \
  -H "Authorization: Bearer $TOKEN"
```

#### Assign Role to User

```bash
curl -X POST http://localhost:8080/api/v1/users/user-456/roles \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "role": "analyst"
  }'
```

### 6. Health and Monitoring

#### Check System Health

```bash
curl -X GET http://localhost:8080/api/v1/health
```

#### Get Framework Status

```bash
curl -X GET http://localhost:8080/api/v1/framework/status \
  -H "Authorization: Bearer $TOKEN"
```

#### List Plugins

```bash
curl -X GET http://localhost:8080/api/v1/plugins \
  -H "Authorization: Bearer $TOKEN"
```

## Real-World AFDP Integration Examples

### Repository Analysis Service Integration

```bash
# Policy for Repository Analysis Service authorization
curl -X POST http://localhost:8080/api/v1/evaluate \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "policy_id": "repository_access",
    "input": {
      "action": "repository:submit",
      "user": {
        "id": "service-repo-analysis",
        "roles": ["service"],
        "service_type": "repository_analysis"
      },
      "resource": {
        "type": "analysis_job",
        "repository_url": "https://github.com/example/target-repo",
        "analysis_type": "comprehensive",
        "case_number": "SEC-2024-015"
      }
    },
    "context": {
      "service_request": true,
      "originating_user": "investigator-jane",
      "priority": "high"
    }
  }'
```

### Evidence Chain of Custody

```bash
# Policy evaluation for evidence handling
curl -X POST http://localhost:8080/api/v1/evaluate \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "policy_id": "evidence_custody",
    "input": {
      "action": "evidence:transfer",
      "user": {
        "id": "forensics-analyst-001",
        "roles": ["forensic_analyst"],
        "clearance": "secret",
        "badge_number": "FA001"
      },
      "resource": {
        "type": "digital_evidence",
        "case_number": "CASE-2024-001",
        "classification": "restricted",
        "chain_of_custody_id": "COC-2024-001-15"
      },
      "target": {
        "user_id": "legal-counsel-002",
        "department": "legal",
        "clearance": "secret"
      }
    }
  }'
```

### Distributed Intelligence Coordination

```bash
# Policy for distributing threat intelligence
curl -X POST http://localhost:8080/api/v1/evaluate \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "policy_id": "intelligence_distribution",
    "input": {
      "action": "intel:distribute",
      "user": {
        "id": "threat-analyst-007",
        "roles": ["threat_analyst", "intel_coordinator"],
        "agency": "federal_bureau"
      },
      "resource": {
        "type": "threat_intelligence",
        "classification": "secret",
        "threat_level": "high",
        "indicators": ["malware_hash", "c2_domain"]
      },
      "distribution": {
        "targets": ["fusion_center", "local_police", "private_sector"],
        "urgency": "immediate",
        "sharing_agreement": "TLP_AMBER"
      }
    }
  }'
```

## Advanced Policy Examples

### Multi-Factor Authorization

Create a policy requiring multiple approvers for sensitive operations:

```bash
curl -X POST http://localhost:8080/api/v1/policies \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "policy_id": "sensitive_operations",
    "policy": "package sensitive\n\ndefault allow = false\ndefault requires_approval = false\n\n# Sensitive operations require dual approval\nrequires_approval {\n  input.action in [\"evidence:delete\", \"case:close\", \"intel:declassify\"]\n  input.resource.classification in [\"secret\", \"top_secret\"]\n}\n\n# Allow if user has required role and approval is present\nallow {\n  input.user.roles[_] in [\"supervisor\", \"admin\"]\n  input.approval.approvers[_].role == \"legal_counsel\"\n  input.approval.approvers[_].role == \"senior_analyst\"\n  count(input.approval.approvers) >= 2\n}",
    "query": "data.sensitive"
  }'
```

### Time-Based Access Control

```bash
curl -X POST http://localhost:8080/api/v1/policies \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "policy_id": "time_based_access",
    "policy": "package temporal\n\ndefault allow = false\n\n# Allow access during business hours\nallow {\n  input.user.roles[_] == \"analyst\"\n  business_hours\n}\n\n# Emergency access allowed 24/7 for critical roles\nallow {\n  input.user.roles[_] in [\"incident_commander\", \"emergency_responder\"]\n}\n\nbusiness_hours {\n  hour := time.clock(time.now_ns())[0]\n  hour >= 8\n  hour <= 18\n}",
    "query": "data.temporal.allow"
  }'
```

## Troubleshooting

### Check Plugin Status

```bash
# Check if evaluator plugin is healthy
curl -X GET http://localhost:8080/api/v1/plugins/evaluator/rego/health \
  -H "Authorization: Bearer $TOKEN"

# Check security plugin
curl -X GET http://localhost:8080/api/v1/plugins/security/default/health \
  -H "Authorization: Bearer $TOKEN"
```

### View Decision History

```bash
# Query recent policy decisions
curl -X GET "http://localhost:8080/api/v1/decisions?limit=10" \
  -H "Authorization: Bearer $TOKEN"

# Query decisions for specific user
curl -X GET "http://localhost:8080/api/v1/decisions?user_id=user-123&limit=5" \
  -H "Authorization: Bearer $TOKEN"
```

### Debug Policy Evaluation

```bash
# Evaluate with detailed context for debugging
curl -X POST http://localhost:8080/api/v1/evaluate \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "policy_id": "basic_rbac",
    "input": {
      "action": "debug_test",
      "user": {"id": "debug-user", "roles": ["debug"]},
      "resource": {"type": "test"}
    },
    "options": {
      "trace": true,
      "explain": true
    }
  }'
```

This Policy Engine is now ready to provide authentication, authorization, and policy evaluation for the AFDP Repository Analysis Service and other components!