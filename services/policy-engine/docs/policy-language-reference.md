# AFDP Framework Extension Guide

**Document Version:** 1.0  
**Last Updated:** July 2025  
**Classification:** Public  
**Author:** AFDP Framework Extension Team  

## 📋 Table of Contents

1. [Introduction](#introduction)
2. [Extension Architecture](#extension-architecture)
3. [Plugin Development](#plugin-development)
4. [Policy Evaluators](#policy-evaluators)
5. [Data Source Extensions](#data-source-extensions)
6. [Workflow Extensions](#workflow-extensions)
7. [Security Extensions](#security-extensions)
8. [Testing and Validation](#testing-and-validation)
9. [Deployment and Distribution](#deployment-and-distribution)
10. [Best Practices](#best-practices)
11. [Examples](#examples)
12. [API Reference](#api-reference)

## 🎯 Introduction

The AFDP Policy Framework is designed for **maximum extensibility**. Rather than limiting users to a single policy language or evaluation model, the framework provides a plugin architecture that allows organizations to build custom policy systems using any technology stack, programming language, or domain-specific approach.

This guide shows you how to extend the framework with custom evaluators, data sources, workflows, and security mechanisms to build policy systems that exactly match your organizational needs.

### Design Principles

**Human-Readable:** Policies should be understandable by business stakeholders, not just developers  
**Declarative:** Express what should happen, not how to make it happen  
**Composable:** Policies can be combined and extended without modification  
**Auditable:** Every policy decision includes detailed reasoning and evidence  
**Secure:** Policy evaluation is isolated and cannot access unauthorized resources  

### Target Audience

- **Policy Authors:** Compliance officers, security professionals, business analysts
- **Policy Administrators:** System administrators, DevOps engineers  
- **Developers:** Integration developers, policy tool builders
- **Auditors:** Internal auditors, compliance reviewers, external assessors

## 🏗️ Policy Language Overview

### Language Foundation

The AFDP Policy Language extends Rego (the Open Policy Agent query language) with domain-specific functions, data structures, and conventions optimized for AI deployment governance.

**Base Language:** Rego v1 (OPA)  
**Extensions:** AFDP-specific functions and data types  
**Evaluation Model:** Datalog-based logical programming  
**Safety:** Guaranteed termination and resource limits  

### Policy Structure

Every AFDP policy consists of:

```rego
# Policy metadata and documentation
package afdp.policies.ai_deployment

import rego.v1

# Policy configuration
metadata := {
    "name": "AI Model Production Deployment",
    "version": "1.2.0",
    "description": "Governs deployment of AI models to production environments",
    "compliance_frameworks": ["SOX", "HIPAA", "PCI-DSS"],
    "last_updated": "2025-07-23T10:30:00Z",
    "author": "security-team@company.com"
}

# Default decisions (security by default)
default allow := false
default require_approval := false

# Policy rules and logic
allow if {
    # Conditions for automatic approval
    input.environment == "development"
    input.risk_score < 3
}

require_approval if {
    # Conditions requiring human approval
    input.environment == "production"
    input.data_classification in ["sensitive", "restricted"]
}

# Decision explanation and context
decision := {
    "result": result,
    "reasoning": reasoning,
    "required_approvers": required_approvers,
    "risk_score": risk_score,
    "compliance_status": compliance_status
}
```

## 📝 Basic Syntax

### Comments and Documentation

```rego
# Single-line comment for brief explanations

# Multi-line documentation block
# Purpose: Explain complex policy logic
# Author: policy-team@company.com
# Last Modified: 2025-07-23

# TODO: Add support for emergency override procedures
# FIXME: Handle edge case for cross-border deployments
```

### Package Declaration

```rego
# Standard AFDP policy package structure
package afdp.policies.domain.specific_policy

# Examples:
package afdp.policies.ai.model_deployment
package afdp.policies.data.classification
package afdp.policies.compliance.sox
package afdp.policies.security.vulnerability_management
```

### Import Statements

```rego
import rego.v1                    # Required for all AFDP policies
import data.afdp.functions       # AFDP-specific helper functions
import data.afdp.compliance      # Compliance framework definitions
import data.afdp.risk           # Risk assessment functions
import future.keywords.if       # Enhanced readability (optional)
```

### Variable Definitions

```rego
# Simple variable assignment
policy_version := "1.2.0"
max_risk_score := 8

# Complex variable with conditions
deployment_environment := env if {
    env := input.deployment.environment
    env in ["development", "staging", "production"]
}

# Default value with fallback
data_classification := input.data.classification
default data_classification := "internal"
```

### Rule Definitions

```rego
# Simple boolean rule
allow if {
    input.user.role == "administrator"
}

# Rule with multiple conditions
require_security_review if {
    input.deployment.environment == "production"
    input.data.classification == "sensitive"
    input.risk_score > 5
}

# Rule with complex logic
approval_required if {
    # Production deployments always require approval
    input.environment == "production"
} else := true if {
    # High-risk deployments require approval regardless of environment
    calculated_risk_score > 7
} else := false
```

## 📊 Data Types and Structures

### Primitive Types

```rego
# String values
environment := "production"
user_email := "marv.tutt@company.com"

# Numeric values  
risk_score := 7.5
max_instances := 10

# Boolean values
is_critical := true
requires_approval := false

# Null values
optional_field := null
```

### Collections

```rego
# Arrays (ordered collections)
supported_environments := ["development", "staging", "production"]
risk_factors := [
    "external_dependencies",
    "sensitive_data_access", 
    "high_compute_requirements"
]

# Objects (key-value mappings)
user_info := {
    "email": "marvin.tutt@company.com",
    "role": "security_officer", 
    "department": "security",
    "clearance_level": "secret"
}

# Sets (unordered unique collections)
required_approvers := {
    "security_officer",
    "compliance_manager",
    "technical_lead"
}
```

### AFDP Data Structures

#### Deployment Request Structure

```rego
# Standard input structure for deployment requests
input_schema := {
    "request_id": "req_1234567890",
    "timestamp": "2025-07-23T10:30:00Z",
    "requestor": {
        "user_id": "marvin.tutt@company.com",
        "role": "ml_engineer", 
        "department": "ai_research"
    },
    "deployment": {
        "name": "fraud-detection-model-v2",
        "version": "2.1.0",
        "environment": "production",
        "region": "us-east-1",
        "replicas": 3
    },
    "model": {
        "name": "fraud-detection-xgboost",
        "version": "2.1.0",
        "framework": "xgboost",
        "training_data_classification": "sensitive",
        "performance_metrics": {
            "accuracy": 0.987,
            "precision": 0.942,
            "recall": 0.953
        }
    },
    "data": {
        "classification": "sensitive",
        "sources": ["customer_transactions", "merchant_data"],
        "compliance_requirements": ["PCI-DSS", "SOX"]
    },
    "infrastructure": {
        "compute_type": "gpu",
        "memory_gb": 32,
        "storage_gb": 500,
        "network_access": "restricted"
    },
    "compliance": {
        "frameworks": ["SOX", "PCI-DSS"],
        "certifications": ["SOC2", "ISO27001"],
        "audit_requirements": true
    }
}
```

#### Policy Decision Structure

```rego
# Standard output structure for policy decisions
decision_schema := {
    "decision_id": "dec_1234567890",
    "request_id": "req_1234567890", 
    "timestamp": "2025-07-23T10:35:00Z",
    "result": "require_approval",              # allow | deny | require_approval
    "confidence": 0.95,                       # Decision confidence (0.0-1.0)
    "reasoning": "Production deployment with sensitive data requires security review",
    "risk_assessment": {
        "overall_score": 7.2,                 # Risk score (0-10 scale)
        "factors": [
            "production_environment",
            "sensitive_data_access",
            "external_api_dependencies"
        ],
        "mitigations": [
            "network_isolation_enabled",
            "encryption_at_rest",
            "audit_logging_enabled"
        ]
    },
    "approval_requirements": {
        "required_approvers": [
            "security_officer",
            "compliance_manager"
        ],
        "approval_deadline": "2025-07-24T10:35:00Z",
        "escalation_path": ["department_head", "ciso"]
    },
    "compliance_status": {
        "sox": "compliant",
        "pci_dss": "compliant", 
        "hipaa": "not_applicable"
    },
    "policy_metadata": {
        "policy_name": "ai-model-production-deployment",
        "policy_version": "1.2.0",
        "evaluation_time_ms": 45
    }
}
```

## ⚖️ Policy Evaluation Logic

### Conditional Logic

```rego
# Simple if-then conditions
allow if {
    input.environment == "development"
    input.user.role in ["developer", "ml_engineer"]
}

# If-then-else with multiple branches
deployment_approved if {
    input.environment == "development"
    # Automatic approval for dev environment
} else if {
    input.environment == "staging"
    input.change_request.approved == true
    # Staging requires change request
} else if {
    input.environment == "production"
    count(approvals) >= 2
    # Production requires multiple approvals
} else {
    false  # Deny by default
}

# Complex conditional with nested logic
high_risk_deployment if {
    # Environment-based risk
    input.environment == "production"
    
    # Data sensitivity risk
    input.data.classification in ["sensitive", "restricted"]
    
    # Model complexity risk
    any([
        input.model.complexity_score > 8,
        count(input.model.dependencies) > 10,
        input.model.training_data_size_gb > 1000
    ])
}
```

### Logical Operators

```rego
# AND operator (all conditions must be true)
secure_deployment if {
    input.encryption.enabled == true          # AND
    input.network.isolated == true           # AND  
    input.logging.audit_enabled == true      # AND
    input.access.mfa_required == true        # (implicit AND)
}

# OR operator using array membership
staging_or_prod if {
    input.environment in ["staging", "production"]
}

# OR operator using multiple rule definitions
urgent_deployment if input.priority == "critical"
urgent_deployment if input.business_justification == "emergency"
urgent_deployment if input.customer_impact == "severe"

# NOT operator using negation
not_restricted if {
    not input.data.classification == "restricted"
}

# Complex logical combinations
deployment_allowed if {
    # Must be authorized user
    authorized_user
    
    # AND must meet environment requirements
    any([
        dev_environment_ok,      # OR development is okay
        staging_approved,        # OR staging is approved  
        production_reviewed      # OR production is reviewed
    ])
    
    # AND must not be restricted
    not restricted_deployment
}
```

### Quantifiers and Aggregation

```rego
# Universal quantifier (all elements must satisfy condition)
all_dependencies_approved if {
    every dep in input.model.dependencies {
        dep.security_scan.status == "passed"
    }
}

# Existential quantifier (at least one element must satisfy condition)
has_security_approval if {
    some approval in input.approvals
    approval.type == "security_review"
    approval.status == "approved"
}

# Counting and aggregation
sufficient_approvals if {
    count([approval | 
        approval := input.approvals[_]
        approval.status == "approved"
    ]) >= 2
}

# Complex aggregation with filtering
average_risk_score := score if {
    risk_scores := [factor.score | 
        factor := input.risk_factors[_]
        factor.category == "security"
    ]
    score := sum(risk_scores) / count(risk_scores)
}
```

## 🔧 Built-in Functions

### String Functions

```rego
# String manipulation
policy_name := sprintf("ai-deployment-%s-v%s", [input.model.name, input.model.version])
environment_upper := upper(input.environment)
user_domain := split(input.user.email, "@")[1]

# String validation
valid_email if {
    regex.match(`^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$`, input.user.email)
}

valid_model_name if {
    regex.match(`^[a-z0-9\-_]+$`, input.model.name)
    count(input.model.name) >= 3
    count(input.model.name) <= 50
}

# String searching and matching
contains_sensitive_keywords if {
    some keyword in ["password", "secret", "api_key", "token"]
    contains(lower(input.model.description), keyword)
}
```

### Numeric Functions

```rego
# Mathematical operations
total_risk_score := sum([
    environment_risk_score,
    data_sensitivity_score, 
    model_complexity_score,
    operational_risk_score
])

# Statistical functions
average_accuracy := sum(input.model.validation_metrics) / count(input.model.validation_metrics)
max_resource_usage := max([cpu_usage, memory_usage, network_usage])

# Comparison and bounds checking
within_performance_bounds if {
    input.model.latency_ms <= 100
    input.model.throughput_rps >= 1000
    input.model.accuracy >= 0.95
}

# Rounding and precision
rounded_risk := round(calculated_risk_score * 100) / 100
```

### Date and Time Functions

```rego
# Current time operations (using external data)
current_timestamp := time.now_ns()
current_date := time.format(time.now_ns())

# Time arithmetic and comparison
request_age_hours := (time.now_ns() - time.parse_rfc3339_ns(input.timestamp)) / 1000000000 / 3600

# Business hours validation
business_hours if {
    hour := time.weekday(time.now_ns())
    hour >= 1  # Monday
    hour <= 5  # Friday
    
    time_of_day := time.clock(time.now_ns())
    time_of_day[0] >= 9   # 9 AM
    time_of_day[0] <= 17  # 5 PM
}

# Time-based access control
emergency_hours if {
    hour := time.clock(time.now_ns())[0]
    any([
        hour < 6,   # Before 6 AM
        hour > 22   # After 10 PM
    ])
}
```

### Collection Functions

```rego
# Array and set operations
unique_risk_factors := {factor | factor := input.risk_factors[_]}
sorted_approvers := sort(required_approvers)

# Set operations
missing_approvers := required_approvers - provided_approvers
common_frameworks := input.compliance.required & input.compliance.certified

# Filtering and transformation
high_risk_factors := [factor | 
    factor := input.risk_factors[_]
    factor.severity == "high"
]

approved_reviewers := {reviewer.email | 
    reviewer := input.approvals[_]
    reviewer.status == "approved"
}

# Complex collection processing
security_controls_by_type := {control_type: controls |
    controls := [control |
        control := input.security_controls[_]
        control.type == control_type
    ]
    control_type := input.security_controls[_].type
}
```

### AFDP-Specific Functions

```rego
# Risk assessment functions
risk_score := afdp.risk.calculate_score(input.deployment, input.model, input.data)

model_risk := afdp.risk.model_complexity(
    input.model.parameters_count,
    input.model.training_data_size,
    input.model.dependencies
)

# Compliance validation functions
sox_compliance := afdp.compliance.sox.validate(input)
hipaa_compliance := afdp.compliance.hipaa.validate(input)
pci_compliance := afdp.compliance.pci.validate(input)

# Security assessment functions  
security_posture := afdp.security.assess_posture(input.infrastructure)
threat_level := afdp.security.threat_assessment(input.deployment.region, input.data.classification)

# Business impact functions
business_impact := afdp.business.impact_assessment(
    input.deployment.customer_facing,
    input.deployment.revenue_impact,
    input.deployment.user_count
)
```

## 🚀 Advanced Features

### Policy Composition and Inheritance

```rego
# Base policy package
package afdp.policies.base.deployment

# Shared rules that can be inherited
default_security_controls if {
    input.encryption.enabled == true
    input.logging.audit_enabled == true
    input.access.authentication == "multi_factor"
}

# Specific policy extending base policy
package afdp.policies.ai.model_deployment

import data.afdp.policies.base.deployment

# Inherit base rules and add specific conditions
allow if {
    deployment.default_security_controls  # Inherit from base
    ai_specific_requirements             # Add AI-specific rules
}

ai_specific_requirements if {
    input.model.bias_testing.completed == true
    input.model.explainability.available == true
    input.model.monitoring.enabled == true
}
```

### Dynamic Policy Loading

```rego
# Load policies based on deployment characteristics
applicable_policies := policies if {
    base_policies := ["security", "compliance"]
    environment_policies := environment_specific_policies(input.environment) 
    compliance_policies := compliance_specific_policies(input.compliance.frameworks)
    
    policies := array.concat(base_policies, array.concat(environment_policies, compliance_policies))
}

environment_specific_policies(env) := ["development"] if env == "development"
environment_specific_policies(env) := ["staging", "change_management"] if env == "staging"  
environment_specific_policies(env) := ["production", "change_management", "incident_response"] if env == "production"
```

### Context-Aware Policies

```rego
# Policies that adapt based on context
approval_requirements := requirements if {
    # Base requirements
    base_requirements := ["technical_review"]
    
    # Add security review for sensitive data
    security_requirements := ["security_review"] if input.data.classification == "sensitive"
    default security_requirements := []
    
    # Add compliance review for regulated frameworks
    compliance_requirements := ["compliance_review"] if count(input.compliance.frameworks) > 0
    default compliance_requirements := []
    
    # Add executive approval for high-risk deployments
    executive_requirements := ["executive_approval"] if risk_score > 8
    default executive_requirements := []
    
    # Combine all requirements
    requirements := array.concat(base_requirements, 
        array.concat(security_requirements,
            array.concat(compliance_requirements, executive_requirements)))
}
```

### Policy Testing and Simulation

```rego
# Test cases embedded in policy for validation
test_allow_development_deployment if {
    allow with input as {
        "environment": "development",
        "data": {"classification": "internal"},
        "user": {"role": "developer"}
    }
}

test_require_approval_production_deployment if {
    require_approval with input as {
        "environment": "production", 
        "data": {"classification": "sensitive"},
        "user": {"role": "developer"}
    }
}

test_deny_restricted_data_without_clearance if {
    not allow with input as {
        "environment": "production",
        "data": {"classification": "restricted"},
        "user": {"clearance_level": "public"}
    }
}

# Simulation scenarios for policy validation
simulation_scenarios := [
    {
        "name": "typical_ml_deployment",
        "input": {
            "environment": "production",
            "model": {"complexity": "medium"},
            "data": {"classification": "internal"}
        },
        "expected_result": "require_approval"
    },
    {
        "name": "high_risk_deployment", 
        "input": {
            "environment": "production",
            "model": {"complexity": "high"},
            "data": {"classification": "sensitive"}
        },
        "expected_result": "require_approval"
    }
]
```

## 📋 Compliance Templates

### SOX (Sarbanes-Oxley) Template

```rego
package afdp.policies.compliance.sox

import rego.v1
import data.afdp.compliance.sox as sox_framework

# SOX compliance requirements for financial reporting systems
sox_compliant if {
    # Financial data handling requirements
    financial_data_controls
    
    # Segregation of duties
    segregation_of_duties
    
    # Change management controls  
    change_management_controls
    
    # Audit trail requirements
    audit_trail_complete
}

financial_data_controls if {
    # Systems processing financial data must have additional controls
    input.data.classification in ["financial", "sensitive"]
    input.security_controls.encryption.enabled == true
    input.security_controls.access_logging.enabled == true
    input.security_controls.data_integrity.enabled == true
}

segregation_of_duties if {
    # No single person can deploy and approve financial systems
    input.requestor.user_id != input.approvals[_].user_id
    
    # Require multiple approvers for financial systems
    count([approval | 
        approval := input.approvals[_]
        approval.status == "approved"
        approval.role in ["financial_controller", "cfo", "audit_manager"]
    ]) >= 2
}

change_management_controls if {
    # All changes must be documented and approved
    input.change_request.id != null
    input.change_request.status == "approved"
    input.change_request.business_justification != null
    
    # Emergency changes require post-deployment review
    not input.change_request.emergency
}

audit_trail_complete if {
    # Complete audit trail from request to deployment
    input.audit_trail.complete == true
    input.audit_trail.immutable == true
    
    # Integration with audit systems
    input.integrations.audit_system.enabled == true
}
```

### HIPAA Template

```rego
package afdp.policies.compliance.hipaa

import rego.v1

# HIPAA compliance for healthcare AI systems
hipaa_compliant if {
    # Technical safeguards
    technical_safeguards
    
    # Administrative safeguards
    administrative_safeguards
    
    # Physical safeguards (infrastructure level)
    physical_safeguards_verified
    
    # Business associate agreements
    business_associate_compliance
}

technical_safeguards if {
    # Access control requirements
    input.access_controls.unique_user_identification == true
    input.access_controls.automatic_logoff.enabled == true
    input.access_controls.encryption.enabled == true
    
    # Audit controls
    input.audit_controls.logging.enabled == true
    input.audit_controls.monitoring.enabled == true
    
    # Integrity controls
    input.integrity_controls.data_integrity.enabled == true
    input.integrity_controls.tampering_detection.enabled == true
    
    # Transmission security
    input.transmission_security.encryption_in_transit == true
    input.transmission_security.end_to_end_encryption == true
}

administrative_safeguards if {
    # Security officer assigned
    input.security_officer.assigned == true
    
    # Workforce training completed
    input.workforce_training.hipaa_training.completed == true
    
    # Access management procedures
    input.access_management.procedures.documented == true
    input.access_management.regular_reviews.enabled == true
}

phi_data_handling if {
    # Protected Health Information handling requirements
    input.data.contains_phi == true implies all([
        input.data.de_identification.status == "safe_harbor",
        input.data.minimum_necessary.applied == true,
        input.data.retention_policy.defined == true
    ])
}
```

### FedRAMP Template

```rego
package afdp.policies.compliance.fedramp

import rego.v1

# FedRAMP compliance for government systems
fedramp_compliant if {
    # Security controls implementation (NIST SP 800-53)
    security_controls_implemented
    
    # Continuous monitoring
    continuous_monitoring_enabled
    
    # Incident response procedures
    incident_response_ready
    
    # Supply chain risk management
    supply_chain_controls
}

security_controls_implemented if {
    # Access Control (AC) family
    access_control_implemented
    
    # Configuration Management (CM) family  
    configuration_management_implemented
    
    # System and Communications Protection (SC) family
    system_protection_implemented
}

access_control_implemented if {
    # AC-2: Account Management
    input.access_controls.account_management.enabled == true
    
    # AC-3: Access Enforcement
    input.access_controls.rbac.enabled == true
    
    # AC-6: Least Privilege
    input.access_controls.least_privilege.enforced == true
    
    # AC-17: Remote Access
    input.access_controls.remote_access.mfa_required == true
}

continuous_monitoring_enabled if {
    # Real-time security monitoring
    input.monitoring.security_events.real_time == true
    
    # Vulnerability scanning
    input.monitoring.vulnerability_scanning.automated == true
    
    # Configuration compliance monitoring
    input.monitoring.configuration_compliance.enabled == true
    
    # Performance monitoring
    input.monitoring.performance.enabled == true
}
```

## 💡 Best Practices

### Policy Organization

```rego
# Use hierarchical package structure
package afdp.policies.domain.subdomain.specific_policy

# Examples of good organization:
# afdp.policies.ai.model_deployment
# afdp.policies.ai.data_processing  
# afdp.policies.security.access_control
# afdp.policies.compliance.sox.financial_reporting
# afdp.policies.infrastructure.network_security
```

### Naming Conventions

```rego
# Use descriptive variable names
deployment_environment := input.deployment.environment  # Good
env := input.environment                                # Avoid

# Use consistent naming patterns
user_has_role(role) if input.user.role == role        # Good function name
check_role(r) if input.user.role == r                 # Less descriptive

# Use meaningful rule names
production_deployment_requires_approval if {           # Clear intent
    input.environment == "production"
}

prod_needs_approval if {                               # Less clear
    input.environment == "production" 
}
```

### Error Handling and Validation

```rego
# Validate input structure
valid_input if {
    # Required fields present
    input.deployment.environment != null
    input.user.email != null
    input.timestamp != null
    
    # Valid values
    input.deployment.environment in ["development", "staging", "production"]
    regex.match(`^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$`, input.user.email)
}

# Provide meaningful error messages
validation_errors := errors if {
    errors := [error |
        not input.deployment.environment
        error := "Missing required field: deployment.environment"
    ] + [error |
        not input.user.email
        error := "Missing required field: user.email"
    ] + [error |
        input.deployment.environment
        not input.deployment.environment in ["development", "staging", "production"]
        error := sprintf("Invalid environment: %s. Must be one of: development, staging, production", [input.deployment.environment])
    ]
    count(errors) > 0
}

# Fail safely with default deny
default allow := false
allow if {
    valid_input
    policy_conditions_met
}
```

### Performance Optimization

```rego
# Use efficient data structures
approved_users := {"alice@company.com", "bob@company.com", "charlie@company.com"}
user_approved if input.user.email in approved_users  # O(1) lookup

# Avoid inefficient patterns
user_approved if {  # Less efficient O(n) search
    some user in ["alice@company.com", "bob@company.com", "charlie@company.com"]
    user == input.user.email
}

# Cache expensive computations
risk_score := score if {
    # Cache result to avoid recalculation
    score := calculate_risk_score_once
}

calculate_risk_score_once := score if {
    # Expensive calculation performed once
    factors := [
        environment_risk(input.environment),
        data_risk(input.data.classification),
        complexity_risk(input.model.complexity)
    ]
    score := sum(factors) / count(factors)
}
```

### Documentation and Maintainability

```rego
# Document complex policies thoroughly
# Policy: AI Model Production Deployment
# Purpose: Ensure AI models meet security and compliance requirements before production deployment
# Compliance: SOX, HIPAA, PCI-DSS
# Last Updated: 2025-07-23
# Author: security-team@company.com

package afdp.policies.ai.production_deployment

import rego.v1

# SECTION: Risk Assessment
# Calculate overall risk score based on multiple factors
risk_score := score if {
    # Environment risk (production = higher risk)
    env_risk := environment_risk_score(input.environment)
    
    # Data sensitivity risk  
    data_risk := data_classification_risk_score(input.data.classification)
    
    # Model complexity risk
    model_risk := model_complexity_risk_score(input.model)
    
    # Infrastructure risk
    infra_risk := infrastructure_risk_score(input.infrastructure)
    
    # Weighted average (adjust weights based on organizational priorities)
    score := (env_risk * 0.3) + (data_risk * 0.3) + (model_risk * 0.25) + (infra_risk * 0.15)
}

# SECTION: Approval Requirements  
# Determine required approvers based on risk and compliance requirements
required_approvers := approvers if {
    base_approvers := ["technical_lead"]
    
    security_approvers := ["security_officer"] if risk_score > 5
    default security_approvers := []
    
    compliance_approvers := ["compliance_manager"] if count(input.compliance.frameworks) > 0
    default compliance_approvers := []
    
    executive_approvers := ["cto"] if risk_score > 8
    default executive_approvers := []
    
    approvers := array.concat(base_approvers,
        array.concat(security_approvers,
            array.concat(compliance_approvers, executive_approvers)))
}
```

## 📖 Examples

### Basic AI Model Deployment Policy

```rego
package afdp.policies.examples.basic_ai_deployment

import rego.v1

# Simple policy for AI model deployments
metadata := {
    "name": "Basic AI Model Deployment",
    "version": "1.0.0",
    "description": "Basic policy for AI model deployment approval",
    "author": "policy-team@company.com"
}

# Default to secure (deny unless explicitly allowed)
default allow := false
default require_approval := false

# Allow automatic deployment to development
allow if {
    input.environment == "development"
    input.data.classification in ["public", "internal"]
    input.user.role in ["developer", "ml_engineer", "data_scientist"]
}

# Require approval for staging deployments
require_approval if {
    input.environment == "staging"
    input.data.classification in ["internal", "sensitive"]
}

# Require approval for all production deployments
require_approval if {
    input.environment == "production"
}

# High-risk models always require approval
require_approval if {
    input.risk_score > 7
}

# Calculate basic risk score
risk_score := score if {
    environment_risk := {"development": 1, "staging": 3, "production": 5}[input.environment]
    data_risk := {"public": 1, "internal": 3, "sensitive": 5, "restricted": 8}[input.data.classification]
    
    # Additional risk factors
    factor_risk := count([factor | 
        factor := input.risk_factors[_]
        factor in ["external_dependencies", "large_model", "real_time_inference"]
    ])
    
    score := environment_risk + data_risk + factor_risk
}

# Determine required approvers
required_approvers := approvers if {
    base_approvers := []
    
    # Add security officer for sensitive data
    security_approvers := ["security_officer"] if input.data.classification in ["sensitive", "restricted"]
    default security_approvers := []
    
    # Add compliance manager for compliance frameworks
    compliance_approvers := ["compliance_manager"] if count(input.compliance.frameworks) > 0
    default compliance_approvers := []
    
    # Add technical lead for production
    tech_approvers := ["technical_lead"] if input.environment == "production"
    default tech_approvers := []
    
    approvers := array.concat(base_approvers,
        array.concat(security_approvers, 
            array.concat(compliance_approvers, tech_approvers)))
}

# Generate decision explanation
decision := {
    "result": result,
    "reasoning": reasoning,
    "risk_score": risk_score,
    "required_approvers": required_approvers,
    "policy_version": metadata.version
}

result := "allow" if allow
result := "require_approval" if require_approval
result := "deny"  # Default

reasoning := "Automatic approval for development environment with internal data" if {
    allow
    input.environment == "development"
}

reasoning := sprintf("Approval required for %s environment (risk score: %d)", [input.environment, risk_score]) if {
    require_approval
}

reasoning := "Deployment denied - does not meet policy requirements" if {
    not allow
    not require_approval
}
```

### Advanced Compliance Policy

```rego
package afdp.policies.examples.advanced_compliance

import rego.v1
import data.afdp.compliance.frameworks

# Advanced policy with multiple compliance frameworks
metadata := {
    "name": "Multi-Framework Compliance Policy",
    "version": "2.1.0", 
    "description": "Comprehensive policy supporting SOX, HIPAA, PCI-DSS, and FedRAMP",
    "compliance_frameworks": ["SOX", "HIPAA", "PCI-DSS", "FedRAMP"],
    "author": "compliance-team@company.com",
    "last_updated": "2025-07-23T10:30:00Z"
}

# Security by default
default allow := false
default require_approval := true

# Multi-framework compliance evaluation
compliant if {
    # Evaluate each required framework
    all_frameworks_compliant
    
    # Security baseline requirements
    security_baseline_met
    
    # Data handling requirements
    data_handling_compliant
}

all_frameworks_compliant if {
    # Check each required compliance framework
    every framework in input.compliance.frameworks {
        framework_compliant(framework)
    }
}

framework_compliant("SOX") if {
    # Sarbanes-Oxley requirements
    sox_financial_controls
    sox_segregation_of_duties
    sox_audit_trail
}

framework_compliant("HIPAA") if {
    # Healthcare data protection
    hipaa_technical_safeguards
    hipaa_administrative_safeguards
    hipaa_phi_protection
}

framework_compliant("PCI-DSS") if {
    # Payment card industry requirements
    pci_network_security
    pci_data_protection
    pci_access_control
}

framework_compliant("FedRAMP") if {
    # Federal security requirements
    fedramp_security_controls
    fedramp_continuous_monitoring
    fedramp_incident_response
}

# SOX-specific requirements
sox_financial_controls if {
    input.data.classification == "financial" implies all([
        input.security.encryption.enabled == true,
        input.security.integrity_monitoring.enabled == true,
        input.security.access_logging.comprehensive == true
    ])
}

sox_segregation_of_duties if {
    # Developer cannot approve their own deployment
    input.requestor.user_id != input.approvals[_].user_id
    
    # Financial systems require CFO or Controller approval
    input.data.classification == "financial" implies any([
        "cfo" in [approval.role | approval := input.approvals[_]; approval.status == "approved"],
        "controller" in [approval.role | approval := input.approvals[_]; approval.status == "approved"]
    ])
}

sox_audit_trail if {
    input.audit.complete == true
    input.audit.immutable == true
    input.audit.retention_years >= 7
}

# HIPAA-specific requirements
hipaa_technical_safeguards if {
    input.data.contains_phi == true implies all([
        input.access.unique_identification == true,
        input.access.automatic_logoff.enabled == true,  
        input.encryption.at_rest == true,
        input.encryption.in_transit == true,
        input.audit.healthcare_specific == true
    ])
}

hipaa_administrative_safeguards if {
    input.data.contains_phi == true implies all([
        input.security_officer.assigned == true,
        input.workforce_training.hipaa.completed == true,
        input.access_management.regular_reviews == true
    ])
}

hipaa_phi_protection if {
    input.data.contains_phi == true implies all([
        input.data.de_identification.method in ["safe_harbor", "expert_determination"],
        input.data.minimum_necessary.applied == true,
        input.business_associates.agreements_signed == true
    ])
}

# Advanced risk calculation with compliance weighting
compliance_weighted_risk_score := score if {
    base_risk := base_risk_calculation
    
    # Increase risk for non-compliant frameworks
    compliance_penalty := count([framework | 
        framework := input.compliance.frameworks[_]
        not framework_compliant(framework)
    ]) * 2
    
    # Decrease risk for additional security controls
    security_bonus := count([control |
        control := input.security.additional_controls[_]
        control.enabled == true
    ]) * 0.5
    
    score := base_risk + compliance_penalty - security_bonus
}

# Dynamic approval requirements based on compliance
compliance_required_approvers := approvers if {
    base_approvers := ["technical_lead"]
    
    # SOX requirements
    sox_approvers := ["cfo", "controller"] if "SOX" in input.compliance.frameworks
    default sox_approvers := []
    
    # HIPAA requirements  
    hipaa_approvers := ["privacy_officer", "security_officer"] if "HIPAA" in input.compliance.frameworks
    default hipaa_approvers := []
    
    # PCI-DSS requirements
    pci_approvers := ["security_officer", "compliance_manager"] if "PCI-DSS" in input.compliance.frameworks
    default pci_approvers := []
    
    # FedRAMP requirements
    fedramp_approvers := ["security_officer", "compliance_manager", "ciso"] if "FedRAMP" in input.compliance.frameworks  
    default fedramp_approvers := []
    
    all_approvers := array.concat(base_approvers,
        array.concat(sox_approvers,
            array.concat(hipaa_approvers,
                array.concat(pci_approvers, fedramp_approvers))))
    
    # Remove duplicates
    approvers := {approver | approver := all_approvers[_]}
}

# Final decision with detailed reasoning
decision := {
    "result": result,
    "reasoning": detailed_reasoning,
    "risk_score": compliance_weighted_risk_score,
    "required_approvers": compliance_required_approvers,
    "compliance_status": compliance_status,
    "policy_metadata": metadata
}

result := "allow" if {
    compliant
    compliance_weighted_risk_score <= 5
}

result := "require_approval" if {
    compliant  
    compliance_weighted_risk_score > 5
}

result := "deny" if {
    not compliant
}

compliance_status := {framework: status |
    framework := input.compliance.frameworks[_]
    status := "compliant" if framework_compliant(framework)
    status := "non_compliant" if not framework_compliant(framework)
}

detailed_reasoning := reasoning if {
    compliant_frameworks := [f | f := input.compliance.frameworks[_]; framework_compliant(f)]
    non_compliant_frameworks := [f | f := input.compliance.frameworks[_]; not framework_compliant(f)]
    
    reasoning := sprintf(
        "Compliance Status: %d/%d frameworks compliant. Risk Score: %.1f. %s",
        [
            count(compliant_frameworks),
            count(input.compliance.frameworks), 
            compliance_weighted_risk_score,
            "Additional approvals required." if compliance_weighted_risk_score > 5 else "Automatic approval authorized."
        ]
    )
}
```

## 🧪 Testing and Validation

### Unit Testing Policies

```rego
# Test file: policy_test.rego
package afdp.policies.examples.basic_ai_deployment_test

import rego.v1
import data.afdp.policies.examples.basic_ai_deployment

# Test automatic approval for development
test_allow_development if {
    basic_ai_deployment.allow with input as {
        "environment": "development",
        "data": {"classification": "internal"},
        "user": {"role": "developer"},
        "risk_factors": []
    }
}

# Test approval required for production
test_require_approval_production if {
    basic_ai_deployment.require_approval with input as {
        "environment": "production", 
        "data": {"classification": "internal"},
        "user": {"role": "developer"},
        "risk_factors": []
    }
}

# Test high-risk deployment requires approval
test_require_approval_high_risk if {
    basic_ai_deployment.require_approval with input as {
        "environment": "development",
        "data": {"classification": "sensitive"},
        "user": {"role": "developer"},
        "risk_factors": ["external_dependencies", "large_model", "real_time_inference"]
    }
}

# Test risk score calculation
test_risk_score_calculation if {
    score := basic_ai_deployment.risk_score with input as {
        "environment": "production",             # +5
        "data": {"classification": "sensitive"}, # +5  
        "risk_factors": ["external_dependencies"] # +1
    }
    score == 11
}

# Test required approvers logic
test_required_approvers if {
    approvers := basic_ai_deployment.required_approvers with input as {
        "environment": "production",
        "data": {"classification": "sensitive"},
        "compliance": {"frameworks": ["SOX", "HIPAA"]}
    }
    
    # Should include all three types of approvers
    "technical_lead" in approvers
    "security_officer" in approvers  
    "compliance_manager" in approvers
}
```

### Integration Testing

```rego
# Integration test scenarios
test_scenarios := [
    {
        "name": "typical_ml_model_deployment",
        "description": "Standard machine learning model deployment to production",
        "input": {
            "environment": "production",
            "data": {"classification": "internal"},
            "model": {"type": "classification", "framework": "tensorflow"},
            "user": {"role": "ml_engineer", "email": "engineer@company.com"},
            "risk_factors": ["external_dependencies"],
            "compliance": {"frameworks": []}
        },
        "expected": {
            "result": "require_approval",
            "required_approvers": ["technical_lead"],
            "risk_score_range": [6, 8]
        }
    },
    {
        "name": "high_risk_financial_model",
        "description": "High-risk financial model with SOX compliance requirements",
        "input": {
            "environment": "production",
            "data": {"classification": "financial", "contains_pii": true},
            "model": {"type": "risk_assessment", "complexity": "high"},
            "user": {"role": "quant_analyst", "email": "analyst@company.com"},
            "risk_factors": ["external_dependencies", "large_model", "real_time_inference"],
            "compliance": {"frameworks": ["SOX"]}
        },
        "expected": {
            "result": "require_approval", 
            "required_approvers": ["technical_lead", "security_officer", "compliance_manager"],
            "risk_score_range": [10, 12]
        }
    },
    {
        "name": "development_prototype",
        "description": "Low-risk development prototype deployment",
        "input": {
            "environment": "development",
            "data": {"classification": "internal"},
            "model": {"type": "experimental", "complexity": "low"},
            "user": {"role": "data_scientist", "email": "scientist@company.com"},
            "risk_factors": [],
            "compliance": {"frameworks": []}
        },
        "expected": {
            "result": "allow",
            "required_approvers": [],
            "risk_score_range": [3, 5]
        }
    }
]

# Run integration tests
test_integration_scenarios if {
    every scenario in test_scenarios {
        test_scenario_passes(scenario)
    }
}

test_scenario_passes(scenario) if {
    # Evaluate policy with scenario input
    result := basic_ai_deployment.decision with input as scenario.input
    
    # Check expected result
    result.result == scenario.expected.result
    
    # Check required approvers
    every expected_approver in scenario.expected.required_approvers {
        expected_approver in result.required_approvers  
    }
    
    # Check risk score range
    result.risk_score >= scenario.expected.risk_score_range[0]
    result.risk_score <= scenario.expected.risk_score_range[1]
}
```

### Policy Validation Tools

```rego
# Policy validation and linting rules
package afdp.policies.validation

import rego.v1

# Validate policy structure
valid_policy_structure(policy) if {
    # Required metadata fields
    policy.metadata.name != ""
    policy.metadata.version != ""
    policy.metadata.description != ""
    policy.metadata.author != ""
    
    # Valid version format (semantic versioning)
    regex.match(`^\d+\.\d+\.\d+$`, policy.metadata.version)
    
    # Valid author email
    regex.match(`^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$`, policy.metadata.author)
}

# Check for security anti-patterns
security_antipatterns(policy) := violations if {
    violations := [violation |
        # Check for hardcoded secrets
        contains(policy.content, "password") 
        violation := "Possible hardcoded password found in policy"
    ] + [violation |
        # Check for overly permissive rules
        contains(policy.content, "default allow := true")
        violation := "Overly permissive default allow rule"
    ] + [violation |
        # Check for missing input validation
        not contains(policy.content, "valid_input")
        violation := "Missing input validation"
    ]
}

# Performance analysis
performance_issues(policy) := issues if {
    issues := [issue |
        # Check for inefficient patterns
        contains(policy.content, "input.[_]")  # O(n) array traversal
        issue := "Inefficient array traversal pattern detected"
    ] + [issue |
        # Check for complex nested loops
        regex.match(`every.*every.*every`, policy.content)
        issue := "Complex nested loops may impact performance"
    ]
}

# Completeness checks
completeness_issues(policy) := issues if {
    issues := [issue |
        not contains(policy.content, "test_")
        issue := "Policy missing unit tests"
    ] + [issue |
        not contains(policy.content, "reasoning :=")
        issue := "Policy missing decision reasoning"
    ] + [issue |
        not contains(policy.content, "metadata :=")
        issue := "Policy missing metadata definition"
    ]
}
```

## 🔒 Security Considerations

### Input Sanitization

```rego
# Always validate and sanitize input data
sanitized_input := clean_input if {
    # Validate required fields exist
    required_fields_present
    
    # Sanitize string inputs
    clean_user_email := trim_space(lower(input.user.email))
    clean_environment := trim_space(lower(input.environment))
    
    # Validate data types
    is_string(input.user.email)
    is_string(input.environment)
    is_number(input.risk_score) if input.risk_score
    
    # Construct sanitized input
    clean_input := {
        "user": {"email": clean_user_email},
        "environment": clean_environment,
        "risk_score": input.risk_score
    }
}

required_fields_present if {
    input.user.email != null
    input.environment != null
    input.timestamp != null
}
```

### Access Control in Policies

```rego
# Implement fine-grained access control within policies
authorized_to_modify_policy if {
    # Only specific roles can modify policies
    input.user.role in ["policy_admin", "compliance_officer", "security_officer"]
    
    # Additional verification for sensitive policies
    input.policy.classification == "restricted" implies input.user.clearance_level == "secret"
    
    # Multi-factor authentication required for policy changes
    input.authentication.mfa_verified == true
}

# Audit all policy access and modifications
audit_policy_access := {
    "timestamp": time.now_ns(),
    "user": input.user.email,
    "action": "policy_evaluation",
    "policy": input.policy.name,
    "result": decision.result,
    "risk_level": calculate_audit_risk_level(input, decision)
}
```

### Cryptographic Integrity

```rego
# Verify policy integrity using cryptographic signatures
policy_integrity_verified if {
    # Check policy signature
    verify_signature(input.policy.content, input.policy.signature, input.policy.public_key)
    
    # Verify policy hasn't been tampered with
    calculated_hash := sha256(input.policy.content)
    calculated_hash == input.policy.content_hash
    
    # Check certificate chain
    valid_certificate_chain(input.policy.certificate_chain)
}

# Helper function to verify signatures (implemented in Go)
verify_signature(content, signature, public_key) := result if {
    # This would be implemented as a built-in function in Go
    # using standard library crypto functions
    result := crypto.verify_ed25519(content, signature, public_key)
}
```

### Resource Limits and DoS Protection

```rego
# Implement resource limits to prevent DoS attacks
within_resource_limits if {
    # Limit policy evaluation time
    evaluation_timeout_ms <= 1000
    
    # Limit input size
    json.marshal(input) |
    count(json.marshal(input)) <= 1048576  # 1MB limit
    
    # Limit complexity of policy decisions
    decision_complexity_score <= 100
}

decision_complexity_score := score if {
    # Calculate complexity based on policy structure
    condition_count := count([rule | rule := rules[_]; rule.type == "condition"])
    approval_count := count(required_approvers)
    compliance_count := count(input.compliance.frameworks)
    
    score := (condition_count * 2) + (approval_count * 3) + (compliance_count * 5)
}
```

---

**Document Control:**
- **Next Review Date:** October 2025
- **Owner:** AFDP Policy Engine Team  
- **Approvers:** Chief Compliance Officer, CISO, Lead Policy Architect
- **Distribution:** Policy authors, administrators, developers, auditors

**Classification:** Public  
**Revision History:** v1.0 - Initial policy language reference documentation