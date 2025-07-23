# AI Model Deployment Policy
# Defines rules for deploying AI models in different environments

package ai.deployment

import rego.v1

# Default decision is to deny unless explicitly allowed
default allow := false
default require_approval := false

# Allow deployment to development environment with minimal restrictions
allow if {
    input.resource.environment == "development"
    input.resource.data_classification in ["public", "internal"]
}

# Production deployments require approval
require_approval if {
    input.resource.environment == "production"
}

# High-risk deployments always require approval
require_approval if {
    input.resource.data_classification == "sensitive"
}

require_approval if {
    "external_dependencies" in input.resource.risk_factors
}

# Define required approvers based on risk and compliance
required_approvers contains "security_officer" if {
    input.resource.environment == "production"
}

required_approvers contains "compliance_manager" if {
    input.resource.data_classification == "sensitive"
}

required_approvers contains "cto" if {
    count(input.resource.risk_factors) > 3
}

# Calculate risk score (0-10 scale)
risk_score := score if {
    environment_risk := environment_risk_score(input.resource.environment)
    data_risk := data_classification_risk_score(input.resource.data_classification)
    factor_risk := count(input.resource.risk_factors)
    
    score := environment_risk + data_risk + factor_risk
}

environment_risk_score(env) := 1 if env == "development"
environment_risk_score(env) := 3 if env == "staging"
environment_risk_score(env) := 5 if env == "production"

data_classification_risk_score(classification) := 1 if classification == "public"
data_classification_risk_score(classification) := 3 if classification == "internal"
data_classification_risk_score(classification) := 5 if classification == "sensitive"

# Compliance framework specific rules
sox_compliant if {
    "SOX" in input.resource.compliance
    input.resource.environment == "production"
    "financial_data" in input.resource.risk_factors
}

hipaa_compliant if {
    "HIPAA" in input.resource.compliance
    input.resource.data_classification == "sensitive"
    "phi_access" in input.resource.risk_factors
}

# Generate explanation for the decision
explanation := msg if {
    allow
    msg := "Deployment allowed: Low risk development environment"
}

explanation := msg if {
    require_approval
    msg := sprintf("Approval required: %s environment with %s data classification", 
        [input.resource.environment, input.resource.data_classification])
}