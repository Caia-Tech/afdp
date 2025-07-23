package models

import (
	"time"
	"github.com/google/uuid"
)

// PolicyRequest represents a request for policy evaluation
type PolicyRequest struct {
	ID        uuid.UUID     `json:"id" db:"id"`
	Subject   string        `json:"subject" db:"subject"`
	Resource  interface{}   `json:"resource" db:"resource"`
	Context   RequestContext `json:"context" db:"context"`
	CreatedAt time.Time     `json:"created_at" db:"created_at"`
}

// RequestContext provides contextual information for policy evaluation
type RequestContext struct {
	Actor      string            `json:"actor" db:"actor"`
	Timestamp  time.Time         `json:"timestamp" db:"timestamp"`
	Compliance []string          `json:"compliance" db:"compliance"`
	Metadata   map[string]string `json:"metadata" db:"metadata"`
}

// PolicyDecision represents the result of policy evaluation
type PolicyDecision struct {
	ID                uuid.UUID         `json:"id" db:"id"`
	RequestID         uuid.UUID         `json:"request_id" db:"request_id"`
	Result            DecisionResult    `json:"result" db:"result"`
	Reasoning         string            `json:"reasoning" db:"reasoning"`
	RequiredApprovals []string          `json:"required_approvals" db:"required_approvals"`
	RiskScore         float64           `json:"risk_score" db:"risk_score"`
	Metadata          map[string]string `json:"metadata" db:"metadata"`
	EvaluatedAt       time.Time         `json:"evaluated_at" db:"evaluated_at"`
	NotaryReceiptID   *string           `json:"notary_receipt_id,omitempty" db:"notary_receipt_id"`
}

// DecisionResult represents the possible outcomes of policy evaluation
type DecisionResult string

const (
	DecisionAllow              DecisionResult = "allow"
	DecisionDeny               DecisionResult = "deny"
	DecisionRequireApproval    DecisionResult = "require_approval"
	DecisionRequireReview      DecisionResult = "require_review"
	DecisionConditionalAllow   DecisionResult = "conditional_allow"
)

// ApprovalRequest represents a human approval required for a policy decision
type ApprovalRequest struct {
	ID              uuid.UUID     `json:"id" db:"id"`
	DecisionID      uuid.UUID     `json:"decision_id" db:"decision_id"`
	ApproverRole    string        `json:"approver_role" db:"approver_role"`
	ApproverEmail   *string       `json:"approver_email,omitempty" db:"approver_email"`
	Status          ApprovalStatus `json:"status" db:"status"`
	Reasoning       *string       `json:"reasoning,omitempty" db:"reasoning"`
	RequestedAt     time.Time     `json:"requested_at" db:"requested_at"`
	RespondedAt     *time.Time    `json:"responded_at,omitempty" db:"responded_at"`
	ExpiresAt       time.Time     `json:"expires_at" db:"expires_at"`
}

// ApprovalStatus represents the status of an approval request
type ApprovalStatus string

const (
	ApprovalPending  ApprovalStatus = "pending"
	ApprovalApproved ApprovalStatus = "approved"
	ApprovalRejected ApprovalStatus = "rejected"
	ApprovalExpired  ApprovalStatus = "expired"
)

// ModelDeployment represents an AI model deployment resource
type ModelDeployment struct {
	Name               string   `json:"name"`
	Version            string   `json:"version"`
	Environment        string   `json:"environment"`
	DataClassification string   `json:"data_classification"`
	Compliance         []string `json:"compliance"`
	RiskFactors        []string `json:"risk_factors"`
}

// Policy represents a policy definition
type Policy struct {
	ID                 uuid.UUID              `json:"id" db:"id"`
	Name               string                 `json:"name" db:"name"`
	Version            string                 `json:"version" db:"version"`
	Description        string                 `json:"description" db:"description"`
	ComplianceFrameworks []string             `json:"compliance_frameworks" db:"compliance_frameworks"`
	Rules              PolicyRules            `json:"rules" db:"rules"`
	WorkflowConfig     WorkflowConfig         `json:"workflow_config" db:"workflow_config"`
	Metadata           map[string]interface{} `json:"metadata" db:"metadata"`
	CreatedAt          time.Time              `json:"created_at" db:"created_at"`
	UpdatedAt          time.Time              `json:"updated_at" db:"updated_at"`
	IsActive           bool                   `json:"is_active" db:"is_active"`
}

// PolicyRules defines the evaluation rules for a policy
type PolicyRules struct {
	Conditions []RuleCondition `json:"conditions"`
	Approvers  []ApproverRule  `json:"approvers"`
}

// RuleCondition represents a condition that must be met
type RuleCondition struct {
	Field    string      `json:"field"`
	Operator string      `json:"operator"`
	Values   []string    `json:"values"`
}

// ApproverRule defines who can approve based on conditions
type ApproverRule struct {
	Role       string  `json:"role"`
	Required   bool    `json:"required"`
	RequiredIf *string `json:"required_if,omitempty"`
}

// WorkflowConfig defines the approval workflow
type WorkflowConfig struct {
	Steps   []WorkflowStep `json:"steps"`
	Timeout string         `json:"timeout"`
}

// WorkflowStep represents a step in the approval workflow
type WorkflowStep struct {
	Name     string `json:"name"`
	Type     string `json:"type"`
	Config   map[string]interface{} `json:"config"`
}