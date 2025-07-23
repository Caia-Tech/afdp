package plugins

import (
	"context"
	"fmt"
	"time"

	"github.com/open-policy-agent/opa/rego"
	"github.com/open-policy-agent/opa/storage"
	"github.com/open-policy-agent/opa/storage/inmem"
	"github.com/Caia-Tech/afdp/services/policy-engine/pkg/framework"
)

// BuiltinRegoEvaluator is the built-in Rego policy evaluator
type BuiltinRegoEvaluator struct {
	config    framework.PluginConfig
	store     storage.Store
	compiler  *rego.Rego
	policies  map[string]*compiledPolicy
	startTime time.Time
	status    framework.PluginStatus
}

type compiledPolicy struct {
	id          string
	query       rego.PreparedEvalQuery
	rawPolicy   string
	compiledAt  time.Time
}

// NewBuiltinRegoEvaluator creates a new Rego evaluator
func NewBuiltinRegoEvaluator(config framework.PluginConfig) (framework.Plugin, error) {
	return &BuiltinRegoEvaluator{
		config:   config,
		store:    inmem.New(),
		policies: make(map[string]*compiledPolicy),
		status:   framework.PluginStatusUnknown,
	}, nil
}

// Plugin interface implementation

func (r *BuiltinRegoEvaluator) Name() string {
	return r.config.Name
}

func (r *BuiltinRegoEvaluator) Version() string {
	return "1.0.0"
}

func (r *BuiltinRegoEvaluator) Type() framework.PluginType {
	return framework.PluginTypeEvaluator
}

func (r *BuiltinRegoEvaluator) Metadata() framework.PluginMetadata {
	return framework.PluginMetadata{
		StartTime:    r.startTime,
		Uptime:       time.Since(r.startTime),
		RequestCount: 0, // Would track in real implementation
		ErrorCount:   0,
		Metadata: map[string]interface{}{
			"engine":           "opa",
			"opa_version":      "0.45.0",
			"supported_builtins": []string{"http.send", "time.now_ns"},
		},
	}
}

func (r *BuiltinRegoEvaluator) Initialize(ctx context.Context, config framework.PluginConfig) error {
	r.status = framework.PluginStatusInitializing
	
	// Initialize OPA store with any data from config
	if data, ok := config.Config["data"].(map[string]interface{}); ok {
		txn, err := r.store.NewTransaction(ctx)
		if err != nil {
			return fmt.Errorf("failed to create transaction: %w", err)
		}
		
		if err := r.store.Write(ctx, txn, storage.AddOp, storage.MustParsePath("/"), data); err != nil {
			r.store.Abort(ctx, txn)
			return fmt.Errorf("failed to initialize data store: %w", err)
		}
		
		if err := r.store.Commit(ctx, txn); err != nil {
			return fmt.Errorf("failed to commit data store: %w", err)
		}
	}
	
	return nil
}

func (r *BuiltinRegoEvaluator) Start(ctx context.Context) error {
	r.status = framework.PluginStatusStarting
	r.startTime = time.Now()
	
	// Load any pre-configured policies
	if policies, ok := r.config.Config["policies"].(map[string]interface{}); ok {
		for id, policy := range policies {
			if policyStr, ok := policy.(string); ok {
				req := &framework.LoadPolicyRequest{
					PolicyID: id,
					Policy:   policyStr,
				}
				if _, err := r.LoadPolicy(ctx, req); err != nil {
					return fmt.Errorf("failed to load policy %s: %w", id, err)
				}
			}
		}
	}
	
	r.status = framework.PluginStatusRunning
	return nil
}

func (r *BuiltinRegoEvaluator) Stop(ctx context.Context) error {
	r.status = framework.PluginStatusStopping
	
	// Clear policies
	r.policies = make(map[string]*compiledPolicy)
	
	r.status = framework.PluginStatusStopped
	return nil
}

func (r *BuiltinRegoEvaluator) Reload(ctx context.Context, config framework.PluginConfig) error {
	// Update configuration
	r.config = config
	
	// Reload data store if provided
	if data, ok := config.Config["data"].(map[string]interface{}); ok {
		txn, err := r.store.NewTransaction(ctx)
		if err != nil {
			return fmt.Errorf("failed to create transaction: %w", err)
		}
		
		if err := r.store.Write(ctx, txn, storage.ReplaceOp, storage.MustParsePath("/"), data); err != nil {
			r.store.Abort(ctx, txn)
			return fmt.Errorf("failed to reload data store: %w", err)
		}
		
		if err := r.store.Commit(ctx, txn); err != nil {
			return fmt.Errorf("failed to commit data store: %w", err)
		}
	}
	
	return nil
}

func (r *BuiltinRegoEvaluator) Health() framework.HealthStatus {
	status := "healthy"
	message := "Rego evaluator is running"
	
	if r.status != framework.PluginStatusRunning {
		status = "unhealthy"
		message = fmt.Sprintf("Plugin is in %s state", r.status)
	}
	
	return framework.HealthStatus{
		Status:     status,
		Message:    message,
		LastCheck:  time.Now(),
		CheckCount: 1,
		Metadata: map[string]interface{}{
			"policies_loaded": len(r.policies),
			"uptime":          time.Since(r.startTime).String(),
		},
	}
}

func (r *BuiltinRegoEvaluator) Metrics() framework.PluginMetrics {
	return framework.PluginMetrics{
		CPUUsage:    0.0, // Would collect real metrics
		MemoryUsage: 0,
		RequestRate: 0.0,
		ErrorRate:   0.0,
		Timestamp:   time.Now(),
	}
}

func (r *BuiltinRegoEvaluator) ValidateConfig(config framework.PluginConfig) framework.ValidationResult {
	result := framework.ValidationResult{
		Valid: true,
	}
	
	// Validate Rego-specific configuration
	if _, hasData := config.Config["data"]; !hasData {
		result.Warnings = append(result.Warnings, framework.ValidationError{
			Field:    "config.data",
			Message:  "No data store configured",
			Code:     "missing_data",
			Severity: "warning",
		})
	}
	
	return result
}

// PolicyEvaluator interface implementation

func (r *BuiltinRegoEvaluator) CompilePolicy(ctx context.Context, req *framework.CompilePolicyRequest) (*framework.CompilePolicyResponse, error) {
	// Compile the policy
	compiler := rego.New(
		rego.Query(req.Query),
		rego.Module(req.PolicyID, req.Policy),
		rego.Store(r.store),
	)
	
	prepared, err := compiler.PrepareForEval(ctx)
	if err != nil {
		return nil, fmt.Errorf("compilation failed: %w", err)
	}
	
	// Store compiled policy
	r.policies[req.PolicyID] = &compiledPolicy{
		id:         req.PolicyID,
		query:      prepared,
		rawPolicy:  req.Policy,
		compiledAt: time.Now(),
	}
	
	return &framework.CompilePolicyResponse{
		PolicyID: req.PolicyID,
		Success:  true,
		Metadata: map[string]interface{}{
			"compiled_at": time.Now(),
		},
	}, nil
}

func (r *BuiltinRegoEvaluator) ValidatePolicy(ctx context.Context, req *framework.ValidatePolicyRequest) (*framework.ValidatePolicyResponse, error) {
	// Try to compile the policy
	compiler := rego.New(
		rego.Query("data.policy.allow"),
		rego.Module("validation", req.Policy),
		rego.Store(r.store),
	)
	
	_, err := compiler.PrepareForEval(ctx)
	
	response := &framework.ValidatePolicyResponse{
		Valid: err == nil,
	}
	
	if err != nil {
		response.Errors = []framework.ValidationError{
			{
				Field:    "policy",
				Message:  err.Error(),
				Code:     "compilation_error",
				Severity: "error",
			},
		}
	}
	
	return response, nil
}

func (r *BuiltinRegoEvaluator) Evaluate(ctx context.Context, req *framework.EvaluationRequest) (*framework.EvaluationResponse, error) {
	// Get compiled policy
	policy, exists := r.policies[req.PolicyID]
	if !exists {
		return nil, fmt.Errorf("policy %s not found", req.PolicyID)
	}
	
	// Evaluate with input
	results, err := policy.query.Eval(ctx, rego.EvalInput(req.Input))
	if err != nil {
		return nil, fmt.Errorf("evaluation failed: %w", err)
	}
	
	// Process results
	decision := &framework.PolicyDecision{
		Result: "deny", // Default deny
		Metadata: map[string]interface{}{
			"evaluated_at": time.Now(),
		},
	}
	
	if len(results) > 0 && len(results[0].Expressions) > 0 {
		if allow, ok := results[0].Expressions[0].Value.(bool); ok && allow {
			decision.Result = "allow"
		}
	}
	
	return &framework.EvaluationResponse{
		Decision:   *decision,
		Reasoning:  "Policy evaluation completed",
		Confidence: 1.0,
		Metadata:   map[string]interface{}{},
	}, nil
}

func (r *BuiltinRegoEvaluator) EvaluateBatch(ctx context.Context, req *framework.BatchEvaluationRequest) (*framework.BatchEvaluationResponse, error) {
	responses := make([]*framework.EvaluationResponse, len(req.Requests))
	
	for i, evalReq := range req.Requests {
		resp, err := r.Evaluate(ctx, evalReq)
		if err != nil {
			return nil, fmt.Errorf("batch evaluation failed at index %d: %w", i, err)
		}
		responses[i] = resp
	}
	
	return &framework.BatchEvaluationResponse{
		Responses: responses,
	}, nil
}

func (r *BuiltinRegoEvaluator) LoadPolicy(ctx context.Context, req *framework.LoadPolicyRequest) (*framework.LoadPolicyResponse, error) {
	// Compile and store the policy
	compileReq := &framework.CompilePolicyRequest{
		PolicyID: req.PolicyID,
		Policy:   req.Policy,
		Query:    "data.policy.allow",
	}
	
	if req.Query != "" {
		compileReq.Query = req.Query
	}
	
	if _, err := r.CompilePolicy(ctx, compileReq); err != nil {
		return nil, err
	}
	
	return &framework.LoadPolicyResponse{
		PolicyID: req.PolicyID,
		Success:  true,
	}, nil
}

func (r *BuiltinRegoEvaluator) UnloadPolicy(ctx context.Context, req *framework.UnloadPolicyRequest) (*framework.UnloadPolicyResponse, error) {
	if _, exists := r.policies[req.PolicyID]; !exists {
		return nil, fmt.Errorf("policy %s not found", req.PolicyID)
	}
	
	delete(r.policies, req.PolicyID)
	
	return &framework.UnloadPolicyResponse{
		PolicyID: req.PolicyID,
		Success:  true,
	}, nil
}

func (r *BuiltinRegoEvaluator) ListPolicies(ctx context.Context, req *framework.ListPoliciesRequest) (*framework.ListPoliciesResponse, error) {
	policies := make([]framework.PolicyInfo, 0, len(r.policies))
	
	for id, policy := range r.policies {
		policies = append(policies, framework.PolicyInfo{
			PolicyID:   id,
			CompiledAt: policy.compiledAt,
			Metadata: map[string]interface{}{
				"size": len(policy.rawPolicy),
			},
		})
	}
	
	return &framework.ListPoliciesResponse{
		Policies: policies,
	}, nil
}

func (r *BuiltinRegoEvaluator) SupportedLanguages() []string {
	return []string{"rego"}
}

func (r *BuiltinRegoEvaluator) SupportedFeatures() []string {
	return []string{
		"data_store",
		"http_calls",
		"batch_evaluation",
		"policy_validation",
	}
}