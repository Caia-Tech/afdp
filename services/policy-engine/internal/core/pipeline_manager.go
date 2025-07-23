package core

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/Caia-Tech/afdp/services/policy-engine/internal/logging"
	"github.com/Caia-Tech/afdp/services/policy-engine/pkg/framework"
)

// PipelineManager manages policy evaluation pipelines
type PipelineManager struct {
	logger         *logging.Logger
	mu             sync.RWMutex
	pipelines      map[string]*PipelineDefinition
	executions     map[string]*PipelineExecution
	executionLimit int
}

// PipelineDefinition defines a policy evaluation pipeline
type PipelineDefinition struct {
	ID          string                   `json:"id"`
	Name        string                   `json:"name"`
	Description string                   `json:"description"`
	Steps       []PipelineStep           `json:"steps"`
	Metadata    map[string]interface{}   `json:"metadata"`
}

// PipelineStep represents a single step in a pipeline
type PipelineStep struct {
	Name        string                 `json:"name"`
	Type        string                 `json:"type"`
	PolicyID    string                 `json:"policy_id,omitempty"`
	Condition   string                 `json:"condition,omitempty"`
	Input       map[string]interface{} `json:"input,omitempty"`
	OnSuccess   string                 `json:"on_success,omitempty"`
	OnFailure   string                 `json:"on_failure,omitempty"`
	Parallel    bool                   `json:"parallel,omitempty"`
}

// PipelineExecution tracks a pipeline execution
type PipelineExecution struct {
	ID           string                 `json:"id"`
	PipelineID   string                 `json:"pipeline_id"`
	Status       string                 `json:"status"`
	StartTime    time.Time              `json:"start_time"`
	EndTime      *time.Time             `json:"end_time,omitempty"`
	CurrentStep  string                 `json:"current_step"`
	StepResults  map[string]StepResult  `json:"step_results"`
	FinalResult  *framework.PolicyDecision `json:"final_result,omitempty"`
	Error        string                 `json:"error,omitempty"`
	Context      map[string]interface{} `json:"context"`
}

// StepResult contains the result of a pipeline step
type StepResult struct {
	StepName   string                    `json:"step_name"`
	Status     string                    `json:"status"`
	StartTime  time.Time                 `json:"start_time"`
	EndTime    time.Time                 `json:"end_time"`
	Decision   *framework.PolicyDecision `json:"decision,omitempty"`
	Error      string                    `json:"error,omitempty"`
	Output     map[string]interface{}    `json:"output,omitempty"`
}

// NewPipelineManager creates a new pipeline manager
func NewPipelineManager(logger *logging.Logger) *PipelineManager {
	return &PipelineManager{
		logger:         logger,
		pipelines:      make(map[string]*PipelineDefinition),
		executions:     make(map[string]*PipelineExecution),
		executionLimit: 1000,
	}
}

// Initialize prepares the pipeline manager
func (pm *PipelineManager) Initialize(ctx context.Context) error {
	pm.logger.Info("Initializing pipeline manager...")
	
	// Load predefined pipelines
	pm.loadDefaultPipelines()
	
	return nil
}

// Execute runs a pipeline
func (pm *PipelineManager) Execute(ctx context.Context, req *framework.PipelineExecutionRequest, engine *DecisionEngine) (*framework.PipelineExecutionResponse, error) {
	// Get pipeline definition
	pm.mu.RLock()
	pipeline, exists := pm.pipelines[req.PipelineID]
	pm.mu.RUnlock()
	
	if !exists {
		return nil, fmt.Errorf("pipeline %s not found", req.PipelineID)
	}
	
	// Create execution record
	contextMap := make(map[string]interface{})
	if req.Context != nil {
		contextMap["request_id"] = req.Context.RequestID
		contextMap["user_id"] = req.Context.UserID
		contextMap["timestamp"] = req.Context.Timestamp
		contextMap["environment"] = req.Context.Environment
		contextMap["correlation_id"] = req.Context.CorrelationID
		if req.Context.Metadata != nil {
			for k, v := range req.Context.Metadata {
				contextMap[k] = v
			}
		}
	}

	execution := &PipelineExecution{
		ID:          generateExecutionID(),
		PipelineID:  req.PipelineID,
		Status:      "running",
		StartTime:   time.Now(),
		CurrentStep: pipeline.Steps[0].Name,
		StepResults: make(map[string]StepResult),
		Context:     contextMap,
	}
	
	// Store execution
	pm.mu.Lock()
	if len(pm.executions) >= pm.executionLimit {
		pm.cleanupOldExecutions()
	}
	pm.executions[execution.ID] = execution
	pm.mu.Unlock()
	
	// Execute pipeline
	go pm.executePipeline(ctx, pipeline, execution, req, engine)
	
	// Return execution ID
	return &framework.PipelineExecutionResponse{
		ExecutionID: execution.ID,
		Status:      execution.Status,
		Message:     fmt.Sprintf("Pipeline %s started", pipeline.Name),
	}, nil
}

// GetStatus returns the status of a pipeline execution
func (pm *PipelineManager) GetStatus(ctx context.Context, executionID string) (*framework.PipelineStatusResponse, error) {
	pm.mu.RLock()
	execution, exists := pm.executions[executionID]
	pm.mu.RUnlock()
	
	if !exists {
		return nil, fmt.Errorf("execution %s not found", executionID)
	}
	
	// Build status response
	stepStatuses := make([]framework.StepStatus, 0, len(execution.StepResults))
	for stepName, result := range execution.StepResults {
		stepStatuses = append(stepStatuses, framework.StepStatus{
			Name:      stepName,
			Status:    result.Status,
			StartTime: result.StartTime,
			EndTime:   result.EndTime,
			Error:     result.Error,
		})
	}
	
	response := &framework.PipelineStatusResponse{
		ExecutionID:  execution.ID,
		PipelineID:   execution.PipelineID,
		Status:       execution.Status,
		CurrentStep:  execution.CurrentStep,
		StartTime:    execution.StartTime,
		StepStatuses: stepStatuses,
	}
	
	if execution.EndTime != nil {
		response.EndTime = *execution.EndTime
		response.Duration = execution.EndTime.Sub(execution.StartTime)
	}
	
	if execution.FinalResult != nil {
		response.FinalResult = execution.FinalResult
	}
	
	if execution.Error != "" {
		response.Error = execution.Error
	}
	
	return response, nil
}

// executePipeline runs the pipeline steps
func (pm *PipelineManager) executePipeline(ctx context.Context, pipeline *PipelineDefinition, execution *PipelineExecution, req *framework.PipelineExecutionRequest, engine *DecisionEngine) {
	defer func() {
		if r := recover(); r != nil {
			pm.logger.Error("Pipeline execution panic", 
				"executionID", execution.ID,
				"panic", r,
			)
			pm.updateExecutionStatus(execution.ID, "failed", fmt.Sprintf("panic: %v", r))
		}
	}()
	
	// Execute each step
	for i, step := range pipeline.Steps {
		// Check context cancellation
		if ctx.Err() != nil {
			pm.updateExecutionStatus(execution.ID, "cancelled", "context cancelled")
			return
		}
		
		// Update current step
		pm.updateCurrentStep(execution.ID, step.Name)
		
		// Execute step
		result, err := pm.executeStep(ctx, step, execution, req, engine)
		
		// Store step result
		pm.storeStepResult(execution.ID, step.Name, result)
		
		// Handle step result
		if err != nil {
			pm.logger.Error("Pipeline step failed",
				"executionID", execution.ID,
				"step", step.Name,
				"error", err,
			)
			
			if step.OnFailure == "continue" {
				continue
			} else if step.OnFailure == "stop" || step.OnFailure == "" {
				pm.updateExecutionStatus(execution.ID, "failed", err.Error())
				return
			}
		}
		
		// Check if we should continue
		if result.Decision != nil && result.Decision.Result == "deny" && step.OnSuccess == "stop" {
			pm.updateExecutionStatus(execution.ID, "completed", "stopped on deny")
			pm.setFinalResult(execution.ID, result.Decision)
			return
		}
		
		// If this is the last step, set final result
		if i == len(pipeline.Steps)-1 {
			pm.updateExecutionStatus(execution.ID, "completed", "all steps completed")
			pm.setFinalResult(execution.ID, result.Decision)
		}
	}
}

// executeStep executes a single pipeline step
func (pm *PipelineManager) executeStep(ctx context.Context, step PipelineStep, execution *PipelineExecution, req *framework.PipelineExecutionRequest, engine *DecisionEngine) (*StepResult, error) {
	startTime := time.Now()
	
	result := &StepResult{
		StepName:  step.Name,
		Status:    "running",
		StartTime: startTime,
		Output:    make(map[string]interface{}),
	}
	
	// Build evaluation request
	evalReq := &framework.PolicyEvaluationRequest{
		PolicyID:    step.PolicyID,
		PolicyType:  step.Type,
		Input:       pm.mergeInputs(req.Input, step.Input, execution.Context),
		Context:     req.Context,
		Options:     req.Options,
		DataSources: req.DataSources,
	}
	
	// Evaluate policy
	decision, err := engine.EvaluatePolicy(ctx, evalReq)
	endTime := time.Now()
	
	result.EndTime = endTime
	
	if err != nil {
		result.Status = "failed"
		result.Error = err.Error()
		return result, err
	}
	
	result.Status = "completed"
	result.Decision = decision
	
	// Store outputs for next steps
	if decision.Metadata != nil {
		for k, v := range decision.Metadata {
			result.Output[k] = v
		}
	}
	
	return result, nil
}

// Helper methods

func (pm *PipelineManager) loadDefaultPipelines() {
	// Example: Multi-stage approval pipeline
	approvalPipeline := &PipelineDefinition{
		ID:          "multi-stage-approval",
		Name:        "Multi-Stage Approval",
		Description: "Requires approvals from multiple policies",
		Steps: []PipelineStep{
			{
				Name:      "rbac-check",
				Type:      "rego",
				PolicyID:  "rbac-policy",
				OnFailure: "stop",
			},
			{
				Name:      "risk-assessment",
				Type:      "rego",
				PolicyID:  "risk-policy",
				OnFailure: "continue",
			},
			{
				Name:      "compliance-check",
				Type:      "rego",
				PolicyID:  "compliance-policy",
				OnFailure: "stop",
			},
		},
	}
	
	pm.pipelines[approvalPipeline.ID] = approvalPipeline
}

func (pm *PipelineManager) mergeInputs(base, step, context map[string]interface{}) map[string]interface{} {
	merged := make(map[string]interface{})
	
	// Copy base input
	for k, v := range base {
		merged[k] = v
	}
	
	// Override with step input
	for k, v := range step {
		merged[k] = v
	}
	
	// Add context
	merged["_context"] = context
	
	return merged
}

func (pm *PipelineManager) updateCurrentStep(executionID, stepName string) {
	pm.mu.Lock()
	defer pm.mu.Unlock()
	
	if execution, exists := pm.executions[executionID]; exists {
		execution.CurrentStep = stepName
	}
}

func (pm *PipelineManager) storeStepResult(executionID, stepName string, result *StepResult) {
	pm.mu.Lock()
	defer pm.mu.Unlock()
	
	if execution, exists := pm.executions[executionID]; exists {
		execution.StepResults[stepName] = *result
		
		// Update context with step outputs
		for k, v := range result.Output {
			execution.Context[fmt.Sprintf("%s_%s", stepName, k)] = v
		}
	}
}

func (pm *PipelineManager) updateExecutionStatus(executionID, status, message string) {
	pm.mu.Lock()
	defer pm.mu.Unlock()
	
	if execution, exists := pm.executions[executionID]; exists {
		execution.Status = status
		if status == "failed" {
			execution.Error = message
		}
		if status == "completed" || status == "failed" || status == "cancelled" {
			now := time.Now()
			execution.EndTime = &now
		}
	}
}

func (pm *PipelineManager) setFinalResult(executionID string, decision *framework.PolicyDecision) {
	pm.mu.Lock()
	defer pm.mu.Unlock()
	
	if execution, exists := pm.executions[executionID]; exists {
		execution.FinalResult = decision
	}
}

func (pm *PipelineManager) cleanupOldExecutions() {
	// Remove oldest executions
	cutoff := time.Now().Add(-24 * time.Hour)
	
	for id, execution := range pm.executions {
		if execution.EndTime != nil && execution.EndTime.Before(cutoff) {
			delete(pm.executions, id)
		}
	}
}

func generateExecutionID() string {
	return fmt.Sprintf("exec_%d_%d", time.Now().UnixNano(), randInt())
}