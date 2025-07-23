package plugins

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/Caia-Tech/afdp/services/policy-engine/pkg/framework"
)

// BuiltinWorkflowEngine is the built-in workflow engine
type BuiltinWorkflowEngine struct {
	config     framework.PluginConfig
	workflows  map[string]*WorkflowDefinition
	executions map[string]*WorkflowExecutionState
	mu         sync.RWMutex
	startTime  time.Time
	status     framework.PluginStatus
}

type WorkflowDefinition struct {
	ID          string                 `json:"id"`
	Name        string                 `json:"name"`
	Description string                 `json:"description"`
	Steps       []WorkflowStep         `json:"steps"`
	Metadata    map[string]interface{} `json:"metadata"`
}

type WorkflowStep struct {
	ID         string                 `json:"id"`
	Name       string                 `json:"name"`
	Type       string                 `json:"type"`
	Config     map[string]interface{} `json:"config"`
	NextSteps  []string               `json:"next_steps"`
	Conditions map[string]interface{} `json:"conditions"`
}

type WorkflowExecutionState struct {
	ExecutionID string                 `json:"execution_id"`
	WorkflowID  string                 `json:"workflow_id"`
	Status      string                 `json:"status"`
	CurrentStep string                 `json:"current_step"`
	StartTime   time.Time              `json:"start_time"`
	EndTime     *time.Time             `json:"end_time"`
	Context     map[string]interface{} `json:"context"`
	Output      map[string]interface{} `json:"output"`
	Error       string                 `json:"error,omitempty"`
}

// NewBuiltinWorkflowEngine creates a new workflow engine
func NewBuiltinWorkflowEngine(config framework.PluginConfig) (framework.Plugin, error) {
	return &BuiltinWorkflowEngine{
		config:     config,
		workflows:  make(map[string]*WorkflowDefinition),
		executions: make(map[string]*WorkflowExecutionState),
		status:     framework.PluginStatusUnknown,
	}, nil
}

// Plugin interface implementation

func (w *BuiltinWorkflowEngine) Name() string {
	return w.config.Name
}

func (w *BuiltinWorkflowEngine) Version() string {
	return "1.0.0"
}

func (w *BuiltinWorkflowEngine) Type() framework.PluginType {
	return framework.PluginTypeWorkflow
}

func (w *BuiltinWorkflowEngine) Metadata() framework.PluginMetadata {
	return framework.PluginMetadata{
		StartTime:    w.startTime,
		Uptime:       time.Since(w.startTime),
		RequestCount: 0,
		ErrorCount:   0,
		Metadata: map[string]interface{}{
			"engine": "builtin",
		},
	}
}

func (w *BuiltinWorkflowEngine) Initialize(ctx context.Context, config framework.PluginConfig) error {
	w.status = framework.PluginStatusInitializing
	
	// Load predefined workflows from config
	if workflows, ok := config.Config["workflows"].([]interface{}); ok {
		for _, wf := range workflows {
			if wfMap, ok := wf.(map[string]interface{}); ok {
				// Parse workflow definition
				def := &WorkflowDefinition{
					ID:          wfMap["id"].(string),
					Name:        wfMap["name"].(string),
					Description: wfMap["description"].(string),
				}
				w.workflows[def.ID] = def
			}
		}
	}
	
	return nil
}

func (w *BuiltinWorkflowEngine) Start(ctx context.Context) error {
	w.status = framework.PluginStatusStarting
	w.startTime = time.Now()
	
	// Start workflow monitoring goroutine
	go w.monitorExecutions(ctx)
	
	w.status = framework.PluginStatusRunning
	return nil
}

func (w *BuiltinWorkflowEngine) Stop(ctx context.Context) error {
	w.status = framework.PluginStatusStopping
	
	// Cancel all running workflows
	w.mu.Lock()
	for _, exec := range w.executions {
		if exec.Status == "running" {
			exec.Status = "cancelled"
			now := time.Now()
			exec.EndTime = &now
			exec.Error = "workflow engine stopped"
		}
	}
	w.mu.Unlock()
	
	w.status = framework.PluginStatusStopped
	return nil
}

func (w *BuiltinWorkflowEngine) Reload(ctx context.Context, config framework.PluginConfig) error {
	w.config = config
	// Reload workflow definitions
	return w.Initialize(ctx, config)
}

func (w *BuiltinWorkflowEngine) Health() framework.HealthStatus {
	status := "healthy"
	message := "Workflow engine is running"
	
	if w.status != framework.PluginStatusRunning {
		status = "unhealthy"
		message = fmt.Sprintf("Plugin is in %s state", w.status)
	}
	
	w.mu.RLock()
	activeCount := 0
	for _, exec := range w.executions {
		if exec.Status == "running" {
			activeCount++
		}
	}
	w.mu.RUnlock()
	
	return framework.HealthStatus{
		Status:    status,
		Message:   message,
		LastCheck: time.Now(),
		Metadata: map[string]interface{}{
			"workflows_loaded": len(w.workflows),
			"active_executions": activeCount,
			"uptime": time.Since(w.startTime).String(),
		},
	}
}

func (w *BuiltinWorkflowEngine) Metrics() framework.PluginMetrics {
	return framework.PluginMetrics{
		CPUUsage:    0.0,
		MemoryUsage: 0,
		RequestRate: 0.0,
		ErrorRate:   0.0,
		Timestamp:   time.Now(),
	}
}

func (w *BuiltinWorkflowEngine) ValidateConfig(config framework.PluginConfig) framework.ValidationResult {
	return framework.ValidationResult{
		Valid: true,
	}
}

// Workflow interface implementation

func (w *BuiltinWorkflowEngine) StartWorkflow(ctx context.Context, req *framework.StartWorkflowRequest) (*framework.StartWorkflowResponse, error) {
	w.mu.RLock()
	workflow, exists := w.workflows[req.WorkflowID]
	w.mu.RUnlock()
	
	if !exists {
		return nil, fmt.Errorf("workflow %s not found", req.WorkflowID)
	}
	
	// Create execution
	execution := &WorkflowExecutionState{
		ExecutionID: generateExecutionID(),
		WorkflowID:  req.WorkflowID,
		Status:      "running",
		CurrentStep: workflow.Steps[0].ID,
		StartTime:   time.Now(),
		Context:     req.Context,
		Output:      make(map[string]interface{}),
	}
	
	// Store execution
	w.mu.Lock()
	w.executions[execution.ExecutionID] = execution
	w.mu.Unlock()
	
	// Start execution in background
	go w.executeWorkflow(ctx, workflow, execution, req.Input)
	
	return &framework.StartWorkflowResponse{
		ExecutionID: execution.ExecutionID,
		Status:      execution.Status,
	}, nil
}

func (w *BuiltinWorkflowEngine) GetWorkflowStatus(ctx context.Context, req *framework.GetWorkflowStatusRequest) (*framework.GetWorkflowStatusResponse, error) {
	w.mu.RLock()
	execution, exists := w.executions[req.ExecutionID]
	w.mu.RUnlock()
	
	if !exists {
		return nil, fmt.Errorf("execution %s not found", req.ExecutionID)
	}
	
	return &framework.GetWorkflowStatusResponse{
		ExecutionID: execution.ExecutionID,
		WorkflowID:  execution.WorkflowID,
		Status:      execution.Status,
		StartTime:   execution.StartTime,
		EndTime:     execution.EndTime,
		Output:      execution.Output,
		Error:       execution.Error,
	}, nil
}

func (w *BuiltinWorkflowEngine) CancelWorkflow(ctx context.Context, req *framework.CancelWorkflowRequest) (*framework.CancelWorkflowResponse, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	
	execution, exists := w.executions[req.ExecutionID]
	if !exists {
		return nil, fmt.Errorf("execution %s not found", req.ExecutionID)
	}
	
	if execution.Status != "running" {
		return &framework.CancelWorkflowResponse{
			Success: false,
			Message: fmt.Sprintf("workflow is not running (status: %s)", execution.Status),
		}, nil
	}
	
	execution.Status = "cancelled"
	now := time.Now()
	execution.EndTime = &now
	execution.Error = fmt.Sprintf("cancelled: %s", req.Reason)
	
	return &framework.CancelWorkflowResponse{
		Success: true,
		Message: "workflow cancelled",
	}, nil
}

func (w *BuiltinWorkflowEngine) HandleEvent(ctx context.Context, req *framework.HandleEventRequest) (*framework.HandleEventResponse, error) {
	// Simple event handling - could trigger workflows based on events
	return &framework.HandleEventResponse{
		Handled: true,
		Message: "event handled",
	}, nil
}

func (w *BuiltinWorkflowEngine) SubscribeToEvents(ctx context.Context, req *framework.SubscribeRequest) (framework.EventStream, error) {
	// Not implemented in basic version
	return nil, fmt.Errorf("event subscription not implemented")
}

func (w *BuiltinWorkflowEngine) ListActiveWorkflows(ctx context.Context, req *framework.ListActiveWorkflowsRequest) (*framework.ListActiveWorkflowsResponse, error) {
	w.mu.RLock()
	defer w.mu.RUnlock()
	
	var workflows []framework.WorkflowExecution
	for _, exec := range w.executions {
		if exec.Status == "running" {
			workflows = append(workflows, framework.WorkflowExecution{
				ExecutionID: exec.ExecutionID,
				WorkflowID:  exec.WorkflowID,
				Status:      exec.Status,
				StartTime:   exec.StartTime,
			})
		}
	}
	
	return &framework.ListActiveWorkflowsResponse{
		Workflows: workflows,
	}, nil
}

func (w *BuiltinWorkflowEngine) GetWorkflowHistory(ctx context.Context, req *framework.GetWorkflowHistoryRequest) (*framework.GetWorkflowHistoryResponse, error) {
	w.mu.RLock()
	defer w.mu.RUnlock()
	
	var executions []framework.WorkflowExecution
	for _, exec := range w.executions {
		if exec.WorkflowID == req.WorkflowID {
			executions = append(executions, framework.WorkflowExecution{
				ExecutionID: exec.ExecutionID,
				WorkflowID:  exec.WorkflowID,
				Status:      exec.Status,
				StartTime:   exec.StartTime,
			})
		}
	}
	
	return &framework.GetWorkflowHistoryResponse{
		Executions: executions,
	}, nil
}

func (w *BuiltinWorkflowEngine) LoadWorkflowDefinition(ctx context.Context, req *framework.LoadWorkflowDefinitionRequest) (*framework.LoadWorkflowDefinitionResponse, error) {
	// Parse and load workflow definition
	// In a real implementation, would parse YAML/JSON definition
	
	def := &WorkflowDefinition{
		ID:          req.WorkflowID,
		Name:        req.WorkflowID,
		Description: "Loaded workflow",
		Steps:       []WorkflowStep{},
	}
	
	w.mu.Lock()
	w.workflows[def.ID] = def
	w.mu.Unlock()
	
	return &framework.LoadWorkflowDefinitionResponse{
		Success: true,
		Message: "workflow loaded",
	}, nil
}

func (w *BuiltinWorkflowEngine) ValidateWorkflowDefinition(ctx context.Context, req *framework.ValidateWorkflowDefinitionRequest) (*framework.ValidateWorkflowDefinitionResponse, error) {
	// Basic validation
	return &framework.ValidateWorkflowDefinitionResponse{
		Valid: true,
	}, nil
}

// Helper methods

func (w *BuiltinWorkflowEngine) executeWorkflow(ctx context.Context, workflow *WorkflowDefinition, execution *WorkflowExecutionState, input map[string]interface{}) {
	// Simple workflow execution
	defer func() {
		if r := recover(); r != nil {
			w.mu.Lock()
			execution.Status = "failed"
			execution.Error = fmt.Sprintf("panic: %v", r)
			now := time.Now()
			execution.EndTime = &now
			w.mu.Unlock()
		}
	}()
	
	// Execute steps sequentially (simplified)
	for _, step := range workflow.Steps {
		// Update current step
		w.mu.Lock()
		execution.CurrentStep = step.ID
		w.mu.Unlock()
		
		// Simulate step execution
		time.Sleep(100 * time.Millisecond)
		
		// Add step output
		w.mu.Lock()
		execution.Output[step.ID] = map[string]interface{}{
			"status": "completed",
			"timestamp": time.Now(),
		}
		w.mu.Unlock()
	}
	
	// Complete workflow
	w.mu.Lock()
	execution.Status = "completed"
	now := time.Now()
	execution.EndTime = &now
	w.mu.Unlock()
}

func (w *BuiltinWorkflowEngine) monitorExecutions(ctx context.Context) {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	
	for {
		select {
		case <-ticker.C:
			w.cleanupExecutions()
		case <-ctx.Done():
			return
		}
	}
}

func (w *BuiltinWorkflowEngine) cleanupExecutions() {
	w.mu.Lock()
	defer w.mu.Unlock()
	
	// Remove old completed executions
	cutoff := time.Now().Add(-24 * time.Hour)
	for id, exec := range w.executions {
		if exec.EndTime != nil && exec.EndTime.Before(cutoff) {
			delete(w.executions, id)
		}
	}
}

func generateExecutionID() string {
	return fmt.Sprintf("exec_%d", time.Now().UnixNano())
}