package core

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/Caia-Tech/afdp/services/policy-engine/internal/logging"
	"github.com/Caia-Tech/afdp/services/policy-engine/internal/metrics"
	"github.com/Caia-Tech/afdp/services/policy-engine/pkg/framework"
)

// DecisionEngine orchestrates policy evaluation across plugins
type DecisionEngine struct {
	logger          *logging.Logger
	metrics         *metrics.Collector
	frameworkCore   *FrameworkCore
	cache           *DecisionCache
	pipelineManager *PipelineManager
	mu              sync.RWMutex
	running         bool
}

// NewDecisionEngine creates a new decision engine
func NewDecisionEngine(logger *logging.Logger, metrics *metrics.Collector) *DecisionEngine {
	return &DecisionEngine{
		logger:          logger,
		metrics:         metrics,
		cache:           NewDecisionCache(logger),
		pipelineManager: NewPipelineManager(logger),
	}
}

// Initialize prepares the decision engine
func (de *DecisionEngine) Initialize(ctx context.Context, frameworkCore *FrameworkCore) error {
	de.logger.Info("Initializing decision engine...")
	
	de.mu.Lock()
	de.frameworkCore = frameworkCore
	de.mu.Unlock()
	
	// Initialize cache
	if err := de.cache.Initialize(ctx); err != nil {
		return fmt.Errorf("failed to initialize cache: %w", err)
	}
	
	// Initialize pipeline manager
	if err := de.pipelineManager.Initialize(ctx); err != nil {
		return fmt.Errorf("failed to initialize pipeline manager: %w", err)
	}
	
	return nil
}

// Start begins decision engine operation
func (de *DecisionEngine) Start(ctx context.Context) error {
	de.mu.Lock()
	defer de.mu.Unlock()
	
	if de.running {
		return fmt.Errorf("decision engine is already running")
	}
	
	de.logger.Info("Starting decision engine...")
	de.running = true
	
	// Start cache cleanup routine
	go de.cache.StartCleanup(ctx)
	
	return nil
}

// Stop shuts down the decision engine
func (de *DecisionEngine) Stop(ctx context.Context) error {
	de.mu.Lock()
	defer de.mu.Unlock()
	
	if !de.running {
		return fmt.Errorf("decision engine is not running")
	}
	
	de.logger.Info("Stopping decision engine...")
	de.running = false
	
	// Stop cache cleanup
	de.cache.StopCleanup()
	
	return nil
}

// EvaluatePolicy evaluates a single policy
func (de *DecisionEngine) EvaluatePolicy(ctx context.Context, req *framework.PolicyEvaluationRequest) (*framework.PolicyDecision, error) {
	start := time.Now()
	defer func() {
		de.metrics.RecordEvaluation(time.Since(start))
	}()
	
	// Validate request
	if err := de.validateEvaluationRequest(req); err != nil {
		return nil, fmt.Errorf("invalid request: %w", err)
	}
	
	// Check cache if enabled
	if req.Options != nil && req.Options.Cache {
		if decision, found := de.cache.Get(req); found {
			de.metrics.RecordCacheHit()
			return decision, nil
		}
	}
	
	// Get policy evaluator plugin
	evaluator, err := de.getEvaluator(req.PolicyType)
	if err != nil {
		return nil, fmt.Errorf("failed to get evaluator: %w", err)
	}
	
	// Enrich input with data sources
	enrichedInput, err := de.enrichInput(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("failed to enrich input: %w", err)
	}
	
	// Create evaluation request
	evalReq := &framework.EvaluationRequest{
		PolicyID: req.PolicyID,
		Input:    enrichedInput,
		Context:  req.Context,
		Options:  req.Options,
	}
	
	// Evaluate policy
	evalResp, err := evaluator.Evaluate(ctx, evalReq)
	if err != nil {
		return nil, fmt.Errorf("evaluation failed: %w", err)
	}
	
	// Create decision
	decision := &framework.PolicyDecision{
		Result:     evalResp.Decision.Result,
		Approvers:  evalResp.Decision.Approvers,
		Conditions: evalResp.Decision.Conditions,
		Metadata:   evalResp.Decision.Metadata,
	}
	
	// Store in cache if enabled
	if req.Options != nil && req.Options.Cache {
		de.cache.Set(req, decision)
	}
	
	// Store decision for audit
	if err := de.storeDecision(ctx, req, decision); err != nil {
		de.logger.Error("Failed to store decision", "error", err)
		// Don't fail the evaluation if storage fails
	}
	
	// Publish decision event
	de.publishDecisionEvent(req, decision)
	
	return decision, nil
}

// EvaluateBatchPolicies evaluates multiple policies
func (de *DecisionEngine) EvaluateBatchPolicies(ctx context.Context, req *framework.BatchPolicyEvaluationRequest) (*framework.BatchPolicyDecision, error) {
	start := time.Now()
	defer func() {
		de.metrics.RecordBatchEvaluation(time.Since(start), len(req.Requests))
	}()
	
	decisions := make([]*framework.PolicyDecision, len(req.Requests))
	errors := make([]error, len(req.Requests))
	
	// Use worker pool for parallel evaluation
	var wg sync.WaitGroup
	semaphore := make(chan struct{}, 10) // Limit concurrent evaluations
	
	for i, evalReq := range req.Requests {
		wg.Add(1)
		go func(index int, request *framework.PolicyEvaluationRequest) {
			defer wg.Done()
			
			semaphore <- struct{}{}
			defer func() { <-semaphore }()
			
			decision, err := de.EvaluatePolicy(ctx, request)
			decisions[index] = decision
			errors[index] = err
		}(i, evalReq)
	}
	
	wg.Wait()
	
	// Aggregate results
	result := &framework.BatchPolicyDecision{
		Decisions: decisions,
		Errors:    errors,
		Metadata: map[string]interface{}{
			"total_count":    len(req.Requests),
			"success_count":  countSuccesses(errors),
			"evaluation_time": time.Since(start).String(),
		},
	}
	
	return result, nil
}

// ExecutePipeline executes a policy evaluation pipeline
func (de *DecisionEngine) ExecutePipeline(ctx context.Context, req *framework.PipelineExecutionRequest) (*framework.PipelineExecutionResponse, error) {
	return de.pipelineManager.Execute(ctx, req, de)
}

// GetPipelineStatus returns the status of a pipeline execution
func (de *DecisionEngine) GetPipelineStatus(ctx context.Context, req *framework.GetPipelineStatusRequest) (*framework.PipelineStatusResponse, error) {
	return de.pipelineManager.GetStatus(ctx, req.PipelineID)
}

// StoreDecision stores a policy decision
func (de *DecisionEngine) StoreDecision(ctx context.Context, decision *framework.PolicyDecision) error {
	return de.storeDecision(ctx, nil, decision)
}

// GetDecision retrieves a stored decision
func (de *DecisionEngine) GetDecision(ctx context.Context, decisionID string) (*framework.PolicyDecision, error) {
	storage := de.frameworkCore.GetStorage()
	
	_, err := storage.Retrieve(ctx, fmt.Sprintf("decisions/%s", decisionID))
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve decision: %w", err)
	}
	
	// Deserialize decision
	// In a real implementation, use proper serialization
	decision := &framework.PolicyDecision{}
	// TODO: Implement actual deserialization from data
	
	return decision, nil
}

// QueryDecisions queries stored decisions
func (de *DecisionEngine) QueryDecisions(ctx context.Context, query *framework.DecisionQuery) (*framework.DecisionQueryResponse, error) {
	// Implementation would query the storage backend
	return &framework.DecisionQueryResponse{
		Decisions: []*framework.PolicyDecision{},
		Total:     0,
		NextToken: "",
	}, nil
}

// GenerateAnalytics generates analytics from decisions
func (de *DecisionEngine) GenerateAnalytics(ctx context.Context, req *framework.AnalyticsRequest) (*framework.AnalyticsResponse, error) {
	// Implementation would analyze stored decisions
	return &framework.AnalyticsResponse{
		Metrics: map[string]interface{}{
			"total_decisions":   0,
			"approval_rate":     0.0,
			"average_eval_time": "0ms",
		},
	}, nil
}

// GetDecisionMetrics returns metrics about decisions
func (de *DecisionEngine) GetDecisionMetrics(ctx context.Context, req *framework.MetricsRequest) (*framework.MetricsResponse, error) {
	// Implementation would gather metrics from storage
	return &framework.MetricsResponse{
		Metrics: map[string]interface{}{
			"decisions_per_minute": 0,
			"cache_hit_rate":       0.0,
		},
	}, nil
}

// Helper methods

func (de *DecisionEngine) validateEvaluationRequest(req *framework.PolicyEvaluationRequest) error {
	if req.PolicyID == "" {
		return fmt.Errorf("policy ID is required")
	}
	if req.Input == nil {
		return fmt.Errorf("input is required")
	}
	if req.Context == nil {
		return fmt.Errorf("context is required")
	}
	return nil
}

func (de *DecisionEngine) getEvaluator(policyType string) (framework.PolicyEvaluator, error) {
	de.mu.RLock()
	defer de.mu.RUnlock()
	
	if de.frameworkCore == nil {
		return nil, fmt.Errorf("framework core not initialized")
	}
	
	// Default to "evaluator" plugin type
	if policyType == "" {
		policyType = "rego"
	}
	
	plugin, err := de.frameworkCore.GetPlugin(string(framework.PluginTypeEvaluator), policyType)
	if err != nil {
		return nil, fmt.Errorf("evaluator plugin not found: %w", err)
	}
	
	evaluator, ok := plugin.(framework.PolicyEvaluator)
	if !ok {
		return nil, fmt.Errorf("plugin is not a policy evaluator")
	}
	
	return evaluator, nil
}

func (de *DecisionEngine) enrichInput(ctx context.Context, req *framework.PolicyEvaluationRequest) (map[string]interface{}, error) {
	enriched := make(map[string]interface{})
	
	// Copy original input
	for k, v := range req.Input {
		enriched[k] = v
	}
	
	// Add data from data sources if configured
	if req.DataSources != nil {
		for _, ds := range req.DataSources {
			data, err := de.fetchDataFromSource(ctx, ds)
			if err != nil {
				de.logger.Warn("Failed to fetch data from source", "source", ds, "error", err)
				continue
			}
			// Merge data
			for k, v := range data {
				enriched[k] = v
			}
		}
	}
	
	return enriched, nil
}

func (de *DecisionEngine) fetchDataFromSource(ctx context.Context, sourceName string) (map[string]interface{}, error) {
	plugin, err := de.frameworkCore.GetPlugin(string(framework.PluginTypeDataSource), sourceName)
	if err != nil {
		return nil, fmt.Errorf("data source not found: %w", err)
	}
	
	dataSource, ok := plugin.(framework.DataSource)
	if !ok {
		return nil, fmt.Errorf("plugin is not a data source")
	}
	
	// Fetch data
	resp, err := dataSource.Fetch(ctx, &framework.FetchRequest{
		Query: map[string]interface{}{},
	})
	if err != nil {
		return nil, fmt.Errorf("failed to fetch data: %w", err)
	}
	
	return resp.Data, nil
}

func (de *DecisionEngine) storeDecision(ctx context.Context, req *framework.PolicyEvaluationRequest, decision *framework.PolicyDecision) error {
	storage := de.frameworkCore.GetStorage()
	
	// Create decision record
	record := map[string]interface{}{
		"decision":   decision,
		"request":    req,
		"timestamp":  time.Now(),
		"decisionID": generateDecisionID(),
	}
	
	// Serialize and store
	// In a real implementation, use proper serialization
	key := fmt.Sprintf("decisions/%s", record["decisionID"])
	data := []byte{} // ... serialization logic ...
	
	return storage.Store(ctx, key, data)
}

func (de *DecisionEngine) publishDecisionEvent(req *framework.PolicyEvaluationRequest, decision *framework.PolicyDecision) {
	event := &framework.Event{
		Type:      "policy.evaluated",
		Source:    "decision.engine",
		Timestamp: time.Now(),
		Data: map[string]interface{}{
			"policy_id": req.PolicyID,
			"decision":  decision.Result,
			"user_id":   req.Context.UserID,
		},
	}
	
	if err := de.frameworkCore.PublishEvent(event); err != nil {
		de.logger.Error("Failed to publish decision event", "error", err)
	}
}

func countSuccesses(errors []error) int {
	count := 0
	for _, err := range errors {
		if err == nil {
			count++
		}
	}
	return count
}

func generateDecisionID() string {
	return fmt.Sprintf("dec_%d_%d", time.Now().UnixNano(), randInt())
}