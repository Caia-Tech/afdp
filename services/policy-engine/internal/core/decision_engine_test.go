package core

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/Caia-Tech/afdp/services/policy-engine/internal/logging"
	"github.com/Caia-Tech/afdp/services/policy-engine/internal/metrics"
	"github.com/Caia-Tech/afdp/services/policy-engine/internal/plugins"
	"github.com/Caia-Tech/afdp/services/policy-engine/pkg/framework"
)

// Mock evaluator for testing
type mockEvaluator struct {
	name     string
	response *framework.PolicyDecision
	err      error
	delay    time.Duration
}

func (m *mockEvaluator) Name() string { return m.name }
func (m *mockEvaluator) Version() string { return "1.0.0" }
func (m *mockEvaluator) Type() framework.PluginType { return framework.PluginTypeEvaluator }
func (m *mockEvaluator) Metadata() framework.PluginMetadata { return framework.PluginMetadata{} }

func (m *mockEvaluator) Initialize(ctx context.Context, config framework.PluginConfig) error {
	return nil
}

func (m *mockEvaluator) Start(ctx context.Context) error { return nil }
func (m *mockEvaluator) Stop(ctx context.Context) error { return nil }
func (m *mockEvaluator) Reload(ctx context.Context, config framework.PluginConfig) error { return nil }
func (m *mockEvaluator) Health() framework.HealthStatus {
	return framework.HealthStatus{Status: "healthy"}
}
func (m *mockEvaluator) Metrics() framework.PluginMetrics { return framework.PluginMetrics{} }
func (m *mockEvaluator) ValidateConfig(config framework.PluginConfig) framework.ValidationResult {
	return framework.ValidationResult{Valid: true}
}

func (m *mockEvaluator) EvaluatePolicy(ctx context.Context, req *framework.PolicyEvaluationRequest) (*framework.PolicyDecision, error) {
	if m.delay > 0 {
		time.Sleep(m.delay)
	}
	
	if m.err != nil {
		return nil, m.err
	}
	
	if m.response != nil {
		return m.response, nil
	}
	
	// Default response
	return &framework.PolicyDecision{
		ID:       "test-decision",
		Result:   "allow",
		Metadata: map[string]interface{}{"evaluator": m.name},
	}, nil
}

func TestDecisionEngine(t *testing.T) {
	logger := logging.NewLogger("debug")
	metricsCollector := metrics.NewCollector(framework.MetricsConfig{})
	pluginManager := plugins.NewManager(logger, metricsCollector)
	
	config := &framework.DecisionEngineConfig{
		CacheEnabled: true,
		CacheTTL:     300,
		MaxCacheSize: 1000,
	}

	t.Run("CreateEngine", func(t *testing.T) {
		de := NewDecisionEngine(config, pluginManager, logger, metricsCollector)
		assert.NotNil(t, de)
		assert.NotNil(t, de.cache)
		assert.Equal(t, config, de.config)
	})

	t.Run("Initialize", func(t *testing.T) {
		de := NewDecisionEngine(config, pluginManager, logger, metricsCollector)
		ctx := context.Background()
		
		err := de.Initialize(ctx)
		assert.NoError(t, err)
	})

	t.Run("StartStop", func(t *testing.T) {
		de := NewDecisionEngine(config, pluginManager, logger, metricsCollector)
		ctx := context.Background()
		
		err := de.Initialize(ctx)
		require.NoError(t, err)
		
		err = de.Start(ctx)
		assert.NoError(t, err)
		
		err = de.Stop(ctx)
		assert.NoError(t, err)
	})

	t.Run("EvaluatePolicy", func(t *testing.T) {
		de := NewDecisionEngine(config, pluginManager, logger, metricsCollector)
		ctx := context.Background()
		
		err := de.Initialize(ctx)
		require.NoError(t, err)
		err = de.Start(ctx)
		require.NoError(t, err)
		defer de.Stop(ctx)

		// Register mock evaluator
		evaluator := &mockEvaluator{
			name: "test-evaluator",
			response: &framework.PolicyDecision{
				ID:     "test-decision-123",
				Result: "allow",
				Metadata: map[string]interface{}{
					"policy": "test_policy",
					"reason": "user has permission",
				},
			},
		}
		
		err = pluginManager.RegisterPlugin(string(framework.PluginTypeEvaluator), "test-evaluator", evaluator)
		require.NoError(t, err)

		// Test evaluation
		req := &framework.PolicyEvaluationRequest{
			PolicyID: "test_policy",
			Input: map[string]interface{}{
				"user":   "alice",
				"action": "read",
			},
			Context: &framework.EvaluationContext{
				UserID:    "user123",
				Timestamp: time.Now(),
			},
		}

		decision, err := de.EvaluatePolicy(ctx, req)
		assert.NoError(t, err)
		assert.NotNil(t, decision)
		assert.Equal(t, "allow", decision.Result)
		assert.Equal(t, "test-decision-123", decision.ID)
		assert.Equal(t, "test_policy", decision.Metadata["policy"])
	})

	t.Run("EvaluateWithCaching", func(t *testing.T) {
		de := NewDecisionEngine(config, pluginManager, logger, metricsCollector)
		ctx := context.Background()
		
		err := de.Initialize(ctx)
		require.NoError(t, err)
		err = de.Start(ctx)
		require.NoError(t, err)
		defer de.Stop(ctx)

		// Register evaluator with delay to test caching
		evaluator := &mockEvaluator{
			name:  "slow-evaluator",
			delay: 50 * time.Millisecond,
			response: &framework.PolicyDecision{
				ID:     "cached-decision",
				Result: "allow",
			},
		}
		
		err = pluginManager.RegisterPlugin(string(framework.PluginTypeEvaluator), "slow-evaluator", evaluator)
		require.NoError(t, err)

		req := &framework.PolicyEvaluationRequest{
			PolicyID: "cache_test_policy",
			Input: map[string]interface{}{
				"user": "bob",
			},
			Context: &framework.EvaluationContext{
				UserID: "user456",
			},
		}

		// First evaluation - should be slow
		start := time.Now()
		decision1, err := de.EvaluatePolicy(ctx, req)
		duration1 := time.Since(start)
		assert.NoError(t, err)
		assert.Equal(t, "allow", decision1.Result)
		assert.GreaterOrEqual(t, duration1, 40*time.Millisecond)

		// Second evaluation - should be fast (cached)
		start = time.Now()
		decision2, err := de.EvaluatePolicy(ctx, req)
		duration2 := time.Since(start)
		assert.NoError(t, err)
		assert.Equal(t, "allow", decision2.Result)
		assert.Less(t, duration2, 10*time.Millisecond)
		
		// Results should be identical
		assert.Equal(t, decision1.ID, decision2.ID)
	})

	t.Run("BatchEvaluation", func(t *testing.T) {
		de := NewDecisionEngine(config, pluginManager, logger, metricsCollector)
		ctx := context.Background()
		
		err := de.Initialize(ctx)
		require.NoError(t, err)
		err = de.Start(ctx)
		require.NoError(t, err)
		defer de.Stop(ctx)

		// Register evaluator
		evaluator := &mockEvaluator{name: "batch-evaluator"}
		err = pluginManager.RegisterPlugin(string(framework.PluginTypeEvaluator), "batch-evaluator", evaluator)
		require.NoError(t, err)

		// Create batch request
		req := &framework.BatchPolicyEvaluationRequest{
			Requests: []*framework.PolicyEvaluationRequest{
				{
					PolicyID: "policy1",
					Input:    map[string]interface{}{"user": "alice"},
					Context:  &framework.EvaluationContext{UserID: "user1"},
				},
				{
					PolicyID: "policy2",
					Input:    map[string]interface{}{"user": "bob"},
					Context:  &framework.EvaluationContext{UserID: "user2"},
				},
				{
					PolicyID: "policy3",
					Input:    map[string]interface{}{"user": "charlie"},
					Context:  &framework.EvaluationContext{UserID: "user3"},
				},
			},
		}

		result, err := de.EvaluateBatch(ctx, req)
		assert.NoError(t, err)
		assert.NotNil(t, result)
		assert.Len(t, result.Decisions, 3)
		
		for i, decision := range result.Decisions {
			assert.Equal(t, "allow", decision.Result)
			assert.NotEmpty(t, decision.ID)
			assert.Equal(t, req.Requests[i].PolicyID, decision.PolicyID)
		}
	})

	t.Run("EvaluationError", func(t *testing.T) {
		de := NewDecisionEngine(config, pluginManager, logger, metricsCollector)
		ctx := context.Background()
		
		err := de.Initialize(ctx)
		require.NoError(t, err)
		err = de.Start(ctx)
		require.NoError(t, err)
		defer de.Stop(ctx)

		// Register evaluator that returns error
		evaluator := &mockEvaluator{
			name: "error-evaluator",
			err:  assert.AnError,
		}
		
		err = pluginManager.RegisterPlugin(string(framework.PluginTypeEvaluator), "error-evaluator", evaluator)
		require.NoError(t, err)

		req := &framework.PolicyEvaluationRequest{
			PolicyID: "error_policy",
			Input: map[string]interface{}{
				"user": "error_user",
			},
			Context: &framework.EvaluationContext{
				UserID: "error_user_id",
			},
		}

		_, err = de.EvaluatePolicy(ctx, req)
		assert.Error(t, err)
	})

	t.Run("NoEvaluatorFound", func(t *testing.T) {
		de := NewDecisionEngine(config, pluginManager, logger, metricsCollector)
		ctx := context.Background()
		
		err := de.Initialize(ctx)
		require.NoError(t, err)
		err = de.Start(ctx)
		require.NoError(t, err)
		defer de.Stop(ctx)

		req := &framework.PolicyEvaluationRequest{
			PolicyID: "nonexistent_policy",
			Input:    map[string]interface{}{"user": "test"},
			Context:  &framework.EvaluationContext{UserID: "test"},
		}

		_, err = de.EvaluatePolicy(ctx, req)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "no evaluator found")
	})

	t.Run("CacheEviction", func(t *testing.T) {
		// Test with very small cache
		smallCacheConfig := &framework.DecisionEngineConfig{
			CacheEnabled: true,
			CacheTTL:     1,        // 1 second TTL
			MaxCacheSize: 2,        // Only 2 entries
		}
		
		de := NewDecisionEngine(smallCacheConfig, pluginManager, logger, metricsCollector)
		ctx := context.Background()
		
		err := de.Initialize(ctx)
		require.NoError(t, err)
		err = de.Start(ctx)
		require.NoError(t, err)
		defer de.Stop(ctx)

		evaluator := &mockEvaluator{name: "cache-test-evaluator"}
		err = pluginManager.RegisterPlugin(string(framework.PluginTypeEvaluator), "cache-test-evaluator", evaluator)
		require.NoError(t, err)

		// Fill cache beyond capacity
		for i := 0; i < 5; i++ {
			req := &framework.PolicyEvaluationRequest{
				PolicyID: fmt.Sprintf("policy_%d", i),
				Input:    map[string]interface{}{"user": "test"},
				Context:  &framework.EvaluationContext{UserID: "test"},
			}
			
			_, err := de.EvaluatePolicy(ctx, req)
			assert.NoError(t, err)
		}

		// Cache should have been evicted to stay under max size
		assert.LessOrEqual(t, de.cache.Len(), 2)

		// Test TTL expiration
		time.Sleep(1100 * time.Millisecond) // Wait for TTL to expire
		
		// Trigger cache cleanup by making another request
		req := &framework.PolicyEvaluationRequest{
			PolicyID: "ttl_test_policy",
			Input:    map[string]interface{}{"user": "test"},
			Context:  &framework.EvaluationContext{UserID: "test"},
		}
		_, err = de.EvaluatePolicy(ctx, req)
		assert.NoError(t, err)
		
		// Previous entries should be expired
		assert.LessOrEqual(t, de.cache.Len(), 1)
	})

	t.Run("ConcurrentEvaluation", func(t *testing.T) {
		de := NewDecisionEngine(config, pluginManager, logger, metricsCollector)
		ctx := context.Background()
		
		err := de.Initialize(ctx)
		require.NoError(t, err)
		err = de.Start(ctx)
		require.NoError(t, err)
		defer de.Stop(ctx)

		evaluator := &mockEvaluator{
			name:  "concurrent-evaluator",
			delay: 10 * time.Millisecond,
		}
		err = pluginManager.RegisterPlugin(string(framework.PluginTypeEvaluator), "concurrent-evaluator", evaluator)
		require.NoError(t, err)

		// Run multiple evaluations concurrently
		numGoroutines := 20
		results := make(chan *framework.PolicyDecision, numGoroutines)
		errors := make(chan error, numGoroutines)

		for i := 0; i < numGoroutines; i++ {
			go func(idx int) {
				req := &framework.PolicyEvaluationRequest{
					PolicyID: "concurrent_policy",
					Input: map[string]interface{}{
						"user":  fmt.Sprintf("user_%d", idx),
						"index": idx,
					},
					Context: &framework.EvaluationContext{
						UserID: fmt.Sprintf("concurrent_user_%d", idx),
					},
				}
				
				decision, err := de.EvaluatePolicy(ctx, req)
				if err != nil {
					errors <- err
				} else {
					results <- decision
				}
			}(i)
		}

		// Collect results
		successCount := 0
		errorCount := 0
		
		for i := 0; i < numGoroutines; i++ {
			select {
			case <-results:
				successCount++
			case <-errors:
				errorCount++
			case <-time.After(5 * time.Second):
				t.Fatal("Test timed out")
			}
		}

		assert.Equal(t, numGoroutines, successCount)
		assert.Equal(t, 0, errorCount)
	})

	t.Run("Health", func(t *testing.T) {
		de := NewDecisionEngine(config, pluginManager, logger, metricsCollector)
		ctx := context.Background()
		
		err := de.Initialize(ctx)
		require.NoError(t, err)
		err = de.Start(ctx)
		require.NoError(t, err)
		defer de.Stop(ctx)

		health := de.Health()
		assert.Equal(t, "healthy", health.Status)
		assert.NotNil(t, health.Metadata)
		assert.Contains(t, health.Metadata, "cache")
		
		cacheInfo, ok := health.Metadata["cache"].(map[string]interface{})
		assert.True(t, ok)
		assert.Contains(t, cacheInfo, "enabled")
		assert.Contains(t, cacheInfo, "size")
		assert.Contains(t, cacheInfo, "max_size")
	})

	t.Run("Metrics", func(t *testing.T) {
		de := NewDecisionEngine(config, pluginManager, logger, metricsCollector)
		ctx := context.Background()
		
		err := de.Initialize(ctx)
		require.NoError(t, err)
		err = de.Start(ctx)
		require.NoError(t, err)
		defer de.Stop(ctx)

		evaluator := &mockEvaluator{name: "metrics-evaluator"}
		err = pluginManager.RegisterPlugin(string(framework.PluginTypeEvaluator), "metrics-evaluator", evaluator)
		require.NoError(t, err)

		// Make several evaluations to generate metrics
		for i := 0; i < 5; i++ {
			req := &framework.PolicyEvaluationRequest{
				PolicyID: "metrics_policy",
				Input:    map[string]interface{}{"iteration": i},
				Context:  &framework.EvaluationContext{UserID: "metrics_user"},
			}
			
			_, err := de.EvaluatePolicy(ctx, req)
			assert.NoError(t, err)
		}

		metrics := de.Metrics()
		assert.NotNil(t, metrics)
		assert.Contains(t, metrics, "evaluations_total")
		assert.Contains(t, metrics, "cache_hits")
		assert.Contains(t, metrics, "cache_misses")
		
		// Should have recorded evaluations
		evaluationsTotal, ok := metrics["evaluations_total"].(int64)
		assert.True(t, ok)
		assert.Greater(t, evaluationsTotal, int64(0))
	})
}