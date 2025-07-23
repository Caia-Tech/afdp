package test

import (
	"context"
	"fmt"
	"runtime"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/Caia-Tech/afdp/services/policy-engine/internal/core"
	"github.com/Caia-Tech/afdp/services/policy-engine/internal/logging"
	"github.com/Caia-Tech/afdp/services/policy-engine/internal/metrics"
	"github.com/Caia-Tech/afdp/services/policy-engine/internal/plugins"
	"github.com/Caia-Tech/afdp/services/policy-engine/internal/security"
	"github.com/Caia-Tech/afdp/services/policy-engine/pkg/framework"
)

// BenchmarkPlugin is a simple plugin for performance testing
type BenchmarkPlugin struct {
	name         string
	pluginType   framework.PluginType
	callCount    int64
	mu           sync.Mutex
	responseTime time.Duration
}

func NewBenchmarkPlugin(name string, pluginType framework.PluginType) *BenchmarkPlugin {
	return &BenchmarkPlugin{
		name:         name,
		pluginType:   pluginType,
		responseTime: 1 * time.Millisecond,
	}
}

func (b *BenchmarkPlugin) Name() string                        { return b.name }
func (b *BenchmarkPlugin) Version() string                     { return "1.0.0" }
func (b *BenchmarkPlugin) Type() framework.PluginType          { return b.pluginType }
func (b *BenchmarkPlugin) Metadata() framework.PluginMetadata  { return framework.PluginMetadata{} }
func (b *BenchmarkPlugin) Initialize(ctx context.Context, config framework.PluginConfig) error { return nil }
func (b *BenchmarkPlugin) Start(ctx context.Context) error     { return nil }
func (b *BenchmarkPlugin) Stop(ctx context.Context) error      { return nil }
func (b *BenchmarkPlugin) Reload(ctx context.Context, config framework.PluginConfig) error { return nil }
func (b *BenchmarkPlugin) Health() framework.HealthStatus {
	return framework.HealthStatus{Status: "healthy"}
}
func (b *BenchmarkPlugin) Metrics() framework.PluginMetrics {
	b.mu.Lock()
	defer b.mu.Unlock()
	return framework.PluginMetrics{
		"calls_total": b.callCount,
	}
}
func (b *BenchmarkPlugin) ValidateConfig(config framework.PluginConfig) framework.ValidationResult {
	return framework.ValidationResult{Valid: true}
}

func (b *BenchmarkPlugin) EvaluatePolicy(ctx context.Context, req *framework.PolicyEvaluationRequest) (*framework.PolicyDecision, error) {
	b.mu.Lock()
	b.callCount++
	responseTime := b.responseTime
	b.mu.Unlock()

	// Simulate work
	time.Sleep(responseTime)

	return &framework.PolicyDecision{
		Result: "allow",
		Metadata: map[string]interface{}{
			"plugin":    b.name,
			"timestamp": time.Now().Unix(),
		},
	}, nil
}

func (b *BenchmarkPlugin) SetResponseTime(duration time.Duration) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.responseTime = duration
}

func (b *BenchmarkPlugin) GetCallCount() int64 {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.callCount
}

func TestPerformance(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping performance tests in short mode")
	}

	logger := logging.NewLogger("error") // Reduce logging for performance tests

	t.Run("PluginManagerPerformance", func(t *testing.T) {
		metricsCollector := metrics.NewCollector(framework.MetricsConfig{})
		pm := plugins.NewManager(logger, metricsCollector)

		// Measure plugin registration time
		start := time.Now()
		numPlugins := 100

		for i := 0; i < numPlugins; i++ {
			plugin := NewBenchmarkPlugin(fmt.Sprintf("perf-plugin-%d", i), framework.PluginTypeEvaluator)
			err := pm.RegisterPlugin(string(framework.PluginTypeEvaluator), fmt.Sprintf("perf-plugin-%d", i), plugin)
			require.NoError(t, err)
		}

		registrationTime := time.Since(start)
		t.Logf("Registered %d plugins in %v (%.2f plugins/sec)", 
			numPlugins, registrationTime, float64(numPlugins)/registrationTime.Seconds())

		// Measure plugin listing time  
		start = time.Now()
		allPlugins := pm.ListPlugins()
		listTime := time.Since(start)

		assert.Len(t, allPlugins, numPlugins)
		t.Logf("Listed %d plugins in %v", numPlugins, listTime)

		// Performance assertions
		assert.Less(t, registrationTime, 5*time.Second, "Plugin registration should complete quickly")
		assert.Less(t, listTime, 100*time.Millisecond, "Plugin listing should be fast")
	})

	t.Run("ConcurrentPluginAccess", func(t *testing.T) {
		metricsCollector := metrics.NewCollector(framework.MetricsConfig{})
		pm := plugins.NewManager(logger, metricsCollector)
		ctx := context.Background()

		// Register test plugin
		plugin := NewBenchmarkPlugin("concurrent-test", framework.PluginTypeEvaluator)
		plugin.SetResponseTime(10 * time.Millisecond)
		
		err := pm.RegisterPlugin(string(framework.PluginTypeEvaluator), "concurrent-test", plugin)
		require.NoError(t, err)

		err = pm.Start(ctx)
		require.NoError(t, err)
		defer pm.Stop(ctx)

		// Concurrent access test
		numGoroutines := 50
		numCallsPerGoroutine := 20
		totalCalls := numGoroutines * numCallsPerGoroutine

		start := time.Now()
		var wg sync.WaitGroup
		wg.Add(numGoroutines)

		for i := 0; i < numGoroutines; i++ {
			go func(goroutineID int) {
				defer wg.Done()
				
				for j := 0; j < numCallsPerGoroutine; j++ {
					req := &framework.PolicyEvaluationRequest{
						PolicyID: "test-policy",
						Input: map[string]interface{}{
							"goroutine": goroutineID,
							"call":      j,
						},
					}
					
					_, err := plugin.EvaluatePolicy(ctx, req)
					assert.NoError(t, err)
				}
			}(i)
		}

		wg.Wait()
		duration := time.Since(start)

		callCount := plugin.GetCallCount()
		assert.Equal(t, int64(totalCalls), callCount)

		throughput := float64(totalCalls) / duration.Seconds()
		t.Logf("Processed %d concurrent calls in %v (%.2f calls/sec)", 
			totalCalls, duration, throughput)

		// Performance assertion - should handle reasonable load
		assert.Greater(t, throughput, 100.0, "Should process at least 100 calls/sec")
	})

	t.Run("AuthenticationPerformance", func(t *testing.T) {
		authManager := security.NewAuthManager(logger, "performance-test-secret")
		ctx := context.Background()

		err := authManager.Initialize(ctx)
		require.NoError(t, err)

		// Create test users
		numUsers := 100
		userCreationStart := time.Now()

		for i := 0; i < numUsers; i++ {
			username := fmt.Sprintf("perfuser%d", i)
			email := fmt.Sprintf("perfuser%d@example.com", i)
			_, err := authManager.CreateUser(username, email, "password123", []string{"user"})
			require.NoError(t, err)
		}

		userCreationTime := time.Since(userCreationStart)
		t.Logf("Created %d users in %v (%.2f users/sec)", 
			numUsers, userCreationTime, float64(numUsers)/userCreationTime.Seconds())

		// Test authentication performance
		authStart := time.Now()
		numAuths := 200

		for i := 0; i < numAuths; i++ {
			username := fmt.Sprintf("perfuser%d", i%numUsers)
			req := &framework.AuthenticationRequest{
				Method: "password",
				Credentials: map[string]interface{}{
					"username": username,
					"password": "password123",
				},
			}

			resp, err := authManager.Authenticate(ctx, req)
			require.NoError(t, err)
			assert.True(t, resp.Success)
		}

		authTime := time.Since(authStart)
		authThroughput := float64(numAuths) / authTime.Seconds()
		
		t.Logf("Performed %d authentications in %v (%.2f auths/sec)", 
			numAuths, authTime, authThroughput)

		// Performance assertions
		assert.Greater(t, authThroughput, 50.0, "Should handle at least 50 auths/sec")
	})

	t.Run("DecisionEnginePerformance", func(t *testing.T) {
		metricsCollector := metrics.NewCollector(framework.MetricsConfig{})
		pluginManager := plugins.NewManager(logger, metricsCollector)
		
		config := &framework.DecisionEngineConfig{
			CacheEnabled: true,
			CacheTTL:     300,
			MaxCacheSize: 1000,
		}

		decisionEngine := core.NewDecisionEngine(config, pluginManager, logger, metricsCollector)
		ctx := context.Background()

		err := decisionEngine.Initialize(ctx)
		require.NoError(t, err)
		err = decisionEngine.Start(ctx)
		require.NoError(t, err)
		defer decisionEngine.Stop(ctx)

		// Register fast benchmark plugin
		plugin := NewBenchmarkPlugin("decision-perf", framework.PluginTypeEvaluator)
		plugin.SetResponseTime(1 * time.Millisecond)
		
		err = pluginManager.RegisterPlugin(string(framework.PluginTypeEvaluator), "decision-perf", plugin)
		require.NoError(t, err)

		// Test decision performance
		numDecisions := 1000
		start := time.Now()

		for i := 0; i < numDecisions; i++ {
			req := &framework.PolicyEvaluationRequest{
				PolicyID: "perf-policy",
				Input: map[string]interface{}{
					"user":      fmt.Sprintf("user%d", i%10), // Some cache hits
					"iteration": i,
				},
				Context: &framework.EvaluationContext{
					UserID: "perf-test",
				},
			}

			decision, err := decisionEngine.EvaluatePolicy(ctx, req)
			require.NoError(t, err)
			assert.Equal(t, "allow", decision.Result)
		}

		duration := time.Since(start)
		throughput := float64(numDecisions) / duration.Seconds()

		t.Logf("Processed %d decisions in %v (%.2f decisions/sec)", 
			numDecisions, duration, throughput)

		// Performance assertion
		assert.Greater(t, throughput, 200.0, "Should process at least 200 decisions/sec")
	})

	t.Run("MemoryUsage", func(t *testing.T) {
		// Measure memory usage during operations
		var m1, m2 runtime.MemStats
		runtime.GC()
		runtime.ReadMemStats(&m1)

		metricsCollector := metrics.NewCollector(framework.MetricsConfig{})
		pm := plugins.NewManager(logger, metricsCollector)

		// Create many plugins
		numPlugins := 500
		for i := 0; i < numPlugins; i++ {
			plugin := NewBenchmarkPlugin(fmt.Sprintf("mem-plugin-%d", i), framework.PluginTypeEvaluator)
			err := pm.RegisterPlugin(string(framework.PluginTypeEvaluator), fmt.Sprintf("mem-plugin-%d", i), plugin)
			require.NoError(t, err)
		}

		runtime.GC()
		runtime.ReadMemStats(&m2)

		allocatedMB := float64(m2.Alloc-m1.Alloc) / 1024 / 1024
		t.Logf("Memory allocated for %d plugins: %.2f MB (%.2f KB per plugin)", 
			numPlugins, allocatedMB, allocatedMB*1024/float64(numPlugins))

		// Memory usage should be reasonable
		assert.Less(t, allocatedMB, 100.0, "Memory usage should be reasonable")
	})

	t.Run("EventBusPerformance", func(t *testing.T) {
		eventBus := core.NewEventBus(logger)
		ctx := context.Background()

		err := eventBus.Initialize(ctx)
		require.NoError(t, err)
		err = eventBus.Start(ctx)
		require.NoError(t, err)
		defer eventBus.Stop(ctx)

		// Create test handler
		var receivedCount int64
		var mu sync.Mutex
		
		handler := &mockEventHandler{
			handleEventFunc: func(ctx context.Context, event *framework.Event) error {
				mu.Lock()
				receivedCount++
				mu.Unlock()
				return nil
			},
		}

		err = eventBus.Subscribe("perf.test", handler)
		require.NoError(t, err)

		// Publish many events
		numEvents := 10000
		start := time.Now()

		for i := 0; i < numEvents; i++ {
			event := &framework.Event{
				Type:   "perf.test",
				Source: "performance-test",
				Data: map[string]interface{}{
					"index": i,
				},
			}

			err := eventBus.Publish(event)
			require.NoError(t, err)
		}

		publishDuration := time.Since(start)
		publishThroughput := float64(numEvents) / publishDuration.Seconds()

		// Wait for all events to be processed
		deadline := time.Now().Add(10 * time.Second)
		for time.Now().Before(deadline) {
			mu.Lock()
			count := receivedCount
			mu.Unlock()

			if count >= int64(numEvents) {
				break
			}
			time.Sleep(10 * time.Millisecond)
		}

		processingDuration := time.Since(start)
		processingThroughput := float64(numEvents) / processingDuration.Seconds()

		mu.Lock()
		finalCount := receivedCount
		mu.Unlock()

		t.Logf("Published %d events in %v (%.2f events/sec)", 
			numEvents, publishDuration, publishThroughput)
		t.Logf("Processed %d events in %v (%.2f events/sec)", 
			finalCount, processingDuration, processingThroughput)

		assert.Equal(t, int64(numEvents), finalCount, "All events should be processed")
		assert.Greater(t, publishThroughput, 1000.0, "Should publish at least 1k events/sec")
		assert.Greater(t, processingThroughput, 500.0, "Should process at least 500 events/sec")
	})

	t.Run("LoadTest", func(t *testing.T) {
		// Comprehensive load test
		metricsCollector := metrics.NewCollector(framework.MetricsConfig{})
		pm := plugins.NewManager(logger, metricsCollector)
		authManager := security.NewAuthManager(logger, "load-test-secret")
		
		ctx := context.Background()
		
		// Initialize components
		err := authManager.Initialize(ctx)
		require.NoError(t, err)
		err = pm.Start(ctx)
		require.NoError(t, err)
		defer pm.Stop(ctx)

		// Register plugins
		numPlugins := 10
		for i := 0; i < numPlugins; i++ {
			plugin := NewBenchmarkPlugin(fmt.Sprintf("load-plugin-%d", i), framework.PluginTypeEvaluator)
			plugin.SetResponseTime(5 * time.Millisecond)
			err := pm.RegisterPlugin(string(framework.PluginTypeEvaluator), fmt.Sprintf("load-plugin-%d", i), plugin)
			require.NoError(t, err)
		}

		// Create users
		numUsers := 50
		for i := 0; i < numUsers; i++ {
			username := fmt.Sprintf("loaduser%d", i)
			email := fmt.Sprintf("loaduser%d@example.com", i)
			_, err := authManager.CreateUser(username, email, "password123", []string{"user"})
			require.NoError(t, err)
		}

		// Simulate concurrent load
		numWorkers := 20
		duration := 10 * time.Second
		
		start := time.Now()
		var wg sync.WaitGroup
		var totalOps int64
		var successOps int64
		var mu sync.Mutex

		for i := 0; i < numWorkers; i++ {
			wg.Add(1)
			go func(workerID int) {
				defer wg.Done()
				
				ops := 0
				successes := 0
				
				for time.Since(start) < duration {
					// Simulate authentication
					username := fmt.Sprintf("loaduser%d", ops%numUsers)
					req := &framework.AuthenticationRequest{
						Method: "password",
						Credentials: map[string]interface{}{
							"username": username,
							"password": "password123",
						},
					}

					_, err := authManager.Authenticate(ctx, req)
					ops++
					if err == nil {
						successes++
					}

					// Small delay to prevent overwhelming
					time.Sleep(1 * time.Millisecond)
				}

				mu.Lock()
				totalOps += int64(ops)
				successOps += int64(successes)
				mu.Unlock()
			}(i)
		}

		wg.Wait()
		actualDuration := time.Since(start)

		successRate := float64(successOps) / float64(totalOps) * 100
		throughput := float64(totalOps) / actualDuration.Seconds()

		t.Logf("Load test results:")
		t.Logf("  Duration: %v", actualDuration)
		t.Logf("  Total operations: %d", totalOps)
		t.Logf("  Successful operations: %d (%.1f%%)", successOps, successRate)
		t.Logf("  Throughput: %.2f ops/sec", throughput)
		t.Logf("  Workers: %d", numWorkers)

		// Performance assertions
		assert.Greater(t, successRate, 95.0, "Success rate should be high under load")
		assert.Greater(t, throughput, 100.0, "Should maintain reasonable throughput under load")
		assert.Greater(t, totalOps, int64(500), "Should complete significant number of operations")
	})
}

// Benchmark tests using Go's built-in benchmarking
func BenchmarkPluginRegistration(b *testing.B) {
	logger := logging.NewLogger("error")
	metricsCollector := metrics.NewCollector(framework.MetricsConfig{})
	pm := plugins.NewManager(logger, metricsCollector)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		plugin := NewBenchmarkPlugin(fmt.Sprintf("bench-plugin-%d", i), framework.PluginTypeEvaluator)
		err := pm.RegisterPlugin(string(framework.PluginTypeEvaluator), fmt.Sprintf("bench-plugin-%d", i), plugin)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkAuthentication(b *testing.B) {
	logger := logging.NewLogger("error")
	authManager := security.NewAuthManager(logger, "benchmark-secret")
	ctx := context.Background()

	err := authManager.Initialize(ctx)
	if err != nil {
		b.Fatal(err)
	}

	// Create test user
	_, err = authManager.CreateUser("benchuser", "bench@example.com", "password123", []string{"user"})
	if err != nil {
		b.Fatal(err)
	}

	req := &framework.AuthenticationRequest{
		Method: "password",
		Credentials: map[string]interface{}{
			"username": "benchuser",
			"password": "password123",
		},
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := authManager.Authenticate(ctx, req)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkPolicyEvaluation(b *testing.B) {
	logger := logging.NewLogger("error")
	plugin := NewBenchmarkPlugin("bench-evaluator", framework.PluginTypeEvaluator)
	plugin.SetResponseTime(0) // No artificial delay for benchmark

	req := &framework.PolicyEvaluationRequest{
		PolicyID: "bench-policy",
		Input: map[string]interface{}{
			"user":   "testuser",
			"action": "read",
		},
		Context: &framework.EvaluationContext{
			UserID: "benchmark",
		},
	}

	ctx := context.Background()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := plugin.EvaluatePolicy(ctx, req)
		if err != nil {
			b.Fatal(err)
		}
	}
}

// mockEventHandler for event bus testing
type mockEventHandler struct {
	receivedEvents  []*framework.Event
	handleEventFunc func(ctx context.Context, event *framework.Event) error
	mu              sync.Mutex
}

func (m *mockEventHandler) HandleEvent(ctx context.Context, event *framework.Event) error {
	if m.handleEventFunc != nil {
		return m.handleEventFunc(ctx, event)
	}
	return nil
}

func (m *mockEventHandler) EventTypes() []string {
	return []string{"perf.test"}
}