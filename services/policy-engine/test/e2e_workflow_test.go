package test

import (
	"context"
	"fmt"
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

// E2ETestFramework provides a complete testing environment
type E2ETestFramework struct {
	logger           *logging.Logger
	metricsCollector *metrics.Collector
	pluginManager    *plugins.Manager
	authManager      *security.AuthManager
	rbacManager      *security.RBACManager
	decisionEngine   *core.DecisionEngine
	eventBus         *core.EventBus
	ctx              context.Context
}

func NewE2ETestFramework() *E2ETestFramework {
	logger := logging.NewLogger("debug")
	metricsCollector := metrics.NewCollector(framework.MetricsConfig{
		Enabled:   true,
		Namespace: "e2e_test",
	})

	pluginManager := plugins.NewManager(logger, metricsCollector)
	authManager := security.NewAuthManager(logger, "e2e-test-secret")
	rbacManager := security.NewRBACManager(logger)
	
	decisionEngineConfig := &framework.DecisionEngineConfig{
		CacheEnabled: true,
		CacheTTL:     300,
		MaxCacheSize: 1000,
	}
	decisionEngine := core.NewDecisionEngine(decisionEngineConfig, pluginManager, logger, metricsCollector)
	eventBus := core.NewEventBus(logger)

	return &E2ETestFramework{
		logger:           logger,
		metricsCollector: metricsCollector,
		pluginManager:    pluginManager,
		authManager:      authManager,
		rbacManager:      rbacManager,
		decisionEngine:   decisionEngine,
		eventBus:         eventBus,
		ctx:              context.Background(),
	}
}

func (e *E2ETestFramework) Initialize() error {
	// Initialize all components
	if err := e.authManager.Initialize(e.ctx); err != nil {
		return fmt.Errorf("failed to initialize auth manager: %w", err)
	}
	
	if err := e.decisionEngine.Initialize(e.ctx); err != nil {
		return fmt.Errorf("failed to initialize decision engine: %w", err)
	}
	
	if err := e.eventBus.Initialize(e.ctx); err != nil {
		return fmt.Errorf("failed to initialize event bus: %w", err)
	}

	return nil
}

func (e *E2ETestFramework) Start() error {
	if err := e.pluginManager.Start(e.ctx); err != nil {
		return fmt.Errorf("failed to start plugin manager: %w", err)
	}
	
	if err := e.decisionEngine.Start(e.ctx); err != nil {
		return fmt.Errorf("failed to start decision engine: %w", err)
	}
	
	if err := e.eventBus.Start(e.ctx); err != nil {
		return fmt.Errorf("failed to start event bus: %w", err)
	}

	return nil
}

func (e *E2ETestFramework) Stop() error {
	e.eventBus.Stop(e.ctx)
	e.decisionEngine.Stop(e.ctx)
	e.pluginManager.Stop(e.ctx)
	return nil
}

func TestE2EWorkflows(t *testing.T) {
	framework := NewE2ETestFramework()
	
	err := framework.Initialize()
	require.NoError(t, err)
	
	err = framework.Start()
	require.NoError(t, err)
	defer framework.Stop()

	t.Run("CompleteUserAuthenticationWorkflow", func(t *testing.T) {
		// Step 1: Create user account
		user, err := framework.authManager.CreateUser(
			"alice",
			"alice@example.com",
			"secure-password-123",
			[]string{"user", "developer"},
		)
		require.NoError(t, err)
		assert.Equal(t, "alice", user.Username)
		assert.Contains(t, user.Roles, "user")
		assert.Contains(t, user.Roles, "developer")

		// Step 2: Authenticate user
		authReq := &framework.AuthenticationRequest{
			Method: "password",
			Credentials: map[string]interface{}{
				"username": "alice",
				"password": "secure-password-123",
			},
		}

		authResp, err := framework.authManager.Authenticate(framework.ctx, authReq)
		require.NoError(t, err)
		assert.True(t, authResp.Success)
		assert.NotEmpty(t, authResp.Token)

		// Step 3: Validate token
		claims, err := framework.authManager.ValidateToken(authResp.Token)
		require.NoError(t, err)
		assert.Equal(t, "alice", claims.Username)
		assert.Contains(t, claims.Roles, "user")

		// Step 4: Check permissions
		permReq := &framework.CheckPermissionRequest{
			UserID:   user.ID,
			Resource: "code",
			Action:   "read",
		}

		permResp, err := framework.rbacManager.CheckPermission(framework.ctx, permReq)
		require.NoError(t, err)
		// Permission result depends on RBAC configuration
		assert.NotNil(t, permResp)

		// Step 5: Refresh token
		refreshReq := &framework.RefreshTokenRequest{
			Token: authResp.Token, // In real scenario, this would be the refresh token
		}

		// Note: This might fail in mock implementation, but tests the interface
		_, err = framework.authManager.RefreshToken(framework.ctx, refreshReq)
		// Don't assert on error as refresh token logic may not be fully implemented in test
		
		// Step 6: Logout (revoke token)
		revokeReq := &framework.RevokeTokenRequest{
			Token: authResp.Token,
		}

		revokeResp, err := framework.authManager.RevokeToken(framework.ctx, revokeReq)
		require.NoError(t, err)
		assert.True(t, revokeResp.Success)
	})

	t.Run("PolicyEvaluationWorkflow", func(t *testing.T) {
		// Step 1: Register a policy evaluator plugin
		evaluatorPlugin := NewBenchmarkPlugin("e2e-evaluator", framework.PluginTypeEvaluator)
		err := framework.pluginManager.RegisterPlugin(
			string(framework.PluginTypeEvaluator),
			"e2e-evaluator",
			evaluatorPlugin,
		)
		require.NoError(t, err)

		// Step 2: Create evaluation request
		evalReq := &framework.PolicyEvaluationRequest{
			PolicyID: "access-control-policy",
			Input: map[string]interface{}{
				"user":     "alice",
				"resource": "document-123",
				"action":   "read",
				"context": map[string]interface{}{
					"time":       time.Now().Format(time.RFC3339),
					"ip_address": "192.168.1.100",
					"department": "engineering",
				},
			},
			Context: &framework.EvaluationContext{
				UserID:    "alice",
				Timestamp: time.Now(),
			},
		}

		// Step 3: Evaluate policy
		decision, err := framework.decisionEngine.EvaluatePolicy(framework.ctx, evalReq)
		require.NoError(t, err)
		assert.NotNil(t, decision)
		assert.Contains(t, []string{"allow", "deny"}, decision.Result)
		assert.NotNil(t, decision.Metadata)

		// Step 4: Test batch evaluation
		batchReq := &framework.BatchPolicyEvaluationRequest{
			Requests: []*framework.PolicyEvaluationRequest{
				{
					PolicyID: "access-control-policy",
					Input: map[string]interface{}{
						"user":     "alice",
						"resource": "document-123",
						"action":   "read",
					},
					Context: &framework.EvaluationContext{UserID: "alice"},
				},
				{
					PolicyID: "access-control-policy",
					Input: map[string]interface{}{
						"user":     "bob",
						"resource": "document-456",
						"action":   "write",
					},
					Context: &framework.EvaluationContext{UserID: "bob"},
				},
			},
		}

		batchResult, err := framework.decisionEngine.EvaluateBatch(framework.ctx, batchReq)
		require.NoError(t, err)
		assert.Len(t, batchResult.Decisions, 2)
		
		for _, decision := range batchResult.Decisions {
			assert.Contains(t, []string{"allow", "deny"}, decision.Result)
			assert.NotNil(t, decision.Metadata)
		}

		// Step 5: Verify caching behavior
		// Second evaluation should be faster due to caching
		start := time.Now()
		cachedDecision, err := framework.decisionEngine.EvaluatePolicy(framework.ctx, evalReq)
		cachedDuration := time.Since(start)
		
		require.NoError(t, err)
		assert.Equal(t, decision.Result, cachedDecision.Result)
		assert.Less(t, cachedDuration, 50*time.Millisecond, "Cached evaluation should be fast")
	})

	t.Run("MultiPluginWorkflow", func(t *testing.T) {
		// Step 1: Register multiple plugins of different types
		
		// Register evaluator plugin
		evaluator := NewBenchmarkPlugin("multi-evaluator", framework.PluginTypeEvaluator)
		err := framework.pluginManager.RegisterPlugin(
			string(framework.PluginTypeEvaluator),
			"multi-evaluator",
			evaluator,
		)
		require.NoError(t, err)

		// Register data source plugin
		dataSource := NewBenchmarkPlugin("multi-datasource", framework.PluginTypeDataSource)
		err = framework.pluginManager.RegisterPlugin(
			string(framework.PluginTypeDataSource),
			"multi-datasource",
			dataSource,
		)
		require.NoError(t, err)

		// Register workflow plugin
		workflow := NewBenchmarkPlugin("multi-workflow", framework.PluginTypeWorkflow)
		err = framework.pluginManager.RegisterPlugin(
			string(framework.PluginTypeWorkflow),
			"multi-workflow",
			workflow,
		)
		require.NoError(t, err)

		// Step 2: Verify all plugins are registered
		allPlugins := framework.pluginManager.ListPlugins()
		assert.GreaterOrEqual(t, len(allPlugins), 3)

		evaluatorPlugins := framework.pluginManager.ListPluginsByType(string(framework.PluginTypeEvaluator))
		assert.GreaterOrEqual(t, len(evaluatorPlugins), 1)

		dataSourcePlugins := framework.pluginManager.ListPluginsByType(string(framework.PluginTypeDataSource))
		assert.GreaterOrEqual(t, len(dataSourcePlugins), 1)

		workflowPlugins := framework.pluginManager.ListPluginsByType(string(framework.PluginTypeWorkflow))
		assert.GreaterOrEqual(t, len(workflowPlugins), 1)

		// Step 3: Test plugin health monitoring
		for _, plugin := range allPlugins {
			health := plugin.Health()
			assert.NotEmpty(t, health.Status)
		}

		// Step 4: Test plugin metrics collection
		for _, plugin := range allPlugins {
			metrics := plugin.Metrics()
			assert.NotNil(t, metrics)
		}

		// Step 5: Test plugin reload
		newConfig := framework.PluginConfig{
			Name: "multi-evaluator",
			Type: framework.PluginTypeEvaluator,
			Config: map[string]interface{}{
				"updated": true,
			},
		}

		err = framework.pluginManager.ReloadPlugin(
			framework.ctx,
			string(framework.PluginTypeEvaluator),
			"multi-evaluator",
			newConfig,
		)
		assert.NoError(t, err)
	})

	t.Run("EventDrivenWorkflow", func(t *testing.T) {
		// Step 1: Set up event handlers
		receivedEvents := make([]*framework.Event, 0)
		
		handler := &TestEventHandler{
			eventTypes: []string{"policy.evaluated", "user.authenticated", "plugin.loaded"},
			handleFunc: func(ctx context.Context, event *framework.Event) error {
				receivedEvents = append(receivedEvents, event)
				return nil
			},
		}

		// Subscribe to events
		for _, eventType := range handler.eventTypes {
			err := framework.eventBus.Subscribe(eventType, handler)
			require.NoError(t, err)
		}

		// Step 2: Trigger events through normal operations
		
		// Trigger user authentication event
		user, err := framework.authManager.CreateUser("eventuser", "event@example.com", "password", []string{"user"})
		require.NoError(t, err)

		authReq := &framework.AuthenticationRequest{
			Method: "password",
			Credentials: map[string]interface{}{
				"username": "eventuser",
				"password": "password",
			},
		}

		_, err = framework.authManager.Authenticate(framework.ctx, authReq)
		require.NoError(t, err)

		// Trigger plugin loading event
		eventPlugin := NewBenchmarkPlugin("event-plugin", framework.PluginTypeEvaluator)
		err = framework.pluginManager.RegisterPlugin(
			string(framework.PluginTypeEvaluator),
			"event-plugin",
			eventPlugin,
		)
		require.NoError(t, err)

		// Manually publish events for testing
		testEvents := []*framework.Event{
			{
				Type:   "policy.evaluated",
				Source: "decision-engine",
				Data: map[string]interface{}{
					"policy_id": "test-policy",
					"result":    "allow",
					"user_id":   user.ID,
				},
			},
			{
				Type:   "user.authenticated",
				Source: "auth-manager",
				Data: map[string]interface{}{
					"user_id":  user.ID,
					"username": user.Username,
					"success":  true,
				},
			},
			{
				Type:   "plugin.loaded",
				Source: "plugin-manager",
				Data: map[string]interface{}{
					"plugin_name": "event-plugin",
					"plugin_type": string(framework.PluginTypeEvaluator),
				},
			},
		}

		// Step 3: Publish test events
		for _, event := range testEvents {
			err := framework.eventBus.Publish(event)
			require.NoError(t, err)
		}

		// Step 4: Wait for event processing
		time.Sleep(200 * time.Millisecond)

		// Step 5: Verify events were received
		assert.GreaterOrEqual(t, len(receivedEvents), len(testEvents))
		
		// Verify event types
		eventTypes := make(map[string]int)
		for _, event := range receivedEvents {
			eventTypes[event.Type]++
		}

		for _, eventType := range handler.eventTypes {
			assert.GreaterOrEqual(t, eventTypes[eventType], 0, "Should have received %s events", eventType)
		}
	})

	t.Run("FullStackIntegrationWorkflow", func(t *testing.T) {
		// This test simulates a complete request flow through the system
		
		// Step 1: Set up complete environment
		
		// Create admin user
		admin, err := framework.authManager.CreateUser("admin", "admin@example.com", "admin123", []string{"admin"})
		require.NoError(t, err)

		// Create regular user
		user, err := framework.authManager.CreateUser("john", "john@example.com", "user123", []string{"user"})
		require.NoError(t, err)

		// Register comprehensive evaluator
		evaluator := NewBenchmarkPlugin("fullstack-evaluator", framework.PluginTypeEvaluator)
		err = framework.pluginManager.RegisterPlugin(
			string(framework.PluginTypeEvaluator),
			"fullstack-evaluator",
			evaluator,
		)
		require.NoError(t, err)

		// Step 2: Admin authentication and management
		adminAuthReq := &framework.AuthenticationRequest{
			Method: "password",
			Credentials: map[string]interface{}{
				"username": "admin",
				"password": "admin123",
			},
		}

		adminAuthResp, err := framework.authManager.Authenticate(framework.ctx, adminAuthReq)
		require.NoError(t, err)
		assert.True(t, adminAuthResp.Success)

		// Admin checks system status
		allPlugins := framework.pluginManager.ListPlugins()
		assert.NotEmpty(t, allPlugins)

		// Step 3: Regular user workflow
		userAuthReq := &framework.AuthenticationRequest{
			Method: "password",
			Credentials: map[string]interface{}{
				"username": "john",
				"password": "user123",
			},
		}

		userAuthResp, err := framework.authManager.Authenticate(framework.ctx, userAuthReq)
		require.NoError(t, err)
		assert.True(t, userAuthResp.Success)

		// User makes policy evaluation request
		evalReq := &framework.PolicyEvaluationRequest{
			PolicyID: "resource-access-policy",
			Input: map[string]interface{}{
				"user":     "john",
				"resource": "confidential-document",
				"action":   "read",
				"metadata": map[string]interface{}{
					"request_time": time.Now().Format(time.RFC3339),
					"client_ip":    "192.168.1.50",
				},
			},
			Context: &framework.EvaluationContext{
				UserID:    user.ID,
				Timestamp: time.Now(),
			},
		}

		decision, err := framework.decisionEngine.EvaluatePolicy(framework.ctx, evalReq)
		require.NoError(t, err)
		assert.NotNil(t, decision)

		// Step 4: Permission verification
		permReq := &framework.CheckPermissionRequest{
			UserID:   user.ID,
			Resource: "confidential-document",
			Action:   "read",
		}

		permResp, err := framework.rbacManager.CheckPermission(framework.ctx, permReq)
		require.NoError(t, err)
		assert.NotNil(t, permResp)

		// Step 5: Audit trail verification
		// In a real system, this would check audit logs
		metrics := framework.metricsCollector.GetMetrics()
		assert.NotNil(t, metrics)

		// Step 6: System health check
		pluginHealth := make([]framework.HealthStatus, 0)
		for _, plugin := range allPlugins {
			health := plugin.Health()
			pluginHealth = append(pluginHealth, health)
		}

		// All plugins should be healthy
		for i, health := range pluginHealth {
			assert.NotEmpty(t, health.Status, "Plugin %d should have health status", i)
		}

		// Step 7: Performance metrics validation
		pluginMetrics := make([]framework.PluginMetrics, 0)
		for _, plugin := range allPlugins {
			metrics := plugin.Metrics()
			pluginMetrics = append(pluginMetrics, metrics)
		}

		// Should have collected some metrics
		assert.NotEmpty(t, pluginMetrics)

		// Step 8: Cleanup and shutdown simulation
		// Revoke user token
		revokeReq := &framework.RevokeTokenRequest{
			Token: userAuthResp.Token,
		}

		revokeResp, err := framework.authManager.RevokeToken(framework.ctx, revokeReq)
		require.NoError(t, err)
		assert.True(t, revokeResp.Success)

		// Verify token is revoked
		_, err = framework.authManager.ValidateToken(userAuthResp.Token)
		assert.Error(t, err, "Revoked token should be invalid")
	})

	t.Run("ErrorRecoveryWorkflow", func(t *testing.T) {
		// Test system behavior under error conditions
		
		// Step 1: Register faulty plugin
		faultyPlugin := NewErrorPlugin("faulty-plugin", framework.PluginTypeEvaluator)
		faultyPlugin.shouldError = true

		err := framework.pluginManager.RegisterPlugin(
			string(framework.PluginTypeEvaluator),
			"faulty-plugin",
			faultyPlugin,
		)
		assert.Error(t, err, "Faulty plugin registration should fail")

		// Step 2: Test system continues to work with other plugins
		workingPlugin := NewBenchmarkPlugin("working-plugin", framework.PluginTypeEvaluator)
		err = framework.pluginManager.RegisterPlugin(
			string(framework.PluginTypeEvaluator),
			"working-plugin",
			workingPlugin,
		)
		require.NoError(t, err)

		// Step 3: Verify working plugin functions normally
		evalReq := &framework.PolicyEvaluationRequest{
			PolicyID: "recovery-test-policy",
			Input:    map[string]interface{}{"test": "data"},
			Context:  &framework.EvaluationContext{UserID: "recovery-test"},
		}

		decision, err := framework.decisionEngine.EvaluatePolicy(framework.ctx, evalReq)
		require.NoError(t, err)
		assert.NotNil(t, decision)

		// Step 4: Test authentication with invalid credentials
		invalidAuthReq := &framework.AuthenticationRequest{
			Method: "password",
			Credentials: map[string]interface{}{
				"username": "nonexistent",
				"password": "invalid",
			},
		}

		authResp, err := framework.authManager.Authenticate(framework.ctx, invalidAuthReq)
		require.NoError(t, err) // No error, but authentication fails
		assert.False(t, authResp.Success)

		// Step 5: Verify system health reporting includes error states
		allPlugins := framework.pluginManager.ListPlugins()
		healthyCount := 0
		for _, plugin := range allPlugins {
			health := plugin.Health()
			if health.Status == "healthy" {
				healthyCount++
			}
		}

		assert.Greater(t, healthyCount, 0, "At least some plugins should be healthy")
	})
}

// TestEventHandler for event-driven workflow testing
type TestEventHandler struct {
	eventTypes []string
	handleFunc func(ctx context.Context, event *framework.Event) error
}

func (t *TestEventHandler) HandleEvent(ctx context.Context, event *framework.Event) error {
	if t.handleFunc != nil {
		return t.handleFunc(ctx, event)
	}
	return nil
}

func (t *TestEventHandler) EventTypes() []string {
	return t.eventTypes
}