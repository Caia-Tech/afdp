package rest

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
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

// Mock FrameworkCore for testing
type mockFrameworkCore struct {
	config          *framework.FrameworkConfig
	pluginManager   *plugins.Manager
	authManager     *security.AuthManager
	rbacManager     *security.RBACManager
	decisionEngine  *core.DecisionEngine
	running         bool
}

func (m *mockFrameworkCore) Initialize(ctx context.Context) error { return nil }
func (m *mockFrameworkCore) Start(ctx context.Context) error     { m.running = true; return nil }
func (m *mockFrameworkCore) Stop(ctx context.Context) error      { m.running = false; return nil }
func (m *mockFrameworkCore) Health() framework.HealthStatus {
	return framework.HealthStatus{Status: "healthy"}
}
func (m *mockFrameworkCore) GetConfiguration() *framework.FrameworkConfig { return m.config }
func (m *mockFrameworkCore) GetPluginManager() framework.PluginManager    { return m.pluginManager }
func (m *mockFrameworkCore) GetAuthManager() framework.AuthManager        { return m.authManager }
func (m *mockFrameworkCore) GetRBACManager() framework.RBACManager        { return m.rbacManager }
func (m *mockFrameworkCore) GetDecisionEngine() framework.DecisionEngine  { return m.decisionEngine }

func setupTestServer(t *testing.T) (*Server, *mockFrameworkCore) {
	logger := logging.NewLogger("debug")
	metricsCollector := metrics.NewCollector(framework.MetricsConfig{})

	// Create mock framework components
	pluginManager := plugins.NewManager(logger, metricsCollector)
	authManager := security.NewAuthManager(logger, "test-secret")
	rbacManager := security.NewRBACManager(logger)
	decisionEngine := core.NewDecisionEngine(&framework.DecisionEngineConfig{
		CacheEnabled: true,
		CacheTTL:     300,
	}, pluginManager, logger, metricsCollector)

	mockCore := &mockFrameworkCore{
		config: &framework.FrameworkConfig{
			Version: "1.0.0",
			Name:    "Test Framework",
		},
		pluginManager:  pluginManager,
		authManager:    authManager,
		rbacManager:    rbacManager,
		decisionEngine: decisionEngine,
	}

	config := framework.RESTConfig{
		Host: "localhost",
		Port: 0, // Use random port for testing
		TLS:  framework.TLSConfig{},
	}

	server := NewServer(mockCore, config, logger)
	return server, mockCore
}

func TestRESTServer(t *testing.T) {
	t.Run("CreateServer", func(t *testing.T) {
		server, _ := setupTestServer(t)
		assert.NotNil(t, server)
		assert.NotNil(t, server.core)
		assert.NotNil(t, server.logger)
		assert.NotNil(t, server.middleware)
	})

	t.Run("Health", func(t *testing.T) {
		server, _ := setupTestServer(t)
		
		req := httptest.NewRequest("GET", "/health", nil)
		w := httptest.NewRecorder()
		
		server.handleHealth(w, req)
		
		assert.Equal(t, http.StatusOK, w.Code)
		
		var response map[string]interface{}
		err := json.Unmarshal(w.Body.Bytes(), &response)
		assert.NoError(t, err)
		assert.Equal(t, "healthy", response["status"])
	})

	t.Run("HealthLive", func(t *testing.T) {
		server, _ := setupTestServer(t)
		
		req := httptest.NewRequest("GET", "/health/live", nil)
		w := httptest.NewRecorder()
		
		server.handleHealthLive(w, req)
		
		assert.Equal(t, http.StatusOK, w.Code)
		
		var response map[string]interface{}
		err := json.Unmarshal(w.Body.Bytes(), &response)
		assert.NoError(t, err)
		assert.Equal(t, "ok", response["status"])
	})

	t.Run("HealthReady", func(t *testing.T) {
		server, mockCore := setupTestServer(t)
		
		// Test when not running
		req := httptest.NewRequest("GET", "/health/ready", nil)
		w := httptest.NewRecorder()
		
		server.handleHealthReady(w, req)
		assert.Equal(t, http.StatusServiceUnavailable, w.Code)
		
		// Test when running
		mockCore.running = true
		w = httptest.NewRecorder()
		server.handleHealthReady(w, req)
		assert.Equal(t, http.StatusOK, w.Code)
	})

	t.Run("Login", func(t *testing.T) {
		server, mockCore := setupTestServer(t)
		
		ctx := context.Background()
		err := mockCore.authManager.Initialize(ctx)
		require.NoError(t, err)
		
		// Create test user
		_, err = mockCore.authManager.CreateUser("testuser", "test@example.com", "testpass", []string{"user"})
		require.NoError(t, err)
		
		loginReq := map[string]interface{}{
			"method": "password",
			"credentials": map[string]interface{}{
				"username": "testuser",
				"password": "testpass",
			},
		}
		
		reqBody, _ := json.Marshal(loginReq)
		req := httptest.NewRequest("POST", "/api/v1/auth/login", bytes.NewBuffer(reqBody))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		
		server.handleLogin(w, req)
		
		assert.Equal(t, http.StatusOK, w.Code)
		
		var response framework.AuthenticationResponse
		err = json.Unmarshal(w.Body.Bytes(), &response)
		assert.NoError(t, err)
		assert.True(t, response.Success)
		assert.NotEmpty(t, response.Token)
	})

	t.Run("LoginInvalidCredentials", func(t *testing.T) {
		server, mockCore := setupTestServer(t)
		
		ctx := context.Background()
		err := mockCore.authManager.Initialize(ctx)
		require.NoError(t, err)
		
		loginReq := map[string]interface{}{
			"method": "password",
			"credentials": map[string]interface{}{
				"username": "nonexistent",
				"password": "wrongpass",
			},
		}
		
		reqBody, _ := json.Marshal(loginReq)
		req := httptest.NewRequest("POST", "/api/v1/auth/login", bytes.NewBuffer(reqBody))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		
		server.handleLogin(w, req)
		
		assert.Equal(t, http.StatusUnauthorized, w.Code)
	})

	t.Run("EvaluatePolicy", func(t *testing.T) {
		server, mockCore := setupTestServer(t)
		
		ctx := context.Background()
		
		// Initialize components
		err := mockCore.authManager.Initialize(ctx)
		require.NoError(t, err)
		err = mockCore.decisionEngine.Initialize(ctx)
		require.NoError(t, err)
		err = mockCore.decisionEngine.Start(ctx)
		require.NoError(t, err)
		defer mockCore.decisionEngine.Stop(ctx)
		
		// Create test user and get token
		_, err = mockCore.authManager.CreateUser("testuser", "test@example.com", "testpass", []string{"user"})
		require.NoError(t, err)
		
		authReq := &framework.AuthenticationRequest{
			Method: "password",
			Credentials: map[string]interface{}{
				"username": "testuser",
				"password": "testpass",
			},
		}
		authResp, err := mockCore.authManager.Authenticate(ctx, authReq)
		require.NoError(t, err)
		require.True(t, authResp.Success)
		
		// Register mock evaluator
		mockEvaluator := &mockPolicyEvaluator{
			name: "test-evaluator",
			response: &framework.PolicyDecision{
				ID:       "test-decision",
				Result:   "allow",
				PolicyID: "test_policy",
			},
		}
		err = mockCore.pluginManager.RegisterPlugin(string(framework.PluginTypeEvaluator), "test-evaluator", mockEvaluator)
		require.NoError(t, err)
		
		evalReq := framework.PolicyEvaluationRequest{
			PolicyID: "test_policy",
			Input: map[string]interface{}{
				"user":   "alice",
				"action": "read",
			},
			Context: &framework.EvaluationContext{
				UserID: "testuser",
			},
		}
		
		reqBody, _ := json.Marshal(evalReq)
		req := httptest.NewRequest("POST", "/api/v1/evaluate", bytes.NewBuffer(reqBody))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer "+authResp.Token)
		w := httptest.NewRecorder()
		
		server.handleEvaluate(w, req)
		
		assert.Equal(t, http.StatusOK, w.Code)
		
		var response framework.PolicyDecision
		err = json.Unmarshal(w.Body.Bytes(), &response)
		assert.NoError(t, err)
		assert.Equal(t, "allow", response.Result)
		assert.Equal(t, "test_policy", response.PolicyID)
	})

	t.Run("EvaluateWithoutAuth", func(t *testing.T) {
		server, _ := setupTestServer(t)
		
		evalReq := framework.PolicyEvaluationRequest{
			PolicyID: "test_policy",
			Input:    map[string]interface{}{"user": "alice"},
		}
		
		reqBody, _ := json.Marshal(evalReq)
		req := httptest.NewRequest("POST", "/api/v1/evaluate", bytes.NewBuffer(reqBody))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		
		server.handleEvaluate(w, req)
		
		assert.Equal(t, http.StatusUnauthorized, w.Code)
	})

	t.Run("BatchEvaluate", func(t *testing.T) {
		server, mockCore := setupTestServer(t)
		
		ctx := context.Background()
		
		// Initialize components
		err := mockCore.authManager.Initialize(ctx)
		require.NoError(t, err)
		err = mockCore.decisionEngine.Initialize(ctx)
		require.NoError(t, err)
		err = mockCore.decisionEngine.Start(ctx)
		require.NoError(t, err)
		defer mockCore.decisionEngine.Stop(ctx)
		
		// Create test user and get token
		_, err = mockCore.authManager.CreateUser("testuser", "test@example.com", "testpass", []string{"user"})
		require.NoError(t, err)
		
		authReq := &framework.AuthenticationRequest{
			Method: "password",
			Credentials: map[string]interface{}{
				"username": "testuser",
				"password": "testpass",
			},
		}
		authResp, err := mockCore.authManager.Authenticate(ctx, authReq)
		require.NoError(t, err)
		
		// Register mock evaluator
		mockEvaluator := &mockPolicyEvaluator{name: "test-evaluator"}
		err = mockCore.pluginManager.RegisterPlugin(string(framework.PluginTypeEvaluator), "test-evaluator", mockEvaluator)
		require.NoError(t, err)
		
		batchReq := framework.BatchPolicyEvaluationRequest{
			Requests: []*framework.PolicyEvaluationRequest{
				{
					PolicyID: "policy1",
					Input:    map[string]interface{}{"user": "alice"},
					Context:  &framework.EvaluationContext{UserID: "testuser"},
				},
				{
					PolicyID: "policy2",
					Input:    map[string]interface{}{"user": "bob"},
					Context:  &framework.EvaluationContext{UserID: "testuser"},
				},
			},
		}
		
		reqBody, _ := json.Marshal(batchReq)
		req := httptest.NewRequest("POST", "/api/v1/evaluate/batch", bytes.NewBuffer(reqBody))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer "+authResp.Token)
		w := httptest.NewRecorder()
		
		server.handleBatchEvaluate(w, req)
		
		assert.Equal(t, http.StatusOK, w.Code)
		
		var response framework.BatchPolicyDecision
		err = json.Unmarshal(w.Body.Bytes(), &response)
		assert.NoError(t, err)
		assert.Len(t, response.Decisions, 2)
		assert.Equal(t, "allow", response.Decisions[0].Result)
		assert.Equal(t, "allow", response.Decisions[1].Result)
	})

	t.Run("ListPlugins", func(t *testing.T) {
		server, mockCore := setupTestServer(t)
		
		ctx := context.Background()
		err := mockCore.authManager.Initialize(ctx)
		require.NoError(t, err)
		
		// Create admin user and get token
		_, err = mockCore.authManager.CreateUser("admin", "admin@example.com", "adminpass", []string{"admin"})
		require.NoError(t, err)
		
		authReq := &framework.AuthenticationRequest{
			Method: "password",
			Credentials: map[string]interface{}{
				"username": "admin",
				"password": "adminpass",
			},
		}
		authResp, err := mockCore.authManager.Authenticate(ctx, authReq)
		require.NoError(t, err)
		
		// Register test plugin
		mockPlugin := &mockPolicyEvaluator{name: "test-plugin"}
		err = mockCore.pluginManager.RegisterPlugin(string(framework.PluginTypeEvaluator), "test-plugin", mockPlugin)
		require.NoError(t, err)
		
		req := httptest.NewRequest("GET", "/api/v1/plugins", nil)
		req.Header.Set("Authorization", "Bearer "+authResp.Token)
		w := httptest.NewRecorder()
		
		server.handleListPlugins(w, req)
		
		assert.Equal(t, http.StatusOK, w.Code)
		
		var response map[string]interface{}
		err = json.Unmarshal(w.Body.Bytes(), &response)
		assert.NoError(t, err)
		
		plugins, ok := response["plugins"].([]interface{})
		assert.True(t, ok)
		assert.Len(t, plugins, 1)
	})

	t.Run("GetFrameworkStatus", func(t *testing.T) {
		server, mockCore := setupTestServer(t)
		
		ctx := context.Background()
		err := mockCore.authManager.Initialize(ctx)
		require.NoError(t, err)
		
		// Create admin user and get token
		_, err = mockCore.authManager.CreateUser("admin", "admin@example.com", "adminpass", []string{"admin"})
		require.NoError(t, err)
		
		authReq := &framework.AuthenticationRequest{
			Method: "password",
			Credentials: map[string]interface{}{
				"username": "admin",
				"password": "adminpass",
			},
		}
		authResp, err := mockCore.authManager.Authenticate(ctx, authReq)
		require.NoError(t, err)
		
		req := httptest.NewRequest("GET", "/api/v1/framework/status", nil)
		req.Header.Set("Authorization", "Bearer "+authResp.Token)
		w := httptest.NewRecorder()
		
		server.handleFrameworkStatus(w, req)
		
		assert.Equal(t, http.StatusOK, w.Code)
		
		var response framework.HealthStatus
		err = json.Unmarshal(w.Body.Bytes(), &response)
		assert.NoError(t, err)
		assert.Equal(t, "healthy", response.Status)
	})

	t.Run("CORS", func(t *testing.T) {
		server, _ := setupTestServer(t)
		
		req := httptest.NewRequest("OPTIONS", "/api/v1/health", nil)
		req.Header.Set("Origin", "http://localhost:3000")
		req.Header.Set("Access-Control-Request-Method", "GET")
		w := httptest.NewRecorder()
		
		server.middleware.CORS(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		})).ServeHTTP(w, req)
		
		assert.Equal(t, http.StatusOK, w.Code)
		assert.Equal(t, "*", w.Header().Get("Access-Control-Allow-Origin"))
		assert.Contains(t, w.Header().Get("Access-Control-Allow-Methods"), "GET")
	})

	t.Run("RateLimiting", func(t *testing.T) {
		server, _ := setupTestServer(t)
		
		// Make multiple requests quickly to trigger rate limiting
		handler := server.middleware.RateLimit(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		}))
		
		successCount := 0
		rateLimitedCount := 0
		
		for i := 0; i < 150; i++ { // Exceed the default limit
			req := httptest.NewRequest("GET", "/test", nil)
			req.RemoteAddr = "127.0.0.1:12345" // Same IP
			w := httptest.NewRecorder()
			
			handler.ServeHTTP(w, req)
			
			if w.Code == http.StatusOK {
				successCount++
			} else if w.Code == http.StatusTooManyRequests {
				rateLimitedCount++
			}
		}
		
		assert.Greater(t, successCount, 0)
		assert.Greater(t, rateLimitedCount, 0)
	})
}

// Mock PolicyEvaluator for testing
type mockPolicyEvaluator struct {
	name     string
	response *framework.PolicyDecision
	err      error
}

func (m *mockPolicyEvaluator) Name() string { return m.name }
func (m *mockPolicyEvaluator) Version() string { return "1.0.0" }
func (m *mockPolicyEvaluator) Type() framework.PluginType { return framework.PluginTypeEvaluator }
func (m *mockPolicyEvaluator) Metadata() framework.PluginMetadata { return framework.PluginMetadata{} }

func (m *mockPolicyEvaluator) Initialize(ctx context.Context, config framework.PluginConfig) error {
	return nil
}
func (m *mockPolicyEvaluator) Start(ctx context.Context) error { return nil }
func (m *mockPolicyEvaluator) Stop(ctx context.Context) error { return nil }
func (m *mockPolicyEvaluator) Reload(ctx context.Context, config framework.PluginConfig) error { return nil }
func (m *mockPolicyEvaluator) Health() framework.HealthStatus {
	return framework.HealthStatus{Status: "healthy"}
}
func (m *mockPolicyEvaluator) Metrics() framework.PluginMetrics { return framework.PluginMetrics{} }
func (m *mockPolicyEvaluator) ValidateConfig(config framework.PluginConfig) framework.ValidationResult {
	return framework.ValidationResult{Valid: true}
}

func (m *mockPolicyEvaluator) EvaluatePolicy(ctx context.Context, req *framework.PolicyEvaluationRequest) (*framework.PolicyDecision, error) {
	if m.err != nil {
		return nil, m.err
	}
	
	if m.response != nil {
		result := *m.response
		result.PolicyID = req.PolicyID
		return &result, nil
	}
	
	return &framework.PolicyDecision{
		ID:       "mock-decision",
		Result:   "allow",
		PolicyID: req.PolicyID,
		Metadata: map[string]interface{}{
			"evaluator": m.name,
		},
	}, nil
}

func TestMiddleware(t *testing.T) {
	logger := logging.NewLogger("debug")
	authManager := security.NewAuthManager(logger, "test-secret")
	rbacManager := security.NewRBACManager(logger)
	
	middleware := NewMiddleware(authManager, rbacManager, logger)

	t.Run("CreateMiddleware", func(t *testing.T) {
		assert.NotNil(t, middleware)
		assert.NotNil(t, middleware.authManager)
		assert.NotNil(t, middleware.rbacManager)
		assert.NotNil(t, middleware.logger)
	})

	t.Run("AuthenticateValid", func(t *testing.T) {
		ctx := context.Background()
		err := authManager.Initialize(ctx)
		require.NoError(t, err)
		
		// Create test user
		_, err = authManager.CreateUser("testuser", "test@example.com", "testpass", []string{"user"})
		require.NoError(t, err)
		
		// Get auth token
		authReq := &framework.AuthenticationRequest{
			Method: "password",
			Credentials: map[string]interface{}{
				"username": "testuser",
				"password": "testpass",
			},
		}
		authResp, err := authManager.Authenticate(ctx, authReq)
		require.NoError(t, err)
		require.True(t, authResp.Success)
		
		// Test middleware
		called := false
		handler := middleware.Authenticate(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			called = true
			w.WriteHeader(http.StatusOK)
		}))
		
		req := httptest.NewRequest("GET", "/test", nil)
		req.Header.Set("Authorization", "Bearer "+authResp.Token)
		w := httptest.NewRecorder()
		
		handler.ServeHTTP(w, req)
		
		assert.True(t, called)
		assert.Equal(t, http.StatusOK, w.Code)
	})

	t.Run("AuthenticateInvalid", func(t *testing.T) {
		called := false
		handler := middleware.Authenticate(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			called = true
		}))
		
		req := httptest.NewRequest("GET", "/test", nil)
		req.Header.Set("Authorization", "Bearer invalid-token")
		w := httptest.NewRecorder()
		
		handler.ServeHTTP(w, req)
		
		assert.False(t, called)
		assert.Equal(t, http.StatusUnauthorized, w.Code)
	})

	t.Run("AuthenticateMissingToken", func(t *testing.T) {
		called := false
		handler := middleware.Authenticate(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			called = true
		}))
		
		req := httptest.NewRequest("GET", "/test", nil)
		w := httptest.NewRecorder()
		
		handler.ServeHTTP(w, req)
		
		assert.False(t, called)
		assert.Equal(t, http.StatusUnauthorized, w.Code)
	})

	t.Run("Logging", func(t *testing.T) {
		handler := middleware.Logging(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		}))
		
		req := httptest.NewRequest("GET", "/test", nil)
		w := httptest.NewRecorder()
		
		handler.ServeHTTP(w, req)
		
		assert.Equal(t, http.StatusOK, w.Code)
		// Logger should have recorded the request (can't easily test without inspecting logs)
	})
}