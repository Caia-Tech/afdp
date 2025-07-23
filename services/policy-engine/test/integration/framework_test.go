package integration

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/Caia-Tech/afdp/services/policy-engine/internal/core"
	"github.com/Caia-Tech/afdp/services/policy-engine/internal/api/rest"
	"github.com/Caia-Tech/afdp/services/policy-engine/internal/logging"
	"github.com/Caia-Tech/afdp/services/policy-engine/internal/metrics"
	"github.com/Caia-Tech/afdp/services/policy-engine/pkg/framework"
)

const (
	testConfigPath = "../config/test-framework.yaml"
	apiBaseURL     = "http://localhost:8081/api/v1"
	healthURL      = "http://localhost:8081/health"
)

// TestFramework is the main integration test suite
type TestFramework struct {
	t             *testing.T
	framework     *core.FrameworkCore
	server        *rest.Server
	configManager *core.ConfigurationManager
	logger        *logging.Logger
	authToken     string
}

func TestFrameworkIntegration(t *testing.T) {
	tf := setupTestFramework(t)
	defer tf.teardown()

	// Run test suites
	t.Run("Health", tf.testHealth)
	t.Run("Authentication", tf.testAuthentication)
	t.Run("PluginManagement", tf.testPluginManagement)
	t.Run("PolicyEvaluation", tf.testPolicyEvaluation)
	t.Run("Pipeline", tf.testPipeline)
	t.Run("RBAC", tf.testRBAC)
	t.Run("ConfigReload", tf.testConfigReload)
}

func setupTestFramework(t *testing.T) *TestFramework {
	logger := logging.NewLogger("debug")
	
	// Load configuration
	configManager := core.NewConfigurationManager(logger)
	config, err := configManager.LoadConfiguration(testConfigPath)
	require.NoError(t, err, "Failed to load test configuration")

	// Create metrics collector
	metricsCollector := metrics.NewCollector(config.Framework.Metrics)
	metricsCollector.Start()

	// Create framework core
	frameworkCore, err := core.NewFrameworkCore(config, logger, metricsCollector)
	require.NoError(t, err, "Failed to create framework core")

	// Initialize framework
	ctx := context.Background()
	err = frameworkCore.Initialize(ctx)
	require.NoError(t, err, "Failed to initialize framework")

	// Start framework
	err = frameworkCore.Start(ctx)
	require.NoError(t, err, "Failed to start framework")

	// Create and start REST server
	server := rest.NewServer(frameworkCore, config.API.REST, logger)
	go func() {
		if err := server.Start(); err != nil && err != http.ErrServerClosed {
			logger.Error("Server failed", "error", err)
		}
	}()

	// Wait for server to start
	time.Sleep(2 * time.Second)

	tf := &TestFramework{
		t:             t,
		framework:     frameworkCore,
		server:        server,
		configManager: configManager,
		logger:        logger,
	}

	// Login to get auth token
	tf.login()

	return tf
}

func (tf *TestFramework) teardown() {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Stop server
	if err := tf.server.Stop(ctx); err != nil {
		tf.logger.Error("Failed to stop server", "error", err)
	}

	// Stop framework
	if err := tf.framework.Stop(ctx); err != nil {
		tf.logger.Error("Failed to stop framework", "error", err)
	}
}

func (tf *TestFramework) login() {
	loginReq := map[string]interface{}{
		"method": "password",
		"credentials": map[string]interface{}{
			"username": "testadmin",
			"password": "testpass123",
		},
	}

	resp := tf.postJSON("/auth/login", loginReq, "")
	require.Equal(tf.t, http.StatusOK, resp.StatusCode)

	var loginResp framework.AuthenticationResponse
	err := json.NewDecoder(resp.Body).Decode(&loginResp)
	require.NoError(tf.t, err)
	require.True(tf.t, loginResp.Success)

	tf.authToken = loginResp.Token
}

// Test cases

func (tf *TestFramework) testHealth(t *testing.T) {
	tests := []struct {
		name     string
		endpoint string
		expected int
	}{
		{"Health", "/health", http.StatusOK},
		{"Health Live", "/health/live", http.StatusOK},
		{"Health Ready", "/health/ready", http.StatusOK},
		{"Metrics", "/metrics", http.StatusOK},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			resp, err := http.Get("http://localhost:8081" + tc.endpoint)
			require.NoError(t, err)
			defer resp.Body.Close()
			assert.Equal(t, tc.expected, resp.StatusCode)
		})
	}
}

func (tf *TestFramework) testAuthentication(t *testing.T) {
	t.Run("ValidLogin", func(t *testing.T) {
		loginReq := map[string]interface{}{
			"method": "password",
			"credentials": map[string]interface{}{
				"username": "testuser",
				"password": "testpass123",
			},
		}

		resp := tf.postJSON("/auth/login", loginReq, "")
		assert.Equal(t, http.StatusOK, resp.StatusCode)

		var authResp framework.AuthenticationResponse
		err := json.NewDecoder(resp.Body).Decode(&authResp)
		require.NoError(t, err)
		assert.True(t, authResp.Success)
		assert.NotEmpty(t, authResp.Token)
	})

	t.Run("InvalidLogin", func(t *testing.T) {
		loginReq := map[string]interface{}{
			"method": "password",
			"credentials": map[string]interface{}{
				"username": "testuser",
				"password": "wrongpassword",
			},
		}

		resp := tf.postJSON("/auth/login", loginReq, "")
		assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
	})

	t.Run("ProtectedEndpoint", func(t *testing.T) {
		// Without token
		resp := tf.getJSON("/framework/status", "")
		assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)

		// With token
		resp = tf.getJSON("/framework/status", tf.authToken)
		assert.Equal(t, http.StatusOK, resp.StatusCode)
	})
}

func (tf *TestFramework) testPluginManagement(t *testing.T) {
	t.Run("ListPlugins", func(t *testing.T) {
		resp := tf.getJSON("/plugins", tf.authToken)
		assert.Equal(t, http.StatusOK, resp.StatusCode)

		var result map[string]interface{}
		err := json.NewDecoder(resp.Body).Decode(&result)
		require.NoError(t, err)

		plugins, ok := result["plugins"].([]interface{})
		assert.True(t, ok)
		assert.GreaterOrEqual(t, len(plugins), 3) // security, rego, workflow
	})

	t.Run("GetPlugin", func(t *testing.T) {
		resp := tf.getJSON("/plugins/evaluator/rego", tf.authToken)
		assert.Equal(t, http.StatusOK, resp.StatusCode)

		var plugin framework.PluginInfo
		err := json.NewDecoder(resp.Body).Decode(&plugin)
		require.NoError(t, err)
		assert.Equal(t, "rego", plugin.Name)
		assert.Equal(t, framework.PluginTypeEvaluator, plugin.Type)
	})

	t.Run("PluginHealth", func(t *testing.T) {
		resp := tf.getJSON("/plugins/evaluator/rego/health", tf.authToken)
		assert.Equal(t, http.StatusOK, resp.StatusCode)

		var health framework.HealthStatus
		err := json.NewDecoder(resp.Body).Decode(&health)
		require.NoError(t, err)
		assert.Equal(t, "healthy", health.Status)
	})
}

func (tf *TestFramework) testPolicyEvaluation(t *testing.T) {
	t.Run("SimpleEvaluation", func(t *testing.T) {
		evalReq := framework.PolicyEvaluationRequest{
			PolicyID: "test_policy",
			Input: map[string]interface{}{
				"user":   "alice",
				"action": "read",
			},
			Context: &framework.EvaluationContext{
				UserID:    "test-user",
				Timestamp: time.Now(),
			},
		}

		resp := tf.postJSON("/evaluate", evalReq, tf.authToken)
		assert.Equal(t, http.StatusOK, resp.StatusCode)

		var decision framework.PolicyDecision
		err := json.NewDecoder(resp.Body).Decode(&decision)
		require.NoError(t, err)
		assert.Equal(t, "allow", decision.Result)
	})

	t.Run("DenyEvaluation", func(t *testing.T) {
		evalReq := framework.PolicyEvaluationRequest{
			PolicyID: "test_policy",
			Input: map[string]interface{}{
				"user":   "alice",
				"action": "write", // Not allowed
			},
			Context: &framework.EvaluationContext{
				UserID:    "test-user",
				Timestamp: time.Now(),
			},
		}

		resp := tf.postJSON("/evaluate", evalReq, tf.authToken)
		assert.Equal(t, http.StatusOK, resp.StatusCode)

		var decision framework.PolicyDecision
		err := json.NewDecoder(resp.Body).Decode(&decision)
		require.NoError(t, err)
		assert.Equal(t, "deny", decision.Result)
	})

	t.Run("BatchEvaluation", func(t *testing.T) {
		batchReq := framework.BatchPolicyEvaluationRequest{
			Requests: []*framework.PolicyEvaluationRequest{
				{
					PolicyID: "test_policy",
					Input: map[string]interface{}{
						"user":   "alice",
						"action": "read",
					},
					Context: &framework.EvaluationContext{
						UserID: "test-user",
					},
				},
				{
					PolicyID: "test_policy",
					Input: map[string]interface{}{
						"user":   "bob",
						"action": "list",
					},
					Context: &framework.EvaluationContext{
						UserID: "test-user",
					},
				},
			},
		}

		resp := tf.postJSON("/evaluate/batch", batchReq, tf.authToken)
		assert.Equal(t, http.StatusOK, resp.StatusCode)

		var result framework.BatchPolicyDecision
		err := json.NewDecoder(resp.Body).Decode(&result)
		require.NoError(t, err)
		assert.Len(t, result.Decisions, 2)
		assert.Equal(t, "allow", result.Decisions[0].Result)
		assert.Equal(t, "allow", result.Decisions[1].Result)
	})
}

func (tf *TestFramework) testPipeline(t *testing.T) {
	t.Run("ExecutePipeline", func(t *testing.T) {
		pipelineReq := framework.PipelineExecutionRequest{
			PipelineID: "multi-stage-approval",
			Input: map[string]interface{}{
				"user":     "alice",
				"resource": "document",
				"action":   "read",
			},
			Context: &framework.EvaluationContext{
				UserID:    "test-user",
				Timestamp: time.Now(),
			},
		}

		resp := tf.postJSON("/pipelines/execute", pipelineReq, tf.authToken)
		assert.Equal(t, http.StatusAccepted, resp.StatusCode)

		var execResp framework.PipelineExecutionResponse
		err := json.NewDecoder(resp.Body).Decode(&execResp)
		require.NoError(t, err)
		assert.NotEmpty(t, execResp.ExecutionID)
		assert.Equal(t, "running", execResp.Status)

		// Check status
		time.Sleep(500 * time.Millisecond)
		statusResp := tf.getJSON(fmt.Sprintf("/pipelines/%s/status", execResp.ExecutionID), tf.authToken)
		assert.Equal(t, http.StatusOK, statusResp.StatusCode)
	})
}

func (tf *TestFramework) testRBAC(t *testing.T) {
	// Login as regular user
	loginReq := map[string]interface{}{
		"method": "password",
		"credentials": map[string]interface{}{
			"username": "testuser",
			"password": "testpass123",
		},
	}

	resp := tf.postJSON("/auth/login", loginReq, "")
	require.Equal(t, http.StatusOK, resp.StatusCode)

	var loginResp framework.AuthenticationResponse
	err := json.NewDecoder(resp.Body).Decode(&loginResp)
	require.NoError(t, err)
	userToken := loginResp.Token

	t.Run("UserPermissions", func(t *testing.T) {
		// User can evaluate policies
		evalReq := framework.PolicyEvaluationRequest{
			PolicyID: "test_policy",
			Input: map[string]interface{}{
				"user":   "alice",
				"action": "read",
			},
			Context: &framework.EvaluationContext{
				UserID: "test-user",
			},
		}

		resp := tf.postJSON("/evaluate", evalReq, userToken)
		assert.Equal(t, http.StatusOK, resp.StatusCode)
	})

	t.Run("AdminOnlyEndpoints", func(t *testing.T) {
		// User cannot reload config
		resp := tf.postJSON("/framework/config/reload", nil, userToken)
		assert.Equal(t, http.StatusForbidden, resp.StatusCode)

		// Admin can reload config
		resp = tf.postJSON("/framework/config/reload", nil, tf.authToken)
		assert.Equal(t, http.StatusOK, resp.StatusCode)
	})

	t.Run("ListRoles", func(t *testing.T) {
		resp := tf.getJSON("/roles", userToken)
		assert.Equal(t, http.StatusOK, resp.StatusCode)

		var rolesResp framework.ListRolesResponse
		err := json.NewDecoder(resp.Body).Decode(&rolesResp)
		require.NoError(t, err)
		assert.GreaterOrEqual(t, len(rolesResp.Roles), 3) // admin, operator, user
	})
}

func (tf *TestFramework) testConfigReload(t *testing.T) {
	t.Run("ReloadConfiguration", func(t *testing.T) {
		// Get current config
		resp := tf.getJSON("/framework/config", tf.authToken)
		assert.Equal(t, http.StatusOK, resp.StatusCode)

		var originalConfig framework.FrameworkConfig
		err := json.NewDecoder(resp.Body).Decode(&originalConfig)
		require.NoError(t, err)

		// Trigger reload
		reloadResp := tf.postJSON("/framework/config/reload", nil, tf.authToken)
		assert.Equal(t, http.StatusOK, reloadResp.StatusCode)

		// Verify config is still valid
		resp = tf.getJSON("/framework/config", tf.authToken)
		assert.Equal(t, http.StatusOK, resp.StatusCode)

		var newConfig framework.FrameworkConfig
		err = json.NewDecoder(resp.Body).Decode(&newConfig)
		require.NoError(t, err)
		assert.Equal(t, originalConfig.Version, newConfig.Version)
	})
}

// Helper methods

func (tf *TestFramework) getJSON(path string, token string) *http.Response {
	req, err := http.NewRequest("GET", apiBaseURL+path, nil)
	require.NoError(tf.t, err)

	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	require.NoError(tf.t, err)

	return resp
}

func (tf *TestFramework) postJSON(path string, body interface{}, token string) *http.Response {
	jsonBody, err := json.Marshal(body)
	require.NoError(tf.t, err)

	req, err := http.NewRequest("POST", apiBaseURL+path, bytes.NewBuffer(jsonBody))
	require.NoError(tf.t, err)

	req.Header.Set("Content-Type", "application/json")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	require.NoError(tf.t, err)

	return resp
}