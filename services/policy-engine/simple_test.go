package main

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/Caia-Tech/afdp/services/policy-engine/internal/logging"
	"github.com/Caia-Tech/afdp/services/policy-engine/internal/metrics"
	"github.com/Caia-Tech/afdp/services/policy-engine/pkg/framework"
)

func TestFrameworkComponents(t *testing.T) {
	t.Run("Logger", func(t *testing.T) {
		logger := logging.NewLogger("debug")
		assert.NotNil(t, logger)
	})

	t.Run("MetricsCollector", func(t *testing.T) {
		config := framework.MetricsConfig{
			Enabled:   true,
			Port:      9090,
			Path:      "/metrics",
			Namespace: "test",
		}
		collector := metrics.NewCollector(config)
		assert.NotNil(t, collector)
	})

	t.Run("FrameworkTypes", func(t *testing.T) {
		// Test framework type constants
		assert.Equal(t, framework.PluginType("evaluator"), framework.PluginTypeEvaluator)
		assert.Equal(t, framework.PluginType("data_source"), framework.PluginTypeDataSource)
		assert.Equal(t, framework.PluginType("workflow"), framework.PluginTypeWorkflow)
		assert.Equal(t, framework.PluginType("security"), framework.PluginTypeSecurity)
	})

	t.Run("HealthStatus", func(t *testing.T) {
		health := framework.HealthStatus{
			Status:    "healthy",
			Message:   "All systems operational",
			Metadata:  map[string]interface{}{"uptime": "1h30m"},
		}
		
		assert.Equal(t, "healthy", health.Status)
		assert.Equal(t, "All systems operational", health.Message)
		assert.Contains(t, health.Metadata, "uptime")
	})
}

func TestPolicyStructures(t *testing.T) {
	t.Run("PolicyEvaluationRequest", func(t *testing.T) {
		req := &framework.PolicyEvaluationRequest{
			PolicyID: "test-policy",
			Input: map[string]interface{}{
				"user":   "alice",
				"action": "read",
			},
			Context: &framework.EvaluationContext{
				UserID: "test-user",
			},
		}
		
		assert.Equal(t, "test-policy", req.PolicyID)
		assert.Equal(t, "alice", req.Input["user"])
		assert.Equal(t, "test-user", req.Context.UserID)
	})

	t.Run("PolicyDecision", func(t *testing.T) {
		decision := &framework.PolicyDecision{
			Result:     "allow",
			Approvers:  []string{"alice"},
			Conditions: []string{"during_business_hours"},
			Metadata: map[string]interface{}{
				"reason": "user has permission",
			},
		}
		
		assert.Equal(t, "allow", decision.Result)
		assert.Contains(t, decision.Approvers, "alice")
		assert.Contains(t, decision.Conditions, "during_business_hours")
		assert.Equal(t, "user has permission", decision.Metadata["reason"])
	})
}

func TestConfiguration(t *testing.T) {
	t.Run("PluginConfig", func(t *testing.T) {
		config := framework.PluginConfig{
			Name:    "test-plugin",
			Type:    framework.PluginTypeEvaluator,
			Enabled: true,
			Source: framework.PluginSource{
				Type:     "local",
				Location: "builtin:rego",
			},
			Config: map[string]interface{}{
				"policies": map[string]interface{}{
					"test": "package policy\ndefault allow = false",
				},
			},
		}
		
		assert.Equal(t, "test-plugin", config.Name)
		assert.Equal(t, framework.PluginTypeEvaluator, config.Type)
		assert.True(t, config.Enabled)
		assert.Equal(t, "local", config.Source.Type)
		assert.Equal(t, "builtin:rego", config.Source.Location)
		assert.Contains(t, config.Config, "policies")
	})

	t.Run("FrameworkConfig", func(t *testing.T) {
		config := &framework.FrameworkConfig{
			Version:     "1.0.0",
			Name:        "Test Framework",
			Description: "Test configuration",
			Framework: framework.FrameworkCoreConfig{
				Logging: framework.LoggingConfig{
					Level:  "debug",
					Format: "json",
					Output: "stdout",
				},
				Metrics: framework.MetricsConfig{
					Enabled:   true,
					Port:      9090,
					Path:      "/metrics",
					Namespace: "test",
				},
			},
		}
		
		assert.Equal(t, "1.0.0", config.Version)
		assert.Equal(t, "Test Framework", config.Name)
		assert.Equal(t, "debug", config.Framework.Logging.Level)
		assert.True(t, config.Framework.Metrics.Enabled)
		assert.Equal(t, 9090, config.Framework.Metrics.Port)
	})
}