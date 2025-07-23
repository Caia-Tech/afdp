package plugins

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/Caia-Tech/afdp/services/policy-engine/pkg/framework"
)

func TestBuiltinRegoEvaluator(t *testing.T) {
	t.Run("CreateEvaluator", func(t *testing.T) {
		config := framework.PluginConfig{
			Name: "test-rego",
			Type: framework.PluginTypeEvaluator,
			Config: map[string]interface{}{
				"data": map[string]interface{}{
					"users": map[string]interface{}{
						"alice": map[string]interface{}{
							"department": "engineering",
							"clearance":  "high",
						},
					},
				},
				"policies": map[string]interface{}{
					"test_policy": `
						package policy
						
						default allow = false
						
						allow {
							input.user == "alice"
							input.action == "read"
						}
					`,
				},
			},
		}

		evaluator := NewBuiltinRegoEvaluator(config)
		assert.NotNil(t, evaluator)
		assert.Equal(t, "test-rego", evaluator.Name())
		assert.Equal(t, framework.PluginTypeEvaluator, evaluator.Type())
	})

	t.Run("Initialize", func(t *testing.T) {
		config := framework.PluginConfig{
			Name: "init-test",
			Type: framework.PluginTypeEvaluator,
			Config: map[string]interface{}{
				"policies": map[string]interface{}{
					"simple_policy": `
						package policy
						default allow = false
						allow { input.user == "test" }
					`,
				},
			},
		}

		evaluator := NewBuiltinRegoEvaluator(config)
		ctx := context.Background()

		err := evaluator.Initialize(ctx, config)
		assert.NoError(t, err)
		assert.NotNil(t, evaluator.rego)
		assert.Contains(t, evaluator.policies, "simple_policy")
	})

	t.Run("StartStop", func(t *testing.T) {
		config := framework.PluginConfig{
			Name: "lifecycle-test",
			Type: framework.PluginTypeEvaluator,
			Config: map[string]interface{}{
				"policies": map[string]interface{}{
					"test": "package policy\ndefault allow = false",
				},
			},
		}

		evaluator := NewBuiltinRegoEvaluator(config)
		ctx := context.Background()

		err := evaluator.Initialize(ctx, config)
		require.NoError(t, err)

		err = evaluator.Start(ctx)
		assert.NoError(t, err)

		err = evaluator.Stop(ctx)
		assert.NoError(t, err)
	})

	t.Run("EvaluateSimplePolicy", func(t *testing.T) {
		config := framework.PluginConfig{
			Name: "simple-eval",
			Type: framework.PluginTypeEvaluator,
			Config: map[string]interface{}{
				"policies": map[string]interface{}{
					"allow_alice": `
						package policy
						
						default allow = false
						
						allow {
							input.user == "alice"
							input.action == "read"
						}
					`,
				},
			},
		}

		evaluator := NewBuiltinRegoEvaluator(config)
		ctx := context.Background()

		err := evaluator.Initialize(ctx, config)
		require.NoError(t, err)
		err = evaluator.Start(ctx)
		require.NoError(t, err)
		defer evaluator.Stop(ctx)

		// Test allowed case
		req := &framework.PolicyEvaluationRequest{
			PolicyID: "allow_alice",
			Input: map[string]interface{}{
				"user":   "alice",
				"action": "read",
			},
			Context: &framework.EvaluationContext{
				UserID: "test-user",
			},
		}

		decision, err := evaluator.EvaluatePolicy(ctx, req)
		assert.NoError(t, err)
		assert.NotNil(t, decision)
		assert.Equal(t, "allow", decision.Result)
		assert.Equal(t, "allow_alice", decision.PolicyID)
		assert.NotEmpty(t, decision.ID)

		// Test denied case
		req.Input["user"] = "bob"
		decision, err = evaluator.EvaluatePolicy(ctx, req)
		assert.NoError(t, err)
		assert.Equal(t, "deny", decision.Result)
	})

	t.Run("EvaluateWithData", func(t *testing.T) {
		config := framework.PluginConfig{
			Name: "data-eval",
			Type: framework.PluginTypeEvaluator,
			Config: map[string]interface{}{
				"data": map[string]interface{}{
					"users": map[string]interface{}{
						"alice": map[string]interface{}{
							"department": "engineering",
							"clearance":  "high",
						},
						"bob": map[string]interface{}{
							"department": "sales",
							"clearance":  "medium",
						},
					},
					"permissions": map[string]interface{}{
						"engineering": []string{"read", "write", "deploy"},
						"sales":       []string{"read"},
					},
				},
				"policies": map[string]interface{}{
					"rbac_policy": `
						package policy
						
						default allow = false
						
						allow {
							user := data.users[input.user]
							permissions := data.permissions[user.department]
							input.action in permissions
						}
					`,
				},
			},
		}

		evaluator := NewBuiltinRegoEvaluator(config)
		ctx := context.Background()

		err := evaluator.Initialize(ctx, config)
		require.NoError(t, err)
		err = evaluator.Start(ctx)
		require.NoError(t, err)
		defer evaluator.Stop(ctx)

		testCases := []struct {
			user     string
			action   string
			expected string
		}{
			{"alice", "read", "allow"},
			{"alice", "write", "allow"},
			{"alice", "deploy", "allow"},
			{"alice", "delete", "deny"},
			{"bob", "read", "allow"},
			{"bob", "write", "deny"},
			{"charlie", "read", "deny"}, // User not in data
		}

		for _, tc := range testCases {
			req := &framework.PolicyEvaluationRequest{
				PolicyID: "rbac_policy",
				Input: map[string]interface{}{
					"user":   tc.user,
					"action": tc.action,
				},
				Context: &framework.EvaluationContext{
					UserID: "test-user",
				},
			}

			decision, err := evaluator.EvaluatePolicy(ctx, req)
			assert.NoError(t, err, "Failed for user=%s, action=%s", tc.user, tc.action)
			assert.Equal(t, tc.expected, decision.Result, 
				"Expected %s for user=%s, action=%s, got %s", 
				tc.expected, tc.user, tc.action, decision.Result)
		}
	})

	t.Run("EvaluateComplexPolicy", func(t *testing.T) {
		config := framework.PluginConfig{
			Name: "complex-eval",
			Type: framework.PluginTypeEvaluator,
			Config: map[string]interface{}{
				"data": map[string]interface{}{
					"roles": map[string]interface{}{
						"admin":    []string{"*"},
						"operator": []string{"read", "execute"},
						"viewer":   []string{"read"},
					},
					"user_roles": map[string]interface{}{
						"alice": []string{"admin"},
						"bob":   []string{"operator"},
						"carol": []string{"viewer"},
					},
				},
				"policies": map[string]interface{}{
					"advanced_rbac": `
						package policy
						
						default allow = false
						
						# Admin can do everything
						allow {
							"admin" in data.user_roles[input.user]
						}
						
						# Check specific permissions
						allow {
							user_roles := data.user_roles[input.user]
							some role in user_roles
							permissions := data.roles[role]
							input.action in permissions
						}
						
						# Time-based restrictions
						deny {
							input.time
							hour := time.parse_rfc3339_ns(input.time).hour
							hour < 9
						}
						
						deny {
							input.time
							hour := time.parse_rfc3339_ns(input.time).hour  
							hour > 17
						}
					`,
				},
			},
		}

		evaluator := NewBuiltinRegoEvaluator(config)
		ctx := context.Background()

		err := evaluator.Initialize(ctx, config)
		require.NoError(t, err)
		err = evaluator.Start(ctx)
		require.NoError(t, err)
		defer evaluator.Stop(ctx)

		// Test admin access
		req := &framework.PolicyEvaluationRequest{
			PolicyID: "advanced_rbac",
			Input: map[string]interface{}{
				"user":   "alice",
				"action": "delete", // Should be allowed for admin
			},
			Context: &framework.EvaluationContext{
				UserID: "test-user",
			},
		}

		decision, err := evaluator.EvaluatePolicy(ctx, req)
		assert.NoError(t, err)
		assert.Equal(t, "allow", decision.Result)

		// Test operator permissions
		req.Input["user"] = "bob"
		req.Input["action"] = "read"
		decision, err = evaluator.EvaluatePolicy(ctx, req)
		assert.NoError(t, err)
		assert.Equal(t, "allow", decision.Result)

		req.Input["action"] = "write"
		decision, err = evaluator.EvaluatePolicy(ctx, req)
		assert.NoError(t, err)
		assert.Equal(t, "deny", decision.Result)

		// Test time-based restrictions (outside business hours)
		req.Input["user"] = "alice"
		req.Input["action"] = "read"
		req.Input["time"] = "2023-12-25T06:00:00Z" // 6 AM
		decision, err = evaluator.EvaluatePolicy(ctx, req)
		assert.NoError(t, err)
		assert.Equal(t, "deny", decision.Result) // Should be denied due to time
	})

	t.Run("NonExistentPolicy", func(t *testing.T) {
		config := framework.PluginConfig{
			Name: "missing-policy",
			Type: framework.PluginTypeEvaluator,
			Config: map[string]interface{}{
				"policies": map[string]interface{}{
					"existing_policy": "package policy\ndefault allow = false",
				},
			},
		}

		evaluator := NewBuiltinRegoEvaluator(config)
		ctx := context.Background()

		err := evaluator.Initialize(ctx, config)
		require.NoError(t, err)
		err = evaluator.Start(ctx)
		require.NoError(t, err)
		defer evaluator.Stop(ctx)

		req := &framework.PolicyEvaluationRequest{
			PolicyID: "nonexistent_policy",
			Input: map[string]interface{}{
				"user": "alice",
			},
			Context: &framework.EvaluationContext{
				UserID: "test-user",
			},
		}

		_, err = evaluator.EvaluatePolicy(ctx, req)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "policy not found")
	})

	t.Run("InvalidRegoPolicy", func(t *testing.T) {
		config := framework.PluginConfig{
			Name: "invalid-rego",
			Type: framework.PluginTypeEvaluator,
			Config: map[string]interface{}{
				"policies": map[string]interface{}{
					"broken_policy": "invalid rego syntax here",
				},
			},
		}

		evaluator := NewBuiltinRegoEvaluator(config)
		ctx := context.Background()

		err := evaluator.Initialize(ctx, config)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "failed to compile policy")
	})

	t.Run("Reload", func(t *testing.T) {
		initialConfig := framework.PluginConfig{
			Name: "reload-test",
			Type: framework.PluginTypeEvaluator,
			Config: map[string]interface{}{
				"policies": map[string]interface{}{
					"test_policy": `
						package policy
						default allow = false
						allow { input.user == "alice" }
					`,
				},
			},
		}

		evaluator := NewBuiltinRegoEvaluator(initialConfig)
		ctx := context.Background()

		err := evaluator.Initialize(ctx, initialConfig)
		require.NoError(t, err)
		err = evaluator.Start(ctx)
		require.NoError(t, err)
		defer evaluator.Stop(ctx)

		// Test initial policy
		req := &framework.PolicyEvaluationRequest{
			PolicyID: "test_policy",
			Input: map[string]interface{}{
				"user": "bob",
			},
			Context: &framework.EvaluationContext{
				UserID: "test-user",
			},
		}

		decision, err := evaluator.EvaluatePolicy(ctx, req)
		assert.NoError(t, err)
		assert.Equal(t, "deny", decision.Result)

		// Reload with updated policy
		updatedConfig := framework.PluginConfig{
			Name: "reload-test",
			Type: framework.PluginTypeEvaluator,
			Config: map[string]interface{}{
				"policies": map[string]interface{}{
					"test_policy": `
						package policy
						default allow = false
						allow { input.user == "bob" }
					`,
				},
			},
		}

		err = evaluator.Reload(ctx, updatedConfig)
		assert.NoError(t, err)

		// Test updated policy
		decision, err = evaluator.EvaluatePolicy(ctx, req)
		assert.NoError(t, err)
		assert.Equal(t, "allow", decision.Result)
	})

	t.Run("Health", func(t *testing.T) {
		config := framework.PluginConfig{
			Name: "health-test",
			Type: framework.PluginTypeEvaluator,
			Config: map[string]interface{}{
				"policies": map[string]interface{}{
					"test": "package policy\ndefault allow = false",
				},
			},
		}

		evaluator := NewBuiltinRegoEvaluator(config)
		ctx := context.Background()

		err := evaluator.Initialize(ctx, config)
		require.NoError(t, err)

		health := evaluator.Health()
		assert.Equal(t, "healthy", health.Status)
		assert.Contains(t, health.Metadata, "policies_loaded")
		assert.Equal(t, 1, health.Metadata["policies_loaded"])
	})

	t.Run("Metrics", func(t *testing.T) {
		config := framework.PluginConfig{
			Name: "metrics-test",
			Type: framework.PluginTypeEvaluator,
			Config: map[string]interface{}{
				"policies": map[string]interface{}{
					"test_policy": `
						package policy
						default allow = false
						allow { input.user == "alice" }
					`,
				},
			},
		}

		evaluator := NewBuiltinRegoEvaluator(config)
		ctx := context.Background()

		err := evaluator.Initialize(ctx, config)
		require.NoError(t, err)
		err = evaluator.Start(ctx)
		require.NoError(t, err)
		defer evaluator.Stop(ctx)

		// Make some evaluations
		req := &framework.PolicyEvaluationRequest{
			PolicyID: "test_policy",
			Input: map[string]interface{}{
				"user": "alice",
			},
			Context: &framework.EvaluationContext{
				UserID: "test-user",
			},
		}

		for i := 0; i < 3; i++ {
			_, err := evaluator.EvaluatePolicy(ctx, req)
			assert.NoError(t, err)
		}

		metrics := evaluator.Metrics()
		assert.Contains(t, metrics, "evaluations_total")
		assert.Contains(t, metrics, "evaluations_success")
		assert.Equal(t, int64(3), metrics["evaluations_total"])
		assert.Equal(t, int64(3), metrics["evaluations_success"])
	})

	t.Run("ValidateConfig", func(t *testing.T) {
		evaluator := NewBuiltinRegoEvaluator(framework.PluginConfig{})

		// Valid config
		validConfig := framework.PluginConfig{
			Name: "test",
			Type: framework.PluginTypeEvaluator,
			Config: map[string]interface{}{
				"policies": map[string]interface{}{
					"test": "package policy\ndefault allow = false",
				},
			},
		}

		result := evaluator.ValidateConfig(validConfig)
		assert.True(t, result.Valid)
		assert.Empty(t, result.Errors)

		// Invalid config - missing policies
		invalidConfig := framework.PluginConfig{
			Name: "test",
			Type: framework.PluginTypeEvaluator,
			Config: map[string]interface{}{},
		}

		result = evaluator.ValidateConfig(invalidConfig)
		assert.False(t, result.Valid)
		assert.Contains(t, result.Errors, "policies configuration is required")

		// Invalid config - invalid Rego syntax
		invalidRegoConfig := framework.PluginConfig{
			Name: "test",
			Type: framework.PluginTypeEvaluator,
			Config: map[string]interface{}{
				"policies": map[string]interface{}{
					"bad_policy": "invalid rego syntax",
				},
			},
		}

		result = evaluator.ValidateConfig(invalidRegoConfig)
		assert.False(t, result.Valid)
		assert.NotEmpty(t, result.Errors)
	})

	t.Run("ConcurrentEvaluations", func(t *testing.T) {
		config := framework.PluginConfig{
			Name: "concurrent-test",
			Type: framework.PluginTypeEvaluator,
			Config: map[string]interface{}{
				"policies": map[string]interface{}{
					"concurrent_policy": `
						package policy
						default allow = false
						allow { input.user != "" }
					`,
				},
			},
		}

		evaluator := NewBuiltinRegoEvaluator(config)
		ctx := context.Background()

		err := evaluator.Initialize(ctx, config)
		require.NoError(t, err)
		err = evaluator.Start(ctx)
		require.NoError(t, err)
		defer evaluator.Stop(ctx)

		// Run concurrent evaluations
		numGoroutines := 10
		results := make(chan string, numGoroutines)
		errors := make(chan error, numGoroutines)

		for i := 0; i < numGoroutines; i++ {
			go func(idx int) {
				req := &framework.PolicyEvaluationRequest{
					PolicyID: "concurrent_policy",
					Input: map[string]interface{}{
						"user": fmt.Sprintf("user_%d", idx),
					},
					Context: &framework.EvaluationContext{
						UserID: fmt.Sprintf("concurrent_user_%d", idx),
					},
				}

				decision, err := evaluator.EvaluatePolicy(ctx, req)
				if err != nil {
					errors <- err
				} else {
					results <- decision.Result
				}
			}(i)
		}

		// Collect results
		for i := 0; i < numGoroutines; i++ {
			select {
			case result := <-results:
				assert.Equal(t, "allow", result)
			case err := <-errors:
				t.Errorf("Unexpected error in concurrent evaluation: %v", err)
			case <-time.After(5 * time.Second):
				t.Fatal("Test timed out")
			}
		}
	})
}