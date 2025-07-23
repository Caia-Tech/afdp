package plugins

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/Caia-Tech/afdp/services/policy-engine/pkg/framework"
)

// Mock workflow execution context
type mockWorkflowContext struct {
	variables map[string]interface{}
	logs      []string
}

func (m *mockWorkflowContext) GetVariable(key string) interface{} {
	return m.variables[key]
}

func (m *mockWorkflowContext) SetVariable(key string, value interface{}) {
	if m.variables == nil {
		m.variables = make(map[string]interface{})
	}
	m.variables[key] = value
}

func (m *mockWorkflowContext) Log(message string) {
	m.logs = append(m.logs, message)
}

func TestBuiltinWorkflowEngine(t *testing.T) {
	t.Run("CreateWorkflowEngine", func(t *testing.T) {
		config := framework.PluginConfig{
			Name: "test-workflow",
			Type: framework.PluginTypeWorkflow,
			Config: map[string]interface{}{
				"workflows": []interface{}{
					map[string]interface{}{
						"id":          "simple-approval",
						"name":        "Simple Approval Workflow",
						"description": "A basic approval workflow",
						"steps": []interface{}{
							map[string]interface{}{
								"id":   "step1",
								"name": "Initial Review",
								"type": "approval",
							},
						},
					},
				},
			},
		}

		wf := NewBuiltinWorkflowEngine(config)
		assert.NotNil(t, wf)
		assert.Equal(t, "test-workflow", wf.Name())
		assert.Equal(t, framework.PluginTypeWorkflow, wf.Type())
	})

	t.Run("Initialize", func(t *testing.T) {
		config := framework.PluginConfig{
			Name: "init-test",
			Type: framework.PluginTypeWorkflow,
			Config: map[string]interface{}{
				"workflows": []interface{}{
					map[string]interface{}{
						"id":   "test-workflow",
						"name": "Test Workflow",
						"steps": []interface{}{
							map[string]interface{}{
								"id":   "step1",
								"type": "evaluate",
							},
						},
					},
				},
			},
		}

		wf := NewBuiltinWorkflowEngine(config)
		ctx := context.Background()

		err := wf.Initialize(ctx, config)
		assert.NoError(t, err)

		// Check that workflow was loaded
		assert.Contains(t, wf.(*BuiltinWorkflowEngine).workflows, "test-workflow")
	})

	t.Run("StartStop", func(t *testing.T) {
		config := framework.PluginConfig{
			Name: "lifecycle-test",
			Type: framework.PluginTypeWorkflow,
			Config: map[string]interface{}{
				"workflows": []interface{}{},
			},
		}

		wf := NewBuiltinWorkflowEngine(config)
		ctx := context.Background()

		err := wf.Initialize(ctx, config)
		require.NoError(t, err)

		err = wf.Start(ctx)
		assert.NoError(t, err)

		err = wf.Stop(ctx)
		assert.NoError(t, err)
	})

	t.Run("ExecuteSimpleWorkflow", func(t *testing.T) {
		config := framework.PluginConfig{
			Name: "execute-test",
			Type: framework.PluginTypeWorkflow,
			Config: map[string]interface{}{
				"workflows": []interface{}{
					map[string]interface{}{
						"id":          "approval-flow",
						"name":        "Approval Flow",
						"description": "Simple approval workflow",
						"steps": []interface{}{
							map[string]interface{}{
								"id":          "validate",
								"name":        "Validate Request",
								"type":        "validate",
								"config":      map[string]interface{}{
									"required_fields": []string{"user", "resource"},
								},
							},
							map[string]interface{}{
								"id":     "approve",
								"name":   "Approve Request",
								"type":   "approval",
								"config": map[string]interface{}{
									"approvers": []string{"manager", "admin"},
								},
							},
							map[string]interface{}{
								"id":     "notify",
								"name":   "Send Notification",
								"type":   "notification",
								"config": map[string]interface{}{
									"recipients": []string{"requester", "approver"},
								},
							},
						},
					},
				},
			},
		}

		wf := NewBuiltinWorkflowEngine(config)
		ctx := context.Background()

		err := wf.Initialize(ctx, config)
		require.NoError(t, err)
		err = wf.Start(ctx)
		require.NoError(t, err)
		defer wf.Stop(ctx)

		// Execute workflow
		req := &framework.WorkflowExecutionRequest{
			WorkflowID: "approval-flow",
			Input: map[string]interface{}{
				"user":     "alice",
				"resource": "document-123",
				"action":   "read",
			},
			Context: &framework.EvaluationContext{
				UserID:    "alice",
				Timestamp: time.Now(),
			},
		}

		resp, err := wf.(framework.WorkflowEngine).ExecuteWorkflow(ctx, req)
		assert.NoError(t, err)
		assert.NotNil(t, resp)
		assert.NotEmpty(t, resp.ExecutionID)
		assert.Equal(t, "approval-flow", resp.WorkflowID)
		assert.Contains(t, []string{"running", "completed", "pending"}, resp.Status)
	})

	t.Run("WorkflowStepExecution", func(t *testing.T) {
		config := framework.PluginConfig{
			Name: "step-test",
			Type: framework.PluginTypeWorkflow,
			Config: map[string]interface{}{
				"workflows": []interface{}{
					map[string]interface{}{
						"id":   "step-workflow",
						"name": "Step Testing Workflow",
						"steps": []interface{}{
							map[string]interface{}{
								"id":   "step1",
								"name": "First Step",
								"type": "evaluate",
								"config": map[string]interface{}{
									"condition": "input.value > 10",
								},
							},
							map[string]interface{}{
								"id":        "step2",
								"name":      "Second Step",
								"type":      "transform",
								"condition": "step1.result == 'success'",
								"config": map[string]interface{}{
									"operation": "multiply",
									"factor":    2,
								},
							},
							map[string]interface{}{
								"id":        "step3",
								"name":      "Final Step",
								"type":      "output",
								"condition": "step2.result != null",
							},
						},
					},
				},
			},
		}

		wf := NewBuiltinWorkflowEngine(config)
		ctx := context.Background()

		err := wf.Initialize(ctx, config)
		require.NoError(t, err)
		err = wf.Start(ctx)
		require.NoError(t, err)
		defer wf.Stop(ctx)

		// Test with input that should pass all steps
		req := &framework.WorkflowExecutionRequest{
			WorkflowID: "step-workflow",
			Input: map[string]interface{}{
				"value": 15,
			},
		}

		resp, err := wf.(framework.WorkflowEngine).ExecuteWorkflow(ctx, req)
		assert.NoError(t, err)
		assert.NotNil(t, resp)
		assert.NotEmpty(t, resp.ExecutionID)

		// Test with input that should fail first step
		req.Input["value"] = 5
		resp, err = wf.(framework.WorkflowEngine).ExecuteWorkflow(ctx, req)
		assert.NoError(t, err)
		assert.NotNil(t, resp)
		// Status might be "failed" or "completed" depending on implementation
		assert.Contains(t, []string{"failed", "completed", "error"}, resp.Status)
	})

	t.Run("GetWorkflowStatus", func(t *testing.T) {
		config := framework.PluginConfig{
			Name: "status-test",
			Type: framework.PluginTypeWorkflow,
			Config: map[string]interface{}{
				"workflows": []interface{}{
					map[string]interface{}{
						"id":   "status-workflow",
						"name": "Status Test Workflow",
						"steps": []interface{}{
							map[string]interface{}{
								"id":   "wait-step",
								"name": "Waiting Step",
								"type": "wait",
								"config": map[string]interface{}{
									"duration": "1s",
								},
							},
						},
					},
				},
			},
		}

		wf := NewBuiltinWorkflowEngine(config)
		ctx := context.Background()

		err := wf.Initialize(ctx, config)
		require.NoError(t, err)
		err = wf.Start(ctx)
		require.NoError(t, err)
		defer wf.Stop(ctx)

		// Execute workflow
		req := &framework.WorkflowExecutionRequest{
			WorkflowID: "status-workflow",
			Input:      map[string]interface{}{"test": "data"},
		}

		resp, err := wf.(framework.WorkflowEngine).ExecuteWorkflow(ctx, req)
		require.NoError(t, err)
		executionID := resp.ExecutionID

		// Get status
		statusReq := &framework.WorkflowStatusRequest{
			ExecutionID: executionID,
		}

		statusResp, err := wf.(framework.WorkflowEngine).GetWorkflowStatus(ctx, statusReq)
		assert.NoError(t, err)
		assert.NotNil(t, statusResp)
		assert.Equal(t, executionID, statusResp.ExecutionID)
		assert.Equal(t, "status-workflow", statusResp.WorkflowID)
		assert.Contains(t, []string{"running", "completed", "pending"}, statusResp.Status)

		// Test non-existent execution
		statusReq.ExecutionID = "non-existent"
		_, err = wf.(framework.WorkflowEngine).GetWorkflowStatus(ctx, statusReq)
		assert.Error(t, err)
	})

	t.Run("CancelWorkflow", func(t *testing.T) {
		config := framework.PluginConfig{
			Name: "cancel-test",
			Type: framework.PluginTypeWorkflow,
			Config: map[string]interface{}{
				"workflows": []interface{}{
					map[string]interface{}{
						"id":   "long-workflow",
						"name": "Long Running Workflow",
						"steps": []interface{}{
							map[string]interface{}{
								"id":   "long-step",
								"name": "Long Step",
								"type": "wait",
								"config": map[string]interface{}{
									"duration": "10s", // Long enough to cancel
								},
							},
						},
					},
				},
			},
		}

		wf := NewBuiltinWorkflowEngine(config)
		ctx := context.Background()

		err := wf.Initialize(ctx, config)
		require.NoError(t, err)
		err = wf.Start(ctx)
		require.NoError(t, err)
		defer wf.Stop(ctx)

		// Execute workflow
		req := &framework.WorkflowExecutionRequest{
			WorkflowID: "long-workflow",
			Input:      map[string]interface{}{"test": "data"},
		}

		resp, err := wf.(framework.WorkflowEngine).ExecuteWorkflow(ctx, req)
		require.NoError(t, err)
		executionID := resp.ExecutionID

		// Cancel the workflow
		cancelReq := &framework.CancelWorkflowRequest{
			ExecutionID: executionID,
			Reason:      "Test cancellation",
		}

		cancelResp, err := wf.(framework.WorkflowEngine).CancelWorkflow(ctx, cancelReq)
		assert.NoError(t, err)
		assert.NotNil(t, cancelResp)
		assert.True(t, cancelResp.Success)

		// Verify status shows cancelled
		statusReq := &framework.WorkflowStatusRequest{
			ExecutionID: executionID,
		}

		statusResp, err := wf.(framework.WorkflowEngine).GetWorkflowStatus(ctx, statusReq)
		assert.NoError(t, err)
		assert.Contains(t, []string{"cancelled", "canceled", "stopped"}, statusResp.Status)
	})

	t.Run("Health", func(t *testing.T) {
		config := framework.PluginConfig{
			Name: "health-test",
			Type: framework.PluginTypeWorkflow,
			Config: map[string]interface{}{
				"workflows": []interface{}{
					map[string]interface{}{
						"id":   "health-workflow",
						"name": "Health Test",
						"steps": []interface{}{
							map[string]interface{}{
								"id":   "health-step",
								"type": "evaluate",
							},
						},
					},
				},
			},
		}

		wf := NewBuiltinWorkflowEngine(config)
		ctx := context.Background()

		err := wf.Initialize(ctx, config)
		require.NoError(t, err)

		health := wf.Health()
		assert.Equal(t, "healthy", health.Status)
		assert.Contains(t, health.Metadata, "workflows_loaded")
		assert.Equal(t, 1, health.Metadata["workflows_loaded"])
		assert.Contains(t, health.Metadata, "active_executions")
	})

	t.Run("Metrics", func(t *testing.T) {
		config := framework.PluginConfig{
			Name: "metrics-test",
			Type: framework.PluginTypeWorkflow,
			Config: map[string]interface{}{
				"workflows": []interface{}{
					map[string]interface{}{
						"id":   "metrics-workflow",
						"name": "Metrics Test",
						"steps": []interface{}{
							map[string]interface{}{
								"id":   "metrics-step",
								"type": "evaluate",
							},
						},
					},
				},
			},
		}

		wf := NewBuiltinWorkflowEngine(config)
		ctx := context.Background()

		err := wf.Initialize(ctx, config)
		require.NoError(t, err)
		err = wf.Start(ctx)
		require.NoError(t, err)
		defer wf.Stop(ctx)

		// Execute workflow multiple times
		for i := 0; i < 3; i++ {
			req := &framework.WorkflowExecutionRequest{
				WorkflowID: "metrics-workflow",
				Input:      map[string]interface{}{"iteration": i},
			}
			_, err := wf.(framework.WorkflowEngine).ExecuteWorkflow(ctx, req)
			assert.NoError(t, err)
		}

		metrics := wf.Metrics()
		assert.Contains(t, metrics, "executions_total")
		assert.Contains(t, metrics, "executions_success")
		assert.Contains(t, metrics, "active_executions")
		
		executionsTotal, ok := metrics["executions_total"].(int64)
		assert.True(t, ok)
		assert.GreaterOrEqual(t, executionsTotal, int64(3))
	})

	t.Run("ValidateConfig", func(t *testing.T) {
		wf := NewBuiltinWorkflowEngine(framework.PluginConfig{})

		// Valid config
		validConfig := framework.PluginConfig{
			Config: map[string]interface{}{
				"workflows": []interface{}{
					map[string]interface{}{
						"id":   "valid-workflow",
						"name": "Valid Workflow",
						"steps": []interface{}{
							map[string]interface{}{
								"id":   "step1",
								"type": "evaluate",
							},
						},
					},
				},
			},
		}

		result := wf.ValidateConfig(validConfig)
		assert.True(t, result.Valid)
		assert.Empty(t, result.Errors)

		// Invalid config - missing workflows
		invalidConfig := framework.PluginConfig{
			Config: map[string]interface{}{},
		}

		result = wf.ValidateConfig(invalidConfig)
		assert.False(t, result.Valid)
		assert.Contains(t, result.Errors, "workflows configuration is required")

		// Invalid workflow - missing required fields
		invalidWorkflowConfig := framework.PluginConfig{
			Config: map[string]interface{}{
				"workflows": []interface{}{
					map[string]interface{}{
						"name": "Missing ID",
						// Missing id and steps
					},
				},
			},
		}

		result = wf.ValidateConfig(invalidWorkflowConfig)
		assert.False(t, result.Valid)
		assert.NotEmpty(t, result.Errors)
	})

	t.Run("Reload", func(t *testing.T) {
		initialConfig := framework.PluginConfig{
			Name: "reload-test",
			Type: framework.PluginTypeWorkflow,
			Config: map[string]interface{}{
				"workflows": []interface{}{
					map[string]interface{}{
						"id":   "original-workflow",
						"name": "Original Workflow",
						"steps": []interface{}{
							map[string]interface{}{
								"id":   "step1",
								"type": "evaluate",
							},
						},
					},
				},
			},
		}

		wf := NewBuiltinWorkflowEngine(initialConfig)
		ctx := context.Background()

		err := wf.Initialize(ctx, initialConfig)
		require.NoError(t, err)

		// Verify original workflow exists
		assert.Contains(t, wf.(*BuiltinWorkflowEngine).workflows, "original-workflow")

		// Reload with new config
		newConfig := framework.PluginConfig{
			Name: "reload-test",
			Type: framework.PluginTypeWorkflow,
			Config: map[string]interface{}{
				"workflows": []interface{}{
					map[string]interface{}{
						"id":   "new-workflow",
						"name": "New Workflow",
						"steps": []interface{}{
							map[string]interface{}{
								"id":   "new-step",
								"type": "transform",
							},
						},
					},
				},
			},
		}

		err = wf.Reload(ctx, newConfig)
		assert.NoError(t, err)

		// Verify workflows were reloaded
		wfEngine := wf.(*BuiltinWorkflowEngine)
		assert.Contains(t, wfEngine.workflows, "new-workflow")
		assert.NotContains(t, wfEngine.workflows, "original-workflow")
	})

	t.Run("ConcurrentExecution", func(t *testing.T) {
		config := framework.PluginConfig{
			Name: "concurrent-test",
			Type: framework.PluginTypeWorkflow,
			Config: map[string]interface{}{
				"workflows": []interface{}{
					map[string]interface{}{
						"id":   "concurrent-workflow",
						"name": "Concurrent Test",
						"steps": []interface{}{
							map[string]interface{}{
								"id":   "concurrent-step",
								"type": "evaluate",
							},
						},
					},
				},
			},
		}

		wf := NewBuiltinWorkflowEngine(config)
		ctx := context.Background()

		err := wf.Initialize(ctx, config)
		require.NoError(t, err)
		err = wf.Start(ctx)
		require.NoError(t, err)
		defer wf.Stop(ctx)

		// Execute workflows concurrently
		numExecutions := 5
		results := make(chan *framework.WorkflowExecutionResponse, numExecutions)
		errors := make(chan error, numExecutions)

		for i := 0; i < numExecutions; i++ {
			go func(idx int) {
				req := &framework.WorkflowExecutionRequest{
					WorkflowID: "concurrent-workflow",
					Input: map[string]interface{}{
						"index": idx,
					},
				}

				resp, err := wf.(framework.WorkflowEngine).ExecuteWorkflow(ctx, req)
				if err != nil {
					errors <- err
				} else {
					results <- resp
				}
			}(i)
		}

		// Collect results
		successCount := 0
		errorCount := 0

		for i := 0; i < numExecutions; i++ {
			select {
			case resp := <-results:
				assert.NotEmpty(t, resp.ExecutionID)
				successCount++
			case err := <-errors:
				t.Logf("Execution error: %v", err)
				errorCount++
			case <-time.After(10 * time.Second):
				t.Fatal("Test timed out")
			}
		}

		assert.Equal(t, numExecutions, successCount)
		assert.Equal(t, 0, errorCount)
	})
}