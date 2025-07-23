package plugins

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/Caia-Tech/afdp/services/policy-engine/internal/logging"
	"github.com/Caia-Tech/afdp/services/policy-engine/internal/metrics"
	"github.com/Caia-Tech/afdp/services/policy-engine/pkg/framework"
)

// Mock plugin for testing
type mockPlugin struct {
	name     string
	version  string
	pType    framework.PluginType
	status   framework.PluginStatus
	health   framework.HealthStatus
	config   framework.PluginConfig
	started  bool
	stopped  bool
}

func (m *mockPlugin) Name() string                        { return m.name }
func (m *mockPlugin) Version() string                     { return m.version }
func (m *mockPlugin) Type() framework.PluginType          { return m.pType }
func (m *mockPlugin) Metadata() framework.PluginMetadata  { return framework.PluginMetadata{} }
func (m *mockPlugin) Initialize(ctx context.Context, config framework.PluginConfig) error {
	m.config = config
	m.status = framework.PluginStatusInitializing
	return nil
}
func (m *mockPlugin) Start(ctx context.Context) error {
	m.started = true
	m.status = framework.PluginStatusRunning
	return nil
}
func (m *mockPlugin) Stop(ctx context.Context) error {
	m.stopped = true
	m.status = framework.PluginStatusStopped
	return nil
}
func (m *mockPlugin) Reload(ctx context.Context, config framework.PluginConfig) error {
	m.config = config
	return nil
}
func (m *mockPlugin) Health() framework.HealthStatus { return m.health }
func (m *mockPlugin) Metrics() framework.PluginMetrics { return framework.PluginMetrics{} }
func (m *mockPlugin) ValidateConfig(config framework.PluginConfig) framework.ValidationResult {
	return framework.ValidationResult{Valid: true}
}

func TestPluginManager(t *testing.T) {
	logger := logging.NewLogger("debug")
	metricsCollector := metrics.NewCollector(framework.MetricsConfig{})
	
	t.Run("CreateManager", func(t *testing.T) {
		pm := NewManager(logger, metricsCollector)
		assert.NotNil(t, pm)
		assert.NotNil(t, pm.plugins)
		assert.NotNil(t, pm.loaders)
		
		// Check plugin type maps are initialized
		for _, pType := range []framework.PluginType{
			framework.PluginTypeEvaluator,
			framework.PluginTypeDataSource,
			framework.PluginTypeWorkflow,
			framework.PluginTypeSecurity,
		} {
			_, exists := pm.plugins[string(pType)]
			assert.True(t, exists, "Plugin type %s should be initialized", pType)
		}
	})
	
	t.Run("StartStop", func(t *testing.T) {
		pm := NewManager(logger, metricsCollector)
		ctx := context.Background()
		
		// Start manager
		err := pm.Start(ctx)
		assert.NoError(t, err)
		
		// Try to start again
		err = pm.Start(ctx)
		assert.Error(t, err)
		
		// Stop manager
		err = pm.Stop(ctx)
		assert.NoError(t, err)
		
		// Try to stop again
		err = pm.Stop(ctx)
		assert.Error(t, err)
	})
	
	t.Run("RegisterPlugin", func(t *testing.T) {
		pm := NewManager(logger, metricsCollector)
		
		plugin := &mockPlugin{
			name:    "test-plugin",
			version: "1.0.0",
			pType:   framework.PluginTypeEvaluator,
			health:  framework.HealthStatus{Status: "healthy"},
		}
		
		// Register plugin
		err := pm.RegisterPlugin(string(framework.PluginTypeEvaluator), "test-plugin", plugin)
		assert.NoError(t, err)
		
		// Try to register again
		err = pm.RegisterPlugin(string(framework.PluginTypeEvaluator), "test-plugin", plugin)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "already registered")
		
		// Register with unknown type
		err = pm.RegisterPlugin("unknown-type", "test-plugin", plugin)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "unknown plugin type")
	})
	
	t.Run("GetPlugin", func(t *testing.T) {
		pm := NewManager(logger, metricsCollector)
		
		plugin := &mockPlugin{
			name:    "test-plugin",
			version: "1.0.0",
			pType:   framework.PluginTypeEvaluator,
		}
		
		err := pm.RegisterPlugin(string(framework.PluginTypeEvaluator), "test-plugin", plugin)
		require.NoError(t, err)
		
		// Get existing plugin
		retrieved, err := pm.GetPlugin(string(framework.PluginTypeEvaluator), "test-plugin")
		assert.NoError(t, err)
		assert.Equal(t, plugin, retrieved)
		
		// Get non-existent plugin
		_, err = pm.GetPlugin(string(framework.PluginTypeEvaluator), "non-existent")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "not found")
		
		// Get from unknown type
		_, err = pm.GetPlugin("unknown-type", "test-plugin")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "unknown plugin type")
	})
	
	t.Run("UnregisterPlugin", func(t *testing.T) {
		pm := NewManager(logger, metricsCollector)
		ctx := context.Background()
		
		plugin := &mockPlugin{
			name:    "test-plugin",
			version: "1.0.0",
			pType:   framework.PluginTypeEvaluator,
			health:  framework.HealthStatus{Status: "healthy"},
		}
		
		err := pm.RegisterPlugin(string(framework.PluginTypeEvaluator), "test-plugin", plugin)
		require.NoError(t, err)
		
		// Start the plugin
		err = plugin.Start(ctx)
		require.NoError(t, err)
		
		// Unregister plugin
		err = pm.UnregisterPlugin(string(framework.PluginTypeEvaluator), "test-plugin")
		assert.NoError(t, err)
		
		// Verify plugin was stopped
		assert.True(t, plugin.stopped)
		
		// Try to get unregistered plugin
		_, err = pm.GetPlugin(string(framework.PluginTypeEvaluator), "test-plugin")
		assert.Error(t, err)
		
		// Try to unregister again
		err = pm.UnregisterPlugin(string(framework.PluginTypeEvaluator), "test-plugin")
		assert.Error(t, err)
	})
	
	t.Run("ListPlugins", func(t *testing.T) {
		pm := NewManager(logger, metricsCollector)
		
		// Register multiple plugins
		plugins := []*mockPlugin{
			{
				name:  "eval1",
				pType: framework.PluginTypeEvaluator,
			},
			{
				name:  "eval2",
				pType: framework.PluginTypeEvaluator,
			},
			{
				name:  "ds1",
				pType: framework.PluginTypeDataSource,
			},
		}
		
		for _, p := range plugins {
			err := pm.RegisterPlugin(string(p.pType), p.name, p)
			require.NoError(t, err)
		}
		
		// List all plugins
		allPlugins := pm.ListPlugins()
		assert.Len(t, allPlugins, 3)
		
		// List by type
		evaluators := pm.ListPluginsByType(string(framework.PluginTypeEvaluator))
		assert.Len(t, evaluators, 2)
		
		dataSources := pm.ListPluginsByType(string(framework.PluginTypeDataSource))
		assert.Len(t, dataSources, 1)
		
		// List unknown type
		unknown := pm.ListPluginsByType("unknown-type")
		assert.Len(t, unknown, 0)
	})
	
	t.Run("Health", func(t *testing.T) {
		pm := NewManager(logger, metricsCollector)
		
		// Register healthy and unhealthy plugins
		healthyPlugin := &mockPlugin{
			name:   "healthy",
			pType:  framework.PluginTypeEvaluator,
			health: framework.HealthStatus{Status: "healthy"},
		}
		
		unhealthyPlugin := &mockPlugin{
			name:   "unhealthy",
			pType:  framework.PluginTypeEvaluator,
			health: framework.HealthStatus{Status: "unhealthy", Message: "test error"},
		}
		
		err := pm.RegisterPlugin(string(framework.PluginTypeEvaluator), "healthy", healthyPlugin)
		require.NoError(t, err)
		
		err = pm.RegisterPlugin(string(framework.PluginTypeEvaluator), "unhealthy", unhealthyPlugin)
		require.NoError(t, err)
		
		// Check manager health
		health := pm.Health()
		assert.Equal(t, "degraded", health.Status)
		assert.Contains(t, health.Message, "1/2 plugins healthy")
		
		metadata, ok := health.Metadata["unhealthy_plugins"].([]string)
		assert.True(t, ok)
		assert.Contains(t, metadata, "evaluator/unhealthy")
	})
	
	t.Run("LoadPlugin", func(t *testing.T) {
		pm := NewManager(logger, metricsCollector)
		ctx := context.Background()
		
		// Test loading a built-in plugin
		config := framework.PluginConfig{
			Name:    "test-rego",
			Type:    framework.PluginTypeEvaluator,
			Enabled: true,
			Source: framework.PluginSource{
				Type:     "local",
				Location: "builtin:rego",
			},
			Config: map[string]interface{}{
				"data": map[string]interface{}{
					"test": "data",
				},
			},
		}
		
		plugin, err := pm.LoadPlugin(ctx, config)
		assert.NoError(t, err)
		assert.NotNil(t, plugin)
		assert.Equal(t, "test-rego", plugin.Name())
		assert.Equal(t, framework.PluginTypeEvaluator, plugin.Type())
	})
	
	t.Run("ReloadPlugin", func(t *testing.T) {
		pm := NewManager(logger, metricsCollector)
		ctx := context.Background()
		
		plugin := &mockPlugin{
			name:    "reload-test",
			version: "1.0.0",
			pType:   framework.PluginTypeEvaluator,
			config: framework.PluginConfig{
				Config: map[string]interface{}{
					"value": "original",
				},
			},
		}
		
		err := pm.RegisterPlugin(string(framework.PluginTypeEvaluator), "reload-test", plugin)
		require.NoError(t, err)
		
		// Reload with new config
		newConfig := framework.PluginConfig{
			Config: map[string]interface{}{
				"value": "updated",
			},
		}
		
		err = pm.ReloadPlugin(ctx, string(framework.PluginTypeEvaluator), "reload-test", newConfig)
		assert.NoError(t, err)
		
		// Verify config was updated
		assert.Equal(t, "updated", plugin.config.Config["value"])
	})
}

func TestPluginValidation(t *testing.T) {
	logger := logging.NewLogger("debug")
	pm := NewManager(logger, metrics.NewCollector(framework.MetricsConfig{}))
	
	t.Run("ValidateEvaluatorPlugin", func(t *testing.T) {
		// Create a plugin that implements PolicyEvaluator
		evaluator := NewBuiltinRegoEvaluator(framework.PluginConfig{
			Name: "test-evaluator",
			Type: framework.PluginTypeEvaluator,
		})
		
		plugin, err := evaluator
		require.NoError(t, err)
		
		// Validation should pass
		err = pm.validatePlugin(plugin, framework.PluginConfig{
			Type: framework.PluginTypeEvaluator,
		})
		assert.NoError(t, err)
		
		// Wrong type should fail
		err = pm.validatePlugin(plugin, framework.PluginConfig{
			Type: framework.PluginTypeDataSource,
		})
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "does not implement DataSource interface")
	})
}

func TestPluginLifecycle(t *testing.T) {
	logger := logging.NewLogger("debug")
	pm := NewManager(logger, metrics.NewCollector(framework.MetricsConfig{}))
	ctx := context.Background()
	
	t.Run("FullLifecycle", func(t *testing.T) {
		// Start manager
		err := pm.Start(ctx)
		require.NoError(t, err)
		
		// Load plugin
		config := framework.PluginConfig{
			Name:    "lifecycle-test",
			Type:    framework.PluginTypeEvaluator,
			Enabled: true,
			Source: framework.PluginSource{
				Type:     "local",
				Location: "builtin:rego",
			},
		}
		
		plugin, err := pm.LoadPlugin(ctx, config)
		require.NoError(t, err)
		
		// Register plugin
		err = pm.RegisterPlugin(string(config.Type), config.Name, plugin)
		require.NoError(t, err)
		
		// Start plugin
		err = plugin.Start(ctx)
		assert.NoError(t, err)
		
		// Check health
		health := plugin.Health()
		assert.Equal(t, "healthy", health.Status)
		
		// Stop plugin
		err = plugin.Stop(ctx)
		assert.NoError(t, err)
		
		// Unregister plugin
		err = pm.UnregisterPlugin(string(config.Type), config.Name)
		assert.NoError(t, err)
		
		// Stop manager
		err = pm.Stop(ctx)
		assert.NoError(t, err)
	})
}

func TestPluginMonitoring(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping monitoring test in short mode")
	}
	
	logger := logging.NewLogger("debug")
	metricsCollector := metrics.NewCollector(framework.MetricsConfig{})
	pm := NewManager(logger, metricsCollector)
	ctx := context.Background()
	
	t.Run("HealthMonitoring", func(t *testing.T) {
		// Create a plugin that changes health status
		plugin := &mockPlugin{
			name:   "monitor-test",
			pType:  framework.PluginTypeEvaluator,
			health: framework.HealthStatus{Status: "healthy"},
		}
		
		err := pm.RegisterPlugin(string(framework.PluginTypeEvaluator), "monitor-test", plugin)
		require.NoError(t, err)
		
		// Start manager (which starts monitoring)
		err = pm.Start(ctx)
		require.NoError(t, err)
		defer pm.Stop(ctx)
		
		// Wait for initial health check
		time.Sleep(100 * time.Millisecond)
		
		// Change plugin health
		plugin.health = framework.HealthStatus{
			Status:  "unhealthy",
			Message: "simulated failure",
		}
		
		// Trigger health check
		pm.checkPluginHealth()
		
		// Verify manager detects unhealthy plugin
		health := pm.Health()
		assert.Equal(t, "degraded", health.Status)
	})
}