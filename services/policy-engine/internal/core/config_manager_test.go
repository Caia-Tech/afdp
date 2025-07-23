package core

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/Caia-Tech/afdp/services/policy-engine/internal/logging"
	"github.com/Caia-Tech/afdp/services/policy-engine/pkg/framework"
)

const testConfigYAML = `
version: "1.0.0"
name: "Test Policy Framework"
description: "Test configuration"

framework:
  logging:
    level: "info"
    format: "json"
    output: "stdout"
  
  metrics:
    enabled: true
    port: 9090
    path: "/metrics"
    namespace: "test"

api:
  rest:
    enabled: true
    host: "localhost"
    port: 8080

plugins:
  - name: "test-plugin"
    type: "evaluator"
    enabled: true
    source:
      type: "local"
      location: "builtin:rego"
    config:
      test_value: "test"

security:
  authentication:
    primary:
      type: "jwt"
      config:
        issuer: "test"
        audience: "test-api"

dynamic_config:
  hot_reload:
    enabled: true
    interval: "10s"
`

const updatedConfigYAML = `
version: "1.1.0"
name: "Updated Test Policy Framework"
description: "Updated test configuration"

framework:
  logging:
    level: "debug"
    format: "text"
    output: "stdout"
  
  metrics:
    enabled: true
    port: 9091
    path: "/metrics"
    namespace: "test_updated"

api:
  rest:
    enabled: true
    host: "localhost"
    port: 8081

plugins:
  - name: "test-plugin"
    type: "evaluator"
    enabled: true
    source:
      type: "local"
      location: "builtin:rego"
    config:
      test_value: "updated_test"
  - name: "new-plugin"
    type: "data_source"
    enabled: true
    source:
      type: "local"
      location: "builtin:postgres"

security:
  authentication:
    primary:
      type: "jwt"
      config:
        issuer: "test_updated"
        audience: "test-api-updated"

dynamic_config:
  hot_reload:
    enabled: true
    interval: "5s"
`

func TestConfigurationManager(t *testing.T) {
	logger := logging.NewLogger("debug")

	t.Run("CreateManager", func(t *testing.T) {
		cm := NewConfigurationManager(logger)
		assert.NotNil(t, cm)
		assert.Equal(t, logger, cm.logger)
		assert.NotNil(t, cm.watchers)
	})

	t.Run("LoadConfiguration", func(t *testing.T) {
		// Create temporary config file
		tmpDir, err := os.MkdirTemp("", "config_test")
		require.NoError(t, err)
		defer os.RemoveAll(tmpDir)

		configPath := filepath.Join(tmpDir, "test_config.yaml")
		err = os.WriteFile(configPath, []byte(testConfigYAML), 0644)
		require.NoError(t, err)

		cm := NewConfigurationManager(logger)
		config, err := cm.LoadConfiguration(configPath)
		
		assert.NoError(t, err)
		assert.NotNil(t, config)
		assert.Equal(t, "1.0.0", config.Version)
		assert.Equal(t, "Test Policy Framework", config.Name)
		assert.Equal(t, "Test configuration", config.Description)
		
		// Check framework config
		assert.Equal(t, "info", config.Framework.Logging.Level)
		assert.Equal(t, "json", config.Framework.Logging.Format)
		assert.True(t, config.Framework.Metrics.Enabled)
		assert.Equal(t, 9090, config.Framework.Metrics.Port)
		
		// Check API config
		assert.True(t, config.API.REST.Enabled)
		assert.Equal(t, "localhost", config.API.REST.Host)
		assert.Equal(t, 8080, config.API.REST.Port)
		
		// Check plugins
		assert.Len(t, config.Plugins, 1)
		assert.Equal(t, "test-plugin", config.Plugins[0].Name)
		assert.Equal(t, framework.PluginTypeEvaluator, config.Plugins[0].Type)
		assert.True(t, config.Plugins[0].Enabled)
		
		// Check security
		assert.Equal(t, "jwt", config.Security.Authentication.Primary.Type)
		assert.Equal(t, "test", config.Security.Authentication.Primary.Config["issuer"])
		
		// Check dynamic config
		assert.True(t, config.DynamicConfig.HotReload.Enabled)
		assert.Equal(t, 10*time.Second, config.DynamicConfig.HotReload.Interval)
	})

	t.Run("LoadNonExistentFile", func(t *testing.T) {
		cm := NewConfigurationManager(logger)
		_, err := cm.LoadConfiguration("/path/that/does/not/exist.yaml")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "failed to read config file")
	})

	t.Run("LoadInvalidYAML", func(t *testing.T) {
		tmpDir, err := os.MkdirTemp("", "config_test")
		require.NoError(t, err)
		defer os.RemoveAll(tmpDir)

		configPath := filepath.Join(tmpDir, "invalid_config.yaml")
		err = os.WriteFile(configPath, []byte("invalid: yaml: content: ["), 0644)
		require.NoError(t, err)

		cm := NewConfigurationManager(logger)
		_, err = cm.LoadConfiguration(configPath)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "failed to parse config file")
	})

	t.Run("ValidateConfiguration", func(t *testing.T) {
		tmpDir, err := os.MkdirTemp("", "config_test")
		require.NoError(t, err)
		defer os.RemoveAll(tmpDir)

		configPath := filepath.Join(tmpDir, "test_config.yaml")
		err = os.WriteFile(configPath, []byte(testConfigYAML), 0644)
		require.NoError(t, err)

		cm := NewConfigurationManager(logger)
		config, err := cm.LoadConfiguration(configPath)
		require.NoError(t, err)

		// Valid configuration
		result := cm.ValidateConfiguration(config)
		assert.True(t, result.Valid)
		assert.Empty(t, result.Errors)

		// Invalid configuration - missing version
		config.Version = ""
		result = cm.ValidateConfiguration(config)
		assert.False(t, result.Valid)
		assert.Contains(t, result.Errors, "version is required")

		// Invalid configuration - invalid plugin type
		config.Version = "1.0.0"
		config.Plugins[0].Type = "invalid_type"
		result = cm.ValidateConfiguration(config)
		assert.False(t, result.Valid)
		assert.Len(t, result.Errors, 1)
	})

	t.Run("ReloadConfiguration", func(t *testing.T) {
		tmpDir, err := os.MkdirTemp("", "config_test")
		require.NoError(t, err)
		defer os.RemoveAll(tmpDir)

		configPath := filepath.Join(tmpDir, "reload_test_config.yaml")
		err = os.WriteFile(configPath, []byte(testConfigYAML), 0644)
		require.NoError(t, err)

		cm := NewConfigurationManager(logger)
		
		// Load initial config
		config, err := cm.LoadConfiguration(configPath)
		require.NoError(t, err)
		assert.Equal(t, "1.0.0", config.Version)

		// Update config file
		err = os.WriteFile(configPath, []byte(updatedConfigYAML), 0644)
		require.NoError(t, err)

		// Reload config
		ctx := context.Background()
		newConfig, err := cm.ReloadConfiguration(ctx)
		assert.NoError(t, err)
		assert.NotNil(t, newConfig)
		assert.Equal(t, "1.1.0", newConfig.Version)
		assert.Equal(t, "Updated Test Policy Framework", newConfig.Name)
		assert.Equal(t, "debug", newConfig.Framework.Logging.Level)
		assert.Equal(t, 9091, newConfig.Framework.Metrics.Port)
		assert.Len(t, newConfig.Plugins, 2)
	})

	t.Run("StartStopWatching", func(t *testing.T) {
		tmpDir, err := os.MkdirTemp("", "config_test")
		require.NoError(t, err)
		defer os.RemoveAll(tmpDir)

		configPath := filepath.Join(tmpDir, "watch_test_config.yaml")
		err = os.WriteFile(configPath, []byte(testConfigYAML), 0644)
		require.NoError(t, err)

		cm := NewConfigurationManager(logger)
		
		// Load config
		_, err = cm.LoadConfiguration(configPath)
		require.NoError(t, err)

		ctx := context.Background()

		// Start watching
		err = cm.StartWatching(ctx)
		assert.NoError(t, err)

		// Try to start again
		err = cm.StartWatching(ctx)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "already watching")

		// Stop watching
		err = cm.StopWatching()
		assert.NoError(t, err)

		// Try to stop again
		err = cm.StopWatching()
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "not watching")
	})

	t.Run("AddConfigChangeHandler", func(t *testing.T) {
		tmpDir, err := os.MkdirTemp("", "config_test")
		require.NoError(t, err)
		defer os.RemoveAll(tmpDir)

		configPath := filepath.Join(tmpDir, "handler_test_config.yaml")
		err = os.WriteFile(configPath, []byte(testConfigYAML), 0644)
		require.NoError(t, err)

		cm := NewConfigurationManager(logger)
		
		// Load config
		_, err = cm.LoadConfiguration(configPath)
		require.NoError(t, err)

		// Add handler
		handlerCalled := false
		var receivedConfig *framework.FrameworkConfig
		
		handler := func(ctx context.Context, oldConfig, newConfig *framework.FrameworkConfig) error {
			handlerCalled = true
			receivedConfig = newConfig
			return nil
		}

		cm.AddConfigChangeHandler("test-handler", handler)

		// Verify handler was added
		assert.Contains(t, cm.changeHandlers, "test-handler")

		// Trigger config change manually
		ctx := context.Background()
		err = os.WriteFile(configPath, []byte(updatedConfigYAML), 0644)
		require.NoError(t, err)

		newConfig, err := cm.ReloadConfiguration(ctx)
		require.NoError(t, err)

		// Wait a bit for handler to be called
		time.Sleep(100 * time.Millisecond)

		assert.True(t, handlerCalled)
		assert.NotNil(t, receivedConfig)
		assert.Equal(t, "1.1.0", receivedConfig.Version)
	})

	t.Run("RemoveConfigChangeHandler", func(t *testing.T) {
		cm := NewConfigurationManager(logger)

		handler := func(ctx context.Context, oldConfig, newConfig *framework.FrameworkConfig) error {
			return nil
		}

		// Add handler
		cm.AddConfigChangeHandler("remove-test", handler)
		assert.Contains(t, cm.changeHandlers, "remove-test")

		// Remove handler
		cm.RemoveConfigChangeHandler("remove-test")
		assert.NotContains(t, cm.changeHandlers, "remove-test")

		// Remove non-existent handler (should not panic)
		cm.RemoveConfigChangeHandler("non-existent")
	})

	t.Run("GetCurrentConfiguration", func(t *testing.T) {
		tmpDir, err := os.MkdirTemp("", "config_test")
		require.NoError(t, err)
		defer os.RemoveAll(tmpDir)

		configPath := filepath.Join(tmpDir, "current_config.yaml")
		err = os.WriteFile(configPath, []byte(testConfigYAML), 0644)
		require.NoError(t, err)

		cm := NewConfigurationManager(logger)

		// No config loaded yet
		config := cm.GetCurrentConfiguration()
		assert.Nil(t, config)

		// Load config
		loadedConfig, err := cm.LoadConfiguration(configPath)
		require.NoError(t, err)

		// Get current config
		config = cm.GetCurrentConfiguration()
		assert.NotNil(t, config)
		assert.Equal(t, loadedConfig.Version, config.Version)
		assert.Equal(t, loadedConfig.Name, config.Name)
	})

	t.Run("ConfigurationHistory", func(t *testing.T) {
		tmpDir, err := os.MkdirTemp("", "config_test")
		require.NoError(t, err)
		defer os.RemoveAll(tmpDir)

		configPath := filepath.Join(tmpDir, "history_config.yaml")
		err = os.WriteFile(configPath, []byte(testConfigYAML), 0644)
		require.NoError(t, err)

		cm := NewConfigurationManager(logger)

		// Load initial config
		_, err = cm.LoadConfiguration(configPath)
		require.NoError(t, err)

		// Get initial history
		history := cm.GetConfigurationHistory()
		assert.Len(t, history, 1)
		assert.Equal(t, "1.0.0", history[0].Version)

		// Reload with updated config
		err = os.WriteFile(configPath, []byte(updatedConfigYAML), 0644)
		require.NoError(t, err)

		ctx := context.Background()
		_, err = cm.ReloadConfiguration(ctx)
		require.NoError(t, err)

		// Check history
		history = cm.GetConfigurationHistory()
		assert.Len(t, history, 2)
		assert.Equal(t, "1.0.0", history[0].Version) // Oldest first
		assert.Equal(t, "1.1.0", history[1].Version) // Newest last

		// Load more configs to test history limit
		for i := 2; i < 12; i++ {
			configContent := testConfigYAML
			configContent = fmt.Sprintf("version: \"1.%d.0\"\n%s", i, configContent[20:])
			
			err = os.WriteFile(configPath, []byte(configContent), 0644)
			require.NoError(t, err)
			
			_, err = cm.ReloadConfiguration(ctx)
			require.NoError(t, err)
		}

		// History should be limited to 10 entries
		history = cm.GetConfigurationHistory()
		assert.LessOrEqual(t, len(history), 10)
	})

	t.Run("MergeConfigurations", func(t *testing.T) {
		cm := NewConfigurationManager(logger)

		base := &framework.FrameworkConfig{
			Version: "1.0.0",
			Name:    "Base Config",
			Framework: framework.FrameworkCoreConfig{
				Logging: framework.LoggingConfig{
					Level:  "info",
					Format: "json",
				},
				Metrics: framework.MetricsConfig{
					Enabled: true,
					Port:    9090,
				},
			},
			Plugins: []framework.PluginConfig{
				{
					Name:    "plugin1",
					Type:    framework.PluginTypeEvaluator,
					Enabled: true,
				},
			},
		}

		override := &framework.FrameworkConfig{
			Framework: framework.FrameworkCoreConfig{
				Logging: framework.LoggingConfig{
					Level: "debug", // Override
				},
				Metrics: framework.MetricsConfig{
					Port: 9091, // Override
				},
			},
			Plugins: []framework.PluginConfig{
				{
					Name:    "plugin2",
					Type:    framework.PluginTypeDataSource,
					Enabled: true,
				},
			},
		}

		merged := cm.MergeConfigurations(base, override)

		// Base values should be preserved where not overridden
		assert.Equal(t, "1.0.0", merged.Version)
		assert.Equal(t, "Base Config", merged.Name)
		assert.True(t, merged.Framework.Metrics.Enabled)

		// Override values should take precedence
		assert.Equal(t, "debug", merged.Framework.Logging.Level)
		assert.Equal(t, 9091, merged.Framework.Metrics.Port)

		// JSON format should be preserved from base
		assert.Equal(t, "json", merged.Framework.Logging.Format)

		// Plugins should be combined
		assert.Len(t, merged.Plugins, 2)
		pluginNames := []string{merged.Plugins[0].Name, merged.Plugins[1].Name}
		assert.Contains(t, pluginNames, "plugin1")
		assert.Contains(t, pluginNames, "plugin2")
	})
}

func TestConfigurationWatching(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping file watching test in short mode")
	}

	logger := logging.NewLogger("debug")
	
	tmpDir, err := os.MkdirTemp("", "config_watch_test")
	require.NoError(t, err)
	defer os.RemoveAll(tmpDir)

	configPath := filepath.Join(tmpDir, "watch_config.yaml")
	err = os.WriteFile(configPath, []byte(testConfigYAML), 0644)
	require.NoError(t, err)

	cm := NewConfigurationManager(logger)
	
	// Load config
	_, err = cm.LoadConfiguration(configPath)
	require.NoError(t, err)

	// Add change handler
	changeDetected := make(chan bool, 1)
	var newConfigVersion string
	
	handler := func(ctx context.Context, oldConfig, newConfig *framework.FrameworkConfig) error {
		newConfigVersion = newConfig.Version
		changeDetected <- true
		return nil
	}
	
	cm.AddConfigChangeHandler("watch-test", handler)

	// Start watching
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	
	err = cm.StartWatching(ctx)
	require.NoError(t, err)
	defer cm.StopWatching()

	// Wait a bit for watcher to initialize
	time.Sleep(500 * time.Millisecond)

	// Update config file
	err = os.WriteFile(configPath, []byte(updatedConfigYAML), 0644)
	require.NoError(t, err)

	// Wait for change detection
	select {
	case <-changeDetected:
		assert.Equal(t, "1.1.0", newConfigVersion)
	case <-time.After(5 * time.Second):
		t.Fatal("Config change was not detected within timeout")
	}
}