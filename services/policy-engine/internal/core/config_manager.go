package core

import (
	"context"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/fsnotify/fsnotify"
	"github.com/Caia-Tech/afdp/services/policy-engine/internal/logging"
	"github.com/Caia-Tech/afdp/services/policy-engine/pkg/framework"
	"gopkg.in/yaml.v3"
)

// ConfigurationManager handles framework configuration
type ConfigurationManager struct {
	logger            *logging.Logger
	mu                sync.RWMutex
	currentConfig     *framework.FrameworkConfig
	configPath        string
	watcher           *fsnotify.Watcher
	changeCallbacks   []framework.ConfigurationChangeCallback
	validationCache   map[string]*ValidationCacheEntry
	environmentConfig map[string]*framework.FrameworkConfig
}

// ValidationCacheEntry caches validation results
type ValidationCacheEntry struct {
	Result    framework.ValidationResult
	Timestamp time.Time
}

// NewConfigurationManager creates a new configuration manager
func NewConfigurationManager(logger *logging.Logger) *ConfigurationManager {
	return &ConfigurationManager{
		logger:            logger,
		validationCache:   make(map[string]*ValidationCacheEntry),
		environmentConfig: make(map[string]*framework.FrameworkConfig),
		changeCallbacks:   make([]framework.ConfigurationChangeCallback, 0),
	}
}

// LoadConfiguration loads configuration from file
func (cm *ConfigurationManager) LoadConfiguration(configPath string) (*framework.FrameworkConfig, error) {
	cm.logger.Info("Loading configuration", "path", configPath)
	
	// Read file
	data, err := ioutil.ReadFile(configPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read config file: %w", err)
	}
	
	// Parse YAML
	var config framework.FrameworkConfig
	if err := yaml.Unmarshal(data, &config); err != nil {
		return nil, fmt.Errorf("failed to parse config: %w", err)
	}
	
	// Apply environment variables
	cm.applyEnvironmentVariables(&config)
	
	// Apply defaults
	cm.applyDefaults(&config)
	
	// Validate configuration
	result := cm.ValidateConfiguration(&config)
	if !result.Valid {
		return nil, fmt.Errorf("configuration validation failed: %v", result.Errors)
	}
	
	// Store configuration
	cm.mu.Lock()
	cm.currentConfig = &config
	cm.configPath = configPath
	cm.mu.Unlock()
	
	cm.logger.Info("Configuration loaded successfully", 
		"version", config.Version,
		"name", config.Name,
	)
	
	return &config, nil
}

// ValidateConfiguration validates a configuration
func (cm *ConfigurationManager) ValidateConfiguration(config *framework.FrameworkConfig) framework.ValidationResult {
	result := framework.ValidationResult{
		Valid:    true,
		Errors:   []framework.ValidationError{},
		Warnings: []framework.ValidationError{},
	}
	
	// Basic validation
	if config.Version == "" {
		result.Valid = false
		result.Errors = append(result.Errors, framework.ValidationError{
			Field:    "version",
			Message:  "version is required",
			Code:     "required_field",
			Severity: "error",
		})
	}
	
	if config.Name == "" {
		result.Valid = false
		result.Errors = append(result.Errors, framework.ValidationError{
			Field:    "name",
			Message:  "name is required",
			Code:     "required_field",
			Severity: "error",
		})
	}
	
	// Validate framework settings
	cm.validateFrameworkConfig(&config.Framework, &result)
	
	// Validate plugins
	cm.validatePlugins(config.Plugins, &result)
	
	// Validate security settings
	cm.validateSecurity(&config.Security, &result)
	
	// Validate storage settings
	cm.validateStorage(&config.Storage, &result)
	
	return result
}

// MergeConfigurations merges multiple configurations
func (cm *ConfigurationManager) MergeConfigurations(base *framework.FrameworkConfig, overrides ...*framework.FrameworkConfig) (*framework.FrameworkConfig, error) {
	// Deep copy base configuration
	merged := cm.deepCopyConfig(base)
	
	// Apply overrides
	for _, override := range overrides {
		cm.mergeConfig(merged, override)
	}
	
	// Validate merged configuration
	result := cm.ValidateConfiguration(merged)
	if !result.Valid {
		return nil, fmt.Errorf("merged configuration is invalid: %v", result.Errors)
	}
	
	return merged, nil
}

// WatchConfiguration watches for configuration changes
func (cm *ConfigurationManager) WatchConfiguration(ctx context.Context, callback framework.ConfigurationChangeCallback) error {
	cm.mu.Lock()
	cm.changeCallbacks = append(cm.changeCallbacks, callback)
	configPath := cm.configPath
	cm.mu.Unlock()
	
	if configPath == "" {
		return fmt.Errorf("no configuration loaded")
	}
	
	// Create file watcher
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		return fmt.Errorf("failed to create watcher: %w", err)
	}
	
	cm.mu.Lock()
	cm.watcher = watcher
	cm.mu.Unlock()
	
	// Watch configuration file
	if err := watcher.Add(configPath); err != nil {
		return fmt.Errorf("failed to watch file: %w", err)
	}
	
	// Start watching
	go cm.watchLoop(ctx)
	
	cm.logger.Info("Configuration watcher started", "path", configPath)
	return nil
}

// ReloadConfiguration reloads the current configuration
func (cm *ConfigurationManager) ReloadConfiguration(ctx context.Context) error {
	cm.mu.RLock()
	configPath := cm.configPath
	oldConfig := cm.currentConfig
	cm.mu.RUnlock()
	
	if configPath == "" {
		return fmt.Errorf("no configuration loaded")
	}
	
	// Load new configuration
	newConfig, err := cm.LoadConfiguration(configPath)
	if err != nil {
		return fmt.Errorf("failed to reload configuration: %w", err)
	}
	
	// Notify callbacks
	for _, callback := range cm.changeCallbacks {
		if err := callback(oldConfig, newConfig); err != nil {
			cm.logger.Error("Configuration change callback failed", "error", err)
			// Rollback
			cm.mu.Lock()
			cm.currentConfig = oldConfig
			cm.mu.Unlock()
			return fmt.Errorf("configuration change callback failed: %w", err)
		}
	}
	
	cm.logger.Info("Configuration reloaded successfully")
	return nil
}

// LoadEnvironmentConfig loads environment-specific configuration
func (cm *ConfigurationManager) LoadEnvironmentConfig(environment string) (*framework.FrameworkConfig, error) {
	// Check cache
	cm.mu.RLock()
	if config, exists := cm.environmentConfig[environment]; exists {
		cm.mu.RUnlock()
		return config, nil
	}
	cm.mu.RUnlock()
	
	// Load base configuration
	baseConfig := cm.GetEffectiveConfiguration()
	
	// Look for environment-specific file
	envConfigPath := fmt.Sprintf("config/%s.yaml", environment)
	if _, err := os.Stat(envConfigPath); err == nil {
		envConfig, err := cm.LoadConfiguration(envConfigPath)
		if err != nil {
			return nil, fmt.Errorf("failed to load environment config: %w", err)
		}
		
		// Merge configurations
		merged, err := cm.MergeConfigurations(baseConfig, envConfig)
		if err != nil {
			return nil, fmt.Errorf("failed to merge configurations: %w", err)
		}
		
		// Cache result
		cm.mu.Lock()
		cm.environmentConfig[environment] = merged
		cm.mu.Unlock()
		
		return merged, nil
	}
	
	// No environment-specific config, use base
	return baseConfig, nil
}

// GetEffectiveConfiguration returns the current configuration
func (cm *ConfigurationManager) GetEffectiveConfiguration() *framework.FrameworkConfig {
	cm.mu.RLock()
	defer cm.mu.RUnlock()
	
	return cm.deepCopyConfig(cm.currentConfig)
}

// LoadTemplate loads a configuration template
func (cm *ConfigurationManager) LoadTemplate(templateName string) (*framework.ConfigurationTemplate, error) {
	templatePath := filepath.Join("templates", templateName + ".yaml")
	
	data, err := ioutil.ReadFile(templatePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read template: %w", err)
	}
	
	var template framework.ConfigurationTemplate
	if err := yaml.Unmarshal(data, &template); err != nil {
		return nil, fmt.Errorf("failed to parse template: %w", err)
	}
	
	return &template, nil
}

// ApplyTemplate applies a template with variables
func (cm *ConfigurationManager) ApplyTemplate(template *framework.ConfigurationTemplate, variables map[string]interface{}) (*framework.FrameworkConfig, error) {
	// This would implement template variable substitution
	// For now, return an error
	return nil, fmt.Errorf("template application not implemented")
}

// Helper methods

func (cm *ConfigurationManager) watchLoop(ctx context.Context) {
	for {
		select {
		case event, ok := <-cm.watcher.Events:
			if !ok {
				return
			}
			
			if event.Op&fsnotify.Write == fsnotify.Write {
				cm.logger.Info("Configuration file changed, reloading...")
				if err := cm.ReloadConfiguration(ctx); err != nil {
					cm.logger.Error("Failed to reload configuration", "error", err)
				}
			}
			
		case err, ok := <-cm.watcher.Errors:
			if !ok {
				return
			}
			cm.logger.Error("Configuration watcher error", "error", err)
			
		case <-ctx.Done():
			cm.watcher.Close()
			return
		}
	}
}

func (cm *ConfigurationManager) applyEnvironmentVariables(config *framework.FrameworkConfig) {
	// Apply environment variable overrides
	if logLevel := os.Getenv("AFDP_LOG_LEVEL"); logLevel != "" {
		config.Framework.Logging.Level = logLevel
	}
	
	if metricsPort := os.Getenv("AFDP_METRICS_PORT"); metricsPort != "" {
		// Parse and set port
	}
	
	// Apply other environment variables as needed
}

func (cm *ConfigurationManager) applyDefaults(config *framework.FrameworkConfig) {
	// Apply default values
	if config.Framework.Logging.Level == "" {
		config.Framework.Logging.Level = "info"
	}
	
	if config.Framework.Logging.Format == "" {
		config.Framework.Logging.Format = "json"
	}
	
	if config.Framework.Metrics.Port == 0 {
		config.Framework.Metrics.Port = 9090
	}
	
	if config.Framework.Health.Port == 0 {
		config.Framework.Health.Port = 8080
	}
	
	// Apply other defaults as needed
}

func (cm *ConfigurationManager) validateFrameworkConfig(config *framework.FrameworkCoreConfig, result *framework.ValidationResult) {
	// Validate logging
	validLogLevels := []string{"debug", "info", "warn", "error"}
	if !contains(validLogLevels, config.Logging.Level) {
		result.Warnings = append(result.Warnings, framework.ValidationError{
			Field:    "framework.logging.level",
			Message:  fmt.Sprintf("invalid log level: %s", config.Logging.Level),
			Code:     "invalid_value",
			Severity: "warning",
		})
	}
	
	// Validate metrics
	if config.Metrics.Enabled && config.Metrics.Port == 0 {
		result.Valid = false
		result.Errors = append(result.Errors, framework.ValidationError{
			Field:    "framework.metrics.port",
			Message:  "metrics port is required when metrics are enabled",
			Code:     "required_field",
			Severity: "error",
		})
	}
}

func (cm *ConfigurationManager) validatePlugins(plugins []framework.PluginConfig, result *framework.ValidationResult) {
	pluginNames := make(map[string]bool)
	
	for i, plugin := range plugins {
		// Check for duplicate names
		if pluginNames[plugin.Name] {
			result.Valid = false
			result.Errors = append(result.Errors, framework.ValidationError{
				Field:    fmt.Sprintf("plugins[%d].name", i),
				Message:  fmt.Sprintf("duplicate plugin name: %s", plugin.Name),
				Code:     "duplicate_value",
				Severity: "error",
			})
		}
		pluginNames[plugin.Name] = true
		
		// Validate plugin configuration
		if plugin.Name == "" {
			result.Valid = false
			result.Errors = append(result.Errors, framework.ValidationError{
				Field:    fmt.Sprintf("plugins[%d].name", i),
				Message:  "plugin name is required",
				Code:     "required_field",
				Severity: "error",
			})
		}
		
		if plugin.Type == "" {
			result.Valid = false
			result.Errors = append(result.Errors, framework.ValidationError{
				Field:    fmt.Sprintf("plugins[%d].type", i),
				Message:  "plugin type is required",
				Code:     "required_field",
				Severity: "error",
			})
		}
	}
}

func (cm *ConfigurationManager) validateSecurity(config *framework.SecurityConfig, result *framework.ValidationResult) {
	// Validate authentication
	if config.Authentication.Primary.Type == "" {
		result.Warnings = append(result.Warnings, framework.ValidationError{
			Field:    "security.authentication.primary.type",
			Message:  "no primary authentication provider configured",
			Code:     "missing_config",
			Severity: "warning",
		})
	}
	
	// Validate authorization
	if config.Authorization.Model == "" {
		config.Authorization.Model = "rbac" // Default
	}
}

func (cm *ConfigurationManager) validateStorage(config *framework.StorageConfig, result *framework.ValidationResult) {
	// Check if at least one storage backend is configured
	hasStorage := false
	
	if config.PostgreSQL.Host != "" {
		hasStorage = true
	}
	if config.Redis.URL != "" {
		hasStorage = true
	}
	if config.S3.Endpoint != "" || config.S3.Bucket != "" {
		hasStorage = true
	}
	
	if !hasStorage {
		result.Warnings = append(result.Warnings, framework.ValidationError{
			Field:    "storage",
			Message:  "no storage backend configured",
			Code:     "missing_config",
			Severity: "warning",
		})
	}
}

func (cm *ConfigurationManager) deepCopyConfig(config *framework.FrameworkConfig) *framework.FrameworkConfig {
	if config == nil {
		return nil
	}
	
	// This is a simplified deep copy - in production, use a proper deep copy library
	data, _ := yaml.Marshal(config)
	var copy framework.FrameworkConfig
	yaml.Unmarshal(data, &copy)
	
	return &copy
}

func (cm *ConfigurationManager) mergeConfig(base, override *framework.FrameworkConfig) {
	// This is a simplified merge - in production, use a proper merge strategy
	if override.Version != "" {
		base.Version = override.Version
	}
	if override.Name != "" {
		base.Name = override.Name
	}
	if override.Description != "" {
		base.Description = override.Description
	}
	
	// Merge other fields as needed
}

func contains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}