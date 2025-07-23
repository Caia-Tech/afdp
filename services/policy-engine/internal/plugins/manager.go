package plugins

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/Caia-Tech/afdp/services/policy-engine/internal/logging"
	"github.com/Caia-Tech/afdp/services/policy-engine/internal/metrics"
	"github.com/Caia-Tech/afdp/services/policy-engine/pkg/framework"
)

// Manager manages the lifecycle of plugins
type Manager struct {
	logger   *logging.Logger
	metrics  *metrics.Collector
	mu       sync.RWMutex
	plugins  map[string]map[string]framework.Plugin // type -> name -> plugin
	loaders  map[string]PluginLoader
	sandbox  *PluginSandbox
	running  bool
}

// PluginLoader interface for loading plugins
type PluginLoader interface {
	LoadPlugin(ctx context.Context, config framework.PluginConfig) (framework.Plugin, error)
	UnloadPlugin(ctx context.Context, plugin framework.Plugin) error
	SupportedTypes() []framework.PluginSource
}

// NewManager creates a new plugin manager
func NewManager(logger *logging.Logger, metrics *metrics.Collector) *Manager {
	pm := &Manager{
		logger:  logger,
		metrics: metrics,
		plugins: make(map[string]map[string]framework.Plugin),
		loaders: make(map[string]PluginLoader),
		sandbox: NewPluginSandbox(logger),
	}
	
	// Initialize plugin type maps
	pluginTypes := []framework.PluginType{
		framework.PluginTypeEvaluator,
		framework.PluginTypeDataSource,
		framework.PluginTypeWorkflow,
		framework.PluginTypeSecurity,
		framework.PluginTypeAudit,
		framework.PluginTypeStorage,
		framework.PluginTypeNotification,
		framework.PluginTypeMonitoring,
	}
	
	for _, pt := range pluginTypes {
		pm.plugins[string(pt)] = make(map[string]framework.Plugin)
	}
	
	// Register default loaders
	pm.registerDefaultLoaders()
	
	return pm
}

// Start begins plugin manager operation
func (pm *Manager) Start(ctx context.Context) error {
	pm.mu.Lock()
	defer pm.mu.Unlock()
	
	if pm.running {
		return fmt.Errorf("plugin manager already running")
	}
	
	pm.logger.Info("Starting plugin manager...")
	pm.running = true
	
	// Start plugin monitoring
	go pm.monitorPlugins(ctx)
	
	return nil
}

// Stop shuts down the plugin manager
func (pm *Manager) Stop(ctx context.Context) error {
	pm.mu.Lock()
	defer pm.mu.Unlock()
	
	if !pm.running {
		return fmt.Errorf("plugin manager not running")
	}
	
	pm.logger.Info("Stopping plugin manager...")
	pm.running = false
	
	// Stop all plugins
	for pluginType, plugins := range pm.plugins {
		for name, plugin := range plugins {
			pm.logger.Info("Stopping plugin", "type", pluginType, "name", name)
			if err := plugin.Stop(ctx); err != nil {
				pm.logger.Error("Failed to stop plugin", 
					"type", pluginType, 
					"name", name, 
					"error", err,
				)
			}
		}
	}
	
	return nil
}

// LoadPlugin loads a plugin from configuration
func (pm *Manager) LoadPlugin(ctx context.Context, config framework.PluginConfig) (framework.Plugin, error) {
	pm.logger.Info("Loading plugin", 
		"name", config.Name,
		"type", config.Type,
		"source", config.Source.Type,
	)
	
	// Get appropriate loader
	loader, exists := pm.loaders[config.Source.Type]
	if !exists {
		return nil, fmt.Errorf("no loader for source type: %s", config.Source.Type)
	}
	
	// Load plugin
	plugin, err := loader.LoadPlugin(ctx, config)
	if err != nil {
		return nil, fmt.Errorf("failed to load plugin: %w", err)
	}
	
	// Validate plugin
	if err := pm.validatePlugin(plugin, config); err != nil {
		return nil, fmt.Errorf("plugin validation failed: %w", err)
	}
	
	// Apply security sandbox
	if err := pm.sandbox.ApplySandbox(plugin, config.Security); err != nil {
		return nil, fmt.Errorf("failed to apply sandbox: %w", err)
	}
	
	// Initialize plugin
	if err := plugin.Initialize(ctx, config); err != nil {
		return nil, fmt.Errorf("plugin initialization failed: %w", err)
	}
	
	pm.metrics.RecordPluginLoad(string(config.Type), config.Name)
	
	return plugin, nil
}

// RegisterPlugin registers a plugin with the manager
func (pm *Manager) RegisterPlugin(pluginType string, name string, plugin framework.Plugin) error {
	pm.mu.Lock()
	defer pm.mu.Unlock()
	
	// Check if plugin type exists
	typeMap, exists := pm.plugins[pluginType]
	if !exists {
		return fmt.Errorf("unknown plugin type: %s", pluginType)
	}
	
	// Check for existing plugin
	if _, exists := typeMap[name]; exists {
		return fmt.Errorf("plugin already registered: %s/%s", pluginType, name)
	}
	
	// Register plugin
	typeMap[name] = plugin
	
	pm.logger.Info("Plugin registered", 
		"type", pluginType,
		"name", name,
		"version", plugin.Version(),
	)
	
	return nil
}

// UnregisterPlugin removes a plugin from the manager
func (pm *Manager) UnregisterPlugin(pluginType string, name string) error {
	pm.mu.Lock()
	defer pm.mu.Unlock()
	
	// Check if plugin type exists
	typeMap, exists := pm.plugins[pluginType]
	if !exists {
		return fmt.Errorf("unknown plugin type: %s", pluginType)
	}
	
	// Check if plugin exists
	plugin, exists := typeMap[name]
	if !exists {
		return fmt.Errorf("plugin not found: %s/%s", pluginType, name)
	}
	
	// Remove from registry
	delete(typeMap, name)
	
	// Get loader for cleanup
	if metadata := plugin.Metadata(); metadata.Metadata != nil {
		if sourceType, ok := metadata.Metadata["source_type"].(string); ok {
			if loader, exists := pm.loaders[sourceType]; exists {
				if err := loader.UnloadPlugin(context.Background(), plugin); err != nil {
					pm.logger.Error("Failed to unload plugin", "error", err)
				}
			}
		}
	}
	
	pm.logger.Info("Plugin unregistered", 
		"type", pluginType,
		"name", name,
	)
	
	pm.metrics.RecordPluginUnload(pluginType, name)
	
	return nil
}

// GetPlugin retrieves a plugin by type and name
func (pm *Manager) GetPlugin(pluginType string, name string) (framework.Plugin, error) {
	pm.mu.RLock()
	defer pm.mu.RUnlock()
	
	typeMap, exists := pm.plugins[pluginType]
	if !exists {
		return nil, fmt.Errorf("unknown plugin type: %s", pluginType)
	}
	
	plugin, exists := typeMap[name]
	if !exists {
		return nil, fmt.Errorf("plugin not found: %s/%s", pluginType, name)
	}
	
	return plugin, nil
}

// ListPlugins returns all loaded plugins
func (pm *Manager) ListPlugins() []framework.Plugin {
	pm.mu.RLock()
	defer pm.mu.RUnlock()
	
	var plugins []framework.Plugin
	for _, typeMap := range pm.plugins {
		for _, plugin := range typeMap {
			plugins = append(plugins, plugin)
		}
	}
	
	return plugins
}

// ListPluginsByType returns plugins of a specific type
func (pm *Manager) ListPluginsByType(pluginType string) []framework.Plugin {
	pm.mu.RLock()
	defer pm.mu.RUnlock()
	
	typeMap, exists := pm.plugins[pluginType]
	if !exists {
		return []framework.Plugin{}
	}
	
	plugins := make([]framework.Plugin, 0, len(typeMap))
	for _, plugin := range typeMap {
		plugins = append(plugins, plugin)
	}
	
	return plugins
}

// Health returns the health status of the plugin manager
func (pm *Manager) Health() framework.HealthStatus {
	pm.mu.RLock()
	defer pm.mu.RUnlock()
	
	totalPlugins := 0
	healthyPlugins := 0
	unhealthyPlugins := []string{}
	
	for pluginType, typeMap := range pm.plugins {
		for name, plugin := range typeMap {
			totalPlugins++
			health := plugin.Health()
			if health.Status == "healthy" {
				healthyPlugins++
			} else {
				unhealthyPlugins = append(unhealthyPlugins, fmt.Sprintf("%s/%s", pluginType, name))
			}
		}
	}
	
	status := "healthy"
	message := fmt.Sprintf("%d/%d plugins healthy", healthyPlugins, totalPlugins)
	
	if len(unhealthyPlugins) > 0 {
		if healthyPlugins == 0 {
			status = "unhealthy"
		} else {
			status = "degraded"
		}
		message = fmt.Sprintf("%s, unhealthy: %v", message, unhealthyPlugins)
	}
	
	return framework.HealthStatus{
		Status:  status,
		Message: message,
		Metadata: map[string]interface{}{
			"total_plugins":     totalPlugins,
			"healthy_plugins":   healthyPlugins,
			"unhealthy_plugins": unhealthyPlugins,
		},
	}
}

// monitorPlugins monitors plugin health
func (pm *Manager) monitorPlugins(ctx context.Context) {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	
	for {
		select {
		case <-ticker.C:
			pm.checkPluginHealth()
		case <-ctx.Done():
			return
		}
	}
}

// checkPluginHealth checks the health of all plugins
func (pm *Manager) checkPluginHealth() {
	pm.mu.RLock()
	defer pm.mu.RUnlock()
	
	for pluginType, typeMap := range pm.plugins {
		for name, plugin := range typeMap {
			health := plugin.Health()
			pm.metrics.RecordPluginHealth(pluginType, name, health.Status)
			
			if health.Status != "healthy" {
				pm.logger.Warn("Plugin unhealthy",
					"type", pluginType,
					"name", name,
					"status", health.Status,
					"message", health.Message,
				)
			}
		}
	}
}

// validatePlugin validates a plugin meets requirements
func (pm *Manager) validatePlugin(plugin framework.Plugin, config framework.PluginConfig) error {
	// Verify plugin implements expected interface
	switch config.Type {
	case framework.PluginTypeEvaluator:
		if _, ok := plugin.(framework.PolicyEvaluator); !ok {
			return fmt.Errorf("plugin does not implement PolicyEvaluator interface")
		}
	case framework.PluginTypeDataSource:
		if _, ok := plugin.(framework.DataSource); !ok {
			return fmt.Errorf("plugin does not implement DataSource interface")
		}
	case framework.PluginTypeWorkflow:
		if _, ok := plugin.(framework.Workflow); !ok {
			return fmt.Errorf("plugin does not implement Workflow interface")
		}
	// Add other types as needed
	}
	
	// Validate configuration
	result := plugin.ValidateConfig(config)
	if !result.Valid {
		return fmt.Errorf("plugin configuration invalid: %v", result.Errors)
	}
	
	return nil
}

// registerDefaultLoaders registers built-in plugin loaders
func (pm *Manager) registerDefaultLoaders() {
	// Register local plugin loader
	pm.loaders["local"] = NewLocalPluginLoader(pm.logger)
	
	// Register gRPC plugin loader
	pm.loaders["grpc"] = NewGRPCPluginLoader(pm.logger)
	
	// Register OCI plugin loader
	pm.loaders["oci"] = NewOCIPluginLoader(pm.logger)
	
	// Register HTTP plugin loader
	pm.loaders["http"] = NewHTTPPluginLoader(pm.logger)
}

// ReloadPlugin reloads a plugin with new configuration
func (pm *Manager) ReloadPlugin(ctx context.Context, pluginType string, name string, config framework.PluginConfig) error {
	pm.mu.Lock()
	defer pm.mu.Unlock()
	
	// Get existing plugin
	typeMap, exists := pm.plugins[pluginType]
	if !exists {
		return fmt.Errorf("unknown plugin type: %s", pluginType)
	}
	
	plugin, exists := typeMap[name]
	if !exists {
		return fmt.Errorf("plugin not found: %s/%s", pluginType, name)
	}
	
	// Attempt reload
	if err := plugin.Reload(ctx, config); err != nil {
		return fmt.Errorf("plugin reload failed: %w", err)
	}
	
	pm.logger.Info("Plugin reloaded", 
		"type", pluginType,
		"name", name,
	)
	
	return nil
}