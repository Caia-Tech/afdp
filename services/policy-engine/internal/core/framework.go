package core

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/Caia-Tech/afdp/services/policy-engine/internal/logging"
	"github.com/Caia-Tech/afdp/services/policy-engine/internal/metrics"
	"github.com/Caia-Tech/afdp/services/policy-engine/internal/plugins"
	"github.com/Caia-Tech/afdp/services/policy-engine/internal/storage"
	"github.com/Caia-Tech/afdp/services/policy-engine/pkg/framework"
)

// FrameworkCore is the main implementation of the framework orchestration engine
type FrameworkCore struct {
	config           *framework.FrameworkConfig
	logger           *logging.Logger
	metrics          *metrics.Collector
	pluginManager    *plugins.Manager
	pluginRegistry   *PluginRegistry
	eventBus         *EventBus
	decisionEngine   *DecisionEngine
	storage          storage.Provider
	securityManager  framework.SecurityManager
	
	mu               sync.RWMutex
	status           framework.PluginStatus
	startTime        time.Time
	shutdownHandlers []func(context.Context) error
}

// NewFrameworkCore creates a new framework core instance
func NewFrameworkCore(config *framework.FrameworkConfig, logger *logging.Logger, metrics *metrics.Collector) (*FrameworkCore, error) {
	// Initialize storage provider
	storageProvider, err := storage.NewProvider(config.Storage, logger)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize storage: %w", err)
	}

	// Create plugin manager
	pluginManager := plugins.NewManager(logger, metrics)

	// Create plugin registry
	pluginRegistry := NewPluginRegistry(logger)

	// Create event bus
	eventBus := NewEventBus(logger)

	// Create decision engine
	decisionEngine := NewDecisionEngine(logger, metrics)

	fc := &FrameworkCore{
		config:         config,
		logger:         logger,
		metrics:        metrics,
		pluginManager:  pluginManager,
		pluginRegistry: pluginRegistry,
		eventBus:       eventBus,
		decisionEngine: decisionEngine,
		storage:        storageProvider,
		status:         framework.PluginStatusUnknown,
		shutdownHandlers: make([]func(context.Context) error, 0),
	}

	return fc, nil
}

// Initialize prepares the framework for operation
func (fc *FrameworkCore) Initialize(ctx context.Context) error {
	fc.mu.Lock()
	defer fc.mu.Unlock()

	fc.logger.Info("Initializing framework core...")
	fc.status = framework.PluginStatusInitializing

	// Initialize storage
	if err := fc.storage.Initialize(ctx); err != nil {
		return fmt.Errorf("failed to initialize storage: %w", err)
	}

	// Initialize plugin registry
	if err := fc.pluginRegistry.Initialize(ctx); err != nil {
		return fmt.Errorf("failed to initialize plugin registry: %w", err)
	}

	// Initialize event bus
	if err := fc.eventBus.Initialize(ctx); err != nil {
		return fmt.Errorf("failed to initialize event bus: %w", err)
	}

	// Initialize decision engine
	if err := fc.decisionEngine.Initialize(ctx, fc); err != nil {
		return fmt.Errorf("failed to initialize decision engine: %w", err)
	}

	// Load plugins defined in configuration
	for _, pluginConfig := range fc.config.Plugins {
		if !pluginConfig.Enabled {
			fc.logger.Debug("Skipping disabled plugin", "name", pluginConfig.Name)
			continue
		}

		fc.logger.Info("Loading plugin", "name", pluginConfig.Name, "type", pluginConfig.Type)
		
		plugin, err := fc.pluginManager.LoadPlugin(ctx, pluginConfig)
		if err != nil {
			fc.logger.Error("Failed to load plugin", "name", pluginConfig.Name, "error", err)
			// Continue loading other plugins
			continue
		}

		// Register plugin
		if err := fc.RegisterPlugin(string(pluginConfig.Type), pluginConfig.Name, plugin); err != nil {
			fc.logger.Error("Failed to register plugin", "name", pluginConfig.Name, "error", err)
			continue
		}

		fc.logger.Info("Plugin loaded successfully", "name", pluginConfig.Name)
	}

	fc.logger.Info("Framework initialization complete")
	return nil
}

// Start begins framework operation
func (fc *FrameworkCore) Start(ctx context.Context) error {
	fc.mu.Lock()
	defer fc.mu.Unlock()

	if fc.status == framework.PluginStatusRunning {
		return fmt.Errorf("framework is already running")
	}

	fc.logger.Info("Starting framework...")
	fc.status = framework.PluginStatusStarting
	fc.startTime = time.Now()

	// Start plugin manager
	if err := fc.pluginManager.Start(ctx); err != nil {
		return fmt.Errorf("failed to start plugin manager: %w", err)
	}

	// Start event bus
	if err := fc.eventBus.Start(ctx); err != nil {
		return fmt.Errorf("failed to start event bus: %w", err)
	}

	// Start decision engine
	if err := fc.decisionEngine.Start(ctx); err != nil {
		return fmt.Errorf("failed to start decision engine: %w", err)
	}

	// Start all registered plugins
	plugins := fc.pluginManager.ListPlugins()
	for _, p := range plugins {
		fc.logger.Info("Starting plugin", "name", p.Name(), "type", p.Type())
		if err := p.Start(ctx); err != nil {
			fc.logger.Error("Failed to start plugin", "name", p.Name(), "error", err)
			// Continue starting other plugins
		}
	}

	// Publish framework started event
	fc.eventBus.Publish(&framework.Event{
		Type:      "framework.started",
		Source:    "framework.core",
		Timestamp: time.Now(),
		Data: map[string]interface{}{
			"version": fc.config.Version,
			"plugins": len(plugins),
		},
	})

	fc.status = framework.PluginStatusRunning
	fc.logger.Info("Framework started successfully")
	return nil
}

// Stop gracefully shuts down the framework
func (fc *FrameworkCore) Stop(ctx context.Context) error {
	fc.mu.Lock()
	defer fc.mu.Unlock()

	if fc.status != framework.PluginStatusRunning {
		return fmt.Errorf("framework is not running")
	}

	fc.logger.Info("Stopping framework...")
	fc.status = framework.PluginStatusStopping

	// Stop all plugins
	plugins := fc.pluginManager.ListPlugins()
	for _, p := range plugins {
		fc.logger.Info("Stopping plugin", "name", p.Name())
		if err := p.Stop(ctx); err != nil {
			fc.logger.Error("Failed to stop plugin", "name", p.Name(), "error", err)
		}
	}

	// Stop decision engine
	if err := fc.decisionEngine.Stop(ctx); err != nil {
		fc.logger.Error("Failed to stop decision engine", "error", err)
	}

	// Stop event bus
	if err := fc.eventBus.Stop(ctx); err != nil {
		fc.logger.Error("Failed to stop event bus", "error", err)
	}

	// Stop plugin manager
	if err := fc.pluginManager.Stop(ctx); err != nil {
		fc.logger.Error("Failed to stop plugin manager", "error", err)
	}

	// Run shutdown handlers
	for _, handler := range fc.shutdownHandlers {
		if err := handler(ctx); err != nil {
			fc.logger.Error("Shutdown handler failed", "error", err)
		}
	}

	fc.status = framework.PluginStatusStopped
	fc.logger.Info("Framework stopped successfully")
	return nil
}

// RegisterPlugin registers a plugin with the framework
func (fc *FrameworkCore) RegisterPlugin(pluginType string, name string, plugin framework.Plugin) error {
	fc.mu.Lock()
	defer fc.mu.Unlock()

	// Register with plugin manager
	if err := fc.pluginManager.RegisterPlugin(pluginType, name, plugin); err != nil {
		return fmt.Errorf("failed to register plugin with manager: %w", err)
	}

	// Register with plugin registry
	if err := fc.pluginRegistry.RegisterPlugin(plugin); err != nil {
		return fmt.Errorf("failed to register plugin with registry: %w", err)
	}

	// Subscribe to plugin events
	if handler, ok := plugin.(framework.EventHandler); ok {
		for _, eventType := range handler.EventTypes() {
			if err := fc.eventBus.Subscribe(eventType, handler); err != nil {
				fc.logger.Error("Failed to subscribe plugin to events", 
					"plugin", name, 
					"eventType", eventType, 
					"error", err)
			}
		}
	}

	// Publish plugin registered event
	fc.eventBus.Publish(&framework.Event{
		Type:      "plugin.registered",
		Source:    "framework.core",
		Timestamp: time.Now(),
		Data: map[string]interface{}{
			"plugin_type": pluginType,
			"plugin_name": name,
			"plugin_info": plugin.Metadata(),
		},
	})

	return nil
}

// UnregisterPlugin removes a plugin from the framework
func (fc *FrameworkCore) UnregisterPlugin(pluginType string, name string) error {
	fc.mu.Lock()
	defer fc.mu.Unlock()

	// Get plugin reference before unregistering
	plugin, err := fc.pluginManager.GetPlugin(pluginType, name)
	if err != nil {
		return fmt.Errorf("plugin not found: %w", err)
	}

	// Stop plugin if running
	if plugin.Health().Status == "healthy" {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		
		if err := plugin.Stop(ctx); err != nil {
			fc.logger.Error("Failed to stop plugin before unregistering", 
				"name", name, 
				"error", err)
		}
	}

	// Unsubscribe from events
	if handler, ok := plugin.(framework.EventHandler); ok {
		for _, eventType := range handler.EventTypes() {
			if err := fc.eventBus.Unsubscribe(eventType, handler); err != nil {
				fc.logger.Error("Failed to unsubscribe plugin from events", 
					"plugin", name, 
					"eventType", eventType, 
					"error", err)
			}
		}
	}

	// Unregister from plugin manager
	if err := fc.pluginManager.UnregisterPlugin(pluginType, name); err != nil {
		return fmt.Errorf("failed to unregister from plugin manager: %w", err)
	}

	// Unregister from plugin registry
	if err := fc.pluginRegistry.UnregisterPlugin(name); err != nil {
		return fmt.Errorf("failed to unregister from plugin registry: %w", err)
	}

	// Publish plugin unregistered event
	fc.eventBus.Publish(&framework.Event{
		Type:      "plugin.unregistered",
		Source:    "framework.core",
		Timestamp: time.Now(),
		Data: map[string]interface{}{
			"plugin_type": pluginType,
			"plugin_name": name,
		},
	})

	return nil
}

// GetPlugin retrieves a plugin by type and name
func (fc *FrameworkCore) GetPlugin(pluginType string, name string) (framework.Plugin, error) {
	fc.mu.RLock()
	defer fc.mu.RUnlock()

	return fc.pluginManager.GetPlugin(pluginType, name)
}

// ListPlugins returns all plugins of a specific type
func (fc *FrameworkCore) ListPlugins(pluginType string) []framework.PluginInfo {
	fc.mu.RLock()
	defer fc.mu.RUnlock()

	plugins := fc.pluginManager.ListPluginsByType(pluginType)
	infos := make([]framework.PluginInfo, 0, len(plugins))
	
	for _, p := range plugins {
		info := framework.PluginInfo{
			Name:        p.Name(),
			Version:     p.Version(),
			Type:        p.Type(),
			Description: p.Metadata().Metadata["description"].(string),
			Metadata:    p.Metadata().Metadata,
		}
		infos = append(infos, info)
	}

	return infos
}

// LoadConfiguration loads a new configuration
func (fc *FrameworkCore) LoadConfiguration(configPath string) error {
	fc.mu.Lock()
	defer fc.mu.Unlock()

	// This would be implemented by the configuration manager
	return fmt.Errorf("not implemented")
}

// ReloadConfiguration reloads the current configuration from file
func (fc *FrameworkCore) ReloadConfiguration() error {
	// For now, just return nil - this would reload from the original config file
	return nil
}

// ReloadConfigurationWithConfig applies a new configuration
func (fc *FrameworkCore) ReloadConfigurationWithConfig(newConfig *framework.FrameworkConfig) error {
	fc.mu.Lock()
	defer fc.mu.Unlock()

	fc.logger.Info("Reloading configuration...")

	// Update framework configuration
	oldConfig := fc.config
	fc.config = newConfig

	// Reload plugins that support hot reload
	plugins := fc.pluginManager.ListPlugins()
	for _, p := range plugins {
		// Find new config for this plugin
		var pluginConfig *framework.PluginConfig
		for _, pc := range newConfig.Plugins {
			if pc.Name == p.Name() {
				pluginConfig = &pc
				break
			}
		}

		if pluginConfig != nil && pluginConfig.Enabled {
			fc.logger.Info("Reloading plugin configuration", "name", p.Name())
			if err := p.Reload(context.Background(), *pluginConfig); err != nil {
				fc.logger.Error("Failed to reload plugin", "name", p.Name(), "error", err)
			}
		}
	}

	// Publish configuration reloaded event
	fc.eventBus.Publish(&framework.Event{
		Type:      "configuration.reloaded",
		Source:    "framework.core",
		Timestamp: time.Now(),
		Data: map[string]interface{}{
			"old_version": oldConfig.Version,
			"new_version": newConfig.Version,
		},
	})

	fc.logger.Info("Configuration reload complete")
	return nil
}

// GetConfiguration returns the current configuration
func (fc *FrameworkCore) GetConfiguration() *framework.FrameworkConfig {
	fc.mu.RLock()
	defer fc.mu.RUnlock()

	return fc.config
}

// ValidateConfiguration validates a configuration
func (fc *FrameworkCore) ValidateConfiguration(config *framework.FrameworkConfig) error {
	// Basic validation
	if config.Version == "" {
		return fmt.Errorf("configuration version is required")
	}

	if config.Name == "" {
		return fmt.Errorf("framework name is required")
	}

	// Validate plugin configurations
	for _, pc := range config.Plugins {
		if pc.Name == "" {
			return fmt.Errorf("plugin name is required")
		}
		if pc.Type == "" {
			return fmt.Errorf("plugin type is required for plugin %s", pc.Name)
		}
	}

	return nil
}

// Subscribe registers an event handler for specific event types
func (fc *FrameworkCore) Subscribe(eventType string, handler framework.EventHandler) error {
	return fc.eventBus.Subscribe(eventType, handler)
}

// Unsubscribe removes an event handler
func (fc *FrameworkCore) Unsubscribe(eventType string, handler framework.EventHandler) error {
	return fc.eventBus.Unsubscribe(eventType, handler)
}

// PublishEvent publishes an event to the event bus
func (fc *FrameworkCore) PublishEvent(event *framework.Event) error {
	return fc.eventBus.Publish(event)
}

// Health returns the health status of the framework
func (fc *FrameworkCore) Health() framework.HealthStatus {
	fc.mu.RLock()
	defer fc.mu.RUnlock()

	status := "healthy"
	message := "Framework is running normally"

	if fc.status != framework.PluginStatusRunning {
		status = "unhealthy"
		message = fmt.Sprintf("Framework is in %s state", fc.status)
	}

	// Check critical components
	pluginHealth := fc.pluginManager.Health()
	if pluginHealth.Status != "healthy" {
		status = "degraded"
		message = "Some plugins are unhealthy"
	}

	return framework.HealthStatus{
		Status:    status,
		Message:   message,
		LastCheck: time.Now(),
		Metadata: map[string]interface{}{
			"uptime":       time.Since(fc.startTime).String(),
			"plugin_count": len(fc.pluginManager.ListPlugins()),
			"status":       string(fc.status),
		},
	}
}

// RegisterShutdownHandler adds a function to be called during shutdown
func (fc *FrameworkCore) RegisterShutdownHandler(handler func(context.Context) error) {
	fc.mu.Lock()
	defer fc.mu.Unlock()

	fc.shutdownHandlers = append(fc.shutdownHandlers, handler)
}

// GetDecisionEngine returns the decision engine for policy evaluation
func (fc *FrameworkCore) GetDecisionEngine() framework.DecisionEngine {
	return fc.decisionEngine
}

// GetStorage returns the storage provider
func (fc *FrameworkCore) GetStorage() storage.Provider {
	return fc.storage
}

// GetEventBus returns the event bus
func (fc *FrameworkCore) GetEventBus() *EventBus {
	return fc.eventBus
}