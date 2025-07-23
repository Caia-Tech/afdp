package plugins

import (
	"context"
	"fmt"
	"plugin"

	"github.com/Caia-Tech/afdp/services/policy-engine/internal/logging"
	"github.com/Caia-Tech/afdp/services/policy-engine/pkg/framework"
)

// LocalPluginLoader loads plugins from local filesystem
type LocalPluginLoader struct {
	logger *logging.Logger
}

// NewLocalPluginLoader creates a new local plugin loader
func NewLocalPluginLoader(logger *logging.Logger) *LocalPluginLoader {
	return &LocalPluginLoader{
		logger: logger,
	}
}

// LoadPlugin loads a plugin from local filesystem
func (l *LocalPluginLoader) LoadPlugin(ctx context.Context, config framework.PluginConfig) (framework.Plugin, error) {
	l.logger.Info("Loading local plugin", 
		"name", config.Name,
		"location", config.Source.Location,
	)
	
	// In a real implementation, this would load a Go plugin (.so file)
	// For now, we'll create built-in plugin instances
	
	switch config.Source.Location {
	case "builtin:rego":
		return NewBuiltinRegoEvaluator(config)
	case "builtin:postgres":
		return NewBuiltinPostgresDataSource(config)
	case "builtin:workflow":
		return NewBuiltinWorkflowEngine(config)
	case "builtin:security":
		return NewBuiltinSecurityProvider(config, l.logger)
	default:
		// Try to load as Go plugin
		return l.loadGoPlugin(config)
	}
}

// UnloadPlugin unloads a local plugin
func (l *LocalPluginLoader) UnloadPlugin(ctx context.Context, plugin framework.Plugin) error {
	// Go plugins cannot be unloaded, just stop the plugin
	return plugin.Stop(ctx)
}

// SupportedTypes returns supported source types
func (l *LocalPluginLoader) SupportedTypes() []framework.PluginSource {
	return []framework.PluginSource{
		{Type: "local"},
	}
}

// loadGoPlugin loads a Go plugin from .so file
func (l *LocalPluginLoader) loadGoPlugin(config framework.PluginConfig) (framework.Plugin, error) {
	// Open the plugin
	p, err := plugin.Open(config.Source.Location)
	if err != nil {
		return nil, fmt.Errorf("failed to open plugin: %w", err)
	}
	
	// Look for the plugin symbol
	symPlugin, err := p.Lookup("Plugin")
	if err != nil {
		return nil, fmt.Errorf("plugin missing Plugin symbol: %w", err)
	}
	
	// Assert the symbol is a Plugin
	var plug framework.Plugin
	plug, ok := symPlugin.(framework.Plugin)
	if !ok {
		return nil, fmt.Errorf("plugin does not implement Plugin interface")
	}
	
	return plug, nil
}