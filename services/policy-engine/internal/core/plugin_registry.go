package core

import (
	"context"
	"fmt"
	"sync"

	"github.com/Caia-Tech/afdp/services/policy-engine/internal/logging"
	"github.com/Caia-Tech/afdp/services/policy-engine/pkg/framework"
)

// PluginRegistry manages plugin discovery and information
type PluginRegistry struct {
	logger  *logging.Logger
	mu      sync.RWMutex
	plugins map[string]*pluginEntry
}

type pluginEntry struct {
	plugin framework.Plugin
	info   framework.PluginInfo
}

// NewPluginRegistry creates a new plugin registry
func NewPluginRegistry(logger *logging.Logger) *PluginRegistry {
	return &PluginRegistry{
		logger:  logger,
		plugins: make(map[string]*pluginEntry),
	}
}

// Initialize prepares the plugin registry
func (pr *PluginRegistry) Initialize(ctx context.Context) error {
	pr.logger.Info("Initializing plugin registry...")
	
	// In a real implementation, this might:
	// - Connect to a remote plugin registry
	// - Load plugin metadata from disk
	// - Verify plugin signatures
	
	return nil
}

// RegisterPlugin adds a plugin to the registry
func (pr *PluginRegistry) RegisterPlugin(plugin framework.Plugin) error {
	pr.mu.Lock()
	defer pr.mu.Unlock()

	name := plugin.Name()
	if _, exists := pr.plugins[name]; exists {
		return fmt.Errorf("plugin %s already registered", name)
	}

	metadata := plugin.Metadata()
	info := framework.PluginInfo{
		Name:        name,
		Version:     plugin.Version(),
		Type:        plugin.Type(),
		Description: getDescription(metadata),
		Author:      getAuthor(metadata),
		License:     getLicense(metadata),
		Tags:        getTags(metadata),
		Metadata:    metadata.Metadata,
	}

	pr.plugins[name] = &pluginEntry{
		plugin: plugin,
		info:   info,
	}

	pr.logger.Info("Plugin registered", 
		"name", name,
		"version", info.Version,
		"type", info.Type,
	)

	return nil
}

// UnregisterPlugin removes a plugin from the registry
func (pr *PluginRegistry) UnregisterPlugin(name string) error {
	pr.mu.Lock()
	defer pr.mu.Unlock()

	if _, exists := pr.plugins[name]; !exists {
		return fmt.Errorf("plugin %s not found", name)
	}

	delete(pr.plugins, name)
	pr.logger.Info("Plugin unregistered", "name", name)
	return nil
}

// GetPluginInfo retrieves information about a specific plugin
func (pr *PluginRegistry) GetPluginInfo(ctx context.Context, name string, version string) (*framework.PluginInfo, error) {
	pr.mu.RLock()
	defer pr.mu.RUnlock()

	entry, exists := pr.plugins[name]
	if !exists {
		return nil, fmt.Errorf("plugin %s not found", name)
	}

	// Check version if specified
	if version != "" && entry.info.Version != version {
		return nil, fmt.Errorf("plugin %s version %s not found (have %s)", name, version, entry.info.Version)
	}

	info := entry.info // Create a copy
	return &info, nil
}

// DiscoverPlugins returns all available plugins
func (pr *PluginRegistry) DiscoverPlugins(ctx context.Context) ([]framework.PluginInfo, error) {
	pr.mu.RLock()
	defer pr.mu.RUnlock()

	plugins := make([]framework.PluginInfo, 0, len(pr.plugins))
	for _, entry := range pr.plugins {
		plugins = append(plugins, entry.info)
	}

	return plugins, nil
}

// SearchPlugins searches for plugins matching the query
func (pr *PluginRegistry) SearchPlugins(ctx context.Context, query framework.PluginQuery) ([]framework.PluginInfo, error) {
	pr.mu.RLock()
	defer pr.mu.RUnlock()

	var results []framework.PluginInfo

	for _, entry := range pr.plugins {
		if matchesQuery(entry.info, query) {
			results = append(results, entry.info)
		}
	}

	return results, nil
}

// Helper functions to extract metadata
func getDescription(metadata framework.PluginMetadata) string {
	if desc, ok := metadata.Metadata["description"].(string); ok {
		return desc
	}
	return ""
}

func getAuthor(metadata framework.PluginMetadata) string {
	if author, ok := metadata.Metadata["author"].(string); ok {
		return author
	}
	return ""
}

func getLicense(metadata framework.PluginMetadata) string {
	if license, ok := metadata.Metadata["license"].(string); ok {
		return license
	}
	return ""
}

func getTags(metadata framework.PluginMetadata) []string {
	if tags, ok := metadata.Metadata["tags"].([]string); ok {
		return tags
	}
	return []string{}
}

func matchesQuery(info framework.PluginInfo, query framework.PluginQuery) bool {
	// Simple query matching implementation
	// In a real system, this would be more sophisticated
	
	// Check type
	if query.Type != "" && info.Type != framework.PluginType(query.Type) {
		return false
	}

	// Check tags
	if len(query.Tags) > 0 {
		hasTag := false
		for _, queryTag := range query.Tags {
			for _, infoTag := range info.Tags {
				if queryTag == infoTag {
					hasTag = true
					break
				}
			}
			if hasTag {
				break
			}
		}
		if !hasTag {
			return false
		}
	}

	// Check capabilities
	if len(query.Capabilities) > 0 {
		hasCapability := false
		for _, queryCap := range query.Capabilities {
			for _, infoCap := range info.Capabilities {
				if queryCap == infoCap {
					hasCapability = true
					break
				}
			}
			if hasCapability {
				break
			}
		}
		if !hasCapability {
			return false
		}
	}

	return true
}

// Additional types needed for the registry

// PluginQuery represents a search query for plugins
type PluginQuery struct {
	Type         string   `json:"type,omitempty"`
	Tags         []string `json:"tags,omitempty"`
	Capabilities []string `json:"capabilities,omitempty"`
	Name         string   `json:"name,omitempty"`
	Author       string   `json:"author,omitempty"`
}