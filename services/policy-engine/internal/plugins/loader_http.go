package plugins

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/Caia-Tech/afdp/services/policy-engine/internal/logging"
	"github.com/Caia-Tech/afdp/services/policy-engine/pkg/framework"
)

// HTTPPluginLoader loads plugins via HTTP/HTTPS
type HTTPPluginLoader struct {
	logger     *logging.Logger
	httpClient *http.Client
	cacheDir   string
}

// NewHTTPPluginLoader creates a new HTTP plugin loader
func NewHTTPPluginLoader(logger *logging.Logger) *HTTPPluginLoader {
	cacheDir := os.Getenv("AFDP_PLUGIN_CACHE_DIR")
	if cacheDir == "" {
		cacheDir = "/tmp/afdp-plugins"
	}
	
	return &HTTPPluginLoader{
		logger: logger,
		httpClient: &http.Client{
			Timeout: 5 * time.Minute,
		},
		cacheDir: cacheDir,
	}
}

// LoadPlugin loads a plugin via HTTP
func (h *HTTPPluginLoader) LoadPlugin(ctx context.Context, config framework.PluginConfig) (framework.Plugin, error) {
	h.logger.Info("Loading HTTP plugin", 
		"name", config.Name,
		"location", config.Source.Location,
	)
	
	// Download plugin
	pluginPath, err := h.downloadPlugin(ctx, config)
	if err != nil {
		return nil, fmt.Errorf("failed to download plugin: %w", err)
	}
	
	// Verify plugin
	if err := h.verifyPlugin(pluginPath, config); err != nil {
		return nil, fmt.Errorf("plugin verification failed: %w", err)
	}
	
	// Load plugin
	return h.loadDownloadedPlugin(ctx, pluginPath, config)
}

// UnloadPlugin unloads an HTTP plugin
func (h *HTTPPluginLoader) UnloadPlugin(ctx context.Context, plugin framework.Plugin) error {
	// Stop plugin and clean up cached files
	if err := plugin.Stop(ctx); err != nil {
		return err
	}
	
	// Clean up cache
	cacheKey := h.getCacheKey(plugin.Name(), plugin.Version())
	cachePath := filepath.Join(h.cacheDir, cacheKey)
	
	if err := os.RemoveAll(cachePath); err != nil {
		h.logger.Warn("Failed to clean up plugin cache", 
			"path", cachePath,
			"error", err,
		)
	}
	
	return nil
}

// SupportedTypes returns supported source types
func (h *HTTPPluginLoader) SupportedTypes() []framework.PluginSource {
	return []framework.PluginSource{
		{Type: "http"},
		{Type: "https"},
	}
}

// downloadPlugin downloads a plugin via HTTP
func (h *HTTPPluginLoader) downloadPlugin(ctx context.Context, config framework.PluginConfig) (string, error) {
	cacheKey := h.getCacheKey(config.Name, config.Source.Version)
	cachePath := filepath.Join(h.cacheDir, cacheKey)
	pluginFile := filepath.Join(cachePath, "plugin.so")
	
	// Check if already cached
	if _, err := os.Stat(pluginFile); err == nil {
		h.logger.Debug("Using cached plugin", "path", pluginFile)
		return pluginFile, nil
	}
	
	// Create cache directory
	if err := os.MkdirAll(cachePath, 0755); err != nil {
		return "", fmt.Errorf("failed to create cache directory: %w", err)
	}
	
	// Create HTTP request
	req, err := http.NewRequestWithContext(ctx, "GET", config.Source.Location, nil)
	if err != nil {
		return "", fmt.Errorf("failed to create request: %w", err)
	}
	
	// Add headers
	req.Header.Set("User-Agent", "AFDP-Policy-Framework/1.0")
	
	// Download
	resp, err := h.httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("download failed: %w", err)
	}
	defer resp.Body.Close()
	
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("download failed with status: %s", resp.Status)
	}
	
	// Create temporary file
	tmpFile := pluginFile + ".tmp"
	out, err := os.Create(tmpFile)
	if err != nil {
		return "", fmt.Errorf("failed to create file: %w", err)
	}
	defer out.Close()
	
	// Copy with progress tracking
	hasher := sha256.New()
	writer := io.MultiWriter(out, hasher)
	
	written, err := io.Copy(writer, resp.Body)
	if err != nil {
		os.Remove(tmpFile)
		return "", fmt.Errorf("failed to save plugin: %w", err)
	}
	
	h.logger.Info("Plugin downloaded", 
		"name", config.Name,
		"size", written,
		"checksum", hex.EncodeToString(hasher.Sum(nil)),
	)
	
	// Make executable
	if err := os.Chmod(tmpFile, 0755); err != nil {
		os.Remove(tmpFile)
		return "", fmt.Errorf("failed to set permissions: %w", err)
	}
	
	// Rename to final location
	if err := os.Rename(tmpFile, pluginFile); err != nil {
		os.Remove(tmpFile)
		return "", fmt.Errorf("failed to finalize plugin: %w", err)
	}
	
	return pluginFile, nil
}

// verifyPlugin verifies plugin integrity
func (h *HTTPPluginLoader) verifyPlugin(pluginPath string, config framework.PluginConfig) error {
	// Verify checksum
	if config.Source.Checksum != "" {
		file, err := os.Open(pluginPath)
		if err != nil {
			return fmt.Errorf("failed to open plugin: %w", err)
		}
		defer file.Close()
		
		hasher := sha256.New()
		if _, err := io.Copy(hasher, file); err != nil {
			return fmt.Errorf("failed to calculate checksum: %w", err)
		}
		
		actual := hex.EncodeToString(hasher.Sum(nil))
		if actual != config.Source.Checksum {
			return fmt.Errorf("checksum mismatch: expected %s, got %s", config.Source.Checksum, actual)
		}
		
		h.logger.Debug("Plugin checksum verified", "checksum", actual)
	}
	
	return nil
}

// loadDownloadedPlugin loads the downloaded plugin
func (h *HTTPPluginLoader) loadDownloadedPlugin(ctx context.Context, pluginPath string, config framework.PluginConfig) (framework.Plugin, error) {
	// In real implementation, would load the actual plugin binary
	// For now, return a mock plugin
	
	switch config.Type {
	case framework.PluginTypeEvaluator:
		return NewBuiltinRegoEvaluator(config)
	case framework.PluginTypeDataSource:
		return NewBuiltinPostgresDataSource(config)
	default:
		return nil, fmt.Errorf("unsupported plugin type: %s", config.Type)
	}
}

// getCacheKey generates a cache key for a plugin
func (h *HTTPPluginLoader) getCacheKey(name, version string) string {
	if version == "" {
		version = "latest"
	}
	return fmt.Sprintf("%s-%s", name, version)
}