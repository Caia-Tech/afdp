package main

import (
	"context"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/Caia-Tech/afdp/services/policy-engine/internal/api/rest"
	"github.com/Caia-Tech/afdp/services/policy-engine/internal/core"
	"github.com/Caia-Tech/afdp/services/policy-engine/internal/logging"
	"github.com/Caia-Tech/afdp/services/policy-engine/internal/metrics"
	"github.com/Caia-Tech/afdp/services/policy-engine/internal/plugins"
	"github.com/Caia-Tech/afdp/services/policy-engine/internal/security"
	"github.com/Caia-Tech/afdp/services/policy-engine/pkg/framework"
)

func main() {
	// Create logger
	logger := logging.NewLogger("policy-engine", "info")
	logger.Info("Starting AFDP Policy Engine...")

	// Create metrics collector
	metrics := metrics.NewCollector(logger)

	// Create example configuration
	config := createExampleConfig()

	// Create framework core
	frameworkCore, err := core.NewFrameworkCore(config, logger, metrics)
	if err != nil {
		log.Fatal("Failed to create framework core:", err)
	}

	// Create context
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Register built-in plugins
	if err := registerBuiltinPlugins(frameworkCore, logger); err != nil {
		log.Fatal("Failed to register built-in plugins:", err)
	}

	// Initialize framework
	if err := frameworkCore.Initialize(ctx); err != nil {
		log.Fatal("Failed to initialize framework:", err)
	}

	// Start framework
	if err := frameworkCore.Start(ctx); err != nil {
		log.Fatal("Failed to start framework:", err)
	}

	// Create REST server
	server := rest.NewServer(":8080", frameworkCore, logger)

	// Start server
	go func() {
		logger.Info("Starting REST server on :8080")
		if err := server.Start(); err != nil {
			log.Fatal("Failed to start server:", err)
		}
	}()

	// Wait for interrupt signal
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	logger.Info("Policy Engine started successfully. Press Ctrl+C to stop.")
	<-sigChan

	logger.Info("Shutting down...")

	// Create shutdown context with timeout
	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer shutdownCancel()

	// Stop server
	if err := server.Stop(shutdownCtx); err != nil {
		logger.Error("Error stopping server", "error", err)
	}

	// Stop framework
	if err := frameworkCore.Stop(shutdownCtx); err != nil {
		logger.Error("Error stopping framework", "error", err)
	}

	logger.Info("Policy Engine stopped")
}

func createExampleConfig() *framework.FrameworkConfig {
	return &framework.FrameworkConfig{
		Name:    "AFDP Policy Engine",
		Version: "1.0.0",
		Storage: framework.StorageConfig{
			Type: "memory", // Use in-memory storage for example
		},
		Plugins: []framework.PluginConfig{
			{
				Name:    "rego",
				Type:    framework.PluginTypeEvaluator,
				Enabled: true,
				Config: map[string]interface{}{
					"data": map[string]interface{}{
						"users": map[string]interface{}{
							"admin": map[string]interface{}{
								"roles": []string{"admin", "user"},
							},
							"user1": map[string]interface{}{
								"roles": []string{"user"},
							},
						},
					},
					"policies": map[string]interface{}{
						"example": `
package policy

default allow = false

# Allow admins to do everything
allow {
	input.user.roles[_] == "admin"
}

# Allow users to read their own data
allow {
	input.action == "read"
	input.resource.owner == input.user.id
}

# Allow users to create new resources
allow {
	input.action == "create"
	input.user.roles[_] == "user"
}
`,
					},
				},
			},
			{
				Name:    "default",
				Type:    framework.PluginTypeSecurity,
				Enabled: true,
				Config: map[string]interface{}{
					"jwt_secret": "development_secret_key_change_in_production",
				},
			},
		},
	}
}

func registerBuiltinPlugins(frameworkCore *core.FrameworkCore, logger *logging.Logger) error {
	// Register Rego evaluator
	regoConfig := framework.PluginConfig{
		Name: "rego",
		Type: framework.PluginTypeEvaluator,
	}
	
	regoPlugin, err := plugins.NewBuiltinRegoEvaluator(regoConfig)
	if err != nil {
		return err
	}

	if err := frameworkCore.RegisterPlugin(string(framework.PluginTypeEvaluator), "rego", regoPlugin); err != nil {
		return err
	}

	// Register security provider
	securityConfig := framework.PluginConfig{
		Name: "default",
		Type: framework.PluginTypeSecurity,
		Config: map[string]interface{}{
			"jwt_secret": "development_secret_key_change_in_production",
		},
	}

	securityPlugin, err := security.NewBuiltinSecurityProvider(securityConfig, logger)
	if err != nil {
		return err
	}

	if err := frameworkCore.RegisterPlugin(string(framework.PluginTypeSecurity), "default", securityPlugin); err != nil {
		return err
	}

	return nil
}