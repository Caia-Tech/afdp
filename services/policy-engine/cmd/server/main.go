package main

import (
	"context"
	"log"
	"os"
	"os/signal"
	"sync"
	"syscall"

	"github.com/Caia-Tech/afdp/services/policy-engine/internal/api/rest"
	"github.com/Caia-Tech/afdp/services/policy-engine/internal/core"
	"github.com/Caia-Tech/afdp/services/policy-engine/internal/logging"
	"github.com/Caia-Tech/afdp/services/policy-engine/internal/metrics"
	"github.com/Caia-Tech/afdp/services/policy-engine/pkg/framework"
)

func main() {
	// Create default configuration first
	config := &framework.FrameworkConfig{
		Version: "0.1.0",
		Name:    "AFDP Policy Engine",
		Framework: framework.FrameworkCoreConfig{
			Logging: framework.LoggingConfig{
				Level:  "info",
				Format: "json",
			},
			Metrics: framework.MetricsConfig{
				Enabled:   true,
				Namespace: "afdp",
			},
		},
		API: framework.APIConfig{
			REST: framework.RESTConfig{
				Enabled: true,
				Host:    "0.0.0.0",
				Port:    8080,
			},
		},
		Storage: framework.StorageConfig{
			PostgreSQL: framework.PostgreSQLConfig{
				Host:     "localhost",
				Port:     5432,
				Database: "afdp",
				Username: "afdp",
				Password: "password",
			},
		},
		Plugins: []framework.PluginConfig{},
	}

	// Override with environment variables
	if port := os.Getenv("PORT"); port != "" {
		config.API.REST.Port = 8080 // Default fallback
	}

	// Initialize logger and metrics based on config
	logger := logging.NewLogger(config.Framework.Logging.Level)
	metrics := metrics.NewCollector(config.Framework.Metrics)

	// Initialize framework core
	frameworkCore, err := core.NewFrameworkCore(config, logger, metrics)
	if err != nil {
		log.Fatalf("Failed to create framework core: %v", err)
	}

	ctx := context.Background()

	// Initialize framework
	if err := frameworkCore.Initialize(ctx); err != nil {
		log.Fatalf("Failed to initialize framework: %v", err)
	}

	// Start framework
	if err := frameworkCore.Start(ctx); err != nil {
		log.Fatalf("Failed to start framework: %v", err)
	}

	// Initialize REST server
	server := rest.NewServer(frameworkCore, config.API.REST, logger)

	// Start server in goroutine
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		logger.Info("Starting AFDP Policy Engine", "port", config.API.REST.Port)
		if err := server.Start(); err != nil {
			logger.Error("Server failed", "error", err)
		}
	}()

	// Wait for interrupt signal
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)
	<-c

	logger.Info("Shutting down server...")

	// Shutdown server
	if err := server.Stop(ctx); err != nil {
		logger.Error("Server shutdown failed", "error", err)
	}

	// Stop framework
	if err := frameworkCore.Stop(ctx); err != nil {
		logger.Error("Framework shutdown failed", "error", err)
	}

	wg.Wait()
	logger.Info("Server stopped")
}