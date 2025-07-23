package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/Caia-Tech/afdp/services/policy-engine/internal/core"
	"github.com/Caia-Tech/afdp/services/policy-engine/internal/api/rest"
	"github.com/Caia-Tech/afdp/services/policy-engine/internal/logging"
	"github.com/Caia-Tech/afdp/services/policy-engine/internal/metrics"
	"github.com/Caia-Tech/afdp/services/policy-engine/pkg/framework"
)

var (
	version   = "dev"
	buildTime = "unknown"
	gitCommit = "unknown"
)

func main() {
	var (
		configFile      = flag.String("config", "framework.yaml", "Path to configuration file")
		showVersion     = flag.Bool("version", false, "Show version information")
		validateConfig  = flag.Bool("validate", false, "Validate configuration and exit")
		dryRun          = flag.Bool("dry-run", false, "Start framework in dry-run mode")
		logLevel        = flag.String("log-level", "", "Override log level (debug, info, warn, error)")
	)
	flag.Parse()

	if *showVersion {
		fmt.Printf("AFDP Policy Framework\n")
		fmt.Printf("Version:    %s\n", version)
		fmt.Printf("Build Time: %s\n", buildTime)
		fmt.Printf("Git Commit: %s\n", gitCommit)
		os.Exit(0)
	}

	// Initialize logging
	logger := logging.NewLogger(*logLevel)
	logger.Info("Starting AFDP Policy Framework",
		"version", version,
		"config", *configFile,
		"pid", os.Getpid(),
	)

	// Load configuration
	configManager := core.NewConfigurationManager(logger)
	config, err := configManager.LoadConfiguration(*configFile)
	if err != nil {
		logger.Error("Failed to load configuration", "error", err)
		os.Exit(1)
	}

	// Validate configuration
	if validationResult := configManager.ValidateConfiguration(config); !validationResult.Valid {
		logger.Error("Configuration validation failed", "errors", validationResult.Errors)
		os.Exit(1)
	}

	if *validateConfig {
		logger.Info("Configuration validation successful")
		os.Exit(0)
	}

	// Initialize metrics
	metricsCollector := metrics.NewCollector(config.Framework.Metrics)
	metricsCollector.Start()
	defer metricsCollector.Stop()

	// Create framework core
	frameworkCore, err := core.NewFrameworkCore(config, logger, metricsCollector)
	if err != nil {
		logger.Error("Failed to create framework core", "error", err)
		os.Exit(1)
	}

	// Initialize framework
	ctx := context.Background()
	if err := frameworkCore.Initialize(ctx); err != nil {
		logger.Error("Failed to initialize framework", "error", err)
		os.Exit(1)
	}

	// Start configuration watcher for hot reload
	if config.DynamicConfig.HotReload.Enabled {
		go func() {
			if err := configManager.WatchConfiguration(ctx, func(oldConfig, newConfig *framework.FrameworkConfig) error {
				logger.Info("Configuration change detected, reloading...")
				return frameworkCore.ReloadConfigurationWithConfig(newConfig)
			}); err != nil {
				logger.Error("Configuration watcher failed", "error", err)
			}
		}()
	}

	// Create and start API servers
	restServer := rest.NewServer(frameworkCore, config.API.REST, logger)
	
	// Start framework in dry-run mode if requested
	if *dryRun {
		logger.Info("Running in dry-run mode, validating startup...")
		ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
		defer cancel()
		
		if err := frameworkCore.Start(ctx); err != nil {
			logger.Error("Dry-run startup failed", "error", err)
			os.Exit(1)
		}
		
		logger.Info("Dry-run successful, framework would start normally")
		os.Exit(0)
	}

	// Start framework
	logger.Info("Starting framework...")
	if err := frameworkCore.Start(ctx); err != nil {
		logger.Error("Failed to start framework", "error", err)
		os.Exit(1)
	}

	// Start API servers
	go func() {
		logger.Info("Starting REST API server", "address", restServer.Address())
		if err := restServer.Start(); err != nil {
			logger.Error("REST API server failed", "error", err)
		}
	}()

	// Setup graceful shutdown
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	// Wait for shutdown signal
	sig := <-sigChan
	logger.Info("Received shutdown signal", "signal", sig)

	// Graceful shutdown with timeout
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Stop API servers
	logger.Info("Stopping API servers...")
	if err := restServer.Stop(shutdownCtx); err != nil {
		logger.Error("Failed to stop REST server gracefully", "error", err)
	}

	// Stop framework
	logger.Info("Stopping framework...")
	if err := frameworkCore.Stop(shutdownCtx); err != nil {
		logger.Error("Failed to stop framework gracefully", "error", err)
	}

	logger.Info("Shutdown complete")
}