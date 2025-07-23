package plugins

import (
	"context"
	"fmt"
	"net"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"github.com/Caia-Tech/afdp/services/policy-engine/internal/logging"
	"github.com/Caia-Tech/afdp/services/policy-engine/pkg/framework"
)

// GRPCPluginLoader loads plugins via gRPC
type GRPCPluginLoader struct {
	logger      *logging.Logger
	connections map[string]*grpc.ClientConn
}

// NewGRPCPluginLoader creates a new gRPC plugin loader
func NewGRPCPluginLoader(logger *logging.Logger) *GRPCPluginLoader {
	return &GRPCPluginLoader{
		logger:      logger,
		connections: make(map[string]*grpc.ClientConn),
	}
}

// LoadPlugin loads a plugin via gRPC
func (g *GRPCPluginLoader) LoadPlugin(ctx context.Context, config framework.PluginConfig) (framework.Plugin, error) {
	g.logger.Info("Loading gRPC plugin", 
		"name", config.Name,
		"location", config.Source.Location,
	)
	
	// Parse location (should be host:port)
	host, port, err := net.SplitHostPort(config.Source.Location)
	if err != nil {
		return nil, fmt.Errorf("invalid gRPC location: %w", err)
	}
	
	// Create gRPC connection
	conn, err := g.createConnection(ctx, host, port)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to plugin: %w", err)
	}
	
	// Store connection
	g.connections[config.Name] = conn
	
	// Create appropriate plugin wrapper based on type
	switch config.Type {
	case framework.PluginTypeEvaluator:
		return NewGRPCEvaluatorPlugin(conn, config, g.logger)
	case framework.PluginTypeDataSource:
		return NewGRPCDataSourcePlugin(conn, config, g.logger)
	case framework.PluginTypeWorkflow:
		return NewGRPCWorkflowPlugin(conn, config, g.logger)
	default:
		return nil, fmt.Errorf("unsupported gRPC plugin type: %s", config.Type)
	}
}

// UnloadPlugin unloads a gRPC plugin
func (g *GRPCPluginLoader) UnloadPlugin(ctx context.Context, plugin framework.Plugin) error {
	// Close gRPC connection
	if conn, exists := g.connections[plugin.Name()]; exists {
		delete(g.connections, plugin.Name())
		return conn.Close()
	}
	return nil
}

// SupportedTypes returns supported source types
func (g *GRPCPluginLoader) SupportedTypes() []framework.PluginSource {
	return []framework.PluginSource{
		{Type: "grpc"},
	}
}

// createConnection creates a gRPC connection
func (g *GRPCPluginLoader) createConnection(ctx context.Context, host, port string) (*grpc.ClientConn, error) {
	addr := net.JoinHostPort(host, port)
	
	// Connection options
	opts := []grpc.DialOption{
		grpc.WithTransportCredentials(insecure.NewCredentials()), // In production, use TLS
		grpc.WithBlock(),
		grpc.WithDefaultCallOptions(
			grpc.MaxCallRecvMsgSize(10 * 1024 * 1024), // 10MB
			grpc.MaxCallSendMsgSize(10 * 1024 * 1024), // 10MB
		),
	}
	
	// Create context with timeout
	dialCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	
	// Connect
	conn, err := grpc.DialContext(dialCtx, addr, opts...)
	if err != nil {
		return nil, fmt.Errorf("failed to dial: %w", err)
	}
	
	return conn, nil
}