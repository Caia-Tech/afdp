package security

import (
	"context"
	"fmt"
	"time"

	"github.com/Caia-Tech/afdp/services/policy-engine/internal/logging"
	"github.com/Caia-Tech/afdp/services/policy-engine/pkg/framework"
)

// BuiltinSecurityProvider implements the SecurityProvider interface
type BuiltinSecurityProvider struct {
	config      framework.PluginConfig
	logger      *logging.Logger
	authManager *AuthManager
	rbac        *RBAC
	startTime   time.Time
	status      framework.PluginStatus
}

// NewBuiltinSecurityProvider creates a new built-in security provider
func NewBuiltinSecurityProvider(config framework.PluginConfig, logger *logging.Logger) (*BuiltinSecurityProvider, error) {
	// Get JWT secret from config
	jwtSecret, _ := config.Config["jwt_secret"].(string)
	if jwtSecret == "" {
		jwtSecret = "default_development_secret"
		logger.Warn("No JWT secret provided in security config, using default")
	}

	// Create auth manager
	authManager := NewAuthManager(logger, jwtSecret)

	// Create RBAC system
	rbac := NewRBAC(logger)

	// Initialize default roles and permissions
	initializeDefaultRoles(rbac)

	return &BuiltinSecurityProvider{
		config:      config,
		logger:      logger,
		authManager: authManager,
		rbac:        rbac,
		status:      framework.PluginStatusUnknown,
	}, nil
}

// Plugin interface implementation

func (p *BuiltinSecurityProvider) Name() string {
	return p.config.Name
}

func (p *BuiltinSecurityProvider) Version() string {
	return "1.0.0"
}

func (p *BuiltinSecurityProvider) Type() framework.PluginType {
	return framework.PluginTypeSecurity
}

func (p *BuiltinSecurityProvider) Metadata() framework.PluginMetadata {
	return framework.PluginMetadata{
		StartTime:    p.startTime,
		Uptime:       time.Since(p.startTime),
		RequestCount: 0,
		ErrorCount:   0,
		Metadata: map[string]interface{}{
			"description":  "Built-in security provider with JWT authentication and RBAC",
			"auth_methods": []string{"password"},
			"features":     []string{"jwt", "rbac", "user_management"},
		},
	}
}

func (p *BuiltinSecurityProvider) Initialize(ctx context.Context, config framework.PluginConfig) error {
	p.status = framework.PluginStatusInitializing
	p.config = config
	
	p.logger.Info("Initializing security provider...")
	return nil
}

func (p *BuiltinSecurityProvider) Start(ctx context.Context) error {
	p.status = framework.PluginStatusStarting
	p.startTime = time.Now()
	
	p.logger.Info("Starting security provider...")
	p.status = framework.PluginStatusRunning
	return nil
}

func (p *BuiltinSecurityProvider) Stop(ctx context.Context) error {
	p.status = framework.PluginStatusStopping
	
	p.logger.Info("Stopping security provider...")
	p.status = framework.PluginStatusStopped
	return nil
}

func (p *BuiltinSecurityProvider) Reload(ctx context.Context, config framework.PluginConfig) error {
	p.config = config
	p.logger.Info("Security provider configuration reloaded")
	return nil
}

func (p *BuiltinSecurityProvider) Health() framework.HealthStatus {
	status := "healthy"
	message := "Security provider is running"
	
	if p.status != framework.PluginStatusRunning {
		status = "unhealthy"
		message = fmt.Sprintf("Plugin is in %s state", p.status)
	}
	
	return framework.HealthStatus{
		Status:     status,
		Message:    message,
		LastCheck:  time.Now(),
		CheckCount: 1,
		Metadata: map[string]interface{}{
			"uptime": time.Since(p.startTime).String(),
		},
	}
}

func (p *BuiltinSecurityProvider) Metrics() framework.PluginMetrics {
	return framework.PluginMetrics{
		CPUUsage:    0.0,
		MemoryUsage: 0,
		RequestRate: 0.0,
		ErrorRate:   0.0,
		Timestamp:   time.Now(),
	}
}

func (p *BuiltinSecurityProvider) ValidateConfig(config framework.PluginConfig) framework.ValidationResult {
	result := framework.ValidationResult{
		Valid: true,
	}
	
	if _, hasSecret := config.Config["jwt_secret"]; !hasSecret {
		result.Warnings = append(result.Warnings, framework.ValidationError{
			Field:    "config.jwt_secret",
			Message:  "No JWT secret configured",
			Code:     "missing_jwt_secret",
			Severity: "warning",
		})
	}
	
	return result
}

// SecurityProvider interface implementation

func (p *BuiltinSecurityProvider) Authenticate(ctx context.Context, req *framework.AuthenticationRequest) (*framework.AuthenticationResponse, error) {
	return p.authManager.Authenticate(ctx, req)
}

func (p *BuiltinSecurityProvider) RefreshToken(ctx context.Context, req *framework.RefreshTokenRequest) (*framework.RefreshTokenResponse, error) {
	return p.authManager.RefreshToken(ctx, req)
}

func (p *BuiltinSecurityProvider) RevokeToken(ctx context.Context, req *framework.RevokeTokenRequest) (*framework.RevokeTokenResponse, error) {
	return p.authManager.RevokeToken(ctx, req)
}

func (p *BuiltinSecurityProvider) ValidateToken(token string) (*Claims, error) {
	return p.authManager.ValidateToken(token)
}

func (p *BuiltinSecurityProvider) Authorize(ctx context.Context, req *framework.AuthorizationRequest) (*framework.AuthorizationResponse, error) {
	return p.rbac.Authorize(ctx, req)
}

func (p *BuiltinSecurityProvider) GetUser(ctx context.Context, req *framework.GetUserRequest) (*framework.GetUserResponse, error) {
	return p.authManager.GetUser(ctx, req)
}

func (p *BuiltinSecurityProvider) AssignRole(ctx context.Context, req *framework.AssignRoleRequest) (*framework.AssignRoleResponse, error) {
	return p.rbac.AssignRole(ctx, req)
}

func (p *BuiltinSecurityProvider) RevokeRole(ctx context.Context, req *framework.RevokeRoleRequest) (*framework.RevokeRoleResponse, error) {
	return p.rbac.RevokeRole(ctx, req)
}

func (p *BuiltinSecurityProvider) ListRoles(ctx context.Context, req *framework.ListRolesRequest) (*framework.ListRolesResponse, error) {
	return p.rbac.ListRoles(ctx, req)
}

func (p *BuiltinSecurityProvider) CreateRole(ctx context.Context, req *framework.CreateRoleRequest) (*framework.CreateRoleResponse, error) {
	return p.rbac.CreateRole(ctx, req)
}

func (p *BuiltinSecurityProvider) DeleteRole(ctx context.Context, req *framework.DeleteRoleRequest) (*framework.DeleteRoleResponse, error) {
	return p.rbac.DeleteRole(ctx, req)
}

func (p *BuiltinSecurityProvider) CheckPermission(ctx context.Context, req *framework.CheckPermissionRequest) (*framework.CheckPermissionResponse, error) {
	return p.rbac.CheckPermission(ctx, req)
}

func (p *BuiltinSecurityProvider) GrantPermission(ctx context.Context, req *framework.GrantPermissionRequest) (*framework.GrantPermissionResponse, error) {
	return p.rbac.GrantPermission(ctx, req)
}

func (p *BuiltinSecurityProvider) RevokePermission(ctx context.Context, req *framework.RevokePermissionRequest) (*framework.RevokePermissionResponse, error) {
	return p.rbac.RevokePermission(ctx, req)
}

// Helper function to initialize default roles and permissions
func initializeDefaultRoles(rbac *RBAC) {
	// Create admin role with all permissions
	rbac.CreateRole(context.Background(), &framework.CreateRoleRequest{
		Name:        "admin",
		Description: "Administrator role with full access",
		Permissions: []string{
			"policy:read", "policy:write", "policy:delete",
			"user:read", "user:write", "user:delete",
			"role:read", "role:write", "role:delete",
			"framework:read", "framework:write",
		},
	})

	// Create user role with basic permissions
	rbac.CreateRole(context.Background(), &framework.CreateRoleRequest{
		Name:        "user",
		Description: "Basic user role",
		Permissions: []string{
			"policy:read",
			"user:read",
		},
	})

	// Create service role for automated systems
	rbac.CreateRole(context.Background(), &framework.CreateRoleRequest{
		Name:        "service",
		Description: "Service account role",
		Permissions: []string{
			"policy:read", "policy:write",
		},
	})
}