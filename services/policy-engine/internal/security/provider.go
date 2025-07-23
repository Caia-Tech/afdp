package security

import (
	"context"
	"time"

	"github.com/Caia-Tech/afdp/services/policy-engine/internal/logging"
	"github.com/Caia-Tech/afdp/services/policy-engine/pkg/framework"
)

// Provider implements the SecurityProvider interface
type Provider struct {
	config      framework.PluginConfig
	logger      *logging.Logger
	authManager *AuthManager
	rbacManager *RBACManager
	startTime   time.Time
	status      framework.PluginStatus
}

// NewProvider creates a new security provider
func NewProvider(config framework.PluginConfig, logger *logging.Logger) (*Provider, error) {
	// Get JWT secret from config
	jwtSecret := ""
	if secret, ok := config.Config["jwt_secret"].(string); ok {
		jwtSecret = secret
	}

	return &Provider{
		config:      config,
		logger:      logger,
		authManager: NewAuthManager(logger, jwtSecret),
		rbacManager: NewRBACManager(logger),
		status:      framework.PluginStatusUnknown,
	}, nil
}

// Plugin interface implementation

func (p *Provider) Name() string {
	return p.config.Name
}

func (p *Provider) Version() string {
	return "1.0.0"
}

func (p *Provider) Type() framework.PluginType {
	return framework.PluginTypeSecurity
}

func (p *Provider) Metadata() framework.PluginMetadata {
	return framework.PluginMetadata{
		StartTime: p.startTime,
		Uptime:    time.Since(p.startTime),
		Metadata: map[string]interface{}{
			"auth_type": "jwt",
			"rbac_type": "role-based",
		},
	}
}

func (p *Provider) Initialize(ctx context.Context, config framework.PluginConfig) error {
	p.status = framework.PluginStatusInitializing
	
	// Initialize from config
	if users, ok := config.Config["users"].([]interface{}); ok {
		for _, u := range users {
			if userMap, ok := u.(map[string]interface{}); ok {
				username := userMap["username"].(string)
				email := userMap["email"].(string)
				password := userMap["password"].(string)
				roles := []string{}
				if r, ok := userMap["roles"].([]interface{}); ok {
					for _, role := range r {
						if roleStr, ok := role.(string); ok {
							roles = append(roles, roleStr)
						}
					}
				}
				p.authManager.CreateUser(username, email, password, roles)
			}
		}
	}

	return nil
}

func (p *Provider) Start(ctx context.Context) error {
	p.status = framework.PluginStatusStarting
	p.startTime = time.Now()
	
	p.logger.Info("Security provider started")
	p.status = framework.PluginStatusRunning
	
	return nil
}

func (p *Provider) Stop(ctx context.Context) error {
	p.status = framework.PluginStatusStopping
	
	p.logger.Info("Security provider stopped")
	p.status = framework.PluginStatusStopped
	
	return nil
}

func (p *Provider) Reload(ctx context.Context, config framework.PluginConfig) error {
	p.config = config
	return nil
}

func (p *Provider) Health() framework.HealthStatus {
	status := "healthy"
	message := "Security provider is running"
	
	if p.status != framework.PluginStatusRunning {
		status = "unhealthy"
		message = "Security provider is not running"
	}
	
	return framework.HealthStatus{
		Status:    status,
		Message:   message,
		LastCheck: time.Now(),
		Metadata: map[string]interface{}{
			"uptime": time.Since(p.startTime).String(),
		},
	}
}

func (p *Provider) Metrics() framework.PluginMetrics {
	return framework.PluginMetrics{
		CPUUsage:    0.0,
		MemoryUsage: 0,
		RequestRate: 0.0,
		ErrorRate:   0.0,
		Timestamp:   time.Now(),
	}
}

func (p *Provider) ValidateConfig(config framework.PluginConfig) framework.ValidationResult {
	result := framework.ValidationResult{
		Valid: true,
	}
	
	// Warn if no JWT secret provided
	if _, hasSecret := config.Config["jwt_secret"]; !hasSecret {
		result.Warnings = append(result.Warnings, framework.ValidationError{
			Field:    "config.jwt_secret",
			Message:  "No JWT secret provided, a random one will be generated",
			Code:     "missing_secret",
			Severity: "warning",
		})
	}
	
	return result
}

// SecurityProvider interface implementation

func (p *Provider) Authenticate(ctx context.Context, req *framework.AuthenticationRequest) (*framework.AuthenticationResponse, error) {
	return p.authManager.Authenticate(ctx, req)
}

func (p *Provider) RefreshToken(ctx context.Context, req *framework.RefreshTokenRequest) (*framework.RefreshTokenResponse, error) {
	return p.authManager.RefreshToken(ctx, req)
}

func (p *Provider) RevokeToken(ctx context.Context, req *framework.RevokeTokenRequest) (*framework.RevokeTokenResponse, error) {
	return p.authManager.RevokeToken(ctx, req)
}

func (p *Provider) Authorize(ctx context.Context, req *framework.AuthorizationRequest) (*framework.AuthorizationResponse, error) {
	return p.rbacManager.Authorize(ctx, req)
}

func (p *Provider) GetPermissions(ctx context.Context, req *framework.GetPermissionsRequest) (*framework.GetPermissionsResponse, error) {
	return p.rbacManager.GetPermissions(ctx, req)
}

func (p *Provider) GetUser(ctx context.Context, req *framework.GetUserRequest) (*framework.GetUserResponse, error) {
	return p.authManager.GetUser(ctx, req)
}

func (p *Provider) ListRoles(ctx context.Context, req *framework.ListRolesRequest) (*framework.ListRolesResponse, error) {
	return p.rbacManager.ListRoles(ctx, req)
}

func (p *Provider) AssignRole(ctx context.Context, req *framework.AssignRoleRequest) (*framework.AssignRoleResponse, error) {
	return p.rbacManager.AssignRole(ctx, req)
}

// Additional methods exposed by the provider

func (p *Provider) GetAuthManager() *AuthManager {
	return p.authManager
}

func (p *Provider) GetRBACManager() *RBACManager {
	return p.rbacManager
}

func (p *Provider) ValidateToken(token string) (*Claims, error) {
	return p.authManager.ValidateToken(token)
}