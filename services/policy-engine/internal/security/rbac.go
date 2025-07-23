package security

import (
	"context"
	"fmt"
	"sync"

	"github.com/Caia-Tech/afdp/services/policy-engine/internal/logging"
	"github.com/Caia-Tech/afdp/services/policy-engine/pkg/framework"
)

// RBACManager handles role-based access control
type RBACManager struct {
	logger      *logging.Logger
	roles       map[string]*Role
	permissions map[string]*Permission
	policies    map[string]*Policy
	mu          sync.RWMutex
}

// Role represents a user role
type Role struct {
	Name        string                 `json:"name"`
	Description string                 `json:"description"`
	Permissions []string               `json:"permissions"`
	Inherits    []string               `json:"inherits"`
	Metadata    map[string]interface{} `json:"metadata"`
}

// Permission represents an action permission
type Permission struct {
	Name        string   `json:"name"`
	Description string   `json:"description"`
	Resource    string   `json:"resource"`
	Actions     []string `json:"actions"`
}

// Policy represents an access control policy
type Policy struct {
	Name        string                 `json:"name"`
	Description string                 `json:"description"`
	Effect      string                 `json:"effect"` // allow or deny
	Resources   []string               `json:"resources"`
	Actions     []string               `json:"actions"`
	Conditions  map[string]interface{} `json:"conditions"`
	Priority    int                    `json:"priority"`
}

// NewRBACManager creates a new RBAC manager
func NewRBACManager(logger *logging.Logger) *RBACManager {
	rm := &RBACManager{
		logger:      logger,
		roles:       make(map[string]*Role),
		permissions: make(map[string]*Permission),
		policies:    make(map[string]*Policy),
	}

	// Initialize default roles and permissions
	rm.initializeDefaults()

	return rm
}

// Authorize checks if a user is authorized to perform an action
func (rm *RBACManager) Authorize(ctx context.Context, req *framework.AuthorizationRequest) (*framework.AuthorizationResponse, error) {
	rm.mu.RLock()
	defer rm.mu.RUnlock()

	// Get user from context (would be set by auth middleware)
	claims, ok := ctx.Value("claims").(*Claims)
	if !ok {
		return &framework.AuthorizationResponse{
			Allowed: false,
			Reason:  "no authentication context",
		}, nil
	}

	// Check if user has required permission
	allowed := rm.checkPermission(claims.Roles, req.Resource, req.Action)

	response := &framework.AuthorizationResponse{
		Allowed: allowed,
		Roles:   claims.Roles,
	}

	if !allowed {
		response.Reason = fmt.Sprintf("user lacks permission for %s on %s", req.Action, req.Resource)
	}

	rm.logger.Debug("Authorization check",
		"user_id", claims.UserID,
		"resource", req.Resource,
		"action", req.Action,
		"allowed", allowed,
	)

	return response, nil
}

// GetPermissions returns permissions for a user
func (rm *RBACManager) GetPermissions(ctx context.Context, req *framework.GetPermissionsRequest) (*framework.GetPermissionsResponse, error) {
	rm.mu.RLock()
	defer rm.mu.RUnlock()

	// Get user roles (would typically come from user service)
	userRoles := []string{"user"} // Default

	// Collect all permissions
	permissionSet := make(map[string]*framework.Permission)

	for _, roleName := range userRoles {
		rm.collectRolePermissions(roleName, permissionSet, make(map[string]bool))
	}

	// Convert to slice
	permissions := make([]framework.Permission, 0, len(permissionSet))
	for _, perm := range permissionSet {
		permissions = append(permissions, *perm)
	}

	return &framework.GetPermissionsResponse{
		Permissions: permissions,
	}, nil
}

// ListRoles returns all available roles
func (rm *RBACManager) ListRoles(ctx context.Context, req *framework.ListRolesRequest) (*framework.ListRolesResponse, error) {
	rm.mu.RLock()
	defer rm.mu.RUnlock()

	roles := make([]framework.RoleInfo, 0, len(rm.roles))
	for _, role := range rm.roles {
		roles = append(roles, framework.RoleInfo{
			Name:        role.Name,
			Description: role.Description,
			Permissions: role.Permissions,
		})
	}

	return &framework.ListRolesResponse{
		Roles: roles,
	}, nil
}

// AssignRole assigns a role to a user
func (rm *RBACManager) AssignRole(ctx context.Context, req *framework.AssignRoleRequest) (*framework.AssignRoleResponse, error) {
	rm.mu.RLock()
	defer rm.mu.RUnlock()

	// Check if role exists
	if _, exists := rm.roles[req.Role]; !exists {
		return &framework.AssignRoleResponse{
			Success: false,
			Message: fmt.Sprintf("role %s not found", req.Role),
		}, nil
	}

	// In a real implementation, would update user-role mapping in database
	rm.logger.Info("Role assigned",
		"user_id", req.UserID,
		"role", req.Role,
	)

	return &framework.AssignRoleResponse{
		Success: true,
		Message: "role assigned successfully",
	}, nil
}

// CreateRole creates a new role
func (rm *RBACManager) CreateRole(name, description string, permissions []string, inherits []string) error {
	rm.mu.Lock()
	defer rm.mu.Unlock()

	if _, exists := rm.roles[name]; exists {
		return fmt.Errorf("role %s already exists", name)
	}

	role := &Role{
		Name:        name,
		Description: description,
		Permissions: permissions,
		Inherits:    inherits,
		Metadata:    make(map[string]interface{}),
	}

	rm.roles[name] = role
	rm.logger.Info("Role created", "name", name)

	return nil
}

// CreatePermission creates a new permission
func (rm *RBACManager) CreatePermission(name, description, resource string, actions []string) error {
	rm.mu.Lock()
	defer rm.mu.Unlock()

	if _, exists := rm.permissions[name]; exists {
		return fmt.Errorf("permission %s already exists", name)
	}

	permission := &Permission{
		Name:        name,
		Description: description,
		Resource:    resource,
		Actions:     actions,
	}

	rm.permissions[name] = permission
	rm.logger.Info("Permission created", "name", name)

	return nil
}

// CreatePolicy creates a new access control policy
func (rm *RBACManager) CreatePolicy(name, description, effect string, resources, actions []string, priority int) error {
	rm.mu.Lock()
	defer rm.mu.Unlock()

	if _, exists := rm.policies[name]; exists {
		return fmt.Errorf("policy %s already exists", name)
	}

	policy := &Policy{
		Name:        name,
		Description: description,
		Effect:      effect,
		Resources:   resources,
		Actions:     actions,
		Conditions:  make(map[string]interface{}),
		Priority:    priority,
	}

	rm.policies[name] = policy
	rm.logger.Info("Policy created", "name", name)

	return nil
}

// Helper methods

func (rm *RBACManager) checkPermission(roles []string, resource, action string) bool {
	// Collect all permissions for user's roles
	permissionSet := make(map[string]*framework.Permission)
	for _, roleName := range roles {
		rm.collectRolePermissions(roleName, permissionSet, make(map[string]bool))
	}

	// Check if any permission allows the action on the resource
	for _, perm := range permissionSet {
		if rm.matchesResource(perm.Resource, resource) {
			for _, permAction := range perm.Actions {
				if permAction == "*" || permAction == action {
					return true
				}
			}
		}
	}

	// Check policies
	return rm.evaluatePolicies(roles, resource, action)
}

func (rm *RBACManager) collectRolePermissions(roleName string, permissionSet map[string]*framework.Permission, visited map[string]bool) {
	// Prevent circular inheritance
	if visited[roleName] {
		return
	}
	visited[roleName] = true

	role, exists := rm.roles[roleName]
	if !exists {
		return
	}

	// Add direct permissions
	for _, permName := range role.Permissions {
		if perm, exists := rm.permissions[permName]; exists {
			permissionSet[permName] = &framework.Permission{
				Resource: perm.Resource,
				Actions:  perm.Actions,
			}
		}
	}

	// Process inherited roles
	for _, inheritedRole := range role.Inherits {
		rm.collectRolePermissions(inheritedRole, permissionSet, visited)
	}
}

func (rm *RBACManager) evaluatePolicies(roles []string, resource, action string) bool {
	// Evaluate policies in priority order
	var allowPolicies, denyPolicies []*Policy

	for _, policy := range rm.policies {
		if rm.policyApplies(policy, resource, action) {
			if policy.Effect == "allow" {
				allowPolicies = append(allowPolicies, policy)
			} else {
				denyPolicies = append(denyPolicies, policy)
			}
		}
	}

	// Explicit deny takes precedence
	for _, policy := range denyPolicies {
		if rm.evaluateConditions(policy.Conditions, roles) {
			return false
		}
	}

	// Check for explicit allow
	for _, policy := range allowPolicies {
		if rm.evaluateConditions(policy.Conditions, roles) {
			return true
		}
	}

	// Default deny
	return false
}

func (rm *RBACManager) policyApplies(policy *Policy, resource, action string) bool {
	// Check if policy applies to resource
	resourceMatch := false
	for _, policyResource := range policy.Resources {
		if rm.matchesResource(policyResource, resource) {
			resourceMatch = true
			break
		}
	}

	if !resourceMatch {
		return false
	}

	// Check if policy applies to action
	for _, policyAction := range policy.Actions {
		if policyAction == "*" || policyAction == action {
			return true
		}
	}

	return false
}

func (rm *RBACManager) matchesResource(pattern, resource string) bool {
	// Simple pattern matching - in production, use proper glob matching
	if pattern == "*" {
		return true
	}
	return pattern == resource
}

func (rm *RBACManager) evaluateConditions(conditions map[string]interface{}, roles []string) bool {
	// Simple condition evaluation - in production, use proper condition engine
	if len(conditions) == 0 {
		return true
	}

	// Example: Check role condition
	if requiredRoles, ok := conditions["roles"].([]string); ok {
		for _, requiredRole := range requiredRoles {
			hasRole := false
			for _, userRole := range roles {
				if userRole == requiredRole {
					hasRole = true
					break
				}
			}
			if !hasRole {
				return false
			}
		}
	}

	return true
}

func (rm *RBACManager) initializeDefaults() {
	// Create default permissions
	rm.CreatePermission("policy.read", "Read policies", "policy", []string{"read", "list"})
	rm.CreatePermission("policy.write", "Write policies", "policy", []string{"create", "update", "delete"})
	rm.CreatePermission("policy.evaluate", "Evaluate policies", "policy", []string{"evaluate"})
	
	rm.CreatePermission("plugin.read", "Read plugins", "plugin", []string{"read", "list"})
	rm.CreatePermission("plugin.write", "Manage plugins", "plugin", []string{"create", "update", "delete"})
	
	rm.CreatePermission("framework.admin", "Administer framework", "framework", []string{"*"})
	
	rm.CreatePermission("user.read", "Read users", "user", []string{"read", "list"})
	rm.CreatePermission("user.write", "Manage users", "user", []string{"create", "update", "delete"})

	// Create default roles
	rm.CreateRole("admin", "Administrator role", 
		[]string{"framework.admin", "policy.write", "plugin.write", "user.write"},
		[]string{})
	
	rm.CreateRole("operator", "Operator role",
		[]string{"policy.read", "policy.evaluate", "plugin.read"},
		[]string{})
	
	rm.CreateRole("user", "Basic user role",
		[]string{"policy.read", "policy.evaluate"},
		[]string{})
	
	rm.CreateRole("service", "Service account role",
		[]string{"policy.evaluate"},
		[]string{})

	// Create default policies
	rm.CreatePolicy("deny-disabled-users", "Deny access to disabled users", "deny",
		[]string{"*"}, []string{"*"}, 100)
	
	rm.CreatePolicy("allow-admin-all", "Allow admins full access", "allow",
		[]string{"*"}, []string{"*"}, 50)
}