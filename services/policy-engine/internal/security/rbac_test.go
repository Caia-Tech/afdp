package security

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/Caia-Tech/afdp/services/policy-engine/internal/logging"
	"github.com/Caia-Tech/afdp/services/policy-engine/pkg/framework"
)

func TestRBACManager(t *testing.T) {
	logger := logging.NewLogger("debug")

	t.Run("CreateRBACManager", func(t *testing.T) {
		rm := NewRBACManager(logger)
		assert.NotNil(t, rm)
		assert.NotNil(t, rm.roles)
		assert.NotNil(t, rm.userRoles)
		
		// Check default roles
		assert.NotEmpty(t, rm.roles)
		assert.Contains(t, rm.roles, "admin")
		assert.Contains(t, rm.roles, "operator")
		assert.Contains(t, rm.roles, "user")
	})

	t.Run("CreateRole", func(t *testing.T) {
		rm := NewRBACManager(logger)

		// Create new role
		role, err := rm.CreateRole("developer", "Developer role", []string{"code.read", "code.write"})
		assert.NoError(t, err)
		assert.NotNil(t, role)
		assert.Equal(t, "developer", role.Name)
		assert.Equal(t, "Developer role", role.Description)
		assert.Contains(t, role.Permissions, "code.read")
		assert.Contains(t, role.Permissions, "code.write")

		// Try to create duplicate role
		_, err = rm.CreateRole("developer", "Another dev role", []string{"deploy"})
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "role already exists")
	})

	t.Run("GetRole", func(t *testing.T) {
		rm := NewRBACManager(logger)
		ctx := context.Background()

		// Get existing role
		req := &framework.GetRoleRequest{RoleName: "admin"}
		resp, err := rm.GetRole(ctx, req)
		assert.NoError(t, err)
		assert.Equal(t, "admin", resp.Role.Name)
		assert.Contains(t, resp.Role.Permissions, "*")

		// Get non-existent role
		req.RoleName = "nonexistent"
		_, err = rm.GetRole(ctx, req)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "role not found")
	})

	t.Run("UpdateRole", func(t *testing.T) {
		rm := NewRBACManager(logger)

		// Create a role
		role, err := rm.CreateRole("test-role", "Test role", []string{"test.read"})
		require.NoError(t, err)

		// Update permissions
		newPermissions := []string{"test.read", "test.write", "test.delete"}
		err = rm.UpdateRole("test-role", newPermissions)
		assert.NoError(t, err)

		// Verify update
		assert.Equal(t, newPermissions, role.Permissions)
		assert.False(t, role.UpdatedAt.IsZero())

		// Update non-existent role
		err = rm.UpdateRole("nonexistent", []string{"perm"})
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "role not found")
	})

	t.Run("DeleteRole", func(t *testing.T) {
		rm := NewRBACManager(logger)
		ctx := context.Background()

		// Create a role
		_, err := rm.CreateRole("temp-role", "Temporary role", []string{"temp.access"})
		require.NoError(t, err)

		// Assign role to user
		_, err = rm.AssignRole(ctx, &framework.AssignRoleRequest{
			UserID: "user123",
			Role:   "temp-role",
		})
		require.NoError(t, err)

		// Delete role
		req := &framework.DeleteRoleRequest{RoleName: "temp-role"}
		resp, err := rm.DeleteRole(ctx, req)
		assert.NoError(t, err)
		assert.True(t, resp.Success)

		// Verify role is deleted
		_, exists := rm.roles["temp-role"]
		assert.False(t, exists)

		// Verify user role assignment is removed
		userRoles, exists := rm.userRoles["user123"]
		assert.True(t, exists)
		assert.NotContains(t, userRoles, "temp-role")

		// Try to delete protected role
		req.RoleName = "admin"
		_, err = rm.DeleteRole(ctx, req)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "cannot delete protected role")
	})

	t.Run("AssignRole", func(t *testing.T) {
		rm := NewRBACManager(logger)
		ctx := context.Background()

		// Assign existing role
		req := &framework.AssignRoleRequest{
			UserID: "user456",
			Role:   "operator",
		}
		resp, err := rm.AssignRole(ctx, req)
		assert.NoError(t, err)
		assert.True(t, resp.Success)

		// Verify assignment
		userRoles := rm.getUserRoles("user456")
		assert.Contains(t, userRoles, "operator")

		// Assign multiple roles
		req.Role = "user"
		resp, err = rm.AssignRole(ctx, req)
		assert.NoError(t, err)
		assert.True(t, resp.Success)

		userRoles = rm.getUserRoles("user456")
		assert.Len(t, userRoles, 2)
		assert.Contains(t, userRoles, "operator")
		assert.Contains(t, userRoles, "user")

		// Assign non-existent role
		req.Role = "nonexistent"
		_, err = rm.AssignRole(ctx, req)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "role not found")
	})

	t.Run("RevokeRole", func(t *testing.T) {
		rm := NewRBACManager(logger)
		ctx := context.Background()

		// Assign roles first
		userID := "user789"
		_, err := rm.AssignRole(ctx, &framework.AssignRoleRequest{
			UserID: userID,
			Role:   "admin",
		})
		require.NoError(t, err)
		_, err = rm.AssignRole(ctx, &framework.AssignRoleRequest{
			UserID: userID,
			Role:   "operator",
		})
		require.NoError(t, err)

		// Revoke one role
		req := &framework.RevokeRoleRequest{
			UserID: userID,
			Role:   "operator",
		}
		resp, err := rm.RevokeRole(ctx, req)
		assert.NoError(t, err)
		assert.True(t, resp.Success)

		// Verify revocation
		userRoles := rm.getUserRoles(userID)
		assert.Contains(t, userRoles, "admin")
		assert.NotContains(t, userRoles, "operator")

		// Revoke non-assigned role
		req.Role = "user"
		resp, err = rm.RevokeRole(ctx, req)
		assert.NoError(t, err)
		assert.False(t, resp.Success)
		assert.Contains(t, resp.Message, "user does not have role")
	})

	t.Run("CheckPermission", func(t *testing.T) {
		rm := NewRBACManager(logger)
		ctx := context.Background()

		// Setup user with roles
		userID := "perm-test-user"
		_, err := rm.AssignRole(ctx, &framework.AssignRoleRequest{
			UserID: userID,
			Role:   "operator",
		})
		require.NoError(t, err)

		// Check allowed permission
		req := &framework.CheckPermissionRequest{
			UserID:   userID,
			Resource: "policy",
			Action:   "read",
		}
		resp, err := rm.CheckPermission(ctx, req)
		assert.NoError(t, err)
		assert.True(t, resp.Allowed)

		// Check denied permission
		req.Action = "delete"
		resp, err = rm.CheckPermission(ctx, req)
		assert.NoError(t, err)
		assert.False(t, resp.Allowed)
		assert.Contains(t, resp.Reason, "insufficient permissions")

		// Check admin wildcard permission
		_, err = rm.AssignRole(ctx, &framework.AssignRoleRequest{
			UserID: userID,
			Role:   "admin",
		})
		require.NoError(t, err)

		req.Resource = "anything"
		req.Action = "everything"
		resp, err = rm.CheckPermission(ctx, req)
		assert.NoError(t, err)
		assert.True(t, resp.Allowed)
	})

	t.Run("GetUserRoles", func(t *testing.T) {
		rm := NewRBACManager(logger)
		ctx := context.Background()

		// Setup user with multiple roles
		userID := "multi-role-user"
		roles := []string{"user", "operator"}
		for _, role := range roles {
			_, err := rm.AssignRole(ctx, &framework.AssignRoleRequest{
				UserID: userID,
				Role:   role,
			})
			require.NoError(t, err)
		}

		// Get user roles
		req := &framework.GetUserRolesRequest{UserID: userID}
		resp, err := rm.GetUserRoles(ctx, req)
		assert.NoError(t, err)
		assert.ElementsMatch(t, roles, resp.Roles)

		// Get roles for non-existent user
		req.UserID = "nonexistent"
		resp, err = rm.GetUserRoles(ctx, req)
		assert.NoError(t, err)
		assert.Empty(t, resp.Roles)
	})

	t.Run("ListRoles", func(t *testing.T) {
		rm := NewRBACManager(logger)
		ctx := context.Background()

		// Create additional roles
		_, err := rm.CreateRole("custom1", "Custom role 1", []string{"custom.read"})
		require.NoError(t, err)
		_, err = rm.CreateRole("custom2", "Custom role 2", []string{"custom.write"})
		require.NoError(t, err)

		// List all roles
		req := &framework.ListRolesRequest{}
		resp, err := rm.ListRoles(ctx, req)
		assert.NoError(t, err)
		assert.GreaterOrEqual(t, len(resp.Roles), 5) // admin, operator, user, custom1, custom2

		// Verify role details
		roleNames := make([]string, len(resp.Roles))
		for i, role := range resp.Roles {
			roleNames[i] = role.Name
		}
		assert.Contains(t, roleNames, "admin")
		assert.Contains(t, roleNames, "operator")
		assert.Contains(t, roleNames, "user")
		assert.Contains(t, roleNames, "custom1")
		assert.Contains(t, roleNames, "custom2")
	})

	t.Run("PermissionMatching", func(t *testing.T) {
		rm := NewRBACManager(logger)

		testCases := []struct {
			permission string
			resource   string
			action     string
			expected   bool
		}{
			// Exact match
			{"policy.read", "policy", "read", true},
			{"policy.write", "policy", "write", true},
			
			// Wildcard resource
			{"*.read", "policy", "read", true},
			{"*.read", "user", "read", true},
			{"*.read", "policy", "write", false},
			
			// Wildcard action
			{"policy.*", "policy", "read", true},
			{"policy.*", "policy", "write", true},
			{"policy.*", "user", "read", false},
			
			// Full wildcard
			{"*", "anything", "everything", true},
			
			// No match
			{"policy.read", "user", "read", false},
			{"policy.read", "policy", "write", false},
		}

		for _, tc := range testCases {
			result := rm.hasPermission([]string{tc.permission}, tc.resource, tc.action)
			assert.Equal(t, tc.expected, result, 
				"Permission %s should %v match %s.%s", 
				tc.permission, 
				map[bool]string{true: "should", false: "should not"}[tc.expected],
				tc.resource, 
				tc.action)
		}
	})

	t.Run("ConcurrentAccess", func(t *testing.T) {
		rm := NewRBACManager(logger)
		ctx := context.Background()

		// Test concurrent role assignments
		done := make(chan bool, 10)
		for i := 0; i < 10; i++ {
			go func(idx int) {
				userID := fmt.Sprintf("concurrent-user-%d", idx)
				req := &framework.AssignRoleRequest{
					UserID: userID,
					Role:   "user",
				}
				_, err := rm.AssignRole(ctx, req)
				assert.NoError(t, err)
				done <- true
			}(i)
		}

		// Wait for all goroutines
		for i := 0; i < 10; i++ {
			<-done
		}

		// Verify all assignments succeeded
		for i := 0; i < 10; i++ {
			userID := fmt.Sprintf("concurrent-user-%d", i)
			roles := rm.getUserRoles(userID)
			assert.Contains(t, roles, "user")
		}
	})
}

func TestRBACIntegration(t *testing.T) {
	logger := logging.NewLogger("debug")
	rm := NewRBACManager(logger)
	ctx := context.Background()

	t.Run("CompleteWorkflow", func(t *testing.T) {
		// Create custom role
		_, err := rm.CreateRole("developer", "Developer with limited access", []string{
			"code.read",
			"code.write",
			"policy.read",
			"metrics.read",
		})
		require.NoError(t, err)

		// Assign role to user
		userID := "dev-user-123"
		_, err = rm.AssignRole(ctx, &framework.AssignRoleRequest{
			UserID: userID,
			Role:   "developer",
		})
		require.NoError(t, err)

		// Check various permissions
		permissions := []struct {
			resource string
			action   string
			allowed  bool
		}{
			{"code", "read", true},
			{"code", "write", true},
			{"code", "delete", false},
			{"policy", "read", true},
			{"policy", "write", false},
			{"metrics", "read", true},
			{"users", "manage", false},
		}

		for _, perm := range permissions {
			resp, err := rm.CheckPermission(ctx, &framework.CheckPermissionRequest{
				UserID:   userID,
				Resource: perm.resource,
				Action:   perm.action,
			})
			require.NoError(t, err)
			assert.Equal(t, perm.allowed, resp.Allowed,
				"Permission check for %s.%s should be %v",
				perm.resource, perm.action, perm.allowed)
		}

		// Update role permissions
		err = rm.UpdateRole("developer", []string{
			"code.*",      // All code permissions
			"policy.read",
			"metrics.read",
			"deploy.staging", // New permission
		})
		require.NoError(t, err)

		// Check updated permissions
		resp, err := rm.CheckPermission(ctx, &framework.CheckPermissionRequest{
			UserID:   userID,
			Resource: "code",
			Action:   "delete",
		})
		require.NoError(t, err)
		assert.True(t, resp.Allowed) // Now allowed due to code.*

		resp, err = rm.CheckPermission(ctx, &framework.CheckPermissionRequest{
			UserID:   userID,
			Resource: "deploy",
			Action:   "staging",
		})
		require.NoError(t, err)
		assert.True(t, resp.Allowed)

		// Revoke role
		_, err = rm.RevokeRole(ctx, &framework.RevokeRoleRequest{
			UserID: userID,
			Role:   "developer",
		})
		require.NoError(t, err)

		// Check permissions after revocation
		resp, err = rm.CheckPermission(ctx, &framework.CheckPermissionRequest{
			UserID:   userID,
			Resource: "code",
			Action:   "read",
		})
		require.NoError(t, err)
		assert.False(t, resp.Allowed)
	})
}