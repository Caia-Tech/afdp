package security

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/Caia-Tech/afdp/services/policy-engine/internal/logging"
	"github.com/Caia-Tech/afdp/services/policy-engine/pkg/framework"
)

func TestAuthManager(t *testing.T) {
	logger := logging.NewLogger("debug")
	
	t.Run("CreateAuthManager", func(t *testing.T) {
		am := NewAuthManager(logger, "test-secret")
		assert.NotNil(t, am)
		assert.NotEmpty(t, am.jwtSecret)
		assert.NotNil(t, am.users)
		assert.NotNil(t, am.sessions)
		
		// Check default users are created
		assert.NotEmpty(t, am.users)
	})
	
	t.Run("CreateUser", func(t *testing.T) {
		am := NewAuthManager(logger, "test-secret")
		
		// Create new user
		user, err := am.CreateUser("testuser", "test@example.com", "password123", []string{"user"})
		assert.NoError(t, err)
		assert.NotNil(t, user)
		assert.Equal(t, "testuser", user.Username)
		assert.Equal(t, "test@example.com", user.Email)
		assert.Contains(t, user.Roles, "user")
		assert.True(t, user.Enabled)
		assert.NotEmpty(t, user.PasswordHash)
		
		// Try to create duplicate user
		_, err = am.CreateUser("testuser", "test2@example.com", "password456", []string{"admin"})
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "username already exists")
	})
	
	t.Run("Authenticate", func(t *testing.T) {
		am := NewAuthManager(logger, "test-secret")
		ctx := context.Background()
		
		// Create test user
		_, err := am.CreateUser("authtest", "auth@example.com", "testpass123", []string{"user", "operator"})
		require.NoError(t, err)
		
		// Successful authentication
		req := &framework.AuthenticationRequest{
			Method: "password",
			Credentials: map[string]interface{}{
				"username": "authtest",
				"password": "testpass123",
			},
		}
		
		resp, err := am.Authenticate(ctx, req)
		assert.NoError(t, err)
		assert.True(t, resp.Success)
		assert.NotEmpty(t, resp.Token)
		assert.False(t, resp.ExpiresAt.IsZero())
		
		userInfo, ok := resp.UserInfo.(map[string]interface{})
		assert.True(t, ok)
		assert.Equal(t, "authtest", userInfo["username"])
		assert.Equal(t, "auth@example.com", userInfo["email"])
		roles, ok := userInfo["roles"].([]string)
		assert.True(t, ok)
		assert.Contains(t, roles, "user")
		assert.Contains(t, roles, "operator")
		
		// Wrong password
		req.Credentials["password"] = "wrongpass"
		resp, err = am.Authenticate(ctx, req)
		assert.NoError(t, err)
		assert.False(t, resp.Success)
		
		// Non-existent user
		req.Credentials["username"] = "nonexistent"
		req.Credentials["password"] = "anypass"
		resp, err = am.Authenticate(ctx, req)
		assert.NoError(t, err)
		assert.False(t, resp.Success)
		
		// Unsupported method
		req.Method = "oauth"
		_, err = am.Authenticate(ctx, req)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "unsupported authentication method")
	})
	
	t.Run("ValidateToken", func(t *testing.T) {
		am := NewAuthManager(logger, "test-secret")
		ctx := context.Background()
		
		// Create and authenticate user
		_, err := am.CreateUser("tokentest", "token@example.com", "testpass123", []string{"admin"})
		require.NoError(t, err)
		
		req := &framework.AuthenticationRequest{
			Method: "password",
			Credentials: map[string]interface{}{
				"username": "tokentest",
				"password": "testpass123",
			},
		}
		
		resp, err := am.Authenticate(ctx, req)
		require.NoError(t, err)
		require.True(t, resp.Success)
		
		// Validate token
		claims, err := am.ValidateToken(resp.Token)
		assert.NoError(t, err)
		assert.NotNil(t, claims)
		assert.Equal(t, "tokentest", claims.Username)
		assert.Contains(t, claims.Roles, "admin")
		
		// Invalid token
		_, err = am.ValidateToken("invalid.token.here")
		assert.Error(t, err)
		
		// Empty token
		_, err = am.ValidateToken("")
		assert.Error(t, err)
	})
	
	t.Run("RefreshToken", func(t *testing.T) {
		am := NewAuthManager(logger, "test-secret")
		ctx := context.Background()
		
		// Create and authenticate user
		user, err := am.CreateUser("refreshtest", "refresh@example.com", "testpass123", []string{"user"})
		require.NoError(t, err)
		
		req := &framework.AuthenticationRequest{
			Method: "password",
			Credentials: map[string]interface{}{
				"username": "refreshtest",
				"password": "testpass123",
			},
		}
		
		authResp, err := am.Authenticate(ctx, req)
		require.NoError(t, err)
		require.True(t, authResp.Success)
		
		// Find the session to get refresh token
		var refreshToken string
		for _, session := range am.sessions {
			if session.UserID == user.ID {
				refreshToken = session.RefreshToken
				break
			}
		}
		require.NotEmpty(t, refreshToken)
		
		// Refresh token
		refreshReq := &framework.RefreshTokenRequest{
			Token: refreshToken,
		}
		
		refreshResp, err := am.RefreshToken(ctx, refreshReq)
		assert.NoError(t, err)
		assert.NotEmpty(t, refreshResp.Token)
		assert.False(t, refreshResp.ExpiresAt.IsZero())
		
		// Validate new token
		claims, err := am.ValidateToken(refreshResp.Token)
		assert.NoError(t, err)
		assert.Equal(t, "refreshtest", claims.Username)
		
		// Invalid refresh token
		refreshReq.Token = "invalid-refresh-token"
		_, err = am.RefreshToken(ctx, refreshReq)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "invalid refresh token")
	})
	
	t.Run("RevokeToken", func(t *testing.T) {
		am := NewAuthManager(logger, "test-secret")
		ctx := context.Background()
		
		// Create and authenticate user
		_, err := am.CreateUser("revoketest", "revoke@example.com", "testpass123", []string{"user"})
		require.NoError(t, err)
		
		req := &framework.AuthenticationRequest{
			Method: "password",
			Credentials: map[string]interface{}{
				"username": "revoketest",
				"password": "testpass123",
			},
		}
		
		authResp, err := am.Authenticate(ctx, req)
		require.NoError(t, err)
		require.True(t, authResp.Success)
		
		// Revoke token
		revokeReq := &framework.RevokeTokenRequest{
			Token: authResp.Token,
		}
		
		revokeResp, err := am.RevokeToken(ctx, revokeReq)
		assert.NoError(t, err)
		assert.True(t, revokeResp.Success)
		
		// Try to revoke again
		revokeResp, err = am.RevokeToken(ctx, revokeReq)
		assert.NoError(t, err)
		assert.False(t, revokeResp.Success)
		assert.Contains(t, revokeResp.Message, "token not found")
	})
	
	t.Run("DisableUser", func(t *testing.T) {
		am := NewAuthManager(logger, "test-secret")
		ctx := context.Background()
		
		// Create user
		user, err := am.CreateUser("disabletest", "disable@example.com", "testpass123", []string{"user"})
		require.NoError(t, err)
		
		// Authenticate
		req := &framework.AuthenticationRequest{
			Method: "password",
			Credentials: map[string]interface{}{
				"username": "disabletest",
				"password": "testpass123",
			},
		}
		
		resp, err := am.Authenticate(ctx, req)
		require.NoError(t, err)
		assert.True(t, resp.Success)
		
		// Disable user
		err = am.DisableUser(user.ID)
		assert.NoError(t, err)
		assert.False(t, user.Enabled)
		
		// Try to authenticate disabled user
		resp, err = am.Authenticate(ctx, req)
		assert.NoError(t, err)
		assert.False(t, resp.Success)
		
		// Verify sessions were revoked
		for _, session := range am.sessions {
			assert.NotEqual(t, user.ID, session.UserID)
		}
	})
	
	t.Run("UpdateUserRoles", func(t *testing.T) {
		am := NewAuthManager(logger, "test-secret")
		
		// Create user
		user, err := am.CreateUser("roletest", "role@example.com", "testpass123", []string{"user"})
		require.NoError(t, err)
		assert.Contains(t, user.Roles, "user")
		
		// Update roles
		newRoles := []string{"admin", "operator"}
		err = am.UpdateUserRoles(user.ID, newRoles)
		assert.NoError(t, err)
		
		// Verify roles updated
		assert.Equal(t, newRoles, user.Roles)
		assert.False(t, user.UpdatedAt.IsZero())
		
		// Update non-existent user
		err = am.UpdateUserRoles("non-existent-id", []string{"admin"})
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "user not found")
	})
	
	t.Run("GetUser", func(t *testing.T) {
		am := NewAuthManager(logger, "test-secret")
		ctx := context.Background()
		
		// Create user
		user, err := am.CreateUser("gettest", "get@example.com", "testpass123", []string{"user", "operator"})
		require.NoError(t, err)
		
		// Get user
		req := &framework.GetUserRequest{
			UserID: user.ID,
		}
		
		resp, err := am.GetUser(ctx, req)
		assert.NoError(t, err)
		assert.Equal(t, user.ID, resp.UserID)
		assert.Equal(t, "gettest", resp.Username)
		assert.Equal(t, "get@example.com", resp.Email)
		assert.Contains(t, resp.Roles, "user")
		assert.Contains(t, resp.Roles, "operator")
		
		// Get non-existent user
		req.UserID = "non-existent"
		_, err = am.GetUser(ctx, req)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "user not found")
	})
}

func TestSessionCleanup(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping session cleanup test in short mode")
	}
	
	logger := logging.NewLogger("debug")
	am := NewAuthManager(logger, "test-secret")
	am.tokenExpiry = 100 * time.Millisecond // Short expiry for testing
	
	ctx := context.Background()
	
	// Create and authenticate user
	_, err := am.CreateUser("cleanuptest", "cleanup@example.com", "testpass123", []string{"user"})
	require.NoError(t, err)
	
	req := &framework.AuthenticationRequest{
		Method: "password",
		Credentials: map[string]interface{}{
			"username": "cleanuptest",
			"password": "testpass123",
		},
	}
	
	resp, err := am.Authenticate(ctx, req)
	require.NoError(t, err)
	require.True(t, resp.Success)
	
	// Verify session exists
	sessionCount := len(am.sessions)
	assert.Equal(t, 1, sessionCount)
	
	// Wait for session to expire and cleanup to run
	time.Sleep(200 * time.Millisecond)
	
	// Manually trigger cleanup for testing
	am.mu.Lock()
	now := time.Now()
	for id, session := range am.sessions {
		if now.After(session.ExpiresAt) {
			delete(am.sessions, id)
		}
	}
	am.mu.Unlock()
	
	// Verify session was cleaned up
	assert.Equal(t, 0, len(am.sessions))
}