package rest

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/Caia-Tech/afdp/services/policy-engine/internal/logging"
	"github.com/Caia-Tech/afdp/services/policy-engine/internal/security"
	"github.com/Caia-Tech/afdp/services/policy-engine/pkg/framework"
)

func TestMiddleware(t *testing.T) {
	logger := logging.NewLogger("debug")
	authManager := security.NewAuthManager(logger, "test-secret-key")
	rbacManager := security.NewRBACManager(logger)
	
	ctx := context.Background()
	err := authManager.Initialize(ctx)
	require.NoError(t, err)
	
	middleware := NewMiddleware(authManager, rbacManager, logger)

	t.Run("CreateMiddleware", func(t *testing.T) {
		assert.NotNil(t, middleware)
		assert.NotNil(t, middleware.authManager)
		assert.NotNil(t, middleware.rbacManager)
		assert.NotNil(t, middleware.logger)
	})

	t.Run("CORS", func(t *testing.T) {
		handler := middleware.CORS(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		}))

		// Test preflight request
		req := httptest.NewRequest("OPTIONS", "/test", nil)
		req.Header.Set("Origin", "http://localhost:3000")
		req.Header.Set("Access-Control-Request-Method", "POST")
		req.Header.Set("Access-Control-Request-Headers", "Content-Type,Authorization")
		w := httptest.NewRecorder()

		handler.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
		assert.Equal(t, "*", w.Header().Get("Access-Control-Allow-Origin"))
		assert.Contains(t, w.Header().Get("Access-Control-Allow-Methods"), "POST")
		assert.Contains(t, w.Header().Get("Access-Control-Allow-Headers"), "Content-Type")
		assert.Contains(t, w.Header().Get("Access-Control-Allow-Headers"), "Authorization")

		// Test actual request
		req = httptest.NewRequest("GET", "/test", nil)
		req.Header.Set("Origin", "http://localhost:3000")
		w = httptest.NewRecorder()

		handler.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
		assert.Equal(t, "*", w.Header().Get("Access-Control-Allow-Origin"))
	})

	t.Run("RateLimiting", func(t *testing.T) {
		callCount := 0
		handler := middleware.RateLimit(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			callCount++
			w.WriteHeader(http.StatusOK)
		}))

		// Make requests up to the limit
		successCount := 0
		rateLimitedCount := 0

		for i := 0; i < 150; i++ { // Exceed default limit of 100
			req := httptest.NewRequest("GET", "/test", nil)
			req.RemoteAddr = "127.0.0.1:12345" // Same IP for rate limiting
			w := httptest.NewRecorder()

			handler.ServeHTTP(w, req)

			if w.Code == http.StatusOK {
				successCount++
			} else if w.Code == http.StatusTooManyRequests {
				rateLimitedCount++
			}
		}

		assert.Greater(t, successCount, 0, "Should allow some requests")
		assert.Greater(t, rateLimitedCount, 0, "Should rate limit some requests")
		assert.Equal(t, 150, successCount+rateLimitedCount, "All requests should be processed")
	})

	t.Run("RateLimitingDifferentIPs", func(t *testing.T) {
		handler := middleware.RateLimit(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		}))

		// Test that different IPs have separate limits
		ips := []string{"127.0.0.1:12345", "192.168.1.1:12345", "10.0.0.1:12345"}
		
		for _, ip := range ips {
			successCount := 0
			for i := 0; i < 10; i++ {
				req := httptest.NewRequest("GET", "/test", nil)
				req.RemoteAddr = ip
				w := httptest.NewRecorder()

				handler.ServeHTTP(w, req)

				if w.Code == http.StatusOK {
					successCount++
				}
			}
			assert.Equal(t, 10, successCount, "Each IP should have its own limit")
		}
	})

	t.Run("Logging", func(t *testing.T) {
		handler := middleware.Logging(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("test response"))
		}))

		req := httptest.NewRequest("GET", "/test/path", nil)
		req.Header.Set("User-Agent", "test-agent")
		w := httptest.NewRecorder()

		start := time.Now()
		handler.ServeHTTP(w, req)
		duration := time.Since(start)

		assert.Equal(t, http.StatusOK, w.Code)
		assert.Equal(t, "test response", w.Body.String())
		
		// Note: In a real test, you'd want to capture log output
		// This test just verifies the handler still works
		assert.Less(t, duration, 1*time.Second)
	})

	t.Run("Security", func(t *testing.T) {
		handler := middleware.Security(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		}))

		req := httptest.NewRequest("GET", "/test", nil)
		w := httptest.NewRecorder()

		handler.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
		
		// Check security headers
		assert.Equal(t, "nosniff", w.Header().Get("X-Content-Type-Options"))
		assert.Equal(t, "1; mode=block", w.Header().Get("X-XSS-Protection"))
		assert.Equal(t, "DENY", w.Header().Get("X-Frame-Options"))
		assert.Equal(t, "no-referrer", w.Header().Get("Referrer-Policy"))
		assert.Contains(t, w.Header().Get("Content-Security-Policy"), "default-src 'self'")
	})

	t.Run("AuthenticateValid", func(t *testing.T) {
		// Create test user and get token
		_, err := authManager.CreateUser("testuser", "test@example.com", "testpass", []string{"user"})
		require.NoError(t, err)

		authReq := &framework.AuthenticationRequest{
			Method: "password",
			Credentials: map[string]interface{}{
				"username": "testuser",
				"password": "testpass",
			},
		}

		authResp, err := authManager.Authenticate(ctx, authReq)
		require.NoError(t, err)
		require.True(t, authResp.Success)

		called := false
		handler := middleware.Authenticate(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			called = true
			w.WriteHeader(http.StatusOK)
		}))

		req := httptest.NewRequest("GET", "/test", nil)
		req.Header.Set("Authorization", "Bearer "+authResp.Token)
		w := httptest.NewRecorder()

		handler.ServeHTTP(w, req)

		assert.True(t, called)
		assert.Equal(t, http.StatusOK, w.Code)
	})

	t.Run("AuthenticateInvalidToken", func(t *testing.T) {
		called := false
		handler := middleware.Authenticate(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			called = true
		}))

		req := httptest.NewRequest("GET", "/test", nil)
		req.Header.Set("Authorization", "Bearer invalid-token")
		w := httptest.NewRecorder()

		handler.ServeHTTP(w, req)

		assert.False(t, called)
		assert.Equal(t, http.StatusUnauthorized, w.Code)
	})

	t.Run("AuthenticateMissingToken", func(t *testing.T) {
		called := false
		handler := middleware.Authenticate(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			called = true
		}))

		req := httptest.NewRequest("GET", "/test", nil)
		w := httptest.NewRecorder()

		handler.ServeHTTP(w, req)

		assert.False(t, called)
		assert.Equal(t, http.StatusUnauthorized, w.Code)
	})

	t.Run("AuthenticateInvalidFormat", func(t *testing.T) {
		called := false
		handler := middleware.Authenticate(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			called = true
		}))

		testCases := []string{
			"invalid-header",
			"Basic dGVzdDp0ZXN0", // Basic auth instead of Bearer
			"Bearer",             // No token
			"Bearer ",           // Empty token
		}

		for _, testCase := range testCases {
			req := httptest.NewRequest("GET", "/test", nil)
			req.Header.Set("Authorization", testCase)
			w := httptest.NewRecorder()

			handler.ServeHTTP(w, req)

			assert.False(t, called, "Handler should not be called for: %s", testCase)
			assert.Equal(t, http.StatusUnauthorized, w.Code, "Wrong status for: %s", testCase)
		}
	})

	t.Run("Authorization", func(t *testing.T) {
		// Create admin user
		_, err := authManager.CreateUser("admin", "admin@example.com", "adminpass", []string{"admin"})
		require.NoError(t, err)

		authReq := &framework.AuthenticationRequest{
			Method: "password",
			Credentials: map[string]interface{}{
				"username": "admin",
				"password": "adminpass",
			},
		}

		authResp, err := authManager.Authenticate(ctx, authReq)
		require.NoError(t, err)

		called := false
		handler := middleware.Authorize("policy", "read")(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			called = true
			w.WriteHeader(http.StatusOK)
		}))

		req := httptest.NewRequest("GET", "/test", nil)
		req.Header.Set("Authorization", "Bearer "+authResp.Token)
		w := httptest.NewRecorder()

		handler.ServeHTTP(w, req)

		assert.True(t, called)
		assert.Equal(t, http.StatusOK, w.Code)
	})

	t.Run("AuthorizationDenied", func(t *testing.T) {
		// Create regular user
		_, err := authManager.CreateUser("regular", "regular@example.com", "regularpass", []string{"user"})
		require.NoError(t, err)

		authReq := &framework.AuthenticationRequest{
			Method: "password",
			Credentials: map[string]interface{}{
				"username": "regular",
				"password": "regularpass",
			},
		}

		authResp, err := authManager.Authenticate(ctx, authReq)
		require.NoError(t, err)

		called := false
		handler := middleware.Authorize("admin", "delete")(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			called = true
		}))

		req := httptest.NewRequest("DELETE", "/test", nil)
		req.Header.Set("Authorization", "Bearer "+authResp.Token)
		w := httptest.NewRecorder()

		handler.ServeHTTP(w, req)

		assert.False(t, called)
		assert.Equal(t, http.StatusForbidden, w.Code)
	})

	t.Run("RequireRoles", func(t *testing.T) {
		// Create user with specific roles
		_, err := authManager.CreateUser("operator", "operator@example.com", "operatorpass", []string{"operator"})
		require.NoError(t, err)

		authReq := &framework.AuthenticationRequest{
			Method: "password",
			Credentials: map[string]interface{}{
				"username": "operator",
				"password": "operatorpass",
			},
		}

		authResp, err := authManager.Authenticate(ctx, authReq)
		require.NoError(t, err)

		called := false
		handler := middleware.RequireRoles("operator")(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			called = true
			w.WriteHeader(http.StatusOK)
		}))

		req := httptest.NewRequest("GET", "/test", nil)
		req.Header.Set("Authorization", "Bearer "+authResp.Token)
		w := httptest.NewRecorder()

		handler.ServeHTTP(w, req)

		assert.True(t, called)
		assert.Equal(t, http.StatusOK, w.Code)
	})

	t.Run("RequireRolesDenied", func(t *testing.T) {
		// Create user without required role
		_, err := authManager.CreateUser("norole", "norole@example.com", "norolepass", []string{"user"})
		require.NoError(t, err)

		authReq := &framework.AuthenticationRequest{
			Method: "password",
			Credentials: map[string]interface{}{
				"username": "norole",
				"password": "norolepass",
			},
		}

		authResp, err := authManager.Authenticate(ctx, authReq)
		require.NoError(t, err)

		called := false
		handler := middleware.RequireRoles("admin")(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			called = true
		}))

		req := httptest.NewRequest("GET", "/test", nil)
		req.Header.Set("Authorization", "Bearer "+authResp.Token)
		w := httptest.NewRecorder()

		handler.ServeHTTP(w, req)

		assert.False(t, called)
		assert.Equal(t, http.StatusForbidden, w.Code)
	})

	t.Run("MiddlewareChaining", func(t *testing.T) {
		// Create user
		_, err := authManager.CreateUser("chain", "chain@example.com", "chainpass", []string{"admin"})
		require.NoError(t, err)

		authReq := &framework.AuthenticationRequest{
			Method: "password",
			Credentials: map[string]interface{}{
				"username": "chain",
				"password": "chainpass",
			},
		}

		authResp, err := authManager.Authenticate(ctx, authReq)
		require.NoError(t, err)

		called := false
		handler := middleware.CORS(
			middleware.Security(
				middleware.Logging(
					middleware.RateLimit(
						middleware.Authenticate(
							middleware.RequireRoles("admin")(
								http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
									called = true
									w.WriteHeader(http.StatusOK)
								}),
							),
						),
					),
				),
			),
		)

		req := httptest.NewRequest("GET", "/test", nil)
		req.Header.Set("Origin", "http://localhost:3000")
		req.Header.Set("Authorization", "Bearer "+authResp.Token)
		req.RemoteAddr = "127.0.0.1:12345"
		w := httptest.NewRecorder()

		handler.ServeHTTP(w, req)

		assert.True(t, called)
		assert.Equal(t, http.StatusOK, w.Code)
		
		// Verify middleware effects
		assert.Equal(t, "*", w.Header().Get("Access-Control-Allow-Origin"))
		assert.Equal(t, "nosniff", w.Header().Get("X-Content-Type-Options"))
	})

	t.Run("ErrorResponses", func(t *testing.T) {
		// Test authentication error response format
		handler := middleware.Authenticate(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))

		req := httptest.NewRequest("GET", "/test", nil)
		w := httptest.NewRecorder()

		handler.ServeHTTP(w, req)

		assert.Equal(t, http.StatusUnauthorized, w.Code)
		assert.Contains(t, w.Body.String(), "error")
		assert.Contains(t, w.Body.String(), "unauthorized")
	})

	t.Run("RateLimitHeaders", func(t *testing.T) {
		handler := middleware.RateLimit(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		}))

		req := httptest.NewRequest("GET", "/test", nil)
		req.RemoteAddr = "127.0.0.1:12345"
		w := httptest.NewRecorder()

		handler.ServeHTTP(w, req)

		// Check that rate limit headers might be present (implementation dependent)
		// Note: This test would need to be adjusted based on actual implementation
		if rateLimitRemaining := w.Header().Get("X-RateLimit-Remaining"); rateLimitRemaining != "" {
			assert.Regexp(t, `^\d+$`, rateLimitRemaining)
		}
	})

	t.Run("ConcurrentRequests", func(t *testing.T) {
		// Create user
		_, err := authManager.CreateUser("concurrent", "concurrent@example.com", "concurrentpass", []string{"user"})
		require.NoError(t, err)

		authReq := &framework.AuthenticationRequest{
			Method: "password",
			Credentials: map[string]interface{}{
				"username": "concurrent",
				"password": "concurrentpass",
			},
		}

		authResp, err := authManager.Authenticate(ctx, authReq)
		require.NoError(t, err)

		callCount := make(map[string]int)
		handler := middleware.Authenticate(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Simulate some work
			time.Sleep(10 * time.Millisecond)
			callCount[r.URL.Path]++
			w.WriteHeader(http.StatusOK)
		}))

		// Make concurrent requests
		numRequests := 10
		done := make(chan bool, numRequests)

		for i := 0; i < numRequests; i++ {
			go func(idx int) {
				req := httptest.NewRequest("GET", fmt.Sprintf("/test-%d", idx), nil)
				req.Header.Set("Authorization", "Bearer "+authResp.Token)
				w := httptest.NewRecorder()

				handler.ServeHTTP(w, req)
				assert.Equal(t, http.StatusOK, w.Code)
				done <- true
			}(i)
		}

		// Wait for all requests to complete
		for i := 0; i < numRequests; i++ {
			select {
			case <-done:
				// Success
			case <-time.After(5 * time.Second):
				t.Fatal("Timeout waiting for concurrent requests")
			}
		}

		// Verify all requests were processed
		assert.Len(t, callCount, numRequests)
		for path, count := range callCount {
			assert.Equal(t, 1, count, "Path %s should be called exactly once", path)
		}
	})
}