package security

import (
	"context"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/Caia-Tech/afdp/services/policy-engine/internal/logging"
	"github.com/Caia-Tech/afdp/services/policy-engine/pkg/framework"
)

// Middleware provides HTTP middleware for authentication and authorization
type Middleware struct {
	logger   *logging.Logger
	provider *Provider
}

// NewMiddleware creates a new security middleware
func NewMiddleware(logger *logging.Logger, provider *Provider) *Middleware {
	return &Middleware{
		logger:   logger,
		provider: provider,
	}
}

// Authenticate is middleware that validates JWT tokens
func (m *Middleware) Authenticate(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Skip authentication for health endpoints
		if strings.HasPrefix(r.URL.Path, "/health") || strings.HasPrefix(r.URL.Path, "/metrics") {
			next.ServeHTTP(w, r)
			return
		}

		// Extract token from Authorization header
		authHeader := r.Header.Get("Authorization")
		if authHeader == "" {
			http.Error(w, "missing authorization header", http.StatusUnauthorized)
			return
		}

		// Check Bearer scheme
		parts := strings.Split(authHeader, " ")
		if len(parts) != 2 || parts[0] != "Bearer" {
			http.Error(w, "invalid authorization header format", http.StatusUnauthorized)
			return
		}

		token := parts[1]

		// Validate token
		claims, err := m.provider.ValidateToken(token)
		if err != nil {
			m.logger.Debug("Token validation failed", "error", err)
			http.Error(w, "invalid token", http.StatusUnauthorized)
			return
		}

		// Add claims to context
		ctx := context.WithValue(r.Context(), "claims", claims)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// Authorize is middleware that checks permissions for specific resources
func (m *Middleware) Authorize(resource, action string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Get claims from context
			claims, ok := r.Context().Value("claims").(*Claims)
			if !ok {
				http.Error(w, "no authentication context", http.StatusUnauthorized)
				return
			}

			// Check authorization
			authReq := &framework.AuthorizationRequest{
				UserID:   claims.UserID,
				Resource: resource,
				Action:   action,
			}

			// Create context with claims for RBAC
			ctx := context.WithValue(r.Context(), "claims", claims)
			authResp, err := m.provider.rbacManager.Authorize(ctx, authReq)
			if err != nil {
				m.logger.Error("Authorization error", "error", err)
				http.Error(w, "authorization error", http.StatusInternalServerError)
				return
			}

			if !authResp.Allowed {
				m.logger.Debug("Authorization denied",
					"user_id", claims.UserID,
					"resource", resource,
					"action", action,
					"reason", authResp.Reason,
				)
				http.Error(w, "forbidden", http.StatusForbidden)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

// RequireRoles is middleware that requires specific roles
func (m *Middleware) RequireRoles(roles ...string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Get claims from context
			claims, ok := r.Context().Value("claims").(*Claims)
			if !ok {
				http.Error(w, "no authentication context", http.StatusUnauthorized)
				return
			}

			// Check if user has any of the required roles
			hasRole := false
			for _, requiredRole := range roles {
				for _, userRole := range claims.Roles {
					if userRole == requiredRole {
						hasRole = true
						break
					}
				}
				if hasRole {
					break
				}
			}

			if !hasRole {
				m.logger.Debug("Role requirement not met",
					"user_id", claims.UserID,
					"required_roles", roles,
					"user_roles", claims.Roles,
				)
				http.Error(w, "insufficient privileges", http.StatusForbidden)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

// APIKey is middleware that validates API keys
func (m *Middleware) APIKey(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Check for API key in header
		apiKey := r.Header.Get("X-API-Key")
		if apiKey == "" {
			// Fall back to query parameter
			apiKey = r.URL.Query().Get("api_key")
		}

		if apiKey == "" {
			// No API key, try JWT authentication
			m.Authenticate(next).ServeHTTP(w, r)
			return
		}

		// Validate API key (simplified - in production, check against database)
		if !m.validateAPIKey(apiKey) {
			http.Error(w, "invalid API key", http.StatusUnauthorized)
			return
		}

		// Create service account context
		claims := &Claims{
			UserID:   "service-" + apiKey[:8],
			Username: "service",
			Roles:    []string{"service"},
		}

		ctx := context.WithValue(r.Context(), "claims", claims)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// RateLimiter is middleware that enforces rate limits
func (m *Middleware) RateLimiter(requestsPerMinute int) func(http.Handler) http.Handler {
	// Simple in-memory rate limiter - in production, use Redis
	limiter := NewRateLimiter(requestsPerMinute)

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Get user ID from context
			userID := "anonymous"
			if claims, ok := r.Context().Value("claims").(*Claims); ok {
				userID = claims.UserID
			}

			// Check rate limit
			if !limiter.Allow(userID) {
				http.Error(w, "rate limit exceeded", http.StatusTooManyRequests)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

// CORS is middleware that handles CORS headers
func (m *Middleware) CORS(allowedOrigins []string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			origin := r.Header.Get("Origin")
			
			// Check if origin is allowed
			allowed := false
			for _, allowedOrigin := range allowedOrigins {
				if allowedOrigin == "*" || allowedOrigin == origin {
					allowed = true
					break
				}
			}

			if allowed {
				w.Header().Set("Access-Control-Allow-Origin", origin)
				w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
				w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization, X-API-Key")
				w.Header().Set("Access-Control-Max-Age", "86400")
			}

			// Handle preflight requests
			if r.Method == "OPTIONS" {
				w.WriteHeader(http.StatusNoContent)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

// validateAPIKey validates an API key
func (m *Middleware) validateAPIKey(apiKey string) bool {
	// In production, validate against database
	// For now, accept any key starting with "sk_"
	return strings.HasPrefix(apiKey, "sk_")
}

// RateLimiter implements a simple token bucket rate limiter
type RateLimiter struct {
	rate    int
	buckets map[string]*tokenBucket
	mu      sync.RWMutex
}

type tokenBucket struct {
	tokens    int
	lastCheck time.Time
}

func NewRateLimiter(rate int) *RateLimiter {
	rl := &RateLimiter{
		rate:    rate,
		buckets: make(map[string]*tokenBucket),
	}

	// Start cleanup goroutine
	go rl.cleanup()

	return rl
}

func (rl *RateLimiter) Allow(key string) bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	bucket, exists := rl.buckets[key]
	if !exists {
		bucket = &tokenBucket{
			tokens:    rl.rate,
			lastCheck: time.Now(),
		}
		rl.buckets[key] = bucket
	}

	// Refill tokens based on elapsed time
	elapsed := time.Since(bucket.lastCheck)
	tokensToAdd := int(elapsed.Minutes() * float64(rl.rate))
	bucket.tokens = min(bucket.tokens+tokensToAdd, rl.rate)
	bucket.lastCheck = time.Now()

	// Check if request is allowed
	if bucket.tokens > 0 {
		bucket.tokens--
		return true
	}

	return false
}

func (rl *RateLimiter) cleanup() {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()

	for range ticker.C {
		rl.mu.Lock()
		cutoff := time.Now().Add(-10 * time.Minute)
		for key, bucket := range rl.buckets {
			if bucket.lastCheck.Before(cutoff) {
				delete(rl.buckets, key)
			}
		}
		rl.mu.Unlock()
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}