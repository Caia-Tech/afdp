package rest

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/gorilla/mux"
	"github.com/Caia-Tech/afdp/services/policy-engine/internal/logging"
	"github.com/Caia-Tech/afdp/services/policy-engine/internal/security"
	"github.com/Caia-Tech/afdp/services/policy-engine/pkg/framework"
)

// Server implements the REST API server
type Server struct {
	config        framework.RESTConfig
	logger        *logging.Logger
	router        *mux.Router
	httpServer    *http.Server
	frameworkCore framework.FrameworkCore
	middleware    *security.Middleware
}

// NewServer creates a new REST API server
func NewServer(frameworkCore framework.FrameworkCore, config framework.RESTConfig, logger *logging.Logger) *Server {
	s := &Server{
		config:        config,
		logger:        logger,
		frameworkCore: frameworkCore,
		router:        mux.NewRouter(),
	}

	// Set up middleware if security is enabled
	if secPlugin, err := frameworkCore.GetPlugin(string(framework.PluginTypeSecurity), "default"); err == nil {
		if provider, ok := secPlugin.(*security.Provider); ok {
			s.middleware = security.NewMiddleware(logger, provider)
		}
	}

	// Set up routes
	s.setupRoutes()

	return s
}

// Start starts the REST API server
func (s *Server) Start() error {
	addr := fmt.Sprintf("%s:%d", s.config.Host, s.config.Port)
	
	s.httpServer = &http.Server{
		Addr:         addr,
		Handler:      s.router,
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 30 * time.Second,
		IdleTimeout:  120 * time.Second,
	}

	s.logger.Info("Starting REST API server", "address", addr)

	if s.config.TLS.MinVersion != "" {
		// TODO: Configure TLS
		return s.httpServer.ListenAndServeTLS("", "")
	}

	return s.httpServer.ListenAndServe()
}

// Stop gracefully shuts down the server
func (s *Server) Stop(ctx context.Context) error {
	s.logger.Info("Stopping REST API server...")
	return s.httpServer.Shutdown(ctx)
}

// Address returns the server address
func (s *Server) Address() string {
	return fmt.Sprintf("%s:%d", s.config.Host, s.config.Port)
}

// setupRoutes configures all API routes
func (s *Server) setupRoutes() {
	// API version prefix
	api := s.router.PathPrefix("/api/v1").Subrouter()

	// Apply global middleware
	s.router.Use(s.loggingMiddleware)
	s.router.Use(s.recoveryMiddleware)
	
	if s.middleware != nil {
		// Apply CORS middleware
		s.router.Use(s.middleware.CORS([]string{"*"}))
		
		// Apply rate limiting
		api.Use(s.middleware.RateLimiter(100))
	}

	// Health and metrics endpoints (no auth)
	s.router.HandleFunc("/health", s.handleHealth).Methods("GET")
	s.router.HandleFunc("/health/live", s.handleHealthLive).Methods("GET")
	s.router.HandleFunc("/health/ready", s.handleHealthReady).Methods("GET")
	s.router.HandleFunc("/metrics", s.handleMetrics).Methods("GET")

	// Auth endpoints (no auth required)
	api.HandleFunc("/auth/login", s.handleLogin).Methods("POST")
	api.HandleFunc("/auth/refresh", s.handleRefreshToken).Methods("POST")

	// Protected endpoints
	if s.middleware != nil {
		// Apply authentication to all other endpoints
		protected := api.PathPrefix("").Subrouter()
		protected.Use(s.middleware.Authenticate)

		// Framework management
		protected.HandleFunc("/framework/status", s.handleFrameworkStatus).Methods("GET")
		protected.Handle("/framework/config", s.middleware.RequireRoles("admin")(http.HandlerFunc(s.handleGetConfig))).Methods("GET")
		protected.Handle("/framework/config/reload", s.middleware.RequireRoles("admin")(http.HandlerFunc(s.handleReloadConfig))).Methods("POST")

		// Plugin management
		protected.HandleFunc("/plugins", s.handleListPlugins).Methods("GET")
		protected.HandleFunc("/plugins/{type}", s.handleListPluginsByType).Methods("GET")
		protected.HandleFunc("/plugins/{type}/{name}", s.handleGetPlugin).Methods("GET")
		protected.HandleFunc("/plugins/{type}/{name}/health", s.handlePluginHealth).Methods("GET")
		protected.Handle("/plugins/{type}/{name}/reload", s.middleware.RequireRoles("admin")(http.HandlerFunc(s.handleReloadPlugin))).Methods("POST")

		// Policy evaluation
		protected.Handle("/evaluate", s.middleware.Authorize("policy", "evaluate")(http.HandlerFunc(s.handleEvaluate))).Methods("POST")
		protected.Handle("/evaluate/batch", s.middleware.Authorize("policy", "evaluate")(http.HandlerFunc(s.handleBatchEvaluate))).Methods("POST")
		
		// Policy management
		protected.Handle("/policies", s.middleware.Authorize("policy", "read")(http.HandlerFunc(s.handleListPolicies))).Methods("GET")
		protected.Handle("/policies/{id}", s.middleware.Authorize("policy", "read")(http.HandlerFunc(s.handleGetPolicy))).Methods("GET")
		protected.Handle("/policies", s.middleware.Authorize("policy", "write")(http.HandlerFunc(s.handleCreatePolicy))).Methods("POST")
		protected.Handle("/policies/{id}", s.middleware.Authorize("policy", "write")(http.HandlerFunc(s.handleUpdatePolicy))).Methods("PUT")
		protected.Handle("/policies/{id}", s.middleware.Authorize("policy", "write")(http.HandlerFunc(s.handleDeletePolicy))).Methods("DELETE")

		// Pipeline management
		protected.Handle("/pipelines/execute", s.middleware.Authorize("policy", "evaluate")(http.HandlerFunc(s.handleExecutePipeline))).Methods("POST")
		protected.HandleFunc("/pipelines/{id}/status", s.handlePipelineStatus).Methods("GET")

		// Decision history
		protected.Handle("/decisions", s.middleware.Authorize("policy", "read")(http.HandlerFunc(s.handleQueryDecisions))).Methods("GET")
		protected.Handle("/decisions/{id}", s.middleware.Authorize("policy", "read")(http.HandlerFunc(s.handleGetDecision))).Methods("GET")

		// User management
		protected.HandleFunc("/users/me", s.handleGetCurrentUser).Methods("GET")
		protected.Handle("/users/{id}", s.middleware.RequireRoles("admin")(http.HandlerFunc(s.handleGetUser))).Methods("GET")
		protected.Handle("/users/{id}/roles", s.middleware.RequireRoles("admin")(http.HandlerFunc(s.handleAssignRole))).Methods("POST")

		// Role management
		protected.HandleFunc("/roles", s.handleListRoles).Methods("GET")
	} else {
		// No security middleware, add unprotected routes
		s.setupUnprotectedRoutes(api)
	}
}

// setupUnprotectedRoutes sets up routes without authentication
func (s *Server) setupUnprotectedRoutes(api *mux.Router) {
	// Framework management
	api.HandleFunc("/framework/status", s.handleFrameworkStatus).Methods("GET")
	api.HandleFunc("/framework/config", s.handleGetConfig).Methods("GET")
	
	// Plugin management
	api.HandleFunc("/plugins", s.handleListPlugins).Methods("GET")
	api.HandleFunc("/plugins/{type}", s.handleListPluginsByType).Methods("GET")
	
	// Policy evaluation
	api.HandleFunc("/evaluate", s.handleEvaluate).Methods("POST")
	
	// Pipeline management
	api.HandleFunc("/pipelines/execute", s.handleExecutePipeline).Methods("POST")
	api.HandleFunc("/pipelines/{id}/status", s.handlePipelineStatus).Methods("GET")
}

// Middleware

func (s *Server) loggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		
		// Wrap response writer to capture status code
		wrapped := &responseWriter{ResponseWriter: w, statusCode: http.StatusOK}
		
		next.ServeHTTP(wrapped, r)
		
		duration := time.Since(start)
		s.logger.Info("HTTP request",
			"method", r.Method,
			"path", r.URL.Path,
			"status", wrapped.statusCode,
			"duration", duration,
			"remote_addr", r.RemoteAddr,
		)
	})
}

func (s *Server) recoveryMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if err := recover(); err != nil {
				s.logger.Error("Panic recovered", "error", err, "path", r.URL.Path)
				http.Error(w, "Internal server error", http.StatusInternalServerError)
			}
		}()
		next.ServeHTTP(w, r)
	})
}

// Response helpers

func (s *Server) respondJSON(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	
	if err := json.NewEncoder(w).Encode(data); err != nil {
		s.logger.Error("Failed to encode response", "error", err)
	}
}

func (s *Server) respondError(w http.ResponseWriter, status int, message string) {
	s.respondJSON(w, status, map[string]interface{}{
		"error": message,
		"status": status,
		"timestamp": time.Now().Unix(),
	})
}

// responseWriter wraps http.ResponseWriter to capture status code
type responseWriter struct {
	http.ResponseWriter
	statusCode int
}

func (w *responseWriter) WriteHeader(code int) {
	w.statusCode = code
	w.ResponseWriter.WriteHeader(code)
}