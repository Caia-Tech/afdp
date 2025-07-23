package rest

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/gorilla/mux"
	"github.com/Caia-Tech/afdp/services/policy-engine/internal/security"
	"github.com/Caia-Tech/afdp/services/policy-engine/pkg/framework"
)

// Health endpoints

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	health := s.frameworkCore.Health()
	
	status := http.StatusOK
	if health.Status != "healthy" {
		status = http.StatusServiceUnavailable
	}
	
	s.respondJSON(w, status, health)
}

func (s *Server) handleHealthLive(w http.ResponseWriter, r *http.Request) {
	s.respondJSON(w, http.StatusOK, map[string]interface{}{
		"status": "alive",
		"timestamp": time.Now().Unix(),
	})
}

func (s *Server) handleHealthReady(w http.ResponseWriter, r *http.Request) {
	health := s.frameworkCore.Health()
	
	if health.Status == "healthy" {
		s.respondJSON(w, http.StatusOK, map[string]interface{}{
			"status": "ready",
			"timestamp": time.Now().Unix(),
		})
	} else {
		s.respondJSON(w, http.StatusServiceUnavailable, map[string]interface{}{
			"status": "not ready",
			"message": health.Message,
			"timestamp": time.Now().Unix(),
		})
	}
}

func (s *Server) handleMetrics(w http.ResponseWriter, r *http.Request) {
	// In a real implementation, would export Prometheus metrics
	w.Header().Set("Content-Type", "text/plain")
	w.Write([]byte("# HELP framework_uptime_seconds Framework uptime in seconds\n"))
	w.Write([]byte("# TYPE framework_uptime_seconds gauge\n"))
	w.Write([]byte("framework_uptime_seconds 0\n"))
}

// Auth endpoints

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	var req framework.AuthenticationRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.respondError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	// Get security provider
	secPlugin, err := s.frameworkCore.GetPlugin(string(framework.PluginTypeSecurity), "default")
	if err != nil {
		s.respondError(w, http.StatusInternalServerError, "security provider not available")
		return
	}

	provider, ok := secPlugin.(framework.SecurityProvider)
	if !ok {
		s.respondError(w, http.StatusInternalServerError, "invalid security provider")
		return
	}

	// Authenticate
	resp, err := provider.Authenticate(r.Context(), &req)
	if err != nil {
		s.logger.Error("Authentication error", "error", err)
		s.respondError(w, http.StatusInternalServerError, "authentication error")
		return
	}

	if !resp.Success {
		s.respondError(w, http.StatusUnauthorized, "invalid credentials")
		return
	}

	s.respondJSON(w, http.StatusOK, resp)
}

func (s *Server) handleRefreshToken(w http.ResponseWriter, r *http.Request) {
	var req framework.RefreshTokenRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.respondError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	// Get security provider
	secPlugin, err := s.frameworkCore.GetPlugin(string(framework.PluginTypeSecurity), "default")
	if err != nil {
		s.respondError(w, http.StatusInternalServerError, "security provider not available")
		return
	}

	provider, ok := secPlugin.(framework.SecurityProvider)
	if !ok {
		s.respondError(w, http.StatusInternalServerError, "invalid security provider")
		return
	}

	// Refresh token
	resp, err := provider.RefreshToken(r.Context(), &req)
	if err != nil {
		s.respondError(w, http.StatusUnauthorized, "invalid refresh token")
		return
	}

	s.respondJSON(w, http.StatusOK, resp)
}

// Framework management

func (s *Server) handleFrameworkStatus(w http.ResponseWriter, r *http.Request) {
	config := s.frameworkCore.GetConfiguration()
	health := s.frameworkCore.Health()
	
	status := map[string]interface{}{
		"name":    config.Name,
		"version": config.Version,
		"health":  health,
		"plugins": s.frameworkCore.ListPlugins(""),
	}
	
	s.respondJSON(w, http.StatusOK, status)
}

func (s *Server) handleGetConfig(w http.ResponseWriter, r *http.Request) {
	config := s.frameworkCore.GetConfiguration()
	s.respondJSON(w, http.StatusOK, config)
}

func (s *Server) handleReloadConfig(w http.ResponseWriter, r *http.Request) {
	if err := s.frameworkCore.ReloadConfiguration(); err != nil {
		s.respondError(w, http.StatusInternalServerError, err.Error())
		return
	}
	
	s.respondJSON(w, http.StatusOK, map[string]interface{}{
		"message": "configuration reloaded",
		"timestamp": time.Now().Unix(),
	})
}

// Plugin management

func (s *Server) handleListPlugins(w http.ResponseWriter, r *http.Request) {
	plugins := s.frameworkCore.ListPlugins("")
	s.respondJSON(w, http.StatusOK, map[string]interface{}{
		"plugins": plugins,
		"total": len(plugins),
	})
}

func (s *Server) handleListPluginsByType(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	pluginType := vars["type"]
	
	plugins := s.frameworkCore.ListPlugins(pluginType)
	s.respondJSON(w, http.StatusOK, map[string]interface{}{
		"type": pluginType,
		"plugins": plugins,
		"total": len(plugins),
	})
}

func (s *Server) handleGetPlugin(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	pluginType := vars["type"]
	pluginName := vars["name"]
	
	plugin, err := s.frameworkCore.GetPlugin(pluginType, pluginName)
	if err != nil {
		s.respondError(w, http.StatusNotFound, "plugin not found")
		return
	}
	
	info := framework.PluginInfo{
		Name:        plugin.Name(),
		Version:     plugin.Version(),
		Type:        plugin.Type(),
		Metadata:    plugin.Metadata().Metadata,
	}
	
	s.respondJSON(w, http.StatusOK, info)
}

func (s *Server) handlePluginHealth(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	pluginType := vars["type"]
	pluginName := vars["name"]
	
	plugin, err := s.frameworkCore.GetPlugin(pluginType, pluginName)
	if err != nil {
		s.respondError(w, http.StatusNotFound, "plugin not found")
		return
	}
	
	health := plugin.Health()
	status := http.StatusOK
	if health.Status != "healthy" {
		status = http.StatusServiceUnavailable
	}
	
	s.respondJSON(w, status, health)
}

func (s *Server) handleReloadPlugin(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	pluginType := vars["type"]
	pluginName := vars["name"]
	
	// TODO: Implement plugin reload
	s.respondJSON(w, http.StatusOK, map[string]interface{}{
		"message": "plugin reload not implemented",
		"plugin_type": pluginType,
		"plugin_name": pluginName,
	})
}

// Policy evaluation

func (s *Server) handleEvaluate(w http.ResponseWriter, r *http.Request) {
	var req framework.PolicyEvaluationRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.respondError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	// Add user context from auth
	if claims, ok := r.Context().Value("claims").(*security.Claims); ok {
		if req.Context == nil {
			req.Context = &framework.EvaluationContext{}
		}
		req.Context.UserID = claims.UserID
	}

	// Get decision engine
	engine := s.frameworkCore.GetDecisionEngine()
	
	// Evaluate policy
	decision, err := engine.EvaluatePolicy(r.Context(), &req)
	if err != nil {
		s.logger.Error("Policy evaluation failed", "error", err)
		s.respondError(w, http.StatusInternalServerError, "evaluation failed")
		return
	}

	s.respondJSON(w, http.StatusOK, decision)
}

func (s *Server) handleBatchEvaluate(w http.ResponseWriter, r *http.Request) {
	var req framework.BatchPolicyEvaluationRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.respondError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	// Add user context to all requests
	if claims, ok := r.Context().Value("claims").(*security.Claims); ok {
		for _, evalReq := range req.Requests {
			if evalReq.Context == nil {
				evalReq.Context = &framework.EvaluationContext{}
			}
			evalReq.Context.UserID = claims.UserID
		}
	}

	// Get decision engine
	engine := s.frameworkCore.GetDecisionEngine()
	
	// Evaluate policies
	result, err := engine.EvaluateBatchPolicies(r.Context(), &req)
	if err != nil {
		s.logger.Error("Batch evaluation failed", "error", err)
		s.respondError(w, http.StatusInternalServerError, "batch evaluation failed")
		return
	}

	s.respondJSON(w, http.StatusOK, result)
}

// Policy management

func (s *Server) handleListPolicies(w http.ResponseWriter, r *http.Request) {
	// Get evaluator plugin
	evaluator, err := s.frameworkCore.GetPlugin(string(framework.PluginTypeEvaluator), "rego")
	if err != nil {
		s.respondError(w, http.StatusInternalServerError, "evaluator not available")
		return
	}

	policyEvaluator, ok := evaluator.(framework.PolicyEvaluator)
	if !ok {
		s.respondError(w, http.StatusInternalServerError, "invalid evaluator")
		return
	}

	// List policies
	resp, err := policyEvaluator.ListPolicies(r.Context(), &framework.ListPoliciesRequest{})
	if err != nil {
		s.respondError(w, http.StatusInternalServerError, "failed to list policies")
		return
	}

	s.respondJSON(w, http.StatusOK, resp)
}

func (s *Server) handleGetPolicy(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	policyID := vars["id"]
	
	// TODO: Implement get policy
	s.respondJSON(w, http.StatusOK, map[string]interface{}{
		"policy_id": policyID,
		"message": "get policy not implemented",
	})
}

func (s *Server) handleCreatePolicy(w http.ResponseWriter, r *http.Request) {
	var req framework.LoadPolicyRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.respondError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	// Get evaluator plugin
	evaluator, err := s.frameworkCore.GetPlugin(string(framework.PluginTypeEvaluator), "rego")
	if err != nil {
		s.respondError(w, http.StatusInternalServerError, "evaluator not available")
		return
	}

	policyEvaluator, ok := evaluator.(framework.PolicyEvaluator)
	if !ok {
		s.respondError(w, http.StatusInternalServerError, "invalid evaluator")
		return
	}

	// Load policy
	resp, err := policyEvaluator.LoadPolicy(r.Context(), &req)
	if err != nil {
		s.respondError(w, http.StatusBadRequest, err.Error())
		return
	}

	s.respondJSON(w, http.StatusCreated, resp)
}

func (s *Server) handleUpdatePolicy(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	policyID := vars["id"]
	
	// TODO: Implement update policy
	s.respondJSON(w, http.StatusOK, map[string]interface{}{
		"policy_id": policyID,
		"message": "update policy not implemented",
	})
}

func (s *Server) handleDeletePolicy(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	policyID := vars["id"]

	// Get evaluator plugin
	evaluator, err := s.frameworkCore.GetPlugin(string(framework.PluginTypeEvaluator), "rego")
	if err != nil {
		s.respondError(w, http.StatusInternalServerError, "evaluator not available")
		return
	}

	policyEvaluator, ok := evaluator.(framework.PolicyEvaluator)
	if !ok {
		s.respondError(w, http.StatusInternalServerError, "invalid evaluator")
		return
	}

	// Unload policy
	resp, err := policyEvaluator.UnloadPolicy(r.Context(), &framework.UnloadPolicyRequest{
		PolicyID: policyID,
	})
	if err != nil {
		s.respondError(w, http.StatusNotFound, err.Error())
		return
	}

	s.respondJSON(w, http.StatusOK, resp)
}

// Pipeline management

func (s *Server) handleExecutePipeline(w http.ResponseWriter, r *http.Request) {
	var req framework.PipelineExecutionRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.respondError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	// Add user context
	if claims, ok := r.Context().Value("claims").(*security.Claims); ok {
		if req.Context == nil {
			req.Context = &framework.EvaluationContext{}
		}
		req.Context.UserID = claims.UserID
	}

	// Get decision engine
	engine := s.frameworkCore.GetDecisionEngine()
	
	// Execute pipeline
	resp, err := engine.ExecutePipeline(r.Context(), &req)
	if err != nil {
		s.logger.Error("Pipeline execution failed", "error", err)
		s.respondError(w, http.StatusInternalServerError, "pipeline execution failed")
		return
	}

	s.respondJSON(w, http.StatusAccepted, resp)
}

func (s *Server) handlePipelineStatus(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	pipelineID := vars["id"]

	// Get decision engine
	engine := s.frameworkCore.GetDecisionEngine()
	
	// Get status
	resp, err := engine.GetPipelineStatus(r.Context(), &framework.GetPipelineStatusRequest{
		PipelineID: pipelineID,
	})
	if err != nil {
		s.respondError(w, http.StatusNotFound, "pipeline execution not found")
		return
	}

	s.respondJSON(w, http.StatusOK, resp)
}

// Decision history

func (s *Server) handleQueryDecisions(w http.ResponseWriter, r *http.Request) {
	// Parse query parameters
	query := &framework.DecisionQuery{
		Limit: 100,
	}
	
	if userID := r.URL.Query().Get("user_id"); userID != "" {
		query.UserID = userID
	}
	if policyID := r.URL.Query().Get("policy_id"); policyID != "" {
		query.PolicyID = policyID
	}
	if result := r.URL.Query().Get("result"); result != "" {
		query.Result = result
	}

	// Get decision engine
	engine := s.frameworkCore.GetDecisionEngine()
	
	// Query decisions
	resp, err := engine.QueryDecisions(r.Context(), query)
	if err != nil {
		s.logger.Error("Decision query failed", "error", err)
		s.respondError(w, http.StatusInternalServerError, "query failed")
		return
	}

	s.respondJSON(w, http.StatusOK, resp)
}

func (s *Server) handleGetDecision(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	decisionID := vars["id"]

	// Get decision engine
	engine := s.frameworkCore.GetDecisionEngine()
	
	// Get decision
	decision, err := engine.GetDecision(r.Context(), decisionID)
	if err != nil {
		s.respondError(w, http.StatusNotFound, "decision not found")
		return
	}

	s.respondJSON(w, http.StatusOK, decision)
}

// User management

func (s *Server) handleGetCurrentUser(w http.ResponseWriter, r *http.Request) {
	claims, ok := r.Context().Value("claims").(*security.Claims)
	if !ok {
		s.respondError(w, http.StatusUnauthorized, "no authentication context")
		return
	}

	// Get security provider
	secPlugin, err := s.frameworkCore.GetPlugin(string(framework.PluginTypeSecurity), "default")
	if err != nil {
		s.respondError(w, http.StatusInternalServerError, "security provider not available")
		return
	}

	provider, ok := secPlugin.(framework.SecurityProvider)
	if !ok {
		s.respondError(w, http.StatusInternalServerError, "invalid security provider")
		return
	}

	// Get user info
	resp, err := provider.GetUser(r.Context(), &framework.GetUserRequest{
		UserID: claims.UserID,
	})
	if err != nil {
		s.respondError(w, http.StatusNotFound, "user not found")
		return
	}

	s.respondJSON(w, http.StatusOK, resp)
}

func (s *Server) handleGetUser(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	userID := vars["id"]

	// Get security provider
	secPlugin, err := s.frameworkCore.GetPlugin(string(framework.PluginTypeSecurity), "default")
	if err != nil {
		s.respondError(w, http.StatusInternalServerError, "security provider not available")
		return
	}

	provider, ok := secPlugin.(framework.SecurityProvider)
	if !ok {
		s.respondError(w, http.StatusInternalServerError, "invalid security provider")
		return
	}

	// Get user info
	resp, err := provider.GetUser(r.Context(), &framework.GetUserRequest{
		UserID: userID,
	})
	if err != nil {
		s.respondError(w, http.StatusNotFound, "user not found")
		return
	}

	s.respondJSON(w, http.StatusOK, resp)
}

func (s *Server) handleAssignRole(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	userID := vars["id"]

	var req framework.AssignRoleRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.respondError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	req.UserID = userID

	// Get security provider
	secPlugin, err := s.frameworkCore.GetPlugin(string(framework.PluginTypeSecurity), "default")
	if err != nil {
		s.respondError(w, http.StatusInternalServerError, "security provider not available")
		return
	}

	provider, ok := secPlugin.(framework.SecurityProvider)
	if !ok {
		s.respondError(w, http.StatusInternalServerError, "invalid security provider")
		return
	}

	// Assign role
	resp, err := provider.AssignRole(r.Context(), &req)
	if err != nil {
		s.respondError(w, http.StatusBadRequest, err.Error())
		return
	}

	s.respondJSON(w, http.StatusOK, resp)
}

// Role management

func (s *Server) handleListRoles(w http.ResponseWriter, r *http.Request) {
	// Get security provider
	secPlugin, err := s.frameworkCore.GetPlugin(string(framework.PluginTypeSecurity), "default")
	if err != nil {
		s.respondError(w, http.StatusInternalServerError, "security provider not available")
		return
	}

	provider, ok := secPlugin.(framework.SecurityProvider)
	if !ok {
		s.respondError(w, http.StatusInternalServerError, "invalid security provider")
		return
	}

	// List roles
	resp, err := provider.ListRoles(r.Context(), &framework.ListRolesRequest{})
	if err != nil {
		s.respondError(w, http.StatusInternalServerError, "failed to list roles")
		return
	}

	s.respondJSON(w, http.StatusOK, resp)
}