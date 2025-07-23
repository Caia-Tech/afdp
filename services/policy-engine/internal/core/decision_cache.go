package core

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"sync"
	"time"

	"github.com/Caia-Tech/afdp/services/policy-engine/internal/logging"
	"github.com/Caia-Tech/afdp/services/policy-engine/pkg/framework"
)

// DecisionCache provides caching for policy decisions
type DecisionCache struct {
	logger     *logging.Logger
	mu         sync.RWMutex
	cache      map[string]*cacheEntry
	maxSize    int
	ttl        time.Duration
	cleanupTicker *time.Ticker
	stopCleanup   chan struct{}
}

type cacheEntry struct {
	decision   *framework.PolicyDecision
	expiration time.Time
	hits       int64
}

// NewDecisionCache creates a new decision cache
func NewDecisionCache(logger *logging.Logger) *DecisionCache {
	return &DecisionCache{
		logger:      logger,
		cache:       make(map[string]*cacheEntry),
		maxSize:     10000,
		ttl:         5 * time.Minute,
		stopCleanup: make(chan struct{}),
	}
}

// Initialize prepares the cache
func (dc *DecisionCache) Initialize(ctx context.Context) error {
	dc.logger.Info("Initializing decision cache...", 
		"maxSize", dc.maxSize,
		"ttl", dc.ttl,
	)
	return nil
}

// StartCleanup starts the cache cleanup routine
func (dc *DecisionCache) StartCleanup(ctx context.Context) {
	dc.cleanupTicker = time.NewTicker(time.Minute)
	
	for {
		select {
		case <-dc.cleanupTicker.C:
			dc.cleanup()
		case <-dc.stopCleanup:
			dc.cleanupTicker.Stop()
			return
		case <-ctx.Done():
			dc.cleanupTicker.Stop()
			return
		}
	}
}

// StopCleanup stops the cache cleanup routine
func (dc *DecisionCache) StopCleanup() {
	close(dc.stopCleanup)
}

// Get retrieves a decision from cache
func (dc *DecisionCache) Get(req *framework.PolicyEvaluationRequest) (*framework.PolicyDecision, bool) {
	key := dc.generateKey(req)
	
	dc.mu.RLock()
	entry, exists := dc.cache[key]
	dc.mu.RUnlock()
	
	if !exists {
		return nil, false
	}
	
	// Check expiration
	if time.Now().After(entry.expiration) {
		dc.mu.Lock()
		delete(dc.cache, key)
		dc.mu.Unlock()
		return nil, false
	}
	
	// Update hit count
	dc.mu.Lock()
	entry.hits++
	dc.mu.Unlock()
	
	return entry.decision, true
}

// Set stores a decision in cache
func (dc *DecisionCache) Set(req *framework.PolicyEvaluationRequest, decision *framework.PolicyDecision) {
	key := dc.generateKey(req)
	
	dc.mu.Lock()
	defer dc.mu.Unlock()
	
	// Check cache size
	if len(dc.cache) >= dc.maxSize {
		// Simple eviction: remove oldest entry
		dc.evictOldest()
	}
	
	dc.cache[key] = &cacheEntry{
		decision:   decision,
		expiration: time.Now().Add(dc.ttl),
		hits:       0,
	}
}

// Clear removes all entries from cache
func (dc *DecisionCache) Clear() {
	dc.mu.Lock()
	defer dc.mu.Unlock()
	
	dc.cache = make(map[string]*cacheEntry)
	dc.logger.Info("Cache cleared")
}

// GetStats returns cache statistics
func (dc *DecisionCache) GetStats() map[string]interface{} {
	dc.mu.RLock()
	defer dc.mu.RUnlock()
	
	totalHits := int64(0)
	for _, entry := range dc.cache {
		totalHits += entry.hits
	}
	
	return map[string]interface{}{
		"size":       len(dc.cache),
		"max_size":   dc.maxSize,
		"ttl":        dc.ttl.String(),
		"total_hits": totalHits,
	}
}

// generateKey creates a cache key from the request
func (dc *DecisionCache) generateKey(req *framework.PolicyEvaluationRequest) string {
	// Create a stable hash of the request
	data := map[string]interface{}{
		"policy_id": req.PolicyID,
		"input":     req.Input,
		"context": map[string]interface{}{
			"user_id":     req.Context.UserID,
			"environment": req.Context.Environment,
		},
	}
	
	jsonData, _ := json.Marshal(data)
	hash := sha256.Sum256(jsonData)
	return hex.EncodeToString(hash[:])
}

// cleanup removes expired entries
func (dc *DecisionCache) cleanup() {
	dc.mu.Lock()
	defer dc.mu.Unlock()
	
	now := time.Now()
	expired := 0
	
	for key, entry := range dc.cache {
		if now.After(entry.expiration) {
			delete(dc.cache, key)
			expired++
		}
	}
	
	if expired > 0 {
		dc.logger.Debug("Cache cleanup completed", "expired", expired)
	}
}

// evictOldest removes the oldest cache entry
func (dc *DecisionCache) evictOldest() {
	var oldestKey string
	var oldestTime time.Time
	
	for key, entry := range dc.cache {
		if oldestKey == "" || entry.expiration.Before(oldestTime) {
			oldestKey = key
			oldestTime = entry.expiration
		}
	}
	
	if oldestKey != "" {
		delete(dc.cache, oldestKey)
	}
}