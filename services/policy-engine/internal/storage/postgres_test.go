package storage

import (
	"context"
	"database/sql"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/Caia-Tech/afdp/services/policy-engine/pkg/models"
)

// MockDB is a test implementation of the database interface
type MockDB struct {
	policies      map[string]*models.Policy
	decisions     map[string]*models.Decision
	evaluations   map[string]*models.Evaluation
	users         map[string]*models.User
	organizations map[string]*models.Organization
	closed        bool
}

func NewMockDB() *MockDB {
	return &MockDB{
		policies:      make(map[string]*models.Policy),
		decisions:     make(map[string]*models.Decision),
		evaluations:   make(map[string]*models.Evaluation),
		users:         make(map[string]*models.User),
		organizations: make(map[string]*models.Organization),
	}
}

func (m *MockDB) Close() error {
	m.closed = true
	return nil
}

func (m *MockDB) Ping() error {
	if m.closed {
		return sql.ErrConnDone
	}
	return nil
}

func (m *MockDB) CreatePolicy(ctx context.Context, policy *models.Policy) error {
	if m.closed {
		return sql.ErrConnDone
	}
	if policy.ID == "" {
		policy.ID = "mock-policy-" + policy.Name
	}
	policy.CreatedAt = time.Now()
	policy.UpdatedAt = time.Now()
	m.policies[policy.ID] = policy
	return nil
}

func (m *MockDB) GetPolicy(ctx context.Context, id string) (*models.Policy, error) {
	if m.closed {
		return nil, sql.ErrConnDone
	}
	policy, exists := m.policies[id]
	if !exists {
		return nil, sql.ErrNoRows
	}
	return policy, nil
}

func (m *MockDB) ListPolicies(ctx context.Context, limit, offset int) ([]*models.Policy, error) {
	if m.closed {
		return nil, sql.ErrConnDone
	}
	
	policies := make([]*models.Policy, 0, len(m.policies))
	for _, policy := range m.policies {
		policies = append(policies, policy)
	}
	
	// Simple pagination
	start := offset
	if start >= len(policies) {
		return []*models.Policy{}, nil
	}
	
	end := start + limit
	if end > len(policies) {
		end = len(policies)
	}
	
	return policies[start:end], nil
}

func (m *MockDB) UpdatePolicy(ctx context.Context, policy *models.Policy) error {
	if m.closed {
		return sql.ErrConnDone
	}
	if _, exists := m.policies[policy.ID]; !exists {
		return sql.ErrNoRows
	}
	policy.UpdatedAt = time.Now()
	m.policies[policy.ID] = policy
	return nil
}

func (m *MockDB) DeletePolicy(ctx context.Context, id string) error {
	if m.closed {
		return sql.ErrConnDone
	}
	if _, exists := m.policies[id]; !exists {
		return sql.ErrNoRows
	}
	delete(m.policies, id)
	return nil
}

func (m *MockDB) CreateDecision(ctx context.Context, decision *models.Decision) error {
	if m.closed {
		return sql.ErrConnDone
	}
	if decision.ID == "" {
		decision.ID = "mock-decision-" + time.Now().Format("20060102150405")
	}
	decision.CreatedAt = time.Now()
	m.decisions[decision.ID] = decision
	return nil
}

func (m *MockDB) GetDecision(ctx context.Context, id string) (*models.Decision, error) {
	if m.closed {
		return nil, sql.ErrConnDone
	}
	decision, exists := m.decisions[id]
	if !exists {
		return nil, sql.ErrNoRows
	}
	return decision, nil
}

func (m *MockDB) ListDecisions(ctx context.Context, policyID string, limit, offset int) ([]*models.Decision, error) {
	if m.closed {
		return nil, sql.ErrConnDone
	}
	
	decisions := make([]*models.Decision, 0)
	for _, decision := range m.decisions {
		if policyID == "" || decision.PolicyID == policyID {
			decisions = append(decisions, decision)
		}
	}
	
	// Simple pagination
	start := offset
	if start >= len(decisions) {
		return []*models.Decision{}, nil
	}
	
	end := start + limit
	if end > len(decisions) {
		end = len(decisions)
	}
	
	return decisions[start:end], nil
}

func TestMockDB(t *testing.T) {
	t.Run("CreateAndPing", func(t *testing.T) {
		db := NewMockDB()
		defer db.Close()
		
		err := db.Ping()
		assert.NoError(t, err)
		
		assert.False(t, db.closed)
	})

	t.Run("PolicyCRUD", func(t *testing.T) {
		db := NewMockDB()
		defer db.Close()
		ctx := context.Background()

		// Create policy
		policy := &models.Policy{
			Name:        "test-policy",
			Description: "Test policy for unit tests",
			Rules:       "package test\nallow = true",
			Version:     "1.0.0",
			Active:      true,
		}

		err := db.CreatePolicy(ctx, policy)
		assert.NoError(t, err)
		assert.NotEmpty(t, policy.ID)
		assert.False(t, policy.CreatedAt.IsZero())

		// Get policy
		retrieved, err := db.GetPolicy(ctx, policy.ID)
		assert.NoError(t, err)
		assert.Equal(t, policy.Name, retrieved.Name)
		assert.Equal(t, policy.Description, retrieved.Description)
		assert.Equal(t, policy.Rules, retrieved.Rules)
		assert.Equal(t, policy.Version, retrieved.Version)
		assert.Equal(t, policy.Active, retrieved.Active)

		// Update policy
		policy.Description = "Updated description"
		policy.Version = "1.1.0"
		err = db.UpdatePolicy(ctx, policy)
		assert.NoError(t, err)

		updated, err := db.GetPolicy(ctx, policy.ID)
		assert.NoError(t, err)
		assert.Equal(t, "Updated description", updated.Description)
		assert.Equal(t, "1.1.0", updated.Version)
		assert.True(t, updated.UpdatedAt.After(updated.CreatedAt))

		// List policies
		policies, err := db.ListPolicies(ctx, 10, 0)
		assert.NoError(t, err)
		assert.Len(t, policies, 1)
		assert.Equal(t, policy.ID, policies[0].ID)

		// Delete policy
		err = db.DeletePolicy(ctx, policy.ID)
		assert.NoError(t, err)

		_, err = db.GetPolicy(ctx, policy.ID)
		assert.Error(t, err)
		assert.Equal(t, sql.ErrNoRows, err)
	})

	t.Run("DecisionCRUD", func(t *testing.T) {
		db := NewMockDB()
		defer db.Close()
		ctx := context.Background()

		// Create decision
		decision := &models.Decision{
			PolicyID: "test-policy-123",
			Input: map[string]interface{}{
				"user":   "alice",
				"action": "read",
			},
			Result: "allow",
			Metadata: map[string]interface{}{
				"reason": "user has permission",
			},
		}

		err := db.CreateDecision(ctx, decision)
		assert.NoError(t, err)
		assert.NotEmpty(t, decision.ID)
		assert.False(t, decision.CreatedAt.IsZero())

		// Get decision
		retrieved, err := db.GetDecision(ctx, decision.ID)
		assert.NoError(t, err)
		assert.Equal(t, decision.PolicyID, retrieved.PolicyID)
		assert.Equal(t, decision.Result, retrieved.Result)
		assert.Equal(t, "alice", retrieved.Input["user"])
		assert.Equal(t, "user has permission", retrieved.Metadata["reason"])

		// List decisions
		decisions, err := db.ListDecisions(ctx, "", 10, 0)
		assert.NoError(t, err)
		assert.Len(t, decisions, 1)

		// List decisions by policy ID
		decisions, err = db.ListDecisions(ctx, "test-policy-123", 10, 0)
		assert.NoError(t, err)
		assert.Len(t, decisions, 1)

		decisions, err = db.ListDecisions(ctx, "non-existent", 10, 0)
		assert.NoError(t, err)
		assert.Len(t, decisions, 0)
	})

	t.Run("Pagination", func(t *testing.T) {
		db := NewMockDB()
		defer db.Close()
		ctx := context.Background()

		// Create multiple policies
		for i := 0; i < 15; i++ {
			policy := &models.Policy{
				Name:        fmt.Sprintf("policy-%d", i),
				Description: fmt.Sprintf("Policy number %d", i),
				Rules:       "package test\nallow = true",
				Version:     "1.0.0",
				Active:      true,
			}
			err := db.CreatePolicy(ctx, policy)
			require.NoError(t, err)
		}

		// Test pagination
		page1, err := db.ListPolicies(ctx, 5, 0)
		assert.NoError(t, err)
		assert.Len(t, page1, 5)

		page2, err := db.ListPolicies(ctx, 5, 5)
		assert.NoError(t, err)
		assert.Len(t, page2, 5)

		page3, err := db.ListPolicies(ctx, 5, 10)
		assert.NoError(t, err)
		assert.Len(t, page3, 5)

		// Beyond available data
		page4, err := db.ListPolicies(ctx, 5, 15)
		assert.NoError(t, err)
		assert.Len(t, page4, 0)
	})

	t.Run("ErrorHandling", func(t *testing.T) {
		db := NewMockDB()
		ctx := context.Background()

		// Close database
		err := db.Close()
		assert.NoError(t, err)
		assert.True(t, db.closed)

		// Operations on closed database should fail
		err = db.Ping()
		assert.Error(t, err)
		assert.Equal(t, sql.ErrConnDone, err)

		policy := &models.Policy{Name: "test"}
		err = db.CreatePolicy(ctx, policy)
		assert.Error(t, err)

		_, err = db.GetPolicy(ctx, "any-id")
		assert.Error(t, err)

		_, err = db.ListPolicies(ctx, 10, 0)
		assert.Error(t, err)

		// Operations on non-existent entities
		db2 := NewMockDB()
		defer db2.Close()

		_, err = db2.GetPolicy(ctx, "non-existent")
		assert.Error(t, err)
		assert.Equal(t, sql.ErrNoRows, err)

		policy.ID = "non-existent"
		err = db2.UpdatePolicy(ctx, policy)
		assert.Error(t, err)
		assert.Equal(t, sql.ErrNoRows, err)

		err = db2.DeletePolicy(ctx, "non-existent")
		assert.Error(t, err)
		assert.Equal(t, sql.ErrNoRows, err)
	})

	t.Run("ConcurrentAccess", func(t *testing.T) {
		db := NewMockDB()
		defer db.Close()
		ctx := context.Background()

		// Test concurrent policy creation
		done := make(chan bool, 10)
		for i := 0; i < 10; i++ {
			go func(idx int) {
				policy := &models.Policy{
					Name:        fmt.Sprintf("concurrent-policy-%d", idx),
					Description: fmt.Sprintf("Policy created concurrently %d", idx),
					Rules:       "package test\nallow = true",
					Version:     "1.0.0",
					Active:      true,
				}
				err := db.CreatePolicy(ctx, policy)
				assert.NoError(t, err)
				done <- true
			}(i)
		}

		// Wait for all goroutines
		for i := 0; i < 10; i++ {
			<-done
		}

		// Verify all policies were created
		policies, err := db.ListPolicies(ctx, 20, 0)
		assert.NoError(t, err)
		assert.Len(t, policies, 10)
	})
}

func TestStorageInterface(t *testing.T) {
	t.Run("InterfaceCompliance", func(t *testing.T) {
		// Verify MockDB implements the expected interface
		var _ interface {
			Close() error
			Ping() error
			CreatePolicy(context.Context, *models.Policy) error
			GetPolicy(context.Context, string) (*models.Policy, error)
			ListPolicies(context.Context, int, int) ([]*models.Policy, error)
			UpdatePolicy(context.Context, *models.Policy) error
			DeletePolicy(context.Context, string) error
			CreateDecision(context.Context, *models.Decision) error
			GetDecision(context.Context, string) (*models.Decision, error)
			ListDecisions(context.Context, string, int, int) ([]*models.Decision, error)
		} = NewMockDB()
	})

	t.Run("DataConsistency", func(t *testing.T) {
		db := NewMockDB()
		defer db.Close()
		ctx := context.Background()

		// Create policy
		policy := &models.Policy{
			Name:        "consistency-test",
			Description: "Test data consistency",
			Rules:       "package test\nallow = true",
			Version:     "1.0.0",
			Active:      true,
		}

		err := db.CreatePolicy(ctx, policy)
		require.NoError(t, err)
		originalID := policy.ID

		// Create decision linked to policy
		decision := &models.Decision{
			PolicyID: originalID,
			Input:    map[string]interface{}{"user": "test"},
			Result:   "allow",
		}

		err = db.CreateDecision(ctx, decision)
		require.NoError(t, err)

		// Verify decision links to policy
		retrieved, err := db.GetDecision(ctx, decision.ID)
		require.NoError(t, err)
		assert.Equal(t, originalID, retrieved.PolicyID)

		// List decisions for the policy
		decisions, err := db.ListDecisions(ctx, originalID, 10, 0)
		require.NoError(t, err)
		assert.Len(t, decisions, 1)
		assert.Equal(t, originalID, decisions[0].PolicyID)
	})
}