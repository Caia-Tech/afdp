package plugins

import (
	"context"
	"database/sql"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/Caia-Tech/afdp/services/policy-engine/pkg/framework"
)

// MockPGDB simulates a PostgreSQL database for testing
type MockPGDB struct {
	connected bool
	data      map[string]interface{}
	queries   []string
}

func NewMockPGDB() *MockPGDB {
	return &MockPGDB{
		connected: false,
		data:      make(map[string]interface{}),
		queries:   make([]string, 0),
	}
}

func (m *MockPGDB) Connect() error {
	m.connected = true
	// Populate with test data
	m.data["users"] = map[string]interface{}{
		"alice": map[string]interface{}{
			"department": "engineering",
			"role":       "senior",
			"clearance":  "high",
		},
		"bob": map[string]interface{}{
			"department": "sales",
			"role":       "manager",
			"clearance":  "medium",
		},
	}
	m.data["permissions"] = map[string]interface{}{
		"engineering": []string{"read", "write", "deploy"},
		"sales":       []string{"read", "contact"},
	}
	return nil
}

func (m *MockPGDB) Close() error {
	m.connected = false
	return nil
}

func (m *MockPGDB) Query(query string, args ...interface{}) (map[string]interface{}, error) {
	if !m.connected {
		return nil, sql.ErrConnDone
	}
	
	m.queries = append(m.queries, query)
	
	// Simple query simulation
	if query == "SELECT * FROM users WHERE username = $1" && len(args) > 0 {
		username := args[0].(string)
		if users, ok := m.data["users"].(map[string]interface{}); ok {
			if user, exists := users[username]; exists {
				return user.(map[string]interface{}), nil
			}
		}
		return nil, sql.ErrNoRows
	}
	
	if query == "SELECT permissions FROM roles WHERE department = $1" && len(args) > 0 {
		dept := args[0].(string)
		if perms, ok := m.data["permissions"].(map[string]interface{}); ok {
			if deptPerms, exists := perms[dept]; exists {
				return map[string]interface{}{"permissions": deptPerms}, nil
			}
		}
		return nil, sql.ErrNoRows
	}
	
	// Default return all data
	return m.data, nil
}

func TestBuiltinPostgresDataSource(t *testing.T) {
	t.Run("CreateDataSource", func(t *testing.T) {
		config := framework.PluginConfig{
			Name: "test-postgres",
			Type: framework.PluginTypeDataSource,
			Config: map[string]interface{}{
				"host":     "localhost",
				"port":     5432,
				"database": "testdb",
				"username": "testuser",
				"password": "testpass",
				"max_connections": 10,
			},
		}

		ds := NewBuiltinPostgresDataSource(config)
		assert.NotNil(t, ds)
		assert.Equal(t, "test-postgres", ds.Name())
		assert.Equal(t, framework.PluginTypeDataSource, ds.Type())
	})

	t.Run("Initialize", func(t *testing.T) {
		config := framework.PluginConfig{
			Name: "init-test",
			Type: framework.PluginTypeDataSource,
			Config: map[string]interface{}{
				"host":     "localhost",
				"port":     5432,
				"database": "testdb",
				"username": "testuser",
				"password": "testpass",
			},
		}

		ds := NewBuiltinPostgresDataSource(config)
		ctx := context.Background()

		// Mock the database connection
		mockDB := NewMockPGDB()
		ds.(*BuiltinPostgresDataSource).db = mockDB

		err := ds.Initialize(ctx, config)
		assert.NoError(t, err)
		assert.True(t, mockDB.connected)
	})

	t.Run("StartStop", func(t *testing.T) {
		config := framework.PluginConfig{
			Name: "lifecycle-test",
			Type: framework.PluginTypeDataSource,
			Config: map[string]interface{}{
				"host": "localhost",
				"port": 5432,
			},
		}

		ds := NewBuiltinPostgresDataSource(config)
		ctx := context.Background()

		// Mock the database
		mockDB := NewMockPGDB()
		ds.(*BuiltinPostgresDataSource).db = mockDB

		err := ds.Initialize(ctx, config)
		require.NoError(t, err)

		err = ds.Start(ctx)
		assert.NoError(t, err)

		err = ds.Stop(ctx)
		assert.NoError(t, err)
		assert.False(t, mockDB.connected)
	})

	t.Run("QueryData", func(t *testing.T) {
		config := framework.PluginConfig{
			Name: "query-test",
			Type: framework.PluginTypeDataSource,
			Config: map[string]interface{}{
				"host": "localhost",
			},
		}

		ds := NewBuiltinPostgresDataSource(config)
		ctx := context.Background()

		// Mock and initialize
		mockDB := NewMockPGDB()
		mockDB.Connect()
		ds.(*BuiltinPostgresDataSource).db = mockDB

		err := ds.Initialize(ctx, config)
		require.NoError(t, err)
		err = ds.Start(ctx)
		require.NoError(t, err)
		defer ds.Stop(ctx)

		// Test user query
		req := &framework.DataQueryRequest{
			Query: "SELECT * FROM users WHERE username = $1",
			Parameters: []interface{}{"alice"},
		}

		resp, err := ds.(framework.DataSource).QueryData(ctx, req)
		assert.NoError(t, err)
		assert.NotNil(t, resp)
		assert.NotNil(t, resp.Data)
		
		userData := resp.Data
		assert.Equal(t, "engineering", userData["department"])
		assert.Equal(t, "senior", userData["role"])
		assert.Equal(t, "high", userData["clearance"])

		// Test permissions query
		req = &framework.DataQueryRequest{
			Query: "SELECT permissions FROM roles WHERE department = $1",
			Parameters: []interface{}{"engineering"},
		}

		resp, err = ds.(framework.DataSource).QueryData(ctx, req)
		assert.NoError(t, err)
		assert.NotNil(t, resp)
		
		perms := resp.Data["permissions"].([]string)
		assert.Contains(t, perms, "read")
		assert.Contains(t, perms, "write")
		assert.Contains(t, perms, "deploy")

		// Test non-existent user
		req = &framework.DataQueryRequest{
			Query: "SELECT * FROM users WHERE username = $1",
			Parameters: []interface{}{"nonexistent"},
		}

		_, err = ds.(framework.DataSource).QueryData(ctx, req)
		assert.Error(t, err)
	})

	t.Run("ConnectionPooling", func(t *testing.T) {
		config := framework.PluginConfig{
			Name: "pool-test",
			Type: framework.PluginTypeDataSource,
			Config: map[string]interface{}{
				"host": "localhost",
				"max_connections": 5,
				"max_idle": 2,
			},
		}

		ds := NewBuiltinPostgresDataSource(config)
		ctx := context.Background()

		mockDB := NewMockPGDB()
		mockDB.Connect()
		ds.(*BuiltinPostgresDataSource).db = mockDB

		err := ds.Initialize(ctx, config)
		require.NoError(t, err)

		// Simulate concurrent queries
		done := make(chan bool, 10)
		for i := 0; i < 10; i++ {
			go func(idx int) {
				req := &framework.DataQueryRequest{
					Query: "SELECT * FROM users WHERE username = $1",
					Parameters: []interface{}{"alice"},
				}
				_, err := ds.(framework.DataSource).QueryData(ctx, req)
				assert.NoError(t, err)
				done <- true
			}(i)
		}

		// Wait for completion
		for i := 0; i < 10; i++ {
			<-done
		}

		// Verify queries were executed
		assert.Len(t, mockDB.queries, 10)
	})

	t.Run("Health", func(t *testing.T) {
		config := framework.PluginConfig{
			Name: "health-test",
			Type: framework.PluginTypeDataSource,
		}

		ds := NewBuiltinPostgresDataSource(config)
		ctx := context.Background()

		// Before initialization
		health := ds.Health()
		assert.Equal(t, "unhealthy", health.Status)

		// After initialization
		mockDB := NewMockPGDB()
		mockDB.Connect()
		ds.(*BuiltinPostgresDataSource).db = mockDB

		err := ds.Initialize(ctx, config)
		require.NoError(t, err)

		health = ds.Health()
		assert.Equal(t, "healthy", health.Status)
		assert.Contains(t, health.Metadata, "connected")
		assert.True(t, health.Metadata["connected"].(bool))
	})

	t.Run("Metrics", func(t *testing.T) {
		config := framework.PluginConfig{
			Name: "metrics-test",
			Type: framework.PluginTypeDataSource,
		}

		ds := NewBuiltinPostgresDataSource(config)
		ctx := context.Background()

		mockDB := NewMockPGDB()
		mockDB.Connect()
		ds.(*BuiltinPostgresDataSource).db = mockDB

		err := ds.Initialize(ctx, config)
		require.NoError(t, err)
		err = ds.Start(ctx)
		require.NoError(t, err)
		defer ds.Stop(ctx)

		// Execute some queries
		for i := 0; i < 5; i++ {
			req := &framework.DataQueryRequest{
				Query: "SELECT * FROM users WHERE username = $1",
				Parameters: []interface{}{"alice"},
			}
			_, err := ds.(framework.DataSource).QueryData(ctx, req)
			assert.NoError(t, err)
		}

		metrics := ds.Metrics()
		assert.Contains(t, metrics, "queries_total")
		assert.Contains(t, metrics, "queries_success")
		assert.Equal(t, int64(5), metrics["queries_total"])
		assert.Equal(t, int64(5), metrics["queries_success"])
	})

	t.Run("ValidateConfig", func(t *testing.T) {
		ds := NewBuiltinPostgresDataSource(framework.PluginConfig{})

		// Valid config
		validConfig := framework.PluginConfig{
			Config: map[string]interface{}{
				"host":     "localhost",
				"port":     5432,
				"database": "testdb",
				"username": "user",
				"password": "pass",
			},
		}

		result := ds.ValidateConfig(validConfig)
		assert.True(t, result.Valid)
		assert.Empty(t, result.Errors)

		// Missing required fields
		invalidConfig := framework.PluginConfig{
			Config: map[string]interface{}{
				"host": "localhost",
				// Missing database, username, password
			},
		}

		result = ds.ValidateConfig(invalidConfig)
		assert.False(t, result.Valid)
		assert.Contains(t, result.Errors, "database is required")
		assert.Contains(t, result.Errors, "username is required")
		assert.Contains(t, result.Errors, "password is required")

		// Invalid port
		invalidPortConfig := framework.PluginConfig{
			Config: map[string]interface{}{
				"host":     "localhost",
				"port":     "invalid-port",
				"database": "testdb",
				"username": "user",
				"password": "pass",
			},
		}

		result = ds.ValidateConfig(invalidPortConfig)
		assert.False(t, result.Valid)
		assert.NotEmpty(t, result.Errors)
	})

	t.Run("Reload", func(t *testing.T) {
		config := framework.PluginConfig{
			Name: "reload-test",
			Type: framework.PluginTypeDataSource,
			Config: map[string]interface{}{
				"host":     "localhost",
				"database": "testdb",
				"username": "user",
				"password": "pass",
				"max_connections": 5,
			},
		}

		ds := NewBuiltinPostgresDataSource(config)
		ctx := context.Background()

		mockDB := NewMockPGDB()
		mockDB.Connect()
		ds.(*BuiltinPostgresDataSource).db = mockDB

		err := ds.Initialize(ctx, config)
		require.NoError(t, err)

		// Reload with new config
		newConfig := framework.PluginConfig{
			Name: "reload-test",
			Type: framework.PluginTypeDataSource,
			Config: map[string]interface{}{
				"host":     "localhost",
				"database": "newdb",
				"username": "newuser",
				"password": "newpass",
				"max_connections": 10,
			},
		}

		err = ds.Reload(ctx, newConfig)
		assert.NoError(t, err)

		// Verify config was updated
		pgDS := ds.(*BuiltinPostgresDataSource)
		assert.Equal(t, newConfig, pgDS.config)
	})

	t.Run("ErrorHandling", func(t *testing.T) {
		config := framework.PluginConfig{
			Name: "error-test",
			Type: framework.PluginTypeDataSource,
		}

		ds := NewBuiltinPostgresDataSource(config)
		ctx := context.Background()

		// Test query without initialization
		req := &framework.DataQueryRequest{
			Query: "SELECT * FROM users",
		}

		_, err := ds.(framework.DataSource).QueryData(ctx, req)
		assert.Error(t, err)

		// Test with closed connection
		mockDB := NewMockPGDB()
		ds.(*BuiltinPostgresDataSource).db = mockDB
		
		err = ds.Initialize(ctx, config)
		require.NoError(t, err)
		
		// Close the connection
		mockDB.Close()
		
		_, err = ds.(framework.DataSource).QueryData(ctx, req)
		assert.Error(t, err)
		assert.Equal(t, sql.ErrConnDone, err)
	})
}