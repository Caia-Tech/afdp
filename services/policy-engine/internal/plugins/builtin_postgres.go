package plugins

import (
	"context"
	"database/sql"
	"fmt"
	"time"
	
	_ "github.com/lib/pq"
	"github.com/Caia-Tech/afdp/services/policy-engine/pkg/framework"
)

// BuiltinPostgresDataSource is the built-in PostgreSQL data source
type BuiltinPostgresDataSource struct {
	config    framework.PluginConfig
	db        *sql.DB
	startTime time.Time
	status    framework.PluginStatus
}

// NewBuiltinPostgresDataSource creates a new PostgreSQL data source
func NewBuiltinPostgresDataSource(config framework.PluginConfig) (framework.Plugin, error) {
	return &BuiltinPostgresDataSource{
		config: config,
		status: framework.PluginStatusUnknown,
	}, nil
}

// Plugin interface implementation

func (p *BuiltinPostgresDataSource) Name() string {
	return p.config.Name
}

func (p *BuiltinPostgresDataSource) Version() string {
	return "1.0.0"
}

func (p *BuiltinPostgresDataSource) Type() framework.PluginType {
	return framework.PluginTypeDataSource
}

func (p *BuiltinPostgresDataSource) Metadata() framework.PluginMetadata {
	return framework.PluginMetadata{
		StartTime:    p.startTime,
		Uptime:       time.Since(p.startTime),
		RequestCount: 0,
		ErrorCount:   0,
		Metadata: map[string]interface{}{
			"driver":      "postgres",
			"driver_version": "1.10.0",
		},
	}
}

func (p *BuiltinPostgresDataSource) Initialize(ctx context.Context, config framework.PluginConfig) error {
	p.status = framework.PluginStatusInitializing
	
	// Build connection string from config
	connStr := p.buildConnectionString(config.Config)
	
	// Open database connection
	db, err := sql.Open("postgres", connStr)
	if err != nil {
		return fmt.Errorf("failed to open database: %w", err)
	}
	
	// Set connection pool settings
	if maxConns, ok := config.Config["max_connections"].(int); ok {
		db.SetMaxOpenConns(maxConns)
	} else {
		db.SetMaxOpenConns(10)
	}
	
	if maxIdle, ok := config.Config["max_idle_connections"].(int); ok {
		db.SetMaxIdleConns(maxIdle)
	} else {
		db.SetMaxIdleConns(5)
	}
	
	p.db = db
	
	return nil
}

func (p *BuiltinPostgresDataSource) Start(ctx context.Context) error {
	p.status = framework.PluginStatusStarting
	p.startTime = time.Now()
	
	// Test connection
	if err := p.db.PingContext(ctx); err != nil {
		return fmt.Errorf("failed to ping database: %w", err)
	}
	
	p.status = framework.PluginStatusRunning
	return nil
}

func (p *BuiltinPostgresDataSource) Stop(ctx context.Context) error {
	p.status = framework.PluginStatusStopping
	
	if p.db != nil {
		if err := p.db.Close(); err != nil {
			return fmt.Errorf("failed to close database: %w", err)
		}
	}
	
	p.status = framework.PluginStatusStopped
	return nil
}

func (p *BuiltinPostgresDataSource) Reload(ctx context.Context, config framework.PluginConfig) error {
	// Close existing connection
	if p.db != nil {
		p.db.Close()
	}
	
	// Reinitialize with new config
	p.config = config
	return p.Initialize(ctx, config)
}

func (p *BuiltinPostgresDataSource) Health() framework.HealthStatus {
	status := "healthy"
	message := "PostgreSQL connection is healthy"
	
	if p.status != framework.PluginStatusRunning {
		status = "unhealthy"
		message = fmt.Sprintf("Plugin is in %s state", p.status)
	} else if p.db != nil {
		// Test database connection
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		
		if err := p.db.PingContext(ctx); err != nil {
			status = "unhealthy"
			message = fmt.Sprintf("Database ping failed: %v", err)
		}
	}
	
	return framework.HealthStatus{
		Status:    status,
		Message:   message,
		LastCheck: time.Now(),
		Metadata: map[string]interface{}{
			"uptime": time.Since(p.startTime).String(),
		},
	}
}

func (p *BuiltinPostgresDataSource) Metrics() framework.PluginMetrics {
	return framework.PluginMetrics{
		CPUUsage:    0.0,
		MemoryUsage: 0,
		RequestRate: 0.0,
		ErrorRate:   0.0,
		Timestamp:   time.Now(),
	}
}

func (p *BuiltinPostgresDataSource) ValidateConfig(config framework.PluginConfig) framework.ValidationResult {
	result := framework.ValidationResult{
		Valid: true,
	}
	
	// Validate required fields
	requiredFields := []string{"host", "port", "database", "username"}
	for _, field := range requiredFields {
		if _, exists := config.Config[field]; !exists {
			result.Valid = false
			result.Errors = append(result.Errors, framework.ValidationError{
				Field:    fmt.Sprintf("config.%s", field),
				Message:  fmt.Sprintf("%s is required", field),
				Code:     "required_field",
				Severity: "error",
			})
		}
	}
	
	return result
}

// DataSource interface implementation

func (p *BuiltinPostgresDataSource) Fetch(ctx context.Context, req *framework.FetchRequest) (*framework.FetchResponse, error) {
	// Simple implementation - execute query and return results
	query, ok := req.Query["sql"].(string)
	if !ok {
		return nil, fmt.Errorf("sql query not provided")
	}
	
	rows, err := p.db.QueryContext(ctx, query)
	if err != nil {
		return nil, fmt.Errorf("query failed: %w", err)
	}
	defer rows.Close()
	
	// Get column names
	columns, err := rows.Columns()
	if err != nil {
		return nil, fmt.Errorf("failed to get columns: %w", err)
	}
	
	// Scan results
	var results []map[string]interface{}
	for rows.Next() {
		// Create a slice of interface{}'s to represent each column
		columnValues := make([]interface{}, len(columns))
		columnPointers := make([]interface{}, len(columns))
		for i := range columnValues {
			columnPointers[i] = &columnValues[i]
		}
		
		// Scan the result into the column pointers...
		if err := rows.Scan(columnPointers...); err != nil {
			return nil, fmt.Errorf("scan failed: %w", err)
		}
		
		// Create map of column name to value
		m := make(map[string]interface{})
		for i, colName := range columns {
			val := columnPointers[i].(*interface{})
			m[colName] = *val
		}
		
		results = append(results, m)
	}
	
	return &framework.FetchResponse{
		Data: map[string]interface{}{
			"results": results,
			"count":   len(results),
		},
		Metadata: map[string]interface{}{
			"query": query,
		},
	}, nil
}

func (p *BuiltinPostgresDataSource) Stream(ctx context.Context, req *framework.StreamRequest) (framework.DataStream, error) {
	// Not implemented for basic version
	return nil, fmt.Errorf("streaming not implemented")
}

func (p *BuiltinPostgresDataSource) Query(ctx context.Context, req *framework.QueryRequest) (*framework.QueryResponse, error) {
	// Execute parameterized query
	rows, err := p.db.QueryContext(ctx, req.Query)
	if err != nil {
		return nil, fmt.Errorf("query failed: %w", err)
	}
	defer rows.Close()
	
	// Get column names
	columns, err := rows.Columns()
	if err != nil {
		return nil, fmt.Errorf("failed to get columns: %w", err)
	}
	
	// Scan results
	var results []map[string]interface{}
	for rows.Next() {
		columnValues := make([]interface{}, len(columns))
		columnPointers := make([]interface{}, len(columns))
		for i := range columnValues {
			columnPointers[i] = &columnValues[i]
		}
		
		if err := rows.Scan(columnPointers...); err != nil {
			return nil, fmt.Errorf("scan failed: %w", err)
		}
		
		m := make(map[string]interface{})
		for i, colName := range columns {
			val := columnPointers[i].(*interface{})
			m[colName] = *val
		}
		
		results = append(results, m)
	}
	
	return &framework.QueryResponse{
		Results: results,
		Metadata: map[string]interface{}{
			"row_count": len(results),
		},
	}, nil
}

func (p *BuiltinPostgresDataSource) Schema(ctx context.Context) (*framework.DataSchema, error) {
	// Query information schema
	query := `
		SELECT table_name, column_name, data_type, is_nullable
		FROM information_schema.columns
		WHERE table_schema = 'public'
		ORDER BY table_name, ordinal_position
	`
	
	rows, err := p.db.QueryContext(ctx, query)
	if err != nil {
		return nil, fmt.Errorf("schema query failed: %w", err)
	}
	defer rows.Close()
	
	// Build schema
	tables := make(map[string]*framework.TableSchema)
	
	for rows.Next() {
		var tableName, columnName, dataType, isNullable string
		if err := rows.Scan(&tableName, &columnName, &dataType, &isNullable); err != nil {
			return nil, fmt.Errorf("scan failed: %w", err)
		}
		
		if _, exists := tables[tableName]; !exists {
			tables[tableName] = &framework.TableSchema{
				Name:    tableName,
				Columns: []framework.ColumnSchema{},
			}
		}
		
		tables[tableName].Columns = append(tables[tableName].Columns, framework.ColumnSchema{
			Name:     columnName,
			Type:     dataType,
			Nullable: isNullable == "YES",
		})
	}
	
	// Convert to slice
	var tableList []framework.TableSchema
	for _, table := range tables {
		tableList = append(tableList, *table)
	}
	
	return &framework.DataSchema{
		Tables: tableList,
	}, nil
}

func (p *BuiltinPostgresDataSource) SupportedQueryTypes() []framework.QueryType {
	return []framework.QueryType{framework.QueryTypeSQL}
}

func (p *BuiltinPostgresDataSource) SupportedDataTypes() []framework.DataType {
	return []framework.DataType{framework.DataTypeStructured}
}

func (p *BuiltinPostgresDataSource) Connect(ctx context.Context) error {
	return p.db.PingContext(ctx)
}

func (p *BuiltinPostgresDataSource) Disconnect(ctx context.Context) error {
	return p.db.Close()
}

func (p *BuiltinPostgresDataSource) TestConnection(ctx context.Context) (*framework.ConnectionTestResult, error) {
	start := time.Now()
	err := p.db.PingContext(ctx)
	latency := time.Since(start)
	
	result := &framework.ConnectionTestResult{
		Success: err == nil,
		Latency: latency,
	}
	
	if err != nil {
		result.Message = err.Error()
	} else {
		result.Message = "Connection successful"
	}
	
	return result, nil
}

// Helper methods

func (p *BuiltinPostgresDataSource) buildConnectionString(config map[string]interface{}) string {
	// Build PostgreSQL connection string
	host := config["host"].(string)
	port := config["port"].(int)
	database := config["database"].(string)
	username := config["username"].(string)
	password, _ := config["password"].(string)
	
	connStr := fmt.Sprintf("host=%s port=%d dbname=%s user=%s",
		host, port, database, username)
	
	if password != "" {
		connStr += fmt.Sprintf(" password=%s", password)
	}
	
	if sslMode, ok := config["ssl_mode"].(string); ok {
		connStr += fmt.Sprintf(" sslmode=%s", sslMode)
	} else {
		connStr += " sslmode=disable"
	}
	
	return connStr
}