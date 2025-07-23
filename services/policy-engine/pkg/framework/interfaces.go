// Package framework defines the core interfaces for the AFDP Policy Framework
// These interfaces enable the plugin architecture and extensibility
package framework

import (
	"context"
	"time"
)

// FrameworkCore represents the main framework orchestration engine
type FrameworkCore interface {
	// Plugin management
	RegisterPlugin(pluginType string, name string, plugin Plugin) error
	UnregisterPlugin(pluginType string, name string) error
	GetPlugin(pluginType string, name string) (Plugin, error)
	ListPlugins(pluginType string) []PluginInfo

	// Configuration management
	LoadConfiguration(configPath string) error
	ReloadConfiguration() error
	GetConfiguration() *FrameworkConfig
	ValidateConfiguration(config *FrameworkConfig) error

	// Lifecycle management
	Start(ctx context.Context) error
	Stop(ctx context.Context) error
	Health() HealthStatus

	// Event system
	Subscribe(eventType string, handler EventHandler) error
	Unsubscribe(eventType string, handler EventHandler) error
	PublishEvent(event *Event) error

	// Decision engine access
	GetDecisionEngine() DecisionEngine
}

// Plugin is the base interface that all plugins must implement
type Plugin interface {
	// Plugin identification and metadata
	Name() string
	Version() string
	Type() PluginType
	Metadata() PluginMetadata

	// Plugin lifecycle
	Initialize(ctx context.Context, config PluginConfig) error
	Start(ctx context.Context) error
	Stop(ctx context.Context) error
	Reload(ctx context.Context, config PluginConfig) error

	// Health and status
	Health() HealthStatus
	Metrics() PluginMetrics

	// Configuration validation
	ValidateConfig(config PluginConfig) ValidationResult
}

// PolicyEvaluator interface for policy evaluation plugins
type PolicyEvaluator interface {
	Plugin

	// Policy compilation and validation
	CompilePolicy(ctx context.Context, req *CompilePolicyRequest) (*CompilePolicyResponse, error)
	ValidatePolicy(ctx context.Context, req *ValidatePolicyRequest) (*ValidatePolicyResponse, error)

	// Policy evaluation
	Evaluate(ctx context.Context, req *EvaluationRequest) (*EvaluationResponse, error)
	EvaluateBatch(ctx context.Context, req *BatchEvaluationRequest) (*BatchEvaluationResponse, error)

	// Policy management
	LoadPolicy(ctx context.Context, req *LoadPolicyRequest) (*LoadPolicyResponse, error)
	UnloadPolicy(ctx context.Context, req *UnloadPolicyRequest) (*UnloadPolicyResponse, error)
	ListPolicies(ctx context.Context, req *ListPoliciesRequest) (*ListPoliciesResponse, error)

	// Capabilities and features
	SupportedLanguages() []string
	SupportedFeatures() []string
}

// DataSource interface for data source plugins
type DataSource interface {
	Plugin

	// Data retrieval
	Fetch(ctx context.Context, req *FetchRequest) (*FetchResponse, error)
	Stream(ctx context.Context, req *StreamRequest) (DataStream, error)
	Query(ctx context.Context, req *QueryRequest) (*QueryResponse, error)

	// Schema and capabilities
	Schema(ctx context.Context) (*DataSchema, error)
	SupportedQueryTypes() []QueryType
	SupportedDataTypes() []DataType

	// Connection management
	Connect(ctx context.Context) error
	Disconnect(ctx context.Context) error
	TestConnection(ctx context.Context) (*ConnectionTestResult, error)
}

// Workflow interface for workflow orchestration plugins
type Workflow interface {
	Plugin

	// Workflow execution
	StartWorkflow(ctx context.Context, req *StartWorkflowRequest) (*StartWorkflowResponse, error)
	GetWorkflowStatus(ctx context.Context, req *GetWorkflowStatusRequest) (*GetWorkflowStatusResponse, error)
	CancelWorkflow(ctx context.Context, req *CancelWorkflowRequest) (*CancelWorkflowResponse, error)

	// Event handling
	HandleEvent(ctx context.Context, req *HandleEventRequest) (*HandleEventResponse, error)
	SubscribeToEvents(ctx context.Context, req *SubscribeRequest) (EventStream, error)

	// Workflow management
	ListActiveWorkflows(ctx context.Context, req *ListActiveWorkflowsRequest) (*ListActiveWorkflowsResponse, error)
	GetWorkflowHistory(ctx context.Context, req *GetWorkflowHistoryRequest) (*GetWorkflowHistoryResponse, error)

	// Workflow definition
	LoadWorkflowDefinition(ctx context.Context, req *LoadWorkflowDefinitionRequest) (*LoadWorkflowDefinitionResponse, error)
	ValidateWorkflowDefinition(ctx context.Context, req *ValidateWorkflowDefinitionRequest) (*ValidateWorkflowDefinitionResponse, error)
}

// SecurityProvider interface for authentication and authorization plugins
type SecurityProvider interface {
	Plugin

	// Authentication
	Authenticate(ctx context.Context, req *AuthenticationRequest) (*AuthenticationResponse, error)
	RefreshToken(ctx context.Context, req *RefreshTokenRequest) (*RefreshTokenResponse, error)
	RevokeToken(ctx context.Context, req *RevokeTokenRequest) (*RevokeTokenResponse, error)

	// Authorization
	Authorize(ctx context.Context, req *AuthorizationRequest) (*AuthorizationResponse, error)
	GetPermissions(ctx context.Context, req *GetPermissionsRequest) (*GetPermissionsResponse, error)

	// User and role management
	GetUser(ctx context.Context, req *GetUserRequest) (*GetUserResponse, error)
	ListRoles(ctx context.Context, req *ListRolesRequest) (*ListRolesResponse, error)
	AssignRole(ctx context.Context, req *AssignRoleRequest) (*AssignRoleResponse, error)
}

// AuditProvider interface for audit and compliance plugins
type AuditProvider interface {
	Plugin

	// Audit logging
	LogEvent(ctx context.Context, event *AuditEvent) error
	LogBatchEvents(ctx context.Context, events []*AuditEvent) error

	// Audit queries
	QueryEvents(ctx context.Context, req *QueryEventsRequest) (*QueryEventsResponse, error)
	GetEvent(ctx context.Context, req *GetEventRequest) (*GetEventResponse, error)

	// Compliance reporting
	GenerateReport(ctx context.Context, req *GenerateReportRequest) (*GenerateReportResponse, error)
	ListReports(ctx context.Context, req *ListReportsRequest) (*ListReportsResponse, error)

	// Retention and archival
	ArchiveEvents(ctx context.Context, req *ArchiveEventsRequest) (*ArchiveEventsResponse, error)
	DeleteEvents(ctx context.Context, req *DeleteEventsRequest) (*DeleteEventsResponse, error)
}

// StorageProvider interface for storage backend plugins
type StorageProvider interface {
	Plugin

	// Basic storage operations
	Store(ctx context.Context, key string, data []byte) error
	Retrieve(ctx context.Context, key string) ([]byte, error)
	Delete(ctx context.Context, key string) error
	Exists(ctx context.Context, key string) (bool, error)

	// Batch operations
	StoreBatch(ctx context.Context, items map[string][]byte) error
	RetrieveBatch(ctx context.Context, keys []string) (map[string][]byte, error)
	DeleteBatch(ctx context.Context, keys []string) error

	// Querying and listing
	List(ctx context.Context, prefix string) ([]string, error)
	Query(ctx context.Context, query StorageQuery) (*StorageQueryResult, error)

	// Transactions
	BeginTransaction(ctx context.Context) (Transaction, error)

	// Backup and restore
	Backup(ctx context.Context, req *BackupRequest) (*BackupResponse, error)
	Restore(ctx context.Context, req *RestoreRequest) (*RestoreResponse, error)
}

// NotificationProvider interface for notification plugins
type NotificationProvider interface {
	Plugin

	// Send notifications
	SendNotification(ctx context.Context, req *SendNotificationRequest) (*SendNotificationResponse, error)
	SendBatchNotifications(ctx context.Context, req *SendBatchNotificationsRequest) (*SendBatchNotificationsResponse, error)

	// Template management
	CreateTemplate(ctx context.Context, req *CreateTemplateRequest) (*CreateTemplateResponse, error)
	UpdateTemplate(ctx context.Context, req *UpdateTemplateRequest) (*UpdateTemplateResponse, error)
	DeleteTemplate(ctx context.Context, req *DeleteTemplateRequest) (*DeleteTemplateResponse, error)

	// Notification status
	GetNotificationStatus(ctx context.Context, req *GetNotificationStatusRequest) (*GetNotificationStatusResponse, error)
	ListNotifications(ctx context.Context, req *ListNotificationsRequest) (*ListNotificationsResponse, error)

	// Webhook support
	RegisterWebhook(ctx context.Context, req *RegisterWebhookRequest) (*RegisterWebhookResponse, error)
	HandleWebhook(ctx context.Context, req *HandleWebhookRequest) (*HandleWebhookResponse, error)
}

// MonitoringProvider interface for monitoring and metrics plugins
type MonitoringProvider interface {
	Plugin

	// Metrics collection
	RecordMetric(ctx context.Context, metric *Metric) error
	RecordBatchMetrics(ctx context.Context, metrics []*Metric) error

	// Metric queries
	QueryMetrics(ctx context.Context, req *QueryMetricsRequest) (*QueryMetricsResponse, error)
	GetMetricHistory(ctx context.Context, req *GetMetricHistoryRequest) (*GetMetricHistoryResponse, error)

	// Alerting
	CreateAlert(ctx context.Context, req *CreateAlertRequest) (*CreateAlertResponse, error)
	UpdateAlert(ctx context.Context, req *UpdateAlertRequest) (*UpdateAlertResponse, error)
	DeleteAlert(ctx context.Context, req *DeleteAlertRequest) (*DeleteAlertResponse, error)

	// Health monitoring
	RegisterHealthCheck(ctx context.Context, req *RegisterHealthCheckRequest) (*RegisterHealthCheckResponse, error)
	RunHealthCheck(ctx context.Context, req *RunHealthCheckRequest) (*RunHealthCheckResponse, error)
}

// EventHandler interface for event processing
type EventHandler interface {
	HandleEvent(ctx context.Context, event *Event) error
	EventTypes() []string
}

// Transaction interface for storage transactions
type Transaction interface {
	Store(ctx context.Context, key string, data []byte) error
	Retrieve(ctx context.Context, key string) ([]byte, error)
	Delete(ctx context.Context, key string) error
	Commit(ctx context.Context) error
	Rollback(ctx context.Context) error
}

// DataStream interface for streaming data
type DataStream interface {
	Next() (*StreamEvent, error)
	Close() error
}

// EventStream interface for streaming events
type EventStream interface {
	Next() (*Event, error)
	Close() error
}

// PluginFactory interface for creating plugin instances
type PluginFactory interface {
	CreatePlugin(pluginType PluginType, config PluginConfig) (Plugin, error)
	SupportedTypes() []PluginType
	ValidateConfig(pluginType PluginType, config PluginConfig) ValidationResult
}

// PluginRegistry interface for plugin discovery and management
type PluginRegistry interface {
	// Plugin discovery
	DiscoverPlugins(ctx context.Context) ([]PluginInfo, error)
	GetPluginInfo(ctx context.Context, name string, version string) (*PluginInfo, error)
	SearchPlugins(ctx context.Context, query PluginQuery) ([]PluginInfo, error)

	// Plugin distribution
	DownloadPlugin(ctx context.Context, req *DownloadPluginRequest) (*DownloadPluginResponse, error)
	InstallPlugin(ctx context.Context, req *InstallPluginRequest) (*InstallPluginResponse, error)
	UninstallPlugin(ctx context.Context, req *UninstallPluginRequest) (*UninstallPluginResponse, error)

	// Plugin versioning
	ListVersions(ctx context.Context, pluginName string) ([]string, error)
	GetLatestVersion(ctx context.Context, pluginName string) (string, error)
	CheckForUpdates(ctx context.Context) ([]PluginUpdate, error)
}

// ConfigurationManager interface for configuration management
type ConfigurationManager interface {
	// Configuration loading and validation
	LoadConfiguration(configPath string) (*FrameworkConfig, error)
	ValidateConfiguration(config *FrameworkConfig) ValidationResult
	MergeConfigurations(base *FrameworkConfig, overrides ...*FrameworkConfig) (*FrameworkConfig, error)

	// Hot reload support
	WatchConfiguration(ctx context.Context, callback ConfigurationChangeCallback) error
	ReloadConfiguration(ctx context.Context) error

	// Environment-specific configuration
	LoadEnvironmentConfig(environment string) (*FrameworkConfig, error)
	GetEffectiveConfiguration() *FrameworkConfig

	// Configuration templates
	LoadTemplate(templateName string) (*ConfigurationTemplate, error)
	ApplyTemplate(template *ConfigurationTemplate, variables map[string]interface{}) (*FrameworkConfig, error)
}

// SecurityManager interface for security operations
type SecurityManager interface {
	// Cryptographic operations
	Sign(ctx context.Context, data []byte) (*Signature, error)
	Verify(ctx context.Context, data []byte, signature *Signature) error
	Encrypt(ctx context.Context, data []byte) ([]byte, error)
	Decrypt(ctx context.Context, encryptedData []byte) ([]byte, error)

	// Key management
	GenerateKey(ctx context.Context, keyType KeyType) (*Key, error)
	RotateKey(ctx context.Context, keyID string) (*Key, error)
	GetKey(ctx context.Context, keyID string) (*Key, error)
	DeleteKey(ctx context.Context, keyID string) error

	// Certificate management
	GenerateCertificate(ctx context.Context, req *GenerateCertificateRequest) (*Certificate, error)
	ValidateCertificate(ctx context.Context, cert *Certificate) error
	RevokeCertificate(ctx context.Context, certID string) error
}

// DecisionEngine interface for the core decision-making engine
type DecisionEngine interface {
	// Decision processing
	EvaluatePolicy(ctx context.Context, req *PolicyEvaluationRequest) (*PolicyDecision, error)
	EvaluateBatchPolicies(ctx context.Context, req *BatchPolicyEvaluationRequest) (*BatchPolicyDecision, error)

	// Pipeline orchestration
	ExecutePipeline(ctx context.Context, req *PipelineExecutionRequest) (*PipelineExecutionResponse, error)
	GetPipelineStatus(ctx context.Context, req *GetPipelineStatusRequest) (*PipelineStatusResponse, error)

	// Decision storage and retrieval
	StoreDecision(ctx context.Context, decision *PolicyDecision) error
	GetDecision(ctx context.Context, decisionID string) (*PolicyDecision, error)
	QueryDecisions(ctx context.Context, query *DecisionQuery) (*DecisionQueryResponse, error)

	// Analytics and insights
	GenerateAnalytics(ctx context.Context, req *AnalyticsRequest) (*AnalyticsResponse, error)
	GetDecisionMetrics(ctx context.Context, req *MetricsRequest) (*MetricsResponse, error)
}

// Callback functions
type ConfigurationChangeCallback func(oldConfig, newConfig *FrameworkConfig) error
type PluginStatusCallback func(plugin Plugin, status PluginStatus) error
type EventCallback func(event *Event) error

// Common data structures

// PluginType represents the type of plugin
type PluginType string

const (
	PluginTypeEvaluator     PluginType = "evaluator"
	PluginTypeDataSource    PluginType = "data_source"
	PluginTypeWorkflow      PluginType = "workflow"
	PluginTypeSecurity      PluginType = "security"
	PluginTypeAudit         PluginType = "audit"
	PluginTypeStorage       PluginType = "storage"
	PluginTypeNotification  PluginType = "notification"
	PluginTypeMonitoring    PluginType = "monitoring"
)

// PluginStatus represents the current status of a plugin
type PluginStatus string

const (
	PluginStatusUnknown      PluginStatus = "unknown"
	PluginStatusInitializing PluginStatus = "initializing"
	PluginStatusStarting     PluginStatus = "starting"
	PluginStatusRunning      PluginStatus = "running"
	PluginStatusStopping     PluginStatus = "stopping"
	PluginStatusStopped      PluginStatus = "stopped"
	PluginStatusError        PluginStatus = "error"
)

// HealthStatus represents the health status of a component
type HealthStatus struct {
	Status      string                 `json:"status"`       // healthy, unhealthy, degraded
	Message     string                 `json:"message"`
	LastCheck   time.Time              `json:"last_check"`
	CheckCount  int64                  `json:"check_count"`
	Metadata    map[string]interface{} `json:"metadata"`
}

// PluginInfo contains metadata about a plugin
type PluginInfo struct {
	Name         string                 `json:"name"`
	Version      string                 `json:"version"`
	Type         PluginType             `json:"type"`
	Description  string                 `json:"description"`
	Author       string                 `json:"author"`
	License      string                 `json:"license"`
	Tags         []string               `json:"tags"`
	Capabilities []string               `json:"capabilities"`
	Dependencies []PluginDependency     `json:"dependencies"`
	Metadata     map[string]interface{} `json:"metadata"`
}

// PluginDependency represents a plugin dependency
type PluginDependency struct {
	Name    string `json:"name"`
	Version string `json:"version"`
	Type    string `json:"type"`
}

// PluginMetadata contains runtime metadata about a plugin
type PluginMetadata struct {
	StartTime    time.Time              `json:"start_time"`
	Uptime       time.Duration          `json:"uptime"`
	RequestCount int64                  `json:"request_count"`
	ErrorCount   int64                  `json:"error_count"`
	LastError    string                 `json:"last_error,omitempty"`
	Metadata     map[string]interface{} `json:"metadata"`
}

// PluginMetrics contains performance metrics for a plugin
type PluginMetrics struct {
	CPUUsage     float64   `json:"cpu_usage"`
	MemoryUsage  int64     `json:"memory_usage"`
	RequestRate  float64   `json:"request_rate"`
	ErrorRate    float64   `json:"error_rate"`
	Latency      Latency   `json:"latency"`
	Timestamp    time.Time `json:"timestamp"`
}

// Latency metrics
type Latency struct {
	P50  time.Duration `json:"p50"`
	P95  time.Duration `json:"p95"`
	P99  time.Duration `json:"p99"`
	Mean time.Duration `json:"mean"`
}

// ValidationResult contains validation results
type ValidationResult struct {
	Valid    bool               `json:"valid"`
	Errors   []ValidationError  `json:"errors,omitempty"`
	Warnings []ValidationError  `json:"warnings,omitempty"`
}

// ValidationError represents a validation error or warning
type ValidationError struct {
	Field    string `json:"field"`
	Message  string `json:"message"`
	Code     string `json:"code"`
	Severity string `json:"severity"`
}

// Event represents a framework event
type Event struct {
	ID          string                 `json:"id"`
	Type        string                 `json:"type"`
	Source      string                 `json:"source"`
	Timestamp   time.Time              `json:"timestamp"`
	Data        map[string]interface{} `json:"data"`
	Metadata    map[string]interface{} `json:"metadata"`
}

// FrameworkConfig represents the main framework configuration
type FrameworkConfig struct {
	Version       string                 `yaml:"version"`
	Name          string                 `yaml:"name"`
	Description   string                 `yaml:"description"`
	Framework     FrameworkCoreConfig    `yaml:"framework"`
	API           APIConfig              `yaml:"api"`
	Plugins       []PluginConfig         `yaml:"plugins"`
	Security      SecurityConfig         `yaml:"security"`
	Storage       StorageConfig          `yaml:"storage"`
	Monitoring    MonitoringConfig       `yaml:"monitoring"`
	DynamicConfig DynamicConfig          `yaml:"dynamic_config"`
	Metadata      map[string]interface{} `yaml:"metadata"`
}

// FrameworkCoreConfig contains core framework settings
type FrameworkCoreConfig struct {
	Logging     LoggingConfig     `yaml:"logging"`
	Metrics     MetricsConfig     `yaml:"metrics"`
	Tracing     TracingConfig     `yaml:"tracing"`
	Health      HealthConfig      `yaml:"health"`
	Performance PerformanceConfig `yaml:"performance"`
}

// PluginConfig contains configuration for a specific plugin
type PluginConfig struct {
	Name         string                 `yaml:"name"`
	Type         PluginType             `yaml:"type"`
	Enabled      bool                   `yaml:"enabled"`
	Source       PluginSource           `yaml:"source"`
	Config       map[string]interface{} `yaml:"config"`
	Resources    ResourceConfig         `yaml:"resources"`
	Security     PluginSecurityConfig   `yaml:"security"`
}

// PluginSource defines where to find the plugin
type PluginSource struct {
	Type       string `yaml:"type"`        // oci, git, local, http
	Location   string `yaml:"location"`    // URL, path, etc.
	Version    string `yaml:"version"`
	Checksum   string `yaml:"checksum"`
	Signature  string `yaml:"signature"`
}

// ResourceConfig defines resource limits for plugins
type ResourceConfig struct {
	CPU    string `yaml:"cpu"`
	Memory string `yaml:"memory"`
	Storage string `yaml:"storage"`
	GPU    string `yaml:"gpu,omitempty"`
}

// Configuration structs for various components
type LoggingConfig struct {
	Level  string `yaml:"level"`
	Format string `yaml:"format"`
	Output string `yaml:"output"`
}

type MetricsConfig struct {
	Enabled   bool   `yaml:"enabled"`
	Port      int    `yaml:"port"`
	Path      string `yaml:"path"`
	Namespace string `yaml:"namespace"`
}

type TracingConfig struct {
	Enabled     bool          `yaml:"enabled"`
	ServiceName string        `yaml:"service_name"`
	Jaeger      JaegerConfig  `yaml:"jaeger"`
}

type JaegerConfig struct {
	Endpoint string `yaml:"endpoint"`
}

type HealthConfig struct {
	Enabled  bool   `yaml:"enabled"`
	Port     int    `yaml:"port"`
	Path     string `yaml:"path"`
	Interval string `yaml:"interval"`
}

type PerformanceConfig struct {
	MaxConcurrentRequests int           `yaml:"max_concurrent_requests"`
	RequestTimeout        time.Duration `yaml:"request_timeout"`
	MaxMemory             string        `yaml:"max_memory"`
}

type SecurityConfig struct {
	Authentication AuthenticationConfig `yaml:"authentication"`
	Authorization  AuthorizationConfig  `yaml:"authorization"`
	Cryptography   CryptographyConfig   `yaml:"cryptography"`
}

type AuthenticationConfig struct {
	Primary  AuthProviderConfig   `yaml:"primary"`
	Fallback []AuthProviderConfig `yaml:"fallback"`
	MFA      MFAConfig            `yaml:"mfa"`
}

type AuthProviderConfig struct {
	Type   string                 `yaml:"type"`
	Config map[string]interface{} `yaml:"config"`
}

type MFAConfig struct {
	Enabled   bool     `yaml:"enabled"`
	Providers []string `yaml:"providers"`
}

type AuthorizationConfig struct {
	Model string                 `yaml:"model"`
	RBAC  RBACConfig             `yaml:"rbac"`
	ABAC  ABACConfig             `yaml:"abac"`
	Config map[string]interface{} `yaml:"config"`
}

type RBACConfig struct {
	Roles       map[string]Role       `yaml:"roles"`
	Assignments []RoleAssignment      `yaml:"assignments"`
}

type Role struct {
	Permissions []string `yaml:"permissions"`
	Inherits    []string `yaml:"inherits"`
}

type RoleAssignment struct {
	User  string   `yaml:"user,omitempty"`
	Group string   `yaml:"group,omitempty"`
	Roles []string `yaml:"roles"`
}

type ABACConfig struct {
	Enabled    bool   `yaml:"enabled"`
	PolicyFile string `yaml:"policy_file"`
}

type CryptographyConfig struct {
	Signing    SigningConfig    `yaml:"signing"`
	Encryption EncryptionConfig `yaml:"encryption"`
	TLS        TLSConfig        `yaml:"tls"`
}

type SigningConfig struct {
	Algorithm         string        `yaml:"algorithm"`
	KeyFile           string        `yaml:"key_file"`
	KeyRotationInterval time.Duration `yaml:"key_rotation_interval"`
}

type EncryptionConfig struct {
	Algorithm     string `yaml:"algorithm"`
	KeyDerivation string `yaml:"key_derivation"`
}

type TLSConfig struct {
	MinVersion   string   `yaml:"min_version"`
	CipherSuites []string `yaml:"cipher_suites"`
}

type StorageConfig struct {
	PostgreSQL PostgreSQLConfig `yaml:"postgresql"`
	Redis      RedisConfig      `yaml:"redis"`
	S3         S3Config         `yaml:"s3"`
}

type PostgreSQLConfig struct {
	Host     string `yaml:"host"`
	Port     int    `yaml:"port"`
	Database string `yaml:"database"`
	Username string `yaml:"username"`
	Password string `yaml:"password"`
}

type RedisConfig struct {
	URL      string `yaml:"url"`
	Password string `yaml:"password"`
}

type S3Config struct {
	Endpoint  string `yaml:"endpoint"`
	Region    string `yaml:"region"`
	Bucket    string `yaml:"bucket"`
	AccessKey string `yaml:"access_key"`
	SecretKey string `yaml:"secret_key"`
}

type MonitoringConfig struct {
	Prometheus PrometheusConfig `yaml:"prometheus"`
	Grafana    GrafanaConfig    `yaml:"grafana"`
	Alerting   AlertingConfig   `yaml:"alerting"`
}

type PrometheusConfig struct {
	Enabled        bool   `yaml:"enabled"`
	ScrapeInterval string `yaml:"scrape_interval"`
}

type GrafanaConfig struct {
	Enabled    bool     `yaml:"enabled"`
	Dashboards []string `yaml:"dashboards"`
}

type AlertingConfig struct {
	Rules []AlertRule `yaml:"rules"`
}

type AlertRule struct {
	Name      string `yaml:"name"`
	Condition string `yaml:"condition"`
	Duration  string `yaml:"duration"`
	Severity  string `yaml:"severity"`
}

type PluginSecurityConfig struct {
	RunAsUser                int      `yaml:"run_as_user"`
	RunAsGroup               int      `yaml:"run_as_group"`
	ReadOnlyRootFilesystem   bool     `yaml:"read_only_root_filesystem"`
	AllowedNetworkDestinations []string `yaml:"allowed_network_destinations"`
}

// Request/Response types for plugin interfaces would be defined here
// These are examples - full implementation would include all request/response types

type EvaluationRequest struct {
	PolicyID    string                 `json:"policy_id"`
	Input       map[string]interface{} `json:"input"`
	Context     *EvaluationContext     `json:"context"`
	Options     *EvaluationOptions     `json:"options"`
}

type EvaluationResponse struct {
	Decision    PolicyDecision         `json:"decision"`
	Reasoning   string                 `json:"reasoning"`
	Confidence  float64                `json:"confidence"`
	Metadata    map[string]interface{} `json:"metadata"`
	Metrics     *EvaluationMetrics     `json:"metrics"`
}

type PolicyDecision struct {
	Result      string                 `json:"result"`
	Approvers   []string               `json:"approvers,omitempty"`
	Conditions  []string               `json:"conditions,omitempty"`
	Metadata    map[string]interface{} `json:"metadata"`
}

type EvaluationContext struct {
	RequestID     string                 `json:"request_id"`
	UserID        string                 `json:"user_id"`
	Timestamp     time.Time              `json:"timestamp"`
	Environment   string                 `json:"environment"`
	CorrelationID string                 `json:"correlation_id"`
	Metadata      map[string]interface{} `json:"metadata"`
}

type EvaluationOptions struct {
	Timeout        time.Duration          `json:"timeout"`
	Cache          bool                   `json:"cache"`
	Explain        bool                   `json:"explain"`
	DryRun         bool                   `json:"dry_run"`
	Options        map[string]interface{} `json:"options"`
}

type EvaluationMetrics struct {
	EvaluationTime time.Duration `json:"evaluation_time"`
	CacheHit       bool          `json:"cache_hit"`
	PluginLatency  time.Duration `json:"plugin_latency"`
	DataFetchTime  time.Duration `json:"data_fetch_time"`
}

// PolicyEvaluator request/response types

type CompilePolicyRequest struct {
	PolicyID string `json:"policy_id"`
	Policy   string `json:"policy"`
	Query    string `json:"query"`
}

type CompilePolicyResponse struct {
	PolicyID string                 `json:"policy_id"`
	Success  bool                   `json:"success"`
	Metadata map[string]interface{} `json:"metadata"`
}

type ValidatePolicyRequest struct {
	Policy string `json:"policy"`
}

type ValidatePolicyResponse struct {
	Valid    bool               `json:"valid"`
	Errors   []ValidationError  `json:"errors,omitempty"`
	Warnings []ValidationError  `json:"warnings,omitempty"`
}

type BatchEvaluationRequest struct {
	Requests []*EvaluationRequest `json:"requests"`
}

type BatchEvaluationResponse struct {
	Responses []*EvaluationResponse `json:"responses"`
}

type LoadPolicyRequest struct {
	PolicyID string `json:"policy_id"`
	Policy   string `json:"policy"`
	Query    string `json:"query,omitempty"`
}

type LoadPolicyResponse struct {
	PolicyID string `json:"policy_id"`
	Success  bool   `json:"success"`
}

type UnloadPolicyRequest struct {
	PolicyID string `json:"policy_id"`
}

type UnloadPolicyResponse struct {
	PolicyID string `json:"policy_id"`
	Success  bool   `json:"success"`
}

type ListPoliciesRequest struct {
	Filter string `json:"filter,omitempty"`
}

type ListPoliciesResponse struct {
	Policies []PolicyInfo `json:"policies"`
}

type PolicyInfo struct {
	PolicyID   string                 `json:"policy_id"`
	CompiledAt time.Time              `json:"compiled_at"`
	Metadata   map[string]interface{} `json:"metadata"`
}

// DataSource request/response types

type FetchRequest struct {
	Query    map[string]interface{} `json:"query"`
	Options  map[string]interface{} `json:"options,omitempty"`
}

type FetchResponse struct {
	Data     map[string]interface{} `json:"data"`
	Metadata map[string]interface{} `json:"metadata"`
}

type StreamRequest struct {
	Query    map[string]interface{} `json:"query"`
	Options  map[string]interface{} `json:"options,omitempty"`
}

type QueryRequest struct {
	Query    string                 `json:"query"`
	Parameters map[string]interface{} `json:"parameters,omitempty"`
}

type QueryResponse struct {
	Results  []map[string]interface{} `json:"results"`
	Metadata map[string]interface{}   `json:"metadata"`
}

type DataSchema struct {
	Tables  []TableSchema          `json:"tables"`
	Metadata map[string]interface{} `json:"metadata"`
}

type TableSchema struct {
	Name    string         `json:"name"`
	Columns []ColumnSchema `json:"columns"`
}

type ColumnSchema struct {
	Name     string `json:"name"`
	Type     string `json:"type"`
	Nullable bool   `json:"nullable"`
}

type ConnectionTestResult struct {
	Success  bool   `json:"success"`
	Message  string `json:"message"`
	Latency  time.Duration `json:"latency"`
}

type QueryType string

const (
	QueryTypeSQL   QueryType = "sql"
	QueryTypeNoSQL QueryType = "nosql"
	QueryTypeGraph QueryType = "graph"
)

type DataType string

const (
	DataTypeStructured   DataType = "structured"
	DataTypeUnstructured DataType = "unstructured"
	DataTypeTimeSeries   DataType = "timeseries"
)

type StreamEvent struct {
	Type      string                 `json:"type"`
	Data      map[string]interface{} `json:"data"`
	Timestamp time.Time              `json:"timestamp"`
}

// Decision Engine types

type PolicyEvaluationRequest struct {
	PolicyID    string                 `json:"policy_id"`
	PolicyType  string                 `json:"policy_type"`
	Input       map[string]interface{} `json:"input"`
	Context     *EvaluationContext     `json:"context"`
	Options     *EvaluationOptions     `json:"options"`
	DataSources []string               `json:"data_sources,omitempty"`
}

type BatchPolicyEvaluationRequest struct {
	Requests []*PolicyEvaluationRequest `json:"requests"`
}

type BatchPolicyDecision struct {
	Decisions []*PolicyDecision      `json:"decisions"`
	Errors    []error                `json:"errors"`
	Metadata  map[string]interface{} `json:"metadata"`
}

type PipelineExecutionRequest struct {
	PipelineID  string                 `json:"pipeline_id"`
	Input       map[string]interface{} `json:"input"`
	Context     *EvaluationContext     `json:"context"`
	Options     *EvaluationOptions     `json:"options"`
	DataSources []string               `json:"data_sources,omitempty"`
}

type PipelineExecutionResponse struct {
	ExecutionID string `json:"execution_id"`
	Status      string `json:"status"`
	Message     string `json:"message"`
}

type GetPipelineStatusRequest struct {
	PipelineID string `json:"pipeline_id"`
}

type PipelineStatusResponse struct {
	ExecutionID  string           `json:"execution_id"`
	PipelineID   string           `json:"pipeline_id"`
	Status       string           `json:"status"`
	CurrentStep  string           `json:"current_step"`
	StartTime    time.Time        `json:"start_time"`
	EndTime      time.Time        `json:"end_time,omitempty"`
	Duration     time.Duration    `json:"duration,omitempty"`
	StepStatuses []StepStatus     `json:"step_statuses"`
	FinalResult  *PolicyDecision  `json:"final_result,omitempty"`
	Error        string           `json:"error,omitempty"`
}

type StepStatus struct {
	Name      string        `json:"name"`
	Status    string        `json:"status"`
	StartTime time.Time     `json:"start_time"`
	EndTime   time.Time     `json:"end_time"`
	Error     string        `json:"error,omitempty"`
}

type DecisionQuery struct {
	UserID    string    `json:"user_id,omitempty"`
	PolicyID  string    `json:"policy_id,omitempty"`
	StartTime time.Time `json:"start_time,omitempty"`
	EndTime   time.Time `json:"end_time,omitempty"`
	Result    string    `json:"result,omitempty"`
	Limit     int       `json:"limit,omitempty"`
}

type DecisionQueryResponse struct {
	Decisions []*PolicyDecision `json:"decisions"`
	Total     int               `json:"total"`
	NextToken string            `json:"next_token,omitempty"`
}

type AnalyticsRequest struct {
	StartTime time.Time `json:"start_time"`
	EndTime   time.Time `json:"end_time"`
	GroupBy   []string  `json:"group_by,omitempty"`
}

type AnalyticsResponse struct {
	Metrics map[string]interface{} `json:"metrics"`
}

type MetricsRequest struct {
	MetricNames []string  `json:"metric_names"`
	StartTime   time.Time `json:"start_time"`
	EndTime     time.Time `json:"end_time"`
}

type MetricsResponse struct {
	Metrics map[string]interface{} `json:"metrics"`
}

// Plugin Registry types

type PluginQuery struct {
	Type         string   `json:"type,omitempty"`
	Tags         []string `json:"tags,omitempty"`
	Capabilities []string `json:"capabilities,omitempty"`
	Name         string   `json:"name,omitempty"`
	Author       string   `json:"author,omitempty"`
}

type PluginUpdate struct {
	Name           string `json:"name"`
	CurrentVersion string `json:"current_version"`
	LatestVersion  string `json:"latest_version"`
	ReleaseNotes   string `json:"release_notes"`
}

type DownloadPluginRequest struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

type DownloadPluginResponse struct {
	Data     []byte                 `json:"data"`
	Checksum string                 `json:"checksum"`
	Metadata map[string]interface{} `json:"metadata"`
}

type InstallPluginRequest struct {
	Name    string `json:"name"`
	Version string `json:"version"`
	Data    []byte `json:"data"`
}

type InstallPluginResponse struct {
	Success bool   `json:"success"`
	Message string `json:"message"`
}

type UninstallPluginRequest struct {
	Name string `json:"name"`
}

type UninstallPluginResponse struct {
	Success bool   `json:"success"`
	Message string `json:"message"`
}

// Storage types

type StorageQuery struct {
	Filter   map[string]interface{} `json:"filter"`
	Sort     []SortOption           `json:"sort,omitempty"`
	Limit    int                    `json:"limit,omitempty"`
	Offset   int                    `json:"offset,omitempty"`
}

type SortOption struct {
	Field     string `json:"field"`
	Direction string `json:"direction"` // asc, desc
}

type StorageQueryResult struct {
	Items    []map[string]interface{} `json:"items"`
	Total    int                      `json:"total"`
	NextPage string                   `json:"next_page,omitempty"`
}

type BackupRequest struct {
	Destination string   `json:"destination"`
	Incremental bool     `json:"incremental"`
	Compress    bool     `json:"compress"`
	Encrypt     bool     `json:"encrypt"`
	Keys        []string `json:"keys,omitempty"`
}

type BackupResponse struct {
	BackupID  string                 `json:"backup_id"`
	Size      int64                  `json:"size"`
	ItemCount int                    `json:"item_count"`
	Metadata  map[string]interface{} `json:"metadata"`
}

type RestoreRequest struct {
	Source    string   `json:"source"`
	BackupID  string   `json:"backup_id"`
	Keys      []string `json:"keys,omitempty"`
	Overwrite bool     `json:"overwrite"`
}

type RestoreResponse struct {
	Success      bool   `json:"success"`
	ItemsRestored int    `json:"items_restored"`
	Message      string `json:"message"`
}

// Workflow types

type StartWorkflowRequest struct {
	WorkflowID string                 `json:"workflow_id"`
	Input      map[string]interface{} `json:"input"`
	Context    map[string]interface{} `json:"context,omitempty"`
}

type StartWorkflowResponse struct {
	ExecutionID string `json:"execution_id"`
	Status      string `json:"status"`
}

type GetWorkflowStatusRequest struct {
	ExecutionID string `json:"execution_id"`
}

type GetWorkflowStatusResponse struct {
	ExecutionID string                 `json:"execution_id"`
	WorkflowID  string                 `json:"workflow_id"`
	Status      string                 `json:"status"`
	StartTime   time.Time              `json:"start_time"`
	EndTime     *time.Time             `json:"end_time,omitempty"`
	Output      map[string]interface{} `json:"output,omitempty"`
	Error       string                 `json:"error,omitempty"`
}

type CancelWorkflowRequest struct {
	ExecutionID string `json:"execution_id"`
	Reason      string `json:"reason,omitempty"`
}

type CancelWorkflowResponse struct {
	Success bool   `json:"success"`
	Message string `json:"message"`
}

type HandleEventRequest struct {
	Event *Event `json:"event"`
}

type HandleEventResponse struct {
	Handled bool   `json:"handled"`
	Message string `json:"message"`
}

type SubscribeRequest struct {
	EventTypes []string `json:"event_types"`
}

type ListActiveWorkflowsRequest struct {
	Filter string `json:"filter,omitempty"`
	Limit  int    `json:"limit,omitempty"`
}

type ListActiveWorkflowsResponse struct {
	Workflows []WorkflowExecution `json:"workflows"`
}

type WorkflowExecution struct {
	ExecutionID string    `json:"execution_id"`
	WorkflowID  string    `json:"workflow_id"`
	Status      string    `json:"status"`
	StartTime   time.Time `json:"start_time"`
}

type GetWorkflowHistoryRequest struct {
	WorkflowID string `json:"workflow_id"`
	Limit      int    `json:"limit,omitempty"`
}

type GetWorkflowHistoryResponse struct {
	Executions []WorkflowExecution `json:"executions"`
}

type LoadWorkflowDefinitionRequest struct {
	WorkflowID string `json:"workflow_id"`
	Definition string `json:"definition"`
}

type LoadWorkflowDefinitionResponse struct {
	Success bool   `json:"success"`
	Message string `json:"message"`
}

type ValidateWorkflowDefinitionRequest struct {
	Definition string `json:"definition"`
}

type ValidateWorkflowDefinitionResponse struct {
	Valid    bool              `json:"valid"`
	Errors   []ValidationError `json:"errors,omitempty"`
	Warnings []ValidationError `json:"warnings,omitempty"`
}

// Security types

type AuthenticationRequest struct {
	Credentials map[string]interface{} `json:"credentials"`
	Method      string                 `json:"method"`
}

type AuthenticationResponse struct {
	Success     bool                   `json:"success"`
	Token       string                 `json:"token,omitempty"`
	ExpiresAt   time.Time              `json:"expires_at,omitempty"`
	UserInfo    map[string]interface{} `json:"user_info,omitempty"`
}

type RefreshTokenRequest struct {
	Token string `json:"token"`
}

type RefreshTokenResponse struct {
	Token     string    `json:"token"`
	ExpiresAt time.Time `json:"expires_at"`
}

type RevokeTokenRequest struct {
	Token string `json:"token"`
}

type RevokeTokenResponse struct {
	Success bool   `json:"success"`
	Message string `json:"message"`
}

type AuthorizationRequest struct {
	UserID   string `json:"user_id"`
	Resource string `json:"resource"`
	Action   string `json:"action"`
}

type AuthorizationResponse struct {
	Allowed bool     `json:"allowed"`
	Reason  string   `json:"reason,omitempty"`
	Roles   []string `json:"roles,omitempty"`
}

type GetPermissionsRequest struct {
	UserID string `json:"user_id"`
}

type GetPermissionsResponse struct {
	Permissions []Permission `json:"permissions"`
}

type Permission struct {
	Resource string   `json:"resource"`
	Actions  []string `json:"actions"`
}

type GetUserRequest struct {
	UserID string `json:"user_id"`
}

type GetUserResponse struct {
	UserID   string                 `json:"user_id"`
	Username string                 `json:"username"`
	Email    string                 `json:"email,omitempty"`
	Roles    []string               `json:"roles"`
	Metadata map[string]interface{} `json:"metadata,omitempty"`
}

type ListRolesRequest struct {
	Filter string `json:"filter,omitempty"`
}

type ListRolesResponse struct {
	Roles []RoleInfo `json:"roles"`
}

type RoleInfo struct {
	Name        string   `json:"name"`
	Description string   `json:"description"`
	Permissions []string `json:"permissions"`
}

type AssignRoleRequest struct {
	UserID string `json:"user_id"`
	Role   string `json:"role"`
}

type AssignRoleResponse struct {
	Success bool   `json:"success"`
	Message string `json:"message"`
}

// Audit types

type AuditEvent struct {
	ID        string                 `json:"id"`
	Timestamp time.Time              `json:"timestamp"`
	UserID    string                 `json:"user_id"`
	Action    string                 `json:"action"`
	Resource  string                 `json:"resource"`
	Result    string                 `json:"result"`
	Metadata  map[string]interface{} `json:"metadata,omitempty"`
}

type QueryEventsRequest struct {
	Filter    map[string]interface{} `json:"filter"`
	StartTime time.Time              `json:"start_time"`
	EndTime   time.Time              `json:"end_time"`
	Limit     int                    `json:"limit,omitempty"`
}

type QueryEventsResponse struct {
	Events    []*AuditEvent `json:"events"`
	NextToken string        `json:"next_token,omitempty"`
}

type GetEventRequest struct {
	EventID string `json:"event_id"`
}

type GetEventResponse struct {
	Event *AuditEvent `json:"event"`
}

type GenerateReportRequest struct {
	ReportType string    `json:"report_type"`
	StartTime  time.Time `json:"start_time"`
	EndTime    time.Time `json:"end_time"`
	Format     string    `json:"format"` // pdf, csv, json
}

type GenerateReportResponse struct {
	ReportID string `json:"report_id"`
	Status   string `json:"status"`
}

type ListReportsRequest struct {
	Filter string `json:"filter,omitempty"`
}

type ListReportsResponse struct {
	Reports []ReportInfo `json:"reports"`
}

type ReportInfo struct {
	ReportID   string    `json:"report_id"`
	ReportType string    `json:"report_type"`
	CreatedAt  time.Time `json:"created_at"`
	Status     string    `json:"status"`
}

type ArchiveEventsRequest struct {
	StartTime   time.Time `json:"start_time"`
	EndTime     time.Time `json:"end_time"`
	Destination string    `json:"destination"`
}

type ArchiveEventsResponse struct {
	ArchivedCount int    `json:"archived_count"`
	ArchiveID     string `json:"archive_id"`
}

type DeleteEventsRequest struct {
	StartTime time.Time `json:"start_time"`
	EndTime   time.Time `json:"end_time"`
}

type DeleteEventsResponse struct {
	DeletedCount int `json:"deleted_count"`
}

// Notification types

type SendNotificationRequest struct {
	Recipients []string               `json:"recipients"`
	Template   string                 `json:"template"`
	Data       map[string]interface{} `json:"data"`
	Channel    string                 `json:"channel"` // email, sms, webhook
}

type SendNotificationResponse struct {
	NotificationID string `json:"notification_id"`
	Status         string `json:"status"`
}

type SendBatchNotificationsRequest struct {
	Notifications []*SendNotificationRequest `json:"notifications"`
}

type SendBatchNotificationsResponse struct {
	Results []SendNotificationResult `json:"results"`
}

type SendNotificationResult struct {
	NotificationID string `json:"notification_id"`
	Status         string `json:"status"`
	Error          string `json:"error,omitempty"`
}

type CreateTemplateRequest struct {
	Name     string `json:"name"`
	Content  string `json:"content"`
	Channel  string `json:"channel"`
	Metadata map[string]interface{} `json:"metadata,omitempty"`
}

type CreateTemplateResponse struct {
	TemplateID string `json:"template_id"`
	Success    bool   `json:"success"`
}

type UpdateTemplateRequest struct {
	TemplateID string `json:"template_id"`
	Content    string `json:"content"`
	Metadata   map[string]interface{} `json:"metadata,omitempty"`
}

type UpdateTemplateResponse struct {
	Success bool   `json:"success"`
	Message string `json:"message"`
}

type DeleteTemplateRequest struct {
	TemplateID string `json:"template_id"`
}

type DeleteTemplateResponse struct {
	Success bool   `json:"success"`
	Message string `json:"message"`
}

type GetNotificationStatusRequest struct {
	NotificationID string `json:"notification_id"`
}

type GetNotificationStatusResponse struct {
	NotificationID string    `json:"notification_id"`
	Status         string    `json:"status"`
	SentAt         time.Time `json:"sent_at,omitempty"`
	DeliveredAt    time.Time `json:"delivered_at,omitempty"`
	Error          string    `json:"error,omitempty"`
}

type ListNotificationsRequest struct {
	Filter string `json:"filter,omitempty"`
	Limit  int    `json:"limit,omitempty"`
}

type ListNotificationsResponse struct {
	Notifications []NotificationInfo `json:"notifications"`
}

type NotificationInfo struct {
	NotificationID string    `json:"notification_id"`
	Template       string    `json:"template"`
	Recipients     []string  `json:"recipients"`
	Status         string    `json:"status"`
	CreatedAt      time.Time `json:"created_at"`
}

type RegisterWebhookRequest struct {
	URL      string   `json:"url"`
	Events   []string `json:"events"`
	Secret   string   `json:"secret,omitempty"`
	Metadata map[string]interface{} `json:"metadata,omitempty"`
}

type RegisterWebhookResponse struct {
	WebhookID string `json:"webhook_id"`
	Success   bool   `json:"success"`
}

type HandleWebhookRequest struct {
	WebhookID string                 `json:"webhook_id"`
	Event     string                 `json:"event"`
	Data      map[string]interface{} `json:"data"`
}

type HandleWebhookResponse struct {
	Success bool   `json:"success"`
	Message string `json:"message"`
}

// Monitoring types

type Metric struct {
	Name      string                 `json:"name"`
	Value     float64                `json:"value"`
	Tags      map[string]string      `json:"tags,omitempty"`
	Timestamp time.Time              `json:"timestamp"`
	Type      string                 `json:"type"` // gauge, counter, histogram
	Unit      string                 `json:"unit,omitempty"`
	Metadata  map[string]interface{} `json:"metadata,omitempty"`
}

type QueryMetricsRequest struct {
	MetricNames []string               `json:"metric_names"`
	Tags        map[string]string      `json:"tags,omitempty"`
	StartTime   time.Time              `json:"start_time"`
	EndTime     time.Time              `json:"end_time"`
	Resolution  string                 `json:"resolution,omitempty"` // 1m, 5m, 1h, etc
	Aggregation string                 `json:"aggregation,omitempty"` // avg, sum, min, max
}

type QueryMetricsResponse struct {
	Metrics []MetricSeries `json:"metrics"`
}

type MetricSeries struct {
	Name       string       `json:"name"`
	DataPoints []DataPoint  `json:"data_points"`
	Tags       map[string]string `json:"tags,omitempty"`
}

type DataPoint struct {
	Timestamp time.Time `json:"timestamp"`
	Value     float64   `json:"value"`
}

type GetMetricHistoryRequest struct {
	MetricName string            `json:"metric_name"`
	Tags       map[string]string `json:"tags,omitempty"`
	StartTime  time.Time         `json:"start_time"`
	EndTime    time.Time         `json:"end_time"`
	Limit      int               `json:"limit,omitempty"`
}

type GetMetricHistoryResponse struct {
	History []DataPoint `json:"history"`
}

type CreateAlertRequest struct {
	Name        string                 `json:"name"`
	Description string                 `json:"description,omitempty"`
	Condition   string                 `json:"condition"`
	Threshold   float64                `json:"threshold"`
	Duration    string                 `json:"duration"` // e.g., "5m"
	Actions     []AlertAction          `json:"actions"`
	Tags        map[string]string      `json:"tags,omitempty"`
	Metadata    map[string]interface{} `json:"metadata,omitempty"`
}

type AlertAction struct {
	Type   string                 `json:"type"` // notify, webhook, execute
	Config map[string]interface{} `json:"config"`
}

type CreateAlertResponse struct {
	AlertID string `json:"alert_id"`
	Success bool   `json:"success"`
}

type UpdateAlertRequest struct {
	AlertID     string                 `json:"alert_id"`
	Description string                 `json:"description,omitempty"`
	Condition   string                 `json:"condition,omitempty"`
	Threshold   float64                `json:"threshold,omitempty"`
	Duration    string                 `json:"duration,omitempty"`
	Actions     []AlertAction          `json:"actions,omitempty"`
	Tags        map[string]string      `json:"tags,omitempty"`
	Metadata    map[string]interface{} `json:"metadata,omitempty"`
}

type UpdateAlertResponse struct {
	Success bool   `json:"success"`
	Message string `json:"message"`
}

type DeleteAlertRequest struct {
	AlertID string `json:"alert_id"`
}

type DeleteAlertResponse struct {
	Success bool   `json:"success"`
	Message string `json:"message"`
}

type RegisterHealthCheckRequest struct {
	Name        string        `json:"name"`
	Description string        `json:"description,omitempty"`
	Type        string        `json:"type"` // http, tcp, script
	Target      string        `json:"target"`
	Interval    time.Duration `json:"interval"`
	Timeout     time.Duration `json:"timeout"`
	Config      map[string]interface{} `json:"config,omitempty"`
}

type RegisterHealthCheckResponse struct {
	CheckID string `json:"check_id"`
	Success bool   `json:"success"`
}

type RunHealthCheckRequest struct {
	CheckID string `json:"check_id"`
}

type RunHealthCheckResponse struct {
	Status   string                 `json:"status"` // healthy, unhealthy, degraded
	Message  string                 `json:"message,omitempty"`
	Duration time.Duration          `json:"duration"`
	Metadata map[string]interface{} `json:"metadata,omitempty"`
}

// Security Manager types

type Signature struct {
	Algorithm string `json:"algorithm"`
	Value     []byte `json:"value"`
	KeyID     string `json:"key_id"`
}

type KeyType string

const (
	KeyTypeRSA     KeyType = "rsa"
	KeyTypeECDSA   KeyType = "ecdsa"
	KeyTypeED25519 KeyType = "ed25519"
)

type Key struct {
	ID        string                 `json:"id"`
	Type      KeyType                `json:"type"`
	PublicKey []byte                 `json:"public_key"`
	CreatedAt time.Time              `json:"created_at"`
	ExpiresAt *time.Time             `json:"expires_at,omitempty"`
	Metadata  map[string]interface{} `json:"metadata,omitempty"`
}

type GenerateCertificateRequest struct {
	Subject      string        `json:"subject"`
	KeyType      KeyType       `json:"key_type"`
	ValidityDays int           `json:"validity_days"`
	SANs         []string      `json:"sans,omitempty"` // Subject Alternative Names
	Usage        []string      `json:"usage,omitempty"`
}

type Certificate struct {
	ID          string     `json:"id"`
	Certificate []byte     `json:"certificate"`
	PrivateKey  []byte     `json:"private_key,omitempty"`
	IssuedAt    time.Time  `json:"issued_at"`
	ExpiresAt   time.Time  `json:"expires_at"`
	Subject     string     `json:"subject"`
	Issuer      string     `json:"issuer"`
}

// Configuration types

type ConfigurationTemplate struct {
	Name        string                 `json:"name"`
	Description string                 `json:"description"`
	Version     string                 `json:"version"`
	Template    string                 `json:"template"`
	Variables   []TemplateVariable     `json:"variables"`
	Metadata    map[string]interface{} `json:"metadata,omitempty"`
}

type TemplateVariable struct {
	Name         string      `json:"name"`
	Description  string      `json:"description,omitempty"`
	Type         string      `json:"type"`
	Default      interface{} `json:"default,omitempty"`
	Required     bool        `json:"required"`
	Validation   string      `json:"validation,omitempty"`
}

// API types

type APIConfig struct {
	REST RESTConfig `yaml:"rest"`
	GRPC GRPCConfig `yaml:"grpc"`
}

type RESTConfig struct {
	Enabled bool   `yaml:"enabled"`
	Host    string `yaml:"host"`
	Port    int    `yaml:"port"`
	TLS     TLSConfig `yaml:"tls"`
}

type GRPCConfig struct {
	Enabled bool   `yaml:"enabled"`
	Host    string `yaml:"host"`
	Port    int    `yaml:"port"`
	TLS     TLSConfig `yaml:"tls"`
}

// Dynamic configuration types

type DynamicConfig struct {
	HotReload HotReloadConfig `yaml:"hot_reload"`
}

type HotReloadConfig struct {
	Enabled  bool   `yaml:"enabled"`
	Interval string `yaml:"interval"`
}

// Additional request/response types would be defined similarly...
// This is a subset to demonstrate the pattern