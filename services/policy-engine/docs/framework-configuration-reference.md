# AFDP Framework Configuration Reference

**Document Version:** 1.0  
**Last Updated:** July 2025  
**Classification:** Public  
**Author:** AFDP Framework Configuration Team  

## 📋 Table of Contents

1. [Introduction](#introduction)
2. [Configuration Hierarchy](#configuration-hierarchy)
3. [Framework Core Configuration](#framework-core-configuration)
4. [Plugin Configuration](#plugin-configuration)
5. [Security Configuration](#security-configuration)
6. [Performance Configuration](#performance-configuration)
7. [Deployment Configuration](#deployment-configuration)
8. [Environment-Specific Configuration](#environment-specific-configuration)
9. [Configuration Validation](#configuration-validation)
10. [Dynamic Configuration](#dynamic-configuration)
11. [Configuration Examples](#configuration-examples)
12. [Troubleshooting](#troubleshooting)

## 🎯 Introduction

The AFDP Policy Framework is **configuration-driven**, meaning complex policy systems can be built, modified, and deployed through declarative configuration files rather than code changes. This approach enables rapid iteration, easier maintenance, and safer deployments.

This reference guide provides comprehensive documentation for all configuration options, patterns, and best practices for the AFDP Framework.

### Configuration Philosophy

**Declarative Over Imperative:** Describe what you want, not how to achieve it  
**Environment Agnostic:** Same configuration works across development, staging, and production  
**Validation First:** All configuration is validated before application  
**Hot Reload Capable:** Most configuration changes applied without restart  
**Security Conscious:** Secrets and sensitive data handled securely  

### Configuration Formats

The framework supports multiple configuration formats:

- **YAML** (recommended): Human-readable, comment-friendly
- **JSON**: Machine-readable, API-friendly  
- **TOML**: Configuration-focused, type-safe
- **Environment Variables**: Container and cloud-native deployments

## 🏗️ Configuration Hierarchy

### Configuration Loading Order

The framework loads configuration in the following precedence order (highest to lowest):

1. **Command Line Arguments** (`--config`, `--log-level`)
2. **Environment Variables** (`AFDP_*` prefixed)
3. **Configuration Files** (specified by `--config` or auto-discovered)
4. **Default Values** (built into framework)

### Auto-Discovery Paths

The framework automatically searches for configuration files in:

```
./framework.yaml
./config/framework.yaml
/etc/afdp/framework.yaml
~/.afdp/framework.yaml
```

### Configuration Composition

Large configurations can be split across multiple files:

```yaml
# Main configuration file
framework:
  version: "1.0.0"
  includes:
    - "plugins/evaluators.yaml"
    - "plugins/data_sources.yaml"
    - "plugins/workflows.yaml"
    - "security/auth.yaml"
    - "environments/${ENVIRONMENT}.yaml"
```

## ⚙️ Framework Core Configuration

### Basic Framework Settings

```yaml
# framework.yaml
apiVersion: afdp.io/v1
kind: FrameworkConfig
metadata:
  name: policy-framework
  namespace: afdp-production
  version: "1.0.0"

# Framework core settings
framework:
  # Basic identification
  name: "afdp-policy-framework"
  version: "1.0.0"
  description: "Enterprise policy framework for AI governance"
  
  # Logging configuration
  logging:
    level: "info"                    # debug, info, warn, error
    format: "json"                   # text, json
    output: "stdout"                 # stdout, stderr, file
    file_path: "/var/log/afdp.log"   # if output is file
    rotation:
      max_size: "100MB"
      max_files: 10
      max_age: "30d"
      
  # Metrics and observability
  metrics:
    enabled: true
    port: 9090
    path: "/metrics"
    namespace: "afdp_framework"
    labels:
      environment: "${ENVIRONMENT}"
      region: "${AWS_REGION}"
      
  # Distributed tracing
  tracing:
    enabled: true
    service_name: "afdp-policy-framework"
    jaeger:
      endpoint: "http://jaeger:14268/api/traces"
      sampler:
        type: "probabilistic"
        param: 0.1
    zipkin:
      endpoint: "http://zipkin:9411/api/v2/spans"
      
  # Health checks
  health:
    enabled: true
    port: 8081
    path: "/health"
    check_interval: "30s"
    timeout: "10s"
    
  # Performance tuning
  performance:
    # Request processing
    max_concurrent_requests: 1000
    request_timeout: "30s"
    request_buffer_size: 1024
    
    # Memory management
    gc_percent: 100
    max_memory: "2GB"
    
    # Connection pooling
    max_idle_connections: 100
    max_connections_per_host: 20
    connection_timeout: "10s"
    
  # Plugin management
  plugins:
    # Plugin discovery
    registry_url: "https://registry.company.com/afdp-plugins"
    auto_discovery: true
    discovery_interval: "5m"
    
    # Plugin lifecycle
    startup_timeout: "60s"
    shutdown_timeout: "30s"
    health_check_interval: "30s"
    
    # Plugin security
    signature_verification: true
    trusted_publishers:
      - "afdp-team@company.com"
      - "security-team@company.com"
```

### API Configuration

```yaml
# API server configuration
api:
  # REST API settings
  rest:
    enabled: true
    port: 8080
    host: "0.0.0.0"
    base_path: "/api/v1"
    
    # TLS configuration
    tls:
      enabled: true
      cert_file: "/etc/certs/server.crt"
      key_file: "/etc/certs/server.key"
      client_ca_file: "/etc/certs/ca.crt"
      min_version: "1.3"
      
    # CORS configuration
    cors:
      enabled: true
      allowed_origins:
        - "https://policy-ui.company.com"
        - "https://admin.company.com"
      allowed_methods: ["GET", "POST", "PUT", "DELETE"]
      allowed_headers: ["Authorization", "Content-Type"]
      max_age: "3600s"
      
    # Rate limiting
    rate_limiting:
      enabled: true
      requests_per_second: 100
      burst: 200
      per_ip_limit: 10
      
    # Request/response middleware
    middleware:
      - name: "request_id"
        enabled: true
      - name: "logging"
        enabled: true
        config:
          log_request_body: false
          log_response_body: false
      - name: "metrics"
        enabled: true
        
  # GraphQL API settings
  graphql:
    enabled: true
    port: 8080
    path: "/graphql"
    playground: true  # Enable in development only
    introspection: false  # Disable in production
    
  # gRPC API settings
  grpc:
    enabled: true
    port: 9090
    reflection: false  # Disable in production
    
    # TLS configuration
    tls:
      enabled: true
      cert_file: "/etc/certs/grpc-server.crt"
      key_file: "/etc/certs/grpc-server.key"
      
    # Connection limits
    max_connections: 500
    max_concurrent_streams: 100
    
# WebSocket configuration for real-time updates
websocket:
  enabled: true
  port: 8080
  path: "/ws"
  max_connections: 1000
  ping_interval: "30s"
  pong_timeout: "60s"
```

## 🔌 Plugin Configuration

### Plugin Registry Configuration

```yaml
# Plugin registry and lifecycle management
plugins:
  # Registry configuration
  registry:
    type: "oci"  # oci, http, git
    url: "registry.company.com/afdp-plugins"
    
    # Authentication for private registries
    auth:
      username: "${REGISTRY_USERNAME}"
      password: "${REGISTRY_PASSWORD}"
    
    # Caching
    cache:
      enabled: true
      directory: "/var/cache/afdp-plugins"
      ttl: "24h"
      
  # Plugin installation
  installation:
    auto_install: false
    verify_signatures: true
    allow_unsigned: false  # Never allow in production
    
    # Installation directories
    plugin_directory: "/opt/afdp/plugins"
    data_directory: "/var/lib/afdp/plugins"
    
  # Plugin security
  security:
    # Sandboxing
    enable_sandboxing: true
    sandbox_type: "container"  # container, chroot, none
    
    # Resource limits per plugin
    resource_limits:
      cpu: "1000m"
      memory: "1Gi"
      storage: "5Gi"
      network_bandwidth: "100Mbps"
      
    # Network policies
    network_policies:
      default_policy: "deny"
      allowed_destinations:
        - "internal.company.com"
        - "api.company.com"
      blocked_destinations:
        - "0.0.0.0/0"  # Block all by default
        
  # Plugin monitoring
  monitoring:
    enabled: true
    metrics_collection: true
    log_aggregation: true
    
    # Health checks
    health_checks:
      enabled: true
      interval: "30s"
      timeout: "10s"
      retries: 3
```

### Evaluator Plugin Configuration

```yaml
# Policy evaluator plugins
evaluators:
  # Rego evaluator
  - name: "rego_evaluator"
    type: "evaluator"
    enabled: true
    
    # Plugin source
    source:
      type: "oci"
      image: "registry.company.com/afdp/rego-evaluator:1.2.0"
      
    # Plugin configuration
    config:
      # Rego-specific settings
      rego:
        version: "v0.58.0"
        optimization_level: 2
        
      # Policy storage
      policies:
        type: "file"  # file, git, database, s3
        path: "/etc/policies"
        watch: true  # Watch for changes
        
      # Caching
      cache:
        enabled: true
        size: "100MB"
        ttl: "1h"
        
    # Resource configuration
    resources:
      replicas: 2
      cpu: "500m"
      memory: "1Gi"
      
    # Security configuration
    security:
      run_as_user: 1000
      run_as_group: 1000
      read_only_root_filesystem: true
      
  # Python evaluator for ML policies
  - name: "python_ml_evaluator"
    type: "evaluator"
    enabled: true
    
    source:
      type: "git"
      repository: "https://github.com/company/afdp-python-evaluator"
      branch: "main"
      
    config:
      python:
        version: "3.11"
        requirements: "requirements.txt"
        
      # ML model configuration
      models:
        fraud_detection:
          path: "/models/fraud_detection.pkl"
          type: "scikit-learn"
        risk_assessment:
          path: "/models/risk_assessment.pb"
          type: "tensorflow"
          
      # GPU support
      gpu:
        enabled: true
        memory_limit: "4GB"
        
    resources:
      replicas: 1
      cpu: "2000m"
      memory: "4Gi"
      nvidia.com/gpu: 1
      
  # Custom DSL evaluator
  - name: "healthcare_dsl_evaluator"
    type: "evaluator"
    enabled: false  # Disabled by default
    
    source:
      type: "local"
      path: "./plugins/healthcare-dsl"
      
    config:
      dsl:
        syntax_version: "1.0"
        schema_validation: true
        
      # Domain-specific configuration
      healthcare:
        hipaa_mode: true
        phi_detection: true
        consent_tracking: true
        
    resources:
      replicas: 1
      cpu: "1000m"
      memory: "2Gi"
```

### Data Source Plugin Configuration

```yaml
# Data source plugins
data_sources:
  # Database data source
  - name: "postgres_primary"
    type: "data_source"
    plugin: "database_source"
    enabled: true
    
    config:
      # Database connection
      database:
        driver: "postgres"
        host: "postgres.company.com"
        port: 5432
        database: "policy_data"
        username: "${DB_USERNAME}"
        password: "${DB_PASSWORD}"
        
        # Connection pooling
        max_connections: 20
        max_idle_connections: 5
        connection_timeout: "30s"
        
        # SSL configuration
        ssl:
          mode: "require"
          cert_file: "/etc/certs/client.crt"
          key_file: "/etc/certs/client.key"
          ca_file: "/etc/certs/ca.crt"
          
      # Query definitions
      queries:
        get_user: |
          SELECT user_id, email, role, department, clearance_level
          FROM users 
          WHERE email = $1 AND active = true
          
        get_model_info: |
          SELECT model_id, name, framework, version, status, accuracy
          FROM ml_models 
          WHERE model_id = $1
          
        search_deployments: |
          SELECT deployment_id, environment, status, created_at
          FROM deployments
          WHERE environment = $1 AND created_at > $2
          ORDER BY created_at DESC
          LIMIT $3
          
      # Caching configuration
      cache:
        enabled: true
        ttl: "5m"
        max_size: "50MB"
        
    # Monitoring
    monitoring:
      slow_query_threshold: "1s"
      connection_monitoring: true
      
  # REST API data source
  - name: "model_registry_api"
    type: "data_source"
    plugin: "rest_api_source"
    enabled: true
    
    config:
      # API configuration
      api:
        base_url: "https://ml-registry.company.com/api/v1"
        timeout: "30s"
        
        # Authentication
        auth:
          type: "bearer_token"
          token: "${ML_REGISTRY_TOKEN}"
          
        # Rate limiting
        rate_limit:
          requests_per_second: 50
          burst: 100
          
      # Endpoint definitions
      endpoints:
        get_model:
          path: "/models/{model_id}"
          method: "GET"
          headers:
            Accept: "application/json"
            
        search_models:
          path: "/models"
          method: "GET"
          query_params:
            status: "approved"
            framework: "{framework}"
            
        get_model_metrics:
          path: "/models/{model_id}/metrics"
          method: "GET"
          cache_ttl: "1h"
          
      # Response transformation
      transformations:
        get_model:
          jsonpath: "$.data"
        search_models:
          jsonpath: "$.data.models[*]"
          
    # Circuit breaker configuration
    circuit_breaker:
      enabled: true
      failure_threshold: 10
      timeout: "60s"
      
  # Message queue data source
  - name: "deployment_events"
    type: "data_source" 
    plugin: "message_queue_source"
    enabled: true
    
    config:
      # Message queue configuration
      queue:
        type: "rabbitmq"
        url: "amqp://guest:guest@rabbitmq:5672/"
        
        # Exchange configuration
        exchanges:
          deployment_events:
            type: "topic"
            durable: true
            
        # Queue configuration  
        queues:
          policy_events:
            exchange: "deployment_events"
            routing_key: "deployment.*"
            durable: true
            
      # Message processing
      processing:
        batch_size: 100
        batch_timeout: "5s"
        max_retries: 3
        
    resources:
      cpu: "500m"
      memory: "512Mi"
```

### Workflow Plugin Configuration

```yaml
# Workflow plugins
workflows:
  # Temporal workflow engine
  - name: "temporal_workflows"
    type: "workflow"
    plugin: "temporal_workflow"
    enabled: true
    
    config:
      # Temporal connection
      temporal:
        host: "temporal.company.com:7233"
        namespace: "afdp-policies"
        
        # TLS configuration
        tls:
          enabled: true
          cert_file: "/etc/certs/temporal-client.crt"
          key_file: "/etc/certs/temporal-client.key"
          
      # Workflow definitions
      workflows:
        approval_workflow:
          task_queue: "approval-tasks"
          timeout: "24h"
          retry_policy:
            max_attempts: 3
            backoff: "exponential"
            
        compliance_review:
          task_queue: "compliance-tasks"
          timeout: "72h"
          
      # Activity configuration
      activities:
        send_notification:
          timeout: "30s"
          retry_policy:
            max_attempts: 5
            
        check_compliance:
          timeout: "1h"
          
    resources:
      replicas: 2
      cpu: "1000m"
      memory: "2Gi"
      
  # Slack workflow for approvals
  - name: "slack_approval_workflow"
    type: "workflow"
    plugin: "slack_workflow"
    enabled: true
    
    config:
      # Slack configuration
      slack:
        bot_token: "${SLACK_BOT_TOKEN}"
        signing_secret: "${SLACK_SIGNING_SECRET}"
        
        # Channel configuration
        channels:
          security_approvals: "C1234567890"
          compliance_approvals: "C0987654321"
          
        # User/role mapping
        approvers:
          security_officer:
            - "U1111111111"  # @security-lead
            - "U2222222222"  # @security-manager
          compliance_manager:
            - "U3333333333"  # @compliance-lead
            
      # Workflow templates
      templates:
        approval_request:
          title: "Policy Approval Required"
          color: "warning"
          fields:
            - title: "Request ID"
              value: "{request_id}"
            - title: "Environment"
              value: "{environment}"
            - title: "Risk Score"
              value: "{risk_score}"
              
        approval_reminder:
          title: "Approval Reminder"
          color: "danger"
          
    resources:
      replicas: 1
      cpu: "500m"
      memory: "1Gi"
      
  # State machine workflow
  - name: "simple_state_machine"
    type: "workflow"
    plugin: "state_machine_workflow"
    enabled: true
    
    config:
      # State machine definition
      states:
        pending:
          on:
            submit: reviewing
            cancel: cancelled
            
        reviewing:
          on:
            approve: approved
            reject: rejected
            request_changes: pending
            
        approved:
          terminal: true
          
        rejected:
          terminal: true
          
        cancelled:
          terminal: true
          
      # State handlers
      handlers:
        reviewing:
          handler: "review_handler"
          timeout: "24h"
          
    resources:
      replicas: 1
      cpu: "200m"
      memory: "256Mi"
```

## 🔒 Security Configuration

### Authentication Configuration

```yaml
# Authentication and authorization
security:
  # Authentication providers
  authentication:
    # Primary authentication method
    primary:
      type: "oidc"
      provider: "keycloak"
      
      # OIDC configuration
      oidc:
        issuer_url: "https://auth.company.com/realms/afdp"
        client_id: "afdp-policy-framework"
        client_secret: "${OIDC_CLIENT_SECRET}"
        redirect_uri: "https://policy.company.com/auth/callback"
        scopes: ["openid", "profile", "email", "groups"]
        
        # Claims mapping
        claims:
          user_id: "sub"
          email: "email"
          name: "name"
          groups: "groups"
          
    # Fallback authentication methods
    fallback:
      - type: "basic_auth"
        enabled: false  # Emergency access only
        
      - type: "api_key"
        enabled: true
        header: "X-API-Key"
        
    # Multi-factor authentication
    mfa:
      enabled: true
      providers:
        - type: "totp"
          issuer: "AFDP Policy Framework"
        - type: "webauthn"
          
  # Authorization configuration
  authorization:
    # Authorization model
    model: "rbac"  # rbac, abac, combined
    
    # Role-based access control
    rbac:
      # Role definitions
      roles:
        policy_viewer:
          permissions:
            - "policies:read"
            - "decisions:read"
            
        policy_author:
          inherits: ["policy_viewer"]
          permissions:
            - "policies:write"
            - "policies:test"
            
        policy_approver:
          inherits: ["policy_viewer"]
          permissions:
            - "policies:approve"
            - "workflows:manage"
            
        security_officer:
          inherits: ["policy_approver", "policy_author"]
          permissions:
            - "security:manage"
            - "audit:read"
            
        system_admin:
          inherits: ["security_officer"]
          permissions:
            - "system:manage"
            - "plugins:manage"
            - "users:manage"
            
      # Role assignments (can be managed via external systems)
      assignments:
        - user: "security-team@company.com"
          roles: ["security_officer"]
        - group: "policy-authors"
          roles: ["policy_author"]
          
    # Attribute-based access control
    abac:
      enabled: false
      policy_file: "/etc/afdp/abac-policies.rego"
      
  # Session management
  sessions:
    provider: "redis"  # memory, redis, database
    
    # Redis session store
    redis:
      url: "redis://session-store:6379/0"
      key_prefix: "afdp:session:"
      
    # Session configuration
    timeout: "8h"
    max_sessions_per_user: 5
    secure_cookies: true
    same_site: "strict"
    
  # Cryptographic settings
  cryptography:
    # Signing keys for tokens and decisions
    signing:
      algorithm: "EdDSA"  # EdDSA, ECDSA, RSA
      key_file: "/etc/certs/signing-key.pem"
      key_rotation_interval: "90d"
      
    # Encryption for sensitive data
    encryption:
      algorithm: "AES-256-GCM"
      key_derivation: "PBKDF2"
      
    # TLS configuration
    tls:
      min_version: "1.3"
      cipher_suites:
        - "TLS_AES_256_GCM_SHA384"
        - "TLS_CHACHA20_POLY1305_SHA256"
        - "TLS_AES_128_GCM_SHA256"
```

### Audit Configuration

```yaml
# Audit and compliance
audit:
  # Audit logging
  logging:
    enabled: true
    level: "info"  # debug, info, warn, error
    
    # Log destinations
    destinations:
      - type: "file"
        path: "/var/log/afdp-audit.log"
        rotation:
          max_size: "100MB"
          max_files: 30
          
      - type: "syslog"
        network: "tcp"
        address: "syslog.company.com:514"
        facility: "local0"
        
      - type: "elasticsearch"
        url: "https://elastic.company.com:9200"
        index: "afdp-audit"
        
    # Log format
    format: "json"
    fields:
      - "timestamp"
      - "user_id"
      - "action"
      - "resource"
      - "result"
      - "ip_address"
      - "user_agent"
      - "correlation_id"
      
  # Event types to audit
  events:
    authentication:
      - "login_success"
      - "login_failure"
      - "logout"
      - "session_expired"
      
    authorization:
      - "access_granted" 
      - "access_denied"
      - "permission_change"
      
    policy_management:
      - "policy_created"
      - "policy_updated"
      - "policy_deleted"
      - "policy_deployed"
      
    decision_events:
      - "policy_evaluated"
      - "decision_made"
      - "workflow_started"
      - "approval_granted"
      - "approval_denied"
      
    system_events:
      - "plugin_loaded"
      - "plugin_unloaded"
      - "configuration_changed"
      - "system_startup"
      - "system_shutdown"
      
  # Compliance reporting
  compliance:
    enabled: true
    
    # Report generation
    reports:
      daily_summary:
        enabled: true
        schedule: "0 0 * * *"  # Daily at midnight
        recipients: ["audit-team@company.com"]
        
      monthly_detailed:
        enabled: true
        schedule: "0 0 1 * *"  # First day of month
        recipients: ["compliance@company.com"]
        
    # Retention policies
    retention:
      audit_logs: "7y"      # 7 years for compliance
      decision_logs: "10y"   # 10 years for AI training data
      system_logs: "1y"     # 1 year for operational data
```

## ⚡ Performance Configuration

### Caching Configuration

```yaml
# Performance and caching
performance:
  # Caching layers
  caching:
    # L1 cache (in-memory)
    l1:
      enabled: true
      type: "lru"
      max_size: "256MB"
      max_entries: 10000
      ttl: "5m"
      
    # L2 cache (distributed)
    l2:
      enabled: true
      type: "redis"
      url: "redis://cache:6379/1"
      max_size: "1GB"
      ttl: "1h"
      
      # Redis-specific settings
      redis:
        pool_size: 10
        timeout: "1s"
        
    # Cache warming
    warming:
      enabled: true
      strategies:
        - type: "predictive"
          model: "access_patterns"
        - type: "scheduled"
          schedule: "0 6 * * *"  # 6 AM daily
          
  # Connection pooling
  connection_pooling:
    # Database connections
    database:
      max_connections: 50
      max_idle_connections: 10
      connection_lifetime: "1h"
      
    # HTTP client connections
    http:
      max_connections_per_host: 20
      max_idle_connections: 100
      idle_timeout: "30s"
      
  # Request processing
  request_processing:
    # Concurrency limits
    max_concurrent_requests: 1000
    max_queued_requests: 2000
    
    # Timeouts
    request_timeout: "30s"
    idle_timeout: "60s"
    
    # Buffer sizes
    read_buffer_size: "64KB"
    write_buffer_size: "64KB"
    
  # Resource limits
  resource_limits:
    # Memory management
    max_memory: "4GB"
    gc_target_percent: 100
    
    # CPU management
    max_cpu_percent: 80
    
    # I/O limits
    max_open_files: 65536
    max_network_connections: 10000
```

### Scaling Configuration

```yaml
# Auto-scaling configuration
scaling:
  # Framework core scaling
  framework:
    enabled: true
    min_replicas: 2
    max_replicas: 10
    
    # Scaling metrics
    metrics:
      - type: "cpu"
        target_utilization: 70
      - type: "memory"
        target_utilization: 80
      - type: "custom"
        metric: "request_queue_length"
        target_value: 100
        
    # Scaling behavior
    behavior:
      scale_up:
        stabilization_window: "30s"
        policies:
          - type: "pods"
            value: 2
            period: "60s"
      scale_down:
        stabilization_window: "300s"
        policies:
          - type: "percent"
            value: 50
            period: "60s"
            
  # Plugin scaling
  plugins:
    # Evaluator scaling
    evaluators:
      enabled: true
      scaling_factor: 2  # Scale with framework
      
      # Per-plugin scaling
      rego_evaluator:
        min_replicas: 1
        max_replicas: 5
        target_cpu: 60
        
      python_ml_evaluator:
        min_replicas: 1
        max_replicas: 3
        target_cpu: 80
        target_memory: 70
        
    # Data source scaling
    data_sources:
      enabled: false  # Usually don't need to scale
      
    # Workflow scaling
    workflows:
      enabled: true
      min_replicas: 1
      max_replicas: 3
```

## 🚀 Deployment Configuration

### Kubernetes Deployment

```yaml
# Kubernetes deployment configuration
deployment:
  # Deployment strategy
  strategy:
    type: "RollingUpdate"
    rolling_update:
      max_unavailable: "25%"
      max_surge: "25%"
      
  # Pod configuration
  pod:
    # Security context
    security_context:
      run_as_non_root: true
      run_as_user: 1000
      run_as_group: 1000
      fs_group: 1000
      
    # Resource requirements
    resources:
      requests:
        cpu: "1000m"
        memory: "2Gi"
        ephemeral-storage: "1Gi"
      limits:
        cpu: "2000m" 
        memory: "4Gi"
        ephemeral-storage: "5Gi"
        
    # Probes
    liveness_probe:
      http_get:
        path: "/health"
        port: 8081
      initial_delay_seconds: 30
      period_seconds: 30
      timeout_seconds: 10
      failure_threshold: 3
      
    readiness_probe:
      http_get:
        path: "/ready"
        port: 8081
      initial_delay_seconds: 5
      period_seconds: 10
      timeout_seconds: 5
      failure_threshold: 3
      
  # Service configuration
  service:
    type: "ClusterIP"
    ports:
      - name: "http"
        port: 80
        target_port: 8080
      - name: "grpc"
        port: 9090
        target_port: 9090
      - name: "metrics"
        port: 9090
        target_port: 9090
        
  # Ingress configuration
  ingress:
    enabled: true
    class: "nginx"
    
    # TLS configuration
    tls:
      enabled: true
      secret_name: "afdp-tls"
      
    # Routing rules
    rules:
      - host: "policy.company.com"
        paths:
          - path: "/api"
            service: "afdp-policy-framework"
            port: 80
            
    # Annotations
    annotations:
      nginx.ingress.kubernetes.io/ssl-redirect: "true"
      nginx.ingress.kubernetes.io/force-ssl-redirect: "true"
      cert-manager.io/cluster-issuer: "letsencrypt-prod"
```

### Storage Configuration

```yaml
# Storage configuration
storage:
  # PostgreSQL for persistent data
  postgresql:
    enabled: true
    
    # Connection configuration
    connection:
      host: "postgres.company.com"
      port: 5432
      database: "afdp_framework"
      username: "${POSTGRES_USERNAME}"
      password: "${POSTGRES_PASSWORD}"
      
    # Connection pooling
    pool:
      max_connections: 25
      min_connections: 5
      connection_lifetime: "1h"
      
    # Database schema
    schema:
      auto_migrate: true
      migration_path: "/migrations"
      
    # Backup configuration
    backup:
      enabled: true
      schedule: "0 2 * * *"  # Daily at 2 AM
      retention: "30d"
      
  # Redis for caching and sessions
  redis:
    enabled: true
    
    # Connection configuration
    connection:
      url: "redis://redis.company.com:6379/0"
      password: "${REDIS_PASSWORD}"
      
    # Cluster configuration (if using Redis Cluster)
    cluster:
      enabled: false
      nodes:
        - "redis-1.company.com:6379"
        - "redis-2.company.com:6379"
        - "redis-3.company.com:6379"
        
  # S3-compatible storage for artifacts
  s3:
    enabled: true
    
    # S3 configuration
    endpoint: "s3.amazonaws.com"
    region: "us-east-1"
    bucket: "afdp-policy-artifacts"
    access_key: "${S3_ACCESS_KEY}"
    secret_key: "${S3_SECRET_KEY}"
    
    # Path configuration
    paths:
      policies: "policies/"
      models: "models/"
      logs: "logs/"
      backups: "backups/"
```

## 🌍 Environment-Specific Configuration

### Development Environment

```yaml
# development.yaml
environment: "development"

# Override logging for development
framework:
  logging:
    level: "debug"
    format: "text"  # More readable for development
    
# Disable security features for easier development
security:
  authentication:
    primary:
      type: "development"  # No authentication required
  authorization:
    model: "none"  # No authorization required
    
# Enable plugin auto-reload
plugins:
  auto_reload: true
  signature_verification: false  # Allow unsigned plugins
  
# Reduce resource requirements
performance:
  caching:
    l1:
      max_size: "64MB"
    l2:
      enabled: false  # No distributed cache needed
      
# Use in-memory storage
storage:
  postgresql:
    enabled: false
  memory:
    enabled: true
```

### Staging Environment

```yaml
# staging.yaml
environment: "staging"

# Production-like logging
framework:
  logging:
    level: "info"
    format: "json"
    
# Enable authentication but with relaxed policies
security:
  authentication:
    primary:
      type: "oidc"
      # Use staging identity provider
      oidc:
        issuer_url: "https://auth-staging.company.com/realms/afdp"
        
# Medium resource allocation
performance:
  caching:
    l1:
      max_size: "128MB"
    l2:
      enabled: true
      
# Use staging database
storage:
  postgresql:
    connection:
      host: "postgres-staging.company.com"
      database: "afdp_staging"
```

### Production Environment

```yaml
# production.yaml
environment: "production"

# Production logging
framework:
  logging:
    level: "warn"  # Reduce log volume
    format: "json"
    
  # Enable all monitoring
  metrics:
    enabled: true
  tracing:
    enabled: true
    
# Full security configuration
security:
  authentication:
    primary:
      type: "oidc"
      oidc:
        issuer_url: "https://auth.company.com/realms/afdp"
  authorization:
    model: "rbac"
    
  # Enable all security features
  cryptography:
    signing:
      key_rotation_interval: "30d"  # More frequent rotation
      
# High availability configuration
deployment:
  replicas: 5
  strategy:
    type: "RollingUpdate"
    rolling_update:
      max_unavailable: "20%"
      max_surge: "20%"
      
# Production resource allocation
performance:
  caching:
    l1:
      max_size: "512MB"
    l2:
      enabled: true
      max_size: "2GB"
      
# Production storage
storage:
  postgresql:
    connection:
      host: "postgres-prod.company.com"
      database: "afdp_production"
    backup:
      enabled: true
      schedule: "0 1 * * *"  # Daily at 1 AM
      retention: "90d"  # Longer retention for production
```

## ✅ Configuration Validation

### Schema Validation

```yaml
# Configuration schema validation
validation:
  # Enable strict validation
  strict_mode: true
  
  # Schema files
  schema_files:
    - "/etc/afdp/schemas/framework-config.json"
    - "/etc/afdp/schemas/plugin-config.json"
    
  # Validation rules
  rules:
    # Required fields
    required_fields:
      - "framework.name"
      - "framework.version"
      - "security.authentication"
      
    # Value constraints
    constraints:
      framework.logging.level:
        enum: ["debug", "info", "warn", "error"]
      performance.max_concurrent_requests:
        minimum: 1
        maximum: 10000
        
  # Custom validators
  custom_validators:
    - name: "port_availability"
      script: "/etc/afdp/validators/check_ports.sh"
    - name: "certificate_validity"
      script: "/etc/afdp/validators/check_certs.sh"
      
# Configuration testing
testing:
  # Dry run mode
  dry_run: false
  
  # Test configuration
  test_suites:
    - name: "basic_functionality"
      tests:
        - "framework_starts"
        - "plugins_load"
        - "api_responds"
        
    - name: "security_validation"
      tests:
        - "authentication_works"
        - "authorization_enforced"
        - "tls_configured"
```

## 🔄 Dynamic Configuration

### Hot Reload Configuration

```yaml
# Dynamic configuration management
dynamic_config:
  # Hot reload settings
  hot_reload:
    enabled: true
    watch_paths:
      - "/etc/afdp/framework.yaml"
      - "/etc/afdp/plugins/"
      - "/etc/afdp/policies/"
      
    # Reload strategy
    strategy: "graceful"  # graceful, immediate, scheduled
    grace_period: "30s"
    
    # Reload filters (what can be reloaded without restart)
    reloadable:
      - "framework.logging"
      - "plugins.*.config"
      - "performance.caching"
      - "security.authorization.rbac.assignments"
      
    # Restart required for these changes
    restart_required:
      - "framework.api.port"
      - "security.authentication.primary"
      - "storage.postgresql.connection"
      
  # Configuration versioning
  versioning:
    enabled: true
    max_versions: 10
    auto_backup: true
    
  # A/B testing support
  ab_testing:
    enabled: true
    traffic_split:
      variant_a: 90  # Current configuration
      variant_b: 10  # New configuration
      
    # Rollback triggers
    rollback_triggers:
      - metric: "error_rate"
        threshold: 5  # Percent
      - metric: "response_time_p99"
        threshold: "1s"
        
# Feature flags
feature_flags:
  # New policy evaluator
  new_evaluator_engine:
    enabled: false
    rollout_percent: 0
    
  # Enhanced audit logging
  enhanced_audit:
    enabled: true
    rollout_percent: 100
    
  # ML-based risk assessment
  ml_risk_assessment:
    enabled: true
    rollout_percent: 25
    conditions:
      - user_group: "beta_users"
      - environment: ["staging", "development"]
```

## 📚 Configuration Examples

### Simple AI Governance Setup

```yaml
# Simple configuration for AI model deployment governance
apiVersion: afdp.io/v1
kind: FrameworkConfig
metadata:
  name: ai-governance-simple
  
framework:
  name: "ai-governance"
  version: "1.0.0"
  
  logging:
    level: "info"
    format: "json"
    
# Single Rego evaluator
evaluators:
  - name: "ai_deployment_policies"
    type: "evaluator"
    plugin: "rego_evaluator"
    enabled: true
    config:
      policies:
        type: "file"
        path: "./policies/ai_deployment.rego"
        
# Simple database data source
data_sources:
  - name: "user_directory"
    type: "data_source"
    plugin: "database_source"
    enabled: true
    config:
      database:
        driver: "postgres"
        connection_string: "${DATABASE_URL}"
      queries:
        get_user: "SELECT * FROM users WHERE email = $1"
        
# Basic email workflow
workflows:
  - name: "email_approval"
    type: "workflow"
    plugin: "email_workflow"
    enabled: true
    config:
      smtp:
        host: "smtp.company.com"
        port: 587
        username: "${SMTP_USERNAME}"
        password: "${SMTP_PASSWORD}"
      templates:
        approval_request: "./templates/approval_request.html"
        
# Minimal security
security:
  authentication:
    primary:
      type: "basic_auth"
      users:
        admin: "${ADMIN_PASSWORD_HASH}"
        
storage:
  postgresql:
    connection_string: "${DATABASE_URL}"
```

### Complex Enterprise Setup

```yaml
# Complex enterprise configuration
apiVersion: afdp.io/v1
kind: FrameworkConfig
metadata:
  name: enterprise-governance
  namespace: afdp-production
  
framework:
  name: "enterprise-policy-framework"
  version: "2.0.0"
  
  logging:
    level: "info"
    format: "json" 
    destinations:
      - type: "stdout"
      - type: "elasticsearch"
        url: "https://logging.company.com:9200"
        index: "afdp-logs"
        
  metrics:
    enabled: true
    exporters:
      - type: "prometheus"
        port: 9090
      - type: "datadog"
        api_key: "${DATADOG_API_KEY}"
        
  tracing:
    enabled: true
    jaeger:
      endpoint: "https://tracing.company.com:14268/api/traces"
      
# Multiple evaluators for different domains
evaluators:
  - name: "ai_ml_policies"
    plugin: "rego_evaluator"
    replicas: 3
    config:
      policies:
        type: "git"
        repository: "https://github.com/company/ai-policies"
        
  - name: "financial_policies"
    plugin: "rego_evaluator"
    replicas: 2
    config:
      policies:
        type: "git" 
        repository: "https://github.com/company/financial-policies"
        
  - name: "ml_risk_evaluator"
    plugin: "python_ml_evaluator"
    replicas: 1
    config:
      models:
        risk_assessment: "/models/risk_model.pkl"
      gpu:
        enabled: true
        
# Multiple data sources
data_sources:
  - name: "user_directory"
    plugin: "ldap_source"
    config:
      ldap:
        server: "ldap.company.com:636"
        base_dn: "ou=users,dc=company,dc=com"
        
  - name: "model_registry"
    plugin: "rest_api_source"
    config:
      api:
        base_url: "https://ml-registry.company.com/api"
        auth:
          type: "oauth2"
          
  - name: "deployment_events"
    plugin: "kafka_source"
    config:
      kafka:
        brokers: ["kafka1:9092", "kafka2:9092", "kafka3:9092"]
        topic: "deployment.events"
        
# Complex workflows
workflows:
  - name: "temporal_workflows"
    plugin: "temporal_workflow"
    replicas: 2
    config:
      temporal:
        host: "temporal.company.com:7233"
        namespace: "afdp"
        
  - name: "slack_approvals"
    plugin: "slack_workflow"
    config:
      slack:
        bot_token: "${SLACK_BOT_TOKEN}"
        
  - name: "jira_integration"
    plugin: "jira_workflow"
    config:
      jira:
        url: "https://company.atlassian.net"
        username: "${JIRA_USERNAME}"
        api_token: "${JIRA_API_TOKEN}"
        
# Enterprise security
security:
  authentication:
    primary:
      type: "oidc"
      oidc:
        issuer_url: "https://auth.company.com/realms/enterprise"
        client_id: "afdp-framework"
        client_secret: "${OIDC_CLIENT_SECRET}"
        
  authorization:
    model: "rbac"
    rbac:
      roles:
        policy_viewer:
          permissions: ["policies:read", "decisions:read"]
        policy_author:
          inherits: ["policy_viewer"]
          permissions: ["policies:write", "policies:test"]
        security_officer:
          inherits: ["policy_author"]
          permissions: ["security:manage", "audit:read"]
          
  audit:
    logging:
      enabled: true
      destinations:
        - type: "splunk"
          url: "https://splunk.company.com:8088"
          token: "${SPLUNK_HEC_TOKEN}"
          
# High availability storage
storage:
  postgresql:
    connection:
      host: "postgres-cluster.company.com"
      port: 5432
      database: "afdp_production"
      username: "${POSTGRES_USERNAME}"
      password: "${POSTGRES_PASSWORD}"
    pool:
      max_connections: 50
    backup:
      enabled: true
      schedule: "0 2 * * *"
      
  redis:
    cluster:
      enabled: true
      nodes:
        - "redis1.company.com:6379"
        - "redis2.company.com:6379" 
        - "redis3.company.com:6379"
        
# Performance configuration
performance:
  caching:
    l1:
      max_size: "1GB"
    l2:
      enabled: true
      max_size: "5GB"
      
  scaling:
    framework:
      min_replicas: 3
      max_replicas: 20
      target_cpu: 70
      
# Monitoring and alerting
monitoring:
  prometheus:
    enabled: true
    scrape_interval: "15s"
    
  grafana:
    enabled: true
    dashboards:
      - "framework_overview"
      - "plugin_performance"
      - "security_metrics"
      
  alerting:
    rules:
      - name: "high_error_rate"
        condition: "error_rate > 5"
        duration: "5m"
        severity: "critical"
        
      - name: "high_latency"
        condition: "p99_latency > 1s"
        duration: "2m"
        severity: "warning"
```

## 🔧 Troubleshooting

### Common Configuration Issues

#### Port Conflicts
**Problem:** Framework fails to start due to port conflicts
```yaml
# Check for port conflicts
framework:
  api:
    rest:
      port: 8080  # Ensure this port is available
    grpc:
      port: 9090  # Ensure this port is available
  metrics:
    port: 9091   # Use different port than gRPC
```

#### Plugin Loading Failures
**Problem:** Plugins fail to load or start
```yaml
# Enable debug logging for plugin issues
framework:
  logging:
    level: "debug"
    
plugins:
  # Check plugin signatures
  signature_verification: true
  
  # Verify plugin resources
  resource_limits:
    cpu: "1000m"     # Ensure adequate resources
    memory: "1Gi"
    
  # Check plugin source accessibility
  registry:
    url: "registry.company.com/afdp-plugins"
    auth:
      username: "${REGISTRY_USERNAME}"
      password: "${REGISTRY_PASSWORD}"
```

#### Database Connection Issues
**Problem:** Cannot connect to database
```yaml
storage:
  postgresql:
    connection:
      host: "postgres.company.com"
      port: 5432
      database: "afdp"
      username: "${DB_USERNAME}"
      password: "${DB_PASSWORD}"
      
      # Add connection troubleshooting
      connect_timeout: "30s"
      
      # SSL configuration if required
      ssl:
        mode: "require"
        cert_file: "/etc/certs/client.crt"
        key_file: "/etc/certs/client.key"
        ca_file: "/etc/certs/ca.crt"
```

#### Authentication Failures
**Problem:** Users cannot authenticate
```yaml
security:
  authentication:
    primary:
      type: "oidc"
      oidc:
        # Verify OIDC configuration
        issuer_url: "https://auth.company.com/realms/afdp"
        client_id: "afdp-framework"
        client_secret: "${OIDC_CLIENT_SECRET}"
        
        # Add debugging
        debug: true  # Enable in development only
        
        # Verify redirect URI
        redirect_uri: "https://policy.company.com/auth/callback"
```

### Configuration Validation Commands

```bash
# Validate configuration syntax
afdp-framework validate --config framework.yaml

# Test database connectivity
afdp-framework test database --config framework.yaml

# Check plugin availability
afdp-framework test plugins --config framework.yaml

# Validate security configuration
afdp-framework test security --config framework.yaml

# Dry run configuration
afdp-framework start --dry-run --config framework.yaml
```

### Performance Troubleshooting

```yaml
# Enable performance debugging
framework:
  logging:
    level: "debug"
    
  # Enable profiling (development only)
  profiling:
    enabled: true
    port: 6060  # pprof endpoint
    
performance:
  # Monitor resource usage
  monitoring:
    enabled: true
    detailed_metrics: true
    
  # Adjust caching
  caching:
    l1:
      max_size: "512MB"  # Increase if high cache miss rate
    l2:
      enabled: true
      ttl: "1h"          # Adjust based on data volatility
      
  # Database performance
storage:
  postgresql:
    pool:
      max_connections: 25      # Adjust based on load
      connection_lifetime: "1h" # Prevent stale connections
```

---

**Document Control:**
- **Next Review Date:** October 2025
- **Owner:** AFDP Framework Configuration Team
- **Approvers:** Framework Architect, Operations Team, Security Team
- **Distribution:** System administrators, DevOps engineers, framework users

**Classification:** Public  
**Revision History:** v1.0 - Initial framework configuration reference documentation