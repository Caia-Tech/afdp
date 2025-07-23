# AFDP Framework Extension Guide

**Document Version:** 1.0  
**Last Updated:** July 2025  
**Classification:** Public  
**Author:** AFDP Framework Extension Team  

## 📋 Table of Contents

1. [Introduction](#introduction)
2. [Extension Architecture](#extension-architecture)
3. [Plugin Development](#plugin-development)
4. [Policy Evaluators](#policy-evaluators)
5. [Data Source Extensions](#data-source-extensions)
6. [Workflow Extensions](#workflow-extensions)
7. [Security Extensions](#security-extensions)
8. [Testing Framework](#testing-framework)
9. [Deployment and Distribution](#deployment-and-distribution)
10. [Performance Optimization](#performance-optimization)
11. [Best Practices](#best-practices)
12. [Examples](#examples)

## 🎯 Introduction

The AFDP Policy Framework is designed for **maximum extensibility**. Rather than limiting users to a single policy language or evaluation model, the framework provides a plugin architecture that allows organizations to build custom policy systems using any technology stack, programming language, or domain-specific approach.

This guide shows you how to extend the framework with custom evaluators, data sources, workflows, and security mechanisms to build policy systems that exactly match your organizational needs.

### Extension Philosophy

**Language Agnostic:** Write policy logic in any programming language  
**Runtime Flexible:** Support compiled, interpreted, and just-in-time evaluation  
**Integration First:** Connect to any data system or external service  
**Security Conscious:** Maintain enterprise security while enabling customization  
**Performance Optimized:** Build high-performance extensions without framework constraints  

### Target Audience

- **Platform Engineers:** Building internal policy platforms for their organizations
- **Security Teams:** Creating custom compliance and security policy systems
- **Domain Experts:** Building specialized governance systems for specific industries
- **Integration Developers:** Connecting the framework to existing enterprise systems
- **Policy Authors:** Creating domain-specific languages for business stakeholders

## 🏗️ Extension Architecture

### Plugin System Overview

The AFDP Framework uses a **plugin-first architecture** where all functionality is implemented as plugins, including the built-in components. This ensures that custom extensions have the same capabilities and performance as framework-provided components.

```
┌─────────────────────────────────────────────────────────────┐
│                    Framework Core                           │
│  ┌─────────────────┐  ┌─────────────────┐                 │
│  │   Plugin        │  │    Security     │                 │
│  │   Registry      │  │    Manager      │                 │
│  └─────────────────┘  └─────────────────┘                 │
│  ┌─────────────────┐  ┌─────────────────┐                 │
│  │  Orchestration  │  │   Configuration │                 │
│  │   Engine        │  │    Manager      │                 │
│  └─────────────────┘  └─────────────────┘                 │
└─────────────────────────────────────────────────────────────┘
                              │
                    ┌─────────┼─────────┐
                    │         │         │
        ┌───────────▼──┐  ┌───▼────┐  ┌─▼────────┐
        │   Policy     │  │  Data  │  │ Workflow │
        │  Evaluator   │  │ Source │  │  Engine  │
        │   Plugin     │  │ Plugin │  │  Plugin  │
        └──────────────┘  └────────┘  └──────────┘
```

### Plugin Communication

Plugins communicate with the framework core through **gRPC interfaces**, providing:

- **High Performance:** Binary protocol with minimal serialization overhead
- **Language Independence:** Plugin can be written in any language with gRPC support
- **Type Safety:** Strongly typed interfaces with automatic code generation
- **Security:** Mutual TLS authentication and encrypted communication
- **Reliability:** Built-in retry, timeout, and circuit breaker mechanisms

## 🔌 Plugin Development

### Plugin Structure

Every plugin follows a standard structure regardless of implementation language:

```
my_custom_plugin/
├── plugin.yaml              # Plugin metadata and configuration
├── Dockerfile              # Container definition for plugin
├── go.mod                  # Go module (if using Go)
├── main.go                 # Plugin entry point
├── internal/
│   ├── evaluator.go        # Plugin implementation
│   ├── config.go           # Configuration handling
│   └── security.go         # Security and validation
├── proto/
│   └── plugin.proto        # gRPC interface definition
├── tests/
│   ├── unit_test.go        # Unit tests
│   └── integration_test.go # Integration tests
└── examples/
    └── sample_policies/    # Example usage
```

### Plugin Metadata

Every plugin includes a `plugin.yaml` file that describes its capabilities:

```yaml
apiVersion: afdp.io/v1
kind: Plugin
metadata:
  name: custom-ml-evaluator
  version: 1.0.0
  description: Machine learning-based policy evaluation using TensorFlow
  author: security-team@company.com
  license: MIT
  
spec:
  type: evaluator
  runtime: container
  
  # Plugin capabilities
  capabilities:
    languages: ["python", "tensorflow"]
    input_formats: ["json", "protobuf"]
    output_formats: ["json", "protobuf"]
    streaming: true
    
  # Resource requirements
  resources:
    cpu: "1000m"
    memory: "2Gi"
    storage: "5Gi"
    gpu: "1" # Optional GPU requirement
    
  # Security requirements
  security:
    permissions:
      - "network.http.client"  # Can make HTTP requests
      - "storage.read"         # Can read from storage
    secrets:
      - "ml-model-credentials" # Required secrets
      
  # Configuration schema
  config_schema:
    type: object
    properties:
      model_path:
        type: string
        description: Path to TensorFlow model
      confidence_threshold:
        type: number
        minimum: 0.0
        maximum: 1.0
        default: 0.8
        
  # Health check configuration
  health_check:
    path: "/health"
    interval: "30s"
    timeout: "10s"
    retries: 3
```

### Plugin Interfaces

#### PolicyEvaluator Interface

```go
// PolicyEvaluator is the main interface for policy evaluation plugins
type PolicyEvaluator interface {
    // Evaluate executes policy logic against input data
    Evaluate(ctx context.Context, req *EvaluationRequest) (*EvaluationResponse, error)
    
    // CompilePolicy compiles policy source code for faster execution
    CompilePolicy(ctx context.Context, req *CompilationRequest) (*CompilationResponse, error)
    
    // ValidatePolicy validates policy syntax and semantics
    ValidatePolicy(ctx context.Context, req *ValidationRequest) (*ValidationResponse, error)
    
    // GetMetadata returns plugin capabilities and information
    GetMetadata(ctx context.Context, req *MetadataRequest) (*MetadataResponse, error)
    
    // Health returns plugin health status
    Health(ctx context.Context, req *HealthRequest) (*HealthResponse, error)
}

// Example request/response types
type EvaluationRequest struct {
    PolicyID    string                    `json:"policy_id"`
    Input       map[string]interface{}    `json:"input"`
    Context     *EvaluationContext        `json:"context"`
    Options     *EvaluationOptions        `json:"options"`
}

type EvaluationResponse struct {
    Decision    PolicyDecision            `json:"decision"`
    Reasoning   string                    `json:"reasoning"`
    Confidence  float64                   `json:"confidence"`
    Metadata    map[string]interface{}    `json:"metadata"`
    Metrics     *EvaluationMetrics        `json:"metrics"`
}
```

#### DataSource Interface

```go
// DataSource interface for connecting external data systems
type DataSource interface {
    // Fetch retrieves data based on query parameters
    Fetch(ctx context.Context, req *FetchRequest) (*FetchResponse, error)
    
    // Stream provides real-time data updates
    Stream(ctx context.Context, req *StreamRequest) (DataSource_StreamServer, error)
    
    // Schema returns the data schema and query capabilities
    Schema(ctx context.Context, req *SchemaRequest) (*SchemaResponse, error)
    
    // Health returns data source health and connectivity status
    Health(ctx context.Context, req *HealthRequest) (*HealthResponse, error)
}

type FetchRequest struct {
    Query       *DataQuery                `json:"query"`
    Context     *RequestContext           `json:"context"`
    Options     *FetchOptions             `json:"options"`
}

type DataQuery struct {
    Type        string                    `json:"type"`        // get, search, aggregate
    Resource    string                    `json:"resource"`    // users, deployments, models
    Filters     map[string]interface{}    `json:"filters"`     // query filters
    Projection  []string                  `json:"projection"`  // fields to return
    Pagination  *PaginationOptions        `json:"pagination"`  // paging options
}
```

#### Workflow Interface

```go
// Workflow interface for custom approval and orchestration logic
type Workflow interface {
    // Start begins a new workflow instance
    Start(ctx context.Context, req *StartWorkflowRequest) (*StartWorkflowResponse, error)
    
    // GetStatus returns current workflow status
    GetStatus(ctx context.Context, req *GetStatusRequest) (*GetStatusResponse, error)
    
    // HandleEvent processes workflow events (approvals, rejections, etc.)
    HandleEvent(ctx context.Context, req *HandleEventRequest) (*HandleEventResponse, error)
    
    // Cancel cancels a running workflow
    Cancel(ctx context.Context, req *CancelWorkflowRequest) (*CancelWorkflowResponse, error)
    
    // ListActive returns all active workflows
    ListActive(ctx context.Context, req *ListActiveRequest) (*ListActiveResponse, error)
}

type StartWorkflowRequest struct {
    WorkflowType string                   `json:"workflow_type"`
    Input        *WorkflowInput           `json:"input"`
    Context      *RequestContext          `json:"context"`
    Options      *WorkflowOptions         `json:"options"`
}

type WorkflowInput struct {
    Decision     *PolicyDecision          `json:"decision"`
    Approvers    []string                 `json:"approvers"`
    Deadline     *time.Time               `json:"deadline,omitempty"`
    Metadata     map[string]interface{}   `json:"metadata"`
}
```

## 🧠 Policy Evaluators

### Built-in Evaluators

The framework includes several built-in evaluators that demonstrate different approaches:

#### Rego Evaluator
**Language:** Open Policy Agent Rego  
**Use Cases:** Complex logical policies, compliance rules  
**Performance:** High (compiled)  
**Learning Curve:** Medium  

```go
// Example Rego evaluator plugin implementation
type RegoEvaluator struct {
    policies map[string]*rego.PreparedEvalQuery
    mutex    sync.RWMutex
}

func (r *RegoEvaluator) Evaluate(ctx context.Context, req *EvaluationRequest) (*EvaluationResponse, error) {
    r.mutex.RLock()
    query, exists := r.policies[req.PolicyID]
    r.mutex.RUnlock()
    
    if !exists {
        return nil, fmt.Errorf("policy not found: %s", req.PolicyID)
    }
    
    results, err := query.Eval(ctx, rego.EvalInput(req.Input))
    if err != nil {
        return nil, fmt.Errorf("policy evaluation failed: %w", err)
    }
    
    // Convert Rego results to framework response
    decision := r.convertRegoResults(results)
    
    return &EvaluationResponse{
        Decision:   decision,
        Reasoning:  r.generateReasoning(results),
        Confidence: 1.0, // Rego decisions are deterministic
        Metadata: map[string]interface{}{
            "evaluator": "rego",
            "version":   r.version,
        },
    }, nil
}
```

#### JavaScript Evaluator
**Language:** JavaScript (V8 engine)  
**Use Cases:** Business logic, dynamic policies  
**Performance:** Medium (JIT compiled)  
**Learning Curve:** Low  

```go
// JavaScript evaluator using V8 engine
type JavaScriptEvaluator struct {
    engine *v8.Engine
    policies map[string]*v8.Script
}

func (js *JavaScriptEvaluator) Evaluate(ctx context.Context, req *EvaluationRequest) (*EvaluationResponse, error) {
    script, exists := js.policies[req.PolicyID]
    if !exists {
        return nil, fmt.Errorf("policy not found: %s", req.PolicyID)
    }
    
    // Create isolated execution context
    isolate := js.engine.NewIsolate()
    defer isolate.Dispose()
    
    context := isolate.NewContext()
    defer context.Close()
    
    // Set input data as global variable
    inputJSON, _ := json.Marshal(req.Input)
    context.Global().Set("input", string(inputJSON))
    
    // Execute policy script
    result, err := context.RunScript(script, "policy.js")
    if err != nil {
        return nil, fmt.Errorf("JavaScript evaluation failed: %w", err)
    }
    
    // Parse result
    var decision PolicyDecision
    if err := json.Unmarshal([]byte(result.String()), &decision); err != nil {
        return nil, fmt.Errorf("failed to parse decision: %w", err)
    }
    
    return &EvaluationResponse{
        Decision:   decision,
        Reasoning:  decision.Reasoning,
        Confidence: decision.Confidence,
        Metadata: map[string]interface{}{
            "evaluator": "javascript",
            "runtime":   "v8",
        },
    }, nil
}
```

#### Python Evaluator
**Language:** Python  
**Use Cases:** Machine learning, data science, complex algorithms  
**Performance:** Medium (interpreted)  
**Learning Curve:** Low  

```python
# Python evaluator implementation
import json
import importlib.util
from typing import Dict, Any
import grpc
from concurrent import futures

class PythonEvaluator:
    def __init__(self):
        self.policies = {}
        
    def Evaluate(self, request, context):
        """Evaluate policy using Python code"""
        try:
            policy_id = request.policy_id
            if policy_id not in self.policies:
                context.set_code(grpc.StatusCode.NOT_FOUND)
                context.set_details(f'Policy not found: {policy_id}')
                return EvaluationResponse()
            
            # Load policy module
            policy_module = self.policies[policy_id]
            
            # Convert protobuf input to Python dict
            input_data = json.loads(request.input)
            
            # Execute policy function
            result = policy_module.evaluate(input_data)
            
            return EvaluationResponse(
                decision=result.get('decision', 'deny'),
                reasoning=result.get('reasoning', ''),
                confidence=result.get('confidence', 1.0),
                metadata={'evaluator': 'python'}
            )
            
        except Exception as e:
            context.set_code(grpc.StatusCode.INTERNAL)
            context.set_details(str(e))
            return EvaluationResponse()

# Example policy module
def evaluate(input_data: Dict[str, Any]) -> Dict[str, Any]:
    """Example Python policy for AI model deployment"""
    environment = input_data.get('environment', '')
    risk_score = calculate_risk_score(input_data)
    
    if environment == 'development' and risk_score < 5:
        return {
            'decision': 'allow',
            'reasoning': f'Low risk development deployment (score: {risk_score})',
            'confidence': 0.9
        }
    elif environment == 'production' and risk_score < 8:
        return {
            'decision': 'require_approval',
            'reasoning': f'Production deployment requires approval (score: {risk_score})',
            'confidence': 0.95
        }
    else:
        return {
            'decision': 'deny',
            'reasoning': f'High risk deployment denied (score: {risk_score})',
            'confidence': 0.99
        }

def calculate_risk_score(input_data: Dict[str, Any]) -> float:
    """Calculate risk score using ML model or business logic"""
    base_score = 0.0
    
    # Environment risk
    env_risk = {
        'development': 1.0,
        'staging': 3.0,
        'production': 5.0
    }.get(input_data.get('environment', ''), 0.0)
    
    # Data classification risk
    data_risk = {
        'public': 1.0,
        'internal': 3.0,
        'sensitive': 6.0,
        'restricted': 9.0
    }.get(input_data.get('data_classification', ''), 0.0)
    
    # Model complexity risk
    model_params = input_data.get('model', {}).get('parameters', 0)
    complexity_risk = min(model_params / 1000000, 5.0)  # Scale based on model size
    
    return env_risk + data_risk + complexity_risk
```

### Custom Evaluator Development

#### Machine Learning Evaluator Example

```python
import tensorflow as tf
import numpy as np
from typing import Dict, Any, List

class MLPolicyEvaluator:
    """TensorFlow-based policy evaluator for complex decision making"""
    
    def __init__(self, model_path: str):
        self.model = tf.keras.models.load_model(model_path)
        self.feature_preprocessor = FeaturePreprocessor()
        
    def evaluate(self, input_data: Dict[str, Any]) -> Dict[str, Any]:
        """Evaluate policy using trained ML model"""
        try:
            # Preprocess input for ML model
            features = self.feature_preprocessor.transform(input_data)
            
            # Run inference
            predictions = self.model.predict(features.reshape(1, -1))
            confidence = float(np.max(predictions))
            decision_class = int(np.argmax(predictions))
            
            # Convert ML output to policy decision
            decision_map = {
                0: 'deny',
                1: 'require_approval', 
                2: 'allow'
            }
            
            decision = decision_map.get(decision_class, 'deny')
            
            # Generate explanation using SHAP or similar
            explanation = self.generate_explanation(features, predictions)
            
            return {
                'decision': decision,
                'reasoning': explanation,
                'confidence': confidence,
                'metadata': {
                    'model_version': self.model.version,
                    'feature_importance': self.get_feature_importance(features),
                    'decision_boundary': float(confidence)
                }
            }
            
        except Exception as e:
            return {
                'decision': 'deny',
                'reasoning': f'ML evaluation failed: {str(e)}',
                'confidence': 0.0
            }

class FeaturePreprocessor:
    """Converts policy input to ML features"""
    
    def transform(self, input_data: Dict[str, Any]) -> np.ndarray:
        """Transform input data to feature vector"""
        features = []
        
        # Environment encoding
        env_encoding = {
            'development': [1, 0, 0],
            'staging': [0, 1, 0],
            'production': [0, 0, 1]
        }
        features.extend(env_encoding.get(input_data.get('environment'), [0, 0, 0]))
        
        # Data classification encoding
        data_encoding = {
            'public': [1, 0, 0, 0],
            'internal': [0, 1, 0, 0],
            'sensitive': [0, 0, 1, 0],
            'restricted': [0, 0, 0, 1]
        }
        features.extend(data_encoding.get(input_data.get('data_classification'), [0, 0, 0, 0]))
        
        # Numerical features
        features.append(input_data.get('model', {}).get('parameters', 0) / 1000000)  # Normalized
        features.append(len(input_data.get('risk_factors', [])))
        features.append(len(input_data.get('compliance_frameworks', [])))
        
        # User role encoding
        role_encoding = {
            'developer': [1, 0, 0],
            'ml_engineer': [0, 1, 0],
            'admin': [0, 0, 1]
        }
        features.extend(role_encoding.get(input_data.get('user', {}).get('role'), [0, 0, 0]))
        
        return np.array(features, dtype=np.float32)
```

#### Custom DSL Evaluator

```go
// Custom domain-specific language evaluator
type DSLEvaluator struct {
    parser   *DSLParser
    compiler *DSLCompiler
    policies map[string]*CompiledPolicy
}

type DSLParser struct {
    lexer *DSLLexer
}

// Example custom DSL for healthcare policies
// Policy syntax: 
// WHEN patient.age > 65 AND treatment.risk_level = "high"
// REQUIRE approval FROM doctor AND ethics_committee
// WITH deadline 24_hours

func (dsl *DSLEvaluator) CompilePolicy(source string) (*CompiledPolicy, error) {
    // Tokenize DSL source
    tokens, err := dsl.parser.lexer.Tokenize(source)
    if err != nil {
        return nil, fmt.Errorf("tokenization failed: %w", err)
    }
    
    // Parse into AST
    ast, err := dsl.parser.Parse(tokens)
    if err != nil {
        return nil, fmt.Errorf("parsing failed: %w", err)
    }
    
    // Compile to executable form
    compiled, err := dsl.compiler.Compile(ast)
    if err != nil {
        return nil, fmt.Errorf("compilation failed: %w", err)
    }
    
    return compiled, nil
}

func (dsl *DSLEvaluator) Evaluate(ctx context.Context, req *EvaluationRequest) (*EvaluationResponse, error) {
    policy, exists := dsl.policies[req.PolicyID]
    if !exists {
        return nil, fmt.Errorf("policy not found: %s", req.PolicyID)
    }
    
    // Execute compiled policy
    result, err := policy.Execute(req.Input)
    if err != nil {
        return nil, fmt.Errorf("policy execution failed: %w", err)
    }
    
    return &EvaluationResponse{
        Decision:   result.Decision,
        Reasoning:  result.GenerateExplanation(),
        Confidence: result.Confidence,
        Metadata: map[string]interface{}{
            "evaluator": "custom_dsl",
            "language":  "healthcare_policy_dsl",
        },
    }, nil
}

// Example DSL structures
type DSLCondition struct {
    Field    string      `json:"field"`
    Operator string      `json:"operator"`
    Value    interface{} `json:"value"`
}

type DSLRule struct {
    Conditions []DSLCondition `json:"conditions"`
    Action     string         `json:"action"`
    Approvers  []string       `json:"approvers"`
    Deadline   time.Duration  `json:"deadline"`
}

type CompiledPolicy struct {
    Rules []DSLRule `json:"rules"`
}

func (cp *CompiledPolicy) Execute(input map[string]interface{}) (*DSLResult, error) {
    for _, rule := range cp.Rules {
        if cp.evaluateConditions(rule.Conditions, input) {
            return &DSLResult{
                Decision:   rule.Action,
                Approvers:  rule.Approvers,
                Deadline:   rule.Deadline,
                Confidence: 1.0, // DSL rules are deterministic
            }, nil
        }
    }
    
    // Default deny
    return &DSLResult{
        Decision:   "deny",
        Confidence: 1.0,
    }, nil
}
```

## 🗄️ Data Source Extensions

### Database Data Source

```go
// Generic database data source supporting multiple database types
type DatabaseDataSource struct {
    config   *DatabaseConfig
    pool     *sql.DB
    queryMap map[string]*PreparedQuery
}

type DatabaseConfig struct {
    Driver          string            `yaml:"driver"`          // postgres, mysql, sqlite
    ConnectionString string           `yaml:"connection"`
    MaxConnections  int               `yaml:"max_connections"`
    QueryTimeout    time.Duration     `yaml:"query_timeout"`
    Queries         map[string]string `yaml:"queries"`         // Named queries
}

func (db *DatabaseDataSource) Fetch(ctx context.Context, req *FetchRequest) (*FetchResponse, error) {
    queryName := req.Query.Type
    query, exists := db.queryMap[queryName]
    if !exists {
        return nil, fmt.Errorf("unsupported query type: %s", queryName)
    }
    
    // Build query parameters from request
    params, err := db.buildQueryParams(req.Query.Filters)
    if err != nil {
        return nil, fmt.Errorf("failed to build query parameters: %w", err)
    }
    
    // Execute query with timeout
    ctx, cancel := context.WithTimeout(ctx, db.config.QueryTimeout)
    defer cancel()
    
    rows, err := query.QueryContext(ctx, params...)
    if err != nil {
        return nil, fmt.Errorf("query execution failed: %w", err)
    }
    defer rows.Close()
    
    // Convert rows to generic data format
    data, err := db.rowsToData(rows)
    if err != nil {
        return nil, fmt.Errorf("data conversion failed: %w", err)
    }
    
    return &FetchResponse{
        Data:     data,
        Metadata: map[string]interface{}{
            "source":     "database",
            "driver":     db.config.Driver,
            "query_time": time.Since(time.Now()),
        },
    }, nil
}

// Example configuration for database data source
// data_sources:
#   - name: "user_directory"
#     plugin: "database_source"
#     config:
#       driver: "postgres"
#       connection: "postgres://user:pass@host/db?sslmode=require"
#       max_connections: 10
#       query_timeout: "30s"
#       queries:
#         get_user: "SELECT * FROM users WHERE email = $1"
#         search_users: "SELECT * FROM users WHERE department = $1 AND active = true"
#         get_user_permissions: |
#           SELECT p.name, p.scope 
#           FROM permissions p 
#           JOIN user_permissions up ON p.id = up.permission_id 
#           WHERE up.user_id = $1
```

### REST API Data Source

```go
// REST API data source with authentication and caching
type RestAPIDataSource struct {
    config     *RestAPIConfig
    client     *http.Client
    cache      cache.Cache
    rateLimit  *rate.Limiter
}

type RestAPIConfig struct {
    BaseURL        string                    `yaml:"base_url"`
    Authentication *AuthenticationConfig     `yaml:"auth"`
    Timeout        time.Duration             `yaml:"timeout"`
    RateLimit      int                       `yaml:"rate_limit"`  // requests per second
    Cache          *CacheConfig              `yaml:"cache"`
    Endpoints      map[string]*EndpointConfig `yaml:"endpoints"`
}

type EndpointConfig struct {
    Path      string            `yaml:"path"`
    Method    string            `yaml:"method"`
    Headers   map[string]string `yaml:"headers"`
    QueryParams map[string]string `yaml:"query_params"`
}

func (api *RestAPIDataSource) Fetch(ctx context.Context, req *FetchRequest) (*FetchResponse, error) {
    // Check rate limit
    if err := api.rateLimit.Wait(ctx); err != nil {
        return nil, fmt.Errorf("rate limit exceeded: %w", err)
    }
    
    // Check cache first
    cacheKey := api.buildCacheKey(req)
    if cached, exists := api.cache.Get(cacheKey); exists {
        return cached.(*FetchResponse), nil
    }
    
    // Build HTTP request
    httpReq, err := api.buildHTTPRequest(ctx, req)
    if err != nil {
        return nil, fmt.Errorf("failed to build HTTP request: %w", err)
    }
    
    // Execute request
    resp, err := api.client.Do(httpReq)
    if err != nil {
        return nil, fmt.Errorf("HTTP request failed: %w", err)
    }
    defer resp.Body.Close()
    
    // Parse response
    data, err := api.parseResponse(resp)
    if err != nil {
        return nil, fmt.Errorf("response parsing failed: %w", err)
    }
    
    response := &FetchResponse{
        Data:     data,
        Metadata: map[string]interface{}{
            "source":      "rest_api",
            "status_code": resp.StatusCode,
            "response_time": time.Since(time.Now()),
        },
    }
    
    // Cache response
    api.cache.Set(cacheKey, response, api.config.Cache.TTL)
    
    return response, nil
}

// Example REST API configuration
# data_sources:
#   - name: "model_registry"
#     plugin: "rest_api_source"
#     config:
#       base_url: "https://ml-registry.company.com/api/v1"
#       timeout: "30s"
#       rate_limit: 100  # 100 requests per second
#       auth:
#         type: "bearer_token"
#         token: "${ML_REGISTRY_TOKEN}"
#       cache:
#         ttl: "5m"
#         max_size: "100MB"
#       endpoints:
#         get_model:
#           path: "/models/{model_id}"
#           method: "GET"
#         search_models:
#           path: "/models"
#           method: "GET"
#           query_params:
#             framework: "{framework}"
#             status: "approved"
```

### Message Queue Data Source

```go
// Message queue data source for real-time data streaming
type MessageQueueDataSource struct {
    config     *MessageQueueConfig
    connection *amqp.Connection
    channel    *amqp.Channel
    consumers  map[string]*Consumer
}

type MessageQueueConfig struct {
    Type        string            `yaml:"type"`         // rabbitmq, kafka, nats
    URL         string            `yaml:"url"`
    Exchanges   map[string]*ExchangeConfig `yaml:"exchanges"`
    Queues      map[string]*QueueConfig    `yaml:"queues"`
}

func (mq *MessageQueueDataSource) Stream(ctx context.Context, req *StreamRequest) (DataSource_StreamServer, error) {
    queueName := req.Query.Resource
    queueConfig, exists := mq.config.Queues[queueName]
    if !exists {
        return nil, fmt.Errorf("unknown queue: %s", queueName)
    }
    
    // Create consumer for this stream
    consumer, err := mq.createConsumer(queueConfig)
    if err != nil {
        return nil, fmt.Errorf("failed to create consumer: %w", err)
    }
    
    // Start consuming messages
    messages, err := consumer.Consume(ctx)
    if err != nil {
        return nil, fmt.Errorf("failed to start consuming: %w", err)
    }
    
    // Create gRPC stream
    stream := &MessageQueueStream{
        messages: messages,
        server:   req.Server, // gRPC server for streaming
    }
    
    go stream.streamMessages(ctx)
    
    return stream, nil
}

type MessageQueueStream struct {
    messages <-chan *Message
    server   DataSource_StreamServer
}

func (stream *MessageQueueStream) streamMessages(ctx context.Context) {
    for {
        select {
        case msg := <-stream.messages:
            if msg == nil {
                return // Channel closed
            }
            
            // Convert message to stream event
            event := &StreamEvent{
                Timestamp: msg.Timestamp,
                Data:      msg.Body,
                Metadata: map[string]interface{}{
                    "message_id":   msg.ID,
                    "routing_key":  msg.RoutingKey,
                    "exchange":     msg.Exchange,
                },
            }
            
            // Send to client
            if err := stream.server.Send(event); err != nil {
                log.Errorf("Failed to send stream event: %v", err)
                return
            }
            
        case <-ctx.Done():
            return
        }
    }
}
```

## 🔄 Workflow Extensions

### Temporal Workflow Integration

```go
// Temporal workflow for complex approval processes
type TemporalWorkflow struct {
    client     client.Client
    workflows  map[string]*WorkflowDefinition
}

type WorkflowDefinition struct {
    Name         string                    `yaml:"name"`
    Description  string                    `yaml:"description"`
    Steps        []WorkflowStep            `yaml:"steps"`
    Timeouts     map[string]time.Duration  `yaml:"timeouts"`
    RetryPolicy  *RetryPolicy              `yaml:"retry_policy"`
}

func (tw *TemporalWorkflow) Start(ctx context.Context, req *StartWorkflowRequest) (*StartWorkflowResponse, error) {
    definition, exists := tw.workflows[req.WorkflowType]
    if !exists {
        return nil, fmt.Errorf("unknown workflow type: %s", req.WorkflowType)
    }
    
    // Start Temporal workflow
    options := client.StartWorkflowOptions{
        ID:                 generateWorkflowID(req),
        TaskQueue:          "afdp-policy-workflows",
        WorkflowRunTimeout: definition.Timeouts["workflow"],
    }
    
    execution, err := tw.client.ExecuteWorkflow(ctx, options, "PolicyApprovalWorkflow", req.Input)
    if err != nil {
        return nil, fmt.Errorf("failed to start workflow: %w", err)
    }
    
    return &StartWorkflowResponse{
        WorkflowID: execution.GetID(),
        RunID:      execution.GetRunID(),
    }, nil
}

// Temporal workflow implementation
func PolicyApprovalWorkflow(ctx workflow.Context, input *WorkflowInput) (*WorkflowResult, error) {
    logger := workflow.GetLogger(ctx)
    logger.Info("Starting policy approval workflow", "decision", input.Decision)
    
    var result WorkflowResult
    
    // Step 1: Security Review
    var securityApproval ApprovalResult
    err := workflow.ExecuteActivity(ctx, 
        workflow.ActivityOptions{
            StartToCloseTimeout: time.Minute * 30,
        },
        "RequestSecurityApproval", 
        input.Decision,
    ).Get(ctx, &securityApproval)
    
    if err != nil {
        return nil, fmt.Errorf("security approval failed: %w", err)
    }
    
    if securityApproval.Status != "approved" {
        result.Status = "rejected"
        result.Reason = "Security approval denied: " + securityApproval.Reason
        return &result, nil
    }
    
    // Step 2: Compliance Review (if required)
    if input.Decision.RequiresCompliance {
        var complianceApproval ApprovalResult
        err := workflow.ExecuteActivity(ctx,
            workflow.ActivityOptions{
                StartToCloseTimeout: time.Hour * 24,
            },
            "RequestComplianceApproval",
            input.Decision,
        ).Get(ctx, &complianceApproval)
        
        if err != nil {
            return nil, fmt.Errorf("compliance approval failed: %w", err)
        }
        
        if complianceApproval.Status != "approved" {
            result.Status = "rejected"
            result.Reason = "Compliance approval denied: " + complianceApproval.Reason
            return &result, nil
        }
    }
    
    // Step 3: Final Approval
    var finalApproval ApprovalResult
    err = workflow.ExecuteActivity(ctx,
        workflow.ActivityOptions{
            StartToCloseTimeout: time.Hour * 4,
        },
        "RequestFinalApproval",
        input.Decision,
    ).Get(ctx, &finalApproval)
    
    if err != nil {
        return nil, fmt.Errorf("final approval failed: %w", err)
    }
    
    result.Status = finalApproval.Status
    result.Reason = finalApproval.Reason
    result.ApprovedBy = []string{securityApproval.ApprovedBy, finalApproval.ApprovedBy}
    
    return &result, nil
}

// Activities for human approvals
func RequestSecurityApproval(ctx context.Context, decision *PolicyDecision) (*ApprovalResult, error) {
    // Send notification to security team
    notificationService := getNotificationService()
    
    approvalRequest := &ApprovalRequest{
        Type:        "security_review",
        Decision:    decision,
        Deadline:    time.Now().Add(time.Hour * 24),
        Approvers:   []string{"security-team@company.com"},
    }
    
    err := notificationService.SendApprovalRequest(ctx, approvalRequest)
    if err != nil {
        return nil, fmt.Errorf("failed to send approval request: %w", err)
    }
    
    // Wait for approval response (this would be handled through Temporal signals)
    // In practice, this would use workflow.GetSignalChannel() to wait for responses
    
    return &ApprovalResult{
        Status:     "approved",
        ApprovedBy: "security-officer@company.com",
        Reason:     "Security review completed successfully",
        Timestamp:  time.Now(),
    }, nil
}
```

### Custom State Machine Workflow

```go
// Simple state machine workflow for basic approval processes
type StateMachineWorkflow struct {
    transitions map[string]map[string]string // state -> event -> next_state
    handlers    map[string]StateHandler      // state -> handler
}

type StateHandler interface {
    Handle(ctx context.Context, workflow *WorkflowInstance, event *WorkflowEvent) error
}

type WorkflowInstance struct {
    ID            string                    `json:"id"`
    Type          string                    `json:"type"`
    CurrentState  string                    `json:"current_state"`
    Input         *WorkflowInput            `json:"input"`
    Context       map[string]interface{}    `json:"context"`
    History       []StateTransition         `json:"history"`
    CreatedAt     time.Time                 `json:"created_at"`
    UpdatedAt     time.Time                 `json:"updated_at"`
}

type StateTransition struct {
    FromState string                    `json:"from_state"`
    ToState   string                    `json:"to_state"`
    Event     string                    `json:"event"`
    Timestamp time.Time                 `json:"timestamp"`
    Metadata  map[string]interface{}    `json:"metadata"`
}

func (sm *StateMachineWorkflow) HandleEvent(ctx context.Context, req *HandleEventRequest) (*HandleEventResponse, error) {
    // Load workflow instance
    workflow, err := sm.loadWorkflow(req.WorkflowID)
    if err != nil {
        return nil, fmt.Errorf("failed to load workflow: %w", err)
    }
    
    // Check if transition is valid
    nextState, valid := sm.transitions[workflow.CurrentState][req.Event.Type]
    if !valid {
        return nil, fmt.Errorf("invalid transition: %s -> %s", workflow.CurrentState, req.Event.Type)
    }
    
    // Execute state handler
    handler, exists := sm.handlers[workflow.CurrentState]
    if exists {
        if err := handler.Handle(ctx, workflow, req.Event); err != nil {
            return nil, fmt.Errorf("state handler failed: %w", err)
        }
    }
    
    // Transition to next state
    oldState := workflow.CurrentState
    workflow.CurrentState = nextState
    workflow.UpdatedAt = time.Now()
    
    // Record transition
    transition := StateTransition{
        FromState: oldState,
        ToState:   nextState,
        Event:     req.Event.Type,
        Timestamp: time.Now(),
        Metadata:  req.Event.Data,
    }
    workflow.History = append(workflow.History, transition)
    
    // Save workflow state
    if err := sm.saveWorkflow(workflow); err != nil {
        return nil, fmt.Errorf("failed to save workflow: %w", err)
    }
    
    return &HandleEventResponse{
        WorkflowID:   workflow.ID,
        CurrentState: workflow.CurrentState,
        Transition:   &transition,
    }, nil
}

// Example state handlers
type PendingApprovalHandler struct {
    notificationService NotificationService
}

func (h *PendingApprovalHandler) Handle(ctx context.Context, workflow *WorkflowInstance, event *WorkflowEvent) error {
    switch event.Type {
    case "approval_requested":
        // Send notifications to approvers
        approvers := workflow.Input.Approvers
        for _, approver := range approvers {
            err := h.notificationService.SendNotification(ctx, &Notification{
                Recipient: approver,
                Subject:   fmt.Sprintf("Approval Required: %s", workflow.Input.Decision.RequestID),
                Template:  "approval_request",
                Data: map[string]interface{}{
                    "workflow":  workflow,
                    "decision":  workflow.Input.Decision,
                    "deadline":  workflow.Input.Deadline,
                },
            })
            if err != nil {
                return fmt.Errorf("failed to send notification to %s: %w", approver, err)
            }
        }
        
    case "approval_response":
        // Process approval response
        response := event.Data["response"].(string)
        approver := event.Data["approver"].(string)
        
        // Store response in workflow context
        if workflow.Context == nil {
            workflow.Context = make(map[string]interface{})
        }
        
        responses, exists := workflow.Context["approval_responses"].([]map[string]interface{})
        if !exists {
            responses = []map[string]interface{}{}
        }
        
        responses = append(responses, map[string]interface{}{
            "approver":  approver,
            "response":  response,
            "timestamp": time.Now(),
        })
        
        workflow.Context["approval_responses"] = responses
        
    default:
        return fmt.Errorf("unsupported event type: %s", event.Type)
    }
    
    return nil
}
```

## 🧪 Testing Framework

### Plugin Testing Infrastructure

```go
// Testing framework for policy plugins
type PluginTester struct {
    plugin     Plugin
    testSuite  *TestSuite
    mockData   map[string]interface{}
}

type TestSuite struct {
    Name        string      `yaml:"name"`
    Description string      `yaml:"description"`
    TestCases   []TestCase  `yaml:"test_cases"`
    Setup       *TestSetup  `yaml:"setup"`
    Teardown    *TestTeardown `yaml:"teardown"`
}

type TestCase struct {
    Name          string                    `yaml:"name"`
    Description   string                    `yaml:"description"`
    Input         map[string]interface{}    `yaml:"input"`
    Expected      *ExpectedResult           `yaml:"expected"`
    Timeout       time.Duration             `yaml:"timeout"`
    Retry         *RetryConfig              `yaml:"retry"`
}

type ExpectedResult struct {
    Decision    string                    `yaml:"decision"`
    Reasoning   string                    `yaml:"reasoning"`
    Confidence  *ConfidenceRange          `yaml:"confidence"`
    Metadata    map[string]interface{}    `yaml:"metadata"`
    Error       *ExpectedError            `yaml:"error"`
}

func (pt *PluginTester) RunTestSuite(ctx context.Context, suite *TestSuite) (*TestResults, error) {
    results := &TestResults{
        SuiteName:  suite.Name,
        StartTime:  time.Now(),
        TestCases:  make([]TestCaseResult, 0, len(suite.TestCases)),
    }
    
    // Run setup if defined
    if suite.Setup != nil {
        if err := pt.runSetup(ctx, suite.Setup); err != nil {
            return nil, fmt.Errorf("test setup failed: %w", err)
        }
    }
    
    // Run test cases
    for _, testCase := range suite.TestCases {
        result := pt.runTestCase(ctx, &testCase)
        results.TestCases = append(results.TestCases, result)
        
        if result.Status == "failed" {
            results.FailedCount++
        } else {
            results.PassedCount++
        }
    }
    
    // Run teardown if defined
    if suite.Teardown != nil {
        if err := pt.runTeardown(ctx, suite.Teardown); err != nil {
            log.Errorf("Test teardown failed: %v", err)
        }
    }
    
    results.EndTime = time.Now()
    results.Duration = results.EndTime.Sub(results.StartTime)
    
    return results, nil
}

func (pt *PluginTester) runTestCase(ctx context.Context, testCase *TestCase) TestCaseResult {
    result := TestCaseResult{
        Name:      testCase.Name,
        StartTime: time.Now(),
    }
    
    // Set timeout for test case
    if testCase.Timeout > 0 {
        var cancel context.CancelFunc
        ctx, cancel = context.WithTimeout(ctx, testCase.Timeout)
        defer cancel()
    }
    
    // Execute test case with retry if configured
    var lastErr error
    maxAttempts := 1
    if testCase.Retry != nil {
        maxAttempts = testCase.Retry.MaxAttempts
    }
    
    for attempt := 1; attempt <= maxAttempts; attempt++ {
        // Run the actual test
        decision, err := pt.runSingleTest(ctx, testCase)
        if err != nil {
            lastErr = err
            if attempt < maxAttempts {
                time.Sleep(testCase.Retry.Delay)
                continue
            }
            break
        }
        
        // Validate results
        if validationErr := pt.validateResult(decision, testCase.Expected); validationErr != nil {
            lastErr = validationErr
            result.Status = "failed"
            result.Error = validationErr.Error()
        } else {
            result.Status = "passed"
            result.ActualResult = decision
        }
        
        break
    }
    
    if lastErr != nil && result.Status != "passed" {
        result.Status = "failed"
        result.Error = lastErr.Error()
    }
    
    result.EndTime = time.Now()
    result.Duration = result.EndTime.Sub(result.StartTime)
    
    return result
}

// Example test suite definition
test_suite_example := `
name: "ai_deployment_policy_tests"
description: "Test suite for AI model deployment policies"

setup:
  mock_data:
    users:
      - email: "test@company.com"
        role: "ml_engineer"
        department: "ai_research"
    models:
      - id: "fraud-detection-v1"
        framework: "tensorflow"
        status: "approved"

test_cases:
  - name: "allow_development_deployment"
    description: "Should allow deployment to development environment"
    input:
      environment: "development"
      user:
        email: "test@company.com"
        role: "ml_engineer"
      model:
        id: "fraud-detection-v1"
        framework: "tensorflow"
      data:
        classification: "internal"
      risk_factors: []
    expected:
      decision: "allow"
      confidence:
        min: 0.8
        max: 1.0
    timeout: "30s"
    
  - name: "require_approval_production_deployment"
    description: "Should require approval for production deployment"
    input:
      environment: "production"
      user:
        email: "test@company.com"
        role: "ml_engineer"
      model:
        id: "fraud-detection-v1"
        framework: "tensorflow"
      data:
        classification: "sensitive"
      risk_factors: ["external_dependencies"]
    expected:
      decision: "require_approval"
      reasoning: "Production deployment with sensitive data requires approval"
      metadata:
        required_approvers:
          - "security_officer"
          - "compliance_manager"
    timeout: "30s"
    
  - name: "deny_high_risk_deployment"
    description: "Should deny deployments with excessive risk"
    input:
      environment: "production"
      user:
        email: "test@company.com"
        role: "developer"  # Not authorized for production
      model:
        id: "experimental-model"
        framework: "custom"
        status: "unapproved"
      data:
        classification: "restricted"
      risk_factors: ["unvalidated_model", "restricted_data", "production_environment"]
    expected:
      decision: "deny"
      confidence:
        min: 0.9
        max: 1.0
    timeout: "30s"
`
```

### Integration Testing

```go
// Integration testing framework for multi-plugin scenarios
type IntegrationTester struct {
    framework    *PolicyFramework
    plugins      map[string]Plugin
    testScenarios []IntegrationScenario
}

type IntegrationScenario struct {
    Name          string                    `yaml:"name"`
    Description   string                    `yaml:"description"`
    Setup         *IntegrationSetup         `yaml:"setup"`
    Steps         []IntegrationStep         `yaml:"steps"`
    Validation    *IntegrationValidation    `yaml:"validation"`
    Cleanup       *IntegrationCleanup       `yaml:"cleanup"`
}

type IntegrationStep struct {
    Name        string                    `yaml:"name"`
    Type        string                    `yaml:"type"`      // evaluate, fetch_data, start_workflow
    Plugin      string                    `yaml:"plugin"`
    Input       map[string]interface{}    `yaml:"input"`
    Expected    map[string]interface{}    `yaml:"expected"`
    StoreResult string                    `yaml:"store_result"` // Store result for use in later steps
}

func (it *IntegrationTester) RunIntegrationScenario(ctx context.Context, scenario *IntegrationScenario) (*IntegrationResult, error) {
    result := &IntegrationResult{
        ScenarioName: scenario.Name,
        StartTime:    time.Now(),
        StepResults:  make([]StepResult, 0, len(scenario.Steps)),
        Context:      make(map[string]interface{}),
    }
    
    // Run setup
    if scenario.Setup != nil {
        if err := it.runIntegrationSetup(ctx, scenario.Setup, result.Context); err != nil {
            return nil, fmt.Errorf("integration setup failed: %w", err)
        }
    }
    
    // Execute steps in sequence
    for i, step := range scenario.Steps {
        stepResult := it.runIntegrationStep(ctx, &step, result.Context)
        result.StepResults = append(result.StepResults, stepResult)
        
        if stepResult.Status == "failed" {
            result.Status = "failed"
            result.FailedAt = i
            break
        }
        
        // Store result if specified
        if step.StoreResult != "" {
            result.Context[step.StoreResult] = stepResult.Output
        }
    }
    
    // Run validation
    if scenario.Validation != nil && result.Status != "failed" {
        if err := it.runIntegrationValidation(ctx, scenario.Validation, result.Context); err != nil {
            result.Status = "failed"
            result.ValidationError = err.Error()
        } else {
            result.Status = "passed"
        }
    }
    
    // Cleanup
    if scenario.Cleanup != nil {
        if err := it.runIntegrationCleanup(ctx, scenario.Cleanup, result.Context); err != nil {
            log.Errorf("Integration cleanup failed: %v", err)
        }
    }
    
    result.EndTime = time.Now()
    result.Duration = result.EndTime.Sub(result.StartTime)
    
    return result, nil
}

// Example integration scenario
integration_scenario_example := `
name: "end_to_end_ai_deployment_approval"
description: "Test complete AI deployment approval workflow"

setup:
  mock_services:
    - name: "model_registry"
      type: "rest_api_mock"
      responses:
        "/models/fraud-detection-v2":
          status: 200
          body:
            id: "fraud-detection-v2"
            status: "approved"
            framework: "tensorflow"
            accuracy: 0.987
    - name: "user_directory" 
      type: "database_mock"
      data:
        users:
          - email: "engineer@company.com"
            role: "ml_engineer"
            clearance: "standard"

steps:
  - name: "fetch_model_info"
    type: "fetch_data"
    plugin: "model_registry"
    input:
      query:
        type: "get"
        resource: "models/fraud-detection-v2"
    store_result: "model_info"
    
  - name: "fetch_user_info"
    type: "fetch_data" 
    plugin: "user_directory"
    input:
      query:
        type: "get"
        resource: "user"
        filters:
          email: "engineer@company.com"
    store_result: "user_info"
    
  - name: "evaluate_deployment_policy"
    type: "evaluate"
    plugin: "rego_evaluator"
    input:
      policy_id: "ai_deployment_policy"
      input:
        environment: "production"
        model: "{{ .model_info }}"
        user: "{{ .user_info }}"
        data:
          classification: "sensitive"
    expected:
      decision: "require_approval"
    store_result: "policy_decision"
    
  - name: "start_approval_workflow"
    type: "start_workflow"
    plugin: "temporal_workflow"
    input:
      workflow_type: "approval_workflow"
      input:
        decision: "{{ .policy_decision }}"
        approvers: ["security@company.com", "compliance@company.com"]
    store_result: "workflow_id"
    
  - name: "simulate_approvals"
    type: "workflow_event"
    plugin: "temporal_workflow"
    input:
      workflow_id: "{{ .workflow_id }}"
      event:
        type: "approval_received"
        data:
          approver: "security@company.com"
          response: "approved"
          
validation:
  checks:
    - name: "workflow_completed"
      type: "workflow_status"
      plugin: "temporal_workflow"
      input:
        workflow_id: "{{ .workflow_id }}"
      expected:
        status: "completed"
        result: "approved"
    - name: "audit_trail_complete"
      type: "query"
      plugin: "audit_store"
      input:
        query: "SELECT COUNT(*) FROM audit_events WHERE correlation_id = '{{ .workflow_id }}'"
      expected:
        count: "> 5"  # Should have multiple audit events

cleanup:
  - name: "cleanup_mock_data"
    type: "cleanup_mocks"
  - name: "cleanup_workflow"
    type: "cancel_workflow"
    plugin: "temporal_workflow"
    input:
      workflow_id: "{{ .workflow_id }}"
`
```

## 📦 Deployment and Distribution

### Plugin Packaging

```dockerfile
# Example Dockerfile for policy evaluator plugin
FROM golang:1.21-alpine AS builder

WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o plugin ./cmd/plugin

FROM alpine:latest
RUN apk --no-cache add ca-certificates
WORKDIR /root/

COPY --from=builder /app/plugin .
COPY --from=builder /app/plugin.yaml .
COPY --from=builder /app/policies/ ./policies/

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
  CMD wget --no-verbose --tries=1 --spider http://localhost:8080/health || exit 1

EXPOSE 8080
CMD ["./plugin"]
```

### Plugin Registry

```yaml
# Plugin registry configuration
apiVersion: afdp.io/v1
kind: PluginRegistry
metadata:
  name: company-policy-plugins
  namespace: afdp

spec:
  plugins:
    - name: "rego-evaluator"
      version: "1.2.0"
      type: "evaluator"
      image: "registry.company.com/afdp/rego-evaluator:1.2.0"
      signature: "sha256:abc123..."
      
    - name: "ml-evaluator"
      version: "2.0.0"
      type: "evaluator"
      image: "registry.company.com/afdp/ml-evaluator:2.0.0"
      signature: "sha256:def456..."
      gpu_required: true
      
    - name: "slack-workflow"
      version: "1.0.0"
      type: "workflow"
      image: "registry.company.com/afdp/slack-workflow:1.0.0"
      signature: "sha256:ghi789..."
      secrets:
        - name: "slack-bot-token"
          key: "SLACK_BOT_TOKEN"
```

### Helm Chart Deployment

```yaml
# values.yaml for AFDP Policy Framework deployment
global:
  image:
    registry: registry.company.com/afdp
    tag: 1.0.0
  security:
    tls:
      enabled: true
      certManager:
        enabled: true

framework:
  replicas: 3
  resources:
    requests:
      cpu: 1000m
      memory: 2Gi
    limits:
      cpu: 2000m
      memory: 4Gi
      
  config:
    log_level: info
    metrics:
      enabled: true
      port: 9090
    tracing:
      enabled: true
      jaeger:
        endpoint: "http://jaeger:14268/api/traces"

plugins:
  # Built-in plugins
  rego_evaluator:
    enabled: true
    replicas: 2
    resources:
      requests:
        cpu: 500m
        memory: 1Gi
        
  # Custom plugins
  custom_ml_evaluator:
    enabled: true
    image: registry.company.com/afdp/custom-ml-evaluator:1.0.0
    replicas: 1
    resources:
      requests:
        cpu: 2000m
        memory: 4Gi
        nvidia.com/gpu: 1
      limits:
        cpu: 4000m
        memory: 8Gi
        nvidia.com/gpu: 1

storage:
  postgresql:
    enabled: true
    auth:
      postgresPassword: "${POSTGRES_PASSWORD}"
    primary:
      persistence:
        size: 100Gi
        storageClass: ssd
        
  redis:
    enabled: true
    auth:
      enabled: true
      password: "${REDIS_PASSWORD}"
    master:
      persistence:
        size: 10Gi

monitoring:
  prometheus:
    enabled: true
  grafana:
    enabled: true
    dashboards:
      enabled: true
```

## 🚀 Performance Optimization

### Plugin Performance Patterns

```go
// High-performance plugin implementation patterns
type OptimizedEvaluator struct {
    // Pre-compiled policies for fast execution
    compiledPolicies map[string]*CompiledPolicy
    
    // Connection pools for external resources
    dbPool    *sql.DB
    httpClient *http.Client
    
    // Caching layers
    l1Cache   *sync.Map           // In-memory cache
    l2Cache   cache.Cache         // Redis/distributed cache
    
    // Resource monitoring
    metrics   *prometheus.MetricSet
    profiler  *pprof.Profiler
    
    // Concurrency control
    semaphore chan struct{}       // Limit concurrent evaluations
    workers   *sync.WaitGroup     // Worker pool management
}

func (oe *OptimizedEvaluator) Evaluate(ctx context.Context, req *EvaluationRequest) (*EvaluationResponse, error) {
    // Acquire semaphore to limit concurrency
    select {
    case oe.semaphore <- struct{}{}:
        defer func() { <-oe.semaphore }()
    case <-ctx.Done():
        return nil, ctx.Err()
    }
    
    // Start performance tracking
    start := time.Now()
    defer func() {
        oe.metrics.EvaluationDuration.Observe(time.Since(start).Seconds())
    }()
    
    // Check L1 cache first
    cacheKey := oe.buildCacheKey(req)
    if cached, exists := oe.l1Cache.Load(cacheKey); exists {
        oe.metrics.CacheHits.WithLabelValues("l1").Inc()
        return cached.(*EvaluationResponse), nil
    }
    
    // Check L2 cache
    if cached, exists := oe.l2Cache.Get(cacheKey); exists {
        oe.metrics.CacheHits.WithLabelValues("l2").Inc()
        // Store in L1 for faster access
        oe.l1Cache.Store(cacheKey, cached)
        return cached.(*EvaluationResponse), nil
    }
    
    // Cache miss - perform evaluation
    oe.metrics.CacheMisses.Inc()
    
    // Get compiled policy
    policy, exists := oe.compiledPolicies[req.PolicyID]
    if !exists {
        return nil, fmt.Errorf("policy not found: %s", req.PolicyID)
    }
    
    // Execute evaluation with timeout
    evalCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
    defer cancel()
    
    result, err := policy.Execute(evalCtx, req.Input)
    if err != nil {
        oe.metrics.EvaluationErrors.Inc()
        return nil, err
    }
    
    response := &EvaluationResponse{
        Decision:   result.Decision,
        Reasoning:  result.Reasoning,
        Confidence: result.Confidence,
        Metadata: map[string]interface{}{
            "evaluation_time_ms": time.Since(start).Milliseconds(),
            "cache_miss":         true,
        },
    }
    
    // Store in caches
    oe.l1Cache.Store(cacheKey, response)
    oe.l2Cache.Set(cacheKey, response, 15*time.Minute)
    
    return response, nil
}

// Batch evaluation for improved throughput
func (oe *OptimizedEvaluator) EvaluateBatch(ctx context.Context, requests []*EvaluationRequest) ([]*EvaluationResponse, error) {
    responses := make([]*EvaluationResponse, len(requests))
    errors := make([]error, len(requests))
    
    // Process requests in parallel with worker pool
    var wg sync.WaitGroup
    workerCount := min(len(requests), runtime.NumCPU())
    requestChan := make(chan struct {
        index int
        request *EvaluationRequest
    }, len(requests))
    
    // Start workers
    for i := 0; i < workerCount; i++ {
        wg.Add(1)
        go func() {
            defer wg.Done()
            for work := range requestChan {
                responses[work.index], errors[work.index] = oe.Evaluate(ctx, work.request)
            }
        }()
    }
    
    // Queue work
    for i, req := range requests {
        requestChan <- struct {
            index int
            request *EvaluationRequest
        }{i, req}
    }
    close(requestChan)
    
    // Wait for completion
    wg.Wait()
    
    // Check for errors
    var firstError error
    for _, err := range errors {
        if err != nil && firstError == nil {
            firstError = err
        }
    }
    
    return responses, firstError
}
```

### Caching Strategies

```go
// Multi-level caching implementation
type CacheManager struct {
    levels []CacheLevel
    stats  *CacheStats
}

type CacheLevel interface {
    Get(key string) (interface{}, bool)
    Set(key string, value interface{}, ttl time.Duration) error
    Delete(key string) error
    Clear() error
    Stats() CacheStats
}

// L1: In-memory cache with LRU eviction
type L1Cache struct {
    cache *lru.Cache
    mutex sync.RWMutex
    stats CacheStats
}

func (l1 *L1Cache) Get(key string) (interface{}, bool) {
    l1.mutex.RLock()
    defer l1.mutex.RUnlock()
    
    value, exists := l1.cache.Get(key)
    if exists {
        l1.stats.Hits++
    } else {
        l1.stats.Misses++
    }
    
    return value, exists
}

// L2: Redis distributed cache
type L2Cache struct {
    client redis.UniversalClient
    stats  CacheStats
}

func (l2 *L2Cache) Get(key string) (interface{}, bool) {
    ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
    defer cancel()
    
    data, err := l2.client.Get(ctx, key).Bytes()
    if err != nil {
        if err == redis.Nil {
            l2.stats.Misses++
        } else {
            l2.stats.Errors++
        }
        return nil, false
    }
    
    // Deserialize cached data
    var value interface{}
    if err := json.Unmarshal(data, &value); err != nil {
        l2.stats.Errors++
        return nil, false
    }
    
    l2.stats.Hits++
    return value, true
}

// Cache warming for predictable workloads
type CacheWarmer struct {
    cacheManager *CacheManager
    predictor    *WorkloadPredictor
}

func (cw *CacheWarmer) WarmCache(ctx context.Context) error {
    // Predict likely cache keys based on historical patterns
    likelyKeys := cw.predictor.PredictHotKeys()
    
    // Pre-populate cache with likely-to-be-requested data
    for _, key := range likelyKeys {
        // Generate or fetch data for key
        data, err := cw.generateCacheData(ctx, key)
        if err != nil {
            log.Errorf("Failed to generate cache data for key %s: %v", key, err)
            continue
        }
        
        // Store in cache
        cw.cacheManager.Set(key, data, 1*time.Hour)
    }
    
    return nil
}
```

---

**Document Control:**
- **Next Review Date:** October 2025
- **Owner:** AFDP Framework Extension Team
- **Approvers:** Framework Architect, Plugin Committee, Security Team
- **Distribution:** Plugin developers, system integrators, framework users

**Classification:** Public  
**Revision History:** v1.0 - Initial framework extension guide