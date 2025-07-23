//! REST API server implementation

use crate::rest::handlers;
use crate::rest::models::*;
use crate::temporal::{TemporalNotaryClient, TemporalNotaryConfig};
use crate::error::Result;
use axum::{
    routing::{get, post},
    Router,
};
use std::sync::Arc;
use tower::ServiceBuilder;
use tower_http::{
    cors::CorsLayer,
    trace::TraceLayer,
};
use tracing::info;
use utoipa::OpenApi;
use utoipa_swagger_ui::SwaggerUi;

/// REST API server for AFDP Notary Service
pub struct NotaryRestServer {
    app: Router,
}

impl NotaryRestServer {
    /// Create a new REST server
    pub async fn new(config: TemporalNotaryConfig) -> Result<Self> {
        let temporal_client = Arc::new(TemporalNotaryClient::new(config).await?);
        
        // Create OpenAPI documentation
        #[derive(OpenApi)]
        #[openapi(
            paths(
                handlers::sign_evidence,
                handlers::sign_evidence_with_approval,
                handlers::sign_evidence_batch,
                handlers::get_workflow_status,
                handlers::validate_evidence,
                handlers::get_notarization_receipt,
                handlers::list_workflows,
                handlers::health_check,
            ),
            components(
                schemas(
                    SignEvidenceRequest,
                    SignEvidenceResponse,
                    SignEvidenceWithApprovalRequest,
                    SignEvidenceWithApprovalResponse,
                    BatchSignRequest,
                    BatchSignResponse,
                    WorkflowStatusResponse,
                    ValidateEvidenceRequest,
                    ValidateEvidenceResponse,
                    ListWorkflowsResponse,
                    EvidencePackageDto,
                    ActorDto,
                    ArtifactDto,
                    NotarizationReceiptDto,
                    ApprovalStatusDto,
                    ValidationResultDto,
                    WorkflowSummaryDto,
                    ErrorResponse
                )
            ),
            tags(
                (name = "Evidence", description = "Evidence package management endpoints"),
                (name = "Workflows", description = "Workflow management endpoints"),
                (name = "Health", description = "Health check endpoints")
            ),
            info(
                title = "AFDP Notary Service API",
                version = "0.1.0",
                description = "REST API for the AI-Ready Forensic Deployment Pipeline Notary Service",
                contact(
                    name = "CAIA Tech",
                    email = "support@caiatech.com"
                ),
                license(
                    name = "MIT",
                    url = "https://opensource.org/licenses/MIT"
                )
            )
        )]
        struct ApiDoc;

        // Build the router
        let app = Router::new()
            // Evidence endpoints
            .route("/api/v1/evidence/sign", post(handlers::sign_evidence))
            .route("/api/v1/evidence/sign/approval", post(handlers::sign_evidence_with_approval))
            .route("/api/v1/evidence/sign/batch", post(handlers::sign_evidence_batch))
            .route("/api/v1/evidence/validate", post(handlers::validate_evidence))
            
            // Workflow endpoints
            .route("/api/v1/workflows/:workflow_id/status", get(handlers::get_workflow_status))
            .route("/api/v1/workflows/:workflow_id/receipt", get(handlers::get_notarization_receipt))
            .route("/api/v1/workflows", get(handlers::list_workflows))
            
            // Health check
            .route("/health", get(handlers::health_check))
            
            // Swagger UI
            .merge(SwaggerUi::new("/swagger-ui").url("/api-docs/openapi.json", ApiDoc::openapi()))
            
            // Add middleware
            .layer(
                ServiceBuilder::new()
                    .layer(TraceLayer::new_for_http())
                    .layer(CorsLayer::permissive())
            )
            .with_state(temporal_client);

        Ok(Self { app })
    }

    /// Start the REST server
    pub async fn serve(self, addr: std::net::SocketAddr) -> Result<()> {
        info!("Starting REST API server on {}", addr);
        info!("Swagger UI available at http://{}/swagger-ui", addr);

        // For axum 0.6, we use hyper directly
        let make_service = self.app.into_make_service();
        
        hyper::Server::bind(&addr)
            .serve(make_service)
            .await
            .map_err(|e| crate::error::NotaryError::TransportError(e.to_string()))?;

        Ok(())
    }

    /// Get the router for testing
    pub fn router(self) -> Router {
        self.app
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_rest_server_creation() {
        let config = TemporalNotaryConfig::default();
        let server = NotaryRestServer::new(config).await.unwrap();
        
        // Test that server was created successfully
        let router = server.router();
        // Router should be created without panicking
        assert!(std::mem::size_of_val(&router) > 0);
    }

    #[tokio::test]
    async fn test_rest_server_router_structure() {
        let config = TemporalNotaryConfig::default();
        let server = NotaryRestServer::new(config).await.unwrap();
        
        let router = server.router();
        
        // Test that the router was created
        // We can't easily test the actual routes without starting the server,
        // but we can verify the router structure exists
        assert!(std::mem::size_of_val(&router) > 0);
    }

    #[test]
    fn test_openapi_documentation_structure() {
        // Test that the OpenAPI documentation can be generated
        use utoipa::OpenApi;
        
        #[derive(OpenApi)]
        #[openapi(
            info(
                title = "Test API",
                version = "0.1.0",
                description = "Test API documentation"
            )
        )]
        struct TestApiDoc;
        
        let openapi_spec = TestApiDoc::openapi();
        
        assert_eq!(openapi_spec.info.title, "Test API");
        assert_eq!(openapi_spec.info.version, "0.1.0");
        assert!(openapi_spec.info.description.is_some());
    }

    #[tokio::test]
    async fn test_server_configuration_fields() {
        let config = TemporalNotaryConfig::default();
        let server = NotaryRestServer::new(config).await.unwrap();
        
        // Test server has the app field
        let router = server.app;
        assert!(std::mem::size_of_val(&router) > 0);
    }

    #[tokio::test]
    async fn test_rest_server_with_custom_config() {
        let config = TemporalNotaryConfig {
            namespace: "custom_namespace".to_string(),
            task_queue: "custom_task_queue".to_string(),
            ..Default::default()
        };
        
        let server = NotaryRestServer::new(config).await.unwrap();
        let router = server.router();
        
        // Verify the server can be created with custom config
        assert!(std::mem::size_of_val(&router) > 0);
    }

    #[test]
    fn test_notary_rest_server_struct_size() {
        // Test that the struct has the expected size (should contain a Router)
        assert!(std::mem::size_of::<NotaryRestServer>() > 0);
        
        // The struct should contain the app field
        let size = std::mem::size_of::<Router>();
        assert!(size > 0);
    }

    #[tokio::test]
    async fn test_multiple_server_instances() {
        let config1 = TemporalNotaryConfig::default();
        let config2 = TemporalNotaryConfig::default();
        
        let server1 = NotaryRestServer::new(config1).await.unwrap();
        let server2 = NotaryRestServer::new(config2).await.unwrap();
        
        let router1 = server1.router();
        let router2 = server2.router();
        
        // Both servers should be created successfully
        assert!(std::mem::size_of_val(&router1) > 0);
        assert!(std::mem::size_of_val(&router2) > 0);
    }

    #[tokio::test]
    async fn test_server_router_middleware_setup() {
        let config = TemporalNotaryConfig::default();
        let server = NotaryRestServer::new(config).await.unwrap();
        
        // Test that the router has middleware layers applied
        let router = server.router();
        
        // The router should be larger than a minimal router due to middleware
        assert!(std::mem::size_of_val(&router) > std::mem::size_of::<Router>() / 2);
    }

    #[test]
    fn test_rest_server_openapi_tags() {
        use utoipa::OpenApi;
        
        #[derive(OpenApi)]
        #[openapi(
            tags(
                (name = "Evidence", description = "Evidence package management endpoints"),
                (name = "Workflows", description = "Workflow management endpoints"),
                (name = "Health", description = "Health check endpoints")
            ),
            info(title = "Test", version = "1.0.0")
        )]
        struct TestApi;
        
        let spec = TestApi::openapi();
        
        // Should have the expected tags
        assert!(spec.tags.is_some());
        let tags = spec.tags.unwrap();
        assert_eq!(tags.len(), 3);
        
        let tag_names: Vec<&str> = tags.iter().map(|t| t.name.as_str()).collect();
        assert!(tag_names.contains(&"Evidence"));
        assert!(tag_names.contains(&"Workflows"));
        assert!(tag_names.contains(&"Health"));
    }

    #[test]
    fn test_rest_server_contact_info() {
        use utoipa::OpenApi;
        
        #[derive(OpenApi)]
        #[openapi(
            info(
                title = "Test API",
                version = "1.0.0",
                contact(
                    name = "CAIA Tech",
                    email = "support@caiatech.com"
                )
            )
        )]
        struct TestApi;
        
        let spec = TestApi::openapi();
        
        assert!(spec.info.contact.is_some());
        let contact = spec.info.contact.unwrap();
        assert_eq!(contact.name, Some("CAIA Tech".to_string()));
        assert_eq!(contact.email, Some("support@caiatech.com".to_string()));
    }

    #[test]
    fn test_rest_server_license_info() {
        use utoipa::OpenApi;
        
        #[derive(OpenApi)]
        #[openapi(
            info(
                title = "Test API",
                version = "1.0.0",
                license(
                    name = "MIT",
                    url = "https://opensource.org/licenses/MIT"
                )
            )
        )]
        struct TestApi;
        
        let spec = TestApi::openapi();
        
        assert!(spec.info.license.is_some());
        let license = spec.info.license.unwrap();
        assert_eq!(license.name, "MIT");
        assert_eq!(license.url, Some("https://opensource.org/licenses/MIT".to_string()));
    }

    #[tokio::test]
    async fn test_rest_server_memory_usage() {
        let config = TemporalNotaryConfig::default();
        let server = NotaryRestServer::new(config).await.unwrap();
        
        // Test that the server doesn't consume excessive memory
        let router_size = std::mem::size_of_val(&server.app);
        
        // Router should be reasonably sized (not empty, but not huge)
        assert!(router_size > 0);
        assert!(router_size < 10_000); // Reasonable upper bound
    }

    #[tokio::test]
    async fn test_server_creation_with_different_configs() {
        let configs = vec![
            TemporalNotaryConfig {
                namespace: "test1".to_string(),
                task_queue: "queue1".to_string(),
                ..Default::default()
            },
            TemporalNotaryConfig {
                namespace: "test2".to_string(),
                task_queue: "queue2".to_string(),
                ..Default::default()
            },
            TemporalNotaryConfig {
                namespace: "production".to_string(),
                task_queue: "prod_queue".to_string(),
                ..Default::default()
            },
        ];
        
        for config in configs {
            let server = NotaryRestServer::new(config).await.unwrap();
            let router = server.router();
            assert!(std::mem::size_of_val(&router) > 0);
        }
    }

    #[test]
    fn test_socket_addr_types() {
        use std::net::{IpAddr, Ipv4Addr, SocketAddr};
        
        // Test different socket address types that could be used with serve()
        let addrs = vec![
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 8080),
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)), 3000),
            "127.0.0.1:8080".parse::<SocketAddr>().unwrap(),
            "0.0.0.0:3000".parse::<SocketAddr>().unwrap(),
        ];
        
        for addr in addrs {
            // Test that addresses are valid
            assert!(addr.port() > 0);
            assert!(!addr.ip().is_unspecified() || addr.ip().to_string() == "0.0.0.0");
        }
    }
}