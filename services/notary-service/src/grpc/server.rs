//! gRPC server implementation for AFDP Notary Service

use crate::grpc::notary::{
    notary_service_server::{NotaryService, NotaryServiceServer},
    *,
};
use crate::temporal::{TemporalNotaryClient, TemporalNotaryConfig};
use crate::error::Result;
use std::sync::Arc;
use tonic::{Request, Response, Status, transport::Server};
use tracing::{info, error};

/// gRPC server for AFDP Notary Service
pub struct NotaryGrpcServer {
    temporal_client: Arc<TemporalNotaryClient>,
    server_start_time: std::time::Instant,
}

impl NotaryGrpcServer {
    /// Create a new gRPC server
    pub async fn new(config: TemporalNotaryConfig) -> Result<Self> {
        let temporal_client = Arc::new(TemporalNotaryClient::new(config).await?);
        
        Ok(Self { 
            temporal_client,
            server_start_time: std::time::Instant::now(),
        })
    }

    /// Start the gRPC server
    pub async fn serve(self, addr: std::net::SocketAddr) -> Result<()> {
        info!("Starting gRPC server on {}", addr);

        let service = NotaryServiceServer::new(self);
        
        Server::builder()
            .add_service(service)
            .serve(addr)
            .await
            .map_err(|e| crate::error::NotaryError::TransportError(e.to_string()))?;

        Ok(())
    }

    /// Get server for use in tests
    pub fn into_service(self) -> NotaryServiceServer<Self> {
        NotaryServiceServer::new(self)
    }
}

#[tonic::async_trait]
impl NotaryService for NotaryGrpcServer {
    async fn sign_evidence(
        &self,
        request: Request<SignEvidenceRequest>,
    ) -> std::result::Result<Response<SignEvidenceResponse>, Status> {
        let req = request.into_inner();
        
        info!("Received gRPC sign evidence request");

        let evidence_package = req.evidence_package
            .ok_or_else(|| Status::invalid_argument("Evidence package is required"))?
            .into();

        match self.temporal_client.sign_evidence_sync(evidence_package).await {
            Ok(result) => {
                let workflow_id = format!("simple-signing-{}", uuid::Uuid::new_v4());
                
                let response = SignEvidenceResponse {
                    workflow_id: workflow_id.clone(),
                    receipt: Some(result.receipt.into()),
                    status: WorkflowStatus::Completed as i32,
                };


                Ok(Response::new(response))
            }
            Err(e) => {
                error!("Failed to sign evidence: {}", e);
                Err(Status::internal(format!("Failed to sign evidence: {}", e)))
            }
        }
    }

    async fn sign_evidence_with_approval(
        &self,
        request: Request<SignEvidenceWithApprovalRequest>,
    ) -> std::result::Result<Response<SignEvidenceWithApprovalResponse>, Status> {
        let req = request.into_inner();
        
        info!("Received gRPC sign evidence with approval request");

        let evidence_package = req.evidence_package
            .ok_or_else(|| Status::invalid_argument("Evidence package is required"))?
            .into();

        match self.temporal_client.sign_evidence_with_approval(evidence_package, req.approvers.clone()).await {
            Ok(execution) => {
                let workflow_id = execution.workflow_id().to_string();

                let approval_statuses = req.approvers
                    .into_iter()
                    .map(|approver| ApprovalStatus {
                        approver,
                        status: ApprovalState::Pending as i32,
                        timestamp: Some(prost_types::Timestamp {
                            seconds: chrono::Utc::now().timestamp(),
                            nanos: 0,
                        }),
                        comment: String::new(),
                    })
                    .collect();

                let response = SignEvidenceWithApprovalResponse {
                    workflow_id: workflow_id.clone(),
                    status: WorkflowStatus::Pending as i32,
                    approval_statuses,
                };


                Ok(Response::new(response))
            }
            Err(e) => {
                error!("Failed to start approval workflow: {}", e);
                Err(Status::internal(format!("Failed to start approval workflow: {}", e)))
            }
        }
    }

    async fn sign_evidence_batch(
        &self,
        request: Request<SignEvidenceBatchRequest>,
    ) -> std::result::Result<Response<SignEvidenceBatchResponse>, Status> {
        let req = request.into_inner();
        
        info!("Received gRPC batch sign evidence request for {} packages", req.evidence_packages.len());

        let evidence_packages: Vec<_> = req.evidence_packages
            .into_iter()
            .map(Into::into)
            .collect();

        match self.temporal_client.sign_evidence_batch(evidence_packages).await {
            Ok(execution) => {
                let batch_workflow_id = execution.workflow_id().to_string();

                let response = SignEvidenceBatchResponse {
                    batch_workflow_id: batch_workflow_id.clone(),
                    results: Vec::new(), // Would be populated in real implementation
                    status: WorkflowStatus::Running as i32,
                };


                Ok(Response::new(response))
            }
            Err(e) => {
                error!("Failed to start batch workflow: {}", e);
                Err(Status::internal(format!("Failed to start batch workflow: {}", e)))
            }
        }
    }

    async fn get_workflow_status(
        &self,
        request: Request<GetWorkflowStatusRequest>,
    ) -> std::result::Result<Response<GetWorkflowStatusResponse>, Status> {
        let req = request.into_inner();
        
        info!("Getting workflow status for: {}", req.workflow_id);

        // Mock implementation - would query actual Temporal server
        let response = GetWorkflowStatusResponse {
            workflow_id: req.workflow_id,
            status: WorkflowStatus::Completed as i32,
            created_at: Some(prost_types::Timestamp {
                seconds: chrono::Utc::now().timestamp() - 3600,
                nanos: 0,
            }),
            completed_at: Some(prost_types::Timestamp {
                seconds: chrono::Utc::now().timestamp(),
                nanos: 0,
            }),
            error_message: String::new(),
            result: None,
        };

        Ok(Response::new(response))
    }

    async fn validate_evidence(
        &self,
        request: Request<ValidateEvidenceRequest>,
    ) -> std::result::Result<Response<ValidateEvidenceResponse>, Status> {
        let req = request.into_inner();
        
        info!("Validating evidence package via gRPC");

        let _evidence_package = req.evidence_package
            .ok_or_else(|| Status::invalid_argument("Evidence package is required"))?;

        // Mock validation - would use actual notary client
        let validation_result = ValidationResult {
            signature_valid: true,
            evidence_hash_valid: true,
            rekor_entry_valid: true,
            timestamp_valid: true,
            warnings: Vec::new(),
        };

        let response = ValidateEvidenceResponse {
            is_valid: true,
            validation_error: String::new(),
            validation_result: Some(validation_result),
        };

        Ok(Response::new(response))
    }

    async fn get_notarization_receipt(
        &self,
        request: Request<GetNotarizationReceiptRequest>,
    ) -> std::result::Result<Response<GetNotarizationReceiptResponse>, Status> {
        let req = request.into_inner();
        
        info!("Getting notarization receipt for workflow: {}", req.workflow_id);

        // Mock receipt - would query actual storage
        let receipt = NotarizationReceipt {
            evidence_package_hash: "mock_hash".to_string(),
            rekor_log_id: "mock_log_id".to_string(),
            rekor_server_url: "https://rekor.sigstore.dev".to_string(),
            signature_b64: "mock_signature".to_string(),
            public_key_b64: "mock_public_key".to_string(),
            integrated_time: chrono::Utc::now().timestamp(),
            log_index: 12345,
        };

        let response = GetNotarizationReceiptResponse {
            receipt: Some(receipt),
            found: true,
        };

        Ok(Response::new(response))
    }

    async fn list_workflows(
        &self,
        request: Request<ListWorkflowsRequest>,
    ) -> std::result::Result<Response<ListWorkflowsResponse>, Status> {
        let _req = request.into_inner();
        
        info!("Listing workflows via gRPC");

        // Mock workflow list - would query actual Temporal server
        let workflows = vec![
            WorkflowSummary {
                workflow_id: "workflow-1".to_string(),
                workflow_type: "simple_signing".to_string(),
                status: WorkflowStatus::Completed as i32,
                created_at: Some(prost_types::Timestamp {
                    seconds: chrono::Utc::now().timestamp() - 3600,
                    nanos: 0,
                }),
                completed_at: Some(prost_types::Timestamp {
                    seconds: chrono::Utc::now().timestamp(),
                    nanos: 0,
                }),
                event_type: "model.deployment".to_string(),
                actor_id: "user@example.com".to_string(),
            }
        ];

        let response = ListWorkflowsResponse {
            workflows,
            next_page_token: String::new(),
            total_count: 1,
        };

        Ok(Response::new(response))
    }

    async fn health_check(
        &self,
        _request: Request<HealthRequest>,
    ) -> std::result::Result<Response<HealthResponse>, Status> {
        info!("gRPC health check requested");

        let uptime = self.server_start_time.elapsed().as_secs() as i64;

        // Mock dependency status - would check actual services
        let dependencies = vec![
            DependencyStatus {
                name: "temporal".to_string(),
                healthy: true,
                response_time_ms: 50,
                error: String::new(),
            },
            DependencyStatus {
                name: "vault".to_string(),
                healthy: true,
                response_time_ms: 25,
                error: String::new(),
            },
            DependencyStatus {
                name: "rekor".to_string(),
                healthy: true,
                response_time_ms: 100,
                error: String::new(),
            },
        ];

        let response = HealthResponse {
            status: "healthy".to_string(),
            version: env!("CARGO_PKG_VERSION").to_string(),
            uptime_seconds: uptime,
            dependencies,
        };

        Ok(Response::new(response))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    

    #[tokio::test]
    async fn test_grpc_server_creation() {
        let config = TemporalNotaryConfig::default();
        let server = NotaryGrpcServer::new(config).await.unwrap();
        
        // Test that server was created successfully
        assert!(server.server_start_time.elapsed().as_secs() < 1);
    }

    #[tokio::test]
    async fn test_health_check() {
        let config = TemporalNotaryConfig::default();
        let server = NotaryGrpcServer::new(config).await.unwrap();
        
        let request = Request::new(HealthRequest {});
        let response = server.health_check(request).await.unwrap();
        
        let health = response.into_inner();
        assert_eq!(health.status, "healthy");
        assert_eq!(health.version, env!("CARGO_PKG_VERSION"));
        assert!(health.uptime_seconds >= 0);
        assert_eq!(health.dependencies.len(), 3);
    }

    #[tokio::test]
    async fn test_sign_evidence_grpc() {
        use crate::{Actor, EvidencePackage};
        
        let config = TemporalNotaryConfig::default();
        let server = NotaryGrpcServer::new(config).await.unwrap();
        
        let actor = Actor {
            actor_type: "test_user".to_string(),
            id: "test@example.com".to_string(),
            auth_provider: Some("test".to_string()),
        };

        let evidence = EvidencePackage::new("test.grpc.sign".to_string(), actor);
        
        let request = Request::new(SignEvidenceRequest {
            evidence_package: Some(evidence.into()),
        });

        let response = server.sign_evidence(request).await.unwrap();
        let sign_response = response.into_inner();
        
        assert!(sign_response.workflow_id.starts_with("simple-signing-"));
        assert!(sign_response.receipt.is_some());
        assert_eq!(sign_response.status, WorkflowStatus::Completed as i32);
    }

    #[tokio::test]
    async fn test_sign_evidence_grpc_missing_package() {
        let config = TemporalNotaryConfig::default();
        let server = NotaryGrpcServer::new(config).await.unwrap();
        
        let request = Request::new(SignEvidenceRequest {
            evidence_package: None,
        });

        let result = server.sign_evidence(request).await;
        assert!(result.is_err());
        
        let error = result.unwrap_err();
        assert_eq!(error.code(), tonic::Code::InvalidArgument);
        assert!(error.message().contains("Evidence package is required"));
    }

    #[tokio::test]
    async fn test_sign_evidence_with_approval_grpc() {
        use crate::{Actor, EvidencePackage};
        
        let config = TemporalNotaryConfig::default();
        let server = NotaryGrpcServer::new(config).await.unwrap();
        
        let actor = Actor {
            actor_type: "test_user".to_string(),
            id: "test@example.com".to_string(),
            auth_provider: Some("test".to_string()),
        };

        let evidence = EvidencePackage::new("test.grpc.approval".to_string(), actor);
        
        let request = Request::new(SignEvidenceWithApprovalRequest {
            evidence_package: Some(evidence.into()),
            approvers: vec!["approver1@example.com".to_string(), "approver2@example.com".to_string()],
        });

        let response = server.sign_evidence_with_approval(request).await.unwrap();
        let approval_response = response.into_inner();
        
        assert!(approval_response.workflow_id.starts_with("approval-signing-"));
        assert_eq!(approval_response.status, WorkflowStatus::Pending as i32);
        assert_eq!(approval_response.approval_statuses.len(), 2);
        
        for status in &approval_response.approval_statuses {
            assert_eq!(status.status, ApprovalState::Pending as i32);
            assert!(status.timestamp.is_some());
            assert!(status.comment.is_empty());
        }
    }

    #[tokio::test]
    async fn test_sign_evidence_with_approval_missing_package() {
        let config = TemporalNotaryConfig::default();
        let server = NotaryGrpcServer::new(config).await.unwrap();
        
        let request = Request::new(SignEvidenceWithApprovalRequest {
            evidence_package: None,
            approvers: vec!["approver@example.com".to_string()],
        });

        let result = server.sign_evidence_with_approval(request).await;
        assert!(result.is_err());
        
        let error = result.unwrap_err();
        assert_eq!(error.code(), tonic::Code::InvalidArgument);
        assert!(error.message().contains("Evidence package is required"));
    }

    #[tokio::test]
    async fn test_sign_evidence_with_approval_empty_approvers() {
        use crate::{Actor, EvidencePackage};
        
        let config = TemporalNotaryConfig::default();
        let server = NotaryGrpcServer::new(config).await.unwrap();
        
        let actor = Actor {
            actor_type: "test_user".to_string(),
            id: "test@example.com".to_string(),
            auth_provider: Some("test".to_string()),
        };

        let evidence = EvidencePackage::new("test.grpc.approval.empty".to_string(), actor);
        
        let request = Request::new(SignEvidenceWithApprovalRequest {
            evidence_package: Some(evidence.into()),
            approvers: vec![],
        });

        let response = server.sign_evidence_with_approval(request).await.unwrap();
        let approval_response = response.into_inner();
        
        assert!(approval_response.workflow_id.starts_with("approval-signing-"));
        assert_eq!(approval_response.status, WorkflowStatus::Pending as i32);
        assert!(approval_response.approval_statuses.is_empty());
    }

    #[tokio::test]
    async fn test_sign_evidence_batch_grpc() {
        use crate::{Actor, EvidencePackage};
        
        let config = TemporalNotaryConfig::default();
        let server = NotaryGrpcServer::new(config).await.unwrap();
        
        let actor1 = Actor {
            actor_type: "batch_user".to_string(),
            id: "user1@example.com".to_string(),
            auth_provider: Some("test".to_string()),
        };
        let actor2 = Actor {
            actor_type: "batch_user".to_string(),
            id: "user2@example.com".to_string(),
            auth_provider: Some("test".to_string()),
        };

        let evidence1 = EvidencePackage::new("test.grpc.batch.1".to_string(), actor1);
        let evidence2 = EvidencePackage::new("test.grpc.batch.2".to_string(), actor2);
        
        let request = Request::new(SignEvidenceBatchRequest {
            evidence_packages: vec![evidence1.into(), evidence2.into()],
        });

        let response = server.sign_evidence_batch(request).await.unwrap();
        let batch_response = response.into_inner();
        
        assert!(batch_response.batch_workflow_id.starts_with("batch-signing-"));
        assert_eq!(batch_response.status, WorkflowStatus::Running as i32);
        assert!(batch_response.results.is_empty()); // Mock implementation
    }

    #[tokio::test]
    async fn test_sign_evidence_batch_empty() {
        let config = TemporalNotaryConfig::default();
        let server = NotaryGrpcServer::new(config).await.unwrap();
        
        let request = Request::new(SignEvidenceBatchRequest {
            evidence_packages: vec![],
        });

        let response = server.sign_evidence_batch(request).await.unwrap();
        let batch_response = response.into_inner();
        
        assert!(batch_response.batch_workflow_id.starts_with("batch-signing-"));
        assert_eq!(batch_response.status, WorkflowStatus::Running as i32);
    }

    #[tokio::test]
    async fn test_get_workflow_status_grpc() {
        let config = TemporalNotaryConfig::default();
        let server = NotaryGrpcServer::new(config).await.unwrap();
        
        let workflow_id = "test-workflow-123".to_string();
        
        let request = Request::new(GetWorkflowStatusRequest {
            workflow_id: workflow_id.clone(),
        });

        let response = server.get_workflow_status(request).await.unwrap();
        let status_response = response.into_inner();
        
        assert_eq!(status_response.workflow_id, workflow_id);
        assert_eq!(status_response.status, WorkflowStatus::Completed as i32);
        assert!(status_response.created_at.is_some());
        assert!(status_response.completed_at.is_some());
        assert!(status_response.error_message.is_empty());
        
        // Mock implementation sets created_at to 1 hour ago
        let created = status_response.created_at.unwrap();
        let completed = status_response.completed_at.unwrap();
        assert!(completed.seconds >= created.seconds);
    }

    #[tokio::test]
    async fn test_validate_evidence_grpc() {
        use crate::{Actor, EvidencePackage};
        
        let config = TemporalNotaryConfig::default();
        let server = NotaryGrpcServer::new(config).await.unwrap();
        
        let actor = Actor {
            actor_type: "validation_user".to_string(),
            id: "validator@example.com".to_string(),
            auth_provider: Some("test".to_string()),
        };

        let evidence = EvidencePackage::new("test.grpc.validation".to_string(), actor);
        
        let request = Request::new(ValidateEvidenceRequest {
            evidence_package: Some(evidence.into()),
            signature: "test_signature".to_string(),
        });

        let response = server.validate_evidence(request).await.unwrap();
        let validation_response = response.into_inner();
        
        assert!(validation_response.is_valid);
        assert!(validation_response.validation_error.is_empty());
        assert!(validation_response.validation_result.is_some());
        
        let result = validation_response.validation_result.unwrap();
        assert!(result.signature_valid);
        assert!(result.evidence_hash_valid);
        assert!(result.rekor_entry_valid);
        assert!(result.timestamp_valid);
        assert!(result.warnings.is_empty());
    }

    #[tokio::test]
    async fn test_validate_evidence_missing_package() {
        let config = TemporalNotaryConfig::default();
        let server = NotaryGrpcServer::new(config).await.unwrap();
        
        let request = Request::new(ValidateEvidenceRequest {
            evidence_package: None,
            signature: "test_signature".to_string(),
        });

        let result = server.validate_evidence(request).await;
        assert!(result.is_err());
        
        let error = result.unwrap_err();
        assert_eq!(error.code(), tonic::Code::InvalidArgument);
        assert!(error.message().contains("Evidence package is required"));
    }

    #[tokio::test]
    async fn test_get_notarization_receipt_grpc() {
        let config = TemporalNotaryConfig::default();
        let server = NotaryGrpcServer::new(config).await.unwrap();
        
        let workflow_id = "test-workflow-456".to_string();
        
        let request = Request::new(GetNotarizationReceiptRequest {
            workflow_id: workflow_id.clone(),
        });

        let response = server.get_notarization_receipt(request).await.unwrap();
        let receipt_response = response.into_inner();
        
        assert!(receipt_response.found);
        assert!(receipt_response.receipt.is_some());
        
        let receipt = receipt_response.receipt.unwrap();
        assert_eq!(receipt.evidence_package_hash, "mock_hash");
        assert_eq!(receipt.rekor_log_id, "mock_log_id");
        assert_eq!(receipt.rekor_server_url, "https://rekor.sigstore.dev");
        assert_eq!(receipt.signature_b64, "mock_signature");
        assert_eq!(receipt.public_key_b64, "mock_public_key");
        assert_eq!(receipt.log_index, 12345);
        assert!(receipt.integrated_time > 0);
    }

    #[tokio::test]
    async fn test_list_workflows_grpc() {
        let config = TemporalNotaryConfig::default();
        let server = NotaryGrpcServer::new(config).await.unwrap();
        
        let request = Request::new(ListWorkflowsRequest {
            page_size: 10,
            page_token: "".to_string(),
            status_filter: WorkflowStatus::Completed as i32,
            start_time: None,
            end_time: None,
        });

        let response = server.list_workflows(request).await.unwrap();
        let list_response = response.into_inner();
        
        assert_eq!(list_response.workflows.len(), 1);
        assert_eq!(list_response.total_count, 1);
        assert!(list_response.next_page_token.is_empty());
        
        let workflow = &list_response.workflows[0];
        assert_eq!(workflow.workflow_id, "workflow-1");
        assert_eq!(workflow.workflow_type, "simple_signing");
        assert_eq!(workflow.status, WorkflowStatus::Completed as i32);
        assert_eq!(workflow.event_type, "model.deployment");
        assert_eq!(workflow.actor_id, "user@example.com");
        assert!(workflow.created_at.is_some());
        assert!(workflow.completed_at.is_some());
    }

    #[tokio::test]
    async fn test_health_check_dependency_status() {
        let config = TemporalNotaryConfig::default();
        let server = NotaryGrpcServer::new(config).await.unwrap();
        
        let request = Request::new(HealthRequest {});
        let response = server.health_check(request).await.unwrap();
        
        let health = response.into_inner();
        
        // Check dependency details
        let dependencies = health.dependencies;
        assert_eq!(dependencies.len(), 3);
        
        let temporal_dep = dependencies.iter().find(|d| d.name == "temporal").unwrap();
        assert!(temporal_dep.healthy);
        assert_eq!(temporal_dep.response_time_ms, 50);
        assert!(temporal_dep.error.is_empty());
        
        let vault_dep = dependencies.iter().find(|d| d.name == "vault").unwrap();
        assert!(vault_dep.healthy);
        assert_eq!(vault_dep.response_time_ms, 25);
        assert!(vault_dep.error.is_empty());
        
        let rekor_dep = dependencies.iter().find(|d| d.name == "rekor").unwrap();
        assert!(rekor_dep.healthy);
        assert_eq!(rekor_dep.response_time_ms, 100);
        assert!(rekor_dep.error.is_empty());
    }

    #[tokio::test]
    async fn test_server_uptime_tracking() {
        let config = TemporalNotaryConfig::default();
        let server = NotaryGrpcServer::new(config).await.unwrap();
        
        // Sleep for a short time to ensure uptime > 0
        tokio::time::sleep(tokio::time::Duration::from_millis(10)).await;
        
        let request = Request::new(HealthRequest {});
        let response = server.health_check(request).await.unwrap();
        
        let health = response.into_inner();
        assert!(health.uptime_seconds >= 0);
        // Should be less than 1 second for this test
        assert!(health.uptime_seconds < 10);
    }

    #[tokio::test] 
    async fn test_server_into_service() {
        let config = TemporalNotaryConfig::default();
        let server = NotaryGrpcServer::new(config).await.unwrap();
        
        let _service = server.into_service();
        // Test passes if no panic occurs during service creation
    }

    #[tokio::test]
    async fn test_sign_evidence_with_many_approvers() {
        use crate::{Actor, EvidencePackage};
        
        let config = TemporalNotaryConfig::default();
        let server = NotaryGrpcServer::new(config).await.unwrap();
        
        let actor = Actor {
            actor_type: "test_user".to_string(),
            id: "test@example.com".to_string(),
            auth_provider: Some("test".to_string()),
        };

        let evidence = EvidencePackage::new("test.grpc.many.approvers".to_string(), actor);
        
        let approvers: Vec<String> = (1..=5)
            .map(|i| format!("approver{}@example.com", i))
            .collect();
        
        let request = Request::new(SignEvidenceWithApprovalRequest {
            evidence_package: Some(evidence.into()),
            approvers: approvers.clone(),
        });

        let response = server.sign_evidence_with_approval(request).await.unwrap();
        let approval_response = response.into_inner();
        
        assert_eq!(approval_response.approval_statuses.len(), 5);
        
        for (i, status) in approval_response.approval_statuses.iter().enumerate() {
            assert_eq!(status.approver, format!("approver{}@example.com", i + 1));
            assert_eq!(status.status, ApprovalState::Pending as i32);
            assert!(status.timestamp.is_some());
        }
    }

    #[tokio::test]
    async fn test_sign_evidence_batch_large() {
        use crate::{Actor, EvidencePackage};
        
        let config = TemporalNotaryConfig::default();
        let server = NotaryGrpcServer::new(config).await.unwrap();
        
        let evidence_packages: Vec<_> = (0..10)
            .map(|i| {
                let actor = Actor {
                    actor_type: "batch_test".to_string(),
                    id: format!("user{}@example.com", i),
                    auth_provider: None,
                };
                EvidencePackage::new(format!("test.grpc.batch.{}", i), actor).into()
            })
            .collect();
        
        let request = Request::new(SignEvidenceBatchRequest {
            evidence_packages,
        });

        let response = server.sign_evidence_batch(request).await.unwrap();
        let batch_response = response.into_inner();
        
        assert!(batch_response.batch_workflow_id.starts_with("batch-signing-"));
        assert_eq!(batch_response.status, WorkflowStatus::Running as i32);
        assert!(batch_response.results.is_empty());
    }

    // Integration test that requires actual Vault connection
    // Uncomment when running with docker-compose
    // #[tokio::test]
    // async fn test_sign_evidence_grpc() {
    //     let config = TemporalNotaryConfig::default();
    //     let server = NotaryGrpcServer::new(config).await.unwrap();
    //     
    //     let actor = Actor {
    //         actor_type: "test_user".to_string(),
    //         id: "test@example.com".to_string(),
    //         auth_provider: Some("test".to_string()),
    //     };

    //     let evidence = EvidencePackage::new("test.grpc.sign".to_string(), actor);
    //     
    //     let request = Request::new(SignEvidenceRequest {
    //         evidence_package: Some(evidence.into()),
    //     });

    //     let response = server.sign_evidence(request).await.unwrap();
    //     let sign_response = response.into_inner();
    //     
    //     assert!(!sign_response.workflow_id.is_empty());
    //     assert!(sign_response.receipt.is_some());
    //     assert_eq!(sign_response.status, WorkflowStatus::Completed as i32);
    // }
}