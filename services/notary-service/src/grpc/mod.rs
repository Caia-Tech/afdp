//! gRPC server implementation for AFDP Notary Service
//!
//! This module provides high-performance gRPC endpoints for service-to-service
//! communication in AFDP deployments. It supports:
//!
//! - Evidence package signing (simple and approval workflows)
//! - Batch processing for efficiency
//! - Real-time workflow status streaming
//! - Evidence validation
//! - Health monitoring

pub mod server;
pub mod conversions;

pub use server::NotaryGrpcServer;

// Generated protobuf types
pub mod notary {
    tonic::include_proto!("afdp.notary.v1");
}

// Re-export common types for convenience
pub use notary::{
    notary_service_server::{NotaryService as NotaryServiceTrait, NotaryServiceServer},
    notary_service_client::NotaryServiceClient,
    EvidencePackage, Actor, Artifact, NotarizationReceipt,
    WorkflowStatus, ApprovalState, ApprovalStatus,
    SignEvidenceRequest, SignEvidenceResponse,
    SignEvidenceWithApprovalRequest, SignEvidenceWithApprovalResponse,
    SignEvidenceBatchRequest, SignEvidenceBatchResponse,
    GetWorkflowStatusRequest, GetWorkflowStatusResponse,
    ValidateEvidenceRequest, ValidateEvidenceResponse,
    ListWorkflowsRequest, ListWorkflowsResponse,
    HealthRequest, HealthResponse, DependencyStatus,
};