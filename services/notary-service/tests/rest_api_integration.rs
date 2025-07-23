//! Integration tests for the AFDP Notary Service REST API

use afdp_notary::{NotaryRestServer, TemporalNotaryConfig};
use axum::http::StatusCode;
use serde_json::json;
use tower::ServiceExt;

#[tokio::test]
async fn test_health_endpoint() {
    let config = TemporalNotaryConfig::default();
    let server = NotaryRestServer::new(config).await.unwrap();
    let app = server.router();

    let response = app
        .oneshot(
            axum::http::Request::builder()
                .uri("/health")
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    
    let body = hyper::body::to_bytes(response.into_body()).await.unwrap();
    let health_response: serde_json::Value = serde_json::from_slice(&body).unwrap();
    
    assert_eq!(health_response["status"], "healthy");
    assert!(health_response["version"].is_string());
}

// Integration test - requires running Vault instance
// Uncomment when running with docker-compose
// #[tokio::test]
#[allow(dead_code)]
async fn test_sign_evidence_endpoint() {
    let config = TemporalNotaryConfig::default();
    let server = NotaryRestServer::new(config).await.unwrap();
    let app = server.router();

    let evidence_request = json!({
        "evidence_package": {
            "spec_version": "1.0.0",
            "timestamp_utc": "2025-07-23T10:00:00Z",
            "event_type": "test.integration.sign",
            "actor": {
                "actor_type": "test_user",
                "id": "test@example.com",
                "auth_provider": "test"
            },
            "artifacts": [
                {
                    "name": "test-artifact",
                    "uri": "file://test-artifact",
                    "hash_sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
                }
            ],
            "metadata": {
                "test": true,
                "integration": "rest_api"
            }
        }
    });

    let response = app
        .oneshot(
            axum::http::Request::builder()
                .uri("/api/v1/evidence/sign")
                .method("POST")
                .header("content-type", "application/json")
                .body(axum::body::Body::from(evidence_request.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();

    let status = response.status();
    let body = hyper::body::to_bytes(response.into_body()).await.unwrap();
    let body_str = String::from_utf8(body.to_vec()).unwrap();
    
    if status != StatusCode::OK {
        println!("Response status: {}", status);
        println!("Response body: {}", body_str);
    }
    
    assert_eq!(status, StatusCode::OK);
    
    let sign_response: serde_json::Value = serde_json::from_slice(&body).unwrap();
    
    assert!(sign_response["workflow_id"].is_string());
    assert_eq!(sign_response["status"], "completed");
    assert!(sign_response["receipt"].is_object());
}

// Integration test - requires running Vault instance
// Uncomment when running with docker-compose
// #[tokio::test]
#[allow(dead_code)]
async fn test_sign_evidence_with_approval_endpoint() {
    let config = TemporalNotaryConfig::default();
    let server = NotaryRestServer::new(config).await.unwrap();
    let app = server.router();

    let approval_request = json!({
        "evidence_package": {
            "spec_version": "1.0.0",
            "timestamp_utc": "2025-07-23T10:00:00Z",
            "event_type": "test.integration.approval",
            "actor": {
                "actor_type": "test_user",
                "id": "test@example.com",
                "auth_provider": "test"
            },
            "artifacts": [],
            "metadata": {
                "requires_approval": true
            }
        },
        "approvers": [
            "approver1@example.com",
            "approver2@example.com"
        ]
    });

    let response = app
        .oneshot(
            axum::http::Request::builder()
                .uri("/api/v1/evidence/sign/approval")
                .method("POST")
                .header("content-type", "application/json")
                .body(axum::body::Body::from(approval_request.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    
    let body = hyper::body::to_bytes(response.into_body()).await.unwrap();
    let approval_response: serde_json::Value = serde_json::from_slice(&body).unwrap();
    
    assert!(approval_response["workflow_id"].is_string());
    assert_eq!(approval_response["status"], "pending");
    assert!(approval_response["approval_statuses"].is_array());
    assert_eq!(approval_response["approval_statuses"].as_array().unwrap().len(), 2);
}

#[tokio::test]
async fn test_batch_sign_evidence_endpoint() {
    let config = TemporalNotaryConfig::default();
    let server = NotaryRestServer::new(config).await.unwrap();
    let app = server.router();

    let batch_request = json!({
        "evidence_packages": [
            {
                "spec_version": "1.0.0",
                "timestamp_utc": "2025-07-23T10:00:00Z",
                "event_type": "test.batch.1",
                "actor": {
                    "actor_type": "test_user",
                    "id": "test@example.com"
                },
                "artifacts": [],
                "metadata": {"batch_item": 1}
            },
            {
                "spec_version": "1.0.0",
                "timestamp_utc": "2025-07-23T10:00:00Z",
                "event_type": "test.batch.2",
                "actor": {
                    "actor_type": "test_user",
                    "id": "test@example.com"
                },
                "artifacts": [],
                "metadata": {"batch_item": 2}
            }
        ]
    });

    let response = app
        .oneshot(
            axum::http::Request::builder()
                .uri("/api/v1/evidence/sign/batch")
                .method("POST")
                .header("content-type", "application/json")
                .body(axum::body::Body::from(batch_request.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    
    let body = hyper::body::to_bytes(response.into_body()).await.unwrap();
    let batch_response: serde_json::Value = serde_json::from_slice(&body).unwrap();
    
    assert!(batch_response["batch_workflow_id"].is_string());
    assert!(batch_response["status"].is_string());
    // Results array may be empty in mock implementation
}

#[tokio::test]
async fn test_workflow_status_endpoint() {
    let config = TemporalNotaryConfig::default();
    let server = NotaryRestServer::new(config).await.unwrap();
    let app = server.router();

    let workflow_id = "test-workflow-123";
    let response = app
        .oneshot(
            axum::http::Request::builder()
                .uri(&format!("/api/v1/workflows/{}/status", workflow_id))
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    
    let body = hyper::body::to_bytes(response.into_body()).await.unwrap();
    let status_response: serde_json::Value = serde_json::from_slice(&body).unwrap();
    
    assert_eq!(status_response["workflow_id"], workflow_id);
    assert!(status_response["status"].is_string());
    assert!(status_response["created_at"].is_string());
}

#[tokio::test]
async fn test_get_receipt_endpoint() {
    let config = TemporalNotaryConfig::default();
    let server = NotaryRestServer::new(config).await.unwrap();
    let app = server.router();

    let workflow_id = "test-workflow-123";
    let response = app
        .oneshot(
            axum::http::Request::builder()
                .uri(&format!("/api/v1/workflows/{}/receipt", workflow_id))
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    
    let body = hyper::body::to_bytes(response.into_body()).await.unwrap();
    let receipt_response: serde_json::Value = serde_json::from_slice(&body).unwrap();
    
    assert!(receipt_response["evidence_package_hash"].is_string());
    assert!(receipt_response["rekor_log_id"].is_string());
    assert!(receipt_response["signature_b64"].is_string());
}

#[tokio::test]
async fn test_list_workflows_endpoint() {
    let config = TemporalNotaryConfig::default();
    let server = NotaryRestServer::new(config).await.unwrap();
    let app = server.router();

    let response = app
        .oneshot(
            axum::http::Request::builder()
                .uri("/api/v1/workflows")
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    
    let body = hyper::body::to_bytes(response.into_body()).await.unwrap();
    let list_response: serde_json::Value = serde_json::from_slice(&body).unwrap();
    
    assert!(list_response["workflows"].is_array());
    assert!(list_response["total_count"].is_number());
}

#[tokio::test]
async fn test_validate_evidence_endpoint() {
    let config = TemporalNotaryConfig::default();
    let server = NotaryRestServer::new(config).await.unwrap();
    let app = server.router();

    let validation_request = json!({
        "evidence_package": {
            "spec_version": "1.0.0",
            "timestamp_utc": "2025-07-23T10:00:00Z",
            "event_type": "test.validation",
            "actor": {
                "actor_type": "test_user",
                "id": "test@example.com"
            },
            "artifacts": [],
            "metadata": {}
        },
        "signature": "mock-signature"
    });

    let response = app
        .oneshot(
            axum::http::Request::builder()
                .uri("/api/v1/evidence/validate")
                .method("POST")
                .header("content-type", "application/json")
                .body(axum::body::Body::from(validation_request.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    
    let body = hyper::body::to_bytes(response.into_body()).await.unwrap();
    let validation_response: serde_json::Value = serde_json::from_slice(&body).unwrap();
    
    assert!(validation_response["is_valid"].is_boolean());
    assert!(validation_response["validation_result"].is_object());
}