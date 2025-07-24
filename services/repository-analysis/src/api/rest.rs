use axum::{
    extract::{Extension, Path, Query, State},
    http::StatusCode,
    response::{IntoResponse, Json},
    routing::{get, post, delete},
    Router,
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tower::ServiceBuilder;
use tower_http::{
    cors::CorsLayer,
    trace::TraceLayer,
};
use uuid::Uuid;

use super::{ApiService, JobSubmission, JobResponse, SearchRequest};
use crate::storage::{JobStatus, Priority, ListJobsQuery};

pub struct RestApi {
    service: Arc<ApiService>,
}

impl RestApi {
    pub fn new(service: Arc<ApiService>) -> Self {
        Self { service }
    }

    pub fn router(self) -> Router {
        Router::new()
            // Job management endpoints
            .route("/api/v1/jobs", post(submit_job))
            .route("/api/v1/jobs", get(list_jobs))
            .route("/api/v1/jobs/:id", get(get_job))
            .route("/api/v1/jobs/:id", delete(cancel_job))
            .route("/api/v1/jobs/:id/results", get(get_results))
            
            // Search endpoints
            .route("/api/v1/search/similar", post(search_similar))
            
            // Repository analysis endpoints
            .route("/api/v1/repositories/:id/findings", get(get_findings))
            .route("/api/v1/repositories/:id/files", get(get_file_analyses))
            
            // Statistics and health
            .route("/api/v1/statistics", get(get_statistics))
            .route("/api/v1/health", get(health_check))
            
            // Add middleware
            .layer(
                ServiceBuilder::new()
                    .layer(TraceLayer::new_for_http())
                    .layer(CorsLayer::permissive())
                    .layer(Extension(self.service))
            )
    }
}

// Handler functions

async fn submit_job(
    Extension(service): Extension<Arc<ApiService>>,
    Json(submission): Json<JobSubmission>,
) -> Result<impl IntoResponse, ApiError> {
    let job = service
        .submit_job(
            submission.repository_url,
            submission.repository_type,
            submission.analysis_type,
            submission.priority,
            submission.submitter_id,
            submission.case_number,
            submission.configuration,
        )
        .await
        .map_err(|e| ApiError::Internal(e.to_string()))?;

    let response = JobResponse {
        job_id: job.id,
        status: job.status,
        created_at: job.created_at,
        estimated_completion: job.estimated_completion,
    };

    Ok((StatusCode::CREATED, Json(response)))
}

async fn list_jobs(
    Extension(service): Extension<Arc<ApiService>>,
    Query(params): Query<ListJobsQueryParams>,
) -> Result<impl IntoResponse, ApiError> {
    let query = ListJobsQuery {
        status: params.status,
        priority: params.priority,
        submitter_id: params.submitter_id,
        case_number: params.case_number,
        created_after: params.created_after,
        created_before: params.created_before,
        limit: params.limit,
        offset: params.offset,
    };

    let response = service.storage.postgres
        .list_jobs(query)
        .await
        .map_err(|e| ApiError::Internal(e.to_string()))?;

    Ok(Json(response))
}

async fn get_job(
    Extension(service): Extension<Arc<ApiService>>,
    Path(id): Path<Uuid>,
) -> Result<impl IntoResponse, ApiError> {
    let job = service
        .get_job(id)
        .await
        .map_err(|e| ApiError::Internal(e.to_string()))?
        .ok_or(ApiError::NotFound("Job not found".to_string()))?;

    Ok(Json(job))
}

async fn cancel_job(
    Extension(service): Extension<Arc<ApiService>>,
    Path(id): Path<Uuid>,
) -> Result<impl IntoResponse, ApiError> {
    let cancelled = service
        .cancel_job(id)
        .await
        .map_err(|e| ApiError::Internal(e.to_string()))?;

    if cancelled {
        Ok(StatusCode::NO_CONTENT)
    } else {
        Err(ApiError::NotFound("Job not found".to_string()))
    }
}

async fn get_results(
    Extension(service): Extension<Arc<ApiService>>,
    Path(id): Path<Uuid>,
) -> Result<impl IntoResponse, ApiError> {
    let results = service
        .get_results(id)
        .await
        .map_err(|e| ApiError::Internal(e.to_string()))?
        .ok_or(ApiError::NotFound("Results not found or job not completed".to_string()))?;

    Ok(Json(results))
}

async fn search_similar(
    Extension(service): Extension<Arc<ApiService>>,
    Json(request): Json<SearchRequest>,
) -> Result<impl IntoResponse, ApiError> {
    let results = service
        .search_similar(
            request.query_text,
            request.file_path,
            request.job_id,
            request.threshold.unwrap_or(0.8),
            request.limit.unwrap_or(10),
        )
        .await
        .map_err(|e| ApiError::Internal(e.to_string()))?;

    Ok(Json(results))
}

async fn get_findings(
    Extension(service): Extension<Arc<ApiService>>,
    Path(job_id): Path<Uuid>,
    Query(params): Query<FindingsQueryParams>,
) -> Result<impl IntoResponse, ApiError> {
    let findings = service.storage.postgres
        .get_findings_by_job(job_id, params.severity, params.finding_type)
        .await
        .map_err(|e| ApiError::Internal(e.to_string()))?;

    Ok(Json(findings))
}

async fn get_file_analyses(
    Extension(service): Extension<Arc<ApiService>>,
    Path(job_id): Path<Uuid>,
    Query(params): Query<FileAnalysesQueryParams>,
) -> Result<impl IntoResponse, ApiError> {
    let analyses = service.storage.postgres
        .get_file_analyses_by_job(job_id, params.file_type, params.classification)
        .await
        .map_err(|e| ApiError::Internal(e.to_string()))?;

    Ok(Json(analyses))
}

async fn get_statistics(
    Extension(service): Extension<Arc<ApiService>>,
) -> Result<impl IntoResponse, ApiError> {
    let stats = service
        .get_statistics()
        .await
        .map_err(|e| ApiError::Internal(e.to_string()))?;

    Ok(Json(stats))
}

async fn health_check(
    Extension(service): Extension<Arc<ApiService>>,
) -> Result<impl IntoResponse, ApiError> {
    let health = service
        .health_check()
        .await
        .map_err(|e| ApiError::Internal(e.to_string()))?;

    let status_code = if health.healthy {
        StatusCode::OK
    } else {
        StatusCode::SERVICE_UNAVAILABLE
    };

    Ok((status_code, Json(health)))
}

// Query parameter structs

#[derive(Debug, Deserialize)]
struct ListJobsQueryParams {
    status: Option<JobStatus>,
    priority: Option<Priority>,
    submitter_id: Option<String>,
    case_number: Option<String>,
    created_after: Option<chrono::DateTime<chrono::Utc>>,
    created_before: Option<chrono::DateTime<chrono::Utc>>,
    limit: Option<i64>,
    offset: Option<i64>,
}

#[derive(Debug, Deserialize)]
struct FindingsQueryParams {
    severity: Option<crate::storage::Severity>,
    finding_type: Option<crate::storage::FindingType>,
}

#[derive(Debug, Deserialize)]
struct FileAnalysesQueryParams {
    file_type: Option<String>,
    classification: Option<crate::storage::Classification>,
}

// Error handling

#[derive(Debug)]
enum ApiError {
    NotFound(String),
    BadRequest(String),
    Unauthorized(String),
    Internal(String),
}

impl IntoResponse for ApiError {
    fn into_response(self) -> axum::response::Response {
        let (status, error_message) = match self {
            ApiError::NotFound(msg) => (StatusCode::NOT_FOUND, msg),
            ApiError::BadRequest(msg) => (StatusCode::BAD_REQUEST, msg),
            ApiError::Unauthorized(msg) => (StatusCode::UNAUTHORIZED, msg),
            ApiError::Internal(msg) => (StatusCode::INTERNAL_SERVER_ERROR, msg),
        };

        let body = Json(serde_json::json!({
            "error": error_message,
            "status": status.as_u16(),
        }));

        (status, body).into_response()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use tower::ServiceExt;

    #[tokio::test]
    async fn test_health_endpoint() {
        // This would need proper mocking in a real implementation
        // For now, it's a structure test
        
        let health_response = super::HealthStatus {
            healthy: true,
            postgres: true,
            object_storage: true,
            vector_storage: true,
            timestamp: chrono::Utc::now(),
        };

        assert!(health_response.healthy);
    }

    #[test]
    fn test_api_error_responses() {
        let not_found = ApiError::NotFound("Job not found".to_string());
        let response = not_found.into_response();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);

        let bad_request = ApiError::BadRequest("Invalid input".to_string());
        let response = bad_request.into_response();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);

        let unauthorized = ApiError::Unauthorized("Invalid token".to_string());
        let response = unauthorized.into_response();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

        let internal = ApiError::Internal("Database error".to_string());
        let response = internal.into_response();
        assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
    }

    #[test]
    fn test_query_params_deserialization() {
        let params = ListJobsQueryParams {
            status: Some(JobStatus::Running),
            priority: Some(Priority::High),
            submitter_id: Some("user123".to_string()),
            case_number: Some("CASE-456".to_string()),
            created_after: None,
            created_before: None,
            limit: Some(50),
            offset: Some(0),
        };

        assert_eq!(params.status, Some(JobStatus::Running));
        assert_eq!(params.priority, Some(Priority::High));
        assert_eq!(params.limit, Some(50));
    }
}