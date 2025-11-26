use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use serde_json::json;
use uuid::Uuid;

#[derive(Debug, thiserror::Error)]
pub enum ApiError {
    #[error("Database error: {0}")]
    Database(#[from] sqlx::Error),

    #[error("External service error: {0}")]
    ExternalService(String),

    #[error("Validation error: {0}")]
    Validation(String),

    #[error("Not found: {0}")]
    NotFound(String),

    #[error("Configuration error: {0}")]
    Config(#[from] config::ConfigError),

    #[error("Configuration error: {0}")]
    Configuration(String),

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Serialization error: {0}")]
    Serialization(#[from] serde_json::Error),

    #[error("HTTP client error: {0}")]
    HttpClient(#[from] reqwest::Error),

    #[error("Migration error: {0}")]
    Migration(#[from] sqlx::migrate::MigrateError),

    #[error("Authentication error: {0}")]
    Authentication(String),

    #[error("Authorization error: {0}")]
    Authorization(String),

    #[error("Rate limit exceeded: {0}")]
    RateLimit(String),

    #[error("Timeout error: {0}")]
    Timeout(String),

    #[error("Conflict error: {0}")]
    Conflict(String),

    #[error("Internal server error: {0}")]
    Internal(String),

    #[error("Unknown error: {0}")]
    Anyhow(#[from] anyhow::Error),
}

impl ApiError {
    /// Create a new validation error
    pub fn validation<T: Into<String>>(msg: T) -> Self {
        Self::Validation(msg.into())
    }

    /// Create a new not found error
    pub fn not_found<T: Into<String>>(msg: T) -> Self {
        Self::NotFound(msg.into())
    }

    /// Create a new internal error
    pub fn internal<T: Into<String>>(msg: T) -> Self {
        Self::Internal(msg.into())
    }

    /// Create a new external service error
    pub fn external_service<T: Into<String>>(msg: T) -> Self {
        Self::ExternalService(msg.into())
    }

    /// Create a new authentication error
    pub fn authentication<T: Into<String>>(msg: T) -> Self {
        Self::Authentication(msg.into())
    }

    /// Create a new authorization error
    pub fn authorization<T: Into<String>>(msg: T) -> Self {
        Self::Authorization(msg.into())
    }

    /// Create a new rate limit error
    pub fn rate_limit<T: Into<String>>(msg: T) -> Self {
        Self::RateLimit(msg.into())
    }

    /// Create a new timeout error
    pub fn timeout<T: Into<String>>(msg: T) -> Self {
        Self::Timeout(msg.into())
    }

    /// Create a new conflict error
    pub fn conflict<T: Into<String>>(msg: T) -> Self {
        Self::Conflict(msg.into())
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let error_id = Uuid::new_v4();

        let (status, error_message, error_code) = match self {
            ApiError::Database(ref err) => {
                tracing::error!(
                    error_id = %error_id,
                    error = %err,
                    "database error occurred"
                );
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "Database error",
                    "DATABASE_ERROR",
                )
            }
            ApiError::ExternalService(ref msg) => {
                tracing::error!(
                    error_id = %error_id,
                    error = %msg,
                    "external service error occurred"
                );
                (
                    StatusCode::BAD_GATEWAY,
                    msg.as_str(),
                    "EXTERNAL_SERVICE_ERROR",
                )
            }
            ApiError::Validation(ref msg) => {
                tracing::warn!(
                    error_id = %error_id,
                    error = %msg,
                    "validation error occurred"
                );
                (StatusCode::BAD_REQUEST, msg.as_str(), "VALIDATION_ERROR")
            }
            ApiError::NotFound(ref msg) => {
                tracing::info!(
                    error_id = %error_id,
                    error = %msg,
                    "resource not found"
                );
                (StatusCode::NOT_FOUND, msg.as_str(), "NOT_FOUND")
            }
            ApiError::Config(ref err) => {
                tracing::error!(
                    error_id = %error_id,
                    error = %err,
                    "configuration error occurred"
                );
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "Configuration error",
                    "CONFIG_ERROR",
                )
            }
            ApiError::Configuration(ref msg) => {
                tracing::error!(
                    error_id = %error_id,
                    error = %msg,
                    "configuration error occurred"
                );
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    msg.as_str(),
                    "CONFIG_ERROR",
                )
            }
            ApiError::Io(ref err) => {
                tracing::error!(
                    error_id = %error_id,
                    error = %err,
                    "IO error occurred"
                );
                (StatusCode::INTERNAL_SERVER_ERROR, "IO error", "IO_ERROR")
            }
            ApiError::Serialization(ref err) => {
                tracing::error!(
                    error_id = %error_id,
                    error = %err,
                    "serialization error occurred"
                );
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "Serialization error",
                    "SERIALIZATION_ERROR",
                )
            }
            ApiError::HttpClient(ref err) => {
                tracing::error!(
                    error_id = %error_id,
                    error = %err,
                    "HTTP client error occurred"
                );
                (
                    StatusCode::BAD_GATEWAY,
                    "External service unavailable",
                    "HTTP_CLIENT_ERROR",
                )
            }
            ApiError::Migration(ref err) => {
                tracing::error!(
                    error_id = %error_id,
                    error = %err,
                    "database migration error occurred"
                );
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "Database migration error",
                    "MIGRATION_ERROR",
                )
            }
            ApiError::Authentication(ref msg) => {
                tracing::warn!(
                    error_id = %error_id,
                    error = %msg,
                    "authentication error occurred"
                );
                (
                    StatusCode::UNAUTHORIZED,
                    msg.as_str(),
                    "AUTHENTICATION_ERROR",
                )
            }
            ApiError::Authorization(ref msg) => {
                tracing::warn!(
                    error_id = %error_id,
                    error = %msg,
                    "authorization error occurred"
                );
                (StatusCode::FORBIDDEN, msg.as_str(), "AUTHORIZATION_ERROR")
            }
            ApiError::RateLimit(ref msg) => {
                tracing::warn!(
                    error_id = %error_id,
                    error = %msg,
                    "rate limit exceeded"
                );
                (
                    StatusCode::TOO_MANY_REQUESTS,
                    msg.as_str(),
                    "RATE_LIMIT_EXCEEDED",
                )
            }
            ApiError::Timeout(ref msg) => {
                tracing::warn!(
                    error_id = %error_id,
                    error = %msg,
                    "timeout error occurred"
                );
                (StatusCode::REQUEST_TIMEOUT, msg.as_str(), "TIMEOUT_ERROR")
            }
            ApiError::Conflict(ref msg) => {
                tracing::warn!(
                    error_id = %error_id,
                    error = %msg,
                    "conflict error occurred"
                );
                (StatusCode::CONFLICT, msg.as_str(), "CONFLICT_ERROR")
            }
            ApiError::Internal(ref msg) => {
                tracing::error!(
                    error_id = %error_id,
                    error = %msg,
                    "internal server error occurred"
                );
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    msg.as_str(),
                    "INTERNAL_ERROR",
                )
            }
            ApiError::Anyhow(ref err) => {
                tracing::error!(
                    error_id = %error_id,
                    error = %err,
                    "unexpected error occurred"
                );
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "Internal server error",
                    "INTERNAL_ERROR",
                )
            }
        };

        let body = Json(json!({
            "error": {
                "message": error_message,
                "code": error_code,
                "error_id": error_id,
                "timestamp": chrono::Utc::now().to_rfc3339(),
            }
        }));

        (status, body).into_response()
    }
}

/// Result type alias for API operations
pub type ApiResult<T> = Result<T, ApiError>;

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{
        body::Body,
        http::{Request, StatusCode},
        routing::get,
        Router,
    };
    use tower::ServiceExt;

    async fn test_error_handler() -> Result<&'static str, ApiError> {
        Err(ApiError::validation("Test validation error"))
    }

    async fn test_not_found_handler() -> Result<&'static str, ApiError> {
        Err(ApiError::not_found("Resource not found"))
    }

    async fn test_internal_error_handler() -> Result<&'static str, ApiError> {
        Err(ApiError::internal("Internal server error"))
    }

    #[tokio::test]
    async fn test_validation_error_response() {
        let app = Router::new().route("/test", get(test_error_handler));

        let request = Request::builder().uri("/test").body(Body::empty()).unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn test_not_found_error_response() {
        let app = Router::new().route("/test", get(test_not_found_handler));

        let request = Request::builder().uri("/test").body(Body::empty()).unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn test_internal_error_response() {
        let app = Router::new().route("/test", get(test_internal_error_handler));

        let request = Request::builder().uri("/test").body(Body::empty()).unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
    }

    #[test]
    fn test_error_constructors() {
        let validation_err = ApiError::validation("test");
        assert!(matches!(validation_err, ApiError::Validation(_)));

        let not_found_err = ApiError::not_found("test");
        assert!(matches!(not_found_err, ApiError::NotFound(_)));

        let internal_err = ApiError::internal("test");
        assert!(matches!(internal_err, ApiError::Internal(_)));

        let external_err = ApiError::external_service("test");
        assert!(matches!(external_err, ApiError::ExternalService(_)));

        let auth_err = ApiError::authentication("test");
        assert!(matches!(auth_err, ApiError::Authentication(_)));

        let authz_err = ApiError::authorization("test");
        assert!(matches!(authz_err, ApiError::Authorization(_)));

        let rate_limit_err = ApiError::rate_limit("test");
        assert!(matches!(rate_limit_err, ApiError::RateLimit(_)));

        let timeout_err = ApiError::timeout("test");
        assert!(matches!(timeout_err, ApiError::Timeout(_)));

        let conflict_err = ApiError::conflict("test");
        assert!(matches!(conflict_err, ApiError::Conflict(_)));
    }
}
