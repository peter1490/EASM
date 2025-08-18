use axum::{
    extract::{Request, State},
    http::{HeaderMap, StatusCode},
    middleware::Next,
    response::Response,
};
use crate::config::Settings;

/// API key authentication middleware using configuration
pub async fn api_key_auth_middleware(
    State(settings): State<Settings>,
    headers: HeaderMap,
    request: Request,
    next: Next,
) -> Result<Response, StatusCode> {
    // Skip authentication if no API keys are configured
    if settings.api_keys.is_empty() {
        tracing::debug!("API key authentication disabled - no keys configured");
        return Ok(next.run(request).await);
    }

    // Get API key from header
    let api_key = headers
        .get(&settings.api_key_header)
        .and_then(|value| value.to_str().ok())
        .map(|s| s.to_string());

    match api_key {
        Some(key) if settings.api_keys.contains(&key) => {
            tracing::debug!("API key authentication successful");
            Ok(next.run(request).await)
        }
        Some(_) => {
            tracing::warn!("API key authentication failed - invalid key");
            Err(StatusCode::UNAUTHORIZED)
        }
        None => {
            tracing::warn!("API key authentication failed - missing header: {}", settings.api_key_header);
            Err(StatusCode::UNAUTHORIZED)
        }
    }
}

/// Create API key authentication middleware with settings
pub fn create_api_key_middleware(settings: Settings) -> impl Fn(HeaderMap, Request, Next) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<Response, StatusCode>> + Send>> + Clone {
    move |headers: HeaderMap, request: Request, next: Next| {
        let settings = settings.clone();
        Box::pin(async move {
            api_key_auth_with_settings(settings, headers, request, next).await
        })
    }
}

/// API key authentication with settings parameter
async fn api_key_auth_with_settings(
    settings: Settings,
    headers: HeaderMap,
    request: Request,
    next: Next,
) -> Result<Response, StatusCode> {
    // Skip authentication if no API keys are configured
    if settings.api_keys.is_empty() {
        tracing::debug!("API key authentication disabled - no keys configured");
        return Ok(next.run(request).await);
    }

    // Get API key from header
    let api_key = headers
        .get(&settings.api_key_header)
        .and_then(|value| value.to_str().ok())
        .map(|s| s.to_string());

    match api_key {
        Some(key) if settings.api_keys.contains(&key) => {
            tracing::debug!("API key authentication successful");
            Ok(next.run(request).await)
        }
        Some(_) => {
            tracing::warn!("API key authentication failed - invalid key");
            Err(StatusCode::UNAUTHORIZED)
        }
        None => {
            tracing::warn!("API key authentication failed - missing header: {}", settings.api_key_header);
            Err(StatusCode::UNAUTHORIZED)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{
        body::Body,
        http::{Request, HeaderValue},
        middleware,
        routing::get,
        Router,
    };
    use tower::ServiceExt;

    async fn test_handler() -> &'static str {
        "authenticated"
    }

    fn create_test_settings(api_keys: Vec<String>) -> Settings {
        let mut settings = Settings::new_with_env_file(false).unwrap();
        settings.api_keys = api_keys;
        settings
    }

    #[tokio::test]
    async fn test_api_key_auth_success() {
        let settings = create_test_settings(vec!["valid-key".to_string()]);
        
        let app = Router::new()
            .route("/test", get(test_handler))
            .layer(middleware::from_fn_with_state(settings, api_key_auth_middleware));

        let request = Request::builder()
            .uri("/test")
            .header("X-API-Key", "valid-key")
            .body(Body::empty())
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_api_key_auth_invalid_key() {
        let settings = create_test_settings(vec!["valid-key".to_string()]);
        
        let app = Router::new()
            .route("/test", get(test_handler))
            .layer(middleware::from_fn_with_state(settings, api_key_auth_middleware));

        let request = Request::builder()
            .uri("/test")
            .header("X-API-Key", "invalid-key")
            .body(Body::empty())
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn test_api_key_auth_missing_header() {
        let settings = create_test_settings(vec!["valid-key".to_string()]);
        
        let app = Router::new()
            .route("/test", get(test_handler))
            .layer(middleware::from_fn_with_state(settings, api_key_auth_middleware));

        let request = Request::builder()
            .uri("/test")
            .body(Body::empty())
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn test_api_key_auth_disabled() {
        let settings = create_test_settings(vec![]); // No API keys configured
        
        let app = Router::new()
            .route("/test", get(test_handler))
            .layer(middleware::from_fn_with_state(settings, api_key_auth_middleware));

        let request = Request::builder()
            .uri("/test")
            .body(Body::empty())
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }
}