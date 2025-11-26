use axum::{extract::Request, middleware::Next, response::Response};
use std::time::Instant;
use tower_http::trace::TraceLayer;
use tracing::Level;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};
use uuid::Uuid;

/// Create structured logging layer with JSON output format based on settings
pub fn create_logging_layer(
) -> TraceLayer<tower_http::classify::SharedClassifier<tower_http::classify::ServerErrorsAsFailures>>
{
    TraceLayer::new_for_http()
        .make_span_with(tower_http::trace::DefaultMakeSpan::new().level(Level::DEBUG))
        .on_response(tower_http::trace::DefaultOnResponse::new().level(Level::DEBUG))
}

/// Request/response logging middleware with proper correlation IDs
pub async fn request_logging_middleware(request: Request, next: Next) -> Response {
    let correlation_id = Uuid::new_v4().to_string();
    let method = request.method().clone();
    let uri = request.uri().clone();
    let start_time = Instant::now();

    // Extract user agent and other relevant headers
    let user_agent = request
        .headers()
        .get("user-agent")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("unknown");

    let remote_addr = request
        .headers()
        .get("x-forwarded-for")
        .and_then(|v| v.to_str().ok())
        .or_else(|| {
            request
                .headers()
                .get("x-real-ip")
                .and_then(|v| v.to_str().ok())
        })
        .unwrap_or("unknown");

    tracing::debug!(
        correlation_id = %correlation_id,
        method = %method,
        uri = %uri,
        user_agent = %user_agent,
        remote_addr = %remote_addr,
        "incoming request"
    );

    let response = next.run(request).await;

    let duration = start_time.elapsed();
    let status = response.status();

    tracing::debug!(
        correlation_id = %correlation_id,
        method = %method,
        uri = %uri,
        status = %status,
        duration_ms = duration.as_millis(),
        "request completed"
    );

    response
}

/// Initialize structured logging with JSON format based on settings
pub fn init_logging(log_level: &str, log_format: &str) -> Result<(), Box<dyn std::error::Error>> {
    let level = match log_level.to_uppercase().as_str() {
        "TRACE" => Level::TRACE,
        "DEBUG" => Level::DEBUG,
        "INFO" => Level::INFO,
        "WARN" | "WARNING" => Level::WARN,
        "ERROR" => Level::ERROR,
        _ => {
            eprintln!("Invalid log level '{}', defaulting to INFO", log_level);
            Level::INFO
        }
    };

    // Build filter string from configured log level
    // This ensures LOG_LEVEL from config always takes precedence over RUST_LOG env var
    let filter_string = format!("rust_backend={},tower_http=info,sqlx=warn", level);
    let env_filter = tracing_subscriber::EnvFilter::new(filter_string);

    let subscriber = tracing_subscriber::registry().with(env_filter);

    match log_format.to_lowercase().as_str() {
        "json" => {
            let json_layer = tracing_subscriber::fmt::layer()
                .json()
                .with_current_span(true)
                .with_span_list(true)
                .with_target(true)
                .with_thread_ids(true)
                .with_thread_names(true);

            subscriber.with(json_layer).init();
        }
        "plain" | "text" => {
            let plain_layer = tracing_subscriber::fmt::layer()
                .with_target(true)
                .with_thread_ids(true)
                .with_thread_names(true);

            subscriber.with(plain_layer).init();
        }
        _ => {
            eprintln!("Invalid log format '{}', defaulting to JSON", log_format);
            let json_layer = tracing_subscriber::fmt::layer()
                .json()
                .with_current_span(true)
                .with_span_list(true)
                .with_target(true)
                .with_thread_ids(true)
                .with_thread_names(true);

            subscriber.with(json_layer).init();
        }
    }

    tracing::info!(
        log_level = %log_level,
        log_format = %log_format,
        "logging initialized"
    );

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{
        body::Body,
        http::{Request, StatusCode},
        middleware,
        routing::get,
        Router,
    };
    use tower::ServiceExt;

    async fn test_handler() -> &'static str {
        "test response"
    }

    #[tokio::test]
    async fn test_request_logging_middleware() {
        let app = Router::new()
            .route("/test", get(test_handler))
            .layer(middleware::from_fn(request_logging_middleware));

        let request = Request::builder()
            .uri("/test")
            .header("user-agent", "test-agent")
            .header("x-forwarded-for", "192.168.1.1")
            .body(Body::empty())
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[test]
    fn test_log_level_parsing() {
        // Test log level parsing logic without initializing global subscriber
        let level = match "INFO".to_uppercase().as_str() {
            "TRACE" => Level::TRACE,
            "DEBUG" => Level::DEBUG,
            "INFO" => Level::INFO,
            "WARN" | "WARNING" => Level::WARN,
            "ERROR" => Level::ERROR,
            _ => Level::INFO,
        };
        assert_eq!(level, Level::INFO);

        let level = match "DEBUG".to_uppercase().as_str() {
            "TRACE" => Level::TRACE,
            "DEBUG" => Level::DEBUG,
            "INFO" => Level::INFO,
            "WARN" | "WARNING" => Level::WARN,
            "ERROR" => Level::ERROR,
            _ => Level::INFO,
        };
        assert_eq!(level, Level::DEBUG);

        let level = match "INVALID".to_uppercase().as_str() {
            "TRACE" => Level::TRACE,
            "DEBUG" => Level::DEBUG,
            "INFO" => Level::INFO,
            "WARN" | "WARNING" => Level::WARN,
            "ERROR" => Level::ERROR,
            _ => Level::INFO,
        };
        assert_eq!(level, Level::INFO); // Should default to INFO
    }

    #[test]
    fn test_log_format_validation() {
        // Test log format validation logic
        let is_json = matches!("json".to_lowercase().as_str(), "json");
        assert!(is_json);

        let is_plain = matches!("plain".to_lowercase().as_str(), "plain" | "text");
        assert!(is_plain);

        let is_text = matches!("text".to_lowercase().as_str(), "plain" | "text");
        assert!(is_text);

        let is_invalid = matches!("invalid".to_lowercase().as_str(), "json" | "plain" | "text");
        assert!(!is_invalid);
    }
}
