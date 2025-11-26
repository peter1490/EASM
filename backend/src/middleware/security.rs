use axum::{
    extract::Request,
    http::{HeaderName, HeaderValue},
    middleware::Next,
    response::Response,
};
use std::collections::HashMap;

/// Security headers middleware for content-type protection and other security measures
pub async fn security_headers_middleware(request: Request, next: Next) -> Response {
    let mut response = next.run(request).await;

    // Get security headers from config
    let security_headers = get_security_headers();

    // Add security headers to response
    let headers = response.headers_mut();
    for (name, value) in security_headers {
        if let (Ok(header_name), Ok(header_value)) =
            (HeaderName::try_from(name), HeaderValue::try_from(value))
        {
            headers.insert(header_name, header_value);
        } else {
            tracing::warn!("Failed to add security header: {} = {}", name, value);
        }
    }

    response
}

/// Get security headers configuration (matches Python backend)
fn get_security_headers() -> HashMap<&'static str, &'static str> {
    let mut headers = HashMap::new();

    // Prevent MIME type sniffing
    headers.insert("X-Content-Type-Options", "nosniff");

    // Prevent clickjacking
    headers.insert("X-Frame-Options", "DENY");

    // Enable XSS protection
    headers.insert("X-XSS-Protection", "1; mode=block");

    // Control referrer information
    headers.insert("Referrer-Policy", "strict-origin-when-cross-origin");

    // Content Security Policy (basic)
    headers.insert(
        "Content-Security-Policy",
        "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'",
    );

    // Strict Transport Security (HTTPS only)
    headers.insert(
        "Strict-Transport-Security",
        "max-age=31536000; includeSubDomains",
    );

    // Permissions Policy (formerly Feature Policy)
    headers.insert(
        "Permissions-Policy",
        "geolocation=(), microphone=(), camera=()",
    );

    headers
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
    async fn test_security_headers_middleware() {
        let app = Router::new()
            .route("/test", get(test_handler))
            .layer(middleware::from_fn(security_headers_middleware));

        let request = Request::builder().uri("/test").body(Body::empty()).unwrap();

        let response = app.oneshot(request).await.unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        let headers = response.headers();
        assert_eq!(headers.get("X-Content-Type-Options").unwrap(), "nosniff");
        assert_eq!(headers.get("X-Frame-Options").unwrap(), "DENY");
        assert_eq!(headers.get("X-XSS-Protection").unwrap(), "1; mode=block");
        assert_eq!(
            headers.get("Referrer-Policy").unwrap(),
            "strict-origin-when-cross-origin"
        );
        assert!(headers.contains_key("Content-Security-Policy"));
        assert!(headers.contains_key("Strict-Transport-Security"));
        assert!(headers.contains_key("Permissions-Policy"));
    }

    #[test]
    fn test_get_security_headers() {
        let headers = get_security_headers();

        assert!(!headers.is_empty());
        assert_eq!(headers.get("X-Content-Type-Options"), Some(&"nosniff"));
        assert_eq!(headers.get("X-Frame-Options"), Some(&"DENY"));
        assert_eq!(headers.get("X-XSS-Protection"), Some(&"1; mode=block"));
        assert_eq!(
            headers.get("Referrer-Policy"),
            Some(&"strict-origin-when-cross-origin")
        );
    }
}
