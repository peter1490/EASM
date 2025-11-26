use axum::{
    extract::{Request, State},
    http::{HeaderMap, StatusCode},
    middleware::Next,
    response::Response,
};
use governor::{
    clock::{DefaultClock, QuantaClock},
    middleware::NoOpMiddleware,
    state::{InMemoryState, NotKeyed},
    Quota, RateLimiter,
};
use std::{net::IpAddr, num::NonZeroU32, sync::Arc, time::Duration};

use crate::config::Settings;

pub type AppRateLimiter = RateLimiter<NotKeyed, InMemoryState, DefaultClock, NoOpMiddleware>;

/// Create a rate limiter based on configuration
pub fn create_rate_limiter(settings: &Settings) -> AppRateLimiter {
    let requests_per_window = NonZeroU32::new(settings.rate_limit_requests)
        .unwrap_or_else(|| NonZeroU32::new(100).unwrap());

    let window_duration = Duration::from_secs(settings.rate_limit_window_seconds as u64);

    let quota = Quota::with_period(window_duration)
        .unwrap()
        .allow_burst(requests_per_window);

    RateLimiter::direct(quota)
}

/// Rate limiting middleware
pub async fn rate_limit_middleware(
    State(rate_limiter): State<Arc<AppRateLimiter>>,
    request: Request,
    next: Next,
) -> Result<Response, StatusCode> {
    // Check if rate limiting is enabled via the request (we'll add this to app state)
    match rate_limiter.check() {
        Ok(_) => {
            // Request is allowed
            let response = next.run(request).await;
            Ok(response)
        }
        Err(_) => {
            // Rate limit exceeded
            tracing::warn!("Rate limit exceeded");
            Err(StatusCode::TOO_MANY_REQUESTS)
        }
    }
}

/// IP-based rate limiting (more sophisticated)
pub struct IpRateLimiter {
    limiter: governor::RateLimiter<
        IpAddr,
        governor::state::keyed::DashMapStateStore<IpAddr>,
        QuantaClock,
        NoOpMiddleware,
    >,
}

impl IpRateLimiter {
    pub fn new(settings: &Settings) -> Self {
        let requests_per_window = NonZeroU32::new(settings.rate_limit_requests)
            .unwrap_or_else(|| NonZeroU32::new(100).unwrap());

        let window_duration = Duration::from_secs(settings.rate_limit_window_seconds as u64);

        let quota = Quota::with_period(window_duration)
            .unwrap()
            .allow_burst(requests_per_window);

        Self {
            limiter: RateLimiter::keyed(quota),
        }
    }

    pub fn check_ip(&self, ip: IpAddr) -> bool {
        self.limiter.check_key(&ip).is_ok()
    }
}

/// Extract client IP from request headers
fn extract_client_ip(headers: &HeaderMap) -> Option<IpAddr> {
    // Check X-Forwarded-For header first (for proxies)
    if let Some(forwarded) = headers.get("x-forwarded-for") {
        if let Ok(forwarded_str) = forwarded.to_str() {
            // Take the first IP in the chain
            if let Some(first_ip) = forwarded_str.split(',').next() {
                if let Ok(ip) = first_ip.trim().parse::<IpAddr>() {
                    return Some(ip);
                }
            }
        }
    }

    // Check X-Real-IP header
    if let Some(real_ip) = headers.get("x-real-ip") {
        if let Ok(ip_str) = real_ip.to_str() {
            if let Ok(ip) = ip_str.parse::<IpAddr>() {
                return Some(ip);
            }
        }
    }

    None
}

/// IP-based rate limiting middleware
pub async fn ip_rate_limit_middleware(
    State(ip_limiter): State<Arc<IpRateLimiter>>,
    request: Request,
    next: Next,
) -> Result<Response, StatusCode> {
    // Extract client IP
    let client_ip =
        extract_client_ip(request.headers()).unwrap_or_else(|| "127.0.0.1".parse().unwrap()); // Default to localhost

    // Check rate limit for this IP
    if ip_limiter.check_ip(client_ip) {
        let response = next.run(request).await;
        Ok(response)
    } else {
        tracing::warn!("Rate limit exceeded for IP: {}", client_ip);
        Err(StatusCode::TOO_MANY_REQUESTS)
    }
}

/// Performance monitoring middleware
pub async fn performance_middleware(request: Request, next: Next) -> Response {
    let start = std::time::Instant::now();
    let method = request.method().clone();
    let uri = request.uri().clone();

    let response = next.run(request).await;

    let duration = start.elapsed();
    let status = response.status();

    // Log slow requests
    if duration > Duration::from_millis(1000) {
        tracing::warn!(
            "Slow request: {} {} - {}ms - {}",
            method,
            uri,
            duration.as_millis(),
            status
        );
    } else {
        tracing::debug!(
            "Request: {} {} - {}ms - {}",
            method,
            uri,
            duration.as_millis(),
            status
        );
    }

    response
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
        "OK"
    }

    fn create_test_settings() -> Settings {
        let mut settings = Settings::new_with_env_file(false).unwrap();
        settings.rate_limit_enabled = true;
        settings.rate_limit_requests = 2; // Very low for testing
        settings.rate_limit_window_seconds = 1;
        settings
    }

    #[tokio::test]
    async fn test_rate_limiter_creation() {
        let settings = create_test_settings();
        let limiter = create_rate_limiter(&settings);

        // First request should succeed
        assert!(limiter.check().is_ok());

        // Second request should succeed
        assert!(limiter.check().is_ok());

        // Third request should fail (rate limited)
        assert!(limiter.check().is_err());
    }

    #[tokio::test]
    async fn test_ip_rate_limiter() {
        let settings = create_test_settings();
        let limiter = IpRateLimiter::new(&settings);

        let ip1: IpAddr = "192.168.1.1".parse().unwrap();
        let ip2: IpAddr = "192.168.1.2".parse().unwrap();

        // First IP should be allowed
        assert!(limiter.check_ip(ip1));
        assert!(limiter.check_ip(ip1));
        assert!(!limiter.check_ip(ip1)); // Third request fails

        // Second IP should still be allowed
        assert!(limiter.check_ip(ip2));
        assert!(limiter.check_ip(ip2));
        assert!(!limiter.check_ip(ip2)); // Third request fails
    }

    #[tokio::test]
    async fn test_extract_client_ip() {
        let mut headers = HeaderMap::new();

        // Test X-Forwarded-For header
        headers.insert("x-forwarded-for", "192.168.1.1, 10.0.0.1".parse().unwrap());
        let ip = extract_client_ip(&headers);
        assert_eq!(ip, Some("192.168.1.1".parse().unwrap()));

        // Test X-Real-IP header
        headers.clear();
        headers.insert("x-real-ip", "192.168.1.2".parse().unwrap());
        let ip = extract_client_ip(&headers);
        assert_eq!(ip, Some("192.168.1.2".parse().unwrap()));

        // Test no headers
        headers.clear();
        let ip = extract_client_ip(&headers);
        assert_eq!(ip, None);
    }

    #[tokio::test]
    async fn test_rate_limit_middleware_integration() {
        let settings = create_test_settings();
        let limiter = Arc::new(create_rate_limiter(&settings));

        let app = Router::new()
            .route("/test", get(test_handler))
            .layer(middleware::from_fn_with_state(
                limiter.clone(),
                rate_limit_middleware,
            ))
            .with_state(limiter);

        // First request should succeed
        let request = Request::builder().uri("/test").body(Body::empty()).unwrap();
        let response = app.clone().oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        // Second request should succeed
        let request = Request::builder().uri("/test").body(Body::empty()).unwrap();
        let response = app.clone().oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        // Third request should be rate limited
        let request = Request::builder().uri("/test").body(Body::empty()).unwrap();
        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
    }
}
