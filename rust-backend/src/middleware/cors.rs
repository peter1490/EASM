use tower_http::cors::{CorsLayer, Any};
use axum::http::{Method, HeaderName};

/// Create CORS layer with configurable origins from settings
pub fn create_cors_layer(allowed_origins: Vec<String>) -> CorsLayer {
    let allowed_headers = vec![
        HeaderName::from_static("content-type"),
        HeaderName::from_static("authorization"),
        HeaderName::from_static("x-api-key"),
        HeaderName::from_static("x-requested-with"),
    ];

    if allowed_origins.is_empty() || allowed_origins.contains(&"*".to_string()) {
        // Development mode - allow all origins
        tracing::debug!("CORS: Allowing all origins (development mode)");
        CorsLayer::new()
            .allow_origin(Any)
            .allow_methods([
                Method::GET, 
                Method::POST, 
                Method::PUT, 
                Method::DELETE, 
                Method::PATCH,
                Method::OPTIONS
            ])
            .allow_headers(allowed_headers)
            .allow_credentials(false)
    } else {
        // Production mode - restrict origins
        let origins: Vec<_> = allowed_origins
            .iter()
            .filter_map(|origin| {
                match origin.parse() {
                    Ok(parsed) => {
                        tracing::debug!("CORS: Allowing origin: {}", origin);
                        Some(parsed)
                    }
                    Err(e) => {
                        tracing::warn!("CORS: Invalid origin '{}': {}", origin, e);
                        None
                    }
                }
            })
            .collect();
            
        if origins.is_empty() {
            tracing::warn!("CORS: No valid origins configured, falling back to permissive mode");
            CorsLayer::new()
                .allow_origin(Any)
                .allow_methods([
                    Method::GET, 
                    Method::POST, 
                    Method::PUT, 
                    Method::DELETE, 
                    Method::PATCH,
                    Method::OPTIONS
                ])
                .allow_headers(allowed_headers)
                .allow_credentials(false)
        } else {
            CorsLayer::new()
                .allow_origin(origins)
                .allow_methods([
                    Method::GET, 
                    Method::POST, 
                    Method::PUT, 
                    Method::DELETE, 
                    Method::PATCH,
                    Method::OPTIONS
                ])
                .allow_headers(allowed_headers)
                .allow_credentials(true)
        }
    }
}