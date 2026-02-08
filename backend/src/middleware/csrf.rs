use axum::{
    extract::Request,
    http::{header::COOKIE, Method, StatusCode},
    middleware::Next,
    response::Response,
};

use crate::auth::context::UserContext;

fn extract_cookie_value(headers: &axum::http::HeaderMap, name: &str) -> Option<String> {
    let raw = headers.get(COOKIE)?.to_str().ok()?;
    for part in raw.split(';') {
        let mut iter = part.trim().splitn(2, '=');
        let key = iter.next()?.trim();
        if key == name {
            return Some(iter.next()?.trim().to_string());
        }
    }
    None
}

/// CSRF middleware: validates X-CSRF-Token header against csrf_token cookie
/// for state-changing requests using session-based auth.
pub async fn csrf_middleware(request: Request, next: Next) -> Result<Response, StatusCode> {
    let method = request.method();
    if matches!(method, &Method::GET | &Method::HEAD | &Method::OPTIONS) {
        return Ok(next.run(request).await);
    }

    let user = request.extensions().get::<UserContext>().cloned();
    if let Some(user) = user {
        if user.is_api_key {
            return Ok(next.run(request).await);
        }
    } else {
        return Err(StatusCode::UNAUTHORIZED);
    }

    let header_token = request
        .headers()
        .get("x-csrf-token")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());
    let cookie_token = extract_cookie_value(request.headers(), "csrf_token");

    match (header_token, cookie_token) {
        (Some(header_val), Some(cookie_val)) if header_val == cookie_val => {
            Ok(next.run(request).await)
        }
        _ => Err(StatusCode::FORBIDDEN),
    }
}
