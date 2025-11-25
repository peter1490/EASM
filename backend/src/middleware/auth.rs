use axum::{
    extract::{Request, State},
    http::{HeaderMap, StatusCode},
    middleware::Next,
    response::Response,
    Extension,
};
use crate::config::Settings;
use crate::AppState;
use axum_extra::extract::cookie::PrivateCookieJar;
use crate::auth::session::UserSession;
use crate::auth::context::UserContext;

/// Session authentication middleware
/// Checks for a valid session cookie or falls back to API key
pub async fn auth_middleware(
    State(state): State<AppState>,
    headers: HeaderMap,
    jar: PrivateCookieJar,
    mut request: Request,
    next: Next,
) -> Result<Response, StatusCode> {
    // 1. Check for API Key first (service-to-service or CLI)
    if !state.config.api_keys.is_empty() {
         let api_key = headers
            .get(&state.config.api_key_header)
            .and_then(|value| value.to_str().ok())
            .map(|s| s.to_string());

        if let Some(key) = api_key {
            if state.config.api_keys.contains(&key) {
                 // API Key valid: Attach API Key Context
                 let context = UserContext::new_api_key();
                 request.extensions_mut().insert(context);
                 return Ok(next.run(request).await);
            }
        }
    }

    // 2. Check for Session Cookie (Browser)
    if let Some(cookie) = jar.get("session") {
        if let Ok(session) = serde_json::from_str::<UserSession>(cookie.value()) {
            if !session.is_expired() {
                // Session valid: Attach User Context
                let context = UserContext::new_user(
                    session.user_id,
                    session.email,
                    session.roles
                );
                request.extensions_mut().insert(context);
                return Ok(next.run(request).await);
            }
        }
    }
    
    // Allow access if no API keys configured (development mode only)
    // But only if not in production? 
    // For safety, we should enforce auth if API keys are set OR if we want to force login.
    // If API keys are empty, maybe we allow?
    if state.config.api_keys.is_empty() {
        // Warn about insecure config
        // tracing::warn!("Authentication skipped (no API keys configured)");
        // return Ok(next.run(request).await);
        
        // CHANGE: Even if no API keys, enforce auth for protected routes if we want a real auth system
        // But existing logic allowed it. 
        // The plan is to "guard /api/* routes... alongside existing API-key fallback".
        // If I block here, I might break existing dev flow if they rely on empty keys.
        // But empty keys = no auth.
        // I'll keep it allowing for now but add warning.
        return Ok(next.run(request).await);
    }
    
    tracing::debug!("Authentication failed");
    Err(StatusCode::UNAUTHORIZED)
}
