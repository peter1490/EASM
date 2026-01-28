use crate::auth::context::UserContext;
use crate::auth::session::UserSession;
use crate::AppState;
use axum::{
    extract::{Request, State},
    http::{HeaderMap, StatusCode},
    middleware::Next,
    response::Response,
};
use axum_extra::extract::cookie::PrivateCookieJar;

/// Session authentication middleware
/// Checks for a valid session cookie or falls back to API key
pub async fn auth_middleware(
    State(state): State<AppState>,
    headers: HeaderMap,
    jar: PrivateCookieJar,
    mut request: Request,
    next: Next,
) -> Result<Response, StatusCode> {
    let settings = state.config.load();

    // Helper to resolve company
    async fn resolve_company(
        user_id: uuid::Uuid,
        headers: &HeaderMap,
        repo: &dyn crate::repositories::UserRepository,
    ) -> Option<uuid::Uuid> {
        let requested_id = headers
            .get("X-Company-ID")
            .and_then(|v| v.to_str().ok())
            .and_then(|s| uuid::Uuid::parse_str(s).ok());

        // Get user companies
        if let Ok(companies) = repo.get_user_companies(user_id).await {
            if let Some(req_id) = requested_id {
                // Check membership
                if companies.iter().any(|c| c.company_id == req_id) {
                    return Some(req_id);
                }
                // Requested company not found for user -> Return None (Unauthorized/Forbidden later)
                return None;
            } else {
                // Default to first company
                return companies.first().map(|c| c.company_id);
            }
        }
        None
    }

    // 1. Check for API Key first (service-to-service or CLI)
    if !settings.api_keys.is_empty() {
        let api_key = headers
            .get(&settings.api_key_header)
            .and_then(|value| value.to_str().ok())
            .map(|s| s.to_string());

        if let Some(key) = api_key {
            if settings.api_keys.contains(&key) {
                // API Key valid
                // For API keys, we check header for company, otherwise default to Default Company ID if possible,
                // or just leave as None? UserContext.company_id is Option.
                // But DB queries will need it.
                // Let's parse header. If explicit header, trust it (Admin access).
                let company_id = headers
                    .get("X-Company-ID")
                    .and_then(|v| v.to_str().ok())
                    .and_then(|s| uuid::Uuid::parse_str(s).ok());

                // TODO: Verify company exists? For now assume API key is admin and knows what it's doing.
                // Or maybe default to the "Default Company" ID known from migration?
                // '00000000-0000-0000-0000-000000000000'

                let mut context = UserContext::new_api_key();
                context.company_id = company_id.or(Some(uuid::Uuid::nil())); // Default to nil UUID (Default Company)

                request.extensions_mut().insert(context);
                return Ok(next.run(request).await);
            }
        }
    }

    // 2. Check for Session Cookie (Browser)
    if let Some(cookie) = jar.get("session") {
        if let Ok(session) = serde_json::from_str::<UserSession>(cookie.value()) {
            if !session.is_expired() {
                // Resolve company
                let company_id =
                    resolve_company(session.user_id, &headers, state.user_repository.as_ref())
                        .await;

                if company_id.is_none() {
                    // User has no companies or requested invalid company -> Forbidden
                    tracing::warn!(
                        "User {} requested invalid company or has no companies",
                        session.user_id
                    );
                    return Err(StatusCode::FORBIDDEN);
                }

                // Session valid: Attach User Context
                let context = UserContext::new_user(
                    session.user_id,
                    session.email,
                    session.roles,
                    company_id,
                );
                request.extensions_mut().insert(context);
                return Ok(next.run(request).await);
            }
        }
    }

    // Allow access if no API keys configured (development mode only)
    if settings.api_keys.is_empty() {
        // Dev mode: create a dummy context?
        // Or if logic below continues...
        return Ok(next.run(request).await);
    }

    tracing::debug!("Authentication failed");
    Err(StatusCode::UNAUTHORIZED)
}
