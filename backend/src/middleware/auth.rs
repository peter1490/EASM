use crate::auth::context::UserContext;
use crate::middleware::rate_limit::extract_client_ip;
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
    if let Some(api_key) = headers
        .get(&settings.api_key_header)
        .and_then(|value| value.to_str().ok())
        .map(|s| s.to_string())
    {
        if settings.api_keys.is_empty() {
            tracing::warn!("API key provided but no API keys configured");
            return Err(StatusCode::UNAUTHORIZED);
        }

        let matching_scope = settings
            .api_keys
            .iter()
            .find(|scope| scope.matches(&api_key));

        if let Some(scope) = matching_scope {
            if !settings.api_key_ip_allowlist.is_empty() {
                let client_ip = extract_client_ip(&headers);
                let ip_allowed = client_ip
                    .map(|ip| settings.api_key_ip_allowlist.iter().any(|net| net.contains(&ip)))
                    .unwrap_or(false);
                if !ip_allowed {
                    tracing::warn!(
                        api_key_id = %scope.key_id(),
                        "API key request denied by IP allowlist"
                    );
                    return Err(StatusCode::FORBIDDEN);
                }
            }

            let requested_company_id = headers
                .get("X-Company-ID")
                .and_then(|v| v.to_str().ok())
                .and_then(|s| uuid::Uuid::parse_str(s).ok());

            let company_id = match requested_company_id {
                Some(requested) if scope.allow_company_override => Some(requested),
                Some(requested) if requested == scope.company_id => Some(requested),
                Some(_) => {
                    tracing::warn!(
                        api_key_id = %scope.key_id(),
                        "API key attempted unauthorized company override"
                    );
                    return Err(StatusCode::FORBIDDEN);
                }
                None => Some(scope.company_id),
            };

            let context = UserContext::new_api_key(
                scope.role.clone(),
                company_id,
                Some(scope.key_id()),
            );
            request.extensions_mut().insert(context);
            return Ok(next.run(request).await);
        }

        tracing::warn!("Invalid API key presented");
        return Err(StatusCode::UNAUTHORIZED);
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

    // Allow access if explicitly enabled (development mode only)
    if settings.allow_anonymous {
        let context = UserContext::new_api_key(
            crate::auth::rbac::Role::Viewer,
            Some(uuid::Uuid::nil()),
            Some("anon".to_string()),
        );
        request.extensions_mut().insert(context);
        return Ok(next.run(request).await);
    }

    tracing::debug!("Authentication failed");
    Err(StatusCode::UNAUTHORIZED)
}
