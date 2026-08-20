use crate::auth::context::UserContext;
use crate::auth::session::UserSession;
use crate::middleware::rate_limit::extract_client_ip;
use crate::AppState;
use axum::{
    extract::{Request, State},
    http::{HeaderMap, StatusCode},
    middleware::Next,
    response::Response,
};
use axum_extra::extract::cookie::PrivateCookieJar;

/// Fold the active company's membership role into the request's role set.
///
/// `user_roles` — the table the session is built from — holds *global*
/// roles, and migration 025 moved every row in it to `global_admin`. Day to
/// day access is granted per company in `user_companies`, which nothing
/// outside `require_company_admin` ever read. The result was that every
/// `has_role(Role::Analyst | Operator | Admin)` gate in the codebase —
/// finding triage, asset importance and comments, tagging, the blacklist,
/// risk recalculation, search reindex — answered 403 for everyone except a
/// global admin, however the company had been set up.
///
/// The company role is merged here so those gates mean what the membership
/// UI says they mean. `global_admin` is deliberately not reachable this
/// way: it is a system role, and `user_companies.role` is a plain VARCHAR.
fn merge_company_role(roles: &mut Vec<crate::auth::rbac::Role>, company_role: Option<&str>) {
    let Some(parsed) = company_role.and_then(crate::auth::rbac::Role::from_str) else {
        return;
    };
    if parsed == crate::auth::rbac::Role::GlobalAdmin {
        tracing::warn!(
            role = %company_role.unwrap_or_default(),
            "Ignoring company membership row claiming a global role"
        );
        return;
    }
    if !roles.contains(&parsed) {
        roles.push(parsed);
    }
}

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

    // Resolution outcomes for the active company on a request. `Resolved` also
    // carries the role the user holds *in that company* — see `merge_company_role`.
    enum CompanyResolution {
        Resolved(uuid::Uuid, Option<String>),
        NoMembership, // User exists but belongs to no company → pass through with no company.
        Forbidden,    // User explicitly requested a company they don't belong to.
    }

    async fn resolve_company(
        user_id: uuid::Uuid,
        headers: &HeaderMap,
        repo: &dyn crate::repositories::UserRepository,
    ) -> CompanyResolution {
        let requested_id = headers
            .get("X-Company-ID")
            .and_then(|v| v.to_str().ok())
            .and_then(|s| uuid::Uuid::parse_str(s).ok());

        let companies = match repo.get_user_companies(user_id).await {
            Ok(c) => c,
            Err(_) => return CompanyResolution::NoMembership,
        };

        if companies.is_empty() {
            // No memberships yet — don't lock the user out. They authenticate but can't
            // hit company-scoped endpoints until an admin grants them access.
            return CompanyResolution::NoMembership;
        }

        if let Some(req_id) = requested_id {
            match companies.iter().find(|c| c.company_id == req_id) {
                Some(membership) => {
                    CompanyResolution::Resolved(req_id, Some(membership.role.clone()))
                }
                None => CompanyResolution::Forbidden,
            }
        } else {
            // No header — default to first company.
            CompanyResolution::Resolved(companies[0].company_id, Some(companies[0].role.clone()))
        }
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
                    .map(|ip| {
                        settings
                            .api_key_ip_allowlist
                            .iter()
                            .any(|net| net.contains(&ip))
                    })
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

            let context =
                UserContext::new_api_key(scope.role.clone(), company_id, Some(scope.key_id()));
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
                let (company_id, company_role) = match resolve_company(
                    session.user_id,
                    &headers,
                    state.user_repository.as_ref(),
                )
                .await
                {
                    CompanyResolution::Resolved(id, role) => (Some(id), role),
                    CompanyResolution::NoMembership => (None, None),
                    CompanyResolution::Forbidden => {
                        tracing::warn!(
                            "User {} requested a company they are not a member of",
                            session.user_id
                        );
                        return Err(StatusCode::FORBIDDEN);
                    }
                };

                let mut roles = session.roles;
                merge_company_role(&mut roles, company_role.as_deref());

                // Session valid: Attach User Context
                let context =
                    UserContext::new_user(session.user_id, session.email, roles, company_id);
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

#[cfg(test)]
mod tests {
    use super::merge_company_role;
    use crate::auth::rbac::Role;

    #[test]
    fn company_role_becomes_a_request_role() {
        let mut roles = vec![];
        merge_company_role(&mut roles, Some("operator"));
        assert_eq!(roles, vec![Role::Operator]);
    }

    #[test]
    fn company_admin_is_not_a_global_admin() {
        let mut roles = vec![];
        merge_company_role(&mut roles, Some("admin"));
        assert_eq!(roles, vec![Role::Admin]);
        assert!(!roles.contains(&Role::GlobalAdmin));
    }

    #[test]
    fn membership_row_cannot_claim_a_global_role() {
        for claim in ["global_admin", "globaladmin", "superadmin", "super_admin"] {
            let mut roles = vec![];
            merge_company_role(&mut roles, Some(claim));
            assert!(roles.is_empty(), "{claim} was merged");
        }
    }

    #[test]
    fn absent_or_unknown_role_changes_nothing() {
        let mut roles = vec![Role::GlobalAdmin];
        merge_company_role(&mut roles, None);
        merge_company_role(&mut roles, Some(""));
        merge_company_role(&mut roles, Some("auditor"));
        assert_eq!(roles, vec![Role::GlobalAdmin]);
    }

    #[test]
    fn an_existing_role_is_not_duplicated() {
        let mut roles = vec![Role::Analyst];
        merge_company_role(&mut roles, Some("analyst"));
        assert_eq!(roles, vec![Role::Analyst]);
    }
}
