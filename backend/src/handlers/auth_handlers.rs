use crate::auth::context::UserContext;
use crate::{error::ApiError, AppState};
use axum::{
    extract::{Query, State},
    response::IntoResponse,
    Extension, Json,
};
use axum_extra::extract::cookie::{Cookie, CookieJar, PrivateCookieJar, SameSite};
use serde::{Deserialize, Serialize};

#[derive(Deserialize)]
pub struct AuthCallbackParams {
    code: String,
    #[serde(rename = "state")]
    _state: String, // CSRF token
}

#[derive(Serialize)]
pub struct LoginResponse {
    url: String,
}

#[derive(Deserialize)]
pub struct LocalLoginParams {
    email: String,
    password: String,
}

/// Check if the deployment uses HTTPS by examining CORS origins or redirect URIs.
/// This determines whether to set the Secure flag on cookies.
/// Allows HTTP deployments in internal/production environments.
fn check_uses_https(state: &AppState) -> bool {
    let config = state.config.load();

    // Check if any CORS origin uses HTTPS
    let cors_uses_https = config
        .cors_allow_origins
        .iter()
        .any(|origin| origin.starts_with("https://"));

    // Check if redirect URIs use HTTPS
    let redirect_uses_https = config
        .google_redirect_uri
        .as_ref()
        .map(|u| u.starts_with("https://"))
        .unwrap_or(false)
        || config
            .keycloak_redirect_uri
            .as_ref()
            .map(|u| u.starts_with("https://"))
            .unwrap_or(false);

    cors_uses_https || redirect_uses_https
}

fn session_same_site(state: &AppState) -> SameSite {
    let config = state.config.load();
    if config.environment.eq_ignore_ascii_case("production") {
        SameSite::Strict
    } else {
        SameSite::Lax
    }
}

fn build_csrf_cookie(uses_https: bool, same_site: SameSite) -> Cookie<'static> {
    let token = uuid::Uuid::new_v4().to_string();
    Cookie::build(("csrf_token", token))
        .path("/")
        .secure(uses_https)
        .http_only(false)
        .same_site(same_site)
        .build()
}

pub async fn login_google(State(state): State<AppState>) -> Result<Json<LoginResponse>, ApiError> {
    let (url, _csrf_token, _nonce) = state.auth_service.get_google_auth_url().await?;
    // In a real app, store csrf_token in cookie/session to verify state param in callback
    Ok(Json(LoginResponse {
        url: url.to_string(),
    }))
}

pub async fn login_local(
    State(state): State<AppState>,
    jar: PrivateCookieJar,
    Json(params): Json<LocalLoginParams>,
) -> Result<
    (
        PrivateCookieJar,
        CookieJar,
        Json<crate::auth::session::UserSession>,
    ),
    ApiError,
> {
    let session = state
        .auth_service
        .login_local(&params.email, &params.password)
        .await?;

    let session_str = serde_json::to_string(&session).map_err(ApiError::Serialization)?;

    let uses_https = check_uses_https(&state);

    let same_site = session_same_site(&state);
    let cookie = Cookie::build(("session", session_str))
        .path("/")
        .secure(uses_https)
        .http_only(true)
        .same_site(same_site)
        .build();

    let jar = jar.add(cookie);
    let csrf_cookie = build_csrf_cookie(uses_https, same_site);
    let csrf_jar = CookieJar::new().add(csrf_cookie);

    Ok((jar, csrf_jar, Json(session)))
}

pub async fn callback_google(
    State(state): State<AppState>,
    jar: PrivateCookieJar,
    Query(params): Query<AuthCallbackParams>,
) -> Result<
    (
        PrivateCookieJar,
        CookieJar,
        Json<crate::auth::session::UserSession>,
    ),
    ApiError,
> {
    let session = state
        .auth_service
        .handle_google_callback(params.code)
        .await?;

    // Serialize session
    let session_str = serde_json::to_string(&session).map_err(ApiError::Serialization)?;

    let uses_https = check_uses_https(&state);

    let same_site = session_same_site(&state);
    let cookie = Cookie::build(("session", session_str))
        .path("/")
        .secure(uses_https)
        .http_only(true)
        .same_site(same_site)
        .build();

    let jar = jar.add(cookie);
    let csrf_cookie = build_csrf_cookie(uses_https, same_site);
    let csrf_jar = CookieJar::new().add(csrf_cookie);

    // Return jar (which sets headers) and session
    Ok((jar, csrf_jar, Json(session)))
}

pub async fn login_keycloak(
    State(state): State<AppState>,
) -> Result<Json<LoginResponse>, ApiError> {
    let (url, _csrf_token, _nonce) = state.auth_service.get_keycloak_auth_url().await?;
    Ok(Json(LoginResponse {
        url: url.to_string(),
    }))
}

pub async fn callback_keycloak(
    State(state): State<AppState>,
    jar: PrivateCookieJar,
    Query(params): Query<AuthCallbackParams>,
) -> Result<
    (
        PrivateCookieJar,
        CookieJar,
        Json<crate::auth::session::UserSession>,
    ),
    ApiError,
> {
    let session = state
        .auth_service
        .handle_keycloak_callback(params.code)
        .await?;

    let session_str = serde_json::to_string(&session).map_err(ApiError::Serialization)?;

    let uses_https = check_uses_https(&state);

    let same_site = session_same_site(&state);
    let cookie = Cookie::build(("session", session_str))
        .path("/")
        .secure(uses_https)
        .http_only(true)
        .same_site(same_site)
        .build();

    let jar = jar.add(cookie);
    let csrf_cookie = build_csrf_cookie(uses_https, same_site);
    let csrf_jar = CookieJar::new().add(csrf_cookie);

    Ok((jar, csrf_jar, Json(session)))
}

pub async fn logout(jar: PrivateCookieJar) -> (PrivateCookieJar, CookieJar, impl IntoResponse) {
    let jar = jar.remove(Cookie::from("session"));
    let csrf_jar = CookieJar::new().remove(Cookie::from("csrf_token"));
    (jar, csrf_jar, "Logged out")
}

pub async fn get_me(Extension(user): Extension<UserContext>) -> Json<UserContext> {
    Json(user)
}
