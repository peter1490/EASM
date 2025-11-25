use axum::{
    extract::{Query, State},
    response::{Redirect, IntoResponse},
    Json,
    Extension,
};
use crate::{AppState, error::ApiError};
use serde::{Deserialize, Serialize};
use axum_extra::extract::cookie::{Cookie, PrivateCookieJar, SameSite};
use crate::auth::context::UserContext;

#[derive(Deserialize)]
pub struct AuthCallbackParams {
    code: String,
    state: String, // CSRF token
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

pub async fn login_google(
    State(state): State<AppState>,
) -> Result<Json<LoginResponse>, ApiError> {
    let (url, _csrf_token, _nonce) = state.auth_service.get_google_auth_url()?;
    // In a real app, store csrf_token in cookie/session to verify state param in callback
    Ok(Json(LoginResponse { url: url.to_string() }))
}

pub async fn login_local(
    State(state): State<AppState>,
    jar: PrivateCookieJar,
    Json(params): Json<LocalLoginParams>,
) -> Result<(PrivateCookieJar, Json<crate::auth::session::UserSession>), ApiError> {
    let session = state.auth_service.login_local(&params.email, &params.password).await?;
    
    let session_str = serde_json::to_string(&session).map_err(ApiError::Serialization)?;
    
    let is_prod = state.config.environment == "production";

    let cookie = Cookie::build(("session", session_str))
        .path("/")
        .secure(is_prod)
        .http_only(true)
        .same_site(SameSite::Lax)
        .build();
        
    let jar = jar.add(cookie);
    
    Ok((jar, Json(session)))
}

pub async fn callback_google(
    State(state): State<AppState>,
    jar: PrivateCookieJar,
    Query(params): Query<AuthCallbackParams>,
) -> Result<(PrivateCookieJar, Json<crate::auth::session::UserSession>), ApiError> {
    let session = state.auth_service.handle_google_callback(params.code).await?;
    
    // Serialize session
    let session_str = serde_json::to_string(&session).map_err(ApiError::Serialization)?;
    
    let is_prod = state.config.environment == "production";

    let cookie = Cookie::build(("session", session_str))
        .path("/")
        .secure(is_prod) // Secure only in production
        .http_only(true)
        .same_site(SameSite::Lax)
        .build();
        
    let jar = jar.add(cookie);
    
    // Return jar (which sets headers) and session
    Ok((jar, Json(session)))
}

pub async fn login_keycloak(
    State(state): State<AppState>,
) -> Result<Json<LoginResponse>, ApiError> {
    let (url, _csrf_token, _nonce) = state.auth_service.get_keycloak_auth_url()?;
    Ok(Json(LoginResponse { url: url.to_string() }))
}

pub async fn callback_keycloak(
    State(state): State<AppState>,
    jar: PrivateCookieJar,
    Query(params): Query<AuthCallbackParams>,
) -> Result<(PrivateCookieJar, Json<crate::auth::session::UserSession>), ApiError> {
    let session = state.auth_service.handle_keycloak_callback(params.code).await?;
    
    let session_str = serde_json::to_string(&session).map_err(ApiError::Serialization)?;
    
    let is_prod = state.config.environment == "production";

    let cookie = Cookie::build(("session", session_str))
        .path("/")
        .secure(is_prod) // Secure only in production
        .http_only(true)
        .same_site(SameSite::Lax)
        .build();
        
    let jar = jar.add(cookie);
    
    Ok((jar, Json(session)))
}

pub async fn logout(
    jar: PrivateCookieJar,
) -> (PrivateCookieJar, impl IntoResponse) {
    let jar = jar.remove(Cookie::from("session"));
    (jar, "Logged out")
}

pub async fn get_me(
    Extension(user): Extension<UserContext>,
) -> Json<UserContext> {
    Json(user)
}
