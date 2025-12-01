use crate::auth::{context::UserContext, rbac::Role};
use crate::repositories::user_repo::User;
use crate::utils::crypto::hash_password;
use crate::{error::ApiError, AppState};
use axum::{
    extract::{Extension, Path, State},
    Json,
};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Serialize)]
pub struct UserWithRoles {
    pub id: Uuid,
    pub email: String,
    pub display_name: Option<String>,
    pub is_active: bool,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub updated_at: chrono::DateTime<chrono::Utc>,
    pub last_login_at: Option<chrono::DateTime<chrono::Utc>>,
    pub roles: Vec<Role>,
}

impl UserWithRoles {
    pub fn from_user_and_roles(user: User, roles: Vec<Role>) -> Self {
        Self {
            id: user.id,
            email: user.email,
            display_name: user.display_name,
            is_active: user.is_active,
            created_at: user.created_at,
            updated_at: user.updated_at,
            last_login_at: user.last_login_at,
            roles,
        }
    }
}

#[derive(Deserialize)]
pub struct UpdateRoleRequest {
    pub role: Role,
    pub action: String, // "add" or "remove"
}

#[derive(Deserialize)]
pub struct CreateUserRequest {
    pub email: String,
    pub password: Option<String>,
    pub display_name: Option<String>,
    pub roles: Option<Vec<String>>,
}

#[derive(Deserialize)]
pub struct UpdateUserRequest {
    pub email: Option<String>,
    pub display_name: Option<String>,
    pub is_active: Option<bool>,
    pub password: Option<String>,
}

pub async fn list_users(
    Extension(context): Extension<UserContext>,
    State(state): State<AppState>,
) -> Result<Json<Vec<UserWithRoles>>, ApiError> {
    if !context.has_role(Role::Admin) {
        return Err(ApiError::Authorization("Admin role required".to_string()));
    }

    let users = state.user_repository.list_users().await?;

    let mut result = Vec::new();
    for user in users {
        let roles = state.user_repository.get_user_roles(user.id).await?;
        result.push(UserWithRoles::from_user_and_roles(user, roles));
    }

    Ok(Json(result))
}

pub async fn update_user_role(
    Extension(context): Extension<UserContext>,
    State(state): State<AppState>,
    Path(user_id): Path<Uuid>,
    Json(req): Json<UpdateRoleRequest>,
) -> Result<Json<String>, ApiError> {
    if !context.has_role(Role::Admin) {
        return Err(ApiError::Authorization("Admin role required".to_string()));
    }

    match req.action.as_str() {
        "add" => {
            state
                .user_repository
                .add_user_role(user_id, req.role, context.user_id)
                .await?;
            Ok(Json("Role added".to_string()))
        }
        "remove" => {
            state
                .user_repository
                .remove_user_role(user_id, req.role)
                .await?;
            Ok(Json("Role removed".to_string()))
        }
        _ => Err(ApiError::Validation(
            "Invalid action. Use 'add' or 'remove'".to_string(),
        )),
    }
}

pub async fn create_user(
    Extension(context): Extension<UserContext>,
    State(state): State<AppState>,
    Json(req): Json<CreateUserRequest>,
) -> Result<Json<UserWithRoles>, ApiError> {
    if !context.has_role(Role::Admin) {
        return Err(ApiError::Authorization("Admin role required".to_string()));
    }

    // Validate email
    if req.email.is_empty() || !req.email.contains('@') {
        return Err(ApiError::Validation("Invalid email address".to_string()));
    }

    // Check if user already exists
    if state.user_repository.find_by_email(&req.email).await?.is_some() {
        return Err(ApiError::Validation("User with this email already exists".to_string()));
    }

    // Hash password if provided
    let password_hash = if let Some(password) = &req.password {
        if password.len() < 8 {
            return Err(ApiError::Validation("Password must be at least 8 characters".to_string()));
        }
        Some(hash_password(password)?)
    } else {
        None
    };

    // Create user
    let user = state
        .user_repository
        .create_user_full(&req.email, password_hash, req.display_name.as_deref())
        .await?;

    // Assign roles if provided
    let roles_to_assign: Vec<Role> = req
        .roles
        .unwrap_or_default()
        .iter()
        .filter_map(|r| Role::from_str(r))
        .collect();

    for role in &roles_to_assign {
        state
            .user_repository
            .add_user_role(user.id, role.clone(), context.user_id)
            .await?;
    }

    // If no roles specified, assign default Viewer role
    if roles_to_assign.is_empty() {
        state
            .user_repository
            .add_user_role(user.id, Role::Viewer, context.user_id)
            .await?;
    }

    // Get final roles
    let roles = state.user_repository.get_user_roles(user.id).await?;

    Ok(Json(UserWithRoles::from_user_and_roles(user, roles)))
}

pub async fn update_user(
    Extension(context): Extension<UserContext>,
    State(state): State<AppState>,
    Path(user_id): Path<Uuid>,
    Json(req): Json<UpdateUserRequest>,
) -> Result<Json<UserWithRoles>, ApiError> {
    if !context.has_role(Role::Admin) {
        return Err(ApiError::Authorization("Admin role required".to_string()));
    }

    // Validate email if provided
    if let Some(email) = &req.email {
        if email.is_empty() || !email.contains('@') {
            return Err(ApiError::Validation("Invalid email address".to_string()));
        }
        // Check if email is taken by another user
        if let Some(existing) = state.user_repository.find_by_email(email).await? {
            if existing.id != user_id {
                return Err(ApiError::Validation("Email already in use by another user".to_string()));
            }
        }
    }

    // Update password if provided
    if let Some(password) = &req.password {
        if password.len() < 8 {
            return Err(ApiError::Validation("Password must be at least 8 characters".to_string()));
        }
        let password_hash = hash_password(password)?;
        state.user_repository.update_password(user_id, &password_hash).await?;
    }

    // Update user fields
    let user = state
        .user_repository
        .update_user(
            user_id,
            req.email.as_deref(),
            req.display_name.as_deref(),
            req.is_active,
        )
        .await?;

    let roles = state.user_repository.get_user_roles(user.id).await?;

    Ok(Json(UserWithRoles::from_user_and_roles(user, roles)))
}

pub async fn delete_user(
    Extension(context): Extension<UserContext>,
    State(state): State<AppState>,
    Path(user_id): Path<Uuid>,
) -> Result<Json<String>, ApiError> {
    if !context.has_role(Role::Admin) {
        return Err(ApiError::Authorization("Admin role required".to_string()));
    }

    // Prevent self-deletion
    if context.user_id == Some(user_id) {
        return Err(ApiError::Validation("Cannot delete your own account".to_string()));
    }

    // Check if user exists
    if state.user_repository.find_by_id(user_id).await?.is_none() {
        return Err(ApiError::NotFound("User not found".to_string()));
    }

    state.user_repository.delete_user(user_id).await?;

    Ok(Json("User deleted".to_string()))
}

pub async fn get_user(
    Extension(context): Extension<UserContext>,
    State(state): State<AppState>,
    Path(user_id): Path<Uuid>,
) -> Result<Json<UserWithRoles>, ApiError> {
    if !context.has_role(Role::Admin) {
        return Err(ApiError::Authorization("Admin role required".to_string()));
    }

    let user = state
        .user_repository
        .find_by_id(user_id)
        .await?
        .ok_or_else(|| ApiError::NotFound("User not found".to_string()))?;

    let roles = state.user_repository.get_user_roles(user.id).await?;

    Ok(Json(UserWithRoles::from_user_and_roles(user, roles)))
}
