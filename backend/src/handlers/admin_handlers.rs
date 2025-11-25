use axum::{
    extract::{State, Path, Extension},
    Json,
};
use crate::{AppState, error::ApiError};
use crate::auth::{context::UserContext, rbac::Role};
use crate::repositories::user_repo::User;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Serialize)]
pub struct UserWithRoles {
    #[serde(flatten)]
    pub user: User,
    pub roles: Vec<Role>,
}

#[derive(Deserialize)]
pub struct UpdateRoleRequest {
    pub role: Role,
    pub action: String, // "add" or "remove"
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
        result.push(UserWithRoles { user, roles });
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
            state.user_repository.add_user_role(user_id, req.role, context.user_id).await?;
            Ok(Json("Role added".to_string()))
        },
        "remove" => {
            state.user_repository.remove_user_role(user_id, req.role).await?;
            Ok(Json("Role removed".to_string()))
        },
        _ => Err(ApiError::Validation("Invalid action. Use 'add' or 'remove'".to_string())),
    }
}

