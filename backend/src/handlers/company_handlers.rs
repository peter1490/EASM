use std::collections::BTreeMap;

use axum::{
    extract::{Extension, Path, State},
    response::Json,
};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::{
    auth::context::UserContext,
    error::ApiError,
    models::{Company, CompanyCreate, CompanyMember, CompanyUpdate, CompanyWithRole},
    repositories::company_repo::DEFAULT_COMPANY_ID,
    AppState,
};

const VALID_COMPANY_ROLES: &[&str] = &["admin", "operator", "analyst", "viewer"];

fn validate_company_role(role: &str) -> Result<String, ApiError> {
    let normalized = role.trim().to_lowercase();
    if VALID_COMPANY_ROLES.contains(&normalized.as_str()) {
        Ok(normalized)
    } else {
        Err(ApiError::Validation(format!(
            "Invalid role '{}'. Must be one of: admin, operator, analyst, viewer",
            role
        )))
    }
}

/// Authorize a per-company action: pass if the user is a global admin, OR if they
/// are an admin (role='admin' in user_companies) of the given company.
async fn require_company_admin(
    app_state: &AppState,
    user: &UserContext,
    company_id: Uuid,
) -> Result<(), ApiError> {
    if user.is_global_admin() {
        return Ok(());
    }
    let user_id = user
        .user_id
        .ok_or_else(|| ApiError::Authorization("User context required".to_string()))?;
    let role = app_state
        .company_repository
        .role_of_user_in_company(user_id, company_id)
        .await?;
    if role.as_deref() == Some("admin") {
        Ok(())
    } else {
        Err(ApiError::Authorization(
            "Global admin or company admin role required".to_string(),
        ))
    }
}

#[derive(Debug, Deserialize)]
pub struct CreateCompanyRequest {
    pub name: String,
}

#[derive(Debug, Deserialize)]
pub struct UpdateCompanyRequest {
    pub name: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct CompanyListResponse {
    pub companies: Vec<CompanyWithRole>,
}

/// GET /api/companies - List companies for the current user
pub async fn list_companies(
    State(app_state): State<AppState>,
    Extension(user): Extension<UserContext>,
) -> Result<Json<CompanyListResponse>, ApiError> {
    let companies = if let Some(user_id) = user.user_id {
        app_state.company_repository.list_for_user(user_id).await?
    } else {
        if !user.is_global_admin() {
            return Err(ApiError::Authorization(
                "Global admin role required to list all companies".to_string(),
            ));
        }

        app_state
            .company_repository
            .list_all()
            .await?
            .into_iter()
            .map(|company| CompanyWithRole {
                id: company.id,
                name: company.name,
                role: "admin".to_string(),
                assigned_at: company.created_at,
                created_at: company.created_at,
                updated_at: company.updated_at,
            })
            .collect()
    };

    Ok(Json(CompanyListResponse { companies }))
}

/// POST /api/companies - Create a new company (admin only)
pub async fn create_company(
    State(app_state): State<AppState>,
    Extension(user): Extension<UserContext>,
    Json(payload): Json<CreateCompanyRequest>,
) -> Result<Json<Company>, ApiError> {
    if !user.is_global_admin() {
        return Err(ApiError::Authorization(
            "Global admin role required to create companies".to_string(),
        ));
    }

    if payload.name.trim().is_empty() {
        return Err(ApiError::Validation(
            "Company name cannot be empty".to_string(),
        ));
    }

    let user_id = user.user_id.ok_or_else(|| {
        ApiError::Authorization("User context required to create company".to_string())
    })?;

    let company = app_state
        .company_repository
        .create(&CompanyCreate { name: payload.name }, user_id)
        .await?;

    Ok(Json(company))
}

/// PATCH /api/companies/:id - Update a company name. Global admin or the company's
/// per-company admin.
pub async fn update_company(
    State(app_state): State<AppState>,
    Extension(user): Extension<UserContext>,
    Path(id): Path<Uuid>,
    Json(payload): Json<UpdateCompanyRequest>,
) -> Result<Json<Company>, ApiError> {
    require_company_admin(&app_state, &user, id).await?;

    let update = CompanyUpdate { name: payload.name };
    let company = app_state.company_repository.update(id, &update).await?;

    Ok(Json(company))
}

#[derive(Debug, Serialize)]
pub struct DeleteCompanyResponse {
    pub deleted: bool,
}

/// DELETE /api/companies/:id - Hard-delete a company and all its scoped data
/// (global admin only). The Default Company cannot be deleted; use clear-data instead.
pub async fn delete_company(
    State(app_state): State<AppState>,
    Extension(user): Extension<UserContext>,
    Path(id): Path<Uuid>,
) -> Result<Json<DeleteCompanyResponse>, ApiError> {
    if !user.is_global_admin() {
        return Err(ApiError::Authorization(
            "Global admin role required to delete companies".to_string(),
        ));
    }

    if id == DEFAULT_COMPANY_ID {
        return Err(ApiError::Validation(
            "The Default Company cannot be deleted; clear its data instead".to_string(),
        ));
    }

    let deleted = app_state.company_repository.delete(id).await?;
    if !deleted {
        return Err(ApiError::NotFound("Company not found".to_string()));
    }
    Ok(Json(DeleteCompanyResponse { deleted: true }))
}

#[derive(Debug, Serialize)]
pub struct ClearCompanyDataResponse {
    pub deleted: BTreeMap<String, u64>,
}

/// POST /api/companies/:id/clear-data - Wipe all scoped data for a company while preserving
/// the company row and its membership rows. Global admin or company admin.
pub async fn clear_company_data(
    State(app_state): State<AppState>,
    Extension(user): Extension<UserContext>,
    Path(id): Path<Uuid>,
) -> Result<Json<ClearCompanyDataResponse>, ApiError> {
    require_company_admin(&app_state, &user, id).await?;

    if app_state
        .company_repository
        .get_by_id(id)
        .await?
        .is_none()
    {
        return Err(ApiError::NotFound("Company not found".to_string()));
    }

    let summary = app_state.company_repository.clear_data(id).await?;
    Ok(Json(ClearCompanyDataResponse { deleted: summary }))
}

#[derive(Debug, Serialize)]
pub struct MembersResponse {
    pub members: Vec<CompanyMember>,
}

/// GET /api/companies/:id/members - List company members. Global admin or company admin.
pub async fn list_company_members(
    State(app_state): State<AppState>,
    Extension(user): Extension<UserContext>,
    Path(id): Path<Uuid>,
) -> Result<Json<MembersResponse>, ApiError> {
    require_company_admin(&app_state, &user, id).await?;
    let members = app_state.company_repository.list_members(id).await?;
    Ok(Json(MembersResponse { members }))
}

#[derive(Debug, Deserialize)]
pub struct AddMemberRequest {
    pub user_id: Uuid,
    pub role: String,
}

/// POST /api/companies/:id/members - Add a user to a company with a per-company role.
/// Global admin or company admin.
pub async fn add_company_member(
    State(app_state): State<AppState>,
    Extension(user): Extension<UserContext>,
    Path(id): Path<Uuid>,
    Json(payload): Json<AddMemberRequest>,
) -> Result<Json<MembersResponse>, ApiError> {
    require_company_admin(&app_state, &user, id).await?;

    let role = validate_company_role(&payload.role)?;

    if app_state
        .company_repository
        .get_by_id(id)
        .await?
        .is_none()
    {
        return Err(ApiError::NotFound("Company not found".to_string()));
    }

    app_state
        .company_repository
        .add_user_to_company(payload.user_id, id, &role)
        .await?;

    let members = app_state.company_repository.list_members(id).await?;
    Ok(Json(MembersResponse { members }))
}

#[derive(Debug, Deserialize)]
pub struct UpdateMemberRoleRequest {
    pub role: String,
}

/// PATCH /api/companies/:id/members/:user_id - Update a member's per-company role.
/// Global admin or company admin.
pub async fn update_company_member_role(
    State(app_state): State<AppState>,
    Extension(user): Extension<UserContext>,
    Path((id, user_id)): Path<(Uuid, Uuid)>,
    Json(payload): Json<UpdateMemberRoleRequest>,
) -> Result<Json<MembersResponse>, ApiError> {
    require_company_admin(&app_state, &user, id).await?;

    let new_role = validate_company_role(&payload.role)?;

    let members = app_state.company_repository.list_members(id).await?;
    let current = members
        .iter()
        .find(|m| m.user_id == user_id)
        .ok_or_else(|| ApiError::NotFound("Member not found".to_string()))?;

    // Block demoting the last admin.
    if current.role == "admin" && new_role != "admin" {
        let admin_count = app_state.company_repository.count_admins(id).await?;
        if admin_count <= 1 {
            return Err(ApiError::Validation(
                "Cannot demote the last admin of the company".to_string(),
            ));
        }
    }

    app_state
        .company_repository
        .add_user_to_company(user_id, id, &new_role)
        .await?;

    let members = app_state.company_repository.list_members(id).await?;
    Ok(Json(MembersResponse { members }))
}

/// DELETE /api/companies/:id/members/:user_id - Remove a member. Global admin or company admin.
/// Refuses to remove the last admin.
pub async fn remove_company_member(
    State(app_state): State<AppState>,
    Extension(user): Extension<UserContext>,
    Path((id, user_id)): Path<(Uuid, Uuid)>,
) -> Result<Json<MembersResponse>, ApiError> {
    require_company_admin(&app_state, &user, id).await?;

    let members = app_state.company_repository.list_members(id).await?;
    let target = members
        .iter()
        .find(|m| m.user_id == user_id)
        .ok_or_else(|| ApiError::NotFound("Member not found".to_string()))?;

    if target.role == "admin" {
        let admin_count = app_state.company_repository.count_admins(id).await?;
        if admin_count <= 1 {
            return Err(ApiError::Validation(
                "Cannot remove the last admin of the company".to_string(),
            ));
        }
    }

    app_state
        .company_repository
        .remove_user_from_company(user_id, id)
        .await?;
    crate::handlers::admin_handlers::deactivate_if_no_access(&app_state, user_id).await?;

    let members = app_state.company_repository.list_members(id).await?;
    Ok(Json(MembersResponse { members }))
}
