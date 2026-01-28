use axum::{
    extract::{Extension, Path, State},
    response::Json,
};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::{
    auth::{context::UserContext, rbac::Role},
    error::ApiError,
    models::{Company, CompanyCreate, CompanyUpdate, CompanyWithRole},
    AppState,
};

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
        if !user.has_role(Role::Admin) {
            return Err(ApiError::Authorization(
                "Admin role required to list companies".to_string(),
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
    if !user.has_role(Role::Admin) {
        return Err(ApiError::Authorization(
            "Admin role required to create companies".to_string(),
        ));
    }

    if payload.name.trim().is_empty() {
        return Err(ApiError::Validation("Company name cannot be empty".to_string()));
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

/// PATCH /api/companies/:id - Update a company name (admin only)
pub async fn update_company(
    State(app_state): State<AppState>,
    Extension(user): Extension<UserContext>,
    Path(id): Path<Uuid>,
    Json(payload): Json<UpdateCompanyRequest>,
) -> Result<Json<Company>, ApiError> {
    if !user.has_role(Role::Admin) {
        return Err(ApiError::Authorization(
            "Admin role required to update companies".to_string(),
        ));
    }

    let update = CompanyUpdate { name: payload.name };
    let company = app_state.company_repository.update(id, &update).await?;

    Ok(Json(company))
}
