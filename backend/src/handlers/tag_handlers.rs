use crate::{
    auth::{context::UserContext, rbac::Role},
    error::ApiError,
    models::{AssetTagDetail, AutoTagResult, Tag, TagCreate, TagListResponse, TagUpdate},
    AppState,
};
use axum::{
    extract::{Extension, Path, Query, State},
    response::Json,
};
use serde::Deserialize;
use uuid::Uuid;

#[derive(Debug, Deserialize)]
pub struct TagListQuery {
    #[serde(default = "default_limit")]
    limit: i64,
    #[serde(default)]
    offset: i64,
}

fn default_limit() -> i64 {
    100
}

/// List all tags with their asset counts
pub async fn list_tags(
    State(app_state): State<AppState>,
    Query(params): Query<TagListQuery>,
) -> Result<Json<TagListResponse>, ApiError> {
    let response = app_state
        .tag_service
        .list_tags(params.limit, params.offset)
        .await?;
    Ok(Json(response))
}

/// Get a single tag by ID
pub async fn get_tag(
    State(app_state): State<AppState>,
    Path(id): Path<Uuid>,
) -> Result<Json<Tag>, ApiError> {
    let tag = app_state
        .tag_service
        .get_tag(&id)
        .await?
        .ok_or_else(|| ApiError::NotFound(format!("Tag {} not found", id)))?;
    Ok(Json(tag))
}

/// Create a new tag
pub async fn create_tag(
    State(app_state): State<AppState>,
    Extension(user): Extension<UserContext>,
    Json(payload): Json<TagCreate>,
) -> Result<Json<Tag>, ApiError> {
    // Require Analyst role or higher
    if !user.has_role(Role::Analyst)
        && !user.has_role(Role::Operator)
        && !user.has_role(Role::Admin)
    {
        return Err(ApiError::Authorization(
            "Analyst role or higher required to create tags".to_string(),
        ));
    }

    let tag = app_state.tag_service.create_tag(payload).await?;
    Ok(Json(tag))
}

/// Update an existing tag
pub async fn update_tag(
    State(app_state): State<AppState>,
    Extension(user): Extension<UserContext>,
    Path(id): Path<Uuid>,
    Json(payload): Json<TagUpdate>,
) -> Result<Json<Tag>, ApiError> {
    // Require Analyst role or higher
    if !user.has_role(Role::Analyst)
        && !user.has_role(Role::Operator)
        && !user.has_role(Role::Admin)
    {
        return Err(ApiError::Authorization(
            "Analyst role or higher required to update tags".to_string(),
        ));
    }

    let tag = app_state.tag_service.update_tag(&id, payload).await?;
    Ok(Json(tag))
}

/// Delete a tag
pub async fn delete_tag(
    State(app_state): State<AppState>,
    Extension(user): Extension<UserContext>,
    Path(id): Path<Uuid>,
) -> Result<Json<()>, ApiError> {
    // Require Operator role or higher
    if !user.has_role(Role::Operator) && !user.has_role(Role::Admin) {
        return Err(ApiError::Authorization(
            "Operator role or higher required to delete tags".to_string(),
        ));
    }

    app_state.tag_service.delete_tag(&id).await?;
    Ok(Json(()))
}

/// Get tags for an asset
pub async fn get_asset_tags(
    State(app_state): State<AppState>,
    Path(asset_id): Path<Uuid>,
) -> Result<Json<Vec<AssetTagDetail>>, ApiError> {
    let tags = app_state.tag_service.get_asset_tags(&asset_id).await?;
    Ok(Json(tags))
}

#[derive(Debug, Deserialize)]
pub struct TagAssetRequest {
    tag_id: Uuid,
}

/// Tag an asset manually
pub async fn tag_asset(
    State(app_state): State<AppState>,
    Extension(user): Extension<UserContext>,
    Path(asset_id): Path<Uuid>,
    Json(payload): Json<TagAssetRequest>,
) -> Result<Json<()>, ApiError> {
    // Require Analyst role or higher
    if !user.has_role(Role::Analyst)
        && !user.has_role(Role::Operator)
        && !user.has_role(Role::Admin)
    {
        return Err(ApiError::Authorization(
            "Analyst role or higher required to tag assets".to_string(),
        ));
    }

    app_state
        .tag_service
        .tag_asset(&asset_id, &payload.tag_id)
        .await?;
    Ok(Json(()))
}

/// Remove a tag from an asset
pub async fn untag_asset(
    State(app_state): State<AppState>,
    Extension(user): Extension<UserContext>,
    Path((asset_id, tag_id)): Path<(Uuid, Uuid)>,
) -> Result<Json<()>, ApiError> {
    // Require Analyst role or higher
    if !user.has_role(Role::Analyst)
        && !user.has_role(Role::Operator)
        && !user.has_role(Role::Admin)
    {
        return Err(ApiError::Authorization(
            "Analyst role or higher required to untag assets".to_string(),
        ));
    }

    app_state.tag_service.untag_asset(&asset_id, &tag_id).await?;
    Ok(Json(()))
}

/// Run auto-tagging for a specific tag
pub async fn run_auto_tag_for_tag(
    State(app_state): State<AppState>,
    Extension(user): Extension<UserContext>,
    Path(tag_id): Path<Uuid>,
) -> Result<Json<AutoTagResult>, ApiError> {
    // Require Operator role or higher
    if !user.has_role(Role::Operator) && !user.has_role(Role::Admin) {
        return Err(ApiError::Authorization(
            "Operator role or higher required to run auto-tagging".to_string(),
        ));
    }

    let result = app_state.tag_service.run_auto_tag_for_tag(&tag_id).await?;
    Ok(Json(result))
}

/// Run all auto-tagging rules
pub async fn run_auto_tag_all(
    State(app_state): State<AppState>,
    Extension(user): Extension<UserContext>,
) -> Result<Json<AutoTagResult>, ApiError> {
    // Require Operator role or higher
    if !user.has_role(Role::Operator) && !user.has_role(Role::Admin) {
        return Err(ApiError::Authorization(
            "Operator role or higher required to run auto-tagging".to_string(),
        ));
    }

    let result = app_state.tag_service.run_auto_tag_all().await?;
    Ok(Json(result))
}

