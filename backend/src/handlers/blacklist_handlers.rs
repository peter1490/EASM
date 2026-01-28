use axum::{
    extract::{Extension, Path, Query, State},
    response::Json,
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use uuid::Uuid;

use crate::{
    auth::{context::UserContext, rbac::Role},
    error::ApiError,
    models::{
        BlacklistCheckResult, BlacklistCreate, BlacklistEntry, BlacklistObjectType,
        BlacklistResult, BlacklistUpdate,
    },
    AppState,
};

#[derive(Debug, Deserialize)]
pub struct BlacklistQuery {
    #[serde(default = "default_limit")]
    pub limit: i64,
    #[serde(default)]
    pub offset: i64,
    #[serde(default)]
    pub object_type: Option<String>,
    #[serde(default)]
    pub q: Option<String>,
}

fn default_limit() -> i64 {
    50
}

#[derive(Debug, Serialize)]
pub struct BlacklistListResponse {
    pub entries: Vec<BlacklistEntry>,
    pub total_count: i64,
    pub limit: i64,
    pub offset: i64,
}

/// POST /api/blacklist - Add an entry to the blacklist
pub async fn create_blacklist_entry(
    State(app_state): State<AppState>,
    Extension(user): Extension<UserContext>,
    Json(payload): Json<BlacklistCreate>,
) -> Result<Json<BlacklistResult>, ApiError> {
    // Require at least Analyst role
    if !user.has_role(Role::Analyst)
        && !user.has_role(Role::Operator)
        && !user.has_role(Role::Admin)
    {
        return Err(ApiError::Authorization(
            "Analyst role or higher required to manage blacklist".to_string(),
        ));
    }

    // Validate the object value
    if payload.object_value.trim().is_empty() {
        return Err(ApiError::Validation(
            "Object value cannot be empty".to_string(),
        ));
    }

    let company_id = user.company_id.unwrap_or_default();

    // Create the blacklist entry
    let entry = app_state
        .blacklist_repository
        .create(&payload, user.email.as_deref(), company_id)
        .await?;

    // If delete_descendants is true, find the asset and delete all descendants
    let mut descendants_deleted = 0i64;
    if payload.delete_descendants {
        // Find the asset by type and value
        if let Some(asset_id) = app_state
            .blacklist_repository
            .find_asset_id(&payload.object_type, &payload.object_value, company_id)
            .await?
        {
            descendants_deleted = app_state
                .blacklist_repository
                .delete_descendant_assets(company_id, &asset_id)
                .await?;

            tracing::info!(
                "Blacklisted {} '{}' and deleted {} descendant assets",
                payload.object_type,
                payload.object_value,
                descendants_deleted
            );
        }
    }

    Ok(Json(BlacklistResult {
        entry,
        descendants_deleted,
    }))
}

/// GET /api/blacklist - List all blacklist entries
pub async fn list_blacklist(
    State(app_state): State<AppState>,
    Extension(user): Extension<UserContext>,
    Query(query): Query<BlacklistQuery>,
) -> Result<Json<BlacklistListResponse>, ApiError> {
    let company_id = user.company_id.unwrap_or_default();
    let object_type = query
        .object_type
        .as_ref()
        .map(|t| BlacklistObjectType::from(t.as_str()));

    let (entries, total_count) = app_state
        .blacklist_repository
        .search(
            query.q.as_deref(),
            object_type.as_ref(),
            company_id,
            query.limit,
            query.offset,
        )
        .await?;

    Ok(Json(BlacklistListResponse {
        entries,
        total_count,
        limit: query.limit,
        offset: query.offset,
    }))
}

/// GET /api/blacklist/:id - Get a specific blacklist entry
pub async fn get_blacklist_entry(
    State(app_state): State<AppState>,
    Extension(user): Extension<UserContext>,
    Path(id): Path<Uuid>,
) -> Result<Json<BlacklistEntry>, ApiError> {
    let company_id = user.company_id.unwrap_or_default();
    let entry = app_state
        .blacklist_repository
        .get_by_id(company_id, &id)
        .await?
        .ok_or_else(|| ApiError::NotFound(format!("Blacklist entry {} not found", id)))?;

    Ok(Json(entry))
}

/// PUT /api/blacklist/:id - Update a blacklist entry
pub async fn update_blacklist_entry(
    State(app_state): State<AppState>,
    Extension(user): Extension<UserContext>,
    Path(id): Path<Uuid>,
    Json(payload): Json<BlacklistUpdate>,
) -> Result<Json<BlacklistEntry>, ApiError> {
    // Require at least Analyst role
    if !user.has_role(Role::Analyst)
        && !user.has_role(Role::Operator)
        && !user.has_role(Role::Admin)
    {
        return Err(ApiError::Authorization(
            "Analyst role or higher required to manage blacklist".to_string(),
        ));
    }

    let company_id = user.company_id.unwrap_or_default();
    let entry = app_state
        .blacklist_repository
        .update(company_id, &id, &payload)
        .await?;

    Ok(Json(entry))
}

/// DELETE /api/blacklist/:id - Remove an entry from the blacklist
pub async fn delete_blacklist_entry(
    State(app_state): State<AppState>,
    Extension(user): Extension<UserContext>,
    Path(id): Path<Uuid>,
) -> Result<Json<Value>, ApiError> {
    // Require at least Analyst role
    if !user.has_role(Role::Analyst)
        && !user.has_role(Role::Operator)
        && !user.has_role(Role::Admin)
    {
        return Err(ApiError::Authorization(
            "Analyst role or higher required to manage blacklist".to_string(),
        ));
    }

    let company_id = user.company_id.unwrap_or_default();
    app_state.blacklist_repository.delete(company_id, &id).await?;

    Ok(Json(json!({
        "message": "Blacklist entry deleted successfully"
    })))
}

/// Check request structure
#[derive(Debug, Deserialize)]
pub struct BlacklistCheckRequest {
    pub object_type: BlacklistObjectType,
    pub object_value: String,
}

/// POST /api/blacklist/check - Check if an object is blacklisted
pub async fn check_blacklist(
    State(app_state): State<AppState>,
    Extension(user): Extension<UserContext>,
    Json(payload): Json<BlacklistCheckRequest>,
) -> Result<Json<BlacklistCheckResult>, ApiError> {
    let company_id = user.company_id.unwrap_or_default();
    let object_value = payload.object_value.trim();

    match payload.object_type {
        BlacklistObjectType::Domain => {
            // Check domain and parent domains
            let entry = app_state
                .blacklist_repository
                .is_domain_or_parent_blacklisted(object_value, company_id)
                .await?;

            let is_blacklisted = entry.is_some();

            // Check if it's an exact match or parent match
            let (parent_blacklisted, parent_entry) = if let Some(ref e) = entry {
                if e.object_value != object_value.to_lowercase() {
                    (true, entry.clone())
                } else {
                    (false, None)
                }
            } else {
                (false, None)
            };

            Ok(Json(BlacklistCheckResult {
                is_blacklisted,
                entry: if !parent_blacklisted { entry } else { None },
                parent_blacklisted,
                parent_entry,
            }))
        }
        BlacklistObjectType::Ip => {
            let entry = app_state
                .blacklist_repository
                .is_ip_blacklisted(object_value, company_id)
                .await?;

            Ok(Json(BlacklistCheckResult {
                is_blacklisted: entry.is_some(),
                entry,
                parent_blacklisted: false,
                parent_entry: None,
            }))
        }
        _ => {
            let is_blacklisted = app_state
                .blacklist_repository
                .is_blacklisted(&payload.object_type, object_value, company_id)
                .await?;

            let entry = if is_blacklisted {
                app_state
                    .blacklist_repository
                    .get_by_type_value(&payload.object_type, object_value, company_id)
                    .await?
            } else {
                None
            };

            Ok(Json(BlacklistCheckResult {
                is_blacklisted,
                entry,
                parent_blacklisted: false,
                parent_entry: None,
            }))
        }
    }
}

/// POST /api/blacklist/from-asset/:id - Blacklist an asset by its ID
#[derive(Debug, Deserialize)]
pub struct BlacklistFromAssetRequest {
    pub reason: Option<String>,
    #[serde(default)]
    pub delete_descendants: bool,
}

pub async fn blacklist_from_asset(
    State(app_state): State<AppState>,
    Extension(user): Extension<UserContext>,
    Path(asset_id): Path<Uuid>,
    Json(payload): Json<BlacklistFromAssetRequest>,
) -> Result<Json<BlacklistResult>, ApiError> {
    // Require at least Analyst role
    if !user.has_role(Role::Analyst)
        && !user.has_role(Role::Operator)
        && !user.has_role(Role::Admin)
    {
        return Err(ApiError::Authorization(
            "Analyst role or higher required to manage blacklist".to_string(),
        ));
    }

    // Get the asset
    let company_id = user.company_id.unwrap_or_default();
    let asset = app_state
        .asset_repository
        .get_by_id(company_id, &asset_id)
        .await?
        .ok_or_else(|| ApiError::NotFound(format!("Asset {} not found", asset_id)))?;

    // Convert asset type to blacklist object type
    let object_type = match asset.asset_type.to_string().as_str() {
        "domain" => BlacklistObjectType::Domain,
        "ip" => BlacklistObjectType::Ip,
        "organization" => BlacklistObjectType::Organization,
        "asn" => BlacklistObjectType::Asn,
        "certificate" => BlacklistObjectType::Certificate,
        _ => {
            return Err(ApiError::Validation(format!(
                "Asset type {} cannot be blacklisted",
                asset.asset_type
            )));
        }
    };

    // Create blacklist entry
    let blacklist_create = BlacklistCreate {
        object_type: object_type.clone(),
        object_value: asset.identifier.clone(),
        reason: payload.reason,
        delete_descendants: payload.delete_descendants,
    };

    let entry = app_state
        .blacklist_repository
        .create(&blacklist_create, user.email.as_deref(), company_id)
        .await?;

    // Delete descendants if requested
    let descendants_deleted = if payload.delete_descendants {
        app_state
            .blacklist_repository
            .delete_descendant_assets(company_id, &asset_id)
            .await?
    } else {
        0
    };

    tracing::info!(
        "User {} blacklisted asset {} ({} '{}'), deleted {} descendants",
        user.email.as_deref().unwrap_or("unknown"),
        asset_id,
        object_type,
        asset.identifier,
        descendants_deleted
    );

    Ok(Json(BlacklistResult {
        entry,
        descendants_deleted,
    }))
}

/// GET /api/blacklist/stats - Get blacklist statistics
#[derive(Debug, Serialize)]
pub struct BlacklistStats {
    pub total_entries: i64,
    pub by_type: std::collections::HashMap<String, i64>,
}

pub async fn get_blacklist_stats(
    State(app_state): State<AppState>,
    Extension(user): Extension<UserContext>,
) -> Result<Json<BlacklistStats>, ApiError> {
    let company_id = user.company_id.unwrap_or_default();
    let total_entries = app_state.blacklist_repository.count(company_id).await?;

    // Get counts by type
    let mut by_type = std::collections::HashMap::new();
    for obj_type in [
        BlacklistObjectType::Domain,
        BlacklistObjectType::Ip,
        BlacklistObjectType::Organization,
        BlacklistObjectType::Asn,
        BlacklistObjectType::Cidr,
        BlacklistObjectType::Certificate,
    ] {
        let entries = app_state
            .blacklist_repository
            .list_by_type(&obj_type, company_id, 0, 0)
            .await?;
        // This is not efficient but works for now - ideally we'd have a count_by_type method
        let count = app_state
            .blacklist_repository
            .search(None, Some(&obj_type), company_id, 1, 0)
            .await?
            .1;
        by_type.insert(obj_type.to_string(), count);
    }

    Ok(Json(BlacklistStats {
        total_entries,
        by_type,
    }))
}
