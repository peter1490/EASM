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
        exclusion::validate_value, ExclusionCheckResult, ExclusionCreate, ExclusionEntry,
        ExclusionObjectType, ExclusionResult, ExclusionUpdate,
    },
    AppState,
};

#[derive(Debug, Deserialize)]
pub struct ExclusionQuery {
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
pub struct ExclusionListResponse {
    pub entries: Vec<ExclusionEntry>,
    pub total_count: i64,
    pub limit: i64,
    pub offset: i64,
}

/// Analyst or higher for anything that changes the list.
fn require_analyst(user: &UserContext) -> Result<(), ApiError> {
    if user.has_role(Role::Analyst) || user.has_role(Role::Operator) || user.has_role(Role::Admin) {
        return Ok(());
    }
    Err(ApiError::Authorization(
        "Analyst role or higher required to manage exclusions".to_string(),
    ))
}

fn company_scope(user: &UserContext) -> Result<Uuid, ApiError> {
    user.company_id
        .ok_or_else(|| ApiError::Authorization("Company scope required for exclusions".to_string()))
}

/// Everything an entry does beyond existing as a row.
///
/// Both ways in — a value typed into the exclusions page, and an asset excluded
/// from its own detail view — have to reach the same four things, and the counts
/// they return are the only evidence the operator gets that they happened.
///
/// A blacklist purges instead of cascading. The purge already takes the
/// descendants with the assets it deletes, so asking for both would delete the
/// same rows twice and report them once.
async fn apply_entry(
    app_state: &AppState,
    company_id: Uuid,
    entry: ExclusionEntry,
    object_type: &ExclusionObjectType,
    object_value: &str,
    delete_descendants: bool,
    known_asset_id: Option<Uuid>,
) -> Result<ExclusionResult, ApiError> {
    let mut descendants_deleted = 0i64;
    let mut assets_deleted = 0i64;

    if entry.blacklisted {
        assets_deleted = app_state
            .exclusion_repository
            .purge_entry_assets(company_id, object_type, object_value)
            .await?;

        tracing::info!(
            "Blacklisted {} '{}' and deleted {} assets",
            object_type,
            object_value,
            assets_deleted
        );
    } else if delete_descendants {
        // The asset the caller already has in hand when one was named, and
        // otherwise whatever the entry matches: a literal names at most one, a
        // CIDR names the addresses inside it, a pattern names all it covers.
        let roots = match known_asset_id {
            Some(id) => vec![id],
            None => {
                app_state
                    .exclusion_repository
                    .matched_asset_ids(company_id, object_type, object_value)
                    .await?
            }
        };

        descendants_deleted = app_state
            .exclusion_repository
            .delete_descendants_of(company_id, &roots)
            .await?;

        tracing::info!(
            "Excluded {} '{}' and deleted {} descendant assets",
            object_type,
            object_value,
            descendants_deleted
        );
    }

    // Apply the entry to work already in flight: a run in progress is holding a
    // queue it built before this entry existed, and — if the entry blacklists
    // them — scans against hosts that no longer exist.
    let (queue_items_removed, scans_cancelled) = app_state
        .discovery_service
        .apply_exclusion_entry(company_id, object_type, object_value, entry.blacklisted)
        .await?;

    Ok(ExclusionResult {
        entry,
        descendants_deleted,
        assets_deleted,
        queue_items_removed,
        scans_cancelled: scans_cancelled as i64,
    })
}

/// POST /api/exclusions - Add an entry to the exclusion list
pub async fn create_exclusion(
    State(app_state): State<AppState>,
    Extension(user): Extension<UserContext>,
    Json(payload): Json<ExclusionCreate>,
) -> Result<Json<ExclusionResult>, ApiError> {
    require_analyst(&user)?;

    // Validate the object value
    let object_value = payload.object_value.trim();
    if object_value.is_empty() {
        return Err(ApiError::Validation(
            "Object value cannot be empty".to_string(),
        ));
    }
    // A pattern that is too broad is refused here rather than stored: as a
    // blacklist it would delete the estate, and nothing downstream is in a
    // position to second-guess an entry that already exists.
    validate_value(&payload.object_type, &object_value.to_lowercase())
        .map_err(ApiError::Validation)?;

    let company_id = company_scope(&user)?;

    let entry = app_state
        .exclusion_repository
        .create(&payload, user.email.as_deref(), company_id)
        .await?;

    let result = apply_entry(
        &app_state,
        company_id,
        entry,
        &payload.object_type,
        &payload.object_value,
        payload.delete_descendants,
        None,
    )
    .await?;

    Ok(Json(result))
}

/// GET /api/exclusions - List all exclusion entries
pub async fn list_exclusions(
    State(app_state): State<AppState>,
    Extension(user): Extension<UserContext>,
    Query(query): Query<ExclusionQuery>,
) -> Result<Json<ExclusionListResponse>, ApiError> {
    let company_id = company_scope(&user)?;
    let object_type = query
        .object_type
        .as_ref()
        .map(|t| ExclusionObjectType::from(t.as_str()));

    let (entries, total_count) = app_state
        .exclusion_repository
        .search(
            query.q.as_deref(),
            object_type.as_ref(),
            company_id,
            query.limit,
            query.offset,
        )
        .await?;

    Ok(Json(ExclusionListResponse {
        entries,
        total_count,
        limit: query.limit,
        offset: query.offset,
    }))
}

/// GET /api/exclusions/:id - Get a specific exclusion entry
pub async fn get_exclusion(
    State(app_state): State<AppState>,
    Extension(user): Extension<UserContext>,
    Path(id): Path<Uuid>,
) -> Result<Json<ExclusionEntry>, ApiError> {
    let company_id = company_scope(&user)?;
    let entry = app_state
        .exclusion_repository
        .get_by_id(company_id, &id)
        .await?
        .ok_or_else(|| ApiError::NotFound(format!("Exclusion entry {} not found", id)))?;

    Ok(Json(entry))
}

/// PATCH /api/exclusions/:id - Update an exclusion entry
///
/// Returns the same shape as a create, because the same things can happen:
/// promoting an exclusion to a blacklist purges what it names and stops the
/// scans running against it, and the operator needs to be told how much.
pub async fn update_exclusion(
    State(app_state): State<AppState>,
    Extension(user): Extension<UserContext>,
    Path(id): Path<Uuid>,
    Json(payload): Json<ExclusionUpdate>,
) -> Result<Json<ExclusionResult>, ApiError> {
    require_analyst(&user)?;

    let company_id = company_scope(&user)?;
    let before = app_state
        .exclusion_repository
        .get_by_id(company_id, &id)
        .await?
        .ok_or_else(|| ApiError::NotFound(format!("Exclusion entry {} not found", id)))?;

    let entry = app_state
        .exclusion_repository
        .update(company_id, &id, &payload)
        .await?;

    let object_type = ExclusionObjectType::from(entry.object_type.as_str());
    let object_value = entry.object_value.clone();

    // Only a promotion has work to do. Editing a reason changes nothing about
    // what the entry covers, and demoting a blacklist cannot bring back what it
    // already deleted — it only stops the rule from applying again.
    if entry.blacklisted && !before.blacklisted {
        let result = apply_entry(
            &app_state,
            company_id,
            entry,
            &object_type,
            &object_value,
            false,
            None,
        )
        .await?;
        return Ok(Json(result));
    }

    // A demotion still has to reach the cache, or discovery keeps treating the
    // entry as the strength it no longer is.
    if before.blacklisted && !entry.blacklisted {
        app_state
            .discovery_service
            .invalidate_exclusion_cache(company_id)
            .await;
    }

    Ok(Json(ExclusionResult {
        entry,
        descendants_deleted: 0,
        assets_deleted: 0,
        queue_items_removed: 0,
        scans_cancelled: 0,
    }))
}

/// DELETE /api/exclusions/:id - Remove an entry from the exclusion list
pub async fn delete_exclusion(
    State(app_state): State<AppState>,
    Extension(user): Extension<UserContext>,
    Path(id): Path<Uuid>,
) -> Result<Json<Value>, ApiError> {
    require_analyst(&user)?;

    let company_id = company_scope(&user)?;
    app_state
        .exclusion_repository
        .delete(company_id, &id)
        .await?;

    // Discovery caches the list between reads, so a removed entry has to be
    // pushed out or it keeps excluding assets for the rest of the window.
    app_state
        .discovery_service
        .invalidate_exclusion_cache(company_id)
        .await;

    Ok(Json(json!({
        "message": "Exclusion entry deleted successfully"
    })))
}

/// Check request structure
#[derive(Debug, Deserialize)]
pub struct ExclusionCheckRequest {
    pub object_type: ExclusionObjectType,
    pub object_value: String,
}

/// POST /api/exclusions/check - Check if an object is excluded
pub async fn check_exclusion(
    State(app_state): State<AppState>,
    Extension(user): Extension<UserContext>,
    Json(payload): Json<ExclusionCheckRequest>,
) -> Result<Json<ExclusionCheckResult>, ApiError> {
    let company_id = company_scope(&user)?;
    let object_value = payload.object_value.trim();

    match payload.object_type {
        ExclusionObjectType::Domain => {
            // Check domain and parent domains
            let entry = app_state
                .exclusion_repository
                .is_domain_or_parent_excluded(object_value, company_id)
                .await?;

            let is_excluded = entry.is_some();
            let is_blacklisted = entry.as_ref().is_some_and(|e| e.blacklisted);

            // Check if it's an exact match or parent match
            let (parent_excluded, parent_entry) = if let Some(ref e) = entry {
                if e.object_value != object_value.to_lowercase() {
                    (true, entry.clone())
                } else {
                    (false, None)
                }
            } else {
                (false, None)
            };

            Ok(Json(ExclusionCheckResult {
                is_excluded,
                is_blacklisted,
                entry: if !parent_excluded { entry } else { None },
                parent_excluded,
                parent_entry,
            }))
        }
        ExclusionObjectType::Ip => {
            let entry = app_state
                .exclusion_repository
                .is_ip_excluded(object_value, company_id)
                .await?;

            Ok(Json(ExclusionCheckResult {
                is_excluded: entry.is_some(),
                is_blacklisted: entry.as_ref().is_some_and(|e| e.blacklisted),
                entry,
                parent_excluded: false,
                parent_entry: None,
            }))
        }
        _ => {
            let is_excluded = app_state
                .exclusion_repository
                .is_excluded(&payload.object_type, object_value, company_id)
                .await?;

            let entry = if is_excluded {
                app_state
                    .exclusion_repository
                    .get_by_type_value(&payload.object_type, object_value, company_id)
                    .await?
            } else {
                None
            };

            Ok(Json(ExclusionCheckResult {
                is_excluded,
                is_blacklisted: entry.as_ref().is_some_and(|e| e.blacklisted),
                entry,
                parent_excluded: false,
                parent_entry: None,
            }))
        }
    }
}

/// POST /api/exclusions/from-asset/:id - Exclude an asset by its ID
#[derive(Debug, Deserialize)]
pub struct ExcludeAssetRequest {
    pub reason: Option<String>,
    #[serde(default)]
    pub delete_descendants: bool,
    /// Delete the asset itself and keep it out for good, rather than only
    /// stopping discovery from finding more through it.
    #[serde(default)]
    pub blacklisted: bool,
}

pub async fn exclude_asset(
    State(app_state): State<AppState>,
    Extension(user): Extension<UserContext>,
    Path(asset_id): Path<Uuid>,
    Json(payload): Json<ExcludeAssetRequest>,
) -> Result<Json<ExclusionResult>, ApiError> {
    require_analyst(&user)?;

    let company_id = company_scope(&user)?;
    let asset = app_state
        .asset_repository
        .get_by_id(company_id, &asset_id)
        .await?
        .ok_or_else(|| ApiError::NotFound(format!("Asset {} not found", asset_id)))?;

    // Convert asset type to exclusion object type
    let object_type = match asset.asset_type.to_string().as_str() {
        "domain" => ExclusionObjectType::Domain,
        "ip" => ExclusionObjectType::Ip,
        "organization" => ExclusionObjectType::Organization,
        "asn" => ExclusionObjectType::Asn,
        "certificate" => ExclusionObjectType::Certificate,
        _ => {
            return Err(ApiError::Validation(format!(
                "Asset type {} cannot be excluded",
                asset.asset_type
            )));
        }
    };

    let entry = app_state
        .exclusion_repository
        .create(
            &ExclusionCreate {
                object_type: object_type.clone(),
                object_value: asset.identifier.clone(),
                reason: payload.reason,
                delete_descendants: payload.delete_descendants,
                blacklisted: payload.blacklisted,
            },
            user.email.as_deref(),
            company_id,
        )
        .await?;

    let result = apply_entry(
        &app_state,
        company_id,
        entry,
        &object_type,
        &asset.identifier,
        payload.delete_descendants,
        Some(asset_id),
    )
    .await?;

    tracing::info!(
        "User {} excluded asset {} ({} '{}', blacklisted: {}), deleted {} assets and \
         {} descendants, removed {} queued items, cancelled {} scans",
        user.email.as_deref().unwrap_or("unknown"),
        asset_id,
        object_type,
        asset.identifier,
        result.entry.blacklisted,
        result.assets_deleted,
        result.descendants_deleted,
        result.queue_items_removed,
        result.scans_cancelled
    );

    Ok(Json(result))
}

/// GET /api/exclusions/stats - Get exclusion statistics
#[derive(Debug, Serialize)]
pub struct ExclusionStats {
    pub total_entries: i64,
    pub by_type: std::collections::HashMap<String, i64>,
    /// How many of the entries are the hard kind, so the page can say so
    /// without counting rows it has not paged in.
    pub blacklisted_entries: i64,
}

pub async fn get_exclusion_stats(
    State(app_state): State<AppState>,
    Extension(user): Extension<UserContext>,
) -> Result<Json<ExclusionStats>, ApiError> {
    let company_id = company_scope(&user)?;
    let total_entries = app_state.exclusion_repository.count(company_id).await?;
    let blacklisted_entries = app_state
        .exclusion_repository
        .count_blacklisted(company_id)
        .await?;

    // Get counts by type
    let mut by_type = std::collections::HashMap::new();
    for obj_type in [
        ExclusionObjectType::Domain,
        ExclusionObjectType::Ip,
        ExclusionObjectType::Organization,
        ExclusionObjectType::Asn,
        ExclusionObjectType::Cidr,
        ExclusionObjectType::Certificate,
    ] {
        // This is not efficient but works for now - ideally we'd have a count_by_type method
        let count = app_state
            .exclusion_repository
            .search(None, Some(&obj_type), company_id, 1, 0)
            .await?
            .1;
        by_type.insert(obj_type.to_string(), count);
    }

    Ok(Json(ExclusionStats {
        total_entries,
        by_type,
        blacklisted_entries,
    }))
}
