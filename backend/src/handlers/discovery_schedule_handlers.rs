use axum::{
    extract::{Extension, Path, State},
    response::Json,
};
use serde::Deserialize;
use serde_json::{json, Value};
use uuid::Uuid;

use crate::{
    auth::context::UserContext,
    error::ApiError,
    models::{
        DiscoveryConfig, DiscoverySchedule, DiscoveryScheduleCreate, DiscoveryScheduleUpdate,
    },
    AppState,
};

#[derive(Debug, Deserialize)]
pub struct CreateDiscoveryScheduleRequest {
    pub name: String,
    pub cron: String,
    pub enabled: Option<bool>,
    pub config: Option<DiscoveryConfig>,
}

#[derive(Debug, Deserialize, Default)]
pub struct UpdateDiscoveryScheduleRequest {
    pub name: Option<String>,
    pub cron: Option<String>,
    pub enabled: Option<bool>,
    pub config: Option<DiscoveryConfig>,
}

/// GET /api/discovery/schedules - List discovery schedules
pub async fn list_discovery_schedules(
    State(app_state): State<AppState>,
    Extension(user): Extension<UserContext>,
) -> Result<Json<Vec<DiscoverySchedule>>, ApiError> {
    let company_id = user.company_id.ok_or_else(|| {
        ApiError::Authorization("Company scope required for schedules".to_string())
    })?;
    let schedules = app_state
        .discovery_schedule_service
        .list_schedules(company_id)
        .await?;
    Ok(Json(schedules))
}

/// POST /api/discovery/schedules - Create a new discovery schedule
pub async fn create_discovery_schedule(
    State(app_state): State<AppState>,
    Extension(user): Extension<UserContext>,
    Json(payload): Json<CreateDiscoveryScheduleRequest>,
) -> Result<Json<DiscoverySchedule>, ApiError> {
    let company_id = user.company_id.ok_or_else(|| {
        ApiError::Authorization("Company scope required for schedules".to_string())
    })?;
    let config_value = payload
        .config
        .map(serde_json::to_value)
        .transpose()?
        .unwrap_or_else(|| json!({}));

    let schedule = DiscoveryScheduleCreate {
        name: payload.name,
        cron: payload.cron,
        enabled: payload.enabled,
        config: Some(config_value),
    };

    let created = app_state
        .discovery_schedule_service
        .create_schedule(company_id, schedule)
        .await?;

    Ok(Json(created))
}

/// PATCH /api/discovery/schedules/:id - Update a discovery schedule
pub async fn update_discovery_schedule(
    State(app_state): State<AppState>,
    Extension(user): Extension<UserContext>,
    Path(id): Path<Uuid>,
    Json(payload): Json<UpdateDiscoveryScheduleRequest>,
) -> Result<Json<DiscoverySchedule>, ApiError> {
    let company_id = user.company_id.ok_or_else(|| {
        ApiError::Authorization("Company scope required for schedules".to_string())
    })?;
    let config_value: Option<Value> = payload.config.map(serde_json::to_value).transpose()?;

    let update = DiscoveryScheduleUpdate {
        name: payload.name,
        cron: payload.cron,
        enabled: payload.enabled,
        config: config_value,
    };

    let updated = app_state
        .discovery_schedule_service
        .update_schedule(company_id, &id, update)
        .await?;

    Ok(Json(updated))
}

/// DELETE /api/discovery/schedules/:id - Delete a discovery schedule
pub async fn delete_discovery_schedule(
    State(app_state): State<AppState>,
    Extension(user): Extension<UserContext>,
    Path(id): Path<Uuid>,
) -> Result<Json<Value>, ApiError> {
    let company_id = user.company_id.ok_or_else(|| {
        ApiError::Authorization("Company scope required for schedules".to_string())
    })?;
    app_state
        .discovery_schedule_service
        .delete_schedule(company_id, &id)
        .await?;

    Ok(Json(json!({
        "message": "Discovery schedule deleted"
    })))
}
