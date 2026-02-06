use chrono::{DateTime, Utc};
use chrono_tz::Tz;
use cron::Schedule;
use serde_json::{json, Value};
use std::str::FromStr;
use std::sync::Arc;
use tokio::time::{sleep, Duration};
use uuid::Uuid;

use crate::{
    error::ApiError,
    models::{DiscoveryConfig, DiscoverySchedule, DiscoveryScheduleCreate, DiscoveryScheduleUpdate, TriggerType},
    repositories::DiscoveryScheduleRepository,
    services::DiscoveryService,
};

pub struct DiscoveryScheduleService {
    schedule_repo: Arc<dyn DiscoveryScheduleRepository + Send + Sync>,
    discovery_service: Arc<DiscoveryService>,
}

impl DiscoveryScheduleService {
    pub fn new(
        schedule_repo: Arc<dyn DiscoveryScheduleRepository + Send + Sync>,
        discovery_service: Arc<DiscoveryService>,
    ) -> Self {
        Self {
            schedule_repo,
            discovery_service,
        }
    }

    pub async fn list_schedules(
        &self,
        company_id: Uuid,
    ) -> Result<Vec<DiscoverySchedule>, ApiError> {
        self.schedule_repo.list(company_id).await
    }

    pub async fn create_schedule(
        &self,
        company_id: Uuid,
        schedule: DiscoveryScheduleCreate,
    ) -> Result<DiscoverySchedule, ApiError> {
        if schedule.name.trim().is_empty() {
            return Err(ApiError::Validation(
                "Schedule name is required".to_string(),
            ));
        }
        let normalized_cron = Self::normalize_cron_expression(&schedule.cron)?;
        let enabled = schedule.enabled.unwrap_or(true);
        let mut config = schedule.config.unwrap_or_else(|| json!({}));
        let timezone = Self::resolve_timezone(&config, None)?;
        Self::ensure_timezone(&mut config, timezone.name());
        let next_run_at = if enabled {
            Self::compute_next_run(&normalized_cron, Utc::now(), timezone)?
        } else {
            None
        };

        self.schedule_repo
            .create(
                company_id,
                &schedule.name,
                &normalized_cron,
                enabled,
                &config,
                next_run_at,
            )
            .await
    }

    pub async fn update_schedule(
        &self,
        company_id: Uuid,
        id: &Uuid,
        update: DiscoveryScheduleUpdate,
    ) -> Result<DiscoverySchedule, ApiError> {
        let existing = self
            .schedule_repo
            .get_by_id(company_id, id)
            .await?
            .ok_or_else(|| ApiError::NotFound(format!("Discovery schedule {} not found", id)))?;

        let name = update.name.unwrap_or_else(|| existing.name.clone());
        if name.trim().is_empty() {
            return Err(ApiError::Validation(
                "Schedule name is required".to_string(),
            ));
        }
        let cron_updated = update.cron.is_some();
        let cron = match update.cron {
            Some(value) => Self::normalize_cron_expression(&value)?,
            None => existing.cron.clone(),
        };
        let enabled_updated = update.enabled.is_some();
        let enabled = update.enabled.unwrap_or(existing.enabled);
        let mut config = update.config.unwrap_or_else(|| existing.config.clone());
        let timezone = Self::resolve_timezone(&config, Some(&existing.config))?;
        Self::ensure_timezone(&mut config, timezone.name());
        let next_run_at = if !enabled {
            None
        } else if cron_updated || enabled_updated || existing.next_run_at.is_none() {
            Self::compute_next_run(&cron, Utc::now(), timezone)?
        } else {
            existing.next_run_at
        };

        self.schedule_repo
            .update(
                company_id,
                id,
                &name,
                &cron,
                enabled,
                &config,
                existing.last_run_at,
                next_run_at,
            )
            .await
    }

    pub async fn delete_schedule(&self, company_id: Uuid, id: &Uuid) -> Result<(), ApiError> {
        self.schedule_repo.delete(company_id, id).await
    }

    pub fn start(self: Arc<Self>) {
        tokio::spawn(async move {
            loop {
                if let Err(e) = self.run_due_schedules().await {
                    tracing::warn!("Discovery schedule runner error: {}", e);
                }
                sleep(Duration::from_secs(30)).await;
            }
        });
    }

    async fn run_due_schedules(&self) -> Result<(), ApiError> {
        let now = Utc::now();
        let schedules = self.schedule_repo.list_due(now).await?;

        for schedule in schedules {
            if let Err(e) = self.process_due_schedule(schedule, now).await {
                tracing::warn!("Failed to process discovery schedule: {}", e);
            }
        }

        Ok(())
    }

    async fn process_due_schedule(
        &self,
        schedule: DiscoverySchedule,
        now: DateTime<Utc>,
    ) -> Result<(), ApiError> {
        let normalized_cron = match Self::normalize_cron_expression(&schedule.cron) {
            Ok(value) => value,
            Err(e) => {
                tracing::warn!(
                    "Invalid cron expression for discovery schedule {}: {}",
                    schedule.id,
                    e
                );
                return Ok(());
            }
        };
        let timezone = Self::resolve_timezone(&schedule.config, None)?;
        let next_run_at = Self::compute_next_run(&normalized_cron, now, timezone)?;
        let mut last_run_at = schedule.last_run_at;

        let should_run = schedule
            .next_run_at
            .map(|next| next <= now)
            .unwrap_or(true);

        if should_run {
            let config = Self::parse_config(schedule.config.clone());
            match self
                .discovery_service
                .run_discovery_with_trigger(
                    schedule.company_id,
                    config,
                    TriggerType::Scheduled,
                    None,
                )
                .await
            {
                Ok(_) => {
                    last_run_at = Some(now);
                }
                Err(e) => {
                    tracing::warn!(
                        "Scheduled discovery failed for schedule {}: {}",
                        schedule.id,
                        e
                    );
                }
            }
        }

        self.schedule_repo
            .update_run_times(
                schedule.company_id,
                &schedule.id,
                last_run_at,
                next_run_at,
            )
            .await?;

        Ok(())
    }

    fn normalize_cron_expression(expr: &str) -> Result<String, ApiError> {
        let trimmed = expr.trim();
        if trimmed.is_empty() {
            return Err(ApiError::Validation(
                "Cron expression is required".to_string(),
            ));
        }

        let parts: Vec<&str> = trimmed.split_whitespace().collect();
        let candidates = match parts.len() {
            5 => vec![format!("0 {}", trimmed), format!("0 {} *", trimmed)],
            6 => vec![trimmed.to_string(), format!("{} *", trimmed)],
            7 => vec![trimmed.to_string()],
            _ => {
                return Err(ApiError::Validation(
                    "Cron expression must have 5, 6, or 7 fields".to_string(),
                ))
            }
        };

        for candidate in candidates {
            if Schedule::from_str(&candidate).is_ok() {
                return Ok(candidate);
            }
        }

        Err(ApiError::Validation(
            "Invalid cron expression".to_string(),
        ))
    }

    fn compute_next_run(
        cron: &str,
        now: DateTime<Utc>,
        timezone: Tz,
    ) -> Result<Option<DateTime<Utc>>, ApiError> {
        let schedule = Schedule::from_str(cron).map_err(|e| {
            ApiError::Validation(format!("Invalid cron expression: {}", e))
        })?;

        let now_tz = now.with_timezone(&timezone);
        Ok(schedule
            .after(&now_tz)
            .next()
            .map(|dt| dt.with_timezone(&Utc)))
    }

    fn parse_config(value: Value) -> Option<DiscoveryConfig> {
        if value.is_null() {
            return None;
        }

        serde_json::from_value::<DiscoveryConfig>(value).ok()
    }

    fn resolve_timezone(config: &Value, fallback: Option<&Value>) -> Result<Tz, ApiError> {
        let tz_str = config
            .get("timezone")
            .and_then(|v| v.as_str())
            .filter(|value| !value.trim().is_empty())
            .or_else(|| {
                fallback
                    .and_then(|value| value.get("timezone"))
                    .and_then(|v| v.as_str())
                    .filter(|value| !value.trim().is_empty())
            })
            .unwrap_or("UTC");

        tz_str
            .parse::<Tz>()
            .map_err(|_| ApiError::Validation(format!("Invalid timezone: {}", tz_str)))
    }

    fn ensure_timezone(config: &mut Value, timezone: &str) {
        match config.as_object_mut() {
            Some(map) => {
                map.entry("timezone".to_string())
                    .or_insert_with(|| json!(timezone));
            }
            None => {
                *config = json!({ "timezone": timezone });
            }
        }
    }
}
