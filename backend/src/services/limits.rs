use std::collections::HashMap;
use std::time::{Duration, Instant};
use tokio::sync::Mutex;
use uuid::Uuid;

use crate::error::ApiError;

/// Simple per-company limiter for expensive operations like reindexing.
pub struct ReindexLimiter {
    last_run: Mutex<HashMap<Uuid, Instant>>,
}

impl ReindexLimiter {
    pub fn new() -> Self {
        Self {
            last_run: Mutex::new(HashMap::new()),
        }
    }

    pub async fn check_and_update(
        &self,
        company_id: Uuid,
        min_interval: Duration,
    ) -> Result<(), ApiError> {
        let mut guard = self.last_run.lock().await;
        if let Some(last) = guard.get(&company_id) {
            let elapsed = last.elapsed();
            if elapsed < min_interval {
                let remaining = min_interval - elapsed;
                return Err(ApiError::RateLimit(format!(
                    "Reindex allowed every {}s (try again in {}s)",
                    min_interval.as_secs(),
                    remaining.as_secs()
                )));
            }
        }

        guard.insert(company_id, Instant::now());
        Ok(())
    }
}
