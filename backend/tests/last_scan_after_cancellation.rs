//! What Surface's LAST SCAN column reads once a scan has been cancelled.
//!
//! A cancelled scan looked at nothing, so it cannot be the asset's last scan.
//! The column falls back to the newest scan that did look; failing that it says
//! "Cancelled", because an operator who has just stopped a scan is the last
//! person who should be told the host was never scanned. Only an asset nothing
//! has ever been queued against reads "Never". The three cancellation paths —
//! the stop button on the scan's row in Ops, stopping the discovery run that
//! queued it, and blacklisting the target mid-scan — all land in the same place.
//!
//! The rule lives in the `assets_enriched` view, one join below every read path,
//! so these go through the repository search the Surface page actually calls
//! rather than asserting on SQL.
//!
//! Requires `DATABASE_URL`. Skipped, loudly, when it is not set.

use chrono::{DateTime, Duration, Utc};
use rust_backend::models::{
    Asset, DiscoveryRunCreate, ScanTriggerType, SecurityScanCreate, SecurityScanType, TriggerType,
};
use rust_backend::{config, AppState};
use serde_json::json;
use uuid::Uuid;

fn database_url() -> Option<String> {
    std::env::var("DATABASE_URL").ok()
}

async fn app_state() -> AppState {
    let db_url = database_url().expect("checked by the caller");
    std::env::set_var("LOG_LEVEL", "error");
    // A production configuration demands API keys these tests have no use for;
    // nothing here reaches an external service.
    std::env::set_var("ENVIRONMENT", "development");

    let settings = config::Settings::new_with_env_file(false).expect("settings");
    let pool = rust_backend::database::create_connection_pool(&db_url)
        .await
        .expect("database pool");

    AppState::new_with_pool(settings, pool)
        .await
        .expect("app state")
}

/// A company of its own per test, so one test's assets cannot answer another's
/// search.
async fn company(state: &AppState) -> Uuid {
    let company_id = Uuid::new_v4();
    sqlx::query("INSERT INTO companies (id, name) VALUES ($1, $2)")
        .bind(company_id)
        .bind(format!("last-scan-test-{company_id}"))
        .execute(&state.db_pool)
        .await
        .expect("insert company");
    company_id
}

/// An asset with an identifier unique to this run, so `search` can find it by
/// query string without a second company's row matching too.
async fn asset(state: &AppState, company_id: Uuid) -> (Uuid, String) {
    let asset_id = Uuid::new_v4();
    let identifier = format!("host-{}.example.test", asset_id.simple());
    sqlx::query(
        "INSERT INTO assets (id, asset_type, identifier, confidence, company_id, metadata)
         VALUES ($1, 'domain'::asset_type, $2, 1.0, $3, '{}'::jsonb)",
    )
    .bind(asset_id)
    .bind(&identifier)
    .bind(company_id)
    .execute(&state.db_pool)
    .await
    .expect("insert asset");
    (asset_id, identifier)
}

async fn pending_scan(
    state: &AppState,
    company_id: Uuid,
    asset_id: Uuid,
    discovery_run_id: Option<Uuid>,
) -> Uuid {
    state
        .security_scan_repository
        .create(
            &SecurityScanCreate {
                asset_id,
                scan_type: Some(SecurityScanType::Full),
                trigger_type: Some(ScanTriggerType::Discovery),
                priority: Some(3),
                note: None,
                config: None,
                discovery_run_id,
            },
            company_id,
        )
        .await
        .expect("create scan")
        .id
}

/// Push a scan back in time. "Latest" is `created_at` order, and rows written a
/// few microseconds apart make for a test that asserts on clock resolution;
/// an explicit hour makes the intended history unambiguous.
async fn backdate(state: &AppState, scan_id: Uuid, hours: i64) {
    sqlx::query("UPDATE security_scans SET created_at = $2 WHERE id = $1")
        .bind(scan_id)
        .bind(Utc::now() - Duration::hours(hours))
        .execute(&state.db_pool)
        .await
        .expect("backdate scan");
}

/// The asset as the Surface list sees it: the same repository search the
/// `/api/assets/search` handler runs, narrowed to this one identifier.
async fn from_surface(state: &AppState, company_id: Uuid, identifier: &str) -> Asset {
    let (assets, total, _) = state
        .asset_repository
        .search(
            company_id,
            Some(identifier),
            None,
            None,
            None,
            None,
            None,
            "created_at",
            "desc",
            25,
            0,
        )
        .await
        .expect("search assets");

    assert_eq!(total, 1, "one asset should match {identifier}");
    assets.into_iter().next().expect("the matched asset")
}

/// The three columns that drive LAST SCAN, together: they are written from one
/// join and a test that checks only the id would pass with a stale timestamp
/// still on screen.
fn last_scan(asset: &Asset) -> (Option<String>, Option<String>, Option<DateTime<Utc>>) {
    (
        asset.last_scan_id.clone(),
        asset.last_scan_status.clone(),
        asset.last_scanned_at,
    )
}

/// What the column actually renders, so the assertions read as the three states
/// an operator can see rather than as a nullability puzzle.
#[derive(Debug, PartialEq, Eq)]
enum Column {
    Scan(String),
    Cancelled,
    Never,
}

fn column(asset: &Asset) -> Column {
    match (asset.last_scanned_at, asset.last_cancelled_scan_at) {
        (Some(_), _) => Column::Scan(
            asset
                .last_scan_status
                .clone()
                .expect("a scan time comes with its status"),
        ),
        (None, Some(_)) => Column::Cancelled,
        (None, None) => Column::Never,
    }
}

#[tokio::test]
async fn cancelling_an_assets_only_scan_reads_cancelled_not_never() {
    let Some(_) = database_url() else {
        eprintln!("DATABASE_URL not set — skipping");
        return;
    };
    let state = app_state().await;
    let company_id = company(&state).await;
    let (asset_id, identifier) = asset(&state, company_id).await;

    let scan_id = pending_scan(&state, company_id, asset_id, None).await;
    state
        .security_scan_service
        .cancel_scan(&scan_id, company_id)
        .await
        .expect("cancel scan");

    let asset = from_surface(&state, company_id, &identifier).await;
    let (id, status, at) = last_scan(&asset);
    // Nothing looked at this host, so no scan time is reported -- not the fresh
    // one from the moment the operator stopped it.
    assert_eq!(id, None, "a cancelled scan is not the last scan");
    assert_eq!(status, None);
    assert_eq!(at, None, "no scan time is reported for a cancelled scan");
    // But the column still has to account for the attempt. "Never" would tell
    // the operator who just stopped the scan that it never existed.
    assert_eq!(column(&asset), Column::Cancelled);
    assert!(asset.last_cancelled_scan_at.is_some());
}

#[tokio::test]
async fn an_asset_that_was_never_scanned_still_reads_never() {
    let Some(_) = database_url() else {
        eprintln!("DATABASE_URL not set — skipping");
        return;
    };
    let state = app_state().await;
    let company_id = company(&state).await;
    let (_, identifier) = asset(&state, company_id).await;

    // The boundary "Cancelled" has to keep: an asset nothing was ever queued
    // against is a different state, and it is the one that reads "Never".
    let asset = from_surface(&state, company_id, &identifier).await;
    assert_eq!(column(&asset), Column::Never);
    assert_eq!(asset.last_cancelled_scan_at, None);
}

#[tokio::test]
async fn cancelling_a_scan_falls_back_to_the_last_completed_one() {
    let Some(_) = database_url() else {
        eprintln!("DATABASE_URL not set — skipping");
        return;
    };
    let state = app_state().await;
    let company_id = company(&state).await;
    let (asset_id, identifier) = asset(&state, company_id).await;

    let completed = pending_scan(&state, company_id, asset_id, None).await;
    backdate(&state, completed, 3).await;
    state
        .security_scan_repository
        .complete(&completed, &json!({}), company_id)
        .await
        .expect("complete scan");

    let cancelled = pending_scan(&state, company_id, asset_id, None).await;
    state
        .security_scan_service
        .cancel_scan(&cancelled, company_id)
        .await
        .expect("cancel scan");

    let asset = from_surface(&state, company_id, &identifier).await;
    let (id, status, at) = last_scan(&asset);
    // What the asset actually knows about itself is three hours old, and that is
    // what the column has to say -- a real scan outranks the cancellation, which
    // stays on the record without taking the column over.
    assert_eq!(id, Some(completed.to_string()), "the surviving scan wins");
    assert_eq!(status.as_deref(), Some("completed"));
    assert_eq!(column(&asset), Column::Scan("completed".to_string()));
    assert!(
        asset.last_cancelled_scan_at.is_some(),
        "the cancellation is still recorded, it just does not win"
    );
    assert!(
        at.expect("a scan time") < Utc::now() - Duration::hours(2),
        "the timestamp is the completed scan's, not the cancellation's"
    );
}

#[tokio::test]
async fn a_failed_scan_still_counts_as_the_last_scan() {
    let Some(_) = database_url() else {
        eprintln!("DATABASE_URL not set — skipping");
        return;
    };
    let state = app_state().await;
    let company_id = company(&state).await;
    let (asset_id, identifier) = asset(&state, company_id).await;

    let failed = pending_scan(&state, company_id, asset_id, None).await;
    backdate(&state, failed, 1).await;
    state
        .security_scan_repository
        .fail(&failed, "connection refused", company_id)
        .await
        .expect("fail scan");

    let cancelled = pending_scan(&state, company_id, asset_id, None).await;
    state
        .security_scan_service
        .cancel_scan(&cancelled, company_id)
        .await
        .expect("cancel scan");

    let asset = from_surface(&state, company_id, &identifier).await;
    let (id, status, _) = last_scan(&asset);
    // Only cancellation is excluded. A failed scan did reach the host and has a
    // result to show, so hiding it would lose the one signal that says the last
    // attempt went wrong.
    assert_eq!(id, Some(failed.to_string()));
    assert_eq!(status.as_deref(), Some("failed"));
    assert_eq!(column(&asset), Column::Scan("failed".to_string()));
}

#[tokio::test]
async fn a_scan_in_flight_is_still_reported() {
    let Some(_) = database_url() else {
        eprintln!("DATABASE_URL not set — skipping");
        return;
    };
    let state = app_state().await;
    let company_id = company(&state).await;
    let (asset_id, identifier) = asset(&state, company_id).await;

    let running = pending_scan(&state, company_id, asset_id, None).await;
    state
        .security_scan_repository
        .start(&running, company_id)
        .await
        .expect("start scan");

    let asset = from_surface(&state, company_id, &identifier).await;
    let (id, status, at) = last_scan(&asset);
    // The list renders `running` with its own marker; dropping unfinished scans
    // alongside cancelled ones would make a scan disappear from the column for
    // exactly as long as it was running.
    assert_eq!(id, Some(running.to_string()));
    assert_eq!(status.as_deref(), Some("running"));
    assert!(at.is_some());
    assert_eq!(column(&asset), Column::Scan("running".to_string()));
}

#[tokio::test]
async fn stopping_a_discovery_run_leaves_the_assets_it_queued_reading_cancelled() {
    let Some(_) = database_url() else {
        eprintln!("DATABASE_URL not set — skipping");
        return;
    };
    let state = app_state().await;
    let company_id = company(&state).await;

    let run = state
        .discovery_run_repository
        .create(
            &DiscoveryRunCreate {
                trigger_type: Some(TriggerType::Manual),
                config: None,
            },
            company_id,
        )
        .await
        .expect("create run");

    let (never_scanned, never_scanned_id) = asset(&state, company_id).await;
    let (scanned_before, scanned_before_id) = asset(&state, company_id).await;

    let earlier = pending_scan(&state, company_id, scanned_before, None).await;
    backdate(&state, earlier, 6).await;
    state
        .security_scan_repository
        .complete(&earlier, &json!({}), company_id)
        .await
        .expect("complete earlier scan");

    pending_scan(&state, company_id, never_scanned, Some(run.id)).await;
    pending_scan(&state, company_id, scanned_before, Some(run.id)).await;

    let cancelled = state
        .security_scan_service
        .cancel_scans_for_discovery_run(&run.id, company_id)
        .await
        .expect("cancel scans for run");
    assert_eq!(cancelled, 2);

    // Stopping a run cancels every scan it had outstanding at once, so this is
    // where a cancelled row masquerading as the last scan showed up in bulk.
    let stopped = from_surface(&state, company_id, &never_scanned_id).await;
    let (id, _, at) = last_scan(&stopped);
    assert_eq!(id, None);
    assert_eq!(at, None);
    assert_eq!(column(&stopped), Column::Cancelled);

    let kept = from_surface(&state, company_id, &scanned_before_id).await;
    let (id, status, _) = last_scan(&kept);
    assert_eq!(
        id,
        Some(earlier.to_string()),
        "the pre-run scan still stands"
    );
    assert_eq!(status.as_deref(), Some("completed"));
    assert_eq!(column(&kept), Column::Scan("completed".to_string()));
}

#[tokio::test]
async fn blacklisting_an_asset_mid_scan_leaves_it_reading_cancelled() {
    let Some(_) = database_url() else {
        eprintln!("DATABASE_URL not set — skipping");
        return;
    };
    let state = app_state().await;
    let company_id = company(&state).await;
    let (asset_id, identifier) = asset(&state, company_id).await;

    let scan_id = pending_scan(&state, company_id, asset_id, None).await;
    state
        .security_scan_repository
        .start(&scan_id, company_id)
        .await
        .expect("start scan");

    let cancelled = state
        .security_scan_service
        .cancel_scans_for_assets(&[asset_id], company_id, "Cancelled: target blacklisted")
        .await
        .expect("cancel scans for assets");
    assert_eq!(cancelled, 1);

    let asset = from_surface(&state, company_id, &identifier).await;
    let (id, status, at) = last_scan(&asset);
    // A scan stopped part-way through a blacklisted host is the case where a
    // timestamp is most misleading: it reads as a completed look at a target we
    // have just undertaken not to touch.
    assert_eq!(id, None);
    assert_eq!(status, None);
    assert_eq!(at, None);
    assert_eq!(column(&asset), Column::Cancelled);
}

#[tokio::test]
async fn an_asset_whose_only_scan_was_cancelled_filters_as_never_scanned() {
    let Some(_) = database_url() else {
        eprintln!("DATABASE_URL not set — skipping");
        return;
    };
    let state = app_state().await;
    let company_id = company(&state).await;
    let (asset_id, identifier) = asset(&state, company_id).await;

    let scan_id = pending_scan(&state, company_id, asset_id, None).await;
    state
        .security_scan_service
        .cancel_scan(&scan_id, company_id)
        .await
        .expect("cancel scan");

    let matches = |scan_status: &'static str| {
        let identifier = identifier.clone();
        let state = &state;
        async move {
            let (assets, _, _) = state
                .asset_repository
                .search(
                    company_id,
                    Some(&identifier),
                    None,
                    None,
                    Some(scan_status),
                    None,
                    None,
                    "created_at",
                    "desc",
                    25,
                    0,
                )
                .await
                .expect("search assets");
            assets.len()
        }
    };

    // Surface's own "Never scanned" / "Scanned" facet reads the same column, so
    // the two have to agree: an asset the column calls never scanned cannot be
    // in the scanned bucket.
    assert_eq!(matches("never_scanned").await, 1);
    assert_eq!(matches("scanned").await, 0);
}
