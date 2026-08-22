//! What stopping a discovery run, and excluding during one, are supposed to
//! reach.
//!
//! These behaviours all cross a service boundary that unit tests cannot see
//! over — the discovery service owns the run, the scan service owns the scans
//! it queued, and the exclusion list owns neither — so they are exercised
//! against a real database through the real services.
//!
//! Requires `DATABASE_URL`. Skipped, loudly, when it is not set.

use rust_backend::models::{
    DiscoveryQueueItemCreate, DiscoveryRunCreate, ExclusionCreate, ExclusionObjectType,
    ExclusionUpdate, QueueItemType, ScanTriggerType, SecurityScanCreate, SecurityScanType,
    TriggerType,
};
use rust_backend::{config, AppState};
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

/// A company of its own per test, so runs and exclusions cannot collide.
async fn company(state: &AppState) -> Uuid {
    let company_id = Uuid::new_v4();
    sqlx::query("INSERT INTO companies (id, name) VALUES ($1, $2)")
        .bind(company_id)
        .bind(format!("stop-exclusion-test-{}", company_id))
        .execute(&state.db_pool)
        .await
        .expect("insert company");
    company_id
}

async fn asset(state: &AppState, company_id: Uuid, asset_type: &str, identifier: &str) -> Uuid {
    let asset_id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO assets (id, asset_type, identifier, confidence, company_id, metadata)
         VALUES ($1, $2::asset_type, $3, 1.0, $4, '{}'::jsonb)",
    )
    .bind(asset_id)
    .bind(asset_type)
    .bind(identifier)
    .bind(company_id)
    .execute(&state.db_pool)
    .await
    .expect("insert asset");
    asset_id
}

/// An asset discovered *through* another one, which is what the blacklist
/// purge follows when it deletes descendants.
async fn child_asset(
    state: &AppState,
    company_id: Uuid,
    asset_type: &str,
    identifier: &str,
    parent_id: Uuid,
) -> Uuid {
    let asset_id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO assets (id, asset_type, identifier, confidence, company_id, metadata, parent_id)
         VALUES ($1, $2::asset_type, $3, 1.0, $4, '{}'::jsonb, $5)",
    )
    .bind(asset_id)
    .bind(asset_type)
    .bind(identifier)
    .bind(company_id)
    .bind(parent_id)
    .execute(&state.db_pool)
    .await
    .expect("insert child asset");
    asset_id
}

async fn asset_exists(state: &AppState, asset_id: Uuid) -> bool {
    sqlx::query_scalar::<_, bool>("SELECT EXISTS(SELECT 1 FROM assets WHERE id = $1)")
        .bind(asset_id)
        .fetch_one(&state.db_pool)
        .await
        .expect("read asset existence")
}

async fn scan_status(state: &AppState, scan_id: Uuid) -> String {
    sqlx::query_scalar::<_, String>("SELECT status FROM security_scans WHERE id = $1")
        .bind(scan_id)
        .fetch_one(&state.db_pool)
        .await
        .expect("read scan status")
}

async fn queue_status(state: &AppState, run_id: Uuid, item_value: &str) -> Option<String> {
    sqlx::query_scalar::<_, String>(
        "SELECT status FROM discovery_queue WHERE discovery_run_id = $1 AND item_value = $2",
    )
    .bind(run_id)
    .bind(item_value)
    .fetch_optional(&state.db_pool)
    .await
    .expect("read queue status")
}

/// Queue an item directly, bypassing the discovery loop.
async fn enqueue(state: &AppState, run_id: Uuid, item_type: QueueItemType, item_value: &str) {
    state
        .discovery_queue_repository
        .enqueue(&DiscoveryQueueItemCreate {
            discovery_run_id: run_id,
            item_type,
            item_value: item_value.to_string(),
            parent_asset_id: None,
            seed_id: None,
            depth: 1,
            priority: 5,
        })
        .await
        .expect("enqueue");
}

/// A pending scan row attributed to `discovery_run_id`, without submitting a
/// task: these tests are about what cancellation writes, not about scanning.
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

#[tokio::test]
async fn stopping_a_run_cancels_the_scans_it_queued_and_leaves_the_others_alone() {
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

    let other_run = state
        .discovery_run_repository
        .create(
            &DiscoveryRunCreate {
                trigger_type: Some(TriggerType::Manual),
                config: None,
            },
            company_id,
        )
        .await
        .expect("create other run");

    let asset_a = asset(&state, company_id, "domain", "a.example.test").await;
    let asset_b = asset(&state, company_id, "domain", "b.example.test").await;

    let from_run = pending_scan(&state, company_id, asset_a, Some(run.id)).await;
    let from_other_run = pending_scan(&state, company_id, asset_b, Some(other_run.id)).await;
    let manual = pending_scan(&state, company_id, asset_b, None).await;

    let cancelled = state
        .security_scan_service
        .cancel_scans_for_discovery_run(&run.id, company_id)
        .await
        .expect("cancel scans for run");

    assert_eq!(cancelled, 1, "only this run's scans are cancelled");
    assert_eq!(scan_status(&state, from_run).await, "cancelled");
    // A scan belonging to another run, and a manual scan, are somebody else's
    // work: stopping this run must not touch either.
    assert_eq!(scan_status(&state, from_other_run).await, "pending");
    assert_eq!(scan_status(&state, manual).await, "pending");
}

#[tokio::test]
async fn cancelling_a_run_twice_is_harmless() {
    let Some(_) = database_url() else {
        eprintln!("DATABASE_URL not set — skipping");
        return;
    };
    let state = app_state().await;
    let company_id = company(&state).await;

    let run = state
        .discovery_run_repository
        .create(&DiscoveryRunCreate::default(), company_id)
        .await
        .expect("create run");
    let asset_id = asset(&state, company_id, "domain", "twice.example.test").await;
    let scan_id = pending_scan(&state, company_id, asset_id, Some(run.id)).await;

    let first = state
        .security_scan_service
        .cancel_scans_for_discovery_run(&run.id, company_id)
        .await
        .expect("first cancel");
    // Both `stop_discovery` and the run's own finaliser can reach this, so the
    // second pass has to be a no-op rather than a double-cancel.
    let second = state
        .security_scan_service
        .cancel_scans_for_discovery_run(&run.id, company_id)
        .await
        .expect("second cancel");

    assert_eq!(first, 1);
    assert_eq!(second, 0);
    assert_eq!(scan_status(&state, scan_id).await, "cancelled");
}

#[tokio::test]
async fn blacklisting_mid_run_clears_the_queue_and_stops_the_scans() {
    let Some(_) = database_url() else {
        eprintln!("DATABASE_URL not set — skipping");
        return;
    };
    let state = app_state().await;
    let company_id = company(&state).await;

    let run = state
        .discovery_run_repository
        .create(&DiscoveryRunCreate::default(), company_id)
        .await
        .expect("create run");
    state
        .discovery_run_repository
        .start(company_id, &run.id)
        .await
        .expect("start run");

    // Two names under the domain about to be blacklisted, and one that is not.
    enqueue(&state, run.id, QueueItemType::Domain, "blocked.test").await;
    enqueue(&state, run.id, QueueItemType::Domain, "api.blocked.test").await;
    enqueue(&state, run.id, QueueItemType::Domain, "keep.test").await;

    let blocked_asset = asset(&state, company_id, "domain", "api.blocked.test").await;
    let kept_asset = asset(&state, company_id, "domain", "keep.test").await;
    let blocked_scan = pending_scan(&state, company_id, blocked_asset, Some(run.id)).await;
    let kept_scan = pending_scan(&state, company_id, kept_asset, Some(run.id)).await;

    state
        .exclusion_repository
        .create(
            &ExclusionCreate {
                object_type: ExclusionObjectType::Domain,
                object_value: "blocked.test".to_string(),
                reason: None,
                delete_descendants: false,
                blacklisted: true,
            },
            None,
            company_id,
        )
        .await
        .expect("create exclusion entry");

    let (queue_removed, scans_cancelled) = state
        .discovery_service
        .apply_exclusion_entry(
            company_id,
            &ExclusionObjectType::Domain,
            "blocked.test",
            true,
        )
        .await
        .expect("apply exclusion entry");

    assert_eq!(queue_removed, 2, "the domain and its subdomain are dropped");
    assert_eq!(
        queue_status(&state, run.id, "blocked.test")
            .await
            .as_deref(),
        Some("skipped")
    );
    assert_eq!(
        queue_status(&state, run.id, "api.blocked.test")
            .await
            .as_deref(),
        Some("skipped")
    );
    // An unrelated name keeps its place in the queue.
    assert_eq!(
        queue_status(&state, run.id, "keep.test").await.as_deref(),
        Some("pending")
    );

    assert_eq!(scans_cancelled, 1);
    assert_eq!(scan_status(&state, blocked_scan).await, "cancelled");
    assert_eq!(scan_status(&state, kept_scan).await, "pending");

    // The queue count the UI reads has to agree with what is left.
    let pending = state
        .discovery_queue_repository
        .get_pending_count(&run.id)
        .await
        .expect("pending count");
    assert_eq!(pending, 1);
}

#[tokio::test]
async fn excluding_mid_run_clears_the_queue_but_leaves_the_scans_alone() {
    let Some(_) = database_url() else {
        eprintln!("DATABASE_URL not set — skipping");
        return;
    };
    let state = app_state().await;
    let company_id = company(&state).await;

    let run = state
        .discovery_run_repository
        .create(&DiscoveryRunCreate::default(), company_id)
        .await
        .expect("create run");
    state
        .discovery_run_repository
        .start(company_id, &run.id)
        .await
        .expect("start run");

    enqueue(&state, run.id, QueueItemType::Domain, "soft.test").await;
    enqueue(&state, run.id, QueueItemType::Domain, "api.soft.test").await;

    let kept = asset(&state, company_id, "domain", "api.soft.test").await;
    let scan = pending_scan(&state, company_id, kept, Some(run.id)).await;

    state
        .exclusion_repository
        .create(
            &ExclusionCreate {
                object_type: ExclusionObjectType::Domain,
                object_value: "soft.test".to_string(),
                reason: None,
                delete_descendants: false,
                blacklisted: false,
            },
            None,
            company_id,
        )
        .await
        .expect("create exclusion entry");

    let (queue_removed, scans_cancelled) = state
        .discovery_service
        .apply_exclusion_entry(company_id, &ExclusionObjectType::Domain, "soft.test", false)
        .await
        .expect("apply exclusion entry");

    // Queued items are plans to find *more* of this, which the exclusion ends.
    assert_eq!(queue_removed, 2);
    assert_eq!(
        queue_status(&state, run.id, "api.soft.test")
            .await
            .as_deref(),
        Some("skipped")
    );

    // The asset itself is the operator's and stays scannable: an ordinary
    // exclusion means "stop finding more", not "stop looking at what I have".
    assert_eq!(scans_cancelled, 0);
    assert_eq!(scan_status(&state, scan).await, "pending");
    assert!(asset_exists(&state, kept).await);
}

#[tokio::test]
async fn blacklisting_deletes_the_named_asset_and_its_descendants() {
    let Some(_) = database_url() else {
        eprintln!("DATABASE_URL not set — skipping");
        return;
    };
    let state = app_state().await;
    let company_id = company(&state).await;

    let root = asset(&state, company_id, "domain", "gone.test").await;
    let child = child_asset(&state, company_id, "domain", "api.gone.test", root).await;
    let grandchild = child_asset(&state, company_id, "ip", "203.0.113.5", child).await;
    // Matches the rule but was never discovered through the root, so it is not
    // a descendant: the purge leaves it for the rule to keep out later.
    let sibling = asset(&state, company_id, "domain", "orphan.gone.test").await;
    let unrelated = asset(&state, company_id, "domain", "keep.test").await;

    let deleted = state
        .exclusion_repository
        .purge_entry_assets(company_id, &ExclusionObjectType::Domain, "gone.test")
        .await
        .expect("purge entry assets");

    assert_eq!(deleted, 3, "the named asset and both of its descendants");
    assert!(!asset_exists(&state, root).await);
    assert!(!asset_exists(&state, child).await);
    assert!(!asset_exists(&state, grandchild).await);
    assert!(asset_exists(&state, sibling).await);
    assert!(asset_exists(&state, unrelated).await);
}

#[tokio::test]
async fn blacklisting_takes_the_findings_and_scans_with_the_asset() {
    let Some(_) = database_url() else {
        eprintln!("DATABASE_URL not set — skipping");
        return;
    };
    let state = app_state().await;
    let company_id = company(&state).await;

    let target = asset(&state, company_id, "domain", "scored.test").await;
    let scan = pending_scan(&state, company_id, target, None).await;
    sqlx::query(
        "INSERT INTO security_findings
             (id, asset_id, company_id, security_scan_id, finding_type, title, severity, status)
         VALUES (gen_random_uuid(), $1, $2, $3, 'test', 'test finding', 'high', 'open')",
    )
    .bind(target)
    .bind(company_id)
    .bind(scan)
    .execute(&state.db_pool)
    .await
    .expect("insert finding");

    state
        .exclusion_repository
        .purge_entry_assets(company_id, &ExclusionObjectType::Domain, "scored.test")
        .await
        .expect("purge entry assets");

    // "Removed from any score" is this: the findings the score reads are gone
    // with the asset, because every one of those tables cascades from it.
    let findings =
        sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM security_findings WHERE asset_id = $1")
            .bind(target)
            .fetch_one(&state.db_pool)
            .await
            .expect("count findings");
    let scans =
        sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM security_scans WHERE asset_id = $1")
            .bind(target)
            .fetch_one(&state.db_pool)
            .await
            .expect("count scans");

    assert_eq!(findings, 0);
    assert_eq!(scans, 0);
}

#[tokio::test]
async fn excluding_something_already_excluded_promotes_it_instead_of_failing() {
    let Some(_) = database_url() else {
        eprintln!("DATABASE_URL not set — skipping");
        return;
    };
    let state = app_state().await;
    let company_id = company(&state).await;

    let soft = state
        .exclusion_repository
        .create(
            &ExclusionCreate {
                object_type: ExclusionObjectType::Domain,
                object_value: "promote.test".to_string(),
                reason: Some("cdn".to_string()),
                delete_descendants: false,
                blacklisted: false,
            },
            None,
            company_id,
        )
        .await
        .expect("create exclusion entry");
    assert!(!soft.blacklisted);

    // The natural way to blacklist something is to blacklist a thing you have
    // already excluded; a unique violation would be a poor answer to that.
    let hard = state
        .exclusion_repository
        .create(
            &ExclusionCreate {
                object_type: ExclusionObjectType::Domain,
                object_value: "promote.test".to_string(),
                reason: None,
                delete_descendants: false,
                blacklisted: true,
            },
            None,
            company_id,
        )
        .await
        .expect("promote exclusion entry");

    assert_eq!(hard.id, soft.id, "the same row, made stronger");
    assert!(hard.blacklisted);
    assert_eq!(
        hard.reason.as_deref(),
        Some("cdn"),
        "a promotion with no reason keeps the one already recorded"
    );

    // And it does not swing back on a plain re-exclude.
    let again = state
        .exclusion_repository
        .create(
            &ExclusionCreate {
                object_type: ExclusionObjectType::Domain,
                object_value: "promote.test".to_string(),
                reason: None,
                delete_descendants: false,
                blacklisted: false,
            },
            None,
            company_id,
        )
        .await
        .expect("re-exclude");
    assert!(again.blacklisted);
}

#[tokio::test]
async fn a_wildcard_exclusion_reaches_the_queue_and_the_assets_it_matches() {
    let Some(_) = database_url() else {
        eprintln!("DATABASE_URL not set — skipping");
        return;
    };
    let state = app_state().await;
    let company_id = company(&state).await;

    let run = state
        .discovery_run_repository
        .create(&DiscoveryRunCreate::default(), company_id)
        .await
        .expect("create run");
    state
        .discovery_run_repository
        .start(company_id, &run.id)
        .await
        .expect("start run");

    enqueue(&state, run.id, QueueItemType::Domain, "a.cdn.wild.test").await;
    enqueue(
        &state,
        run.id,
        QueueItemType::Domain,
        "deep.chain.cdn.wild.test",
    )
    .await;
    // The apex the pattern deliberately does not cover, and an unrelated name.
    enqueue(&state, run.id, QueueItemType::Domain, "cdn.wild.test").await;
    enqueue(&state, run.id, QueueItemType::Domain, "keep.wild.test").await;

    let shallow = asset(&state, company_id, "domain", "a.cdn.wild.test").await;
    let deep = asset(&state, company_id, "domain", "deep.chain.cdn.wild.test").await;
    let apex = asset(&state, company_id, "domain", "cdn.wild.test").await;
    let unrelated = asset(&state, company_id, "domain", "keep.wild.test").await;

    state
        .exclusion_repository
        .create(
            &ExclusionCreate {
                object_type: ExclusionObjectType::Domain,
                object_value: "*.cdn.wild.test".to_string(),
                reason: None,
                delete_descendants: false,
                blacklisted: false,
            },
            None,
            company_id,
        )
        .await
        .expect("create wildcard entry");

    let (queue_removed, _) = state
        .discovery_service
        .apply_exclusion_entry(
            company_id,
            &ExclusionObjectType::Domain,
            "*.cdn.wild.test",
            false,
        )
        .await
        .expect("apply wildcard entry");

    assert_eq!(
        queue_removed, 2,
        "every depth under the pattern, and nothing else"
    );
    assert_eq!(
        queue_status(&state, run.id, "a.cdn.wild.test")
            .await
            .as_deref(),
        Some("skipped")
    );
    assert_eq!(
        queue_status(&state, run.id, "deep.chain.cdn.wild.test")
            .await
            .as_deref(),
        Some("skipped")
    );
    // Keeping the apex is the reason to write a pattern rather than a plain
    // domain entry, which would cover both.
    assert_eq!(
        queue_status(&state, run.id, "cdn.wild.test")
            .await
            .as_deref(),
        Some("pending")
    );
    assert_eq!(
        queue_status(&state, run.id, "keep.wild.test")
            .await
            .as_deref(),
        Some("pending")
    );

    // The same rule, applied to assets rather than queue items.
    let matched = state
        .exclusion_repository
        .matched_asset_ids(company_id, &ExclusionObjectType::Domain, "*.cdn.wild.test")
        .await
        .expect("matched asset ids");

    assert!(matched.contains(&shallow));
    assert!(matched.contains(&deep));
    assert!(!matched.contains(&apex));
    assert!(!matched.contains(&unrelated));

    // And to the scan-cancellation lookup, which walks its own query.
    let covered = state
        .asset_repository
        .find_excluded_ids(company_id, &ExclusionObjectType::Domain, "*.cdn.wild.test")
        .await
        .expect("find excluded ids");

    assert!(covered.contains(&shallow) && covered.contains(&deep));
    assert!(!covered.contains(&apex) && !covered.contains(&unrelated));
}

#[tokio::test]
async fn a_wildcard_blacklist_purges_every_match_and_its_descendants() {
    let Some(_) = database_url() else {
        eprintln!("DATABASE_URL not set — skipping");
        return;
    };
    let state = app_state().await;
    let company_id = company(&state).await;

    let matched_a = asset(&state, company_id, "domain", "one.junk.purge.test").await;
    let matched_b = asset(&state, company_id, "domain", "two.junk.purge.test").await;
    // Found through a matched name, so it goes with it even though its own
    // identifier is an address the pattern could never match.
    let child = child_asset(&state, company_id, "ip", "198.51.100.7", matched_a).await;
    let apex = asset(&state, company_id, "domain", "junk.purge.test").await;
    let unrelated = asset(&state, company_id, "domain", "one.junk.keep.test").await;

    let deleted = state
        .exclusion_repository
        .purge_entry_assets(
            company_id,
            &ExclusionObjectType::Domain,
            "*.junk.purge.test",
        )
        .await
        .expect("purge wildcard entry");

    assert_eq!(deleted, 3, "both matches and the child of one of them");
    assert!(!asset_exists(&state, matched_a).await);
    assert!(!asset_exists(&state, matched_b).await);
    assert!(!asset_exists(&state, child).await);
    assert!(asset_exists(&state, apex).await);
    assert!(asset_exists(&state, unrelated).await);
}

#[tokio::test]
async fn a_literal_underscore_in_a_value_is_not_a_sql_wildcard() {
    let Some(_) = database_url() else {
        eprintln!("DATABASE_URL not set — skipping");
        return;
    };
    let state = app_state().await;
    let company_id = company(&state).await;

    // `_` matches any single character in SQL LIKE. Escaping is what keeps a
    // pattern from reaching a name the operator never wrote.
    let literal = asset(&state, company_id, "domain", "a_b.under.test").await;
    let decoy = asset(&state, company_id, "domain", "axb.under.test").await;

    let matched = state
        .exclusion_repository
        .matched_asset_ids(company_id, &ExclusionObjectType::Domain, "a_b.*")
        .await
        .expect("matched asset ids");

    assert!(matched.contains(&literal));
    assert!(
        !matched.contains(&decoy),
        "an underscore is a character, not a wildcard"
    );
}

#[tokio::test]
async fn editing_a_reason_leaves_the_strength_alone() {
    let Some(_) = database_url() else {
        eprintln!("DATABASE_URL not set — skipping");
        return;
    };
    let state = app_state().await;
    let company_id = company(&state).await;

    let entry = state
        .exclusion_repository
        .create(
            &ExclusionCreate {
                object_type: ExclusionObjectType::Domain,
                object_value: "edit.test".to_string(),
                reason: None,
                delete_descendants: false,
                blacklisted: true,
            },
            None,
            company_id,
        )
        .await
        .expect("create exclusion entry");

    // The common edit: a reason, and nothing else. Leaving `blacklisted` unset
    // must not quietly demote the entry.
    let renamed = state
        .exclusion_repository
        .update(
            company_id,
            &entry.id,
            &ExclusionUpdate {
                reason: Some("shared host".to_string()),
                blacklisted: None,
            },
        )
        .await
        .expect("update reason");

    assert_eq!(renamed.reason.as_deref(), Some("shared host"));
    assert!(renamed.blacklisted, "an unset field is not a demotion");

    // And an explicit demotion still works.
    let demoted = state
        .exclusion_repository
        .update(
            company_id,
            &entry.id,
            &ExclusionUpdate {
                reason: None,
                blacklisted: Some(false),
            },
        )
        .await
        .expect("demote entry");

    assert!(!demoted.blacklisted);
    assert_eq!(
        demoted.reason.as_deref(),
        Some("shared host"),
        "an unset reason is not a deletion either"
    );
}

#[tokio::test]
async fn blacklisting_a_cidr_reaches_the_addresses_inside_it() {
    let Some(_) = database_url() else {
        eprintln!("DATABASE_URL not set — skipping");
        return;
    };
    let state = app_state().await;
    let company_id = company(&state).await;

    let run = state
        .discovery_run_repository
        .create(&DiscoveryRunCreate::default(), company_id)
        .await
        .expect("create run");
    state
        .discovery_run_repository
        .start(company_id, &run.id)
        .await
        .expect("start run");

    enqueue(&state, run.id, QueueItemType::Ip, "10.10.0.5").await;
    enqueue(&state, run.id, QueueItemType::Ip, "10.11.0.5").await;
    // A malformed identifier must not abort the inet comparison for the rest.
    enqueue(&state, run.id, QueueItemType::Ip, "not-an-ip").await;

    let inside = asset(&state, company_id, "ip", "10.10.0.5").await;
    let outside = asset(&state, company_id, "ip", "10.11.0.5").await;
    let inside_scan = pending_scan(&state, company_id, inside, Some(run.id)).await;
    let outside_scan = pending_scan(&state, company_id, outside, Some(run.id)).await;

    state
        .exclusion_repository
        .create(
            &ExclusionCreate {
                object_type: ExclusionObjectType::Cidr,
                object_value: "10.10.0.0/16".to_string(),
                reason: None,
                delete_descendants: false,
                blacklisted: true,
            },
            None,
            company_id,
        )
        .await
        .expect("create exclusion entry");

    let (queue_removed, scans_cancelled) = state
        .discovery_service
        .apply_exclusion_entry(company_id, &ExclusionObjectType::Cidr, "10.10.0.0/16", true)
        .await
        .expect("apply exclusion entry");

    assert_eq!(queue_removed, 1);
    assert_eq!(
        queue_status(&state, run.id, "10.10.0.5").await.as_deref(),
        Some("skipped")
    );
    assert_eq!(
        queue_status(&state, run.id, "10.11.0.5").await.as_deref(),
        Some("pending")
    );
    assert_eq!(
        queue_status(&state, run.id, "not-an-ip").await.as_deref(),
        Some("pending")
    );

    assert_eq!(scans_cancelled, 1);
    assert_eq!(scan_status(&state, inside_scan).await, "cancelled");
    assert_eq!(scan_status(&state, outside_scan).await, "pending");
}

#[tokio::test]
async fn a_blacklist_added_after_a_run_stops_still_reaches_its_leftovers() {
    let Some(_) = database_url() else {
        eprintln!("DATABASE_URL not set — skipping");
        return;
    };
    let state = app_state().await;
    let company_id = company(&state).await;

    let run = state
        .discovery_run_repository
        .create(&DiscoveryRunCreate::default(), company_id)
        .await
        .expect("create run");
    state
        .discovery_run_repository
        .start(company_id, &run.id)
        .await
        .expect("start run");

    enqueue(&state, run.id, QueueItemType::Domain, "late.test").await;

    // The run is cancelled with the item still queued -- which is what happens
    // when a stop lands between two batches.
    state
        .discovery_run_repository
        .update_status(company_id, &run.id, "cancelled", Some("Stopped by user"))
        .await
        .expect("cancel run");

    let (queue_removed, _) = state
        .discovery_service
        .apply_exclusion_entry(company_id, &ExclusionObjectType::Domain, "late.test", true)
        .await
        .expect("apply exclusion entry");

    // Nothing is dequeuing a cancelled run, so its leftovers are not the
    // exclusion list's problem -- they are cleared with the run itself.
    assert_eq!(queue_removed, 0);

    state
        .discovery_queue_repository
        .clear_run(&run.id)
        .await
        .expect("clear run");
    assert_eq!(queue_status(&state, run.id, "late.test").await, None);
}

#[tokio::test]
async fn a_blacklisted_asset_is_not_written_by_discovery() {
    let Some(_) = database_url() else {
        eprintln!("DATABASE_URL not set — skipping");
        return;
    };
    let state = app_state().await;
    let company_id = company(&state).await;

    state
        .exclusion_repository
        .create(
            &ExclusionCreate {
                object_type: ExclusionObjectType::Domain,
                object_value: "excluded.test".to_string(),
                reason: None,
                delete_descendants: false,
                blacklisted: true,
            },
            None,
            company_id,
        )
        .await
        .expect("create exclusion entry");

    // Written before the entry existed, so it is what a mid-run blacklist
    // leaves behind and what `find_excluded_ids` has to find again.
    let sub = asset(&state, company_id, "domain", "api.excluded.test").await;
    let unrelated = asset(&state, company_id, "domain", "other.test").await;

    let found = state
        .asset_repository
        .find_excluded_ids(company_id, &ExclusionObjectType::Domain, "excluded.test")
        .await
        .expect("find excluded ids");

    assert!(
        found.contains(&sub),
        "subdomains of a blacklisted domain count"
    );
    assert!(!found.contains(&unrelated));
}

#[tokio::test]
async fn stopping_a_run_files_its_counters_and_clears_the_live_ones() {
    let Some(_) = database_url() else {
        eprintln!("DATABASE_URL not set — skipping");
        return;
    };
    let state = app_state().await;
    let company_id = company(&state).await;

    // A run with nothing to do finishes immediately, which is enough to reach
    // the start-of-run reset -- the part that used to inherit the previous
    // run's numbers.
    let run = state
        .discovery_service
        .run_discovery(company_id, None, None)
        .await
        .expect("start discovery");

    // Wait for the task to settle rather than racing it.
    let mut status = state
        .discovery_service
        .get_discovery_status(company_id)
        .await;
    for _ in 0..100 {
        if !status.is_running {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        status = state
            .discovery_service
            .get_discovery_status(company_id)
            .await;
    }

    assert!(
        !status.is_running,
        "a run with no seeds finishes on its own"
    );
    assert_eq!(status.run_id, Some(run.id));

    // Nothing carries over into the next run: the counters, the queue depth and
    // the error list all start empty.
    assert_eq!(status.seeds_processed, 0);
    assert_eq!(status.assets_discovered, 0);
    assert_eq!(status.assets_updated, 0);
    assert_eq!(status.queue_pending, 0);
    assert_eq!(status.scans_queued, 0);
    assert!(status.errors.is_empty());
}

#[tokio::test]
async fn stopping_a_run_that_is_not_running_is_rejected() {
    let Some(_) = database_url() else {
        eprintln!("DATABASE_URL not set — skipping");
        return;
    };
    let state = app_state().await;
    let company_id = company(&state).await;

    let err = state
        .discovery_service
        .stop_discovery(company_id)
        .await
        .expect_err("nothing to stop");

    assert!(err.to_string().contains("not running"), "got: {}", err);
}

#[tokio::test]
async fn a_failed_stop_still_lets_the_next_run_start() {
    let Some(_) = database_url() else {
        eprintln!("DATABASE_URL not set — skipping");
        return;
    };
    let state = app_state().await;
    let company_id = company(&state).await;

    state
        .discovery_service
        .run_discovery(company_id, None, None)
        .await
        .expect("first run");

    // Delete the run row out from under the stop, so marking it cancelled
    // fails. The in-memory state must still be released -- otherwise the
    // company is stuck on "discovery is already running" for good.
    sqlx::query("DELETE FROM discovery_runs WHERE company_id = $1")
        .bind(company_id)
        .execute(&state.db_pool)
        .await
        .expect("delete run");

    // The run may already have finished on its own; either way the next start
    // is what matters.
    let _ = state.discovery_service.stop_discovery(company_id).await;

    let status = state
        .discovery_service
        .get_discovery_status(company_id)
        .await;
    assert!(!status.is_running);

    state
        .discovery_service
        .run_discovery(company_id, None, None)
        .await
        .expect("a second run can still start");
}
