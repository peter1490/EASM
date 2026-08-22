//! End-to-end exercise of the deep TLS/DNS/HTTP scanners through the real
//! `SecurityScanService`, against a purpose-built local target.
//!
//! The unit tests in `services::scanners::*` cover the rules; this covers the
//! wiring — that a scan actually reaches the scanners, that their findings are
//! persisted with the right types and severities, and that the structured result
//! lands in `result_summary` where the UI reads it.
//!
//! Requires `DATABASE_URL`. Skipped, loudly, when it is not set.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use rust_backend::models::{AssetType, SecurityScanCreate, SecurityScanType};
use rust_backend::{config, AppState};
use serde_json::{json, Value};
use uuid::Uuid;

mod local_target;

fn database_url() -> Option<String> {
    std::env::var("DATABASE_URL").ok()
}

async fn app_state() -> AppState {
    let db_url = database_url().expect("checked by the caller");
    std::env::set_var("LOG_LEVEL", "error");
    // The target is 127.0.0.1, which every other scan path treats as internal.
    std::env::set_var("ALLOW_INTERNAL_SCANS", "true");
    std::env::set_var("BLOCK_INTERNAL_IP_SCANS", "false");
    std::env::set_var("ENVIRONMENT", "development");

    let settings = config::Settings::new_with_env_file(false).expect("settings");
    let pool = rust_backend::database::create_connection_pool(&db_url)
        .await
        .expect("database pool");

    // `app_settings` is a persisted singleton that overrides the environment once
    // the application has run against this database. These tests scan 127.0.0.1,
    // which every scan-policy check treats as internal, so a stored
    // `allow_internal_scans = false` would reject the scan before any scanner
    // ran — and the failure would look like a scanner bug rather than leftover
    // state. DATABASE_URL points at a test database, so clearing it is safe.
    sqlx::query("DELETE FROM app_settings")
        .execute(&pool)
        .await
        .expect("clear persisted settings");

    AppState::new_with_pool(settings, pool)
        .await
        .expect("app state")
}

/// Create a company and an asset pointing at `identifier`.
async fn seed_asset(state: &AppState, identifier: &str, asset_type: AssetType) -> (Uuid, Uuid) {
    let company_id = Uuid::new_v4();
    let asset_id = Uuid::new_v4();
    let pool = state.db_pool.clone();

    sqlx::query("INSERT INTO companies (id, name) VALUES ($1, $2) ON CONFLICT (id) DO NOTHING")
        .bind(company_id)
        .bind(format!("deep-scan-test-{}", company_id))
        .execute(&pool)
        .await
        .expect("insert company");

    // `asset_type` is a Postgres enum, so the string has to be cast explicitly.
    sqlx::query(
        "INSERT INTO assets (id, asset_type, identifier, confidence, company_id, metadata)
         VALUES ($1, $2::asset_type, $3, 100, $4, '{}'::jsonb)",
    )
    .bind(asset_id)
    .bind(asset_type.to_string())
    .bind(identifier)
    .bind(company_id)
    .execute(&pool)
    .await
    .expect("insert asset");

    (company_id, asset_id)
}

async fn cleanup(state: &AppState, company_id: Uuid) {
    let pool = state.db_pool.clone();
    for table in ["security_findings", "security_scans", "assets", "companies"] {
        let column = if table == "companies" { "id" } else { "company_id" };
        let _ = sqlx::query(&format!("DELETE FROM {} WHERE {} = $1", table, column))
            .bind(company_id)
            .execute(&pool)
            .await;
    }
}

/// Run a scan to completion and return `(result_summary, findings)`.
async fn run_scan(
    state: &AppState,
    company_id: Uuid,
    asset_id: Uuid,
    scan_type: SecurityScanType,
) -> (Value, Vec<(String, String, String)>) {
    let scan = state
        .security_scan_service
        .create_scan(
            SecurityScanCreate {
                asset_id,
                scan_type: Some(scan_type),
                trigger_type: None,
                priority: None,
                note: Some("deep scan integration test".to_string()),
                // Exercise the exhaustive path — that is what is under test.
                config: Some(json!({ "deep": true })),
                discovery_run_id: None,
            },
            company_id,
            None,
        )
        .await
        .expect("create scan");

    // The scan runs as a background task; poll until it settles.
    let deadline = std::time::Instant::now() + Duration::from_secs(180);
    loop {
        let current = state
            .security_scan_service
            .get_scan(&scan.id, company_id)
            .await
            .expect("get scan")
            .expect("scan exists");
        if matches!(current.status.as_str(), "completed" | "failed" | "cancelled") {
            assert_eq!(
                current.status, "completed",
                "scan did not complete: {:?}",
                current.result_summary
            );
            let findings = sqlx::query_as::<_, (String, String, String)>(
                "SELECT finding_type, severity, title FROM security_findings
                 WHERE security_scan_id = $1 ORDER BY finding_type",
            )
            .bind(scan.id)
            .fetch_all(&state.db_pool)
            .await
            .expect("load findings");
            return (current.result_summary, findings);
        }
        assert!(
            std::time::Instant::now() < deadline,
            "scan {} did not finish within the timeout (status {})",
            scan.id,
            current.status
        );
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
}

#[tokio::test]
async fn http_scan_finds_and_persists_real_misconfigurations() {
    let Some(_) = database_url() else {
        eprintln!("skipping: DATABASE_URL is not set");
        return;
    };

    let server = local_target::start().await;
    let state = app_state().await;
    // An IP asset: `scan_ip` probes the well-known web ports to find the target,
    // which is the same path a real scan of a bare host takes.
    let (company_id, asset_id) = seed_asset(&state, "127.0.0.1", AssetType::Ip).await;
    assert!(server.port() >= 8000, "the fixture must bind a web port");

    let (summary, findings) =
        run_scan(&state, company_id, asset_id, SecurityScanType::HttpProbe).await;

    let types: Vec<&str> = findings.iter().map(|(t, _, _)| t.as_str()).collect();
    let by_type = |wanted: &str| findings.iter().find(|(t, _, _)| t == wanted);

    // The deep result must reach `result_summary`, which is what the UI reads.
    let http = summary
        .get("http")
        .and_then(Value::as_object)
        .unwrap_or_else(|| panic!("summary has no `http` section: {}", summary));
    assert_eq!(http["status"], json!(200));
    let observatory = http["observatory"].as_object().expect("observatory score");
    assert!(
        observatory["score"].as_i64().unwrap() < 40,
        "a deliberately misconfigured server should score badly, got {}",
        observatory["score"]
    );

    // Each of these corresponds to something the fixture actually does wrong.
    for expected in [
        "sensitive_data_exposed", // /.env with DB_PASSWORD
        "debug_endpoint_exposed", // /server-status
        "insecure_cookies",       // PHPSESSID with no flags
        "cors_misconfiguration",  // reflected Origin + credentials
        "dangerous_http_method",  // TRACE echoes the request
        "weak_security_header",   // CSP present but permits script-src https:
        "information_disclosure", // Python traceback in the body
        "missing_sri",            // external script with no integrity
    ] {
        assert!(
            types.contains(&expected),
            "expected a {} finding; got {:?}",
            expected,
            types
        );
    }

    // Severity has to survive the trip through the repository. Several probes
    // share the `sensitive_data_exposed` type, so match on the title.
    let by_title = |wanted: &str| {
        findings
            .iter()
            .find(|(_, _, title)| title == wanted)
            .unwrap_or_else(|| panic!("no {} finding in {:?}", wanted, findings))
    };
    assert_eq!(
        by_title("Environment file exposed").1,
        "critical",
        "an exposed .env is critical"
    );
    assert_eq!(
        by_title("Git repository exposed").1,
        "high",
        "an exposed .git is high"
    );
    let (_, severity, _) = by_type("cors_misconfiguration").unwrap();
    assert_eq!(severity, "high", "reflected origin with credentials is high");

    // The false-positive guard: /.DS_Store answers 200 with the wrong content,
    // so it must not be reported.
    assert!(
        !findings
            .iter()
            .any(|(_, _, title)| title.contains(".DS_Store")),
        "a 200 with non-matching content must not be reported as an exposure"
    );

    cleanup(&state, company_id).await;
}

#[tokio::test]
async fn dns_audit_persists_findings_and_a_graded_summary() {
    let Some(_) = database_url() else {
        eprintln!("skipping: DATABASE_URL is not set");
        return;
    };

    let state = app_state().await;
    // A domain that resolves but has almost no email or DNS hardening.
    let (company_id, asset_id) = seed_asset(&state, "example.com", AssetType::Domain).await;

    let (summary, findings) =
        run_scan(&state, company_id, asset_id, SecurityScanType::DnsAudit).await;

    let dns = summary
        .get("dns")
        .and_then(Value::as_object)
        .unwrap_or_else(|| panic!("summary has no `dns` section: {}", summary));
    assert_eq!(dns["domain"], json!("example.com"));
    assert!(dns["score"].as_i64().is_some(), "a hygiene score is expected");
    assert!(
        dns["grade"].as_str().is_some_and(|g| g.len() == 1),
        "a letter grade is expected, got {:?}",
        dns["grade"]
    );
    // Nameserver enumeration is the part that must work for anything else to.
    assert!(
        !dns["nameservers"]["nameservers"]
            .as_array()
            .map(Vec::is_empty)
            .unwrap_or(true),
        "no nameservers were resolved, so the DNS scan did not run"
    );

    // The legacy summary shape has to keep working for anything still reading it.
    assert!(summary.get("dns_security").is_some());

    // Every persisted finding must be a type a DNS audit can auto-resolve, or it
    // will stay open forever after it is fixed.
    let resolvable: Vec<&str> = rust_backend::services::scanners::dns_scan::EMITTED_FINDING_TYPES
        .to_vec();
    for (finding_type, _, title) in &findings {
        assert!(
            resolvable.contains(&finding_type.as_str()),
            "{} ({}) is not declared by the DNS scanner",
            finding_type,
            title
        );
    }

    cleanup(&state, company_id).await;
}

#[tokio::test]
async fn tls_scan_grades_a_local_endpoint_that_does_not_speak_tls() {
    let Some(_) = database_url() else {
        eprintln!("skipping: DATABASE_URL is not set");
        return;
    };

    // A plain-HTTP listener on the TLS path: the scanner must conclude "no TLS
    // here" rather than inventing a grade for it.
    let server = local_target::start().await;
    let state = app_state().await;
    let addr: SocketAddr = format!("127.0.0.1:{}", server.port()).parse().unwrap();

    let result = rust_backend::services::scanners::tls_scan::scan(
        "127.0.0.1",
        addr,
        addr.port(),
        Duration::from_secs(5),
        true,
    )
    .await;

    assert!(!result.reachable(), "a plain HTTP port speaks no TLS");
    assert!(result.supported_protocols.is_empty());
    assert!(
        rust_backend::services::scanners::tls_scan::build_findings(&result).is_empty(),
        "an endpoint with no TLS must not produce TLS findings"
    );
    assert!(
        !result.errors.is_empty(),
        "the reason should be recorded rather than left silent"
    );

    drop(Arc::new(state));
}
