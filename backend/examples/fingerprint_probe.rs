//! Live fingerprinting probe.
//!
//! Fetches the URLs given on the command line (or a default sample) exactly the
//! way the scanner does — same signals, same engine — and prints what it
//! detects. Used to sanity-check the ruleset against the real internet, where
//! pages are messier than any fixture.
//!
//!   cargo run --example fingerprint_probe -- https://example.com https://…
//!
//! Pass `--cve` to also run the real NVD lookup for every versioned detection
//! that carries a CPE, with CISA KEV and EPSS enrichment — i.e. the exact chain
//! a scan runs, without needing a database.

use std::collections::HashMap;
use std::time::Duration;

use rust_backend::services::external::{NvdClient, ThreatIntelClient};
use rust_backend::services::fingerprint::{engine, DetectionInput};
use rust_backend::utils::cpe::Cpe;

const BROWSER_USER_AGENT: &str = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) \
     AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36";

#[tokio::main]
async fn main() {
    let mut args: Vec<String> = std::env::args().skip(1).collect();
    let with_cve = args.iter().any(|a| a == "--cve");
    args.retain(|a| a != "--cve");
    let targets: Vec<String> = if args.is_empty() {
        vec![
            "https://wordpress.org/".to_string(),
            "https://www.drupal.org/".to_string(),
            "https://jquery.com/".to_string(),
            "https://nginx.org/".to_string(),
        ]
    } else {
        args
    };

    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(15))
        .danger_accept_invalid_certs(true)
        .user_agent(BROWSER_USER_AGENT)
        .build()
        .expect("client");

    println!("ruleset: {} signatures\n", engine().signature_count());

    for target in targets {
        match probe(&client, &target, with_cve).await {
            Ok(()) => {}
            Err(e) => println!("{target}\n  ! {e}\n"),
        }
    }
}

async fn probe(client: &reqwest::Client, target: &str, with_cve: bool) -> Result<(), String> {
    let response = client
        .get(target)
        .send()
        .await
        .map_err(|e| format!("request failed: {e}"))?;

    let final_url = response.url().to_string();
    let status = response.status();
    let headers: Vec<(String, String)> = response
        .headers()
        .iter()
        .map(|(k, v)| {
            (
                k.as_str().to_ascii_lowercase(),
                v.to_str().unwrap_or("").to_string(),
            )
        })
        .collect();
    let set_cookies: Vec<String> = response
        .headers()
        .get_all(reqwest::header::SET_COOKIE)
        .iter()
        .filter_map(|v| v.to_str().ok().map(|s| s.to_string()))
        .collect();
    let body = response.text().await.unwrap_or_default();

    let robots = fetch_text(client, &final_url, "/robots.txt").await;
    let favicon = fetch_favicon(client, &final_url).await;

    let input = DetectionInput::new(&final_url, &body)
        .with_headers(&headers)
        .with_cookies(&set_cookies)
        .with_robots_txt(robots.as_deref())
        .with_favicon_hash(favicon);

    let started = std::time::Instant::now();
    let detections = engine().detect_with(&input);
    let elapsed = started.elapsed();

    println!(
        "{final_url}  [{}]  {} bytes  detect {:.1}ms",
        status.as_u16(),
        body.len(),
        elapsed.as_secs_f64() * 1000.0
    );
    if detections.is_empty() {
        println!("  (nothing detected)");
    }
    for d in &detections {
        println!(
            "  {:<24} {:<10} conf {:>3}  via {:<14} [{}]",
            d.display_name,
            d.version.as_deref().unwrap_or("-"),
            d.confidence,
            d.source,
            d.sources.join(",")
        );
    }

    if with_cve {
        report_cves(&detections).await;
    }
    println!();
    let _ = HashMap::<String, String>::new();
    Ok(())
}

/// Run the real CVE path for every versioned, reliable detection with a CPE.
async fn report_cves(detections: &[rust_backend::services::fingerprint::TechDetection]) {
    let nvd = match NvdClient::new() {
        Ok(c) => c,
        Err(e) => {
            println!("  ! NVD client: {e}");
            return;
        }
    };
    let intel = ThreatIntelClient::new();

    for det in detections {
        let (Some(version), Some(cpe)) = (det.version.as_deref(), det.cpe.as_deref()) else {
            continue;
        };
        if !det.is_reliable() {
            continue;
        }
        let Some(parsed) = Cpe::parse(cpe) else { continue };

        let series = NvdClient::is_series_version(version);
        let vulns = match nvd.search_affecting_cpe(&parsed, version).await {
            Ok(v) => v,
            Err(e) => {
                println!("  ! NVD lookup for {} {}: {e}", det.product, version);
                continue;
            }
        };
        println!(
            "\n  CVEs for {} {}{} — {} found",
            det.product,
            version,
            if series { " (series, exact build unknown)" } else { "" },
            vulns.len()
        );

        let ids: Vec<String> = vulns.iter().map(|v| v.id.clone()).collect();
        let ctx = intel.context_for(&ids).await;
        let mut rows: Vec<_> = vulns
            .iter()
            .map(|v| {
                let c = ctx.get(&v.id.to_uppercase()).cloned().unwrap_or_default();
                let mut p = c.priority_score(v.base_score);
                if series {
                    p *= 0.8;
                }
                (p, v, c)
            })
            .collect();
        rows.sort_by(|a, b| b.0.partial_cmp(&a.0).unwrap_or(std::cmp::Ordering::Equal));

        for (priority, v, c) in rows.iter().take(8) {
            println!(
                "    {:<16} prio {:>4.1}  cvss {:<4}  epss {:<7}  {}",
                v.id,
                priority,
                v.base_score.map(|s| format!("{s:.1}")).unwrap_or_else(|| "-".into()),
                c.epss
                    .map(|e| format!("{:.2}%", e.probability * 100.0))
                    .unwrap_or_else(|| "-".into()),
                if c.is_known_exploited() { "KEV" } else { "" }
            );
        }
        if rows.len() > 8 {
            println!("    … and {} more", rows.len() - 8);
        }
    }
}

async fn fetch_text(client: &reqwest::Client, base: &str, path: &str) -> Option<String> {
    let url = url::Url::parse(base).ok()?.join(path).ok()?;
    let resp = client.get(url.as_str()).send().await.ok()?;
    if !resp.status().is_success() {
        return None;
    }
    let ct = resp
        .headers()
        .get(reqwest::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();
    if !ct.starts_with("text/plain") {
        return None;
    }
    resp.text().await.ok()
}

async fn fetch_favicon(client: &reqwest::Client, base: &str) -> Option<i32> {
    let url = url::Url::parse(base).ok()?.join("/favicon.ico").ok()?;
    let resp = client.get(url.as_str()).send().await.ok()?;
    if !resp.status().is_success() {
        return None;
    }
    let bytes = resp.bytes().await.ok()?;
    if bytes.is_empty() {
        return None;
    }
    Some(rust_backend::services::external::http::shodan_favicon_hash(
        &bytes,
    ))
}
