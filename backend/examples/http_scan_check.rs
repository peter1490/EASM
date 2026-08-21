//! Live end-to-end check of the HTTP scanner.
//!
//!     cargo run --example http_scan_check -- citynove.com
use std::time::Duration;

use rust_backend::services::scanners::http_scan;

const BROWSER_UA: &str = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 \
                          (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36";

#[tokio::main]
async fn main() {
    let target = std::env::args().nth(1).unwrap_or_else(|| "citynove.com".into());

    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(15))
        .user_agent(BROWSER_UA)
        .danger_accept_invalid_certs(true)
        .build()
        .expect("client");
    let plain = reqwest::Client::builder()
        .timeout(Duration::from_secs(15))
        .user_agent(BROWSER_UA)
        .redirect(reqwest::redirect::Policy::none())
        .danger_accept_invalid_certs(true)
        .build()
        .expect("plain client");

    let outcome = http_scan::scan(&client, &plain, &target, Duration::from_secs(10), true).await;
    println!("{}", serde_json::to_string_pretty(&outcome.result).unwrap());
    println!("\n=== {} findings ===", outcome.findings.len());
    for f in &outcome.findings {
        println!("[{}] {} — {}", f.severity, f.finding_type, f.title);
    }
}
