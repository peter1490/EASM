//! Live end-to-end check of the DNS scanner.
//!
//!     cargo run --example dns_scan_check -- citynove.com
use std::sync::Arc;
use std::time::Duration;

use rust_backend::services::external::DnsResolver;
use rust_backend::services::scanners::dns_scan;

#[tokio::main]
async fn main() {
    let domain = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "citynove.com".to_string());

    let resolver = Arc::new(DnsResolver::new().await.expect("resolver"));
    let http = reqwest::Client::builder()
        .timeout(Duration::from_secs(10))
        .build()
        .expect("http client");

    let outcome = dns_scan::scan(&resolver, &http, &domain, Duration::from_secs(6), true).await;
    println!("{}", serde_json::to_string_pretty(&outcome.result).unwrap());
    println!("\n=== {} findings ===", outcome.findings.len());
    for finding in &outcome.findings {
        println!("[{}] {} — {}", finding.severity, finding.finding_type, finding.title);
    }
}
