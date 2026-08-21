//! Live end-to-end check of the TLS scanner.
//!
//!     cargo run --example tls_scan_check -- citynove.com 443
use std::net::ToSocketAddrs;
use std::time::Duration;

use rust_backend::services::scanners::tls_scan;

#[tokio::main]
async fn main() {
    let mut args = std::env::args().skip(1);
    let host = args.next().unwrap_or_else(|| "citynove.com".to_string());
    let port: u16 = args.next().and_then(|p| p.parse().ok()).unwrap_or(443);

    let addr = format!("{}:{}", host, port)
        .to_socket_addrs()
        .expect("resolve")
        .next()
        .expect("no address");

    let result = tls_scan::scan(&host, addr, port, Duration::from_secs(8), true).await;
    println!("{}", serde_json::to_string_pretty(&result).unwrap());
}
