//! A `dig`-shaped raw DNS query against a chosen nameserver.
//!
//! Useful for cross-checking what the DNS scanner reports, and for the record
//! types the stub resolver cannot decode (DNSKEY, DS, TLSA).
//!
//!     cargo run --example dns_query -- 1.1.1.1 example.com DNSKEY
use std::net::SocketAddr;
use std::time::Duration;

use rust_backend::services::scanners::dns_wire;

#[tokio::main]
async fn main() {
    let mut args = std::env::args().skip(1);
    let server: String = args.next().unwrap_or_else(|| "1.1.1.1".into());
    let name: String = args.next().unwrap_or_else(|| "citynove.com".into());
    let qtype = match args.next().unwrap_or_else(|| "A".into()).to_uppercase().as_str() {
        "A" => 1, "NS" => 2, "CNAME" => 5, "SOA" => 6, "MX" => 15, "TXT" => 16,
        "AAAA" => 28, "SRV" => 33, "DS" => 43, "DNSKEY" => 48, "TLSA" => 52, "CAA" => 257,
        other => other.parse().unwrap_or(1),
    };
    let addr: SocketAddr = format!("{}:53", server).parse().expect("server");
    match dns_wire::query_over_tcp(&name, qtype, addr, Duration::from_secs(8), true).await {
        Ok((rcode, records)) => {
            println!("rcode={} answers={}", rcode, records.len());
            for r in records {
                println!("  {} {} {} {}", r.name, r.ttl, r.record_type, r.value);
            }
        }
        Err(e) => println!("error: {}", e),
    }
}
