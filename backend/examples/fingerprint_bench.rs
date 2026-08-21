//! Detection timing on saved page bodies.
//!
//!   cargo run --release --example fingerprint_bench -- page1.html page2.html

use std::time::Instant;

use rust_backend::services::fingerprint::{engine, DetectionInput};

fn main() {
    let paths: Vec<String> = std::env::args().skip(1).collect();
    println!("{} signatures", engine().signature_count());
    for path in paths {
        let Ok(body) = std::fs::read_to_string(&path) else {
            println!("{path}: unreadable");
            continue;
        };
        // Warm caches, then take the best of several runs.
        let input = DetectionInput::new("https://example.com/", &body);
        let mut best = f64::MAX;
        let mut n = 0;
        for _ in 0..5 {
            let t = Instant::now();
            let dets = engine().detect_with(&input);
            best = best.min(t.elapsed().as_secs_f64() * 1000.0);
            n = dets.len();
        }
        println!(
            "  {:<40} {:>8} bytes  {:>8.2} ms  {} detections",
            path.rsplit('/').next().unwrap_or(&path),
            body.len(),
            best,
            n
        );
    }
}
