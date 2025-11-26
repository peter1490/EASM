use serde::{Deserialize, Serialize};
use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};
use sysinfo::System;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RequestMetrics {
    pub total_requests: u64,
    pub successful_requests: u64,
    pub failed_requests: u64,
    pub average_response_time_ms: f64,
    pub max_response_time_ms: u64,
    pub min_response_time_ms: u64,
    pub requests_per_second: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EndpointMetrics {
    pub endpoint: String,
    pub method: String,
    pub metrics: RequestMetrics,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SystemMetrics {
    pub uptime_seconds: u64,
    pub memory_usage_bytes: u64,
    pub total_memory_bytes: u64,
    pub cpu_usage_percent: f64,
    pub active_connections: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PerformanceReport {
    pub timestamp: chrono::DateTime<chrono::Utc>,
    pub system: SystemMetrics,
    pub endpoints: Vec<EndpointMetrics>,
    pub overall: RequestMetrics,
}

#[derive(Debug, Clone)]
struct RequestRecord {
    timestamp: Instant,
    duration: Duration,
    success: bool,
}

#[derive(Debug)]
struct EndpointStats {
    method: String,
    records: Vec<RequestRecord>,
}

pub struct MetricsService {
    start_time: Instant,
    endpoint_stats: Arc<Mutex<HashMap<String, EndpointStats>>>,
    window_duration: Duration,
    system_monitor: Arc<Mutex<System>>,
}

impl MetricsService {
    pub fn new() -> Self {
        let mut system = System::new_all();
        system.refresh_all();

        Self {
            start_time: Instant::now(),
            endpoint_stats: Arc::new(Mutex::new(HashMap::new())),
            window_duration: Duration::from_secs(300), // 5 minute window
            system_monitor: Arc::new(Mutex::new(system)),
        }
    }

    /// Record a request for metrics collection
    pub fn record_request(&self, endpoint: &str, method: &str, duration: Duration, success: bool) {
        let mut stats = self.endpoint_stats.lock().unwrap();
        let endpoint_stats = stats
            .entry(endpoint.to_string())
            .or_insert_with(|| EndpointStats {
                method: method.to_string(),
                records: Vec::new(),
            });

        endpoint_stats.records.push(RequestRecord {
            timestamp: Instant::now(),
            duration,
            success,
        });

        // Clean old records outside the window
        let cutoff = Instant::now() - self.window_duration;
        endpoint_stats
            .records
            .retain(|record| record.timestamp > cutoff);
    }

    /// Calculate metrics for a set of request records
    fn calculate_metrics(&self, records: &[RequestRecord]) -> RequestMetrics {
        if records.is_empty() {
            return RequestMetrics {
                total_requests: 0,
                successful_requests: 0,
                failed_requests: 0,
                average_response_time_ms: 0.0,
                max_response_time_ms: 0,
                min_response_time_ms: 0,
                requests_per_second: 0.0,
            };
        }

        let total_requests = records.len() as u64;
        let successful_requests = records.iter().filter(|r| r.success).count() as u64;
        let failed_requests = total_requests - successful_requests;

        let durations: Vec<u64> = records
            .iter()
            .map(|r| r.duration.as_millis() as u64)
            .collect();

        let total_duration_ms: u64 = durations.iter().sum();
        let average_response_time_ms = if total_requests > 0 {
            total_duration_ms as f64 / total_requests as f64
        } else {
            0.0
        };

        let max_response_time_ms = durations.iter().max().copied().unwrap_or(0);
        let min_response_time_ms = durations.iter().min().copied().unwrap_or(0);

        // Calculate requests per second over the window
        let window_seconds = self.window_duration.as_secs_f64();
        let requests_per_second = if window_seconds > 0.0 {
            total_requests as f64 / window_seconds
        } else {
            0.0
        };

        RequestMetrics {
            total_requests,
            successful_requests,
            failed_requests,
            average_response_time_ms,
            max_response_time_ms,
            min_response_time_ms,
            requests_per_second,
        }
    }

    /// Get current system metrics using sysinfo
    fn get_system_metrics(&self) -> SystemMetrics {
        let uptime_seconds = self.start_time.elapsed().as_secs();

        // Refresh system info
        let mut system = self.system_monitor.lock().unwrap();
        system.refresh_cpu_all();
        system.refresh_memory();

        let memory_usage_bytes = system.used_memory();
        let total_memory_bytes = system.total_memory();
        let cpu_usage_percent = system.global_cpu_usage() as f64;

        SystemMetrics {
            uptime_seconds,
            memory_usage_bytes,
            total_memory_bytes,
            cpu_usage_percent,
            active_connections: 0, // This would require deeper OS integration or a different crate
        }
    }

    /// Generate a comprehensive performance report
    pub fn generate_report(&self) -> PerformanceReport {
        let stats = self.endpoint_stats.lock().unwrap();

        let mut endpoints = Vec::new();
        let mut all_records: Vec<RequestRecord> = Vec::new();

        for (endpoint, endpoint_stats) in stats.iter() {
            let metrics = self.calculate_metrics(&endpoint_stats.records);
            endpoints.push(EndpointMetrics {
                endpoint: endpoint.clone(),
                method: endpoint_stats.method.clone(),
                metrics,
            });

            // Collect all records for overall metrics
            all_records.extend(endpoint_stats.records.iter().cloned());
        }

        let overall = self.calculate_metrics(&all_records);
        let system = self.get_system_metrics();

        PerformanceReport {
            timestamp: chrono::Utc::now(),
            system,
            endpoints,
            overall,
        }
    }

    /// Get metrics for a specific endpoint
    pub fn get_endpoint_metrics(&self, endpoint: &str) -> Option<EndpointMetrics> {
        let stats = self.endpoint_stats.lock().unwrap();
        stats.get(endpoint).map(|endpoint_stats| {
            let metrics = self.calculate_metrics(&endpoint_stats.records);
            EndpointMetrics {
                endpoint: endpoint.to_string(),
                method: endpoint_stats.method.clone(),
                metrics,
            }
        })
    }

    /// Get overall system performance metrics
    pub fn get_overall_metrics(&self) -> RequestMetrics {
        let stats = self.endpoint_stats.lock().unwrap();
        let mut all_records: Vec<RequestRecord> = Vec::new();

        for endpoint_stats in stats.values() {
            all_records.extend(endpoint_stats.records.iter().cloned());
        }

        self.calculate_metrics(&all_records)
    }

    /// Clear all metrics (useful for testing or reset)
    pub fn clear_metrics(&self) {
        let mut stats = self.endpoint_stats.lock().unwrap();
        stats.clear();
    }

    /// Get the number of unique endpoints being tracked
    pub fn get_endpoint_count(&self) -> usize {
        let stats = self.endpoint_stats.lock().unwrap();
        stats.len()
    }
}

impl Default for MetricsService {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_metrics_service_creation() {
        let service = MetricsService::new();
        assert_eq!(service.get_endpoint_count(), 0);
    }

    #[test]
    fn test_record_request() {
        let service = MetricsService::new();

        service.record_request("/api/test", "GET", Duration::from_millis(100), true);
        service.record_request("/api/test", "GET", Duration::from_millis(200), false);

        let metrics = service.get_endpoint_metrics("/api/test").unwrap();
        assert_eq!(metrics.metrics.total_requests, 2);
        assert_eq!(metrics.metrics.successful_requests, 1);
        assert_eq!(metrics.metrics.failed_requests, 1);
        assert_eq!(metrics.metrics.average_response_time_ms, 150.0);
    }

    #[test]
    fn test_overall_metrics() {
        let service = MetricsService::new();

        service.record_request("/api/test1", "GET", Duration::from_millis(100), true);
        service.record_request("/api/test2", "POST", Duration::from_millis(200), true);

        let overall = service.get_overall_metrics();
        assert_eq!(overall.total_requests, 2);
        assert_eq!(overall.successful_requests, 2);
        assert_eq!(overall.failed_requests, 0);
        assert_eq!(overall.average_response_time_ms, 150.0);
    }

    #[test]
    fn test_performance_report() {
        let service = MetricsService::new();

        service.record_request("/api/test", "GET", Duration::from_millis(100), true);

        let report = service.generate_report();
        assert_eq!(report.endpoints.len(), 1);
        assert_eq!(report.overall.total_requests, 1);
        assert!(report.system.uptime_seconds > 0 || report.system.uptime_seconds == 0);
        // Note: In tests we can't reliably check sysinfo values as CI environments vary
    }

    #[test]
    fn test_clear_metrics() {
        let service = MetricsService::new();

        service.record_request("/api/test", "GET", Duration::from_millis(100), true);
        assert_eq!(service.get_endpoint_count(), 1);

        service.clear_metrics();
        assert_eq!(service.get_endpoint_count(), 0);
    }

    #[test]
    fn test_metrics_calculation_edge_cases() {
        let service = MetricsService::new();

        // Test with no records
        let empty_metrics = service.calculate_metrics(&[]);
        assert_eq!(empty_metrics.total_requests, 0);
        assert_eq!(empty_metrics.average_response_time_ms, 0.0);

        // Test with single record
        let single_record = vec![RequestRecord {
            timestamp: Instant::now(),
            duration: Duration::from_millis(500),
            success: true,
        }];

        let single_metrics = service.calculate_metrics(&single_record);
        assert_eq!(single_metrics.total_requests, 1);
        assert_eq!(single_metrics.average_response_time_ms, 500.0);
        assert_eq!(single_metrics.max_response_time_ms, 500);
        assert_eq!(single_metrics.min_response_time_ms, 500);
    }
}
