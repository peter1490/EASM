use crate::error::ApiError;
use std::net::{IpAddr, SocketAddr};
use std::time::Duration;
use tokio::net::TcpStream;
use tokio::time::timeout;

pub async fn scan_port(
    ip: IpAddr,
    port: u16,
    timeout_duration: Duration,
) -> Result<bool, ApiError> {
    let socket_addr = SocketAddr::new(ip, port);

    match timeout(timeout_duration, TcpStream::connect(socket_addr)).await {
        Ok(Ok(_)) => Ok(true),
        Ok(Err(_)) => Ok(false),
        Err(_) => Ok(false), // Timeout
    }
}

pub fn expand_cidr(cidr: &str) -> Result<Vec<IpAddr>, ApiError> {
    let network: ipnet::IpNet = cidr
        .parse()
        .map_err(|e| ApiError::Validation(format!("Invalid CIDR: {}", e)))?;

    let hosts: Vec<IpAddr> = network.hosts().collect();
    Ok(hosts)
}

pub async fn scan_ports(ip: IpAddr, ports: &[u16], timeout_duration: Duration) -> Vec<u16> {
    let mut open_ports = Vec::new();

    for &port in ports {
        if let Ok(true) = scan_port(ip, port, timeout_duration).await {
            open_ports.push(port);
        }
    }

    open_ports
}
