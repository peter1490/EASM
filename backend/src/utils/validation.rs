use std::net::IpAddr;
use crate::error::ApiError;

pub fn validate_domain(domain: &str) -> Result<(), ApiError> {
    if domain.is_empty() {
        return Err(ApiError::Validation("Domain cannot be empty".to_string()));
    }
    
    if domain.len() > 253 {
        return Err(ApiError::Validation("Domain too long".to_string()));
    }
    
    // Basic domain validation
    if !domain.chars().all(|c| c.is_alphanumeric() || c == '.' || c == '-') {
        return Err(ApiError::Validation("Invalid domain characters".to_string()));
    }
    
    Ok(())
}

pub fn validate_ip(ip_str: &str) -> Result<IpAddr, ApiError> {
    ip_str.parse()
        .map_err(|_| ApiError::Validation("Invalid IP address".to_string()))
}

pub fn validate_cidr(cidr: &str) -> Result<(), ApiError> {
    cidr.parse::<ipnet::IpNet>()
        .map_err(|_| ApiError::Validation("Invalid CIDR notation".to_string()))?;
    Ok(())
}