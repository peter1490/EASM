use axum::{
    extract::{Path, State},
    http::{header, HeaderMap},
    response::{IntoResponse, Response},
};
use std::path::PathBuf;
use tokio::fs;
use crate::{AppState, error::ApiError};

/// Serve static evidence files with proper security
pub async fn serve_evidence_file(
    State(app_state): State<AppState>,
    Path(file_path): Path<String>,
) -> Result<Response, ApiError> {
    // Validate and sanitize the file path
    let sanitized_path = sanitize_file_path(&file_path)?;
    
    // Construct full path within evidence storage directory
    let evidence_dir = PathBuf::from(&app_state.settings.evidence_storage_path);
    let full_path = evidence_dir.join(&sanitized_path);
    
    // Security check: ensure the resolved path is still within evidence directory
    let canonical_evidence_dir = fs::canonicalize(&evidence_dir).await
        .map_err(|e| ApiError::internal(format!("Failed to resolve evidence directory: {}", e)))?;
    
    let canonical_file_path = match fs::canonicalize(&full_path).await {
        Ok(path) => path,
        Err(_) => return Err(ApiError::not_found("File not found")),
    };
    
    if !canonical_file_path.starts_with(&canonical_evidence_dir) {
        tracing::warn!(
            "Attempted path traversal attack: requested={}, resolved={}",
            file_path,
            canonical_file_path.display()
        );
        return Err(ApiError::authorization("Access denied"));
    }
    
    // Check if file exists and is a file (not directory)
    let metadata = match fs::metadata(&canonical_file_path).await {
        Ok(metadata) => metadata,
        Err(_) => return Err(ApiError::not_found("File not found")),
    };
    
    if !metadata.is_file() {
        return Err(ApiError::not_found("Path is not a file"));
    }
    
    // Check file size limits
    if metadata.len() > app_state.settings.max_evidence_bytes {
        return Err(ApiError::validation("File too large"));
    }
    
    // Read file content
    let file_content = fs::read(&canonical_file_path).await
        .map_err(|e| ApiError::internal(format!("Failed to read file: {}", e)))?;
    
    // Determine content type
    let content_type = determine_content_type(&canonical_file_path, &file_content);
    
    // Validate content type against allowed types
    if !is_content_type_allowed(&content_type, &app_state.settings.evidence_allowed_types) {
        return Err(ApiError::authorization("File type not allowed"));
    }
    
    // Create response with appropriate headers
    let mut headers = HeaderMap::new();
    headers.insert(header::CONTENT_TYPE, content_type.parse().unwrap());
    headers.insert(header::CONTENT_LENGTH, metadata.len().to_string().parse().unwrap());
    
    // Security headers for file serving
    headers.insert(header::CACHE_CONTROL, "no-cache, no-store, must-revalidate".parse().unwrap());
    headers.insert(header::PRAGMA, "no-cache".parse().unwrap());
    headers.insert(
        axum::http::HeaderName::from_static("x-content-type-options"), 
        "nosniff".parse().unwrap()
    );
    
    // Set Content-Disposition for downloads
    let filename = canonical_file_path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("download");
    
    headers.insert(
        header::CONTENT_DISPOSITION,
        format!("attachment; filename=\"{}\"", filename).parse().unwrap()
    );
    
    tracing::info!(
        file_path = %file_path,
        content_type = %content_type,
        file_size = metadata.len(),
        "serving evidence file"
    );
    
    Ok((headers, file_content).into_response())
}

/// Sanitize file path to prevent directory traversal attacks
fn sanitize_file_path(path: &str) -> Result<PathBuf, ApiError> {
    // Remove any path traversal attempts
    let sanitized = path
        .replace("../", "")
        .replace("..\\", "")
        .replace("./", "")
        .replace(".\\", "");
    
    // Ensure path doesn't start with / or \
    let sanitized = sanitized.trim_start_matches('/').trim_start_matches('\\');
    
    // Validate path doesn't contain null bytes or other dangerous characters
    if sanitized.contains('\0') || sanitized.contains('\x01') {
        return Err(ApiError::validation("Invalid characters in file path"));
    }
    
    // Ensure path is not empty after sanitization
    if sanitized.is_empty() {
        return Err(ApiError::validation("Empty file path"));
    }
    
    Ok(PathBuf::from(sanitized))
}

/// Determine content type based on file extension and content
fn determine_content_type(file_path: &PathBuf, _content: &[u8]) -> String {
    // Use mime_guess to determine content type from file extension
    let mime_type = mime_guess::from_path(file_path).first_or_octet_stream();
    mime_type.to_string()
}

/// Check if content type is allowed based on configuration
fn is_content_type_allowed(content_type: &str, allowed_types: &[String]) -> bool {
    if allowed_types.is_empty() {
        return true; // If no restrictions, allow all
    }
    
    // Check exact match
    if allowed_types.contains(&content_type.to_string()) {
        return true;
    }
    
    // Check wildcard matches (e.g., "image/*")
    for allowed_type in allowed_types {
        if allowed_type.ends_with("/*") {
            let prefix = &allowed_type[..allowed_type.len() - 2];
            if content_type.starts_with(prefix) {
                return true;
            }
        }
    }
    
    false
}

/// Health check for static file serving
pub async fn static_files_health_check(State(app_state): State<AppState>) -> Result<&'static str, ApiError> {
    // Check if evidence directory exists and is accessible
    let evidence_dir = PathBuf::from(&app_state.settings.evidence_storage_path);
    
    match fs::metadata(&evidence_dir).await {
        Ok(metadata) if metadata.is_dir() => Ok("Static file serving is healthy"),
        Ok(_) => Err(ApiError::internal("Evidence path is not a directory")),
        Err(e) => Err(ApiError::internal(format!("Evidence directory not accessible: {}", e))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::TempDir;

    #[test]
    fn test_sanitize_file_path() {
        // Valid paths
        assert!(sanitize_file_path("test.txt").is_ok());
        assert!(sanitize_file_path("folder/test.txt").is_ok());
        
        // Path traversal attempts
        assert_eq!(
            sanitize_file_path("../test.txt").unwrap(),
            PathBuf::from("test.txt")
        );
        assert_eq!(
            sanitize_file_path("../../test.txt").unwrap(),
            PathBuf::from("test.txt")
        );
        assert_eq!(
            sanitize_file_path("folder/../test.txt").unwrap(),
            PathBuf::from("folder/test.txt")
        );
        
        // Invalid paths
        assert!(sanitize_file_path("").is_err());
        assert!(sanitize_file_path("test\0.txt").is_err());
    }

    #[test]
    fn test_determine_content_type() {
        let path = PathBuf::from("test.txt");
        let content = b"hello world";
        assert_eq!(determine_content_type(&path, content), "text/plain");
        
        let path = PathBuf::from("test.json");
        assert_eq!(determine_content_type(&path, content), "application/json");
        
        let path = PathBuf::from("test.png");
        assert_eq!(determine_content_type(&path, content), "image/png");
    }

    #[test]
    fn test_is_content_type_allowed() {
        let allowed_types = vec![
            "text/plain".to_string(),
            "image/*".to_string(),
            "application/json".to_string(),
        ];
        
        // Exact matches
        assert!(is_content_type_allowed("text/plain", &allowed_types));
        assert!(is_content_type_allowed("application/json", &allowed_types));
        
        // Wildcard matches
        assert!(is_content_type_allowed("image/png", &allowed_types));
        assert!(is_content_type_allowed("image/jpeg", &allowed_types));
        
        // Not allowed
        assert!(!is_content_type_allowed("application/pdf", &allowed_types));
        assert!(!is_content_type_allowed("video/mp4", &allowed_types));
        
        // Empty allowed types (allow all)
        assert!(is_content_type_allowed("anything", &[]));
    }

    #[tokio::test]
    async fn test_serve_evidence_file_not_found() {
        let temp_dir = TempDir::new().unwrap();
        let settings = crate::config::Settings {
            evidence_storage_path: temp_dir.path().to_string_lossy().to_string(),
            evidence_allowed_types: vec!["text/plain".to_string()],
            max_evidence_bytes: 1024,
            ..Default::default()
        };
        
        let db_pool = crate::database::create_database_pool(&settings.database_url).await.expect("DB pool");
        let app_state = AppState::new_with_pool(settings, db_pool).await.unwrap();
        
        let result = serve_evidence_file(
            State(app_state),
            Path("nonexistent.txt".to_string())
        ).await;
        
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), ApiError::NotFound(_)));
    }

    #[tokio::test]
    async fn test_serve_evidence_file_success() {
        let temp_dir = TempDir::new().unwrap();
        let file_path = temp_dir.path().join("test.txt");
        fs::write(&file_path, "Hello, World!").unwrap();
        
        let settings = crate::config::Settings {
            evidence_storage_path: temp_dir.path().to_string_lossy().to_string(),
            evidence_allowed_types: vec!["text/plain".to_string()],
            max_evidence_bytes: 1024,
            ..Default::default()
        };
        
        let db_pool = crate::database::create_database_pool(&settings.database_url).await.expect("DB pool");
        let app_state = AppState::new_with_pool(settings, db_pool).await.unwrap();
        
        let result = serve_evidence_file(
            State(app_state),
            Path("test.txt".to_string())
        ).await;
        
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_serve_evidence_file_path_traversal() {
        let temp_dir = TempDir::new().unwrap();
        let settings = crate::config::Settings {
            evidence_storage_path: temp_dir.path().to_string_lossy().to_string(),
            evidence_allowed_types: vec!["text/plain".to_string()],
            max_evidence_bytes: 1024,
            ..Default::default()
        };
        
        let db_pool = crate::database::create_database_pool(&settings.database_url).await.expect("DB pool");
        let app_state = AppState::new_with_pool(settings, db_pool).await.unwrap();
        
        let result = serve_evidence_file(
            State(app_state),
            Path("../../../etc/passwd".to_string())
        ).await;
        
        assert!(result.is_err());
        // Should be NotFound because the sanitized path won't exist
        assert!(matches!(result.unwrap_err(), ApiError::NotFound(_)));
    }
}