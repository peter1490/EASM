use crate::{
    error::ApiError,
    models::{Evidence, EvidenceCreate},
    AppState,
};
use axum::{
    body::Bytes,
    extract::{Multipart, Path, State},
    http::{header, StatusCode},
    response::{Json, Response},
};
use std::path::PathBuf;
use tokio::fs;
use tokio::io::AsyncWriteExt;
use uuid::Uuid;

pub async fn upload_evidence(
    State(app_state): State<AppState>,
    Path(scan_id): Path<Uuid>,
    mut multipart: Multipart,
) -> Result<Json<Evidence>, ApiError> {
    let mut file_data: Option<Bytes> = None;
    let mut filename: Option<String> = None;
    let mut content_type: Option<String> = None;

    // Process multipart form data
    while let Some(field) = multipart
        .next_field()
        .await
        .map_err(|e| ApiError::Validation(format!("Failed to read multipart field: {}", e)))?
    {
        let field_name = field.name().unwrap_or("").to_string();

        if field_name == "file" {
            filename = field.file_name().map(|s| s.to_string());
            content_type = field.content_type().map(|s| s.to_string());
            file_data =
                Some(field.bytes().await.map_err(|e| {
                    ApiError::Validation(format!("Failed to read file data: {}", e))
                })?);
        }
    }

    let file_data =
        file_data.ok_or_else(|| ApiError::Validation("No file provided".to_string()))?;

    let filename =
        filename.ok_or_else(|| ApiError::Validation("No filename provided".to_string()))?;
    let settings = app_state.config.load();

    // Validate file size
    if file_data.len() as u64 > settings.max_evidence_bytes {
        return Err(ApiError::Validation(format!(
            "File size {} exceeds maximum allowed size of {} bytes",
            file_data.len(),
            settings.max_evidence_bytes
        )));
    }

    // Validate file type
    if let Some(ref ct) = content_type {
        if !settings.evidence_allowed_types.contains(ct) {
            return Err(ApiError::Validation(format!(
                "File type '{}' is not allowed. Allowed types: {}",
                ct,
                settings.evidence_allowed_types.join(", ")
            )));
        }
    }

    // Create evidence storage directory if it doesn't exist
    let storage_path = PathBuf::from(&settings.evidence_storage_path);
    fs::create_dir_all(&storage_path)
        .await
        .map_err(|e| ApiError::Internal(format!("Failed to create storage directory: {}", e)))?;

    // Generate unique filename to avoid conflicts
    let evidence_id = Uuid::new_v4();
    let file_path_buf = PathBuf::from(&filename);
    let file_extension = file_path_buf
        .extension()
        .and_then(|ext| ext.to_str())
        .unwrap_or("");
    let stored_filename = if file_extension.is_empty() {
        evidence_id.to_string()
    } else {
        format!("{}.{}", evidence_id, file_extension)
    };

    let file_path = storage_path.join(&stored_filename);

    // Write file to disk
    let mut file = fs::File::create(&file_path)
        .await
        .map_err(|e| ApiError::Internal(format!("Failed to create file: {}", e)))?;

    file.write_all(&file_data)
        .await
        .map_err(|e| ApiError::Internal(format!("Failed to write file: {}", e)))?;

    // Create evidence record
    let evidence_create = EvidenceCreate {
        scan_id,
        filename: filename.clone(),
        content_type: content_type.unwrap_or_else(|| "application/octet-stream".to_string()),
        file_size: file_data.len() as i64,
        file_path: file_path.to_string_lossy().to_string(),
    };

    let evidence = app_state
        .evidence_repository
        .create(&evidence_create)
        .await?;
    Ok(Json(evidence))
}

pub async fn download_evidence(
    State(app_state): State<AppState>,
    Path(id): Path<Uuid>,
) -> Result<Response, ApiError> {
    let evidence = app_state
        .evidence_repository
        .get_by_id(&id)
        .await?
        .ok_or_else(|| ApiError::NotFound(format!("Evidence {} not found", id)))?;

    let file_path = PathBuf::from(&evidence.file_path);

    // Check if file exists
    if !file_path.exists() {
        return Err(ApiError::NotFound(
            "Evidence file not found on disk".to_string(),
        ));
    }

    // Read file content
    let file_content = fs::read(&file_path)
        .await
        .map_err(|e| ApiError::Internal(format!("Failed to read file: {}", e)))?;

    // Determine content type
    let content_type = evidence.content_type.as_str();

    // Create response with appropriate headers
    let mut response = Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, content_type)
        .header(header::CONTENT_LENGTH, file_content.len())
        .header(
            header::CONTENT_DISPOSITION,
            format!("attachment; filename=\"{}\"", evidence.filename),
        );

    // Add security headers
    response = response
        .header("X-Content-Type-Options", "nosniff")
        .header("X-Frame-Options", "DENY");

    let response = response
        .body(axum::body::Body::from(file_content))
        .map_err(|e| ApiError::Internal(format!("Failed to create response: {}", e)))?;

    Ok(response)
}

pub async fn get_evidence(
    State(app_state): State<AppState>,
    Path(id): Path<Uuid>,
) -> Result<Json<Evidence>, ApiError> {
    let evidence = app_state
        .evidence_repository
        .get_by_id(&id)
        .await?
        .ok_or_else(|| ApiError::NotFound(format!("Evidence {} not found", id)))?;
    Ok(Json(evidence))
}

pub async fn list_evidence_by_scan(
    State(app_state): State<AppState>,
    Path(scan_id): Path<Uuid>,
) -> Result<Json<Vec<Evidence>>, ApiError> {
    let evidence = app_state.evidence_repository.list_by_scan(&scan_id).await?;
    Ok(Json(evidence))
}
