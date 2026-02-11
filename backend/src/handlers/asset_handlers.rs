use crate::{
    auth::{context::UserContext, rbac::Role},
    error::ApiError,
    models::{
        Asset, AssetEvolutionResponse, AssetRiskHistoryEntry, AssetScanHistoryEntry, AssetType,
        SecurityFinding, SecurityScan, Seed, SeedCreate,
    },
    AppState,
};
use axum::{
    extract::{Extension, Path, Query, State},
    http::{header, StatusCode},
    response::{Json, Response},
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::{cmp::Ordering, collections::BTreeMap};
use uuid::Uuid;

#[derive(Debug, Deserialize)]
pub struct AssetQuery {
    #[serde(default, alias = "min_confidence")]
    confidence_threshold: Option<f64>,
    #[serde(default)]
    limit: Option<i64>,
    #[serde(default)]
    offset: Option<i64>,
}

/// Advanced search query parameters for assets
#[derive(Debug, Deserialize)]
pub struct AssetSearchQuery {
    /// Text search across value, sources, and metadata
    #[serde(default)]
    pub q: Option<String>,
    /// Filter by asset type (domain, ip)
    #[serde(default)]
    pub asset_type: Option<String>,
    /// Minimum confidence threshold
    #[serde(default)]
    pub min_confidence: Option<f64>,
    /// Filter by scan status: "scanned", "never_scanned", or "all"
    #[serde(default)]
    pub scan_status: Option<String>,
    /// Filter by source (exact match)
    #[serde(default)]
    pub source: Option<String>,
    /// Filter by risk level
    #[serde(default)]
    pub risk_level: Option<String>,
    /// Sort field: "created_at", "confidence", "value", "importance"
    #[serde(default)]
    pub sort_by: Option<String>,
    /// Sort direction: "asc" or "desc"
    #[serde(default)]
    pub sort_dir: Option<String>,
    /// Pagination limit
    #[serde(default)]
    pub limit: Option<i64>,
    /// Pagination offset
    #[serde(default)]
    pub offset: Option<i64>,
}

#[derive(Debug, Serialize)]
pub struct AssetListResponse {
    pub assets: Vec<Asset>,
    pub total_count: i64,
    pub limit: i64,
    pub offset: i64,
}

#[derive(Debug, Deserialize)]
pub struct UpdateImportanceRequest {
    pub importance: i32,
}

#[derive(Debug, Deserialize)]
pub struct UpdateCommentRequest {
    pub comment: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct AssetEvolutionQuery {
    #[serde(default)]
    pub limit: Option<i64>,
}

pub async fn create_seed(
    State(app_state): State<AppState>,
    Extension(user): Extension<UserContext>,
    Json(payload): Json<SeedCreate>,
) -> Result<Json<Seed>, ApiError> {
    let company_id = user
        .company_id
        .ok_or_else(|| ApiError::Authorization("Company scope required for assets".to_string()))?;
    let seed = app_state
        .discovery_service
        .create_seed(payload, company_id)
        .await?;
    Ok(Json(seed))
}

pub async fn list_seeds(
    State(app_state): State<AppState>,
    Extension(user): Extension<UserContext>,
) -> Result<Json<Vec<Seed>>, ApiError> {
    let company_id = user
        .company_id
        .ok_or_else(|| ApiError::Authorization("Company scope required for assets".to_string()))?;
    let seeds = app_state.discovery_service.list_seeds(company_id).await?;
    Ok(Json(seeds))
}

pub async fn delete_seed(
    State(app_state): State<AppState>,
    Extension(user): Extension<UserContext>,
    Path(id): Path<Uuid>,
) -> Result<Json<()>, ApiError> {
    let company_id = user
        .company_id
        .ok_or_else(|| ApiError::Authorization("Company scope required for assets".to_string()))?;
    app_state
        .discovery_service
        .delete_seed(company_id, &id)
        .await?;
    Ok(Json(()))
}

pub async fn list_assets(
    State(app_state): State<AppState>,
    Extension(user): Extension<UserContext>,
    Query(params): Query<AssetQuery>,
) -> Result<Json<AssetListResponse>, ApiError> {
    let limit = params.limit.unwrap_or(25);
    let offset = params.offset.unwrap_or(0);
    let company_id = user
        .company_id
        .ok_or_else(|| ApiError::Authorization("Company scope required for assets".to_string()))?;

    let assets = app_state
        .discovery_service
        .list_assets(
            company_id,
            params.confidence_threshold,
            Some(limit),
            Some(offset),
        )
        .await?;

    let total_count = app_state
        .discovery_service
        .count_assets(company_id, params.confidence_threshold)
        .await?;

    Ok(Json(AssetListResponse {
        assets,
        total_count,
        limit,
        offset,
    }))
}

pub async fn get_asset(
    State(app_state): State<AppState>,
    Extension(user): Extension<UserContext>,
    Path(id): Path<Uuid>,
) -> Result<Json<Asset>, ApiError> {
    let company_id = user
        .company_id
        .ok_or_else(|| ApiError::Authorization("Company scope required for assets".to_string()))?;
    let asset = app_state
        .discovery_service
        .get_asset(company_id, &id)
        .await?
        .ok_or_else(|| ApiError::NotFound(format!("Asset {} not found", id)))?;
    Ok(Json(asset))
}

/// GET /api/assets/:id/report - Download a full PDF security and risk report for an asset
pub async fn download_asset_report(
    State(app_state): State<AppState>,
    Extension(user): Extension<UserContext>,
    Path(id): Path<Uuid>,
) -> Result<Response, ApiError> {
    let company_id = user
        .company_id
        .ok_or_else(|| ApiError::Authorization("Company scope required for assets".to_string()))?;

    let asset = app_state
        .asset_repository
        .get_by_id(company_id, &id)
        .await?
        .ok_or_else(|| ApiError::NotFound(format!("Asset {} not found", id)))?;

    let findings = app_state
        .security_finding_repository
        .list_by_asset(&id, 2000, company_id)
        .await?;

    let scans = app_state
        .security_scan_service
        .list_scans_for_asset(&id, company_id)
        .await?;
    let risk_history = app_state
        .asset_repository
        .get_risk_history(company_id, &id, 60)
        .await?;

    let pdf_bytes = generate_asset_pdf_report(&asset, &findings, &scans, &risk_history)?;
    let safe_identifier = sanitize_filename_component(&asset.identifier);
    let filename = format!("asset-security-risk-overview-{}.pdf", safe_identifier);

    let response = Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, "application/pdf")
        .header(header::CONTENT_LENGTH, pdf_bytes.len())
        .header(
            header::CONTENT_DISPOSITION,
            format!("attachment; filename=\"{}\"", filename),
        )
        .header("X-Content-Type-Options", "nosniff")
        .header("X-Frame-Options", "DENY")
        .body(axum::body::Body::from(pdf_bytes))
        .map_err(|e| ApiError::Internal(format!("Failed to build PDF response: {}", e)))?;

    Ok(response)
}

pub async fn get_asset_path(
    State(app_state): State<AppState>,
    Extension(user): Extension<UserContext>,
    Path(id): Path<Uuid>,
) -> Result<Json<Vec<Asset>>, ApiError> {
    let company_id = user
        .company_id
        .ok_or_else(|| ApiError::Authorization("Company scope required for assets".to_string()))?;
    let path = app_state
        .discovery_service
        .get_asset_path(company_id, &id)
        .await?;
    Ok(Json(path))
}

pub async fn update_asset_importance(
    State(app_state): State<AppState>,
    Extension(user): Extension<UserContext>,
    Path(id): Path<Uuid>,
    Json(payload): Json<UpdateImportanceRequest>,
) -> Result<Json<Asset>, ApiError> {
    if !user.has_role(Role::Analyst)
        && !user.has_role(Role::Operator)
        && !user.has_role(Role::Admin)
    {
        return Err(ApiError::Authorization(
            "Analyst role or higher required".to_string(),
        ));
    }

    if payload.importance < 0 || payload.importance > 5 {
        return Err(ApiError::Validation(
            "Importance must be between 0 and 5".to_string(),
        ));
    }

    let company_id = user
        .company_id
        .ok_or_else(|| ApiError::Authorization("Company scope required for assets".to_string()))?;
    let asset = app_state
        .asset_repository
        .update_importance(company_id, &id, payload.importance)
        .await?;
    Ok(Json(asset))
}

pub async fn update_asset_comment(
    State(app_state): State<AppState>,
    Extension(user): Extension<UserContext>,
    Path(id): Path<Uuid>,
    Json(payload): Json<UpdateCommentRequest>,
) -> Result<Json<Asset>, ApiError> {
    if !user.has_role(Role::Analyst)
        && !user.has_role(Role::Operator)
        && !user.has_role(Role::Admin)
    {
        return Err(ApiError::Authorization(
            "Analyst role or higher required".to_string(),
        ));
    }

    let normalized_comment = payload
        .comment
        .as_deref()
        .map(str::trim)
        .filter(|comment| !comment.is_empty());

    if let Some(comment) = normalized_comment {
        if comment.chars().count() > 1000 {
            return Err(ApiError::Validation(
                "Comment must be at most 1000 characters".to_string(),
            ));
        }
    }

    let company_id = user
        .company_id
        .ok_or_else(|| ApiError::Authorization("Company scope required for assets".to_string()))?;
    let asset = app_state
        .asset_repository
        .update_comment(company_id, &id, normalized_comment)
        .await?;
    Ok(Json(asset))
}

/// GET /api/assets/:id/evolution - Get evolution history for an asset
pub async fn get_asset_evolution(
    State(app_state): State<AppState>,
    Extension(user): Extension<UserContext>,
    Path(id): Path<Uuid>,
    Query(params): Query<AssetEvolutionQuery>,
) -> Result<Json<AssetEvolutionResponse>, ApiError> {
    let company_id = user
        .company_id
        .ok_or_else(|| ApiError::Authorization("Company scope required for assets".to_string()))?;
    let limit = params.limit.unwrap_or(50).min(200);

    // Ensure asset exists and is accessible
    let _asset = app_state
        .asset_repository
        .get_by_id(company_id, &id)
        .await?
        .ok_or_else(|| ApiError::NotFound(format!("Asset {} not found", id)))?;

    let risk_history = app_state
        .asset_repository
        .get_risk_history(company_id, &id, limit)
        .await?;

    let scans = app_state
        .security_scan_service
        .list_scans_for_asset(&id, company_id)
        .await?;

    let scan_history: Vec<AssetScanHistoryEntry> = scans
        .into_iter()
        .take(limit as usize)
        .map(|scan| AssetScanHistoryEntry {
            id: scan.id,
            scan_type: scan.scan_type,
            status: scan.status,
            created_at: scan.created_at,
            started_at: scan.started_at,
            completed_at: scan.completed_at,
            result_summary: scan.result_summary,
        })
        .collect();

    Ok(Json(AssetEvolutionResponse {
        risk_history,
        scan_history,
    }))
}

/// Advanced search response with sources list
#[derive(Debug, Serialize)]
pub struct AssetSearchResponse {
    pub assets: Vec<Asset>,
    pub total_count: i64,
    pub sources: Vec<String>,
    pub limit: i64,
    pub offset: i64,
}

/// Advanced asset search endpoint with full-text search and filtering
pub async fn search_assets(
    State(app_state): State<AppState>,
    Extension(user): Extension<UserContext>,
    Query(params): Query<AssetSearchQuery>,
) -> Result<Json<AssetSearchResponse>, ApiError> {
    let limit = params.limit.unwrap_or(25).min(500);
    let offset = params.offset.unwrap_or(0);
    let company_id = user
        .company_id
        .ok_or_else(|| ApiError::Authorization("Company scope required for assets".to_string()))?;

    // Parse asset type if provided
    let asset_type = params
        .asset_type
        .as_ref()
        .and_then(|t| match t.to_lowercase().as_str() {
            "domain" => Some(AssetType::Domain),
            "ip" => Some(AssetType::Ip),
            _ => None,
        });

    // Parse sort options
    let sort_by = params.sort_by.as_deref().unwrap_or("created_at");
    let sort_dir = params.sort_dir.as_deref().unwrap_or("desc");

    // Call the repository search method
    let (assets, total_count, sources) = app_state
        .asset_repository
        .search(
            company_id,
            params.q.as_deref(),
            asset_type,
            params.min_confidence,
            params.scan_status.as_deref(),
            params.source.as_deref(),
            params.risk_level.as_deref(),
            sort_by,
            sort_dir,
            limit,
            offset,
        )
        .await?;

    Ok(Json(AssetSearchResponse {
        assets,
        total_count,
        sources,
        limit,
        offset,
    }))
}

#[derive(Clone)]
struct ReportLine {
    text: String,
    font_size: f32,
    bold: bool,
    indent: f32,
    color: (f32, f32, f32),
    line_height: f32,
}

fn generate_asset_pdf_report(
    asset: &Asset,
    findings: &[SecurityFinding],
    scans: &[SecurityScan],
    risk_history: &[AssetRiskHistoryEntry],
) -> Result<Vec<u8>, ApiError> {
    let generated_at = Utc::now();
    let findings_summary = summarize_findings(findings);
    let lines = build_report_lines(asset, findings, scans, &findings_summary);
    let pages = paginate_report_lines(lines);
    let mut rendered_pages = vec![render_dashboard_page(
        asset,
        &findings_summary,
        scans,
        risk_history,
        generated_at,
        1,
        pages.len() + 1,
    )];
    rendered_pages.extend(
        pages
            .iter()
            .enumerate()
            .map(|(idx, page_lines)| {
                render_pdf_page(
                    page_lines,
                    idx + 2,
                    pages.len() + 1,
                    &asset.identifier,
                    generated_at,
                )
            })
            .collect::<Vec<_>>(),
    );
    Ok(build_pdf_document(rendered_pages))
}

fn build_report_lines(
    asset: &Asset,
    findings: &[SecurityFinding],
    scans: &[SecurityScan],
    summary: &FindingsSummary,
) -> Vec<ReportLine> {
    let mut lines = Vec::new();

    let discovery_sources = parse_sources(&asset.sources);
    let risk_score = asset
        .risk_score
        .map(|score| format!("{:.1}/100", score))
        .unwrap_or_else(|| "Not calculated".to_string());
    let risk_level = asset
        .risk_level
        .clone()
        .unwrap_or_else(|| "unknown".to_string());

    push_section_title(&mut lines, "Executive Summary");
    push_wrapped_text(
        &mut lines,
        &format!("Asset: {}", asset.identifier),
        11.0,
        true,
        0.0,
        (0.05, 0.05, 0.05),
        88,
    );
    push_text_line(
        &mut lines,
        &format!("Asset type: {}", asset.asset_type),
        10.5,
        false,
        0.0,
        (0.14, 0.14, 0.14),
    );
    push_text_line(
        &mut lines,
        &format!("Ownership confidence: {:.2}", asset.confidence),
        10.5,
        false,
        0.0,
        (0.14, 0.14, 0.14),
    );
    push_text_line(
        &mut lines,
        &format!("Risk score: {} ({})", risk_score, risk_level),
        10.5,
        false,
        0.0,
        (0.14, 0.14, 0.14),
    );
    push_text_line(
        &mut lines,
        &format!(
            "Security findings: {} total | {} active | {} resolved",
            findings.len(),
            summary.active_findings,
            summary.resolved_findings
        ),
        10.5,
        false,
        0.0,
        (0.14, 0.14, 0.14),
    );
    push_text_line(
        &mut lines,
        &format!("Scans executed: {}", scans.len()),
        10.5,
        false,
        0.0,
        (0.14, 0.14, 0.14),
    );
    push_spacer(&mut lines, 8.0);

    push_section_title(&mut lines, "Risk Overview");
    push_text_line(
        &mut lines,
        &format!("Risk level: {}", uppercase_first(&risk_level)),
        10.5,
        false,
        0.0,
        (0.14, 0.14, 0.14),
    );
    push_text_line(
        &mut lines,
        &format!("Business importance: {}/5", asset.importance),
        10.5,
        false,
        0.0,
        (0.14, 0.14, 0.14),
    );
    push_text_line(
        &mut lines,
        &format!(
            "Last risk calculation: {}",
            format_datetime(asset.last_risk_run.as_ref())
        ),
        10.5,
        false,
        0.0,
        (0.14, 0.14, 0.14),
    );
    push_text_line(
        &mut lines,
        &format!("Lifecycle status: {}", uppercase_first(&asset.status)),
        10.5,
        false,
        0.0,
        (0.14, 0.14, 0.14),
    );
    if let Some(method) = &asset.discovery_method {
        push_text_line(
            &mut lines,
            &format!("Discovery method: {}", method),
            10.5,
            false,
            0.0,
            (0.14, 0.14, 0.14),
        );
    }
    push_spacer(&mut lines, 8.0);

    push_section_title(&mut lines, "Security Findings Summary");
    push_text_line(
        &mut lines,
        &format!(
            "Critical: {} | High: {} | Medium: {} | Low: {} | Info: {}",
            summary.by_severity("critical"),
            summary.by_severity("high"),
            summary.by_severity("medium"),
            summary.by_severity("low"),
            summary.by_severity("info")
        ),
        10.5,
        false,
        0.0,
        (0.14, 0.14, 0.14),
    );
    push_text_line(
        &mut lines,
        &format!(
            "Open: {} | In progress: {} | Acknowledged: {} | Resolved: {}",
            summary.by_status("open"),
            summary.by_status("in_progress"),
            summary.by_status("acknowledged"),
            summary.resolved_findings
        ),
        10.5,
        false,
        0.0,
        (0.14, 0.14, 0.14),
    );
    push_spacer(&mut lines, 5.0);

    let mut prioritized_findings = findings.to_vec();
    prioritized_findings.sort_by(|a, b| {
        severity_rank(&b.severity)
            .cmp(&severity_rank(&a.severity))
            .then_with(|| {
                b.cvss_score
                    .partial_cmp(&a.cvss_score)
                    .unwrap_or(Ordering::Equal)
            })
            .then_with(|| b.first_seen_at.cmp(&a.first_seen_at))
    });

    if prioritized_findings.is_empty() {
        push_text_line(
            &mut lines,
            "No findings have been recorded for this asset.",
            10.0,
            false,
            0.0,
            (0.14, 0.14, 0.14),
        );
    } else {
        for (idx, finding) in prioritized_findings.iter().enumerate() {
            push_wrapped_text(
                &mut lines,
                &format!(
                    "{}. [{}] {}",
                    idx + 1,
                    finding.severity.to_uppercase(),
                    finding.title
                ),
                10.25,
                true,
                0.0,
                severity_theme_color(&finding.severity),
                86,
            );
            push_wrapped_text(
                &mut lines,
                &format!(
                    "Status: {} | CVSS: {} | First seen: {}",
                    finding.status,
                    finding
                        .cvss_score
                        .map(|s| format!("{:.1}", s))
                        .unwrap_or_else(|| "n/a".to_string()),
                    format_datetime(Some(&finding.first_seen_at))
                ),
                9.5,
                false,
                14.0,
                (0.2, 0.2, 0.2),
                82,
            );
            if let Some(description) = &finding.description {
                push_wrapped_text(
                    &mut lines,
                    &truncate_text(description, 320),
                    9.3,
                    false,
                    14.0,
                    (0.24, 0.24, 0.24),
                    82,
                );
            }
            if let Some(remediation) = &finding.remediation {
                push_wrapped_text(
                    &mut lines,
                    &format!("Remediation: {}", truncate_text(remediation, 200)),
                    9.3,
                    false,
                    14.0,
                    (0.24, 0.24, 0.24),
                    82,
                );
            }
            push_spacer(&mut lines, 4.0);
        }
    }

    push_spacer(&mut lines, 8.0);
    push_section_title(&mut lines, "Recent Scan Activity");
    if scans.is_empty() {
        push_text_line(
            &mut lines,
            "No security scans are available for this asset yet.",
            10.0,
            false,
            0.0,
            (0.14, 0.14, 0.14),
        );
    } else {
        for scan in scans.iter().take(30) {
            push_wrapped_text(
                &mut lines,
                &format!(
                    "{} | status: {} | started: {} | completed: {}",
                    scan.scan_type,
                    scan.status,
                    format_datetime(scan.started_at.as_ref()),
                    format_datetime(scan.completed_at.as_ref())
                ),
                9.8,
                false,
                0.0,
                (0.14, 0.14, 0.14),
                84,
            );
        }
    }

    push_spacer(&mut lines, 8.0);
    push_section_title(&mut lines, "Discovery Context");
    push_text_line(
        &mut lines,
        &format!(
            "First seen: {} | Last seen: {}",
            format_datetime(asset.first_seen_at.as_ref()),
            format_datetime(asset.last_seen_at.as_ref())
        ),
        10.0,
        false,
        0.0,
        (0.14, 0.14, 0.14),
    );
    if discovery_sources.is_empty() {
        push_text_line(
            &mut lines,
            "Sources: none",
            10.0,
            false,
            0.0,
            (0.14, 0.14, 0.14),
        );
    } else {
        push_wrapped_text(
            &mut lines,
            &format!("Sources: {}", discovery_sources.join(", ")),
            10.0,
            false,
            0.0,
            (0.14, 0.14, 0.14),
            85,
        );
    }

    push_spacer(&mut lines, 8.0);
    push_section_title(&mut lines, "Metadata Highlights");
    if let Some(metadata_obj) = asset.metadata.as_object() {
        let mut keys = metadata_obj.keys().cloned().collect::<Vec<_>>();
        keys.sort();
        if keys.is_empty() {
            push_text_line(
                &mut lines,
                "No metadata available.",
                10.0,
                false,
                0.0,
                (0.14, 0.14, 0.14),
            );
        } else {
            for key in keys.iter().take(25) {
                let value = metadata_obj
                    .get(key)
                    .map(|v| summarize_json_value(v, 180))
                    .unwrap_or_else(|| "null".to_string());
                push_wrapped_text(
                    &mut lines,
                    &format!("{}: {}", key, value),
                    9.5,
                    false,
                    0.0,
                    (0.18, 0.18, 0.18),
                    84,
                );
            }
        }
    } else {
        push_text_line(
            &mut lines,
            "Metadata is not in object format.",
            10.0,
            false,
            0.0,
            (0.14, 0.14, 0.14),
        );
    }

    lines
}

fn push_section_title(lines: &mut Vec<ReportLine>, title: &str) {
    lines.push(ReportLine {
        text: title.to_string(),
        font_size: 13.0,
        bold: true,
        indent: 0.0,
        color: (0.06, 0.2, 0.38),
        line_height: 20.0,
    });
}

fn push_text_line(
    lines: &mut Vec<ReportLine>,
    text: &str,
    font_size: f32,
    bold: bool,
    indent: f32,
    color: (f32, f32, f32),
) {
    lines.push(ReportLine {
        text: text.to_string(),
        font_size,
        bold,
        indent,
        color,
        line_height: (font_size + 4.2).max(11.0),
    });
}

fn push_spacer(lines: &mut Vec<ReportLine>, spacing: f32) {
    lines.push(ReportLine {
        text: String::new(),
        font_size: 9.0,
        bold: false,
        indent: 0.0,
        color: (0.0, 0.0, 0.0),
        line_height: spacing,
    });
}

fn push_wrapped_text(
    lines: &mut Vec<ReportLine>,
    text: &str,
    font_size: f32,
    bold: bool,
    indent: f32,
    color: (f32, f32, f32),
    max_chars: usize,
) {
    let wrapped = wrap_text(text, max_chars);
    for segment in wrapped {
        push_text_line(lines, &segment, font_size, bold, indent, color);
    }
}

fn wrap_text(text: &str, max_chars: usize) -> Vec<String> {
    let normalized = text
        .replace('\n', " ")
        .replace('\r', " ")
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ");
    if normalized.is_empty() {
        return vec![String::new()];
    }

    let mut lines = Vec::new();
    let mut current = String::new();

    for word in normalized.split_whitespace() {
        if word.len() > max_chars {
            if !current.is_empty() {
                lines.push(current.clone());
                current.clear();
            }
            for chunk in chunk_string(word, max_chars) {
                lines.push(chunk);
            }
            continue;
        }

        if current.is_empty() {
            current.push_str(word);
        } else if current.len() + 1 + word.len() <= max_chars {
            current.push(' ');
            current.push_str(word);
        } else {
            lines.push(current.clone());
            current.clear();
            current.push_str(word);
        }
    }

    if !current.is_empty() {
        lines.push(current);
    }

    if lines.is_empty() {
        vec![String::new()]
    } else {
        lines
    }
}

fn chunk_string(value: &str, chunk_size: usize) -> Vec<String> {
    let mut chunks = Vec::new();
    let mut start = 0;
    let chars = value.chars().collect::<Vec<_>>();
    while start < chars.len() {
        let end = (start + chunk_size).min(chars.len());
        let chunk = chars[start..end].iter().collect::<String>();
        chunks.push(chunk);
        start = end;
    }
    chunks
}

fn paginate_report_lines(lines: Vec<ReportLine>) -> Vec<Vec<ReportLine>> {
    const TOP_START: f32 = 742.0;
    const FOOTER_SPACE: f32 = 62.0;

    let mut pages = Vec::<Vec<ReportLine>>::new();
    let mut current_page = Vec::<ReportLine>::new();
    let mut y = TOP_START;

    for line in lines {
        if y - line.line_height < FOOTER_SPACE && !current_page.is_empty() {
            pages.push(current_page);
            current_page = Vec::new();
            y = TOP_START;
        }
        y -= line.line_height;
        current_page.push(line);
    }

    if current_page.is_empty() {
        current_page.push(ReportLine {
            text: "No report data available.".to_string(),
            font_size: 10.0,
            bold: false,
            indent: 0.0,
            color: (0.12, 0.12, 0.12),
            line_height: 12.0,
        });
    }
    pages.push(current_page);
    pages
}

fn render_pdf_page(
    lines: &[ReportLine],
    page_number: usize,
    total_pages: usize,
    asset_identifier: &str,
    generated_at: DateTime<Utc>,
) -> String {
    let mut content = String::new();
    content.push_str("0.98 0.985 0.995 rg 0 0 595 842 re f\n");
    content.push_str("q\n");
    content.push_str("0.04 0.16 0.33 rg\n");
    content.push_str("0 772 595 70 re f\n");
    content.push_str("0.08 0.30 0.58 rg\n");
    content.push_str("0 772 595 8 re f\n");
    content.push_str("Q\n");
    content.push_str(&format!(
        "BT /F2 21 Tf 1 1 1 rg 40 814 Td ({}) Tj ET\n",
        pdf_escape("Security & Risk Report")
    ));
    content.push_str(&format!(
        "BT /F1 10 Tf 0.90 0.95 1 rg 40 794 Td ({}) Tj ET\n",
        pdf_escape(&format!("Asset: {}", asset_identifier))
    ));
    content.push_str(&format!(
        "BT /F1 9 Tf 0.90 0.95 1 rg 40 780 Td ({}) Tj ET\n",
        pdf_escape(&format!(
            "Generated: {} UTC",
            generated_at.format("%Y-%m-%d %H:%M")
        ))
    ));

    let mut y = 742.0;
    for line in lines {
        y -= line.line_height;
        if line.text.is_empty() {
            continue;
        }

        let font_name = if line.bold { "F2" } else { "F1" };
        content.push_str(&format!(
            "BT /{} {:.2} Tf {:.3} {:.3} {:.3} rg {:.2} {:.2} Td ({}) Tj ET\n",
            font_name,
            line.font_size,
            line.color.0,
            line.color.1,
            line.color.2,
            40.0 + line.indent,
            y,
            pdf_escape(&line.text)
        ));
    }

    content.push_str("0.72 0.72 0.72 rg 0.6 w 40 50 m 555 50 l S\n");
    content.push_str(&format!(
        "BT /F1 8.8 Tf 0.35 0.35 0.35 rg 40 36 Td ({}) Tj ET\n",
        pdf_escape("Confidential - Generated by EASM")
    ));
    content.push_str(&format!(
        "BT /F1 8.8 Tf 0.35 0.35 0.35 rg 465 36 Td ({}) Tj ET\n",
        pdf_escape(&format!("Page {} of {}", page_number, total_pages))
    ));
    content
}

fn render_dashboard_page(
    asset: &Asset,
    summary: &FindingsSummary,
    scans: &[SecurityScan],
    risk_history: &[AssetRiskHistoryEntry],
    generated_at: DateTime<Utc>,
    page_number: usize,
    total_pages: usize,
) -> String {
    let mut content = String::new();
    let risk_score = asset.risk_score.unwrap_or(0.0).clamp(0.0, 100.0);
    let high_impact = summary.by_severity("critical") + summary.by_severity("high");

    content.push_str("0.95 0.97 0.99 rg 0 0 595 842 re f\n");
    content.push_str("q\n");
    content.push_str("0.05 0.18 0.35 rg 0 740 595 102 re f\n");
    content.push_str("0.10 0.36 0.62 rg 0 740 595 14 re f\n");
    content.push_str("Q\n");
    pdf_text(
        &mut content,
        "F2",
        24.0,
        (1.0, 1.0, 1.0),
        36.0,
        804.0,
        "Security Dashboard",
    );
    pdf_text(
        &mut content,
        "F1",
        11.0,
        (0.90, 0.95, 1.0),
        36.0,
        782.0,
        &format!("Asset: {}", asset.identifier),
    );
    pdf_text(
        &mut content,
        "F1",
        9.5,
        (0.86, 0.92, 0.98),
        36.0,
        766.0,
        &format!("Generated: {} UTC", generated_at.format("%Y-%m-%d %H:%M")),
    );
    pdf_text(
        &mut content,
        "F1",
        9.5,
        (0.86, 0.92, 0.98),
        400.0,
        766.0,
        &format!(
            "Type: {} | Confidence: {:.2}",
            asset.asset_type, asset.confidence
        ),
    );

    render_kpi_card(
        &mut content,
        36.0,
        646.0,
        125.0,
        80.0,
        "Risk Score",
        &format!("{:.1}/100", risk_score),
        risk_level_color(asset.risk_level.as_deref()),
    );
    render_kpi_card(
        &mut content,
        174.0,
        646.0,
        125.0,
        80.0,
        "Active Findings",
        &summary.active_findings.to_string(),
        (0.77, 0.16, 0.25),
    );
    render_kpi_card(
        &mut content,
        312.0,
        646.0,
        125.0,
        80.0,
        "Critical + High",
        &high_impact.to_string(),
        (0.93, 0.45, 0.08),
    );
    render_kpi_card(
        &mut content,
        450.0,
        646.0,
        109.0,
        80.0,
        "Scans",
        &scans.len().to_string(),
        (0.09, 0.55, 0.42),
    );

    draw_card_bg(&mut content, 36.0, 422.0, 258.0, 196.0);
    pdf_text(
        &mut content,
        "F2",
        12.0,
        (0.10, 0.18, 0.30),
        52.0,
        592.0,
        "Risk Gauge",
    );
    draw_risk_gauge(&mut content, 58.0, 530.0, 214.0, 18.0, risk_score);
    pdf_text(
        &mut content,
        "F1",
        10.0,
        (0.20, 0.24, 0.30),
        58.0,
        505.0,
        &format!(
            "Risk Level: {}",
            uppercase_first(asset.risk_level.as_deref().unwrap_or("unknown"))
        ),
    );
    pdf_text(
        &mut content,
        "F1",
        9.5,
        (0.27, 0.30, 0.35),
        58.0,
        486.0,
        &format!(
            "Importance: {}/5 | Last risk run: {}",
            asset.importance,
            format_datetime(asset.last_risk_run.as_ref())
        ),
    );
    let top_findings = top_finding_titles(summary, scans, asset);
    for (idx, line) in top_findings.iter().enumerate() {
        pdf_text(
            &mut content,
            "F1",
            9.2,
            (0.22, 0.26, 0.33),
            58.0,
            456.0 - idx as f32 * 14.0,
            line,
        );
    }

    draw_card_bg(&mut content, 308.0, 422.0, 251.0, 196.0);
    pdf_text(
        &mut content,
        "F2",
        12.0,
        (0.10, 0.18, 0.30),
        324.0,
        592.0,
        "Findings by Severity",
    );
    draw_severity_chart(&mut content, 330.0, 452.0, 205.0, 112.0, summary);

    draw_card_bg(&mut content, 36.0, 214.0, 523.0, 180.0);
    pdf_text(
        &mut content,
        "F2",
        12.0,
        (0.10, 0.18, 0.30),
        52.0,
        370.0,
        "Finding Status Distribution",
    );
    draw_status_distribution(&mut content, 52.0, 338.0, 491.0, 22.0, summary);

    pdf_text(
        &mut content,
        "F2",
        12.0,
        (0.10, 0.18, 0.30),
        52.0,
        296.0,
        "Risk Trend",
    );
    draw_risk_trend_chart(&mut content, 52.0, 236.0, 275.0, 56.0, risk_history);

    pdf_text(
        &mut content,
        "F2",
        12.0,
        (0.10, 0.18, 0.30),
        348.0,
        296.0,
        "Scan Activity",
    );
    draw_scan_status_chart(&mut content, 348.0, 236.0, 195.0, 56.0, scans);

    content.push_str("0.72 0.72 0.76 rg 0.6 w 36 44 m 559 44 l S\n");
    pdf_text(
        &mut content,
        "F1",
        8.6,
        (0.32, 0.35, 0.40),
        36.0,
        30.0,
        "Confidential - Generated by EASM",
    );
    pdf_text(
        &mut content,
        "F1",
        8.6,
        (0.32, 0.35, 0.40),
        500.0,
        30.0,
        &format!("Page {} of {}", page_number, total_pages),
    );

    content
}

fn draw_card_bg(content: &mut String, x: f32, y: f32, w: f32, h: f32) {
    content.push_str(&format!(
        "1 1 1 rg {:.2} {:.2} {:.2} {:.2} re f\n",
        x, y, w, h
    ));
    content.push_str("0.88 0.91 0.95 RG 0.8 w\n");
    content.push_str(&format!("{:.2} {:.2} {:.2} {:.2} re S\n", x, y, w, h));
}

fn render_kpi_card(
    content: &mut String,
    x: f32,
    y: f32,
    w: f32,
    h: f32,
    title: &str,
    value: &str,
    accent: (f32, f32, f32),
) {
    draw_card_bg(content, x, y, w, h);
    content.push_str(&format!(
        "{:.3} {:.3} {:.3} rg {:.2} {:.2} {:.2} 7 re f\n",
        accent.0,
        accent.1,
        accent.2,
        x,
        y + h - 7.0,
        w
    ));
    pdf_text(
        content,
        "F1",
        9.2,
        (0.28, 0.32, 0.38),
        x + 12.0,
        y + h - 25.0,
        title,
    );
    pdf_text(
        content,
        "F2",
        19.0,
        (0.12, 0.17, 0.24),
        x + 12.0,
        y + 28.0,
        value,
    );
}

fn draw_risk_gauge(content: &mut String, x: f32, y: f32, w: f32, h: f32, score: f64) {
    let third = w / 3.0;
    content.push_str(&format!(
        "0.16 0.64 0.44 rg {:.2} {:.2} {:.2} {:.2} re f\n",
        x, y, third, h
    ));
    content.push_str(&format!(
        "0.94 0.74 0.18 rg {:.2} {:.2} {:.2} {:.2} re f\n",
        x + third,
        y,
        third,
        h
    ));
    content.push_str(&format!(
        "0.82 0.20 0.24 rg {:.2} {:.2} {:.2} {:.2} re f\n",
        x + 2.0 * third,
        y,
        third,
        h
    ));
    content.push_str("0.82 0.85 0.90 RG 1 w\n");
    content.push_str(&format!("{:.2} {:.2} {:.2} {:.2} re S\n", x, y, w, h));
    let marker_x = x + ((score as f32 / 100.0) * w);
    content.push_str(&format!(
        "0.08 0.10 0.12 rg {:.2} {:.2} m {:.2} {:.2} l {:.2} {:.2} l f\n",
        marker_x,
        y + h + 8.0,
        marker_x - 5.0,
        y + h + 1.5,
        marker_x + 5.0,
        y + h + 1.5
    ));
    pdf_text(
        content,
        "F2",
        11.0,
        (0.18, 0.23, 0.31),
        marker_x - 14.0,
        y + h + 13.0,
        &format!("{:.0}", score),
    );
}

fn draw_severity_chart(
    content: &mut String,
    x: f32,
    y: f32,
    w: f32,
    h: f32,
    summary: &FindingsSummary,
) {
    let levels = ["critical", "high", "medium", "low", "info"];
    let labels = ["C", "H", "M", "L", "I"];
    let colors = [
        (0.72, 0.11, 0.18),
        (0.84, 0.31, 0.12),
        (0.92, 0.63, 0.15),
        (0.26, 0.60, 0.84),
        (0.44, 0.50, 0.60),
    ];
    let values = levels
        .iter()
        .map(|lvl| summary.by_severity(lvl) as f32)
        .collect::<Vec<_>>();
    let max_value = values.iter().copied().fold(0.0, f32::max).max(1.0);
    let bar_w = w / 8.0;
    let gap = (w - bar_w * values.len() as f32) / (values.len() as f32 + 1.0);

    content.push_str("0.80 0.84 0.90 RG 0.7 w\n");
    content.push_str(&format!("{:.2} {:.2} m {:.2} {:.2} l S\n", x, y, x + w, y));
    for (idx, value) in values.iter().enumerate() {
        let bx = x + gap + idx as f32 * (bar_w + gap);
        let bh = (*value / max_value) * h;
        let by = y;
        let color = colors[idx];
        content.push_str(&format!(
            "{:.3} {:.3} {:.3} rg {:.2} {:.2} {:.2} {:.2} re f\n",
            color.0, color.1, color.2, bx, by, bar_w, bh
        ));
        pdf_text(
            content,
            "F1",
            8.5,
            (0.30, 0.34, 0.40),
            bx + 1.0,
            y - 14.0,
            labels[idx],
        );
        pdf_text(
            content,
            "F1",
            8.0,
            (0.22, 0.25, 0.30),
            bx + 1.0,
            by + bh + 6.0,
            &format!("{}", *value as i32),
        );
    }
}

fn draw_status_distribution(
    content: &mut String,
    x: f32,
    y: f32,
    w: f32,
    h: f32,
    summary: &FindingsSummary,
) {
    let status_def = [
        ("open", "Open", (0.80, 0.22, 0.24)),
        ("in_progress", "In Progress", (0.96, 0.62, 0.20)),
        ("acknowledged", "Acknowledged", (0.18, 0.52, 0.82)),
        ("resolved", "Resolved", (0.15, 0.66, 0.47)),
        ("false_positive", "False+", (0.54, 0.57, 0.64)),
    ];
    let total = status_def
        .iter()
        .map(|(key, _, _)| summary.by_status(key))
        .sum::<usize>()
        .max(1);

    draw_card_bg(content, x - 2.0, y - 2.0, w + 4.0, h + 4.0);
    let mut cursor = x;
    for (idx, (key, label, color)) in status_def.iter().enumerate() {
        let count = summary.by_status(key);
        if count == 0 {
            continue;
        }
        let seg_w = ((count as f32 / total as f32) * w).max(if idx == status_def.len() - 1 {
            0.0
        } else {
            1.5
        });
        content.push_str(&format!(
            "{:.3} {:.3} {:.3} rg {:.2} {:.2} {:.2} {:.2} re f\n",
            color.0, color.1, color.2, cursor, y, seg_w, h
        ));
        if seg_w > 45.0 {
            pdf_text(
                content,
                "F1",
                8.3,
                (1.0, 1.0, 1.0),
                cursor + 4.0,
                y + 7.0,
                &format!("{} {}", label, count),
            );
        }
        cursor += seg_w;
    }
}

fn draw_risk_trend_chart(
    content: &mut String,
    x: f32,
    y: f32,
    w: f32,
    h: f32,
    risk_history: &[AssetRiskHistoryEntry],
) {
    draw_card_bg(content, x - 2.0, y - 2.0, w + 4.0, h + 4.0);
    content.push_str("0.85 0.88 0.93 RG 0.6 w\n");
    content.push_str(&format!("{:.2} {:.2} m {:.2} {:.2} l S\n", x, y, x, y + h));
    content.push_str(&format!("{:.2} {:.2} m {:.2} {:.2} l S\n", x, y, x + w, y));

    let mut points = risk_history.to_vec();
    points.sort_by(|a, b| a.calculated_at.cmp(&b.calculated_at));
    if points.len() < 2 {
        pdf_text(
            content,
            "F1",
            9.0,
            (0.42, 0.45, 0.52),
            x + 8.0,
            y + h / 2.0,
            "Not enough history",
        );
        return;
    }
    let start_ts = points
        .first()
        .map(|p| p.calculated_at.timestamp())
        .unwrap_or_else(|| Utc::now().timestamp());
    let end_ts = points
        .last()
        .map(|p| p.calculated_at.timestamp())
        .unwrap_or_else(|| Utc::now().timestamp());
    let span = (end_ts - start_ts).max(1) as f32;
    content.push_str("0.07 0.44 0.76 RG 1.8 w\n");
    let mut plot_points = Vec::new();
    for (idx, point) in points.iter().enumerate() {
        let t = (point.calculated_at.timestamp() - start_ts) as f32 / span;
        let px = x + t * w;
        let py = y + ((point.risk_score as f32).clamp(0.0, 100.0) / 100.0) * h;
        plot_points.push((px, py));
        if idx == 0 {
            content.push_str(&format!("{:.2} {:.2} m\n", px, py));
        } else {
            content.push_str(&format!("{:.2} {:.2} l\n", px, py));
        }
    }
    content.push_str("S\n");
    for (px, py) in plot_points {
        content.push_str(&format!(
            "0.07 0.44 0.76 rg {:.2} {:.2} 3.2 3.2 re f\n",
            px - 1.6,
            py - 1.6
        ));
    }
}

fn draw_scan_status_chart(
    content: &mut String,
    x: f32,
    y: f32,
    w: f32,
    h: f32,
    scans: &[SecurityScan],
) {
    draw_card_bg(content, x - 2.0, y - 2.0, w + 4.0, h + 4.0);
    let mut counts: BTreeMap<String, usize> = BTreeMap::new();
    for scan in scans {
        *counts.entry(scan.status.to_lowercase()).or_insert(0) += 1;
    }
    if scans.is_empty() {
        pdf_text(
            content,
            "F1",
            9.0,
            (0.42, 0.45, 0.52),
            x + 8.0,
            y + h / 2.0,
            "No scans yet",
        );
        return;
    }

    let bars = [
        ("completed", (0.17, 0.65, 0.48)),
        ("running", (0.95, 0.62, 0.20)),
        ("pending", (0.55, 0.58, 0.65)),
        ("failed", (0.79, 0.22, 0.24)),
        ("cancelled", (0.45, 0.50, 0.60)),
    ];
    let max_count = bars
        .iter()
        .map(|(k, _)| *counts.get(*k).unwrap_or(&0) as f32)
        .fold(0.0, f32::max)
        .max(1.0);
    let bar_h = (h - 10.0) / bars.len() as f32;
    for (idx, (status, color)) in bars.iter().enumerate() {
        let count = *counts.get(*status).unwrap_or(&0) as f32;
        let by = y + h - (idx as f32 + 1.0) * bar_h;
        let bw = (count / max_count) * (w - 62.0);
        pdf_text(
            content,
            "F1",
            8.4,
            (0.28, 0.32, 0.38),
            x + 2.0,
            by + 3.0,
            &uppercase_first(status),
        );
        content.push_str(&format!(
            "{:.3} {:.3} {:.3} rg {:.2} {:.2} {:.2} {:.2} re f\n",
            color.0,
            color.1,
            color.2,
            x + 56.0,
            by + 1.5,
            bw.max(0.5),
            bar_h - 3.0
        ));
        pdf_text(
            content,
            "F1",
            8.2,
            (0.22, 0.25, 0.30),
            x + 60.0 + bw,
            by + 3.0,
            &format!("{}", count as i32),
        );
    }
}

fn top_finding_titles(
    summary: &FindingsSummary,
    scans: &[SecurityScan],
    asset: &Asset,
) -> Vec<String> {
    let mut lines = Vec::new();
    lines.push(format!(
        "Open findings: {} | Resolved findings: {}",
        summary.by_status("open"),
        summary.resolved_findings
    ));
    lines.push(format!(
        "Severity mix -> C:{} H:{} M:{} L:{} I:{}",
        summary.by_severity("critical"),
        summary.by_severity("high"),
        summary.by_severity("medium"),
        summary.by_severity("low"),
        summary.by_severity("info"),
    ));
    lines.push(format!(
        "Discovery status: {} | Last seen: {}",
        uppercase_first(&asset.status),
        format_datetime(asset.last_seen_at.as_ref())
    ));
    if let Some(last_scan) = scans.first() {
        lines.push(format!(
            "Last scan: {} ({})",
            last_scan.scan_type,
            uppercase_first(&last_scan.status)
        ));
    }
    lines
}

fn risk_level_color(level: Option<&str>) -> (f32, f32, f32) {
    match level.unwrap_or("unknown").to_lowercase().as_str() {
        "critical" => (0.75, 0.18, 0.20),
        "high" => (0.86, 0.38, 0.12),
        "medium" => (0.92, 0.66, 0.14),
        "low" => (0.18, 0.58, 0.80),
        _ => (0.36, 0.44, 0.56),
    }
}

fn severity_theme_color(severity: &str) -> (f32, f32, f32) {
    match severity.to_lowercase().as_str() {
        "critical" => (0.74, 0.10, 0.17),
        "high" => (0.82, 0.30, 0.11),
        "medium" => (0.85, 0.57, 0.08),
        "low" => (0.17, 0.52, 0.80),
        _ => (0.35, 0.40, 0.50),
    }
}

fn pdf_text(
    content: &mut String,
    font: &str,
    size: f32,
    color: (f32, f32, f32),
    x: f32,
    y: f32,
    text: &str,
) {
    content.push_str(&format!(
        "BT /{} {:.2} Tf {:.3} {:.3} {:.3} rg {:.2} {:.2} Td ({}) Tj ET\n",
        font,
        size,
        color.0,
        color.1,
        color.2,
        x,
        y,
        pdf_escape(text)
    ));
}

fn build_pdf_document(page_streams: Vec<String>) -> Vec<u8> {
    let page_count = page_streams.len().max(1);
    let font_regular_id = 3 + page_count * 2;
    let font_bold_id = font_regular_id + 1;
    let total_objects = font_bold_id;

    let mut objects = Vec::<Vec<u8>>::new();

    objects.push(b"<< /Type /Catalog /Pages 2 0 R >>".to_vec());

    let mut kids = String::new();
    for page_idx in 0..page_count {
        let page_obj_id = 3 + page_idx * 2;
        kids.push_str(&format!("{} 0 R ", page_obj_id));
    }
    objects.push(
        format!(
            "<< /Type /Pages /Kids [{}] /Count {} >>",
            kids.trim_end(),
            page_count
        )
        .into_bytes(),
    );

    for (idx, stream) in page_streams.iter().enumerate() {
        let content_obj_id = 4 + idx * 2;
        objects.push(
            format!(
                "<< /Type /Page /Parent 2 0 R /MediaBox [0 0 595 842] /Resources << /Font << /F1 {} 0 R /F2 {} 0 R >> >> /Contents {} 0 R >>",
                font_regular_id, font_bold_id, content_obj_id
            )
            .into_bytes(),
        );

        let stream_bytes = stream.as_bytes();
        let mut content_obj =
            format!("<< /Length {} >>\nstream\n", stream_bytes.len()).into_bytes();
        content_obj.extend_from_slice(stream_bytes);
        content_obj.extend_from_slice(b"\nendstream");
        objects.push(content_obj);
    }

    objects.push(b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>".to_vec());
    objects.push(b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica-Bold >>".to_vec());

    let mut pdf = Vec::<u8>::new();
    pdf.extend_from_slice(b"%PDF-1.4\n%\xE2\xE3\xCF\xD3\n");

    let mut offsets = vec![0usize; total_objects + 1];
    for object_id in 1..=total_objects {
        offsets[object_id] = pdf.len();
        pdf.extend_from_slice(format!("{} 0 obj\n", object_id).as_bytes());
        pdf.extend_from_slice(&objects[object_id - 1]);
        pdf.extend_from_slice(b"\nendobj\n");
    }

    let xref_start = pdf.len();
    pdf.extend_from_slice(format!("xref\n0 {}\n", total_objects + 1).as_bytes());
    pdf.extend_from_slice(b"0000000000 65535 f \n");
    for offset in offsets.iter().skip(1) {
        pdf.extend_from_slice(format!("{:010} 00000 n \n", offset).as_bytes());
    }
    pdf.extend_from_slice(
        format!(
            "trailer\n<< /Size {} /Root 1 0 R >>\nstartxref\n{}\n%%EOF\n",
            total_objects + 1,
            xref_start
        )
        .as_bytes(),
    );

    pdf
}

#[derive(Default)]
struct FindingsSummary {
    severity_counts: BTreeMap<String, usize>,
    status_counts: BTreeMap<String, usize>,
    active_findings: usize,
    resolved_findings: usize,
}

impl FindingsSummary {
    fn by_severity(&self, level: &str) -> usize {
        *self.severity_counts.get(level).unwrap_or(&0)
    }

    fn by_status(&self, status: &str) -> usize {
        *self.status_counts.get(status).unwrap_or(&0)
    }
}

fn summarize_findings(findings: &[SecurityFinding]) -> FindingsSummary {
    let mut summary = FindingsSummary::default();
    for finding in findings {
        let severity = finding.severity.to_lowercase();
        let status = finding.status.to_lowercase();
        *summary.severity_counts.entry(severity).or_insert(0) += 1;
        *summary.status_counts.entry(status.clone()).or_insert(0) += 1;

        if status == "resolved" || status == "false_positive" {
            summary.resolved_findings += 1;
        } else {
            summary.active_findings += 1;
        }
    }
    summary
}

fn severity_rank(severity: &str) -> i32 {
    match severity.to_lowercase().as_str() {
        "critical" => 5,
        "high" => 4,
        "medium" => 3,
        "low" => 2,
        _ => 1,
    }
}

fn format_datetime(value: Option<&DateTime<Utc>>) -> String {
    value
        .map(|dt| dt.format("%Y-%m-%d %H:%M UTC").to_string())
        .unwrap_or_else(|| "n/a".to_string())
}

fn truncate_text(value: &str, max_chars: usize) -> String {
    if value.chars().count() <= max_chars {
        value.to_string()
    } else {
        let truncated = value.chars().take(max_chars).collect::<String>();
        format!("{}...", truncated)
    }
}

fn summarize_json_value(value: &Value, max_chars: usize) -> String {
    let compact = if let Some(s) = value.as_str() {
        s.to_string()
    } else {
        serde_json::to_string(value).unwrap_or_else(|_| "<unavailable>".to_string())
    };
    truncate_text(&compact, max_chars)
}

fn uppercase_first(value: &str) -> String {
    let mut chars = value.chars();
    if let Some(first) = chars.next() {
        format!("{}{}", first.to_ascii_uppercase(), chars.as_str())
    } else {
        String::new()
    }
}

fn parse_sources(sources: &Value) -> Vec<String> {
    sources
        .as_array()
        .map(|arr| {
            arr.iter()
                .filter_map(|entry| entry.as_str().map(|s| s.to_string()))
                .collect::<Vec<_>>()
        })
        .unwrap_or_default()
}

fn pdf_escape(value: &str) -> String {
    let mut escaped = String::with_capacity(value.len());
    for ch in value.chars() {
        match ch {
            '\\' => escaped.push_str("\\\\"),
            '(' => escaped.push_str("\\("),
            ')' => escaped.push_str("\\)"),
            '\n' | '\r' | '\t' => escaped.push(' '),
            c if c.is_ascii_graphic() || c == ' ' => escaped.push(c),
            _ => escaped.push('?'),
        }
    }
    escaped
}

fn sanitize_filename_component(value: &str) -> String {
    let normalized = value
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.' {
                c
            } else {
                '_'
            }
        })
        .collect::<String>();
    let trimmed = normalized.trim_matches('_');
    if trimmed.is_empty() {
        "asset".to_string()
    } else {
        trimmed.chars().take(60).collect()
    }
}
