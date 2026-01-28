//! Tag Service
//!
//! Handles tag management and auto-tagging of assets.
//! Auto-tagging supports:
//! - Regex patterns for string-based assets (domains, certificates, ASNs, organizations)
//! - IP range (CIDR) matching for IP assets

use ipnet::IpNet;
use regex::Regex;
use std::net::IpAddr;
use std::sync::Arc;
use uuid::Uuid;

use crate::{
    error::ApiError,
    models::{
        AssetTag, AssetTagCreate, AssetTagDetail, AssetType, AutoTagResult, Tag, TagCreate,
        TagListResponse, TagUpdate,
    },
    repositories::{AssetRepository, TagRepository},
};

pub struct TagService {
    tag_repo: Arc<dyn TagRepository + Send + Sync>,
    asset_repo: Arc<dyn AssetRepository + Send + Sync>,
}

impl TagService {
    pub fn new(
        tag_repo: Arc<dyn TagRepository + Send + Sync>,
        asset_repo: Arc<dyn AssetRepository + Send + Sync>,
    ) -> Self {
        Self {
            tag_repo,
            asset_repo,
        }
    }

    // ========================================================================
    // TAG CRUD OPERATIONS
    // ========================================================================

    pub async fn create_tag(
        &self,
        company_id: Uuid,
        tag_create: TagCreate,
    ) -> Result<Tag, ApiError> {
        // Validate tag name
        if tag_create.name.trim().is_empty() {
            return Err(ApiError::Validation("Tag name cannot be empty".to_string()));
        }

        if tag_create.name.len() > 100 {
            return Err(ApiError::Validation(
                "Tag name cannot exceed 100 characters".to_string(),
            ));
        }

        // Validate importance
        if tag_create.importance < 1 || tag_create.importance > 5 {
            return Err(ApiError::Validation(
                "Importance must be between 1 and 5".to_string(),
            ));
        }

        // Check for duplicate name
        if let Some(_) = self
            .tag_repo
            .get_by_name(company_id, &tag_create.name)
            .await?
        {
            return Err(ApiError::Validation(format!(
                "Tag with name '{}' already exists",
                tag_create.name
            )));
        }

        // Validate rule if provided
        if let (Some(rule_type), Some(rule_value)) =
            (&tag_create.rule_type, &tag_create.rule_value)
        {
            self.validate_rule(rule_type, rule_value)?;
        }

        self.tag_repo.create(company_id, &tag_create).await
    }

    pub async fn get_tag(&self, company_id: Uuid, id: &Uuid) -> Result<Option<Tag>, ApiError> {
        self.tag_repo.get_by_id(company_id, id).await
    }

    pub async fn list_tags(
        &self,
        company_id: Uuid,
        limit: i64,
        offset: i64,
    ) -> Result<TagListResponse, ApiError> {
        let tags = self.tag_repo.list(company_id, limit, offset).await?;
        let total_count = self.tag_repo.count(company_id).await?;

        Ok(TagListResponse {
            tags,
            total_count,
            limit,
            offset,
        })
    }

    pub async fn update_tag(
        &self,
        company_id: Uuid,
        id: &Uuid,
        update: TagUpdate,
    ) -> Result<Tag, ApiError> {
        // Validate importance if provided
        if let Some(importance) = update.importance {
            if importance < 1 || importance > 5 {
                return Err(ApiError::Validation(
                    "Importance must be between 1 and 5".to_string(),
                ));
            }
        }

        // Validate name if provided
        if let Some(ref name) = update.name {
            if name.trim().is_empty() {
                return Err(ApiError::Validation("Tag name cannot be empty".to_string()));
            }
            if name.len() > 100 {
                return Err(ApiError::Validation(
                    "Tag name cannot exceed 100 characters".to_string(),
                ));
            }

            // Check for duplicate name (excluding current tag)
            if let Some(existing) = self.tag_repo.get_by_name(company_id, name).await? {
                if existing.id != *id {
                    return Err(ApiError::Validation(format!(
                        "Tag with name '{}' already exists",
                        name
                    )));
                }
            }
        }

        // Validate rule if provided (and not clearing)
        if !update.clear_rule {
            if let (Some(rule_type), Some(rule_value)) = (&update.rule_type, &update.rule_value) {
                self.validate_rule(rule_type, rule_value)?;
            }
        }

        self.tag_repo.update(company_id, id, &update).await
    }

    pub async fn delete_tag(&self, company_id: Uuid, id: &Uuid) -> Result<(), ApiError> {
        // Check if tag exists
        if self.tag_repo.get_by_id(company_id, id).await?.is_none() {
            return Err(ApiError::NotFound(format!("Tag {} not found", id)));
        }

        self.tag_repo.delete(company_id, id).await
    }

    // ========================================================================
    // ASSET TAGGING OPERATIONS
    // ========================================================================

    pub async fn tag_asset(
        &self,
        company_id: Uuid,
        asset_id: &Uuid,
        tag_id: &Uuid,
    ) -> Result<AssetTag, ApiError> {
        // Verify asset exists
        if self
            .asset_repo
            .get_by_id(company_id, asset_id)
            .await?
            .is_none()
        {
            return Err(ApiError::NotFound(format!("Asset {} not found", asset_id)));
        }

        // Verify tag exists
        if self
            .tag_repo
            .get_by_id(company_id, tag_id)
            .await?
            .is_none()
        {
            return Err(ApiError::NotFound(format!("Tag {} not found", tag_id)));
        }

        let tag_create = AssetTagCreate {
            tag_id: *tag_id,
            applied_by: "manual".to_string(),
            matched_rule: None,
        };

        self.tag_repo
            .tag_asset(company_id, asset_id, &tag_create)
            .await
    }

    pub async fn untag_asset(
        &self,
        company_id: Uuid,
        asset_id: &Uuid,
        tag_id: &Uuid,
    ) -> Result<(), ApiError> {
        if self
            .asset_repo
            .get_by_id(company_id, asset_id)
            .await?
            .is_none()
        {
            return Err(ApiError::NotFound(format!("Asset {} not found", asset_id)));
        }

        self.tag_repo
            .untag_asset(company_id, asset_id, tag_id)
            .await
    }

    pub async fn get_asset_tags(
        &self,
        company_id: Uuid,
        asset_id: &Uuid,
    ) -> Result<Vec<AssetTagDetail>, ApiError> {
        if self
            .asset_repo
            .get_by_id(company_id, asset_id)
            .await?
            .is_none()
        {
            return Err(ApiError::NotFound(format!("Asset {} not found", asset_id)));
        }

        self.tag_repo.get_asset_tags(company_id, asset_id).await
    }

    // ========================================================================
    // AUTO-TAGGING LOGIC
    // ========================================================================

    /// Run auto-tagging for a specific tag on all applicable assets
    pub async fn run_auto_tag_for_tag(
        &self,
        company_id: Uuid,
        tag_id: &Uuid,
    ) -> Result<AutoTagResult, ApiError> {
        let tag = self
            .tag_repo
            .get_by_id(company_id, tag_id)
            .await?
            .ok_or_else(|| ApiError::NotFound(format!("Tag {} not found", tag_id)))?;

        let (rule_type, rule_value) = match (&tag.rule_type, &tag.rule_value) {
            (Some(rt), Some(rv)) => (rt.clone(), rv.clone()),
            _ => {
                return Err(ApiError::Validation(
                    "Tag does not have an auto-tagging rule configured".to_string(),
                ))
            }
        };

        self.apply_tag_rule(company_id, &tag.id, &rule_type, &rule_value)
            .await
    }

    /// Run all auto-tagging rules against all assets
    pub async fn run_auto_tag_all(&self, company_id: Uuid) -> Result<AutoTagResult, ApiError> {
        let tags_with_rules = self.tag_repo.list_with_rules(company_id).await?;

        let mut total_tags_applied: i64 = 0;
        let mut total_assets_tagged: i64 = 0;
        let mut errors: Vec<String> = Vec::new();

        for tag in tags_with_rules {
            if let (Some(rule_type), Some(rule_value)) = (&tag.rule_type, &tag.rule_value) {
                match self
                    .apply_tag_rule(company_id, &tag.id, rule_type, rule_value)
                    .await
                {
                    Ok(result) => {
                        total_tags_applied += result.tags_applied;
                        total_assets_tagged += result.assets_tagged;
                        errors.extend(result.errors);
                    }
                    Err(e) => {
                        errors.push(format!("Error applying tag '{}': {}", tag.name, e));
                    }
                }
            }
        }

        Ok(AutoTagResult {
            tags_applied: total_tags_applied,
            assets_tagged: total_assets_tagged,
            errors,
        })
    }

    /// Apply a specific tag rule to matching assets
    async fn apply_tag_rule(
        &self,
        company_id: Uuid,
        tag_id: &Uuid,
        rule_type: &str,
        rule_value: &str,
    ) -> Result<AutoTagResult, ApiError> {
        let mut matching_asset_ids: Vec<Uuid> = Vec::new();
        let mut errors: Vec<String> = Vec::new();

        // Get all assets (paginated for large datasets)
        let mut offset = 0;
        let batch_size = 1000;

        loop {
            let assets = self
                .asset_repo
                .list(company_id, None, Some(batch_size), Some(offset))
                .await?;

            if assets.is_empty() {
                break;
            }

            for asset in &assets {
                let matches = match rule_type {
                    "regex" => self.matches_regex(rule_value, &asset.identifier, &asset.asset_type),
                    "ip_range" => self.matches_ip_range(rule_value, &asset.identifier, &asset.asset_type),
                    _ => {
                        errors.push(format!("Unknown rule type: {}", rule_type));
                        continue;
                    }
                };

                match matches {
                    Ok(true) => {
                        // Check if already tagged
                        if !self
                            .tag_repo
                            .is_asset_tagged(company_id, &asset.id, tag_id)
                            .await?
                        {
                            matching_asset_ids.push(asset.id);
                        }
                    }
                    Ok(false) => {}
                    Err(e) => {
                        errors.push(format!(
                            "Error matching asset {}: {}",
                            asset.identifier, e
                        ));
                    }
                }
            }

            offset += batch_size;
        }

        // Bulk tag matching assets
        let assets_tagged = if !matching_asset_ids.is_empty() {
            self.tag_repo
                .bulk_tag_assets(company_id, &matching_asset_ids, tag_id, rule_value)
                .await?
        } else {
            0
        };

        Ok(AutoTagResult {
            tags_applied: assets_tagged,
            assets_tagged,
            errors,
        })
    }

    /// Apply auto-tagging rules to a single asset (called during discovery)
    pub async fn auto_tag_asset(
        &self,
        company_id: Uuid,
        asset_id: &Uuid,
    ) -> Result<Vec<Tag>, ApiError> {
        let asset = self
            .asset_repo
            .get_by_id(company_id, asset_id)
            .await?
            .ok_or_else(|| ApiError::NotFound(format!("Asset {} not found", asset_id)))?;

        let tags_with_rules = self.tag_repo.list_with_rules(company_id).await?;
        let mut applied_tags: Vec<Tag> = Vec::new();

        for tag in tags_with_rules {
            if let (Some(rule_type), Some(rule_value)) = (&tag.rule_type, &tag.rule_value) {
                let matches = match rule_type.as_str() {
                    "regex" => {
                        self.matches_regex(rule_value, &asset.identifier, &asset.asset_type)
                    }
                    "ip_range" => {
                        self.matches_ip_range(rule_value, &asset.identifier, &asset.asset_type)
                    }
                    _ => continue,
                };

                if matches.unwrap_or(false) {
                    // Check if not already tagged
                    if !self
                        .tag_repo
                        .is_asset_tagged(company_id, asset_id, &tag.id)
                        .await?
                    {
                        let tag_create = AssetTagCreate {
                            tag_id: tag.id,
                            applied_by: "auto_rule".to_string(),
                            matched_rule: Some(rule_value.clone()),
                        };
                        self.tag_repo
                            .tag_asset(company_id, asset_id, &tag_create)
                            .await?;
                        applied_tags.push(tag);
                    }
                }
            }
        }

        Ok(applied_tags)
    }

    // ========================================================================
    // HELPER METHODS
    // ========================================================================

    /// Validate a tagging rule
    fn validate_rule(&self, rule_type: &str, rule_value: &str) -> Result<(), ApiError> {
        match rule_type {
            "regex" => {
                Regex::new(rule_value).map_err(|e| {
                    ApiError::Validation(format!("Invalid regex pattern: {}", e))
                })?;
            }
            "ip_range" => {
                // Support multiple CIDR ranges separated by comma
                for cidr in rule_value.split(',') {
                    let cidr = cidr.trim();
                    if !cidr.is_empty() {
                        cidr.parse::<IpNet>().map_err(|e| {
                            ApiError::Validation(format!("Invalid CIDR notation '{}': {}", cidr, e))
                        })?;
                    }
                }
            }
            _ => {
                return Err(ApiError::Validation(format!(
                    "Invalid rule type: '{}'. Must be 'regex' or 'ip_range'",
                    rule_type
                )));
            }
        }
        Ok(())
    }

    /// Check if an asset identifier matches a regex pattern
    fn matches_regex(
        &self,
        pattern: &str,
        identifier: &str,
        asset_type: &AssetType,
    ) -> Result<bool, ApiError> {
        // Only apply regex to string-based assets
        match asset_type {
            AssetType::Domain | AssetType::Certificate | AssetType::Organization | AssetType::Asn => {
                let regex = Regex::new(pattern)
                    .map_err(|e| ApiError::Validation(format!("Invalid regex: {}", e)))?;
                Ok(regex.is_match(identifier))
            }
            AssetType::Ip | AssetType::Port => {
                // IP and Port assets should use ip_range rule type
                Ok(false)
            }
        }
    }

    /// Check if an IP asset matches a CIDR range
    fn matches_ip_range(
        &self,
        cidr_value: &str,
        identifier: &str,
        asset_type: &AssetType,
    ) -> Result<bool, ApiError> {
        // Only apply IP range to IP assets
        if *asset_type != AssetType::Ip {
            return Ok(false);
        }

        // Parse the IP address
        let ip: IpAddr = identifier
            .parse()
            .map_err(|e| ApiError::Validation(format!("Invalid IP address '{}': {}", identifier, e)))?;

        // Support multiple CIDR ranges separated by comma
        for cidr in cidr_value.split(',') {
            let cidr = cidr.trim();
            if cidr.is_empty() {
                continue;
            }

            let network: IpNet = cidr
                .parse()
                .map_err(|e| ApiError::Validation(format!("Invalid CIDR '{}': {}", cidr, e)))?;

            if network.contains(&ip) {
                return Ok(true);
            }
        }

        Ok(false)
    }
}
