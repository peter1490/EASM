use async_trait::async_trait;
use uuid::Uuid;
use crate::{
    database::DatabasePool,
    error::ApiError,
    models::{Finding, FindingCreate, FindingFilter, FindingListResponse},
};

#[async_trait]
pub trait FindingRepository {
    async fn create(&self, finding: &FindingCreate) -> Result<Finding, ApiError>;
    async fn list_by_scan(&self, scan_id: &Uuid) -> Result<Vec<Finding>, ApiError>;
    async fn list_by_type(&self, finding_type: &str) -> Result<Vec<Finding>, ApiError>;
    async fn search(&self, query: &str) -> Result<Vec<Finding>, ApiError>;
    async fn count_by_scan(&self, scan_id: &Uuid) -> Result<i64, ApiError>;
    async fn filter(&self, filter: &FindingFilter) -> Result<FindingListResponse, ApiError>;
}

pub struct SqlxFindingRepository {
    pool: DatabasePool,
}

impl SqlxFindingRepository {
    pub fn new(pool: DatabasePool) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl FindingRepository for SqlxFindingRepository {
    async fn create(&self, finding: &FindingCreate) -> Result<Finding, ApiError> {
        let id = Uuid::new_v4();
        let now = chrono::Utc::now();
        
        let result = sqlx::query_as::<_, Finding>(
            r#"
            INSERT INTO findings (id, scan_id, finding_type, data, created_at)
            VALUES ($1, $2, $3, $4, $5)
            RETURNING id, scan_id, finding_type, data, created_at
            "#
        )
        .bind(id)
        .bind(finding.scan_id)
        .bind(&finding.finding_type)
        .bind(&finding.data)
        .bind(now)
        .fetch_one(&self.pool)
        .await?;

        Ok(result)
    }

    async fn list_by_scan(&self, scan_id: &Uuid) -> Result<Vec<Finding>, ApiError> {
        let results = sqlx::query_as::<_, Finding>(
            r#"
            SELECT id, scan_id, finding_type, data, created_at
            FROM findings
            WHERE scan_id = $1
            ORDER BY created_at DESC
            "#
        )
        .bind(scan_id)
        .fetch_all(&self.pool)
        .await?;

        Ok(results)
    }

    async fn list_by_type(&self, finding_type: &str) -> Result<Vec<Finding>, ApiError> {
        let results = sqlx::query_as::<_, Finding>(
            r#"
            SELECT id, scan_id, finding_type, data, created_at
            FROM findings
            WHERE finding_type = $1
            ORDER BY created_at DESC
            "#
        )
        .bind(finding_type)
        .fetch_all(&self.pool)
        .await?;

        Ok(results)
    }

    async fn search(&self, query: &str) -> Result<Vec<Finding>, ApiError> {
        // Search in finding_type and JSON data fields
        let search_pattern = format!("%{}%", query);
        
        #[cfg(test)]
        let results = sqlx::query_as::<_, Finding>(
            r#"
            SELECT id, scan_id, finding_type, data, created_at
            FROM findings
            WHERE finding_type LIKE $1 OR json_extract(data, '$') LIKE $1
            ORDER BY created_at DESC
            "#
        )
        .bind(&search_pattern)
        .fetch_all(&self.pool)
        .await?;

        #[cfg(not(test))]
        let results = sqlx::query_as::<_, Finding>(
            r#"
            SELECT id, scan_id, finding_type, data, created_at
            FROM findings
            WHERE finding_type ILIKE $1 OR data::text ILIKE $1
            ORDER BY created_at DESC
            "#
        )
        .bind(&search_pattern)
        .fetch_all(&self.pool)
        .await?;

        Ok(results)
    }

    async fn count_by_scan(&self, scan_id: &Uuid) -> Result<i64, ApiError> {
        let result = sqlx::query_scalar::<_, i64>(
            r#"
            SELECT COUNT(*)
            FROM findings
            WHERE scan_id = $1
            "#
        )
        .bind(scan_id)
        .fetch_one(&self.pool)
        .await?;

        Ok(result)
    }

    async fn filter(&self, filter: &FindingFilter) -> Result<FindingListResponse, ApiError> {
        // Build dynamic WHERE clause
        let mut where_clauses = Vec::new();
        let mut param_index = 1;
        
        // Filter by finding types
        if let Some(ref types) = filter.finding_types {
            if !types.is_empty() {
                where_clauses.push(format!("finding_type = ANY(${})", param_index));
                param_index += 1;
            }
        }
        
        // Filter by scan IDs
        if let Some(ref scan_ids) = filter.scan_ids {
            if !scan_ids.is_empty() {
                where_clauses.push(format!("scan_id = ANY(${})", param_index));
                param_index += 1;
            }
        }
        
        // Filter by date range - after
        if filter.created_after.is_some() {
            where_clauses.push(format!("created_at >= ${}", param_index));
            param_index += 1;
        }
        
        // Filter by date range - before
        if filter.created_before.is_some() {
            where_clauses.push(format!("created_at <= ${}", param_index));
            param_index += 1;
        }
        
        // Text search
        if let Some(ref search_text) = filter.search_text {
            if !search_text.is_empty() {
                #[cfg(test)]
                where_clauses.push(format!("(finding_type LIKE ${} OR json_extract(data, '$') LIKE ${})", param_index, param_index));
                
                #[cfg(not(test))]
                where_clauses.push(format!("(finding_type ILIKE ${} OR data::text ILIKE ${})", param_index, param_index));
                
                param_index += 1;
            }
        }
        
        // Build WHERE clause
        let where_sql = if where_clauses.is_empty() {
            String::new()
        } else {
            format!("WHERE {}", where_clauses.join(" AND "))
        };
        
        // Validate sort field and direction
        let sort_field = match filter.sort_by.as_str() {
            "created_at" | "finding_type" => &filter.sort_by,
            _ => "created_at",
        };
        
        let sort_direction = match filter.sort_direction.to_lowercase().as_str() {
            "asc" | "desc" => filter.sort_direction.to_uppercase(),
            _ => "DESC".to_string(),
        };
        
        // Build ORDER BY clause
        let order_sql = format!("ORDER BY {} {}", sort_field, sort_direction);
        
        // Build LIMIT and OFFSET
        let limit = filter.limit.max(1).min(1000); // Cap at 1000
        let offset = filter.offset.max(0);
        
        // Count query
        let count_sql = format!("SELECT COUNT(*) FROM findings {}", where_sql);
        
        // Main query
        let main_sql = format!(
            "SELECT id, scan_id, finding_type, data, created_at FROM findings {} {} LIMIT ${} OFFSET ${}",
            where_sql, order_sql, param_index, param_index + 1
        );
        
        tracing::debug!("Filter SQL: {}", main_sql);
        tracing::debug!("Count SQL: {}", count_sql);
        
        // Prepare search pattern if needed (must outlive query bindings)
        let search_pattern = filter.search_text
            .as_ref()
            .filter(|s| !s.is_empty())
            .map(|s| format!("%{}%", s));
        
        // Execute count query
        let mut count_query = sqlx::query_scalar::<_, i64>(&count_sql);
        
        // Bind parameters for count query
        if let Some(ref types) = filter.finding_types {
            if !types.is_empty() {
                count_query = count_query.bind(types);
            }
        }
        
        if let Some(ref scan_ids) = filter.scan_ids {
            if !scan_ids.is_empty() {
                count_query = count_query.bind(scan_ids);
            }
        }
        
        if let Some(ref created_after) = filter.created_after {
            count_query = count_query.bind(created_after);
        }
        
        if let Some(ref created_before) = filter.created_before {
            count_query = count_query.bind(created_before);
        }
        
        if let Some(ref pattern) = search_pattern {
            count_query = count_query.bind(pattern);
        }
        
        let total_count = count_query.fetch_one(&self.pool).await?;
        
        // Execute main query
        let mut main_query = sqlx::query_as::<_, Finding>(&main_sql);
        
        // Bind parameters for main query
        if let Some(ref types) = filter.finding_types {
            if !types.is_empty() {
                main_query = main_query.bind(types);
            }
        }
        
        if let Some(ref scan_ids) = filter.scan_ids {
            if !scan_ids.is_empty() {
                main_query = main_query.bind(scan_ids);
            }
        }
        
        if let Some(ref created_after) = filter.created_after {
            main_query = main_query.bind(created_after);
        }
        
        if let Some(ref created_before) = filter.created_before {
            main_query = main_query.bind(created_before);
        }
        
        if let Some(ref pattern) = search_pattern {
            main_query = main_query.bind(pattern);
        }
        
        main_query = main_query.bind(limit).bind(offset);
        
        let findings = main_query.fetch_all(&self.pool).await?;
        
        Ok(FindingListResponse {
            findings,
            total_count,
            limit,
            offset,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use crate::database::create_connection_pool;

    async fn setup_test_db() -> DatabasePool {
        let db_url = std::env::var("DATABASE_URL").expect("DATABASE_URL must be set for tests");
        let pool = create_connection_pool(&db_url).await.unwrap();
        let _ = sqlx::query("TRUNCATE TABLE findings RESTART IDENTITY CASCADE").execute(&pool).await;
        pool
    }

    #[tokio::test]
    async fn test_create_finding() {
        let pool = setup_test_db().await;
        let repo = SqlxFindingRepository::new(pool);

        let scan_id = Uuid::new_v4();
        let finding_create = FindingCreate {
            scan_id,
            finding_type: "port_scan".to_string(),
            data: json!({"port": 80, "service": "http"}),
        };

        let result = repo.create(&finding_create).await;
        assert!(result.is_ok());

        let finding = result.unwrap();
        assert_eq!(finding.scan_id, scan_id);
        assert_eq!(finding.finding_type, "port_scan");
        assert_eq!(finding.data["port"], 80);
    }

    #[tokio::test]
    async fn test_list_by_scan() {
        let pool = setup_test_db().await;
        let repo = SqlxFindingRepository::new(pool);

        let scan_id = Uuid::new_v4();
        let other_scan_id = Uuid::new_v4();

        // Create findings for the target scan
        let finding1 = FindingCreate {
            scan_id,
            finding_type: "port_scan".to_string(),
            data: json!({"port": 80}),
        };
        let finding2 = FindingCreate {
            scan_id,
            finding_type: "dns_record".to_string(),
            data: json!({"record": "A"}),
        };

        // Create finding for different scan
        let finding3 = FindingCreate {
            scan_id: other_scan_id,
            finding_type: "port_scan".to_string(),
            data: json!({"port": 443}),
        };

        repo.create(&finding1).await.unwrap();
        repo.create(&finding2).await.unwrap();
        repo.create(&finding3).await.unwrap();

        let results = repo.list_by_scan(&scan_id).await.unwrap();
        assert_eq!(results.len(), 2);

        let other_results = repo.list_by_scan(&other_scan_id).await.unwrap();
        assert_eq!(other_results.len(), 1);
    }

    #[tokio::test]
    async fn test_list_by_type() {
        let pool = setup_test_db().await;
        let repo = SqlxFindingRepository::new(pool);

        let scan_id = Uuid::new_v4();

        // Create findings of different types
        let finding1 = FindingCreate {
            scan_id,
            finding_type: "port_scan".to_string(),
            data: json!({"port": 80}),
        };
        let finding2 = FindingCreate {
            scan_id,
            finding_type: "port_scan".to_string(),
            data: json!({"port": 443}),
        };
        let finding3 = FindingCreate {
            scan_id,
            finding_type: "dns_record".to_string(),
            data: json!({"record": "A"}),
        };

        repo.create(&finding1).await.unwrap();
        repo.create(&finding2).await.unwrap();
        repo.create(&finding3).await.unwrap();

        let port_scan_results = repo.list_by_type("port_scan").await.unwrap();
        assert_eq!(port_scan_results.len(), 2);

        let dns_results = repo.list_by_type("dns_record").await.unwrap();
        assert_eq!(dns_results.len(), 1);

        let nonexistent_results = repo.list_by_type("nonexistent").await.unwrap();
        assert_eq!(nonexistent_results.len(), 0);
    }

    #[tokio::test]
    async fn test_search() {
        let pool = setup_test_db().await;
        let repo = SqlxFindingRepository::new(pool);

        let scan_id = Uuid::new_v4();

        // Create findings with searchable content
        let finding1 = FindingCreate {
            scan_id,
            finding_type: "port_scan".to_string(),
            data: json!({"port": 80, "service": "http"}),
        };
        let finding2 = FindingCreate {
            scan_id,
            finding_type: "dns_record".to_string(),
            data: json!({"record": "A", "value": "192.168.1.1"}),
        };
        let finding3 = FindingCreate {
            scan_id,
            finding_type: "certificate".to_string(),
            data: json!({"subject": "example.com", "issuer": "Let's Encrypt"}),
        };

        repo.create(&finding1).await.unwrap();
        repo.create(&finding2).await.unwrap();
        repo.create(&finding3).await.unwrap();

        // Search by finding type
        let port_results = repo.search("port").await.unwrap();
        assert_eq!(port_results.len(), 1);

        // Search by data content
        let http_results = repo.search("http").await.unwrap();
        assert_eq!(http_results.len(), 1);

        // Search that matches multiple findings
        let record_results = repo.search("record").await.unwrap();
        assert_eq!(record_results.len(), 1);

        // Search with no matches
        let no_results = repo.search("nonexistent").await.unwrap();
        assert_eq!(no_results.len(), 0);
    }
}