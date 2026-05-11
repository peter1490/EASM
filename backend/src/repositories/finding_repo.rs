use crate::{
    database::DatabasePool,
    error::ApiError,
    models::{Finding, FindingCreate, FindingFilter, FindingListResponse},
};
use async_trait::async_trait;
use uuid::Uuid;

#[async_trait]
pub trait FindingRepository {
    async fn create(&self, finding: &FindingCreate, company_id: Uuid) -> Result<Finding, ApiError>;
    async fn list_by_scan(
        &self,
        scan_id: &Uuid,
        company_id: Uuid,
    ) -> Result<Vec<Finding>, ApiError>;
    async fn list_by_type(
        &self,
        finding_type: &str,
        company_id: Uuid,
    ) -> Result<Vec<Finding>, ApiError>;
    async fn list_by_asset(
        &self,
        asset_identifier: &str,
        company_id: Uuid,
    ) -> Result<Vec<Finding>, ApiError>;
    async fn search(&self, query: &str, company_id: Uuid) -> Result<Vec<Finding>, ApiError>;
    async fn count_by_scan(&self, scan_id: &Uuid, company_id: Uuid) -> Result<i64, ApiError>;
    async fn filter(
        &self,
        filter: &FindingFilter,
        company_id: Uuid,
    ) -> Result<FindingListResponse, ApiError>;
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
    async fn create(&self, finding: &FindingCreate, company_id: Uuid) -> Result<Finding, ApiError> {
        let id = Uuid::new_v4();
        let now = chrono::Utc::now();

        let result = sqlx::query_as::<_, Finding>(
            r#"
            INSERT INTO findings (id, scan_id, finding_type, data, created_at, company_id)
            VALUES ($1, $2, $3, $4, $5, $6)
            RETURNING id, scan_id, finding_type, data, created_at, company_id
            "#,
        )
        .bind(id)
        .bind(finding.scan_id)
        .bind(&finding.finding_type)
        .bind(&finding.data)
        .bind(now)
        .bind(company_id)
        .fetch_one(&self.pool)
        .await?;

        Ok(result)
    }

    async fn list_by_scan(
        &self,
        scan_id: &Uuid,
        company_id: Uuid,
    ) -> Result<Vec<Finding>, ApiError> {
        let results = sqlx::query_as::<_, Finding>(
            r#"
            SELECT id, scan_id, finding_type, data, created_at, company_id
            FROM findings
            WHERE scan_id = $1 AND company_id = $2
            ORDER BY created_at DESC
            "#,
        )
        .bind(scan_id)
        .bind(company_id)
        .fetch_all(&self.pool)
        .await?;

        Ok(results)
    }

    async fn list_by_type(
        &self,
        finding_type: &str,
        company_id: Uuid,
    ) -> Result<Vec<Finding>, ApiError> {
        let results = sqlx::query_as::<_, Finding>(
            r#"
            SELECT id, scan_id, finding_type, data, created_at, company_id
            FROM findings
            WHERE finding_type = $1 AND company_id = $2
            ORDER BY created_at DESC
            "#,
        )
        .bind(finding_type)
        .bind(company_id)
        .fetch_all(&self.pool)
        .await?;

        Ok(results)
    }

    async fn list_by_asset(
        &self,
        asset_identifier: &str,
        company_id: Uuid,
    ) -> Result<Vec<Finding>, ApiError> {
        let results = sqlx::query_as::<_, Finding>(
            r#"
            SELECT f.id, f.scan_id, f.finding_type, f.data, f.created_at, f.company_id
            FROM findings f
            JOIN scans s ON f.scan_id = s.id
            WHERE LOWER(TRIM(s.target)) = LOWER(TRIM($1)) AND f.company_id = $2
            ORDER BY f.created_at DESC
            "#,
        )
        .bind(asset_identifier)
        .bind(company_id)
        .fetch_all(&self.pool)
        .await?;

        Ok(results)
    }

    async fn search(&self, query: &str, company_id: Uuid) -> Result<Vec<Finding>, ApiError> {
        let search_pattern = format!("%{}%", query);

        #[cfg(test)]
        let results = sqlx::query_as::<_, Finding>(
            r#"
            SELECT id, scan_id, finding_type, data, created_at, company_id
            FROM findings
            WHERE (finding_type LIKE $1 OR json_extract(data, '$') LIKE $1) AND company_id = $2
            ORDER BY created_at DESC
            "#,
        )
        .bind(&search_pattern)
        .bind(company_id)
        .fetch_all(&self.pool)
        .await?;

        #[cfg(not(test))]
        let results = sqlx::query_as::<_, Finding>(
            r#"
            SELECT id, scan_id, finding_type, data, created_at, company_id
            FROM findings
            WHERE (finding_type ILIKE $1 OR data::text ILIKE $1) AND company_id = $2
            ORDER BY created_at DESC
            "#,
        )
        .bind(&search_pattern)
        .bind(company_id)
        .fetch_all(&self.pool)
        .await?;

        Ok(results)
    }

    async fn count_by_scan(&self, scan_id: &Uuid, company_id: Uuid) -> Result<i64, ApiError> {
        let result = sqlx::query_scalar::<_, i64>(
            r#"
            SELECT COUNT(*)
            FROM findings
            WHERE scan_id = $1 AND company_id = $2
            "#,
        )
        .bind(scan_id)
        .bind(company_id)
        .fetch_one(&self.pool)
        .await?;

        Ok(result)
    }

    async fn filter(
        &self,
        filter: &FindingFilter,
        company_id: Uuid,
    ) -> Result<FindingListResponse, ApiError> {
        let mut where_clauses = Vec::new();
        let mut param_index = 1;

        // Add company_id filter
        where_clauses.push(format!("company_id = ${}", param_index));
        param_index += 1;

        if let Some(ref types) = filter.finding_types {
            if !types.is_empty() {
                where_clauses.push(format!("finding_type = ANY(${})", param_index));
                param_index += 1;
            }
        }

        if let Some(ref scan_ids) = filter.scan_ids {
            if !scan_ids.is_empty() {
                where_clauses.push(format!("scan_id = ANY(${})", param_index));
                param_index += 1;
            }
        }

        if filter.created_after.is_some() {
            where_clauses.push(format!("created_at >= ${}", param_index));
            param_index += 1;
        }

        if filter.created_before.is_some() {
            where_clauses.push(format!("created_at <= ${}", param_index));
            param_index += 1;
        }

        if let Some(ref search_text) = filter.search_text {
            if !search_text.is_empty() {
                #[cfg(test)]
                where_clauses.push(format!(
                    "(finding_type LIKE ${} OR json_extract(data, '$') LIKE ${})",
                    param_index, param_index
                ));

                #[cfg(not(test))]
                where_clauses.push(format!(
                    "(finding_type ILIKE ${} OR data::text ILIKE ${})",
                    param_index, param_index
                ));

                param_index += 1;
            }
        }

        let where_sql = if where_clauses.is_empty() {
            String::new()
        } else {
            format!("WHERE {}", where_clauses.join(" AND "))
        };

        let sort_field = match filter.sort_by.as_str() {
            "created_at" | "finding_type" => &filter.sort_by,
            _ => "created_at",
        };

        let sort_direction = match filter.sort_direction.to_lowercase().as_str() {
            "asc" | "desc" => filter.sort_direction.to_uppercase(),
            _ => "DESC".to_string(),
        };

        let order_sql = format!("ORDER BY {} {}", sort_field, sort_direction);

        let limit = filter.limit.max(1).min(1000);
        let offset = filter.offset.max(0);

        let count_sql = format!("SELECT COUNT(*) FROM findings {}", where_sql);

        let main_sql = format!(
            "SELECT id, scan_id, finding_type, data, created_at, company_id FROM findings {} {} LIMIT ${} OFFSET ${}",
            where_sql, order_sql, param_index, param_index + 1
        );

        let search_pattern = filter
            .search_text
            .as_ref()
            .filter(|s| !s.is_empty())
            .map(|s| format!("%{}%", s));

        let mut count_query = sqlx::query_scalar::<_, i64>(&count_sql);

        // Bind company_id
        count_query = count_query.bind(company_id);

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

        let mut main_query = sqlx::query_as::<_, Finding>(&main_sql);

        // Bind company_id
        main_query = main_query.bind(company_id);

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
    use crate::database::create_connection_pool;
    use serde_json::json;

    async fn setup_test_db() -> DatabasePool {
        let db_url = std::env::var("DATABASE_URL").expect("DATABASE_URL must be set for tests");
        let pool = create_connection_pool(&db_url).await.unwrap();
        let _ = sqlx::query("TRUNCATE TABLE findings RESTART IDENTITY CASCADE")
            .execute(&pool)
            .await;
        pool
    }

    async fn insert_scan(pool: &DatabasePool, scan_id: Uuid, company_id: Uuid) {
        let _ = sqlx::query(
            r#"
            INSERT INTO scans (id, target, status, created_at, updated_at, company_id)
            VALUES ($1, $2, 'queued', NOW(), NOW(), $3)
            "#,
        )
        .bind(scan_id)
        .bind("test-scan")
        .bind(company_id)
        .execute(pool)
        .await;
    }

    #[tokio::test]
    async fn test_create_finding() {
        let pool = setup_test_db().await;
        let repo = SqlxFindingRepository::new(pool.clone());

        let scan_id = Uuid::new_v4();
        let company_id = Uuid::nil();
        insert_scan(&pool, scan_id, company_id).await;

        let finding_create = FindingCreate {
            scan_id,
            finding_type: "port_scan".to_string(),
            data: json!({"port": 80, "service": "http"}),
        };

        let result = repo.create(&finding_create, company_id).await;
        assert!(result.is_ok());

        let finding = result.unwrap();
        assert_eq!(finding.scan_id, scan_id);
        assert_eq!(finding.finding_type, "port_scan");
        assert_eq!(finding.data["port"], 80);
    }

    #[tokio::test]
    async fn test_list_by_scan() {
        let pool = setup_test_db().await;
        let repo = SqlxFindingRepository::new(pool.clone());

        let scan_id = Uuid::new_v4();
        let other_scan_id = Uuid::new_v4();
        let company_id = Uuid::nil();
        insert_scan(&pool, scan_id, company_id).await;
        insert_scan(&pool, other_scan_id, company_id).await;

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
        let finding3 = FindingCreate {
            scan_id: other_scan_id,
            finding_type: "port_scan".to_string(),
            data: json!({"port": 443}),
        };

        repo.create(&finding1, company_id).await.unwrap();
        repo.create(&finding2, company_id).await.unwrap();
        repo.create(&finding3, company_id).await.unwrap();

        let results = repo.list_by_scan(&scan_id, company_id).await.unwrap();
        assert_eq!(results.len(), 2);

        let other_results = repo
            .list_by_scan(&other_scan_id, company_id)
            .await
            .unwrap();
        assert_eq!(other_results.len(), 1);
    }

    #[tokio::test]
    async fn test_list_by_type() {
        let pool = setup_test_db().await;
        let repo = SqlxFindingRepository::new(pool.clone());

        let scan_id = Uuid::new_v4();
        let company_id = Uuid::nil();
        insert_scan(&pool, scan_id, company_id).await;

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

        repo.create(&finding1, company_id).await.unwrap();
        repo.create(&finding2, company_id).await.unwrap();
        repo.create(&finding3, company_id).await.unwrap();

        let port_scan_results = repo.list_by_type("port_scan", company_id).await.unwrap();
        assert_eq!(port_scan_results.len(), 2);

        let dns_results = repo.list_by_type("dns_record", company_id).await.unwrap();
        assert_eq!(dns_results.len(), 1);

        let nonexistent_results = repo.list_by_type("nonexistent", company_id).await.unwrap();
        assert_eq!(nonexistent_results.len(), 0);
    }

    #[tokio::test]
    async fn test_count_by_scan() {
        let pool = setup_test_db().await;
        let repo = SqlxFindingRepository::new(pool.clone());

        let scan_id = Uuid::new_v4();
        let other_scan_id = Uuid::new_v4();
        let company_id = Uuid::nil();
        insert_scan(&pool, scan_id, company_id).await;
        insert_scan(&pool, other_scan_id, company_id).await;

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
            scan_id: other_scan_id,
            finding_type: "port_scan".to_string(),
            data: json!({"port": 22}),
        };

        repo.create(&finding1, company_id).await.unwrap();
        repo.create(&finding2, company_id).await.unwrap();
        repo.create(&finding3, company_id).await.unwrap();

        let count = repo.count_by_scan(&scan_id, company_id).await.unwrap();
        assert_eq!(count, 2);

        let other_count = repo
            .count_by_scan(&other_scan_id, company_id)
            .await
            .unwrap();
        assert_eq!(other_count, 1);
    }
}
