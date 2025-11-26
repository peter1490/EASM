use crate::error::ApiError;
use sqlx::{Pool, Postgres};
use std::sync::OnceLock;

pub type DatabasePool = Pool<Postgres>;

pub async fn create_connection_pool(database_url: &str) -> Result<DatabasePool, ApiError> {
    let pool = sqlx::PgPool::connect(database_url).await?;

    // Run database migrations
    run_migrations(&pool).await?;

    Ok(pool)
}

pub async fn health_check(pool: &DatabasePool) -> Result<(), ApiError> {
    sqlx::query("SELECT 1").execute(pool).await?;
    Ok(())
}

/// Run database migrations
static MIGRATIONS_RAN: OnceLock<()> = OnceLock::new();

pub async fn run_migrations(pool: &DatabasePool) -> Result<(), ApiError> {
    if MIGRATIONS_RAN.get().is_some() {
        return Ok(());
    }
    tracing::info!("Running database migrations...");

    match sqlx::migrate!("./migrations").run(pool).await {
        Ok(()) => {
            tracing::info!("Database migrations completed successfully");
            let _ = MIGRATIONS_RAN.set(());
            Ok(())
        }
        Err(e) => {
            tracing::error!("Database migration failed: {}", e);
            Err(ApiError::Database(e.into()))
        }
    }
}

/// Alias for create_connection_pool for compatibility
pub async fn create_database_pool(database_url: &str) -> Result<DatabasePool, ApiError> {
    create_connection_pool(database_url).await
}

// Note: tests now require a PostgreSQL instance available via DATABASE_URL
