//! Store layer for `uptime_checks` (per-check uptime/SSL samples). Runtime-checked sqlx only.
//!
//! Schema: migrations/0001_init.sql §4. PK INTEGER AUTOINCREMENT. Append-only time series;
//! `is_up` is INTEGER 0/1. Booleans (`ssl_cert_valid`) are nullable INTEGER. Pruned by retention.

use super::super::error::LocalResult;
use sqlx::sqlite::SqlitePool;
use sqlx::Row as _;

/// A row of the `uptime_checks` table.
#[derive(Debug, Clone, sqlx::FromRow, serde::Serialize, serde::Deserialize)]
pub struct UptimeCheck {
    pub id: i64,
    pub target_id: i64,
    pub checked_at: String,
    pub is_up: i64,
    #[serde(default)]
    pub status_code: Option<i64>,
    #[serde(default)]
    pub response_time_ms: Option<i64>,
    #[serde(default)]
    pub error_message: Option<String>,
    #[serde(default)]
    pub ssl_cert_valid: Option<i64>,
    #[serde(default)]
    pub ssl_cert_expires_at: Option<String>,
    #[serde(default)]
    pub ssl_cert_days_until_expiry: Option<i64>,
    #[serde(default)]
    pub ssl_cert_issuer: Option<String>,
    #[serde(default)]
    pub ssl_error: Option<String>,
}

/// Fields recorded on a single uptime sample. `target_id` and `is_up` are required;
/// `checked_at` defaults to now via the schema when omitted.
#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct NewUptimeCheck {
    pub target_id: i64,
    pub is_up: i64,
    /// RFC3339; when `None` the schema default (now) is used.
    #[serde(default)]
    pub checked_at: Option<String>,
    #[serde(default)]
    pub status_code: Option<i64>,
    #[serde(default)]
    pub response_time_ms: Option<i64>,
    #[serde(default)]
    pub error_message: Option<String>,
    #[serde(default)]
    pub ssl_cert_valid: Option<i64>,
    #[serde(default)]
    pub ssl_cert_expires_at: Option<String>,
    #[serde(default)]
    pub ssl_cert_days_until_expiry: Option<i64>,
    #[serde(default)]
    pub ssl_cert_issuer: Option<String>,
    #[serde(default)]
    pub ssl_error: Option<String>,
}

const SELECT_COLS: &str = "id, target_id, checked_at, is_up, status_code, response_time_ms, \
    error_message, ssl_cert_valid, ssl_cert_expires_at, ssl_cert_days_until_expiry, \
    ssl_cert_issuer, ssl_error";

/// Insert one uptime sample; returns the new row id. When `checked_at` is `None` the schema
/// default (now) applies.
pub async fn insert(pool: &SqlitePool, c: &NewUptimeCheck) -> LocalResult<i64> {
    let id = sqlx::query(
        "INSERT INTO uptime_checks \
         (target_id, checked_at, is_up, status_code, response_time_ms, error_message, \
          ssl_cert_valid, ssl_cert_expires_at, ssl_cert_days_until_expiry, ssl_cert_issuer, ssl_error) \
         VALUES (?, COALESCE(?, strftime('%Y-%m-%dT%H:%M:%fZ','now')), ?, ?, ?, ?, ?, ?, ?, ?, ?)",
    )
    .bind(c.target_id)
    .bind(&c.checked_at)
    .bind(c.is_up)
    .bind(c.status_code)
    .bind(c.response_time_ms)
    .bind(&c.error_message)
    .bind(c.ssl_cert_valid)
    .bind(&c.ssl_cert_expires_at)
    .bind(c.ssl_cert_days_until_expiry)
    .bind(&c.ssl_cert_issuer)
    .bind(&c.ssl_error)
    .execute(pool)
    .await?
    .last_insert_rowid();
    Ok(id)
}

/// Fetch one uptime check by id, or `None` if absent.
pub async fn get_by_id(pool: &SqlitePool, id: i64) -> LocalResult<Option<UptimeCheck>> {
    let row = sqlx::query_as::<_, UptimeCheck>(&format!(
        "SELECT {SELECT_COLS} FROM uptime_checks WHERE id = ?"
    ))
    .bind(id)
    .fetch_optional(pool)
    .await?;
    Ok(row)
}

/// List uptime samples for a target, newest-first, capped at `limit`.
pub async fn list_by_target(pool: &SqlitePool, target_id: i64, limit: i64) -> LocalResult<Vec<UptimeCheck>> {
    let rows = sqlx::query_as::<_, UptimeCheck>(&format!(
        "SELECT {SELECT_COLS} FROM uptime_checks WHERE target_id = ? \
         ORDER BY checked_at DESC, id DESC LIMIT ?"
    ))
    .bind(target_id)
    .bind(limit)
    .fetch_all(pool)
    .await?;
    Ok(rows)
}

/// The most recent uptime sample for a target, or `None`.
pub async fn latest_for_target(pool: &SqlitePool, target_id: i64) -> LocalResult<Option<UptimeCheck>> {
    let row = sqlx::query_as::<_, UptimeCheck>(&format!(
        "SELECT {SELECT_COLS} FROM uptime_checks WHERE target_id = ? \
         ORDER BY checked_at DESC, id DESC LIMIT 1"
    ))
    .bind(target_id)
    .fetch_optional(pool)
    .await?;
    Ok(row)
}

/// Uptime ratio (fraction up, 0.0..=1.0) for a target since `since_rfc3339`. Returns `None`
/// when there are no samples in the window.
pub async fn uptime_ratio_since(
    pool: &SqlitePool,
    target_id: i64,
    since_rfc3339: &str,
) -> LocalResult<Option<f64>> {
    let row = sqlx::query(
        "SELECT count(*) AS total, COALESCE(sum(is_up), 0) AS up \
         FROM uptime_checks WHERE target_id = ? AND checked_at >= ?",
    )
    .bind(target_id)
    .bind(since_rfc3339)
    .fetch_one(pool)
    .await?;
    let total: i64 = row.try_get("total")?;
    if total == 0 {
        return Ok(None);
    }
    let up: i64 = row.try_get("up")?;
    Ok(Some(up as f64 / total as f64))
}

/// Delete all uptime samples for a target (also cascades on target delete). Returns rows affected.
pub async fn delete_by_target(pool: &SqlitePool, target_id: i64) -> LocalResult<u64> {
    let n = sqlx::query("DELETE FROM uptime_checks WHERE target_id = ?")
        .bind(target_id)
        .execute(pool)
        .await?
        .rows_affected();
    Ok(n)
}

/// Retention prune: delete samples older than `cutoff_rfc3339`. Returns rows affected.
pub async fn prune_older_than(pool: &SqlitePool, cutoff_rfc3339: &str) -> LocalResult<u64> {
    let n = sqlx::query("DELETE FROM uptime_checks WHERE checked_at < ?")
        .bind(cutoff_rfc3339)
        .execute(pool)
        .await?
        .rows_affected();
    if n > 0 {
        tracing::info!(deleted = n, cutoff = %cutoff_rfc3339, "uptime_checks pruned by retention");
    }
    Ok(n)
}

/// Count uptime samples for a target.
pub async fn count_by_target(pool: &SqlitePool, target_id: i64) -> LocalResult<i64> {
    let n: i64 = sqlx::query("SELECT count(*) FROM uptime_checks WHERE target_id = ?")
        .bind(target_id)
        .fetch_one(pool)
        .await?
        .try_get(0)?;
    Ok(n)
}
