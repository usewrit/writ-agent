//! Store layer for `selector_extractors` (field extractors under a target selector).
//! Runtime-checked sqlx only.
//!
//! Schema: migrations/0001_init.sql §3. PK INTEGER AUTOINCREMENT. `config` is JSON-TEXT
//! (callers serde). No timestamps on this table per the schema.

use super::super::error::LocalResult;
use sqlx::sqlite::SqlitePool;

/// A row of the `selector_extractors` table.
#[derive(Debug, Clone, sqlx::FromRow, serde::Serialize, serde::Deserialize)]
pub struct SelectorExtractor {
    pub id: i64,
    pub target_selector_id: i64,
    pub name: String,
    pub output_name: String,
    pub enabled: i64,
    pub extract_type: String,
    #[serde(default)]
    pub config: Option<String>,
    pub is_array: i64,
    #[serde(default)]
    pub default_value: Option<String>,
}

/// Fields accepted when creating an extractor. `target_selector_id`, `name`, `output_name`
/// are required.
#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct NewSelectorExtractor {
    pub target_selector_id: i64,
    pub name: String,
    pub output_name: String,
    #[serde(default)]
    pub enabled: Option<i64>,
    #[serde(default)]
    pub extract_type: Option<String>,
    #[serde(default)]
    pub config: Option<String>,
    #[serde(default)]
    pub is_array: Option<i64>,
    #[serde(default)]
    pub default_value: Option<String>,
}

/// Partial update; `None` fields left untouched.
#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct SelectorExtractorUpdate {
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub output_name: Option<String>,
    #[serde(default)]
    pub enabled: Option<i64>,
    #[serde(default)]
    pub extract_type: Option<String>,
    #[serde(default)]
    pub config: Option<String>,
    #[serde(default)]
    pub is_array: Option<i64>,
    #[serde(default)]
    pub default_value: Option<String>,
}

const SELECT_COLS: &str =
    "id, target_selector_id, name, output_name, enabled, extract_type, config, is_array, default_value";

/// Insert an extractor; returns the new row id.
pub async fn insert(pool: &SqlitePool, e: &NewSelectorExtractor) -> LocalResult<i64> {
    let id = sqlx::query(
        "INSERT INTO selector_extractors \
         (target_selector_id, name, output_name, enabled, extract_type, config, is_array, default_value) \
         VALUES (?, ?, ?, COALESCE(?, 1), COALESCE(?, 'text'), COALESCE(?, '{}'), COALESCE(?, 0), ?)",
    )
    .bind(e.target_selector_id)
    .bind(&e.name)
    .bind(&e.output_name)
    .bind(e.enabled)
    .bind(&e.extract_type)
    .bind(&e.config)
    .bind(e.is_array)
    .bind(&e.default_value)
    .execute(pool)
    .await?
    .last_insert_rowid();
    tracing::info!(
        extractor_id = id,
        target_selector_id = e.target_selector_id,
        output_name = %e.output_name,
        "selector extractor inserted"
    );
    Ok(id)
}

/// Fetch one extractor by id, or `None` if absent.
pub async fn get_by_id(pool: &SqlitePool, id: i64) -> LocalResult<Option<SelectorExtractor>> {
    let row = sqlx::query_as::<_, SelectorExtractor>(&format!(
        "SELECT {SELECT_COLS} FROM selector_extractors WHERE id = ?"
    ))
    .bind(id)
    .fetch_optional(pool)
    .await?;
    Ok(row)
}

/// List all extractors for a selector, by id ascending (stable creation order).
pub async fn list_by_selector(
    pool: &SqlitePool,
    target_selector_id: i64,
) -> LocalResult<Vec<SelectorExtractor>> {
    let rows = sqlx::query_as::<_, SelectorExtractor>(&format!(
        "SELECT {SELECT_COLS} FROM selector_extractors WHERE target_selector_id = ? ORDER BY id ASC"
    ))
    .bind(target_selector_id)
    .fetch_all(pool)
    .await?;
    Ok(rows)
}

/// List only enabled extractors for a selector (extraction-loop input).
pub async fn list_enabled_by_selector(
    pool: &SqlitePool,
    target_selector_id: i64,
) -> LocalResult<Vec<SelectorExtractor>> {
    let rows = sqlx::query_as::<_, SelectorExtractor>(&format!(
        "SELECT {SELECT_COLS} FROM selector_extractors \
         WHERE target_selector_id = ? AND enabled = 1 ORDER BY id ASC"
    ))
    .bind(target_selector_id)
    .fetch_all(pool)
    .await?;
    Ok(rows)
}

/// Apply a partial update. Returns the refreshed row (or `None` if absent).
pub async fn update(
    pool: &SqlitePool,
    id: i64,
    u: &SelectorExtractorUpdate,
) -> LocalResult<Option<SelectorExtractor>> {
    sqlx::query(
        "UPDATE selector_extractors SET \
         name = COALESCE(?, name), \
         output_name = COALESCE(?, output_name), \
         enabled = COALESCE(?, enabled), \
         extract_type = COALESCE(?, extract_type), \
         config = COALESCE(?, config), \
         is_array = COALESCE(?, is_array), \
         default_value = COALESCE(?, default_value) \
         WHERE id = ?",
    )
    .bind(&u.name)
    .bind(&u.output_name)
    .bind(u.enabled)
    .bind(&u.extract_type)
    .bind(&u.config)
    .bind(u.is_array)
    .bind(&u.default_value)
    .bind(id)
    .execute(pool)
    .await?;
    get_by_id(pool, id).await
}

/// Toggle `enabled`. Returns rows affected.
pub async fn set_enabled(pool: &SqlitePool, id: i64, enabled: bool) -> LocalResult<u64> {
    let n = sqlx::query("UPDATE selector_extractors SET enabled = ? WHERE id = ?")
        .bind(enabled as i64)
        .bind(id)
        .execute(pool)
        .await?
        .rows_affected();
    Ok(n)
}

/// Hard-delete an extractor. Returns rows affected.
pub async fn delete(pool: &SqlitePool, id: i64) -> LocalResult<u64> {
    let n = sqlx::query("DELETE FROM selector_extractors WHERE id = ?")
        .bind(id)
        .execute(pool)
        .await?
        .rows_affected();
    tracing::info!(extractor_id = id, deleted = n, "selector extractor deleted");
    Ok(n)
}

/// Delete all extractors under a selector (e.g. when re-authoring). Returns rows affected.
pub async fn delete_by_selector(pool: &SqlitePool, target_selector_id: i64) -> LocalResult<u64> {
    let n = sqlx::query("DELETE FROM selector_extractors WHERE target_selector_id = ?")
        .bind(target_selector_id)
        .execute(pool)
        .await?
        .rows_affected();
    Ok(n)
}
