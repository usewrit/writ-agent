//! Store layer for `target_selectors` (named selectors under a target). Runtime-checked sqlx only.
//!
//! Schema: migrations/0001_init.sql §3. PK INTEGER AUTOINCREMENT, UNIQUE(target_id, selector).
//! `visual_region` is JSON-TEXT (callers serde). `baseline_screenshot`/`baseline_content` may be
//! large blobs-as-text; not secret, but verbose — never logged.

use super::super::error::LocalResult;
use sqlx::sqlite::SqlitePool;
use sqlx::Row as _;

/// A row of the `target_selectors` table.
#[derive(Debug, Clone, sqlx::FromRow, serde::Serialize, serde::Deserialize)]
pub struct TargetSelector {
    pub id: i64,
    pub target_id: i64,
    pub name: String,
    pub selector: String,
    #[serde(default)]
    pub description: Option<String>,
    pub enabled: i64,
    #[serde(default)]
    pub content_type: Option<String>,
    #[serde(default)]
    pub visual_region: Option<String>,
    #[serde(default)]
    pub ignore_regex: Option<String>,
    #[serde(default)]
    pub priority: Option<i64>,
    #[serde(default)]
    pub baseline_hash: Option<String>,
    #[serde(default)]
    pub baseline_content: Option<String>,
    #[serde(default)]
    pub baseline_screenshot: Option<String>,
    #[serde(default)]
    pub baseline_fetched_at: Option<String>,
    #[serde(default)]
    pub last_content_hash: Option<String>,
    #[serde(default)]
    pub last_checked_at: Option<String>,
    #[serde(default)]
    pub change_count: Option<i64>,
    pub created_at: String,
    #[serde(default)]
    pub updated_at: Option<String>,
}

/// Fields accepted when creating a selector. `target_id`, `name`, `selector` are required.
#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct NewTargetSelector {
    pub target_id: i64,
    pub name: String,
    pub selector: String,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub enabled: Option<i64>,
    #[serde(default)]
    pub content_type: Option<String>,
    #[serde(default)]
    pub visual_region: Option<String>,
    #[serde(default)]
    pub ignore_regex: Option<String>,
    #[serde(default)]
    pub priority: Option<i64>,
}

/// Partial update of mutable config fields; bumps `updated_at`.
#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct TargetSelectorUpdate {
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub selector: Option<String>,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub enabled: Option<i64>,
    #[serde(default)]
    pub content_type: Option<String>,
    #[serde(default)]
    pub visual_region: Option<String>,
    #[serde(default)]
    pub ignore_regex: Option<String>,
    #[serde(default)]
    pub priority: Option<i64>,
}

const SELECT_COLS: &str = "id, target_id, name, selector, description, enabled, content_type, \
    visual_region, ignore_regex, priority, baseline_hash, baseline_content, baseline_screenshot, \
    baseline_fetched_at, last_content_hash, last_checked_at, change_count, created_at, updated_at";

/// Insert a selector; returns the new row id.
pub async fn insert(pool: &SqlitePool, s: &NewTargetSelector) -> LocalResult<i64> {
    let id = sqlx::query(
        "INSERT INTO target_selectors \
         (target_id, name, selector, description, enabled, content_type, visual_region, ignore_regex, priority) \
         VALUES (?, ?, ?, ?, COALESCE(?, 1), COALESCE(?, 'text'), ?, ?, COALESCE(?, 0))",
    )
    .bind(s.target_id)
    .bind(&s.name)
    .bind(&s.selector)
    .bind(&s.description)
    .bind(s.enabled)
    .bind(&s.content_type)
    .bind(&s.visual_region)
    .bind(&s.ignore_regex)
    .bind(s.priority)
    .execute(pool)
    .await?
    .last_insert_rowid();
    tracing::info!(selector_id = id, target_id = s.target_id, name = %s.name, "target selector inserted");
    Ok(id)
}

/// Fetch one selector by id, or `None` if absent.
pub async fn get_by_id(pool: &SqlitePool, id: i64) -> LocalResult<Option<TargetSelector>> {
    let row = sqlx::query_as::<_, TargetSelector>(&format!(
        "SELECT {SELECT_COLS} FROM target_selectors WHERE id = ?"
    ))
    .bind(id)
    .fetch_optional(pool)
    .await?;
    Ok(row)
}

/// Look up a selector by the pair the schema makes unique (`UNIQUE(target_id, selector)`), so an API
/// handler can PRE-CHECK a duplicate and answer with an actionable 409 instead of letting the insert
/// trip the index. The generic constraint mapping in `error.rs` still catches the race.
pub async fn get_by_target_and_selector(
    pool: &SqlitePool,
    target_id: i64,
    selector: &str,
) -> LocalResult<Option<TargetSelector>> {
    let row = sqlx::query_as::<_, TargetSelector>(&format!(
        "SELECT {SELECT_COLS} FROM target_selectors WHERE target_id = ? AND selector = ?"
    ))
    .bind(target_id)
    .bind(selector)
    .fetch_optional(pool)
    .await?;
    Ok(row)
}

/// List all selectors for a target, priority-desc then newest-first, capped at `limit`.
pub async fn list_by_target(pool: &SqlitePool, target_id: i64, limit: i64) -> LocalResult<Vec<TargetSelector>> {
    let rows = sqlx::query_as::<_, TargetSelector>(&format!(
        "SELECT {SELECT_COLS} FROM target_selectors WHERE target_id = ? \
         ORDER BY priority DESC, created_at DESC, id DESC LIMIT ?"
    ))
    .bind(target_id)
    .bind(limit)
    .fetch_all(pool)
    .await?;
    Ok(rows)
}

/// List only enabled selectors for a target, priority-desc (check-loop input).
pub async fn list_enabled_by_target(pool: &SqlitePool, target_id: i64) -> LocalResult<Vec<TargetSelector>> {
    let rows = sqlx::query_as::<_, TargetSelector>(&format!(
        "SELECT {SELECT_COLS} FROM target_selectors WHERE target_id = ? AND enabled = 1 \
         ORDER BY priority DESC, id ASC"
    ))
    .bind(target_id)
    .fetch_all(pool)
    .await?;
    Ok(rows)
}

/// Apply a partial config update; bumps `updated_at`. Returns the refreshed row (or `None`).
pub async fn update(
    pool: &SqlitePool,
    id: i64,
    u: &TargetSelectorUpdate,
) -> LocalResult<Option<TargetSelector>> {
    sqlx::query(
        "UPDATE target_selectors SET \
         name = COALESCE(?, name), \
         selector = COALESCE(?, selector), \
         description = COALESCE(?, description), \
         enabled = COALESCE(?, enabled), \
         content_type = COALESCE(?, content_type), \
         visual_region = COALESCE(?, visual_region), \
         ignore_regex = COALESCE(?, ignore_regex), \
         priority = COALESCE(?, priority), \
         updated_at = strftime('%Y-%m-%dT%H:%M:%fZ','now') \
         WHERE id = ?",
    )
    .bind(&u.name)
    .bind(&u.selector)
    .bind(&u.description)
    .bind(u.enabled)
    .bind(&u.content_type)
    .bind(&u.visual_region)
    .bind(&u.ignore_regex)
    .bind(u.priority)
    .bind(id)
    .execute(pool)
    .await?;
    get_by_id(pool, id).await
}

/// Capture the baseline (hash/content/screenshot) and stamp `baseline_fetched_at`/`updated_at` now.
pub async fn set_baseline(
    pool: &SqlitePool,
    id: i64,
    baseline_hash: Option<&str>,
    baseline_content: Option<&str>,
    baseline_screenshot: Option<&str>,
) -> LocalResult<()> {
    set_baseline_with(pool, id, baseline_hash, baseline_content, baseline_screenshot).await
}

/// [`set_baseline`] over any executor, so the caller can put it in a TRANSACTION together with the
/// `changes` row it belongs to. See `changes::insert_with` for why that pairing must be atomic.
pub async fn set_baseline_with<'e, E>(
    exec: E,
    id: i64,
    baseline_hash: Option<&str>,
    baseline_content: Option<&str>,
    baseline_screenshot: Option<&str>,
) -> LocalResult<()>
where
    E: sqlx::Executor<'e, Database = sqlx::Sqlite>,
{
    sqlx::query(
        "UPDATE target_selectors SET baseline_hash = ?, baseline_content = ?, baseline_screenshot = ?, \
         baseline_fetched_at = strftime('%Y-%m-%dT%H:%M:%fZ','now'), \
         updated_at = strftime('%Y-%m-%dT%H:%M:%fZ','now') WHERE id = ?",
    )
    .bind(baseline_hash)
    .bind(baseline_content)
    .bind(baseline_screenshot)
    .bind(id)
    .execute(exec)
    .await?;
    Ok(())
}

/// Record the latest observed content hash + checked-at, and (optionally) bump the change counter.
pub async fn record_check(
    pool: &SqlitePool,
    id: i64,
    last_content_hash: Option<&str>,
    bump_change_count: bool,
) -> LocalResult<()> {
    sqlx::query(
        "UPDATE target_selectors SET last_content_hash = ?, \
         last_checked_at = strftime('%Y-%m-%dT%H:%M:%fZ','now'), \
         change_count = COALESCE(change_count, 0) + ?, \
         updated_at = strftime('%Y-%m-%dT%H:%M:%fZ','now') WHERE id = ?",
    )
    .bind(last_content_hash)
    .bind(if bump_change_count { 1_i64 } else { 0 })
    .bind(id)
    .execute(pool)
    .await?;
    Ok(())
}

/// Toggle `enabled`; bumps `updated_at`. Returns rows affected.
pub async fn set_enabled(pool: &SqlitePool, id: i64, enabled: bool) -> LocalResult<u64> {
    let n = sqlx::query(
        "UPDATE target_selectors SET enabled = ?, updated_at = strftime('%Y-%m-%dT%H:%M:%fZ','now') WHERE id = ?",
    )
    .bind(enabled as i64)
    .bind(id)
    .execute(pool)
    .await?
    .rows_affected();
    Ok(n)
}

/// Hard-delete a selector (cascades to its extractors; sets changes.target_selector_id NULL).
pub async fn delete(pool: &SqlitePool, id: i64) -> LocalResult<u64> {
    let n = sqlx::query("DELETE FROM target_selectors WHERE id = ?")
        .bind(id)
        .execute(pool)
        .await?
        .rows_affected();
    tracing::info!(selector_id = id, deleted = n, "target selector deleted");
    Ok(n)
}

/// Count selectors for a target.
pub async fn count_by_target(pool: &SqlitePool, target_id: i64) -> LocalResult<i64> {
    let n: i64 = sqlx::query("SELECT count(*) FROM target_selectors WHERE target_id = ?")
        .bind(target_id)
        .fetch_one(pool)
        .await?
        .try_get(0)?;
    Ok(n)
}
