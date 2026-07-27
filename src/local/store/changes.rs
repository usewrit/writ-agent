//! Store layer for `changes` (change-only detected-difference history). Runtime-checked sqlx only.
//!
//! Schema: migrations/0001_init.sql §4. PK INTEGER AUTOINCREMENT. Append-mostly history;
//! `last_detected_at` is bumped when the same change recurs (dedupe by content_hash). The
//! `content_*`/`screenshot_*` columns can be large blobs-as-text — never logged verbatim.

use super::super::error::LocalResult;
use sqlx::sqlite::SqlitePool;
use sqlx::Row as _;

/// A row of the `changes` table.
#[derive(Debug, Clone, sqlx::FromRow, serde::Serialize, serde::Deserialize)]
pub struct Change {
    pub id: i64,
    pub target_id: i64,
    #[serde(default)]
    pub target_selector_id: Option<i64>,
    pub content_hash: String,
    #[serde(default)]
    pub previous_hash: Option<String>,
    #[serde(default)]
    pub diff_snippet: Option<String>,
    #[serde(default)]
    pub content_before: Option<String>,
    #[serde(default)]
    pub content_after: Option<String>,
    #[serde(default)]
    pub screenshot_before: Option<String>,
    #[serde(default)]
    pub screenshot_after: Option<String>,
    #[serde(default)]
    pub screenshot_diff: Option<String>,
    pub first_detected_at: String,
    pub last_detected_at: String,
}

/// Fields recorded on a newly detected change. `target_id` and `content_hash` are required.
#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct NewChange {
    pub target_id: i64,
    #[serde(default)]
    pub target_selector_id: Option<i64>,
    pub content_hash: String,
    #[serde(default)]
    pub previous_hash: Option<String>,
    #[serde(default)]
    pub diff_snippet: Option<String>,
    #[serde(default)]
    pub content_before: Option<String>,
    #[serde(default)]
    pub content_after: Option<String>,
    #[serde(default)]
    pub screenshot_before: Option<String>,
    #[serde(default)]
    pub screenshot_after: Option<String>,
    #[serde(default)]
    pub screenshot_diff: Option<String>,
}

const SELECT_COLS: &str = "id, target_id, target_selector_id, content_hash, previous_hash, \
    diff_snippet, content_before, content_after, screenshot_before, screenshot_after, \
    screenshot_diff, first_detected_at, last_detected_at";

/// Insert a newly detected change; returns the new row id. `first_detected_at`/`last_detected_at`
/// default to now via the schema.
pub async fn insert(pool: &SqlitePool, c: &NewChange) -> LocalResult<i64> {
    insert_with(pool, c).await
}

/// [`insert`] over any executor, so the caller can put it in a TRANSACTION.
///
/// The monitor runner must write a change row and advance the watched selector's baseline together:
/// the baseline is what stops the very same diff from being re-detected (and re-notified) on every
/// subsequent check. Two autocommit statements cannot express that, so both writes take an executor
/// and the runner hands them one transaction (`monitor::runner::commit_change_and_baseline`).
pub async fn insert_with<'e, E>(exec: E, c: &NewChange) -> LocalResult<i64>
where
    E: sqlx::Executor<'e, Database = sqlx::Sqlite>,
{
    let id = sqlx::query(
        "INSERT INTO changes \
         (target_id, target_selector_id, content_hash, previous_hash, diff_snippet, content_before, \
          content_after, screenshot_before, screenshot_after, screenshot_diff) \
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
    )
    .bind(c.target_id)
    .bind(c.target_selector_id)
    .bind(&c.content_hash)
    .bind(&c.previous_hash)
    .bind(&c.diff_snippet)
    .bind(&c.content_before)
    .bind(&c.content_after)
    .bind(&c.screenshot_before)
    .bind(&c.screenshot_after)
    .bind(&c.screenshot_diff)
    .execute(exec)
    .await?
    .last_insert_rowid();
    tracing::info!(change_id = id, target_id = c.target_id, "change recorded");
    Ok(id)
}

/// Fetch one change by id, or `None` if absent.
pub async fn get_by_id(pool: &SqlitePool, id: i64) -> LocalResult<Option<Change>> {
    let row = sqlx::query_as::<_, Change>(&format!("SELECT {SELECT_COLS} FROM changes WHERE id = ?"))
        .bind(id)
        .fetch_optional(pool)
        .await?;
    Ok(row)
}

/// List changes for a target, newest-first (by first_detected_at), capped at `limit`.
pub async fn list_by_target(pool: &SqlitePool, target_id: i64, limit: i64) -> LocalResult<Vec<Change>> {
    let rows = sqlx::query_as::<_, Change>(&format!(
        "SELECT {SELECT_COLS} FROM changes WHERE target_id = ? \
         ORDER BY first_detected_at DESC, id DESC LIMIT ?"
    ))
    .bind(target_id)
    .bind(limit)
    .fetch_all(pool)
    .await?;
    Ok(rows)
}

/// List changes for a single selector under a target, newest-first, capped at `limit`.
pub async fn list_by_selector(
    pool: &SqlitePool,
    target_selector_id: i64,
    limit: i64,
) -> LocalResult<Vec<Change>> {
    let rows = sqlx::query_as::<_, Change>(&format!(
        "SELECT {SELECT_COLS} FROM changes WHERE target_selector_id = ? \
         ORDER BY first_detected_at DESC, id DESC LIMIT ?"
    ))
    .bind(target_selector_id)
    .bind(limit)
    .fetch_all(pool)
    .await?;
    Ok(rows)
}

/// List recent changes across all targets, newest-first, capped at `limit` (activity feed).
pub async fn list_recent(pool: &SqlitePool, limit: i64) -> LocalResult<Vec<Change>> {
    let rows = sqlx::query_as::<_, Change>(&format!(
        "SELECT {SELECT_COLS} FROM changes ORDER BY last_detected_at DESC, id DESC LIMIT ?"
    ))
    .bind(limit)
    .fetch_all(pool)
    .await?;
    Ok(rows)
}

/// A recent change joined with its monitor URL + selector name, for the home "recent changes" feed.
/// Deliberately omits the large `content_*`/`screenshot_*` blobs — the feed only needs a one-line
/// label, a truncated diff snippet, and the timestamp; full detail lives on the monitor page.
#[derive(Debug, Clone, sqlx::FromRow, serde::Serialize)]
pub struct RecentChange {
    pub id: i64,
    pub target_id: i64,
    pub target_url: String,
    #[serde(default)]
    pub target_selector_id: Option<i64>,
    #[serde(default)]
    pub selector_name: Option<String>,
    #[serde(default)]
    pub diff_snippet: Option<String>,
    pub first_detected_at: String,
    pub last_detected_at: String,
}

/// Recent changes across ALL targets, newest-first (by `last_detected_at`), each enriched with the
/// monitor URL + selector name and a diff snippet truncated to a feed-friendly length. Capped at
/// `limit`. A change whose target row was deleted is excluded by the inner JOIN; a NULL/absent
/// selector yields `selector_name = None`.
pub async fn list_recent_enriched(pool: &SqlitePool, limit: i64) -> LocalResult<Vec<RecentChange>> {
    let rows = sqlx::query_as::<_, RecentChange>(
        "SELECT c.id, c.target_id, t.url AS target_url, c.target_selector_id, \
                s.name AS selector_name, substr(c.diff_snippet, 1, 280) AS diff_snippet, \
                c.first_detected_at, c.last_detected_at \
         FROM changes c \
         JOIN targets t ON t.id = c.target_id \
         LEFT JOIN target_selectors s ON s.id = c.target_selector_id \
         ORDER BY c.last_detected_at DESC, c.id DESC LIMIT ?",
    )
    .bind(limit)
    .fetch_all(pool)
    .await?;
    Ok(rows)
}

/// The most recent change for a target (whatever selector), or `None`.
pub async fn latest_for_target(pool: &SqlitePool, target_id: i64) -> LocalResult<Option<Change>> {
    let row = sqlx::query_as::<_, Change>(&format!(
        "SELECT {SELECT_COLS} FROM changes WHERE target_id = ? \
         ORDER BY first_detected_at DESC, id DESC LIMIT 1"
    ))
    .bind(target_id)
    .fetch_optional(pool)
    .await?;
    Ok(row)
}

/// Bump `last_detected_at` to now for a recurring change (dedupe path). Returns rows affected.
pub async fn touch_last_detected(pool: &SqlitePool, id: i64) -> LocalResult<u64> {
    let n = sqlx::query(
        "UPDATE changes SET last_detected_at = strftime('%Y-%m-%dT%H:%M:%fZ','now') WHERE id = ?",
    )
    .bind(id)
    .execute(pool)
    .await?
    .rows_affected();
    Ok(n)
}

/// Delete one change by id. Returns rows affected.
pub async fn delete(pool: &SqlitePool, id: i64) -> LocalResult<u64> {
    let n = sqlx::query("DELETE FROM changes WHERE id = ?")
        .bind(id)
        .execute(pool)
        .await?
        .rows_affected();
    Ok(n)
}

/// Delete all changes for a target (history reset). Returns rows affected.
pub async fn delete_by_target(pool: &SqlitePool, target_id: i64) -> LocalResult<u64> {
    let n = sqlx::query("DELETE FROM changes WHERE target_id = ?")
        .bind(target_id)
        .execute(pool)
        .await?
        .rows_affected();
    tracing::info!(target_id, deleted = n, "changes purged for target");
    Ok(n)
}

/// Retention prune: delete changes older than `cutoff_rfc3339` (by last_detected_at).
/// Returns rows affected.
pub async fn prune_older_than(pool: &SqlitePool, cutoff_rfc3339: &str) -> LocalResult<u64> {
    let n = sqlx::query("DELETE FROM changes WHERE last_detected_at < ?")
        .bind(cutoff_rfc3339)
        .execute(pool)
        .await?
        .rows_affected();
    if n > 0 {
        tracing::info!(deleted = n, cutoff = %cutoff_rfc3339, "changes pruned by retention");
    }
    Ok(n)
}

/// Count changes for a target.
pub async fn count_by_target(pool: &SqlitePool, target_id: i64) -> LocalResult<i64> {
    let n: i64 = sqlx::query("SELECT count(*) FROM changes WHERE target_id = ?")
        .bind(target_id)
        .fetch_one(pool)
        .await?
        .try_get(0)?;
    Ok(n)
}
