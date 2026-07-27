//! Store layer for `monitor_state` (live, change-only monitor state — one row per target).
//! Runtime-checked sqlx only.
//!
//! Schema: migrations/0001_init.sql §4. PK is `target_id` (no surrogate id, no autoincrement);
//! this table holds the latest live state per target and is written via upsert. `state` is a
//! short status token (e.g. "unchanged"/"changed"/"error"); booleans are INTEGER 0/1.

use super::super::error::LocalResult;
use sqlx::sqlite::SqlitePool;
use sqlx::Row as _;

/// A row of the `monitor_state` table.
#[derive(Debug, Clone, sqlx::FromRow, serde::Serialize, serde::Deserialize)]
pub struct MonitorState {
    pub target_id: i64,
    pub checked_at: String,
    #[serde(default)]
    pub state: Option<String>,
    #[serde(default)]
    pub is_up: Option<i64>,
    #[serde(default)]
    pub status_code: Option<i64>,
    #[serde(default)]
    pub last_change_at: Option<String>,
    pub updated_at: String,
}

/// Values written on each live-state update.
#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct MonitorStateUpsert {
    /// RFC3339 timestamp of the check that produced this state.
    pub checked_at: String,
    #[serde(default)]
    pub state: Option<String>,
    #[serde(default)]
    pub is_up: Option<i64>,
    #[serde(default)]
    pub status_code: Option<i64>,
    /// When `Some`, overwrites `last_change_at` (set on a detected change). When `None`, the
    /// existing `last_change_at` is preserved across the upsert.
    #[serde(default)]
    pub last_change_at: Option<String>,
}

const SELECT_COLS: &str = "target_id, checked_at, state, is_up, status_code, last_change_at, updated_at";

/// Insert or update the live state for `target_id`. `last_change_at` is preserved when the new
/// value is NULL (only a detected change supplies it). Bumps `updated_at`.
pub async fn upsert(pool: &SqlitePool, target_id: i64, s: &MonitorStateUpsert) -> LocalResult<()> {
    sqlx::query(
        "INSERT INTO monitor_state (target_id, checked_at, state, is_up, status_code, last_change_at, updated_at) \
         VALUES (?, ?, ?, ?, ?, ?, strftime('%Y-%m-%dT%H:%M:%fZ','now')) \
         ON CONFLICT(target_id) DO UPDATE SET \
         checked_at = excluded.checked_at, \
         state = excluded.state, \
         is_up = excluded.is_up, \
         status_code = excluded.status_code, \
         last_change_at = COALESCE(excluded.last_change_at, monitor_state.last_change_at), \
         updated_at = strftime('%Y-%m-%dT%H:%M:%fZ','now')",
    )
    .bind(target_id)
    .bind(&s.checked_at)
    .bind(&s.state)
    .bind(s.is_up)
    .bind(s.status_code)
    .bind(&s.last_change_at)
    .execute(pool)
    .await?;
    Ok(())
}

/// Mark a target's live state as `"checking"` — an IN-PROGRESS check — without disturbing the
/// last-checked timestamp or the prior result fields (`is_up`/`status_code`/`last_change_at`). The
/// terminal [`upsert`] at the end of the check overwrites `state` with the real outcome
/// (`up`/`down`/`changed`/`unchanged`/`error`), so this marker is transient. `updated_at` is bumped
/// so readers can age out a stale marker left by a mid-check crash (nothing else clears it until the
/// next scheduled check). For a never-checked target the inserted row carries an empty `checked_at`,
/// which still reads as "never checked" everywhere `checked_at` is consumed.
pub async fn mark_checking(pool: &SqlitePool, target_id: i64) -> LocalResult<()> {
    sqlx::query(
        "INSERT INTO monitor_state (target_id, checked_at, state, updated_at) \
         VALUES (?, '', 'checking', strftime('%Y-%m-%dT%H:%M:%fZ','now')) \
         ON CONFLICT(target_id) DO UPDATE SET \
         state = 'checking', \
         updated_at = strftime('%Y-%m-%dT%H:%M:%fZ','now')",
    )
    .bind(target_id)
    .execute(pool)
    .await?;
    Ok(())
}

/// Fetch the live state for a target, or `None` if it has never been checked.
pub async fn get(pool: &SqlitePool, target_id: i64) -> LocalResult<Option<MonitorState>> {
    let row = sqlx::query_as::<_, MonitorState>(&format!(
        "SELECT {SELECT_COLS} FROM monitor_state WHERE target_id = ?"
    ))
    .bind(target_id)
    .fetch_optional(pool)
    .await?;
    Ok(row)
}

/// Fetch live state for many targets at once (dashboard overlay). Empty input ⇒ empty result.
pub async fn get_many(pool: &SqlitePool, target_ids: &[i64]) -> LocalResult<Vec<MonitorState>> {
    if target_ids.is_empty() {
        return Ok(Vec::new());
    }
    let placeholders = std::iter::repeat_n("?", target_ids.len()).collect::<Vec<_>>().join(",");
    let sql = format!(
        "SELECT {SELECT_COLS} FROM monitor_state WHERE target_id IN ({placeholders}) ORDER BY checked_at DESC"
    );
    let mut q = sqlx::query_as::<_, MonitorState>(&sql);
    for id in target_ids {
        q = q.bind(id);
    }
    let rows = q.fetch_all(pool).await?;
    Ok(rows)
}

/// List all live monitor states, most-recently-checked first, capped at `limit`.
pub async fn list(pool: &SqlitePool, limit: i64) -> LocalResult<Vec<MonitorState>> {
    let rows = sqlx::query_as::<_, MonitorState>(&format!(
        "SELECT {SELECT_COLS} FROM monitor_state ORDER BY checked_at DESC LIMIT ?"
    ))
    .bind(limit)
    .fetch_all(pool)
    .await?;
    Ok(rows)
}

/// Delete the live state for a target (also removed by FK cascade when the target is deleted).
/// Returns rows affected.
pub async fn delete(pool: &SqlitePool, target_id: i64) -> LocalResult<u64> {
    let n = sqlx::query("DELETE FROM monitor_state WHERE target_id = ?")
        .bind(target_id)
        .execute(pool)
        .await?
        .rows_affected();
    Ok(n)
}

/// Count targets that currently have live state.
pub async fn count(pool: &SqlitePool) -> LocalResult<i64> {
    let n: i64 = sqlx::query("SELECT count(*) FROM monitor_state")
        .fetch_one(pool)
        .await?
        .try_get(0)?;
    Ok(n)
}
