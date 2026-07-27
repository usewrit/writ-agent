//! Store layer for the `local_api_keys` table (§9 of 0001_init.sql).
//!
//! External clients/agents (Claude Desktop, n8n, ...) authenticate to the local API with a key
//! `wlk_<...>`. The RAW key is shown ONCE at creation and NEVER stored — this table holds only
//! the `prefix` (`wlk_` + first 6 chars, for UI) and the `key_hash` (sha256 of the full key).
//! Auth = hash the presented key, look up an enabled, non-revoked row by hash. We NEVER log the
//! hash or the raw key.
//!
//! Runtime-checked sqlx only (no compile-time macros). Errors map into `LocalError` via `?`.

use super::super::error::LocalResult;
use sqlx::sqlite::SqlitePool;

/// Max rows returned by an unbounded `list`.
const LIST_CAP: i64 = 200;

/// One row of the `local_api_keys` table. `key_hash` is sensitive — never serialize to clients.
/// `Debug` is hand-written (see the `store` module docs): `key_hash` is a credential verifier, and
/// echoing verifiers into logs is how an offline-guessing corpus gets built.
#[derive(Clone, sqlx::FromRow, serde::Serialize, serde::Deserialize)]
pub struct LocalApiKey {
    #[serde(default)]
    pub id: i64,
    pub name: String,
    /// `wlk_` + first 6 chars of the raw key — safe to show.
    pub prefix: String,
    /// sha256 of the full key. Hidden from API responses.
    #[serde(skip_serializing)]
    pub key_hash: String,
    /// CSV of scopes: read|run|admin
    pub scopes: String,
    pub enabled: i64,
    #[serde(default)]
    pub last_used_at: Option<String>,
    pub created_at: String,
    #[serde(default)]
    pub revoked_at: Option<String>,
}

/// Fields accepted on create. The caller generates the raw key, derives `prefix` + `key_hash`,
/// and passes ONLY those here (never the raw key).
/// `Debug` redacts `key_hash`, like [`LocalApiKey`].
#[derive(Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct NewLocalApiKey {
    pub name: String,
    pub prefix: String,
    /// sha256 of the full key — caller-computed.
    pub key_hash: String,
    /// Defaults to `"run"` when empty.
    #[serde(default)]
    pub scopes: Option<String>,
}

/// Insert a new API key record, returning the full row.
pub async fn insert(pool: &SqlitePool, k: &NewLocalApiKey) -> LocalResult<LocalApiKey> {
    let row = sqlx::query_as::<_, LocalApiKey>(
        r#"
        INSERT INTO local_api_keys (name, prefix, key_hash, scopes)
        VALUES (?1, ?2, ?3, COALESCE(?4, 'run'))
        RETURNING *
        "#,
    )
    .bind(&k.name)
    .bind(&k.prefix)
    .bind(&k.key_hash)
    .bind(&k.scopes)
    .fetch_one(pool)
    .await?;
    // NOTE: never log key_hash.
    tracing::info!(api_key_id = row.id, name = %row.name, prefix = %row.prefix, "local api key created");
    Ok(row)
}

/// Fetch one key by id.
pub async fn get_by_id(pool: &SqlitePool, id: i64) -> LocalResult<Option<LocalApiKey>> {
    let row = sqlx::query_as::<_, LocalApiKey>("SELECT * FROM local_api_keys WHERE id = ?1")
        .bind(id)
        .fetch_optional(pool)
        .await?;
    Ok(row)
}

/// AUTH lookup: find an enabled, non-revoked key by its `key_hash`. Returns `None` if the hash
/// is unknown, disabled, or revoked — caller maps `None` to 401.
pub async fn get_active_by_hash(
    pool: &SqlitePool,
    key_hash: &str,
) -> LocalResult<Option<LocalApiKey>> {
    let row = sqlx::query_as::<_, LocalApiKey>(
        "SELECT * FROM local_api_keys WHERE key_hash = ?1 AND enabled = 1 AND revoked_at IS NULL",
    )
    .bind(key_hash)
    .fetch_optional(pool)
    .await?;
    Ok(row)
}

/// List keys, newest-first, capped. (`key_hash` is present on the struct but `#[serde(skip_serializing)]`.)
pub async fn list(pool: &SqlitePool, limit: Option<i64>) -> LocalResult<Vec<LocalApiKey>> {
    let lim = limit.unwrap_or(LIST_CAP).clamp(1, LIST_CAP);
    let rows = sqlx::query_as::<_, LocalApiKey>(
        "SELECT * FROM local_api_keys ORDER BY created_at DESC, id DESC LIMIT ?1",
    )
    .bind(lim)
    .fetch_all(pool)
    .await?;
    Ok(rows)
}

/// Rename / re-scope a key (COALESCE: `None` leaves the column untouched).
/// Returns the updated row, or `None` if id absent.
pub async fn update(
    pool: &SqlitePool,
    id: i64,
    name: Option<&str>,
    scopes: Option<&str>,
) -> LocalResult<Option<LocalApiKey>> {
    let row = sqlx::query_as::<_, LocalApiKey>(
        r#"
        UPDATE local_api_keys SET
            name   = COALESCE(?2, name),
            scopes = COALESCE(?3, scopes)
        WHERE id = ?1
        RETURNING *
        "#,
    )
    .bind(id)
    .bind(name)
    .bind(scopes)
    .fetch_optional(pool)
    .await?;
    Ok(row)
}

/// Enable/disable a key (toggle without revoking). Returns true if a row was touched.
pub async fn set_enabled(pool: &SqlitePool, id: i64, enabled: bool) -> LocalResult<bool> {
    let res = sqlx::query("UPDATE local_api_keys SET enabled = ?2 WHERE id = ?1")
        .bind(id)
        .bind(enabled as i64)
        .execute(pool)
        .await?;
    Ok(res.rows_affected() > 0)
}

/// Stamp `last_used_at` to now on a successful auth. No-op if id absent.
pub async fn touch_used(pool: &SqlitePool, id: i64) -> LocalResult<()> {
    sqlx::query(
        "UPDATE local_api_keys SET last_used_at = strftime('%Y-%m-%dT%H:%M:%fZ','now') WHERE id = ?1",
    )
    .bind(id)
    .execute(pool)
    .await?;
    Ok(())
}

/// Revoke a key: disable it and stamp `revoked_at`. Idempotent. Returns true if a row was touched.
pub async fn revoke(pool: &SqlitePool, id: i64) -> LocalResult<bool> {
    let res = sqlx::query(
        r#"
        UPDATE local_api_keys SET
            enabled    = 0,
            revoked_at = strftime('%Y-%m-%dT%H:%M:%fZ','now')
        WHERE id = ?1
        "#,
    )
    .bind(id)
    .execute(pool)
    .await?;
    let touched = res.rows_affected() > 0;
    if touched {
        tracing::info!(api_key_id = id, "local api key revoked");
    }
    Ok(touched)
}

/// Hard-delete a key row. Returns true if removed.
pub async fn delete(pool: &SqlitePool, id: i64) -> LocalResult<bool> {
    let res = sqlx::query("DELETE FROM local_api_keys WHERE id = ?1")
        .bind(id)
        .execute(pool)
        .await?;
    let removed = res.rows_affected() > 0;
    if removed {
        tracing::info!(api_key_id = id, "local api key deleted");
    }
    Ok(removed)
}

impl std::fmt::Debug for LocalApiKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LocalApiKey")
            .field("id", &self.id)
            .field("name", &self.name)
            .field("prefix", &self.prefix) // non-secret display fragment, by design
            .field("scopes", &self.scopes)
            .field("enabled", &self.enabled)
            .field("revoked_at", &self.revoked_at)
            .field("key_hash", &super::REDACTED)
            .finish_non_exhaustive()
    }
}

impl std::fmt::Debug for NewLocalApiKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NewLocalApiKey")
            .field("name", &self.name)
            .field("prefix", &self.prefix)
            .field("scopes", &self.scopes)
            .field("key_hash", &super::REDACTED)
            .finish_non_exhaustive()
    }
}

