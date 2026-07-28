//! Store layer for the `config` key/value table (§10 of 0001_init.sql).
//!
//! `CREATE TABLE config (key TEXT PRIMARY KEY, value TEXT NOT NULL)` — a tiny string KV used for
//! scheduler cursors, onboarding flags, and migration markers. SECRETS/KEYS NEVER GO HERE (those
//! belong in the OS keyring / `vault_secrets` ciphertext). Accordingly this store does not redact
//! values, but callers must not write secret material through it.
//!
//! Runtime-checked sqlx only (no compile-time macros). Errors map into `LocalError` via `?`.

use super::super::error::LocalResult;
use sqlx::sqlite::SqlitePool;
use sqlx::Row;

/// `config` key holding the gateway-assigned recorder `agent_id` for a cloud-linked desktop.
///
/// This lives HERE, with the other `config` key names, rather than in `cloud::gateway` — it is a
/// row NAME in this table, not cloud transport. Keeping it in the cloud module forced non-cloud
/// callers (`api::v1::cloud_agent`, `relay::cloud`) to `use crate::local::cloud::gateway::…` just to
/// read a string constant, which trips `scripts/desktop/offline-first-guard.sh` (the `cloud::gateway`
/// pattern) even though no cloud reach is involved. `cloud::gateway` re-exports it for continuity.
///
/// The value is non-secret routing metadata (see the module note above: no secrets in `config`).
pub const LINKED_AGENT_ID_KEY: &str = "cloud.linked_agent_id";

/// One row of the `config` table.
#[derive(Debug, Clone, sqlx::FromRow, serde::Serialize, serde::Deserialize)]
pub struct ConfigEntry {
    pub key: String,
    pub value: String,
}

/// Get a config value by key. Returns `None` if the key is unset.
pub async fn get(pool: &SqlitePool, key: &str) -> LocalResult<Option<String>> {
    let row = sqlx::query("SELECT value FROM config WHERE key = ?1")
        .bind(key)
        .fetch_optional(pool)
        .await?;
    Ok(row.map(|r| r.get::<String, _>("value")))
}

/// Get a config value, or `default` (owned) if unset.
pub async fn get_or(pool: &SqlitePool, key: &str, default: &str) -> LocalResult<String> {
    Ok(get(pool, key).await?.unwrap_or_else(|| default.to_string()))
}

/// Set (upsert) a config value. Insert if new, replace if the key already exists.
pub async fn set(pool: &SqlitePool, key: &str, value: &str) -> LocalResult<()> {
    sqlx::query(
        r#"
        INSERT INTO config (key, value) VALUES (?1, ?2)
        ON CONFLICT(key) DO UPDATE SET value = excluded.value
        "#,
    )
    .bind(key)
    .bind(value)
    .execute(pool)
    .await?;
    tracing::debug!(config_key = %key, "config set");
    Ok(())
}

/// Delete a config key. Returns `true` if a row was removed.
pub async fn delete(pool: &SqlitePool, key: &str) -> LocalResult<bool> {
    let res = sqlx::query("DELETE FROM config WHERE key = ?1")
        .bind(key)
        .execute(pool)
        .await?;
    Ok(res.rows_affected() > 0)
}

/// List all config entries, ordered by key. The `config` table is small (cursors/flags), so this
/// is intentionally uncapped.
pub async fn list_all(pool: &SqlitePool) -> LocalResult<Vec<ConfigEntry>> {
    let rows = sqlx::query_as::<_, ConfigEntry>("SELECT key, value FROM config ORDER BY key ASC")
        .fetch_all(pool)
        .await?;
    Ok(rows)
}
