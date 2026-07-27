//! Store layer for the `vault_secrets` table (§7 of 0001_init.sql).
//!
//! Each row is a named secret whose value is ciphertext-only (`value_encrypted`). The plaintext
//! and the vault key NEVER touch this DB and are NEVER logged. `key` is UNIQUE. The ciphertext is
//! produced by the API handler (`api::v1::secrets`) via the `Vault` before it reaches this layer —
//! the store NEVER sees, seals, or stores plaintext; it persists the WF1: blob as-is.
//!
//! Runtime-checked sqlx only (no compile-time macros). Errors map into `LocalError` via `?`.

use super::super::error::LocalResult;
use sqlx::sqlite::SqlitePool;

/// Max rows returned by an unbounded `list`.
const LIST_CAP: i64 = 500;

/// One row of the `vault_secrets` table.
/// `Debug` is hand-written (see the `store` module docs): `value_encrypted` is the whole point of
/// this table, and a derived `Debug` printed the ciphertext into any log line that formatted a row.
#[derive(Clone, sqlx::FromRow, serde::Serialize, serde::Deserialize)]
pub struct VaultSecret {
    #[serde(default)]
    pub id: i64,
    pub key: String,
    /// Ciphertext — never logged, never returned to untrusted callers.
    pub value_encrypted: String,
    #[serde(default)]
    pub description: Option<String>,
    /// credentials|api_keys|tokens|ai_provider
    #[serde(default)]
    pub category: Option<String>,
    pub created_at: String,
    #[serde(default)]
    pub updated_at: Option<String>,
    #[serde(default)]
    pub last_used_at: Option<String>,
    #[serde(default)]
    pub use_count: i64,
}

/// Fields accepted on insert.
/// `Debug` redacts `value_encrypted`, like [`VaultSecret`].
#[derive(Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct NewVaultSecret {
    pub key: String,
    /// Ciphertext WF1: blob — the API handler seals the plaintext with the vault before insert.
    pub value_encrypted: String,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub category: Option<String>,
}

/// Insert a secret, returning the full row. Fails (unique violation) on duplicate `key`.
pub async fn insert(pool: &SqlitePool, s: &NewVaultSecret) -> LocalResult<VaultSecret> {
    let row = sqlx::query_as::<_, VaultSecret>(
        r#"
        INSERT INTO vault_secrets (key, value_encrypted, description, category)
        VALUES (?1, ?2, ?3, ?4)
        RETURNING *
        "#,
    )
    .bind(&s.key)
    .bind(&s.value_encrypted)
    .bind(&s.description)
    .bind(&s.category)
    .fetch_one(pool)
    .await?;
    // NOTE: do not log value_encrypted.
    tracing::info!(secret_id = row.id, key = %row.key, "vault secret inserted");
    Ok(row)
}

/// Upsert by `key`: insert, or replace ciphertext/description/category and bump `updated_at`.
/// Returns the resulting row.
pub async fn upsert(pool: &SqlitePool, s: &NewVaultSecret) -> LocalResult<VaultSecret> {
    let row = sqlx::query_as::<_, VaultSecret>(
        r#"
        INSERT INTO vault_secrets (key, value_encrypted, description, category)
        VALUES (?1, ?2, ?3, ?4)
        ON CONFLICT(key) DO UPDATE SET
            value_encrypted = excluded.value_encrypted,
            description     = excluded.description,
            category        = excluded.category,
            updated_at      = strftime('%Y-%m-%dT%H:%M:%fZ','now')
        RETURNING *
        "#,
    )
    .bind(&s.key)
    .bind(&s.value_encrypted)
    .bind(&s.description)
    .bind(&s.category)
    .fetch_one(pool)
    .await?;
    tracing::info!(secret_id = row.id, key = %row.key, "vault secret upserted");
    Ok(row)
}

/// Fetch one secret by id.
pub async fn get_by_id(pool: &SqlitePool, id: i64) -> LocalResult<Option<VaultSecret>> {
    let row = sqlx::query_as::<_, VaultSecret>("SELECT * FROM vault_secrets WHERE id = ?1")
        .bind(id)
        .fetch_optional(pool)
        .await?;
    Ok(row)
}

/// Fetch one secret by its unique `key`.
pub async fn get_by_key(pool: &SqlitePool, key: &str) -> LocalResult<Option<VaultSecret>> {
    let row = sqlx::query_as::<_, VaultSecret>("SELECT * FROM vault_secrets WHERE key = ?1")
        .bind(key)
        .fetch_optional(pool)
        .await?;
    Ok(row)
}

/// List secrets, newest-first, capped. (Rows still carry `value_encrypted` — callers must not
/// expose it; UI listings should project to non-secret columns.)
pub async fn list(pool: &SqlitePool, limit: Option<i64>) -> LocalResult<Vec<VaultSecret>> {
    let lim = limit.unwrap_or(LIST_CAP).clamp(1, LIST_CAP);
    let rows = sqlx::query_as::<_, VaultSecret>(
        "SELECT * FROM vault_secrets ORDER BY created_at DESC, id DESC LIMIT ?1",
    )
    .bind(lim)
    .fetch_all(pool)
    .await?;
    Ok(rows)
}

/// List secrets in a category, newest-first.
pub async fn list_by_category(pool: &SqlitePool, category: &str) -> LocalResult<Vec<VaultSecret>> {
    let rows = sqlx::query_as::<_, VaultSecret>(
        "SELECT * FROM vault_secrets WHERE category = ?1 ORDER BY created_at DESC, id DESC",
    )
    .bind(category)
    .fetch_all(pool)
    .await?;
    Ok(rows)
}

/// Update the ciphertext for an existing secret (rotate). Bumps `updated_at`.
/// Returns the updated row, or `None` if id absent.
pub async fn update_value(
    pool: &SqlitePool,
    id: i64,
    value_encrypted: &str,
) -> LocalResult<Option<VaultSecret>> {
    let row = sqlx::query_as::<_, VaultSecret>(
        r#"
        UPDATE vault_secrets SET
            value_encrypted = ?2,
            updated_at      = strftime('%Y-%m-%dT%H:%M:%fZ','now')
        WHERE id = ?1
        RETURNING *
        "#,
    )
    .bind(id)
    .bind(value_encrypted)
    .fetch_optional(pool)
    .await?;
    if row.is_some() {
        tracing::info!(secret_id = id, "vault secret value rotated");
    }
    Ok(row)
}

/// Update metadata (description/category) only, leaving ciphertext untouched. Bumps `updated_at`.
pub async fn update_meta(
    pool: &SqlitePool,
    id: i64,
    description: Option<&str>,
    category: Option<&str>,
) -> LocalResult<Option<VaultSecret>> {
    let row = sqlx::query_as::<_, VaultSecret>(
        r#"
        UPDATE vault_secrets SET
            description = COALESCE(?2, description),
            category    = COALESCE(?3, category),
            updated_at  = strftime('%Y-%m-%dT%H:%M:%fZ','now')
        WHERE id = ?1
        RETURNING *
        "#,
    )
    .bind(id)
    .bind(description)
    .bind(category)
    .fetch_optional(pool)
    .await?;
    Ok(row)
}

/// Record a use: bump `use_count` and stamp `last_used_at`. No-op if id absent.
pub async fn mark_used(pool: &SqlitePool, id: i64) -> LocalResult<()> {
    sqlx::query(
        r#"
        UPDATE vault_secrets SET
            use_count    = COALESCE(use_count, 0) + 1,
            last_used_at = strftime('%Y-%m-%dT%H:%M:%fZ','now')
        WHERE id = ?1
        "#,
    )
    .bind(id)
    .execute(pool)
    .await?;
    Ok(())
}

/// Hard-delete a secret by id. Returns `true` if a row was removed.
pub async fn delete(pool: &SqlitePool, id: i64) -> LocalResult<bool> {
    let res = sqlx::query("DELETE FROM vault_secrets WHERE id = ?1")
        .bind(id)
        .execute(pool)
        .await?;
    let removed = res.rows_affected() > 0;
    if removed {
        tracing::info!(secret_id = id, "vault secret deleted");
    }
    Ok(removed)
}

/// Hard-delete a secret by its unique `key`. Returns `true` if a row was removed.
pub async fn delete_by_key(pool: &SqlitePool, key: &str) -> LocalResult<bool> {
    let res = sqlx::query("DELETE FROM vault_secrets WHERE key = ?1")
        .bind(key)
        .execute(pool)
        .await?;
    let removed = res.rows_affected() > 0;
    if removed {
        tracing::info!(key = %key, "vault secret deleted by key");
    }
    Ok(removed)
}

impl std::fmt::Debug for VaultSecret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VaultSecret")
            .field("id", &self.id)
            .field("key", &self.key)
            .field("category", &self.category)
            .field("use_count", &self.use_count)
            .field("value_encrypted", &super::REDACTED)
            .finish_non_exhaustive()
    }
}

impl std::fmt::Debug for NewVaultSecret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NewVaultSecret")
            .field("key", &self.key)
            .field("category", &self.category)
            .field("value_encrypted", &super::REDACTED)
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::local::vault::Vault;

    /// Open a fresh keyed SQLCipher DB (migrations create `vault_secrets`).
    async fn pool() -> SqlitePool {
        let dir = Box::leak(Box::new(tempfile::tempdir().unwrap()));
        let v = Vault::load_or_create(dir.path(), false).unwrap();
        crate::local::db::open(&dir.path().join("t.db"), &v.db_key_hex()).await.unwrap()
    }

    #[tokio::test]
    async fn store_persists_ciphertext_verbatim_never_plaintext() {
        let pool = pool().await;

        // The store contract: it receives an ALREADY-sealed ciphertext blob (the handler seals).
        // We hand it a WF1: blob containing no recognizable plaintext and verify it stores/returns
        // exactly that — the store never sees, derives, or stores plaintext.
        let plaintext = "PLAINTEXT-CANARY-shouldnt-be-here";
        let ciphertext = "WF1:c2VhbGVkLW9wYXF1ZS1ibG9i"; // opaque; not the plaintext

        let new = NewVaultSecret {
            key: "API_TOKEN".into(),
            value_encrypted: ciphertext.into(),
            description: Some("token".into()),
            category: Some("tokens".into()),
        };
        let row = insert(&pool, &new).await.unwrap();
        assert!(row.id > 0);
        assert_eq!(row.value_encrypted, ciphertext, "store must persist ciphertext verbatim");
        assert!(!row.value_encrypted.contains(plaintext));

        // Read-back is byte-identical ciphertext; the store never substitutes plaintext.
        let got = get_by_key(&pool, "API_TOKEN").await.unwrap().unwrap();
        assert_eq!(got.value_encrypted, ciphertext);

        // Serializing a listed row exposes the ciphertext column but NEVER any plaintext (the store
        // simply has none). API projection (`api::v1::secrets::meta`) drops the column entirely.
        let listed = list(&pool, None).await.unwrap();
        assert_eq!(listed.len(), 1);
        assert!(!serde_json::to_string(&listed).unwrap().contains(plaintext));

        // Metadata mutation leaves the ciphertext untouched.
        let upd = update_meta(&pool, row.id, Some("renamed"), None).await.unwrap().unwrap();
        assert_eq!(upd.value_encrypted, ciphertext);
        assert_eq!(upd.description.as_deref(), Some("renamed"));

        assert!(delete_by_key(&pool, "API_TOKEN").await.unwrap());
        assert!(get_by_key(&pool, "API_TOKEN").await.unwrap().is_none());
    }

    #[tokio::test]
    async fn upsert_rotates_ciphertext() {
        let pool = pool().await;
        let mut new = NewVaultSecret {
            key: "K".into(),
            value_encrypted: "WF1:first".into(),
            ..Default::default()
        };
        let a = upsert(&pool, &new).await.unwrap();
        new.value_encrypted = "WF1:second".into();
        let b = upsert(&pool, &new).await.unwrap();
        assert_eq!(a.id, b.id, "same key → same row");
        assert_eq!(b.value_encrypted, "WF1:second", "ciphertext rotated in place");
    }
}
