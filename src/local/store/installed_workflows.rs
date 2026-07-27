//! Store layer for the `installed_workflows` table (0004_marketplace_installs.sql).
//!
//! One row per installed marketplace listing. The row carries listing METADATA (title/creator/price/
//! free flag/input schema) plus the `sealed_recipe` — the listing's frozen recipe encrypted with this
//! agent's per-agent Fernet channel key (and optionally vault-field-wrapped on top). The PLAINTEXT
//! recipe is NEVER stored here; the executor unseals the blob IN MEMORY at run time.
//!
//! SECURITY (the never-trust-a-BYO-agent rule + marketplace protected-executor invariants):
//! - The `sealed_recipe` is the ONLY representation of the recipe persisted; it is opaque ciphertext.
//! - [`list`] returns METADATA ONLY ([`InstalledMeta`]) and NEVER includes `sealed_recipe` — so no
//!   local REST/IPC surface that lists installs can leak the sealed blob (let alone plaintext steps).
//! - [`get_by_slug`] returns the full row ([`InstalledWorkflow`]) including `sealed_recipe`; it is for
//!   the in-daemon executor ONLY and must NEVER be serialized back over the loopback API.
//! - No field here is logged (the sealed blob is opaque, but we still avoid `tracing`-ing it).
//!
//! Runtime-checked sqlx only (no compile-time macros). Errors map into `LocalError` via `?`.
//!
//! Net-new Rust in this crate (marketplace protected-executor — daemon stage 1).

use super::super::error::LocalResult;
use sqlx::sqlite::SqlitePool;

/// Full `installed_workflows` row, INCLUDING the sealed recipe blob.
///
/// SECURITY: holds `sealed_recipe` (opaque ciphertext). This struct is NOT `Serialize` on purpose —
/// it must never be returned over the loopback API. It is for the in-daemon executor only. Use
/// [`InstalledMeta`] (metadata-only, `Serialize`) for anything the UI/IPC can see.
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct InstalledWorkflow {
    pub id: i64,
    pub slug: String,
    pub listing_title: Option<String>,
    pub creator: Option<String>,
    /// 1 = free listing (run locally, no charge) | 0 = paid (metered).
    pub is_free: bool,
    /// Creator price-per-run in micro-USD (paid listings; reflection only). `None` for free.
    pub price_micros: Option<i64>,
    /// Cloud proxy workflow id created by the install endpoint.
    pub proxy_cloud_id: Option<String>,
    /// channel_key-Fernet-sealed (then optionally vault-sealed) recipe blob. OPAQUE. Never logged,
    /// never returned over the API; unsealed in memory by the executor only.
    pub sealed_recipe: String,
    /// JSON: BYO input/secret slots the consumer must attach. Metadata.
    pub input_schema: Option<String>,
    /// JSON (0017): the CONSUMER's saved attachment choices — `{"secrets":{slot->vault KEY NAME},
    /// "persona_id":N,"persona_none":bool,"inputs":{non-secret defaults}}`. Names/ids only for
    /// secrets/personas (values stay in their ciphertext stores). Executor-side; not in
    /// [`InstalledMeta`].
    #[sqlx(default)]
    pub bindings: Option<String>,
    pub installed_at: String,
    pub last_run_at: Option<String>,
}

/// Metadata-only projection of an install — SAFE to serialize over the loopback API / to the UI.
///
/// Deliberately OMITS `sealed_recipe`. The `SELECT` in [`list`]/[`get_meta`] never reads that column,
/// so the sealed blob cannot leak through this type even by accident.
#[derive(Debug, Clone, sqlx::FromRow, serde::Serialize)]
pub struct InstalledMeta {
    pub id: i64,
    pub slug: String,
    pub listing_title: Option<String>,
    pub creator: Option<String>,
    pub is_free: bool,
    pub price_micros: Option<i64>,
    pub proxy_cloud_id: Option<String>,
    pub input_schema: Option<String>,
    pub installed_at: String,
    pub last_run_at: Option<String>,
}

/// Owned values for an upsert. Borrows would force lifetime juggling at the call site (the executor
/// builds these from cloud responses), so this takes owned fields.
#[derive(Debug, Clone)]
pub struct NewInstall {
    pub slug: String,
    pub listing_title: Option<String>,
    pub creator: Option<String>,
    pub is_free: bool,
    pub price_micros: Option<i64>,
    pub proxy_cloud_id: Option<String>,
    /// The sealed recipe blob (channel_key-Fernet, optionally vault-wrapped). OPAQUE.
    pub sealed_recipe: String,
    pub input_schema: Option<String>,
}

/// Upsert an install keyed on `slug`. On conflict (a re-install / recipe refresh of the same listing)
/// every field except `installed_at` is refreshed, and `last_run_at` is preserved. `installed_at`
/// keeps the ORIGINAL first-install timestamp (the DEFAULT only applies on first insert).
///
/// NOTE: the `sealed_recipe` value is bound directly; it is opaque ciphertext and is never logged.
pub async fn upsert(pool: &SqlitePool, install: &NewInstall) -> LocalResult<()> {
    sqlx::query(
        r#"
        INSERT INTO installed_workflows
            (slug, listing_title, creator, is_free, price_micros, proxy_cloud_id, sealed_recipe, input_schema)
        VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)
        ON CONFLICT(slug) DO UPDATE SET
            listing_title  = excluded.listing_title,
            creator        = excluded.creator,
            is_free        = excluded.is_free,
            price_micros   = excluded.price_micros,
            proxy_cloud_id = excluded.proxy_cloud_id,
            sealed_recipe  = excluded.sealed_recipe,
            input_schema   = excluded.input_schema
        "#,
    )
    .bind(&install.slug)
    .bind(&install.listing_title)
    .bind(&install.creator)
    .bind(install.is_free)
    .bind(install.price_micros)
    .bind(&install.proxy_cloud_id)
    .bind(&install.sealed_recipe)
    .bind(&install.input_schema)
    .execute(pool)
    .await?;
    tracing::debug!(slug = %install.slug, is_free = install.is_free, "marketplace install upserted");
    Ok(())
}

/// Fetch the FULL install row (including `sealed_recipe`) for the executor. `None` if not installed.
///
/// SECURITY: the returned struct carries the sealed blob — for the in-daemon executor ONLY. Do NOT
/// serialize it back over the loopback API; use [`get_meta`]/[`list`] for anything UI-facing.
pub async fn get_by_slug(pool: &SqlitePool, slug: &str) -> LocalResult<Option<InstalledWorkflow>> {
    let row = sqlx::query_as::<_, InstalledWorkflow>(
        "SELECT id, slug, listing_title, creator, is_free, price_micros, proxy_cloud_id,
                sealed_recipe, input_schema, bindings, installed_at, last_run_at
           FROM installed_workflows WHERE slug = ?1",
    )
    .bind(slug)
    .fetch_optional(pool)
    .await?;
    Ok(row)
}

/// Persist (or clear) the consumer's BINDINGS JSON for an install (0017). Names/ids only for
/// secrets/personas — never secret values. Returns `true` if the row existed.
pub async fn set_bindings(pool: &SqlitePool, slug: &str, bindings: Option<&str>) -> LocalResult<bool> {
    let res = sqlx::query("UPDATE installed_workflows SET bindings = ?2 WHERE slug = ?1")
        .bind(slug)
        .bind(bindings)
        .execute(pool)
        .await?;
    Ok(res.rows_affected() > 0)
}

/// Replace an install's sealed recipe blob (opaque ciphertext, never logged). Used by the
/// executor's SELF-HEAL when a re-link minted a new channel key and the stored seal can no longer
/// decrypt — the cloud re-seals for the current key and this persists it. Returns `true` if the
/// row existed.
pub async fn set_sealed_recipe(pool: &SqlitePool, slug: &str, sealed: &str) -> LocalResult<bool> {
    let res = sqlx::query("UPDATE installed_workflows SET sealed_recipe = ?2 WHERE slug = ?1")
        .bind(slug)
        .bind(sealed)
        .execute(pool)
        .await?;
    Ok(res.rows_affected() > 0)
}

/// Fetch the METADATA-ONLY projection for one install (no sealed blob). `None` if not installed.
/// Safe to return over the loopback API.
pub async fn get_meta(pool: &SqlitePool, slug: &str) -> LocalResult<Option<InstalledMeta>> {
    let row = sqlx::query_as::<_, InstalledMeta>(
        "SELECT id, slug, listing_title, creator, is_free, price_micros, proxy_cloud_id,
                input_schema, installed_at, last_run_at
           FROM installed_workflows WHERE slug = ?1",
    )
    .bind(slug)
    .fetch_optional(pool)
    .await?;
    Ok(row)
}

/// List ALL installs as METADATA ONLY (no `sealed_recipe`), most-recently-installed first. This is
/// the projection the `/v1/cloud/marketplace/installs` endpoint returns.
pub async fn list(pool: &SqlitePool) -> LocalResult<Vec<InstalledMeta>> {
    let rows = sqlx::query_as::<_, InstalledMeta>(
        "SELECT id, slug, listing_title, creator, is_free, price_micros, proxy_cloud_id,
                input_schema, installed_at, last_run_at
           FROM installed_workflows ORDER BY installed_at DESC, id DESC",
    )
    .fetch_all(pool)
    .await?;
    Ok(rows)
}

/// Stamp `last_run_at = now` for an install after a local run. Returns `true` if the row existed.
pub async fn set_last_run(pool: &SqlitePool, slug: &str) -> LocalResult<bool> {
    let res = sqlx::query(
        "UPDATE installed_workflows
            SET last_run_at = strftime('%Y-%m-%dT%H:%M:%fZ','now')
          WHERE slug = ?1",
    )
    .bind(slug)
    .execute(pool)
    .await?;
    Ok(res.rows_affected() > 0)
}

/// Remove an install by slug (e.g. uninstall). Returns `true` if a row was removed.
pub async fn delete(pool: &SqlitePool, slug: &str) -> LocalResult<bool> {
    let res = sqlx::query("DELETE FROM installed_workflows WHERE slug = ?1")
        .bind(slug)
        .execute(pool)
        .await?;
    Ok(res.rows_affected() > 0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::local::db;

    async fn pool() -> SqlitePool {
        let dir = Box::leak(Box::new(tempfile::tempdir().unwrap()));
        db::open(&dir.path().join("t.db"), "test-key-installed").await.unwrap()
    }

    fn sample(slug: &str, is_free: bool) -> NewInstall {
        NewInstall {
            slug: slug.into(),
            listing_title: Some("Cool Workflow".into()),
            creator: Some("acme".into()),
            is_free,
            price_micros: if is_free { None } else { Some(50_000) },
            proxy_cloud_id: Some("wf_proxy_1".into()),
            sealed_recipe: "gAAAAA_sealed_blob".into(),
            input_schema: Some(r#"{"inputs":[{"name":"q"}]}"#.into()),
        }
    }

    #[tokio::test]
    async fn upsert_get_list_and_last_run() {
        let pool = pool().await;

        // Insert a paid install.
        upsert(&pool, &sample("cool-wf", false)).await.unwrap();

        // Full row (executor view) carries the sealed blob.
        let full = get_by_slug(&pool, "cool-wf").await.unwrap().unwrap();
        assert_eq!(full.slug, "cool-wf");
        assert!(!full.is_free);
        assert_eq!(full.price_micros, Some(50_000));
        assert_eq!(full.sealed_recipe, "gAAAAA_sealed_blob");
        assert!(full.last_run_at.is_none());

        // Metadata view exists and does NOT expose the sealed blob (it has no such field).
        let meta = get_meta(&pool, "cool-wf").await.unwrap().unwrap();
        assert_eq!(meta.slug, "cool-wf");
        assert_eq!(meta.listing_title.as_deref(), Some("Cool Workflow"));

        // Metadata serialization must NOT contain the sealed blob.
        let json = serde_json::to_string(&meta).unwrap();
        assert!(!json.contains("sealed"), "metadata JSON must not leak the sealed recipe");

        // last_run stamp.
        assert!(set_last_run(&pool, "cool-wf").await.unwrap());
        let after = get_meta(&pool, "cool-wf").await.unwrap().unwrap();
        assert!(after.last_run_at.is_some());

        // A second install + list ordering (metadata only).
        upsert(&pool, &sample("free-wf", true)).await.unwrap();
        let all = list(&pool).await.unwrap();
        assert_eq!(all.len(), 2);
        // The free one has no price.
        let free = all.iter().find(|m| m.slug == "free-wf").unwrap();
        assert!(free.is_free);
        assert!(free.price_micros.is_none());
    }

    #[tokio::test]
    async fn upsert_is_idempotent_and_refreshes_blob() {
        let pool = pool().await;
        upsert(&pool, &sample("wf", false)).await.unwrap();

        // Stamp a run so we can prove the upsert preserves last_run_at.
        set_last_run(&pool, "wf").await.unwrap();
        let before = get_meta(&pool, "wf").await.unwrap().unwrap();
        assert!(before.last_run_at.is_some());

        // Re-install with a NEW sealed blob + flipped pricing.
        let mut updated = sample("wf", true);
        updated.sealed_recipe = "gAAAAA_new_blob".into();
        upsert(&pool, &updated).await.unwrap();

        let all = list(&pool).await.unwrap();
        assert_eq!(all.len(), 1, "re-install upserts, never duplicates");

        let full = get_by_slug(&pool, "wf").await.unwrap().unwrap();
        assert_eq!(full.sealed_recipe, "gAAAAA_new_blob", "sealed blob refreshed");
        assert!(full.is_free, "pricing refreshed");

        // last_run_at survives the re-install (DO UPDATE does not touch it).
        let after = get_meta(&pool, "wf").await.unwrap().unwrap();
        assert_eq!(after.last_run_at, before.last_run_at, "last_run_at preserved across re-install");
        // installed_at also unchanged.
        assert_eq!(after.installed_at, before.installed_at, "installed_at preserved across re-install");
    }

    #[tokio::test]
    async fn delete_and_absent_lookups() {
        let pool = pool().await;
        assert!(get_by_slug(&pool, "nope").await.unwrap().is_none());
        assert!(get_meta(&pool, "nope").await.unwrap().is_none());
        assert!(!set_last_run(&pool, "nope").await.unwrap());
        assert!(!delete(&pool, "nope").await.unwrap());

        upsert(&pool, &sample("wf", true)).await.unwrap();
        assert!(delete(&pool, "wf").await.unwrap());
        assert!(get_by_slug(&pool, "wf").await.unwrap().is_none());
    }
}
