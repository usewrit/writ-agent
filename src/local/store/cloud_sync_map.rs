//! Store layer for the `cloud_sync_map` table (0003_cloud_sync.sql).
//!
//! Each row links a LOCAL entity row (`workflow|persona|monitor`) to the cloud row it was PULLED
//! from (`origin='cloud'`) or PUSHED up to (`origin='local'`). `content_hash` snapshots the
//! normalized recipe at last sync so a later PULL can detect local divergence (the local row was
//! edited after it was pulled) and REPORT it — never silently overwrite — per the directionality
//! LAW. The `(entity_type, cloud_id)` and `(entity_type, local_id)` unique indexes guarantee a
//! single mapping in each direction so a re-pull/re-push is an idempotent upsert.
//!
//! Runtime-checked sqlx only (no compile-time macros). Holds NO secret material (only ids + a
//! non-secret content hash); safe to read/serialize. Errors map into `LocalError` via `?`.

use super::super::error::LocalResult;
use sqlx::sqlite::SqlitePool;

/// One row of the `cloud_sync_map` table.
#[derive(Debug, Clone, sqlx::FromRow, serde::Serialize, serde::Deserialize)]
pub struct SyncMap {
    pub id: i64,
    /// `'workflow' | 'persona' | 'monitor'`.
    pub entity_type: String,
    pub local_id: i64,
    pub cloud_id: String,
    /// Hash of the normalized recipe captured at last sync (divergence detection). `None` for rows
    /// where a hash wasn't computed (e.g. a pushed reference whose content we don't re-hash).
    #[serde(default)]
    pub content_hash: Option<String>,
    /// `'cloud'` (pulled down) | `'local'` (pushed up).
    pub origin: String,
    /// RFC3339 UTC timestamp of the last sync touch.
    pub synced_at: String,
}

/// Upsert a mapping, handling BOTH unique indexes migration 0003 creates.
///
/// `(entity_type, cloud_id)` is refreshed in place via `ON CONFLICT` (so a re-pull/re-push of the same
/// pair is idempotent and keeps the row's `id`). `(entity_type, local_id)` is the second unique index,
/// and it used to be an *unenforced caller obligation* documented in this comment: "callers must
/// ensure the local_id isn't already bound to a DIFFERENT cloud_id". Any caller that got that wrong —
/// re-binding a local row to a different cloud row (re-import, cloud row recreated, a local row reused
/// after its cloud counterpart was deleted) — got a raw `UNIQUE constraint failed` from the driver
/// instead of a sync. A stale binding for this `local_id` is by definition superseded by the one being
/// written, so it is dropped first, in the SAME transaction as the insert.
pub async fn upsert(
    pool: &SqlitePool,
    entity_type: &str,
    local_id: i64,
    cloud_id: &str,
    content_hash: Option<&str>,
    origin: &str,
) -> LocalResult<()> {
    let mut tx = pool.begin().await?;

    // Drop a mapping that binds this local row to a DIFFERENT cloud row (would trip the
    // `(entity_type, local_id)` index). Same-pair re-syncs are untouched and fall to the upsert below,
    // which preserves the existing row.
    let stale = sqlx::query(
        "DELETE FROM cloud_sync_map WHERE entity_type = ?1 AND local_id = ?2 AND cloud_id <> ?3",
    )
    .bind(entity_type)
    .bind(local_id)
    .bind(cloud_id)
    .execute(&mut *tx)
    .await?
    .rows_affected();
    if stale > 0 {
        tracing::info!(
            entity_type,
            local_id,
            new_cloud_id = %cloud_id,
            "cloud_sync_map: re-binding local row (dropped its superseded mapping)"
        );
    }

    sqlx::query(
        r#"
        INSERT INTO cloud_sync_map (entity_type, local_id, cloud_id, content_hash, origin, synced_at)
        VALUES (?1, ?2, ?3, ?4, ?5, strftime('%Y-%m-%dT%H:%M:%fZ','now'))
        ON CONFLICT(entity_type, cloud_id) DO UPDATE SET
            local_id     = excluded.local_id,
            content_hash = excluded.content_hash,
            origin       = excluded.origin,
            synced_at    = excluded.synced_at
        "#,
    )
    .bind(entity_type)
    .bind(local_id)
    .bind(cloud_id)
    .bind(content_hash)
    .bind(origin)
    .execute(&mut *tx)
    .await?;

    tx.commit().await?;
    Ok(())
}

/// Refresh just the `content_hash` (+ `synced_at`) of an existing mapping by `(entity_type,
/// local_id)`. Used after a PULL re-writes a cloud-origin row to record the new normalized hash.
pub async fn set_content_hash(
    pool: &SqlitePool,
    entity_type: &str,
    local_id: i64,
    content_hash: &str,
) -> LocalResult<()> {
    sqlx::query(
        r#"
        UPDATE cloud_sync_map
           SET content_hash = ?3,
               synced_at    = strftime('%Y-%m-%dT%H:%M:%fZ','now')
         WHERE entity_type = ?1 AND local_id = ?2
        "#,
    )
    .bind(entity_type)
    .bind(local_id)
    .bind(content_hash)
    .execute(pool)
    .await?;
    Ok(())
}

/// Look up the mapping for a given cloud row, or `None` if it was never synced.
pub async fn get_by_cloud_id(
    pool: &SqlitePool,
    entity_type: &str,
    cloud_id: &str,
) -> LocalResult<Option<SyncMap>> {
    let row = sqlx::query_as::<_, SyncMap>(
        "SELECT id, entity_type, local_id, cloud_id, content_hash, origin, synced_at
           FROM cloud_sync_map WHERE entity_type = ?1 AND cloud_id = ?2",
    )
    .bind(entity_type)
    .bind(cloud_id)
    .fetch_optional(pool)
    .await?;
    Ok(row)
}

/// Look up the mapping for a given local row, or `None` if it was never synced (locally-authored).
pub async fn get_by_local_id(
    pool: &SqlitePool,
    entity_type: &str,
    local_id: i64,
) -> LocalResult<Option<SyncMap>> {
    let row = sqlx::query_as::<_, SyncMap>(
        "SELECT id, entity_type, local_id, cloud_id, content_hash, origin, synced_at
           FROM cloud_sync_map WHERE entity_type = ?1 AND local_id = ?2",
    )
    .bind(entity_type)
    .bind(local_id)
    .fetch_optional(pool)
    .await?;
    Ok(row)
}

/// All mappings for an entity type, keyed by `local_id` for an O(1) join against a freshly-listed
/// set of local rows (used by the `items` endpoint).
pub async fn list_by_type(pool: &SqlitePool, entity_type: &str) -> LocalResult<Vec<SyncMap>> {
    let rows = sqlx::query_as::<_, SyncMap>(
        "SELECT id, entity_type, local_id, cloud_id, content_hash, origin, synced_at
           FROM cloud_sync_map WHERE entity_type = ?1",
    )
    .bind(entity_type)
    .fetch_all(pool)
    .await?;
    Ok(rows)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::local::db;

    async fn pool() -> SqlitePool {
        let dir = Box::leak(Box::new(tempfile::tempdir().unwrap()));
        db::open(&dir.path().join("t.db"), "test-key-csm").await.unwrap()
    }

    #[tokio::test]
    async fn upsert_get_and_rehash() {
        let pool = pool().await;

        // Insert a cloud-origin mapping.
        upsert(&pool, "workflow", 1, "wf_cloud_1", Some("hashA"), "cloud").await.unwrap();
        let m = get_by_cloud_id(&pool, "workflow", "wf_cloud_1").await.unwrap().unwrap();
        assert_eq!(m.local_id, 1);
        assert_eq!(m.origin, "cloud");
        assert_eq!(m.content_hash.as_deref(), Some("hashA"));

        // Re-pull the same cloud row: idempotent upsert (no duplicate row).
        upsert(&pool, "workflow", 1, "wf_cloud_1", Some("hashB"), "cloud").await.unwrap();
        let all = list_by_type(&pool, "workflow").await.unwrap();
        assert_eq!(all.len(), 1, "re-pull upserts, never duplicates");
        assert_eq!(all[0].content_hash.as_deref(), Some("hashB"));

        // Rehash after a pull rewrite.
        set_content_hash(&pool, "workflow", 1, "hashC").await.unwrap();
        let m = get_by_local_id(&pool, "workflow", 1).await.unwrap().unwrap();
        assert_eq!(m.content_hash.as_deref(), Some("hashC"));

        // A different entity type is independent.
        upsert(&pool, "persona", 1, "p_cloud_9", None, "local").await.unwrap();
        assert!(get_by_local_id(&pool, "persona", 1).await.unwrap().is_some());
        assert!(get_by_local_id(&pool, "monitor", 1).await.unwrap().is_none());
    }

    /// Migration 0003 makes `(entity_type, local_id)` unique too. Re-binding a local row to a NEW
    /// cloud row used to hit that index and surface as a raw driver error.
    #[tokio::test]
    async fn rebinding_a_local_row_to_a_new_cloud_row_replaces_the_stale_mapping() {
        let pool = pool().await;
        upsert(&pool, "workflow", 7, "wf_old", Some("h1"), "cloud").await.unwrap();

        // The cloud row was recreated (new id) for the same local workflow.
        upsert(&pool, "workflow", 7, "wf_new", Some("h2"), "cloud")
            .await
            .expect("must not trip UNIQUE(entity_type, local_id)");

        let all = list_by_type(&pool, "workflow").await.unwrap();
        assert_eq!(all.len(), 1, "exactly one mapping per local row: {all:?}");
        assert_eq!(all[0].cloud_id, "wf_new");
        assert_eq!(all[0].content_hash.as_deref(), Some("h2"));
        assert!(get_by_cloud_id(&pool, "workflow", "wf_old").await.unwrap().is_none());
    }

    /// The mirror case: a cloud row moving to a different local row still goes through the
    /// `(entity_type, cloud_id)` upsert, and does not leave the old local row mapped.
    #[tokio::test]
    async fn rebinding_a_cloud_row_to_a_new_local_row_leaves_one_mapping() {
        let pool = pool().await;
        upsert(&pool, "monitor", 1, "m_cloud", None, "cloud").await.unwrap();
        upsert(&pool, "monitor", 2, "m_cloud", None, "cloud").await.unwrap();

        let all = list_by_type(&pool, "monitor").await.unwrap();
        assert_eq!(all.len(), 1, "{all:?}");
        assert_eq!(all[0].local_id, 2);
        assert!(get_by_local_id(&pool, "monitor", 1).await.unwrap().is_none());
    }
}
