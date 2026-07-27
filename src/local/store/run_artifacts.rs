//! Store layer for the `run_artifacts` table (0001_init.sql §2) — screenshots/downloads/extracted
//! files/diffs produced by a run.
//!
//! Runtime-checked sqlx only. `file_id` is a nullable TEXT handle into `stored_files` (the bytes
//! live age-encrypted under `~/.writ/files`); `path` is an alternative on-disk pointer. `meta` is
//! JSON-TEXT — callers serde it. Artifacts are immutable once written (no `update`).

use super::super::error::{LocalError, LocalResult};
use sqlx::sqlite::SqlitePool;
use sqlx::Row as _;

/// A full `run_artifacts` row.
#[derive(Debug, Clone, sqlx::FromRow, serde::Serialize, serde::Deserialize)]
pub struct RunArtifact {
    pub id: i64,
    pub run_id: i64,
    pub kind: String,
    #[serde(default)]
    pub step_index: Option<i64>,
    /// TEXT handle into `stored_files` (`file_<hex>`), or NULL when only `path` is used.
    #[serde(default)]
    pub file_id: Option<String>,
    #[serde(default)]
    pub path: Option<String>,
    #[serde(default)]
    pub content_type: Option<String>,
    #[serde(default)]
    pub meta: Option<String>,
    pub created_at: String,
}

/// Caller-supplied fields for a new artifact. `kind` is required
/// (`screenshot|download|extracted_file|diff`); the rest are optional pointers/metadata.
#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct NewRunArtifact {
    pub run_id: i64,
    pub kind: String,
    #[serde(default)]
    pub step_index: Option<i64>,
    #[serde(default)]
    pub file_id: Option<String>,
    #[serde(default)]
    pub path: Option<String>,
    #[serde(default)]
    pub content_type: Option<String>,
    /// JSON-TEXT the caller has already serialized.
    #[serde(default)]
    pub meta: Option<String>,
}

const SELECT_COLS: &str =
    "id, run_id, kind, step_index, file_id, path, content_type, meta, created_at";

/// Insert an artifact and return its full materialized row.
pub async fn insert(pool: &SqlitePool, new: &NewRunArtifact) -> LocalResult<RunArtifact> {
    let id: i64 = sqlx::query(
        "INSERT INTO run_artifacts 
         (run_id, kind, step_index, file_id, path, content_type, meta) 
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7) 
         RETURNING id",
    )
    .bind(new.run_id)
    .bind(&new.kind)
    .bind(new.step_index)
    .bind(&new.file_id)
    .bind(&new.path)
    .bind(&new.content_type)
    .bind(&new.meta)
    .fetch_one(pool)
    .await?
    .try_get(0)?;

    tracing::debug!(artifact_id = id, run_id = new.run_id, kind = %new.kind, "run artifact recorded");
    get_by_id(pool, id)
        .await?
        .ok_or_else(|| LocalError::Internal("run artifact vanished after insert".into()))
}

/// Fetch one artifact by id.
pub async fn get_by_id(pool: &SqlitePool, id: i64) -> LocalResult<Option<RunArtifact>> {
    let row = sqlx::query_as::<_, RunArtifact>(&format!(
        "SELECT {SELECT_COLS} FROM run_artifacts WHERE id = ?1"
    ))
    .bind(id)
    .fetch_optional(pool)
    .await?;
    Ok(row)
}

/// List artifacts for one run, oldest-first (capture order: ascending id), capped at `limit`.
pub async fn list_by_run(pool: &SqlitePool, run_id: i64, limit: i64) -> LocalResult<Vec<RunArtifact>> {
    let limit = limit.clamp(1, 1000);
    let rows = sqlx::query_as::<_, RunArtifact>(&format!(
        "SELECT {SELECT_COLS} FROM run_artifacts WHERE run_id = ?1 ORDER BY id ASC LIMIT ?2"
    ))
    .bind(run_id)
    .bind(limit)
    .fetch_all(pool)
    .await?;
    Ok(rows)
}

/// List artifacts for one run filtered by `kind`, oldest-first, capped at `limit`.
pub async fn list_by_run_kind(
    pool: &SqlitePool,
    run_id: i64,
    kind: &str,
    limit: i64,
) -> LocalResult<Vec<RunArtifact>> {
    let limit = limit.clamp(1, 1000);
    let rows = sqlx::query_as::<_, RunArtifact>(&format!(
        "SELECT {SELECT_COLS} FROM run_artifacts WHERE run_id = ?1 AND kind = ?2 
         ORDER BY id ASC LIMIT ?3"
    ))
    .bind(run_id)
    .bind(kind)
    .bind(limit)
    .fetch_all(pool)
    .await?;
    Ok(rows)
}

/// Delete one artifact row. Returns whether a row was removed.
pub async fn delete(pool: &SqlitePool, id: i64) -> LocalResult<bool> {
    let res = sqlx::query("DELETE FROM run_artifacts WHERE id = ?1")
        .bind(id)
        .execute(pool)
        .await?;
    Ok(res.rows_affected() > 0)
}

/// Delete all artifacts for a run (e.g. when pruning history); returns the number removed.
pub async fn delete_for_run(pool: &SqlitePool, run_id: i64) -> LocalResult<u64> {
    let res = sqlx::query("DELETE FROM run_artifacts WHERE run_id = ?1")
        .bind(run_id)
        .execute(pool)
        .await?;
    Ok(res.rows_affected())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::local::db;
    use crate::local::store::runs::{self, NewRun};
    use crate::local::store::workflows::{self, NewWorkflow};

    async fn pool() -> SqlitePool {
        let dir = Box::leak(Box::new(tempfile::tempdir().unwrap()));
        db::open(&dir.path().join("t.db"), "test-key-art").await.unwrap()
    }

    #[tokio::test]
    async fn insert_list_delete() {
        let pool = pool().await;
        let wf = workflows::insert(&pool, &NewWorkflow { name: "wf".into(), ..Default::default() })
            .await
            .unwrap();
        let run = runs::insert(&pool, &NewRun { workflow_id: Some(wf.id), ..Default::default() })
            .await
            .unwrap();

        let a = insert(
            &pool,
            &NewRunArtifact {
                run_id: run.id,
                kind: "screenshot".into(),
                step_index: Some(0),
                content_type: Some("image/png".into()),
                meta: Some(r#"{\"w\":800}"#.into()),
                ..Default::default()
            },
        )
        .await
        .unwrap();
        assert!(a.id > 0);
        assert_eq!(a.kind, "screenshot");
        assert_eq!(a.content_type.as_deref(), Some("image/png"));

        let _b = insert(
            &pool,
            &NewRunArtifact { run_id: run.id, kind: "diff".into(), ..Default::default() },
        )
        .await
        .unwrap();

        assert_eq!(list_by_run(&pool, run.id, 50).await.unwrap().len(), 2);
        assert_eq!(list_by_run_kind(&pool, run.id, "screenshot", 50).await.unwrap().len(), 1);
        assert!(get_by_id(&pool, a.id).await.unwrap().is_some());

        assert!(delete(&pool, a.id).await.unwrap());
        assert_eq!(list_by_run(&pool, run.id, 50).await.unwrap().len(), 1);
        assert_eq!(delete_for_run(&pool, run.id).await.unwrap(), 1);
        assert_eq!(list_by_run(&pool, run.id, 50).await.unwrap().len(), 0);
    }

    #[tokio::test]
    async fn cascade_on_run_delete() {
        let pool = pool().await;
        let wf = workflows::insert(&pool, &NewWorkflow { name: "wf".into(), ..Default::default() })
            .await
            .unwrap();
        let run = runs::insert(&pool, &NewRun { workflow_id: Some(wf.id), ..Default::default() })
            .await
            .unwrap();
        let a = insert(
            &pool,
            &NewRunArtifact { run_id: run.id, kind: "download".into(), ..Default::default() },
        )
        .await
        .unwrap();

        assert!(runs::delete(&pool, run.id).await.unwrap());
        // ON DELETE CASCADE removed the artifact.
        assert!(get_by_id(&pool, a.id).await.unwrap().is_none());
    }
}
