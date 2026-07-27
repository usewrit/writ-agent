//! Store layer for `ai_preview_steps` (0012) — the disk-cheap per-step REPLAY cache for
//! "watch the AI". One row per loop step of an AI session (`kind='ai'`) or concierge mission
//! (`kind='concierge'`): the model's `thought`, a human `action` summary, the page `url`, the run
//! `status`, and a downscaled+deduped keyframe (`screenshot`, raw JPEG bytes; `None` = unchanged from
//! the previous step). Bounded + self-pruning: [`insert`] callers [`trim`] to the most recent N.

use super::super::error::LocalResult;
use sqlx::sqlite::SqlitePool;

/// Keep at most this many steps per session — a long form-fill run caps its own replay footprint.
pub const MAX_STEPS: i64 = 150;
/// Replay keyframe geometry (long edge, px) + JPEG quality — small enough that a full run is a few
/// hundred KB, legible enough to follow what the AI did. See `live_preview::downscale_jpeg`.
pub const KEYFRAME_MAX_EDGE: u32 = 720;
pub const KEYFRAME_QUALITY: u8 = 45;

/// A new replay step to persist.
#[derive(Debug, Clone, Default)]
pub struct NewStep {
    pub kind: String,
    pub ref_id: i64,
    pub step_num: i64,
    pub thought: Option<String>,
    pub action: Option<String>,
    pub url: Option<String>,
    pub status: Option<String>,
    /// Downscaled JPEG bytes, or `None` when identical to the previous step's frame.
    pub screenshot: Option<Vec<u8>>,
}

/// A persisted replay step (screenshot kept as raw bytes; the API base64-encodes at read).
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct Step {
    pub step_num: i64,
    pub thought: Option<String>,
    pub action: Option<String>,
    pub url: Option<String>,
    pub status: Option<String>,
    pub screenshot: Option<Vec<u8>>,
    pub created_at: String,
}

/// Insert one replay step. Best-effort persistence — the caller ignores errors so a replay write
/// never breaks the live run.
pub async fn insert(pool: &SqlitePool, step: &NewStep) -> LocalResult<i64> {
    let id: i64 = sqlx::query_scalar(
        "INSERT INTO ai_preview_steps (kind, ref_id, step_num, thought, action, url, status, screenshot)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8) RETURNING id",
    )
    .bind(&step.kind)
    .bind(step.ref_id)
    .bind(step.step_num)
    .bind(&step.thought)
    .bind(&step.action)
    .bind(&step.url)
    .bind(&step.status)
    .bind(step.screenshot.as_deref())
    .fetch_one(pool)
    .await?;
    Ok(id)
}

/// The next sequential `step_num` for a session (max + 1, or 1 when empty). For callers without a
/// loop counter of their own (e.g. the concierge's per-tool steps).
pub async fn next_step_num(pool: &SqlitePool, kind: &str, ref_id: i64) -> LocalResult<i64> {
    let n: i64 = sqlx::query_scalar(
        "SELECT COALESCE(MAX(step_num), 0) + 1 FROM ai_preview_steps WHERE kind = ?1 AND ref_id = ?2",
    )
    .bind(kind)
    .bind(ref_id)
    .fetch_one(pool)
    .await?;
    Ok(n)
}

/// List a session's replay steps, oldest-first.
pub async fn list_for(pool: &SqlitePool, kind: &str, ref_id: i64) -> LocalResult<Vec<Step>> {
    let rows = sqlx::query_as::<_, Step>(
        "SELECT step_num, thought, action, url, status, screenshot, created_at
         FROM ai_preview_steps WHERE kind = ?1 AND ref_id = ?2 ORDER BY step_num ASC, id ASC",
    )
    .bind(kind)
    .bind(ref_id)
    .fetch_all(pool)
    .await?;
    Ok(rows)
}

/// Delete every replay step for a session (called when the owning session row is deleted).
pub async fn delete_for(pool: &SqlitePool, kind: &str, ref_id: i64) -> LocalResult<u64> {
    let res = sqlx::query("DELETE FROM ai_preview_steps WHERE kind = ?1 AND ref_id = ?2")
        .bind(kind)
        .bind(ref_id)
        .execute(pool)
        .await?;
    Ok(res.rows_affected())
}

/// Retention prune: delete replay keyframes older than `cutoff_rfc3339` (by `created_at`), across ALL
/// kinds (both `ai` and `concierge`). The heavy per-step JPEGs shouldn't outlive the retention window
/// even when the owning session row is kept. Returns rows removed.
pub async fn prune_older_than(pool: &SqlitePool, cutoff_rfc3339: &str) -> LocalResult<u64> {
    let res = sqlx::query("DELETE FROM ai_preview_steps WHERE created_at < ?1")
        .bind(cutoff_rfc3339)
        .execute(pool)
        .await?;
    Ok(res.rows_affected())
}

/// Trim a session's replay to its most recent `keep` steps (drops the oldest). Bounds disk for a run
/// that hits many iterations.
pub async fn trim(pool: &SqlitePool, kind: &str, ref_id: i64, keep: i64) -> LocalResult<u64> {
    let res = sqlx::query(
        "DELETE FROM ai_preview_steps
         WHERE kind = ?1 AND ref_id = ?2
           AND id NOT IN (
             SELECT id FROM ai_preview_steps
             WHERE kind = ?1 AND ref_id = ?2
             ORDER BY step_num DESC, id DESC LIMIT ?3
           )",
    )
    .bind(kind)
    .bind(ref_id)
    .bind(keep.max(1))
    .execute(pool)
    .await?;
    Ok(res.rows_affected())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::local::db;

    async fn pool() -> SqlitePool {
        let dir = Box::leak(Box::new(tempfile::tempdir().unwrap()));
        db::open(&dir.path().join("t.db"), "test-key-preview-steps").await.unwrap()
    }

    #[tokio::test]
    async fn insert_list_dedup_trim_delete() {
        let pool = pool().await;
        // Step 1 with a frame, step 2 with NULL (dedup marker), step 3 with a frame.
        for (n, shot) in [(1i64, Some(vec![1u8, 2, 3])), (2, None), (3, Some(vec![9u8]))] {
            insert(
                &pool,
                &NewStep {
                    kind: "ai".into(),
                    ref_id: 42,
                    step_num: n,
                    thought: Some(format!("thinking {n}")),
                    action: Some("did a thing".into()),
                    url: Some("https://example.com".into()),
                    status: Some("running".into()),
                    screenshot: shot,
                },
            )
            .await
            .unwrap();
        }
        let steps = list_for(&pool, "ai", 42).await.unwrap();
        assert_eq!(steps.len(), 3);
        assert_eq!(steps[0].step_num, 1);
        assert_eq!(steps[0].screenshot.as_deref(), Some(&[1u8, 2, 3][..]));
        assert!(steps[1].screenshot.is_none(), "dedup marker keeps NULL frame");

        // Trim to the most recent 2 → step 1 drops.
        trim(&pool, "ai", 42, 2).await.unwrap();
        let steps = list_for(&pool, "ai", 42).await.unwrap();
        assert_eq!(steps.len(), 2);
        assert_eq!(steps[0].step_num, 2);

        // A different session is untouched.
        assert!(list_for(&pool, "ai", 99).await.unwrap().is_empty());

        delete_for(&pool, "ai", 42).await.unwrap();
        assert!(list_for(&pool, "ai", 42).await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn prune_older_than_removes_by_age_across_kinds() {
        let pool = pool().await;
        for (kind, ref_id) in [("ai", 1i64), ("concierge", 2i64)] {
            insert(
                &pool,
                &NewStep {
                    kind: kind.into(),
                    ref_id,
                    step_num: 1,
                    thought: Some("t".into()),
                    action: None,
                    url: None,
                    status: Some("running".into()),
                    screenshot: Some(vec![1u8]),
                },
            )
            .await
            .unwrap();
        }
        // A cutoff in the past keeps the just-inserted rows.
        assert_eq!(prune_older_than(&pool, "2000-01-01T00:00:00.000Z").await.unwrap(), 0);
        assert_eq!(list_for(&pool, "ai", 1).await.unwrap().len(), 1);
        // A cutoff far in the future purges everything — both kinds.
        assert_eq!(prune_older_than(&pool, "2999-01-01T00:00:00.000Z").await.unwrap(), 2);
        assert!(list_for(&pool, "ai", 1).await.unwrap().is_empty());
        assert!(list_for(&pool, "concierge", 2).await.unwrap().is_empty());
    }
}
