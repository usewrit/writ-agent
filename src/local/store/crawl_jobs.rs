//! Store layer for the `crawl_jobs` table (0018_crawl_jobs.sql) — the durable control-plane record
//! for one Dragnet whole-site crawl running LOCALLY on this machine.
//!
//! Runtime-checked sqlx only. A crawl starts in `status='queued'` (via [`insert`]), advances through
//! `mapping`→`crawling` with the counter helpers below as the in-process worker pool drains the
//! frontier, and is finalized to a terminal state (`completed|failed|cancelled`) via [`finalize`].
//! `include_paths`/`exclude_paths`/`extract_schema` are JSON-TEXT — callers serde them. Timestamps
//! are TEXT RFC3339 UTC (matches 0008_concierge_sessions.sql).

use super::super::error::{LocalError, LocalResult};
use sqlx::sqlite::SqlitePool;
use sqlx::Row as _;

/// A full `crawl_jobs` row.
#[derive(Debug, Clone, sqlx::FromRow, serde::Serialize, serde::Deserialize)]
pub struct CrawlJob {
    pub id: i64,
    pub name: String,
    pub seed_url: String,
    /// JSON-TEXT array of path regexes (allowlist).
    pub include_paths: String,
    /// JSON-TEXT array of path regexes (denylist).
    pub exclude_paths: String,
    pub max_depth: i64,
    /// boolean as i64 0/1
    pub same_domain: i64,
    /// boolean as i64 0/1
    pub allow_subdomains: i64,
    /// markdown | schema
    pub extract_mode: String,
    #[serde(default)]
    pub extract_schema: Option<String>,
    /// JSON-TEXT content-selection spec (preset/include_comments/exclude_selectors/…), or NULL for
    /// the engine default. Honored by `build_config` → the extractor's content selection.
    #[serde(default)]
    pub content_spec: Option<String>,
    #[serde(default)]
    pub persona_id: Option<i64>,
    /// boolean as i64 0/1
    pub respect_robots: i64,
    pub delay_ms: i64,
    pub max_concurrent: i64,
    pub page_budget: i64,
    #[serde(default)]
    pub workflow_id: Option<i64>,
    #[serde(default)]
    pub concierge_session_id: Option<i64>,
    /// Saved [`super::crawl_definitions::CrawlDefinition`] this run was launched from, or NULL for an
    /// ad-hoc crawl started straight from the wizard (every pre-0024 row).
    #[serde(default)]
    pub definition_id: Option<i64>,
    pub status: String,
    pub pages_discovered: i64,
    pub pages_done: i64,
    pub pages_failed: i64,
    pub pages_skipped: i64,
    pub workers_active: i64,
    pub current_depth: i64,
    #[serde(default)]
    pub error: Option<String>,
    pub cancel_requested: i64,
    pub created_at: String,
    #[serde(default)]
    pub updated_at: Option<String>,
    #[serde(default)]
    pub started_at: Option<String>,
    #[serde(default)]
    pub completed_at: Option<String>,
}

impl CrawlJob {
    /// Terminal states never re-enter the loop.
    pub fn is_terminal(&self) -> bool {
        matches!(self.status.as_str(), "completed" | "failed" | "cancelled")
    }
}

/// Caller-supplied fields to start a crawl. Anything omitted falls to the column default.
#[derive(Debug, Clone, Default)]
pub struct NewCrawlJob {
    pub name: String,
    pub seed_url: String,
    /// JSON-TEXT array already serialized by the caller (`[]` when omitted).
    pub include_paths: Option<String>,
    pub exclude_paths: Option<String>,
    pub max_depth: Option<i64>,
    pub same_domain: Option<i64>,
    pub allow_subdomains: Option<i64>,
    pub extract_mode: Option<String>,
    pub extract_schema: Option<String>,
    /// JSON-TEXT content-selection spec, already serialized by the caller (NULL = engine default).
    pub content_spec: Option<String>,
    pub persona_id: Option<i64>,
    pub respect_robots: Option<i64>,
    pub delay_ms: Option<i64>,
    pub max_concurrent: Option<i64>,
    pub page_budget: Option<i64>,
    pub concierge_session_id: Option<i64>,
}

const SELECT_COLS: &str = "id, name, seed_url, include_paths, exclude_paths, max_depth, same_domain,
    allow_subdomains, extract_mode, extract_schema, content_spec, persona_id, respect_robots, delay_ms,
    max_concurrent, page_budget, workflow_id, concierge_session_id, definition_id, status, pages_discovered,
    pages_done, pages_failed, pages_skipped, workers_active, current_depth, error, cancel_requested,
    created_at, updated_at, started_at, completed_at";

/// The column list a `CrawlJob` needs, for sibling stores that select the same row shape.
///
/// Exposed as a function rather than making the const public so there stays exactly ONE list: a
/// column added here reaches every query, instead of the next reader hand-copying a list that then
/// drifts (the `SELECT_COLS` divergence that has bitten the get-vs-list pair before).
pub fn select_cols() -> &'static str {
    SELECT_COLS
}

/// Start a crawl (`status='queued'`). Returns the full row.
pub async fn insert(pool: &SqlitePool, new: &NewCrawlJob) -> LocalResult<CrawlJob> {
    let id: i64 = sqlx::query(
        r#"
        INSERT INTO crawl_jobs
            (name, seed_url, include_paths, exclude_paths, max_depth, same_domain, allow_subdomains,
             extract_mode, extract_schema, content_spec, persona_id, respect_robots, delay_ms,
             max_concurrent, page_budget, concierge_session_id, status)
        VALUES
            (?1, ?2, COALESCE(?3, '[]'), COALESCE(?4, '[]'), COALESCE(?5, 3), COALESCE(?6, 1),
             COALESCE(?7, 1), COALESCE(?8, 'markdown'), ?9, ?10, ?11, COALESCE(?12, 1), COALESCE(?13, 250),
             COALESCE(?14, 4), COALESCE(?15, 500), ?16, 'queued')
        RETURNING id
        "#,
    )
    .bind(&new.name)
    .bind(&new.seed_url)
    .bind(new.include_paths.as_deref())
    .bind(new.exclude_paths.as_deref())
    .bind(new.max_depth)
    .bind(new.same_domain)
    .bind(new.allow_subdomains)
    .bind(new.extract_mode.as_deref())
    .bind(new.extract_schema.as_deref())
    .bind(new.content_spec.as_deref())
    .bind(new.persona_id)
    .bind(new.respect_robots)
    .bind(new.delay_ms)
    .bind(new.max_concurrent)
    .bind(new.page_budget)
    .bind(new.concierge_session_id)
    .fetch_one(pool)
    .await?
    .try_get(0)?;

    tracing::info!(crawl_id = id, seed = %new.seed_url, "crawl created");
    get_by_id(pool, id)
        .await?
        .ok_or_else(|| LocalError::Internal("crawl_job vanished after insert".into()))
}

/// Fetch one crawl by id.
pub async fn get_by_id(pool: &SqlitePool, id: i64) -> LocalResult<Option<CrawlJob>> {
    let row = sqlx::query_as::<_, CrawlJob>(&format!(
        "SELECT {SELECT_COLS} FROM crawl_jobs WHERE id = ?1"
    ))
    .bind(id)
    .fetch_optional(pool)
    .await?;
    Ok(row)
}

/// List crawls newest-first, capped at `limit`.
pub async fn list(pool: &SqlitePool, limit: i64) -> LocalResult<Vec<CrawlJob>> {
    let limit = limit.clamp(1, 1000);
    let rows = sqlx::query_as::<_, CrawlJob>(&format!(
        "SELECT {SELECT_COLS} FROM crawl_jobs ORDER BY created_at DESC, id DESC LIMIT ?1"
    ))
    .bind(limit)
    .fetch_all(pool)
    .await?;
    Ok(rows)
}

/// Bind the synthetic per-crawl workflow the page datasets aggregate under.
pub async fn set_workflow_id(pool: &SqlitePool, id: i64, workflow_id: i64) -> LocalResult<()> {
    sqlx::query(
        "UPDATE crawl_jobs SET workflow_id = ?2, updated_at = strftime('%Y-%m-%dT%H:%M:%fZ','now') WHERE id = ?1",
    )
    .bind(id)
    .bind(workflow_id)
    .execute(pool)
    .await?;
    Ok(())
}

/// Delete a crawl row. Returns true if a row was removed. The caller is expected to
/// have verified the crawl is terminal (a live crawl must be stopped first).
pub async fn delete(pool: &SqlitePool, id: i64) -> LocalResult<bool> {
    let res = sqlx::query("DELETE FROM crawl_jobs WHERE id = ?1")
        .bind(id)
        .execute(pool)
        .await?;
    Ok(res.rows_affected() > 0)
}

/// Move a crawl into a live status, stamping `started_at` the first time it leaves `queued`.
pub async fn set_status(pool: &SqlitePool, id: i64, status: &str) -> LocalResult<()> {
    sqlx::query(
        "UPDATE crawl_jobs SET
            status = ?2,
            started_at = COALESCE(started_at, CASE WHEN ?2 IN ('mapping','crawling') THEN strftime('%Y-%m-%dT%H:%M:%fZ','now') ELSE started_at END),
            updated_at = strftime('%Y-%m-%dT%H:%M:%fZ','now')
         WHERE id = ?1",
    )
    .bind(id)
    .bind(status)
    .execute(pool)
    .await?;
    Ok(())
}

/// The live counter snapshot the crawl loop pushes each time it makes progress. Discovered/done/
/// failed/skipped are SET to the running totals the loop accumulates (not summed here), so the loop
/// stays the single source of truth. `current_depth` advances monotonically (max).
#[derive(Debug, Clone, Default)]
pub struct CounterSnapshot {
    pub pages_discovered: i64,
    pub pages_done: i64,
    pub pages_failed: i64,
    pub pages_skipped: i64,
    pub workers_active: i64,
    pub current_depth: i64,
}

/// Push the live counter snapshot (used by the running crawl loop each tick).
pub async fn set_counters(pool: &SqlitePool, id: i64, c: &CounterSnapshot) -> LocalResult<()> {
    sqlx::query(
        "UPDATE crawl_jobs SET
            pages_discovered = ?2,
            pages_done = ?3,
            pages_failed = ?4,
            pages_skipped = ?5,
            workers_active = ?6,
            current_depth = MAX(current_depth, ?7),
            updated_at = strftime('%Y-%m-%dT%H:%M:%fZ','now')
         WHERE id = ?1",
    )
    .bind(id)
    .bind(c.pages_discovered)
    .bind(c.pages_done)
    .bind(c.pages_failed)
    .bind(c.pages_skipped)
    .bind(c.workers_active)
    .bind(c.current_depth)
    .execute(pool)
    .await?;
    Ok(())
}

/// Request cancellation: set the boolean the crawl loop observes and flip the status to `stopping`
/// so the UI reflects the drain immediately. The loop finalizes to `cancelled` once workers drain.
pub async fn request_cancel(pool: &SqlitePool, id: i64) -> LocalResult<bool> {
    let affected = sqlx::query(
        "UPDATE crawl_jobs SET
            cancel_requested = 1,
            status = CASE WHEN status IN ('queued','mapping','crawling') THEN 'stopping' ELSE status END,
            updated_at = strftime('%Y-%m-%dT%H:%M:%fZ','now')
         WHERE id = ?1 AND status NOT IN ('completed','failed','cancelled')",
    )
    .bind(id)
    .execute(pool)
    .await?
    .rows_affected();
    Ok(affected > 0)
}

/// Has cancellation been requested for this crawl? Re-read fresh (the loop polls it between waves).
pub async fn is_cancel_requested(pool: &SqlitePool, id: i64) -> LocalResult<bool> {
    let v: Option<i64> = sqlx::query("SELECT cancel_requested FROM crawl_jobs WHERE id = ?1")
        .bind(id)
        .fetch_optional(pool)
        .await?
        .and_then(|r| r.try_get(0).ok());
    Ok(v.unwrap_or(0) != 0)
}

/// Finalize a crawl to a terminal `status` (`completed|failed|cancelled`), stamping `completed_at`,
/// clearing `workers_active`, and recording an optional error. Returns the finalized row.
///
/// TERMINAL-STATUS GUARDED, like its sibling [`request_cancel`]: a crawl that has already reached
/// `completed|failed|cancelled` is never rewritten. Without the guard, a late finalize could overwrite
/// a settled outcome — a straggler worker completing after a user cancel turning `cancelled` into
/// `completed`, or `interrupt_orphaned`'s boot sweep being undone by a task that outlived it. Calling
/// this on an already-terminal crawl is a NO-OP that returns the existing row, so the (idempotent)
/// caller does not have to care who got there first.
///
/// Also clears `cancel_requested`: the flag exists for the running loop to observe, and leaving it set
/// on a settled row makes a re-inspected crawl look like it is still draining.
pub async fn finalize(
    pool: &SqlitePool,
    id: i64,
    status: &str,
    error: Option<&str>,
) -> LocalResult<CrawlJob> {
    let res = sqlx::query(
        "UPDATE crawl_jobs SET
            status = ?2,
            error = ?3,
            workers_active = 0,
            cancel_requested = 0,
            updated_at = strftime('%Y-%m-%dT%H:%M:%fZ','now'),
            completed_at = strftime('%Y-%m-%dT%H:%M:%fZ','now')
         WHERE id = ?1 AND status NOT IN ('completed','failed','cancelled')",
    )
    .bind(id)
    .bind(status)
    .bind(error)
    .execute(pool)
    .await?;

    let row = get_by_id(pool, id)
        .await?
        .ok_or_else(|| LocalError::NotFound(format!("crawl_job {id}")))?;
    if res.rows_affected() == 0 {
        // The row exists (we just read it) but the guard held ⇒ it was already terminal.
        tracing::debug!(
            crawl_id = id,
            requested = %status,
            settled = %row.status,
            "crawl finalize ignored (already terminal)"
        );
        return Ok(row);
    }
    tracing::info!(crawl_id = id, status = %status, "crawl finalized");
    Ok(row)
}

/// Boot reconciliation: a killed daemon leaves crawls in a live status with no in-process loop
/// behind them (the frontier lived in memory, so they cannot resume). Sweep any non-terminal crawl
/// to `failed` so it stops showing as in-flight. Returns the number of rows reconciled.
pub async fn interrupt_orphaned(pool: &SqlitePool) -> LocalResult<u64> {
    let n = sqlx::query(
        "UPDATE crawl_jobs SET
            status = 'failed',
            cancel_requested = 0,
            workers_active = 0,
            error = 'Interrupted: the app restarted while the crawl was running.',
            updated_at = strftime('%Y-%m-%dT%H:%M:%fZ','now'),
            completed_at = strftime('%Y-%m-%dT%H:%M:%fZ','now')
         WHERE status IN ('queued','mapping','crawling','stopping')",
    )
    .execute(pool)
    .await?
    .rows_affected();
    Ok(n)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::local::db;

    async fn pool() -> SqlitePool {
        let dir = Box::leak(Box::new(tempfile::tempdir().unwrap()));
        db::open(&dir.path().join("t.db"), "test-key-crawl").await.unwrap()
    }

    #[tokio::test]
    async fn insert_defaults_advance_finalize() {
        let pool = pool().await;
        let c = insert(
            &pool,
            &NewCrawlJob {
                name: "Dragnet: example.com".into(),
                seed_url: "https://example.com".into(),
                ..Default::default()
            },
        )
        .await
        .unwrap();
        assert_eq!(c.status, "queued");
        assert_eq!(c.extract_mode, "markdown"); // COALESCE default
        assert_eq!(c.max_depth, 3);
        assert_eq!(c.page_budget, 500);
        assert_eq!(c.max_concurrent, 4);
        assert_eq!(c.respect_robots, 1);
        assert_eq!(c.include_paths, "[]");
        assert!(!c.is_terminal());

        set_status(&pool, c.id, "crawling").await.unwrap();
        set_counters(
            &pool,
            c.id,
            &CounterSnapshot {
                pages_discovered: 10,
                pages_done: 4,
                pages_failed: 1,
                pages_skipped: 2,
                workers_active: 3,
                current_depth: 2,
            },
        )
        .await
        .unwrap();
        let mid = get_by_id(&pool, c.id).await.unwrap().unwrap();
        assert_eq!(mid.status, "crawling");
        assert_eq!(mid.pages_discovered, 10);
        assert_eq!(mid.pages_done, 4);
        assert_eq!(mid.current_depth, 2);
        assert!(mid.started_at.is_some(), "started_at stamped on first live status");

        // current_depth advances monotonically (a lower value never lowers it).
        set_counters(&pool, c.id, &CounterSnapshot { current_depth: 1, ..Default::default() })
            .await
            .unwrap();
        assert_eq!(get_by_id(&pool, c.id).await.unwrap().unwrap().current_depth, 2);

        // Cancel request flips to stopping + sets the flag.
        assert!(request_cancel(&pool, c.id).await.unwrap());
        assert!(is_cancel_requested(&pool, c.id).await.unwrap());
        assert_eq!(get_by_id(&pool, c.id).await.unwrap().unwrap().status, "stopping");

        let done = finalize(&pool, c.id, "cancelled", None).await.unwrap();
        assert_eq!(done.status, "cancelled");
        assert!(done.is_terminal());
        assert!(done.completed_at.is_some());
        assert_eq!(done.workers_active, 0);
        assert_eq!(done.cancel_requested, 0, "the drain flag is cleared once settled");

        // A terminal crawl no longer accepts a cancel request.
        assert!(!request_cancel(&pool, c.id).await.unwrap());
    }

    /// A late finalize must not rewrite a settled outcome: a straggler worker reporting `completed`
    /// after the user cancelled would otherwise erase the cancellation.
    #[tokio::test]
    async fn finalize_is_guarded_against_an_already_terminal_row() {
        let pool = pool().await;
        let c = insert(
            &pool,
            &NewCrawlJob { name: "x".into(), seed_url: "https://x.test".into(), ..Default::default() },
        )
        .await
        .unwrap();
        set_status(&pool, c.id, "crawling").await.unwrap();
        request_cancel(&pool, c.id).await.unwrap();
        let cancelled = finalize(&pool, c.id, "cancelled", None).await.unwrap();
        let settled_at = cancelled.completed_at.clone();

        // The straggler's finalize is accepted as a no-op, returning the SETTLED row.
        let again = finalize(&pool, c.id, "completed", Some("worker finished late")).await.unwrap();
        assert_eq!(again.status, "cancelled", "terminal status must not be overwritten");
        assert!(again.error.is_none(), "nor its error field");
        assert_eq!(again.completed_at, settled_at, "nor its completion timestamp");

        // A crawl that does not exist is still NotFound, not a silent success.
        assert!(matches!(
            finalize(&pool, 9_999, "failed", None).await,
            Err(LocalError::NotFound(_))
        ));
    }

    #[tokio::test]
    async fn orphan_sweep_fails_live_crawls() {
        let pool = pool().await;
        let c = insert(
            &pool,
            &NewCrawlJob { name: "x".into(), seed_url: "https://x.test".into(), ..Default::default() },
        )
        .await
        .unwrap();
        set_status(&pool, c.id, "crawling").await.unwrap();
        assert_eq!(interrupt_orphaned(&pool).await.unwrap(), 1);
        let swept = get_by_id(&pool, c.id).await.unwrap().unwrap();
        assert_eq!(swept.status, "failed");
        assert!(swept.error.as_deref().unwrap().contains("restarted"));
        // Idempotent: nothing left to sweep.
        assert_eq!(interrupt_orphaned(&pool).await.unwrap(), 0);
    }
}
