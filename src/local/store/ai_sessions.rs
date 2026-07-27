//! Store layer for the `ai_sessions` table (0006_ai_sessions.sql) — the server-side autonomous AI
//! browser-agent runs (form-filler loop; the Rust port of the Python `ai_generate_workflow`).
//!
//! Runtime-checked sqlx only. A session starts in `status='running'` (via [`insert`]), has its live
//! progress tracked (`step_count`, `filled_fields`, `clicked_indices`, `last_url`) via
//! [`update_tracking`], and is finalized to a terminal state via [`finalize`]. JSON fields
//! (`available_data`, `fill_data`, `filled_fields`, `clicked_indices`, `result_data`) are TEXT — the
//! caller serdes them.

use super::super::error::{LocalError, LocalResult};
use sqlx::sqlite::SqlitePool;
use sqlx::Row as _;

/// A full `ai_sessions` row.
#[derive(Debug, Clone, sqlx::FromRow, serde::Serialize, serde::Deserialize)]
pub struct AiSession {
    pub id: i64,
    #[serde(default)]
    pub run_id: Option<i64>,
    #[serde(default)]
    pub workflow_id: Option<i64>,
    #[serde(default)]
    pub name: Option<String>,
    pub goal: String,
    #[serde(default)]
    pub entry_url: Option<String>,
    pub status: String,
    pub step_count: i64,
    pub max_steps: i64,
    #[serde(default)]
    pub available_data: Option<String>,
    #[serde(default)]
    pub fill_data: Option<String>,
    #[serde(default)]
    pub filled_fields: Option<String>,
    #[serde(default)]
    pub clicked_indices: Option<String>,
    #[serde(default)]
    pub last_url: Option<String>,
    #[serde(default)]
    pub result_data: Option<String>,
    #[serde(default)]
    pub error_message: Option<String>,
    /// `1` ⇒ on a successful (`complete`) finish, assemble + persist a reusable `workflows` row from
    /// the captured steps and link it (`workflow_id`); `0` ⇒ skip. Column default `1` (see 0014).
    /// `#[sqlx(default)]` keeps any `SELECT *`/pre-0014 sidecar path decoding across the additive column.
    #[serde(default = "default_generate_workflow")]
    #[sqlx(default)]
    pub generate_workflow: i64,
    pub created_at: String,
    #[serde(default)]
    pub started_at: Option<String>,
    #[serde(default)]
    pub completed_at: Option<String>,
}

/// Caller-supplied fields to start an AI session. Anything omitted falls to the column default
/// (`status='running'`, `step_count=0`, `max_steps=20`, JSON fields `{}`/`[]`).
#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct NewAiSession {
    #[serde(default)]
    pub run_id: Option<i64>,
    #[serde(default)]
    pub workflow_id: Option<i64>,
    #[serde(default)]
    pub name: Option<String>,
    pub goal: String,
    #[serde(default)]
    pub entry_url: Option<String>,
    #[serde(default)]
    pub max_steps: Option<i64>,
    /// JSON-TEXT the caller has already serialized (keys/values shown to the model).
    #[serde(default)]
    pub available_data: Option<String>,
    /// JSON-TEXT the caller has already serialized (actual values to fill; secrets decrypted).
    #[serde(default)]
    pub fill_data: Option<String>,
    /// Whether a successful finish should record a reusable workflow. `None` ⇒ the column default (1,
    /// i.e. DO record). Set `Some(false)` to skip (e.g. an automation-internal AI step).
    #[serde(default)]
    pub generate_workflow: Option<bool>,
}

/// serde default for [`AiSession::generate_workflow`] — a session absent the column (pre-0014
/// sidecar / `SELECT *` decode) defaults to the record-a-workflow behavior (`1`).
fn default_generate_workflow() -> i64 {
    1
}

const SELECT_COLS: &str = "id, run_id, workflow_id, name, goal, entry_url, status, step_count,
    max_steps, available_data, fill_data, filled_fields, clicked_indices, last_url, result_data,
    error_message, generate_workflow, created_at, started_at, completed_at";

/// Start an AI session (`status='running'`, `started_at=now`). Returns the full row.
pub async fn insert(pool: &SqlitePool, new: &NewAiSession) -> LocalResult<AiSession> {
    let id: i64 = sqlx::query(
        "INSERT INTO ai_sessions
         (run_id, workflow_id, name, goal, entry_url, status, max_steps,
          available_data, fill_data, generate_workflow, started_at)
         VALUES
         (?1, ?2, ?3, ?4, ?5, 'running', COALESCE(?6, 20),
          COALESCE(?7, '{}'), COALESCE(?8, '{}'), COALESCE(?9, 1),
          strftime('%Y-%m-%dT%H:%M:%fZ','now'))
         RETURNING id",
    )
    .bind(new.run_id)
    .bind(new.workflow_id)
    .bind(&new.name)
    .bind(&new.goal)
    .bind(&new.entry_url)
    .bind(new.max_steps)
    .bind(&new.available_data)
    .bind(&new.fill_data)
    // NULL ⇒ column default (1). `Some(bool)` maps to 1/0.
    .bind(new.generate_workflow.map(|b| b as i64))
    .fetch_one(pool)
    .await?
    .try_get(0)?;

    tracing::info!(ai_session_id = id, workflow_id = ?new.workflow_id, "ai session started");
    get_by_id(pool, id)
        .await?
        .ok_or_else(|| LocalError::Internal("ai_session vanished after insert".into()))
}

/// Fetch one AI session by id.
pub async fn get_by_id(pool: &SqlitePool, id: i64) -> LocalResult<Option<AiSession>> {
    let row =
        sqlx::query_as::<_, AiSession>(&format!("SELECT {SELECT_COLS} FROM ai_sessions WHERE id = ?1"))
            .bind(id)
            .fetch_optional(pool)
            .await?;
    Ok(row)
}

/// List AI sessions newest-first, capped at `limit`.
pub async fn list(pool: &SqlitePool, limit: i64) -> LocalResult<Vec<AiSession>> {
    let limit = limit.clamp(1, 1000);
    let rows = sqlx::query_as::<_, AiSession>(&format!(
        "SELECT {SELECT_COLS} FROM ai_sessions ORDER BY created_at DESC, id DESC LIMIT ?1"
    ))
    .bind(limit)
    .fetch_all(pool)
    .await?;
    Ok(rows)
}

/// Update the live progress of a running session (step count + filled/clicked tracking + last url).
/// `filled_fields` / `clicked_indices` are JSON-TEXT arrays the caller serialized. Returns whether a
/// row was affected. Best-effort progress mirror — never finalizes.
pub async fn update_tracking(
    pool: &SqlitePool,
    id: i64,
    step_count: i64,
    filled_fields: Option<&str>,
    clicked_indices: Option<&str>,
    last_url: Option<&str>,
) -> LocalResult<bool> {
    let res = sqlx::query(
        "UPDATE ai_sessions SET
            step_count = ?2,
            filled_fields = COALESCE(?3, filled_fields),
            clicked_indices = COALESCE(?4, clicked_indices),
            last_url = COALESCE(?5, last_url)
         WHERE id = ?1",
    )
    .bind(id)
    .bind(step_count)
    .bind(filled_fields)
    .bind(clicked_indices)
    .bind(last_url)
    .execute(pool)
    .await?;
    Ok(res.rows_affected() > 0)
}

/// Boot reconciliation: mark orphaned non-terminal AI sessions (a run the crash/restart killed) as
/// `cancelled` so they stop showing as live in the list. Safe to call only after the singleton lock is
/// held (no other live daemon owns these). Returns the number of rows reconciled.
pub async fn interrupt_orphaned(pool: &SqlitePool) -> LocalResult<u64> {
    let n = sqlx::query(
        "UPDATE ai_sessions SET
            status = 'cancelled',
            error_message = COALESCE(error_message, 'daemon restarted while this session was running'),
            completed_at = strftime('%Y-%m-%dT%H:%M:%fZ','now')
         WHERE status NOT IN ('complete','blocked','max_steps','stuck','error','cancelled','interrupted')",
    )
    .execute(pool)
    .await?
    .rows_affected();
    Ok(n)
}

/// Finalize an AI session to a terminal `status` (`complete|blocked|max_steps|stuck|error`), stamping
/// `completed_at=now`, the final `step_count`, the (JSON-TEXT) `result_data`, and an optional
/// `error_message`. Returns the finalized row.
#[allow(clippy::too_many_arguments)]
pub async fn finalize(
    pool: &SqlitePool,
    id: i64,
    status: &str,
    step_count: i64,
    last_url: Option<&str>,
    result_data: Option<&str>,
    error_message: Option<&str>,
) -> LocalResult<AiSession> {
    let res = sqlx::query(
        "UPDATE ai_sessions SET
            status = ?2, step_count = ?3,
            last_url = COALESCE(?4, last_url),
            result_data = ?5, error_message = ?6,
            completed_at = strftime('%Y-%m-%dT%H:%M:%fZ','now')
         WHERE id = ?1",
    )
    .bind(id)
    .bind(status)
    .bind(step_count)
    .bind(last_url)
    .bind(result_data)
    .bind(error_message)
    .execute(pool)
    .await?;
    if res.rows_affected() == 0 {
        return Err(LocalError::NotFound(format!("ai_session {id}")));
    }
    tracing::info!(ai_session_id = id, status = %status, "ai session finalized");
    get_by_id(pool, id)
        .await?
        .ok_or_else(|| LocalError::NotFound(format!("ai_session {id}")))
}

/// Link a session to the reusable `workflows` row it produced. Called AFTER a successful finish once
/// the workflow has been assembled + inserted from the captured steps. Returns whether a row was
/// updated (false → the session was deleted between finalize and link — a benign race).
pub async fn set_workflow_id(pool: &SqlitePool, id: i64, workflow_id: i64) -> LocalResult<bool> {
    let res = sqlx::query("UPDATE ai_sessions SET workflow_id = ?2 WHERE id = ?1")
        .bind(id)
        .bind(workflow_id)
        .execute(pool)
        .await?;
    Ok(res.rows_affected() > 0)
}

/// Hard-delete an AI session row by id. Returns whether a row was removed (false → already gone).
/// `run_id` / `workflow_id` FKs are `ON DELETE SET NULL`, so deleting a session never cascades into
/// runs or workflows.
pub async fn delete(pool: &SqlitePool, id: i64) -> LocalResult<bool> {
    let res = sqlx::query("DELETE FROM ai_sessions WHERE id = ?1")
        .bind(id)
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
        db::open(&dir.path().join("t.db"), "test-key-ai-sessions").await.unwrap()
    }

    #[tokio::test]
    async fn insert_track_finalize_list() {
        let pool = pool().await;
        let s = insert(
            &pool,
            &NewAiSession {
                name: Some("signup".into()),
                goal: "complete the registration form".into(),
                entry_url: Some("https://example.com/signup".into()),
                available_data: Some(r#"{"email":"a@b.com"}"#.into()),
                fill_data: Some(r#"{"email":"a@b.com"}"#.into()),
                ..Default::default()
            },
        )
        .await
        .unwrap();
        assert_eq!(s.status, "running");
        assert_eq!(s.step_count, 0);
        assert_eq!(s.max_steps, 20); // COALESCE default
        assert_eq!(s.goal, "complete the registration form");
        assert!(s.started_at.is_some());
        assert_eq!(s.available_data.as_deref(), Some(r#"{"email":"a@b.com"}"#));

        assert!(update_tracking(
            &pool,
            s.id,
            2,
            Some(r#"["email"]"#),
            Some("[]"),
            Some("https://example.com/step2"),
        )
        .await
        .unwrap());

        let mid = get_by_id(&pool, s.id).await.unwrap().unwrap();
        assert_eq!(mid.step_count, 2);
        assert_eq!(mid.filled_fields.as_deref(), Some(r#"["email"]"#));
        assert_eq!(mid.last_url.as_deref(), Some("https://example.com/step2"));

        let done = finalize(
            &pool,
            s.id,
            "complete",
            3,
            Some("https://example.com/done"),
            Some(r#"{"submitted":true}"#),
            None,
        )
        .await
        .unwrap();
        assert_eq!(done.status, "complete");
        assert_eq!(done.step_count, 3);
        assert_eq!(done.last_url.as_deref(), Some("https://example.com/done"));
        assert_eq!(done.result_data.as_deref(), Some(r#"{"submitted":true}"#));
        assert!(done.completed_at.is_some());

        assert_eq!(list(&pool, 50).await.unwrap().len(), 1);
    }

    #[tokio::test]
    async fn finalize_missing_is_not_found() {
        let pool = pool().await;
        let err = finalize(&pool, 999, "error", 0, None, None, Some("nope")).await;
        assert!(matches!(err, Err(LocalError::NotFound(_))));
    }

    /// `generate_workflow` defaults to 1 (record a workflow) when absent, and honors an explicit
    /// `Some(false)`. The 0014 column is decoded onto the row struct.
    #[tokio::test]
    async fn generate_workflow_defaults_on_and_respects_opt_out() {
        let pool = pool().await;

        // Absent (None) → the column default of 1.
        let default_on = insert(&pool, &NewAiSession { goal: "g".into(), ..Default::default() })
            .await
            .unwrap();
        assert_eq!(default_on.generate_workflow, 1, "None ⇒ column default 1");
        assert_eq!(
            get_by_id(&pool, default_on.id).await.unwrap().unwrap().generate_workflow,
            1
        );

        // Explicit opt-out → 0.
        let opted_out = insert(
            &pool,
            &NewAiSession { goal: "g2".into(), generate_workflow: Some(false), ..Default::default() },
        )
        .await
        .unwrap();
        assert_eq!(opted_out.generate_workflow, 0, "Some(false) ⇒ 0");

        // Explicit opt-in → 1.
        let opted_in = insert(
            &pool,
            &NewAiSession { goal: "g3".into(), generate_workflow: Some(true), ..Default::default() },
        )
        .await
        .unwrap();
        assert_eq!(opted_in.generate_workflow, 1, "Some(true) ⇒ 1");
    }

    /// `set_workflow_id` links a finished session to the workflow it produced; a missing session is a
    /// benign `false` (no row updated), never an error.
    #[tokio::test]
    async fn set_workflow_id_links_and_tolerates_missing() {
        use crate::local::store::workflows;
        let pool = pool().await;

        let s = insert(&pool, &NewAiSession { goal: "g".into(), ..Default::default() })
            .await
            .unwrap();
        assert_eq!(s.workflow_id, None);

        let wf = workflows::insert(&pool, &workflows::NewWorkflow { name: "w".into(), ..Default::default() })
            .await
            .unwrap();

        assert!(set_workflow_id(&pool, s.id, wf.id).await.unwrap(), "linked");
        assert_eq!(get_by_id(&pool, s.id).await.unwrap().unwrap().workflow_id, Some(wf.id));

        // A non-existent session id updates nothing (benign race) — not an error.
        assert!(!set_workflow_id(&pool, 999_999, wf.id).await.unwrap());
    }
}
