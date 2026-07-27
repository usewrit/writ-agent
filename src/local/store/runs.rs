//! Store layer for the `runs` table (0001_init.sql §2) — a collapsed AutomationTask.
//!
//! Runtime-checked sqlx only. A run starts in `status='running'`, then is finalized via
//! `complete`/`fail`. `trigger_context`, `result_data` are JSON-TEXT — callers serde them. The
//! nullable `success` column is a tri-state (NULL = still running) modeled as `Option<i64>` (0/1).

use super::super::error::{LocalError, LocalResult};
use sqlx::sqlite::SqlitePool;
use sqlx::Row as _;

/// A full `runs` row.
#[derive(Debug, Clone, sqlx::FromRow, serde::Serialize, serde::Deserialize)]
pub struct Run {
    pub id: i64,
    #[serde(default)]
    pub workflow_id: Option<i64>,
    #[serde(default)]
    pub target_id: Option<i64>,
    #[serde(default)]
    pub change_id: Option<i64>,
    #[serde(default)]
    pub automation_id: Option<i64>,
    pub status: String,
    pub trigger_type: String,
    /// Tri-state: NULL while running, then 0/1. Modeled as `Option<i64>`.
    #[serde(default)]
    pub success: Option<i64>,
    #[serde(default)]
    pub started_at: Option<String>,
    #[serde(default)]
    pub completed_at: Option<String>,
    #[serde(default)]
    pub duration_ms: Option<i64>,
    #[serde(default)]
    pub trigger_context: Option<String>,
    #[serde(default)]
    pub result_data: Option<String>,
    #[serde(default)]
    pub error_message: Option<String>,
    #[serde(default)]
    pub failure_category: Option<String>,
    /// AI auto-repair verdict (0023). Tri-state like `success`: NULL = no verdict (repair off, never
    /// triggered, or the daemon died mid-repair), 1 = the AI's fix worked, 0 = the AI tried and gave
    /// up. `#[sqlx(default)]` keeps `SELECT *` paths (tests) working across the additive migration.
    #[serde(default)]
    #[sqlx(default)]
    pub ai_repair_succeeded: Option<i64>,
    pub attempt_count: i64,
    pub max_attempts: i64,
    pub created_at: String,
}

/// Caller-supplied fields to start a run. Anything omitted falls to the column default
/// (`status='running'`, `trigger_type='manual'`, `attempt_count=0`, `max_attempts=3`).
#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct NewRun {
    #[serde(default)]
    pub workflow_id: Option<i64>,
    #[serde(default)]
    pub target_id: Option<i64>,
    #[serde(default)]
    pub change_id: Option<i64>,
    #[serde(default)]
    pub automation_id: Option<i64>,
    /// `manual|on_change|scheduled|webhook|api|workflow`. Empty → schema default (`manual`).
    #[serde(default)]
    pub trigger_type: Option<String>,
    /// JSON-TEXT trigger context the caller has already serialized.
    #[serde(default)]
    pub trigger_context: Option<String>,
    #[serde(default)]
    pub max_attempts: Option<i64>,
}

const SELECT_COLS: &str = "id, workflow_id, target_id, change_id, automation_id, status,
    trigger_type, success, started_at, completed_at, duration_ms, trigger_context, result_data,
    error_message, failure_category, ai_repair_succeeded, attempt_count, max_attempts, created_at";

/// Start a run (`status='running'`, `started_at=now`, `attempt_count=1`). Returns the full row.
pub async fn insert(pool: &SqlitePool, new: &NewRun) -> LocalResult<Run> {
    let id: i64 = sqlx::query(
        "INSERT INTO runs 
         (workflow_id, target_id, change_id, automation_id, status, trigger_type, 
          trigger_context, started_at, attempt_count, max_attempts) 
         VALUES 
         (?1, ?2, ?3, ?4, 'running', COALESCE(?5, 'manual'), ?6, 
          strftime('%Y-%m-%dT%H:%M:%fZ','now'), 1, COALESCE(?7, 3)) 
         RETURNING id",
    )
    .bind(new.workflow_id)
    .bind(new.target_id)
    .bind(new.change_id)
    .bind(new.automation_id)
    .bind(&new.trigger_type)
    .bind(&new.trigger_context)
    .bind(new.max_attempts)
    .fetch_one(pool)
    .await?
    .try_get(0)?;

    tracing::info!(run_id = id, workflow_id = ?new.workflow_id, "run started");
    get_by_id(pool, id)
        .await?
        .ok_or_else(|| LocalError::Internal("run vanished after insert".into()))
}

/// Insert a fully-formed, already-TERMINAL run imported from the cloud (cloud→app extracted-data
/// sync). Unlike [`insert`] (which starts a `running` row stamped `now`), this writes the terminal
/// state, `result_data`, and the ORIGINAL cloud timestamp in one statement so the Data explorer
/// reflects the cloud run faithfully (correct ordering by run time). `run_at` falls back to `now`
/// when the cloud omitted it. `trigger_type` is fixed to `api` (the row came from the cloud API).
pub async fn insert_imported(
    pool: &SqlitePool,
    workflow_id: i64,
    status: &str,
    success: bool,
    run_at: Option<&str>,
    result_data: Option<&str>,
    trigger_context: Option<&str>,
) -> LocalResult<Run> {
    let id: i64 = sqlx::query(
        "INSERT INTO runs
         (workflow_id, status, trigger_type, success, started_at, completed_at,
          trigger_context, result_data, attempt_count, max_attempts)
         VALUES
         (?, ?, 'api', ?,
          COALESCE(?, strftime('%Y-%m-%dT%H:%M:%fZ','now')),
          COALESCE(?, strftime('%Y-%m-%dT%H:%M:%fZ','now')),
          ?, ?, 1, 1)
         RETURNING id",
    )
    .bind(workflow_id)
    .bind(status)
    .bind(success as i64)
    .bind(run_at)
    .bind(run_at)
    .bind(trigger_context)
    .bind(result_data)
    .fetch_one(pool)
    .await?
    .try_get(0)?;

    get_by_id(pool, id)
        .await?
        .ok_or_else(|| LocalError::Internal("run vanished after import insert".into()))
}

/// Fetch one run by id.
pub async fn get_by_id(pool: &SqlitePool, id: i64) -> LocalResult<Option<Run>> {
    let row = sqlx::query_as::<_, Run>(&format!("SELECT {SELECT_COLS} FROM runs WHERE id = ?1"))
        .bind(id)
        .fetch_optional(pool)
        .await?;
    Ok(row)
}

/// List runs newest-first, capped at `limit`.
pub async fn list(pool: &SqlitePool, limit: i64) -> LocalResult<Vec<Run>> {
    let limit = limit.clamp(1, 1000);
    let rows = sqlx::query_as::<_, Run>(&format!(
        "SELECT {SELECT_COLS} FROM runs ORDER BY created_at DESC, id DESC LIMIT ?1"
    ))
    .bind(limit)
    .fetch_all(pool)
    .await?;
    Ok(rows)
}

/// List runs for one workflow, newest-first, capped at `limit`.
pub async fn list_by_workflow(
    pool: &SqlitePool,
    workflow_id: i64,
    limit: i64,
) -> LocalResult<Vec<Run>> {
    let limit = limit.clamp(1, 1000);
    let rows = sqlx::query_as::<_, Run>(&format!(
        "SELECT {SELECT_COLS} FROM runs WHERE workflow_id = ?1 
         ORDER BY created_at DESC, id DESC LIMIT ?2"
    ))
    .bind(workflow_id)
    .bind(limit)
    .fetch_all(pool)
    .await?;
    Ok(rows)
}

/// Full-text search over runs' extracted_data via the FTS5 index (migration 0022). Returns the
/// SUCCESSFUL matching runs newest-first, optionally scoped to one workflow (dataset), bounded by
/// `cap`. `match_query` is an FTS5 MATCH expression (build it with `data_query::fts5_match_query`).
/// `SELECT r.*` (not the FTS columns) so the row maps straight onto `Run`.
pub async fn search_fts(
    pool: &SqlitePool,
    match_query: &str,
    workflow_id: Option<i64>,
    cap: i64,
) -> LocalResult<Vec<Run>> {
    let cap = cap.clamp(1, 5000);
    let sql = format!(
        "SELECT r.* FROM run_data_fts f JOIN runs r ON r.id = f.rowid \
         WHERE run_data_fts MATCH ?1 AND r.success = 1{} \
         ORDER BY COALESCE(r.completed_at, r.created_at) DESC, r.id DESC LIMIT ?2",
        if workflow_id.is_some() { " AND f.workflow_id = ?3" } else { "" }
    );
    let mut q = sqlx::query_as::<_, Run>(&sql).bind(match_query).bind(cap);
    if let Some(wid) = workflow_id {
        q = q.bind(wid);
    }
    Ok(q.fetch_all(pool).await?)
}

/// One row of the persona-scoped run listing: a run joined to the workflow it executed, for
/// workflows whose `default_persona_id` is the persona. Runs are not persona-stamped locally, so
/// the workflow link IS the persona attribution (every run of that workflow acted as its persona).
#[derive(Debug, Clone, sqlx::FromRow, serde::Serialize)]
pub struct PersonaRunRow {
    pub id: i64,
    pub workflow_id: Option<i64>,
    pub workflow_name: Option<String>,
    pub status: String,
    /// Tri-state: NULL while running, then 0/1.
    pub success: Option<i64>,
    pub started_at: Option<String>,
    pub completed_at: Option<String>,
    pub error_message: Option<String>,
}

/// Recent runs that acted as `persona_id` (via their workflow's `default_persona_id`), newest-first.
pub async fn list_by_default_persona(
    pool: &SqlitePool,
    persona_id: i64,
    limit: i64,
) -> LocalResult<Vec<PersonaRunRow>> {
    let limit = limit.clamp(1, 50);
    let rows = sqlx::query_as::<_, PersonaRunRow>(
        "SELECT r.id, r.workflow_id, w.name AS workflow_name, r.status, r.success,
                r.started_at, r.completed_at, r.error_message
         FROM runs r JOIN workflows w ON w.id = r.workflow_id
         WHERE w.default_persona_id = ?1
         ORDER BY r.created_at DESC, r.id DESC LIMIT ?2",
    )
    .bind(persona_id)
    .bind(limit)
    .fetch_all(pool)
    .await?;
    Ok(rows)
}

/// List runs by status (e.g. `running` for crash-recovery sweeps), newest-first, capped.
pub async fn list_by_status(pool: &SqlitePool, status: &str, limit: i64) -> LocalResult<Vec<Run>> {
    let limit = limit.clamp(1, 1000);
    let rows = sqlx::query_as::<_, Run>(&format!(
        "SELECT {SELECT_COLS} FROM runs WHERE status = ?1 
         ORDER BY created_at DESC, id DESC LIMIT ?2"
    ))
    .bind(status)
    .bind(limit)
    .fetch_all(pool)
    .await?;
    Ok(rows)
}

/// Runs of a given `trigger_type` that are still IN FLIGHT, newest first.
///
/// "In flight" is `status IN ('running','repairing')` — deliberately the same set
/// [`interrupt_running`] reconciles to `interrupted` on daemon restart, so the two views can never
/// disagree about what "live" means (a status this considers live but that one doesn't would linger
/// forever after a crash).
///
/// Used by `GET /v1/cloud/agent/runs` with `trigger_type = "cloud"` to list the cloud-dispatched
/// runs this device is serving right now. The `runs` row is the authoritative liveness record: it is
/// inserted before the run starts and finalized when it ends, so it is accurate for the whole run.
pub async fn list_live_by_trigger_type(
    pool: &SqlitePool,
    trigger_type: &str,
    limit: i64,
) -> LocalResult<Vec<Run>> {
    let limit = limit.clamp(1, 1000);
    let rows = sqlx::query_as::<_, Run>(&format!(
        "SELECT {SELECT_COLS} FROM runs
         WHERE trigger_type = ?1 AND status IN ('running', 'repairing')
         ORDER BY created_at DESC, id DESC LIMIT ?2"
    ))
    .bind(trigger_type)
    .bind(limit)
    .fetch_all(pool)
    .await?;
    Ok(rows)
}

/// Finalize a run as successful. Sets `status='success'`, `success=1`, `completed_at=now`, and
/// stores the (JSON-TEXT) result + measured `duration_ms`.
pub async fn complete(
    pool: &SqlitePool,
    id: i64,
    result_data: Option<&str>,
    duration_ms: Option<i64>,
) -> LocalResult<Run> {
    let res = sqlx::query(
        "UPDATE runs SET 
            status = 'success', success = 1, 
            completed_at = strftime('%Y-%m-%dT%H:%M:%fZ','now'), 
            result_data = ?2, duration_ms = ?3 
         WHERE id = ?1",
    )
    .bind(id)
    .bind(result_data)
    .bind(duration_ms)
    .execute(pool)
    .await?;
    if res.rows_affected() == 0 {
        return Err(LocalError::NotFound(format!("run {id}")));
    }
    tracing::info!(run_id = id, "run completed");
    get_by_id(pool, id)
        .await?
        .ok_or_else(|| LocalError::NotFound(format!("run {id}")))
}

/// Finalize a run as failed. `status` lets the caller pick a terminal non-success state
/// (`failed|cancelled|timeout|interrupted|captcha_required`); `success` is set to 0.
pub async fn fail(
    pool: &SqlitePool,
    id: i64,
    status: &str,
    error_message: Option<&str>,
    failure_category: Option<&str>,
    duration_ms: Option<i64>,
) -> LocalResult<Run> {
    let res = sqlx::query(
        "UPDATE runs SET 
            status = ?2, success = 0, 
            completed_at = strftime('%Y-%m-%dT%H:%M:%fZ','now'), 
            error_message = ?3, failure_category = ?4, duration_ms = ?5 
         WHERE id = ?1",
    )
    .bind(id)
    .bind(status)
    .bind(error_message)
    .bind(failure_category)
    .bind(duration_ms)
    .execute(pool)
    .await?;
    if res.rows_affected() == 0 {
        return Err(LocalError::NotFound(format!("run {id}")));
    }
    tracing::info!(run_id = id, status = %status, "run failed");
    get_by_id(pool, id)
        .await?
        .ok_or_else(|| LocalError::NotFound(format!("run {id}")))
}

/// Set a run's status without finalizing (e.g. an in-flight transition). Returns whether a row was
/// affected.
pub async fn set_status(pool: &SqlitePool, id: i64, status: &str) -> LocalResult<bool> {
    let res = sqlx::query("UPDATE runs SET status = ?2 WHERE id = ?1")
        .bind(id)
        .bind(status)
        .execute(pool)
        .await?;
    Ok(res.rows_affected() > 0)
}

/// Record the AI auto-repair verdict for a run (0023): `true` = the fix worked, `false` = the AI
/// tried and could not fix it. Returns whether a row was affected.
///
/// Called at each point where repair reaches a verdict, and the LAST call wins — deliberately. The
/// smart-repair self-heal restart re-enters `execute` with the SAME run id, so a run that was fixed
/// and then broke again in a way the AI could not repair must end up reading "repair failed": the
/// run still needs a human, and that is the whole signal Home's "Needs attention" acts on.
///
/// Unlike `status='repairing'` (transient, overwritten the moment the repair resolves), this is the
/// durable record — it is what survives to the runs feed after the run terminates.
pub async fn set_repair_outcome(pool: &SqlitePool, id: i64, succeeded: bool) -> LocalResult<bool> {
    let res = sqlx::query("UPDATE runs SET ai_repair_succeeded = ?2 WHERE id = ?1")
        .bind(id)
        .bind(i64::from(succeeded))
        .execute(pool)
        .await?;
    Ok(res.rows_affected() > 0)
}

/// Boot crash-reconciliation: terminally mark EVERY still-`running` row as `interrupted`
/// (`success=0`, `completed_at=now`, `failure_category='interrupted'`). Called once at daemon
/// startup, AFTER the singleton lock is held, because a `kill -9`/crash leaves runs stuck `running`
/// forever and no other live daemon could own them. Returns the number of rows reconciled.
pub async fn interrupt_running(pool: &SqlitePool) -> LocalResult<u64> {
    let n = sqlx::query(
        "UPDATE runs SET
            status = 'interrupted', success = 0,
            completed_at = strftime('%Y-%m-%dT%H:%M:%fZ','now'),
            error_message = COALESCE(error_message, 'daemon restarted while this run was in flight'),
            failure_category = COALESCE(failure_category, 'interrupted')
         WHERE status IN ('running', 'repairing')",
    )
    .execute(pool)
    .await?
    .rows_affected();
    if n > 0 {
        tracing::warn!(count = n, "reconciled orphaned 'running' runs to 'interrupted'");
    }
    Ok(n)
}

/// Increment the attempt counter (returns the new count) — used when a run is retried.
pub async fn bump_attempt(pool: &SqlitePool, id: i64) -> LocalResult<i64> {
    let count: i64 = sqlx::query(
        "UPDATE runs SET attempt_count = attempt_count + 1 WHERE id = ?1 RETURNING attempt_count",
    )
    .bind(id)
    .fetch_optional(pool)
    .await?
    .map(|r| r.try_get(0))
    .transpose()?
    .ok_or_else(|| LocalError::NotFound(format!("run {id}")))?;
    Ok(count)
}

/// Delete a run row. Cascades to `run_artifacts` (ON DELETE CASCADE). Returns whether a row was
/// removed.
pub async fn delete(pool: &SqlitePool, id: i64) -> LocalResult<bool> {
    let res = sqlx::query("DELETE FROM runs WHERE id = ?1")
        .bind(id)
        .execute(pool)
        .await?;
    Ok(res.rows_affected() > 0)
}

/// Overwrite a run's `result_data` JSON-TEXT column (used when the Data UI
/// removes one or more extracted records from a completed run). Passing
/// `None` clears the column entirely.
pub async fn set_result_data(
    pool: &SqlitePool,
    id: i64,
    result_data: Option<&str>,
) -> LocalResult<bool> {
    let res = sqlx::query("UPDATE runs SET result_data = ?2 WHERE id = ?1")
        .bind(id)
        .bind(result_data)
        .execute(pool)
        .await?;
    Ok(res.rows_affected() > 0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::local::db;
    use crate::local::store::workflows::{self, NewWorkflow};

    async fn pool() -> SqlitePool {
        let dir = Box::leak(Box::new(tempfile::tempdir().unwrap()));
        db::open(&dir.path().join("t.db"), "test-key-runs").await.unwrap()
    }

    /// The AI-repair verdict (0023) is a tri-state that starts with NO verdict, and the LAST verdict
    /// wins — the smart-repair self-heal restart re-enters `execute` with the same run id, so a fix
    /// followed by a give-up must end up reading "repair failed" (the run still needs a human).
    #[tokio::test]
    async fn repair_outcome_is_tri_state_and_last_verdict_wins() {
        let pool = pool().await;
        let wf = workflows::insert(&pool, &NewWorkflow { name: "wf".into(), ..Default::default() })
            .await
            .unwrap();
        let run = insert(&pool, &NewRun { workflow_id: Some(wf.id), ..Default::default() })
            .await
            .unwrap();
        // No repair has happened: no verdict (NOT "failed").
        assert_eq!(run.ai_repair_succeeded, None);

        assert!(set_repair_outcome(&pool, run.id, true).await.unwrap());
        assert_eq!(get_by_id(&pool, run.id).await.unwrap().unwrap().ai_repair_succeeded, Some(1));

        // A later give-up in the SAME run supersedes the earlier fix.
        assert!(set_repair_outcome(&pool, run.id, false).await.unwrap());
        assert_eq!(get_by_id(&pool, run.id).await.unwrap().unwrap().ai_repair_succeeded, Some(0));

        // Unknown run → no row touched (and no error).
        assert!(!set_repair_outcome(&pool, 999_999, true).await.unwrap());
    }

    /// Finalizing a run must not disturb the repair verdict: `complete`/`fail` are what run AFTER a
    /// repair resolves, and if they cleared it the badge would vanish exactly when it matters.
    #[tokio::test]
    async fn finalizing_a_run_preserves_the_repair_verdict() {
        let pool = pool().await;
        let wf = workflows::insert(&pool, &NewWorkflow { name: "wf".into(), ..Default::default() })
            .await
            .unwrap();

        let fixed = insert(&pool, &NewRun { workflow_id: Some(wf.id), ..Default::default() })
            .await
            .unwrap();
        set_repair_outcome(&pool, fixed.id, true).await.unwrap();
        let done = complete(&pool, fixed.id, Some("{}"), Some(5)).await.unwrap();
        assert_eq!(done.ai_repair_succeeded, Some(1));

        let broken = insert(&pool, &NewRun { workflow_id: Some(wf.id), ..Default::default() })
            .await
            .unwrap();
        set_repair_outcome(&pool, broken.id, false).await.unwrap();
        let dead = fail(&pool, broken.id, "failed", Some("boom"), Some("selector"), Some(5))
            .await
            .unwrap();
        assert_eq!(dead.ai_repair_succeeded, Some(0));
        assert!(dead.completed_at.is_some());
    }

    /// A run whose `result_data` is NOT valid JSON must still COMPLETE.
    ///
    /// Since 0022 the FTS triggers call json_extract() on this column for every
    /// runs write, and json_extract RAISES on a malformed argument — so without the
    /// `json_valid()` guard in the trigger, one bad blob would abort the UPDATE and
    /// the run could never be finalized. Indexing is best-effort; completing the run
    /// is not. (The row is simply absent from the search index.)
    #[tokio::test]
    async fn malformed_result_data_still_completes_and_is_not_indexed() {
        let pool = pool().await;
        let wf = workflows::insert(&pool, &NewWorkflow { name: "wf".into(), ..Default::default() })
            .await
            .unwrap();
        let run = insert(&pool, &NewRun { workflow_id: Some(wf.id), ..Default::default() })
            .await
            .unwrap();

        // Not JSON at all — the trigger must skip it, not explode.
        let done = complete(&pool, run.id, Some("this is not json {"), Some(5)).await.unwrap();
        assert_eq!(done.status, "success");
        assert_eq!(done.result_data.as_deref(), Some("this is not json {"));

        // Valid JSON that simply has no extracted_data is also skipped, no error.
        let run2 = insert(&pool, &NewRun { workflow_id: Some(wf.id), ..Default::default() })
            .await
            .unwrap();
        let done2 = complete(&pool, run2.id, Some(r#"{"other":1}"#), Some(5)).await.unwrap();
        assert_eq!(done2.status, "success");

        // ...and a well-formed run with extracted_data IS indexed, proving the
        // guard didn't disable indexing wholesale.
        let run3 = insert(&pool, &NewRun { workflow_id: Some(wf.id), ..Default::default() })
            .await
            .unwrap();
        complete(&pool, run3.id, Some(r#"{"extracted_data":{"title":"findme"}}"#), Some(5))
            .await
            .unwrap();
        let hits = search_fts(&pool, "findme", None, 10).await.unwrap();
        assert!(
            hits.iter().any(|r| r.id == run3.id),
            "a well-formed run must still be indexed/findable"
        );
        // ...and the malformed + no-extracted_data runs are absent from the index.
        assert!(!hits.iter().any(|r| r.id == run.id || r.id == run2.id));
    }

    #[tokio::test]
    async fn start_complete_fail_list() {
        let pool = pool().await;
        let wf = workflows::insert(&pool, &NewWorkflow { name: "wf".into(), ..Default::default() })
            .await
            .unwrap();

        let run = insert(
            &pool,
            &NewRun {
                workflow_id: Some(wf.id),
                trigger_type: Some("scheduled".into()),
                ..Default::default()
            },
        )
        .await
        .unwrap();
        assert_eq!(run.status, "running");
        assert_eq!(run.trigger_type, "scheduled");
        assert_eq!(run.success, None);
        assert_eq!(run.attempt_count, 1);
        assert_eq!(run.max_attempts, 3); // COALESCE default
        assert!(run.started_at.is_some());

        assert_eq!(list_by_status(&pool, "running", 50).await.unwrap().len(), 1);

        // NB: a RAW string — `\"` is NOT an escape here, so `r#"{\"ok\":true}"#`
        // would be the literal bytes `{\"ok\":true}`, which is malformed JSON.
        // Since 0022 the FTS triggers json_extract() this column on write, so a
        // malformed blob fails the UPDATE outright.
        let done = complete(&pool, run.id, Some(r#"{"ok":true}"#), Some(1234)).await.unwrap();
        assert_eq!(done.status, "success");
        assert_eq!(done.success, Some(1));
        assert_eq!(done.duration_ms, Some(1234));
        assert_eq!(done.result_data.as_deref(), Some(r#"{"ok":true}"#));
        assert!(done.completed_at.is_some());

        // a second, failing run
        let run2 = insert(&pool, &NewRun { workflow_id: Some(wf.id), ..Default::default() })
            .await
            .unwrap();
        assert_eq!(bump_attempt(&pool, run2.id).await.unwrap(), 2);
        let failed = fail(&pool, run2.id, "timeout", Some("slow"), Some("infra"), Some(99))
            .await
            .unwrap();
        assert_eq!(failed.status, "timeout");
        assert_eq!(failed.success, Some(0));
        assert_eq!(failed.failure_category.as_deref(), Some("infra"));

        assert_eq!(list(&pool, 50).await.unwrap().len(), 2);
        assert_eq!(list_by_workflow(&pool, wf.id, 50).await.unwrap().len(), 2);

        assert!(delete(&pool, run2.id).await.unwrap());
        assert_eq!(list(&pool, 50).await.unwrap().len(), 1);
    }

    /// Boot reconciliation flips every `running` row to `interrupted` and leaves terminal rows alone.
    #[tokio::test]
    async fn interrupt_running_reconciles_only_in_flight() {
        let pool = pool().await;
        let wf = workflows::insert(&pool, &NewWorkflow { name: "wf".into(), ..Default::default() })
            .await
            .unwrap();

        // Two in-flight runs + one already completed.
        let r1 = insert(&pool, &NewRun { workflow_id: Some(wf.id), ..Default::default() }).await.unwrap();
        let r2 = insert(&pool, &NewRun { workflow_id: Some(wf.id), ..Default::default() }).await.unwrap();
        let done = insert(&pool, &NewRun { workflow_id: Some(wf.id), ..Default::default() }).await.unwrap();
        complete(&pool, done.id, None, Some(1)).await.unwrap();

        assert_eq!(list_by_status(&pool, "running", 50).await.unwrap().len(), 2);

        let n = interrupt_running(&pool).await.unwrap();
        assert_eq!(n, 2, "both running rows reconciled");
        assert_eq!(list_by_status(&pool, "running", 50).await.unwrap().len(), 0);

        for id in [r1.id, r2.id] {
            let row = get_by_id(&pool, id).await.unwrap().unwrap();
            assert_eq!(row.status, "interrupted");
            assert_eq!(row.success, Some(0));
            assert_eq!(row.failure_category.as_deref(), Some("interrupted"));
            assert!(row.completed_at.is_some());
        }
        // The already-completed run is untouched.
        let still_done = get_by_id(&pool, done.id).await.unwrap().unwrap();
        assert_eq!(still_done.status, "success");

        // A second pass is a no-op (nothing left running).
        assert_eq!(interrupt_running(&pool).await.unwrap(), 0);
    }

    /// The FTS5 index (migration 0022) + its runs triggers make a completed run's extracted_data
    /// searchable: `search_fts` finds it by a prefix term, respects the workflow scope, and misses
    /// non-matching terms. Also proves markdown content (a `markdown` field) is indexed.
    #[tokio::test]
    async fn fts_search_over_extracted_data() {
        use crate::local::data_query::{fts5_match_query, parse_search_terms};
        let pool = pool().await;
        let wf1 = workflows::insert(&pool, &NewWorkflow { name: "shops".into(), ..Default::default() })
            .await
            .unwrap();
        let wf2 = workflows::insert(&pool, &NewWorkflow { name: "docs".into(), ..Default::default() })
            .await
            .unwrap();

        // wf1: a JSON record; wf2: a markdown document record.
        let r1 = insert(&pool, &NewRun { workflow_id: Some(wf1.id), ..Default::default() }).await.unwrap();
        complete(&pool, r1.id, Some(r#"{"extracted_data":[{"name":"Amazon Paris","price":"9"}]}"#), Some(1))
            .await
            .unwrap();
        let r2 = insert(&pool, &NewRun { workflow_id: Some(wf2.id), ..Default::default() }).await.unwrap();
        complete(&pool, r2.id, Some(r##"{"extracted_data":[{"markdown":"# Guide\nInstall the widget in Berlin."}]}"##), Some(1))
            .await
            .unwrap();

        let mq = |q: &str| fts5_match_query(&parse_search_terms(q));

        // Global prefix search finds the matching run, scoped to neither workflow.
        let hits = search_fts(&pool, &mq("amaz"), None, 50).await.unwrap();
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].id, r1.id);

        // Markdown content is searchable too.
        let md = search_fts(&pool, &mq("berlin"), None, 50).await.unwrap();
        assert_eq!(md.len(), 1);
        assert_eq!(md[0].id, r2.id);

        // Workflow scope narrows to that dataset only.
        assert_eq!(search_fts(&pool, &mq("amaz"), Some(wf2.id), 50).await.unwrap().len(), 0);
        assert_eq!(search_fts(&pool, &mq("amaz"), Some(wf1.id), 50).await.unwrap().len(), 1);

        // A non-matching term returns nothing.
        assert_eq!(search_fts(&pool, &mq("zzz"), None, 50).await.unwrap().len(), 0);

        // Deleting the run drops it from the index (trigger).
        assert!(delete(&pool, r1.id).await.unwrap());
        assert_eq!(search_fts(&pool, &mq("amaz"), None, 50).await.unwrap().len(), 0);
    }
}
