//! AI auto-repair history — one row per recipe-level repair (whole-workflow rewrite or autonomous
//! re-record), so the UI can show what changed and offer a revert. Selector-only in-place fixes are
//! not recorded here. See migration `0021_workflow_repair_history.sql`.

use serde::Serialize;
use sqlx::SqlitePool;

use crate::local::error::LocalResult;

/// One recorded repair. `old_steps`/`new_steps` are JSON-text snapshots of the steps array.
#[derive(Debug, Clone, sqlx::FromRow, Serialize)]
pub struct RepairHistoryRow {
    pub id: i64,
    pub workflow_id: i64,
    pub repaired_at: String,
    pub kind: String,
    pub old_steps: String,
    pub new_steps: Option<String>,
    pub note: Option<String>,
}

/// Append a repair-history entry. `kind` is `"recipe"` (whole-workflow rewrite) or `"re_record"`
/// (autonomous). `old_steps`/`new_steps` are the steps arrays serialized to JSON text.
pub async fn record(
    pool: &SqlitePool,
    workflow_id: i64,
    kind: &str,
    old_steps: &str,
    new_steps: Option<&str>,
    note: Option<&str>,
) -> LocalResult<()> {
    sqlx::query(
        "INSERT INTO workflow_repair_history (workflow_id, kind, old_steps, new_steps, note)
         VALUES (?1, ?2, ?3, ?4, ?5)",
    )
    .bind(workflow_id)
    .bind(kind)
    .bind(old_steps)
    .bind(new_steps)
    .bind(note)
    .execute(pool)
    .await?;
    Ok(())
}

/// The repair history for a workflow, newest first.
pub async fn list_for_workflow(pool: &SqlitePool, workflow_id: i64) -> LocalResult<Vec<RepairHistoryRow>> {
    let rows = sqlx::query_as::<_, RepairHistoryRow>(
        "SELECT id, workflow_id, repaired_at, kind, old_steps, new_steps, note
         FROM workflow_repair_history WHERE workflow_id = ?1 ORDER BY id DESC",
    )
    .bind(workflow_id)
    .fetch_all(pool)
    .await?;
    Ok(rows)
}
