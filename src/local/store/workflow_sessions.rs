//! Store layer for `workflow_sessions` (0015_http_lane.sql): the per-workflow persisted auth session
//! the browserless HTTP lane reuses across runs.
//!
//! `session_state_encrypted` is a vault Layer-B sealed `SessionState` JSON blob (AAD
//! `workflow_sessions|session_state_encrypted|<workflow_id>`): NEVER logged. `extracted_at` is
//! duplicated outside the sealed blob so a TTL check never has to decrypt.

use super::super::error::LocalResult;
use sqlx::sqlite::SqlitePool;

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct WorkflowSession {
    pub workflow_id: i64,
    pub session_state_encrypted: Option<String>,
    pub extracted_at: Option<String>,
    pub engine: Option<String>,
    pub updated_at: String,
}

/// Fetch the persisted session for a workflow, if any.
pub async fn get(pool: &SqlitePool, workflow_id: i64) -> LocalResult<Option<WorkflowSession>> {
    let row = sqlx::query_as::<_, WorkflowSession>(
        "SELECT workflow_id, session_state_encrypted, extracted_at, engine, updated_at
         FROM workflow_sessions WHERE workflow_id = ?1",
    )
    .bind(workflow_id)
    .fetch_optional(pool)
    .await?;
    Ok(row)
}

/// Upsert the sealed session for a workflow. `engine` records which lane captured it ('http'|'browser').
pub async fn upsert(
    pool: &SqlitePool,
    workflow_id: i64,
    sealed: &str,
    extracted_at: &str,
    engine: &str,
) -> LocalResult<()> {
    sqlx::query(
        "INSERT INTO workflow_sessions (workflow_id, session_state_encrypted, extracted_at, engine, updated_at)
         VALUES (?1, ?2, ?3, ?4, strftime('%Y-%m-%dT%H:%M:%fZ','now'))
         ON CONFLICT(workflow_id) DO UPDATE SET
            session_state_encrypted = excluded.session_state_encrypted,
            extracted_at = excluded.extracted_at,
            engine = excluded.engine,
            updated_at = strftime('%Y-%m-%dT%H:%M:%fZ','now')",
    )
    .bind(workflow_id)
    .bind(sealed)
    .bind(extracted_at)
    .bind(engine)
    .execute(pool)
    .await?;
    Ok(())
}

/// Clear a workflow's persisted session (force a fresh login next run).
pub async fn clear(pool: &SqlitePool, workflow_id: i64) -> LocalResult<()> {
    sqlx::query("DELETE FROM workflow_sessions WHERE workflow_id = ?1")
        .bind(workflow_id)
        .execute(pool)
        .await?;
    Ok(())
}
