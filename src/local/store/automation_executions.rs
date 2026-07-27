//! Store for `automation_executions` — one row per time an automation fires (its lifecycle +
//! per-action results). Net-new Rust for the Writ Desktop local backend.
//!
//! Runtime-checked sqlx only (no compile-time macros). JSON-TEXT columns (trigger_context /
//! action_results) stay `String`; callers serde them. See migrations/0001_init.sql §5.

use super::super::error::LocalResult;
use sqlx::sqlite::SqlitePool;
use sqlx::Row;

/// One row of `automation_executions`.
#[derive(Debug, Clone, sqlx::FromRow, serde::Serialize, serde::Deserialize)]
pub struct AutomationExecution {
    pub id: i64,
    pub automation_id: i64,
    #[serde(default)]
    pub change_id: Option<i64>,
    /// pending|running|success|failed (free-form; schema default 'pending')
    #[serde(default)]
    pub status: Option<String>,
    /// JSON-TEXT (nullable)
    #[serde(default)]
    pub trigger_context: Option<String>,
    /// JSON-TEXT array; defaults to `[]`.
    pub action_results: String,
    pub triggered_at: String,
    #[serde(default)]
    pub completed_at: Option<String>,
    #[serde(default)]
    pub error_message: Option<String>,
}

/// Fields accepted on insert. Schema defaults fill `status` ('pending') / `action_results` ('[]').
#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct NewAutomationExecution {
    pub automation_id: i64,
    #[serde(default)]
    pub change_id: Option<i64>,
    #[serde(default)]
    pub status: Option<String>,
    /// JSON-TEXT (nullable)
    #[serde(default)]
    pub trigger_context: Option<String>,
    /// JSON-TEXT array; defaults to `[]`.
    #[serde(default)]
    pub action_results: Option<String>,
}

/// Insert a pending/running execution; returns the full inserted row.
pub async fn insert(
    pool: &SqlitePool,
    new: &NewAutomationExecution,
) -> LocalResult<AutomationExecution> {
    let id: i64 = sqlx::query(
        r#"
        INSERT INTO automation_executions
            (automation_id, change_id, status, trigger_context, action_results)
        VALUES
            (?1, ?2, COALESCE(?3, 'pending'), ?4, COALESCE(?5, '[]'))
        RETURNING id
        "#,
    )
    .bind(new.automation_id)
    .bind(new.change_id)
    .bind(new.status.as_deref())
    .bind(new.trigger_context.as_deref())
    .bind(new.action_results.as_deref())
    .fetch_one(pool)
    .await?
    .try_get(0)?;

    tracing::info!(
        execution_id = id,
        automation_id = new.automation_id,
        "automation execution started"
    );
    get_by_id(pool, id)
        .await?
        .ok_or_else(|| super::super::error::LocalError::NotFound(format!("automation_execution {id}")))
}

/// Fetch one execution by id.
pub async fn get_by_id(pool: &SqlitePool, id: i64) -> LocalResult<Option<AutomationExecution>> {
    let row =
        sqlx::query_as::<_, AutomationExecution>("SELECT * FROM automation_executions WHERE id = ?1")
            .bind(id)
            .fetch_optional(pool)
            .await?;
    Ok(row)
}

/// List executions, newest first, capped at `limit`.
pub async fn list(pool: &SqlitePool, limit: i64) -> LocalResult<Vec<AutomationExecution>> {
    let rows = sqlx::query_as::<_, AutomationExecution>(
        "SELECT * FROM automation_executions ORDER BY triggered_at DESC, id DESC LIMIT ?1",
    )
    .bind(limit)
    .fetch_all(pool)
    .await?;
    Ok(rows)
}

/// List executions for one automation, newest first, capped at `limit`.
pub async fn list_for_automation(
    pool: &SqlitePool,
    automation_id: i64,
    limit: i64,
) -> LocalResult<Vec<AutomationExecution>> {
    let rows = sqlx::query_as::<_, AutomationExecution>(
        r#"
        SELECT * FROM automation_executions
        WHERE automation_id = ?1
        ORDER BY triggered_at DESC, id DESC
        LIMIT ?2
        "#,
    )
    .bind(automation_id)
    .bind(limit)
    .fetch_all(pool)
    .await?;
    Ok(rows)
}

/// Update the live `status` and (optionally) the rolling `action_results` JSON. Does NOT stamp
/// completion — use [`complete`] for terminal states. Returns `true` if a row was updated.
pub async fn set_status(
    pool: &SqlitePool,
    id: i64,
    status: &str,
    action_results: Option<&str>,
) -> LocalResult<bool> {
    let affected = sqlx::query(
        r#"
        UPDATE automation_executions SET
            status = ?2,
            action_results = COALESCE(?3, action_results)
        WHERE id = ?1
        "#,
    )
    .bind(id)
    .bind(status)
    .bind(action_results)
    .execute(pool)
    .await?
    .rows_affected();
    Ok(affected > 0)
}

/// Stamp a terminal state: set `status`, `completed_at = now`, final `action_results`, and an
/// optional `error_message`. Returns the updated row, or `None` if no such id.
pub async fn complete(
    pool: &SqlitePool,
    id: i64,
    status: &str,
    action_results: Option<&str>,
    error_message: Option<&str>,
) -> LocalResult<Option<AutomationExecution>> {
    let affected = sqlx::query(
        r#"
        UPDATE automation_executions SET
            status = ?2,
            action_results = COALESCE(?3, action_results),
            error_message = ?4,
            completed_at = strftime('%Y-%m-%dT%H:%M:%fZ','now')
        WHERE id = ?1
        "#,
    )
    .bind(id)
    .bind(status)
    .bind(action_results)
    .bind(error_message)
    .execute(pool)
    .await?
    .rows_affected();

    if affected == 0 {
        return Ok(None);
    }
    tracing::info!(execution_id = id, status, "automation execution completed");
    get_by_id(pool, id).await
}

/// Hard-delete an execution row. Returns `true` if a row was removed.
pub async fn delete(pool: &SqlitePool, id: i64) -> LocalResult<bool> {
    let affected = sqlx::query("DELETE FROM automation_executions WHERE id = ?1")
        .bind(id)
        .execute(pool)
        .await?
        .rows_affected();
    Ok(affected > 0)
}

/// Prune executions for an automation older than `keep` most-recent rows (retention cap).
/// Returns the number of rows deleted.
pub async fn prune_for_automation(
    pool: &SqlitePool,
    automation_id: i64,
    keep: i64,
) -> LocalResult<u64> {
    let deleted = sqlx::query(
        r#"
        DELETE FROM automation_executions
        WHERE automation_id = ?1
          AND id NOT IN (
              SELECT id FROM automation_executions
              WHERE automation_id = ?1
              ORDER BY triggered_at DESC, id DESC
              LIMIT ?2
          )
        "#,
    )
    .bind(automation_id)
    .bind(keep)
    .execute(pool)
    .await?
    .rows_affected();
    Ok(deleted)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::local::db;
    use crate::local::store::automations::{self, NewAutomation};

    async fn pool() -> SqlitePool {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("t.db");
        std::mem::forget(dir);
        db::open(&path, "test-key").await.unwrap()
    }

    #[tokio::test]
    async fn lifecycle_roundtrip() {
        let pool = pool().await;
        // FK: automation_executions.automation_id NOT NULL → need a parent automation.
        let auto = automations::insert(
            &pool,
            &NewAutomation {
                name: "parent".into(),
                ..Default::default()
            },
        )
        .await
        .unwrap();

        let exec = insert(
            &pool,
            &NewAutomationExecution {
                automation_id: auto.id,
                trigger_context: Some(r#"{\"source\":\"change\"}"#.into()),
                ..Default::default()
            },
        )
        .await
        .unwrap();
        assert_eq!(exec.status.as_deref(), Some("pending"));
        assert_eq!(exec.action_results, "[]");

        assert!(set_status(&pool, exec.id, "running", None).await.unwrap());

        let done = complete(
            &pool,
            exec.id,
            "success",
            Some(r#"[{\"action\":\"notify\",\"ok\":true}]"#),
            None,
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(done.status.as_deref(), Some("success"));
        assert!(done.completed_at.is_some());
        assert_eq!(done.action_results, r#"[{\"action\":\"notify\",\"ok\":true}]"#);

        let listed = list_for_automation(&pool, auto.id, 10).await.unwrap();
        assert_eq!(listed.len(), 1);

        assert!(delete(&pool, exec.id).await.unwrap());
        assert!(get_by_id(&pool, exec.id).await.unwrap().is_none());
    }
}
