//! Store for `webhook_triggers` — inbound HTTP triggers (token + optional custom path) that run a
//! workflow or fire a target check. Net-new Rust for the Writ Desktop local backend.
//!
//! Runtime-checked sqlx only (no compile-time macros). `secret_encrypted` is a Layer-B WF1
//! ciphertext column — it is NEVER logged or returned in trace output. JSON-TEXT columns
//! (payload_mapping / conditions) stay `String`; callers serde them. See migrations/0001_init.sql §5.

use super::super::error::LocalResult;
use sqlx::sqlite::SqlitePool;
use sqlx::Row;

/// One row of `webhook_triggers`. `secret_encrypted` carries WF1 ciphertext — do not log it.
/// `Debug` is hand-written (see the `store` module docs). `token` is a PLAINTEXT bearer credential —
/// whoever holds it can fire this trigger — and `secret_encrypted` is the HMAC signing secret. Neither
/// belongs in a log line, which is where a derived `Debug` put both.
#[derive(Clone, sqlx::FromRow, serde::Serialize, serde::Deserialize)]
pub struct WebhookTrigger {
    pub id: i64,
    pub token: String,
    pub name: String,
    /// boolean as i64 0/1
    pub enabled: i64,
    /// WF1 ciphertext (nullable) — never logged.
    #[serde(default)]
    pub secret_encrypted: Option<String>,
    #[serde(default)]
    pub workflow_id: Option<i64>,
    #[serde(default)]
    pub target_id: Option<i64>,
    /// run_workflow|check_target|... (schema default 'run_workflow')
    pub action: String,
    /// JSON-TEXT (nullable)
    #[serde(default)]
    pub payload_mapping: Option<String>,
    /// JSON-TEXT (nullable)
    #[serde(default)]
    pub conditions: Option<String>,
    /// boolean as i64 0/1
    pub wait_for_result: i64,
    pub wait_timeout: i64,
    #[serde(default)]
    pub custom_path: Option<String>,
    #[serde(default)]
    pub function_name: Option<String>,
    #[serde(default)]
    pub last_triggered_at: Option<String>,
    #[serde(default)]
    pub trigger_count: Option<i64>,
    pub created_at: String,
    #[serde(default)]
    pub updated_at: Option<String>,
}

/// Fields accepted on insert. `token` is the caller-minted unique handle; schema defaults fill
/// `enabled` (1), `action` ('run_workflow'), `wait_for_result` (0), `wait_timeout` (120).
/// `Debug` redacts `token` + `secret_encrypted`, like [`WebhookTrigger`].
#[derive(Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct NewWebhookTrigger {
    pub token: String,
    pub name: String,
    #[serde(default)]
    pub enabled: Option<i64>,
    /// WF1 ciphertext (nullable) — never logged.
    #[serde(default)]
    pub secret_encrypted: Option<String>,
    #[serde(default)]
    pub workflow_id: Option<i64>,
    #[serde(default)]
    pub target_id: Option<i64>,
    #[serde(default)]
    pub action: Option<String>,
    #[serde(default)]
    pub payload_mapping: Option<String>,
    #[serde(default)]
    pub conditions: Option<String>,
    #[serde(default)]
    pub wait_for_result: Option<i64>,
    #[serde(default)]
    pub wait_timeout: Option<i64>,
    #[serde(default)]
    pub custom_path: Option<String>,
    #[serde(default)]
    pub function_name: Option<String>,
}

/// Mutable fields for `update`. `None` leaves the existing value untouched (COALESCE).
/// `token` is immutable (it's the routing handle) and so is not patchable here.
/// `Debug` redacts `secret_encrypted`, like [`WebhookTrigger`].
#[derive(Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct WebhookTriggerPatch {
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub enabled: Option<i64>,
    /// WF1 ciphertext (nullable) — never logged.
    #[serde(default)]
    pub secret_encrypted: Option<String>,
    #[serde(default)]
    pub workflow_id: Option<i64>,
    #[serde(default)]
    pub target_id: Option<i64>,
    #[serde(default)]
    pub action: Option<String>,
    #[serde(default)]
    pub payload_mapping: Option<String>,
    #[serde(default)]
    pub conditions: Option<String>,
    #[serde(default)]
    pub wait_for_result: Option<i64>,
    #[serde(default)]
    pub wait_timeout: Option<i64>,
    #[serde(default)]
    pub custom_path: Option<String>,
    #[serde(default)]
    pub function_name: Option<String>,
}

/// Insert a new webhook trigger; returns the full inserted row.
pub async fn insert(pool: &SqlitePool, new: &NewWebhookTrigger) -> LocalResult<WebhookTrigger> {
    let id: i64 = sqlx::query(
        r#"
        INSERT INTO webhook_triggers
            (token, name, enabled, secret_encrypted, workflow_id, target_id, action,
             payload_mapping, conditions, wait_for_result, wait_timeout, custom_path, function_name)
        VALUES
            (?1, ?2, COALESCE(?3, 1), ?4, ?5, ?6, COALESCE(?7, 'run_workflow'),
             ?8, ?9, COALESCE(?10, 0), COALESCE(?11, 120), ?12, ?13)
        RETURNING id
        "#,
    )
    .bind(&new.token)
    .bind(&new.name)
    .bind(new.enabled)
    .bind(new.secret_encrypted.as_deref())
    .bind(new.workflow_id)
    .bind(new.target_id)
    .bind(new.action.as_deref())
    .bind(new.payload_mapping.as_deref())
    .bind(new.conditions.as_deref())
    .bind(new.wait_for_result)
    .bind(new.wait_timeout)
    .bind(new.custom_path.as_deref())
    .bind(new.function_name.as_deref())
    .fetch_one(pool)
    .await?
    .try_get(0)?;

    // NOTE: never log token/secret_encrypted values.
    tracing::info!(webhook_trigger_id = id, name = %new.name, "webhook trigger inserted");
    get_by_id(pool, id)
        .await?
        .ok_or_else(|| super::super::error::LocalError::NotFound(format!("webhook_trigger {id}")))
}

/// Fetch one trigger by id.
pub async fn get_by_id(pool: &SqlitePool, id: i64) -> LocalResult<Option<WebhookTrigger>> {
    let row = sqlx::query_as::<_, WebhookTrigger>("SELECT * FROM webhook_triggers WHERE id = ?1")
        .bind(id)
        .fetch_optional(pool)
        .await?;
    Ok(row)
}

/// Resolve a trigger by its unique routing `token` (inbound-request lookup).
pub async fn get_by_token(pool: &SqlitePool, token: &str) -> LocalResult<Option<WebhookTrigger>> {
    let row = sqlx::query_as::<_, WebhookTrigger>("SELECT * FROM webhook_triggers WHERE token = ?1")
        .bind(token)
        .fetch_optional(pool)
        .await?;
    Ok(row)
}

/// Resolve a trigger by its unique `custom_path` (pretty-URL inbound lookup).
pub async fn get_by_custom_path(
    pool: &SqlitePool,
    custom_path: &str,
) -> LocalResult<Option<WebhookTrigger>> {
    let row =
        sqlx::query_as::<_, WebhookTrigger>("SELECT * FROM webhook_triggers WHERE custom_path = ?1")
            .bind(custom_path)
            .fetch_optional(pool)
            .await?;
    Ok(row)
}

/// List triggers, newest first, capped at `limit`.
pub async fn list(pool: &SqlitePool, limit: i64) -> LocalResult<Vec<WebhookTrigger>> {
    let rows = sqlx::query_as::<_, WebhookTrigger>(
        "SELECT * FROM webhook_triggers ORDER BY created_at DESC, id DESC LIMIT ?1",
    )
    .bind(limit)
    .fetch_all(pool)
    .await?;
    Ok(rows)
}

/// List triggers bound to a workflow, newest first, capped at `limit`.
pub async fn list_for_workflow(
    pool: &SqlitePool,
    workflow_id: i64,
    limit: i64,
) -> LocalResult<Vec<WebhookTrigger>> {
    let rows = sqlx::query_as::<_, WebhookTrigger>(
        r#"
        SELECT * FROM webhook_triggers
        WHERE workflow_id = ?1
        ORDER BY created_at DESC, id DESC
        LIMIT ?2
        "#,
    )
    .bind(workflow_id)
    .bind(limit)
    .fetch_all(pool)
    .await?;
    Ok(rows)
}

/// Patch mutable fields (COALESCE: `None` keeps the existing value). Bumps `updated_at`.
/// Returns the updated row, or `None` if no such id.
pub async fn update(
    pool: &SqlitePool,
    id: i64,
    patch: &WebhookTriggerPatch,
) -> LocalResult<Option<WebhookTrigger>> {
    let affected = sqlx::query(
        r#"
        UPDATE webhook_triggers SET
            name            = COALESCE(?2, name),
            enabled         = COALESCE(?3, enabled),
            secret_encrypted = COALESCE(?4, secret_encrypted),
            workflow_id     = COALESCE(?5, workflow_id),
            target_id       = COALESCE(?6, target_id),
            action          = COALESCE(?7, action),
            payload_mapping = COALESCE(?8, payload_mapping),
            conditions      = COALESCE(?9, conditions),
            wait_for_result = COALESCE(?10, wait_for_result),
            wait_timeout    = COALESCE(?11, wait_timeout),
            custom_path     = COALESCE(?12, custom_path),
            function_name   = COALESCE(?13, function_name),
            updated_at      = strftime('%Y-%m-%dT%H:%M:%fZ','now')
        WHERE id = ?1
        "#,
    )
    .bind(id)
    .bind(patch.name.as_deref())
    .bind(patch.enabled)
    .bind(patch.secret_encrypted.as_deref())
    .bind(patch.workflow_id)
    .bind(patch.target_id)
    .bind(patch.action.as_deref())
    .bind(patch.payload_mapping.as_deref())
    .bind(patch.conditions.as_deref())
    .bind(patch.wait_for_result)
    .bind(patch.wait_timeout)
    .bind(patch.custom_path.as_deref())
    .bind(patch.function_name.as_deref())
    .execute(pool)
    .await?
    .rows_affected();

    if affected == 0 {
        return Ok(None);
    }
    get_by_id(pool, id).await
}

/// Toggle the `enabled` flag. Returns `true` if a row was updated.
pub async fn set_enabled(pool: &SqlitePool, id: i64, enabled: bool) -> LocalResult<bool> {
    let affected = sqlx::query(
        "UPDATE webhook_triggers SET enabled = ?2, updated_at = strftime('%Y-%m-%dT%H:%M:%fZ','now') WHERE id = ?1",
    )
    .bind(id)
    .bind(enabled as i64)
    .execute(pool)
    .await?
    .rows_affected();
    Ok(affected > 0)
}

/// Record a fire: stamp `last_triggered_at = now` and increment `trigger_count`.
pub async fn mark_triggered(pool: &SqlitePool, id: i64) -> LocalResult<bool> {
    let affected = sqlx::query(
        r#"
        UPDATE webhook_triggers SET
            last_triggered_at = strftime('%Y-%m-%dT%H:%M:%fZ','now'),
            trigger_count = COALESCE(trigger_count, 0) + 1
        WHERE id = ?1
        "#,
    )
    .bind(id)
    .execute(pool)
    .await?
    .rows_affected();
    Ok(affected > 0)
}

/// Hard-delete a trigger. Returns `true` if a row was removed.
pub async fn delete(pool: &SqlitePool, id: i64) -> LocalResult<bool> {
    let affected = sqlx::query("DELETE FROM webhook_triggers WHERE id = ?1")
        .bind(id)
        .execute(pool)
        .await?
        .rows_affected();
    if affected > 0 {
        tracing::info!(webhook_trigger_id = id, "webhook trigger deleted");
    }
    Ok(affected > 0)
}

impl std::fmt::Debug for WebhookTrigger {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WebhookTrigger")
            .field("id", &self.id)
            .field("name", &self.name)
            .field("enabled", &self.enabled)
            .field("action", &self.action)
            .field("workflow_id", &self.workflow_id)
            .field("target_id", &self.target_id)
            .field("custom_path", &self.custom_path)
            // The URL token is a bearer credential; the secret signs payloads.
            .field("token", &super::REDACTED)
            .field("secret_encrypted", &super::redacted(&self.secret_encrypted))
            .finish_non_exhaustive()
    }
}

impl std::fmt::Debug for NewWebhookTrigger {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NewWebhookTrigger")
            .field("name", &self.name)
            .field("action", &self.action)
            .field("workflow_id", &self.workflow_id)
            .field("target_id", &self.target_id)
            .field("custom_path", &self.custom_path)
            .field("token", &super::REDACTED)
            .field("secret_encrypted", &super::redacted(&self.secret_encrypted))
            .finish_non_exhaustive()
    }
}

impl std::fmt::Debug for WebhookTriggerPatch {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WebhookTriggerPatch")
            .field("name", &self.name)
            .field("action", &self.action)
            .field("enabled", &self.enabled)
            .field("custom_path", &self.custom_path)
            .field("secret_encrypted", &super::redacted(&self.secret_encrypted))
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::local::db;

    async fn pool() -> SqlitePool {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("t.db");
        std::mem::forget(dir);
        db::open(&path, "test-key").await.unwrap()
    }

    #[tokio::test]
    async fn crud_and_lookups() {
        let pool = pool().await;
        let created = insert(
            &pool,
            &NewWebhookTrigger {
                token: "tok_abc123".into(),
                name: "inbound run".into(),
                custom_path: Some("deploy-hook".into()),
                secret_encrypted: Some("WF1:ZmFrZQ==".into()),
                ..Default::default()
            },
        )
        .await
        .unwrap();
        assert!(created.id > 0);
        assert_eq!(created.enabled, 1);
        assert_eq!(created.action, "run_workflow");
        assert_eq!(created.wait_timeout, 120);

        let by_token = get_by_token(&pool, "tok_abc123").await.unwrap().unwrap();
        assert_eq!(by_token.id, created.id);
        let by_path = get_by_custom_path(&pool, "deploy-hook")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(by_path.id, created.id);

        let patched = update(
            &pool,
            created.id,
            &WebhookTriggerPatch {
                name: Some("renamed hook".into()),
                wait_for_result: Some(1),
                ..Default::default()
            },
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(patched.name, "renamed hook");
        assert_eq!(patched.wait_for_result, 1);
        // secret untouched by COALESCE patch
        assert_eq!(patched.secret_encrypted.as_deref(), Some("WF1:ZmFrZQ=="));

        assert!(set_enabled(&pool, created.id, false).await.unwrap());
        assert!(mark_triggered(&pool, created.id).await.unwrap());
        let bumped = get_by_id(&pool, created.id).await.unwrap().unwrap();
        assert_eq!(bumped.enabled, 0);
        assert_eq!(bumped.trigger_count, Some(1));

        assert_eq!(list(&pool, 10).await.unwrap().len(), 1);

        assert!(delete(&pool, created.id).await.unwrap());
        assert!(get_by_token(&pool, "tok_abc123").await.unwrap().is_none());
    }
}
