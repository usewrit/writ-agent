//! Store for the `automations` table — event→action rules (change_detected, webhook_received,
//! workflow_started/completed). Net-new Rust for the Writ Desktop local backend.
//!
//! Runtime-checked sqlx only (no compile-time macros). JSON-TEXT columns (conditions / actions /
//! blocks) stay `String`; callers serde them. See migrations/0001_init.sql §5 for the schema.

use super::super::error::LocalResult;
use sqlx::sqlite::SqlitePool;
use sqlx::Row;

/// Deserialize a JSON-TEXT column (conditions / actions / blocks) from the API accepting EITHER a
/// raw JSON string OR a parsed array/object — the cloud and the FlowBuilder send the PARSED shape
/// (`blocks: [...]`, `conditions: {...}`), not a pre-stringified string. Both normalize to the
/// stored JSON text; null/absent → None. Keeps the desktop request contract in step with cloud.
fn de_json_text<'de, D: serde::Deserializer<'de>>(d: D) -> Result<Option<String>, D::Error> {
    let v = <Option<serde_json::Value> as serde::Deserialize>::deserialize(d)?;
    Ok(match v {
        None | Some(serde_json::Value::Null) => None,
        Some(serde_json::Value::String(s)) => Some(s),
        Some(other) => Some(other.to_string()),
    })
}

/// One row of `automations`.
#[derive(Debug, Clone, sqlx::FromRow, serde::Serialize, serde::Deserialize)]
pub struct Automation {
    pub id: i64,
    #[serde(default)]
    pub target_id: Option<i64>,
    /// change_detected|webhook_received|workflow_started|workflow_completed
    pub event_type: String,
    #[serde(default)]
    pub target_selector_id: Option<i64>,
    #[serde(default)]
    pub workflow_id: Option<i64>,
    #[serde(default)]
    pub webhook_trigger_id: Option<i64>,
    pub name: String,
    #[serde(default)]
    pub description: Option<String>,
    /// boolean as i64 0/1
    pub enabled: i64,
    #[serde(default)]
    pub priority: Option<i64>,
    /// JSON-TEXT (object)
    pub conditions: String,
    /// JSON-TEXT (array): notify|workflow|return_data
    pub actions: String,
    /// JSON-TEXT (nullable)
    #[serde(default)]
    pub blocks: Option<String>,
    #[serde(default)]
    pub last_triggered_at: Option<String>,
    #[serde(default)]
    pub trigger_count: Option<i64>,
    pub created_at: String,
    #[serde(default)]
    pub updated_at: Option<String>,
}

/// Fields accepted on insert. Defaults in the schema fill anything left `None`.
#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct NewAutomation {
    #[serde(default)]
    pub target_id: Option<i64>,
    #[serde(default)]
    pub event_type: Option<String>,
    #[serde(default)]
    pub target_selector_id: Option<i64>,
    #[serde(default)]
    pub workflow_id: Option<i64>,
    #[serde(default)]
    pub webhook_trigger_id: Option<i64>,
    pub name: String,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub enabled: Option<i64>,
    #[serde(default)]
    pub priority: Option<i64>,
    /// JSON-TEXT object; defaults to `{}`. Accepts a parsed object or a JSON string.
    #[serde(default, deserialize_with = "de_json_text")]
    pub conditions: Option<String>,
    /// JSON-TEXT array; defaults to `[]`. Accepts a parsed array or a JSON string.
    #[serde(default, deserialize_with = "de_json_text")]
    pub actions: Option<String>,
    #[serde(default, deserialize_with = "de_json_text")]
    pub blocks: Option<String>,
}

/// Mutable fields for `update`. `None` leaves the existing value untouched (COALESCE).
#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct AutomationPatch {
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub event_type: Option<String>,
    #[serde(default)]
    pub target_id: Option<i64>,
    #[serde(default)]
    pub target_selector_id: Option<i64>,
    #[serde(default)]
    pub workflow_id: Option<i64>,
    #[serde(default)]
    pub webhook_trigger_id: Option<i64>,
    #[serde(default)]
    pub enabled: Option<i64>,
    #[serde(default)]
    pub priority: Option<i64>,
    #[serde(default, deserialize_with = "de_json_text")]
    pub conditions: Option<String>,
    #[serde(default, deserialize_with = "de_json_text")]
    pub actions: Option<String>,
    #[serde(default, deserialize_with = "de_json_text")]
    pub blocks: Option<String>,
}

/// Insert a new automation; returns the full inserted row.
pub async fn insert(pool: &SqlitePool, new: &NewAutomation) -> LocalResult<Automation> {
    let id: i64 = sqlx::query(
        r#"
        INSERT INTO automations
            (target_id, event_type, target_selector_id, workflow_id, webhook_trigger_id,
             name, description, enabled, priority, conditions, actions, blocks)
        VALUES
            (?1, COALESCE(?2, 'change_detected'), ?3, ?4, ?5,
             ?6, ?7, COALESCE(?8, 1), COALESCE(?9, 0),
             COALESCE(?10, '{}'), COALESCE(?11, '[]'), ?12)
        RETURNING id
        "#,
    )
    .bind(new.target_id)
    .bind(new.event_type.as_deref())
    .bind(new.target_selector_id)
    .bind(new.workflow_id)
    .bind(new.webhook_trigger_id)
    .bind(&new.name)
    .bind(new.description.as_deref())
    .bind(new.enabled)
    .bind(new.priority)
    .bind(new.conditions.as_deref())
    .bind(new.actions.as_deref())
    .bind(new.blocks.as_deref())
    .fetch_one(pool)
    .await?
    .try_get(0)?;

    tracing::info!(automation_id = id, name = %new.name, "automation inserted");
    get_by_id(pool, id)
        .await?
        .ok_or_else(|| super::super::error::LocalError::NotFound(format!("automation {id}")))
}

/// Fetch one automation by id.
pub async fn get_by_id(pool: &SqlitePool, id: i64) -> LocalResult<Option<Automation>> {
    let row = sqlx::query_as::<_, Automation>("SELECT * FROM automations WHERE id = ?1")
        .bind(id)
        .fetch_optional(pool)
        .await?;
    Ok(row)
}

/// List automations, newest first, capped at `limit`.
pub async fn list(pool: &SqlitePool, limit: i64) -> LocalResult<Vec<Automation>> {
    let rows = sqlx::query_as::<_, Automation>(
        "SELECT * FROM automations ORDER BY created_at DESC, id DESC LIMIT ?1",
    )
    .bind(limit)
    .fetch_all(pool)
    .await?;
    Ok(rows)
}

/// List automations attached to a target (enabled-first then newest), capped at `limit`.
pub async fn list_for_target(
    pool: &SqlitePool,
    target_id: i64,
    limit: i64,
) -> LocalResult<Vec<Automation>> {
    let rows = sqlx::query_as::<_, Automation>(
        r#"
        SELECT * FROM automations
        WHERE target_id = ?1
        ORDER BY enabled DESC, priority DESC, created_at DESC, id DESC
        LIMIT ?2
        "#,
    )
    .bind(target_id)
    .bind(limit)
    .fetch_all(pool)
    .await?;
    Ok(rows)
}

/// List enabled automations for a given event type (used by the dispatch path).
pub async fn list_enabled_for_event(
    pool: &SqlitePool,
    event_type: &str,
    limit: i64,
) -> LocalResult<Vec<Automation>> {
    let rows = sqlx::query_as::<_, Automation>(
        r#"
        SELECT * FROM automations
        WHERE enabled = 1 AND event_type = ?1
        ORDER BY priority DESC, id ASC
        LIMIT ?2
        "#,
    )
    .bind(event_type)
    .bind(limit)
    .fetch_all(pool)
    .await?;
    Ok(rows)
}

/// List ALL enabled automations (any event type), newest-first, capped at `limit`. Used by the
/// scheduler to scan for `scheduled`-rooted automations whose cadence has come due — those are not
/// dispatched from an incoming event, so they need a periodic pull, not `list_enabled_for_event`.
pub async fn list_enabled(pool: &SqlitePool, limit: i64) -> LocalResult<Vec<Automation>> {
    let rows = sqlx::query_as::<_, Automation>(
        "SELECT * FROM automations WHERE enabled = 1 ORDER BY priority DESC, id ASC LIMIT ?1",
    )
    .bind(limit)
    .fetch_all(pool)
    .await?;
    Ok(rows)
}

/// The enabled `webhook_received` automation bound to a given webhook trigger (highest priority,
/// newest first), if any. Used by the webhook ingress to divert a hook to its automation flow.
pub async fn find_by_webhook_trigger(
    pool: &SqlitePool,
    webhook_trigger_id: i64,
) -> LocalResult<Option<Automation>> {
    let row = sqlx::query_as::<_, Automation>(
        r#"
        SELECT * FROM automations
        WHERE enabled = 1 AND event_type = 'webhook_received' AND webhook_trigger_id = ?1
        ORDER BY priority DESC, id DESC
        LIMIT 1
        "#,
    )
    .bind(webhook_trigger_id)
    .fetch_optional(pool)
    .await?;
    Ok(row)
}

/// Patch mutable fields (COALESCE: `None` keeps the existing value). Bumps `updated_at`.
/// Returns the updated row, or `None` if no such id.
pub async fn update(
    pool: &SqlitePool,
    id: i64,
    patch: &AutomationPatch,
) -> LocalResult<Option<Automation>> {
    let affected = sqlx::query(
        r#"
        UPDATE automations SET
            name               = COALESCE(?2, name),
            description        = COALESCE(?3, description),
            event_type         = COALESCE(?4, event_type),
            target_id          = COALESCE(?5, target_id),
            target_selector_id = COALESCE(?6, target_selector_id),
            workflow_id        = COALESCE(?7, workflow_id),
            webhook_trigger_id = COALESCE(?8, webhook_trigger_id),
            enabled            = COALESCE(?9, enabled),
            priority           = COALESCE(?10, priority),
            conditions         = COALESCE(?11, conditions),
            actions            = COALESCE(?12, actions),
            blocks             = COALESCE(?13, blocks),
            updated_at         = strftime('%Y-%m-%dT%H:%M:%fZ','now')
        WHERE id = ?1
        "#,
    )
    .bind(id)
    .bind(patch.name.as_deref())
    .bind(patch.description.as_deref())
    .bind(patch.event_type.as_deref())
    .bind(patch.target_id)
    .bind(patch.target_selector_id)
    .bind(patch.workflow_id)
    .bind(patch.webhook_trigger_id)
    .bind(patch.enabled)
    .bind(patch.priority)
    .bind(patch.conditions.as_deref())
    .bind(patch.actions.as_deref())
    .bind(patch.blocks.as_deref())
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
        "UPDATE automations SET enabled = ?2, updated_at = strftime('%Y-%m-%dT%H:%M:%fZ','now') WHERE id = ?1",
    )
    .bind(id)
    .bind(enabled as i64)
    .execute(pool)
    .await?
    .rows_affected();
    Ok(affected > 0)
}

/// Record a trigger: stamp `last_triggered_at = now` and increment `trigger_count`.
pub async fn mark_triggered(pool: &SqlitePool, id: i64) -> LocalResult<bool> {
    let affected = sqlx::query(
        r#"
        UPDATE automations SET
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

/// Hard-delete an automation (executions cascade via FK). Returns `true` if a row was removed.
pub async fn delete(pool: &SqlitePool, id: i64) -> LocalResult<bool> {
    let affected = sqlx::query("DELETE FROM automations WHERE id = ?1")
        .bind(id)
        .execute(pool)
        .await?
        .rows_affected();
    if affected > 0 {
        tracing::info!(automation_id = id, "automation deleted");
    }
    Ok(affected > 0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::local::db;

    #[test]
    fn new_automation_accepts_parsed_or_stringified_json_fields() {
        // The FlowBuilder + cloud send PARSED blocks/actions/conditions; a legacy caller may send a
        // pre-stringified string. Both must normalize to the stored JSON text.
        let parsed: NewAutomation = serde_json::from_value(serde_json::json!({
            "name": "a",
            "conditions": { "max_fires": 1 },
            "actions": [{ "type": "notification", "config": {} }],
            "blocks": [{ "id": "e", "type": "event", "blockType": "change_detected", "config": {} }],
        })).unwrap();
        assert_eq!(parsed.conditions.as_deref(), Some("{\"max_fires\":1}"));
        assert!(parsed.actions.as_deref().unwrap().contains("\"notification\""));
        assert!(parsed.blocks.as_deref().unwrap().contains("\"change_detected\""));

        let stringified: NewAutomation = serde_json::from_value(serde_json::json!({
            "name": "b",
            "blocks": "[{\"id\":\"e\"}]",
        })).unwrap();
        assert_eq!(stringified.blocks.as_deref(), Some("[{\"id\":\"e\"}]"));

        // Absent → None (schema defaults fill on insert).
        let bare: NewAutomation = serde_json::from_value(serde_json::json!({ "name": "c" })).unwrap();
        assert!(bare.blocks.is_none() && bare.actions.is_none() && bare.conditions.is_none());
    }

    async fn pool() -> SqlitePool {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("t.db");
        // keep the tempdir alive for the duration of the pool
        std::mem::forget(dir);
        db::open(&path, "test-key").await.unwrap()
    }

    #[tokio::test]
    async fn crud_roundtrip() {
        let pool = pool().await;
        let created = insert(
            &pool,
            &NewAutomation {
                name: "notify on change".into(),
                event_type: Some("change_detected".into()),
                actions: Some(r#"[{\"type\":\"notify\"}]"#.into()),
                ..Default::default()
            },
        )
        .await
        .unwrap();
        assert!(created.id > 0);
        assert_eq!(created.enabled, 1);
        assert_eq!(created.conditions, "{}");
        assert_eq!(created.actions, r#"[{\"type\":\"notify\"}]"#);

        let got = get_by_id(&pool, created.id).await.unwrap().unwrap();
        assert_eq!(got.name, "notify on change");

        let patched = update(
            &pool,
            created.id,
            &AutomationPatch {
                name: Some("renamed".into()),
                enabled: Some(0),
                ..Default::default()
            },
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(patched.name, "renamed");
        assert_eq!(patched.enabled, 0);
        assert!(patched.updated_at.is_some());

        assert!(mark_triggered(&pool, created.id).await.unwrap());
        let bumped = get_by_id(&pool, created.id).await.unwrap().unwrap();
        assert_eq!(bumped.trigger_count, Some(1));
        assert!(bumped.last_triggered_at.is_some());

        assert!(set_enabled(&pool, created.id, true).await.unwrap());
        let all = list(&pool, 10).await.unwrap();
        assert_eq!(all.len(), 1);

        assert!(delete(&pool, created.id).await.unwrap());
        assert!(get_by_id(&pool, created.id).await.unwrap().is_none());
    }
}
