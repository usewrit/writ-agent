//! Store for `notification_connectors` — reusable "fast connector" notification destinations
//! (Slack / Discord / Telegram) referenced from automation notification blocks via the unified
//! `provider:id` recipient format. The LOCAL mirror of the cloud slack/discord/telegram recipient
//! tables, collapsed into ONE table keyed by `provider` (no tenant/user columns locally).
//!
//! Runtime-checked sqlx only (no compile-time macros). `webhook_url` / `bot_token` are
//! credential-bearing — they are NEVER logged. The whole DB is SQLCipher-encrypted at rest, so these
//! columns inherit encryption at rest (matching migrations/0010_notification_connectors.sql).

use super::super::error::LocalResult;
use sqlx::sqlite::SqlitePool;
use sqlx::Row;

/// One row of `notification_connectors`. `webhook_url` / `bot_token` carry secrets — do not log them.
/// `Debug` is hand-written (see the `store` module docs). A Slack/Discord `webhook_url` IS the
/// credential (anyone with the URL can post to the channel) and `bot_token` is a bearer token; a
/// derived `Debug` printed both.
#[derive(Clone, sqlx::FromRow, serde::Serialize, serde::Deserialize)]
pub struct NotificationConnector {
    pub id: i64,
    /// 'slack' | 'discord' | 'telegram'
    pub provider: String,
    pub name: String,
    /// slack/discord incoming-webhook URL (secret, nullable). NEVER log.
    #[serde(default)]
    pub webhook_url: Option<String>,
    /// telegram bot token (secret, nullable). NEVER log.
    #[serde(default)]
    pub bot_token: Option<String>,
    /// telegram chat id (non-secret, nullable).
    #[serde(default)]
    pub chat_id: Option<String>,
    /// boolean as i64 0/1
    pub enabled: i64,
    pub created_at: String,
}

/// Fields accepted on insert. `enabled` defaults to 1 (on) when omitted.
/// `Debug` redacts the credential fields, like [`NotificationConnector`].
#[derive(Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct NewNotificationConnector {
    pub provider: String,
    pub name: String,
    #[serde(default)]
    pub webhook_url: Option<String>,
    #[serde(default)]
    pub bot_token: Option<String>,
    #[serde(default)]
    pub chat_id: Option<String>,
    #[serde(default)]
    pub enabled: Option<i64>,
}

/// Insert a new connector; returns the full inserted row.
pub async fn insert(
    pool: &SqlitePool,
    new: &NewNotificationConnector,
) -> LocalResult<NotificationConnector> {
    let id: i64 = sqlx::query(
        r#"
        INSERT INTO notification_connectors
            (provider, name, webhook_url, bot_token, chat_id, enabled)
        VALUES
            (?1, ?2, ?3, ?4, ?5, COALESCE(?6, 1))
        RETURNING id
        "#,
    )
    .bind(&new.provider)
    .bind(&new.name)
    .bind(new.webhook_url.as_deref())
    .bind(new.bot_token.as_deref())
    .bind(new.chat_id.as_deref())
    .bind(new.enabled)
    .fetch_one(pool)
    .await?
    .try_get(0)?;

    // NOTE: never log webhook_url / bot_token values.
    tracing::info!(connector_id = id, provider = %new.provider, name = %new.name, "notification connector inserted");
    get_by_id(pool, id)
        .await?
        .ok_or_else(|| super::super::error::LocalError::NotFound(format!("notification_connector {id}")))
}

/// Fetch one connector by id.
pub async fn get_by_id(pool: &SqlitePool, id: i64) -> LocalResult<Option<NotificationConnector>> {
    let row = sqlx::query_as::<_, NotificationConnector>(
        "SELECT * FROM notification_connectors WHERE id = ?1",
    )
    .bind(id)
    .fetch_optional(pool)
    .await?;
    Ok(row)
}

/// List all connectors, newest first.
pub async fn list(pool: &SqlitePool) -> LocalResult<Vec<NotificationConnector>> {
    let rows = sqlx::query_as::<_, NotificationConnector>(
        "SELECT * FROM notification_connectors ORDER BY created_at DESC, id DESC",
    )
    .fetch_all(pool)
    .await?;
    Ok(rows)
}

/// List enabled connectors for a given provider (the "notify all enabled" fallback source).
pub async fn list_by_provider_enabled(
    pool: &SqlitePool,
    provider: &str,
) -> LocalResult<Vec<NotificationConnector>> {
    let rows = sqlx::query_as::<_, NotificationConnector>(
        r#"
        SELECT * FROM notification_connectors
        WHERE provider = ?1 AND enabled = 1
        ORDER BY created_at DESC, id DESC
        "#,
    )
    .bind(provider)
    .fetch_all(pool)
    .await?;
    Ok(rows)
}

/// Toggle the `enabled` flag. Returns `true` if a row was updated.
pub async fn set_enabled(pool: &SqlitePool, id: i64, enabled: bool) -> LocalResult<bool> {
    let affected = sqlx::query("UPDATE notification_connectors SET enabled = ?2 WHERE id = ?1")
        .bind(id)
        .bind(enabled as i64)
        .execute(pool)
        .await?
        .rows_affected();
    Ok(affected > 0)
}

/// Flip `enabled` to its opposite in one statement; returns the updated row (or `None` if no such id).
pub async fn toggle(pool: &SqlitePool, id: i64) -> LocalResult<Option<NotificationConnector>> {
    let affected =
        sqlx::query("UPDATE notification_connectors SET enabled = 1 - enabled WHERE id = ?1")
            .bind(id)
            .execute(pool)
            .await?
            .rows_affected();
    if affected == 0 {
        return Ok(None);
    }
    get_by_id(pool, id).await
}

/// Hard-delete a connector. Returns `true` if a row was removed.
pub async fn delete(pool: &SqlitePool, id: i64) -> LocalResult<bool> {
    let affected = sqlx::query("DELETE FROM notification_connectors WHERE id = ?1")
        .bind(id)
        .execute(pool)
        .await?
        .rows_affected();
    if affected > 0 {
        tracing::info!(connector_id = id, "notification connector deleted");
    }
    Ok(affected > 0)
}

impl std::fmt::Debug for NotificationConnector {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NotificationConnector")
            .field("id", &self.id)
            .field("provider", &self.provider)
            .field("name", &self.name)
            .field("enabled", &self.enabled)
            // A webhook URL IS the credential; so is a bot token. `chat_id` is an addressee, not a
            // secret, but it identifies a private destination, so it is withheld too.
            .field("webhook_url", &super::redacted(&self.webhook_url))
            .field("bot_token", &super::redacted(&self.bot_token))
            .field("chat_id", &super::redacted(&self.chat_id))
            .finish_non_exhaustive()
    }
}

impl std::fmt::Debug for NewNotificationConnector {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NewNotificationConnector")
            .field("provider", &self.provider)
            .field("name", &self.name)
            .field("enabled", &self.enabled)
            .field("webhook_url", &super::redacted(&self.webhook_url))
            .field("bot_token", &super::redacted(&self.bot_token))
            .field("chat_id", &super::redacted(&self.chat_id))
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
    async fn crud_and_provider_filter() {
        let pool = pool().await;

        // Insert one of each provider; one disabled slack.
        let slack = insert(
            &pool,
            &NewNotificationConnector {
                provider: "slack".into(),
                name: "team".into(),
                webhook_url: Some("https://hooks.slack.com/services/AAA".into()),
                ..Default::default()
            },
        )
        .await
        .unwrap();
        assert!(slack.id > 0);
        assert_eq!(slack.enabled, 1);

        let slack_off = insert(
            &pool,
            &NewNotificationConnector {
                provider: "slack".into(),
                name: "alerts (off)".into(),
                webhook_url: Some("https://hooks.slack.com/services/BBB".into()),
                enabled: Some(0),
                ..Default::default()
            },
        )
        .await
        .unwrap();
        assert_eq!(slack_off.enabled, 0);

        let tg = insert(
            &pool,
            &NewNotificationConnector {
                provider: "telegram".into(),
                name: "bot".into(),
                bot_token: Some("123:abc".into()),
                chat_id: Some("-100999".into()),
                ..Default::default()
            },
        )
        .await
        .unwrap();
        assert_eq!(tg.chat_id.as_deref(), Some("-100999"));

        // list returns all 3.
        assert_eq!(list(&pool).await.unwrap().len(), 3);

        // enabled-by-provider fallback source: only the ON slack row.
        let enabled_slack = list_by_provider_enabled(&pool, "slack").await.unwrap();
        assert_eq!(enabled_slack.len(), 1);
        assert_eq!(enabled_slack[0].id, slack.id);

        // toggle the enabled slack off → now zero enabled slack.
        let toggled = toggle(&pool, slack.id).await.unwrap().unwrap();
        assert_eq!(toggled.enabled, 0);
        assert!(list_by_provider_enabled(&pool, "slack").await.unwrap().is_empty());

        // set_enabled back on.
        assert!(set_enabled(&pool, slack.id, true).await.unwrap());
        assert_eq!(list_by_provider_enabled(&pool, "slack").await.unwrap().len(), 1);

        // delete telegram.
        assert!(delete(&pool, tg.id).await.unwrap());
        assert!(get_by_id(&pool, tg.id).await.unwrap().is_none());
        assert_eq!(list(&pool).await.unwrap().len(), 2);
    }
}
