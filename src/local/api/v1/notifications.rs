//! `/v1/notifications/*` — the local notification feed the app polls + the "fast connector"
//! (Slack / Discord / Telegram) CRUD surface.
//!
//! `/v1/notifications/pending` drains the process-global OS-toast queue (see
//! [`crate::local::flow::drain_pending_toasts`]). `desktop`-channel automation notifications land in
//! that queue because the daemon can't reach the Tauri shell directly; the webview poller drains this
//! endpoint and raises each entry as a real native OS toast via the Tauri notification plugin.
//!
//! `/v1/notifications/connectors` manages the reusable Slack/Discord/Telegram destinations that
//! automation notification blocks reference via the unified `provider:id` recipient format. The list
//! projection deliberately omits the secret columns (`webhook_url`/`bot_token`); only
//! `{id, provider, name, enabled}` is returned. `POST /{id}/test` delivers a sample message through
//! the same SSRF-guarded senders the flow interpreter uses.

use crate::local::error::{LocalError, LocalResult};
use crate::local::flow;
use crate::local::server::AppState;
use crate::local::store::notification_connectors::{self, NewNotificationConnector};
use axum::extract::{Path, State};
use axum::routing::{get, post};
use axum::{Json, Router};
use serde::Deserialize;
use serde_json::{json, Value};

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/v1/notifications/pending", get(pending))
        .route(
            "/v1/notifications/connectors",
            get(list_connectors).post(create_connector),
        )
        .route("/v1/notifications/connectors/:id", axum::routing::delete(delete_connector))
        .route("/v1/notifications/connectors/:id/toggle", axum::routing::patch(toggle_connector))
        .route("/v1/notifications/connectors/:id/test", post(test_connector))
        .route("/v1/notifications/recipients/all", get(cloud_recipients))
        .route(
            "/v1/notifications/preferences",
            get(cloud_preferences_get).put(cloud_preferences_put),
        )
}

/// `GET /v1/notifications/recipients/all?enabled_only=…` — the LINKED cloud
/// account's configured notification recipients (email / Pushover / SMS /
/// WhatsApp / Signal), forwarded verbatim so the automation builder can offer
/// real cloud contacts for the relay channels. Unlinked → an empty list (the
/// builder then shows only the local channels), never an error.
async fn cloud_recipients(
    State(st): State<AppState>,
    axum::extract::Query(q): axum::extract::Query<RecipientsQuery>,
) -> Json<Value> {
    // The cloud-link client (`local::cloud`) only exists in the managed `cloud` build; the
    // fleet/self-host build has no linked account, so it honestly reports "no cloud recipients".
    #[cfg(feature = "cloud")]
    {
        if !crate::local::cloud::notify::is_linked(&st.db).await {
            return Json(json!([]));
        }
        match crate::local::cloud::notify::recipients(&st.db, q.enabled_only.unwrap_or(false)).await {
            Ok(rows) => Json(rows),
            Err(e) => {
                tracing::warn!("cloud recipients fetch failed: {e}");
                Json(json!([]))
            }
        }
    }
    #[cfg(not(feature = "cloud"))]
    {
        let _ = (&st, &q.enabled_only);
        Json(json!([]))
    }
}

#[derive(Deserialize)]
struct RecipientsQuery {
    enabled_only: Option<bool>,
}

/// `GET /v1/notifications/preferences` — the LINKED cloud account's platform
/// notification preference sheet (event/channel catalog + effective matrix +
/// delivery contact fields), forwarded verbatim so the desktop Settings →
/// Notifications tab renders the same matrix the cloud webapp shows. Unlike
/// `cloud_recipients` there is no honest empty projection for this shape, so
/// unlinked (and the cloud-free fleet/self-host build) answers the daemon's
/// standard `401 {error, code: "unauthorized"}` — the exact error the
/// `cloud::notify` client funnel yields for a missing link — which the frontend
/// treats as "not linked".
async fn cloud_preferences_get(State(st): State<AppState>) -> LocalResult<Json<Value>> {
    // The cloud-link client (`local::cloud`) only exists in the managed `cloud` build; the
    // fleet/self-host build has no linked account, so the surface is honestly unavailable.
    #[cfg(feature = "cloud")]
    {
        if !crate::local::cloud::notify::is_linked(&st.db).await {
            return Err(LocalError::Unauthorized);
        }
        Ok(Json(
            crate::local::cloud::notify::preferences_get(&st.db).await?,
        ))
    }
    #[cfg(not(feature = "cloud"))]
    {
        let _ = &st;
        Err(LocalError::Unauthorized)
    }
}

/// `PUT /v1/notifications/preferences` — partial preference update forwarded to the
/// linked cloud account (`{preferences?, phone_number?, pushover_user_key?,
/// marketing_consent?}`; an event's dict REPLACES that event's overrides, `{}` resets
/// it to defaults). Returns the refreshed full sheet. Same not-linked mapping as the
/// GET: `401 {error, code: "unauthorized"}`.
async fn cloud_preferences_put(
    State(st): State<AppState>,
    Json(body): Json<Value>,
) -> LocalResult<Json<Value>> {
    #[cfg(feature = "cloud")]
    {
        if !crate::local::cloud::notify::is_linked(&st.db).await {
            return Err(LocalError::Unauthorized);
        }
        Ok(Json(
            crate::local::cloud::notify::preferences_put(&st.db, &body).await?,
        ))
    }
    #[cfg(not(feature = "cloud"))]
    {
        let _ = (&st, &body);
        Err(LocalError::Unauthorized)
    }
}

/// `GET /v1/notifications/pending` — drain + return queued OS toasts as
/// `{ "notifications": [{ "title", "body" }] }`. Draining is idempotent per item: once returned,
/// an entry is removed, so the poller never re-raises the same toast.
async fn pending(State(_st): State<AppState>) -> Json<Value> {
    Json(json!({ "notifications": flow::drain_pending_toasts() }))
}

/// Supported connector providers. Kept in lockstep with the delivery arm in `flow.rs`.
const PROVIDERS: [&str; 3] = ["slack", "discord", "telegram"];

/// Body for `POST /v1/notifications/connectors` — create a connector. Only the fields relevant to
/// the chosen `provider` are used; the rest are ignored (slack/discord: `webhook_url`; telegram:
/// `bot_token` + `chat_id`).
#[derive(Debug, Deserialize)]
struct CreateBody {
    provider: String,
    name: String,
    #[serde(default)]
    webhook_url: Option<String>,
    #[serde(default)]
    bot_token: Option<String>,
    #[serde(default)]
    chat_id: Option<String>,
    #[serde(default)]
    enabled: Option<bool>,
}

/// `GET /v1/notifications/connectors` — list all connectors, projecting ONLY the non-secret fields
/// `{ id, provider, name, enabled }` (never returns `webhook_url` / `bot_token`).
async fn list_connectors(State(st): State<AppState>) -> LocalResult<Json<Value>> {
    let rows = notification_connectors::list(&st.db).await?;
    let out: Vec<Value> = rows
        .into_iter()
        .map(|c| {
            json!({
                "id": c.id,
                "provider": c.provider,
                "name": c.name,
                "enabled": c.enabled != 0,
            })
        })
        .collect();
    Ok(Json(json!(out)))
}

/// `POST /v1/notifications/connectors` — create a Slack/Discord/Telegram connector. Validates the
/// provider and that the provider's required destination fields are present. Returns the non-secret
/// projection of the created row.
async fn create_connector(
    State(st): State<AppState>,
    Json(body): Json<CreateBody>,
) -> LocalResult<Json<Value>> {
    let provider = body.provider.trim().to_lowercase();
    if !PROVIDERS.contains(&provider.as_str()) {
        return Err(LocalError::BadRequest(format!(
            "unsupported connector provider '{provider}'"
        )));
    }
    let name = body.name.trim();
    if name.is_empty() {
        return Err(LocalError::BadRequest("name is required".into()));
    }

    // Per-provider required destination fields.
    match provider.as_str() {
        "slack" | "discord" => {
            let url = body.webhook_url.as_deref().unwrap_or("").trim();
            if !(url.starts_with("http://") || url.starts_with("https://")) {
                return Err(LocalError::BadRequest(
                    "webhook_url must be an http(s) URL".into(),
                ));
            }
        }
        "telegram" => {
            if body.bot_token.as_deref().unwrap_or("").trim().is_empty() {
                return Err(LocalError::BadRequest("bot_token is required".into()));
            }
            if body.chat_id.as_deref().unwrap_or("").trim().is_empty() {
                return Err(LocalError::BadRequest("chat_id is required".into()));
            }
        }
        _ => unreachable!(),
    }

    // Only persist the fields relevant to the provider (avoid stray secrets on the wrong provider).
    let (webhook_url, bot_token, chat_id) = match provider.as_str() {
        "slack" | "discord" => (
            body.webhook_url.map(|s| s.trim().to_string()),
            None,
            None,
        ),
        "telegram" => (
            None,
            body.bot_token.map(|s| s.trim().to_string()),
            body.chat_id.map(|s| s.trim().to_string()),
        ),
        _ => unreachable!(),
    };

    let created = notification_connectors::insert(
        &st.db,
        &NewNotificationConnector {
            provider: provider.clone(),
            name: name.to_string(),
            webhook_url,
            bot_token,
            chat_id,
            enabled: Some(body.enabled.unwrap_or(true) as i64),
        },
    )
    .await?;

    Ok(Json(json!({
        "id": created.id,
        "provider": created.provider,
        "name": created.name,
        "enabled": created.enabled != 0,
    })))
}

/// `DELETE /v1/notifications/connectors/{id}` — hard-delete a connector. 404 if it doesn't exist.
async fn delete_connector(
    State(st): State<AppState>,
    Path(id): Path<i64>,
) -> LocalResult<Json<Value>> {
    if notification_connectors::delete(&st.db, id).await? {
        Ok(Json(json!({ "deleted": true })))
    } else {
        Err(LocalError::NotFound(format!("notification connector {id}")))
    }
}

/// `PATCH /v1/notifications/connectors/{id}/toggle` — flip `enabled`. Returns the non-secret
/// projection of the updated row; 404 if it doesn't exist.
async fn toggle_connector(
    State(st): State<AppState>,
    Path(id): Path<i64>,
) -> LocalResult<Json<Value>> {
    match notification_connectors::toggle(&st.db, id).await? {
        Some(c) => Ok(Json(json!({
            "id": c.id,
            "provider": c.provider,
            "name": c.name,
            "enabled": c.enabled != 0,
        }))),
        None => Err(LocalError::NotFound(format!("notification connector {id}"))),
    }
}

/// `POST /v1/notifications/connectors/{id}/test` — deliver a sample message through the connector
/// using the same SSRF-guarded senders the flow interpreter uses. Returns `{ delivered: bool }`;
/// 404 if the connector doesn't exist.
async fn test_connector(
    State(st): State<AppState>,
    Path(id): Path<i64>,
) -> LocalResult<Json<Value>> {
    let connector = notification_connectors::get_by_id(&st.db, id)
        .await?
        .ok_or_else(|| LocalError::NotFound(format!("notification connector {id}")))?;
    let delivered = flow::deliver_to_connector(
        &connector,
        "Writ test notification",
        "This is a test message from your Writ connector.",
    )
    .await;
    Ok(Json(json!({ "delivered": delivered })))
}
