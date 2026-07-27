//! Authenticated passthroughs to the cloud notification relay
//! (`/api/notifications/relay` + `/api/notifications/recipients/all`) and the
//! account-wide platform notification preferences (`/api/notifications/preferences`).
//!
//! Desktop automations run on the LOCAL interpreter (`local::flow`), but the
//! relay-needing channels (email / Pushover / SMS / WhatsApp / Signal) can only
//! deliver from the cloud. When a cloud account is linked, the flow
//! interpreter hands those channels here as one relay call; unlinked they stay
//! honest `cloud_only_channel` skips. Mirrors the `cloud::crawl` passthrough
//! style: one `client()` funnel, raw JSON in/out, the cloud owns semantics
//! (tenant-scoped recipients, rate limits, channel allowlist).

use super::client::CloudClient;
use super::state::LinkState;
use crate::local::error::LocalResult;
use serde_json::Value;
use sqlx::sqlite::SqlitePool;

/// Backend notifications router mount (the cloud backend's `notifications` router,
/// `include_router(prefix="/api")`).
const NOTIFICATIONS: &str = "/api/notifications";

/// True when a cloud account is linked. Never panics; unreadable reads unlinked.
pub async fn is_linked(db: &SqlitePool) -> bool {
    LinkState::load_or_default(db)
        .await
        .map(|l| l.is_linked())
        .unwrap_or(false)
}

/// Open an authenticated cloud client for the current link, or a clean
/// `Unauthorized` when the desktop is not linked.
async fn client(db: &SqlitePool) -> LocalResult<CloudClient> {
    let link = LinkState::load_or_default(db).await?;
    CloudClient::connect(Some(&link))
}

/// `POST /api/notifications/relay` — deliver a one-shot notification through the
/// linked tenant's cloud-configured providers. `body` carries
/// `{channels, recipients?, title?, message, priority?, url?, email_subject?}`.
pub async fn relay(db: &SqlitePool, body: &Value) -> LocalResult<Value> {
    client(db)
        .await?
        .post_json(&format!("{NOTIFICATIONS}/relay"), body)
        .await
}

/// `GET /api/notifications/recipients/all?enabled_only=…` — the linked tenant's
/// configured notification recipients (`{id, provider, name, identifier_preview,
/// enabled}` rows), so the block builder can offer real cloud contacts.
pub async fn recipients(db: &SqlitePool, enabled_only: bool) -> LocalResult<Value> {
    client(db)
        .await?
        .get_json(&format!(
            "{NOTIFICATIONS}/recipients/all?enabled_only={enabled_only}"
        ))
        .await
}

/// `GET /api/notifications/preferences` — the linked account's platform
/// notification preference sheet: `{catalog, effective, overrides,
/// channel_availability, phone_number, pushover_user_key_set, marketing_consent}`.
/// Forwarded verbatim so the desktop Settings tab renders the same matrix the
/// cloud webapp shows; the cloud owns the catalog and the locked-channel rules.
pub async fn preferences_get(db: &SqlitePool) -> LocalResult<Value> {
    client(db)
        .await?
        .get_json(&format!("{NOTIFICATIONS}/preferences"))
        .await
}

/// `PUT /api/notifications/preferences` — partial preference update. `body`
/// carries any of `{preferences, phone_number, pushover_user_key,
/// marketing_consent}`; an event's dict REPLACES that event's overrides (`{}`
/// resets it to defaults). Returns the same full sheet as `preferences_get`.
pub async fn preferences_put(db: &SqlitePool, body: &Value) -> LocalResult<Value> {
    client(db)
        .await?
        .put_json(&format!("{NOTIFICATIONS}/preferences"), body)
        .await
}
