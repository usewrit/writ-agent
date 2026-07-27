//! Unauthenticated KEYLESS cloud tier (backend `routers/keyless.py`): single-page scrape + site map
//! for a managed desktop with NO linked account and NO API key. Daily-capped per device id + IP. The
//! expensive whole-site crawl is NOT here — it always needs a credential (see `cloud::crawl`).
//!
//! No bearer is attached (there is none). Instead every call carries the stable per-install device id
//! (`X-Writ-Client-Id`) so the cloud attributes the daily quota to THIS install rather than a shared
//! egress IP. The id is the SAME install id the auto-updater uses (config_kv `update.install_id`), so
//! one stable identifier tracks the machine everywhere.

use super::client::{require_secure_cloud_url, CloudClient};
use super::state::LinkState;
use crate::local::error::{LocalError, LocalResult};
use crate::local::store::config_kv;
use base64::Engine;
use rand::RngCore;
use serde_json::Value;
use sqlx::sqlite::SqlitePool;
use std::time::Duration;

/// Keyless router mount (the cloud backend's `keyless` router, mounted self-prefixed at `/v1/keyless`).
const KEYLESS: &str = "/v1/keyless";
/// Device-identity header the keyless quota is keyed on (backend `_client_id`).
const CLIENT_ID_HEADER: &str = "X-Writ-Client-Id";
/// Shared with the auto-updater (`api/v1/update.rs`) so ONE stable id identifies this install.
const INSTALL_ID_KEY: &str = "update.install_id";
const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);

/// Stable per-install device id, reused from the updater's install id (minted once, persisted in
/// config_kv). Sent as `X-Writ-Client-Id` so the keyless daily quota is attributed to THIS install.
pub async fn device_id(db: &SqlitePool) -> LocalResult<String> {
    if let Some(id) = config_kv::get(db, INSTALL_ID_KEY).await? {
        if !id.trim().is_empty() {
            return Ok(id);
        }
    }
    // Mint the SAME shape the updater does (128-bit URL-safe base64), persisted under the shared key.
    let mut raw = [0u8; 16];
    rand::rngs::OsRng.fill_bytes(&mut raw);
    let id = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(raw);
    config_kv::set(db, INSTALL_ID_KEY, &id).await?;
    Ok(id)
}

/// POST an unauthenticated keyless call carrying the device id. Surfaces the backend's
/// `{detail:{message,code}}` (a 402 needs-key / 429 over-quota) as a relayable `BadRequest`, so the
/// driving model reads it as a clear outcome rather than a protocol failure.
async fn post(db: &SqlitePool, path: &str, body: &Value) -> LocalResult<Value> {
    let link = LinkState::load_or_default(db).await.ok();
    let base = CloudClient::resolve_base_url(link.as_ref());
    require_secure_cloud_url(&base)?;
    let cid = device_id(db).await?;
    let http = reqwest::Client::builder()
        .timeout(REQUEST_TIMEOUT)
        .user_agent(concat!("writ-agent/", env!("CARGO_PKG_VERSION")))
        .build()
        .map_err(|e| LocalError::Internal(format!("keyless client build failed: {e}")))?;
    let resp = http
        .post(format!("{base}{path}"))
        .header(CLIENT_ID_HEADER, cid)
        .json(body)
        .send()
        .await
        .map_err(|e| LocalError::CloudUnreachable(format!("keyless request failed: {e}")))?;
    let status = resp.status();
    let val: Value = resp
        .json()
        .await
        .map_err(|e| LocalError::Internal(format!("keyless response was not JSON: {e}")))?;
    if status.is_success() {
        return Ok(val);
    }
    let msg = val
        .get("detail")
        .and_then(|d| d.get("message"))
        .and_then(Value::as_str)
        .map(str::to_string)
        .unwrap_or_else(|| format!("keyless call failed ({})", status.as_u16()));
    Err(LocalError::BadRequest(msg))
}

/// `POST /v1/keyless/scrape` — one page → full markdown (daily-capped, per install).
pub async fn scrape(db: &SqlitePool, body: &Value) -> LocalResult<Value> {
    post(db, &format!("{KEYLESS}/scrape"), body).await
}

/// `POST /v1/keyless/map` — a site's ranked URLs (daily-capped; spends a request, no pages).
pub async fn map(db: &SqlitePool, body: &Value) -> LocalResult<Value> {
    post(db, &format!("{KEYLESS}/map"), body).await
}
