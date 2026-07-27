//! Authenticated passthroughs to the cloud billing reads (`/api/billing`).
//!
//! The desktop shows a linked account's CLOUD usage (run-time minutes, AI tokens,
//! wallet, billing period) on the Account page and the sidebar Usage modal. Those
//! numbers are cloud truth — the daemon holds the `wto_` token, so the webview asks
//! the daemon and the daemon forwards. READ-ONLY by design: checkout/portal/webhook
//! surfaces stay browser-only (deep-link to the cloud billing page), so no mutation
//! is ever proxied here. Mirrors the `cloud::crawl` passthrough style: one `client()`
//! funnel, raw JSON out, the cloud owns every semantic.

use super::client::CloudClient;
use super::state::LinkState;
use crate::local::error::LocalResult;
use serde_json::Value;
use sqlx::sqlite::SqlitePool;

/// Backend billing router mount (the cloud backend's `billing` router, `include_router(prefix="/api")`).
const BILLING: &str = "/api/billing";

/// Open an authenticated cloud client for the current link, or a clean `Unauthorized`
/// when the desktop is not linked (no panic, no partial work).
async fn client(db: &SqlitePool) -> LocalResult<CloudClient> {
    let link = LinkState::load_or_default(db).await?;
    CloudClient::connect(Some(&link))
}

/// `GET /api/billing/usage/limits` — per-resource usage vs. the linked plan's limits
/// (execution ms, AI tokens, monitors, …). The Account page + Usage modal meters.
pub async fn usage_limits(db: &SqlitePool) -> LocalResult<Value> {
    client(db).await?.get_json(&format!("{BILLING}/usage/limits")).await
}

/// `GET /api/billing/account-status` — account lifecycle snapshot (wallet balance,
/// billing-period window, overage/consent flags) for banners and modals.
pub async fn account_status(db: &SqlitePool) -> LocalResult<Value> {
    client(db).await?.get_json(&format!("{BILLING}/account-status")).await
}

/// `GET /api/billing/account/usage` — the canonical UNIFIED-CREDIT usage summary:
/// the three credit pools (monthly included grant used/remaining + purchased wallet,
/// all whole credits), residential funding mode, and the period reset date. This is
/// what the desktop credit surfaces (Account page, sidebar Usage glance) now read.
pub async fn account_usage(db: &SqlitePool) -> LocalResult<Value> {
    client(db).await?.get_json(&format!("{BILLING}/account/usage")).await
}
