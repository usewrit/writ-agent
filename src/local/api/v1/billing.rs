//! `/v1/billing/*` REST handlers — READ-ONLY cloud billing reflection for a linked account.
//!
//! The desktop webview's usage surfaces (Account page, sidebar Usage modal, the crawl
//! wizard's quota hint) read `/v1/billing/usage/limits`, `/v1/billing/account-status`,
//! and the unified-credit `/v1/billing/account/usage` from the LOCAL daemon; these thin
//! handlers forward to the cloud via
//! [`crate::local::cloud::billing`] with the keyring-held `wto_` token. Unlinked → clean
//! 401 (the UI gates these reads on `linked`, so that only happens on a stale webview).
//!
//! Mutations (checkout, portal, plan changes) are DELIBERATELY absent: money moves only
//! in the cloud web app via deep-link. House style: thin handlers, `LocalResult<Json<_>>`
//! with `?` propagation, no auth layer here (server.rs applies the loopback bearer).

use crate::local::error::LocalResult;
use crate::local::server::AppState;
use axum::extract::State;
use axum::routing::get;
use axum::{Json, Router};
use serde_json::Value;

/// Routes for this resource, mounted under the shared `/v1` namespace by the parent router.
pub fn router() -> Router<AppState> {
    Router::new()
        .route("/v1/billing/usage/limits", get(usage_limits))
        .route("/v1/billing/account-status", get(account_status))
        .route("/v1/billing/account/usage", get(account_usage))
}

/// `GET /v1/billing/usage/limits` — the linked plan's per-resource usage vs. limits.
async fn usage_limits(State(st): State<AppState>) -> LocalResult<Json<Value>> {
    Ok(Json(crate::local::cloud::billing::usage_limits(&st.db).await?))
}

/// `GET /v1/billing/account-status` — wallet balance, billing-period window, overage flags.
async fn account_status(State(st): State<AppState>) -> LocalResult<Json<Value>> {
    Ok(Json(crate::local::cloud::billing::account_status(&st.db).await?))
}

/// `GET /v1/billing/account/usage` — the canonical unified-credit usage summary the
/// desktop credit surfaces read (three credit pools + residential funding + reset date).
async fn account_usage(State(st): State<AppState>) -> LocalResult<Json<Value>> {
    Ok(Json(crate::local::cloud::billing::account_usage(&st.db).await?))
}
