//! `/v1` REST API surface for the Writ desktop local backend.
//!
//! Each resource lives in its own module and exposes `pub fn router() -> Router<AppState>` that
//! registers its `/v1/<resource>` routes WITHOUT any auth layer — `server.rs` applies the loopback
//! bearer + Origin/Host guard once at the top-level router. This module merges every resource into
//! a single `Router<AppState>` that `build_router` can `.merge(...)` onto the base router.

use crate::local::server::AppState;
use axum::Router;

pub mod ai_concierge;
pub mod ai_sessions;
pub mod automations;
pub mod backup;
// Read-only cloud billing reflection (usage/limits + account-status). Cloud-managed
// product surface; the cloud-free OSS build has no billing, so it is compiled out.
#[cfg(feature = "cloud")]
pub mod billing;
pub mod crawl;
// Cloud-link REST surface (link/unlink/status/marketplace/sync). Cloud-managed product; the
// cloud-free OSS build compiles the `cloud` module out entirely, so these handlers are omitted.
#[cfg(feature = "cloud")]
pub mod cloud;
pub mod data;
pub mod data_admin;
pub mod diagnostics;
pub mod extractors;
pub mod files;
pub mod hooks;
pub mod keys;
pub mod lifecycle;
pub mod mcp_connect;
pub mod monitors;
pub mod network;
pub mod oauth;
pub mod tls;
pub mod token;
pub mod update;
pub mod selectors;
pub mod personas;
pub mod runs;
pub mod runtime;
pub mod secrets;
pub mod settings;
pub mod streaming_sessions;
pub mod vault;
pub mod workflows;
pub mod ws_ticket;
pub mod openai;
pub mod ai_assist;
pub mod ai_config;
pub mod notifications;
// Cloud-dispatch agent REST surface — a cloud-managed capability compiled out of the cloud-free
// OSS build.
#[cfg(feature = "cloud")]
pub mod cloud_agent;
// IP-relay REST surface — deferred to phase 2, behind the default-off `ip_relay` feature.
#[cfg(feature = "ip_relay")]
pub mod relay;

/// Merge all `/v1` resource routers into one. Auth is applied by `server.rs` at the router level.
pub fn router() -> Router<AppState> {
    let r = Router::new()
        .merge(workflows::router())
        .merge(runs::router())
        .merge(monitors::router())
        .merge(crawl::router())
        .merge(selectors::router())
        .merge(extractors::router())
        .merge(automations::router())
        .merge(data::router())
        .merge(personas::router())
        .merge(secrets::router())
        .merge(vault::router())
        .merge(files::router())
        .merge(hooks::router())
        .merge(keys::router())
        .merge(mcp_connect::router())
        .merge(network::router())
        .merge(oauth::router())
        .merge(tls::router())
        .merge(runtime::router())
        .merge(settings::router())
        .merge(backup::router())
        .merge(data_admin::router())
        .merge(diagnostics::router())
        .merge(openai::router())
        .merge(streaming_sessions::router())
        .merge(ai_sessions::router())
        .merge(ai_concierge::router())
        .merge(ai_assist::router())
        .merge(ai_config::router())
        .merge(notifications::router())
        .merge(ws_ticket::router())
        .merge(update::router())
        .merge(lifecycle::router())
        .merge(token::router());
    // Cloud-only REST surfaces are merged only when the `cloud` feature is compiled in.
    #[cfg(feature = "cloud")]
    let r = r
        .merge(cloud::router())
        .merge(cloud_agent::router())
        .merge(billing::router());
    // The IP-relay REST surface is gated on its own (phase-2) `ip_relay` feature.
    #[cfg(feature = "ip_relay")]
    let r = r.merge(relay::router());
    r.merge(crate::local::mcp::http::router())
}
