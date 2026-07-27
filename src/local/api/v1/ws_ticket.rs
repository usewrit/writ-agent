//! `POST /v1/ws-ticket` — mint a single-use WebSocket connect ticket.
//!
//! A browser cannot set an `Authorization` header on a WebSocket, so the loopback recorder /
//! live-preview sockets need an in-band credential. Rather than putting the long-lived `wlt_` bearer
//! in the WS URL (where a query string leaks via history/referrer/proxy logs), the webview calls this
//! AUTHENTICATED endpoint (the bearer rides in the header, gated by `server::auth_mw`) to obtain a
//! short-lived, single-use, route-scoped ticket. It then opens the socket with `?ticket=<wtk_…>`.
//!
//! See [`crate::local::ws_ticket`] for the ticket store + its security properties.
//!
//! House style: thin handler, `LocalResult<Json<_>>`, no auth layer here (server.rs applies the
//! loopback bearer + Origin/Host guard); NEVER logs the minted ticket.

use crate::local::error::{LocalError, LocalResult};
use crate::local::server::AppState;
use crate::local::ws_ticket::{self, WsRoute};
use axum::extract::State;
use axum::routing::post;
use axum::{Json, Router};
use serde::Deserialize;
use serde_json::{json, Value};

/// Mount `POST /v1/ws-ticket`. Auth (the `wlt_`/scoped bearer + loopback guard) is applied by
/// `server.rs` because this router is merged INSIDE the `auth_mw` layer.
pub fn router() -> Router<AppState> {
    Router::new().route("/v1/ws-ticket", post(mint))
}

/// Request body: the route the ticket is for, plus (for `ai-preview`) the channel key it is scoped
/// to. A `record` ticket carries no channel.
#[derive(Debug, Deserialize)]
struct MintBody {
    /// `"record"` | `"ai-preview"`.
    route: String,
    /// The `ai-preview` channel key (`ai-{id}` / `concierge-{id}` / `streaming-{key}`). Ignored for
    /// `record`; required for `ai-preview`.
    #[serde(default)]
    channel: Option<String>,
}

/// `POST /v1/ws-ticket` → `{ ticket, expires_in_secs }`.
async fn mint(State(_st): State<AppState>, Json(body): Json<MintBody>) -> LocalResult<Json<Value>> {
    let route = WsRoute::parse(&body.route).ok_or_else(|| {
        LocalError::BadRequest(format!("unknown ws route {:?}", body.route))
    })?;

    // Scope validation: an ai-preview ticket MUST name a channel; a record ticket must not.
    let channel = match route {
        WsRoute::AiPreview => {
            let key = body.channel.as_deref().map(str::trim).unwrap_or("");
            if key.is_empty() {
                return Err(LocalError::BadRequest("ai-preview ticket requires a channel".into()));
            }
            Some(key.to_string())
        }
        WsRoute::Record => None,
    };

    let (ticket, ttl) = ws_ticket::issue(route, channel).map_err(|_| {
        // Rate-limited / capacity — the only issue failure. A 429-style refusal; the bearer holder
        // simply retries after the window. Never surfaces the ticket.
        LocalError::TooManyRequests
    })?;

    Ok(Json(json!({
        "ticket": ticket,
        "expires_in_secs": ttl.as_secs(),
    })))
}
