//! Axum WebSocket route for the local recorder (`GET /ws/record`).
//!
//! Does its OWN auth (a browser can't set an `Authorization` header on a WebSocket): the connect
//! carries a SINGLE-USE `?ticket=<wtk_…>` minted by the authenticated `POST /v1/ws-ticket` endpoint
//! (see `crate::local::ws_ticket`), consumed atomically here, PLUS the same loopback Origin/Host
//! guard the bearer middleware enforces (DNS-rebind defense). The long-lived `wlt_` bearer NEVER
//! appears in a WS URL. Mounted OUTSIDE the header-bearer `auth_mw` layer (see `server::build_router`).
//! NO ws-gateway, NO `saas_bridge`, NO remote agent — the daemon drives its OWN warm Chromium.

use std::collections::HashMap;

use axum::extract::ws::WebSocketUpgrade;
use axum::extract::{Query, State};
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::IntoResponse;
use axum::routing::get;
use axum::Router;

use crate::local::auth;
use crate::local::server::AppState;
use crate::local::ws_ticket::{self, WsRoute};

/// The recording sub-router. State-agnostic (`Router<AppState>`); the caller attaches `AppState`.
pub fn router() -> Router<AppState> {
    Router::new().route("/ws/record", get(handler))
}

/// `GET /ws/record` — authenticate (single-use ticket + loopback Origin/Host), then upgrade to a
/// recording WebSocket bound to the daemon's local recorder. Auth runs BEFORE the upgrade so an
/// unauthorized peer never reaches the recorder. Returns 401 on auth failure, 503 if no recorder is
/// configured (e.g. an engine with no browser — only the test-only `StubEngine`).
async fn handler(
    ws: WebSocketUpgrade,
    Query(query): Query<HashMap<String, String>>,
    headers: HeaderMap,
    State(state): State<AppState>,
) -> impl IntoResponse {
    let origin = headers.get(header::ORIGIN).and_then(|v| v.to_str().ok());
    let host = headers.get(header::HOST).and_then(|v| v.to_str().ok());

    // Loopback guard first (DNS-rebind defense), then atomically consume the single-use ticket. The
    // ticket is spent regardless of the upgrade outcome, so a replayed URL can never reconnect.
    let ticket = query.get("ticket").map(|s| s.as_str()).unwrap_or("");
    if !auth::ws_origin_allowed(origin, host, state.config.port)
        || !ws_ticket::consume(ticket, WsRoute::Record, None)
    {
        return (StatusCode::UNAUTHORIZED, "unauthorized").into_response();
    }

    let recorder = match state.recorder.clone() {
        Some(r) => r,
        None => {
            // No browser-backed engine → recording is unavailable in this build.
            return (StatusCode::SERVICE_UNAVAILABLE, "recorder unavailable").into_response();
        }
    };

    ws.on_upgrade(move |socket| super::session::run(socket, recorder)).into_response()
}
