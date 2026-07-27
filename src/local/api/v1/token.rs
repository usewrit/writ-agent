//! `POST /v1/token/rotate` — LIVE, transactional rotation of the `wlt_` runtime bearer.
//!
//! The shell's transactional rotation (frontend-desktop `src-tauri/src/token.rs`) refuses to touch the
//! on-disk token or its cached handle unless the RUNNING daemon confirms the SAME new token is active.
//! This endpoint is what makes that confirmation real: it mints a new `wlt_`, rewrites the durable
//! `local_token` file and the `runtime.json` discovery descriptor (both `0600`), then swaps the LIVE
//! in-memory token so the daemon immediately stops honoring the old value and starts honoring the new
//! one. The shell then round-trips `GET /v1/agent` with the returned token to confirm it is active.
//!
//! ORDER (crash-safe): (1) mint, (2) write `local_token`, (3) rewrite `runtime.json`, (4) live swap.
//! A failure at step 2 or 3 returns an error with NOTHING activated (old token still valid
//! everywhere); a crash before the live swap reverts to the old token on restart (the durable file
//! is only adopted by a fresh process, which republishes a matching `runtime.json` at boot). There is
//! no window where the daemon honors a token the shell cannot obtain from the response.
//!
//! AUTH: mounted inside `server::auth_mw`. The full-access `wlt_` UI token (the shell) bypasses the
//! scope gate; an external `wlk_`/`wlo_` key needs the `manage` device-control capability
//! (`auth::is_device_management_path`), because re-issuing the master bearer is device control.
//!
//! House style: thin handler, NEVER logs the token value.

use crate::local::app::runtime_file::{self, RuntimeInfo};
use crate::local::config::{self, Paths};
use crate::local::error::{LocalError, LocalResult};
use crate::local::runtime_token;
use crate::local::server::AppState;
use axum::extract::State;
use axum::routing::post;
use axum::{Json, Router};
use serde_json::{json, Value};

pub fn router() -> Router<AppState> {
    Router::new().route("/v1/token/rotate", post(rotate))
}

/// `POST /v1/token/rotate` → `{ token: "wlt_…" }`. Rotates the live runtime bearer transactionally.
async fn rotate(State(st): State<AppState>) -> LocalResult<Json<Value>> {
    // Resolve the home paths the daemon itself uses (WRIT_HOME / ~/.writ).
    let paths = Paths::resolve().map_err(|_| {
        LocalError::Internal("could not resolve the Writ home for token rotation".into())
    })?;

    // (1)+(2) mint a new token and overwrite the durable `local_token` file (0600). On failure,
    // nothing is activated — the old token is still valid everywhere.
    let new_token = config::rotate_token_file(&paths).map_err(|_| {
        LocalError::Internal("could not persist the rotated token".into())
    })?;

    // (3) rewrite the `runtime.json` discovery descriptor so a co-located UI re-reads the new token.
    let info = RuntimeInfo::current(st.config.port, new_token.clone());
    runtime_file::write(&paths, &info).map_err(|_| {
        LocalError::Internal("could not republish runtime.json for the rotated token".into())
    })?;

    // (4) swap the LIVE in-memory token: from here the daemon honors the new token and rejects the
    // old one. Keyed by the boot seed so this daemon's rotation is isolated (matters only in tests).
    runtime_token::set(st.token.as_str(), &new_token);

    tracing::info!("wlt_ runtime token rotated (file + runtime.json + live swap)");
    Ok(Json(json!({ "token": new_token })))
}
