//! `/v1/streaming/sessions` REST handlers — LAUNCH / LIST / END the long-lived streaming sessions a
//! streaming workflow holds.
//!
//! A STREAMING workflow (`workflow_type == "streaming"`) is NOT run via `/v1/workflows/:id/run`
//! (that path replays recorded steps once); it keeps a warm browser tab alive and exposes callable
//! handlers. These routes are the desktop "Run a streaming workflow" path — they drive the engine's
//! [`LocalStreamingManager`] (`start_session` / `list_sessions` / `stop_session`), the local mirror
//! of the cloud agent's streaming-session lifecycle (`backend/models/streaming_session.py`).
//!
//! All segments are STATIC (`/start`, `/stop`) — a `:workflow_id` path param at the same position as
//! the `start`/`stop` literals would conflict under matchit, so the workflow id travels in the body.
//! No auth layer here — `server.rs` applies the loopback bearer + Origin/Host guard at the router.

use crate::local::engine::streaming::{LocalStreamingManager, SessionInfo};
use crate::local::error::{LocalError, LocalResult};
use crate::local::server::AppState;
use crate::local::store::workflows;
use axum::extract::State;
use axum::routing::{get, post};
use axum::{Json, Router};
use serde::Deserialize;
use serde_json::{json, Value};
use std::sync::Arc;

/// Mount the streaming-session routes onto the shared `AppState` router. Auth is applied by `server.rs`.
pub fn router() -> Router<AppState> {
    Router::new()
        .route("/v1/streaming/sessions", get(list))
        .route("/v1/streaming/sessions/start", post(start))
        .route("/v1/streaming/sessions/stop", post(stop))
}

/// The engine's streaming manager, or a 400 when the engine can't stream (the `StubEngine` build —
/// no warm browser). Mirrors how the cloud returns "no agent available" when streaming is impossible.
fn require_streaming(st: &AppState) -> LocalResult<Arc<LocalStreamingManager>> {
    st.engine
        .streaming()
        .ok_or_else(|| LocalError::BadRequest("streaming is not supported by this engine".into()))
}

/// `{ workflow_id }` — the body both `start` and `stop` take (the id can't ride in the path; see the
/// module docs on the matchit static-vs-param conflict).
#[derive(Debug, Deserialize)]
struct SessionBody {
    workflow_id: i64,
}

/// `GET /v1/streaming/sessions` — every live session (one per streaming workflow), all `running`.
async fn list(State(st): State<AppState>) -> LocalResult<Json<Vec<SessionInfo>>> {
    let mgr = require_streaming(&st)?;
    Ok(Json(mgr.list_sessions()))
}

/// `POST /v1/streaming/sessions/start` `{ workflow_id }` — LAUNCH (find-or-start) the workflow's
/// streaming session and return its live record (`status: "running"`). 404 if the workflow is gone,
/// 400 if it is not a streaming workflow (a regular workflow has no session — it runs via `/run`).
async fn start(
    State(st): State<AppState>,
    Json(body): Json<SessionBody>,
) -> LocalResult<Json<SessionInfo>> {
    let mgr = require_streaming(&st)?;
    let wf = workflows::get_by_id(&st.db, body.workflow_id)
        .await?
        .ok_or_else(|| LocalError::NotFound(format!("workflow {}", body.workflow_id)))?;
    if wf.workflow_type != "streaming" {
        return Err(LocalError::BadRequest(format!(
            "workflow {} is not a streaming workflow (type: {})",
            body.workflow_id, wf.workflow_type
        )));
    }
    let info = mgr.start_session(&wf).await?;
    Ok(Json(info))
}

/// `POST /v1/streaming/sessions/stop` `{ workflow_id }` — END the workflow's live session. Returns
/// `{ stopped, session? }`: `stopped:false` (no session was live) is a normal idempotent no-op, not
/// an error. `end_reason` is recorded as `user_ended` (the explicit Stop/End control).
async fn stop(
    State(st): State<AppState>,
    Json(body): Json<SessionBody>,
) -> LocalResult<Json<Value>> {
    let mgr = require_streaming(&st)?;
    match mgr.stop_session(body.workflow_id, "user_ended").await {
        Some(info) => Ok(Json(json!({ "stopped": true, "session": info }))),
        None => Ok(Json(json!({ "stopped": false }))),
    }
}
