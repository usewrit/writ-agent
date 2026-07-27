use std::sync::Arc;

use axum::extract::{Path, State};
use serde_json::json;

use crate::server::app::AppState;

pub async fn list_active(
    State(state): State<Arc<AppState>>,
) -> axum::Json<serde_json::Value> {
    let sessions = state.recorder.list_sessions(None);
    axum::Json(json!({
        "sessions": sessions,
    }))
}

pub async fn stop_session(
    State(state): State<Arc<AppState>>,
    Path(session_id): Path<String>,
) -> axum::Json<serde_json::Value> {
    tracing::info!(session_id = %session_id, "Stop session requested");

    match state.recorder.end_session(&session_id).await {
        Ok(result) => {
            axum::Json(json!({
                "status": "stopped",
                "session_id": session_id,
                "stepCount": result.step_count,
                "rawReplayCount": result.raw_replay_count,
            }))
        }
        Err(e) => {
            axum::Json(json!({
                "status": "error",
                "session_id": session_id,
                "error": e.to_string(),
            }))
        }
    }
}
