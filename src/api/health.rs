use std::sync::Arc;

use axum::extract::State;
use serde_json::json;

use crate::server::app::AppState;
use crate::config::constants;

pub async fn health(State(state): State<Arc<AppState>>) -> axum::Json<serde_json::Value> {
    axum::Json(json!({
        "status": "healthy",
        "active_sessions": state.recorder.session_count(),
        "uptime_seconds": state.start_time.elapsed().as_secs(),
    }))
}

pub async fn status(State(state): State<Arc<AppState>>) -> axum::Json<serde_json::Value> {
    axum::Json(json!({
        "version": constants::SERVER_VERSION,
        "status": "running",
        "active_sessions": state.recorder.session_count(),
        "max_sessions": constants::MAX_SESSIONS,
        "headless": state.config.headless,
        "environment": state.config.environment,
        "uptime_seconds": state.start_time.elapsed().as_secs(),
    }))
}
