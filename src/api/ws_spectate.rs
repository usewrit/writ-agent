use std::collections::HashMap;
use std::sync::Arc;

use axum::extract::ws::{Message, WebSocket};
use axum::extract::{Path, Query, State, WebSocketUpgrade};
use axum::http::{HeaderMap, StatusCode};
use axum::response::IntoResponse;
use tokio::sync::broadcast;

use crate::config::constants;
use crate::server::app::AppState;
use crate::server::auth::ws_request_authorized;

/// 1:1 port of Python websocket_spectate (recorder.py line 10585).
///
/// Read-only WebSocket that receives screenshot frames from a running session.
/// Uses the session's screenshot broadcast channel — spectators subscribe to
/// the same stream the primary recording websocket receives.
pub async fn handler(
    ws: WebSocketUpgrade,
    Path(session_id): Path<String>,
    Query(query): Query<HashMap<String, String>>,
    headers: HeaderMap,
    State(state): State<Arc<AppState>>,
) -> impl IntoResponse {
    if !ws_request_authorized(
        &query,
        &headers,
        &state.config.auth_secret,
        state.config.auth_bypass_enabled(),
    ) {
        return (StatusCode::UNAUTHORIZED, "unauthorized").into_response();
    }
    ws.on_upgrade(move |socket| handle_socket(socket, session_id, state))
        .into_response()
}

async fn handle_socket(
    mut socket: WebSocket,
    session_id: String,
    state: Arc<AppState>,
) {
    tracing::info!(session_id = %session_id, "Spectator WebSocket connected");

    // 1. Check session exists (Python line 10599)
    let screenshot_rx = {
        let session_ref = match state.recorder.get_session_mut(&session_id) {
            Some(s) => s,
            None => {
                let _ = socket.send(Message::Text(
                    serde_json::json!({"type": "error", "message": format!("Session {} not found", session_id)}).to_string(),
                )).await;
                let _ = socket.close().await;
                return;
            }
        };

        // 2. Subscribe to screenshot broadcast (Python: session.spectators.append(websocket))
        match &session_ref.screenshot_tx {
            Some(tx) => {
                if tx.receiver_count() >= constants::MAX_SPECTATORS {
                    let _ = socket.send(Message::Text(
                        serde_json::json!({"type": "error", "message": "Max spectators reached"}).to_string(),
                    )).await;
                    let _ = socket.close().await;
                    return;
                }
                tx.subscribe()
            }
            None => {
                let _ = socket.send(Message::Text(
                    serde_json::json!({"type": "error", "message": "Session not streaming"}).to_string(),
                )).await;
                let _ = socket.close().await;
                return;
            }
        }
    };

    // 3. Send initial info (Python line 10627)
    let current_url = state
        .recorder
        .get_session_mut(&session_id)
        .map(|s| s.current_url.clone())
        .unwrap_or_default();

    let _ = socket.send(Message::Text(
        serde_json::json!({
            "type": "spectate_started",
            "session_id": session_id,
            "url": current_url,
        }).to_string(),
    )).await;

    // 4. Forward frames and handle ping/pong until disconnect
    stream_to_spectator(socket, screenshot_rx, &session_id).await;

    tracing::info!(session_id = %session_id, "Spectator WebSocket disconnected");
}

/// Forward screenshot frames from broadcast channel to spectator websocket.
/// Also handles incoming ping/pong from spectator.
async fn stream_to_spectator(
    mut socket: WebSocket,
    mut screenshot_rx: broadcast::Receiver<Vec<u8>>,
    session_id: &str,
) {
    loop {
        tokio::select! {
            // Forward screenshot frames to spectator
            frame = screenshot_rx.recv() => {
                match frame {
                    Ok(data) => {
                        if socket.send(Message::Binary(data)).await.is_err() {
                            break;
                        }
                    }
                    Err(broadcast::error::RecvError::Lagged(n)) => {
                        tracing::debug!(session_id = %session_id, skipped = n, "Spectator lagged, skipping frames");
                    }
                    Err(broadcast::error::RecvError::Closed) => {
                        tracing::info!(session_id = %session_id, "Session ended, closing spectator");
                        break;
                    }
                }
            }
            // Handle incoming messages from spectator (ping/pong only)
            msg = socket.recv() => {
                match msg {
                    Some(Ok(Message::Text(text))) => {
                        if let Ok(parsed) = serde_json::from_str::<serde_json::Value>(&text) {
                            if parsed.get("type").and_then(|v| v.as_str()) == Some("ping") {
                                let _ = socket.send(Message::Text(
                                    serde_json::json!({"type": "pong"}).to_string(),
                                )).await;
                            }
                        }
                    }
                    Some(Ok(Message::Ping(_))) => {
                        let _ = socket.send(Message::Pong(vec![])).await;
                    }
                    Some(Ok(Message::Close(_))) | None | Some(Err(_)) => break,
                    _ => {}
                }
            }
        }
    }
}
