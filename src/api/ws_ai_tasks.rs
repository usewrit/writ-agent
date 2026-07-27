use std::collections::HashMap;
use std::sync::Arc;

use axum::extract::ws::{Message, WebSocket};
use axum::extract::{Query, State, WebSocketUpgrade};
use axum::http::{HeaderMap, StatusCode};
use axum::response::IntoResponse;

use crate::server::app::AppState;
use crate::server::auth::ws_request_authorized;

/// 1:1 port of Python websocket_ai_tasks (recorder.py lines 10468-10581).
///
/// WebSocket endpoint for receiving AI session tasks from the coordinator.
/// The coordinator pushes tasks here; the recorder executes them using the
/// AI workflow generation capabilities and returns the recorded steps.
pub async fn handler(
    ws: WebSocketUpgrade,
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
    ws.on_upgrade(move |socket| handle_socket(socket, state))
        .into_response()
}

async fn handle_socket(mut socket: WebSocket, state: Arc<AppState>) {
    tracing::info!("AI task WebSocket connected");

    while let Some(msg) = socket.recv().await {
        let text = match msg {
            Ok(Message::Text(t)) => t,
            Ok(Message::Ping(_)) => {
                let _ = socket.send(Message::Pong(vec![])).await;
                continue;
            }
            Ok(Message::Close(_)) => break,
            Ok(_) => continue,
            Err(_) => break,
        };

        let parsed: serde_json::Value = match serde_json::from_str(&text) {
            Ok(v) => v,
            Err(_) => continue,
        };

        let msg_type = parsed.get("type").and_then(|v| v.as_str()).unwrap_or("");

        match msg_type {
            "ai_task" => {
                handle_ai_task(&mut socket, &state, &parsed).await;
            }
            "ping" => {
                let _ = socket
                    .send(Message::Text(serde_json::json!({"type": "pong"}).to_string()))
                    .await;
            }
            _ => {}
        }
    }

    tracing::info!("AI task WebSocket disconnected");
}

/// Execute one AI task: start session, run workflow, return steps.
/// Mirrors the Python ai_task branch (recorder.py lines 10488-10571).
async fn handle_ai_task(
    socket: &mut WebSocket,
    state: &Arc<AppState>,
    data: &serde_json::Value,
) {
    let task_id = data.get("task_id").and_then(|v| v.as_str()).unwrap_or("").to_string();
    let session_id_in = data.get("ai_session_id").and_then(|v| v.as_str()).unwrap_or("").to_string();
    let config = data.get("config").cloned().unwrap_or(serde_json::json!({}));

    let url = config.get("url").and_then(|v| v.as_str()).unwrap_or("").to_string();
    let goal = config.get("goal").and_then(|v| v.as_str()).unwrap_or("Complete the form").to_string();
    let max_steps = config.get("max_steps").and_then(|v| v.as_u64()).unwrap_or(20) as usize;
    let mode = config.get("mode").and_then(|v| v.as_str()).unwrap_or("standard").to_string();
    let tenant_id = config.get("tenant_id").and_then(|v| v.as_str()).unwrap_or("").to_string();

    // Parse available_data into HashMap (Python line 10496)
    let mut data_map: HashMap<String, String> = HashMap::new();
    if let Some(obj) = config.get("available_data").and_then(|v| v.as_object()) {
        for (k, v) in obj {
            let val = v.as_str().map(|s| s.to_string()).unwrap_or_else(|| v.to_string());
            data_map.insert(k.clone(), val);
        }
    }

    tracing::info!(task_id = %task_id, session = %session_id_in, goal = %goal, "Received AI task");

    if url.is_empty() {
        let _ = socket.send(Message::Text(
            serde_json::json!({"type": "ai_task_error", "task_id": task_id, "error": "URL required"}).to_string(),
        )).await;
        return;
    }

    // Send ai_task_started (Python line 10513)
    let _ = socket.send(Message::Text(
        serde_json::json!({
            "type": "ai_task_started",
            "task_id": task_id,
            "session_id": session_id_in,
        }).to_string(),
    )).await;

    // Start browser session for this task (Python line 10520)
    let tenant_opt = if tenant_id.is_empty() { None } else { Some(tenant_id.clone()) };
    let sid = match state.recorder.start_session(url.clone(), false, tenant_opt).await {
        Ok(s) => s,
        Err(e) => {
            let _ = socket.send(Message::Text(
                serde_json::json!({
                    "type": "ai_task_failed",
                    "task_id": task_id,
                    "session_id": session_id_in,
                    "error": format!("Session start failed: {}", e),
                }).to_string(),
            )).await;
            return;
        }
    };

    // Get page handle + current URL (Python line 10522)
    let (page, current_url) = match state.recorder.get_session_mut(&sid).map(|s| (s.page.clone(), s.current_url.clone())) {
        Some(p) => p,
        None => {
            let _ = state.recorder.end_session(&sid).await;
            let _ = socket.send(Message::Text(
                serde_json::json!({
                    "type": "ai_task_failed",
                    "task_id": task_id,
                    "session_id": session_id_in,
                    "error": "Session page not available",
                }).to_string(),
            )).await;
            return;
        }
    };

    // Send ai_task_progress (Python line 10522)
    let _ = socket.send(Message::Text(
        serde_json::json!({
            "type": "ai_task_progress",
            "task_id": task_id,
            "status": "navigated",
            "url": current_url,
        }).to_string(),
    )).await;

    // Get the shared AI client
    let ai_client_lock = crate::ai::client::get_shared_client();
    let ai_ref = if let Some(ref lock) = ai_client_lock {
        Some(lock.lock().await)
    } else {
        None
    };
    let ai_client_ref = ai_ref.as_deref().map(|c| c as &dyn crate::ai::client::AiClient);

    // Run AI workflow generation (Python line 10530)
    let workflow_result = if mode == "intelligent" {
        let cfg = crate::ai::intelligent_mode::IntelligentModeConfig {
            goal: goal.clone(),
            user_context: None,
            available_data: data_map.clone(),
            fill_data: data_map.clone(),
            max_actions: max_steps,
            secure_keys: Vec::new(),
            tenant_id: tenant_id.clone(),
        };
        crate::ai::intelligent_mode::ai_generate_workflow_intelligent(&page, cfg, ai_client_ref)
            .await
            .map(|r| (r.success, r.steps, r.raw_replay, r.error))
    } else {
        let cfg = crate::ai::standard_mode::StandardModeConfig {
            goal: goal.clone(),
            available_data: data_map.clone(),
            fill_data: data_map.clone(),
            max_steps,
            use_vision: true,
            tenant_id: tenant_id.clone(),
            secure_keys: Vec::new(),
        };
        crate::ai::standard_mode::ai_generate_workflow(&page, cfg, ai_client_ref)
            .await
            .map(|r| (r.success, r.steps, r.raw_replay, r.error))
    };

    // Release AI client lock before ending session
    drop(ai_ref);

    // End the session (Python line 10542)
    let _ = state.recorder.end_session(&sid).await;

    match workflow_result {
        Ok((success, steps, raw_replay, error)) => {
            if let Some(err) = error {
                let _ = socket.send(Message::Text(
                    serde_json::json!({
                        "type": "ai_task_failed",
                        "task_id": task_id,
                        "session_id": session_id_in,
                        "error": err,
                    }).to_string(),
                )).await;
            } else {
                let _ = socket.send(Message::Text(
                    serde_json::json!({
                        "type": "ai_task_complete",
                        "task_id": task_id,
                        "session_id": session_id_in,
                        "steps": steps,
                        "step_count": steps.len(),
                        "raw_replay": raw_replay,
                        "entry_url": url,
                        "form_data": data_map,
                        "success": success,
                        "message": "AI workflow completed",
                    }).to_string(),
                )).await;
            }
        }
        Err(e) => {
            tracing::error!(task_id = %task_id, error = %e, "AI task failed");
            let _ = socket.send(Message::Text(
                serde_json::json!({
                    "type": "ai_task_failed",
                    "task_id": task_id,
                    "session_id": session_id_in,
                    "error": e.to_string(),
                }).to_string(),
            )).await;
        }
    }
}
