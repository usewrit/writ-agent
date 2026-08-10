use std::collections::HashMap;
use std::sync::Arc;

use axum::extract::ws::{Message, WebSocket};
use axum::extract::{Query, State, WebSocketUpgrade};
use axum::http::{HeaderMap, StatusCode};
use axum::response::IntoResponse;
use futures_util::{SinkExt, StreamExt};
use serde_json::json;

use crate::recorder::action_handler::{ActionResult, IncomingAction};
use crate::server::app::AppState;
use crate::server::auth::ws_request_authorized;

pub async fn handler(
    ws: WebSocketUpgrade,
    Query(query): Query<HashMap<String, String>>,
    headers: HeaderMap,
    State(state): State<Arc<AppState>>,
) -> impl IntoResponse {
    // Defense-in-depth: authenticate before upgrading the socket.
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

async fn handle_socket(socket: WebSocket, state: Arc<AppState>) {
    tracing::info!("Recording WebSocket connected");

    let (ws_sender, mut ws_receiver) = socket.split();

    // Shared sender behind Arc<Mutex> so the screenshot forwarder and message handler
    // can both send on the same WebSocket.
    let ws_sender = Arc::new(tokio::sync::Mutex::new(ws_sender));

    let mut session_id: Option<String> = None;
    let mut screenshot_forward_task: Option<tokio::task::JoinHandle<()>> = None;
    let mut event_forward_task: Option<tokio::task::JoinHandle<()>> = None;

    loop {
        let msg = match ws_receiver.next().await {
            Some(Ok(Message::Text(text))) => text,
            Some(Ok(Message::Binary(_))) => continue,
            Some(Ok(Message::Ping(_))) => {
                let sender = ws_sender.clone();
                let _ = sender.lock().await.send(Message::Pong(vec![])).await;
                continue;
            }
            Some(Ok(Message::Close(_))) => break,
            Some(Ok(_)) => continue,
            Some(Err(e)) => {
                tracing::debug!(error = %e, "WebSocket receive error");
                break;
            }
            None => break,
        };

        let parsed: serde_json::Value = match serde_json::from_str(&msg) {
            Ok(v) => v,
            Err(e) => {
                let sender = ws_sender.clone();
                let _ = sender
                    .lock()
                    .await
                    .send(Message::Text(
                        json!({"type": "error", "error": format!("Invalid JSON: {}", e)}).to_string(),
                    ))
                    .await;
                continue;
            }
        };

        let msg_type = parsed
            .get("type")
            .and_then(|v| v.as_str())
            .unwrap_or("");

        match msg_type {
            "start" => {
                let url = parsed
                    .get("url")
                    .and_then(|v| v.as_str())
                    .unwrap_or("about:blank")
                    .to_string();

                if url.is_empty() {
                    let sender = ws_sender.clone();
                    let _ = sender
                        .lock()
                        .await
                        .send(Message::Text(
                            json!({"type": "error", "message": "URL required"}).to_string(),
                        ))
                        .await;
                    continue;
                }

                // Get recording options
                let record_wait_steps = parsed
                    .get("options")
                    .and_then(|o| o.get("record_wait_steps"))
                    .and_then(|v| v.as_bool())
                    .unwrap_or(true);

                tracing::info!(url = %url, "WS: Start recording");

                match state.recorder.start_session(url.clone(), record_wait_steps, None).await {
                    Ok(sid) => {
                        // Subscribe to screenshot broadcast channel and forward frames
                        if let Some(session_ref) = state.recorder.get_session_mut(&sid) {
                            if let Some(ref tx) = session_ref.screenshot_tx {
                                let mut rx = tx.subscribe();
                                let sender = ws_sender.clone();
                                let fwd_task = tokio::spawn(async move {
                                    loop {
                                        match rx.recv().await {
                                            Ok(frame) => {
                                                let mut s = sender.lock().await;
                                                if s.send(Message::Binary(frame)).await.is_err() {
                                                    break;
                                                }
                                            }
                                            Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
                                            Err(tokio::sync::broadcast::error::RecvError::Lagged(n)) => {
                                                tracing::debug!(lagged = n, "Screenshot subscriber lagged, skipping frames");
                                            }
                                        }
                                    }
                                });
                                screenshot_forward_task = Some(fwd_task);
                            }
                        }

                        // Forward JSON events (step_recorded, navigation, select_options, etc.)
                        // to the frontend. Without this, recorded actions never reach the UI.
                        if let Some(mut event_rx) = state.recorder.take_event_rx(&sid) {
                            let sender = ws_sender.clone();
                            let evt_task = tokio::spawn(async move {
                                while let Some(event) = event_rx.recv().await {
                                    let mut s = sender.lock().await;
                                    if s.send(Message::Text(event.to_string())).await.is_err() {
                                        break;
                                    }
                                }
                            });
                            event_forward_task = Some(evt_task);
                        }

                        let actual_url = state
                            .recorder
                            .get_session_mut(&sid)
                            .map(|s| s.current_url.clone())
                            .unwrap_or(url);

                        session_id = Some(sid.clone());

                        let sender = ws_sender.clone();
                        let _ = sender
                            .lock()
                            .await
                            .send(Message::Text(
                                json!({
                                    "type": "started",
                                    "sessionId": sid,
                                    "url": actual_url,
                                })
                                .to_string(),
                            ))
                            .await;
                    }
                    Err(e) => {
                        let sender = ws_sender.clone();
                        let _ = sender
                            .lock()
                            .await
                            .send(Message::Text(
                                json!({"type": "error", "message": e.to_string()}).to_string(),
                            ))
                            .await;
                    }
                }
            }

            "action" if session_id.is_some() => {
                let sid = session_id.as_ref().unwrap().clone();

                // Rate limit check
                let action_type = parsed
                    .get("action")
                    .and_then(|v| v.as_str())
                    .unwrap_or("");

                if !state.rate_limiter.check_rate(&sid, action_type) {
                    let sender = ws_sender.clone();
                    let _ = sender
                        .lock()
                        .await
                        .send(Message::Text(
                            json!({"type": "error", "message": "Rate limit: too many actions"}).to_string(),
                        ))
                        .await;
                    continue;
                }

                // Dispatch action to recorder
                let result = {
                    let action = IncomingAction {
                        action_type: action_type.to_string(),
                        data: serde_json::from_value(parsed.clone()).unwrap_or_default(),
                    };

                    // Async acquire — this runs ON the WebSocket read loop and the
                    // guard is then held across every await of the action. A
                    // blocking acquire parks the worker thread, and a Playwright
                    // event handler blocking on the same shard completes a circular
                    // wait that wedges the whole session mid-navigation. See
                    // `recorder::session_lock`; the local record transport and the
                    // cloud bridge carry the identical fix.
                    if let Some(mut session_ref) = state.recorder.get_session_mut_async(&sid).await {
                        let session = session_ref.value_mut();
                        crate::recorder::action_handler::handle_action(session, action).await
                    } else {
                        ActionResult::err("Session not found")
                    }
                };

                // Send error if action failed
                if !result.success {
                    if let Some(ref error) = result.error {
                        let sender = ws_sender.clone();
                        let _ = sender
                            .lock()
                            .await
                            .send(Message::Text(
                                json!({"type": "error", "message": error}).to_string(),
                            ))
                            .await;
                    }
                }

                // Return eval results for script testing
                if let Some(ref data) = result.data {
                    if data.get("eval_result").is_some() {
                        let sender = ws_sender.clone();
                        let _ = sender
                            .lock()
                            .await
                            .send(Message::Text(
                                json!({
                                    "type": "eval_result",
                                    "result": data.get("eval_result"),
                                    "error": data.get("error"),
                                })
                                .to_string(),
                            ))
                            .await;
                    }

                    // Live element picker (check wizard) — element_info /
                    // elements_in_region / dom_content frames (parity with bridge).
                    if let Some(info) = data.get("element_info") {
                        if let Some(obj) = info.as_object() {
                            let mut frame = serde_json::Map::new();
                            frame.insert("type".into(), json!("element_info"));
                            for (k, v) in obj {
                                frame.insert(k.clone(), v.clone());
                            }
                            let sender = ws_sender.clone();
                            let _ = sender
                                .lock()
                                .await
                                .send(Message::Text(serde_json::Value::Object(frame).to_string()))
                                .await;
                        }
                    }
                    if let Some(elements) = data.get("elements_in_region") {
                        let sender = ws_sender.clone();
                        let _ = sender
                            .lock()
                            .await
                            .send(Message::Text(
                                json!({"type": "elements_in_region", "elements": elements}).to_string(),
                            ))
                            .await;
                    }
                    if let Some(html) = data.get("dom_content") {
                        let html = if html.is_null() { json!("") } else { html.clone() };
                        let sender = ws_sender.clone();
                        let _ = sender
                            .lock()
                            .await
                            .send(Message::Text(
                                json!({"type": "dom_content", "html": html}).to_string(),
                            ))
                            .await;
                    }

                    // Forward select_options, native_picker, etc. to frontend
                    if let Some("select_options" | "native_picker") =
                        data.get("type").and_then(|v| v.as_str())
                    {
                        let sender = ws_sender.clone();
                        let _ = sender
                            .lock()
                            .await
                            .send(Message::Text(data.to_string()))
                            .await;
                    }
                }
            }

            // Answer to an `upload_prompt` — unparks the page's file chooser.
            "upload_file_selected" if session_id.is_some() => {
                let sid = session_id.as_ref().unwrap().clone();
                state.recorder.deliver_upload_answer(&sid, &parsed).await;
            }
            "stop" if session_id.is_some() => {
                let sid = session_id.take().unwrap();
                tracing::info!(session_id = %sid, "WS: Stop recording");

                // Stop screenshot + event forwarding
                if let Some(task) = screenshot_forward_task.take() {
                    task.abort();
                }
                if let Some(task) = event_forward_task.take() {
                    task.abort();
                }

                // End the session
                match state.recorder.end_session(&sid).await {
                    Ok(result) => {
                        let sender = ws_sender.clone();
                        let _ = sender
                            .lock()
                            .await
                            .send(Message::Text(
                                json!({
                                    "type": "stopped",
                                    "steps": result.steps,
                                    "stepCount": result.step_count,
                                    "raw_replay": result.raw_replay,
                                    "rawReplayCount": result.raw_replay_count,
                                })
                                .to_string(),
                            ))
                            .await;
                    }
                    Err(e) => {
                        let sender = ws_sender.clone();
                        let _ = sender
                            .lock()
                            .await
                            .send(Message::Text(
                                json!({"type": "error", "message": e.to_string()}).to_string(),
                            ))
                            .await;
                    }
                }
            }

            "ai_start" => {
                let url = parsed
                    .get("url")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string();
                let goal = parsed
                    .get("goal")
                    .and_then(|v| v.as_str())
                    .unwrap_or("Complete the form")
                    .to_string();
                let available_data = parsed.get("data").cloned().unwrap_or(json!({}));
                let max_steps = parsed
                    .get("max_steps")
                    .and_then(|v| v.as_u64())
                    .unwrap_or(20) as usize;
                let mode = parsed
                    .get("mode")
                    .and_then(|v| v.as_str())
                    .unwrap_or("standard")
                    .to_string();
                let tenant_id = parsed
                    .get("tenant_id")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string();

                if url.is_empty() {
                    let sender = ws_sender.clone();
                    let _ = sender
                        .lock()
                        .await
                        .send(Message::Text(
                            json!({"type": "error", "message": "URL required"}).to_string(),
                        ))
                        .await;
                    continue;
                }

                tracing::info!(url = %url, goal = %goal, mode = %mode, "WS: AI start");

                match state.recorder.start_session(url.clone(), false, None).await {
                    Ok(sid) => {
                        // Subscribe to screenshot broadcast for AI sessions too
                        if let Some(session_ref) = state.recorder.get_session_mut(&sid) {
                            if let Some(ref tx) = session_ref.screenshot_tx {
                                let mut rx = tx.subscribe();
                                let sender = ws_sender.clone();
                                let fwd_task = tokio::spawn(async move {
                                    loop {
                                        match rx.recv().await {
                                            Ok(frame) => {
                                                let mut s = sender.lock().await;
                                                if s.send(Message::Binary(frame)).await.is_err() {
                                                    break;
                                                }
                                            }
                                            Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
                                            Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => {}
                                        }
                                    }
                                });
                                screenshot_forward_task = Some(fwd_task);
                            }
                        }

                        // Forward JSON events (step_recorded, etc.) during AI generation
                        if let Some(mut event_rx) = state.recorder.take_event_rx(&sid) {
                            let sender = ws_sender.clone();
                            let evt_task = tokio::spawn(async move {
                                while let Some(event) = event_rx.recv().await {
                                    let mut s = sender.lock().await;
                                    if s.send(Message::Text(event.to_string())).await.is_err() {
                                        break;
                                    }
                                }
                            });
                            event_forward_task = Some(evt_task);
                        }

                        // Get the page handle for AI work
                        let page = state
                            .recorder
                            .get_session_mut(&sid)
                            .map(|s| s.page.clone());

                        session_id = Some(sid.clone());

                        let sender = ws_sender.clone();
                        let _ = sender
                            .lock()
                            .await
                            .send(Message::Text(
                                json!({
                                    "type": "ai_started",
                                    "sessionId": sid,
                                    "url": url,
                                    "goal": goal,
                                })
                                .to_string(),
                            ))
                            .await;

                        // Run AI workflow generation in a spawned task
                        let ai_sender = ws_sender.clone();
                        let ai_url = url.clone();
                        let ai_sid = sid.clone();
                        let ai_state = state.clone();
                        tokio::spawn(async move {
                            // Send initial status
                            {
                                let _ = ai_sender.lock().await.send(Message::Text(
                                    json!({
                                        "type": "ai_status",
                                        "message": "Starting AI workflow generation...",
                                        "step": 0,
                                        "maxSteps": max_steps,
                                    })
                                    .to_string(),
                                )).await;
                            }

                            let page = match page {
                                Some(p) => p,
                                None => {
                                    let _ = ai_sender.lock().await.send(Message::Text(
                                        json!({"type": "ai_error", "error": "Session page not available"}).to_string(),
                                    )).await;
                                    return;
                                }
                            };

                            // Parse available_data into HashMap
                            let mut data_map = std::collections::HashMap::new();
                            if let Some(obj) = available_data.as_object() {
                                for (k, v) in obj {
                                    if let Some(s) = v.as_str() {
                                        data_map.insert(k.clone(), s.to_string());
                                    } else {
                                        data_map.insert(k.clone(), v.to_string());
                                    }
                                }
                            }

                            // Get the shared AI client
                            let ai_client_lock = crate::ai::client::get_shared_client();

                            if mode == "intelligent" {
                                // Intelligent mode
                                let ai_ref = if let Some(ref lock) = ai_client_lock {
                                    Some(lock.lock().await)
                                } else {
                                    None
                                };

                                let config = crate::ai::intelligent_mode::IntelligentModeConfig {
                                    goal: goal.clone(),
                                    user_context: None,
                                    available_data: data_map.clone(),
                                    fill_data: data_map.clone(),
                                    max_actions: max_steps,
                                    secure_keys: Vec::new(),
                                    tenant_id: tenant_id.clone(),
                                };

                                let ai_client_ref = ai_ref.as_deref().map(|c| c as &dyn crate::ai::client::AiClient);

                                match crate::ai::intelligent_mode::ai_generate_workflow_intelligent(
                                    &page,
                                    config,
                                    ai_client_ref,
                                ).await {
                                    Ok(result) => {
                                        let _ = ai_sender.lock().await.send(Message::Text(
                                            json!({
                                                "type": "ai_complete",
                                                "steps": result.steps,
                                                "stepCount": result.steps.len(),
                                                "raw_replay": result.raw_replay,
                                                "rawReplayCount": result.raw_replay.len(),
                                                "entry_url": ai_url,
                                                "success": result.success,
                                            })
                                            .to_string(),
                                        )).await;
                                    }
                                    Err(e) => {
                                        let _ = ai_sender.lock().await.send(Message::Text(
                                            json!({"type": "ai_error", "error": e.to_string()}).to_string(),
                                        )).await;
                                    }
                                }
                            } else {
                                // Standard mode
                                let ai_ref = if let Some(ref lock) = ai_client_lock {
                                    Some(lock.lock().await)
                                } else {
                                    None
                                };

                                let config = crate::ai::standard_mode::StandardModeConfig {
                                    goal: goal.clone(),
                                    available_data: data_map.clone(),
                                    fill_data: data_map.clone(),
                                    max_steps,
                                    use_vision: true,
                                    tenant_id: tenant_id.clone(),
                                    secure_keys: Vec::new(),
                                };

                                let ai_client_ref = ai_ref.as_deref().map(|c| c as &dyn crate::ai::client::AiClient);

                                match crate::ai::standard_mode::ai_generate_workflow(
                                    &page,
                                    config,
                                    ai_client_ref,
                                ).await {
                                    Ok(result) => {
                                        let _ = ai_sender.lock().await.send(Message::Text(
                                            json!({
                                                "type": "ai_complete",
                                                "steps": result.steps,
                                                "stepCount": result.steps.len(),
                                                "raw_replay": result.raw_replay,
                                                "rawReplayCount": result.raw_replay.len(),
                                                "entry_url": ai_url,
                                                "success": result.success,
                                            })
                                            .to_string(),
                                        )).await;
                                    }
                                    Err(e) => {
                                        let _ = ai_sender.lock().await.send(Message::Text(
                                            json!({"type": "ai_error", "error": e.to_string()}).to_string(),
                                        )).await;
                                    }
                                }
                            }

                            // End the session after AI completes
                            let _ = ai_state.recorder.end_session(&ai_sid).await;
                        });
                    }
                    Err(e) => {
                        let sender = ws_sender.clone();
                        let _ = sender
                            .lock()
                            .await
                            .send(Message::Text(
                                json!({"type": "error", "message": e.to_string()}).to_string(),
                            ))
                            .await;
                    }
                }
            }

            "ping" => {
                let sender = ws_sender.clone();
                let _ = sender
                    .lock()
                    .await
                    .send(Message::Text(
                        json!({"type": "pong"}).to_string(),
                    ))
                    .await;
            }

            _ => {
                tracing::debug!(msg_type = msg_type, "WS: Unknown message type");
            }
        }
    }

    // Cleanup on disconnect
    if let Some(task) = screenshot_forward_task.take() {
        task.abort();
    }
    if let Some(task) = event_forward_task.take() {
        task.abort();
    }

    // End session if still active
    if let Some(sid) = session_id.take() {
        tracing::info!(session_id = %sid, "WS disconnected, ending session");
        let _ = state.recorder.end_session(&sid).await;
    }

    tracing::info!("Recording WebSocket disconnected");
}

