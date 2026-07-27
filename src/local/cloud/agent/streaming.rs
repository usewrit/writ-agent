//! `start_streaming_session` / `streaming_command` / `end_streaming_session` — desktop mirror of the
//! cloud `bridge/saas_bridge` streaming relay (Workstream A, Stage 2).
//!
//! The cloud dispatches a long-lived streaming session (a chat-style workflow driven via
//! `ps.on(...)` handlers) to this machine. The saas_bridge version is welded to `PlaywrightRecorder`
//! + an ad-hoc `AgentSessionRelay` + a bespoke per-session command loop. The desktop instead routes
//! onto its OWN [`LocalStreamingManager`] (the same engine behind `/v1/streaming/sessions`), which
//! already owns the warm browser, persona login, setup-step replay, and per-turn dispatch — so cloud
//! streaming runs on the SAME Chromium as local streaming, never a second one.
//!
//! ## What is supported vs degraded (honest capability surface)
//! The `LocalStreamingManager` is keyed by a LOCAL streaming [`workflow`](crate::local::store::workflows)
//! id and drives the session off that local recipe (its handlers / advanced script / persona). So this
//! handler supports the case the desktop can actually service faithfully: a dispatch that names a
//! **cloud-callable local streaming workflow** by id (`local_workflow_id`, matching the by-id
//! `run_local_workflow` contract). An **ad-hoc** streaming dispatch (an inline recipe with no local
//! workflow) would require porting the entire ad-hoc relay + command loop; rather than run a subtly
//! divergent second engine we ACK it as not-yet-supported so the backend degrades gracefully (it can
//! fall back to a cloud-hosted session). This is recorded in the step's stubbed list.
//!
//! ## Frame contract (mirrors saas_bridge)
//!   * `start_streaming_session` → `task_result{success, result_data:{session_key,status}}` up-front,
//!     then `streaming_session_started{session_key,url}` once the warm tab is live.
//!   * `streaming_command`       → run ONE turn; forward each `ps.stream(...)` chunk as
//!     `stream_chunk{session_key,request_id,data}` and finish with `command_response{...,data}` (or a
//!     `command_response` carrying an `error`).
//!   * `end_streaming_session`   → stop the local session; `streaming_session_ended{session_key,end_reason}`.
//!
//! SECURITY (the never-trust-a-BYO-agent rule): identity/billing stay server-side. The stream carries
//! model OUTPUT only (never credentials); the local session decrypts persona secrets on-device via the
//! same vault the local streaming path uses. Every wire-derived string is char-safe truncated in logs.

use std::sync::Arc;

use serde_json::{json, Value};
use tokio::sync::mpsc;
use tokio_tungstenite::tungstenite::Message;

use super::super::super::engine::streaming::{LocalStreamingManager, StreamEvent};
use super::super::super::store::workflows;
use super::streaming_map;

/// Char-safe truncation for logging wire-derived strings (mirrors `gateway::truncate_str`).
fn truncate_str(s: &str, max_chars: usize) -> String {
    s.chars().take(max_chars).collect()
}

/// The `session_key` for a streaming frame: `config.session_key` then top-level `session_key` (matches
/// the cloud `handle_start_streaming_session` precedence).
fn session_key_of(msg: &Value) -> String {
    msg["config"]["session_key"]
        .as_str()
        .or(msg["session_key"].as_str())
        .unwrap_or("")
        .to_string()
}

/// The local workflow id a streaming dispatch names, if any. Mirrors the `run_local_workflow` by-id
/// contract: `local_workflow_id` at the top level or under `config`. A non-numeric / absent id → `None`
/// (→ the ad-hoc path, which the desktop degrades).
fn local_workflow_id_of(msg: &Value) -> Option<i64> {
    let raw = msg["local_workflow_id"]
        .as_str()
        .or(msg["config"]["local_workflow_id"].as_str())?;
    raw.trim().parse::<i64>().ok()
}

/// Handle `start_streaming_session`. Routes a dispatch that names a cloud-callable LOCAL streaming
/// workflow onto [`LocalStreamingManager::start_session`] (warm tab, persona login, setup replay), then
/// binds `session_key → workflow_id` so follow-up commands resolve. An ad-hoc dispatch (no resolvable
/// local workflow) is ACKed as not-yet-supported so the backend degrades to a cloud-hosted session.
///
/// Emits directly onto `outgoing` (rather than returning one frame) because it sends TWO frames: the
/// immediate `task_result` ack, then `streaming_session_started` once the tab is live.
pub async fn handle_start(
    task_id: &str,
    msg: &Value,
    streaming: &Arc<LocalStreamingManager>,
    db: &sqlx::SqlitePool,
    outgoing: &mpsc::UnboundedSender<Message>,
) {
    let session_key = session_key_of(msg);
    let wf_id = match local_workflow_id_of(msg) {
        Some(id) => id,
        None => {
            // Ad-hoc streaming (inline recipe, no local workflow) — the desktop can't service it
            // without a divergent second engine. Fail closed so the backend degrades gracefully.
            let _ = outgoing.send(Message::Text(
                task_result(task_id, false, json!({"session_key": session_key}),
                    Some("ad-hoc streaming sessions are not supported on this agent; \
                          only cloud-callable local streaming workflows can run here".into()))
                    .to_string(),
            ));
            return;
        }
    };

    // Load the local streaming recipe by id. A missing workflow fails closed.
    //
    // SECURITY (TB-1): the cloud may only start a session on a workflow the owner has EXPLICITLY
    // exposed (`cloud_callable == 1`) AND that is actually a streaming recipe. A dispatch naming a
    // non-exposed id, or a non-streaming workflow, is refused before any browser/session is started —
    // otherwise a guessed/stale id would launch a never-exposed private workflow.
    let wf = match workflows::get_by_id(db, wf_id).await {
        Ok(Some(wf)) if wf.cloud_callable == 1 && wf.workflow_type == "streaming" => wf,
        Ok(Some(wf)) if wf.cloud_callable != 1 => {
            let _ = outgoing.send(Message::Text(
                task_result(task_id, false, json!({"session_key": session_key}),
                    Some(format!("workflow {wf_id} is not exposed for cloud execution"))).to_string(),
            ));
            return;
        }
        Ok(Some(_)) => {
            let _ = outgoing.send(Message::Text(
                task_result(task_id, false, json!({"session_key": session_key}),
                    Some(format!("workflow {wf_id} is not a streaming workflow"))).to_string(),
            ));
            return;
        }
        Ok(None) => {
            let _ = outgoing.send(Message::Text(
                task_result(task_id, false, json!({"session_key": session_key}),
                    Some(format!("local streaming workflow {wf_id} not found"))).to_string(),
            ));
            return;
        }
        Err(e) => {
            let _ = outgoing.send(Message::Text(
                task_result(task_id, false, json!({"session_key": session_key}),
                    Some(format!("failed to load workflow {wf_id}: {e}"))).to_string(),
            ));
            return;
        }
    };

    tracing::info!(
        task_id,
        wf_id,
        session_key = %truncate_str(&session_key, 16),
        "LinkedAgentBridge starting cloud streaming session on the local engine"
    );

    match streaming.start_session(&wf).await {
        Ok(info) => {
            // Bind the CLOUD session_key to the local workflow so streaming_command / end resolve.
            if !session_key.is_empty() {
                streaming_map::bind(&session_key, wf_id);
            }
            // Up-front task_result ack (parity with the cloud handler — the streaming service flips the
            // session to "running" off this, without waiting on setup).
            let _ = outgoing.send(Message::Text(
                task_result(
                    task_id,
                    true,
                    json!({ "session_key": session_key, "status": "running" }),
                    None,
                )
                .to_string(),
            ));
            // Then the "runtime ready" confirmation frame.
            let _ = outgoing.send(Message::Text(
                json!({
                    "type": "streaming_session_started",
                    "session_key": session_key,
                    "url": info.target_url,
                })
                .to_string(),
            ));
        }
        Err(e) => {
            let _ = outgoing.send(Message::Text(
                task_result(task_id, false, json!({"session_key": session_key}),
                    Some(format!("streaming session start failed: {e}"))).to_string(),
            ));
        }
    }
}

/// Handle `streaming_command`: run ONE turn on the session's warm tab and forward its streamed output.
///
/// Resolves `session_key → workflow_id` from the process map. Unknown session → a single
/// `command_response` carrying an error (never a hang). Each [`StreamEvent::Chunk`] is forwarded as a
/// `stream_chunk`; the terminal `Done`/`Error` becomes one `command_response`.
pub async fn handle_command(
    msg: &Value,
    streaming: &Arc<LocalStreamingManager>,
    db: &sqlx::SqlitePool,
    outgoing: &mpsc::UnboundedSender<Message>,
) {
    let session_key = msg["session_key"].as_str().unwrap_or("").to_string();
    let request_id = msg["request_id"].as_str().unwrap_or("").to_string();

    let wf_id = match streaming_map::workflow_for(&session_key) {
        Some(id) => id,
        None => {
            tracing::warn!(
                session_key = %truncate_str(&session_key, 16),
                "streaming_command for unknown session (no live local session)"
            );
            let _ = outgoing.send(Message::Text(command_response(
                &session_key,
                &request_id,
                json!({ "error": "unknown streaming session" }),
            ).to_string()));
            return;
        }
    };

    // Load the recipe fresh each turn (cheap; keeps the handler map + persona resolution correct even
    // if the session was started before this daemon process). A vanished workflow ends the turn.
    let wf = match workflows::get_by_id(db, wf_id).await {
        Ok(Some(wf)) => wf,
        _ => {
            let _ = outgoing.send(Message::Text(command_response(
                &session_key,
                &request_id,
                json!({ "error": format!("workflow {wf_id} no longer available") }),
            ).to_string()));
            return;
        }
    };

    // The command payload the handler reads: prefer `config`/`data`/`inputs` (whatever the backend
    // sends), else pass the whole frame's action fields through. `request_id` is forwarded so the local
    // manager's own request routing stays internal (the cloud request_id is echoed on the way out).
    let inputs = msg
        .get("data")
        .or_else(|| msg.get("config"))
        .or_else(|| msg.get("inputs"))
        .cloned()
        .unwrap_or_else(|| json!({}));

    match streaming.run_turn(&wf, inputs).await {
        Ok((mut rx, response_field)) => {
            while let Some(ev) = rx.recv().await {
                match ev {
                    StreamEvent::Chunk { content } => {
                        let _ = outgoing.send(Message::Text(
                            json!({
                                "type": "stream_chunk",
                                "session_key": session_key,
                                "request_id": request_id,
                                "data": content,
                            })
                            .to_string(),
                        ));
                    }
                    StreamEvent::Done { data } => {
                        // Surface the whole final payload; the backend pulls `response_field` out of it
                        // exactly like the local SSE layer, so include it as a hint for parity.
                        let _ = outgoing.send(Message::Text(command_response(
                            &session_key,
                            &request_id,
                            json!({ "data": data, "response_field": response_field }),
                        ).to_string()));
                        break;
                    }
                    StreamEvent::Error { message } => {
                        let _ = outgoing.send(Message::Text(command_response(
                            &session_key,
                            &request_id,
                            json!({ "error": message }),
                        ).to_string()));
                        break;
                    }
                }
            }
        }
        Err(e) => {
            let _ = outgoing.send(Message::Text(command_response(
                &session_key,
                &request_id,
                json!({ "error": format!("turn dispatch failed: {e}") }),
            ).to_string()));
        }
    }
}

/// Handle `end_streaming_session`: stop the local session for the resolved workflow and confirm.
/// Unknown/finished session → a terminal `streaming_session_ended` anyway (idempotent teardown).
pub async fn handle_end(
    msg: &Value,
    streaming: &Arc<LocalStreamingManager>,
    outgoing: &mpsc::UnboundedSender<Message>,
) {
    let session_key = msg["session_key"].as_str().unwrap_or("").to_string();
    let reason = msg["reason"].as_str().or(msg["end_reason"].as_str()).unwrap_or("user_ended");

    if let Some(wf_id) = streaming_map::workflow_for(&session_key) {
        let _ = streaming.stop_session(wf_id, reason).await;
    }
    // Drop the mapping regardless (idempotent) so a stale key can never mis-route a later command.
    streaming_map::unbind(&session_key);

    let _ = outgoing.send(Message::Text(
        json!({
            "type": "streaming_session_ended",
            "session_key": session_key,
            "end_reason": reason,
        })
        .to_string(),
    ));
}

/// The fixed streaming `task_result` frame (the cloud streaming ack uses `result_data`, NOT the
/// `extracted_data` of a normal run — kept faithful so the backend correlates the start).
fn task_result(task_id: &str, success: bool, result_data: Value, error: Option<String>) -> Value {
    json!({
        "type": "task_result",
        "task_id": task_id,
        "success": success,
        "result_data": result_data,
        "error": error,
    })
}

/// The `command_response` frame terminating one streaming turn.
fn command_response(session_key: &str, request_id: &str, data: Value) -> Value {
    json!({
        "type": "command_response",
        "session_key": session_key,
        "request_id": request_id,
        "data": data,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn session_key_precedence_config_then_top_level() {
        assert_eq!(session_key_of(&json!({"config": {"session_key": "a"}})), "a");
        assert_eq!(session_key_of(&json!({"session_key": "b"})), "b");
        // config wins over top-level (matches the cloud handler).
        assert_eq!(
            session_key_of(&json!({"config": {"session_key": "cfg"}, "session_key": "top"})),
            "cfg"
        );
        assert_eq!(session_key_of(&json!({})), "");
    }

    #[test]
    fn local_workflow_id_parses_top_level_and_config() {
        assert_eq!(local_workflow_id_of(&json!({"local_workflow_id": "42"})), Some(42));
        assert_eq!(
            local_workflow_id_of(&json!({"config": {"local_workflow_id": "7"}})),
            Some(7)
        );
        // Non-numeric / absent → None (ad-hoc path).
        assert_eq!(local_workflow_id_of(&json!({"local_workflow_id": "abc"})), None);
        assert_eq!(local_workflow_id_of(&json!({"config": {"steps": []}})), None);
    }

    #[test]
    fn task_result_streaming_shape_uses_result_data() {
        let ok = task_result("t1", true, json!({"session_key": "s", "status": "running"}), None);
        assert_eq!(ok["type"], "task_result");
        assert_eq!(ok["task_id"], "t1");
        assert_eq!(ok["success"], true);
        assert_eq!(ok["result_data"]["status"], "running");
        assert!(ok["error"].is_null());
        // Failure carries the message and NO extracted_data key (streaming uses result_data).
        let bad = task_result("t2", false, json!({"session_key": "s"}), Some("boom".into()));
        assert_eq!(bad["success"], false);
        assert_eq!(bad["error"], "boom");
        assert!(bad.get("extracted_data").is_none());
    }

    #[test]
    fn command_response_shape_matches_contract() {
        let f = command_response("sk", "req-9", json!({"data": {"content": "hi"}}));
        assert_eq!(f["type"], "command_response");
        assert_eq!(f["session_key"], "sk");
        assert_eq!(f["request_id"], "req-9");
        assert_eq!(f["data"]["data"]["content"], "hi");
    }

    #[tokio::test]
    async fn handle_command_for_unknown_session_answers_error_without_panic() {
        // No live session bound → one command_response carrying an error, no hang, no browser needed.
        // (We reach the unknown-session branch before touching the streaming manager or db.)
        let (tx, mut rx) = mpsc::unbounded_channel::<Message>();
        let msg = json!({
            "type": "streaming_command",
            "session_key": "streaming-handler-unknown-session-test",
            "request_id": "r1",
        });
        // Build a throwaway pool/manager only to satisfy the signature; the unknown-session branch
        // returns BEFORE touching the browser or db (it resolves the empty process map first), so no
        // Chromium is launched. Use an in-memory sqlite + a temp-dir vault so no real filesystem/home
        // is touched.
        let db = sqlx::SqlitePool::connect("sqlite::memory:").await.unwrap();
        let browser = Arc::new(crate::browser::manager::BrowserManager::new(Arc::new(
            crate::config::env::AppConfig::from_env(),
        )));
        let dir = tempfile::tempdir().unwrap();
        let vault = Arc::new(crate::local::vault::Vault::load_or_create(dir.path(), false).unwrap());
        let mgr = Arc::new(LocalStreamingManager::new(browser, db.clone(), vault));
        handle_command(&msg, &mgr, &db, &tx).await;
        let out = rx.recv().await.expect("a command_response was emitted");
        let v: Value = serde_json::from_str(out.to_text().unwrap()).unwrap();
        assert_eq!(v["type"], "command_response");
        assert_eq!(v["session_key"], "streaming-handler-unknown-session-test");
        assert!(v["data"]["error"].as_str().unwrap().contains("unknown streaming session"));
    }
}
