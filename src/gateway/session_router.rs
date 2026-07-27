use std::sync::Arc;

use dashmap::DashMap;

use crate::ai::relay::GatewaySessionRelay;

pub struct GatewaySession {
    pub local_session_id: Option<String>,
    pub relay: Arc<GatewaySessionRelay>,
    pub action_timestamps: Vec<std::time::Instant>,
}

pub type GatewaySessions = Arc<DashMap<String, GatewaySession>>;

pub async fn on_session_open(
    sessions: &GatewaySessions,
    session_id: &str,
    _purpose: &str,
    _config: &serde_json::Value,
    relay: Arc<GatewaySessionRelay>,
) -> bool {
    sessions.insert(
        session_id.to_string(),
        GatewaySession {
            local_session_id: None,
            relay,
            action_timestamps: Vec::new(),
        },
    );

    tracing::info!(session_id = session_id, "Gateway session opened");
    true
}

pub async fn on_session_message(
    _sessions: &GatewaySessions,
    session_id: &str,
    msg: &serde_json::Value,
) {
    let msg_type = msg.get("type").and_then(|v| v.as_str()).unwrap_or("");

    match msg_type {
        "start" => {
            let url = msg.get("url").and_then(|v| v.as_str()).unwrap_or("");
            tracing::info!(session_id = session_id, url = url, "Gateway: start session");
            // recorder.start_session(), store local_sid
        }
        "action" => {
            // Rate limit check (30/s excluding scroll/mousemove/hover)
            // recorder.handle_action()
        }
        "stop" => {
            tracing::info!(session_id = session_id, "Gateway: stop session");
            // recorder.end_session(), send result
        }
        "ai_start" => {
            let url = msg.get("url").and_then(|v| v.as_str()).unwrap_or("");
            let goal = msg.get("goal").and_then(|v| v.as_str()).unwrap_or("");
            tracing::info!(
                session_id = session_id,
                url = url,
                goal = goal,
                "Gateway: AI start"
            );
            // Start session, run AI workflow
        }
        "ping" => {
            // Send pong
        }
        "start_streaming" => {
            tracing::info!(session_id = session_id, "Gateway: start streaming");
            // Create StreamingSessionManager, decrypt credentials, start
        }
        "streaming_command" => {
            // Delegate to StreamingSessionManager.handle_command()
        }
        "end_streaming" => {
            tracing::info!(session_id = session_id, "Gateway: end streaming");
            // End streaming manager
        }
        "add_handler" | "remove_handler" => {
            // Delegate to streaming manager
        }
        other => {
            tracing::warn!(
                session_id = session_id,
                msg_type = other,
                "Gateway: unknown message type"
            );
        }
    }
}

pub async fn on_session_close(sessions: &GatewaySessions, session_id: &str) {
    if let Some((_, _session)) = sessions.remove(session_id) {
        tracing::info!(session_id = session_id, "Gateway session closed");
        // End streaming session if active
        // End local recorder session
    }
}
