use std::sync::Arc;

use dashmap::DashMap;

use crate::streaming::manager::StreamingSessionManager;

pub type StreamingSessions = Arc<DashMap<String, StreamingSessionManager>>;

pub async fn create_streaming_session(
    sessions: &StreamingSessions,
    session_key: &str,
    config: serde_json::Value,
    page: playwright_rs::Page,
    context: playwright_rs::BrowserContext,
) -> Result<(), anyhow::Error> {
    let mut manager = StreamingSessionManager::new(session_key.to_string(), config);
    manager.start(page, context).await?;
    sessions.insert(session_key.to_string(), manager);
    Ok(())
}

pub async fn handle_streaming_command(
    sessions: &StreamingSessions,
    session_key: &str,
    cmd: &serde_json::Value,
) -> Result<(), anyhow::Error> {
    let mut entry = sessions
        .get_mut(session_key)
        .ok_or_else(|| anyhow::anyhow!("Streaming session not found: {}", session_key))?;

    // `handle_command` now returns an optional reply value (CR-2); this gateway router discards it
    // (the caller here only cares about success/failure).
    crate::streaming::commands::handle_command(entry.value_mut(), cmd)
        .await
        .map(|_| ())
}

pub async fn end_streaming_session(
    sessions: &StreamingSessions,
    session_key: &str,
    reason: &str,
) {
    if let Some(mut entry) = sessions.get_mut(session_key) {
        entry.value_mut().end(reason).await;
    }
    sessions.remove(session_key);
}
