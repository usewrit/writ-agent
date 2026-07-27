//! Process-global cloud `session_key` ↔ local streaming `workflow_id` correlation (Workstream A,
//! Stage 2 — the streaming capability).
//!
//! The cloud streaming protocol addresses a live session by an opaque `session_key` (its correlation
//! key over the gateway WS), while the desktop's [`crate::local::engine::streaming::LocalStreamingManager`]
//! keys its one-session-per-workflow registry by the LOCAL integer `workflow_id`. This tiny in-memory
//! table bridges the two so a follow-up `streaming_command` / `end_streaming_session` frame (which
//! carries only the `session_key`) can resolve back to the local workflow whose warm tab is serving it.
//!
//! The map is a `DashMap<String, i64>` behind a process-global `OnceLock` (mirrors [`super::runs`] and
//! the `RelayNodeManager` singleton). It is PURE local routing metadata — never a token, credential, or
//! recipe content; identity/billing stay server-side (the never-trust-a-BYO-agent rule). Entries are
//! inserted when a session starts and removed on `end_streaming_session` (or a start failure) so a
//! stale `session_key` can never mis-route a turn.

use std::sync::OnceLock;

use dashmap::DashMap;

/// The process-global `session_key → workflow_id` table. Lazily created on first use.
fn table() -> &'static DashMap<String, i64> {
    static MAP: OnceLock<DashMap<String, i64>> = OnceLock::new();
    MAP.get_or_init(DashMap::new)
}

/// Record that cloud streaming `session_key` is being served by the local streaming `workflow_id`. An
/// empty `session_key` is ignored (a dispatch with no correlation key can't be commanded/ended by key).
/// Overwrites a prior entry for the same key (an idempotent re-start reuses it) so the map always
/// points at the current workflow.
pub fn bind(session_key: &str, workflow_id: i64) {
    if session_key.is_empty() {
        return;
    }
    table().insert(session_key.to_string(), workflow_id);
}

/// Look up the local `workflow_id` currently serving cloud streaming `session_key`, if any. Used by
/// `streaming_command` / `end_streaming_session` to route to the right warm session.
pub fn workflow_for(session_key: &str) -> Option<i64> {
    table().get(session_key).map(|e| *e.value())
}

/// Drop the entry for `session_key` (the session ended / the start failed). Idempotent: removing an
/// absent key is a no-op. Called from every terminal path that [`bind`]s, so the table only ever holds
/// LIVE cloud streaming sessions.
pub fn unbind(session_key: &str) {
    if session_key.is_empty() {
        return;
    }
    table().remove(session_key);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bind_lookup_unbind_roundtrip() {
        let key = "test-streaming-map-abc";
        assert!(workflow_for(key).is_none(), "absent key → None");
        bind(key, 91);
        assert_eq!(workflow_for(key), Some(91));
        unbind(key);
        assert!(workflow_for(key).is_none(), "unbound key → None");
    }

    #[test]
    fn empty_session_key_is_ignored() {
        bind("", 1);
        assert!(workflow_for("").is_none());
        unbind(""); // no panic / no-op
    }

    #[test]
    fn rebind_overwrites_to_current_workflow() {
        let key = "test-streaming-map-rebind";
        bind(key, 1);
        bind(key, 2);
        assert_eq!(workflow_for(key), Some(2), "re-start points at the current workflow");
        unbind(key);
    }
}
