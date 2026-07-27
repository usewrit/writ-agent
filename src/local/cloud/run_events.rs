//! Cloud run-events forwarder.
//!
//! Subscribes to the linked account's cloud `GET /api/runs/events` SSE stream and injects an event
//! into the engine's GLOBAL run-events stream on each frame. The desktop shell forwards the global
//! stream as a Tauri `run:event`, so the webview reacts the instant something changes cloud-side —
//! WITHOUT polling.
//!
//! Design (best-practice, self-healing):
//!   * Runs only while the desktop is LINKED — an unlinked/expired token just backs off and rechecks;
//!     never a hot loop, never a surfaced error.
//!   * ONE long-lived connection with capped exponential backoff on drop; the cloud's 15s keep-alive
//!     comments hold it open, and [`CloudClient::open_stream`] refreshes the token on a connect-time
//!     401.
//!
//! ## What we read out of a cloud frame
//! The cloud stream carries two families (see the cloud backend's `run_events` service):
//!
//!   * **Run deltas** → a [`RunEvent::CloudReflected`] NUDGE, the frame's contents untouched. The
//!     webview always refetches fresh reflection state, so there is nothing to gain by parsing.
//!   * **Entity deltas** (`event: "entity"`) → a [`RunEvent::CloudEntity`]. These describe a RECORD
//!     changing, and a nudge is not enough: the webview must know WHICH list to refresh, and a
//!     "refetch everything on any frame" fallback would re-list on every run-progress tick.
//!
//! So we parse, but only the control metadata — the record type, the action and row ids. We never
//! read a name, URL, or any other payload field, preserving the rule that a cloud value never
//! transits this forwarder.

use std::sync::Arc;
use std::time::Duration;

use futures_util::StreamExt;
use sqlx::SqlitePool;

use super::client::CloudClient;
use super::state::LinkState;
use crate::local::engine::events::RunEvent;
use crate::local::engine::RunRegistry;

/// Cloud all-runs SSE (backend `routers/runs.py::runs_events`).
const CLOUD_RUN_EVENTS_PATH: &str = "/api/runs/events";
/// Reconnect backoff bounds (seconds).
const BACKOFF_MIN_S: u64 = 2;
const BACKOFF_MAX_S: u64 = 30;
/// How often to re-check the link when unlinked / tokenless (cheap; avoids a hot loop).
const UNLINKED_RECHECK_S: u64 = 20;
/// Safety cap on the frame buffer so a peer that never sends a delimiter can't grow it unbounded.
const MAX_FRAME_BUFFER: usize = 64 * 1024;

/// Run the forwarder loop forever. Spawn once at daemon startup with the engine's registry.
pub async fn run(db: SqlitePool, registry: Arc<RunRegistry>) {
    let mut backoff = BACKOFF_MIN_S;
    loop {
        let mut client = match connect_client(&db).await {
            Some(c) => c,
            None => {
                // Not linked / no token yet — recheck periodically without hammering.
                tokio::time::sleep(Duration::from_secs(UNLINKED_RECHECK_S)).await;
                continue;
            }
        };

        match client.open_stream(CLOUD_RUN_EVENTS_PATH).await {
            Ok(resp) => {
                backoff = BACKOFF_MIN_S; // a healthy connection resets the backoff
                consume_stream(resp, &registry).await;
                // Stream ended (server restart / token expiry / network blip) → reconnect.
            }
            Err(e) => {
                tracing::debug!(error = %e, "cloud run-events stream unavailable; will retry");
            }
        }
        tokio::time::sleep(Duration::from_secs(backoff)).await;
        backoff = (backoff * 2).min(BACKOFF_MAX_S);
    }
}

/// Build a cloud client for the CURRENT link, or `None` when the desktop isn't linked / has no token.
async fn connect_client(db: &SqlitePool) -> Option<CloudClient> {
    let link = LinkState::load_or_default(db).await.ok()?;
    CloudClient::connect(Some(&link)).ok()
}

/// Drain an SSE response body, emitting one event per `data:` frame. Buffers across chunks and splits
/// on the SSE frame delimiter (a blank line). Comment/keep-alive frames (`: ping`) carry no `data:`
/// line and are ignored. We treat the bytes as lossy UTF-8 — only the ASCII `\n\n` delimiter and the
/// `data:` prefix are inspected, so a multibyte char split across a chunk boundary is harmless.
async fn consume_stream(resp: reqwest::Response, registry: &Arc<RunRegistry>) {
    let mut stream = resp.bytes_stream();
    let mut buf = String::new();
    while let Some(chunk) = stream.next().await {
        let bytes = match chunk {
            Ok(b) => b,
            Err(_) => break, // stream error → reconnect
        };
        buf.push_str(&String::from_utf8_lossy(&bytes));
        while let Some(idx) = buf.find("\n\n") {
            let frame: String = buf.drain(..idx + 2).collect();
            if frame.lines().any(|l| l.starts_with("data:")) {
                // An entity frame names the record that changed; anything else is a run delta and
                // stays a contents-free nudge.
                let ev = parse_entity_frame(&frame)
                    .unwrap_or(RunEvent::CloudReflected { task_id: 0 });
                registry.emit_global(ev);
            }
        }
        if buf.len() > MAX_FRAME_BUFFER {
            buf.clear();
        }
    }
}

/// Extract a [`RunEvent::CloudEntity`] from a frame carrying the backend's `event: "entity"`
/// discriminant. Returns `None` for a run delta, an unparseable body, or an entity frame missing its
/// `entity` field — every one of which the caller degrades to a plain nudge.
///
/// Reads ONLY `event` / `entity` / `action` / `id` / `target_id`. Other payload fields are ignored,
/// never copied, and never logged.
fn parse_entity_frame(frame: &str) -> Option<RunEvent> {
    let data: String = frame
        .lines()
        .filter_map(|l| l.strip_prefix("data:"))
        .map(str::trim)
        .collect();
    if data.is_empty() {
        return None;
    }
    let v: serde_json::Value = serde_json::from_str(&data).ok()?;
    if v.get("event")?.as_str()? != "entity" {
        return None;
    }
    Some(RunEvent::CloudEntity {
        entity: v.get("entity")?.as_str()?.to_string(),
        action: v
            .get("action")
            .and_then(serde_json::Value::as_str)
            .unwrap_or("updated")
            .to_string(),
        id: v.get("id").and_then(serde_json::Value::as_i64),
        target_id: v.get("target_id").and_then(serde_json::Value::as_i64),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn entity_frame_parses_control_fields_only() {
        let frame = "data: {\"event\":\"entity\",\"entity\":\"workflow\",\"action\":\"updated\",\"id\":42,\"name\":\"secret\"}\n\n";
        match parse_entity_frame(frame) {
            Some(RunEvent::CloudEntity { entity, action, id, target_id }) => {
                assert_eq!(entity, "workflow");
                assert_eq!(action, "updated");
                assert_eq!(id, Some(42));
                assert_eq!(target_id, None);
            }
            other => panic!("expected CloudEntity, got {other:?}"),
        }
    }

    #[test]
    fn change_frame_carries_target_id() {
        let frame = "data: {\"event\":\"entity\",\"entity\":\"change\",\"action\":\"created\",\"id\":7,\"target_id\":3}\n\n";
        match parse_entity_frame(frame) {
            Some(RunEvent::CloudEntity { entity, id, target_id, .. }) => {
                assert_eq!(entity, "change");
                assert_eq!(id, Some(7));
                assert_eq!(target_id, Some(3));
            }
            other => panic!("expected CloudEntity, got {other:?}"),
        }
    }

    #[test]
    fn run_delta_and_garbage_are_not_entities() {
        // A run delta must fall through to the nudge path, not be mistaken for an entity.
        assert!(parse_entity_frame("data: {\"event\":\"updated\",\"run_type\":\"workflow\",\"id\":\"workflow-1\"}\n\n").is_none());
        // The queue broadcaster's push, which has no `id` at all.
        assert!(parse_entity_frame("data: {\"event\":\"queue\",\"queue_total\":0,\"runs\":[]}\n\n").is_none());
        assert!(parse_entity_frame("data: not json\n\n").is_none());
        assert!(parse_entity_frame(": ping\n\n").is_none());
        // An entity frame missing its `entity` field degrades to a nudge rather than panicking.
        assert!(parse_entity_frame("data: {\"event\":\"entity\",\"action\":\"updated\"}\n\n").is_none());
    }

    #[test]
    fn entity_serializes_shape_identical_to_the_cloud_frame() {
        // The webview branches on `event === "entity"` for BOTH transports, so the Tauri IPC payload
        // must match the cloud's own SSE frame shape.
        let ev = RunEvent::CloudEntity {
            entity: "monitor".into(),
            action: "created".into(),
            id: Some(5),
            target_id: None,
        };
        let v: serde_json::Value = serde_json::to_value(&ev).unwrap();
        assert_eq!(v.get("event").unwrap(), "entity");
        assert_eq!(v.get("entity").unwrap(), "monitor");
        assert_eq!(v.get("action").unwrap(), "created");
        assert_eq!(v.get("id").unwrap(), 5);
    }
}
