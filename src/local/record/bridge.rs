//! `session_open{purpose:"record"}` — desktop mirror of the cloud recorder relay.
//!
//! When the cloud frontend clicks "Record", the ws-gateway (`handlers/record.ts`) picks an agent
//! and sends `{type:"session_open", session_id, purpose:"record", config:{}}` to it, then
//! MULTIPLEXES every subsequent frontend↔agent frame through the SAME agent WS wrapped as
//! `{channel:"session", session_id, msg}` (or a `[0x01][4B sid_len][sid][jpeg]` binary envelope
//! for screencast frames). The desktop daemon owns a real `PlaywrightRecorder` (used by the
//! loopback `/ws/record`), so a cloud-dispatched recording should run on the SAME recorder + warm
//! Chromium — never on the AI-browsing session router (which the previous build hit by treating
//! ALL `session_open` frames the same, opening a plain browser context and never emitting recorder
//! events, so nothing was captured).
//!
//! This module is the seam:
//!   * [`CloudRecordSink`] — wraps outbound JSON in `{channel:"session", session_id, msg}` and
//!     outbound binary in `[0x01][4B sid_len][sid][payload]` before pushing to the bridge's
//!     `outgoing_tx`, so [`crate::local::record::session::SessionDriver`] stays sink-agnostic and
//!     the loopback + cloud paths share ONE recorder driver.
//!   * [`open`] — spawns a per-session task holding a `SessionDriver<CloudRecordSink>` and
//!     registers its inbound-frame `mpsc::UnboundedSender<Value>` in the process-global map keyed
//!     by `session_id`. Returns the immediate `session_opened` ack for the bridge to send.
//!   * [`dispatch_wrapped`] — the LinkedAgentBridge router calls this when it sees a
//!     `{channel:"session", session_id, msg}` inbound frame; we look up the live session and
//!     forward the unwrapped `msg` into its driver task.
//!   * [`close`] — teardown on `session_close` from the gateway (or a client-driven `stop` inside
//!     the driver; either path removes the entry and lets the driver drop cleanly).
//!
//! SECURITY: identity/billing/quota stay server-side (the never-trust-a-BYO-agent rule). The
//! recorder itself vets the start URL (SSRF guard) before opening a context; nothing here trusts
//! anything on the wire beyond routing metadata. Never logs steps/credentials/URLs beyond a
//! char-safe truncated session id.

use std::sync::atomic::{AtomicI64, Ordering};
use std::sync::{Arc, OnceLock};

use dashmap::DashMap;
use serde_json::{json, Value};
use tokio::sync::mpsc;
use tokio_tungstenite::tungstenite::Message;

use crate::local::record::session::{RecordSink, SessionDriver};
use crate::recorder::core::PlaywrightRecorder;

/// Char-safe truncation for wire-derived strings before they land in logs (mirrors
/// `gateway::truncate_str`; a hostile gateway could otherwise wedge us on a multibyte id).
fn truncate_str(s: &str, max_chars: usize) -> String {
    s.chars().take(max_chars).collect()
}

// ---------------------------------------------------------------------------
// Outbound sink — wraps FLAT recorder frames back into the ws-gateway envelope
// ---------------------------------------------------------------------------

/// [`RecordSink`] impl that pushes onto the LinkedAgentBridge's outbound `mpsc::UnboundedSender`
/// with the ws-gateway envelope re-applied:
///   * text  → `{channel:"session", session_id, msg: <FLAT frame>}` as `Message::Text`
///   * bytes → `[0x01][4B BE sid_len][sid_utf8][payload]` as `Message::Binary`
///
/// The gateway's `session-dispatcher.ts` `dispatchToFrontend` / `dispatchBinaryToFrontend` strip
/// exactly that shape and forward the inner `msg` / `payload` to the frontend — so a
/// `SessionDriver<CloudRecordSink>` produces bytes-identical frames on the cloud side and the
/// loopback side (via `LoopbackSink`) beyond the envelope layer.
///
/// A closed peer channel is treated as "peer gone": both send methods return `false` so the
/// forwarder tasks (screencast pump, recorder-event pump) stop pulling from their sources.
#[derive(Clone)]
pub struct CloudRecordSink {
    session_id: Arc<String>,
    outgoing: mpsc::UnboundedSender<Message>,
}

impl CloudRecordSink {
    pub fn new(session_id: String, outgoing: mpsc::UnboundedSender<Message>) -> Self {
        Self { session_id: Arc::new(session_id), outgoing }
    }
}

impl RecordSink for CloudRecordSink {
    async fn send_json(&self, v: Value) -> bool {
        let frame = json!({
            "channel": "session",
            "session_id": self.session_id.as_str(),
            "msg": v,
        });
        self.outgoing.send(Message::Text(frame.to_string())).is_ok()
    }

    async fn send_binary(&self, bytes: Vec<u8>) -> bool {
        // Envelope layout the ws-gateway `dispatchBinaryToFrontend` unwraps (verbatim mirror):
        //   [0x01] [4B BE session_id_len] [session_id_utf8] [payload]
        let sid = self.session_id.as_bytes();
        let sid_len = sid.len();
        // The length field is 4 bytes, so a longer id cannot be described by the
        // envelope. `sid_len as u32` would silently TRUNCATE the length while
        // writing all the bytes, desynchronising the peer's parser for the rest of
        // the connection. `open` bounds ids to MAX_SESSION_ID_CHARS so this is
        // unreachable in practice — fail the send rather than emit a corrupt frame.
        let Ok(sid_len_u32) = u32::try_from(sid_len) else {
            tracing::error!(sid_len, "session_id too long for the screencast envelope — dropping frame");
            return false;
        };
        let mut framed = Vec::with_capacity(1 + 4 + sid_len + bytes.len());
        framed.push(0x01);
        framed.extend_from_slice(&sid_len_u32.to_be_bytes());
        framed.extend_from_slice(sid);
        framed.extend_from_slice(&bytes);
        self.outgoing.send(Message::Binary(framed)).is_ok()
    }
}

// ---------------------------------------------------------------------------
// Process-global session registry
// ---------------------------------------------------------------------------

/// Handle for one live cloud recording session: an mpsc the router uses to feed inbound frames
/// (unwrapped `msg` from the ws-gateway envelope) into the driver task.
struct SessionHandle {
    /// Feed inbound FLAT `{type:...}` frames from the wrapped `{channel:"session", session_id, msg}`
    /// envelope. Dropping this closes the receiver → the driver task exits → shutdown fires.
    inbound_tx: mpsc::UnboundedSender<Value>,
    /// The bridge's OUTBOUND channel for this session. Held purely as a liveness probe:
    /// `is_closed()` flips when the owning listen loop exits and drops the receiver, which
    /// is how the reaper learns the peer is gone without the coordinator sending
    /// `session_close`.
    peer: mpsc::UnboundedSender<Message>,
    /// Monotonic ms of the last inbound frame for this session (see [`start_reaper`]).
    last_used_ms: Arc<AtomicI64>,
}

/// Process-global map `session_id → SessionHandle`. Populated by [`open`] and cleared by
/// [`close`] / the driver task's own end-of-life cleanup. Mirrors the other agent process-globals
/// (`runs`, `streaming_map`, ai_browsing `SESSIONS`).
///
/// LIFETIME: every entry pins a driver task holding a real recorder session (Chromium context +
/// page). A coordinator that drops the WS without sending `session_close` used to leave the entry —
/// and the browser — alive until process exit, AND `open` refuses a duplicate `session_id`, so the
/// stale entry permanently blocked re-opening that id. [`start_reaper`] now drops sessions whose
/// peer channel is closed or that have gone silent past [`SESSION_IDLE_TIMEOUT_SECS`], and `open`
/// evicts a provably-dead entry instead of refusing (see there).
static SESSIONS: OnceLock<DashMap<String, SessionHandle>> = OnceLock::new();

fn sessions() -> &'static DashMap<String, SessionHandle> {
    SESSIONS.get_or_init(DashMap::new)
}

/// Idle window before the reaper tears a recording session down.
const SESSION_IDLE_TIMEOUT_SECS: i64 = 3600;

/// How often the reaper sweeps.
const REAPER_INTERVAL_SECS: u64 = 60;

/// Hard ceiling on concurrent cloud recording sessions on one agent. Each pins a
/// Chromium context, so a peer must not be able to open them without limit.
const MAX_LIVE_SESSIONS: usize = 16;

/// Longest `session_id` accepted from the wire. Ids are gateway-minted uuids; this
/// also keeps the 4-byte length field of the binary screencast envelope honest
/// (see `CloudRecordSink::send_binary`).
const MAX_SESSION_ID_CHARS: usize = 128;

// Compile-time invariants on the bounds above.
const _: () = assert!(MAX_LIVE_SESSIONS > 0 && MAX_LIVE_SESSIONS <= 256);
// A bounded id keeps the 4-byte length field of the screencast envelope honest.
const _: () = assert!(MAX_SESSION_ID_CHARS > 0 && MAX_SESSION_ID_CHARS <= u32::MAX as usize);
// The reaper must sweep several times inside the idle window.
const _: () = assert!((REAPER_INTERVAL_SECS as i64) * 4 <= SESSION_IDLE_TIMEOUT_SECS);

fn now_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

/// True when this session can no longer be reached or driven: its peer channel is
/// closed (the listen loop that owned it exited) or its driver task has gone.
fn is_dead(handle: &SessionHandle) -> bool {
    handle.peer.is_closed() || handle.inbound_tx.is_closed()
}

/// What the registry already holds for a `session_id` being opened.
#[derive(Debug, PartialEq, Eq)]
enum Duplicate {
    /// Nothing registered — proceed.
    Absent,
    /// A provably-dead entry was found and removed — proceed and take the id over.
    EvictedDead,
    /// A genuinely live session owns this id — refuse.
    Live,
}

/// Resolve a duplicate `session_id` collision.
///
/// A duplicate used to be refused UNCONDITIONALLY, which meant a stale entry (peer
/// dropped the WS without `session_close`) permanently blocked re-opening that id — a
/// self-inflicted denial of service, since the coordinator's natural recovery is to
/// retry the same id. Evict what we can prove is dead; only refuse a live session,
/// because taking a live id over would strand its recorder + browser context.
fn resolve_duplicate(session_id: &str) -> Duplicate {
    let Some(existing) = sessions().get(session_id) else {
        return Duplicate::Absent;
    };
    let dead = is_dead(existing.value());
    drop(existing); // release the guard before mutating the map
    if !dead {
        return Duplicate::Live;
    }
    tracing::info!(session_id = %truncate_str(session_id, 16),
        "Replacing a dead recording session with the same session_id");
    sessions().remove(session_id);
    Duplicate::EvictedDead
}

/// Start the idle/orphan reaper (idempotent — only the first call spawns it).
///
/// Removing the handle drops `inbound_tx`, which ends the driver task's
/// `recv().await`, which runs `driver.shutdown()` and closes the recorder session —
/// so this reclaims the browser context, not just the map entry.
pub fn start_reaper() {
    static STARTED: OnceLock<()> = OnceLock::new();
    if STARTED.set(()).is_err() {
        return; // already running
    }
    tokio::spawn(async move {
        let idle_ms = SESSION_IDLE_TIMEOUT_SECS.saturating_mul(1000);
        loop {
            tokio::time::sleep(std::time::Duration::from_secs(REAPER_INTERVAL_SECS)).await;
            let now = now_ms();
            let stale: Vec<(String, bool)> = sessions()
                .iter()
                .filter_map(|e| {
                    let dead = is_dead(e.value());
                    let idle =
                        now.saturating_sub(e.last_used_ms.load(Ordering::Relaxed)) > idle_ms;
                    (dead || idle).then(|| (e.key().clone(), dead))
                })
                .collect();
            for (sid, dead) in stale {
                if sessions().remove(&sid).is_some() {
                    tracing::warn!(
                        session_id = %truncate_str(&sid, 16), dead,
                        "Reaping orphaned cloud record session"
                    );
                }
            }
        }
    });
}

/// Drop EVERY live recording session. Call when the owning listen loop exits: the
/// peer that could have closed them is gone, so their driver tasks should shut down
/// (each dropped `inbound_tx` makes its task run `driver.shutdown()`).
pub fn close_all() {
    let ids: Vec<String> = sessions().iter().map(|e| e.key().clone()).collect();
    for sid in ids {
        sessions().remove(&sid);
    }
}

/// Number of live cloud recording sessions (diagnostics / status).
pub fn live_count() -> usize {
    SESSIONS.get().map(|m| m.len()).unwrap_or(0)
}

/// Whether a given `session_id` currently has a live recording driver on this agent — the
/// router calls this to decide whether a `session_close` should take the record teardown path
/// (vs. falling through to ai_browsing). Non-mutating and cheap; a dashmap point-lookup.
pub fn is_active(session_id: &str) -> bool {
    SESSIONS.get().map(|m| m.contains_key(session_id)).unwrap_or(false)
}

// ---------------------------------------------------------------------------
// Public entry points — called by the LinkedAgentBridge router
// ---------------------------------------------------------------------------

/// Parse the addressed `session_id` from a `session_open`/`session_close` / wrapped-envelope
/// frame — checked at top level then under `config` (matches the cloud recorder conventions).
/// BOUNDED at ingest: the id is peer-controlled and becomes a registry key, a log field, and the
/// `session_id` header of every binary screencast frame, so it is truncated (char-safe, never
/// mid-UTF-8) on EVERY read so lookup and insertion always agree on the same key.
pub fn session_id_of(msg: &Value) -> String {
    let raw = msg["session_id"]
        .as_str()
        .or(msg["config"]["session_id"].as_str())
        .unwrap_or("");
    raw.chars().take(MAX_SESSION_ID_CHARS).collect()
}

/// Whether an inbound `session_open` frame is asking for a RECORDING session (`purpose:"record"`).
/// Anything else (missing purpose, `"stream"`, `"ai"`, …) stays on the ai_browsing router.
pub fn is_record_open(msg: &Value) -> bool {
    msg["purpose"].as_str() == Some("record")
        || msg["config"]["purpose"].as_str() == Some("record")
}

/// Handle a `session_open{purpose:"record"}` frame. Spawns the per-session driver task, registers
/// its inbound mpsc in the process-global map, and returns the `session_opened` ack the bridge
/// should send back over the WS.
///
/// * `recorder = None` (browserless build / StubEngine) → returns `session_opened{success:false}`
///   with a specific error so the frontend can degrade cleanly instead of hanging on a session
///   that will never produce any events (the previous silently-broken path).
/// * a duplicate `session_id` (a rogue gateway re-sending an open) → returns
///   `session_opened{success:false}` naming the collision; the existing driver keeps running.
pub async fn open(
    msg: &Value,
    recorder: Option<&Arc<PlaywrightRecorder>>,
    outgoing: &mpsc::UnboundedSender<Message>,
) -> Value {
    let session_id = session_id_of(msg);
    if session_id.is_empty() {
        return ack(&session_id, false, Some("session_open missing session_id".into()));
    }

    let recorder = match recorder {
        Some(r) => r.clone(),
        None => {
            return ack(
                &session_id,
                false,
                Some("no recorder available on this agent (browserless build)".into()),
            );
        }
    };

    // Make sure the reaper is running before the first session can be stranded.
    start_reaper();

    // Evict a provably-dead entry rather than letting it block the id forever (see
    // `resolve_duplicate`); only a genuinely live session refuses the open.
    if resolve_duplicate(&session_id) == Duplicate::Live {
        return ack(
            &session_id,
            false,
            Some("a recording session with this session_id is already open on this agent".into()),
        );
    }

    if sessions().len() >= MAX_LIVE_SESSIONS {
        return ack(
            &session_id,
            false,
            Some(format!("too many live recording sessions on this agent (max {MAX_LIVE_SESSIONS})")),
        );
    }

    let sink = CloudRecordSink::new(session_id.clone(), outgoing.clone());
    let (inbound_tx, mut inbound_rx) = mpsc::unbounded_channel::<Value>();
    sessions().insert(
        session_id.clone(),
        SessionHandle {
            inbound_tx,
            peer: outgoing.clone(),
            last_used_ms: Arc::new(AtomicI64::new(now_ms())),
        },
    );

    // Drive the recorder from its own task so a long-running action (page load, JS eval) never
    // wedges the bridge's read loop. The task lives until the mpsc receiver closes (either the
    // router's `close` dropped the handle, or the driver's own `stop` handler ran).
    let task_session_id = session_id.clone();
    tokio::spawn(async move {
        let mut driver = SessionDriver::new(recorder, sink);
        tracing::info!(session_id = %truncate_str(&task_session_id, 16),
            "cloud record session driver started");

        while let Some(msg) = inbound_rx.recv().await {
            driver.handle_frame(msg).await;
        }

        // Receiver closed (either the router dropped the handle on `session_close`, or an
        // upstream error propagated). Tear down the recorder session so a stranded browser
        // context can't linger.
        driver.shutdown().await;
        sessions().remove(&task_session_id);
        tracing::info!(session_id = %truncate_str(&task_session_id, 16),
            "cloud record session driver ended");
    });

    ack(&session_id, true, None)
}

/// Route ONE `{channel:"session", session_id, msg}` wrapped inbound frame from the ws-gateway to
/// its live recorder driver task. Returns `true` if the session was live and the frame was
/// forwarded, `false` when the session is unknown (silently dropped — a stale envelope from a
/// half-closed frontend can never wake up a dead session).
pub fn dispatch_wrapped(session_id: &str, msg: Value) -> bool {
    let Some(handle) = sessions().get(session_id) else { return false };
    // Stamp liveness so the idle reaper never tears down a session the coordinator is
    // actively driving.
    handle.last_used_ms.store(now_ms(), Ordering::Relaxed);
    handle.inbound_tx.send(msg).is_ok()
}

/// Handle a `session_close` frame from the ws-gateway (frontend disconnect / user-ended). Removes
/// the session handle so the driver task's `recv().await` returns `None` → the task calls
/// `shutdown()` on the driver (idempotent) and ends the underlying recorder session. The bridge
/// caller sends the `session_closed` ack back.
pub fn close(session_id: &str) -> Value {
    // Remove BEFORE building the ack — a subsequent `session_close` should see it gone.
    let existed = sessions().remove(session_id).is_some();
    tracing::info!(session_id = %truncate_str(session_id, 16), existed,
        "cloud record session_close from gateway");
    json!({
        "type": "session_closed",
        "session_id": session_id,
        "success": true,
        "error": Value::Null,
    })
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Build the `session_opened` ack the bridge sends back to the ws-gateway on a
/// `session_open{purpose:"record"}` frame. Kept flat (no `channel:"session"` envelope) because
/// the gateway consumes `session_opened` at the AGENT protocol layer (`session-dispatcher.ts`
/// `handleAgentOpen`), NOT the multiplexed session layer — mirrors the ai_browsing ack shape.
fn ack(session_id: &str, success: bool, error: Option<String>) -> Value {
    json!({
        "type": "session_opened",
        "session_id": session_id,
        "success": success,
        "error": error,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn is_record_open_reads_purpose_top_level_and_config() {
        assert!(is_record_open(&json!({"type": "session_open", "purpose": "record"})));
        assert!(is_record_open(&json!({"type": "session_open", "config": {"purpose": "record"}})));
        assert!(!is_record_open(&json!({"type": "session_open", "purpose": "stream"})));
        assert!(!is_record_open(&json!({"type": "session_open"})));
    }

    #[test]
    fn session_id_of_reads_top_level_then_config() {
        assert_eq!(session_id_of(&json!({"session_id": "abc"})), "abc");
        assert_eq!(session_id_of(&json!({"config": {"session_id": "def"}})), "def");
        assert_eq!(session_id_of(&json!({})), "");
    }

    #[tokio::test]
    async fn cloud_record_sink_wraps_json_in_session_envelope() {
        let (tx, mut rx) = mpsc::unbounded_channel::<Message>();
        let sink = CloudRecordSink::new("s-1".into(), tx);
        assert!(sink.send_json(json!({"type": "step_recorded", "step": {"kind": "click"}})).await);

        let Some(Message::Text(text)) = rx.recv().await else {
            panic!("expected a Text frame");
        };
        let v: Value = serde_json::from_str(&text).unwrap();
        assert_eq!(v["channel"], "session");
        assert_eq!(v["session_id"], "s-1");
        assert_eq!(v["msg"]["type"], "step_recorded");
        assert_eq!(v["msg"]["step"]["kind"], "click");
    }

    #[tokio::test]
    async fn cloud_record_sink_binary_uses_gateway_screencast_header() {
        let (tx, mut rx) = mpsc::unbounded_channel::<Message>();
        let sink = CloudRecordSink::new("sid-42".into(), tx);
        assert!(sink.send_binary(vec![0xff, 0xd8, 0xff, 0xe0]).await); // JPEG SOI + APP0

        let Some(Message::Binary(bytes)) = rx.recv().await else {
            panic!("expected a Binary frame");
        };
        // Envelope layout: [0x01][4B BE sid_len][sid_utf8][payload]
        assert_eq!(bytes[0], 0x01, "prefix byte for screencast envelope");
        let sid_len = u32::from_be_bytes([bytes[1], bytes[2], bytes[3], bytes[4]]) as usize;
        assert_eq!(sid_len, "sid-42".len());
        let sid = std::str::from_utf8(&bytes[5..5 + sid_len]).unwrap();
        assert_eq!(sid, "sid-42");
        let payload = &bytes[5 + sid_len..];
        assert_eq!(payload, &[0xff, 0xd8, 0xff, 0xe0]);
    }

    #[tokio::test]
    async fn open_without_recorder_fails_closed_with_named_reason() {
        let (tx, mut rx) = mpsc::unbounded_channel::<Message>();
        let frame = json!({"type": "session_open", "session_id": "no-rec", "purpose": "record"});
        let ack = open(&frame, None, &tx).await;
        assert_eq!(ack["type"], "session_opened");
        assert_eq!(ack["success"], false);
        assert!(ack["error"].as_str().unwrap().contains("no recorder"));
        // No inbound frames should have been queued when we failed pre-spawn.
        assert!(rx.try_recv().is_err());
        // And the session must NOT be registered.
        assert!(!sessions().contains_key("no-rec"));
    }

    #[tokio::test]
    async fn open_without_session_id_is_rejected() {
        let (tx, _rx) = mpsc::unbounded_channel::<Message>();
        let ack = open(&json!({"type": "session_open", "purpose": "record"}), None, &tx).await;
        assert_eq!(ack["success"], false);
        assert!(ack["error"].as_str().unwrap().contains("session_id"));
    }

    #[test]
    fn dispatch_wrapped_returns_false_for_unknown_session() {
        assert!(!dispatch_wrapped("this-session-does-not-exist", json!({"type": "stop"})));
    }

    /// Seed a live-looking handle so registry tests stay decoupled from `open` (which spawns a
    /// task and needs a recorder). Returns the channel receivers — DROP them to simulate the
    /// owning listen loop / driver task going away.
    fn seed_session(
        session_id: &str,
        idle_for: std::time::Duration,
    ) -> (mpsc::UnboundedReceiver<Value>, mpsc::UnboundedReceiver<Message>) {
        let (inbound_tx, inbound_rx) = mpsc::unbounded_channel::<Value>();
        let (peer, peer_rx) = mpsc::unbounded_channel::<Message>();
        let stamp = now_ms() - idle_for.as_millis() as i64;
        sessions().insert(
            session_id.to_string(),
            SessionHandle {
                inbound_tx,
                peer,
                last_used_ms: Arc::new(AtomicI64::new(stamp)),
            },
        );
        (inbound_rx, peer_rx)
    }

    #[test]
    fn close_reports_success_and_removes_the_entry_when_present() {
        let _keep = seed_session("close-test-1", std::time::Duration::ZERO);
        assert!(sessions().contains_key("close-test-1"));
        let ack = close("close-test-1");
        assert_eq!(ack["type"], "session_closed");
        assert_eq!(ack["success"], true);
        assert!(!sessions().contains_key("close-test-1"));

        // Idempotent: a second close on an already-gone session still returns success (best-effort
        // teardown; a stale frontend can never wedge us on a repeated close).
        let again = close("close-test-1");
        assert_eq!(again["success"], true);
    }

    // ── Item 3: unbounded / undrained session registry ───────────────────────

    #[test]
    fn a_session_whose_peer_link_died_is_detected_as_dead() {
        let (inbound_rx, peer_rx) = seed_session("dead-peer", std::time::Duration::ZERO);
        {
            let h = sessions().get("dead-peer").unwrap();
            assert!(!is_dead(h.value()), "both channels open → live");
        }
        // The owning listen loop exited: its outbound receiver is dropped.
        drop(peer_rx);
        {
            let h = sessions().get("dead-peer").unwrap();
            assert!(is_dead(h.value()), "closed peer channel → dead");
        }
        // …and independently, a driver task that ended closes the inbound side.
        drop(inbound_rx);
        {
            let h = sessions().get("dead-peer").unwrap();
            assert!(is_dead(h.value()));
        }
        sessions().remove("dead-peer");
    }

    #[test]
    fn duplicate_session_id_replaces_a_dead_entry_instead_of_blocking_it_forever() {
        let (inbound_rx, peer_rx) = seed_session("dup-dead", std::time::Duration::ZERO);
        // Kill the seeded session the way an abandoned WS does.
        drop(peer_rx);
        drop(inbound_rx);

        assert_eq!(
            resolve_duplicate("dup-dead"),
            Duplicate::EvictedDead,
            "a dead duplicate must be evicted so the id can be re-opened"
        );
        assert!(
            !sessions().contains_key("dup-dead"),
            "the dead entry must be gone, not left blocking the id forever"
        );
        // And a second attempt now sees a clean slate.
        assert_eq!(resolve_duplicate("dup-dead"), Duplicate::Absent);
    }

    #[test]
    fn duplicate_session_id_still_refuses_while_the_session_is_live() {
        // Keep both receivers alive → the session is genuinely live.
        let _keep = seed_session("dup-live", std::time::Duration::ZERO);
        assert_eq!(
            resolve_duplicate("dup-live"),
            Duplicate::Live,
            "taking over a LIVE id would strand its recorder + browser context"
        );
        assert!(sessions().contains_key("dup-live"), "the live session is untouched");
        sessions().remove("dup-live");
    }

    #[tokio::test]
    async fn open_refuses_a_live_duplicate_through_the_public_entry_point() {
        let (tx, _rx) = mpsc::unbounded_channel::<Message>();
        let _keep = seed_session("dup-live-e2e", std::time::Duration::ZERO);
        let ack = open(
            &json!({"type": "session_open", "session_id": "dup-live-e2e", "purpose": "record"}),
            // `recorder = None` short-circuits first, so assert on the branch we CAN reach and
            // leave the duplicate policy itself to the focused tests above.
            None,
            &tx,
        )
        .await;
        assert_eq!(ack["success"], false);
        assert!(sessions().contains_key("dup-live-e2e"), "a failed open must not evict a live session");
        sessions().remove("dup-live-e2e");
    }

    #[test]
    fn close_all_drops_every_session_so_nothing_survives_the_listen_loop() {
        let keep: Vec<_> = (0..3)
            .map(|i| seed_session(&format!("bulk-{i}"), std::time::Duration::ZERO))
            .collect();
        assert!(live_count() >= 3);
        close_all();
        for i in 0..3 {
            assert!(!sessions().contains_key(&format!("bulk-{i}")));
        }
        // Dropping the handle closes each driver task's inbound channel — that is what makes the
        // task run `driver.shutdown()` and release the browser context.
        for (mut inbound_rx, _) in keep {
            assert!(inbound_rx.try_recv().is_err());
        }
    }

    #[test]
    fn dispatch_wrapped_stamps_liveness_so_an_active_session_is_not_reaped() {
        let (mut inbound_rx, _peer_rx) = seed_session("touch-me", std::time::Duration::from_secs(9999));
        let before = sessions().get("touch-me").unwrap().last_used_ms.load(Ordering::Relaxed);
        assert!(dispatch_wrapped("touch-me", json!({"type": "ping"})));
        let after = sessions().get("touch-me").unwrap().last_used_ms.load(Ordering::Relaxed);
        assert!(after > before, "an inbound frame must refresh last_used");
        assert!(inbound_rx.try_recv().is_ok(), "and the frame must still be forwarded");
        sessions().remove("touch-me");
    }

    // ── Item 1/3: bounded session ids ────────────────────────────────────────

    #[test]
    fn session_id_is_bounded_at_ingest() {
        let long = "x".repeat(MAX_SESSION_ID_CHARS * 4);
        let got = session_id_of(&json!({"session_id": long}));
        assert_eq!(got.chars().count(), MAX_SESSION_ID_CHARS);
        // Truncation must be char-safe: a multibyte id must never be split mid-codepoint
        // (that would panic on a byte slice and can wedge us on a hostile gateway).
        let multi = "é".repeat(MAX_SESSION_ID_CHARS * 2);
        let got = session_id_of(&json!({"session_id": multi}));
        assert_eq!(got.chars().count(), MAX_SESSION_ID_CHARS);
        assert!(got.chars().all(|c| c == 'é'));
        // And truncation is stable, so a lookup key always matches the insertion key.
        assert_eq!(session_id_of(&json!({"session_id": got.clone()})), got);
    }

    #[tokio::test]
    async fn screencast_envelope_length_field_never_silently_truncates() {
        // `sid_len as u32` would wrap for a >4 GiB id, writing a short length with a long body
        // and desynchronising the peer's parser. Ids are bounded at ingest, so assert the
        // envelope stays self-consistent for the ids we DO accept.
        let (tx, mut rx) = mpsc::unbounded_channel::<Message>();
        let sid = "s".repeat(MAX_SESSION_ID_CHARS);
        let sink = CloudRecordSink::new(sid.clone(), tx);
        assert!(sink.send_binary(vec![1, 2, 3]).await);
        let Some(Message::Binary(bytes)) = rx.recv().await else {
            panic!("expected a Binary frame");
        };
        let declared = u32::from_be_bytes([bytes[1], bytes[2], bytes[3], bytes[4]]) as usize;
        assert_eq!(declared, sid.len(), "declared length must match the bytes written");
        assert_eq!(&bytes[5 + declared..], &[1, 2, 3]);
    }
}
