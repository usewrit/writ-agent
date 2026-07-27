
use std::collections::VecDeque;

use tokio::sync::mpsc;

/// Hard cap on a remote-supplied `session_id`. The relay embeds the id in EVERY outbound binary
/// frame (`[0x01][4B sid_len][sid][payload]`) and sizes that per-frame `Vec` from its length, so an
/// unbounded id would be re-allocated (and re-sent) on every screencast frame — a cheap amplification
/// knob for whoever controls the id. 128 bytes is far above every id the product mints (a uuid, a
/// `sess-<uuid>` or a numeric task id).
const MAX_SESSION_ID_BYTES: usize = 128;

/// Inbound (frontend → session loop) queue depth. These are CONTROL frames (clicks, keystrokes,
/// commands), so the policy on overflow is "drop + log loudly", NOT grow: the queue only fills when
/// the session loop is wedged, and a wedged loop will not become un-wedged by buffering another
/// 10 000 clicks — it would just convert a stuck session into an OOM. 512 is ~30s of very fast
/// human input, so a healthy session never sees the cap.
const INCOMING_CAP: usize = 512;

/// Depth of the un-read ("pushback") stack. A coalescing drain pushes back at most one message per
/// pass, so >1 only happens if a future caller nests drains; the cap keeps that from becoming an
/// unbounded second queue.
const PUSHBACK_CAP: usize = 16;

/// Virtual WebSocket adapter for in-process recording sessions.
/// Quacks like a FastAPI WebSocket — the recorder can't tell the difference.
/// Routes messages through the SaaS bridge's single persistent WS connection.
pub struct AgentSessionRelay {
    pub session_id: String,
    /// Sender half — bridge calls `dispatch_incoming()` to push messages here. BOUNDED (see
    /// [`INCOMING_CAP`]): a peer that floods commands at a stalled session loop must not be able to
    /// grow this without limit.
    incoming_tx: mpsc::Sender<serde_json::Value>,
    /// Receiver half — session loop calls `receive_json()` to read
    incoming_rx: tokio::sync::Mutex<mpsc::Receiver<serde_json::Value>>,
    /// Un-read ("pushback") stack. A coalescing drain (see `try_receive_json`)
    /// that pulls a message it must NOT consume (e.g. a non-scroll while merging
    /// a scroll backlog) returns it here so the next `receive_json()` yields it
    /// first — preserving message order. LIFO (`push_front`/`pop_front`), like an
    /// `ungetc` stack: the most recently un-read message is re-read first.
    /// Bounded — see [`PUSHBACK_CAP`]; it used to be a single slot that silently
    /// OVERWROTE (i.e. dropped) an already-pushed-back message.
    pushback: std::sync::Mutex<VecDeque<serde_json::Value>>,
    /// Sender to the bridge's outgoing WS (JSON messages)
    bridge_tx: mpsc::UnboundedSender<BridgeOutgoing>,
    closed: std::sync::atomic::AtomicBool,
}

/// Messages the relay sends to the bridge for WS transmission.
///
/// Canonically defined in the always-compiled `crate::streaming` module (so the cloud-free `fleet`
/// build's streaming keepalive loops can use it) and re-exported here for the cloud callers that
/// reference `session_relay::BridgeOutgoing`.
pub use crate::streaming::BridgeOutgoing;

impl AgentSessionRelay {
    pub fn new(
        session_id: String,
        bridge_tx: mpsc::UnboundedSender<BridgeOutgoing>,
    ) -> Self {
        // Bound the remote-controlled id at INGEST (char-safe truncation — slicing bytes could split
        // a multibyte codepoint and panic). Truncating rather than rejecting keeps the session
        // usable; an id this long is a bug or an attack, and both are worth a loud log line.
        let session_id = if session_id.len() > MAX_SESSION_ID_BYTES {
            let truncated: String = session_id
                .chars()
                .scan(0usize, |acc, c| {
                    *acc += c.len_utf8();
                    if *acc <= MAX_SESSION_ID_BYTES { Some(c) } else { None }
                })
                .collect();
            tracing::warn!(
                len = session_id.len(),
                max = MAX_SESSION_ID_BYTES,
                "session_id exceeds the relay cap — truncating (every outbound binary frame carries it)"
            );
            truncated
        } else {
            session_id
        };
        let (incoming_tx, incoming_rx) = mpsc::channel(INCOMING_CAP);
        Self {
            session_id,
            incoming_tx,
            incoming_rx: tokio::sync::Mutex::new(incoming_rx),
            pushback: std::sync::Mutex::new(VecDeque::new()),
            bridge_tx,
            closed: std::sync::atomic::AtomicBool::new(false),
        }
    }

    /// Send a JSON message to the frontend via the bridge.
    /// Wraps in session envelope: { channel: "session", session_id, msg }
    pub async fn send_json(&self, data: serde_json::Value) {
        if self.is_closed() {
            return;
        }
        let envelope = serde_json::json!({
            "channel": "session",
            "session_id": self.session_id,
            "msg": data,
        });
        let _ = self.bridge_tx.send(BridgeOutgoing::Json(envelope));
    }

    /// Send a JSON message to the bridge WS WITHOUT the session envelope —
    /// i.e. a TOP-LEVEL frame. Backend-orchestrated AI sessions correlate their
    /// agent_action replies on a top-level `request_id`; the relay-wrapped
    /// {channel:"session", msg} form would never reach the backend's dispatch
    /// (it switches on the top-level `type`). Use this for backend-driven replies.
    pub async fn send_json_toplevel(&self, data: serde_json::Value) {
        if self.is_closed() {
            return;
        }
        let _ = self.bridge_tx.send(BridgeOutgoing::Json(data));
    }

    /// Send binary data (screenshots) to the frontend via the bridge.
    /// Prepends session envelope: [0x01][4B sid_len BE][session_id][payload]
    pub async fn send_bytes(&self, data: &[u8]) {
        if self.is_closed() {
            return;
        }
        let sid_bytes = self.session_id.as_bytes();
        // The wire field is 4 bytes BE. `as u32` would SILENTLY WRAP a >4 GiB id into a small
        // length and desynchronize the peer's framing; `try_from` cannot (and the ingest cap above
        // makes it unreachable — belt and braces, since the framing is security-relevant).
        let Ok(sid_len) = u32::try_from(sid_bytes.len()) else {
            tracing::error!(len = sid_bytes.len(), "session_id too long to frame — dropping binary frame");
            return;
        };
        let mut envelope = Vec::with_capacity(1 + 4 + sid_bytes.len() + data.len());
        envelope.push(0x01);
        envelope.extend_from_slice(&sid_len.to_be_bytes());
        envelope.extend_from_slice(sid_bytes);
        envelope.extend_from_slice(data);
        let _ = self.bridge_tx.send(BridgeOutgoing::Binary(envelope));
    }

    /// Receive a message from the frontend (dispatched by the bridge).
    ///
    /// Yields `None` once the relay is closed AND its queue is drained — the session loop treats
    /// that as end-of-stream. The explicit closed check matters because the wake sentinel `close()`
    /// pushes is best-effort on a bounded queue: if the queue happened to be full, a loop that only
    /// watched for the sentinel would park here until its multi-hour idle timeout.
    pub async fn receive_json(&self) -> Option<serde_json::Value> {
        // A pushed-back message (from a coalescing drain) takes priority so
        // ordering is preserved.
        if let Some(msg) = self.pop_pushback() {
            return Some(msg);
        }
        let mut rx = self.incoming_rx.lock().await;
        // Deliver anything already queued first (ordering: everything dispatched before the close
        // still gets processed), and only then honour the close.
        if let Ok(msg) = rx.try_recv() {
            return Some(msg);
        }
        if self.is_closed() {
            return None;
        }
        rx.recv().await
    }

    /// Non-blocking receive — returns an already-queued message or None without
    /// waiting. Used to coalesce a backlog of cheap-to-merge actions (e.g. a
    /// trackpad scroll burst) so the session loop doesn't process them one
    /// slow round-trip at a time and fall behind the user.
    pub fn try_receive_json(&self) -> Option<serde_json::Value> {
        if let Some(msg) = self.pop_pushback() {
            return Some(msg);
        }
        // The session loop is the only receiver, so try_lock succeeds in
        // practice; if it ever can't, we simply stop draining (correctness is
        // unaffected — the message stays queued for the next receive_json).
        if let Ok(mut rx) = self.incoming_rx.try_lock() {
            if let Ok(msg) = rx.try_recv() {
                return Some(msg);
            }
        }
        None
    }

    /// Return a message to the front of the queue. Used when a coalescing drain
    /// pulls a message it must not consume, to preserve ordering.
    pub fn push_back(&self, msg: serde_json::Value) {
        let mut q = self.lock_pushback();
        if q.len() >= PUSHBACK_CAP {
            // Never silently swallow: the old single-slot implementation dropped the previous
            // message with no trace, which is indistinguishable from a lost user action.
            let dropped = q.pop_back();
            tracing::error!(
                cap = PUSHBACK_CAP,
                dropped_type = dropped.as_ref().and_then(|m| m["type"].as_str()).unwrap_or("?"),
                "session pushback stack full — dropping the oldest un-read message"
            );
        }
        q.push_front(msg);
    }

    /// Called by the bridge when a session message arrives from the gateway.
    ///
    /// Non-blocking by contract (the bridge read loop calls it), so a full queue DROPS the frame
    /// with a loud log rather than growing without bound or blocking frame I/O — see
    /// [`INCOMING_CAP`].
    pub fn dispatch_incoming(&self, msg: serde_json::Value) {
        if let Err(e) = self.incoming_tx.try_send(msg) {
            match e {
                mpsc::error::TrySendError::Full(msg) => tracing::error!(
                    session_id = %self.session_id,
                    cap = INCOMING_CAP,
                    msg_type = msg["type"].as_str().unwrap_or("?"),
                    "session inbound queue FULL (session loop wedged?) — dropping command frame"
                ),
                mpsc::error::TrySendError::Closed(_) => tracing::debug!(
                    session_id = %self.session_id,
                    "session inbound queue closed — dropping command frame"
                ),
            }
        }
    }

    /// Signal that this session is done.
    pub fn close(&self) {
        self.closed.store(true, std::sync::atomic::Ordering::Relaxed);
        // Wake up receive_json() so the session loop can exit. Best-effort: if the queue is full the
        // loop has plenty of queued messages to wake on and `is_closed()` is already true.
        let _ = self.incoming_tx.try_send(serde_json::json!({"type": "__session_closed__"}));
    }

    pub fn is_closed(&self) -> bool {
        self.closed.load(std::sync::atomic::Ordering::Relaxed)
    }

    /// Lock the pushback stack, recovering from poisoning.
    ///
    /// A panic while the guard is held would otherwise poison the mutex FOREVER, and relays live in
    /// a long-lived process-wide map that survives reconnects — one panic would permanently break
    /// every later session's message ordering. The protected data is a plain message queue with no
    /// invariant a panic could break, so resuming with the inner value is safe.
    fn lock_pushback(&self) -> std::sync::MutexGuard<'_, VecDeque<serde_json::Value>> {
        self.pushback.lock().unwrap_or_else(|e| e.into_inner())
    }

    fn pop_pushback(&self) -> Option<serde_json::Value> {
        self.lock_pushback().pop_front()
    }
}

// ---------------------------------------------------------------------------
// Shared bridge plumbing
//
// This module is compiled by BOTH bridge builds (`cloud` and `fleet,local` — see `bridge/mod.rs`),
// while `saas_bridge`/`fleet_bridge` are each gated to exactly one of them. It is therefore the only
// home where the two bridges can SHARE transport plumbing instead of drifting apart with two
// near-identical copies (the drift between them is the root cause of several past outages).
// ---------------------------------------------------------------------------

/// What a WS read-idle expiry should do next.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProbeAction {
    /// Nothing has arrived for a while — send a client-initiated `Ping` and start the pong deadline.
    SendPing,
    /// A ping went unanswered past its deadline: the peer (or the path to it) is gone. Tear the
    /// session down and reconnect.
    PeerDead,
}

/// Client-initiated WS liveness probe bookkeeping.
///
/// WHY this exists: a silently-dropped TCP flow (NAT/conntrack reap, a load balancer that vanishes,
/// a peer that was SIGKILLed) leaves a WebSocket reader parked in `read.next()` for as long as the
/// OS takes to give up on the socket — on Linux, with default keepalives, ~15 minutes. During that
/// window the worker looks healthy to itself (its `connected` flag is still true, so `/healthz` is
/// green) while the coordinator has already reaped it and is dispatching elsewhere. An app-level
/// heartbeat does NOT close this hole: a heartbeat is a *write*, and writes into a black-holed flow
/// succeed into the socket buffer for a long time.
///
/// So the read loop must have its own deadline: if nothing at all arrives within `idle`, send a
/// `Ping` and require a `Pong` within `pong_grace`. Any inbound frame — data, ping or pong — proves
/// the path is alive and resets the state.
///
/// `now` is passed in rather than read from the clock so the state machine is unit-testable.
pub struct WsLiveness {
    idle: std::time::Duration,
    pong_grace: std::time::Duration,
    /// Deadline for the outstanding ping's pong; `None` when no probe is in flight.
    pong_deadline: Option<std::time::Instant>,
}

impl WsLiveness {
    pub fn new(idle: std::time::Duration, pong_grace: std::time::Duration) -> Self {
        Self { idle, pong_grace, pong_deadline: None }
    }

    /// How long to wait for the next frame before acting. While a probe is outstanding this is the
    /// remaining pong grace (which can be zero — the caller then acts immediately).
    pub fn timeout(&self, now: std::time::Instant) -> std::time::Duration {
        match self.pong_deadline {
            Some(deadline) => deadline.saturating_duration_since(now),
            None => self.idle,
        }
    }

    /// Any inbound frame proves liveness and clears an outstanding probe.
    pub fn on_frame(&mut self) {
        self.pong_deadline = None;
    }

    /// The read wait expired. Either we probe, or the probe we already sent went unanswered.
    pub fn on_idle(&mut self, now: std::time::Instant) -> ProbeAction {
        match self.pong_deadline {
            Some(_) => ProbeAction::PeerDead,
            None => {
                self.pong_deadline = Some(now + self.pong_grace);
                ProbeAction::SendPing
            }
        }
    }

    /// Whether a probe is currently outstanding (exposed for logging/tests).
    pub fn probe_outstanding(&self) -> bool {
        self.pong_deadline.is_some()
    }
}

/// Outcome of a [`shed_backlog`] pass.
pub enum ShedOutcome<T> {
    /// The backlog was brought back under the cap. The returned frames are the survivors, in their
    /// original relative order, and MUST be written before anything newer is pulled.
    Shed { keep: VecDeque<T>, dropped: usize },
    /// Even after dropping every droppable frame the backlog is over the hard cap: the peer is not
    /// reading at all. The caller should tear the connection down rather than keep buffering.
    Overflow { queued: usize },
}

/// Enforce a bound on an outgoing frame queue whose sender side is (necessarily) unbounded.
///
/// The senders are cloned into ~20 call sites across long-lived spawned tasks, relays and the
/// monitor loop, so the channel itself has to stay `UnboundedSender` — but "unbounded sender" must
/// not mean "unbounded memory". tungstenite's own `max_write_buffer_size` is a *second* buffer
/// behind this one, and its default is `usize::MAX`, so with a peer whose receive window is closed
/// BOTH grow until the process is OOM-killed.
///
/// Policy, and why:
///   * `is_droppable` frames (screencast / streaming video) are dropped OLDEST-FIRST. A stale
///     screencast frame is worthless — the next one supersedes it — so shedding is strictly better
///     than either blocking or dying.
///   * everything else (control frames: task results, acks, heartbeats) is KEPT. Dropping a
///     `task_result` is the failure mode that makes a coordinator redispatch work that already ran.
///   * if the control frames alone still exceed `hard_cap`, we do NOT grow: the peer has stopped
///     reading entirely, so the connection is already useless. Report `Overflow` so the caller
///     drops the session; reconnecting re-establishes a working writer and the coordinator's
///     retry/idempotency path covers the in-flight work.
///
/// The caller decides WHEN to shed (typically `rx.len() > soft cap`); one pass always drains the
/// whole current backlog.
pub fn shed_backlog<T>(
    rx: &mut mpsc::UnboundedReceiver<T>,
    is_droppable: impl Fn(&T) -> bool,
    hard_cap: usize,
) -> ShedOutcome<T> {
    let mut keep: VecDeque<T> = VecDeque::new();
    let mut dropped = 0usize;
    // Drain the whole current backlog once: droppable frames evaporate, control frames survive in
    // order. `try_recv` never blocks, so this is a bounded, synchronous pass.
    while let Ok(item) = rx.try_recv() {
        if is_droppable(&item) {
            dropped += 1;
        } else {
            keep.push_back(item);
        }
        if keep.len() > hard_cap {
            return ShedOutcome::Overflow { queued: keep.len() };
        }
    }
    ShedOutcome::Shed { keep, dropped }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{Duration, Instant};

    #[test]
    fn session_id_is_bounded_at_ingest() {
        let (tx, _rx) = mpsc::unbounded_channel();
        let relay = AgentSessionRelay::new("é".repeat(500), tx);
        assert!(relay.session_id.len() <= MAX_SESSION_ID_BYTES);
        // Truncation is char-safe: the id is still valid UTF-8 of whole codepoints.
        assert!(relay.session_id.chars().all(|c| c == 'é'));
    }

    #[test]
    fn pushback_is_a_bounded_lifo_stack() {
        let (tx, _rx) = mpsc::unbounded_channel();
        let relay = AgentSessionRelay::new("s1".to_string(), tx);
        relay.push_back(serde_json::json!({"n": 1}));
        relay.push_back(serde_json::json!({"n": 2}));
        // Most recently un-read comes back first (ungetc semantics).
        assert_eq!(relay.try_receive_json().unwrap()["n"], 2);
        assert_eq!(relay.try_receive_json().unwrap()["n"], 1);
        assert!(relay.try_receive_json().is_none());

        // Overflow keeps the newest PUSHBACK_CAP entries instead of silently overwriting one slot.
        for n in 0..(PUSHBACK_CAP + 5) {
            relay.push_back(serde_json::json!({"n": n}));
        }
        assert_eq!(relay.lock_pushback().len(), PUSHBACK_CAP);
    }

    /// `close()` must end the stream even when the bounded queue was full and swallowed the wake
    /// sentinel — otherwise the session loop parks until its idle timeout.
    #[tokio::test]
    async fn close_ends_the_stream_even_with_a_full_queue() {
        let (tx, _rx) = mpsc::unbounded_channel();
        let relay = AgentSessionRelay::new("s1".to_string(), tx);
        for n in 0..(INCOMING_CAP + 10) {
            relay.dispatch_incoming(serde_json::json!({"n": n}));
        }
        relay.close();
        // Everything that was queued is still delivered…
        let mut seen = 0;
        while let Some(_msg) = relay.receive_json().await {
            seen += 1;
            assert!(seen <= INCOMING_CAP + 1, "must terminate");
        }
        // …and then the stream ENDS (the loop above returned) rather than hanging.
        assert_eq!(seen, INCOMING_CAP);
    }

    #[tokio::test]
    async fn incoming_queue_is_bounded_and_drops_when_full() {
        let (tx, _rx) = mpsc::unbounded_channel();
        let relay = AgentSessionRelay::new("s1".to_string(), tx);
        // Nothing is draining, so exactly INCOMING_CAP frames are buffered and the rest are dropped
        // (not queued, not blocking the caller).
        for n in 0..(INCOMING_CAP + 50) {
            relay.dispatch_incoming(serde_json::json!({"n": n}));
        }
        let mut seen = 0;
        while relay.try_receive_json().is_some() {
            seen += 1;
        }
        assert_eq!(seen, INCOMING_CAP);
    }

    #[test]
    fn liveness_probes_then_declares_the_peer_dead() {
        let t0 = Instant::now();
        let mut live = WsLiveness::new(Duration::from_secs(60), Duration::from_secs(15));
        assert_eq!(live.timeout(t0), Duration::from_secs(60));

        // Idle expiry → probe, and the wait shrinks to the pong grace.
        assert_eq!(live.on_idle(t0), ProbeAction::SendPing);
        assert!(live.probe_outstanding());
        assert_eq!(live.timeout(t0), Duration::from_secs(15));
        assert_eq!(live.timeout(t0 + Duration::from_secs(10)), Duration::from_secs(5));
        // Past the deadline the remaining wait is zero (saturating, never a panic).
        assert_eq!(live.timeout(t0 + Duration::from_secs(99)), Duration::ZERO);

        // Grace expired with no frame → dead.
        assert_eq!(live.on_idle(t0 + Duration::from_secs(15)), ProbeAction::PeerDead);
    }

    #[test]
    fn liveness_is_reset_by_any_inbound_frame() {
        let t0 = Instant::now();
        let mut live = WsLiveness::new(Duration::from_secs(60), Duration::from_secs(15));
        assert_eq!(live.on_idle(t0), ProbeAction::SendPing);
        live.on_frame(); // a Pong (or any data frame) arrived
        assert!(!live.probe_outstanding());
        assert_eq!(live.timeout(t0), Duration::from_secs(60));
        // …so the NEXT idle expiry probes again rather than declaring death.
        assert_eq!(live.on_idle(t0 + Duration::from_secs(60)), ProbeAction::SendPing);
    }

    #[test]
    fn shed_drops_screencast_and_keeps_control_frames_in_order() {
        let (tx, mut rx) = mpsc::unbounded_channel::<(bool, u32)>();
        // Interleave 5 droppable "video" frames with 3 control frames.
        for n in 0..5u32 {
            tx.send((true, n)).unwrap();
            if n < 3 {
                tx.send((false, n)).unwrap();
            }
        }
        match shed_backlog(&mut rx, |(droppable, _)| *droppable, 100) {
            ShedOutcome::Shed { keep, dropped } => {
                assert_eq!(dropped, 5);
                assert_eq!(keep.iter().map(|(_, n)| *n).collect::<Vec<_>>(), vec![0, 1, 2]);
            }
            ShedOutcome::Overflow { .. } => panic!("should not overflow under the hard cap"),
        }
    }

    #[test]
    fn shed_reports_overflow_when_control_frames_alone_exceed_the_hard_cap() {
        let (tx, mut rx) = mpsc::unbounded_channel::<(bool, u32)>();
        for n in 0..20u32 {
            tx.send((false, n)).unwrap();
        }
        match shed_backlog(&mut rx, |(droppable, _)| *droppable, 5) {
            ShedOutcome::Overflow { queued } => assert!(queued > 5),
            ShedOutcome::Shed { .. } => panic!("control-frame flood must report Overflow"),
        }
    }
}
