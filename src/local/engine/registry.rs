//! `RunRegistry` (STAGE E2) — the in-process table of LIVE runs, keyed by `run_id`.
//!
//! Each in-flight run owns a [`RunHandle`] holding (a) a `tokio::broadcast` sender that fans
//! lifecycle [`RunEvent`]s out to any number of SSE subscribers, and (b) a watch-based
//! [`CancelToken`] the execute loop checks between steps so a `POST /v1/runs/:id/cancel` can
//! actually abort the run (not just acknowledge). When the run finalizes, the engine drops the
//! handle from the registry, so the table only ever holds genuinely-live runs.
//!
//! ## Why watch, not tokio-util
//! The crate does not depend on `tokio-util`, and the cancellation contract here is trivial
//! (one-shot, fan-out, await-able). A `tokio::sync::watch::<bool>` channel gives both a cheap
//! `is_cancelled()` poll and an await-able `cancelled()` future from the standard tokio surface —
//! no new dependency. The token is `Clone` (cloned senders/receivers share the same channel).
//!
//! ## Secret hygiene
//! The registry stores only ids, an atomic status code, the event channel, and the cancel token —
//! never credentials, inputs, or extracted values. Events themselves are structural (see
//! [`super::events`]). Nothing here is logged with a value payload.

use super::events::RunEvent;
use super::RunStatus;
use dashmap::DashMap;
use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::Arc;
use tokio::sync::{broadcast, watch};

/// How many lifecycle events the broadcast channel buffers per run before a slow subscriber starts
/// lagging. Runs are short and event-sparse (one Started, a handful of Step/Progress, one terminal),
/// so a small ring is plenty; a subscriber that falls behind sees `RecvError::Lagged` and the SSE
/// layer simply skips the gap rather than wedging the producer.
const EVENT_CHANNEL_CAPACITY: usize = 256;

/// A one-shot, fan-out, await-able cancellation signal backed by a `watch::<bool>` channel.
///
/// Cloning the token clones the underlying sender, so any clone can `cancel()` and every clone
/// observes it. The execute loop holds a clone and polls [`CancelToken::is_cancelled`] between
/// steps; a long await can race [`CancelToken::cancelled`] for prompt abort.
#[derive(Clone)]
pub struct CancelToken {
    tx: Arc<watch::Sender<bool>>,
}

impl CancelToken {
    fn new() -> Self {
        let (tx, _rx) = watch::channel(false);
        Self { tx: Arc::new(tx) }
    }

    /// Signal cancellation. Idempotent — a second call is a no-op. Returns whether THIS call flipped
    /// the flag (i.e. it was not already cancelled).
    pub fn cancel(&self) -> bool {
        // `send_replace` ALWAYS updates the watched value + wakes any receivers, even when there are
        // zero receivers right now (unlike `send`, which errors and DROPS the update without a
        // receiver). The execute loop polls `is_cancelled()` without holding a receiver, so the
        // value must persist regardless.
        let was = self.tx.send_replace(true);
        !was
    }

    /// Non-blocking check — true once `cancel()` has been called by anyone.
    pub fn is_cancelled(&self) -> bool {
        *self.tx.borrow()
    }

    /// Resolves the moment the token is cancelled (or immediately if it already is). Lets the
    /// execute loop `select!` a long step against a cancel request for prompt abort.
    pub async fn cancelled(&self) {
        if self.is_cancelled() {
            return;
        }
        let mut rx = self.tx.subscribe();
        // Wait until the watched value becomes true. `changed()` errors only if the sender dropped;
        // the sender is `Arc`-held by the token, so while we hold `&self` it cannot drop.
        loop {
            if *rx.borrow() {
                return;
            }
            if rx.changed().await.is_err() {
                return;
            }
        }
    }
}

/// A handle to one live run: its event fan-out + cancel token + a snapshot status.
pub struct RunHandle {
    /// Broadcast source for lifecycle events. Subscribers call [`RunHandle::subscribe`].
    events: broadcast::Sender<RunEvent>,
    /// The run's cancellation token (cloned into the execute loop).
    cancel: CancelToken,
    /// Latest known status as a packed code (see [`status_to_code`]). Atomic so a reader (the API
    /// `cancel`/SSE handlers) can sample it without locking the producer.
    status: Arc<AtomicU8>,
}

impl RunHandle {
    /// Subscribe to this run's lifecycle events. Each subscriber gets an independent receiver; events
    /// emitted before subscription are not replayed (the SSE handler sends a synthetic snapshot).
    pub fn subscribe(&self) -> broadcast::Receiver<RunEvent> {
        self.events.subscribe()
    }

    /// Clone of the run's cancel token (for the execute loop or a cancel request).
    pub fn cancel_token(&self) -> CancelToken {
        self.cancel.clone()
    }

    /// Signal cancellation. Returns whether this call flipped the flag (false if already cancelled).
    pub fn request_cancel(&self) -> bool {
        self.cancel.cancel()
    }

    /// Current best-known status snapshot.
    pub fn status(&self) -> RunStatus {
        code_to_status(self.status.load(Ordering::SeqCst))
    }
}

/// How many lifecycle events the GLOBAL (all-runs) broadcast buffers before a lagging subscriber
/// starts dropping. Larger than the per-run ring because it carries every live run's frames.
const GLOBAL_EVENT_CHANNEL_CAPACITY: usize = 256;

/// The live-run table. Cheap to clone (it's all behind a `DashMap` + `Arc`s); the engine holds one
/// `Arc<RunRegistry>` and hands the SAME `Arc` to the API layer (via `LocalEngine::registry`).
///
/// In addition to the per-run fan-out, it owns ONE `global` broadcast that every run's [`EmitGuard::
/// emit`] also feeds — so a single subscriber (`GET /v1/runs/events`) sees the lifecycle of EVERY
/// run without polling. The desktop shell subscribes to it and re-emits a Tauri `run:event`, which
/// is what makes the app's Live activity fully push-driven.
pub struct RunRegistry {
    runs: DashMap<i64, RunHandleInner>,
    global: broadcast::Sender<RunEvent>,
}

impl Default for RunRegistry {
    fn default() -> Self {
        let (global, _rx) = broadcast::channel(GLOBAL_EVENT_CHANNEL_CAPACITY);
        Self { runs: DashMap::new(), global }
    }
}

/// Internal storage for a run's live state. The public `RunHandle` is a borrowed VIEW built on
/// demand (so we never hand out a clone that outlives the registry entry).
struct RunHandleInner {
    events: broadcast::Sender<RunEvent>,
    cancel: CancelToken,
    status: Arc<AtomicU8>,
}

impl RunRegistry {
    /// Build an empty registry.
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a freshly-started run. Returns an [`EmitGuard`] the engine uses to publish events +
    /// read its cancel token; the entry is removed when the guard is `finish`ed (or dropped). A
    /// second registration of the same id replaces the first (should not happen — ids are unique).
    pub fn register(self: &Arc<Self>, run_id: i64) -> EmitGuard {
        let (tx, _rx) = broadcast::channel(EVENT_CHANNEL_CAPACITY);
        let cancel = CancelToken::new();
        let status = Arc::new(AtomicU8::new(status_to_code(RunStatus::Running)));
        self.runs.insert(
            run_id,
            RunHandleInner {
                events: tx.clone(),
                cancel: cancel.clone(),
                status: status.clone(),
            },
        );
        EmitGuard {
            registry: Arc::clone(self),
            run_id,
            events: tx,
            global: self.global.clone(),
            cancel,
            status,
            finished: false,
        }
    }

    /// Subscribe to the GLOBAL run-events stream — every live run's lifecycle frames on one
    /// receiver. Backs `GET /v1/runs/events`; events emitted before subscription are not replayed.
    pub fn subscribe_global(&self) -> broadcast::Receiver<RunEvent> {
        self.global.subscribe()
    }

    /// Inject an event directly onto the GLOBAL stream without a per-run channel — used by the cloud
    /// run-events forwarder to push [`RunEvent::CloudReflected`] nudges (a linked account's cloud-side
    /// run changed). Best-effort: a send with no subscribers is a no-op.
    pub fn emit_global(&self, event: RunEvent) {
        let _ = self.global.send(event);
    }

    /// Look up a live run's handle (a snapshot view). `None` once the run has finalized + been
    /// removed.
    pub fn get(&self, run_id: i64) -> Option<RunHandle> {
        self.runs.get(&run_id).map(|e| RunHandle {
            events: e.events.clone(),
            cancel: e.cancel.clone(),
            status: e.status.clone(),
        })
    }

    /// Request cancellation of a live run. Returns:
    ///   - `Some(true)`  — the run was live and THIS call flipped it to cancelling,
    ///   - `Some(false)` — the run was live but already cancelling,
    ///   - `None`        — no live run with this id (already finished / never existed).
    pub fn cancel(&self, run_id: i64) -> Option<bool> {
        self.runs.get(&run_id).map(|e| e.cancel.cancel())
    }

    /// Number of currently-registered live runs.
    pub fn live_count(&self) -> usize {
        self.runs.len()
    }

    /// True if a live run with this id is registered.
    pub fn is_live(&self, run_id: i64) -> bool {
        self.runs.contains_key(&run_id)
    }

    fn remove(&self, run_id: i64) {
        self.runs.remove(&run_id);
    }
}

/// The engine's emit side for one run. Publishes [`RunEvent`]s to subscribers, exposes the cancel
/// token to the execute loop, and — critically — removes the registry entry when the run ends
/// (`finish` or `Drop`), so a panicking/aborted run can never leak a live entry.
pub struct EmitGuard {
    registry: Arc<RunRegistry>,
    run_id: i64,
    events: broadcast::Sender<RunEvent>,
    /// The registry's GLOBAL fan-out — every emit is mirrored here so the all-runs
    /// stream (`/v1/runs/events`) sees this run's lifecycle.
    global: broadcast::Sender<RunEvent>,
    cancel: CancelToken,
    status: Arc<AtomicU8>,
    finished: bool,
}

impl EmitGuard {
    /// The run id this guard governs.
    pub fn run_id(&self) -> i64 {
        self.run_id
    }

    /// Clone of the cancel token for the execute loop to poll between steps.
    pub fn cancel_token(&self) -> CancelToken {
        self.cancel.clone()
    }

    /// A detached, `Send + 'static` emitter onto the SAME broadcast channel as this guard. The
    /// execute loop runs in a spawned task that does not own the `EmitGuard` (the guard stays on the
    /// parent to write the terminal frame + de-register); this hands it the publish side only.
    pub fn step_emitter(&self) -> StepEmitter {
        StepEmitter { events: self.events.clone() }
    }

    /// Publish a lifecycle event to all subscribers — BOTH this run's per-run channel and the
    /// registry's global all-runs channel. A send with zero subscribers is a no-op (the `Err` is
    /// intentionally ignored — events are best-effort observability, never load-bearing).
    pub fn emit(&self, event: RunEvent) {
        let _ = self.global.send(event.clone());
        let _ = self.events.send(event);
    }

    /// Update the cached status snapshot (read by the API `cancel`/SSE handlers).
    pub fn set_status(&self, status: RunStatus) {
        self.status.store(status_to_code(status), Ordering::SeqCst);
    }

    /// Emit the terminal [`RunEvent::Finished`], update the snapshot, and de-register the run. After
    /// this the registry no longer reports the run as live and SSE streams close.
    pub fn finish(mut self, status: RunStatus) {
        self.set_status(status);
        self.emit(RunEvent::Finished { run_id: self.run_id, status });
        self.registry.remove(self.run_id);
        self.finished = true;
    }

    /// Emit a terminal [`RunEvent::Error`] (orchestration failure / panic) and de-register. The
    /// snapshot is set to `Failed`.
    pub fn finish_error(mut self, message: String) {
        self.set_status(RunStatus::Failed);
        self.emit(RunEvent::Error { run_id: self.run_id, message });
        self.registry.remove(self.run_id);
        self.finished = true;
    }
}

/// The publish-only side of a run's event channel, handed to the spawned execute task. `Clone` +
/// `Send + 'static` so it can cross the `tokio::spawn` boundary without the `EmitGuard`.
#[derive(Clone)]
pub struct StepEmitter {
    events: broadcast::Sender<RunEvent>,
}

impl StepEmitter {
    /// Publish a lifecycle event (best-effort; a send with no subscribers is a no-op).
    pub fn emit(&self, event: RunEvent) {
        let _ = self.events.send(event);
    }
}

impl Drop for EmitGuard {
    fn drop(&mut self) {
        // Defense-in-depth: if the run body panicked or returned without an explicit `finish`/
        // `finish_error`, still emit a terminal Error + de-register so subscribers don't hang and
        // the live table doesn't leak. (The normal paths consume the guard before Drop runs.)
        if !self.finished {
            let ev = RunEvent::Error {
                run_id: self.run_id,
                message: "run ended without a terminal result".into(),
            };
            let _ = self.global.send(ev.clone());
            let _ = self.events.send(ev);
            self.registry.remove(self.run_id);
        }
    }
}

/// Pack a [`RunStatus`] into a `u8` for the atomic snapshot.
fn status_to_code(s: RunStatus) -> u8 {
    match s {
        RunStatus::Running => 0,
        RunStatus::Success => 1,
        RunStatus::Failed => 2,
        RunStatus::Cancelled => 3,
        RunStatus::Timeout => 4,
        RunStatus::CaptchaRequired => 5,
        RunStatus::TwofaRequired => 6,
    }
}

/// Inverse of [`status_to_code`]. An unknown code falls back to `Running` (defensive only).
fn code_to_status(code: u8) -> RunStatus {
    match code {
        1 => RunStatus::Success,
        2 => RunStatus::Failed,
        3 => RunStatus::Cancelled,
        4 => RunStatus::Timeout,
        5 => RunStatus::CaptchaRequired,
        6 => RunStatus::TwofaRequired,
        _ => RunStatus::Running,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::local::engine::events::StepStatus;

    #[tokio::test]
    async fn register_emit_subscribe_finish() {
        let reg = Arc::new(RunRegistry::new());
        let guard = reg.register(42);
        assert!(reg.is_live(42));
        assert_eq!(reg.live_count(), 1);

        let mut rx = reg.get(42).unwrap().subscribe();
        guard.emit(RunEvent::Started { run_id: 42, total_steps: 2 });
        guard.emit(RunEvent::Step {
            run_id: 42,
            index: 0,
            step_type: "wait".into(),
            status: StepStatus::Running,
        });

        let e1 = rx.recv().await.unwrap();
        assert!(matches!(e1, RunEvent::Started { total_steps: 2, .. }));
        let e2 = rx.recv().await.unwrap();
        assert_eq!(e2.name(), "step");

        guard.finish(RunStatus::Success);
        // The terminal event is delivered…
        let term = rx.recv().await.unwrap();
        assert!(matches!(term, RunEvent::Finished { status: RunStatus::Success, .. }));
        // …and the run is de-registered.
        assert!(!reg.is_live(42));
        assert_eq!(reg.live_count(), 0);
    }

    #[tokio::test]
    async fn cancel_flips_token_and_reports_state() {
        let reg = Arc::new(RunRegistry::new());
        let guard = reg.register(7);
        let token = guard.cancel_token();
        assert!(!token.is_cancelled());

        // First cancel flips; second is a no-op.
        assert_eq!(reg.cancel(7), Some(true));
        assert!(token.is_cancelled());
        assert_eq!(reg.cancel(7), Some(false));

        // The await-able future resolves promptly since it's already cancelled.
        token.cancelled().await;

        // Cancelling an unknown run reports None.
        assert_eq!(reg.cancel(9999), None);
        drop(guard);
    }

    #[tokio::test]
    async fn cancelled_future_resolves_on_late_cancel() {
        let reg = Arc::new(RunRegistry::new());
        let guard = reg.register(3);
        let token = guard.cancel_token();
        let waiter = tokio::spawn(async move { token.cancelled().await });
        // Give the waiter a beat to park, then cancel.
        tokio::task::yield_now().await;
        assert_eq!(reg.cancel(3), Some(true));
        waiter.await.unwrap();
        drop(guard);
    }

    #[tokio::test]
    async fn drop_without_finish_emits_error_and_deregisters() {
        let reg = Arc::new(RunRegistry::new());
        let mut rx = {
            let guard = reg.register(11);
            let rx = reg.get(11).unwrap().subscribe();
            // guard dropped here WITHOUT finish → Drop fires the defensive Error.
            drop(guard);
            rx
        };
        let e = rx.recv().await.unwrap();
        assert!(matches!(e, RunEvent::Error { .. }));
        assert!(!reg.is_live(11));
    }
}
