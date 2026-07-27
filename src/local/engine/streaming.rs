//! Local streaming sessions — the in-process engine behind the OpenAI-compat `stream:true` path.
//!
//! A recorded STREAMING workflow (one whose `streaming_config` carries an `advanced_script` +
//! handlers, e.g. a chat site driven via `ps.on("message", …)`) is long-lived: a warm browser tab
//! stays open and each chat turn `ps._dispatch`es an action into the page, which streams tokens
//! back via the privileged runtime bridge (`window.ps.stream(...)` → [`BridgeEvent::Stream`]) and
//! finishes with one `ps.respond(...)` → [`BridgeEvent::Respond`]. This module finds-or-lazily-starts
//! one such session per workflow and turns a single turn into a [`tokio::sync::mpsc`] stream of
//! [`StreamEvent`]s the OpenAI SSE handler proxies into `chat.completion.chunk` objects.
//!
//! ## Why this lives next to `RealEngine` (not in the cloud bridge)
//! The cloud streaming path (`bridge::saas_bridge`) is welded to the ws-gateway relay transport: it
//! sends `stream_chunk` / `command_response` WS frames. Here there is no gateway and no tenant — the
//! daemon drives its OWN warm Chromium directly and proxies bridge events straight to the local HTTP
//! caller. We reuse the genuine common core — the streaming [`StreamingSessionManager`] + the
//! [`runtime_bridge`] expose-function plumbing — but own a tiny single-user orchestration around it.
//!
//! ## Concurrency model
//! Each workflow's session lives behind a [`tokio::sync::Mutex`] so turns on the SAME session
//! serialize (a single tab cannot drive two turns at once). Distinct workflows get distinct sessions
//! and run concurrently. A per-session router task fans every [`BridgeEvent`] to the right in-flight
//! turn by `request_id`; a turn with no registered channel (a late/async emit) is dropped.
//!
//! ## Secret hygiene
//! Stream chunks carry model OUTPUT (assistant tokens) — never credentials. We never log chunk
//! bodies; only structural lifecycle (turn started/ended, chunk counts) at debug.

use std::collections::HashMap;
use std::sync::atomic::{AtomicI64, AtomicU64, Ordering};
use std::sync::{Arc, OnceLock, Weak};

use dashmap::DashMap;
use sqlx::SqlitePool;
use tokio::sync::{mpsc, Mutex};

use crate::browser::manager::BrowserManager;
use crate::local::error::{LocalError, LocalResult};
use crate::local::store::workflows::Workflow;
use crate::local::vault::Vault;
use crate::streaming::manager::StreamingSessionManager;
use crate::streaming::runtime_bridge::{self, BridgeEvent};

use super::persona;
use super::LocalEngine;

/// One streamed event of a single chat turn, proxied from the page's runtime bridge.
///
/// A turn emits zero or more [`StreamEvent::Chunk`] (incremental assistant text) and exactly one
/// terminal [`StreamEvent::Done`] (the final `ps.respond` payload) OR one [`StreamEvent::Error`]
/// (dispatch failure / timeout). Consumers MUST treat `Done`/`Error` as stream-closing.
#[derive(Debug, Clone)]
pub enum StreamEvent {
    /// An incremental token/delta. `content` is the text already extracted from the bridge chunk
    /// (the runtime emits `{content: "..."}` or a bare string).
    Chunk { content: String },
    /// Terminal: the handler called `ps.respond(request_id, data)`. `data` is the raw final payload;
    /// the SSE layer pulls the configured `response_field` (default `content`) out of it.
    Done { data: serde_json::Value },
    /// Terminal: the turn failed before/around dispatch (no handler, page eval error, or timeout).
    Error { message: String },
}

/// How long a single streamed turn may run before we give up waiting for `ps.respond`. Mirrors the
/// cloud per-turn watchdog (`WRIT_STREAMING_TURN_TIMEOUT_SECS`, default 120s) but generous for a
/// long model answer; a stream chunk does NOT currently extend it (the local caller can disconnect).
const TURN_TIMEOUT_SECS: u64 = 660;

/// Live in-memory mirror of the cloud `StreamingSession` row (see
/// `backend/models/streaming_session.py`) for the ONE long-lived session a streaming workflow holds
/// locally. Shared (`Arc`) between the [`Session`] and its bridge-router task so both update the live
/// counters as the page streams. Single-user daemon: there is no gateway/agent, so `agent_id` is
/// always absent and the only statuses the record can be in are `running` (in the map) or `ended`
/// (built at stop time, then removed). Counters mirror the Python semantics exactly:
/// `commands_received` = handler invocations (one per turn), `events_emitted` = autonomous
/// `ps.emit(...)` events the script fires on its own.
struct SessionMeta {
    /// Unique key for this session instance (UUID). A new key is minted each time a workflow's
    /// session is (re)started — parity with the cloud `session_key`.
    session_key: String,
    /// The page the chat lives on (the workflow's entry url) — the cloud `target_url`.
    target_url: String,
    /// Auto-end ceiling in seconds (cloud default 3600). Mirrors the manager's hard-timeout config.
    max_duration_seconds: i64,
    /// When setup completed and the session went `running` (RFC3339).
    started_at: String,
    /// Autonomous events the script emitted (`ps.emit`) — bumped by the bridge-router task.
    events_emitted: AtomicU64,
    /// Handler invocations received — bumped once per dispatched turn in [`LocalStreamingManager::run_turn`].
    commands_received: AtomicU64,
    /// Cumulative input/output tokens metered across OpenAI-compat turns served by this session — a
    /// live gauge for the operator (rough count, not billing). Bumped by
    /// [`LocalStreamingManager::record_tokens`] from the OpenAI-compat surface.
    tokens_in: AtomicU64,
    tokens_out: AtomicU64,
    /// Last command-or-event wall clock (epoch ms) — the cloud `last_activity_at`.
    last_activity_ms: AtomicI64,
    /// Registered handler names (snapshotted after `manager.start()`), surfaced to the UI.
    handler_names: Vec<String>,
}

impl SessionMeta {
    /// Build a serializable snapshot in the cloud `StreamingSession` shape. `status`/`ended_at`/
    /// `end_reason` are supplied by the caller because they depend on whether this is a live read
    /// (`running`) or the terminal snapshot returned by `stop_session` (`ended`).
    fn snapshot(
        &self,
        workflow_id: i64,
        status: &str,
        ended_at: Option<String>,
        end_reason: Option<String>,
    ) -> SessionInfo {
        SessionInfo {
            session_key: self.session_key.clone(),
            workflow_id,
            status: status.to_string(),
            target_url: self.target_url.clone(),
            current_url: None,
            agent_id: None,
            events_emitted: self.events_emitted.load(Ordering::Relaxed),
            commands_received: self.commands_received.load(Ordering::Relaxed),
            tokens_in: self.tokens_in.load(Ordering::Relaxed),
            tokens_out: self.tokens_out.load(Ordering::Relaxed),
            started_at: self.started_at.clone(),
            last_activity_at: ms_to_rfc3339(self.last_activity_ms.load(Ordering::Relaxed)),
            ended_at,
            end_reason,
            max_duration_seconds: self.max_duration_seconds,
            error_message: None,
            handlers: self
                .handler_names
                .iter()
                .map(|n| HandlerInfo { name: n.clone(), kind: "steps".into() })
                .collect(),
        }
    }
}

/// Serializable session record returned by the `/v1/streaming/sessions*` routes. Field-for-field the
/// cloud `StreamingSession` shape the desktop TS `StreamingSession` type already mirrors, so the
/// frontend renders a local session exactly like a cloud one.
#[derive(Debug, Clone, serde::Serialize)]
pub struct SessionInfo {
    pub session_key: String,
    pub workflow_id: i64,
    pub status: String,
    pub target_url: String,
    pub current_url: Option<String>,
    pub agent_id: Option<String>,
    pub events_emitted: u64,
    pub commands_received: u64,
    /// Cumulative metered tokens for OpenAI-compat turns (rough live gauge, not billing).
    pub tokens_in: u64,
    pub tokens_out: u64,
    pub started_at: String,
    pub last_activity_at: String,
    pub ended_at: Option<String>,
    pub end_reason: Option<String>,
    pub max_duration_seconds: i64,
    pub error_message: Option<String>,
    pub handlers: Vec<HandlerInfo>,
}

/// One registered handler, in the cloud `StreamingHandler` shape (name + type). Local handlers are
/// always step-group handlers, so `kind` is `"steps"`.
#[derive(Debug, Clone, serde::Serialize)]
pub struct HandlerInfo {
    pub name: String,
    #[serde(rename = "type")]
    pub kind: String,
}

/// A live streaming session for one workflow: the manager (behind a mutex so turns serialize), the
/// owned target page, the per-session bridge token, the in-flight-turn routing table, and the live
/// session-record metadata.
struct Session {
    /// The streaming session manager (drives setup steps, handler registry, thread tabs). Behind a
    /// mutex because a turn mutates it (`get_thread_page`, `touch`) and only one turn runs at a time.
    manager: Mutex<StreamingSessionManager>,
    /// The session's main page (cloned handle; cheap). Turns dispatch `ps._dispatch` onto the
    /// thread-resolved page, but the main page is the default + the dispatch target when multi-conv
    /// is off.
    page: playwright_rs::Page,
    /// Per-session bridge capability token (forwarded to the privileged bridges). Not logged.
    bridge_token: String,
    /// `request_id` → the turn's live entry (event sender + creation time). The router task looks the
    /// turn up here to fan bridge events to the right in-flight turn; a missing entry means the turn
    /// already finished. The creation time lets the router SWEEP turns whose handler never responded
    /// (see [`TurnEntry`]) so the map cannot grow without bound on a misbehaving script.
    turns: Arc<DashMap<String, TurnEntry>>,
    /// Live session-record metadata (counters/timestamps/identity), shared with the router task.
    meta: Arc<SessionMeta>,
    /// Live-preview handle for the "watch the AI" screencast (registry key `streaming-{session_key}`),
    /// the SAME channel the `/ws/ai-preview/:key` WebSocket serves. Held only for its `Drop`: when the
    /// session ends and this `Session` is dropped, the channel deregisters and spectators' sockets
    /// close (the lazy screencast task, if any, self-stops once watchers hit zero).
    #[allow(dead_code)]
    preview: crate::local::ai::live_preview::PreviewHandle,
}

/// One in-flight streaming turn's routing entry: the event sender the router fans chunks/Done into,
/// plus the epoch-ms creation time. The creation time lets the router task sweep an entry whose
/// handler never called `ps.respond` (which would otherwise leak the channel + map slot forever).
struct TurnEntry {
    tx: mpsc::UnboundedSender<StreamEvent>,
    created_ms: i64,
}

/// Wall-clock helpers (the daemon is allowed `chrono::Utc::now()`; only the workflow JS sandbox bans
/// it). RFC3339 strings match the cloud session timestamps the frontend already parses.
fn now_rfc3339() -> String {
    chrono::Utc::now().to_rfc3339()
}
fn now_ms() -> i64 {
    chrono::Utc::now().timestamp_millis()
}
fn ms_to_rfc3339(ms: i64) -> String {
    chrono::DateTime::<chrono::Utc>::from_timestamp_millis(ms)
        .map(|d| d.to_rfc3339())
        .unwrap_or_else(now_rfc3339)
}

/// Find-or-lazily-start manager for local streaming sessions, keyed by workflow id. Holds the shared
/// warm [`BrowserManager`] so a streaming session reuses the same Chromium the run engine drives.
pub struct LocalStreamingManager {
    browser: Arc<BrowserManager>,
    /// Encrypted store handle — used to load a workflow's pinned persona (`default_persona_id`) so
    /// a streaming session can sign in as it. Shares the engine's pool.
    db: SqlitePool,
    /// The vault that decrypts the persona's sealed login/session/proxy/TOTP fields. Shared `Arc`.
    vault: Arc<Vault>,
    /// workflow_id → its live session. `Arc<Session>` so a turn can hold the session across the
    /// `&self` map borrow (the map entry is only locked briefly to look up / insert).
    sessions: DashMap<i64, Arc<Session>>,
    /// Serializes the find-or-start critical section per process so two concurrent first-turns for
    /// the SAME workflow don't both launch a tab. (Per-workflow would need a keyed lock; a single
    /// start lock is fine — starts are rare and brief relative to turns.)
    start_lock: Mutex<()>,
    /// A weak handle to the OUTER engine (the `FlowEventEngine` decorator), set once after the engine
    /// Arc is constructed (see [`Self::set_engine`]). Used to fire `streaming_session_started` /
    /// `streaming_session_ended` automations — those run `workflow` actions, which need an engine.
    /// `Weak` breaks the Arc cycle (engine → streaming manager → engine); a firing whose engine has
    /// been dropped is simply skipped.
    engine: OnceLock<Weak<dyn LocalEngine>>,
}

impl LocalStreamingManager {
    pub fn new(browser: Arc<BrowserManager>, db: SqlitePool, vault: Arc<Vault>) -> Self {
        Self {
            browser,
            db,
            vault,
            sessions: DashMap::new(),
            start_lock: Mutex::new(()),
            engine: OnceLock::new(),
        }
    }

    /// Install the (weak) outer-engine handle used to fire streaming-session automations. Called once
    /// by the daemon after the `Arc<dyn LocalEngine>` decorator is built (the manager lives INSIDE the
    /// engine, so the handle can only be wired post-construction). A second call is a no-op.
    pub fn set_engine(&self, engine: Weak<dyn LocalEngine>) {
        let _ = self.engine.set(engine);
    }

    /// Fire all enabled automations for a streaming lifecycle `event` (`streaming_session_started` /
    /// `streaming_session_ended`) whose root event watches this workflow (or any). Detached +
    /// best-effort — a load error or a single automation failure is logged, never propagated (it must
    /// not affect session start/stop). No-op if no engine handle was wired or it has been dropped.
    ///
    /// **Loop guard.** Automations are fired with [`RunSource::Workflow`] so any `workflow` action
    /// they run is one-hop-bounded (that run's own completion automations cannot cascade) — the same
    /// bound the workflow-lifecycle events use.
    fn fire_streaming_event(&self, event: &'static str, workflow_id: i64, context: serde_json::Value) {
        let engine = match self.engine.get().and_then(Weak::upgrade) {
            Some(e) => e,
            None => return, // no engine wired (e.g. tests) — nothing to run actions with
        };
        let db = self.db.clone();
        tokio::spawn(async move {
            let autos =
                match crate::local::store::automations::list_enabled_for_event(&db, event, 256).await
                {
                    Ok(v) => v,
                    Err(e) => {
                        tracing::warn!(event, error = %e, "could not load streaming-event automations");
                        return;
                    }
                };
            for auto in autos {
                // Watch scope: an automation with a linked `workflow_id` only fires for THAT
                // workflow's session; an unset `workflow_id` watches any streaming session.
                if let Some(wid) = auto.workflow_id {
                    if wid != workflow_id {
                        continue;
                    }
                }
                if !crate::local::flow::has_executable_tree(auto.blocks.as_deref()) {
                    continue;
                }
                let trigger = crate::local::flow::FlowTrigger {
                    event: event.to_string(),
                    change_id: None,
                    base_inputs: serde_json::json!({}),
                    context: context.clone(),
                    source: super::RunSource::Workflow,
                    lane: super::Lane::Background,
                };
                if let Err(e) = crate::local::flow::run_automation(&db, &engine, &auto, trigger).await {
                    tracing::warn!(automation_id = auto.id, event, error = %e, "streaming-event automation failed");
                }
            }
        });
    }

    /// Run ONE streamed chat turn for `wf` against its (find-or-lazily-started) session.
    ///
    /// `inputs` is the resolved run-input object (see [`super::resolve`]) — typically `{message,
    /// messages, input.*, ...}`. We dispatch the workflow's configured `default_handler` action with
    /// that payload and return an unbounded receiver of [`StreamEvent`]s. The receiver yields chunks
    /// as the page streams them and a single terminal `Done`/`Error`.
    ///
    /// Returns the resolved `response_field` alongside the receiver so the SSE layer can extract the
    /// final content from the `Done` payload without re-reading config.
    pub async fn run_turn(
        &self,
        wf: &Workflow,
        inputs: serde_json::Value,
    ) -> LocalResult<(mpsc::UnboundedReceiver<StreamEvent>, String)> {
        let session = self.find_or_start(wf).await?;
        // A dispatched turn IS a handler invocation — mirror the cloud `commands_received` counter
        // (and refresh `last_activity_at`) the moment the command arrives, like the Python session.
        session.meta.commands_received.fetch_add(1, Ordering::Relaxed);
        session.meta.last_activity_ms.store(now_ms(), Ordering::Relaxed);
        let (default_handler, response_field) = openai_compat_knobs(wf);

        // Build the dispatch payload. `message` is the last user turn (what a chat handler reads);
        // we also forward the whole resolved inputs object so an advanced script can read named
        // fields. `_thread_id` routes multi-conversation tabs (None → main page).
        let data = match inputs {
            serde_json::Value::Object(map) => map,
            other => {
                // A non-object input still gets a `message` slot so a chat handler has something.
                let mut m = serde_json::Map::new();
                if let serde_json::Value::String(s) = other {
                    m.insert("message".into(), serde_json::Value::String(s));
                }
                m
            }
        };
        let thread_id = data
            .get("_thread_id")
            .and_then(|v| v.as_str())
            .map(String::from);

        // Register the turn's channel BEFORE dispatch so an immediate stream chunk is not lost.
        let request_id = uuid::Uuid::new_v4().simple().to_string();
        let (tx, rx) = mpsc::unbounded_channel();
        session
            .turns
            .insert(request_id.clone(), TurnEntry { tx: tx.clone(), created_ms: now_ms() });

        // Resolve the conversation's page (main page unless multi-conv routes a thread tab), then
        // re-inject the runtime + advanced script if the page navigated and lost `window.ps`.
        let (target_page, adv) = {
            let mut mgr = session.manager.lock().await;
            mgr.touch();
            let adv = mgr.advanced_script_code().map(|s| s.to_string());
            let page = mgr
                .get_thread_page(thread_id.as_deref())
                .await
                .unwrap_or_else(|_| session.page.clone());
            (page, adv)
        };
        if let Err(e) =
            runtime_bridge::reinject_runtime(&target_page, adv.as_deref(), &session.bridge_token).await
        {
            session.turns.remove(&request_id);
            return Err(LocalError::Internal(format!("runtime re-inject failed: {e}")));
        }

        // Dispatch the action into the page (EXACT parity with the cloud `ps._dispatch` shape): a
        // named handler (`ps.on("<action>")`) takes priority; otherwise the legacy `message`
        // catch-all. The `request_id` is the 3rd dispatch arg (the handler echoes it to ps.respond /
        // ps.stream); the handler then runs ASYNC and streams back via the bridge.
        let args =
            serde_json::json!([default_handler, serde_json::Value::Object(data), request_id.clone()]);
        let dispatch: serde_json::Value = target_page
            .evaluate(DISPATCH_JS, Some(&args))
            .await
            .unwrap_or_else(|e| serde_json::json!({ "error": format!("evaluate failed: {e}") }));

        if let Some(err) = dispatch.get("error").and_then(|v| v.as_str()) {
            // No handler / dispatch error: surface a terminal Error and retire the turn channel (no
            // ps.respond will ever fire, so the router would otherwise leave the entry dangling).
            tracing::warn!(workflow_id = wf.id, action = %default_handler, error = err, "stream dispatch error");
            session.turns.remove(&request_id);
            let _ = tx.send(StreamEvent::Error { message: err.to_string() });
        }

        Ok((rx, response_field))
    }

    /// Explicitly LAUNCH a streaming session for `wf` (find-or-start) WITHOUT dispatching a turn —
    /// the entry point for the desktop "Run" button on a streaming workflow. Opens the warm tab,
    /// runs setup steps, injects the runtime + advanced script, and returns the live session record
    /// (`status: "running"`). Idempotent: calling it again while a session is live returns the
    /// SAME session (its existing record), mirroring the cloud find-or-start.
    pub async fn start_session(&self, wf: &Workflow) -> LocalResult<SessionInfo> {
        // Fire `streaming_session_started` ONLY when this call actually LAUNCHES a new session — an
        // idempotent re-start of an already-live session must not re-fire the event. `find_or_start`
        // is idempotent, so we probe liveness first (a benign race with a concurrent start is bounded
        // by the automation guardrails downstream).
        let was_live = self.sessions.contains_key(&wf.id);
        let session = self.find_or_start(wf).await?;
        if !was_live {
            self.fire_streaming_event(
                "streaming_session_started",
                wf.id,
                serde_json::json!({
                    "event": "streaming_session_started",
                    "workflow_id": wf.id,
                    "session_key": session.meta.session_key,
                }),
            );
        }
        Ok(session.meta.snapshot(wf.id, "running", None, None))
    }

    /// Snapshot every live session (one per workflow) for `GET /v1/streaming/sessions`. All listed
    /// sessions are `running` — ended sessions are removed from the map by [`Self::stop_session`].
    pub fn list_sessions(&self) -> Vec<SessionInfo> {
        self.sessions
            .iter()
            .map(|e| e.value().meta.snapshot(*e.key(), "running", None, None))
            .collect()
    }

    /// Snapshot the live session for one workflow, or `None` if it has no session running.
    pub fn get_session(&self, workflow_id: i64) -> Option<SessionInfo> {
        self.sessions
            .get(&workflow_id)
            .map(|s| s.meta.snapshot(workflow_id, "running", None, None))
    }

    /// Add one turn's metered token usage to the workflow's live session so the desktop live page can
    /// show running in/out consumption. No-op if the workflow has no live session. Also refreshes
    /// `last_activity_at`, since a metered turn IS activity. Called from the OpenAI-compat surface,
    /// which is the component that knows the request (input) and assembled reply (output) text.
    pub fn record_tokens(&self, workflow_id: i64, tokens_in: u64, tokens_out: u64) {
        if let Some(session) = self.sessions.get(&workflow_id) {
            session.meta.tokens_in.fetch_add(tokens_in, Ordering::Relaxed);
            session.meta.tokens_out.fetch_add(tokens_out, Ordering::Relaxed);
            session.meta.last_activity_ms.store(now_ms(), Ordering::Relaxed);
        }
    }

    /// END the workflow's live session (the "Stop"/"End session" control): drop it from the
    /// registry, then drive the manager's `end(reason)` (aborts keepalive/idle/hard-timeout tasks,
    /// closes thread + main contexts, extracts session state). Returns the terminal `ended` snapshot,
    /// or `None` if no session was live. `reason` matches the cloud `end_reason` vocabulary
    /// (`user_ended` / `timeout` / `error`).
    pub async fn stop_session(&self, workflow_id: i64, reason: &str) -> Option<SessionInfo> {
        let (_, session) = self.sessions.remove(&workflow_id)?;
        // The `preview` handle deregisters when `session` drops (closing spectators; the lazy
        // screencast self-stops once its watcher count hits zero).
        let snap = session
            .meta
            .snapshot(workflow_id, "ended", Some(now_rfc3339()), Some(reason.to_string()));
        {
            let mut mgr = session.manager.lock().await;
            mgr.end(reason).await;
        }
        tracing::info!(workflow_id, reason, "local streaming session ended");
        self.fire_streaming_event(
            "streaming_session_ended",
            workflow_id,
            serde_json::json!({
                "event": "streaming_session_ended",
                "workflow_id": workflow_id,
                "session_key": snap.session_key,
                "end_reason": reason,
            }),
        );
        Some(snap)
    }

    /// Return the live session for `wf`, lazily starting one (browser context + page + runtime
    /// bridge + handler registry + bridge-event router task) on first use. Idempotent under the
    /// start lock so concurrent first-turns for one workflow share a single session.
    async fn find_or_start(&self, wf: &Workflow) -> LocalResult<Arc<Session>> {
        if let Some(existing) = self.sessions.get(&wf.id) {
            return Ok(existing.clone());
        }
        let _guard = self.start_lock.lock().await;
        // Re-check inside the lock (another task may have started it while we waited).
        if let Some(existing) = self.sessions.get(&wf.id) {
            return Ok(existing.clone());
        }

        // Resolve the workflow's pinned persona (login identity) so the session signs in AS it —
        // decrypts its credentials / fingerprint / session_state / proxy / TOTP. A dangling id is
        // non-fatal (the session simply runs without a persona); a broken 2FA seed fails loudly.
        let resolved_persona = match wf.default_persona_id {
            Some(pid) => persona::resolve_persona(&self.db, &self.vault, pid)
                .await
                .map_err(|e| LocalError::Internal(format!("persona resolution failed: {e}")))?,
            None => None,
        };

        // PRE-FLIGHT 2FA gate: email/SMS codes can only be read in the cloud, so a LOCAL streaming
        // session cannot serve them. If the persona uses email/SMS 2FA and this workflow has a
        // `twofa` step, fail fast with a clear message (parity with the run engine, real.rs). TOTP
        // mints on-device, so it never trips this.
        if let Some(p) = resolved_persona.as_ref() {
            if matches!(p.twofa_method.as_str(), "email_otp" | "sms") && streaming_has_twofa_step(wf) {
                return Err(LocalError::BadRequest(format!(
                    "This streaming workflow signs in with a 2FA code sent by {}. Reading that code \
                     requires running in the cloud.",
                    if p.twofa_method == "sms" { "SMS" } else { "email" }
                )));
            }
        }

        let mut config = build_streaming_config(wf);
        // Restore the persona's saved auth (cookies + storage) BEFORE the manager navigates, so the
        // session starts already logged in — the shared manager's `start` reads `config["session_state"]`
        // and injects it pre-navigation (1:1 with the run engine's session restore).
        if let Some(state) = resolved_persona.as_ref().and_then(|p| p.session_state.as_ref()) {
            if let (Ok(v), serde_json::Value::Object(map)) =
                (serde_json::to_value(state), &mut config)
            {
                map.insert("session_state".into(), v);
            }
        }

        let headless = wf.headless != 0;
        // Pin the persona's captured fingerprint (returning-user warmth) + BYO residential proxy.
        let fingerprint = resolved_persona.as_ref().and_then(|p| p.fingerprint.clone());
        let proxy = resolved_persona.as_ref().and_then(|p| p.proxy.clone());

        // Warm the shared browser, then a stealth context pinned to the persona fingerprint + proxy
        // (both None → fresh fingerprint + env/direct egress, identical to the prior behaviour).
        self.browser
            .ensure_warm_browser_with(headless)
            .await
            .map_err(|e| LocalError::Internal(format!("browser launch failed: {e}")))?;
        let (context, page, _fp) = self
            .browser
            .create_stealth_context_with_fingerprint_proxy(fingerprint, proxy)
            .await
            .map_err(|e| LocalError::Internal(format!("browser context failed: {e}")))?;

        // Wire the privileged runtime bridge (expose-function callbacks + window.ps) and capture the
        // per-session token + the bridge-event receiver we route to in-flight turns.
        let (bridge_tx, mut bridge_rx) = mpsc::unbounded_channel::<BridgeEvent>();
        let bridge_token = runtime_bridge::setup_runtime_bridge(&page, bridge_tx.clone())
            .await
            .map_err(|e| LocalError::Internal(format!("runtime bridge setup failed: {e}")))?;

        // Build + start the session manager (navigates to the start url, runs setup steps, registers
        // handlers, injects the advanced script, starts keepalive/idle tasks). `start` (not
        // `start_attached`) because WE own the page lifecycle here, like the gateway path.
        let mut manager = StreamingSessionManager::new(wf.id.to_string(), config);
        manager.set_bridge_token(bridge_token.clone());
        // Feed the persona's login secrets (username/password + minted TOTP under `otp`) to the
        // setup/login steps so `{{secret:...}}` resolves and the session authenticates. Empty when
        // there is no persona → unchanged (setup runs credential-less). SECRET — never logged.
        if let Some(p) = resolved_persona.as_ref() {
            let mut setup_creds: HashMap<String, String> = HashMap::new();
            p.merge_into_credentials(&mut setup_creds);
            if !setup_creds.is_empty() {
                manager.set_setup_credentials(setup_creds);
            }
        }
        manager
            .start(page.clone(), context.clone())
            .await
            .map_err(|e| LocalError::Internal(format!("streaming session start failed: {e}")))?;
        manager.set_bridge_event_tx(bridge_tx.clone());
        manager.set_browser_manager(self.browser.clone());

        // Build the live session record now that setup is done and handlers are registered. The
        // session is `running` the instant this returns — parity with the Python agent, which acks
        // `status: "running"` immediately after constructing the manager.
        let meta = Arc::new(SessionMeta {
            session_key: uuid::Uuid::new_v4().simple().to_string(),
            target_url: wf.entry_url.clone().unwrap_or_default(),
            max_duration_seconds: session_max_duration_seconds(wf),
            started_at: now_rfc3339(),
            events_emitted: AtomicU64::new(0),
            commands_received: AtomicU64::new(0),
            tokens_in: AtomicU64::new(0),
            tokens_out: AtomicU64::new(0),
            last_activity_ms: AtomicI64::new(now_ms()),
            handler_names: manager.handler_names(),
        });

        let turns: Arc<DashMap<String, TurnEntry>> = Arc::new(DashMap::new());

        // Router task: fan each bridge event to the in-flight turn it belongs to (by request_id).
        // Lives for the session; ends when the bridge sender is dropped (session end / context
        // close). NEVER logs chunk bodies.
        {
            let turns = turns.clone();
            let meta = meta.clone();
            let wf_id = wf.id;
            tokio::spawn(async move {
                while let Some(event) = bridge_rx.recv().await {
                    // Sweep leaked turns on every bridge event: a handler that never calls
                    // `ps.respond` (or whose SSE receiver was already dropped) would otherwise leave
                    // its entry + channel in the map forever. Retire anything older than the per-turn
                    // timeout or whose receiver has hung up. Cheap relative to event frequency.
                    let cutoff = now_ms() - turn_timeout().as_millis() as i64;
                    turns.retain(|_, entry| entry.created_ms >= cutoff && !entry.tx.is_closed());
                    match event {
                        BridgeEvent::Stream { request_id, chunk } => {
                            if let Some(entry) = turns.get(&request_id) {
                                let _ = entry.tx.send(StreamEvent::Chunk { content: chunk_content(&chunk) });
                            }
                        }
                        BridgeEvent::Respond { request_id, data } => {
                            // Terminal: deliver Done and retire the turn channel.
                            if let Some((_, entry)) = turns.remove(&request_id) {
                                let _ = entry.tx.send(StreamEvent::Done { data });
                            }
                        }
                        BridgeEvent::Emit { name, .. } => {
                            // An autonomous `ps.emit(...)` — the cloud `events_emitted` counter.
                            meta.events_emitted.fetch_add(1, Ordering::Relaxed);
                            meta.last_activity_ms.store(now_ms(), Ordering::Relaxed);
                            tracing::debug!(workflow_id = wf_id, event = %name, "streaming emit");
                        }
                        BridgeEvent::Log { message } => {
                            tracing::info!(workflow_id = wf_id, "[ps.log] {}", message);
                        }
                    }
                }
                tracing::debug!(workflow_id = wf_id, "streaming bridge router ended");
            });
        }

        // Live preview: stream a screencast of this session's page to any Watch spectators, keyed
        // `streaming-{session_key}` (the same `/ws/ai-preview/:key` channel AI sessions use), BOUND to
        // this page. The screencast is LAZY — it starts only when someone opens the preview and stops
        // when the last watcher leaves, so an unwatched session never pays a screenshot.
        let preview = crate::local::ai::live_preview::register_with_page(
            format!("streaming-{}", meta.session_key),
            page.clone(),
        );

        let session = Arc::new(Session {
            manager: Mutex::new(manager),
            page,
            bridge_token,
            turns,
            meta,
            preview,
        });
        self.sessions.insert(wf.id, session.clone());
        tracing::info!(workflow_id = wf.id, "local streaming session started");
        Ok(session)
    }
}

/// JS that dispatches an action into the page's `window.ps` runtime — EXACT parity with the cloud
/// dispatch (a named `ps.on("<action>")` handler wins; else the legacy `message` catch-all). Args
/// arrive via `evaluate`'s parameter (NOT string interpolation), so untrusted text never becomes code.
const DISPATCH_JS: &str = r#"([action, data, requestId]) => {
    if (!window.ps) return {error: 'ps runtime not injected'};
    if (!window.ps._dispatch) return {error: 'ps._dispatch not available'};
    const handlers = window.ps._handlers || {};
    const named = handlers[action] && handlers[action].length > 0;
    const hasMsg = handlers.message && handlers.message.length > 0;
    if (!named && !hasMsg) return {error: 'no handler registered for action: ' + action};
    try {
        if (named) ps._dispatch(action, {data, requestId});
        else ps._dispatch('message', {action, data, requestId});
        return {ok: true, dispatched: named ? action : 'message'};
    } catch(e) {
        return {error: 'dispatch error: ' + e.message};
    }
}"#;

/// Extract the assistant-visible text from a bridge stream chunk. The runtime emits either a bare
/// string or `{content: "..."}` (parity with the cloud `chunk["data"].get("content")`).
fn chunk_content(chunk: &serde_json::Value) -> String {
    match chunk {
        serde_json::Value::String(s) => s.clone(),
        serde_json::Value::Object(_) => chunk
            .get("content")
            .and_then(|v| v.as_str())
            .map(String::from)
            .unwrap_or_default(),
        _ => String::new(),
    }
}

/// Read the OpenAI-compat knobs from a workflow's `streaming_config.openai_compat`:
/// `(default_handler, response_field)`. Defaults match the Python resolver (`chat` / `content`).
/// Honors `streaming_config.openai_compat.response_field` (the "openai_response_field" knob).
fn openai_compat_knobs(wf: &Workflow) -> (String, String) {
    let sc: serde_json::Value = wf
        .streaming_config
        .as_deref()
        .and_then(|s| serde_json::from_str(s).ok())
        .unwrap_or(serde_json::Value::Null);
    let oc = sc.get("openai_compat");
    let default_handler = oc
        .and_then(|o| o.get("default_handler"))
        .and_then(|v| v.as_str())
        .unwrap_or("chat")
        .to_string();
    let response_field = oc
        .and_then(|o| o.get("response_field"))
        .and_then(|v| v.as_str())
        .unwrap_or("content")
        .to_string();
    (default_handler, response_field)
}

/// Whether this streaming workflow has a `twofa` step anywhere in its recorded steps — the trigger
/// for the email/SMS 2FA pre-flight gate (those codes can't be read locally). Best-effort: a
/// non-array / unparseable `steps` yields `false` (nothing to gate).
fn streaming_has_twofa_step(wf: &Workflow) -> bool {
    serde_json::from_str::<Vec<serde_json::Value>>(&wf.steps)
        .unwrap_or_default()
        .iter()
        .any(|s| s.get("type").and_then(|v| v.as_str()) == Some("twofa"))
}

/// The session's auto-end ceiling in seconds, from `streaming_config.max_duration_seconds`. Defaults
/// to the cloud `StreamingSession` default (3600 = 1h) when unset, so the local record reads the
/// same as a cloud one.
fn session_max_duration_seconds(wf: &Workflow) -> i64 {
    wf.streaming_config
        .as_deref()
        .and_then(|s| serde_json::from_str::<serde_json::Value>(s).ok())
        .and_then(|v| v.get("max_duration_seconds").and_then(|n| n.as_i64()))
        .unwrap_or(3600)
}

/// Build the config object [`StreamingSessionManager::new`] + [`StreamingSessionManager::start`]
/// consume, from a recorded workflow row. The manager expects a flat config with top-level
/// `handlers` / `advanced_script` / `setup_steps_count` (which already live in the workflow's
/// `streaming_config` blob) plus `url` / `steps` / `form_data`, and a NESTED `streaming_config`
/// sub-object for the multi-conversation knobs (the manager reads `config.streaming_config.*`).
fn build_streaming_config(wf: &Workflow) -> serde_json::Value {
    // Base = the stored streaming_config blob (handlers, advanced_script, setup_steps_count,
    // openai_compat, multi_conversation, context_mode, max_concurrent_threads).
    let base: serde_json::Value = wf
        .streaming_config
        .as_deref()
        .and_then(|s| serde_json::from_str(s).ok())
        .unwrap_or(serde_json::json!({}));

    let mut config = base.as_object().cloned().unwrap_or_default();

    // url: the workflow's entry url (the page the chat lives on).
    if let Some(url) = wf.entry_url.as_deref().filter(|s| !s.is_empty()) {
        config.insert("url".into(), serde_json::Value::String(url.to_string()));
    }
    // steps: parsed from the workflow's stored JSON-TEXT (setup/handler steps reference these).
    let steps: serde_json::Value = serde_json::from_str(&wf.steps).unwrap_or(serde_json::json!([]));

    // setup_steps_count: how many LEADING steps run ONCE at session start (login / navigation)
    // before the live handler takes over. The recorder persists this in the base blob, but a
    // workflow created or last-edited through a path that didn't re-persist it (or an older row)
    // can carry 0/absent — which makes the manager skip setup entirely (`run_setup_steps` returns
    // early when the count is 0) and inject the long-running advanced script against a page that was
    // never set up. Recover it: when there is NO explicit positive count AND the workflow declares
    // no named per-message handlers, every recorded step BEFORE the advanced-script step is a setup
    // step. The `advanced_script` step (a first-class trailing step) is injected separately, so it is
    // never itself replayed as a setup step. Handler-based workflows — where a 0 count is intentional
    // (their steps fire per-turn, not at start) — are left untouched.
    let has_handlers = base
        .get("handlers")
        .and_then(|v| v.as_array())
        .map(|a| !a.is_empty())
        .unwrap_or(false);
    let stored_count = base
        .get("setup_steps_count")
        .and_then(|v| v.as_u64())
        .unwrap_or(0);
    if stored_count == 0 && !has_handlers {
        if let Some(arr) = steps.as_array() {
            let count = arr
                .iter()
                .position(|s| s.get("type").and_then(|t| t.as_str()) == Some("advanced_script"))
                .unwrap_or(arr.len());
            config.insert("setup_steps_count".into(), serde_json::json!(count));
        }
    }

    config.insert("steps".into(), steps);
    // form_data: the workflow's stored non-secret form values (handler steps fill from these).
    if let Some(fd) = wf
        .form_data
        .as_deref()
        .and_then(|s| serde_json::from_str::<serde_json::Value>(s).ok())
    {
        config.insert("form_data".into(), fd);
    }
    // login url patterns (relogin detection) — optional.
    if let Some(p) = wf
        .login_url_patterns
        .as_deref()
        .and_then(|s| serde_json::from_str::<serde_json::Value>(s).ok())
    {
        config.insert("login_url_patterns".into(), p);
    }

    // The manager reads the multi-conversation knobs from a NESTED `streaming_config` key. Lift them
    // out of the base blob (where they sit at the top level) into the shape the manager expects.
    let nested = serde_json::json!({
        "multi_conversation": base.get("multi_conversation").cloned().unwrap_or(serde_json::json!(false)),
        "context_mode": base.get("context_mode").cloned().unwrap_or(serde_json::json!("shared")),
        "max_concurrent_threads": base.get("max_concurrent_threads").cloned().unwrap_or(serde_json::json!(3)),
    });
    config.insert("streaming_config".into(), nested);

    serde_json::Value::Object(config)
}

/// Per-turn timeout as a `Duration`. Exposed so the SSE layer can bound its receive loop.
pub fn turn_timeout() -> std::time::Duration {
    std::time::Duration::from_secs(
        std::env::var("WRIT_STREAMING_TURN_TIMEOUT_SECS")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(TURN_TIMEOUT_SECS),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::local::store::workflows::{self, NewWorkflow};
    use crate::local::{db, vault};

    async fn pool() -> sqlx::SqlitePool {
        let dir = Box::leak(Box::new(tempfile::tempdir().unwrap()));
        let v = vault::Vault::load_or_create(dir.path(), false).unwrap();
        db::open(&dir.path().join("t.db"), &v.db_key_hex()).await.unwrap()
    }

    #[tokio::test]
    async fn knobs_default_to_chat_and_content() {
        let p = pool().await;
        let wf = workflows::insert(&p, &NewWorkflow { name: "s".into(), ..Default::default() })
            .await
            .unwrap();
        let (h, f) = openai_compat_knobs(&wf);
        assert_eq!(h, "chat");
        assert_eq!(f, "content");
    }

    #[tokio::test]
    async fn knobs_honor_openai_compat_overrides() {
        let p = pool().await;
        let sc = r#"{"openai_compat":{"default_handler":"sendMessage","response_field":"answer"}}"#;
        let wf = workflows::insert(
            &p,
            &NewWorkflow {
                name: "s".into(),
                streaming_config: Some(sc.into()),
                ..Default::default()
            },
        )
        .await
        .unwrap();
        let (h, f) = openai_compat_knobs(&wf);
        assert_eq!(h, "sendMessage");
        assert_eq!(f, "answer");
    }

    #[tokio::test]
    async fn config_lifts_multi_conv_knobs_into_nested_streaming_config() {
        let p = pool().await;
        let sc = r#"{
            "multi_conversation": true,
            "context_mode": "isolated",
            "max_concurrent_threads": 5,
            "handlers": [{"name":"chat","type":"code","code":"x"}],
            "advanced_script": {"enabled": true, "code": "y"}
        }"#;
        let wf = workflows::insert(
            &p,
            &NewWorkflow {
                name: "s".into(),
                streaming_config: Some(sc.into()),
                steps: Some(r#"[{"type":"wait"}]"#.into()),
                entry_url: Some("https://example.com".into()),
                form_data: Some(r#"{"k":"v"}"#.into()),
                ..Default::default()
            },
        )
        .await
        .unwrap();

        let cfg = build_streaming_config(&wf);
        // Nested streaming_config carries the multi-conversation knobs the manager reads.
        assert_eq!(cfg["streaming_config"]["multi_conversation"], serde_json::json!(true));
        assert_eq!(cfg["streaming_config"]["context_mode"], serde_json::json!("isolated"));
        assert_eq!(cfg["streaming_config"]["max_concurrent_threads"], serde_json::json!(5));
        // Top-level keys preserved from the base blob + lifted columns.
        assert_eq!(cfg["url"], serde_json::json!("https://example.com"));
        assert_eq!(cfg["steps"], serde_json::json!([{"type":"wait"}]));
        assert_eq!(cfg["form_data"], serde_json::json!({"k":"v"}));
        assert!(cfg["handlers"].is_array());
        assert_eq!(cfg["advanced_script"]["enabled"], serde_json::json!(true));
    }

    #[tokio::test]
    async fn config_recovers_setup_steps_count_when_missing() {
        let p = pool().await;
        // Streaming workflow: recorded setup steps (login) + a trailing advanced_script step, but a
        // streaming_config that never persisted setup_steps_count (0/absent). Without recovery the
        // manager would skip setup and inject the long-running script against an un-set-up page.
        let sc = r##"{"advanced_script":{"enabled":true,"code":"ps.on('message',()=>{})"}}"##;
        let steps = r##"[
            {"type":"navigate","config":{"url":"https://example.com/login"}},
            {"type":"fill","config":{"selector":"#u","value":"x"}},
            {"type":"advanced_script","config":{"code":"ps.on('message',()=>{})"}}
        ]"##;
        let wf = workflows::insert(
            &p,
            &NewWorkflow {
                name: "s".into(),
                streaming_config: Some(sc.into()),
                steps: Some(steps.into()),
                entry_url: Some("https://example.com".into()),
                ..Default::default()
            },
        )
        .await
        .unwrap();

        let cfg = build_streaming_config(&wf);
        // The two leading recorded steps become setup steps; the trailing advanced_script step is
        // excluded (it is injected separately, never replayed as a setup step).
        assert_eq!(cfg["setup_steps_count"], serde_json::json!(2));
    }

    #[tokio::test]
    async fn config_leaves_setup_steps_count_for_handler_workflows() {
        let p = pool().await;
        // A handler-based streaming workflow legitimately has setup_steps_count 0 — its steps fire
        // per-turn via the named handler, not at start. Recovery must NOT override that.
        let sc = r##"{"handlers":[{"name":"chat","type":"steps","step_range":[0,1]}]}"##;
        let steps = r##"[{"type":"fill","config":{"selector":"#m","value":"x"}},{"type":"click","config":{"selector":"#send"}}]"##;
        let wf = workflows::insert(
            &p,
            &NewWorkflow {
                name: "s".into(),
                streaming_config: Some(sc.into()),
                steps: Some(steps.into()),
                ..Default::default()
            },
        )
        .await
        .unwrap();

        let cfg = build_streaming_config(&wf);
        // No explicit count stored, but handlers ARE present → recovery skipped, count stays 0/absent.
        assert_eq!(cfg.get("setup_steps_count").and_then(|v| v.as_u64()).unwrap_or(0), 0);
    }

    /// LOW (streaming.rs:344): the router's turn-sweep drops entries whose handler never responded
    /// (older than the turn timeout) or whose SSE receiver has hung up, while keeping fresh live turns.
    /// Exercises the exact `retain` predicate the router task runs on each bridge event.
    #[test]
    fn turn_sweep_drops_stale_and_closed_but_keeps_live() {
        let turns: DashMap<String, TurnEntry> = DashMap::new();
        let now = now_ms();
        let timeout_ms = turn_timeout().as_millis() as i64;

        // A fresh, live turn (receiver held): must survive.
        let (live_tx, _live_rx) = mpsc::unbounded_channel();
        turns.insert("live".into(), TurnEntry { tx: live_tx, created_ms: now });

        // A stale turn (older than the timeout), receiver still held: swept for age.
        let (stale_tx, _stale_rx) = mpsc::unbounded_channel();
        turns.insert("stale".into(), TurnEntry { tx: stale_tx, created_ms: now - timeout_ms - 1_000 });

        // A fresh turn whose receiver was dropped (SSE client gone): swept as closed.
        let (closed_tx, closed_rx) = mpsc::unbounded_channel::<StreamEvent>();
        drop(closed_rx);
        turns.insert("closed".into(), TurnEntry { tx: closed_tx, created_ms: now });

        let cutoff = now_ms() - turn_timeout().as_millis() as i64;
        turns.retain(|_, entry| entry.created_ms >= cutoff && !entry.tx.is_closed());

        assert!(turns.contains_key("live"), "fresh live turn survives the sweep");
        assert!(!turns.contains_key("stale"), "timed-out turn is swept");
        assert!(!turns.contains_key("closed"), "closed-receiver turn is swept");
    }

    #[test]
    fn chunk_content_handles_string_and_object_and_other() {
        assert_eq!(chunk_content(&serde_json::json!("hi")), "hi");
        assert_eq!(chunk_content(&serde_json::json!({ "content": "tok" })), "tok");
        assert_eq!(chunk_content(&serde_json::json!({ "other": 1 })), "");
        assert_eq!(chunk_content(&serde_json::json!(42)), "");
    }

    #[tokio::test]
    async fn fresh_manager_has_no_live_sessions() {
        // We cannot launch Chromium in CI, so the find-or-start path itself is exercised by an
        // ignored browser test (run locally). Here we assert construction + the empty-session
        // invariant; the config/knobs/chunk-content units above cover the pure logic.
        let dir = tempfile::tempdir().unwrap();
        let v = Arc::new(vault::Vault::load_or_create(dir.path(), false).unwrap());
        let db = db::open(&dir.path().join("t.db"), &v.db_key_hex()).await.unwrap();
        let mgr = LocalStreamingManager::new(
            Arc::new(crate::browser::manager::BrowserManager::new(Arc::new(
                crate::config::env::AppConfig::from_env(),
            ))),
            db,
            v,
        );
        assert!(mgr.sessions.is_empty());
    }
}
