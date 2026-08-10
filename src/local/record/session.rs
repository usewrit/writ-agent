//! Recording-session driver for the local loopback WS AND for cloud-dispatched recording sessions.
//!
//! Drives a [`crate::recorder::core::PlaywrightRecorder`] session on the daemon's OWN warm Chromium
//! and pumps its outbound frames (screencast bytes, recorded-step events, picker overlays, live API
//! captures) to some [`RecordSink`] while feeding inbound commands back into the recorder. This is
//! the in-process equivalent of the cloud `bridge::saas_bridge::run_session_loop` + the cloud
//! `api::ws_record` handler.
//!
//! Transports plug into the same driver via the [`RecordSink`] trait:
//!   * `LoopbackSink` (this file) — the loopback WS `/ws/record`, FLAT frames + RAW binary bytes.
//!   * `CloudRecordSink` (in [`crate::local::record::bridge`]) — the ws-gateway / coordinator WS the
//!     desktop cloud-link AND the OSS fleet worker multiplex over, so the SAME driver handles a
//!     coordinator-dispatched recording ([`ws-gateway/src/handlers/record.ts`](...) sends
//!     `{type:"session_open", purpose:"record"}` + wraps subsequent frames in
//!     `{channel:"session", session_id, msg}` — the sink adds the envelope so the driver logic stays
//!     transport-agnostic).
//!
//! House style: module-local `thiserror` is unnecessary here (the recorder's own typed errors are
//! surfaced as `error` frames); `tracing` only; never logs secrets/tokens.

use std::collections::HashMap;
use std::sync::Arc;

use axum::extract::ws::{Message, WebSocket};
use futures_util::stream::{SplitSink, SplitStream};
use futures_util::{SinkExt, StreamExt};
use serde_json::{json, Value};
use tokio::sync::Mutex;

use crate::automation::network_capture::NetworkCapture;
use crate::recorder::action_handler::{handle_action, ActionResult, IncomingAction};
use crate::recorder::core::PlaywrightRecorder;

/// A cloneable outbound sink for a recording session. Impls in the tree:
///   * [`LoopbackSink`] — FLAT JSON + RAW binary over the loopback `/ws/record` WS.
///   * `crate::local::record::bridge::CloudRecordSink` — wraps JSON in the ws-gateway session
///     envelope + prepends the binary session-id header so coordinator-dispatched recording (desktop
///     cloud-link AND the OSS fleet worker) rides the multiplexed WS without duplicating the driver.
///
/// `send_json` / `send_binary` return `false` when the peer is gone, so forwarder tasks can stop
/// pumping instead of spinning.
pub trait RecordSink: Clone + Send + Sync + 'static {
    fn send_json(&self, v: Value) -> impl std::future::Future<Output = bool> + Send;
    fn send_binary(&self, bytes: Vec<u8>) -> impl std::future::Future<Output = bool> + Send;
}

/// The sending half of a loopback recording socket. Cloneable so the screencast forwarder, the
/// recorder event forwarder, and the command handler can all write to the one socket concurrently.
///
/// Frames are sent FLAT (no `{channel:"session"}` envelope) and screencast bytes are forwarded RAW
/// (the `ScreencastStream::encode_frame` `[4B BE url_len][url][JPEG]` layout the UI decodes
/// directly) — there is no gateway in the loop to strip an envelope, so none is added.
#[derive(Clone)]
pub struct LoopbackSink {
    inner: Arc<Mutex<SplitSink<WebSocket, Message>>>,
}

impl LoopbackSink {
    fn new(sink: SplitSink<WebSocket, Message>) -> Self {
        Self { inner: Arc::new(Mutex::new(sink)) }
    }
}

impl RecordSink for LoopbackSink {
    async fn send_json(&self, v: Value) -> bool {
        let mut s = self.inner.lock().await;
        s.send(Message::Text(v.to_string())).await.is_ok()
    }

    async fn send_binary(&self, bytes: Vec<u8>) -> bool {
        let mut s = self.inner.lock().await;
        s.send(Message::Binary(bytes)).await.is_ok()
    }
}

/// Run one recording session for the lifetime of a loopback WebSocket connection.
///
/// Splits the socket, then loops on inbound text frames dispatching the recorder protocol. On the
/// first `start` it opens a browser session on the SHARED warm Chromium, wires the screencast +
/// event forwarders, and (by default) attaches live API capture. On disconnect — or an explicit
/// `stop` — it tears the browser session down. Idempotent cleanup: ending an already-ended session
/// is a no-op.
pub async fn run(socket: WebSocket, recorder: Arc<PlaywrightRecorder>) {
    let (sink, stream) = socket.split();
    let sink = LoopbackSink::new(sink);
    let mut driver = SessionDriver::new(recorder, sink);
    driver.run_stream(stream).await;
}

/// Per-connection recording state. Owns the local browser session id + the forwarder task handles so
/// they can be aborted on stop/disconnect. Generic over the outbound sink so the SAME driver serves
/// both the loopback `/ws/record` transport and the cloud LinkedAgentBridge transport (each supplies
/// its own [`RecordSink`] impl — one FLAT, one wrapped in the ws-gateway session envelope).
pub struct SessionDriver<S: RecordSink> {
    recorder: Arc<PlaywrightRecorder>,
    sink: S,
    session_id: Option<String>,
    screenshot_task: Option<tokio::task::JoinHandle<()>>,
    event_task: Option<tokio::task::JoinHandle<()>>,
}

impl<S: RecordSink> SessionDriver<S> {
    pub fn new(recorder: Arc<PlaywrightRecorder>, sink: S) -> Self {
        Self {
            recorder,
            sink,
            session_id: None,
            screenshot_task: None,
            event_task: None,
        }
    }

    /// Loopback path — read one WS at a time, dispatch each text frame via [`Self::handle_frame`].
    /// Kept here so the loopback transport stays a thin `split → loop → handle_frame` shim; the
    /// cloud bridge does its own read loop (frames arrive multiplexed from the ws-gateway) and just
    /// calls `handle_frame` per inbound wrapped message.
    async fn run_stream(&mut self, mut stream: SplitStream<WebSocket>) {
        tracing::info!("local recording WS connected");

        while let Some(frame) = stream.next().await {
            let text = match frame {
                Ok(Message::Text(t)) => t,
                Ok(Message::Binary(_)) => continue,
                Ok(Message::Ping(_)) => {
                    // axum auto-replies to control pings; nothing to do.
                    continue;
                }
                Ok(Message::Pong(_)) => continue,
                Ok(Message::Close(_)) => break,
                Err(e) => {
                    tracing::debug!(error = %e, "local recording WS receive error");
                    break;
                }
            };

            let msg: Value = match serde_json::from_str(&text) {
                Ok(v) => v,
                Err(e) => {
                    self.sink
                        .send_json(json!({"type": "error", "message": format!("Invalid JSON: {e}")}))
                        .await;
                    continue;
                }
            };
            self.handle_frame(msg).await;
        }

        // Disconnect cleanup — abort forwarders, end any live browser session.
        self.shutdown().await;
        tracing::info!("local recording WS disconnected");
    }

    /// Dispatch ONE inbound recorder-protocol frame. Public so external transports (the cloud
    /// LinkedAgentBridge multiplexed record path) can feed frames one-at-a-time without owning a
    /// WS. `msg` is the FLAT recorder frame (`{type: "start"|"action"|…, …}`), NOT the ws-gateway
    /// `{channel:"session", session_id, msg}` envelope (the caller unwraps that first).
    pub async fn handle_frame(&mut self, msg: Value) {
        let msg_type = msg.get("type").and_then(|v| v.as_str()).unwrap_or("");
        match msg_type {
            "start" => self.handle_start(&msg).await,
            "action" if self.session_id.is_some() => self.handle_action(&msg).await,
            "agent_action" if self.session_id.is_some() => self.handle_agent_action(&msg).await,
            "replay_steps" if self.session_id.is_some() => self.handle_replay_steps(&msg).await,
            "replay_cancel" if self.session_id.is_some() => self.handle_replay_cancel().await,
            "stop" if self.session_id.is_some() => {
                self.handle_stop().await;
                // A cloud bridge / loopback UI may reuse the transport (a fresh `start` reopens
                // a session on this driver); the outer loop keeps reading.
            }
            "ping" => {
                self.sink.send_json(json!({"type": "pong"})).await;
            }
            _ => tracing::debug!(msg_type, "recording driver: unknown / out-of-state message"),
        }
    }

    /// Explicit teardown for transports that don't have a "stream ended" moment (e.g. the cloud
    /// bridge dispatcher, when it receives a `session_close` from the ws-gateway). Idempotent —
    /// aborts forwarders and ends any live browser session; a second call is a no-op.
    pub async fn shutdown(&mut self) {
        self.abort_forwarders();
        if let Some(sid) = self.session_id.take() {
            tracing::info!(session_id = %sid, "recording driver shutdown — ending browser session");
            let _ = self.recorder.end_session(&sid).await;
        }
    }

    /// `start` — open a recording session on the shared warm browser, wire screencast + event
    /// forwarders, attach live API capture (unless disabled), and confirm with a `started` frame.
    async fn handle_start(&mut self, msg: &Value) {
        if self.session_id.is_some() {
            self.sink
                .send_json(json!({"type": "error", "message": "A recording session is already active"}))
                .await;
            return;
        }

        let url = msg.get("url").and_then(|v| v.as_str()).unwrap_or("about:blank").to_string();
        if url.is_empty() {
            self.sink.send_json(json!({"type": "error", "message": "URL required"})).await;
            return;
        }
        let record_wait = msg
            .get("options")
            .and_then(|o| o.get("record_wait_steps"))
            .and_then(|v| v.as_bool())
            .unwrap_or(true);
        let capture_api = msg
            .get("options")
            .and_then(|o| o.get("capture_api"))
            .and_then(|v| v.as_bool())
            .unwrap_or(true);

        tracing::info!(%url, "local recording: start");

        // Single-user desktop → no tenant scoping.
        // Coordinator-resolved egress for THIS recording (backend
        // routers/internal.py::recording_authorize -> ws-gateway injects it onto the start
        // frame). Shape matches Playwright's ProxySettings 1:1 — {server, username, password,
        // bypass} — where for platform-residential `username` is an opaque per-session routing
        // token for the relay broker, never the provider's credentials.
        //
        // A malformed dict must NOT silently drop us onto the box's datacenter IP: that is the
        // exact failure this field exists to prevent, and it is invisible from the outside. Warn
        // loudly instead, so a bad payload is diagnosable rather than looking like "residential
        // just doesn't work".
        let egress_proxy = match msg.get("egress_proxy") {
            None | Some(Value::Null) => None,
            Some(v) => match serde_json::from_value::<playwright_rs::protocol::ProxySettings>(
                v.clone(),
            ) {
                Ok(p) => Some(p),
                Err(e) => {
                    tracing::warn!(
                        error = %e,
                        "recording egress: coordinator sent an egress_proxy this agent could not \
                         parse — recording DIRECTLY on this machine's own IP"
                    );
                    None
                }
            },
        };

        // Exit country of that egress, shipped alongside it, so the recorded identity's
        // locale / timezone / Accept-Language agree with the address the session exits
        // from (a US timezone on a foreign residential exit is the contradiction the
        // residential spend exists to avoid). Absent → neutral self-consistent default.
        let egress_country = msg
            .get("egress_country")
            .and_then(|v| v.as_str())
            .filter(|s| !s.is_empty())
            .map(|s| s.to_string());

        let sid = match self
            .recorder
            .start_session_with_egress(
                url.clone(),
                record_wait,
                None,
                egress_proxy,
                egress_country,
            )
            .await
        {
            Ok(sid) => sid,
            Err(e) => {
                self.sink.send_json(json!({"type": "error", "message": e.to_string()})).await;
                return;
            }
        };

        // Forward screencast frames RAW (no envelope).
        if let Some(session_ref) = self.recorder.get_session_mut(&sid) {
            if let Some(tx) = session_ref.screenshot_tx.as_ref() {
                let mut rx = tx.subscribe();
                let sink = self.sink.clone();
                self.screenshot_task = Some(tokio::spawn(async move {
                    loop {
                        match rx.recv().await {
                            Ok(frame) => {
                                if !sink.send_binary(frame).await {
                                    break;
                                }
                            }
                            Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
                            Err(tokio::sync::broadcast::error::RecvError::Lagged(n)) => {
                                tracing::debug!(lagged = n, "screencast subscriber lagged");
                            }
                        }
                    }
                }));
            }
        }

        // Forward recorder JSON events (step_recorded, navigation, select_options, twofa_detected, …).
        if let Some(mut event_rx) = self.recorder.take_event_rx(&sid) {
            let sink = self.sink.clone();
            self.event_task = Some(tokio::spawn(async move {
                while let Some(event) = event_rx.recv().await {
                    if !sink.send_json(event).await {
                        break;
                    }
                }
            }));
        }

        // Attach live API capture AFTER the event forwarder is running so `api_captured`/`page_no_api`
        // events have a path to the UI. Clone the context/sender/capture out under a brief lock, then
        // register listeners unlocked (never hold a DashMap RefMut across an `.await`).
        if capture_api {
            let handles = self
                .recorder
                .get_session_mut(&sid)
                .map(|s| (s.context.clone(), s.event_tx.clone(), s.network_capture.clone()));
            if let Some((context, Some(ev_tx), cap)) = handles {
                attach_recording_network_capture(&context, cap, ev_tx).await;
                tracing::debug!(session_id = %sid, "live API capture attached");
            }
        }

        let actual_url = self
            .recorder
            .get_session_mut(&sid)
            .map(|s| s.current_url.clone())
            .unwrap_or(url);

        self.session_id = Some(sid.clone());
        self.sink
            .send_json(json!({"type": "started", "sessionId": sid, "url": actual_url}))
            .await;
        tracing::info!(session_id = %sid, "local recording session started");
    }

    /// `action` — dispatch a recorded interaction to the recorder, then surface any
    /// eval/picker/overlay results the action produced (parity with the cloud session loop).
    async fn handle_action(&mut self, msg: &Value) {
        let sid = match self.session_id.as_ref() {
            Some(s) => s.clone(),
            None => return,
        };

        // The UI sends a FLAT frame: {type:"action", action:"click", x:.., y:..}. Build an
        // IncomingAction from the `action` string + the whole frame as data.
        let action_type = msg.get("action").and_then(|v| v.as_str()).unwrap_or("");
        if action_type.is_empty() {
            tracing::warn!("action frame missing 'action' field");
            return;
        }
        let data: HashMap<String, Value> = serde_json::from_value(msg.clone()).unwrap_or_default();
        let action = IncomingAction { action_type: action_type.to_string(), data };

        // Async acquire: this runs ON the record WebSocket read loop, and the guard
        // is then held across every await of the action (page I/O included). A
        // blocking acquire here would park the reader's worker thread; combined
        // with a Playwright event handler blocking on the same shard, that is the
        // circular wait that froze the recorder on navigation. See
        // `recorder::session_lock`.
        let result = if let Some(mut session_ref) = self.recorder.get_session_mut_async(&sid).await {
            handle_action(session_ref.value_mut(), action).await
        } else {
            ActionResult::err("Session not found")
        };

        if let Some(ref err) = result.error {
            self.sink.send_json(json!({"type": "error", "message": err})).await;
        }
        if let Some(ref data) = result.data {
            // Script-test eval result.
            if data.get("eval_result").is_some() {
                self.sink
                    .send_json(json!({
                        "type": "eval_result",
                        "result": data.get("eval_result"),
                        "error": data.get("error"),
                    }))
                    .await;
            }
            // Live element picker (check wizard).
            if let Some(info) = data.get("element_info").and_then(|v| v.as_object()) {
                let mut frame = serde_json::Map::new();
                frame.insert("type".into(), json!("element_info"));
                for (k, v) in info {
                    frame.insert(k.clone(), v.clone());
                }
                self.sink.send_json(Value::Object(frame)).await;
            }
            if let Some(elements) = data.get("elements_in_region") {
                self.sink
                    .send_json(json!({"type": "elements_in_region", "elements": elements}))
                    .await;
            }
            if let Some(html) = data.get("dom_content") {
                let html = if html.is_null() { json!("") } else { html.clone() };
                self.sink.send_json(json!({"type": "dom_content", "html": html})).await;
            }
            // Payloads that are already a complete UI frame (select/picker overlays,
            // the extraction highlight box, a live extract test result) → forward
            // verbatim. One shared allowlist with the cloud bridge so neither
            // transport can silently lack a frame the other forwards.
            if let Some(dtype) = data.get("type").and_then(|v| v.as_str()) {
                if crate::recorder::action_handler::is_passthrough_frame(dtype) {
                    self.sink.send_json(data.clone()).await;
                }
            }
        }
    }

    /// `agent_action` — ephemeral AI-assist actions: run the AI's chosen browser action(s) on the
    /// LIVE page WITHOUT recording steps, then return a fresh observation for the next turn. The
    /// DECISION loop runs locally (`POST /v1/ai-assist/agent` on the user's own provider); this is
    /// only the EXECUTION half. It reuses the cloud recorder's `run_agent_actions` so the
    /// action/observation contract the local brain consumes matches exactly — `read_only = false`
    /// is the interactive scraper-builder path (full raw JS for complex scrape scripts).
    async fn handle_agent_action(&mut self, msg: &Value) {
        let request_id = msg.get("request_id").cloned().unwrap_or(Value::Null);
        let session_id = self.session_id.clone().unwrap_or_default();

        // Clone the page out under a BRIEF lock — never hold the DashMap guard across the
        // executor's `.await`s (same rule as handle_replay_steps).
        let page = self
            .session_id
            .clone()
            .and_then(|sid| self.recorder.get_session_mut(&sid).map(|s| s.page.clone()));

        let response = match page {
            Some(page) => {
                let (results, observation) =
                    crate::automation::run_agent_actions(&page, msg, false).await;
                json!({
                    "type": "agent_action_result",
                    "request_id": request_id,
                    "session_id": session_id,
                    "results": results,
                    "observation": observation,
                })
            }
            None => json!({
                "type": "agent_action_result",
                "request_id": request_id,
                "session_id": session_id,
                "results": [],
                "observation": Value::Null,
                "error": "Session not found",
            }),
        };
        self.sink.send_json(response).await;
    }

    /// `replay_steps` — "play to here": re-run recorded steps `0..=up_to_index` on the LIVE page,
    /// streaming `replay_progress` frames and a final `replay_done`. Runs in a spawned task so a
    /// concurrent `replay_cancel` can interrupt it (the read loop keeps reading while it runs).
    async fn handle_replay_steps(&mut self, msg: &Value) {
        let sid = match self.session_id.as_ref() {
            Some(s) => s.clone(),
            None => return,
        };
        let request_id = msg.get("request_id").cloned().unwrap_or(Value::Null);

        // Clone the page + cancel flag under a brief lock; drop the DashMap guard before the
        // spawn/await (never hold it across `.await`).
        let pc = self.recorder.get_session_mut(&sid).map(|s| {
            s.replay_cancel.store(false, std::sync::atomic::Ordering::Relaxed);
            (s.page.clone(), s.replay_cancel.clone())
        });
        let (page, cancel) = match pc {
            Some(pc) => pc,
            None => {
                self.sink
                    .send_json(json!({"type": "replay_error", "request_id": request_id, "error": "No active session"}))
                    .await;
                return;
            }
        };

        let steps = msg.get("steps").and_then(|v| v.as_array()).cloned().unwrap_or_default();
        let up_to = msg.get("up_to_index").and_then(|v| v.as_i64()).unwrap_or(0);
        let delay_ms = msg.get("step_delay_ms").and_then(|v| v.as_u64()).unwrap_or(300);
        let sink = self.sink.clone();
        tokio::spawn(async move {
            run_replay(sink, page, cancel, steps, up_to, delay_ms, request_id).await;
        });
    }

    /// `replay_cancel` — cooperative cancel for an in-flight visual replay.
    async fn handle_replay_cancel(&mut self) {
        if let Some(sid) = self.session_id.as_ref() {
            if let Some(s) = self.recorder.get_session_mut(sid) {
                s.replay_cancel.store(true, std::sync::atomic::Ordering::Relaxed);
            }
        }
    }

    /// `stop` — finalize the session: abort forwarders, end the browser session, return the recorded
    /// steps + raw replay + captured network calls.
    async fn handle_stop(&mut self) {
        let sid = match self.session_id.take() {
            Some(s) => s,
            None => return,
        };
        tracing::info!(session_id = %sid, "local recording: stop");
        self.abort_forwarders();

        match self.recorder.end_session(&sid).await {
            Ok(result) => {
                let steps: Vec<Value> = result
                    .steps
                    .iter()
                    .map(|s| serde_json::to_value(s).unwrap_or(Value::Null))
                    .collect();
                let raw_replay: Vec<Value> = result
                    .raw_replay
                    .iter()
                    .map(|s| serde_json::to_value(s).unwrap_or(Value::Null))
                    .collect();
                let network_calls: Vec<Value> = result
                    .network_calls
                    .iter()
                    .map(|c| serde_json::to_value(c).unwrap_or(Value::Null))
                    .collect();
                self.sink
                    .send_json(json!({
                        "type": "stopped",
                        "steps": steps,
                        "stepCount": result.step_count,
                        "raw_replay": raw_replay,
                        "rawReplayCount": result.raw_replay_count,
                        "network_calls": network_calls,
                        "network_calls_count": result.network_calls.len(),
                    }))
                    .await;
            }
            Err(e) => {
                self.sink.send_json(json!({"type": "error", "message": e.to_string()})).await;
            }
        }
    }

    fn abort_forwarders(&mut self) {
        if let Some(t) = self.screenshot_task.take() {
            t.abort();
        }
        if let Some(t) = self.event_task.take() {
            t.abort();
        }
    }
}

// ---------------------------------------------------------------------------
// Live API capture (ported for the loopback path — sends FLAT frames)
// ---------------------------------------------------------------------------

/// Attach passive API capture to a recording session's context. Records XHR/fetch + document
/// form-submits into the shared [`NetworkCapture`], streams newly-seen endpoints to the UI as
/// `api_captured`, and flags server-rendered page loads (a GET navigation that triggers no API
/// calls) as `page_no_api`. The listeners hold ONLY `Arc<Mutex<NetworkCapture>>` + the event sender
/// — never `sessions.get_mut()`, so they can't starve the recording path. No lock across `.await`.
pub(crate) async fn attach_recording_network_capture(
    context: &playwright_rs::BrowserContext,
    capture: Arc<tokio::sync::Mutex<NetworkCapture>>,
    event_tx: tokio::sync::mpsc::UnboundedSender<Value>,
) {
    use playwright_rs::server::channel_owner::ChannelOwner;
    use std::collections::HashSet;

    // Request side — record by stable GUID.
    let cap_req = capture.clone();
    let _ = context
        .on_request(move |request: playwright_rs::Request| {
            let cap = cap_req.clone();
            async move {
                let request_id = request.guid().to_string();
                let method = request.method().to_string();
                let url = request.url().to_string();
                let resource_type = request.resource_type().to_string();
                let headers = request.headers();
                let body = request.post_data();
                cap.lock().await.on_request(&request_id, &method, &url, &resource_type, headers, body);
                Ok(())
            }
        })
        .await;

    // Response side — finalize captured calls, emit live events, detect server-rendered pages.
    let cap_resp = capture.clone();
    let seen_endpoints: Arc<tokio::sync::Mutex<HashSet<String>>> =
        Arc::new(tokio::sync::Mutex::new(HashSet::new()));
    let warned_pages: Arc<tokio::sync::Mutex<HashSet<String>>> =
        Arc::new(tokio::sync::Mutex::new(HashSet::new()));
    let _ = context
        .on_response(move |response: playwright_rs::protocol::ResponseObject| {
            let cap = cap_resp.clone();
            let event_tx = event_tx.clone();
            let seen_endpoints = seen_endpoints.clone();
            let warned_pages = warned_pages.clone();
            async move {
                let parent = match response.parent() {
                    Some(p) => p,
                    None => return Ok(()),
                };
                let request_id = parent.guid().to_string();
                let (req_method, is_navigation) =
                    match parent.as_any().downcast_ref::<playwright_rs::Request>() {
                        Some(req) => (req.method().to_string(), req.is_navigation_request()),
                        None => (String::new(), false),
                    };
                let url = response.url().to_string();
                let status = response.status();

                // Server-rendered detection: a top-level GET document navigation that, after a short
                // settle, triggered no NEW captured API calls → the data is baked into the HTML.
                if is_navigation && req_method.eq_ignore_ascii_case("GET") {
                    let before = cap.lock().await.get_all_calls().len();
                    let cap2 = cap.clone();
                    let ev2 = event_tx.clone();
                    let warned = warned_pages.clone();
                    let nav_url = url.clone();
                    tokio::spawn(async move {
                        tokio::time::sleep(std::time::Duration::from_millis(2500)).await;
                        let after = cap2.lock().await.get_all_calls().len();
                        if after == before && warned.lock().await.insert(nav_url.clone()) {
                            let _ = ev2.send(json!({
                                "type": "page_no_api",
                                "url": nav_url,
                                "message": "This page appears server-rendered — its data is in the HTML, so there is no API to capture here.",
                            }));
                        }
                    });
                    return Ok(());
                }

                // API responses only — skip assets entirely (no body download).
                if !cap.lock().await.has_pending(&request_id) {
                    return Ok(());
                }

                let headers: HashMap<String, String> = match response.raw_headers().await {
                    Ok(entries) => entries.into_iter().map(|e| (e.name, e.value)).collect(),
                    Err(_) => HashMap::new(),
                };
                let content_type = headers
                    .iter()
                    .find(|(k, _)| k.eq_ignore_ascii_case("content-type"))
                    .map(|(_, v)| v.to_lowercase());
                let want_body = content_type
                    .as_deref()
                    .map(|ct| ["json", "text", "xml", "html", "form"].iter().any(|t| ct.contains(t)))
                    .unwrap_or(false);
                let body: Option<String> = if want_body {
                    match response.body().await {
                        Ok(b) => String::from_utf8(b).ok(),
                        Err(_) => None,
                    }
                } else {
                    None
                };

                let finalized = cap.lock().await.on_response(&request_id, status, headers, body);
                if let Some(call) = finalized {
                    let key = format!("{} {}", call.method, call.url);
                    if seen_endpoints.lock().await.insert(key) {
                        let _ = event_tx.send(json!({
                            "type": "api_captured",
                            "call": serde_json::to_value(&call).unwrap_or(Value::Null),
                        }));
                    }
                }
                Ok(())
            }
        })
        .await;
}

// ---------------------------------------------------------------------------
// Visual replay ("play to here") — ported for the loopback path
// ---------------------------------------------------------------------------

/// Replay recorded steps `0..=up_to_index` on the live page, streaming a `replay_progress` frame per
/// step and a final `replay_done`. A concurrent `replay_cancel` (via `cancel`) stops it between
/// steps. Mirrors the cloud `run_replay_steps`.
async fn run_replay<S: RecordSink>(
    sink: S,
    page: playwright_rs::Page,
    cancel: Arc<std::sync::atomic::AtomicBool>,
    steps: Vec<Value>,
    up_to_index: i64,
    step_delay_ms: u64,
    request_id: Value,
) {
    use std::sync::atomic::Ordering;

    let n = steps.len() as i64;
    let target = if n == 0 { -1 } else { up_to_index.clamp(0, n - 1) };
    if target < 0 {
        sink.send_json(json!({
            "type": "replay_done", "request_id": request_id,
            "replayed": 0, "skipped": 0, "failed": 0, "cancelled": false,
            "stopped_at": Value::Null, "url": page.url(),
        }))
        .await;
        return;
    }

    let delay_ms = step_delay_ms.min(3000);
    let total = target + 1;
    let (mut replayed, mut skipped, mut failed) = (0i64, 0i64, 0i64);
    let mut cancelled = false;

    for i in 0..total {
        if cancel.load(Ordering::Relaxed) {
            cancelled = true;
            sink.send_json(json!({
                "type": "replay_progress", "request_id": request_id,
                "index": i, "status": "cancelled", "total": total,
            }))
            .await;
            break;
        }
        let step = &steps[i as usize];
        if step.get("enabled") == Some(&Value::Bool(false)) {
            skipped += 1;
            sink.send_json(json!({
                "type": "replay_progress", "request_id": request_id,
                "index": i, "status": "skipped", "reason": "disabled", "total": total,
            }))
            .await;
            continue;
        }
        sink.send_json(json!({
            "type": "replay_progress", "request_id": request_id,
            "index": i, "status": "running", "total": total,
        }))
        .await;
        let (status, reason) = match tokio::time::timeout(
            std::time::Duration::from_secs(50),
            replay_one_recorded_step(&page, step),
        )
        .await
        {
            Ok(t) => t,
            Err(_) => ("failed", Some("timed out".to_string())),
        };
        match status {
            "done" => replayed += 1,
            "skipped" => skipped += 1,
            _ => failed += 1,
        }
        sink.send_json(json!({
            "type": "replay_progress", "request_id": request_id,
            "index": i, "status": status, "reason": reason, "total": total,
        }))
        .await;
        if delay_ms > 0 && i < target {
            tokio::time::sleep(std::time::Duration::from_millis(delay_ms)).await;
        }
    }

    sink.send_json(json!({
        "type": "replay_done", "request_id": request_id,
        "replayed": replayed, "skipped": skipped, "failed": failed,
        "cancelled": cancelled, "stopped_at": target, "url": page.url(),
    }))
    .await;
}

/// Recorded-step types we deliberately DON'T re-run on the live page during a visual replay: they
/// need a real run context (server-minted 2FA / secrets), have side effects outside the browser
/// (HTTP/file), are pure data reads that don't move the cursor, or are tab-orchestration markers
/// that don't replay cleanly in a single-page recording session. Mirrors the cloud recorder.
fn replay_skippable(step_type: &str) -> bool {
    matches!(
        step_type,
        "twofa"
            | "api_call"
            | "upload"
            | "wait_for_download"
            | "screenshot"
            | "return"
            | "end_point"
            | "codegen"
            | "open_tab"
            | "switch_tab"
            | "tab_closed"
            | "wait_for_tab"
            | "evaluate"
            | "extract"
    )
}

/// Bounded post-action settle so replay re-establishes position without hanging on a busy page.
/// Mirrors the cloud `settle_page` (uses the shared `navigation::wait_for_load_state`).
async fn settle_page(page: &playwright_rs::Page, navigated: bool) {
    use std::time::Duration;
    if navigated {
        let _ = tokio::time::timeout(
            Duration::from_secs(8),
            crate::browser::navigation::wait_for_load_state(page, "domcontentloaded", Duration::from_secs(8)),
        )
        .await;
    }
    // networkidle can stall on long-poll/streaming pages, so keep it short and treat a timeout as
    // "settled enough".
    let _ = tokio::time::timeout(
        Duration::from_millis(2500),
        crate::browser::navigation::wait_for_load_state(page, "networkidle", Duration::from_millis(2500)),
    )
    .await;
}

/// Best-effort execute ONE recorded step on the live page. Returns `(status, reason)` where status
/// is `"done" | "skipped" | "failed"`. Never panics — a failure is captured so replay keeps going.
/// Mirrors the cloud `replay_one_recorded_step`.
async fn replay_one_recorded_step(page: &playwright_rs::Page, step: &Value) -> (&'static str, Option<String>) {
    use crate::browser::{navigation, page_actions};
    use std::time::Duration;

    let stype = step.get("type").and_then(|v| v.as_str()).unwrap_or("").trim();
    let selector = step.get("selector").and_then(|v| v.as_str()).unwrap_or("");
    let value = step.get("value").and_then(|v| v.as_str());
    let options = step.get("options");

    if stype.is_empty() || replay_skippable(stype) {
        let label = if stype.is_empty() { "unknown" } else { stype };
        return ("skipped", Some(format!("{label} not replayable here")));
    }

    let is_template = |v: Option<&str>| v.is_some_and(|s| s.contains("{{") && s.contains("}}"));
    let opt_bool =
        |k: &str| options.and_then(|o| o.get(k)).and_then(|v| v.as_bool()).unwrap_or(false);

    let res: anyhow::Result<(&'static str, Option<String>)> = async {
        match stype {
            "navigate" | "navigated_to" => {
                let url = step.get("url").and_then(|v| v.as_str()).or(value);
                let url = match url {
                    Some(u) if !u.is_empty() => u,
                    _ => return Ok(("skipped", Some("no url".to_string()))),
                };
                if !crate::security::url_guard::is_url_safe(url) {
                    return Ok(("failed", Some("blocked: unsafe/internal URL".to_string())));
                }
                navigation::goto(page, url, "domcontentloaded", Duration::from_secs(30)).await?;
                settle_page(page, true).await;
                Ok(("done", None))
            }
            "click" => {
                if !selector.is_empty() {
                    page_actions::click_selector(page, selector, false).await?;
                } else if let Some(c) = step.get("coordinates") {
                    let x = c.get("x").and_then(|v| v.as_f64()).unwrap_or(0.0);
                    let y = c.get("y").and_then(|v| v.as_f64()).unwrap_or(0.0);
                    page_actions::mouse_click(page, x, y, "left").await?;
                } else {
                    return Ok(("skipped", Some("no selector".to_string())));
                }
                settle_page(page, true).await;
                Ok(("done", None))
            }
            "fill" | "type" => {
                if selector.is_empty() {
                    return Ok(("skipped", Some("no selector".to_string())));
                }
                if is_template(value) || opt_bool("is_sensitive") {
                    return Ok(("skipped", Some("needs runtime value".to_string())));
                }
                page_actions::fill(page, selector, value.unwrap_or("")).await?;
                Ok(("done", None))
            }
            "press" => {
                let key = value
                    .filter(|s| !s.is_empty())
                    .or_else(|| options.and_then(|o| o.get("key")).and_then(|v| v.as_str()))
                    .unwrap_or("Enter");
                page_actions::keyboard_press(page, key).await?;
                settle_page(page, true).await;
                Ok(("done", None))
            }
            "select" => {
                if selector.is_empty() {
                    return Ok(("skipped", Some("no selector".to_string())));
                }
                page_actions::select_option(page, selector, value.unwrap_or("")).await?;
                Ok(("done", None))
            }
            "check" | "uncheck" => {
                if selector.is_empty() {
                    return Ok(("skipped", Some("no selector".to_string())));
                }
                if stype == "check" {
                    page_actions::check(page, selector).await?;
                } else {
                    page_actions::uncheck(page, selector).await?;
                }
                Ok(("done", None))
            }
            "hover" => {
                if selector.is_empty() {
                    return Ok(("skipped", Some("no selector".to_string())));
                }
                page_actions::hover(page, selector).await?;
                Ok(("done", None))
            }
            "scroll" | "scroll_into_view" | "scroll-container" => {
                if stype == "scroll_into_view" && !selector.is_empty() {
                    let _ = page_actions::scroll_into_view(page, selector).await;
                } else {
                    let dy = options
                        .and_then(|o| o.get("deltaY").or_else(|| o.get("amount")))
                        .and_then(|v| v.as_f64())
                        .unwrap_or(600.0);
                    page_actions::mouse_wheel(page, 0.0, dy).await?;
                }
                Ok(("done", None))
            }
            "wait" => {
                let secs = options
                    .and_then(|o| o.get("duration_ms"))
                    .and_then(|v| v.as_f64())
                    .map(|ms| ms / 1000.0)
                    .or_else(|| value.and_then(|s| s.parse::<f64>().ok()))
                    .unwrap_or(1.0)
                    .clamp(0.0, 10.0);
                tokio::time::sleep(Duration::from_secs_f64(secs)).await;
                Ok(("done", None))
            }
            "wait_for_change" => {
                settle_page(page, false).await;
                Ok(("done", None))
            }
            other => Ok(("skipped", Some(format!("{other} not replayable here")))),
        }
    }
    .await;

    match res {
        Ok(t) => t,
        Err(e) => {
            let msg: String = e.to_string().chars().take(200).collect();
            ("failed", Some(msg))
        }
    }
}

#[cfg(test)]
mod session_tests {
    use super::*;

    #[test]
    fn replay_skips_non_replayable_step_types() {
        // Side-effecting / run-context-only / tab-orchestration / pure-read steps are skipped.
        for t in [
            "twofa", "api_call", "upload", "wait_for_download", "screenshot", "return", "end_point",
            "codegen", "open_tab", "switch_tab", "tab_closed", "wait_for_tab", "evaluate", "extract",
        ] {
            assert!(replay_skippable(t), "{t} should be skippable");
        }
        // Page interactions are replayable.
        for t in ["click", "fill", "type", "press", "select", "check", "hover", "scroll", "navigate", "wait"] {
            assert!(!replay_skippable(t), "{t} should be replayable");
        }
    }
}
