use std::collections::HashMap;
use std::sync::Arc;

use futures_util::{SinkExt, StreamExt};
use tokio::sync::{mpsc, Mutex, RwLock};
use tokio::task::JoinHandle;
use tokio_tungstenite::tungstenite::Message;

use super::auth;
use super::session_relay::{
    shed_backlog, AgentSessionRelay, BridgeOutgoing, ProbeAction, ShedOutcome, WsLiveness,
};
// The twofa step + the wire `execute_workflow` executor live in the shared `wire_exec` module
// (the fleet bridge runs the same code); this bridge keeps thin transport shims.
use crate::browser::manager::BrowserManager;
use crate::cli::setup::AgentConfig;
use crate::recorder::core::PlaywrightRecorder;
use playwright_rs::server::channel_owner::ChannelOwner;

type WsStream = tokio_tungstenite::WebSocketStream<
    tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>,
>;

/// Char-safe truncation for logging wire-derived strings (session ids, response
/// bodies, etc). A byte slice like `&s[..8]` PANICS if byte 8 falls in the middle
/// of a multibyte UTF-8 sequence — a malicious gateway could crash the agent by
/// returning such an id. Truncating on char boundaries is panic-free.
fn truncate_str(s: &str, max_chars: usize) -> String {
    s.chars().take(max_chars).collect()
}

// --- transport limits (mirrors `fleet_bridge`; the two bridges are feature-exclusive) ------------
//
// Sizing: the largest legitimate inbound frames are full wire workflow definitions (steps +
// credentials + a sealed `session_state` of gzipped cookies/localStorage) and monitoring
// `assign_targets` pushes. 8 MiB is ~10× the worst observed frame while bounding the JSON-expansion
// blast radius to ~160 MB instead of 1.3 GB.
const WS_MAX_MESSAGE_SIZE: usize = 8 * 1024 * 1024;
const WS_MAX_FRAME_SIZE: usize = 2 * 1024 * 1024;
/// Cap on tungstenite's own write buffer (default `usize::MAX`). Must exceed the largest frame we
/// SEND — screencast/screenshot frames are the big ones — hence generous but finite.
const WS_MAX_WRITE_BUFFER: usize = 32 * 1024 * 1024;

// --- read-loop liveness ----------------------------------------------------
/// No inbound frame for this long → send a client-initiated `Ping`.
const READ_IDLE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(60);
/// A probe unanswered for this long means the path is gone (half-open flow) → reconnect.
const PONG_GRACE: std::time::Duration = std::time::Duration::from_secs(15);
/// A single WS write that cannot complete in this long means the peer's receive window is shut.
const WRITE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

// --- outgoing queue bounds (see `session_relay::shed_backlog`) -------------
/// Above this many queued outgoing frames we run a shed pass (screencast dropped, control kept).
const OUTGOING_SOFT_CAP: usize = 256;
/// Control frames alone above this = the peer stopped reading → drop the session instead of growing.
const OUTGOING_HARD_CAP: usize = 4096;

pub struct SaaSBridge {
    config: AgentConfig,
    service_mode: bool,
    // Arc so the autonomous monitor loop can read the assigned agent_id too.
    agent_id: Arc<RwLock<Option<String>>>,
    tenant_id: RwLock<Option<String>>,
    connected: std::sync::atomic::AtomicBool,
    running: std::sync::atomic::AtomicBool,
    reconnect_delay: Mutex<f64>,
    max_sessions: usize,
    recorder: Arc<PlaywrightRecorder>,

    // Startup CPU speed profile — computed ONCE in new() and cached, reused in
    // both /connect and every heartbeat so the backend can rank/route by
    // single-core speed and refresh on VM resize. Best-effort; never blocks.
    speed_profile: super::speed_profile::SpeedProfile,

    // Outgoing channel — session relays and internal code push messages here
    outgoing_tx: mpsc::UnboundedSender<BridgeOutgoing>,
    outgoing_rx: Mutex<Option<mpsc::UnboundedReceiver<BridgeOutgoing>>>,

    // Active session relays
    active_relays: Arc<dashmap::DashMap<String, Arc<AgentSessionRelay>>>,

    // AI completion pending futures
    ai_pending: Arc<dashmap::DashMap<String, tokio::sync::oneshot::Sender<serde_json::Value>>>,

    // Backend-orchestrated AI sessions: relay session_id -> browser session_id,
    // so ai_session_close can drive teardown + harvest auth_session directly.
    ai_session_browser_map: Arc<dashmap::DashMap<String, String>>,

    // Scheduled, parallel target-monitoring subsystem (runs alongside the
    // recorder bridge; fed by assign_targets/target_sync/assign_workflows).
    monitor: Arc<crate::monitor::MonitorState>,

    // True once the first gateway connection has succeeded, so later cycles print
    // "Reconnected" instead of the first-connect banner. (Replaces never-incremented
    // task counters whose is_reconnect derivation was always false.)
    has_connected: std::sync::atomic::AtomicBool,
}

impl SaaSBridge {
    pub fn new(config: AgentConfig, service_mode: bool, recorder: Arc<PlaywrightRecorder>) -> Self {
        let max_sessions = config.recorder.max_sessions as usize;
        let (outgoing_tx, outgoing_rx) = mpsc::unbounded_channel();
        // Profile host capacity once; advertised on connect, drives parallelism.
        let capacity = crate::monitor::capacity::CapacityReport::profile(60_000);
        let monitor = Arc::new(crate::monitor::MonitorState::new(capacity));
        Self {
            config,
            service_mode,
            agent_id: Arc::new(RwLock::new(None)),
            tenant_id: RwLock::new(None),
            connected: std::sync::atomic::AtomicBool::new(false),
            running: std::sync::atomic::AtomicBool::new(false),
            reconnect_delay: Mutex::new(1.0),
            max_sessions,
            recorder,
            speed_profile: super::speed_profile::SpeedProfile::compute(),
            outgoing_tx,
            outgoing_rx: Mutex::new(Some(outgoing_rx)),
            active_relays: Arc::new(dashmap::DashMap::new()),
            ai_pending: Arc::new(dashmap::DashMap::new()),
            ai_session_browser_map: Arc::new(dashmap::DashMap::new()),
            monitor,
            has_connected: std::sync::atomic::AtomicBool::new(false),
        }
    }

    fn role(&self) -> &str {
        if self.service_mode { "infrastructure" } else { "user-hosted" }
    }

    /// Minimum listen()-time before a session counts as HEALTHY. A clean close inside this window
    /// is treated as a rapid rejection (accept-then-close auth loops) and keeps backing off; a
    /// close after it resets the backoff so the next reconnect is immediate-ish.
    const MIN_HEALTHY_SESSION: std::time::Duration = std::time::Duration::from_secs(5);

    /// Main loop — connect and maintain the connection with auto-reconnect.
    pub async fn run(&self) {
        self.running.store(true, std::sync::atomic::Ordering::Relaxed);

        while self.running.load(std::sync::atomic::Ordering::Relaxed) {
            let started = tokio::time::Instant::now();
            let outcome = self.connect_and_listen().await;
            let session = started.elapsed();

            // Backoff resets only after a session that HELD for a while (not merely a successful
            // connect — a gateway that accepts then instantly closes must keep backing off).
            if session >= Self::MIN_HEALTHY_SESSION {
                *self.reconnect_delay.lock().await = 1.0;
            }

            match outcome {
                // `listen` returned Ok — a clean close. That is TERMINAL only when we were asked
                // to stop: an explicit server `disconnect` frame or `shutdown()` (both flip
                // `self.running` to false before the read loop exits). A bare server-side close
                // (gateway restart/redeploy, idle reap, stream end) leaves `running` true and MUST
                // reconnect — otherwise an unattended agent stays disconnected forever.
                Ok(()) => {
                    if !self.running.load(std::sync::atomic::Ordering::Relaxed) {
                        break; // deliberate disconnect/shutdown
                    }
                    self.connected.store(false, std::sync::atomic::Ordering::Relaxed);
                    tracing::warn!(
                        session_s = session.as_secs(),
                        "Gateway closed the connection — reconnecting"
                    );
                }
                Err(e) => {
                    if !self.running.load(std::sync::atomic::Ordering::Relaxed) {
                        break;
                    }

                    // Definitive revocation — do NOT reconnect. Clear the dead
                    // credentials and tell the user to re-link the machine.
                    if e.downcast_ref::<auth::AuthRevoked>().is_some() {
                        self.connected.store(false, std::sync::atomic::Ordering::Relaxed);
                        self.running.store(false, std::sync::atomic::Ordering::Relaxed);
                        auth::clear_credentials();
                        println!("\n  \x1b[31m✗ This agent has been disconnected from your account.\x1b[0m");
                        println!("    Run 'writ-agent login' to re-link this machine, then 'writ-agent start'.\n");
                        tracing::error!(error = %e, "Auth revoked, stopping agent");
                        break;
                    }

                    self.connected.store(false, std::sync::atomic::Ordering::Relaxed);

                    let delay = self.next_reconnect_delay().await;
                    println!("\n  ⚠ Connection lost: {}. Reconnecting in {:.0}s...", e, delay);
                    tracing::warn!(error = %e, delay_s = delay, "Connection lost, reconnecting");
                    tokio::time::sleep(std::time::Duration::from_secs_f64(delay)).await;
                    continue;
                }
            }

            // Clean-close reconnect path (Ok above): same jittered backoff as the error path.
            let delay = self.next_reconnect_delay().await;
            println!("\n  ⚠ Connection closed by server. Reconnecting in {:.0}s...", delay);
            tokio::time::sleep(std::time::Duration::from_secs_f64(delay)).await;
        }
    }

    /// Compute the next FULL-JITTER backoff sleep (thundering-herd guard): sleep a RANDOM fraction
    /// of the current ceiling so a gateway restart doesn't make every agent reconnect at the same
    /// instant. The ceiling grows ×2 per cycle (capped 30s); the randomness is on the actual sleep,
    /// not just the next ceiling. subsec_nanos ∈ [0, 1e9) → divide by 1e9 for a [0,1) fraction —
    /// agents detect disconnect at slightly different instants, so the nanosecond is enough entropy
    /// to de-correlate their reconnects.
    async fn next_reconnect_delay(&self) -> f64 {
        let mut d = self.reconnect_delay.lock().await;
        let ceiling = *d;
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .subsec_nanos() as f64;
        let rand01 = nanos / 1_000_000_000.0;
        *d = (ceiling * 2.0).min(30.0);
        (ceiling * rand01).max(0.1)
    }

    /// Single connect + listen cycle. (The backoff reset lives in `run` and is keyed on session
    /// LENGTH, not on a successful connect — see MIN_HEALTHY_SESSION.)
    async fn connect_and_listen(&self) -> Result<(), anyhow::Error> {
        let ws = self.connect().await?;
        self.listen(ws).await
    }

    /// Two-step connection flow (exact port of Python SaaSBridge._connect):
    /// 1. POST /api/recorder/connect → get gateway URL + short-lived JWT
    /// 2. WS to gateway with the JWT → register as recorder agent
    async fn connect(&self) -> Result<WsStream, anyhow::Error> {
        // Get auth token based on mode
        let token = if self.service_mode {
            auth::get_service_token()
                .ok_or_else(|| anyhow::anyhow!("WRIT_SERVICE_TOKEN not set"))?
        } else {
            // Refresh if expired. A revoked/expired refresh token surfaces as
            // AuthRevoked so run() stops instead of looping forever.
            match auth::get_valid_token().await {
                Ok(Some(t)) => t,
                Ok(None) => return Err(anyhow::anyhow!("Not logged in — run: writ-agent login")),
                Err(revoked) => return Err(anyhow::Error::new(revoked)),
            }
        };

        let saas_url = self.config.saas.url.trim_end_matches('/');
        // wss-only outside local dev: the step-1 /connect call carries the agent's
        // long-lived auth token as a Bearer header, so a plaintext saas.url would
        // leak it. Refuse it unless loopback or an explicit allow_insecure opt-in.
        let allow_insecure = self.config.saas.allow_insecure;
        require_secure_url(saas_url, allow_insecure, "saas")?;

        let is_reconnect = self.has_connected.load(std::sync::atomic::Ordering::Relaxed);

        if !is_reconnect {
            println!("  Discovering gateway...");
        }
        tracing::info!(url = %saas_url, "Discovering gateway");

        // Load stored agent identity BEFORE /connect so we can send it — the
        // backend bakes it into the gateway JWT and the ws-gateway honors the SAME
        // agent_id across restarts. Without this the agent gets a fresh random id
        // each connect, orphaning warm-session affinity (keyed by agent_id) → the
        // workflow logs in fresh every restart even with warm sessions enabled.
        let creds = auth::load_credentials().unwrap_or(serde_json::json!({}));
        let stored_agent_id = creds["agent_id"].as_str().unwrap_or("").to_string();
        {
            let mut tid = self.tenant_id.write().await;
            *tid = creds["tenant_id"].as_str().map(String::from);
        }

        // Step 1: POST /api/recorder/connect → get gateway assignment
        let client = reqwest::Client::new();
        let mut connect_body = serde_json::json!({
            "max_sessions": self.max_sessions,
            "captcha_trusted": false,
            "agent_id": stored_agent_id,
            // Monitoring capability: advertise capacity + check modes so the
            // backend distributor can assign target time-slots to this recorder.
            "capacity": self.monitor.capacity.to_json(),
            "check_modes": ["content", "uptime", "playwright"],
        });
        if let Some(obj) = connect_body.as_object_mut() {
            self.speed_profile.inject_into(obj);
        }
        let resp = client
            .post(format!("{}/api/recorder/connect", saas_url))
            .header("Authorization", format!("Bearer {}", token))
            .json(&connect_body)
            .timeout(std::time::Duration::from_secs(15))
            .send()
            .await?;

        if !resp.status().is_success() {
            let status = resp.status();
            // 401/403 = token rejected: this agent was disconnected/revoked from
            // the dashboard. Stop retrying and prompt re-login (handled in run()).
            if !self.service_mode && (status.as_u16() == 401 || status.as_u16() == 403) {
                return Err(anyhow::Error::new(auth::AuthRevoked(format!(
                    "agent token rejected ({}) by /connect",
                    status.as_u16()
                ))));
            }
            let body = resp.text().await.unwrap_or_default();
            return Err(anyhow::anyhow!(
                "Gateway discovery failed ({}): {}",
                status,
                truncate_str(&body, 200)
            ));
        }

        let connect_data: serde_json::Value = resp.json().await?;
        let gateway_ws_url = connect_data["gateway_ws_url"]
            .as_str()
            .ok_or_else(|| anyhow::anyhow!("Missing gateway_ws_url in response"))?;
        let gateway_token = connect_data["gateway_token"]
            .as_str()
            .ok_or_else(|| anyhow::anyhow!("Missing gateway_token in response"))?;

        // wss-only outside local dev: never open the persistent gateway WS over
        // plaintext. The gateway URL is backend-supplied, but a proxy misconfig
        // (missing x-forwarded-proto) or a bad WS_GATEWAY_PUBLIC_URL can hand back
        // ws://; connecting anyway would expose the gateway JWT + every session
        // frame. Fail closed unless loopback or an explicit allow_insecure opt-in.
        require_secure_url(gateway_ws_url, allow_insecure, "gateway")?;

        // (agent identity + tenant already loaded above, before /connect)

        // Build connection URL — the gateway JWT is sent in the Authorization
        // header (below), NOT the query string, so it never lands in proxy/access
        // logs. The remaining params are non-secret routing/capability hints;
        // identity is derived gateway-side from the verified JWT claims.
        let separator = if gateway_ws_url.contains('?') { "&" } else { "?" };
        let mut full_url = format!(
            "{}{}role=recorder&max_sessions={}",
            gateway_ws_url,
            separator,
            self.max_sessions,
        );
        if !stored_agent_id.is_empty() {
            full_url.push_str(&format!("&agent_id={}", urlencoding(&stored_agent_id)));
        }

        if !is_reconnect {
            println!("  Connecting to gateway...");
        }
        tracing::info!(url = %gateway_ws_url, "Connecting to gateway");

        // Step 2: WebSocket connect — gateway JWT in the Authorization header so it
        // stays out of URLs/logs. The gateway accepts Bearer (recorder-auth.ts).
        use tokio_tungstenite::tungstenite::client::IntoClientRequest;
        use tokio_tungstenite::tungstenite::http::HeaderValue;
        let mut request = full_url
            .as_str()
            .into_client_request()
            .map_err(|e| anyhow::anyhow!("Failed to build gateway WS request: {}", e))?;
        let bearer = HeaderValue::from_str(&format!("Bearer {}", gateway_token))
            .map_err(|e| anyhow::anyhow!("Invalid gateway token header: {}", e))?;
        request.headers_mut().insert("Authorization", bearer);

        // Bounded WS config. `connect_async`'s tungstenite defaults are 64 MiB max message, 16 MiB
        // max frame and an UNBOUNDED (`usize::MAX`) write buffer — i.e. a single 64 MiB text frame of
        // `[],[],[]…` inflates ~20× into `serde_json::Value` (~1.3 GB resident) and OOMs the agent,
        // and a peer that stops reading grows the write buffer without limit. See `WS_MAX_*`.
        let ws_config = tokio_tungstenite::tungstenite::protocol::WebSocketConfig {
            max_message_size: Some(WS_MAX_MESSAGE_SIZE),
            max_frame_size: Some(WS_MAX_FRAME_SIZE),
            max_write_buffer_size: WS_MAX_WRITE_BUFFER,
            ..Default::default()
        };
        let (ws_stream, _) =
            tokio_tungstenite::connect_async_with_config(request, Some(ws_config), false)
                .await
                .map_err(|e| anyhow::anyhow!("WebSocket connect failed: {}", e))?;

        // Split for reading welcome message
        let (write, mut read) = ws_stream.split();
        let write = Arc::new(Mutex::new(write));

        // Wait for welcome message with agent_id assignment
        let assigned_agent_id = match tokio::time::timeout(
            std::time::Duration::from_secs(5),
            read.next(),
        ).await {
            Ok(Some(Ok(Message::Text(text)))) => {
                if let Ok(welcome) = serde_json::from_str::<serde_json::Value>(&text) {
                    if welcome["type"].as_str() == Some("welcome") {
                        welcome["agent_id"]
                            .as_str()
                            .unwrap_or(&stored_agent_id)
                            .to_string()
                    } else {
                        stored_agent_id.clone()
                    }
                } else {
                    stored_agent_id.clone()
                }
            }
            _ => stored_agent_id.clone(),
        };

        let final_agent_id = if assigned_agent_id.is_empty() {
            format!("agent-{}", &uuid::Uuid::new_v4().to_string()[..8])
        } else {
            assigned_agent_id
        };

        // Store agent_id
        {
            let mut aid = self.agent_id.write().await;
            *aid = Some(final_agent_id.clone());
        }

        // Persist agent_id to credentials
        let mut updated_creds = creds.clone();
        if let Some(obj) = updated_creds.as_object_mut() {
            obj.insert("agent_id".to_string(), serde_json::json!(final_agent_id));
        }
        auth::save_credentials(&updated_creds);

        self.connected.store(true, std::sync::atomic::Ordering::Relaxed);
        // Mark that we've connected at least once so subsequent cycles are treated
        // as reconnects (drives the console banner + reconnect messaging above).
        self.has_connected.store(true, std::sync::atomic::Ordering::Relaxed);

        if is_reconnect {
            println!("  ✓ Reconnected");
        } else {
            println!("  ✓ Connected as {}", final_agent_id);
            println!("  Waiting for tasks...");
        }

        let tid = self.tenant_id.read().await;
        tracing::info!(
            agent_id = %final_agent_id,
            tenant = ?*tid,
            role = self.role(),
            "Connected to gateway"
        );

        // Reunite the stream
        let ws_stream = read.reunite(Arc::try_unwrap(write)
            .map_err(|_| anyhow::anyhow!("Failed to reunite WS"))?
            .into_inner()
        ).map_err(|e| anyhow::anyhow!("Reunite failed: {}", e))?;

        Ok(ws_stream)
    }

    /// Build the backend artifact-callback context for a file-bearing run (§6.3).
    ///
    /// Returns `None` unless the run references stored files (config has a non-empty
    /// `files` map) AND the run carries a numeric backend task id (string ids like the
    /// scheduled-monitor `sched-...` path don't map to backend tasks) AND a usable auth
    /// token is available. The two artifact-init/finalize JSON calls authenticate with
    /// the SAME Bearer the agent uses for `/api/recorder/connect` (a tenant-scoped
    /// JWT/API key) plus the executor-binding agent_id. The bytes never touch the
    /// backend — the bulk upload goes straight to storage (§4.4).
    async fn build_artifact_context(
        &self,
        task_id: &str,
        msg: &serde_json::Value,
    ) -> Option<crate::automation::files::ArtifactContext> {
        // Only file-bearing runs need a capture context.
        let has_files = msg
            .get("config")
            .and_then(|c| c.get("files"))
            .and_then(|f| f.as_object())
            .map(|o| !o.is_empty())
            .unwrap_or(false);
        if !has_files {
            return None;
        }
        // Backend tasks are integer-keyed; a non-numeric id (e.g. scheduled-monitor
        // `sched-...`) has no backend task to attach captures to.
        if task_id.parse::<i64>().is_err() {
            tracing::debug!(task_id, "Skipping artifact context for non-backend task id");
            return None;
        }
        // Same auth the agent uses for /connect: service token in service mode, else a
        // valid (refreshed) user token. A revoked/expired token yields None → capture
        // is skipped and the wait_for_download step fails closed.
        let token = if self.service_mode {
            auth::get_service_token()
        } else {
            auth::get_valid_token().await.unwrap_or_default()
        }?;
        let agent_id = self.agent_id.read().await.clone().unwrap_or_default();
        if agent_id.is_empty() {
            return None;
        }
        // The automation router (artifact-init/finalize) is mounted under /api.
        let base_url = format!("{}/api", self.config.saas.url.trim_end_matches('/'));
        Some(crate::automation::files::ArtifactContext {
            base_url,
            token,
            agent_id,
            task_id: task_id.to_string(),
        })
    }

    /// Main listen loop — exact port of Python SaaSBridge._listen()
    async fn listen(&self, ws: WsStream) -> Result<(), anyhow::Error> {
        let (mut write, mut read) = ws.split();

        // Take the shared outgoing receiver for this connection cycle. The sender
        // (`self.outgoing_tx`) is STABLE across reconnects — every relay/heartbeat
        // clone keeps working — so we must hand the receiver BACK when this cycle
        // ends (see the reclaim at the bottom). The writer task therefore returns
        // the receiver instead of dropping it; without that reclaim, the next
        // connect cycle would find `None` here and the agent would never
        // re-register (CR-1: reconnect broke permanently after the first drop).
        let mut outgoing_rx = self.outgoing_rx.lock().await.take()
            .ok_or_else(|| anyhow::anyhow!("Outgoing receiver already taken"))?;

        // Stop signal so we can retire the writer WITHOUT dropping the receiver.
        let (writer_stop_tx, mut writer_stop_rx) = tokio::sync::oneshot::channel::<()>();
        // PRIORITY control lane for WebSocket CONTROL frames (Ping/Pong).
        //
        // Two reasons it is separate from `outgoing_tx`: (1) `BridgeOutgoing` has no control-frame
        // variant, and an incoming Ping used to be answered with `BridgeOutgoing::Binary(data)` — a
        // DATA frame, not a Pong, which is not a protocol pong at all AND collides with the relay's
        // `[0x01][4B sid_len][sid][payload]` screencast framing (the frontend would try to demux it);
        // (2) a pong that queues behind a screencast backlog is a pong that arrives too late to keep
        // the peer from reaping us. Bounded + non-blocking: if 64 control frames are already queued
        // the writer is wedged and one more pong changes nothing.
        let (control_tx, mut control_rx) = mpsc::channel::<Message>(64);
        // `mut` because the read loop `select!`s on `&mut write_handle` to notice a dead write half.
        let mut write_handle: JoinHandle<mpsc::UnboundedReceiver<BridgeOutgoing>> =
            tokio::spawn(async move {
                // Control frames rescued by a shed pass, written before anything newer is pulled so
                // survivors keep their relative order.
                let mut rescued: std::collections::VecDeque<BridgeOutgoing> =
                    std::collections::VecDeque::new();
                'writer: loop {
                    while let Some(msg) = rescued.pop_front() {
                        if !write_frame(&mut write, bridge_outgoing_to_message(msg)).await {
                            break 'writer;
                        }
                    }
                    tokio::select! {
                        biased; // control frames first — see the lane comment above
                        _ = &mut writer_stop_rx => break 'writer,
                        Some(ctl) = control_rx.recv() => {
                            if !write_frame(&mut write, ctl).await {
                                break 'writer;
                            }
                        }
                        maybe = outgoing_rx.recv() => match maybe {
                            Some(msg) => {
                                // Bound the queue: the SENDER must stay unbounded (it is cloned into
                                // relays, the monitor loop and every spawned handler), but that must
                                // not mean unbounded MEMORY when the peer stops reading.
                                if outgoing_rx.len() > OUTGOING_SOFT_CAP {
                                    match shed_backlog(
                                        &mut outgoing_rx,
                                        |m| matches!(m, BridgeOutgoing::Binary(_)),
                                        OUTGOING_HARD_CAP,
                                    ) {
                                        ShedOutcome::Shed { keep, dropped } => {
                                            if dropped > 0 {
                                                tracing::warn!(
                                                    dropped,
                                                    kept = keep.len(),
                                                    "outgoing WS backlog over cap — dropped stale screencast frames"
                                                );
                                            }
                                            rescued = keep;
                                        }
                                        ShedOutcome::Overflow { queued } => {
                                            tracing::error!(
                                                queued,
                                                cap = OUTGOING_HARD_CAP,
                                                "gateway stopped reading — dropping this WS session instead of buffering without bound"
                                            );
                                            break 'writer;
                                        }
                                    }
                                }
                                if !write_frame(&mut write, bridge_outgoing_to_message(msg)).await {
                                    break 'writer;
                                }
                            }
                            None => break 'writer, // sender dropped (never, in practice)
                        },
                    }
                }
                // Return the receiver so the next connect cycle can reuse it.
                outgoing_rx
            });

        // Spawn heartbeat — includes metadata matching Python SaaSBridge._heartbeat_loop()
        let heartbeat_tx = self.outgoing_tx.clone();
        let heartbeat_recorder = self.recorder.clone();
        let heartbeat_max_sessions = self.max_sessions;
        let heartbeat_role = self.role().to_string();
        // Cached profile (computed once at init) — reused on every heartbeat so
        // spec changes (e.g. VM resize across restarts) refresh backend-side.
        let heartbeat_profile = self.speed_profile.clone();
        let heartbeat_handle = tokio::spawn(async move {
            loop {
                tokio::time::sleep(std::time::Duration::from_secs(25)).await;
                let mut msg = serde_json::json!({
                    "type": "heartbeat",
                    "active_sessions": heartbeat_recorder.session_count(),
                    "max_sessions": heartbeat_max_sessions,
                    "platform": std::env::consts::OS,
                    "version": env!("CARGO_PKG_VERSION"),
                    "role": heartbeat_role,
                });
                if let Some(obj) = msg.as_object_mut() {
                    heartbeat_profile.inject_into(obj);
                }
                if heartbeat_tx.send(BridgeOutgoing::Json(msg)).is_err() {
                    break;
                }
            }
        });

        // Spawn the autonomous monitoring loop (scheduled parallel target checks).
        let monitor_handle = {
            let state = self.monitor.clone();
            let browser = self.recorder.browser_manager.clone();
            let outgoing = self.outgoing_tx.clone();
            let agent_id = self.agent_id.clone();
            let running = Arc::new(std::sync::atomic::AtomicBool::new(true));
            let running_loop = running.clone();
            // The credential channel key a scheduled workflow needs to open its sealed credentials —
            // formerly loaded inside the per-exec shim; now threaded into the loop (stable per agent,
            // refreshed each reconnect since `listen` re-runs).
            let channel_key = auth::load_credentials().and_then(|c| {
                c.get("channel_key")
                    .and_then(|v| v.as_str())
                    .filter(|k| !k.is_empty())
                    .map(String::from)
            });
            let handle = tokio::spawn(async move {
                crate::monitor::run_monitor_loop(state, browser, outgoing, agent_id, running_loop, channel_key).await;
            });
            (handle, running)
        };

        // Register monitoring capacity now that the gateway assigned our agent_id
        // (the /connect POST can't carry it on first connect). The backend persists
        // capacity + distributes + pushes our targets over the gateway.
        {
            let aid = self.agent_id.read().await.clone().unwrap_or_default();
            if !aid.is_empty() {
                let _ = self.outgoing_tx.send(BridgeOutgoing::Json(serde_json::json!({
                    "type": "monitor_register",
                    "agent_id": aid,
                    "capacity": self.monitor.capacity.to_json(),
                    "check_modes": ["content", "uptime", "playwright"],
                })));
            }
        }

        // Read loop. The loop's outcome is captured (not `return`ed early) so the
        // receiver-reclaim + task cleanup at the bottom ALWAYS runs — otherwise a
        // WS read error would drop the writer task (and the receiver with it),
        // permanently breaking reconnect (CR-1).
        let mut read_result: Result<(), anyhow::Error> = Ok(());
        // Half-open-connection detector: probe with a client-initiated Ping after a silent stretch
        // and require a Pong. Without it, a black-holed TCP flow (NAT reap, vanished LB, SIGKILLed
        // peer) parks this loop in `read.next()` for ~15 minutes while the agent still reports itself
        // connected and the gateway has already reaped it. The 25s app-level heartbeat does NOT cover
        // this: it is a WRITE, and writes into a black hole succeed into the socket buffer.
        let mut liveness = WsLiveness::new(READ_IDLE_TIMEOUT, PONG_GRACE);
        // Set when the writer task is joined inside the loop, so the cleanup below does not poll a
        // finished JoinHandle.
        let mut reclaimed_rx: Option<mpsc::UnboundedReceiver<BridgeOutgoing>> = None;
        while self.running.load(std::sync::atomic::Ordering::Relaxed) {
            let wait = liveness.timeout(std::time::Instant::now());
            let frame: Message = tokio::select! {
                // The write half died (write error, peer window shut for WRITE_TIMEOUT, or the
                // backlog blew the hard cap). It used to `break` in silence, leaving this loop
                // reading happily on a session that could no longer answer anything.
                joined = &mut write_handle => {
                    match joined {
                        Ok(rx) => reclaimed_rx = Some(rx),
                        Err(e) => tracing::error!(error = %e, "outgoing WS writer task failed"),
                    }
                    read_result = Err(anyhow::anyhow!(
                        "outgoing WS writer stopped — tearing down the session to reconnect"
                    ));
                    break;
                }
                res = tokio::time::timeout(wait, read.next()) => match res {
                    Err(_elapsed) => match liveness.on_idle(std::time::Instant::now()) {
                        ProbeAction::SendPing => {
                            tracing::debug!("no gateway frame for {READ_IDLE_TIMEOUT:?} — probing with a WS ping");
                            let _ = control_tx.try_send(Message::Ping(Vec::new()));
                            continue;
                        }
                        ProbeAction::PeerDead => {
                            read_result = Err(anyhow::anyhow!(
                                "gateway did not answer a WS ping within {PONG_GRACE:?} — \
                                 connection is half-open, reconnecting"
                            ));
                            break;
                        }
                    },
                    Ok(Some(Ok(m))) => m,
                    Ok(Some(Err(e))) => {
                        read_result = Err(anyhow::anyhow!("WS read error: {}", e));
                        break;
                    }
                    Ok(None) => break,
                },
            };

            // ANY inbound frame proves the path is alive.
            liveness.on_frame();

            let raw = match frame {
                Message::Text(text) => text,
                Message::Ping(data) => {
                    // A real Pong CONTROL frame on the priority lane (this used to send a Binary
                    // DATA frame, which is not a pong and collides with the screencast framing).
                    let _ = control_tx.try_send(Message::Pong(data));
                    continue;
                }
                Message::Close(_) => break,
                _ => continue,
            };

            let msg: serde_json::Value = match serde_json::from_str(&raw) {
                Ok(v) => v,
                Err(_) => continue,
            };

            let msg_type = msg["type"].as_str().unwrap_or("");
            let msg_channel = msg["channel"].as_str();

            // AI completion responses → resolve pending futures
            if msg_type == "ai_completion_result" {
                if let Some(rid) = msg["request_id"].as_str() {
                    if let Some((_, sender)) = self.ai_pending.remove(rid) {
                        let payload = msg["payload"].clone();
                        let _ = sender.send(payload);
                    }
                }
                continue;
            }

            if msg_type == "ai_completion_error" {
                if let Some(rid) = msg["request_id"].as_str() {
                    if let Some((_, sender)) = self.ai_pending.remove(rid) {
                        let _ = sender.send(serde_json::json!({"error": msg["payload"]["error"]}));
                    }
                }
                continue;
            }

            // Ping → pong
            if msg_type == "ping" {
                let _ = self.outgoing_tx.send(BridgeOutgoing::Json(serde_json::json!({"type": "pong"})));
                continue;
            }

            // Session messages → dispatch to relay
            if msg_channel == Some("session") {
                if let Some(sid) = msg["session_id"].as_str() {
                    if let Some(relay) = self.active_relays.get(sid) {
                        let inner = msg["msg"].clone();
                        relay.dispatch_incoming(inner);
                    }
                }
                continue;
            }

            // Session lifecycle
            if msg_type == "session_open" {
                let sid = msg["session_id"].as_str().unwrap_or("").to_string();
                if !sid.is_empty() {
                    let relay = Arc::new(AgentSessionRelay::new(
                        sid.clone(),
                        self.outgoing_tx.clone(),
                    ));
                    self.active_relays.insert(sid.clone(), relay.clone());

                    // Confirm to gateway
                    let _ = self.outgoing_tx.send(BridgeOutgoing::Json(serde_json::json!({
                        "type": "session_opened",
                        "session_id": &sid,
                    })));

                    let sid_short = truncate_str(&sid, 8);

                    // Spawn session loop
                    let sid_clone = sid.clone();
                    let recorder = self.recorder.clone();
                    let relays = self.active_relays.clone();
                    let outgoing = self.outgoing_tx.clone();
                    let tenant_id = self.tenant_id.read().await.clone();
                    tokio::spawn(async move {
                        run_session_loop(&sid_clone, relay, recorder, tenant_id, None).await;
                        relays.remove(&sid_clone);
                        let _ = outgoing.send(BridgeOutgoing::Json(serde_json::json!({
                            "type": "session_closed",
                            "session_id": &sid_clone,
                        })));
                    });

                    println!("  ▶ Session {} opened", sid_short);
                }
                continue;
            }

            if msg_type == "session_close" {
                if let Some(sid) = msg["session_id"].as_str() {
                    if let Some((_, relay)) = self.active_relays.remove(sid) {
                        relay.close();
                    }
                }
                continue;
            }

            // Backend-orchestrated AI session lifecycle. Thin aliases over the
            // existing session machinery (run_session_loop + start_session +
            // handle_agent_action + end_session), driven by the BACKEND
            // orchestrator (not the frontend recorder UI). Acks are TOP-LEVEL
            // (not relay-wrapped) so the backend correlates by session_id.
            if msg_type == "ai_session_open" {
                let sid = {
                    let s = msg["session_id"].as_str().unwrap_or("").to_string();
                    if s.is_empty() { uuid::Uuid::new_v4().to_string() } else { s }
                };
                let request_id = msg.get("request_id").cloned().unwrap_or(serde_json::Value::Null);
                let url = msg["url"].as_str()
                    .or(msg["config"]["url"].as_str())
                    .unwrap_or("")
                    .to_string();
                let purpose = msg.get("purpose").cloned().unwrap_or(serde_json::Value::Null);
                let _ = purpose; // purpose is forwarded for future per-purpose teardown

                let relay = Arc::new(AgentSessionRelay::new(
                    sid.clone(),
                    self.outgoing_tx.clone(),
                ));
                self.active_relays.insert(sid.clone(), relay.clone());

                // Auto-navigate: feed a synthetic 'start' frame so the browser
                // opens at `url` without recording wait steps.
                if !url.is_empty() {
                    relay.dispatch_incoming(serde_json::json!({
                        "type": "start",
                        "url": url,
                        "options": {"record_wait_steps": false},
                    }));
                }

                let sid_clone = sid.clone();
                let recorder = self.recorder.clone();
                let relays = self.active_relays.clone();
                let outgoing = self.outgoing_tx.clone();
                let tenant_id = self.tenant_id.read().await.clone();
                let ai_map = self.ai_session_browser_map.clone();
                let ai_map_cleanup = self.ai_session_browser_map.clone();
                tokio::spawn(async move {
                    run_session_loop(&sid_clone, relay, recorder, tenant_id, Some(ai_map)).await;
                    relays.remove(&sid_clone);
                    ai_map_cleanup.remove(&sid_clone);
                    let _ = outgoing.send(BridgeOutgoing::Json(serde_json::json!({
                        "type": "session_closed",
                        "session_id": &sid_clone,
                    })));
                });

                let _ = self.outgoing_tx.send(BridgeOutgoing::Json(serde_json::json!({
                    "type": "ai_session_opened",
                    "session_id": &sid,
                    "request_id": request_id,
                })));
                println!("  ▶ AI session {} opened", truncate_str(&sid, 8));
                continue;
            }

            if msg_type == "ai_session_close" {
                let sid = msg["session_id"].as_str().unwrap_or("").to_string();
                let request_id = msg.get("request_id").cloned().unwrap_or(serde_json::Value::Null);

                // Harvest auth_session BEFORE tearing down: clone the page +
                // context out of the session under a BRIEF lock, drop the
                // RefMut, then extract UNLOCKED (never hold a DashMap RefMut
                // across an `.await` — see "Rust Port — Concurrency Gotchas").
                let mut auth_session = serde_json::Value::Null;
                let browser_sid = self.ai_session_browser_map
                    .get(&sid)
                    .map(|e| e.value().clone());

                if let Some(ref bsid) = browser_sid {
                    let page_ctx = self.recorder
                        .get_session_mut(bsid)
                        .map(|s| (s.page.clone(), s.context.clone()));
                    if let Some((page, context)) = page_ctx {
                        let headers: std::collections::HashMap<String, String> =
                            std::collections::HashMap::new();
                        let state = crate::automation::session_state::extract_session_state(
                            &page, &context, &headers,
                        ).await;
                        auth_session = serde_json::to_value(&state)
                            .unwrap_or(serde_json::Value::Null);
                    }
                    // Tear down the browser session (closes context).
                    let _ = self.recorder.end_session(bsid).await;
                }

                // Close the relay so run_session_loop exits and emits
                // session_closed (its cleanup end_session is idempotent — the
                // session was already removed above).
                if let Some((_, relay)) = self.active_relays.remove(&sid) {
                    relay.close();
                }
                self.ai_session_browser_map.remove(&sid);

                let _ = self.outgoing_tx.send(BridgeOutgoing::Json(serde_json::json!({
                    "type": "ai_session_closed",
                    "session_id": &sid,
                    "request_id": request_id,
                    "auth_session": auth_session,
                })));
                println!("  ■ AI session {} closed", truncate_str(&sid, 8));
                continue;
            }

            // Task dispatch — execute_workflow
            if msg_type == "execute_workflow" {
                // task_id arrives as a JSON number — coerce faithfully (see task_id_str).
                let task_id = task_id_str(&msg["task_id"]);

                // DRAGNET distributed crawl: the coordinator dispatches each crawl shard
                // as an `execute_workflow` whose `trigger_context` carries the URL batch
                // (`_crawl_shard`) + extraction spec (`_crawl_extract`), or whose first
                // step is `crawl_batch`. Serve it via the SHARED shard runner (HTTP-first
                // + this agent's warm browser for JS fallback) and reply the reply-awaited
                // `task_result` — the SAME fleet-crawl contract FleetBridge serves, so the
                // OSS writ-agent (this SaaS dialect) crawls fully instead of choking on an
                // unknown `crawl_batch` step.
                let cfg = msg.get("config").cloned().unwrap_or_else(|| serde_json::json!({}));
                let tc = cfg
                    .get("trigger_context")
                    .cloned()
                    .or_else(|| msg.get("trigger_context").cloned())
                    .unwrap_or_else(|| serde_json::json!({}));
                let is_crawl_shard = tc.get("_crawl_shard").is_some()
                    || cfg
                        .get("steps")
                        .and_then(|s| s.as_array())
                        .and_then(|a| a.first())
                        .and_then(|s| s.get("type"))
                        .and_then(|t| t.as_str())
                        == Some("crawl_batch");
                if is_crawl_shard {
                    println!("\n  ▶ Received crawl shard task #{}", task_id);
                    let mut cfg = cfg;
                    // The shard runner reads the batch under `config.trigger_context`;
                    // fold in a top-level placement if that's where it rode.
                    if cfg.get("trigger_context").is_none() {
                        if let Some(obj) = cfg.as_object_mut() {
                            obj.insert("trigger_context".into(), tc);
                        }
                    }
                    let outgoing = self.outgoing_tx.clone();
                    let browser = self.recorder.browser_manager.clone();
                    let tid = task_id.clone();
                    tokio::spawn(async move {
                        let frame = crate::crawl_shard::run_shard_from_message(
                            Some(browser), &tid, &cfg,
                        )
                        .await;
                        let _ = outgoing.send(BridgeOutgoing::Json(frame));
                    });
                    continue;
                }

                let entry_url = msg["config"]["entry_url"].as_str().unwrap_or("").to_string();
                println!("\n  ▶ Received workflow task #{} — {}", task_id, entry_url);

                let outgoing = self.outgoing_tx.clone();
                let msg_clone = msg.clone();
                let browser_mgr = self.recorder.browser_manager.clone();

                // File assets (§6.3): build the backend artifact-callback context so a
                // wait_for_download step can capture files DIRECT-TO-STORAGE
                // (artifact-init/finalize authenticate with the SAME Bearer the agent
                // uses for /api/recorder/connect — a tenant-scoped JWT/API key — plus
                // the executor-binding agent_id). Built ONLY for file-bearing runs.
                let artifact_ctx = self.build_artifact_context(&task_id, &msg).await;

                tokio::spawn(async move {
                    handle_execute_workflow(&task_id, &msg_clone, &browser_mgr, &outgoing, artifact_ctx).await;
                });
                continue;
            }

            // Task dispatch — execute_ai_task
            if msg_type == "execute_ai_task" {
                let task_id = task_id_str(&msg["task_id"]);
                let goal = msg["config"]["goal"].as_str().unwrap_or("AI task").to_string();
                println!("\n  ▶ Received AI task #{} — {}", task_id, goal);

                let outgoing = self.outgoing_tx.clone();
                let msg_clone = msg.clone();
                let browser_mgr = self.recorder.browser_manager.clone();
                let ai_pending = self.ai_pending.clone();
                let tenant_id = self.tenant_id.read().await.clone();
                tokio::spawn(async move {
                    handle_execute_ai_task(
                        &task_id, &msg_clone, &browser_mgr, &outgoing,
                        &ai_pending, tenant_id.as_deref(),
                    ).await;
                });
                continue;
            }

            // Streaming session lifecycle
            if msg_type == "start_streaming_session" {
                let task_id = task_id_str(&msg["task_id"]);
                let session_key = msg["config"]["session_key"].as_str()
                    .or(msg["session_key"].as_str())
                    .unwrap_or("").to_string();
                let url = msg["config"]["target_url"].as_str()
                    .or(msg["target_url"].as_str())
                    .unwrap_or("").to_string();
                println!("\n  ▶ Received streaming session {} — {}", task_id, url);

                let outgoing = self.outgoing_tx.clone();
                let relays = self.active_relays.clone();
                let msg_clone = msg.clone();
                let browser_mgr = self.recorder.browser_manager.clone();
                tokio::spawn(async move {
                    // Cloud path resolves credentials/proxy the saas way (its own
                    // channel key) and passes them into the SHARED handler.
                    let config = &msg_clone["config"];
                    let credentials = resolve_credentials(config);
                    let proxy_override = extract_proxy_override(config);
                    crate::bridge::streaming_session::handle_start_streaming_session(
                        &task_id, &session_key, &msg_clone,
                        &browser_mgr, &outgoing, &relays,
                        credentials, proxy_override,
                    ).await;
                });
                continue;
            }

            if msg_type == "streaming_command" {
                let session_key = msg["session_key"].as_str().unwrap_or("");
                let action = msg["action"].as_str().unwrap_or("?");
                let request_id = msg["request_id"].as_str().unwrap_or("?");
                tracing::info!(
                    session_key, action, request_id,
                    "Routing streaming_command to session relay"
                );
                if let Some(relay) = self.active_relays.get(session_key) {
                    relay.dispatch_incoming(msg.clone());
                } else {
                    tracing::warn!(
                        session_key,
                        active_relays = self.active_relays.len(),
                        "Streaming command for unknown session. Active relay keys: {:?}",
                        self.active_relays.iter().map(|e| e.key().clone()).collect::<Vec<_>>()
                    );
                }
                continue;
            }

            if msg_type == "end_streaming_session" {
                let session_key = msg["session_key"].as_str().unwrap_or("");
                if let Some((_, relay)) = self.active_relays.remove(session_key) {
                    relay.close();
                    println!("  ■ Streaming session {} ended", truncate_str(session_key, 8));
                }
                continue;
            }

            if msg_type == "cancel_task" {
                let task_id = task_id_str(&msg["task_id"]);
                println!("\n  ✕ Task #{} cancelled", task_id);
                continue;
            }

            // ---- Monitoring coordination (autonomous scheduled checks) -------
            if msg_type == "assign_targets" {
                let n = msg.get("targets").and_then(|v| v.as_array()).map(|a| a.len()).unwrap_or(0);
                println!("\n  ◎ Assigned {} monitoring target(s)", n);
                self.monitor.assign_targets(&msg).await;
                continue;
            }
            if msg_type == "target_sync" {
                self.monitor.apply_sync(&msg).await;
                continue;
            }
            // On-demand check: the coordinator asks us to check one assigned target
            // NOW (user pressed "Check now"), out of the normal schedule.
            if msg_type == "check_target_now" {
                if let Some(tid) = msg.get("target_id").and_then(|v| v.as_i64()) {
                    self.monitor.check_target_now(tid).await;
                }
                continue;
            }
            if msg_type == "assign_workflows" {
                self.monitor.assign_workflows(&msg).await;
                continue;
            }

            if msg_type == "disconnect" {
                let reason = msg["reason"].as_str().unwrap_or("unknown");
                println!("\n  ⚠ Server requested disconnect: {}", reason);
                self.running.store(false, std::sync::atomic::Ordering::Relaxed);
                break;
            }
        }

        // Stop the monitor loop for this connection (it re-spawns on reconnect).
        monitor_handle.1.store(false, std::sync::atomic::Ordering::Relaxed);
        monitor_handle.0.abort();
        heartbeat_handle.abort();

        // Retire the writer task WITHOUT dropping the receiver: signal it to stop,
        // then await it to reclaim the receiver and re-store it for the next
        // connect cycle. (If the writer already exited on its own — e.g. the WS
        // write side broke — the stop send fails harmlessly and the await still
        // yields the receiver.)
        // If the loop above already joined the writer (it died mid-session), reuse that receiver —
        // awaiting a finished JoinHandle again would panic.
        if let Some(rx) = reclaimed_rx {
            *self.outgoing_rx.lock().await = Some(rx);
            return read_result;
        }
        let _ = writer_stop_tx.send(());
        match write_handle.await {
            Ok(rx) => {
                *self.outgoing_rx.lock().await = Some(rx);
            }
            Err(e) => {
                // Unreachable in practice: the writer body has no panic points and
                // we never cancel it. If it ever did panic the receiver is lost;
                // restore a fresh receiver so the next `listen` doesn't hard-error
                // and the agent can still re-register + read (outgoing frames would
                // be degraded until process restart — logged loudly for triage).
                tracing::error!(error = %e, "Outgoing writer task failed; restoring a fresh receiver");
                let (_tx, rx) = mpsc::unbounded_channel();
                *self.outgoing_rx.lock().await = Some(rx);
            }
        }

        read_result
    }

    pub fn shutdown(&self) {
        self.running.store(false, std::sync::atomic::Ordering::Relaxed);
    }
}

/// The split write half of the gateway WS.
type WsSink = futures_util::stream::SplitSink<WsStream, Message>;

/// Render an outgoing app frame as a WS message.
fn bridge_outgoing_to_message(msg: BridgeOutgoing) -> Message {
    match msg {
        BridgeOutgoing::Json(v) => Message::Text(serde_json::to_string(&v).unwrap_or_default()),
        BridgeOutgoing::Binary(b) => Message::Binary(b),
    }
}

/// Write one frame with a DEADLINE. Returns `false` when the write half is unusable and the session
/// must be torn down. (Deliberately mirrors `fleet_bridge::write_frame`; the two bridges are
/// mutually-exclusive cargo features, so the helper cannot literally be shared.)
///
/// The timeout matters: a peer whose receive window is shut makes `send().await` park indefinitely,
/// so the writer never drains — and therefore never sheds — its queue, while looking exactly like a
/// healthy idle writer.
async fn write_frame(write: &mut WsSink, msg: Message) -> bool {
    match tokio::time::timeout(WRITE_TIMEOUT, write.send(msg)).await {
        Ok(Ok(())) => true,
        Ok(Err(e)) => {
            tracing::warn!(error = %e, "gateway WS write failed");
            false
        }
        Err(_) => {
            tracing::warn!(
                timeout_s = WRITE_TIMEOUT.as_secs(),
                "gateway WS write timed out (peer not reading) — dropping the session"
            );
            false
        }
    }
}

// ---------------------------------------------------------------------------
// Channel key credential decryption
// ---------------------------------------------------------------------------

/// Decrypt credentials using the per-agent channel key.
///
/// The backend re-encrypts workflow credentials with our channel key
/// before sending them over the WebSocket. We decrypt with the same
/// key that was issued during the OAuth device flow.
/// No master/global keys are ever shared with user-hosted recorders.
fn decrypt_with_channel_key(encrypted: &str) -> HashMap<String, String> {
    let creds = match auth::load_credentials() {
        Some(c) => c,
        None => {
            tracing::error!("No credentials file — cannot load channel_key");
            return HashMap::new();
        }
    };

    let channel_key = match creds.get("channel_key").and_then(|v| v.as_str()) {
        Some(k) if !k.is_empty() => k.to_string(),
        _ => {
            tracing::error!("No channel_key in credentials — cannot decrypt");
            return HashMap::new();
        }
    };

    match crate::security::crypto::decrypt_credentials(encrypted, &channel_key) {
        Ok(decrypted) => decrypted,
        Err(e) => {
            tracing::error!(error = %e, "Failed to decrypt credentials with channel key");
            HashMap::new()
        }
    }
}

/// Resolve credentials from the config message.
/// Tries credentials_encrypted (decrypted via channel_key), falls back to credentials_decrypted.
///
/// The reserved `__proxy__` key (a per-run BYO persona proxy OBJECT) is stripped
/// here — it is NOT a login secret and must never leak into a form field or a
/// Refuse a plaintext (ws://_/http://) endpoint outside local dev.
///
/// Plaintext exposes the bearer token AND all session traffic on the wire, so we
/// hard-fail unless (a) the scheme is already wss://https://, (b) the host is
/// loopback (local dev), or (c) the operator explicitly opted in via
/// saas.allow_insecure (a trusted private network they accept the risk on).
/// Strip the port from a `host[:port]` authority, returning the bare host.
/// Handles bracketed IPv6 (`[::1]`, `[::1]:8080`) — an unbracketed IPv6 literal
/// is ambiguous with the colon-separated port form, so callers should only pass
/// authorities as produced by a real URL (which brackets IPv6).
fn strip_port(hostport: &str) -> &str {
    if let Some(rest) = hostport.strip_prefix('[') {
        // Bracketed IPv6: return the address inside the brackets.
        return rest.split(']').next().unwrap_or(rest);
    }
    // host or host:port — split on the single colon (IPv4/DNS names have none).
    match hostport.split_once(':') {
        Some((host, _port)) => host,
        None => hostport,
    }
}

fn require_secure_url(url: &str, allow_insecure: bool, what: &str) -> anyhow::Result<()> {
    let lower = url.trim().to_lowercase();
    if lower.starts_with("wss://") || lower.starts_with("https://") {
        return Ok(());
    }
    // Authority = host[:port] after the scheme, before any path/query, sans userinfo.
    let after = lower.split_once("://").map(|x| x.1).unwrap_or(lower.as_str());
    let authority = after.split(['/', '?', '#']).next().unwrap_or("");
    let hostport = authority.rsplit('@').next().unwrap_or(authority);
    // Extract the bare host (strip the port), then compare EXACTLY. A prefix match
    // (`starts_with("localhost")` / `"127."`) lets an attacker host like
    // `localhost.attacker.com` or `127.0.0.1.attacker.com` pass as "local", so the
    // agent would ship its Bearer token in cleartext to an EXTERNAL host. Parse the
    // host and require host == "localhost" or a loopback IP.
    let host = strip_port(hostport);
    let is_local = host == "localhost"
        || host
            .parse::<std::net::IpAddr>()
            .map(|ip| ip.is_loopback())
            .unwrap_or(false);
    if allow_insecure || is_local {
        return Ok(());
    }
    anyhow::bail!(
        "Refusing insecure {what} URL '{url}': plaintext would expose the agent \
         token and all session traffic on the wire. Use a wss://https:// endpoint, \
         or set saas.allow_insecure=true only on a trusted private network."
    )
}

/// `{{secret:KEY}}` substitution. It is consumed separately via
/// `extract_proxy_override`. Mirrors the Python agent popping `__proxy__` from the
/// credentials dict (automation_engine.py:3373) before secret substitution.
fn resolve_credentials(config: &serde_json::Value) -> HashMap<String, String> {
    // Preferred path: decrypt to a JSON object so a non-string value (the reserved
    // `__proxy__` object) does NOT make the whole `HashMap<String,String>` parse
    // fail and silently drop every credential. Keep only string-valued entries,
    // dropping `__proxy__` (and any other non-string keys).
    if let Some(map) = decrypt_credentials_object(config) {
        let creds: HashMap<String, String> = map
            .into_iter()
            .filter(|(k, _)| k != "__proxy__")
            .filter_map(|(k, v)| v.as_str().map(|s| (k, s.to_string())))
            .collect();
        if !creds.is_empty() {
            return creds;
        }
    }

    // Fall back to the legacy string-map decrypt (covers the all-strings case if
    // the object path returned nothing).
    if let Some(encrypted) = config.get("credentials_encrypted").and_then(|v| v.as_str()) {
        if !encrypted.is_empty() {
            let mut decrypted = decrypt_with_channel_key(encrypted);
            if !decrypted.is_empty() {
                decrypted.remove("__proxy__");
                return decrypted;
            }
        }
    }

    // Fall back to pre-decrypted credentials (sent as JSON)
    if let Some(creds_val) = config.get("credentials_decrypted") {
        // May be a JSON string or an object
        if let Some(s) = creds_val.as_str() {
            if let Ok(mut parsed) = serde_json::from_str::<HashMap<String, String>>(s) {
                parsed.remove("__proxy__");
                return parsed;
            }
        } else if let Ok(mut parsed) = serde_json::from_value::<HashMap<String, String>>(creds_val.clone()) {
            parsed.remove("__proxy__");
            return parsed;
        }
    }

    HashMap::new()
}

// ---------------------------------------------------------------------------
// Per-run BYO persona proxy (__proxy__)
// ---------------------------------------------------------------------------

/// Decrypt the run credentials blob into a JSON object WITHOUT collapsing values
/// to strings.
///
/// `crypto::decrypt_credentials` (used by `resolve_credentials`) deserializes into
/// `HashMap<String, String>`, which CANNOT hold the reserved `__proxy__` object
/// (`{server, username, password, bypass}`). To read `__proxy__` faithfully we
/// re-run the same Fernet decrypt with the channel key and parse the plaintext as
/// an arbitrary JSON object — exactly what the Python bridge does
/// (`json.loads(fernet.decrypt(...))`). Returns None when no encrypted blob,
/// no channel key, or decrypt/parse fails (fail toward direct egress).
fn decrypt_credentials_object(config: &serde_json::Value) -> Option<serde_json::Map<String, serde_json::Value>> {
    // Preferred: encrypted blob decrypted with the per-agent channel key.
    if let Some(encrypted) = config.get("credentials_encrypted").and_then(|v| v.as_str()) {
        if !encrypted.is_empty() {
            let creds = auth::load_credentials()?;
            let channel_key = creds.get("channel_key").and_then(|v| v.as_str()).filter(|k| !k.is_empty())?;
            let fernet = fernet::Fernet::new(channel_key)?;
            let plaintext = fernet.decrypt(encrypted).ok()?;
            let json_str = String::from_utf8(plaintext).ok()?;
            if let Ok(serde_json::Value::Object(map)) = serde_json::from_str::<serde_json::Value>(&json_str) {
                return Some(map);
            }
            return None;
        }
    }

    // Fallback: pre-decrypted credentials sent as JSON (string or object).
    if let Some(creds_val) = config.get("credentials_decrypted") {
        if let Some(s) = creds_val.as_str() {
            if let Ok(serde_json::Value::Object(map)) = serde_json::from_str::<serde_json::Value>(s) {
                return Some(map);
            }
        } else if let serde_json::Value::Object(map) = creds_val {
            return Some(map.clone());
        }
    }

    None
}

/// Extract the per-run BYO persona proxy carried as the reserved `__proxy__` key
/// inside the run credentials, and map it to `ProxySettings`.
///
/// Parity with the Python agent (automation_engine.py:3373): the proxy rides as a
/// dict `{server, username, password, bypass}`; pop it, then accept it ONLY if it
/// is an object with a non-empty `server`. No precedence logic here — the backend
/// guarantees `__proxy__` is only present when allowed (no creator-IP relay bound
/// and not a residential-intent run), so the agent simply applies whatever it is
/// given. Returns None when absent/invalid → falls back to env proxy / direct.
fn extract_proxy_override(config: &serde_json::Value) -> Option<playwright_rs::protocol::ProxySettings> {
    let creds = decrypt_credentials_object(config)?;
    let proxy = creds.get("__proxy__")?.as_object()?;

    // Validate: a usable proxy MUST have a non-empty `server` (mirrors the Python
    // `isinstance(dict) and run_proxy.get('server')` guard). When in doubt, None.
    let server = proxy.get("server").and_then(|v| v.as_str()).filter(|s| !s.is_empty())?;

    let str_field = |k: &str| {
        proxy
            .get(k)
            .and_then(|v| v.as_str())
            .filter(|s| !s.is_empty())
            .map(|s| s.to_string())
    };

    Some(playwright_rs::protocol::ProxySettings {
        server: server.to_string(),
        bypass: str_field("bypass"),
        username: str_field("username"),
        password: str_field("password"),
    })
}


// ---------------------------------------------------------------------------
// BridgeAIClient — routes AI completions through the bridge's existing WS
// ---------------------------------------------------------------------------

/// AI client that routes completions through the bridge's existing WS.
///
/// Implements the same request/response pattern as GatewayAIClient so the
/// recorder AI modes can use it transparently. No extra connections —
/// piggybacks on the single warm WS the bridge already maintains.
pub struct BridgeAIClient {
    outgoing_tx: mpsc::UnboundedSender<BridgeOutgoing>,
    ai_pending: Arc<dashmap::DashMap<String, tokio::sync::oneshot::Sender<serde_json::Value>>>,
    /// API key that initiated this task, echoed into every ai_completion payload
    /// so the gateway bills the key's budget and meters cost per key. None for
    /// JWT/dashboard runs.
    api_key_id: Option<String>,
}

impl BridgeAIClient {
    pub fn new(
        outgoing_tx: mpsc::UnboundedSender<BridgeOutgoing>,
        ai_pending: Arc<dashmap::DashMap<String, tokio::sync::oneshot::Sender<serde_json::Value>>>,
    ) -> Self {
        Self { outgoing_tx, ai_pending, api_key_id: None }
    }

    /// Bind the initiating API key id (chainable).
    pub fn with_api_key(mut self, api_key_id: Option<String>) -> Self {
        self.api_key_id = api_key_id;
        self
    }

    /// Send an AI completion request over the bridge WS and wait for the response.
    pub async fn send_and_wait(
        &self,
        messages: Vec<serde_json::Value>,
        tenant_id: &str,
        system: Option<&str>,
        max_tokens: u32,
        purpose: &str,
        timeout_secs: u64,
    ) -> Result<serde_json::Value, anyhow::Error> {
        let request_id = uuid::Uuid::new_v4().to_string();
        let (tx, rx) = tokio::sync::oneshot::channel::<serde_json::Value>();
        self.ai_pending.insert(request_id.clone(), tx);

        let mut payload = serde_json::json!({
            "tenant_id": tenant_id,
            "messages": messages,
            "max_tokens": max_tokens,
            "purpose": purpose,
        });
        if let Some(sys) = system {
            payload["system"] = serde_json::json!(sys);
        }
        if let Some(ak) = &self.api_key_id {
            payload["api_key_id"] = serde_json::json!(ak);
        }

        let envelope = serde_json::json!({
            "type": "ai_completion",
            "request_id": &request_id,
            "payload": payload,
        });

        self.outgoing_tx.send(BridgeOutgoing::Json(envelope))
            .map_err(|_| anyhow::anyhow!("Bridge WS disconnected"))?;

        match tokio::time::timeout(std::time::Duration::from_secs(timeout_secs), rx).await {
            Ok(Ok(value)) => {
                if let Some(err) = value.get("error").and_then(|e| e.as_str()) {
                    anyhow::bail!("AI completion error: {}", err);
                }
                Ok(value)
            }
            Ok(Err(_)) => {
                self.ai_pending.remove(&request_id);
                anyhow::bail!("AI completion channel closed unexpectedly")
            }
            Err(_) => {
                self.ai_pending.remove(&request_id);
                anyhow::bail!("AI completion timed out after {}s", timeout_secs)
            }
        }
    }

    /// Text-only completion -> parsed JSON.
    pub async fn complete_json(
        &self,
        system_prompt: &str,
        user_prompt: &str,
        tenant_id: &str,
        max_tokens: u32,
        purpose: &str,
    ) -> Option<serde_json::Value> {
        let messages = vec![serde_json::json!({
            "role": "user",
            "content": user_prompt,
        })];

        match self.send_and_wait(
            messages, tenant_id, Some(system_prompt), max_tokens, purpose, 120,
        ).await {
            Ok(result) => {
                let content = result.get("content").and_then(|c| c.as_str()).unwrap_or("");
                crate::ai::json_parser::parse_ai_json(content)
            }
            Err(e) => {
                tracing::error!(error = %e, "BridgeAIClient::complete_json failed");
                None
            }
        }
    }

    /// Vision completion (screenshot + prompt) -> parsed JSON.
    pub async fn complete_vision(
        &self,
        screenshot_b64: &str,
        prompt: &str,
        tenant_id: &str,
        max_tokens: u32,
        purpose: &str,
    ) -> Option<serde_json::Value> {
        let messages = vec![serde_json::json!({
            "role": "user",
            "content": [
                {
                    "type": "image",
                    "source": {
                        "type": "base64",
                        "media_type": "image/jpeg",
                        "data": screenshot_b64,
                    }
                },
                {
                    "type": "text",
                    "text": prompt,
                }
            ]
        })];

        match self.send_and_wait(
            messages, tenant_id, None, max_tokens, purpose, 120,
        ).await {
            Ok(result) => {
                let content = result.get("content").and_then(|c| c.as_str()).unwrap_or("");
                crate::ai::json_parser::parse_ai_json(content)
            }
            Err(e) => {
                tracing::error!(error = %e, "BridgeAIClient::complete_vision failed");
                None
            }
        }
    }

    /// Vision completion with system prompt.
    pub async fn complete_vision_with_system(
        &self,
        system_prompt: &str,
        screenshot_b64: &str,
        prompt: &str,
        tenant_id: &str,
        max_tokens: u32,
        purpose: &str,
    ) -> Option<serde_json::Value> {
        let messages = vec![serde_json::json!({
            "role": "user",
            "content": [
                {
                    "type": "image",
                    "source": {
                        "type": "base64",
                        "media_type": "image/jpeg",
                        "data": screenshot_b64,
                    }
                },
                {
                    "type": "text",
                    "text": prompt,
                }
            ]
        })];

        match self.send_and_wait(
            messages, tenant_id, Some(system_prompt), max_tokens, purpose, 120,
        ).await {
            Ok(result) => {
                let content = result.get("content").and_then(|c| c.as_str()).unwrap_or("");
                crate::ai::json_parser::parse_ai_json(content)
            }
            Err(e) => {
                tracing::error!(error = %e, "BridgeAIClient::complete_vision_with_system failed");
                None
            }
        }
    }
}

/// Drive the AI modes over the bridge WS via the object-safe `AiClient` trait.
/// Inherent methods shadow the trait methods — no recursion.
impl crate::ai::client::AiClient for BridgeAIClient {
    fn complete_json<'a>(
        &'a self,
        system_prompt: &'a str,
        user_prompt: &'a str,
        tenant_id: &'a str,
        max_tokens: u32,
        purpose: &'a str,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Option<serde_json::Value>> + Send + 'a>> {
        Box::pin(BridgeAIClient::complete_json(
            self, system_prompt, user_prompt, tenant_id, max_tokens, purpose,
        ))
    }

    fn complete_vision<'a>(
        &'a self,
        screenshot_b64: &'a str,
        prompt: &'a str,
        tenant_id: &'a str,
        max_tokens: u32,
        purpose: &'a str,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Option<serde_json::Value>> + Send + 'a>> {
        Box::pin(BridgeAIClient::complete_vision(
            self, screenshot_b64, prompt, tenant_id, max_tokens, purpose,
        ))
    }

    fn complete_vision_with_system<'a>(
        &'a self,
        system_prompt: &'a str,
        screenshot_b64: &'a str,
        prompt: &'a str,
        tenant_id: &'a str,
        max_tokens: u32,
        purpose: &'a str,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Option<serde_json::Value>> + Send + 'a>> {
        Box::pin(BridgeAIClient::complete_vision_with_system(
            self, system_prompt, screenshot_b64, prompt, tenant_id, max_tokens, purpose,
        ))
    }
}


/// Recording session message loop — exact port of Python _run_session_loop().
/// Attach passive API capture to a recording session's context. Records XHR/fetch
/// + document form-submits into the shared `NetworkCapture`, streams newly-seen
/// endpoints to the frontend as `api_captured` events, and flags server-rendered
/// page loads (a GET navigation that triggers no API calls) as `page_no_api`.
///
/// SAFETY: the listeners share only `Arc<Mutex<NetworkCapture>>` and the `event_tx`
/// sender — they NEVER call `sessions.get_mut()`, so they cannot starve the tokio
/// workers the way DashMap-touching listeners would (recording-path deadlock note
/// in page_listeners.rs). No lock is held across an `.await`.
async fn attach_recording_network_capture(
    context: &playwright_rs::BrowserContext,
    capture: Arc<Mutex<crate::automation::network_capture::NetworkCapture>>,
    event_tx: tokio::sync::mpsc::UnboundedSender<serde_json::Value>,
) {
    use std::collections::HashSet;

    // Request side — record by stable GUID (mirrors api_discovery correlation).
    let cap_req = capture.clone();
    let _ = context.on_request(move |request: playwright_rs::Request| {
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
    }).await;

    // Response side — finalize captured calls, emit live events, detect server-rendered pages.
    let cap_resp = capture.clone();
    let seen_endpoints: Arc<Mutex<HashSet<String>>> = Arc::new(Mutex::new(HashSet::new()));
    let warned_pages: Arc<Mutex<HashSet<String>>> = Arc::new(Mutex::new(HashSet::new()));
    let _ = context.on_response(move |response: playwright_rs::protocol::ResponseObject| {
        let cap = cap_resp.clone();
        let event_tx = event_tx.clone();
        let seen_endpoints = seen_endpoints.clone();
        let warned_pages = warned_pages.clone();
        async move {
            // A Response's parent ChannelOwner IS its originating Request.
            let parent = match response.parent() {
                Some(p) => p,
                None => return Ok(()),
            };
            let request_id = parent.guid().to_string();
            let (req_method, is_navigation) = match parent.as_any().downcast_ref::<playwright_rs::Request>() {
                Some(req) => (req.method().to_string(), req.is_navigation_request()),
                None => (String::new(), false),
            };
            let url = response.url().to_string();
            let status = response.status();

            // Server-rendered detection: a top-level GET document navigation. After
            // a short settle, if it triggered no NEW captured API calls, the page's
            // data is baked into the HTML → tell the user we can't capture here.
            // (POST/PUT/PATCH navigations are form submits we DO want to capture, so
            // they fall through to the capture path below.)
            if is_navigation && req_method.eq_ignore_ascii_case("GET") {
                let before = cap.lock().await.get_all_calls().len();
                let cap2 = cap.clone();
                let ev2 = event_tx.clone();
                let warned = warned_pages.clone();
                let nav_url = url.clone();
                tokio::spawn(async move {
                    tokio::time::sleep(std::time::Duration::from_millis(2500)).await;
                    let after = cap2.lock().await.get_all_calls().len();
                    if after == before
                        && warned.lock().await.insert(nav_url.clone()) {
                            let _ = ev2.send(serde_json::json!({
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
            let content_type = headers.iter()
                .find(|(k, _)| k.eq_ignore_ascii_case("content-type"))
                .map(|(_, v)| v.to_lowercase());
            let want_body = content_type.as_deref()
                .map(|ct| ["json", "text", "xml", "html", "form"].iter().any(|t| ct.contains(t)))
                .unwrap_or(false);
            let _ = content_type; // (kept above only to gate the body download)
            let body: Option<String> = if want_body {
                match response.body().await { Ok(b) => String::from_utf8(b).ok(), Err(_) => None }
            } else {
                None
            };

            // Finalize the call and stream the FULL record (request + response
            // headers/bodies, all ≤10KB) so the frontend can build a real api_call
            // step and auto-detect response extractions live — one event per
            // unique method+URL endpoint.
            let finalized = cap.lock().await.on_response(&request_id, status, headers, body);
            if let Some(call) = finalized {
                let key = format!("{} {}", call.method, call.url);
                if seen_endpoints.lock().await.insert(key) {
                    let _ = event_tx.send(serde_json::json!({
                        "type": "api_captured",
                        "call": serde_json::to_value(&call).unwrap_or(serde_json::Value::Null),
                    }));
                }
            }
            Ok(())
        }
    }).await;
}

async fn run_session_loop(
    session_id: &str,
    relay: Arc<AgentSessionRelay>,
    recorder: Arc<PlaywrightRecorder>,
    tenant_id: Option<String>,
    ai_session_browser_map: Option<Arc<dashmap::DashMap<String, String>>>,
) {
    let mut local_session_id: Option<String> = None;

    loop {
        let mut msg = match tokio::time::timeout(
            std::time::Duration::from_secs(300),
            relay.receive_json(),
        ).await {
            Ok(Some(msg)) => msg,
            Ok(None) => break, // channel closed
            Err(_) => {
                tracing::info!(session_id, "Session idle timeout (300s)");
                break;
            }
        };

        let msg_type = msg["type"].as_str().unwrap_or("").to_string();
        let msg_type = msg_type.as_str();

        if msg_type == "__session_closed__" {
            tracing::info!(session_id, "Frontend disconnected");
            break;
        }

        match msg_type {
            "start" => {
                let url = msg["url"].as_str().unwrap_or("about:blank");
                let record_wait = msg["options"]["record_wait_steps"].as_bool().unwrap_or(true);
                // Harvest API endpoints while recording (default on — it's how a user
                // clicks through the real flow to build a fast API). Set to false to skip.
                let capture_api = msg["options"]["capture_api"].as_bool().unwrap_or(true);
                println!("  ▶ Recording {}", url);

                match recorder.start_session(
                    url.to_string(),
                    record_wait,
                    tenant_id.clone(),
                ).await {
                    Ok(sid) => {
                        local_session_id = Some(sid.clone());
                        // Record relay_sid -> browser_sid so a backend-driven
                        // ai_session_close can harvest auth_session directly.
                        if let Some(ref map) = ai_session_browser_map {
                            map.insert(session_id.to_string(), sid.clone());
                        }

                        if let Some(mut session_ref) = recorder.get_session_mut(&sid) {
                            // Subscribe to screenshot broadcast and forward frames through relay
                            if let Some(ref tx) = session_ref.screenshot_tx {
                                let mut rx = tx.subscribe();
                                let relay_for_screenshots = relay.clone();
                                tokio::spawn(async move {
                                    loop {
                                        match rx.recv().await {
                                            Ok(frame) => {
                                                relay_for_screenshots.send_bytes(&frame).await;
                                            }
                                            Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
                                            Err(tokio::sync::broadcast::error::RecvError::Lagged(n)) => {
                                                tracing::debug!(lagged = n, "Screenshot relay lagged");
                                            }
                                        }
                                    }
                                });
                            }

                            // Subscribe to JSON events and forward through relay
                            // (step_recorded, navigation, select_options, sensitive_field, tab_list)
                            let (event_tx, mut event_rx) = tokio::sync::mpsc::unbounded_channel();
                            session_ref.event_tx = Some(event_tx);
                            let relay_for_events = relay.clone();
                            tokio::spawn(async move {
                                while let Some(event) = event_rx.recv().await {
                                    relay_for_events.send_json(event).await;
                                }
                            });
                        }

                        // Attach API capture (after event_tx is set so live events reach
                        // the frontend). Clone the context/sender/capture out of the session
                        // FIRST, then attach unlocked — never hold the DashMap RefMut across
                        // the async listener registration.
                        if capture_api {
                            let handles = recorder.get_session_mut(&sid).map(|s| {
                                (s.context.clone(), s.event_tx.clone(), s.network_capture.clone())
                            });
                            if let Some((context, Some(ev_tx), cap)) = handles {
                                attach_recording_network_capture(&context, cap, ev_tx).await;
                                println!("  ◆ API capture enabled for session {}", sid);
                            }
                        }

                        relay.send_json(serde_json::json!({
                            "type": "started",
                            "sessionId": sid,
                            "url": url,
                        })).await;
                        println!("  ✓ Browser session {} started", sid);
                    }
                    Err(e) => {
                        println!("  ✗ Failed to start browser: {}", e);
                        relay.send_json(serde_json::json!({
                            "type": "error",
                            "message": e.to_string(),
                        })).await;
                    }
                }
            }

            "action" => {
                if let Some(ref sid) = local_session_id {
                    // Coalesce a scroll backlog. Each mouse.wheel round-trip costs
                    // ~50ms, so a trackpad/momentum gesture (dozens of tiny wheel
                    // events per second) outruns serial processing and the queue
                    // grows without bound — the browser scrolls seconds behind the
                    // user. Drain every consecutively-queued scroll action into this
                    // one, summing deltas and taking the latest cursor position, then
                    // do a SINGLE wheel. Net scroll distance and the recorded
                    // consolidated-scroll step are unchanged (pending_scroll already
                    // accumulates delta_y); we just stop falling behind. Only flat
                    // {type:"action", action:"scroll", deltaX, deltaY, x, y} frames
                    // — the form the frontend actually sends.
                    if msg.get("action").and_then(|v| v.as_str()) == Some("scroll") {
                        let mut dx = msg.get("deltaX").and_then(|v| v.as_f64()).unwrap_or(0.0);
                        let mut dy = msg.get("deltaY").and_then(|v| v.as_f64()).unwrap_or(0.0);
                        let mut last_x = msg.get("x").cloned();
                        let mut last_y = msg.get("y").cloned();
                        let mut merged = 0u32;
                        while let Some(next) = relay.try_receive_json() {
                            let is_scroll = next.get("type").and_then(|v| v.as_str()) == Some("action")
                                && next.get("action").and_then(|v| v.as_str()) == Some("scroll");
                            if is_scroll {
                                dx += next.get("deltaX").and_then(|v| v.as_f64()).unwrap_or(0.0);
                                dy += next.get("deltaY").and_then(|v| v.as_f64()).unwrap_or(0.0);
                                if let Some(x) = next.get("x") { last_x = Some(x.clone()); }
                                if let Some(y) = next.get("y") { last_y = Some(y.clone()); }
                                merged += 1;
                            } else {
                                // Not mergeable — hand it back so ordering is preserved.
                                relay.push_back(next);
                                break;
                            }
                        }
                        if merged > 0 {
                            if let Some(obj) = msg.as_object_mut() {
                                obj.insert("deltaX".into(), serde_json::json!(dx));
                                obj.insert("deltaY".into(), serde_json::json!(dy));
                                if let Some(x) = last_x { obj.insert("x".into(), x); }
                                if let Some(y) = last_y { obj.insert("y".into(), y); }
                            }
                            tracing::debug!(session_id, merged, delta_y = dy, "Coalesced scroll backlog");
                        }
                    }

                    // Build the IncomingAction from the message. The frontend sends a
                    // FLAT message: {"type":"action", "action":"click", "x":.., "y":..}
                    // where `action` is a STRING naming the action type and the params
                    // are siblings. A gateway MAY instead wrap it as
                    // {"type":"action", "action":{"type":"click", ...}}. Handle both.
                    use crate::recorder::action_handler::IncomingAction;
                    let action: Option<IncomingAction> = match msg.get("action") {
                        // Flat form — action type is the string, data is the whole msg.
                        Some(serde_json::Value::String(action_type)) => {
                            let data: std::collections::HashMap<String, serde_json::Value> =
                                serde_json::from_value(msg.clone()).unwrap_or_default();
                            Some(IncomingAction {
                                action_type: action_type.clone(),
                                data,
                            })
                        }
                        // Nested form — action type from inner "type", data is inner obj.
                        Some(obj @ serde_json::Value::Object(_)) => {
                            let action_type = obj
                                .get("type")
                                .and_then(|v| v.as_str())
                                .unwrap_or("")
                                .to_string();
                            let data: std::collections::HashMap<String, serde_json::Value> =
                                serde_json::from_value(obj.clone()).unwrap_or_default();
                            Some(IncomingAction { action_type, data })
                        }
                        _ => {
                            tracing::warn!(session_id, "Action message missing 'action' field");
                            None
                        }
                    };

                    // Async acquire — this runs ON the bridge's frame loop and the
                    // guard is then held across every await of the action. A
                    // blocking acquire parks the worker thread, and a Playwright
                    // event handler blocking on the same shard completes a circular
                    // wait that wedges the whole session mid-navigation. See
                    // `recorder::session_lock`; the local record transport and
                    // `api::ws_record` carry the identical fix.
                    let session_guard = match action.as_ref() {
                        Some(_) => recorder.get_session_mut_async(sid).await,
                        None => None,
                    };
                    if let (Some(action), Some(mut session)) = (action, session_guard) {
                        let result = crate::recorder::action_handler::handle_action(
                            session.value_mut(),
                            action,
                        ).await;
                        if let Some(ref err) = result.error {
                            relay.send_json(serde_json::json!({
                                "type": "error",
                                "message": err,
                            })).await;
                        }
                        if let Some(ref data) = result.data {
                            // eval results for script testing
                            if data.get("eval_result").is_some() {
                                relay.send_json(serde_json::json!({
                                    "type": "eval_result",
                                    "result": data.get("eval_result"),
                                    "error": data.get("error"),
                                })).await;
                            }
                            // Live element picker (check wizard) — mirrors the
                            // Python bridge's element_info/dom_content frames.
                            if let Some(info) = data.get("element_info") {
                                if let Some(obj) = info.as_object() {
                                    let mut frame = serde_json::Map::new();
                                    frame.insert("type".into(), serde_json::json!("element_info"));
                                    for (k, v) in obj {
                                        frame.insert(k.clone(), v.clone());
                                    }
                                    relay.send_json(serde_json::Value::Object(frame)).await;
                                }
                            }
                            if let Some(elements) = data.get("elements_in_region") {
                                relay.send_json(serde_json::json!({
                                    "type": "elements_in_region",
                                    "elements": elements,
                                })).await;
                            }
                            if let Some(html) = data.get("dom_content") {
                                relay.send_json(serde_json::json!({
                                    "type": "dom_content",
                                    "html": if html.is_null() { serde_json::json!("") } else { html.clone() },
                                })).await;
                            }
                            // Payloads that are already a complete UI frame (select /
                            // picker overlays, the extraction highlight box, a live
                            // extract test result) → forward directly so the frontend
                            // can render them. One shared allowlist with the local
                            // record driver so neither transport can silently lack a
                            // frame the other forwards.
                            if let Some(dtype) = data.get("type").and_then(|v| v.as_str()) {
                                if crate::recorder::action_handler::is_passthrough_frame(dtype) {
                                    relay.send_json(data.clone()).await;
                                }
                            }
                        }
                    }
                }
            }

            // AI scraper builder: execute ephemeral action(s) on the live page
            // WITHOUT recording workflow steps, then return per-action results plus
            // a compact observation for the model's next decision. 1:1 port of the
            // Python recorder handle_agent_action / _run_agent_action /
            // _build_agent_observation. Step recording is structurally suppressed on
            // this path — it drives the page directly and the action_executor
            // fallback returns results without ever touching session.steps or the
            // _record_step* helpers.
            "agent_action" => {
                if let Some(ref sid) = local_session_id {
                    let request_id = msg.get("request_id").cloned().unwrap_or(serde_json::Value::Null);

                    // Clone the page out of the session under a BRIEF lock, then drop
                    // the DashMap RefMut BEFORE any async page I/O. Holding a
                    // get_mut() guard across an `.await` starves tokio workers and
                    // deadlocks (see "Rust Port — Concurrency Gotchas").
                    let page = recorder.get_session_mut(sid).map(|s| s.page.clone());

                    // Autonomous (backend-orchestrated) sessions get READ-ONLY
                    // evaluate_js; the interactive scraper-builder (no browser map)
                    // keeps full raw JS so its complex-scrape scripts (.click()/
                    // history.back() inside evaluate) still work.
                    let read_only = ai_session_browser_map.is_some();
                    let response = match page {
                        Some(page) => {
                            let (results, observation) =
                                crate::automation::run_agent_actions(&page, &msg, read_only).await;
                            serde_json::json!({
                                "type": "agent_action_result",
                                "request_id": request_id,
                                "session_id": session_id,
                                "results": results,
                                "observation": observation,
                            })
                        }
                        None => serde_json::json!({
                            "type": "agent_action_result",
                            "request_id": request_id,
                            "session_id": session_id,
                            "results": [],
                            "observation": serde_json::Value::Null,
                            "error": "Session not found",
                        }),
                    };
                    // Backend-orchestrated sessions (ai_session_browser_map is Some)
                    // correlate on a TOP-LEVEL frame; the frontend assist loop
                    // correlates through the relay-wrapped {channel:"session"}
                    // envelope. Route accordingly.
                    if ai_session_browser_map.is_some() {
                        relay.send_json_toplevel(response).await;
                    } else {
                        relay.send_json(response).await;
                    }
                }
            }

            // Visual replay ("play to here"): re-execute the supplied recorded
            // steps 0..up_to_index on the LIVE page, streaming replay_progress
            // frames. Runs in a spawned task so a concurrent `replay_cancel`
            // frame can interrupt it (the session loop keeps reading frames).
            // 1:1 port of the Python recorder handle_replay_steps.
            "replay_steps" => {
                if let Some(ref sid) = local_session_id {
                    let request_id = msg.get("request_id").cloned().unwrap_or(serde_json::Value::Null);
                    // Clone the page + cancel flag under a BRIEF lock; drop the
                    // DashMap guard BEFORE the spawn/await (never hold it across .await).
                    let pc = recorder.get_session_mut(sid).map(|s| {
                        s.replay_cancel.store(false, std::sync::atomic::Ordering::Relaxed);
                        (s.page.clone(), s.replay_cancel.clone())
                    });
                    match pc {
                        None => {
                            relay.send_json(serde_json::json!({
                                "type": "replay_error",
                                "request_id": request_id,
                                "error": "No active session",
                            })).await;
                        }
                        Some((page, cancel)) => {
                            let steps = msg.get("steps").and_then(|v| v.as_array())
                                .cloned().unwrap_or_default();
                            let up_to = msg.get("up_to_index").and_then(|v| v.as_i64()).unwrap_or(0);
                            let delay_ms = msg.get("step_delay_ms").and_then(|v| v.as_u64()).unwrap_or(300);
                            let relay2 = relay.clone();
                            tokio::spawn(async move {
                                run_replay_steps(relay2, page, cancel, steps, up_to, delay_ms, request_id).await;
                            });
                        }
                    }
                }
            }

            // Cooperative cancel for an in-flight visual replay.
            "replay_cancel" => {
                if let Some(ref sid) = local_session_id {
                    if let Some(s) = recorder.get_session_mut(sid) {
                        s.replay_cancel.store(true, std::sync::atomic::Ordering::Relaxed);
                    }
                }
            }

            "stop" => {
                if let Some(ref sid) = local_session_id {
                    match recorder.end_session(sid).await {
                        Ok(result) => {
                            let steps: Vec<serde_json::Value> = result.steps
                                .iter()
                                .map(|s| serde_json::to_value(s).unwrap_or_default())
                                .collect();
                            let raw_replay: Vec<serde_json::Value> = result.raw_replay
                                .iter()
                                .map(|s| serde_json::to_value(s).unwrap_or_default())
                                .collect();
                            let network_calls: Vec<serde_json::Value> = result.network_calls
                                .iter()
                                .map(|c| serde_json::to_value(c).unwrap_or_default())
                                .collect();

                            relay.send_json(serde_json::json!({
                                "type": "stopped",
                                "steps": steps,
                                "stepCount": result.step_count,
                                "raw_replay": raw_replay,
                                "rawReplayCount": result.raw_replay_count,
                                "network_calls": network_calls,
                                "network_calls_count": result.network_calls.len(),
                            })).await;
                        }
                        Err(e) => {
                            relay.send_json(serde_json::json!({
                                "type": "error",
                                "message": e.to_string(),
                            })).await;
                        }
                    }
                    break;
                }
            }

            "ping" => {
                relay.send_json(serde_json::json!({"type": "pong"})).await;
            }

            _ => {
                tracing::debug!(msg_type, session_id, "Unknown session message type");
            }
        }
    }

    // Cleanup: end any active browser session
    if let Some(ref sid) = local_session_id {
        if recorder.get_session_mut(sid).is_some() {
            let _ = recorder.end_session(sid).await;
        }
    }
    tracing::info!(session_id, "Session loop ended");
}

// ---------------------------------------------------------------------------
// AI scraper builder — ephemeral agent actions (no step recording)
// Port of Python recorder.handle_agent_action / _run_agent_action /
// _build_agent_observation.
// ---------------------------------------------------------------------------

/// Deterministically let the page settle after a mutating action, fully bounded so
/// it can never hang. Navigating actions wait for the new document; all allow a
/// brief network-quiet window so SPA/XHR re-renders land before the next selector.
async fn settle_page(page: &playwright_rs::Page, navigated: bool) {
    use std::time::Duration;
    if navigated {
        let _ = tokio::time::timeout(
            Duration::from_secs(8),
            crate::browser::navigation::wait_for_load_state(page, "domcontentloaded", Duration::from_secs(8)),
        )
        .await;
    }
    // networkidle can stall on long-poll/streaming pages, so keep it short and
    // treat a timeout as "settled enough".
    let _ = tokio::time::timeout(
        Duration::from_millis(2500),
        crate::browser::navigation::wait_for_load_state(page, "networkidle", Duration::from_millis(2500)),
    )
    .await;
}

/// Recorded-step types we deliberately DON'T re-run on the live page during a
/// visual replay: they need a real run context (server-minted 2FA / secrets),
/// have side effects outside the browser (HTTP/file), are pure data reads that
/// don't move the cursor, or are tab-orchestration markers that don't replay
/// cleanly in a single-page recording session. Mirrors the Python recorder.
fn replay_skippable(step_type: &str) -> bool {
    matches!(
        step_type,
        "twofa" | "api_call" | "upload" | "wait_for_download"
            | "screenshot" | "return" | "end_point" | "codegen"
            | "open_tab" | "switch_tab" | "tab_closed" | "wait_for_tab"
            | "evaluate" | "extract"
    )
}

/// Best-effort execute ONE recorded step on the live page. Returns
/// `(status, reason)` where status is "done" | "skipped" | "failed". Never
/// panics — a failure is captured so the replay loop can keep going and the page
/// still lands as close to the target as possible. 1:1 with the Python
/// `_replay_one_recorded_step`.
async fn replay_one_recorded_step(
    page: &playwright_rs::Page,
    step: &serde_json::Value,
) -> (&'static str, Option<String>) {
    use crate::browser::{navigation, page_actions};
    use std::time::Duration;

    let stype = step.get("type").and_then(|v| v.as_str()).unwrap_or("").trim();
    let selector = step.get("selector").and_then(|v| v.as_str()).unwrap_or("");
    let value = step.get("value").and_then(|v| v.as_str());
    let options = step.get("options");

    if stype.is_empty() || replay_skippable(stype) {
        let label = if stype.is_empty() { "unknown" } else { stype };
        return ("skipped", Some(format!("{} not replayable here", label)));
    }

    let is_template = |v: Option<&str>| v.is_some_and(|s| s.contains("{{") && s.contains("}}"));
    let opt_bool = |k: &str| {
        options
            .and_then(|o| o.get(k))
            .and_then(|v| v.as_bool())
            .unwrap_or(false)
    };

    let res: anyhow::Result<(&'static str, Option<String>)> = async {
        match stype {
            "navigate" | "navigated_to" => {
                let url = step.get("url").and_then(|v| v.as_str()).or(value);
                let url = match url {
                    Some(u) if !u.is_empty() => u,
                    _ => return Ok(("skipped", Some("no url".to_string()))),
                };
                // Top-level navigation must use the fail-CLOSED, DNS-resolving guard (not the
                // fail-open subresource variant `is_url_safe`): a mid-workflow navigate to an internal
                // host that is transiently unresolvable / split-horizon must be refused, not allowed.
                if !crate::security::url_guard::is_navigation_url_safe_async(url).await {
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
                // A {{secret:}}/{{field}} placeholder or sensitive field has no
                // value outside a real run — skip rather than type the literal.
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
                // Re-establishing position: a bounded settle is enough.
                settle_page(page, false).await;
                Ok(("done", None))
            }
            other => Ok(("skipped", Some(format!("{} not replayable here", other)))),
        }
    }
    .await;

    match res {
        Ok(t) => t,
        Err(e) => ("failed", Some(truncate_str(&e.to_string(), 200))),
    }
}

/// Replay recorded steps 0..up_to_index on the live page, streaming a
/// `replay_progress` frame per step and a final `replay_done`. Spawned as its own
/// task so a concurrent `replay_cancel` frame (checked via `cancel`) can stop it
/// between steps. 1:1 with the Python `handle_replay_steps`.
async fn run_replay_steps(
    relay: Arc<AgentSessionRelay>,
    page: playwright_rs::Page,
    cancel: Arc<std::sync::atomic::AtomicBool>,
    steps: Vec<serde_json::Value>,
    up_to_index: i64,
    step_delay_ms: u64,
    request_id: serde_json::Value,
) {
    use std::sync::atomic::Ordering;

    let n = steps.len() as i64;
    let target = if n == 0 { -1 } else { up_to_index.clamp(0, n - 1) };
    if target < 0 {
        relay
            .send_json(serde_json::json!({
                "type": "replay_done", "request_id": request_id,
                "replayed": 0, "skipped": 0, "failed": 0, "cancelled": false,
                "stopped_at": serde_json::Value::Null, "url": page.url(),
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
            relay
                .send_json(serde_json::json!({
                    "type": "replay_progress", "request_id": request_id,
                    "index": i, "status": "cancelled", "total": total,
                }))
                .await;
            break;
        }
        let step = &steps[i as usize];
        // Disabled steps are skipped at run time — mirror that here.
        if step.get("enabled") == Some(&serde_json::Value::Bool(false)) {
            skipped += 1;
            relay
                .send_json(serde_json::json!({
                    "type": "replay_progress", "request_id": request_id,
                    "index": i, "status": "skipped", "reason": "disabled", "total": total,
                }))
                .await;
            continue;
        }
        relay
            .send_json(serde_json::json!({
                "type": "replay_progress", "request_id": request_id,
                "index": i, "status": "running", "total": total,
            }))
            .await;
        // Generous per-step ceiling: a slow navigate is goto(30s) + settle(~10s);
        // the inner ops are individually bounded, this just backstops a hang.
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
        relay
            .send_json(serde_json::json!({
                "type": "replay_progress", "request_id": request_id,
                "index": i, "status": status, "reason": reason, "total": total,
            }))
            .await;
        if delay_ms > 0 && i < target {
            tokio::time::sleep(std::time::Duration::from_millis(delay_ms)).await;
        }
    }

    relay
        .send_json(serde_json::json!({
            "type": "replay_done", "request_id": request_id,
            "replayed": replayed, "skipped": skipped, "failed": failed,
            "cancelled": cancelled, "stopped_at": target, "url": page.url(),
        }))
        .await;
}


// ---------------------------------------------------------------------------
// Task handlers — exact ports of Python SaaSBridge._handle_*
// ---------------------------------------------------------------------------


/// Extract a `task_id` as a faithful string regardless of its JSON type.
///
/// The backend sends `task_id` as a JSON **number** (the AutomationTask row id)
/// for execute_workflow / execute_ai_task, but as a **string** (e.g.
/// `stream-<key>`) for streaming. `Value::as_str()` returns None for a number,
/// so the old `.as_str().unwrap_or("?")` turned every numeric task_id into "?".
/// The agent then echoed "?" back in task_result, the backend's
/// `int(str(task_id))` lookup (user_recorder_ws._handle_task_result) failed, and
/// the run was never marked complete/failed — it stayed "running" in the UI.
/// This mirrors the Python agent, which uses `msg.get("task_id")` verbatim. An
/// integer stringifies to e.g. "12345", which `int(str(...))` parses cleanly.
fn task_id_str(v: &serde_json::Value) -> String {
    match v {
        serde_json::Value::String(s) => s.clone(),
        serde_json::Value::Number(n) => n.to_string(),
        serde_json::Value::Null => String::new(),
        other => other.to_string(),
    }
}

/// Execute a recorded workflow dispatched over the wire: decrypt creds, create a stealth context,
/// navigate to entry_url, iterate the steps, capture auth, send `task_result`. Thin cloud-transport
/// shim over the SHARED executor [`crate::bridge::wire_exec::handle_execute_workflow`] (the fleet
/// bridge runs the same one): this wrapper supplies the `BridgeOutgoing` frame sink and the
/// device-flow channel key (the per-agent Fernet key that opens `credentials_encrypted`).
pub(crate) async fn handle_execute_workflow(
    task_id: &str,
    msg: &serde_json::Value,
    browser_mgr: &Arc<BrowserManager>,
    outgoing: &mpsc::UnboundedSender<BridgeOutgoing>,
    artifact_ctx: Option<crate::automation::files::ArtifactContext>,
) {
    let channel_key = auth::load_credentials().and_then(|c| {
        c.get("channel_key")
            .and_then(|v| v.as_str())
            .filter(|k| !k.is_empty())
            .map(String::from)
    });
    let out = outgoing.clone();
    let send = move |v: serde_json::Value| {
        let _ = out.send(BridgeOutgoing::Json(v));
    };
    crate::bridge::wire_exec::handle_execute_workflow(
        task_id,
        msg,
        browser_mgr,
        &send,
        artifact_ctx,
        channel_key.as_deref(),
    )
    .await;
}


/// Execute an AI task: create stealth context, navigate, run the appropriate
/// AI mode (standard/intelligent/api_discovery), send result.
async fn handle_execute_ai_task(
    task_id: &str,
    msg: &serde_json::Value,
    browser_mgr: &Arc<BrowserManager>,
    outgoing: &mpsc::UnboundedSender<BridgeOutgoing>,
    ai_pending: &Arc<dashmap::DashMap<String, tokio::sync::oneshot::Sender<serde_json::Value>>>,
    tenant_id: Option<&str>,
) {
    tracing::info!(task_id, "Executing AI task");

    let config = &msg["config"];
    let url = config["url"].as_str().unwrap_or("about:blank");
    let goal = config["goal"].as_str().unwrap_or("");
    let mode = config["mode"].as_str().unwrap_or("intelligent");
    let max_steps = config["max_steps"].as_u64().unwrap_or(20) as usize;
    let max_actions = config["max_actions"].as_u64().unwrap_or(50) as usize;
    let use_vision = config["use_vision"].as_bool().unwrap_or(true);
    let tenant = tenant_id.unwrap_or("");

    // Resolve credentials and form data
    let credentials = resolve_credentials(config);
    let mut form_data: HashMap<String, String> = config.get("form_data")
        .and_then(|v| serde_json::from_value(v.clone()).ok())
        .unwrap_or_default();
    let available_data: HashMap<String, String> = config.get("available_data")
        .and_then(|v| serde_json::from_value(v.clone()).ok())
        .unwrap_or_default();
    let secure_keys: Vec<String> = config.get("secure_keys")
        .and_then(|v| serde_json::from_value(v.clone()).ok())
        .unwrap_or_default();
    let user_context = config.get("user_context").and_then(|v| v.as_str()).map(String::from);

    // Merge credentials into form_data so the AI modes have access
    for (k, v) in &credentials {
        form_data.entry(k.clone()).or_insert_with(|| v.clone());
    }

    // Per-run BYO persona proxy: read the reserved `__proxy__` object from the run
    // credentials (backend-gated). When present this context egresses through the
    // consumer's residential proxy; None → env proxy / direct. Parity with Python.
    let proxy_override = extract_proxy_override(config);

    // Honor an EXPLICIT per-session headless setting (relaunch the warm browser in
    // that mode if it differs). Conservative: only act when the backend actually
    // sent `headless` — absent means "leave the warm browser as-is", so a globally
    // headed setup is never forced back to headless.
    if let Some(headless) = config.get("headless").and_then(|v| v.as_bool()) {
        if let Err(e) = browser_mgr.ensure_warm_browser_with(headless).await {
            let _ = outgoing.send(BridgeOutgoing::Json(serde_json::json!({
                "type": "task_result",
                "task_id": task_id,
                "success": false,
                "error": format!("Browser launch failed: {}", e),
            })));
            println!("  ✗ AI task #{} failed: {}", task_id, e);
            return;
        }
    }

    // Create stealth browser context (1:1 with Python — random fingerprint per context).
    let (context, page) = match browser_mgr.create_stealth_context_with_proxy(proxy_override).await {
        Ok(cp) => cp,
        Err(e) => {
            let _ = outgoing.send(BridgeOutgoing::Json(serde_json::json!({
                "type": "task_result",
                "task_id": task_id,
                "success": false,
                "error": format!("Browser context failed: {}", e),
            })));
            println!("  ✗ AI task #{} failed: {}", task_id, e);
            return;
        }
    };

    // SECURITY (SSRF): vet the tenant-supplied target URL before the top-level navigation. The browser
    // route-blocker only inspects subresources AFTER navigation is underway, so the entry URL must be
    // fail-closed checked here — mirroring the workflow lane — else an AI task pointed at
    // http://169.254.169.254/… or an internal host would navigate there and surface the response as
    // agent context.
    if !crate::security::url_guard::is_navigation_url_safe_async(url).await {
        let _ = context.close().await;
        let _ = outgoing.send(BridgeOutgoing::Json(serde_json::json!({
            "type": "task_result",
            "task_id": task_id,
            "success": false,
            "error": format!("Refused unsafe URL: {}", url),
        })));
        println!("  ✗ AI task #{} refused unsafe URL: {}", task_id, url);
        return;
    }

    // Navigate to target URL
    if let Err(e) = crate::browser::navigation::goto(
        &page, url, "domcontentloaded",
        std::time::Duration::from_secs(30),
    ).await {
        let _ = context.close().await;
        let _ = outgoing.send(BridgeOutgoing::Json(serde_json::json!({
            "type": "task_result",
            "task_id": task_id,
            "success": false,
            "error": format!("Navigation failed: {}", e),
        })));
        println!("  ✗ AI task #{} failed: navigation to {}", task_id, url);
        return;
    }

    // Create a BridgeAIClient for AI completions through the bridge WS.
    // Echo the initiating api_key_id (if any) so the gateway bills per key.
    let api_key_id = config.get("api_key_id").and_then(|v| {
        v.as_str().map(String::from).or_else(|| v.as_i64().map(|n| n.to_string()))
    });
    let ai_client = BridgeAIClient::new(outgoing.clone(), ai_pending.clone())
        .with_api_key(api_key_id);

    // Run the appropriate AI mode
    let result_data: serde_json::Value = match mode {
        "standard" => {
            let ai_config = crate::ai::standard_mode::StandardModeConfig {
                goal: goal.to_string(),
                available_data: available_data.clone(),
                fill_data: form_data.clone(),
                max_steps,
                use_vision,
                tenant_id: tenant.to_string(),
                secure_keys: secure_keys.clone(),
            };
            // Drive standard mode through the bridge WS via the AiClient trait.
            match crate::ai::standard_mode::ai_generate_workflow(
                &page, ai_config, Some(&ai_client),
            ).await {
                Ok(result) => {
                    serde_json::json!({
                        "success": result.success,
                        "steps": result.steps,
                        "raw_replay": result.raw_replay,
                        "endpoint": result.endpoint,
                        "error": result.error,
                    })
                }
                Err(e) => {
                    serde_json::json!({
                        "success": false,
                        "error": e.to_string(),
                    })
                }
            }
        }

        "intelligent" => {
            let ai_config = crate::ai::intelligent_mode::IntelligentModeConfig {
                goal: goal.to_string(),
                user_context,
                available_data: available_data.clone(),
                fill_data: form_data.clone(),
                max_actions,
                secure_keys,
                tenant_id: tenant.to_string(),
            };
            match crate::ai::intelligent_mode::ai_generate_workflow_intelligent(
                &page, ai_config, Some(&ai_client),
            ).await {
                Ok(result) => {
                    serde_json::json!({
                        "success": result.success,
                        "steps": result.steps,
                        "raw_replay": result.raw_replay,
                        "endpoint": result.endpoint,
                        "error": result.error,
                    })
                }
                Err(e) => {
                    serde_json::json!({
                        "success": false,
                        "error": e.to_string(),
                    })
                }
            }
        }

        "api_discovery" => {
            let ai_config = crate::ai::api_discovery_mode::ApiDiscoveryConfig {
                goal: goal.to_string(),
                user_context: user_context.clone(),
                available_data: available_data.clone(),
                fill_data: form_data.clone(),
                max_actions,
                tenant_id: tenant.to_string(),
                secure_keys: secure_keys.clone(),
            };
            match crate::ai::api_discovery_mode::ai_discover_api(
                &page, &context, ai_config, Some(&ai_client),
            ).await {
                Ok(result) => {
                    serde_json::json!({
                        "success": result.success,
                        "api_functions": result.api_functions,
                        "steps": result.steps,
                        "error": result.error,
                        "server_rendered_pages": result.server_rendered_pages,
                    })
                }
                Err(e) => {
                    serde_json::json!({
                        "success": false,
                        "error": e.to_string(),
                    })
                }
            }
        }

        other => {
            tracing::warn!(mode = other, "Unknown AI mode, defaulting to intelligent");
            serde_json::json!({
                "success": false,
                "error": format!("Unknown AI mode: {}", other),
            })
        }
    };

    let success = result_data.get("success").and_then(|v| v.as_bool()).unwrap_or(false);
    let error = result_data.get("error").and_then(|v| v.as_str()).map(String::from);

    let result_msg = serde_json::json!({
        "type": "task_result",
        "task_id": task_id,
        "success": success,
        "result_data": result_data,
        "error": error,
    });
    let _ = outgoing.send(BridgeOutgoing::Json(result_msg));

    if success {
        let step_count = result_data.get("steps")
            .and_then(|v| v.as_array())
            .map(|a| a.len())
            .unwrap_or(0);
        println!("  ✓ AI task #{} completed — {} steps ({})", task_id, step_count, mode);
    } else {
        println!("  ✗ AI task #{} failed: {}", task_id,
                 error.as_deref().unwrap_or("unknown"));
    }

    // Cleanup
    let _ = context.close().await;
}

/// Start a streaming session: create stealth context, execute setup steps,
/// inject streaming runtime, then handle commands via page.evaluate() dispatch.
fn urlencoding(s: &str) -> String {
    url::form_urlencoded::byte_serialize(s.as_bytes()).collect()
}

#[cfg(test)]
mod tests {
    use super::{require_secure_url, strip_port};

    #[test]
    fn strip_port_variants() {
        assert_eq!(strip_port("localhost"), "localhost");
        assert_eq!(strip_port("localhost:8080"), "localhost");
        assert_eq!(strip_port("127.0.0.1:9000"), "127.0.0.1");
        assert_eq!(strip_port("[::1]"), "::1");
        assert_eq!(strip_port("[::1]:8080"), "::1");
        assert_eq!(strip_port("example.com:443"), "example.com");
    }

    #[test]
    fn require_secure_url_allows_https_and_wss() {
        assert!(require_secure_url("https://api.example.com", false, "saas").is_ok());
        assert!(require_secure_url("wss://gw.example.com/ws", false, "saas").is_ok());
    }

    #[test]
    fn require_secure_url_allows_real_loopback() {
        assert!(require_secure_url("http://localhost:8080", false, "saas").is_ok());
        assert!(require_secure_url("ws://127.0.0.1:9000/ws", false, "saas").is_ok());
        assert!(require_secure_url("http://[::1]:8080", false, "saas").is_ok());
    }

    #[test]
    fn require_secure_url_rejects_localhost_prefix_spoof() {
        // AC-4: a prefix match would treat these as "local" and ship the bearer
        // token in cleartext to an EXTERNAL host. They MUST be rejected.
        assert!(require_secure_url("http://localhost.evil.com/steal", false, "saas").is_err());
        assert!(require_secure_url("http://127.0.0.1.evil.com/steal", false, "saas").is_err());
        assert!(require_secure_url("ws://localhost-evil.com", false, "saas").is_err());
        // userinfo trick: real host is evil.com, not localhost.
        assert!(require_secure_url("http://localhost@evil.com/", false, "saas").is_err());
    }

    #[test]
    fn require_secure_url_allow_insecure_opt_in() {
        // Explicit operator opt-in bypasses the check on a trusted private network.
        assert!(require_secure_url("http://internal-box:8080", true, "saas").is_ok());
    }
}
