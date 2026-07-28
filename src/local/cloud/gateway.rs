//! `LinkedAgentBridge` — the desktop daemon's outbound link that lets **Writ Cloud** invoke this
//! machine's OWN local workflows by id (the "cloud-callable LOCAL workflows" feature).
//!
//! Shape mirrors the cloud `bridge/saas_bridge::SaaSBridge` connect/handshake/listen skeleton
//! (two-step connect → welcome frame → read loop with auto-reconnect + full-jitter backoff), but the
//! payloads are different and the auth is the LINKED-ACCOUNT cloud token, not the cloud-build
//! credentials file:
//!   * Step 1 authenticates `POST {base_url}/api/recorder/connect` with the `wto_` cloud account
//!     access token ([`super::token::get`]); a 401 drives a single refresh via [`CloudClient`].
//!   * Step 2 opens the gateway WS with `role=recorder` and the gateway JWT in the `Authorization`
//!     header (NEVER the URL), then reads the `welcome` frame for the assigned `agent_id`.
//!
//! SECURITY INVARIANT (the never-trust-a-BYO-agent rule):
//!   * Identity/billing/metering/success-truth live in the backend + gateway. The gateway STAMPS the
//!     authenticated `agent_id` onto every frame it publishes; the backend trusts ONLY the
//!     token-derived `tenant_id`/`agent_id`, never anything in our message body.
//!   * The advertised catalog is METADATA ONLY — declared inputs + declared output fields. Workflow
//!     STEPS and CREDENTIALS are NEVER serialized into a catalog frame. The run path loads the
//!     recipe locally by id and executes in-process; the recipe never crosses the wire.
//!
//! The assigned `agent_id` is non-secret routing metadata, so it is persisted in the encrypted
//! `config` kv table (a NEW slot, [`LINKED_AGENT_ID_KEY`]) — NOT in the cloud-build credentials file
//! and NOT in the keyring (which holds only the secret `wto_`/`wtr_` token pair).
//!
//! Net-new Rust in this crate, behind the `local` cargo feature.

use std::sync::Arc;
use std::time::Instant;

use futures_util::{SinkExt, StreamExt};
use serde_json::{json, Value};
use sqlx::sqlite::SqlitePool;
use tokio::sync::{mpsc, Mutex, Notify};
use tokio::task::JoinHandle;
use tokio_tungstenite::tungstenite::Message;

use super::super::engine::{Lane, LocalEngine, RunRequest, RunSource};
use super::super::store::{config_kv, workflows};
use super::client::CloudClient;
use super::state::LinkState;

/// Reserved `config` kv key under which the gateway-assigned recorder `agent_id` is persisted, so the
/// same id is reused across daemon restarts (gateway honors a re-presented id for warm affinity).
/// Non-secret routing metadata — never holds token material.
///
/// DEFINED in [`crate::local::store::config_kv`] alongside the other `config` row names and
/// re-exported here so this module (and its doc links) keep referring to it by the same path. A
/// non-cloud module that only needs the key name imports it from `config_kv`, not from here.
pub use crate::local::store::config_kv::LINKED_AGENT_ID_KEY;

type WsStream =
    tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>;

/// Char-safe truncation for logging wire-derived strings (a malicious gateway could otherwise crash
/// the agent with a multibyte id sliced mid-codepoint). Mirrors `saas_bridge::truncate_str`.
fn truncate_str(s: &str, max_chars: usize) -> String {
    s.chars().take(max_chars).collect()
}

/// Refuse a plaintext endpoint outside local dev: plaintext would expose the bearer token and every
/// frame on the wire. Accept `wss://`/`https://`, a loopback host, or an explicit opt-in. Mirrors
/// `saas_bridge::require_secure_url` (kept local so the bridge stays self-contained).
fn require_secure_url(url: &str, allow_insecure: bool, what: &str) -> anyhow::Result<()> {
    let lower = url.trim().to_lowercase();
    if lower.starts_with("wss://") || lower.starts_with("https://") {
        return Ok(());
    }
    let after = lower.splitn(2, "://").nth(1).unwrap_or(lower.as_str());
    let authority = after.split(['/', '?', '#']).next().unwrap_or("");
    let hostport = authority.rsplit('@').next().unwrap_or(authority);
    let is_local = hostport.starts_with("localhost")
        || hostport.starts_with("127.")
        || hostport.starts_with("0.0.0.0")
        || hostport.starts_with("[::1]")
        || hostport == "::1";
    if allow_insecure || is_local {
        return Ok(());
    }
    anyhow::bail!(
        "Refusing insecure {what} URL '{url}': plaintext would expose the cloud token and all \
         session traffic on the wire. Use a wss://https:// endpoint."
    )
}

/// Minimal percent-encoding for query-string values (the agent_id routing hint). Mirrors
/// `saas_bridge::urlencoding`.
fn urlencoding(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char)
            }
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

/// Coerce a wire `task_id` (string OR number) to a String faithfully — the dispatch echoes it back
/// in `task_result` so the backend can correlate. Mirrors `saas_bridge::task_id_str`.
fn task_id_str(v: &Value) -> String {
    match v {
        Value::String(s) => s.clone(),
        Value::Number(n) => n.to_string(),
        Value::Null => String::new(),
        other => other.to_string(),
    }
}

/// Shared, NON-SECRET connection state the running [`LinkedAgentBridge`] publishes so the
/// [`super::agent::manager::LinkedAgentManager`] status endpoint can report the REAL liveness
/// (connected + welcomed vs. retrying) and the last connect error — instead of an optimistic "online"
/// that only meant "the supervisor is attempting to run the bridge" (which made a failing connect, e.g.
/// a 422 from a bad connect body, look healthy). Written by the bridge from its connect/reconnect loop
/// (the lock is held ONLY across a sync section, never across an `.await`); read synchronously by the
/// status snapshot. Carries no token / channel-key / credential material.
#[derive(Default)]
pub struct BridgeStatus {
    connected: std::sync::atomic::AtomicBool,
    last_error: std::sync::Mutex<Option<String>>,
}

impl BridgeStatus {
    /// True only when the gateway WS is up AND the `welcome` handshake completed — the agent is truly
    /// live (an `agent_id` was assigned). NOT merely "the supervisor is trying to connect".
    pub fn is_connected(&self) -> bool {
        self.connected.load(std::sync::atomic::Ordering::Relaxed)
    }

    /// The last connect/transport error (non-secret), surfaced while the agent is not connected so the
    /// UI can show WHY (e.g. `HTTP 422` from a rejected connect body). `None` once connected.
    pub fn last_error(&self) -> Option<String> {
        self.last_error.lock().ok().and_then(|g| g.clone())
    }

    /// Mark the bridge CONNECTED (WS up + welcomed): clears any stale error.
    fn mark_connected(&self) {
        self.connected.store(true, std::sync::atomic::Ordering::Relaxed);
        if let Ok(mut g) = self.last_error.lock() {
            *g = None;
        }
    }

    /// Mark the bridge DISCONNECTED. `Some(err)` records WHY (char-safe); `None` is a clean close that
    /// leaves the last recorded error untouched. `pub` because the manager also drives this on
    /// supervisor-side transitions (stop / precondition-fail / select-cancel) where the bridge future
    /// may be dropped before it can mark itself offline. Only the bridge marks CONNECTED (private).
    pub fn mark_disconnected(&self, err: Option<String>) {
        self.connected.store(false, std::sync::atomic::Ordering::Relaxed);
        if let Some(e) = err {
            if let Ok(mut g) = self.last_error.lock() {
                *g = Some(truncate_str(&e, 240));
            }
        }
    }
}

/// Why [`LinkedAgentBridge::run`] returned, so the supervisor can tell "park until re-link" apart
/// from "rebuild is fine". Without this the supervisor rebuilt a fresh bridge after EVERY exit —
/// including the Unauthorized one, where `CloudClient::connect()` fails instantly (cleared keyring
/// token, no network round-trip), which turned one revoked token into a ~500 Hz
/// rebuild/error-log storm.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BridgeExit {
    /// Clean stop: `shutdown()` was called, or the server closed a healthy long-lived session.
    /// The supervisor may rebuild/reconnect if still desired-running.
    Stopped,
    /// The cloud link is unauthorized (token cleared on `invalid_grant` / revoked server-side).
    /// Reconnecting is doomed until the user re-links — the supervisor must PARK, not rebuild.
    Unauthorized,
}

/// The outbound link from this daemon to Writ Cloud for cloud-callable local workflows.
///
/// Holds the in-process [`LocalEngine`] (to run workflows by id) and the encrypted [`SqlitePool`]
/// (to read the `cloud_callable` catalog + persist the assigned agent_id). Spawned by `writ-agentd`
/// ONLY when the desktop is cloud-linked AND `cloud_expose_workflows` is on.
pub struct LinkedAgentBridge {
    engine: Arc<dyn LocalEngine>,
    db: SqlitePool,
    /// Cloud link metadata (base url resolution). Loaded at construction; never holds a token.
    link: Option<LinkState>,
    /// Allow plaintext endpoints (loopback-equivalent dev only). Off in production.
    allow_insecure: bool,
    running: std::sync::atomic::AtomicBool,
    reconnect_delay: Mutex<f64>,
    /// The gateway-assigned recorder agent_id for THIS connection (persisted across restarts).
    agent_id: Mutex<Option<String>>,
    /// Full-capability subsystems pulled from the engine at construction (via
    /// [`LinkedAgentBridge::with_subsystems`]), so cloud-dispatched capability frames drive the SAME
    /// warm browser + governor the local runs use — never a second Chromium.
    ///
    /// The legacy [`LinkedAgentBridge::new`] leaves these `None`; in that mode the router serves only
    /// the metadata catalog + `run_local_workflow` (by-id) contract, and answers any capability frame
    /// that needs a browser with a failed `task_result` (fail-closed, never a 2nd browser).
    subsystems: AgentSubsystems,
    /// Shared liveness/error state the manager's status endpoint reads. `None` for the legacy/test
    /// bridges (observability is then a no-op); set by the supervisor via [`LinkedAgentBridge::with_status`].
    status: Option<Arc<BridgeStatus>>,
    /// Poked by [`LinkedAgentBridge::request_catalog_refresh`] whenever a local `cloud_callable`
    /// workflow is created / updated / deleted, so the read loop re-sends the `local_catalog` frame
    /// without waiting for a WS reconnect. `notify_one()` stores a permit when no waiter is registered,
    /// so a poke fired between select! iterations is not lost. A no-op when the bridge isn't running.
    catalog_refresh: Notify,
}

/// The engine subsystems a full-capability bridge routes cloud work onto. Every field is `Option`:
/// the `StubEngine` (no warm browser) yields `None`, and the router MUST fail capability frames
/// closed rather than launch a second browser.
#[derive(Clone, Default)]
struct AgentSubsystems {
    /// The single warm `BrowserManager` shared with local runs/record/streaming. `None` → no browser
    /// (StubEngine) → capability frames are answered with a failed `task_result`.
    browser: Option<Arc<crate::browser::manager::BrowserManager>>,
    /// The at-rest vault. Used to re-seal cloud-dispatched per-run credentials into the ephemeral
    /// recipe (so the UNMODIFIED engine run pipeline resolves them) and to back the local AI client.
    vault: Option<Arc<crate::local::vault::Vault>>,
    /// The process-wide resource governor, so cloud work shares the owner's concurrency ceiling.
    /// (Consumed indirectly today: `engine.run_recipe` admits through the SAME governor; held for the
    /// direct-admission handlers added in a later step.)
    #[allow(dead_code)]
    governor: Option<Arc<crate::local::governor::ResourceGovernor>>,
    /// The streaming-session manager (cloud-dispatched streaming sessions, Stage 2). Cloud
    /// `start_streaming_session` / `streaming_command` / `end_streaming_session` frames route onto this
    /// — the SAME engine behind `/v1/streaming/sessions` — never a second browser.
    streaming: Option<Arc<super::super::engine::streaming::LocalStreamingManager>>,
    /// The live-run registry (`/v1/runs/:id/events` + cancel). Cancel is routed via
    /// [`super::super::engine::LocalEngine::cancel`] today; held for the runs-listing endpoint.
    #[allow(dead_code)]
    registry: Option<Arc<super::super::engine::RunRegistry>>,
    /// The daemon's shared `PlaywrightRecorder` (lifecycle stage 5b), so a cloud-dispatched
    /// `session_open{purpose:"record"}` runs on the SAME recorder + warm browser the loopback
    /// `/ws/record` uses. `None` on a browserless build → the record router answers with
    /// `session_opened{success:false, error:"no recorder available on this agent"}`.
    recorder: Option<Arc<crate::recorder::core::PlaywrightRecorder>>,
}

impl LinkedAgentBridge {
    /// Build a bridge over the given engine + encrypted store. `link` carries the resolved cloud base
    /// url (falls back to env/default when `None`). `allow_insecure` is for loopback dev only.
    ///
    /// This is the LEGACY constructor: it serves only the metadata catalog + `run_local_workflow`
    /// (by-id) contract. Full-capability cloud dispatch (ad-hoc `execute_workflow`, AI tasks,
    /// streaming) requires the warm browser + subsystems — use [`LinkedAgentBridge::with_subsystems`].
    pub fn new(
        engine: Arc<dyn LocalEngine>,
        db: SqlitePool,
        link: Option<LinkState>,
        allow_insecure: bool,
    ) -> Self {
        Self {
            engine,
            db,
            link,
            allow_insecure,
            running: std::sync::atomic::AtomicBool::new(false),
            reconnect_delay: Mutex::new(1.0),
            agent_id: Mutex::new(None),
            subsystems: AgentSubsystems::default(),
            status: None,
            catalog_refresh: Notify::new(),
        }
    }

    /// Build a FULL-CAPABILITY bridge: pull the warm browser + vault + governor + streaming + run
    /// registry off the engine so cloud-dispatched capability frames run on the SAME Chromium and
    /// share the owner's `ResourceGovernor` ceiling — never a second browser.
    ///
    /// When `engine.browser()` is `None` (the `StubEngine`), the subsystems stay `None` and the
    /// router answers capability frames with a failed `task_result` (fail-closed). `link` /
    /// `allow_insecure` behave exactly as in [`LinkedAgentBridge::new`].
    pub fn with_subsystems(
        engine: Arc<dyn LocalEngine>,
        db: SqlitePool,
        vault: Arc<crate::local::vault::Vault>,
        link: Option<LinkState>,
        allow_insecure: bool,
    ) -> Self {
        let subsystems = AgentSubsystems {
            browser: engine.browser(),
            // Prefer the engine's own vault handle (identical Arc), falling back to the passed one so
            // the caller can always supply the daemon vault even for a browserless engine.
            vault: engine.vault().or(Some(vault)),
            governor: engine.governor(),
            streaming: engine.streaming(),
            registry: engine.registry(),
            // Attached by the manager via `with_recorder(...)` AFTER construction (the recorder
            // lives on `AppState`, not on `LocalEngine`, so it isn't reachable through `engine.*`).
            recorder: None,
        };
        Self {
            engine,
            db,
            link,
            allow_insecure,
            running: std::sync::atomic::AtomicBool::new(false),
            reconnect_delay: Mutex::new(1.0),
            agent_id: Mutex::new(None),
            subsystems,
            status: None,
            catalog_refresh: Notify::new(),
        }
    }

    /// Attach a shared [`BridgeStatus`] the bridge publishes its real connect/disconnect state to, so
    /// the manager's `/v1/cloud/agent/status` reports true liveness + the last connect error (not an
    /// optimistic "online"). Consuming builder so it composes with [`LinkedAgentBridge::with_subsystems`]
    /// before the `Arc::new`. No-op observability when unset (legacy/test bridges pass none).
    pub fn with_status(mut self, status: Arc<BridgeStatus>) -> Self {
        self.status = Some(status);
        self
    }

    /// Attach the shared `PlaywrightRecorder` so a cloud-dispatched `session_open{purpose:"record"}`
    /// runs on the SAME recorder the loopback `/ws/record` uses. Consuming builder so the manager
    /// can chain it after `with_status`. `None` leaves the record router failing closed with a
    /// `session_opened{success:false}` — a browserless build simply can't service a recording.
    pub fn with_recorder(
        mut self,
        recorder: Option<Arc<crate::recorder::core::PlaywrightRecorder>>,
    ) -> Self {
        self.subsystems.recorder = recorder;
        self
    }

    /// Publish CONNECTED (WS up + welcomed). No-op when no status handle is attached.
    fn mark_connected(&self) {
        if let Some(s) = &self.status {
            s.mark_connected();
        }
    }

    /// Publish DISCONNECTED with an optional error reason. No-op when no status handle is attached.
    fn mark_disconnected(&self, err: Option<String>) {
        if let Some(s) = &self.status {
            s.mark_disconnected(err);
        }
    }

    /// Whether this bridge has a warm browser to run cloud capability work on. `false` → the router
    /// fails capability frames closed (never launches a second browser).
    fn has_browser(&self) -> bool {
        self.subsystems.browser.is_some()
    }

    /// Resolved cloud base url (env → LinkState → default), no trailing slash.
    fn base_url(&self) -> String {
        CloudClient::resolve_base_url(self.link.as_ref())
    }

    /// Minimum listen()-time before a session counts as HEALTHY. A close (clean OR error) inside
    /// this window is treated as a rapid rejection (e.g. ws-gateway `close(4002, "agent_id already
    /// connected")` because the previous WS hadn't finished deregistering, or a transient
    /// backend-side gate) — we surface it via `last_error` and back off before retrying instead of
    /// letting the supervisor hot-loop reconnect + resend catalog + get closed again.
    const MIN_HEALTHY_SESSION: std::time::Duration = std::time::Duration::from_secs(5);

    /// Main loop — connect + listen with auto-reconnect (full-jitter backoff). A definitively
    /// revoked/unlinked token stops the loop (re-link required); transient failures retry.
    ///
    /// Returns WHY it stopped ([`BridgeExit`]) so the supervisor can park on `Unauthorized`
    /// instead of instantly rebuilding a bridge whose next `connect()` fails with no network
    /// round-trip (cleared token) — the rebuild-instantly path was an observed ~500 Hz error storm.
    ///
    /// A CLEAN close (`Message::Close` / stream-`None`) from the server AFTER a healthy long-lived
    /// session breaks the loop (legit shutdown, e.g. mgr.stop()). A clean close INSIDE
    /// [`MIN_HEALTHY_SESSION`] is treated as a soft failure and cycles through backoff — this is
    /// the observed hot-loop cause: the ws-gateway rejects a duplicate `agent_id` with a Close
    /// frame right after the previous WS drops but before the gateway's `on("close")` cleanup
    /// deregisters the stale entry, so an eager reconnect gets rejected in a tight cycle.
    pub async fn run(&self) -> BridgeExit {
        self.running.store(true, std::sync::atomic::Ordering::Relaxed);

        while self.running.load(std::sync::atomic::Ordering::Relaxed) {
            let started = tokio::time::Instant::now();
            let outcome = self.connect_and_listen().await;
            let session = started.elapsed();

            // A session that actually stayed up for `MIN_HEALTHY_SESSION` demonstrated the connect
            // + auth + gateway registration all worked — reset the backoff so a later transient
            // blip doesn't inherit an accumulated delay. On an unhealthy session (or a hard connect
            // error), leave the backoff growing — that's what turns the observed hot loop into an
            // exponentially-spaced retry.
            if session >= Self::MIN_HEALTHY_SESSION {
                *self.reconnect_delay.lock().await = 1.0;
            }

            match outcome {
                Ok(()) if session >= Self::MIN_HEALTHY_SESSION => {
                    // Legit clean shutdown after a healthy session.
                    self.mark_disconnected(None);
                    return BridgeExit::Stopped;
                }
                Ok(()) => {
                    // Suspiciously fast clean-close — surface as an error and back off. Without
                    // this the supervisor rebuilds instantly, we reconnect + resend `local_catalog`
                    // + get closed again, forever.
                    let msg = format!(
                        "connection closed by remote after {}ms (likely rejected; e.g. duplicate agent_id or transient gate)",
                        session.as_millis()
                    );
                    tracing::warn!(
                        session_ms = session.as_millis() as u64,
                        "LinkedAgentBridge WS closed cleanly within {:?} — treating as rejection + backing off",
                        Self::MIN_HEALTHY_SESSION,
                    );
                    self.mark_disconnected(Some(msg));
                }
                Err(e) => {
                    // Surface WHY to the status endpoint (e.g. "HTTP 422" from a rejected connect body)
                    // so a failing agent is diagnosable instead of showing a misleading "online".
                    self.mark_disconnected(Some(e.to_string()));
                    if !self.running.load(std::sync::atomic::Ordering::Relaxed) {
                        break;
                    }
                    // Token cleared/unlinked (CloudClient cleared it on invalid_grant): stop instead
                    // of hot-looping a doomed reconnect. The user must re-link the desktop.
                    if matches!(
                        e.downcast_ref::<super::super::error::LocalError>(),
                        Some(super::super::error::LocalError::Unauthorized)
                    ) {
                        tracing::error!("cloud link unauthorized — stopping LinkedAgentBridge (re-link required)");
                        self.running.store(false, std::sync::atomic::Ordering::Relaxed);
                        return BridgeExit::Unauthorized;
                    }
                    tracing::warn!(error = %e, "LinkedAgentBridge connection lost, will back off");
                }
            }

            if !self.running.load(std::sync::atomic::Ordering::Relaxed) {
                break;
            }

            // Full-jitter backoff. Applies to BOTH the fast-clean-close case (above) AND any hard
            // error — so a broken gateway never turns into a 20Hz reconnect storm.
            let delay = {
                let mut d = self.reconnect_delay.lock().await;
                let ceiling = *d;
                let nanos = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .subsec_nanos() as f64;
                let rand01 = nanos / 1_000_000_000.0;
                *d = (ceiling * 2.0).min(30.0);
                (ceiling * rand01).max(0.1)
            };
            tracing::warn!(
                delay_s = delay,
                session_ms = session.as_millis() as u64,
                "LinkedAgentBridge sleeping before reconnect"
            );
            tokio::time::sleep(std::time::Duration::from_secs_f64(delay)).await;
        }
        BridgeExit::Stopped
    }

    /// Connect + welcome + listen. Does NOT reset `reconnect_delay` — the reset is now driven by
    /// [`LinkedAgentBridge::run`] from actual listen()-time so a WS that closes immediately after
    /// `connect()` succeeded doesn't optimistically wipe the accumulated backoff.
    async fn connect_and_listen(&self) -> Result<(), anyhow::Error> {
        let ws = self.connect().await?;
        // `connect()` completed the two-step handshake AND read the `welcome` frame (an agent_id is
        // assigned) — the agent is truly live now. Publish it before entering the read loop.
        self.mark_connected();
        self.listen(ws).await
    }

    /// Two-step connect: (1) POST /api/recorder/connect with the cloud `wto_` Bearer (refresh on
    /// 401), (2) WS to the returned gateway url with the gateway JWT in the Authorization header.
    async fn connect(&self) -> Result<WsStream, anyhow::Error> {
        let base_url = self.base_url();
        require_secure_url(&base_url, self.allow_insecure, "cloud")?;

        // Load the previously-assigned agent_id (non-secret) so the gateway reuses it across
        // restarts (warm-session affinity is keyed by agent_id).
        let stored_agent_id = config_kv::get(&self.db, LINKED_AGENT_ID_KEY)
            .await
            .ok()
            .flatten()
            .unwrap_or_default();
        {
            let mut aid = self.agent_id.lock().await;
            *aid = if stored_agent_id.is_empty() { None } else { Some(stored_agent_id.clone()) };
        }

        // Step 1: POST /api/recorder/connect with the cloud account token. A 401 → single refresh →
        // retry, via CloudClient. The connect body is non-secret routing/capability hints; identity
        // is derived gateway-side from the verified token (the never-trust-a-BYO-agent rule).
        let mut client = CloudClient::connect(self.link.as_ref())?;
        // The supply-pool opt-in is read fresh from the persisted config (the REST enable/disable +
        // config-set paths write `config.toml`; the bridge holds no config snapshot). A read error
        // fails SAFE to `false` (advertise owner-only capabilities).
        let (supply_pool_opt_in, max_sessions) = match crate::local::config::Paths::resolve() {
            Ok(paths) => {
                let cfg = crate::local::config::load_config(&paths);
                // Advertise the daemon's real concurrency ceiling (clamped >= 1). The backend
                // `ConnectRequest.max_sessions` REQUIRES `>= 1` (a 0 → 422 that rejected every connect
                // BEFORE auth), so 0 must never be sent.
                (cfg.supply_pool_opt_in, (cfg.max_concurrent_runs as u32).max(1))
            }
            // Fail SAFE: opt-in off + the minimum valid session count (never 0 → never a 422).
            Err(_) => (false, 1),
        };
        let connect_body = build_connect_body(&stored_agent_id, supply_pool_opt_in, max_sessions);
        let connect_data: Value = client
            .post_json("/api/recorder/connect", &connect_body)
            .await?;

        let gateway_ws_url = connect_data["gateway_ws_url"]
            .as_str()
            .ok_or_else(|| anyhow::anyhow!("Missing gateway_ws_url in /connect response"))?;
        let gateway_token = connect_data["gateway_token"]
            .as_str()
            .ok_or_else(|| anyhow::anyhow!("Missing gateway_token in /connect response"))?;
        require_secure_url(gateway_ws_url, self.allow_insecure, "gateway")?;

        // Build the WS url — gateway JWT goes in the Authorization header (below), NOT the query
        // string, so it never lands in proxy/access logs. agent_id is a non-secret routing hint.
        let separator = if gateway_ws_url.contains('?') { "&" } else { "?" };
        let mut full_url = format!("{}{}role=recorder", gateway_ws_url, separator);
        if !stored_agent_id.is_empty() {
            full_url.push_str(&format!("&agent_id={}", urlencoding(&stored_agent_id)));
        }

        // Step 2: WebSocket connect with the gateway JWT in the Authorization header.
        use tokio_tungstenite::tungstenite::client::IntoClientRequest;
        use tokio_tungstenite::tungstenite::http::HeaderValue;
        let mut request = full_url
            .as_str()
            .into_client_request()
            .map_err(|e| anyhow::anyhow!("Failed to build gateway WS request: {}", e))?;
        let bearer = HeaderValue::from_str(&format!("Bearer {}", gateway_token))
            .map_err(|e| anyhow::anyhow!("Invalid gateway token header: {}", e))?;
        request.headers_mut().insert("Authorization", bearer);

        let (ws_stream, _) = tokio_tungstenite::connect_async(request)
            .await
            .map_err(|e| anyhow::anyhow!("WebSocket connect failed: {}", e))?;

        // Read the welcome frame for the assigned agent_id.
        let (write, mut read) = ws_stream.split();
        let assigned_agent_id =
            match tokio::time::timeout(std::time::Duration::from_secs(5), read.next()).await {
                Ok(Some(Ok(Message::Text(text)))) => {
                    match serde_json::from_str::<Value>(&text) {
                        Ok(welcome) if welcome["type"].as_str() == Some("welcome") => welcome
                            ["agent_id"]
                            .as_str()
                            .unwrap_or(&stored_agent_id)
                            .to_string(),
                        _ => stored_agent_id.clone(),
                    }
                }
                _ => stored_agent_id.clone(),
            };

        let final_agent_id = if assigned_agent_id.is_empty() {
            format!("agent-{}", &uuid::Uuid::new_v4().to_string()[..8])
        } else {
            assigned_agent_id
        };

        {
            let mut aid = self.agent_id.lock().await;
            *aid = Some(final_agent_id.clone());
        }
        // Persist the assigned id to the NEW config slot (non-secret routing metadata).
        if final_agent_id != stored_agent_id {
            if let Err(e) = config_kv::set(&self.db, LINKED_AGENT_ID_KEY, &final_agent_id).await {
                tracing::warn!(error = %e, "failed to persist linked agent_id (continuing)");
            }
        }

        tracing::info!(agent_id = %final_agent_id, "LinkedAgentBridge connected to gateway");

        // Reunite the stream halves.
        let ws_stream = read
            .reunite(write)
            .map_err(|e| anyhow::anyhow!("Reunite failed: {}", e))?;
        Ok(ws_stream)
    }

    /// Read loop: send the catalog on connect; answer `request_local_catalog`; run `run_local_workflow`
    /// dispatches; honor `disconnect`. The outgoing writer runs on its own task so a long-running run
    /// never blocks frame I/O. Returns `Ok` on a clean shutdown/close; `Err` to trigger reconnect.
    async fn listen(&self, ws: WsStream) -> Result<(), anyhow::Error> {
        let (mut write, mut read) = ws.split();

        // Outgoing writer task — internal code pushes Messages here; this drains them to the socket.
        let (outgoing_tx, mut outgoing_rx) = mpsc::unbounded_channel::<Message>();
        let write_handle: JoinHandle<()> = tokio::spawn(async move {
            while let Some(msg) = outgoing_rx.recv().await {
                if write.send(msg).await.is_err() {
                    break;
                }
            }
        });

        // Advertise the catalog immediately on connect (metadata only).
        self.send_catalog(&outgoing_tx).await;

        // Heartbeat loop — keeps this agent in the backend's DISPATCHABLE registry. The gateway's
        // Redis recorder entry (and the `_pick_recorder` live set) expire on a short TTL (~90s); an
        // open WS alone is NOT enough — without a periodic `heartbeat` frame the entry lapses and the
        // backend can no longer route runs here, even while the DB's "seen recently" grace still shows
        // the agent "online". 25s matches the cloud saas_bridge cadence. Aborted with the writer below.
        let heartbeat_handle: JoinHandle<()> = {
            let hb_tx = outgoing_tx.clone();
            let hb_engine = self.engine.clone();
            let hb_max_sessions = match crate::local::config::Paths::resolve() {
                Ok(p) => (crate::local::config::load_config(&p).max_concurrent_runs as u64).max(1),
                Err(_) => 1,
            };
            tokio::spawn(async move {
                loop {
                    tokio::time::sleep(std::time::Duration::from_secs(25)).await;
                    let msg = json!({
                        "type": "heartbeat",
                        // Available capacity = max_sessions - active_sessions; report the live concurrent
                        // run count so the backend ranks/routes by real headroom.
                        "active_sessions": hb_engine.active_runs(),
                        "max_sessions": hb_max_sessions,
                        "platform": std::env::consts::OS,
                        "version": env!("CARGO_PKG_VERSION"),
                        "role": "user-hosted",
                    });
                    if hb_tx.send(Message::Text(msg.to_string())).is_err() {
                        break; // writer gone → connection tearing down
                    }
                }
            })
        };

        let result: Result<(), anyhow::Error> = loop {
            if !self.running.load(std::sync::atomic::Ordering::Relaxed) {
                break Ok(());
            }
            // Race the incoming WS frame against a local catalog-dirty poke — a workflow mutation
            // that flipped `cloud_callable` needs to be re-advertised WITHOUT waiting for the cloud
            // to send `request_local_catalog` or for the WS to reconnect. `Notify::notified()` +
            // `notify_one()` are cancel-safe: the fresh `notified()` on the next loop iteration
            // consumes any permit stored while another branch was resolving, so a poke fired between
            // iterations is not lost.
            let raw = tokio::select! {
                _ = self.catalog_refresh.notified() => {
                    self.send_catalog(&outgoing_tx).await;
                    continue;
                }
                frame = read.next() => match frame {
                    Some(Ok(Message::Text(text))) => text,
                    Some(Ok(Message::Ping(data))) => {
                        let _ = outgoing_tx.send(Message::Pong(data));
                        continue;
                    }
                    Some(Ok(Message::Binary(_))) | Some(Ok(Message::Pong(_))) => continue,
                    Some(Ok(Message::Close(_))) | None => break Ok(()),
                    Some(Ok(Message::Frame(_))) => continue,
                    Some(Err(e)) => break Err(anyhow::anyhow!("WS read error: {}", e)),
                }
            };

            let msg: Value = match serde_json::from_str(&raw) {
                Ok(v) => v,
                Err(_) => continue,
            };
            let msg_type = msg["type"].as_str().unwrap_or("");

            // The concrete arm taken below is the single source of truth for routing; `route_kind`
            // (unit-tested without a live WS/browser) documents + pins that same decision table so a
            // future edit to the arm list is caught by the routing tests.

            match msg_type {
                "ping" => {
                    let _ = outgoing_tx.send(Message::Text(json!({"type": "pong"}).to_string()));
                }
                "request_local_catalog" => {
                    self.send_catalog(&outgoing_tx).await;
                }
                "run_local_workflow" => {
                    let task_id = task_id_str(&msg["task_id"]);
                    let local_workflow_id = msg["local_workflow_id"].as_str().unwrap_or("").to_string();
                    let inputs = msg.get("inputs").cloned().unwrap_or_else(|| json!({}));
                    tracing::info!(
                        task_id,
                        local_workflow_id,
                        "LinkedAgentBridge received run_local_workflow"
                    );
                    let engine = self.engine.clone();
                    let db = self.db.clone();
                    let out = outgoing_tx.clone();
                    // Spawn so a long run never wedges the read loop (frames keep flowing).
                    tokio::spawn(async move {
                        let frame =
                            run_local_workflow(&engine, &db, &task_id, &local_workflow_id, inputs).await;
                        let _ = out.send(Message::Text(frame.to_string()));
                    });
                }
                "disconnect" => {
                    let reason = msg["reason"].as_str().unwrap_or("unknown");
                    tracing::warn!(reason, "LinkedAgentBridge: server requested disconnect");
                    self.running.store(false, std::sync::atomic::Ordering::Relaxed);
                    break Ok(());
                }
                // Full-capability cloud dispatch frames. When this bridge has NO warm browser
                // (StubEngine, or the legacy `new()` constructor) we FAIL CLOSED with a
                // `task_result{success:false}` so the backend degrades gracefully instead of hanging on
                // a dispatch we can never service — and we never launch a second Chromium (A3). This
                // guard is checked FIRST so the browser-bearing arms below can assume a warm browser.
                "execute_workflow" | "execute_ai_task" | "start_streaming_session"
                    if !self.has_browser() =>
                {
                    let task_id = task_id_str(&msg["task_id"]);
                    let frame = task_result_frame(
                        &task_id,
                        false,
                        json!({}),
                        Some("no browser available on this agent".to_string()),
                        0,
                    );
                    let _ = outgoing_tx.send(Message::Text(frame.to_string()));
                }
                // Ad-hoc cloud workflow (recipe inline in `config`) → run via the shared engine
                // (governor + `/v1/runs` visibility) with per-run creds decrypted on-device (A4).
                "execute_workflow" => {
                    let task_id = task_id_str(&msg["task_id"]);
                    let entry_url =
                        msg["config"]["entry_url"].as_str().unwrap_or("about:blank").to_string();
                    tracing::info!(task_id, entry_url = %truncate_str(&entry_url, 200),
                        "LinkedAgentBridge received execute_workflow");
                    let engine = self.engine.clone();
                    let vault = self.subsystems.vault.clone();
                    let db = self.db.clone();
                    let out = outgoing_tx.clone();
                    let msg = msg.clone();
                    tokio::spawn(async move {
                        // Defense-in-depth (§8 invariant 6): refuse other-tenant supply-pool work when
                        // this device has NOT opted into the shared pool (the server is the authority,
                        // this is the second line). The owner's OWN cloud dispatches are always allowed.
                        if super::agent::should_refuse_foreign_tenant(&msg, &db).await {
                            let frame = task_result_frame(
                                &task_id,
                                false,
                                json!({}),
                                Some("agent not opted into the shared supply pool".to_string()),
                                0,
                            );
                            let _ = out.send(Message::Text(frame.to_string()));
                            return;
                        }
                        // `has_browser()` implies a full-capability engine; a full-capability engine
                        // always carries a vault (with_subsystems). Missing vault → fail closed.
                        let frame = match vault {
                            Some(vault) => {
                                super::agent::workflow::handle(&task_id, &msg, &engine, &vault).await
                            }
                            None => task_result_frame(
                                &task_id,
                                false,
                                json!({}),
                                Some("no vault available on this agent".to_string()),
                                0,
                            ),
                        };
                        let _ = out.send(Message::Text(frame.to_string()));
                    });
                }
                // Ad-hoc cloud AI task → run the AI modes on the LOCAL provider (never cloud AI),
                // on the SAME warm browser (A4/A5).
                "execute_ai_task" => {
                    let task_id = task_id_str(&msg["task_id"]);
                    tracing::info!(task_id, "LinkedAgentBridge received execute_ai_task");
                    let browser = self.subsystems.browser.clone();
                    let vault = self.subsystems.vault.clone();
                    let db = self.db.clone();
                    let out = outgoing_tx.clone();
                    let msg = msg.clone();
                    tokio::spawn(async move {
                        // Defense-in-depth (§8 invariant 6): refuse other-tenant supply-pool work when
                        // this device has NOT opted into the shared pool (server-authoritative; agent
                        // second line). The owner's OWN cloud dispatches are always allowed.
                        if super::agent::should_refuse_foreign_tenant(&msg, &db).await {
                            let frame = task_result_frame(
                                &task_id,
                                false,
                                json!({}),
                                Some("agent not opted into the shared supply pool".to_string()),
                                0,
                            );
                            let _ = out.send(Message::Text(frame.to_string()));
                            return;
                        }
                        let frame = match (browser, vault) {
                            (Some(browser), Some(vault)) => {
                                super::agent::ai_task::handle(&task_id, &msg, &browser, &db, &vault)
                                    .await
                            }
                            _ => task_result_frame(
                                &task_id,
                                false,
                                json!({}),
                                Some("no browser/vault available on this agent".to_string()),
                                0,
                            ),
                        };
                        let _ = out.send(Message::Text(frame.to_string()));
                    });
                }
                // Cloud-dispatched streaming session → route onto the LOCAL streaming engine
                // (`LocalStreamingManager`, the same one behind `/v1/streaming/sessions`) so it runs on
                // the SAME warm browser (A4). Only a dispatch that names a cloud-callable LOCAL
                // streaming workflow is serviced; an ad-hoc streaming config is acked not-supported by
                // the handler so the backend degrades. A browserless/streamless engine already
                // fail-closed above.
                "start_streaming_session" => {
                    let task_id = task_id_str(&msg["task_id"]);
                    match self.subsystems.streaming.clone() {
                        Some(streaming) => {
                            let db = self.db.clone();
                            let out = outgoing_tx.clone();
                            let msg = msg.clone();
                            tokio::spawn(async move {
                                // Defense-in-depth supply-pool gate (same as the other capability arms).
                                if super::agent::should_refuse_foreign_tenant(&msg, &db).await {
                                    let frame = task_result_frame(
                                        &task_id,
                                        false,
                                        json!({}),
                                        Some("agent not opted into the shared supply pool".to_string()),
                                        0,
                                    );
                                    let _ = out.send(Message::Text(frame.to_string()));
                                    return;
                                }
                                super::agent::streaming::handle_start(&task_id, &msg, &streaming, &db, &out).await;
                            });
                        }
                        None => {
                            let frame = task_result_frame(
                                &task_id,
                                false,
                                json!({}),
                                Some("streaming not available on this agent".to_string()),
                                0,
                            );
                            let _ = outgoing_tx.send(Message::Text(frame.to_string()));
                        }
                    }
                }
                // A follow-up turn on a live cloud streaming session → run one turn on its warm tab and
                // stream the result back (`stream_chunk` + terminal `command_response`). Unknown session
                // → a single error `command_response` (never a hang).
                "streaming_command" => {
                    if let Some(streaming) = self.subsystems.streaming.clone() {
                        let db = self.db.clone();
                        let out = outgoing_tx.clone();
                        let msg = msg.clone();
                        tokio::spawn(async move {
                            super::agent::streaming::handle_command(&msg, &streaming, &db, &out).await;
                        });
                    }
                }
                // End a live cloud streaming session → stop the local session + confirm.
                "end_streaming_session" => {
                    if let Some(streaming) = self.subsystems.streaming.clone() {
                        let out = outgoing_tx.clone();
                        let msg = msg.clone();
                        tokio::spawn(async move {
                            super::agent::streaming::handle_end(&msg, &streaming, &out).await;
                        });
                    }
                }
                // Cloud-orchestrated monitoring assignment → persist the pushed targets into the LOCAL
                // store; the already-running local scheduler runs the checks. `assign_workflows` is
                // acked not-persisted (no local workflow-id map). These write only monitor rows the user
                // could create themselves (no browser needed → serviced even on a browserless engine).
                // Cloud monitor assignment is ACK-ONLY on a user-hosted BYO agent — NEVER persisted.
                // A desktop is not a shared monitoring-fleet node; adopting cloud-pushed targets would
                // surface OTHER tenants' monitors locally and run their checks on the user's machine.
                "assign_targets" | "target_sync" => {
                    let ack = super::agent::monitoring::handle_assign_targets(&msg);
                    let _ = outgoing_tx.send(Message::Text(ack.to_string()));
                }
                "assign_workflows" => {
                    let ack = super::agent::monitoring::handle_assign_workflows(&msg);
                    let _ = outgoing_tx.send(Message::Text(ack.to_string()));
                }
                // Cloud-dispatched RECORDING session — the ws-gateway `/ws/record` handler sends
                // `session_open{purpose:"record"}` when a user clicks Record in the cloud UI, then
                // multiplexes every subsequent frontend↔agent frame as `{channel:"session",
                // session_id, msg}` over this same WS. Route to the recorder that also serves the
                // loopback `/ws/record` (never launch a second Chromium; never confuse the
                // ai_browsing router). `session_close` for a live record session takes the record
                // teardown path; if it's not a record session, it falls through to the ai_browsing
                // branch below.
                "session_open" if super::agent::record::is_record_open(&msg) => {
                    let recorder = self.subsystems.recorder.clone();
                    let db = self.db.clone();
                    let out = outgoing_tx.clone();
                    let msg = msg.clone();
                    tokio::spawn(async move {
                        if super::agent::should_refuse_foreign_tenant(&msg, &db).await {
                            let frame = super::agent::ai_browsing::refusal_ack(
                                &msg,
                                "agent not opted into the shared supply pool",
                            );
                            let _ = out.send(Message::Text(frame.to_string()));
                            return;
                        }
                        let ack =
                            super::agent::record::open(&msg, recorder.as_ref(), &out).await;
                        let _ = out.send(Message::Text(ack.to_string()));
                    });
                }
                "session_close"
                    if super::agent::record::is_active(
                        super::agent::record::session_id_of(&msg).as_str(),
                    ) =>
                {
                    // Live record session targeted → remove the handle. The registry drop closes
                    // the driver's inbound mpsc → its `recv().await` returns None → the task
                    // calls `shutdown()` on the driver (idempotent) which ends the recorder
                    // session. Then we ack. No browser context is left stranded.
                    let sid = super::agent::record::session_id_of(&msg);
                    let ack = super::agent::record::close(&sid);
                    let _ = outgoing_tx.send(Message::Text(ack.to_string()));
                }
                // Wrapped frontend→agent multiplex frame from `session-dispatcher.sendToAgent`:
                // `{channel:"session", session_id, msg:{...recorder frame...}}`. Route to the LIVE
                // record session's driver; unknown session_id silently drops (a stale envelope
                // from a half-closed frontend can never wedge us).
                _ if msg["channel"].as_str() == Some("session")
                    && msg["session_id"].as_str().is_some()
                    && msg["msg"].is_object() =>
                {
                    let sid = msg["session_id"].as_str().unwrap_or("");
                    let inner = msg["msg"].clone();
                    if !super::agent::record::dispatch_wrapped(sid, inner) {
                        tracing::debug!(
                            session_id = %truncate_str(sid, 16),
                            "wrapped session frame for unknown record session (silently dropped)"
                        );
                    }
                }
                // A backend spectator started/stopped watching a live AI session — screencast its page
                // back to the coordinator as `spectate_frame`s (relayed to the frontend by
                // `/ws/ai-spectate/`). Cheap + non-blocking: start spawns its own frame task, stop just
                // flips a flag; neither wedges the read loop.
                "spectate_start" => {
                    let sid = msg["session_id"].as_str().unwrap_or("").to_string();
                    super::agent::ai_browsing::start_spectate(&sid, outgoing_tx.clone());
                }
                "spectate_stop" => {
                    let sid = msg["session_id"].as_str().unwrap_or("").to_string();
                    super::agent::ai_browsing::stop_spectate(&sid);
                }
                // Backend-orchestrated interactive/AI browsing: the cloud opens a live session on this
                // agent and drives it step-by-step (`agent_action`) over the SAME warm browser. Spawned
                // because a single `agent_action` batch can run up to ~95s — it must never wedge the read
                // loop. The foreign-tenant supply-pool gate is applied first (defense in depth, §8).
                "session_open" | "session_close" | "ai_session_open" | "ai_session_close"
                | "agent_action" => {
                    let browser = self.subsystems.browser.clone();
                    let db = self.db.clone();
                    let out = outgoing_tx.clone();
                    let msg = msg.clone();
                    tokio::spawn(async move {
                        if super::agent::should_refuse_foreign_tenant(&msg, &db).await {
                            let frame = super::agent::ai_browsing::refusal_ack(
                                &msg,
                                "agent not opted into the shared supply pool",
                            );
                            let _ = out.send(Message::Text(frame.to_string()));
                            return;
                        }
                        if let Some(frame) =
                            super::agent::ai_browsing::handle(&msg, browser.as_ref()).await
                        {
                            let _ = out.send(Message::Text(frame.to_string()));
                        }
                    });
                }
                // Cancel a live cloud-dispatched run: resolve `task_id → run_id` (§7 process map) and
                // route `engine.cancel(run_id)`. Unknown/finished task → no-op (nothing live).
                "cancel_task" => {
                    let task_id = task_id_str(&msg["task_id"]);
                    match super::agent::runs::run_id_for(&task_id) {
                        Some(run_id) => {
                            let signalled = self.engine.cancel(run_id);
                            tracing::info!(task_id, run_id, ?signalled,
                                "LinkedAgentBridge cancel_task routed to engine.cancel");
                        }
                        None => {
                            tracing::debug!(task_id, "cancel_task for unknown/finished cloud run (no-op)");
                        }
                    }
                }
                _ => {} // ignore unrelated frames (this bridge only handles its own contract)
            }
        };

        heartbeat_handle.abort();
        write_handle.abort();
        result
    }

    /// Build + send the `local_catalog` frame from the `cloud_callable` workflows. METADATA ONLY —
    /// steps/credentials are never read into the projection. A read failure logs and sends an empty
    /// catalog (fail-closed: cloud sees nothing rather than stale/leaked data).
    async fn send_catalog(&self, outgoing_tx: &mpsc::UnboundedSender<Message>) {
        let entries = match workflows::list_cloud_callable(&self.db).await {
            Ok(rows) => rows.iter().map(catalog_entry).collect::<Vec<_>>(),
            Err(e) => {
                tracing::error!(error = %e, "failed to read cloud_callable workflows; sending empty catalog");
                Vec::new()
            }
        };
        tracing::info!(count = entries.len(), "LinkedAgentBridge advertising local catalog");
        let frame = json!({ "type": "local_catalog", "catalog": entries });
        let _ = outgoing_tx.send(Message::Text(frame.to_string()));
    }

    /// Stop the loop (graceful shutdown).
    pub fn shutdown(&self) {
        self.running.store(false, std::sync::atomic::Ordering::Relaxed);
    }

    /// Poke the running read loop to re-send the `local_catalog` frame right away — the caller (a
    /// workflow create/update/delete) has just changed what the catalog should advertise. `notify_one()`
    /// stores a permit when no waiter is registered yet, so a poke fired between select! iterations is
    /// not lost. Silent no-op when the bridge isn't running (no WS ⇒ nothing to send; the next connect
    /// will send a fresh catalog anyway).
    pub fn request_catalog_refresh(&self) {
        self.catalog_refresh.notify_one();
    }
}

/// Project a workflow row to the METADATA-ONLY catalog entry that crosses the wire.
///
/// SECURITY: this is the single projection seam. It reads ONLY non-sensitive fields — id, name,
/// description, declared inputs (`{{input.NAME}}` placeholders in the steps TEXT), and declared
/// output fields (union of `functions[].output_fields`). The `steps` text is SCANNED for input names
/// but NEVER copied out; `credentials_encrypted`, `form_data`, `raw_replay`, and the raw `steps`
/// array are NEVER serialized. `recipe_hash` is a content hash for drift detection, not the recipe.
fn catalog_entry(wf: &workflows::Workflow) -> Value {
    json!({
        "local_id": wf.id.to_string(),
        "name": wf.name,
        "description": wf.description,
        "input_schema": input_schema_metadata(wf),
        "recipe_hash": recipe_hash(wf),
        "cloud_callable": true,
    })
}

/// The metadata-only input/output schema for a workflow: declared `{{input.NAME}}` placeholders as
/// required string properties, plus the declared output field names. NO steps, NO credentials.
fn input_schema_metadata(wf: &workflows::Workflow) -> Value {
    let inputs = scan_input_placeholders(&wf.steps);
    let mut properties = serde_json::Map::new();
    let mut required = Vec::with_capacity(inputs.len());
    for name in &inputs {
        properties.insert(
            name.clone(),
            json!({ "type": "string", "description": format!("Input: {name}") }),
        );
        required.push(Value::String(name.clone()));
    }
    json!({
        "type": "object",
        "properties": Value::Object(properties),
        "required": required,
        "output_fields": declared_output_fields(wf),
    })
}

/// Content hash of the workflow recipe for cloud-side drift detection. Hashes the LOCAL steps +
/// declared metadata; the hash leaves the device but the recipe does not. Hex sha256.
fn recipe_hash(wf: &workflows::Workflow) -> String {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(wf.steps.as_bytes());
    if let Some(f) = wf.functions.as_deref() {
        h.update(b"\x00");
        h.update(f.as_bytes());
    }
    if let Some(fd) = wf.form_data.as_deref() {
        h.update(b"\x00");
        h.update(fd.as_bytes());
    }
    // Render hex without pulling in the `hex` crate (matches `storage::files::sha256_hex`).
    h.finalize().iter().map(|b| format!("{b:02x}")).collect()
}

/// Distinct `{{input.NAME}}` names referenced in a steps TEXT blob (order-preserving, first-seen).
/// `{{secret:...}}` is never matched. Self-contained copy of the MCP placeholder scanner so this
/// module compiles without the MCP layer; the grammar is identical (`[A-Za-z0-9_.-]`).
fn scan_input_placeholders(steps_text: &str) -> Vec<String> {
    const OPEN: &str = "{{";
    const PREFIX: &str = "input.";
    let mut names: Vec<String> = Vec::new();
    let mut seen: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
    let bytes = steps_text.as_bytes();
    let mut i = 0usize;
    while let Some(rel) = steps_text[i..].find(OPEN) {
        let mut p = i + rel + OPEN.len();
        while p < bytes.len() && bytes[p].is_ascii_whitespace() {
            p += 1;
        }
        if steps_text[p..].starts_with(PREFIX) {
            let name_start = p + PREFIX.len();
            let mut q = name_start;
            while q < bytes.len() {
                let c = bytes[q];
                if c.is_ascii_alphanumeric() || matches!(c, b'_' | b'.' | b'-') {
                    q += 1;
                } else {
                    break;
                }
            }
            let name = &steps_text[name_start..q];
            let mut r = q;
            while r < bytes.len() && bytes[r].is_ascii_whitespace() {
                r += 1;
            }
            if !name.is_empty() && steps_text[r..].starts_with("}}") && seen.insert(name.to_string())
            {
                names.push(name.to_string());
            }
        }
        i = i + rel + OPEN.len();
    }
    names
}

/// Declared output fields = union of `functions[].output_fields` (bare string or `{"name": ...}`).
/// Self-contained copy of the data-API helper so this module is independent of the API layer.
fn declared_output_fields(wf: &workflows::Workflow) -> Vec<String> {
    let parsed: Value = match wf.functions.as_deref() {
        None => return Vec::new(),
        Some(s) if s.trim().is_empty() => return Vec::new(),
        Some(s) => serde_json::from_str(s).unwrap_or(Value::Null),
    };
    let fns = match parsed.as_array() {
        Some(a) => a,
        None => return Vec::new(),
    };
    let mut fields: Vec<String> = Vec::new();
    for fnv in fns {
        let ofs = match fnv.get("output_fields").and_then(|v| v.as_array()) {
            Some(a) => a,
            None => continue,
        };
        for f in ofs {
            match f {
                Value::String(s) => fields.push(s.clone()),
                Value::Object(o) => {
                    if let Some(Value::String(name)) = o.get("name") {
                        fields.push(name.clone());
                    }
                }
                _ => {}
            }
        }
    }
    fields
}

/// Run a workflow by its local id and build the `task_result` frame (same shape the cloud bridge
/// uses, so the gateway stamps agent_id + the backend correlates by task_id).
///
/// A non-numeric/unparseable id, or any engine error, yields `success:false` with an `error` string
/// (never panics — a hostile id must not crash the daemon).
///
/// SECURITY (TB-1): the cloud may only run a local workflow the owner has EXPLICITLY exposed. Before
/// dispatching to the engine we load the row and refuse unless `cloud_callable == 1` (the same flag the
/// catalog filters on) — otherwise a dispatch naming ANY local id (guessed / stale) would execute a
/// never-exposed private workflow. Read-only; the engine is untouched. Fail closed on a missing row.
async fn run_local_workflow(
    engine: &Arc<dyn LocalEngine>,
    db: &SqlitePool,
    task_id: &str,
    local_workflow_id: &str,
    inputs: Value,
) -> Value {
    let start = Instant::now();

    let wf_id = match local_workflow_id.trim().parse::<i64>() {
        Ok(id) => id,
        Err(_) => {
            return task_result_frame(
                task_id,
                false,
                json!({}),
                Some(format!("invalid local_workflow_id: {}", truncate_str(local_workflow_id, 64))),
                start.elapsed().as_millis() as u64,
            );
        }
    };

    // Gate on the owner's explicit exposure flag. An unknown row, a load error, or a workflow that was
    // never marked cloud-callable is refused with a clear reason (never dispatched).
    match workflows::get_by_id(db, wf_id).await {
        Ok(Some(wf)) if wf.cloud_callable == 1 => {}
        Ok(Some(_)) => {
            return task_result_frame(
                task_id,
                false,
                json!({}),
                Some(format!("workflow {wf_id} is not exposed for cloud execution")),
                start.elapsed().as_millis() as u64,
            );
        }
        Ok(None) => {
            return task_result_frame(
                task_id,
                false,
                json!({}),
                Some(format!("workflow {wf_id} not found")),
                start.elapsed().as_millis() as u64,
            );
        }
        Err(e) => {
            return task_result_frame(
                task_id,
                false,
                json!({}),
                Some(format!("failed to load workflow {wf_id}: {e}")),
                start.elapsed().as_millis() as u64,
            );
        }
    }

    let req = RunRequest {
        workflow_id: wf_id,
        inputs,
        // A run dispatched to this machine by the linked cloud account — tag it `"cloud"` so the run
        // surfaces as cloud-initiated in `/v1/runs` (provenance only; identity/billing stay
        // server-side, the never-trust-a-BYO-agent rule).
        source: RunSource::CloudAgent,
        lane: Lane::Background,
        dry_run: false,
        persona_id: None,
        // This is the OWNER's own saved workflow (loaded by id from THIS machine's DB, gated above on
        // the owner's explicit `cloud_callable` flag) being run on the owner's own device — the
        // `RunSource::CloudAgent` tag here is provenance only. Its steps are the owner's, not
        // cloud-authored, so it legitimately resolves the owner's LOCAL vault/file refs. TB-2's
        // opt-out targets the AD-HOC cloud-AUTHORED recipe path (`run_recipe`), not this by-id path.
        allow_local_secret_refs: true,
    };

    match engine.run(req).await {
        Ok(res) => task_result_frame(
            task_id,
            res.success,
            res.extracted_data,
            res.error,
            res.duration_ms,
        ),
        Err(e) => task_result_frame(
            task_id,
            false,
            json!({}),
            Some(e.to_string()),
            start.elapsed().as_millis() as u64,
        ),
    }
}

/// Build the fixed-contract `task_result` frame. `error` is `null` on success.
fn task_result_frame(
    task_id: &str,
    success: bool,
    extracted_data: Value,
    error: Option<String>,
    duration_ms: u64,
) -> Value {
    json!({
        "type": "task_result",
        "task_id": task_id,
        "success": success,
        "extracted_data": extracted_data,
        "error": error,
        "duration_ms": duration_ms,
    })
}

/// Best-effort non-secret host display name for the connect body (`device_name`). Never fatal — an
/// unavailable hostname yields `"unknown"` so the connect always proceeds. Char-safe truncation guards
/// a pathological hostname (this value is display metadata, not an identity signal — the gateway
/// derives identity from the verified token, never this field).
fn device_name() -> String {
    sysinfo::System::host_name()
        .map(|h| truncate_str(h.trim(), 128))
        .filter(|h| !h.is_empty())
        .unwrap_or_else(|| "unknown".to_string())
}

/// Build the non-secret `/api/recorder/connect` body (§8/A9). Extracted from [`LinkedAgentBridge::
/// connect`] so the advertised tier/capabilities/supply-pool/platform/version can be unit-tested
/// without a live gateway.
///
/// SECURITY (the never-trust-a-BYO-agent rule): every field here is a NON-SECRET routing/capability
/// hint. Identity/isolation/billing are the gateway's job — it stamps the token-derived
/// `tenant_id`/`agent_id` and picks agents from the pool; a lie in this body cannot escalate. In
/// particular `captcha_trusted` is ALWAYS `false` (a desktop BYO agent cannot be trusted to solve
/// captcha), and `supply_pool_opt_in` reflects the local opt-in (the server MUST NOT route
/// other-tenant work to a `false` agent — the agent also refuses it, see
/// [`super::agent::should_refuse_foreign_tenant`]).
fn build_connect_body(stored_agent_id: &str, supply_pool_opt_in: bool, max_sessions: u32) -> Value {
    json!({
        // The desktop's concurrent-session ceiling. The backend `ConnectRequest` REQUIRES this `>= 1`
        // (a 0 fails body validation with a 422 BEFORE auth even runs — which silently rejected EVERY
        // desktop connect). We advertise the local ResourceGovernor ceiling (`max_concurrent_runs`,
        // clamped >= 1 by the caller), which also bounds concurrent cloud-dispatched runs.
        "max_sessions": max_sessions,
        // A desktop BYO agent can NEVER be trusted to solve captcha — hard `false`, always.
        "captcha_trusted": false,
        "agent_id": stored_agent_id,
        // Supply pool = the SHARED fleet tier (the backend `ConnectRequest.tier` honors this).
        "tier": "shared",
        // The full capability set this agent can service (drives backend dispatch routing). The
        // routing table in `listen()` is the runtime source of truth for what these mean.
        // NOTE: NO "monitoring" capability — a user-hosted desktop is not a shared monitoring-fleet
        // node. Advertising it made the backend push other tenants' monitor targets here (`assign_targets`),
        // which then ran on the user's machine and showed as their own monitors. The desktop runs ONLY
        // the user's own local monitors.
        "capabilities": [
            "local_workflows",
            "execute_workflow",
            "execute_ai_task",
            "streaming",
        ],
        // Local opt-in to other-tenant shared-supply work (default off). Server-authoritative;
        // agent enforces it too (defense in depth).
        "supply_pool_opt_in": supply_pool_opt_in,
        // Non-secret host/display + build metadata for the fleet UI.
        "platform": std::env::consts::OS,
        "device_name": device_name(),
        "version": env!("CARGO_PKG_VERSION"),
    })
}

/// The listen-loop routing decision for a frame `type`, given whether this bridge has a warm browser.
/// This is the SAME decision table the `match msg_type { .. }` arms encode, extracted as a pure fn so
/// the routing per message type is unit-testable without a live WS/browser (the arms themselves stay
/// the runtime source of truth; a divergence surfaces as a failing routing test that must be updated
/// alongside the arm list).
///
/// `purpose` distinguishes a cloud RECORDING `session_open{purpose:"record"}` (routed to the shared
/// `PlaywrightRecorder` — the same recorder the loopback `/ws/record` uses) from an interactive AI
/// browsing `session_open` (routed to `ai_browsing`). Any other `purpose` value falls back to
/// ai_browsing (matches the runtime arm-order in `listen()`).
///
/// `is_wrapped_session` marks a multiplex envelope from the ws-gateway
/// (`{channel:"session", session_id, msg:{...}}`, sent by `session-dispatcher::sendToAgent` for
/// every FE→agent frame after a record `session_open`). It routes to the LIVE record session's
/// driver, so we spell it as its own routing bucket.
#[cfg(test)]
fn route_kind(
    msg_type: &str,
    has_browser: bool,
    purpose: Option<&str>,
    is_wrapped_session: bool,
) -> &'static str {
    if is_wrapped_session {
        return "record_wrapped";
    }
    match msg_type {
        "ping" => "pong",
        "request_local_catalog" => "catalog",
        "run_local_workflow" => "run_local_workflow",
        "disconnect" => "disconnect",
        // Capability frames fail closed (no browser) before reaching their real handler.
        "execute_workflow" | "execute_ai_task" | "start_streaming_session" if !has_browser => {
            "fail_closed_no_browser"
        }
        "execute_workflow" => "execute_workflow",
        "execute_ai_task" => "execute_ai_task",
        "start_streaming_session" => "start_streaming_session",
        "streaming_command" => "streaming_command",
        "end_streaming_session" => "end_streaming_session",
        "assign_targets" | "target_sync" => "assign_targets",
        "assign_workflows" => "assign_workflows",
        // Cloud-dispatched RECORDING: `session_open{purpose:"record"}` runs on the shared
        // recorder — never the ai_browsing router (that opens a plain page and captures nothing).
        "session_open" if purpose == Some("record") => "record",
        "session_open" | "session_close" | "ai_session_open" | "ai_session_close"
        | "agent_action" => "ai_browsing",
        "cancel_task" => "cancel_task",
        _ => "ignored",
    }
}

#[cfg(test)]
mod tests {
    use super::super::super::engine::RunResult;
    use super::super::super::error::LocalResult;
    use super::*;

    /// Build a workflow row with only the fields the projection reads; everything else is benign.
    fn wf_with(
        id: i64,
        name: &str,
        steps: &str,
        functions: Option<&str>,
        creds: Option<&str>,
        form_data: Option<&str>,
    ) -> workflows::Workflow {
        workflows::Workflow {
            id,
            name: name.into(),
            description: Some("desc".into()),
            workflow_type: "recorded".into(),
            steps: steps.into(),
            raw_replay: Some("RAW_REPLAY_SECRET".into()),
            form_data: form_data.map(|s| s.into()),
            exit_condition: None,
            input_rules: None,
            api_functions: None,
            streaming_config: None,
            functions: functions.map(|s| s.into()),
            credentials_encrypted: creds.map(|s| s.into()),
            entry_url: Some("https://example.com".into()),
            timeout_ms: 0,
            retry_count: 0,
            headless: 1,
            fast_mode: 0,
            is_active: 1,
            is_verified: 0,
            schedule_enabled: 0,
            schedule_interval_ms: None,
            schedule_kind: None,
            schedule_time: None,
            schedule_days: None,
            schedule_tz: None,
            last_scheduled_at: None,
            next_scheduled_at: None,
            session_persistence: 0,
            session_ttl_seconds: None,
            login_url_patterns: None,
            relogin_max_retries: 0,
            http_capable: -1,
            auth_config: None,
            default_persona_id: None,
            estimated_duration_ms: None,
            usage_count: 0,
            total_run_count: 0,
            total_failure_count: 0,
            consecutive_failures: 0,
            last_run_at: None,
            last_run_status: None,
            last_run_duration_ms: None,
            last_run_has_extracted_data: None,
            last_failure_at: None,
            last_failure_error: None,
            cloud_callable: 1,
            execution_target: None,
            ai_repair_enabled: 0,
            last_repaired_at: None,
            marketplace_slug: None,
            created_at: "2026-01-01T00:00:00Z".into(),
            updated_at: None,
        }
    }

    #[test]
    fn catalog_entry_is_metadata_only_never_leaks_steps_or_creds() {
        let steps = r##"[
            {"type":"goto","url":"{{input.target_url}}"},
            {"type":"fill","value":"{{ input.username }}","selector":"#u"},
            {"type":"fill","value":"{{secret:login_password}}","selector":"#p"},
            {"type":"click","selector":"#SUPER_SECRET_SELECTOR"}
        ]"##;
        let functions = r#"[{"name":"main","output_fields":["title",{"name":"price"}]}]"#;
        let wf = wf_with(
            42,
            "My WF",
            steps,
            Some(functions),
            Some("WF1:ENCRYPTED_CREDENTIAL_BLOB"),
            Some(r#"{"hidden_field":"FORM_SECRET"}"#),
        );

        let entry = catalog_entry(&wf);

        // Contract shape.
        assert_eq!(entry["local_id"], "42", "local_id is the daemon id as a STRING");
        assert_eq!(entry["name"], "My WF");
        assert_eq!(entry["cloud_callable"], true);
        assert!(entry["recipe_hash"].as_str().unwrap().len() == 64, "hex sha256");

        // Declared inputs surface (secret excluded by construction).
        let props = &entry["input_schema"]["properties"];
        assert_eq!(props["target_url"]["type"], "string");
        assert_eq!(props["username"]["type"], "string");
        assert!(props.get("login_password").is_none(), "secrets are never callable args");
        assert_eq!(entry["input_schema"]["required"], json!(["target_url", "username"]));
        assert_eq!(entry["input_schema"]["output_fields"], json!(["title", "price"]));

        // CRITICAL: the serialized frame must NOT contain steps/credentials/raw_replay/form-data
        // secrets or the raw selector text. Scan the whole JSON string.
        let serialized = serde_json::to_string(&entry).unwrap();
        assert!(!serialized.contains("SUPER_SECRET_SELECTOR"), "step selectors must not leak");
        assert!(!serialized.contains("ENCRYPTED_CREDENTIAL_BLOB"), "credentials must not leak");
        assert!(!serialized.contains("RAW_REPLAY_SECRET"), "raw_replay must not leak");
        assert!(!serialized.contains("FORM_SECRET"), "form_data values must not leak");
        assert!(!serialized.contains("\"steps\""), "no steps key");
        assert!(!serialized.contains("\"credentials_encrypted\""), "no credentials key");
        assert!(!serialized.contains("login_password"), "secret name must not leak");
    }

    #[test]
    fn recipe_hash_is_stable_and_drift_sensitive() {
        let a = wf_with(1, "a", r#"[{"type":"goto"}]"#, None, None, None);
        let b = wf_with(1, "a", r#"[{"type":"goto"}]"#, None, None, None);
        assert_eq!(recipe_hash(&a), recipe_hash(&b), "same recipe → same hash");

        let c = wf_with(1, "a", r#"[{"type":"goto","url":"x"}]"#, None, None, None);
        assert_ne!(recipe_hash(&a), recipe_hash(&c), "changed steps → changed hash");
    }

    #[test]
    fn input_schema_empty_when_no_placeholders() {
        let wf = wf_with(7, "noargs", r#"[{"type":"goto","url":"https://x"}]"#, None, None, None);
        let schema = input_schema_metadata(&wf);
        assert_eq!(schema["required"], json!([]));
        assert_eq!(schema["properties"], json!({}));
        assert_eq!(schema["output_fields"], json!([]));
    }

    #[test]
    fn scan_input_placeholders_excludes_secrets() {
        let steps = r#"[
            {"value":"{{input.a}}"},
            {"value":"{{ input.b }}"},
            {"value":"{{secret:c}}"},
            {"value":"{{input.a}}"}
        ]"#;
        assert_eq!(scan_input_placeholders(steps), vec!["a".to_string(), "b".to_string()]);
    }

    #[test]
    fn task_result_frame_shape_matches_contract() {
        // Success → error is JSON null, not a string/omitted.
        let ok = task_result_frame("t1", true, json!({"k": 1}), None, 1234);
        assert_eq!(ok["type"], "task_result");
        assert_eq!(ok["task_id"], "t1");
        assert_eq!(ok["success"], true);
        assert_eq!(ok["extracted_data"], json!({"k": 1}));
        assert!(ok["error"].is_null(), "success → error: null");
        assert_eq!(ok["duration_ms"], 1234);

        // Failure → error carries the message.
        let bad = task_result_frame("t2", false, json!({}), Some("boom".into()), 5);
        assert_eq!(bad["success"], false);
        assert_eq!(bad["error"], "boom");
    }

    #[test]
    fn run_local_workflow_frame_de_serialization_roundtrips() {
        // The run dispatch frame the cloud sends → fields we parse out.
        let dispatch = json!({
            "type": "run_local_workflow",
            "task_id": "abc-123",
            "local_workflow_id": "42",
            "inputs": {"target_url": "https://x", "username": "u"}
        });
        assert_eq!(task_id_str(&dispatch["task_id"]), "abc-123");
        assert_eq!(dispatch["local_workflow_id"].as_str(), Some("42"));
        assert_eq!(dispatch["inputs"]["username"], "u");

        // A numeric task_id coerces faithfully (gateway/backend correlate by it).
        let numeric = json!({ "task_id": 98765 });
        assert_eq!(task_id_str(&numeric["task_id"]), "98765");
    }

    #[tokio::test]
    async fn run_local_workflow_rejects_non_numeric_id_without_panic() {
        // A bad id must fail closed (no engine call, no panic).
        struct NeverEngine;
        impl LocalEngine for NeverEngine {
            fn run<'a>(
                &'a self,
                _req: RunRequest,
            ) -> std::pin::Pin<
                Box<dyn std::future::Future<Output = LocalResult<RunResult>> + Send + 'a>,
            > {
                Box::pin(async { panic!("engine must not be called for a bad id") })
            }
            fn active_runs(&self) -> usize {
                0
            }
        }
        let engine: Arc<dyn LocalEngine> = Arc::new(NeverEngine);
        // A migrated pool is required by the signature; the bad-id branch returns before touching it.
        let dir = tempfile::tempdir().unwrap();
        let db = crate::local::db::open(&dir.path().join("t.db"), "test-key-tb1")
            .await
            .unwrap();
        let frame = run_local_workflow(&engine, &db, "t9", "not-a-number", json!({})).await;
        assert_eq!(frame["success"], false);
        assert_eq!(frame["task_id"], "t9");
        assert!(frame["error"].as_str().unwrap().contains("invalid local_workflow_id"));
    }

    /// TB-1: a valid id that names a workflow NOT flagged `cloud_callable` must be refused before the
    /// engine is ever invoked (a never-exposed private workflow must never run via cloud dispatch).
    #[tokio::test]
    async fn run_local_workflow_refuses_non_cloud_callable_id() {
        struct NeverEngine;
        impl LocalEngine for NeverEngine {
            fn run<'a>(
                &'a self,
                _req: RunRequest,
            ) -> std::pin::Pin<
                Box<dyn std::future::Future<Output = LocalResult<RunResult>> + Send + 'a>,
            > {
                Box::pin(async { panic!("engine must not run a non-exposed workflow") })
            }
            fn active_runs(&self) -> usize {
                0
            }
        }
        let dir = tempfile::tempdir().unwrap();
        let db = crate::local::db::open(&dir.path().join("t.db"), "test-key-tb1b")
            .await
            .unwrap();
        // Inserted with the default cloud_callable=0 → NOT exposed.
        let wf = workflows::insert(
            &db,
            &workflows::NewWorkflow { name: "private".into(), ..Default::default() },
        )
        .await
        .unwrap();

        let engine: Arc<dyn LocalEngine> = Arc::new(NeverEngine);
        let frame =
            run_local_workflow(&engine, &db, "tb1", &wf.id.to_string(), json!({})).await;
        assert_eq!(frame["success"], false);
        assert!(frame["error"].as_str().unwrap().contains("not exposed"));

        // A never-existing id fails closed too (unknown row, not a silent run).
        let missing = run_local_workflow(&engine, &db, "tb1b", "999999", json!({})).await;
        assert_eq!(missing["success"], false);
        assert!(missing["error"].as_str().unwrap().contains("not found"));
    }

    #[test]
    fn require_secure_url_rejects_plaintext_in_prod() {
        assert!(require_secure_url("wss://gw-1.usewrit.app/ws", false, "gateway").is_ok());
        assert!(require_secure_url("https://api.usewrit.app", false, "cloud").is_ok());
        // Loopback is allowed for dev.
        assert!(require_secure_url("ws://127.0.0.1:9000/ws", false, "gateway").is_ok());
        assert!(require_secure_url("ws://localhost:9000/ws", false, "gateway").is_ok());
        // Plaintext to a real host is refused unless explicitly opted in.
        assert!(require_secure_url("ws://gw.example.com/ws", false, "gateway").is_err());
        assert!(require_secure_url("ws://gw.example.com/ws", true, "gateway").is_ok());
    }

    #[test]
    fn urlencoding_escapes_unsafe_chars() {
        assert_eq!(urlencoding("agent-abc_123.x~"), "agent-abc_123.x~");
        assert_eq!(urlencoding("a b/c?d"), "a%20b%2Fc%3Fd");
    }

    #[test]
    fn connect_body_advertises_tier_capabilities_and_reflects_opt_in() {
        // Opt-in ON → supply_pool_opt_in:true; the tier/capabilities/version/platform are constant.
        let body = build_connect_body("agent-xyz", true, 3);
        assert_eq!(body["tier"], "shared", "supply pool advertises the shared tier");
        assert_eq!(body["agent_id"], "agent-xyz", "echoes the stored routing id");
        assert_eq!(body["supply_pool_opt_in"], true, "reflects the config opt-in");
        // REGRESSION GUARD: max_sessions MUST be >= 1 — the backend rejects 0 with a 422 (pre-auth),
        // which silently blocked every desktop connect.
        assert_eq!(body["max_sessions"], 3, "advertises the passed concurrency ceiling");
        assert!(body["max_sessions"].as_u64().unwrap() >= 1, "max_sessions must be >= 1 (backend ge=1)");
        // captcha_trusted is a HARD false regardless of opt-in (a BYO agent can't solve captcha).
        assert_eq!(body["captcha_trusted"], false);
        assert_eq!(body["version"], env!("CARGO_PKG_VERSION"));
        assert_eq!(body["platform"], std::env::consts::OS);
        assert!(body["device_name"].is_string() && !body["device_name"].as_str().unwrap().is_empty());
        // The advertised capability set (drives backend dispatch routing).
        let caps = body["capabilities"].as_array().expect("capabilities is an array");
        for expected in ["local_workflows", "execute_workflow", "execute_ai_task", "streaming"] {
            assert!(
                caps.iter().any(|c| c.as_str() == Some(expected)),
                "capabilities must advertise {expected}"
            );
        }
        // Must NOT advertise monitoring — a user-hosted desktop is not a shared monitoring-fleet node.
        assert!(
            !caps.iter().any(|c| c.as_str() == Some("monitoring")),
            "user-hosted agent must NOT advertise the monitoring capability"
        );

        // Opt-in OFF → supply_pool_opt_in:false (the default), everything else identical.
        let off = build_connect_body("agent-xyz", false, 1);
        assert_eq!(off["supply_pool_opt_in"], false, "opt-in off is faithfully advertised");
        assert_eq!(off["captcha_trusted"], false);
        assert_eq!(off["tier"], "shared");
        assert_eq!(off["max_sessions"], 1, "the minimum valid session count is advertised, never 0");

        // The body carries NO secret (token/channel key live elsewhere).
        let raw = serde_json::to_string(&body).unwrap();
        assert!(!raw.contains("wto_") && !raw.contains("channel"), "no secret leak: {raw}");
    }

    #[test]
    fn bridge_status_reflects_connect_disconnect_transitions() {
        let s = BridgeStatus::default();
        // Defaults: not connected, no error.
        assert!(!s.is_connected());
        assert!(s.last_error().is_none());

        // A failed connect records WHY and stays offline (the 422-loop case).
        s.mark_disconnected(Some("HTTP 422 Unprocessable Entity".into()));
        assert!(!s.is_connected());
        assert_eq!(s.last_error().as_deref(), Some("HTTP 422 Unprocessable Entity"));

        // A successful connect flips online AND clears the stale error.
        s.mark_connected();
        assert!(s.is_connected());
        assert!(s.last_error().is_none(), "connect clears the last error");

        // A clean disconnect (None) goes offline but leaves the last error untouched (still none here).
        s.mark_disconnected(None);
        assert!(!s.is_connected());
        assert!(s.last_error().is_none());

        // A hostile multibyte error is truncated char-safe (never panics).
        s.mark_disconnected(Some("é".repeat(1000)));
        assert_eq!(s.last_error().unwrap().chars().count(), 240);
    }

    #[tokio::test]
    async fn request_catalog_refresh_stores_a_permit_for_the_next_notified() {
        // A poke fired while no waiter is registered stores a permit on the Notify; the very next
        // `notified().await` returns immediately. That is what lets a workflow mutation racing the
        // read-loop's select! iteration NOT lose the refresh.
        let dir = tempfile::tempdir().unwrap();
        let paths = crate::local::config::Paths::at(dir.path().join(".writ"));
        paths.ensure_dirs().unwrap();
        let vault = crate::local::vault::Vault::load_or_create(&paths.root, false).unwrap();
        let pool = crate::local::db::open(&paths.db(), &vault.db_key_hex()).await.unwrap();
        let engine: std::sync::Arc<dyn crate::local::engine::LocalEngine> =
            std::sync::Arc::new(crate::local::engine::StubEngine);
        let bridge = LinkedAgentBridge::new(engine, pool, None, true);

        bridge.request_catalog_refresh();
        // Consume the stored permit — a working notify returns Ready without waiting.
        let waited =
            tokio::time::timeout(std::time::Duration::from_millis(50), bridge.catalog_refresh.notified()).await;
        assert!(waited.is_ok(), "request_catalog_refresh must store a permit for the next notified().await");
    }

    // ---- listen() routing table (dispatch shape per msg type, no browser needed) ----

    /// Test convenience — call route_kind with the historical (msg_type, has_browser) shape.
    /// New parameters default to "not a record open" + "not a wrapped multiplex frame".
    fn rk(msg_type: &str, has_browser: bool) -> &'static str {
        route_kind(msg_type, has_browser, None, false)
    }

    #[test]
    fn route_kind_capability_frames_fail_closed_without_a_browser() {
        // A browserless bridge (StubEngine / legacy new()) NEVER launches a second Chromium: every
        // capability frame is answered with a failed task_result up front.
        assert_eq!(rk("execute_workflow", false), "fail_closed_no_browser");
        assert_eq!(rk("execute_ai_task", false), "fail_closed_no_browser");
        assert_eq!(rk("start_streaming_session", false), "fail_closed_no_browser");
    }

    #[test]
    fn route_kind_capability_frames_dispatch_when_browser_present() {
        // With a warm browser, execute_workflow/execute_ai_task and the streaming lifecycle frames all
        // reach their real handlers (streaming routes onto the LocalStreamingManager, Stage 2).
        assert_eq!(rk("execute_workflow", true), "execute_workflow");
        assert_eq!(rk("execute_ai_task", true), "execute_ai_task");
        assert_eq!(rk("start_streaming_session", true), "start_streaming_session");
    }

    #[test]
    fn route_kind_stage2_frames_dispatch_to_their_handlers() {
        // Streaming follow-ups, monitoring assignment, and the interactive-browsing acks route
        // regardless of the browser flag (streaming_command/end resolve via the process map; monitoring
        // writes store rows; ai-browsing acks are pure). This pins the Stage-2 routing decisions.
        for &has in &[false, true] {
            assert_eq!(rk("streaming_command", has), "streaming_command");
            assert_eq!(rk("end_streaming_session", has), "end_streaming_session");
            assert_eq!(rk("assign_targets", has), "assign_targets");
            assert_eq!(rk("target_sync", has), "assign_targets");
            assert_eq!(rk("assign_workflows", has), "assign_workflows");
            for f in [
                "session_open",
                "session_close",
                "ai_session_open",
                "ai_session_close",
                "agent_action",
            ] {
                assert_eq!(rk(f, has), "ai_browsing", "{f}");
            }
        }
    }

    #[test]
    fn route_kind_control_frames_are_stable_regardless_of_browser() {
        for &has in &[false, true] {
            assert_eq!(rk("ping", has), "pong");
            assert_eq!(rk("request_local_catalog", has), "catalog");
            assert_eq!(rk("run_local_workflow", has), "run_local_workflow");
            assert_eq!(rk("disconnect", has), "disconnect");
            assert_eq!(rk("cancel_task", has), "cancel_task");
            // An unrelated frame is ignored (this bridge only owns its own contract).
            assert_eq!(rk("some_other_type", has), "ignored");
            assert_eq!(rk("", has), "ignored");
        }
    }

    #[test]
    fn route_kind_record_open_diverges_from_ai_browsing() {
        // The regression this whole slice fixes: a `session_open{purpose:"record"}` from the cloud
        // used to land on `ai_browsing` (which opens a plain page and captures NOTHING). It now
        // takes its own `record` route. A `session_open` without purpose stays on ai_browsing so
        // the AI-session case is unchanged.
        for &has in &[false, true] {
            assert_eq!(
                route_kind("session_open", has, Some("record"), false),
                "record",
                "purpose=record must route to the recorder"
            );
            assert_eq!(
                route_kind("session_open", has, None, false),
                "ai_browsing",
                "session_open with no purpose stays on ai_browsing"
            );
            assert_eq!(
                route_kind("session_open", has, Some("stream"), false),
                "ai_browsing",
                "purpose=stream / anything!=record stays on ai_browsing (matches runtime arm order)"
            );
        }
    }

    #[test]
    fn route_kind_wrapped_session_envelope_routes_to_record_driver() {
        // Every FE→agent frame after a record `session_open` arrives wrapped by the ws-gateway as
        // `{channel:"session", session_id, msg:{...}}` (session-dispatcher::sendToAgent). Regardless
        // of the inner msg's type, it MUST route to the live recorder driver — never fall through
        // to some other handler that misinterprets the envelope.
        for &has in &[false, true] {
            for inner_type in ["start", "action", "stop", "ping", "replay_steps"] {
                assert_eq!(
                    route_kind(inner_type, has, None, true),
                    "record_wrapped",
                    "wrapped multiplex frame (inner type {inner_type}) must route to the record driver",
                );
            }
        }
    }

    #[test]
    fn cancel_task_resolves_via_the_process_run_map() {
        // cancel_task routing depends only on the process-global task_id→run_id map (no browser). An
        // unknown/finished task resolves to None (no-op); a bound task resolves to its run_id so the
        // arm can call engine.cancel(run_id).
        use super::super::agent::runs;
        let tid = "gateway-cancel-route-test-1";
        assert!(runs::run_id_for(tid).is_none(), "unknown task → no live run to cancel");
        runs::bind(tid, 777);
        assert_eq!(runs::run_id_for(tid), Some(777), "bound task resolves to its run_id");
        runs::unbind(tid);
        assert!(runs::run_id_for(tid).is_none(), "after terminal/unbind → no-op cancel");
    }
}
