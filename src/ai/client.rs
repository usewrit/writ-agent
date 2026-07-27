use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, OnceLock};

use dashmap::DashMap;
use futures_util::stream::{SplitSink, SplitStream};
use futures_util::{SinkExt, StreamExt};
use tokio::net::TcpStream;
use tokio::sync::{oneshot, Mutex};
use tokio::task::JoinHandle;
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::{connect_async, MaybeTlsStream, WebSocketStream};

use super::json_parser::parse_ai_json;
use super::relay::GatewaySessionRelay;
use crate::models::ai::{AiCompletionRequest, AiContentPart, AiMessage, AiMessageContent, ImageSource};
use crate::models::messages::GatewayOutgoing;

// ── Shared singleton ──────────────────────────────────────────

/// Process-wide shared AI client instance.
///
/// Set once at startup via `set_shared_client()`, then retrieved anywhere via
/// `get_shared_client()`.  Uses `std::sync::OnceLock` (stable since Rust 1.70).
static SHARED_CLIENT: OnceLock<Arc<Mutex<GatewayAIClient>>> = OnceLock::new();

/// Store the shared client singleton.  Returns `Err` if already set.
pub fn set_shared_client(client: Arc<Mutex<GatewayAIClient>>) -> Result<(), Arc<Mutex<GatewayAIClient>>> {
    SHARED_CLIENT.set(client)
}

/// Retrieve the shared client singleton (if set).
pub fn get_shared_client() -> Option<Arc<Mutex<GatewayAIClient>>> {
    SHARED_CLIENT.get().cloned()
}

// ── Direct provider transport (BYO keys / local Ollama) ────────
// When the agent has local provider keys, AI runs DIRECTLY against the provider
// instead of routing through the backend gateway — keys never leave the agent.

/// Direct-provider configuration (BYO key).
///
/// `Debug` is hand-written: `api_key` is a live provider credential and a derived `Debug` prints it in
/// full wherever this struct reaches a log line, a panic message or a `?`-formatted error. Same pattern
/// as `local::ai::provider::AiConfig` and `local::cloud::token::TokenPair`.
#[derive(Clone)]
pub struct DirectAiConfig {
    pub provider: String,
    pub api_key: Option<String>,
    pub model: String,
    pub base_url: Option<String>,
}

impl std::fmt::Debug for DirectAiConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DirectAiConfig")
            .field("provider", &self.provider)
            .field("model", &self.model)
            .field("base_url", &self.base_url)
            // NEVER print key material — only whether one is set.
            .field("api_key", &self.api_key.as_ref().map(|_| "<redacted>"))
            .finish()
    }
}

/// Build direct-provider config from EXPLICIT values — no environment access.
///
/// This is the form callers that already hold the configuration in memory should use. It exists
/// because the only reason `~/.writ/config.yaml`'s `ai.api_key` was ever staged into the process
/// environment (`cli::setup::apply_ai_env_vars`) was that the resolution below read it from there —
/// and the process environment is inherited by the browser subprocess, where it is readable via
/// `/proc/<pid>/environ`. Passing the key in closes that: see the note on `apply_ai_env_vars`.
///
/// Every argument is optional and follows the same precedence the env form does:
/// * `provider` explicit, else inferred from which key/base-url is present;
/// * `anthropic_key`/`openai_key` select the provider when it is not stated;
/// * `ollama` gets the local default base url;
/// * `openai` with no key yields `None` (there is nothing to call).
pub fn direct_ai_config_from(
    provider: Option<&str>,
    anthropic_key: Option<&str>,
    openai_key: Option<&str>,
    base_url: Option<&str>,
    model: Option<&str>,
) -> Option<DirectAiConfig> {
    let clean = |s: Option<&str>| s.map(str::trim).filter(|s| !s.is_empty()).map(str::to_string);
    let explicit = clean(provider).map(|s| s.to_lowercase());
    let anthropic_key = clean(anthropic_key);
    let openai_key = clean(openai_key);
    let base_url = clean(base_url);
    let model = clean(model);

    let provider = explicit.or_else(|| {
        if anthropic_key.is_some() {
            Some("anthropic".to_string())
        } else if base_url.as_deref().is_some_and(|b| b.contains("11434")) {
            Some("ollama".to_string())
        } else if openai_key.is_some() || base_url.is_some() {
            Some("openai".to_string())
        } else {
            None
        }
    })?;

    if provider == "anthropic" {
        let key = anthropic_key?;
        return Some(DirectAiConfig {
            provider,
            api_key: Some(key),
            model: model.unwrap_or_else(|| "claude-sonnet-4-20250514".to_string()),
            base_url,
        });
    }

    // openai / ollama / custom — all OpenAI-compatible chat
    let mut base_url = base_url;
    if provider == "ollama" && base_url.is_none() {
        base_url = Some("http://localhost:11434/v1".to_string());
    }
    if provider == "openai" && openai_key.is_none() {
        return None;
    }
    Some(DirectAiConfig {
        provider,
        api_key: openai_key,
        model: model.unwrap_or_else(|| "gpt-4o".to_string()),
        base_url,
    })
}

/// Build direct-provider config from the process ENVIRONMENT, or `None` if no keys are configured.
///
/// This remains the fallback for keys the USER exported in their own shell (`ANTHROPIC_API_KEY=… writ
/// …`), which is a legitimate source we cannot see any other way — see
/// `local::ai::provider::resolve_config`, whose primary source is the encrypted store. It is no longer
/// how the agent's OWN configured key is resolved: that is passed in via [`direct_ai_config_from`], so
/// nothing this crate controls has to put a key in the environment.
pub fn detect_direct_ai_config() -> Option<DirectAiConfig> {
    let env = |k: &str| std::env::var(k).ok().filter(|s| !s.is_empty());
    let provider = env("AI_PROVIDER");
    let anthropic_key = env("ANTHROPIC_API_KEY");
    // `OPENAI_MODEL` is only a fallback for the OpenAI-compatible providers; it must not become an
    // Anthropic model name (the pre-refactor code read it in that branch only).
    let anthropic_selected = match provider.as_deref() {
        Some(p) => p.trim().eq_ignore_ascii_case("anthropic"),
        None => anthropic_key.is_some(),
    };
    let model = env("AI_MODEL").or_else(|| if anthropic_selected { None } else { env("OPENAI_MODEL") });
    direct_ai_config_from(
        provider.as_deref(),
        anthropic_key.as_deref(),
        env("OPENAI_API_KEY").as_deref(),
        env("AI_BASE_URL").or_else(|| env("OPENAI_BASE_URL")).as_deref(),
        model.as_deref(),
    )
}

/// True if the agent can run AI directly — advertised as a capability so the
/// gateway routes BYO calls to this agent instead of using managed keys.
pub fn ai_keys_configured() -> bool {
    detect_direct_ai_config().is_some()
}

/// Convert internal (Anthropic-shaped) messages to OpenAI chat format.
fn to_openai_messages(messages: &[AiMessage], system: Option<&str>) -> Vec<serde_json::Value> {
    let mut out: Vec<serde_json::Value> = Vec::new();
    if let Some(sys) = system {
        out.push(serde_json::json!({"role": "system", "content": sys}));
    }
    for m in messages {
        match &m.content {
            AiMessageContent::Text(t) => {
                out.push(serde_json::json!({"role": m.role, "content": t}));
            }
            AiMessageContent::Parts(parts) => {
                let conv: Vec<serde_json::Value> = parts
                    .iter()
                    .map(|p| match p {
                        AiContentPart::Text { text } => {
                            serde_json::json!({"type": "text", "text": text})
                        }
                        AiContentPart::Image { source } => serde_json::json!({
                            "type": "image_url",
                            "image_url": {"url": format!("data:{};base64,{}", source.media_type, source.data)}
                        }),
                    })
                    .collect();
                out.push(serde_json::json!({"role": m.role, "content": conv}));
            }
        }
    }
    out
}

/// Call the configured provider directly (BYO key). Returns `{"content", "usage"}`.
async fn direct_complete(
    messages: &[AiMessage],
    system: Option<&str>,
    max_tokens: u32,
    cfg: &DirectAiConfig,
) -> anyhow::Result<serde_json::Value> {
    // Every other outbound client in this crate sets a timeout; this one did not, so a hung or
    // black-holing AI endpoint would keep an in-flight run (and its governor permit) parked forever.
    // `connect_timeout` is separate from the total timeout: reqwest's default connect timeout is
    // `None`, so a host that accepts nothing would otherwise hold the slot for the full window.
    let http = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(120))
        .connect_timeout(std::time::Duration::from_secs(10))
        .build()
        .unwrap_or_else(|_| reqwest::Client::new());

    if cfg.provider == "anthropic" {
        let base = cfg
            .base_url
            .clone()
            .unwrap_or_else(|| "https://api.anthropic.com".to_string());
        let url = format!("{}/v1/messages", base.trim_end_matches('/'));
        let mut body = serde_json::json!({
            "model": cfg.model,
            "max_tokens": max_tokens,
            "messages": messages,
        });
        if let Some(sys) = system {
            body["system"] = serde_json::json!(sys);
        }
        let data: serde_json::Value = http
            .post(&url)
            .header("x-api-key", cfg.api_key.clone().unwrap_or_default())
            .header("anthropic-version", "2023-06-01")
            .header("content-type", "application/json")
            .json(&body)
            .send()
            .await?
            .error_for_status()?
            .json()
            .await?;
        let text = data
            .get("content")
            .and_then(|c| c.as_array())
            .map(|arr| {
                arr.iter()
                    .filter(|p| p.get("type").and_then(|t| t.as_str()) == Some("text"))
                    .filter_map(|p| p.get("text").and_then(|t| t.as_str()))
                    .collect::<Vec<_>>()
                    .join("")
            })
            .unwrap_or_default();
        return Ok(serde_json::json!({
            "content": text,
            "usage": data.get("usage").cloned().unwrap_or_else(|| serde_json::json!({})),
        }));
    }

    // openai / ollama / custom (OpenAI-compatible)
    let base = cfg
        .base_url
        .clone()
        .unwrap_or_else(|| "https://api.openai.com/v1".to_string());
    let url = format!("{}/chat/completions", base.trim_end_matches('/'));
    let body = serde_json::json!({
        "model": cfg.model,
        "max_tokens": max_tokens,
        "messages": to_openai_messages(messages, system),
    });
    let mut req = http
        .post(&url)
        .header("content-type", "application/json")
        .json(&body);
    if let Some(k) = &cfg.api_key {
        if !k.is_empty() {
            req = req.header("authorization", format!("Bearer {}", k));
        }
    }
    let data: serde_json::Value = req.send().await?.error_for_status()?.json().await?;
    let text = data
        .get("choices")
        .and_then(|c| c.get(0))
        .and_then(|c| c.get("message"))
        .and_then(|m| m.get("content"))
        .and_then(|t| t.as_str())
        .unwrap_or("")
        .to_string();
    Ok(serde_json::json!({
        "content": text,
        "usage": data.get("usage").cloned().unwrap_or_else(|| serde_json::json!({})),
    }))
}

// ── Type aliases ───────────────────────────────────────────────

/// Write half of the gateway WebSocket.
pub type WsSink = SplitSink<WebSocketStream<MaybeTlsStream<TcpStream>>, Message>;
/// Read half of the gateway WebSocket.
pub type WsStream = SplitStream<WebSocketStream<MaybeTlsStream<TcpStream>>>;

/// Async callback: `(session_id, purpose, config, relay) -> bool` (accepted?)
pub type SessionOpenHandler = Box<
    dyn Fn(String, String, serde_json::Value, GatewaySessionRelay)
            -> Pin<Box<dyn Future<Output = bool> + Send>>
        + Send
        + Sync,
>;

/// Async callback: `(session_id, inner_msg) -> ()`
pub type SessionMessageHandler = Box<
    dyn Fn(String, serde_json::Value) -> Pin<Box<dyn Future<Output = ()> + Send>>
        + Send
        + Sync,
>;

/// Async callback: `(session_id) -> ()`
pub type SessionCloseHandler =
    Box<dyn Fn(String) -> Pin<Box<dyn Future<Output = ()> + Send>> + Send + Sync>;

// ── Client ─────────────────────────────────────────────────────

/// Unified AI client -- routes all LLM calls through the backend AI gateway
/// via a warm WebSocket connection.
///
/// One instance per recorder process, shared across all concurrent sessions.
/// Tenant ID is set per-request (different sessions may belong to different tenants).
///
/// Also handles session multiplexing: the ws-gateway routes frontend recording
/// sessions through this single WS connection using `session_open` /
/// `session_close` messages and `{ channel: "session" }` envelopes.
pub struct GatewayAIClient {
    ws_url: String,
    recorder_secret: String,
    /// STABLE backend-derived agent identity. The backend AI-gateway WS binds every
    /// AI charge to the reporting agent (Agent row keyed by agent_id) and REJECTS a
    /// connection with no agent_id (close 4003), so a tenant's wallet cannot be
    /// drained by a forged payload tenant_id. This is the SAME id the bridge sends to
    /// /connect for warm-session affinity (deployment bakes it in as AGENT_ID).
    agent_id: String,
    /// Write half shared with relay instances.
    ws_tx: Option<Arc<Mutex<WsSink>>>,
    /// In-flight completion requests keyed by request_id.
    pending: Arc<DashMap<String, oneshot::Sender<serde_json::Value>>>,
    /// Whether the WS connection is alive.
    connected: Arc<AtomicBool>,
    /// Background listener task handle.
    listener_handle: Option<JoinHandle<()>>,

    // Session multiplexing handlers (set by recorder at startup)
    session_open_handler: Option<Arc<SessionOpenHandler>>,
    session_message_handler: Option<Arc<SessionMessageHandler>>,
    session_close_handler: Option<Arc<SessionCloseHandler>>,

    /// Transport: "gateway" (route via backend) or "direct" (call provider with local keys).
    transport: String,
    direct_cfg: Option<DirectAiConfig>,
}

impl GatewayAIClient {
    pub fn new(ws_url: String, recorder_secret: String) -> Self {
        // Default the stable agent identity from the env the deployment bakes in
        // (AGENT_ID, see backend providers/*_provider.py). Callers that hold the id
        // explicitly should use `with_agent_id` to thread it in.
        let agent_id = std::env::var("AGENT_ID")
            .ok()
            .or_else(|| std::env::var("RECORDER_AGENT_ID").ok())
            .map(|s| s.trim().to_string())
            .unwrap_or_default();
        Self {
            ws_url: ws_url.trim_end_matches('/').to_string(),
            recorder_secret,
            agent_id,
            ws_tx: None,
            pending: Arc::new(DashMap::new()),
            connected: Arc::new(AtomicBool::new(false)),
            listener_handle: None,
            session_open_handler: None,
            session_message_handler: None,
            session_close_handler: None,
            transport: "gateway".to_string(),
            direct_cfg: None,
        }
    }

    /// Set the STABLE backend-derived agent identity explicitly (e.g. the id a
    /// caller already obtained from /connect). Overrides the env-sourced default so
    /// the AI-gateway WS connect carries the correct `agent_id` the backend bills to.
    pub fn with_agent_id(mut self, agent_id: impl Into<String>) -> Self {
        let id = agent_id.into().trim().to_string();
        if !id.is_empty() {
            self.agent_id = id;
        }
        self
    }

    /// Construct a DIRECT-mode client that calls the provider with local keys
    /// (keys never leave the agent). No gateway WS is used.
    pub fn new_direct(cfg: DirectAiConfig) -> Self {
        let mut c = Self::new(String::new(), String::new());
        c.transport = "direct".to_string();
        c.direct_cfg = Some(cfg);
        c.connected.store(true, Ordering::SeqCst);
        c
    }

    // ── Connection lifecycle ───────────────────────────────────

    /// Establish warm WS connection to the backend AI gateway.
    pub async fn connect(&mut self) -> anyhow::Result<()> {
        if self.transport == "direct" {
            self.connected.store(true, Ordering::SeqCst);
            tracing::info!(
                provider = ?self.direct_cfg.as_ref().map(|c| c.provider.as_str()),
                "AI client DIRECT mode — calling provider directly, no gateway"
            );
            return Ok(());
        }
        let recorder_port =
            std::env::var("RECORDER_PORT").unwrap_or_else(|_| "8081".to_string());
        let recorder_host =
            std::env::var("RECORDER_HOST").unwrap_or_else(|_| "playwright-recorder".to_string());
        let recorder_url = std::env::var("RECORDER_SELF_URL")
            .unwrap_or_else(|_| format!("http://{}:{}", recorder_host, recorder_port));
        let max_sessions =
            std::env::var("RECORDER_MAX_SESSIONS").unwrap_or_else(|_| "5".to_string());

        let encoded_url = urlencoding::encode(&recorder_url);
        let mut url = format!(
            "{}/ws/ai-gateway?secret={}&role=recorder&recorder_url={}&max_sessions={}",
            self.ws_url, self.recorder_secret, encoded_url, max_sessions,
        );
        // Bind this connection's AI charges to our stable agent identity. The backend
        // rejects a connection with no agent_id (close 4003), so always send it when
        // known.
        if !self.agent_id.is_empty() {
            url.push_str(&format!("&agent_id={}", urlencoding::encode(&self.agent_id)));
        }

        let (ws_stream, _response) = connect_async(&url).await?;
        let (sink, stream) = ws_stream.split();
        let ws_tx = Arc::new(Mutex::new(sink));

        self.ws_tx = Some(ws_tx.clone());
        self.connected.store(true, Ordering::SeqCst);

        // Spawn listener
        let handle = self.spawn_listener(ws_tx.clone(), stream);
        self.listener_handle = Some(handle);

        tracing::info!(
            ws_url = %self.ws_url,
            recorder_url = %recorder_url,
            "AI gateway WS connected"
        );
        Ok(())
    }

    /// Gracefully close the connection, cancel the listener, and fail all pending requests.
    pub async fn close(&mut self) {
        self.connected.store(false, Ordering::SeqCst);

        if let Some(handle) = self.listener_handle.take() {
            handle.abort();
            let _ = handle.await;
        }

        if let Some(tx) = self.ws_tx.take() {
            let mut sink = tx.lock().await;
            let _ = sink.close().await;
        }

        // Fail all pending requests
        let keys: Vec<String> = self.pending.iter().map(|r| r.key().clone()).collect();
        for key in keys {
            if let Some((_, sender)) = self.pending.remove(&key) {
                let _ = sender.send(serde_json::json!({
                    "error": "AI client closed"
                }));
            }
        }
    }

    /// Whether the WS connection is alive.
    pub fn is_connected(&self) -> bool {
        if self.transport == "direct" {
            return true;
        }
        self.connected.load(Ordering::SeqCst)
    }

    /// Register session multiplexing handlers.
    pub fn set_session_handlers(
        &mut self,
        on_open: SessionOpenHandler,
        on_message: SessionMessageHandler,
        on_close: SessionCloseHandler,
    ) {
        self.session_open_handler = Some(Arc::new(on_open));
        self.session_message_handler = Some(Arc::new(on_message));
        self.session_close_handler = Some(Arc::new(on_close));
    }

    /// Get a clone of the write half (used when creating relays externally).
    pub fn ws_tx(&self) -> Option<Arc<Mutex<WsSink>>> {
        self.ws_tx.clone()
    }

    // ── Reconnect ──────────────────────────────────────────────

    /// Maximum number of automatic reconnection attempts.
    #[allow(dead_code)] // used by the retained `_reconnect` path
    const MAX_RECONNECT_ATTEMPTS: u32 = 3;
    /// Base delay between reconnection attempts (doubles each time).
    #[allow(dead_code)] // used by the retained `_reconnect` path
    const RECONNECT_BASE_DELAY_MS: u64 = 1000;

    /// Attempt to re-establish the WebSocket connection.
    ///
    /// Tears down the old listener, opens a fresh WS, and spawns a new
    /// listener task.  Returns `Ok(())` on success.
    async fn _reconnect(&mut self) -> anyhow::Result<()> {
        tracing::info!("Attempting AI gateway reconnect...");

        // Tear down old connection.
        self.connected.store(false, Ordering::SeqCst);
        if let Some(handle) = self.listener_handle.take() {
            handle.abort();
            let _ = handle.await;
        }
        if let Some(tx) = self.ws_tx.take() {
            let mut sink = tx.lock().await;
            let _ = sink.close().await;
        }

        // Re-establish.
        for attempt in 1..=Self::MAX_RECONNECT_ATTEMPTS {
            let delay = std::time::Duration::from_millis(
                Self::RECONNECT_BASE_DELAY_MS * (1 << (attempt - 1)),
            );
            tracing::debug!(attempt, delay_ms = delay.as_millis(), "Reconnect attempt");
            tokio::time::sleep(delay).await;

            match self.connect().await {
                Ok(()) => {
                    tracing::info!(attempt, "AI gateway reconnected successfully");
                    return Ok(());
                }
                Err(e) => {
                    tracing::warn!(
                        attempt,
                        error = %e,
                        "Reconnect attempt failed"
                    );
                }
            }
        }

        anyhow::bail!(
            "AI gateway reconnect failed after {} attempts",
            Self::MAX_RECONNECT_ATTEMPTS
        )
    }

    // ── Core request/response ──────────────────────────────────

    /// Send an AI completion request over the WS and wait for the response.
    ///
    /// If the connection is detected as dropped, one automatic reconnect
    /// cycle is attempted before failing.
    pub async fn send_and_wait(
        &self,
        messages: Vec<AiMessage>,
        tenant_id: &str,
        system: Option<&str>,
        max_tokens: u32,
        purpose: &str,
        timeout_secs: u64,
    ) -> anyhow::Result<serde_json::Value> {
        if self.transport == "direct" {
            let cfg = self
                .direct_cfg
                .as_ref()
                .ok_or_else(|| anyhow::anyhow!("direct transport but no config"))?;
            return direct_complete(&messages, system, max_tokens, cfg).await;
        }
        if !self.is_connected() {
            // Connection is known to be dead.  The caller should use the
            // shared client mutex to call `_reconnect()`, but we surface a
            // clear error so they can.
            anyhow::bail!("AI gateway not connected (call reconnect)");
        }

        let ws_tx = self
            .ws_tx
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("No WS connection"))?;

        let request_id = uuid::Uuid::new_v4().to_string();
        let (tx, rx) = oneshot::channel::<serde_json::Value>();
        self.pending.insert(request_id.clone(), tx);

        // Build payload
        let request = AiCompletionRequest {
            tenant_id: Some(tenant_id.to_string()),
            messages,
            max_tokens,
            purpose: purpose.to_string(),
            system: system.map(|s| s.to_string()),
        };

        let envelope = serde_json::json!({
            "type": "ai_completion",
            "request_id": request_id,
            "payload": serde_json::to_value(&request)?,
        });

        {
            let mut sink = ws_tx.lock().await;
            // On send failure the response can never arrive, so drop the pending
            // entry before propagating — otherwise the map leaks one oneshot
            // sender per failed request for the life of the client.
            if let Err(e) = sink.send(Message::Text(serde_json::to_string(&envelope)?)).await {
                drop(sink);
                self.pending.remove(&request_id);
                return Err(e.into());
            }
        }

        // Wait with timeout
        match tokio::time::timeout(std::time::Duration::from_secs(timeout_secs), rx).await {
            Ok(Ok(value)) => {
                // Check if the resolved value is an error
                if let Some(err) = value.get("error").and_then(|e| e.as_str()) {
                    anyhow::bail!("AI completion error: {}", err);
                }
                Ok(value)
            }
            Ok(Err(_)) => {
                self.pending.remove(&request_id);
                anyhow::bail!("AI completion channel closed unexpectedly")
            }
            Err(_) => {
                self.pending.remove(&request_id);
                anyhow::bail!("AI completion timed out after {}s", timeout_secs)
            }
        }
    }

    // ── High-level convenience methods ─────────────────────────

    /// Text-only completion -> parsed JSON.
    pub async fn complete_json(
        &self,
        system_prompt: &str,
        user_prompt: &str,
        tenant_id: &str,
        max_tokens: u32,
        purpose: &str,
    ) -> Option<serde_json::Value> {
        let messages = vec![AiMessage {
            role: "user".to_string(),
            content: AiMessageContent::Text(user_prompt.to_string()),
        }];

        match self
            .send_and_wait(messages, tenant_id, Some(system_prompt), max_tokens, purpose, 120)
            .await
        {
            Ok(result) => {
                let content = result
                    .get("content")
                    .and_then(|c| c.as_str())
                    .unwrap_or("");
                parse_ai_json(content)
            }
            Err(e) => {
                tracing::error!(error = %e, "complete_json failed");
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
        let messages = vec![AiMessage {
            role: "user".to_string(),
            content: AiMessageContent::Parts(vec![
                AiContentPart::Image {
                    source: ImageSource {
                        source_type: "base64".to_string(),
                        media_type: "image/jpeg".to_string(),
                        data: screenshot_b64.to_string(),
                    },
                },
                AiContentPart::Text {
                    text: prompt.to_string(),
                },
            ]),
        }];

        match self
            .send_and_wait(messages, tenant_id, None, max_tokens, purpose, 120)
            .await
        {
            Ok(result) => {
                let content = result
                    .get("content")
                    .and_then(|c| c.as_str())
                    .unwrap_or("");
                parse_ai_json(content)
            }
            Err(e) => {
                tracing::error!(error = %e, "complete_vision failed");
                None
            }
        }
    }

    /// Vision + system prompt -> parsed JSON.
    pub async fn complete_vision_with_system(
        &self,
        system_prompt: &str,
        screenshot_b64: &str,
        prompt: &str,
        tenant_id: &str,
        max_tokens: u32,
        purpose: &str,
    ) -> Option<serde_json::Value> {
        let messages = vec![AiMessage {
            role: "user".to_string(),
            content: AiMessageContent::Parts(vec![
                AiContentPart::Image {
                    source: ImageSource {
                        source_type: "base64".to_string(),
                        media_type: "image/jpeg".to_string(),
                        data: screenshot_b64.to_string(),
                    },
                },
                AiContentPart::Text {
                    text: prompt.to_string(),
                },
            ]),
        }];

        match self
            .send_and_wait(
                messages,
                tenant_id,
                Some(system_prompt),
                max_tokens,
                purpose,
                120,
            )
            .await
        {
            Ok(result) => {
                let content = result
                    .get("content")
                    .and_then(|c| c.as_str())
                    .unwrap_or("");
                parse_ai_json(content)
            }
            Err(e) => {
                tracing::error!(error = %e, "complete_vision_with_system failed");
                None
            }
        }
    }

    /// Raw completion -> text string.
    pub async fn complete_raw(
        &self,
        messages: Vec<AiMessage>,
        tenant_id: &str,
        system: Option<&str>,
        max_tokens: u32,
        purpose: &str,
    ) -> anyhow::Result<String> {
        let result = self
            .send_and_wait(messages, tenant_id, system, max_tokens, purpose, 120)
            .await?;
        let content = result
            .get("content")
            .and_then(|c| c.as_str())
            .unwrap_or("")
            .to_string();
        Ok(content)
    }

    // ── Listener ───────────────────────────────────────────────

    /// Spawn the background WS listener task.
    fn spawn_listener(
        &self,
        ws_tx: Arc<Mutex<WsSink>>,
        mut stream: WsStream,
    ) -> JoinHandle<()> {
        let pending = self.pending.clone();
        let connected = self.connected.clone();
        let on_open = self.session_open_handler.clone();
        let on_message = self.session_message_handler.clone();
        let on_close = self.session_close_handler.clone();

        tokio::spawn(async move {
            while let Some(result) = stream.next().await {
                let msg = match result {
                    Ok(m) => m,
                    Err(e) => {
                        tracing::error!(error = %e, "AI gateway WS read error");
                        break;
                    }
                };

                match msg {
                    Message::Text(text) => {
                        let parsed: serde_json::Value = match serde_json::from_str(&text) {
                            Ok(v) => v,
                            Err(_) => continue,
                        };

                        let msg_type = parsed.get("type").and_then(|t| t.as_str()).unwrap_or("");
                        let channel = parsed.get("channel").and_then(|c| c.as_str()).unwrap_or("");
                        let request_id = parsed
                            .get("request_id")
                            .and_then(|r| r.as_str())
                            .unwrap_or("");

                        match msg_type {
                            // AI completion responses
                            "ai_completion_result" if !request_id.is_empty() => {
                                if let Some((_, sender)) = pending.remove(request_id) {
                                    let payload = parsed
                                        .get("payload")
                                        .cloned()
                                        .unwrap_or(serde_json::Value::Null);
                                    let _ = sender.send(payload);
                                }
                            }

                            "ai_completion_error" if !request_id.is_empty() => {
                                if let Some((_, sender)) = pending.remove(request_id) {
                                    let error_msg = parsed
                                        .get("payload")
                                        .and_then(|p| p.get("error"))
                                        .and_then(|e| e.as_str())
                                        .unwrap_or("AI call failed");
                                    let _ = sender.send(serde_json::json!({
                                        "error": error_msg
                                    }));
                                }
                            }

                            // Session multiplexing: open
                            "session_open" => {
                                let session_id = parsed
                                    .get("session_id")
                                    .and_then(|s| s.as_str())
                                    .unwrap_or("")
                                    .to_string();
                                let purpose = parsed
                                    .get("purpose")
                                    .and_then(|p| p.as_str())
                                    .unwrap_or("record")
                                    .to_string();
                                let config = parsed
                                    .get("config")
                                    .cloned()
                                    .unwrap_or(serde_json::Value::Object(Default::default()));

                                if let Some(ref handler) = on_open {
                                    if !session_id.is_empty() {
                                        let relay = GatewaySessionRelay::new(
                                            ws_tx.clone(),
                                            session_id.clone(),
                                        );
                                        let handler = handler.clone();
                                        let ws_tx_c = ws_tx.clone();
                                        let sid = session_id.clone();
                                        tokio::spawn(async move {
                                            handle_session_open(
                                                handler, ws_tx_c, sid, purpose, config,
                                                relay,
                                            )
                                            .await;
                                        });
                                    }
                                } else {
                                    tracing::warn!(
                                        session_id = %session_id,
                                        "session_open received but no handler registered"
                                    );
                                }
                            }

                            // Session multiplexing: close
                            "session_close" => {
                                let session_id = parsed
                                    .get("session_id")
                                    .and_then(|s| s.as_str())
                                    .unwrap_or("")
                                    .to_string();
                                if let Some(ref handler) = on_close {
                                    if !session_id.is_empty() {
                                        let handler = handler.clone();
                                        let sid = session_id;
                                        tokio::spawn(async move {
                                            (handler)(sid).await;
                                        });
                                    }
                                }
                            }

                            // Keepalive
                            "ping" => {
                                let pong = GatewayOutgoing::Pong;
                                if let Ok(text) = serde_json::to_string(&pong) {
                                    let mut sink = ws_tx.lock().await;
                                    let _ = sink.send(Message::Text(text)).await;
                                }
                            }

                            // Session relay messages (channel == "session")
                            _ if channel == "session" => {
                                let session_id = parsed
                                    .get("session_id")
                                    .and_then(|s| s.as_str())
                                    .unwrap_or("")
                                    .to_string();
                                let inner = parsed
                                    .get("msg")
                                    .cloned()
                                    .unwrap_or(serde_json::Value::Object(Default::default()));
                                if let Some(ref handler) = on_message {
                                    if !session_id.is_empty() {
                                        let handler = handler.clone();
                                        let sid = session_id;
                                        tokio::spawn(async move {
                                            (handler)(sid, inner).await;
                                        });
                                    }
                                }
                            }

                            _ => {
                                tracing::trace!(msg_type = %msg_type, "Unhandled gateway message");
                            }
                        }
                    }

                    Message::Close(_) => {
                        tracing::info!("AI gateway WS closed by server");
                        break;
                    }

                    // Binary frames / pings handled by tungstenite automatically
                    _ => {}
                }
            }

            // Connection lost
            connected.store(false, Ordering::SeqCst);

            // Fail all pending
            let keys: Vec<String> = pending.iter().map(|r| r.key().clone()).collect();
            for key in keys {
                if let Some((_, sender)) = pending.remove(&key) {
                    let _ = sender.send(serde_json::json!({
                        "error": "AI gateway connection lost"
                    }));
                }
            }

            tracing::warn!("AI gateway listener exited");
        })
    }
}

// ── Object-safe AI client trait ────────────────────────────────

/// Object-safe abstraction over an AI completion backend.
///
/// Implemented by both [`GatewayAIClient`] (its own WS to the AI gateway) and
/// `BridgeAIClient` (routes over the bridge's existing WS), so the AI modes
/// (standard / intelligent / api_discovery) can be driven by either transport
/// through `&dyn AiClient`. Uses the boxed-future pattern (no `async-trait`
/// dependency), mirroring [`crate::dom::analyzer::PageEvaluator`].
pub trait AiClient: Send + Sync {
    fn complete_json<'a>(
        &'a self,
        system_prompt: &'a str,
        user_prompt: &'a str,
        tenant_id: &'a str,
        max_tokens: u32,
        purpose: &'a str,
    ) -> Pin<Box<dyn Future<Output = Option<serde_json::Value>> + Send + 'a>>;

    fn complete_vision<'a>(
        &'a self,
        screenshot_b64: &'a str,
        prompt: &'a str,
        tenant_id: &'a str,
        max_tokens: u32,
        purpose: &'a str,
    ) -> Pin<Box<dyn Future<Output = Option<serde_json::Value>> + Send + 'a>>;

    fn complete_vision_with_system<'a>(
        &'a self,
        system_prompt: &'a str,
        screenshot_b64: &'a str,
        prompt: &'a str,
        tenant_id: &'a str,
        max_tokens: u32,
        purpose: &'a str,
    ) -> Pin<Box<dyn Future<Output = Option<serde_json::Value>> + Send + 'a>>;
}

impl AiClient for GatewayAIClient {
    fn complete_json<'a>(
        &'a self,
        system_prompt: &'a str,
        user_prompt: &'a str,
        tenant_id: &'a str,
        max_tokens: u32,
        purpose: &'a str,
    ) -> Pin<Box<dyn Future<Output = Option<serde_json::Value>> + Send + 'a>> {
        // Inherent method shadows the trait method — no recursion.
        Box::pin(GatewayAIClient::complete_json(
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
    ) -> Pin<Box<dyn Future<Output = Option<serde_json::Value>> + Send + 'a>> {
        Box::pin(GatewayAIClient::complete_vision(
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
    ) -> Pin<Box<dyn Future<Output = Option<serde_json::Value>> + Send + 'a>> {
        Box::pin(GatewayAIClient::complete_vision_with_system(
            self, system_prompt, screenshot_b64, prompt, tenant_id, max_tokens, purpose,
        ))
    }
}

/// Handle a session_open: call the recorder's handler, then send confirmation or rejection.
async fn handle_session_open(
    handler: Arc<SessionOpenHandler>,
    ws_tx: Arc<Mutex<WsSink>>,
    session_id: String,
    purpose: String,
    config: serde_json::Value,
    relay: GatewaySessionRelay,
) {
    let accepted = (handler)(session_id.clone(), purpose, config, relay).await;

    if accepted {
        let ack = GatewayOutgoing::SessionOpened {
            session_id: session_id.clone(),
        };
        if let Ok(text) = serde_json::to_string(&ack) {
            let mut sink = ws_tx.lock().await;
            let _ = sink.send(Message::Text(text)).await;
        }
        tracing::info!(session_id = %session_id, "Session opened via gateway relay");
    } else {
        let nack = GatewayOutgoing::SessionOpenFailed {
            session_id: session_id.clone(),
            reason: "Recorder rejected session".to_string(),
        };
        if let Ok(text) = serde_json::to_string(&nack) {
            let mut sink = ws_tx.lock().await;
            let _ = sink.send(Message::Text(text)).await;
        }
    }
}

// Helpers for URL-encoding (avoid pulling in a large crate for just this)
mod urlencoding {
    pub fn encode(input: &str) -> String {
        let mut result = String::with_capacity(input.len() * 3);
        for byte in input.bytes() {
            match byte {
                b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                    result.push(byte as char);
                }
                _ => {
                    result.push('%');
                    result.push_str(&format!("{:02X}", byte));
                }
            }
        }
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn direct_config_debug_never_prints_the_key() {
        let cfg = DirectAiConfig {
            provider: "anthropic".into(),
            api_key: Some("sk-ant-REALSECRETVALUE".into()),
            model: "claude-sonnet-4-20250514".into(),
            base_url: None,
        };
        let shown = format!("{cfg:?}");
        assert!(!shown.contains("REALSECRETVALUE"), "key leaked into Debug: {shown}");
        assert!(shown.contains("<redacted>"), "{shown}");
        // The non-secret fields are still useful for diagnostics.
        assert!(shown.contains("anthropic") && shown.contains("claude-sonnet-4"));

        let none = DirectAiConfig { api_key: None, ..cfg };
        assert!(format!("{none:?}").contains("None"));
    }

    #[test]
    fn explicit_config_resolves_without_touching_the_environment() {
        // Anthropic, selected by its key alone.
        let c = direct_ai_config_from(None, Some("sk-ant-x"), None, None, None).unwrap();
        assert_eq!(c.provider, "anthropic");
        assert_eq!(c.api_key.as_deref(), Some("sk-ant-x"));
        assert_eq!(c.model, "claude-sonnet-4-20250514");

        // OpenAI, selected by its key alone, model default.
        let c = direct_ai_config_from(None, None, Some("sk-o"), None, None).unwrap();
        assert_eq!(c.provider, "openai");
        assert_eq!(c.model, "gpt-4o");

        // Ollama: inferred from the port in the base url, and gets the local default when absent.
        let c = direct_ai_config_from(None, None, None, Some("http://127.0.0.1:11434/v1"), None).unwrap();
        assert_eq!(c.provider, "ollama");
        let c = direct_ai_config_from(Some("ollama"), None, None, None, Some("llama3")).unwrap();
        assert_eq!(c.base_url.as_deref(), Some("http://localhost:11434/v1"));
        assert_eq!(c.model, "llama3");

        // An explicit provider wins over key-based inference.
        let c = direct_ai_config_from(Some("ANTHROPIC"), Some("k"), Some("o"), None, None).unwrap();
        assert_eq!(c.provider, "anthropic");
        assert_eq!(c.api_key.as_deref(), Some("k"));

        // Nothing configured, or `openai` with no key, is None (there is nothing to call).
        assert!(direct_ai_config_from(None, None, None, None, None).is_none());
        assert!(direct_ai_config_from(Some("openai"), None, None, None, None).is_none());
        // Blank/whitespace values count as absent.
        assert!(direct_ai_config_from(None, Some("  "), Some(""), None, None).is_none());
    }
}
