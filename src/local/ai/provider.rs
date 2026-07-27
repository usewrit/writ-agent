//! Multi-provider AI gateway for the local daemon.
//!
//! A single [`complete`] call fans out to whichever provider the user configured — OpenAI
//! (chat completions OR the Responses API), Anthropic, Google Gemini, or any OpenAI-compatible
//! endpoint (OpenRouter, Ollama, a custom URL, a local LLM). Keys never leave the machine: AI runs
//! DIRECTLY against the provider, exactly like the BYO-direct path in [`crate::ai::client`], never
//! through the cloud gateway.
//!
//! Config storage (resolved fresh on every call, so Settings changes apply with no restart):
//!   * non-secret fields (`provider` / `model` / `base_url`) → the plaintext `config` KV table.
//!   * the API key → the SAME `config` KV table but VAULT-SEALED (WF1: ciphertext, AAD-bound) so it
//!     is encrypted at rest and stays OUT of the user-facing Secrets list. Env vars
//!     (`detect_direct_ai_config`) are the fallback when nothing is stored.

use crate::local::error::{LocalError, LocalResult};
use crate::local::store::config_kv;
use crate::local::vault::Vault;
use crate::models::ai::{AiContentPart, AiMessage, AiMessageContent};
use serde::Serialize;
use sqlx::sqlite::SqlitePool;

// `config` KV keys. The API key is stored SEALED (never plaintext) under K_API_KEY.
const K_PROVIDER: &str = "ai.provider";
const K_MODEL: &str = "ai.model";
const K_BASE_URL: &str = "ai.base_url";
const K_API_KEY: &str = "ai.api_key_sealed";
/// AAD binding the sealed key to its config slot (mirrors `vault_secrets|value_encrypted|<key>`).
const API_KEY_AAD: &str = "config|ai.api_key_sealed";
/// When `"true"`, ALL local AI-assist completions are routed through the managed cloud AI gateway
/// (metered/billed to the linked account's wallet) instead of the local BYO provider. Set from
/// Settings → AI Provider; only honored when the daemon is linked (and the `cloud` feature is built).
const K_USE_CLOUD_GATEWAY: &str = "ai.use_cloud_gateway";

// ── Per-feature AI output-token ceilings ("AI usage limits") ─────────────────
// A cap is a CEILING: the effective `max_tokens` for a call = min(built-in default, cap).
// Stored (non-secret plaintext ints) in the SAME `config` KV as provider/model. A missing / null /
// ≤0 cap means "use the built-in default". Three buckets only — there is NO `repair` bucket locally
// (AI repair does not run in the OSS daemon).
const K_MAX_TOKENS_AGENT: &str = "ai.max_tokens.agent";
const K_MAX_TOKENS_ASSIST: &str = "ai.max_tokens.assist";
const K_MAX_TOKENS_OPTIMIZE: &str = "ai.max_tokens.optimize";

/// Built-in default output-token budgets per bucket (exposed to the GET response so the UI can show
/// what a call uses when no cap is set). These mirror the largest hard-coded `max_tokens` literal in
/// each bucket at the call sites in `ai_assist.rs`.
pub const DEFAULT_MAX_TOKENS_AGENT: u32 = 3000;
pub const DEFAULT_MAX_TOKENS_ASSIST: u32 = 2000;
pub const DEFAULT_MAX_TOKENS_OPTIMIZE: u32 = 6000;

/// Sane clamp range for a stored cap (a cap outside this is coerced onto the nearest bound; a cap
/// ≤0 / non-numeric is treated as unset). 128 keeps completions usable; 100k is far above any need.
const CAP_MIN: u32 = 128;
const CAP_MAX: u32 = 100_000;

/// Map a bucket name to its KV key. Unknown buckets have no cap key (→ always the default).
fn cap_key(bucket: &str) -> Option<&'static str> {
    match bucket {
        "agent" => Some(K_MAX_TOKENS_AGENT),
        "assist" => Some(K_MAX_TOKENS_ASSIST),
        "optimize" => Some(K_MAX_TOKENS_OPTIMIZE),
        _ => None,
    }
}

/// Parse + clamp a stored cap string. `None` when unset, blank, non-numeric, or ≤0.
fn parse_cap(raw: Option<String>) -> Option<u32> {
    let n: u32 = raw?.trim().parse().ok()?;
    if n == 0 {
        None
    } else {
        Some(n.clamp(CAP_MIN, CAP_MAX))
    }
}

/// The three currently-stored caps (already clamped), `None` per bucket when unset/≤0.
#[derive(Debug, Clone, Copy, Default, Serialize)]
pub struct AiLimits {
    pub agent: Option<u32>,
    pub assist: Option<u32>,
    pub optimize: Option<u32>,
}

/// Read all three per-feature caps from the `config` KV.
pub async fn read_limits(pool: &SqlitePool) -> LocalResult<AiLimits> {
    Ok(AiLimits {
        agent: parse_cap(config_kv::get(pool, K_MAX_TOKENS_AGENT).await?),
        assist: parse_cap(config_kv::get(pool, K_MAX_TOKENS_ASSIST).await?),
        optimize: parse_cap(config_kv::get(pool, K_MAX_TOKENS_OPTIMIZE).await?),
    })
}

/// Persist a single bucket's cap. `Some(n>0)` stores the clamped value; `None` (or n≤0 pre-filtered
/// by the caller) DELETES the key so the built-in default applies. Unknown buckets are a no-op.
pub async fn set_limit(pool: &SqlitePool, bucket: &str, cap: Option<u32>) -> LocalResult<()> {
    let Some(key) = cap_key(bucket) else { return Ok(()) };
    match cap.filter(|&n| n > 0) {
        Some(n) => config_kv::set(pool, key, &n.clamp(CAP_MIN, CAP_MAX).to_string()).await?,
        None => {
            config_kv::delete(pool, key).await?;
        }
    }
    Ok(())
}

/// Resolve the effective output-token budget for a call: `min(default, cap)` when a positive cap is
/// stored for `bucket`, otherwise the built-in `default`. Buckets with no stored cap (or an unknown
/// bucket) get `default` unchanged, so behavior is identical to before when nothing is set.
pub async fn resolve_max_tokens(pool: &SqlitePool, bucket: &str, default: u32) -> u32 {
    let Some(key) = cap_key(bucket) else { return default };
    let cap = match config_kv::get(pool, key).await {
        Ok(raw) => parse_cap(raw),
        // A KV read failure must never break the AI call — fall back to the default.
        Err(_) => None,
    };
    match cap {
        Some(c) => default.min(c),
        None => default,
    }
}

/// One selectable provider in the catalog the Settings UI renders.
#[derive(Debug, Clone, Serialize)]
pub struct ProviderInfo {
    pub id: &'static str,
    pub label: &'static str,
    /// Whether the provider requires an API key (Ollama / custom local endpoints may not).
    pub needs_key: bool,
    pub default_base_url: &'static str,
    pub default_model: &'static str,
    /// Transport family: `openai_chat` | `openai_responses` | `anthropic` | `google`.
    pub api_style: &'static str,
}

/// The static provider catalog (also drives the Settings dropdown via `/v1/ai/config`).
pub fn provider_catalog() -> Vec<ProviderInfo> {
    vec![
        ProviderInfo { id: "openai", label: "OpenAI", needs_key: true,
            default_base_url: "https://api.openai.com/v1", default_model: "gpt-4o", api_style: "openai_chat" },
        ProviderInfo { id: "openai_responses", label: "OpenAI (Responses API)", needs_key: true,
            default_base_url: "https://api.openai.com/v1", default_model: "gpt-4o", api_style: "openai_responses" },
        ProviderInfo { id: "anthropic", label: "Anthropic (Claude)", needs_key: true,
            default_base_url: "https://api.anthropic.com", default_model: "claude-sonnet-4-20250514", api_style: "anthropic" },
        ProviderInfo { id: "google", label: "Google Gemini", needs_key: true,
            default_base_url: "https://generativelanguage.googleapis.com", default_model: "gemini-2.0-flash", api_style: "google" },
        ProviderInfo { id: "openrouter", label: "OpenRouter", needs_key: true,
            default_base_url: "https://openrouter.ai/api/v1", default_model: "openai/gpt-4o", api_style: "openai_chat" },
        ProviderInfo { id: "ollama", label: "Ollama (local)", needs_key: false,
            default_base_url: "http://localhost:11434/v1", default_model: "llama3.1", api_style: "openai_chat" },
        ProviderInfo { id: "custom", label: "Custom / local (OpenAI-compatible)", needs_key: false,
            default_base_url: "", default_model: "", api_style: "openai_chat" },
    ]
}

/// Map a provider id to its transport family. Unknown ids default to OpenAI-compatible chat — that
/// is the lingua franca for OpenRouter / Ollama / vLLM / LM Studio / any local server.
fn api_style_for(provider: &str) -> &'static str {
    match provider {
        "anthropic" => "anthropic",
        "google" | "gemini" => "google",
        "openai_responses" => "openai_responses",
        _ => "openai_chat",
    }
}

/// Default base URL for a provider when the user left it blank.
fn default_base_url_for(provider: &str) -> Option<&'static str> {
    provider_catalog()
        .into_iter()
        .find(|p| p.id == provider)
        .map(|p| p.default_base_url)
        .filter(|b| !b.is_empty())
}

/// Default model for a provider when the config left it blank.
fn default_model_for(provider: &str) -> Option<&'static str> {
    provider_catalog()
        .into_iter()
        .find(|p| p.id == provider)
        .map(|p| p.default_model)
        .filter(|m| !m.is_empty())
}

/// Fully-resolved AI config (key already opened to plaintext) ready to drive a completion.
///
/// `Debug` is hand-written to REDACT `api_key` (SE-5/F7): a stray `{:?}` — in a log line, an error
/// wrapper, a panic message — must never spill the provider key. Only presence is shown.
#[derive(Clone)]
pub struct AiConfig {
    pub provider: String,
    pub model: String,
    pub base_url: Option<String>,
    pub api_key: Option<String>,
}

impl std::fmt::Debug for AiConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AiConfig")
            .field("provider", &self.provider)
            .field("model", &self.model)
            .field("base_url", &self.base_url)
            // NEVER print key material — show only whether one is set.
            .field("api_key", &self.api_key.as_ref().map(|_| "<redacted>"))
            .finish()
    }
}

/// Read the persisted AI config (decrypting the key), falling back to env vars. `Ok(None)` when no
/// provider has been configured AND no env keys are present.
pub async fn resolve_config(pool: &SqlitePool, vault: &Vault) -> LocalResult<Option<AiConfig>> {
    if let Some(provider) = config_kv::get(pool, K_PROVIDER).await?.filter(|s| !s.trim().is_empty()) {
        let model = config_kv::get(pool, K_MODEL).await?.unwrap_or_default();
        let base_url = config_kv::get(pool, K_BASE_URL).await?.filter(|s| !s.trim().is_empty());
        let api_key = match config_kv::get(pool, K_API_KEY).await? {
            Some(sealed) if !sealed.is_empty() => {
                let bytes = vault.open_field(&sealed, API_KEY_AAD)?;
                Some(String::from_utf8_lossy(&bytes).into_owned())
            }
            _ => None,
        };
        return Ok(Some(AiConfig { provider, model, base_url, api_key }));
    }
    // Env fallback: reuse the recorder crate's existing detector.
    Ok(crate::ai::client::detect_direct_ai_config().map(|c| AiConfig {
        provider: c.provider,
        model: c.model,
        base_url: c.base_url,
        api_key: c.api_key,
    }))
}

/// Whether an API key is currently stored (so the UI can show "saved" without ever revealing it).
pub async fn has_api_key(pool: &SqlitePool) -> LocalResult<bool> {
    Ok(config_kv::get(pool, K_API_KEY).await?.map(|s| !s.is_empty()).unwrap_or(false))
}

/// Persist AI config. `api_key`: `None` leaves the stored key untouched, `Some("")` clears it,
/// `Some(k)` seals + stores `k`. The non-secret fields are always overwritten.
pub async fn save_config(
    pool: &SqlitePool,
    vault: &Vault,
    provider: &str,
    model: &str,
    base_url: Option<&str>,
    api_key: Option<&str>,
) -> LocalResult<()> {
    config_kv::set(pool, K_PROVIDER, provider).await?;
    config_kv::set(pool, K_MODEL, model).await?;
    match base_url {
        Some(b) if !b.trim().is_empty() => config_kv::set(pool, K_BASE_URL, b.trim()).await?,
        _ => {
            config_kv::delete(pool, K_BASE_URL).await?;
        }
    }
    match api_key {
        None => {}
        Some("") => {
            config_kv::delete(pool, K_API_KEY).await?;
        }
        Some(k) => {
            let sealed = vault.seal_field(k.as_bytes(), API_KEY_AAD)?;
            config_kv::set(pool, K_API_KEY, &sealed).await?;
        }
    }
    Ok(())
}

/// Result of a completion: the assistant text + best-effort token usage + the model that answered.
#[derive(Debug, Clone, Serialize, Default)]
pub struct Completion {
    pub text: String,
    pub input_tokens: u32,
    pub output_tokens: u32,
    pub model: String,
}

/// Run a chat completion against the configured provider. `system` is the system/instruction prompt;
/// `messages` is the conversation (Anthropic-shaped internally — converted per provider).
pub async fn complete(
    cfg: &AiConfig,
    messages: &[AiMessage],
    system: Option<&str>,
    max_tokens: u32,
) -> LocalResult<Completion> {
    // A configured model always wins; when the config left it blank (raw-API PUT,
    // partial env config, …) fall back to the catalog default for the provider so
    // the request never goes out with `"model": ""`.
    let defaulted;
    let cfg = if cfg.model.trim().is_empty() {
        match default_model_for(&cfg.provider) {
            Some(m) => {
                defaulted = AiConfig { model: m.to_string(), ..cfg.clone() };
                &defaulted
            }
            None => cfg,
        }
    } else {
        cfg
    };
    let style = api_style_for(&cfg.provider);
    match style {
        "anthropic" => anthropic_complete(cfg, messages, system, max_tokens).await,
        "google" => google_complete(cfg, messages, system, max_tokens).await,
        "openai_responses" => openai_responses_complete(cfg, messages, system, max_tokens).await,
        _ => openai_chat_complete(cfg, messages, system, max_tokens).await,
    }
}

// ── Cloud AI gateway routing ─────────────────────────────────────────────────
// A single toggle (`ai.use_cloud_gateway`) makes every local AI feature run on the
// managed cloud gateway (billed to the wallet) instead of a local BYO key.

/// Whether the "route all local AI through the cloud gateway" toggle is on. A KV read failure is
/// treated as OFF so a storage blip never silently diverts AI (and billing) to the cloud.
pub async fn cloud_gateway_enabled(pool: &SqlitePool) -> bool {
    matches!(config_kv::get(pool, K_USE_CLOUD_GATEWAY).await, Ok(Some(v)) if v == "true")
}

/// Persist the cloud-gateway toggle. `true` stores `"true"`; `false` clears the key.
pub async fn set_cloud_gateway(pool: &SqlitePool, enabled: bool) -> LocalResult<()> {
    if enabled {
        config_kv::set(pool, K_USE_CLOUD_GATEWAY, "true").await?;
    } else {
        config_kv::delete(pool, K_USE_CLOUD_GATEWAY).await?;
    }
    Ok(())
}

/// On a *fresh* cloud link, default the managed cloud AI gateway ON when the user has no local BYO
/// key — so a just-linked desktop can use every AI feature immediately without first configuring a
/// provider. Returns `true` if it flipped the toggle on.
///
/// Intentionally conservative: a no-op when a BYO key is already stored (the user's own key wins) or
/// the gateway is already enabled. Callers MUST invoke this ONLY at the moment a link is first
/// established for a profile (fresh materialization), never on every boot — otherwise it would
/// re-enable the gateway for a user who deliberately turned it off. A KV failure is surfaced so the
/// caller can log it, but is never fatal to the link itself.
pub async fn enable_cloud_gateway_if_no_byo_key(pool: &SqlitePool) -> LocalResult<bool> {
    if has_api_key(pool).await? {
        return Ok(false);
    }
    if cloud_gateway_enabled(pool).await {
        return Ok(false);
    }
    set_cloud_gateway(pool, true).await?;
    Ok(true)
}

/// The AI-completion choke point for local features. When the cloud-gateway toggle is ON (and the
/// daemon is linked, cloud build), routes the completion through the managed gateway; otherwise runs
/// it on the locally-configured BYO provider. `bucket` is the attribution bucket forwarded to the
/// gateway (`agent` | `assist` | `optimize` | `workflow`).
pub async fn complete_routed(
    pool: &SqlitePool,
    vault: &Vault,
    messages: &[AiMessage],
    system: Option<&str>,
    max_tokens: u32,
    bucket: &str,
) -> LocalResult<Completion> {
    if cloud_gateway_enabled(pool).await {
        #[cfg(feature = "cloud")]
        {
            return cloud_gateway_complete(pool, messages, system, max_tokens, bucket).await;
        }
    }
    // `bucket` only labels the cloud path; without the `cloud` feature there is no gateway to route to.
    #[cfg(not(feature = "cloud"))]
    let _ = bucket;
    let cfg = resolve_config(pool, vault)
        .await?
        .filter(|c| !c.provider.trim().is_empty())
        .ok_or_else(|| {
            LocalError::BadRequest(
                "No AI provider configured. Open Settings → AI and choose a provider + API key, or turn on the cloud AI gateway.".into(),
            )
        })?;
    complete(&cfg, messages, system, max_tokens).await
}

/// Like [`complete_routed`] but for callers that ALREADY hold a resolved [`AiConfig`] (e.g. the AI
/// session / form-filler engine, which resolves the provider once up-front). Routes to the cloud
/// gateway when the toggle is on, otherwise runs the completion on the supplied `cfg`.
pub async fn complete_with(
    pool: &SqlitePool,
    cfg: &AiConfig,
    messages: &[AiMessage],
    system: Option<&str>,
    max_tokens: u32,
    bucket: &str,
) -> LocalResult<Completion> {
    complete_with_gateway_pref(pool, cfg, messages, system, max_tokens, bucket, false).await
}

/// Like [`complete_with`], but `force_gateway` pins the completion to the MANAGED cloud gateway
/// regardless of the `ai.use_cloud_gateway` toggle. Used by AI auto-repair's autonomous re-record so
/// the whole agent run is metered on the linked account (never a BYO key), matching per-step repair.
/// With the `cloud` feature off (OSS build) there is no gateway, so it always runs the BYO provider.
pub async fn complete_with_gateway_pref(
    pool: &SqlitePool,
    cfg: &AiConfig,
    messages: &[AiMessage],
    system: Option<&str>,
    max_tokens: u32,
    bucket: &str,
    force_gateway: bool,
) -> LocalResult<Completion> {
    if force_gateway || cloud_gateway_enabled(pool).await {
        #[cfg(feature = "cloud")]
        {
            return cloud_gateway_complete(pool, messages, system, max_tokens, bucket).await;
        }
    }
    // `bucket`/`force_gateway` only label the cloud path; without the `cloud` feature there is no
    // gateway to route to, so fall back to the BYO provider.
    #[cfg(not(feature = "cloud"))]
    let _ = (bucket, force_gateway);
    complete(cfg, messages, system, max_tokens).await
}

/// AI auto-repair completion. Unlike [`complete_routed`]/[`complete_with`], this ALWAYS runs on the
/// managed cloud gateway (bucket `"repair"`) and never on a BYO provider — repair is a metered cloud
/// capability (billed/enforced server-side), so it must not spend a user's BYO key even when one is
/// configured. Requires the `cloud` feature and a linked account; an out-of-credit account surfaces
/// as [`LocalError::PaymentRequired`] (the gateway's 402 → upgrade message). Cloud-only by design.
#[cfg(feature = "cloud")]
pub async fn repair_complete(
    pool: &SqlitePool,
    messages: &[AiMessage],
    system: Option<&str>,
    max_tokens: u32,
) -> LocalResult<Completion> {
    cloud_gateway_complete(pool, messages, system, max_tokens, "repair").await
}

/// POST the conversation to the managed cloud AI gateway (`/api/ai-assist/complete`) and map the
/// metered response back to a [`Completion`]. Requires a linked account.
#[cfg(feature = "cloud")]
async fn cloud_gateway_complete(
    pool: &SqlitePool,
    messages: &[AiMessage],
    system: Option<&str>,
    max_tokens: u32,
    bucket: &str,
) -> LocalResult<Completion> {
    use crate::local::cloud::client::CloudClient;
    use crate::local::cloud::state::LinkState;

    let link = LinkState::load_or_default(pool).await?;
    if !link.is_linked() {
        return Err(LocalError::BadRequest(
            "The cloud AI gateway needs a linked account. Link your account in Settings → Account, or turn the gateway off.".into(),
        ));
    }
    let mut cc = CloudClient::connect(Some(&link))?;
    // `AiMessage` already serializes to the Anthropic content-block shape the gateway accepts.
    let mut body = serde_json::json!({
        "messages": messages,
        "max_tokens": max_tokens,
        "purpose": bucket,
    });
    if let Some(sys) = system {
        body["system"] = serde_json::json!(sys);
    }
    let resp: serde_json::Value = cc.post_json("/api/ai-assist/complete", &body).await?;
    Ok(Completion {
        text: resp.get("content").and_then(|v| v.as_str()).unwrap_or_default().to_string(),
        input_tokens: u32_at(&resp, &["input_tokens"]),
        output_tokens: u32_at(&resp, &["output_tokens"]),
        model: resp.get("model").and_then(|v| v.as_str()).unwrap_or_default().to_string(),
    })
}

fn http() -> reqwest::Client {
    reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(120))
        .user_agent(concat!("writ-agent/", env!("CARGO_PKG_VERSION")))
        .build()
        .unwrap_or_default()
}

fn require_key(cfg: &AiConfig) -> LocalResult<&str> {
    cfg.api_key
        .as_deref()
        .filter(|k| !k.is_empty())
        .ok_or_else(|| LocalError::BadRequest(format!("no API key configured for provider '{}'", cfg.provider)))
}

fn base_or(cfg: &AiConfig, fallback: &str) -> String {
    cfg.base_url
        .clone()
        .or_else(|| default_base_url_for(&cfg.provider).map(|s| s.to_string()))
        .unwrap_or_else(|| fallback.to_string())
        .trim_end_matches('/')
        .to_string()
}

/// Send a provider request and parse the JSON response, surfacing the provider's OWN error detail
/// on non-2xx. `error_for_status()` would discard the body — but that body is the only place a
/// provider says WHY (OpenAI's 429 `insufficient_quota` vs a real rate limit, a bad model id, …).
///
/// A transient 429 (rate limit) is RETRIED with backoff, honoring a `Retry-After` header when present.
/// Free models (OpenRouter `:free`, etc.) share a tiny rate budget and 429 constantly on the per-minute
/// window — one wait usually clears it, so retrying keeps a run alive that would otherwise die on the
/// first tick. A DAILY/quota-exhausted 429 (`insufficient_quota`, free-models-per-day) never clears by
/// retrying, so it fails fast with an actionable message.
async fn provider_json(req: reqwest::RequestBuilder) -> LocalResult<serde_json::Value> {
    const MAX_RETRIES: u32 = 3;
    let mut req = Some(req);
    let mut attempt: u32 = 0;
    loop {
        let current = req.take().expect("request builder present each iteration");
        // Clone BEFORE send (send consumes the builder) so a 429 can be retried. A non-cloneable body
        // (streaming) yields None → no retry.
        let retry_clone = if attempt < MAX_RETRIES { current.try_clone() } else { None };
        let resp = current.send().await.map_err(provider_err)?;
        let status = resp.status().as_u16();
        if (200..300).contains(&status) {
            return resp.json().await.map_err(provider_err);
        }
        // Read Retry-After (seconds) before the body consumes the response.
        let retry_after = resp
            .headers()
            .get(reqwest::header::RETRY_AFTER)
            .and_then(|v| v.to_str().ok())
            .and_then(|s| s.trim().parse::<u64>().ok());
        let body = resp.text().await.unwrap_or_default();
        if status == 429 && is_retryable_rate_limit(&body) {
            if let Some(next) = retry_clone {
                attempt += 1;
                // Honor Retry-After (capped at 10s) else linear-ish backoff 1s/2s/4s.
                let wait = retry_after
                    .unwrap_or(match attempt {
                        1 => 1,
                        2 => 2,
                        _ => 4,
                    })
                    .min(10);
                tracing::warn!(attempt, wait_s = wait, "AI provider 429 — backing off and retrying");
                tokio::time::sleep(std::time::Duration::from_secs(wait)).await;
                req = Some(next);
                continue;
            }
        }
        return Err(provider_http_err(status, &body));
    }
}

/// Whether a 429 is a TRANSIENT rate limit worth retrying. Out-of-credit / daily-exhausted 429s never
/// clear by retrying (OpenAI `insufficient_quota`; OpenRouter free-model daily cap) — don't loop on them.
fn is_retryable_rate_limit(body: &str) -> bool {
    let low = body.to_ascii_lowercase();
    let terminal = low.contains("insufficient_quota")
        || low.contains("per-day")
        || low.contains("per day")
        || low.contains("daily limit")
        || low.contains("free-models-per-day")
        || low.contains("add 10 credits")
        || low.contains("add more credits");
    !terminal
}

/// Pull the human-readable message out of a provider error body. OpenAI / Anthropic / Google all
/// nest it under `error` (`error.message`, plus `error.code`/`error.type`/`error.status` labels);
/// fall back to the raw body. Truncated so a huge HTML error page can't flood logs/toasts.
fn provider_error_detail(body: &str) -> String {
    const MAX: usize = 300;
    let detail = serde_json::from_str::<serde_json::Value>(body)
        .ok()
        .and_then(|v| {
            let err = v.get("error")?;
            let msg = err.get("message").and_then(|m| m.as_str()).unwrap_or_default();
            let label = ["code", "type", "status"]
                .iter()
                .find_map(|k| err.get(*k).and_then(|c| c.as_str().map(|s| s.to_string())))
                .unwrap_or_default();
            match (label.is_empty(), msg.is_empty()) {
                (false, false) => Some(format!("{label}: {msg}")),
                (true, false) => Some(msg.to_string()),
                (false, true) => Some(label),
                (true, true) => None,
            }
        })
        .unwrap_or_else(|| body.trim().to_string());
    let mut detail = detail.replace(['\n', '\r'], " ");
    if detail.len() > MAX {
        // Cut on a char boundary so multi-byte text can't panic the truncation.
        let cut = detail.char_indices().take_while(|(i, _)| *i < MAX).last().map(|(i, c)| i + c.len_utf8()).unwrap_or(0);
        detail.truncate(cut);
        detail.push('…');
    }
    detail
}

/// Map a non-2xx provider response (status + body) to a clean, actionable `LocalError`.
fn provider_http_err(status: u16, body: &str) -> LocalError {
    let detail = provider_error_detail(body);
    let suffix = if detail.is_empty() { String::new() } else { format!(" — {detail}") };
    if status == 401 || status == 403 {
        LocalError::BadRequest(format!(
            "AI provider rejected the API key ({status}) — check the key in Settings{suffix}"
        ))
    } else if status == 429 {
        // OpenAI (and compatibles) use 429 for BOTH rate limiting and an out-of-credit account
        // (`insufficient_quota`). The latter never resolves by retrying — say so explicitly.
        let low = format!("{body} {detail}").to_ascii_lowercase();
        if low.contains("insufficient_quota") {
            LocalError::BadRequest(format!(
                "The provider account for this API key has no available credit (429 insufficient_quota) — add billing/credits on the provider's platform; retrying won't help{suffix}"
            ))
        } else if low.contains("per-day") || low.contains("per day") || low.contains("daily limit")
            || low.contains("free-models-per-day") || low.contains("add 10 credits") || low.contains("add more credits")
        {
            // OpenRouter free models share a small DAILY budget across all users — a free model 429s
            // constantly once that's spent. Retrying won't help today; the fix is a different model.
            LocalError::BadRequest(format!(
                "This free model hit its daily rate limit (429) — free models share a small shared quota. Pick a paid model, or add a few credits on your provider to unlock higher limits{suffix}"
            ))
        } else {
            // Transient per-minute rate limit — we already retried with backoff before surfacing this.
            LocalError::BadRequest(format!("AI provider rate-limited the request (429) — the free model is busy; try again in a moment or switch to a paid model{suffix}"))
        }
    } else {
        LocalError::BadRequest(format!("AI provider returned HTTP {status}{suffix}"))
    }
}

fn u32_at(v: &serde_json::Value, path: &[&str]) -> u32 {
    let mut cur = v;
    for k in path {
        match cur.get(k) {
            Some(next) => cur = next,
            None => return 0,
        }
    }
    cur.as_u64().unwrap_or(0) as u32
}

// ── Anthropic (/v1/messages) ────────────────────────────────────────────────
async fn anthropic_complete(
    cfg: &AiConfig,
    messages: &[AiMessage],
    system: Option<&str>,
    max_tokens: u32,
) -> LocalResult<Completion> {
    let key = require_key(cfg)?;
    let url = format!("{}/v1/messages", base_or(cfg, "https://api.anthropic.com"));
    // AiMessage already serializes to Anthropic's content-block shape (text + base64 image blocks).
    let mut body = serde_json::json!({
        "model": cfg.model,
        "max_tokens": max_tokens,
        "messages": messages,
    });
    if let Some(sys) = system {
        body["system"] = serde_json::json!(sys);
    }
    let data: serde_json::Value = provider_json(
        http()
            .post(&url)
            .header("x-api-key", key)
            .header("anthropic-version", "2023-06-01")
            .header("content-type", "application/json")
            .json(&body),
    )
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
    Ok(Completion {
        text,
        input_tokens: u32_at(&data, &["usage", "input_tokens"]),
        output_tokens: u32_at(&data, &["usage", "output_tokens"]),
        model: data.get("model").and_then(|m| m.as_str()).unwrap_or(&cfg.model).to_string(),
    })
}

// ── OpenAI-compatible chat completions (OpenAI, OpenRouter, Ollama, custom, local) ──────────────
/// Best-effort detection of an OpenAI reasoning model by name (o1/o3/o4-mini, gpt-5, …; also matches
/// an OpenRouter-style `vendor/model` id like `openai/gpt-5`).
fn is_reasoning_model(model: &str) -> bool {
    let m = model.to_ascii_lowercase();
    m.starts_with("o1")
        || m.starts_with("o3")
        || m.starts_with("o4")
        || m.contains("gpt-5")
        || m.contains("reasoning")
}

/// Token headroom added for reasoning models. They spend the budget on HIDDEN reasoning before any
/// visible output, and the token cap (`max_output_tokens` / `max_completion_tokens`) bounds reasoning +
/// output COMBINED — so a tight cap that suits a normal model starves a reasoning model to an EMPTY
/// `incomplete` response. Non-reasoning models are unaffected (the cap is a ceiling, not a target).
const REASONING_HEADROOM_TOKENS: u32 = 12000;

fn effective_max_output_tokens(model: &str, requested: u32) -> u32 {
    if requested > 0 && is_reasoning_model(model) {
        requested.saturating_add(REASONING_HEADROOM_TOKENS)
    } else {
        requested
    }
}

async fn openai_chat_complete(
    cfg: &AiConfig,
    messages: &[AiMessage],
    system: Option<&str>,
    max_tokens: u32,
) -> LocalResult<Completion> {
    let url = format!("{}/chat/completions", base_or(cfg, "https://api.openai.com/v1"));
    // api.openai.com deprecated `max_tokens` — current models (o-series, gpt-5.x) hard-reject it in
    // favor of `max_completion_tokens`. Other OpenAI-COMPATIBLE servers (Ollama, OpenRouter, vLLM,
    // LM Studio) still speak `max_tokens`, so only the first-party `openai` provider gets the new name.
    let max_tokens_field = if cfg.provider == "openai" { "max_completion_tokens" } else { "max_tokens" };
    let body = serde_json::json!({
        "model": cfg.model,
        max_tokens_field: effective_max_output_tokens(&cfg.model, max_tokens),
        "messages": to_openai_messages(messages, system),
    });
    let mut req = http().post(&url).header("content-type", "application/json").json(&body);
    if let Some(k) = cfg.api_key.as_deref().filter(|k| !k.is_empty()) {
        req = req.header("authorization", format!("Bearer {k}"));
    }
    let data: serde_json::Value = provider_json(req).await?;
    let text = data
        .pointer("/choices/0/message/content")
        .and_then(|t| t.as_str())
        .unwrap_or("")
        .to_string();
    Ok(Completion {
        text,
        input_tokens: u32_at(&data, &["usage", "prompt_tokens"]),
        output_tokens: u32_at(&data, &["usage", "completion_tokens"]),
        model: data.get("model").and_then(|m| m.as_str()).unwrap_or(&cfg.model).to_string(),
    })
}

// ── OpenAI Responses API (/v1/responses) ────────────────────────────────────
async fn openai_responses_complete(
    cfg: &AiConfig,
    messages: &[AiMessage],
    system: Option<&str>,
    max_tokens: u32,
) -> LocalResult<Completion> {
    let key = require_key(cfg)?;
    let url = format!("{}/responses", base_or(cfg, "https://api.openai.com/v1"));
    let mut body = serde_json::json!({
        "model": cfg.model,
        "max_output_tokens": effective_max_output_tokens(&cfg.model, max_tokens),
        "input": to_responses_input(messages),
        // The Responses API STORES responses server-side (30 days) by default — opt out; this
        // daemon is local-first and stateless per call (no previous_response_id chaining).
        "store": false,
    });
    if let Some(sys) = system {
        body["instructions"] = serde_json::json!(sys);
    }
    let data: serde_json::Value = provider_json(
        http()
            .post(&url)
            .header("authorization", format!("Bearer {key}"))
            .header("content-type", "application/json")
            .json(&body),
    )
    .await?;
    // `output_text` is an SDK-side convenience (not in the REST payload) — tolerate it if a proxy
    // adds it, else walk output[] taking only `message` items' `output_text` parts (skipping the
    // `reasoning` items o-series / gpt-5 models emit alongside).
    let text = data
        .get("output_text")
        .and_then(|t| t.as_str())
        .map(|s| s.to_string())
        .unwrap_or_else(|| {
            data.get("output")
                .and_then(|o| o.as_array())
                .map(|items| {
                    items
                        .iter()
                        .filter(|it| it.get("type").and_then(|t| t.as_str()).is_none_or(|t| t == "message"))
                        .filter_map(|it| it.get("content").and_then(|c| c.as_array()))
                        .flatten()
                        .filter(|p| p.get("type").and_then(|t| t.as_str()) == Some("output_text"))
                        .filter_map(|p| p.get("text").and_then(|t| t.as_str()))
                        .collect::<Vec<_>>()
                        .join("")
                })
                .unwrap_or_default()
        });
    Ok(Completion {
        text,
        input_tokens: u32_at(&data, &["usage", "input_tokens"]),
        output_tokens: u32_at(&data, &["usage", "output_tokens"]),
        model: data.get("model").and_then(|m| m.as_str()).unwrap_or(&cfg.model).to_string(),
    })
}

/// Build the Gemini `generateContent` URL. The API key is NEVER put here (see `google_complete`); it
/// travels in the `x-goog-api-key` header so it can't leak through reqwest's URL-bearing error Display.
fn gemini_url(base: &str, model: &str) -> String {
    format!("{base}/v1beta/models/{model}:generateContent")
}

// ── Google Gemini (generateContent) ─────────────────────────────────────────
async fn google_complete(
    cfg: &AiConfig,
    messages: &[AiMessage],
    system: Option<&str>,
    max_tokens: u32,
) -> LocalResult<Completion> {
    let key = require_key(cfg)?;
    let base = base_or(cfg, "https://generativelanguage.googleapis.com");
    // SECURITY: send the API key in the `x-goog-api-key` HEADER, NOT the `?key=` query string. A key in
    // the URL rides along in reqwest's error Display on any transport failure, which `provider_err`
    // would then log and return in the error body (the log redactor doesn't match `AIza…` keys). Gemini
    // accepts the header form, so the key never enters the URL.
    let url = gemini_url(&base, &cfg.model);
    let mut body = serde_json::json!({
        "contents": to_gemini_contents(messages),
        "generationConfig": { "maxOutputTokens": max_tokens },
    });
    if let Some(sys) = system {
        body["systemInstruction"] = serde_json::json!({ "parts": [{ "text": sys }] });
    }
    let data: serde_json::Value = provider_json(
        http()
            .post(&url)
            .header("content-type", "application/json")
            .header("x-goog-api-key", key)
            .json(&body),
    )
    .await?;
    let text = data
        .pointer("/candidates/0/content/parts")
        .and_then(|p| p.as_array())
        .map(|parts| {
            parts
                .iter()
                .filter_map(|p| p.get("text").and_then(|t| t.as_str()))
                .collect::<Vec<_>>()
                .join("")
        })
        .unwrap_or_default();
    Ok(Completion {
        text,
        input_tokens: u32_at(&data, &["usageMetadata", "promptTokenCount"]),
        output_tokens: u32_at(&data, &["usageMetadata", "candidatesTokenCount"]),
        model: cfg.model.clone(),
    })
}

// ── Message converters ──────────────────────────────────────────────────────

/// Internal (Anthropic-shaped) messages → OpenAI chat format (`image_url` parts, system inlined).
fn to_openai_messages(messages: &[AiMessage], system: Option<&str>) -> Vec<serde_json::Value> {
    let mut out: Vec<serde_json::Value> = Vec::new();
    if let Some(sys) = system {
        out.push(serde_json::json!({ "role": "system", "content": sys }));
    }
    for m in messages {
        match &m.content {
            AiMessageContent::Text(t) => out.push(serde_json::json!({ "role": m.role, "content": t })),
            AiMessageContent::Parts(parts) => {
                let conv: Vec<serde_json::Value> = parts
                    .iter()
                    .map(|p| match p {
                        AiContentPart::Text { text } => serde_json::json!({ "type": "text", "text": text }),
                        AiContentPart::Image { source } => serde_json::json!({
                            "type": "image_url",
                            "image_url": { "url": format!("data:{};base64,{}", source.media_type, source.data) }
                        }),
                    })
                    .collect();
                out.push(serde_json::json!({ "role": m.role, "content": conv }));
            }
        }
    }
    out
}

/// Internal messages → OpenAI Responses API `input` items, using the PORTABLE `EasyInputMessage` shape:
/// `{role, content}` with NO `type` field. Text turns send `content` as a plain STRING; only a mixed
/// text+image turn (a user turn with a screenshot) uses typed `input_text` / `input_image` parts.
///
/// Why not `{type:"message", content:[{type:"output_text"}]}` for assistant turns: that OUTPUT-message
/// shape is accepted by api.openai.com but REJECTED by strict OpenAI-compatible `/responses` endpoints
/// (OpenRouter's validator wants `input_text` parts and 400s on `output_text` — the `invalid_prompt`
/// seen in the gateway logs). A plain-string `EasyInputMessage` is valid on ALL of them for EVERY role,
/// so it sidesteps the input_text/output_text discriminator entirely. Assistant turns (always model
/// text) therefore never carry typed parts.
fn to_responses_input(messages: &[AiMessage]) -> Vec<serde_json::Value> {
    messages
        .iter()
        .map(|m| match &m.content {
            // Text turn (incl. every assistant turn) → plain-string content: unambiguous everywhere.
            AiMessageContent::Text(t) => serde_json::json!({ "role": m.role, "content": t }),
            AiMessageContent::Parts(parts) if m.role == "assistant" => {
                // Assistant turns are model text; flatten any parts to a string so they never hit the
                // typed-part discriminator (images never occur here in practice).
                let text: String = parts
                    .iter()
                    .map(|p| match p {
                        AiContentPart::Text { text } => text.as_str(),
                        AiContentPart::Image { .. } => "[image]",
                    })
                    .collect::<Vec<_>>()
                    .join("");
                serde_json::json!({ "role": m.role, "content": text })
            }
            // User/system multimodal turn → typed input parts (`input_text` is correct for input items).
            AiMessageContent::Parts(parts) => {
                let content: Vec<serde_json::Value> = parts
                    .iter()
                    .map(|p| match p {
                        AiContentPart::Text { text } => serde_json::json!({ "type": "input_text", "text": text }),
                        AiContentPart::Image { source } => serde_json::json!({
                            "type": "input_image",
                            "image_url": format!("data:{};base64,{}", source.media_type, source.data)
                        }),
                    })
                    .collect();
                serde_json::json!({ "role": m.role, "content": content })
            }
        })
        .collect()
}

/// Internal messages → Gemini `contents` (`user`/`model` roles, `inline_data` images).
fn to_gemini_contents(messages: &[AiMessage]) -> Vec<serde_json::Value> {
    messages
        .iter()
        .map(|m| {
            let role = if m.role == "assistant" { "model" } else { "user" };
            let parts: Vec<serde_json::Value> = match &m.content {
                AiMessageContent::Text(t) => vec![serde_json::json!({ "text": t })],
                AiMessageContent::Parts(parts) => parts
                    .iter()
                    .map(|p| match p {
                        AiContentPart::Text { text } => serde_json::json!({ "text": text }),
                        AiContentPart::Image { source } => serde_json::json!({
                            "inline_data": { "mime_type": source.media_type, "data": source.data }
                        }),
                    })
                    .collect(),
            };
            serde_json::json!({ "role": role, "parts": parts })
        })
        .collect()
}

/// Map a provider TRANSPORT/decode error to a clean `LocalError` (no key leakage). HTTP-status
/// errors are handled by [`provider_http_err`], which keeps the provider's own error detail; this
/// path covers connect/timeout/body-decode failures (the status branches remain as a safety net).
fn provider_err(e: reqwest::Error) -> LocalError {
    let status = e.status().map(|s| s.as_u16()).unwrap_or(0);
    if status == 401 || status == 403 {
        LocalError::BadRequest("AI provider rejected the API key (401/403) — check the key in Settings".into())
    } else if status == 429 {
        LocalError::BadRequest("AI provider rate-limited the request (429) — try again shortly".into())
    } else if status >= 400 {
        LocalError::BadRequest(format!("AI provider returned HTTP {status}"))
    } else {
        // Defense-in-depth: strip the request URL from the error before formatting. reqwest's Display
        // renders the full URL, and a provider that carries credentials in the URL query string (e.g. a
        // legacy `?key=` base_url) would otherwise leak them into this logged + returned message.
        LocalError::Internal(format!("AI provider request failed: {}", e.without_url()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn gemini_url_carries_no_key_query_param() {
        // SE-5/F7: the key must NOT ride in the URL — it travels in the x-goog-api-key header.
        let url = gemini_url("https://generativelanguage.googleapis.com", "gemini-1.5-pro");
        assert!(!url.contains("key="), "gemini URL must not carry ?key= : {url}");
        assert!(!url.contains('?'), "gemini URL must carry no query string: {url}");
        assert_eq!(
            url,
            "https://generativelanguage.googleapis.com/v1beta/models/gemini-1.5-pro:generateContent"
        );
    }

    #[test]
    fn responses_input_uses_portable_easyinputmessage_shape() {
        // PORTABLE shape (valid on api.openai.com AND strict compatibles like OpenRouter): text turns
        // are plain-string `EasyInputMessage`s with NO `type` field and NO `output_text` parts — the
        // `output_text`/`type:message` shape 400s on OpenRouter's /responses validator.
        let messages = vec![
            AiMessage { role: "user".into(), content: AiMessageContent::Text("hi".into()) },
            AiMessage { role: "assistant".into(), content: AiMessageContent::Text("hello".into()) },
        ];
        let items = to_responses_input(&messages);
        assert_eq!(items[0], serde_json::json!({ "role": "user", "content": "hi" }));
        assert_eq!(items[1], serde_json::json!({ "role": "assistant", "content": "hello" }));
        let dump = serde_json::to_string(&items).unwrap();
        assert!(!dump.contains("output_text"), "must not emit output_text: {dump}");
        assert!(!dump.contains("\"type\":\"message\""), "must not wrap in type:message: {dump}");
    }

    #[test]
    fn responses_input_user_image_turn_uses_typed_input_parts() {
        use crate::models::ai::ImageSource;
        let messages = vec![AiMessage {
            role: "user".into(),
            content: AiMessageContent::Parts(vec![
                AiContentPart::Text { text: "look".into() },
                AiContentPart::Image { source: ImageSource { source_type: "base64".into(), media_type: "image/jpeg".into(), data: "AAAA".into() } },
            ]),
        }];
        let items = to_responses_input(&messages);
        assert_eq!(items[0]["content"][0]["type"], "input_text");
        assert_eq!(items[0]["content"][1]["type"], "input_image");
    }

    #[test]
    fn reasoning_models_get_token_headroom() {
        assert!(is_reasoning_model("gpt-5") && is_reasoning_model("o3-mini") && is_reasoning_model("openai/gpt-5"));
        assert!(!is_reasoning_model("gpt-4o") && !is_reasoning_model("claude-3-5-sonnet"));
        // Reasoning models get headroom on top of the ask; normal models are untouched; 0 stays 0.
        assert_eq!(effective_max_output_tokens("gpt-5", 2000), 2000 + REASONING_HEADROOM_TOKENS);
        assert_eq!(effective_max_output_tokens("gpt-4o", 2000), 2000);
        assert_eq!(effective_max_output_tokens("o1", 0), 0);
    }

    #[test]
    fn provider_http_err_surfaces_openai_insufficient_quota() {
        // A 429 from an out-of-credit OpenAI account must NOT read as "try again shortly".
        let body = r#"{"error":{"message":"You exceeded your current quota, please check your plan and billing details.","type":"insufficient_quota","param":null,"code":"insufficient_quota"}}"#;
        let msg = provider_http_err(429, body).to_string();
        assert!(msg.contains("insufficient_quota"), "quota cause lost: {msg}");
        assert!(msg.contains("credit"), "should explain it's a billing problem: {msg}");
        assert!(msg.contains("exceeded your current quota"), "provider detail lost: {msg}");
        assert!(!msg.contains("try again shortly"), "must not suggest retrying: {msg}");
    }

    #[test]
    fn provider_http_err_keeps_detail_for_plain_rate_limit_and_4xx() {
        let body = r#"{"error":{"message":"Rate limit reached for gpt-4o","type":"tokens","code":"rate_limit_exceeded"}}"#;
        let msg = provider_http_err(429, body).to_string();
        assert!(msg.contains("try again") && msg.contains("Rate limit reached"), "{msg}");

        // OpenRouter free-model DAILY limit → actionable "switch model", NOT "try again".
        let daily = r#"{"error":{"message":"Rate limit exceeded: free-models-per-day. Add 10 credits to unlock 1000 requests/day","code":429}}"#;
        let msg = provider_http_err(429, daily).to_string();
        assert!(msg.contains("daily rate limit") && msg.contains("paid model"), "{msg}");
        assert!(!is_retryable_rate_limit(daily), "daily cap must not be retried");
        assert!(is_retryable_rate_limit(r#"{"error":{"message":"Rate limit reached, retry soon"}}"#), "transient must retry");

        let bad_model = r#"{"error":{"message":"The model `gpt-4o-nope` does not exist","type":"invalid_request_error","code":"model_not_found"}}"#;
        let msg = provider_http_err(404, bad_model).to_string();
        assert!(msg.contains("HTTP 404") && msg.contains("does not exist"), "{msg}");

        // Non-JSON bodies fall back to the (truncated, newline-flattened) raw text.
        let msg = provider_http_err(503, "<html>Service\nUnavailable</html>").to_string();
        assert!(msg.contains("HTTP 503") && msg.contains("Service Unavailable"), "{msg}");
    }

    #[test]
    fn provider_error_detail_truncates_on_char_boundary() {
        let long = "é".repeat(400);
        let detail = provider_error_detail(&long);
        assert!(detail.ends_with('…'));
        assert!(detail.chars().count() < 400);
    }

    #[test]
    fn ai_config_debug_redacts_api_key() {
        // SE-5/F7: a stray {:?} must never spill the key.
        let cfg = AiConfig {
            provider: "google".into(),
            model: "gemini-1.5-pro".into(),
            base_url: None,
            api_key: Some("AIzaSuperSecretKeyValue".into()),
        };
        let dbg = format!("{cfg:?}");
        assert!(!dbg.contains("AIzaSuperSecretKeyValue"), "api_key leaked in Debug: {dbg}");
        assert!(dbg.contains("redacted"), "Debug should mark the key redacted: {dbg}");
        // A missing key shows as None, not "<redacted>".
        let none = AiConfig { api_key: None, ..cfg };
        assert!(format!("{none:?}").contains("None"));
    }

    /// Open a fresh encrypted DB keyed by a throwaway (no-keyring) vault — mirrors state.rs tests.
    async fn fresh_pool() -> (tempfile::TempDir, SqlitePool, Vault) {
        use crate::local::config::Paths;
        use crate::local::db;
        let dir = tempfile::tempdir().unwrap();
        let paths = Paths::at(dir.path().join(".writ"));
        paths.ensure_dirs().unwrap();
        let vault = Vault::load_or_create(&paths.root, false).unwrap();
        let pool = db::open(&paths.db(), &vault.db_key_hex()).await.unwrap();
        (dir, pool, vault)
    }

    #[tokio::test]
    async fn fresh_link_enables_gateway_only_without_byo_key() {
        let (_dir, pool, vault) = fresh_pool().await;

        // No BYO key, gateway off → auto-enables and reports it flipped.
        assert!(!cloud_gateway_enabled(&pool).await);
        assert!(enable_cloud_gateway_if_no_byo_key(&pool).await.unwrap(), "should enable when no key");
        assert!(cloud_gateway_enabled(&pool).await, "gateway should now be ON");

        // Idempotent: a second call is a no-op (already on).
        assert!(!enable_cloud_gateway_if_no_byo_key(&pool).await.unwrap(), "second call must be a no-op");

        // Turn it off (simulating a user opt-out), set a BYO key → must NOT re-enable.
        set_cloud_gateway(&pool, false).await.unwrap();
        save_config(&pool, &vault, "openai", "gpt-4o", None, Some("sk-user-key")).await.unwrap();
        assert!(has_api_key(&pool).await.unwrap());
        assert!(!enable_cloud_gateway_if_no_byo_key(&pool).await.unwrap(), "must not enable when a BYO key exists");
        assert!(!cloud_gateway_enabled(&pool).await, "gateway must stay OFF when the user has their own key");
    }
}
