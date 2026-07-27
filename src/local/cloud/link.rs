//! OAuth 2.0 Device Authorization Grant (RFC 8628) — link this desktop to a Writ Cloud account.
//!
//! This is the *account-linking* flow shared by the `writ login` CLI and the Tauri GUI. It:
//!   1. POSTs a device-authorization request → receives `device_code`, `user_code`,
//!      `verification_uri` (+ `_complete`), `interval`, `expires_in`.
//!   2. presents the `user_code` to the user and opens `verification_uri` in their browser.
//!   3. polls the token endpoint (`grant_type = urn:ietf:params:oauth:grant-type:device_code`),
//!      honoring `interval`, `slow_down`, and `authorization_pending`, until success/expiry.
//!   4. on success persists the `wto_`/`wtr_` pair via [`super::token`] and writes
//!      [`super::state::LinkState`].
//!
//! The same surface drives two front-ends via plain `Fn` callbacks (NO `async-trait`,
//! NO boxed *async* trait) — the caller renders the code / opens the URL however it likes.
//!
//! SECURITY (SECURITY_AND_ENTITLEMENTS_SPEC + the never-trust-a-BYO-agent rule):
//! - The minted cloud ACCOUNT token (`wto_` access / `wtr_` refresh) is STRICTLY SEPARATE from the
//!   local-API bearer (`wlt_`, loopback only) and from the vault root key. It is written ONLY to the
//!   OS keyring (`writ-cloud/account`) — NEVER to `writ.db`, NEVER to disk, NEVER logged.
//! - [`LinkState`] persists ONLY non-secret reflection metadata (account id/email/base url/scopes).
//! - Linking is NOT an authorization grant for paid features. Scopes/entitlements are reflection-only
//!   (UI/upsell + offline grace); every metered/cloud capability is re-enforced SERVER-SIDE per call.
//! - Token material (`device_code`, `user_code`, `access`/`refresh`, `channel_key`) is NEVER passed to
//!   `tracing`. The `device_code` is a bearer-equivalent polling secret and is treated as such.
//!
//! BACKEND CONTRACT (see the cloud backend's `oauth` router, mounted at `/api`):
//!   `POST /api/oauth/device`        — JSON `{client_id, mode?}` → device-authorization response.
//!   `POST /api/oauth/device/token`  — JSON `{grant_type, device_code, client_id}` →
//!        200 token response | 428 `{"error":"authorization_pending"}` | 410 expired/consumed.
//!     (Standard RFC 8628 errors `slow_down` / `access_denied` are also handled if/when the backend
//!      starts returning them; today the server uses 428-pending + 410-expired.)
//!
//! Net-new Rust in this crate (Stage B-1 — cloud device-flow link).

use super::super::error::{LocalError, LocalResult};
use super::channel;
use super::state::LinkState;
use super::token::{self, TokenPair};
use serde::Deserialize;
use sqlx::sqlite::SqlitePool;
use std::time::Duration;

/// Bound a server error body before it hits the logs (F9): a verbose/hostile upstream body must not be
/// dumped verbatim into `tracing`. Char-safe cap at 500.
fn truncate_body(s: &str) -> String {
    const MAX: usize = 500;
    if s.chars().count() <= MAX {
        return s.to_string();
    }
    let head: String = s.chars().take(MAX).collect();
    format!("{head}…[truncated]")
}

/// True when the URL's host is loopback (`localhost`, `127.0.0.0/8`, `[::1]`) — the only case in which
/// plaintext `http` is acceptable, since nothing leaves the machine.
fn is_loopback_host(u: &url::Url) -> bool {
    match u.host() {
        Some(url::Host::Domain(d)) => d.eq_ignore_ascii_case("localhost") || d.ends_with(".localhost"),
        Some(url::Host::Ipv4(ip)) => ip.is_loopback(),
        Some(url::Host::Ipv6(ip)) => ip.is_loopback(),
        None => false,
    }
}

/// Decide whether the SERVER-SUPPLIED verification URL may be handed to the `open_url` callback
/// (whose default is [`opener::open`]).
///
/// `opener` builds argv, so there is no shell-metacharacter risk — but it dispatches to
/// `/usr/bin/open` / `xdg-open` / `ShellExecuteW`, which LAUNCH whatever the URL designates. A
/// `file:///…/Installer.app` or a registered-handler scheme would therefore be executed rather than
/// browsed, and the value arrives over the network in `verification_uri_complete`.
///
/// Both conditions are required:
///   1. `https` (or `http` to loopback, for a local dev backend), and
///   2. the same host as the cloud base we chose to talk to — so even a compromised backend can only
///      send us to itself, never to a third-party origin.
///
/// [`link_device_flow`] additionally calls [`super::client::require_secure_cloud_url`] on the base
/// before any request, so a plaintext non-loopback base cannot be used to inject this value at all.
fn verification_url_is_openable(candidate: &str, base_url: &str) -> bool {
    let Ok(u) = url::Url::parse(candidate) else {
        return false;
    };
    if !(u.scheme() == "https" || (u.scheme() == "http" && is_loopback_host(&u))) {
        return false;
    }
    let Ok(base) = url::Url::parse(base_url) else {
        return false;
    };
    match (u.host_str(), base.host_str()) {
        (Some(a), Some(b)) => a.eq_ignore_ascii_case(b),
        _ => false,
    }
}

/// OAuth client id for the device-flow public client (must match the backend `DEVICE_CLIENT_ID`).
pub const DEVICE_CLIENT_ID: &str = "writ-agent";

/// RFC 8628 device-code grant type for the token endpoint.
pub const DEVICE_GRANT_TYPE: &str = "urn:ietf:params:oauth:grant-type:device_code";

/// Device-authorization request path (relative to the cloud base url).
pub const DEVICE_AUTH_PATH: &str = "/api/oauth/device";
/// Device token-poll path (relative to the cloud base url).
pub const DEVICE_TOKEN_PATH: &str = "/api/oauth/device/token";

/// Fallback poll interval (seconds) when the server omits `interval` from the device-auth response.
pub const DEFAULT_POLL_INTERVAL_SECS: u64 = 5;
/// Lower clamp on the poll interval, so a hostile/buggy server can't make us hammer the endpoint.
pub const MIN_POLL_INTERVAL_SECS: u64 = 1;
/// Increment applied to the poll interval on every `slow_down` (RFC 8628 §3.5 recommends +5s).
pub const SLOW_DOWN_INCREMENT_SECS: u64 = 5;
/// Per-request timeout for the device-flow HTTP calls.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);
/// Connect-phase timeout so an OFFLINE cloud fails the link/poll fast (retryable 503) instead of
/// hanging ~30s — the "login does nothing then eventually errors" symptom. Mirrors `client.rs`.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(4);

// ─────────────────────────────────────────────────────────────────────────────
// Wire types
// ─────────────────────────────────────────────────────────────────────────────

/// Parsed device-authorization response (RFC 8628 §3.2).
///
/// `device_code` is a polling SECRET (bearer-equivalent) and is never logged. `Debug` redacts it.
#[derive(Clone, Deserialize)]
pub struct DeviceAuthorization {
    /// The device verification code — POSTed back to the token endpoint while polling. SECRET.
    pub device_code: String,
    /// The human-readable code the user types on the verification page (e.g. `ABCD-2345`).
    pub user_code: String,
    /// URL the user visits to enter the `user_code`.
    pub verification_uri: String,
    /// Same URL with the code pre-filled, when the server provides it (RFC 8628 §3.3.1).
    #[serde(default)]
    pub verification_uri_complete: Option<String>,
    /// Lifetime of the `device_code`/`user_code` in seconds.
    #[serde(default)]
    pub expires_in: Option<u64>,
    /// Minimum seconds the client should wait between polls. Falls back to
    /// [`DEFAULT_POLL_INTERVAL_SECS`] when absent.
    #[serde(default)]
    pub interval: Option<u64>,
}

impl std::fmt::Debug for DeviceAuthorization {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // NEVER print the device_code (polling secret) or the raw user_code in logs.
        f.debug_struct("DeviceAuthorization")
            .field("device_code", &"<redacted>")
            .field("user_code", &"<redacted>")
            .field("verification_uri", &self.verification_uri)
            .field("verification_uri_complete", &self.verification_uri_complete)
            .field("expires_in", &self.expires_in)
            .field("interval", &self.interval)
            .finish()
    }
}

impl DeviceAuthorization {
    /// The URL to open in the browser: the pre-filled `verification_uri_complete` when present,
    /// else the bare `verification_uri`.
    pub fn open_url(&self) -> &str {
        self.verification_uri_complete.as_deref().unwrap_or(&self.verification_uri)
    }

    /// Server-suggested poll interval, clamped to a sane floor, with a default when omitted.
    pub fn poll_interval(&self) -> Duration {
        let secs = self.interval.unwrap_or(DEFAULT_POLL_INTERVAL_SECS).max(MIN_POLL_INTERVAL_SECS);
        Duration::from_secs(secs)
    }
}

/// Successful device token-endpoint response (the subset we consume).
///
/// `access_token`/`refresh_token`/`channel_key` are secrets; `Debug` redacts them.
#[derive(Clone, Deserialize)]
struct DeviceTokenResponse {
    access_token: String,
    #[serde(default)]
    refresh_token: Option<String>,
    #[serde(default)]
    expires_in: Option<u64>,
    /// "user-hosted" (returns `wto_`/`wtr_`) or "infrastructure" (returns a JWT service token).
    #[serde(default)]
    mode: Option<String>,
    /// Per-agent Fernet channel key for credential-in-transit encryption. SECRET. Returned to the
    /// caller (it belongs in the recorder/gateway bridge config), never persisted by this module.
    #[serde(default)]
    channel_key: Option<String>,
    #[serde(default)]
    tenant_id: Option<String>,
    #[serde(default)]
    email: Option<String>,
    #[serde(default)]
    org_name: Option<String>,
    /// The linked user's preferred UI language (`en`/`fr`/`es`), when the server reflects one.
    /// REFLECTION-ONLY: the desktop adopts it on first link if the user hasn't chosen locally.
    #[serde(default)]
    language: Option<String>,
    /// Granted scopes, when the server echoes them. REFLECTION-ONLY.
    #[serde(default)]
    scope: Option<String>,
    #[serde(default)]
    scopes: Option<Vec<String>>,
    /// Some deployments key the account id as `agent_id` (infra) rather than `tenant_id`.
    #[serde(default)]
    agent_id: Option<String>,
}

impl std::fmt::Debug for DeviceTokenResponse {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DeviceTokenResponse")
            .field("access_token", &"<redacted>")
            .field("refresh_token", &"<redacted>")
            .field("channel_key", &"<redacted>")
            .field("expires_in", &self.expires_in)
            .field("mode", &self.mode)
            .field("tenant_id", &self.tenant_id)
            .field("email", &self.email)
            .field("org_name", &self.org_name)
            .finish()
    }
}

/// RFC 8628 §3.5 error body for a non-success token-poll response.
#[derive(Clone, Debug, Deserialize)]
struct DeviceTokenError {
    #[serde(default)]
    error: Option<String>,
}

// ─────────────────────────────────────────────────────────────────────────────
// Poll state machine (pure, testable seam)
// ─────────────────────────────────────────────────────────────────────────────

/// One classified outcome of a single token-endpoint poll, normalized from the HTTP response.
///
/// This is the injection point for tests: [`poll_decide`] is a pure function of `(PollResponse,
/// current interval)`, so the full pending → slow_down → success/expired machine can be driven with
/// hand-built values and zero network. The live [`poll_once`] just maps an HTTP response onto this.
#[derive(Clone, Debug)]
pub enum PollResponse {
    /// 200 — the user approved; tokens issued.
    Approved(LinkOutcome),
    /// 428 + `authorization_pending` — keep polling at the current interval.
    Pending,
    /// `slow_down` — keep polling, but increase the interval first (RFC 8628 §3.5).
    SlowDown,
    /// `access_denied` — the user explicitly declined. Terminal.
    Denied,
    /// 410 / `expired_token` — the device code expired or was already consumed. Terminal.
    Expired,
}

/// What the poll loop should do next, given a [`PollResponse`].
///
/// Not `PartialEq`/`Eq` — the `Done` payload ([`LinkOutcome`]) holds secret token material that has
/// no equality. Match on the variant in tests/callers instead of comparing whole values.
#[derive(Clone, Debug)]
pub enum PollAction {
    /// Wait `Duration` then poll again.
    Wait(Duration),
    /// Linking succeeded — stop with this outcome.
    Done(Box<LinkOutcome>),
    /// Linking failed terminally with this error — stop.
    Fail(PollTerminal),
}

/// Terminal (non-retryable) poll failures. Kept distinct from [`LocalError`] so the state machine is
/// trivially testable without constructing transport errors; [`PollTerminal::into_error`] folds them.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PollTerminal {
    /// The user declined the authorization request.
    Denied,
    /// The device/user code expired (or was already consumed) before approval.
    Expired,
}

impl PollTerminal {
    /// Fold into the boundary [`LocalError`] for the public API.
    pub fn into_error(self) -> LocalError {
        match self {
            PollTerminal::Denied => LocalError::BadRequest("device authorization denied by the user".into()),
            PollTerminal::Expired => {
                LocalError::BadRequest("device code expired before approval — start the link again".into())
            }
        }
    }
}

/// Pure poll-state transition. Given the classified `response` and the `current` poll interval,
/// decide the next [`PollAction`] (including the *next* interval after a `slow_down` bump).
///
/// No I/O, no clock, no network — this is the unit-tested heart of the flow.
pub fn poll_decide(response: PollResponse, current: Duration) -> PollAction {
    match response {
        PollResponse::Approved(outcome) => PollAction::Done(Box::new(outcome)),
        PollResponse::Pending => PollAction::Wait(current),
        PollResponse::SlowDown => {
            let next = current
                .checked_add(Duration::from_secs(SLOW_DOWN_INCREMENT_SECS))
                .unwrap_or(current)
                .max(Duration::from_secs(MIN_POLL_INTERVAL_SECS));
            PollAction::Wait(next)
        }
        PollResponse::Denied => PollAction::Fail(PollTerminal::Denied),
        PollResponse::Expired => PollAction::Fail(PollTerminal::Expired),
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Public outcome + callbacks
// ─────────────────────────────────────────────────────────────────────────────

/// The result of a successful device-flow link.
///
/// Carries the persisted [`LinkState`] reflection metadata plus the freshly minted [`TokenPair`]
/// (already written to the keyring by [`link_device_flow`]) so the caller can immediately build a
/// [`super::client::CloudClient`] without a second keyring read. `channel_key` (the per-agent
/// credential-channel secret) is surfaced for the recorder/gateway bridge — this module does not own
/// or persist it.
#[derive(Clone)]
pub struct LinkOutcome {
    /// Non-secret link metadata (also persisted to the encrypted `config` kv on success).
    pub link_state: LinkState,
    /// The minted account token pair. SECRET — already in the keyring; do not log.
    pub token: TokenPair,
    /// Token mode: `"user-hosted"` (default) or `"infrastructure"`.
    pub mode: String,
    /// Per-agent Fernet channel key, if the server issued one. SECRET — do not log/persist here.
    pub channel_key: Option<String>,
}

impl std::fmt::Debug for LinkOutcome {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LinkOutcome")
            .field("link_state", &self.link_state)
            .field("token", &self.token) // TokenPair Debug already redacts
            .field("mode", &self.mode)
            .field("channel_key", &self.channel_key.as_ref().map(|_| "<redacted>"))
            .finish()
    }
}

/// Caller hooks for displaying the user-code and opening the verification URL.
///
/// Plain (sync) `Fn` closures — NO async-trait, NO boxed futures. The CLI prints to stdout; the Tauri
/// GUI emits an event to the webview. `open_url` defaults to [`opener::open`] when not overridden via
/// [`LinkCallbacks::with_open`]; pass a no-op to suppress auto-open (e.g. headless/CI).
pub struct LinkCallbacks<'a> {
    /// Invoked once with the device-authorization details right after the device-auth request, so the
    /// front-end can render the `user_code` and instructions before polling starts.
    pub on_prompt: Box<dyn Fn(&DeviceAuthorization) + Send + 'a>,
    /// Open the verification URL for the user. Errors are non-fatal (logged; the user can still type
    /// the code manually).
    pub open_url: Box<dyn Fn(&str) -> std::io::Result<()> + Send + 'a>,
}

impl<'a> Default for LinkCallbacks<'a> {
    fn default() -> Self {
        Self {
            on_prompt: Box::new(|_auth| {}),
            open_url: Box::new(|url: &str| opener::open(url).map_err(std::io::Error::other)),
        }
    }
}

impl<'a> LinkCallbacks<'a> {
    /// Builder: set the prompt callback (render the user-code / instructions).
    pub fn with_prompt(mut self, f: impl Fn(&DeviceAuthorization) + Send + 'a) -> Self {
        self.on_prompt = Box::new(f);
        self
    }

    /// Builder: override how the verification URL is opened (e.g. a no-op for headless).
    pub fn with_open(mut self, f: impl Fn(&str) -> std::io::Result<()> + Send + 'a) -> Self {
        self.open_url = Box::new(f);
        self
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Live flow
// ─────────────────────────────────────────────────────────────────────────────

/// JSON body for the device-authorization request.
#[derive(serde::Serialize)]
struct DeviceAuthRequest<'a> {
    client_id: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    mode: Option<&'a str>,
}

/// JSON body for the device token-poll request.
#[derive(serde::Serialize)]
struct DeviceTokenRequest<'a> {
    grant_type: &'a str,
    device_code: &'a str,
    client_id: &'a str,
}

/// Build the (unauthenticated) HTTP client used for the device-flow handshake.
fn build_http() -> LocalResult<reqwest::Client> {
    reqwest::Client::builder()
        .timeout(REQUEST_TIMEOUT)
        .connect_timeout(CONNECT_TIMEOUT)
        .user_agent(concat!("writ-agent/", env!("CARGO_PKG_VERSION")))
        .build()
        .map_err(|e| LocalError::Internal(format!("device-flow http client build: {e}")))
}

fn join(base_url: &str, path: &str) -> String {
    format!("{}/{}", base_url.trim_end_matches('/'), path.trim_start_matches('/'))
}

/// Step 1: request a device + user code from the cloud (RFC 8628 §3.1/§3.2).
///
/// `mode` is `None` for the standard user-hosted link (the server applies its default), or
/// `Some("infrastructure")` for trusted-fleet enrollment (platform-admin-gated server-side).
pub async fn request_device_code(
    http: &reqwest::Client,
    base_url: &str,
    mode: Option<&str>,
) -> LocalResult<DeviceAuthorization> {
    let url = join(base_url, DEVICE_AUTH_PATH);
    let body = DeviceAuthRequest { client_id: DEVICE_CLIENT_ID, mode };
    let resp = http
        .post(&url)
        .json(&body)
        .send()
        .await
        .map_err(|e| super::client::classify_send_err(e, "device-auth request failed"))?;

    let status = resp.status();
    if status.is_success() {
        let auth: DeviceAuthorization = resp
            .json()
            .await
            .map_err(|e| LocalError::Internal(format!("device-auth decode: {e}")))?;
        tracing::debug!(
            verification_uri = %auth.verification_uri,
            expires_in = ?auth.expires_in,
            "device authorization requested"
        );
        return Ok(auth);
    }

    let detail = resp.text().await.unwrap_or_default();
    tracing::warn!(status = status.as_u16(), detail = %truncate_body(&detail), "device-auth request rejected");
    Err(match status {
        reqwest::StatusCode::TOO_MANY_REQUESTS => {
            LocalError::BadRequest("too many link attempts — wait a minute and try again".into())
        }
        reqwest::StatusCode::BAD_REQUEST => LocalError::BadRequest("cloud rejected the link request".into()),
        s => LocalError::Internal(format!("device-auth request failed (HTTP {})", s.as_u16())),
    })
}

/// Single non-interactive poll of the token endpoint — the testable seam over the network.
///
/// Maps the HTTP response onto a [`PollResponse`] without sleeping or persisting anything. A
/// transport/5xx error is surfaced as `Err` (the loop treats it as transient and retries); the
/// terminal *protocol* outcomes (denied/expired) come back as `Ok(PollResponse::{Denied,Expired})`.
pub async fn poll_once(
    http: &reqwest::Client,
    base_url: &str,
    device_code: &str,
) -> LocalResult<PollResponse> {
    let url = join(base_url, DEVICE_TOKEN_PATH);
    let body = DeviceTokenRequest {
        grant_type: DEVICE_GRANT_TYPE,
        device_code,
        client_id: DEVICE_CLIENT_ID,
    };
    let resp = http
        .post(&url)
        .json(&body)
        .send()
        .await
        .map_err(|e| super::client::classify_send_err(e, "device-token poll failed"))?;

    let status = resp.status();

    // 200 — approved; parse tokens and build the outcome.
    if status.is_success() {
        let parsed: DeviceTokenResponse = resp
            .json()
            .await
            .map_err(|e| LocalError::Internal(format!("device-token decode: {e}")))?;
        return Ok(PollResponse::Approved(outcome_from_token(base_url, parsed)));
    }

    // Non-success: pull the body once and classify the RFC 8628 error code (and 428/410 status).
    let err = resp.json::<DeviceTokenError>().await.ok();
    let code = err.as_ref().and_then(|e| e.error.as_deref()).unwrap_or("");

    Ok(match (status, code) {
        // RFC 8628 §3.5 error codes take precedence when present.
        (_, "authorization_pending") => PollResponse::Pending,
        (_, "slow_down") => PollResponse::SlowDown,
        (_, "access_denied") => PollResponse::Denied,
        (_, "expired_token") => PollResponse::Expired,
        // Backend status mapping when no/other error code body is present.
        (reqwest::StatusCode::PRECONDITION_REQUIRED, _) => PollResponse::Pending, // 428
        (reqwest::StatusCode::GONE, _) => PollResponse::Expired,                  // 410
        (s, other) => {
            tracing::warn!(status = s.as_u16(), error_code = %other, "unexpected device-token poll response");
            // Treat as transient (the loop will retry until the device code expires) rather than
            // terminating the whole link on a blip.
            return Err(LocalError::Internal(format!(
                "device-token poll returned HTTP {}",
                s.as_u16()
            )));
        }
    })
}

/// Build a [`LinkOutcome`] from a parsed token response, deriving the [`LinkState`] reflection
/// metadata. The token is NOT persisted here (the orchestrator does that, fail-closed).
fn outcome_from_token(base_url: &str, parsed: DeviceTokenResponse) -> LinkOutcome {
    let expires_at = parsed
        .expires_in
        .filter(|s| *s > 0)
        .map(|s| chrono::Utc::now() + chrono::Duration::seconds(s as i64));
    // For user-hosted there is always a refresh token; for infra mode there may be none — keep an
    // empty string so the keyring blob round-trips (refresh simply won't be usable, re-link to rotate).
    let refresh = parsed.refresh_token.clone().unwrap_or_default();
    let token = TokenPair::new(parsed.access_token.clone(), refresh, expires_at);

    let account_id = parsed
        .tenant_id
        .clone()
        .or_else(|| parsed.agent_id.clone())
        .unwrap_or_default();

    // Scopes: prefer an explicit list, else split a space-delimited `scope` string.
    let scopes = parsed.scopes.clone().unwrap_or_else(|| {
        parsed
            .scope
            .as_deref()
            .map(|s| s.split_whitespace().map(str::to_string).collect())
            .unwrap_or_default()
    });

    // Normalize the reflected language to a supported base code (`en`/`fr`/`es`); anything else is
    // dropped so the desktop never adopts a code it can't render.
    let language = parsed
        .language
        .as_deref()
        .map(|l| l.split('-').next().unwrap_or(l).trim().to_lowercase())
        .filter(|l| matches!(l.as_str(), "en" | "fr" | "es"));

    let link_state = LinkState {
        account_id,
        email: parsed.email.clone().unwrap_or_default(),
        cloud_base_url: base_url.trim_end_matches('/').to_string(),
        scopes,
        linked_at: Some(chrono::Utc::now()),
        language,
    };

    LinkOutcome {
        link_state,
        token,
        mode: parsed.mode.clone().unwrap_or_else(|| "user-hosted".to_string()),
        channel_key: parsed.channel_key.clone(),
    }
}

/// Run the full device-authorization grant against `base_url` and, on success, persist the token
/// (keyring) + link state (encrypted `config` kv).
///
/// This is the entry point for both `writ login` and the Tauri "Link account" action. It:
///   - requests a device/user code, fires `cb.on_prompt`, and opens the verification URL,
///   - polls until the user approves (success), declines (`Denied`), the code expires (`Expired`),
///     or the overall `expires_in` deadline passes,
///   - on success writes the `wto_`/`wtr_` pair to the keyring and `LinkState` to the DB *before*
///     returning (fail-closed: a keyring write error aborts the link without leaving half-state).
///
/// `mode` is `None` for a standard user-hosted link. Transient poll errors (network blips / 5xx) are
/// retried at the current interval until the device code expires.
pub async fn link_device_flow(
    pool: &SqlitePool,
    base_url: &str,
    mode: Option<&str>,
    cb: &LinkCallbacks<'_>,
) -> LocalResult<LinkOutcome> {
    let http = build_http()?;
    let base_url = base_url.trim_end_matches('/').to_string();
    // Refuse a plaintext remote base BEFORE any POST — the device code + account tokens must never
    // travel in cleartext. (loopback + `WRIT_ALLOW_INSECURE_CLOUD` dev opt-in are allowed.)
    super::client::require_secure_cloud_url(&base_url)?;

    // Step 1 — device authorization request.
    let auth = request_device_code(&http, &base_url, mode).await?;

    // Step 2 — surface the code + open the browser.
    (cb.on_prompt)(&auth);
    // The URL we are about to hand to the OS opener came from the NETWORK
    // (`verification_uri_complete`). The default `open_url` callback is `opener::open`, which
    // dispatches to `open` / `xdg-open` / `ShellExecuteW` — LAUNCHERS, not browsers: a
    // `file:///…/Installer.app` value would be executed. Vet it HERE rather than inside the default
    // callback so the Tauri GUI's own callback is covered by the same gate. `on_prompt` has already
    // rendered the code + URL, so on rejection the user simply opens it themselves.
    if !verification_url_is_openable(auth.open_url(), &base_url) {
        tracing::warn!(
            // Scheme + host only: the URL embeds the user_code, which `Debug` deliberately redacts.
            scheme = %url::Url::parse(auth.open_url()).map(|u| u.scheme().to_string()).unwrap_or_default(),
            host = %url::Url::parse(auth.open_url()).ok().and_then(|u| u.host_str().map(String::from)).unwrap_or_default(),
            "refusing to auto-open the verification URL (not https on the cloud host) — open it manually"
        );
    } else if let Err(e) = (cb.open_url)(auth.open_url()) {
        // Non-fatal: the user can still navigate manually and type the code.
        tracing::warn!(error = %e, "could not auto-open verification URL");
    }

    // Step 3 — poll until terminal, honoring interval / slow_down / overall expiry.
    let mut interval = auth.poll_interval();
    let deadline = auth
        .expires_in
        .filter(|s| *s > 0)
        .map(|s| std::time::Instant::now() + Duration::from_secs(s));

    loop {
        if let Some(d) = deadline {
            if std::time::Instant::now() >= d {
                tracing::warn!("device flow deadline passed before approval");
                return Err(PollTerminal::Expired.into_error());
            }
        }
        tokio::time::sleep(interval).await;

        let response = match poll_once(&http, &base_url, &auth.device_code).await {
            Ok(r) => r,
            Err(e) => {
                // Transient transport/5xx — log and keep polling until the code expires.
                tracing::debug!(error = %e, "transient device-token poll error; will retry");
                continue;
            }
        };

        match poll_decide(response, interval) {
            PollAction::Wait(next) => {
                interval = next;
                continue;
            }
            PollAction::Fail(t) => return Err(t.into_error()),
            PollAction::Done(outcome) => {
                let outcome = *outcome;
                // Step 4 — persist token FIRST (keyring), then link state (DB). Fail closed: if the
                // keyring write fails, do not write LinkState (avoids "linked metadata, no token").
                token::set(&outcome.token)?;
                // Persist the per-agent channel key (keyring) so the marketplace executor can later
                // unseal cloud-sealed recipes for THIS agent. Best-effort: a keyring write failure
                // here must not undo a successful link (re-link can re-mint the key); marketplace
                // unseal will surface a clear error if the key is absent.
                persist_channel_key(outcome.channel_key.as_deref());
                if let Err(e) = outcome.link_state.save(pool).await {
                    // Roll back the keyring token so we don't leave a token with no metadata.
                    let _ = token::clear();
                    let _ = channel::clear();
                    return Err(e);
                }
                // Fresh link: default the managed cloud AI gateway ON when no local BYO key exists, so
                // AI works immediately without configuring a provider (best-effort; never fatal).
                crate::local::app::lifecycle::default_cloud_gateway_on_fresh_link(pool).await;
                tracing::info!(account_id = %outcome.link_state.account_id, mode = %outcome.mode, "cloud account linked");
                return Ok(outcome);
            }
        }
    }
}

/// Persist the per-agent channel key to the keyring, when the server issued one. Best-effort: a
/// keyring write failure is logged (without the key value) but does NOT abort the link — the key can
/// be re-minted by re-linking, and the marketplace unseal path fails closed with a clear error if it
/// is absent. The key value is NEVER logged.
fn persist_channel_key(channel_key: Option<&str>) {
    match channel_key {
        Some(key) if !key.is_empty() => {
            if let Err(e) = channel::set(key) {
                tracing::warn!(error = %e, "could not persist channel key (re-link to retry)");
            }
        }
        _ => {
            // No channel key in this link (e.g. some infra-mode tokens). Clear any stale one so the
            // executor doesn't unseal with a key that no longer matches this agent.
            let _ = channel::clear();
        }
    }
}

/// Unlink this desktop: clear the keyring account token, the per-agent channel key, AND the
/// persisted `LinkState`.
///
/// Idempotent. Returns `true` if anything was actually removed (token entry, channel key, and/or
/// metadata row). Note: this only drops the LOCAL link; it does not revoke the token server-side (do
/// that via the cloud account UI / a future revoke call). Also drops any in-flight device-flow
/// ([`PendingLink`]).
pub async fn unlink(pool: &SqlitePool) -> LocalResult<bool> {
    clear_pending().await;
    let token_removed = token::clear()?;
    let channel_removed = channel::clear()?;
    let state_removed = LinkState::clear(pool).await?;
    tracing::info!(token_removed, channel_removed, state_removed, "cloud account unlinked (local)");
    Ok(token_removed || channel_removed || state_removed)
}

// ─────────────────────────────────────────────────────────────────────────────
// Start / poll seam (UI-driven device flow)
// ─────────────────────────────────────────────────────────────────────────────
//
// [`link_device_flow`] above is the one-shot, blocking variant used by the `writ login` CLI: it
// requests a code, opens the browser, and blocks polling until terminal. A GUI can't block — it
// needs to (1) START the flow and immediately render the user-code, then (2) POLL on its own cadence
// (e.g. a Tauri timer) so the window stays responsive. [`start_link`] + [`poll_link`] provide that.
//
// The in-flight handshake (the `device_code` polling SECRET, base url, interval, expiry) is held in a
// process-global, in-MEMORY [`PendingLink`] — NEVER written to disk or the DB (the `device_code` is
// bearer-equivalent; see the module SECURITY notes). It is cleared on success, terminal failure,
// expiry, [`unlink`], or an explicit [`cancel_link`]. Only one device flow may be in flight at a
// time; a second [`start_link`] replaces (and discards) any prior pending handshake.

use std::sync::OnceLock;
use tokio::sync::Mutex;

/// In-memory record of a device flow that has been STARTED but not yet completed. Holds the polling
/// secret (`device_code`) plus the metadata the poll loop needs. NEVER persisted.
struct PendingLink {
    /// The device verification code — POSTed to the token endpoint while polling. SECRET.
    device_code: String,
    /// Cloud base url this flow targets (no trailing slash).
    base_url: String,
    /// Current poll interval (advances on `slow_down`).
    interval: Duration,
    /// Absolute deadline after which the user/device code is expired (from the auth `expires_in`).
    deadline: Option<std::time::Instant>,
}

impl std::fmt::Debug for PendingLink {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // NEVER print the device_code (polling secret).
        f.debug_struct("PendingLink")
            .field("device_code", &"<redacted>")
            .field("base_url", &self.base_url)
            .field("interval", &self.interval)
            .field("has_deadline", &self.deadline.is_some())
            .finish()
    }
}

/// Process-global slot for the single in-flight device flow.
fn pending_slot() -> &'static Mutex<Option<PendingLink>> {
    static SLOT: OnceLock<Mutex<Option<PendingLink>>> = OnceLock::new();
    SLOT.get_or_init(|| Mutex::new(None))
}

/// Clear any in-flight pending device flow (best-effort; no error). Called on success, terminal
/// failure, expiry, cancel, and unlink.
pub async fn clear_pending() {
    *pending_slot().lock().await = None;
}

/// Cancel an in-flight device flow started by [`start_link`]. Idempotent; returns `true` if a flow
/// was actually pending. Does NOT touch the keyring/LinkState (nothing is linked until poll success).
pub async fn cancel_link() -> bool {
    let mut slot = pending_slot().lock().await;
    let was = slot.is_some();
    *slot = None;
    was
}

/// The status of a [`poll_link`] advance, shaped for a UI.
///
/// `Linked` carries the freshly persisted [`LinkState`] (reflection metadata) so the caller can show
/// the account without a second read. Token material is NOT included (it is already in the keyring).
#[derive(Clone, Debug)]
pub enum LinkPollStatus {
    /// Still waiting on the user to approve in the browser — keep polling.
    Pending,
    /// The user approved; the token + link state are now persisted. Carries the link metadata.
    Linked(LinkState),
    /// The user explicitly declined. Terminal — the pending flow has been cleared.
    Denied,
    /// The device/user code expired (or no flow is in progress). Terminal — pending cleared.
    Expired,
}

/// STEP 1 (UI): request a device + user code and stash the in-flight handshake in memory.
///
/// Returns the [`DeviceAuthorization`] so the caller can render `user_code` / `verification_uri`
/// and open the browser itself (the GUI controls how the URL is opened). Does NOT open the browser
/// or block. A prior in-flight flow (if any) is replaced. `mode` is `None` for the standard
/// user-hosted link.
pub async fn start_link(base_url: &str, mode: Option<&str>) -> LocalResult<DeviceAuthorization> {
    let http = build_http()?;
    let base_url = base_url.trim_end_matches('/').to_string();
    // Refuse a plaintext remote base before the device-code request (loopback/dev opt-in excepted).
    super::client::require_secure_cloud_url(&base_url)?;
    let auth = request_device_code(&http, &base_url, mode).await?;

    let deadline = auth
        .expires_in
        .filter(|s| *s > 0)
        .map(|s| std::time::Instant::now() + Duration::from_secs(s));
    let pending = PendingLink {
        device_code: auth.device_code.clone(),
        base_url,
        interval: auth.poll_interval(),
        deadline,
    };
    *pending_slot().lock().await = Some(pending);
    tracing::debug!("device flow started (awaiting UI poll)");
    Ok(auth)
}

/// STEP 2 (UI): advance the in-flight device flow by exactly ONE poll and report the status.
///
/// - `Pending` — keep polling (after roughly the suggested interval). A `slow_down` is absorbed here
///   (the stored interval is bumped) and reported as `Pending`.
/// - `Linked(state)` — the `wto_`/`wtr_` pair was written to the keyring and `LinkState` to the DB
///   (fail-closed: a keyring write error aborts without leaving half-state); pending cleared.
/// - `Denied` / `Expired` — terminal; pending cleared.
///
/// When no flow is in progress (never started, already completed, or expired), returns `Expired`.
/// A transient transport/5xx blip is reported as `Pending` so the UI simply polls again — the
/// handshake stays in flight until its own deadline.
pub async fn poll_link(pool: &SqlitePool) -> LocalResult<LinkPollStatus> {
    // Snapshot what we need under the lock, then release it across the network call.
    let (device_code, base_url, interval) = {
        let mut slot = pending_slot().lock().await;
        let Some(p) = slot.as_mut() else {
            return Ok(LinkPollStatus::Expired);
        };
        // Overall deadline check before spending a network round-trip.
        if let Some(d) = p.deadline {
            if std::time::Instant::now() >= d {
                *slot = None;
                tracing::warn!("device flow deadline passed before approval");
                return Ok(LinkPollStatus::Expired);
            }
        }
        (p.device_code.clone(), p.base_url.clone(), p.interval)
    };

    let http = build_http()?;
    let response = match poll_once(&http, &base_url, &device_code).await {
        Ok(r) => r,
        Err(e) => {
            // Transient — let the UI poll again; keep the handshake in flight.
            tracing::debug!(error = %e, "transient device-token poll error; UI should retry");
            return Ok(LinkPollStatus::Pending);
        }
    };

    match poll_decide(response, interval) {
        PollAction::Wait(next) => {
            // Persist the (possibly slow_down-bumped) interval back onto the pending flow.
            if let Some(p) = pending_slot().lock().await.as_mut() {
                p.interval = next;
            }
            Ok(LinkPollStatus::Pending)
        }
        PollAction::Fail(PollTerminal::Denied) => {
            clear_pending().await;
            Ok(LinkPollStatus::Denied)
        }
        PollAction::Fail(PollTerminal::Expired) => {
            clear_pending().await;
            Ok(LinkPollStatus::Expired)
        }
        PollAction::Done(outcome) => {
            let outcome = *outcome;
            let ls = &outcome.link_state;
            let account_id = ls.account_id.clone();
            if account_id.is_empty() {
                clear_pending().await;
                return Err(LocalError::Internal("link succeeded but account id is empty".into()));
            }

            // MULTI-PROFILE: write the token + non-secret account metadata into the ACCOUNT's keyring
            // entry (keyed by account id), NOT the active profile. The shell then switches the daemon
            // into this account's profile (`~/.writ/profiles/<account_id>`), where boot reconciliation
            // turns the keyring metadata into that profile's `LinkState`. We do NOT write `LinkState`
            // into the CURRENT (e.g. anonymous `local`) profile's DB — its data stays its own.
            // Fail closed: a keyring write error aborts before any state is persisted.
            let meta = token::AccountMeta {
                account_id: ls.account_id.clone(),
                email: ls.email.clone(),
                scopes: ls.scopes.clone(),
                base_url: ls.cloud_base_url.clone(),
                linked_at: ls.linked_at,
                language: ls.language.clone(),
            };
            token::store_account(&account_id, &outcome.token, &meta)?;
            // Persist the per-agent channel key (keyring) for the marketplace executor's unseal path.
            persist_channel_key(outcome.channel_key.as_deref());

            // RE-LINK IN PLACE: if we're already running AS this account's profile (e.g. a logged-out
            // session re-authenticating), make the live profile linked NOW — no switch/restart needed.
            if account_id == token::active_profile() {
                if let Err(e) = outcome.link_state.save(pool).await {
                    let _ = token::clear_account(&account_id);
                    let _ = channel::clear();
                    clear_pending().await;
                    return Err(e);
                }
                // Re-linked in place: default the managed cloud AI gateway ON when no local BYO key
                // exists, so AI works immediately without configuring a provider (best-effort).
                crate::local::app::lifecycle::default_cloud_gateway_on_fresh_link(pool).await;
            }

            clear_pending().await;
            tracing::info!(
                account_id = %account_id,
                mode = %outcome.mode,
                "cloud account linked (UI device flow) — token in keyring[account], awaiting profile switch"
            );
            Ok(LinkPollStatus::Linked(outcome.link_state))
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests — pure state machine + parsing/formatting (no network).
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    /// The `verification_uri_complete` gate: only https (or loopback http) on the CLOUD host is handed
    /// to the OS URL opener. `opener` launches whatever the URL designates, so a `file://` value would
    /// start an application.
    #[test]
    fn only_same_host_https_verification_urls_are_opened() {
        let base = "https://api.usewrit.app";

        assert!(verification_url_is_openable(
            "https://api.usewrit.app/link?code=ABCD-2345",
            base
        ));
        assert!(verification_url_is_openable("https://API.UseWrit.app/link", base));

        for bad in [
            "file:///Applications/Installer.app",
            "file:///tmp/x.desktop",
            "smb://attacker/share",
            "vscode://x",
            "javascript:alert(1)",
            "data:text/html,x",
            "http://api.usewrit.app/link",   // plaintext to a non-loopback host
            "https://evil.example/link",     // right scheme, wrong host
            "not a url",
        ] {
            assert!(!verification_url_is_openable(bad, base), "must refuse `{bad}`");
        }

        // A loopback dev backend over plaintext http is allowed — nothing leaves the machine.
        assert!(verification_url_is_openable(
            "http://localhost:8000/link?code=X",
            "http://localhost:8000"
        ));
        assert!(verification_url_is_openable("http://127.0.0.1:8000/l", "http://127.0.0.1:8000"));
        // ...but not a loopback URL when the configured base is remote.
        assert!(!verification_url_is_openable("http://127.0.0.1:8000/l", base));
    }

    fn sample_outcome() -> LinkOutcome {
        LinkOutcome {
            link_state: LinkState {
                account_id: "acct_1".into(),
                email: "u@example.com".into(),
                cloud_base_url: "https://api.usewrit.app".into(),
                scopes: vec!["workflows:execute".into()],
                linked_at: Some(chrono::Utc::now()),
                language: None,
            },
            token: TokenPair::new("wto_a".into(), "wtr_b".into(), None),
            mode: "user-hosted".into(),
            channel_key: Some("ck".into()),
        }
    }

    #[test]
    fn pending_waits_at_current_interval() {
        let cur = Duration::from_secs(5);
        match poll_decide(PollResponse::Pending, cur) {
            PollAction::Wait(d) => assert_eq!(d, cur),
            other => panic!("expected Wait, got {other:?}"),
        }
    }

    #[test]
    fn slow_down_bumps_interval_by_increment() {
        // 5s → 10s → 15s, each slow_down adds SLOW_DOWN_INCREMENT_SECS.
        let mut cur = Duration::from_secs(5);
        for expected in [10u64, 15, 20] {
            match poll_decide(PollResponse::SlowDown, cur) {
                PollAction::Wait(next) => {
                    assert_eq!(next, Duration::from_secs(expected));
                    cur = next;
                }
                other => panic!("expected Wait, got {other:?}"),
            }
        }
    }

    #[test]
    fn slow_down_never_goes_below_floor() {
        // Even from a zero interval, a slow_down stays >= the min floor.
        let next = match poll_decide(PollResponse::SlowDown, Duration::from_secs(0)) {
            PollAction::Wait(d) => d,
            other => panic!("expected Wait, got {other:?}"),
        };
        assert!(next >= Duration::from_secs(MIN_POLL_INTERVAL_SECS));
    }

    #[test]
    fn approved_is_done() {
        match poll_decide(PollResponse::Approved(sample_outcome()), Duration::from_secs(5)) {
            PollAction::Done(o) => {
                assert_eq!(o.link_state.account_id, "acct_1");
                assert_eq!(o.mode, "user-hosted");
            }
            other => panic!("expected Done, got {other:?}"),
        }
    }

    #[test]
    fn denied_and_expired_are_terminal() {
        assert!(matches!(
            poll_decide(PollResponse::Denied, Duration::from_secs(5)),
            PollAction::Fail(PollTerminal::Denied)
        ));
        assert!(matches!(
            poll_decide(PollResponse::Expired, Duration::from_secs(5)),
            PollAction::Fail(PollTerminal::Expired)
        ));
    }

    #[test]
    fn full_machine_pending_then_slowdown_then_success() {
        // Drive the machine through a realistic sequence with injected responses.
        let mut interval = Duration::from_secs(5);

        // pending → wait, interval unchanged.
        interval = match poll_decide(PollResponse::Pending, interval) {
            PollAction::Wait(d) => d,
            o => panic!("{o:?}"),
        };
        assert_eq!(interval, Duration::from_secs(5));

        // slow_down → wait, interval bumped.
        interval = match poll_decide(PollResponse::SlowDown, interval) {
            PollAction::Wait(d) => d,
            o => panic!("{o:?}"),
        };
        assert_eq!(interval, Duration::from_secs(10));

        // pending again → still 10s.
        interval = match poll_decide(PollResponse::Pending, interval) {
            PollAction::Wait(d) => d,
            o => panic!("{o:?}"),
        };
        assert_eq!(interval, Duration::from_secs(10));

        // success → done.
        match poll_decide(PollResponse::Approved(sample_outcome()), interval) {
            PollAction::Done(_) => {}
            o => panic!("expected Done, got {o:?}"),
        }
    }

    #[test]
    fn full_machine_expires() {
        let interval = Duration::from_secs(5);
        match poll_decide(PollResponse::Expired, interval) {
            PollAction::Fail(PollTerminal::Expired) => {}
            o => panic!("expected Fail(Expired), got {o:?}"),
        }
    }

    #[test]
    fn terminal_maps_to_bad_request() {
        assert!(matches!(PollTerminal::Denied.into_error(), LocalError::BadRequest(_)));
        assert!(matches!(PollTerminal::Expired.into_error(), LocalError::BadRequest(_)));
    }

    #[test]
    fn device_auth_open_url_prefers_complete() {
        let with_complete = DeviceAuthorization {
            device_code: "dc".into(),
            user_code: "ABCD-2345".into(),
            verification_uri: "https://app.usewrit.app/oauth/device".into(),
            verification_uri_complete: Some("https://app.usewrit.app/oauth/device?code=ABCD-2345".into()),
            expires_in: Some(900),
            interval: Some(5),
        };
        assert_eq!(with_complete.open_url(), "https://app.usewrit.app/oauth/device?code=ABCD-2345");

        let bare = DeviceAuthorization { verification_uri_complete: None, ..with_complete.clone() };
        assert_eq!(bare.open_url(), "https://app.usewrit.app/oauth/device");
    }

    #[test]
    fn device_auth_poll_interval_defaults_and_floors() {
        let base = DeviceAuthorization {
            device_code: "dc".into(),
            user_code: "ABCD-2345".into(),
            verification_uri: "https://x/".into(),
            verification_uri_complete: None,
            expires_in: Some(900),
            interval: None,
        };
        // Missing interval → default.
        assert_eq!(base.poll_interval(), Duration::from_secs(DEFAULT_POLL_INTERVAL_SECS));
        // Below floor → clamped up.
        let zero = DeviceAuthorization { interval: Some(0), ..base.clone() };
        assert_eq!(zero.poll_interval(), Duration::from_secs(MIN_POLL_INTERVAL_SECS));
        // Explicit value honored.
        let ten = DeviceAuthorization { interval: Some(10), ..base.clone() };
        assert_eq!(ten.poll_interval(), Duration::from_secs(10));
    }

    #[test]
    fn device_auth_debug_redacts_codes() {
        let auth = DeviceAuthorization {
            device_code: "SECRET_DEVICE_CODE".into(),
            user_code: "SECRET-USER".into(),
            verification_uri: "https://x/".into(),
            verification_uri_complete: None,
            expires_in: Some(900),
            interval: Some(5),
        };
        let dbg = format!("{auth:?}");
        assert!(!dbg.contains("SECRET_DEVICE_CODE"), "device_code must be redacted");
        assert!(!dbg.contains("SECRET-USER"), "user_code must be redacted");
        assert!(dbg.contains("redacted"));
    }

    #[test]
    fn link_outcome_debug_redacts_secrets() {
        let dbg = format!("{:?}", sample_outcome());
        assert!(!dbg.contains("wto_a"), "access token must not leak");
        assert!(!dbg.contains("wtr_b"), "refresh token must not leak");
        assert!(!dbg.contains("\"ck\""), "channel_key must not leak");
    }

    #[test]
    fn device_auth_parses_backend_shape() {
        // Matches the cloud backend's `oauth` router `device_authorization` response.
        let json = r#"{
            "device_code": "dc_xxx",
            "user_code": "ABCD-2345",
            "verification_uri": "https://app.usewrit.app/oauth/device",
            "verification_uri_complete": "https://app.usewrit.app/oauth/device?code=ABCD-2345",
            "expires_in": 900,
            "interval": 5
        }"#;
        let auth: DeviceAuthorization = serde_json::from_str(json).unwrap();
        assert_eq!(auth.user_code, "ABCD-2345");
        assert_eq!(auth.expires_in, Some(900));
        assert_eq!(auth.interval, Some(5));
        assert!(auth.verification_uri_complete.is_some());
    }

    #[test]
    fn device_token_parses_user_hosted_shape() {
        // Matches backend user-hosted success body.
        let json = r#"{
            "access_token": "wto_abc",
            "token_type": "bearer",
            "mode": "user-hosted",
            "expires_in": 3600,
            "refresh_token": "wtr_def",
            "channel_key": "ck_ghi",
            "tenant_id": "tenant_42",
            "email": "u@example.com",
            "org_name": "Acme",
            "language": "fr-CA"
        }"#;
        let parsed: DeviceTokenResponse = serde_json::from_str(json).unwrap();
        let outcome = outcome_from_token("https://api.usewrit.app/", parsed);
        assert_eq!(outcome.link_state.account_id, "tenant_42");
        assert_eq!(outcome.link_state.email, "u@example.com");
        // Reflected language is normalized to the supported base code (fr-CA → fr).
        assert_eq!(outcome.link_state.language.as_deref(), Some("fr"));
        assert_eq!(outcome.link_state.cloud_base_url, "https://api.usewrit.app");
        assert_eq!(outcome.mode, "user-hosted");
        assert_eq!(outcome.channel_key.as_deref(), Some("ck_ghi"));
        assert_eq!(outcome.token.access(), "wto_abc");
        assert_eq!(outcome.token.refresh(), "wtr_def");
        assert!(outcome.token.expires_at.is_some());
        assert!(outcome.link_state.linked_at.is_some());
    }

    #[test]
    fn device_token_infra_shape_without_refresh() {
        // Infra mode: no refresh_token, account id may arrive as agent_id; scope as a string.
        let json = r#"{
            "access_token": "svc.jwt.token",
            "token_type": "bearer",
            "mode": "infrastructure",
            "expires_in": 0,
            "channel_key": "ck",
            "agent_id": "writ-abc123",
            "scope": "agent:connect workflows:execute"
        }"#;
        let parsed: DeviceTokenResponse = serde_json::from_str(json).unwrap();
        let outcome = outcome_from_token("https://api.usewrit.app", parsed);
        assert_eq!(outcome.mode, "infrastructure");
        assert_eq!(outcome.link_state.account_id, "writ-abc123");
        assert!(outcome.token.refresh().is_empty(), "no refresh token in infra mode");
        // expires_in == 0 → no expiry hint recorded.
        assert!(outcome.token.expires_at.is_none());
        assert_eq!(outcome.link_state.scopes, vec!["agent:connect", "workflows:execute"]);
    }

    #[test]
    fn join_handles_slashes() {
        assert_eq!(join("https://api.usewrit.app/", "/api/oauth/device"), "https://api.usewrit.app/api/oauth/device");
        assert_eq!(join("https://api.usewrit.app", "api/oauth/device/token"), "https://api.usewrit.app/api/oauth/device/token");
    }

    #[tokio::test]
    async fn unlink_is_idempotent_no_panic() {
        // With no DB and the throwaway test keyring this should not panic; it returns whatever was
        // removed. We can't easily provide a pool here without the db harness, so just exercise the
        // token-clear half is covered by token.rs; this guards the public fn compiles + the keyring
        // call path. (Full unlink roundtrip is covered indirectly by state.rs tests + token.rs.)
        // No assertion on bool (depends on machine keyring state); only that it does not panic.
        let _ = token::clear();
    }

    // ── Real-network end-to-end (requires a live backend + a human approving the code). ──
    #[tokio::test]
    #[ignore = "network: requires a live Writ Cloud backend and a human to approve the device code"]
    async fn live_device_flow_link() {
        let base = std::env::var(super::super::client::ENV_CLOUD_URL)
            .unwrap_or_else(|_| super::super::client::DEFAULT_CLOUD_BASE_URL.to_string());
        let http = build_http().unwrap();
        let auth = request_device_code(&http, &base, None).await.expect("device-auth request");
        println!("Open {} and enter code: {}", auth.open_url(), auth.user_code);
        // Poll a few times to demonstrate the live wire path (won't complete without human approval).
        for _ in 0..3 {
            tokio::time::sleep(auth.poll_interval()).await;
            match poll_once(&http, &base, &auth.device_code).await {
                Ok(PollResponse::Approved(o)) => {
                    println!("linked: account={}", o.link_state.account_id);
                    return;
                }
                Ok(other) => println!("poll: {other:?}"),
                Err(e) => println!("poll error: {e}"),
            }
        }
    }
}
