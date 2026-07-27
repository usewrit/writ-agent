//! Authenticated Writ Cloud HTTP client (reqwest 0.12).
//!
//! Resolves the cloud API base url, attaches the `wto_` Bearer access token, and on a `401` performs
//! a SINGLE refresh using the stored `wtr_` refresh token against the PUBLIC device-refresh endpoint
//! (`/api/oauth/device/refresh` — the desktop is an RFC 8628 public client), persists the rotated
//! pair to the keyring, then retries the original request exactly once.
//!
//! SECURITY (the never-trust-a-BYO-agent rule): this client only *carries* the account token to the
//! cloud — it is NOT an authorization gate. Every paid/metered capability is re-enforced SERVER-SIDE
//! per call. Token values are NEVER logged (only outcomes/status). The account token lives solely in
//! the OS keyring (see [`super::token`]); this module never writes it to disk or the DB.
//!
//! House style: no `async-trait` — async methods on a concrete struct; errors fold into
//! [`crate::local::error::LocalError`]. Runtime-resolved base url (no compile-time const url).
//!
//! Net-new Rust in this crate (Stage A — cloud client foundation).

use super::super::error::{LocalError, LocalResult};
use super::state::LinkState;
use super::token::{self, TokenPair};
use serde::de::DeserializeOwned;
use serde::Serialize;
use std::time::Duration;

lazy_static::lazy_static! {
    /// Process-global refresh lock (CR-8). The `wtr_` refresh token is SINGLE-USE and rotated by the
    /// server on each grant, so two concurrent refreshes race: both POST the same token, one wins and
    /// persists the rotated pair, the loser gets `invalid_grant` for a token that is now stale. We
    /// serialize refreshes behind this mutex so only one grant is ever in flight; a caller that blocks
    /// here re-reads the keyring after acquiring so it picks up a pair the winner just persisted instead
    /// of re-spending the token it started with.
    static ref REFRESH_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::new(());
}

/// Built-in default cloud base url, used when neither `WRIT_CLOUD_URL` nor a persisted
/// [`LinkState::base_url`] is set. No trailing slash.
///
/// This must be the PRODUCTION api host and nothing else. It previously pointed at an internal
/// bench host, which (a) contradicted `README.md` and `docs/CONFIGURATION.md`, both of which
/// document this default, and (b) published an internal hostname in a public repository. A
/// disclosure table that names the wrong network destination is worse than no table.
///
/// Only the optional desktop cloud-link reads this; the self-host `fleet` build has no cloud link
/// at all, and any deployment can override it with `WRIT_CLOUD_URL`.
pub const DEFAULT_CLOUD_BASE_URL: &str = "https://api.usewrit.app";

/// Env override for the cloud base url (takes precedence over `LinkState`). No trailing slash.
pub const ENV_CLOUD_URL: &str = "WRIT_CLOUD_URL";

/// OAuth client id for the device-flow public client (matches the backend `DEVICE_CLIENT_ID`).
const OAUTH_CLIENT_ID: &str = "writ-agent";

/// Per-request timeout for cloud calls.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);
/// Per-request timeout for a LONG-LIVED streaming GET (SSE). Overrides the short global
/// [`REQUEST_TIMEOUT`] so a persistent run-events stream isn't reaped; the forwarder reconnects at
/// least this often even in the absence of any server frame (server keep-alives normally keep it
/// warm well within the window).
const STREAM_REQUEST_TIMEOUT: Duration = Duration::from_secs(3600);

/// Connect-phase timeout. Bounds how long an OFFLINE / unreachable cloud can hang before we fail
/// fast to a retryable 503 — WITHOUT shortening the 30s read budget for slow-but-connected
/// responses (e.g. a large sync pull). Keep in sync with the device-flow client in `link.rs`.
const CLOUD_CONNECT_TIMEOUT: Duration = Duration::from_secs(4);

/// Classify a reqwest send/transport error. Connect-refused / DNS-failure / connect-or-read timeout
/// mean the cloud is unreachable (offline) → [`LocalError::CloudUnreachable`] (503, retryable);
/// everything else is a genuine [`LocalError::Internal`] (500). Keeping "offline" out of the 500
/// bucket is what lets the desktop UI degrade gracefully instead of showing a hard error. Shared
/// with the device-flow paths in `link.rs`.
pub(crate) fn classify_send_err(e: reqwest::Error, ctx: &str) -> LocalError {
    if e.is_connect() || e.is_timeout() {
        LocalError::CloudUnreachable(format!("{ctx}: {e}"))
    } else {
        LocalError::Internal(format!("{ctx}: {e}"))
    }
}

/// An authenticated cloud HTTP client.
///
/// Holds a configured `reqwest::Client`, the resolved base url, and the in-memory token pair. Build
/// it with [`CloudClient::connect`] (loads the token from the keyring) or [`CloudClient::with_token`]
/// (inject a pair, e.g. right after device-flow link).
#[derive(Debug, Clone)]
pub struct CloudClient {
    http: reqwest::Client,
    base_url: String,
    token: TokenPair,
}

/// Read a response header as an owned `String` (empty when absent / non-ASCII). Used only for
/// decode-failure diagnostics, never for control flow.
fn header_str(resp: &reqwest::Response, name: reqwest::header::HeaderName) -> String {
    resp.headers()
        .get(name)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string()
}

/// Bound a server error body before it hits the logs (F9). A hostile / verbose upstream could otherwise
/// dump an unbounded body verbatim into `tracing`; cap it char-safely at 500 chars for diagnostics.
fn truncate_body(s: &str) -> String {
    const MAX: usize = 500;
    if s.chars().count() <= MAX {
        return s.to_string();
    }
    let head: String = s.chars().take(MAX).collect();
    format!("{head}…[truncated]")
}

/// True when a rejected refresh-grant body is a genuine OAuth token rejection rather than some
/// interposer's 401/400 page. Only such a body may cause the stored token to be DISCARDED.
///
/// The backend answers a dead/unknown refresh token with FastAPI's `{"detail": "invalid_grant: …"}`
/// and a wrong client with `invalid_client`; RFC 6749 spells the same values in `{"error": "…"}`.
/// A captive portal, proxy, or SSO front door returns HTML or an unrelated JSON shape and matches
/// none of them — so it is treated as transient and the session survives.
fn is_invalid_grant(body: &str) -> bool {
    let b = body.to_ascii_lowercase();
    b.contains("invalid_grant") || b.contains("invalid_client") || b.contains("invalid_token")
}

/// Pull a user-facing message out of a cloud error body. The backend uses several shapes across
/// endpoints — `{"detail": {"message": "…"}}` (AI-guard / metered denials), `{"detail": "…"}`
/// (FastAPI HTTPException), and `{"message": "…"}` / `{"error": "…"}`. Returns the first non-empty
/// string found, so a 402's "upgrade / add credit" text reaches the UI verbatim.
fn extract_detail_message(body: &str) -> Option<String> {
    let v: serde_json::Value = serde_json::from_str(body).ok()?;
    let pick = |val: Option<&serde_json::Value>| -> Option<String> {
        match val {
            Some(serde_json::Value::String(s)) if !s.trim().is_empty() => Some(s.trim().to_string()),
            Some(serde_json::Value::Object(o)) => o
                .get("message")
                .and_then(|m| m.as_str())
                .filter(|s| !s.trim().is_empty())
                .map(|s| s.trim().to_string()),
            _ => None,
        }
    };
    pick(v.get("detail"))
        .or_else(|| pick(v.get("message")))
        .or_else(|| pick(v.get("error")))
}

/// Refuse a plaintext cloud base URL outside loopback/dev. An `http://` REMOTE base would transmit
/// the device code and the `wto_`/`wtr_` account tokens in cleartext (the WS gateway already enforces
/// this via `gateway::require_secure_url`; this is the matching gate for the REST + device-flow HTTP
/// paths). Accept `https://`, any loopback host, or an explicit `WRIT_ALLOW_INSECURE_CLOUD` dev
/// opt-in. `pub(crate)` so `link.rs` shares the exact same check.
pub(crate) fn require_secure_cloud_url(url: &str) -> LocalResult<()> {
    let lower = url.trim().to_lowercase();
    if lower.starts_with("https://") {
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
    let allow_insecure = std::env::var("WRIT_ALLOW_INSECURE_CLOUD")
        .map(|v| {
            let v = v.trim().to_ascii_lowercase();
            v == "1" || v == "true" || v == "yes" || v == "on"
        })
        .unwrap_or(false);
    if is_local || allow_insecure {
        return Ok(());
    }
    Err(LocalError::BadRequest(format!(
        "refusing insecure cloud URL '{url}': plaintext would expose the device code and account \
         tokens on the wire — use an https:// endpoint"
    )))
}

impl CloudClient {
    /// Resolve the cloud base url with precedence: `WRIT_CLOUD_URL` env → persisted `LinkState` →
    /// [`DEFAULT_CLOUD_BASE_URL`]. Returns a value with no trailing slash. Pure given its inputs.
    pub fn resolve_base_url(link: Option<&LinkState>) -> String {
        if let Ok(env) = std::env::var(ENV_CLOUD_URL) {
            let trimmed = env.trim().trim_end_matches('/');
            if !trimmed.is_empty() {
                return trimmed.to_string();
            }
        }
        if let Some(url) = link.and_then(|l| l.base_url()) {
            return url.to_string();
        }
        DEFAULT_CLOUD_BASE_URL.to_string()
    }

    fn build_http() -> LocalResult<reqwest::Client> {
        reqwest::Client::builder()
            .timeout(REQUEST_TIMEOUT)
            .connect_timeout(CLOUD_CONNECT_TIMEOUT)
            .user_agent(concat!("writ-agent/", env!("CARGO_PKG_VERSION")))
            // The cloud runs Starlette GZipMiddleware (gzips bodies >1000 bytes when the
            // client advertises gzip). Enable transparent gzip so reqwest negotiates
            // Accept-Encoding AND decompresses — otherwise large list responses (e.g. the
            // workflows sync pull) arrive as raw gzip bytes and JSON decode fails.
            .gzip(true)
            .build()
            .map_err(|e| LocalError::Internal(format!("cloud http client build: {e}")))
    }

    /// Construct a client from an explicit token pair + resolved base url. Used immediately after a
    /// fresh device-flow link, before anything is persisted.
    pub fn with_token(base_url: impl Into<String>, token: TokenPair) -> LocalResult<Self> {
        let base_url = base_url.into().trim_end_matches('/').to_string();
        require_secure_cloud_url(&base_url)?;
        Ok(Self { http: Self::build_http()?, base_url, token })
    }

    /// Build a client by loading the account token from the OS keyring and resolving the base url
    /// from `link` (or env/default). Returns [`LocalError::Unauthorized`] when no token is stored —
    /// the desktop is not linked — rather than panicking.
    pub fn connect(link: Option<&LinkState>) -> LocalResult<Self> {
        let token = token::get()?.ok_or(LocalError::Unauthorized)?;
        let base_url = Self::resolve_base_url(link);
        require_secure_cloud_url(&base_url)?;
        Ok(Self { http: Self::build_http()?, base_url, token })
    }

    /// The resolved base url this client targets (no trailing slash).
    pub fn base_url(&self) -> &str {
        &self.base_url
    }

    /// Join the base url and a path (the path may or may not start with `/`).
    fn url(&self, path: &str) -> String {
        format!("{}/{}", self.base_url, path.trim_start_matches('/'))
    }

    /// Authenticated GET returning a deserialized JSON body. Retries once after a 401 refresh.
    pub async fn get_json<T: DeserializeOwned>(&mut self, path: &str) -> LocalResult<T> {
        self.send_json::<(), T>(reqwest::Method::GET, path, None).await
    }

    /// Authenticated GET returning the raw response bytes plus the `Content-Type` and
    /// `Content-Disposition` headers (each `None` when absent). Retries once after a 401 refresh.
    /// Used to stream a cloud data EXPORT (CSV/JSON download bytes) straight back through the
    /// daemon without a JSON round-trip — the cloud already framed the attachment headers.
    pub async fn get_bytes(
        &mut self,
        path: &str,
    ) -> LocalResult<(Vec<u8>, Option<String>, Option<String>)> {
        let url = self.url(path);
        let first = self.execute::<()>(reqwest::Method::GET, &url, None).await?;
        let resp = if first.status() == reqwest::StatusCode::UNAUTHORIZED {
            tracing::debug!("cloud 401 (GET bytes) — attempting token refresh");
            self.refresh().await?;
            self.execute::<()>(reqwest::Method::GET, &url, None).await?
        } else {
            first
        };
        let status = resp.status();
        if !status.is_success() {
            let detail = resp.text().await.unwrap_or_default();
            tracing::warn!(status = status.as_u16(), detail = %truncate_body(&detail), "cloud request returned error");
            return Err(Self::status_error(status));
        }
        let opt = |s: String| if s.is_empty() { None } else { Some(s) };
        let ctype = opt(header_str(&resp, reqwest::header::CONTENT_TYPE));
        let cdisp = opt(header_str(&resp, reqwest::header::CONTENT_DISPOSITION));
        let bytes = resp
            .bytes()
            .await
            .map_err(|e| LocalError::Internal(format!("cloud response read: {e}")))?;
        Ok((bytes.to_vec(), ctype, cdisp))
    }

    /// Authenticated POST of a JSON body returning a deserialized JSON body. Retries once after a
    /// 401 refresh.
    pub async fn post_json<B: Serialize, T: DeserializeOwned>(
        &mut self,
        path: &str,
        body: &B,
    ) -> LocalResult<T> {
        self.send_json::<B, T>(reqwest::Method::POST, path, Some(body)).await
    }

    /// Authenticated PATCH of a JSON body returning a deserialized JSON body. Retries once after a
    /// 401 refresh. Used by the granular sync PUSH update path (`PATCH /automation/workflows/{id}`
    /// etc.) to overwrite a previously-pushed private cloud record.
    pub async fn patch_json<B: Serialize, T: DeserializeOwned>(
        &mut self,
        path: &str,
        body: &B,
    ) -> LocalResult<T> {
        self.send_json::<B, T>(reqwest::Method::PATCH, path, Some(body)).await
    }

    /// Authenticated PUT of a JSON body. Retries once after a 401 refresh. Used by the sync PUSH
    /// update path for resources whose backend update verb is PUT (e.g. `PUT /api/automation/workflows/{id}`)
    /// rather than PATCH.
    pub async fn put_json<B: Serialize, T: DeserializeOwned>(
        &mut self,
        path: &str,
        body: &B,
    ) -> LocalResult<T> {
        self.send_json::<B, T>(reqwest::Method::PUT, path, Some(body)).await
    }

    /// Authenticated DELETE. Retries once after a 401 refresh. The cloud delete endpoints answer
    /// `204 No Content` (empty body), so this checks ONLY the status and discards any body — calling
    /// `send_json` here would fail trying to deserialize an empty body. Used by the workflow
    /// reflection control path (delete a cloud workflow / cancel a cloud run).
    pub async fn delete(&mut self, path: &str) -> LocalResult<()> {
        let url = self.url(path);
        let first = self.execute::<()>(reqwest::Method::DELETE, &url, None).await?;
        let resp = if first.status() == reqwest::StatusCode::UNAUTHORIZED {
            tracing::debug!("cloud 401 (DELETE) — attempting token refresh");
            self.refresh().await?;
            self.execute::<()>(reqwest::Method::DELETE, &url, None).await?
        } else {
            first
        };
        Self::check_status(resp).await
    }

    /// Core request flow: build → send with current access token → on 401, refresh once → retry once.
    async fn send_json<B: Serialize, T: DeserializeOwned>(
        &mut self,
        method: reqwest::Method,
        path: &str,
        body: Option<&B>,
    ) -> LocalResult<T> {
        let url = self.url(path);

        let first = self.execute(method.clone(), &url, body).await?;
        if first.status() != reqwest::StatusCode::UNAUTHORIZED {
            return Self::parse(first).await;
        }

        // 401 → attempt a single refresh, then retry once.
        tracing::debug!(%method, "cloud 401 — attempting token refresh");
        self.refresh().await?;
        let second = self.execute(method, &url, body).await?;
        Self::parse(second).await
    }

    /// Authenticated GET that opens a LONG-LIVED streaming response (Server-Sent Events). Unlike the
    /// JSON/bytes verbs, it overrides the client's short global request timeout with a long
    /// per-request one (`STREAM_REQUEST_TIMEOUT`) so a persistent stream isn't reaped mid-flight —
    /// the server's periodic keep-alive comments keep bytes flowing, and the caller reconnects when
    /// the stream ends. Retries ONCE after a 401 refresh at connect time; a mid-stream auth failure
    /// simply ends the stream, which the caller handles by reconnecting. The caller consumes
    /// `resp.bytes_stream()`; nothing is buffered here.
    pub async fn open_stream(&mut self, path: &str) -> LocalResult<reqwest::Response> {
        let url = self.url(path);
        let open = |c: &reqwest::Client, tok: &str| {
            c.get(&url)
                .bearer_auth(tok)
                .header(reqwest::header::ACCEPT, "text/event-stream")
                .timeout(STREAM_REQUEST_TIMEOUT)
                .send()
        };
        let first = open(&self.http, self.token.access())
            .await
            .map_err(|e| classify_send_err(e, "cloud stream open failed"))?;
        let resp = if first.status() == reqwest::StatusCode::UNAUTHORIZED {
            tracing::debug!("cloud 401 (open_stream) — attempting token refresh");
            self.refresh().await?;
            open(&self.http, self.token.access())
                .await
                .map_err(|e| classify_send_err(e, "cloud stream reopen failed"))?
        } else {
            first
        };
        let status = resp.status();
        if !status.is_success() {
            return Err(Self::status_error(status));
        }
        Ok(resp)
    }

    /// Build + send one request with the current Bearer token. Network errors fold into `Internal`.
    async fn execute<B: Serialize>(
        &self,
        method: reqwest::Method,
        url: &str,
        body: Option<&B>,
    ) -> LocalResult<reqwest::Response> {
        let mut req = self
            .http
            .request(method, url)
            .bearer_auth(self.token.access());
        if let Some(b) = body {
            req = req.json(b);
        }
        req.send()
            .await
            .map_err(|e| classify_send_err(e, "cloud request failed"))
    }

    /// Map a response into either the deserialized body or a typed [`LocalError`] by status.
    /// Error bodies are NOT surfaced verbatim (they may echo input); detail goes to `tracing`.
    async fn parse<T: DeserializeOwned>(resp: reqwest::Response) -> LocalResult<T> {
        let status = resp.status();
        if status.is_success() {
            // Capture diagnostics BEFORE consuming the body so a decode failure is
            // actionable (content-type / encoding / a short body snippet) instead of the
            // opaque "error decoding response body". reqwest has already transparently
            // gunzipped the body here (the `gzip` feature), so a leftover content-encoding
            // would itself be the smoking gun.
            let ctype = header_str(&resp, reqwest::header::CONTENT_TYPE);
            let cenc = header_str(&resp, reqwest::header::CONTENT_ENCODING);
            // The final URL (after any redirects) pins down WHICH cloud base was hit — the
            // host part is the diagnostic; the path carries no secret.
            let req_url = resp.url().as_str().to_string();
            let bytes = resp
                .bytes()
                .await
                .map_err(|e| LocalError::Internal(format!("cloud response read: {e}")))?;
            return serde_json::from_slice::<T>(&bytes).map_err(|e| {
                let snippet: String = String::from_utf8_lossy(&bytes).chars().take(160).collect();
                LocalError::Internal(format!(
                    "cloud response decode: {e} (url='{req_url}' content-type='{ctype}' content-encoding='{cenc}' len={} snippet={snippet:?})",
                    bytes.len()
                ))
            });
        }
        // Pull the body for logs (and, for 402, to surface the server's upgrade message).
        let detail = resp.text().await.unwrap_or_default();
        tracing::warn!(status = status.as_u16(), detail = %truncate_body(&detail), "cloud request returned error");
        // 402 = out of credit / over a plan limit on a metered call (e.g. AI auto-repair). Unlike
        // other errors, the body carries a USER-FACING "upgrade / add credit" message worth
        // surfacing (mirrors the keyless-tier `{detail:{message}}` shape), so extract it here.
        if status == reqwest::StatusCode::PAYMENT_REQUIRED {
            return Err(LocalError::PaymentRequired(extract_detail_message(&detail).unwrap_or_else(
                || "You're out of AI credit for this action. Upgrade your plan or add credit to keep using AI auto-repair.".into(),
            )));
        }
        Err(Self::status_error(status))
    }

    /// Map a non-success cloud status to a typed [`LocalError`]. Shared by [`Self::parse`] and
    /// [`Self::check_status`] so the JSON and no-body paths classify errors identically.
    fn status_error(status: reqwest::StatusCode) -> LocalError {
        match status {
            reqwest::StatusCode::UNAUTHORIZED => LocalError::Unauthorized,
            reqwest::StatusCode::NOT_FOUND => LocalError::NotFound("cloud resource".into()),
            reqwest::StatusCode::BAD_REQUEST => LocalError::BadRequest("cloud rejected the request".into()),
            reqwest::StatusCode::PAYMENT_REQUIRED => LocalError::PaymentRequired(
                "You're out of AI credit for this action. Upgrade your plan or add credit to continue.".into(),
            ),
            s => LocalError::Internal(format!("cloud request failed (HTTP {})", s.as_u16())),
        }
    }

    /// Validate a response that carries no meaningful body (e.g. a `204 No Content` from a DELETE):
    /// `Ok(())` on any 2xx, else the typed error. The body is read only for the warn log.
    async fn check_status(resp: reqwest::Response) -> LocalResult<()> {
        let status = resp.status();
        if status.is_success() {
            return Ok(());
        }
        let detail = resp.text().await.unwrap_or_default();
        tracing::warn!(status = status.as_u16(), detail = %truncate_body(&detail), "cloud request returned error");
        Err(Self::status_error(status))
    }

    /// Perform the OAuth `refresh_token` grant with the stored `wtr_` token, persist the rotated
    /// pair to the keyring, and update the in-memory token. On `invalid_grant` (refresh revoked /
    /// expired) the stored token is cleared and [`LocalError::Unauthorized`] is returned so callers
    /// can prompt a re-link.
    pub async fn refresh(&mut self) -> LocalResult<()> {
        // Serialize refreshes process-wide (CR-8): the `wtr_` refresh token is single-use and
        // server-rotated, so two concurrent refreshes would spend the SAME token — one wins, the loser
        // gets `invalid_grant` for a now-stale token.
        let _guard = REFRESH_LOCK.lock().await;

        // Having acquired the lock, re-read the keyring: a refresh that ran WHILE we blocked may have
        // already rotated the pair. If the stored refresh token differs from the one we were about to
        // spend, another caller succeeded — adopt the fresh pair and skip the grant entirely rather
        // than spend a token that is now stale.
        if let Ok(Some(current)) = token::get() {
            if current.refresh() != self.token.refresh() {
                tracing::debug!("cloud token already refreshed by a concurrent caller — adopting it");
                self.token = current;
                return Ok(());
            }
        }

        // The desktop links via the OAuth 2.0 Device Authorization Grant (RFC 8628) as a PUBLIC
        // client (`writ-agent`, no client_secret). Its refresh therefore goes to the dedicated PUBLIC
        // device-refresh endpoint, NOT the generic `/api/oauth/token` grant — that endpoint
        // authenticates a CONFIDENTIAL client and rejects the secret-less public client (422/401), so
        // refreshing there would silently fail and the linked session would die ~1h after linking,
        // the moment the `wto_` access token first expires. Matches `bridge/auth.rs::refresh_token()`
        // and the backend `device_refresh_token` handler (JSON `{refresh_token, client_id}`).
        let url = self.url("/api/oauth/device/refresh");
        let body = serde_json::json!({
            "refresh_token": self.token.refresh(),
            "client_id": OAUTH_CLIENT_ID,
        });
        let resp = self
            .http
            .post(&url)
            .json(&body)
            .send()
            .await
            .map_err(|e| classify_send_err(e, "cloud refresh request failed"))?;

        let status = resp.status();
        if status.is_success() {
            let parsed: RefreshResponse = resp
                .json()
                .await
                .map_err(|e| LocalError::Internal(format!("cloud refresh decode: {e}")))?;
            let expires_at = parsed
                .expires_in
                .filter(|s| *s > 0)
                .map(|s| chrono::Utc::now() + chrono::Duration::seconds(s as i64));
            // The server rotates the refresh token; keep the old one only if none was returned.
            let new_refresh = parsed.refresh_token.unwrap_or_else(|| self.token.refresh().to_string());
            let pair = TokenPair::new(parsed.access_token, new_refresh, expires_at);
            token::set(&pair)?;
            self.token = pair;
            tracing::debug!("cloud token refreshed");
            return Ok(());
        }

        // 400 invalid_grant / 401 => refresh token revoked or expired.
        if status == reqwest::StatusCode::BAD_REQUEST || status == reqwest::StatusCode::UNAUTHORIZED {
            // Before clearing, RE-READ the keyring one more time: we may have lost a refresh race whose
            // winner persisted a fresh pair AFTER our re-read above but before our grant returned. If
            // the stored token now differs from the one we spent, the "rejection" is only because our
            // copy is stale — adopt the winner's pair instead of clearing (which would force-unlink both
            // callers at expiry). Only a genuinely revoked/unknown token (stored pair unchanged) clears.
            if let Ok(Some(current)) = token::get() {
                if current.refresh() != self.token.refresh() {
                    tracing::debug!(
                        "cloud refresh rejected but keyring was rotated concurrently — adopting the fresh pair"
                    );
                    self.token = current;
                    return Ok(());
                }
            }
            // Clearing the token forces a full re-link, so demand PROOF the rejection came from OUR
            // token endpoint: the backend answers a dead refresh token with `invalid_grant` (and a
            // bad client with `invalid_client`). A 401/400 that carries neither is far more likely to
            // be an interposer — a captive portal, a corporate proxy, an SSO/WAF front door, a
            // misrouted request — and discarding a valid 10-year refresh token on that evidence
            // signs the user out of a perfectly good session with no way back but re-linking.
            // Anything unrecognised is treated as transient: keep the token and fail this call.
            let detail = resp.text().await.unwrap_or_default();
            if !is_invalid_grant(&detail) {
                tracing::warn!(
                    status = status.as_u16(),
                    detail = %truncate_body(&detail),
                    "cloud refresh rejected WITHOUT an OAuth error — treating as transient, token kept"
                );
                return Err(LocalError::Internal(format!(
                    "cloud refresh failed (HTTP {})",
                    status.as_u16()
                )));
            }
            let _ = token::clear();
            tracing::warn!(status = status.as_u16(), "cloud refresh rejected — token cleared, re-link required");
            return Err(LocalError::Unauthorized);
        }
        // 5xx etc. — transient; don't discard the token.
        Err(LocalError::Internal(format!("cloud refresh failed (HTTP {})", status.as_u16())))
    }
}

/// Subset of the OAuth token-endpoint response we consume on refresh.
#[derive(serde::Deserialize)]
struct RefreshResponse {
    access_token: String,
    #[serde(default)]
    refresh_token: Option<String>,
    #[serde(default)]
    expires_in: Option<u64>,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dummy_token() -> TokenPair {
        TokenPair::new("wto_a".into(), "wtr_b".into(), None)
    }

    #[test]
    fn only_a_real_oauth_rejection_may_discard_the_token() {
        // What the backend actually returns for a dead refresh token (FastAPI `detail` shape).
        assert!(is_invalid_grant(r#"{"detail":"invalid_grant: refresh token not found or revoked"}"#));
        assert!(is_invalid_grant(r#"{"detail":"invalid_client"}"#));
        // RFC 6749 spelling, and case-insensitively.
        assert!(is_invalid_grant(r#"{"error":"invalid_grant"}"#));
        assert!(is_invalid_grant(r#"{"error":"INVALID_GRANT"}"#));

        // Interposers: a captive portal, a proxy, an SSO front door, an empty body. None of these
        // is evidence the refresh token is dead — clearing on them would sign the user out for good.
        assert!(!is_invalid_grant("<html><body>Sign in to the network</body></html>"));
        assert!(!is_invalid_grant(r#"{"message":"Unauthorized"}"#));
        assert!(!is_invalid_grant("Access denied by corporate proxy"));
        assert!(!is_invalid_grant(""));
    }

    #[test]
    fn base_url_precedence_env_over_link_over_default() {
        // Snapshot + clear env so the test is deterministic regardless of CI environment.
        let prev = std::env::var(ENV_CLOUD_URL).ok();
        std::env::remove_var(ENV_CLOUD_URL);

        // No env, no link → default.
        assert_eq!(CloudClient::resolve_base_url(None), DEFAULT_CLOUD_BASE_URL);

        // Link (trailing slash trimmed by LinkState::base_url) wins over default.
        let link = LinkState {
            cloud_base_url: "https://cloud.example.com/".into(),
            ..LinkState::default()
        };
        assert_eq!(CloudClient::resolve_base_url(Some(&link)), "https://cloud.example.com");

        // Env wins over everything.
        std::env::set_var(ENV_CLOUD_URL, "https://env.example.com/");
        assert_eq!(CloudClient::resolve_base_url(Some(&link)), "https://env.example.com");
        assert_eq!(CloudClient::resolve_base_url(None), "https://env.example.com");

        // An empty/whitespace env value is ignored (falls through to link/default).
        std::env::set_var(ENV_CLOUD_URL, "   ");
        assert_eq!(CloudClient::resolve_base_url(Some(&link)), "https://cloud.example.com");

        // Restore.
        match prev {
            Some(v) => std::env::set_var(ENV_CLOUD_URL, v),
            None => std::env::remove_var(ENV_CLOUD_URL),
        }
    }

    #[test]
    fn url_join_handles_slashes() {
        let c = CloudClient::with_token("https://api.usewrit.app/", dummy_token()).unwrap();
        assert_eq!(c.base_url(), "https://api.usewrit.app", "trailing slash trimmed");
        assert_eq!(c.url("/api/v1/me"), "https://api.usewrit.app/api/v1/me");
        assert_eq!(c.url("api/v1/me"), "https://api.usewrit.app/api/v1/me");
    }

    #[test]
    fn secure_cloud_url_gate() {
        std::env::remove_var("WRIT_ALLOW_INSECURE_CLOUD");
        // https and loopback (dev) are allowed.
        assert!(require_secure_cloud_url("https://api.usewrit.app").is_ok());
        assert!(require_secure_cloud_url("http://127.0.0.1:8080").is_ok());
        assert!(require_secure_cloud_url("http://localhost:9000/path").is_ok());
        assert!(require_secure_cloud_url("http://[::1]:9000").is_ok());
        // A plaintext REMOTE base is refused (would leak the device code + wto_/wtr_ tokens).
        assert!(require_secure_cloud_url("http://api.usewrit.app").is_err());
        assert!(require_secure_cloud_url("http://evil.example.com/api").is_err());
        // with_token rejects an insecure remote base too.
        assert!(CloudClient::with_token("http://api.usewrit.app", dummy_token()).is_err());
    }

    #[test]
    fn connect_without_token_is_unauthorized_not_panic() {
        // No token is set in the (test) keyring under writ-cloud/account for this throwaway service,
        // so connect() must surface Unauthorized. If a real keyring entry exists on the dev machine
        // this would instead succeed — guard on either outcome, never a panic.
        match CloudClient::connect(None) {
            Ok(_) => { /* a token happened to be present on this machine */ }
            Err(LocalError::Unauthorized) => { /* expected: not linked */ }
            // No default keychain in this session (headless / CI / a parallel `cargo test`
            // run): connect() could not consult the keyring at all. That is an ENVIRONMENT
            // outcome, not a product failure — and this test's contract is only that
            // connect() never PANICS, which still holds.
            Err(LocalError::Internal(msg)) if msg.contains("keyring") => {}
            Err(other) => panic!("unexpected error from connect(): {other:?}"),
        }
    }

    // Network-touching refresh/get/post paths require a live backend.
    #[tokio::test]
    #[ignore = "network: requires a live Writ Cloud backend + a valid refresh token"]
    async fn refresh_against_live_backend() {
        let mut c = CloudClient::connect(None).expect("a linked token");
        c.refresh().await.expect("refresh should succeed against live backend");
    }
}
