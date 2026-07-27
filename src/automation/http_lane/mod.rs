//! Browserless HTTP execution lane.
//!
//! Runs api_call / login_post workflows with a plain HTTP client + a serializable cookie jar instead
//! of launching Chromium. Shares the request step config, placeholder grammar, response-extraction
//! and SSRF policy with the browser lane, and round-trips `SessionState` so a session captured either
//! way restores into the other. When the lane can't faithfully run a workflow (a challenge page, a
//! login loop, a non-HTTP-representable auth) it returns a [`FallbackReason`] and the caller re-runs
//! the workflow in the browser — the always-safe default.

pub mod eligibility;
pub mod jar;
pub mod ladder;
pub mod recipe;
pub mod steps;

#[cfg(test)]
mod tests;

pub use eligibility::{http_lane_eligible, HttpEligibility};

use std::collections::HashMap;
use std::time::Duration;

use url::Url;

use crate::models::session::SessionState;
use jar::CookieJar;

/// Why the HTTP lane gave up and the caller should try the browser. Every variant means "the browser
/// might still succeed" — a truly fatal problem (SSRF-blocked URL, corrupt config) is [`HttpLaneError::Fatal`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FallbackReason {
    /// The response looked like an anti-bot / challenge interstitial (Cloudflare, "Just a moment", …).
    ChallengePage,
    /// A step that expected JSON got an HTML document — likely a login redirect or a soft block.
    HtmlNotJson,
    /// Re-login ran but the site still redirected to the login page (a loop we won't spin on).
    LoginLoop,
    /// The endpoint rejected our credentials/session (401/403 after the cookie-only retry).
    AuthFailed,
    /// A connection/TLS error — the browser's network stack (proxy PAC, HTTP/2, TLS fp) may differ.
    Network,
    /// The workflow/recipe uses something this lane can't represent yet.
    Unsupported,
}

impl FallbackReason {
    pub fn as_str(&self) -> &'static str {
        match self {
            FallbackReason::ChallengePage => "challenge_page",
            FallbackReason::HtmlNotJson => "html_not_json",
            FallbackReason::LoginLoop => "login_loop",
            FallbackReason::AuthFailed => "auth_failed",
            FallbackReason::Network => "network",
            FallbackReason::Unsupported => "unsupported",
        }
    }
}

/// How a park (unattended-2FA) should be reported by the caller.
#[derive(Debug, Clone)]
pub enum ParkKind {
    /// Needs an emailed/SMS code that this surface cannot read.
    Twofa(String),
    /// Needs a code only the user can supply (push approval, authenticator the run can't reach).
    Attention(String),
}

#[derive(Debug)]
#[allow(dead_code)]
pub enum HttpLaneError {
    /// The browser might work — fall back within the same run.
    Fallback(FallbackReason),
    /// The browser won't help (SSRF-blocked URL, corrupt step config). Terminal failure.
    Fatal(String),
    /// The run can't proceed unattended and must surface a typed "needs a code" state.
    Parked(ParkKind),
}

impl std::fmt::Display for HttpLaneError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            HttpLaneError::Fallback(r) => write!(f, "http lane fallback: {}", r.as_str()),
            HttpLaneError::Fatal(m) => write!(f, "http lane fatal: {m}"),
            HttpLaneError::Parked(_) => write!(f, "http lane parked (needs a one-time code)"),
        }
    }
}

/// Proxy egress for the HTTP lane, mapped field-for-field from the persona's `ProxySettings`.
#[derive(Debug, Clone)]
pub struct HttpProxyConfig {
    pub server: String,
    pub username: Option<String>,
    pub password: Option<String>,
    pub bypass: Option<String>,
}

/// Construction inputs for an [`HttpLaneExecutor`].
pub struct HttpLaneOptions<'a> {
    /// Persona / SessionState fingerprint — supplies the UA + Accept-Language so requests carry the
    /// same identity the session was minted under.
    pub fingerprint: Option<serde_json::Value>,
    pub proxy: Option<HttpProxyConfig>,
    /// A persisted session to seed cookies / headers / tokens from.
    pub session: Option<&'a SessionState>,
    pub entry_url: Option<&'a str>,
    /// Per-request timeout (from the workflow's `timeout_ms`).
    pub timeout: Duration,
}

/// The outcome of a single HTTP request through the lane.
#[derive(Debug, Clone)]
pub struct HttpResponse {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: String,
    /// Parsed JSON when the body parses; `None` otherwise.
    pub json: Option<serde_json::Value>,
    pub final_url: Url,
    /// Every `Location` target followed (for redirect_param extraction + stale detection).
    pub redirect_chain: Vec<Url>,
    pub elapsed_ms: u64,
}

const MAX_REDIRECTS: usize = 10;
const DEFAULT_UA: &str =
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36";

/// Auth-class request headers stripped when a redirect crosses to a different registrable domain.
fn is_auth_header(name: &str) -> bool {
    matches!(
        name.to_ascii_lowercase().as_str(),
        "authorization" | "cookie" | "x-api-key" | "x-auth-token" | "api-key"
    )
}

/// Naive registrable domain = last two labels. Used only to decide whether a redirect is "cross-site"
/// for the purpose of stripping auth headers; over-stripping is safe, so the imprecision on multi-part
/// TLDs (`co.uk`) only ever errs toward dropping an auth header, never leaking one.
fn registrable_domain(host: &str) -> String {
    let labels: Vec<&str> = host.split('.').collect();
    if labels.len() <= 2 {
        host.to_string()
    } else {
        labels[labels.len() - 2..].join(".")
    }
}

pub struct HttpLaneExecutor {
    client: reqwest::Client,
    jar: CookieJar,
    /// Headers replayed on every request (seeded from `SessionState.headers`; the recipe token store
    /// folds `store:"header"` tokens in here scoped to the entry registrable domain).
    sticky_headers: HashMap<String, String>,
    entry_registrable: Option<String>,
    seeded_state: Option<SessionState>,
    /// AuthRecipe token store to persist with the session (exported into `SessionState.tokens`).
    token_store: Option<serde_json::Value>,
    #[cfg(test)]
    pub(crate) skip_url_vetting: bool,
}

impl HttpLaneExecutor {
    pub fn new(opts: HttpLaneOptions<'_>) -> Result<Self, HttpLaneError> {
        let (ua, accept_language) = fingerprint_headers(opts.fingerprint.as_ref());

        let mut builder = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .timeout(opts.timeout)
            // reqwest's default connect timeout is None: a black-holing host would hold this lane for
            // the full per-request budget on the handshake alone.
            .connect_timeout(Duration::from_secs(10))
            // SSRF: vet the address reqwest actually DIALS. This lane already re-vets every redirect
            // hop by URL (see `request`), which closes the redirect-pivot hole — but not the
            // guard-then-connect race: `vet_url` resolves the hostname, then reqwest resolves it AGAIN
            // at connect time, so a short-TTL rebind between the two reached loopback / RFC1918 /
            // metadata anyway. The resolver filters every candidate address, and yields an empty set
            // (fail-closed connect) when a name resolves only to blocked addresses. TLS is unaffected
            // — SNI and certificate verification still use the original hostname.
            .dns_resolver(crate::security::vetting_resolver::shared())
            .user_agent(ua);

        // Default Accept-Language from the fingerprint locale (parity with the monitor checker).
        let mut default_headers = reqwest::header::HeaderMap::new();
        if let Ok(v) = reqwest::header::HeaderValue::from_str(&accept_language) {
            default_headers.insert(reqwest::header::ACCEPT_LANGUAGE, v);
        }
        builder = builder.default_headers(default_headers);

        if let Some(p) = &opts.proxy {
            let server = normalize_proxy_url(&p.server);
            let mut proxy = reqwest::Proxy::all(&server)
                .map_err(|e| HttpLaneError::Fatal(format!("bad proxy '{server}': {e}")))?;
            if let (Some(u), Some(pw)) = (p.username.as_ref(), p.password.as_ref()) {
                proxy = proxy.basic_auth(u, pw);
            }
            if let Some(b) = &p.bypass {
                proxy = proxy.no_proxy(reqwest::NoProxy::from_string(b));
            }
            builder = builder.proxy(proxy);
        }

        let client = builder
            .build()
            .map_err(|e| HttpLaneError::Fatal(format!("http client build failed: {e}")))?;

        let mut jar = CookieJar::new();
        let mut sticky_headers = HashMap::new();
        if let Some(s) = opts.session {
            jar = CookieJar::from_session_cookies(&s.cookies);
            for (k, v) in &s.headers {
                sticky_headers.insert(k.clone(), v.clone());
            }
        }

        let entry_registrable = opts
            .entry_url
            .and_then(|u| Url::parse(u).ok())
            .and_then(|u| u.host_str().map(registrable_domain));

        Ok(Self {
            client,
            jar,
            sticky_headers,
            entry_registrable,
            seeded_state: opts.session.cloned(),
            token_store: opts.session.and_then(|s| s.tokens.clone()),
            #[cfg(test)]
            skip_url_vetting: false,
        })
    }

    /// Record the AuthRecipe token store so it is persisted with the exported session.
    pub fn merge_tokens(&mut self, tokens: serde_json::Value) {
        self.token_store = Some(tokens);
    }

    /// Whether the jar currently carries any cookie (used to decide lazy-login skipping).
    pub fn has_session(&self) -> bool {
        !self.jar.is_empty() || !self.sticky_headers.is_empty()
    }

    pub fn jar_mut(&mut self) -> &mut CookieJar {
        &mut self.jar
    }

    /// The value of a cookie by name currently in the jar (AuthRecipe `from: "cookie"`).
    pub fn cookie_value(&self, name: &str) -> Option<String> {
        self.jar.value_of(name)
    }

    /// The entry registrable domain (for scoping recipe token-store headers), if known.
    pub fn entry_registrable(&self) -> Option<&str> {
        self.entry_registrable.as_deref()
    }

    /// Fold a header into the sticky set (recipe token store, `store:"header"`).
    pub fn set_sticky_header(&mut self, name: &str, value: String) {
        self.sticky_headers.insert(name.to_string(), value);
    }

    /// Seed the token-store headers from a persisted `SessionState.tokens` blob so a warm run replays
    /// bearer/api-key tokens. Only `store: header` tokens become sticky headers here.
    pub fn seed_tokens(&mut self, tokens: &serde_json::Value) {
        if let Some(map) = tokens.as_object() {
            for entry in map.values() {
                let (Some(header), Some(value)) = (
                    entry.get("header").and_then(|v| v.as_str()),
                    entry.get("value").and_then(|v| v.as_str()),
                ) else {
                    continue;
                };
                let prefix = entry.get("prefix").and_then(|v| v.as_str()).unwrap_or("");
                self.sticky_headers.insert(header.to_string(), format!("{prefix}{value}"));
            }
        }
    }

    async fn vet_url(&self, url: &str) -> bool {
        #[cfg(test)]
        if self.skip_url_vetting {
            return true;
        }
        crate::security::url_guard::is_navigation_url_safe_async(url).await
    }

    /// Execute one request, following redirects manually (≤10 hops) with per-hop SSRF re-vet, cookie
    /// jar attach + Set-Cookie capture, and cross-registrable-domain auth-header stripping.
    pub async fn request(
        &mut self,
        method: &str,
        url: &str,
        headers: &[(String, String)],
        body: Option<String>,
    ) -> Result<HttpResponse, HttpLaneError> {
        let start = std::time::Instant::now();
        let mut cur_url = Url::parse(url)
            .map_err(|e| HttpLaneError::Fatal(format!("bad api_call URL '{url}': {e}")))?;
        let mut cur_method = method.to_uppercase();
        let mut cur_body = body;
        let mut redirect_chain: Vec<Url> = Vec::new();
        let origin_registrable = cur_url.host_str().map(registrable_domain);

        for _hop in 0..=MAX_REDIRECTS {
            if !self.vet_url(cur_url.as_str()).await {
                return Err(HttpLaneError::Fatal(format!(
                    "api_call URL blocked by SSRF guard: {cur_url}"
                )));
            }

            let cross_site = cur_url.host_str().map(registrable_domain) != origin_registrable;
            let m = reqwest::Method::from_bytes(cur_method.as_bytes())
                .map_err(|e| HttpLaneError::Fatal(format!("bad method '{cur_method}': {e}")))?;
            let mut req = self.client.request(m, cur_url.clone());

            // Sticky headers (session + token store), then per-request headers (override), dropping
            // auth-class headers when we've crossed to a different registrable domain.
            for (k, v) in self.sticky_headers.iter().chain(headers.iter().map(|(a, b)| (a, b))) {
                if cross_site && is_auth_header(k) {
                    continue;
                }
                req = req.header(k, v);
            }
            if let Some(cookie) = self.jar.cookie_header_for(&cur_url, now_epoch()) {
                if !(cross_site) {
                    req = req.header(reqwest::header::COOKIE, cookie);
                }
            }
            let allows_body = cur_method != "GET" && cur_method != "HEAD";
            if allows_body {
                if let Some(b) = &cur_body {
                    req = req.body(b.clone());
                }
            }

            let resp = match req.send().await {
                Ok(r) => r,
                Err(e) => {
                    if e.is_timeout() {
                        return Err(HttpLaneError::Fallback(FallbackReason::Network));
                    }
                    return Err(HttpLaneError::Fallback(FallbackReason::Network));
                }
            };

            let status = resp.status().as_u16();
            // Capture every Set-Cookie on this hop (including on 3xx).
            for hv in resp.headers().get_all(reqwest::header::SET_COOKIE).iter() {
                if let Ok(s) = hv.to_str() {
                    self.jar.store_set_cookie(&cur_url, s);
                }
            }

            // Redirect handling (manual): 301/302/303 → GET + drop body; 307/308 keep method+body.
            if (300..400).contains(&status) {
                if let Some(loc) = resp
                    .headers()
                    .get(reqwest::header::LOCATION)
                    .and_then(|v| v.to_str().ok())
                {
                    let next = cur_url.join(loc).map_err(|e| {
                        HttpLaneError::Fatal(format!("bad redirect Location '{loc}': {e}"))
                    })?;
                    redirect_chain.push(next.clone());
                    if matches!(status, 301..=303) {
                        cur_method = "GET".to_string();
                        cur_body = None;
                    }
                    cur_url = next;
                    continue;
                }
            }

            // Terminal response.
            let resp_headers: Vec<(String, String)> = resp
                .headers()
                .iter()
                .map(|(k, v)| (k.as_str().to_string(), v.to_str().unwrap_or("").to_string()))
                .collect();
            let final_url = cur_url.clone();
            // BOUNDED body read (see `crawl_shard::body_limit`). reqwest transparently gunzips, so an
            // uncapped `text()` let a hostile endpoint inflate ~1 MB on the wire into ~1 GB resident.
            // An over-budget body is a lane FALLBACK, not a fatal error: the browser lane may still be
            // able to run this workflow.
            let body_text = match crate::crawl_shard::body_limit::read_text_capped(
                resp,
                crate::crawl_shard::body_limit::API_RESPONSE_MAX,
            )
            .await
            {
                Ok(t) => t,
                Err(e) => {
                    tracing::warn!(url = %final_url, error = %e, "http lane response body rejected");
                    return Err(HttpLaneError::Fallback(FallbackReason::Network));
                }
            };
            let json = serde_json::from_str::<serde_json::Value>(&body_text).ok();

            return Ok(HttpResponse {
                status,
                headers: resp_headers,
                body: body_text,
                json,
                final_url,
                redirect_chain,
                elapsed_ms: start.elapsed().as_millis() as u64,
            });
        }

        Err(HttpLaneError::Fallback(FallbackReason::LoginLoop))
    }

    /// Snapshot the current session as a `SessionState`, preserving the seeded localStorage /
    /// sessionStorage / fingerprint (an HTTP run doesn't touch those) and refreshing cookies + headers.
    pub fn export_session_state(&self) -> SessionState {
        let mut state = self.seeded_state.clone().unwrap_or_else(|| SessionState {
            cookies: Vec::new(),
            headers: HashMap::new(),
            local_storage: HashMap::new(),
            session_storage: HashMap::new(),
            extracted_at: None,
            fingerprint: None,
            tokens: None,
        });
        state.cookies = self.jar.to_session_cookies();
        for (k, v) in &self.sticky_headers {
            state.headers.insert(k.clone(), v.clone());
        }
        if let Some(tokens) = &self.token_store {
            state.tokens = Some(tokens.clone());
        }
        state.extracted_at = Some(chrono::Utc::now().to_rfc3339());
        state
    }
}

/// Extract (User-Agent, Accept-Language) from a stored fingerprint JSON, falling back to a Chrome UA.
fn fingerprint_headers(fp: Option<&serde_json::Value>) -> (String, String) {
    let ua = fp
        .and_then(|f| f.get("user_agent").and_then(|v| v.as_str()))
        .unwrap_or(DEFAULT_UA)
        .to_string();
    let locale = fp
        .and_then(|f| f.get("locale").and_then(|v| v.as_str()))
        .unwrap_or("en-US");
    // "en-US" -> "en-US,en;q=0.9" (checker parity).
    let base = locale.split(['-', '_']).next().unwrap_or("en");
    let accept_language = format!("{locale},{base};q=0.9");
    (ua, accept_language)
}

/// reqwest::Proxy needs a scheme; a bare "host:port" becomes "http://host:port".
fn normalize_proxy_url(server: &str) -> String {
    if server.contains("://") {
        server.to_string()
    } else {
        format!("http://{server}")
    }
}

fn now_epoch() -> f64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs_f64())
        .unwrap_or(0.0)
}
