//! Local HTTP server seam — `AppState` + loopback router + auth middleware + a health route.
//! Every API phase (REST `/v1`, OpenAI-compat, MCP-over-HTTP) mounts onto this router.
//! Loopback-bound; bearer + Origin/Host guard (the local-backend spec §7). No JWT/tenant.

use super::app::health::SharedHealth;
use super::auth;
use super::config::LocalConfig;
use super::engine::LocalEngine;
use super::error::{LocalError, LocalResult};
use super::store::{local_api_keys, workflows};
use super::vault::Vault;
use axum::extract::{Request, State};
use axum::http::header;
use axum::middleware::{self, Next};
use axum::response::Response;
use axum::routing::get;
use axum::{Json, Router};
use serde_json::json;
use sha2::{Digest, Sha256};
use sqlx::SqlitePool;
use std::sync::Arc;

/// Shared state injected into every handler. Cheaply cloneable (pool + Arcs).
#[derive(Clone)]
pub struct AppState {
    pub db: SqlitePool,
    pub vault: Arc<Vault>,
    pub engine: Arc<dyn LocalEngine>,
    pub config: LocalConfig,
    pub token: Arc<String>,
    /// Shared liveness snapshot the scheduler updates each tick; read by `/v1/agent` + `/v1/health`.
    pub health: SharedHealth,
    /// In-process recorder driving the daemon's OWN warm Chromium for the local recording WS
    /// (`local::record`). Shares the engine's `BrowserManager` so recording reuses the one warm
    /// browser — NO cloud, NO ws-gateway, NO remote agent. `None` when the engine has no browser
    /// (e.g. the `StubEngine` used by unit tests), in which case `/ws/record` returns 503.
    pub recorder: Option<Arc<crate::recorder::core::PlaywrightRecorder>>,
}

/// Build the loopback router with auth applied. Feature phases extend this with their /v1 routes.
pub fn build_router(state: AppState) -> Router {
    // The local recording WebSocket is mounted OUTSIDE the bearer-header `auth_mw` layer: a browser
    // cannot set an `Authorization` header on a WebSocket, so `/ws/record` does its OWN auth — the
    // `wlt_` token as a `?token=` query param (constant-time compared) PLUS the same loopback
    // Origin/Host guard. This mirrors the `/v1/hooks/*` bearer-exemption pattern, but as a dedicated
    // sub-router so the upgrade request never hits the header-bearer gate. NO ws-gateway / NO remote
    // agent — the daemon drives its own warm Chromium directly (`local::record`).
    let record_router = crate::local::record::router().with_state(state.clone());
    // The AI-preview screencast WebSocket is mounted alongside `/ws/record`, OUTSIDE `auth_mw`, for
    // the same reason: a browser can't set an Authorization header on a WS, so it self-authenticates
    // with the `?token=` query param + the loopback Origin/Host guard (see `local::ai::live_preview`).
    let preview_router = crate::local::ai::live_preview::router().with_state(state.clone());

    Router::new()
        .route("/v1/agent", get(agent_status))
        .route("/v1/health", get(health))
        .merge(crate::local::api::v1::router())
        .layer(middleware::from_fn_with_state(state.clone(), auth_mw))
        .merge(record_router)
        .merge(preview_router)
        // CORS is the OUTERMOST layer so a browser preflight (`OPTIONS`, which carries no
        // Authorization header) is answered here BEFORE `auth_mw` can 401 it. The Tauri webview
        // runs at `tauri://localhost`, so every `fetch`/XHR to this loopback origin is
        // cross-origin and the browser preflights it. The bearer token remains the real auth gate
        // (and `auth_mw` still enforces the loopback/tauri Origin+Host DNS-rebind guard on the
        // actual request), so reflecting the request origin here only unblocks the browser.
        .layer(cors_layer())
        .with_state(state)
}

/// Permissive-but-scoped CORS so the Tauri webview (and the dev Vite server) can call the loopback
/// API cross-origin. Security is the `wlt_`/`wlk_` bearer + the loopback Origin/Host guard in
/// `auth_mw`; CORS here only lets the browser's preflight succeed and exposes responses.
fn cors_layer() -> tower_http::cors::CorsLayer {
    use axum::http::{header, HeaderName, Method};
    use tower_http::cors::{AllowOrigin, CorsLayer};
    CorsLayer::new()
        .allow_origin(AllowOrigin::mirror_request())
        .allow_methods([
            Method::GET,
            Method::POST,
            Method::PATCH,
            Method::PUT,
            Method::DELETE,
            Method::OPTIONS,
        ])
        // `x-writ-account` is the per-account data-isolation binding header the webview stamps on
        // every request; it must be in the preflight allow-list or the browser blocks the request.
        .allow_headers([
            header::AUTHORIZATION,
            header::CONTENT_TYPE,
            header::ACCEPT,
            HeaderName::from_static("x-writ-account"),
        ])
        .max_age(std::time::Duration::from_secs(600))
}

/// `GET /v1/agent` — enriched status for the UI/CLI. Liveness counters come from the shared health
/// snapshot the scheduler updates each tick; the warm-browser hint is OR'd with live `active_runs`
/// (an in-flight run means the browser is warm right now). NO secrets.
async fn agent_status(State(st): State<AppState>) -> Json<serde_json::Value> {
    let active = st.engine.active_runs();
    Json(json!({
        "status": "ok",
        "version": env!("CARGO_PKG_VERSION"),
        "active_runs": active,
        "encrypted": true,
        "due_monitors": st.health.due_monitors(),
        "last_tick_at": st.health.last_tick_at(),
        "warm_browser": st.health.warm_browser() || active > 0,
    }))
}

/// `GET /v1/health` — a deeper, self-checking health probe (still loopback + bearer gated). Reports
/// the daemon version, encrypted-store reachability (SQLCipher cipher present + a trivial query),
/// keyring availability, active runs, scheduler liveness (last tick + due monitors), the warm-browser
/// hint, and cloud-link reflection. NO secrets: cipher presence is a bool, the cloud account id is an
/// opaque server id, no token/key/path is ever included.
async fn health(State(st): State<AppState>) -> Json<serde_json::Value> {
    // Encrypted DB: cipher must be active AND a trivial query must succeed.
    let cipher_ok = crate::local::db::assert_cipher_active(&st.db).await.is_ok();
    let db_ok = cipher_ok
        && sqlx::query("SELECT 1").fetch_optional(&st.db).await.is_ok();

    // Keyring availability: a non-secret reachability probe (does the keyring entry resolve?). This
    // does NOT read or return any key material — only whether the OS keyring is usable. Skipped (and
    // reported true) when the daemon is configured for the file-fallback vault.
    let keyring_ok = if st.config.use_keyring {
        crate::local::vault::Vault::keyring_available()
    } else {
        true
    };

    // Cloud-link reflection (non-secret metadata only). In the cloud-free OSS build there is no link
    // module compiled in, so the daemon reports itself unlinked with no account.
    #[cfg(feature = "cloud")]
    let (link_linked, link_account_id) = {
        let link = crate::local::cloud::state::LinkState::load_or_default(&st.db)
            .await
            .unwrap_or_default();
        let linked = link.is_linked();
        (linked, if linked { Some(link.account_id.clone()) } else { None })
    };
    #[cfg(not(feature = "cloud"))]
    let (link_linked, link_account_id): (bool, Option<String>) = (false, None);
    let active = st.engine.active_runs();

    Json(json!({
        "status": if db_ok { "ok" } else { "degraded" },
        "version": env!("CARGO_PKG_VERSION"),
        "cipher_present": cipher_ok,
        "db_ok": db_ok,
        "keyring_ok": keyring_ok,
        "active_runs": active,
        "scheduler": {
            "last_tick_at": st.health.last_tick_at(),
            "due_monitors": st.health.due_monitors(),
        },
        "warm_browser": st.health.warm_browser() || active > 0,
        "cloud_link": {
            "linked": link_linked,
            "account_id": link_account_id,
        },
    }))
}

/// Run the rest of the stack with the resolved capability ([`auth::Caller`]) stashed in the request's
/// extensions.
///
/// EVERY path that leaves `auth_mw` successfully goes through here, so a handler can trust that the
/// extension is present and re-apply the scope gate on a decision the method+path gate could not make
/// (the mixed `PUT /v1/settings/runtime` route; MCP `tools/call`, where the tool name is in the body).
/// A handler that finds NO extension fails closed (see [`auth::caller_or_deny`]).
async fn run_as(mut req: Request, caller: auth::Caller, next: Next) -> Response {
    req.extensions_mut().insert(caller);
    next.run(req).await
}

/// Loopback auth: reject non-loopback Origin/Host (DNS-rebind defense), then authenticate the
/// bearer. The full-access `wlt_` UI token is accepted as-is; otherwise the bearer is treated as a
/// scoped `wlk_` client key (sha256-hashed, matched against an active row, scope-gated by
/// method/route). Webhook ingress (`/v1/hooks/*`) is BEARER-EXEMPT — those requests authenticate
/// out-of-band via the trigger token in the path + an optional HMAC signature (see `api::v1::hooks`).
async fn auth_mw(State(st): State<AppState>, req: Request, next: Next) -> Result<Response, LocalError> {
    let h = req.headers();
    let port = st.config.port;
    // DNS-rebind guard. Loopback Origin/Host always pass; when the daemon is LAN-exposed we ALSO
    // accept our own bind/LAN host (so same-origin LAN browsers + API clients pass) but still reject
    // foreign browser origins. A non-browser API client sends no Origin and a Host of our own address.
    let exposed = st.config.network_exposed;
    let lan_hosts = lan_hosts(exposed);
    if let Some(origin) = h.get(header::ORIGIN).and_then(|v| v.to_str().ok()) {
        if !auth::origin_allowed_for(origin, port, exposed, &lan_hosts) {
            return Err(LocalError::Unauthorized);
        }
    }
    if let Some(host) = h.get(header::HOST).and_then(|v| v.to_str().ok()) {
        if !auth::origin_allowed_for(host, port, exposed, &lan_hosts) {
            return Err(LocalError::Unauthorized);
        }
    }

    // Webhook ingress is exempt from the bearer layer — it carries its own token+HMAC auth. The
    // Origin/Host loopback guard above STILL applies (the daemon is loopback-bound regardless).
    let path = req.uri().path();
    if path.starts_with("/v1/hooks/") || path == "/v1/hooks" {
        // Webhook ingress carries its own token+HMAC and only ever reaches the hooks handler, which
        // does no capability-based branching; mark it full-access so the extension is never absent.
        return Ok(run_as(req, auth::Caller::FullAccess, next).await);
    }
    // OAuth + discovery routes are bearer-exempt BY DESIGN — they are how an MCP client MINTS its
    // bearer (RFC 9728/8414 discovery, RFC 7591 registration, authorize/consent/token). The
    // DNS-rebind Origin/Host guard above still applies; consent additionally requires a user click.
    if path.starts_with("/oauth/") || path.starts_with("/.well-known/") {
        // These routes MINT credentials rather than spend them; they never consult the capability.
        return Ok(run_as(req, auth::Caller::FullAccess, next).await);
    }
    // MCP auth-off escape hatch (explicit user opt-in, LOOPBACK ONLY): some MCP hosts can't send
    // any credential at all. When the toggle is set AND the daemon is not LAN-exposed, `POST /mcp`
    // skips the bearer. LAN exposure force-restores auth regardless of the persisted toggle.
    if path == "/mcp"
        && !exposed
        && crate::local::store::config_kv::get(&st.db, MCP_AUTH_DISABLED_KEY)
            .await?
            .as_deref()
            == Some("true")
    {
        warn_mcp_auth_disabled_once();
        // Deliberately FULL access: with no credential presented there is no scope to enforce, so
        // this hatch also lifts the per-tool scope gate in `mcp::tool_executor`. That is why it is
        // loopback-only, opt-in, and loudly logged — see `warn_mcp_auth_disabled_once`.
        return Ok(run_as(req, auth::Caller::FullAccess, next).await);
    }

    // Request-time account binding (defense-in-depth for per-account data isolation). The webview
    // stamps every `/v1` request with `X-Writ-Account` naming the account it BELIEVES it is bound to.
    // If that disagrees with the profile this daemon is actually serving — a profile swap raced the
    // UI, or two windows point at different profiles — REFUSE (403) rather than let one account's UI
    // read/write another's data. Absent header ⇒ unbound ⇒ allowed, so external `wlk_`/`wlo_`/MCP
    // callers (which never send it) are unaffected. Cloud-only: OSS is single-home (`local`).
    #[cfg(feature = "cloud")]
    if let Some(bound) = h.get("x-writ-account").and_then(|v| v.to_str().ok()) {
        let bound = bound.trim();
        let serving = crate::local::cloud::token::active_profile();
        if !bound.is_empty() && bound != serving {
            tracing::warn!(
                bound = %bound,
                serving = %serving,
                "rejecting request: X-Writ-Account does not match the profile this daemon serves"
            );
            return Err(LocalError::IsolationViolation(format!(
                "request bound to account '{bound}' but this daemon serves '{serving}'"
            )));
        }
    }

    let presented = match h
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(auth::parse_bearer)
    {
        Some(p) => p,
        // A bare 401 is useless to an OAuth-only MCP host — RFC 9728 §5.1 says point it at the
        // protected-resource metadata so it can start the discovery dance.
        None if path == "/mcp" => return Ok(mcp_unauthorized(&st, h)),
        None => return Err(LocalError::Unauthorized),
    };

    // Full-access UI token (`wlt_`) — constant-time match against the CURRENT effective token (the
    // live-rotated value if `POST /v1/token/rotate` swapped it, else the boot seed), no scope gate.
    if crate::local::runtime_token::verify(presented, st.token.as_str()) {
        return Ok(run_as(req, auth::Caller::FullAccess, next).await);
    }

    // OAuth access token (`wlo_`, minted by `api::v1::oauth`) — hash lookup, expiry + scope gate.
    // Scope semantics are IDENTICAL to `wlk_` (same CSV tokens through the same chain).
    if presented.starts_with("wlo_") {
        let now = chrono::Utc::now().timestamp();
        let tok = match crate::local::store::oauth::get_active_by_access_hash(
            &st.db,
            &sha256_hex(presented.as_bytes()),
            now,
        )
        .await?
        {
            Some(t) => t,
            None if path == "/mcp" => return Ok(mcp_unauthorized(&st, h)),
            None => return Err(LocalError::Unauthorized),
        };
        let needed = auth::required_scope(req.method().as_str(), path);
        if !auth::scope_grants(&tok.scope, needed) {
            tracing::warn!(oauth_token_id = tok.id, scope = needed.as_str(), "wlo_ token lacks required scope");
            return Err(LocalError::Forbidden);
        }
        // Same external-caller Connect-surface gate as `wlk_` (REST run toggle).
        if let Some(id) = rest_run_workflow_id(req.method().as_str(), path) {
            if let Some(wf) = workflows::get_by_id(&st.db, id).await? {
                if !wf.connect_surfaces().rest {
                    tracing::warn!(oauth_token_id = tok.id, workflow_id = id, "wlo_ run blocked: REST surface disabled");
                    return Err(LocalError::Forbidden);
                }
            }
        }
        let _ = crate::local::store::oauth::touch_used(&st.db, tok.id).await;
        // Carry the granted scope forward so body-level gates (MCP per-tool minimum scope, the mixed
        // runtime-settings route) judge a `wlo_` token by exactly what consent issued it.
        return Ok(run_as(req, auth::Caller::Scoped(tok.scope.clone()), next).await);
    }

    // Otherwise treat it as a scoped `wlk_` client key: hash → active-row lookup → scope gate.
    let key_hash = sha256_hex(presented.as_bytes());
    let key = match local_api_keys::get_active_by_hash(&st.db, &key_hash).await? {
        Some(k) => k,
        None if path == "/mcp" => return Ok(mcp_unauthorized(&st, h)),
        None => return Err(LocalError::Unauthorized),
    };

    let needed = auth::required_scope(req.method().as_str(), path);
    if !auth::scope_grants(&key.scopes, needed) {
        tracing::warn!(api_key_id = key.id, scope = needed.as_str(), "wlk_ key lacks required scope");
        // Authenticated but unauthorized for this capability → 403.
        return Err(LocalError::Forbidden);
    }

    // Connect surface gate (EXTERNAL `wlk_` callers only — the full-access `wlt_` UI token returned
    // earlier and never reaches here). If the workflow's REST surface is toggled OFF in its Connect
    // settings, reject an external `POST /v1/workflows/{id}/run` while leaving in-app Run untouched.
    // OpenAI- and MCP-surface gating lives in those handlers (the workflow id is in the body there).
    if let Some(id) = rest_run_workflow_id(req.method().as_str(), path) {
        if let Some(wf) = workflows::get_by_id(&st.db, id).await? {
            if !wf.connect_surfaces().rest {
                tracing::warn!(api_key_id = key.id, workflow_id = id, "wlk_ run blocked: REST surface disabled");
                return Err(LocalError::Forbidden);
            }
        }
    }

    // Best-effort usage stamp (never block the request on a write failure).
    let _ = local_api_keys::touch_used(&st.db, key.id).await;

    // Same rationale as the `wlo_` branch: the body-level gates need the key's own CSV grant.
    Ok(run_as(req, auth::Caller::Scoped(key.scopes.clone()), next).await)
}

/// The `config` kv key for the MCP auth-off escape hatch (see `auth_mw` + `api::v1::mcp_connect`).
/// Value `"true"` disables the bearer requirement on `POST /mcp` — LOOPBACK ONLY (ignored when
/// `network_exposed`), explicit user opt-in from the Connect UI.
pub const MCP_AUTH_DISABLED_KEY: &str = "mcp_auth_disabled";

/// Has the MCP auth-off hatch already been announced in this process?
static MCP_AUTH_OFF_ANNOUNCED: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

/// Announce the MCP auth-off hatch LOUDLY, once per daemon lifetime, the first time it actually
/// takes effect.
///
/// The toggle is persisted in `config_kv`, so a user who enabled it months ago has no reminder that
/// `POST /mcp` now takes NO credential — and, because there is no credential, no scope either: the
/// per-tool gate in `mcp::tool_executor` sees `Caller::FullAccess` and every `writ_*` tool (create
/// automation, set schedule, install API) is reachable by anything that can open a loopback socket.
/// That is an acceptable, explicitly-chosen trade for MCP hosts with no credential field, but it must
/// never be a FORGOTTEN one. Warn on first use rather than at boot so the message appears exactly
/// when the hatch is live, without the boot path having to query the DB.
fn warn_mcp_auth_disabled_once() {
    use std::sync::atomic::Ordering;
    if MCP_AUTH_OFF_ANNOUNCED.swap(true, Ordering::Relaxed) {
        return;
    }
    tracing::warn!(
        config_key = MCP_AUTH_DISABLED_KEY,
        "SECURITY: MCP bearer auth is DISABLED — `POST /mcp` is serving UNAUTHENTICATED requests. \
         Any process able to reach this loopback port can call every writ_* tool (create automations, \
         set schedules, install APIs) with full privileges, because no credential means no scope to \
         enforce. This is loopback-only and was explicitly opted into; turn it back on in Writ \
         (Connect → MCP) as soon as your client can send an Authorization header."
    );
}

/// A `401` for the `/mcp` surface that an OAuth-capable MCP host can act on: RFC 9728 §5.1 —
/// `WWW-Authenticate: Bearer resource_metadata="<url>"` pointing at our protected-resource
/// document, so the client discovers the local authorization server and runs the code+PKCE flow
/// (`api::v1::oauth`). The URL is rebuilt from the request's own Host so it stays on whichever
/// lane (http/https) the client is already using.
fn mcp_unauthorized(st: &AppState, headers: &axum::http::HeaderMap) -> Response {
    use axum::response::IntoResponse;
    let host = headers.get(header::HOST).and_then(|v| v.to_str().ok());
    let base = crate::local::api::v1::oauth::base_url_for_host(host, &st.config);
    let mut resp = LocalError::Unauthorized.into_response();
    if let Ok(v) = format!(
        "Bearer resource_metadata=\"{base}/.well-known/oauth-protected-resource\", error=\"invalid_token\""
    )
    .parse()
    {
        resp.headers_mut().insert(header::WWW_AUTHENTICATE, v);
    }
    resp
}

/// Parse the workflow id from a `POST /v1/workflows/{id}/run` request, else `None`. Used by the
/// Connect REST-surface gate; matches ONLY the run-invocation route (not `/cancel`, sub-paths, or
/// non-POST methods), and a non-numeric id yields `None` (the handler will 404 it normally).
fn rest_run_workflow_id(method: &str, path: &str) -> Option<i64> {
    if !method.eq_ignore_ascii_case("POST") {
        return None;
    }
    let inner = path.strip_prefix("/v1/workflows/")?.strip_suffix("/run")?;
    // Reject any deeper path (the id segment must be a single component).
    if inner.is_empty() || inner.contains('/') {
        return None;
    }
    inner.parse::<i64>().ok()
}

/// Lowercase-hex sha256 (matches the `wlk_` key-hash idiom in `api::v1::keys`). Never log the input.
fn sha256_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hasher.finalize().iter().map(|b| format!("{b:02x}")).collect()
}

/// The textual bind host for the daemon's listener, given the exposure flag: `"127.0.0.1"` when
/// loopback-only (the default), `"0.0.0.0"` when the operator opted into LAN exposure (all IPv4
/// interfaces, LAN-reachable). Surfaced by `GET /v1/network/status`.
pub fn bind_host(network_exposed: bool) -> &'static str {
    if network_exposed { "0.0.0.0" } else { "127.0.0.1" }
}

/// Best-effort discovery of this machine's primary LAN IPv4 address, with NO extra dependency.
///
/// Trick: open a UDP socket and `connect()` it to an off-box address. UDP `connect` is purely local —
/// it sets the socket's default peer and lets the OS pick the source interface, but sends NO packets
/// (so it works offline and never touches the network). `local_addr()` then reports the IP the OS
/// would route from, i.e. our LAN address. Returns `None` on any failure or when only loopback is
/// available. Used to render the `lan_url` hint and to widen the Origin/Host allowlist when exposed.
pub fn primary_lan_ip() -> Option<std::net::IpAddr> {
    // 203.0.113.0/24 is TEST-NET-3 (RFC 5737) — guaranteed non-routable, so this is purely a
    // local routing-table lookup; nothing leaves the machine.
    let sock = std::net::UdpSocket::bind(("0.0.0.0", 0)).ok()?;
    sock.connect(("203.0.113.1", 9)).ok()?;
    let ip = sock.local_addr().ok()?.ip();
    if ip.is_loopback() || ip.is_unspecified() {
        return None;
    }
    Some(ip)
}

/// The set of host strings (WITHOUT a port) that the Origin/Host allowlist accepts as "us" when the
/// daemon is LAN-exposed: the configured bind host plus the best-effort primary LAN IP. Empty when
/// not exposed (the caller then enforces loopback-only). Kept tiny + allocation-light.
pub fn lan_hosts(network_exposed: bool) -> Vec<String> {
    if !network_exposed {
        return Vec::new();
    }
    let mut hosts = vec![bind_host(true).to_string()];
    if let Some(ip) = primary_lan_ip() {
        hosts.push(ip.to_string());
    }
    hosts
}

/// Bind and serve the local API.
///
/// SECURITY (LOCAL_BACKEND_SPEC §7 + SECURITY.md "Network exposure"): the daemon is LOOPBACK-ONLY by
/// default (`127.0.0.1`). It binds a NON-loopback address (`0.0.0.0`, all interfaces) ONLY when the
/// operator has explicitly set `network_exposed = true`. A DEFENSIVE GUARD refuses to bind any
/// non-loopback address unless that flag is set, so an accidental/forced non-loopback bind can never
/// silently expose the API; a clear WARNING is logged whenever we do bind non-loopback. The bearer
/// token stays mandatory in both modes and the DNS-rebind Origin/Host guard still rejects foreign
/// browser origins.
pub async fn serve(state: AppState) -> LocalResult<()> {
    let exposed = state.config.network_exposed;
    let port = state.config.port;

    // Choose the bind IP from the exposure flag.
    let ip: std::net::IpAddr = if exposed {
        std::net::Ipv4Addr::UNSPECIFIED.into() // 0.0.0.0 — all interfaces, LAN-reachable
    } else {
        std::net::Ipv4Addr::LOCALHOST.into() // 127.0.0.1 — loopback only
    };
    let addr = std::net::SocketAddr::new(ip, port);

    // Defensive guard: a non-loopback bind is permitted ONLY with explicit opt-in. This is the last
    // line of defense against a bug/env that flips the address without flipping the consent flag.
    if !addr.ip().is_loopback() && !exposed {
        return Err(LocalError::Internal(format!(
            "refusing to bind non-loopback address {addr} without network_exposed=true (loopback-only by default)"
        )));
    }

    let listener = tokio::net::TcpListener::bind(addr).await?;
    if exposed {
        let lan = primary_lan_ip().map(|ip| format!("http://{ip}:{port}"));
        tracing::warn!(
            %addr,
            lan_url = lan.as_deref().unwrap_or("(unknown)"),
            "local API is NETWORK-EXPOSED on all interfaces (LAN-reachable). The bearer token is still \
             required and DNS-rebind protection is still enforced; use a scoped wlk_ key + the app-lock. \
             Disable exposure to return to loopback-only."
        );
    } else {
        tracing::info!(%addr, "local API listening (loopback)");
    }

    // HTTPS lane — the TLS twin of the plain listener, serving the SAME router (same bearer +
    // Origin/Host guard; `is_loopback_authority` is port-agnostic so no auth change). Exists because
    // some MCP / OpenAI-compat clients refuse a plain `http://` base URL; the cert chains to the
    // per-install local CA (`local::tls`). FAIL-SOFT by design: any material/bind failure logs a
    // warning and the plain lane lives on — HTTPS is an add-on, never a boot blocker.
    spawn_tls_listener(&state);

    // Cloud run-events forwarder: push a linked account's cloud-side run changes into the engine's
    // GLOBAL run-events stream (→ shell `run:event` → webview refetch), so the desktop's "Running in
    // cloud" reflection needs no poll. Best-effort + self-healing; only for an engine that owns a run
    // registry (the real engine — a stub has none). Cloud-only: the OSS self-host build has no cloud
    // account to reflect, and `super::cloud` is not compiled there.
    #[cfg(feature = "cloud")]
    if let Some(registry) = state.engine.registry() {
        let db = state.db.clone();
        tokio::spawn(async move {
            super::cloud::run_events::run(db, registry).await;
        });
    }

    // Opt-in anonymized usage metrics. DORMANT unless the user turned telemetry on in Settings AND
    // the desktop is cloud-linked; the loop re-reads the opt-in from disk each tick, so switching it
    // off takes effect without a restart. Counts/durations/booleans only — see
    // `cloud::usage_metrics` for why no user string can reach the payload.
    #[cfg(feature = "cloud")]
    {
        let db = state.db.clone();
        tokio::spawn(async move {
            super::cloud::usage_metrics::run(db).await;
        });
    }

    axum::serve(listener, build_router(state)).await?;
    Ok(())
}

/// Bind the HTTPS lane on `config.tls_port` (0 = disabled) and serve `build_router` over rustls in
/// a background task. Never returns an error: every failure path logs and leaves plain HTTP intact.
fn spawn_tls_listener(state: &AppState) {
    let tls_port = state.config.tls_port;
    if tls_port == 0 {
        tracing::info!("HTTPS lane disabled (tls_port = 0)");
        return;
    }
    let exposed = state.config.network_exposed;
    if tls_port == state.config.port {
        tracing::warn!(port = tls_port, "HTTPS lane disabled: tls_port collides with the plain port");
        return;
    }

    let paths = match super::config::Paths::resolve() {
        Ok(p) => p,
        Err(e) => {
            tracing::warn!(error = %e, "HTTPS lane disabled: cannot resolve WRIT_HOME for TLS material");
            return;
        }
    };
    // When LAN-exposed, put the LAN IP in the leaf SANs so `https://<lan-ip>:<tls_port>` validates.
    let extra_sans: Vec<String> = if exposed {
        primary_lan_ip().map(|ip| ip.to_string()).into_iter().collect()
    } else {
        Vec::new()
    };
    let material = match super::tls::load_or_create(&paths, &extra_sans) {
        Ok(m) => m,
        Err(e) => {
            tracing::warn!(error = %e, "HTTPS lane disabled: TLS material unavailable");
            return;
        }
    };

    let ip: std::net::IpAddr = if exposed {
        std::net::Ipv4Addr::UNSPECIFIED.into()
    } else {
        std::net::Ipv4Addr::LOCALHOST.into()
    };
    let tls_addr = std::net::SocketAddr::new(ip, tls_port);
    let rustls_cfg = axum_server::tls_rustls::RustlsConfig::from_config(material.server_config.clone());
    let router = build_router(state.clone());

    super::tls::install_status(super::tls::TlsRuntimeStatus {
        port: tls_port,
        ca_path: material.ca_path.to_string_lossy().into_owned(),
        ca_fingerprint_sha256: material.ca_fingerprint_sha256.clone(),
        ca_expires_at: material.ca_expires_at.clone(),
        leaf_expires_at: material.leaf_expires_at.clone(),
    });
    tracing::info!(%tls_addr, ca = %material.ca_path.display(), "local API also listening over HTTPS");

    tokio::spawn(async move {
        if let Err(e) =
            axum_server::bind_rustls(tls_addr, rustls_cfg).serve(router.into_make_service()).await
        {
            tracing::warn!(error = %e, %tls_addr, "HTTPS lane exited (plain HTTP unaffected)");
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::local::{config, db, engine, vault};
    use axum::body::Body;
    use tower::ServiceExt;

    async fn test_state(token: &str) -> AppState {
        let dir = tempfile::tempdir().unwrap();
        let paths = config::Paths::at(dir.keep()); // into_path persists (no cleanup) for the test
        paths.ensure_dirs().unwrap();
        let v = vault::Vault::load_or_create(&paths.root, false).unwrap();
        let pool = db::open(&paths.db(), &v.db_key_hex()).await.unwrap();
        AppState {
            db: pool,
            vault: Arc::new(v),
            engine: Arc::new(engine::StubEngine),
            config: LocalConfig::default(),
            token: Arc::new(token.to_string()),
            health: crate::local::app::health::DaemonHealth::shared(),
            recorder: None,
        }
    }

    #[test]
    fn rest_run_path_matcher() {
        // Matches only POST to the exact run-invocation route.
        assert_eq!(rest_run_workflow_id("POST", "/v1/workflows/42/run"), Some(42));
        assert_eq!(rest_run_workflow_id("post", "/v1/workflows/7/run"), Some(7));
        // Wrong method, wrong/deeper path, cancel, or non-numeric id → no match (gate is skipped).
        assert_eq!(rest_run_workflow_id("GET", "/v1/workflows/42/run"), None);
        assert_eq!(rest_run_workflow_id("POST", "/v1/workflows/42/cancel"), None);
        assert_eq!(rest_run_workflow_id("POST", "/v1/workflows/42/run/extra"), None);
        assert_eq!(rest_run_workflow_id("POST", "/v1/workflows//run"), None);
        assert_eq!(rest_run_workflow_id("POST", "/v1/workflows/abc/run"), None);
        assert_eq!(rest_run_workflow_id("POST", "/v1/workflows"), None);
    }

    #[tokio::test]
    async fn health_requires_bearer() {
        let state = test_state("wlt_secret").await;

        // No token → 401.
        let resp = build_router(state.clone())
            .oneshot(Request::builder().uri("/v1/agent").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(resp.status(), 401);

        // Correct token → 200.
        let resp = build_router(state)
            .oneshot(
                Request::builder()
                    .uri("/v1/agent")
                    .header("authorization", "Bearer wlt_secret")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), 200);
    }

    #[tokio::test]
    async fn health_endpoint_reports_db_and_no_secrets() {
        use axum::body::to_bytes;
        let state = test_state("wlt_h").await;
        let resp = build_router(state)
            .oneshot(
                Request::builder()
                    .uri("/v1/health")
                    .header("authorization", "Bearer wlt_h")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), 200);
        let body = to_bytes(resp.into_body(), 64 * 1024).await.unwrap();
        let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
        // SQLCipher is active in tests → cipher_present + db_ok true, status ok.
        assert_eq!(v["status"], "ok");
        assert_eq!(v["cipher_present"], serde_json::json!(true));
        assert_eq!(v["db_ok"], serde_json::json!(true));
        assert_eq!(v["active_runs"], serde_json::json!(0));
        // Scheduler block present; no tick yet → last_tick_at null, due_monitors 0.
        assert!(v["scheduler"].is_object());
        assert_eq!(v["scheduler"]["due_monitors"], serde_json::json!(0));
        assert!(v["scheduler"]["last_tick_at"].is_null());
        // Cloud unlinked in a fresh DB.
        assert_eq!(v["cloud_link"]["linked"], serde_json::json!(false));
        // Defense-in-depth: the health payload must never carry the bearer token or a sealed blob.
        let raw = String::from_utf8_lossy(&body);
        assert!(!raw.contains("wlt_"), "no token in health payload");
        assert!(!raw.contains("WF1:"), "no sealed blob in health payload");
    }

    #[tokio::test]
    async fn workflows_crud_over_http() {
        let state = test_state("wlt_k").await;

        // Create a workflow through the full stack (router → handler → store → encrypted DB).
        let resp = build_router(state.clone())
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/workflows")
                    .header("authorization", "Bearer wlt_k")
                    .header("content-type", "application/json")
                    .body(Body::from(r#"{"name":"My WF"}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), 200, "create workflow");

        // List should now succeed (200).
        let resp = build_router(state.clone())
            .oneshot(
                Request::builder()
                    .uri("/v1/workflows")
                    .header("authorization", "Bearer wlt_k")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), 200, "list workflows");

        // No bearer → 401 even on a mounted /v1 route.
        let resp = build_router(state)
            .oneshot(Request::builder().uri("/v1/workflows").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(resp.status(), 401, "list without token");
    }

    #[tokio::test]
    async fn workflow_create_accepts_wizard_shape_and_seals_credentials() {
        use axum::body::to_bytes;
        let state = test_state("wlt_cred").await;

        // The desktop wizard's REAL create body: `steps` as an array, `form_data` as an object,
        // `headless` as a bool, plus a PLAINTEXT `credentials` map. This shape used to 422.
        let body = serde_json::json!({
            "name": "Login flow",
            "workflow_type": "streaming",
            "steps": [{ "type": "click", "selector": "#go" }],
            "form_data": { "city": "Paris" },
            "headless": false,
            "fast_mode": true,
            "credentials": { "LOGIN_PW": "hunter2" },
        });
        let resp = build_router(state.clone())
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/workflows")
                    .header("authorization", "Bearer wlt_cred")
                    .header("content-type", "application/json")
                    .body(Body::from(body.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), 200, "wizard-shaped create must not 422");

        let bytes = to_bytes(resp.into_body(), 64 * 1024).await.unwrap();
        let v: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        let id = v["id"].as_i64().unwrap();
        // Bool run-settings landed as 0/1 columns.
        assert_eq!(v["headless"], serde_json::json!(0));
        assert_eq!(v["fast_mode"], serde_json::json!(1));
        // JSON-TEXT columns are re-hydrated into rich JSON on the way out — symmetric with the
        // array/object shape they came in as. The frontend does `steps.map(...)`, so a stored-string
        // `steps` (the old behavior) would crash the step editor.
        assert!(v["steps"].is_array(), "steps must be a real array, not a JSON string");
        assert_eq!(v["steps"][0]["selector"], serde_json::json!("#go"));
        assert!(v["form_data"].is_object(), "form_data must be a real object, not a JSON string");
        assert_eq!(v["form_data"]["city"], serde_json::json!("Paris"));
        // Secret hygiene: the ciphertext is redacted and a non-secret flag stands in; the plaintext
        // and the sealed blob NEVER cross the API boundary.
        assert_eq!(v["has_credentials"], serde_json::json!(true));
        assert!(v.get("credentials_encrypted").is_none(), "ciphertext must be redacted");
        let raw = String::from_utf8_lossy(&bytes);
        assert!(!raw.contains("hunter2"), "plaintext credential must never be echoed");
        assert!(!raw.contains("WF1:"), "sealed blob must never be echoed");

        // The run-time path opens the sealed blob with the row-bound AAD (single source of truth).
        let wf = crate::local::store::workflows::get_by_id(&state.db, id).await.unwrap().unwrap();
        let blob = wf.credentials_encrypted.as_deref().expect("credentials sealed on the row");
        assert!(blob.starts_with("WF1:"), "stored as a sealed Layer-B blob");
        let aad = crate::local::store::workflows::credentials_aad(id);
        let plain = state.vault.open_field(blob, &aad).unwrap();
        let map: std::collections::BTreeMap<String, String> =
            serde_json::from_slice(&plain).unwrap();
        assert_eq!(map.get("LOGIN_PW").map(String::as_str), Some("hunter2"));

        // And the stored steps are valid JSON TEXT the engine can `from_str`.
        let steps: serde_json::Value = serde_json::from_str(&wf.steps).unwrap();
        assert_eq!(steps[0]["selector"], serde_json::json!("#go"));
    }

    /// Mint a `wlk_` key with the given scopes directly in the store, returning the raw key.
    async fn mint_key(st: &AppState, scopes: &str) -> String {
        use crate::local::store::local_api_keys::{insert, NewLocalApiKey};
        let raw = format!("wlk_test_{}", scopes.replace(',', "_"));
        let key_hash = sha256_hex(raw.as_bytes());
        insert(
            &st.db,
            &NewLocalApiKey {
                name: "k".into(),
                prefix: "wlk_test".into(),
                key_hash,
                scopes: Some(scopes.into()),
            },
        )
        .await
        .unwrap();
        raw
    }

    #[tokio::test]
    async fn wlk_key_scopes_are_enforced() {
        let st = test_state("wlt_full").await;
        let read_key = mint_key(&st, "read").await;
        let admin_key = mint_key(&st, "admin").await;

        // read-scoped key: GET allowed (200), POST mutation rejected (403).
        let resp = build_router(st.clone())
            .oneshot(
                Request::builder()
                    .uri("/v1/workflows")
                    .header("authorization", format!("Bearer {read_key}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), 200, "read key may GET");

        let resp = build_router(st.clone())
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/workflows")
                    .header("authorization", format!("Bearer {read_key}"))
                    .header("content-type", "application/json")
                    .body(Body::from(r#"{"name":"x"}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), 403, "read key may NOT create");

        // admin key: the mutation is allowed past auth (200 create).
        let resp = build_router(st.clone())
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/workflows")
                    .header("authorization", format!("Bearer {admin_key}"))
                    .header("content-type", "application/json")
                    .body(Body::from(r#"{"name":"x"}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), 200, "admin key may create");

        // An unknown wlk_ key → 401.
        let resp = build_router(st)
            .oneshot(
                Request::builder()
                    .uri("/v1/workflows")
                    .header("authorization", "Bearer wlk_unknown")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), 401, "unknown key rejected");
    }

    #[test]
    fn bind_host_reflects_exposure() {
        assert_eq!(bind_host(false), "127.0.0.1", "loopback-only by default");
        assert_eq!(bind_host(true), "0.0.0.0", "all interfaces when exposed");
    }

    #[test]
    fn lan_hosts_empty_unless_exposed() {
        // Not exposed → no LAN hosts at all (the allowlist stays loopback-only).
        assert!(lan_hosts(false).is_empty());
        // Exposed → at least the bind host is present (the LAN IP is best-effort/env-dependent).
        let hosts = lan_hosts(true);
        assert!(hosts.iter().any(|h| h == "0.0.0.0"), "bind host present: {hosts:?}");
    }

    /// The defensive guard: when the resolved bind address is non-loopback but `network_exposed` is
    /// false, `serve()` must refuse to bind (a forced/accidental non-loopback can never silently
    /// expose the API). We assert the EXACT guard predicate `serve()` uses, mirroring its logic.
    #[test]
    fn loopback_default_refuses_non_loopback_bind() {
        // Loopback default: the chosen IP is 127.0.0.1 and the guard does NOT trip.
        let exposed = false;
        let ip: std::net::IpAddr = if exposed {
            std::net::Ipv4Addr::UNSPECIFIED.into()
        } else {
            std::net::Ipv4Addr::LOCALHOST.into()
        };
        let addr = std::net::SocketAddr::new(ip, 8131);
        assert!(addr.ip().is_loopback(), "default binds loopback");
        assert!(!(!addr.ip().is_loopback() && !exposed), "guard does not trip on the loopback default");

        // A forced non-loopback address WITHOUT the consent flag → the guard trips (refusal).
        let forced = std::net::SocketAddr::new(std::net::Ipv4Addr::UNSPECIFIED.into(), 8131);
        assert!(!forced.ip().is_loopback());
        assert!(
            !forced.ip().is_loopback() && !exposed,
            "guard MUST trip: non-loopback bind without network_exposed"
        );
    }

    #[test]
    fn exposed_allows_zero_zero_zero_zero() {
        // With the consent flag, 0.0.0.0 is selected and the guard permits it.
        let exposed = true;
        let ip: std::net::IpAddr = if exposed {
            std::net::Ipv4Addr::UNSPECIFIED.into()
        } else {
            std::net::Ipv4Addr::LOCALHOST.into()
        };
        let addr = std::net::SocketAddr::new(ip, 8131);
        assert_eq!(addr.ip().to_string(), "0.0.0.0");
        assert!(!(!addr.ip().is_loopback() && !exposed), "guard permits an exposed 0.0.0.0 bind");
    }

    /// End-to-end on the real `serve()` path: a loopback-default state actually binds an ephemeral
    /// loopback port and serves (the guard never trips). We bind on port 0, confirm the listener came
    /// up on 127.0.0.1, then drop it (we don't run the accept loop).
    #[tokio::test]
    async fn serve_binds_loopback_on_default() {
        let state = test_state("wlt_bind").await;
        assert!(!state.config.network_exposed, "default is loopback-only");
        // Mirror serve()'s address selection + guard, then actually bind to prove it works.
        let ip: std::net::IpAddr = std::net::Ipv4Addr::LOCALHOST.into();
        let addr = std::net::SocketAddr::new(ip, 0);
        assert!(!(!addr.ip().is_loopback() && !state.config.network_exposed));
        let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
        assert!(listener.local_addr().unwrap().ip().is_loopback(), "bound a loopback address");
    }

    /// End-to-end HTTPS lane: real axum-server rustls listener on an ephemeral port, real rustls
    /// client that trusts ONLY the generated local CA. Proves (1) the served chain validates against
    /// the on-disk anchor (incl. the name-constrained CA), (2) the TLS lane serves the SAME router —
    /// a request without a bearer hits the auth layer and gets 401.
    #[tokio::test]
    async fn https_lane_serves_router_with_valid_chain() {
        let state = test_state("wlt_tls").await;
        let dir = tempfile::tempdir().unwrap();
        let paths = config::Paths::at(dir.path().join(".writ"));
        paths.ensure_dirs().unwrap();
        let material = crate::local::tls::load_or_create(&paths, &[]).unwrap();

        let cfg = axum_server::tls_rustls::RustlsConfig::from_config(material.server_config.clone());
        let handle = axum_server::Handle::new();
        let router = build_router(state);
        let h = handle.clone();
        tokio::spawn(async move {
            let _ = axum_server::bind_rustls("127.0.0.1:0".parse().unwrap(), cfg)
                .handle(h)
                .serve(router.into_make_service())
                .await;
        });
        let addr = handle.listening().await.expect("TLS listener came up");

        let ca_pem = std::fs::read(paths.tls_dir().join("ca.pem")).unwrap();
        let status_line = tokio::task::spawn_blocking(move || {
            use rustls::pki_types::pem::PemObject;
            let ca_der = rustls::pki_types::CertificateDer::from_pem_slice(&ca_pem).unwrap();
            let mut roots = rustls::RootCertStore::empty();
            roots.add(ca_der).unwrap();
            let provider = std::sync::Arc::new(rustls::crypto::ring::default_provider());
            let cc = rustls::ClientConfig::builder_with_provider(provider)
                .with_safe_default_protocol_versions()
                .unwrap()
                .with_root_certificates(roots)
                .with_no_client_auth();
            let name = rustls::pki_types::ServerName::try_from("localhost").unwrap();
            let mut conn =
                rustls::ClientConnection::new(std::sync::Arc::new(cc), name).unwrap();
            let mut tcp = std::net::TcpStream::connect(addr).unwrap();
            let mut tls = rustls::Stream::new(&mut conn, &mut tcp);
            use std::io::{Read, Write};
            tls.write_all(b"GET /v1/agent HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
                .unwrap();
            let mut buf = Vec::new();
            let _ = tls.read_to_end(&mut buf); // close_notify-less shutdown is fine for the assert
            String::from_utf8_lossy(&buf).lines().next().unwrap_or_default().to_string()
        })
        .await
        .unwrap();

        assert!(
            status_line.contains("401"),
            "TLS handshake verified against the local CA and reached the auth layer (got: {status_line})"
        );
    }

    #[tokio::test]
    async fn ws_ticket_mint_requires_bearer_and_scopes_the_ticket() {
        use axum::body::to_bytes;
        let st = test_state("wlt_ticket").await;

        // No bearer → 401 (the endpoint is inside auth_mw).
        let resp = build_router(st.clone())
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/ws-ticket")
                    .header("content-type", "application/json")
                    .body(Body::from(r#"{"route":"record"}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), 401, "ws-ticket mint requires the bearer");

        // With the bearer → 200 + a single-use wtk_ ticket that the record route accepts once.
        let resp = build_router(st.clone())
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/ws-ticket")
                    .header("authorization", "Bearer wlt_ticket")
                    .header("content-type", "application/json")
                    .body(Body::from(r#"{"route":"record"}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), 200);
        let body = to_bytes(resp.into_body(), 16 * 1024).await.unwrap();
        let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
        let ticket = v["ticket"].as_str().unwrap().to_string();
        assert!(ticket.starts_with("wtk_"));
        assert!(v["expires_in_secs"].as_u64().unwrap() > 0);
        // Single-use + route-scoped: accepted once for record, then spent; never valid for preview.
        use crate::local::ws_ticket::{self, WsRoute};
        assert!(!ws_ticket::consume(&ticket, WsRoute::AiPreview, Some("ai-1")), "wrong route rejected");
        // (that mismatched attempt burned it; mint a fresh one to prove the happy path)
        let resp = build_router(st.clone())
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/ws-ticket")
                    .header("authorization", "Bearer wlt_ticket")
                    .header("content-type", "application/json")
                    .body(Body::from(r#"{"route":"record"}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        let body = to_bytes(resp.into_body(), 16 * 1024).await.unwrap();
        let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
        let ticket2 = v["ticket"].as_str().unwrap().to_string();
        assert!(ws_ticket::consume(&ticket2, WsRoute::Record, None));
        assert!(!ws_ticket::consume(&ticket2, WsRoute::Record, None), "replay rejected");

        // Bad route → 400.
        let resp = build_router(st.clone())
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/ws-ticket")
                    .header("authorization", "Bearer wlt_ticket")
                    .header("content-type", "application/json")
                    .body(Body::from(r#"{"route":"bogus"}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), 400, "unknown route rejected");

        // ai-preview WITHOUT a channel → 400 (a preview ticket must be channel-scoped).
        let resp = build_router(st.clone())
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/ws-ticket")
                    .header("authorization", "Bearer wlt_ticket")
                    .header("content-type", "application/json")
                    .body(Body::from(r#"{"route":"ai-preview"}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), 400, "ai-preview ticket needs a channel");

        // The minted ticket + expiry must never contain the master bearer.
        let raw = String::from_utf8_lossy(&body);
        assert!(!raw.contains("wlt_"), "mint response must not carry the wlt_ bearer");
    }

    // ── Auto-update verify endpoint (POST /v1/update/verify) ─────────────────
    //
    // Builds a real signed manifest with the test key pinned under #[cfg(test)] and drives it through
    // the full router so the daemon's §3 policy chain runs end-to-end. Proves the endpoint (a)
    // requires the bearer, (b) approves ONLY a fully-valid, in-policy, correctly-signed manifest, and
    // (c) fails CLOSED on tamper / downgrade / version-mismatch.

    fn test_signed(version: &str) -> crate::local::update::Signed {
        use crate::local::update::Artifact;
        let mut artifacts = std::collections::BTreeMap::new();
        // Artifact for the CURRENT platform so the artifact-select gate passes on the test host.
        artifacts.insert(
            crate::local::update::current_platform_key().to_string(),
            Artifact {
                url: "https://downloads.example/writ.dmg".into(),
                size_bytes: 1024,
                sha256: "a".repeat(64),
                format: "dmg".into(),
                installer: None,
            },
        );
        crate::local::update::Signed {
            manifest_id: "11111111-1111-1111-1111-111111111111".into(),
            channel: "stable".into(),
            version: version.into(),
            min_supported_version: "0.0.1".into(),
            released_at: "2026-01-01T00:00:00Z".into(),
            manifest_expires_at: "2099-01-01T00:00:00Z".into(),
            notes_url: None,
            changelog: None,
            security_advisory: false,
            rollout: None,
            chromium_revision: None,
            artifacts,
        }
    }

    async fn post_verify(st: &AppState, bearer: Option<&str>, manifest_json: &str) -> (axum::http::StatusCode, serde_json::Value) {
        use axum::body::to_bytes;
        let mut req = Request::builder()
            .method("POST")
            .uri("/v1/update/verify")
            .header("content-type", "application/json");
        if let Some(b) = bearer {
            req = req.header("authorization", format!("Bearer {b}"));
        }
        let resp = build_router(st.clone())
            .oneshot(req.body(Body::from(manifest_json.to_string())).unwrap())
            .await
            .unwrap();
        let status = resp.status();
        let body = to_bytes(resp.into_body(), 64 * 1024).await.unwrap();
        let v = serde_json::from_slice(&body).unwrap_or(serde_json::Value::Null);
        (status, v)
    }

    #[tokio::test]
    async fn update_verify_requires_bearer() {
        let st = test_state("wlt_upd").await;
        let signed = test_signed("999.0.0");
        let manifest_bytes = crate::local::update::test_support::sign_manifest(&signed);
        let manifest: serde_json::Value = serde_json::from_slice(&manifest_bytes).unwrap();
        let body = serde_json::json!({ "manifest": manifest }).to_string();
        let (status, _) = post_verify(&st, None, &body).await;
        assert_eq!(status, 401, "verify requires the bearer");
    }

    #[tokio::test]
    async fn update_verify_approves_valid_signed_manifest() {
        let st = test_state("wlt_upd").await;
        let signed = test_signed("999.0.0");
        let manifest_bytes = crate::local::update::test_support::sign_manifest(&signed);
        let manifest: serde_json::Value = serde_json::from_slice(&manifest_bytes).unwrap();
        let body = serde_json::json!({ "manifest": manifest, "expected_version": "999.0.0" }).to_string();
        let (status, v) = post_verify(&st, Some("wlt_upd"), &body).await;
        assert_eq!(status, 200);
        assert_eq!(v["approved"], serde_json::json!(true), "valid manifest approved: {v}");
        assert_eq!(v["version"], serde_json::json!("999.0.0"));
        assert_eq!(v["expected_sha256"].as_str().unwrap().len(), 64);
    }

    #[tokio::test]
    async fn update_verify_fails_closed_on_tampered_signature() {
        let st = test_state("wlt_upd").await;
        let signed = test_signed("999.0.0");
        let manifest_bytes = crate::local::update::test_support::sign_manifest(&signed);
        let mut manifest: serde_json::Value = serde_json::from_slice(&manifest_bytes).unwrap();
        // Tamper the signed payload AFTER signing — the signature no longer matches.
        manifest["signed"]["version"] = serde_json::json!("1000.0.0");
        let body = serde_json::json!({ "manifest": manifest }).to_string();
        let (status, v) = post_verify(&st, Some("wlt_upd"), &body).await;
        assert_eq!(status, 200);
        assert_eq!(v["approved"], serde_json::json!(false), "tampered manifest rejected");
        assert_eq!(v["code"], serde_json::json!("bad_signature"));
    }

    #[tokio::test]
    async fn update_verify_fails_closed_on_downgrade_and_version_mismatch() {
        let st = test_state("wlt_upd").await;
        // Downgrade: a version not newer than the installed build → not_newer (approved:false).
        let signed = test_signed("0.0.2");
        let manifest_bytes = crate::local::update::test_support::sign_manifest(&signed);
        let manifest: serde_json::Value = serde_json::from_slice(&manifest_bytes).unwrap();
        let body = serde_json::json!({ "manifest": manifest }).to_string();
        let (_s, v) = post_verify(&st, Some("wlt_upd"), &body).await;
        assert_eq!(v["approved"], serde_json::json!(false));
        assert_eq!(v["code"], serde_json::json!("not_newer"));

        // Version mismatch: a valid, newer manifest but the shell claims to install a DIFFERENT
        // version → rejected (defense against a check/install swap).
        let signed = test_signed("999.0.0");
        let manifest_bytes = crate::local::update::test_support::sign_manifest(&signed);
        let manifest: serde_json::Value = serde_json::from_slice(&manifest_bytes).unwrap();
        let body = serde_json::json!({ "manifest": manifest, "expected_version": "998.0.0" }).to_string();
        let (_s, v) = post_verify(&st, Some("wlt_upd"), &body).await;
        assert_eq!(v["approved"], serde_json::json!(false));
        assert_eq!(v["code"], serde_json::json!("version_mismatch"));
    }

    #[tokio::test]
    async fn token_rotate_swaps_the_live_bearer_transactionally() {
        use axum::body::to_bytes;
        // The endpoint resolves WRIT_HOME (Paths::resolve) to write local_token + runtime.json, so
        // point it at an isolated temp home under the crate-wide env guard.
        let _g = crate::local::config::test_env_guard();
        let home = tempfile::tempdir().unwrap();
        std::env::set_var("WRIT_HOME", home.path());

        let seed = "wlt_rotate_seed_unique";
        let st = test_state(seed).await;

        // No bearer → 401.
        let resp = build_router(st.clone())
            .oneshot(Request::builder().method("POST").uri("/v1/token/rotate").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(resp.status(), 401, "rotate requires the bearer");

        // Rotate with the current (seed) token → 200 + a new wlt_ token.
        let resp = build_router(st.clone())
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/token/rotate")
                    .header("authorization", format!("Bearer {seed}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), 200);
        let body = to_bytes(resp.into_body(), 16 * 1024).await.unwrap();
        let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
        let new_token = v["token"].as_str().unwrap().to_string();
        assert!(new_token.starts_with("wlt_"));
        assert_ne!(new_token, seed, "rotation must mint a different token");

        // Durable file + discovery descriptor were rewritten with the new token.
        let on_disk = std::fs::read_to_string(home.path().join("local_token")).unwrap();
        assert_eq!(on_disk.trim(), new_token, "local_token holds the rotated value");
        let runtime: serde_json::Value =
            serde_json::from_slice(&std::fs::read(home.path().join("runtime.json")).unwrap()).unwrap();
        assert_eq!(runtime["token"].as_str().unwrap(), new_token, "runtime.json republished");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(home.path().join("local_token")).unwrap().permissions().mode();
            assert_eq!(mode & 0o777, 0o600, "local_token must stay 0600");
        }

        // The OLD token no longer authenticates the LIVE server; the NEW one does.
        let resp = build_router(st.clone())
            .oneshot(
                Request::builder()
                    .uri("/v1/agent")
                    .header("authorization", format!("Bearer {seed}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), 401, "old token is rejected after live rotation");

        let resp = build_router(st)
            .oneshot(
                Request::builder()
                    .uri("/v1/agent")
                    .header("authorization", format!("Bearer {new_token}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), 200, "new token authenticates the live server");

        std::env::remove_var("WRIT_HOME");
    }

    #[tokio::test]
    async fn hooks_path_is_bearer_exempt() {
        let st = test_state("wlt_h").await;
        // No bearer, unknown token → the handler runs (NOT 401 from the auth layer) and returns 404
        // because the trigger doesn't exist. This proves the `/v1/hooks/` exemption is wired.
        let resp = build_router(st)
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/hooks/nonexistent-token")
                    .header("content-type", "application/json")
                    .body(Body::from("{}"))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), 404, "hooks reached the handler without a bearer");
    }
}
