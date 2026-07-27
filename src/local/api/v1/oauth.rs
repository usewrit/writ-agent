//! Local OAuth 2.1 authorization server — for MCP-capable AI apps that only speak OAuth.
//!
//! Several MCP hosts (and OpenAI-compat "custom connector" UIs) have NO api-key field: they run the
//! spec discovery dance instead. This module makes the daemon its own tiny authorization server so
//! those clients can mint a scoped local bearer without the user ever copying a key:
//!
//!   GET  /.well-known/oauth-protected-resource[/mcp] — RFC 9728: which AS protects this resource
//!   GET  /.well-known/oauth-authorization-server[/mcp] — RFC 8414: AS endpoints + capabilities
//!   POST /oauth/register  — RFC 7591 dynamic client registration (public clients, NO secret)
//!   GET  /oauth/authorize — authorization-code + PKCE (S256 ONLY); renders a local consent page
//!   POST /oauth/consent   — the consent form target (same-origin; loopback guard applies)
//!   POST /oauth/token     — code + refresh grants; mints `wlo_` access / `wrt_` refresh tokens
//!
//! Security model: everything is loopback (or the user's explicit LAN exposure) and the flow ends
//! in a USER CLICK on the consent page — same trust boundary as the 0600 runtime descriptor (any
//! same-user process could read that instead; OAuth here is about CLIENT UX, not new privilege).
//! Tokens are hash-stored (sha256, like `wlk_`), scope-gated through the same `auth::Scope` chain
//! (granted scope: `run`), expiring, and refresh-rotated. These routes are BEARER-EXEMPT in
//! `server::auth_mw` (they exist to mint the bearer) but stay behind the Origin/Host DNS-rebind
//! guard. NEVER log a raw code/token.

use crate::local::auth;
use crate::local::config::LocalConfig;
use crate::local::error::LocalResult;
use crate::local::server::AppState;
use crate::local::store::oauth as store;
use axum::extract::{Host, Query, State};
use axum::http::{header, StatusCode};
use axum::response::{Html, IntoResponse, Redirect, Response};
use axum::routing::{get, post};
use axum::{Form, Json, Router};
use base64::Engine;
use rand::RngCore;
use serde::Deserialize;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::sync::Mutex;

/// Mount the discovery + OAuth routes. `server::auth_mw` exempts `/oauth/*` and `/.well-known/*`
/// from the bearer (Origin/Host guard still applies).
pub fn router() -> Router<AppState> {
    Router::new()
        .route("/.well-known/oauth-protected-resource", get(protected_resource))
        .route("/.well-known/oauth-protected-resource/mcp", get(protected_resource))
        .route("/.well-known/oauth-authorization-server", get(as_metadata))
        .route("/.well-known/oauth-authorization-server/mcp", get(as_metadata))
        .route("/oauth/register", post(register))
        .route("/oauth/authorize", get(authorize))
        .route("/oauth/consent", post(consent))
        .route("/oauth/token", post(token))
}

/// Access-token lifetime (7 days) and refresh lifetime (90 days, rotated on every refresh).
const ACCESS_TTL_SECS: i64 = 7 * 86_400;
const REFRESH_TTL_SECS: i64 = 90 * 86_400;
/// Authorization codes are single-use and short-lived.
const CODE_TTL_SECS: i64 = 300;
/// Pending consent transactions expire after 10 minutes.
const TXN_TTL_SECS: i64 = 600;
/// Every OAuth grant carries the execute capability (implies `read` via the scope chain) — the
/// same default a freshly minted `wlk_` key gets.
const GRANTED_SCOPE: &str = "run";

fn now_unix() -> i64 {
    chrono::Utc::now().timestamp()
}

fn sha256_hex(bytes: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(bytes);
    h.finalize().iter().map(|b| format!("{b:02x}")).collect()
}

/// 32 bytes of OS entropy, base64url — the raw credential material for ids/codes/tokens.
fn random_token(prefix: &str) -> String {
    let mut b = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut b);
    format!("{prefix}{}", base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(b))
}

/// The origin the CLIENT is talking to, reconstructed from the Host header: scheme is `https` iff
/// the host's port is the TLS lane's port (both lanes serve this router). Fallback: plain loopback.
pub fn base_url_for_host(host: Option<&str>, cfg: &LocalConfig) -> String {
    match host {
        Some(h) if !h.trim().is_empty() => {
            let h = h.trim();
            let https = cfg.tls_port != 0 && h.ends_with(&format!(":{}", cfg.tls_port));
            format!("{}://{}", if https { "https" } else { "http" }, h)
        }
        _ => format!("http://127.0.0.1:{}", cfg.port),
    }
}

/// `GET /.well-known/oauth-protected-resource[/mcp]` — RFC 9728. Points the client at OUR OWN
/// authorization server (same origin).
async fn protected_resource(State(st): State<AppState>, Host(host): Host) -> Json<Value> {
    let base = base_url_for_host(Some(&host), &st.config);
    Json(json!({
        "resource": format!("{base}/mcp"),
        "authorization_servers": [base],
        "bearer_methods_supported": ["header"],
        "scopes_supported": [GRANTED_SCOPE],
        "resource_name": "Writ (local)",
    }))
}

/// `GET /.well-known/oauth-authorization-server[/mcp]` — RFC 8414 metadata. Public clients + PKCE
/// S256 only; no client secrets anywhere.
async fn as_metadata(State(st): State<AppState>, Host(host): Host) -> Json<Value> {
    let base = base_url_for_host(Some(&host), &st.config);
    Json(json!({
        "issuer": base,
        "authorization_endpoint": format!("{base}/oauth/authorize"),
        "token_endpoint": format!("{base}/oauth/token"),
        "registration_endpoint": format!("{base}/oauth/register"),
        "response_types_supported": ["code"],
        "grant_types_supported": ["authorization_code", "refresh_token"],
        "code_challenge_methods_supported": ["S256"],
        "token_endpoint_auth_methods_supported": ["none"],
        "scopes_supported": [GRANTED_SCOPE],
    }))
}

// ── Dynamic client registration (RFC 7591) ───────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
struct RegisterBody {
    redirect_uris: Vec<String>,
    #[serde(default)]
    client_name: Option<String>,
    // Accepted-and-ignored standard fields so strict clients don't fail on extras.
    #[serde(default)]
    #[allow(dead_code)]
    grant_types: Option<Vec<String>>,
    #[serde(default)]
    #[allow(dead_code)]
    response_types: Option<Vec<String>>,
    #[serde(default)]
    #[allow(dead_code)]
    token_endpoint_auth_method: Option<String>,
    #[serde(default)]
    #[allow(dead_code)]
    scope: Option<String>,
}

/// Syntactic gate for a registered redirect URI: absolute (custom app schemes like `claude://…`
/// included — native-app OAuth uses them), no whitespace/fragment, sane length. EXACT string match
/// is enforced at authorize time, so this only needs to reject garbage.
fn redirect_uri_ok(uri: &str) -> bool {
    !uri.is_empty()
        && uri.len() <= 2048
        && uri.contains("://")
        && !uri.contains(char::is_whitespace)
        && !uri.contains('#')
}

/// `POST /oauth/register` — mint a public client id for the presented redirect URIs.
async fn register(State(st): State<AppState>, Json(body): Json<RegisterBody>) -> Response {
    if body.redirect_uris.is_empty()
        || body.redirect_uris.len() > 10
        || !body.redirect_uris.iter().all(|u| redirect_uri_ok(u))
    {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "invalid_redirect_uri", "error_description": "1–10 absolute redirect URIs required"})),
        )
            .into_response();
    }
    let client_name = body
        .client_name
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(|s| s.chars().take(200).collect::<String>());

    let client_id = random_token("wcl_");
    let uris_json = serde_json::to_string(&body.redirect_uris).unwrap_or_else(|_| "[]".into());
    match store::insert_client(&st.db, &client_id, client_name.as_deref(), &uris_json).await {
        Ok(row) => (
            StatusCode::CREATED,
            Json(json!({
                "client_id": row.client_id,
                "client_name": row.client_name,
                "redirect_uris": body.redirect_uris,
                "token_endpoint_auth_method": "none",
                "grant_types": ["authorization_code", "refresh_token"],
                "response_types": ["code"],
            })),
        )
            .into_response(),
        Err(e) => e.into_response(),
    }
}

// ── Authorize + consent ──────────────────────────────────────────────────────────────────────────

/// A consent transaction awaiting the user's click. In-memory on purpose: a daemon restart simply
/// aborts pending flows (the client retries), and nothing secret is at rest.
/// `Debug` is hand-written: `code_challenge` is the PKCE verifier commitment for an in-flight
/// authorization and `state` is client-supplied opaque data. Neither belongs in a log line.
#[derive(Clone)]
struct PendingAuthz {
    client_id: String,
    client_name: String,
    redirect_uri: String,
    code_challenge: String,
    state: Option<String>,
    created_unix: i64,
}

impl std::fmt::Debug for PendingAuthz {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PendingAuthz")
            .field("client_id", &self.client_id)
            .field("client_name", &self.client_name)
            .field("redirect_uri", &self.redirect_uri)
            .field("created_unix", &self.created_unix)
            .field("code_challenge", &"<redacted>")
            .field("state", &self.state.as_ref().map(|_| "<redacted>"))
            .finish()
    }
}

static PENDING: Mutex<Option<HashMap<String, PendingAuthz>>> = Mutex::new(None);

fn pending_insert(txn: String, p: PendingAuthz) {
    let mut guard = PENDING.lock().unwrap();
    let map = guard.get_or_insert_with(HashMap::new);
    // Opportunistic expiry sweep — the map only ever holds in-flight consents.
    let now = now_unix();
    map.retain(|_, v| now - v.created_unix < TXN_TTL_SECS);
    map.insert(txn, p);
}

fn pending_take(txn: &str) -> Option<PendingAuthz> {
    let mut guard = PENDING.lock().unwrap();
    let map = guard.get_or_insert_with(HashMap::new);
    let p = map.remove(txn)?;
    (now_unix() - p.created_unix < TXN_TTL_SECS).then_some(p)
}

/// `Debug` is hand-written: `code_challenge` binds the eventual token exchange and `state` is
/// client-opaque data that has historically carried session identifiers.
#[derive(Deserialize)]
struct AuthorizeQuery {
    #[serde(default)]
    response_type: Option<String>,
    #[serde(default)]
    client_id: Option<String>,
    #[serde(default)]
    redirect_uri: Option<String>,
    #[serde(default)]
    code_challenge: Option<String>,
    #[serde(default)]
    code_challenge_method: Option<String>,
    #[serde(default)]
    state: Option<String>,
    // Accepted-and-ignored: scope (we always grant `run`), resource (RFC 8707 audience).
    #[serde(default)]
    #[allow(dead_code)]
    scope: Option<String>,
    #[serde(default)]
    #[allow(dead_code)]
    resource: Option<String>,
}

impl std::fmt::Debug for AuthorizeQuery {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AuthorizeQuery")
            .field("response_type", &self.response_type)
            .field("client_id", &self.client_id)
            .field("redirect_uri", &self.redirect_uri)
            .field("code_challenge_method", &self.code_challenge_method)
            .field("scope", &self.scope)
            .field("resource", &self.resource)
            .field("code_challenge", &self.code_challenge.as_ref().map(|_| "<redacted>"))
            .field("state", &self.state.as_ref().map(|_| "<redacted>"))
            .finish()
    }
}

fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;").replace('"', "&quot;")
}

/// Anti-framing headers for every HTML page this module serves.
///
/// The consent page is the ONE place in the product where a click grants a client a real local
/// credential, so it must never be renderable inside someone else's document. Loopback pages ARE
/// framable from an HTTPS origin (the DNS-rebind Origin/Host guard in `server::auth_mw` inspects the
/// request's Origin — it does not stop a remote page from putting `http://127.0.0.1:8131/...` in an
/// `<iframe>`), which is the classic setup for clickjacking a hidden Approve button.
///
/// Both headers, on purpose: `frame-ancestors 'none'` is the modern directive, `X-Frame-Options: DENY`
/// covers anything that does not implement it. `default-src 'none'`/`style-src 'unsafe-inline'` also
/// pins the page to its own inline content: it loads no script, no font, no image, and cannot be made
/// to — so an injected reference would fetch nothing. `form-action 'self'` keeps the Approve/Deny POST
/// on this origin.
fn html_page_headers() -> [(header::HeaderName, &'static str); 2] {
    [
        (header::X_FRAME_OPTIONS, "DENY"),
        (
            header::CONTENT_SECURITY_POLICY,
            "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; \
             frame-ancestors 'none'; base-uri 'none'",
        ),
    ]
}

/// A terminal error PAGE (used when we must NOT redirect: unknown client / unregistered URI).
fn authz_error_page(msg: &str) -> Response {
    (
        StatusCode::BAD_REQUEST,
        html_page_headers(),
        Html(format!(
            "<!doctype html><meta charset=\"utf-8\"><title>Writ — authorization error</title>\
             <body style=\"font-family:system-ui;margin:4rem auto;max-width:28rem\">\
             <h2>Can’t authorize</h2><p>{}</p></body>",
            html_escape(msg)
        )),
    )
        .into_response()
}

/// `GET /oauth/authorize` — validate the request, park it as a pending transaction, and render the
/// consent page. Errors on client identity/redirect are PAGES (never redirect an unvalidated URI);
/// later errors redirect per RFC 6749 §4.1.2.1.
async fn authorize(State(st): State<AppState>, Query(q): Query<AuthorizeQuery>) -> LocalResult<Response> {
    // Client + redirect URI first: these decide whether redirecting is safe at all.
    let client_id = match q.client_id.as_deref().filter(|s| !s.is_empty()) {
        Some(c) => c,
        None => return Ok(authz_error_page("Missing client_id.")),
    };
    let client = match store::get_client(&st.db, client_id).await? {
        Some(c) => c,
        None => return Ok(authz_error_page("Unknown client. Register first (POST /oauth/register).")),
    };
    let registered: Vec<String> = serde_json::from_str(&client.redirect_uris).unwrap_or_default();
    let redirect_uri = match q.redirect_uri.as_deref().filter(|s| !s.is_empty()) {
        Some(r) if registered.iter().any(|u| u == r) => r.to_string(),
        Some(_) => return Ok(authz_error_page("redirect_uri is not registered for this client.")),
        None => return Ok(authz_error_page("Missing redirect_uri.")),
    };

    // From here the redirect URI is trusted — spec errors go BACK to the client via redirect.
    let redirect_err = |code: &str, desc: &str| {
        let sep = if redirect_uri.contains('?') { '&' } else { '?' };
        let state = q
            .state
            .as_deref()
            .map(|s| format!("&state={}", urlencode(s)))
            .unwrap_or_default();
        Redirect::to(&format!(
            "{redirect_uri}{sep}error={code}&error_description={}{state}",
            urlencode(desc)
        ))
        .into_response()
    };

    if q.response_type.as_deref() != Some("code") {
        return Ok(redirect_err("unsupported_response_type", "only response_type=code is supported"));
    }
    // OAuth 2.1: PKCE is mandatory; S256 only (plain is rejected).
    let code_challenge = match q.code_challenge.as_deref().filter(|s| !s.is_empty()) {
        Some(c) if q.code_challenge_method.as_deref() == Some("S256") => c.to_string(),
        _ => return Ok(redirect_err("invalid_request", "PKCE with code_challenge_method=S256 is required")),
    };

    let txn = random_token("txn_");
    let client_name = client.client_name.clone().unwrap_or_else(|| "An MCP client".into());
    pending_insert(
        txn.clone(),
        PendingAuthz {
            client_id: client_id.to_string(),
            client_name: client_name.clone(),
            redirect_uri,
            code_challenge,
            state: q.state.clone(),
            created_unix: now_unix(),
        },
    );

    // The consent page: local, self-contained, one decision. The form posts same-origin, so the
    // DNS-rebind Origin guard covers CSRF; the txn id is single-use and short-lived; and
    // `html_page_headers` makes the page unframable so the Approve button cannot be clickjacked.
    let name = html_escape(&client_name);
    Ok((
        html_page_headers(),
        Html(format!(
        r#"<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Writ — connect {name}</title>
<style>
  :root {{ color-scheme: light dark; }}
  body {{ font-family: system-ui, sans-serif; display:flex; min-height:100vh; margin:0; align-items:center; justify-content:center; background:Canvas; color:CanvasText; }}
  .card {{ max-width: 26rem; padding: 2rem 2.25rem; border: 1px solid color-mix(in srgb, CanvasText 15%, transparent); border-radius: 12px; }}
  h1 {{ font-size: 1.15rem; margin: 0 0 .75rem; }}
  p {{ margin: .5rem 0; line-height: 1.45; }}
  .scope {{ font-size:.9rem; padding:.5rem .75rem; border-radius:8px; background: color-mix(in srgb, CanvasText 7%, transparent); }}
  form {{ display:inline; }}
  .row {{ display:flex; gap:.75rem; margin-top:1.5rem; }}
  button {{ flex:1; padding:.6rem 1rem; border-radius:8px; border:1px solid color-mix(in srgb, CanvasText 25%, transparent); background:transparent; color:inherit; font-size:.95rem; cursor:pointer; }}
  button.approve {{ background: CanvasText; color: Canvas; border-color: CanvasText; }}
  small {{ opacity:.65; display:block; margin-top:1.25rem; }}
</style></head><body>
<div class="card">
  <h1>Connect “{name}” to Writ?</h1>
  <p>This app is asking to use your local Writ agent.</p>
  <div class="scope">It will be able to <b>run your workflows and tools</b> and read their results (scope: <code>run</code>). It cannot manage keys, secrets, or device settings.</div>
  <div class="row">
    <form method="post" action="/oauth/consent"><input type="hidden" name="txn" value="{txn}"><input type="hidden" name="action" value="deny"><button type="submit">Deny</button></form>
    <form method="post" action="/oauth/consent"><input type="hidden" name="txn" value="{txn}"><input type="hidden" name="action" value="approve"><button type="submit" class="approve">Approve</button></form>
  </div>
  <small>Writ local agent — this authorization never leaves your machine.</small>
</div></body></html>"#
        )),
    )
        .into_response())
}

/// Percent-encode the small set of characters that matter in a query value. Deliberately minimal
/// (no new dependency): everything unreserved passes through.
fn urlencode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => out.push(b as char),
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

/// `Debug` is hand-written: `txn` addresses a pending consent — presenting it is what approves the
/// authorization, so it is a single-use credential, not an identifier.
#[derive(Deserialize)]
struct ConsentForm {
    txn: String,
    action: String,
}

impl std::fmt::Debug for ConsentForm {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ConsentForm")
            .field("txn", &"<redacted>")
            .field("action", &self.action)
            .finish()
    }
}

/// `POST /oauth/consent` — the user's click. Approve mints a single-use code bound to the PKCE
/// challenge; both outcomes 302 back to the client.
async fn consent(State(st): State<AppState>, Form(f): Form<ConsentForm>) -> LocalResult<Response> {
    let Some(p) = pending_take(&f.txn) else {
        return Ok(authz_error_page("This authorization request expired — retry from the app."));
    };
    let sep = if p.redirect_uri.contains('?') { '&' } else { '?' };
    let state = p.state.as_deref().map(|s| format!("&state={}", urlencode(s))).unwrap_or_default();

    if f.action != "approve" {
        return Ok(Redirect::to(&format!("{}{}error=access_denied{state}", p.redirect_uri, sep)).into_response());
    }

    let code = random_token("wac_");
    store::insert_code(
        &st.db,
        &sha256_hex(code.as_bytes()),
        &p.client_id,
        &p.redirect_uri,
        &p.code_challenge,
        GRANTED_SCOPE,
        now_unix() + CODE_TTL_SECS,
    )
    .await?;
    tracing::info!(client = %p.client_name, "oauth consent approved (code minted)");
    Ok(Redirect::to(&format!("{}{}code={}{state}", p.redirect_uri, sep, urlencode(&code))).into_response())
}

// ── Token endpoint ───────────────────────────────────────────────────────────────────────────────

/// `Debug` is hand-written. Every credential the token endpoint accepts lands in this struct: the
/// authorization `code`, the PKCE `code_verifier`, and the `refresh_token`. A derived `Debug` printed
/// all three verbatim — and this is the one handler where a `tracing` line or an axum rejection message
/// is most likely to format the extracted body.
#[derive(Deserialize)]
struct TokenForm {
    grant_type: String,
    #[serde(default)]
    code: Option<String>,
    #[serde(default)]
    redirect_uri: Option<String>,
    #[serde(default)]
    client_id: Option<String>,
    #[serde(default)]
    code_verifier: Option<String>,
    #[serde(default)]
    refresh_token: Option<String>,
    // Accepted-and-ignored (RFC 8707 audience binding — single-resource server).
    #[serde(default)]
    #[allow(dead_code)]
    resource: Option<String>,
}

impl std::fmt::Debug for TokenForm {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TokenForm")
            .field("grant_type", &self.grant_type)
            .field("client_id", &self.client_id)
            .field("redirect_uri", &self.redirect_uri)
            .field("resource", &self.resource)
            // Presence matters for diagnosing a malformed grant; the values never do.
            .field("code", &self.code.as_ref().map(|_| "<redacted>"))
            .field("code_verifier", &self.code_verifier.as_ref().map(|_| "<redacted>"))
            .field("refresh_token", &self.refresh_token.as_ref().map(|_| "<redacted>"))
            .finish()
    }
}

/// RFC 6749 §5.2-shaped error.
fn token_err(status: StatusCode, code: &str, desc: &str) -> Response {
    (status, Json(json!({ "error": code, "error_description": desc }))).into_response()
}

/// Mint + persist an access/refresh pair **inside the caller's transaction**, returning the
/// RFC 6749 §5.1 success body.
///
/// Takes the transaction rather than the pool because the grant that authorizes this mint has already
/// CONSUMED a single-use credential (an authorization code, or the previous refresh token). Consuming
/// and minting must commit together: as separate autocommit statements, a failure in between revoked
/// the client's only refresh token without issuing a replacement, permanently locking it out of the
/// local API until the user re-ran the whole authorization flow.
async fn mint_pair(
    tx: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
    client_id: &str,
    scope: &str,
) -> LocalResult<Response> {
    let access = random_token("wlo_");
    let refresh = random_token("wrt_");
    let now = now_unix();
    store::insert_token_with(
        &mut **tx,
        &sha256_hex(access.as_bytes()),
        Some(&sha256_hex(refresh.as_bytes())),
        client_id,
        scope,
        now + ACCESS_TTL_SECS,
        Some(now + REFRESH_TTL_SECS),
    )
    .await?;
    Ok((
        StatusCode::OK,
        [(header::CACHE_CONTROL, "no-store")],
        Json(json!({
            "access_token": access,
            "token_type": "Bearer",
            "expires_in": ACCESS_TTL_SECS,
            "refresh_token": refresh,
            "scope": scope,
        })),
    )
        .into_response())
}

/// `POST /oauth/token` — authorization_code (with PKCE proof) and refresh_token (rotating) grants.
///
/// Both grants consume a single-use credential and immediately mint its replacement. That pair runs in
/// ONE transaction so the two can never diverge.
///
/// Note the deliberate `tx.commit()` on the bind-check failure paths: burning the credential when the
/// presented `client_id`/`redirect_uri` does not match what it was issued for is the pre-existing
/// (and correct, fail-closed) behaviour — rolling back there would hand a mismatching caller unlimited
/// retries against a still-live code or refresh token.
async fn token(State(st): State<AppState>, Form(f): Form<TokenForm>) -> LocalResult<Response> {
    let now = now_unix();
    let out = match f.grant_type.as_str() {
        "authorization_code" => {
            let (Some(code), Some(verifier)) = (f.code.as_deref(), f.code_verifier.as_deref()) else {
                return Ok(token_err(StatusCode::BAD_REQUEST, "invalid_request", "code and code_verifier are required"));
            };
            let mut tx = st.db.begin().await?;
            // Single-use claim (replay finds used=1 → invalid_grant).
            let Some(row) = store::take_code_with(&mut *tx, &sha256_hex(code.as_bytes()), now).await? else {
                return Ok(token_err(StatusCode::BAD_REQUEST, "invalid_grant", "code is invalid, expired, or already used"));
            };
            // Bind checks: client + redirect_uri must match what the code was minted for.
            if f.client_id.as_deref() != Some(row.client_id.as_str()) {
                tx.commit().await?; // keep the code burned — see the fn doc
                return Ok(token_err(StatusCode::BAD_REQUEST, "invalid_grant", "client_id mismatch"));
            }
            if let Some(r) = f.redirect_uri.as_deref() {
                if r != row.redirect_uri {
                    tx.commit().await?;
                    return Ok(token_err(StatusCode::BAD_REQUEST, "invalid_grant", "redirect_uri mismatch"));
                }
            }
            // PKCE S256 proof (constant-time compare via the bearer helper).
            let computed = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()));
            if !auth::verify_local_bearer(&computed, &row.code_challenge) {
                tx.commit().await?;
                return Ok(token_err(StatusCode::BAD_REQUEST, "invalid_grant", "PKCE verification failed"));
            }
            let resp = mint_pair(&mut tx, &row.client_id, &row.scope).await?;
            tx.commit().await?;
            resp
        }
        "refresh_token" => {
            let Some(refresh) = f.refresh_token.as_deref() else {
                return Ok(token_err(StatusCode::BAD_REQUEST, "invalid_request", "refresh_token is required"));
            };
            let mut tx = st.db.begin().await?;
            // Rotation: claiming revokes the old pair; the replacement is minted in the SAME
            // transaction, so a client can never end up with neither.
            let Some(row) = store::take_refresh_with(&mut *tx, &sha256_hex(refresh.as_bytes()), now).await? else {
                return Ok(token_err(StatusCode::BAD_REQUEST, "invalid_grant", "refresh token is invalid, expired, or rotated"));
            };
            if let Some(cid) = f.client_id.as_deref() {
                if cid != row.client_id {
                    tx.commit().await?; // keep the old pair revoked — see the fn doc
                    return Ok(token_err(StatusCode::BAD_REQUEST, "invalid_grant", "client_id mismatch"));
                }
            }
            let resp = mint_pair(&mut tx, &row.client_id, &row.scope).await?;
            tx.commit().await?;
            resp
        }
        other => {
            return Ok(token_err(
                StatusCode::BAD_REQUEST,
                "unsupported_grant_type",
                &format!("unsupported grant_type '{other}'"),
            ))
        }
    };
    // Housekeeping only — outside the grant transaction so a purge hiccup can never fail a mint.
    let _ = store::purge_expired(&st.db, now).await;
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::local::config::{LocalConfig, Paths};
    use crate::local::server::build_router;
    use crate::local::{db, engine, vault};
    use axum::body::{to_bytes, Body};
    use axum::http::Request;
    use std::sync::Arc;
    use tower::ServiceExt;

    const TOKEN: &str = "wlt_oauth_secret";

    async fn test_state() -> (tempfile::TempDir, AppState) {
        let dir = tempfile::tempdir().unwrap();
        std::env::set_var("WRIT_HOME", dir.path().join(".writ"));
        let paths = Paths::resolve().unwrap();
        paths.ensure_dirs().unwrap();
        let v = vault::Vault::load_or_create(&paths.root, false).unwrap();
        let pool = db::open(&paths.db(), &v.db_key_hex()).await.unwrap();
        let st = AppState {
            db: pool,
            vault: Arc::new(v),
            engine: Arc::new(engine::StubEngine),
            config: LocalConfig::default(),
            token: Arc::new(TOKEN.to_string()),
            health: crate::local::app::health::DaemonHealth::shared(),
            recorder: None,
        };
        (dir, st)
    }

    async fn send(st: &AppState, req: Request<Body>) -> (u16, Vec<u8>, axum::http::HeaderMap) {
        let resp = build_router(st.clone()).oneshot(req).await.unwrap();
        let status = resp.status().as_u16();
        let headers = resp.headers().clone();
        let bytes = to_bytes(resp.into_body(), 1 << 20).await.unwrap().to_vec();
        (status, bytes, headers)
    }

    fn jget(bytes: &[u8]) -> Value {
        serde_json::from_slice(bytes).unwrap()
    }

    /// Extract `name="txn" value="..."` from the consent HTML.
    fn txn_from_html(html: &str) -> String {
        let marker = "name=\"txn\" value=\"";
        let start = html.find(marker).expect("txn field in consent page") + marker.len();
        html[start..].split('"').next().unwrap().to_string()
    }

    fn query_param(url: &str, key: &str) -> Option<String> {
        let qs = url.split_once('?')?.1;
        qs.split('&').find_map(|kv| {
            let (k, v) = kv.split_once('=')?;
            (k == key).then(|| v.to_string())
        })
    }

    /// The full spec dance a real MCP host runs: discovery → DCR → authorize → consent → token →
    /// authenticated API call with the minted wlo_ bearer → refresh rotation → replay rejection.
    #[tokio::test]
    async fn full_oauth_flow_end_to_end() {
        let _g = crate::local::config::test_env_guard();
        let (_dir, st) = test_state().await;

        // Discovery is bearer-exempt.
        let (code, body, _) = send(
            &st,
            Request::builder()
                .uri("/.well-known/oauth-authorization-server")
                .header("host", "127.0.0.1:8131")
                .body(Body::empty())
                .unwrap(),
        )
        .await;
        assert_eq!(code, 200, "AS metadata must not require a bearer");
        let meta = jget(&body);
        assert_eq!(meta["issuer"], json!("http://127.0.0.1:8131"));
        assert_eq!(meta["code_challenge_methods_supported"], json!(["S256"]));

        let (code, body, _) = send(
            &st,
            Request::builder()
                .uri("/.well-known/oauth-protected-resource/mcp")
                .header("host", "127.0.0.1:8131")
                .body(Body::empty())
                .unwrap(),
        )
        .await;
        assert_eq!(code, 200);
        assert_eq!(jget(&body)["resource"], json!("http://127.0.0.1:8131/mcp"));

        // Dynamic client registration.
        let (code, body, _) = send(
            &st,
            Request::builder()
                .method("POST")
                .uri("/oauth/register")
                .header("content-type", "application/json")
                .body(Body::from(
                    r#"{"redirect_uris":["http://127.0.0.1:33418/callback"],"client_name":"Test MCP Host"}"#,
                ))
                .unwrap(),
        )
        .await;
        assert_eq!(code, 201, "{}", String::from_utf8_lossy(&body));
        let client_id = jget(&body)["client_id"].as_str().unwrap().to_string();
        assert!(client_id.starts_with("wcl_"));

        // Authorize with PKCE (S256).
        let verifier = "test-verifier-string-that-is-long-enough-123456";
        let challenge = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(Sha256::digest(verifier.as_bytes()));
        let (code_http, body, _) = send(
            &st,
            Request::builder()
                .uri(format!(
                    "/oauth/authorize?response_type=code&client_id={client_id}&redirect_uri=http%3A%2F%2F127.0.0.1%3A33418%2Fcallback&code_challenge={challenge}&code_challenge_method=S256&state=xyz123"
                ))
                .header("host", "127.0.0.1:8131")
                .body(Body::empty())
                .unwrap(),
        )
        .await;
        assert_eq!(code_http, 200);
        let html = String::from_utf8_lossy(&body).to_string();
        assert!(html.contains("Test MCP Host"), "consent names the client");
        let txn = txn_from_html(&html);

        // Approve → 302 with code + state.
        let (code_http, _, headers) = send(
            &st,
            Request::builder()
                .method("POST")
                .uri("/oauth/consent")
                .header("content-type", "application/x-www-form-urlencoded")
                .body(Body::from(format!("txn={txn}&action=approve")))
                .unwrap(),
        )
        .await;
        assert_eq!(code_http, 303, "axum Redirect::to uses 303 See Other");
        let loc = headers.get("location").unwrap().to_str().unwrap().to_string();
        assert!(loc.starts_with("http://127.0.0.1:33418/callback?"), "loc={loc}");
        assert_eq!(query_param(&loc, "state").as_deref(), Some("xyz123"));
        let auth_code = query_param(&loc, "code").unwrap();

        // Token exchange (correct PKCE).
        let (code_http, body, _) = send(
            &st,
            Request::builder()
                .method("POST")
                .uri("/oauth/token")
                .header("content-type", "application/x-www-form-urlencoded")
                .body(Body::from(format!(
                    "grant_type=authorization_code&code={auth_code}&client_id={client_id}&redirect_uri=http%3A%2F%2F127.0.0.1%3A33418%2Fcallback&code_verifier={verifier}"
                )))
                .unwrap(),
        )
        .await;
        assert_eq!(code_http, 200, "{}", String::from_utf8_lossy(&body));
        let tok = jget(&body);
        let access = tok["access_token"].as_str().unwrap().to_string();
        let refresh = tok["refresh_token"].as_str().unwrap().to_string();
        assert!(access.starts_with("wlo_"));
        assert_eq!(tok["token_type"], json!("Bearer"));

        // The minted bearer authenticates a real API call (read via the run-scope chain).
        let (code_http, body, _) = send(
            &st,
            Request::builder()
                .uri("/v1/agent")
                .header("authorization", format!("Bearer {access}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await;
        assert_eq!(code_http, 200, "wlo_ bearer works: {}", String::from_utf8_lossy(&body));

        // …and the MCP surface itself.
        let (code_http, body, _) = send(
            &st,
            Request::builder()
                .method("POST")
                .uri("/mcp")
                .header("authorization", format!("Bearer {access}"))
                .header("content-type", "application/json")
                .body(Body::from(r#"{"jsonrpc":"2.0","id":1,"method":"initialize"}"#))
                .unwrap(),
        )
        .await;
        assert_eq!(code_http, 200, "wlo_ bearer opens /mcp: {}", String::from_utf8_lossy(&body));

        // Code replay is rejected (single-use).
        let (code_http, body, _) = send(
            &st,
            Request::builder()
                .method("POST")
                .uri("/oauth/token")
                .header("content-type", "application/x-www-form-urlencoded")
                .body(Body::from(format!(
                    "grant_type=authorization_code&code={auth_code}&client_id={client_id}&code_verifier={verifier}"
                )))
                .unwrap(),
        )
        .await;
        assert_eq!(code_http, 400);
        assert_eq!(jget(&body)["error"], json!("invalid_grant"));

        // Refresh rotation: new pair, old refresh dead, old access revoked.
        let (code_http, body, _) = send(
            &st,
            Request::builder()
                .method("POST")
                .uri("/oauth/token")
                .header("content-type", "application/x-www-form-urlencoded")
                .body(Body::from(format!("grant_type=refresh_token&refresh_token={refresh}&client_id={client_id}")))
                .unwrap(),
        )
        .await;
        assert_eq!(code_http, 200, "{}", String::from_utf8_lossy(&body));
        let access2 = jget(&body)["access_token"].as_str().unwrap().to_string();
        assert_ne!(access, access2);

        let (replay, _, _) = send(
            &st,
            Request::builder()
                .method("POST")
                .uri("/oauth/token")
                .header("content-type", "application/x-www-form-urlencoded")
                .body(Body::from(format!("grant_type=refresh_token&refresh_token={refresh}&client_id={client_id}")))
                .unwrap(),
        )
        .await;
        assert_eq!(replay, 400, "rotated refresh token must be dead");

        let (old_access, _, _) = send(
            &st,
            Request::builder()
                .uri("/v1/agent")
                .header("authorization", format!("Bearer {access}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await;
        assert_eq!(old_access, 401, "rotation revokes the old access token");

        std::env::remove_var("WRIT_HOME");
    }

    #[tokio::test]
    async fn pkce_mismatch_and_scope_ceiling() {
        let _g = crate::local::config::test_env_guard();
        let (_dir, st) = test_state().await;

        // Register + authorize + approve with challenge for verifier A…
        let (_, body, _) = send(
            &st,
            Request::builder()
                .method("POST")
                .uri("/oauth/register")
                .header("content-type", "application/json")
                .body(Body::from(r#"{"redirect_uris":["myapp://cb"]}"#))
                .unwrap(),
        )
        .await;
        let client_id = jget(&body)["client_id"].as_str().unwrap().to_string();
        let challenge =
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(Sha256::digest(b"verifier-A"));
        let (_, body, _) = send(
            &st,
            Request::builder()
                .uri(format!(
                    "/oauth/authorize?response_type=code&client_id={client_id}&redirect_uri=myapp%3A%2F%2Fcb&code_challenge={challenge}&code_challenge_method=S256"
                ))
                .header("host", "127.0.0.1:8131")
                .body(Body::empty())
                .unwrap(),
        )
        .await;
        let txn = txn_from_html(&String::from_utf8_lossy(&body));
        let (_, _, headers) = send(
            &st,
            Request::builder()
                .method("POST")
                .uri("/oauth/consent")
                .header("content-type", "application/x-www-form-urlencoded")
                .body(Body::from(format!("txn={txn}&action=approve")))
                .unwrap(),
        )
        .await;
        let loc = headers.get("location").unwrap().to_str().unwrap().to_string();
        let auth_code = query_param(&loc, "code").unwrap();

        // …then present verifier B → invalid_grant, and the code is consumed (no second chance).
        let (code_http, body, _) = send(
            &st,
            Request::builder()
                .method("POST")
                .uri("/oauth/token")
                .header("content-type", "application/x-www-form-urlencoded")
                .body(Body::from(format!(
                    "grant_type=authorization_code&code={auth_code}&client_id={client_id}&code_verifier=verifier-B"
                )))
                .unwrap(),
        )
        .await;
        assert_eq!(code_http, 400);
        assert_eq!(jget(&body)["error"], json!("invalid_grant"));

        // Scope ceiling: a wlo_ token holds `run` — device-management (Manage) must 401/403.
        // (Mint a pair directly through the store to skip a second consent dance.)
        let now = chrono::Utc::now().timestamp();
        crate::local::store::oauth::insert_token(
            &st.db,
            &sha256_hex(b"wlo_direct-access"),
            None,
            &client_id,
            "run",
            now + 3600,
            None,
        )
        .await
        .unwrap();
        // sha256_hex of the RAW bearer is looked up, so present the raw value we hashed.
        let (code_http, _, _) = send(
            &st,
            Request::builder()
                .method("POST")
                .uri("/v1/keys")
                .header("authorization", "Bearer wlo_direct-access")
                .header("content-type", "application/json")
                .body(Body::from(r#"{"name":"escalation"}"#))
                .unwrap(),
        )
        .await;
        assert_eq!(code_http, 403, "run-scoped wlo_ token must not reach device management");

        std::env::remove_var("WRIT_HOME");
    }

    /// The consent page must not be framable: it is the only click in the product that hands out a
    /// local credential, and loopback pages ARE reachable from a remote HTTPS document's `<iframe>`.
    #[tokio::test]
    async fn consent_page_is_not_framable() {
        let _g = crate::local::config::test_env_guard();
        let (_dir, st) = test_state().await;

        let (_, body, _) = send(
            &st,
            Request::builder()
                .method("POST")
                .uri("/oauth/register")
                .header("content-type", "application/json")
                .body(Body::from(r#"{"redirect_uris":["myapp://cb"],"client_name":"Framed"}"#))
                .unwrap(),
        )
        .await;
        let client_id = jget(&body)["client_id"].as_str().unwrap().to_string();
        let challenge =
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(Sha256::digest(b"verifier"));
        let (code, _body, headers) = send(
            &st,
            Request::builder()
                .uri(format!(
                    "/oauth/authorize?response_type=code&client_id={client_id}&redirect_uri=myapp%3A%2F%2Fcb&code_challenge={challenge}&code_challenge_method=S256"
                ))
                .header("host", "127.0.0.1:8131")
                .body(Body::empty())
                .unwrap(),
        )
        .await;
        assert_eq!(code, 200);
        assert_eq!(headers.get("x-frame-options").unwrap(), "DENY");
        let csp = headers.get("content-security-policy").unwrap().to_str().unwrap();
        assert!(csp.contains("frame-ancestors 'none'"), "csp={csp}");
        assert!(csp.contains("form-action 'self'"), "csp={csp}");

        // The terminal error page carries them too (it is served on the same origin).
        let (code, _b, headers) = send(
            &st,
            Request::builder()
                .uri("/oauth/authorize?response_type=code&client_id=wcl_nope&redirect_uri=myapp%3A%2F%2Fcb&code_challenge=x&code_challenge_method=S256")
                .header("host", "127.0.0.1:8131")
                .body(Body::empty())
                .unwrap(),
        )
        .await;
        assert_eq!(code, 400);
        assert_eq!(headers.get("x-frame-options").unwrap(), "DENY");

        std::env::remove_var("WRIT_HOME");
    }

    #[tokio::test]
    async fn deny_and_error_paths() {
        let _g = crate::local::config::test_env_guard();
        let (_dir, st) = test_state().await;

        // Unknown client → error PAGE (no redirect).
        let (code, body, _) = send(
            &st,
            Request::builder()
                .uri("/oauth/authorize?response_type=code&client_id=wcl_nope&redirect_uri=myapp%3A%2F%2Fcb&code_challenge=x&code_challenge_method=S256")
                .header("host", "127.0.0.1:8131")
                .body(Body::empty())
                .unwrap(),
        )
        .await;
        assert_eq!(code, 400);
        assert!(String::from_utf8_lossy(&body).contains("Unknown client"));

        // Registered client, DENY → error=access_denied redirect.
        let (_, body, _) = send(
            &st,
            Request::builder()
                .method("POST")
                .uri("/oauth/register")
                .header("content-type", "application/json")
                .body(Body::from(r#"{"redirect_uris":["myapp://cb"],"client_name":"D"}"#))
                .unwrap(),
        )
        .await;
        let client_id = jget(&body)["client_id"].as_str().unwrap().to_string();
        let (_, body, _) = send(
            &st,
            Request::builder()
                .uri(format!(
                    "/oauth/authorize?response_type=code&client_id={client_id}&redirect_uri=myapp%3A%2F%2Fcb&code_challenge=abc&code_challenge_method=S256"
                ))
                .header("host", "127.0.0.1:8131")
                .body(Body::empty())
                .unwrap(),
        )
        .await;
        let txn = txn_from_html(&String::from_utf8_lossy(&body));
        let (code, _, headers) = send(
            &st,
            Request::builder()
                .method("POST")
                .uri("/oauth/consent")
                .header("content-type", "application/x-www-form-urlencoded")
                .body(Body::from(format!("txn={txn}&action=deny")))
                .unwrap(),
        )
        .await;
        assert_eq!(code, 303);
        let loc = headers.get("location").unwrap().to_str().unwrap();
        assert!(loc.contains("error=access_denied"), "loc={loc}");

        // Missing PKCE → redirected spec error (redirect_uri IS registered).
        let (code, _, headers) = send(
            &st,
            Request::builder()
                .uri(format!(
                    "/oauth/authorize?response_type=code&client_id={client_id}&redirect_uri=myapp%3A%2F%2Fcb"
                ))
                .header("host", "127.0.0.1:8131")
                .body(Body::empty())
                .unwrap(),
        )
        .await;
        assert_eq!(code, 303);
        assert!(headers.get("location").unwrap().to_str().unwrap().contains("error=invalid_request"));

        std::env::remove_var("WRIT_HOME");
    }
}
