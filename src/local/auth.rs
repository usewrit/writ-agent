//! Local API auth — loopback-only bearer (`wlt_` UI token or a `wlk_` scoped key) + an
//! Origin/Host allowlist (DNS-rebinding defense). Constant-time compare; NO JWT/Claims — cloud
//! account tokens (`wto_`/`wtr_`/`wte_`) are NOT accepted here. See the local-backend spec §7.

/// Constant-time byte equality (no early return on length-equal inputs).
pub fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

/// Verify a presented bearer against the runtime `wlt_` token (constant-time).
pub fn verify_local_bearer(presented: &str, token: &str) -> bool {
    ct_eq(presented.as_bytes(), token.as_bytes())
}

/// Allow only loopback origins/hosts. Blocks DNS-rebinding from a browser page.
///
/// This is the LOOPBACK-ONLY matcher (used directly by the WS-connect guard, which is never LAN
/// exposed). For the LAN-exposed daemon use [`origin_allowed_for`], which folds these loopback
/// values in and ADDS the bind/LAN host only when the operator opted into exposure.
pub fn origin_allowed(value: &str, port: u16) -> bool {
    // Port-agnostic: any LOOPBACK authority is accepted regardless of port (see
    // `is_loopback_authority`). `port` is retained for signature stability with
    // the LAN-aware `origin_allowed_for`, which still needs it for the bind host.
    let _ = port;
    let v = value.trim();
    // Packaged Tauri webview custom-protocol origins:
    //   macOS:          tauri://localhost
    //   Windows/Linux:  http(s)://tauri.localhost
    if v == "tauri://localhost" || v == "http://tauri.localhost" || v == "https://tauri.localhost" {
        return true;
    }
    // Any loopback authority, on ANY port. The daemon is loopback-only and the
    // bearer token is the real gate; this matcher exists for DNS-rebind defense,
    // whose threat is a FOREIGN origin (e.g. `http://evil.example`) that rebinds
    // its domain to 127.0.0.1 — the browser still sends the attacker's DOMAIN as
    // the Origin, never a loopback host, so it is rejected. Accepting any loopback
    // PORT is what lets the Tauri dev server (`http://localhost:5173` under
    // `tauri:dev`) and the local CLI reach the daemon without pinning to the
    // runtime port.
    is_loopback_authority(v)
}

/// True when `value` (an `Origin` like `scheme://host:port` or a bare `Host` like
/// `host:port`) resolves to a loopback host, on ANY port. Only `http`/`https`/
/// scheme-less authorities qualify; any other scheme (`file:`, a foreign custom
/// protocol, …) is rejected. IPv6 literals (`[::1]`) are handled.
fn is_loopback_authority(value: &str) -> bool {
    let v = value.trim();
    let authority = match v.strip_prefix("http://").or_else(|| v.strip_prefix("https://")) {
        Some(rest) => rest,
        // Scheme-less Host header (`host:port`) is fine; anything that still
        // carries a `scheme://` delimiter is a non-http scheme → reject.
        None if !v.contains("://") => v,
        None => return false,
    };
    // Defensive: drop any path/query/fragment (an Origin/Host shouldn't carry one).
    let authority = authority.split(['/', '?', '#']).next().unwrap_or(authority);
    let host = if let Some(rest) = authority.strip_prefix('[') {
        // IPv6 literal: `[::1]:port` → `::1`.
        match rest.split(']').next() {
            Some(h) => h,
            None => return false,
        }
    } else {
        authority.split(':').next().unwrap_or(authority)
    };
    let host = host.to_ascii_lowercase();
    host == "127.0.0.1" || host == "localhost" || host == "::1"
}

/// Origin/Host allowlist that is aware of LAN exposure.
///
/// Loopback values are ALWAYS accepted (so the local UI and CLI keep working in either mode). When
/// `exposed` is true we ADDITIONALLY accept the daemon's own bind/LAN host(s) — passed in as
/// `lan_hosts` (the best-effort local IPs / configured bind host, WITHOUT a port) — so a same-origin
/// browser page or an API client reaching us over the LAN passes. We do this in BOTH the `host:port`
/// (Host header) and `http://host:port` (Origin header) shapes.
///
/// This preserves DNS-rebind protection: a foreign browser `Origin` (e.g. `http://evil.example`)
/// never matches our loopback values NOR our own LAN IP, so it is rejected even when exposed. Only a
/// request whose Origin/Host is loopback or literally our own bind address is allowed; a request with
/// NO Origin (a non-browser API client) is handled by the caller (it simply has nothing to check).
pub fn origin_allowed_for(value: &str, port: u16, exposed: bool, lan_hosts: &[String]) -> bool {
    if origin_allowed(value, port) {
        return true;
    }
    if !exposed {
        return false;
    }
    let v = value.trim();
    lan_hosts.iter().any(|h| {
        let h = h.trim();
        !h.is_empty()
            && (v == format!("{h}:{port}")
                || v == format!("http://{h}:{port}")
                || v == format!("https://{h}:{port}"))
    })
}

/// Extract a bearer token from an `Authorization: Bearer <t>` header value.
pub fn parse_bearer(header: &str) -> Option<&str> {
    header.strip_prefix("Bearer ").map(str::trim)
}

/// Authorize a loopback WebSocket connect (`/ws/record`). A browser CANNOT set an `Authorization`
/// header on a WebSocket, so the full-access `wlt_` UI token rides in a `?token=` query param and is
/// constant-time compared to the daemon's runtime token. The same loopback Origin/Host allowlist the
/// header-bearer middleware enforces is applied here too (DNS-rebind defense): if an `Origin` or
/// `Host` is present it must be loopback. Returns true only when BOTH the token matches AND the
/// origin/host (when present) is allowed. NEVER logs the presented token.
pub fn ws_connect_authorized(
    presented_token: Option<&str>,
    origin: Option<&str>,
    host: Option<&str>,
    runtime_token: &str,
    port: u16,
) -> bool {
    // Loopback Origin/Host guard — reject a cross-origin upgrade attempt up front.
    if let Some(o) = origin {
        if !origin_allowed(o, port) {
            return false;
        }
    }
    if let Some(h) = host {
        if !origin_allowed(h, port) {
            return false;
        }
    }
    // Constant-time token compare. An empty/absent token never matches.
    match presented_token {
        Some(t) if !t.is_empty() => verify_local_bearer(t, runtime_token),
        _ => false,
    }
}

/// The loopback Origin/Host guard for a WebSocket upgrade, WITHOUT the token check. A browser can't
/// set an `Authorization` header on a WS, so the credential now rides as a single-use `?ticket=`
/// (see [`crate::local::ws_ticket`]) consumed by the handler; this remains the DNS-rebind defense
/// applied before the upgrade. Returns true only when any present `Origin`/`Host` is loopback.
pub fn ws_origin_allowed(origin: Option<&str>, host: Option<&str>, port: u16) -> bool {
    if let Some(o) = origin {
        if !origin_allowed(o, port) {
            return false;
        }
    }
    if let Some(h) = host {
        if !origin_allowed(h, port) {
            return false;
        }
    }
    true
}

/// The capability a request requires of a scoped `wlk_` key. The `wlt_` UI token is full-access and
/// never goes through this gate. Derived from the HTTP method + path so the scope model is uniform
/// across every mounted resource (REST `/v1`, MCP-over-HTTP, OpenAI-compat).
///
/// SECURITY — device control vs. resource CRUD (AC-2): `Admin` covers ordinary resource mutations
/// (create/update/delete a workflow/monitor/persona, edit secrets, cloud link/sync). It DOES NOT
/// grant `Manage`, which gates the small set of routes that hand over control of the DEVICE ITSELF —
/// turning off the app-lock, resetting/restoring all data, minting/revoking API keys, exposing the
/// daemon on the LAN, unlinking the cloud account. Those are things a mundane "create a workflow"
/// key must never be able to do just because it happened to be scoped `admin`. `Manage` is a
/// SEPARATE, explicitly-granted capability (see [`scope_grants`]): `admin` does NOT imply it, so an
/// external `wlk_` key reaches the device-control routes only if it was deliberately issued `manage`.
/// The in-app Tauri `wlt_` token bypasses this gate entirely and keeps full control.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Scope {
    /// Pure reads — `GET` requests.
    Read,
    /// Executing a workflow/tool — the `/run` + MCP/OpenAI execute surfaces.
    Run,
    /// Ordinary resource mutations (create/update/delete, secret/persona management, cloud link/sync).
    Admin,
    /// Device-control routes (vault app-lock, data reset/restore, key issuance, LAN expose, cloud
    /// unlink). NOT implied by `admin` — must be granted explicitly.
    Manage,
}

impl Scope {
    /// The CSV token this scope is named by in `local_api_keys.scopes`.
    pub fn as_str(self) -> &'static str {
        match self {
            Scope::Read => "read",
            Scope::Run => "run",
            Scope::Admin => "admin",
            Scope::Manage => "manage",
        }
    }
}

/// Map an inbound `(method, path)` to the `Scope` a `wlk_` key must hold to be allowed.
///
/// Rules (least → most privileged):
///   * a device-control READ (see [`is_privileged_read_path`]) → `Manage`, checked FIRST so the
///     blanket "GET ⇒ read" rule cannot undercut it
///   * any other `GET`                 → `Read`
///   * an execute surface (`POST` to a `/run`/`/cancel` route, `POST /mcp`, the OpenAI-compat
///     completion/responses endpoints) → `Run`
///   * a DEVICE-CONTROL route (vault app-lock, data reset/restore, key issuance, LAN expose, cloud
///     link/unlink, OS trust-store install) → `Manage` (see [`is_device_management_path`]) — NOT
///     satisfied by `admin`
///   * everything else (ordinary resource mutations) → `Admin`
///
/// `path` is the request URI path WITHOUT a query string. A `run`-scoped key implicitly satisfies
/// `Read` (see [`scope_grants`]); `admin` satisfies `read`/`run`/`admin` but NOT `manage`.
///
/// MIXED ROUTES: a route whose privilege depends on the BODY cannot be classified here (this gate
/// only sees method+path). `PUT /v1/settings/runtime` is the one such route: it carries harmless
/// resource ceilings AND the four DANGEROUS browser-security flags, so it stays `Admin` here and the
/// handler re-gates on [`Caller::grants`] with `Manage` when a dangerous flag actually changes value
/// (see `api::v1::settings::put_runtime`). Same pattern for MCP `tools/call`, whose per-tool minimum
/// scope lives in `mcp::tool_executor` because the tool name is in the JSON-RPC body.
pub fn required_scope(method: &str, path: &str) -> Scope {
    // Device control by READING — must precede the method shortcut below.
    if is_privileged_read_path(path) {
        return Scope::Manage;
    }
    if method.eq_ignore_ascii_case("GET") || method.eq_ignore_ascii_case("HEAD") {
        return Scope::Read;
    }
    // Execute surfaces — these consume the `run` capability rather than `admin`. OpenAI-compat
    // endpoints are matched by SUFFIX so both the global `/v1/chat/completions` and the per-workflow
    // base `/v1/workflows/{id}/v1/chat/completions` (cloud-parity slug) resolve to `run`. Checked
    // BEFORE device-management so cloud `/run` reflect/marketplace routes stay `run`, not `manage`.
    let is_run = path.ends_with("/run")
        || path.ends_with("/cancel")
        || path == "/mcp"
        || path.ends_with("/completions")
        || path.ends_with("/responses");
    if is_run {
        return Scope::Run;
    }
    if is_device_management_path(path) {
        return Scope::Manage;
    }
    Scope::Admin
}

/// The (very short) list of READ routes that are device control despite being `GET`s, because the
/// RESPONSE ITSELF hands over device state rather than describing it.
///
/// `GET /v1/backup/download` streams the encrypted archive of the whole device home. A blanket
/// "GET ⇒ `Read`" would let any `read`/`run`/`admin` key — including the `run` grant every OAuth
/// consent issues (`api::v1::oauth::GRANTED_SCOPE`), whose consent page promises the client "cannot
/// manage keys, secrets, or device settings" — walk off with it. Exporting the device is exactly as
/// privileged as restoring over it (`/v1/backup/restore`, already `Manage`), so it is classified the
/// same. The full-access `wlt_` UI token bypasses this gate, so the in-app Back-up button is
/// unaffected.
fn is_privileged_read_path(path: &str) -> bool {
    path == "/v1/backup/download"
}

/// True for the small set of non-run mutation routes that hand over control of the DEVICE ITSELF
/// (AC-2). These require the explicit `Manage` capability that `admin` does not grant. Kept narrow
/// on purpose: ordinary resource CRUD (workflows/monitors/personas/secrets, cloud data sync) stays
/// `Admin`. Callers pass a query-stripped path; matching is by prefix/exact so `:id`-style dynamic
/// segments (e.g. `/v1/keys/7`) are covered.
fn is_device_management_path(path: &str) -> bool {
    // Vault app-lock control (enable/disable/lock/unlock/recovery) — turning off the PIN or
    // re-issuing recovery material is full device compromise.
    path.starts_with("/v1/vault/")
        || path == "/v1/vault"
        // API-key issuance/revocation — a key that can mint keys can escalate itself arbitrarily.
        || path == "/v1/keys"
        || path.starts_with("/v1/keys/")
        // Rotating the master `wlt_` runtime bearer — re-issuing the device's full-access token is
        // device control (the full-access UI token bypasses this gate; an external key needs `manage`).
        || path == "/v1/token/rotate"
        // Wholesale data destruction / restore-over-the-top.
        || path == "/v1/data/reset"
        || path == "/v1/backup/restore"
        // Binding the daemon onto the LAN (attack-surface change).
        || path == "/v1/network/expose"
        // Turning the MCP bearer requirement off (attack-surface change of the same kind).
        || path == "/v1/mcp/auth"
        // Opting this device INTO sending anonymized usage metrics to the cloud. What crosses the
        // boundary is only counts/booleans (`cloud::usage_metrics`), but the DECISION to open an
        // outbound reporting channel at all is the owner's, not an `admin`-scoped key's — same class
        // as `/v1/network/expose`. (Opting OUT is gated identically: a privacy setting an external key
        // could flip either way is not the owner's setting.)
        || path.starts_with("/v1/settings/telemetry")
        // ACQUIRING a cloud account link is at least as privileged as severing one. `link/start`
        // returns the device-flow `user_code` + `verification_uri_complete` TO THE CALLER, who can
        // approve it in an account THEY control; `link/poll` then auto-starts the cloud execution
        // agent, whose dispatch frames carry recipes inline (`eval` steps included) — i.e. a durable
        // remote-code path onto this machine. Leaving these at `Admin` while `unlink` needed `Manage`
        // was backwards: an `admin` key could install a remote controller it could not then evict.
        || path == "/v1/cloud/link/start"
        || path == "/v1/cloud/link/poll"
        // Severing the cloud account link.
        || path == "/v1/cloud/unlink"
        // Installing the local CA into the OS *user* trust store. Once trusted, that anchor validates
        // any leaf the CA key signs, for this user, outside Writ — a device-wide trust decision.
        || path == "/v1/tls/trust"
}

/// Does a key's CSV `scopes` (`read|run|admin|manage`) grant the `needed` capability? Hierarchy:
/// `admin` ⊇ `run` ⊇ `read` — a higher scope implies the lower ones. `manage` is SEPARATE and OUT of
/// that chain (AC-2): `admin` does NOT imply `manage`, so a key reaches the device-control routes
/// only if it was explicitly issued `manage`. A `manage` grant is orthogonal — it does NOT by itself
/// confer `read`/`run`/`admin`. Unknown tokens are ignored.
pub fn scope_grants(scopes_csv: &str, needed: Scope) -> bool {
    let mut has_read = false;
    let mut has_run = false;
    let mut has_admin = false;
    let mut has_manage = false;
    for tok in scopes_csv.split(',') {
        match tok.trim() {
            "read" => has_read = true,
            "run" => has_run = true,
            "admin" => has_admin = true,
            "manage" => has_manage = true,
            _ => {}
        }
    }
    match needed {
        Scope::Read => has_read || has_run || has_admin,
        Scope::Run => has_run || has_admin,
        Scope::Admin => has_admin,
        // Device control is fail-closed: only an explicit `manage` token opens it. `admin` alone
        // (the scope a "create a workflow" key gets) is intentionally NOT enough.
        Scope::Manage => has_manage,
    }
}

/// WHO the current request authenticated as, in capability terms — stashed into the request's
/// extensions by `server::auth_mw` so a handler can re-apply the scope gate on something the
/// method+path gate could not see.
///
/// The middleware gate ([`required_scope`]) is necessarily coarse: it knows only method+path. Two
/// surfaces need finer decisions that live in the BODY:
///   * `PUT /v1/settings/runtime` — mixed privilege (harmless ceilings alongside the four DANGEROUS
///     browser-security flags),
///   * MCP `tools/call` — one HTTP route (`POST /mcp`, classified `Run`) multiplexing tools that are
///     `Read`, `Run` and `Admin` on the REST surface.
///
/// Carrying the resolved capability forward keeps ONE scope model instead of a second, divergent
/// notion of privilege in those handlers. It holds NO credential material — only the CSV grant.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Caller {
    /// The full-access `wlt_` runtime bearer, the process-trust stdio surface, or an explicitly
    /// opted-into bearer-exempt loopback surface. Holds every capability, `Manage` included — this is
    /// the in-app UI / the machine's owner, which the scope model never restricted.
    FullAccess,
    /// A scoped external credential (`wlk_` client key or `wlo_` OAuth token) carrying the CSV grant
    /// it was issued (`read|run|admin|manage`).
    Scoped(String),
}

impl Caller {
    /// Does this caller hold `needed`? `FullAccess` always does; a scoped credential is decided by
    /// [`scope_grants`], so `admin` still does NOT imply `manage` (AC-2).
    pub fn grants(&self, needed: Scope) -> bool {
        match self {
            Caller::FullAccess => true,
            Caller::Scoped(csv) => scope_grants(csv, needed),
        }
    }

    /// The grant string for logs/diagnostics. NEVER a credential — safe to trace.
    pub fn describe(&self) -> &str {
        match self {
            Caller::FullAccess => "full-access",
            Caller::Scoped(csv) => csv.as_str(),
        }
    }
}

/// Resolve the capability of a request whose `Caller` extension is MISSING. Fail CLOSED: an absent
/// extension means the request never passed `server::auth_mw` (a route mounted outside the auth
/// layer, or a handler exercised directly), and a privilege decision must not default to "allowed".
/// `Scoped("")` grants nothing at all (see [`scope_grants`]).
pub fn caller_or_deny(caller: Option<&Caller>) -> Caller {
    caller.cloned().unwrap_or_else(|| Caller::Scoped(String::new()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bearer_and_origin() {
        assert!(verify_local_bearer("wlt_abc", "wlt_abc"));
        assert!(!verify_local_bearer("wlt_abc", "wlt_abd"));
        assert!(!verify_local_bearer("short", "longer-token"));

        assert_eq!(parse_bearer("Bearer wlt_xyz"), Some("wlt_xyz"));
        assert_eq!(parse_bearer("Basic xxx"), None);

        assert!(origin_allowed("http://127.0.0.1:8131", 8131));
        assert!(origin_allowed("tauri://localhost", 8131));
        assert!(origin_allowed("localhost:8131", 8131));
        // Packaged Tauri webview origins on Windows/Linux (custom protocol).
        assert!(origin_allowed("http://tauri.localhost", 8131));
        assert!(origin_allowed("https://tauri.localhost", 8131));
        // Loopback on ANY port is accepted: the `tauri:dev` Vite server runs on
        // :5173 and the CLI dials the runtime port. Only the loopback HOST matters
        // for DNS-rebind defense; the bearer token is the real gate.
        assert!(origin_allowed("http://localhost:5173", 8131));
        assert!(origin_allowed("http://127.0.0.1:9999", 8131));
        assert!(origin_allowed("http://[::1]:5173", 8131));
        // Foreign origins are still rejected — a DNS-rebind page sends its own
        // domain as the Origin, never a loopback host.
        assert!(!origin_allowed("http://evil.example", 8131));
        assert!(!origin_allowed("http://evil.example:8131", 8131));
        // A non-http scheme, or a host that merely embeds "localhost", is rejected.
        assert!(!origin_allowed("file:///etc/passwd", 8131));
        assert!(!origin_allowed("http://localhost.evil.com", 8131));
    }

    #[test]
    fn origin_allowed_for_lan_exposure() {
        let port = 8131;
        let lan = vec!["192.168.1.50".to_string()];

        // Loopback is always accepted, exposed or not.
        assert!(origin_allowed_for("http://127.0.0.1:8131", port, false, &lan));
        assert!(origin_allowed_for("tauri://localhost", port, true, &lan));

        // When NOT exposed, the LAN host is rejected (loopback-only).
        assert!(!origin_allowed_for("192.168.1.50:8131", port, false, &lan));
        assert!(!origin_allowed_for("http://192.168.1.50:8131", port, false, &lan));

        // When exposed, the daemon's own LAN host passes — as a Host header and as an Origin.
        assert!(origin_allowed_for("192.168.1.50:8131", port, true, &lan));
        assert!(origin_allowed_for("http://192.168.1.50:8131", port, true, &lan));
        assert!(origin_allowed_for("https://192.168.1.50:8131", port, true, &lan));

        // DNS-rebind defense holds even when exposed: a foreign browser Origin never matches our own
        // loopback values NOR our LAN IP, so it is still rejected.
        assert!(!origin_allowed_for("http://evil.example", port, true, &lan));
        assert!(!origin_allowed_for("http://evil.example:8131", port, true, &lan));
        // A different LAN IP (not ours) is rejected — only OUR bind address is allowed.
        assert!(!origin_allowed_for("http://192.168.1.99:8131", port, true, &lan));
        // Right host, wrong port → rejected.
        assert!(!origin_allowed_for("http://192.168.1.50:9999", port, true, &lan));
        // Exposed but no LAN hosts resolved → only loopback passes (fail-safe).
        assert!(!origin_allowed_for("http://192.168.1.50:8131", port, true, &[]));
    }

    #[test]
    fn ws_connect_auth() {
        let tok = "wlt_secret";
        let port = 8131;
        // Happy path: correct token, loopback origin/host.
        assert!(ws_connect_authorized(
            Some(tok),
            Some("http://127.0.0.1:8131"),
            Some("127.0.0.1:8131"),
            tok,
            port,
        ));
        // Token may ride alone (no Origin/Host headers on a native WS client).
        assert!(ws_connect_authorized(Some(tok), None, None, tok, port));
        // Wrong token → rejected even on loopback.
        assert!(!ws_connect_authorized(Some("wlt_wrong"), None, None, tok, port));
        // Missing / empty token → rejected.
        assert!(!ws_connect_authorized(None, None, None, tok, port));
        assert!(!ws_connect_authorized(Some(""), None, None, tok, port));
        // Cross-origin upgrade (DNS-rebind) → rejected even with the right token.
        assert!(!ws_connect_authorized(
            Some(tok),
            Some("http://evil.example"),
            None,
            tok,
            port,
        ));
        // Foreign Host → rejected.
        assert!(!ws_connect_authorized(Some(tok), None, Some("evil.example"), tok, port));
    }

    #[test]
    fn scope_mapping_by_method_and_path() {
        // GET is always read.
        assert_eq!(required_scope("GET", "/v1/workflows"), Scope::Read);
        assert_eq!(required_scope("get", "/v1/runs/3"), Scope::Read);
        // Execute surfaces are `run`.
        assert_eq!(required_scope("POST", "/v1/workflows/3/run"), Scope::Run);
        assert_eq!(required_scope("POST", "/v1/workflows/3/cancel"), Scope::Run);
        assert_eq!(required_scope("POST", "/mcp"), Scope::Run);
        assert_eq!(required_scope("POST", "/v1/chat/completions"), Scope::Run);
        assert_eq!(required_scope("POST", "/v1/responses"), Scope::Run);
        // Per-workflow OpenAI base (cloud-parity slug) maps to `run` by suffix.
        assert_eq!(required_scope("POST", "/v1/workflows/3/v1/chat/completions"), Scope::Run);
        assert_eq!(required_scope("POST", "/v1/workflows/3/v1/responses"), Scope::Run);
        assert_eq!(required_scope("GET", "/v1/workflows/3/v1/models"), Scope::Read);
        // Ordinary resource mutations are admin.
        assert_eq!(required_scope("POST", "/v1/workflows"), Scope::Admin);
        assert_eq!(required_scope("PATCH", "/v1/workflows/1"), Scope::Admin);
        assert_eq!(required_scope("POST", "/v1/secrets"), Scope::Admin);
        // Cloud DATA SYNC is ordinary admin; cloud LINK is device management (see below).
        assert_eq!(required_scope("POST", "/v1/cloud/sync/push"), Scope::Admin);
        assert_eq!(required_scope("POST", "/v1/cloud/sync/pull"), Scope::Admin);

        // AC-2: device-control routes require the SEPARATE `manage` capability, not `admin`.
        assert_eq!(required_scope("POST", "/v1/vault/disable"), Scope::Manage);
        assert_eq!(required_scope("POST", "/v1/vault/enable"), Scope::Manage);
        assert_eq!(required_scope("POST", "/v1/vault/unlock"), Scope::Manage);
        assert_eq!(required_scope("POST", "/v1/vault/recovery/generate"), Scope::Manage);
        assert_eq!(required_scope("POST", "/v1/keys"), Scope::Manage);
        assert_eq!(required_scope("DELETE", "/v1/keys/1"), Scope::Manage);
        // Rotating the master runtime bearer is device control → `manage`, not `admin`.
        assert_eq!(required_scope("POST", "/v1/token/rotate"), Scope::Manage);
        assert_eq!(required_scope("POST", "/v1/data/reset"), Scope::Manage);
        assert_eq!(required_scope("POST", "/v1/backup/restore"), Scope::Manage);
        assert_eq!(required_scope("POST", "/v1/network/expose"), Scope::Manage);
        assert_eq!(required_scope("POST", "/v1/cloud/unlink"), Scope::Manage);
        // A cloud reflect/marketplace `/run` route stays `run`, never `manage`.
        assert_eq!(required_scope("POST", "/v1/cloud/marketplace/run"), Scope::Run);
        assert_eq!(required_scope("POST", "/v1/cloud/reflect/workflows/42/run"), Scope::Run);
        // Data purge/retention are ordinary admin (destructive-but-scoped), not device reset.
        assert_eq!(required_scope("POST", "/v1/data/purge"), Scope::Admin);
    }

    /// ACQUIRING a cloud link is device control: `link/start` hands the caller a device-flow code it
    /// can approve in ITS OWN account, and `link/poll` then auto-starts the cloud execution agent
    /// (inline-recipe dispatch = a durable remote-code path). These used to be `Admin`, which let an
    /// `admin` key install a remote controller that the same key could not `unlink` again.
    #[test]
    fn cloud_link_requires_manage_not_admin() {
        for path in ["/v1/cloud/link/start", "/v1/cloud/link/poll"] {
            assert_eq!(required_scope("POST", path), Scope::Manage, "{path} must be manage");
            assert!(!scope_grants("admin", required_scope("POST", path)), "{path}: admin must NOT reach it");
            assert!(!scope_grants("read,run,admin", required_scope("POST", path)));
            assert!(scope_grants("manage", required_scope("POST", path)), "{path}: manage opens it");
        }
        // Unlink stays symmetric with link (it already required `manage`).
        assert!(!scope_grants("admin", required_scope("POST", "/v1/cloud/unlink")));
    }

    /// Device-SECURITY-POSTURE routes are `Manage`, not `Admin`: installing the local CA into the OS
    /// user trust store is a device-wide trust decision, and `GET /v1/backup/download` streams an
    /// encrypted copy of the entire device home (vault root + master bearer live in that home), so the
    /// blanket "GET ⇒ read" rule must not reach it.
    #[test]
    fn device_posture_routes_require_manage() {
        assert_eq!(required_scope("POST", "/v1/tls/trust"), Scope::Manage);
        assert!(!scope_grants("admin", required_scope("POST", "/v1/tls/trust")));
        // Reading the TLS lane's public facts stays a plain read.
        assert_eq!(required_scope("GET", "/v1/tls/status"), Scope::Read);

        assert_eq!(required_scope("GET", "/v1/backup/download"), Scope::Manage);
        for grant in ["read", "run", "admin", "read,run,admin"] {
            assert!(
                !scope_grants(grant, required_scope("GET", "/v1/backup/download")),
                "'{grant}' must NOT be able to download the device backup"
            );
        }
        assert!(scope_grants("manage", required_scope("GET", "/v1/backup/download")));
        // The rest of the backup surface keeps its classification: export/inspect are admin
        // mutations, restore is device control.
        assert_eq!(required_scope("POST", "/v1/backup/export"), Scope::Admin);
        assert_eq!(required_scope("POST", "/v1/backup/inspect"), Scope::Admin);
        assert_eq!(required_scope("POST", "/v1/backup/restore"), Scope::Manage);
        // A normal read is still a read (the privileged-read list is exactly one path).
        assert_eq!(required_scope("GET", "/v1/vault/status"), Scope::Read);
        assert_eq!(required_scope("GET", "/v1/settings/runtime"), Scope::Read);
    }

    /// The `Caller` capability carried in request extensions preserves the scope model exactly: the
    /// in-app full-access token holds everything, a scoped credential is judged by `scope_grants`
    /// (so `admin` still never implies `manage`), and a MISSING extension fails closed.
    #[test]
    fn caller_capability_matches_the_scope_model() {
        let full = Caller::FullAccess;
        for s in [Scope::Read, Scope::Run, Scope::Admin, Scope::Manage] {
            assert!(full.grants(s), "wlt_ full access holds {s:?}");
        }

        let admin = Caller::Scoped("admin".into());
        assert!(admin.grants(Scope::Read) && admin.grants(Scope::Run) && admin.grants(Scope::Admin));
        assert!(!admin.grants(Scope::Manage), "admin must NOT imply manage");

        let run = Caller::Scoped("run".into());
        assert!(run.grants(Scope::Read) && run.grants(Scope::Run));
        assert!(!run.grants(Scope::Admin) && !run.grants(Scope::Manage));

        // Fail-closed default when the middleware never ran: nothing is granted.
        let denied = caller_or_deny(None);
        for s in [Scope::Read, Scope::Run, Scope::Admin, Scope::Manage] {
            assert!(!denied.grants(s), "a missing Caller extension must grant nothing ({s:?})");
        }
        assert_eq!(caller_or_deny(Some(&Caller::FullAccess)), Caller::FullAccess);
        // `describe` is log-safe: the grant string, never a credential.
        assert_eq!(Caller::Scoped("run".into()).describe(), "run");
        assert_eq!(Caller::FullAccess.describe(), "full-access");
    }

    #[test]
    fn scope_hierarchy() {
        // admin ⊇ run ⊇ read
        assert!(scope_grants("admin", Scope::Read));
        assert!(scope_grants("admin", Scope::Run));
        assert!(scope_grants("admin", Scope::Admin));

        assert!(scope_grants("run", Scope::Read));
        assert!(scope_grants("run", Scope::Run));
        assert!(!scope_grants("run", Scope::Admin));

        assert!(scope_grants("read", Scope::Read));
        assert!(!scope_grants("read", Scope::Run));
        assert!(!scope_grants("read", Scope::Admin));

        // AC-2: `manage` is OUT of the read⊆run⊆admin chain. `admin` does NOT confer it, so a plain
        // admin key cannot reach device-control routes; only an explicit `manage` token opens them.
        assert!(!scope_grants("admin", Scope::Manage), "admin must NOT imply manage");
        assert!(!scope_grants("read,run,admin", Scope::Manage));
        assert!(scope_grants("manage", Scope::Manage));
        assert!(scope_grants("admin,manage", Scope::Manage));
        // A bare `manage` grant does not backfill the ordinary capabilities.
        assert!(!scope_grants("manage", Scope::Admin));
        assert!(!scope_grants("manage", Scope::Read));

        // CSV with whitespace + unknown tokens.
        assert!(scope_grants(" read , run ", Scope::Run));
        assert!(!scope_grants("read,bogus", Scope::Run));
        assert!(scope_grants("read,run,admin", Scope::Admin));
        // Empty grants nothing.
        assert!(!scope_grants("", Scope::Read));
        assert!(!scope_grants("", Scope::Manage));
    }
}
