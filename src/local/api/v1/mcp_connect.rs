//! `GET /v1/mcp/connect-info` — everything a UI needs to connect an MCP client (Claude Desktop,
//! Claude Code, or any other MCP-capable agent) to this daemon: the loopback HTTP endpoint, the
//! stdio command (this binary + the `mcp` verb), ready-made client snippets, and the currently
//! exposed tool names.
//!
//! NO secrets: neither the `wlt_` token nor any `wlk_` key appears in the payload. The recommended
//! stdio transport needs no credential in the client config at all — the spawned `writ-agentd mcp`
//! child discovers the running daemon and reads the `0600` runtime descriptor itself (see
//! `cli::mcp_stdio`). Direct-HTTP callers mint a `run`-scoped `wlk_` key through the existing
//! `/v1/keys` surface instead.

use crate::local::error::{LocalError, LocalResult};
use crate::local::server::{AppState, MCP_AUTH_DISABLED_KEY};
use crate::local::store::config_kv;
use axum::extract::State;
use axum::routing::{get, post};
use axum::{Json, Router};
use serde_json::{json, Value};
use std::path::{Path, PathBuf};

/// Mount the `/v1/mcp/*` routes. Auth is applied by `server.rs` at the router level; note that
/// `POST /v1/mcp/auth` is in the device-management (`Manage`) scope set — turning MCP auth OFF is
/// an attack-surface change, like LAN exposure.
pub fn router() -> Router<AppState> {
    Router::new()
        .route("/v1/mcp/connect-info", get(connect_info))
        .route("/v1/mcp/auth", get(auth_status).post(auth_set))
        .route("/v1/mcp/install-client", post(install_client))
        .route("/v1/mcp/install-status", get(install_status))
}

/// The MCP hosts the desktop Connect page offers a one-click install for. The
/// status endpoint reports each one; the install endpoint accepts each id.
const INSTALL_CLIENT_IDS: &[&str] = &[
    "claude_code",
    "claude_desktop",
    "codex",
    "cursor",
    "windsurf",
    "vscode",
];

/// `GET /v1/mcp/connect-info` — connection material for MCP clients.
///
/// `stdio.command` is THIS daemon binary (`current_exe`), whose `mcp` verb proxies stdio frames to
/// the running daemon (or boots headless when none runs) — so the snippets stay valid whether the
/// app is running or not, and never embed a token. `tools` reflects the live catalog (enabled
/// workflows whose Connect → MCP surface is on), so the UI can show what a connected Claude sees.
async fn connect_info(State(st): State<AppState>) -> LocalResult<Json<Value>> {
    let catalog = crate::local::mcp::tools::catalog(&st).await?;
    let tool_names: Vec<&str> = catalog.iter().map(|t| t.name.as_str()).collect();

    let exe = std::env::current_exe()
        .ok()
        .map(|p| p.to_string_lossy().into_owned())
        .unwrap_or_else(|| "writ-agentd".to_string());
    let endpoint = format!("http://127.0.0.1:{}/mcp", st.config.port);
    // The HTTPS twin (same router over TLS; see `local::tls`) — present only when the lane is
    // actually up this boot. Clients that refuse plain-http base URLs use this once the local CA
    // is trusted (`POST /v1/tls/trust`, details on `GET /v1/tls/status`).
    let tls_status = crate::local::tls::runtime_status();
    let endpoint_https = tls_status.map(|s| format!("https://127.0.0.1:{}/mcp", s.port));
    // The three credential modes an MCP host can use, in preference order: OAuth (spec discovery,
    // for hosts with no key field), a scoped wlk_ key, or — explicit loopback-only opt-out — none.
    let auth_disabled = config_kv::get(&st.db, MCP_AUTH_DISABLED_KEY).await?.as_deref() == Some("true");
    let auth_required = !auth_disabled || st.config.network_exposed;

    Ok(Json(json!({
        "endpoint": endpoint,
        "endpoint_https": endpoint_https,
        "auth_required": auth_required,
        "oauth": {
            // RFC 9728 entry point — an OAuth-capable host discovers everything else from here
            // (also advertised via WWW-Authenticate on a /mcp 401).
            "resource_metadata": format!("http://127.0.0.1:{}/.well-known/oauth-protected-resource", st.config.port),
            "resource_metadata_https": tls_status.map(|s| format!(
                "https://127.0.0.1:{}/.well-known/oauth-protected-resource", s.port
            )),
        },
        "tls": tls_status.map(|s| json!({
            "port": s.port,
            "ca_path": s.ca_path,
            "ca_fingerprint_sha256": s.ca_fingerprint_sha256,
            "trust_hint": "Trust the local CA once: POST /v1/tls/trust (or see GET /v1/tls/status manual_instructions)",
        })),
        "stdio": { "command": exe, "args": ["mcp"] },
        "snippets": {
            // One-liner for Claude Code (stdio child; no credential needed in the config).
            "claude_code": format!("claude mcp add writ -- \"{exe}\" mcp"),
            // Drop-in block for claude_desktop_config.json.
            "claude_desktop": { "mcpServers": { "writ": { "command": exe, "args": ["mcp"] } } },
        },
        // Direct HTTP clients authenticate with a scoped key minted via /v1/keys (never the wlt_).
        "http_auth_hint": "POST /mcp requires a Bearer wlk_ key with the 'run' scope (Settings → API keys)",
        "tools": tool_names,
        "workflows_exposed": catalog.len(),
    })))
}

// ────────────────────────────────────────────────────────────────────────────
// `POST /v1/mcp/install-client` — one-click "wire Writ into this AI agent".
//
// The desktop Connect page offers a button per popular MCP host; clicking it
// merges Writ's local stdio server into that host's own config file (same
// `command`+`args` the connect-info snippets show — this daemon binary + the
// `mcp` verb). NO secrets are written: the stdio bridge reads the 0600 runtime
// descriptor itself, so the config only ever contains a public command path.
//
// Every host but Codex reads a JSON file with an `mcpServers` (or, for VS Code,
// `servers`) map; Codex reads `~/.codex/config.toml`. We read-modify-write,
// preserving any servers/keys already present, and refuse (rather than clobber)
// a config file that doesn't parse — the UI falls back to the manual snippet.
// ────────────────────────────────────────────────────────────────────────────

/// A JSON-config MCP host: the file to edit, the map key its servers live under
/// (`mcpServers` for Claude/Cursor/Windsurf, `servers` for VS Code), and whether
/// the entry needs an explicit `"type": "stdio"` (VS Code requires it; the others
/// infer transport from the presence of `command`).
struct JsonSpec {
    path: PathBuf,
    servers_key: &'static str,
    include_type: bool,
}

/// Where a given client id installs to. Codex is TOML; everything else is JSON.
enum ClientTarget {
    Json(JsonSpec),
    /// `~/.codex/config.toml` — `[mcp_servers.writ]`.
    Toml(PathBuf),
}

fn no_config_dir() -> LocalError {
    LocalError::Internal("no OS config directory on this system".into())
}

/// Map a client id (as sent by the Connect page) to its on-disk config target.
/// Paths follow each host's documented default location, per-OS via `dirs`
/// (`config_dir()` = `~/Library/Application Support` on macOS, `%APPDATA%` on
/// Windows, `~/.config` on Linux).
fn resolve_client(client: &str) -> LocalResult<ClientTarget> {
    let home = dirs::home_dir().ok_or_else(|| LocalError::Internal("no home directory on this system".into()))?;
    Ok(match client {
        // Claude Desktop — `<config>/Claude/claude_desktop_config.json`.
        "claude_desktop" => ClientTarget::Json(JsonSpec {
            path: dirs::config_dir().ok_or_else(no_config_dir)?.join("Claude").join("claude_desktop_config.json"),
            servers_key: "mcpServers",
            include_type: false,
        }),
        // Claude Code (CLI) — user-scope servers live in `~/.claude.json`.
        "claude_code" => ClientTarget::Json(JsonSpec {
            path: home.join(".claude.json"),
            servers_key: "mcpServers",
            include_type: false,
        }),
        // Cursor — `~/.cursor/mcp.json`.
        "cursor" => ClientTarget::Json(JsonSpec {
            path: home.join(".cursor").join("mcp.json"),
            servers_key: "mcpServers",
            include_type: false,
        }),
        // Windsurf (Codeium) — `~/.codeium/windsurf/mcp_config.json`.
        "windsurf" => ClientTarget::Json(JsonSpec {
            path: home.join(".codeium").join("windsurf").join("mcp_config.json"),
            servers_key: "mcpServers",
            include_type: false,
        }),
        // VS Code — user-profile `<config>/Code/User/mcp.json`; note the map key
        // is `servers` (not `mcpServers`) and entries carry an explicit type.
        "vscode" => ClientTarget::Json(JsonSpec {
            path: dirs::config_dir().ok_or_else(no_config_dir)?.join("Code").join("User").join("mcp.json"),
            servers_key: "servers",
            include_type: true,
        }),
        // OpenAI Codex CLI — `~/.codex/config.toml`.
        "codex" => ClientTarget::Toml(home.join(".codex").join("config.toml")),
        other => return Err(LocalError::BadRequest(format!("unknown MCP client '{other}'"))),
    })
}

/// The stdio server entry we install under the key `writ`. `include_type` adds
/// the `"type": "stdio"` field VS Code needs; other hosts infer it from `command`.
fn json_server_entry(exe: &str, include_type: bool) -> Value {
    let mut m = serde_json::Map::new();
    if include_type {
        m.insert("type".into(), json!("stdio"));
    }
    m.insert("command".into(), json!(exe));
    m.insert("args".into(), json!(["mcp"]));
    Value::Object(m)
}

/// Create parent dirs then write the file (whole-file replace — we've already
/// merged the caller's existing content into `contents`).
fn write_config(path: &Path, contents: String) -> LocalResult<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(path, contents)?;
    Ok(())
}

/// Merge `writ` into a JSON host config, preserving every other server and key.
/// Returns the action taken for the UI's toast: `created` (no file before),
/// `already_present` (our exact entry was already there), or `updated`.
fn install_json(spec: &JsonSpec, exe: &str) -> LocalResult<&'static str> {
    let existed = spec.path.exists();
    let mut root: Value = if existed {
        let raw = std::fs::read_to_string(&spec.path)?;
        if raw.trim().is_empty() {
            json!({})
        } else {
            serde_json::from_str(&raw).map_err(|e| {
                LocalError::BadRequest(format!(
                    "the existing config at {} isn't valid JSON ({e}) — fix it or use the manual snippet",
                    spec.path.display()
                ))
            })?
        }
    } else {
        json!({})
    };

    let obj = root.as_object_mut().ok_or_else(|| {
        LocalError::BadRequest(format!("the config at {} isn't a JSON object", spec.path.display()))
    })?;
    let servers = obj
        .entry(spec.servers_key.to_string())
        .or_insert_with(|| json!({}));
    let servers = servers.as_object_mut().ok_or_else(|| {
        LocalError::BadRequest(format!("'{}' in {} isn't an object", spec.servers_key, spec.path.display()))
    })?;

    let entry = json_server_entry(exe, spec.include_type);
    let action = if servers.get("writ") == Some(&entry) {
        "already_present"
    } else if existed {
        "updated"
    } else {
        "created"
    };
    servers.insert("writ".to_string(), entry);

    let mut out = serde_json::to_string_pretty(&root)?;
    out.push('\n');
    write_config(&spec.path, out)?;
    Ok(action)
}

/// Merge `[mcp_servers.writ]` into `~/.codex/config.toml`, preserving the rest.
fn install_codex_toml(path: &Path, exe: &str) -> LocalResult<&'static str> {
    let existed = path.exists();
    let mut root: toml::Table = if existed {
        let raw = std::fs::read_to_string(path)?;
        if raw.trim().is_empty() {
            toml::Table::new()
        } else {
            raw.parse().map_err(|e| {
                LocalError::BadRequest(format!(
                    "the existing config at {} isn't valid TOML ({e}) — fix it or use the manual snippet",
                    path.display()
                ))
            })?
        }
    } else {
        toml::Table::new()
    };

    let servers = root
        .entry("mcp_servers".to_string())
        .or_insert_with(|| toml::Value::Table(toml::Table::new()));
    let servers = servers.as_table_mut().ok_or_else(|| {
        LocalError::BadRequest(format!("'mcp_servers' in {} isn't a table", path.display()))
    })?;

    let entry = codex_server_entry(exe);
    let action = if servers.get("writ") == Some(&entry) {
        "already_present"
    } else if existed {
        "updated"
    } else {
        "created"
    };
    servers.insert("writ".to_string(), entry);

    let out = toml::to_string_pretty(&root)
        .map_err(|e| LocalError::Internal(format!("could not serialize codex config: {e}")))?;
    write_config(path, out)?;
    Ok(action)
}

/// The Codex `[mcp_servers.writ]` table we'd write — used both to install and to
/// recognise an existing install.
fn codex_server_entry(exe: &str) -> toml::Value {
    let mut entry = toml::Table::new();
    entry.insert("command".to_string(), toml::Value::String(exe.to_string()));
    entry.insert("args".to_string(), toml::Value::Array(vec![toml::Value::String("mcp".to_string())]));
    toml::Value::Table(entry)
}

/// Non-mutating read of a JSON host's current state, for the status endpoint.
/// `installed` = our exact entry is already there; `stale` = a `writ` server is
/// present but points somewhere else (a moved binary → offer a one-click update).
/// An unreadable/unparseable config is reported as "not installed" rather than
/// erroring the whole status call.
fn inspect_json(client: &str, spec: &JsonSpec, exe: &str) -> Value {
    let (config_exists, installed, stale) = match std::fs::read_to_string(&spec.path) {
        Ok(raw) if !raw.trim().is_empty() => match serde_json::from_str::<Value>(&raw) {
            Ok(root) => {
                let entry = json_server_entry(exe, spec.include_type);
                match root.get(spec.servers_key).and_then(|m| m.get("writ")) {
                    Some(v) if *v == entry => (true, true, false),
                    Some(_) => (true, false, true),
                    None => (true, false, false),
                }
            }
            Err(_) => (true, false, false),
        },
        Ok(_) => (true, false, false),
        Err(_) => (false, false, false),
    };
    json!({
        "client": client,
        "path": spec.path.display().to_string(),
        "config_exists": config_exists,
        "installed": installed,
        "stale": stale,
    })
}

/// Non-mutating read of Codex's `config.toml` state (mirror of `inspect_json`).
fn inspect_codex_toml(client: &str, path: &Path, exe: &str) -> Value {
    let (config_exists, installed, stale) = match std::fs::read_to_string(path) {
        Ok(raw) if !raw.trim().is_empty() => match raw.parse::<toml::Table>() {
            Ok(root) => {
                let entry = codex_server_entry(exe);
                match root.get("mcp_servers").and_then(|m| m.as_table()).and_then(|m| m.get("writ")) {
                    Some(v) if *v == entry => (true, true, false),
                    Some(_) => (true, false, true),
                    None => (true, false, false),
                }
            }
            Err(_) => (true, false, false),
        },
        Ok(_) => (true, false, false),
        Err(_) => (false, false, false),
    };
    json!({
        "client": client,
        "path": path.display().to_string(),
        "config_exists": config_exists,
        "installed": installed,
        "stale": stale,
    })
}

/// `GET /v1/mcp/install-status` — for each supported host, whether Writ is
/// already wired into its config (`installed`), present but pointing at a
/// different binary (`stale`), and whether the host's config file exists at all
/// (`config_exists`, a soft "is this app set up here" signal). The Connect page
/// uses this to pre-mark buttons on load instead of always offering a fresh install.
async fn install_status() -> LocalResult<Json<Value>> {
    let exe = std::env::current_exe()
        .ok()
        .map(|p| p.to_string_lossy().into_owned())
        .unwrap_or_else(|| "writ-agentd".to_string());

    let mut clients = Vec::with_capacity(INSTALL_CLIENT_IDS.len());
    for &id in INSTALL_CLIENT_IDS {
        let status = match resolve_client(id)? {
            ClientTarget::Json(spec) => inspect_json(id, &spec, &exe),
            ClientTarget::Toml(path) => inspect_codex_toml(id, &path, &exe),
        };
        clients.push(status);
    }
    Ok(Json(json!({ "clients": clients })))
}

/// Body for `POST /v1/mcp/install-client`.
#[derive(Debug, serde::Deserialize)]
struct InstallBody {
    /// One of: `claude_desktop`, `claude_code`, `cursor`, `windsurf`, `vscode`, `codex`.
    client: String,
}

/// `POST /v1/mcp/install-client` — merge this daemon's local MCP server into the
/// named host's config file. Idempotent: re-running reports `already_present`.
/// The `command` written is `current_exe` + the `mcp` verb, identical to the
/// connect-info snippets, so a manual and a one-click install are interchangeable.
async fn install_client(Json(body): Json<InstallBody>) -> LocalResult<Json<Value>> {
    let exe = std::env::current_exe()
        .ok()
        .map(|p| p.to_string_lossy().into_owned())
        .unwrap_or_else(|| "writ-agentd".to_string());

    let target = resolve_client(&body.client)?;
    let (path, action) = match &target {
        ClientTarget::Json(spec) => (spec.path.clone(), install_json(spec, &exe)?),
        ClientTarget::Toml(path) => (path.clone(), install_codex_toml(path, &exe)?),
    };

    tracing::info!(
        client = %body.client,
        action,
        path = %path.display(),
        "installed local MCP server into an AI client config"
    );
    Ok(Json(json!({
        "ok": true,
        "client": body.client,
        "path": path.display().to_string(),
        "action": action,
    })))
}

/// Body for `POST /v1/mcp/auth`. `required=false` is the loopback-only escape hatch.
#[derive(Debug, serde::Deserialize)]
struct AuthBody {
    required: bool,
}

/// `GET /v1/mcp/auth` — current MCP-auth posture. `forced_by_lan` tells the UI the persisted
/// opt-out is being overridden because the daemon is LAN-exposed.
async fn auth_status(State(st): State<AppState>) -> LocalResult<Json<Value>> {
    let disabled = config_kv::get(&st.db, MCP_AUTH_DISABLED_KEY).await?.as_deref() == Some("true");
    Ok(Json(json!({
        "required": !disabled || st.config.network_exposed,
        "opt_out_persisted": disabled,
        "forced_by_lan": disabled && st.config.network_exposed,
    })))
}

/// `POST /v1/mcp/auth` — persist the toggle (kv, effective immediately — `auth_mw` reads it per
/// `/mcp` request). Device-management scope (`Manage`) for external keys; the UI's `wlt_` bypasses.
/// The opt-out NEVER takes effect while LAN-exposed (`auth_mw` re-checks `network_exposed` live).
async fn auth_set(State(st): State<AppState>, Json(body): Json<AuthBody>) -> LocalResult<Json<Value>> {
    config_kv::set(&st.db, MCP_AUTH_DISABLED_KEY, if body.required { "false" } else { "true" }).await?;
    tracing::warn!(
        auth_required = body.required,
        lan_exposed = st.config.network_exposed,
        "MCP auth toggle persisted (opt-out is loopback-only; LAN exposure forces auth back on)"
    );
    Ok(Json(json!({
        "required": body.required || st.config.network_exposed,
        "opt_out_persisted": !body.required,
        "forced_by_lan": !body.required && st.config.network_exposed,
    })))
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

    const TOKEN: &str = "wlt_mcp_connect_secret";

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

    #[tokio::test]
    async fn connect_info_shape_and_no_secret_leak() {
        let _g = crate::local::config::test_env_guard();
        let (_dir, st) = test_state().await;

        let resp = build_router(st.clone())
            .oneshot(
                Request::builder()
                    .uri("/v1/mcp/connect-info")
                    .header("authorization", format!("Bearer {TOKEN}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), 200);
        let bytes = to_bytes(resp.into_body(), 1 << 20).await.unwrap();
        let v: Value = serde_json::from_slice(&bytes).unwrap();

        // Endpoint reflects the configured port and the /mcp path.
        let endpoint = v["endpoint"].as_str().unwrap();
        assert!(endpoint.starts_with("http://127.0.0.1:"), "loopback endpoint: {endpoint}");
        assert!(endpoint.ends_with("/mcp"));

        // stdio command is a concrete binary path with the `mcp` verb.
        assert!(v["stdio"]["command"].as_str().unwrap().len() > 1);
        assert_eq!(v["stdio"]["args"], json!(["mcp"]));

        // Snippets exist for both Claude clients and reference the same command.
        assert!(v["snippets"]["claude_code"].as_str().unwrap().contains(" mcp"));
        assert_eq!(
            v["snippets"]["claude_desktop"]["mcpServers"]["writ"]["args"],
            json!(["mcp"])
        );

        // Fresh DB → no workflows exposed yet, and tools is an (empty) array.
        assert_eq!(v["workflows_exposed"], json!(0));
        assert!(v["tools"].as_array().unwrap().is_empty());

        // The payload must NEVER carry a token or raw key material. The auth HINT mentions "wlk_"
        // as prose — actual key material would be `wlk_` followed immediately by the key chars.
        let raw = String::from_utf8_lossy(&bytes);
        assert!(!raw.contains("wlt_"), "no wlt_ token in connect-info");
        for (i, _) in raw.match_indices("wlk_") {
            let next = raw.as_bytes().get(i + 4).copied().unwrap_or(b' ');
            assert!(
                !next.is_ascii_alphanumeric(),
                "raw wlk_ key material must never appear in connect-info"
            );
        }
        std::env::remove_var("WRIT_HOME");
    }

    #[tokio::test]
    async fn mcp_auth_toggle_and_oauth_discovery_401() {
        let _g = crate::local::config::test_env_guard();
        let (_dir, st) = test_state().await;

        // Bare POST /mcp (no bearer) → 401 that CARRIES the RFC 9728 discovery pointer.
        let resp = build_router(st.clone())
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/mcp")
                    .header("host", "127.0.0.1:8131")
                    .header("content-type", "application/json")
                    .body(Body::from(r#"{"jsonrpc":"2.0","id":1,"method":"initialize"}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), 401);
        let www = resp
            .headers()
            .get("www-authenticate")
            .expect("401 on /mcp must advertise resource metadata")
            .to_str()
            .unwrap();
        assert!(
            www.contains("/.well-known/oauth-protected-resource"),
            "WWW-Authenticate points at discovery: {www}"
        );

        // Flip auth OFF (UI wlt_ token; loopback daemon) → persisted + effective immediately.
        let resp = build_router(st.clone())
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/mcp/auth")
                    .header("authorization", format!("Bearer {TOKEN}"))
                    .header("content-type", "application/json")
                    .body(Body::from(r#"{"required":false}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), 200);

        // Bare POST /mcp now succeeds (initialize answers) — the DNS-rebind guard still applies.
        let resp = build_router(st.clone())
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/mcp")
                    .header("content-type", "application/json")
                    .body(Body::from(r#"{"jsonrpc":"2.0","id":1,"method":"initialize"}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), 200, "auth-off /mcp answers without a bearer");

        // …but ONLY /mcp: the REST surface still demands a bearer.
        let resp = build_router(st.clone())
            .oneshot(Request::builder().uri("/v1/workflows").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(resp.status(), 401, "auth-off is scoped to /mcp, never the REST surface");

        // A LAN-exposed daemon force-restores the bearer requirement despite the persisted opt-out.
        let mut exposed = st.clone();
        exposed.config.network_exposed = true;
        let resp = build_router(exposed)
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/mcp")
                    .header("content-type", "application/json")
                    .body(Body::from(r#"{"jsonrpc":"2.0","id":1,"method":"initialize"}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), 401, "LAN exposure forces MCP auth back on");

        // connect-info reflects the posture.
        let resp = build_router(st.clone())
            .oneshot(
                Request::builder()
                    .uri("/v1/mcp/connect-info")
                    .header("authorization", format!("Bearer {TOKEN}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let bytes = to_bytes(resp.into_body(), 1 << 20).await.unwrap();
        let v: Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(v["auth_required"], json!(false));
        assert!(v["oauth"]["resource_metadata"]
            .as_str()
            .unwrap()
            .ends_with("/.well-known/oauth-protected-resource"));

        std::env::remove_var("WRIT_HOME");
    }

    #[test]
    fn install_json_merges_and_is_idempotent() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("nested").join("claude_desktop_config.json");
        // Seed a pre-existing config with an UNRELATED server + a sibling key.
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(
            &path,
            r#"{"someOtherKey":true,"mcpServers":{"other":{"command":"x","args":[]}}}"#,
        )
        .unwrap();

        let spec = JsonSpec { path: path.clone(), servers_key: "mcpServers", include_type: false };

        // First install → updated (file existed), our entry added, others preserved.
        assert_eq!(install_json(&spec, "/opt/writ-agentd").unwrap(), "updated");
        let v: Value = serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        assert_eq!(v["someOtherKey"], json!(true));
        assert_eq!(v["mcpServers"]["other"]["command"], json!("x"));
        assert_eq!(v["mcpServers"]["writ"]["command"], json!("/opt/writ-agentd"));
        assert_eq!(v["mcpServers"]["writ"]["args"], json!(["mcp"]));
        // No `type` field for a non-VS-Code host.
        assert!(v["mcpServers"]["writ"].get("type").is_none());

        // Re-running with the same exe → already_present (idempotent).
        assert_eq!(install_json(&spec, "/opt/writ-agentd").unwrap(), "already_present");
    }

    #[test]
    fn install_json_creates_missing_file_and_vscode_shape() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("Code").join("User").join("mcp.json");
        let spec = JsonSpec { path: path.clone(), servers_key: "servers", include_type: true };

        // No file yet → created, with VS Code's `servers` key + explicit stdio type.
        assert_eq!(install_json(&spec, "/opt/writ-agentd").unwrap(), "created");
        let v: Value = serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        assert_eq!(v["servers"]["writ"]["type"], json!("stdio"));
        assert_eq!(v["servers"]["writ"]["command"], json!("/opt/writ-agentd"));
        assert!(v.get("mcpServers").is_none(), "VS Code uses `servers`, not `mcpServers`");
    }

    #[test]
    fn install_json_refuses_malformed_config() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("broken.json");
        std::fs::write(&path, "{ this is not json ").unwrap();
        let spec = JsonSpec { path, servers_key: "mcpServers", include_type: false };
        let err = install_json(&spec, "/opt/writ-agentd").unwrap_err();
        assert_eq!(err.status(), axum::http::StatusCode::BAD_REQUEST);
    }

    #[test]
    fn install_codex_toml_merges_preserving_other_tables() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(".codex").join("config.toml");
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, "model = \"o3\"\n\n[mcp_servers.other]\ncommand = \"x\"\nargs = []\n").unwrap();

        assert_eq!(install_codex_toml(&path, "/opt/writ-agentd").unwrap(), "updated");
        let t: toml::Table = std::fs::read_to_string(&path).unwrap().parse().unwrap();
        assert_eq!(t["model"].as_str(), Some("o3"));
        let servers = t["mcp_servers"].as_table().unwrap();
        assert!(servers.contains_key("other"), "existing server preserved");
        assert_eq!(servers["writ"]["command"].as_str(), Some("/opt/writ-agentd"));
        assert_eq!(servers["writ"]["args"], toml::Value::Array(vec![toml::Value::String("mcp".into())]));

        // Idempotent.
        assert_eq!(install_codex_toml(&path, "/opt/writ-agentd").unwrap(), "already_present");
    }

    #[test]
    fn inspect_json_reports_installed_stale_and_missing() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("mcp.json");
        let spec = JsonSpec { path: path.clone(), servers_key: "mcpServers", include_type: false };

        // No file → not installed, config_exists false.
        let s = inspect_json("cursor", &spec, "/opt/writ-agentd");
        assert_eq!(s["config_exists"], json!(false));
        assert_eq!(s["installed"], json!(false));
        assert_eq!(s["stale"], json!(false));

        // Install our entry → installed true.
        assert_eq!(install_json(&spec, "/opt/writ-agentd").unwrap(), "created");
        let s = inspect_json("cursor", &spec, "/opt/writ-agentd");
        assert_eq!(s["config_exists"], json!(true));
        assert_eq!(s["installed"], json!(true));
        assert_eq!(s["stale"], json!(false));

        // Same file inspected against a DIFFERENT binary path → stale (offer update).
        let s = inspect_json("cursor", &spec, "/new/location/writ-agentd");
        assert_eq!(s["installed"], json!(false));
        assert_eq!(s["stale"], json!(true));
    }

    #[test]
    fn inspect_codex_toml_reports_installed() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        assert_eq!(install_codex_toml(&path, "/opt/writ-agentd").unwrap(), "created");
        let s = inspect_codex_toml("codex", &path, "/opt/writ-agentd");
        assert_eq!(s["installed"], json!(true));
        let s = inspect_codex_toml("codex", &path, "/moved/writ-agentd");
        assert_eq!(s["stale"], json!(true));
    }

    #[tokio::test]
    async fn install_status_route_covers_all_clients_and_reflects_installs() {
        let _g = crate::local::config::test_env_guard();
        let (_dir, st) = test_state().await;

        let scratch = tempfile::tempdir().unwrap();
        std::env::set_var("HOME", scratch.path());
        std::env::set_var("XDG_CONFIG_HOME", scratch.path().join("config"));

        // Fresh machine → all six clients reported, none installed.
        let resp = build_router(st.clone())
            .oneshot(
                Request::builder()
                    .uri("/v1/mcp/install-status")
                    .header("authorization", format!("Bearer {TOKEN}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), 200);
        let bytes = to_bytes(resp.into_body(), 1 << 20).await.unwrap();
        let v: Value = serde_json::from_slice(&bytes).unwrap();
        let clients = v["clients"].as_array().unwrap();
        assert_eq!(clients.len(), 6);
        assert!(clients.iter().all(|c| c["installed"] == json!(false)));

        // Install into cursor, then status reflects it.
        build_router(st.clone())
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/mcp/install-client")
                    .header("authorization", format!("Bearer {TOKEN}"))
                    .header("content-type", "application/json")
                    .body(Body::from(r#"{"client":"cursor"}"#))
                    .unwrap(),
            )
            .await
            .unwrap();

        let resp = build_router(st.clone())
            .oneshot(
                Request::builder()
                    .uri("/v1/mcp/install-status")
                    .header("authorization", format!("Bearer {TOKEN}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let bytes = to_bytes(resp.into_body(), 1 << 20).await.unwrap();
        let v: Value = serde_json::from_slice(&bytes).unwrap();
        let cursor = v["clients"].as_array().unwrap().iter().find(|c| c["client"] == json!("cursor")).unwrap();
        assert_eq!(cursor["installed"], json!(true));

        std::env::remove_var("XDG_CONFIG_HOME");
        std::env::remove_var("WRIT_HOME");
    }

    #[tokio::test]
    async fn install_client_route_writes_config_and_unknown_client_is_400() {
        let _g = crate::local::config::test_env_guard();
        let (_dir, st) = test_state().await;

        // Point config/home dirs at a scratch tree so the route doesn't touch the real user profile.
        let scratch = tempfile::tempdir().unwrap();
        std::env::set_var("HOME", scratch.path());
        std::env::set_var("XDG_CONFIG_HOME", scratch.path().join("config"));

        let resp = build_router(st.clone())
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/mcp/install-client")
                    .header("authorization", format!("Bearer {TOKEN}"))
                    .header("content-type", "application/json")
                    .body(Body::from(r#"{"client":"cursor"}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), 200);
        let bytes = to_bytes(resp.into_body(), 1 << 20).await.unwrap();
        let v: Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(v["ok"], json!(true));
        assert_eq!(v["action"], json!("created"));
        let written = v["path"].as_str().unwrap();
        assert!(written.ends_with(".cursor/mcp.json"), "cursor path: {written}");
        // The file really exists and carries our server (no secret material).
        let raw = std::fs::read_to_string(written).unwrap();
        assert!(raw.contains("\"writ\""));
        assert!(!raw.contains("wlt_") && !raw.contains("wlk_"));

        // Unknown client → 400.
        let resp = build_router(st.clone())
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/mcp/install-client")
                    .header("authorization", format!("Bearer {TOKEN}"))
                    .header("content-type", "application/json")
                    .body(Body::from(r#"{"client":"nope"}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), 400);

        std::env::remove_var("XDG_CONFIG_HOME");
        std::env::remove_var("WRIT_HOME");
    }

    #[tokio::test]
    async fn connect_info_requires_bearer() {
        let _g = crate::local::config::test_env_guard();
        let (_dir, st) = test_state().await;
        let resp = build_router(st)
            .oneshot(
                Request::builder().uri("/v1/mcp/connect-info").body(Body::empty()).unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), 401);
        std::env::remove_var("WRIT_HOME");
    }
}
