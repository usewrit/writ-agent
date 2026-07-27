//! `writ mcp stdio` / `writ-agentd mcp` — the MCP server over stdin/stdout (line-delimited JSON-RPC).
//!
//! Two modes, picked automatically:
//!   * PROXY — when a running daemon is discovered via `~/.writ/runtime.json` (and answers a live
//!     probe), each stdin frame is forwarded to its loopback `POST /mcp` with the `wlt_` bearer and
//!     the reply is written back to stdout. This is the DESKTOP path: the app's daemon stays the
//!     single owner of the store + warm browser (the singleton lock would refuse a second bootstrap
//!     anyway), and the MCP client's config needs NO credential — this child process reads the
//!     `0600` descriptor itself, so the file remains the trust boundary.
//!   * BOOT — with no daemon running, bootstrap a full [`AppState`] (encrypted store + vault + real
//!     engine, the same cold-start the daemon uses) and serve stdio directly. This is the HEADLESS
//!     path (zero-config: first run scaffolds the home).
//!
//! Trust on the stdio transport is by process ownership (no bearer there); only the loopback HTTP
//! hop inside proxy mode carries the descriptor's token. Diagnostics go to `tracing` (stderr);
//! stdout is reserved for the JSON-RPC stream. NEVER logs a token or secret.

use crate::local::app;
use crate::local::app::runtime_file::{self, RuntimeInfo};
use crate::local::config::Paths;
use crate::local::error::{LocalError, LocalResult};
use crate::local::mcp;
use crate::local::mcp::protocol::{JsonRpcResponse, INTERNAL_ERROR, PARSE_ERROR};
use serde_json::Value;
use std::collections::HashSet;
use std::path::PathBuf;
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

/// Liveness-probe budget for daemon discovery — loopback and cheap.
const PROBE_TIMEOUT: Duration = Duration::from_secs(2);

/// Per-frame budget in proxy mode. A `tools/call` runs a real workflow (browser navigation,
/// retries), so this is generous; the engine enforces its own per-run timeout well below it.
const FRAME_TIMEOUT: Duration = Duration::from_secs(15 * 60);

/// Run the stdio MCP surface until stdin closes: proxy to a live daemon when one is discovered,
/// else bootstrap a local backend in-process and serve directly.
pub async fn run() -> LocalResult<()> {
    align_with_desktop_active_profile();
    if let Some(info) = discover_daemon_with_startup_grace().await {
        tracing::info!(port = info.port, "mcp stdio: running daemon discovered — proxying to /mcp");
        return proxy_stdio(&info).await;
    }

    tracing::info!("mcp stdio: no running daemon — bootstrapping a local backend (process-trust)");
    let state = app::bootstrap().await?;
    let result = mcp::run_stdio(state).await;

    // Clean up the lock + runtime.json this process published so the next owner starts fresh. Best
    // effort — never override the loop's result.
    if let Ok(paths) = Paths::resolve() {
        app::heartbeat::remove(&paths);
        app::release(&paths);
    }
    result
}

async fn discover_daemon_with_startup_grace() -> Option<RuntimeInfo> {
    for attempt in 0..3 {
        if let Some(info) = discover_daemon().await {
            return Some(info);
        }
        if attempt < 2 {
            tokio::time::sleep(Duration::from_millis(350)).await;
        }
    }
    None
}

/// The desktop isolates signed-in/local profiles under `<base>/profiles/<id>` and starts its daemon
/// with that directory as WRIT_HOME. An MCP client is spawned independently and does not inherit the
/// desktop process environment, so resolve the same `active_profile` pointer before looking for
/// runtime.json. Without this, MCP silently boots a second store under `~/.writ` and saved workflows
/// never appear in the open desktop app.
// The profile-identity env var (`WRIT_PROFILE`). Tied to the token module's constant in
// cloud builds; the cloud-free fleet build has no `local::cloud`, so it carries the
// literal — the value is the shell↔daemon contract and cannot drift silently.
#[cfg(feature = "cloud")]
const ENV_PROFILE: &str = crate::local::cloud::token::ENV_PROFILE;
#[cfg(not(feature = "cloud"))]
const ENV_PROFILE: &str = "WRIT_PROFILE";

fn align_with_desktop_active_profile() {
    if std::env::var_os("WRIT_HOME").is_some() {
        return; // explicit operator/client override always wins
    }
    let Some(base) = dirs::home_dir().map(|h| h.join(".writ")) else { return };
    let profile = std::fs::read_to_string(base.join("active_profile"))
        .unwrap_or_else(|_| "local".into());
    let profile = profile.trim();
    let safe = !profile.is_empty()
        && profile != "local"
        && profile.len() <= 128
        && profile.chars().all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-');
    if safe {
        std::env::set_var("WRIT_HOME", base.join("profiles").join(profile));
        // Identity MUST follow home. `assert_profile_owner` compares the DB's durable
        // owner stamp against `token::active_profile()`, which reads WRIT_PROFILE and
        // defaults to "local" — so homing into a profile dir WITHOUT also claiming its
        // identity makes the fallback bootstrap (desktop daemon down) adopt a fresh DB
        // there as `local`, permanently bricking the profile with an isolation
        // violation on every subsequent desktop boot.
        if std::env::var_os(ENV_PROFILE).is_none() {
            std::env::set_var(ENV_PROFILE, profile);
        }
    }
}

/// Discover a live daemon: read `runtime.json`, then confirm it actually answers `/v1/agent` within
/// the probe budget. A stale descriptor (crashed daemon) fails the probe and falls through to the
/// bootstrap path, which acquires the singleton lock cleanly.
async fn discover_daemon() -> Option<RuntimeInfo> {
    let http = reqwest::Client::builder().timeout(PROBE_TIMEOUT).build().ok()?;
    for paths in daemon_candidate_homes() {
        let Some(info) = runtime_file::read(&paths).ok().flatten() else { continue };
        let url = format!("http://127.0.0.1:{}/v1/agent", info.port);
        match http.get(&url).bearer_auth(&info.token).send().await {
            Ok(resp) if resp.status().is_success() => return Some(info),
            _ => tracing::warn!(home = %paths.root.display(), "mcp stdio: stale daemon descriptor; trying the next desktop profile"),
        }
    }
    None
}

/// Candidate order is deliberate: configured/current home first, then the desktop's active profile,
/// then local and other known profiles. This makes stdio MCP a bridge to an already-running desktop
/// daemon even when the AI client inherited a stale/different WRIT_HOME.
fn daemon_candidate_homes() -> Vec<Paths> {
    let mut roots: Vec<PathBuf> = Vec::new();
    if let Ok(p) = Paths::resolve() {
        roots.push(p.root.clone());
    }
    if let Some(base) = dirs::home_dir().map(|h| h.join(".writ")) {
        if let Ok(profile) = std::fs::read_to_string(base.join("active_profile")) {
            let p = profile.trim();
            if p != "local" && !p.is_empty() && p.len() <= 128
                && p.chars().all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-') {
                roots.push(base.join("profiles").join(p));
            }
        }
        roots.push(base.clone());
        if let Ok(entries) = std::fs::read_dir(base.join("profiles")) {
            for entry in entries.flatten().take(32) {
                if entry.file_type().map(|t| t.is_dir()).unwrap_or(false) {
                    roots.push(entry.path());
                }
            }
        }
    }
    let mut seen = HashSet::new();
    roots.into_iter().filter(|p| seen.insert(p.clone())).map(Paths::at).collect()
}

/// The stdio↔HTTP proxy loop: one JSON-RPC frame per stdin line → `POST /mcp` → one reply line.
/// Notifications (daemon answers `202`/empty) produce no output line, matching the direct runner.
/// Transport failures become well-formed JSON-RPC error frames so the client never hangs on a
/// missing reply; the loop keeps serving until stdin closes.
async fn proxy_stdio(info: &RuntimeInfo) -> LocalResult<()> {
    let http = reqwest::Client::builder()
        .timeout(FRAME_TIMEOUT)
        .user_agent(concat!("writ-mcp-proxy/", env!("CARGO_PKG_VERSION")))
        .build()
        .map_err(|e| LocalError::Internal(format!("mcp proxy http client build: {e}")))?;
    let url = format!("http://127.0.0.1:{}/mcp", info.port);

    let stdin = tokio::io::stdin();
    let mut reader = BufReader::new(stdin).lines();
    let mut stdout = tokio::io::stdout();

    while let Some(line) = reader.next_line().await? {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        // Parse locally first so a malformed frame never round-trips to the daemon.
        let frame: Value = match serde_json::from_str(trimmed) {
            Ok(v) => v,
            Err(e) => {
                tracing::debug!(error = %e, "mcp proxy: parse error");
                write_line(&mut stdout, err_line(Value::Null, PARSE_ERROR, "Parse error")).await?;
                continue;
            }
        };
        // Best-effort id for transport-failure replies (batch arrays have none → null).
        let id = frame.get("id").cloned().unwrap_or(Value::Null);

        let reply = match http.post(&url).bearer_auth(&info.token).json(&frame).send().await {
            // 202 = every frame was a notification → no reply line, per the stdio contract.
            Ok(resp) if resp.status() == reqwest::StatusCode::ACCEPTED => None,
            Ok(resp) if resp.status().is_success() => {
                let text = resp.text().await.unwrap_or_default();
                if text.trim().is_empty() { None } else { Some(compact(&text)) }
            }
            Ok(resp) => {
                tracing::error!(status = %resp.status(), "mcp proxy: daemon rejected the frame");
                Some(err_line(id, INTERNAL_ERROR, "daemon rejected the frame"))
            }
            Err(e) => {
                tracing::error!(error = %e, "mcp proxy: daemon unreachable");
                Some(err_line(id, INTERNAL_ERROR, "daemon unreachable"))
            }
        };
        if let Some(buf) = reply {
            write_line(&mut stdout, buf).await?;
        }
    }

    tracing::info!("mcp proxy: stdin closed, exiting");
    Ok(())
}

/// Write one reply line to stdout and flush (the client reads line-delimited JSON).
async fn write_line(stdout: &mut tokio::io::Stdout, mut buf: String) -> LocalResult<()> {
    buf.push('\n');
    stdout.write_all(buf.as_bytes()).await?;
    stdout.flush().await?;
    Ok(())
}

/// Re-serialize an HTTP response body as a single compact line. The daemon emits compact JSON
/// already; this is defense against any pretty/whitespace variant breaking the line protocol.
fn compact(text: &str) -> String {
    match serde_json::from_str::<Value>(text) {
        Ok(v) => v.to_string(),
        Err(_) => text.split_whitespace().collect::<Vec<_>>().join(" "),
    }
}

/// A well-formed single-line JSON-RPC error frame for transport-level failures.
fn err_line(id: Value, code: i64, message: &str) -> String {
    serde_json::to_string(&JsonRpcResponse::err(id, code, message))
        .unwrap_or_else(|_| format!(r#"{{"jsonrpc":"2.0","id":null,"error":{{"code":{code},"message":"{message}"}}}}"#))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn compact_flattens_multiline_json() {
        let pretty = "{\n  \"jsonrpc\": \"2.0\",\n  \"id\": 1,\n  \"result\": {}\n}";
        let line = compact(pretty);
        assert!(!line.contains('\n'), "single line: {line}");
        let v: Value = serde_json::from_str(&line).unwrap();
        assert_eq!(v["id"], json!(1));
    }

    #[test]
    fn err_line_is_single_line_jsonrpc() {
        let line = err_line(json!(7), INTERNAL_ERROR, "daemon unreachable");
        assert!(!line.contains('\n'));
        let v: Value = serde_json::from_str(&line).unwrap();
        assert_eq!(v["id"], json!(7));
        assert_eq!(v["error"]["code"], json!(INTERNAL_ERROR));
        assert_eq!(v["error"]["message"], json!("daemon unreachable"));
    }
}
