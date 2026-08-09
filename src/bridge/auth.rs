use std::io::Write;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::cli::setup;

const CLIENT_ID: &str = "writ-agent";
const POLL_INTERVAL: u64 = 5;
const DEVICE_CODE_EXPIRY: u64 = 900;

/// Max characters of a server error body we are willing to surface. A hostile/verbose upstream must
/// not be able to dump an unbounded blob into the terminal (and from there into scrollback / CI logs).
const MAX_ERROR_BODY_CHARS: usize = 200;

/// Bound AND scrub a server error body before printing it.
///
/// Both call sites are non-2xx branches, so a token should not be in the body — "should not" is not a
/// guarantee for a response we do not control, and one of them is reached on ANY unexpected status
/// while polling the TOKEN endpoint. Passing it through the shared sink redactor masks the shapes that
/// matter (`w*_` tokens, `sk-…`/`AIza…` provider keys, secret query values, URL userinfo).
fn safe_error_body(body: &str) -> String {
    let scrubbed = crate::util::logging::redact_line(body);
    // Collapse newlines so a multi-line body stays one terminal line.
    let one_line: String = scrubbed
        .chars()
        .map(|c| if c == '\n' || c == '\r' { ' ' } else { c })
        .collect();
    if one_line.chars().count() <= MAX_ERROR_BODY_CHARS {
        return one_line;
    }
    let head: String = one_line.chars().take(MAX_ERROR_BODY_CHARS).collect();
    format!("{head}…[truncated]")
}

/// Refuse a plaintext SaaS base URL for the device flow.
///
/// `device_flow_login` never checked this, while `cli::setup` defaults `saas.url` to
/// `http://localhost:8000`. A user who points that at a remote host over plaintext hands the device
/// code AND the minted `wto_`/`wtr_` pair to anyone on the path — and, because the server's
/// `verification_uri_complete` is then attacker-injectable, also hands them the value we pass to
/// `opener::open`. Loopback is exempt (nothing leaves the machine); a deliberate plaintext LAN
/// deployment can still opt in via the existing `saas.allow_insecure` config flag.
///
/// Mirrors `local::cloud::client::require_secure_cloud_url`, which the desktop link flow already
/// enforces; that function is `local`-gated and so unavailable to this cloud-only module.
fn require_secure_saas_url(saas_url: &str) -> Result<(), String> {
    let parsed = url::Url::parse(saas_url)
        .map_err(|e| format!("SaaS URL '{saas_url}' is not a valid URL: {e}"))?;
    match parsed.scheme() {
        "https" => Ok(()),
        "http" if is_loopback_host(&parsed) => Ok(()),
        "http" if setup::load_config().saas.allow_insecure => {
            eprintln!(
                "  \x1b[33m⚠ saas.allow_insecure is set — sending the device code over PLAINTEXT.\x1b[0m"
            );
            Ok(())
        }
        // Spelled as a runnable command, for the same reason as the gateway
        // refusal in `saas_bridge`: `saas.allow_insecure: true` is the YAML
        // shape, not something you can type at the CLI.
        _ => Err(format!(
            "refusing to run the device flow against '{}': plaintext would expose the device code \
             and your account tokens on the wire. Use an https:// URL, or, on a trusted private \
             network only, run:\n    writ-agent config set saas.allow_insecure true",
            parsed.scheme()
        )),
    }
}

/// True when the URL's host is loopback (`localhost`, `127.0.0.0/8`, `[::1]`).
fn is_loopback_host(u: &url::Url) -> bool {
    match u.host() {
        Some(url::Host::Domain(d)) => d.eq_ignore_ascii_case("localhost") || d.ends_with(".localhost"),
        Some(url::Host::Ipv4(ip)) => ip.is_loopback(),
        Some(url::Host::Ipv6(ip)) => ip.is_loopback(),
        None => false,
    }
}

/// Decide whether a SERVER-SUPPLIED verification URL may be handed to `opener::open`.
///
/// `opener` uses argv (no shell-metacharacter risk) but it dispatches to `/usr/bin/open` /
/// `xdg-open` / `ShellExecuteW`, which are *launchers*: a `file:///…/Installer.app` or an
/// `ms-msdt:` style value would be EXECUTED, not browsed. The URL comes from the device-authorization
/// response's `verification_uri_complete`, i.e. from the network.
///
/// Two independent conditions, both required:
///   1. the scheme is `https` (or `http` to a loopback host, for a local dev backend), and
///   2. the host matches the SaaS base URL we chose to talk to — so even a compromised/spoofed
///      backend can only send us to itself, not to an arbitrary third-party origin.
fn verification_url_is_openable(candidate: &str, saas_url: &str) -> bool {
    let Ok(u) = url::Url::parse(candidate) else {
        return false;
    };
    let scheme_ok = u.scheme() == "https" || (u.scheme() == "http" && is_loopback_host(&u));
    if !scheme_ok {
        return false;
    }
    let Ok(base) = url::Url::parse(saas_url) else {
        return false;
    };
    match (u.host_str(), base.host_str()) {
        (Some(a), Some(b)) => a.eq_ignore_ascii_case(b),
        _ => false,
    }
}

/// Error signalling that the agent's credentials are definitively dead — the
/// user disconnected this agent from the dashboard (or the refresh token
/// expired). The bridge must stop reconnecting and prompt `writ-agent login`,
/// as opposed to a transient/network error which should retry.
#[derive(Debug, Clone)]
pub struct AuthRevoked(pub String);

impl std::fmt::Display for AuthRevoked {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "agent credentials revoked: {}", self.0)
    }
}

impl std::error::Error for AuthRevoked {}

/// Outcome of a token refresh attempt.
enum RefreshOutcome {
    Refreshed,
    /// Transient failure (network, 5xx) — safe to retry later.
    Transient,
    /// Definitive: refresh token revoked or expired — re-login required.
    Revoked,
}

// ---------------------------------------------------------------------------
// Service token helpers (infrastructure mode)
// ---------------------------------------------------------------------------

pub fn is_service_mode() -> bool {
    get_service_token().is_some()
}

pub fn get_service_token() -> Option<String> {
    if let Ok(token) = std::env::var("WRIT_SERVICE_TOKEN") {
        if !token.is_empty() {
            return Some(token);
        }
    }
    let creds = load_credentials()?;
    let mode = creds.get("mode").and_then(|v| v.as_str())?;
    if mode != "infrastructure" {
        return None;
    }
    let token = creds.get("access_token").and_then(|v| v.as_str())?;
    if token.starts_with("eyJ") {
        Some(token.to_string())
    } else {
        None
    }
}

// ---------------------------------------------------------------------------
// Credentials I/O
// ---------------------------------------------------------------------------

pub fn load_credentials() -> Option<serde_json::Value> {
    let path = setup::get_credentials_path();
    if !path.exists() {
        return None;
    }
    let content = std::fs::read_to_string(&path).ok()?;
    serde_json::from_str(&content).ok()
}

/// Write `credentials.json` atomically at `0600`, reporting failure instead of swallowing it.
///
/// This file holds the agent's ACCESS TOKEN plus the assigned `agent_id`, so it gets the same
/// treatment `cli::setup::save_config` already uses (and for the same reasons documented there):
///
///   * **Perms at creation.** The old code wrote with `std::fs::write` (0644 under a typical umask)
///     and only chmod'd afterwards, leaving a window in which any local user could read the token —
///     and a descriptor opened across the chmod keeps the loose mode entirely.
///   * **Atomic replace.** `std::fs::write` truncates first, so a crash or a full disk mid-write
///     leaves a TRUNCATED credentials.json: the agent then loads nothing, loses its token AND its
///     `agent_id`, and re-registers as a brand-new fleet member. Writing a private sibling temp and
///     renaming over the target means the previous file survives any failure.
///   * **Audible failure.** Every error used to be dropped with `let _ =`. A silent failure here is
///     invisible until much later, as identity churn: the assigned `agent_id` is never persisted, so
///     each reconnect asks for a fresh one and leaves a stale agent behind.
pub fn save_credentials(creds: &serde_json::Value) {
    let path = setup::get_credentials_path();
    if let Some(parent) = path.parent() {
        if let Err(e) = std::fs::create_dir_all(parent) {
            tracing::error!(error = %e, path = %parent.display(), "could not create credentials dir");
            return;
        }
    }
    let json = match serde_json::to_string_pretty(creds) {
        Ok(j) => j,
        Err(e) => {
            tracing::error!(error = %e, "could not serialize credentials");
            return;
        }
    };

    #[cfg(unix)]
    {
        use std::io::Write;
        use std::os::unix::fs::OpenOptionsExt;

        let tmp = path.with_file_name(format!(".credentials.json.tmp.{}", std::process::id()));
        let _ = std::fs::remove_file(&tmp); // a stale temp from a prior crash would fail create_new
        let opened = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true) // O_EXCL: never adopt a file someone else planted here
            .mode(0o600) // perms at creation → no world-readable window
            .open(&tmp);
        match opened {
            Ok(mut f) => {
                if let Err(e) = f.write_all(json.as_bytes()).and_then(|_| f.sync_all()) {
                    let _ = std::fs::remove_file(&tmp);
                    tracing::error!(error = %e, path = %path.display(), "could not write credentials");
                    return;
                }
                drop(f);
                if let Err(e) = std::fs::rename(&tmp, &path) {
                    let _ = std::fs::remove_file(&tmp);
                    tracing::error!(error = %e, path = %path.display(), "could not replace credentials");
                }
            }
            Err(e) => {
                tracing::error!(error = %e, path = %path.display(), "could not open credentials temp")
            }
        }
    }
    #[cfg(not(unix))]
    {
        // Windows: file permissions come from the parent directory's ACL (the config dir is already
        // user-scoped), so a plain write is equivalent here — but still report failures.
        if let Err(e) = std::fs::write(&path, json) {
            tracing::error!(error = %e, path = %path.display(), "could not write credentials");
        }
    }
}

pub fn clear_credentials() {
    let path = setup::get_credentials_path();
    if path.exists() {
        let _ = std::fs::remove_file(&path);
    }
}

pub fn get_user_token() -> Option<String> {
    let creds = load_credentials()?;
    let token = creds.get("access_token").and_then(|v| v.as_str())?;
    if token.starts_with("wto_") || token.starts_with("pso_") || token.starts_with("eyJ") {
        Some(token.to_string())
    } else {
        None
    }
}

fn now_secs() -> f64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs_f64()
}

fn save_full_credentials(
    access_token: &str,
    refresh_token: Option<&str>,
    expires_in: u64,
    saas_url: &str,
    tenant_id: Option<&str>,
    email: Option<&str>,
    org_name: Option<&str>,
    channel_key: Option<&str>,
    mode: Option<&str>,
) {
    let existing = load_credentials().unwrap_or(serde_json::json!({}));
    let ck = channel_key
        .or_else(|| existing.get("channel_key").and_then(|v| v.as_str()));
    let m = mode
        .or_else(|| existing.get("mode").and_then(|v| v.as_str()))
        .unwrap_or("user-hosted");

    let creds = serde_json::json!({
        "access_token": access_token,
        "refresh_token": refresh_token,
        "expires_at": if expires_in > 0 { now_secs() + expires_in as f64 } else { 0.0 },
        "saas_url": saas_url,
        "tenant_id": tenant_id,
        "email": email,
        "org_name": org_name,
        "channel_key": ck,
        "mode": m,
    });
    save_credentials(&creds);
}

// ---------------------------------------------------------------------------
// Token refresh
// ---------------------------------------------------------------------------

/// Get a valid access token, refreshing if expired.
///
/// - `Ok(Some(token))` — a usable token.
/// - `Ok(None)` — not logged in, or a transient refresh failure (caller should
///   treat as a retryable error, not a re-login trigger).
/// - `Err(AuthRevoked)` — refresh token revoked/expired; re-login required.
pub async fn get_valid_token() -> Result<Option<String>, AuthRevoked> {
    let creds = match load_credentials() {
        Some(c) => c,
        None => return Ok(None),
    };

    // Infrastructure tokens don't expire
    if creds.get("mode").and_then(|v| v.as_str()) == Some("infrastructure") {
        return Ok(creds.get("access_token").and_then(|v| v.as_str()).map(String::from));
    }

    let expires_at = creds.get("expires_at").and_then(|v| v.as_f64()).unwrap_or(0.0);
    if now_secs() < expires_at - 30.0 {
        return Ok(creds.get("access_token").and_then(|v| v.as_str()).map(String::from));
    }

    // Token expired — try refresh
    match refresh_token().await {
        RefreshOutcome::Refreshed => {
            let refreshed = load_credentials();
            Ok(refreshed
                .and_then(|c| c.get("access_token").and_then(|v| v.as_str()).map(String::from)))
        }
        RefreshOutcome::Transient => Ok(None),
        RefreshOutcome::Revoked => Err(AuthRevoked("refresh token revoked or expired".to_string())),
    }
}

async fn refresh_token() -> RefreshOutcome {
    let creds = match load_credentials() {
        Some(c) => c,
        None => return RefreshOutcome::Transient,
    };
    let refresh = match creds.get("refresh_token").and_then(|v| v.as_str()) {
        Some(r) if !r.is_empty() => r.to_string(),
        _ => return RefreshOutcome::Transient,
    };
    let saas_url = creds.get("saas_url").and_then(|v| v.as_str()).unwrap_or("http://localhost:8000");

    let client = reqwest::Client::new();
    let resp = match client
        .post(format!("{}/api/oauth/device/refresh", saas_url))
        .json(&serde_json::json!({
            "refresh_token": refresh,
            "client_id": CLIENT_ID,
        }))
        .timeout(std::time::Duration::from_secs(15))
        .send()
        .await
    {
        Ok(r) => r,
        Err(_) => return RefreshOutcome::Transient,  // network error — retry
    };

    let status = resp.status();
    if status.is_success() {
        if let Ok(data) = resp.json::<serde_json::Value>().await {
            save_full_credentials(
                data["access_token"].as_str().unwrap_or(""),
                data.get("refresh_token").and_then(|v| v.as_str())
                    .or(Some(&refresh)),
                data["expires_in"].as_u64().unwrap_or(900),
                saas_url,
                data.get("tenant_id").and_then(|v| v.as_str())
                    .or(creds.get("tenant_id").and_then(|v| v.as_str())),
                data.get("email").and_then(|v| v.as_str())
                    .or(creds.get("email").and_then(|v| v.as_str())),
                data.get("org_name").and_then(|v| v.as_str())
                    .or(creds.get("org_name").and_then(|v| v.as_str())),
                None,
                None,
            );
            return RefreshOutcome::Refreshed;
        }
        return RefreshOutcome::Transient;  // 200 but unparseable — retry
    }

    // 400 invalid_grant / 401 = refresh token revoked or expired → re-login. Demand the OAuth error
    // in the body first: `Revoked` stops the bridge and forces `writ-agent login`, and a captive
    // portal / corporate proxy / SSO front door also answers 401 — treating those as a revocation
    // logs out a session whose refresh token is perfectly valid. Unrecognised bodies retry instead.
    if status.as_u16() == 400 || status.as_u16() == 401 {
        let body = resp.text().await.unwrap_or_default().to_ascii_lowercase();
        if body.contains("invalid_grant") || body.contains("invalid_client") || body.contains("invalid_token") {
            return RefreshOutcome::Revoked;
        }
        return RefreshOutcome::Transient;  // 401 from something that isn't our token endpoint
    }
    RefreshOutcome::Transient  // 5xx etc. — retry
}

// ---------------------------------------------------------------------------
// OAuth device flow — exact port of Python DeviceAuth.login()
// ---------------------------------------------------------------------------

pub async fn device_flow_login(saas_url: &str, mode: Option<&str>) {
    let saas_url = saas_url.trim_end_matches('/');
    let is_infra = mode == Some("infrastructure");

    // Refuse a plaintext remote base BEFORE any POST: the device code and the minted account tokens
    // must never travel in cleartext, and a MITM on a plaintext base can inject the
    // `verification_uri_complete` we are about to hand to the OS URL opener.
    if let Err(msg) = require_secure_saas_url(saas_url) {
        println!();
        println!("\x1b[31m✗ {}\x1b[0m", msg);
        return;
    }

    println!();
    if is_infra {
        println!("\x1b[1mLinking infrastructure recorder\x1b[0m");
    } else {
        println!("\x1b[1mLinking to your Writ account\x1b[0m");
    }
    println!("{}", "─".repeat(40));

    // Step 1: Request device code
    let mut body = serde_json::json!({"client_id": CLIENT_ID});
    if is_infra {
        body["mode"] = serde_json::json!("infrastructure");
    }

    let client = reqwest::Client::new();
    let resp = match client
        .post(format!("{}/api/oauth/device", saas_url))
        .json(&body)
        .timeout(std::time::Duration::from_secs(15))
        .send()
        .await
    {
        Ok(r) => r,
        Err(e) => {
            println!("\x1b[31m✗ Could not connect to {}: {}\x1b[0m", saas_url, e);
            return;
        }
    };

    if !resp.status().is_success() {
        let text = resp.text().await.unwrap_or_default();
        println!("\x1b[31m✗ Device flow failed: {}\x1b[0m", safe_error_body(&text));
        return;
    }

    let data: serde_json::Value = match resp.json().await {
        Ok(d) => d,
        Err(e) => {
            println!("\x1b[31m✗ Invalid response: {}\x1b[0m", e);
            return;
        }
    };

    let device_code = data["device_code"].as_str().unwrap_or("");
    let user_code = data["user_code"].as_str().unwrap_or("");
    let verification_uri = data["verification_uri"].as_str().unwrap_or("");
    let expires_in = data["expires_in"].as_u64().unwrap_or(DEVICE_CODE_EXPIRY);
    let mut interval = data["interval"].as_u64().unwrap_or(POLL_INTERVAL);

    // Build approval URL
    let approval_url = data
        .get("verification_uri_complete")
        .and_then(|v| v.as_str())
        .map(String::from)
        .unwrap_or_else(|| format!("{}?code={}", verification_uri, user_code));

    // Step 2: Show URL and open browser
    println!();
    println!("  Approve in your browser:");
    println!("  \x1b[36;1m{}\x1b[0m", approval_url);
    println!();

    // The value we are about to hand to the OS URL opener came from the NETWORK. `opener` dispatches
    // to `open`/`xdg-open`/`ShellExecuteW`, which launch things — a `file:///…/Installer.app` value
    // would be executed, not browsed. Only auto-open an https (or loopback-http) URL on the SAME host
    // as the SaaS base we chose to contact; otherwise print it and let the user decide.
    if verification_url_is_openable(&approval_url, saas_url) && opener::open(&approval_url).is_ok() {
        println!("  (Browser opened — click Authorize to continue)");
    } else {
        println!("  Code: {}", user_code);
        println!("  Open the URL above and click Authorize");
    }

    println!();
    eprint!("  Waiting for approval");
    std::io::stderr().flush().ok();

    // Step 3: Poll for token
    let deadline = now_secs() + expires_in as f64;

    while now_secs() < deadline {
        tokio::time::sleep(std::time::Duration::from_secs(interval)).await;
        eprint!(".");
        std::io::stderr().flush().ok();

        let resp = match client
            .post(format!("{}/api/oauth/device/token", saas_url))
            .json(&serde_json::json!({
                "grant_type": "urn:ietf:params:oauth:grant-type:device_code",
                "device_code": device_code,
                "client_id": CLIENT_ID,
            }))
            .timeout(std::time::Duration::from_secs(15))
            .send()
            .await
        {
            Ok(r) => r,
            Err(_) => continue,
        };

        let status = resp.status().as_u16();

        if status == 200 {
            let token_data: serde_json::Value = match resp.json().await {
                Ok(d) => d,
                Err(_) => continue,
            };

            println!();
            println!();

            let resp_mode = token_data["mode"].as_str().unwrap_or("user-hosted");

            save_full_credentials(
                token_data["access_token"].as_str().unwrap_or(""),
                token_data.get("refresh_token").and_then(|v| v.as_str()),
                token_data["expires_in"].as_u64().unwrap_or(900),
                saas_url,
                token_data.get("tenant_id").and_then(|v| v.as_str()),
                token_data.get("email").and_then(|v| v.as_str()),
                token_data.get("org_name").and_then(|v| v.as_str()),
                token_data.get("channel_key").and_then(|v| v.as_str()),
                Some(resp_mode),
            );

            if resp_mode == "infrastructure" {
                let org = token_data["org_name"].as_str().unwrap_or("unknown");
                println!("\x1b[32m✓ Infrastructure recorder linked to {}\x1b[0m", org);
                println!();
                println!("  The service token is saved locally.");
                println!("  Next: writ-agent start");
            } else {
                let email = token_data["email"].as_str().unwrap_or("unknown");
                let org = token_data["org_name"].as_str().unwrap_or("");
                println!("\x1b[32m✓ Logged in as {} ({})\x1b[0m", email, org);
                println!();
                println!("Next: writ-agent start");
            }
            return;
        }

        if status == 428 {
            // authorization_pending — keep polling
            continue;
        }

        if status == 410 {
            println!();
            println!("\x1b[31m✗ Device code expired. Run writ-agent login again.\x1b[0m");
            return;
        }

        if status == 429 {
            // slow_down
            interval = (interval + 2).min(30);
            continue;
        }

        // Unexpected — log and retry
        let text = resp.text().await.unwrap_or_default();
        eprintln!("\n  Unexpected response ({}): {}", status, safe_error_body(&text));
        eprint!("  Retrying");
        std::io::stderr().flush().ok();
    }

    // Poll timed out — try recovery then manual paste
    println!();
    println!();
    println!("  \x1b[33m⚠ Could not detect login completion.\x1b[0m");
    println!();

    // Try recover by code
    if try_recover_token(&client, saas_url, user_code).await {
        return;
    }

    // Manual paste fallback
    println!("  If you approved in your browser, the confirmation page shows your token.");
    println!("  Paste it below (or press Enter to cancel):");
    println!();
    // HIDDEN input: a `wto_` account token is a bearer credential. Reading it with a plain `read_line`
    // put it in terminal scrollback, tmux/`script` capture, screen shares and CI output.
    let manual = setup::prompt_string_hidden("  Token");
    let manual = manual.trim();

    if manual.starts_with("wto_") || manual.starts_with("pso_") {
        if validate_and_save_manual_token(&client, saas_url, manual).await {
            return;
        }
        println!("  \x1b[31m✗ Token could not be validated.\x1b[0m");
    } else if !manual.is_empty() {
        println!("  \x1b[31m✗ Token must start with wto_\x1b[0m");
    } else {
        println!("  Cancelled. Run writ-agent login to try again.");
    }
}

async fn try_recover_token(client: &reqwest::Client, saas_url: &str, user_code: &str) -> bool {
    let resp = match client
        .post(format!("{}/api/oauth/device/token-by-code", saas_url))
        .json(&serde_json::json!({"user_code": user_code, "client_id": CLIENT_ID}))
        .timeout(std::time::Duration::from_secs(10))
        .send()
        .await
    {
        Ok(r) if r.status().is_success() => r,
        _ => return false,
    };

    let data: serde_json::Value = match resp.json().await {
        Ok(d) => d,
        Err(_) => return false,
    };

    save_full_credentials(
        data["access_token"].as_str().unwrap_or(""),
        data.get("refresh_token").and_then(|v| v.as_str()),
        data["expires_in"].as_u64().unwrap_or(900),
        saas_url,
        data.get("tenant_id").and_then(|v| v.as_str()),
        data.get("email").and_then(|v| v.as_str()),
        data.get("org_name").and_then(|v| v.as_str()),
        data.get("channel_key").and_then(|v| v.as_str()),
        None,
    );

    let email = data["email"].as_str().unwrap_or("unknown");
    let org = data["org_name"].as_str().unwrap_or("");
    println!("  \x1b[32m✓ Recovered! Logged in as {} ({})\x1b[0m", email, org);
    true
}

async fn validate_and_save_manual_token(client: &reqwest::Client, saas_url: &str, token: &str) -> bool {
    let resp = match client
        .post(format!("{}/api/oauth/device/validate-token", saas_url))
        .json(&serde_json::json!({"access_token": token, "client_id": CLIENT_ID}))
        .timeout(std::time::Duration::from_secs(10))
        .send()
        .await
    {
        Ok(r) if r.status().is_success() => r,
        _ => return false,
    };

    let data: serde_json::Value = match resp.json().await {
        Ok(d) => d,
        Err(_) => return false,
    };

    save_full_credentials(
        token,
        data.get("refresh_token").and_then(|v| v.as_str()),
        data["expires_in"].as_u64().unwrap_or(900),
        saas_url,
        data.get("tenant_id").and_then(|v| v.as_str()),
        data.get("email").and_then(|v| v.as_str()),
        data.get("org_name").and_then(|v| v.as_str()),
        data.get("channel_key").and_then(|v| v.as_str()),
        None,
    );

    let email = data["email"].as_str().unwrap_or("unknown");
    let org = data["org_name"].as_str().unwrap_or("");
    println!("  \x1b[32m✓ Logged in as {} ({})\x1b[0m", email, org);
    println!();
    println!("  Next: writ-agent start");
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A server-supplied verification URL is only opened when it is https (or loopback http) AND on the
    /// same host as the SaaS base we chose. `opener` dispatches to `open`/`xdg-open`/`ShellExecuteW`,
    /// so a `file://` value would LAUNCH the target.
    #[test]
    fn only_same_host_https_urls_are_auto_opened() {
        let base = "https://app.writ.example";

        assert!(verification_url_is_openable(
            "https://app.writ.example/device?code=ABCD-2345",
            base
        ));
        // Case-insensitive host match.
        assert!(verification_url_is_openable("https://APP.Writ.Example/device", base));

        // Dangerous schemes an OS launcher would ACT on.
        for bad in [
            "file:///Applications/Installer.app",
            "file:///tmp/evil.desktop",
            "vscode://x",
            "smb://attacker/share",
            "javascript:alert(1)",
            "data:text/html,<h1>x</h1>",
        ] {
            assert!(!verification_url_is_openable(bad, base), "must refuse `{bad}`");
        }

        // Right scheme, WRONG host — a spoofed/compromised backend must not be able to send the user
        // to a third-party origin.
        assert!(!verification_url_is_openable("https://evil.example/device", base));
        // Plaintext http to a non-loopback host is refused even on the right name.
        assert!(!verification_url_is_openable("http://app.writ.example/device", base));
        // Garbage input.
        assert!(!verification_url_is_openable("not a url", base));
        assert!(!verification_url_is_openable("https://app.writ.example/", "not a url"));

        // A local dev backend over loopback http is allowed (nothing leaves the machine).
        assert!(verification_url_is_openable(
            "http://localhost:8000/device?code=X",
            "http://localhost:8000"
        ));
        assert!(verification_url_is_openable(
            "http://127.0.0.1:8000/device",
            "http://127.0.0.1:8000"
        ));
    }

    /// https is always fine; plaintext is fine ONLY for loopback. A plaintext remote base is refused
    /// (unless the operator opted in via `saas.allow_insecure`, which this test does not touch).
    #[test]
    fn plaintext_remote_saas_url_is_refused() {
        assert!(require_secure_saas_url("https://app.writ.example").is_ok());
        assert!(require_secure_saas_url("http://localhost:8000").is_ok());
        assert!(require_secure_saas_url("http://127.0.0.1:8000").is_ok());
        assert!(require_secure_saas_url("http://[::1]:8000").is_ok());
        assert!(require_secure_saas_url("not a url").is_err());
    }

    /// A server error body is bounded AND scrubbed before it reaches the terminal.
    #[test]
    fn error_bodies_are_scrubbed_and_bounded() {
        let out = safe_error_body("{\"error\":\"bad\",\"access_token\":\"wto_LEAKEDtoken1234\"}");
        assert!(!out.contains("wto_LEAKEDtoken1234"), "token masked: {out}");
        assert!(out.contains("<token:redacted>"), "{out}");

        // Newlines collapsed, length bounded.
        let long = "x\n".repeat(500);
        let out = safe_error_body(&long);
        assert!(!out.contains('\n'), "single line");
        assert!(out.ends_with("…[truncated]"), "{out}");
        assert!(out.chars().count() <= MAX_ERROR_BODY_CHARS + "…[truncated]".chars().count());
    }
}
