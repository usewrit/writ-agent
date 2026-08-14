//! Implementations of the `writ` CLI subcommands. Kept here so `src/bin/writ.rs` stays a thin clap
//! shell. Each command returns [`LocalResult<()>`]; the binary maps an `Err` to a non-zero exit.
//!
//! Surfaces:
//!   * `init`            — scaffold `~/.writ` (dirs + default config.toml + mint the `wlt_` token).
//!   * `start`           — launch the daemon (foreground or detached), resolving the `writ-agentd`
//!                          sibling binary next to this `writ` executable.
//!   * `status`          — read `agentd.json` / `runtime.json` for a quick health line (no network),
//!                          optionally enriched by a loopback `GET /v1/agent` when reachable.
//!   * `token show|rotate` — print or re-mint the loopback `wlt_` token.
//!   * `config get|set`  — read/write fields of `~/.writ/config.toml`.
//!   * `cloud login|logout|status` — drive the device-flow / unlink / reflection via the running
//!                          daemon's `/v1/cloud/*` REST (the daemon owns the keyring + DB).
//!
//! SECURITY: `token show` prints the `wlt_` loopback token ON PURPOSE (the user asked for it, to wire
//! a local client) — that is the one place a token reaches stdout, and only via this explicit command.
//! Nothing here logs a token through `tracing`. `~/.writ` paths stay local.
//!
//! House style: module-local error reuse (`crate::local::error`), `tracing` only, no `async-trait`.

use super::client::DaemonClient;
use crate::local::app::heartbeat::{self, Heartbeat};
use crate::local::app::runtime_file::{self, RuntimeInfo};
use crate::local::config::{self, LocalConfig, Paths};
use crate::local::error::{LocalError, LocalResult};
use serde_json::Value;
use std::io::Write;
use std::path::PathBuf;
use std::process::Command;

/// The sibling daemon binary name (resolved next to the running `writ` executable).
const DAEMON_BIN: &str = "writ-agentd";

// ────────────────────────────────────────────────────────────────────────────────────────────────
// init
// ────────────────────────────────────────────────────────────────────────────────────────────────

/// `writ init` — first-run scaffold of `~/.writ`.
///
/// Creates the directory tree (`0700` root), materializes a documented default `config.toml`, and
/// mints the loopback `wlt_` token if absent. Idempotent: re-running leaves an existing config/token
/// untouched (it only fills what's missing). Prints the resolved home so the user knows where it is.
pub fn init(paths: &Paths) -> LocalResult<()> {
    paths.ensure_dirs()?;
    // load_config materializes a default config.toml on first run (best-effort) and returns the
    // effective config; calling it here gives the user a documented file to edit.
    let _cfg = config::load_config(paths);
    // Mint (or reuse) the loopback token so a freshly-init'd home is immediately usable.
    let _token = config::load_or_create_token(paths)?;

    println!("Initialized Writ home at {}", paths.root.display());
    println!("  config: {}", paths.config_toml().display());
    println!("  db:     {}", paths.db().display());
    println!("Run `writ start` to launch the local daemon.");
    Ok(())
}

// ────────────────────────────────────────────────────────────────────────────────────────────────
// start
// ────────────────────────────────────────────────────────────────────────────────────────────────

/// `writ start` — launch the `writ-agentd` daemon.
///
/// In `foreground` mode the daemon inherits this terminal (stdout/stderr) and `writ` blocks until it
/// exits, forwarding its exit code. Otherwise the daemon is spawned DETACHED (a true background
/// process that survives the CLI exiting) and `writ` returns immediately after confirming it came up.
///
/// The daemon enforces its own singleton lock, so a second `start` while one is already running fails
/// fast inside the daemon (we surface that as a friendly message in the detached path by checking the
/// descriptor first).
pub fn start(paths: &Paths, foreground: bool) -> LocalResult<()> {
    // If a daemon is already up, don't try to start a second (the lock would refuse anyway).
    if let Some(info) = runtime_file::read(paths)? {
        if pid_alive(info.pid) {
            println!(
                "writ-agentd is already running (pid {}, port {}).",
                info.pid, info.port
            );
            return Ok(());
        }
        // Stale descriptor (dead pid) — the daemon's own boot will reclaim the lock; fall through.
        tracing::debug!(pid = info.pid, "stale runtime.json (owner not alive); starting a fresh daemon");
    }

    let daemon = resolve_daemon_bin()?;
    tracing::info!(bin = %daemon.display(), foreground, "launching writ-agentd");

    if foreground {
        // Inherit the terminal; block until the daemon exits and forward its status.
        let status = Command::new(&daemon)
            .status()
            .map_err(|e| LocalError::Internal(format!("failed to launch {}: {e}", daemon.display())))?;
        if status.success() {
            return Ok(());
        }
        return Err(LocalError::Internal(format!(
            "writ-agentd exited with status {:?}",
            status.code()
        )));
    }

    // Detached: spawn without waiting. stdin/out/err go to null so the child fully decouples from the
    // terminal (the daemon writes its own logs under ~/.writ/logs via the LaunchAgent/systemd path,
    // or to its console when started by hand).
    let child = Command::new(&daemon)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .map_err(|e| LocalError::Internal(format!("failed to launch {}: {e}", daemon.display())))?;

    println!("Started writ-agentd (pid {}).", child.id());
    println!("Use `writ status` to check health, or `writ start --foreground` to run it attached.");
    Ok(())
}

/// Resolve the `writ-agentd` binary: prefer a sibling next to the running `writ` executable (the
/// normal install layout), else fall back to a bare `writ-agentd` on `PATH`.
fn resolve_daemon_bin() -> LocalResult<PathBuf> {
    if let Ok(exe) = std::env::current_exe() {
        if let Some(dir) = exe.parent() {
            let sibling = dir.join(daemon_file_name());
            if sibling.exists() {
                return Ok(sibling);
            }
        }
    }
    // Fall back to PATH resolution by the OS at spawn time.
    Ok(PathBuf::from(DAEMON_BIN))
}

/// Platform executable filename for the daemon (`.exe` suffix on Windows).
fn daemon_file_name() -> String {
    if cfg!(target_os = "windows") {
        format!("{DAEMON_BIN}.exe")
    } else {
        DAEMON_BIN.to_string()
    }
}

// ────────────────────────────────────────────────────────────────────────────────────────────────
// status
// ────────────────────────────────────────────────────────────────────────────────────────────────

/// `writ status` — a quick health summary read from the on-disk descriptors, enriched by a loopback
/// `GET /v1/agent` when the daemon answers.
///
/// Source of truth, cheapest first:
///   1. `agentd.json` heartbeat → pid / started_at / healthy / active_runs / due_monitors / warm.
///   2. `runtime.json` → port (+ confirms a daemon published discovery).
///   3. live `GET /v1/agent` (best-effort) → version + a definitive "reachable" signal.
///
/// Prints a friendly "not running" line (and returns Ok) when nothing is found, so `status` is safe
/// to call any time. `--json` dumps the merged snapshot for scripts.
pub fn status(paths: &Paths, json: bool) -> LocalResult<()> {
    let hb = heartbeat::read(paths).ok().flatten();
    let info = runtime_file::read(paths).ok().flatten();

    // Best-effort live probe: only if a descriptor exists AND its pid looks alive.
    let live = match &info {
        Some(i) if pid_alive(i.pid) => DaemonClient::from_runtime(i)
            .ok()
            .and_then(|c| c.get("/v1/agent").ok()),
        _ => None,
    };

    if json {
        let merged = serde_json::json!({
            "running": is_running(&hb, &info),
            "heartbeat": hb.as_ref().map(heartbeat_json),
            "runtime": info.as_ref().map(runtime_json),
            "agent": live,
        });
        println!("{}", serde_json::to_string_pretty(&merged)?);
        return Ok(());
    }

    match (&hb, &info) {
        (None, None) => {
            println!("writ-agentd: not running (no agentd.json / runtime.json under {}).", paths.root.display());
        }
        _ => {
            let pid = hb.as_ref().map(|h| h.pid).or_else(|| info.as_ref().map(|i| i.pid));
            let port = info.as_ref().map(|i| i.port);
            let reachable = live.is_some();
            let running = is_running(&hb, &info);

            println!("writ-agentd: {}", if running { "running" } else { "not running (stale descriptor)" });
            if let Some(pid) = pid {
                println!("  pid:           {pid}{}", if pid_alive(pid) { "" } else { " (not alive)" });
            }
            if let Some(port) = port {
                println!("  port:          {port} (loopback)");
            }
            if let Some(h) = &hb {
                println!("  started:       {}", h.started_at);
                println!("  active runs:   {}", h.active_runs);
                println!("  due monitors:  {}", h.due_monitors);
                println!("  warm browser:  {}", h.warm_browser);
                if let Some(t) = &h.last_tick_at {
                    println!("  last tick:     {t}");
                }
            }
            if let Some(agent) = &live {
                if let Some(v) = agent.get("version").and_then(Value::as_str) {
                    println!("  version:       {v}");
                }
            }
            println!("  loopback API:  {}", if reachable { "reachable" } else { "not reachable" });
        }
    }
    Ok(())
}

/// "Running" = a heartbeat or runtime descriptor exists AND its recorded pid is a live process.
fn is_running(hb: &Option<Heartbeat>, info: &Option<RuntimeInfo>) -> bool {
    let pid = hb.as_ref().map(|h| h.pid).or_else(|| info.as_ref().map(|i| i.pid));
    pid.map(pid_alive).unwrap_or(false)
}

/// Non-secret heartbeat projection for `--json` (carries no token; the heartbeat never did).
fn heartbeat_json(h: &Heartbeat) -> Value {
    serde_json::json!({
        "pid": h.pid,
        "started_at": h.started_at,
        "healthy": h.healthy,
        "active_runs": h.active_runs,
        "due_monitors": h.due_monitors,
        "last_tick_at": h.last_tick_at,
        "warm_browser": h.warm_browser,
    })
}

/// Non-secret runtime projection for `--json` — pid/port/version only. The `wlt_` token in the
/// descriptor is DELIBERATELY OMITTED (status output must never leak it).
fn runtime_json(i: &RuntimeInfo) -> Value {
    serde_json::json!({
        "pid": i.pid,
        "port": i.port,
        "version": i.version,
        "started_at": i.started_at,
    })
}

// ────────────────────────────────────────────────────────────────────────────────────────────────
// token
// ────────────────────────────────────────────────────────────────────────────────────────────────

/// `writ token show` — print the loopback `wlt_` bearer so the user can wire a local client.
///
/// This is the ONE intentional place a token reaches stdout. It is printed bare (no label prefix on
/// the value line is added beyond a heading) so it is easy to capture in a shell var.
pub fn token_show(paths: &Paths) -> LocalResult<()> {
    let token = config::load_or_create_token(paths)?;
    println!("{token}");
    Ok(())
}

/// `writ token rotate` — mint a FRESH loopback `wlt_` token, replacing the persisted one.
///
/// A running daemon holds the OLD token in memory until it restarts, so rotation only takes full
/// effect after `writ start --foreground` (or a service restart). We print that reminder. The new
/// token is written `0600`.
pub fn token_rotate(paths: &Paths) -> LocalResult<()> {
    paths.ensure_dirs()?;
    let token = rotate_local_token(paths)?;
    println!("Rotated the loopback token.");
    println!("{token}");
    if runtime_file::read(paths).ok().flatten().is_some() {
        println!("Note: a running daemon keeps the previous token until it restarts — run `writ start` again to apply.");
    }
    Ok(())
}

/// Mint a new `wlt_` token and overwrite the persisted one (`0600`). Distinct from
/// `load_or_create_token` (which is mint-IF-ABSENT); rotate always replaces.
fn rotate_local_token(paths: &Paths) -> LocalResult<String> {
    // Remove the existing file so `load_or_create_token` mints + persists a fresh one.
    let path = paths.local_token();
    if path.exists() {
        std::fs::remove_file(&path)?;
    }
    config::load_or_create_token(paths)
}

// ────────────────────────────────────────────────────────────────────────────────────────────────
// config get|set
// ────────────────────────────────────────────────────────────────────────────────────────────────

/// `writ config get [key]` — print one config value, or the whole effective config when `key` is
/// omitted. Keys are the flat runtime field names (e.g. `port`, `html_floor_ms`, `use_keyring`,
/// `telemetry_opt_in`, `cloud_expose_workflows`, `js_floor_ms`).
pub fn config_get(paths: &Paths, key: Option<&str>) -> LocalResult<()> {
    let cfg = config::load_config(paths);
    match key {
        None => {
            for (k, v) in config_pairs(&cfg) {
                println!("{k} = {v}");
            }
        }
        Some(k) => {
            let val = config_pairs(&cfg)
                .into_iter()
                .find(|(name, _)| *name == k)
                .map(|(_, v)| v)
                .ok_or_else(|| LocalError::BadRequest(format!("unknown config key '{k}' (try `writ config get`)")))?;
            println!("{val}");
        }
    }
    Ok(())
}

/// `writ config set <key> <value>` — update one config field and persist `config.toml` (`0600`).
///
/// Validates the value against the field's type (u16/u64/bool). A running daemon reads config only at
/// boot, so the change applies on the next `writ start` — we print that reminder.
pub fn config_set(paths: &Paths, key: &str, value: &str) -> LocalResult<()> {
    paths.ensure_dirs()?;
    let mut cfg = config::load_config(paths);
    apply_config_set(&mut cfg, key, value)?;
    config::write_config(paths, &cfg)?;
    println!("Set {key} = {value}");
    if runtime_file::read(paths).ok().flatten().is_some() {
        println!("Note: the running daemon loads config at boot — run `writ start` again to apply.");
    }
    Ok(())
}

/// The settable flat config fields as `(name, string-value)` pairs (single source for get + the
/// `set` key whitelist). Never includes any secret (config carries none).
fn config_pairs(cfg: &LocalConfig) -> Vec<(&'static str, String)> {
    vec![
        ("port", cfg.port.to_string()),
        ("html_floor_ms", cfg.html_floor_ms.to_string()),
        ("js_floor_ms", cfg.js_floor_ms.to_string()),
        ("telemetry_opt_in", cfg.telemetry_opt_in.to_string()),
        ("use_keyring", cfg.use_keyring.to_string()),
        ("cloud_expose_workflows", cfg.cloud_expose_workflows.to_string()),
        ("cloud_agent_disabled", cfg.cloud_agent_disabled.to_string()),
        ("supply_pool_opt_in", cfg.supply_pool_opt_in.to_string()),
    ]
}

/// Parse + apply a single `key=value` mutation onto `cfg`, type-checking the value. Returns
/// `BadRequest` for an unknown key or an unparseable value.
fn apply_config_set(cfg: &mut LocalConfig, key: &str, value: &str) -> LocalResult<()> {
    match key {
        "port" => cfg.port = parse_u16(key, value)?,
        "html_floor_ms" => cfg.html_floor_ms = parse_u64(key, value)?,
        "js_floor_ms" => cfg.js_floor_ms = parse_u64(key, value)?,
        "telemetry_opt_in" => cfg.telemetry_opt_in = parse_bool(key, value)?,
        "use_keyring" => cfg.use_keyring = parse_bool(key, value)?,
        "cloud_expose_workflows" => cfg.cloud_expose_workflows = parse_bool(key, value)?,
        "cloud_agent_disabled" => cfg.cloud_agent_disabled = parse_bool(key, value)?,
        "supply_pool_opt_in" => cfg.supply_pool_opt_in = parse_bool(key, value)?,
        other => {
            return Err(LocalError::BadRequest(format!(
                "unknown config key '{other}' (settable: port, html_floor_ms, js_floor_ms, telemetry_opt_in, use_keyring, cloud_expose_workflows, cloud_agent_disabled, supply_pool_opt_in)"
            )))
        }
    }
    Ok(())
}

fn parse_u16(key: &str, v: &str) -> LocalResult<u16> {
    v.trim()
        .parse::<u16>()
        .map_err(|_| LocalError::BadRequest(format!("'{key}' expects a number 0-65535, got '{v}'")))
}

fn parse_u64(key: &str, v: &str) -> LocalResult<u64> {
    v.trim()
        .parse::<u64>()
        .map_err(|_| LocalError::BadRequest(format!("'{key}' expects a non-negative number, got '{v}'")))
}

fn parse_bool(key: &str, v: &str) -> LocalResult<bool> {
    match v.trim().to_ascii_lowercase().as_str() {
        "1" | "true" | "yes" | "on" => Ok(true),
        "0" | "false" | "no" | "off" => Ok(false),
        _ => Err(LocalError::BadRequest(format!("'{key}' expects a boolean (true/false), got '{v}'"))),
    }
}

// ────────────────────────────────────────────────────────────────────────────────────────────────
// cloud login|logout|status
// ────────────────────────────────────────────────────────────────────────────────────────────────

/// `writ cloud status` — am I linked, and to whom? Reads the daemon's `/v1/cloud/status` reflection.
pub fn cloud_status(paths: &Paths) -> LocalResult<()> {
    let client = connect_daemon(paths)?;
    let body = client.get("/v1/cloud/status")?;
    let linked = body.get("linked").and_then(Value::as_bool).unwrap_or(false);
    if !linked {
        println!("Not linked to a Writ Cloud account.");
        if let Some(url) = body.get("base_url").and_then(Value::as_str) {
            println!("  cloud endpoint: {url}");
        }
        println!("Run `writ cloud login` to link this desktop.");
        return Ok(());
    }
    println!("Linked to Writ Cloud.");
    if let Some(acct) = body.get("account") {
        if let Some(id) = acct.get("account_id").and_then(Value::as_str) {
            println!("  account: {id}");
        }
        if let Some(email) = acct.get("email").and_then(Value::as_str) {
            if !email.is_empty() {
                println!("  email:   {email}");
            }
        }
    }
    if let Some(url) = body.get("base_url").and_then(Value::as_str) {
        println!("  endpoint: {url}");
    }
    Ok(())
}

/// `writ telemetry status` — is the anonymous usage summary on, and what has it sent?
///
/// Reads the daemon's `/v1/settings/telemetry`, so it reports the value the reporter ACTUALLY uses
/// (`[app].telemetry_opt_in`) rather than a preference file the daemon never consults.
pub fn telemetry_status(paths: &Paths) -> LocalResult<()> {
    let body = connect_daemon(paths)?.get("/v1/settings/telemetry")?;
    let enabled = body.get("enabled").and_then(Value::as_bool).unwrap_or(false);
    println!("Anonymous usage telemetry: {}", if enabled { "ON" } else { "off" });
    if !body.get("supported").and_then(Value::as_bool).unwrap_or(false) {
        println!("  (this build has no cloud ingest — nothing is ever sent)");
    }
    match body.get("last_reported_day").and_then(Value::as_str) {
        Some(day) => println!("  last day sent: {day}"),
        None => println!("  last day sent: never"),
    }
    if let Some(id) = body.get("install_id").and_then(Value::as_str) {
        println!("  random report id: {id}");
    }
    if !enabled {
        println!("Run `writ telemetry on` to enable it, `writ telemetry preview` to see what it would send.");
    }
    Ok(())
}

/// `writ telemetry on|off` — flip the opt-in through the daemon (the only writer of that key).
pub fn telemetry_set(paths: &Paths, enabled: bool) -> LocalResult<()> {
    let body = connect_daemon(paths)?
        .put_json("/v1/settings/telemetry", &serde_json::json!({ "enabled": enabled }))?;
    let now = body.get("enabled").and_then(Value::as_bool).unwrap_or(false);
    println!("Anonymous usage telemetry: {}", if now { "ON" } else { "off" });
    if !now {
        println!("  the random report id was dropped — enabling again starts a fresh, unlinkable one");
    }
    Ok(())
}

/// `writ telemetry preview` / `writ telemetry send` — build yesterday's report, printing the EXACT
/// payload either way.
///
/// `preview` sends nothing: it is the "read what leaves before you trust the description of it"
/// affordance, and the only way to answer "what exactly does this collect?" from the outside.
pub fn telemetry_report(paths: &Paths, send: bool, day: Option<&str>) -> LocalResult<()> {
    let mut body = serde_json::json!({ "dry_run": !send });
    if let Some(d) = day {
        body["day"] = Value::String(d.to_string());
    }
    let out = connect_daemon(paths)?.post_json("/v1/settings/telemetry/report", &body)?;

    // The payload first — it is the point of the command.
    if let Some(report) = out.get("report") {
        println!("{}", serde_json::to_string_pretty(report).unwrap_or_default());
    }
    let sent = out.get("sent").and_then(Value::as_bool).unwrap_or(false);
    let reason = out.get("skipped_reason").and_then(Value::as_str);
    match (sent, reason) {
        (true, _) => println!("\nSent to Writ Cloud."),
        (false, Some("dry_run")) => println!("\nNothing was sent (preview). Use `writ telemetry send` to send it."),
        (false, Some("not_linked")) => println!("\nNothing was sent: this desktop is not linked to a Writ Cloud account."),
        (false, Some("rejected")) => println!("\nNothing was sent: the cloud rejected the report (it will be retried)."),
        (false, other) => println!("\nNothing was sent{}.", other.map(|r| format!(" ({r})")).unwrap_or_default()),
    }
    Ok(())
}

/// `writ cloud login` — run the OAuth device-authorization flow against the daemon.
///
/// Drives the daemon's `/v1/cloud/link/start` (which mints a device/user code and stashes the
/// in-flight handshake server-side, in the daemon), prints the user-code + verification URL, opens the
/// browser, then polls `/v1/cloud/link/poll` on the server-suggested interval until the user approves
/// (success), declines, or the code expires. The `wto_`/`wtr_` tokens land in the daemon's OS keyring
/// — never on this CLI's stdout/disk.
pub fn cloud_login(paths: &Paths) -> LocalResult<()> {
    let client = connect_daemon(paths)?;

    let start = client.post_empty("/v1/cloud/link/start")?;
    let user_code = start.get("user_code").and_then(Value::as_str).unwrap_or("");
    let verification_uri = start.get("verification_uri").and_then(Value::as_str).unwrap_or("");
    let verification_uri_complete = start.get("verification_uri_complete").and_then(Value::as_str);
    let interval_secs = start.get("interval").and_then(Value::as_u64).unwrap_or(5).max(1);

    let open_url = verification_uri_complete.unwrap_or(verification_uri);
    println!("To link this desktop to Writ Cloud:");
    println!("  1. Open: {verification_uri}");
    println!("  2. Enter code: {user_code}");
    println!();
    // Best-effort browser open (non-fatal — the user can navigate manually).
    if !open_url.is_empty() {
        if let Err(e) = opener::open(open_url) {
            tracing::debug!(error = %e, "could not auto-open the verification URL");
        }
    }
    print!("Waiting for approval");
    let _ = std::io::stdout().flush();

    let poll_interval = std::time::Duration::from_secs(interval_secs);
    loop {
        std::thread::sleep(poll_interval);
        let body = client.post_empty("/v1/cloud/link/poll")?;
        match body.get("status").and_then(Value::as_str).unwrap_or("") {
            "pending" => {
                print!(".");
                let _ = std::io::stdout().flush();
            }
            "linked" => {
                println!("\nLinked successfully.");
                if let Some(id) = body.get("account").and_then(|a| a.get("account_id")).and_then(Value::as_str) {
                    println!("  account: {id}");
                }
                return Ok(());
            }
            "denied" => {
                println!();
                return Err(LocalError::BadRequest("the link request was denied".into()));
            }
            "expired" => {
                println!();
                return Err(LocalError::BadRequest(
                    "the device code expired before approval — run `writ cloud login` again".into(),
                ));
            }
            other => {
                println!();
                return Err(LocalError::Internal(format!("unexpected link status '{other}'")));
            }
        }
    }
}

/// `writ cloud logout` — unlink this desktop (clear the keyring token + persisted link metadata)
/// via the daemon's `/v1/cloud/unlink`. Idempotent.
///
/// A 200 always means the link metadata is gone; `ok:false` means the OS keyring refused to drop a
/// credential that is STILL VALID against the cloud. That is a partial success, so it exits
/// non-zero — a provisioning script that decommissions a machine must not read "logged out" as
/// "no credential left behind".
pub fn cloud_logout(paths: &Paths) -> LocalResult<()> {
    let client = connect_daemon(paths)?;
    let body = client.post_empty("/v1/cloud/unlink")?;
    if body["ok"] == Value::Bool(false) {
        println!("Unlinked from Writ Cloud locally (link metadata cleared).");
        if let Some(why) = body["keyring_error"].as_str() {
            eprintln!("writ: the OS keyring refused to remove a stored credential: {why}");
        }
        eprintln!(
            "writ: that credential is still valid. Unlock your keychain and re-run \
             `writ cloud logout`, or delete the 'writ-cloud' item by hand."
        );
        return Err(LocalError::Internal(
            "unlink incomplete: a cloud credential survives in the OS keyring".into(),
        ));
    }
    println!("Unlinked from Writ Cloud (local token + metadata cleared).");
    Ok(())
}

/// Connect to the running daemon, mapping the "no daemon" case to a friendly, actionable message.
fn connect_daemon(paths: &Paths) -> LocalResult<DaemonClient> {
    DaemonClient::connect(paths).map_err(|e| match e {
        LocalError::NotFound(_) => LocalError::BadRequest(
            "no running daemon — start it first with `writ start`, then retry".into(),
        ),
        other => other,
    })
}

// ────────────────────────────────────────────────────────────────────────────────────────────────
// shared
// ────────────────────────────────────────────────────────────────────────────────────────────────

/// Is `pid` a currently-running process? Uses `sysinfo` (already a crate dep — no `libc`). A pid of 0
/// is never alive. Mirrors the liveness check in `app::lifecycle`.
fn pid_alive(pid: u32) -> bool {
    if pid == 0 {
        return false;
    }
    let mut sys = sysinfo::System::new();
    sys.refresh_process(sysinfo::Pid::from_u32(pid))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fresh_home() -> (tempfile::TempDir, Paths) {
        let dir = tempfile::tempdir().unwrap();
        let paths = Paths::at(dir.path().join(".writ"));
        (dir, paths)
    }

    #[test]
    fn init_scaffolds_home_config_and_token() {
        let (_dir, paths) = fresh_home();
        init(&paths).unwrap();
        assert!(paths.root.is_dir());
        assert!(paths.config_toml().is_file(), "config.toml materialized");
        assert!(paths.local_token().is_file(), "wlt_ token minted");
        let tok = std::fs::read_to_string(paths.local_token()).unwrap();
        assert!(tok.trim().starts_with("wlt_"));
        // Idempotent re-run keeps the same token.
        let again = config::load_or_create_token(&paths).unwrap();
        assert_eq!(again, tok.trim());
    }

    #[test]
    fn token_rotate_changes_the_value() {
        let (_dir, paths) = fresh_home();
        paths.ensure_dirs().unwrap();
        let first = config::load_or_create_token(&paths).unwrap();
        let rotated = rotate_local_token(&paths).unwrap();
        assert!(rotated.starts_with("wlt_"));
        assert_ne!(first, rotated, "rotate must mint a fresh token");
        // The persisted file now holds the rotated value.
        let on_disk = std::fs::read_to_string(paths.local_token()).unwrap();
        assert_eq!(on_disk.trim(), rotated);
    }

    #[test]
    fn config_set_get_roundtrips_each_field() {
        let (_dir, paths) = fresh_home();
        paths.ensure_dirs().unwrap();
        // Avoid env overrides perturbing the assertions.
        for k in ["WRIT_PORT", "WRIT_HTML_FLOOR_MS", "WRIT_JS_FLOOR_MS", "WRIT_TELEMETRY", "WRIT_USE_KEYRING", "WRIT_CLOUD_EXPOSE", "WRIT_CLOUD_AGENT_DISABLED", "WRIT_SUPPLY_POOL"] {
            std::env::remove_var(k);
        }

        config_set(&paths, "port", "9099").unwrap();
        config_set(&paths, "telemetry_opt_in", "true").unwrap();
        config_set(&paths, "use_keyring", "false").unwrap();
        config_set(&paths, "html_floor_ms", "120000").unwrap();
        // The cloud-agent off-switch + supply-pool opt-in are CLI-settable and persist across a reload.
        config_set(&paths, "cloud_agent_disabled", "true").unwrap();
        config_set(&paths, "supply_pool_opt_in", "on").unwrap();

        let cfg = config::load_config(&paths);
        assert_eq!(cfg.port, 9099);
        assert!(cfg.telemetry_opt_in);
        assert!(!cfg.use_keyring);
        assert_eq!(cfg.html_floor_ms, 120_000);
        assert!(cfg.cloud_agent_disabled, "cloud_agent_disabled persisted");
        assert!(cfg.supply_pool_opt_in, "supply_pool_opt_in persisted");
    }

    #[test]
    fn config_set_rejects_unknown_key_and_bad_value() {
        let mut cfg = LocalConfig::default();
        assert!(apply_config_set(&mut cfg, "nope", "1").is_err(), "unknown key rejected");
        assert!(apply_config_set(&mut cfg, "port", "not-a-number").is_err(), "bad u16 rejected");
        assert!(apply_config_set(&mut cfg, "use_keyring", "maybe").is_err(), "bad bool rejected");
        // A valid set mutates.
        apply_config_set(&mut cfg, "use_keyring", "off").unwrap();
        assert!(!cfg.use_keyring);
    }

    #[test]
    fn bool_parser_accepts_common_spellings() {
        for t in ["1", "true", "YES", "On"] {
            assert!(parse_bool("k", t).unwrap());
        }
        for f in ["0", "false", "NO", "Off"] {
            assert!(!parse_bool("k", f).unwrap());
        }
        assert!(parse_bool("k", "nope").is_err());
    }

    #[test]
    fn pid_zero_is_never_alive() {
        assert!(!pid_alive(0));
        // Our own pid is alive.
        assert!(pid_alive(std::process::id()));
    }
}
