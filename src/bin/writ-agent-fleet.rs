//! `writ-agent-fleet` — the Writ self-host OSS FLEET worker.
//!
//! A cloud-free standalone agent: it opens the SAME SQLCipher-encrypted local store + vault +
//! browser-backed engine the desktop daemon uses, but instead of serving a loopback HTTP API +
//! scheduler + monitor, it runs ONE thing — the [`crate::bridge::fleet_bridge::FleetBridge`] loop,
//! an outbound link to a self-host COORDINATOR over its persistent `/ws/ai-gateway` WS. The
//! coordinator can DEPLOY workflows / secrets / personas to this worker (sealed under the per-agent
//! channel key), and DISPATCH those workflows to run fully on this machine.
//!
//! There is NO daemon HTTP server, scheduler, or monitor here — a fleet worker is a pure execution
//! node driven by the coordinator. Only builds with BOTH the `fleet` and `local` cargo features
//! (the OSS self-host export: `--no-default-features --features local,fleet,openai`).
//!
//! ## Configuration (all via environment — the cloud-gated CLI/config-writer is absent here)
//!   * `WRIT_SERVICE_TOKEN` (REQUIRED) — the long-lived fleet token minted by the coordinator
//!     (`POST /api/fleet/tokens`). Sent as the connect Bearer.
//!   * `WRIT_COORDINATOR_URL` (or `SAAS_URL`, REQUIRED) — the coordinator HTTP(S) base url (NOT the
//!     `/ws/ai-gateway` WS url; the worker POSTs `<base>/api/recorder/connect` and dials the WS the
//!     coordinator hands back).
//!   * `WRIT_HOME` (or `WRIT_VAULT_ROOT`) — the data home (default `~/.writ`); holds the encrypted
//!     `writ.db` + the `0600 vault.key` file root when the OS keyring is unavailable/disabled. The
//!     worker takes a SINGLETON LOCK on this directory and refuses to start if another Writ process
//!     already owns it (two pools over one SQLCipher file, either of which can quarantine the other's
//!     database — give every worker its own home).
//!   * `WRIT_RETENTION_DAYS` — data-retention window in days (default 90; `0` = keep everything).
//!     A fleet worker runs neither the desktop scheduler nor the local HTTP API, so it drives its own
//!     periodic purge + `wal_checkpoint(TRUNCATE)` + `logs/` reclaim from this value.
//!   * `WRIT_FLEET_DRAIN_TIMEOUT_S` — bounded graceful-drain window on SIGTERM/Ctrl-C (default 30,
//!     max 600). The worker stops taking the process down until in-flight runs finish (so their
//!     `task_result` reaches the coordinator instead of leaving it hanging), then shuts the browser
//!     down explicitly. Must be LESS than the supervisor's stop grace period (`docker stop -t`,
//!     compose `stop_grace_period`, systemd `TimeoutStopSec`) or the drain is SIGKILLed mid-way.
//!   * `WRIT_USE_KEYRING` — `1`/`true` to root the vault in the OS keyring (default OFF: headless
//!     file/env root, so a container/service never blocks on a Keychain prompt).
//!   * `WRIT_FLEET_ALLOW_INSECURE` — `1`/`true` to allow a plaintext (`http://`/`ws://`) non-loopback
//!     coordinator (a trusted private network only; the worker otherwise refuses to send its token
//!     in cleartext).
//!   * `WRIT_AI_KEYS_CONFIGURED` — `1`/`true` to advertise BYO-AI capability to the coordinator.
//!   * `WRIT_FLEET_STATUS_PORT` — set to a port number to serve a loopback-only status endpoint,
//!     `GET http://127.0.0.1:<port>/healthz` (for Docker HEALTHCHECK / systemd watchdogs). Replies
//!     `200` with `{"status":"ok","connected":true,"uptime_s":…,"last_task_at":…,"version":…}` only
//!     when EVERY check passes, `503` otherwise, with `status` naming the first failing one:
//!       - `"draining"` — a shutdown signal arrived and in-flight runs are finishing,
//!       - `"auth_rejected"` (plus `auth_error`) — the coordinator refused this worker's fleet token,
//!         which needs an operator to re-mint it,
//!       - `"disconnected"` — no live coordinator WS session,
//!       - `"db_unavailable"` — the encrypted store failed a `SELECT 1` probe (a worker whose DB is
//!         unusable fails every task with an opaque `db_error` while otherwise looking fine),
//!       - `"task_failures"` — consecutive INFRASTRUCTURE-category run failures crossed the
//!         unhealthy threshold (`infra_failure_streak` in the body; author-side workflow faults are
//!         excluded, so one broken workflow never trips it).
//!     So `curl -f` health checks fail while the worker is wedged/disconnected/broken. Binds STRICTLY
//!     `127.0.0.1` (never exposed off-host), serves no other route, and is OFF when unset.
//!
//! ## Exit codes (a supervisor is expected to restart this process)
//!   * `0` — clean shutdown on SIGTERM/Ctrl-C.
//!   * `1` — startup/config failure (bad token/url/home; restarting will not help until fixed).
//!   * `3` — the bridge loop stopped on its own (e.g. coordinator `disconnect`) → RESTART.
//!   * `4` — the bridge loop panicked → RESTART.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use writ_agent::bridge::fleet_bridge::FleetBridge;
use writ_agent::local;

/// `--help` / `--version`, handled BEFORE any setup.
///
/// Two reasons this is not optional. First, a shipped binary that ignores `--help` and instead
/// fails with "WRIT_SERVICE_TOKEN is not set" is a bad first impression for the one command every
/// operator tries first. Second, it is the CI smoke test: `docker run … writ-agent-fleet --help`
/// must exit 0, which proves the binary actually *loads and runs* in the runtime image — the check
/// that catches a builder/runtime glibc mismatch, since a successful `docker build` alone does not.
///
/// Returns `Some(exit_code)` when it handled the argument and the process should stop.
fn handle_cli_args() -> Option<std::process::ExitCode> {
    let mut args = std::env::args().skip(1);
    match args.next().as_deref() {
        Some("--help" | "-h" | "help") => {
            println!(
                "writ-agent-fleet {}\n\
                 \n\
                 The Writ self-host fleet worker. Connects OUT to your coordinator over HTTPS/WSS\n\
                 and runs the workflows it dispatches. No inbound ports are required.\n\
                 \n\
                 USAGE:\n\
                 \x20   writ-agent-fleet            Run the worker (configured entirely by environment)\n\
                 \x20   writ-agent-fleet --help     Show this message\n\
                 \x20   writ-agent-fleet --version  Print the version\n\
                 \n\
                 REQUIRED ENVIRONMENT:\n\
                 \x20   WRIT_SERVICE_TOKEN      Fleet token, minted in the coordinator UI\n\
                 \x20                           (Fleet -> \"Connect a new agent\")\n\
                 \x20   WRIT_COORDINATOR_URL    Coordinator HTTP(S) base URL\n\
                 \n\
                 COMMON OPTIONAL ENVIRONMENT:\n\
                 \x20   WRIT_HOME               Data directory (default ~/.writ): encrypted writ.db + vault key\n\
                 \x20                           One worker per directory (a singleton lock enforces it)\n\
                 \x20   WRIT_FLEET_STATUS_PORT  Serve a loopback-only GET /healthz on this port\n\
                 \x20   WRIT_RETENTION_DAYS     Data-retention window in days (default 90; 0 = keep everything)\n\
                 \x20   WRIT_FLEET_DRAIN_TIMEOUT_S  Graceful-drain window on SIGTERM (default {}, max {})\n\
                 \x20   WRIT_USE_KEYRING        Root the vault key in the OS keyring instead of a 0600 file\n\
                 \x20   WRIT_FLEET_ALLOW_INSECURE  Permit a plaintext http:// coordinator (trusted networks only)\n\
                 \n\
                 Full reference: docs/CONFIGURATION.md\n\
                 Exit codes: 0 clean shutdown - 1 startup/config error - {} bridge stopped - {} bridge panicked",
                env!("CARGO_PKG_VERSION"),
                DEFAULT_DRAIN_TIMEOUT.as_secs(),
                MAX_DRAIN_TIMEOUT.as_secs(),
                EXIT_BRIDGE_STOPPED,
                EXIT_BRIDGE_PANIC,
            );
            Some(std::process::ExitCode::SUCCESS)
        }
        Some("--version" | "-V" | "version") => {
            println!("writ-agent-fleet {}", env!("CARGO_PKG_VERSION"));
            Some(std::process::ExitCode::SUCCESS)
        }
        _ => None,
    }
}

/// SYNCHRONOUS prologue, then the runtime — deliberately not `#[tokio::main]`.
///
/// Everything that mutates the process ENVIRONMENT runs here, before the runtime (and therefore
/// before any worker thread) exists. `std::env::set_var` writes the libc `environ` block without
/// synchronization, which is undefined behaviour once another thread can be inside `getenv` — Rust
/// 1.80+ marks it `unsafe` for exactly that reason. Two writers qualify:
///   * `dotenvy::dotenv()` — sets every var from `.env`.
///   * `init_driver_env()` — the Playwright driver override. It was previously reached only lazily,
///     from `BrowserManager::initialize().await`, i.e. from inside the multi-thread runtime and
///     potentially from several tasks at once.
///
/// `writ-agentd` was hoisted for this reason already; this binary — the one OSS users actually run —
/// had been left on `#[tokio::main]`. Resolving the driver up front also means the log line naming
/// the chosen driver appears at startup, rather than at the first browser launch.
fn main() -> std::process::ExitCode {
    // Before dotenv, tracing, or the panic hook — `--help` must work in a bare container with no
    // configuration and no writable data directory.
    if let Some(code) = handle_cli_args() {
        return code;
    }

    dotenvy::dotenv().ok();
    // Tracing first so `init_driver_env`'s decision is actually visible; it is a plain synchronous
    // subscriber install with no background thread, so it is safe outside a runtime.
    init_tracing();
    writ_agent::browser::manager::init_driver_env();

    match tokio::runtime::Builder::new_multi_thread().enable_all().build() {
        Ok(rt) => rt.block_on(async_main()),
        Err(e) => {
            tracing::error!(error = %e, "could not start the async runtime");
            eprintln!("writ-agent-fleet: could not start the async runtime: {e}");
            std::process::ExitCode::FAILURE
        }
    }
}

async fn async_main() -> std::process::ExitCode {
    local::crash::install_panic_hook("writ-agent-fleet");

    match run().await {
        Ok(code) => code,
        Err(e) => {
            tracing::error!(error = %e, "writ-agent-fleet exited with error");
            eprintln!("writ-agent-fleet: {e}");
            std::process::ExitCode::FAILURE
        }
    }
}

/// Exit code when the bridge loop returned on its own (e.g. a coordinator `disconnect` frame).
///
/// A DISTINCT non-zero code matters: `docker run --restart=always` and systemd `Restart=always`
/// only fire when the process EXITS. The old `main` awaited nothing but the OS signal, so a bridge
/// that stopped left the process alive and idle forever — a zombie worker that no supervisor
/// restarted, with `/healthz` its only (silent) witness.
const EXIT_BRIDGE_STOPPED: u8 = 3;
/// Exit code when the bridge loop task PANICKED.
const EXIT_BRIDGE_PANIC: u8 = 4;

/// Default bounded window the worker spends finishing in-flight runs after a shutdown signal.
///
/// 30s is chosen to sit UNDER the common supervisor defaults that would otherwise SIGKILL us mid-drain
/// (`docker stop` grace is 10s, so compose deployments must raise `stop_grace_period`; systemd's
/// `TimeoutStopSec` is 90s; Kubernetes' `terminationGracePeriodSeconds` is 30s) while still covering a
/// typical workflow run. Raise it with `WRIT_FLEET_DRAIN_TIMEOUT_S` *and* the supervisor's grace.
const DEFAULT_DRAIN_TIMEOUT: Duration = Duration::from_secs(30);

/// Hard ceiling on `WRIT_FLEET_DRAIN_TIMEOUT_S`. A drain longer than this is indistinguishable from a
/// hung shutdown to every supervisor that will SIGKILL us long before it elapses.
const MAX_DRAIN_TIMEOUT: Duration = Duration::from_secs(600);

/// How often the drain re-reads the engine's in-flight count.
const DRAIN_POLL: Duration = Duration::from_millis(250);

/// Grace after the last run finishes, before the bridge loop is stopped.
///
/// `active_runs()` drops to zero the instant a run's future completes, which is a beat BEFORE its
/// handler has pushed the `task_result` frame through the outgoing channel and onto the socket.
/// Stopping the read loop in that window retires the writer task and the result would evaporate —
/// precisely the coordinator-hangs bug the drain exists to fix.
const RESULT_FLUSH_GRACE: Duration = Duration::from_secs(2);

/// How long to wait for the bridge loop to return on its own after [`FleetBridge::shutdown`] before
/// aborting the task. The loop checks its `running` flag once per frame/select, so this is generous.
const LOOP_STOP_GRACE: Duration = Duration::from_secs(5);

/// Ceiling on the explicit browser teardown (CDP close + driver stop).
const BROWSER_SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(20);

/// Releases the `WRIT_HOME` singleton lock however `run` returns — including an early `?` on a later
/// startup step, and a panic unwinding out of `run`.
///
/// Without this, any startup failure AFTER the lock was taken would leave a pidfile behind. That is
/// self-healing (the next start sees a dead owner and reclaims it) but noisy, and it makes a genuine
/// double-start indistinguishable from leftover state in the logs.
struct HomeLock {
    paths: local::config::Paths,
}

impl Drop for HomeLock {
    fn drop(&mut self) {
        local::app::lifecycle::release_singleton(&self.paths);
        tracing::debug!("singleton lock released");
    }
}

/// The configured graceful-drain window from `WRIT_FLEET_DRAIN_TIMEOUT_S` (seconds).
///
/// Unset/empty ⇒ [`DEFAULT_DRAIN_TIMEOUT`]. `0` is honored as "do not drain" (an operator who wants
/// the old abrupt behavior can ask for it). An unparseable value warns and falls back to the default
/// rather than failing startup — a bad drain knob must not stop a worker from running.
fn drain_timeout() -> Duration {
    let Some(raw) = std::env::var("WRIT_FLEET_DRAIN_TIMEOUT_S").ok() else {
        return DEFAULT_DRAIN_TIMEOUT;
    };
    let raw = raw.trim();
    if raw.is_empty() {
        return DEFAULT_DRAIN_TIMEOUT;
    }
    match raw.parse::<u64>() {
        Ok(secs) => {
            let requested = Duration::from_secs(secs);
            if requested > MAX_DRAIN_TIMEOUT {
                tracing::warn!(
                    requested_s = secs,
                    max_s = MAX_DRAIN_TIMEOUT.as_secs(),
                    "WRIT_FLEET_DRAIN_TIMEOUT_S exceeds the ceiling — clamping"
                );
            }
            requested.min(MAX_DRAIN_TIMEOUT)
        }
        Err(_) => {
            tracing::warn!(
                value = %raw,
                default_s = DEFAULT_DRAIN_TIMEOUT.as_secs(),
                "WRIT_FLEET_DRAIN_TIMEOUT_S is not a whole number of seconds — using the default"
            );
            DEFAULT_DRAIN_TIMEOUT
        }
    }
}

async fn run() -> anyhow::Result<std::process::ExitCode> {
    // Process start — the `/healthz` uptime anchor.
    let started = std::time::Instant::now();

    // --- Required config ---------------------------------------------------
    let token = std::env::var("WRIT_SERVICE_TOKEN")
        .ok()
        .filter(|t| !t.trim().is_empty())
        .ok_or_else(|| {
            anyhow::anyhow!(
                "WRIT_SERVICE_TOKEN is not set — mint a fleet token in the coordinator \
                 (POST /api/fleet/tokens) and export it before starting the worker"
            )
        })?;
    let base_url = std::env::var("WRIT_COORDINATOR_URL")
        .ok()
        .or_else(|| std::env::var("SAAS_URL").ok())
        .map(|u| u.trim().trim_end_matches('/').to_string())
        .filter(|u| !u.is_empty())
        .ok_or_else(|| {
            anyhow::anyhow!(
                "WRIT_COORDINATOR_URL (or SAAS_URL) is not set — point it at the coordinator \
                 HTTP base url (e.g. https://coordinator.example.com)"
            )
        })?;
    let allow_insecure = env_flag("WRIT_FLEET_ALLOW_INSECURE");
    let ai_keys_configured = env_flag("WRIT_AI_KEYS_CONFIGURED");
    let use_keyring = env_flag("WRIT_USE_KEYRING");

    // --- Home / vault / db -------------------------------------------------
    // `WRIT_VAULT_ROOT` is an explicit override for the data home (aliasing `WRIT_HOME`) so a
    // headless deployment can point the vault + db at a mounted volume; otherwise `Paths::resolve`
    // reads `WRIT_HOME` / `~/.writ`.
    if let Some(root) = std::env::var_os("WRIT_VAULT_ROOT") {
        if std::env::var_os("WRIT_HOME").is_none() {
            std::env::set_var("WRIT_HOME", root);
        }
    }
    let paths = local::config::Paths::resolve()?;
    paths.ensure_dirs()?;
    tracing::info!(root = %paths.root.display(), "writ fleet home ready");

    // Singleton guard on the data home — the SAME pidfile lock the desktop daemon takes.
    //
    // Two processes over one `WRIT_HOME` is not merely "a bit slower": each opens its OWN connection
    // pool (4 connections, 5s busy handler) against the same SQLCipher file, so writes serialize into
    // `database is locked` failures under any load — and each independently runs the MANAGED boot
    // policy in `db::open_managed`, which QUARANTINES a database it cannot read. One worker mid-write
    // can therefore look corrupt to the other, which renames the live `writ.db` aside and starts
    // fresh, silently destroying the first worker's deployed workflows and sealed secrets. Refuse.
    local::app::lifecycle::acquire_singleton(&paths).map_err(|e| {
        anyhow::anyhow!(
            "{e}\n\n\
             The data home {} is already owned by another live Writ process (a second fleet worker, \
             or the desktop daemon). Two processes must never share one WRIT_HOME.\n\
             Fix: give every worker its OWN directory — e.g. `-e WRIT_HOME=/data` with a SEPARATE \
             docker volume per container, or `WRIT_HOME=~/.writ-worker2` for a second service unit.\n\
             If you are certain no other worker is running, the lockfile is stale and can be removed: \
             {}",
            paths.root.display(),
            paths.lock().display(),
        )
    })?;
    // Held for the rest of `run()`; released on EVERY exit path (see `HomeLock`).
    let _home_lock = HomeLock { paths: paths.clone() };
    tracing::info!(lock = %paths.lock().display(), "singleton lock acquired for this data home");
    // Startup acquisition alone cannot notice the lockfile being deleted underneath us later, and a
    // vanished lock silently lets a SECOND worker start over this same home. Keep asserting it.
    local::app::lifecycle::spawn_lock_watchdog(paths.clone());

    // Vault root: OS keyring when explicitly enabled, else the `0600 vault.key` file root. Log which
    // custody path is in use so a headless operator can confirm the key is where they expect.
    if use_keyring {
        tracing::info!("vault root: OS keyring (WRIT_USE_KEYRING enabled)");
    } else {
        tracing::info!(
            key_file = %paths.vault_key().display(),
            "vault root: file fallback (OS keyring disabled/unavailable in headless mode) — \
             protect this 0600 vault.key alongside the encrypted writ.db"
        );
    }
    let vault = Arc::new(local::vault::Vault::load_or_create(&paths.root, use_keyring)?);
    let db = local::db::open_managed(&paths.db(), &vault.db_key_hex()).await?;
    tracing::info!(db = %paths.db().display(), "encrypted database open + migrated");

    // --- Engine (headless-forced, browser-backed) --------------------------
    // A fleet worker is always unattended → force the warm browser headless regardless of any
    // per-workflow / config knob. Governor ceilings fold from the local config (a fleet worker keeps
    // the same concurrency + memory-shedding safety as the daemon).
    let config = local::config::load_config(&paths);
    let gov_cfg = local::governor::GovernorConfig::from_local(&config);
    let mut browser_cfg = writ_agent::config::env::AppConfig::from_env();
    browser_cfg.headless = true;
    let engine: Arc<dyn local::engine::LocalEngine> = Arc::new(
        local::engine::RealEngine::with_app_config_governed(
            db.clone(),
            vault.clone(),
            browser_cfg,
            gov_cfg,
        ),
    );
    tracing::info!("fleet execution engine ready (headless; browser launches lazily on first run)");

    // --- Periodic data maintenance ----------------------------------------
    // A fleet worker runs NEITHER the scheduler (whose Lane 4 drives the desktop purge) NOR the local
    // HTTP API (whose `POST /v1/data-admin` is the manual lever), so without this loop nothing ever
    // reclaimed anything: every dispatched run appended `runs` rows plus events, artifacts and
    // extracted data forever, the `-wal` file stayed at its high-water mark, and `logs/` grew
    // unrotated. A worker taking a few thousand runs a week eventually filled its volume and then
    // failed every task with an opaque `db_error` while `/healthz` still reported fine.
    let maintenance = local::retention::spawn_maintenance(
        db.clone(),
        paths.clone(),
        local::retention::MaintenanceConfig::new(config.retention_days),
    );

    // --- Bridge loop -------------------------------------------------------
    let bridge = Arc::new(FleetBridge::new(
        engine.clone(),
        db.clone(),
        vault,
        base_url,
        token,
        ai_keys_configured,
        allow_insecure,
    ));

    // Set for the whole graceful-shutdown window so `/healthz` answers 503 `"draining"` the moment a
    // signal lands — an orchestrator must stop treating this worker as ready before it goes away.
    let draining = Arc::new(AtomicBool::new(false));

    // --- Optional loopback status listener (/healthz) ----------------------
    // Enabled only when WRIT_FLEET_STATUS_PORT is a valid port; a bind failure logs a warning and
    // the worker continues (the listener is observability, never load-bearing).
    if let Some(port) = status_port() {
        spawn_status_listener(
            port,
            StatusState {
                bridge: bridge.clone(),
                db: db.clone(),
                started,
                draining: draining.clone(),
            },
        );
    }

    let run_handle = bridge.clone();
    let mut loop_task = tokio::spawn(async move { run_handle.run().await });

    // Wait for whichever comes first: an OS shutdown signal, or the bridge loop ENDING.
    //
    // The bridge loop is the entire purpose of this process, so if it returns (a coordinator
    // `disconnect` frame flips `running` to false unconditionally) or panics, the process MUST exit
    // with a non-zero code so the supervisor restarts it. Awaiting only the signal — the previous
    // behavior — turned every coordinator-initiated disconnect into a permanent zombie: the bridge
    // was dead, `main` blocked forever, and no restart policy ever fired.
    // Which arm won. The bridge-loop arm resolves to its exit code; the signal arm defers ALL work to
    // `graceful_shutdown` *after* the select, so `loop_task` can be moved into it by value (a
    // `&mut loop_task` borrow is still live inside the select).
    enum Woke {
        BridgeEnded(std::process::ExitCode),
        Signal,
    }

    let woke = tokio::select! {
        joined = &mut loop_task => {
            // Whatever happened, the bridge is not connected any more. Clear the flag explicitly so
            // `/healthz` cannot answer 200 for a dead bridge during the short shutdown window (the
            // loop also clears it via its own drop guard).
            bridge.mark_disconnected();
            let code = match joined {
                Ok(()) => {
                    tracing::error!(
                        "fleet bridge loop exited on its own (coordinator disconnect or internal \
                         stop) — exiting {EXIT_BRIDGE_STOPPED} so the supervisor restarts this worker"
                    );
                    eprintln!("writ-agent-fleet: bridge loop stopped — exiting for restart");
                    std::process::ExitCode::from(EXIT_BRIDGE_STOPPED)
                }
                Err(e) if e.is_panic() => {
                    tracing::error!(
                        error = %e,
                        "fleet bridge loop PANICKED — exiting {EXIT_BRIDGE_PANIC} so the supervisor \
                         restarts this worker"
                    );
                    eprintln!("writ-agent-fleet: bridge loop panicked — exiting for restart");
                    std::process::ExitCode::from(EXIT_BRIDGE_PANIC)
                }
                Err(e) => {
                    // Cancelled: nothing in this binary aborts the task except the shutdown path
                    // below, so treat it like an unexpected stop.
                    tracing::error!(error = %e, "fleet bridge loop ended unexpectedly (cancelled)");
                    std::process::ExitCode::from(EXIT_BRIDGE_STOPPED)
                }
            };
            Woke::BridgeEnded(code)
        }
        _ = shutdown_signal() => Woke::Signal,
    };

    let exit = match woke {
        Woke::BridgeEnded(code) => code,
        Woke::Signal => {
            graceful_shutdown(&bridge, &engine, loop_task, &draining, drain_timeout()).await;
            std::process::ExitCode::SUCCESS
        }
    };

    // Stop the maintenance loop before the process exits so an in-flight purge finishes its DELETE
    // rather than being torn out mid-statement.
    maintenance.shutdown().await;

    // Explicit browser teardown on EVERY exit path — including the bridge-ended one, which otherwise
    // left Chromium behind exactly like the abrupt-signal path did (see `shutdown_browser`).
    shutdown_browser(&engine).await;

    // `_home_lock` drops here, releasing the singleton pidfile.
    Ok(exit)
}

/// Graceful drain on SIGTERM/Ctrl-C.
///
/// The old path was `bridge.shutdown(); loop_task.abort();` and nothing else — which abandoned every
/// in-flight run. Two concrete consequences, both routinely hit by a `docker restart` or a systemd
/// deploy landing mid-run:
///   1. the coordinator that dispatched the run never receives a `task_result`, so it waits on its own
///      timeout while the work is simply gone; and
///   2. `BrowserManager::shutdown()` was never called, so teardown fell to `Drop for Playwright` —
///      which drops the driver's stdin and IMMEDIATELY `start_kill()`s it. That SIGKILL races the
///      node driver's own stdin-close cleanup, so Chromium and its renderer/GPU children are orphaned.
///      `tini` reaps them once they exit, but nothing asks them to exit; across repeated deploys they
///      accumulate, each holding hundreds of MB.
///
/// Order matters, and specifically the drain happens while the WS is STILL UP:
///   1. flip `draining` so `/healthz` reports 503 `"draining"` (stop being counted as ready);
///   2. wait up to `budget` for `engine.active_runs()` to reach zero — with the coordinator link
///      alive, because `task_result` frames are written by the bridge's per-connection writer task,
///      which is retired the moment the read loop returns. Stopping the bridge FIRST would send every
///      in-flight result into a dead channel, i.e. reproduce bug (1) rather than fix it. The trade is
///      that the coordinator can still dispatch during the bounded drain; a freshly dispatched task
///      that we abandon is retryable, a lost result is not;
///   3. a short flush grace, because `active_runs()` hits zero a beat before the last frame is on the
///      socket;
///   4. stop the bridge loop (bounded, then abort);
///   5. the caller then shuts the browser down explicitly and releases the home lock.
///
/// Scope: `active_runs()` is the ENGINE's in-flight count — the same number the connect body and the
/// heartbeat advertise — so it covers coordinator-dispatched workflow runs, which are the work whose
/// loss is unrecoverable. Scheduled MONITOR checks are not engine runs and are not waited for; they
/// are idempotent and simply re-run on their next cadence.
async fn graceful_shutdown(
    bridge: &Arc<FleetBridge>,
    engine: &Arc<dyn local::engine::LocalEngine>,
    loop_task: tokio::task::JoinHandle<()>,
    draining: &AtomicBool,
    budget: Duration,
) {
    draining.store(true, Ordering::Relaxed);
    let in_flight = engine.active_runs();
    tracing::info!(
        in_flight,
        drain_budget_s = budget.as_secs(),
        "shutdown signal received — draining writ-agent-fleet"
    );

    if in_flight > 0 && !budget.is_zero() {
        let engine_for_drain = engine.clone();
        let drained = local::app::lifecycle::drain_until_idle(
            move || engine_for_drain.active_runs(),
            budget,
            DRAIN_POLL,
        )
        .await;
        if drained {
            tracing::info!("all in-flight runs finished — flushing final task results");
            // Let the completing handlers' `task_result` frames reach the socket (see the constant).
            tokio::time::sleep(RESULT_FLUSH_GRACE).await;
        } else {
            tracing::warn!(
                still_running = engine.active_runs(),
                "drain budget expired — the coordinator will not receive results for the runs still \
                 in flight; raise WRIT_FLEET_DRAIN_TIMEOUT_S (and the supervisor's stop grace period)"
            );
        }
    } else if in_flight > 0 {
        tracing::warn!(in_flight, "drain disabled (WRIT_FLEET_DRAIN_TIMEOUT_S=0) — abandoning in-flight runs");
    }

    // Now stop taking work and let the loop unwind on its own; abort only if it overruns.
    bridge.shutdown();
    match tokio::time::timeout(LOOP_STOP_GRACE, loop_task).await {
        Ok(Ok(())) => tracing::info!("fleet bridge loop stopped cleanly"),
        Ok(Err(e)) => tracing::warn!(error = %e, "fleet bridge loop ended with a join error"),
        Err(_) => {
            tracing::warn!(
                grace_s = LOOP_STOP_GRACE.as_secs(),
                "fleet bridge loop did not stop within the grace period — aborting it"
            );
            // `timeout` consumed the handle; the task is detached and the process is about to exit,
            // and the bridge's `running` flag is already false, so nothing new can be accepted.
        }
    }
    bridge.mark_disconnected();
}

/// Shut the warm browser down EXPLICITLY (CDP `Browser.close`, then stop the Playwright driver).
///
/// Bounded, best-effort, and safe to call when no browser was ever launched (`browser()` is `None` on
/// a browserless/stub engine, and `shutdown()` on a never-warmed manager is a no-op). Prior to this,
/// `cli/commands.rs` was the ONLY non-test caller of `BrowserManager::shutdown()` in the tree — the
/// long-lived worker, the one process that launches Chromium thousands of times, never called it.
async fn shutdown_browser(engine: &Arc<dyn local::engine::LocalEngine>) {
    let Some(browser) = engine.browser() else {
        return;
    };
    match tokio::time::timeout(BROWSER_SHUTDOWN_TIMEOUT, browser.shutdown()).await {
        Ok(Ok(())) => tracing::info!("browser + playwright driver shut down"),
        Ok(Err(e)) => tracing::warn!(error = %e, "browser shutdown reported an error (continuing to exit)"),
        Err(_) => tracing::warn!(
            timeout_s = BROWSER_SHUTDOWN_TIMEOUT.as_secs(),
            "browser shutdown timed out — exiting anyway (tini will reap the driver's children)"
        ),
    }
}

/// The status-listener port from `WRIT_FLEET_STATUS_PORT`, if set to a valid non-zero port.
/// Unset/empty → the listener stays off (the default). An unparseable value logs a warning and
/// disables the listener rather than failing startup.
fn status_port() -> Option<u16> {
    let raw = std::env::var("WRIT_FLEET_STATUS_PORT").ok()?;
    let raw = raw.trim();
    if raw.is_empty() {
        return None;
    }
    match raw.parse::<u16>() {
        Ok(p) if p != 0 => Some(p),
        _ => {
            tracing::warn!(
                value = %raw,
                "WRIT_FLEET_STATUS_PORT is not a valid port — status listener disabled"
            );
            None
        }
    }
}

/// Everything `/healthz` reports on. Cheaply cloneable (two `Arc`s + a pool handle).
#[derive(Clone)]
struct StatusState {
    bridge: Arc<FleetBridge>,
    /// The encrypted store, for the `SELECT 1` probe + the recent-run failure streak.
    db: sqlx::SqlitePool,
    /// Process start — the uptime anchor.
    started: std::time::Instant,
    /// Set for the whole graceful-shutdown window.
    draining: Arc<AtomicBool>,
}

/// Compute the health verdict: `(healthy, status)`.
///
/// Every signal is a way a BROKEN worker previously reported `200`, so any one of them failing fails
/// the check. Order is by what an operator should act on first.
/// How stale the read-loop stamp may get before the loop is considered WEDGED.
///
/// The loop re-enters itself at least every `READ_IDLE_TIMEOUT` (60s) on a healthy-but-idle link via
/// the ping probe, so this only needs to clear that with margin. 5 minutes is ~5 idle cycles: long
/// enough that a slow-but-progressing handler is never called dead, short enough that a genuinely
/// stuck worker is restarted long before a human notices.
const READ_LOOP_STALE_SECS: i64 = 300;

fn health_verdict(
    draining: bool,
    connected: bool,
    auth_rejected: bool,
    db_ok: bool,
    infra_streak: u32,
    read_loop_stale_for: Option<i64>,
) -> (bool, &'static str) {
    if draining {
        // Not a fault — but the worker is going away and must not be counted as ready.
        (false, "draining")
    } else if auth_rejected {
        // Distinct from a plain disconnect: only an operator re-minting the token fixes it.
        (false, "auth_rejected")
    } else if !connected {
        (false, "disconnected")
    } else if !db_ok {
        (false, "db_unavailable")
    } else if read_loop_stale_for.is_some_and(|age| age > READ_LOOP_STALE_SECS) {
        // The socket is up and the DB is fine, but the frame handler has not come back around. This
        // is the case every other signal misses: `connected` was set at handshake, `last_task_at`
        // looks merely idle, and the WS ping/pong detector only catches a dead SOCKET. A wedged
        // worker that reports 200 is worse than one that crashes, because nothing restarts it.
        (false, "read_loop_wedged")
    } else if infra_streak >= local::app::health::INFRA_STREAK_UNHEALTHY {
        (false, "task_failures")
    } else {
        (true, "ok")
    }
}

/// Serve the loopback-only `/healthz` status endpoint on `127.0.0.1:<port>`.
///
/// Deliberately a tiny hand-rolled HTTP/1.1 responder (no router, no auth — it never leaves
/// loopback and serves exactly one read-only route): `GET|HEAD /healthz` → `200` only when every
/// check in [`health_verdict`] passes, `503` otherwise. Anything else → `404`. Bind failures warn and
/// give up — the worker itself keeps running.
///
/// Cost per request is deliberately tiny (it is polled by a Docker HEALTHCHECK every 30s): one
/// `SELECT 1` under a 2s timeout plus one index-ordered `LIMIT 12` read of `runs`.
fn spawn_status_listener(port: u16, state: StatusState) {
    tokio::spawn(async move {
        // STRICTLY loopback: never 0.0.0.0 — this endpoint is unauthenticated by design.
        let addr = std::net::SocketAddr::from(([127, 0, 0, 1], port));
        let listener = match tokio::net::TcpListener::bind(addr).await {
            Ok(l) => l,
            Err(e) => {
                tracing::warn!(error = %e, %addr, "status listener bind failed — /healthz disabled (worker continues)");
                return;
            }
        };
        tracing::info!(%addr, "status listener up — GET /healthz (loopback only)");
        loop {
            let (mut stream, _peer) = match listener.accept().await {
                Ok(conn) => conn,
                Err(e) => {
                    tracing::debug!(error = %e, "status listener accept failed");
                    continue;
                }
            };
            let state = state.clone();
            tokio::spawn(async move {
                use tokio::io::{AsyncReadExt, AsyncWriteExt};
                // One bounded read is enough for a health-check request line + headers.
                let mut buf = [0u8; 1024];
                let n = match tokio::time::timeout(
                    std::time::Duration::from_secs(2),
                    stream.read(&mut buf),
                )
                .await
                {
                    Ok(Ok(n)) if n > 0 => n,
                    _ => return,
                };
                let head = String::from_utf8_lossy(&buf[..n]);
                let mut parts = head.split_whitespace();
                let method = parts.next().unwrap_or("");
                let path = parts.next().unwrap_or("").split('?').next().unwrap_or("");

                let (status_line, body) = if matches!(method, "GET" | "HEAD") && path == "/healthz" {
                    let bridge = &state.bridge;
                    let draining = state.draining.load(Ordering::Relaxed);
                    let connected = bridge.is_connected();
                    // An auth rejection is reported as its OWN status: "disconnected" tells an
                    // operator to look at the network, `auth_rejected` tells them to re-mint the
                    // fleet token. Both answer 503 (the worker cannot take work), but only one of
                    // them will ever fix itself.
                    let auth_rejected = bridge.is_auth_rejected();
                    // Store probes: a worker whose DB is unusable, or whose last N runs all failed
                    // with an INFRASTRUCTURE fault, previously answered 200 while being useless.
                    let db_ok = local::app::health::db_reachable(
                        &state.db,
                        local::app::health::DB_PROBE_TIMEOUT,
                    )
                    .await;
                    let infra_streak = local::app::health::infra_failure_streak(
                        &state.db,
                        local::app::health::INFRA_STREAK_WINDOW,
                        local::app::health::INFRA_STREAK_RECENCY_S,
                    )
                    .await;
                    // Age of the last COMPLETED read-loop iteration. `None` before the first one
                    // (a worker that has not connected yet is already covered by `connected`).
                    let read_loop_stale_for = bridge
                        .last_frame_at()
                        .map(|ts| chrono::Utc::now().timestamp().saturating_sub(ts));
                    let (healthy, status) = health_verdict(
                        draining,
                        connected,
                        auth_rejected,
                        db_ok,
                        infra_streak,
                        read_loop_stale_for,
                    );
                    let body = serde_json::json!({
                        "status": status,
                        "connected": connected,
                        "draining": draining,
                        "db_ok": db_ok,
                        "last_frame_at": bridge.last_frame_at(),
                        "read_loop_idle_s": read_loop_stale_for,
                        "auth_rejected": auth_rejected,
                        "auth_failures": bridge.auth_failure_count(),
                        "auth_error": bridge.last_auth_error().await,
                        "uptime_s": state.started.elapsed().as_secs(),
                        "last_task_at": bridge.last_task_at(),
                        "tracked_tasks": bridge.tracked_tasks(),
                        "infra_failure_streak": infra_streak,
                        "infra_failure_threshold": local::app::health::INFRA_STREAK_UNHEALTHY,
                        "version": env!("CARGO_PKG_VERSION"),
                    })
                    .to_string();
                    let status_line = if healthy {
                        "HTTP/1.1 200 OK"
                    } else {
                        "HTTP/1.1 503 Service Unavailable"
                    };
                    (status_line, body)
                } else {
                    ("HTTP/1.1 404 Not Found", r#"{"error":"not found"}"#.to_string())
                };

                let payload = if method == "HEAD" { "" } else { body.as_str() };
                let resp = format!(
                    "{status_line}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{payload}",
                    body.len(),
                );
                let _ = stream.write_all(resp.as_bytes()).await;
                let _ = stream.shutdown().await;
            });
        }
    });
}

/// A truthy env flag: `1` / `true` / `yes` / `on` (case-insensitive).
fn env_flag(key: &str) -> bool {
    std::env::var(key)
        .map(|v| matches!(v.trim().to_ascii_lowercase().as_str(), "1" | "true" | "yes" | "on"))
        .unwrap_or(false)
}

/// Resolve when the process is asked to terminate: Ctrl-C (all platforms) or SIGTERM (unix).
async fn shutdown_signal() {
    let ctrl_c = async {
        let _ = tokio::signal::ctrl_c().await;
    };
    #[cfg(unix)]
    let term = async {
        match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
            Ok(mut s) => {
                s.recv().await;
            }
            Err(_) => std::future::pending::<()>().await,
        }
    };
    #[cfg(not(unix))]
    let term = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {},
        _ = term => {},
    }
}

/// Console tracing for the fleet worker. Honors `RUST_LOG` (default `info`), quiets the playwright-rs
/// internal spam, and routes every line through the redaction writer so no token / sealed blob /
/// `~/.writ` path can reach stdout (defense in depth).
fn init_tracing() {
    use tracing_subscriber::EnvFilter;
    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new("info"))
        .add_directive(
            "playwright_rs::server::object_factory=off".parse().expect("static directive"),
        )
        .add_directive(
            "playwright_rs::server::connection=off".parse().expect("static directive"),
        );
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(true)
        .with_ansi(false)
        .with_writer(local::logging::RedactingMakeWriter)
        .init();
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Serializes the two tests below, which mutate PROCESS-GLOBAL environment variables.
    /// `config::test_env_guard()` is `#[cfg(test)]` on the LIBRARY, so it does not exist when the
    /// library is linked into this binary's test target — hence a local lock.
    static ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    /// A healthy worker is connected, not draining, has a reachable store, and no infra-failure
    /// streak. Every OTHER combination answers 503 with the first actionable reason — these are all
    /// states in which the worker previously reported `200` while being unable to do useful work.
    #[test]
    fn health_verdict_fails_on_every_broken_signal() {
        // healthy
        assert_eq!(health_verdict(false, true, false, true, 0, None), (true, "ok"));
        // A streak under the threshold is still healthy — transient site/network faults happen.
        assert_eq!(
            health_verdict(false, true, false, true, local::app::health::INFRA_STREAK_UNHEALTHY - 1, None),
            (true, "ok")
        );

        // draining wins over everything: the worker is going away.
        assert_eq!(health_verdict(true, true, false, true, 0, None), (false, "draining"));
        assert_eq!(health_verdict(true, false, true, false, 99, None), (false, "draining"));
        // auth rejection is reported ahead of "disconnected" — it needs an operator, not patience.
        assert_eq!(health_verdict(false, false, true, true, 0, None), (false, "auth_rejected"));
        assert_eq!(health_verdict(false, false, false, true, 0, None), (false, "disconnected"));
        // connected but the store is gone: every task would fail with an opaque db_error.
        assert_eq!(health_verdict(false, true, false, false, 0, None), (false, "db_unavailable"));
        // connected + reachable store, but nothing succeeds any more.
        assert_eq!(
            health_verdict(false, true, false, true, local::app::health::INFRA_STREAK_UNHEALTHY, None),
            (false, "task_failures")
        );
    }

    #[test]
    fn a_wedged_read_loop_is_unhealthy_even_when_everything_else_looks_fine() {
        // THE case every other signal misses: socket connected, DB reachable, no auth problem, no
        // task failures — and the frame handler stuck. Before this, such a worker answered 200
        // forever and no supervisor ever restarted it.
        assert_eq!(
            health_verdict(false, true, false, true, 0, Some(READ_LOOP_STALE_SECS + 1)),
            (false, "read_loop_wedged")
        );
        // Exactly at the threshold is still healthy (strictly-greater comparison).
        assert_eq!(
            health_verdict(false, true, false, true, 0, Some(READ_LOOP_STALE_SECS)),
            (true, "ok")
        );
        // An IDLE-but-healthy link must not trip it: the loop re-enters itself every
        // READ_IDLE_TIMEOUT via the ping probe, so a small age is normal.
        assert_eq!(health_verdict(false, true, false, true, 0, Some(90)), (true, "ok"));
        // Never connected yet -> no stamp; `disconnected` is the honest verdict, not "wedged".
        assert_eq!(health_verdict(false, false, false, true, 0, None), (false, "disconnected"));
        // Precedence: a real fault outranks a wedge diagnosis.
        assert_eq!(
            health_verdict(true, true, false, true, 0, Some(9_999)),
            (false, "draining")
        );
        assert_eq!(
            health_verdict(false, true, false, false, 0, Some(9_999)),
            (false, "db_unavailable")
        );
    }

    /// `WRIT_FLEET_DRAIN_TIMEOUT_S` parsing: default when unset/blank/garbage, honored when valid,
    /// clamped at the ceiling, and `0` accepted as an explicit opt-out.
    #[test]
    fn drain_timeout_parsing() {
        let _g = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        const KEY: &str = "WRIT_FLEET_DRAIN_TIMEOUT_S";

        std::env::remove_var(KEY);
        assert_eq!(drain_timeout(), DEFAULT_DRAIN_TIMEOUT, "unset → default");

        std::env::set_var(KEY, "   ");
        assert_eq!(drain_timeout(), DEFAULT_DRAIN_TIMEOUT, "blank → default");

        std::env::set_var(KEY, "not-a-number");
        assert_eq!(drain_timeout(), DEFAULT_DRAIN_TIMEOUT, "garbage → default, never a startup failure");

        std::env::set_var(KEY, "120");
        assert_eq!(drain_timeout(), Duration::from_secs(120));

        std::env::set_var(KEY, "0");
        assert_eq!(drain_timeout(), Duration::ZERO, "0 is an explicit no-drain opt-out");

        std::env::set_var(KEY, "99999");
        assert_eq!(drain_timeout(), MAX_DRAIN_TIMEOUT, "clamped to the ceiling");

        std::env::remove_var(KEY);
    }

    /// `status_port` is off unless set to a valid non-zero port, and a bad value disables the listener
    /// rather than failing startup.
    #[test]
    fn status_port_parsing() {
        let _g = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        const KEY: &str = "WRIT_FLEET_STATUS_PORT";

        std::env::remove_var(KEY);
        assert_eq!(status_port(), None);
        std::env::set_var(KEY, "9444");
        assert_eq!(status_port(), Some(9444));
        std::env::set_var(KEY, "0");
        assert_eq!(status_port(), None, "port 0 is not a health endpoint");
        std::env::set_var(KEY, "nope");
        assert_eq!(status_port(), None);
        std::env::remove_var(KEY);
    }
}
