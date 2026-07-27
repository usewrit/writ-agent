//! `writ-agentd` — the Writ Desktop OSS local daemon.
//!
//! Tiny entrypoint: init tracing → `local::app::bootstrap()` (cold-start the encrypted store +
//! vault + real engine, acquire the singleton lock, publish `runtime.json`) → `local::server::serve`
//! (loopback-bound REST/OpenAI/MCP API). Only builds with the `local` cargo feature; the default
//! cloud `writ-agent` build never sees this binary (`required-features = ["local"]`).
//!
//! On a bootstrap error the daemon logs and exits non-zero — bootstrap may legitimately fail when
//! a second daemon already owns the home, the keyring is unavailable, or the DB is corrupt.

use writ_agent::local;

/// Minimal subcommand dispatch layered over the daemon's default behavior.
///
/// The daemon keeps its zero-arg contract: invoked with NO subcommand it cold-starts + serves exactly
/// as before. Three extra verbs:
///   * `writ-agentd install-service`   — register as a USER-LEVEL OS service (no elevation).
///   * `writ-agentd uninstall-service` — stop + remove the unit.
///   * `writ-agentd mcp`               — MCP server over stdin/stdout: proxies to the RUNNING daemon's
///     `POST /mcp` when one is discovered, else boots a headless backend in-process (see
///     `cli::mcp_stdio`). This binary ships in the app bundle, so MCP client configs point here.
///
/// Kept deliberately tiny (a hand match on the first arg, not a full clap derive) so the daemon
/// entrypoint stays a thin bootstrap shell; the rich CLI surface lives in the separate `writ` binary.
enum Mode {
    /// Default: run the daemon (cold-start + serve).
    Run,
    /// Install the daemon as a user-level service.
    InstallService,
    /// Uninstall the user-level service.
    UninstallService,
    /// Serve MCP over stdio (proxy-or-boot).
    Mcp,
    /// Print usage for the recognized verbs and exit non-zero.
    Usage(String),
}

/// Classify `std::env::args()` into a [`Mode`]. Only the first positional arg is inspected; unknown
/// verbs yield [`Mode::Usage`]. `-h`/`--help`/`help` also print usage.
fn parse_mode() -> Mode {
    let mut args = std::env::args().skip(1);
    match args.next().as_deref() {
        None => Mode::Run,
        Some("install-service") => Mode::InstallService,
        Some("uninstall-service") => Mode::UninstallService,
        Some("mcp") => Mode::Mcp,
        Some("-h") | Some("--help") | Some("help") => Mode::Usage(String::new()),
        Some(other) => Mode::Usage(format!("unknown argument '{other}'")),
    }
}

/// SYNCHRONOUS prologue: everything that mutates the process ENVIRONMENT, run before the tokio
/// runtime (and therefore before any worker thread) exists.
///
/// `std::env::set_var` writes the libc `environ` block without synchronization; doing that once other
/// threads may be in `getenv` is undefined behaviour (Rust 1.80+ marks it `unsafe` for exactly this
/// reason). Both writers here used to run inside the async runtime:
///   * `dotenvy::dotenv()` — sets every var from `.env`.
///   * the Playwright patchright driver override — was inside `BrowserManager::initialize().await`,
///     reachable from several concurrent tasks (see `browser::manager::init_driver_env`).
/// Hoisting them into a sync `main` that then builds the runtime itself makes both single-threaded.
fn main() -> std::process::ExitCode {
    dotenvy::dotenv().ok();
    writ_agent::browser::manager::init_driver_env();

    match tokio::runtime::Builder::new_multi_thread().enable_all().build() {
        Ok(rt) => rt.block_on(async_main()),
        Err(e) => {
            eprintln!("writ-agentd: could not start the async runtime: {e}");
            std::process::ExitCode::FAILURE
        }
    }
}

async fn async_main() -> std::process::ExitCode {
    let mode = parse_mode();
    // MCP stdio reserves stdout for the JSON-RPC stream, so its diagnostics must go to stderr;
    // every other mode keeps the daemon's redacting stdout logger.
    match mode {
        Mode::Mcp => init_tracing_stderr(),
        _ => init_tracing(),
    }

    // Crash reporting: install the scrubbed panic hook EARLY (right after tracing, before any work
    // that could panic) so even an init-time / bootstrap panic is captured to ~/.writ/logs/crash-*.json
    // and logged. The hook REPLACES the default hook (which printed the panic payload to stderr
    // unredacted) with a redacted equivalent; unwind/abort semantics are unaffected, since the hook is
    // only a reporter. The daemon ALSO isolates panics at two finer grains:
    //   * per-RUN — the engine drives each workflow run in a spawned task whose JoinError surfaces a
    //     step panic as a terminal failed run, never unwinding into the daemon (engine::real, Wave 2a).
    //   * per-REQUEST — axum/tower already isolate a handler panic to the one failed response (the
    //     other connections and the daemon keep running); the global hook here still records it.
    local::crash::install_panic_hook("writ-agentd");

    // Service install/uninstall are synchronous, do NOT bootstrap the store/engine, and must run
    // BEFORE any daemon cold-start (they only touch the OS service manager + a unit file).
    match mode {
        Mode::Run => {}
        Mode::Mcp => {
            return match local::cli::mcp_stdio::run().await {
                Ok(()) => std::process::ExitCode::SUCCESS,
                Err(e) => {
                    eprintln!("writ-agentd: mcp failed: {e}");
                    std::process::ExitCode::FAILURE
                }
            };
        }
        Mode::InstallService => {
            return match local::cli::service::install() {
                Ok(()) => std::process::ExitCode::SUCCESS,
                Err(e) => {
                    eprintln!("writ-agentd: install-service failed: {e}");
                    std::process::ExitCode::FAILURE
                }
            };
        }
        Mode::UninstallService => {
            return match local::cli::service::uninstall() {
                Ok(()) => std::process::ExitCode::SUCCESS,
                Err(e) => {
                    eprintln!("writ-agentd: uninstall-service failed: {e}");
                    std::process::ExitCode::FAILURE
                }
            };
        }
        Mode::Usage(msg) => {
            if !msg.is_empty() {
                eprintln!("writ-agentd: {msg}");
            }
            eprintln!(
                "usage: writ-agentd [install-service | uninstall-service | mcp]\n\
                 \n\
                 With no arguments, runs the local daemon (cold-start + serve).\n\
                 `mcp` serves MCP over stdin/stdout (proxies to a running daemon, else boots headless).\n\
                 For the full control CLI (init/start/status/token/config/cloud/mcp), use `writ`."
            );
            // `help` is a success; an unknown-arg message is a failure.
            return if msg.is_empty() {
                std::process::ExitCode::SUCCESS
            } else {
                std::process::ExitCode::FAILURE
            };
        }
    }

    let state = match local::app::bootstrap().await {
        Ok(state) => state,
        Err(e) => {
            tracing::error!(error = %e, "writ-agentd bootstrap failed");
            return std::process::ExitCode::FAILURE;
        }
    };

    // Background work: the scheduler drives DUE monitor checks (+ their change_detected automations)
    // and DUE time-scheduled workflows through the SAME encrypted store + warm-browser engine the
    // API uses. It is the piece that makes monitors/automations actually fire on the daemon. It also
    // updates the shared health snapshot each tick (read by the heartbeat + `/v1/health`).
    let scheduler = local::scheduler::spawn(
        state.db.clone(),
        state.engine.clone(),
        local::scheduler::SchedulerConfig::default(),
        state.health.clone(),
    );

    // Liveness heartbeat: rewrite `~/.writ/agentd.json` every 5s ({pid, started_at, healthy,
    // active_runs, due_monitors, last_tick_at, warm_browser}) so the thin UI can tell the daemon is
    // alive without hitting the loopback API. Resolve the home once; on failure, skip the heartbeat
    // (non-fatal — the API + scheduler still run).
    let heartbeat = match local::config::Paths::resolve() {
        Ok(paths) => Some(local::app::spawn_heartbeat(
            paths,
            state.engine.clone(),
            state.health.clone(),
            chrono::Utc::now().to_rfc3339(),
        )),
        Err(e) => {
            tracing::warn!(error = %e, "could not resolve home for heartbeat; agentd.json not written");
            None
        }
    };

    // Full cloud EXECUTION AGENT: when the desktop is cloud-LINKED (and the user hasn't explicitly
    // DISABLED it) the LinkedAgentManager supervises an outbound LinkedAgentBridge that lets Writ Cloud
    // dispatch work TO this machine — cloud-callable LOCAL workflows by id, ad-hoc recipes, and AI
    // tasks — all on the SAME warm browser + engine + encrypted store, with per-run creds decrypted via
    // the keyring channel key. Recipe + credentials stay on-device; identity/billing stay server-side
    // (the never-trust-a-BYO-agent rule). The manager is DEFAULT-ON-when-linked and fully GATED: it
    // refuses to start unless the desktop is linked, a channel key is sealed, and the agent isn't
    // disabled — so an unlinked/key-less daemon never connects. Install the process-global manager so
    // the `/v1/cloud/agent/*` handlers + the link/unlink REST path can drive start/stop; spawn its
    // supervised loop; and best-effort boot-restore (no-op if preconditions are unmet).
    //
    // Cloud-only: the cloud-free OSS build compiles the `cloud` module out entirely, so there is no
    // linked-agent bridge to supervise — a self-hosted daemon is never cloud-dispatchable.
    #[cfg(feature = "cloud")]
    let cloud_agent = {
        let mgr = std::sync::Arc::new(local::cloud::agent::manager::LinkedAgentManager::new(
            state.db.clone(),
            state.engine.clone(),
            state.vault.clone(),
            // Same recorder the loopback `/ws/record` route uses (stage 5b), so a cloud-dispatched
            // `session_open{purpose:"record"}` records on the SAME warm Chromium — never a second one.
            state.recorder.clone(),
        ));
        local::cloud::agent::manager::install_global(mgr.clone());
        let run_handle = mgr.clone();
        let handle = tokio::spawn(async move { run_handle.run().await });
        let boot = mgr.clone();
        tokio::spawn(async move {
            if let Err(e) = boot.start().await {
                tracing::warn!(error = %e, "cloud agent boot-time start check failed");
            }
        });
        (mgr, handle)
    };

    // IP-relay NODE (stage 1: control plane + settings + REST; the broker WSS data plane lands in
    // stage 2). Install the process-global RelayNodeManager so the `/v1/relay/*` handlers can drive
    // start/stop, and spawn its supervised loop. The manager itself is fully GATED: it refuses to
    // start unless the desktop is cloud-linked AND the user has registered/consented/enabled the node
    // and the schedule window is open. Stage 1's supervisor only honors start/stop intent (no dial).
    //
    // Phase-2 (default OFF): the IP-relay node lives behind the `ip_relay` feature, so no default
    // build compiles it and the daemon never installs or runs a relay node. The OSS agent mirror
    // strips the relay module entirely.
    #[cfg(feature = "ip_relay")]
    let relay_node = {
        let mgr = std::sync::Arc::new(local::relay::node::RelayNodeManager::new(state.db.clone()));
        local::relay::node::install_global(mgr.clone());
        let run_handle = mgr.clone();
        let handle = tokio::spawn(async move { run_handle.run().await });
        // Best-effort: if the user already enabled+consented the node before a restart, bring it back.
        let boot = mgr.clone();
        tokio::spawn(async move {
            if let Err(e) = boot.start().await {
                tracing::warn!(error = %e, "relay node boot-time start check failed");
            }
        });
        (mgr, handle)
    };

    // Serve the loopback API until it errors OR an OS shutdown signal arrives, then stop the
    // scheduler and release the singleton lock + runtime.json so the next boot starts clean.
    let serve = local::server::serve(state);
    tokio::pin!(serve);
    let exit = tokio::select! {
        res = &mut serve => match res {
            Ok(()) => std::process::ExitCode::SUCCESS,
            Err(e) => {
                tracing::error!(error = %e, "writ-agentd server exited with error");
                std::process::ExitCode::FAILURE
            }
        },
        _ = shutdown_signal() => {
            tracing::info!("shutdown signal received — stopping writ-agentd");
            std::process::ExitCode::SUCCESS
        }
    };

    scheduler.shutdown().await;
    if let Some(hb) = heartbeat {
        hb.shutdown().await;
    }
    #[cfg(feature = "cloud")]
    {
        let (mgr, handle) = cloud_agent;
        mgr.stop();
        handle.abort();
    }
    #[cfg(feature = "ip_relay")]
    {
        let (mgr, handle) = relay_node;
        mgr.stop();
        handle.abort();
    }
    if let Ok(paths) = local::config::Paths::resolve() {
        local::app::heartbeat::remove(&paths);
        local::app::release(&paths);
    }
    exit
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

/// Console tracing for the daemon. Kept self-contained (no log-file appender) so the binary stays
/// tiny and free of `AppConfig`; honors `RUST_LOG`, defaulting to `info`. Quiets the two benign
/// playwright-rs internal targets (the `Disposable` channel-object spam) the same way
/// `util::logging` does, since the engine drives the same vendored driver.
///
/// Every rendered line is routed through the [`local::logging`] redaction writer, a last-line scrub
/// so no token / sealed blob / `~/.writ` path can reach stdout even if some field is logged by
/// accident (defense in depth — handlers/stores already avoid logging secrets by construction).
fn init_tracing() {
    use tracing_subscriber::EnvFilter;
    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new("info"))
        .add_directive(
            "playwright_rs::server::object_factory=off"
                .parse()
                .expect("static directive"),
        )
        .add_directive(
            "playwright_rs::server::connection=off"
                .parse()
                .expect("static directive"),
        );
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(true)
        .with_ansi(false) // the redacting writer forwards bytes verbatim; ANSI codes only add noise
        .with_writer(local::logging::RedactingMakeWriter)
        .init();
}

/// Tracing for `mcp` mode → stderr only (stdout is the JSON-RPC stream). Quiet by default (`warn`)
/// like the `writ` CLI; honors `RUST_LOG`. The same playwright-rs channel spam is silenced since the
/// in-process boot path drives the same vendored engine.
///
/// Wrapped in the SAME redacting writer as the daemon's stdout sink. This sink is not a throwaway:
/// `mcp` mode is launched by an AI IDE, which captures the child's stderr into its own log files — so
/// an unredacted line here is persisted somewhere the user never looks.
fn init_tracing_stderr() {
    use tracing_subscriber::EnvFilter;
    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new("warn"))
        .add_directive(
            "playwright_rs::server::object_factory=off"
                .parse()
                .expect("static directive"),
        )
        .add_directive(
            "playwright_rs::server::connection=off"
                .parse()
                .expect("static directive"),
        );
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(false)
        .with_ansi(false)
        .with_writer(local::logging::Redacting(std::io::stderr))
        .init();
}
