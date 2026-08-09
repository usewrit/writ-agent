//! App lifecycle — the single first-run startup path that turns a cold `~/.writ/` into a live
//! [`AppState`], plus a best-effort singleton guard so two daemons can't fight over one home.
//!
//! Bootstrap order (the local-backend spec §0/§1/§10):
//!   1. resolve + create the `~/.writ/` tree
//!   2. acquire the singleton lock (refuse if another LIVE daemon already owns this home)
//!   3. load/mint the vault root (OS keyring, file fallback) — derives the SQLCipher key
//!   4. open the SQLCipher-encrypted DB (fail-closed cipher gate) + run migrations
//!   5. construct the real browser-backed engine
//!   6. load/mint the `wlt_` runtime token
//!   7. publish `runtime.json` (discovery descriptor, `0600`)
//!   8. assemble + return [`AppState`]
//!
//! NEVER logs the token, the vault key, or any secret. Each step emits a structured `tracing` line.
//!
//! ## Singleton lock — chosen approach (no new deps)
//! `fs2`/advisory flock is intentionally avoided. Instead we use an **atomic create-new pidfile** at
//! `~/.writ/writ.lock`:
//!   * `File::create_new` (`O_CREAT|O_EXCL`) makes acquisition race-free at the filesystem layer.
//!   * If the file already exists we read the recorded pid and test liveness with `sysinfo`
//!     (already a crate dependency — no `libc`, no `unsafe`). A LIVE owner ⇒ refuse to start. A
//!     DEAD owner (stale lock from a crash) ⇒ remove the lockfile and retry once.
//! This is not a kernel-held lock (the file persists if the process is `kill -9`'d), but the
//! liveness re-check makes a stale lock self-healing, which is the right trade-off for a single-user
//! desktop daemon and keeps the dependency surface flat.

use std::path::Path;
use std::sync::Arc;

use crate::local::config::{load_config, load_or_create_token, Paths};
use crate::local::db;
use crate::local::engine::RealEngine;
use crate::local::error::{LocalError, LocalResult};
use crate::local::server::AppState;
use crate::local::vault::Vault;

use super::runtime_file::{self, RuntimeInfo};

/// Bring up the local backend from a (possibly cold) `~/.writ/` and return a ready [`AppState`].
///
/// Acquires the singleton lock; if another live daemon already owns this home, returns
/// [`LocalError::Internal`] rather than racing it. On success the caller hands the returned state to
/// [`crate::local::server::serve`]. The engine is the real, browser-backed [`RealEngine`] (the
/// `StubEngine` is only used by the server's own unit tests).
pub async fn bootstrap() -> LocalResult<AppState> {
    // 1. Resolve + create the home tree.
    let paths = Paths::resolve()?;
    paths.ensure_dirs()?;
    tracing::info!(root = %paths.root.display(), "writ home ready");

    // 2. Singleton guard — refuse to run a second live daemon over the same home.
    acquire_singleton(&paths)?;
    tracing::info!(lock = %paths.lock().display(), "singleton lock acquired");
    // Re-assert it for the process lifetime: acquisition is a startup-only check, so a lockfile
    // deleted afterwards would silently admit a second daemon over this home.
    spawn_lock_watchdog(paths.clone());

    // 2b. Load user config from `~/.writ/config.toml` (materializing a default file on first run);
    // `WRIT_*` env overrides win. Loaded before the vault so `[security].use_keyring` applies.
    let config = load_config(&paths);
    tracing::info!(port = config.port, use_keyring = config.use_keyring, "config loaded");

    // Install the user-configured monitor cadence floors into the scheduler's process-global clamp so
    // a raised floor from `[monitors]` takes effect for this session (the hard anti-detection
    // constants remain the absolute minimum). Re-installed live on each `/v1/settings/runtime` save.
    crate::local::scheduler::clamp::install_monitor_floors(config.html_floor_ms, config.js_floor_ms);
    // Same pattern for the device check-capacity budget override (0 = auto from hardware): the
    // capacity gate protects THIS machine from monitor overload — it is not a plan limit.
    crate::local::scheduler::capacity::install_capacity_override(config.max_check_units_per_min);

    // 3. Vault root (OS keyring, file fallback). NEVER logged.
    let mut vault = Vault::load_or_create(&paths.root, config.use_keyring)?;
    tracing::info!("vault root loaded");

    // 3b. Finish any vault rotation a crash interrupted before it could persist the new root, so the
    // DB and `vault.key` can never be left keyed to different roots (which would otherwise brick the
    // next boot). Best-effort: a failure here is logged, and the managed DB open below still self-heals
    // an unreadable DB. If recovery changed the on-disk root, reload the vault so we open the DB under
    // the right key.
    match crate::local::vault_rotate::recover_interrupted_rotation(
        &paths.root,
        &paths.db(),
        &vault,
        config.use_keyring,
    )
    .await
    {
        Ok(true) => {
            vault = Vault::load_or_create(&paths.root, config.use_keyring)?;
            tracing::warn!("completed an interrupted vault rotation on boot");
        }
        Ok(false) => {}
        Err(e) => tracing::warn!(error = %e, "vault rotation recovery check failed (continuing)"),
    }

    // 4. SQLCipher-encrypted DB + migrations (fail-closed cipher gate inside `db::open`). The MANAGED
    // open additionally enforces the data-lifecycle boot policy (PROD-17): it QUARANTINES a corrupt
    // DB (renames it aside + starts fresh) and REFUSES to open a DB written by a NEWER app version
    // (no silent downgrade) — see `db::open_managed`.
    let db = db::open_managed(&paths.db(), &vault.db_key_hex()).await?;
    tracing::info!(db = %paths.db().display(), "encrypted database open + migrated");

    // 4a. Per-account data-isolation boot assertion (fail-closed). The daemon is told which profile
    // to serve via `WRIT_PROFILE`; each profile's DB is durably stamped with the account that OWNS
    // it. If they disagree — this profile home holds a DB stamped for a DIFFERENT account (a moved /
    // restored data dir, or tampering) — REFUSE to boot rather than serve one account's workflows +
    // extracted data as another's. On a never-stamped DB it adopts the current profile as owner, so
    // existing installs are never falsely flagged; only future cross-profile contamination is caught.
    // Cloud-only: the OSS build is single-home (always `local`) so there is nothing to cross.
    #[cfg(feature = "cloud")]
    {
        let profile = crate::local::cloud::token::active_profile();
        assert_profile_owner(&db, &profile).await?;
    }

    // 4b. Crash reconciliation: a previous daemon that was `kill -9`'d (or crashed) can leave `runs`
    // rows stuck in `status='running'` forever. The singleton lock guarantees no OTHER live daemon
    // owns this home right now, so any leftover `running` row is orphaned — mark it `interrupted` so
    // it stops showing as in-flight. Best-effort: a failure here is logged, never fatal.
    let reconciled = reconcile_orphaned_runs(&db).await;
    if reconciled > 0 {
        tracing::warn!(count = reconciled, "marked orphaned 'running' runs as 'interrupted' on boot");
    }
    // Same crash reconciliation for AI sessions + concierge missions: a killed daemon leaves their rows
    // in an active status with no loop behind them, so they show as "live" forever and Stop does nothing
    // (no loop observes the flag). Sweep them to 'cancelled' — a paused ('awaiting_input') mission is
    // resumable via /respond, so it is deliberately left intact.
    match crate::local::store::ai_sessions::interrupt_orphaned(&db).await {
        Ok(n) if n > 0 => tracing::warn!(count = n, "cancelled orphaned AI sessions on boot"),
        Err(e) => tracing::warn!(error = %e, "boot reconciliation of orphaned AI sessions failed (continuing)"),
        _ => {}
    }
    match crate::local::store::concierge_sessions::interrupt_orphaned(&db).await {
        Ok(n) if n > 0 => tracing::warn!(count = n, "cancelled orphaned concierge missions on boot"),
        Err(e) => tracing::warn!(error = %e, "boot reconciliation of orphaned concierge missions failed (continuing)"),
        _ => {}
    }
    // A Dragnet crawl's frontier lives in memory, so a killed daemon leaves the row `crawling` with
    // no loop that can resume it. Sweep any non-terminal crawl to `failed` so it stops showing as
    // in-flight (the user can start a fresh crawl). Best-effort, never fatal.
    match crate::local::store::crawl_jobs::interrupt_orphaned(&db).await {
        Ok(n) if n > 0 => tracing::warn!(count = n, "failed orphaned crawls on boot"),
        Err(e) => tracing::warn!(error = %e, "boot reconciliation of orphaned crawls failed (continuing)"),
        _ => {}
    }

    // 4b2. Auto-update version bookkeeping + post-update self-check (AUTO_UPDATE.md §3 step 12,
    // PROD-7). Best-effort — it never blocks or panics the boot. The whole updater is a desktop
    // concern; the fleet/coordinator builds still compile it (it is `local`-gated) but it is a no-op
    // cost here. See [`reconcile_update_state`] for the ordering rationale.
    if let Err(e) = reconcile_update_state(&db).await {
        tracing::warn!(error = %e, "auto-update state reconciliation failed (continuing)");
    }

    // 4c. Multi-profile link reconciliation: when the shell has just switched this daemon into an
    // ACCOUNT profile (`WRIT_PROFILE=<account_id>`) whose data dir is fresh — its DB has no
    // `LinkState` yet — but the OS keyring already holds that account's token + metadata (written by
    // the device-flow before the switch), materialize the `LinkState` into THIS profile's DB so the
    // profile boots already linked. Best-effort; never fatal. Cloud-only: the OSS build has no
    // multi-profile cloud link, so there is no LinkState to reconcile.
    #[cfg(feature = "cloud")]
    reconcile_profile_link_state(&db).await;

    let vault = Arc::new(vault);

    // 5. Real browser-backed engine (warm Chromium launched lazily on first run). PROD-14: the engine
    // owns the process-wide resource governor, configured from `[engine]` (global/background run
    // ceilings + soft RSS watermark) so concurrent-run bounds + memory shedding honor the user config.
    let gov_cfg = crate::local::governor::GovernorConfig::from_local(&config);
    // Seed the browser AppConfig from process env, then overlay the user's `[browser]` config (e.g.
    // the global `headless` default) so a Settings → Runtime change actually governs the warm browser.
    let mut browser_cfg = crate::config::env::AppConfig::from_env();
    browser_cfg.headless = config.browser_headless;
    // Overlay the DANGEROUS browser-security toggles (default false = secure). These weaken the OS
    // sandbox / TLS validation / same-origin policy and are OFF unless the user explicitly enabled
    // them in Settings → Runtime; boot-fixed like headless (a change applies on the next restart).
    browser_cfg.disable_sandbox = config.browser_disable_sandbox;
    browser_cfg.ignore_certificate_errors = config.browser_ignore_certificate_errors;
    browser_cfg.disable_web_security = config.browser_disable_web_security;
    // Opt-in: seed the baseline from the user's real local Chrome profile (default OFF = clean
    // baseline). The copy lands in the per-account `~/.writ/.browser_profile` (0700/0600).
    browser_cfg.use_local_chrome = config.browser_use_local_chrome;
    if browser_cfg.disable_sandbox || browser_cfg.ignore_certificate_errors || browser_cfg.disable_web_security {
        tracing::warn!(
            disable_sandbox = browser_cfg.disable_sandbox,
            ignore_certificate_errors = browser_cfg.ignore_certificate_errors,
            disable_web_security = browser_cfg.disable_web_security,
            "INSECURE browser flags enabled — the warm Chromium runs with a weakened security boundary"
        );
    }
    let real_engine: Arc<dyn crate::local::engine::LocalEngine> = Arc::new(
        RealEngine::with_app_config_governed(db.clone(), vault.clone(), browser_cfg, gov_cfg),
    );
    // Wrap the real engine so every workflow run fires its `workflow_started`/`workflow_completed`
    // automations (the wrapper delegates browser/governor/registry/recipe/streaming to the inner
    // engine, so recording + scheduling are unaffected).
    let engine: Arc<dyn crate::local::engine::LocalEngine> = Arc::new(
        crate::local::engine::FlowEventEngine::new(real_engine, db.clone()),
    );
    // Wire a WEAK back-reference to the engine into the streaming manager so streaming-session
    // start/stop can fire `streaming_session_started`/`_ended` automations (their `workflow` actions
    // need an engine). `Weak` avoids an Arc cycle; the manager lives inside the engine.
    if let Some(streaming) = engine.streaming() {
        streaming.set_engine(Arc::downgrade(&engine));
    }
    tracing::info!("execution engine ready (browser launches lazily on first run)");

    // 5b. In-process recorder for the local recording WS (`local::record`). It SHARES the engine's
    // warm `BrowserManager` so recording drives the daemon's OWN Chromium directly over CDP — no
    // second browser, no ws-gateway, no remote agent. If the engine exposes no browser (it always
    // does here; the `None` arm only triggers for the test-only `StubEngine`), recording is simply
    // unavailable and `/ws/record` returns 503.
    let recorder = engine
        .browser()
        .map(|bm| Arc::new(crate::recorder::core::PlaywrightRecorder::new(bm)));
    if recorder.is_some() {
        tracing::info!("local recorder ready (shares the engine's warm browser)");
    }

    // 5c. Install the process-global vault app-lock from its persisted `config` state. If a lock was
    // configured the daemon starts LOCKED (a fresh process must re-authenticate via `/v1/vault/unlock`)
    // and secret-touching routes return 423 until then; otherwise the lock is Disabled (no-op). The
    // lock lives in a global slot (same pattern as `cloud::link`) so no `AppState` field is threaded.
    // NOTE: headless `writ-agentd` honors a configured lock — operators who run unattended should not
    // enable the app-lock (it is a desktop-only, human-present feature per SECURITY spec §1.3).
    let lock = crate::local::vault_lock::VaultLock::load(&db).await?;
    crate::local::vault_lock::install_global(lock.clone());
    if lock.status().enabled {
        tracing::info!(locked = lock.status().locked, "vault app-lock active (configured)");
    }

    // 5d. IP-relay node manager. Install the process-global manager + spawn its supervised data-plane
    // loop. The node stays STOPPED until `/v1/relay/*` enables it; here we auto-RESUME a node that was
    // left enabled in a previous session (best-effort — `start` re-checks every precondition: linked +
    // a sealed credential + policy enabled + schedule-open, and the loop itself dials the broker only
    // while desired-running). Cloud-account-gated: unlinked ⇒ `can_run` is false ⇒ the node never dials.
    // The IP-relay node is DEFERRED to phase 2 behind the default-off `ip_relay` feature, so no
    // default build compiles it (nothing to install or auto-resume); the OSS build strips it too.
    #[cfg(feature = "ip_relay")]
    {
        let relay_mgr = Arc::new(crate::local::relay::RelayNodeManager::new(db.clone()));
        crate::local::relay::node::install_global(relay_mgr.clone());
        tokio::spawn(relay_mgr.clone().run());
        tokio::spawn(async move {
            if matches!(relay_mgr.start().await, Ok(true)) {
                tracing::info!("ip-relay node auto-resumed from persisted policy");
            }
        });
    }

    // 6. Runtime bearer token (mint + persist `0600` on first run). NEVER logged.
    let token = load_or_create_token(&paths)?;
    tracing::info!("runtime token ready");

    // 7. Discovery descriptor (`0600`). Config-derived port.
    let info = RuntimeInfo::current(config.port, token.clone());
    runtime_file::write(&paths, &info)?;
    tracing::info!(pid = info.pid, port = info.port, "runtime.json published");

    // 8. Assemble the shared state. The health snapshot starts empty (no tick yet); the scheduler
    // updates it each tick and the heartbeat/`/v1/health` read it — the SAME Arc the daemon hands to
    // `scheduler::spawn` / `spawn_heartbeat`.
    Ok(AppState {
        db,
        vault,
        engine,
        config,
        token: Arc::new(token),
        health: super::health::DaemonHealth::shared(),
        recorder,
    })
}

/// Acquire the best-effort singleton lock for `~/.writ/`.
///
/// See the module docs for the rationale. Returns `Ok(())` once we hold the lock (a fresh pidfile
/// carrying our pid), or [`LocalError::Internal`] if a live daemon already owns this home.
///
/// `pub` because the SELF-HOST FLEET WORKER (`src/bin/writ-agent-fleet.rs`) needs the same guard
/// without the rest of [`bootstrap`] (it has no HTTP server, scheduler, runtime token or
/// `runtime.json`). Two processes sharing one `WRIT_HOME` each get their own connection pool with a
/// 5s busy handler over the same SQLCipher file, and each can independently take the DB-QUARANTINE
/// path in [`db::open_managed`] — i.e. one worker can rename the other's live database aside.
pub fn acquire_singleton(paths: &Paths) -> LocalResult<()> {
    let lock = paths.lock();

    // First attempt — race-free create.
    match try_create_lock(&lock) {
        Ok(()) => return Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
            // Fall through to the stale-lock check.
        }
        Err(e) => return Err(e.into()),
    }

    // The lockfile exists. Decide whether its owner is still alive.
    if lock_owner_alive(&lock) {
        return Err(LocalError::Internal(format!(
            "another Writ daemon is already running for this home (lock held at {})",
            lock.display()
        )));
    }

    // Stale lock (owner is gone). Clear it and try once more.
    tracing::warn!(lock = %lock.display(), "removing stale singleton lock (owner not alive)");
    let _ = std::fs::remove_file(&lock);
    match try_create_lock(&lock) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => Err(LocalError::Internal(
            "raced another Writ daemon while reclaiming a stale lock".into(),
        )),
        Err(e) => Err(e.into()),
    }
}

/// Atomically create the lockfile (`O_CREAT|O_EXCL`) and write our pid into it (`0600` on unix).
/// `AlreadyExists` is propagated so the caller can run the stale-owner check.
fn try_create_lock(lock: &Path) -> std::io::Result<()> {
    use std::io::Write;
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(lock)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = f.set_permissions(std::fs::Permissions::from_mode(0o600));
    }
    write!(f, "{}", std::process::id())?;
    f.flush()?;
    Ok(())
}

/// Is the pid recorded in `lock` a currently-running process? A malformed/empty lockfile (or one we
/// can't read) is treated as NOT alive, so a corrupt lock self-heals rather than wedging startup.
fn lock_owner_alive(lock: &Path) -> bool {
    let Ok(contents) = std::fs::read_to_string(lock) else {
        return false;
    };
    let Ok(pid) = contents.trim().parse::<u32>() else {
        return false;
    };
    // A lockfile carrying our own pid (e.g. a re-bootstrap in the same process) is "us", not a
    // competitor — treat as not-alive so we reclaim it.
    if pid == std::process::id() {
        return false;
    }
    let mut sys = sysinfo::System::new();
    // `refresh_process` returns true iff a process with this pid exists.
    sys.refresh_process(sysinfo::Pid::from_u32(pid))
}

/// Best-effort teardown of lifecycle-owned files (lock + runtime descriptor). Idempotent; intended
/// for a graceful shutdown hook. Missing files are not errors.
pub fn release(paths: &Paths) {
    runtime_file::remove(paths);
    release_singleton(paths);
}

/// How often the watchdog re-checks that we still own the lockfile.
const LOCK_WATCHDOG_INTERVAL: std::time::Duration = std::time::Duration::from_secs(30);

/// Keep asserting ownership of the singleton lock for as long as this process runs.
///
/// [`acquire_singleton`] only runs at startup, so on its own it cannot notice the lockfile
/// disappearing afterwards — and once it is gone, the NEXT process starts happily alongside us and
/// two workers share one SQLCipher home. Ownership-checked [`release_singleton`] removes the common
/// cause, but not every one: an older build without that fix, an `rm`, a `tmpfiles`/cleaner sweep,
/// or a restored backup can all still clear it.
///
/// So we re-check periodically and:
///   * missing        → recreate it with our pid (we are the rightful owner; restore the guard),
///   * owned by a DEAD pid → reclaim it the same way,
///   * owned by ANOTHER LIVE pid → log an error every tick. We deliberately do NOT exit: by then the
///     other worker is already up, and racing to `remove_file` would just ping-pong the lock. A loud,
///     repeating error is the actionable signal, and the operator kills the duplicate.
///
/// Cheap by construction: one small read (plus a rare write) every 30s.
pub fn spawn_lock_watchdog(paths: Paths) {
    tokio::spawn(async move {
        let lock = paths.lock();
        loop {
            tokio::time::sleep(LOCK_WATCHDOG_INTERVAL).await;
            if lock_is_ours(&lock) {
                continue;
            }
            if lock.exists() && lock_owner_alive(&lock) {
                tracing::error!(
                    lock = %lock.display(),
                    "singleton lock is held by ANOTHER LIVE process — two workers are sharing this \
                     WRIT_HOME. Two connection pools over one SQLCipher file corrupt state and can \
                     quarantine the database. Stop the duplicate worker, or give it its own WRIT_HOME."
                );
                continue;
            }
            // Missing, malformed, or owned by a dead pid — restore our claim so the next process
            // to start is correctly refused.
            let _ = std::fs::remove_file(&lock);
            match try_create_lock(&lock) {
                Ok(()) => tracing::warn!(
                    lock = %lock.display(),
                    "singleton lock had vanished while we were running — re-asserted it"
                ),
                Err(e) => tracing::error!(
                    lock = %lock.display(), error = %e,
                    "could not re-assert the singleton lock"
                ),
            }
        }
    });
}

/// Release ONLY the singleton lock, leaving `runtime.json` alone.
///
/// The fleet worker publishes no `runtime.json` (it serves no local API to discover), so it releases
/// just the lock. Idempotent; a missing lockfile is not an error. Note the lock is a pidfile, not a
/// kernel lock: a `kill -9` leaves it behind, and the next start reclaims it after confirming the
/// recorded pid is dead (see the module docs).
///
/// OWNERSHIP-CHECKED. This used to `remove_file` unconditionally, which made the whole singleton
/// guard defeatable by ordinary use: any short-lived process that bootstraps this home and exits
/// (a `writ` CLI command, a failed start, a test) ran this teardown and deleted the lockfile of the
/// LIVE daemon that legitimately owned it. The next start then found no lockfile at all, sailed
/// past `acquire_singleton`, and a SECOND worker came up over the same `WRIT_HOME` — two connection
/// pools and two `db::open_managed` boot policies against one SQLCipher file, which is exactly the
/// scenario the acquire path refuses (and which can quarantine a live database). Observed in the
/// wild: a 10-day-old fleet worker still running while a new one held the lockfile.
///
/// Deleting only OUR OWN pidfile makes teardown safe for every caller and keeps a live owner's lock
/// intact. A stale lock left by a `kill -9` is still self-healing via the liveness check in
/// [`acquire_singleton`].
pub fn release_singleton(paths: &Paths) {
    if lock_is_ours(&paths.lock()) {
        let _ = std::fs::remove_file(paths.lock());
    }
}

/// True when the lockfile exists and records THIS process's pid.
///
/// A missing or unreadable lockfile is "not ours" — we must not delete a file we cannot prove we
/// own. A malformed lockfile is likewise left alone here (unlike [`lock_owner_alive`], which treats
/// it as dead so startup can self-heal): teardown has no reason to clear it, and the next
/// `acquire_singleton` will.
fn lock_is_ours(lock: &Path) -> bool {
    std::fs::read_to_string(lock)
        .ok()
        .and_then(|c| c.trim().parse::<u32>().ok())
        .is_some_and(|pid| pid == std::process::id())
}

/// Wait until `active()` reports zero in-flight work, or `budget` elapses. Returns `true` if the
/// process went idle within the budget, `false` on timeout.
///
/// The SIGTERM drain primitive: a container redeploy (`docker restart`, a systemd `Restart=`, a k8s
/// rollout) must not abandon a run mid-flight, because the coordinator that dispatched it is waiting
/// for a `task_result` frame and will otherwise hang until its own timeout. Polling (rather than a
/// completion signal) is deliberate — the engine's in-flight count is the only cross-lane truth, it
/// covers runs started by ANY lane, and a 250ms poll during shutdown costs nothing.
///
/// `active` is a closure rather than an `&dyn LocalEngine` so the timeout path is unit-testable
/// without a browser-backed engine.
pub async fn drain_until_idle<F>(active: F, budget: std::time::Duration, poll: std::time::Duration) -> bool
where
    F: Fn() -> usize,
{
    let deadline = std::time::Instant::now() + budget;
    loop {
        let in_flight = active();
        if in_flight == 0 {
            return true;
        }
        if std::time::Instant::now() >= deadline {
            tracing::warn!(
                in_flight,
                budget_s = budget.as_secs(),
                "drain budget expired with work still in flight — abandoning it to exit \
                 (raise the drain timeout, or the supervisor's stop grace period, if this recurs)"
            );
            return false;
        }
        tokio::time::sleep(poll.min(deadline.saturating_duration_since(std::time::Instant::now()))).await;
    }
}

/// Boot reconciliation of the auto-update state (AUTO_UPDATE.md §3 step 12, PROD-7).
///
/// This is the ONE place the version record advances, and the ordering matters:
///
///   1. **Seed** — a cold `app_meta` stamps `installed_version` from the compiled-in build version.
///   2. **Detect the apply** — this daemon ships INSIDE the desktop bundle, so a boot whose
///      `CARGO_PKG_VERSION` is strictly newer than the recorded `installed_version` *is* the first
///      boot after an update applied. That is the only trustworthy apply signal available offline:
///      the shell cannot be asked (it may have been replaced mid-flight) and a self-claim in the
///      manifest is attacker-controlled. Recording it here retains the outgoing version as
///      `prior_version` (the rollback target) and advances the downgrade anchor the §3 policy chain
///      gates against — without this the anchor would stay pinned at the ORIGINAL install forever,
///      and a "downgrade" to any version above it would read as an upgrade.
///   3. **Self-check** — only then does the gate probe the RUNNING build (the encrypted store opens,
///      SQLCipher is genuinely linked, a trivial query succeeds — the SAME signal `GET /v1/health`
///      reports). Step 2 resets the health-fail counter, so a fresh update always gets its full
///      `HEALTH_FAIL_ROLLBACK_THRESHOLD` budget rather than inheriting the previous build's failures.
///   4. **Persist the verdict** — a demanded rollback is written to `update.rollback_to` so it
///      SURVIVES this process. The daemon cannot replace its own binary, so the durable key is how
///      the demand reaches the shell (`GET /v1/update/state`), which surfaces it and stops offering
///      the unhealthy build. A healthy boot clears the key.
///
/// Every step is best-effort: a bookkeeping failure logs and continues, and never rolls back (that
/// would risk a rollback loop on a transient DB hiccup — a genuinely broken store is caught by the
/// self-check itself, which opens it).
async fn reconcile_update_state(db: &sqlx::SqlitePool) -> LocalResult<()> {
    use crate::local::store::config_kv;
    use crate::local::update::{RollbackAction, VersionRecord};

    const ROLLBACK_TO_KEY: &str = "update.rollback_to";
    let running = env!("CARGO_PKG_VERSION");

    let record = VersionRecord::ensure_seeded(db, running, None).await?;

    // Step 2: did an update just apply? Compare with semver, not string equality, so a build that
    // ships an unparseable version can never fabricate an "upgrade".
    let applied = match (
        record.installed_version.as_deref().and_then(|v| semver::Version::parse(v).ok()),
        semver::Version::parse(running).ok(),
    ) {
        (Some(recorded), Some(now)) => now > recorded,
        // An unparseable recorded or running version is NOT an apply signal — leave the anchor put.
        _ => false,
    };
    if applied {
        match record.record_successful_update(db, running, None).await {
            Ok(_) => tracing::info!(
                version = running,
                prior = record.installed_version.as_deref().unwrap_or("<none>"),
                "auto-update: first boot on a newer build — advanced the downgrade anchor"
            ),
            // The monotonic guard inside `record_successful_update` is defence in depth; we already
            // proved `now > recorded`, so this is a genuine bookkeeping failure, not a policy reject.
            Err(e) => tracing::warn!(error = %e, "auto-update: could not record the applied update"),
        }
    }

    // Steps 3 + 4.
    match crate::local::update::run_post_update_gate(db).await {
        RollbackAction::Rollback { prior_version } => {
            match prior_version.as_deref() {
                Some(prior) => {
                    // Durable so the shell can act on it after this process is gone.
                    config_kv::set(db, ROLLBACK_TO_KEY, prior).await?;
                    tracing::error!(
                        prior_version = prior,
                        "auto-update: self-check failed repeatedly — recorded a rollback demand to the retained prior version"
                    );
                }
                None => {
                    // Nothing retained (e.g. the failure landed on the very first install). Surface
                    // the demand WITHOUT a target so the UI can still tell the user the build is
                    // unhealthy instead of silently limping.
                    config_kv::set(db, ROLLBACK_TO_KEY, "").await?;
                    tracing::error!(
                        "auto-update: self-check failed repeatedly but NO prior version is retained — cannot roll back"
                    );
                }
            }
        }
        RollbackAction::HeldFailing { fail_count } => {
            tracing::warn!(fail_count, "auto-update: post-update self-check failing (below rollback threshold)");
        }
        RollbackAction::Healthy => {
            // Clear any stale demand from an earlier bad build so a recovered install stops nagging.
            if config_kv::delete(db, ROLLBACK_TO_KEY).await? {
                tracing::info!("auto-update: build is healthy again — cleared the rollback demand");
            }
        }
    }
    Ok(())
}

/// Boot reconciliation: mark every `runs` row still in `status='running'` as `interrupted`. Safe to
/// call only AFTER the singleton lock is held (no other live daemon could own these in-flight rows).
/// Returns the number of rows reconciled. Errors are logged, not propagated — reconciliation must
/// never block startup.
async fn reconcile_orphaned_runs(db: &sqlx::SqlitePool) -> u64 {
    match crate::local::store::runs::interrupt_running(db).await {
        Ok(n) => n,
        Err(e) => {
            tracing::warn!(error = %e, "boot reconciliation of orphaned runs failed (continuing)");
            0
        }
    }
}

/// Reconcile this profile's `LinkState` against the keyring on boot.
///
/// * **Account profile** (`WRIT_PROFILE=<account_id>`): materialize the `LinkState` from the keyring
///   (token + metadata written by the device flow before the switch) when the profile's DB has none,
///   so it boots already linked. No-op if it already has `LinkState` matching a keyring token.
///   **Ghost case:** if `LinkState` is in the DB but the keyring has NO entry for this profile
///   (`Ok(None)`, not a transient keyring error), the token was independently cleared/revoked or the
///   DB was restored from a `writ.db.corrupt-*` sibling while the keychain wasn't — the desktop LOOKS
///   linked in the UI but can't actually talk to the cloud, and every gate that reads a live token
///   (cloud agent supervisor, refresh path, marketplace unseal) silently fails. Clear it (LinkState +
///   channel key) so the user gets kicked to `/login` and can re-link cleanly.
/// * **`local` profile** (the no-account side user): the device flow NEVER links here, so any
///   `LinkState` is legacy residue from the pre-isolation flat layout — CLEAR it, otherwise the stale
///   ghost account pins the login gate to `logged_out` and traps the user (they chose "continue
///   without an account" but can never get past `/login`).
///
/// Best-effort — a failure leaves the profile `logged_out` (the user can re-link), never blocks boot.
/// A transient `Err` from the keyring is preserved as "keep LinkState" (don't wipe on a locked
/// keychain), only a definitive `Ok(None)` triggers the ghost sweep.
///
/// Cloud-only: the cloud-free OSS build has no `cloud` module and never links, so this reconciliation
/// (and its inner form) are compiled out entirely.
#[cfg(feature = "cloud")]
async fn reconcile_profile_link_state(db: &sqlx::SqlitePool) {
    let profile = crate::local::cloud::token::active_profile();
    reconcile_profile_link_state_for(db, &profile).await;
}

/// Fail-closed per-account data-isolation assertion, run once on boot (see call site §4a).
///
/// Compares the profile the daemon was told to serve (`WRIT_PROFILE`) against the account durably
/// stamped as the OWNER of this DB:
///  - unstamped DB → ADOPT the current profile as owner and continue (first boot after this guard
///    shipped, or a freshly-created profile). Existing data is thereby owned by whatever profile it
///    currently runs as, so no real install is ever falsely flagged.
///  - stamped == current profile → the normal case, continue.
///  - stamped != current profile → ISOLATION VIOLATION. Return an error so `bootstrap` aborts and
///    the daemon never serves the wrong account's data. Recovery: the shell can switch to another
///    profile (each boots its own daemon), or the offending profile dir is removed / re-linked.
#[cfg(feature = "cloud")]
async fn assert_profile_owner(db: &sqlx::SqlitePool, profile: &str) -> LocalResult<()> {
    use crate::local::cloud::state;
    match state::profile_owner(db).await? {
        None => {
            state::set_profile_owner(db, profile).await?;
            tracing::info!(profile = %profile, "stamped profile owner on first boot (data-isolation anchor)");
            Ok(())
        }
        Some(owner) if owner == profile => Ok(()),
        Some(owner) => {
            tracing::error!(
                serving_profile = %profile,
                data_owner = %owner,
                "ISOLATION VIOLATION: this profile home's DB belongs to a different account — refusing to boot. \
                 The data dir may have been moved/restored into the wrong profile. Remove/rename the offending \
                 profile directory or re-link the account."
            );
            Err(LocalError::IsolationViolation(format!(
                "profile home '{profile}' holds data owned by account '{owner}'"
            )))
        }
    }
}

/// Profile-parameterised inner form, so the ghost-sweep + materialise paths can be unit-tested
/// without env-var mutation. Same behaviour as [`reconcile_profile_link_state`].
#[cfg(feature = "cloud")]
async fn reconcile_profile_link_state_for(db: &sqlx::SqlitePool, profile: &str) {
    use crate::local::cloud::state::LinkState;
    use crate::local::cloud::{channel, token};

    if profile == token::LOCAL_PROFILE {
        match LinkState::clear(db).await {
            Ok(true) => tracing::info!(
                "cleared stale legacy LinkState from the local (no-account) profile — see reconcile_profile_link_state"
            ),
            Ok(false) => {}
            Err(e) => tracing::warn!(error = %e, "could not clear stale local-profile LinkState (continuing)"),
        }
        return;
    }
    let ls = match LinkState::load(db).await {
        Ok(ls) => ls,
        Err(e) => {
            tracing::warn!(error = %e, "link reconciliation: could not read LinkState (skipping)");
            return;
        }
    };
    if ls.is_some() {
        // Ghost sweep: DB says linked, but does the keyring back it? Only a definitive `Ok(None)`
        // (no entry) counts as a ghost — a keyring `Err` (locked/unavailable) leaves the LinkState
        // intact so a transient failure doesn't nuke a legit link.
        match token::load_account(profile) {
            Ok(Some(_)) => {} // matched → nothing to do
            Ok(None) => {
                match LinkState::clear(db).await {
                    Ok(true) => tracing::info!(
                        profile = %profile,
                        "cleared ghost LinkState — DB was linked but keyring had no token (likely a DB restore from writ.db.corrupt-* without a matching keychain). User will be prompted to re-link."
                    ),
                    Ok(false) => {}
                    Err(e) => tracing::warn!(error = %e, "could not clear ghost LinkState (continuing)"),
                }
                // Also drop any stray channel key so the marketplace executor doesn't unseal with a
                // key that no longer matches a live link. Best-effort; a missing entry is fine.
                let _ = channel::clear();
            }
            Err(e) => {
                tracing::warn!(
                    profile = %profile,
                    error = %e,
                    "link reconciliation: keyring read failed — leaving LinkState in place (transient error, not a ghost)"
                );
            }
        }
        return;
    }
    // No LinkState → try to materialize one from the keyring (post-switch bootstrap).
    let acct = match token::load_account(profile) {
        Ok(Some(a)) => a,
        Ok(None) => {
            // No keyring token for this profile → the daemon will report logged_out/unlinked and the
            // login gate will ask the user to (re-)link. Logged so a "stuck on login after link" is
            // diagnosable from the daemon log.
            tracing::warn!(profile = %profile, "link reconciliation: no keyring token for this profile — staying unlinked");
            return;
        }
        Err(e) => {
            tracing::warn!(profile = %profile, error = %e, "link reconciliation: keyring read failed — staying unlinked");
            return;
        }
    };
    if acct.meta.account_id.is_empty() {
        tracing::warn!(profile = %profile, "link reconciliation: keyring token has no account metadata — user must re-link");
        return;
    }
    let ls = LinkState {
        account_id: acct.meta.account_id,
        email: acct.meta.email,
        cloud_base_url: acct.meta.base_url,
        scopes: acct.meta.scopes,
        linked_at: acct.meta.linked_at,
        language: acct.meta.language,
    };
    match ls.save(db).await {
        Ok(()) => {
            tracing::info!(profile = %profile, "reconciled LinkState from keyring for switched-in profile");
            // Fresh link for this profile (LinkState was absent → just materialized). If the user has
            // no local BYO key, default the managed cloud AI gateway ON so AI works immediately. This
            // materialize branch only runs once per link (subsequent boots find LinkState present and
            // take the ghost-sweep path), so it never overrides a later user opt-out.
            default_cloud_gateway_on_fresh_link(db).await;
        }
        Err(e) => tracing::warn!(error = %e, "link reconciliation: could not persist LinkState"),
    }
}

/// On a freshly-established link, turn the managed cloud AI gateway ON when no local BYO key is set,
/// so a just-linked desktop can use AI without configuring a provider. Best-effort: a storage error
/// is logged but never disrupts the link. See [`provider::enable_cloud_gateway_if_no_byo_key`].
#[cfg(feature = "cloud")]
pub(crate) async fn default_cloud_gateway_on_fresh_link(db: &sqlx::SqlitePool) {
    use crate::local::ai::provider;
    match provider::enable_cloud_gateway_if_no_byo_key(db).await {
        Ok(true) => tracing::info!("no BYO AI key on fresh link — enabled the managed cloud AI gateway by default"),
        Ok(false) => {}
        Err(e) => tracing::warn!(error = %e, "could not auto-enable the cloud AI gateway on link (continuing)"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The lock is acquired once, refuses a same-home re-acquire while held, and is reclaimable
    /// after `release`. Exercises the create-new + stale-check logic without a browser/DB.
    #[test]
    fn singleton_lock_acquire_refuse_release() {
        let dir = tempfile::tempdir().unwrap();
        let paths = Paths::at(dir.path().join(".writ"));
        paths.ensure_dirs().unwrap();

        // First acquire succeeds and writes our pid.
        acquire_singleton(&paths).unwrap();
        assert!(paths.lock().is_file());
        let recorded = std::fs::read_to_string(paths.lock()).unwrap();
        assert_eq!(recorded.trim(), std::process::id().to_string());

        // A lock owned by THIS process is treated as not-a-competitor (so re-bootstrap reclaims it),
        // which means a second acquire in-process succeeds rather than deadlocking.
        acquire_singleton(&paths).unwrap();

        // A lock owned by a definitely-dead pid is stale and gets reclaimed.
        std::fs::write(paths.lock(), "999999999").unwrap();
        assert!(!lock_owner_alive(&paths.lock()), "absurd pid must be dead");
        acquire_singleton(&paths).unwrap();
        assert_eq!(
            std::fs::read_to_string(paths.lock()).unwrap().trim(),
            std::process::id().to_string()
        );

        // A lock owned by a LIVE foreign pid (use pid 1 — always alive on unix) is refused.
        std::fs::write(paths.lock(), "1").unwrap();
        #[cfg(unix)]
        {
            assert!(lock_owner_alive(&paths.lock()), "pid 1 must be alive on unix");
            let err = acquire_singleton(&paths).unwrap_err();
            assert!(matches!(err, LocalError::Internal(_)), "live owner must refuse: {err:?}");
        }

        // release() is OWNERSHIP-CHECKED: a live foreign owner's lock must survive our teardown.
        // Deleting it unconditionally is what previously let a second worker start over a home a
        // live daemon still owned.
        #[cfg(unix)]
        {
            std::fs::write(paths.lock(), "1").unwrap();
            release(&paths);
            assert!(paths.lock().is_file(), "must not delete a LIVE foreign owner's lock");
            assert_eq!(std::fs::read_to_string(paths.lock()).unwrap().trim(), "1");
        }

        // Our OWN lock is cleared, so a fresh acquire works.
        std::fs::write(paths.lock(), std::process::id().to_string()).unwrap();
        release(&paths);
        assert!(!paths.lock().exists());
        acquire_singleton(&paths).unwrap();
    }

    /// The fleet worker's variant: `release_singleton` clears the lock WITHOUT touching
    /// `runtime.json` (a fleet worker publishes none), and a second holder is refused while it is
    /// held by a live foreign pid — the whole point of the guard for a shared `WRIT_HOME`.
    #[test]
    fn release_singleton_clears_only_the_lock() {
        let dir = tempfile::tempdir().unwrap();
        let paths = Paths::at(dir.path().join(".writ"));
        paths.ensure_dirs().unwrap();
        // A stand-in runtime.json that the fleet path must not delete.
        std::fs::write(paths.runtime_json(), "{}").unwrap();

        acquire_singleton(&paths).unwrap();
        assert!(paths.lock().is_file());

        release_singleton(&paths);
        assert!(!paths.lock().exists(), "lock released");
        assert!(paths.runtime_json().is_file(), "runtime.json untouched by release_singleton");

        // Idempotent.
        release_singleton(&paths);

        // A lock owned by someone ELSE is never removed by our teardown. This is the regression
        // that let two fleet workers share one WRIT_HOME: a short-lived process that bootstrapped
        // this home and exited used to delete the live owner's pidfile on its way out, after which
        // the next start found no lock and came up alongside the running worker.
        #[cfg(unix)]
        {
            std::fs::write(paths.lock(), "1").unwrap();
            release_singleton(&paths);
            assert!(paths.lock().is_file(), "another owner's lock must survive our teardown");
        }
        // A malformed lockfile is likewise not ours to delete.
        std::fs::write(paths.lock(), "not-a-pid").unwrap();
        release_singleton(&paths);
        assert!(paths.lock().is_file(), "malformed lock is not ours to remove");
        std::fs::remove_file(paths.lock()).unwrap();

        // A LIVE foreign owner is refused (pid 1 is always alive on unix).
        #[cfg(unix)]
        {
            std::fs::write(paths.lock(), "1").unwrap();
            let err = acquire_singleton(&paths).unwrap_err();
            assert!(
                matches!(err, LocalError::Internal(_)),
                "a second holder of one WRIT_HOME must be refused: {err:?}"
            );
        }
    }

    /// `drain_until_idle` returns as soon as the in-flight count hits zero, and reports `false` when
    /// the budget expires with work still running (the SIGTERM path that must still exit).
    #[tokio::test]
    async fn drain_until_idle_waits_then_times_out() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        use std::time::Duration;

        // Already idle → returns immediately.
        assert!(
            drain_until_idle(|| 0, Duration::from_secs(5), Duration::from_millis(5)).await,
            "an idle process drains instantly"
        );

        // Two in-flight runs that finish while we wait → drained within the budget.
        let active = Arc::new(AtomicUsize::new(2));
        let ticker = active.clone();
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(30)).await;
            ticker.store(0, Ordering::SeqCst);
        });
        let a = active.clone();
        assert!(
            drain_until_idle(move || a.load(Ordering::SeqCst), Duration::from_secs(5), Duration::from_millis(5)).await,
            "work that completes inside the budget drains cleanly"
        );

        // Work that never finishes → the budget expires and we give up rather than hang forever.
        let stuck = Arc::new(AtomicUsize::new(1));
        let s = stuck.clone();
        let started = std::time::Instant::now();
        assert!(
            !drain_until_idle(move || s.load(Ordering::SeqCst), Duration::from_millis(60), Duration::from_millis(5))
                .await,
            "an expired drain budget must report failure, not block"
        );
        assert!(started.elapsed() >= Duration::from_millis(60), "the full budget was honored");
    }

    /// A malformed lockfile is treated as not-alive (self-healing), not a hard error.
    #[test]
    fn malformed_lock_is_not_alive() {
        let dir = tempfile::tempdir().unwrap();
        let lock = dir.path().join("writ.lock");
        std::fs::write(&lock, "not-a-pid").unwrap();
        assert!(!lock_owner_alive(&lock));
        std::fs::write(&lock, "").unwrap();
        assert!(!lock_owner_alive(&lock));
    }

    /// Full bootstrap needs the OS keyring + a launchable browser path; gate it as ignored so it
    /// doesn't run in CI. The composable parts (lock, runtime_file) are covered above and in
    /// `runtime_file`. Run locally with:
    ///   `cargo test --features local -- --ignored bootstrap_smoke`
    #[tokio::test]
    #[ignore = "touches the real OS keyring + ~/.writ via WRIT_HOME; run manually"]
    async fn bootstrap_smoke() {
        let dir = tempfile::tempdir().unwrap();
        std::env::set_var("WRIT_HOME", dir.path().join(".writ"));
        let state = bootstrap().await.expect("bootstrap");
        assert!(state.token.starts_with("wlt_"));
        assert_eq!(state.engine.active_runs(), 0);
        // runtime.json was published with our pid.
        let paths = Paths::resolve().unwrap();
        let info = runtime_file::read(&paths).unwrap().expect("runtime.json");
        assert_eq!(info.pid, std::process::id());
        release(&paths);
    }

    /// An **account profile** with a `LinkState` row in the DB but NO keyring token is a ghost — the
    /// UI reads it as "linked" (email/name from stale metadata) but every gate that needs a live token
    /// silently fails (cloud agent supervisor stays parked with `no_channel_key`, refresh 401s,
    /// marketplace unseal fails). Reproduces the case where `writ.db` was recovered from a
    /// `writ.db.corrupt-*` sibling but the OS keychain wasn't. Boot reconciliation must clear the ghost.
    ///
    /// Uses a random profile name that has never been linked, so `token::load_account` returns
    /// `Ok(None)` — the ghost signal. Guarded so a CI env whose keyring returns `Err` (locked/absent)
    /// skips instead of failing (mirrors `manager_refuses_when_linked_but_no_channel_key` in
    /// `agent::manager`).
    #[cfg(feature = "cloud")]
    #[tokio::test]
    async fn reconcile_clears_ghost_link_state_on_account_profile() {
        use crate::local::cloud::state::LinkState;
        use crate::local::cloud::token;

        let dir = tempfile::tempdir().unwrap();
        let paths = Paths::at(dir.path().join(".writ"));
        paths.ensure_dirs().unwrap();
        let v = crate::local::vault::Vault::load_or_create(&paths.root, false).unwrap();
        let db = crate::local::db::open(&paths.db(), &v.db_key_hex()).await.unwrap();

        // A profile name that has never been linked — no keyring entry for it.
        let profile = format!("acct_ghost_reconcile_{}", std::process::id());
        // Only run the assertion if the keyring is available AND reports "no entry" cleanly.
        // Otherwise skip (CI without keyring / locked keychain).
        match token::load_account(&profile) {
            Ok(None) => {}
            _ => return,
        }

        LinkState {
            account_id: "acct_ghost".into(),
            email: "ghost@example.com".into(),
            cloud_base_url: "https://cloud.example.com/".into(),
            scopes: vec![],
            linked_at: Some(chrono::Utc::now()),
            language: None,
        }
        .save(&db)
        .await
        .unwrap();
        assert!(LinkState::load(&db).await.unwrap().is_some(), "precondition: DB linked");

        // Ghost sweep: DB says linked, keyring says no → clear the LinkState so the login gate can
        // ask the user to re-link.
        reconcile_profile_link_state_for(&db, &profile).await;
        assert!(
            LinkState::load(&db).await.unwrap().is_none(),
            "ghost LinkState (DB-linked, no keyring token) must be cleared"
        );
    }

    /// Owner-stamp boot assertion (data isolation). A fresh DB is ADOPTED by the profile it first
    /// boots as (stamped, no error); a subsequent boot of the SAME profile matches; a boot of that
    /// DB under a DIFFERENT profile name is an isolation violation and errors (fail closed).
    #[cfg(feature = "cloud")]
    #[tokio::test]
    async fn owner_stamp_adopts_then_rejects_mismatch() {
        use crate::local::cloud::state;

        let dir = tempfile::tempdir().unwrap();
        let paths = Paths::at(dir.path().join(".writ"));
        paths.ensure_dirs().unwrap();
        let v = crate::local::vault::Vault::load_or_create(&paths.root, false).unwrap();
        let db = crate::local::db::open(&paths.db(), &v.db_key_hex()).await.unwrap();

        // First boot as account A: unstamped DB → adopt A as owner, no error.
        assert!(state::profile_owner(&db).await.unwrap().is_none(), "precondition: unstamped");
        assert_profile_owner(&db, "acct_A").await.expect("first boot adopts the current profile");
        assert_eq!(state::profile_owner(&db).await.unwrap().as_deref(), Some("acct_A"));

        // Re-boot as the SAME account A → matches, no error, owner unchanged.
        assert_profile_owner(&db, "acct_A").await.expect("same-profile re-boot is fine");
        assert_eq!(state::profile_owner(&db).await.unwrap().as_deref(), Some("acct_A"));

        // Boot the SAME DB under account B → isolation violation (fail closed).
        let err = assert_profile_owner(&db, "acct_B").await.expect_err("cross-account boot must fail");
        assert!(
            matches!(err, LocalError::IsolationViolation(_)),
            "mismatch must be an IsolationViolation, got {err:?}"
        );
        // The stamp is NOT overwritten by the rejected boot.
        assert_eq!(state::profile_owner(&db).await.unwrap().as_deref(), Some("acct_A"));
    }

    /// The `local` (no-account) profile must never carry a `LinkState`. A legacy flat-layout build
    /// wrote one there on link; boot reconciliation must clear that residue, otherwise the desktop
    /// gate reads the ghost account as `logged_out` and traps the "continue without an account" user
    /// on the login screen forever. Runs on the default `local` profile (`WRIT_PROFILE` unset).
    #[cfg(feature = "cloud")]
    #[tokio::test]
    async fn reconcile_clears_stale_link_state_on_local_profile() {
        use crate::local::cloud::state::LinkState;
        use crate::local::cloud::token;
        assert_eq!(token::active_profile(), token::LOCAL_PROFILE, "test assumes the local profile");

        let dir = tempfile::tempdir().unwrap();
        let paths = Paths::at(dir.path().join(".writ"));
        paths.ensure_dirs().unwrap();
        let v = crate::local::vault::Vault::load_or_create(&paths.root, false).unwrap();
        let db = crate::local::db::open(&paths.db(), &v.db_key_hex()).await.unwrap();

        // Legacy residue: a LinkState persisted into the base/local home by an old flat-layout build.
        LinkState {
            account_id: "acct_legacy".into(),
            email: "ghost@example.com".into(),
            cloud_base_url: "https://cloud.example.com/".into(),
            scopes: vec![],
            linked_at: Some(chrono::Utc::now()),
            language: None,
        }
        .save(&db)
        .await
        .unwrap();
        assert!(LinkState::load(&db).await.unwrap().is_some(), "precondition: ghost present");

        // Boot reconciliation on the `local` profile clears it, self-healing the DB.
        reconcile_profile_link_state(&db).await;
        assert!(
            LinkState::load(&db).await.unwrap().is_none(),
            "stale LinkState must be cleared on the local profile"
        );
    }
}
