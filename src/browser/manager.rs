use std::collections::HashMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use anyhow::Result;
use tokio::sync::{Mutex, OwnedSemaphorePermit, Semaphore};

use crate::config::env::AppConfig;
use super::context::{build_launch_args, Fingerprint};
use super::stealth;

/// The bundled Chromium executable, when this build ships one and the shell exported it.
///
/// Feature-gated by construction rather than by convenience: a bundled browser is a **desktop**
/// concept. The cloud agent ships no browser (it uses whatever the fleet image installed), so on the
/// default build this is always `None` and every launch path behaves exactly as it did before —
/// which is what keeps the cloud build byte-clean of the local backend.
fn bundled_chromium_exe() -> Option<std::path::PathBuf> {
    #[cfg(feature = "local")]
    {
        crate::local::runtime_setup::bundled_chromium_exe()
    }
    #[cfg(not(feature = "local"))]
    {
        None
    }
}

/// Default ceiling on concurrently-LIVE browser contexts on one manager.
///
/// This is the LAST-RESORT bound, not the tuned one: the local/fleet builds call
/// [`BrowserManager::set_context_limit`] with a value derived from the resource governor
/// (`GovernorConfig::max_browser_contexts`), which is what actually sizes a desktop or fleet worker.
/// The default is deliberately the same `50` ceiling the fleet capacity detector clamps to, so a
/// build that never configures it (the managed cloud agent) behaves exactly as it did before this
/// bound existed — bounded, but not newly throttled.
pub const DEFAULT_MAX_LIVE_CONTEXTS: usize = 50;

/// How long a context request waits for a free slot before failing.
///
/// A wait is normal (another run is finishing); an unbounded wait is not. If every slot is held for
/// longer than this, either the machine is genuinely saturated or a context leaked, and both cases
/// must surface as a clear, attributable error rather than a task that hangs until the coordinator's
/// own timeout fires and redispatches the work.
const CONTEXT_SLOT_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(120);

/// How often the per-context slot watcher re-checks whether its context has closed. Small enough
/// that a freed slot is reusable promptly, large enough that `limit` sleeping tasks cost nothing.
const CONTEXT_SLOT_POLL: std::time::Duration = std::time::Duration::from_millis(250);

/// Resolve the Playwright driver override into the PROCESS ENVIRONMENT — exactly once, and from a
/// SYNCHRONOUS context.
///
/// ## Why this is not inline in `BrowserManager::initialize`
/// It used to be. `initialize` is `async` and runs on a multi-thread tokio runtime, so the two
/// `std::env::set_var` calls were unsynchronized writes to the libc `environ` block while other
/// worker threads could be in `getenv` — genuine undefined behaviour (and, because `initialize` can be
/// entered from several tasks, a write/write race with itself). Rust 1.80+ marks `set_var` `unsafe`
/// for precisely this reason. This is the one place the crate violated its otherwise `unsafe`-free
/// property in spirit.
///
/// The vendored `playwright-rs` resolver only reads these values from the environment (there is no
/// config API to pass them through), so the env write cannot be avoided — but it CAN be moved to
/// process start, before any runtime or worker thread exists. Call this at the top of `main`, before
/// building the tokio runtime. It is idempotent: the `OnceLock` makes the write happen at most once
/// per process, so even a late first call cannot race a second one.
///
/// ## What it does
/// Prefer patchright's STEALTH driver. The vendored playwright-rs resolver honors
/// PLAYWRIGHT_NODE_EXE/CLI_JS ahead of its bundled VANILLA driver, so pointing them at patchright
/// makes every CDP interaction stealthy: no Runtime.enable → not flagged by anti-bot AND no
/// console/runtime event flood (the cause of huge per-action latency). If patchright isn't installed,
/// or an operator already set the override, we leave it and fall back to the bundled driver.
/// `WRIT_DISABLE_PATCHRIGHT=1` forces the bundled VANILLA driver (for A/B testing whether patchright's
/// Runtime.enable suppression breaks the expose_function bridge / bindingCall delivery).
///
/// ## The relocation fallback
/// "The bundled driver" is a COMPILE-TIME ABSOLUTE PATH into the build machine's `target/` or
/// `~/.cache/playwright-rs-driver/`. A binary that is moved off that machine — a release download,
/// the container image's runtime stage — resolves it to a path that does not exist, and the first
/// browser launch fails with `ServerNotFound`. So when neither an operator override nor patchright
/// supplies a driver, fall back to one shipped NEXT TO the executable
/// ([`install::find_sibling_driver`]) before leaving the process to discover the gap at launch time.
/// Both are written into the same `PLAYWRIGHT_NODE_EXE`/`PLAYWRIGHT_CLI_JS` pair — deliberately not
/// `PLAYWRIGHT_DRIVER_PATH`, which the vendored resolver ranks ABOVE them and would let a vanilla
/// sibling driver silently shadow patchright's stealth one.
pub fn init_driver_env() {
    static DONE: std::sync::OnceLock<()> = std::sync::OnceLock::new();
    DONE.get_or_init(|| {
        // `PLAYWRIGHT_DRIVER_PATH` outranks everything this function can set, so an operator who
        // pinned one has already decided; touching the pair below would be a no-op at best.
        if std::env::var_os("PLAYWRIGHT_DRIVER_PATH").is_some()
            || std::env::var_os("PLAYWRIGHT_NODE_EXE").is_some()
        {
            return; // operator override already in place
        }

        let disable_patchright = std::env::var_os("WRIT_DISABLE_PATCHRIGHT").is_some();
        if disable_patchright {
            tracing::warn!("WRIT_DISABLE_PATCHRIGHT set — using vanilla Playwright (no stealth)");
        } else if let Some((node, cli)) = crate::browser::install::find_patchright_driver() {
            std::env::set_var("PLAYWRIGHT_NODE_EXE", &node);
            std::env::set_var("PLAYWRIGHT_CLI_JS", &cli);
            tracing::info!(
                driver = %node.display(),
                "Using patchright stealth driver (Runtime.enable suppressed)"
            );
            return;
        } else {
            tracing::warn!(
                "patchright driver not found — falling back to vanilla Playwright \
                 (DETECTABLE by anti-bot + slower). Install with `patchright install` \
                 (or set WRIT_PATCHRIGHT_DRIVER)."
            );
        }

        // Vanilla path. Prefer a driver that travelled with this binary over the compile-time one,
        // which only exists on the machine that built it.
        match crate::browser::install::find_sibling_driver() {
            Some((node, cli)) => {
                std::env::set_var("PLAYWRIGHT_NODE_EXE", &node);
                std::env::set_var("PLAYWRIGHT_CLI_JS", &cli);
                tracing::info!(
                    driver = %node.display(),
                    "Using the Playwright driver shipped alongside this binary"
                );
            }
            None => tracing::debug!(
                "no sibling Playwright driver found — relying on the compile-time bundled path \
                 (valid only on the machine that built this binary)"
            ),
        }
    });
}

/// Reduce a proxy `server` string to the only part that is safe to log: `scheme://host[:port]`.
///
/// The value comes straight from caller-supplied JSON (a persona's BYO proxy) and the
/// `http://user:pass@host:port` form is what a user pastes from a proxy vendor's dashboard. The
/// sink-level redactor now masks URL userinfo too, but the credential must not be handed to the
/// formatter in the first place. Falls back to `<unparseable-proxy>` rather than echoing the raw
/// string, so a value that is not a URL at all can't leak by accident.
/// Redact a proxy server URL down to host:port for logs (credentials in the userinfo of a
/// proxy URL must never be logged). `pub(crate)` so the recorder can log which egress a
/// session was routed through without re-implementing the redaction.
pub(crate) fn proxy_endpoint_for_log(server: &str) -> String {
    // Playwright accepts a bare `host:port` (no scheme) too. We cannot simply try `Url::parse` first
    // and fall back: `bob:pass@host:3128` parses "successfully" as scheme `bob` with no host, which
    // would report `<unparseable-proxy>` for a perfectly valid credential-bearing proxy string. So key
    // off the `://` separator, which is what actually distinguishes the two forms.
    let parsed = if server.contains("://") {
        url::Url::parse(server)
    } else {
        url::Url::parse(&format!("http://{server}"))
    };
    match parsed {
        Ok(u) => match u.host_str() {
            Some(host) => match u.port() {
                Some(port) => format!("{}://{host}:{port}", u.scheme()),
                None => format!("{}://{host}", u.scheme()),
            },
            None => "<unparseable-proxy>".to_string(),
        },
        Err(_) => "<unparseable-proxy>".to_string(),
    }
}

pub struct BrowserManager {
    pw: Arc<Mutex<Option<playwright_rs::Playwright>>>,
    warm_browser: Arc<Mutex<Option<playwright_rs::Browser>>>,
    /// The headless mode the warm browser was last launched in. The warm browser
    /// is shared, so a workflow that requests a DIFFERENT mode than this triggers a
    /// relaunch (honors a workflow's per-run headless override). None until first launch.
    warm_headless: Arc<Mutex<Option<bool>>>,
    config: Arc<AppConfig>,
    /// Baseline storage state (cookies + localStorage origins) snapshotted from an
    /// uploaded Chrome profile. Applied to every stealth context so each session
    /// looks like a returning user (anti-bot) and inherits baseline auth.
    /// 1:1 with Python AutomationEngine._baseline_storage_state.
    baseline_storage_state: Arc<Mutex<Option<playwright_rs::StorageState>>>,
    /// Whether baseline capture has been attempted (so we only try once).
    baseline_captured: Arc<Mutex<bool>>,
    /// ADMISSION for context creation — the one choke point every entry path shares.
    ///
    /// Before this existed, `grep 'Semaphore\|permit\|max_sessions' src/browser/manager.rs` returned
    /// nothing: the resource governor bounded *engine runs*, but raw wire `execute_workflow`, crawl
    /// shards, streaming sessions, concierge/browse sessions and monitor checks all called
    /// `create_stealth_context*` on this manager DIRECTLY, with no ceiling anywhere. A worker
    /// advertising 16 sessions could therefore have 16 shards × the shard concurrency constant of
    /// in-flight page work plus browser fallbacks, and OOM. Bounding it HERE means the ceiling holds
    /// regardless of which entry point asked, including future ones.
    ///
    /// A permit is acquired before the context is created and released when that context is observed
    /// closed (see `spawn_slot_watcher`), so the count tracks LIVE contexts rather than calls.
    context_slots: Arc<Semaphore>,
    /// The live value of the context ceiling, so [`Self::set_context_limit`] can compute the delta to
    /// add/forget on `context_slots` (a `Semaphore` has no "resize" operation).
    context_limit: Arc<AtomicUsize>,
    /// How long [`Self::acquire_context_slot`] waits before giving up, in milliseconds. A field rather
    /// than a bare constant purely so the saturation path is unit-testable in seconds instead of
    /// minutes — production always uses [`CONTEXT_SLOT_TIMEOUT`].
    slot_timeout_ms: Arc<std::sync::atomic::AtomicU64>,
}

impl BrowserManager {
    pub fn new(config: Arc<AppConfig>) -> Self {
        Self {
            pw: Arc::new(Mutex::new(None)),
            warm_browser: Arc::new(Mutex::new(None)),
            warm_headless: Arc::new(Mutex::new(None)),
            config,
            baseline_storage_state: Arc::new(Mutex::new(None)),
            baseline_captured: Arc::new(Mutex::new(false)),
            context_slots: Arc::new(Semaphore::new(DEFAULT_MAX_LIVE_CONTEXTS)),
            context_limit: Arc::new(AtomicUsize::new(DEFAULT_MAX_LIVE_CONTEXTS)),
            slot_timeout_ms: Arc::new(std::sync::atomic::AtomicU64::new(
                CONTEXT_SLOT_TIMEOUT.as_millis() as u64,
            )),
        }
    }

    /// Test-only: shorten the slot-acquisition deadline so the at-capacity path can be exercised in
    /// milliseconds. Never called outside tests.
    #[cfg(test)]
    fn set_slot_timeout_for_test(&self, d: std::time::Duration) {
        self.slot_timeout_ms
            .store(d.as_millis() as u64, Ordering::SeqCst);
    }

    /// Set the ceiling on concurrently-live browser contexts.
    ///
    /// Called once at engine construction with the governor-derived value
    /// (`GovernorConfig::max_browser_contexts`) so the number a coordinator schedules against and the
    /// number the machine can actually host are the same number. Clamped to at least 1 — a zero
    /// ceiling would wedge every context request.
    ///
    /// Safe to call while contexts are live: the delta is applied with `add_permits` /
    /// `forget_permits`, so LOWERING the ceiling never revokes a permit already held — it just means
    /// the next releases are absorbed instead of handed on.
    pub fn set_context_limit(&self, limit: usize) {
        let limit = limit.max(1);
        let prev = self.context_limit.swap(limit, Ordering::SeqCst);
        match limit.cmp(&prev) {
            std::cmp::Ordering::Greater => self.context_slots.add_permits(limit - prev),
            std::cmp::Ordering::Less => {
                // Best-effort shrink: `forget_permits` removes only what is currently AVAILABLE and
                // returns how many it actually took. Anything it could not take stays outstanding and
                // is simply not re-added when the holder releases — the ceiling converges downward as
                // live contexts close, without ever yanking a slot from a running context.
                let _ = self.context_slots.forget_permits(prev - limit);
            }
            std::cmp::Ordering::Equal => {}
        }
        tracing::info!(max_live_contexts = limit, "browser context ceiling set");
    }

    /// The configured ceiling on concurrently-live contexts.
    pub fn context_limit(&self) -> usize {
        self.context_limit.load(Ordering::SeqCst).max(1)
    }

    /// Free context slots right now (observability / health readouts).
    pub fn available_context_slots(&self) -> usize {
        self.context_slots.available_permits()
    }

    /// Wait (bounded) for a context slot. `Err` means the machine is at its context ceiling — the
    /// caller must FAIL rather than create the context, so the pressure is reported instead of
    /// turning into memory growth.
    async fn acquire_context_slot(&self) -> Result<OwnedSemaphorePermit> {
        let wait = std::time::Duration::from_millis(
            self.slot_timeout_ms.load(Ordering::SeqCst).max(1),
        );
        match tokio::time::timeout(wait, self.context_slots.clone().acquire_owned()).await {
            Ok(Ok(permit)) => Ok(permit),
            // The semaphore is never closed in normal operation; treat it as unavailable.
            Ok(Err(_)) => anyhow::bail!("browser context pool is closed"),
            Err(_) => {
                let limit = self.context_limit();
                tracing::error!(
                    max_live_contexts = limit,
                    waited_ms = wait.as_millis(),
                    "no browser context slot became free — refusing to create another context"
                );
                anyhow::bail!(
                    "at browser context capacity ({limit} live contexts) — no slot freed in {}ms",
                    wait.as_millis()
                )
            }
        }
    }

    /// Hold `permit` until `context` is observed closed (or the browser goes away), then release it.
    ///
    /// Polling rather than `context.on_close` on purpose: the close EVENT only arrives while the
    /// driver connection is healthy, so a browser that died would strand the permit forever and
    /// convert a leak into a hard stall. `is_closed()` plus a browser-liveness check covers both the
    /// ordinary `close()` and browser death, and self-heals with no bookkeeping.
    fn spawn_slot_watcher(
        permit: OwnedSemaphorePermit,
        context: playwright_rs::BrowserContext,
        browser: playwright_rs::Browser,
    ) {
        tokio::spawn(async move {
            use playwright_rs::server::channel_owner::ChannelOwner as _;
            // Bound to `_permit` so it is released exactly when this task ends.
            let _permit = permit;
            let guid = context.guid().to_string();
            loop {
                tokio::time::sleep(CONTEXT_SLOT_POLL).await;
                if context.is_closed() || !browser.is_connected() {
                    // Drop this context's device init script alongside its slot, so the
                    // registry tracks LIVE contexts and cannot grow without bound on a
                    // long-lived agent.
                    super::stealth::forget_device(&guid);
                    return;
                }
            }
        });
    }

    /// The Chromium argv for every launch on this manager: the always-on hardened base plus any of
    /// the DANGEROUS opt-in flags (sandbox / TLS / same-origin) the user enabled in Settings →
    /// Runtime. Read from `self.config` (fixed for the daemon session), so a change is applied on the
    /// next engine restart — matching the `browser.headless` lifecycle.
    fn launch_args(&self) -> Vec<String> {
        build_launch_args(
            self.config.disable_sandbox,
            self.config.ignore_certificate_errors,
            self.config.disable_web_security,
        )
    }

    pub async fn initialize(&self) -> Result<()> {
        // Driver-path env resolution is HOISTED out of the async path — see `init_driver_env`. This
        // call is a no-op once the process has primed it (which every binary we own does BEFORE the
        // tokio runtime exists).
        init_driver_env();

        let mut pw_lock = self.pw.lock().await;
        if pw_lock.is_none() {
            let pw = playwright_rs::Playwright::launch().await
                .map_err(|e| anyhow::anyhow!("Playwright init failed: {}", e))?;
            *pw_lock = Some(pw);
            tracing::info!("Playwright initialized");
        }
        drop(pw_lock);

        // Capture the baseline storage state from an uploaded profile (best-effort).
        self.capture_baseline().await;
        Ok(())
    }

    /// Find an uploaded browser profile directory for the baseline (optional).
    /// 1:1 port of Python AutomationEngine._find_uploaded_profile (lines 684-711).
    /// Checks, in order:
    ///   1. config.baseline_profile_dir (BASELINE_PROFILE_DIR env var)
    ///   2. /app/baseline_profile (Docker standard path)
    ///   3. ./baseline_profile (local dev, relative to cwd)
    /// Returns the path only if it exists and contains non-hidden files.
    fn find_uploaded_profile(&self) -> Option<String> {
        let mut candidates: Vec<String> = Vec::new();
        if let Some(ref dir) = self.config.baseline_profile_dir {
            if !dir.is_empty() {
                candidates.push(dir.clone());
            }
        }
        candidates.push("/app/baseline_profile".to_string());
        candidates.push("./baseline_profile".to_string());

        for cand in candidates {
            let path = std::path::Path::new(&cand);
            if !path.is_dir() {
                continue;
            }
            // Require at least one non-hidden entry (matches Python real_files check).
            let has_real_files = std::fs::read_dir(path)
                .map(|entries| {
                    entries.flatten().any(|e| {
                        e.file_name()
                            .to_str()
                            .map(|n| !n.starts_with('.'))
                            .unwrap_or(false)
                    })
                })
                .unwrap_or(false);
            if has_real_files {
                return Some(cand);
            }
        }
        None
    }

    /// Capture the baseline storage state. 1:1 port of Python _start_playwright_browser
    /// baseline capture (lines 928-965). If an uploaded profile exists, launch a temp
    /// persistent context to import its cookies/storage, snapshot storage_state(), and
    /// close it. Otherwise leave baseline empty (clean baseline).
    async fn capture_baseline(&self) {
        {
            let mut captured = self.baseline_captured.lock().await;
            if *captured {
                return;
            }
            *captured = true;
        }

        // Resolve the baseline SOURCE, honoring the opt-in local-Chrome setting:
        //   * `use_local_chrome` (Settings → Runtime, default OFF) → copy the user's REAL Chrome
        //     profile into the secure, per-account work dir (`~/.writ/.browser_profile`, 0700) and
        //     seed the baseline from it;
        //   * otherwise → an explicitly-provided uploaded/cloud baseline profile, if present;
        //   * otherwise → a clean generated baseline (the default — no real cookies imported).
        let profile_dir = if self.config.use_local_chrome {
            match crate::browser::chrome_profile::copy_chrome_profile() {
                Ok(dir) => {
                    tracing::info!(profile = %dir.display(), "Seeding baseline from local Chrome (opt-in)");
                    dir.to_string_lossy().to_string()
                }
                Err(e) => {
                    tracing::warn!(error = %e, "Could not copy local Chrome — using a clean baseline");
                    return;
                }
            }
        } else {
            match self.find_uploaded_profile() {
                Some(dir) => dir,
                None => {
                    tracing::info!("Using a clean generated baseline (local Chrome import is off)");
                    return;
                }
            }
        };

        tracing::info!(profile = %profile_dir, "Loading baseline from profile");

        let pw_lock = self.pw.lock().await;
        let Some(pw) = pw_lock.as_ref() else {
            tracing::warn!("Playwright not initialized — skipping baseline capture");
            return;
        };

        let args: Vec<String> = self.launch_args();
        let mut opts_builder = playwright_rs::BrowserContextOptions::builder()
            .headless(true)
            .args(args)
            // File assets (§6.2): accept downloads so the `download` event fires (vs the
            // browser handling/blocking them natively) — needed for wait_for_download
            // capture. Set on every create_stealth_context_* path (recording + replay).
            .accept_downloads(true);
        // Drive the browser we ship, when we ship one. Without an explicit executablePath the driver
        // resolves whatever sits at its OWN pinned-revision path, so the baseline could be captured
        // from a different browser build than the one the app reports and replays with.
        if let Some(exe) = bundled_chromium_exe() {
            opts_builder = opts_builder.executable_path(exe.to_string_lossy().into_owned());
        }
        let opts = opts_builder.build();

        match pw.chromium().launch_persistent_context_with_options(profile_dir, opts).await {
            Ok(temp_ctx) => {
                // Warm the context (navigate a page to about:blank) before snapshot.
                let pages = temp_ctx.pages();
                if let Some(p) = pages.first() {
                    let _ = p.goto("about:blank", None).await;
                }
                match temp_ctx.storage_state().await {
                    Ok(state) => {
                        let cookie_count = state.cookies.len();
                        *self.baseline_storage_state.lock().await = Some(state);
                        tracing::info!(cookies = cookie_count, "Baseline storage state captured");
                    }
                    Err(e) => {
                        tracing::warn!(error = %e, "Failed to snapshot baseline storage state");
                    }
                }
                let _ = temp_ctx.close().await;
            }
            Err(e) => {
                tracing::warn!(error = %e, "Failed to launch baseline profile context");
            }
        }
    }

    pub async fn ensure_warm_browser(&self) -> Result<()> {
        // Default callers (recording, monitoring) use the agent's global headless.
        self.ensure_warm_browser_with(self.config.headless).await
    }

    /// Ensure the warm browser is running in the requested headless mode.
    ///
    /// The warm browser is shared across runs, so when a workflow requests a
    /// DIFFERENT mode than the one the warm browser was launched in, we relaunch it
    /// in the requested mode. Without this a workflow toggled to headed kept
    /// running in the global (headless) mode the warm browser was started with —
    /// 1:1 with the Python/desktop agents honoring a per-run headless override.
    pub async fn ensure_warm_browser_with(&self, headless: bool) -> Result<()> {
        // Ensure the Playwright driver is initialized before launching a browser.
        // The local daemon defers ALL browser bootstrap to first use — runs
        // (`real.rs`), recording (`/ws/record`) and monitoring all funnel through
        // here — and nothing else calls `initialize()`, so this is the single
        // point that guarantees the driver is up. `initialize()` is idempotent
        // (it no-ops once `self.pw` is set), so this is a cheap check after warmup.
        if self.pw.lock().await.is_none() {
            self.initialize().await?;
        }

        let mut browser_lock = self.warm_browser.lock().await;
        let mut mode_lock = self.warm_headless.lock().await;

        if let Some(ref browser) = *browser_lock {
            if browser.is_connected() && *mode_lock == Some(headless) {
                return Ok(());
            }
            if *mode_lock != Some(headless) {
                tracing::info!(
                    from = ?*mode_lock, to = headless,
                    "Headless mode changed for this run — relaunching warm browser"
                );
            } else {
                tracing::warn!("Warm browser disconnected, relaunching");
            }
            // Drop the existing warm browser before relaunching in the new mode.
            if let Some(browser) = browser_lock.take() {
                let _ = browser.close().await;
            }
        }

        let pw_lock = self.pw.lock().await;
        let pw = pw_lock
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("Playwright not initialized — call initialize() first"))?;

        let chromium = pw.chromium();

        let args: Vec<String> = self.launch_args();

        // Prefer the browser WE ship. Two reasons this matters beyond tidiness:
        //   * `channel("chrome")` launches the user's installed Google Chrome — a build we do not
        //     pin, do not test against, and which may not even be present. The bundled browser was
        //     never actually driven on this path.
        //   * without an explicit executablePath the driver falls back to its OWN pinned-revision
        //     directory, so `detect_chromium()` could report `bundled` while a different binary was
        //     the one really running.
        // `channel` and `executablePath` are mutually exclusive in Playwright, so they are set in
        // alternation, never together.
        let bundled = bundled_chromium_exe();
        let base_opts = playwright_rs::LaunchOptions::new()
            .headless(headless)
            .args(args.clone());
        let launch_opts = match &bundled {
            Some(exe) => base_opts.executable_path(exe.to_string_lossy().into_owned()),
            None => base_opts.channel("chrome".to_string()),
        };

        let browser = match chromium.launch_with_options(launch_opts).await {
            Ok(b) => {
                match &bundled {
                    Some(exe) => tracing::info!(headless, browser = %exe.display(), "Warm browser launched (bundled)"),
                    None => tracing::info!(headless, "Warm browser launched (chrome channel)"),
                }
                b
            }
            Err(e) => {
                // The fallback drops BOTH channel and executablePath, letting the driver use its own
                // pinned revision. That is a genuine last resort — if the bundled binary failed to
                // launch, this may well be a different browser build than the one we ship.
                tracing::warn!(error = %e, bundled = bundled.is_some(), "Preferred browser failed to launch, falling back to the driver's default Chromium");
                let fallback = playwright_rs::LaunchOptions::new()
                    .headless(headless)
                    .args(args);
                chromium.launch_with_options(fallback).await
                    .map_err(|e| anyhow::anyhow!("Browser launch failed: {}", e))?
            }
        };

        *browser_lock = Some(browser);
        *mode_lock = Some(headless);
        Ok(())
    }

    /// Create a stealth browser context with a RANDOM fingerprint (1:1 with
    /// Python). For ad-hoc/interactive use (e.g. manual recording) where there is
    /// no persisted auth to stay consistent with.
    pub async fn create_stealth_context(
        &self,
    ) -> Result<(playwright_rs::BrowserContext, playwright_rs::Page)> {
        let (ctx, page, _fp) = self.create_stealth_context_with_fingerprint(None).await?;
        Ok((ctx, page))
    }

    /// Like `create_stealth_context` but lets the caller pin a per-run BYO persona
    /// proxy (resolved from the consumer's Persona at dispatch and carried as the
    /// reserved `__proxy__` key inside the run credentials). No-op when None →
    /// falls back to the browser-level (env) proxy, exactly like the proxy-less
    /// `create_stealth_context`. Parity with Python `_create_stealth_context(proxy=)`.
    pub async fn create_stealth_context_with_proxy(
        &self,
        proxy_override: Option<playwright_rs::protocol::ProxySettings>,
    ) -> Result<(playwright_rs::BrowserContext, playwright_rs::Page)> {
        let (ctx, page, _fp) = self
            .create_stealth_context_full_proxy(None, None, proxy_override)
            .await?;
        Ok((ctx, page))
    }

    /// Create a stealth browser context.
    ///
    /// 1:1 with Python automation_engine._start_playwright_browser context_opts
    /// (lines 861-885): viewport 1920x1080, the full extra_http_headers set (with
    /// FIXED sec-ch-ua / sec-ch-ua-platform), plus the captured baseline storage
    /// state and proxy.
    ///
    /// `fingerprint`:
    ///   - `Some(fp)` → reuse a previously-captured fingerprint (a "warm" session
    ///     stays a returning user so restored auth is not invalidated).
    ///   - `None` → random user_agent/locale/timezone (a fresh session).
    ///
    /// Returns the fingerprint actually used so the caller can persist it.
    pub async fn create_stealth_context_with_fingerprint(
        &self,
        fingerprint: Option<Fingerprint>,
    ) -> Result<(playwright_rs::BrowserContext, playwright_rs::Page, Fingerprint)> {
        // Default viewport (1920x1080) — workflow/automation parity with Python.
        // No per-run BYO proxy override → browser-level (env) proxy applies
        // (create_stealth_context_full delegates to *_proxy with None).
        self.create_stealth_context_full(fingerprint, None)
            .await
    }

    /// Like `create_stealth_context_with_fingerprint` but lets the caller pin a
    /// per-run BYO persona proxy. `proxy_override`: `Some(p)` egresses this context
    /// through the consumer's residential proxy (a context-level proxy that
    /// overrides the browser-level env proxy); `None` keeps the env proxy. Parity
    /// with Python `_create_stealth_context(fingerprint=, proxy=)`.
    pub async fn create_stealth_context_with_fingerprint_proxy(
        &self,
        fingerprint: Option<Fingerprint>,
        proxy_override: Option<playwright_rs::protocol::ProxySettings>,
    ) -> Result<(playwright_rs::BrowserContext, playwright_rs::Page, Fingerprint)> {
        self.create_stealth_context_full_proxy(fingerprint, None, proxy_override)
            .await
    }

    /// Like `create_stealth_context_with_fingerprint` but lets the caller pin the
    /// viewport. Workflows pass None to keep the 1920x1080 automation parity.
    ///
    /// Monitoring passes the size a target's `visual_region` zones were DRAWN at
    /// (`monitor::visual_region::context_viewport`) so the page lays out the way it
    /// did in the recorder preview and the zone clips the same pixels. It is NOT a
    /// fixed 1280x800: this context runs the recorder at 1920x1080, so pinning
    /// 1280x800 clipped every recorder-drawn zone ~1.5x off and at the wrong aspect
    /// ratio.
    pub async fn create_stealth_context_full(
        &self,
        fingerprint: Option<Fingerprint>,
        viewport: Option<playwright_rs::Viewport>,
    ) -> Result<(playwright_rs::BrowserContext, playwright_rs::Page, Fingerprint)> {
        // No per-run BYO proxy override → browser-level (env) proxy applies.
        self.create_stealth_context_full_proxy(fingerprint, viewport, None)
            .await
    }

    /// Like `create_stealth_context_full` but lets the caller pin a per-run BYO
    /// persona proxy.
    ///
    /// `proxy_override`: a per-run BYO persona proxy resolved at dispatch and
    /// carried as the reserved `__proxy__` credential. When `Some`, it is applied
    /// to THIS context and takes precedence over the browser-level env proxy
    /// (`self.proxy_settings()`); when `None`, the env proxy (if any) applies.
    /// 1:1 with Python `_create_stealth_context(proxy=)` (a context-level proxy
    /// overrides the browser-level env `PROXY_SERVER`).
    pub async fn create_stealth_context_full_proxy(
        &self,
        fingerprint: Option<Fingerprint>,
        viewport: Option<playwright_rs::Viewport>,
        proxy_override: Option<playwright_rs::protocol::ProxySettings>,
    ) -> Result<(playwright_rs::BrowserContext, playwright_rs::Page, Fingerprint)> {
        // Lazily launch the warm browser the first time a context is requested
        // without one. The engine warms Chromium lazily "on first run", but the
        // recorder opens a session over `/ws/record` BEFORE any run has warmed it,
        // so without this it failed with "No warm browser". We only launch when
        // NONE exists — we never relaunch/retoggle an already-warm browser here, so
        // a run that pinned a headed/headless mode via `ensure_warm_browser_with()`
        // is left untouched (calling `ensure_warm_browser()` unconditionally would
        // clobber that mode back to the agent default).
        if self.warm_browser.lock().await.is_none() {
            self.ensure_warm_browser().await?;
        }

        // ADMISSION: claim a live-context slot BEFORE touching the browser. Taken here rather than
        // inside the `warm_browser` lock below, because a caller that waits for a slot must not hold
        // the browser mutex while it waits (that would block warm-browser relaunch and every other
        // context request behind it). The permit is handed to a watcher after the context exists; any
        // early return between here and there drops it, releasing the slot.
        let slot = self.acquire_context_slot().await?;

        let browser_lock = self.warm_browser.lock().await;
        let browser = browser_lock
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("No warm browser — call ensure_warm_browser() first"))?;

        // Reuse the restored fingerprint or roll a fresh one whose UA matches the
        // REAL browser's Chrome major version (avoids a stale Chrome/120 advertised
        // on a newer engine). Restored fingerprints are kept as-is (returning user).
        let chrome_major = crate::browser::context::chrome_major_from_version(browser.version());
        let fingerprint = fingerprint
            .unwrap_or_else(|| Fingerprint::random_for_chrome_major(&chrome_major));

        // Context-safe headers, with UA client hints (sec-ch-ua version + platform)
        // DERIVED from the chosen UA so they never contradict navigator.userAgent.
        // The browser sets Accept / Accept-Encoding / Upgrade-Insecure-Requests and
        // the Sec-Fetch-* headers PER REQUEST; forcing them context-wide stamps
        // `sec-fetch-mode: navigate` onto sub-resource requests — an invalid
        // combination newer Chrome (148+) rejects with net::ERR_INVALID_ARGUMENT
        // (pages load with no CSS/JS).
        // Accept-Language follows the identity's exit country when one was resolved
        // (Fingerprint::for_identity); empty keeps the neutral en-US default.
        let extra_headers: HashMap<String, String> =
            crate::browser::context::build_stealth_headers_lang(
                &fingerprint.user_agent,
                &fingerprint.accept_language,
            );

        // Build context options — exact Python context_opts (lines 861-885) plus the
        // captured baseline storage state and proxy if configured.
        let baseline = self.baseline_storage_state.lock().await.clone();
        // Prefer the per-run BYO persona proxy (context-level) over the
        // browser-level env proxy. The backend only ever sends `__proxy__` when
        // it is allowed (no creator-IP relay bound + not residential-intent), so
        // here we just apply whatever override we were given. Parity with Python.
        let proxy = match proxy_override {
            Some(p) => {
                tracing::info!(
                    // HOST:PORT only. `p.server` is unvalidated user JSON and users routinely paste
                    // `http://user:pass@proxy.host:8080` — logging it verbatim at INFO published the
                    // proxy credentials to the daemon log, journald and the diagnostics bundle.
                    endpoint = %proxy_endpoint_for_log(&p.server),
                    bypass = %p.bypass.clone().unwrap_or_default(),
                    has_credentials = p.username.is_some() || p.password.is_some(),
                    "Per-run BYO persona proxy applied to context"
                );
                Some(p)
            }
            None => self.proxy_settings(),
        };

        // Viewport precedence: an explicit caller pin (monitoring's visual-region size)
        // always wins; otherwise the identity's own device viewport (derived from its
        // screen, so window < screen stays true); otherwise the 1920x1080 default.
        // `unwrap_or`, not `unwrap_or_else`: the fallback is a couple of field reads and a small
        // struct literal, so there is nothing to defer and clippy rejects the closure.
        let effective_viewport = viewport.unwrap_or({
            match fingerprint.device.as_ref() {
                Some(d) => playwright_rs::Viewport {
                    width: d.viewport.width,
                    height: d.viewport.height,
                },
                None => playwright_rs::Viewport { width: 1920, height: 1080 },
            }
        });
        let mut builder = playwright_rs::BrowserContextOptions::builder()
            .viewport(effective_viewport)
            .user_agent(fingerprint.user_agent.clone())
            .locale(fingerprint.locale.clone())
            .timezone_id(fingerprint.timezone.clone())
            .color_scheme("light".to_string())
            // device_scale_factor stays 1.0 for every identity: device_identity pins
            // dpr 1 (screencast frames are captured at this scale and clicks are mapped
            // against a 1x frame), so this never contradicts the advertised device.
            .device_scale_factor(1.0)
            .has_touch(false)
            .is_mobile(false)
            .bypass_csp(false)
            // File assets (§6.2): accept downloads so a wait_for_download step can
            // capture the file the page produces (otherwise the browser handles the
            // download natively and the `download` event never fires). Applies to both
            // recording (on_download listener) and replay (expect_download).
            .accept_downloads(true)
            .extra_http_headers(extra_headers);
        if let Some(state) = baseline {
            builder = builder.storage_state(state);
        }
        if let Some(p) = proxy {
            builder = builder.proxy(p);
        }
        let context = browser.new_context_with_options(builder.build()).await
            .map_err(|e| anyhow::anyhow!("Context creation (with options) failed: {}", e))?;

        // Register this identity's DEVICE overrides against the context guid so every
        // stealth (re)injection on any of its pages stamps the matching
        // hardwareConcurrency / deviceMemory / navigator.platform / window.screen. No-op
        // when the identity pins no device (a real headed machine keeps real values).
        // Unregistered by the slot watcher when the context closes.
        {
            use playwright_rs::server::channel_owner::ChannelOwner as _;
            super::stealth::register_device(context.guid(), fingerprint.device.as_ref());
            if let Some(d) = fingerprint.device.as_ref() {
                tracing::info!(
                    platform = %d.platform,
                    screen = %format!("{}x{}", d.screen.width, d.screen.height),
                    cores = d.hardware_concurrency,
                    memory_gb = d.device_memory,
                    locale = %fingerprint.locale,
                    timezone = %fingerprint.timezone,
                    "Device identity applied to context"
                );
            }
        }

        // From here on the context EXISTS inside Chromium, so every failure path below must close it
        // — `BrowserContext` has no `Drop`, so returning `Err` with the handle would strand the
        // context (renderer + memory) for the life of the browser. The guard closes it on any early
        // `?`; it is disarmed once we hand the context to the caller.
        let mut ctx_guard = super::context::ContextCloseGuard::new(context.clone());

        // Release the admission slot when THIS context closes (whoever closes it), so the ceiling
        // tracks live contexts rather than calls. Handed off before the fallible steps below so a
        // failure there still releases via the guard's close → `is_closed()` → watcher exit.
        Self::spawn_slot_watcher(slot, context.clone(), browser.clone());

        // Install SSRF request blocker on all outbound requests.
        // Uses the async (tokio non-blocking) DNS variant so the blocking
        // `to_socket_addrs` lookup never stalls a tokio worker inside this
        // per-request callback. Per-request checks fail OPEN on DNS error
        // (navigation/entry targets use the fail-closed variant separately).
        let route_installed = context.route("**/*", |route: playwright_rs::Route| async move {
            let request = route.request();
            let url = request.url();
            if !crate::security::url_guard::is_url_safe_async(url).await {
                tracing::warn!(url = %url, "SSRF route block");
                route.abort(Some("blockedbyclient")).await?;
            } else {
                route.continue_(None).await?;
            }
            Ok(())
        }).await;
        if let Err(e) = route_installed {
            // SECURITY + hygiene: a context WITHOUT the SSRF blocker must never be handed out, and it
            // must not be left open either. Close it deterministically here.
            ctx_guard.close().await;
            return Err(anyhow::anyhow!("Route install failed: {}", e));
        }

        // Stealth is injected MANUALLY via page.evaluate (here + after every
        // navigation in navigation::goto / the framenavigated listeners), NOT via
        // context.add_init_script. This matches the Python reference's isolated
        // mode: add_init_script (Page.addScriptToEvaluateOnNewDocument) is both an
        // anti-bot CDP detection signature AND breaks DNS resolution on some
        // server Chromium builds. The stealth.js guard (`__stealth_injected`)
        // makes repeat evaluate calls idempotent and cheap.
        let page = match context.new_page().await {
            Ok(p) => p,
            Err(e) => {
                ctx_guard.close().await;
                return Err(anyhow::anyhow!("Page creation failed: {}", e));
            }
        };

        // Evaluate stealth on the first page (covers about:blank before first nav), with
        // THIS context's device overrides appended (registered just above).
        {
            use playwright_rs::server::channel_owner::ChannelOwner as _;
            let script = stealth::scripts_for_context(context.guid());
            let _: Result<serde_json::Value, _> = page.evaluate(&script, None::<&()>).await;
        }

        // The context is now the CALLER's to close (the engine/bridge close it on every exit path and
        // arm their own guard for the panic case). Disarm so this function's guard doesn't also close it.
        ctx_guard.disarm();

        tracing::debug!(
            user_agent = %fingerprint.user_agent,
            locale = %fingerprint.locale,
            timezone = %fingerprint.timezone,
            "Stealth context created"
        );

        Ok((context, page, fingerprint))
    }

    /// Build ProxySettings from config if a proxy server is configured.
    /// 1:1 with Python _start_playwright_browser proxy support.
    fn proxy_settings(&self) -> Option<playwright_rs::protocol::ProxySettings> {
        let server = self.config.proxy_server.as_ref().filter(|s| !s.is_empty())?;
        Some(playwright_rs::protocol::ProxySettings {
            server: server.clone(),
            bypass: None,
            username: self.config.proxy_username.clone().filter(|s| !s.is_empty()),
            password: self.config.proxy_password.clone().filter(|s| !s.is_empty()),
        })
    }

    pub async fn browser_ref(&self) -> Option<playwright_rs::Browser> {
        self.warm_browser.lock().await.clone()
    }

    /// Whether this agent runs headless by default.
    ///
    /// Drives whether a synthetic DEVICE signature is advertised: a headless run (cloud
    /// fleet / self-host server) has no real display and would otherwise leak the
    /// container's hardware, while a HEADED run is a real machine whose values are already
    /// real and coherent — faking them there would replace truth with a constant.
    pub fn is_headless(&self) -> bool {
        self.config.headless
    }

    /// Chrome major version of the warm browser ("120" when none is running yet), so a
    /// caller can build a UA whose advertised version matches the REAL engine before a
    /// context exists. Same derivation `create_stealth_context_full_proxy` uses.
    pub async fn chrome_major(&self) -> String {
        match self.warm_browser.lock().await.as_ref() {
            Some(b) => crate::browser::context::chrome_major_from_version(b.version()),
            None => "120".to_string(),
        }
    }

    pub async fn shutdown(&self) -> Result<()> {
        let mut browser_lock = self.warm_browser.lock().await;
        if let Some(browser) = browser_lock.take() {
            browser.close().await
                .map_err(|e| anyhow::anyhow!("Browser close failed: {}", e))?;
            tracing::info!("Warm browser closed");
        }

        let mut pw_lock = self.pw.lock().await;
        *pw_lock = None;
        tracing::info!("Playwright stopped");
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A pasted `http://user:pass@host:port` proxy must never reach a log line — only the endpoint.
    #[test]
    fn proxy_endpoint_log_drops_userinfo() {
        assert_eq!(
            proxy_endpoint_for_log("http://bob:s3cr3tPASS@proxy.example.com:8080"),
            "http://proxy.example.com:8080"
        );
        // No scheme (Playwright accepts bare host:port) still yields host:port, never credentials.
        assert_eq!(
            proxy_endpoint_for_log("bob:s3cr3tPASS@proxy.example.com:3128"),
            "http://proxy.example.com:3128"
        );
        // Credential-free values round-trip usefully.
        assert_eq!(proxy_endpoint_for_log("socks5://127.0.0.1:9050"), "socks5://127.0.0.1:9050");
        assert_eq!(proxy_endpoint_for_log("https://proxy.example.com"), "https://proxy.example.com");
        // Junk is reported as junk rather than echoed.
        assert_eq!(proxy_endpoint_for_log(""), "<unparseable-proxy>");

        for bad in ["http://bob:s3cr3tPASS@proxy.example.com:8080", "bob:s3cr3tPASS@h:1"] {
            assert!(
                !proxy_endpoint_for_log(bad).contains("s3cr3tPASS"),
                "password must not survive: {bad}"
            );
        }
    }

    /// `init_driver_env` is idempotent — the `OnceLock` guarantees at most one `environ` write per
    /// process, which is what removes the write/write race the async call site had.
    #[test]
    fn init_driver_env_is_idempotent() {
        init_driver_env();
        init_driver_env();
        init_driver_env();
    }

    /// A manager with no browser at all still exposes the context ceiling, so the admission bound is
    /// testable without Chromium.
    fn bare_manager() -> BrowserManager {
        BrowserManager::new(Arc::new(AppConfig::from_env()))
    }

    /// The default ceiling is the historical fleet clamp, so a build that never configures it (the
    /// managed cloud agent) is bounded without being newly throttled.
    #[test]
    fn default_context_limit_is_the_historical_ceiling() {
        let m = bare_manager();
        assert_eq!(m.context_limit(), DEFAULT_MAX_LIVE_CONTEXTS);
        assert_eq!(m.available_context_slots(), DEFAULT_MAX_LIVE_CONTEXTS);
    }

    /// `set_context_limit` resizes the semaphore in BOTH directions and clamps zero to one (a zero
    /// ceiling would wedge every context request).
    #[test]
    fn set_context_limit_resizes_both_ways_and_clamps() {
        let m = bare_manager();

        m.set_context_limit(4);
        assert_eq!(m.context_limit(), 4);
        assert_eq!(m.available_context_slots(), 4, "shrink removes available permits");

        m.set_context_limit(9);
        assert_eq!(m.context_limit(), 9);
        assert_eq!(m.available_context_slots(), 9, "grow adds permits");

        m.set_context_limit(0);
        assert_eq!(m.context_limit(), 1, "zero clamps to one usable slot");
        assert_eq!(m.available_context_slots(), 1);
    }

    /// The ceiling is a real bound: the Nth+1 concurrent acquisition WAITS rather than proceeding, and
    /// resolves as soon as a held slot is released. This is the invariant that stops an unbounded
    /// entry path (raw `execute_workflow`, a crawl shard) from fanning out contexts without limit.
    #[tokio::test]
    async fn context_slots_bound_concurrent_acquisition() {
        let m = bare_manager();
        m.set_context_limit(2);

        let a = m.acquire_context_slot().await.expect("slot 1");
        let b = m.acquire_context_slot().await.expect("slot 2");
        assert_eq!(m.available_context_slots(), 0, "ceiling reached");

        // A third request must PARK (not proceed, not error immediately).
        let fut = m.acquire_context_slot();
        tokio::pin!(fut);
        assert!(
            futures_util::poll!(&mut fut).is_pending(),
            "at the ceiling a context request waits for a slot"
        );

        // Releasing one slot lets it through.
        drop(b);
        let c = tokio::time::timeout(std::time::Duration::from_secs(1), fut)
            .await
            .expect("acquisition resolves once a slot frees")
            .expect("slot 3");

        drop(a);
        drop(c);
        assert_eq!(m.available_context_slots(), 2, "all slots released");
    }

    /// Saturation must FAIL LOUDLY, not hang: when no slot frees within the timeout the acquisition
    /// returns an error naming the ceiling, so the caller answers its dispatcher instead of parking
    /// until the dispatcher's own timeout redispatches the work.
    #[tokio::test]
    async fn context_slot_acquisition_times_out_at_capacity() {
        let m = bare_manager();
        m.set_context_limit(1);
        m.set_slot_timeout_for_test(std::time::Duration::from_millis(30));
        let _held = m.acquire_context_slot().await.expect("the only slot");

        let err = m.acquire_context_slot().await.expect_err("must not wait forever");
        let msg = err.to_string();
        assert!(msg.contains("capacity"), "error names the condition: {msg}");
        assert!(msg.contains('1'), "error names the ceiling: {msg}");
    }
}
