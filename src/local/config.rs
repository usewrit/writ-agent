//! App paths, config, and the local bearer token for the desktop backend.
//!
//! Layout under `~/.writ/` (override via `WRIT_HOME`): the SQLCipher db, file/artifact stores,
//! logs, the vault-key fallback, config.toml, runtime.json (discovery), the wlt_ local token,
//! the heartbeat, and the singleton lock. See the local-backend spec §0/§1/§10.
//!
//! Net-new Rust — NOT ported from the legacy Python `desktop-agent`.

use super::error::{LocalError, LocalResult};
use base64::Engine;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

/// Canonical local port (loopback only); override via `WRIT_PORT`.
pub const DEFAULT_PORT: u16 = 8131;
/// Canonical local HTTPS port (the TLS twin of [`DEFAULT_PORT`], serving the SAME router). Some MCP
/// / OpenAI-compat clients refuse a plain `http://` base URL, so the daemon also serves the API over
/// TLS with a per-install local CA (see `local::tls`). `0` disables the HTTPS lane. Override via
/// `WRIT_TLS_PORT`.
pub const DEFAULT_TLS_PORT: u16 = 8132;
/// Min-interval safety floors (anti-detection; not a paywall). Clamp at save AND tick.
pub const HTML_FLOOR_MS: u64 = 60_000;
pub const JS_FLOOR_MS: u64 = 300_000;
pub const WORKFLOW_FLOOR_MS: u64 = 60_000;

/// The on-disk `config.toml` schema version. Bump when the sectioned shape changes incompatibly.
pub const CONFIG_SCHEMA_VERSION: u32 = 1;

/// Default UI language for `[app].language` — BCP-47-ish short tag matching the frontend i18n set
/// (`en`/`fr`/`es`). The desktop wizard's first step lets the user pick; the value is non-secret
/// reflection the Tauri shell reads to seed react-i18next. Env override: `WRIT_LANGUAGE`.
pub const DEFAULT_LANGUAGE: &str = "en";

/// Default retention window (days) for runs/changes/uptime_checks/workflow-output artifacts. `0`
/// means "keep everything" — the purge becomes a no-op. The scheduler reads this each tick; a REST
/// `POST /v1/data/purge` reads it on demand. Generous default for a single-user desktop.
pub const DEFAULT_RETENTION_DAYS: u32 = 90;

/// Resource-governor (PROD-14) defaults, surfaced on the runtime config + the `[engine]` section so
/// the ceilings are documented and tunable. The governor ([`crate::local::governor`]) owns the
/// canonical defaults; these mirror them. `rss_soft_watermark_mb = 0` disables memory-based shedding.
pub const DEFAULT_MAX_CONCURRENT_RUNS: usize = 4;
pub const DEFAULT_MAX_BACKGROUND_RUNS: usize = 2;
pub const DEFAULT_RSS_SOFT_WATERMARK_MB: u64 = 1_536;

/// Hard ceiling for `max_concurrent_runs` accepted from the settings UI. A desktop shares ONE warm
/// Chromium; even a beefy box hits CDP/memory contention well before this. The governor clamps the
/// LOWER bound (≥1); this bounds the UPPER so a fat-fingered value can't try to fan out 10k contexts.
pub const MAX_CONCURRENT_RUNS_CEILING: usize = 64;

/// Floor for a NON-ZERO `rss_soft_watermark_mb` accepted from the settings UI. `0` disables memory
/// shedding entirely (allowed); any positive value is clamped up to this so a tiny watermark can't
/// wedge the daemon into shedding every background run the instant it warms one browser.
pub const MIN_RSS_SOFT_WATERMARK_MB: u64 = 256;

/// Default global headless mode for the warm browser (`[browser].headless`). `true` = run Chromium
/// headless (the unattended default); `false` = show a visible window (handy for debugging a recipe
/// or watching a monitor check). This is the DEFAULT the warm browser + recording + monitoring use;
/// an individual workflow run still honors its own per-run `headless` override. Env: `WRIT_HEADLESS`.
pub const DEFAULT_BROWSER_HEADLESS: bool = true;

/// DANGEROUS browser-security toggles — all default `false` (secure). Each disables a real OS/browser
/// protection and is surfaced ONLY behind the Settings → Runtime "Browser security (advanced)"
/// toggles; they thread into the warm-browser launch argv via `config::env::AppConfig` +
/// `browser::context::build_launch_args`. Boot-fixed (like `headless`): a change applies on restart.
///   * sandbox      → `--no-sandbox` etc. (removes the OS renderer sandbox → renderer RCE = user RCE)
///   * cert errors  → `--ignore-certificate-errors` (accept any TLS cert → MITM of logged-in sessions)
///   * web security → `--disable-web-security` (disables the same-origin policy)
/// Env overrides: `WRIT_BROWSER_DISABLE_SANDBOX` / `WRIT_BROWSER_IGNORE_CERT_ERRORS` /
/// `WRIT_BROWSER_DISABLE_WEB_SECURITY`.
pub const DEFAULT_BROWSER_DISABLE_SANDBOX: bool = false;
pub const DEFAULT_BROWSER_IGNORE_CERT_ERRORS: bool = false;
pub const DEFAULT_BROWSER_DISABLE_WEB_SECURITY: bool = false;

/// Opt-in (default false): seed the browser baseline from the user's REAL local Chrome profile
/// (cookies/storage) instead of a clean generated baseline. Surfaced in Settings → Runtime "Browser
/// security (advanced)"; the copied profile is stored inside the profile-isolated `~/.writ` home
/// (0700 dir / 0600 files). Boot-fixed like the other browser knobs. Env: `WRIT_BROWSER_USE_LOCAL_CHROME`.
pub const DEFAULT_BROWSER_USE_LOCAL_CHROME: bool = false;

const TOKEN_PREFIX: &str = "wlt_";

/// Resolved filesystem layout rooted at `~/.writ/`.
#[derive(Debug, Clone)]
pub struct Paths {
    pub root: PathBuf,
}

impl Paths {
    /// Production: `$WRIT_HOME` or `~/.writ`.
    pub fn resolve() -> LocalResult<Self> {
        let root = std::env::var_os("WRIT_HOME")
            .map(PathBuf::from)
            .or_else(|| dirs::home_dir().map(|h| h.join(".writ")))
            .ok_or_else(|| LocalError::Internal("cannot resolve home directory".into()))?;
        Ok(Self { root })
    }

    /// Explicit root (tests/headless).
    pub fn at(root: impl Into<PathBuf>) -> Self {
        Self { root: root.into() }
    }

    pub fn db(&self) -> PathBuf { self.root.join("writ.db") }
    /// Local-HTTPS material (`~/.writ/tls`): the per-install CA cert/key + metadata. The CA KEY is
    /// `0600`; the CA CERT is the public trust anchor the user installs into the OS store.
    pub fn tls_dir(&self) -> PathBuf { self.root.join("tls") }
    pub fn files_dir(&self) -> PathBuf { self.root.join("files") }
    pub fn artifacts_dir(&self) -> PathBuf { self.root.join("artifacts") }
    pub fn logs_dir(&self) -> PathBuf { self.root.join("logs") }
    pub fn vault_key(&self) -> PathBuf { self.root.join("vault.key") }
    pub fn config_toml(&self) -> PathBuf { self.root.join("config.toml") }
    pub fn runtime_json(&self) -> PathBuf { self.root.join("runtime.json") }
    pub fn local_token(&self) -> PathBuf { self.root.join("local_token") }
    pub fn agentd_json(&self) -> PathBuf { self.root.join("agentd.json") }
    pub fn lock(&self) -> PathBuf { self.root.join("writ.lock") }

    /// Cloud-link artifact dir (`~/.writ/cloud`). Holds the durable Ed25519 entitlement-JWS
    /// fallback (Stage B). The cloud *account token* never lands here — it lives in the OS keyring
    /// (`writ-cloud/account`), and `LinkState` metadata lives in the encrypted `config` kv table.
    pub fn cloud_dir(&self) -> PathBuf { self.root.join("cloud") }

    /// Create the directory tree (root `0700` on unix) idempotently.
    pub fn ensure_dirs(&self) -> LocalResult<()> {
        std::fs::create_dir_all(&self.root)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&self.root, std::fs::Permissions::from_mode(0o700))?;
        }
        std::fs::create_dir_all(self.files_dir())?;
        for sub in ["workflow_output", "screenshots", "diffs"] {
            std::fs::create_dir_all(self.artifacts_dir().join(sub))?;
        }
        std::fs::create_dir_all(self.logs_dir())?;
        std::fs::create_dir_all(self.cloud_dir())?;
        Ok(())
    }
}

/// User-tunable runtime config, flattened from the sectioned `~/.writ/config.toml`
/// (see [`load_config`] / [`ConfigFile`]). This is the in-memory shape the daemon threads through
/// `AppState`; the on-disk file is sectioned (`[server] [app] [engine] [monitors] [ai]
/// [cloud_link] [security]`) and folds into this via [`ConfigFile::into_local`].
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct LocalConfig {
    pub port: u16,
    /// Loopback HTTPS port — the TLS twin of `port`, serving the SAME router for clients that
    /// require an `https://` base URL (MCP / OpenAI-compat). `0` disables the HTTPS lane. The
    /// certificate chains to the per-install local CA in `~/.writ/tls` (see `local::tls`); the
    /// lane is FAIL-SOFT (a bind/material failure logs a warning, plain HTTP survives). Env
    /// override: `WRIT_TLS_PORT`.
    pub tls_port: u16,
    pub html_floor_ms: u64,
    pub js_floor_ms: u64,
    /// Device check-capacity override, units/min (`0` = auto from hardware). See
    /// `scheduler::capacity` — machine protection, not a plan gate.
    pub max_check_units_per_min: u64,
    pub telemetry_opt_in: bool,
    pub use_keyring: bool,
    /// Opt-in: expose this daemon's `cloud_callable` workflows for cloud-initiated execution. When
    /// on (and the desktop is cloud-linked), `writ-agentd` spawns the `LinkedAgentBridge`, which
    /// advertises a METADATA-ONLY catalog to Writ Cloud and runs workflows dispatched by id. The
    /// recipe + credentials never leave the device; identity/billing/metering stay server-side
    /// (the never-trust-a-BYO-agent rule). Default OFF — exposure is always an explicit opt-in.
    /// Env override: `WRIT_CLOUD_EXPOSE` (truthy = 1/true/yes/on).
    pub cloud_expose_workflows: bool,
    /// Explicit OFF-switch for the full cloud execution agent (`LinkedAgentManager`). The agent is
    /// DEFAULT-ON when the desktop is cloud-linked (activation is gated on `LinkState::is_linked()` +
    /// a sealed channel key), so `cloud_expose_workflows` no longer needs to be flipped for the agent
    /// to run. This flag is the user's explicit "keep the agent off even though I'm linked" switch;
    /// `POST /v1/cloud/agent/disable` sets it, `enable` clears it. Default OFF (agent runs when linked).
    /// Env override: `WRIT_CLOUD_AGENT_DISABLED` (truthy = 1/true/yes/on).
    pub cloud_agent_disabled: bool,
    /// Opt-in: advertise this agent as eligible for the SHARED supply pool (other-tenant BYO-clean
    /// work), not just the owner's own cloud-dispatched workflows. Default OFF — supply-pool
    /// participation is always an explicit opt-in. Identity/isolation/billing stay server-side
    /// (the never-trust-a-BYO-agent rule); this flag only widens the advertised capability set.
    /// Env override: `WRIT_SUPPLY_POOL` (truthy = 1/true/yes/on).
    pub supply_pool_opt_in: bool,
    /// Opt-in: expose the local API/MCP/OpenAI surface on the LAN (bind `0.0.0.0` instead of the
    /// `127.0.0.1` loopback default) so other devices on the same network can call it. Default OFF —
    /// the daemon is loopback-only unless the user explicitly opts in via the UI. The `wlt_`/`wlk_`
    /// bearer token stays mandatory in BOTH modes, and the DNS-rebind Origin/Host guard still rejects
    /// foreign browser origins; this flag only widens the bind address + the accepted LAN host. The
    /// bind only changes on a daemon RESTART (the running listener is fixed for its lifetime).
    /// Env override: `WRIT_NETWORK_EXPOSE` (truthy = 1/true/yes/on). See SECURITY.md "Network exposure".
    pub network_exposed: bool,
    /// Config-driven data retention window, in DAYS. Rows in the high-churn history tables
    /// (`runs` + `run_artifacts`, `changes`, `uptime_checks`) and their captured workflow-output
    /// artifacts older than this are purged by the scheduler tick (and `POST /v1/data/purge`). `0`
    /// disables the purge (keep everything). Env override: `WRIT_RETENTION_DAYS`.
    pub retention_days: u32,
    /// Resource governor (PROD-14): global ceiling on concurrent engine runs (interactive +
    /// background combined). The daemon shares ONE warm Chromium; this bounds how many contexts can
    /// run at once. Interactive (user/API/MCP) runs may use the full ceiling; background
    /// (scheduled/monitor) runs are capped at [`max_background_runs`](Self::max_background_runs).
    /// Env override: `WRIT_MAX_CONCURRENT_RUNS`.
    pub max_concurrent_runs: usize,
    /// Resource governor (PROD-14): sub-ceiling on concurrent BACKGROUND runs — kept below
    /// `max_concurrent_runs` so interactive runs always have reserved headroom. Clamped into
    /// `1..=max_concurrent_runs`. Env override: `WRIT_MAX_BACKGROUND_RUNS`.
    pub max_background_runs: usize,
    /// Resource governor (PROD-14): soft RSS watermark in MEGABYTES. When the daemon's resident memory
    /// crosses this, the governor sheds background work first (new background runs return busy; the
    /// scheduler skips heavy ticks) while still admitting interactive runs. `0` disables memory-based
    /// shedding. Env override: `WRIT_RSS_SOFT_WATERMARK_MB`.
    pub rss_soft_watermark_mb: u64,
    /// Global default headless mode for the warm browser (`[browser].headless`). `true` runs Chromium
    /// headless (the unattended default); `false` shows a visible window. This seeds the browser
    /// `AppConfig` at boot (see `app::lifecycle`), so it is the DEFAULT the warm browser + recording +
    /// monitoring use — an individual workflow run still honors its own per-run `headless` override.
    /// Applied only on a daemon RESTART (the warm browser's launch mode is fixed for the running
    /// session). Env override: `WRIT_HEADLESS`.
    pub browser_headless: bool,
    /// DANGEROUS browser-security toggle: disable Chromium's OS-level renderer sandbox (`--no-sandbox`
    /// …). Default FALSE (sandboxed). Boot-fixed like [`browser_headless`]. See
    /// [`DEFAULT_BROWSER_DISABLE_SANDBOX`]. Env: `WRIT_BROWSER_DISABLE_SANDBOX`.
    pub browser_disable_sandbox: bool,
    /// DANGEROUS browser-security toggle: accept ANY TLS certificate in the automation browser
    /// (`--ignore-certificate-errors`). Default FALSE. Env: `WRIT_BROWSER_IGNORE_CERT_ERRORS`.
    pub browser_ignore_certificate_errors: bool,
    /// DANGEROUS browser-security toggle: disable the same-origin policy (`--disable-web-security`).
    /// Default FALSE. Env: `WRIT_BROWSER_DISABLE_WEB_SECURITY`.
    pub browser_disable_web_security: bool,
    /// Opt-in: seed the baseline from the user's real local Chrome profile (default FALSE = clean
    /// baseline). See [`DEFAULT_BROWSER_USE_LOCAL_CHROME`]. Env: `WRIT_BROWSER_USE_LOCAL_CHROME`.
    pub browser_use_local_chrome: bool,
    /// First-run setup gate: `false` until the desktop onboarding wizard finishes (it flips this to
    /// `true` via `POST /v1/runtime/onboarding/complete`). The Tauri shell reads it on launch to
    /// decide whether to show the setup wizard. Default FALSE so a fresh install always onboards.
    /// Env override: `WRIT_ONBOARDING_COMPLETED`.
    pub onboarding_completed: bool,
    /// UI language tag (`en`/`fr`/`es`, see [`DEFAULT_LANGUAGE`]). Non-secret reflection the shell
    /// reads to seed react-i18next; the wizard's language step writes it. Env override: `WRIT_LANGUAGE`.
    pub language: String,
}

impl Default for LocalConfig {
    fn default() -> Self {
        Self {
            port: std::env::var("WRIT_PORT").ok().and_then(|s| s.parse().ok()).unwrap_or(DEFAULT_PORT),
            tls_port: std::env::var("WRIT_TLS_PORT")
                .ok()
                .and_then(|s| s.trim().parse().ok())
                .unwrap_or(DEFAULT_TLS_PORT),
            html_floor_ms: HTML_FLOOR_MS,
            js_floor_ms: JS_FLOOR_MS,
            max_check_units_per_min: 0,
            telemetry_opt_in: false,
            // Default OFF: root the vault in the 0600 `~/.writ/vault.key` file (in a 0700
            // dir). Enabling the OS keyring triggers a BLOCKING macOS Keychain prompt —
            // fine for a SIGNED/notarized prod build (one-time grant) but on an unsigned/dev
            // build it can hang the daemon before it binds the loopback port. Opt in via
            // [security].use_keyring once the app is signed.
            use_keyring: false,
            cloud_expose_workflows: env_truthy("WRIT_CLOUD_EXPOSE"),
            cloud_agent_disabled: env_truthy("WRIT_CLOUD_AGENT_DISABLED"),
            supply_pool_opt_in: env_truthy("WRIT_SUPPLY_POOL"),
            network_exposed: network_expose_override().unwrap_or(false),
            retention_days: std::env::var("WRIT_RETENTION_DAYS")
                .ok()
                .and_then(|s| s.trim().parse().ok())
                .unwrap_or(DEFAULT_RETENTION_DAYS),
            max_concurrent_runs: std::env::var("WRIT_MAX_CONCURRENT_RUNS")
                .ok()
                .and_then(|s| s.trim().parse().ok())
                .unwrap_or(DEFAULT_MAX_CONCURRENT_RUNS),
            max_background_runs: std::env::var("WRIT_MAX_BACKGROUND_RUNS")
                .ok()
                .and_then(|s| s.trim().parse().ok())
                .unwrap_or(DEFAULT_MAX_BACKGROUND_RUNS),
            rss_soft_watermark_mb: std::env::var("WRIT_RSS_SOFT_WATERMARK_MB")
                .ok()
                .and_then(|s| s.trim().parse().ok())
                .unwrap_or(DEFAULT_RSS_SOFT_WATERMARK_MB),
            browser_headless: env_bool("WRIT_HEADLESS").unwrap_or(DEFAULT_BROWSER_HEADLESS),
            browser_disable_sandbox: env_bool("WRIT_BROWSER_DISABLE_SANDBOX")
                .unwrap_or(DEFAULT_BROWSER_DISABLE_SANDBOX),
            browser_ignore_certificate_errors: env_bool("WRIT_BROWSER_IGNORE_CERT_ERRORS")
                .unwrap_or(DEFAULT_BROWSER_IGNORE_CERT_ERRORS),
            browser_disable_web_security: env_bool("WRIT_BROWSER_DISABLE_WEB_SECURITY")
                .unwrap_or(DEFAULT_BROWSER_DISABLE_WEB_SECURITY),
            browser_use_local_chrome: env_bool("WRIT_BROWSER_USE_LOCAL_CHROME")
                .unwrap_or(DEFAULT_BROWSER_USE_LOCAL_CHROME),
            onboarding_completed: env_truthy("WRIT_ONBOARDING_COMPLETED"),
            language: std::env::var("WRIT_LANGUAGE")
                .ok()
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .unwrap_or_else(|| DEFAULT_LANGUAGE.to_string()),
        }
    }
}

/// Parse a boolean-ish env var: `1|true|yes|on` (case-insensitive) is true; `0|false|no|off` is
/// false; anything else (incl. unset/empty/garbage) yields `None` so a caller can keep its prior
/// value. Used for opt-in feature toggles.
fn env_bool(key: &str) -> Option<bool> {
    match std::env::var(key).ok().map(|s| s.trim().to_ascii_lowercase()).as_deref() {
        Some("1") | Some("true") | Some("yes") | Some("on") => Some(true),
        Some("0") | Some("false") | Some("no") | Some("off") => Some(false),
        _ => None,
    }
}

/// Parse a boolean-ish env var: `1|true|yes|on` (case-insensitive) is true; anything else (incl.
/// unset/empty) is false. Used for opt-in feature toggles that default OFF.
fn env_truthy(key: &str) -> bool {
    env_bool(key).unwrap_or(false)
}

/// Resolve the `WRIT_NETWORK_EXPOSE` override with a SECURITY GATE. Binding the local API to
/// `0.0.0.0` (LAN-reachable) is a consequential action that should normally go through the in-app
/// Network consent toggle (persisted config). ENABLING it via env is therefore honored only in a dev
/// build, OR in a release build when the operator ALSO sets `WRIT_ALLOW_ENV_EXPOSE` to acknowledge the
/// risk — so a stray/injected env var (a poisoned launch agent, shell profile, or wrapper) can no
/// longer silently expose the API LAN-wide. DISABLING via env is always honored (turning it off is
/// safe). Returns the effective override, or `None` to fall back to the on-disk/UI value.
fn network_expose_override() -> Option<bool> {
    match env_bool("WRIT_NETWORK_EXPOSE") {
        Some(false) => Some(false),
        Some(true) => {
            let acknowledged = cfg!(debug_assertions) || env_truthy("WRIT_ALLOW_ENV_EXPOSE");
            if acknowledged {
                tracing::warn!(
                    "LAN exposure ENABLED via WRIT_NETWORK_EXPOSE — the local API will bind 0.0.0.0 \
                     (bearer token still required). This bypasses the in-app Network consent toggle."
                );
                Some(true)
            } else {
                tracing::warn!(
                    "IGNORING WRIT_NETWORK_EXPOSE=1: enabling LAN exposure via env in a release build \
                     requires WRIT_ALLOW_ENV_EXPOSE=1 to acknowledge the risk (or use the in-app \
                     Network setting). Staying loopback-only."
                );
                None
            }
        }
        None => None,
    }
}

// ---------------------------------------------------------------------------------------------
// config.toml — sectioned on-disk schema (schema_version=1) + loader/writer.
// ---------------------------------------------------------------------------------------------

/// The on-disk `~/.writ/config.toml` shape. Sectioned per the local-backend spec §10
/// (`[server] [app] [engine] [monitors] [ai] [cloud_link] [security]`). Every field is optional so
/// a sparse/old file loads forward; `#[serde(default)]` fills the rest. This struct is purely the
/// FILE representation — it folds into the runtime [`LocalConfig`] via [`into_local`](Self::into_local).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct ConfigFile {
    /// On-disk schema version. Always written as [`CONFIG_SCHEMA_VERSION`]; a future bump migrates.
    pub schema_version: u32,
    pub server: ServerSection,
    pub app: AppSection,
    pub engine: EngineSection,
    pub browser: BrowserSection,
    pub monitors: MonitorsSection,
    pub ai: AiSection,
    pub cloud_link: CloudLinkSection,
    pub security: SecuritySection,
}

impl Default for ConfigFile {
    fn default() -> Self {
        Self {
            schema_version: CONFIG_SCHEMA_VERSION,
            server: ServerSection::default(),
            app: AppSection::default(),
            engine: EngineSection::default(),
            browser: BrowserSection::default(),
            monitors: MonitorsSection::default(),
            ai: AiSection::default(),
            cloud_link: CloudLinkSection::default(),
            security: SecuritySection::default(),
        }
    }
}

/// `[server]` — the local API bind. Loopback-only by default; LAN exposure is an explicit opt-in.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct ServerSection {
    /// Loopback port. Env override `WRIT_PORT`.
    pub port: u16,
    /// Loopback HTTPS port (TLS twin of `port`, same router; `0` disables). Env override
    /// `WRIT_TLS_PORT`. See [`LocalConfig::tls_port`].
    pub tls_port: u16,
    /// Expose the API on the LAN (bind `0.0.0.0` instead of `127.0.0.1`). Default FALSE = loopback
    /// only. The bearer token stays mandatory; DNS-rebind protection still applies. The bind only
    /// changes on a daemon restart. Env override `WRIT_NETWORK_EXPOSE`.
    pub network_exposed: bool,
}
impl Default for ServerSection {
    fn default() -> Self {
        Self { port: DEFAULT_PORT, tls_port: DEFAULT_TLS_PORT, network_exposed: false }
    }
}

/// Accept a TOML bool OR a quoted-string bool (`true` / `"true"`). The Tauri shell shares this
/// `config.toml` and historically wrote `[app]` flags as STRINGS (`onboarding_completed = "true"`);
/// a plain `bool` field rejected that and made the daemon discard the ENTIRE config. Tolerating the
/// string form heals those existing files on read — and the next daemon-side write re-serializes the
/// field as a canonical bool. New shells write a real bool, so this is a legacy/robustness shim.
fn de_bool_lenient<'de, D: serde::Deserializer<'de>>(d: D) -> Result<bool, D::Error> {
    struct V;
    impl serde::de::Visitor<'_> for V {
        type Value = bool;
        fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
            f.write_str(r#"a boolean or the string "true"/"false""#)
        }
        fn visit_bool<E: serde::de::Error>(self, b: bool) -> Result<bool, E> {
            Ok(b)
        }
        fn visit_str<E: serde::de::Error>(self, s: &str) -> Result<bool, E> {
            match s.trim().to_ascii_lowercase().as_str() {
                "true" | "1" | "yes" | "on" => Ok(true),
                "false" | "0" | "no" | "off" | "" => Ok(false),
                other => Err(E::custom(format!("invalid boolean: {other:?}"))),
            }
        }
        fn visit_string<E: serde::de::Error>(self, s: String) -> Result<bool, E> {
            self.visit_str(&s)
        }
    }
    d.deserialize_any(V)
}

/// `[app]` — UI/telemetry/data-retention preferences.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct AppSection {
    /// Opt-in anonymous telemetry. Env override `WRIT_TELEMETRY`.
    #[serde(deserialize_with = "de_bool_lenient")]
    pub telemetry_opt_in: bool,
    /// Data retention window in DAYS for the history tables (`0` = keep everything). Env override
    /// `WRIT_RETENTION_DAYS`. See [`LocalConfig::retention_days`].
    pub retention_days: u32,
    /// First-run setup gate — `false` until the desktop onboarding wizard finishes. The shell reads
    /// this to decide whether to show setup. Env override `WRIT_ONBOARDING_COMPLETED`. The Tauri shell
    /// once wrote this as a quoted string, so it is parsed leniently (see [`de_bool_lenient`]).
    #[serde(deserialize_with = "de_bool_lenient")]
    pub onboarding_completed: bool,
    /// UI language tag (`en`/`fr`/`es`). Env override `WRIT_LANGUAGE`. See [`LocalConfig::language`].
    pub language: String,
}
impl Default for AppSection {
    fn default() -> Self {
        Self {
            telemetry_opt_in: false,
            retention_days: DEFAULT_RETENTION_DAYS,
            onboarding_completed: false,
            language: DEFAULT_LANGUAGE.to_string(),
        }
    }
}

/// `[engine]` — execution-engine resource-governance knobs (PROD-14). These fold into the runtime
/// [`LocalConfig`] and configure [`crate::local::governor::ResourceGovernor`]: the global concurrent-
/// run ceiling, the background sub-ceiling, and the soft RSS watermark (MB). Env overrides win.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct EngineSection {
    /// Global ceiling on concurrent engine runs. Env override `WRIT_MAX_CONCURRENT_RUNS`.
    pub max_concurrent_runs: usize,
    /// Sub-ceiling on concurrent BACKGROUND runs (scheduled/monitor). Env override
    /// `WRIT_MAX_BACKGROUND_RUNS`.
    pub max_background_runs: usize,
    /// Soft RSS watermark in MEGABYTES (`0` disables memory shedding). Env override
    /// `WRIT_RSS_SOFT_WATERMARK_MB`.
    pub rss_soft_watermark_mb: u64,
}
impl Default for EngineSection {
    fn default() -> Self {
        Self {
            max_concurrent_runs: DEFAULT_MAX_CONCURRENT_RUNS,
            max_background_runs: DEFAULT_MAX_BACKGROUND_RUNS,
            rss_soft_watermark_mb: DEFAULT_RSS_SOFT_WATERMARK_MB,
        }
    }
}

/// `[browser]` — global browser (Chromium) defaults. Folds into the runtime [`LocalConfig`] and, at
/// boot, seeds the browser [`crate::config::env::AppConfig`] the warm-browser manager reads. The
/// per-run `headless` override on a workflow still wins for that field; the security toggles are
/// global-only (a compromised recipe must never be able to weaken the sandbox for its own run).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct BrowserSection {
    /// Global default headless mode for the warm browser. Env override `WRIT_HEADLESS`.
    pub headless: bool,
    /// DANGEROUS: disable the OS renderer sandbox (`--no-sandbox`). Default false. See
    /// [`DEFAULT_BROWSER_DISABLE_SANDBOX`]. Env `WRIT_BROWSER_DISABLE_SANDBOX`.
    pub disable_sandbox: bool,
    /// DANGEROUS: accept any TLS cert (`--ignore-certificate-errors`). Default false. Env
    /// `WRIT_BROWSER_IGNORE_CERT_ERRORS`.
    pub ignore_certificate_errors: bool,
    /// DANGEROUS: disable the same-origin policy (`--disable-web-security`). Default false. Env
    /// `WRIT_BROWSER_DISABLE_WEB_SECURITY`.
    pub disable_web_security: bool,
    /// Opt-in: seed the baseline from the user's real local Chrome profile. Default false. Env
    /// `WRIT_BROWSER_USE_LOCAL_CHROME`.
    pub use_local_chrome: bool,
}
impl Default for BrowserSection {
    fn default() -> Self {
        Self {
            headless: DEFAULT_BROWSER_HEADLESS,
            disable_sandbox: DEFAULT_BROWSER_DISABLE_SANDBOX,
            ignore_certificate_errors: DEFAULT_BROWSER_IGNORE_CERT_ERRORS,
            disable_web_security: DEFAULT_BROWSER_DISABLE_WEB_SECURITY,
            use_local_chrome: DEFAULT_BROWSER_USE_LOCAL_CHROME,
        }
    }
}

/// `[monitors]` — the monitor scheduler's safety floors. These are the SAVE/TICK clamp inputs the
/// scheduler reads; lowering them below the hard anti-detection floors has no effect (clamped).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct MonitorsSection {
    /// HTML/content (HTTP fast-path) minimum interval, ms. Env override `WRIT_HTML_FLOOR_MS`.
    pub html_floor_ms: u64,
    /// JS/Playwright (browser-path) minimum interval, ms. Env override `WRIT_JS_FLOOR_MS`.
    pub js_floor_ms: u64,
    /// Device check-capacity budget override, units/min (`0` = auto from hardware). Env override
    /// `WRIT_MAX_CHECK_UNITS_PER_MIN`. Protects the machine from monitor overload — not a paywall.
    pub max_check_units_per_min: u64,
}
impl Default for MonitorsSection {
    fn default() -> Self {
        Self { html_floor_ms: HTML_FLOOR_MS, js_floor_ms: JS_FLOOR_MS, max_check_units_per_min: 0 }
    }
}

/// `[ai]` — BYO local AI provider preferences. The provider KEY itself NEVER lands here (it lives in
/// the vault); this is non-secret reflection only.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct AiSection {}

/// `[cloud_link]` — optional cloud exposure toggles. The cloud account TOKEN never lands here (OS
/// keyring); link METADATA lives in the encrypted `config` kv table. This is the local opt-in only.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct CloudLinkSection {
    /// Expose `cloud_callable` workflows for cloud-initiated execution. Env override `WRIT_CLOUD_EXPOSE`.
    pub expose_workflows: bool,
    /// Explicit OFF-switch for the full cloud execution agent (default-on-when-linked). Env override
    /// `WRIT_CLOUD_AGENT_DISABLED`.
    pub agent_disabled: bool,
    /// Opt-in to the shared supply pool (other-tenant BYO-clean work). Env override `WRIT_SUPPLY_POOL`.
    pub supply_pool_opt_in: bool,
}

/// `[security]` — vault/keyring behavior.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
#[derive(Default)]
pub struct SecuritySection {
    /// Use the OS keyring to root the vault master key (file fallback when false/unavailable).
    /// Env override `WRIT_USE_KEYRING`.
    pub use_keyring: bool,
}

impl ConfigFile {
    /// Fold the sectioned file into the flat runtime [`LocalConfig`], applying `WRIT_*` env overrides
    /// LAST so an env var always wins over the file. NEVER reads or carries any secret material.
    pub fn into_local(self) -> LocalConfig {
        let port = std::env::var("WRIT_PORT")
            .ok()
            .and_then(|s| s.trim().parse::<u16>().ok())
            .unwrap_or(self.server.port);
        let tls_port = std::env::var("WRIT_TLS_PORT")
            .ok()
            .and_then(|s| s.trim().parse::<u16>().ok())
            .unwrap_or(self.server.tls_port);
        let html_floor_ms = std::env::var("WRIT_HTML_FLOOR_MS")
            .ok()
            .and_then(|s| s.trim().parse::<u64>().ok())
            .unwrap_or(self.monitors.html_floor_ms);
        let js_floor_ms = std::env::var("WRIT_JS_FLOOR_MS")
            .ok()
            .and_then(|s| s.trim().parse::<u64>().ok())
            .unwrap_or(self.monitors.js_floor_ms);
        let max_check_units_per_min = std::env::var("WRIT_MAX_CHECK_UNITS_PER_MIN")
            .ok()
            .and_then(|s| s.trim().parse::<u64>().ok())
            .unwrap_or(self.monitors.max_check_units_per_min);
        LocalConfig {
            port,
            tls_port,
            html_floor_ms,
            js_floor_ms,
            max_check_units_per_min,
            telemetry_opt_in: env_bool("WRIT_TELEMETRY").unwrap_or(self.app.telemetry_opt_in),
            use_keyring: env_bool("WRIT_USE_KEYRING").unwrap_or(self.security.use_keyring),
            cloud_expose_workflows: env_bool("WRIT_CLOUD_EXPOSE")
                .unwrap_or(self.cloud_link.expose_workflows),
            cloud_agent_disabled: env_bool("WRIT_CLOUD_AGENT_DISABLED")
                .unwrap_or(self.cloud_link.agent_disabled),
            supply_pool_opt_in: env_bool("WRIT_SUPPLY_POOL")
                .unwrap_or(self.cloud_link.supply_pool_opt_in),
            network_exposed: network_expose_override().unwrap_or(self.server.network_exposed),
            retention_days: std::env::var("WRIT_RETENTION_DAYS")
                .ok()
                .and_then(|s| s.trim().parse::<u32>().ok())
                .unwrap_or(self.app.retention_days),
            max_concurrent_runs: std::env::var("WRIT_MAX_CONCURRENT_RUNS")
                .ok()
                .and_then(|s| s.trim().parse::<usize>().ok())
                .unwrap_or(self.engine.max_concurrent_runs),
            max_background_runs: std::env::var("WRIT_MAX_BACKGROUND_RUNS")
                .ok()
                .and_then(|s| s.trim().parse::<usize>().ok())
                .unwrap_or(self.engine.max_background_runs),
            rss_soft_watermark_mb: std::env::var("WRIT_RSS_SOFT_WATERMARK_MB")
                .ok()
                .and_then(|s| s.trim().parse::<u64>().ok())
                .unwrap_or(self.engine.rss_soft_watermark_mb),
            browser_headless: env_bool("WRIT_HEADLESS").unwrap_or(self.browser.headless),
            browser_disable_sandbox: env_bool("WRIT_BROWSER_DISABLE_SANDBOX")
                .unwrap_or(self.browser.disable_sandbox),
            browser_ignore_certificate_errors: env_bool("WRIT_BROWSER_IGNORE_CERT_ERRORS")
                .unwrap_or(self.browser.ignore_certificate_errors),
            browser_disable_web_security: env_bool("WRIT_BROWSER_DISABLE_WEB_SECURITY")
                .unwrap_or(self.browser.disable_web_security),
            browser_use_local_chrome: env_bool("WRIT_BROWSER_USE_LOCAL_CHROME")
                .unwrap_or(self.browser.use_local_chrome),
            onboarding_completed: env_bool("WRIT_ONBOARDING_COMPLETED")
                .unwrap_or(self.app.onboarding_completed),
            language: std::env::var("WRIT_LANGUAGE")
                .ok()
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .unwrap_or(self.app.language),
        }
    }

    /// Re-derive the sectioned file shape from a flat [`LocalConfig`] (round-trip / first-write).
    pub fn from_local(c: &LocalConfig) -> Self {
        Self {
            schema_version: CONFIG_SCHEMA_VERSION,
            server: ServerSection {
                port: c.port,
                tls_port: c.tls_port,
                network_exposed: c.network_exposed,
            },
            app: AppSection {
                telemetry_opt_in: c.telemetry_opt_in,
                retention_days: c.retention_days,
                onboarding_completed: c.onboarding_completed,
                language: c.language.clone(),
            },
            engine: EngineSection {
                max_concurrent_runs: c.max_concurrent_runs,
                max_background_runs: c.max_background_runs,
                rss_soft_watermark_mb: c.rss_soft_watermark_mb,
            },
            browser: BrowserSection {
                headless: c.browser_headless,
                disable_sandbox: c.browser_disable_sandbox,
                ignore_certificate_errors: c.browser_ignore_certificate_errors,
                disable_web_security: c.browser_disable_web_security,
                use_local_chrome: c.browser_use_local_chrome,
            },
            monitors: MonitorsSection {
                html_floor_ms: c.html_floor_ms,
                js_floor_ms: c.js_floor_ms,
                max_check_units_per_min: c.max_check_units_per_min,
            },
            ai: AiSection::default(),
            cloud_link: CloudLinkSection {
                expose_workflows: c.cloud_expose_workflows,
                agent_disabled: c.cloud_agent_disabled,
                supply_pool_opt_in: c.supply_pool_opt_in,
            },
            security: SecuritySection { use_keyring: c.use_keyring },
        }
    }
}

/// Load `~/.writ/config.toml` into a runtime [`LocalConfig`], applying `WRIT_*` env overrides last.
///
/// Behavior:
///   * Missing file → the full default config (env overrides still apply) is returned, and a default
///     `config.toml` is written (`0600`) so the user has a documented file to edit. A write failure
///     is logged, not fatal (the daemon still runs on the in-memory defaults).
///   * Present-but-malformed file → the error is logged and defaults are used (env overrides apply),
///     so a hand-edited typo can never wedge startup. The bad file is left untouched.
///
/// NEVER logs secrets — the file carries none (provider keys/tokens live in the vault/keyring).
pub fn load_config(paths: &Paths) -> LocalConfig {
    let path = paths.config_toml();
    match std::fs::read_to_string(&path) {
        Ok(text) => match toml::from_str::<ConfigFile>(&text) {
            Ok(file) => {
                if file.schema_version != CONFIG_SCHEMA_VERSION {
                    tracing::warn!(
                        found = file.schema_version,
                        expected = CONFIG_SCHEMA_VERSION,
                        "config.toml schema_version mismatch; loading on a best-effort basis"
                    );
                }
                file.into_local()
            }
            Err(e) => {
                tracing::warn!(error = %e, path = %path.display(), "config.toml is malformed; using defaults");
                LocalConfig::default()
            }
        },
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            // First run: materialize a documented default file (best-effort) and return defaults.
            let cfg = LocalConfig::default();
            if let Err(e) = write_config(paths, &cfg) {
                tracing::warn!(error = %e, "could not write a default config.toml (continuing on defaults)");
            } else {
                tracing::info!(path = %path.display(), "wrote default config.toml");
            }
            cfg
        }
        Err(e) => {
            tracing::warn!(error = %e, path = %path.display(), "could not read config.toml; using defaults");
            LocalConfig::default()
        }
    }
}

/// Serialize a [`LocalConfig`] back to the sectioned `config.toml` (`0600`). Used on first-run
/// materialization and by `config set`. Overwrites the file atomically-enough for a single-user
/// daemon (write + chmod); never partial on success.
pub fn write_config(paths: &Paths, cfg: &LocalConfig) -> LocalResult<()> {
    let file = ConfigFile::from_local(cfg);
    let text = toml::to_string_pretty(&file)
        .map_err(|e| LocalError::Internal(format!("serialize config.toml: {e}")))?;
    write_0600(&paths.config_toml(), text.as_bytes())
}

/// Read the on-disk `~/.writ/config.toml` into its sectioned [`ConfigFile`] shape (no env overlay,
/// no fold to the runtime [`LocalConfig`]). A missing file yields the default; a malformed file
/// yields the default too (logged) so a hand-edit typo never wedges a config write. This is the
/// read half used by the focused field-writers below so they preserve every OTHER on-disk field.
fn read_config_file(paths: &Paths) -> ConfigFile {
    match std::fs::read_to_string(paths.config_toml()) {
        Ok(text) => toml::from_str::<ConfigFile>(&text).unwrap_or_else(|e| {
            tracing::warn!(error = %e, "config.toml is malformed; writing over defaults");
            ConfigFile::default()
        }),
        Err(_) => ConfigFile::default(),
    }
}

/// Persist ONLY the `[server].network_exposed` flag to `~/.writ/config.toml` (`0600`), preserving
/// every other on-disk field (read-modify-write of the sectioned file, NOT a clobber from the boot
/// snapshot). Used by `POST /v1/network/expose` so the LAN-exposure opt-in survives a daemon restart.
///
/// IMPORTANT: this is a persistence-only flip — the running listener's bind is fixed for its lifetime,
/// so the caller MUST restart the daemon for the new bind to take effect (`needs_restart = true`).
/// NEVER reads or writes any secret material (the file carries none).
pub fn set_network_exposed(paths: &Paths, enabled: bool) -> LocalResult<()> {
    let mut file = read_config_file(paths);
    file.schema_version = CONFIG_SCHEMA_VERSION;
    file.server.network_exposed = enabled;
    let text = toml::to_string_pretty(&file)
        .map_err(|e| LocalError::Internal(format!("serialize config.toml: {e}")))?;
    write_0600(&paths.config_toml(), text.as_bytes())
}

/// Persist ONLY the cloud-agent toggles to `~/.writ/config.toml` (`0600`), preserving every other
/// on-disk field (read-modify-write of the sectioned file, NOT a clobber from the boot snapshot).
/// Used by `POST /v1/cloud/agent/{enable,disable}` so the on/off choice + supply-pool opt-in survive a
/// daemon restart. `enabled` maps to `[cloud_link].agent_disabled = !enabled` (the flag is an
/// OFF-switch so the agent stays default-on-when-linked); `supply_pool_opt_in` is persisted verbatim.
/// NEVER reads or writes any secret material (the file carries none).
pub fn set_cloud_agent(paths: &Paths, enabled: bool, supply_pool_opt_in: bool) -> LocalResult<()> {
    let mut file = read_config_file(paths);
    file.schema_version = CONFIG_SCHEMA_VERSION;
    file.cloud_link.agent_disabled = !enabled;
    file.cloud_link.supply_pool_opt_in = supply_pool_opt_in;
    let text = toml::to_string_pretty(&file)
        .map_err(|e| LocalError::Internal(format!("serialize config.toml: {e}")))?;
    write_0600(&paths.config_toml(), text.as_bytes())
}

/// Persist ONLY the `[app].retention_days` field to `~/.writ/config.toml` (`0600`), preserving every
/// other on-disk field (read-modify-write of the sectioned file). Used by `POST /v1/data/retention`
/// so the retention window survives a daemon restart. Takes effect on the NEXT scheduler tick that
/// re-reads config; the running `AppState.config` snapshot is unchanged for its lifetime (the purge
/// REST route reads the persisted value directly so a just-saved window applies immediately on a
/// manual purge). NEVER reads or writes any secret material (the file carries none).
pub fn set_retention_days(paths: &Paths, days: u32) -> LocalResult<()> {
    let mut file = read_config_file(paths);
    file.schema_version = CONFIG_SCHEMA_VERSION;
    file.app.retention_days = days;
    let text = toml::to_string_pretty(&file)
        .map_err(|e| LocalError::Internal(format!("serialize config.toml: {e}")))?;
    write_0600(&paths.config_toml(), text.as_bytes())
}

/// Persist ONLY the `[app].onboarding_completed` flag to `~/.writ/config.toml` (`0600`), preserving
/// every other on-disk field (read-modify-write of the sectioned file). The desktop onboarding wizard
/// calls this on finish (via `POST /v1/runtime/onboarding/complete`). Idempotent; takes effect on the
/// next config load (the Tauri shell reads it at launch to decide whether to show setup). NEVER reads
/// or writes any secret material (the file carries none).
pub fn set_onboarding_completed(paths: &Paths, completed: bool) -> LocalResult<()> {
    let mut file = read_config_file(paths);
    file.schema_version = CONFIG_SCHEMA_VERSION;
    file.app.onboarding_completed = completed;
    let text = toml::to_string_pretty(&file)
        .map_err(|e| LocalError::Internal(format!("serialize config.toml: {e}")))?;
    write_0600(&paths.config_toml(), text.as_bytes())
}

/// Persist ONLY the `[app].telemetry_opt_in` flag to `~/.writ/config.toml` (`0600`), preserving every
/// other on-disk field (read-modify-write of the sectioned file). Written by
/// `PUT /v1/settings/telemetry` — the desktop Settings toggle. It MUST go through the daemon rather
/// than the Tauri shell's `config_set`, because `[app].telemetry_opt_in` is a daemon-authoritative key
/// that the shell's write allowlist deliberately rejects.
///
/// Persistence only: the reporter loop (`cloud::usage_metrics`) re-reads this from disk every tick, so
/// a flip takes effect within one tick with NO daemon restart — and turning it OFF also drops the
/// install id, so a later opt-in cannot be correlated with earlier reports. NEVER touches a secret.
pub fn set_telemetry_opt_in(paths: &Paths, enabled: bool) -> LocalResult<()> {
    let mut file = read_config_file(paths);
    file.schema_version = CONFIG_SCHEMA_VERSION;
    file.app.telemetry_opt_in = enabled;
    let text = toml::to_string_pretty(&file)
        .map_err(|e| LocalError::Internal(format!("serialize config.toml: {e}")))?;
    write_0600(&paths.config_toml(), text.as_bytes())
}

/// Persist ONLY the `[app].language` tag to `~/.writ/config.toml` (`0600`), preserving every other
/// on-disk field (read-modify-write). The wizard's language step writes it; the shell reads it to seed
/// react-i18next. An empty/whitespace value is rejected as a bad request (keep a valid tag on disk).
/// NEVER reads or writes any secret material (the file carries none).
pub fn set_language(paths: &Paths, language: &str) -> LocalResult<()> {
    let lang = language.trim();
    if lang.is_empty() {
        return Err(LocalError::BadRequest("language must be a non-empty tag".into()));
    }
    let mut file = read_config_file(paths);
    file.schema_version = CONFIG_SCHEMA_VERSION;
    file.app.language = lang.to_string();
    let text = toml::to_string_pretty(&file)
        .map_err(|e| LocalError::Internal(format!("serialize config.toml: {e}")))?;
    write_0600(&paths.config_toml(), text.as_bytes())
}

/// The user-tunable "daemon / browser" runtime knobs surfaced by the desktop Settings → Runtime tab
/// (`/v1/settings/runtime`): the resource-governor ceilings (concurrent + background run caps, soft
/// RSS/"max RAM" watermark), the global browser headless default, and the monitor cadence floors
/// (minimum content-check + browser-check intervals). A focused view over [`LocalConfig`] so the
/// settings surface reads/writes exactly this set without touching unrelated fields (network,
/// retention, language, …). Carries NO secret.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RuntimeSettings {
    pub max_concurrent_runs: usize,
    pub max_background_runs: usize,
    pub rss_soft_watermark_mb: u64,
    pub browser_headless: bool,
    /// DANGEROUS browser-security toggles (default false = secure); boot-fixed like `browser_headless`.
    pub browser_disable_sandbox: bool,
    pub browser_ignore_certificate_errors: bool,
    pub browser_disable_web_security: bool,
    /// Opt-in: seed the baseline from the user's real local Chrome profile (default false).
    pub browser_use_local_chrome: bool,
    /// Minimum content (HTTP fast-path) monitor-check interval, ms. Clamped up to [`HTML_FLOOR_MS`].
    pub html_floor_ms: u64,
    /// Minimum JS/browser monitor-check interval, ms. Clamped up to [`JS_FLOOR_MS`].
    pub js_floor_ms: u64,
}

impl RuntimeSettings {
    /// Snapshot the runtime-settings subset out of a runtime [`LocalConfig`] (the values as they were
    /// booted / as they sit on disk after a load).
    pub fn from_local(c: &LocalConfig) -> Self {
        Self {
            max_concurrent_runs: c.max_concurrent_runs,
            max_background_runs: c.max_background_runs,
            rss_soft_watermark_mb: c.rss_soft_watermark_mb,
            browser_headless: c.browser_headless,
            browser_disable_sandbox: c.browser_disable_sandbox,
            browser_ignore_certificate_errors: c.browser_ignore_certificate_errors,
            browser_disable_web_security: c.browser_disable_web_security,
            browser_use_local_chrome: c.browser_use_local_chrome,
            html_floor_ms: c.html_floor_ms,
            js_floor_ms: c.js_floor_ms,
        }
    }

    /// Clamp into a safe, enforceable shape so the value PERSISTED never lies about what actually
    /// takes effect. This MIRRORS the downstream clamps — the governor
    /// ([`crate::local::governor::GovernorConfig::sanitized`]) and the monitor scheduler's hard
    /// anti-detection floors ([`crate::local::scheduler::clamp`]) — plus an UPPER bound on the global
    /// ceiling and a floor under a non-zero watermark:
    ///   * `max_concurrent_runs` → `1..=MAX_CONCURRENT_RUNS_CEILING`
    ///   * `max_background_runs`  → `1..=max_concurrent_runs`
    ///   * `rss_soft_watermark_mb`→ `0` (disabled) OR clamped up to `MIN_RSS_SOFT_WATERMARK_MB`
    ///   * `html_floor_ms`/`js_floor_ms` → clamped UP to the hard [`HTML_FLOOR_MS`]/[`JS_FLOOR_MS`]
    ///     constants (the user can only RAISE the cadence, never drop below the safe minimum)
    #[must_use]
    pub fn clamp(mut self) -> Self {
        self.max_concurrent_runs = self.max_concurrent_runs.clamp(1, MAX_CONCURRENT_RUNS_CEILING);
        self.max_background_runs = self.max_background_runs.clamp(1, self.max_concurrent_runs);
        if self.rss_soft_watermark_mb != 0 {
            self.rss_soft_watermark_mb = self.rss_soft_watermark_mb.max(MIN_RSS_SOFT_WATERMARK_MB);
        }
        self.html_floor_ms = self.html_floor_ms.max(HTML_FLOOR_MS);
        self.js_floor_ms = self.js_floor_ms.max(JS_FLOOR_MS);
        self
    }
}

/// Persist the "daemon / browser" runtime knobs ([`RuntimeSettings`]) to `~/.writ/config.toml`
/// (`0600`), preserving every OTHER on-disk field (read-modify-write of the sectioned file, NOT a
/// clobber from the boot snapshot). The values are [`RuntimeSettings::clamp`]ed first so a
/// fat-fingered ceiling / tiny watermark / sub-floor interval can never wedge the daemon.
///
/// LIFECYCLE: the governor ceilings + the browser headless default are read at BOOT (the running
/// governor's semaphore + the warm browser's launch mode are fixed for the session), so those take
/// effect only on the next daemon start — the caller signals `needs_restart` for them. The monitor
/// floors are read from a process-global that the caller re-installs on save
/// ([`crate::local::scheduler::clamp::install_monitor_floors`]), so they apply on the next scheduler
/// tick WITHOUT a restart. NEVER writes any secret (the file carries none).
pub fn set_runtime_settings(paths: &Paths, settings: &RuntimeSettings) -> LocalResult<()> {
    let s = settings.clamp();
    let mut file = read_config_file(paths);
    file.schema_version = CONFIG_SCHEMA_VERSION;
    file.engine.max_concurrent_runs = s.max_concurrent_runs;
    file.engine.max_background_runs = s.max_background_runs;
    file.engine.rss_soft_watermark_mb = s.rss_soft_watermark_mb;
    file.browser.headless = s.browser_headless;
    file.browser.disable_sandbox = s.browser_disable_sandbox;
    file.browser.ignore_certificate_errors = s.browser_ignore_certificate_errors;
    file.browser.disable_web_security = s.browser_disable_web_security;
    file.browser.use_local_chrome = s.browser_use_local_chrome;
    file.monitors.html_floor_ms = s.html_floor_ms;
    file.monitors.js_floor_ms = s.js_floor_ms;
    let text = toml::to_string_pretty(&file)
        .map_err(|e| LocalError::Internal(format!("serialize config.toml: {e}")))?;
    write_0600(&paths.config_toml(), text.as_bytes())
}

/// Load the `wlt_` local API bearer token, or mint + persist one (`0600`) on first run.
/// External clients use named `wlk_` keys (local_api_keys table); this is the UI/runtime token.
pub fn load_or_create_token(paths: &Paths) -> LocalResult<String> {
    let path = paths.local_token();
    if let Ok(s) = std::fs::read_to_string(&path) {
        let t = s.trim().to_string();
        if t.starts_with(TOKEN_PREFIX) {
            return Ok(t);
        }
    }
    let token = mint_token();
    write_0600(&path, token.as_bytes())?;
    Ok(token)
}

/// Mint a fresh `wlt_` token: prefix + URL-safe, no-pad base64 of 32 CSPRNG bytes. Does NOT persist —
/// callers that ROTATE (not first-run create) use [`rotate_token_file`] to overwrite the file.
pub fn mint_token() -> String {
    let mut raw = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut raw);
    format!("{TOKEN_PREFIX}{}", base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(raw))
}

/// Rotate the `wlt_` token FILE: mint a new value and overwrite `~/.writ/local_token` (`0600`),
/// returning the new token. The caller is responsible for swapping the live in-memory token and
/// republishing `runtime.json` so the running daemon and the file stay in lockstep.
pub fn rotate_token_file(paths: &Paths) -> LocalResult<String> {
    let token = mint_token();
    write_0600(&paths.local_token(), token.as_bytes())?;
    Ok(token)
}

/// A process-wide lock for tests that mutate the GLOBAL `WRIT_HOME` env var (which
/// [`Paths::resolve`] reads). `WRIT_HOME` is process-global, so two tests in DIFFERENT modules that
/// each point it at their own sandbox would clobber each other when run in parallel. Any test that
/// sets `WRIT_HOME` should hold THIS shared guard for the whole test body so all such tests across
/// the crate serialize on one lock (a per-module lock only serializes within that module). Use:
/// `let _g = config::test_env_guard();`.
#[cfg(test)]
pub fn test_env_guard() -> std::sync::MutexGuard<'static, ()> {
    static ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
    ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner())
}

/// Persist a secret/sensitive file `0600`. Delegates to the shared atomic writer so the bytes are
/// never visible at umask-default perms even briefly (write-then-chmod race): config.toml and the
/// `wlt_` local token both carry same-machine trust and must not be world-readable at any instant.
fn write_0600(path: &Path, bytes: &[u8]) -> LocalResult<()> {
    crate::local::vault::write_secret_file(path, bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn paths_and_token() {
        let dir = tempfile::tempdir().unwrap();
        let p = Paths::at(dir.path().join(".writ"));
        p.ensure_dirs().unwrap();
        assert!(p.files_dir().is_dir());
        assert!(p.artifacts_dir().join("screenshots").is_dir());
        assert!(p.db().to_string_lossy().ends_with("writ.db"));

        let t1 = load_or_create_token(&p).unwrap();
        assert!(t1.starts_with("wlt_") && t1.len() > 40);
        let t2 = load_or_create_token(&p).unwrap();
        assert_eq!(t1, t2, "token must persist across calls");
    }

    /// A missing config.toml materializes a default file and yields the default config; loading the
    /// just-written file round-trips to the same values.
    #[test]
    fn missing_config_writes_default_and_roundtrips() {
        let dir = tempfile::tempdir().unwrap();
        let p = Paths::at(dir.path().join(".writ"));
        p.ensure_dirs().unwrap();
        // Make sure no env overrides perturb the assertions in this process.
        for k in ["WRIT_PORT", "WRIT_HTML_FLOOR_MS", "WRIT_JS_FLOOR_MS", "WRIT_TELEMETRY", "WRIT_USE_KEYRING", "WRIT_CLOUD_EXPOSE", "WRIT_NETWORK_EXPOSE", "WRIT_RETENTION_DAYS", "WRIT_ONBOARDING_COMPLETED", "WRIT_LANGUAGE", "WRIT_HEADLESS"] {
            std::env::remove_var(k);
        }

        assert!(!p.config_toml().exists(), "no file before first load");
        let cfg = load_config(&p);
        assert!(p.config_toml().is_file(), "first load materializes the file");
        assert_eq!(cfg.port, DEFAULT_PORT);
        assert_eq!(cfg.html_floor_ms, HTML_FLOOR_MS);
        assert_eq!(cfg.js_floor_ms, JS_FLOOR_MS);
        assert!(!cfg.use_keyring, "keyring is opt-in; default is the file-rooted vault");
        assert!(!cfg.telemetry_opt_in);
        assert!(!cfg.cloud_expose_workflows);
        assert!(!cfg.network_exposed, "loopback-only is the default");
        assert_eq!(cfg.retention_days, DEFAULT_RETENTION_DAYS);
        assert!(!cfg.onboarding_completed, "first run is never pre-completed");
        assert_eq!(cfg.language, DEFAULT_LANGUAGE);

        // The written file is mode 0600 on unix (no secrets, but consistent with the home tree).
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(p.config_toml()).unwrap().permissions().mode();
            assert_eq!(mode & 0o777, 0o600);
        }

        // Re-loading the file gives identical values.
        let again = load_config(&p);
        assert_eq!(again.port, cfg.port);
        assert_eq!(again.html_floor_ms, cfg.html_floor_ms);
        assert_eq!(again.js_floor_ms, cfg.js_floor_ms);
    }

    /// A sectioned file is parsed into the flat runtime config; sections fold correctly.
    #[test]
    fn sectioned_toml_folds_into_local() {
        let toml_src = r#"
            schema_version = 1
            [server]
            port = 9191
            [app]
            telemetry_opt_in = true
            [monitors]
            html_floor_ms = 120000
            js_floor_ms = 600000
            [cloud_link]
            expose_workflows = true
            [security]
            use_keyring = false
        "#;
        let file: ConfigFile = toml::from_str(toml_src).unwrap();
        let cfg = file.into_local();
        // Without env overrides set, the file values win.
        if std::env::var("WRIT_PORT").is_err() {
            assert_eq!(cfg.port, 9191);
        }
        assert_eq!(cfg.html_floor_ms, 120_000);
        assert_eq!(cfg.js_floor_ms, 600_000);
    }

    /// A sparse file (only one section) still loads — missing sections fall to their defaults.
    #[test]
    fn sparse_toml_uses_section_defaults() {
        let file: ConfigFile = toml::from_str("[app]\ntelemetry_opt_in = true\n").unwrap();
        assert_eq!(file.server.port, DEFAULT_PORT);
        assert_eq!(file.monitors.html_floor_ms, HTML_FLOOR_MS);
        assert!(!file.security.use_keyring);
        assert!(file.app.telemetry_opt_in);
    }

    /// Regression: the Tauri shell once wrote `[app]` bools as QUOTED STRINGS
    /// (`onboarding_completed = "true"`), which made the whole config parse fail and every
    /// setting (language, engine governor, retention…) silently revert to defaults. The lenient
    /// bool deserializer must accept the string form so those existing files heal on read.
    #[test]
    fn stringy_app_bools_parse_and_dont_nuke_config() {
        let src = "[app]\nonboarding_completed = \"true\"\ntelemetry_opt_in = \"false\"\nlanguage = \"fr\"\nretention_days = 45\n";
        let file: ConfigFile = toml::from_str(src).expect("stringy bool must not fail the parse");
        assert!(file.app.onboarding_completed, "\"true\" → true");
        assert!(!file.app.telemetry_opt_in, "\"false\" → false");
        // The rest of the section survives (was being discarded before the fix).
        assert_eq!(file.app.language, "fr");
        assert_eq!(file.app.retention_days, 45);
        // A real TOML bool still works.
        let native: ConfigFile = toml::from_str("[app]\nonboarding_completed = true\n").unwrap();
        assert!(native.app.onboarding_completed);
    }

    /// `WRIT_*` env overrides win over the file values.
    #[test]
    fn env_overrides_win() {
        // Use a private guard so we restore the env after the test (tests share the process).
        let prev_port = std::env::var("WRIT_PORT").ok();
        let prev_tel = std::env::var("WRIT_TELEMETRY").ok();
        std::env::set_var("WRIT_PORT", "7777");
        std::env::set_var("WRIT_TELEMETRY", "true");

        let file = ConfigFile {
            server: ServerSection { port: 9191, ..Default::default() },
            ..Default::default()
        };
        let cfg = file.into_local();
        assert_eq!(cfg.port, 7777, "WRIT_PORT overrides [server].port");
        assert!(cfg.telemetry_opt_in, "WRIT_TELEMETRY overrides [app].telemetry_opt_in");

        // restore
        match prev_port {
            Some(v) => std::env::set_var("WRIT_PORT", v),
            None => std::env::remove_var("WRIT_PORT"),
        }
        match prev_tel {
            Some(v) => std::env::set_var("WRIT_TELEMETRY", v),
            None => std::env::remove_var("WRIT_TELEMETRY"),
        }
    }

    /// A malformed file does not wedge startup — defaults are returned.
    #[test]
    fn malformed_toml_falls_back_to_defaults() {
        let dir = tempfile::tempdir().unwrap();
        let p = Paths::at(dir.path().join(".writ"));
        p.ensure_dirs().unwrap();
        std::fs::write(p.config_toml(), "this is = = not valid toml [[[").unwrap();
        for k in ["WRIT_PORT", "WRIT_HTML_FLOOR_MS", "WRIT_JS_FLOOR_MS"] {
            std::env::remove_var(k);
        }
        let cfg = load_config(&p);
        assert_eq!(cfg.port, DEFAULT_PORT, "garbage file → defaults, not a crash");
    }

    /// `set_network_exposed` flips ONLY `[server].network_exposed` while preserving every other
    /// on-disk field (read-modify-write, not a clobber from a boot snapshot), and the flip survives
    /// a re-load. Default stays loopback-only (false).
    #[test]
    fn set_network_exposed_persists_and_preserves_other_fields() {
        let dir = tempfile::tempdir().unwrap();
        let p = Paths::at(dir.path().join(".writ"));
        p.ensure_dirs().unwrap();
        for k in ["WRIT_PORT", "WRIT_NETWORK_EXPOSE", "WRIT_TELEMETRY", "WRIT_USE_KEYRING"] {
            std::env::remove_var(k);
        }

        // Seed a file with non-default neighbors so we can prove they survive the flip.
        std::fs::write(
            p.config_toml(),
            "schema_version = 1\n[server]\nport = 9191\n[app]\ntelemetry_opt_in = true\n[security]\nuse_keyring = false\n",
        )
        .unwrap();

        // Default reflects loopback-only until flipped.
        assert!(!load_config(&p).network_exposed);

        set_network_exposed(&p, true).unwrap();
        let after = load_config(&p);
        assert!(after.network_exposed, "flag is now on");
        assert_eq!(after.port, 9191, "port preserved");
        assert!(after.telemetry_opt_in, "telemetry preserved");
        assert!(!after.use_keyring, "use_keyring preserved");

        // Flip back off.
        set_network_exposed(&p, false).unwrap();
        assert!(!load_config(&p).network_exposed, "flag is off again");

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(p.config_toml()).unwrap().permissions().mode();
            assert_eq!(mode & 0o777, 0o600, "writer keeps the 0600 mode");
        }
    }

    /// `set_cloud_agent` maps `enabled` to `[cloud_link].agent_disabled = !enabled`, persists the
    /// supply-pool opt-in, and preserves every other on-disk field (read-modify-write). The agent is
    /// default-ON (disable flag off) so a fresh file yields `cloud_agent_disabled == false`.
    #[test]
    fn set_cloud_agent_persists_toggles_and_preserves_other_fields() {
        let dir = tempfile::tempdir().unwrap();
        let p = Paths::at(dir.path().join(".writ"));
        p.ensure_dirs().unwrap();
        for k in ["WRIT_PORT", "WRIT_CLOUD_AGENT_DISABLED", "WRIT_SUPPLY_POOL", "WRIT_TELEMETRY"] {
            std::env::remove_var(k);
        }

        // Seed a file with non-default neighbors so we can prove they survive the writes.
        std::fs::write(
            p.config_toml(),
            "schema_version = 1\n[server]\nport = 9292\n[app]\ntelemetry_opt_in = true\n",
        )
        .unwrap();

        // Default: agent is on-when-linked (disable flag off) and supply pool off.
        let base = load_config(&p);
        assert!(!base.cloud_agent_disabled, "default: agent not disabled");
        assert!(!base.supply_pool_opt_in, "default: supply pool off");

        // Disable the agent + opt into the supply pool.
        set_cloud_agent(&p, false, true).unwrap();
        let after = load_config(&p);
        assert!(after.cloud_agent_disabled, "enabled=false ⇒ disable flag on");
        assert!(after.supply_pool_opt_in, "supply pool opt-in persisted");
        assert_eq!(after.port, 9292, "port preserved");
        assert!(after.telemetry_opt_in, "telemetry preserved");

        // Re-enable (disable flag off), keep supply pool off.
        set_cloud_agent(&p, true, false).unwrap();
        let after = load_config(&p);
        assert!(!after.cloud_agent_disabled, "enabled=true ⇒ disable flag off");
        assert!(!after.supply_pool_opt_in, "supply pool opt-out persisted");

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(p.config_toml()).unwrap().permissions().mode();
            assert_eq!(mode & 0o777, 0o600, "writer keeps the 0600 mode");
        }
    }

    /// `set_retention_days` flips ONLY `[app].retention_days` while preserving every other on-disk
    /// field, and the flip survives a re-load.
    #[test]
    fn set_retention_days_persists_and_preserves_other_fields() {
        let dir = tempfile::tempdir().unwrap();
        let p = Paths::at(dir.path().join(".writ"));
        p.ensure_dirs().unwrap();
        for k in ["WRIT_PORT", "WRIT_RETENTION_DAYS", "WRIT_TELEMETRY", "WRIT_NETWORK_EXPOSE"] {
            std::env::remove_var(k);
        }

        // Seed a file with non-default neighbors so we can prove they survive the flip.
        std::fs::write(
            p.config_toml(),
            "schema_version = 1\n[server]\nport = 9191\nnetwork_exposed = true\n[app]\ntelemetry_opt_in = true\n",
        )
        .unwrap();

        set_retention_days(&p, 7).unwrap();
        let after = load_config(&p);
        assert_eq!(after.retention_days, 7, "retention persisted");
        assert_eq!(after.port, 9191, "port preserved");
        assert!(after.telemetry_opt_in, "telemetry preserved");
        assert!(after.network_exposed, "network_exposed preserved");

        // 0 (keep-everything) round-trips too.
        set_retention_days(&p, 0).unwrap();
        assert_eq!(load_config(&p).retention_days, 0);
    }

    /// `set_onboarding_completed` + `set_language` each flip ONLY their field while preserving every
    /// other on-disk field, and the flips survive a re-load. Empty language is rejected.
    #[test]
    fn onboarding_and_language_persist_and_preserve_other_fields() {
        let _g = test_env_guard();
        let dir = tempfile::tempdir().unwrap();
        let p = Paths::at(dir.path().join(".writ"));
        p.ensure_dirs().unwrap();
        for k in ["WRIT_PORT", "WRIT_ONBOARDING_COMPLETED", "WRIT_LANGUAGE", "WRIT_TELEMETRY", "WRIT_RETENTION_DAYS"] {
            std::env::remove_var(k);
        }

        // Seed a file with non-default neighbors so we can prove they survive the flips.
        std::fs::write(
            p.config_toml(),
            "schema_version = 1\n[server]\nport = 9191\n[app]\ntelemetry_opt_in = true\nretention_days = 7\n",
        )
        .unwrap();

        // Fresh: not completed, default language.
        let before = load_config(&p);
        assert!(!before.onboarding_completed);
        assert_eq!(before.language, DEFAULT_LANGUAGE);

        // Complete the wizard.
        set_onboarding_completed(&p, true).unwrap();
        let after = load_config(&p);
        assert!(after.onboarding_completed, "completion persisted");
        assert_eq!(after.port, 9191, "port preserved");
        assert!(after.telemetry_opt_in, "telemetry preserved");
        assert_eq!(after.retention_days, 7, "retention preserved");
        assert_eq!(after.language, DEFAULT_LANGUAGE, "language untouched by completion write");

        // Set a language; completion + neighbors survive.
        set_language(&p, "es").unwrap();
        let after = load_config(&p);
        assert_eq!(after.language, "es", "language persisted");
        assert!(after.onboarding_completed, "completion preserved through the language write");
        assert_eq!(after.port, 9191, "port still preserved");

        // A blank language is a bad request and leaves disk intact.
        assert!(matches!(set_language(&p, "   "), Err(LocalError::BadRequest(_))));
        assert_eq!(load_config(&p).language, "es", "rejected write left disk intact");

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(p.config_toml()).unwrap().permissions().mode();
            assert_eq!(mode & 0o777, 0o600, "writers keep the 0600 mode");
        }
    }

    /// `set_runtime_settings` persists the engine/browser/monitor knobs (clamped) while preserving
    /// every OTHER on-disk field, and the clamp mirrors the governor + anti-detection floors.
    #[test]
    fn set_runtime_settings_persists_clamped_and_preserves_other_fields() {
        let _g = test_env_guard();
        let dir = tempfile::tempdir().unwrap();
        let p = Paths::at(dir.path().join(".writ"));
        p.ensure_dirs().unwrap();
        for k in [
            "WRIT_PORT", "WRIT_MAX_CONCURRENT_RUNS", "WRIT_MAX_BACKGROUND_RUNS",
            "WRIT_RSS_SOFT_WATERMARK_MB", "WRIT_HEADLESS", "WRIT_HTML_FLOOR_MS", "WRIT_JS_FLOOR_MS",
            "WRIT_NETWORK_EXPOSE", "WRIT_TELEMETRY", "WRIT_RETENTION_DAYS",
        ] {
            std::env::remove_var(k);
        }

        // Seed a file with non-default neighbors so we can prove they survive the write.
        std::fs::write(
            p.config_toml(),
            "schema_version = 1\n[server]\nport = 9191\nnetwork_exposed = true\n[app]\ntelemetry_opt_in = true\nretention_days = 7\n",
        )
        .unwrap();

        // Absurd/out-of-range values → clamped on persist.
        let req = RuntimeSettings {
            max_concurrent_runs: 100_000,
            max_background_runs: 100_000,
            rss_soft_watermark_mb: 10, // non-zero but below the floor
            browser_headless: false,
            browser_disable_sandbox: true,
            browser_ignore_certificate_errors: false,
            browser_disable_web_security: true,
            browser_use_local_chrome: true,
            html_floor_ms: 1, // below the hard content floor
            js_floor_ms: 1,   // below the hard browser floor
        };
        set_runtime_settings(&p, &req).unwrap();

        let after = load_config(&p);
        assert_eq!(after.max_concurrent_runs, MAX_CONCURRENT_RUNS_CEILING, "ceiling capped");
        assert!(after.browser_disable_sandbox, "dangerous browser toggle round-trips (persisted)");
        assert!(!after.browser_ignore_certificate_errors, "unset dangerous toggle stays off");
        assert!(after.browser_disable_web_security, "dangerous browser toggle round-trips (persisted)");
        assert!(after.browser_use_local_chrome, "local-chrome toggle round-trips (persisted)");
        assert_eq!(after.max_background_runs, MAX_CONCURRENT_RUNS_CEILING, "bg clamped to ceiling");
        assert_eq!(after.rss_soft_watermark_mb, MIN_RSS_SOFT_WATERMARK_MB, "tiny watermark raised");
        assert!(!after.browser_headless, "headless persisted");
        assert_eq!(after.html_floor_ms, HTML_FLOOR_MS, "sub-floor content interval raised to the floor");
        assert_eq!(after.js_floor_ms, JS_FLOOR_MS, "sub-floor browser interval raised to the floor");
        // A raised floor round-trips (the user can slow checks down).
        set_runtime_settings(&p, &RuntimeSettings { html_floor_ms: 300_000, ..RuntimeSettings::from_local(&after) }).unwrap();
        assert_eq!(load_config(&p).html_floor_ms, 300_000, "raised content floor persisted");
        // Neighbors preserved (read-modify-write, not a clobber).
        assert_eq!(after.port, 9191, "port preserved");
        assert!(after.network_exposed, "network_exposed preserved");
        assert!(after.telemetry_opt_in, "telemetry preserved");
        assert_eq!(after.retention_days, 7, "retention preserved");

        // A `0` watermark (shedding disabled) is a legal value and is preserved verbatim.
        let disabled = RuntimeSettings { rss_soft_watermark_mb: 0, ..RuntimeSettings::from_local(&after) };
        set_runtime_settings(&p, &disabled).unwrap();
        assert_eq!(load_config(&p).rss_soft_watermark_mb, 0, "0 disables shedding");
    }
}
