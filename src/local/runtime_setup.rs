//! First-run RUNTIME readiness — Chromium + patchright-driver detection and a best-effort
//! "install Chromium" orchestration for the desktop onboarding wizard.
//!
//! This is the testable core behind the `/v1/runtime/*` REST surface (see
//! [`crate::local::api::v1::runtime`]). It answers two questions the first-run setup needs:
//!
//!   * Is a usable **Chromium** present, and where did it come from?
//!       - `bundled` — the Tauri shell exported `WRIT_BUNDLED_CHROMIUM` to a path that exists (a
//!         Chromium shipped inside the app bundle's resource dir).
//!       - `system`  — no bundled Chromium, but a playwright/patchright-installed (or genuine system)
//!         Chromium executable resolves on disk.
//!       - `none`    — neither resolves; the wizard offers to install one.
//!   * Is the **patchright driver** bundled? `driver.bundled` reflects `WRIT_BUNDLED_DRIVER` (set by
//!     the shell when the driver resource exists). The driver is ALWAYS shipped, so it is reported but
//!     NEVER offered for install — only Chromium is installable.
//!
//! Install: `POST /v1/runtime/install-chromium` spawns the bundled driver's "install chromium" CLI as
//! a background task and streams coarse progress into a process-global [`InstallProgress`] cell that
//! `GET /v1/runtime/install-chromium/progress` polls. Output is parsed best-effort for a percentage;
//! when none is visible, `percent` stays `null` and the wizard shows an indeterminate spinner.
//!
//! House style: no `async-trait`; `thiserror` lives at the API edge (this module returns plain values
//! / `std::io`); `tracing` only, and we NEVER log a secret (this surface carries none — only public
//! filesystem paths and process output, which is itself scrubbed by the log sink).
//!
//! Net-new Rust in this crate (behind the `local` feature).

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, OnceLock};
use std::time::Duration;

use serde::Serialize;

/// Env var the Tauri shell sets to the bundled Chromium executable path when that resource exists in
/// the app bundle. Presence + an existing path ⇒ `chromium.source = "bundled"`.
pub const ENV_BUNDLED_CHROMIUM: &str = "WRIT_BUNDLED_CHROMIUM";
/// Env var the Tauri shell sets to the bundled patchright-driver dir/exe when that resource exists.
/// Presence + an existing path ⇒ `driver.bundled = true`. The driver is always shipped — never
/// offered for install.
pub const ENV_BUNDLED_DRIVER: &str = "WRIT_BUNDLED_DRIVER";

// ---------------------------------------------------------------------------------------------
// Detection — the GET /v1/runtime/status payload.
// ---------------------------------------------------------------------------------------------

/// Where a resolved Chromium came from. Serializes to the fixed contract strings.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum ChromiumSource {
    /// A Chromium shipped inside the app bundle (`WRIT_BUNDLED_CHROMIUM` set + exists).
    Bundled,
    /// A playwright/patchright-installed or genuine system Chromium resolved on disk.
    System,
    /// No Chromium resolves anywhere — the wizard offers to install one.
    None,
}

/// Chromium half of the runtime status. `available` is `source != none`; `path` is the resolved
/// executable/marker path when known (always set for `bundled`, best-effort for `system`, `null` for
/// `none`).
#[derive(Debug, Clone, Serialize)]
pub struct ChromiumStatus {
    pub available: bool,
    pub source: ChromiumSource,
    pub path: Option<String>,
    /// Best-effort browser version line (e.g. "Chromium 124.0.6367.60") probed from the resolved
    /// executable (`<exe> --version`). `None` when unresolved or the probe failed/timed out. Cached
    /// per-path so the status endpoint never re-spawns the subprocess on every poll.
    pub version: Option<String>,
}

/// Patchright-driver half of the runtime status. `bundled` reflects `WRIT_BUNDLED_DRIVER`; the driver
/// is always shipped, so this is informational only — never an install affordance.
#[derive(Debug, Clone, Serialize)]
pub struct DriverStatus {
    pub bundled: bool,
    pub path: Option<String>,
    /// Best-effort driver version from the driver package's `package.json` (`<dir>/package/package.json`
    /// or `<dir>/package.json`). `None` when not bundled or unreadable.
    pub version: Option<String>,
}

/// The full `GET /v1/runtime/status` body.
#[derive(Debug, Clone, Serialize)]
pub struct RuntimeStatus {
    pub chromium: ChromiumStatus,
    pub driver: DriverStatus,
}

/// Resolve a non-empty env var to a path that exists on disk. Returns `None` for unset/empty/missing.
fn existing_env_path(key: &str) -> Option<PathBuf> {
    let raw = std::env::var_os(key)?;
    if raw.is_empty() {
        return None;
    }
    let p = PathBuf::from(raw);
    if p.exists() {
        Some(p)
    } else {
        None
    }
}

/// Detect the Chromium posture per the fixed contract:
///   1. `WRIT_BUNDLED_CHROMIUM` set AND the path exists ⇒ `bundled`.
///   2. else a playwright/patchright-installed or system Chromium executable resolves ⇒ `system`.
///   3. else ⇒ `none`.
pub fn detect_chromium() -> ChromiumStatus {
    if let Some(p) = existing_env_path(ENV_BUNDLED_CHROMIUM) {
        return ChromiumStatus {
            available: true,
            source: ChromiumSource::Bundled,
            version: chromium_version_cached(&p),
            path: Some(p.to_string_lossy().into_owned()),
        };
    }
    if let Some(p) = resolve_system_chromium() {
        return ChromiumStatus {
            available: true,
            source: ChromiumSource::System,
            version: chromium_version_cached(&p),
            path: Some(p.to_string_lossy().into_owned()),
        };
    }
    ChromiumStatus { available: false, source: ChromiumSource::None, path: None, version: None }
}

/// Detect the bundled patchright driver per the fixed contract: `WRIT_BUNDLED_DRIVER` set + exists.
/// Never resolves a "system" driver — the bundled driver is the only one this reports for setup.
pub fn detect_driver() -> DriverStatus {
    match existing_env_path(ENV_BUNDLED_DRIVER) {
        Some(p) => DriverStatus {
            bundled: true,
            version: driver_version(&p),
            path: Some(p.to_string_lossy().into_owned()),
        },
        None => DriverStatus { bundled: false, path: None, version: None },
    }
}

/// Full status = chromium ⊕ driver.
pub fn detect_runtime() -> RuntimeStatus {
    RuntimeStatus { chromium: detect_chromium(), driver: detect_driver() }
}

// ---------------------------------------------------------------------------------------------
// Version probing — the best-effort `chromium.version` / `driver.version` fields.
// ---------------------------------------------------------------------------------------------

/// Process-global cache of `exe path → probed version`. The status endpoint is POLLED, so we run the
/// `--version` subprocess at most ONCE per resolved binary and serve the memoized answer thereafter.
/// Keyed by path so a Chromium installed later (a new `chromium-<rev>` dir) probes fresh.
fn chromium_version_cache() -> &'static Mutex<HashMap<PathBuf, Option<String>>> {
    static CELL: OnceLock<Mutex<HashMap<PathBuf, Option<String>>>> = OnceLock::new();
    CELL.get_or_init(|| Mutex::new(HashMap::new()))
}

/// Cached `<exe> --version`. Returns the memoized value when present, else probes once and stores it.
fn chromium_version_cached(exe: &Path) -> Option<String> {
    {
        let cache = chromium_version_cache().lock().unwrap_or_else(|e| e.into_inner());
        if let Some(hit) = cache.get(exe) {
            return hit.clone();
        }
    }
    let v = probe_chromium_version(exe);
    let mut cache = chromium_version_cache().lock().unwrap_or_else(|e| e.into_inner());
    cache.insert(exe.to_path_buf(), v.clone());
    v
}

/// Run `<exe> --version` on a detached thread with a bounded wait, returning the trimmed first output
/// line (e.g. "Chromium 124.0.6367.60"). Best-effort — a spawn error, non-zero exit, timeout, or empty
/// output all yield `None`. Never blocks the caller longer than the timeout; a genuinely hung binary
/// leaves its worker thread detached (harmless for a diagnostic probe).
fn probe_chromium_version(exe: &Path) -> Option<String> {
    let exe = exe.to_path_buf();
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let out = std::process::Command::new(&exe).arg("--version").output();
        let _ = tx.send(out);
    });
    let out = rx.recv_timeout(Duration::from_secs(3)).ok()?.ok()?;
    // `--version` prints to stdout; fall back to stderr for builds that emit there.
    let text = if out.stdout.is_empty() { out.stderr } else { out.stdout };
    let line = String::from_utf8_lossy(&text).lines().next().unwrap_or("").trim().to_string();
    // Only accept a line that actually carries a version number (avoids capturing warnings/banners).
    if line.is_empty() || !line.chars().any(|c| c.is_ascii_digit()) {
        return None;
    }
    Some(line)
}

/// Read the driver package version from `<dir>/package/package.json` (patchright/playwright driver
/// layout) or a bare `<dir>/package.json`. Accepts a dir OR the node exe path (normalizes to the dir).
/// Best-effort — returns `None` when no readable `package.json` with a string `version` is found.
fn driver_version(dir_or_exe: &Path) -> Option<String> {
    let dir = if dir_or_exe.is_dir() {
        dir_or_exe.to_path_buf()
    } else {
        dir_or_exe.parent()?.to_path_buf()
    };
    for pkg in [dir.join("package").join("package.json"), dir.join("package.json")] {
        if let Ok(raw) = std::fs::read_to_string(&pkg) {
            if let Ok(json) = serde_json::from_str::<serde_json::Value>(&raw) {
                if let Some(v) = json.get("version").and_then(|v| v.as_str()) {
                    if !v.is_empty() {
                        return Some(v.to_string());
                    }
                }
            }
        }
    }
    None
}

/// Known cache roots where Playwright/Patchright drop downloaded browser binaries. Mirrors
/// `crate::browser::install::CACHE_DIRS` but with `$HOME` expanded at runtime (so tests can point
/// `HOME` at a sandbox). `PLAYWRIGHT_BROWSERS_PATH`, when set, is probed FIRST.
fn chromium_cache_roots() -> Vec<PathBuf> {
    let mut roots = Vec::new();
    if let Some(custom) = std::env::var_os("PLAYWRIGHT_BROWSERS_PATH") {
        if !custom.is_empty() {
            roots.push(PathBuf::from(custom));
        }
    }
    if let Some(home) = dirs::home_dir() {
        for tail in [
            ".cache/ms-playwright",
            ".cache/patchright",
            "Library/Caches/ms-playwright",
            "Library/Caches/patchright",
            // Windows: %USERPROFILE%\AppData\Local\ms-playwright
            "AppData/Local/ms-playwright",
            "AppData/Local/patchright",
        ] {
            roots.push(home.join(tail));
        }
    }
    roots
}

/// The platform's relative path from a `chromium-*` browser dir to the actual launchable executable.
/// Best-effort: we return the FIRST candidate that exists. Mirrors Playwright's on-disk layout.
fn chromium_exe_candidates(browser_dir: &Path) -> Vec<PathBuf> {
    #[cfg(target_os = "macos")]
    {
        vec![
            browser_dir
                .join("chrome-mac/Chromium.app/Contents/MacOS/Chromium"),
            browser_dir
                .join("chrome-mac/Chromium.app/Contents/MacOS/Chrome"),
        ]
    }
    #[cfg(target_os = "windows")]
    {
        vec![
            browser_dir.join("chrome-win/chrome.exe"),
            browser_dir.join("chrome-win/headless_shell.exe"),
        ]
    }
    #[cfg(all(unix, not(target_os = "macos")))]
    {
        vec![
            browser_dir.join("chrome-linux/chrome"),
            browser_dir.join("chrome-linux/headless_shell"),
        ]
    }
    #[cfg(not(any(unix, windows)))]
    {
        let _ = browser_dir;
        Vec::new()
    }
}

/// Resolve a usable Chromium executable installed by playwright/patchright (or a genuine system
/// Chrome/Chromium). Returns the executable path when one exists on disk, else `None`.
///
/// Strategy:
///   1. Scan each cache root for `chromium*`/`chrome*` browser dirs and probe the per-OS executable
///      candidate inside (so `path` is the real launchable binary, not just the dir).
///   2. Fall back to a handful of well-known system Chrome/Chromium install locations.
pub fn resolve_system_chromium() -> Option<PathBuf> {
    for root in chromium_cache_roots() {
        if !root.is_dir() {
            continue;
        }
        for entry in std::fs::read_dir(&root).into_iter().flatten().flatten() {
            let name = entry.file_name();
            let name = name.to_string_lossy();
            let is_chromium_dir = name.starts_with("chromium") || name.starts_with("chrome");
            if !is_chromium_dir || !entry.path().is_dir() {
                continue;
            }
            for cand in chromium_exe_candidates(&entry.path()) {
                if cand.exists() {
                    return Some(cand);
                }
            }
        }
    }
    resolve_system_browser_binary()
}

/// Well-known absolute locations of a genuine system Chrome/Chromium executable, per OS. Probed only
/// after the playwright/patchright caches miss. These let a desktop with Chrome already installed skip
/// the download entirely.
fn resolve_system_browser_binary() -> Option<PathBuf> {
    #[cfg(target_os = "macos")]
    let candidates: &[&str] = &[
        "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
        "/Applications/Chromium.app/Contents/MacOS/Chromium",
        "/Applications/Microsoft Edge.app/Contents/MacOS/Microsoft Edge",
    ];
    #[cfg(all(unix, not(target_os = "macos")))]
    let candidates: &[&str] = &[
        "/usr/bin/google-chrome",
        "/usr/bin/google-chrome-stable",
        "/usr/bin/chromium",
        "/usr/bin/chromium-browser",
        "/snap/bin/chromium",
    ];
    #[cfg(target_os = "windows")]
    let candidates: &[&str] = &[
        r"C:\Program Files\Google\Chrome\Application\chrome.exe",
        r"C:\Program Files (x86)\Google\Chrome\Application\chrome.exe",
        r"C:\Program Files\Chromium\Application\chrome.exe",
    ];
    #[cfg(not(any(unix, windows)))]
    let candidates: &[&str] = &[];

    candidates.iter().map(PathBuf::from).find(|p| p.exists())
}

// ---------------------------------------------------------------------------------------------
// Install orchestration — POST /v1/runtime/install-chromium + the pollable progress cell.
// ---------------------------------------------------------------------------------------------

/// Coarse install lifecycle. Serializes to the fixed contract strings.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum InstallState {
    /// Never started (or finished + reset). The default before any install request.
    Idle,
    /// The driver's `install chromium` is running.
    Running,
    /// Chromium installed successfully and now resolves on disk.
    Done,
    /// The install failed (spawn error, non-zero exit, or a post-install resolve miss).
    Error,
}

/// A snapshot of the install progress — exactly the `GET …/progress` body.
#[derive(Debug, Clone, Serialize)]
pub struct InstallProgress {
    pub state: InstallState,
    /// 0–100 when a percentage is parseable from the driver output; `null` for indeterminate.
    pub percent: Option<u8>,
    /// A short, non-secret human status line (e.g. "downloading Chromium 124.0…", an error reason).
    pub message: Option<String>,
}

impl InstallProgress {
    fn idle() -> Self {
        Self { state: InstallState::Idle, percent: None, message: None }
    }
}

/// The process-global progress cell. The install runs as a detached background task, so its progress
/// lives outside `AppState` (which is cloned per-request and per-test); a single global mirrors how a
/// single-user daemon has exactly one install in flight. Reads (the progress GET) and writes (the
/// background task) both go through this `Mutex`.
fn progress_cell() -> &'static Mutex<InstallProgress> {
    static CELL: OnceLock<Mutex<InstallProgress>> = OnceLock::new();
    CELL.get_or_init(|| Mutex::new(InstallProgress::idle()))
}

/// Read the current install progress snapshot (cheap clone under the lock).
pub fn install_progress() -> InstallProgress {
    progress_cell().lock().unwrap_or_else(|e| e.into_inner()).clone()
}

/// Overwrite the progress snapshot (used by the background install task).
fn set_progress(state: InstallState, percent: Option<u8>, message: Option<String>) {
    let mut g = progress_cell().lock().unwrap_or_else(|e| e.into_inner());
    *g = InstallProgress { state, percent, message };
}

/// Begin a Chromium install IF one is not already running. Returns `true` when this call started a
/// fresh install, `false` when an install is already `Running` (idempotent — a second click is a
/// no-op, not a second download). Spawns the actual work on a detached background task so the POST
/// returns immediately; the wizard polls `…/progress` for completion.
///
/// `started=false` is also returned (with no spawn) when Chromium is ALREADY available — there is
/// nothing to install, and the wizard should treat the runtime as ready.
pub fn start_install_chromium() -> bool {
    // Already have a Chromium → nothing to do; reflect "done" so a poll resolves immediately.
    if detect_chromium().available {
        set_progress(InstallState::Done, Some(100), Some("Chromium already available".into()));
        return false;
    }
    {
        let mut g = progress_cell().lock().unwrap_or_else(|e| e.into_inner());
        if g.state == InstallState::Running {
            return false; // an install is already in flight — idempotent.
        }
        *g = InstallProgress {
            state: InstallState::Running,
            percent: None,
            message: Some("starting Chromium install…".into()),
        };
    }
    tokio::spawn(async move {
        run_install_chromium().await;
    });
    true
}

/// Drive the bundled driver's "install chromium" command, streaming coarse progress into the global
/// cell. Best-effort percentage parsing from the child's stdout/stderr; a non-zero exit or a
/// post-install resolve miss lands `Error`.
///
/// Resolution of the install command, in order:
///   1. The BUNDLED patchright driver (`WRIT_BUNDLED_DRIVER`): invoke its node CLI as
///      `<driver>/node <driver>/package/cli.js install chromium` (the patchright/playwright driver's
///      own installer entrypoint). This is the path that works in a shipped app where only the bundled
///      driver — never a system `patchright`/`playwright` — is guaranteed present.
///   2. Fallbacks (dev machines): `patchright install chromium`, then `playwright install chromium`.
async fn run_install_chromium() {
    let cmd = match resolve_install_command() {
        Some(c) => c,
        None => {
            set_progress(
                InstallState::Error,
                None,
                Some("no Chromium installer found (bundled driver missing)".into()),
            );
            return;
        }
    };

    tracing::info!(program = %cmd.program.to_string_lossy(), "starting Chromium install");
    match spawn_and_stream(cmd).await {
        Ok(()) => {
            // Verify the install actually produced a resolvable Chromium before declaring success.
            let status = detect_chromium();
            if !status.available {
                set_progress(
                    InstallState::Error,
                    None,
                    Some("installer finished but no Chromium resolved".into()),
                );
                tracing::warn!("Chromium install finished but nothing resolved on disk");
                return;
            }
            // Integrity gate (fail-closed): the downloaded browser executable must match a
            // compiled-in SHA-256 pin for its revision + platform. A mismatch OR a missing pin
            // refuses the install, exactly like the "nothing resolved" branch above — we never
            // let an unverified binary reach `Done`.
            if let Err(reason) = verify_downloaded_chromium(&status) {
                set_progress(InstallState::Error, None, Some(reason.clone()));
                tracing::warn!(reason = %reason, "Chromium integrity verification failed; refusing install");
                return;
            }
            set_progress(InstallState::Done, Some(100), Some("Chromium ready".into()));
            tracing::info!("Chromium install complete");
        }
        Err(e) => {
            set_progress(InstallState::Error, None, Some(format!("install failed: {e}")));
            tracing::warn!(error = %e, "Chromium install failed");
        }
    }
}

// ---------------------------------------------------------------------------------------------
// Download integrity (fail-closed) — verify the installed Chromium against a compiled-in pin.
// ---------------------------------------------------------------------------------------------

/// The compiled-in SHA-256 pin table, embedded from `resources/engine/chromium-pins.json`.
/// Keyed `chromium-revision -> { platform-key -> lowercase-hex sha256 }`. Compiled INTO the binary
/// (never fetched) so an attacker who tampers with the downloaded browser cannot also supply a
/// matching hash. See the file's own `_TODO` for the placeholder-hash caveat.
const CHROMIUM_PINS_JSON: &str = include_str!("../../resources/engine/chromium-pins.json");

/// The all-zero SHA-256 used as the PLACEHOLDER in `chromium-pins.json`. A pin whose value is this
/// sentinel is treated as "not yet a real pin" → fail-closed (never satisfied by a real binary,
/// whose digest is astronomically never all-zero). Lets the shipped table compile and the gate stay
/// closed until real hashes are filled in, without a special "is this a placeholder" flag.
const CHROMIUM_PIN_PLACEHOLDER: &str =
    "0000000000000000000000000000000000000000000000000000000000000000";

/// The platform key for the running target, matching the `chromium-pins.json` / AUTO_UPDATE.md
/// artifact keys (`macos-aarch64` | `macos-x86_64` | `windows-x86_64` | `linux-x86_64`). `None` on a
/// target we have no pins for — which the caller treats as fail-closed (no pin ⇒ refuse).
fn current_platform_key() -> Option<&'static str> {
    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    {
        Some("macos-aarch64")
    }
    #[cfg(all(target_os = "macos", target_arch = "x86_64"))]
    {
        Some("macos-x86_64")
    }
    #[cfg(all(target_os = "windows", target_arch = "x86_64"))]
    {
        Some("windows-x86_64")
    }
    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    {
        Some("linux-x86_64")
    }
    #[cfg(not(any(
        all(target_os = "macos", target_arch = "aarch64"),
        all(target_os = "macos", target_arch = "x86_64"),
        all(target_os = "windows", target_arch = "x86_64"),
        all(target_os = "linux", target_arch = "x86_64"),
    )))]
    {
        None
    }
}

/// Extract the patchright/playwright Chromium REVISION from a resolved executable path — the `NNNN`
/// in a `chromium-NNNN` cache dir component (e.g. `.../ms-playwright/chromium-1148/chrome-mac/…`).
/// Returns the revision string when a `chromium-<rev>` path segment is present, else `None` (a genuine
/// system Chrome — `/Applications/Google Chrome.app/…` — has no such segment; the caller fails closed
/// because there is no revision to pin against).
fn chromium_revision_from_path(exe: &Path) -> Option<String> {
    for comp in exe.components() {
        let seg = comp.as_os_str().to_string_lossy();
        if let Some(rev) = seg.strip_prefix("chromium-") {
            if !rev.is_empty() {
                return Some(rev.to_string());
            }
        }
    }
    None
}

/// Look up the pinned lowercase-hex SHA-256 for `(revision, platform_key)` in the embedded table.
/// Returns `None` when the JSON is unparseable, the revision is absent, the platform is absent, the
/// value is not a string, OR the value is the all-zero placeholder — every one of which the caller
/// treats as "no usable pin" ⇒ fail-closed.
fn pinned_chromium_sha256(revision: &str, platform_key: &str) -> Option<String> {
    let json: serde_json::Value = serde_json::from_str(CHROMIUM_PINS_JSON).ok()?;
    let pin = json
        .get("pins")?
        .get(revision)?
        .get(platform_key)?
        .as_str()?
        .trim()
        .to_ascii_lowercase();
    if pin.is_empty() || pin == CHROMIUM_PIN_PLACEHOLDER {
        return None;
    }
    Some(pin)
}

/// Compute the lowercase-hex SHA-256 of a file's bytes (streamed, so a ~200 MB browser binary never
/// materializes fully in memory). `Err` on any read/open failure.
fn sha256_hex_of_file(path: &Path) -> std::io::Result<String> {
    use sha2::{Digest, Sha256};
    use std::io::Read;

    let mut f = std::fs::File::open(path)?;
    let mut hasher = Sha256::new();
    let mut buf = [0u8; 64 * 1024];
    loop {
        let n = f.read(&mut buf)?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    let digest = hasher.finalize();
    let mut hex = String::with_capacity(digest.len() * 2);
    for b in digest {
        use std::fmt::Write;
        let _ = write!(hex, "{b:02x}");
    }
    Ok(hex)
}

/// Fail-closed integrity check for a freshly-installed Chromium. Resolves the launchable executable
/// from `status`, derives its revision from the on-disk path, computes the SHA-256 of the binary, and
/// compares it to the compiled-in pin for `(revision, current platform)`.
///
/// Returns `Ok(())` ONLY when a real (non-placeholder) pin exists AND the computed digest matches it
/// byte-for-byte. Every other outcome — unresolved path, unknown platform, no `chromium-<rev>` segment,
/// missing/placeholder pin, read failure, or a digest MISMATCH — returns `Err(non-secret reason)` so
/// the caller lands `InstallState::Error` and refuses to proceed. The reason string is safe to surface
/// (public paths / revision / platform only; never a secret).
fn verify_downloaded_chromium(status: &ChromiumStatus) -> Result<(), String> {
    let path = status
        .path
        .as_deref()
        .ok_or_else(|| "integrity check: installed Chromium path is unknown".to_string())?;
    let exe = Path::new(path);

    let platform_key = current_platform_key()
        .ok_or_else(|| "integrity check: no Chromium pin for this platform".to_string())?;

    let revision = chromium_revision_from_path(exe).ok_or_else(|| {
        "integrity check: could not determine Chromium revision from the install path".to_string()
    })?;

    let pinned = pinned_chromium_sha256(&revision, platform_key).ok_or_else(|| {
        format!(
            "integrity check: no pinned SHA-256 for Chromium revision {revision} on {platform_key} (refusing unverified browser)"
        )
    })?;

    let actual = sha256_hex_of_file(exe)
        .map_err(|e| format!("integrity check: could not read installed Chromium: {e}"))?;

    if actual == pinned {
        tracing::info!(revision = %revision, platform = %platform_key, "Chromium integrity pin verified");
        Ok(())
    } else {
        // Non-secret: revision + platform + both digests are public integrity metadata.
        Err(format!(
            "integrity check: Chromium SHA-256 mismatch for revision {revision} on {platform_key} (expected {pinned}, got {actual})"
        ))
    }
}

/// A resolved install invocation: the program plus its args (and any env the driver CLI needs).
struct InstallCommand {
    program: PathBuf,
    args: Vec<String>,
    /// Extra env (k, v) — e.g. pointing the driver at its bundled node. Never secrets.
    envs: Vec<(String, String)>,
}

/// Pick the install command per the resolution order above. Returns `None` only when nothing
/// installable is found (no bundled driver AND no dev `patchright`/`playwright` on PATH).
fn resolve_install_command() -> Option<InstallCommand> {
    // 1. Bundled patchright driver: <driver>/node <driver>/package/cli.js install chromium.
    if let Some(driver_dir) = existing_env_path(ENV_BUNDLED_DRIVER) {
        // `WRIT_BUNDLED_DRIVER` may point at the driver DIR or directly at the node exe; handle both.
        let driver_dir = if driver_dir.is_dir() {
            driver_dir
        } else {
            driver_dir.parent().map(Path::to_path_buf).unwrap_or(driver_dir)
        };
        let node = driver_dir.join(if cfg!(windows) { "node.exe" } else { "node" });
        let cli = driver_dir.join("package").join("cli.js");
        if node.exists() && cli.exists() {
            return Some(InstallCommand {
                program: node,
                args: vec![
                    cli.to_string_lossy().into_owned(),
                    "install".into(),
                    "chromium".into(),
                ],
                envs: Vec::new(),
            });
        }
        // TODO(install-cli): if a future bundled driver lays the CLI out differently (e.g. a single
        // `patchright` shim instead of node+cli.js), resolve that entrypoint here. The orchestration
        // (spawn → stream → verify) is layout-independent; only THIS resolver needs the exact path.
        tracing::warn!(
            dir = %driver_dir.display(),
            "WRIT_BUNDLED_DRIVER set but node/cli.js not found in the expected layout"
        );
    }

    // 2. Dev-machine fallbacks: a `patchright` / `playwright` CLI on PATH.
    for prog in ["patchright", "playwright"] {
        if command_on_path(prog) {
            return Some(InstallCommand {
                program: PathBuf::from(prog),
                args: vec!["install".into(), "chromium".into()],
                envs: Vec::new(),
            });
        }
    }
    None
}

/// Is `program` resolvable on `PATH`? Uses `which`/`where` (no extra crate dep), best-effort.
fn command_on_path(program: &str) -> bool {
    let finder = if cfg!(windows) { "where" } else { "which" };
    std::process::Command::new(finder)
        .arg(program)
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

/// Spawn the install child, stream its merged output line-by-line, and update progress as a percentage
/// becomes visible. Returns `Ok(())` on a zero exit, `Err` on spawn failure or a non-zero exit.
async fn spawn_and_stream(cmd: InstallCommand) -> std::io::Result<()> {
    use tokio::process::Command;

    let mut command = Command::new(&cmd.program);
    command
        .args(&cmd.args)
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped());
    for (k, v) in &cmd.envs {
        command.env(k, v);
    }
    let mut child = command.spawn()?;

    // Stream stdout + stderr concurrently; the driver writes progress to either depending on TTY.
    // `pump_lines` is generic over the reader type so it serves both the (distinct) stdout/stderr
    // handle types from one definition.
    let stdout = child.stdout.take();
    let stderr = child.stderr.take();
    let (_, _, status) = tokio::join!(pump_lines(stdout), pump_lines(stderr), child.wait());
    let status = status?;
    if status.success() {
        Ok(())
    } else {
        Err(std::io::Error::other(
            format!("installer exited with status {status}"),
        ))
    }
}

/// Read an optional child pipe line-by-line, folding any visible percentage / status into the global
/// progress cell. Generic over the concrete reader (stdout vs stderr have distinct types in tokio).
async fn pump_lines<R>(reader: Option<R>)
where
    R: tokio::io::AsyncRead + Unpin,
{
    use tokio::io::{AsyncBufReadExt, BufReader};
    let Some(r) = reader else { return };
    let mut lines = BufReader::new(r).lines();
    while let Ok(Some(line)) = lines.next_line().await {
        if let Some(pct) = parse_percent(&line) {
            set_progress(InstallState::Running, Some(pct), Some(short_line(&line)));
        } else if let Some(msg) = parse_status_line(&line) {
            set_progress(InstallState::Running, current_percent(), Some(msg));
        }
    }
}

/// The last-seen percent (so a non-percent status line doesn't clobber the bar back to indeterminate).
fn current_percent() -> Option<u8> {
    progress_cell().lock().unwrap_or_else(|e| e.into_inner()).percent
}

/// Best-effort: pull a `NN%` percentage out of a driver output line (e.g. Playwright prints
/// `|████      | 42% of 168.4 MiB`). Returns `0..=100` or `None`.
fn parse_percent(line: &str) -> Option<u8> {
    let bytes = line.as_bytes();
    // Find a '%' and walk back over the preceding digits.
    let pct_idx = line.find('%')?;
    let mut start = pct_idx;
    while start > 0 && bytes[start - 1].is_ascii_digit() {
        start -= 1;
    }
    if start == pct_idx {
        return None; // no digits before '%'
    }
    line[start..pct_idx].parse::<u32>().ok().map(|n| n.min(100) as u8)
}

/// Best-effort: surface a short human status from a recognizable driver line (downloading/extracting),
/// so the wizard shows *something* even before a percentage appears. `None` for noise we skip.
fn parse_status_line(line: &str) -> Option<String> {
    let l = line.trim();
    if l.is_empty() {
        return None;
    }
    let lower = l.to_ascii_lowercase();
    if lower.contains("download") || lower.contains("install") || lower.contains("chromium") {
        Some(short_line(l))
    } else {
        None
    }
}

/// Clamp a status line to a reasonable length for the UI (the full line still goes to the log sink,
/// which scrubs it). Never carries a secret — driver output is install progress, not credentials.
fn short_line(line: &str) -> String {
    let t = line.trim();
    if t.chars().count() > 120 {
        t.chars().take(117).collect::<String>() + "…"
    } else {
        t.to_string()
    }
}

#[cfg(test)]
pub(crate) fn reset_install_progress_for_test() {
    set_progress(InstallState::Idle, None, None);
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `WRIT_BUNDLED_CHROMIUM` pointing at an existing path ⇒ `source = bundled` + `available`.
    #[test]
    fn bundled_chromium_detected_when_env_set_to_existing_path() {
        let _g = crate::local::config::test_env_guard();
        let dir = tempfile::tempdir().unwrap();
        // A plain file standing in for the bundled Chromium executable.
        let exe = dir.path().join("Chromium");
        std::fs::write(&exe, b"#!/bin/sh\n").unwrap();
        std::env::set_var(ENV_BUNDLED_CHROMIUM, &exe);

        let st = detect_chromium();
        assert!(st.available);
        assert_eq!(st.source, ChromiumSource::Bundled);
        assert_eq!(st.path.as_deref(), Some(exe.to_string_lossy().as_ref()));

        std::env::remove_var(ENV_BUNDLED_CHROMIUM);
    }

    /// `WRIT_BUNDLED_CHROMIUM` set to a path that does NOT exist must NOT report `bundled` (it falls
    /// through to system/none detection — the contract requires the path to exist).
    #[test]
    fn bundled_chromium_ignored_when_path_missing() {
        let _g = crate::local::config::test_env_guard();
        std::env::set_var(ENV_BUNDLED_CHROMIUM, "/writ/definitely/not/here/Chromium");
        let st = detect_chromium();
        assert_ne!(st.source, ChromiumSource::Bundled, "missing path must not count as bundled");
        std::env::remove_var(ENV_BUNDLED_CHROMIUM);
    }

    /// With no bundled Chromium and the cache roots pointed at an EMPTY sandbox (no system browser
    /// resolvable), detection asserts `none` loosely — we only assert it is NOT `bundled`, since a CI
    /// host may legitimately have a real system Chrome installed at a well-known path.
    #[test]
    fn no_bundled_chromium_is_not_bundled() {
        let _g = crate::local::config::test_env_guard();
        std::env::remove_var(ENV_BUNDLED_CHROMIUM);
        // Redirect HOME + the playwright browsers path at an empty sandbox so the cache scan misses.
        let dir = tempfile::tempdir().unwrap();
        let prev_home = std::env::var_os("HOME");
        let prev_pw = std::env::var_os("PLAYWRIGHT_BROWSERS_PATH");
        std::env::set_var("HOME", dir.path());
        std::env::set_var("PLAYWRIGHT_BROWSERS_PATH", dir.path().join("empty"));

        let st = detect_chromium();
        assert_ne!(st.source, ChromiumSource::Bundled);
        // available iff a real system browser binary happens to exist on the CI host — either way it
        // is never `bundled` here, and `available == (source != none)`.
        assert_eq!(st.available, st.source != ChromiumSource::None);

        match prev_home {
            Some(v) => std::env::set_var("HOME", v),
            None => std::env::remove_var("HOME"),
        }
        match prev_pw {
            Some(v) => std::env::set_var("PLAYWRIGHT_BROWSERS_PATH", v),
            None => std::env::remove_var("PLAYWRIGHT_BROWSERS_PATH"),
        }
    }

    /// A playwright-style cache layout (`<root>/chromium-1148/chrome-*/…`) resolves as `system` with
    /// the executable path. Uses `PLAYWRIGHT_BROWSERS_PATH` to point the scan at a sandbox.
    #[test]
    fn system_chromium_resolves_from_cache_layout() {
        let _g = crate::local::config::test_env_guard();
        std::env::remove_var(ENV_BUNDLED_CHROMIUM);
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("ms-playwright");
        let browser = root.join("chromium-1148");

        // Lay down the per-OS executable so the resolver finds a real path.
        #[cfg(target_os = "macos")]
        let exe = browser.join("chrome-mac/Chromium.app/Contents/MacOS/Chromium");
        #[cfg(target_os = "windows")]
        let exe = browser.join("chrome-win/chrome.exe");
        #[cfg(all(unix, not(target_os = "macos")))]
        let exe = browser.join("chrome-linux/chrome");
        #[cfg(not(any(unix, windows)))]
        let exe = browser.join("chrome");

        std::fs::create_dir_all(exe.parent().unwrap()).unwrap();
        std::fs::write(&exe, b"binary").unwrap();

        let prev_pw = std::env::var_os("PLAYWRIGHT_BROWSERS_PATH");
        std::env::set_var("PLAYWRIGHT_BROWSERS_PATH", &root);

        let resolved = resolve_system_chromium();
        // On the exotic `not(unix/windows)` target there are no candidates; skip the assert there.
        #[cfg(any(unix, windows))]
        {
            assert_eq!(resolved.as_deref(), Some(exe.as_path()), "resolved the cache executable");
            let st = detect_chromium();
            assert_eq!(st.source, ChromiumSource::System);
            assert!(st.available);
        }
        #[cfg(not(any(unix, windows)))]
        let _ = resolved;

        match prev_pw {
            Some(v) => std::env::set_var("PLAYWRIGHT_BROWSERS_PATH", v),
            None => std::env::remove_var("PLAYWRIGHT_BROWSERS_PATH"),
        }
    }

    /// `driver.bundled` mirrors `WRIT_BUNDLED_DRIVER` (set+exists ⇒ true; unset ⇒ false).
    #[test]
    fn driver_bundled_reflects_env() {
        let _g = crate::local::config::test_env_guard();
        std::env::remove_var(ENV_BUNDLED_DRIVER);
        assert!(!detect_driver().bundled, "unset ⇒ not bundled");

        let dir = tempfile::tempdir().unwrap();
        std::env::set_var(ENV_BUNDLED_DRIVER, dir.path());
        let d = detect_driver();
        assert!(d.bundled, "set+exists ⇒ bundled");
        assert_eq!(d.path.as_deref(), Some(dir.path().to_string_lossy().as_ref()));

        std::env::remove_var(ENV_BUNDLED_DRIVER);
    }

    /// `driver_version` reads `<dir>/package/package.json` (playwright driver layout) and also a bare
    /// `<dir>/package.json`, and returns `None` when neither carries a string version.
    #[test]
    fn driver_version_reads_package_json() {
        // Standard driver layout: <dir>/package/package.json.
        let dir = tempfile::tempdir().unwrap();
        let pkg = dir.path().join("package");
        std::fs::create_dir_all(&pkg).unwrap();
        std::fs::write(pkg.join("package.json"), r#"{"name":"playwright-core","version":"1.47.2"}"#)
            .unwrap();
        assert_eq!(driver_version(dir.path()).as_deref(), Some("1.47.2"));

        // Bare <dir>/package.json also works.
        let dir2 = tempfile::tempdir().unwrap();
        std::fs::write(dir2.path().join("package.json"), r#"{"version":"1.0.0"}"#).unwrap();
        assert_eq!(driver_version(dir2.path()).as_deref(), Some("1.0.0"));

        // No package.json ⇒ None.
        let empty = tempfile::tempdir().unwrap();
        assert_eq!(driver_version(empty.path()), None);
    }

    /// `chromium_version_cached` runs the binary's `--version` once and memoizes it. Uses a tiny
    /// executable stub so the test needs no real browser (unix-only: relies on a `+x` shell script).
    #[cfg(unix)]
    #[test]
    fn chromium_version_probes_and_caches() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let exe = dir.path().join("fake-chromium");
        std::fs::write(&exe, "#!/bin/sh\necho 'Chromium 124.0.6367.60'\n").unwrap();
        std::fs::set_permissions(&exe, std::fs::Permissions::from_mode(0o755)).unwrap();

        let v = chromium_version_cached(&exe);
        assert_eq!(v.as_deref(), Some("Chromium 124.0.6367.60"));
        // Second call is served from the cache (same answer; no re-spawn observable here).
        assert_eq!(chromium_version_cached(&exe), v);
    }

    /// A binary whose `--version` prints no digits (or a spawn failure) yields `None`.
    #[cfg(unix)]
    #[test]
    fn chromium_version_none_without_digits() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let exe = dir.path().join("no-version");
        std::fs::write(&exe, "#!/bin/sh\necho 'no version banner'\n").unwrap();
        std::fs::set_permissions(&exe, std::fs::Permissions::from_mode(0o755)).unwrap();
        assert_eq!(chromium_version_cached(&exe), None);

        // A path that isn't executable can't be probed → None.
        assert_eq!(probe_chromium_version(dir.path().join("does-not-exist").as_path()), None);
    }

    /// Percent parsing pulls `NN%` out of representative driver output and clamps to 100.
    #[test]
    fn parse_percent_extracts_and_clamps() {
        assert_eq!(parse_percent("|████      | 42% of 168.4 MiB"), Some(42));
        assert_eq!(parse_percent("Downloading Chromium 124.0 - 0% of 168 MiB"), Some(0));
        assert_eq!(parse_percent("done 100%"), Some(100));
        assert_eq!(parse_percent("weird 250%"), Some(100), "clamped to 100");
        assert_eq!(parse_percent("no percentage here"), None);
        assert_eq!(parse_percent("just a % sign"), None, "no digits before %");
    }

    /// The embedded pin table parses and its shipped placeholder pins are treated as "no pin" so the
    /// gate stays fail-closed until real hashes are filled in.
    #[test]
    fn embedded_pins_parse_and_placeholder_is_no_pin() {
        // The compiled-in JSON must always parse (a broken file would brick the install path).
        let json: serde_json::Value = serde_json::from_str(CHROMIUM_PINS_JSON).unwrap();
        assert!(json.get("pins").is_some(), "pins table present");
        // The shipped placeholder revision resolves to NO usable pin on any platform key.
        for plat in ["macos-aarch64", "macos-x86_64", "windows-x86_64", "linux-x86_64"] {
            assert!(
                pinned_chromium_sha256("1148", plat).is_none(),
                "placeholder pin for {plat} must count as no-pin (fail-closed)"
            );
        }
        // An unknown revision is likewise no-pin.
        assert!(pinned_chromium_sha256("does-not-exist", "linux-x86_64").is_none());
    }

    /// The revision is read from a `chromium-<rev>` path segment; a path without one (a genuine
    /// system Chrome) yields `None`.
    #[test]
    fn revision_parsed_from_chromium_dir_segment() {
        let p = Path::new("/home/u/.cache/ms-playwright/chromium-1148/chrome-linux/chrome");
        assert_eq!(chromium_revision_from_path(p).as_deref(), Some("1148"));

        let sys = Path::new("/Applications/Google Chrome.app/Contents/MacOS/Google Chrome");
        assert_eq!(chromium_revision_from_path(sys), None);
    }

    /// `verify_downloaded_chromium` FAILS CLOSED when the only available pin for the resolved
    /// revision/platform is the placeholder (or the revision is absent) — a real binary must never
    /// slip through unverified.
    #[test]
    fn verify_fails_closed_on_missing_or_placeholder_pin() {
        let dir = tempfile::tempdir().unwrap();
        // A `chromium-1148` layout so a revision IS parsed — the only reason to reject is the
        // placeholder (all-zero) pin.
        let exe = dir.path().join("chromium-1148").join("browser-bin");
        std::fs::create_dir_all(exe.parent().unwrap()).unwrap();
        std::fs::write(&exe, b"pretend-chromium-bytes").unwrap();

        let status = ChromiumStatus {
            available: true,
            source: ChromiumSource::System,
            path: Some(exe.to_string_lossy().into_owned()),
            version: None,
        };
        let err = verify_downloaded_chromium(&status).unwrap_err();
        assert!(err.contains("integrity check"), "non-secret reason: {err}");

        // No `chromium-<rev>` segment ⇒ no revision ⇒ also fail-closed.
        let sys = ChromiumStatus {
            available: true,
            source: ChromiumSource::System,
            path: Some("/Applications/Google Chrome.app/Contents/MacOS/Google Chrome".into()),
            version: None,
        };
        assert!(verify_downloaded_chromium(&sys).is_err());
    }

    /// `sha256_hex_of_file` streams the correct lowercase-hex digest for known bytes (the empty file
    /// has the canonical SHA-256 of the empty string).
    #[test]
    fn sha256_hex_of_file_matches_known_vector() {
        let dir = tempfile::tempdir().unwrap();
        let f = dir.path().join("empty");
        std::fs::write(&f, b"").unwrap();
        assert_eq!(
            sha256_hex_of_file(&f).unwrap(),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    /// The progress cell defaults to idle and round-trips set/read.
    #[test]
    fn progress_cell_roundtrips() {
        let _g = crate::local::config::test_env_guard();
        reset_install_progress_for_test();
        let p = install_progress();
        assert_eq!(p.state, InstallState::Idle);
        assert!(p.percent.is_none());

        set_progress(InstallState::Running, Some(33), Some("downloading".into()));
        let p = install_progress();
        assert_eq!(p.state, InstallState::Running);
        assert_eq!(p.percent, Some(33));
        assert_eq!(p.message.as_deref(), Some("downloading"));

        reset_install_progress_for_test();
    }

    /// `start_install_chromium` short-circuits to `done` (returns false, no spawn) when a Chromium is
    /// already available — there is nothing to install.
    #[tokio::test]
    async fn start_install_short_circuits_when_already_available() {
        let _g = crate::local::config::test_env_guard();
        reset_install_progress_for_test();
        let dir = tempfile::tempdir().unwrap();
        let exe = dir.path().join("Chromium");
        std::fs::write(&exe, b"#!/bin/sh\n").unwrap();
        std::env::set_var(ENV_BUNDLED_CHROMIUM, &exe);

        let started = start_install_chromium();
        assert!(!started, "already-available ⇒ no install started");
        assert_eq!(install_progress().state, InstallState::Done);

        std::env::remove_var(ENV_BUNDLED_CHROMIUM);
        reset_install_progress_for_test();
    }

    /// A LIVE Chromium download via the real bundled/system driver. Ignored by default — it touches
    /// the network and writes hundreds of MB. Run explicitly with:
    ///   `cargo test --features local -- --ignored runtime_setup::tests::live_install_chromium`
    /// Requires `WRIT_BUNDLED_DRIVER` (or a `patchright`/`playwright` on PATH) to be resolvable.
    #[tokio::test]
    #[ignore = "downloads a real Chromium over the network (hundreds of MB)"]
    async fn live_install_chromium() {
        let _g = crate::local::config::test_env_guard();
        reset_install_progress_for_test();
        std::env::remove_var(ENV_BUNDLED_CHROMIUM); // force an actual install path

        let started = start_install_chromium();
        assert!(started, "install should start when no Chromium is present");

        // Poll up to ~5 minutes for a terminal state.
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(300);
        loop {
            let p = install_progress();
            if matches!(p.state, InstallState::Done | InstallState::Error) {
                assert_eq!(p.state, InstallState::Done, "install ended in error: {:?}", p.message);
                break;
            }
            if std::time::Instant::now() > deadline {
                panic!("install did not finish within 5 minutes (last: {:?})", p);
            }
            tokio::time::sleep(std::time::Duration::from_secs(2)).await;
        }
        reset_install_progress_for_test();
    }
}
