use std::path::{Path, PathBuf};
use anyhow::{Context, Result};
use tracing::{info, warn};

/// Known cache directories where Playwright/Patchright store browser binaries.
const CACHE_DIRS: &[&str] = &[
    "~/.cache/ms-playwright",
    "~/.cache/patchright",
    "~/Library/Caches/ms-playwright",
    "~/Library/Caches/patchright",
    "/root/.cache/ms-playwright",
    "/root/.cache/patchright",
];

/// Chromium directory names to look for inside each cache dir.
const CHROMIUM_DIRS: &[&str] = &["chromium", "chromium-", "chrome"];

/// Expand `~` to the user's home directory.
fn expand_home(path: &str) -> PathBuf {
    if let Some(stripped) = path.strip_prefix("~/") {
        if let Some(home) = dirs_home() {
            return home.join(stripped);
        }
    }
    PathBuf::from(path)
}

fn dirs_home() -> Option<PathBuf> {
    std::env::var("HOME").ok().map(PathBuf::from)
}

/// Check whether a usable Chromium binary already exists in known cache paths.
fn find_installed_browser() -> bool {
    for cache_dir in CACHE_DIRS {
        let base = expand_home(cache_dir);
        if !base.exists() {
            continue;
        }
        // Check for chromium-* directories (e.g. chromium-1148, chrome)
        for entry in std::fs::read_dir(&base).into_iter().flatten().flatten() {
            let name = entry.file_name();
            let name_str = name.to_string_lossy();
            for pattern in CHROMIUM_DIRS {
                if name_str.starts_with(pattern) && entry.path().is_dir() {
                    info!(path = %entry.path().display(), "Found installed browser");
                    return true;
                }
            }
        }
    }
    false
}

/// Ensure a Chromium browser is installed.
///
/// Locate patchright's bundled Playwright driver — returns `(node_exe, cli_js)`.
///
/// patchright is a stealth-patched Playwright fork. Driving ITS driver from
/// playwright-rs removes the vanilla `Runtime.enable` call, which is both the #1
/// anti-bot detection signature AND the source of the `Runtime.*`/console event
/// flood that makes per-action latency huge on heavy sites. patchright bundles
/// playwright-core 1.60 (the exact protocol playwright-rs 0.13 targets), so the
/// Rust bindings drive it unchanged — they just go through patchright's stealth
/// layer underneath.
///
/// Resolution, in order: `WRIT_PATCHRIGHT_DRIVER` (operator override → a `.../driver` dir),
/// `WRIT_BUNDLED_DRIVER` (what an installer shipped), a
/// `patchright-driver/` shipped NEXT TO the executable (or under `WRIT_HOME`) so a release needs no
/// Python at all, then `python3`/`python -c "import patchright"` to find an installed package, then
/// common site-packages globs. Returns `None` when nothing is found, so the caller transparently
/// falls back to the bundled vanilla driver.
pub fn find_patchright_driver() -> Option<(PathBuf, PathBuf)> {
    // 1. Explicit operator override — a `.../patchright/driver` directory.
    if let Ok(d) = std::env::var("WRIT_PATCHRIGHT_DRIVER") {
        if let Some(r) = driver_from_dir(Path::new(&d)) {
            return Some(r);
        }
    }
    // 2. The driver the INSTALLER bundled.
    //
    // The desktop app ships a patchright driver and hands the daemon `WRIT_BUNDLED_DRIVER`
    // ("wiring bundled patchright driver for writ-agentd"), but only `runtime_setup`'s
    // chromium-install resolver ever read that variable — this lookup checked a DIFFERENT name
    // (`WRIT_PATCHRIGHT_DRIVER`). So the bundle installed Chromium and was then ignored for the
    // stealth path: the daemon reported the driver as bundled while launching VANILLA. Read the
    // same variable here, with the same dir-or-node-exe tolerance `resolve_install_command` uses.
    if let Ok(raw) = std::env::var("WRIT_BUNDLED_DRIVER") {
        let p = PathBuf::from(raw);
        let dir = if p.is_dir() { p.clone() } else { p.parent().map(Path::to_path_buf).unwrap_or(p) };
        if let Some(r) = driver_from_dir(&dir) {
            return Some(r);
        }
    }
    // 3. A patchright driver that TRAVELS WITH the binary.
    //
    // Every probe below this point needs a Python interpreter that can `import patchright`. A
    // downloaded release binary / container image has no such interpreter, so a SHIPPED agent
    // always fell through to the vanilla driver — silently, since the fallback only logs a warning.
    // Vanilla leaves `Runtime.enable` on, which is an instant anti-bot tell, so the stealth path
    // existed but was dead in exactly the deployments that need it most. Probing a sibling
    // directory first lets the release drop the driver in with no Python anywhere in the image.
    for dir in sibling_patchright_candidates() {
        if let Some(r) = driver_from_dir(&dir) {
            return Some(r);
        }
    }
    // 4. Interpreters that can `import patchright`: the patchright CLI's OWN python
    //    (via its shebang — most reliable, it's by definition the env that has it),
    //    then python3 / python on PATH.
    let mut interps: Vec<String> = Vec::new();
    if let Some(py) = patchright_cli_python() {
        interps.push(py);
    }
    interps.push("python3".to_string());
    interps.push("python".to_string());
    for py in interps {
        if let Some(dir) = py_patchright_driver_dir(&py) {
            if let Some(r) = driver_from_dir(&dir) {
                return Some(r);
            }
        }
    }
    // 5. Glob common site-packages layouts (user-site + nearby venvs).
    for dir in candidate_patchright_dirs() {
        if let Some(r) = driver_from_dir(&dir) {
            return Some(r);
        }
    }
    None
}

/// Directory name a PATCHRIGHT (stealth) driver shipped alongside the binary uses.
/// Kept next to [`SIBLING_DRIVER_DIRNAME`] because the same three things must agree on it: this
/// lookup, the release archive layout, and the container image. Deliberately a DIFFERENT directory
/// from the vanilla one so a release can carry both and the stealth driver is chosen on merit
/// rather than by overwriting.
pub const SIBLING_PATCHRIGHT_DIRNAME: &str = "patchright-driver";

/// Candidate directories for a bundled patchright driver, most specific first.
///
/// SECURITY: mirrors [`sibling_driver_candidates`] exactly — the resolved `node` is EXECUTED, so
/// every candidate is anchored to the running executable's own directory or `WRIT_HOME`, never to
/// the CWD and never to anything remote.
fn sibling_patchright_candidates() -> Vec<PathBuf> {
    let mut out = Vec::new();
    if let Ok(exe) = std::env::current_exe() {
        if let Some(dir) = exe.parent() {
            out.push(dir.join(SIBLING_PATCHRIGHT_DIRNAME));
        }
    }
    let writ_home = std::env::var("WRIT_HOME")
        .ok()
        .map(PathBuf::from)
        .or_else(|| dirs_home().map(|h| h.join(".writ")));
    if let Some(home) = writ_home {
        out.push(home.join(SIBLING_PATCHRIGHT_DIRNAME));
    }
    out
}

/// Directory name a driver shipped **alongside** the binary is expected to use.
/// Kept in one place because three things must agree on it: this lookup, the release archive
/// layout (`.github/workflows/release.yml`), and the container image (`Dockerfile`).
pub const SIBLING_DRIVER_DIRNAME: &str = "playwright-driver";

/// Locate a vanilla Playwright driver that TRAVELS WITH the binary.
///
/// `vendor/playwright-rs`'s build script bakes an **absolute** path to whatever driver it used —
/// either the build's `OUT_DIR` or the builder's `~/.cache/playwright-rs-driver/…`. Both are paths
/// on the machine that *compiled* the binary. The vendored resolver checks that path with
/// `.exists()`, so on any other machine it simply misses, and the only remaining fallbacks are an
/// `npm` Playwright on `PATH` or the `playwright-rs install` user cache — neither of which someone
/// who downloaded a release binary (or pulled the container image) has. The failure surfaces late,
/// as `ServerNotFound` on the first browser launch, long after startup looked healthy.
///
/// So probe for a driver directory shipped next to the executable — the layout the release archives
/// and the container image use — and then under `WRIT_HOME`, so an operator can drop one in without
/// repackaging. Returns `(node, cli.js)`, or `None` when nothing usable is present.
pub fn find_sibling_driver() -> Option<(PathBuf, PathBuf)> {
    for dir in sibling_driver_candidates() {
        if let Some(r) = driver_from_dir(&dir) {
            return Some(r);
        }
    }
    None
}

/// Candidate directories for [`find_sibling_driver`], most specific first.
///
/// SECURITY: the resolved `node` is later EXECUTED, so every candidate is anchored to a path the
/// operator controls — the directory the running executable was launched from, or `WRIT_HOME`.
/// Nothing here is derived from the current working directory or from any remote input.
fn sibling_driver_candidates() -> Vec<PathBuf> {
    let mut out = Vec::new();
    if let Ok(exe) = std::env::current_exe() {
        if let Some(dir) = exe.parent() {
            out.push(dir.join(SIBLING_DRIVER_DIRNAME));
        }
    }
    let writ_home = std::env::var("WRIT_HOME")
        .ok()
        .map(PathBuf::from)
        .or_else(|| dirs_home().map(|h| h.join(".writ")));
    if let Some(home) = writ_home {
        out.push(home.join(SIBLING_DRIVER_DIRNAME));
    }
    out
}

/// Validate a patchright `driver` dir, returning `(node, cli.js)` if both exist.
fn driver_from_dir(dir: &Path) -> Option<(PathBuf, PathBuf)> {
    let node = if cfg!(windows) {
        dir.join("node.exe")
    } else {
        dir.join("node")
    };
    let cli = dir.join("package").join("cli.js");
    if node.exists() && cli.exists() {
        Some((node, cli))
    } else {
        None
    }
}

/// Run `<py> -c "import patchright"` and return its bundled `driver` dir.
fn py_patchright_driver_dir(py: &str) -> Option<PathBuf> {
    let out = std::process::Command::new(py)
        .args([
            "-c",
            "import patchright,os;print(os.path.join(os.path.dirname(patchright.__file__),'driver'),end='')",
        ])
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    let p = PathBuf::from(String::from_utf8_lossy(&out.stdout).trim().to_string());
    if p.is_dir() {
        Some(p)
    } else {
        None
    }
}

/// The interpreter that backs the `patchright` CLI (read from its shebang), so we
/// import from the exact env that installed patchright even when it's a venv not
/// otherwise on PATH for `python3`.
fn patchright_cli_python() -> Option<String> {
    let out = std::process::Command::new("which").arg("patchright").output().ok()?;
    if !out.status.success() {
        return None;
    }
    let cli = String::from_utf8_lossy(&out.stdout).trim().to_string();
    if cli.is_empty() {
        return None;
    }
    // SECURITY: `which` follows $PATH, which an attacker who controls the launch
    // environment can poison. We read the CLI's shebang and later EXECUTE that
    // interpreter, so only trust a CLI resolved from an operator-controlled root
    // (HOME or WRIT_HOME) — never a cwd-relative or otherwise-attacker-placed path.
    let cli_path = std::fs::canonicalize(&cli).ok()?;
    if !path_under_trusted_root(&cli_path) {
        warn!(cli = %cli_path.display(), "ignoring `patchright` from an untrusted PATH location");
        return None;
    }
    let first = std::fs::read_to_string(&cli_path).ok()?;
    first.lines().next()?.strip_prefix("#!").map(|s| s.trim().to_string())
}

/// True if `p` lives under an operator-controlled root we're willing to execute
/// code from (HOME, WRIT_HOME). Paths must be canonicalized before this check so
/// `..` traversal can't escape the trusted prefix.
fn path_under_trusted_root(p: &Path) -> bool {
    let mut roots: Vec<PathBuf> = Vec::new();
    if let Ok(home) = std::env::var("HOME") {
        roots.push(PathBuf::from(home));
    }
    if let Ok(writ_home) = std::env::var("WRIT_HOME") {
        roots.push(PathBuf::from(writ_home));
    }
    roots
        .iter()
        .filter_map(|r| std::fs::canonicalize(r).ok())
        .any(|root| p.starts_with(&root))
}

/// Common site-packages locations to probe for `patchright/driver` when no
/// interpreter on PATH can import it (user-site installs, project venvs).
fn candidate_patchright_dirs() -> Vec<PathBuf> {
    const TAIL: &str = "site-packages/patchright/driver";
    let mut out = Vec::new();
    // For each child of `base` whose name starts with `prefix`, push child/<sub>.
    let glob = |out: &mut Vec<PathBuf>, base: PathBuf, prefix: &str, sub: &str| {
        if let Ok(rd) = std::fs::read_dir(&base) {
            for e in rd.flatten() {
                if e.file_name().to_string_lossy().starts_with(prefix) {
                    out.push(e.path().join(sub));
                }
            }
        }
    };
    if let Ok(home) = std::env::var("HOME") {
        let home = PathBuf::from(home);
        // macOS user-site: ~/Library/Python/<ver>/lib/python/site-packages/...
        glob(&mut out, home.join("Library/Python"), "", &format!("lib/python/{TAIL}"));
        // Linux user-site: ~/.local/lib/python<ver>/site-packages/...
        glob(&mut out, home.join(".local/lib"), "python", TAIL);
    }
    // A venv under WRIT_HOME (operator-controlled), if one exists. SECURITY: never
    // probe cwd-relative `./.venv` / `./*/.venv` — the daemon may be launched from
    // an attacker-controlled directory, and we later EXECUTE the resolved node/cli.js.
    // Driver dirs must come only from trusted, operator-controlled roots.
    if let Ok(writ_home) = std::env::var("WRIT_HOME") {
        glob(&mut out, PathBuf::from(writ_home).join(".venv/lib"), "python", TAIL);
    }
    out
}

/// Decide the browser DRIVER before launch.
///
/// If patchright's stealth driver is already present, there's nothing to do —
/// `BrowserManager::initialize()` will pick it up. If it's NOT present and we're
/// on an interactive terminal, ask the user to choose: install patchright
/// (stealth, recommended) or continue with regular Playwright (more easily
/// flagged by anti-bot + slower on heavy pages). Non-interactive runs
/// (service/daemon) are never blocked — they warn and continue on the bundled
/// vanilla driver, overridable via `patchright install` / `WRIT_PATCHRIGHT_DRIVER`.
pub async fn ensure_stealth_driver() {
    if find_patchright_driver().is_some() {
        info!("patchright stealth driver detected — anti-bot stealth enabled");
        return;
    }

    use std::io::{IsTerminal, Write};

    if !std::io::stdin().is_terminal() {
        warn!(
            "patchright (stealth) driver not found — using regular Playwright, which is \
             more easily detected by anti-bot systems and slower on heavy pages. Install \
             patchright or set WRIT_PATCHRIGHT_DRIVER to enable stealth."
        );
        return;
    }

    println!();
    println!("  \x1b[33m⚠  Stealth driver (patchright) not found.\x1b[0m");
    println!("     Regular Playwright is easily flagged by anti-bot systems (Cloudflare,");
    println!("     DataDome, …) and is slower to react on heavy pages.");
    println!();
    println!("     [1] Install patchright now  \x1b[2m(recommended — enables stealth)\x1b[0m");
    println!("     [2] Continue with regular Playwright");
    print!("  Choose [1/2] (default 1): ");
    let _ = std::io::stdout().flush();

    let mut input = String::new();
    let _ = std::io::stdin().read_line(&mut input);

    if input.trim() == "2" {
        warn!("Continuing with regular (non-stealth) Playwright by user choice.");
        return;
    }

    // default / "1" → best-effort install of the patchright package (which ships
    // the stealth driver). The browser binary is handled by ensure_browser_installed
    // / the chrome channel, so we only need the package here.
    println!("  Installing patchright …");
    let installed = try_install_command("python3", &["-m", "pip", "install", "--upgrade", "patchright"])
        .await
        .unwrap_or(false);

    if installed && find_patchright_driver().is_some() {
        println!("  \x1b[32m✓ patchright installed — stealth enabled.\x1b[0m");
    } else {
        warn!(
            "Could not auto-install patchright — continuing with regular Playwright. \
             Install it manually with:  python3 -m pip install patchright  (or point \
             WRIT_PATCHRIGHT_DRIVER at an existing patchright driver dir)."
        );
    }
}

/// First checks well-known cache directories. If no browser is found, attempts
/// to install via `patchright install chromium` (preferred) then falls back to
/// `playwright install chromium`. Returns `true` when a browser is available
/// after the call.
pub async fn ensure_browser_installed() -> Result<bool> {
    if find_installed_browser() {
        info!("Browser already installed");
        return Ok(true);
    }

    warn!("No installed browser found — attempting install");

    // Try patchright first (stealth-patched Chromium)
    if try_install_command("patchright", &["install", "chromium"]).await? {
        info!("Installed Chromium via patchright");
        return Ok(true);
    }

    // Fall back to playwright
    if try_install_command("playwright", &["install", "chromium"]).await? {
        info!("Installed Chromium via playwright");
        return Ok(true);
    }

    // Try npx variants
    if try_install_command("npx", &["patchright", "install", "chromium"]).await? {
        info!("Installed Chromium via npx patchright");
        return Ok(true);
    }

    anyhow::bail!("Failed to install Chromium via any known method")
}

/// Run an install command with a 300-second timeout. Returns `true` on success.
async fn try_install_command(program: &str, args: &[&str]) -> Result<bool> {
    info!(cmd = program, ?args, "Running install command");

    let result = tokio::time::timeout(
        std::time::Duration::from_secs(300),
        tokio::process::Command::new(program)
            .args(args)
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .context(format!("Failed to spawn {program}"))?
            .wait_with_output(),
    )
    .await;

    match result {
        Ok(Ok(output)) => {
            if output.status.success() {
                Ok(true)
            } else {
                let stderr = String::from_utf8_lossy(&output.stderr);
                warn!(cmd = program, %stderr, "Install command failed");
                Ok(false)
            }
        }
        Ok(Err(e)) => {
            warn!(cmd = program, error = %e, "Install command error");
            Ok(false)
        }
        Err(_) => {
            warn!(cmd = program, "Install command timed out after 300s");
            Ok(false)
        }
    }
}

#[cfg(test)]
mod tests {

    /// Serializes every env-mutating test in this module.
    ///
    /// `local::config::test_env_guard` is gated behind the `local` feature, which is NOT in
    /// `default` — so under a plain `cargo test` it compiled to nothing and these tests raced each
    /// other on `HOME`/`WRIT_HOME` (process-global). The symptom was a failing assertion in a test
    /// that had not changed, which reads like a real regression rather than a flake. This lock is
    /// unconditional, so it holds for every feature combination.
    static ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
    fn env_lock() -> std::sync::MutexGuard<'static, ()> {
        // Do not let one panicking test poison the rest of the module.
        ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner())
    }

    use super::*;

    #[test]
    fn trusted_root_rejects_paths_outside_writ_home() {
        // Serialize with every other test that mutates the process-global HOME/WRIT_HOME env — this
        // test both overrides WRIT_HOME and REMOVES HOME, which would otherwise race a concurrent
        // test's `Paths::resolve()` (e.g. the backup snapshot opening the wrong keyed DB). The shared
        // guard lives in `local::config`; the WRIT_HOME-based tests it serializes with only exist in
        // the `local` build, so the guard is only needed there.
        let _lock = env_lock();
        #[cfg(feature = "local")]
        let _g = crate::local::config::test_env_guard();
        // A poisoned $PATH could resolve `patchright` anywhere; only paths under a
        // canonicalized operator root must be trusted.
        let tmp = std::env::temp_dir().join(format!("writ_trust_test_{}", std::process::id()));
        let inside = tmp.join("bin").join("patchright");
        std::fs::create_dir_all(inside.parent().unwrap()).unwrap();
        std::fs::write(&inside, b"#!/usr/bin/python3\n").unwrap();

        // Preserve and override the env for a deterministic check. The guard is what makes
        // "preserve and restore" actually deterministic: HOME/WRIT_HOME are process-global, so
        // without it a sibling test mutating them on another thread lands mid-assertion.
        let _lock = env_lock();
        #[cfg(feature = "local")]
        let _g = crate::local::config::test_env_guard();

        let prev_home = std::env::var("HOME").ok();
        let prev_writ = std::env::var("WRIT_HOME").ok();
        std::env::set_var("WRIT_HOME", &tmp);
        std::env::remove_var("HOME");

        let inside_c = std::fs::canonicalize(&inside).unwrap();
        assert!(path_under_trusted_root(&inside_c), "path under WRIT_HOME must be trusted");

        // A world-writable path outside any trusted root must be rejected.
        let outside = std::fs::canonicalize(std::env::temp_dir()).unwrap();
        assert!(!path_under_trusted_root(&outside), "path outside trusted roots must be rejected");

        // Restore.
        match prev_home {
            Some(v) => std::env::set_var("HOME", v),
            None => std::env::remove_var("HOME"),
        }
        match prev_writ {
            Some(v) => std::env::set_var("WRIT_HOME", v),
            None => std::env::remove_var("WRIT_HOME"),
        }
        let _ = std::fs::remove_dir_all(&tmp);
    }

    /// The release archives and the container image both lay the driver out as
    /// `<exe dir>/playwright-driver`, and a binary that cannot find it starts, connects and reports
    /// healthy before failing every run at browser launch — a failure mode no smoke test catches.
    /// Pin the two things that make that layout work: the directory NAME, and the fact that
    /// `WRIT_HOME` is the documented second place to drop one.
    #[test]
    fn sibling_driver_is_found_next_to_the_executable_and_under_writ_home() {
        let _lock = env_lock();
        #[cfg(feature = "local")]
        let _g = crate::local::config::test_env_guard();

        let tmp = std::env::temp_dir().join(format!("writ_sibling_driver_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&tmp);

        // A directory is only a driver once BOTH files are there — a half-extracted archive must
        // not be accepted, or the failure moves to `node` exiting with a parse error.
        let dir = tmp.join(SIBLING_DRIVER_DIRNAME);
        std::fs::create_dir_all(dir.join("package")).unwrap();
        assert!(driver_from_dir(&dir).is_none(), "empty dir must not pass as a driver");
        let node_name = if cfg!(windows) { "node.exe" } else { "node" };
        std::fs::write(dir.join(node_name), b"").unwrap();
        assert!(driver_from_dir(&dir).is_none(), "node without cli.js must not pass");
        std::fs::write(dir.join("package").join("cli.js"), b"").unwrap();
        let (node, cli) = driver_from_dir(&dir).expect("node + cli.js is a driver");
        assert_eq!(node, dir.join(node_name));
        assert_eq!(cli, dir.join("package").join("cli.js"));

        // `WRIT_HOME/playwright-driver` must be among the probed candidates.
        let prev_writ = std::env::var("WRIT_HOME").ok();
        std::env::set_var("WRIT_HOME", &tmp);
        assert!(
            sibling_driver_candidates().contains(&dir),
            "WRIT_HOME/{SIBLING_DRIVER_DIRNAME} must be a candidate, got {:?}",
            sibling_driver_candidates()
        );
        assert_eq!(
            find_sibling_driver().map(|(n, _)| n),
            Some(dir.join(node_name)),
            "a driver under WRIT_HOME must resolve"
        );

        // The executable's own directory is the FIRST candidate — that is the release-archive and
        // container layout, and it must not be reachable only through WRIT_HOME.
        let exe_dir = std::env::current_exe().ok().and_then(|e| e.parent().map(|p| p.to_path_buf()));
        if let Some(exe_dir) = exe_dir {
            assert_eq!(
                sibling_driver_candidates().first(),
                Some(&exe_dir.join(SIBLING_DRIVER_DIRNAME)),
                "the executable's directory must be probed first"
            );
        }

        match prev_writ {
            Some(v) => std::env::set_var("WRIT_HOME", v),
            None => std::env::remove_var("WRIT_HOME"),
        }
        let _ = std::fs::remove_dir_all(&tmp);
    }

    /// A release ships the stealth driver next to the binary; no Python is involved. This pins the
    /// directory name the release archive must use — if it drifts, a shipped agent silently falls
    /// back to the vanilla driver (Runtime.enable on = detectable), which is exactly the failure
    /// this lookup was added to end.
    #[test]
    fn sibling_patchright_dir_is_probed_from_writ_home() {
        // `WRIT_HOME` is process-global and several tests in this file drive it. Without the shared
        // guard this races them (they run on parallel threads), which is exactly how it first went
        // red — a flake, not a real failure, and the worst kind to leave behind.
        let _lock = env_lock();
        #[cfg(feature = "local")]
        let _g = crate::local::config::test_env_guard();

        let tmp = std::env::temp_dir().join(format!("writ-pr-{}", std::process::id()));
        let dir = tmp.join(SIBLING_PATCHRIGHT_DIRNAME);
        std::fs::create_dir_all(dir.join("package")).unwrap();
        let node = dir.join(if cfg!(windows) { "node.exe" } else { "node" });
        std::fs::write(&node, b"").unwrap();
        std::fs::write(dir.join("package").join("cli.js"), b"").unwrap();

        // SAFETY: single-threaded test process; restored immediately below.
        let prev = std::env::var_os("WRIT_HOME");
        std::env::set_var("WRIT_HOME", &tmp);
        let found = sibling_patchright_candidates()
            .into_iter()
            .find_map(|d| driver_from_dir(&d));
        match prev {
            Some(v) => std::env::set_var("WRIT_HOME", v),
            None => std::env::remove_var("WRIT_HOME"),
        }
        std::fs::remove_dir_all(&tmp).ok();

        let (n, c) = found.expect("a patchright driver under WRIT_HOME must be found");
        assert_eq!(n, node);
        assert!(c.ends_with("package/cli.js") || c.ends_with("package\\cli.js"));
    }

    /// The stealth and vanilla sibling directories must stay DISTINCT, so a release can carry both
    /// and the stealth one wins on merit instead of one silently overwriting the other.
    #[test]
    fn sibling_driver_dirnames_are_distinct() {
        assert_ne!(SIBLING_PATCHRIGHT_DIRNAME, SIBLING_DRIVER_DIRNAME);
    }
}
