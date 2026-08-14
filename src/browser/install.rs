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

/// The user's home directory.
///
/// `HOME` IS NOT SET ON WINDOWS. Reading only `HOME` made every home-derived candidate in this
/// module resolve to `None` on the one platform whose driver resolution has repeatedly failed —
/// silently, because each caller treats `None` as "not present" rather than "could not look".
/// Windows exposes the home directory as `USERPROFILE` (and, on domain-joined machines, as
/// `HOMEDRIVE` + `HOMEPATH`), so fall through those before giving up.
fn dirs_home() -> Option<PathBuf> {
    if let Some(h) = std::env::var_os("HOME").filter(|v| !v.is_empty()) {
        return Some(PathBuf::from(h));
    }
    if let Some(h) = std::env::var_os("USERPROFILE").filter(|v| !v.is_empty()) {
        return Some(PathBuf::from(h));
    }
    match (std::env::var_os("HOMEDRIVE"), std::env::var_os("HOMEPATH")) {
        (Some(drive), Some(path)) if !drive.is_empty() && !path.is_empty() => {
            // `drive` is already an `OsString` from `var_os`; wrapping it in `OsString::from`
            // is a no-op that clippy rejects under -D warnings.
            let mut p = drive;
            p.push(path);
            Some(PathBuf::from(p))
        }
        _ => None,
    }
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
    // 1/2/2b — the driver this app SHIPS. One resolver, shared with `runtime_setup` (see
    // [`bundled_driver_dir`]): the operator override, the shell's env var, and exe-relative
    // discovery all live there so the stealth driver, the runtime-status payload and the Chromium
    // installer can never again disagree about whether a bundled driver exists.
    if let Some(dir) = bundled_driver_dir() {
        if let Some(r) = driver_from_dir(&dir) {
            return Some(r);
        }
    }
    // Nothing bundled resolved. Say EXACTLY what was inspected before falling through to the Python
    // probes (which never succeed in a shipped app) and ultimately to the compile-time baked driver
    // path — a path on the CI machine that does not exist here, so the client sits waiting on a
    // driver that never handshakes and the whole thing surfaces as an opaque "Playwright timeout"
    // instead of "no driver". Twice now the resolution has been debugged by hand because the daemon
    // reported nothing; a shipped build has to be able to answer "where did you look?" from its log.
    {
        let exe = std::env::current_exe().ok();
        let tried: Vec<String> = bundled_engine_driver_candidates()
            .iter()
            .map(|p| p.display().to_string())
            .collect();
        tracing::warn!(
            current_exe = ?exe,
            writ_bundled_driver = ?std::env::var_os(ENV_BUNDLED_DRIVER),
            writ_patchright_driver = ?std::env::var_os(ENV_PATCHRIGHT_DRIVER),
            home = ?dirs_home(),
            candidates_tried = ?tried,
            "no BUNDLED patchright driver resolved next to the executable"
        );
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

/// Env var an OPERATOR sets to pin a specific patchright `.../driver` directory. Highest priority.
pub const ENV_PATCHRIGHT_DRIVER: &str = "WRIT_PATCHRIGHT_DRIVER";

/// Env var the Tauri shell sets to the driver dir (or its `node` exe) when the resource shipped.
/// Kept here rather than in `local::runtime_setup` because THIS module is feature-independent and
/// both consumers must agree on the spelling; `runtime_setup::ENV_BUNDLED_DRIVER` aliases it.
pub const ENV_BUNDLED_DRIVER: &str = "WRIT_BUNDLED_DRIVER";

/// **THE** resolver for the patchright driver directory this app ships. Returns a directory that is
/// already proven to hold a real driver (`node[.exe]` + `package/cli.js`), or `None`.
///
/// ## Why this is one function
/// The driver had FOUR independent consumers and they did not agree:
/// * [`find_patchright_driver`] — the stealth driver behind `PLAYWRIGHT_NODE_EXE` (had the
/// exe-relative fallback);
/// * `runtime_setup::detect_driver` — the `driver.bundled` field of `GET /v1/runtime/status`
/// (env var ONLY);
/// * `runtime_setup::resolve_install_command` — `node cli.js install chromium`, the only Chromium
/// installer a shipped app has once the direct download is unavailable (env var ONLY);
/// * the Tauri shell, which computes the path a fourth time from its own `resource_dir()`.
///
/// So on any install where the shell does not export `WRIT_BUNDLED_DRIVER` — a fresh Windows
/// install, a portable/unpacked build, a `.deb`/AppImage, or the daemon started by hand — the
/// stealth path recovered while the status reported `bundled: false` and the Chromium installer
/// reported "no Chromium installer found (bundled driver missing)", with the driver sitting in the
/// install tree the whole time. Setting the env var by hand fixed all three at once, which is
/// exactly why it looked like an env-var bug rather than three copies of one resolver.
///
/// SECURITY: the `node` under the returned directory is EXECUTED. Every candidate is anchored to an
/// operator-set env var or to the running executable's own directory — never the CWD, never remote
/// input — and [`driver_from_dir`] validates the layout before a directory can win.
pub fn bundled_driver_dir() -> Option<PathBuf> {
    // Explicit env first: an operator pin outranks discovery, and the shell's value (when it is set)
    // is the cheapest correct answer. Tolerate both shapes — the dir itself, or its `node` exe.
    for key in [ENV_PATCHRIGHT_DRIVER, ENV_BUNDLED_DRIVER] {
        let Some(raw) = std::env::var_os(key).filter(|v| !v.is_empty()) else {
            continue;
        };
        let p = PathBuf::from(raw);
        let dir = if p.is_dir() { p } else { p.parent().map(Path::to_path_buf).unwrap_or_default() };
        // Normalized before it escapes: `resolve_install_command` spawns `<dir>/node <dir>/package/
        // cli.js install chromium`, so a verbatim dir here is the same EISDIR death as the driver.
        let dir = simplified_path(&dir);
        if driver_from_dir(&dir).is_some() {
            return Some(dir);
        }
    }
    // Then find it ourselves, relative to `current_exe` — the path that needs no cooperation from
    // whatever launched us.
    //
    // MEMOIZED. This is reached from `runtime_setup::detect_driver`, which serves the POLLED
    // `GET /v1/runtime/status`, so an un-cached answer meant re-walking the install tree on every
    // poll — under Windows Defender, a repeated traversal of `C:\Program Files\...` is slow enough
    // to be felt as UI latency. The install tree cannot change under a running daemon (an update
    // replaces the files and restarts it), so resolving once per process is correct.
    static DISCOVERED: std::sync::OnceLock<Option<PathBuf>> = std::sync::OnceLock::new();
    DISCOVERED
        .get_or_init(|| {
            bundled_engine_driver_candidates().into_iter().find(|d| driver_from_dir(d).is_some())
        })
        .clone()
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

/// Driver dirs shipped by the TAURI DESKTOP bundle, resolved RELATIVE TO THE DAEMON'S OWN EXE — the
/// self-sufficient path that does NOT depend on the shell exporting `WRIT_BUNDLED_DRIVER`.
///
/// Tauri copies the resource `resources/engine/<triple>/driver` into the install tree next to the
/// executable (`<install>/resources/engine/<triple>/driver` on Windows/Linux; inside
/// `Contents/Resources/` on macOS, one level up from the sidecar in `Contents/MacOS/`). We probe both
/// shapes under the exe's directory, matching a flat `.../engine/driver` and any per-triple
/// `.../engine/<name>/driver`, and let [`driver_from_dir`] validate that a real `node[.exe]` +
/// `package/cli.js` are present. Order is candidates only; the caller validates.
fn bundled_engine_driver_candidates() -> Vec<PathBuf> {
    match std::env::current_exe().ok().and_then(|e| e.parent().map(Path::to_path_buf)) {
        Some(base) => bundled_engine_driver_candidates_in(&base),
        None => Vec::new(),
    }
}

/// [`bundled_engine_driver_candidates`] for an explicit exe directory (the testable core).
///
/// Deliberately LAYOUT-INDEPENDENT. The first cut hard-coded `resources/engine/{,<triple>/}driver`,
/// which is what the bundle config declares — but a hard-coded guess is exactly what already failed
/// once here, and Tauri's installed layout differs per platform (and per installer: NSIS vs MSI vs
/// the macOS `.app`). So we do what a human does when the guess misses: walk down from the install
/// root looking for a real driver. Bounded depth + a pruned walk keep it cheap, and
/// [`driver_from_dir`] is still the thing that decides a hit (node[.exe] + package/cli.js present),
/// so a same-named-but-empty directory can never win.
fn bundled_engine_driver_candidates_in(base: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    // Fast paths first, so the common layouts cost one `is_dir` each and never touch the walk.
    // macOS: the sidecar lives in Contents/MacOS while resources are in Contents/Resources.
    for root in [base.to_path_buf(), base.join("..").join("Resources")] {
        let engine = root.join("resources").join("engine");
        if engine.is_dir() {
            out.push(engine.join("driver"));
            if let Ok(entries) = std::fs::read_dir(&engine) {
                for entry in entries.flatten() {
                    if entry.path().is_dir() {
                        out.push(entry.path().join("driver"));
                    }
                }
            }
        }
    }
    // A known layout already holds a REAL driver ⇒ stop. The walk below is a RECOVERY path for
    // layouts we don't know; running it anyway made the common case pay a full traversal of the
    // install tree for nothing.
    if out.iter().any(|d| driver_from_dir(d).is_some()) {
        return out;
    }
    // Bounded discovery walk: any `*/driver` under the install root, depth-limited so a deep tree
    // (or a symlink loop) can't turn startup into a filesystem crawl. Depth 6 (not 4): the known
    // Tauri layout puts it at depth 4 (`resources/engine/<triple>/driver`), and guessing the
    // installer's exact nesting is precisely what has already failed twice here — the extra levels
    // cost one `read_dir` each on a pruned tree and remove a whole class of near-miss.
    collect_driver_dirs(base, 6, &mut out);
    out.dedup();
    out
}

/// Depth-bounded scan for directories NAMED `driver` under `dir`, appending each to `out`.
/// Skips the browser payload (`chrome-*`) — it is large, never contains the node driver, and is the
/// one subtree that would dominate the walk.
fn collect_driver_dirs(dir: &Path, depth_left: usize, out: &mut Vec<PathBuf>) {
    if depth_left == 0 {
        return;
    }
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let p = entry.path();
        // `file_type` here does NOT follow symlinks, so a link loop cannot trap the walk.
        if !entry.file_type().map(|t| t.is_dir()).unwrap_or(false) {
            continue;
        }
        let name = entry.file_name();
        let name = name.to_string_lossy();
        if name.starts_with("chrome-") || name == "node_modules" {
            continue;
        }
        if name == "driver" {
            out.push(p.clone());
        }
        collect_driver_dirs(&p, depth_left - 1, out);
    }
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

/// Strip a Windows **verbatim** (`\\?\`) prefix when it is safe to do so.
///
/// NODE CANNOT RUN A SCRIPT WHOSE PATH IS VERBATIM. `node \\?\C:\…\cli.js` dies before executing
/// a single line:
/// ```text
/// Error: EISDIR: illegal operation on a directory, lstat 'C:'
/// at Object.realpathSync (node:fs)
/// at resolveMainPath (node:internal/modules/run_main)
/// ```
/// `resolveMainPath` → `toRealPath` → `realpathSync` walks the path component by component; against
/// `\\?\C:\…` it ends up calling `lstat("C:")`, which is a directory reference, not a file — EISDIR,
/// exit code 1. The driver then dies ~200 ms in, and because the only liveness check ran at 100 ms
/// the caller saw nothing but "Playwright initialization timeout after 30 seconds".
///
/// Where the prefix comes from: the Tauri shell derives the resource dir from `resource_dir()` and
/// exports it as `WRIT_BUNDLED_DRIVER`, and on Windows that value carries `\\?\`. Nothing on the
/// Rust side minds — `exists()`, `join()` and `CreateProcess` all accept it — so it survives every
/// check we make and only detonates inside Node.
///
/// Only `\\?\C:\…` and `\\?\UNC\server\share\…` are simplified (the two forms with a plain
/// equivalent), and only when the result stays under Windows' legacy `MAX_PATH`: past that the
/// verbatim form is load-bearing and removing it would break the path instead. `\\.\` device paths
/// and bare `\\?\` verbatim paths are returned untouched. No-op on every other platform.
pub fn simplified_path(p: &Path) -> PathBuf {
    #[cfg(not(windows))]
    {
        p.to_path_buf()
    }
    #[cfg(windows)]
    {
        use std::ffi::OsString;
        use std::path::{Component, Prefix};

        let mut comps = p.components();
        let Some(Component::Prefix(prefix)) = comps.next() else {
            return p.to_path_buf();
        };
        let rest = comps.as_path();
        let simplified = match prefix.kind() {
            Prefix::VerbatimDisk(drive) => {
                let mut s = OsString::from(format!("{}:", drive as char));
                if rest.as_os_str().is_empty() {
                    s.push("\\");
                } else {
                    s.push(rest.as_os_str());
                }
                PathBuf::from(s)
            }
            Prefix::VerbatimUNC(server, share) => {
                let mut s = OsString::from(r"\\");
                s.push(server);
                s.push("\\");
                s.push(share);
                s.push(rest.as_os_str());
                PathBuf::from(s)
            }
            // Verbatim(..) / DeviceNS(..) have no plain equivalent; Disk/UNC are already plain.
            _ => return p.to_path_buf(),
        };
        // Past MAX_PATH the `\\?\` prefix is what makes the path usable at all — keep it.
        if simplified.as_os_str().len() < 260 {
            simplified
        } else {
            p.to_path_buf()
        }
    }
}

/// Validate a patchright `driver` dir, returning `(node, cli.js)` if both exist.
///
/// THE choke point every driver resolution funnels through, and therefore the right place to
/// normalize: both paths are handed to Node (one as the program, one as its main module), so a
/// verbatim prefix here is fatal — see [`simplified_path`].
fn driver_from_dir(dir: &Path) -> Option<(PathBuf, PathBuf)> {
    let dir = simplified_path(dir);
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
    // NOTE: `use super::*` already lives further down in this module — do not re-import it here.

    /// The Tauri desktop layout `<install>/resources/engine/<triple>/driver` must resolve from the
    /// exe directory alone — the fresh-install case where the shell never set `WRIT_BUNDLED_DRIVER`.
    #[test]
    fn finds_the_bundled_driver_relative_to_the_exe() {
        let dir = tempfile::tempdir().unwrap();
        let base = dir.path();
        // Build a realistic per-triple bundle: .../resources/engine/x86_64-pc-windows-msvc/driver
        let driver = base
            .join("resources")
            .join("engine")
            .join("x86_64-pc-windows-msvc")
            .join("driver");
        std::fs::create_dir_all(driver.join("package")).unwrap();
        let node_name = if cfg!(windows) { "node.exe" } else { "node" };
        std::fs::write(driver.join(node_name), b"").unwrap();
        std::fs::write(driver.join("package").join("cli.js"), b"").unwrap();

        // The candidate list must include the real driver dir, and driver_from_dir must validate it.
        let cands = bundled_engine_driver_candidates_in(base);
        assert!(cands.contains(&driver), "per-triple driver not among candidates: {cands:?}");
        let resolved = cands.iter().find_map(|d| driver_from_dir(d));
        let (node, cli) = resolved.expect("a bundled driver should resolve");
        assert_eq!(node, driver.join(node_name));
        assert_eq!(cli, driver.join("package").join("cli.js"));

        // Nothing to find under an empty tree → empty candidate list, no panic.
        let empty = tempfile::tempdir().unwrap();
        assert!(bundled_engine_driver_candidates_in(empty.path()).is_empty());
    }

    /// The resolver must NOT depend on the exact bundle layout: a driver parked somewhere the
    /// hard-coded `resources/engine/...` guess doesn't cover must still be found. This is the case
    /// that made a fresh Windows install fail while a manual `WRIT_BUNDLED_DRIVER` worked.
    #[test]
    fn finds_the_driver_even_under_an_unexpected_layout() {
        let dir = tempfile::tempdir().unwrap();
        let base = dir.path();
        // A layout NOT matching resources/engine/<triple>/driver.
        let driver = base.join("engine").join("win-x64").join("driver");
        std::fs::create_dir_all(driver.join("package")).unwrap();
        let node_name = if cfg!(windows) { "node.exe" } else { "node" };
        std::fs::write(driver.join(node_name), b"").unwrap();
        std::fs::write(driver.join("package").join("cli.js"), b"").unwrap();

        let resolved = bundled_engine_driver_candidates_in(base)
            .iter()
            .find_map(|d| driver_from_dir(d));
        assert!(resolved.is_some(), "an off-layout driver must still resolve");

        // A directory NAMED `driver` but missing node/cli.js must NOT be accepted as a hit.
        let decoy = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(decoy.path().join("stuff").join("driver")).unwrap();
        assert!(
            bundled_engine_driver_candidates_in(decoy.path())
                .iter()
                .find_map(|d| driver_from_dir(d))
                .is_none(),
            "an empty `driver` dir must not resolve"
        );
    }

    /// [`bundled_driver_dir`] is the ONE resolver three consumers share, so pin its contract:
    /// a real layout behind the env var wins, an env var pointing at a non-driver is not a hit
    /// (it must fall through rather than pin a directory nothing can launch), and the `node` exe
    /// form is accepted as well as the directory form.
    #[test]
    fn bundled_driver_dir_validates_the_layout_behind_the_env_var() {
        let _lock = env_lock();
        #[cfg(feature = "local")]
        let _g = crate::local::config::test_env_guard();

        let prev_bundled = std::env::var_os(ENV_BUNDLED_DRIVER);
        let prev_pin = std::env::var_os(ENV_PATCHRIGHT_DRIVER);
        std::env::remove_var(ENV_PATCHRIGHT_DRIVER);

        let tmp = std::env::temp_dir().join(format!("writ_bundled_driver_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&tmp);
        let driver = tmp.join("driver");
        std::fs::create_dir_all(driver.join("package")).unwrap();
        let node_name = if cfg!(windows) { "node.exe" } else { "node" };
        std::fs::write(driver.join(node_name), b"").unwrap();
        std::fs::write(driver.join("package").join("cli.js"), b"").unwrap();

        // Directory form.
        std::env::set_var(ENV_BUNDLED_DRIVER, &driver);
        assert_eq!(bundled_driver_dir().as_deref(), Some(driver.as_path()));

        // `node` exe form — the shell may export either.
        std::env::set_var(ENV_BUNDLED_DRIVER, driver.join(node_name));
        assert_eq!(bundled_driver_dir().as_deref(), Some(driver.as_path()));

        // An env var pointing at a directory that is NOT a driver must not be accepted. It falls
        // through to exe-relative discovery, which finds nothing beside the test binary — the point
        // is that a bogus env value can never "win" and mask a real driver elsewhere.
        let bogus = tmp.join("not-a-driver");
        std::fs::create_dir_all(&bogus).unwrap();
        std::env::set_var(ENV_BUNDLED_DRIVER, &bogus);
        assert_ne!(bundled_driver_dir().as_deref(), Some(bogus.as_path()));

        match prev_bundled {
            Some(v) => std::env::set_var(ENV_BUNDLED_DRIVER, v),
            None => std::env::remove_var(ENV_BUNDLED_DRIVER),
        }
        if let Some(v) = prev_pin {
            std::env::set_var(ENV_PATCHRIGHT_DRIVER, v);
        }
        let _ = std::fs::remove_dir_all(&tmp);
    }

    /// A verbatim `\\?\` path handed to Node kills it before it runs a line
    /// (`EISDIR: … lstat 'C:'` from `resolveMainPath`). Pin the simplification, and pin that the
    /// forms with no plain equivalent are left alone.
    #[test]
    fn verbatim_windows_prefixes_are_simplified() {
        // Non-verbatim paths are returned untouched on every platform.
        let plain = PathBuf::from("relative/driver");
        assert_eq!(simplified_path(&plain), plain);

        #[cfg(windows)]
        {
            assert_eq!(
                simplified_path(Path::new(r"\\?\C:\Program Files\Writ\driver\node.exe")),
                PathBuf::from(r"C:\Program Files\Writ\driver\node.exe")
            );
            assert_eq!(simplified_path(Path::new(r"\\?\C:\")), PathBuf::from(r"C:\"));
            assert_eq!(
                simplified_path(Path::new(r"\\?\UNC\server\share\driver")),
                PathBuf::from(r"\\server\share\driver")
            );
            // Already plain → unchanged.
            let plain_disk = PathBuf::from(r"C:\Program Files\Writ\driver");
            assert_eq!(simplified_path(&plain_disk), plain_disk);
            // Device namespace has no plain equivalent → untouched.
            let device = PathBuf::from(r"\\.\pipe\something");
            assert_eq!(simplified_path(&device), device);
            // Past MAX_PATH the prefix is load-bearing → kept.
            let long = PathBuf::from(format!(r"\\?\C:\{}", "a".repeat(300)));
            assert_eq!(simplified_path(&long), long);
        }
    }

    /// `HOME` is not set on Windows — every home-derived driver candidate resolved to `None` there.
    /// `USERPROFILE` must stand in for it.
    #[test]
    fn home_falls_back_to_userprofile_when_home_is_unset() {
        let _lock = env_lock();
        #[cfg(feature = "local")]
        let _g = crate::local::config::test_env_guard();

        let prev_home = std::env::var_os("HOME");
        let prev_profile = std::env::var_os("USERPROFILE");

        std::env::remove_var("HOME");
        std::env::set_var("USERPROFILE", "/writ-test/userprofile");
        assert_eq!(dirs_home(), Some(PathBuf::from("/writ-test/userprofile")));

        // HOME still wins when both are present (unix behaviour is unchanged).
        std::env::set_var("HOME", "/writ-test/home");
        assert_eq!(dirs_home(), Some(PathBuf::from("/writ-test/home")));

        match prev_home {
            Some(v) => std::env::set_var("HOME", v),
            None => std::env::remove_var("HOME"),
        }
        match prev_profile {
            Some(v) => std::env::set_var("USERPROFILE", v),
            None => std::env::remove_var("USERPROFILE"),
        }
    }

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

        // Preserve and override the env for a deterministic check. The guards taken at the top of
        // this test are what make "preserve and restore" deterministic: HOME/WRIT_HOME are
        // process-global, so without them a sibling test mutating them on another thread lands
        // mid-assertion. They are NOT re-acquired here — `std::sync::Mutex` is not reentrant, and a
        // second `env_lock()` on this thread deadlocks against the guard still held above (shadowing
        // a `let _lock` does not drop the previous one; it lives until end of scope).
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
