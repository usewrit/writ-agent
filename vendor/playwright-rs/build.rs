//! Build script for playwright-rs
//!
//! Obtains the Playwright Node.js driver (`node` + `package/cli.js`) and extracts it into Cargo's
//! `$OUT_DIR`; the runtime side (`src/server/driver.rs`) picks the path up via compile-time
//! `option_env!()` lookups. Because `$OUT_DIR` lives inside `target/`, the driver is cached by any
//! `target/`-cache configuration in CI (e.g. `Swatinem/rust-cache`), and it is ALSO mirrored into
//! `~/.cache/playwright-rs-driver/` so it survives `cargo clean` and lockfile churn.
//!
//! The source is the **PyPI `playwright` wheel**, SHA-256-pinned — NOT the old Azure CDN, which was
//! decommissioned (see `pinned_driver_archive`). Resolution order is: `PLAYWRIGHT_DRIVER_PATH`
//! (explicit, offline) → OUT_DIR cache → machine cache → download. An explicit override always wins
//! over a warm cache, and a build that cannot obtain the driver FAILS rather than producing a binary
//! that compiles but cannot launch a browser.

use sha2::{Digest, Sha256};
use std::env;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

const PLAYWRIGHT_VERSION: &str = "1.60.0";

/// Per-platform driver ARCHIVE: `(url, sha256)`.
///
/// SOURCE OF TRUTH — read this before changing the URL. The original driver CDN
/// (`playwright.azureedge.net/builds/driver`) was DECOMMISSIONED and now returns 404 for every
/// version, and the replacement host (`cdn.playwright.dev/dbazure/download/playwright`) serves
/// `builds/chromium/...` but NOT `builds/driver/...` (HTTP 400, gateway error 20012). There is no
/// live standalone driver-ZIP endpoint to point at.
///
/// So we take the driver from the **PyPI `playwright` wheel**, which bundles exactly the same
/// payload under `playwright/driver/` (`node` + `package/cli.js`) — this is how `playwright-python`
/// itself ships the driver. PyPI artifact URLs are content-addressed and immutable, and the digests
/// below are PyPI's own published `digests.sha256` values, so the pin is verifiable out-of-band:
///
///   curl -s https://pypi.org/pypi/playwright/$VER/json | jq -r '.urls[] | "\(.filename) \(.digests.sha256)"'
///
/// These are the SUPPLY-CHAIN integrity anchor: the archive contains a `node` binary that is later
/// executed, and TLS alone does not defend against a poisoned mirror, a registry compromise, or a
/// TLS-terminating proxy substituting the archive. MUST be regenerated whenever
/// `PLAYWRIGHT_VERSION` changes — the build fails closed on a mismatch.
///
/// Overrides, for mirrors / air-gapped builds (both must be set together):
///   `PLAYWRIGHT_DRIVER_URL`     — fetch the archive from here instead.
///   `PLAYWRIGHT_DRIVER_SHA256`  — the expected digest of that archive.
/// Either a PyPI-style wheel (entries under `playwright/driver/`) or a legacy Playwright driver ZIP
/// (entries at the archive root) is accepted; the prefix is detected automatically.
fn pinned_driver_archive(platform: &str) -> Option<(&'static str, &'static str)> {
    // playwright 1.60.0 — PyPI wheels (see doc comment above).
    Some(match platform {
        "mac" => (
            "https://files.pythonhosted.org/packages/21/f0/832bd9677194908da118064eef20082f2791e3d18215cc6d9391ee2c5a67/playwright-1.60.0-py3-none-macosx_10_13_x86_64.whl",
            "6a8cd0fec171fb3089e95e898c8bc8a6f35dea0b78b399e12fcc19427e91b1d7",
        ),
        "mac-arm64" => (
            "https://files.pythonhosted.org/packages/59/7b/e1d32ae8a3ed937ec2be3721c5f728b13d731a0b7c6442e0b3bec5094ac0/playwright-1.60.0-py3-none-macosx_11_0_arm64.whl",
            "39b5420ba6145045b69ced4c5c47d4d9fe5bddfc8ff816c518913afcb25ec7a5",
        ),
        "linux" => (
            "https://files.pythonhosted.org/packages/22/7b/1d679f4fced4ea94efadd17103856d8c565384f68382a1681264e46f5925/playwright-1.60.0-py3-none-manylinux1_x86_64.whl",
            "1c2bfae7884fb3fb05b853290eab8f343d524e5016f2f1def702acbbdf14c93e",
        ),
        "linux-arm64" => (
            "https://files.pythonhosted.org/packages/84/c2/1528d267d4442bd2c6b8eaeab819dd52c2030bf80e89293f0ba1f687473b/playwright-1.60.0-py3-none-manylinux_2_17_aarch64.manylinux2014_aarch64.whl",
            "43e66564125ee31b07a58cefb21e256d62d67d8d1713e6858df7a3019d8ed353",
        ),
        "win32_x64" => (
            "https://files.pythonhosted.org/packages/55/f0/0541524133104f9cc20bf900870ff4a736b76a23483f3a55295ddfa58409/playwright-1.60.0-py3-none-win_amd64.whl",
            "9566821ce6030a1f9e7146a24e19355ab0d98805fd0f9be50bb3d8fef1750c02",
        ),
        "win32_arm64" => (
            "https://files.pythonhosted.org/packages/80/c8/210f282d278e4709cdd71b12a31af45a30a22ab3207b387e29b37e478713/playwright-1.60.0-py3-none-win_arm64.whl",
            "6e4f6700a4c2250efff8e690a81d66e3855754fb587b6b87cf5c784014f91537",
        ),
        _ => return None,
    })
}

/// Resolve the archive URL + expected digest for `platform`, honoring the env overrides.
/// Both overrides must be set together — a URL without a digest would silently disable the
/// supply-chain gate, so that combination is a hard error rather than a warning.
fn driver_archive_for(platform: &str) -> io::Result<(String, String)> {
    let url_override = non_empty_env("PLAYWRIGHT_DRIVER_URL");
    let sha_override = non_empty_env("PLAYWRIGHT_DRIVER_SHA256");
    match (url_override, sha_override) {
        (Some(url), Some(sha)) => Ok((url, sha.to_ascii_lowercase())),
        (Some(_), None) => Err(io::Error::other(
            "PLAYWRIGHT_DRIVER_URL is set without PLAYWRIGHT_DRIVER_SHA256 — refusing to fetch an \
             unverified archive containing an executable `node` binary. Set both, or unset both.",
        )),
        (None, Some(sha)) => {
            // A digest override alone still pins the built-in URL (useful to accept a known-good
            // rebuild without editing the source).
            let (url, _) = pinned_driver_archive(platform).ok_or_else(|| unsupported(platform))?;
            Ok((url.to_string(), sha.to_ascii_lowercase()))
        }
        (None, None) => {
            let (url, sha) = pinned_driver_archive(platform).ok_or_else(|| unsupported(platform))?;
            Ok((url.to_string(), sha.to_string()))
        }
    }
}

fn unsupported(platform: &str) -> io::Error {
    io::Error::other(format!(
        "no pinned Playwright driver for platform '{platform}' — set PLAYWRIGHT_DRIVER_URL and \
         PLAYWRIGHT_DRIVER_SHA256, or PLAYWRIGHT_DRIVER_PATH to an already-extracted driver"
    ))
}

fn non_empty_env(key: &str) -> Option<String> {
    println!("cargo:rerun-if-env-changed={key}");
    env::var(key)
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
}

/// Verify `bytes` against `expected`. FAIL-CLOSED: any mismatch is an error, so a tampered or
/// unexpected archive is NEVER extracted or executed.
fn verify_driver_sha256(bytes: &[u8], platform: &str, expected: &str) -> io::Result<()> {
    let actual = hex_lower(&Sha256::digest(bytes));
    if actual != expected {
        return Err(io::Error::other(format!(
            "driver archive SHA-256 mismatch for {platform}: expected {expected}, got {actual}"
        )));
    }
    Ok(())
}

fn hex_lower(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    bytes.iter().fold(String::with_capacity(bytes.len() * 2), |mut s, b| {
        let _ = write!(s, "{b:02x}");
        s
    })
}

fn main() {
    println!("cargo:rerun-if-changed=build.rs");

    // Skip driver download on docs.rs — it has no network access and doesn't need drivers
    if std::env::var("DOCS_RS").is_ok() {
        println!("cargo:rustc-env=PLAYWRIGHT_DRIVER_DIR=");
        println!("cargo:rustc-env=PLAYWRIGHT_DRIVER_VERSION={PLAYWRIGHT_VERSION}");
        println!("cargo:rustc-env=PLAYWRIGHT_DRIVER_PLATFORM=docs-rs");
        return;
    }

    let out_dir = PathBuf::from(env::var("OUT_DIR").expect("OUT_DIR set by Cargo"));
    let drivers_dir = out_dir.join("playwright-driver");

    let platform = detect_platform();
    let driver_dir = drivers_dir.join(format!("playwright-{PLAYWRIGHT_VERSION}-{platform}"));

    // Old driver versions linger in OUT_DIR until `cargo clean` — Cargo's
    // build-script fingerprint reruns this on PLAYWRIGHT_VERSION bumps
    // (which change build.rs) so the new version is always written, but
    // we don't garbage-collect prior versions. Disk bloat only.
    // ORDER MATTERS, AND THIS IS FIRST.
    //
    // PRE-EXTRACTED DRIVER: `PLAYWRIGHT_DRIVER_PATH` points at a directory that already contains
    // `node` + `package/cli.js`. This is the air-gapped / offline-build escape hatch.
    //
    // It is checked BEFORE the OUT_DIR and machine caches, not after. An EXPLICIT operator override
    // must win over an incidentally-warm cache — otherwise the documented behaviour is a lie on every
    // machine that has built once before (which is every CI runner with a `target/` cache, and every
    // developer). It also has to precede any network access so a genuinely offline build never
    // touches the wire.
    if let Some(dir) = non_empty_env("PLAYWRIGHT_DRIVER_PATH") {
        let dir = PathBuf::from(dir);
        if driver_dir_is_complete(&dir) {
            println!("cargo:warning=Using PLAYWRIGHT_DRIVER_PATH driver at {}", dir.display());
            set_output_env_vars(&dir, platform);
            return;
        }
        // Fail rather than silently falling through to a cache or a download: the operator asked for
        // a specific driver, and quietly using a different one is how an air-gapped build ends up
        // shipping something nobody vetted.
        panic!(
            "PLAYWRIGHT_DRIVER_PATH={} does not look like a Playwright driver directory \
             (expected `node`{} and `package/cli.js` inside it)",
            dir.display(),
            if cfg!(windows) { " / `node.exe`" } else { "" }
        );
    }
    // A mirror override is likewise explicit: skip the caches so the operator actually gets the
    // archive they pointed at (and its digest checked) rather than a stale local copy.
    let has_url_override = non_empty_env("PLAYWRIGHT_DRIVER_URL").is_some();

    if driver_dir.exists() && !has_url_override {
        set_output_env_vars(&driver_dir, platform);
        return;
    }

    // MACHINE-LEVEL CACHE: any Cargo metadata change (new dep, feature unification) mints a fresh
    // OUT_DIR hash, so without this every lockfile touch would re-download ~45 MB even though the
    // driver is already on disk. The cache lives OUTSIDE target/ so `cargo clean` keeps it too. Env
    // vars can point straight at the cache dir — no copy into OUT_DIR needed.
    let machine_cache = machine_cache_dir(platform);
    if let Some(cache) = machine_cache.as_ref() {
        if !has_url_override && driver_dir_is_complete(cache) {
            println!("cargo:warning=Using machine-cached Playwright driver at {}", cache.display());
            set_output_env_vars(cache, platform);
            return;
        }
    }

    println!("cargo:warning=Downloading Playwright driver {PLAYWRIGHT_VERSION} for {platform}...");

    match download_and_extract_driver(&drivers_dir, platform) {
        Ok(extracted_dir) => {
            println!(
                "cargo:warning=Playwright driver downloaded to {}",
                extracted_dir.display()
            );
            // Mirror into the machine cache (best-effort) so future OUT_DIRs skip the download.
            if let Some(cache) = machine_cache.as_ref() {
                if let Err(e) = copy_dir_recursive(&extracted_dir, cache) {
                    println!("cargo:warning=Could not mirror driver to machine cache: {e}");
                }
            }
            set_output_env_vars(&extracted_dir, platform);
        }
        Err(e) => {
            // FAIL LOUDLY AND HERE.
            //
            // This branch used to only print `cargo:warning` lines and return. Because
            // `src/lib.rs` reads the driver version with `env!` (not `option_env!`), returning
            // without calling `set_output_env_vars` produced a baffling
            // "environment variable `PLAYWRIGHT_DRIVER_VERSION` not defined at compile time"
            // error inside the vendored crate, 40 lines away from the real cause. Worse, if that
            // ever became non-fatal it would yield a binary that compiles and then cannot launch a
            // browser at runtime. A build that cannot obtain the driver MUST fail, with the actual
            // reason and the actual remedies.
            panic!(
                "could not obtain the Playwright {PLAYWRIGHT_VERSION} driver for '{platform}': {e}\n\
                 \n\
                 The driver is required: it carries the `node` binary and `package/cli.js` that\n\
                 drive the browser. To fix this, either:\n\
                 \n\
                   * restore network access to files.pythonhosted.org (the driver is taken from the\n\
                     PyPI `playwright` wheel — see the pinned table in this build script); or\n\
                   * set PLAYWRIGHT_DRIVER_URL + PLAYWRIGHT_DRIVER_SHA256 to an internal mirror of\n\
                     that archive; or\n\
                   * set PLAYWRIGHT_DRIVER_PATH to a directory that already contains `node` and\n\
                     `package/cli.js` (offline / air-gapped builds).\n"
            );
        }
    }
}

/// Does `dir` contain a usable driver (the `node` binary and `package/cli.js`)?
/// Used for both the machine cache and the `PLAYWRIGHT_DRIVER_PATH` override, so a
/// half-written cache directory is never accepted as valid.
fn driver_dir_is_complete(dir: &Path) -> bool {
    let node = if cfg!(windows) { dir.join("node.exe") } else { dir.join("node") };
    node.exists() && dir.join("package").join("cli.js").exists()
}

/// Per-user driver cache that survives `cargo clean` and OUT_DIR rehashing:
/// `~/.cache/playwright-rs-driver/playwright-<version>-<platform>` (HOME/USERPROFILE based — the
/// build script has no extra deps for platform dirs).
fn machine_cache_dir(platform: &str) -> Option<PathBuf> {
    let home = env::var_os("HOME").or_else(|| env::var_os("USERPROFILE"))?;
    Some(
        PathBuf::from(home)
            .join(".cache")
            .join("playwright-rs-driver")
            .join(format!("playwright-{PLAYWRIGHT_VERSION}-{platform}")),
    )
}

/// Minimal recursive copy preserving unix permission bits (the driver ships an executable `node`).
fn copy_dir_recursive(src: &Path, dst: &Path) -> io::Result<()> {
    fs::create_dir_all(dst)?;
    for entry in fs::read_dir(src)? {
        let entry = entry?;
        let to = dst.join(entry.file_name());
        if entry.file_type()?.is_dir() {
            copy_dir_recursive(&entry.path(), &to)?;
        } else {
            fs::copy(entry.path(), &to)?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let mode = fs::metadata(entry.path())?.permissions().mode();
                fs::set_permissions(&to, fs::Permissions::from_mode(mode))?;
            }
        }
    }
    Ok(())
}

/// Detect the current platform and return the Playwright platform identifier
fn detect_platform() -> &'static str {
    let os = env::consts::OS;
    let arch = env::consts::ARCH;

    match (os, arch) {
        ("macos", "x86_64") => "mac",
        ("macos", "aarch64") => "mac-arm64",
        ("linux", "x86_64") => "linux",
        ("linux", "aarch64") => "linux-arm64",
        ("windows", "x86_64") => "win32_x64",
        ("windows", "aarch64") => "win32_arm64",
        _ => {
            println!("cargo:warning=Unsupported platform: {} {}", os, arch);
            println!("cargo:warning=Defaulting to linux platform");
            "linux"
        }
    }
}

/// Download and extract the Playwright driver.
//
// TODO: this download/extract routine is duplicated in
// `src/bin/playwright_rs.rs::ensure_driver_in_user_cache` for v0.x.
// Extract to a shared module (via `include!()` or an internal crate)
// once the architecture stabilizes.
fn download_and_extract_driver(drivers_dir: &Path, platform: &str) -> io::Result<PathBuf> {
    // Create drivers directory
    fs::create_dir_all(drivers_dir)?;

    let (url, expected_sha) = driver_archive_for(platform)?;

    println!("cargo:warning=Downloading from: {}", url);

    // Download the file via ureq (synchronous, minimal dep tree).
    let mut response = ureq::get(&url)
        .call()
        .map_err(|e| io::Error::other(format!("Download failed: {}", e)))?;

    let status = response.status().as_u16();
    if !(200..300).contains(&status) {
        return Err(io::Error::other(format!(
            "Download failed with status: {}",
            status
        )));
    }

    // The driver archive is ~45 MB; ureq's default body limit is 10 MB. Lift it, but keep a hard
    // ceiling rather than `u64::MAX` so a hostile/misconfigured mirror cannot stream unbounded
    // bytes into this build's memory. The digest gate below still rejects anything unexpected.
    const MAX_ARCHIVE_BYTES: u64 = 256 * 1024 * 1024;
    let bytes: Vec<u8> = response
        .body_mut()
        .with_config()
        .limit(MAX_ARCHIVE_BYTES)
        .read_to_vec()
        .map_err(|e| io::Error::other(format!("Failed to read response: {}", e)))?;

    println!("cargo:warning=Downloaded {} bytes", bytes.len());

    // SUPPLY-CHAIN GATE: verify the archive's SHA-256 against the pinned value BEFORE we open,
    // extract, or ever execute anything from it. Fail-closed on mismatch.
    verify_driver_sha256(&bytes, platform, &expected_sha)?;
    println!("cargo:warning=Driver SHA-256 verified");

    // Extract ZIP file
    let cursor = io::Cursor::new(bytes);
    let mut archive = zip::ZipArchive::new(cursor)
        .map_err(|e| io::Error::other(format!("Failed to open ZIP: {}", e)))?;

    let extract_dir = drivers_dir.join(format!("playwright-{}-{}", PLAYWRIGHT_VERSION, platform));

    // ARCHIVE-LAYOUT DETECTION. A PyPI `playwright` wheel nests the payload under
    // `playwright/driver/`; a legacy Playwright driver ZIP has `node` + `package/` at the root.
    // Strip the wheel prefix so BOTH shapes extract to the same on-disk layout
    // (`<extract_dir>/node`, `<extract_dir>/package/cli.js`) that `set_output_env_vars` expects.
    const WHEEL_PREFIX: &str = "playwright/driver/";
    let strip_prefix = archive
        .file_names()
        .any(|n| n.starts_with(WHEEL_PREFIX))
        .then_some(WHEEL_PREFIX);
    if strip_prefix.is_some() {
        println!("cargo:warning=Archive is a PyPI wheel — extracting {WHEEL_PREFIX}**");
    }

    println!("cargo:warning=Extracting to: {}", extract_dir.display());

    let mut extracted = 0usize;
    for i in 0..archive.len() {
        let mut file = archive
            .by_index(i)
            .map_err(|e| io::Error::other(format!("Failed to read ZIP entry: {}", e)))?;

        // LAYOUT FILTER: when the archive is a wheel, take ONLY the driver subtree and re-root it.
        // The comparison is on the raw archive name (which always uses `/`), before any path
        // handling, so the prefix strip cannot be confused by platform separators. Everything
        // outside the driver subtree (the Python package, dist-info, RECORD, ...) is skipped.
        let archive_name = file.name().to_string();
        let rel_name = match strip_prefix {
            Some(prefix) => match archive_name.strip_prefix(prefix) {
                Some(rest) => rest.to_string(),
                None => continue,
            },
            None => archive_name.clone(),
        };
        if rel_name.is_empty() {
            continue;
        }

        // ZIP-SLIP GUARD: `enclosed_name()` returns `None` for absolute paths or any `..` that would
        // escape the target, and yields a normalized relative path otherwise. We additionally assert
        // the joined path stays under `extract_dir` (defense in depth). A malicious entry is rejected,
        // never written outside the driver dir. NOTE: the guard is evaluated on the FULL archive name
        // (not the prefix-stripped one) so a traversal hidden inside the driver subtree is still
        // caught, and the stripped name is then re-validated against the target root below.
        let outpath = match file.enclosed_name() {
            Some(_) => {
                let out = extract_dir.join(&rel_name);
                // Re-validate the re-rooted path: `rel_name` came from raw archive bytes, so it
                // must be normalized and contained just like the original.
                if rel_name.contains("..")
                    || Path::new(&rel_name).is_absolute()
                    || !out.starts_with(&extract_dir)
                {
                    return Err(io::Error::other(format!(
                        "ZIP entry escapes target dir (path traversal): {}",
                        file.name()
                    )));
                }
                out
            }
            None => {
                return Err(io::Error::other(format!(
                    "unsafe ZIP entry name (path traversal): {}",
                    file.name()
                )))
            }
        };

        if file.is_dir() {
            fs::create_dir_all(&outpath)?;
        } else {
            if let Some(parent) = outpath.parent() {
                fs::create_dir_all(parent)?;
            }
            let stored_mode = file.unix_mode();
            let mut outfile = fs::File::create(&outpath)?;
            io::copy(&mut file, &mut outfile)?;
            drop(outfile);
            extracted += 1;

            // Set executable permissions on Unix. Prefer the archive's own stored mode (wheels and
            // driver ZIPs both record it), and fall back to the name heuristic when a producer
            // omitted it — `node` MUST end up executable or the driver cannot start.
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;

                let name_says_exec = outpath.ends_with("node")
                    || outpath.extension().and_then(|s| s.to_str()) == Some("sh");
                let mode = match stored_mode {
                    // Honor the stored bits, but never write something world-writable.
                    Some(m) if m & 0o111 != 0 => (m & 0o777) | 0o700,
                    Some(m) if name_says_exec => (m & 0o777) | 0o755,
                    Some(m) => m & 0o777,
                    None if name_says_exec => 0o755,
                    None => 0o644,
                };
                fs::set_permissions(&outpath, fs::Permissions::from_mode(mode))?;
            }
            #[cfg(not(unix))]
            let _ = stored_mode;
        }
    }

    println!("cargo:warning=Successfully extracted {} files", extracted);

    // COMPLETENESS GATE: a wrong prefix, a producer layout change, or a partial archive must not
    // yield a "successful" extraction that later fails at runtime with a missing browser driver.
    if !driver_dir_is_complete(&extract_dir) {
        return Err(io::Error::other(format!(
            "extracted archive is not a usable driver: {} is missing `node` and/or `package/cli.js` \
             (extracted {extracted} files)",
            extract_dir.display()
        )));
    }

    Ok(extract_dir)
}

/// Set environment variables for use at runtime
fn set_output_env_vars(driver_dir: &Path, platform: &str) {
    // Set the driver directory for runtime
    println!(
        "cargo:rustc-env=PLAYWRIGHT_DRIVER_DIR={}",
        driver_dir.display()
    );
    println!(
        "cargo:rustc-env=PLAYWRIGHT_DRIVER_VERSION={}",
        PLAYWRIGHT_VERSION
    );
    println!("cargo:rustc-env=PLAYWRIGHT_DRIVER_PLATFORM={}", platform);

    // Node executable path
    let node_exe = if cfg!(windows) {
        driver_dir.join("node.exe")
    } else {
        driver_dir.join("node")
    };

    if node_exe.exists() {
        println!("cargo:rustc-env=PLAYWRIGHT_NODE_EXE={}", node_exe.display());
    }

    // CLI.js path
    let cli_js = driver_dir.join("package").join("cli.js");
    if cli_js.exists() {
        println!("cargo:rustc-env=PLAYWRIGHT_CLI_JS={}", cli_js.display());
    }
}
