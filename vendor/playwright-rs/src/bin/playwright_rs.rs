//! playwright-rs CLI — bootstrap the Playwright driver into a stable
//! user cache and install browsers.
//!
//! For downstream binaries distributed via `cargo install`, the
//! compile-time `$OUT_DIR` driver path is invalidated when Cargo cleans
//! up the build's `target/`. Running `playwright-rs install` populates
//! `dirs::cache_dir()/playwright-rust/<version>/`, which the library's
//! runtime resolution chain probes after the bundled lookup.
//
// TODO: the download/extract logic is duplicated from `build.rs` for
// v0.x. Extract to a shared module (via `include!()` or an internal
// crate) once the architecture stabilises.

use clap::{Parser, Subcommand};
use sha2::{Digest, Sha256};
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

const DRIVER_BASE_URL: &str = "https://playwright.azureedge.net/builds/driver";

/// Pinned SHA-256 of each platform's driver ZIP. MUST match the pins in `build.rs` and be regenerated
/// on a `PLAYWRIGHT_DRIVER_VERSION` bump. Supply-chain integrity anchor for the runtime user-cache
/// download (the ZIP carries a `node` binary that is later executed) — see `verify_driver_sha256`.
fn pinned_driver_sha256(platform: &str) -> Option<&'static str> {
    // playwright 1.60.0
    Some(match platform {
        "mac" => "5ceb115caacc70d6e81760ce2101ff9ee455ed7e34e6b46df397902ffdd83dd0",
        "mac-arm64" => "d60af6c58869b42d603eefd2dd953a6ee848286cbcf74dd8f06582a4729cfed0",
        "linux" => "13219f82df3802fee67c6b1351131492cda1b5320c6d658980c2699a613d0410",
        "linux-arm64" => "9e31548634ca192c87649df7ceb292d8a40c0cd382d7524cb684ddefbf6c4250",
        "win32_x64" => "7707bf263ead21df9d28114336d4e36368658298977be12ee12c92e386244c82",
        "win32_arm64" => "133caad29e33b4d570629c9a768703b6959a6aa6946dbd37168baa34e9a023f9",
        _ => return None,
    })
}

/// Verify `bytes` against the pinned SHA-256 for `platform` (or a `PLAYWRIGHT_DRIVER_SHA256` env
/// override). FAIL-CLOSED: an unknown platform or a mismatch is an error, so a tampered archive is
/// never extracted or executed.
fn verify_driver_sha256(bytes: &[u8], platform: &str) -> Result<(), Box<dyn std::error::Error>> {
    let expected = std::env::var("PLAYWRIGHT_DRIVER_SHA256")
        .ok()
        .map(|s| s.trim().to_ascii_lowercase())
        .filter(|s| !s.is_empty())
        .or_else(|| pinned_driver_sha256(platform).map(str::to_string))
        .ok_or_else(|| {
            format!(
                "no pinned SHA-256 for platform '{platform}' — refusing to extract an unverified \
                 driver (set PLAYWRIGHT_DRIVER_SHA256 to override)"
            )
        })?;
    let actual = {
        use std::fmt::Write as _;
        Sha256::digest(bytes).iter().fold(String::new(), |mut s, b| {
            let _ = write!(s, "{b:02x}");
            s
        })
    };
    if actual != expected {
        return Err(format!(
            "driver archive SHA-256 mismatch for {platform}: expected {expected}, got {actual}"
        )
        .into());
    }
    Ok(())
}

#[derive(Parser)]
#[command(name = "playwright-rs", version, about, long_about = None)]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Download the Playwright driver to the user cache (if missing) and install browsers.
    Install {
        /// Browser names to install (e.g. `chromium firefox webkit`). Omit to install all.
        browsers: Vec<String>,
        /// Pass `--with-deps` to the Playwright CLI (forced on Linux regardless).
        #[arg(long)]
        with_deps: bool,
        /// Populate the user-cache driver but skip the browser-install step.
        /// Intended for CI smoke tests and `cargo install` post-install bootstrap.
        #[arg(long)]
        driver_only: bool,
    },
}

#[tokio::main]
async fn main() -> ExitCode {
    let cli = Cli::parse();

    match cli.cmd {
        Cmd::Install {
            browsers,
            with_deps,
            driver_only,
        } => match run_install(browsers, with_deps, driver_only).await {
            Ok(()) => ExitCode::SUCCESS,
            Err(e) => {
                eprintln!("playwright-rs: {e}");
                ExitCode::FAILURE
            }
        },
    }
}

async fn run_install(
    browsers: Vec<String>,
    with_deps: bool,
    driver_only: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    let version = env!("PLAYWRIGHT_DRIVER_VERSION");
    let platform = env!("PLAYWRIGHT_DRIVER_PLATFORM");

    let driver_dir = ensure_driver_in_user_cache(version, platform)?;
    eprintln!("Driver ready at: {}", driver_dir.display());

    if driver_only {
        return Ok(());
    }

    // The library's `install_browsers_with_deps` calls `get_driver_executable()`,
    // which probes the bundled path first. Override via `PLAYWRIGHT_DRIVER_PATH`
    // so the user-cache driver is used instead of whatever the compile-time
    // bundled path happens to be (which may not exist post-`cargo install`).
    // SAFETY: set_var is unsafe in Rust 2024 because env mutation isn't
    // thread-safe; we run before spawning any worker threads.
    unsafe {
        std::env::set_var("PLAYWRIGHT_DRIVER_PATH", &driver_dir);
    }

    let browser_refs: Vec<&str> = browsers.iter().map(String::as_str).collect();
    let browsers_arg: Option<&[&str]> = if browser_refs.is_empty() {
        None
    } else {
        Some(&browser_refs)
    };

    if with_deps {
        playwright_rs::install_browsers_with_deps(browsers_arg).await?;
    } else {
        playwright_rs::install_browsers(browsers_arg).await?;
    }

    Ok(())
}

/// Ensure the Playwright driver exists at
/// `<cache>/playwright-rust/<version>/playwright-<version>-<platform>/`.
/// Downloads + extracts from Azure CDN if absent. Returns the driver dir.
fn ensure_driver_in_user_cache(
    version: &str,
    platform: &str,
) -> Result<PathBuf, Box<dyn std::error::Error>> {
    let cache_root = dirs::cache_dir().ok_or("could not determine user cache directory")?;
    let driver_dir = cache_root
        .join("playwright-rust")
        .join(version)
        .join(format!("playwright-{version}-{platform}"));

    let cli_js = driver_dir.join("package").join("cli.js");
    if cli_js.exists() {
        return Ok(driver_dir);
    }

    let parent = driver_dir.parent().expect("driver_dir always has a parent");
    fs::create_dir_all(parent)?;

    let url = format!("{DRIVER_BASE_URL}/playwright-{version}-{platform}.zip");
    eprintln!("Downloading driver from {url}");

    let mut response = ureq::get(&url).call()?;
    let status = response.status().as_u16();
    if !(200..300).contains(&status) {
        return Err(format!("download failed with status: {status}").into());
    }

    let bytes: Vec<u8> = response
        .body_mut()
        .with_config()
        .limit(u64::MAX)
        .read_to_vec()?;
    eprintln!("Downloaded {} bytes", bytes.len());

    // SUPPLY-CHAIN GATE: verify the archive SHA-256 before opening/extracting/executing anything.
    verify_driver_sha256(&bytes, platform)?;
    eprintln!("Driver SHA-256 verified");

    let cursor = io::Cursor::new(bytes);
    let mut archive = zip::ZipArchive::new(cursor)?;
    extract_zip_to(&mut archive, &driver_dir)?;

    Ok(driver_dir)
}

fn extract_zip_to(
    archive: &mut zip::ZipArchive<io::Cursor<Vec<u8>>>,
    dest: &Path,
) -> io::Result<()> {
    fs::create_dir_all(dest)?;
    for i in 0..archive.len() {
        let mut file = archive
            .by_index(i)
            .map_err(|e| io::Error::other(format!("zip read failed: {e}")))?;
        // ZIP-SLIP GUARD: reject absolute/`..` entries; keep every write under `dest`.
        let outpath = match file.enclosed_name() {
            Some(rel) => {
                let out = dest.join(&rel);
                if !out.starts_with(dest) {
                    return Err(io::Error::other(format!(
                        "zip entry escapes target dir (path traversal): {}",
                        file.name()
                    )));
                }
                out
            }
            None => {
                return Err(io::Error::other(format!(
                    "unsafe zip entry name (path traversal): {}",
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
            let mut outfile = fs::File::create(&outpath)?;
            io::copy(&mut file, &mut outfile)?;

            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                if outpath.ends_with("node")
                    || outpath.extension().and_then(|s| s.to_str()) == Some("sh")
                {
                    let mut perms = fs::metadata(&outpath)?.permissions();
                    perms.set_mode(0o755);
                    fs::set_permissions(&outpath, perms)?;
                }
            }
        }
    }
    Ok(())
}
