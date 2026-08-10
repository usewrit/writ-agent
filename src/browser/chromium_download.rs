//! First-run Chromium acquisition — a self-contained, dependency-free download.
//!
//! ## Why this exists
//!
//! [`super::install::ensure_browser_installed`] shells out to `patchright` / `playwright` / `npx`.
//! Every one of those needs Python or Node **already on the user's machine**. That is fine on a
//! developer box and useless on the clean desktop this app ships to: the install simply fails and
//! the user is left with an app that cannot open a browser. This module is the replacement path —
//! plain HTTPS + unzip, no interpreter, no package manager, no PATH assumptions.
//!
//! ## What it downloads, and why that specific build
//!
//! Open-source **Chromium** (BSD-3-Clause), from the Chromium project's own snapshot bucket — NOT
//! "Google Chrome for Testing", which is what Playwright/patchright download. Chrome for Testing is
//! Google-copyrighted and distributed under the Chrome Terms of Service; Chromium is BSD and the
//! user obtains it directly from Google here rather than receiving a copy from us.
//!
//! The revisions below are pinned to the branch position of a Chromium **stable** release, so the
//! build is a known quantity rather than whatever `LAST_CHANGE` happens to point at. Note the
//! trade-off this inherits: Google publishes no *stable channel* of open-source Chromium binaries,
//! only continuous builds, so moving to a newer Chromium means re-pinning here deliberately.
//!
//! ## Layout
//!
//! Each archive expands to exactly the directory tree
//! [`super::super::local::runtime_setup`] already probes (`chrome-mac/`, `chrome-linux/`,
//! `chrome-win/`), so an installed browser is discovered by the existing resolver with no special
//! case. Installs land in `<writ-home>/browsers/chromium-<position>/`.

use std::io;
use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};
use futures_util::StreamExt as _;
use tracing::{info, warn};

/// A pinned, per-platform open-source Chromium build.
struct ChromiumBuild {
    /// Snapshot bucket platform directory.
    platform_dir: &'static str,
    /// Chromium main-branch position. Pinned to a stable release's position.
    position: u32,
    /// Archive file name within the position directory.
    archive: &'static str,
    /// Executable path RELATIVE to the extracted root — must match the candidates that
    /// `runtime_setup::chromium_exe_candidates` probes, or a successful install still resolves to
    /// "no browser".
    exe_rel: &'static str,
}

/// The build for the host platform, or `None` where the Chromium project publishes no desktop build.
///
/// **arm64 Linux is deliberately `None`.** The Chromium project ships no arm64 desktop build at all
/// (`Linux_ARM_Cross-Compile` is 32-bit and frozen at a 2014 revision), and the only real arm64
/// Chromium is a distro package that expects ~40 system libraries from its own release. Dropping a
/// copy of that into our own directory would produce a binary that cannot start. On that platform
/// the correct answer genuinely is the system package manager, and [`ensure_chromium`] says so
/// instead of failing with a download error that suggests a network problem.
const HOST_BUILD: Option<ChromiumBuild> = {
    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    {
        Some(ChromiumBuild {
            platform_dir: "Mac_Arm",
            position: 1_654_411,
            archive: "chrome-mac.zip",
            exe_rel: "chrome-mac/Chromium.app/Contents/MacOS/Chromium",
        })
    }
    #[cfg(all(target_os = "macos", target_arch = "x86_64"))]
    {
        Some(ChromiumBuild {
            platform_dir: "Mac",
            position: 1_654_411,
            archive: "chrome-mac.zip",
            exe_rel: "chrome-mac/Chromium.app/Contents/MacOS/Chromium",
        })
    }
    #[cfg(all(target_os = "windows", target_arch = "x86_64"))]
    {
        Some(ChromiumBuild {
            platform_dir: "Win_x64",
            position: 1_654_400,
            archive: "chrome-win.zip",
            exe_rel: "chrome-win/chrome.exe",
        })
    }
    #[cfg(all(target_os = "windows", target_arch = "aarch64"))]
    {
        // Windows on ARM. The Chromium project DOES publish an arm64 desktop build (Win_Arm64),
        // unlike arm64 Linux, so this is a real download rather than a `None`. The archive layout
        // matches the x64 Windows build (chrome-win/chrome.exe).
        Some(ChromiumBuild {
            platform_dir: "Win_Arm64",
            position: 1_654_438,
            archive: "chrome-win.zip",
            exe_rel: "chrome-win/chrome.exe",
        })
    }
    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    {
        Some(ChromiumBuild {
            platform_dir: "Linux_x64",
            position: 1_654_408,
            archive: "chrome-linux.zip",
            exe_rel: "chrome-linux/chrome",
        })
    }
    #[cfg(not(any(
        all(target_os = "macos", target_arch = "aarch64"),
        all(target_os = "macos", target_arch = "x86_64"),
        all(target_os = "windows", target_arch = "x86_64"),
        all(target_os = "windows", target_arch = "aarch64"),
        all(target_os = "linux", target_arch = "x86_64"),
    )))]
    {
        None
    }
};

const SNAPSHOT_BASE: &str = "https://commondatastorage.googleapis.com/chromium-browser-snapshots";

/// Root under which downloaded browsers are installed: `$WRIT_HOME/browsers` (else `~/.writ/browsers`).
fn browsers_root() -> Result<PathBuf> {
    if let Ok(h) = std::env::var("WRIT_HOME") {
        if !h.trim().is_empty() {
            return Ok(PathBuf::from(h).join("browsers"));
        }
    }
    let home = std::env::var("HOME")
        .ok()
        .or_else(|| std::env::var("USERPROFILE").ok())
        .context("neither WRIT_HOME nor HOME/USERPROFILE is set — cannot choose an install directory")?;
    Ok(PathBuf::from(home).join(".writ").join("browsers"))
}

/// Where this platform's pinned build installs to, and the executable inside it.
pub fn install_paths() -> Result<Option<(PathBuf, PathBuf)>> {
    let Some(b) = HOST_BUILD else { return Ok(None) };
    let dir = browsers_root()?.join(format!("chromium-{}", b.position));
    let exe = dir.join(b.exe_rel);
    Ok(Some((dir, exe)))
}

/// The already-installed Chromium for this platform, if the download has run before.
pub fn installed_exe() -> Option<PathBuf> {
    let (_, exe) = install_paths().ok()??;
    exe.exists().then_some(exe)
}

/// Download + install Chromium for the host platform, reporting coarse progress.
///
/// Idempotent: an install that is already present returns immediately. `progress` is called with
/// `(percent, message)` and is the only channel this has to the UI, so it fires during the download
/// (which is the slow part) rather than only at stage boundaries.
pub async fn ensure_chromium<F>(progress: F) -> Result<PathBuf>
where
    F: Fn(u8, &str) + Send + Sync,
{
    let Some(build) = HOST_BUILD else {
        bail!(
            "no open-source Chromium build is published for this platform ({} {}). \
             Install Chromium with your package manager (e.g. `sudo apt install chromium`) and \
             restart — it will be detected automatically.",
            std::env::consts::OS,
            std::env::consts::ARCH
        );
    };

    let (dir, exe) = install_paths()?.expect("HOST_BUILD is Some, so install_paths is too");
    if exe.exists() {
        info!(path = %exe.display(), "Chromium already installed");
        progress(100, "Chromium is ready");
        return Ok(exe);
    }

    let url = format!(
        "{SNAPSHOT_BASE}/{}/{}/{}",
        build.platform_dir, build.position, build.archive
    );
    info!(%url, dest = %dir.display(), "downloading Chromium");
    progress(0, "Starting Chromium download");

    // Download to a temp file NEXT TO the destination (same filesystem, so the later rename is
    // atomic) rather than the system temp dir, which is frequently a different mount.
    let parent = dir.parent().unwrap_or(Path::new("."));
    tokio::fs::create_dir_all(parent)
        .await
        .with_context(|| format!("could not create {}", parent.display()))?;
    let tmp_zip = parent.join(format!(".chromium-{}.zip.part", build.position));
    let _ = tokio::fs::remove_file(&tmp_zip).await;

    let resp = reqwest::Client::builder()
        .build()?
        .get(&url)
        .send()
        .await
        .with_context(|| format!("could not reach {url}"))?;
    if !resp.status().is_success() {
        bail!("Chromium download failed: HTTP {} for {url}", resp.status());
    }
    let total = resp.content_length();

    {
        use tokio::io::AsyncWriteExt as _;
        let mut file = tokio::fs::File::create(&tmp_zip)
            .await
            .with_context(|| format!("could not create {}", tmp_zip.display()))?;
        let mut stream = resp.bytes_stream();
        let mut seen: u64 = 0;
        let mut last_pct: u8 = 0;
        while let Some(chunk) = stream.next().await {
            let chunk = chunk.context("Chromium download interrupted")?;
            file.write_all(&chunk).await?;
            seen += chunk.len() as u64;
            // 0..=90 is the download; the remaining 10 is extraction.
            if let Some(total) = total.filter(|t| *t > 0) {
                let pct = ((seen as f64 / total as f64) * 90.0) as u8;
                if pct > last_pct {
                    last_pct = pct;
                    progress(pct, &format!("Downloading Chromium ({}%)", pct.min(90)));
                }
            }
        }
        file.flush().await?;
    }
    // Resolve the size BEFORE the log call. Awaiting inside `info!` holds the macro's
    // `fmt::Arguments` across the await point, which makes the whole future non-`Send` and so
    // un-spawnable — the install runs on `tokio::spawn`.
    let downloaded_bytes = seen_len(&tmp_zip).await;
    info!(bytes = downloaded_bytes, "Chromium archive downloaded");

    progress(92, "Extracting Chromium");
    // Extract to a staging dir, then rename into place. A half-extracted directory at the final
    // path would be indistinguishable from a good install on the next launch, and the app would
    // start against a broken browser forever.
    let staging = parent.join(format!(".chromium-{}.staging", build.position));
    let _ = tokio::fs::remove_dir_all(&staging).await;
    let zip_path = tmp_zip.clone();
    let staging_for_task = staging.clone();
    tokio::task::spawn_blocking(move || extract_zip(&zip_path, &staging_for_task))
        .await
        .context("extraction task panicked")??;

    let staged_exe = staging.join(build.exe_rel);
    if !staged_exe.exists() {
        let _ = tokio::fs::remove_dir_all(&staging).await;
        bail!(
            "the downloaded archive did not contain {} — the pinned build layout has changed",
            build.exe_rel
        );
    }

    let _ = tokio::fs::remove_dir_all(&dir).await;
    tokio::fs::rename(&staging, &dir)
        .await
        .with_context(|| format!("could not move the extracted browser into {}", dir.display()))?;
    let _ = tokio::fs::remove_file(&tmp_zip).await;

    info!(path = %exe.display(), "Chromium installed");
    progress(100, "Chromium is ready");
    Ok(exe)
}

async fn seen_len(p: &Path) -> u64 {
    tokio::fs::metadata(p).await.map(|m| m.len()).unwrap_or(0)
}

/// Extract `zip_path` into `dest`, preserving **symlinks** and the **executable bit**.
///
/// Both matter and neither is the zip crate's default. macOS Chromium ships as a framework bundle
/// whose `Versions/Current` and top-level entries are symlinks; materialising those as real copies
/// triples the size AND produces a bundle macOS refuses to treat as a valid framework. Losing the
/// exec bit on Unix leaves a browser that cannot be launched at all.
fn extract_zip(zip_path: &Path, dest: &Path) -> Result<()> {
    let file = std::fs::File::open(zip_path)
        .with_context(|| format!("could not open {}", zip_path.display()))?;
    let mut archive = zip::ZipArchive::new(std::io::BufReader::new(file))
        .context("the downloaded file is not a valid zip archive")?;
    std::fs::create_dir_all(dest)?;

    for i in 0..archive.len() {
        let mut entry = archive.by_index(i)?;

        // Reject absolute paths and `..` traversal before touching the filesystem: this archive is
        // fetched over the network, and a crafted entry could otherwise write outside `dest`.
        let Some(rel) = entry.enclosed_name() else {
            warn!(name = entry.name(), "skipping zip entry with an unsafe path");
            continue;
        };
        let out = dest.join(&rel);

        if entry.is_dir() {
            std::fs::create_dir_all(&out)?;
            continue;
        }
        if let Some(parent) = out.parent() {
            std::fs::create_dir_all(parent)?;
        }

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            if entry.is_symlink() {
                let mut target = String::new();
                io::Read::read_to_string(&mut entry, &mut target)?;
                let _ = std::fs::remove_file(&out);
                std::os::unix::fs::symlink(&target, &out).with_context(|| {
                    format!("could not create symlink {} -> {target}", out.display())
                })?;
                continue;
            }
            let mut f = std::fs::File::create(&out)?;
            io::copy(&mut entry, &mut f)?;
            if let Some(mode) = entry.unix_mode() {
                std::fs::set_permissions(&out, std::fs::Permissions::from_mode(mode))?;
            }
        }
        #[cfg(not(unix))]
        {
            let mut f = std::fs::File::create(&out)?;
            io::copy(&mut entry, &mut f)?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The pinned executable path must match what the resolver probes, per OS. If these drift, a
    /// download "succeeds" and the app still reports no browser — a failure with no obvious cause.
    #[test]
    fn pinned_exe_path_matches_the_resolver_layout() {
        let Some(b) = HOST_BUILD else { return };
        #[cfg(target_os = "macos")]
        assert_eq!(b.exe_rel, "chrome-mac/Chromium.app/Contents/MacOS/Chromium");
        #[cfg(target_os = "linux")]
        assert_eq!(b.exe_rel, "chrome-linux/chrome");
        #[cfg(target_os = "windows")]
        assert_eq!(b.exe_rel, "chrome-win/chrome.exe");
    }

    /// The install directory is namespaced by revision, so re-pinning to a newer Chromium installs
    /// alongside rather than half-overwriting a running browser.
    #[test]
    fn install_dir_is_revision_namespaced() {
        let Some((dir, exe)) = install_paths().unwrap() else { return };
        let name = dir.file_name().unwrap().to_string_lossy().into_owned();
        assert!(name.starts_with("chromium-"), "got {name}");
        assert!(exe.starts_with(&dir));
    }

    /// LIVE end-to-end: really download + install Chromium for this platform, then assert the
    /// things a green unit test cannot: that the archive layout still matches the pin, that the
    /// binary is launchable, that macOS framework SYMLINKS survived extraction (materialising them
    /// as copies is what made the bundled attempt unpackageable), and that the installed executable
    /// matches the compiled-in SHA-256 the integrity gate will check.
    ///
    /// Ignored by default — hundreds of MB over the network. Run with:
    ///   `cargo test --features local -- --ignored chromium_download::tests::live_download`
    #[tokio::test]
    #[ignore = "downloads a real Chromium over the network (hundreds of MB)"]
    async fn live_download_installs_a_launchable_verified_browser() {
        let Some((dir, _)) = install_paths().unwrap() else {
            eprintln!("no published build for this platform — nothing to test");
            return;
        };
        let _ = std::fs::remove_dir_all(&dir);

        let exe = ensure_chromium(|pct, msg| eprintln!("  [{pct:>3}%] {msg}"))
            .await
            .expect("download must succeed");
        assert!(exe.exists(), "installed executable must exist at {}", exe.display());

        // Launchable, not merely present: losing the exec bit during extraction yields a file that
        // exists and cannot run.
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            let mode = std::fs::metadata(&exe).unwrap().permissions().mode();
            assert!(mode & 0o111 != 0, "executable bit lost during extraction (mode {mode:o})");
        }

        // It must actually be Chromium, and report a version.
        let out = std::process::Command::new(&exe).arg("--version").output();
        if let Ok(out) = out {
            let v = String::from_utf8_lossy(&out.stdout);
            eprintln!("  version: {}", v.trim());
            assert!(v.to_lowercase().contains("chromium"), "expected Chromium, got {v:?}");
        }

        // macOS: the framework symlinks are the whole reason this is not bundled. If extraction
        // materialised them as directories, the bundle is invalid and codesign would reject it.
        #[cfg(target_os = "macos")]
        {
            let fw = dir.join("chrome-mac/Chromium.app/Contents/Frameworks/Chromium Framework.framework/Versions/Current");
            assert!(
                fw.symlink_metadata().map(|m| m.file_type().is_symlink()).unwrap_or(false),
                "Versions/Current must remain a SYMLINK ({} )",
                fw.display()
            );
        }

        // And the digest the integrity gate will compare against.
        use sha2::{Digest as _, Sha256};
        let mut h = Sha256::new();
        let mut f = std::fs::File::open(&exe).unwrap();
        io::copy(&mut f, &mut h).unwrap();
        let got = format!("{:x}", h.finalize());
        eprintln!("  sha256: {got}");
        let pins: serde_json::Value =
            serde_json::from_str(include_str!("../../resources/engine/chromium-pins.json")).unwrap();
        let build = HOST_BUILD.unwrap();
        let key = if cfg!(target_os = "macos") && cfg!(target_arch = "aarch64") {
            "macos-aarch64"
        } else if cfg!(target_os = "macos") {
            "macos-x86_64"
        } else if cfg!(target_os = "windows") && cfg!(target_arch = "aarch64") {
            "windows-aarch64"
        } else if cfg!(target_os = "windows") {
            "windows-x86_64"
        } else {
            "linux-x86_64"
        };
        let want = pins["pins"][build.position.to_string()][key]
            .as_str()
            .expect("a pin must exist for this platform/revision");
        assert_eq!(got, want, "installed Chromium does not match its compiled-in pin");
    }

    /// A zip entry escaping the destination must be skipped, not written. This archive comes off the
    /// network, so path traversal is a real input, not a theoretical one.
    #[test]
    fn extract_rejects_path_traversal() {
        let tmp = std::env::temp_dir().join(format!("writ-zip-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&tmp);
        std::fs::create_dir_all(&tmp).unwrap();
        let zip_path = tmp.join("evil.zip");

        {
            let f = std::fs::File::create(&zip_path).unwrap();
            let mut w = zip::ZipWriter::new(f);
            let opts: zip::write::FileOptions<'_, ()> = zip::write::FileOptions::default();
            w.start_file("../escaped.txt", opts).unwrap();
            io::Write::write_all(&mut w, b"nope").unwrap();
            w.start_file("safe.txt", opts).unwrap();
            io::Write::write_all(&mut w, b"ok").unwrap();
            w.finish().unwrap();
        }

        let dest = tmp.join("out");
        extract_zip(&zip_path, &dest).unwrap();
        assert!(dest.join("safe.txt").exists(), "the safe entry must extract");
        assert!(
            !tmp.join("escaped.txt").exists(),
            "a `..` entry must never be written outside the destination"
        );
        let _ = std::fs::remove_dir_all(&tmp);
    }
}
