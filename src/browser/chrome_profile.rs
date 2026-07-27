//! Local Chrome profile copy (opt-in).
//!
//! 1:1 port of Python AutomationEngine._get_chrome_profile_dir (line 672) and
//! _copy_chrome_profile (line 713). Copies the user's real Chrome cookies/storage
//! into a working directory so the browser looks like a returning user.
//!
//! This is OPT-IN — only used when the operator passes `--use-local-chrome` at
//! startup. The default is a clean baseline (no local profile copy).

use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

/// Essential profile files needed for session persistence (skip large caches).
/// Matches Python _copy_chrome_profile essential_files.
const ESSENTIAL_ITEMS: &[&str] = &[
    "Cookies",
    "Cookies-journal",
    "Local Storage",
    "Session Storage",
    "Preferences",
    "Secure Preferences",
];

/// Staleness window: re-copy only if the cached profile is older than 1 hour.
const PROFILE_CACHE_TTL: Duration = Duration::from_secs(3600);

/// Find the user's real Chrome "Default" profile directory.
/// 1:1 port of Python _get_chrome_profile_dir (line 672).
pub fn get_chrome_profile_dir() -> Option<PathBuf> {
    let home = dirs_home()?;

    let path = if cfg!(target_os = "macos") {
        home.join("Library")
            .join("Application Support")
            .join("Google")
            .join("Chrome")
            .join("Default")
    } else if cfg!(target_os = "windows") {
        home.join("AppData")
            .join("Local")
            .join("Google")
            .join("Chrome")
            .join("User Data")
            .join("Default")
    } else {
        home.join(".config").join("google-chrome").join("Default")
    };

    if path.exists() {
        Some(path)
    } else {
        None
    }
}

/// Copy the user's Chrome "Default" profile to a working directory for
/// Playwright to use. 1:1 port of Python _copy_chrome_profile (line 713).
///
/// Returns the path to the working profile directory. If Chrome isn't found,
/// returns an empty working directory (blank profile) — same as Python.
pub fn copy_chrome_profile() -> std::io::Result<PathBuf> {
    let work_dir = work_profile_dir();

    let chrome_profile = match get_chrome_profile_dir() {
        Some(p) => p,
        None => {
            tracing::warn!("Chrome profile not found, using blank profile");
            if let Some(parent) = work_dir.parent() {
                std::fs::create_dir_all(parent)?;
                lock_dir_0700(parent);
            }
            std::fs::create_dir_all(&work_dir)?;
            lock_dir_0700(&work_dir);
            return Ok(work_dir);
        }
    };

    copy_profile_from(&chrome_profile)
}

/// Copy a specific source profile directory (any Chromium-family profile the
/// user chose via `import-profile`) into the working `.browser_profile` dir.
///
/// Re-copies only when the cached copy is stale (>1h) OR was made from a
/// DIFFERENT source — so switching the imported profile takes effect immediately
/// instead of being masked by the time-based cache.
pub fn copy_profile_from(source: &Path) -> std::io::Result<PathBuf> {
    let work_dir = work_profile_dir();
    let source_tag = source.to_string_lossy();

    // Reuse the existing copy only if it came from the SAME source and is fresh.
    let marker = work_dir.join(".profile_copied");
    if let Ok(meta) = std::fs::metadata(&marker) {
        let same_source = std::fs::read_to_string(&marker)
            .map(|c| c.trim() == source_tag)
            .unwrap_or(false);
        if same_source {
            if let Ok(modified) = meta.modified() {
                if let Ok(age) = SystemTime::now().duration_since(modified) {
                    if age < PROFILE_CACHE_TTL {
                        tracing::debug!(age_secs = age.as_secs(), "Reusing copied profile");
                        return Ok(work_dir);
                    }
                }
            }
        }
    }

    // Remove old copy and start fresh.
    if work_dir.exists() {
        let _ = std::fs::remove_dir_all(&work_dir);
    }
    // Ensure the parent home exists and lock the working dir to 0700 BEFORE writing any cookies into
    // it (so there is never a window where the copied secrets are world-readable).
    if let Some(parent) = work_dir.parent() {
        std::fs::create_dir_all(parent)?;
        lock_dir_0700(parent);
    }
    std::fs::create_dir_all(&work_dir)?;
    lock_dir_0700(&work_dir);

    // Copy only the essential files (skip large caches).
    for item in ESSENTIAL_ITEMS {
        let src = source.join(item);
        let dst = work_dir.join(item);
        if src.is_dir() {
            if let Err(e) = copy_dir_recursive(&src, &dst) {
                tracing::debug!(item = item, error = %e, "Could not copy profile dir");
            }
        } else if src.is_file() {
            if let Err(e) = std::fs::copy(&src, &dst) {
                tracing::debug!(item = item, error = %e, "Could not copy profile file");
            }
        }
    }

    // Record which source this copy came from (powers the same-source check above).
    let _ = std::fs::write(&marker, source_tag.as_bytes());

    // Tighten permissions on everything we just copied: the imported cookies/storage must be
    // owner-only (0600 files / 0700 dirs), never world-readable.
    harden_perms(&work_dir);

    tracing::info!(source = %source.display(), "Copied browser profile");
    Ok(work_dir)
}

/// The working profile directory: `<WRIT_HOME>/.browser_profile` (falling back to `~/.writ`).
///
/// SECURITY + ISOLATION: this holds a COPY of real browser cookies/storage. It must live inside the
/// daemon's per-account `WRIT_HOME` (the `0700` home the daemon runs against, which is
/// `<base>/profiles/<account>` under profile isolation) — NOT a shared, world-readable `<cwd>` dir.
/// That gives it both restrictive permissions and per-account isolation for free (one account's
/// imported cookies are never visible to another profile or to other local users).
fn work_profile_dir() -> PathBuf {
    let base = std::env::var_os("WRIT_HOME")
        .map(PathBuf::from)
        .or_else(|| dirs_home().map(|h| h.join(".writ")))
        .unwrap_or_else(|| PathBuf::from(".writ"));
    base.join(".browser_profile")
}

/// Lock a freshly-created directory to `0700` (owner-only) on unix. Best-effort.
fn lock_dir_0700(dir: &Path) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700));
    }
    #[cfg(not(unix))]
    let _ = dir;
}

/// Recursively tighten permissions on the copied profile: directories `0700`, files `0600`, so the
/// imported cookies/storage are never readable by other local users. Best-effort per entry.
fn harden_perms(root: &Path) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut stack = vec![root.to_path_buf()];
        while let Some(dir) = stack.pop() {
            let _ = std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700));
            let Ok(entries) = std::fs::read_dir(&dir) else { continue };
            for entry in entries.flatten() {
                let path = entry.path();
                match entry.file_type() {
                    Ok(ft) if ft.is_dir() => stack.push(path),
                    Ok(_) => {
                        let _ = std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600));
                    }
                    Err(_) => {}
                }
            }
        }
    }
    #[cfg(not(unix))]
    let _ = root;
}

fn dirs_home() -> Option<PathBuf> {
    std::env::var_os("HOME")
        .or_else(|| std::env::var_os("USERPROFILE"))
        .map(PathBuf::from)
}

/// Recursively copy a directory tree.
fn copy_dir_recursive(src: &Path, dst: &Path) -> std::io::Result<()> {
    std::fs::create_dir_all(dst)?;
    for entry in std::fs::read_dir(src)? {
        let entry = entry?;
        let file_type = entry.file_type()?;
        let from = entry.path();
        let to = dst.join(entry.file_name());
        if file_type.is_dir() {
            copy_dir_recursive(&from, &to)?;
        } else if file_type.is_file() {
            std::fs::copy(&from, &to)?;
        }
    }
    Ok(())
}

// Verifies the M4 storage/isolation posture. Gated on `feature = "local"` so it can serialize on the
// crate-wide `WRIT_HOME` env guard (the same one the config tests use), avoiding an env-var race.
#[cfg(all(test, unix, feature = "local"))]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    fn mode(p: &Path) -> u32 {
        std::fs::metadata(p).unwrap().permissions().mode() & 0o777
    }

    /// `harden_perms` tightens a copied tree to owner-only: dirs 0700, files 0600.
    #[test]
    fn harden_perms_locks_owner_only() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("prof");
        std::fs::create_dir_all(root.join("Local Storage")).unwrap();
        std::fs::write(root.join("Cookies"), b"c").unwrap();
        std::fs::write(root.join("Local Storage").join("leveldb"), b"x").unwrap();
        // Loosen first to prove hardening actually tightens.
        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o755)).unwrap();
        std::fs::set_permissions(root.join("Cookies"), std::fs::Permissions::from_mode(0o644)).unwrap();

        harden_perms(&root);

        assert_eq!(mode(&root), 0o700);
        assert_eq!(mode(&root.join("Cookies")), 0o600);
        assert_eq!(mode(&root.join("Local Storage")), 0o700);
        assert_eq!(mode(&root.join("Local Storage").join("leveldb")), 0o600);
    }

    /// The copied profile lands under the profile-isolated `WRIT_HOME` (not `<cwd>`), owner-only.
    #[test]
    fn copy_profile_stores_under_writ_home_owner_only() {
        let _g = crate::local::config::test_env_guard();
        let home = tempfile::tempdir().unwrap();
        std::env::set_var("WRIT_HOME", home.path());

        // A fake source profile carrying a "cookie".
        let src = tempfile::tempdir().unwrap();
        std::fs::write(src.path().join("Cookies"), b"secret-cookie").unwrap();

        let work = copy_profile_from(src.path()).unwrap();

        // Isolation: stored inside WRIT_HOME/.browser_profile, never a shared cwd dir.
        assert!(work.starts_with(home.path()), "profile copy must live under WRIT_HOME");
        assert_eq!(work.file_name().unwrap(), ".browser_profile");
        // Storage: owner-only dir + copied cookie file (not world-readable).
        assert_eq!(mode(&work), 0o700, "work dir must be 0700");
        let copied = work.join("Cookies");
        assert!(copied.exists(), "cookie copied");
        assert_eq!(mode(&copied), 0o600, "copied cookie must be 0600");

        std::env::remove_var("WRIT_HOME");
    }
}
