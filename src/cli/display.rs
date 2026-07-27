use std::env;
use std::path::{Path, PathBuf};
use std::process::Command;

/// Directories a system helper may be executed FROM.
///
/// Every helper this module runs (`xdpyinfo`, `Xvfb`, `pgrep`, `sudo`, the package managers) used to be
/// resolved through `$PATH` — either directly (`Command::new("Xvfb")`) or via a `which` subprocess
/// whose answer we then EXECUTED. `$PATH` is attacker-controllable by anyone who controls the launch
/// environment (a wrapper script, a poisoned shell profile, a service unit's `Environment=`), so that
/// is arbitrary code execution as the agent user. `browser::install::path_under_trusted_root` guards
/// the patchright driver against exactly this class; system helpers need the same treatment with the
/// roots appropriate to them — SYSTEM bin directories, not `$HOME`, which is where a `$PATH` shim
/// would be planted.
///
/// The list is deliberately fixed and small: root-owned locations on a normal unix, plus the two
/// package-manager prefixes (`/usr/local/bin`, `/opt/homebrew/bin`) and X11's own (`/opt/X11/bin`)
/// where these tools legitimately live.
const TRUSTED_BIN_DIRS: &[&str] = &[
    "/usr/bin",
    "/bin",
    "/usr/sbin",
    "/sbin",
    "/usr/local/bin",
    "/usr/local/sbin",
    "/opt/homebrew/bin",
    "/opt/homebrew/sbin",
    "/opt/X11/bin",
];

/// Environment variables holding a BYO AI provider key.
///
/// `cli::setup::apply_ai_env_vars` NO LONGER stages these (see the security note there — the browser
/// subprocess inherited them), but the USER may still export one in their own shell, and
/// `ai::client::detect_direct_ai_config` honours that. Every child we spawn ourselves therefore still
/// drops them: a display helper has no business inheriting an API key.
const AI_KEY_ENV_VARS: &[&str] = &["ANTHROPIC_API_KEY", "OPENAI_API_KEY"];

/// Build a `Command` with the BYO AI keys removed from the child's environment.
///
/// Use this instead of `Command::new` for every subprocess. `env_remove` unsets the variable for the
/// CHILD only — the parent's environment (which `ai::client` reads) is untouched, so this is not the
/// `set_var`-from-a-runtime hazard.
pub(crate) fn command_without_ai_keys(program: impl AsRef<std::ffi::OsStr>) -> Command {
    let mut cmd = Command::new(program);
    for k in AI_KEY_ENV_VARS {
        cmd.env_remove(k);
    }
    cmd
}

/// Resolve a system helper to an ABSOLUTE path under a trusted root, or `None`.
///
/// Replaces the old `which` subprocess: we probe [`TRUSTED_BIN_DIRS`] ourselves, canonicalize the hit
/// (so a symlink out of a trusted dir into a writable one is caught) and re-check the prefix. `$PATH`
/// is never consulted, so a poisoned `$PATH` cannot influence what we execute.
fn trusted_program(program: &str) -> Option<PathBuf> {
    // A program name must be a bare filename — never a path fragment a caller could use to escape.
    if program.is_empty() || program.contains('/') || program.contains('\\') {
        return None;
    }
    for dir in TRUSTED_BIN_DIRS {
        let candidate = Path::new(dir).join(program);
        if !candidate.is_file() {
            continue;
        }
        // Canonicalize + re-check: `/usr/local/bin/foo -> /home/user/evil` must not pass.
        let resolved = match std::fs::canonicalize(&candidate) {
            Ok(p) => p,
            Err(_) => continue,
        };
        if TRUSTED_BIN_DIRS.iter().any(|root| resolved.starts_with(root)) {
            return Some(resolved);
        }
        tracing::warn!(
            program = program,
            "ignoring a system helper that resolves outside the trusted bin directories"
        );
    }
    None
}

/// True when an `Xvfb` process is running. Resolves `pgrep` from a TRUSTED bin dir rather than `$PATH`
/// (see [`trusted_program`]) and returns `false` when `pgrep` isn't available at all — the previous
/// code's `Command::new("pgrep")` both trusted `$PATH` and treated a missing binary as "not running",
/// so only the trust part changes.
fn xvfb_running() -> bool {
    let Some(pgrep) = trusted_program("pgrep") else {
        return false;
    };
    command_without_ai_keys(pgrep)
        .args(["-x", "Xvfb"])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .map(|st| st.success())
        .unwrap_or(false)
}

#[derive(Debug, Clone, PartialEq)]
pub enum DisplayType {
    X11,
    X11Unverified,
    Wayland,
    MacOS,
    Windows,
    XvfbDocker,
    None,
}

#[derive(Debug, Clone)]
pub struct DisplayInfo {
    pub available: bool,
    pub display: Option<String>,
    pub display_type: DisplayType,
    pub message: String,
}

/// Check if a display server (X11, Wayland, Xvfb, macOS Quartz, Windows GDI)
/// is available for headed browser mode.
/// Exact port of Python recorder.py `check_display_available()`.
pub fn check_display_available() -> DisplayInfo {
    let mut info = DisplayInfo {
        available: false,
        display: None,
        display_type: DisplayType::None,
        message: "No display detected".to_string(),
    };

    // Check DISPLAY environment variable (X11/Xvfb)
    if let Ok(display) = env::var("DISPLAY") {
        if !display.is_empty() {
            info.display = Some(display.clone());

            // Verify X server is actually running via xdpyinfo
            if let Ok(xdpyinfo_path) = which("xdpyinfo") {
                match command_without_ai_keys(&xdpyinfo_path)
                    .env("DISPLAY", &display)
                    .stdout(std::process::Stdio::null())
                    .stderr(std::process::Stdio::null())
                    .status()
                {
                    Ok(status) if status.success() => {
                        info.available = true;
                        info.display_type = DisplayType::X11;
                        info.message = format!("X11 display available at {}", display);
                        return info;
                    }
                    Ok(_) => {
                        info.message =
                            format!("DISPLAY={} set but X server not responding", display);
                    }
                    Err(e) => {
                        info.message =
                            format!("DISPLAY={} set but check failed: {}", display, e);
                    }
                }
            } else {
                // No xdpyinfo — assume it works (Docker with Xvfb)
                info.available = true;
                info.display_type = DisplayType::X11Unverified;
                info.message = format!(
                    "DISPLAY={} set (xdpyinfo not available to verify)",
                    display
                );
                return info;
            }
        }
    }

    // Check WAYLAND_DISPLAY
    if let Ok(wayland) = env::var("WAYLAND_DISPLAY") {
        if !wayland.is_empty() {
            info.available = true;
            info.display = Some(wayland.clone());
            info.display_type = DisplayType::Wayland;
            info.message = format!("Wayland display available at {}", wayland);
            return info;
        }
    }

    // Check if running in Docker with Xvfb
    if Path::new("/.dockerenv").exists()
        && xvfb_running() {
            info.available = true;
            info.display_type = DisplayType::XvfbDocker;
            info.display = Some(":99".to_string());
            info.message = "Xvfb running in Docker".to_string();
            return info;
        }

    // macOS — always has display when in GUI session
    if cfg!(target_os = "macos")
        && (env::var("TERM_PROGRAM").is_ok()
            || env::var("Apple_PubSub_Socket_Render").is_ok())
        {
            info.available = true;
            info.display_type = DisplayType::MacOS;
            info.message = "macOS display available".to_string();
            return info;
        }

    // Windows — always has display
    if cfg!(target_os = "windows") {
        info.available = true;
        info.display_type = DisplayType::Windows;
        info.message = "Windows display available".to_string();
        return info;
    }

    info
}

/// Determine if recorder should run in headless mode.
/// Prefers headed mode for native UI elements, falls back to headless if no display.
/// Exact port of Python recorder.py `determine_headless_mode()`.
pub fn determine_headless_mode() -> bool {
    // Explicit env var override
    if let Ok(val) = env::var("RECORDER_HEADLESS") {
        return val.to_lowercase() != "false";
    }

    // Auto-detect based on display availability
    let disp = check_display_available();
    if disp.available {
        tracing::info!(
            display_type = ?disp.display_type,
            msg = %disp.message,
            "Display detected — using headed mode"
        );
        false // headed
    } else {
        tracing::info!(
            msg = %disp.message,
            "No display — using headless mode"
        );
        true // headless
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum DisplayMode {
    Headed,
    Headless,
    Xvfb,
}

impl std::fmt::Display for DisplayMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DisplayMode::Headed => write!(f, "headed"),
            DisplayMode::Headless => write!(f, "headless"),
            DisplayMode::Xvfb => write!(f, "xvfb"),
        }
    }
}

/// Start Xvfb virtual display on :99 (1920x1080x24).
/// Exact port of start.sh `start_xvfb()`.
pub fn start_xvfb() -> Result<(), String> {
    // Check if already running
    if xvfb_running() {
        env::set_var("DISPLAY", ":99");
        return Ok(());
    }

    // Start Xvfb from a TRUSTED bin dir — a `$PATH`-resolved `Xvfb` is arbitrary code execution as the
    // agent user for anyone who controls the launch environment.
    let xvfb = trusted_program("Xvfb")
        .ok_or_else(|| "Xvfb not found in a trusted system bin directory".to_string())?;
    let child = command_without_ai_keys(xvfb)
        .args([":99", "-screen", "0", "1920x1080x24"])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn();

    match child {
        Ok(_) => {
            std::thread::sleep(std::time::Duration::from_secs(1));
            env::set_var("DISPLAY", ":99");

            // Verify it started
            if xvfb_running() {
                return Ok(());
            }
            Err("Xvfb started but not running after 1 second".to_string())
        }
        Err(e) => Err(format!("Failed to start Xvfb: {}", e)),
    }
}

/// Install Xvfb via system package manager.
/// Exact port of start.sh `install_xvfb()`.
pub fn install_xvfb() -> Result<(), String> {
    let (cmd, args): (&str, &[&str]) = if which("apt-get").is_ok() {
        ("sudo", &["apt-get", "install", "-y", "xvfb", "x11-utils"])
    } else if which("yum").is_ok() {
        ("sudo", &["yum", "install", "-y", "xorg-x11-server-Xvfb", "xorg-x11-utils"])
    } else if which("dnf").is_ok() {
        ("sudo", &["dnf", "install", "-y", "xorg-x11-server-Xvfb", "xorg-x11-utils"])
    } else {
        return Err("No supported package manager found (apt-get, yum, dnf)".to_string());
    };

    // `sudo` too: it is the most valuable binary in the process to hijack.
    let sudo = trusted_program(cmd)
        .ok_or_else(|| format!("`{cmd}` not found in a trusted system bin directory"))?;
    let status = command_without_ai_keys(sudo)
        .args(args)
        .status()
        .map_err(|e| format!("Package install failed: {}", e))?;

    if status.success() {
        Ok(())
    } else {
        Err("Package install returned non-zero exit code".to_string())
    }
}

/// Locate a system helper. Kept as `which(…) -> Result<String, ()>` for the existing call sites, but it
/// no longer SHELLS OUT to `which` (itself a `$PATH` lookup we then executed) — it probes the fixed
/// [`TRUSTED_BIN_DIRS`] instead. See [`trusted_program`].
fn which(program: &str) -> Result<String, ()> {
    trusted_program(program)
        .map(|p| p.to_string_lossy().into_owned())
        .ok_or(())
}

/// Interactive display mode selector — same flow as start.sh lines 270-375.
/// Returns the chosen DisplayMode and whether Xvfb was started.
pub fn interactive_display_mode_select() -> (DisplayMode, bool) {
    let display_info = check_display_available();

    println!();
    println!("  Checking display environment...");
    println!();

    match display_info.display_type {
        DisplayType::X11 => {
            println!("  \x1b[32m[OK]\x1b[0m X11 display detected (DISPLAY={})",
                display_info.display.as_deref().unwrap_or("?"));
            println!("       Headed mode available — native UI elements will render properly");
        }
        DisplayType::X11Unverified => {
            println!("  \x1b[33m[OK]\x1b[0m X11 display set (DISPLAY={}) but xdpyinfo not available",
                display_info.display.as_deref().unwrap_or("?"));
            println!("       Assuming display works...");
        }
        DisplayType::Wayland => {
            println!("  \x1b[32m[OK]\x1b[0m Wayland display detected");
            println!("       Headed mode available — native UI elements will render properly");
        }
        DisplayType::MacOS => {
            println!("  \x1b[32m[OK]\x1b[0m macOS display detected");
            println!("       Headed mode available — native UI elements will render properly");
        }
        DisplayType::Windows => {
            println!("  \x1b[32m[OK]\x1b[0m Windows display detected");
            println!("       Headed mode available — native UI elements will render properly");
        }
        DisplayType::XvfbDocker => {
            println!("  \x1b[32m[OK]\x1b[0m Xvfb running in Docker");
            println!("       Headed mode available");
        }
        DisplayType::None => {
            println!("  \x1b[31m[!]\x1b[0m No display server detected");
            println!("       Headless mode will be used — some UI elements may not render");
        }
    }

    println!();
    println!("  Select display mode:");
    println!();

    if display_info.available {
        println!("    1) Headed (use current display)");
        println!("       \x1b[32mRecommended — display available\x1b[0m");
    } else {
        println!("    1) Headed (use current display)");
        println!("       \x1b[33mWarning: No display detected — may fail\x1b[0m");
    }
    println!();
    println!("    2) Headless (no display needed)");
    println!("       \x1b[33mFaster but no native UI rendering\x1b[0m");
    println!();

    if cfg!(target_os = "linux") {
        println!("    3) Xvfb (virtual display)");
        println!("       \x1b[32mEnables headed mode without a physical display\x1b[0m");
        println!();
    }

    let max_choice = if cfg!(target_os = "linux") { 3 } else { 2 };
    let default = if display_info.available { 1 } else { 2 };

    loop {
        eprint!("  Choice [1-{}] (default {}): ", max_choice, default);
        let mut input = String::new();
        if std::io::stdin().read_line(&mut input).is_err() {
            return (if display_info.available { DisplayMode::Headed } else { DisplayMode::Headless }, false);
        }
        let input = input.trim();
        let choice: u32 = if input.is_empty() {
            default
        } else {
            match input.parse() {
                Ok(n) => n,
                Err(_) => {
                    println!("  Invalid choice.");
                    continue;
                }
            }
        };

        match choice {
            1 => {
                println!();
                println!("  \x1b[32m→ Headed mode\x1b[0m");
                return (DisplayMode::Headed, false);
            }
            2 => {
                println!();
                println!("  \x1b[33m→ Headless mode\x1b[0m");
                return (DisplayMode::Headless, false);
            }
            3 if cfg!(target_os = "linux") => {
                println!();
                // Check if Xvfb is already available
                if which("Xvfb").is_err() {
                    println!("  Xvfb not installed.");
                    eprint!("  Install Xvfb? [Y/n]: ");
                    let mut yn = String::new();
                    let _ = std::io::stdin().read_line(&mut yn);
                    if yn.trim().to_lowercase() != "n" {
                        match install_xvfb() {
                            Ok(()) => println!("  \x1b[32m[OK]\x1b[0m Xvfb installed"),
                            Err(e) => {
                                println!("  \x1b[31m[FAIL]\x1b[0m {}", e);
                                println!("  Falling back to headless mode.");
                                return (DisplayMode::Headless, false);
                            }
                        }
                    } else {
                        println!("  Falling back to headless mode.");
                        return (DisplayMode::Headless, false);
                    }
                }

                match start_xvfb() {
                    Ok(()) => {
                        println!("  \x1b[32m[OK]\x1b[0m Xvfb started on display :99");
                        println!("  \x1b[32m→ Headed mode via Xvfb\x1b[0m");
                        return (DisplayMode::Xvfb, true);
                    }
                    Err(e) => {
                        println!("  \x1b[31m[FAIL]\x1b[0m {}", e);
                        println!("  Falling back to headless mode.");
                        return (DisplayMode::Headless, false);
                    }
                }
            }
            _ => {
                println!("  Invalid choice.");
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `$PATH` is never consulted, and a program name can't be used to escape the trusted roots.
    #[test]
    fn trusted_program_ignores_path_and_rejects_path_fragments() {
        // Plant a shim in a writable dir and put it FIRST on $PATH — the old `which` subprocess would
        // have returned it and we would have executed it.
        let dir = tempfile::tempdir().unwrap();
        let shim = dir.path().join("writ_fake_helper_xyz");
        std::fs::write(&shim, b"#!/bin/sh\nexit 0\n").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&shim, std::fs::Permissions::from_mode(0o755)).unwrap();
        }
        let prev_path = env::var_os("PATH");
        env::set_var(
            "PATH",
            format!("{}:{}", dir.path().display(), prev_path.as_ref().map(|p| p.to_string_lossy().into_owned()).unwrap_or_default()),
        );

        assert!(
            trusted_program("writ_fake_helper_xyz").is_none(),
            "a $PATH-planted binary must never be resolved"
        );
        assert!(which("writ_fake_helper_xyz").is_err(), "the `which` wrapper agrees");

        match prev_path {
            Some(v) => env::set_var("PATH", v),
            None => env::remove_var("PATH"),
        }

        // Path fragments / traversal are rejected outright.
        for bad in ["", "../../bin/sh", "/bin/sh", "sub/dir/tool", "..\\evil"] {
            assert!(trusted_program(bad).is_none(), "must reject `{bad}`");
        }
    }

    /// A real system helper still resolves — the guard must not break normal operation.
    #[cfg(unix)]
    #[test]
    fn trusted_program_finds_a_real_system_helper() {
        // `sh` exists at /bin/sh on every supported unix.
        let found = trusted_program("sh").expect("/bin/sh resolves");
        assert!(found.is_absolute(), "{}", found.display());
        assert!(
            TRUSTED_BIN_DIRS.iter().any(|r| found.starts_with(r)),
            "resolved under a trusted root: {}",
            found.display()
        );
    }

    /// A child process never inherits a BYO AI key the user exported in their shell.
    #[cfg(unix)]
    #[test]
    fn spawned_children_do_not_inherit_ai_keys() {
        let sh = trusted_program("sh").expect("/bin/sh");
        // The parent env holds a key (e.g. `ANTHROPIC_API_KEY=… writ start`).
        env::set_var("ANTHROPIC_API_KEY", "sk-ant-TESTkeyVALUE1234567890");
        let out = command_without_ai_keys(&sh)
            .args(["-c", "echo \"[${ANTHROPIC_API_KEY:-unset}][${OPENAI_API_KEY:-unset}]\""])
            .output()
            .expect("spawn sh");
        env::remove_var("ANTHROPIC_API_KEY");

        let stdout = String::from_utf8_lossy(&out.stdout);
        assert!(!stdout.contains("TESTkeyVALUE"), "key leaked into the child: {stdout}");
        assert!(stdout.contains("[unset][unset]"), "both keys unset in the child: {stdout}");
    }
}
