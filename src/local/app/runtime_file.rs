//! `runtime.json` — the local discovery descriptor a UI/CLI reads to find a running daemon.
//!
//! Written `0600` to `~/.writ/runtime.json` on bootstrap and removed on clean shutdown. It carries
//! the loopback port, the running pid, the process version, the start time, and the `wlt_` runtime
//! token a same-machine client presents as the bearer. The file is the discovery + handshake
//! contract: it MUST never leave the machine, hence the restrictive mode. See the local-backend spec
//! §0/§10.
//!
//! Net-new Rust — NOT ported from the legacy Python `desktop-agent`.

use crate::local::config::Paths;
use crate::local::error::LocalResult;
use serde::{Deserialize, Serialize};
use std::path::Path;

/// Discovery descriptor persisted at `~/.writ/runtime.json`.
///
/// `token` is the `wlt_` runtime bearer — same-machine only, never logged, never transmitted. It is
/// included here because a co-located UI reads this file (mode `0600`) to authenticate to the
/// loopback API; the file is the trust boundary, not the wire.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RuntimeInfo {
    pub pid: u32,
    pub port: u16,
    pub token: String,
    pub version: String,
    /// RFC3339 UTC start time.
    pub started_at: String,
}

impl RuntimeInfo {
    /// Capture the current process's runtime descriptor.
    pub fn current(port: u16, token: impl Into<String>) -> Self {
        Self {
            pid: std::process::id(),
            port,
            token: token.into(),
            version: env!("CARGO_PKG_VERSION").to_string(),
            started_at: chrono::Utc::now().to_rfc3339(),
        }
    }
}

/// Serialize `info` and persist it `0600` at `paths.runtime_json()`.
pub fn write(paths: &Paths, info: &RuntimeInfo) -> LocalResult<()> {
    let bytes = serde_json::to_vec_pretty(info)?;
    write_0600(&paths.runtime_json(), &bytes)
}

/// Read + parse `~/.writ/runtime.json`. Returns `Ok(None)` if the file is absent (no daemon
/// discovered); surfaces other IO/parse errors.
pub fn read(paths: &Paths) -> LocalResult<Option<RuntimeInfo>> {
    match std::fs::read(paths.runtime_json()) {
        Ok(bytes) => Ok(Some(serde_json::from_slice(&bytes)?)),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e.into()),
    }
}

/// Best-effort removal of the descriptor (clean shutdown). A missing file is not an error.
pub fn remove(paths: &Paths) {
    let _ = std::fs::remove_file(paths.runtime_json());
}

/// Persist `runtime.json` `0600` via the shared atomic secret writer so the `wlt_` token it carries is
/// never world-readable, not even for the instant between a plain write and a follow-up chmod.
fn write_0600(path: &Path, bytes: &[u8]) -> LocalResult<()> {
    crate::local::vault::write_secret_file(path, bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn runtime_round_trip() {
        let dir = tempfile::tempdir().unwrap();
        let paths = Paths::at(dir.path().join(".writ"));
        paths.ensure_dirs().unwrap();

        // Absent until written.
        assert_eq!(read(&paths).unwrap(), None);

        let info = RuntimeInfo {
            pid: 4242,
            port: 8131,
            token: "wlt_secret".into(),
            version: "1.2.3".into(),
            started_at: "2026-06-28T12:00:00+00:00".into(),
        };
        write(&paths, &info).unwrap();

        let back = read(&paths).unwrap().expect("descriptor present after write");
        assert_eq!(back, info);

        // Mode is 0600 (owner-only) on unix — the token must not be world-readable.
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(paths.runtime_json()).unwrap().permissions().mode();
            assert_eq!(mode & 0o777, 0o600, "runtime.json must be 0600");
        }

        // `current()` stamps this process's pid + the crate version.
        let cur = RuntimeInfo::current(9000, "wlt_x");
        assert_eq!(cur.pid, std::process::id());
        assert_eq!(cur.port, 9000);
        assert_eq!(cur.version, env!("CARGO_PKG_VERSION"));

        // Removal is idempotent.
        remove(&paths);
        assert_eq!(read(&paths).unwrap(), None);
        remove(&paths); // no panic on second remove
    }
}
