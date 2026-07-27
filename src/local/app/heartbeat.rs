//! `~/.writ/agentd.json` — the 5s liveness heartbeat the thin UI polls to tell "is the daemon alive
//! and healthy?" without hitting the loopback API (the local-backend spec §0).
//!
//! Written `0600` every [`HEARTBEAT_INTERVAL`] from a background task and removed on clean shutdown.
//! The payload is `{pid, started_at, healthy, active_runs, due_monitors, last_tick_at, warm_browser}`
//! — liveness only. It NEVER carries a token, key, or any `~/.writ` path (it lives AT that path; it
//! does not name it).

use std::sync::Arc;
use std::time::Duration;

use serde::{Deserialize, Serialize};
use tokio::sync::watch;
use tokio::task::JoinHandle;

use crate::local::app::health::SharedHealth;
use crate::local::config::Paths;
use crate::local::engine::LocalEngine;

/// How often the heartbeat file is rewritten.
pub const HEARTBEAT_INTERVAL: Duration = Duration::from_secs(5);

/// The on-disk `agentd.json` shape. Stable field names — the UI reads these directly.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Heartbeat {
    pub pid: u32,
    /// RFC3339 UTC daemon start time (constant across the process lifetime).
    pub started_at: String,
    /// Coarse health: true while the daemon's serve loop + scheduler are up. Detailed reachability
    /// (db/keyring/cipher) lives behind `GET /v1/health`; the heartbeat is a cheap liveness ping.
    pub healthy: bool,
    pub active_runs: u64,
    pub due_monitors: i64,
    /// RFC3339 of the last completed scheduler tick, or `null` before the first tick.
    pub last_tick_at: Option<String>,
    pub warm_browser: bool,
}

/// Owns the running heartbeat task + its cancellation channel. Call [`shutdown`](Self::shutdown) from
/// the daemon's signal handler for a clean stop (the file is removed by lifecycle `release`).
pub struct HeartbeatHandle {
    cancel: watch::Sender<bool>,
    task: JoinHandle<()>,
}

impl HeartbeatHandle {
    /// Signal the writer to stop and await its exit. Idempotent-ish: a second call (or one after the
    /// task already ended) returns immediately.
    pub async fn shutdown(self) {
        let _ = self.cancel.send(true);
        match self.task.await {
            Ok(()) => tracing::debug!("heartbeat writer stopped"),
            Err(e) if e.is_cancelled() => {}
            Err(e) => tracing::warn!(error = %e, "heartbeat task join error on shutdown"),
        }
    }
}

/// Spawn the heartbeat writer. Writes `agentd.json` immediately, then every [`HEARTBEAT_INTERVAL`]
/// until shutdown. A write failure is logged at debug (the UI tolerates a stale/absent file by
/// treating the daemon as down) and never crashes the daemon.
pub fn spawn_heartbeat(
    paths: Paths,
    engine: Arc<dyn LocalEngine>,
    health: SharedHealth,
    started_at: String,
) -> HeartbeatHandle {
    let (cancel_tx, mut cancel_rx) = watch::channel(false);
    let pid = std::process::id();

    let task = tokio::spawn(async move {
        let mut ticker = tokio::time::interval(HEARTBEAT_INTERVAL);
        // Write one immediately, then on the cadence (no skipped catch-up burst after a slow write).
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            tokio::select! {
                biased;
                res = cancel_rx.changed() => {
                    if res.is_err() || *cancel_rx.borrow() {
                        break;
                    }
                }
                _ = ticker.tick() => {
                    let hb = Heartbeat {
                        pid,
                        started_at: started_at.clone(),
                        healthy: true,
                        active_runs: engine.active_runs() as u64,
                        due_monitors: health.due_monitors(),
                        last_tick_at: health.last_tick_at(),
                        warm_browser: health.warm_browser(),
                    };
                    if let Err(e) = write(&paths, &hb) {
                        tracing::debug!(error = %e, "failed to write agentd.json heartbeat");
                    }
                }
            }
        }
    });

    HeartbeatHandle { cancel: cancel_tx, task }
}

/// Serialize `hb` and persist it `0600` at `paths.agentd_json()`.
pub fn write(paths: &Paths, hb: &Heartbeat) -> std::io::Result<()> {
    let bytes = serde_json::to_vec(hb).map_err(std::io::Error::other)?;
    std::fs::write(paths.agentd_json(), &bytes)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(paths.agentd_json(), std::fs::Permissions::from_mode(0o600))?;
    }
    Ok(())
}

/// Read + parse `~/.writ/agentd.json`. Returns `Ok(None)` when absent (daemon down / never started).
pub fn read(paths: &Paths) -> std::io::Result<Option<Heartbeat>> {
    match std::fs::read(paths.agentd_json()) {
        Ok(bytes) => Ok(Some(serde_json::from_slice(&bytes).map_err(std::io::Error::other)?)),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e),
    }
}

/// Best-effort removal of the heartbeat file (clean shutdown). Missing file is not an error.
pub fn remove(paths: &Paths) {
    let _ = std::fs::remove_file(paths.agentd_json());
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn heartbeat_round_trips_and_is_0600() {
        let dir = tempfile::tempdir().unwrap();
        let paths = Paths::at(dir.path().join(".writ"));
        paths.ensure_dirs().unwrap();

        assert_eq!(read(&paths).unwrap(), None);

        let hb = Heartbeat {
            pid: 1234,
            started_at: "2026-06-29T00:00:00Z".into(),
            healthy: true,
            active_runs: 2,
            due_monitors: 5,
            last_tick_at: Some("2026-06-29T00:00:05.000Z".into()),
            warm_browser: true,
        };
        write(&paths, &hb).unwrap();
        assert_eq!(read(&paths).unwrap().as_ref(), Some(&hb));

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(paths.agentd_json()).unwrap().permissions().mode();
            assert_eq!(mode & 0o777, 0o600, "agentd.json must be 0600");
        }

        remove(&paths);
        assert_eq!(read(&paths).unwrap(), None);
        remove(&paths); // idempotent
    }
}
