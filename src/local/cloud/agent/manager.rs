//! `LinkedAgentManager` — the supervised lifecycle holder for the full cloud execution agent
//! (`golden-stargazing-gadget` Workstream A, §6).
//!
//! A near-copy of [`crate::local::relay::node::RelayNodeManager`] (the proven supervised-loop
//! template): it holds the shared runtime state, exposes `start`/`stop` that the `/v1/cloud/agent/*`
//! handlers + the boot supervisor drive, and runs a supervised loop that — while desired-running —
//! builds a [`LinkedAgentBridge`] with the engine's warm subsystems and awaits `bridge.run()`,
//! reconnecting for the process lifetime. A `stop()` (or unlink/disable) races the serve future via a
//! `wake` notify so the WS tears down promptly.
//!
//! SECURITY (HARD INVARIANTS — will be audited, the never-trust-a-BYO-agent rule): the agent NEVER
//! starts unless ALL of [`LinkedAgentManager::can_run`]'s preconditions hold — the desktop is cloud
//! LINKED, the user has not explicitly DISABLED the agent, and a channel key is sealed in the keyring
//! (no channel key ⇒ the agent can't decrypt any per-run cloud creds ⇒ it must not advertise). All
//! start paths are gated on this so an unlinked / key-less daemon can never connect the agent.
//! Identity/isolation/billing stay server-side; the agent authorizes nothing.
//!
//! Net-new Rust in this crate (behind the `local` feature), Workstream A stage 3.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, OnceLock};

use serde::Serialize;
use sqlx::sqlite::SqlitePool;
use tokio::sync::{Mutex, Notify};

use super::super::gateway::{BridgeExit, BridgeStatus, LinkedAgentBridge};
use super::super::state::LinkState;
use crate::local::engine::LocalEngine;
use crate::local::error::LocalResult;
use crate::local::vault::Vault;

/// Process-global slot for the single [`LinkedAgentManager`], so the `/v1/cloud/agent/*` handlers +
/// the cloud link/unlink REST path can drive start/stop without threading a new field through
/// `AppState`. Installed once at daemon boot (mirrors the relay `node::GLOBAL` /
/// `cloud::link` process-global pattern). `None` until installed (e.g. unit tests that don't boot the
/// daemon) — handlers then operate on config + link state only.
static GLOBAL: OnceLock<Arc<LinkedAgentManager>> = OnceLock::new();

/// Install the process-global agent manager. Idempotent: a second call is a no-op. Returns whether
/// THIS call won the slot (mirrors `relay::node::install_global`).
pub fn install_global(mgr: Arc<LinkedAgentManager>) -> bool {
    GLOBAL.set(mgr).is_ok()
}

/// The installed process-global agent manager, if any.
pub fn global() -> Option<Arc<LinkedAgentManager>> {
    GLOBAL.get().cloned()
}

/// A plain, non-secret snapshot of the agent's live state for the `/v1/cloud/agent/status` response.
/// NEVER carries token / channel-key / credential material.
#[derive(Debug, Clone, Serialize)]
pub struct AgentStatusSnapshot {
    /// The operator currently WANTS the agent running (intent). Distinct from `online`.
    pub desired_running: bool,
    /// The agent's outbound gateway WS is up right now (liveness). Reflects the running bridge.
    pub online: bool,
    /// The last transport/connect error the supervisor observed, if any (non-secret, char-safe).
    pub last_error: Option<String>,
    /// Stable, non-secret token naming the precondition that is currently blocking the agent from
    /// running (`"unlinked"`, `"disabled"`, `"no_channel_key"`), or `None` when all gates pass.
    /// The UI shows this so a "linked but Offline" state has a specific reason — previously the
    /// gate was only logged, leaving the user with a silent Offline for `start()` refusals.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub blocking_reason: Option<&'static str>,
}

/// The supervised lifecycle holder for the full cloud execution agent.
///
/// `desired_running` is the operator's intent (enable/link ⇒ true; disable/unlink ⇒ false). The live
/// `bridge` handle lets `stop()` tear the running WS down. The `wake` notify lets the supervised loop
/// react to state changes promptly. `db`/`engine`/`vault` are re-read at start time so the bridge is
/// built with the freshest link + warm subsystems.
pub struct LinkedAgentManager {
    db: SqlitePool,
    engine: Arc<dyn LocalEngine>,
    vault: Arc<Vault>,
    /// The shared in-process recorder that drives the daemon's OWN warm Chromium (lifecycle stage
    /// 5b). Threaded through here so a cloud-dispatched `session_open{purpose:"record"}` can spawn a
    /// [`crate::local::record::session::SessionDriver`] over the SAME recorder the loopback
    /// `/ws/record` uses — never a second recorder / second browser. `None` in a browserless
    /// (StubEngine) build; the bridge's record router then fails the open closed with a matching
    /// `session_opened{success:false}` ack.
    recorder: Option<Arc<crate::recorder::core::PlaywrightRecorder>>,
    /// Allow plaintext cloud endpoints (loopback-equivalent dev only). Off in production boot.
    allow_insecure: bool,
    desired_running: AtomicBool,
    /// The live bridge for the current supervised connection, so `stop()` can `shutdown()` it. `None`
    /// while parked (desired-stopped) or between reconnects.
    bridge: Mutex<Option<Arc<LinkedAgentBridge>>>,
    /// Shared liveness/error state, WRITTEN by the running bridge on real connect/disconnect (and by
    /// this supervisor on stop/precondition-fail). `online`/`last_error` in the status snapshot read it,
    /// so the endpoint reports true liveness (connected + welcomed) — never an optimistic "attempting".
    status: Arc<BridgeStatus>,
    wake: Notify,
}

impl LinkedAgentManager {
    /// Build a manager over the engine + encrypted store + vault. The agent is NOT running until
    /// [`LinkedAgentManager::start`] is called (and only then if its preconditions hold). Production
    /// boot passes `allow_insecure = false` (require wss/https unless the endpoint is loopback).
    ///
    /// `recorder` is the shared `PlaywrightRecorder` from lifecycle stage 5b — pass `Some` when the
    /// engine has a warm browser (production), `None` on a browserless StubEngine build. A cloud
    /// `session_open{purpose:"record"}` needs it to spawn the same recording driver the loopback
    /// `/ws/record` uses (no second recorder, no second Chromium).
    pub fn new(
        db: SqlitePool,
        engine: Arc<dyn LocalEngine>,
        vault: Arc<Vault>,
        recorder: Option<Arc<crate::recorder::core::PlaywrightRecorder>>,
    ) -> Self {
        Self {
            db,
            engine,
            vault,
            recorder,
            allow_insecure: false,
            desired_running: AtomicBool::new(false),
            bridge: Mutex::new(None),
            status: Arc::new(BridgeStatus::default()),
            wake: Notify::new(),
        }
    }

    /// Whether the operator currently WANTS the agent running (intent, not liveness).
    pub fn is_desired_running(&self) -> bool {
        self.desired_running.load(Ordering::Relaxed)
    }

    /// True when ALL hard preconditions to run the agent are satisfied right now: the desktop is
    /// LINKED with an account token still stored (an `invalid_grant` clears the keyring token while
    /// LinkState still says linked), the agent is not explicitly DISABLED by config, and a channel
    /// key is sealed (without it the agent can't decrypt per-run cloud creds so it must not
    /// advertise). Returns `Ok(false)` (not an error) when a precondition is simply absent (mirrors
    /// relay `can_run`).
    ///
    /// SECURITY: the agent is DEFAULT-ON when linked (no separate "enabled" flag to flip) but the
    /// explicit `cloud_agent_disabled` OFF-switch and the linked/keyed gates are HARD — an unlinked or
    /// key-less daemon can NEVER start the agent (the never-trust-a-BYO-agent rule).
    pub async fn can_run(&self) -> LocalResult<bool> {
        Ok(self.blocking_gate().await?.is_none())
    }

    /// The specific precondition that is blocking the agent right now, or `None` when all gates pass.
    /// Same checks + same order as [`LinkedAgentManager::can_run`] — factored out so callers (start,
    /// supervisor) can log WHY the agent stayed stopped instead of a single opaque "preconditions not
    /// met" line. The returned names are non-secret, stable, log-safe tokens.
    async fn blocking_gate(&self) -> LocalResult<Option<&'static str>> {
        // Linked?
        let link = LinkState::load_or_default(&self.db).await?;
        if !link.is_linked() {
            return Ok(Some("unlinked"));
        }
        // Account token still stored? `invalid_grant` clears the keyring token while the DB
        // LinkState still says linked — in that state every bridge connect fails instantly with
        // Unauthorized (no network round-trip), so the gate must refuse to (re)start the agent
        // rather than let the supervisor rebuild a doomed bridge. Also gives the status endpoint
        // a truthful blocking_reason instead of a bare last_error.
        if super::super::token::get()?.is_none() {
            return Ok(Some("no_account_token"));
        }
        // Explicitly disabled by the user? (default OFF ⇒ agent runs when linked).
        if self.agent_disabled().await {
            return Ok(Some("disabled"));
        }
        // Channel key sealed? No key ⇒ can't decrypt cloud creds ⇒ don't advertise.
        if super::super::channel::get()?.is_none() {
            return Ok(Some("no_channel_key"));
        }
        Ok(None)
    }

    /// Read the current `cloud_agent_disabled` flag from the persisted config (freshest value — the
    /// REST enable/disable path writes `config.toml`, and this manager holds no config snapshot). A
    /// read failure fails SAFE (treats the agent as NOT disabled, i.e. default-on-when-linked) rather
    /// than silently stopping a linked agent; the other `can_run` gates still hold.
    async fn agent_disabled(&self) -> bool {
        match crate::local::config::Paths::resolve() {
            Ok(paths) => crate::local::config::load_config(&paths).cloud_agent_disabled,
            Err(_) => false,
        }
    }

    /// START the agent: gate on [`LinkedAgentManager::can_run`], then flip desired-running + wake the
    /// supervised loop (which builds the bridge + dials the gateway). A no-op returning `false` when a
    /// precondition isn't met (the agent stays stopped — defense in depth on top of the REST gate).
    ///
    /// SECURITY: refuses to start when the desktop is not linked / not keyed / explicitly disabled
    /// (HARD INVARIANT — those conditions ⇒ the agent never starts).
    pub async fn start(&self) -> LocalResult<bool> {
        if let Some(gate) = self.blocking_gate().await? {
            tracing::info!(gate, "cloud agent start requested but preconditions not met — staying stopped");
            return Ok(false);
        }
        self.desired_running.store(true, Ordering::Relaxed);
        // Edge-triggered wake: `notified()` inside the supervisor's outer `select!` is a live
        // waiter (bridge already running) and gets woken; if the loop is parked at the top-level
        // `notified().await`, that waiter is also live. The historical `notify_waiters()` semantics
        // are the working shape — DO NOT switch to `notify_one()`: the stored permit is consumed
        // by the FIRST `notified()` polled on the shared Notify, which for a running bridge is the
        // supervisor's `select!` branch that then calls `bridge.shutdown()`. Any callers that
        // repeatedly `start()` a bridge that is already running would hot-loop the supervisor
        // (tear-down + rebuild + reconnect + tear-down…), which we OBSERVED in the wild.
        self.wake.notify_waiters();
        tracing::info!("cloud agent start requested");
        Ok(true)
    }

    /// STOP the agent: flip desired-running off, `shutdown()` any live bridge (stops its run loop), and
    /// wake the supervised loop so it parks. Idempotent.
    pub fn stop(&self) {
        self.desired_running.store(false, Ordering::Relaxed);
        // Reflect offline immediately (the bridge future may be dropped by the supervisor's select
        // before it can mark itself). A clean stop leaves any prior error untouched.
        self.status.mark_disconnected(None);
        // Best-effort synchronous shutdown of the live bridge. `try_lock` avoids blocking a caller that
        // holds no runtime (the supervised loop also observes `desired_running` + `wake` and tears the
        // bridge down on the next race, so a contended lock here is not load-bearing).
        if let Ok(guard) = self.bridge.try_lock() {
            if let Some(bridge) = guard.as_ref() {
                bridge.shutdown();
            }
        }
        self.wake.notify_waiters();
        tracing::info!("cloud agent stop requested");
    }

    /// The supervised run loop, spawned once at daemon boot. Parks on `wake` while desired-stopped;
    /// while desired-running it builds a [`LinkedAgentBridge`] over the warm engine subsystems and
    /// awaits `bridge.run()` (its OWN reconnect/backoff loop), racing `wake.notified()` so a
    /// `stop()`/unlink tears the WS down promptly. Never returns (lives for the process).
    pub async fn run(self: Arc<Self>) {
        tracing::debug!("cloud agent supervisor started");
        loop {
            if !self.is_desired_running() {
                self.status.mark_disconnected(None);
                self.wake.notified().await;
                continue;
            }

            // Re-check preconditions each cycle (a stale desired flag from an unlink/disable that
            // hasn't wired stop() yet must not connect a doomed agent).
            match self.blocking_gate().await {
                Ok(None) => {}
                Ok(Some(gate)) => {
                    tracing::info!(gate, "cloud agent supervisor parking — precondition failed");
                    self.desired_running.store(false, Ordering::Relaxed);
                    self.status.mark_disconnected(None);
                    continue;
                }
                Err(e) => {
                    // Surface the precondition-read failure so the status endpoint shows WHY the agent
                    // isn't connecting rather than a silent offline.
                    self.status.mark_disconnected(Some(truncate_err(&e.to_string())));
                    // Precondition read failed transiently: park until woken rather than hot-loop.
                    self.wake.notified().await;
                    continue;
                }
            }

            // Build a fresh full-capability bridge over the warm subsystems. `link` is loaded here so
            // the bridge resolves the current cloud base url.
            let link = LinkState::load(&self.db).await.ok().flatten();
            // Hand the bridge the shared status handle so IT publishes the REAL connect/disconnect
            // state (WS up + welcomed vs. retrying) + the last error — the supervisor no longer guesses
            // "online" the moment it starts attempting.
            let bridge = Arc::new(
                LinkedAgentBridge::with_subsystems(
                    self.engine.clone(),
                    self.db.clone(),
                    self.vault.clone(),
                    link,
                    self.allow_insecure,
                )
                .with_status(self.status.clone())
                .with_recorder(self.recorder.clone()),
            );
            *self.bridge.lock().await = Some(bridge.clone());

            // Serve one bridge lifetime (its own reconnect loop), racing a stop/intent change so we
            // tear down promptly. `bridge.run()` returns on a clean unlink/disconnect or when its
            // internal `running` flag is cleared by `shutdown()`.
            let started = tokio::time::Instant::now();
            let run_bridge = bridge.clone();
            tokio::select! {
                exit = run_bridge.run() => {
                    match exit {
                        // Token cleared/revoked (invalid_grant): every rebuild fails instantly with
                        // no network round-trip, so rebuilding here was a ~500 Hz error-log storm.
                        // PARK until re-link — link_poll success calls `start()`, which re-gates and
                        // wakes us. The bridge already recorded the error on the shared status.
                        BridgeExit::Unauthorized => {
                            tracing::warn!(
                                "cloud agent supervisor parking — cloud link unauthorized (re-link required)"
                            );
                            self.desired_running.store(false, Ordering::Relaxed);
                        }
                        BridgeExit::Stopped => {
                            // `run()` backs off internally before every reconnect, so a Stopped exit
                            // this fast means a bug regressed that. Never let the rebuild loop spin
                            // hot again — floor it at 1s.
                            if started.elapsed() < std::time::Duration::from_secs(1) {
                                tokio::time::sleep(std::time::Duration::from_secs(1)).await;
                            }
                        }
                    }
                }
                () = self.wake.notified() => {
                    // Intent changed (stop/disable/unlink): stop the bridge loop + drop the future.
                    bridge.shutdown();
                }
            }

            // The bridge future may have been DROPPED by the select (never ran its own offline mark),
            // so reflect offline here. A clean transition leaves any recorded error intact.
            self.status.mark_disconnected(None);
            *self.bridge.lock().await = None;
            // If still desired-running (a transient bridge exit, not a stop), loop back to rebuild +
            // reconnect; an Unauthorized exit flipped desired-running off above, so the loop parks.
        }
    }

    /// A non-secret snapshot of the agent's current state for the status endpoint.
    ///
    /// Async because it reads the DB-backed link state (via [`blocking_gate`]) so the UI can see
    /// WHY the agent is refusing to run instead of a silent Offline. A gate-read failure fails
    /// SAFE (no `blocking_reason`) — the endpoint never 500s on a transient DB blip.
    pub async fn snapshot(&self) -> AgentStatusSnapshot {
        AgentStatusSnapshot {
            desired_running: self.desired_running.load(Ordering::Relaxed),
            // TRUE liveness (WS up + welcomed), published by the running bridge — not the old optimistic
            // "the supervisor is attempting" flag that made a failing connect look online.
            online: self.status.is_connected(),
            last_error: self.status.last_error(),
            blocking_reason: self.blocking_gate().await.ok().flatten(),
        }
    }

    /// Live cloud-initiated `(task_id, run_id)` pairs from the process-global correlation map (§7), for
    /// the `GET /v1/cloud/agent/runs` listing. Pure routing metadata — never any credential/recipe.
    pub fn live_runs(&self) -> Vec<(String, i64)> {
        super::runs::live_pairs()
    }

    /// Poke the current bridge (if any) to re-send the `local_catalog` frame right away — a
    /// workflow create/update/delete just changed what should be advertised. Silently no-op when
    /// the supervisor is parked (unlinked / disabled / preconditions unmet) or between reconnects;
    /// the next connect always sends a fresh catalog. Returns whether a live bridge was poked.
    pub async fn request_catalog_refresh(&self) -> bool {
        let guard = self.bridge.lock().await;
        match guard.as_ref() {
            Some(bridge) => {
                bridge.request_catalog_refresh();
                true
            }
            None => false,
        }
    }
}

/// Poke the installed cloud-agent bridge to re-send its `local_catalog` frame. Called from the
/// workflow REST handlers after any create/update/delete that could change what the cloud sees, so
/// a `cloud_callable` toggle takes effect without waiting for a WS reconnect or a
/// `request_local_catalog` from the backend. A no-op when the process has no manager installed
/// (unit tests, or a daemon booted without cloud) or the manager is parked (unlinked / disabled).
pub async fn notify_catalog_dirty() {
    if let Some(mgr) = global() {
        let _ = mgr.request_catalog_refresh().await;
    }
}

/// Char-safe truncation for a wire/engine-derived error string before it lands in the status snapshot
/// (a hostile gateway could otherwise wedge a multibyte string sliced mid-codepoint). 240 chars is
/// plenty for a diagnostic message.
fn truncate_err(s: &str) -> String {
    s.chars().take(240).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::local::config::Paths;
    use crate::local::engine::StubEngine;
    use crate::local::{db, vault::Vault};

    async fn test_manager() -> (tempfile::TempDir, Arc<LinkedAgentManager>) {
        let dir = tempfile::tempdir().unwrap();
        let paths = Paths::at(dir.path().join(".writ"));
        paths.ensure_dirs().unwrap();
        let vault = Arc::new(Vault::load_or_create(&paths.root, false).unwrap());
        let pool = db::open(&paths.db(), &vault.db_key_hex()).await.unwrap();
        let engine: Arc<dyn LocalEngine> = Arc::new(StubEngine);
        // Test builds pass no recorder (StubEngine has no warm browser anyway); the record-open
        // router path then fail-closes with a `session_opened{success:false}` ack.
        let mgr = Arc::new(LinkedAgentManager::new(pool, engine, vault, None));
        (dir, mgr)
    }

    #[tokio::test]
    async fn manager_start_refuses_when_unlinked() {
        let (_dir, mgr) = test_manager().await;
        // Unlinked → can_run false → start is a no-op (never connects).
        assert!(!mgr.can_run().await.unwrap());
        assert!(!mgr.start().await.unwrap(), "must not start while unlinked");
        assert!(!mgr.is_desired_running());

        // stop is always idempotent.
        mgr.stop();
        assert!(!mgr.is_desired_running());
    }

    #[tokio::test]
    async fn manager_refuses_when_linked_but_no_channel_key() {
        // Linked metadata present, but no channel key sealed → can_run false (can't decrypt cloud
        // creds ⇒ don't advertise). This is the HARD "no channel key" gate.
        let (_dir, mgr) = test_manager().await;
        LinkState {
            account_id: "acct_agent".into(),
            email: "u@example.com".into(),
            cloud_base_url: "https://api.usewrit.app".into(),
            scopes: vec![],
            linked_at: Some(chrono::Utc::now()),
            language: None,
        }
        .save(&mgr.db)
        .await
        .unwrap();

        // In the test process there is no keyring channel key sealed for this link → can_run false.
        // `channel::get()` yields Ok(None) when nothing is sealed — but in a session with no
        // default keychain (headless / CI / a parallel `cargo test` run) it yields Err instead,
        // so `.unwrap()` here would panic on the ENVIRONMENT rather than fail on the behaviour.
        // Match Ok(None) explicitly: assert only when we could actually consult the keyring.
        if matches!(super::super::super::channel::get(), Ok(None)) {
            assert!(!mgr.can_run().await.unwrap(), "linked but no channel key ⇒ must not run");
            assert!(!mgr.start().await.unwrap(), "must not start without a channel key");
            assert!(!mgr.is_desired_running());
        }
    }

    #[tokio::test]
    async fn snapshot_is_non_secret_and_defaults_offline() {
        let (_dir, mgr) = test_manager().await;
        let snap = mgr.snapshot().await;
        assert!(!snap.desired_running);
        assert!(!snap.online);
        assert!(snap.last_error.is_none());
        // Unlinked at rest → the gate names the reason so the UI can explain the Offline.
        assert_eq!(snap.blocking_reason, Some("unlinked"));
        // The snapshot serializes without any token/secret field.
        let raw = serde_json::to_string(&snap).unwrap();
        assert!(!raw.contains("wto_") && !raw.contains("channel"), "no secret leak: {raw}");
    }

    #[tokio::test]
    async fn live_runs_reflects_the_process_map() {
        let (_dir, mgr) = test_manager().await;
        let tid = "manager-live-runs-test-1";
        super::super::runs::bind(tid, 909);
        assert!(mgr.live_runs().iter().any(|(t, r)| t == tid && *r == 909));
        super::super::runs::unbind(tid);
        assert!(!mgr.live_runs().iter().any(|(t, _)| t == tid));
    }

    #[test]
    fn truncate_err_is_char_safe() {
        // A multibyte string truncated at the char boundary never panics.
        let s = "é".repeat(1000);
        let t = truncate_err(&s);
        assert_eq!(t.chars().count(), 240);
    }

    #[tokio::test]
    async fn request_catalog_refresh_returns_false_when_parked() {
        // No bridge is stashed until the supervised loop connects one. A workflow mutation firing
        // the refresh in that window is a silent no-op — the next connect will send a fresh catalog.
        let (_dir, mgr) = test_manager().await;
        assert!(!mgr.request_catalog_refresh().await, "no live bridge ⇒ nothing to poke");
    }

    #[tokio::test]
    async fn request_catalog_refresh_pokes_the_installed_bridge() {
        // With a bridge stashed in the manager's slot (the same shape the supervised loop uses
        // between connect and disconnect), `request_catalog_refresh` reports it poked one.
        let (_dir, mgr) = test_manager().await;
        let engine: Arc<dyn LocalEngine> = Arc::new(crate::local::engine::StubEngine);
        let bridge = Arc::new(crate::local::cloud::gateway::LinkedAgentBridge::new(
            engine,
            mgr.db.clone(),
            None,
            true,
        ));
        *mgr.bridge.lock().await = Some(bridge);
        assert!(mgr.request_catalog_refresh().await, "a live bridge slot ⇒ poke lands");
    }
}
