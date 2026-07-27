//! The daemon's background tick loop (Stage B).
//!
//! A single long-lived tokio task wakes on a fixed cadence and drives all of the local backend's
//! periodic work:
//!   1. DUE monitor checks + their `change_detected` automations — delegated to Stage A's
//!      [`crate::local::monitor::run_due_checks`] (we NEVER reimplement check logic here).
//!   2. DUE time-scheduled workflows — workflows with `schedule_enabled=1`, a positive
//!      `schedule_interval_ms`, and a `next_scheduled_at` that has come due — dispatched through the
//!      shared [`crate::local::engine::LocalEngine`] with [`RunSource::Scheduled`].
//!
//! ## What the schema supports (and what it does NOT)
//! The only first-class *time-scheduled* concept in the local schema (`migrations/0001_init.sql`) is
//! on the `workflows` table: `schedule_enabled` / `schedule_interval_ms` / `last_scheduled_at` /
//! `next_scheduled_at` (with the partial index `ix_workflows_due_schedule`). There is **no cron
//! column and no separate `scheduled_jobs` table**, so this scheduler implements a fixed-interval
//! cadence only — it does not (and cannot, without inventing columns) evaluate cron expressions.
//!
//! `webhook_triggers` are purely *inbound* HTTP triggers (token / `custom_path`); they carry NO
//! schedule/cron/interval column, so they are NOT time-driven and the tick does not poll them. They
//! fire from the REST webhook handler, which dispatches with [`RunSource::Webhook`]. The scheduler
//! therefore owns Monitor + Scheduled lanes only.
//!
//! ## Design properties (per the task contract)
//! * **Graceful shutdown** — a `tokio::sync::watch` cancellation channel; [`SchedulerHandle::shutdown`]
//!   flips it and `join`s the task so SIGTERM/SIGINT can stop the daemon cleanly.
//! * **Panic / error resilience** — each tick body runs inside `AssertUnwindSafe(..).catch_unwind`
//!   *and* its `LocalResult` is logged-not-propagated, so one bad tick never kills the loop.
//! * **Bounded concurrency** — scheduled-workflow dispatches run through a small semaphore
//!   (`max_concurrent_dispatch`, default 1) because the engine shares ONE warm browser.
//! * **No overlap pileup** — if a previous tick's heavy work is still running when the next cadence
//!   fires, the new tick is skipped (logged) rather than stacking. Monitor checks are inherently
//!   serialized inside `run_due_checks`; this guard protects the slower scheduled-workflow lane.

pub mod capacity;
pub mod clamp;
mod loop_task;
pub mod recurrence;
mod scheduled;
mod scheduled_automations;
mod tick;

use std::sync::Arc;

use sqlx::SqlitePool;
use tokio::sync::watch;
use tokio::task::JoinHandle;

use crate::local::app::health::SharedHealth;
use crate::local::engine::LocalEngine;

pub use scheduled::ScheduledReport;
pub use scheduled_automations::ScheduledAutomationReport;
pub use tick::TickSummary;

/// Default cadence between scheduler wakeups. Generous for a single-user desktop — monitor `next_run_at`
/// and the anti-detection floor are the real rate gates; this is just how often we re-evaluate "due".
pub const DEFAULT_TICK_INTERVAL_SECS: u64 = 15;

/// Default cap on concurrent engine dispatches the scheduler will launch in one tick. The engine
/// shares ONE warm browser, so we keep this tiny (serial by default).
pub const DEFAULT_MAX_CONCURRENT_DISPATCH: usize = 1;

/// How many due scheduled workflows one tick will dispatch at most (the rest roll to the next tick).
pub const DEFAULT_SCHEDULED_BATCH_LIMIT: i64 = 64;

/// Tunables for the scheduler loop. `Default` mirrors the `DEFAULT_*` consts.
#[derive(Debug, Clone)]
pub struct SchedulerConfig {
    /// Wall-clock cadence between ticks.
    pub tick_interval: std::time::Duration,
    /// Max concurrent engine dispatches launched from one tick's scheduled-workflow lane.
    pub max_concurrent_dispatch: usize,
    /// Max due scheduled workflows dispatched per tick.
    pub scheduled_batch_limit: i64,
    /// Data-retention window in days for the daily retention lane (DL-6). `0` disables retention
    /// (keep everything). Defaults to [`crate::local::config::DEFAULT_RETENTION_DAYS`]; the daemon
    /// should override it from the persisted `[app].retention_days` config so the user's setting wins.
    pub retention_days: u32,
}

impl Default for SchedulerConfig {
    fn default() -> Self {
        Self {
            tick_interval: std::time::Duration::from_secs(DEFAULT_TICK_INTERVAL_SECS),
            max_concurrent_dispatch: DEFAULT_MAX_CONCURRENT_DISPATCH,
            scheduled_batch_limit: DEFAULT_SCHEDULED_BATCH_LIMIT,
            retention_days: crate::local::config::DEFAULT_RETENTION_DAYS,
        }
    }
}

impl SchedulerConfig {
    /// Clamp any nonsensical values into a safe shape so a bad config can't wedge the loop:
    /// a non-zero cadence, at least one dispatch slot, at least one batched job.
    fn sanitized(mut self) -> Self {
        if self.tick_interval.is_zero() {
            self.tick_interval = std::time::Duration::from_secs(DEFAULT_TICK_INTERVAL_SECS);
        }
        self.max_concurrent_dispatch = self.max_concurrent_dispatch.max(1);
        self.scheduled_batch_limit = self.scheduled_batch_limit.max(1);
        self
    }
}

/// Owns the running scheduler task and its cancellation channel. Dropping it WITHOUT calling
/// [`shutdown`](Self::shutdown) detaches the task (it keeps running until the process exits); prefer
/// an explicit `shutdown().await` from the daemon's signal handler for a clean stop.
pub struct SchedulerHandle {
    cancel: watch::Sender<bool>,
    task: JoinHandle<()>,
}

impl SchedulerHandle {
    /// Signal the loop to stop and await its exit. Idempotent-ish: a second call (or one after the
    /// task already finished) is a no-op that returns immediately. NEVER panics on a poisoned/joined
    /// task — a panicked loop body is already caught inside the loop, so the join should be clean.
    pub async fn shutdown(self) {
        // Flip the cancel flag; ignore the error if all receivers are already gone (task ended).
        let _ = self.cancel.send(true);
        match self.task.await {
            Ok(()) => tracing::info!("scheduler stopped"),
            Err(e) if e.is_cancelled() => tracing::info!("scheduler task cancelled"),
            Err(e) => tracing::warn!(error = %e, "scheduler task join error on shutdown"),
        }
    }

    /// Has the loop task finished (e.g. cancelled)? Useful in tests / health checks.
    pub fn is_finished(&self) -> bool {
        self.task.is_finished()
    }
}

/// Spawn the scheduler loop and return a handle to stop it.
///
/// The loop wakes every `config.tick_interval`, runs one [`tick`](tick::run_tick), and continues
/// until [`SchedulerHandle::shutdown`] is called (or the process exits). The first tick fires after
/// the initial interval elapses (not immediately) so the daemon finishes booting before background
/// work starts; this also matches the cloud subsystem's "settle then poll" cadence.
pub fn spawn(
    db: SqlitePool,
    engine: Arc<dyn LocalEngine>,
    config: SchedulerConfig,
    health: SharedHealth,
) -> SchedulerHandle {
    let config = config.sanitized();
    let (cancel_tx, cancel_rx) = watch::channel(false);
    tracing::info!(
        tick_interval_ms = config.tick_interval.as_millis() as u64,
        max_concurrent_dispatch = config.max_concurrent_dispatch,
        scheduled_batch_limit = config.scheduled_batch_limit,
        "scheduler starting"
    );
    let task = tokio::spawn(loop_task::run(db, engine, config, health, cancel_rx));
    SchedulerHandle { cancel: cancel_tx, task }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::local::engine::{RunRequest, RunResult, RunStatus};
    use crate::local::error::LocalResult;
    use crate::local::{db, vault};
    use std::future::Future;
    use std::pin::Pin;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::Duration;

    async fn pool() -> SqlitePool {
        let dir = Box::leak(Box::new(tempfile::tempdir().unwrap()));
        let v = vault::Vault::load_or_create(dir.path(), false).unwrap();
        db::open(&dir.path().join("t.db"), &v.db_key_hex()).await.unwrap()
    }

    /// An inert engine that never gets driven in these tests (no due work is seeded), but records any
    /// calls so we can assert the loop touched nothing unexpected.
    #[derive(Default)]
    struct InertEngine {
        calls: AtomicUsize,
    }
    impl LocalEngine for InertEngine {
        fn run<'a>(
            &'a self,
            _req: RunRequest,
        ) -> Pin<Box<dyn Future<Output = LocalResult<RunResult>> + Send + 'a>> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            Box::pin(async {
                Ok(RunResult {
                    run_id: 0,
                    status: RunStatus::Success,
                    success: true,
                    error: None,
                    extracted_data: serde_json::json!({}),
                    duration_ms: 0,
                })
            })
        }
        fn active_runs(&self) -> usize {
            0
        }
    }

    /// `spawn` + `shutdown` cleanly stops the loop: the task finishes promptly after `shutdown()`.
    #[tokio::test]
    async fn shutdown_stops_the_loop() {
        let pool = pool().await;
        let engine: Arc<dyn LocalEngine> = Arc::new(InertEngine::default());

        // Fast cadence so a tick would fire if we waited, but we shut down before it matters.
        let handle = spawn(
            pool,
            engine,
            SchedulerConfig { tick_interval: Duration::from_millis(50), ..Default::default() },
            crate::local::app::health::DaemonHealth::shared(),
        );
        assert!(!handle.is_finished(), "loop should be running right after spawn");

        // Let it run a couple of ticks, then ask it to stop. `shutdown` joins the task; if the loop
        // didn't honor cancellation this await would hang and the test would time out.
        tokio::time::sleep(Duration::from_millis(160)).await;
        tokio::time::timeout(Duration::from_secs(5), handle.shutdown())
            .await
            .expect("shutdown joined the loop within 5s");
    }

    /// Cancelling a never-ticking loop (huge cadence) also stops promptly — proves shutdown doesn't
    /// depend on a tick firing first.
    #[tokio::test]
    async fn shutdown_is_immediate_even_without_a_tick() {
        let pool = pool().await;
        let engine: Arc<dyn LocalEngine> = Arc::new(InertEngine::default());
        let handle = spawn(
            pool,
            engine,
            SchedulerConfig { tick_interval: Duration::from_secs(3600), ..Default::default() },
            crate::local::app::health::DaemonHealth::shared(),
        );
        tokio::time::timeout(Duration::from_secs(5), handle.shutdown())
            .await
            .expect("shutdown returns without waiting for the (1h-away) first tick");
    }

    /// A zero/garbage config is sanitized into a safe shape rather than wedging the loop.
    #[test]
    fn config_sanitized_clamps_bad_values() {
        let c = SchedulerConfig {
            tick_interval: Duration::ZERO,
            max_concurrent_dispatch: 0,
            scheduled_batch_limit: -5,
            retention_days: crate::local::config::DEFAULT_RETENTION_DAYS,
        }
        .sanitized();
        assert!(!c.tick_interval.is_zero(), "zero cadence is replaced with the default");
        assert_eq!(c.max_concurrent_dispatch, 1, "at least one dispatch slot");
        assert_eq!(c.scheduled_batch_limit, 1, "at least one batched job");
    }
}
