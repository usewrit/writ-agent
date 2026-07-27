//! The long-lived tick loop: cadence + cancellation + panic resilience + no-overlap.
//!
//! Split out from `mod.rs` so the orchestration (wake → guard → catch → log) is isolated from the
//! per-tick work (`tick::run_tick`). The loop owns nothing the rest of the daemon needs — it holds a
//! `SqlitePool` (cheap clone) and an `Arc<dyn LocalEngine>`.

use std::future::Future;
use std::panic::AssertUnwindSafe;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use futures_util::FutureExt;
use sqlx::SqlitePool;
use tokio::sync::watch;

use super::{tick, SchedulerConfig};
use crate::local::app::health::SharedHealth;
use crate::local::engine::LocalEngine;

/// Run the scheduler loop until `cancel` flips to `true`. Returns when cancelled (the spawned task
/// then ends). Each wake either runs one tick (guarded) or — if a prior tick is still in flight —
/// skips with a log line, so slow scheduled-workflow runs can't pile up. After each successful tick
/// the shared [`SharedHealth`] is updated so the heartbeat / `GET /v1/health` reflect liveness.
pub async fn run(
    db: SqlitePool,
    engine: Arc<dyn LocalEngine>,
    config: SchedulerConfig,
    health: SharedHealth,
    mut cancel: watch::Receiver<bool>,
) {
    let mut ticker = tokio::time::interval(config.tick_interval);
    // If a tick runs long, don't fire a burst of catch-up ticks afterward — just resume the cadence.
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    // The first `tick()` on a fresh interval resolves immediately; consume it so the FIRST real tick
    // happens one full interval after boot (let the daemon settle before background work starts).
    ticker.tick().await;

    // No-overlap guard: set while a tick body is running, so the next wake can skip instead of stack.
    let running = Arc::new(AtomicBool::new(false));

    loop {
        tokio::select! {
            // Cancellation wins over a due tick if both are ready.
            biased;

            res = cancel.changed() => {
                // `changed()` errs only if the sender dropped — treat that as "stop" too.
                if res.is_err() || *cancel.borrow() {
                    tracing::info!("scheduler loop received shutdown signal");
                    break;
                }
            }

            _ = ticker.tick() => {
                if running.swap(true, Ordering::SeqCst) {
                    // A previous tick's heavy work is still in flight — skip this cadence slot.
                    tracing::warn!("scheduler tick skipped: previous tick still running");
                    continue;
                }
                // PROD-14 backpressure: if the resource governor reports the daemon is over its soft
                // RSS watermark, SHED this tick's heavy background work (monitor checks + scheduled-
                // workflow dispatch both drive the engine → the warm browser). We still publish a
                // liveness heartbeat so health stays green, and resume automatically once memory falls
                // back under the watermark. Interactive (user/API) runs are unaffected — they bypass
                // the scheduler and are never shed by the governor.
                if should_shed_tick(&engine) {
                    tracing::warn!("scheduler tick shed: process RSS over the soft watermark (background work deferred)");
                    health.record_tick(0, false, &now_rfc3339());
                    running.store(false, Ordering::SeqCst);
                    continue;
                }
                let summary = guarded_tick(&db, &engine, &config).await;
                running.store(false, Ordering::SeqCst);
                if let Some(s) = summary {
                    // Publish liveness for the heartbeat / health endpoint. A tick that dispatched a
                    // scheduled workflow drove the engine → the warm browser; treat that as a
                    // best-effort "browser warmed" hint (API/monitor runs warm it independently).
                    let warmed = s.scheduled_dispatched > 0;
                    health.record_tick(s.monitors_considered as i64, warmed, &now_rfc3339());
                    tracing::debug!(
                        monitors_considered = s.monitors_considered,
                        monitors_changed = s.monitors_changed,
                        scheduled_dispatched = s.scheduled_dispatched,
                        scheduled_failed = s.scheduled_failed,
                        "scheduler tick done"
                    );
                }
            }
        }
    }
}

/// Run one tick body, catching BOTH a returned `Err` (logged) and a panic (caught + logged) so the
/// loop is fully isolated from a misbehaving tick. Returns the tick summary on success, `None` if the
/// tick errored or panicked.
async fn guarded_tick(
    db: &SqlitePool,
    engine: &Arc<dyn LocalEngine>,
    config: &SchedulerConfig,
) -> Option<tick::TickSummary> {
    let fut = tick::run_tick(db, engine, config);
    match catch(fut).await {
        Ok(Ok(summary)) => Some(summary),
        Ok(Err(e)) => {
            tracing::error!(error = %e, "scheduler tick returned an error (loop continues)");
            None
        }
        Err(_panic) => {
            tracing::error!("scheduler tick PANICKED (caught; loop continues)");
            None
        }
    }
}

/// Should this tick SHED its heavy background work? True when the engine exposes a resource governor
/// (PROD-14) and that governor reports the daemon is over its soft RSS watermark. An engine without a
/// governor (e.g. the test `StubEngine`) is never shed — the tick runs normally.
fn should_shed_tick(engine: &Arc<dyn LocalEngine>) -> bool {
    engine
        .governor()
        .map(|g| g.should_shed_background())
        .unwrap_or(false)
}

/// Canonical RFC3339 (ms precision + `Z`) for the health snapshot's `last_tick_at`, matching the
/// timestamp shape the stores write.
fn now_rfc3339() -> String {
    chrono::Utc::now().format("%Y-%m-%dT%H:%M:%S%.3fZ").to_string()
}

/// Catch a panic from an async tick body without aborting the loop task. `AssertUnwindSafe` is sound
/// here because a panic leaves the loop's own state untouched — the only shared state is the DB
/// (transactional) and the atomic guard (reset by the caller regardless of outcome).
async fn catch<F, T>(fut: F) -> Result<T, Box<dyn std::any::Any + Send>>
where
    F: Future<Output = T>,
{
    AssertUnwindSafe(fut).catch_unwind().await
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `catch` turns a panicking future into an `Err` instead of unwinding the loop task.
    #[tokio::test]
    async fn catch_isolates_a_panicking_tick() {
        let ok = catch(async { 41 + 1 }).await;
        assert_eq!(ok.ok(), Some(42));

        let boom = catch(async { panic!("tick exploded") as () }).await;
        assert!(boom.is_err(), "a panic must be caught, not propagated");
    }

    /// The no-overlap guard is an `AtomicBool::swap`: the first claimant gets `false` (proceeds), a
    /// second concurrent claimant gets `true` (skips). Releasing resets it. This mirrors exactly what
    /// the loop does around `guarded_tick`.
    #[test]
    fn overlap_guard_admits_one_and_skips_the_rest() {
        let running = AtomicBool::new(false);

        // First wake claims the slot.
        assert!(!running.swap(true, Ordering::SeqCst), "first claimant proceeds");
        // A second wake while the first is in flight is rejected.
        assert!(running.swap(true, Ordering::SeqCst), "overlapping claimant must skip");
        // Tick body finishes → release.
        running.store(false, Ordering::SeqCst);
        // Next wake can proceed again.
        assert!(!running.swap(true, Ordering::SeqCst), "after release the next tick proceeds");
    }

    /// `should_shed_tick` (PROD-14): an engine exposing a governor sheds the heavy tick when over the
    /// soft RSS watermark; an engine with NO governor never sheds.
    #[tokio::test]
    async fn shed_tick_gated_by_governor_watermark() {
        use crate::local::engine::{
            LocalEngine, RunRequest, RunResult, RunStatus,
        };
        use crate::local::error::LocalResult;
        use crate::local::governor::{GovernorConfig, ResourceGovernor};
        use std::future::Future;
        use std::pin::Pin;

        /// An engine that owns a governor (so we can drive its watermark) but never actually runs.
        struct GovEngine {
            gov: Arc<ResourceGovernor>,
        }
        impl LocalEngine for GovEngine {
            fn run<'a>(
                &'a self,
                _req: RunRequest,
            ) -> Pin<Box<dyn Future<Output = LocalResult<RunResult>> + Send + 'a>> {
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
            fn governor(&self) -> Option<Arc<ResourceGovernor>> {
                Some(self.gov.clone())
            }
        }

        // An engine with NO governor never sheds.
        struct NoGovEngine;
        impl LocalEngine for NoGovEngine {
            fn run<'a>(
                &'a self,
                _req: RunRequest,
            ) -> Pin<Box<dyn Future<Output = LocalResult<RunResult>> + Send + 'a>> {
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

        // 1 GiB watermark so the governor's test hook can straddle it.
        let gov = Arc::new(ResourceGovernor::new(GovernorConfig {
            max_concurrent_runs: 4,
            max_background_runs: 2,
            rss_soft_watermark_bytes: 1024 * 1024 * 1024,
        }));
        let engine: Arc<dyn LocalEngine> = Arc::new(GovEngine { gov: gov.clone() });

        // Under the watermark → no shed.
        gov.set_rss_for_test_pub(256 * 1024 * 1024);
        assert!(!should_shed_tick(&engine), "under watermark → tick runs");

        // Over the watermark → shed.
        gov.set_rss_for_test_pub(2 * 1024 * 1024 * 1024);
        assert!(should_shed_tick(&engine), "over watermark → tick shed");

        // A governorless engine is never shed.
        let plain: Arc<dyn LocalEngine> = Arc::new(NoGovEngine);
        assert!(!should_shed_tick(&plain), "no governor → never shed");
    }
}
