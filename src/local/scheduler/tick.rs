//! One scheduler tick: drive the two background lanes and report a tiny summary.
//!
//! Lane 1 — **monitors**: delegated wholesale to Stage A's [`crate::local::monitor::run_due_checks`],
//! which selects due targets, applies the 60s anti-detection floor, checks each under a timeout, and
//! dispatches `change_detected` automations. We do NOT touch check logic here.
//!
//! Lane 2 — **scheduled workflows**: due `workflows` rows (see [`super::scheduled`]) dispatched
//! through the engine with [`RunSource::Scheduled`], bounded by a small semaphore.
//!
//! Lane concurrency: the monitor lane and the scheduled-workflow/automation lanes run CONCURRENTLY
//! (via `tokio::join!`) so a slow scheduled run can't head-of-line-block DUE monitor checks — a
//! monitor with a 60s cadence must not be starved behind a multi-minute engine run. The lanes touch
//! disjoint scheduling state (monitors advance `targets.next_run_at`; scheduled advances
//! `workflows.next_scheduled_at`) and each is internally best-effort, so a failure in one is logged
//! and never aborts the other. Both drive the SAME warm-browser engine, but the engine's own resource
//! governor / run caps bound total concurrency — this join only removes the artificial serialization.
//!
//! Lane 4 — **retention**: a daily data-retention purge (DL-6), rate-limited to ~once/24h via a
//! process-global last-run marker so it runs on real ticks but not every tick.

use std::sync::atomic::{AtomicI64, Ordering};
use std::sync::Arc;

use chrono::Utc;
use sqlx::SqlitePool;

use super::{scheduled, scheduled_automations, SchedulerConfig};
use crate::local::engine::LocalEngine;
use crate::local::error::LocalResult;

/// Epoch-millis of the last retention purge (0 = never run this process). A process-global marker
/// (not a stored one) is enough: retention is idempotent and only reclaims OLD rows, so at worst a
/// daemon restart runs it once more than strictly needed.
static LAST_RETENTION_MS: AtomicI64 = AtomicI64::new(0);

/// Minimum gap between retention purges — once per day. The tick cadence is far shorter, so this
/// gate is what keeps retention a *daily* lane instead of running every tick.
const RETENTION_INTERVAL_MS: i64 = 24 * 60 * 60 * 1000;

/// Compact, log-friendly result of one tick (no per-item detail — that lives in the store rows and
/// in `monitor::TickReport` / `scheduled::ScheduledReport` if a caller wants the breakdown).
#[derive(Debug, Clone, Default)]
pub struct TickSummary {
    /// Monitors that were due and considered this tick (from `monitor::TickReport::considered`).
    pub monitors_considered: usize,
    /// Monitor checks that detected a change this tick.
    pub monitors_changed: usize,
    /// Scheduled workflows dispatched (engine.run launched) this tick.
    pub scheduled_dispatched: usize,
    /// Scheduled-workflow dispatches that failed (engine error or non-success run).
    pub scheduled_failed: usize,
    /// Scheduled-rooted automations dispatched this tick (cadence elapsed).
    pub scheduled_automations_dispatched: usize,
    /// Scheduled-automation dispatches that failed.
    pub scheduled_automations_failed: usize,
}

/// Run both lanes once. Returns `Err` ONLY for an unrecoverable infrastructure failure that the loop
/// should log (e.g. the monitor selection query itself failing); per-item failures are absorbed into
/// the summary so the loop keeps ticking.
pub async fn run_tick(
    db: &SqlitePool,
    engine: &Arc<dyn LocalEngine>,
    config: &SchedulerConfig,
) -> LocalResult<TickSummary> {
    let now = Utc::now();
    let mut summary = TickSummary::default();

    // Run the monitor lane CONCURRENTLY with the scheduled-workflow + scheduled-automation lanes so a
    // slow engine run in the scheduled lanes can't starve DUE monitor checks (CR-10). The two lanes
    // advance disjoint scheduling columns and each isolates its own per-item failures internally.
    let monitors = crate::local::monitor::run_due_checks(db, engine, now);
    let scheduled = run_scheduled_lanes(db, engine, now, config);
    let (mon_res, sched) = tokio::join!(monitors, scheduled);

    // --- Lane 1: monitors. A hard error (e.g. the due-select query failed) bubbles up so the loop
    // logs it; the lane already isolates per-target failures internally.
    let mon = mon_res?;
    summary.monitors_considered = mon.considered;
    summary.monitors_changed = mon.changed;

    // --- Lanes 2 & 3: scheduled workflows + scheduled automations (already isolated, see below). ---
    summary.scheduled_dispatched = sched.scheduled_dispatched;
    summary.scheduled_failed = sched.scheduled_failed;
    summary.scheduled_automations_dispatched = sched.scheduled_automations_dispatched;
    summary.scheduled_automations_failed = sched.scheduled_automations_failed;

    // --- Lane 4: daily retention purge (DL-6). Rate-limited + fully best-effort. ---
    maybe_run_retention(db, config, now).await;

    Ok(summary)
}

/// Partial summary for the scheduled workflow + automation lanes (Lanes 2 & 3), run as one future so
/// the whole group can be `join!`ed against the monitor lane.
#[derive(Default)]
struct ScheduledLanesSummary {
    scheduled_dispatched: usize,
    scheduled_failed: usize,
    scheduled_automations_dispatched: usize,
    scheduled_automations_failed: usize,
}

/// Drive the scheduled-workflow lane then the scheduled-automation lane. Each is isolated: a failure
/// to SELECT/load a lane's due set is logged and the OTHER lane still runs. Never returns `Err` — the
/// monitor lane owns the tick's fallible result.
async fn run_scheduled_lanes(
    db: &SqlitePool,
    engine: &Arc<dyn LocalEngine>,
    now: chrono::DateTime<Utc>,
    config: &SchedulerConfig,
) -> ScheduledLanesSummary {
    let mut out = ScheduledLanesSummary::default();

    // --- Lane 2: due time-scheduled workflows. Per-workflow dispatch failures are tallied inside the
    // lane; only a failure to SELECT the due set is logged here. `scheduled::dispatch_due_scheduled`
    // advances each row's schedule BEFORE dispatch, which is what prevents a double-launch.
    match scheduled::dispatch_due_scheduled(db, engine, now, config).await {
        Ok(rep) => {
            out.scheduled_dispatched = rep.dispatched;
            out.scheduled_failed = rep.failed;
        }
        Err(e) => {
            tracing::warn!(error = %e, "scheduled-workflow lane failed this tick (monitors unaffected)");
        }
    }

    // --- Lane 3: due `scheduled`-rooted automations. Isolated like Lane 2.
    match scheduled_automations::dispatch_due_scheduled_automations(db, engine, now, config).await {
        Ok(rep) => {
            out.scheduled_automations_dispatched = rep.dispatched;
            out.scheduled_automations_failed = rep.failed;
        }
        Err(e) => {
            tracing::warn!(error = %e, "scheduled-automation lane failed this tick (other lanes unaffected)");
        }
    }

    out
}

/// Run the retention purge if at least [`RETENTION_INTERVAL_MS`] has elapsed since the last one this
/// process. Best-effort: a purge error is logged, never propagated (a bad purge must not wedge the
/// loop). A no-op when `config.retention_days == 0` (retention disabled) — but the marker is still
/// advanced so a disabled config doesn't re-check every tick.
async fn maybe_run_retention(db: &SqlitePool, config: &SchedulerConfig, now: chrono::DateTime<Utc>) {
    let now_ms = now.timestamp_millis();
    if !retention_due(LAST_RETENTION_MS.load(Ordering::Relaxed), now_ms) {
        return;
    }
    // Claim this slot before doing the work so two overlapping ticks can't both purge.
    LAST_RETENTION_MS.store(now_ms, Ordering::Relaxed);

    if config.retention_days == 0 {
        return; // retention disabled — keep everything
    }
    match crate::local::retention::purge_from_scheduler(db, config.retention_days).await {
        Ok(report) => {
            if report.cutoff.is_some() {
                tracing::info!(retention_days = config.retention_days, "retention lane ran");
            }
        }
        Err(e) => {
            tracing::warn!(error = %e, "retention lane failed this tick (loop continues)");
        }
    }
}

/// Whether the retention lane should run: never run before (`last == 0`), or at least
/// [`RETENTION_INTERVAL_MS`] since the last run. Pure so the daily-cadence gate is unit-testable.
fn retention_due(last_ms: i64, now_ms: i64) -> bool {
    last_ms == 0 || now_ms - last_ms >= RETENTION_INTERVAL_MS
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The retention gate fires on the first-ever check, then not again until a full day has elapsed.
    #[test]
    fn retention_daily_cadence() {
        let base = 1_000_000_000_000; // arbitrary epoch-ms
        assert!(retention_due(0, base), "never-run must fire");
        assert!(!retention_due(base, base + 1000), "1s later must NOT re-run");
        assert!(
            !retention_due(base, base + RETENTION_INTERVAL_MS - 1),
            "just under a day must NOT re-run"
        );
        assert!(
            retention_due(base, base + RETENTION_INTERVAL_MS),
            "a full day later must re-run"
        );
    }

    /// `maybe_run_retention` invokes the purge when the daily gate is open, and a second call within
    /// the window is a no-op. Both phases are written to tolerate a concurrent scheduler-loop test
    /// claiming the process-global gate — see the comments inline.
    #[tokio::test]
    async fn retention_lane_invoked_then_rate_limited() {
        use crate::local::store::runs::{self, NewRun};
        use crate::local::{config::Paths, db, vault::Vault};

        // Isolate this test's home so `purge_from_scheduler` (which resolves `$WRIT_HOME`) targets our
        // temp DB, and reset the process-global marker so ordering with other tests doesn't matter.
        // Hold the crate-wide env guard for the whole body — `WRIT_HOME` is process-global.
        let _g = crate::local::config::test_env_guard();
        let dir = Box::leak(Box::new(tempfile::tempdir().unwrap()));
        std::env::set_var("WRIT_HOME", dir.path());
        LAST_RETENTION_MS.store(0, Ordering::Relaxed);

        let paths = Paths::resolve().unwrap();
        paths.ensure_dirs().unwrap();
        let vault = Vault::load_or_create(&paths.root, false).unwrap();
        let pool = db::open(&paths.db(), &vault.db_key_hex()).await.unwrap();

        // An old run that a 30-day retention window should purge.
        let old = runs::insert(&pool, &NewRun::default()).await.unwrap();
        sqlx::query("UPDATE runs SET created_at = '2000-01-01T00:00:00.000Z' WHERE id = ?1")
            .bind(old.id)
            .execute(&pool)
            .await
            .unwrap();

        let config = SchedulerConfig { retention_days: 30, ..Default::default() };
        let now = Utc::now();

        // First call: gate fires → the old run is purged and the marker is claimed.
        //
        // `LAST_RETENTION_MS` is PROCESS-GLOBAL and `test_env_guard` only serializes `WRIT_HOME`, so
        // a scheduler-loop test running on another test thread (`scheduler::tests`
        // `shutdown_stops_the_loop` spins a 50ms cadence for ~160ms) can claim the very slot we just
        // reset — in which case our call correctly returns early and nothing is purged, through no
        // fault of the code under test. Re-arm and retry until we win the slot; the purge is
        // idempotent, so retrying cannot mask a real failure (only a lane that NEVER purges fails).
        let mut purged = false;
        for _ in 0..50 {
            LAST_RETENTION_MS.store(0, Ordering::Relaxed);
            maybe_run_retention(&pool, &config, now).await;
            if runs::get_by_id(&pool, old.id).await.unwrap().is_none() {
                purged = true;
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
        assert!(purged, "old run purged by the lane");
        assert_ne!(
            LAST_RETENTION_MS.load(Ordering::Relaxed),
            0,
            "retention marker claimed after the lane ran"
        );

        // Second call a minute later: within the daily window → no-op.
        //
        // Asserted BEHAVIORALLY (the row survives) rather than by comparing the marker: any recent
        // marker value closes the gate, so this holds whether the slot is ours or a concurrent
        // scheduler tick's, whereas an exact marker comparison would be racy for the same reason.
        let old2 = runs::insert(&pool, &NewRun::default()).await.unwrap();
        sqlx::query("UPDATE runs SET created_at = '2000-01-01T00:00:00.000Z' WHERE id = ?1")
            .bind(old2.id)
            .execute(&pool)
            .await
            .unwrap();
        maybe_run_retention(&pool, &config, now + chrono::Duration::minutes(1)).await;
        assert!(
            runs::get_by_id(&pool, old2.id).await.unwrap().is_some(),
            "within-day re-call must NOT purge again"
        );

        std::env::remove_var("WRIT_HOME");
    }
}
