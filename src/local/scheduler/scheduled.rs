//! The time-scheduled-workflow lane.
//!
//! Selects `workflows` rows whose fixed-interval schedule has come due, advances each one's schedule
//! BEFORE dispatch (so a slow/hung run can't leave the row perpetually due and double-fire next
//! tick — the same ordering Stage A uses for `targets.next_run_at`), and runs each through the shared
//! [`LocalEngine`] with [`RunSource::Scheduled`]. The engine persists the `runs` row itself
//! (`trigger_type='scheduled'`), so this lane records executions by *dispatching*, not by writing run
//! rows directly.
//!
//! ## Due selection (schema-grounded; no invented columns)
//! "Due" = `schedule_enabled=1 AND is_active=1 AND schedule_interval_ms IS NOT NULL AND
//! schedule_interval_ms > 0 AND (next_scheduled_at IS NULL OR next_scheduled_at <= now)`. This is
//! exactly the predicate of the partial index `ix_workflows_due_schedule` (plus the `now` gate and a
//! positive-interval guard). A NULL `next_scheduled_at` on an enabled schedule means "never scheduled
//! yet" → due immediately. There is NO cron column in the schema, so only fixed intervals are honored.
//!
//! ## Concurrency
//! Dispatches run concurrently up to `config.max_concurrent_dispatch` (default 1) via a semaphore,
//! because the engine shares ONE warm browser. With the default of 1 this is effectively serial.

use std::sync::Arc;

use chrono::{DateTime, Duration as ChronoDuration, Utc};
use sqlx::SqlitePool;

use super::recurrence::{self, Kind, Recurrence};
use super::SchedulerConfig;
use crate::local::engine::{Lane, LocalEngine, RunRequest, RunSource};
use crate::local::error::LocalResult;
use crate::local::store::workflows;

/// Result of one scheduled-workflow lane pass.
#[derive(Debug, Clone, Default)]
pub struct ScheduledReport {
    /// Workflows that were due and selected this tick.
    pub considered: usize,
    /// Workflows whose `engine.run` was launched (regardless of run outcome).
    pub dispatched: usize,
    /// Dispatches that failed (engine error or a non-success run result).
    pub failed: usize,
}

/// A due workflow's minimal scheduling fields (we don't need the whole heavy `Workflow` row to
/// dispatch — just the id + the recurrence to advance the schedule).
#[derive(Debug, Clone, sqlx::FromRow)]
struct DueScheduled {
    id: i64,
    schedule_interval_ms: i64,
    /// Structured recurrence columns (0013_schedule_recurrence.sql). `schedule_kind` defaults to
    /// `interval` for every pre-existing row, so those advance exactly as before.
    schedule_kind: Option<String>,
    schedule_time: Option<String>,
    schedule_days: Option<String>,
    schedule_tz: Option<String>,
}

/// Dispatch all DUE time-scheduled workflows as of `now`. Advances each row's `next_scheduled_at`
/// first, then runs it through the engine under a concurrency cap. Per-workflow failures are tallied,
/// never propagated — only a failure to SELECT the due set (or compute the schedule) returns `Err`.
pub async fn dispatch_due_scheduled(
    db: &SqlitePool,
    engine: &Arc<dyn LocalEngine>,
    now: DateTime<Utc>,
    config: &SchedulerConfig,
) -> LocalResult<ScheduledReport> {
    let now_str = rfc3339(now);
    let due = list_due(db, &now_str, config.scheduled_batch_limit).await?;
    let mut report = ScheduledReport { considered: due.len(), ..Default::default() };
    if due.is_empty() {
        return Ok(report);
    }

    let sem = Arc::new(tokio::sync::Semaphore::new(config.max_concurrent_dispatch));
    let mut tasks = Vec::with_capacity(due.len());

    for row in due {
        // Advance the schedule FIRST so a long/hung run can't leave this workflow perpetually due.
        // The next fire is computed by the shared `recurrence` helper so daily/weekly land on the
        // right wall-clock time; the `interval` kind (default, and every pre-existing row) is the
        // unchanged `now + interval` path with the workflow floor (60s) applied via the shared `clamp`
        // module — the SAME floor applied at SAVE time — so a zero/negative/too-small interval can't
        // pin it permanently due or run faster than the anti-detection cadence. Daily/weekly are ≥ 1/day
        // and so trivially clear the cadence floor — the clamp is intentionally interval-only.
        let next = rfc3339(next_run_for(&row, now));
        if let Err(e) = workflows::mark_scheduled(db, row.id, Some(&next)).await {
            tracing::warn!(workflow_id = row.id, error = %e, "failed to advance scheduled workflow; skipping this tick");
            continue;
        }

        let db = db.clone();
        let engine = engine.clone();
        let sem = sem.clone();
        tasks.push(tokio::spawn(async move {
            // Hold a permit for the whole dispatch — bounds concurrent engine runs (one warm browser).
            let _permit = match sem.acquire_owned().await {
                Ok(p) => p,
                Err(_) => return DispatchTally { dispatched: false, failed: true },
            };
            run_one(&db, &engine, row.id).await
        }));
    }

    for t in tasks {
        match t.await {
            Ok(tally) => {
                if tally.dispatched {
                    report.dispatched += 1;
                }
                if tally.failed {
                    report.failed += 1;
                }
            }
            Err(e) => {
                // A panicked/cancelled dispatch task — count it as a failure, keep going.
                tracing::warn!(error = %e, "scheduled-workflow dispatch task join error");
                report.failed += 1;
            }
        }
    }

    if report.dispatched > 0 || report.failed > 0 {
        tracing::info!(
            considered = report.considered,
            dispatched = report.dispatched,
            failed = report.failed,
            "scheduled-workflow lane complete"
        );
    }
    Ok(report)
}

/// Tiny per-dispatch tally returned from a spawned task.
struct DispatchTally {
    dispatched: bool,
    failed: bool,
}

/// Run one scheduled workflow through the engine. The engine inserts + finalizes the `runs` row
/// (`trigger_type='scheduled'`), so a successful launch IS the recorded execution. Any engine error
/// or non-success result is logged and counted as failed, but never propagated.
async fn run_one(db: &SqlitePool, engine: &Arc<dyn LocalEngine>, workflow_id: i64) -> DispatchTally {
    let req = RunRequest {
        workflow_id,
        inputs: serde_json::json!({}),
        source: RunSource::Scheduled,
        lane: Lane::Background,
        dry_run: false,
        persona_id: None,
        allow_local_secret_refs: true,
    };
    match engine.run(req).await {
        Ok(result) if result.success => {
            tracing::info!(workflow_id, run_id = result.run_id, "scheduled workflow ran");
            DispatchTally { dispatched: true, failed: false }
        }
        Ok(result) => {
            tracing::warn!(
                workflow_id,
                run_id = result.run_id,
                error = result.error.as_deref().unwrap_or("non-success run"),
                "scheduled workflow did not succeed"
            );
            DispatchTally { dispatched: true, failed: true }
        }
        Err(e) => {
            // The engine failed to even start/finish the run (e.g. workflow vanished). Don't let it
            // wedge the lane — record the failure against the workflow's rollup counters so the
            // failure is visible, then move on.
            tracing::warn!(workflow_id, error = %e, "scheduled workflow dispatch failed");
            let _ = workflows::record_run_outcome(db, workflow_id, false, Some(&e.to_string())).await;
            DispatchTally { dispatched: true, failed: true }
        }
    }
}

/// Select due time-scheduled workflows. Runtime-checked sqlx (no compile-time macro), mirroring the
/// `ix_workflows_due_schedule` partial index plus the `now`/positive-interval gates.
async fn list_due(pool: &SqlitePool, now_rfc3339: &str, limit: i64) -> LocalResult<Vec<DueScheduled>> {
    // Interval workflows require a positive `schedule_interval_ms` (the existing predicate); daily/weekly
    // have no interval to gate on, so those are due whenever `next_scheduled_at` has come due (or is
    // NULL). The recurrence advance re-derives the next fire regardless of interval.
    let rows = sqlx::query_as::<_, DueScheduled>(
        "SELECT id, schedule_interval_ms, schedule_kind, schedule_time, schedule_days, schedule_tz \
         FROM workflows \
         WHERE schedule_enabled = 1 AND is_active = 1 \
           AND ( (schedule_kind = 'interval' AND schedule_interval_ms IS NOT NULL AND schedule_interval_ms > 0) \
                 OR schedule_kind IN ('daily','weekly') ) \
           AND (next_scheduled_at IS NULL OR next_scheduled_at <= ?1) \
         ORDER BY next_scheduled_at ASC, id ASC \
         LIMIT ?2",
    )
    .bind(now_rfc3339)
    .bind(limit)
    .fetch_all(pool)
    .await?;
    Ok(rows)
}

/// Canonical RFC3339 (ms precision + `Z`) matching the schema's `strftime('%Y-%m-%dT%H:%M:%fZ')` so
/// string comparisons against `next_scheduled_at` are correctly ordered.
fn rfc3339(t: DateTime<Utc>) -> String {
    t.format("%Y-%m-%dT%H:%M:%S%.3fZ").to_string()
}

/// The next fire for a due scheduled workflow. The `interval` kind (default; every pre-existing row)
/// is the byte-identical `now + clamped_interval` path (60s workflow floor via the shared `clamp`).
/// `daily`/`weekly` land on their local wall-clock occurrence via the shared `recurrence` helper —
/// no clamp (they are ≥ 1/day and so trivially clear the anti-detection cadence).
fn next_run_for(row: &DueScheduled, now: DateTime<Utc>) -> DateTime<Utc> {
    let r = Recurrence::from_columns(
        row.schedule_kind.as_deref(),
        row.schedule_interval_ms,
        row.schedule_time.as_deref(),
        row.schedule_days.as_deref(),
        row.schedule_tz.as_deref(),
    );
    match r.kind {
        Kind::Interval => {
            let interval_ms = super::clamp::clamp_workflow_interval_ms(Some(row.schedule_interval_ms));
            now + ChronoDuration::milliseconds(interval_ms)
        }
        Kind::Daily | Kind::Weekly => recurrence::next_run(&r, now),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::local::engine::{LocalEngine, RunResult, RunStatus};
    use crate::local::store::workflows::{self, NewWorkflow, WorkflowUpdate};
    use crate::local::{db, vault};
    use std::future::Future;
    use std::pin::Pin;
    use std::sync::atomic::{AtomicUsize, Ordering};

    /// A fresh encrypted DB over a file-backed vault (no keyring prompt).
    async fn pool() -> SqlitePool {
        let dir = Box::leak(Box::new(tempfile::tempdir().unwrap()));
        let v = vault::Vault::load_or_create(dir.path(), false).unwrap();
        db::open(&dir.path().join("t.db"), &v.db_key_hex()).await.unwrap()
    }

    /// Counts dispatches and can be told to fail, without touching a browser.
    #[derive(Default)]
    struct CountingEngine {
        runs: AtomicUsize,
        fail: bool,
    }
    impl LocalEngine for CountingEngine {
        fn run<'a>(
            &'a self,
            req: RunRequest,
        ) -> Pin<Box<dyn Future<Output = LocalResult<RunResult>> + Send + 'a>> {
            let fail = self.fail;
            self.runs.fetch_add(1, Ordering::SeqCst);
            Box::pin(async move {
                Ok(RunResult {
                    run_id: req.workflow_id,
                    status: if fail { RunStatus::Failed } else { RunStatus::Success },
                    success: !fail,
                    error: if fail { Some("boom".into()) } else { None },
                    extracted_data: serde_json::json!({}),
                    duration_ms: 1,
                })
            })
        }
        fn active_runs(&self) -> usize {
            0
        }
    }

    fn cfg() -> SchedulerConfig {
        SchedulerConfig::default()
    }

    /// Enable a fixed-interval schedule on a workflow with the given `next_scheduled_at`.
    async fn enable_schedule(pool: &SqlitePool, id: i64, interval_ms: i64, next_at: Option<&str>) {
        workflows::update(
            pool,
            id,
            &WorkflowUpdate {
                schedule_enabled: Some(1),
                schedule_interval_ms: Some(interval_ms),
                ..Default::default()
            },
        )
        .await
        .unwrap();
        workflows::mark_scheduled(pool, id, next_at).await.unwrap();
    }

    /// A workflow with a NULL next_scheduled_at (never scheduled) is due; one in the future is not;
    /// a disabled-schedule one is not.
    #[tokio::test]
    async fn list_due_predicate() {
        let pool = pool().await;

        // Due: enabled schedule, next NULL.
        let due = workflows::insert(&pool, &NewWorkflow { name: "due".into(), ..Default::default() })
            .await
            .unwrap();
        enable_schedule(&pool, due.id, 60_000, None).await;

        // Not due: enabled schedule, next far in the future.
        let future = workflows::insert(&pool, &NewWorkflow { name: "future".into(), ..Default::default() })
            .await
            .unwrap();
        let far = rfc3339(Utc::now() + ChronoDuration::hours(1));
        enable_schedule(&pool, future.id, 60_000, Some(&far)).await;

        // Not due: schedule disabled (even though interval set + next NULL).
        let off = workflows::insert(&pool, &NewWorkflow { name: "off".into(), ..Default::default() })
            .await
            .unwrap();
        workflows::update(
            &pool,
            off.id,
            &WorkflowUpdate { schedule_interval_ms: Some(60_000), ..Default::default() },
        )
        .await
        .unwrap();

        // Not due: enabled but no interval.
        let no_interval =
            workflows::insert(&pool, &NewWorkflow { name: "nointerval".into(), ..Default::default() })
                .await
                .unwrap();
        workflows::update(
            &pool,
            no_interval.id,
            &WorkflowUpdate { schedule_enabled: Some(1), ..Default::default() },
        )
        .await
        .unwrap();

        let now_str = rfc3339(Utc::now());
        let ids: Vec<i64> = list_due(&pool, &now_str, 100).await.unwrap().into_iter().map(|r| r.id).collect();
        assert!(ids.contains(&due.id), "null next_scheduled_at on enabled schedule is due");
        assert!(!ids.contains(&future.id), "future next_scheduled_at is not due");
        assert!(!ids.contains(&off.id), "disabled schedule is not due");
        assert!(!ids.contains(&no_interval.id), "enabled schedule with no interval is not due");
    }

    /// Dispatching a due workflow runs it through the engine, advances its `next_scheduled_at` into
    /// the future, and removes it from the due set on the next pass.
    #[tokio::test]
    async fn dispatch_runs_and_advances_schedule() {
        let pool = pool().await;
        // Keep a typed handle to assert the engine was driven, and an erased clone to pass in.
        let counting = Arc::new(CountingEngine::default());
        let engine: Arc<dyn LocalEngine> = counting.clone();

        let wf = workflows::insert(&pool, &NewWorkflow { name: "sched".into(), ..Default::default() })
            .await
            .unwrap();
        enable_schedule(&pool, wf.id, 3_600_000, None).await; // 1h interval, due now

        let now = Utc::now();
        let rep = dispatch_due_scheduled(&pool, &engine, now, &cfg()).await.unwrap();
        assert_eq!(rep.considered, 1);
        assert_eq!(rep.dispatched, 1);
        assert_eq!(rep.failed, 0);

        // The engine was driven exactly once.
        assert_eq!(counting.runs.load(Ordering::SeqCst), 1);

        // next_scheduled_at advanced ~1h into the future → no longer due on the next pass.
        let after = workflows::get_by_id(&pool, wf.id).await.unwrap().unwrap();
        let next = after.next_scheduled_at.expect("next_scheduled_at set after dispatch");
        assert!(next > rfc3339(now), "schedule advanced past now: {next}");
        assert!(after.last_scheduled_at.is_some(), "last_scheduled_at stamped");

        let rep2 = dispatch_due_scheduled(&pool, &engine, now, &cfg()).await.unwrap();
        assert_eq!(rep2.considered, 0, "advanced schedule is no longer due");
    }

    /// A non-success run is tallied as failed but still counts as dispatched, and the lane keeps going.
    #[tokio::test]
    async fn failing_run_is_counted_failed() {
        let pool = pool().await;
        let engine: Arc<dyn LocalEngine> = Arc::new(CountingEngine { fail: true, ..Default::default() });

        let wf = workflows::insert(&pool, &NewWorkflow { name: "fails".into(), ..Default::default() })
            .await
            .unwrap();
        enable_schedule(&pool, wf.id, 60_000, None).await;

        let rep = dispatch_due_scheduled(&pool, &engine, Utc::now(), &cfg()).await.unwrap();
        assert_eq!(rep.dispatched, 1);
        assert_eq!(rep.failed, 1);
    }
}
