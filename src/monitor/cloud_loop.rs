//! Cloud recorder-agent monitoring loop.
//!
//! The autonomous tick loop driven by the ws-gateway coordinator: the recorder advertises its
//! [`capacity`](super::capacity) on connect; the backend pushes `assign_targets` / `target_sync` /
//! `assign_workflows` frames over the ws-gateway; this loop decides when a slot is due, runs its
//! targets in parallel, and reports `target_check_batch` frames back up.
//!
//! It depends only on `bridge::session_relay` (the ungated `BridgeOutgoing`) + the SHARED
//! `bridge::wire_exec` execute path + the neutral scheduling primitives (`capacity`/`checker`/
//! `grouping`/…) — so it compiles for BOTH the managed cloud recorder (`cloud`) and the OSS fleet
//! worker (`fleet,local`), which is a shared monitoring-fleet node that runs coordinator-assigned
//! checks. The per-run credential channel key is threaded in by the caller (cloud loads it from the
//! agent creds; fleet from its per-agent channel key).

use std::sync::Arc;

use chrono::Utc;
use tokio::sync::mpsc::UnboundedSender;
use tokio::sync::{Mutex, Semaphore};

use crate::browser::manager::BrowserManager;
use crate::bridge::session_relay::BridgeOutgoing;
use super::capacity::CapacityReport;
use super::checker::Checker;
use super::grouping::{group_targets, PeriodGroup};
use super::incremental::{IncrementalUpdate, IncrementalUpdateManager};
use super::models::{ReportItem, Target};
use super::scheduler::now_ms;
use super::workflow_scheduler::WorkflowScheduler;

/// Coordinator anti-detection hint for one period.
#[derive(Debug, Clone, Default)]
struct AntiDetection {
    skip_next_check: bool,
    next_check_jitter_ms: i64,
}

/// The assignment + scheduling state the monitor loop operates on.
struct Assignment {
    targets: Vec<Target>,
    groups: Vec<PeriodGroup>,
    global_period_ms: i64,
    sync_epoch_ms: Option<i64>,
    time_slot_offsets: serde_json::Value,
}

impl Default for Assignment {
    fn default() -> Self {
        Self {
            targets: Vec::new(),
            groups: Vec::new(),
            global_period_ms: 60_000,
            sync_epoch_ms: None,
            time_slot_offsets: serde_json::Value::Null,
        }
    }
}

/// Shared monitoring state. All mutation goes through the single `Mutex`; the
/// loop only holds it briefly (never across an `.await` that does I/O — checks
/// run after the lock is dropped), matching the recorder's concurrency rules.
pub struct MonitorState {
    inner: Mutex<Assignment>,
    anti_detection: Mutex<std::collections::HashMap<i64, AntiDetection>>,
    incremental: Mutex<IncrementalUpdateManager>,
    workflows: Mutex<WorkflowScheduler>,
    checker: Checker,
    pub capacity: CapacityReport,
    parallel_workers: usize,
    /// ONE process-wide permit pool for HTTP-path checks, shared across every concurrently-running
    /// batch. A per-batch semaphore multiplied real concurrency by the number of due batches (each
    /// batch got its own `parallel_workers` permits), which could stampede the host; a single shared
    /// pool caps total in-flight HTTP checks at `parallel_workers` regardless of batch count.
    http_sem: Arc<Semaphore>,
    /// A small SEPARATE pool for browser-path checks (JS/auth/visual). Each launches a headless
    /// context — far heavier than an HTTP fetch — so it must not draw from (or saturate) the HTTP pool.
    browser_sem: Arc<Semaphore>,
    /// Wakes the loop immediately when assignments change so a freshly-assigned
    /// fast target fires on its very next boundary instead of after a full sleep.
    changed: tokio::sync::Notify,
    /// On-demand "check now" queue — target ids the coordinator asked us to check
    /// immediately (via a `check_target_now` frame), OUT of the normal schedule.
    /// Drained each loop wake; each id runs a one-off `run_batch` and reports
    /// through the same `target_check_batch` path (so it's metered identically).
    pending_now: Mutex<Vec<i64>>,
    /// When each currently-`running` scheduled workflow was launched.
    ///
    /// `WorkflowScheduler` tracks only the running SET, and its `mark_completed` is both the
    /// "finished" signal and what RE-ARMS the schedule — so a workflow that never gets marked
    /// completed is silently disabled forever (`due()` filters the running set), and `MonitorState`
    /// outlives every reconnect, so nothing clears it. This map is what lets the loop REAP such a
    /// slot. Three independent guards now cover it: an RAII drop guard (panic/abort), a timeout
    /// (a hung run), and this reaper (anything that skipped both, e.g. runtime teardown).
    running_since: Mutex<std::collections::HashMap<i64, std::time::Instant>>,
}

/// Hard ceiling on one scheduled-workflow execution. `run_scheduled_workflow` drives a real browser
/// through an arbitrary recipe with no internal deadline; without this a single hung navigation
/// parks the workflow in the running set forever and it never fires again.
const WORKFLOW_RUN_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(15 * 60);
/// Age at which a still-`running` slot is force-completed by the reaper. Comfortably beyond
/// `WORKFLOW_RUN_TIMEOUT` so it only ever fires for slots whose owner disappeared without running
/// its guard (never for a legitimately slow run).
const STALE_RUNNING_AGE: std::time::Duration = std::time::Duration::from_secs(20 * 60);

impl MonitorState {
    pub fn new(capacity: CapacityReport) -> Self {
        let parallel_workers = capacity.parallel_workers.max(1);
        // Browser checks are memory-heavy (a headless context each); cap them well below the HTTP
        // fan-out so a burst of auth/visual targets can't OOM the host. A quarter of the HTTP width,
        // floored at 1 and capped at 4, matches the single-warm-browser realities of the recorder.
        let browser_workers = (parallel_workers / 4).clamp(1, 4);
        Self {
            inner: Mutex::new(Assignment::default()),
            anti_detection: Mutex::new(std::collections::HashMap::new()),
            incremental: Mutex::new(IncrementalUpdateManager::new()),
            workflows: Mutex::new(WorkflowScheduler::new()),
            checker: Checker::new(None),
            capacity,
            parallel_workers,
            http_sem: Arc::new(Semaphore::new(parallel_workers)),
            browser_sem: Arc::new(Semaphore::new(browser_workers)),
            changed: tokio::sync::Notify::new(),
            pending_now: Mutex::new(Vec::new()),
            running_since: Mutex::new(std::collections::HashMap::new()),
        }
    }

    /// Mark a scheduled workflow as running (and remember WHEN, for the reaper).
    async fn begin_workflow(&self, wf_id: i64) -> Option<serde_json::Value> {
        let data = {
            let mut ws = self.workflows.lock().await;
            ws.mark_running(wf_id);
            ws.workflow_data(wf_id)
        };
        self.running_since.lock().await.insert(wf_id, std::time::Instant::now());
        data
    }

    /// Mark a scheduled workflow finished — which is ALSO what re-arms its next run.
    async fn finish_workflow(&self, wf_id: i64) {
        self.workflows.lock().await.mark_completed(wf_id);
        self.running_since.lock().await.remove(&wf_id);
    }

    /// Force-complete scheduled workflows that have been "running" implausibly long.
    ///
    /// The safety net for the one case neither the drop guard nor the timeout can cover: a task that
    /// disappeared without its `Drop` ever running. Leaving the slot set would permanently disable
    /// the workflow, so a stale slot is released (and loudly logged) rather than trusted.
    async fn reap_stale_running(&self) {
        let stale: Vec<i64> = {
            let map = self.running_since.lock().await;
            map.iter()
                .filter(|(_, since)| since.elapsed() > STALE_RUNNING_AGE)
                .map(|(id, _)| *id)
                .collect()
        };
        for wf_id in stale {
            tracing::error!(
                workflow_id = wf_id,
                age_s = STALE_RUNNING_AGE.as_secs(),
                "scheduled workflow has been 'running' far too long — force-completing it so its \
                 schedule re-arms (its executor is gone)"
            );
            self.finish_workflow(wf_id).await;
        }
    }

    /// Queue an on-demand check of one target (from a `check_target_now` frame) and
    /// wake the loop so it runs immediately, regardless of the target's schedule.
    /// A no-op if the target isn't in our current assignment (it belongs to another
    /// recorder, or was just unassigned).
    pub async fn check_target_now(&self, target_id: i64) {
        {
            let has = self.inner.lock().await.targets.iter().any(|t| t.id == Some(target_id));
            if !has {
                tracing::debug!(target_id, "check_target_now: target not assigned here, ignoring");
                return;
            }
        }
        {
            let mut q = self.pending_now.lock().await;
            if !q.contains(&target_id) {
                q.push(target_id);
            }
        }
        tracing::info!(target_id, "check_target_now queued");
        self.changed.notify_one();
    }

    /// Drain the on-demand queue into a batch of the matching assigned targets.
    async fn collect_pending_now(&self) -> Vec<Target> {
        let ids: Vec<i64> = { std::mem::take(&mut *self.pending_now.lock().await) };
        if ids.is_empty() {
            return Vec::new();
        }
        let a = self.inner.lock().await;
        a.targets.iter().filter(|t| t.id.is_some_and(|tid| ids.contains(&tid))).cloned().collect()
    }

    /// Milliseconds until the earliest slot/workflow is due (capped by the caller).
    /// `i64::MAX` when nothing is scheduled.
    async fn next_due_in_ms(&self) -> i64 {
        let mut min = i64::MAX;
        {
            let a = self.inner.lock().await;
            for group in &a.groups {
                for slot in &group.slots {
                    min = min.min(slot.scheduler.time_until_next_run_ms());
                }
            }
        }
        {
            let ws = self.workflows.lock().await;
            min = min.min(ws.next_due_in_ms());
        }
        min
    }

    /// Handle an `assign_targets` frame: replace the target set + scheduling and
    /// rebuild the slot groups.
    pub async fn assign_targets(&self, msg: &serde_json::Value) {
        let targets: Vec<Target> = msg
            .get("targets")
            .and_then(|v| serde_json::from_value(v.clone()).ok())
            .unwrap_or_default();
        let global_period_ms =
            msg.get("global_period_ms").and_then(|v| v.as_i64()).unwrap_or(60_000);
        let sync_epoch_ms = msg.get("sync_epoch_ms").and_then(|v| v.as_i64());
        let time_slot_offsets =
            msg.get("time_slot_offsets").cloned().unwrap_or(serde_json::Value::Null);

        let groups = group_targets(&targets, global_period_ms, sync_epoch_ms, &time_slot_offsets);
        let mut a = self.inner.lock().await;
        a.targets = targets;
        a.global_period_ms = global_period_ms;
        a.sync_epoch_ms = sync_epoch_ms;
        a.time_slot_offsets = time_slot_offsets;
        a.groups = groups;
        tracing::info!(targets = a.targets.len(), "assign_targets applied");
        drop(a);
        self.changed.notify_one();
    }

    /// Handle a `target_sync` frame: anti-detection hints + incremental updates.
    pub async fn apply_sync(&self, msg: &serde_json::Value) {
        if let Some(ad) = msg.get("anti_detection").and_then(|v| v.as_object()) {
            let mut map = self.anti_detection.lock().await;
            for (period_str, v) in ad {
                if let Ok(period) = period_str.parse::<i64>() {
                    map.insert(
                        period,
                        AntiDetection {
                            skip_next_check: v
                                .get("skip_next_check")
                                .and_then(|x| x.as_bool())
                                .unwrap_or(false),
                            next_check_jitter_ms: v
                                .get("next_check_jitter_ms")
                                .and_then(|x| x.as_i64())
                                .unwrap_or(0),
                        },
                    );
                }
            }
        }

        if let Some(upd) = msg.get("incremental_target_update") {
            if let Some(update) = IncrementalUpdate::from_json(upd) {
                self.incremental.lock().await.queue(update);
            }
        }
        self.changed.notify_one();
    }

    /// Handle an `assign_workflows` frame.
    pub async fn assign_workflows(&self, msg: &serde_json::Value) {
        let workflows: Vec<serde_json::Value> = msg
            .get("scheduled_workflows")
            .and_then(|v| v.as_array())
            .cloned()
            .unwrap_or_default();
        let sync_epoch_ms = msg.get("sync_epoch_ms").and_then(|v| v.as_i64()).unwrap_or(0);
        self.workflows.lock().await.update_workflows(&workflows, sync_epoch_ms);
        self.changed.notify_one();
    }

    /// Drain incremental updates between cycles; regroup if the target set moved.
    async fn apply_pending_incremental(&self) {
        let has_pending = { self.incremental.lock().await.has_pending() };
        if !has_pending {
            return;
        }
        let mut a = self.inner.lock().await;
        let mut targets = std::mem::take(&mut a.targets);
        let result = self.incremental.lock().await.apply(&mut targets);
        a.targets = targets;
        if result.needs_regroup {
            a.groups = group_targets(
                &a.targets,
                a.global_period_ms,
                a.sync_epoch_ms,
                &a.time_slot_offsets,
            );
            tracing::info!(
                changes = result.changes_applied,
                full_rebuild = result.full_rebuild,
                targets = a.targets.len(),
                "incremental update applied; regrouped"
            );
        }
    }

    /// One scheduler tick: collect due slots, mark them completed (brief lock),
    /// then run their checks in parallel and report. Returns due workflow ids to
    /// run (executed by the caller, which owns the browser/bridge handles).
    async fn collect_due(&self) -> (Vec<Vec<Target>>, Vec<i64>) {
        // Snapshot anti-detection for this tick.
        let ad_map = { self.anti_detection.lock().await.clone() };

        let mut due_batches: Vec<Vec<Target>> = Vec::new();
        // Periods that actually had a due slot this tick — only these consume their one-shot
        // `skip_next_check`. Resetting it for EVERY period on every idle tick (the old behavior) threw
        // the flag away before its period was ever due, so a coordinator "skip this cycle" hint was
        // silently lost and the target got checked anyway.
        let mut consumed_skip_periods: Vec<i64> = Vec::new();
        {
            let mut a = self.inner.lock().await;
            for group in a.groups.iter_mut() {
                let ad = ad_map.get(&group.period_ms).cloned().unwrap_or_default();
                let jitter = ad.next_check_jitter_ms;
                for slot in group.slots.iter_mut() {
                    if !slot.scheduler.should_run() {
                        continue;
                    }
                    // Advance the schedule now (brief lock, no await held) so a
                    // long-running check can't double-fire the slot.
                    slot.scheduler.mark_completed(jitter);
                    if ad.skip_next_check {
                        // This period's one-shot skip fired for a genuinely-due slot — consume it.
                        consumed_skip_periods.push(group.period_ms);
                        continue; // coordinator told us to skip this cycle
                    }
                    due_batches.push(slot.targets.clone());
                }
            }
        }

        // Consume one-shot skip flags ONLY for periods whose slot was due this tick.
        if !consumed_skip_periods.is_empty() {
            let mut map = self.anti_detection.lock().await;
            for period in consumed_skip_periods {
                if let Some(ad) = map.get_mut(&period) {
                    ad.skip_next_check = false;
                }
            }
        }

        let due_workflows = { self.workflows.lock().await.due() };
        (due_batches, due_workflows)
    }

    /// Run a single slot batch in parallel and emit a `target_check_batch`
    /// frame plus any `precheck_complete` frames.
    async fn run_batch(
        self: &Arc<Self>,
        targets: Vec<Target>,
        browser: &Arc<BrowserManager>,
        outgoing: &UnboundedSender<BridgeOutgoing>,
        agent_id: &str,
    ) {
        let mut handles = Vec::with_capacity(targets.len());
        for target in targets {
            // Route each target to the pool matching its cost: heavy browser-path checks (JS/auth/
            // visual) draw from the small `browser_sem`, everything else from the shared `http_sem`.
            // Both are process-wide, so total in-flight work is bounded across ALL concurrent batches.
            let sem = if target.needs_browser() {
                self.browser_sem.clone()
            } else {
                self.http_sem.clone()
            };
            let state = self.clone();
            let browser = browser.clone();
            let outgoing = outgoing.clone();
            let agent_id = agent_id.to_string();
            handles.push(tokio::spawn(async move {
                let _permit = sem.acquire_owned().await;
                let outcome = state.checker.check_target(&target, &browser).await;
                // Persist refreshed auth from a browser/pre-check run.
                if let Some(auth) = outcome.auth_session {
                    let _ = outgoing.send(BridgeOutgoing::Json(serde_json::json!({
                        "type": "precheck_complete",
                        "agent_id": agent_id,
                        "target_id": target.id,
                        "auth_session": auth,
                    })));
                }
                outcome.reports
            }));
        }

        let mut reports: Vec<ReportItem> = Vec::new();
        for h in handles {
            if let Ok(mut r) = h.await {
                reports.append(&mut r);
            }
        }
        if reports.is_empty() {
            return;
        }
        let frame = serde_json::json!({
            "type": "target_check_batch",
            "agent_id": agent_id,
            "timestamp": Utc::now().to_rfc3339(),
            "reports": reports,
        });
        let _ = outgoing.send(BridgeOutgoing::Json(frame));
    }
}

/// The autonomous monitoring loop. Spawned once per gateway connection alongside
/// the heartbeat. Ticks ~4×/s; cheap when there are no targets.
pub async fn run_monitor_loop(
    state: Arc<MonitorState>,
    browser: Arc<BrowserManager>,
    outgoing: UnboundedSender<BridgeOutgoing>,
    agent_id: Arc<tokio::sync::RwLock<Option<String>>>,
    running: Arc<std::sync::atomic::AtomicBool>,
    // Per-agent credential channel key used to open a scheduled workflow's `credentials_encrypted`
    // (captured once per connection; the key is stable per agent and refreshed on reconnect). `None`
    // → scheduled workflows run without decrypting sealed credentials (a plain check still works).
    channel_key: Option<String>,
) {
    tracing::info!(
        parallel_workers = state.parallel_workers,
        "monitor loop started"
    );
    // Re-evaluation cap: bounds idle wake-ups to ~1/s. The precise next-due time
    // drives the sleep, so as a boundary approaches the sleep shrinks below the
    // cap and we wake exactly on it — a 1s target fires every 1s, not every cap.
    const MAX_SLEEP_MS: i64 = 1_000;
    const MIN_SLEEP_MS: i64 = 5;
    // Last stale-`running` sweep (the loop ticks ~1/s; the sweep runs ~1/min).
    let mut last_reap = std::time::Instant::now();
    while running.load(std::sync::atomic::Ordering::Relaxed) {
        // Sleep until the next slot is due (or an assignment change wakes us).
        let due_in = state.next_due_in_ms().await;
        let sleep_ms = due_in.clamp(MIN_SLEEP_MS, MAX_SLEEP_MS) as u64;
        tokio::select! {
            _ = tokio::time::sleep(std::time::Duration::from_millis(sleep_ms)) => {}
            _ = state.changed.notified() => {}
        }

        // Apply queued incremental updates between cycles (Python: between checks).
        state.apply_pending_incremental().await;

        // Release scheduled workflows whose executor vanished without completing them (see
        // `reap_stale_running`) — checked at most once a minute, it walks a handful of entries.
        if last_reap.elapsed() >= std::time::Duration::from_secs(60) {
            last_reap = std::time::Instant::now();
            state.reap_stale_running().await;
        }

        let (mut due_batches, due_workflows) = state.collect_due().await;
        // On-demand "check now" targets run as their own one-off batch this wake.
        let pending_now = state.collect_pending_now().await;
        if !pending_now.is_empty() {
            due_batches.push(pending_now);
        }
        if due_batches.is_empty() && due_workflows.is_empty() {
            continue;
        }

        let aid = { agent_id.read().await.clone().unwrap_or_default() };

        for batch in due_batches {
            let state = state.clone();
            let browser = browser.clone();
            let outgoing = outgoing.clone();
            let aid = aid.clone();
            tokio::spawn(async move {
                state.run_batch(batch, &browser, &outgoing, &aid).await;
            });
        }

        // Scheduled workflows reuse the full execute_workflow path.
        for wf_id in due_workflows {
            let Some(data) = state.begin_workflow(wf_id).await else { continue };
            let state = state.clone();
            let browser = browser.clone();
            let outgoing = outgoing.clone();
            let channel_key = channel_key.clone();
            tokio::spawn(async move {
                // RAII: `mark_completed` is both "finished" and "re-arm the schedule", so it MUST
                // run on every exit path. As a bare statement after the await it was skipped by a
                // panic inside the run (and by any future cancellation), which left the workflow in
                // the running set forever — permanently disabled, since `MonitorState` survives
                // reconnects and nothing else clears it.
                let _guard = RunningGuard { state: state.clone(), wf_id };
                // …and a deadline, so a hung browser cannot hold the slot for the process lifetime.
                let run = run_scheduled_workflow(
                    wf_id,
                    &data,
                    &browser,
                    &outgoing,
                    channel_key.as_deref(),
                );
                if tokio::time::timeout(WORKFLOW_RUN_TIMEOUT, run).await.is_err() {
                    tracing::error!(
                        workflow_id = wf_id,
                        timeout_s = WORKFLOW_RUN_TIMEOUT.as_secs(),
                        "scheduled workflow timed out — abandoning the run and re-arming its schedule"
                    );
                    // The coordinator awaits a completion for this run; tell it, or it waits forever.
                    let _ = outgoing.send(BridgeOutgoing::Json(serde_json::json!({
                        "type": "scheduled_workflow_complete",
                        "workflow_id": wf_id,
                        "success": false,
                        "result_data": serde_json::Value::Null,
                        "error": format!("timed out after {}s on the agent", WORKFLOW_RUN_TIMEOUT.as_secs()),
                    })));
                }
            });
        }
    }
    tracing::info!("monitor loop stopped");
}

/// Drop guard that releases a scheduled workflow's `running` slot no matter how its task ends
/// (normal return, panic unwind, or the task being dropped mid-await).
///
/// `finish_workflow` is async (the scheduler lives behind a `tokio::Mutex`), so the guard hands the
/// completion to a detached task. `Handle::try_current` keeps that safe when the drop happens during
/// runtime teardown, where `tokio::spawn` would panic — in that case the process is going away and
/// the in-memory running set dies with it anyway.
struct RunningGuard {
    state: Arc<MonitorState>,
    wf_id: i64,
}

impl Drop for RunningGuard {
    fn drop(&mut self) {
        let state = self.state.clone();
        let wf_id = self.wf_id;
        if let Ok(handle) = tokio::runtime::Handle::try_current() {
            handle.spawn(async move {
                state.finish_workflow(wf_id).await;
            });
        }
    }
}

/// Build an `execute_workflow`-shaped message from a scheduled workflow and run
/// it through the existing bridge handler (which emits a
/// `scheduled_workflow_complete` frame because of the `_scheduled` tag).
async fn run_scheduled_workflow(
    workflow_id: i64,
    data: &serde_json::Value,
    browser: &Arc<BrowserManager>,
    outgoing: &UnboundedSender<BridgeOutgoing>,
    channel_key: Option<&str>,
) {
    let task_id = format!("sched-{workflow_id}-{}", now_ms());
    // The workflow's executable config is either under `config` or the object itself.
    let config = data.get("config").cloned().unwrap_or_else(|| data.clone());
    let msg = serde_json::json!({
        "type": "execute_workflow",
        "task_id": task_id,
        "config": config,
        "workflow_id": workflow_id,
        "_scheduled": true,
    });
    // Run through the SHARED wire executor (the exact path the cloud `saas_bridge` shim called — it
    // only added the credential-channel-key load, now threaded in). Scheduled monitoring workflows
    // have no backend artifact-callback context (a non-numeric task id, no per-task agent auth), so
    // download capture is unavailable here and a wait_for_download step fails closed (File assets §6.3).
    let out = outgoing.clone();
    let send = move |v: serde_json::Value| {
        let _ = out.send(BridgeOutgoing::Json(v));
    };
    crate::bridge::wire_exec::handle_execute_workflow(&task_id, &msg, browser, &send, None, channel_key)
        .await;
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A cheap CapacityReport (the real one benchmarks the host; the scheduling tests below only
    /// need the struct).
    fn test_capacity() -> CapacityReport {
        CapacityReport {
            cpu_cores: 1,
            cpu_threads: 2,
            ram_total_gb: 8.0,
            check_mode: "content".to_string(),
            parallel_workers: 2,
            avg_check_latency_ms: 100.0,
            timeslots_needed: 1,
            targets_per_timeslot: 10,
            total_capacity: 10,
        }
    }

    async fn state_with_workflow(wf_id: i64) -> Arc<MonitorState> {
        let state = Arc::new(MonitorState::new(test_capacity()));
        state
            .assign_workflows(&serde_json::json!({
                "scheduled_workflows": [
                    {"id": wf_id, "schedule_interval_ms": 1000, "time_slot_offset_ms": 0}
                ],
                "sync_epoch_ms": super::super::scheduler::now_ms() - 1_000_000,
            }))
            .await;
        state
    }

    /// A PANIC inside a scheduled-workflow task must still release the `running` slot — otherwise
    /// `due()` never returns that workflow again and the schedule is dead for the process lifetime.
    #[tokio::test]
    async fn running_guard_releases_the_slot_on_panic() {
        let state = state_with_workflow(7).await;
        assert!(state.begin_workflow(7).await.is_some());
        // While running, the scheduler must not re-launch it.
        assert!(!state.workflows.lock().await.due().contains(&7));

        let guard_state = state.clone();
        let handle = tokio::spawn(async move {
            let _guard = RunningGuard { state: guard_state, wf_id: 7 };
            panic!("workflow blew up mid-run");
        });
        assert!(handle.await.is_err(), "the task must have panicked");
        // The guard's completion is handed to a detached task; give it a turn.
        tokio::task::yield_now().await;
        for _ in 0..50 {
            if !state.running_since.lock().await.contains_key(&7) {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        }
        assert!(
            !state.running_since.lock().await.contains_key(&7),
            "panic must not leave the workflow marked running"
        );
        // …and the schedule is re-armed (mark_completed ran), so it can fire again.
        tokio::time::sleep(std::time::Duration::from_millis(1_100)).await;
        assert!(state.workflows.lock().await.due().contains(&7));
    }

    /// The reaper is the last line of defence: a slot whose owner vanished without dropping its
    /// guard is force-completed rather than disabling the workflow forever.
    #[tokio::test]
    async fn reaper_force_completes_a_stale_running_slot() {
        let state = state_with_workflow(9).await;
        state.begin_workflow(9).await;
        // Backdate the launch instant beyond the stale threshold.
        state
            .running_since
            .lock()
            .await
            .insert(9, std::time::Instant::now() - (STALE_RUNNING_AGE + std::time::Duration::from_secs(1)));

        state.reap_stale_running().await;
        assert!(state.running_since.lock().await.is_empty());
        tokio::time::sleep(std::time::Duration::from_millis(1_100)).await;
        assert!(
            state.workflows.lock().await.due().contains(&9),
            "a reaped workflow must become due again"
        );
    }
}
