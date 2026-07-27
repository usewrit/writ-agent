//! Scheduled-workflow runner. Port of
//! `desktop-agent/lib/workflow_scheduler.py` (scheduling half).
//!
//! Each scheduled workflow gets its own sync-aligned [`TimeSlotScheduler`]
//! (interval + offset). The monitor loop polls [`due`](WorkflowScheduler::due),
//! runs each due workflow through the existing `handle_execute_workflow` path,
//! and reports `scheduled_workflow_complete`. A running-set prevents a slow
//! workflow from being launched twice.

use std::collections::{HashMap, HashSet};

use super::scheduler::{self, TimeSlotScheduler};

struct WorkflowEntry {
    scheduler: TimeSlotScheduler,
    interval_ms: i64,
    offset_ms: i64,
    data: serde_json::Value,
}

#[derive(Default)]
pub struct WorkflowScheduler {
    sync_epoch_ms: i64,
    entries: HashMap<i64, WorkflowEntry>,
    running: HashSet<i64>,
}

impl WorkflowScheduler {
    pub fn new() -> Self {
        Self::default()
    }

    /// Reconcile the scheduled-workflow set from an `assign_workflows` frame.
    pub fn update_workflows(&mut self, workflows: &[serde_json::Value], sync_epoch_ms: i64) {
        // Clamp the wire-supplied epoch before it is stored or used for slot alignment.
        let sync_epoch_ms = sync_epoch_ms.clamp(0, scheduler::MAX_EPOCH_MS);
        self.sync_epoch_ms = sync_epoch_ms;
        let mut active: HashSet<i64> = HashSet::new();

        for wf in workflows {
            let Some(id) = wf.get("id").and_then(|v| v.as_i64()) else { continue };
            active.insert(id);
            // CLAMP AT INGEST. `.unwrap_or(60_000)` only defaults when the field is ABSENT — an
            // explicit `"schedule_interval_ms": 0` (or a negative) passes straight through. That
            // used to reach `TimeSlotScheduler::calculate_next_run` and hang it in a
            // non-advancing loop, holding this struct's mutex, on the WS read-loop task.
            // `TimeSlotScheduler::new` now clamps too (defence in depth); clamping here as well
            // keeps `entry.interval_ms` consistent with what the scheduler actually uses, so the
            // "unchanged schedule" fast path below compares like with like.
            let interval_ms = wf
                .get("schedule_interval_ms")
                .and_then(|v| v.as_i64())
                .unwrap_or(60_000)
                .clamp(scheduler::MIN_PERIOD_MS, scheduler::MAX_PERIOD_MS);
            let offset_ms = wf
                .get("time_slot_offset_ms")
                .and_then(|v| v.as_i64())
                .unwrap_or(0)
                .clamp(-scheduler::MAX_PERIOD_MS, scheduler::MAX_PERIOD_MS);

            match self.entries.get_mut(&id) {
                Some(entry) if entry.interval_ms == interval_ms && entry.offset_ms == offset_ms => {
                    entry.data = wf.clone(); // keep schedule, refresh payload
                }
                _ => {
                    let scheduler = TimeSlotScheduler::new(
                        interval_ms,
                        offset_ms,
                        Some(sync_epoch_ms),
                        false,
                        0.0,
                        None,
                    );
                    self.entries.insert(
                        id,
                        WorkflowEntry { scheduler, interval_ms, offset_ms, data: wf.clone() },
                    );
                }
            }
        }

        // Drop workflows no longer scheduled.
        self.entries.retain(|id, _| active.contains(id));
        self.running.retain(|id| active.contains(id));
    }

    /// Milliseconds until the earliest not-running workflow is due (`i64::MAX`
    /// if none), so the monitor loop can sleep exactly until then.
    pub fn next_due_in_ms(&self) -> i64 {
        self.entries
            .iter()
            .filter(|(id, _)| !self.running.contains(id))
            .map(|(_, e)| e.scheduler.time_until_next_run_ms())
            .min()
            .unwrap_or(i64::MAX)
    }

    /// Workflow ids due to run now (excluding ones already running).
    pub fn due(&self) -> Vec<i64> {
        self.entries
            .iter()
            .filter(|(id, e)| !self.running.contains(id) && e.scheduler.should_run())
            .map(|(id, _)| *id)
            .collect()
    }

    pub fn workflow_data(&self, id: i64) -> Option<serde_json::Value> {
        self.entries.get(&id).map(|e| e.data.clone())
    }

    pub fn mark_running(&mut self, id: i64) {
        self.running.insert(id);
    }

    /// Mark a workflow finished and schedule its next run.
    pub fn mark_completed(&mut self, id: i64) {
        self.running.remove(&id);
        if let Some(entry) = self.entries.get_mut(&id) {
            entry.scheduler.mark_completed(0);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn schedules_and_dedups_running() {
        let mut ws = WorkflowScheduler::new();
        let epoch = super::super::scheduler::now_ms() - 1_000_000;
        ws.update_workflows(
            &[serde_json::json!({"id": 7, "schedule_interval_ms": 1000, "time_slot_offset_ms": 0})],
            epoch,
        );
        // The workflow is scheduled (next aligned slot is within one interval).
        let next = ws.entries.get(&7).unwrap().scheduler.time_until_next_run_ms();
        assert!(next <= 1000, "next run should be within the interval, got {next}");
        // A running workflow is never returned by due(), regardless of timing.
        ws.mark_running(7);
        assert!(ws.due().is_empty(), "running workflow must not be re-launched");
        ws.mark_completed(7);
        assert!(ws.workflow_data(7).is_some());
    }

    #[test]
    fn removes_unscheduled() {
        let mut ws = WorkflowScheduler::new();
        ws.update_workflows(&[serde_json::json!({"id": 1, "schedule_interval_ms": 5000})], 0);
        ws.update_workflows(&[serde_json::json!({"id": 2, "schedule_interval_ms": 5000})], 0);
        assert!(ws.workflow_data(1).is_none());
        assert!(ws.workflow_data(2).is_some());
    }
}
