//! Process-global cloud task_id ↔ local run_id correlation (Workstream A, §7).
//!
//! When the desktop acts as a cloud execution agent, a cloud dispatch carries an opaque `task_id`
//! (backend correlation key) while the LOCAL engine tracks the work by its own integer `run_id` (the
//! `runs` row + `RunRegistry` handle). This module holds the tiny in-memory bridge between the two so:
//!   * `cancel_task{task_id}` can resolve `task_id → run_id` and route `engine.cancel(run_id)`, and
//!   * a later `GET /v1/cloud/agent/runs` endpoint can list the live cloud-initiated runs.
//!
//! The map is a `DashMap<String, i64>` behind a process-global `OnceLock` (mirrors the
//! `RelayNodeManager` / marketplace singletons). It is PURE local routing metadata — it never holds a
//! token, a credential, or any recipe content; identity/billing stay server-side
//! (the never-trust-a-BYO-agent rule). Entries are inserted when a run's `run_id` is known and
//! removed when the run reaches a terminal state, so a stale `task_id` can never mis-route a cancel.

use std::sync::OnceLock;

use dashmap::DashMap;

/// The process-global `task_id → run_id` table. Lazily created on first use.
fn table() -> &'static DashMap<String, i64> {
    static MAP: OnceLock<DashMap<String, i64>> = OnceLock::new();
    MAP.get_or_init(DashMap::new)
}

/// Record that cloud `task_id` is being served by local `run_id`. An empty `task_id` is ignored (a
/// dispatch with no correlation id can't be cancelled/listed by id anyway). Overwrites a prior entry
/// for the same `task_id` (a re-dispatch reuses the id) so the map always points at the newest run.
pub fn bind(task_id: &str, run_id: i64) {
    if task_id.is_empty() {
        return;
    }
    table().insert(task_id.to_string(), run_id);
}

/// Look up the local `run_id` currently serving cloud `task_id`, if any. Used by `cancel_task` to
/// route `engine.cancel(run_id)`.
pub fn run_id_for(task_id: &str) -> Option<i64> {
    table().get(task_id).map(|e| *e.value())
}

/// Drop the entry for `task_id` (the run reached a terminal state / the dispatch failed to start).
/// Idempotent: removing an absent id is a no-op. Called from the terminal path of every handler that
/// [`bind`]s, so the table only ever holds LIVE cloud runs.
pub fn unbind(task_id: &str) {
    if task_id.is_empty() {
        return;
    }
    table().remove(task_id);
}

/// Snapshot the live `(task_id, run_id)` pairs (for the `GET /v1/cloud/agent/runs` listing added in a
/// later step). Cloned so the caller never holds a shard lock across an `await`.
pub fn live_pairs() -> Vec<(String, i64)> {
    table()
        .iter()
        .map(|e| (e.key().clone(), *e.value()))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bind_lookup_unbind_roundtrip() {
        // Use a task_id unique to this test so the process-global table doesn't collide with peers.
        let tid = "test-runs-roundtrip-abc";
        assert!(run_id_for(tid).is_none(), "absent id → None");
        bind(tid, 4242);
        assert_eq!(run_id_for(tid), Some(4242));
        assert!(live_pairs().iter().any(|(t, r)| t == tid && *r == 4242));
        unbind(tid);
        assert!(run_id_for(tid).is_none(), "unbound id → None");
    }

    #[test]
    fn empty_task_id_is_ignored() {
        // An empty id must never be stored (it would alias every un-correlated dispatch).
        bind("", 1);
        assert!(run_id_for("").is_none());
        unbind(""); // no panic / no-op
    }

    #[test]
    fn rebind_overwrites_to_newest_run() {
        let tid = "test-runs-rebind-xyz";
        bind(tid, 1);
        bind(tid, 2);
        assert_eq!(run_id_for(tid), Some(2), "re-dispatch points at the newest run");
        unbind(tid);
    }
}
