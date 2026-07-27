//! Per-workflow AI-repair lock.
//!
//! When a run enters AI auto-repair for a workflow (re-deriving a broken selector, or the heavier
//! whole-recipe re-record), it holds a per-workflow lock for the rest of that run. Any OTHER run of
//! the SAME workflow waits at its start until the repair finishes, then proceeds with the freshly
//! repaired recipe. This stops a thundering herd — N concurrent calls that all hit the same broken
//! step would otherwise each launch its own (expensive) repair and race to overwrite the recipe.
//!
//! Backed by a per-workflow async mutex kept in a small shared map. `begin`/`try_begin` acquire the
//! lock (the repairing run holds the guard, threaded through the self-heal restart so it never blocks
//! on itself); `wait_if_repairing` is a barrier the run-entry path uses to hold new calls until an
//! in-flight repair completes.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use tokio::sync::{Mutex as AsyncMutex, OwnedMutexGuard};

/// Cheap-to-clone handle over the shared per-workflow repair locks.
#[derive(Clone, Default)]
pub struct RepairGate {
    inner: Arc<Mutex<HashMap<i64, Arc<AsyncMutex<()>>>>>,
}

impl RepairGate {
    /// The async mutex for `workflow_id`, created on first use. Held in the map so every run of the
    /// workflow shares the SAME lock.
    fn lock_for(&self, workflow_id: i64) -> Arc<AsyncMutex<()>> {
        let mut map = self.inner.lock().unwrap();
        map.entry(workflow_id)
            .or_insert_with(|| Arc::new(AsyncMutex::new(())))
            .clone()
    }

    /// Acquire the repair lock without waiting. `Some(guard)` if it was free (this run becomes the
    /// repairer), `None` if another run already holds it (the caller should wait + restart instead of
    /// repairing in parallel).
    // Only called from the cloud-gated AI auto-repair path in `real.rs`; dead in the fleet build.
    #[cfg_attr(not(feature = "cloud"), allow(dead_code))]
    pub fn try_begin(&self, workflow_id: i64) -> Option<RepairGuard> {
        let lock = self.lock_for(workflow_id);
        lock.try_lock_owned().ok().map(|guard| RepairGuard { _guard: guard })
    }

    /// True if a repair is currently in flight for `workflow_id` (best-effort — the lock may free the
    /// instant after this returns; the loop-level `try_begin` is the actual correctness guarantee).
    pub fn is_repairing(&self, workflow_id: i64) -> bool {
        self.lock_for(workflow_id).try_lock().is_err()
    }

    /// Barrier: return once no repair is in flight for `workflow_id`. If a repair is running, this
    /// blocks until it finishes (acquires the lock behind the repairer, then releases immediately).
    pub async fn wait_if_repairing(&self, workflow_id: i64) {
        let lock = self.lock_for(workflow_id);
        let _ = lock.lock().await; // waits for any holder to release, then drops right away
    }
}

/// Held by the run doing the repair. Releasing it (drop) lets waiting runs proceed. Moved through the
/// self-heal restart so the whole repair→restart→settle sequence holds the lock as one unit.
pub struct RepairGuard {
    _guard: OwnedMutexGuard<()>,
}
