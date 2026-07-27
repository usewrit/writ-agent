//! Incremental target updates. Port of
//! `desktop-agent/lib/incremental_updater.py`.
//!
//! Updates are *queued* (with monotonic version ordering) and applied between
//! check cycles, never mid-cycle. A `full_rebuild_required` update clears the
//! queue and signals the caller to re-group from scratch.

use std::collections::VecDeque;

use super::models::Target;

/// One coordinator update: a batch of add/remove/modify changes at a version.
#[derive(Debug, Clone)]
pub struct IncrementalUpdate {
    pub version: i64,
    pub changes: Vec<serde_json::Value>,
    pub full_rebuild_required: bool,
}

impl IncrementalUpdate {
    /// Parse from a `target_sync.incremental_target_update` JSON object.
    pub fn from_json(v: &serde_json::Value) -> Option<Self> {
        let version = v.get("version").and_then(|x| x.as_i64())?;
        let changes = v
            .get("changes")
            .and_then(|x| x.as_array())
            .cloned()
            .unwrap_or_default();
        let full_rebuild_required =
            v.get("full_rebuild_required").and_then(|x| x.as_bool()).unwrap_or(false);
        Some(Self { version, changes, full_rebuild_required })
    }
}

#[derive(Debug, Clone)]
enum Pending {
    FullRebuild(IncrementalUpdate),
    Incremental(IncrementalUpdate),
}

/// Outcome of draining the queue against the live target list.
#[derive(Debug, Default)]
pub struct ApplyResult {
    /// Targets changed and the caller must re-group the schedulers.
    pub needs_regroup: bool,
    /// Coordinator asked for a full rebuild (re-fetch / re-distribute).
    pub full_rebuild: bool,
    /// Number of add/remove/modify operations applied.
    pub changes_applied: usize,
}

#[derive(Debug, Default)]
pub struct IncrementalUpdateManager {
    pending: VecDeque<Pending>,
    /// Highest version already APPLIED to the live target list.
    current_version: i64,
    /// Highest version accepted into the queue but not yet applied. Gating on this (not just
    /// `current_version`) rejects an out-of-order arrival — a stale v3 landing after a v5 was queued
    /// but before either is applied — so updates apply in version order, never arrival order.
    highest_queued_version: i64,
}

impl IncrementalUpdateManager {
    pub fn new() -> Self {
        Self::default()
    }

    /// Queue an update. Returns false if it's stale — its version is `<=` the highest version already
    /// applied OR already queued. Gating on both means an out-of-order arrival (a stale v3 after a v5
    /// was queued but not yet applied) is dropped rather than overwriting newer state on apply.
    pub fn queue(&mut self, update: IncrementalUpdate) -> bool {
        let floor = self.current_version.max(self.highest_queued_version);
        if update.version <= floor {
            tracing::warn!(
                version = update.version,
                current = self.current_version,
                highest_queued = self.highest_queued_version,
                "Ignoring stale/out-of-order incremental update"
            );
            return false;
        }
        self.highest_queued_version = update.version;
        if update.full_rebuild_required {
            self.pending.clear();
            self.pending.push_back(Pending::FullRebuild(update));
        } else {
            self.pending.push_back(Pending::Incremental(update));
        }
        true
    }

    pub fn has_pending(&self) -> bool {
        !self.pending.is_empty()
    }

    /// Apply every queued update to `targets` in order. Mutates `targets` in
    /// place; on a full-rebuild request the queue is drained and the caller
    /// should re-fetch/re-distribute.
    pub fn apply(&mut self, targets: &mut Vec<Target>) -> ApplyResult {
        let mut result = ApplyResult::default();
        while let Some(item) = self.pending.pop_front() {
            match item {
                Pending::FullRebuild(u) => {
                    self.current_version = u.version.max(self.current_version);
                    result.full_rebuild = true;
                    result.needs_regroup = true;
                    // Everything after a full rebuild is superseded.
                    self.pending.clear();
                    return result;
                }
                Pending::Incremental(u) => {
                    for change in &u.changes {
                        if Self::apply_change(targets, change) {
                            result.changes_applied += 1;
                            result.needs_regroup = true;
                        }
                    }
                    self.current_version = u.version.max(self.current_version);
                }
            }
        }
        result
    }

    fn apply_change(targets: &mut Vec<Target>, change: &serde_json::Value) -> bool {
        let op = change.get("operation").and_then(|v| v.as_str()).unwrap_or("");
        let target_id = change.get("target_id").and_then(|v| v.as_i64());
        match op {
            "add" => {
                if let Some(data) = change.get("target_data") {
                    if let Ok(t) = serde_json::from_value::<Target>(data.clone()) {
                        // Replace if a target with this id/url already exists.
                        targets.retain(|x| x.id != t.id || x.url != t.url);
                        targets.push(t);
                        return true;
                    }
                }
                false
            }
            "remove" => {
                let before = targets.len();
                if let Some(id) = target_id {
                    targets.retain(|x| x.id != Some(id));
                } else if let Some(url) =
                    change.get("target_data").and_then(|d| d.get("url")).and_then(|v| v.as_str())
                {
                    targets.retain(|x| x.url != url);
                }
                targets.len() != before
            }
            "modify" => {
                if let Some(data) = change.get("target_data") {
                    if let Ok(t) = serde_json::from_value::<Target>(data.clone()) {
                        if let Some(slot) = targets.iter_mut().find(|x| {
                            (target_id.is_some() && x.id == target_id) || x.url == t.url
                        }) {
                            *slot = t;
                            return true;
                        }
                        // Modify of an unknown target → treat as add.
                        targets.push(t);
                        return true;
                    }
                }
                false
            }
            _ => false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn target(id: i64, url: &str) -> serde_json::Value {
        serde_json::json!({ "id": id, "url": url, "check_type": "content" })
    }

    #[test]
    fn add_remove_modify_and_version_gate() {
        let mut mgr = IncrementalUpdateManager::new();
        let mut targets: Vec<Target> = vec![];

        // add v1
        assert!(mgr.queue(IncrementalUpdate {
            version: 1,
            changes: vec![serde_json::json!({"operation":"add","target_id":1,"target_data":target(1,"https://a")})],
            full_rebuild_required: false,
        }));
        let r = mgr.apply(&mut targets);
        assert_eq!(r.changes_applied, 1);
        assert_eq!(targets.len(), 1);

        // stale v1 rejected
        assert!(!mgr.queue(IncrementalUpdate { version: 1, changes: vec![], full_rebuild_required: false }));

        // modify v2
        mgr.queue(IncrementalUpdate {
            version: 2,
            changes: vec![serde_json::json!({"operation":"modify","target_id":1,
                "target_data":{"id":1,"url":"https://a","check_type":"uptime"}})],
            full_rebuild_required: false,
        });
        mgr.apply(&mut targets);
        assert_eq!(targets[0].check_type, "uptime");

        // remove v3
        mgr.queue(IncrementalUpdate {
            version: 3,
            changes: vec![serde_json::json!({"operation":"remove","target_id":1})],
            full_rebuild_required: false,
        });
        mgr.apply(&mut targets);
        assert!(targets.is_empty());
    }

    #[test]
    fn rejects_out_of_order_before_apply() {
        let mut mgr = IncrementalUpdateManager::new();
        let mut targets: Vec<Target> = vec![];

        // Queue v5, then a stale v3 arrives BEFORE either is applied → v3 must be rejected so it can't
        // overwrite v5's newer state when the queue drains.
        assert!(mgr.queue(IncrementalUpdate {
            version: 5,
            changes: vec![serde_json::json!({"operation":"add","target_id":1,
                "target_data":{"id":1,"url":"https://v5","check_type":"content"}})],
            full_rebuild_required: false,
        }));
        assert!(
            !mgr.queue(IncrementalUpdate {
                version: 3,
                changes: vec![serde_json::json!({"operation":"add","target_id":2,
                    "target_data":{"id":2,"url":"https://v3","check_type":"content"}})],
                full_rebuild_required: false,
            }),
            "a v3 arriving after v5 was queued is out-of-order and must be dropped"
        );

        mgr.apply(&mut targets);
        assert_eq!(targets.len(), 1, "only the newer v5 add applied");
        assert_eq!(targets[0].url, "https://v5");
    }

    #[test]
    fn full_rebuild_clears_queue() {
        let mut mgr = IncrementalUpdateManager::new();
        let mut targets: Vec<Target> = vec![];
        mgr.queue(IncrementalUpdate { version: 5, changes: vec![], full_rebuild_required: true });
        let r = mgr.apply(&mut targets);
        assert!(r.full_rebuild && r.needs_regroup);
        assert!(!mgr.has_pending());
    }
}
