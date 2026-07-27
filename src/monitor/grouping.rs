//! Group targets by period and distribute them round-robin across the agent's
//! assigned time slots. Port of `_group_targets_by_period_and_slots`.
//!
//! Each target lands in exactly ONE slot (no duplicates). Because every
//! `TimeSlotScheduler` derives its next run from the shared `sync_epoch_ms`,
//! rebuilding fresh schedulers re-derives the same aligned slot times — so we
//! don't need the Python `preserve_existing` path to avoid drift.

use std::collections::BTreeMap;

use super::models::Target;
use super::scheduler::TimeSlotScheduler;

/// Anti-detection floor: no single agent ever checks a target faster than this,
/// regardless of the target's interval. A fast (e.g. 1s) target's cadence is
/// achieved by a FLEET of staggered agents — it needs ~`60000/interval` servers
/// to reach its interval; with fewer it degrades gracefully instead of one
/// server hammering the site. Mirrors the backend distributor's
/// `ANTI_DETECTION_THRESHOLD_MS`.
pub const MIN_CHECK_INTERVAL_MS: i64 = 60_000;

/// One time slot: a scheduler plus the targets assigned to it.
pub struct Slot {
    pub scheduler: TimeSlotScheduler,
    pub targets: Vec<Target>,
    pub slot_index: usize,
    pub offset_ms: i64,
}

/// All slots for one period.
pub struct PeriodGroup {
    pub period_ms: i64,
    pub slots: Vec<Slot>,
}

/// Resolved scheduling for one period group: slot offsets (phase) + the
/// effective period each agent actually checks at.
struct Resolved {
    offsets: Vec<i64>,
    effective_period_ms: i64,
}

/// Resolve slot offsets + the agent's effective check period for `period_ms`
/// from the coordinator's `time_slot_offsets` (a JSON list — legacy — or a dict
/// keyed by period — rolling mode).
///
/// The coordinator's `effective_period_ms` (= period × num_agents, floored at
/// the 60s anti-detection threshold) is the cadence THIS agent checks at; the
/// fleet collectively achieves the target's interval via staggered offsets. We
/// honor it, then floor defensively at [`MIN_CHECK_INTERVAL_MS`] so a missing /
/// misconfigured value can never make one agent hammer a site.
fn resolve(
    time_slot_offsets: &serde_json::Value,
    period_ms: i64,
    period_idx: usize,
    num_period_groups: usize,
) -> Resolved {
    let floor = |p: i64| p.max(MIN_CHECK_INTERVAL_MS);
    // Rolling mode: { "<period>": { "offset_ms": X, "effective_period_ms": Y } | [offsets] }
    if time_slot_offsets.is_object() {
        let obj = time_slot_offsets.as_object().unwrap();
        let pc = obj
            .get(&period_ms.to_string())
            .or_else(|| obj.get(&format!("{period_ms}")))
            .cloned()
            .unwrap_or(serde_json::Value::Null);
        if let Some(map) = pc.as_object() {
            let offset_ms = map.get("offset_ms").and_then(|v| v.as_i64()).unwrap_or(0);
            let eff = map.get("effective_period_ms").and_then(|v| v.as_i64()).unwrap_or(period_ms);
            return Resolved { offsets: vec![offset_ms], effective_period_ms: floor(eff) };
        }
        if let Some(list) = pc.as_array() {
            let offsets: Vec<i64> = list.iter().filter_map(|v| v.as_i64()).collect();
            return Resolved {
                offsets: if offsets.is_empty() { vec![0] } else { offsets },
                effective_period_ms: floor(period_ms),
            };
        }
        return Resolved { offsets: vec![0], effective_period_ms: floor(period_ms) };
    }

    // Legacy mode: a flat list of base offsets, staggered per period group.
    let base: Vec<i64> = time_slot_offsets
        .as_array()
        .map(|a| a.iter().filter_map(|v| v.as_i64()).collect())
        .unwrap_or_default();
    let base = if base.is_empty() { vec![0] } else { base };

    let num_base = base.len();
    let shift_per_period = if num_base > 1 && num_period_groups > 1 {
        let slot_duration = base[1] - base[0];
        slot_duration / (num_period_groups as i64 + 1)
    } else {
        0
    };
    let offsets = if shift_per_period > 0 {
        let shift = period_idx as i64 * shift_per_period;
        base.iter().map(|o| o + shift).collect()
    } else {
        base
    };
    Resolved { offsets, effective_period_ms: floor(period_ms) }
}

/// Build period groups + slots from the assigned target list.
pub fn group_targets(
    targets: &[Target],
    global_period_ms: i64,
    sync_epoch_ms: Option<i64>,
    time_slot_offsets: &serde_json::Value,
) -> Vec<PeriodGroup> {
    // Group by period (BTreeMap → deterministic, sorted like the Python `sorted`).
    let mut by_period: BTreeMap<i64, Vec<Target>> = BTreeMap::new();
    for t in targets {
        let period = t.check_period_ms.unwrap_or(global_period_ms);
        by_period.entry(period).or_default().push(t.clone());
    }

    let num_groups = by_period.len();
    let mut out = Vec::new();

    for (period_idx, (period_ms, period_targets)) in by_period.into_iter().enumerate() {
        let resolved = resolve(time_slot_offsets, period_ms, period_idx, num_groups);
        let num_slots = resolved.offsets.len().max(1);

        let mut slots = Vec::new();
        for (slot_idx, &offset_ms) in resolved.offsets.iter().enumerate() {
            // Round-robin: target i belongs to slot (i % num_slots).
            let slot_targets: Vec<Target> = period_targets
                .iter()
                .enumerate()
                .filter(|(i, _)| i % num_slots == slot_idx)
                .map(|(_, t)| t.clone())
                .collect();
            if slot_targets.is_empty() {
                continue;
            }
            // Scheduler PERIOD = the coordinator's effective period (floored) so
            // THIS agent checks at the anti-detection-safe cadence; the fleet
            // hits the target's interval via staggered offsets.
            let scheduler = TimeSlotScheduler::new(
                resolved.effective_period_ms,
                offset_ms,
                sync_epoch_ms,
                false, // respect assigned offset from the start
                0.0,   // coordinator controls jitter via target_sync
                None,
            );
            slots.push(Slot { scheduler, targets: slot_targets, slot_index: slot_idx, offset_ms });
        }
        out.push(PeriodGroup { period_ms, slots });
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn target(url: &str, period: Option<i64>) -> Target {
        Target {
            id: None, url: url.into(), check_type: "content".into(),
            check_period_ms: period, requires_playwright: false,
            pre_check_workflow: None, auth_session: None, timeout_ms: None,
            expected_status_code: None, check_ssl: true, selectors: vec![],
        }
    }

    #[test]
    fn round_robin_no_duplicates_legacy_offsets() {
        let targets: Vec<Target> = (0..5).map(|i| target(&format!("https://x/{i}"), None)).collect();
        let offsets = serde_json::json!([0, 5000]); // 2 slots
        let groups = group_targets(&targets, 10_000, Some(super::super::scheduler::now_ms()), &offsets);
        assert_eq!(groups.len(), 1);
        let g = &groups[0];
        assert_eq!(g.slots.len(), 2);
        let total: usize = g.slots.iter().map(|s| s.targets.len()).sum();
        assert_eq!(total, 5);
        // slot 0 gets indices 0,2,4; slot 1 gets 1,3
        assert_eq!(g.slots[0].targets.len(), 3);
        assert_eq!(g.slots[1].targets.len(), 2);
    }

    #[test]
    fn rolling_mode_honors_coordinator_effective_period() {
        let targets = vec![target("https://a", Some(1_000)), target("https://b", Some(1_000))];
        // 1s target across a 120-agent fleet → coordinator sends effective_period
        // 120s; THIS agent checks every 120s (staggered), the fleet hits 1s.
        let offsets = serde_json::json!({ "1000": { "offset_ms": 1000, "effective_period_ms": 120_000 } });
        let groups = group_targets(&targets, 10_000, Some(0), &offsets);
        assert_eq!(groups[0].slots[0].offset_ms, 1000);
        assert_eq!(groups[0].slots[0].scheduler.period_ms, 120_000, "must honor coordinator effective period");
    }

    #[test]
    fn one_second_target_never_hammers_one_agent() {
        // A 1s target with NO fleet info must NOT be checked every 1s by a single
        // agent — it floors at the 60s anti-detection threshold.
        let targets = vec![target("https://a", Some(1_000))];
        let groups = group_targets(&targets, 60_000, Some(0), &serde_json::Value::Null);
        assert_eq!(
            groups[0].slots[0].scheduler.period_ms, MIN_CHECK_INTERVAL_MS,
            "one server must not check a 1s target faster than the anti-detection floor"
        );
    }
}
