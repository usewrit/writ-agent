//! The scheduled-**automation** lane.
//!
//! A `scheduled`-rooted automation fires on a fixed cadence rather than in response to an incoming
//! event. There is no incoming trigger to pull it, so — unlike `change_detected` / `webhook_received`
//! / `workflow_*` automations, which are dispatched from their trigger site — this lane PERIODICALLY
//! scans enabled automations, finds those whose parsed block tree has a root `event` block of
//! `blockType == "scheduled"`, reads the cadence from that event's config (`interval_ms`, or minutes
//! via a small compatibility shim), and dispatches [`flow::run_automation`] once the interval has
//! elapsed since the automation's `last_triggered_at`.
//!
//! ## Due decision (schema-grounded)
//! The `automations` table has no `next_scheduled_at` column, so "due" is computed from
//! `last_triggered_at` + the block-config interval: due iff `last_triggered_at` is NULL (never fired)
//! OR `now - last_triggered_at >= interval`. `run_automation` stamps `last_triggered_at = now` via
//! `mark_triggered` as part of firing, which advances the cadence for the next tick. The interval is
//! floored to the workflow anti-detection cadence (60s) via the shared `clamp` module so a tiny/zero
//! interval can't pin an automation perpetually due.
//!
//! ## Loop safety
//! `run_automation`'s own guardrails (cooldown / `max_fires` from `conditions`) still run inside the
//! dispatch, and the automation is fired with [`RunSource::Scheduled`] so any `workflow` action it
//! runs is one-hop-bounded exactly like the cloud service. Per-automation failures are logged, never
//! propagated — a bad automation cannot wedge the lane.

use std::sync::Arc;

use chrono::{DateTime, Utc};
use serde_json::{json, Value};
use sqlx::SqlitePool;

use super::recurrence::{self, Kind, Recurrence};
use super::SchedulerConfig;
use crate::local::engine::{Lane, LocalEngine, RunSource};
use crate::local::error::LocalResult;
use crate::local::flow;
use crate::local::store::automations::{self, Automation};

/// Result of one scheduled-automation lane pass.
#[derive(Debug, Clone, Default)]
pub struct ScheduledAutomationReport {
    /// Enabled `scheduled`-rooted automations considered this tick.
    pub considered: usize,
    /// Automations whose cadence had elapsed and were dispatched.
    pub dispatched: usize,
    /// Dispatches that failed (a `run_automation` error).
    pub failed: usize,
}

/// Dispatch all DUE `scheduled`-rooted automations as of `now`. Best-effort: only a failure to LOAD
/// the enabled set returns `Err`; per-automation failures are tallied and logged.
pub async fn dispatch_due_scheduled_automations(
    db: &SqlitePool,
    engine: &Arc<dyn LocalEngine>,
    now: DateTime<Utc>,
    config: &SchedulerConfig,
) -> LocalResult<ScheduledAutomationReport> {
    // Scope the scan to `scheduled`-rooted automations in SQL. Scanning ALL enabled automations under
    // a shared cap (change_detected/webhook/… included) meant scheduled ones past the cap were
    // permanently dropped from this lane; filtering by `event_type` in the query keeps the cap for the
    // rows this lane actually dispatches. `scheduled_interval_ms` still re-confirms the block-tree root.
    let enabled =
        automations::list_enabled_for_event(db, "scheduled", config.scheduled_batch_limit).await?;
    let mut report = ScheduledAutomationReport::default();

    for auto in enabled {
        // Only automations whose root event is `scheduled` participate in this lane. The recurrence
        // is read from the scheduled event block's config (mode/interval/time/days/tz).
        let recurrence = match scheduled_recurrence(&auto) {
            Some(r) => r,
            None => continue,
        };
        report.considered += 1;

        if !recurrence::is_due(&recurrence, auto.last_triggered_at.as_deref(), now) {
            continue;
        }

        // Only automations with a real executable block tree run here — a bare scheduled event with
        // no actions would do nothing.
        if !flow::has_executable_tree(auto.blocks.as_deref()) {
            continue;
        }

        let trigger = flow::FlowTrigger {
            event: "scheduled".to_string(),
            change_id: None,
            base_inputs: json!({}),
            context: json!({ "event": "scheduled" }),
            // Scheduled-sourced → any workflow action it runs is one-hop-bounded (cannot cascade).
            source: RunSource::Scheduled,
            lane: Lane::Background,
        };
        match flow::run_automation(db, engine, &auto, trigger).await {
            Ok(_) => report.dispatched += 1,
            Err(e) => {
                tracing::warn!(automation_id = auto.id, error = %e, "scheduled automation failed");
                report.failed += 1;
            }
        }
    }

    if report.dispatched > 0 || report.failed > 0 {
        tracing::info!(
            considered = report.considered,
            dispatched = report.dispatched,
            failed = report.failed,
            "scheduled-automation lane complete"
        );
    }
    Ok(report)
}

/// The [`Recurrence`] of an automation whose ROOT event block is `blockType == "scheduled"`, or
/// `None` if it is not a scheduled automation. Reads the block config's `mode`/`interval_ms`
/// (or the `interval_minutes` ×60000 compatibility shim) / `time` / `days` / `tz` via the shared
/// [`Recurrence::from_block_config`] helper.
///
/// For the `interval` kind (the default; every pre-existing scheduled automation) the interval is
/// floored to the same anti-detection cadence a scheduled WORKFLOW uses (60s) via the shared `clamp`
/// module, so the elapsed-since-last due check keeps its exact prior behavior. `daily`/`weekly` fire
/// on their local wall-clock occurrence and need no clamp (they are ≥ 1/day).
fn scheduled_recurrence(auto: &Automation) -> Option<Recurrence> {
    let blocks: Value = serde_json::from_str(auto.blocks.as_deref()?.trim()).ok()?;
    let arr = blocks.as_array()?;
    let root = arr.iter().find(|b| {
        b.get("type").and_then(Value::as_str) == Some("event")
            && b.get("parentId").map(Value::is_null).unwrap_or(true)
    })?;
    if root.get("blockType").and_then(Value::as_str) != Some("scheduled") {
        return None;
    }
    let cfg = root.get("config").cloned().unwrap_or(Value::Null);
    let mut r = Recurrence::from_block_config(&cfg);
    if r.kind == Kind::Interval {
        r.interval_ms = super::clamp::clamp_workflow_interval_ms(Some(r.interval_ms));
    }
    Some(r)
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Duration as ChronoDuration;

    fn auto_with(blocks: Option<&str>, last: Option<&str>) -> Automation {
        Automation {
            id: 1,
            target_id: None,
            event_type: "scheduled".into(),
            target_selector_id: None,
            workflow_id: None,
            webhook_trigger_id: None,
            name: "s".into(),
            description: None,
            enabled: 1,
            priority: Some(0),
            conditions: "{}".into(),
            actions: "[]".into(),
            blocks: blocks.map(String::from),
            last_triggered_at: last.map(String::from),
            trigger_count: Some(0),
            created_at: "2026-01-01T00:00:00.000Z".into(),
            updated_at: None,
        }
    }

    #[test]
    fn interval_reads_interval_ms_and_floors() {
        let a = auto_with(
            Some(r#"[{"id":"e","type":"event","blockType":"scheduled","config":{"interval_ms":600000}}]"#),
            None,
        );
        let r = scheduled_recurrence(&a).unwrap();
        assert_eq!(r.kind, Kind::Interval);
        assert_eq!(r.interval_ms, 600_000);
    }

    #[test]
    fn interval_accepts_minutes_shim() {
        let a = auto_with(
            Some(r#"[{"id":"e","type":"event","blockType":"scheduled","config":{"interval_minutes":10}}]"#),
            None,
        );
        let r = scheduled_recurrence(&a).unwrap();
        assert_eq!(r.interval_ms, 600_000);
    }

    #[test]
    fn zero_interval_floored_not_zero() {
        let a = auto_with(
            Some(r#"[{"id":"e","type":"event","blockType":"scheduled","config":{"interval_ms":0}}]"#),
            None,
        );
        // Floored to the 60s workflow cadence, never 0.
        assert_eq!(scheduled_recurrence(&a).unwrap().interval_ms, 60_000);
    }

    #[test]
    fn non_scheduled_root_is_ignored() {
        let a = auto_with(
            Some(r#"[{"id":"e","type":"event","blockType":"change_detected","config":{}}]"#),
            None,
        );
        assert!(scheduled_recurrence(&a).is_none());
    }

    #[test]
    fn daily_recurrence_parsed_from_block() {
        let a = auto_with(
            Some(r#"[{"id":"e","type":"event","blockType":"scheduled","config":{"mode":"daily","time":"09:00","tz":"America/New_York"}}]"#),
            None,
        );
        let r = scheduled_recurrence(&a).unwrap();
        assert_eq!(r.kind, Kind::Daily);
        assert_eq!(r.time.as_deref(), Some("09:00"));
        assert_eq!(r.tz, "America/New_York");
    }

    #[test]
    fn due_when_never_fired_or_interval_elapsed() {
        let now = Utc::now();
        let a = auto_with(
            Some(r#"[{"id":"e","type":"event","blockType":"scheduled","config":{"interval_ms":60000}}]"#),
            None,
        );
        let r = scheduled_recurrence(&a).unwrap();
        assert!(recurrence::is_due(&r, None, now), "never fired is due");

        let recent = (now - ChronoDuration::seconds(10)).to_rfc3339();
        assert!(!recurrence::is_due(&r, Some(&recent), now), "10s ago with 60s interval is not due");

        let old = (now - ChronoDuration::seconds(120)).to_rfc3339();
        assert!(recurrence::is_due(&r, Some(&old), now), "120s ago with 60s interval is due");
    }
}
