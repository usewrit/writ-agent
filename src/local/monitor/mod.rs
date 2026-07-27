//! Local monitor CHECK RUNNER (Stage A).
//!
//! Executes DUE monitor checks against the local encrypted DB and records results into the local
//! stores, dispatching `change_detected` automations through the in-process [`LocalEngine`]. This is
//! the offline-first sibling of the cloud monitoring loop (`crate::monitor`): it REUSES the cloud
//! [`Checker`](crate::monitor::checker::Checker) — the transport-agnostic HTTP-fetch + CSS-extract +
//! hash + diff + change-detection core — but owns its own DB-rooted orchestration. It pulls in NO
//! cloud transport (no ws-gateway, no backend callbacks, no `SaaSBridge`).
//!
//! ## What "due" means
//! A target is due when:
//!   * it is `enabled`, AND
//!   * its `next_run_at` is unset or `<= now` (the same gate cloud uses via `targets::list_due`), AND
//!   * the 60s anti-detection floor since its last `monitor_state.checked_at` has elapsed.
//! The interval is `targets.check_period_ms` (clamped to a `MIN_CHECK_INTERVAL_MS = 60_000` floor).
//! After a check we advance `next_run_at = now + interval` so the row won't re-fire next tick.
//!
//! ## Change-only persistence (matches the existing pattern)
//! Live state lives in `monitor_state` (one upsert per check). The `changes` / `uptime_checks` tables
//! are append history written ONLY when something happened:
//!   * content target: a `changes` row is inserted only when a selector's hash differs from its
//!     stored baseline (first check seeds the baseline, never a "change"); `monitor_state.state` is
//!     `"changed"` / `"unchanged"` / `"error"` and `last_change_at` is stamped only on change.
//!   * uptime target: an `uptime_checks` sample is appended every check (it IS the time series);
//!     `monitor_state.is_up` / `status_code` reflect the latest sample.
//!
//! ## Dispatch
//! On a detected content change we look up enabled `change_detected` automations for that target and
//! run each one's `workflow_id` through `engine.run(RunRequest{ source: Monitor, lane: Background })`,
//! recording an `automation_executions` row per automation. One target's failure never aborts the
//! others — each check is bounded by a timeout and classified into [`CheckStatus`].

mod runner;

pub use runner::{
    capture_all_baselines, capture_selector_baseline, probe_selector, run_check_for_target,
    run_due_checks, sweep_stale_health, BaselineSummary, CheckOutcome, CheckStatus, DispatchOutcome,
    SelectorProbe, TickReport,
};

/// Anti-detection floor: never check the same target more often than this, regardless of its
/// configured interval. Mirrors the cloud subsystem's 60s cadence floor.
pub const MIN_CHECK_INTERVAL_MS: i64 = 60_000;

/// Per-target wall-clock budget for one check. A slow/hung target trips this and is classified as a
/// timeout rather than wedging the whole tick.
pub const CHECK_TIMEOUT_SECS: u64 = 90;

/// The `automations.event_type` a detected content change fires.
pub const EVENT_CHANGE_DETECTED: &str = "change_detected";

/// Monitor-HEALTH events (mirror the cloud trigger service + FE block catalog). Fired on the EDGE
/// between the healthy ({unchanged, changed, up, ok}) and unhealthy ({error, down, stale}) states:
///   * `monitor_down`      — a healthy monitor's check started failing / became unreachable.
///   * `monitor_recovered` — a down/stale monitor's check succeeded again.
///   * `monitor_stale`     — a monitor stopped being checked within its expected cadence (sweep).
pub const EVENT_MONITOR_DOWN: &str = "monitor_down";
pub const EVENT_MONITOR_STALE: &str = "monitor_stale";
pub const EVENT_MONITOR_RECOVERED: &str = "monitor_recovered";
