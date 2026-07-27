//! Device check-capacity budget — how many checks per minute THIS machine can sustainably run.
//!
//! Sibling of [`clamp`](super::clamp) with the same philosophy: this is NOT a paywall and NOT a
//! plan gate — local monitors are free and never metered by billing. It is machine protection
//! only: every enabled monitor consumes a slice of a hardware-derived checks-per-minute budget,
//! and a create/update that would push the AGGREGATE past what this hardware can drain is refused
//! with an actionable error (slow an interval, disable a monitor, or run the heavy ones in the
//! cloud) instead of silently degrading into a permanently-late check queue and a hot laptop.
//!
//! ## Units
//! Cost is normalized to HTTP-fast-path units: an HTML check = 1 unit, a `requires_playwright`
//! check = [`JS_UNIT_COST`] units (a real browser context is roughly an order of magnitude heavier
//! in CPU/RAM — mirrors the cloud's weighted check units). A monitor's load is
//! `unit_cost × checks/min`, so at the anti-detection floors (HTML 60s, JS 300s) EVERY monitor
//! costs exactly 1 unit/min — the budget reads naturally as "monitors at floor cadence".
//!
//! ## Budget
//! Auto-derived from hardware once per process: `min(cores × 6, ram_gib × 4)` clamped into
//! [`AUTO_MIN_UNITS`]..=[`AUTO_MAX_UNITS`]. Both terms are deliberately conservative — the monitor
//! runner is sequential within a tick, and RAM is what browser contexts actually exhaust. A
//! non-zero `[monitors].max_check_units_per_min` (env `WRIT_MAX_CHECK_UNITS_PER_MIN`) overrides
//! the auto value; it is installed at boot exactly like the cadence floors.
//!
//! ## Enforcement
//! SAVE-time only (create / interval change / browser-path flip / enable). Reductions are NEVER
//! blocked — an already-over-budget set (older build, hand-edited DB, downgraded hardware) can
//! always be walked back down, and disabling always succeeds.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::OnceLock;

use serde::Serialize;

use crate::local::error::{LocalError, LocalResult};
use crate::local::store::targets::{self, Target};

/// Relative cost of a browser-path check vs. the HTTP fast-path (cloud parity: HTML=1, JS=5).
pub const JS_UNIT_COST: f64 = 5.0;
/// Auto-budget floor: even the weakest supported machine can hold a dozen floor-cadence monitors.
const AUTO_MIN_UNITS: f64 = 12.0;
/// Auto-budget ceiling: past this, the sequential runner (not hardware) is the bottleneck.
const AUTO_MAX_UNITS: f64 = 240.0;
/// Cap on the enabled-target scan; far above anything a single machine can actually sustain.
const SCAN_LIMIT: i64 = 10_000;

/// Process-global user-configured budget override (units/min). `0` = auto (hardware-derived).
/// Installed at boot from `[monitors].max_check_units_per_min` (see `app::lifecycle`), mirroring
/// the cadence-floor pattern in [`clamp`](super::clamp).
static OVERRIDE_UNITS_PER_MIN: AtomicU64 = AtomicU64::new(0);

/// Install the user-configured budget override (`0` = auto). Called once at boot.
pub fn install_capacity_override(units_per_min: u64) {
    OVERRIDE_UNITS_PER_MIN.store(units_per_min, Ordering::Relaxed);
}

/// Unit cost of one check on the given path.
pub fn unit_cost(requires_playwright: bool) -> f64 {
    if requires_playwright {
        JS_UNIT_COST
    } else {
        1.0
    }
}

/// Budget units/min one monitor consumes at the given cadence. A non-positive/absent period is
/// costed at the path's anti-detection floor (what it would actually run at after clamping).
pub fn units_per_min(check_period_ms: Option<i64>, requires_playwright: bool) -> f64 {
    let floor = super::clamp::monitor_floor_ms(requires_playwright);
    let period = match check_period_ms {
        Some(ms) if ms > 0 => ms.max(floor),
        _ => floor,
    } as f64;
    unit_cost(requires_playwright) * (60_000.0 / period)
}

/// Hardware profile `(logical_cores, ram_gib)`, probed once per process. Cores come from the
/// standard library; only the memory total needs `sysinfo`.
fn hardware() -> (usize, f64) {
    static HW: OnceLock<(usize, f64)> = OnceLock::new();
    *HW.get_or_init(|| {
        let cores = std::thread::available_parallelism().map(|n| n.get()).unwrap_or(4);
        let mut sys = sysinfo::System::new();
        sys.refresh_memory();
        let ram_gib = sys.total_memory() as f64 / 1_073_741_824.0; // bytes → GiB
        (cores, ram_gib)
    })
}

/// The auto (hardware-derived) budget for a given profile. Pure so tests can pin it.
pub fn auto_budget_units_per_min(cores: usize, ram_gib: f64) -> f64 {
    ((cores as f64) * 6.0).min(ram_gib * 4.0).clamp(AUTO_MIN_UNITS, AUTO_MAX_UNITS)
}

/// The effective budget: the installed override when non-zero, else the auto value.
pub fn budget_units_per_min() -> f64 {
    let ovr = OVERRIDE_UNITS_PER_MIN.load(Ordering::Relaxed);
    if ovr > 0 {
        return ovr as f64;
    }
    let (cores, ram_gib) = hardware();
    auto_budget_units_per_min(cores, ram_gib)
}

/// Sum the budget load of every ENABLED monitor.
pub async fn used_units_per_min(db: &sqlx::SqlitePool) -> LocalResult<f64> {
    let rows = targets::list_enabled(db, SCAN_LIMIT).await?;
    Ok(rows
        .iter()
        .map(|t| units_per_min(t.check_period_ms, t.requires_playwright != 0))
        .sum())
}

/// What the FE's capacity meter reads (`GET /v1/monitors/capacity`).
#[derive(Debug, Serialize)]
pub struct CapacitySnapshot {
    pub budget_units_per_min: f64,
    pub used_units_per_min: f64,
    pub cores: usize,
    pub ram_gib: f64,
    /// Non-zero when `[monitors].max_check_units_per_min` overrides the auto budget.
    pub override_units_per_min: u64,
}

pub async fn snapshot(db: &sqlx::SqlitePool) -> LocalResult<CapacitySnapshot> {
    let (cores, ram_gib) = hardware();
    Ok(CapacitySnapshot {
        budget_units_per_min: budget_units_per_min(),
        used_units_per_min: used_units_per_min(db).await?,
        cores,
        ram_gib: (ram_gib * 10.0).round() / 10.0,
        override_units_per_min: OVERRIDE_UNITS_PER_MIN.load(Ordering::Relaxed),
    })
}

/// SAVE-time gate: refuse a monitor create/update whose PROSPECTIVE aggregate load exceeds the
/// device budget. `existing` is the pre-patch row for updates (`None` on create); the `new_*`
/// values are the POST-clamp effective state being written.
///
/// Never blocks a reduction: if the change does not increase this monitor's own load, it passes
/// even when the aggregate is already over budget (so over-budget states are always escapable).
pub async fn ensure_capacity_for_change(
    db: &sqlx::SqlitePool,
    existing: Option<&Target>,
    new_period_ms: i64,
    new_requires_playwright: bool,
    new_enabled: bool,
) -> LocalResult<()> {
    let old_units = existing
        .filter(|t| t.enabled != 0)
        .map(|t| units_per_min(t.check_period_ms, t.requires_playwright != 0))
        .unwrap_or(0.0);
    let new_units = if new_enabled {
        units_per_min(Some(new_period_ms), new_requires_playwright)
    } else {
        0.0
    };
    if new_units <= old_units {
        return Ok(()); // reduction / no-op — always allowed
    }
    let used = used_units_per_min(db).await?;
    let budget = budget_units_per_min();
    let would_use = used - old_units + new_units;
    if would_use > budget {
        return Err(LocalError::DeviceCapacity { would_use, budget });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unit_costs_mirror_cloud_weighting() {
        assert_eq!(unit_cost(false), 1.0);
        assert_eq!(unit_cost(true), JS_UNIT_COST);
    }

    /// At the anti-detection floors every monitor costs exactly 1 unit/min, so the budget reads
    /// as "monitors at floor cadence".
    #[test]
    fn floor_cadence_costs_one_unit() {
        assert!((units_per_min(Some(60_000), false) - 1.0).abs() < 1e-9);
        assert!((units_per_min(Some(300_000), true) - 1.0).abs() < 1e-9);
        // Slower than floor scales down linearly…
        assert!((units_per_min(Some(120_000), false) - 0.5).abs() < 1e-9);
        // …and a sub-floor / unset period is costed AT the floor (what it would really run at).
        assert!((units_per_min(Some(1_000), false) - 1.0).abs() < 1e-9);
        assert!((units_per_min(None, true) - 1.0).abs() < 1e-9);
    }

    #[test]
    fn auto_budget_is_conservative_and_clamped() {
        // Low-end laptop: 2 cores / 4 GiB → cpu term 12, ram term 16 → 12 (the floor).
        assert_eq!(auto_budget_units_per_min(2, 4.0), 12.0);
        // Mid: 8 cores / 8 GiB → min(48, 32) = 32 — RAM is the browser-context bottleneck.
        assert_eq!(auto_budget_units_per_min(8, 8.0), 32.0);
        // Big workstation: 32 cores / 128 GiB → min(192, 512) = 192, under the ceiling.
        assert_eq!(auto_budget_units_per_min(32, 128.0), 192.0);
        // Absurd hardware still hits the sequential-runner ceiling.
        assert_eq!(auto_budget_units_per_min(128, 1024.0), AUTO_MAX_UNITS);
    }

    #[test]
    fn override_wins_when_installed() {
        // Serialize on the global (mirrors clamp.rs's test discipline).
        install_capacity_override(77);
        assert_eq!(budget_units_per_min(), 77.0);
        install_capacity_override(0); // back to auto for other tests
        assert!(budget_units_per_min() >= AUTO_MIN_UNITS);
    }
}
