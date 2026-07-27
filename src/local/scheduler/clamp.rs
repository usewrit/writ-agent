//! Interval safety clamps — the single source of truth for the anti-detection minimum cadences.
//!
//! These floors are NOT a paywall; they are a politeness/anti-detection guard so a user can't (by
//! typo or otherwise) hammer a target faster than is safe. The floors are applied in TWO places, and
//! this module is the one definition both call so they can never drift:
//!   * **SAVE** — when a monitor/workflow interval is written through the API, so the persisted value
//!     is already floored (the UI shows the effective cadence, not a lie).
//!   * **TICK** — when the scheduler computes the *effective* interval before advancing the schedule,
//!     so an interval written by some other path (import, direct DB edit, an older build) is still
//!     respected at run time.
//!
//! ## The three floors
//!   * **HTML / content (HTTP fast-path)** — [`HTML_FLOOR_MS`] (60s). A target whose check is a plain
//!     HTTP fetch + CSS extract.
//!   * **JS / Playwright (browser-path)** — [`JS_FLOOR_MS`] (300s). A target that `requires_playwright`
//!     (it drives a real browser context — much heavier + far more detectable, hence the higher floor).
//!   * **Workflow schedule** — [`WORKFLOW_FLOOR_MS`] (60s). A time-scheduled workflow's fixed interval.
//!
//! The floor SELECTION for a monitor is by `targets.requires_playwright` (the only schema signal for
//! "this check drives a browser"): playwright ⇒ the JS floor, otherwise the HTML floor.
//!
//! ## User-configured floors (Settings → Runtime)
//! The desktop "Daemon / Browser" settings let the user RAISE the two monitor floors (make checks
//! less frequent). Those values live in `[monitors]` and are installed into the process-global below
//! at boot (`app::lifecycle`) and live on every save (`/v1/settings/runtime`). The hard constants
//! ([`HTML_FLOOR_MS`]/[`JS_FLOOR_MS`]) remain the ABSOLUTE minimum: the effective floor is
//! `max(configured, constant)`, so a user can only slow checks down, never below the anti-detection
//! safe minimum — even if a bad value is installed. Reads are lock-free (this is the hot clamp path).

use std::sync::atomic::{AtomicU64, Ordering};

use crate::local::config::{HTML_FLOOR_MS, JS_FLOOR_MS, WORKFLOW_FLOOR_MS};

/// Process-global user-configured monitor cadence floors (ms). Initialized to the hard constants so an
/// uninstalled (e.g. unit-test) process behaves EXACTLY as before; [`install_monitor_floors`] raises
/// them from the user's `[monitors]` config. Stored already-floored to the constants, and read with a
/// second `max(constant)` guard, so the anti-detection minimum can never be undercut.
static HTML_FLOOR_CONFIGURED_MS: AtomicU64 = AtomicU64::new(HTML_FLOOR_MS);
static JS_FLOOR_CONFIGURED_MS: AtomicU64 = AtomicU64::new(JS_FLOOR_MS);

/// Install the user-configured monitor floors (from [`crate::local::config::LocalConfig`]). Each value
/// is stored floored to its hard anti-detection constant, so the stored value is always safe. Called
/// once at boot (`app::lifecycle`) and again on every `/v1/settings/runtime` save so a change takes
/// effect on the next scheduler tick WITHOUT a daemon restart.
pub fn install_monitor_floors(html_floor_ms: u64, js_floor_ms: u64) {
    HTML_FLOOR_CONFIGURED_MS.store(html_floor_ms.max(HTML_FLOOR_MS), Ordering::Relaxed);
    JS_FLOOR_CONFIGURED_MS.store(js_floor_ms.max(JS_FLOOR_MS), Ordering::Relaxed);
}

/// The currently-installed configured floors (ms), `(html, js)`. For observability + tests.
pub fn configured_monitor_floors() -> (u64, u64) {
    (
        HTML_FLOOR_CONFIGURED_MS.load(Ordering::Relaxed),
        JS_FLOOR_CONFIGURED_MS.load(Ordering::Relaxed),
    )
}

/// The minimum monitor-check interval (ms) for a target, selected by whether the check drives a
/// real browser. `requires_playwright == true` ⇒ the heavier JS floor; otherwise the HTTP-fast-path
/// HTML floor. Each is the user-configured floor clamped up to its hard anti-detection constant
/// ([`JS_FLOOR_MS`]/[`HTML_FLOOR_MS`]) so a check can only be slowed, never sped below the safe floor.
pub fn monitor_floor_ms(requires_playwright: bool) -> i64 {
    let (html, js) = configured_monitor_floors();
    if requires_playwright {
        js.max(JS_FLOOR_MS) as i64
    } else {
        html.max(HTML_FLOOR_MS) as i64
    }
}

/// Clamp a *monitor* interval up to its anti-detection floor. A `None`/non-positive requested value
/// means "unset" and yields the floor; any value below the floor is raised to it. The floor is
/// chosen by `requires_playwright` (see [`monitor_floor_ms`]).
pub fn clamp_monitor_interval_ms(requested_ms: Option<i64>, requires_playwright: bool) -> i64 {
    let floor = monitor_floor_ms(requires_playwright);
    match requested_ms {
        Some(ms) if ms > 0 => ms.max(floor),
        _ => floor,
    }
}

/// Clamp a *time-scheduled workflow* interval up to [`WORKFLOW_FLOOR_MS`] (60s). A `None`/non-positive
/// requested value yields the floor; anything below it is raised.
pub fn clamp_workflow_interval_ms(requested_ms: Option<i64>) -> i64 {
    let floor = WORKFLOW_FLOOR_MS as i64;
    match requested_ms {
        Some(ms) if ms > 0 => ms.max(floor),
        _ => floor,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The configured-floor global is process-wide; tests that read OR mutate it must serialize on
    /// this lock (and any mutator must reset to the constants before releasing) so they can't race.
    fn floor_lock() -> std::sync::MutexGuard<'static, ()> {
        static LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
        let g = LOCK.lock().unwrap_or_else(|e| e.into_inner());
        // Every guarded test starts from the pristine default (constants) regardless of what a prior
        // mutator left behind.
        install_monitor_floors(HTML_FLOOR_MS, JS_FLOOR_MS);
        g
    }

    #[test]
    fn monitor_floor_selects_by_playwright() {
        let _g = floor_lock();
        assert_eq!(monitor_floor_ms(false), HTML_FLOOR_MS as i64);
        assert_eq!(monitor_floor_ms(true), JS_FLOOR_MS as i64);
        // JS floor is the higher of the two (browser is heavier/more detectable).
        assert!(monitor_floor_ms(true) > monitor_floor_ms(false));
    }

    #[test]
    fn clamp_monitor_raises_below_floor_and_keeps_above() {
        let _g = floor_lock();
        // HTML path (60s floor).
        assert_eq!(clamp_monitor_interval_ms(Some(1_000), false), HTML_FLOOR_MS as i64);
        assert_eq!(clamp_monitor_interval_ms(Some(120_000), false), 120_000);
        assert_eq!(clamp_monitor_interval_ms(None, false), HTML_FLOOR_MS as i64);
        assert_eq!(clamp_monitor_interval_ms(Some(0), false), HTML_FLOOR_MS as i64);
        assert_eq!(clamp_monitor_interval_ms(Some(-5), false), HTML_FLOOR_MS as i64);

        // JS path (300s floor) — a value between the two floors is raised to the JS floor.
        assert_eq!(clamp_monitor_interval_ms(Some(120_000), true), JS_FLOOR_MS as i64);
        assert_eq!(clamp_monitor_interval_ms(Some(600_000), true), 600_000);
        assert_eq!(clamp_monitor_interval_ms(None, true), JS_FLOOR_MS as i64);
    }

    #[test]
    fn clamp_workflow_raises_below_floor() {
        // Workflow floor is a fixed constant (not user-configurable) — no global to guard.
        assert_eq!(clamp_workflow_interval_ms(Some(1_000)), WORKFLOW_FLOOR_MS as i64);
        assert_eq!(clamp_workflow_interval_ms(Some(3_600_000)), 3_600_000);
        assert_eq!(clamp_workflow_interval_ms(None), WORKFLOW_FLOOR_MS as i64);
        assert_eq!(clamp_workflow_interval_ms(Some(0)), WORKFLOW_FLOOR_MS as i64);
    }

    /// Installing a RAISED configured floor lifts the effective floor for BOTH the direct
    /// `monitor_floor_ms` and the `clamp_monitor_interval_ms` path — and a check requested between
    /// the constant and the configured floor is raised to the configured one.
    #[test]
    fn configured_floor_raises_effective_cadence() {
        let _g = floor_lock();
        // Raise HTML to 5min and JS to 10min.
        let html = 300_000_u64;
        let js = 600_000_u64;
        install_monitor_floors(html, js);
        assert_eq!(configured_monitor_floors(), (html, js));

        assert_eq!(monitor_floor_ms(false), html as i64, "html floor raised");
        assert_eq!(monitor_floor_ms(true), js as i64, "js floor raised");
        // A 2min HTML request now floors up to the configured 5min (it exceeded the 60s constant but
        // is below the user's floor).
        assert_eq!(clamp_monitor_interval_ms(Some(120_000), false), html as i64);
        // A value ABOVE the configured floor is kept.
        assert_eq!(clamp_monitor_interval_ms(Some(900_000), false), 900_000);
        // reset happens in floor_lock() on the next guarded test.
    }

    /// A configured value BELOW the hard constant can never undercut the anti-detection minimum —
    /// `install_monitor_floors` floors it up on store, and the read re-guards it.
    #[test]
    fn configured_floor_never_undercuts_the_hard_minimum() {
        let _g = floor_lock();
        install_monitor_floors(1, 1); // absurdly low
        let (html, js) = configured_monitor_floors();
        assert_eq!(html, HTML_FLOOR_MS, "sub-constant html floored up on store");
        assert_eq!(js, JS_FLOOR_MS, "sub-constant js floored up on store");
        assert_eq!(monitor_floor_ms(false), HTML_FLOOR_MS as i64);
        assert_eq!(monitor_floor_ms(true), JS_FLOOR_MS as i64);
    }
}
