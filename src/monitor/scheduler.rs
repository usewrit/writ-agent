//! Scheduling for periodic target checks.
//!
//! 1:1 port of `desktop-agent/lib/scheduler.py`. The `TimeSlotScheduler` is the
//! one that matters for coordinated multi-agent checking: it derives every run
//! time from a shared `sync_epoch_ms` so jitter never accumulates into drift.

use std::time::{SystemTime, UNIX_EPOCH};

/// Wall-clock milliseconds since the Unix epoch.
///
/// We intentionally use wall-clock (not a monotonic `Instant`) because the
/// schedule is synchronized across agents against an absolute `sync_epoch_ms`
/// handed down by the coordinator.
pub fn now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

/// Smallest period the scheduler primitives will accept.
///
/// This is a **termination guarantee**, not a policy floor: it exists so that no wire-supplied
/// interval can produce a scheduler whose next-run computation fails to advance. The real
/// anti-detection policy floor is [`crate::monitor::grouping::MIN_CHECK_INTERVAL_MS`] (60 s) and is
/// applied by the target path; deliberately keeping this one small means clamping here cannot
/// silently slow down a legitimately fast workflow schedule.
pub const MIN_PERIOD_MS: i64 = 1_000;
/// Largest period we will honor (~365 days). Bounds the arithmetic and rejects absurd input.
pub const MAX_PERIOD_MS: i64 = 365 * 24 * 60 * 60 * 1_000;
/// Latest `sync_epoch_ms` we will accept (~year 2100). A wildly out-of-range epoch is a bug or an
/// attack, not a schedule.
pub const MAX_EPOCH_MS: i64 = 4_102_444_800_000;

/// Simple periodic scheduler with optional additive jitter.
///
/// Port of `scheduler.Scheduler`.
#[derive(Debug, Clone)]
pub struct Scheduler {
    pub period_ms: i64,
    pub jitter_ms: i64,
    pub last_run_ts: Option<i64>,
    pub next_run_ts: i64,
    /// Deterministic-ish jitter counter; we avoid `rand` to keep the port
    /// dependency-free and reproducible. Varies the jitter per tick.
    jitter_seed: u64,
}

impl Scheduler {
    pub fn new(period_ms: i64, jitter_ms: i64) -> Self {
        // Same clamp as `TimeSlotScheduler::new`. This scheduler has no drift-correction loop to
        // wedge, but a zero/negative period makes `should_run()` permanently true, which turns the
        // caller's "run when due" loop into a hot loop instead.
        let period_ms = period_ms.clamp(MIN_PERIOD_MS, MAX_PERIOD_MS);
        let jitter_ms = jitter_ms.clamp(0, MAX_PERIOD_MS);
        let mut s = Self {
            period_ms,
            jitter_ms,
            last_run_ts: None,
            next_run_ts: 0,
            jitter_seed: (now_ms() as u64) ^ 0x9E37_79B9_7F4A_7C15,
        };
        s.calculate_next_run();
        s
    }

    fn next_jitter(&mut self, max: i64) -> i64 {
        if max <= 0 {
            return 0;
        }
        // xorshift — small, no deps, good enough for anti-detection spread.
        let mut x = self.jitter_seed;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.jitter_seed = x;
        (x % (max as u64 + 1)) as i64
    }

    fn calculate_next_run(&mut self) {
        let now = now_ms();
        let mut next = now + self.period_ms;
        if self.jitter_ms > 0 {
            let j = self.next_jitter(self.jitter_ms);
            next += j;
        }
        self.next_run_ts = next;
    }

    pub fn should_run(&self) -> bool {
        now_ms() >= self.next_run_ts
    }

    pub fn mark_completed(&mut self) {
        self.last_run_ts = Some(now_ms());
        self.calculate_next_run();
    }

    pub fn update_period(&mut self, period_ms: i64) {
        self.period_ms = period_ms;
        self.calculate_next_run();
    }

    pub fn time_until_next_run_ms(&self) -> i64 {
        (self.next_run_ts - now_ms()).max(0)
    }
}

/// Adaptive scheduler that tightens the period when changes are seen and relaxes
/// it after several quiet checks. Port of `scheduler.AdaptiveScheduler`.
#[derive(Debug, Clone)]
pub struct AdaptiveScheduler {
    pub base: Scheduler,
    pub min_period_ms: i64,
    pub max_period_ms: i64,
    pub increase_factor: f64,
    pub decrease_factor: f64,
    pub change_count: u64,
    pub no_change_count: u64,
}

impl AdaptiveScheduler {
    pub fn new(initial_period_ms: i64, min_period_ms: i64, max_period_ms: i64) -> Self {
        Self {
            base: Scheduler::new(initial_period_ms, 0),
            min_period_ms,
            max_period_ms,
            increase_factor: 1.5,
            decrease_factor: 0.75,
            change_count: 0,
            no_change_count: 0,
        }
    }

    pub fn report_change_detected(&mut self) {
        self.change_count += 1;
        self.no_change_count = 0;
        let new_period =
            ((self.base.period_ms as f64 * self.decrease_factor) as i64).max(self.min_period_ms);
        if new_period != self.base.period_ms {
            self.base.update_period(new_period);
        }
    }

    pub fn report_no_change(&mut self) {
        self.no_change_count += 1;
        if self.no_change_count >= 5 {
            let new_period = ((self.base.period_ms as f64 * self.increase_factor) as i64)
                .min(self.max_period_ms);
            if new_period != self.base.period_ms {
                self.base.update_period(new_period);
                self.no_change_count = 0;
            }
        }
    }
}

/// Time-slot-aware scheduler for coordinated agent checking with anti-detection
/// jitter. Port of `scheduler.TimeSlotScheduler`.
///
/// Every run time is computed from `sync_epoch_ms` so that jitter applied on one
/// tick does not push subsequent ticks (no drift accumulation). Jitter is
/// clamped to ±80% of the period so a coordinator value can never shove a check
/// into a neighbouring period.
#[derive(Debug, Clone)]
pub struct TimeSlotScheduler {
    pub period_ms: i64,
    pub time_slot_offset_ms: i64,
    pub sync_epoch_ms: i64,
    pub jitter_percent: f64,
    pub last_run_ts: Option<i64>,
    pub next_run_ts: i64,
    jitter_seed: u64,
}

impl TimeSlotScheduler {
    /// Mirrors the Python constructor's three init paths.
    ///
    /// * `immediate_first_run` → first check fires now, then snaps to the slot.
    /// * else if `last_run_ts` is provided → rebuild without re-triggering.
    /// * else → compute the next aligned slot.
    pub fn new(
        period_ms: i64,
        time_slot_offset_ms: i64,
        sync_epoch_ms: Option<i64>,
        immediate_first_run: bool,
        jitter_percent: f64,
        last_run_ts: Option<i64>,
    ) -> Self {
        // FLOOR THE PERIOD AT CONSTRUCTION — do not remove.
        //
        // `period_ms` arrives from the coordinator over the wire. `workflow_scheduler` reads
        // `schedule_interval_ms` with `.unwrap_or(60_000)`, which only defaults when the field is
        // ABSENT — an explicit `0` (or a negative) passes straight through. A zero period makes
        // `calculate_next_run`'s drift-correction loop never advance, pinning a core at 100% forever
        // while holding the scheduler mutex. Clamping here means no constructor argument, from any
        // caller or any frame, can produce a non-advancing scheduler.
        //
        // The clamp is also the reason `calculate_next_run` can use plain arithmetic below: with
        // `period_ms >= MIN_PERIOD_MS` the loop always terminates.
        let period_ms = period_ms.clamp(MIN_PERIOD_MS, MAX_PERIOD_MS);
        // A hostile/garbled epoch or offset must not be able to overflow the arithmetic below
        // (release builds have `overflow-checks` off, so this would wrap silently rather than panic).
        let time_slot_offset_ms = time_slot_offset_ms.clamp(-MAX_PERIOD_MS, MAX_PERIOD_MS);
        let sync_epoch_ms = sync_epoch_ms.map(|e| e.clamp(0, MAX_EPOCH_MS));
        let mut s = Self {
            period_ms,
            time_slot_offset_ms,
            sync_epoch_ms: sync_epoch_ms.unwrap_or_else(now_ms),
            jitter_percent,
            last_run_ts,
            next_run_ts: 0,
            jitter_seed: (now_ms() as u64)
                ^ ((time_slot_offset_ms as u64).wrapping_mul(0x2545_F491_4F6C_DD1D))
                ^ 0x9E37_79B9_7F4A_7C15,
        };
        if immediate_first_run {
            s.next_run_ts = now_ms();
        } else {
            s.calculate_next_run(0);
        }
        s
    }

    fn next_signed_jitter(&mut self, range: i64) -> i64 {
        if range <= 0 {
            return 0;
        }
        let mut x = self.jitter_seed;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.jitter_seed = x;
        // map into [-range, range]
        let span = (range as u64) * 2 + 1;
        ((x % span) as i64) - range
    }

    /// Port of `_calculate_next_run`. `coordinator_jitter_ms != 0` overrides the
    /// random jitter (and is clamped to ±80% of the period).
    fn calculate_next_run(&mut self, coordinator_jitter_ms: i64) {
        let now_ms_v = now_ms();

        // DEFENCE IN DEPTH: `new()` clamps `period_ms` to `>= MIN_PERIOD_MS`, but a future setter or
        // a deserialized struct could bypass that. A non-positive period here would make the
        // drift-correction step below non-advancing, so refuse to schedule instead of spinning.
        if self.period_ms <= 0 {
            debug_assert!(false, "period_ms must be clamped by TimeSlotScheduler::new");
            tracing::error!(
                period_ms = self.period_ms,
                "scheduler: non-positive period — parking this entry instead of spinning"
            );
            self.next_run_ts = i64::MAX;
            return;
        }

        // Always derive from sync_epoch to prevent drift accumulation. All arithmetic is
        // saturating: `overflow-checks` is OFF in release, so an extreme (hostile or clock-skewed)
        // epoch/offset would otherwise wrap and produce a nonsense schedule rather than a clamped one.
        let time_since_epoch = now_ms_v.saturating_sub(self.sync_epoch_ms);
        let periods_elapsed = time_since_epoch.div_euclid(self.period_ms);

        let elapsed_span = periods_elapsed.saturating_mul(self.period_ms);
        let current_slot_time = self
            .sync_epoch_ms
            .saturating_add(elapsed_span)
            .saturating_add(self.time_slot_offset_ms);
        let next_slot_time = current_slot_time.saturating_add(self.period_ms);

        let mut base_next_run = if now_ms_v < current_slot_time {
            current_slot_time
        } else {
            next_slot_time
        };

        // Guarantee a future time even with stale epochs / drift.
        //
        // Computed, not iterated: the old `while base_next_run <= now { base_next_run += period }`
        // loop needed ~1.5e14 iterations for a far-past epoch with a 60 s period — tens of hours
        // pinned at 100% CPU inside the caller (which, for `assign_targets`, was the WS read loop).
        // One `div_euclid` gets the same answer in constant time.
        if base_next_run <= now_ms_v {
            let behind = now_ms_v.saturating_sub(base_next_run);
            let jumps = behind.div_euclid(self.period_ms).saturating_add(1);
            base_next_run =
                base_next_run.saturating_add(jumps.saturating_mul(self.period_ms));
        }

        let jitter_ms = if coordinator_jitter_ms != 0 {
            let max_safe = (self.period_ms as f64 * 0.8) as i64;
            coordinator_jitter_ms.clamp(-max_safe, max_safe)
        } else {
            // `jitter_percent` is a float that also crosses the wire; a NaN/huge value would make
            // `as i64` saturate to something absurd, so clamp the percentage itself first.
            let pct = if self.jitter_percent.is_finite() {
                self.jitter_percent.clamp(0.0, 100.0)
            } else {
                0.0
            };
            let range = (self.period_ms as f64 * (pct / 100.0)) as i64;
            self.next_signed_jitter(range)
        };

        let next_with_jitter = base_next_run.saturating_add(jitter_ms);
        self.next_run_ts = now_ms_v.max(next_with_jitter);
    }

    pub fn should_run(&self) -> bool {
        now_ms() >= self.next_run_ts
    }

    /// For `TimeSlotScheduler` the sync-aligned calculation corrects drift, so
    /// only anti-detection jitter is passed here (never a correction term).
    pub fn mark_completed(&mut self, coordinator_jitter_ms: i64) {
        self.last_run_ts = Some(now_ms());
        self.calculate_next_run(coordinator_jitter_ms);
    }

    pub fn update_period(&mut self, period_ms: i64) {
        self.period_ms = period_ms;
        self.calculate_next_run(0);
    }

    pub fn update_time_slot(&mut self, time_slot_offset_ms: i64) {
        self.time_slot_offset_ms = time_slot_offset_ms;
        self.calculate_next_run(0);
    }

    pub fn time_until_next_run_ms(&self) -> i64 {
        (self.next_run_ts - now_ms()).max(0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scheduler_schedules_into_future() {
        let s = Scheduler::new(10_000, 0);
        let remaining = s.time_until_next_run_ms();
        assert!(remaining > 9_000 && remaining <= 10_000, "got {remaining}");
        assert!(!s.should_run());
    }

    #[test]
    fn timeslot_aligns_to_slot_and_is_future() {
        // Epoch far in the past, 30s period, 5s offset.
        let epoch = now_ms() - 1_000_000;
        let mut s = TimeSlotScheduler::new(30_000, 5_000, Some(epoch), false, 0.0, None);
        assert!(s.next_run_ts > now_ms(), "next run must be in the future");

        // The aligned slot (no jitter) must satisfy (next - epoch - offset) % period == 0.
        let rel = (s.next_run_ts - epoch - 5_000).rem_euclid(30_000);
        assert_eq!(rel, 0, "next run must land exactly on the slot");

        // Completing should advance by roughly one period.
        let before = s.next_run_ts;
        s.mark_completed(0);
        assert!(s.next_run_ts >= before, "schedule should not go backwards");
    }

    #[test]
    fn coordinator_jitter_is_clamped() {
        let epoch = now_ms() - 1_000_000;
        let mut s = TimeSlotScheduler::new(10_000, 0, Some(epoch), false, 0.0, None);
        let base = {
            // recompute aligned base with no jitter for comparison
            let mut c = s.clone();
            c.calculate_next_run(0);
            c.next_run_ts
        };
        // Ask for absurd +60s jitter on a 10s period → clamp to +8s (80%).
        s.calculate_next_run(60_000);
        let applied = s.next_run_ts - base;
        assert!(applied <= 8_000, "jitter must be clamped to 80% of period, got {applied}");
    }

    #[test]
    fn immediate_first_run_fires_now() {
        let s = TimeSlotScheduler::new(30_000, 0, None, true, 0.0, None);
        assert!(s.should_run(), "immediate-first-run scheduler should be due");
    }

    #[test]
    fn adaptive_tightens_and_relaxes() {
        let mut a = AdaptiveScheduler::new(10_000, 1_000, 60_000);
        a.report_change_detected();
        assert_eq!(a.base.period_ms, 7_500);
        for _ in 0..5 {
            a.report_no_change();
        }
        assert!(a.base.period_ms > 7_500);
    }

    // ----------------------------------------------------------------------- //
    // Hostile-input regressions.                                              //
    //                                                                         //
    // These construct schedulers from values a coordinator can put on the wire.
    // Before the clamps, `period_ms = 0` made `calculate_next_run` loop forever
    // without advancing — pinning a core at 100% while holding the scheduler
    // mutex, on the WebSocket read-loop task, with `/healthz` still reporting
    // 200. Each assertion below simply RETURNING is the property under test:
    // an unclamped build hangs here instead of failing.
    // ----------------------------------------------------------------------- //

    #[test]
    fn zero_period_does_not_hang_and_is_floored() {
        let s = TimeSlotScheduler::new(0, 0, Some(now_ms()), false, 0.0, None);
        assert_eq!(s.period_ms, MIN_PERIOD_MS, "zero period must be floored");
        assert!(s.next_run_ts > 0, "must produce a concrete next run");
    }

    #[test]
    fn negative_period_does_not_hang_and_is_floored() {
        let s = TimeSlotScheduler::new(-5_000, 0, Some(now_ms()), false, 0.0, None);
        assert_eq!(s.period_ms, MIN_PERIOD_MS);
        assert!(s.next_run_ts >= now_ms());
    }

    #[test]
    fn far_past_epoch_is_computed_not_iterated() {
        // A 1970 epoch with a 60 s period is ~2.8e7 periods behind; the old `while … += period`
        // loop walked every one of them (and for i64::MIN-ish values, ~1.5e14 of them). This must
        // return promptly with a future run time.
        let s = TimeSlotScheduler::new(60_000, 0, Some(0), false, 0.0, None);
        assert!(s.next_run_ts >= now_ms(), "next run must be in the future");
        assert!(s.next_run_ts < now_ms() + 2 * 60_000, "and within one period of now");
    }

    #[test]
    fn extreme_wire_values_do_not_overflow_or_hang() {
        // `overflow-checks` is off in release, so unclamped arithmetic here would wrap silently.
        for (period, offset, epoch) in [
            (i64::MAX, i64::MAX, Some(i64::MAX)),
            (i64::MIN, i64::MIN, Some(i64::MIN)),
            (1, i64::MAX, Some(0)),
            (60_000, i64::MIN, Some(i64::MAX)),
        ] {
            let s = TimeSlotScheduler::new(period, offset, epoch, false, f64::NAN, None);
            assert!(s.period_ms >= MIN_PERIOD_MS && s.period_ms <= MAX_PERIOD_MS);
            assert!(s.next_run_ts >= 0, "next_run_ts must stay sane for {period}/{offset}");
        }
    }

    #[test]
    fn simple_scheduler_zero_period_is_not_immediately_due_forever() {
        // With period 0 this used to be permanently `should_run()`, turning the caller's
        // "run when due" loop into a hot loop.
        let s = Scheduler::new(0, 0);
        assert_eq!(s.period_ms, MIN_PERIOD_MS);
        assert!(!s.should_run(), "a freshly built scheduler must not be instantly due");
    }

    #[test]
    fn advance_from_far_past_stays_bounded_after_many_ticks() {
        // Repeated recomputation from a stale epoch must not drift or wedge.
        let mut s = TimeSlotScheduler::new(60_000, 0, Some(0), false, 0.0, None);
        for _ in 0..1_000 {
            s.calculate_next_run(0);
            assert!(s.next_run_ts >= now_ms());
        }
    }
}
