//! Process-wide resource governance (PROD-14).
//!
//! A single desktop daemon shares ONE warm Chromium across runs, recording, and streaming. Without a
//! ceiling, a burst of API/MCP calls plus a tick full of due monitors/scheduled workflows could fan
//! out an unbounded number of concurrent contexts and blow the machine's memory. The scheduler
//! already bounds ITS per-tick dispatch (`max_concurrent_dispatch`), but that is a *per-tick* knob on
//! one lane only — it does not bound the engine globally, and it does not know about interactive
//! API/MCP/streaming runs happening in parallel.
//!
//! The [`ResourceGovernor`] sits ABOVE both: every engine run — interactive or background — acquires
//! a governor permit by [`Lane`] before it launches a browser context, and the scheduler consults the
//! governor's memory watermark before doing heavy per-tick work. It enforces three things:
//!
//! 1. **A global concurrent-run ceiling** (a semaphore). Interactive runs (`Lane::Interactive` — the
//!    user/API/MCP/streaming surface) get PRIORITY: they may use the full ceiling and WAIT for a slot
//!    if the ceiling is momentarily saturated. Background runs (`Lane::Background` — scheduled /
//!    monitor) are admitted only up to a *lower* background sub-ceiling and are REJECTED (never
//!    queued) when that is hit, so background fan-out can never starve an interactive run of slots.
//!
//! 2. **A soft RSS watermark.** The governor samples the daemon process's resident memory (via
//!    `sysinfo`, already a crate dep) with a short cache. Once RSS crosses the soft watermark, the
//!    governor *sheds background work first*: new background runs are rejected and the scheduler skips
//!    its heavy per-tick lanes, while interactive runs are STILL admitted (the human is waiting). This
//!    is best-effort relief, not a hard cap — we never kill an in-flight run.
//!
//! 3. **Bounded backpressure.** The semaphore IS the bound: there is no unbounded queue. Interactive
//!    callers await a bounded number of permits; background callers `try_acquire` and get a prompt
//!    busy signal instead of piling up. Nothing here grows without limit.
//!
//! ## Secret hygiene
//! The governor holds only counters, a semaphore, and a cached memory sample — never credentials,
//! inputs, workflow contents, or any value payload. Nothing is logged with a secret.
//!
//! ## Why a sub-ceiling instead of preemption
//! The shared warm browser makes mid-flight preemption of a background run unsafe (a half-driven
//! context can leave a site in a bad state). Reserving headroom for interactive runs by capping
//! background concurrency BELOW the global ceiling gives interactive priority without ever aborting
//! an in-flight background run — a cooperative, non-preemptive scheme that fits the engine's model.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use tokio::sync::{OwnedSemaphorePermit, Semaphore};

use crate::local::config::LocalConfig;
use crate::local::engine::Lane;

/// Default global ceiling on concurrent engine runs (interactive + background combined). A desktop
/// shares ONE warm Chromium; a handful of parallel contexts is the practical ceiling before memory
/// and CDP contention dominate. Interactive runs may use all of these; background runs only the
/// sub-ceiling below.
pub const DEFAULT_MAX_CONCURRENT_RUNS: usize = 4;

/// Default background sub-ceiling: how many of the global slots background (scheduled/monitor) runs
/// may occupy at once. Kept BELOW [`DEFAULT_MAX_CONCURRENT_RUNS`] so there is always headroom an
/// interactive run can claim without waiting on background fan-out.
pub const DEFAULT_MAX_BACKGROUND_RUNS: usize = 2;

/// Default soft RSS watermark (bytes) above which the governor sheds background work. 0 = disabled
/// (no memory-based shedding). The default (1.5 GiB) is generous for a single-user desktop daemon +
/// one warm Chromium; operators on small boxes can lower it, and it is purely a *soft* relief valve
/// (interactive runs are never shed). Env/file configurable via [`LocalConfig`].
pub const DEFAULT_RSS_SOFT_WATERMARK_BYTES: u64 = 1_536 * 1024 * 1024;

/// How long a sampled RSS reading is reused before the governor re-samples. Reading process memory
/// via `sysinfo` is comparatively expensive and the watermark is a coarse relief valve, so a short
/// cache keeps the hot admit path cheap without meaningfully blunting responsiveness.
const RSS_SAMPLE_TTL: Duration = Duration::from_millis(750);

/// Why a run was refused admission by the governor. Carries no payload — purely the reason a caller
/// (the engine entry, the scheduler) maps into a "busy"/"deferred" outcome.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GovernorReject {
    /// The background sub-ceiling is saturated (the global ceiling may still have interactive-only
    /// headroom). Background runs only — interactive runs wait for a slot instead.
    BackgroundCeilingReached,
    /// Process RSS is over the soft watermark; background work is being shed to relieve memory.
    /// Interactive runs are never rejected for this reason.
    MemoryWatermark,
}

impl GovernorReject {
    /// A stable, secret-free reason string for logs / a "busy" error message.
    pub fn as_str(self) -> &'static str {
        match self {
            GovernorReject::BackgroundCeilingReached => "background concurrency ceiling reached",
            GovernorReject::MemoryWatermark => "memory watermark exceeded (shedding background work)",
        }
    }
}

/// Tunables for the [`ResourceGovernor`], folded from [`LocalConfig`] (or [`Default`] in tests). All
/// values are sanitized in [`ResourceGovernor::new`] so a nonsensical config can't wedge admission.
#[derive(Debug, Clone, Copy)]
pub struct GovernorConfig {
    /// Global ceiling on concurrent engine runs (interactive + background).
    pub max_concurrent_runs: usize,
    /// Sub-ceiling for background (scheduled/monitor) runs — kept below `max_concurrent_runs` so
    /// interactive runs always have reserved headroom.
    pub max_background_runs: usize,
    /// Soft RSS watermark in bytes; `0` disables memory-based shedding.
    pub rss_soft_watermark_bytes: u64,
}

impl Default for GovernorConfig {
    fn default() -> Self {
        Self {
            max_concurrent_runs: DEFAULT_MAX_CONCURRENT_RUNS,
            max_background_runs: DEFAULT_MAX_BACKGROUND_RUNS,
            rss_soft_watermark_bytes: DEFAULT_RSS_SOFT_WATERMARK_BYTES,
        }
    }
}

impl GovernorConfig {
    /// Derive the governor tunables from the runtime [`LocalConfig`]. The config carries the watermark
    /// in MEGABYTES (human-friendly on disk); convert to the governor's canonical BYTES here.
    pub fn from_local(c: &LocalConfig) -> Self {
        Self {
            max_concurrent_runs: c.max_concurrent_runs,
            max_background_runs: c.max_background_runs,
            rss_soft_watermark_bytes: c.rss_soft_watermark_mb.saturating_mul(1024 * 1024),
        }
    }

    /// Ceiling on concurrently-LIVE browser contexts this machine should host, derived from the run
    /// ceiling and applied to [`crate::browser::manager::BrowserManager::set_context_limit`].
    ///
    /// It is deliberately NOT equal to `max_concurrent_runs`. A run holds one context, but the same
    /// warm browser is also used by things the governor does not admit: recording sessions,
    /// coordinator-dispatched crawl shards' browser fallbacks, streaming/concierge sessions and
    /// monitor checks. Sizing the context pool exactly at the run ceiling would let those starve a
    /// governed run that already holds its permit — trading an unbounded leak for a stall. Doubling it
    /// (floor 4) leaves headroom for the non-run users while still bounding total live contexts to a
    /// number derived from the operator's configured concurrency instead of nothing at all.
    pub fn max_browser_contexts(self) -> usize {
        let c = self.sanitized();
        c.max_concurrent_runs.saturating_mul(2).max(4)
    }

    /// How many concurrent tasks a REMOTE dispatcher (a self-host coordinator) may schedule against
    /// this machine.
    ///
    /// This is the background sub-ceiling, not the global one, because every coordinator-dispatched
    /// unit of work runs on [`Lane::Background`] — and that lane REJECTS rather than queues. Before
    /// this existed the fleet worker advertised `min(cores, RAM/1.3)` (up to 50) while only
    /// `max_background_runs` (default 2) could actually be admitted, so a 16-core box accepted 16
    /// dispatches, ran 2, and failed 14 instantly with a cryptic "background ceiling reached". The
    /// number a dispatcher schedules against must be the number that can run.
    pub fn dispatchable_sessions(self) -> usize {
        self.sanitized().max_background_runs
    }

    /// Clamp into a safe shape: at least one global slot, a background sub-ceiling in `1..=global`
    /// (never above the global ceiling, never zero so background work isn't permanently starved). A
    /// `0` watermark is preserved (means "disabled").
    fn sanitized(mut self) -> Self {
        self.max_concurrent_runs = self.max_concurrent_runs.max(1);
        // Background may never exceed the global ceiling, and is at least 1.
        self.max_background_runs = self.max_background_runs.clamp(1, self.max_concurrent_runs);
        self
    }
}

/// A live admission grant. Holding it keeps one global slot (and, for a background run, one
/// background slot) occupied; dropping it releases both. Returned by [`ResourceGovernor::admit`].
///
/// The permit is intentionally opaque: the caller holds it for the lifetime of the run and lets it
/// drop when the run finalizes. It carries the `OwnedSemaphorePermit` for the global ceiling plus,
/// for background runs, a guard that decrements the background in-flight counter on drop.
pub struct RunPermit {
    _global: OwnedSemaphorePermit,
    /// Present only for background runs — decrements the background gauge on drop.
    _bg: Option<BackgroundGuard>,
}

impl std::fmt::Debug for RunPermit {
    /// Opaque — a permit is a held resource, not data. We never log its internals (no secret, but
    /// nothing useful either). This exists so `Result<RunPermit, _>::unwrap_err` works in tests.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RunPermit").field("background", &self._bg.is_some()).finish()
    }
}

/// RAII guard that decrements the background in-flight gauge when a background run's permit drops.
struct BackgroundGuard {
    gauge: std::sync::Arc<AtomicU64>,
}

impl Drop for BackgroundGuard {
    fn drop(&mut self) {
        // Saturating: never wrap below zero even under a logic bug.
        let prev = self.gauge.load(Ordering::SeqCst);
        if prev > 0 {
            self.gauge.fetch_sub(1, Ordering::SeqCst);
        }
    }
}

/// The process-wide resource governor. Cheap to clone the `Arc`; the daemon holds ONE and shares the
/// same `Arc` with the engine (for [`admit`](Self::admit)) and the scheduler (for
/// [`should_shed_background`](Self::should_shed_background)).
pub struct ResourceGovernor {
    cfg: GovernorConfig,
    /// The global ceiling. Interactive runs `acquire` (await) a permit; background runs `try_acquire`
    /// (non-blocking) so they reject instead of queueing.
    global: std::sync::Arc<Semaphore>,
    /// Background in-flight gauge — bounds background runs to `cfg.max_background_runs` WITHOUT a
    /// second semaphore (a second semaphore can't atomically pair with the global one). We reserve a
    /// global slot first, then check this gauge; if over the sub-ceiling we drop the global slot and
    /// reject. The gauge is decremented by the [`BackgroundGuard`] on permit drop.
    background_inflight: std::sync::Arc<AtomicU64>,
    /// Cached RSS sample + when it was taken, behind a `Mutex` so the cheap admit path can refresh it
    /// at most every [`RSS_SAMPLE_TTL`]. The `Mutex` is held only for the (fast) sample read/store.
    rss_cache: Mutex<RssCache>,
}

/// The cached memory sample. `taken` is `None` until the first sample.
struct RssCache {
    bytes: u64,
    taken: Option<Instant>,
}

impl ResourceGovernor {
    /// Build a governor from sanitized config.
    pub fn new(cfg: GovernorConfig) -> Self {
        let cfg = cfg.sanitized();
        tracing::info!(
            max_concurrent_runs = cfg.max_concurrent_runs,
            max_background_runs = cfg.max_background_runs,
            rss_soft_watermark_mb = cfg.rss_soft_watermark_bytes / (1024 * 1024),
            "resource governor active"
        );
        Self {
            global: std::sync::Arc::new(Semaphore::new(cfg.max_concurrent_runs)),
            background_inflight: std::sync::Arc::new(AtomicU64::new(0)),
            rss_cache: Mutex::new(RssCache { bytes: 0, taken: None }),
            cfg,
        }
    }

    /// Build a governor from the runtime [`LocalConfig`].
    pub fn from_config(c: &LocalConfig) -> Self {
        Self::new(GovernorConfig::from_local(c))
    }

    /// Try to admit a run on `lane`, returning a held [`RunPermit`] on success.
    ///
    /// * **Interactive** — awaits a global slot (bounded wait; the ceiling is small) and is NEVER
    ///   rejected for memory. The human/API caller is waiting, so we prioritize it over background
    ///   fan-out. It only fails if the semaphore was closed (process shutting down).
    /// * **Background** — fails FAST (never queues): rejected with [`GovernorReject::MemoryWatermark`]
    ///   when RSS is over the soft watermark, or [`GovernorReject::BackgroundCeilingReached`] when no
    ///   global slot is free OR the background sub-ceiling is already full.
    ///
    /// The returned permit must be held for the run's lifetime; dropping it frees the slot(s).
    pub async fn admit(&self, lane: Lane) -> Result<RunPermit, GovernorReject> {
        match lane {
            Lane::Interactive => {
                // Priority lane: wait for a global slot. `acquire_owned` errors only if the semaphore
                // is closed (we never close it in normal operation) — treat that as a ceiling reject.
                let permit = self
                    .global
                    .clone()
                    .acquire_owned()
                    .await
                    .map_err(|_| GovernorReject::BackgroundCeilingReached)?;
                Ok(RunPermit { _global: permit, _bg: None })
            }
            Lane::Background => self.admit_background(),
        }
    }

    /// Non-blocking background admission. Shed on the watermark first, then enforce BOTH the global
    /// ceiling (no free slot ⇒ interactive runs are using everything) and the background sub-ceiling.
    fn admit_background(&self) -> Result<RunPermit, GovernorReject> {
        // 1) Memory shed: refuse new background work when over the soft watermark.
        if self.should_shed_background() {
            return Err(GovernorReject::MemoryWatermark);
        }

        // 2) Reserve a global slot WITHOUT blocking. No permit ⇒ the global ceiling is full (e.g.
        //    interactive runs are using every slot) ⇒ reject this background run.
        let permit = self
            .global
            .clone()
            .try_acquire_owned()
            .map_err(|_| GovernorReject::BackgroundCeilingReached)?;

        // 3) Enforce the background sub-ceiling via the gauge. We hold a global slot already; if the
        //    background gauge is at its cap, DROP the global slot (permit) and reject so interactive
        //    headroom is preserved. The compare-and-increment is a CAS loop so two concurrent
        //    background admits can't both slip past the cap.
        loop {
            let cur = self.background_inflight.load(Ordering::SeqCst);
            if cur as usize >= self.cfg.max_background_runs {
                // At the sub-ceiling — release the global slot we just took and reject.
                drop(permit);
                return Err(GovernorReject::BackgroundCeilingReached);
            }
            if self
                .background_inflight
                .compare_exchange(cur, cur + 1, Ordering::SeqCst, Ordering::SeqCst)
                .is_ok()
            {
                break;
            }
            // Lost the race — retry with the fresh value.
        }

        Ok(RunPermit {
            _global: permit,
            _bg: Some(BackgroundGuard { gauge: self.background_inflight.clone() }),
        })
    }

    /// Should the scheduler skip its HEAVY per-tick lanes (scheduled-workflow dispatch + monitor
    /// checks that launch the engine) this tick? True when RSS is over the soft watermark — the same
    /// signal that sheds new background runs. The scheduler consults this before dispatching so it
    /// stops adding load while memory is high, then resumes automatically once RSS falls back.
    pub fn should_shed_background(&self) -> bool {
        let limit = self.cfg.rss_soft_watermark_bytes;
        if limit == 0 {
            // Memory-based shedding disabled.
            return false;
        }
        self.current_rss_bytes() > limit
    }

    /// Current count of in-flight background runs (the gauge). For health/observability + tests.
    pub fn background_inflight(&self) -> u64 {
        self.background_inflight.load(Ordering::SeqCst)
    }

    /// Number of global slots currently free (interactive headroom). For health/observability.
    pub fn available_slots(&self) -> usize {
        self.global.available_permits()
    }

    /// The configured tunables (after sanitization).
    pub fn config(&self) -> GovernorConfig {
        self.cfg
    }

    /// Current resident-memory sample in bytes (cached for [`RSS_SAMPLE_TTL`]). Surfaced by the
    /// settings/runtime status readout so the UI can show live footprint against the configured
    /// watermark. Returns `0` if a sample can't be taken (fail-open, same as the admit path).
    pub fn rss_sample_bytes(&self) -> u64 {
        self.current_rss_bytes()
    }

    /// Sample the daemon process's resident memory in bytes, reusing a reading for [`RSS_SAMPLE_TTL`]
    /// so the admit path stays cheap. Reads the CURRENT process only (never scans the whole system).
    /// A sampling failure yields `0` (treated as "under watermark" — fail OPEN so a transient
    /// `sysinfo` hiccup never wedges background work).
    fn current_rss_bytes(&self) -> u64 {
        let mut cache = match self.rss_cache.lock() {
            Ok(g) => g,
            // A poisoned mutex (a panic while holding it) must not wedge admission — fail open.
            Err(poisoned) => poisoned.into_inner(),
        };
        let fresh = cache
            .taken
            .map(|t| t.elapsed() < RSS_SAMPLE_TTL)
            .unwrap_or(false);
        if fresh {
            return cache.bytes;
        }
        let bytes = sample_process_rss_bytes();
        cache.bytes = bytes;
        cache.taken = Some(Instant::now());
        bytes
    }

    /// Test-only: force the cached RSS sample to a fixed value so the watermark logic can be exercised
    /// without depending on the real process footprint. The TTL keeps it pinned for the sample window.
    /// `pub(crate)` so cross-module tests (e.g. the scheduler shed-gating test) can drive it.
    #[cfg(test)]
    pub(crate) fn set_rss_for_test_pub(&self, bytes: u64) {
        let mut cache = self.rss_cache.lock().unwrap();
        cache.bytes = bytes;
        cache.taken = Some(Instant::now());
    }
}

/// Read THIS process's resident set size in bytes via `sysinfo` (already a crate dep; the same API
/// `lifecycle.rs` uses for the singleton-lock liveness check). Returns `0` on any failure so callers
/// fail OPEN (treat as under the watermark). Never logs a value.
fn sample_process_rss_bytes() -> u64 {
    let pid = sysinfo::Pid::from_u32(std::process::id());
    let mut sys = sysinfo::System::new();
    // Refresh ONLY our own process — cheap and scoped (no full-system scan).
    sys.refresh_process(pid);
    sys.process(pid).map(|p| p.memory()).unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn governor(global: usize, background: usize, watermark: u64) -> ResourceGovernor {
        ResourceGovernor::new(GovernorConfig {
            max_concurrent_runs: global,
            max_background_runs: background,
            rss_soft_watermark_bytes: watermark,
        })
    }

    /// Config sanitization clamps nonsense: zero global → 1, background clamped into `1..=global`.
    #[test]
    fn config_sanitized_clamps() {
        let c = GovernorConfig { max_concurrent_runs: 0, max_background_runs: 0, rss_soft_watermark_bytes: 0 }
            .sanitized();
        assert_eq!(c.max_concurrent_runs, 1, "zero global → at least one slot");
        assert_eq!(c.max_background_runs, 1, "zero background → at least one slot");

        let c2 = GovernorConfig { max_concurrent_runs: 3, max_background_runs: 99, rss_soft_watermark_bytes: 0 }
            .sanitized();
        assert_eq!(c2.max_background_runs, 3, "background can never exceed the global ceiling");

        // A zero watermark is preserved (means "disabled").
        let c3 = GovernorConfig { max_concurrent_runs: 4, max_background_runs: 2, rss_soft_watermark_bytes: 0 }
            .sanitized();
        assert_eq!(c3.rss_soft_watermark_bytes, 0);
    }

    /// Interactive runs may use the FULL global ceiling; once saturated, a further interactive admit
    /// blocks (does not reject) until a permit drops.
    #[tokio::test]
    async fn interactive_uses_full_ceiling_and_waits() {
        let gov = governor(2, 1, 0);
        let p1 = gov.admit(Lane::Interactive).await.expect("slot 1");
        let p2 = gov.admit(Lane::Interactive).await.expect("slot 2 (full ceiling)");
        assert_eq!(gov.available_slots(), 0, "both global slots taken");

        // A third interactive admit must WAIT, not reject. Prove it's pending, then release one.
        let fut = gov.admit(Lane::Interactive);
        tokio::pin!(fut);
        assert!(
            futures_util::poll!(&mut fut).is_pending(),
            "interactive admit waits when the ceiling is full (no reject)"
        );
        drop(p2);
        // Now it resolves.
        let p3 = tokio::time::timeout(std::time::Duration::from_secs(1), fut)
            .await
            .expect("admit resolves after a slot frees")
            .expect("interactive admit");
        drop(p1);
        drop(p3);
        assert_eq!(gov.available_slots(), 2, "all slots released");
    }

    /// Background runs are bounded by the SUB-ceiling and rejected (not queued) once it's reached,
    /// even when the global ceiling still has interactive-reserved headroom.
    #[tokio::test]
    async fn background_capped_by_subceiling_and_rejects() {
        // Global 4, background sub-ceiling 2, watermark disabled.
        let gov = governor(4, 2, 0);
        let b1 = gov.admit(Lane::Background).await.expect("bg slot 1");
        let b2 = gov.admit(Lane::Background).await.expect("bg slot 2");
        assert_eq!(gov.background_inflight(), 2);

        // A third BACKGROUND admit is rejected at the sub-ceiling, even though 2 global slots remain.
        let rej = gov.admit(Lane::Background).await.unwrap_err();
        assert_eq!(rej, GovernorReject::BackgroundCeilingReached);
        assert!(gov.available_slots() >= 2, "interactive headroom preserved while bg is capped");

        // Interactive can STILL claim the reserved headroom while background is at its cap.
        let i1 = gov.admit(Lane::Interactive).await.expect("interactive admits into reserved headroom");

        // Releasing a background permit frees a background slot → the next background admit succeeds.
        drop(b1);
        assert_eq!(gov.background_inflight(), 1);
        let b3 = gov.admit(Lane::Background).await.expect("bg slot frees up after a drop");

        drop(b2);
        drop(b3);
        drop(i1);
        assert_eq!(gov.background_inflight(), 0, "all background slots released");
    }

    /// Background runs are rejected when no global slot is free (interactive runs occupy them all),
    /// distinct from hitting the sub-ceiling.
    #[tokio::test]
    async fn background_rejected_when_global_full_of_interactive() {
        // Global 2, background sub-ceiling 2 (so the cap is the GLOBAL ceiling here, not the sub).
        let gov = governor(2, 2, 0);
        let i1 = gov.admit(Lane::Interactive).await.expect("i1");
        let i2 = gov.admit(Lane::Interactive).await.expect("i2");
        assert_eq!(gov.available_slots(), 0, "interactive runs hold every global slot");

        let rej = gov.admit(Lane::Background).await.unwrap_err();
        assert_eq!(rej, GovernorReject::BackgroundCeilingReached, "no global slot for background");
        assert_eq!(gov.background_inflight(), 0, "rejected background run took no background slot");

        drop(i1);
        drop(i2);
    }

    /// Over the soft RSS watermark, background work is SHED (admit rejected + scheduler shed signal),
    /// while interactive runs are STILL admitted.
    #[tokio::test]
    async fn watermark_sheds_background_but_not_interactive() {
        // 1 GiB watermark.
        let gov = governor(4, 2, 1024 * 1024 * 1024);

        // Under the watermark: background admits normally, scheduler does not shed.
        gov.set_rss_for_test_pub(256 * 1024 * 1024);
        assert!(!gov.should_shed_background(), "under watermark → no shed");
        let under = gov.admit(Lane::Background).await.expect("bg admits under watermark");
        drop(under);

        // Push RSS over the watermark.
        gov.set_rss_for_test_pub(2 * 1024 * 1024 * 1024);
        assert!(gov.should_shed_background(), "over watermark → scheduler sheds heavy ticks");

        // Background is now rejected with the memory reason.
        let rej = gov.admit(Lane::Background).await.unwrap_err();
        assert_eq!(rej, GovernorReject::MemoryWatermark);
        assert_eq!(gov.background_inflight(), 0, "shed background run claimed no slot");

        // Interactive is unaffected by the watermark — the human is waiting.
        let i1 = gov.admit(Lane::Interactive).await.expect("interactive admits despite high memory");
        drop(i1);
    }

    /// A zero watermark disables memory-based shedding entirely (background never shed for memory).
    #[tokio::test]
    async fn zero_watermark_disables_memory_shedding() {
        let gov = governor(4, 2, 0);
        gov.set_rss_for_test_pub(64 * 1024 * 1024 * 1024); // absurdly high
        assert!(!gov.should_shed_background(), "watermark=0 disables shedding");
        let b = gov.admit(Lane::Background).await.expect("background still admits with shedding off");
        drop(b);
    }

    /// The advertised dispatch capacity is the BACKGROUND sub-ceiling — the lane every
    /// coordinator-dispatched task actually runs on, and the only number that can be admitted.
    #[test]
    fn dispatchable_sessions_is_the_background_subceiling() {
        let c = GovernorConfig { max_concurrent_runs: 16, max_background_runs: 3, rss_soft_watermark_bytes: 0 };
        assert_eq!(c.dispatchable_sessions(), 3, "not the global ceiling, not the core count");

        // Sanitization applies: nonsense config still yields a schedulable number ≥ 1.
        let junk = GovernorConfig { max_concurrent_runs: 0, max_background_runs: 0, rss_soft_watermark_bytes: 0 };
        assert_eq!(junk.dispatchable_sessions(), 1);

        // A background sub-ceiling above the global one is clamped to the global one.
        let over = GovernorConfig { max_concurrent_runs: 2, max_background_runs: 99, rss_soft_watermark_bytes: 0 };
        assert_eq!(over.dispatchable_sessions(), 2);
    }

    /// The browser-context ceiling leaves headroom ABOVE the run ceiling for the non-run context
    /// users (recording / monitoring / streaming / concierge) that share the same warm browser, so a
    /// governed run holding a permit can never be starved of a context by them.
    #[test]
    fn max_browser_contexts_leaves_headroom_over_the_run_ceiling() {
        let c = GovernorConfig::default();
        assert!(
            c.max_browser_contexts() > c.max_concurrent_runs,
            "context pool must exceed the run ceiling, got {} vs {}",
            c.max_browser_contexts(),
            c.max_concurrent_runs
        );

        // Floor: even a 1-run machine gets a few contexts (recording + a monitor check + a run).
        let tiny = GovernorConfig { max_concurrent_runs: 1, max_background_runs: 1, rss_soft_watermark_bytes: 0 };
        assert_eq!(tiny.max_browser_contexts(), 4);

        // Scales with the configured concurrency rather than with raw CPU/RAM.
        let big = GovernorConfig { max_concurrent_runs: 12, max_background_runs: 6, rss_soft_watermark_bytes: 0 };
        assert_eq!(big.max_browser_contexts(), 24);

        // No overflow on an absurd config.
        let absurd = GovernorConfig {
            max_concurrent_runs: usize::MAX,
            max_background_runs: 1,
            rss_soft_watermark_bytes: 0,
        };
        assert_eq!(absurd.max_browser_contexts(), usize::MAX);
    }

    /// The reject reasons carry stable, secret-free strings.
    #[test]
    fn reject_reason_strings() {
        assert!(GovernorReject::BackgroundCeilingReached.as_str().contains("ceiling"));
        assert!(GovernorReject::MemoryWatermark.as_str().contains("memory"));
    }
}
