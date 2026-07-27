//! Shared daemon health snapshot — the single source the heartbeat writer (`agentd.json`) and the
//! `GET /v1/health` / enriched `GET /v1/agent` endpoints read.
//!
//! The scheduler updates the liveness fields once per tick (`last_tick_at`, `due_monitors`, and a
//! best-effort `warm_browser` hint); everything else (version, db/keyring/cipher reachability,
//! active runs, cloud-link reflection) is computed on demand by the readers. Cheaply cloneable (one
//! `Arc`); lock-free for the scalar counters, a tiny `RwLock<String>` for the timestamp.
//!
//! It also hosts the STORE-side health probes ([`db_reachable`], [`infra_failure_streak`]) used by
//! the self-host fleet worker's loopback `GET /healthz`. Those live here rather than in the binary so
//! they are unit-tested against a real encrypted pool, and so the desktop `/v1/health` route can
//! adopt the same signals later.
//!
//! NEVER carries any secret: no token, no key material, no extracted values, no `~/.writ` paths.

use std::sync::atomic::{AtomicBool, AtomicI64, Ordering};
use std::sync::{Arc, RwLock};
use std::time::Duration;

use sqlx::SqlitePool;

/// Liveness counters the scheduler publishes each tick and the health readers consume. Shared via
/// [`SharedHealth`]. All reads are cheap and non-blocking enough for a 5s heartbeat + a health route.
#[derive(Debug, Default)]
pub struct DaemonHealth {
    /// Monitors that were DUE on the most recent scheduler tick.
    due_monitors: AtomicI64,
    /// Best-effort hint that the warm Chromium has been launched at least once this session. Set by
    /// the scheduler when a tick drove a browser-path check; the API run lane warms it independently,
    /// which is reflected via the engine's `active_runs()` rather than here.
    warm_browser: AtomicBool,
    /// RFC3339 (ms, `Z`) timestamp of the last completed scheduler tick. Empty until the first tick.
    last_tick_at: RwLock<String>,
}

/// Shared, cheaply-clonable handle to the daemon health snapshot.
pub type SharedHealth = Arc<DaemonHealth>;

impl DaemonHealth {
    /// A fresh, never-ticked snapshot wrapped in an `Arc`.
    pub fn shared() -> SharedHealth {
        Arc::new(Self::default())
    }

    /// Record the result of one scheduler tick: how many monitors were due, whether the tick used
    /// the warm browser, and the tick's wall-clock time (RFC3339).
    pub fn record_tick(&self, due_monitors: i64, warmed_browser: bool, tick_at_rfc3339: &str) {
        self.due_monitors.store(due_monitors, Ordering::Relaxed);
        if warmed_browser {
            self.warm_browser.store(true, Ordering::Relaxed);
        }
        if let Ok(mut w) = self.last_tick_at.write() {
            *w = tick_at_rfc3339.to_string();
        }
    }

    /// Monitors that were due on the most recent tick (0 before the first tick).
    pub fn due_monitors(&self) -> i64 {
        self.due_monitors.load(Ordering::Relaxed)
    }

    /// Best-effort warm-browser hint (see field docs).
    pub fn warm_browser(&self) -> bool {
        self.warm_browser.load(Ordering::Relaxed)
    }

    /// RFC3339 timestamp of the last tick, or `None` if no tick has completed yet.
    pub fn last_tick_at(&self) -> Option<String> {
        self.last_tick_at
            .read()
            .ok()
            .map(|s| s.clone())
            .filter(|s| !s.is_empty())
    }
}

// -------------------------------------------------------------------------------------------------
// Store-side probes (fleet worker `/healthz`)
// -------------------------------------------------------------------------------------------------

/// Hard ceiling on the `SELECT 1` probe. A health endpoint polled every 30s must never be the thing
/// that blocks: if the pool cannot answer a trivial read in this long, the store IS the problem and
/// "unhealthy" is the correct answer.
pub const DB_PROBE_TIMEOUT: Duration = Duration::from_secs(2);

/// How many recent terminal runs [`infra_failure_streak`] inspects.
pub const INFRA_STREAK_WINDOW: u32 = 12;

/// Consecutive infrastructure-category run failures that mark the worker unhealthy.
///
/// Deliberately high. The remedy for an unhealthy worker is a supervisor restart, and a restart fixes
/// worker-shaped faults (a dead warm browser, an exhausted pool) but NOT author-shaped ones. The
/// category filter already excludes author faults (`creator` — a stale selector, a timeout on the
/// page), so this threshold only guards against the residual overlap: `infra` also covers
/// `Navigation failed`, which a target site being down would produce. Ten in a row without a single
/// success in between is worker-shaped in practice; one broken workflow is not.
pub const INFRA_STREAK_UNHEALTHY: u32 = 10;

/// A streak older than this is history, not a live fault — an idle worker whose last ten runs failed
/// yesterday is healthy today, and must not be restart-looped over it.
pub const INFRA_STREAK_RECENCY_S: i64 = 60 * 60;

/// `failure_category` values that mean "this MACHINE is broken" rather than "this workflow is broken".
///
/// Set by the engine: browser launch/context failure, navigation failure, and the timeout path (see
/// `engine::real::classify_step_error`). Author faults are `creator`, credential faults are `buyer`,
/// anti-bot is `captcha`, and a killed process leaves `interrupted` — none of which a restart fixes,
/// so none of them count here.
const INFRA_CATEGORY: &str = "infra";

/// Probe that the encrypted store still answers a trivial read, bounded by `timeout`.
///
/// Catches what "the process is alive" cannot: a pool whose connections are all wedged behind a
/// writer, a store that was quarantined out from under us, a `writ.db` on a filesystem that went
/// read-only or unresponsive. Without it a worker whose DB is unusable answers `200` on `/healthz`
/// while failing every single dispatched task with an opaque `db_error`.
pub async fn db_reachable(db: &SqlitePool, timeout: Duration) -> bool {
    matches!(
        tokio::time::timeout(timeout, sqlx::query("SELECT 1").fetch_optional(db)).await,
        Ok(Ok(_))
    )
}

/// Count how many of the MOST RECENT terminal runs failed consecutively with an infrastructure fault.
///
/// Walks the newest `window` terminal `runs` rows from newest to oldest and stops at the first row
/// that is not an `infra` failure — a success, or a failure of any other category. Returns `0` when
/// the newest such failure is older than `recency_s` seconds (see [`INFRA_STREAK_RECENCY_S`]).
///
/// Best-effort: a query failure returns `0` rather than an error, because [`db_reachable`] is the
/// probe that owns "the store is broken" and this one must not double-report it.
pub async fn infra_failure_streak(db: &SqlitePool, window: u32, recency_s: i64) -> u32 {
    let rows: Vec<(String, Option<String>, Option<String>)> = match sqlx::query_as(
        r#"
        SELECT status, failure_category, COALESCE(completed_at, created_at) AS at
        FROM runs
        WHERE status <> 'running'
        ORDER BY id DESC
        LIMIT ?1
        "#,
    )
    .bind(i64::from(window))
    .fetch_all(db)
    .await
    {
        Ok(rows) => rows,
        Err(e) => {
            tracing::debug!(error = %e, "health: recent-run query failed (streak reported as 0)");
            return 0;
        }
    };

    let mut streak = 0u32;
    for (_status, category, at) in &rows {
        if category.as_deref() != Some(INFRA_CATEGORY) {
            break;
        }
        // Gate on the FIRST (newest) row only: if the streak's freshest member is stale, the whole
        // streak is stale.
        if streak == 0 && !is_recent(at.as_deref(), recency_s) {
            return 0;
        }
        streak += 1;
    }
    streak
}

/// Is an RFC3339-ish timestamp within `recency_s` seconds of now? An absent/unparseable stamp counts
/// as NOT recent — an unreadable timestamp must never be what marks a worker unhealthy.
fn is_recent(at: Option<&str>, recency_s: i64) -> bool {
    let Some(at) = at else { return false };
    let Ok(parsed) = chrono::DateTime::parse_from_rfc3339(at) else {
        return false;
    };
    let age = chrono::Utc::now().signed_duration_since(parsed.with_timezone(&chrono::Utc));
    age.num_seconds() <= recency_s
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn pool() -> SqlitePool {
        let dir = Box::leak(Box::new(tempfile::tempdir().unwrap()));
        let v = crate::local::vault::Vault::load_or_create(dir.path(), false).unwrap();
        crate::local::db::open(&dir.path().join("t.db"), &v.db_key_hex())
            .await
            .unwrap()
    }

    /// Insert a run and drive it to a terminal state through the SAME store helpers the engine uses
    /// (so any FTS/JSON write trigger on `runs` is exercised exactly as in production), then force its
    /// `completed_at`/`created_at` to `at` so the recency gate can be tested.
    async fn seed_run(db: &SqlitePool, status: &str, category: Option<&str>, at: &str) {
        use crate::local::store::runs::{self, NewRun};
        let run = runs::insert(db, &NewRun::default()).await.unwrap();
        if status == "success" {
            runs::complete(db, run.id, Some(r#"{"ok":true}"#), Some(1)).await.unwrap();
        } else {
            runs::fail(db, run.id, status, Some("boom"), category, Some(1)).await.unwrap();
        }
        sqlx::query("UPDATE runs SET completed_at = ?2, created_at = ?2 WHERE id = ?1")
            .bind(run.id)
            .bind(at)
            .execute(db)
            .await
            .unwrap();
    }

    fn now_iso() -> String {
        chrono::Utc::now().to_rfc3339()
    }

    #[test]
    fn records_and_reads_tick() {
        let h = DaemonHealth::shared();
        assert_eq!(h.due_monitors(), 0);
        assert!(!h.warm_browser());
        assert_eq!(h.last_tick_at(), None);

        h.record_tick(3, false, "2026-06-29T00:00:01.000Z");
        assert_eq!(h.due_monitors(), 3);
        assert!(!h.warm_browser(), "browser not warmed yet");
        assert_eq!(h.last_tick_at().as_deref(), Some("2026-06-29T00:00:01.000Z"));

        h.record_tick(0, true, "2026-06-29T00:00:16.000Z");
        assert_eq!(h.due_monitors(), 0);
        assert!(h.warm_browser(), "warm flag latches true");
        assert_eq!(h.last_tick_at().as_deref(), Some("2026-06-29T00:00:16.000Z"));
    }

    /// A live pool is reachable; a CLOSED pool is not (the case a `/healthz` that only reports process
    /// liveness misses entirely).
    #[tokio::test]
    async fn db_probe_detects_an_unusable_pool() {
        let db = pool().await;
        assert!(db_reachable(&db, DB_PROBE_TIMEOUT).await, "a live pool answers SELECT 1");
        db.close().await;
        assert!(!db_reachable(&db, DB_PROBE_TIMEOUT).await, "a closed pool must fail the probe");
    }

    /// An empty history is a zero streak — a brand-new worker is healthy, not suspicious.
    #[tokio::test]
    async fn streak_is_zero_with_no_history() {
        let db = pool().await;
        assert_eq!(infra_failure_streak(&db, INFRA_STREAK_WINDOW, INFRA_STREAK_RECENCY_S).await, 0);
    }

    /// Consecutive infra failures accumulate, and a SUCCESS (or any other category) breaks the streak
    /// — that is what stops one broken user workflow from marking the worker unhealthy.
    #[tokio::test]
    async fn streak_counts_only_the_consecutive_recent_infra_failures() {
        let db = pool().await;
        let now = now_iso();

        // Oldest → newest: infra, infra, infra.
        for _ in 0..3 {
            seed_run(&db, "failed", Some("infra"), &now).await;
        }
        assert_eq!(
            infra_failure_streak(&db, INFRA_STREAK_WINDOW, INFRA_STREAK_RECENCY_S).await,
            3
        );

        // A newer SUCCESS resets it to zero.
        seed_run(&db, "success", None, &now).await;
        assert_eq!(
            infra_failure_streak(&db, INFRA_STREAK_WINDOW, INFRA_STREAK_RECENCY_S).await,
            0,
            "a success breaks the streak"
        );

        // Author-side failures ('creator' = a stale selector) never count: restarting the worker
        // cannot fix a broken workflow, so they must not trip the health check.
        for _ in 0..5 {
            seed_run(&db, "failed", Some("creator"), &now).await;
        }
        assert_eq!(
            infra_failure_streak(&db, INFRA_STREAK_WINDOW, INFRA_STREAK_RECENCY_S).await,
            0,
            "creator-category failures are the workflow's fault, not the worker's"
        );

        // Two fresh infra failures on top count again, and stop at the 'creator' row below them.
        seed_run(&db, "failed", Some("infra"), &now).await;
        seed_run(&db, "timeout", Some("infra"), &now).await;
        assert_eq!(
            infra_failure_streak(&db, INFRA_STREAK_WINDOW, INFRA_STREAK_RECENCY_S).await,
            2
        );
    }

    /// A streak whose newest member is old is history, not a live fault: an idle worker must not stay
    /// unhealthy (and restart-looping) forever over yesterday's failures.
    #[tokio::test]
    async fn stale_streak_is_ignored() {
        let db = pool().await;
        let long_ago = (chrono::Utc::now() - chrono::Duration::days(2)).to_rfc3339();
        for _ in 0..INFRA_STREAK_UNHEALTHY + 2 {
            seed_run(&db, "failed", Some("infra"), &long_ago).await;
        }
        assert_eq!(
            infra_failure_streak(&db, INFRA_STREAK_WINDOW, INFRA_STREAK_RECENCY_S).await,
            0,
            "a streak older than the recency window does not mark the worker unhealthy"
        );

        // But it becomes live again the moment a fresh infra failure lands on top.
        seed_run(&db, "failed", Some("infra"), &now_iso()).await;
        let streak = infra_failure_streak(&db, INFRA_STREAK_WINDOW, INFRA_STREAK_RECENCY_S).await;
        assert_eq!(streak, INFRA_STREAK_WINDOW, "the window bounds the count");
        assert!(streak >= INFRA_STREAK_UNHEALTHY, "and it does cross the unhealthy threshold");
    }

    /// The window BOUNDS the query: the streak can never exceed it, so `/healthz` stays O(window).
    #[tokio::test]
    async fn streak_is_bounded_by_the_window() {
        let db = pool().await;
        let now = now_iso();
        for _ in 0..40 {
            seed_run(&db, "failed", Some("infra"), &now).await;
        }
        assert_eq!(infra_failure_streak(&db, 5, INFRA_STREAK_RECENCY_S).await, 5);
    }

    /// `is_recent` fails CLOSED on a missing/garbage timestamp — an unparseable stamp must never be
    /// what marks a worker unhealthy.
    #[test]
    fn unparseable_timestamps_are_not_recent() {
        assert!(!is_recent(None, 3600));
        assert!(!is_recent(Some(""), 3600));
        assert!(!is_recent(Some("not-a-date"), 3600));
        assert!(is_recent(Some(&chrono::Utc::now().to_rfc3339()), 3600));
        // The store writes `%Y-%m-%dT%H:%M:%fZ`, which must parse as RFC3339.
        assert!(is_recent(
            Some(&chrono::Utc::now().format("%Y-%m-%dT%H:%M:%S%.3fZ").to_string()),
            3600
        ));
    }
}
