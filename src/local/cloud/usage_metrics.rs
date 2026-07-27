//! Opt-in ANONYMIZED desktop usage metrics — the "how is the product actually used?" signal.
//!
//! This is the only product-analytics path in the desktop app, and it is **OFF by default**. It runs
//! only when BOTH hold:
//!
//!   1. the user opted in (`[app].telemetry_opt_in` in `~/.writ/config.toml`, flipped by
//!      Settings → General → "Diagnostics & telemetry" via `PUT /v1/settings/telemetry`), AND
//!   2. the desktop is LINKED to a Writ Cloud account (there is no unauthenticated ingest — an
//!      unlinked install has nowhere to send and never tries).
//!
//! ## What is sent — and what is structurally impossible to send
//!
//! Every field is a COUNT, a DURATION, a BOOLEAN, or a fixed enum. The collector runs pure aggregate
//! SQL (`COUNT`/`SUM`) over the local tables; it never selects a text column, so a URL, page title,
//! selector, workflow/persona/monitor name, extracted value, credential, file path, or IP CANNOT
//! reach the payload — not "is scrubbed from", but is never read in the first place. Read
//! [`collect`]'s query set to verify: the only strings in a report are the crate version and
//! `std::env::consts::{OS,ARCH}`.
//!
//! Identity is a locally-generated random UUID ([`INSTALL_ID_KEY`]), NOT the account id, machine id,
//! MAC, or hostname. It exists so the server can tell "one install reporting 30 days" apart from
//! "30 installs reporting once", and nothing else. Opting out DELETES it, so a later opt-in starts a
//! fresh, unlinkable identity. The server hashes it again before storage (see the backend's
//! `desktop_usage_reports` model) and discards the authenticated account entirely at persist time —
//! the row cannot be traced back to a tenant.
//!
//! ## Cadence
//!
//! Whole UTC days, reported once each. The loop wakes every [`TICK_MINUTES`] and reports any
//! COMPLETE day not yet acknowledged, up to [`MAX_BACKFILL_DAYS`] (so a laptop that was closed for a
//! week still contributes, but a machine idle for a year does not replay a year on wake). A day is
//! marked done only after the server accepts it, and the marker only moves FORWARD, so a failed POST
//! retries on the next tick rather than being lost — and a duplicate delivery is harmless because
//! the ingest upserts on (install, day).
//!
//! Best-effort by construction: every failure path logs at debug and backs off. Telemetry must never
//! slow, block, or fail anything the user asked for.

use std::time::Duration;

use chrono::{Datelike, NaiveDate, TimeZone, Utc};
use serde::{Deserialize, Serialize};
use sqlx::sqlite::SqlitePool;
use sqlx::Row;

use super::client::CloudClient;
use super::state::LinkState;
use crate::local::config::{self, Paths};
use crate::local::error::{LocalError, LocalResult};
use crate::local::store::config_kv;

/// Cloud ingest route (backend `routers/telemetry.py::desktop_usage`).
const INGEST_PATH: &str = "/api/telemetry/desktop-usage";

/// `config` kv key holding this install's random reporting id. Generated on first report, DELETED on
/// opt-out so a re-opt-in is a brand-new, unlinkable identity. Never derived from hardware, the
/// account, or anything else stable across a reset.
pub const INSTALL_ID_KEY: &str = "telemetry.install_id";
/// `config` kv key holding the last UTC day (`YYYY-MM-DD`) the server ACCEPTED. Advances only on a
/// successful POST, so a failure retries instead of silently skipping a day.
pub const LAST_PERIOD_KEY: &str = "telemetry.last_period";

/// How often the loop wakes to look for an unreported complete day.
const TICK_MINUTES: u64 = 30;
/// Ceiling on days replayed after a long offline stretch (also the first-run window).
const MAX_BACKFILL_DAYS: i64 = 7;
/// Wall-clock delay before the first tick, so telemetry never competes with boot work.
const STARTUP_DELAY_S: u64 = 120;

/// One whole-day anonymized report. Counts, durations, booleans and fixed enums ONLY — see the module
/// docs for why no free-text field can exist here.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UsageReport {
    /// Locally-generated random UUID (see [`INSTALL_ID_KEY`]). Re-hashed server-side before storage.
    pub install_id: String,
    /// The whole UTC day this report covers, `YYYY-MM-DD`.
    pub period_day: String,
    /// Crate version of the daemon that produced it (`CARGO_PKG_VERSION`).
    pub agent_version: String,
    /// `std::env::consts::OS` / `ARCH` — a fixed compile-time enum, not a probe of the user's machine.
    pub os: String,
    pub arch: String,

    // ── Run volume + outcome ────────────────────────────────────────────────────
    pub runs_total: i64,
    pub runs_succeeded: i64,
    pub runs_failed: i64,
    /// Summed `duration_ms` over completed runs in the window (engine time, not wall-clock uptime).
    pub run_ms_total: i64,
    // Runs by trigger — which entry points people actually use.
    pub runs_manual: i64,
    pub runs_scheduled: i64,
    pub runs_on_change: i64,
    pub runs_webhook: i64,
    pub runs_api: i64,

    // ── Library size (point-in-time totals, not per-day) ────────────────────────
    pub workflows_total: i64,
    pub workflows_scheduled: i64,
    pub monitors_total: i64,
    pub monitors_enabled: i64,
    pub personas_total: i64,
    pub automations_enabled: i64,

    // ── Activity in the window ──────────────────────────────────────────────────
    pub checks_total: i64,
    pub changes_total: i64,
    pub crawls_total: i64,
    pub automation_execs: i64,
    pub ai_repairs: i64,

    // ── Feature adoption (booleans, never a value) ──────────────────────────────
    pub feat_crawl: bool,
    pub feat_ai_repair: bool,
    pub feat_scheduler: bool,
    pub feat_api: bool,
    pub feat_personas: bool,
    pub feat_cloud_agent: bool,
    pub feat_network_exposed: bool,
    pub feat_headless: bool,
}

/// Run the reporter loop forever. Spawned once at daemon startup (cloud builds only).
///
/// Re-reads the opt-in from DISK on every tick rather than trusting the boot snapshot, so turning
/// telemetry off in Settings stops the very next tick — no daemon restart, no "one last report".
pub async fn run(db: SqlitePool) {
    tokio::time::sleep(Duration::from_secs(STARTUP_DELAY_S)).await;
    loop {
        if let Err(e) = tick(&db).await {
            tracing::debug!(error = %e, "usage-metrics tick failed; will retry");
        }
        tokio::time::sleep(Duration::from_secs(TICK_MINUTES * 60)).await;
    }
}

/// One pass: honor the opt-in, then report every complete unreported day.
async fn tick(db: &SqlitePool) -> LocalResult<()> {
    let paths = Paths::resolve()?;
    let cfg = config::load_config(&paths);

    if !cfg.telemetry_opt_in {
        // Opted out (or never in). Drop the install id so a later opt-in cannot be correlated with
        // anything reported before it. Cheap and idempotent — `delete` on a missing key is a no-op.
        let _ = config_kv::delete(db, INSTALL_ID_KEY).await;
        let _ = config_kv::delete(db, LAST_PERIOD_KEY).await;
        return Ok(());
    }

    // No account → no ingest. We never open an unauthenticated telemetry channel.
    let link = LinkState::load_or_default(db).await?;
    let Ok(mut client) = CloudClient::connect(Some(&link)) else {
        return Ok(());
    };

    let install_id = install_id(db).await?;
    let today = Utc::now().date_naive();
    for day in pending_days(db, today).await? {
        let report = collect(db, &cfg, &install_id, day).await?;
        // A non-2xx (throttled, ingest disabled, schema drift) leaves the marker where it is, so the
        // day is retried next tick. Never surfaced to the user.
        match client.post_json::<_, serde_json::Value>(INGEST_PATH, &report).await {
            Ok(_) => {
                config_kv::set(db, LAST_PERIOD_KEY, &day.to_string()).await?;
                tracing::debug!(day = %day, "desktop usage report accepted");
            }
            Err(e) => {
                tracing::debug!(error = %e, day = %day, "desktop usage report rejected; will retry");
                break; // keep days strictly in order; retry this one before moving on
            }
        }
    }
    Ok(())
}

/// Outcome of an on-demand report (`POST /v1/settings/telemetry/report`).
#[derive(Debug, Clone, Serialize)]
pub struct ReportOutcome {
    /// The EXACT payload that would be (or was) sent. Always present — the whole point of the
    /// dry run is that a user can read what leaves before deciding, rather than trusting a
    /// paragraph of copy about it.
    pub report: UsageReport,
    /// True only when the cloud accepted it. False for a dry run and for every failure.
    pub sent: bool,
    /// Why nothing was sent, when nothing was: `dry_run`, `opted_out`, `not_linked`, `rejected`.
    pub skipped_reason: Option<String>,
}

/// Build (and optionally send) a report for one day, on demand.
///
/// Exists because the loop reports on its own daily cadence, which makes the feature impossible to
/// verify or support: "is telemetry working, and what exactly did it send?" had no answer short of
/// waiting a day. `dry_run` answers the second half without sending anything.
///
/// `day` defaults to yesterday — the most recent COMPLETE day, the same window the loop uses. A
/// successful send advances the day marker exactly as the loop would, so an on-demand report and the
/// loop never double-report a day (and the ingest upserts anyway).
///
/// Honors the opt-in even for a dry run: a device that has not opted in does not get its usage
/// summarized, not even locally into an API response.
pub async fn report_now(
    db: &SqlitePool,
    day: Option<NaiveDate>,
    dry_run: bool,
) -> LocalResult<ReportOutcome> {
    let paths = Paths::resolve()?;
    let cfg = config::load_config(&paths);
    let day = match day.or_else(|| Utc::now().date_naive().pred_opt()) {
        Some(d) => d,
        None => return Err(LocalError::BadRequest("no complete day to report".into())),
    };

    if !cfg.telemetry_opt_in {
        return Err(LocalError::BadRequest(
            "telemetry is off; enable it first (PUT /v1/settings/telemetry)".into(),
        ));
    }

    let install_id = install_id(db).await?;
    let report = collect(db, &cfg, &install_id, day).await?;

    if dry_run {
        return Ok(ReportOutcome { report, sent: false, skipped_reason: Some("dry_run".into()) });
    }

    let link = LinkState::load_or_default(db).await?;
    let Ok(mut client) = CloudClient::connect(Some(&link)) else {
        return Ok(ReportOutcome { report, sent: false, skipped_reason: Some("not_linked".into()) });
    };
    match client.post_json::<_, serde_json::Value>(INGEST_PATH, &report).await {
        Ok(_) => {
            // Only advance the marker FORWARD — a manual re-send of an older day must not make the
            // loop skip the newer ones it still owes.
            let last = config_kv::get(db, LAST_PERIOD_KEY)
                .await?
                .and_then(|s| s.parse::<NaiveDate>().ok());
            if last.map_or(true, |l| day > l) {
                config_kv::set(db, LAST_PERIOD_KEY, &day.to_string()).await?;
            }
            Ok(ReportOutcome { report, sent: true, skipped_reason: None })
        }
        Err(e) => {
            tracing::debug!(error = %e, day = %day, "on-demand usage report rejected");
            Ok(ReportOutcome { report, sent: false, skipped_reason: Some("rejected".into()) })
        }
    }
}

/// This install's reporting id, generating (and persisting) a fresh random UUID on first use.
async fn install_id(db: &SqlitePool) -> LocalResult<String> {
    if let Some(existing) = config_kv::get(db, INSTALL_ID_KEY).await?.filter(|s| !s.is_empty()) {
        return Ok(existing);
    }
    let fresh = uuid::Uuid::new_v4().to_string();
    config_kv::set(db, INSTALL_ID_KEY, &fresh).await?;
    Ok(fresh)
}

/// The complete UTC days still owed, oldest first. Empty when everything through yesterday is
/// acknowledged. Never includes TODAY (a partial day would under-report and then be un-correctable,
/// since the ingest upserts one row per day).
async fn pending_days(db: &SqlitePool, today: NaiveDate) -> LocalResult<Vec<NaiveDate>> {
    let Some(yesterday) = today.pred_opt() else {
        return Ok(Vec::new());
    };
    let last = config_kv::get(db, LAST_PERIOD_KEY)
        .await?
        .and_then(|s| s.parse::<NaiveDate>().ok());
    let earliest = yesterday - chrono::Duration::days(MAX_BACKFILL_DAYS - 1);
    let mut cursor = match last {
        // Resume the day after the last acknowledged one, but never replay more than the cap.
        Some(d) => d.succ_opt().unwrap_or(yesterday).max(earliest),
        // First ever report: just yesterday. A fresh install has no history worth backfilling, and
        // starting narrow keeps the first payload honest about what this install actually did.
        None => yesterday,
    };
    let mut days = Vec::new();
    while cursor <= yesterday {
        days.push(cursor);
        let Some(next) = cursor.succ_opt() else { break };
        cursor = next;
    }
    Ok(days)
}

/// RFC3339 bounds of a whole UTC day, in the exact `strftime('%Y-%m-%dT%H:%M:%fZ')` shape the local
/// tables store their timestamps in — so a plain string comparison is a correct range scan.
fn day_bounds(day: NaiveDate) -> (String, String) {
    let start = Utc.with_ymd_and_hms(day.year(), day.month(), day.day(), 0, 0, 0).unwrap();
    let end = start + chrono::Duration::days(1);
    let fmt = |d: chrono::DateTime<Utc>| d.format("%Y-%m-%dT%H:%M:%S%.3fZ").to_string();
    (fmt(start), fmt(end))
}

/// Run one `SELECT COUNT(*) … WHERE <ts> >= ?1 AND <ts> < ?2` and return the count. The SQL is a
/// `&'static str` (never assembled from input) and the only binds are the day bounds, so this helper
/// cannot be pointed at a text column.
async fn windowed_count(
    db: &SqlitePool,
    sql: &'static str,
    from: &str,
    to: &str,
) -> LocalResult<i64> {
    let row = sqlx::query(sql).bind(from).bind(to).fetch_one(db).await?;
    Ok(row.get::<i64, _>(0))
}

/// Build the report for one whole UTC day.
///
/// PRIVACY-CRITICAL: every statement below selects only `COUNT(...)` / `SUM(...)` / a comparison on a
/// FIXED enum literal (`status`, `trigger_type`). No statement selects a user-authored text column,
/// so there is no path by which a URL, name, selector, or extracted value could enter the payload.
/// Keep it that way — a new counter must be expressible as an aggregate, or it does not belong here.
pub async fn collect(
    db: &SqlitePool,
    cfg: &config::LocalConfig,
    install_id: &str,
    day: NaiveDate,
) -> LocalResult<UsageReport> {
    let (from, to) = day_bounds(day);

    // One pass over the day's runs: total, outcome split, engine time, and the trigger histogram.
    let r = sqlx::query(
        r#"
        SELECT
            COUNT(*)                                                        AS total,
            COALESCE(SUM(status = 'success'), 0)                            AS succeeded,
            COALESCE(SUM(status IN ('failed','timeout','interrupted')), 0)   AS failed,
            COALESCE(SUM(duration_ms), 0)                                    AS ms_total,
            COALESCE(SUM(trigger_type = 'manual'), 0)                        AS t_manual,
            COALESCE(SUM(trigger_type = 'scheduled'), 0)                     AS t_scheduled,
            COALESCE(SUM(trigger_type = 'on_change'), 0)                     AS t_on_change,
            COALESCE(SUM(trigger_type = 'webhook'), 0)                       AS t_webhook,
            COALESCE(SUM(trigger_type = 'api'), 0)                           AS t_api
        FROM runs WHERE created_at >= ?1 AND created_at < ?2
        "#,
    )
    .bind(&from)
    .bind(&to)
    .fetch_one(db)
    .await?;

    let checks_total = windowed_count(db, "SELECT COUNT(*) FROM uptime_checks WHERE checked_at >= ?1 AND checked_at < ?2", &from, &to).await?;
    let changes_total = windowed_count(db, "SELECT COUNT(*) FROM changes WHERE first_detected_at >= ?1 AND first_detected_at < ?2", &from, &to).await?;
    let automation_execs = windowed_count(db, "SELECT COUNT(*) FROM automation_executions WHERE triggered_at >= ?1 AND triggered_at < ?2", &from, &to).await?;
    let ai_repairs = windowed_count(db, "SELECT COUNT(*) FROM workflow_repair_history WHERE repaired_at >= ?1 AND repaired_at < ?2", &from, &to).await?;
    // `crawl_jobs` arrived in migration 0018; an older DB mid-upgrade simply reports 0 rather than
    // failing the whole report.
    let crawls_total = windowed_count(db, "SELECT COUNT(*) FROM crawl_jobs WHERE created_at >= ?1 AND created_at < ?2", &from, &to)
        .await
        .unwrap_or(0);

    let totals = sqlx::query(
        r#"
        SELECT
            (SELECT COUNT(*) FROM workflows WHERE is_active = 1)                          AS wf_total,
            (SELECT COUNT(*) FROM workflows WHERE is_active = 1 AND schedule_enabled = 1) AS wf_sched,
            (SELECT COUNT(*) FROM targets)                                                AS mon_total,
            (SELECT COUNT(*) FROM targets WHERE enabled = 1)                              AS mon_enabled,
            (SELECT COUNT(*) FROM personas WHERE is_active = 1)                           AS personas,
            (SELECT COUNT(*) FROM automations WHERE enabled = 1)                          AS autos,
            (SELECT COUNT(*) FROM workflows WHERE ai_repair_enabled = 1)                  AS ai_repair_on
        "#,
    )
    .fetch_one(db)
    .await?;

    let workflows_scheduled: i64 = totals.get("wf_sched");
    let runs_api: i64 = r.get("t_api");
    let personas_total: i64 = totals.get("personas");
    let ai_repair_on: i64 = totals.get("ai_repair_on");

    Ok(UsageReport {
        install_id: install_id.to_string(),
        period_day: day.to_string(),
        agent_version: env!("CARGO_PKG_VERSION").to_string(),
        os: std::env::consts::OS.to_string(),
        arch: std::env::consts::ARCH.to_string(),

        runs_total: r.get("total"),
        runs_succeeded: r.get("succeeded"),
        runs_failed: r.get("failed"),
        run_ms_total: r.get("ms_total"),
        runs_manual: r.get("t_manual"),
        runs_scheduled: r.get("t_scheduled"),
        runs_on_change: r.get("t_on_change"),
        runs_webhook: r.get("t_webhook"),
        runs_api,

        workflows_total: totals.get("wf_total"),
        workflows_scheduled,
        monitors_total: totals.get("mon_total"),
        monitors_enabled: totals.get("mon_enabled"),
        personas_total,
        automations_enabled: totals.get("autos"),

        checks_total,
        changes_total,
        crawls_total,
        automation_execs,
        ai_repairs,

        feat_crawl: crawls_total > 0,
        feat_ai_repair: ai_repair_on > 0 || ai_repairs > 0,
        feat_scheduler: workflows_scheduled > 0,
        feat_api: runs_api > 0,
        feat_personas: personas_total > 0,
        feat_cloud_agent: !cfg.cloud_agent_disabled,
        feat_network_exposed: cfg.network_exposed,
        feat_headless: cfg.browser_headless,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::local::{db, vault::Vault};

    /// A fresh migrated encrypted DB. `keep()` leaks the temp dir for the test's lifetime, which is
    /// what the other store tests in this crate do (the pool outlives a dropped `TempDir`).
    async fn pool() -> SqlitePool {
        let dir = tempfile::tempdir().unwrap().keep();
        let vault = Vault::load_or_create(&dir, false).unwrap();
        db::open(&dir.join("t.db"), &vault.db_key_hex()).await.unwrap()
    }

    #[test]
    fn day_bounds_are_a_whole_utc_day_in_the_stored_format() {
        let (from, to) = day_bounds(NaiveDate::from_ymd_opt(2026, 7, 26).unwrap());
        assert_eq!(from, "2026-07-26T00:00:00.000Z");
        assert_eq!(to, "2026-07-27T00:00:00.000Z");
        // Lexicographic ordering must match chronological ordering, or the range scan is wrong.
        assert!(from < to);
        assert!(from.as_str() < "2026-07-26T13:45:01.001Z");
        assert!("2026-07-26T23:59:59.999Z" < to.as_str());
    }

    #[tokio::test]
    async fn first_run_reports_only_yesterday() {
        let db = pool().await;
        let today = NaiveDate::from_ymd_opt(2026, 7, 27).unwrap();
        let days = pending_days(&db, today).await.unwrap();
        assert_eq!(days, vec![NaiveDate::from_ymd_opt(2026, 7, 26).unwrap()]);
    }

    #[tokio::test]
    async fn acknowledged_days_are_not_resent_and_gaps_backfill_to_the_cap() {
        let db = pool().await;
        let today = NaiveDate::from_ymd_opt(2026, 7, 27).unwrap();

        config_kv::set(&db, LAST_PERIOD_KEY, "2026-07-26").await.unwrap();
        assert!(pending_days(&db, today).await.unwrap().is_empty(), "yesterday already sent");

        config_kv::set(&db, LAST_PERIOD_KEY, "2026-07-23").await.unwrap();
        let days = pending_days(&db, today).await.unwrap();
        assert_eq!(days.len(), 3, "24th, 25th, 26th");
        assert_eq!(days[0], NaiveDate::from_ymd_opt(2026, 7, 24).unwrap());
        assert_eq!(days[2], NaiveDate::from_ymd_opt(2026, 7, 26).unwrap());

        // A machine offline for a year replays at most MAX_BACKFILL_DAYS, not a year.
        config_kv::set(&db, LAST_PERIOD_KEY, "2025-01-01").await.unwrap();
        let days = pending_days(&db, today).await.unwrap();
        assert_eq!(days.len(), MAX_BACKFILL_DAYS as usize);
        assert_eq!(days[days.len() - 1], NaiveDate::from_ymd_opt(2026, 7, 26).unwrap());
    }

    #[tokio::test]
    async fn install_id_is_stable_random_and_reset_on_opt_out() {
        let db = pool().await;
        let first = install_id(&db).await.unwrap();
        assert_eq!(first, install_id(&db).await.unwrap(), "stable across reports");
        assert!(uuid::Uuid::parse_str(&first).is_ok(), "a random UUID, not a machine id");

        // The opt-out path drops it, so re-opting-in yields an unlinkable new identity.
        config_kv::delete(&db, INSTALL_ID_KEY).await.unwrap();
        assert_ne!(first, install_id(&db).await.unwrap());
    }

    #[tokio::test]
    async fn collect_counts_the_window_and_carries_no_free_text() {
        let db = pool().await;
        let day = NaiveDate::from_ymd_opt(2026, 7, 26).unwrap();

        sqlx::query(
            "INSERT INTO workflows (id, name, entry_url, schedule_enabled) VALUES (1, 'secret name', 'https://private.example/path?token=abc', 1)",
        )
        .execute(&db)
        .await
        .unwrap();
        for (status, trigger, ms, created) in [
            ("success", "manual", 1_000, "2026-07-26T01:00:00.000Z"),
            ("failed", "scheduled", 500, "2026-07-26T23:59:59.999Z"),
            ("success", "api", 250, "2026-07-27T00:00:00.000Z"), // next day — excluded
            ("success", "manual", 250, "2026-07-25T23:59:59.999Z"), // previous day — excluded
        ] {
            sqlx::query(
                "INSERT INTO runs (workflow_id, status, trigger_type, duration_ms, created_at) VALUES (1, ?1, ?2, ?3, ?4)",
            )
            .bind(status).bind(trigger).bind(ms).bind(created)
            .execute(&db).await.unwrap();
        }

        let cfg = config::LocalConfig::default();
        let report = collect(&db, &cfg, "install-1", day).await.unwrap();

        assert_eq!(report.runs_total, 2, "only the two runs inside the UTC day");
        assert_eq!(report.runs_succeeded, 1);
        assert_eq!(report.runs_failed, 1);
        assert_eq!(report.run_ms_total, 1_500);
        assert_eq!(report.runs_manual, 1);
        assert_eq!(report.runs_scheduled, 1);
        assert_eq!(report.runs_api, 0, "the api run is on the next day");
        assert_eq!(report.workflows_total, 1);
        assert!(report.feat_scheduler, "the workflow has a schedule");
        assert!(!report.feat_api);
        assert_eq!(report.period_day, "2026-07-26");

        // The privacy guarantee, asserted rather than assumed: nothing the user authored is in the
        // serialized payload. The workflow's name and entry URL exist in the DB rows we just counted.
        let wire = serde_json::to_string(&report).unwrap();
        assert!(!wire.contains("secret name"));
        assert!(!wire.contains("private.example"));
        assert!(!wire.contains("token=abc"));
        assert!(!wire.contains("http"));
    }
}
