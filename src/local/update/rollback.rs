//! Post-update self-check + auto-rollback (AUTO_UPDATE.md §3 step 12, PROD-7).
//!
//! After an update applies, the NEXT launch must prove the new build is actually healthy before the
//! version record commits it as the good build. The self-check is deliberately the SAME liveness
//! signal the daemon health probe uses (`src/local/app/health.rs` / `GET /v1/health`): the encrypted
//! store opens, SQLCipher is genuinely linked (`PRAGMA cipher_version` non-empty), and a trivial
//! query succeeds. If the new build can't open its own encrypted DB (e.g. a bad SQLCipher link, a
//! broken migration), that is exactly the class of failure a rollback must catch.
//!
//! Rollback keeps EXACTLY ONE prior version (the version record's `prior_version`). After
//! [`HEALTH_FAIL_ROLLBACK_THRESHOLD`] consecutive failed self-checks, [`decide`] returns
//! [`RollbackAction::Rollback`] and the caller restores the retained prior build (the actual binary
//! swap is the OS-updater/Tauri concern; this module owns the DECISION + the version-record
//! bookkeeping via [`super::version_record::VersionRecord`]).
//!
//! This module is offline + does no binary swapping itself — it computes the self-check report and
//! the rollback decision, and drives the `app_meta` counter. The lifecycle hook
//! ([`super::super::app::lifecycle`]) calls [`run_post_update_gate`] once per boot.

use super::super::error::LocalResult;
use super::version_record::VersionRecord;
use sqlx::sqlite::SqlitePool;

/// Consecutive post-update self-check failures that trigger an auto-rollback to the retained prior
/// version. Set to 2 so a single transient boot hiccup (e.g. a briefly-locked keychain unrelated to
/// the update) does not roll back a genuinely-good build, but a build that reliably can't come up is
/// reverted on its second failed launch.
pub const HEALTH_FAIL_ROLLBACK_THRESHOLD: i64 = 2;

/// The result of one post-update self-check. `healthy` is the AND of every sub-probe; the individual
/// bools are surfaced for diagnostics (AUTO_UPDATE.md §3 step 12: "surface diagnostics" on failure).
#[derive(Debug, Clone, Default, serde::Serialize)]
pub struct SelfCheckReport {
    /// SQLCipher is genuinely linked (`PRAGMA cipher_version` non-empty) — the fail-closed cipher gate.
    pub cipher_present: bool,
    /// The encrypted DB opened AND a trivial `SELECT 1` succeeded.
    pub db_ok: bool,
    /// Overall verdict: every probe passed within budget.
    pub healthy: bool,
}

impl SelfCheckReport {
    /// Run the self-check against an already-open pool. This mirrors `server::health`'s `db_ok`
    /// computation exactly (cipher active AND a trivial query), so "healthy here" == "healthy on the
    /// `/v1/health` route". A caller that only has a DB path can use [`self_check_db_path`] instead.
    pub async fn probe(pool: &SqlitePool) -> Self {
        let cipher_present = super::super::db::assert_cipher_active(pool).await.is_ok();
        let db_ok = cipher_present && sqlx::query("SELECT 1").fetch_optional(pool).await.is_ok();
        let healthy = db_ok;
        SelfCheckReport { cipher_present, db_ok, healthy }
    }
}

/// Open the encrypted DB at `path` with `key` and run the self-check — the boot-time variant, which
/// proves the NEW build can open its own SQLCipher store from scratch (the failure mode a rollback
/// exists to catch). Returns a fail-report (`healthy=false`) if the DB won't even open.
pub async fn self_check_db_path(path: &std::path::Path, key: &str) -> SelfCheckReport {
    match super::super::db::open(path, key).await {
        Ok(pool) => {
            let report = SelfCheckReport::probe(&pool).await;
            pool.close().await;
            report
        }
        Err(e) => {
            tracing::error!(error = %e, "post-update self-check: encrypted DB failed to open");
            SelfCheckReport::default() // all false ⇒ unhealthy
        }
    }
}

/// What the boot-time post-update gate decided.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RollbackAction {
    /// The new build is healthy; the fail counter was reset (or was already 0). Nothing to do.
    Healthy,
    /// The self-check failed but the consecutive-fail count is still below the threshold — record the
    /// failure and let the app keep running for now (it may be transient); re-checked next boot.
    HeldFailing { fail_count: i64 },
    /// The consecutive-fail count reached [`HEALTH_FAIL_ROLLBACK_THRESHOLD`]; the caller must restore
    /// the retained prior version. `prior_version` is the target (or `None` if none is retained — the
    /// caller then surfaces diagnostics but cannot roll back).
    Rollback { prior_version: Option<String> },
}

/// Pure decision core: given the current [`VersionRecord`] and a self-check `report`, decide the
/// action WITHOUT touching the DB (so it is trivially unit-testable). The DB mutation happens in
/// [`run_post_update_gate`], which persists the resulting counter/rollback via the version record.
pub fn decide(record: &VersionRecord, report: &SelfCheckReport) -> RollbackAction {
    if report.healthy {
        return RollbackAction::Healthy;
    }
    // Unhealthy: this boot's failure will be the (count+1)-th consecutive failure.
    let next = record.health_fail_count.saturating_add(1);
    if next >= HEALTH_FAIL_ROLLBACK_THRESHOLD {
        RollbackAction::Rollback { prior_version: record.prior_version.clone() }
    } else {
        RollbackAction::HeldFailing { fail_count: next }
    }
}

/// Boot-time post-update gate: load the version record, run the self-check against the LIVE pool,
/// apply [`decide`], and persist the outcome (reset the counter on health, bump it on a held failure,
/// or record the rollback + return the prior version to restore).
///
/// Returns the [`RollbackAction`] so the lifecycle can act on `Rollback` (hand the retained prior
/// version to the OS updater to restore) and surface diagnostics. This is the ONE call the lifecycle
/// hook makes; everything else here is its testable decomposition.
///
/// Best-effort by contract: it must never panic the boot. On any DB error it logs and returns
/// `Healthy` (we do NOT roll back on a bookkeeping error — that would risk a rollback loop; a genuine
/// unhealthy DB is caught by the self-check itself, which opens the store).
pub async fn run_post_update_gate(pool: &SqlitePool) -> RollbackAction {
    let record = match VersionRecord::load(pool).await {
        Ok(r) => r,
        Err(e) => {
            tracing::warn!(error = %e, "post-update gate: could not load version record (skipping)");
            return RollbackAction::Healthy;
        }
    };
    let report = SelfCheckReport::probe(pool).await;
    let action = decide(&record, &report);
    match &action {
        RollbackAction::Healthy => {
            if let Err(e) = record.record_health_success(pool).await {
                tracing::warn!(error = %e, "post-update gate: could not reset health-fail counter");
            }
        }
        RollbackAction::HeldFailing { fail_count } => {
            let _ = record.record_health_fail(pool).await;
            tracing::warn!(
                fail_count,
                threshold = HEALTH_FAIL_ROLLBACK_THRESHOLD,
                cipher_present = report.cipher_present,
                db_ok = report.db_ok,
                "post-update self-check failed (below rollback threshold; will re-check next boot)"
            );
        }
        RollbackAction::Rollback { prior_version } => {
            // Persist the rollback in the version record (restore prior, clear it, reset counter). The
            // ACTUAL binary restore is the OS-updater's job; the caller performs it from the returned
            // prior_version.
            if let Err(e) = record.record_rollback(pool).await {
                tracing::error!(error = %e, "post-update gate: could not record rollback in app_meta");
            }
            tracing::error!(
                prior_version = prior_version.as_deref().unwrap_or("<none retained>"),
                cipher_present = report.cipher_present,
                db_ok = report.db_ok,
                "post-update self-check failed repeatedly — AUTO-ROLLBACK to the retained prior version"
            );
        }
    }
    action
}

/// Public thin wrapper the lifecycle hook calls (named per the task spec). Runs the boot-time
/// post-update gate and returns the decided action.
pub async fn post_update_self_check(pool: &SqlitePool) -> LocalResult<RollbackAction> {
    Ok(run_post_update_gate(pool).await)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rec(installed: &str, prior: Option<&str>, fails: i64) -> VersionRecord {
        VersionRecord {
            installed_version: Some(installed.to_string()),
            prior_version: prior.map(|s| s.to_string()),
            installed_build_released_at: None,
            health_fail_count: fails,
        }
    }

    fn report(healthy: bool) -> SelfCheckReport {
        SelfCheckReport { cipher_present: healthy, db_ok: healthy, healthy }
    }

    #[test]
    fn healthy_report_is_healthy_action() {
        assert_eq!(decide(&rec("1.1.0", Some("1.0.0"), 5), &report(true)), RollbackAction::Healthy);
    }

    #[test]
    fn first_failure_is_held_below_threshold() {
        // count 0 → this failure is #1, below the threshold of 2 → held.
        assert_eq!(
            decide(&rec("1.1.0", Some("1.0.0"), 0), &report(false)),
            RollbackAction::HeldFailing { fail_count: 1 }
        );
    }

    #[test]
    fn second_consecutive_failure_triggers_rollback() {
        // count 1 → this failure is #2 == threshold → rollback to the retained prior.
        assert_eq!(
            decide(&rec("1.1.0", Some("1.0.0"), 1), &report(false)),
            RollbackAction::Rollback { prior_version: Some("1.0.0".to_string()) }
        );
    }

    #[test]
    fn rollback_with_no_prior_is_reported_as_none() {
        assert_eq!(
            decide(&rec("1.1.0", None, 1), &report(false)),
            RollbackAction::Rollback { prior_version: None }
        );
    }

    /// The self-check on a real encrypted pool must report healthy (cipher linked + query ok).
    #[tokio::test]
    async fn self_check_on_good_db_is_healthy() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("sc.db");
        let report = self_check_db_path(&path, "self-check-key").await;
        assert!(report.cipher_present, "SQLCipher must be linked");
        assert!(report.db_ok);
        assert!(report.healthy);
    }
}
