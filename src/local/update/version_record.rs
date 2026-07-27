//! Version record — the monotonic installed/prior-version state in the SQLCipher DB (`app_meta`).
//!
//! This is the DOWNGRADE ANCHOR (AUTO_UPDATE.md §3 step 6): the update policy compares a candidate
//! manifest's `version` against `installed_version` read from HERE, not against whatever the manifest
//! claims. It is also the rollback source of truth (§3 step 12 / PROD-7): exactly ONE `prior_version`
//! is retained so a failed update can restore the last-good build, and a post-update health-fail
//! counter drives auto-rollback.
//!
//! State transitions (all through this module, so the invariants hold in one place):
//!   * [`VersionRecord::ensure_seeded`] — first boot stamps `installed_version` from the compiled-in
//!     `CARGO_PKG_VERSION` (and its `released_at` if the caller has one). Idempotent.
//!   * [`VersionRecord::record_successful_update`] — after a verified update APPLIES and passes its
//!     post-update self-check: move the current `installed_version` → `prior_version` (keep exactly
//!     one), set `installed_version` to the new version + its signed `released_at`, and RESET the
//!     health-fail counter. Monotonic: it refuses a non-greater version (defence in depth — the
//!     policy already gates this).
//!   * [`VersionRecord::record_health_success`] / [`record_health_fail`] — the post-update self-check
//!     bumps or clears the consecutive-fail counter (rollback.rs reads it to decide auto-rollback).
//!   * [`VersionRecord::record_rollback`] — after an auto-rollback restores `prior_version`: swap
//!     `installed_version` back to `prior_version`, clear `prior_version`, reset the counter.
//!
//! Runtime-checked sqlx only (no compile-time macros), mirroring the rest of `store`. No secrets.

use super::super::error::LocalResult;
use sqlx::sqlite::SqlitePool;
use sqlx::Row;

/// The single `app_meta` row (`id = 1`), holding the auto-update version state.
#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct VersionRecord {
    /// The version the running app was installed as (the downgrade anchor). `None` until seeded.
    pub installed_version: Option<String>,
    /// The single retained prior version (one-step rollback target). `None` until the first update.
    pub prior_version: Option<String>,
    /// RFC3339 UTC release timestamp of the installed build (the manifest's signed `released_at`).
    /// Replay/staleness anchor for AUTO_UPDATE.md §3 step 5. `None` until a manifest supplies one.
    pub installed_build_released_at: Option<String>,
    /// Consecutive post-update self-check failures since the last success. Auto-rollback fires at the
    /// configured ceiling (see `rollback::HEALTH_FAIL_ROLLBACK_THRESHOLD`).
    pub health_fail_count: i64,
}

impl VersionRecord {
    /// Load the singleton `app_meta` row. The migration seeds the row (`id=1`, NULL versions), so a
    /// well-formed DB always has it; a missing row (e.g. a hand-edited DB) yields a default record.
    pub async fn load(pool: &SqlitePool) -> LocalResult<Self> {
        let row = sqlx::query(
            "SELECT installed_version, prior_version, installed_build_released_at, health_fail_count \
             FROM app_meta WHERE id = 1",
        )
        .fetch_optional(pool)
        .await?;
        Ok(match row {
            Some(r) => VersionRecord {
                installed_version: r.try_get::<Option<String>, _>("installed_version").unwrap_or(None),
                prior_version: r.try_get::<Option<String>, _>("prior_version").unwrap_or(None),
                installed_build_released_at: r
                    .try_get::<Option<String>, _>("installed_build_released_at")
                    .unwrap_or(None),
                health_fail_count: r.try_get::<i64, _>("health_fail_count").unwrap_or(0),
            },
            None => VersionRecord::default(),
        })
    }

    /// Persist this record into the singleton row (`id=1`), upserting defensively so a DB missing the
    /// seed row still gets one. Stamps `updated_at`.
    async fn save(&self, pool: &SqlitePool) -> LocalResult<()> {
        sqlx::query(
            r#"
            INSERT INTO app_meta
                (id, installed_version, prior_version, installed_build_released_at, health_fail_count, updated_at)
            VALUES
                (1, ?1, ?2, ?3, ?4, strftime('%Y-%m-%dT%H:%M:%fZ','now'))
            ON CONFLICT(id) DO UPDATE SET
                installed_version = excluded.installed_version,
                prior_version = excluded.prior_version,
                installed_build_released_at = excluded.installed_build_released_at,
                health_fail_count = excluded.health_fail_count,
                updated_at = excluded.updated_at
            "#,
        )
        .bind(&self.installed_version)
        .bind(&self.prior_version)
        .bind(&self.installed_build_released_at)
        .bind(self.health_fail_count)
        .execute(pool)
        .await?;
        Ok(())
    }

    /// First-boot seed: if `installed_version` is unset, stamp it from the running build's version
    /// (`current_version`, typically `CARGO_PKG_VERSION`) plus an optional `released_at`. Idempotent —
    /// a second call with an already-seeded row is a no-op. Returns the (possibly updated) record.
    pub async fn ensure_seeded(
        pool: &SqlitePool,
        current_version: &str,
        released_at: Option<&str>,
    ) -> LocalResult<Self> {
        let mut rec = Self::load(pool).await?;
        if rec.installed_version.as_deref().unwrap_or("").is_empty() {
            rec.installed_version = Some(current_version.to_string());
            if rec.installed_build_released_at.is_none() {
                rec.installed_build_released_at = released_at.map(|s| s.to_string());
            }
            rec.save(pool).await?;
            tracing::info!(version = %current_version, "seeded installed_version in app_meta");
        }
        Ok(rec)
    }

    /// Commit a SUCCESSFUL update to `new_version` (post-apply, post-self-check): retain the current
    /// installed version as the single `prior_version`, advance `installed_version` + its
    /// `released_at`, and reset the health-fail counter. Monotonic guard (defence in depth): refuses a
    /// `new_version` that is not strictly greater than the current installed version.
    pub async fn record_successful_update(
        &self,
        pool: &SqlitePool,
        new_version: &str,
        new_released_at: Option<&str>,
    ) -> LocalResult<Self> {
        if let Some(cur) = self.installed_version.as_deref() {
            if let (Ok(a), Ok(b)) = (semver::Version::parse(new_version), semver::Version::parse(cur)) {
                if a <= b {
                    return Err(super::super::error::LocalError::BadRequest(format!(
                        "refusing to record update to {new_version}: not newer than installed {cur}"
                    )));
                }
            }
        }
        let next = VersionRecord {
            prior_version: self.installed_version.clone(),
            installed_version: Some(new_version.to_string()),
            installed_build_released_at: new_released_at
                .map(|s| s.to_string())
                .or_else(|| self.installed_build_released_at.clone()),
            health_fail_count: 0,
        };
        next.save(pool).await?;
        tracing::info!(
            from = self.installed_version.as_deref().unwrap_or("<none>"),
            to = %new_version,
            "recorded successful update in app_meta (prior retained for rollback)"
        );
        Ok(next)
    }

    /// Post-update self-check PASSED: reset the consecutive-fail counter to 0. No-op if already 0.
    pub async fn record_health_success(&self, pool: &SqlitePool) -> LocalResult<Self> {
        if self.health_fail_count == 0 {
            return Ok(self.clone());
        }
        let next = VersionRecord { health_fail_count: 0, ..self.clone() };
        next.save(pool).await?;
        Ok(next)
    }

    /// Post-update self-check FAILED: increment the consecutive-fail counter. Returns the updated
    /// record so the caller can compare against the rollback threshold.
    pub async fn record_health_fail(&self, pool: &SqlitePool) -> LocalResult<Self> {
        let next = VersionRecord {
            health_fail_count: self.health_fail_count.saturating_add(1),
            ..self.clone()
        };
        next.save(pool).await?;
        tracing::warn!(
            count = next.health_fail_count,
            version = self.installed_version.as_deref().unwrap_or("<none>"),
            "post-update self-check failed"
        );
        Ok(next)
    }

    /// Commit an auto-ROLLBACK: restore `prior_version` as the installed version, clear
    /// `prior_version` (nothing further back is retained), and reset the fail counter. No-op-safe if
    /// there is no prior version (returns `Ok` with the record unchanged, having only reset the
    /// counter) — the caller decides whether a rollback was actually possible.
    pub async fn record_rollback(&self, pool: &SqlitePool) -> LocalResult<Self> {
        let next = match self.prior_version.clone() {
            Some(prior) => VersionRecord {
                installed_version: Some(prior),
                prior_version: None,
                // We don't retain the prior build's release date across a rollback; clear it so a
                // subsequent replay check uses the (now-unknown) restored build's date conservatively.
                installed_build_released_at: None,
                health_fail_count: 0,
            },
            None => VersionRecord { health_fail_count: 0, ..self.clone() },
        };
        next.save(pool).await?;
        tracing::warn!(
            restored = next.installed_version.as_deref().unwrap_or("<none>"),
            "recorded auto-rollback to prior version in app_meta"
        );
        Ok(next)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn mem_pool() -> SqlitePool {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("vr.db");
        // Leak the tempdir so the file lives for the pool's lifetime in-test.
        std::mem::forget(dir);
        super::super::super::db::open(&path, "vr-test-key").await.unwrap()
    }

    #[tokio::test]
    async fn seed_is_idempotent_and_persists() {
        let pool = mem_pool().await;
        let r = VersionRecord::ensure_seeded(&pool, "1.0.0", Some("2026-01-01T00:00:00Z")).await.unwrap();
        assert_eq!(r.installed_version.as_deref(), Some("1.0.0"));

        // A second seed with a different version must NOT overwrite (already seeded).
        let r2 = VersionRecord::ensure_seeded(&pool, "9.9.9", None).await.unwrap();
        assert_eq!(r2.installed_version.as_deref(), Some("1.0.0"), "seed is idempotent");
        let loaded = VersionRecord::load(&pool).await.unwrap();
        assert_eq!(loaded.installed_version.as_deref(), Some("1.0.0"));
        assert_eq!(loaded.installed_build_released_at.as_deref(), Some("2026-01-01T00:00:00Z"));
        pool.close().await;
    }

    #[tokio::test]
    async fn successful_update_retains_exactly_one_prior() {
        let pool = mem_pool().await;
        let r = VersionRecord::ensure_seeded(&pool, "1.0.0", None).await.unwrap();
        let r = r.record_successful_update(&pool, "1.1.0", Some("2026-02-01T00:00:00Z")).await.unwrap();
        assert_eq!(r.installed_version.as_deref(), Some("1.1.0"));
        assert_eq!(r.prior_version.as_deref(), Some("1.0.0"));
        assert_eq!(r.health_fail_count, 0);

        // A second update rolls the prior forward — still exactly ONE prior retained.
        let r = r.record_successful_update(&pool, "1.2.0", None).await.unwrap();
        assert_eq!(r.installed_version.as_deref(), Some("1.2.0"));
        assert_eq!(r.prior_version.as_deref(), Some("1.1.0"), "keep exactly one prior");
        pool.close().await;
    }

    #[tokio::test]
    async fn successful_update_refuses_non_newer() {
        let pool = mem_pool().await;
        let r = VersionRecord::ensure_seeded(&pool, "2.0.0", None).await.unwrap();
        assert!(r.record_successful_update(&pool, "2.0.0", None).await.is_err(), "equal is not newer");
        assert!(r.record_successful_update(&pool, "1.5.0", None).await.is_err(), "older is not newer");
        pool.close().await;
    }

    #[tokio::test]
    async fn health_counter_and_rollback() {
        let pool = mem_pool().await;
        let r = VersionRecord::ensure_seeded(&pool, "1.0.0", None).await.unwrap();
        let r = r.record_successful_update(&pool, "1.1.0", None).await.unwrap();
        let r = r.record_health_fail(&pool).await.unwrap();
        let r = r.record_health_fail(&pool).await.unwrap();
        assert_eq!(r.health_fail_count, 2);
        let r = r.record_health_success(&pool).await.unwrap();
        assert_eq!(r.health_fail_count, 0, "success resets the counter");

        // Roll back: 1.1.0 → restore 1.0.0, clear prior.
        let r = r.record_rollback(&pool).await.unwrap();
        assert_eq!(r.installed_version.as_deref(), Some("1.0.0"));
        assert_eq!(r.prior_version, None);
        pool.close().await;
    }
}
