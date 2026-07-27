//! Config-driven data retention (PROD-18) — purge high-churn history older than `retention_days`.
//!
//! The desktop daemon accumulates run history, change history, uptime samples, and captured
//! workflow-output artifacts forever unless something reclaims them. [`purge_older_than`] deletes the
//! rows (and the on-disk encrypted blobs of expired workflow-output files) older than a cutoff, and
//! [`purge_with_config`] computes that cutoff from the live `retention_days` setting.
//!
//! What is purged (only the high-churn, regenerable history — never the user's *definitions*):
//!   * `runs` older than the cutoff (by `created_at`). `run_artifacts` cascade-delete with the run;
//!     `stored_files.source_run_id` is `ON DELETE SET NULL`, so workflow-output BLOBS are reclaimed
//!     explicitly here BEFORE the runs go (otherwise their bytes would be orphaned on disk).
//!   * `changes` older than the cutoff (`last_detected_at`) — delegated to `store::changes`.
//!   * `uptime_checks` older than the cutoff (`checked_at`) — delegated to `store::uptime_checks`.
//!
//!   * expired `logs/` text — aged-out `crash-*.json` records and `*.log`/`*.err`/`*.out` captures
//!     (see [`prune_expired_logs`]), plus an unconditional size cap on any single oversized log
//!     ([`cap_oversized_logs`]). Nothing else rotates these: the launchd/systemd/Docker unit points
//!     the process's stdout+stderr at plain files that the supervisor never truncates.
//!
//! What is NEVER purged by retention: workflows, targets, personas, vault_secrets, automations,
//! webhook_triggers, local_api_keys, config, and any non-workflow-output file (uploads/api). Those
//! are user-authored assets; only "delete all / reset" ([`crate::local::backup::reset`]) removes them.
//!
//! `retention_days == 0` means "keep everything" — every entry point becomes a no-op. The single
//! exception is [`cap_oversized_logs`], which is a disk-safety valve rather than a history window:
//! "keep all my history" must not mean "let one unrotated log file fill the volume".
//!
//! ## Who drives retention
//!   * the desktop daemon — Lane 4 of the scheduler tick (`scheduler::tick`, ~daily),
//!   * `POST /v1/data-admin` — an operator-triggered purge,
//!   * the self-host FLEET worker — [`spawn_maintenance`], because a fleet worker runs NEITHER a
//!     scheduler nor the local HTTP API. Without it a worker's SQLCipher DB grew monotonically with
//!     every dispatched run (rows + events + artifacts + extracted data) until the volume filled and
//!     every task started failing with an opaque `db_error`, with no operator lever to reclaim it.
//!
//! House style: module-local nothing (reuses `LocalError`); `tracing` only; NEVER logs secrets.
//! Net-new Rust behind the `local` feature.

use std::path::Path;
use std::time::{Duration as StdDuration, Instant};

use chrono::{DateTime, Duration, Utc};
use sqlx::SqlitePool;
use tokio::sync::watch;
use tokio::task::JoinHandle;

use crate::local::config::Paths;
use crate::local::error::LocalResult;
use crate::local::storage;
use crate::local::store::{ai_preview_steps, changes, stored_files, uptime_checks};

/// A single log file bigger than this is truncated (keeping its tail) by [`cap_oversized_logs`].
///
/// The supervisor-managed stdout/stderr capture is an append-only plain file that nothing rotates,
/// so a chatty `RUST_LOG=debug` deployment or a repeating error can grow it without bound on the
/// same volume that holds the encrypted DB — and a full volume fails every run.
const LOG_FILE_SIZE_CAP_BYTES: u64 = 32 * 1024 * 1024;

/// How much of an oversized log's TAIL is preserved when it is capped. The tail is the part an
/// operator actually debugs from; discarding the whole file would trade a disk problem for a
/// diagnosis problem.
const LOG_FILE_TAIL_KEEP_BYTES: u64 = 4 * 1024 * 1024;

/// Marker written at the head of a capped log so the gap is self-explanatory in the file itself.
const LOG_TRUNCATION_NOTICE: &[u8] =
    b"[writ retention] earlier lines were truncated to reclaim disk space\n";

/// Per-table tallies from one purge pass (all best-effort; a failure in one table is logged and the
/// others still run). Zeroed when retention is disabled.
#[derive(Debug, Clone, Default, serde::Serialize)]
pub struct PurgeReport {
    /// The RFC3339 cutoff instant used (rows strictly older than this were removed). `None` when
    /// retention is disabled (`retention_days == 0`).
    pub cutoff: Option<String>,
    pub runs_deleted: u64,
    pub changes_deleted: u64,
    pub uptime_checks_deleted: u64,
    /// "Watch the AI" replay keyframes (ai + concierge) removed past the window.
    pub preview_steps_deleted: u64,
    /// Workflow-output file handles whose row + on-disk blob were reclaimed.
    pub output_files_deleted: u64,
    /// Expired `logs/` files (crash records + stdout/stderr captures) removed past the window.
    pub log_files_deleted: u64,
    /// Bytes reclaimed under `logs/` — deleted expired files PLUS the head of any capped log.
    pub log_bytes_reclaimed: u64,
}

/// Scheduler-friendly entry point: resolve the home (`$WRIT_HOME`/`~/.writ`) and purge using
/// `retention_days`. A scheduler tick that only holds the `db` pool + the configured window can call
/// this directly (the tick does not thread `Paths`). `retention_days == 0` ⇒ a no-op report. Errors
/// resolving the home are surfaced; the caller should log-not-propagate so a bad tick can't wedge the
/// loop.
pub async fn purge_from_scheduler(db: &SqlitePool, retention_days: u32) -> LocalResult<PurgeReport> {
    if retention_days == 0 {
        return Ok(PurgeReport::default());
    }
    let paths = Paths::resolve()?;
    purge_with_config(db, &paths, retention_days).await
}

/// Purge using the daemon's configured retention window. `retention_days == 0` ⇒ a no-op report. The
/// cutoff is `now - retention_days`. `paths` is needed to delete the on-disk blobs of expired
/// workflow-output files.
pub async fn purge_with_config(
    db: &SqlitePool,
    paths: &Paths,
    retention_days: u32,
) -> LocalResult<PurgeReport> {
    if retention_days == 0 {
        return Ok(PurgeReport::default());
    }
    let cutoff = Utc::now() - Duration::days(retention_days as i64);
    let cutoff_rfc3339 = cutoff.format("%Y-%m-%dT%H:%M:%S%.3fZ").to_string();
    purge_older_than(db, paths, &cutoff_rfc3339).await
}

/// Purge every retention-managed table of rows older than `cutoff_rfc3339`. Best-effort per table:
/// a failure is logged and the remaining tables still run, so one bad table can't wedge the purge.
pub async fn purge_older_than(
    db: &SqlitePool,
    paths: &Paths,
    cutoff_rfc3339: &str,
) -> LocalResult<PurgeReport> {
    let mut report = PurgeReport { cutoff: Some(cutoff_rfc3339.to_string()), ..Default::default() };

    // 1. Workflow-output file blobs tied to runs older than the cutoff. Reclaim the bytes + row
    // FIRST, while the run rows still exist (the join keys off `source_run_id`). Best-effort: a
    // single file failing to delete is logged, never aborts the pass.
    match purge_expired_output_files(db, paths, cutoff_rfc3339).await {
        Ok(n) => report.output_files_deleted = n,
        Err(e) => tracing::warn!(error = %e, "retention: workflow-output file purge failed (continuing)"),
    }

    // 2. Old run rows (cascades run_artifacts). Direct DELETE on `created_at`.
    match purge_old_runs(db, cutoff_rfc3339).await {
        Ok(n) => report.runs_deleted = n,
        Err(e) => tracing::warn!(error = %e, "retention: runs purge failed (continuing)"),
    }

    // 3. Change history (delegated to the store helper, by `last_detected_at`).
    match changes::prune_older_than(db, cutoff_rfc3339).await {
        Ok(n) => report.changes_deleted = n,
        Err(e) => tracing::warn!(error = %e, "retention: changes purge failed (continuing)"),
    }

    // 4. Uptime samples (delegated to the store helper, by `checked_at`).
    match uptime_checks::prune_older_than(db, cutoff_rfc3339).await {
        Ok(n) => report.uptime_checks_deleted = n,
        Err(e) => tracing::warn!(error = %e, "retention: uptime_checks purge failed (continuing)"),
    }

    // 5. "Watch the AI" replay keyframes (ai + concierge), by `created_at`. A deleted session already
    // drops its own steps (via `delete_for`); this is the time-based backstop so heavy JPEGs don't
    // outlive the window even for sessions that are kept.
    match ai_preview_steps::prune_older_than(db, cutoff_rfc3339).await {
        Ok(n) => report.preview_steps_deleted = n,
        Err(e) => tracing::warn!(error = %e, "retention: ai_preview_steps purge failed (continuing)"),
    }

    // 6. `logs/` text older than the cutoff — crash records + the supervisor's stdout/stderr capture.
    // Nothing else reclaims these: the launchd plist / systemd unit / Docker log driver points the
    // process's stdout+stderr at plain files that the supervisor never rotates, and the panic hook
    // writes one `crash-<ts>.json` per panic. A cutoff parse failure only skips this step.
    match DateTime::parse_from_rfc3339(cutoff_rfc3339) {
        Ok(cutoff) => {
            let (files, bytes) = prune_expired_logs(paths, cutoff.with_timezone(&Utc));
            report.log_files_deleted = files;
            report.log_bytes_reclaimed = bytes;
        }
        Err(e) => tracing::warn!(error = %e, "retention: unparseable cutoff — skipping log pruning"),
    }

    // 7. Size-cap any single oversized log. Deliberately runs on the SAME pass rather than only from
    // the fleet maintenance loop, so the desktop daemon (whose only retention driver is the scheduler
    // tick) gets the disk-safety valve too.
    let (_capped, capped_bytes) = cap_oversized_logs(paths);
    report.log_bytes_reclaimed += capped_bytes;

    if report.runs_deleted
        + report.changes_deleted
        + report.uptime_checks_deleted
        + report.preview_steps_deleted
        + report.output_files_deleted
        + report.log_files_deleted
        + report.log_bytes_reclaimed
        > 0
    {
        tracing::info!(
            cutoff = %cutoff_rfc3339,
            runs = report.runs_deleted,
            changes = report.changes_deleted,
            uptime = report.uptime_checks_deleted,
            preview_steps = report.preview_steps_deleted,
            output_files = report.output_files_deleted,
            log_files = report.log_files_deleted,
            log_bytes = report.log_bytes_reclaimed,
            "retention purge completed"
        );
    }
    Ok(report)
}

/// Delete `runs` rows older than the cutoff (cascades `run_artifacts` via FK). Returns rows removed.
async fn purge_old_runs(db: &SqlitePool, cutoff_rfc3339: &str) -> LocalResult<u64> {
    let n = sqlx::query("DELETE FROM runs WHERE created_at < ?1")
        .bind(cutoff_rfc3339)
        .execute(db)
        .await?
        .rows_affected();
    Ok(n)
}

/// Reclaim workflow-output file handles whose owning run is older than the cutoff: remove the on-disk
/// encrypted blob, then hard-delete the `stored_files` row. Returns the count reclaimed.
///
/// Scoped to `source='workflow_output'` (run-captured artifacts) — uploads/api files are user assets
/// and are NEVER touched by retention. A file whose run was already pruned (source_run_id now NULL)
/// is left alone here; it gets reclaimed by the normal file-GC path, not retention.
async fn purge_expired_output_files(
    db: &SqlitePool,
    paths: &Paths,
    cutoff_rfc3339: &str,
) -> LocalResult<u64> {
    let rows: Vec<stored_files::StoredFile> = sqlx::query_as::<_, stored_files::StoredFile>(
        r#"
        SELECT sf.* FROM stored_files sf
        JOIN runs r ON r.id = sf.source_run_id
        WHERE sf.source = 'workflow_output'
          AND sf.deleted_at IS NULL
          AND r.created_at < ?1
        "#,
    )
    .bind(cutoff_rfc3339)
    .fetch_all(db)
    .await?;

    let mut removed = 0u64;
    for f in rows {
        // Remove the encrypted blob (best-effort: a missing file is fine — the row still goes).
        if let Ok(path) = storage::storage_path_for_key(paths, &f.source, &f.storage_key) {
            match std::fs::remove_file(&path) {
                Ok(()) => {}
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                Err(e) => tracing::warn!(file_id = %f.id, error = %e, "retention: could not remove output blob"),
            }
        }
        // Hard-delete the metadata row.
        if stored_files::delete(db, &f.id).await.unwrap_or(false) {
            removed += 1;
        }
    }
    Ok(removed)
}

// -------------------------------------------------------------------------------------------------
// `logs/` hygiene
// -------------------------------------------------------------------------------------------------

/// Is `name` a `logs/` file retention is allowed to touch?
///
/// Deliberately an ALLOWLIST rather than "everything in logs/": `~/.writ/logs` is a directory an
/// operator may drop their own notes into, and a retention pass must never delete a file it does not
/// recognise. Matched shapes:
///   * `crash-<ts>.json` — panic records written by [`crate::local::crash::install_panic_hook`],
///   * `*.log` / `*.err` / `*.out` — the supervisor's stdout+stderr capture (`agentd.log`, …),
///   * `*.log.<n>` — siblings left behind by an external rotator (`logrotate`, `newsyslog`).
fn is_prunable_log(name: &str) -> bool {
    if name.starts_with("crash-") && name.ends_with(".json") {
        return true;
    }
    is_capturable_log(name) || name.contains(".log.")
}

/// Is `name` a live append-target log (as opposed to a crash record)? Only these are size-capped —
/// a `crash-*.json` is a small whole document whose head is as valuable as its tail.
fn is_capturable_log(name: &str) -> bool {
    name.ends_with(".log") || name.ends_with(".err") || name.ends_with(".out")
}

/// Delete recognised `logs/` files last modified before `cutoff`. Returns `(files, bytes)`.
///
/// Best-effort throughout: an unreadable directory yields `(0, 0)` and a single file that refuses to
/// go is logged and skipped. Only file NAMES are logged — never contents (a log line could carry
/// material the sink redactor already masked, and we do not re-read it here anyway).
pub fn prune_expired_logs(paths: &Paths, cutoff: DateTime<Utc>) -> (u64, u64) {
    let dir = paths.logs_dir();
    let Ok(entries) = std::fs::read_dir(&dir) else {
        return (0, 0); // no logs dir yet (cold home) — nothing to do
    };
    let (mut files, mut bytes) = (0u64, 0u64);
    for entry in entries.flatten() {
        let path = entry.path();
        let Some(name) = path.file_name().and_then(|n| n.to_str()) else {
            continue;
        };
        if !is_prunable_log(name) {
            continue;
        }
        let Ok(md) = entry.metadata() else { continue };
        if !md.is_file() {
            continue;
        }
        // No usable mtime (exotic filesystem) ⇒ leave the file alone rather than guess.
        let Ok(modified) = md.modified() else { continue };
        if DateTime::<Utc>::from(modified) >= cutoff {
            continue;
        }
        match std::fs::remove_file(&path) {
            Ok(()) => {
                files += 1;
                bytes += md.len();
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => {
                tracing::warn!(error = %e, file = %name, "retention: could not remove an expired log file")
            }
        }
    }
    (files, bytes)
}

/// Cap any single live log file that has grown past [`LOG_FILE_SIZE_CAP_BYTES`], keeping its last
/// [`LOG_FILE_TAIL_KEEP_BYTES`]. Returns `(files_capped, bytes_reclaimed)`.
///
/// This is a DISK-SAFETY valve, not a history window, so it is intentionally independent of
/// `retention_days` (see the module docs). It is also why the cap TRUNCATES IN PLACE instead of
/// renaming: the writer is an external supervisor (launchd / systemd / a shell `>>`) that holds an
/// open `O_APPEND` descriptor on this inode. Renaming the file would simply move the descriptor's
/// target and reclaim nothing; `set_len(0)` on an `O_APPEND` descriptor resets the write offset to
/// the new EOF, so the supervisor keeps appending correctly afterwards.
pub fn cap_oversized_logs(paths: &Paths) -> (u64, u64) {
    let dir = paths.logs_dir();
    let Ok(entries) = std::fs::read_dir(&dir) else {
        return (0, 0);
    };
    let (mut capped, mut bytes) = (0u64, 0u64);
    for entry in entries.flatten() {
        let path = entry.path();
        let Some(name) = path.file_name().and_then(|n| n.to_str()).map(str::to_string) else {
            continue;
        };
        if !is_capturable_log(&name) {
            continue;
        }
        let Ok(md) = entry.metadata() else { continue };
        if !md.is_file() || md.len() <= LOG_FILE_SIZE_CAP_BYTES {
            continue;
        }
        match truncate_keeping_tail(&path, md.len(), LOG_FILE_TAIL_KEEP_BYTES) {
            Ok(reclaimed) => {
                capped += 1;
                bytes += reclaimed;
                tracing::warn!(
                    file = %name,
                    was_bytes = md.len(),
                    reclaimed_bytes = reclaimed,
                    "retention: log file exceeded the size cap — truncated, keeping the tail"
                );
            }
            Err(e) => {
                tracing::warn!(error = %e, file = %name, "retention: could not cap an oversized log file")
            }
        }
    }
    (capped, bytes)
}

/// Rewrite `path` so it holds only its last `keep` bytes (starting at the first line boundary within
/// them), prefixed by [`LOG_TRUNCATION_NOTICE`]. Returns the bytes reclaimed.
///
/// A concurrent append from the external writer between the read and the rewrite can lose a few log
/// lines; that is an accepted trade against an unbounded file, and it cannot corrupt anything but log
/// text (no reader parses these files structurally — the diagnostics bundle only scrubs and copies
/// them).
fn truncate_keeping_tail(path: &Path, len: u64, keep: u64) -> std::io::Result<u64> {
    use std::io::{Read, Seek, SeekFrom, Write};

    let keep = keep.min(len);
    let mut src = std::fs::File::open(path)?;
    src.seek(SeekFrom::Start(len - keep))?;
    let mut tail = Vec::with_capacity(keep as usize);
    src.read_to_end(&mut tail)?;
    drop(src);

    // Start the kept region at a line boundary so the first surviving line is whole.
    let start = tail.iter().position(|&b| b == b'\n').map_or(0, |i| i + 1);
    let tail = &tail[start..];

    let mut dst = std::fs::OpenOptions::new().write(true).open(path)?;
    dst.set_len(0)?;
    dst.write_all(LOG_TRUNCATION_NOTICE)?;
    dst.write_all(tail)?;
    dst.flush()?;
    // Reclaimed = old size minus what we wrote back (tail + the notice we prepended).
    let kept = tail.len() as u64 + LOG_TRUNCATION_NOTICE.len() as u64;
    Ok(len.saturating_sub(kept))
}

// -------------------------------------------------------------------------------------------------
// Periodic maintenance loop (the fleet worker's only retention driver)
// -------------------------------------------------------------------------------------------------

/// Checkpoint the write-ahead log into the main DB file and TRUNCATE `writ.db-wal` back to zero.
///
/// SQLite auto-checkpoints at ~1000 pages but leaves the `-wal` file at its high-water mark forever,
/// so a worker that once ran a big batch keeps that space pinned for the life of the process. A
/// periodic `TRUNCATE` checkpoint is what actually returns it to the filesystem. Deliberately NOT
/// `VACUUM`: that needs a transient copy of the whole database plus an exclusive lock, which is the
/// wrong thing to do behind an unattended worker's back — freed pages are reused in place instead.
pub async fn wal_checkpoint_truncate(db: &SqlitePool) -> LocalResult<()> {
    sqlx::query("PRAGMA wal_checkpoint(TRUNCATE)").execute(db).await?;
    Ok(())
}

/// Cadence + window for [`spawn_maintenance`].
#[derive(Debug, Clone)]
pub struct MaintenanceConfig {
    /// How often the loop wakes. Each wake caps oversized logs and checkpoints the WAL — both cheap.
    pub tick: StdDuration,
    /// Minimum gap between full retention purges (row deletes + blob/log reclamation).
    pub purge_every: StdDuration,
    /// The retention window in days (`0` = keep everything; the purge becomes a no-op).
    pub retention_days: u32,
}

impl MaintenanceConfig {
    /// Hourly wake: frequent enough to bound the `-wal` file and a runaway log, far too infrequent to
    /// matter for load. (Contrast the scheduler tick, which is seconds — retention must NOT ride it.)
    pub const DEFAULT_TICK: StdDuration = StdDuration::from_secs(60 * 60);
    /// Daily purge — the same cadence the desktop scheduler's retention lane uses.
    pub const DEFAULT_PURGE_EVERY: StdDuration = StdDuration::from_secs(24 * 60 * 60);

    /// Defaults with an explicit retention window (normally `LocalConfig::retention_days`, i.e.
    /// `WRIT_RETENTION_DAYS` / `[app].retention_days`).
    pub fn new(retention_days: u32) -> Self {
        Self {
            tick: Self::DEFAULT_TICK,
            purge_every: Self::DEFAULT_PURGE_EVERY,
            retention_days,
        }
    }

    /// Clamp nonsense values so a misconfigured cadence can't spin the loop.
    fn sanitized(mut self) -> Self {
        self.tick = self.tick.max(StdDuration::from_millis(50));
        self.purge_every = self.purge_every.max(self.tick);
        self
    }
}

/// Owns the running maintenance task and its cancellation channel. Mirrors
/// [`crate::local::scheduler::SchedulerHandle`]. Dropping it also ends the loop (at its next wake the
/// `watch` sender is gone), but WITHOUT waiting for an in-flight purge — prefer the explicit
/// [`shutdown`](Self::shutdown) from the process's signal handler.
pub struct MaintenanceHandle {
    cancel: watch::Sender<bool>,
    task: JoinHandle<()>,
}

impl MaintenanceHandle {
    /// Signal the loop to stop and await its exit (so an in-flight purge finishes rather than being
    /// torn out mid-DELETE). Safe to call after the task already ended.
    pub async fn shutdown(self) {
        let _ = self.cancel.send(true);
        match self.task.await {
            Ok(()) => tracing::info!("retention maintenance loop stopped"),
            Err(e) if e.is_cancelled() => tracing::info!("retention maintenance task cancelled"),
            Err(e) => tracing::warn!(error = %e, "retention maintenance task join error on shutdown"),
        }
    }

    /// Has the loop task finished? (Tests / health reporting.)
    pub fn is_finished(&self) -> bool {
        self.task.is_finished()
    }
}

/// Spawn the periodic data-maintenance loop and return a handle to stop it.
///
/// The FLEET worker's only retention driver — it runs neither the scheduler (whose Lane 4 drives the
/// desktop purge) nor the local HTTP API (whose `POST /v1/data-admin` is the manual lever), so
/// without this a worker's DB, artifacts and logs grew forever with no way to reclaim them.
///
/// Each pass, in order: cap oversized logs → purge (only when `purge_every` has elapsed) →
/// `wal_checkpoint(TRUNCATE)`. The FIRST pass runs immediately rather than after a full interval:
/// a worker that was just restarted because its volume filled needs the reclaim now, not in an hour.
pub fn spawn_maintenance(db: SqlitePool, paths: Paths, config: MaintenanceConfig) -> MaintenanceHandle {
    let config = config.sanitized();
    let (cancel_tx, cancel_rx) = watch::channel(false);
    tracing::info!(
        tick_s = config.tick.as_secs(),
        purge_every_s = config.purge_every.as_secs(),
        retention_days = config.retention_days,
        "data maintenance loop starting (retention purge + log cap + WAL checkpoint)"
    );
    let task = tokio::spawn(maintenance_loop(db, paths, config, cancel_rx));
    MaintenanceHandle { cancel: cancel_tx, task }
}

/// Should a full purge run now? `None` = never purged this process ⇒ yes. Pure, so the cadence gate
/// is unit-testable without waiting real hours.
fn purge_due(since_last: Option<StdDuration>, every: StdDuration) -> bool {
    match since_last {
        None => true,
        Some(elapsed) => elapsed >= every,
    }
}

/// The loop body. Every step is best-effort: a failure is logged and the loop keeps its cadence, so
/// one bad pass (a locked DB, an unreadable log) can never wedge maintenance for the process's life.
async fn maintenance_loop(
    db: SqlitePool,
    paths: Paths,
    config: MaintenanceConfig,
    mut cancel: watch::Receiver<bool>,
) {
    let mut last_purge: Option<Instant> = None;
    loop {
        // Disk-safety valve first, and unconditionally: it must work even with retention disabled.
        let (capped, capped_bytes) = cap_oversized_logs(&paths);
        if capped > 0 {
            tracing::warn!(files = capped, bytes = capped_bytes, "maintenance: capped oversized log files");
        }

        if purge_due(last_purge.map(|t| t.elapsed()), config.purge_every) {
            last_purge = Some(Instant::now());
            match purge_with_config(&db, &paths, config.retention_days).await {
                Ok(report) if report.cutoff.is_some() => tracing::info!(
                    retention_days = config.retention_days,
                    cutoff = report.cutoff.as_deref().unwrap_or(""),
                    runs = report.runs_deleted,
                    changes = report.changes_deleted,
                    uptime = report.uptime_checks_deleted,
                    preview_steps = report.preview_steps_deleted,
                    output_files = report.output_files_deleted,
                    log_files = report.log_files_deleted,
                    log_bytes = report.log_bytes_reclaimed,
                    "maintenance: retention purge pass complete"
                ),
                // Retention disabled (`retention_days == 0`) — say so ONCE per pass at debug so an
                // operator grepping for "why is my disk full" finds the reason.
                Ok(_) => tracing::debug!("maintenance: retention disabled (retention_days = 0)"),
                Err(e) => tracing::warn!(error = %e, "maintenance: retention purge failed (loop continues)"),
            }
        }

        if let Err(e) = wal_checkpoint_truncate(&db).await {
            tracing::warn!(error = %e, "maintenance: WAL checkpoint failed (loop continues)");
        }

        // Sleep until the next pass, or return promptly when asked to stop.
        tokio::select! {
            _ = tokio::time::sleep(config.tick) => {}
            _ = cancel.changed() => {
                tracing::info!("maintenance loop cancelled — exiting");
                return;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::local::store::runs::{self, NewRun};
    use crate::local::vault::Vault;
    use crate::local::{config::Paths, db};

    async fn setup() -> (Paths, Vault, SqlitePool) {
        let dir = Box::leak(Box::new(tempfile::tempdir().unwrap()));
        let paths = Paths::at(dir.path().join(".writ"));
        paths.ensure_dirs().unwrap();
        let vault = Vault::load_or_create(&paths.root, false).unwrap();
        let pool = db::open(&paths.db(), &vault.db_key_hex()).await.unwrap();
        (paths, vault, pool)
    }

    /// Back-date a run's `created_at` to an old instant so the purge cutoff catches it.
    async fn backdate_run(pool: &SqlitePool, id: i64, iso: &str) {
        sqlx::query("UPDATE runs SET created_at = ?2 WHERE id = ?1")
            .bind(id)
            .bind(iso)
            .execute(pool)
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn retention_zero_is_a_noop() {
        let (paths, _v, pool) = setup().await;
        let r = runs::insert(&pool, &NewRun::default()).await.unwrap();
        let report = purge_with_config(&pool, &paths, 0).await.unwrap();
        assert!(report.cutoff.is_none());
        assert_eq!(report.runs_deleted, 0);
        // Run survives.
        assert!(runs::get_by_id(&pool, r.id).await.unwrap().is_some());
    }

    #[tokio::test]
    async fn purges_old_runs_and_their_output_files_but_keeps_recent() {
        let (paths, vault, pool) = setup().await;

        // Old run + its captured workflow-output file.
        let old = runs::insert(&pool, &NewRun::default()).await.unwrap();
        let temp = storage::local_path_for_run(&paths, old.id, "shot.png").unwrap();
        std::fs::write(&temp, b"\x89PNG old artifact").unwrap();
        let old_file =
            storage::capture_output(&pool, &vault, &paths, &temp, "shot.png", Some("image/png"), old.id)
                .await
                .unwrap();
        let blob_path =
            storage::storage_path_for_key(&paths, &old_file.source, &old_file.storage_key).unwrap();
        assert!(blob_path.exists(), "output blob written");

        // Recent run (kept).
        let recent = runs::insert(&pool, &NewRun::default()).await.unwrap();

        // Back-date the old run well past the cutoff.
        backdate_run(&pool, old.id, "2000-01-01T00:00:00.000Z").await;

        let report = purge_with_config(&pool, &paths, 30).await.unwrap();
        assert_eq!(report.runs_deleted, 1, "only the old run is purged");
        assert_eq!(report.output_files_deleted, 1, "its workflow-output file is reclaimed");

        assert!(runs::get_by_id(&pool, old.id).await.unwrap().is_none(), "old run gone");
        assert!(runs::get_by_id(&pool, recent.id).await.unwrap().is_some(), "recent run kept");
        assert!(stored_files::get_by_id(&pool, &old_file.id).await.unwrap().is_none(), "file row gone");
        assert!(!blob_path.exists(), "on-disk blob reclaimed");
    }

    #[tokio::test]
    async fn purges_old_changes_and_uptime_checks() {
        use crate::local::store::changes::{self, NewChange};
        use crate::local::store::targets::{self, NewTarget};
        use crate::local::store::uptime_checks::{self, NewUptimeCheck};

        let (paths, _v, pool) = setup().await;
        // A target is required (FK on changes/uptime_checks). `insert` returns the new id.
        let target_id = targets::insert(
            &pool,
            &NewTarget { url: "https://example.com".into(), ..Default::default() },
        )
        .await
        .unwrap();

        // Old + recent change.
        let old_change = changes::insert(
            &pool,
            &NewChange { target_id, content_hash: "h1".into(), ..Default::default() },
        )
        .await
        .unwrap();
        sqlx::query("UPDATE changes SET last_detected_at = '2000-01-01T00:00:00.000Z' WHERE id = ?1")
            .bind(old_change)
            .execute(&pool)
            .await
            .unwrap();
        let recent_change = changes::insert(
            &pool,
            &NewChange { target_id, content_hash: "h2".into(), ..Default::default() },
        )
        .await
        .unwrap();

        // Old + recent uptime check (`is_up` is an INTEGER 0/1).
        let old_up = uptime_checks::insert(
            &pool,
            &NewUptimeCheck { target_id, is_up: 1, ..Default::default() },
        )
        .await
        .unwrap();
        sqlx::query("UPDATE uptime_checks SET checked_at = '2000-01-01T00:00:00.000Z' WHERE id = ?1")
            .bind(old_up)
            .execute(&pool)
            .await
            .unwrap();
        let _recent_up = uptime_checks::insert(
            &pool,
            &NewUptimeCheck { target_id, is_up: 1, ..Default::default() },
        )
        .await
        .unwrap();

        let report = purge_with_config(&pool, &paths, 30).await.unwrap();
        assert_eq!(report.changes_deleted, 1);
        assert_eq!(report.uptime_checks_deleted, 1);
        assert!(changes::get_by_id(&pool, old_change).await.unwrap().is_none());
        assert!(changes::get_by_id(&pool, recent_change).await.unwrap().is_some());
    }

    /// Write a `logs/` file of `bytes` length. There is no no-dep portable mtime setter, so the tests
    /// below move the CUTOFF instead of back-dating the file: a future cutoff expires everything, a
    /// past cutoff expires nothing.
    fn seed_log(paths: &Paths, name: &str, bytes: usize) -> std::path::PathBuf {
        let p = paths.logs_dir().join(name);
        std::fs::write(&p, vec![b'x'; bytes]).unwrap();
        p
    }

    /// The allowlist matches exactly the shapes retention owns and nothing else — an operator's own
    /// notes in `logs/` must never be deleted by a retention pass.
    #[test]
    fn log_allowlist_is_narrow() {
        assert!(is_prunable_log("crash-2026-07-25T00-00-00Z.json"));
        assert!(is_prunable_log("agentd.log"));
        assert!(is_prunable_log("writ-agent-fleet.err"));
        assert!(is_prunable_log("writ-agent-fleet.out"));
        assert!(is_prunable_log("agentd.log.1"));
        // NOT ours.
        assert!(!is_prunable_log("notes.txt"));
        assert!(!is_prunable_log("config.toml"));
        assert!(!is_prunable_log("crash-notes.md"));
        assert!(!is_prunable_log("writ.db"));
        // Only live append-targets are size-capped; a crash record is a whole document.
        assert!(is_capturable_log("agentd.log"));
        assert!(!is_capturable_log("crash-2026.json"));
        assert!(!is_capturable_log("agentd.log.1"));
    }

    /// Expired `logs/` files are removed and their bytes counted; files newer than the cutoff and
    /// unrecognised files both survive.
    #[tokio::test]
    async fn prunes_expired_logs_and_keeps_unknown_files() {
        let (paths, _v, _pool) = setup().await;
        let crash = seed_log(&paths, "crash-2026-01-01T00-00-00Z.json", 128);
        let log = seed_log(&paths, "agentd.log", 256);
        let notes = seed_log(&paths, "operator-notes.txt", 32);

        // A cutoff in the past keeps everything (the files were just written).
        let (files, bytes) = prune_expired_logs(&paths, Utc::now() - Duration::days(1));
        assert_eq!((files, bytes), (0, 0), "nothing is expired yet");
        assert!(crash.exists() && log.exists());

        // A cutoff in the future expires every recognised file, and only those.
        let (files, bytes) = prune_expired_logs(&paths, Utc::now() + Duration::days(1));
        assert_eq!(files, 2, "both the crash record and the log capture are pruned");
        assert_eq!(bytes, 128 + 256, "reclaimed bytes are tallied");
        assert!(!crash.exists());
        assert!(!log.exists());
        assert!(notes.exists(), "an unrecognised file must survive a retention pass");
    }

    /// An oversized log is truncated to its tail, keeps a whole final line, gains the truncation
    /// notice, and reports the bytes reclaimed. A small log is left completely alone.
    #[tokio::test]
    async fn caps_oversized_log_keeping_the_tail() {
        let (paths, _v, _pool) = setup().await;
        let small = seed_log(&paths, "small.log", 64);

        // Build a file over the cap out of numbered lines so we can assert WHICH end survived.
        let big_path = paths.logs_dir().join("big.log");
        {
            use std::io::Write;
            let mut f = std::io::BufWriter::new(std::fs::File::create(&big_path).unwrap());
            let line = "y".repeat(1023);
            // 33 MiB of 1 KiB lines > the 32 MiB cap.
            for _ in 0..(33 * 1024) {
                writeln!(f, "{line}").unwrap();
            }
            writeln!(f, "LAST-LINE-MARKER").unwrap();
            f.flush().unwrap();
        }
        let before = std::fs::metadata(&big_path).unwrap().len();
        assert!(before > LOG_FILE_SIZE_CAP_BYTES, "precondition: over the cap");

        let (capped, reclaimed) = cap_oversized_logs(&paths);
        assert_eq!(capped, 1, "only the oversized file is capped");
        assert!(reclaimed > 0);

        let after = std::fs::metadata(&big_path).unwrap().len();
        assert!(after < before, "file shrank");
        assert!(
            after <= LOG_FILE_TAIL_KEEP_BYTES + LOG_TRUNCATION_NOTICE.len() as u64,
            "kept at most the tail budget, got {after}"
        );
        let text = std::fs::read_to_string(&big_path).unwrap();
        assert!(text.starts_with("[writ retention]"), "truncation is self-documenting");
        assert!(text.trim_end().ends_with("LAST-LINE-MARKER"), "the TAIL is what survived");
        // The first surviving log line is whole (no half line after the notice).
        let first_kept = text.lines().nth(1).unwrap();
        assert_eq!(first_kept.len(), 1023, "kept region starts at a line boundary");

        assert_eq!(std::fs::metadata(&small).unwrap().len(), 64, "a small log is untouched");
    }

    /// The purge cadence gate: never-run fires, then nothing until a full window has elapsed.
    #[test]
    fn purge_cadence_gate() {
        let every = StdDuration::from_secs(86_400);
        assert!(purge_due(None, every), "never purged must fire");
        assert!(!purge_due(Some(StdDuration::from_secs(1)), every));
        assert!(!purge_due(Some(every - StdDuration::from_millis(1)), every));
        assert!(purge_due(Some(every), every), "a full window later must re-run");
    }

    /// `MaintenanceConfig::sanitized` refuses a spin-the-CPU cadence and keeps `purge_every >= tick`.
    #[test]
    fn maintenance_config_is_sanitized() {
        let c = MaintenanceConfig {
            tick: StdDuration::ZERO,
            purge_every: StdDuration::ZERO,
            retention_days: 7,
        }
        .sanitized();
        assert!(c.tick >= StdDuration::from_millis(50));
        assert!(c.purge_every >= c.tick);
        let d = MaintenanceConfig::new(90);
        assert_eq!(d.retention_days, 90);
        assert_eq!(d.tick, MaintenanceConfig::DEFAULT_TICK);
        assert_eq!(d.purge_every, MaintenanceConfig::DEFAULT_PURGE_EVERY);
    }

    /// `wal_checkpoint_truncate` succeeds on a live WAL-mode pool (and is safe to repeat).
    #[tokio::test]
    async fn wal_checkpoint_is_callable() {
        let (_paths, _v, pool) = setup().await;
        wal_checkpoint_truncate(&pool).await.unwrap();
        wal_checkpoint_truncate(&pool).await.unwrap();
    }

    /// End-to-end for the FLEET worker's only retention driver: the spawned loop purges an aged run
    /// on its first pass (which is immediate, not one interval later) and then stops cleanly on
    /// `shutdown()`.
    #[tokio::test]
    async fn maintenance_loop_purges_then_stops_cleanly() {
        let (paths, _v, pool) = setup().await;
        let old = runs::insert(&pool, &NewRun::default()).await.unwrap();
        let recent = runs::insert(&pool, &NewRun::default()).await.unwrap();
        backdate_run(&pool, old.id, "2000-01-01T00:00:00.000Z").await;

        let handle = spawn_maintenance(
            pool.clone(),
            paths.clone(),
            MaintenanceConfig {
                tick: StdDuration::from_millis(50),
                purge_every: StdDuration::from_millis(50),
                retention_days: 30,
            },
        );

        // The first pass is immediate; poll briefly rather than sleeping a fixed amount.
        let mut purged = false;
        for _ in 0..100 {
            if runs::get_by_id(&pool, old.id).await.unwrap().is_none() {
                purged = true;
                break;
            }
            tokio::time::sleep(StdDuration::from_millis(20)).await;
        }
        assert!(purged, "the maintenance loop must purge the aged run without an operator");
        assert!(
            runs::get_by_id(&pool, recent.id).await.unwrap().is_some(),
            "the recent run survives"
        );

        handle.shutdown().await;
    }

    /// With retention disabled the loop still runs (log cap + WAL checkpoint) but deletes no history.
    #[tokio::test]
    async fn maintenance_loop_respects_retention_disabled() {
        let (paths, _v, pool) = setup().await;
        let old = runs::insert(&pool, &NewRun::default()).await.unwrap();
        backdate_run(&pool, old.id, "2000-01-01T00:00:00.000Z").await;

        let handle = spawn_maintenance(
            pool.clone(),
            paths.clone(),
            MaintenanceConfig {
                tick: StdDuration::from_millis(20),
                purge_every: StdDuration::from_millis(20),
                retention_days: 0,
            },
        );
        tokio::time::sleep(StdDuration::from_millis(150)).await;
        handle.shutdown().await;

        assert!(
            runs::get_by_id(&pool, old.id).await.unwrap().is_some(),
            "retention_days = 0 must keep everything"
        );
    }
}
