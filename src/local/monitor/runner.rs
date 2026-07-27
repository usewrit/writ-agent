//! The check runner: select due targets, check each (bounded + isolated), persist change-only
//! results, and dispatch `change_detected` automations through the engine.

use std::sync::Arc;
use std::time::Duration;

use chrono::{DateTime, Utc};
use sqlx::SqlitePool;

use super::{
    CHECK_TIMEOUT_SECS, EVENT_CHANGE_DETECTED, EVENT_MONITOR_DOWN, EVENT_MONITOR_RECOVERED,
    EVENT_MONITOR_STALE, MIN_CHECK_INTERVAL_MS,
};
use crate::config::env::AppConfig;
use crate::local::engine::{Lane, LocalEngine, RunSource};
use crate::local::error::LocalResult;
use crate::local::store::{
    automations, changes, monitor_state, target_selectors, targets, uptime_checks,
};
use crate::monitor::checker::Checker;
use crate::monitor::models::{
    CheckOutcome as CloudOutcome, ReportItem as CloudReport, Selector as CloudSelector,
    Target as CloudTarget,
};

/// How many due targets one `run_due_checks` tick will process at most (bounds a tick's work; the
/// rest are picked up next tick). Generous — a single-user desktop rarely has this many monitors.
const DUE_BATCH_LIMIT: i64 = 256;

/// Terminal classification of a single target check.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CheckStatus {
    /// Check ran; no selector changed vs baseline (or first-check baseline seeded).
    Unchanged,
    /// Check ran; at least one selector changed (or a uptime up/down transition).
    Changed,
    /// The check itself failed (fetch/browser/extract error) — `monitor_state.state = "error"`.
    Error,
    /// The check exceeded [`CHECK_TIMEOUT_SECS`] and was abandoned.
    Timeout,
    /// The target was due-selected but skipped (disabled mid-tick, or anti-detection floor).
    Skipped,
}

/// The result of dispatching automations triggered by ONE detected change.
#[derive(Debug, Clone, Default, serde::Serialize)]
pub struct DispatchOutcome {
    /// Enabled `change_detected` automations matched for this target.
    pub matched: usize,
    /// Automations whose workflow ran to a successful [`crate::local::engine::RunResult`].
    pub succeeded: usize,
    /// Automations that failed (no workflow_id, engine error, or non-success run).
    pub failed: usize,
}

/// The outcome of checking a single target.
#[derive(Debug, Clone, serde::Serialize)]
pub struct CheckOutcome {
    pub target_id: i64,
    pub status: CheckStatus,
    /// A `changes.id` when a change row was written (content targets only).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub change_id: Option<i64>,
    /// Automation dispatch tally (present only when a change fired automations).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dispatch: Option<DispatchOutcome>,
    /// Human-readable error (only when `status == Error`/`Timeout`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

impl CheckOutcome {
    fn skipped(target_id: i64) -> Self {
        Self { target_id, status: CheckStatus::Skipped, change_id: None, dispatch: None, error: None }
    }
}

/// Aggregate result of one scheduler tick.
#[derive(Debug, Clone, Default, serde::Serialize)]
pub struct TickReport {
    /// Targets that were due and considered this tick.
    pub considered: usize,
    pub checked: usize,
    pub changed: usize,
    pub unchanged: usize,
    pub errored: usize,
    pub timed_out: usize,
    pub skipped: usize,
    /// Per-target outcomes (in processing order).
    pub outcomes: Vec<CheckOutcome>,
}

impl TickReport {
    fn record(&mut self, o: CheckOutcome) {
        match o.status {
            CheckStatus::Unchanged => self.unchanged += 1,
            CheckStatus::Changed => self.changed += 1,
            CheckStatus::Error => self.errored += 1,
            CheckStatus::Timeout => self.timed_out += 1,
            CheckStatus::Skipped => self.skipped += 1,
        }
        if o.status != CheckStatus::Skipped {
            self.checked += 1;
        }
        self.outcomes.push(o);
    }
}

/// Run all DUE monitor checks as of `now`. Selects enabled targets whose `next_run_at` is due, then
/// for each one that also clears the 60s anti-detection floor, performs the check, persists results
/// change-only, advances `next_run_at`, and dispatches `change_detected` automations. Targets are
/// processed sequentially; each check is bounded by [`CHECK_TIMEOUT_SECS`] and isolated, so one slow
/// or failing target never aborts the rest of the tick.
///
/// This is the ergonomic entry point a tokio scheduler loop calls each tick.
pub async fn run_due_checks(
    db: &SqlitePool,
    engine: &Arc<dyn LocalEngine>,
    now: DateTime<Utc>,
) -> LocalResult<TickReport> {
    let now_str = rfc3339(now);
    let due = targets::list_due(db, &now_str, DUE_BATCH_LIMIT).await?;
    let mut report = TickReport { considered: due.len(), ..Default::default() };

    // A long-lived checker per tick reuses one HTTP client/UA across targets (stable content hashes).
    let checker = Checker::new(None);
    let browser = LazyBrowser::new();

    for target in due {
        // Re-confirm enabled (a row could have been disabled between select and now) and clear the
        // anti-detection floor against the last recorded live-state check time.
        if target.enabled == 0 {
            report.record(CheckOutcome::skipped(target.id));
            continue;
        }
        if !floor_cleared(db, target.id, now).await? {
            tracing::debug!(target_id = target.id, "skipping: 60s anti-detection floor not cleared");
            report.record(CheckOutcome::skipped(target.id));
            continue;
        }

        let outcome = check_one_isolated(db, engine, &checker, &browser, &target, now).await;
        report.record(outcome);
    }

    // Fire monitor_stale for overdue targets that have a stale automation. Runs after the due
    // checks (which refresh their own targets), so an actively-checked monitor is never flagged.
    let _ = sweep_stale_health(db, engine, now).await;

    tracing::info!(
        considered = report.considered,
        checked = report.checked,
        changed = report.changed,
        errored = report.errored,
        timed_out = report.timed_out,
        "monitor tick complete"
    );
    Ok(report)
}

/// Force a check of one target by id REGARDLESS of its schedule (manual "run now"), still respecting
/// the 60s anti-detection floor. Used by `POST /v1/monitors/:id/run`. Returns the per-target outcome.
pub async fn run_check_for_target(
    db: &SqlitePool,
    engine: &Arc<dyn LocalEngine>,
    target_id: i64,
) -> LocalResult<CheckOutcome> {
    let now = Utc::now();
    let target = targets::get_by_id(db, target_id)
        .await?
        .ok_or_else(|| crate::local::error::LocalError::NotFound(format!("monitor {target_id}")))?;

    if !floor_cleared(db, target_id, now).await? {
        return Ok(CheckOutcome::skipped(target_id));
    }

    let checker = Checker::new(None);
    let browser = LazyBrowser::new();
    Ok(check_one_isolated(db, engine, &checker, &browser, &target, now).await)
}

/// [`check_one`] with PANIC ISOLATION — one hostile target can never take down the rest of the tick.
///
/// WHY: `run_due_checks` walks due targets SEQUENTIALLY in one task. Any panic inside a check
/// (historically: a byte-slice off a UTF-8 boundary in the diff builder, on content the monitored page
/// controls) therefore unwound past the whole loop, so every target ordered after the hostile one was
/// silently skipped — and it repeated on every tick for as long as the content stayed poisoned. The
/// cloud loop never had this problem because it spawns a task per target; this is the local
/// equivalent, without needing `'static` borrows.
///
/// `AssertUnwindSafe` is sound here: nothing this future mutates is shared across targets in a way a
/// half-finished check could corrupt — the `Checker` is stateless (a client + a UA string), the SQLite
/// pool maintains its own invariants, and the browser handle is an `Arc`. A panicking target is
/// recorded as an `Error` outcome (and persisted as one) rather than being lost.
async fn check_one_isolated(
    db: &SqlitePool,
    engine: &Arc<dyn LocalEngine>,
    checker: &Checker,
    browser: &LazyBrowser,
    target: &targets::Target,
    now: DateTime<Utc>,
) -> CheckOutcome {
    use futures_util::FutureExt;
    let fut = std::panic::AssertUnwindSafe(check_one(db, engine, checker, browser, target, now));
    match fut.catch_unwind().await {
        Ok(outcome) => outcome,
        Err(payload) => {
            let detail = panic_message(payload.as_ref());
            let msg = format!("check panicked: {detail}");
            tracing::error!(target_id = target.id, url = %target.url, "{msg}");
            persist_error(db, target.id, now, &msg).await;
            CheckOutcome {
                target_id: target.id,
                status: CheckStatus::Error,
                change_id: None,
                dispatch: None,
                error: Some(msg),
            }
        }
    }
}

/// Best-effort human text out of a caught panic payload (`&str` / `String` are what `panic!` produces).
fn panic_message(payload: &(dyn std::any::Any + Send)) -> String {
    if let Some(s) = payload.downcast_ref::<&'static str>() {
        return (*s).to_string();
    }
    if let Some(s) = payload.downcast_ref::<String>() {
        return s.clone();
    }
    "unknown panic".to_string()
}

// ---------------------------------------------------------------------------------------------
// Selector probes + baseline capture (the "test selector" / "set baseline" UI actions)
// ---------------------------------------------------------------------------------------------

/// The result of probing ONE selector against the live page (no persistence). Drives the recorder /
/// monitor-edit "Test" button and the "Set baseline" confirmation.
#[derive(Debug, Clone, serde::Serialize)]
pub struct SelectorProbe {
    pub selector_id: i64,
    /// The selector resolved to content (text/html present, or a visual region captured).
    pub matched: bool,
    /// Extracted text/html (truncated by the checker). `None` for visual selectors or on a miss.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub content: Option<String>,
    /// SHA-256 content hash (text/html) or pixel hash (visual). Omitted on a miss.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub content_hash: Option<String>,
    /// Base64 PNG of the captured region (visual selectors only).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub screenshot: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status_code: Option<i64>,
    /// Present when the selector did not resolve (fetch failure, `selector_missing`, …).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

impl SelectorProbe {
    fn from_report(selector_id: i64, report: Option<&CloudReport>) -> Self {
        match report {
            Some(r) => {
                let ok = r.error_type.is_none();
                SelectorProbe {
                    selector_id,
                    matched: ok,
                    content: r.content.clone(),
                    // The checker emits a sentinel "0"*64 hash on a miss — only surface a real one.
                    content_hash: if ok { r.content_hash.clone() } else { None },
                    screenshot: r.screenshot.clone(),
                    status_code: r.status_code,
                    error: r.error_message.clone(),
                }
            }
            None => SelectorProbe {
                selector_id,
                matched: false,
                content: None,
                content_hash: None,
                screenshot: None,
                status_code: None,
                error: Some("checker produced no report".into()),
            },
        }
    }
}

/// Summary of a bulk baseline capture (`set-all-baselines`).
#[derive(Debug, Clone, serde::Serialize)]
pub struct BaselineSummary {
    pub target_id: i64,
    /// Selectors considered (all of the target's selectors).
    pub selectors: usize,
    /// Selectors whose baseline was (re)captured from a live match.
    pub captured: usize,
}

/// Load a selector that MUST belong to `target_id`, else `NotFound` (prevents cross-target id probing).
async fn load_owned_selector(
    db: &SqlitePool,
    target_id: i64,
    selector_id: i64,
) -> LocalResult<target_selectors::TargetSelector> {
    target_selectors::get_by_id(db, selector_id)
        .await?
        .filter(|s| s.target_id == target_id)
        .ok_or_else(|| crate::local::error::LocalError::NotFound(format!("selector {selector_id}")))
}

/// Fetch `target_id` or `NotFound`.
async fn load_target(db: &SqlitePool, target_id: i64) -> LocalResult<targets::Target> {
    targets::get_by_id(db, target_id)
        .await?
        .ok_or_else(|| crate::local::error::LocalError::NotFound(format!("monitor {target_id}")))
}

/// Run a one-off check of the supplied selectors on `target`'s page under the standard timeout,
/// WITHOUT persisting anything. Shared by probe + baseline capture. Unlike the scheduled path this
/// does NOT apply the anti-detection floor — these are explicit, low-frequency user actions.
async fn check_selectors_now(
    target: &targets::Target,
    selectors: Vec<target_selectors::TargetSelector>,
) -> LocalResult<CloudOutcome> {
    let cloud = assemble_cloud_target(target, to_cloud_selectors(selectors));
    let checker = Checker::new(None);
    let browser = LazyBrowser::new();
    let browser_arc = if cloud.needs_browser() {
        browser.get().await
    } else {
        browser.dummy().clone()
    };
    let fut = checker.check_target(&cloud, &browser_arc);
    match tokio::time::timeout(Duration::from_secs(CHECK_TIMEOUT_SECS), fut).await {
        Ok(o) => Ok(o),
        Err(_) => Err(crate::local::error::LocalError::Internal(format!(
            "selector check timed out after {CHECK_TIMEOUT_SECS}s"
        ))),
    }
}

/// Probe ONE selector against the live page (no persistence). Backs
/// `POST /v1/monitors/:id/selectors/:sid/test`.
pub async fn probe_selector(
    db: &SqlitePool,
    target_id: i64,
    selector_id: i64,
) -> LocalResult<SelectorProbe> {
    let target = load_target(db, target_id).await?;
    let sel = load_owned_selector(db, target_id, selector_id).await?;
    let outcome = check_selectors_now(&target, vec![sel]).await?;
    Ok(SelectorProbe::from_report(selector_id, outcome.reports.first()))
}

/// Capture the baseline for ONE selector from a fresh fetch. Backs
/// `POST /v1/monitors/:id/selectors/:sid/set-baseline`.
pub async fn capture_selector_baseline(
    db: &SqlitePool,
    target_id: i64,
    selector_id: i64,
) -> LocalResult<SelectorProbe> {
    let target = load_target(db, target_id).await?;
    let mut sel = load_owned_selector(db, target_id, selector_id).await?;
    // Probe with the baseline cleared so the report carries the CURRENT content/hash to store.
    sel.baseline_hash = None;
    sel.baseline_content = None;
    let outcome = check_selectors_now(&target, vec![sel]).await?;
    let probe = SelectorProbe::from_report(selector_id, outcome.reports.first());
    if probe.matched {
        target_selectors::set_baseline(
            db,
            selector_id,
            probe.content_hash.as_deref(),
            probe.content.as_deref(),
            probe.screenshot.as_deref(),
        )
        .await?;
    }
    Ok(probe)
}

/// Capture baselines for ALL of a target's selectors in one fetch. Backs
/// `POST /v1/monitors/:id/selectors/set-all-baselines`.
pub async fn capture_all_baselines(db: &SqlitePool, target_id: i64) -> LocalResult<BaselineSummary> {
    let target = load_target(db, target_id).await?;
    let rows = target_selectors::list_by_target(db, target_id, 1000).await?;
    let total = rows.len();
    if rows.is_empty() {
        return Ok(BaselineSummary { target_id, selectors: 0, captured: 0 });
    }
    // Clear baselines on the working copies so each report carries current content to persist; the
    // report order mirrors the selector order, so we can zip them back to their rows.
    let probe_rows: Vec<target_selectors::TargetSelector> = rows
        .into_iter()
        .map(|mut s| {
            s.baseline_hash = None;
            s.baseline_content = None;
            s
        })
        .collect();
    let outcome = check_selectors_now(&target, probe_rows.clone()).await?;

    let mut captured = 0usize;
    for (sel, report) in probe_rows.iter().zip(outcome.reports.iter()) {
        if report.error_type.is_some() {
            continue;
        }
        if let Some(hash) = report.content_hash.as_deref() {
            target_selectors::set_baseline(
                db,
                sel.id,
                Some(hash),
                report.content.as_deref(),
                report.screenshot.as_deref(),
            )
            .await?;
            captured += 1;
        }
    }
    Ok(BaselineSummary { target_id, selectors: total, captured })
}

// ---------------------------------------------------------------------------------------------
// Per-target check
// ---------------------------------------------------------------------------------------------

/// Check ONE target end-to-end: run the (bounded) check, persist results change-only, advance the
/// schedule, and dispatch automations on change. Never returns `Err` for a per-target failure — a
/// failed check becomes a `CheckStatus::Error`/`Timeout` outcome so the tick keeps going.
async fn check_one(
    db: &SqlitePool,
    engine: &Arc<dyn LocalEngine>,
    checker: &Checker,
    browser: &LazyBrowser,
    target: &targets::Target,
    now: DateTime<Utc>,
) -> CheckOutcome {
    // Capture the prior TERMINAL state BEFORE `mark_checking` overwrites it, so we can detect a
    // health EDGE (healthy↔unhealthy) once the check completes and fire down/recovered automations.
    let prior_state = monitor_state::get(db, target.id)
        .await
        .ok()
        .flatten()
        .and_then(|s| s.state);
    let outcome = check_one_inner(db, engine, checker, browser, target, now).await;
    maybe_dispatch_health_edge(db, engine, target, prior_state.as_deref(), outcome.status).await;
    outcome
}

async fn check_one_inner(
    db: &SqlitePool,
    engine: &Arc<dyn LocalEngine>,
    checker: &Checker,
    browser: &LazyBrowser,
    target: &targets::Target,
    now: DateTime<Utc>,
) -> CheckOutcome {
    // Always advance the schedule FIRST (brief, before the slow check) so a long/hung check can't
    // leave the row perpetually "due" and double-fire on the next tick. The `interval` kind (default;
    // every pre-existing monitor) is the unchanged `now + clamped_check_period` path; daily/weekly
    // land on their local wall-clock occurrence via the shared `recurrence` helper.
    let next = rfc3339(next_run_for_target(target, now));
    if let Err(e) = targets::set_next_run_at(db, target.id, Some(&next)).await {
        tracing::warn!(target_id = target.id, error = %e, "failed to advance next_run_at");
    }

    // Publish an in-progress marker so the live-activity UI can show this monitor as actively
    // being checked (the closest we get to a real "running" signal — checks write no runs row).
    // It preserves `last_checked_at`/prior result; every exit path below writes a terminal state
    // that overwrites `"checking"`, and readers age out a stale marker via `updated_at`.
    if let Err(e) = monitor_state::mark_checking(db, target.id).await {
        tracing::debug!(target_id = target.id, error = %e, "failed to mark monitor checking");
    }

    // Heal a legacy/imported single-selector content target before building the check model, so a
    // target that only has its top-level `selector` column (no `target_selectors` rows — e.g. a cloud
    // import) actually gets checked instead of comparing an empty selector set forever.
    if let Err(e) = heal_single_selector(db, target).await {
        tracing::warn!(target_id = target.id, error = %e, "single-selector heal failed");
    }

    // Build the cloud check model from the local rows, then run the cloud checker under a timeout.
    let cloud_target = match build_cloud_target(db, target).await {
        Ok(t) => t,
        Err(e) => {
            let msg = format!("could not load monitor config: {e}");
            persist_error(db, target.id, now, &msg).await;
            return CheckOutcome {
                target_id: target.id,
                status: CheckStatus::Error,
                change_id: None,
                dispatch: None,
                error: Some(msg),
            };
        }
    };

    // Resolve the browser handle up front (warming on demand only for browser-path checks), then run
    // the check under a wall-clock budget so a hung target trips a timeout rather than the tick.
    let browser_arc = if cloud_target.needs_browser() {
        browser.get().await
    } else {
        browser.dummy().clone()
    };
    let outcome = {
        let fut = checker.check_target(&cloud_target, &browser_arc);
        match tokio::time::timeout(Duration::from_secs(CHECK_TIMEOUT_SECS), fut).await {
            Ok(o) => o,
            Err(_) => {
                let msg = format!("check timed out after {CHECK_TIMEOUT_SECS}s");
                tracing::warn!(target_id = target.id, "{msg}");
                persist_error(db, target.id, now, &msg).await;
                return CheckOutcome {
                    target_id: target.id,
                    status: CheckStatus::Timeout,
                    change_id: None,
                    dispatch: None,
                    error: Some(msg),
                };
            }
        }
    };

    if target.check_type == "uptime" {
        finalize_uptime(db, target, now, &outcome).await
    } else {
        finalize_content(db, engine, target, now, &cloud_target, &outcome).await
    }
}

/// Record a detected change AND advance the selector's baseline **atomically**, returning the new
/// `changes.id`.
///
/// These two writes carry a single invariant: "a change row exists ⇒ its selector's baseline is the
/// content that change describes". Break it and the diff is re-detected on the next check, a second
/// change row is written, and the user is notified again — every check, indefinitely. SQLite gives us
/// that atomicity for free via a transaction; the previous code used two autocommit statements and
/// discarded the second one's `Result`, so any failure (or a crash in the gap) silently produced the
/// re-notify loop.
async fn commit_change_and_baseline(
    db: &SqlitePool,
    new_change: &changes::NewChange,
    sel_id: i64,
    new_hash: &str,
    content: Option<&str>,
    screenshot: Option<&str>,
) -> LocalResult<i64> {
    let mut tx = db.begin().await?;
    let id = changes::insert_with(&mut *tx, new_change).await?;
    target_selectors::set_baseline_with(&mut *tx, sel_id, Some(new_hash), content, screenshot).await?;
    tx.commit().await?;
    Ok(id)
}

/// Persist a content-check outcome change-only, then dispatch automations on change.
async fn finalize_content(
    db: &SqlitePool,
    engine: &Arc<dyn LocalEngine>,
    target: &targets::Target,
    now: DateTime<Utc>,
    cloud_target: &CloudTarget,
    outcome: &CloudOutcome,
) -> CheckOutcome {
    let now_str = rfc3339(now);

    // A check that produced only error rows (e.g. fetch failed) is an error, not "unchanged".
    let all_errors = !outcome.reports.is_empty()
        && outcome.reports.iter().all(|r| r.error_type.is_some());
    if all_errors {
        let msg = outcome
            .reports
            .iter()
            .find_map(|r| r.error_message.clone())
            .unwrap_or_else(|| "content check failed".into());
        persist_error(db, target.id, now, &msg).await;
        return CheckOutcome {
            target_id: target.id,
            status: CheckStatus::Error,
            change_id: None,
            dispatch: None,
            error: Some(msg),
        };
    }

    // Walk per-selector reports alongside the cloud selectors (same order) so we can update each
    // selector's baseline + last_content_hash and write a change row on a real diff.
    let mut change_id: Option<i64> = None;
    for (sel, report) in cloud_target.selectors.iter().zip(outcome.reports.iter()) {
        let Some(sel_id) = sel.id else { continue };
        if report.error_type.is_some() {
            // selector missing this round — record the check, don't bump change count.
            let _ = target_selectors::record_check(db, sel_id, None, false).await;
            continue;
        }
        let Some(new_hash) = report.content_hash.as_deref() else { continue };
        let had_baseline = sel.baseline_hash.as_deref().is_some_and(|b| !b.is_empty());
        let changed = had_baseline && sel.baseline_hash.as_deref() != Some(new_hash);

        let _ = target_selectors::record_check(db, sel_id, Some(new_hash), changed).await;

        if !had_baseline {
            // First check: seed the baseline, do not emit a change. Persist the report's
            // screenshot too — for a VISUAL selector the content is None and the image IS
            // the baseline, so passing `None` here wiped it (only `capture_*_baselines` had
            // been storing it). Text selectors carry no screenshot, so this is a no-op for them.
            // No change row accompanies this write, so a failure is self-healing (the next check
            // seeds again) — but it must still be VISIBLE rather than dropped on the floor.
            if let Err(e) = target_selectors::set_baseline(
                db,
                sel_id,
                Some(new_hash),
                report.content.as_deref(),
                report.screenshot.as_deref(),
            )
            .await
            {
                tracing::warn!(
                    target_id = target.id,
                    selector_id = sel_id,
                    error = %e,
                    "failed to seed first-check baseline (will retry next check)"
                );
            }
            continue;
        }
        if changed {
            // For a visual change, carry the PRIOR baseline image as "before" so the change
            // feed can show before/after; `sel` (the cloud model) doesn't carry the stored
            // screenshot, so read it from the row before we advance the baseline below.
            let screenshot_before = if report.screenshot.is_some() {
                target_selectors::get_by_id(db, sel_id)
                    .await
                    .ok()
                    .flatten()
                    .and_then(|s| s.baseline_screenshot)
            } else {
                None
            };
            let new_change = changes::NewChange {
                target_id: target.id,
                target_selector_id: Some(sel_id),
                content_hash: new_hash.to_string(),
                previous_hash: sel.baseline_hash.clone(),
                diff_snippet: report.diff_snippet.clone(),
                content_before: report.previous_content.clone(),
                content_after: report.content.clone(),
                screenshot_before,
                screenshot_after: report.screenshot.clone(),
                ..Default::default()
            };
            // The change row and the baseline advance are ONE fact, so they are ONE transaction.
            // Advancing the baseline is what stops this same diff from being re-detected — and
            // re-notified — on every later check. Writing them as two autocommit statements meant a
            // failed (or crash-interrupted) baseline write left a COMMITTED change row behind a stale
            // baseline, so the monitor re-fired the identical change forever. If the pair fails we
            // record NOTHING and leave `change_id` unset: no notification goes out, and the next
            // check re-detects the diff and retries.
            match commit_change_and_baseline(
                db,
                &new_change,
                sel_id,
                new_hash,
                report.content.as_deref(),
                report.screenshot.as_deref(),
            )
            .await
            {
                Ok(id) => change_id.get_or_insert(id),
                Err(e) => {
                    tracing::warn!(
                        target_id = target.id,
                        selector_id = sel_id,
                        error = %e,
                        "change + baseline transaction failed; not recording or notifying this change"
                    );
                    continue;
                }
            };
        }
    }

    let changed = outcome.changed && change_id.is_some();
    let state = if changed { "changed" } else { "unchanged" };
    let _ = monitor_state::upsert(
        db,
        target.id,
        &monitor_state::MonitorStateUpsert {
            checked_at: now_str.clone(),
            state: Some(state.to_string()),
            is_up: Some(1),
            status_code: outcome.reports.iter().find_map(|r| r.status_code),
            last_change_at: if changed { Some(now_str.clone()) } else { None },
        },
    )
    .await;

    if !changed {
        return CheckOutcome {
            target_id: target.id,
            status: CheckStatus::Unchanged,
            change_id: None,
            dispatch: None,
            error: None,
        };
    }

    // Dispatch enabled change_detected automations for THIS target.
    let dispatch = dispatch_change_automations(db, engine, target.id, change_id).await;
    // Independently of automations, deliver the target's own per-monitor direct notifications
    // (best-effort, never fatal). Both paths may fire for one change.
    dispatch_change_direct_notifications(db, target, change_id).await;
    CheckOutcome {
        target_id: target.id,
        status: CheckStatus::Changed,
        change_id,
        dispatch: Some(dispatch),
        error: None,
    }
}

/// Persist an uptime-check outcome: append the sample, upsert live state, classify up/down.
async fn finalize_uptime(
    db: &SqlitePool,
    target: &targets::Target,
    now: DateTime<Utc>,
    outcome: &CloudOutcome,
) -> CheckOutcome {
    let now_str = rfc3339(now);
    let Some(item) = outcome.reports.first() else {
        let msg = "uptime check produced no result".to_string();
        persist_error(db, target.id, now, &msg).await;
        return CheckOutcome {
            target_id: target.id,
            status: CheckStatus::Error,
            change_id: None,
            dispatch: None,
            error: Some(msg),
        };
    };

    let is_up = item.is_up.unwrap_or(false);
    let sample = uptime_checks::NewUptimeCheck {
        target_id: target.id,
        is_up: is_up as i64,
        checked_at: Some(now_str.clone()),
        status_code: item.status_code,
        response_time_ms: item.response_time_ms,
        error_message: item.error_message.clone(),
        ..Default::default()
    };
    let _ = uptime_checks::insert(db, &sample).await;

    // Live-state transition: compare to the prior recorded up/down to flag a change.
    let prior_up = monitor_state::get(db, target.id)
        .await
        .ok()
        .flatten()
        .and_then(|s| s.is_up)
        .map(|v| v != 0);
    let transitioned = prior_up.is_some_and(|p| p != is_up);
    let state = if !is_up { "down" } else if transitioned { "up" } else { "unchanged" };
    let _ = monitor_state::upsert(
        db,
        target.id,
        &monitor_state::MonitorStateUpsert {
            checked_at: now_str.clone(),
            state: Some(state.to_string()),
            is_up: Some(is_up as i64),
            status_code: item.status_code,
            last_change_at: if transitioned { Some(now_str) } else { None },
        },
    )
    .await;

    let status = if !is_up { CheckStatus::Error } else { CheckStatus::Unchanged };
    CheckOutcome {
        target_id: target.id,
        status,
        change_id: None,
        dispatch: None,
        error: if is_up { None } else { item.error_message.clone() },
    }
}

/// Find enabled `change_detected` automations for `target_id` and run each one's workflow through the
/// engine, recording an `automation_executions` row per automation. Returns the dispatch tally.
async fn dispatch_change_automations(
    db: &SqlitePool,
    engine: &Arc<dyn LocalEngine>,
    target_id: i64,
    change_id: Option<i64>,
) -> DispatchOutcome {
    let mut out = DispatchOutcome::default();
    let all = match automations::list_enabled_for_event(db, EVENT_CHANGE_DETECTED, 256).await {
        Ok(v) => v,
        Err(e) => {
            tracing::warn!(target_id, error = %e, "could not load change automations");
            return out;
        }
    };
    // `list_enabled_for_event` is not target-scoped — filter to this target here.
    let matched: Vec<automations::Automation> =
        all.into_iter().filter(|a| a.target_id == Some(target_id)).collect();
    out.matched = matched.len();

    // Build the change scope once — the fields a flow's conditions/blocks read (shared per automation).
    let context = build_change_context(db, target_id, change_id).await;

    for auto in matched {
        // Run the automation's full block tree (conditions, branches, actions). Falls back to the
        // single linked workflow when the automation has no blocks. The interpreter owns the
        // execution-row lifecycle (open → walk → complete).
        let trigger = crate::local::flow::FlowTrigger {
            event: EVENT_CHANGE_DETECTED.to_string(),
            change_id,
            base_inputs: serde_json::json!({}),
            context: context.clone(),
            source: RunSource::Monitor,
            lane: Lane::Background,
        };
        match crate::local::flow::run_automation(db, engine, &auto, trigger).await {
            // Failed iff a workflow action came back not-ok; everything else (incl. notify-only or a
            // gated-off branch) is a clean dispatch.
            Ok(Some(exec)) if exec.status.as_deref() == Some("failed") => out.failed += 1,
            Ok(_) => out.succeeded += 1,
            Err(e) => {
                tracing::warn!(automation_id = auto.id, error = %e, "automation flow run failed");
                out.failed += 1;
            }
        }
    }
    out
}

/// Deliver THIS target's own per-monitor direct notifications for a confirmed change — a separate
/// concern from `dispatch_change_automations`, keyed off the target's `notification_providers` map.
/// Best-effort and non-fatal: all delivery lives in `flow::dispatch_direct_notifications`, which
/// logs and swallows any error so it can never break the monitor run. No-op when the target has no
/// enabled providers.
async fn dispatch_change_direct_notifications(
    db: &SqlitePool,
    target: &targets::Target,
    change_id: Option<i64>,
) {
    // Cheap gate: skip building the scope + touching the DB when nothing is configured.
    if target.notification_providers.as_deref().map(str::trim).is_none_or(str::is_empty) {
        return;
    }

    // Minimal render scope from data on hand at the dispatch site: the target url (also used as its
    // display name — desktop targets carry no separate `name`) plus any change fields.
    let mut scope = serde_json::Map::new();
    scope.insert("url".into(), serde_json::Value::String(target.url.clone()));
    scope.insert("target_name".into(), serde_json::Value::String(target.url.clone()));
    scope.insert("target_id".into(), serde_json::Value::from(target.id));
    if let Some(cid) = change_id {
        scope.insert("change_id".into(), serde_json::Value::from(cid));
        if let Ok(Some(change)) = changes::get_by_id(db, cid).await {
            if let Some(diff) = change.diff_snippet {
                scope.insert("diff_snippet".into(), serde_json::Value::String(diff));
            }
            if let Some(content) = change.content_after {
                scope.insert("content".into(), serde_json::Value::String(content));
            }
        }
    }

    crate::local::flow::dispatch_direct_notifications(
        db,
        target.notification_providers.as_deref(),
        target.notification_title.as_deref(),
        target.notification_message.as_deref(),
        &scope,
    )
    .await;
}

// ---------------------------------------------------------------------------------------------
// Monitor-HEALTH automations (down / stale / recovered) — the health-edge sibling of the
// change_detected dispatch above.
// ---------------------------------------------------------------------------------------------

/// The health event to fire for a `prior → this-check` state transition, or `None` when no
/// healthy↔unhealthy boundary was crossed (incl. the first-ever check and a `Skipped` check).
/// The transient `"checking"` marker is never the prior we capture (we read it before mark_checking).
fn classify_health_edge(prior: Option<&str>, status: CheckStatus) -> Option<&'static str> {
    let now_unhealthy = matches!(status, CheckStatus::Error | CheckStatus::Timeout);
    let now_healthy = matches!(status, CheckStatus::Changed | CheckStatus::Unchanged);
    let prior_healthy = matches!(prior, Some("unchanged" | "changed" | "up" | "ok"));
    let prior_unhealthy = matches!(prior, Some("error" | "down" | "stale"));
    if now_unhealthy && prior_healthy {
        Some(EVENT_MONITOR_DOWN)
    } else if now_healthy && prior_unhealthy {
        Some(EVENT_MONITOR_RECOVERED)
    } else {
        None
    }
}

/// Fire down/recovered automations when a check crosses a health edge. No-op otherwise (the common
/// steady-state case), so it costs only the cheap `classify_health_edge` on every check.
async fn maybe_dispatch_health_edge(
    db: &SqlitePool,
    engine: &Arc<dyn LocalEngine>,
    target: &targets::Target,
    prior: Option<&str>,
    status: CheckStatus,
) {
    if let Some(event) = classify_health_edge(prior, status) {
        let _ = dispatch_health_automations(db, engine, target, event).await;
    }
}

/// Run enabled `event` (monitor_down/stale/recovered) automations bound to `target`. Mirrors
/// `dispatch_change_automations`: target-scoped, one `automation_executions` row per automation via
/// the flow interpreter (which owns guardrails + the execution lifecycle).
async fn dispatch_health_automations(
    db: &SqlitePool,
    engine: &Arc<dyn LocalEngine>,
    target: &targets::Target,
    event: &str,
) -> DispatchOutcome {
    let mut out = DispatchOutcome::default();
    let all = match automations::list_enabled_for_event(db, event, 256).await {
        Ok(v) => v,
        Err(e) => {
            tracing::warn!(target_id = target.id, event, error = %e, "could not load health automations");
            return out;
        }
    };
    let matched: Vec<automations::Automation> =
        all.into_iter().filter(|a| a.target_id == Some(target.id)).collect();
    out.matched = matched.len();
    if matched.is_empty() {
        return out;
    }

    let context = build_health_context(target, event);
    for auto in matched {
        let trigger = crate::local::flow::FlowTrigger {
            event: event.to_string(),
            change_id: None,
            base_inputs: serde_json::json!({}),
            context: context.clone(),
            source: RunSource::Monitor,
            lane: Lane::Background,
        };
        match crate::local::flow::run_automation(db, engine, &auto, trigger).await {
            Ok(Some(exec)) if exec.status.as_deref() == Some("failed") => out.failed += 1,
            Ok(_) => out.succeeded += 1,
            Err(e) => {
                tracing::warn!(automation_id = auto.id, error = %e, "health automation flow run failed");
                out.failed += 1;
            }
        }
    }
    tracing::info!(target_id = target.id, event, matched = out.matched, "dispatched monitor-health automations");
    out
}

/// The scope a monitor-health flow sees: the event, the target ids/url, and the resulting state.
fn build_health_context(target: &targets::Target, event: &str) -> serde_json::Value {
    let state = match event {
        EVENT_MONITOR_RECOVERED => "ok",
        EVENT_MONITOR_STALE => "stale",
        _ => "down",
    };
    serde_json::json!({
        "event": event,
        "target_id": target.id,
        "target_name": target.url,
        "url": target.url,
        "state": state,
    })
}

/// Fire `monitor_stale` for targets whose last check is well past their expected cadence (× 2.5,
/// matching the read-time staleness used elsewhere). Scoped to targets that actually have an enabled
/// `monitor_stale` automation, so it's cheap. Marks the target `state = "stale"` so the edge fires
/// once; the next successful check recovers it (`classify_health_edge` treats `"stale"` as unhealthy).
pub async fn sweep_stale_health(
    db: &SqlitePool,
    engine: &Arc<dyn LocalEngine>,
    now: DateTime<Utc>,
) -> DispatchOutcome {
    let mut out = DispatchOutcome::default();
    let autos = match automations::list_enabled_for_event(db, EVENT_MONITOR_STALE, 256).await {
        Ok(v) => v,
        Err(_) => return out,
    };
    if autos.is_empty() {
        return out;
    }

    let mut target_ids: Vec<i64> = autos.iter().filter_map(|a| a.target_id).collect();
    target_ids.sort_unstable();
    target_ids.dedup();

    let now_ms = now.timestamp_millis();
    for tid in target_ids {
        let Some(target) = targets::get_by_id(db, tid).await.ok().flatten() else { continue };
        if target.enabled == 0 {
            continue; // a paused monitor isn't "stale"
        }
        let Some(st) = monitor_state::get(db, tid).await.ok().flatten() else { continue };
        let state = st.state.as_deref().unwrap_or("");
        // Already unhealthy (don't re-fire) or never actually checked (empty checked_at).
        if matches!(state, "stale" | "down" | "error") || st.checked_at.is_empty() {
            continue;
        }
        let Ok(checked) = DateTime::parse_from_rfc3339(&st.checked_at) else { continue };
        let expected = effective_interval_ms(&target).max(MIN_CHECK_INTERVAL_MS);
        if (now_ms - checked.timestamp_millis()) as f64 > expected as f64 * 2.5 {
            let _ = monitor_state::upsert(
                db,
                tid,
                &monitor_state::MonitorStateUpsert {
                    checked_at: st.checked_at.clone(),
                    state: Some("stale".to_string()),
                    is_up: st.is_up,
                    status_code: st.status_code,
                    last_change_at: Some(rfc3339(now)),
                },
            )
            .await;
            let d = dispatch_health_automations(db, engine, &target, EVENT_MONITOR_STALE).await;
            out.matched += d.matched;
            out.succeeded += d.succeeded;
            out.failed += d.failed;
        }
    }
    out
}

/// Assemble the scope a `change_detected` flow sees: the event + ids, plus the change's diff snippet,
/// new content, and changed-selector name when a change row is available. Best-effort — a missing or
/// unreadable change/selector simply omits those fields (never fails the dispatch).
async fn build_change_context(
    db: &SqlitePool,
    target_id: i64,
    change_id: Option<i64>,
) -> serde_json::Value {
    let mut ctx = serde_json::json!({
        "event": EVENT_CHANGE_DETECTED,
        "target_id": target_id,
        "change_id": change_id,
    });
    let obj = ctx.as_object_mut().expect("json object");
    if let Some(cid) = change_id {
        if let Ok(Some(change)) = changes::get_by_id(db, cid).await {
            if let Some(diff) = change.diff_snippet {
                obj.insert("diff_snippet".into(), serde_json::Value::String(diff));
            }
            if let Some(content) = change.content_after {
                obj.insert("content".into(), serde_json::Value::String(content));
            }
            if let Some(sel_id) = change.target_selector_id {
                if let Ok(Some(sel)) = target_selectors::get_by_id(db, sel_id).await {
                    obj.insert("selector_name".into(), serde_json::Value::String(sel.name));
                }
            }
        }
    }
    ctx
}

// ---------------------------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------------------------

/// True when at least [`MIN_CHECK_INTERVAL_MS`] has elapsed since this target's last recorded
/// `monitor_state.checked_at` (or it has never been checked). Fail-open: an unreadable/unparseable
/// timestamp permits the check (the schedule's `next_run_at` is the primary gate).
async fn floor_cleared(db: &SqlitePool, target_id: i64, now: DateTime<Utc>) -> LocalResult<bool> {
    let Some(state) = monitor_state::get(db, target_id).await? else {
        return Ok(true);
    };
    let Some(last) = parse_rfc3339(&state.checked_at) else {
        return Ok(true);
    };
    let elapsed = now.signed_duration_since(last).num_milliseconds();
    Ok(elapsed >= MIN_CHECK_INTERVAL_MS)
}

/// The effective check interval in ms: the target's `check_period_ms` clamped up to the
/// anti-detection floor (defaulted to the floor when unset/non-positive). The floor is selected by
/// `requires_playwright` via the shared [`clamp`](crate::local::scheduler::clamp) module — the SAME
/// definition used at SAVE time — so the browser-path (JS) floor and the HTTP-path (HTML) floor can
/// never drift between the two call sites.
fn effective_interval_ms(target: &targets::Target) -> i64 {
    crate::local::scheduler::clamp::clamp_monitor_interval_ms(
        target.check_period_ms,
        target.requires_playwright != 0,
    )
}

/// The next `next_run_at` for a monitor target. The `interval` kind (default; every pre-existing
/// monitor) keeps the anti-detection-clamped `check_period_ms` cadence (60s HTML / 300s JS floor via
/// the shared `clamp` — the SAME floor drift-free with SAVE time). `daily`/`weekly` compute their
/// local wall-clock occurrence via the shared `recurrence` helper and BYPASS the floor (they are ≥
/// 1/day and so trivially clear the anti-detection cadence).
fn next_run_for_target(target: &targets::Target, now: DateTime<Utc>) -> DateTime<Utc> {
    use crate::local::scheduler::recurrence::{self, Kind, Recurrence};
    let r = Recurrence::from_columns(
        target.schedule_kind.as_deref(),
        target.check_period_ms.unwrap_or(0),
        target.schedule_time.as_deref(),
        target.schedule_days.as_deref(),
        target.schedule_tz.as_deref(),
    );
    match r.kind {
        Kind::Interval => now + chrono::Duration::milliseconds(effective_interval_ms(target)),
        Kind::Daily | Kind::Weekly => recurrence::next_run(&r, now),
    }
}

/// Map stored selector rows → the cloud checker's selector model, carrying their stored baselines.
fn to_cloud_selectors(rows: Vec<target_selectors::TargetSelector>) -> Vec<CloudSelector> {
    rows.into_iter()
        .map(|s| CloudSelector {
            id: Some(s.id),
            name: Some(s.name),
            selector: s.selector,
            content_type: s.content_type.unwrap_or_else(|| "text".into()),
            ignore_regex: s.ignore_regex,
            baseline_hash: s.baseline_hash,
            baseline_content: s.baseline_content,
            visual_region: s
                .visual_region
                .as_deref()
                .and_then(|v| serde_json::from_str(v).ok()),
        })
        .collect()
}

/// Assemble the cloud [`CloudTarget`] from a local target row + a prepared selector list.
fn assemble_cloud_target(target: &targets::Target, selectors: Vec<CloudSelector>) -> CloudTarget {
    CloudTarget {
        id: Some(target.id),
        url: target.url.clone(),
        check_type: target.check_type.clone(),
        check_period_ms: target.check_period_ms,
        requires_playwright: target.requires_playwright != 0,
        // Inline setup-steps manifest (recorded login/navigate/click steps): the shared checker
        // replays these in the browser BEFORE the content read. Its presence also forces the browser
        // path via `CloudTarget::needs_browser()`. Absent/unparseable → a plain check (no setup).
        pre_check_workflow: target
            .setup_steps
            .as_deref()
            .filter(|s| !s.trim().is_empty() && s.trim() != "null")
            .and_then(|s| serde_json::from_str(s).ok()),
        auth_session: None,
        timeout_ms: target.timeout_ms,
        expected_status_code: target.expected_status_code,
        check_ssl: target.check_ssl.map(|v| v != 0).unwrap_or(true),
        selectors,
    }
}

/// Heal a legacy/imported content target that has a top-level `selector` but no `target_selectors`
/// rows: materialize ONE real selector row from `target.selector` so the check has a persisted
/// selector to baseline + diff against (the check pipeline reads ONLY `target_selectors`, never the
/// target's own `selector` column). Idempotent — a no-op once any selector row exists, for uptime
/// targets, or when `selector` is empty. This is what makes cloud-imported single-selector monitors
/// start producing change detection without a re-sync.
async fn heal_single_selector(db: &SqlitePool, target: &targets::Target) -> LocalResult<()> {
    if target.check_type == "uptime" {
        return Ok(());
    }
    let selector = target.selector.as_deref().map(str::trim).unwrap_or("");
    if selector.is_empty() {
        return Ok(());
    }
    if target_selectors::count_by_target(db, target.id).await? > 0 {
        return Ok(());
    }
    let new = target_selectors::NewTargetSelector {
        target_id: target.id,
        name: "Content".to_string(),
        selector: selector.to_string(),
        ignore_regex: target.ignore_regex.clone(),
        ..Default::default()
    };
    target_selectors::insert(db, &new).await?;
    tracing::info!(
        target_id = target.id,
        "materialized legacy single-selector into a target_selectors row"
    );
    Ok(())
}

/// Build the cloud [`CloudTarget`] (the checker's input) from the local target row + its enabled
/// selectors with their stored baselines. For uptime targets the selector list is empty.
async fn build_cloud_target(db: &SqlitePool, target: &targets::Target) -> LocalResult<CloudTarget> {
    let selectors = if target.check_type == "uptime" {
        Vec::new()
    } else {
        to_cloud_selectors(target_selectors::list_enabled_by_target(db, target.id).await?)
    };
    Ok(assemble_cloud_target(target, selectors))
}

/// Record a failed check into live state (`state = "error"`), preserving `last_change_at`.
async fn persist_error(db: &SqlitePool, target_id: i64, now: DateTime<Utc>, msg: &str) {
    let _ = monitor_state::upsert(
        db,
        target_id,
        &monitor_state::MonitorStateUpsert {
            checked_at: rfc3339(now),
            state: Some("error".into()),
            is_up: Some(0),
            status_code: None,
            last_change_at: None,
        },
    )
    .await;
    tracing::warn!(target_id, error = %msg, "monitor check failed");
}

/// Canonical RFC3339 with millisecond precision and a `Z` suffix — matches the schema's
/// `strftime('%Y-%m-%dT%H:%M:%fZ','now')` so string comparisons against `next_run_at` are ordered.
fn rfc3339(t: DateTime<Utc>) -> String {
    t.format("%Y-%m-%dT%H:%M:%S%.3fZ").to_string()
}

/// Lenient RFC3339 parse for stored timestamps (handles the `Z` and millisecond forms we write).
fn parse_rfc3339(s: &str) -> Option<DateTime<Utc>> {
    DateTime::parse_from_rfc3339(s).ok().map(|dt| dt.with_timezone(&Utc))
}

/// A browser manager built lazily on first browser-path check (most local monitors are plain HTTP).
/// Owns a single `BrowserManager` shared across the tick once warmed. The `dummy()` handle satisfies
/// the cloud checker's `&Arc<BrowserManager>` parameter for HTTP-path checks that never touch it.
struct LazyBrowser {
    inner: tokio::sync::OnceCell<Arc<crate::browser::manager::BrowserManager>>,
    dummy: Arc<crate::browser::manager::BrowserManager>,
}

impl LazyBrowser {
    fn new() -> Self {
        let dummy = Arc::new(crate::browser::manager::BrowserManager::new(Arc::new(
            AppConfig::from_env(),
        )));
        Self { inner: tokio::sync::OnceCell::new(), dummy }
    }

    /// The shared (warmed-on-demand) browser for JS/auth/visual checks.
    async fn get(&self) -> Arc<crate::browser::manager::BrowserManager> {
        self.inner
            .get_or_init(|| async {
                Arc::new(crate::browser::manager::BrowserManager::new(Arc::new(
                    AppConfig::from_env(),
                )))
            })
            .await
            .clone()
    }

    /// An unwarmed handle for HTTP-path checks (the cloud checker takes the arg but never drives it
    /// when `needs_browser()` is false).
    fn dummy(&self) -> &Arc<crate::browser::manager::BrowserManager> {
        &self.dummy
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::local::engine::StubEngine;
    use crate::local::store::{automation_executions, automations, target_selectors, targets};
    use crate::local::{db, vault};

    /// A fresh encrypted DB over a file-backed vault (no keyring prompt) + a stub engine arc.
    async fn fixture() -> (SqlitePool, Arc<dyn LocalEngine>) {
        let dir = Box::leak(Box::new(tempfile::tempdir().unwrap()));
        let v = vault::Vault::load_or_create(dir.path(), false).unwrap();
        let pool = db::open(&dir.path().join("t.db"), &v.db_key_hex()).await.unwrap();
        let engine: Arc<dyn LocalEngine> = Arc::new(StubEngine);
        (pool, engine)
    }

    fn ago(ms: i64) -> DateTime<Utc> {
        Utc::now() - chrono::Duration::milliseconds(ms)
    }

    // ------------------------------------------------------------------
    // The change row + baseline advance must be ATOMIC.
    // ------------------------------------------------------------------

    /// Seed a content target with one selector that already has a baseline, returning both ids.
    async fn seed_target_with_baselined_selector(pool: &SqlitePool) -> (i64, i64) {
        let target_id = targets::insert(
            pool,
            &targets::NewTarget {
                url: "https://example.test/watch".into(),
                check_type: Some("content".into()),
                ..Default::default()
            },
        )
        .await
        .unwrap();
        let sel_id = target_selectors::insert(
            pool,
            &target_selectors::NewTargetSelector {
                target_id,
                name: "price".into(),
                selector: ".price".into(),
                ..Default::default()
            },
        )
        .await
        .unwrap();
        target_selectors::set_baseline(pool, sel_id, Some("old-hash"), Some("$9"), None)
            .await
            .unwrap();
        (target_id, sel_id)
    }

    #[tokio::test]
    async fn change_and_baseline_commit_together() {
        let (pool, _engine) = fixture().await;
        let (target_id, sel_id) = seed_target_with_baselined_selector(&pool).await;

        let new_change = changes::NewChange {
            target_id,
            target_selector_id: Some(sel_id),
            content_hash: "new-hash".into(),
            previous_hash: Some("old-hash".into()),
            content_after: Some("$7".into()),
            ..Default::default()
        };
        let id = commit_change_and_baseline(&pool, &new_change, sel_id, "new-hash", Some("$7"), None)
            .await
            .unwrap();

        assert!(id > 0);
        assert_eq!(changes::list_by_target(&pool, target_id, 10).await.unwrap().len(), 1);
        let sel = target_selectors::get_by_id(&pool, sel_id).await.unwrap().unwrap();
        assert_eq!(
            sel.baseline_hash.as_deref(),
            Some("new-hash"),
            "baseline must have advanced with the change row"
        );
    }

    /// THE REGRESSION: when the baseline advance fails, the change row must NOT be committed. A
    /// committed change behind a stale baseline is re-detected and re-notified on every later check.
    ///
    /// The failure is induced the only way SQLite lets us induce one on an `UPDATE ... WHERE id = ?`
    /// without touching a migration: a temporary UNIQUE index over `baseline_hash`, so advancing a
    /// second selector to a hash another selector already holds raises SQLITE_CONSTRAINT_UNIQUE.
    #[tokio::test]
    async fn failed_baseline_write_rolls_back_the_change_row() {
        let (pool, _engine) = fixture().await;
        // `sel_a` already holds baseline "old-hash"; the unique index below makes that hash a trap.
        let (target_id, _sel_a) = seed_target_with_baselined_selector(&pool).await;
        let sel_b = target_selectors::insert(
            &pool,
            &target_selectors::NewTargetSelector {
                target_id,
                name: "stock".into(),
                selector: ".stock".into(),
                ..Default::default()
            },
        )
        .await
        .unwrap();
        target_selectors::set_baseline(&pool, sel_b, Some("b-hash"), Some("in stock"), None)
            .await
            .unwrap();

        sqlx::query("CREATE UNIQUE INDEX tmp_unique_baseline ON target_selectors(baseline_hash)")
            .execute(&pool)
            .await
            .unwrap();

        // Advancing sel_b onto sel_a's hash now violates the temporary unique index.
        let new_change = changes::NewChange {
            target_id,
            target_selector_id: Some(sel_b),
            content_hash: "old-hash".into(),
            previous_hash: Some("b-hash".into()),
            ..Default::default()
        };
        let err = commit_change_and_baseline(&pool, &new_change, sel_b, "old-hash", None, None).await;
        assert!(err.is_err(), "the baseline write must have failed");

        sqlx::query("DROP INDEX tmp_unique_baseline").execute(&pool).await.unwrap();

        assert_eq!(
            changes::list_by_target(&pool, target_id, 10).await.unwrap().len(),
            0,
            "the change row must have rolled back with the failed baseline write"
        );
        let b = target_selectors::get_by_id(&pool, sel_b).await.unwrap().unwrap();
        assert_eq!(b.baseline_hash.as_deref(), Some("b-hash"), "baseline unchanged");
    }

    #[test]
    fn rfc3339_roundtrips_and_orders() {
        let t = Utc::now();
        let s = rfc3339(t);
        assert!(s.ends_with('Z') && s.contains('T'));
        let back = parse_rfc3339(&s).unwrap();
        // millisecond precision: within 1ms of the original
        assert!((t - back).num_milliseconds().abs() <= 1);
    }

    #[test]
    fn interval_respects_floor() {
        let mut t = targets::Target {
            id: 1,
            url: "https://x".into(),
            check_type: "content".into(),
            selector: None,
            ignore_regex: None,
            check_period_ms: Some(1_000), // below floor
            expected_status_code: None,
            timeout_ms: None,
            max_response_time_ms: None,
            check_ssl: None,
            enabled: 1,
            requires_playwright: 0,
            baseline_hash: None,
            baseline_content: None,
            baseline_fetched_at: None,
            pre_check_workflow_id: None,
            setup_steps: None,
            on_change_workflow_id: None,
            on_change_enabled: 0,
            on_change_conditions: None,
            on_change_in_session: 0,
            persona_id: None,
            auth_session_encrypted: None,
            notification_providers: None,
            provider_notification_settings: None,
            notification_title: None,
            notification_message: None,
            notification_priority: None,
            next_run_at: None,
            schedule_kind: None,
            schedule_time: None,
            schedule_days: None,
            schedule_tz: None,
            created_at: "x".into(),
            updated_at: None,
        };
        assert_eq!(effective_interval_ms(&t), MIN_CHECK_INTERVAL_MS);
        t.check_period_ms = Some(120_000);
        assert_eq!(effective_interval_ms(&t), 120_000);
        t.check_period_ms = None;
        assert_eq!(effective_interval_ms(&t), MIN_CHECK_INTERVAL_MS);
    }

    #[test]
    fn panic_message_reads_str_and_string_payloads() {
        let s: Box<dyn std::any::Any + Send> = Box::new("boom");
        assert_eq!(panic_message(s.as_ref()), "boom");
        let s: Box<dyn std::any::Any + Send> = Box::new(String::from("formatted boom"));
        assert_eq!(panic_message(s.as_ref()), "formatted boom");
        let s: Box<dyn std::any::Any + Send> = Box::new(42u8);
        assert_eq!(panic_message(s.as_ref()), "unknown panic");
    }

    /// The per-target isolation mechanism itself: `AssertUnwindSafe(..).catch_unwind()` must turn a
    /// panic inside ONE check into a value the loop can record, instead of unwinding the whole tick.
    ///
    /// This also guards the build configuration: if a profile ever switched to `panic = "abort"`, the
    /// isolation would silently stop working and this test would take the runner down with it.
    #[tokio::test]
    async fn a_panicking_check_future_is_caught_not_propagated() {
        use futures_util::FutureExt;
        let fut = std::panic::AssertUnwindSafe(async {
            // An await point BEFORE the panic, so this exercises the real shape (a panic part-way
            // through an async check) rather than a panic in a synchronous prologue.
            tokio::task::yield_now().await;
            panic!("hostile page content");
        });
        let caught = fut.catch_unwind().await;
        let payload = caught.expect_err("panic should have been caught");
        assert_eq!(panic_message(payload.as_ref()), "hostile page content");
    }

    /// A content target with a top-level `selector` but no `target_selectors` rows (the cloud-import
    /// shape) gets exactly one selector row materialized, idempotently. Uptime targets are untouched.
    #[tokio::test]
    async fn heal_materializes_single_selector_once() {
        let (pool, _eng) = fixture().await;
        let tid = targets::insert(
            &pool,
            &targets::NewTarget {
                url: "https://heal.test".into(),
                check_type: Some("content".into()),
                selector: Some(".price".into()),
                ..Default::default()
            },
        )
        .await
        .unwrap();
        let target = targets::get_by_id(&pool, tid).await.unwrap().unwrap();

        assert_eq!(target_selectors::count_by_target(&pool, tid).await.unwrap(), 0);
        heal_single_selector(&pool, &target).await.unwrap();
        assert_eq!(target_selectors::count_by_target(&pool, tid).await.unwrap(), 1);
        // Idempotent.
        heal_single_selector(&pool, &target).await.unwrap();
        assert_eq!(target_selectors::count_by_target(&pool, tid).await.unwrap(), 1);

        // Uptime target → never materializes a selector.
        let uid = targets::insert(
            &pool,
            &targets::NewTarget {
                url: "https://up.test".into(),
                check_type: Some("uptime".into()),
                ..Default::default()
            },
        )
        .await
        .unwrap();
        let ut = targets::get_by_id(&pool, uid).await.unwrap().unwrap();
        heal_single_selector(&pool, &ut).await.unwrap();
        assert_eq!(target_selectors::count_by_target(&pool, uid).await.unwrap(), 0);
    }

    /// A target with `next_run_at` in the future is NOT due-selected; one due/unset IS.
    #[tokio::test]
    async fn due_selection_respects_next_run_at() {
        let (pool, _eng) = fixture().await;
        // Due (next_run_at unset).
        let due_id = targets::insert(
            &pool,
            &NewTargetShim::content("https://example.test/due", None),
        )
        .await
        .unwrap();
        // Not due (next_run_at far in the future).
        let future_id = targets::insert(
            &pool,
            &NewTargetShim::content("https://example.test/future", Some(rfc3339(Utc::now() + chrono::Duration::hours(1)))),
        )
        .await
        .unwrap();

        let now = Utc::now();
        let selected = targets::list_due(&pool, &rfc3339(now), 100).await.unwrap();
        let ids: Vec<i64> = selected.iter().map(|t| t.id).collect();
        assert!(ids.contains(&due_id), "unset next_run_at must be due");
        assert!(!ids.contains(&future_id), "future next_run_at must not be due");
    }

    /// The 60s floor blocks a re-check when a fresh monitor_state row exists; an old/absent one lets
    /// it through.
    #[tokio::test]
    async fn anti_detection_floor_blocks_recent_checks() {
        let (pool, _eng) = fixture().await;
        let id = targets::insert(&pool, &NewTargetShim::content("https://example.test/floor", None))
            .await
            .unwrap();
        let now = Utc::now();

        // Never checked → floor cleared.
        assert!(floor_cleared(&pool, id, now).await.unwrap());

        // Checked 10s ago → floor NOT cleared.
        monitor_state::upsert(
            &pool,
            id,
            &monitor_state::MonitorStateUpsert {
                checked_at: rfc3339(ago(10_000)),
                state: Some("unchanged".into()),
                is_up: Some(1),
                status_code: Some(200),
                last_change_at: None,
            },
        )
        .await
        .unwrap();
        assert!(!floor_cleared(&pool, id, now).await.unwrap(), "10s < 60s floor must block");

        // Checked 61s ago → floor cleared.
        monitor_state::upsert(
            &pool,
            id,
            &monitor_state::MonitorStateUpsert {
                checked_at: rfc3339(ago(61_000)),
                state: Some("unchanged".into()),
                is_up: Some(1),
                status_code: Some(200),
                last_change_at: None,
            },
        )
        .await
        .unwrap();
        assert!(floor_cleared(&pool, id, now).await.unwrap(), "61s >= 60s floor must clear");
    }

    /// Change-only persistence for a content selector: first check seeds the baseline (no change
    /// row); a differing hash on a later check writes exactly one change row, upserts live state to
    /// "changed", and fires the matching automation. We drive finalize_content directly with a
    /// hand-built CloudOutcome so the test needs no network/browser.
    #[tokio::test]
    async fn change_only_persistence_and_dispatch() {
        let (pool, eng) = fixture().await;
        let now = Utc::now();

        let tid = targets::insert(&pool, &NewTargetShim::content("https://example.test/c", None))
            .await
            .unwrap();
        let sid = target_selectors::insert(
            &pool,
            &target_selectors::NewTargetSelector {
                target_id: tid,
                name: "price".into(),
                selector: ".price".into(),
                ..Default::default()
            },
        )
        .await
        .unwrap();
        // An enabled change_detected automation on THIS target (workflow_id absent → noop success).
        let _auto = automations::insert(
            &pool,
            &automations::NewAutomation {
                name: "on price change".into(),
                event_type: Some("change_detected".into()),
                target_id: Some(tid),
                enabled: Some(1),
                ..Default::default()
            },
        )
        .await
        .unwrap();

        let target = targets::get_by_id(&pool, tid).await.unwrap().unwrap();

        // --- First check: hash "AAA", no baseline yet → seeds baseline, Unchanged, no change row.
        let cloud1 = build_cloud_target(&pool, &target).await.unwrap();
        let outcome1 = synthetic_outcome(sid, "A".repeat(64).as_str(), None, false);
        let res1 = finalize_content(&pool, &eng, &target, now, &cloud1, &outcome1).await;
        assert_eq!(res1.status, CheckStatus::Unchanged, "first check seeds baseline, not a change");
        assert_eq!(changes::count_by_target(&pool, tid).await.unwrap(), 0);
        let seeded = target_selectors::get_by_id(&pool, sid).await.unwrap().unwrap();
        assert_eq!(seeded.baseline_hash.as_deref(), Some("A".repeat(64).as_str()));

        // --- Second check: hash "BBB" differs from baseline → one change row, Changed, dispatch.
        let target2 = targets::get_by_id(&pool, tid).await.unwrap().unwrap();
        let cloud2 = build_cloud_target(&pool, &target2).await.unwrap();
        let outcome2 = synthetic_outcome(sid, "B".repeat(64).as_str(), Some("old"), true);
        let res2 = finalize_content(&pool, &eng, &target2, now, &cloud2, &outcome2).await;
        assert_eq!(res2.status, CheckStatus::Changed);
        assert!(res2.change_id.is_some());
        assert_eq!(changes::count_by_target(&pool, tid).await.unwrap(), 1, "exactly one change row");

        // The automation fired (noop-success because the automation carries no workflow_id).
        let dispatch = res2.dispatch.expect("dispatch tally present on change");
        assert_eq!(dispatch.matched, 1, "the target-scoped automation matched");
        assert_eq!(dispatch.succeeded, 1);
        let execs = automation_executions::list(&pool, 10).await.unwrap();
        assert_eq!(execs.len(), 1, "one automation_executions row recorded");
        assert_eq!(execs[0].status.as_deref(), Some("success"));

        // Live state reflects the change.
        let state = monitor_state::get(&pool, tid).await.unwrap().unwrap();
        assert_eq!(state.state.as_deref(), Some("changed"));
        assert!(state.last_change_at.is_some());

        // --- Third check: same hash "BBB" as the (advanced) baseline → Unchanged, still one change.
        let target3 = targets::get_by_id(&pool, tid).await.unwrap().unwrap();
        let cloud3 = build_cloud_target(&pool, &target3).await.unwrap();
        let outcome3 = synthetic_outcome(sid, "B".repeat(64).as_str(), None, false);
        let res3 = finalize_content(&pool, &eng, &target3, now, &cloud3, &outcome3).await;
        assert_eq!(res3.status, CheckStatus::Unchanged, "same hash as baseline is not a change");
        assert_eq!(changes::count_by_target(&pool, tid).await.unwrap(), 1, "no new change row");
    }

    /// A change on a target with NO matching automation still records the change but dispatches none.
    #[tokio::test]
    async fn change_with_no_automation_dispatches_none() {
        let (pool, eng) = fixture().await;
        let now = Utc::now();
        let tid = targets::insert(&pool, &NewTargetShim::content("https://example.test/n", None))
            .await
            .unwrap();
        let sid = target_selectors::insert(
            &pool,
            &target_selectors::NewTargetSelector {
                target_id: tid,
                name: "x".into(),
                selector: ".x".into(),
                ..Default::default()
            },
        )
        .await
        .unwrap();
        // Seed baseline.
        target_selectors::set_baseline(&pool, sid, Some("A".repeat(64).as_str()), Some("a"), None)
            .await
            .unwrap();

        let target = targets::get_by_id(&pool, tid).await.unwrap().unwrap();
        let cloud = build_cloud_target(&pool, &target).await.unwrap();
        let outcome = synthetic_outcome(sid, "C".repeat(64).as_str(), Some("a"), true);
        let res = finalize_content(&pool, &eng, &target, now, &cloud, &outcome).await;
        assert_eq!(res.status, CheckStatus::Changed);
        assert_eq!(res.dispatch.unwrap().matched, 0, "no automation on this target");
        assert_eq!(automation_executions::list(&pool, 10).await.unwrap().len(), 0);
    }

    // --- test-only constructors -------------------------------------------------------------

    /// Tiny builder over `targets::NewTarget` for tests (keeps the call sites terse).
    struct NewTargetShim;
    impl NewTargetShim {
        fn content(url: &str, next_run_at: Option<String>) -> targets::NewTarget {
            targets::NewTarget {
                url: url.into(),
                check_type: Some("content".into()),
                next_run_at,
                ..Default::default()
            }
        }
    }

    /// Build a one-selector content `CloudOutcome` without touching the network: a single report row
    /// carrying `content_hash`, optional `previous_content`, and the `changed` flag.
    fn synthetic_outcome(
        selector_id: i64,
        hash: &str,
        previous_content: Option<&str>,
        changed: bool,
    ) -> CloudOutcome {
        use crate::monitor::models::ReportItem;
        CloudOutcome {
            reports: vec![ReportItem {
                target_url: "https://example.test".into(),
                check_type: "content".into(),
                target_id: Some(1),
                selector_id: Some(selector_id),
                selector_name: Some("s".into()),
                content_hash: Some(hash.to_string()),
                content: Some(format!("content-{hash}")),
                previous_content: previous_content.map(|s| s.to_string()),
                diff_snippet: if changed { Some("- old\n+ new".into()) } else { None },
                status_code: Some(200),
                ..Default::default()
            }],
            auth_session: None,
            changed,
        }
    }
}
