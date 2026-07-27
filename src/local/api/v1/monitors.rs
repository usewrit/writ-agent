//! `/v1/monitors` REST handlers — CRUD over the `targets` table (route alias only; the physical
//! table is `targets`). House style: thin handlers over `store::targets`, `LocalResult<Json<_>>`
//! with `?` propagation, no auth layer here (server.rs applies the loopback bearer middleware).
//!
//! Per-monitor selectors + their field extractors live in the sibling `selectors` / `extractors`
//! route modules (`/v1/monitors/:id/selectors`, `/v1/extractors`). `POST /v1/monitors/:id/run` runs
//! the check NOW through the shared monitor runner and returns the [`CheckOutcome`].

use crate::local::error::{LocalError, LocalResult};
use crate::local::scheduler::{capacity, clamp};
use crate::local::server::AppState;
use crate::local::store::monitor_state::MonitorState;
use crate::local::store::targets::{self, NewTarget, Target, TargetUpdate};
use crate::local::store::{changes, monitor_state, target_selectors, uptime_checks};
use axum::extract::{Path, Query, State};
use axum::routing::{get, post};
use axum::{Json, Router};
use serde::Deserialize;
use serde_json::{json, Value};
use std::collections::HashMap;

/// Default page size for the list endpoint when `?limit=` is omitted.
const DEFAULT_LIMIT: i64 = 100;
/// Hard cap so a client cannot ask for an unbounded scan.
const MAX_LIMIT: i64 = 500;

#[derive(Debug, Default, Deserialize)]
struct ListQuery {
    limit: Option<i64>,
    /// Optional `content` / `uptime` filter so the desktop "Checks" list shows only the kind it asked
    /// for. Absent → every target.
    #[serde(default)]
    check_type: Option<String>,
}

impl ListQuery {
    /// Clamp the requested limit into `1..=MAX_LIMIT`, defaulting when unset.
    fn limit(&self) -> i64 {
        self.limit.unwrap_or(DEFAULT_LIMIT).clamp(1, MAX_LIMIT)
    }
}

/// Routes for this resource, mounted under the shared `/v1` namespace by the parent router.
pub fn router() -> Router<AppState> {
    Router::new()
        .route("/v1/monitors", get(list).post(create))
        // Device check-capacity meter (static path — never collides with `:id` below).
        .route("/v1/monitors/capacity", get(capacity_status))
        .route(
            "/v1/monitors/:id",
            get(get_one).patch(update).delete(delete),
        )
        .route("/v1/monitors/:id/run", post(run))
        .route("/v1/monitors/:id/changes", get(history))
        // Global, cross-monitor activity feed for the home page. Fully static path, so it never
        // collides with the `/v1/monitors/:id/changes` param route above.
        .route("/v1/changes/recent", get(recent_changes))
}

/// `GET /v1/monitors` — newest-first list of targets, capped by `?limit`, optionally filtered to one
/// `?check_type` (`content` / `uptime`). Each row is enriched with its live check state (see
/// [`enrich`]) so the UI can show "last checked", health, and change/selector counts.
async fn list(State(st): State<AppState>, Query(q): Query<ListQuery>) -> LocalResult<Json<Vec<Value>>> {
    let rows = match q.check_type.as_deref().map(str::trim).filter(|s| !s.is_empty()) {
        Some(ct) => targets::list_by_check_type(&st.db, ct, q.limit()).await?,
        None => targets::list(&st.db, q.limit()).await?,
    };
    // Batch the live states for the whole page, then fold counts in per row.
    let ids: Vec<i64> = rows.iter().map(|t| t.id).collect();
    let states: HashMap<i64, MonitorState> = monitor_state::get_many(&st.db, &ids)
        .await?
        .into_iter()
        .map(|s| (s.target_id, s))
        .collect();
    let mut out = Vec::with_capacity(rows.len());
    for t in rows {
        let state = states.get(&t.id).cloned();
        out.push(enrich(&st.db, t, state).await?);
    }
    Ok(Json(out))
}

/// Placeholder substituted for a redacted `setup_steps.credentials` map at the API boundary.
const REDACTED_CREDS: &str = "«redacted»";

/// Redact the `credentials` sub-object from a `setup_steps` JSON-TEXT payload so the pre-check login
/// secrets NEVER cross the monitor API boundary. The `steps` array (needed by the UI to show/edit the
/// setup flow) is preserved; only the credential VALUES are stripped, replaced by a sentinel so the UI
/// can still show that credentials are configured. A non-JSON / unparsable payload is dropped to the
/// sentinel string fail-closed rather than echoed raw. `None` passes through.
fn redact_setup_steps(raw: Option<&str>) -> Option<Value> {
    let raw = raw?;
    match serde_json::from_str::<Value>(raw) {
        Ok(mut v) => {
            if let Some(obj) = v.as_object_mut() {
                if obj.get("credentials").is_some_and(|c| !c.is_null()) {
                    obj.insert("credentials".into(), json!(REDACTED_CREDS));
                }
            }
            Some(v)
        }
        // Unparsable payload could still embed secrets in some other shape — never echo it raw.
        Err(_) => Some(json!(REDACTED_CREDS)),
    }
}

/// Overwrite the serialized `setup_steps` field of a target JSON object with its credential-redacted
/// form. Call on every JSON built from a `Target` before it leaves a handler.
fn redact_target_value(obj: &mut serde_json::Map<String, Value>) {
    // The raw column serializes as a JSON string (JSON-TEXT). Re-read it, redact, and store back the
    // redacted structure (now a real object) so no credential value survives in the response.
    let raw = obj.get("setup_steps").and_then(|v| v.as_str()).map(str::to_string);
    match redact_setup_steps(raw.as_deref()) {
        Some(redacted) => {
            obj.insert("setup_steps".into(), redacted);
        }
        None => {
            obj.insert("setup_steps".into(), Value::Null);
        }
    }
}

/// Merge a target row with its live `monitor_state` + change/selector counts into the JSON the UI
/// reads. State fields are snake_case (`state`, `last_checked_at`, `status_code`, `is_up`,
/// `last_change_at`) — the desktop reads these (or their camelCase twins) for the health line. Without
/// this, a target that IS being checked still renders as "never checked". The `setup_steps`
/// credentials are redacted here (see [`redact_target_value`]) so login secrets never leave the box.
async fn enrich(db: &sqlx::SqlitePool, t: Target, state: Option<MonitorState>) -> LocalResult<Value> {
    let target_id = t.id;
    let mut v = serde_json::to_value(&t)?;
    if let Some(obj) = v.as_object_mut() {
        redact_target_value(obj);
        if let Some(s) = state {
            obj.insert("state".into(), json!(s.state));
            obj.insert("last_checked_at".into(), json!(s.checked_at));
            obj.insert("status_code".into(), json!(s.status_code));
            obj.insert("is_up".into(), json!(s.is_up.map(|x| x != 0)));
            obj.insert("last_change_at".into(), json!(s.last_change_at));
            // `state == "checking"` is a transient in-progress marker. Expose the live-state row's
            // own `updated_at` under a DISTINCT key (the target already serializes its config
            // `updated_at`) so the UI can age out a marker left stuck by a mid-check crash rather
            // than showing it live forever.
            obj.insert("state_updated_at".into(), json!(s.updated_at));
        }
        obj.insert("changes_count".into(), json!(changes::count_by_target(db, target_id).await?));
        obj.insert(
            "selector_count".into(),
            json!(target_selectors::count_by_target(db, target_id).await?),
        );
    }
    Ok(v)
}

/// `POST /v1/monitors` — create a target. Requires a non-empty `url`; schema defaults fill the rest.
/// SAVE-time clamp: the requested `check_period_ms` is floored to the anti-detection minimum for the
/// chosen path (HTML vs JS/Playwright) so the persisted interval is never below the safe cadence.
/// SAVE-time capacity gate: an enabled monitor whose cadence would push the machine past its
/// sustainable checks/min budget is refused (409 `device_capacity`) — device protection, not a plan.
async fn create(State(st): State<AppState>, Json(mut body): Json<NewTarget>) -> LocalResult<Json<Value>> {
    if body.url.trim().is_empty() {
        return Err(LocalError::BadRequest("url is required".into()));
    }
    let requires_pw = body.requires_playwright.unwrap_or(0) != 0;
    let clamped = clamp::clamp_monitor_interval_ms(body.check_period_ms, requires_pw);
    body.check_period_ms = Some(clamped);
    let enabled = body.enabled.map(|e| e != 0).unwrap_or(true);
    capacity::ensure_capacity_for_change(&st.db, None, clamped, requires_pw, enabled).await?;
    let id = targets::insert(&st.db, &body).await?;
    let row = targets::get_by_id(&st.db, id)
        .await?
        .ok_or_else(|| LocalError::Internal(format!("monitor {id} vanished after insert")))?;
    // Redact setup-step credentials before the row leaves the handler (parity with `enrich`).
    let mut v = serde_json::to_value(&row)?;
    if let Some(obj) = v.as_object_mut() {
        redact_target_value(obj);
    }
    Ok(Json(v))
}

/// `GET /v1/monitors/:id` — one target (enriched with live check state) or 404.
async fn get_one(State(st): State<AppState>, Path(id): Path<i64>) -> LocalResult<Json<Value>> {
    let row = targets::get_by_id(&st.db, id)
        .await?
        .ok_or_else(|| LocalError::NotFound(format!("monitor {id}")))?;
    let state = monitor_state::get(&st.db, id).await?;
    Ok(Json(enrich(&st.db, row, state).await?))
}

/// `PATCH /v1/monitors/:id` — partial update (COALESCE); returns the refreshed row or 404.
/// SAVE-time clamp: when the interval and/or the path (`requires_playwright`) is being changed, the
/// effective `check_period_ms` is re-floored against the effective path so a patch can't drop the
/// persisted cadence below the anti-detection minimum.
async fn update(
    State(st): State<AppState>,
    Path(id): Path<i64>,
    Json(mut body): Json<TargetUpdate>,
) -> LocalResult<Json<Value>> {
    // Anything that could RAISE this monitor's load — a cadence/path change or an enable — needs
    // the pre-patch row, both to clamp correctly and to run the device-capacity gate against the
    // post-patch effective state. Pure reductions (disable, slower interval) always pass the gate.
    let touches_cadence = body.check_period_ms.is_some() || body.requires_playwright.is_some();
    if touches_cadence || matches!(body.enabled, Some(e) if e != 0) {
        // A missing row 404s here rather than after a no-op update.
        let existing = targets::get_by_id(&st.db, id)
            .await?
            .ok_or_else(|| LocalError::NotFound(format!("monitor {id}")))?;
        let requires_pw = body
            .requires_playwright
            .map(|v| v != 0)
            .unwrap_or(existing.requires_playwright != 0);
        if touches_cadence {
            let effective_interval = body.check_period_ms.or(existing.check_period_ms);
            body.check_period_ms =
                Some(clamp::clamp_monitor_interval_ms(effective_interval, requires_pw));
        }
        let new_enabled = body.enabled.map(|e| e != 0).unwrap_or(existing.enabled != 0);
        let new_period = body
            .check_period_ms
            .or(existing.check_period_ms)
            .unwrap_or_else(|| clamp::monitor_floor_ms(requires_pw));
        capacity::ensure_capacity_for_change(&st.db, Some(&existing), new_period, requires_pw, new_enabled)
            .await?;
    }
    let row = targets::update(&st.db, id, &body)
        .await?
        .ok_or_else(|| LocalError::NotFound(format!("monitor {id}")))?;
    // Redact setup-step credentials before the row leaves the handler (parity with `enrich`).
    let mut v = serde_json::to_value(&row)?;
    if let Some(obj) = v.as_object_mut() {
        redact_target_value(obj);
    }
    Ok(Json(v))
}

/// `GET /v1/monitors/capacity` — the device check-capacity meter: how much of this machine's
/// sustainable checks/min budget the enabled monitors consume. Powers the Monitors page meter;
/// NOT a billing/plan surface (local checks are free) — see `scheduler::capacity`.
async fn capacity_status(State(st): State<AppState>) -> LocalResult<Json<Value>> {
    let snap = capacity::snapshot(&st.db).await?;
    Ok(Json(serde_json::to_value(snap)?))
}

/// `DELETE /v1/monitors/:id` — hard-delete (cascades to selectors/state/changes/uptime). 404 if absent.
async fn delete(State(st): State<AppState>, Path(id): Path<i64>) -> LocalResult<Json<serde_json::Value>> {
    let n = targets::delete(&st.db, id).await?;
    if n == 0 {
        return Err(LocalError::NotFound(format!("monitor {id}")));
    }
    Ok(Json(json!({ "deleted": true, "id": id })))
}

/// `POST /v1/monitors/:id/run` — run this monitor's check NOW through the shared engine and return
/// the [`CheckOutcome`](crate::local::monitor::CheckOutcome). A missing/disabled-by-floor target is
/// surfaced by the runner (NotFound / skipped).
async fn run(State(st): State<AppState>, Path(id): Path<i64>) -> LocalResult<Json<serde_json::Value>> {
    let outcome = crate::local::monitor::run_check_for_target(&st.db, &st.engine, id).await?;
    Ok(Json(serde_json::to_value(outcome).unwrap_or_else(|_| json!({ "monitor_id": id }))))
}

/// Pagination for the history endpoint.
#[derive(Debug, Default, Deserialize)]
struct HistoryQuery {
    limit: Option<i64>,
    offset: Option<i64>,
}

impl HistoryQuery {
    fn limit(&self) -> i64 {
        self.limit.unwrap_or(DEFAULT_LIMIT).clamp(1, MAX_LIMIT)
    }
    fn offset(&self) -> i64 {
        self.offset.unwrap_or(0).max(0)
    }
}

/// `GET /v1/monitors/:id/changes` — paginated change + uptime history for a target.
///
/// Returns BOTH series so a UI can render one timeline regardless of `check_type`:
///   * `changes` — content-diff history (newest-first) for `content`/visual monitors.
///   * `uptime_checks` — up/down + SSL samples (newest-first) for `uptime` monitors.
/// Paginated by `?limit` (default [`DEFAULT_LIMIT`], capped at [`MAX_LIMIT`]) and `?offset`. Each
/// series is paged independently against the SAME window. `has_more` reflects whether either series
/// has rows beyond the page. 404 if the monitor doesn't exist.
async fn history(
    State(st): State<AppState>,
    Path(id): Path<i64>,
    Query(q): Query<HistoryQuery>,
) -> LocalResult<Json<serde_json::Value>> {
    // 404 early so an empty page can't be confused with a missing monitor.
    if targets::get_by_id(&st.db, id).await?.is_none() {
        return Err(LocalError::NotFound(format!("monitor {id}")));
    }

    let limit = q.limit();
    let offset = q.offset();
    // The stores expose newest-first `list_by_target(limit)` (no offset). Over-fetch the window plus
    // one extra row so we can slice the requested page AND detect `has_more` without a count query.
    let fetch = offset.saturating_add(limit).saturating_add(1);

    let all_changes = changes::list_by_target(&st.db, id, fetch).await?;
    let changes_has_more = (all_changes.len() as i64) > offset + limit;
    let changes_page: Vec<_> = all_changes
        .into_iter()
        .skip(offset as usize)
        .take(limit as usize)
        .collect();

    let all_uptime = uptime_checks::list_by_target(&st.db, id, fetch).await?;
    let uptime_has_more = (all_uptime.len() as i64) > offset + limit;
    let uptime_page: Vec<_> = all_uptime
        .into_iter()
        .skip(offset as usize)
        .take(limit as usize)
        .collect();

    Ok(Json(json!({
        "monitor_id": id,
        "limit": limit,
        "offset": offset,
        "has_more": changes_has_more || uptime_has_more,
        "changes": changes_page,
        "uptime_checks": uptime_page,
    })))
}

/// Pagination for the global recent-changes feed.
#[derive(Debug, Default, Deserialize)]
struct RecentChangesQuery {
    limit: Option<i64>,
}

/// `GET /v1/changes/recent` — newest-first detected content changes across ALL monitors, each
/// enriched with the monitor URL + selector name + a truncated diff snippet. Powers the home
/// "recent changes" activity feed. Capped by `?limit` (default 10, hard-capped at 50). Uptime
/// samples are NOT included here — this feed is content-change history only.
async fn recent_changes(
    State(st): State<AppState>,
    Query(q): Query<RecentChangesQuery>,
) -> LocalResult<Json<Vec<changes::RecentChange>>> {
    let limit = q.limit.unwrap_or(10).clamp(1, 50);
    Ok(Json(changes::list_recent_enriched(&st.db, limit).await?))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::local::config::{HTML_FLOOR_MS, JS_FLOOR_MS};
    use crate::local::store::{changes::NewChange, uptime_checks::NewUptimeCheck};
    use crate::local::{db, engine, vault};
    use std::sync::Arc;

    /// A minimal AppState over a fresh encrypted DB (file-fallback vault, no keyring prompt).
    async fn state() -> AppState {
        let dir = Box::leak(Box::new(tempfile::tempdir().unwrap()));
        let v = vault::Vault::load_or_create(dir.path(), false).unwrap();
        let pool = db::open(&dir.path().join("t.db"), &v.db_key_hex()).await.unwrap();
        AppState {
            db: pool,
            vault: Arc::new(v),
            engine: Arc::new(engine::StubEngine),
            config: crate::local::config::LocalConfig::default(),
            token: Arc::new("wlt_test".into()),
            health: crate::local::app::health::DaemonHealth::shared(),
            recorder: None,
        }
    }

    /// The content-monitor wizard posts JSON-natural shapes: `enabled`/`requires_playwright` as
    /// BOOLS, the interval possibly as a numeric STRING (form/select), and `setup_steps` as either a
    /// pre-serialized string OR an object. All of these must deserialize into `NewTarget` — a type
    /// mismatch on any of them is what surfaced as the monitor-create 422.
    #[test]
    fn new_target_accepts_wizard_payload_shapes() {
        // Bools + numeric interval + string setup_steps (the standard wizard create body).
        let standard = serde_json::json!({
            "url": "https://example.com", "selector": "body", "check_type": "content",
            "enabled": true, "check_period_ms": 60000, "requires_playwright": false,
            "preferred_region": null,
            "setup_steps": "{\"steps\":[{\"type\":\"click\"}],\"credentials\":{}}",
        });
        let t: NewTarget = serde_json::from_value(standard).unwrap();
        assert_eq!(t.enabled, Some(1));
        assert_eq!(t.requires_playwright, Some(0));
        assert_eq!(t.check_period_ms, Some(60000));

        // Hardened: a numeric STRING interval and a persona-id string (from a <select>) coerce.
        let stringy = serde_json::json!({
            "url": "https://example.com", "enabled": 1, "check_period_ms": "300000",
            "persona_id": "7",
        });
        let t: NewTarget = serde_json::from_value(stringy).unwrap();
        assert_eq!(t.check_period_ms, Some(300000));
        assert_eq!(t.persona_id, Some(7));

        // Hardened: `setup_steps` sent as an OBJECT is stored as JSON text (engine `from_str`-able).
        let obj_steps = serde_json::json!({
            "url": "https://example.com",
            "setup_steps": { "steps": [{ "type": "click" }], "credentials": {} },
        });
        let t: NewTarget = serde_json::from_value(obj_steps).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(t.setup_steps.as_deref().unwrap()).unwrap();
        assert_eq!(parsed["steps"][0]["type"], serde_json::json!("click"));

        // A genuinely non-numeric interval is still a hard error (not silently coerced to 0).
        let bad = serde_json::json!({ "url": "https://example.com", "check_period_ms": "soon" });
        assert!(serde_json::from_value::<NewTarget>(bad).is_err());
    }

    /// Create floors a too-small interval to the HTML floor (HTTP path) and to the JS floor when the
    /// monitor requires playwright.
    #[tokio::test]
    async fn create_clamps_interval_by_path() {
        let st = state().await;

        // HTML path: 1s requested → floored to the HTML minimum.
        let body = NewTarget {
            url: "https://example.test/html".into(),
            check_period_ms: Some(1_000),
            ..Default::default()
        };
        let Json(t) = create(State(st.clone()), Json(body)).await.unwrap();
        assert_eq!(t["check_period_ms"].as_i64(), Some(HTML_FLOOR_MS as i64));

        // JS path: 1s requested with requires_playwright → floored to the (higher) JS minimum.
        let body = NewTarget {
            url: "https://example.test/js".into(),
            check_period_ms: Some(1_000),
            requires_playwright: Some(1),
            ..Default::default()
        };
        let Json(t) = create(State(st), Json(body)).await.unwrap();
        assert_eq!(t["check_period_ms"].as_i64(), Some(JS_FLOOR_MS as i64));
    }

    /// Patching the interval down re-floors it; flipping to playwright re-floors a now-too-small
    /// existing interval even when the patch doesn't restate the interval.
    #[tokio::test]
    async fn update_clamps_interval() {
        let st = state().await;
        let Json(created) = create(
            State(st.clone()),
            Json(NewTarget { url: "https://example.test".into(), check_period_ms: Some(120_000), ..Default::default() }),
        )
        .await
        .unwrap();
        assert_eq!(created["check_period_ms"].as_i64(), Some(120_000));
        let created_id = created["id"].as_i64().unwrap();

        // Patch the interval below the HTML floor → re-floored.
        let Json(after) = update(
            State(st.clone()),
            Path(created_id),
            Json(TargetUpdate { check_period_ms: Some(5_000), ..Default::default() }),
        )
        .await
        .unwrap();
        assert_eq!(after["check_period_ms"].as_i64(), Some(HTML_FLOOR_MS as i64));

        // Bump the interval back to 120s, then flip to playwright WITHOUT restating the interval:
        // 120s < JS floor, so the effective interval is re-floored to the JS minimum.
        let _ = update(
            State(st.clone()),
            Path(created_id),
            Json(TargetUpdate { check_period_ms: Some(120_000), ..Default::default() }),
        )
        .await
        .unwrap();
        let Json(pw) = update(
            State(st),
            Path(created_id),
            Json(TargetUpdate { requires_playwright: Some(1), ..Default::default() }),
        )
        .await
        .unwrap();
        assert_eq!(pw["check_period_ms"].as_i64(), Some(JS_FLOOR_MS as i64));
        assert_eq!(pw["requires_playwright"].as_i64(), Some(1));
    }

    /// History returns paginated changes + uptime samples and a 404 for a missing monitor.
    #[tokio::test]
    async fn history_paginates_both_series() {
        let st = state().await;
        let Json(t) = create(
            State(st.clone()),
            Json(NewTarget { url: "https://example.test".into(), ..Default::default() }),
        )
        .await
        .unwrap();
        let t_id = t["id"].as_i64().unwrap();

        // Seed 3 changes + 3 uptime samples.
        for i in 0..3 {
            changes::insert(
                &st.db,
                &NewChange {
                    target_id: t_id,
                    content_hash: format!("{:064x}", i),
                    ..Default::default()
                },
            )
            .await
            .unwrap();
            uptime_checks::insert(
                &st.db,
                &NewUptimeCheck { target_id: t_id, is_up: 1, ..Default::default() },
            )
            .await
            .unwrap();
        }

        // Page 1 (limit=2) → 2 of each + has_more.
        let Json(p1) = history(
            State(st.clone()),
            Path(t_id),
            Query(HistoryQuery { limit: Some(2), offset: Some(0) }),
        )
        .await
        .unwrap();
        assert_eq!(p1["changes"].as_array().unwrap().len(), 2);
        assert_eq!(p1["uptime_checks"].as_array().unwrap().len(), 2);
        assert_eq!(p1["has_more"], serde_json::json!(true));

        // Page 2 (offset=2) → the remaining 1 of each, no more.
        let Json(p2) = history(
            State(st.clone()),
            Path(t_id),
            Query(HistoryQuery { limit: Some(2), offset: Some(2) }),
        )
        .await
        .unwrap();
        assert_eq!(p2["changes"].as_array().unwrap().len(), 1);
        assert_eq!(p2["uptime_checks"].as_array().unwrap().len(), 1);
        assert_eq!(p2["has_more"], serde_json::json!(false));

        // Missing monitor → 404.
        let err = history(State(st), Path(999_999), Query(HistoryQuery::default()))
            .await
            .unwrap_err();
        assert!(matches!(err, LocalError::NotFound(_)));
    }

    /// The global `/v1/changes/recent` feed returns changes across ALL monitors newest-first,
    /// enriched with the monitor URL, and respects the `?limit`.
    #[tokio::test]
    async fn recent_changes_feed_is_global_and_enriched() {
        let st = state().await;
        let Json(a) = create(
            State(st.clone()),
            Json(NewTarget { url: "https://a.test".into(), ..Default::default() }),
        )
        .await
        .unwrap();
        let Json(b) = create(
            State(st.clone()),
            Json(NewTarget { url: "https://b.test".into(), ..Default::default() }),
        )
        .await
        .unwrap();

        // One change on A, then one on B (B is newest).
        changes::insert(
            &st.db,
            &NewChange { target_id: a["id"].as_i64().unwrap(), content_hash: format!("{:064x}", 1), ..Default::default() },
        )
        .await
        .unwrap();
        changes::insert(
            &st.db,
            &NewChange {
                target_id: b["id"].as_i64().unwrap(),
                content_hash: format!("{:064x}", 2),
                diff_snippet: Some("+ added line".into()),
                ..Default::default()
            },
        )
        .await
        .unwrap();

        // Default feed spans both monitors, newest-first, with the URL joined in.
        let Json(all) = recent_changes(State(st.clone()), Query(RecentChangesQuery::default()))
            .await
            .unwrap();
        assert_eq!(all.len(), 2);
        assert_eq!(all[0].target_url, "https://b.test");
        assert_eq!(all[0].diff_snippet.as_deref(), Some("+ added line"));
        assert_eq!(all[1].target_url, "https://a.test");

        // `?limit=1` returns only the newest.
        let Json(one) = recent_changes(State(st), Query(RecentChangesQuery { limit: Some(1) }))
            .await
            .unwrap();
        assert_eq!(one.len(), 1);
        assert_eq!(one[0].target_url, "https://b.test");
    }

    /// `list` / `get_one` fold the live `monitor_state` + counts into the JSON the desktop reads for
    /// the health line — without this a checked monitor renders as "never checked".
    #[tokio::test]
    async fn list_and_get_enrich_with_live_state() {
        let st = state().await;
        let Json(created) = create(
            State(st.clone()),
            Json(NewTarget { url: "https://enrich.test".into(), ..Default::default() }),
        )
        .await
        .unwrap();
        let created_id = created["id"].as_i64().unwrap();

        // Before any check: counts are present + zero, no state token.
        let Json(pre) = get_one(State(st.clone()), Path(created_id)).await.unwrap();
        assert_eq!(pre["changes_count"], serde_json::json!(0));
        assert_eq!(pre["selector_count"], serde_json::json!(0));
        assert!(pre.get("state").map(|v| v.is_null()).unwrap_or(true));

        // Simulate a check writing live state, then confirm both endpoints surface it.
        monitor_state::upsert(
            &st.db,
            created_id,
            &monitor_state::MonitorStateUpsert {
                checked_at: "2026-06-29T00:00:00.000Z".into(),
                state: Some("unchanged".into()),
                is_up: Some(1),
                status_code: Some(200),
                last_change_at: None,
            },
        )
        .await
        .unwrap();

        let Json(one) = get_one(State(st.clone()), Path(created_id)).await.unwrap();
        assert_eq!(one["state"], serde_json::json!("unchanged"));
        assert_eq!(one["last_checked_at"], serde_json::json!("2026-06-29T00:00:00.000Z"));
        assert_eq!(one["status_code"], serde_json::json!(200));
        assert_eq!(one["is_up"], serde_json::json!(true));

        let Json(rows) = list(State(st), Query(ListQuery::default())).await.unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0]["state"], serde_json::json!("unchanged"));
        assert_eq!(rows[0]["url"], serde_json::json!("https://enrich.test"));
    }

    /// The pre-check `setup_steps.credentials` login secrets must NEVER cross the monitor API
    /// boundary on create / get / list — only the redaction sentinel is returned, while the `steps`
    /// array (needed to render/edit the flow) is preserved.
    #[tokio::test]
    async fn monitor_response_redacts_setup_step_credentials() {
        let st = state().await;
        let setup = r##"{"steps":[{"type":"fill","selector":"#user","value":"{{email}}"}],"credentials":{"email":"a@b.com","password":"hunter2"}}"##;

        let Json(created) = create(
            State(st.clone()),
            Json(NewTarget {
                url: "https://login.test".into(),
                setup_steps: Some(setup.into()),
                ..Default::default()
            }),
        )
        .await
        .unwrap();
        let created_id = created["id"].as_i64().unwrap();

        // Create response: steps survive, credentials are the sentinel, no secret leaks.
        assert_eq!(created["setup_steps"]["steps"][0]["type"], serde_json::json!("fill"));
        assert_eq!(created["setup_steps"]["credentials"], serde_json::json!(REDACTED_CREDS));
        assert!(!created.to_string().contains("hunter2"));

        // Get response: same redaction.
        let Json(got) = get_one(State(st.clone()), Path(created_id)).await.unwrap();
        assert_eq!(got["setup_steps"]["credentials"], serde_json::json!(REDACTED_CREDS));
        assert!(!got.to_string().contains("hunter2"));

        // List response: same redaction.
        let Json(rows) = list(State(st.clone()), Query(ListQuery::default())).await.unwrap();
        assert_eq!(rows[0]["setup_steps"]["credentials"], serde_json::json!(REDACTED_CREDS));
        assert!(!serde_json::to_string(&rows).unwrap().contains("hunter2"));

        // Patch response: same redaction (the row round-trips through the DB unchanged).
        let Json(patched) = update(
            State(st),
            Path(created_id),
            Json(TargetUpdate { notification_title: Some("t".into()), ..Default::default() }),
        )
        .await
        .unwrap();
        assert_eq!(patched["setup_steps"]["credentials"], serde_json::json!(REDACTED_CREDS));
        assert!(!patched.to_string().contains("hunter2"));
    }
}
