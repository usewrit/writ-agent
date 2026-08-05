//! `/v1/runs` REST handlers — read-only views over the `runs` table.
//!
//! Thin HTTP adapters over `store::runs`. Runs are created by the engine/scheduler, not by this
//! API, so there are no create/update routes here — just list + per-run reads. House style: each
//! handler propagates store errors with `?` (they're `IntoResponse`). No auth layer here —
//! `server.rs` applies the loopback bearer + Origin/Host guard at the router level.

use crate::local::engine::events::RunEvent;
use crate::local::error::{LocalError, LocalResult};
use crate::local::server::AppState;
use crate::local::store::{runs, workflows};
use axum::extract::{Path, Query, State};
use axum::http::header;
use axum::response::sse::{Event, KeepAlive, Sse};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use futures_util::stream::{self, BoxStream};
use futures_util::StreamExt as _;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::HashMap;
use std::convert::Infallible;
use std::time::Duration;
use tokio::sync::broadcast::error::RecvError;

/// Mount the run routes onto the shared `AppState` router. Auth is applied by `server.rs`.
pub fn router() -> Router<AppState> {
    Router::new()
        .route("/v1/runs", get(list))
        // Static "/events" is matched ahead of the "/:id" param by the router, so it never collides
        // with `/v1/runs/:id`. This is the GLOBAL all-runs stream (below).
        .route("/v1/runs/events", get(global_events))
        .route("/v1/runs/:id", get(get_one))
        .route("/v1/runs/:id/results", get(results))
        .route("/v1/runs/:id/data", get(data))
        .route("/v1/runs/:id/events", get(events))
        .route("/v1/runs/:id/cancel", post(cancel))
}

/// `GET /v1/runs/events` — a live Server-Sent-Events stream of EVERY run's lifecycle frames
/// (`started` / `step` / `progress` / `finished` / `error`) across ALL runs, from the registry's
/// global fan-out. Unlike the per-run stream this is PERSISTENT: a terminal frame for one run does
/// NOT close it. One subscriber (the desktop shell) re-emits each frame as a Tauri `run:event`,
/// making the app's Live activity fully push-driven (no polling). Frames carry only structural
/// metadata — never a secret/value (see engine::events secret-hygiene note).
async fn global_events(
    State(st): State<AppState>,
) -> Sse<BoxStream<'static, Result<Event, Infallible>>> {
    let stream: BoxStream<'static, Result<Event, Infallible>> = match st.engine.registry() {
        Some(reg) => {
            let rx = reg.subscribe_global();
            stream::unfold(rx, |mut rx| async move {
                loop {
                    match rx.recv().await {
                        Ok(ev) => return Some((Ok(sse_event(&ev)), rx)),
                        // Lagged past the ring — skip the gap, keep streaming.
                        Err(RecvError::Lagged(_)) => continue,
                        // The registry (and its global sender) live for the daemon's lifetime, so
                        // Closed is effectively unreachable; end the stream cleanly if it ever fires.
                        Err(RecvError::Closed) => return None,
                    }
                }
            })
            .boxed()
        }
        // Stub engine with no registry — hand back an inert keep-alive stream.
        None => stream::empty().boxed(),
    };
    Sse::new(stream).keep_alive(KeepAlive::new().interval(Duration::from_secs(15)))
}

/// `POST /v1/runs/:id/cancel` — cancel a live run BY RUN ID. Unlike `/v1/workflows/:id/cancel` (which
/// resolves the newest running run of a *persisted workflow*), this cancels ANY run row directly —
/// including an ad-hoc cloud-dispatched run that has `workflow_id = NULL` (an `execute_workflow` recipe
/// the cloud sent us), which the workflow-scoped route can't address. Signals the engine registry's
/// cancellation token; the execute loop aborts between steps and finalizes the run as `cancelled`.
///
/// Returns `202 {run_id, status:"cancel_requested"}` when a live run was signalled, `409 Conflict
/// {status:"not_running"}` when the run is already terminal or the engine has no live handle for it,
/// and `404` when the run id is unknown.
async fn cancel(
    State(st): State<AppState>,
    Path(id): Path<i64>,
) -> LocalResult<(axum::http::StatusCode, Json<Value>)> {
    let run = runs::get_by_id(&st.db, id)
        .await?
        .ok_or_else(|| LocalError::NotFound(format!("run {id}")))?;
    // Only an in-flight run is cancellable; a terminal row has nothing live to signal.
    if run.status != "running" {
        return Ok((
            axum::http::StatusCode::CONFLICT,
            Json(json!({ "run_id": id, "status": "not_running", "run_status": run.status })),
        ));
    }
    match st.engine.cancel(id) {
        Some(_) => Ok((
            axum::http::StatusCode::ACCEPTED,
            Json(json!({ "run_id": id, "status": "cancel_requested" })),
        )),
        // Row says running but the engine has no live handle (stub/sync engine, or a crash-orphaned
        // row) — nothing live to signal.
        None => Ok((
            axum::http::StatusCode::CONFLICT,
            Json(json!({ "run_id": id, "status": "not_running" })),
        )),
    }
}

/// Enriched run-feed item — the shape the desktop UI consumes (`frontend-desktop` `api/runs.ts`
/// `Run`). It mirrors the Writ Cloud `/runs` projection so the ported list/detail/dashboard pages
/// render identically: a derived `run_type`, the resolved entity *name* (not just an id), and the
/// precomputed frontend deep-links (`detail_url_hint` / `data_url_hint`). The raw `runs` row only
/// carries foreign-key ids and snake_case columns (`completed_at`, `error_message`, `trigger_type`),
/// which is why a feed built straight off the rows showed blank, link-less, "—" entries.
#[derive(Debug, Serialize)]
struct RunFeedItem {
    /// Composite + unique across the feed, matching the cloud contract: `"<run_type>-<row id>"`.
    id: String,
    run_type: &'static str,
    entity_id: Option<i64>,
    entity_name: Option<String>,
    status: String,
    started_at: Option<String>,
    finished_at: Option<String>,
    duration_ms: Option<i64>,
    trigger_source: Option<String>,
    error: Option<String>,
    /// Engine-assigned failure bucket (`runs.failure_category`, e.g. "twofa" vs "twofa_persona").
    /// Lets the UI offer the RIGHT fix for a shared status — a `twofa_required` run is "run it in
    /// the cloud" when the persona's code arrives by email/SMS, but "attach a persona / import the
    /// 2FA secret" when there is no usable persona at all. `None` on successful runs.
    #[serde(skip_serializing_if = "Option::is_none")]
    failure_category: Option<String>,
    detail_url_hint: Option<String>,
    data_url_hint: Option<String>,
    /// Workflow runs only: how many data records the run produced (the row count the Data view
    /// shows). `None` for check/automation runs — lets the UI render "N rows extracted" inline.
    rows_extracted: Option<i64>,
    /// Check runs only: whether this check detected a change (`runs.change_id` is set). `None` for
    /// workflow/automation runs — lets the UI render "Change detected" vs "No change".
    change_detected: Option<bool>,
    /// Which lane ran this (from `result_data.engine`): "http" | "browser" | "hybrid". `None` for
    /// non-workflow runs and older result_data — drives the HTTP/Hybrid run badge.
    #[serde(skip_serializing_if = "Option::is_none")]
    engine: Option<String>,
    /// Workflow runs only: AI auto-repair fixed this run (`runs.ai_repair_succeeded = 1`). Drives the
    /// "Repaired" badge. `None` for check/automation runs, where repair is meaningless.
    repaired: Option<bool>,
    /// Workflow runs only: AI auto-repair tried and could NOT fix this run
    /// (`runs.ai_repair_succeeded = 0`). Drives the "Repair failed" badge — the AI already had a go
    /// and gave up, so this failure is a human's problem. Never true at the same time as `repaired`.
    repair_failed: Option<bool>,
    /// Workflow runs only: the parent workflow was repaired AFTER this failed run finished, so the
    /// recipe that broke it has since been fixed. The run stays failed (history is immutable), but
    /// Home drops it from "Needs attention": it's resolved, not actionable. Distinct from `repaired`,
    /// which is THIS run's own fix.
    repaired_since: Option<bool>,
}

/// Pre-fetched workflow facts the run projection needs, resolved in one bulk query by the caller.
struct WfInfo {
    name: String,
    /// `standard` | `streaming` | … — a streaming workflow is a live session with no Data view.
    wtype: String,
    /// When AI last persisted a repair to this workflow (0023); `None` = never repaired.
    last_repaired_at: Option<String>,
}

/// Derive the feed `run_type` from whichever foreign key the row carries. Order matters: a run is
/// created with exactly one association in practice, but automation/check associations are checked
/// first so a workflow-backed check (a pre-check setup workflow) still reads as its true type. A row
/// with no association (an ephemeral marketplace-recipe run) falls through to `workflow`.
fn run_type_of(run: &runs::Run) -> &'static str {
    if run.automation_id.is_some() {
        "automation"
    } else if run.target_id.is_some() || run.change_id.is_some() {
        "check"
    } else {
        "workflow"
    }
}

/// Project a raw `runs` row into the enriched [`RunFeedItem`]. `wf_names` maps workflow id →
/// `(name, workflow_type)` (pre-fetched in bulk by the caller) so workflow runs resolve a real name
/// and a Data deep-link. Streaming workflows are live sessions with no tabular output, so they get a
/// detail link but no `data_url_hint` — same rule as the cloud feed.
fn project_run(run: &runs::Run, wf_names: &HashMap<i64, WfInfo>) -> RunFeedItem {
    let run_type = run_type_of(run);
    let is_workflow = run_type == "workflow";
    let wf_info = run.workflow_id.and_then(|id| wf_names.get(&id));
    // AI-repair verdict for this run (0023), tri-state: NULL = no verdict, 1 = fixed, 0 = gave up.
    let repaired = is_workflow.then(|| run.ai_repair_succeeded == Some(1));
    let repair_failed = is_workflow.then(|| run.ai_repair_succeeded == Some(0));
    // Has the workflow been repaired SINCE this run broke? Both timestamps are written with the same
    // ISO-8601 UTC strftime format, so a lexicographic compare is chronological. Only meaningful for
    // a FINISHED failure: a run with no completed_at can't be ordered against the repair, so it stays
    // actionable rather than being optimistically hidden.
    let repaired_since = is_workflow.then(|| {
        matches!(
            (wf_info.and_then(|w| w.last_repaired_at.as_deref()), run.completed_at.as_deref()),
            (Some(repaired_at), Some(finished)) if run.status == "failed" && repaired_at > finished
        )
    });
    // Type-specific annotations, computed up front so the workflow arm can gate its Data deep-link
    // on whether the run's data actually lands in the Data view. Workflow runs carry a record count
    // (parse result_data once and count via the shared data engine, so the feed agrees with the
    // Data view); check runs carry a change-detected flag (the change FK is set only on a change).
    let parsed_result = run
        .result_data
        .as_deref()
        .and_then(|s| serde_json::from_str::<Value>(s).ok());
    let rows_extracted = (run_type == "workflow")
        .then(|| crate::local::data_query::record_count(parsed_result.as_ref().unwrap_or(&Value::Null)) as i64);
    let engine = parsed_result
        .as_ref()
        .and_then(|v| v.get("engine"))
        .and_then(|v| v.as_str())
        .map(String::from);
    let change_detected = (run_type == "check").then(|| run.change_id.is_some());

    let (entity_id, entity_name, detail_url_hint, data_url_hint) = match run_type {
        "workflow" => {
            let name = wf_info
                .map(|w| w.name.clone())
                .unwrap_or_else(|| format!("Run {}", run.id));
            let detail = run.workflow_id.map(|id| format!("/workflows/{id}"));
            // No Data tab for streaming workflows (live sessions, no extracted table).
            let is_streaming = wf_info.map(|w| w.wtype == "streaming").unwrap_or(false);
            // Only advertise the aggregated Data view when THIS run's data appears there. That view
            // aggregates successful runs only, one row per extracted record — so a failed run, a
            // 0-row run, or a streaming session gets a detail link but NO data link. This stops the
            // feed from surfacing "View data" affordances that open an empty table (noise).
            let has_data = run.success == Some(1) && rows_extracted.unwrap_or(0) > 0;
            let data = match &detail {
                Some(d) if !is_streaming && has_data => Some(format!("{d}?tab=data")),
                _ => None,
            };
            (run.workflow_id, Some(name), detail, data)
        }
        "check" => {
            let tid = run.target_id;
            (tid, None, tid.map(|id| format!("/monitors/{id}")), None)
        }
        // automation
        _ => {
            let aid = run.automation_id;
            (aid, None, aid.map(|id| format!("/automations/{id}")), None)
        }
    };
    RunFeedItem {
        id: format!("{run_type}-{}", run.id),
        run_type,
        entity_id,
        entity_name,
        status: run.status.clone(),
        started_at: run.started_at.clone().or_else(|| Some(run.created_at.clone())),
        finished_at: run.completed_at.clone(),
        duration_ms: run.duration_ms,
        trigger_source: Some(run.trigger_type.clone()),
        error: run.error_message.clone(),
        failure_category: run.failure_category.clone(),
        detail_url_hint,
        data_url_hint,
        rows_extracted,
        change_detected,
        engine,
        repaired,
        repair_failed,
        repaired_since,
    }
}

/// Resolve the [`WfInfo`] map for every workflow-backed row in `rows`, then project each row to a
/// [`RunFeedItem`]. One bulk lookup (no N+1).
async fn project_rows(st: &AppState, rows: &[runs::Run]) -> LocalResult<Vec<RunFeedItem>> {
    let mut wf_ids: Vec<i64> = rows
        .iter()
        .filter(|r| run_type_of(r) == "workflow")
        .filter_map(|r| r.workflow_id)
        .collect();
    wf_ids.sort_unstable();
    wf_ids.dedup();
    let wf_names: HashMap<i64, WfInfo> = workflows::names_and_types(&st.db, &wf_ids)
        .await?
        .into_iter()
        .map(|(id, name, wtype, last_repaired_at)| (id, WfInfo { name, wtype, last_repaired_at }))
        .collect();
    Ok(rows.iter().map(|r| project_run(r, &wf_names)).collect())
}

/// Query params for `GET /v1/runs`.
#[derive(Debug, Deserialize)]
struct ListQuery {
    /// Optional filter to runs of a single workflow (legacy/local param name).
    #[serde(default)]
    workflow_id: Option<i64>,
    /// Frontend contract param (`frontend-desktop` `runsApi.list` sends `entity_id`): the id of the
    /// entity to scope to, interpreted per `run_type` (workflow_id / target_id / automation_id) —
    /// mirroring the Writ Cloud feed. Aliases `workflow_id` for workflow-type queries.
    #[serde(default)]
    entity_id: Option<i64>,
    /// Optional run-type filter (`workflow|check|automation`). The local feed only persists
    /// workflow runs today, so `check`/`automation` yield an empty page (the scoped detail pages
    /// then correctly show "no runs" instead of the global workflow feed).
    #[serde(default)]
    run_type: Option<String>,
    /// Optional filter by terminal/in-flight status (`running|success|failed|...`).
    #[serde(default)]
    status: Option<String>,
    /// Page size (clamped to 1..=1000 by the store).
    #[serde(default = "default_limit")]
    limit: i64,
    /// Pagination offset (applied after scoping/projection).
    #[serde(default)]
    offset: i64,
}

fn default_limit() -> i64 {
    100
}

/// `GET /v1/runs` — list runs newest-first, optionally scoped to an entity / run_type / status. Each
/// row is returned as an enriched [`RunFeedItem`] (resolved name + deep-links), not the raw DB row,
/// so the UI feed has something to render. `run_type` / `entity_id` mirror the cloud contract: a
/// non-workflow `run_type` returns an empty page (no such rows persist locally) rather than leaking
/// the global workflow feed into a scoped detail view.
async fn list(
    State(st): State<AppState>,
    Query(q): Query<ListQuery>,
) -> LocalResult<Json<Value>> {
    let offset = q.offset.max(0) as usize;
    // Fetch enough rows to cover the requested page after slicing.
    let fetch_n = q.limit.clamp(1, 1000).saturating_add(q.offset.max(0));
    let rt = q.run_type.as_deref();
    let is_workflow_scope = matches!(rt, None | Some("workflow"));
    // `entity_id` means workflow_id for a workflow query (the only type with persisted rows).
    let workflow_scope = if is_workflow_scope { q.entity_id.or(q.workflow_id) } else { None };

    let rows = match (workflow_scope, q.status.as_deref()) {
        (Some(wf), _) => runs::list_by_workflow(&st.db, wf, fetch_n).await?,
        (None, Some(status)) => runs::list_by_status(&st.db, status, fetch_n).await?,
        (None, None) => runs::list(&st.db, fetch_n).await?,
    };
    let mut items = project_rows(&st, &rows).await?;
    // run_type is derived from the row's FKs, so filter it post-projection. A non-workflow type
    // matches nothing today → empty page (correct for scoped detail views).
    if let Some(rt) = rt {
        items.retain(|i| i.run_type == rt);
    } else {
        // Monitor content-checks are noise in the unified feed — surface only FAILED checks so a
        // successful check doesn't swamp real executions. An explicit run_type='check' query (a
        // scoped monitor view) is unaffected — it takes the branch above.
        items.retain(|i| i.run_type != "check" || i.status == "failed");
    }
    let total = items.len();
    let page: Vec<RunFeedItem> = items.into_iter().skip(offset).take(q.limit.max(0) as usize).collect();
    Ok(Json(json!({ "data": page, "count": page.len(), "total": total })))
}

/// `GET /v1/runs/:id` — fetch one run as the enriched [`RunFeedItem`] (same projection as the list).
async fn get_one(
    State(st): State<AppState>,
    Path(id): Path<i64>,
) -> LocalResult<Json<RunFeedItem>> {
    let run = runs::get_by_id(&st.db, id)
        .await?
        .ok_or_else(|| LocalError::NotFound(format!("run {id}")))?;
    let items = project_rows(&st, std::slice::from_ref(&run)).await?;
    let item = items
        .into_iter()
        .next()
        .ok_or_else(|| LocalError::Internal("run projection vanished".into()))?;
    Ok(Json(item))
}

/// `GET /v1/runs/:id/results` — the raw `result_data` JSON-TEXT, parsed back to JSON. Returns
/// `null` when the run produced no result (still running, or no payload).
async fn results(
    State(st): State<AppState>,
    Path(id): Path<i64>,
) -> LocalResult<Json<Value>> {
    let run = runs::get_by_id(&st.db, id)
        .await?
        .ok_or_else(|| LocalError::NotFound(format!("run {id}")))?;
    let result = parse_json_text(run.result_data.as_deref())?;
    Ok(Json(json!({
        "run_id": run.id,
        "status": run.status,
        "result": result,
    })))
}

/// Query params for `GET /v1/runs/:id/data`.
#[derive(Debug, Default, Deserialize)]
struct DataQuery {
    /// `json` (default) or `csv`. CSV flattens the run's extracted records into a table (one row per
    /// record) via the shared `data_query` engine — same shape as the workflow-level export.
    #[serde(default)]
    format: Option<String>,
}

/// `GET /v1/runs/:id/data` — the extracted data for a single run. The engine stores extracted output
/// under the `extracted_data` key of `result_data` (matching `RunResult`); if absent we fall back to
/// the whole result payload so callers always get something usable.
///
/// `?format=csv` returns a downloadable CSV (per-run) built with `data_query::to_csv`: the run's
/// extracted records flattened to rows (a list-extracting run yields one row per item). The default
/// (`json`) returns the raw extracted JSON.
async fn data(
    State(st): State<AppState>,
    Path(id): Path<i64>,
    Query(q): Query<DataQuery>,
) -> LocalResult<Response> {
    let run = runs::get_by_id(&st.db, id)
        .await?
        .ok_or_else(|| LocalError::NotFound(format!("run {id}")))?;

    if q.format.as_deref().map(|f| f.eq_ignore_ascii_case("csv")).unwrap_or(false) {
        return Ok(run_data_csv(&run));
    }

    let result = parse_json_text(run.result_data.as_deref())?;
    let extracted = result
        .as_object()
        .and_then(|o| o.get("extracted_data"))
        .cloned()
        .unwrap_or(result);
    Ok(Json(json!({
        "run_id": run.id,
        "status": run.status,
        "data": extracted,
    }))
    .into_response())
}

/// Build a per-run CSV download. Reuses the shared `data_query` flatten + `to_csv` engine over a
/// single-run input so the redaction (internal envelope + secret-shaped keys) is identical to the
/// workflow-level export. No declared-field projection (single run → use whatever it produced).
fn run_data_csv(run: &runs::Run) -> Response {
    use crate::local::data_query::{self, RunInput};

    let run_input = RunInput {
        run_id: run.id,
        run_at: run.completed_at.clone().or_else(|| Some(run.created_at.clone())),
        status: Some(run.status.clone()),
        success: run.success.map(|s| s != 0),
        duration_ms: run.duration_ms,
        result_data: parse_json_text(run.result_data.as_deref()).unwrap_or(Value::Null),
        trigger_context: parse_json_text(run.trigger_context.as_deref()).unwrap_or(Value::Null),
    };
    let (columns, rows) = data_query::flatten(std::slice::from_ref(&run_input), &[], false);
    let body = data_query::to_csv(&columns, &rows);
    let disposition = format!("attachment; filename=\"run-{}-data.csv\"", run.id);
    (
        [
            (header::CONTENT_TYPE, "text/csv; charset=utf-8".to_string()),
            (header::CONTENT_DISPOSITION, disposition),
        ],
        body,
    )
        .into_response()
}

/// `GET /v1/runs/:id/events` — a live Server-Sent-Events stream of the run's lifecycle (STAGE E2).
///
/// If the run is LIVE (registered in the engine's run registry) we subscribe to its broadcast
/// channel and stream `RunEvent`s (`started` / `step` / `progress` / `finished` / `error`) until a
/// terminal frame, then close. If the run is NOT live — already finished, or an engine with no
/// registry (stub) — we emit a single synthetic terminal snapshot from the persisted `runs` row and
/// close IMMEDIATELY, so a late subscriber still gets a well-formed, stream-closing event.
async fn events(
    State(st): State<AppState>,
    Path(id): Path<i64>,
) -> LocalResult<Sse<BoxStream<'static, Result<Event, Infallible>>>> {
    // The run must exist (404 otherwise) so a typo doesn't hang on an empty stream.
    let run = runs::get_by_id(&st.db, id)
        .await?
        .ok_or_else(|| LocalError::NotFound(format!("run {id}")))?;

    // LIVE path: subscribe to the registry's broadcast channel for this run. Both arms box their
    // stream to the SAME `BoxStream` type so the `impl Stream` return unifies.
    if let Some(reg) = st.engine.registry() {
        if let Some(handle) = reg.get(id) {
            let rx = handle.subscribe();
            // Seed with a synthetic `started` so an immediate subscriber gets a frame even though the
            // producer's own Started was emitted before subscription (broadcast does not replay). The
            // authoritative per-step / progress / terminal frames follow from the live channel.
            let seed = sse_event(&RunEvent::Started { run_id: id, total_steps: 0 });
            let live = stream::unfold(Some(rx), |state| async move {
                let mut rx = state?;
                loop {
                    match rx.recv().await {
                        Ok(ev) => {
                            let terminal = ev.is_terminal();
                            let item: Result<Event, Infallible> = Ok(sse_event(&ev));
                            // After a terminal frame, stop the stream (None next-state).
                            return Some((item, if terminal { None } else { Some(rx) }));
                        }
                        // A slow subscriber lagged past the ring; skip the gap and keep reading.
                        Err(RecvError::Lagged(_)) => continue,
                        // Producer dropped its sender without a terminal frame (e.g. the guard's
                        // defensive Drop). Close the stream.
                        Err(RecvError::Closed) => return None,
                    }
                }
            });
            let stream = stream::once(async move { Ok::<_, Infallible>(seed) })
                .chain(live)
                .boxed();
            return Ok(Sse::new(stream).keep_alive(KeepAlive::new().interval(Duration::from_secs(15))));
        }
    }

    // FINISHED / no-registry path: one synthetic terminal frame from the persisted row, then close.
    let terminal = terminal_event_for(&run);
    let item: Result<Event, Infallible> = Ok(sse_event(&terminal));
    let stream = stream::once(async move { item }).boxed();
    Ok(Sse::new(stream).keep_alive(KeepAlive::new().interval(Duration::from_secs(15))))
}

/// Render a `RunEvent` as an SSE `Event` with its typed `event:` name + JSON `data:`. Serialization
/// is infallible for these small structural events; a (theoretically) failed encode degrades to an
/// empty-data event of the right name rather than tearing down the stream.
fn sse_event(ev: &RunEvent) -> Event {
    let data = serde_json::to_string(ev).unwrap_or_else(|_| "{}".into());
    Event::default().event(ev.name()).data(data)
}

/// Map a finalized `runs` row to a terminal [`RunEvent`] for the immediate-close path. A row that
/// (defensively) is still `running` but not live maps to an `error` so the stream still closes.
fn terminal_event_for(run: &runs::Run) -> RunEvent {
    use crate::local::engine::RunStatus;
    let status = match run.status.as_str() {
        "success" => RunStatus::Success,
        "cancelled" => RunStatus::Cancelled,
        "timeout" => RunStatus::Timeout,
        "captcha_required" => RunStatus::CaptchaRequired,
        "twofa_required" => RunStatus::TwofaRequired,
        "running" | "repairing" => {
            // Not live but the row says running/repairing (orphaned / engine has no registry):
            // surface an error so the client doesn't wait forever.
            return RunEvent::Error {
                run_id: run.id,
                message: "run is not live (no event stream available)".into(),
            };
        }
        // failed | interrupted | anything else → failed.
        _ => RunStatus::Failed,
    };
    RunEvent::Finished { run_id: run.id, status }
}

/// Parse a stored JSON-TEXT column. `None`/empty → JSON null. A non-JSON string is wrapped as a
/// JSON string rather than 500-ing, so a malformed legacy row still reads back.
fn parse_json_text(raw: Option<&str>) -> LocalResult<Value> {
    match raw {
        None => Ok(Value::Null),
        Some(s) if s.trim().is_empty() => Ok(Value::Null),
        Some(s) => Ok(serde_json::from_str(s).unwrap_or_else(|_| Value::String(s.to_string()))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::local::config::LocalConfig;
    use crate::local::server::AppState;
    use crate::local::store::runs::{complete, insert, NewRun};
    use crate::local::store::workflows::{self, NewWorkflow};
    use crate::local::{config, db, engine, vault};
    use axum::body::{to_bytes, Body};
    use axum::http::Request;
    use std::sync::Arc;
    use tower::ServiceExt;

    /// A minimal `AppState` over a fresh encrypted DB with the (registry-less) `StubEngine`. The
    /// run-row reads + the FINISHED-path SSE + per-run CSV don't need a live engine; they exercise
    /// the persisted-row paths, which is exactly the immediate-close / export behavior under test.
    async fn state() -> AppState {
        let dir = tempfile::tempdir().unwrap();
        let paths = config::Paths::at(dir.keep());
        paths.ensure_dirs().unwrap();
        let v = vault::Vault::load_or_create(&paths.root, false).unwrap();
        let pool = db::open(&paths.db(), &v.db_key_hex()).await.unwrap();
        AppState {
            db: pool,
            vault: Arc::new(v),
            engine: Arc::new(engine::StubEngine),
            config: LocalConfig::default(),
            token: Arc::new("wlt_test".into()),
            health: crate::local::app::health::DaemonHealth::shared(),
            recorder: None,
        }
    }

    /// Mount just the runs router (no auth layer — these tests target the handlers directly).
    fn app(st: AppState) -> Router {
        router().with_state(st)
    }

    /// `GET /v1/runs` must carry the AI-repair verdict (0023) through to the feed, because it is the
    /// ONLY post-run trace a repair leaves (`status='repairing'` is transient and overwritten).
    /// Drives the real handler end-to-end over seeded rows: a fixed run, a gave-up run, an untouched
    /// failure, and a failure whose workflow was repaired afterwards.
    #[tokio::test]
    async fn feed_carries_the_repair_verdict_and_resolves_stale_failures() {
        let st = state().await;
        // Two workflows so `repaired_since` is scoped per-workflow, not global.
        let fixed_wf = workflows::insert(&st.db, &NewWorkflow { name: "fixed".into(), ..Default::default() })
            .await
            .unwrap();
        let plain_wf = workflows::insert(&st.db, &NewWorkflow { name: "plain".into(), ..Default::default() })
            .await
            .unwrap();

        // Fails FIRST, then the workflow gets repaired → resolved, not actionable.
        let stale = insert(&st.db, &NewRun { workflow_id: Some(fixed_wf.id), ..Default::default() }).await.unwrap();
        runs::fail(&st.db, stale.id, "failed", Some("boom"), Some("selector"), Some(1)).await.unwrap();
        // strftime has millisecond resolution; make sure the repair lands strictly after the failure.
        tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        workflows::mark_repaired(&st.db, fixed_wf.id).await.unwrap();

        // Repair gave up → stays actionable, badged.
        let gave_up = insert(&st.db, &NewRun { workflow_id: Some(plain_wf.id), ..Default::default() }).await.unwrap();
        runs::set_repair_outcome(&st.db, gave_up.id, false).await.unwrap();
        runs::fail(&st.db, gave_up.id, "failed", Some("boom"), Some("selector"), Some(1)).await.unwrap();

        // Repair worked → resolved.
        let healed = insert(&st.db, &NewRun { workflow_id: Some(plain_wf.id), ..Default::default() }).await.unwrap();
        runs::set_repair_outcome(&st.db, healed.id, true).await.unwrap();
        runs::fail(&st.db, healed.id, "failed", Some("boom"), Some("selector"), Some(1)).await.unwrap();

        // Never touched by repair → actionable, no badge.
        let untouched = insert(&st.db, &NewRun { workflow_id: Some(plain_wf.id), ..Default::default() }).await.unwrap();
        runs::fail(&st.db, untouched.id, "failed", Some("boom"), Some("selector"), Some(1)).await.unwrap();

        let resp = app(st)
            .oneshot(Request::builder().uri("/v1/runs?limit=50").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(resp.status(), 200);
        let body = to_bytes(resp.into_body(), 256 * 1024).await.unwrap();
        let v: Value = serde_json::from_slice(&body).unwrap();
        let by_id: HashMap<String, &Value> = v["data"]
            .as_array()
            .unwrap()
            .iter()
            .map(|i| (i["id"].as_str().unwrap().to_string(), i))
            .collect();

        let item = |run_id: i64| *by_id.get(&format!("workflow-{run_id}")).expect("run missing from feed");

        // (repaired, repair_failed, repaired_since)
        let flags = |run_id: i64| {
            let i = item(run_id);
            (i["repaired"].as_bool(), i["repair_failed"].as_bool(), i["repaired_since"].as_bool())
        };
        assert_eq!(flags(stale.id), (Some(false), Some(false), Some(true)), "workflow fixed after it failed");
        assert_eq!(flags(gave_up.id), (Some(false), Some(true), Some(false)), "AI tried and gave up");
        assert_eq!(flags(healed.id), (Some(true), Some(false), Some(false)), "AI fixed this run");
        assert_eq!(flags(untouched.id), (Some(false), Some(false), Some(false)), "repair never ran");

        // The Home filter these flags exist to drive: keep only what still needs a human.
        let keeps: Vec<i64> = [stale.id, gave_up.id, healed.id, untouched.id]
            .into_iter()
            .filter(|id| {
                let (rp, rf, rs) = flags(*id);
                rf.unwrap() || !(rp.unwrap() || rs.unwrap())
            })
            .collect();
        assert_eq!(keeps, vec![gave_up.id, untouched.id]);
    }

    /// A FAILED run of a workflow that was repaired EARLIER is the newest break, not a stale row — it
    /// must stay actionable. This is the case that a naive "workflow was ever repaired" check breaks.
    #[tokio::test]
    async fn a_failure_newer_than_the_repair_stays_actionable() {
        let st = state().await;
        let wf = workflows::insert(&st.db, &NewWorkflow { name: "wf".into(), ..Default::default() })
            .await
            .unwrap();
        workflows::mark_repaired(&st.db, wf.id).await.unwrap();
        tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        let run = insert(&st.db, &NewRun { workflow_id: Some(wf.id), ..Default::default() }).await.unwrap();
        runs::fail(&st.db, run.id, "failed", Some("broke again"), Some("selector"), Some(1)).await.unwrap();

        let resp = app(st)
            .oneshot(Request::builder().uri("/v1/runs?limit=50").body(Body::empty()).unwrap())
            .await
            .unwrap();
        let body = to_bytes(resp.into_body(), 256 * 1024).await.unwrap();
        let v: Value = serde_json::from_slice(&body).unwrap();
        let item = &v["data"].as_array().unwrap()[0];
        assert_eq!(item["id"], format!("workflow-{}", run.id));
        assert_eq!(item["repaired_since"], false, "the failure came AFTER the repair");
    }

    /// An UNFINISHED run can't be ordered against a repair, so it must never be optimistically hidden
    /// as resolved — `repaired_since` is only meaningful once `completed_at` exists.
    #[tokio::test]
    async fn an_unfinished_run_is_never_marked_resolved() {
        let st = state().await;
        let wf = workflows::insert(&st.db, &NewWorkflow { name: "wf".into(), ..Default::default() })
            .await
            .unwrap();
        workflows::mark_repaired(&st.db, wf.id).await.unwrap();
        let run = insert(&st.db, &NewRun { workflow_id: Some(wf.id), ..Default::default() }).await.unwrap();

        let resp = app(st)
            .oneshot(Request::builder().uri(format!("/v1/runs/{}", run.id)).body(Body::empty()).unwrap())
            .await
            .unwrap();
        let body = to_bytes(resp.into_body(), 64 * 1024).await.unwrap();
        let v: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(v["status"], "running");
        assert_eq!(v["repaired_since"], false);
        assert_eq!(v["repaired"], false);
        assert_eq!(v["repair_failed"], false);
    }

    /// A finished run's `/events` stream emits exactly one terminal `finished` frame then closes
    /// (immediate-close path: the run is not live in the stub engine's absent registry).
    #[tokio::test]
    async fn events_immediate_close_for_finished_run() {
        let st = state().await;
        let wf = workflows::insert(&st.db, &NewWorkflow { name: "wf".into(), ..Default::default() })
            .await
            .unwrap();
        let run = insert(&st.db, &NewRun { workflow_id: Some(wf.id), ..Default::default() }).await.unwrap();
        complete(&st.db, run.id, Some(r#"{"success":true,"extracted_data":{}}"#), Some(5)).await.unwrap();

        let resp = app(st)
            .oneshot(
                Request::builder()
                    .uri(format!("/v1/runs/{}/events", run.id))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), 200);
        assert_eq!(
            resp.headers().get(header::CONTENT_TYPE).unwrap(),
            "text/event-stream"
        );
        // The body is a single SSE frame: event: finished + a data line with status success.
        let body = to_bytes(resp.into_body(), 64 * 1024).await.unwrap();
        let text = String::from_utf8_lossy(&body);
        assert!(text.contains("event: finished"), "got: {text}");
        assert!(text.contains("\"status\":\"success\""), "got: {text}");
    }

    /// `/events` for a missing run is a clean 404 (not a hung empty stream).
    #[tokio::test]
    async fn events_missing_run_is_404() {
        let st = state().await;
        let resp = app(st)
            .oneshot(Request::builder().uri("/v1/runs/999999/events").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(resp.status(), 404);
    }

    /// `/data?format=csv` flattens a run's extracted list into a per-row CSV via the shared engine.
    #[tokio::test]
    async fn per_run_csv_export() {
        let st = state().await;
        let wf = workflows::insert(&st.db, &NewWorkflow { name: "wf".into(), ..Default::default() })
            .await
            .unwrap();
        let run = insert(&st.db, &NewRun { workflow_id: Some(wf.id), ..Default::default() }).await.unwrap();
        // A run that extracted a 2-item list under `items`.
        let result = serde_json::json!({
            "success": true,
            "extracted_data": { "items": [ {"title": "A", "price": 10}, {"title": "B", "price": 20} ] }
        });
        complete(&st.db, run.id, Some(&result.to_string()), Some(7)).await.unwrap();

        let resp = app(st)
            .oneshot(
                Request::builder()
                    .uri(format!("/v1/runs/{}/data?format=csv", run.id))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), 200);
        assert!(resp
            .headers()
            .get(header::CONTENT_TYPE)
            .unwrap()
            .to_str()
            .unwrap()
            .starts_with("text/csv"));
        let body = to_bytes(resp.into_body(), 64 * 1024).await.unwrap();
        let csv = String::from_utf8_lossy(&body);
        // Header carries run metadata + the data columns; both records become rows.
        assert!(csv.contains("run_id"), "csv header: {csv}");
        assert!(csv.contains("title"), "csv header: {csv}");
        assert!(csv.contains('A') && csv.contains('B'), "csv rows: {csv}");
    }

    /// `GET /v1/runs` returns ENRICHED feed items (resolved name + deep-links), not raw rows.
    /// This is the contract the desktop UI reads — a regression here is what made run rows blank.
    #[tokio::test]
    async fn list_projects_enriched_feed_items() {
        let st = state().await;
        let wf = workflows::insert(&st.db, &NewWorkflow { name: "Daily scrape".into(), ..Default::default() })
            .await
            .unwrap();
        let run = insert(&st.db, &NewRun { workflow_id: Some(wf.id), ..Default::default() }).await.unwrap();
        complete(&st.db, run.id, Some(r#"{"success":true,"extracted_data":{"title":"x"}}"#), Some(42)).await.unwrap();

        let resp = app(st)
            .oneshot(Request::builder().uri("/v1/runs").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(resp.status(), 200);
        let body = to_bytes(resp.into_body(), 64 * 1024).await.unwrap();
        let v: Value = serde_json::from_slice(&body).unwrap();
        let item = &v["data"][0];
        assert_eq!(item["id"], format!("workflow-{}", run.id));
        assert_eq!(item["run_type"], "workflow");
        assert_eq!(item["entity_id"], wf.id);
        assert_eq!(item["entity_name"], "Daily scrape");
        assert_eq!(item["status"], "success");
        assert_eq!(item["duration_ms"], 42);
        assert_eq!(item["detail_url_hint"], format!("/workflows/{}", wf.id));
        // A successful run that produced a row advertises the Data view.
        assert_eq!(item["data_url_hint"], format!("/workflows/{}?tab=data", wf.id));
        // started_at falls back to created_at; finished_at is the completion stamp.
        assert!(item["started_at"].is_string());
        assert!(item["finished_at"].is_string());
        // Workflow run carries a record count (one record → 1) and no change flag.
        assert_eq!(item["rows_extracted"], 1);
        assert!(item["change_detected"].is_null());
    }

    /// A SUCCESSFUL run that extracted no rows (empty `extracted_data`) gets a detail link but NO
    /// data link — the aggregated Data view would show nothing for it, so advertising "View data"
    /// is just noise.
    #[tokio::test]
    async fn list_zero_row_run_has_no_data_link() {
        let st = state().await;
        let wf = workflows::insert(&st.db, &NewWorkflow { name: "wf".into(), ..Default::default() })
            .await
            .unwrap();
        let run = insert(&st.db, &NewRun { workflow_id: Some(wf.id), ..Default::default() }).await.unwrap();
        complete(&st.db, run.id, Some(r#"{"success":true,"extracted_data":{}}"#), Some(3)).await.unwrap();

        let resp = app(st)
            .oneshot(Request::builder().uri("/v1/runs").body(Body::empty()).unwrap())
            .await
            .unwrap();
        let body = to_bytes(resp.into_body(), 64 * 1024).await.unwrap();
        let v: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(v["data"][0]["status"], "success");
        assert_eq!(v["data"][0]["rows_extracted"], 0);
        assert_eq!(v["data"][0]["detail_url_hint"], format!("/workflows/{}", wf.id));
        assert!(v["data"][0]["data_url_hint"].is_null(), "0-row run must not advertise a data link");
    }

    /// A FAILED run gets no data link even if it wrote a partial `extracted_data` before dying: the
    /// Data view aggregates successful runs only, so its data never appears there.
    #[tokio::test]
    async fn list_failed_run_has_no_data_link() {
        use crate::local::store::runs::fail;
        let st = state().await;
        let wf = workflows::insert(&st.db, &NewWorkflow { name: "wf".into(), ..Default::default() })
            .await
            .unwrap();
        let run = insert(&st.db, &NewRun { workflow_id: Some(wf.id), ..Default::default() }).await.unwrap();
        // Write a partial extracted_data payload, then finalize as failed (success flips to 0;
        // `fail` leaves result_data intact) — modelling a run that scraped something before dying.
        complete(&st.db, run.id, Some(r#"{"extracted_data":{"title":"partial"}}"#), Some(4)).await.unwrap();
        fail(&st.db, run.id, "failed", Some("boom"), Some("recipe"), Some(4)).await.unwrap();

        let resp = app(st)
            .oneshot(Request::builder().uri("/v1/runs").body(Body::empty()).unwrap())
            .await
            .unwrap();
        let body = to_bytes(resp.into_body(), 64 * 1024).await.unwrap();
        let v: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(v["data"][0]["status"], "failed");
        assert!(v["data"][0]["data_url_hint"].is_null(), "failed run must not advertise a data link");
    }

    /// A workflow run that extracted a list of records reports that record count under
    /// `rows_extracted` — the same row count the Data view shows — so the feed can say "N rows
    /// extracted" without materializing the table.
    #[tokio::test]
    async fn list_counts_extracted_rows() {
        let st = state().await;
        let wf = workflows::insert(&st.db, &NewWorkflow { name: "scrape".into(), ..Default::default() })
            .await
            .unwrap();
        let run = insert(&st.db, &NewRun { workflow_id: Some(wf.id), ..Default::default() }).await.unwrap();
        let result = serde_json::json!({
            "success": true,
            "extracted_data": { "items": [ {"title": "A"}, {"title": "B"}, {"title": "C"} ] }
        });
        complete(&st.db, run.id, Some(&result.to_string()), Some(9)).await.unwrap();

        let resp = app(st)
            .oneshot(Request::builder().uri("/v1/runs").body(Body::empty()).unwrap())
            .await
            .unwrap();
        let body = to_bytes(resp.into_body(), 64 * 1024).await.unwrap();
        let v: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(v["data"][0]["rows_extracted"], 3);
        assert!(v["data"][0]["change_detected"].is_null());
    }

    /// A FAILED run surfaces its error inline under the projected `error` key (raw column is
    /// `error_message`) — the field the UI renders in the row.
    #[tokio::test]
    async fn list_maps_error_message_to_error() {
        use crate::local::store::runs::fail;
        let st = state().await;
        let wf = workflows::insert(&st.db, &NewWorkflow { name: "wf".into(), ..Default::default() })
            .await
            .unwrap();
        let run = insert(&st.db, &NewRun { workflow_id: Some(wf.id), ..Default::default() }).await.unwrap();
        fail(&st.db, run.id, "failed", Some("selector not found"), Some("recipe"), Some(7)).await.unwrap();

        let resp = app(st)
            .oneshot(Request::builder().uri("/v1/runs").body(Body::empty()).unwrap())
            .await
            .unwrap();
        let body = to_bytes(resp.into_body(), 64 * 1024).await.unwrap();
        let v: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(v["data"][0]["status"], "failed");
        assert_eq!(v["data"][0]["error"], "selector not found");
    }

    /// `?entity_id=` scopes the feed to that workflow (the contract the workflow-detail runs tab
    /// sends); other workflows' runs are excluded.
    #[tokio::test]
    async fn list_scopes_by_entity_id() {
        let st = state().await;
        let wf1 = workflows::insert(&st.db, &NewWorkflow { name: "one".into(), ..Default::default() }).await.unwrap();
        let wf2 = workflows::insert(&st.db, &NewWorkflow { name: "two".into(), ..Default::default() }).await.unwrap();
        insert(&st.db, &NewRun { workflow_id: Some(wf1.id), ..Default::default() }).await.unwrap();
        insert(&st.db, &NewRun { workflow_id: Some(wf2.id), ..Default::default() }).await.unwrap();
        insert(&st.db, &NewRun { workflow_id: Some(wf2.id), ..Default::default() }).await.unwrap();

        let resp = app(st)
            .oneshot(
                Request::builder()
                    .uri(format!("/v1/runs?run_type=workflow&entity_id={}", wf2.id))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let body = to_bytes(resp.into_body(), 64 * 1024).await.unwrap();
        let v: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(v["count"], 2, "only wf2's two runs");
        for item in v["data"].as_array().unwrap() {
            assert_eq!(item["entity_id"], wf2.id);
        }
    }

    /// A non-workflow `run_type` returns an EMPTY page (no check/automation rows persist locally) —
    /// not the global workflow feed leaked into a scoped detail view.
    #[tokio::test]
    async fn list_non_workflow_run_type_is_empty() {
        let st = state().await;
        let wf = workflows::insert(&st.db, &NewWorkflow { name: "wf".into(), ..Default::default() }).await.unwrap();
        insert(&st.db, &NewRun { workflow_id: Some(wf.id), ..Default::default() }).await.unwrap();

        let resp = app(st)
            .oneshot(
                Request::builder()
                    .uri("/v1/runs?run_type=automation&entity_id=5")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let body = to_bytes(resp.into_body(), 64 * 1024).await.unwrap();
        let v: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(v["count"], 0);
        assert_eq!(v["data"].as_array().unwrap().len(), 0);
    }

    /// A streaming workflow gets a detail link but NO data link (live session, no extracted table).
    #[tokio::test]
    async fn list_streaming_workflow_has_no_data_link() {
        let st = state().await;
        let wf = workflows::insert(
            &st.db,
            &NewWorkflow { name: "chat".into(), workflow_type: Some("streaming".into()), ..Default::default() },
        )
        .await
        .unwrap();
        let run = insert(&st.db, &NewRun { workflow_id: Some(wf.id), ..Default::default() }).await.unwrap();
        complete(&st.db, run.id, None, Some(1)).await.unwrap();

        let resp = app(st)
            .oneshot(Request::builder().uri("/v1/runs").body(Body::empty()).unwrap())
            .await
            .unwrap();
        let body = to_bytes(resp.into_body(), 64 * 1024).await.unwrap();
        let v: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(v["data"][0]["detail_url_hint"], format!("/workflows/{}", wf.id));
        assert!(v["data"][0]["data_url_hint"].is_null());
    }

    /// Default `/data` (no format) still returns the extracted JSON envelope.
    #[tokio::test]
    async fn per_run_data_json_default() {
        let st = state().await;
        let wf = workflows::insert(&st.db, &NewWorkflow { name: "wf".into(), ..Default::default() })
            .await
            .unwrap();
        let run = insert(&st.db, &NewRun { workflow_id: Some(wf.id), ..Default::default() }).await.unwrap();
        complete(&st.db, run.id, Some(r#"{"success":true,"extracted_data":{"k":"v"}}"#), Some(3)).await.unwrap();

        let resp = app(st)
            .oneshot(
                Request::builder()
                    .uri(format!("/v1/runs/{}/data", run.id))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), 200);
        let body = to_bytes(resp.into_body(), 64 * 1024).await.unwrap();
        let v: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(v["data"]["k"], "v");
        assert_eq!(v["status"], "success");
    }
}
