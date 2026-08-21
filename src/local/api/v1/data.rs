//! `/v1/data` REST handlers — the extracted-data query surface for the desktop backend.
//!
//! Every run persists what it scraped under the `extracted_data` key of `runs.result_data`.
//! These endpoints aggregate that across a workflow's runs into one sortable/searchable table
//! (see `local::data_query` for the pure flatten/filter/sort/paginate/facets/CSV engine and the
//! SECURITY-CRITICAL redaction). This single-user local backend has no tenant boundary, but the
//! redaction in `data_query` is still load-bearing: the internal envelope (raw_html, cookies,
//! auth_session, html, screenshots, …) and secret-shaped run inputs (password/token/otp/…) must
//! never surface as a column or cell.
//!
//! House style: thin handlers over the `runs`/`workflows` stores + the pure query module,
//! `LocalResult<Json<_>>` (or a raw `Response` for export) with `?` propagation. No auth layer
//! here — `server.rs` applies the loopback bearer + Origin/Host guard at the router level.

use crate::local::data_query::{self, Clause, RunInput, TableQuery};
use crate::local::error::{LocalError, LocalResult};
use crate::local::server::AppState;
use crate::local::store::{runs, workflows};
use axum::extract::{Path, Query, RawQuery, State};
use axum::http::{header, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::{Json, Router};
use serde::Deserialize;
use serde_json::{json, Map, Value};
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::sync::{Mutex, OnceLock};

/// How many recent runs we scan when building the table. Bounded so a workflow with a huge
/// history stays responsive; the response flags `truncated` when the scan hits this ceiling.
const DATA_SCAN_CAP: i64 = 1000;

/// Default page size for `GET /v1/workflows/:id/data` when `?limit=` is omitted.
const DEFAULT_PAGE: usize = 50;
/// Hard cap on a single page so a client cannot ask for an unbounded page.
const MAX_PAGE: usize = 500;

/// Mount the data routes onto the shared `AppState` router. Auth is applied by `server.rs`.
/// NB: nested routes reuse the `:id` param name — a different name at the same segment panics
/// matchit at startup.
pub fn router() -> Router<AppState> {
    Router::new()
        .route("/v1/data", get(list_data_workflows))
        .route(
            "/v1/workflows/:id/data",
            get(workflow_data).delete(delete_workflow_data),
        )
        .route("/v1/workflows/:id/data/rows", get(workflow_data_rows))
        .route("/v1/workflows/:id/data/runs", get(workflow_data_runs))
        .route(
            "/v1/workflows/:id/data/records/:record_uid/history",
            get(workflow_record_history),
        )
        .route("/v1/workflows/:id/data/facets", get(workflow_data_facets))
        .route("/v1/workflows/:id/data/export", get(export_workflow_data))
        .route("/v1/workflows/:id/data/preview", axum::routing::post(workflow_data_preview))
        // Datasets — the first-class, consumer-facing framing of a data source's accumulated
        // extracted data. A dataset's id IS its workflow id, so every handler reuses the exact
        // same scan/flatten/redaction (and cloud-forward) as the workflow-data routes above.
        .route("/v1/datasets", get(list_datasets))
        .route("/v1/datasets/search", get(search_datasets))
        .route("/v1/datasets/:id", get(dataset_meta))
        .route("/v1/datasets/:id/records", get(dataset_records))
        .route("/v1/datasets/:id/search", get(search_dataset))
        .route("/v1/datasets/:id/export", get(export_dataset))
}

// ---------------------------------------------------------------------------
// Shared helpers.
// ---------------------------------------------------------------------------

/// Parse a stored JSON-TEXT column to a `Value`. `None`/empty → JSON null; a non-JSON legacy
/// string is wrapped as a JSON string rather than failing the whole scan.
fn parse_json_text(raw: Option<&str>) -> Value {
    match raw {
        None => Value::Null,
        Some(s) if s.trim().is_empty() => Value::Null,
        Some(s) => serde_json::from_str(s).unwrap_or_else(|_| Value::String(s.to_string())),
    }
}

/// The workflow's DECLARED output fields = the union of `output_fields` across its callable
/// `functions` (JSON-TEXT `functions` column). A field entry is a bare string or `{"name": ...}`.
/// Returns a flat list of field-name strings (empty when nothing is declared).
/// `pub(crate)`: the MCP `writ_search_data` tool builds the same table the Data page shows.
pub(crate) fn declared_output_fields(wf: &workflows::Workflow) -> Vec<String> {
    let parsed = parse_json_text(wf.functions.as_deref());
    let fns = match parsed.as_array() {
        Some(a) => a,
        None => return Vec::new(),
    };
    let mut fields: Vec<String> = Vec::new();
    for fnv in fns {
        let ofs = match fnv.get("output_fields").and_then(|v| v.as_array()) {
            Some(a) => a,
            None => continue,
        };
        for f in ofs {
            match f {
                Value::String(s) => fields.push(s.clone()),
                Value::Object(o) => {
                    if let Some(Value::String(name)) = o.get("name") {
                        fields.push(name.clone());
                    }
                }
                _ => {}
            }
        }
    }
    fields
}

/// Convert a `runs::Run` row into the `RunInput` the query engine consumes (parsing its JSON-TEXT
/// columns once). `run_at` is the completed time, falling back to created time (recency).
fn to_run_input(run: runs::Run) -> RunInput {
    let run_at = run.completed_at.clone().or_else(|| Some(run.created_at.clone()));
    RunInput {
        run_id: run.id,
        run_at,
        status: Some(run.status.clone()),
        success: run.success.map(|s| s != 0),
        duration_ms: run.duration_ms,
        result_data: parse_json_text(run.result_data.as_deref()),
        trigger_context: parse_json_text(run.trigger_context.as_deref()),
    }
}

/// Most-recent SUCCESSFUL runs of a workflow that produced a real `extracted_data` value, bounded
/// by `DATA_SCAN_CAP`. Returns (run inputs, truncated).
///
/// The Data surface aggregates ONLY successful runs. A failed / timed-out / cancelled run can still
/// write a partial or junk `extracted_data` before it stopped; surfacing those rows clutters the
/// table (and the workflow picker's run count) with data the user never actually got — the "failed
/// run data" noise. Filtering to `success == 1` keeps the Data page to what a run genuinely
/// produced. Per-run inspection of a failed run's partial payload stays available on
/// `GET /v1/runs/:id/data` (a distinct, explicit surface).
async fn scan_workflow_data_runs(st: &AppState, workflow_id: i64) -> LocalResult<(Vec<RunInput>, bool)> {
    scan_workflow_data_runs_pool(&st.db, workflow_id).await
}

/// Pool-level variant of [`scan_workflow_data_runs`] — the shared scan the export helper (and the
/// `flow.rs` file-export actions + the MCP `writ_workflow_data` tool) reuse without an `AppState`.
pub(crate) async fn scan_workflow_data_runs_pool(
    db: &sqlx::sqlite::SqlitePool,
    workflow_id: i64,
) -> LocalResult<(Vec<RunInput>, bool)> {
    // Fetch the workflow's runs newest-first (store clamps the limit to 1..=1000), then keep only
    // SUCCESSFUL runs whose parsed result_data carries a non-null `extracted_data`. We over-fetch at
    // the cap and the post-filter keeps it bounded; `truncated` is true when the scan hit the ceiling.
    let rows = runs::list_by_workflow(db, workflow_id, DATA_SCAN_CAP).await?;
    let scanned = rows.len();
    let truncated = scanned as i64 >= DATA_SCAN_CAP;
    let inputs: Vec<RunInput> = rows
        .into_iter()
        .filter(|r| {
            // Only successful runs feed the Data surface (`success == 1` is set exclusively by the
            // success finalizer `store::runs::complete` and by imported cloud runs that succeeded).
            if r.success != Some(1) {
                return false;
            }
            // Cheap pre-filter on the raw text before a full parse: must mention extracted_data.
            r.result_data
                .as_deref()
                .map(|s| s.contains("extracted_data"))
                .unwrap_or(false)
        })
        .map(to_run_input)
        .filter(|ri| {
            // Authoritative filter: a non-null extracted_data value (or a usable top-level shape).
            ri.result_data
                .as_object()
                .and_then(|o| o.get("extracted_data"))
                .map(|v| !v.is_null())
                .unwrap_or(false)
        })
        .collect();
    Ok((inputs, truncated))
}

/// Parse repeated `filter=column:substr` query params into a column→substring map. Splits on the
/// FIRST colon so values may themselves contain colons. (Legacy per-column filter API.)
fn parse_col_filters(filters: &[String]) -> BTreeMap<String, String> {
    let mut out = BTreeMap::new();
    for raw in filters {
        if let Some((col, sub)) = raw.split_once(':') {
            let col = col.trim();
            if !col.is_empty() {
                out.insert(col.to_string(), sub.to_string());
            }
        }
    }
    out
}

/// Parse the structured smart-filter param: a JSON array of clauses like
/// `[{"col":"price","op":"between","min":10,"max":50}]`. Returns `[]` on any problem (never
/// errors) — a malformed filter must not fail the data view.
fn parse_structured_filters(filters_json: Option<&str>) -> Vec<Clause> {
    let raw = match filters_json {
        Some(s) if !s.trim().is_empty() => s,
        _ => return Vec::new(),
    };
    let parsed: Value = match serde_json::from_str(raw) {
        Ok(v) => v,
        Err(_) => return Vec::new(),
    };
    let arr = match parsed.as_array() {
        Some(a) => a,
        None => return Vec::new(),
    };
    arr.iter()
        .filter_map(|c| serde_json::from_value::<Clause>(c.clone()).ok())
        .filter(|c| !c.col.is_empty() && !c.op.is_empty())
        .collect()
}

/// Sanitize a workflow name into a safe export filename stem.
fn safe_export_filename(name: &str) -> String {
    let mut out = String::new();
    let mut last_dash = false;
    for ch in name.trim().chars() {
        if ch.is_ascii_alphanumeric() || ch == '.' || ch == '_' || ch == '-' {
            out.push(ch);
            last_dash = ch == '-';
        } else if !last_dash {
            out.push('-');
            last_dash = true;
        }
    }
    let trimmed = out.trim_matches('-');
    let base = if trimmed.is_empty() { "workflow" } else { trimmed };
    base.chars().take(60).collect()
}

// ---------------------------------------------------------------------------
// Query params.
// ---------------------------------------------------------------------------

#[derive(Debug, Default, Deserialize)]
struct TableParams {
    /// Global substring filter across extracted fields.
    #[serde(default)]
    q: Option<String>,
    /// Per-column legacy filter `column:substring` (repeatable).
    #[serde(default)]
    filter: Vec<String>,
    /// Structured smart filters: a JSON array of clauses.
    #[serde(default)]
    filters: Option<String>,
    /// A data column or `run_at`/`status`/`duration_ms`/`run_id`.
    #[serde(default)]
    sort_by: Option<String>,
    /// `asc` or `desc`.
    #[serde(default)]
    sort_dir: Option<String>,
    #[serde(default)]
    limit: Option<usize>,
    #[serde(default)]
    offset: Option<usize>,
    /// Also surface run input values as `input.<name>` columns (view=all only).
    #[serde(default)]
    include_inputs: bool,
    /// Lens: `latest` | `run` | `all` (default all).
    #[serde(default)]
    view: Option<String>,
    /// The snapshot to show — required when `view=run`.
    #[serde(default)]
    run_id: Option<i64>,
    /// Explicit identity key: comma-separated field names (identity pinning echo).
    #[serde(default)]
    key: Option<String>,
    /// view=latest: include records missing from the newest snapshot. Parsed STRICTLY — only the
    /// literal "true" enables it.
    #[serde(default)]
    include_missing: Option<String>,
    /// view=latest/run: only records from this originating list key ("" = untagged records);
    /// the response's `sources` counts stay unfiltered (spec 3.1).
    #[serde(default)]
    source: Option<String>,
    /// Nested-collection pivot — NOT implemented server-side on the daemon (the desktop app
    /// scopes nested collections client-side). Accepted only so the spec-pinned validation
    /// holds: `view!=all` + `collection` → 400 "change tracking operates on top-level records".
    #[serde(default)]
    collection: Option<String>,
    /// `csv` (default) or `json` — read by the export endpoint only. Lives here rather than in a
    /// `#[serde(flatten)]` wrapper: serde_urlencoded cannot deserialize numeric fields (`run_id`,
    /// `limit`, …) through `flatten`, which 400-rejected every `view=run` snapshot export.
    #[serde(default)]
    format: Option<String>,
    /// Grid preview mode: string fields longer than this many characters are cut to it and the
    /// row lists them under `_truncated`; the grid hydrates full records on demand via
    /// `GET /data/rows`. JSON table responses only — exports stay full.
    #[serde(default)]
    preview_chars: Option<usize>,
}

impl TableParams {
    /// Build the pure-engine query (page-bounded). `limit=None` means "use the page cap".
    fn to_query(&self, paged: bool) -> TableQuery {
        TableQuery {
            q: self.q.clone(),
            col_filters: parse_col_filters(&self.filter),
            filters: parse_structured_filters(self.filters.as_deref()),
            sort_by: self.sort_by.clone(),
            sort_dir: self.sort_dir.clone().unwrap_or_else(|| "desc".into()),
            offset: self.offset.unwrap_or(0),
            limit: if paged {
                Some(self.limit.unwrap_or(DEFAULT_PAGE).clamp(1, MAX_PAGE))
            } else {
                None
            },
        }
    }
}

#[derive(Debug, Default, Deserialize)]
struct FacetParams {
    #[serde(default)]
    include_inputs: bool,
    /// Lens: `latest` | `run` | `all` (default all) — facets compute over exactly that rowset.
    #[serde(default)]
    view: Option<String>,
    #[serde(default)]
    run_id: Option<i64>,
    #[serde(default)]
    key: Option<String>,
    /// Strict "true" includes missing records in the view=latest rowset.
    #[serde(default)]
    include_missing: Option<String>,
    /// view=latest/run: facet only records from this originating list key ("" = untagged).
    #[serde(default)]
    source: Option<String>,
    /// Accepted only for the shared lens-param validation (see `TableParams::collection`).
    #[serde(default)]
    collection: Option<String>,
}

/// Query params for the lineage endpoints (`/data/runs`, `/history`): the identity `key` echo.
#[derive(Debug, Default, Deserialize)]
struct LineageParams {
    #[serde(default)]
    key: Option<String>,
}

// ---------------------------------------------------------------------------
// Lineage lenses (DATA_REDESIGN_SPEC) — shared assembly for view=latest / view=run.
// ---------------------------------------------------------------------------

/// Identity scoring samples at most this many of the newest data-bearing runs (spec 1.3).
const IDENTITY_SAMPLE_RUNS: usize = 50;
/// The picker skips `last_delta` when a workflow's flattened rows exceed this (spec 1.5.7).
const PICKER_DELTA_MAX_ROWS: usize = 20_000;

/// Everything the lens endpoints need: the scanned runs flattened per-run (ascending chain
/// order), canonical columns, the chosen identity and the lineage pass output.
struct Lens {
    wf: workflows::Workflow,
    declared: Vec<String>,
    flat: Vec<data_query::FlatRun>,
    columns: Vec<String>,
    identity: data_query::Identity,
    lineage: data_query::Lineage,
    scanned: usize,
    truncated: bool,
}

async fn build_lens(
    st: &AppState,
    id: i64,
    key: Option<&str>,
    detail_run: Option<i64>,
) -> LocalResult<Lens> {
    let wf = load_workflow(st, id).await?;
    let declared = declared_output_fields(&wf);
    let (mut runs_with_data, truncated) = scan_workflow_data_runs(st, id).await?;
    let scanned = runs_with_data.len();
    sort_runs_ascending(&mut runs_with_data);
    let flat = data_query::flatten_runs(&runs_with_data, &declared);
    let columns = data_query::canonical_columns(&flat, &declared);
    let identity = pick_identity(&flat, &columns, key);
    let lineage = data_query::build_lineage(&flat, identity.mode, &identity.fields, detail_run);
    Ok(Lens { wf, declared, flat, columns, identity, lineage, scanned, truncated })
}

/// Chain order: ascending (coalesce(completed_at, created_at), run_id) — run_id as tie-break.
fn sort_runs_ascending(runs: &mut [RunInput]) {
    runs.sort_by(|a, b| {
        (a.run_at.as_deref().unwrap_or(""), a.run_id)
            .cmp(&(b.run_at.as_deref().unwrap_or(""), b.run_id))
    });
}

/// Identity over the bounded sample: the newest ≤50 data-bearing runs' records.
fn pick_identity(
    flat: &[data_query::FlatRun],
    columns: &[String],
    key: Option<&str>,
) -> data_query::Identity {
    let bearing: Vec<Vec<Map<String, Value>>> = flat
        .iter()
        .filter(|r| r.data_bearing)
        .map(|r| r.records.iter().map(|(_, m)| m.clone()).collect())
        .collect();
    let start = bearing.len().saturating_sub(IDENTITY_SAMPLE_RUNS);
    data_query::choose_identity(&bearing[start..], columns, key)
}

/// Strict-bool parse for `include_missing`: only the literal "true" enables it.
fn parse_include_missing(v: Option<&str>) -> bool {
    v == Some("true")
}

/// A lens-param 400 in the python engines' FastAPI body shape (`{"detail": ...}`).
fn lens_params_400(detail: &str) -> Response {
    (StatusCode::BAD_REQUEST, Json(json!({ "detail": detail }))).into_response()
}

/// The spec-pinned 400 for a lens request missing `run_id` (byte-matches the cloud engine).
fn run_id_required() -> Response {
    lens_params_400("run_id is required when view=run")
}

/// Shared 400-validation for the lens params on GET data / facets / export — mirrors the python
/// engines' `_validate_data_lens_params` (identical messages, spec-pinned where noted). Returns
/// the normalized view. The daemon has no server-side `collection` pivot, but the param is still
/// parsed so `view!=all` + `collection` rejects exactly like cloud/coordinator (spec 1.5(1)).
fn validate_lens_params(
    view: Option<&str>,
    run_id: Option<i64>,
    collection: Option<&str>,
) -> Result<String, Response> {
    let view = match view {
        Some(v) if !v.is_empty() => v.trim().to_ascii_lowercase(),
        _ => "all".to_string(),
    };
    if !matches!(view.as_str(), "all" | "latest" | "run") {
        return Err(lens_params_400("view must be one of: latest, run, all"));
    }
    if view != "all" && collection.is_some_and(|c| !c.is_empty()) {
        return Err(lens_params_400("change tracking operates on top-level records"));
    }
    if view == "run" && run_id.is_none() {
        return Err(run_id_required());
    }
    Ok(view)
}

/// The deduped current-dataset rows: one (Row, lineage-payload) pair per latest entry.
fn latest_pairs(lens: &Lens, include_missing: bool) -> Vec<(data_query::Row, Value)> {
    let by_run: BTreeMap<i64, &data_query::FlatRun> =
        lens.flat.iter().map(|r| (r.run_id, r)).collect();
    lens.lineage
        .latest
        .iter()
        .filter(|e| include_missing || e["change"].as_str() != Some("missing"))
        .map(|e| {
            let run_id = e["run_id"].as_i64().unwrap_or_default();
            let record_index = e["record_index"].as_u64().unwrap_or_default() as usize;
            let meta = by_run.get(&run_id);
            let row = data_query::Row {
                run_id,
                run_at: e["last_seen_at"].as_str().map(str::to_string),
                status: meta.and_then(|r| r.status.clone()),
                success: meta.and_then(|r| r.success),
                duration_ms: meta.and_then(|r| r.duration_ms),
                record_index,
                fields: e["fields"].as_object().cloned().unwrap_or_default(),
                inputs: Map::new(),
            };
            let lineage = json!({
                "uid": e["uid"], "change": e["change"],
                "changed_fields": e["changed_fields"], "changed_leaf_count": e["changed_leaf_count"],
                "first_seen_at": e["first_seen_at"], "last_seen_at": e["last_seen_at"],
                "versions": e["versions"],
                // The originating list key of a multi-list expansion (spec 3.1) — looked up on
                // the record's OWN run (the golden-pinned lineage structures stay source-free).
                "source": meta.and_then(|r| r.sources.get(&record_index).cloned()),
            });
            (row, lineage)
        })
        .collect()
}

/// One snapshot's rows (view=run), annotated vs the previous chain member.
fn run_pairs(lens: &Lens, detail: &data_query::RunDetail) -> Vec<(data_query::Row, Value)> {
    let meta = lens.flat.iter().find(|r| r.run_id == detail.run_id);
    detail
        .rows
        .iter()
        .map(|r| {
            let row = data_query::Row {
                run_id: detail.run_id,
                run_at: meta.and_then(|m| m.run_at.clone()),
                status: meta.and_then(|m| m.status.clone()),
                success: meta.and_then(|m| m.success),
                duration_ms: meta.and_then(|m| m.duration_ms),
                record_index: r.record_index,
                fields: r.fields.clone(),
                inputs: Map::new(),
            };
            let lineage = json!({
                "uid": r.uid, "change": r.change,
                "changed_fields": r.changed_fields, "changed_leaf_count": r.changed_leaf_count,
                // WALK-TIME values, matching the python engines' `run_views` (first_seen is
                // set-once so the chain-wide map is fine; last_seen for a snapshot row is that
                // snapshot's OWN run_at; versions counts change-points AS OF this snapshot —
                // never the end-of-chain totals, which would leak later runs into an old view).
                "first_seen_at": lens.lineage.first_seen.get(&r.uid),
                "last_seen_at": meta.and_then(|m| m.run_at.clone()),
                "versions": r.versions,
                "prev_run_id": detail.prev_run_id,
                // Originating list key within THIS snapshot (spec 3.1); null when untagged.
                "source": meta.and_then(|m| m.sources.get(&r.record_index).cloned()),
            });
            (row, lineage)
        })
        .collect()
}

/// The `sources: {<key|"">: count}` response envelope over a lens rowset (spec 3.1) — computed
/// BEFORE the source filter + search so chip counts stay stable while one source is selected;
/// untagged records bucket under `""`.
fn sources_envelope(pairs: &[(data_query::Row, Value)]) -> Value {
    let mut counts: BTreeMap<String, u64> = BTreeMap::new();
    for (_, lineage) in pairs {
        let bucket = lineage["source"].as_str().unwrap_or("").to_string();
        *counts.entry(bucket).or_insert(0) += 1;
    }
    json!(counts)
}

/// Keep only the lens rows whose lineage source matches (`""` selects untagged records) —
/// applied before search/filters/pagination (spec 3.1).
fn filter_pairs_by_source(
    pairs: Vec<(data_query::Row, Value)>,
    source: &str,
) -> Vec<(data_query::Row, Value)> {
    pairs
        .into_iter()
        .filter(|(_, lineage)| lineage["source"].as_str().unwrap_or("") == source)
        .collect()
}

/// Search / structured filters / sort / paginate for lens rows — applied AFTER dedup/annotation.
/// The default order is the lineage default (pairs arrive pre-sorted); an explicit `sort_by` may
/// also target the lineage keys first_seen_at / last_seen_at / versions. Returns
/// `(page, post-filter total)`.
fn apply_lens_query(
    mut pairs: Vec<(data_query::Row, Value)>,
    query: &TableQuery,
    columns: &[String],
) -> (Vec<(data_query::Row, Value)>, usize) {
    if let Some(q) = &query.q {
        let needle = q.trim().to_ascii_lowercase();
        if !needle.is_empty() {
            pairs.retain(|(r, _)| data_query::row_matches(r, &needle));
        }
    }
    for (col, sub) in &query.col_filters {
        let sub = sub.trim().to_ascii_lowercase();
        if sub.is_empty() {
            continue;
        }
        pairs.retain(|(r, _)| {
            data_query::cell_text(&r.value(col)).to_ascii_lowercase().contains(&sub)
        });
    }
    for clause in &query.filters {
        if !clause.col.is_empty() && !clause.op.is_empty() {
            pairs.retain(|(r, _)| data_query::clause_matches(r, clause));
        }
    }
    let total = pairs.len();

    const LINEAGE_SORT_KEYS: [&str; 3] = ["first_seen_at", "last_seen_at", "versions"];
    if let Some(sort_by) = &query.sort_by {
        let is_lineage = LINEAGE_SORT_KEYS.contains(&sort_by.as_str());
        let is_column = columns.contains(sort_by)
            || ["run_at", "status", "duration_ms", "run_id"].contains(&sort_by.as_str());
        if is_lineage || is_column {
            pairs.sort_by(|a, b| {
                let (av, bv) = if is_lineage {
                    (a.1[sort_by.as_str()].clone(), b.1[sort_by.as_str()].clone())
                } else {
                    (a.0.value(sort_by), b.0.value(sort_by))
                };
                data_query::sort_key_for(&av).cmp(&data_query::sort_key_for(&bv))
            });
            if !query.sort_dir.eq_ignore_ascii_case("asc") {
                pairs.reverse();
            }
        }
    }

    let page: Vec<(data_query::Row, Value)> = match query.limit {
        None => pairs.into_iter().skip(query.offset).collect(),
        Some(lim) => pairs.into_iter().skip(query.offset).take(lim).collect(),
    };
    (page, total)
}

/// The row-lineage payload as the API exposes it: `changed_fields` is present only when the
/// row's change is "changed" (spec 1.5).
fn api_lineage(lineage: &Value) -> Value {
    let mut m = lineage.as_object().cloned().unwrap_or_default();
    if m.get("change").and_then(Value::as_str) != Some("changed") {
        m.remove("changed_fields");
    }
    Value::Object(m)
}

/// Table-endpoint rows for a lens: run-meta + `fields` (exactly as view=all) + a sibling
/// `lineage` object.
fn pairs_to_table_json(pairs: &[(data_query::Row, Value)], columns: &[String]) -> Vec<Value> {
    pairs
        .iter()
        .map(|(row, lineage)| {
            let mut v = data_query::row_to_table_json(row, columns);
            v["lineage"] = api_lineage(lineage);
            v
        })
        .collect()
}

// ---------------------------------------------------------------------------
// Cloud-dataset forwarding (desktop-app builds only).
// ---------------------------------------------------------------------------
//
// A cloud Dragnet crawl's pages aggregate under a synthetic per-crawl workflow that lives on the
// fleet — its `data_workflow_id` has no row in this local db. When a data read names an id that is
// NOT a local workflow AND a cloud account is linked, it must be that cloud dataset, so we forward
// the read to `/api/workflows/{id}/data*` and hand the cloud's own response straight back. Cloud
// dataset ids come from a large shared server sequence and never collide with the small local id
// space, so "absent locally + linked ⇒ cloud" is unambiguous in practice. A local workflow always
// wins the check, so local recordings are untouched; unlinked/OSS builds always serve local (and a
// genuinely unknown id 404s locally, exactly as before).

/// Forward a JSON data read (table / facets / runs / record-history) to the cloud when `id` names
/// no local workflow but a cloud account is linked; `Ok(None)` means "serve local". `sub` is the
/// path suffix after `/data` (`""`, `/facets`, `/runs`, `/records/{uid}/history`).
#[cfg(feature = "cloud")]
async fn try_forward_cloud_data(
    st: &AppState,
    id: i64,
    sub: &str,
    raw_query: Option<&str>,
) -> LocalResult<Option<Response>> {
    if workflows::get_by_id(&st.db, id).await?.is_some() {
        return Ok(None); // a real local workflow — never forward.
    }
    if !crate::local::cloud::crawl::is_linked(&st.db).await {
        return Ok(None); // unlinked / OSS — let the local path 404 naturally.
    }
    let value = crate::local::cloud::workflow_data::get(&st.db, id, sub, raw_query).await?;
    Ok(Some(Json(value).into_response()))
}

#[cfg(not(feature = "cloud"))]
async fn try_forward_cloud_data(
    _st: &AppState,
    _id: i64,
    _sub: &str,
    _raw_query: Option<&str>,
) -> LocalResult<Option<Response>> {
    Ok(None)
}

/// Export variant of [`try_forward_cloud_data`]: streams the cloud CSV/JSON bytes back through the
/// daemon with the cloud's own attachment headers preserved.
#[cfg(feature = "cloud")]
async fn try_forward_cloud_export(
    st: &AppState,
    id: i64,
    raw_query: Option<&str>,
) -> LocalResult<Option<Response>> {
    if workflows::get_by_id(&st.db, id).await?.is_some() {
        return Ok(None);
    }
    if !crate::local::cloud::crawl::is_linked(&st.db).await {
        return Ok(None);
    }
    let (bytes, ctype, cdisp) =
        crate::local::cloud::workflow_data::export(&st.db, id, raw_query).await?;
    // These headers came off the WIRE. The daemon serves from loopback with NO global security-header
    // middleware (see `render_table`, which sets these for the local renderer), so relaying an
    // upstream `Content-Type` verbatim let a compromised/mis-deployed cloud response decide how the
    // browser interprets bytes the daemon serves from its own origin — `text/html` here is a stored
    // XSS with the daemon's loopback origin, and the bytes themselves are scraped third-party content.
    // Pin the type to the two shapes an export can legitimately be, and frame the same nosniff + CSP
    // the local renderer does.
    let ct = export_content_type(ctype.as_deref());
    let cd = sanitize_content_disposition(cdisp.as_deref());
    Ok(Some((
        [
            (header::CONTENT_TYPE, ct.to_string()),
            (header::CONTENT_DISPOSITION, cd),
            (header::X_CONTENT_TYPE_OPTIONS, "nosniff".to_string()),
            (header::CONTENT_SECURITY_POLICY, EXPORT_CSP.to_string()),
        ],
        bytes,
    )
        .into_response()))
}

/// CSP for bytes the daemon serves that originated OUTSIDE it. `default-src 'none'` means the document
/// can load and execute nothing at all, whatever the content turns out to be. Mirrors `render_table`.
#[cfg(feature = "cloud")]
const EXPORT_CSP: &str =
    "default-src 'none'; base-uri 'none'; form-action 'none'; sandbox; frame-ancestors 'none'";

/// Map an upstream export `Content-Type` onto the exact set an export can be.
///
/// An ALLOWLIST, deliberately: anything unrecognised becomes `application/octet-stream` (download it,
/// never render it) rather than being passed through. Only the base type is inspected so upstream
/// `charset`/boundary parameters cannot smuggle anything in.
#[cfg(feature = "cloud")]
fn export_content_type(upstream: Option<&str>) -> &'static str {
    let base = upstream
        .unwrap_or("")
        .split(';')
        .next()
        .unwrap_or("")
        .trim()
        .to_ascii_lowercase();
    match base.as_str() {
        "text/csv" => "text/csv; charset=utf-8",
        "application/json" => "application/json; charset=utf-8",
        "application/x-ndjson" | "application/jsonl" => "application/x-ndjson; charset=utf-8",
        "text/plain" => "text/plain; charset=utf-8",
        // Includes the `None` case: the cloud export handler always frames a type, so an absent one
        // means something unusual happened — treat it as opaque.
        _ => "application/octet-stream",
    }
}

/// Sanitize a relayed `Content-Disposition`: strip control characters (header splitting) and force the
/// `attachment` disposition so the payload is never rendered inline.
#[cfg(feature = "cloud")]
fn sanitize_content_disposition(upstream: Option<&str>) -> String {
    const FALLBACK: &str = "attachment; filename=\"export\"";
    let Some(raw) = upstream else {
        return FALLBACK.to_string();
    };
    let cleaned: String = raw.chars().filter(|c| !c.is_control()).collect();
    let cleaned = cleaned.trim();
    if cleaned.is_empty() {
        return FALLBACK.to_string();
    }
    // `inline` (or any other disposition) would render in the browser; we only ever hand back a file.
    let mut parts = cleaned.splitn(2, ';');
    let disposition = parts.next().unwrap_or("").trim();
    let params = parts.next().map(str::trim).filter(|s| !s.is_empty());
    if disposition.eq_ignore_ascii_case("attachment") {
        return cleaned.to_string();
    }
    match params {
        Some(p) => format!("attachment; {p}"), // keep the filename, drop the disposition
        None => FALLBACK.to_string(),
    }
}

#[cfg(not(feature = "cloud"))]
async fn try_forward_cloud_export(
    _st: &AppState,
    _id: i64,
    _raw_query: Option<&str>,
) -> LocalResult<Option<Response>> {
    Ok(None)
}

/// Percent-encode a single path segment (RFC 3986 unreserved chars pass through). Used to rebuild
/// the cloud `/records/{uid}/history` path when forwarding — a record uid can carry `/`, `?`, `#`.
fn encode_path_segment(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char)
            }
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

// ---------------------------------------------------------------------------
// Bounded fastpath — serve the hot data reads without parsing the whole window.
//
// Every handler above used to load and parse the FULL payload of up to
// DATA_SCAN_CAP runs per request; for a content dataset (crawled pages of
// markdown) that is megabytes of JSON parsed per request, several times per
// Data-page open. The fastpath mirrors the cloud/coordinator
// services/dataset_fastpath.py: a stub pass fetches only (id, recency,
// payload size), a tiny per-run digest {row count, column order, flags} is
// computed ONCE with the real data_query coercion and cached, and only the
// runs covering the requested page load their payloads. Any fastpath error
// falls back to the legacy full scan — it is an optimization, never the only
// road to the data.
// ---------------------------------------------------------------------------

/// The picker's last_delta teaser needs the full window to compute exactly, so
/// it is size-gated (rows via the spec's PICKER_DELTA_MAX_ROWS, bytes here);
/// past the gates it is null — the API contract's "unknown".
const PICKER_DELTA_MAX_BYTES: i64 = 3_000_000;
/// view=all facets budget: past it the facets describe only the NEWEST rows
/// (`sampled: true`, `row_count` = rows faceted, `total_rows` exact).
const FACET_SAMPLE_ROWS: usize = 2000;
const FACET_SAMPLE_BYTES: i64 = 12_000_000;
/// Digest-miss payload loads are batched by run count AND bytes so a cold
/// cache over a heavy window streams through memory instead of spiking it.
const DIGEST_BATCH_RUNS: usize = 64;
const DIGEST_BATCH_BYTES: i64 = 16_000_000;
/// Digest entries are a few dozen bytes; the coarse full clear past the cap is
/// a runaway backstop, not an eviction policy — entries recompute on demand.
const DIGEST_CACHE_MAX: usize = 200_000;

/// (run id, payload size, declared-fields fingerprint, per-workflow delete
/// epoch). Size self-invalidates edits; the epoch makes row deletes
/// deterministic rather than probabilistic; the fingerprint misses when the
/// declared output schema changes (the digest projects records to it).
type DigestKey = (i64, i64, u64, u64);

fn digest_cache() -> &'static Mutex<HashMap<DigestKey, data_query::RunDigest>> {
    static CACHE: OnceLock<Mutex<HashMap<DigestKey, data_query::RunDigest>>> = OnceLock::new();
    CACHE.get_or_init(|| Mutex::new(HashMap::new()))
}

fn data_epochs() -> &'static Mutex<HashMap<i64, u64>> {
    static EPOCHS: OnceLock<Mutex<HashMap<i64, u64>>> = OnceLock::new();
    EPOCHS.get_or_init(|| Mutex::new(HashMap::new()))
}

fn data_epoch_for(workflow_id: i64) -> u64 {
    data_epochs()
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .get(&workflow_id)
        .copied()
        .unwrap_or(0)
}

/// Call after mutating stored extracted data (row deletes / clear-all) so
/// cached digests for the workflow stop matching.
fn bump_data_epoch(workflow_id: i64) {
    let mut m = data_epochs()
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    *m.entry(workflow_id).or_insert(0) += 1;
}

fn declared_fingerprint(declared: &[String]) -> u64 {
    use std::hash::{Hash, Hasher};
    let mut h = std::collections::hash_map::DefaultHasher::new();
    declared.hash(&mut h);
    h.finish()
}

/// Digests for every stub — cache-first, misses loaded in bounded batches and
/// computed with `data_query::run_digest` (the real coercion). Keyed back by
/// run id; a run deleted since the stub pass is simply absent (0 rows).
async fn window_digests(
    db: &sqlx::sqlite::SqlitePool,
    stubs: &[runs::DataStub],
    declared: &[String],
    epoch: u64,
) -> LocalResult<HashMap<i64, data_query::RunDigest>> {
    let fp = declared_fingerprint(declared);
    let mut out: HashMap<i64, data_query::RunDigest> = HashMap::new();
    let mut missing: Vec<&runs::DataStub> = Vec::new();
    {
        let cache = digest_cache()
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        for s in stubs {
            match cache.get(&(s.id, s.size, fp, epoch)) {
                Some(d) => {
                    out.insert(s.id, d.clone());
                }
                None => missing.push(s),
            }
        }
    }
    let mut batches: Vec<Vec<i64>> = Vec::new();
    let mut cur: Vec<i64> = Vec::new();
    let mut cur_bytes: i64 = 0;
    let mut size_by_id: HashMap<i64, i64> = HashMap::new();
    for s in &missing {
        size_by_id.insert(s.id, s.size);
        if !cur.is_empty() && (cur.len() >= DIGEST_BATCH_RUNS || cur_bytes + s.size > DIGEST_BATCH_BYTES)
        {
            batches.push(std::mem::take(&mut cur));
            cur_bytes = 0;
        }
        cur.push(s.id);
        cur_bytes += s.size;
    }
    if !cur.is_empty() {
        batches.push(cur);
    }
    for ids in batches {
        let loaded = runs::get_by_ids(db, &ids).await?;
        let mut cache = digest_cache()
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if cache.len() > DIGEST_CACHE_MAX {
            cache.clear();
        }
        for run in loaded {
            let size = size_by_id.get(&run.id).copied().unwrap_or(0);
            let input = to_run_input(run);
            let digest = data_query::run_digest(&input, declared);
            cache.insert((input.run_id, size, fp, epoch), digest.clone());
            out.insert(input.run_id, digest);
        }
    }
    Ok(out)
}

/// Columns exactly as the flatten derives them: declared fields verbatim when
/// present, else first-seen key order across the window in SCAN order.
fn merged_columns(
    stubs: &[runs::DataStub],
    digests: &HashMap<i64, data_query::RunDigest>,
    declared: &[String],
) -> Vec<String> {
    let declared_cols = data_query::declared_columns(declared);
    if !declared_cols.is_empty() {
        return declared_cols;
    }
    let mut seen: Vec<String> = Vec::new();
    for s in stubs {
        if let Some(d) = digests.get(&s.id) {
            for c in &d.cols {
                if !seen.contains(c) {
                    seen.push(c.clone());
                }
            }
        }
    }
    seen
}

/// Preview-size the serialized table rows: any top-level STRING field longer
/// than `chars` is cut to `chars` characters and the row gains a
/// `_truncated: [field, ...]` sibling so the UI hydrates the full record on
/// demand. Objects/arrays pass through whole (client-side collection pivots
/// and file stamps need them) — mirrors the python engines byte-for-byte.
fn truncate_preview_rows(rows: &mut [Value], chars: usize) {
    for row in rows.iter_mut() {
        let Some(fields) = row.get_mut("fields").and_then(Value::as_object_mut) else {
            continue;
        };
        let mut cut: Vec<String> = Vec::new();
        for (k, v) in fields.iter_mut() {
            if let Value::String(s) = v {
                if s.chars().count() > chars {
                    *s = s.chars().take(chars).collect();
                    cut.push(k.clone());
                }
            }
        }
        if !cut.is_empty() {
            row["_truncated"] = json!(cut);
        }
    }
}

/// True when a table request is the DEFAULT page shape the fastpath can serve
/// exactly: no search, no filters, no inputs, newest-first run_at order.
fn fast_table_shape(params: &TableParams) -> bool {
    params.q.as_deref().map(|s| s.trim().is_empty()).unwrap_or(true)
        && parse_col_filters(&params.filter).is_empty()
        && parse_structured_filters(params.filters.as_deref()).is_empty()
        && !params.include_inputs
        && params.sort_by.as_deref().map(|s| s == "run_at").unwrap_or(true)
        && !params
            .sort_dir
            .as_deref()
            .unwrap_or("desc")
            .eq_ignore_ascii_case("asc")
}

/// The bounded view=all page. Reproduces `build_table`'s row order exactly:
/// build_table stable-sorts ALL rows ascending by run_at then reverses, so the
/// served order is (run_at DESC, scan-position DESC) with each run's records
/// slot-DESC — emulated here as reversed stable-ascending run blocks with each
/// block's rows reversed.
async fn fast_workflow_data_all(
    db: &sqlx::sqlite::SqlitePool,
    wf: &workflows::Workflow,
    declared: &[String],
    params: &TableParams,
) -> LocalResult<Value> {
    let (stubs, raw_n) = runs::data_window_stubs(db, wf.id, DATA_SCAN_CAP).await?;
    let truncated = raw_n >= DATA_SCAN_CAP;
    let epoch = data_epoch_for(wf.id);
    let digests = window_digests(db, &stubs, declared, epoch).await?;
    let scanned = stubs
        .iter()
        .filter(|s| digests.get(&s.id).map(|d| d.nonnull).unwrap_or(false))
        .count();
    let n_of = |id: i64| digests.get(&id).map(|d| d.n).unwrap_or(0);
    let total: usize = stubs.iter().map(|s| n_of(s.id)).sum();
    let columns = merged_columns(&stubs, &digests, declared);

    let query = params.to_query(true);
    let limit = query.limit.unwrap_or(DEFAULT_PAGE);
    let offset = query.offset;

    let mut order: Vec<&runs::DataStub> = stubs.iter().collect();
    order.sort_by(|a, b| {
        a.at.as_deref().unwrap_or("").cmp(b.at.as_deref().unwrap_or(""))
    });
    order.reverse();

    let mut cover: Vec<i64> = Vec::new();
    let mut before: usize = 0;
    let mut pos: usize = 0;
    for s in &order {
        let n = n_of(s.id);
        if n == 0 {
            continue;
        }
        if pos + n > offset && pos < offset + limit {
            if cover.is_empty() {
                before = pos;
            }
            cover.push(s.id);
        }
        pos += n;
        if pos >= offset + limit {
            break;
        }
    }

    let mut page_rows: Vec<data_query::Row> = Vec::new();
    if !cover.is_empty() {
        let loaded = runs::get_by_ids(db, &cover).await?;
        let by_id: HashMap<i64, RunInput> =
            loaded.into_iter().map(|r| (r.id, to_run_input(r))).collect();
        for id in &cover {
            if let Some(input) = by_id.get(id) {
                let (_cols, mut rows) =
                    data_query::flatten(std::slice::from_ref(input), declared, false);
                rows.reverse();
                page_rows.extend(rows);
            }
        }
        let skip = offset.saturating_sub(before);
        page_rows = page_rows.into_iter().skip(skip).take(limit).collect();
    }

    let mut rows_json = data_query::rows_to_table_json(&page_rows, &columns);
    if let Some(chars) = params.preview_chars {
        truncate_preview_rows(&mut rows_json, chars);
    }
    Ok(json!({
        "workflow_id": wf.id,
        "workflow_name": wf.name,
        "columns": columns,
        "declared": !data_query::declared_columns(declared).is_empty(),
        "rows": rows_json,
        "total": total,
        "scanned_runs": scanned,
        "truncated": truncated,
        "limit": query.limit,
        "offset": query.offset,
    }))
}

// ---------------------------------------------------------------------------
// Handlers.
// ---------------------------------------------------------------------------

/// `GET /v1/data` — the workflow picker for the Data explorer: every workflow that has produced
/// extracted data in a SUCCESSFUL run, each with a (successful) run count and a last-data timestamp.
/// Sorted by most recent data first. Workflows whose only data came from failed runs are omitted, so
/// the picker doesn't list empty/noise entries.
///
/// Active state is NOT a filter here: the Data explorer surfaces data that EXISTS, exactly like the
/// per-workflow Data tab (`/v1/workflows/:id/data`, which loads by id regardless of `is_active`). A
/// legacy workflow parked inactive by the old soft-delete still owns real extracted data — hiding it
/// from the picker (but not the direct tab) is what made "my data disappeared" happen. We list
/// inactive-but-data-bearing workflows too; a hard-deleted workflow is gone (its runs cascade), so it
/// can never appear.
async fn list_data_workflows(State(st): State<AppState>) -> LocalResult<Json<Value>> {
    let wfs = workflows::list(&st.db, false, 1000).await?;
    let mut out: Vec<Value> = Vec::new();
    for wf in wfs {
        // Bounded picker line: run_count / last_data_at from cached per-run
        // digests (real record_count semantics — zero-row workflows still
        // hide), payloads loaded only for datasets small enough to compute the
        // exact last_delta teaser. This is what keeps opening the Data page
        // from parsing every workflow's whole corpus.
        if let Some(line) = fast_picker_line(&st.db, &wf).await? {
            out.push(line);
        }
    }
    // Linked desktop: a Dragnet crawl runs on the fleet, so its collected dataset lives on cloud —
    // merge those in (tagged `origin:"cloud"`) so the Outputs picker lists them alongside local
    // data. The read routes forward by the same absent-locally-⇒-cloud rule. Best-effort: a cloud
    // hiccup must never blank the local picker.
    #[cfg(feature = "cloud")]
    if crate::local::cloud::crawl::is_linked(&st.db).await {
        if let Ok(listing) = crate::local::cloud::crawl::list(&st.db, 100).await {
            let crawls = listing
                .get("crawls")
                .and_then(|v| v.as_array())
                .cloned()
                .or_else(|| listing.as_array().cloned())
                .unwrap_or_default();
            for c in crawls {
                // The synthetic dataset workflow (null while a crawl is still queued/mapping).
                let dwid = c
                    .get("data_workflow_id")
                    .and_then(|v| v.as_i64())
                    .or_else(|| c.get("workflow_id").and_then(|v| v.as_i64()));
                let Some(dwid) = dwid else { continue };
                // Only surface crawls that actually collected something (else the picker row opens
                // to an empty table).
                let records = c.get("records_total").and_then(|v| v.as_i64()).unwrap_or(0);
                let done = c.get("pages_done").and_then(|v| v.as_i64()).unwrap_or(0);
                if records <= 0 && done <= 0 {
                    continue;
                }
                let name = c.get("name").and_then(|v| v.as_str()).unwrap_or("Crawl").to_string();
                let last = c
                    .get("completed_at")
                    .and_then(|v| v.as_str())
                    .or_else(|| c.get("created_at").and_then(|v| v.as_str()))
                    .map(|s| s.to_string());
                out.push(json!({
                    "workflow_id": dwid,
                    "workflow_name": name,
                    // A forwarded Dragnet crawl dataset — lock the grid to the
                    // aggregated (all-shards) view.
                    "workflow_type": "crawl",
                    "run_count": 1,
                    "last_data_at": last,
                    "last_delta": Value::Null,
                    "origin": "cloud",
                }));
            }
        }
    }
    out.sort_by(|a, b| {
        let av = a.get("last_data_at").and_then(|v| v.as_str()).unwrap_or("");
        let bv = b.get("last_data_at").and_then(|v| v.as_str()).unwrap_or("");
        bv.cmp(av)
    });
    Ok(Json(json!({ "workflows": out })))
}

/// One picker line from stubs + cached digests (payloads only for the
/// size-gated last_delta). None hides the workflow: no window run flattens to
/// a row — the exact legacy rule, decided from real per-run record counts.
async fn fast_picker_line(
    db: &sqlx::sqlite::SqlitePool,
    wf: &workflows::Workflow,
) -> LocalResult<Option<Value>> {
    let declared = declared_output_fields(wf);
    let (stubs, _raw_n) = runs::data_window_stubs(db, wf.id, DATA_SCAN_CAP).await?;
    if stubs.is_empty() {
        return Ok(None);
    }
    let epoch = data_epoch_for(wf.id);
    let digests = window_digests(db, &stubs, &declared, epoch).await?;
    let n_of = |id: i64| digests.get(&id).map(|d| d.n).unwrap_or(0);
    let total_rows: usize = stubs.iter().map(|s| n_of(s.id)).sum();
    if total_rows == 0 {
        return Ok(None);
    }
    let contributing: Vec<&runs::DataStub> =
        stubs.iter().filter(|s| n_of(s.id) > 0).collect();
    let run_count = contributing.len();
    let last_data_at: Option<String> = contributing.iter().filter_map(|s| s.at.clone()).max();
    let chain_len = stubs
        .iter()
        .filter(|s| digests.get(&s.id).map(|d| d.data_bearing).unwrap_or(false))
        .count();
    let total_bytes: i64 = stubs.iter().map(|s| s.size).sum();
    // last_delta stays exact (the legacy computation over the full window) but
    // only for datasets small enough to load; past the row/byte gates it is
    // null — the API contract's "unknown".
    let last_delta = if chain_len < 2
        || total_rows > PICKER_DELTA_MAX_ROWS
        || total_bytes > PICKER_DELTA_MAX_BYTES
    {
        Value::Null
    } else {
        let (mut runs_with_data, _t) = scan_workflow_data_runs_pool(db, wf.id).await?;
        sort_runs_ascending(&mut runs_with_data);
        let flat = data_query::flatten_runs(&runs_with_data, &declared);
        picker_delta(&flat, &declared)
    };
    Ok(Some(json!({
        "workflow_id": wf.id,
        "workflow_name": wf.name,
        // Lets the Data explorer lock a crawl dataset to the aggregated view
        // (its shards are one dataset, not temporal snapshots).
        "workflow_type": wf.workflow_type,
        "run_count": run_count,
        "last_data_at": last_data_at,
        "last_delta": last_delta,
        "origin": "local",
    })))
}

/// last_delta = the newest two chain snapshots compared under the sampled
/// identity (spec 1.5.7). `flat` must be the full window, ascending.
fn picker_delta(flat: &[data_query::FlatRun], declared: &[String]) -> Value {
    let chain: Vec<&data_query::FlatRun> = flat.iter().filter(|r| r.data_bearing).collect();
    if chain.len() < 2 {
        return Value::Null;
    }
    let columns = data_query::canonical_columns(flat, declared);
    let identity = pick_identity(flat, &columns, None);
    let uids_of = |run: &data_query::FlatRun| -> BTreeMap<String, Map<String, Value>> {
        data_query::assign_uids(&run.records, identity.mode, &identity.fields)
            .into_iter()
            .map(|(uid, _idx, rec)| (uid, rec))
            .collect()
    };
    let prev = uids_of(chain[chain.len() - 2]);
    let cur = uids_of(chain[chain.len() - 1]);
    let mut new = 0usize;
    let mut changed = 0usize;
    for (uid, rec) in &cur {
        match prev.get(uid) {
            None => new += 1,
            Some(old) => {
                if !data_query::diff_fields(old, rec).0.is_empty() {
                    changed += 1;
                }
            }
        }
    }
    let removed = prev.keys().filter(|u| !cur.contains_key(*u)).count();
    json!({ "new": new, "changed": changed, "removed": removed })
}

// ---------------------------------------------------------------------------
// Datasets — the first-class, consumer-facing framing of a data source's
// accumulated extracted data. A dataset IS a data-bearing workflow (or a
// crawl's synthetic workflow); its id equals the workflow id, so every handler
// reuses the exact scan/flatten/redaction (and cloud-forward) above. Lineage
// lenses stay on the richer /workflows/:id/data surface; a dataset's records
// are the flat grid — one row per extracted record.
// ---------------------------------------------------------------------------

/// A dataset backed by a whole-site crawl reports `crawl`; anything else `workflow`.
fn dataset_source_type(wf: &workflows::Workflow) -> &'static str {
    if wf.workflow_type == "crawl" {
        "crawl"
    } else {
        "workflow"
    }
}

// ── Output formats (`?format=`) ───────────────────────────────────────────────
//
// Every dataset read serves `json` (default — the documented envelope), `csv`,
// `markdown` or `html`. markdown/html are CONTENT-AWARE (a crawl's pages render
// as documents, structured data as a table) — see `data_query::to_markdown` /
// `to_html`. Mirrors the cloud `/api/v1/datasets/*` surface.

/// The output formats every dataset read accepts.
const DATASET_FORMATS: [&str; 4] = ["json", "csv", "markdown", "html"];

/// Validate + normalize `?format=`. An unknown value is a 400 rather than a
/// silent JSON fallback, so a typo surfaces instead of being mistaken for data.
fn norm_format(fmt: Option<&str>) -> LocalResult<String> {
    let f = fmt.unwrap_or("json").trim().to_ascii_lowercase();
    if !DATASET_FORMATS.contains(&f.as_str()) {
        return Err(LocalError::BadRequest(format!(
            "Unsupported format '{}'. Use one of: {}",
            f,
            DATASET_FORMATS.join(", ")
        )));
    }
    Ok(f)
}

/// Serialize a table in `fmt` as a ready `Response`, or `None` for `json` (the
/// caller owns its own envelope). When `filename` is set the response is framed
/// as a download (the export routes).
///
/// SECURITY: a markdown/html body is SCRAPED THIRD-PARTY content. The renderers
/// already escape raw HTML and allowlist link schemes; unlike the cloud (which
/// has a global security-header middleware) the daemon has none, so the transport
/// defenses are set here: never MIME-sniff, and a CSP that cannot execute script.
fn render_table(
    fmt: &str,
    columns: &[String],
    rows: &[data_query::Row],
    title: &str,
    filename: Option<&str>,
) -> Option<Response> {
    let (body, ctype, ext) = match fmt {
        "csv" => (
            data_query::to_csv(columns, rows),
            "text/csv; charset=utf-8",
            "csv",
        ),
        "markdown" => (
            data_query::to_markdown(columns, rows, Some(title)),
            "text/markdown; charset=utf-8",
            "md",
        ),
        "html" => (
            data_query::to_html(columns, rows, Some(title)),
            "text/html; charset=utf-8",
            "html",
        ),
        _ => return None, // json — the caller's envelope
    };
    let mut headers = axum::http::HeaderMap::new();
    headers.insert(header::CONTENT_TYPE, axum::http::HeaderValue::from_static(ctype));
    headers.insert(
        header::X_CONTENT_TYPE_OPTIONS,
        axum::http::HeaderValue::from_static("nosniff"),
    );
    headers.insert(
        header::CONTENT_SECURITY_POLICY,
        axum::http::HeaderValue::from_static(
            "default-src 'none'; style-src 'unsafe-inline'; img-src https: data:; \
             base-uri 'none'; form-action 'none'",
        ),
    );
    if let Some(f) = filename {
        if let Ok(v) = axum::http::HeaderValue::from_str(&format!(
            "attachment; filename=\"{f}.{ext}\""
        )) {
            headers.insert(header::CONTENT_DISPOSITION, v);
        }
    }
    Some((headers, body).into_response())
}

/// `GET /v1/datasets` — every data source that has accumulated extracted data, framed as a
/// dataset: `{id, name, source_type, run_count, last_updated}`. Reuses the Data-explorer picker
/// (local data-bearing workflows + forwarded cloud crawl datasets), re-keyed to the dataset shape.
async fn list_datasets(state: State<AppState>) -> LocalResult<Json<Value>> {
    let picker = list_data_workflows(state).await?;
    let workflows = picker
        .0
        .get("workflows")
        .and_then(|v| v.as_array())
        .cloned()
        .unwrap_or_default();
    let datasets: Vec<Value> = workflows
        .iter()
        .map(|w| {
            let source_type = if w.get("workflow_type").and_then(|v| v.as_str()) == Some("crawl") {
                "crawl"
            } else {
                "workflow"
            };
            json!({
                "id": w.get("workflow_id"),
                "name": w.get("workflow_name"),
                "source_type": source_type,
                "run_count": w.get("run_count"),
                "last_updated": w.get("last_data_at"),
                "origin": w.get("origin"),
            })
        })
        .collect();
    Ok(Json(json!({ "datasets": datasets })))
}

/// Concierge-facing dataset catalogue: the same `{datasets:[{id,name,source_type,run_count,
/// last_updated,origin}]}` the `/v1/datasets` route returns (local data-bearing workflows + merged
/// cloud crawl datasets on a linked desktop). `pub(crate)` so Scribe can browse existing datasets
/// before crawling.
pub(crate) async fn concierge_list_datasets(st: &AppState) -> LocalResult<Value> {
    let Json(v) = list_datasets(State(st.clone())).await?;
    Ok(v)
}

/// `GET /v1/datasets/:id` — a dataset's metadata + inferred schema (columns, per-column facets,
/// row/run counts). Forwards to the cloud dataset when the id is a linked crawl dataset (the
/// forwarded body is the cloud facets shape).
async fn dataset_meta(
    State(st): State<AppState>,
    Path(id): Path<i64>,
    RawQuery(raw_query): RawQuery,
) -> LocalResult<Response> {
    if let Some(resp) = try_forward_cloud_data(&st, id, "/facets", raw_query.as_deref()).await? {
        return Ok(resp);
    }
    let wf = load_workflow(&st, id).await?;
    let declared = declared_output_fields(&wf);
    let (runs_with_data, truncated) = scan_workflow_data_runs(&st, id).await?;
    let scanned = runs_with_data.len();
    let (columns, rows) = data_query::flatten(&runs_with_data, &declared, true);
    let facets = data_query::compute_facets(&columns, &rows);
    Ok(Json(json!({
        "id": wf.id,
        "name": wf.name,
        "source_type": dataset_source_type(&wf),
        "columns": columns,
        "facets": facets,
        "row_count": rows.len(),
        "run_count": scanned,
        "truncated": truncated,
    }))
    .into_response())
}

/// Re-key a forwarded cloud workflow-data table into the dataset records shape so a local read
/// and a forwarded (crawl) read look identical to the SDK. A forwarded dataset is always a crawl.
#[cfg(feature = "cloud")]
fn cloud_table_to_dataset(v: Value) -> Value {
    json!({
        "dataset": {
            "id": v.get("workflow_id").cloned().unwrap_or(Value::Null),
            "name": v.get("workflow_name").cloned().unwrap_or(Value::Null),
            "source_type": "crawl",
        },
        "columns": v.get("columns").cloned().unwrap_or_else(|| json!([])),
        "declared": v.get("declared").cloned().unwrap_or(Value::Bool(false)),
        "records": v.get("rows").cloned().unwrap_or_else(|| json!([])),
        "total": v.get("total").cloned().unwrap_or(Value::Null),
        "scanned_runs": v.get("scanned_runs").cloned().unwrap_or(Value::Null),
        "truncated": v.get("truncated").cloned().unwrap_or(Value::Bool(false)),
        "limit": v.get("limit").cloned().unwrap_or(Value::Null),
        "offset": v.get("offset").cloned().unwrap_or(Value::Null),
    })
}

/// `GET /v1/datasets/:id/records` — page through a dataset's records as one sortable/searchable
/// table (the flat grid). Same query params as the workflow-data table (q / filter / filters /
/// sort_by / sort_dir / limit / offset / include_inputs). Forwards to the cloud dataset when linked.
async fn dataset_records(
    State(st): State<AppState>,
    Path(id): Path<i64>,
    RawQuery(raw_query): RawQuery,
    Query(params): Query<TableParams>,
) -> LocalResult<Response> {
    // `raw_query` is only consumed by the cloud-forwarding path below.
    #[cfg(not(feature = "cloud"))]
    let _ = &raw_query;
    let fmt = norm_format(params.format.as_deref())?;
    // Cloud crawl dataset (absent locally + linked): forward to the fleet's workflow-data table
    // and re-key its response so local and cloud reads look identical.
    #[cfg(feature = "cloud")]
    if workflows::get_by_id(&st.db, id).await?.is_none()
        && crate::local::cloud::crawl::is_linked(&st.db).await
    {
        let value =
            crate::local::cloud::workflow_data::get(&st.db, id, "", raw_query.as_deref()).await?;
        // The cloud data route has no `format` of its own — render the forwarded
        // table here so a cloud dataset formats exactly like a local one.
        if fmt != "json" {
            let (columns, rows) = rows_from_payload(&value, "rows");
            let title = value.get("workflow_name").and_then(|v| v.as_str()).unwrap_or("Dataset");
            if let Some(resp) = render_table(&fmt, &columns, &rows, title, None) {
                return Ok(resp);
            }
        }
        return Ok(Json(cloud_table_to_dataset(value)).into_response());
    }
    let wf = load_workflow(&st, id).await?;
    let declared = declared_output_fields(&wf);
    let (runs_with_data, truncated) = scan_workflow_data_runs(&st, id).await?;
    let scanned = runs_with_data.len();
    let query = params.to_query(true);
    let table = data_query::build_table(&runs_with_data, &declared, &query, params.include_inputs);
    // A non-json format serves this same page rendered; `/export` serves the whole set.
    let ds_title = if wf.name.is_empty() { format!("Dataset {}", wf.id) } else { wf.name.clone() };
    if let Some(resp) = render_table(&fmt, &table.columns, &table.rows, &ds_title, None) {
        return Ok(resp);
    }
    let records = data_query::rows_to_table_json(&table.rows, &table.columns);
    Ok(Json(json!({
        "dataset": { "id": wf.id, "name": wf.name, "source_type": dataset_source_type(&wf) },
        "columns": table.columns,
        "declared": table.declared,
        "records": records,
        "total": table.total,
        "scanned_runs": scanned,
        "truncated": truncated,
        "limit": query.limit,
        "offset": query.offset,
    }))
    .into_response())
}

/// `GET /v1/datasets/:id/export` — download a dataset's full records as CSV/JSON. The exported
/// bytes are identical to the workflow-data export, so this delegates straight to it.
async fn export_dataset(
    state: State<AppState>,
    path: Path<i64>,
    raw: RawQuery,
    query: Query<TableParams>,
) -> LocalResult<Response> {
    export_workflow_data(state, path, raw, query).await
}

// ---------------------------------------------------------------------------
// Datasets full-text search (SQLite FTS5, migration 0022). The FTS index finds
// matching runs fast + uncapped; we then flatten only those runs and keep the
// records that contain every term — newest-first, with a highlight snippet.
// Extracted data covers BOTH JSON fields and markdown (a markdown page is a
// record with a `markdown` field), so this searches both. Mirrors the cloud
// /api/v1/datasets/search[/:id] semantics.
// ---------------------------------------------------------------------------

/// How many recent matching runs we materialize per search (the FTS index finds every match
/// uncapped; this bounds the flatten). `truncated` flags when we hit it.
const SEARCH_CANDIDATE_CAP: i64 = 500;
const SEARCH_DEFAULT_PAGE: usize = 50;
const SEARCH_MAX_PAGE: usize = 200;

#[derive(Debug, Default, Deserialize)]
struct SearchParams {
    #[serde(default)]
    q: Option<String>,
    #[serde(default)]
    limit: Option<usize>,
    #[serde(default)]
    offset: Option<usize>,
    /// `json` (default) | `csv` | `markdown` | `html` — renders the matches
    /// instead of the JSON envelope. The per-result dataset tag + highlight
    /// snippet exist only in the JSON shape.
    #[serde(default)]
    format: Option<String>,
}

/// Re-shape a payload's record array into the `(columns, rows)` the renderers
/// consume, so `?format=` works the same on a search payload (`key = "results"`)
/// and on a forwarded cloud table (`key = "rows"` — the cloud's data route has no
/// `format` of its own, so the daemon renders the forwarded table itself).
/// An explicit `columns` list wins; otherwise columns are the union of field keys
/// in first-seen order.
/// `pub(crate)` so the dataset MCP tools render `format=markdown|csv` through the
/// exact same path the REST `?format=` serves.
pub(crate) fn rows_from_payload(payload: &Value, key: &str) -> (Vec<String>, Vec<data_query::Row>) {
    let mut columns: Vec<String> = payload
        .get("columns")
        .and_then(|v| v.as_array())
        .map(|a| a.iter().filter_map(|c| c.as_str().map(String::from)).collect())
        .unwrap_or_default();
    let mut rows: Vec<data_query::Row> = Vec::new();
    for r in payload.get(key).and_then(|v| v.as_array()).cloned().unwrap_or_default() {
        let fields = r.get("fields").and_then(|v| v.as_object()).cloned().unwrap_or_default();
        for k in fields.keys() {
            if !columns.iter().any(|c| c == k) {
                columns.push(k.clone());
            }
        }
        rows.push(data_query::Row {
            run_id: r.get("run_id").and_then(|v| v.as_i64()).unwrap_or_default(),
            run_at: r.get("run_at").and_then(|v| v.as_str()).map(|s| s.to_string()),
            status: Some(
                r.get("status").and_then(|v| v.as_str()).unwrap_or("success").to_string(),
            ),
            success: Some(true),
            duration_ms: None,
            record_index: r.get("record_index").and_then(|v| v.as_u64()).unwrap_or(0) as usize,
            fields,
            inputs: Map::new(),
        });
    }
    (columns, rows)
}

/// `GET /v1/datasets/search` — full-text search across every local dataset.
async fn search_datasets(
    State(st): State<AppState>,
    Query(p): Query<SearchParams>,
) -> LocalResult<Response> {
    let fmt = norm_format(p.format.as_deref())?;
    let limit = p.limit.unwrap_or(SEARCH_DEFAULT_PAGE);
    let offset = p.offset.unwrap_or(0);
    let q = p.q.as_deref().unwrap_or("");
    let payload = run_dataset_search(&st, None, q, limit, offset).await?;
    if fmt != "json" {
        let (columns, rows) = rows_from_payload(&payload, "results");
        if let Some(resp) = render_table(&fmt, &columns, &rows, &format!("Search: {q}"), None) {
            return Ok(resp);
        }
    }
    Ok(Json(payload).into_response())
}

/// `GET /v1/datasets/:id/search` — full-text search within one dataset. A cloud crawl dataset
/// (absent locally + linked) forwards to the fleet's data table filtered by `q`.
async fn search_dataset(
    State(st): State<AppState>,
    Path(id): Path<i64>,
    Query(p): Query<SearchParams>,
) -> LocalResult<Response> {
    let fmt = norm_format(p.format.as_deref())?;
    #[cfg(feature = "cloud")]
    if workflows::get_by_id(&st.db, id).await?.is_none()
        && crate::local::cloud::crawl::is_linked(&st.db).await
    {
        let q = p.q.as_deref().unwrap_or("").trim();
        let limit = p.limit.unwrap_or(SEARCH_DEFAULT_PAGE).clamp(1, SEARCH_MAX_PAGE);
        let raw = format!("q={}&limit={}", encode_path_segment(q), limit);
        let value = crate::local::cloud::workflow_data::get(&st.db, id, "", Some(&raw)).await?;
        // The cloud data route has no `format` of its own — render the forwarded
        // table here so a cloud dataset formats exactly like a local one.
        if fmt != "json" {
            let (columns, rows) = rows_from_payload(&value, "rows");
            let title = value.get("workflow_name").and_then(|v| v.as_str()).unwrap_or("Dataset");
            if let Some(resp) =
                render_table(&fmt, &columns, &rows, &format!("{title} — search: {q}"), None)
            {
                return Ok(resp);
            }
        }
        return Ok(Json(value).into_response());
    }
    let limit = p.limit.unwrap_or(SEARCH_DEFAULT_PAGE);
    let offset = p.offset.unwrap_or(0);
    let q = p.q.as_deref().unwrap_or("");
    let payload = run_dataset_search(&st, Some(id), q, limit, offset).await?;
    if fmt != "json" {
        let (columns, rows) = rows_from_payload(&payload, "results");
        if let Some(resp) = render_table(&fmt, &columns, &rows, &format!("Search: {q}"), None) {
            return Ok(resp);
        }
    }
    Ok(Json(payload).into_response())
}

/// Shared search: `workflow_id=Some` scopes to one dataset, `None` searches all local datasets.
/// `pub(crate)` so the MCP `writ_dataset_search` tool serves the same results as the REST route.
pub(crate) async fn run_dataset_search(
    st: &AppState,
    workflow_id: Option<i64>,
    q_in: &str,
    limit: usize,
    offset: usize,
) -> LocalResult<Value> {
    let q = q_in.trim().to_string();
    let terms = data_query::parse_search_terms(&q);
    let empty = json!({
        "query": q, "terms": terms, "results": [], "total": 0, "truncated": false, "scanned_runs": 0
    });
    if terms.is_empty() {
        return Ok(empty);
    }
    let match_query = data_query::fts5_match_query(&terms);
    let candidates = runs::search_fts(&st.db, &match_query, workflow_id, SEARCH_CANDIDATE_CAP).await?;
    let scanned = candidates.len();
    let truncated = scanned as i64 >= SEARCH_CANDIDATE_CAP;
    if candidates.is_empty() {
        return Ok(empty);
    }

    // Group matched runs by dataset; resolve names/types once.
    let mut by_wf: BTreeMap<i64, Vec<RunInput>> = BTreeMap::new();
    for run in candidates {
        let wid = run.workflow_id.unwrap_or_default();
        by_wf.entry(wid).or_default().push(to_run_input(run));
    }
    let ids: Vec<i64> = by_wf.keys().copied().collect();
    let meta: BTreeMap<i64, (String, String)> = workflows::names_and_types(&st.db, &ids)
        .await?
        .into_iter()
        .map(|(id, name, wtype, _)| {
            let st = if wtype == "crawl" { "crawl" } else { "workflow" };
            (id, (name, st.to_string()))
        })
        .collect();

    let mut results: Vec<Value> = Vec::new();
    for (wid, group) in &by_wf {
        let (name, source_type) = meta
            .get(wid)
            .cloned()
            .unwrap_or_else(|| (String::new(), "workflow".to_string()));
        // Empty declared: search doesn't need the declared-field projection (fields come from the
        // data itself); this keeps it to one flatten per dataset with no extra workflow load.
        let (_cols, rows) = data_query::flatten(group, &[], false);
        for row in &rows {
            if data_query::search_matches_all(row, &terms) {
                results.push(json!({
                    "dataset": { "id": wid, "name": name, "source_type": source_type },
                    "run_id": row.run_id,
                    "run_at": row.run_at,
                    "fields": row.fields,
                    "highlight": data_query::search_highlight(row, &terms),
                }));
            }
        }
    }

    // Newest-first across datasets.
    results.sort_by(|a, b| {
        let av = a.get("run_at").and_then(|v| v.as_str()).unwrap_or("");
        let bv = b.get("run_at").and_then(|v| v.as_str()).unwrap_or("");
        bv.cmp(av)
    });
    let total = results.len();
    let limit = limit.clamp(1, SEARCH_MAX_PAGE);
    let page: Vec<Value> = results.into_iter().skip(offset).take(limit).collect();
    Ok(json!({
        "query": q,
        "terms": terms,
        "results": page,
        "total": total,
        "truncated": truncated,
        "scanned_runs": scanned,
    }))
}

/// Concierge-facing dataset search returning the canonical `{query, results:[{dataset, run_id,
/// run_at, fields, highlight}], total, ...}` shape. A per-dataset search whose id is a linked crawl
/// dataset (absent locally) forwards to the fleet and re-keys the forwarded `{rows}` into that same
/// results shape, so a linked desktop can answer from a cloud-collected dataset the same way it does
/// a local one. A global search (`workflow_id=None`) is the local FTS across every local dataset.
/// `pub(crate)` so the Scribe concierge reuses the exact REST/MCP search semantics.
pub(crate) async fn concierge_dataset_search(
    st: &AppState,
    workflow_id: Option<i64>,
    q: &str,
    limit: usize,
    offset: usize,
) -> LocalResult<Value> {
    #[cfg(feature = "cloud")]
    if let Some(id) = workflow_id {
        if workflows::get_by_id(&st.db, id).await?.is_none()
            && crate::local::cloud::crawl::is_linked(&st.db).await
        {
            let qq = q.trim();
            let l = limit.clamp(1, SEARCH_MAX_PAGE);
            let raw = format!("q={}&limit={}", encode_path_segment(qq), l);
            let value = crate::local::cloud::workflow_data::get(&st.db, id, "", Some(&raw)).await?;
            let name = value.get("workflow_name").cloned().unwrap_or(Value::Null);
            let rows = value.get("rows").and_then(|r| r.as_array()).cloned().unwrap_or_default();
            let total = value.get("total").and_then(|v| v.as_i64()).unwrap_or(rows.len() as i64);
            let results: Vec<Value> = rows
                .iter()
                .map(|row| {
                    json!({
                        "dataset": { "id": id, "name": name, "source_type": "crawl" },
                        "run_id": row.get("run_id").cloned().unwrap_or(Value::Null),
                        "run_at": row.get("run_at").cloned().unwrap_or(Value::Null),
                        "fields": row.get("fields").cloned().unwrap_or_else(|| row.clone()),
                        "highlight": Value::Null,
                    })
                })
                .collect();
            return Ok(json!({
                "query": q, "terms": data_query::parse_search_terms(q), "results": results,
                "total": total, "truncated": value.get("truncated").cloned().unwrap_or(Value::Bool(false)),
                "scanned_runs": value.get("scanned_runs").cloned().unwrap_or(Value::Null),
            }));
        }
    }
    run_dataset_search(st, workflow_id, q, limit, offset).await
}

/// `GET /v1/workflows/:id/data` — aggregate every run's `extracted_data` for a workflow into one
/// sortable/searchable table (columns + a paginated page of rows). `view=all` (default) is the
/// flat grid — one row per record, each carrying the run it came from; `view=latest` is the
/// deduplicated current dataset; `view=run&run_id=N` is one snapshot annotated vs the previous.
async fn workflow_data(
    State(st): State<AppState>,
    Path(id): Path<i64>,
    RawQuery(raw_query): RawQuery,
    Query(params): Query<TableParams>,
) -> LocalResult<Response> {
    if let Some(resp) = try_forward_cloud_data(&st, id, "", raw_query.as_deref()).await? {
        return Ok(resp);
    }
    let view = match validate_lens_params(
        params.view.as_deref(),
        params.run_id,
        params.collection.as_deref(),
    ) {
        Ok(v) => v,
        Err(resp) => return Ok(resp),
    };
    match view.as_str() {
        "latest" => workflow_data_latest(&st, id, &params).await,
        "run" => workflow_data_run(&st, id, &params).await,
        _ => workflow_data_all(&st, id, &params).await,
    }
}

/// `view=all` — today's flat grid, schema unchanged (no new keys). The default
/// page shape (no search/filters, newest-first) serves from the bounded
/// fastpath; anything else — and any fastpath error — takes the full scan.
async fn workflow_data_all(st: &AppState, id: i64, params: &TableParams) -> LocalResult<Response> {
    let wf = load_workflow(st, id).await?;
    let declared = declared_output_fields(&wf);
    if fast_table_shape(params) {
        match fast_workflow_data_all(&st.db, &wf, &declared, params).await {
            Ok(body) => return Ok(Json(body).into_response()),
            Err(e) => tracing::warn!(
                workflow_id = id, error = %e,
                "data fastpath failed; serving via full scan"
            ),
        }
    }
    let (runs_with_data, truncated) = scan_workflow_data_runs(st, id).await?;
    let scanned = runs_with_data.len();
    let query = params.to_query(true);
    let table = data_query::build_table(&runs_with_data, &declared, &query, params.include_inputs);

    // The desktop table UI reads each cell from `row.fields[column]`, so the rows MUST nest data
    // columns under `fields` (a flat row renders every data cell blank).
    let mut rows = data_query::rows_to_table_json(&table.rows, &table.columns);
    if let Some(chars) = params.preview_chars {
        truncate_preview_rows(&mut rows, chars);
    }
    Ok(Json(json!({
        "workflow_id": wf.id,
        "workflow_name": wf.name,
        "columns": table.columns,
        "declared": table.declared,
        "rows": rows,
        "total": table.total,
        "scanned_runs": scanned,
        "truncated": truncated,
        "limit": query.limit,
        "offset": query.offset,
    }))
    .into_response())
}

/// `view=latest` — the deduplicated current dataset: one row per unique record (its newest
/// version) with a `lineage` sibling. Search/filters/pagination apply AFTER dedup; `counts` are
/// post-dedup, pre-search/filter (missing counted regardless of the toggle). `sources` buckets
/// the lens rowset by originating list key (pre-source-filter); `source` filters to one key
/// ("" = untagged) before search/filters/pagination (spec 3.1).
async fn workflow_data_latest(
    st: &AppState,
    id: i64,
    params: &TableParams,
) -> LocalResult<Response> {
    let lens = build_lens(st, id, params.key.as_deref(), None).await?;
    let include_missing = parse_include_missing(params.include_missing.as_deref());
    let (mut new, mut changed, mut same, mut missing) = (0usize, 0usize, 0usize, 0usize);
    for e in &lens.lineage.latest {
        match e["change"].as_str().unwrap_or_default() {
            "new" => new += 1,
            "changed" => changed += 1,
            "same" => same += 1,
            _ => missing += 1,
        }
    }
    let mut pairs = latest_pairs(&lens, include_missing);
    let sources = sources_envelope(&pairs);
    if let Some(src) = params.source.as_deref() {
        pairs = filter_pairs_by_source(pairs, src);
    }
    let query = params.to_query(true);
    let (page, total) = apply_lens_query(pairs, &query, &lens.columns);
    let mut rows = pairs_to_table_json(&page, &lens.columns);
    if let Some(chars) = params.preview_chars {
        truncate_preview_rows(&mut rows, chars);
    }
    Ok(Json(json!({
        "workflow_id": lens.wf.id,
        "workflow_name": lens.wf.name,
        "columns": lens.columns,
        "declared": !lens.declared.is_empty(),
        "rows": rows,
        "total": total,
        "scanned_runs": lens.scanned,
        "truncated": lens.truncated,
        "limit": query.limit,
        "offset": query.offset,
        "identity": lens.identity.to_json(),
        "counts": { "new": new, "changed": changed, "same": same, "missing": missing },
        "sources": sources,
    }))
    .into_response())
}

/// `view=run` — one snapshot's records annotated vs the previous chain member, plus the records
/// that vanished (`removed_records`) and the snapshot delta. `sources` buckets the snapshot's
/// records by originating list key; `source` filters to one key before search (spec 3.1).
async fn workflow_data_run(st: &AppState, id: i64, params: &TableParams) -> LocalResult<Response> {
    let Some(run_id) = params.run_id else {
        return Ok(run_id_required());
    };
    let lens = build_lens(st, id, params.key.as_deref(), Some(run_id)).await?;
    let Some(detail) = lens.lineage.run_detail.as_ref() else {
        return Err(LocalError::NotFound(format!(
            "run {run_id} is not a data snapshot of workflow {id}"
        )));
    };
    let mut pairs = run_pairs(&lens, detail);
    let sources = sources_envelope(&pairs);
    if let Some(src) = params.source.as_deref() {
        pairs = filter_pairs_by_source(pairs, src);
    }
    let query = params.to_query(true);
    let (page, total) = apply_lens_query(pairs, &query, &lens.columns);
    let mut removed_records: Vec<Value> = detail
        .removed
        .iter()
        .map(|(uid, fields)| json!({ "uid": uid, "fields": fields }))
        .collect();
    let mut rows = pairs_to_table_json(&page, &lens.columns);
    if let Some(chars) = params.preview_chars {
        truncate_preview_rows(&mut rows, chars);
        truncate_preview_rows(&mut removed_records, chars);
    }
    Ok(Json(json!({
        "workflow_id": lens.wf.id,
        "workflow_name": lens.wf.name,
        "columns": lens.columns,
        "declared": !lens.declared.is_empty(),
        "rows": rows,
        "total": total,
        "scanned_runs": lens.scanned,
        "truncated": lens.truncated,
        "limit": query.limit,
        "offset": query.offset,
        "identity": lens.identity.to_json(),
        "delta": detail.delta.to_json(),
        "removed_records": removed_records,
        "prev_run_id": detail.prev_run_id,
        "sources": sources,
    }))
    .into_response())
}

/// Row refs for the hydration lane (`GET /data/rows?ref=run:idx&ref=…`).
#[derive(Debug, Default, Deserialize)]
struct RowRefsParams {
    #[serde(rename = "ref", default)]
    refs: Vec<String>,
}

/// `GET /v1/workflows/:id/data/rows` — FULL (untruncated) rows for specific
/// `run_id:record_index` refs: the hydration lane behind the table's
/// `preview_chars` mode. The grid loads preview-sized cells, then fetches the
/// complete record here only when the user expands, views, copies, or sends
/// it. Same flatten pipeline (same redaction + declared projection) as the
/// table; unknown refs are simply absent from the result. Cloud datasets
/// forward like every other data read.
async fn workflow_data_rows(
    State(st): State<AppState>,
    Path(id): Path<i64>,
    RawQuery(raw_query): RawQuery,
    Query(params): Query<RowRefsParams>,
) -> LocalResult<Response> {
    if let Some(resp) = try_forward_cloud_data(&st, id, "/rows", raw_query.as_deref()).await? {
        return Ok(resp);
    }
    let wf = load_workflow(&st, id).await?;
    let declared = declared_output_fields(&wf);
    let mut refs: Vec<(i64, usize)> = Vec::new();
    for raw in &params.refs {
        if let Some((run_s, idx_s)) = raw.split_once(':') {
            if let (Ok(run_id), Ok(idx)) = (run_s.parse::<i64>(), idx_s.parse::<usize>()) {
                refs.push((run_id, idx));
            }
        }
    }
    if refs.len() > 100 {
        return Ok(lens_params_400("at most 100 refs per request"));
    }
    let mut ids: Vec<i64> = Vec::new();
    for (rid, _) in &refs {
        if !ids.contains(rid) {
            ids.push(*rid);
        }
    }
    let loaded = runs::get_by_ids(&st.db, &ids).await?;
    let mut by_ref: HashMap<(i64, usize), Value> = HashMap::new();
    for run in loaded {
        // Scope + parity with the table scan: this workflow's SUCCESSFUL runs only.
        if run.workflow_id != Some(wf.id) || run.success != Some(1) {
            continue;
        }
        let input = to_run_input(run);
        let (_cols, rows) = data_query::flatten(std::slice::from_ref(&input), &declared, false);
        for row in rows {
            by_ref.insert(
                (row.run_id, row.record_index),
                json!({
                    "run_id": row.run_id,
                    "run_at": row.run_at,
                    "status": row.status,
                    "record_index": row.record_index,
                    "fields": row.fields,
                }),
            );
        }
    }
    let rows: Vec<Value> = refs.iter().filter_map(|r| by_ref.remove(r)).collect();
    Ok(Json(json!({ "workflow_id": wf.id, "rows": rows })).into_response())
}

/// `GET /v1/workflows/:id/data/runs` — the snapshot index: every successful data-bearing run
/// (newest first) with record count, explicit-empty flag and delta vs the previous chain member
/// (null for the oldest).
async fn workflow_data_runs(
    State(st): State<AppState>,
    Path(id): Path<i64>,
    RawQuery(raw_query): RawQuery,
    Query(params): Query<LineageParams>,
) -> LocalResult<Response> {
    if let Some(resp) = try_forward_cloud_data(&st, id, "/runs", raw_query.as_deref()).await? {
        return Ok(resp);
    }
    let lens = build_lens(&st, id, params.key.as_deref(), None).await?;
    let status_by_run: BTreeMap<i64, Option<String>> =
        lens.flat.iter().map(|r| (r.run_id, r.status.clone())).collect();
    let runs: Vec<Value> = lens
        .lineage
        .runs_index
        .iter()
        .cloned()
        .map(|mut entry| {
            let rid = entry["run_id"].as_i64().unwrap_or_default();
            entry["status"] = json!(status_by_run.get(&rid).cloned().flatten());
            entry
        })
        .collect();
    Ok(Json(json!({
        "runs": runs,
        "identity": lens.identity.to_json(),
        "scanned_runs": lens.scanned,
        "truncated": lens.truncated,
    }))
    .into_response())
}

/// `GET /v1/workflows/:id/data/records/:record_uid/history` — the record's CHANGE-POINT versions
/// (first appearance + each changed appearance), oldest→newest. Unknown uid → 404 whose body
/// carries the current identity so the client can re-key and refetch.
async fn workflow_record_history(
    State(st): State<AppState>,
    Path((id, record_uid)): Path<(i64, String)>,
    RawQuery(raw_query): RawQuery,
    Query(params): Query<LineageParams>,
) -> LocalResult<Response> {
    let sub = format!("/records/{}/history", encode_path_segment(&record_uid));
    if let Some(resp) = try_forward_cloud_data(&st, id, &sub, raw_query.as_deref()).await? {
        return Ok(resp);
    }
    let lens = build_lens(&st, id, params.key.as_deref(), None).await?;
    let Some(versions) = lens.lineage.histories.get(&record_uid) else {
        return Ok((
            StatusCode::NOT_FOUND,
            Json(json!({
                "detail": format!("record {record_uid} not found"),
                "identity": lens.identity.to_json(),
            })),
        )
            .into_response());
    };
    Ok(Json(json!({
        "record_uid": record_uid,
        "identity": lens.identity.to_json(),
        "first_seen_at": lens.lineage.first_seen.get(&record_uid),
        "last_seen_at": lens.lineage.last_seen.get(&record_uid),
        "versions": versions,
    }))
    .into_response())
}

/// `GET /v1/workflows/:id/data/facets` — per-column facets over the workflow's present extracted
/// data (inferred type, non-empty count, numeric min/max, distinct pick-list when low cardinality).
/// Drives the grid's smart, data-aware column filters. `view=latest|run` computes over exactly
/// that lens's (post-dedup / single-snapshot) rowset; default view=all is unchanged.
async fn workflow_data_facets(
    State(st): State<AppState>,
    Path(id): Path<i64>,
    RawQuery(raw_query): RawQuery,
    Query(params): Query<FacetParams>,
) -> LocalResult<Response> {
    if let Some(resp) = try_forward_cloud_data(&st, id, "/facets", raw_query.as_deref()).await? {
        return Ok(resp);
    }
    let view = match validate_lens_params(
        params.view.as_deref(),
        params.run_id,
        params.collection.as_deref(),
    ) {
        Ok(v) => v,
        Err(resp) => return Ok(resp),
    };
    if view == "latest" || view == "run" {
        let (lens, pairs) = match view.as_str() {
            "latest" => {
                let lens = build_lens(&st, id, params.key.as_deref(), None).await?;
                let include_missing = parse_include_missing(params.include_missing.as_deref());
                let pairs = latest_pairs(&lens, include_missing);
                (lens, pairs)
            }
            _ => {
                let Some(run_id) = params.run_id else {
                    return Ok(run_id_required());
                };
                let lens = build_lens(&st, id, params.key.as_deref(), Some(run_id)).await?;
                let pairs = match lens.lineage.run_detail.as_ref() {
                    Some(detail) => run_pairs(&lens, detail),
                    None => {
                        return Err(LocalError::NotFound(format!(
                            "run {run_id} is not a data snapshot of workflow {id}"
                        )))
                    }
                };
                (lens, pairs)
            }
        };
        // Facets compute over exactly the lens rowset — `source` (spec 3.1) narrows it first;
        // the `sources` envelope stays pre-filter so chip counts hold while one is selected.
        let sources = sources_envelope(&pairs);
        let pairs = match params.source.as_deref() {
            Some(src) => filter_pairs_by_source(pairs, src),
            None => pairs,
        };
        let rows: Vec<data_query::Row> = pairs.into_iter().map(|(r, _)| r).collect();
        let facets = data_query::compute_facets(&lens.columns, &rows);
        return Ok(Json(json!({
            "workflow_id": lens.wf.id,
            "columns": lens.columns,
            "facets": facets,
            "sources": sources,
            "row_count": rows.len(),
            "scanned_runs": lens.scanned,
            "truncated": lens.truncated,
        }))
        .into_response());
    }
    let wf = load_workflow(&st, id).await?;
    let declared = declared_output_fields(&wf);
    if !params.include_inputs {
        // Fastpath: exact for small windows; a heavy dataset gets facets over
        // its NEWEST rows within a sample budget (`sampled: true`, `row_count`
        // = rows faceted, `total_rows` = exact window total) instead of a
        // whole-corpus parse per request. Errors fall back to the full scan.
        match fast_workflow_data_facets(&st.db, &wf, &declared).await {
            Ok(body) => return Ok(Json(body).into_response()),
            Err(e) => tracing::warn!(
                workflow_id = id, error = %e,
                "data facets fastpath failed; serving via full scan"
            ),
        }
    }
    let (runs_with_data, truncated) = scan_workflow_data_runs(&st, id).await?;
    let scanned = runs_with_data.len();
    let (columns, rows) = data_query::flatten(&runs_with_data, &declared, params.include_inputs);
    let facets = data_query::compute_facets(&columns, &rows);
    Ok(Json(json!({
        "workflow_id": wf.id,
        "columns": columns,
        "facets": facets,
        "row_count": rows.len(),
        "scanned_runs": scanned,
        "truncated": truncated,
    }))
    .into_response())
}

/// The bounded view=all facets body (see the fastpath section notes).
async fn fast_workflow_data_facets(
    db: &sqlx::sqlite::SqlitePool,
    wf: &workflows::Workflow,
    declared: &[String],
) -> LocalResult<Value> {
    let (stubs, raw_n) = runs::data_window_stubs(db, wf.id, DATA_SCAN_CAP).await?;
    let truncated = raw_n >= DATA_SCAN_CAP;
    let epoch = data_epoch_for(wf.id);
    let digests = window_digests(db, &stubs, declared, epoch).await?;
    let scanned = stubs
        .iter()
        .filter(|s| digests.get(&s.id).map(|d| d.nonnull).unwrap_or(false))
        .count();
    let n_of = |id: i64| digests.get(&id).map(|d| d.n).unwrap_or(0);
    let total: usize = stubs.iter().map(|s| n_of(s.id)).sum();
    let columns = merged_columns(&stubs, &digests, declared);

    // Cover the newest rows within the sample budget, in SCAN order (the
    // legacy facets flatten un-sorted, so its "first rows" are these).
    let mut cover: Vec<i64> = Vec::new();
    let mut covered_rows: usize = 0;
    let mut covered_bytes: i64 = 0;
    let mut sampled = false;
    for s in &stubs {
        let n = n_of(s.id);
        if n == 0 {
            continue;
        }
        if !cover.is_empty()
            && (covered_rows >= FACET_SAMPLE_ROWS || covered_bytes + s.size > FACET_SAMPLE_BYTES)
        {
            sampled = true;
            break;
        }
        cover.push(s.id);
        covered_rows += n;
        covered_bytes += s.size;
    }
    let loaded = runs::get_by_ids(db, &cover).await?;
    let inputs: Vec<RunInput> = loaded.into_iter().map(to_run_input).collect();
    let (_cols, rows) = data_query::flatten(&inputs, declared, false);
    let facets = data_query::compute_facets(&columns, &rows);
    Ok(json!({
        "workflow_id": wf.id,
        "columns": columns,
        "facets": facets,
        "row_count": rows.len(),
        "total_rows": total,
        "sampled": sampled,
        "scanned_runs": scanned,
        "truncated": truncated,
    }))
}

/// `GET /v1/workflows/:id/data/export` — download the full (search/sort/filter applied,
/// UN-paginated) extracted-data table as CSV (`?format=csv`, default) or JSON (`?format=json`).
/// Bounded by the scan cap. `view=latest|run` exports that lens's rowset: CSV appends the
/// lineage columns after the run-meta columns; JSON rows carry `_lineage` (spec 1.5.5).
async fn export_workflow_data(
    State(st): State<AppState>,
    Path(id): Path<i64>,
    RawQuery(raw_query): RawQuery,
    Query(params): Query<TableParams>,
) -> LocalResult<Response> {
    if let Some(resp) = try_forward_cloud_export(&st, id, raw_query.as_deref()).await? {
        return Ok(resp);
    }
    let view = match validate_lens_params(
        params.view.as_deref(),
        params.run_id,
        params.collection.as_deref(),
    ) {
        Ok(v) => v,
        Err(resp) => return Ok(resp),
    };
    if view == "latest" || view == "run" {
        return export_lens(&st, id, &params, view == "run").await;
    }
    let wf = load_workflow(&st, id).await?;
    let declared = declared_output_fields(&wf);
    let (runs_with_data, _truncated) = scan_workflow_data_runs(&st, id).await?;
    let query = params.to_query(false); // un-paginated (limit=None)
    let table = data_query::build_table(&runs_with_data, &declared, &query, params.include_inputs);

    let name = if wf.name.is_empty() {
        format!("workflow-{}", wf.id)
    } else {
        wf.name.clone()
    };
    let stem = safe_export_filename(&name);

    // markdown / html render through the shared helper, which frames the download
    // + the safe-render headers. json / csv keep their existing branches below.
    let fmt = norm_format(params.format.as_deref())?;
    if fmt == "markdown" || fmt == "html" {
        if let Some(resp) = render_table(
            &fmt,
            &table.columns,
            &table.rows,
            &name,
            Some(&format!("{stem}-data")),
        ) {
            return Ok(resp);
        }
    }

    if params.format.as_deref().map(|f| f.eq_ignore_ascii_case("json")).unwrap_or(false) {
        let records = data_query::rows_to_json(&table.rows, &table.columns);
        let body = serde_json::to_string_pretty(&records)?;
        let disposition = format!("attachment; filename=\"{stem}-data.json\"");
        return Ok((
            [
                (header::CONTENT_TYPE, "application/json".to_string()),
                (header::CONTENT_DISPOSITION, disposition),
            ],
            body,
        )
            .into_response());
    }

    let body = data_query::to_csv(&table.columns, &table.rows);
    let disposition = format!("attachment; filename=\"{stem}-data.csv\"");
    Ok((
        [
            (header::CONTENT_TYPE, "text/csv; charset=utf-8".to_string()),
            (header::CONTENT_DISPOSITION, disposition),
        ],
        body,
    )
        .into_response())
}

/// Lens export (`view=latest|run`): the same search/sort/filter machinery, un-paginated, with
/// lineage attached — CSV lineage columns after the run-meta columns, `_lineage` on JSON rows.
async fn export_lens(
    st: &AppState,
    id: i64,
    params: &TableParams,
    is_run: bool,
) -> LocalResult<Response> {
    let lens;
    let pairs;
    if is_run {
        let Some(run_id) = params.run_id else {
            return Ok(run_id_required());
        };
        lens = build_lens(st, id, params.key.as_deref(), Some(run_id)).await?;
        let Some(detail) = lens.lineage.run_detail.as_ref() else {
            return Err(LocalError::NotFound(format!(
                "run {run_id} is not a data snapshot of workflow {id}"
            )));
        };
        pairs = run_pairs(&lens, detail);
    } else {
        lens = build_lens(st, id, params.key.as_deref(), None).await?;
        let include_missing = parse_include_missing(params.include_missing.as_deref());
        pairs = latest_pairs(&lens, include_missing);
    }
    let query = params.to_query(false); // un-paginated export
    let (rows, _total) = apply_lens_query(pairs, &query, &lens.columns);

    let name = if lens.wf.name.is_empty() {
        format!("workflow-{}", lens.wf.id)
    } else {
        lens.wf.name.clone()
    };
    let stem = safe_export_filename(&name);

    if params.format.as_deref().map(|f| f.eq_ignore_ascii_case("json")).unwrap_or(false) {
        let records: Vec<Value> = rows
            .iter()
            .map(|(row, lineage)| {
                let mut rec = data_query::row_to_json(row, &lens.columns);
                rec["_lineage"] = api_lineage(lineage);
                rec
            })
            .collect();
        let body = serde_json::to_string_pretty(&records)?;
        let disposition = format!("attachment; filename=\"{stem}-data.json\"");
        return Ok((
            [
                (header::CONTENT_TYPE, "application/json".to_string()),
                (header::CONTENT_DISPOSITION, disposition),
            ],
            body,
        )
            .into_response());
    }

    let body = data_query::to_csv_with_lineage(&lens.columns, &rows);
    let disposition = format!("attachment; filename=\"{stem}-data.csv\"");
    Ok((
        [
            (header::CONTENT_TYPE, "text/csv; charset=utf-8".to_string()),
            (header::CONTENT_DISPOSITION, disposition),
        ],
        body,
    )
        .into_response())
}

/// Body for `POST /v1/workflows/:id/data/preview` — an optional structured-filter array (same shape
/// as `?filters=` on the table endpoint) and an optional row cap.
#[derive(Debug, Default, Deserialize)]
struct PreviewBody {
    /// Structured smart-filter clauses (a JSON array; same schema as the table `filters` param).
    #[serde(default)]
    filters: Option<Value>,
    /// Max sample rows to return (default `DEFAULT_PREVIEW_LIMIT`, hard-capped at `MAX_PREVIEW_LIMIT`).
    #[serde(default)]
    limit: Option<usize>,
}

/// Default sample size for the redacted preview when the body omits `limit`.
const DEFAULT_PREVIEW_LIMIT: usize = 5;
/// Hard cap on a preview page — a preview is a small sample, never a bulk export.
const MAX_PREVIEW_LIMIT: usize = 50;

/// `POST /v1/workflows/:id/data/preview` — a small REDACTED sample of the workflow's extracted data:
/// `{ columns, rows }` only, capped at `limit` (default 5). Every cell is run through the SAME
/// `strip_meta` + `redact_secret_keys` path the Data surface uses (via `data_query::build_table`),
/// so the internal envelope (cookies/auth_session/screenshots/…) and secret-shaped inputs
/// (password/token/api_key/…) NEVER surface. `rows` are the redacted data columns only (nested under
/// no run-meta) — this is a schema/sample preview, not the full run log.
async fn workflow_data_preview(
    State(st): State<AppState>,
    Path(id): Path<i64>,
    Json(body): Json<PreviewBody>,
) -> LocalResult<Json<Value>> {
    let wf = load_workflow(&st, id).await?;
    let declared = declared_output_fields(&wf);
    let (runs_with_data, _truncated) = scan_workflow_data_runs(&st, id).await?;

    let limit = body.limit.unwrap_or(DEFAULT_PREVIEW_LIMIT).clamp(1, MAX_PREVIEW_LIMIT);
    // Serialize the optional filters value back to the string the shared parser consumes.
    let filters_str = body.filters.as_ref().map(|v| v.to_string());
    let query = TableQuery {
        q: None,
        col_filters: BTreeMap::new(),
        filters: parse_structured_filters(filters_str.as_deref()),
        sort_by: None,
        sort_dir: "desc".into(),
        offset: 0,
        limit: Some(limit),
    };
    // include_inputs = false: never surface run-input columns in a preview.
    let table = data_query::build_table(&runs_with_data, &declared, &query, false);

    // Redacted rows: the data columns only (each cell already meta/secret-stripped by the engine).
    let rows: Vec<Value> = table
        .rows
        .iter()
        .map(|r| {
            let mut fields = serde_json::Map::new();
            for c in &table.columns {
                // `table.columns` are the flattened DATA columns; read straight from the row's
                // (already meta/secret-redacted) `fields` map. A column absent for this row → null.
                fields.insert(c.clone(), r.fields.get(c).cloned().unwrap_or(Value::Null));
            }
            Value::Object(fields)
        })
        .collect();

    Ok(Json(json!({
        "columns": table.columns,
        "rows": rows,
    })))
}

/// Export a workflow's extracted-data table to raw bytes (`csv` or `json`), applying the SAME
/// scan + flatten + redaction (`strip_meta` + `redact_secret_keys`) the Data surface uses. Shared by
/// `POST /v1/files/from-data` and the `flow.rs` `save_data_to_file` / `query_and_export` actions so
/// there is ONE export path. `filters_json` is the optional structured-filter array (as JSON text).
/// Returns `(bytes, filename, content_type)`.
pub(crate) async fn export_workflow_data_bytes(
    db: &sqlx::sqlite::SqlitePool,
    workflow_id: i64,
    format: &str,
    filters_json: Option<&str>,
) -> LocalResult<(Vec<u8>, String, String)> {
    let wf = workflows::get_by_id(db, workflow_id)
        .await?
        .ok_or_else(|| crate::local::error::LocalError::NotFound(format!("workflow {workflow_id}")))?;
    let declared = declared_output_fields(&wf);
    let (runs_with_data, _truncated) = scan_workflow_data_runs_pool(db, workflow_id).await?;

    let query = TableQuery {
        q: None,
        col_filters: BTreeMap::new(),
        filters: parse_structured_filters(filters_json),
        sort_by: None,
        sort_dir: "desc".into(),
        offset: 0,
        limit: None, // un-paginated export
    };
    let table = data_query::build_table(&runs_with_data, &declared, &query, false);

    let name = if wf.name.is_empty() {
        format!("workflow-{}", wf.id)
    } else {
        wf.name.clone()
    };
    let stem = safe_export_filename(&name);

    if format.eq_ignore_ascii_case("json") {
        let records = data_query::rows_to_json(&table.rows, &table.columns);
        let body = serde_json::to_string_pretty(&records)?;
        Ok((body.into_bytes(), format!("{stem}-data.json"), "application/json".into()))
    } else {
        let body = data_query::to_csv(&table.columns, &table.rows);
        Ok((body.into_bytes(), format!("{stem}-data.csv"), "text/csv; charset=utf-8".into()))
    }
}

/// Load the workflow whose data is requested or 404. (No tenant check — single-user local backend.)
async fn load_workflow(st: &AppState, id: i64) -> LocalResult<workflows::Workflow> {
    workflows::get_by_id(&st.db, id)
        .await?
        .ok_or_else(|| crate::local::error::LocalError::NotFound(format!("workflow {id}")))
}

/// One row the caller wants gone: `(run_id, record_index)`. Matches the shape a Data-table row
/// carries in the GET response so the frontend can pass rows through verbatim — record_index is
/// the stored slot for a top-level list (a coerced table's first data row is slot 1) and the
/// sorted-key running counter for dict payloads.
#[derive(Debug, Deserialize)]
struct ExtractedRowRef {
    run_id: i64,
    #[serde(default)]
    record_index: usize,
}

/// Body for `DELETE /v1/workflows/:id/data` — explicit rows and/or record uids.
#[derive(Debug, Deserialize)]
struct DeleteRowsBody {
    #[serde(default)]
    records: Vec<ExtractedRowRef>,
    /// Lineage uids — the delete set expands to EVERY stored version of each uid.
    #[serde(default)]
    record_uids: Vec<String>,
    /// Identity pinning echo: the identity.fields of the response the uids came from.
    #[serde(default)]
    key: Option<String>,
    /// Clear EVERY extracted record for this workflow (the Outputs picker's bulk-remove — the
    /// whole workflow drops out of the list). Ignores `records`/`record_uids` when set.
    #[serde(default)]
    clear_all: bool,
}

/// `DELETE /v1/workflows/:id/data` — remove extracted-data rows from a workflow. The delete set
/// = `records` ∪ all resolved versions of `record_uids` (resolved against the same flatten +
/// identity the GET rows came from; the single-writer daemon serializes resolution and mutation).
/// Per-run semantics:
///
/// - `extracted_data` is a JSON list → pop the given stored slots (higher first so earlier
///   deletions don't reindex the later ones). If the list empties — or a coerced table is left
///   with only its header row — `extracted_data` is set to null.
/// - a dict payload → the global record_index maps back to (list key, stored slot) via the same
///   sorted-key offset arithmetic the flatten uses; sibling lists are untouched.
/// - a single dict/scalar record → any index request clears it entirely.
///
/// The `result_data` envelope is preserved (only its `extracted_data` field is mutated), so the
/// run still shows up in Runs; it just no longer contributes rows to the Data view. Response:
/// `{deleted, resolved: {uid: n_versions}, unmatched: [uids]}`.
async fn delete_workflow_data(
    State(st): State<AppState>,
    Path(id): Path<i64>,
    Json(body): Json<DeleteRowsBody>,
) -> LocalResult<Json<Value>> {
    let _wf = load_workflow(&st, id).await?;

    // Bulk-remove: clear ALL extracted data for the workflow (drops it out of the Outputs
    // picker). Null `extracted_data` on every run of this workflow that carries any, counting
    // the records dropped. The `result_data` envelope is preserved so the runs still show in Runs.
    if body.clear_all {
        let mut deleted: usize = 0;
        for run in runs::list_by_workflow(&st.db, id, 1000).await? {
            let raw = run.result_data.as_deref().unwrap_or("");
            if raw.trim().is_empty() {
                continue;
            }
            let mut rd: Value = match serde_json::from_str(raw) {
                Ok(v) => v,
                Err(_) => continue,
            };
            // Skip runs that carry no extracted_data — nothing to clear.
            let has_data = rd
                .get("extracted_data")
                .map(|v| !v.is_null())
                .unwrap_or(false);
            if !has_data {
                continue;
            }
            deleted += data_query::record_count(&rd);
            if let Some(obj) = rd.as_object_mut() {
                obj.insert("extracted_data".into(), Value::Null);
            }
            let new_json = serde_json::to_string(&rd)?;
            runs::set_result_data(&st.db, run.id, Some(&new_json)).await?;
        }
        // Rewritten payloads invalidate the fastpath's cached per-run digests
        // deterministically (size-keying alone is only near-certain).
        bump_data_epoch(id);
        return Ok(Json(
            json!({ "deleted": deleted, "resolved": {}, "unmatched": [] }),
        ));
    }

    if body.records.is_empty() && body.record_uids.is_empty() {
        return Ok(Json(json!({ "deleted": 0, "resolved": {}, "unmatched": [] })));
    }

    // Group by run so each affected run gets ONE UPDATE.
    let mut by_run: BTreeMap<i64, BTreeSet<usize>> = BTreeMap::new();
    for r in &body.records {
        by_run.entry(r.run_id).or_default().insert(r.record_index);
    }

    // Resolve uids → every (run_id, record_index) appearance across the snapshot chain.
    let mut resolved = Map::new();
    let mut unmatched: Vec<String> = Vec::new();
    if !body.record_uids.is_empty() {
        let lens = build_lens(&st, id, body.key.as_deref(), None).await?;
        let requested: BTreeSet<&String> = body.record_uids.iter().collect();
        let mut appearances: BTreeMap<String, u64> = BTreeMap::new();
        for run in lens.flat.iter().filter(|r| r.data_bearing) {
            for (uid, idx, _rec) in
                data_query::assign_uids(&run.records, lens.identity.mode, &lens.identity.fields)
            {
                if requested.contains(&uid) {
                    by_run.entry(run.run_id).or_default().insert(idx);
                    *appearances.entry(uid).or_insert(0) += 1;
                }
            }
        }
        for uid in &body.record_uids {
            match appearances.get(uid) {
                Some(n) => {
                    resolved.insert(uid.clone(), json!(n));
                }
                None if !unmatched.contains(uid) => unmatched.push(uid.clone()),
                None => {}
            }
        }
    }

    let mut deleted: usize = 0;
    for (run_id, idxs) in by_run {
        let run = match runs::get_by_id(&st.db, run_id).await? {
            Some(r) => r,
            None => continue,
        };
        // Only touch runs that belong to this workflow — protects against a bogus (run_id, wf_id)
        // pair the client might send.
        if run.workflow_id != Some(id) {
            continue;
        }
        let raw = run.result_data.as_deref().unwrap_or("");
        if raw.trim().is_empty() {
            continue;
        }
        let mut rd: Value = match serde_json::from_str(raw) {
            Ok(v) => v,
            Err(_) => continue,
        };
        let obj = match rd.as_object_mut() {
            Some(o) => o,
            None => continue,
        };
        if !obj.contains_key("extracted_data") {
            continue;
        }

        // Locate the stored slots the GET row indices point at (mirrors
        // `data_query::coerce_records`): a top-level list's record_index IS the stored slot; a
        // dict payload expands every non-empty list key in SORTED order with a global running
        // counter, so the index maps back through per-list offset arithmetic. Without this, a
        // per-row delete on a wrapper dict would wipe sibling datasets.
        //
        // Classify first (read-only borrow), then mutate through a fresh borrow.
        struct Seg {
            key: String,
            table: bool,
            records: usize,
        }
        enum Shape {
            TopLevelList { table: bool },
            SortedLists(Vec<Seg>),
            ClearAll,
            Skip,
        }
        let shape: Shape = {
            let ext = obj.get("extracted_data").expect("checked above");
            match ext {
                Value::Array(items) if items.is_empty() => Shape::Skip,
                Value::Array(items) => Shape::TopLevelList {
                    table: data_query::detect_table(items).is_some(),
                },
                Value::Object(inner) => {
                    let mut keys: Vec<&String> = inner
                        .iter()
                        .filter(|(k, v)| {
                            !data_query::is_meta_key(k)
                                && matches!(v, Value::Array(a) if !a.is_empty())
                        })
                        .map(|(k, _)| k)
                        .collect();
                    keys.sort();
                    if keys.is_empty() {
                        Shape::ClearAll
                    } else {
                        Shape::SortedLists(
                            keys.into_iter()
                                .map(|k| {
                                    let items =
                                        inner[k.as_str()].as_array().expect("list keys checked");
                                    let table = data_query::detect_table(items).is_some();
                                    Seg {
                                        key: k.clone(),
                                        table,
                                        records: items.len() - usize::from(table),
                                    }
                                })
                                .collect(),
                        )
                    }
                }
                Value::Null => Shape::Skip,
                _ => Shape::ClearAll,
            }
        };

        match shape {
            Shape::Skip => continue,
            Shape::ClearAll => {
                obj.insert("extracted_data".into(), Value::Null);
                deleted += 1;
            }
            Shape::TopLevelList { table } => {
                let items = match obj.get_mut("extracted_data") {
                    Some(Value::Array(a)) => a,
                    _ => continue,
                };
                // record_index IS the stored slot; a coerced table's slot 0 is the header —
                // never deletable as a row.
                let min_slot = usize::from(table);
                let slots: Vec<usize> = idxs
                    .into_iter()
                    .filter(|i| *i >= min_slot && *i < items.len())
                    .collect();
                if slots.is_empty() {
                    continue;
                }
                for i in slots.iter().rev() {
                    items.remove(*i);
                    deleted += 1;
                }
                // Emptied — or a coerced table left with only its header row — carries no data.
                if items.is_empty() || (table && items.len() == 1) {
                    obj.insert("extracted_data".into(), Value::Null);
                }
            }
            Shape::SortedLists(segs) => {
                // Global record_index → (list key, stored slot) via sorted-key offsets; the
                // stored slot skips a coerced table's header row.
                let mut per_key: BTreeMap<String, (bool, Vec<usize>)> = BTreeMap::new();
                for idx in idxs {
                    let mut offset = 0usize;
                    for seg in &segs {
                        if idx < offset + seg.records {
                            per_key
                                .entry(seg.key.clone())
                                .or_insert_with(|| (seg.table, Vec::new()))
                                .1
                                .push(idx - offset + usize::from(seg.table));
                            break;
                        }
                        offset += seg.records;
                    }
                }
                let inner = match obj.get_mut("extracted_data").and_then(|v| v.as_object_mut()) {
                    Some(o) => o,
                    None => continue,
                };
                for (key, (table, mut slots)) in per_key {
                    let items = match inner.get_mut(&key) {
                        Some(Value::Array(a)) => a,
                        _ => continue,
                    };
                    slots.sort_unstable();
                    slots.dedup();
                    for s in slots.iter().rev() {
                        if *s < items.len() {
                            items.remove(*s);
                            deleted += 1;
                        }
                    }
                    // A table left with only its header row carries no data — empty it so the
                    // header can't re-coerce into a phantom col_N record.
                    if table && items.len() == 1 {
                        items.clear();
                    }
                }
                // If nothing meaningful survives at the envelope level, null the whole
                // extracted_data.
                let has_any_data = inner.iter().any(|(k, v)| {
                    if data_query::is_meta_key(k) {
                        return false;
                    }
                    match v {
                        Value::Null => false,
                        Value::Array(a) => !a.is_empty(),
                        Value::Object(m) => !m.is_empty(),
                        Value::String(s) => !s.is_empty(),
                        _ => true,
                    }
                });
                if !has_any_data {
                    obj.insert("extracted_data".into(), Value::Null);
                }
            }
        }

        let new_json = serde_json::to_string(&rd)?;
        runs::set_result_data(&st.db, run_id, Some(&new_json)).await?;
    }

    if deleted > 0 {
        // Rewritten payloads invalidate the fastpath's cached per-run digests
        // deterministically (size-keying alone is only near-certain).
        bump_data_epoch(id);
    }
    Ok(Json(json!({ "deleted": deleted, "resolved": resolved, "unmatched": unmatched })))
}

#[cfg(test)]
mod tests {
    use super::*;

    // ------------------------------------------------------------------
    // Bounded fastpath — byte parity with the legacy full scan.
    // ------------------------------------------------------------------
    mod fastpath {
        use super::super::*;
        use crate::local::db;
        use crate::local::store::workflows::{self, NewWorkflow};
        use crate::local::store::runs::NewRun;

        async fn pool() -> sqlx::sqlite::SqlitePool {
            let dir = Box::leak(Box::new(tempfile::tempdir().unwrap()));
            db::open(&dir.path().join("t.db"), "test-key-data-fastpath").await.unwrap()
        }

        /// Insert a completed, successful run carrying `extracted_data`.
        async fn seed_run(
            pool: &sqlx::sqlite::SqlitePool,
            wf_id: i64,
            completed_at: &str,
            extracted: Value,
        ) -> i64 {
            let run = runs::insert(pool, &NewRun { workflow_id: Some(wf_id), ..Default::default() })
                .await
                .unwrap();
            let rd = json!({ "extracted_data": extracted }).to_string();
            sqlx::query(
                "UPDATE runs SET status='success', success=1, completed_at=?2, result_data=?3
                 WHERE id=?1",
            )
            .bind(run.id)
            .bind(completed_at)
            .bind(rd)
            .fetch_optional(pool)
            .await
            .unwrap();
            run.id
        }

        /// One of every coercion shape, timestamp TIES included (the tie order
        /// build_table produces — asc stable sort then reverse — is the trap).
        async fn seed_workflow(pool: &sqlx::sqlite::SqlitePool) -> workflows::Workflow {
            let wf = workflows::insert(pool, &NewWorkflow { name: "wf".into(), ..Default::default() })
                .await
                .unwrap();
            seed_run(pool, wf.id, "2026-08-19T10:00:00Z", json!([
                {"title": "A", "price": 120},
                {"title": "B", "price": 95},
                {"title": "C", "url": "https://example.com", "posts": {"items": [{"a": 1}, {"a": 2}]}},
            ]))
            .await;
            seed_run(pool, wf.id, "2026-08-18T10:00:00Z", json!({"title": "solo", "extra": "x"})).await;
            seed_run(pool, wf.id, "2026-08-18T10:00:00Z", json!([
                ["Store", "Net"], ["s1", "10"], ["s2", "20"],
            ]))
            .await;
            seed_run(pool, wf.id, "2026-08-17T10:00:00Z", json!([1, "x", null])).await;
            seed_run(pool, wf.id, "2026-08-16T10:00:00Z", json!({"dry_run": true})).await;
            seed_run(pool, wf.id, "2026-08-13T10:00:00Z", json!([])).await;
            seed_run(pool, wf.id, "2026-08-12T10:00:00Z", json!([
                {"title": "Doc", "markdown": "M".repeat(5000), "meta": {"lang": "fr"}},
            ]))
            .await;
            wf
        }

        #[tokio::test]
        async fn fast_page_matches_build_table_for_every_offset() {
            let pool = pool().await;
            let wf = seed_workflow(&pool).await;
            let declared: Vec<String> = Vec::new();
            let (inputs, _t) = scan_workflow_data_runs_pool(&pool, wf.id).await.unwrap();
            let scanned = inputs.len();
            let full = data_query::build_table(
                &inputs,
                &declared,
                &TableQuery {
                    sort_by: Some("run_at".into()),
                    sort_dir: "desc".into(),
                    offset: 0,
                    limit: None,
                    ..Default::default()
                },
                false,
            );
            for limit in [1usize, 3, 50] {
                for offset in 0..=(full.total + 1) {
                    let query = TableQuery {
                        sort_by: Some("run_at".into()),
                        sort_dir: "desc".into(),
                        offset,
                        limit: Some(limit),
                        ..Default::default()
                    };
                    let table = data_query::build_table(&inputs, &declared, &query, false);
                    let expected = data_query::rows_to_table_json(&table.rows, &table.columns);
                    let params = TableParams {
                        sort_by: Some("run_at".into()),
                        sort_dir: Some("desc".into()),
                        limit: Some(limit),
                        offset: Some(offset),
                        ..Default::default()
                    };
                    let body = fast_workflow_data_all(&pool, &wf, &declared, &params)
                        .await
                        .unwrap();
                    assert_eq!(body["rows"], json!(expected), "offset={offset} limit={limit}");
                    assert_eq!(body["total"], json!(table.total));
                    assert_eq!(body["columns"], json!(table.columns));
                    assert_eq!(body["scanned_runs"], json!(scanned));
                }
            }
        }

        #[test]
        fn preview_truncation_marks_and_bounds_string_cells() {
            let mut rows = vec![json!({
                "run_id": 1, "record_index": 0,
                "fields": {"title": "Doc", "markdown": "M".repeat(5000), "meta": {"lang": "fr"}},
            })];
            truncate_preview_rows(&mut rows, 256);
            assert_eq!(rows[0]["fields"]["markdown"], json!("M".repeat(256)));
            assert_eq!(rows[0]["_truncated"], json!(["markdown"]));
            // Short strings and objects pass through untouched.
            assert_eq!(rows[0]["fields"]["title"], json!("Doc"));
            assert_eq!(rows[0]["fields"]["meta"], json!({"lang": "fr"}));
            // Nothing to cut: no marker key appears.
            let mut short = vec![json!({"fields": {"title": "A"}})];
            truncate_preview_rows(&mut short, 256);
            assert!(short[0].get("_truncated").is_none());
        }

        #[tokio::test]
        async fn picker_line_matches_the_scan_and_hides_empty_workflows() {
            let pool = pool().await;
            let wf = seed_workflow(&pool).await;
            let line = fast_picker_line(&pool, &wf).await.unwrap().expect("listed");

            let (mut inputs, _t) = scan_workflow_data_runs_pool(&pool, wf.id).await.unwrap();
            sort_runs_ascending(&mut inputs);
            let declared: Vec<String> = Vec::new();
            let flat = data_query::flatten_runs(&inputs, &declared);
            let contributing: Vec<&data_query::FlatRun> =
                flat.iter().filter(|r| !r.records.is_empty()).collect();
            assert_eq!(line["run_count"], json!(contributing.len()));
            let last: Option<String> = contributing.iter().filter_map(|r| r.run_at.clone()).max();
            assert_eq!(line["last_data_at"], json!(last));
            assert_eq!(line["last_delta"], picker_delta(&flat, &declared));

            // A workflow whose only runs flatten to zero rows never lists.
            let empty =
                workflows::insert(&pool, &NewWorkflow { name: "empty".into(), ..Default::default() })
                    .await
                    .unwrap();
            seed_run(&pool, empty.id, "2026-08-19T10:00:00Z", json!({"dry_run": true})).await;
            assert!(fast_picker_line(&pool, &empty).await.unwrap().is_none());
        }

        #[tokio::test]
        async fn facets_are_exact_under_the_budget_and_flagged_past_it() {
            let pool = pool().await;
            let wf = seed_workflow(&pool).await;
            let declared: Vec<String> = Vec::new();
            let (inputs, _t) = scan_workflow_data_runs_pool(&pool, wf.id).await.unwrap();
            let (columns, rows) = data_query::flatten(&inputs, &declared, false);
            let body = fast_workflow_data_facets(&pool, &wf, &declared).await.unwrap();
            assert_eq!(body["sampled"], json!(false));
            assert_eq!(body["columns"], json!(columns));
            assert_eq!(body["row_count"], json!(rows.len()));
            assert_eq!(body["total_rows"], json!(rows.len()));
            assert_eq!(body["facets"], data_query::compute_facets(&columns, &rows));
        }
    }

    // ------------------------------------------------------------------
    // Relayed cloud-export headers are pinned, not passed through.
    // ------------------------------------------------------------------
    #[cfg(feature = "cloud")]
    mod relayed_export_headers {
        use super::super::{export_content_type, sanitize_content_disposition};

        #[test]
        fn content_type_is_allowlisted() {
            assert_eq!(export_content_type(Some("text/csv")), "text/csv; charset=utf-8");
            assert_eq!(
                export_content_type(Some("text/CSV; charset=iso-8859-1")),
                "text/csv; charset=utf-8",
                "only the base type is honoured; upstream parameters are dropped"
            );
            assert_eq!(
                export_content_type(Some("application/json")),
                "application/json; charset=utf-8"
            );

            // Anything that could RENDER, or that we do not recognise, becomes opaque.
            for hostile in [
                "text/html",
                "text/html; charset=utf-8",
                "image/svg+xml",
                "application/xhtml+xml",
                "text/csv, text/html",
                "",
                "  ",
            ] {
                assert_eq!(
                    export_content_type(Some(hostile)),
                    "application/octet-stream",
                    "{hostile} was passed through"
                );
            }
            assert_eq!(export_content_type(None), "application/octet-stream");
        }

        #[test]
        fn content_disposition_is_forced_to_attachment_and_stripped_of_control_chars() {
            assert_eq!(
                sanitize_content_disposition(Some("attachment; filename=\"crawl.csv\"")),
                "attachment; filename=\"crawl.csv\""
            );
            // `inline` would render in the browser; the filename is kept, the disposition is not.
            assert_eq!(
                sanitize_content_disposition(Some("inline; filename=\"x.csv\"")),
                "attachment; filename=\"x.csv\""
            );
            assert_eq!(sanitize_content_disposition(Some("inline")), "attachment; filename=\"export\"");

            // Header splitting: CR/LF must not survive into the response at all.
            let out = sanitize_content_disposition(Some(
                "attachment; filename=\"a.csv\"\r\nSet-Cookie: x=1",
            ));
            assert!(!out.contains('\r') && !out.contains('\n'), "{out}");
            assert!(out.starts_with("attachment;"));

            assert_eq!(sanitize_content_disposition(None), "attachment; filename=\"export\"");
            assert_eq!(sanitize_content_disposition(Some("   ")), "attachment; filename=\"export\"");
        }
    }

    // ------------------------------------------------------------------
    // Integration: the Data surface aggregates SUCCESSFUL runs only.
    // ------------------------------------------------------------------
    mod integration {
        use crate::local::config::{self, LocalConfig};
        use crate::local::server::AppState;
        use crate::local::store::runs::{complete, fail, insert, NewRun};
        use crate::local::store::workflows::{self, NewWorkflow};
        use crate::local::{db, engine, vault};
        use axum::body::{to_bytes, Body};
        use axum::http::Request;
        use axum::Router;
        use serde_json::Value;
        use std::sync::Arc;
        use tower::ServiceExt;

        /// A minimal `AppState` over a fresh encrypted DB with the (registry-less) `StubEngine` —
        /// the data handlers read persisted rows + run the pure query engine, no live engine needed.
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

        fn app(st: AppState) -> Router {
            super::super::router().with_state(st)
        }

        /// The workflow data table (and the workflow picker) must include a SUCCESSFUL run's
        /// extracted data and EXCLUDE a failed run's partial payload — the "failed run data" noise.
        #[tokio::test]
        async fn failed_run_data_is_excluded_from_the_table() {
            let st = state().await;
            let wf = workflows::insert(&st.db, &NewWorkflow { name: "scrape".into(), ..Default::default() })
                .await
                .unwrap();

            // A successful run that extracted a real record.
            let ok = insert(&st.db, &NewRun { workflow_id: Some(wf.id), ..Default::default() }).await.unwrap();
            complete(&st.db, ok.id, Some(r#"{"success":true,"extracted_data":{"title":"good"}}"#), Some(5))
                .await
                .unwrap();
            // A run that scraped a partial record, then FAILED — must not appear on the Data surface.
            let bad = insert(&st.db, &NewRun { workflow_id: Some(wf.id), ..Default::default() }).await.unwrap();
            complete(&st.db, bad.id, Some(r#"{"extracted_data":{"title":"partial-junk"}}"#), Some(6))
                .await
                .unwrap();
            fail(&st.db, bad.id, "failed", Some("boom"), Some("recipe"), Some(6)).await.unwrap();

            // Workflow data table → only the successful run's row.
            let resp = app(st.clone())
                .oneshot(
                    Request::builder()
                        .uri(format!("/v1/workflows/{}/data", wf.id))
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(resp.status(), 200);
            let body = to_bytes(resp.into_body(), 64 * 1024).await.unwrap();
            let v: Value = serde_json::from_slice(&body).unwrap();
            assert_eq!(v["total"], 1, "only the successful run's record is in the table");
            assert_eq!(v["scanned_runs"], 1, "only successful data-bearing runs are scanned");
            assert_eq!(v["rows"][0]["status"], "success");
            assert_eq!(v["rows"][0]["fields"]["title"], "good");
            let blob = String::from_utf8_lossy(&body);
            assert!(!blob.contains("partial-junk"), "failed run's data leaked into the table");

            // Global picker (/v1/data) → the workflow's run_count reflects successful runs only.
            let resp = app(st)
                .oneshot(Request::builder().uri("/v1/data").body(Body::empty()).unwrap())
                .await
                .unwrap();
            let body = to_bytes(resp.into_body(), 64 * 1024).await.unwrap();
            let v: Value = serde_json::from_slice(&body).unwrap();
            let wfs = v["workflows"].as_array().unwrap();
            assert_eq!(wfs.len(), 1);
            assert_eq!(wfs[0]["workflow_id"], wf.id);
            assert_eq!(wfs[0]["run_count"], 1, "picker counts successful data runs only");
        }

        /// `POST /v1/workflows/:id/data/preview` returns a small `{ columns, rows }` sample, capped at
        /// `limit`, and NEVER leaks the internal envelope (cookies/auth_session/...) or secret-shaped
        /// keys — the redaction is the security boundary for this new surface.
        #[tokio::test]
        async fn preview_is_capped_and_redacted() {
            let st = state().await;
            let wf = workflows::insert(&st.db, &NewWorkflow { name: "scrape".into(), ..Default::default() })
                .await
                .unwrap();
            // Three successful runs, each with a legit field + secret/envelope keys that must not leak.
            for i in 0..3 {
                let r = insert(&st.db, &NewRun { workflow_id: Some(wf.id), ..Default::default() })
                    .await
                    .unwrap();
                let payload = format!(
                    r#"{{"success":true,"extracted_data":{{"title":"item-{i}","password":"hunter2","cookies":"SESSION=abc","auth_session":{{"t":"x"}}}}}}"#
                );
                complete(&st.db, r.id, Some(&payload), Some(5)).await.unwrap();
            }

            let resp = app(st)
                .oneshot(
                    Request::builder()
                        .method("POST")
                        .uri(format!("/v1/workflows/{}/data/preview", wf.id))
                        .header("content-type", "application/json")
                        .body(Body::from(r#"{"limit":2}"#))
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(resp.status(), 200);
            let body = to_bytes(resp.into_body(), 64 * 1024).await.unwrap();
            let v: Value = serde_json::from_slice(&body).unwrap();

            assert_eq!(v["rows"].as_array().unwrap().len(), 2, "capped at limit");
            let cols: Vec<&str> = v["columns"].as_array().unwrap().iter().filter_map(|c| c.as_str()).collect();
            assert!(cols.contains(&"title"), "the real field is present");

            let blob = String::from_utf8_lossy(&body);
            assert!(!blob.contains("hunter2"), "secret value must not leak");
            assert!(!blob.contains("password"), "secret key must not leak");
            assert!(!blob.contains("cookies"), "envelope key must not leak");
            assert!(!blob.contains("auth_session"), "session envelope must not leak");
        }

        /// A workflow whose only SUCCESSFUL run produced an empty / meta-only `extracted_data`
        /// (flattens to zero rows — the "chatgpt: 2 runs → No extracted data yet" case) is omitted
        /// from the picker, instead of padding it with an entry whose table is empty.
        #[tokio::test]
        async fn picker_omits_workflow_with_zero_materialized_rows() {
            let st = state().await;
            let wf = workflows::insert(&st.db, &NewWorkflow { name: "chatgpt".into(), ..Default::default() })
                .await
                .unwrap();
            // Two successful runs whose extracted_data flattens to nothing (empty object / meta-only).
            let a = insert(&st.db, &NewRun { workflow_id: Some(wf.id), ..Default::default() }).await.unwrap();
            complete(&st.db, a.id, Some(r#"{"success":true,"extracted_data":{}}"#), Some(5)).await.unwrap();
            let b = insert(&st.db, &NewRun { workflow_id: Some(wf.id), ..Default::default() }).await.unwrap();
            complete(&st.db, b.id, Some(r#"{"success":true,"extracted_data":{"_error_context":{"x":1}}}"#), Some(5))
                .await
                .unwrap();

            let resp = app(st)
                .oneshot(Request::builder().uri("/v1/data").body(Body::empty()).unwrap())
                .await
                .unwrap();
            let body = to_bytes(resp.into_body(), 64 * 1024).await.unwrap();
            let v: Value = serde_json::from_slice(&body).unwrap();
            assert_eq!(
                v["workflows"].as_array().unwrap().len(),
                0,
                "a workflow whose runs flatten to zero rows must not appear in the picker",
            );
        }

        /// A workflow whose ONLY data-bearing run failed is omitted from the picker entirely.
        #[tokio::test]
        async fn picker_omits_workflow_with_only_failed_data() {
            let st = state().await;
            let wf = workflows::insert(&st.db, &NewWorkflow { name: "flaky".into(), ..Default::default() })
                .await
                .unwrap();
            let bad = insert(&st.db, &NewRun { workflow_id: Some(wf.id), ..Default::default() }).await.unwrap();
            complete(&st.db, bad.id, Some(r#"{"extracted_data":{"title":"x"}}"#), Some(6)).await.unwrap();
            fail(&st.db, bad.id, "failed", Some("boom"), Some("recipe"), Some(6)).await.unwrap();

            let resp = app(st)
                .oneshot(Request::builder().uri("/v1/data").body(Body::empty()).unwrap())
                .await
                .unwrap();
            let body = to_bytes(resp.into_body(), 64 * 1024).await.unwrap();
            let v: Value = serde_json::from_slice(&body).unwrap();
            assert_eq!(v["workflows"].as_array().unwrap().len(), 0, "no successful data → not listed");
        }

        /// A workflow parked inactive (`is_active=0`) by a legacy soft-delete but still owning a
        /// SUCCESSFUL data-bearing run MUST appear in the picker — active state is not a filter for
        /// the Data explorer, which surfaces data that exists (this is the "my data disappeared" fix).
        #[tokio::test]
        async fn picker_includes_inactive_workflow_that_has_data() {
            let st = state().await;
            let wf = workflows::insert(&st.db, &NewWorkflow { name: "archived".into(), ..Default::default() })
                .await
                .unwrap();
            let ok = insert(&st.db, &NewRun { workflow_id: Some(wf.id), ..Default::default() }).await.unwrap();
            complete(&st.db, ok.id, Some(r#"{"success":true,"extracted_data":{"title":"kept"}}"#), Some(5))
                .await
                .unwrap();
            // Park it inactive (simulates a legacy soft-deleted row still in the DB).
            workflows::update(
                &st.db,
                wf.id,
                &workflows::WorkflowUpdate { is_active: Some(0), ..Default::default() },
            )
            .await
            .unwrap();

            let resp = app(st)
                .oneshot(Request::builder().uri("/v1/data").body(Body::empty()).unwrap())
                .await
                .unwrap();
            let body = to_bytes(resp.into_body(), 64 * 1024).await.unwrap();
            let v: Value = serde_json::from_slice(&body).unwrap();
            let wfs = v["workflows"].as_array().unwrap();
            assert_eq!(wfs.len(), 1, "an inactive workflow with data is still listed");
            assert_eq!(wfs[0]["workflow_id"], wf.id);
            assert_eq!(wfs[0]["run_count"], 1);
        }

        /// Spec 3.1: a multi-list extraction tags each lens row with its originating list key
        /// (`lineage.source`), the lens response carries a `sources` bucket map (pre-filter),
        /// and `?source=` narrows the rowset server-side. view=all stays schema-frozen.
        #[tokio::test]
        async fn lens_rows_carry_source_and_source_param_filters() {
            let st = state().await;
            let wf = workflows::insert(&st.db, &NewWorkflow { name: "multi".into(), ..Default::default() })
                .await
                .unwrap();
            let r = insert(&st.db, &NewRun { workflow_id: Some(wf.id), ..Default::default() }).await.unwrap();
            complete(
                &st.db,
                r.id,
                Some(r#"{"success":true,"extracted_data":{"workflows":[{"name":"A"}],"targets":[{"url":"u1"},{"url":"u2"}]}}"#),
                Some(5),
            )
            .await
            .unwrap();

            // view=latest: every row is source-tagged; the envelope buckets by list key.
            let resp = app(st.clone())
                .oneshot(
                    Request::builder()
                        .uri(format!("/v1/workflows/{}/data?view=latest", wf.id))
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(resp.status(), 200);
            let body = to_bytes(resp.into_body(), 64 * 1024).await.unwrap();
            let v: Value = serde_json::from_slice(&body).unwrap();
            assert_eq!(v["sources"], serde_json::json!({ "targets": 2, "workflows": 1 }));
            let tagged: Vec<&str> = v["rows"]
                .as_array()
                .unwrap()
                .iter()
                .map(|r| r["lineage"]["source"].as_str().unwrap())
                .collect();
            assert_eq!(tagged.iter().filter(|s| **s == "targets").count(), 2);
            assert_eq!(tagged.iter().filter(|s| **s == "workflows").count(), 1);

            // ?source= filters before pagination; the envelope stays unfiltered.
            let resp = app(st.clone())
                .oneshot(
                    Request::builder()
                        .uri(format!("/v1/workflows/{}/data?view=latest&source=targets", wf.id))
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            let body = to_bytes(resp.into_body(), 64 * 1024).await.unwrap();
            let v: Value = serde_json::from_slice(&body).unwrap();
            assert_eq!(v["total"], 2, "source filter narrows to the targets list");
            assert_eq!(v["sources"], serde_json::json!({ "targets": 2, "workflows": 1 }));

            // view=all stays schema-frozen: no lineage/source/sources keys anywhere.
            let resp = app(st)
                .oneshot(
                    Request::builder()
                        .uri(format!("/v1/workflows/{}/data", wf.id))
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            let body = to_bytes(resp.into_body(), 64 * 1024).await.unwrap();
            let blob = String::from_utf8_lossy(&body);
            assert!(!blob.contains("lineage"), "view=all must not carry lineage");
            assert!(!blob.contains("\"sources\""), "view=all must not carry sources");
        }

        /// The shared lens-param 400s byte-match the python engines (spec 1.5(1)): unknown view,
        /// `view!=all` + `collection` (the daemon has no server-side collection pivot, but the
        /// pinned rejection must still hold), and `view=run` without `run_id`.
        #[tokio::test]
        async fn lens_param_400s_match_the_python_engines() {
            let st = state().await;
            let wf = workflows::insert(&st.db, &NewWorkflow { name: "guard".into(), ..Default::default() })
                .await
                .unwrap();

            let detail_of = |uri: String, st: AppState| async move {
                let resp = app(st)
                    .oneshot(Request::builder().uri(uri).body(Body::empty()).unwrap())
                    .await
                    .unwrap();
                let status = resp.status();
                let body = to_bytes(resp.into_body(), 64 * 1024).await.unwrap();
                let v: Value = serde_json::from_slice(&body).unwrap();
                (status, v["detail"].as_str().unwrap_or_default().to_string())
            };

            let (status, detail) =
                detail_of(format!("/v1/workflows/{}/data?view=bogus", wf.id), st.clone()).await;
            assert_eq!(status, 400);
            assert_eq!(detail, "view must be one of: latest, run, all");

            let (status, detail) = detail_of(
                format!("/v1/workflows/{}/data?view=latest&collection=posts.items", wf.id),
                st.clone(),
            )
            .await;
            assert_eq!(status, 400);
            assert_eq!(detail, "change tracking operates on top-level records");

            let (status, detail) =
                detail_of(format!("/v1/workflows/{}/data?view=run", wf.id), st.clone()).await;
            assert_eq!(status, 400);
            assert_eq!(detail, "run_id is required when view=run");

            // The facets + export endpoints run the same validation.
            let (status, detail) = detail_of(
                format!("/v1/workflows/{}/data/facets?view=run&collection=x", wf.id),
                st.clone(),
            )
            .await;
            assert_eq!(status, 400);
            assert_eq!(detail, "change tracking operates on top-level records");
            let (status, detail) =
                detail_of(format!("/v1/workflows/{}/data/export?view=nope", wf.id), st).await;
            assert_eq!(status, 400);
            assert_eq!(detail, "view must be one of: latest, run, all");
        }

        /// `view=run` row lineage carries WALK-TIME values (python `run_views` parity): viewing an
        /// old snapshot must not leak later change-points into `versions`, and `last_seen_at` is
        /// the snapshot's own run_at — not the end-of-chain values.
        #[tokio::test]
        async fn run_view_lineage_is_walk_time_not_end_of_chain() {
            let st = state().await;
            let wf = workflows::insert(&st.db, &NewWorkflow { name: "walk".into(), ..Default::default() })
                .await
                .unwrap();
            // Two snapshots of the same record (id=1) whose price changes in the second.
            let r1 = insert(&st.db, &NewRun { workflow_id: Some(wf.id), ..Default::default() }).await.unwrap();
            complete(&st.db, r1.id, Some(r#"{"success":true,"extracted_data":{"id":1,"price":10}}"#), Some(5))
                .await
                .unwrap();
            let r2 = insert(&st.db, &NewRun { workflow_id: Some(wf.id), ..Default::default() }).await.unwrap();
            complete(&st.db, r2.id, Some(r#"{"success":true,"extracted_data":{"id":1,"price":12}}"#), Some(5))
                .await
                .unwrap();

            let resp = app(st)
                .oneshot(
                    Request::builder()
                        .uri(format!("/v1/workflows/{}/data?view=run&run_id={}&key=id", wf.id, r1.id))
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(resp.status(), 200);
            let body = to_bytes(resp.into_body(), 64 * 1024).await.unwrap();
            let v: Value = serde_json::from_slice(&body).unwrap();
            let row = &v["rows"][0];
            assert_eq!(
                row["lineage"]["versions"], 1,
                "an old snapshot's versions must not count the later change-point"
            );
            assert_eq!(
                row["lineage"]["last_seen_at"], row["run_at"],
                "a snapshot row's last_seen_at is that snapshot's own run_at"
            );
        }

        /// The snapshot export query (`format=…&view=run&run_id=N`) must deserialize: numeric
        /// `run_id` used to sit behind a `#[serde(flatten)]` wrapper, which serde_urlencoded
        /// rejects ("invalid type: string, expected i64") — 400ing every By-date export.
        #[tokio::test]
        async fn run_view_export_query_deserializes() {
            let st = state().await;
            let wf = workflows::insert(&st.db, &NewWorkflow { name: "exp".into(), ..Default::default() })
                .await
                .unwrap();
            let r1 = insert(&st.db, &NewRun { workflow_id: Some(wf.id), ..Default::default() }).await.unwrap();
            complete(&st.db, r1.id, Some(r#"{"success":true,"extracted_data":{"id":1,"price":10}}"#), Some(5))
                .await
                .unwrap();
            let r2 = insert(&st.db, &NewRun { workflow_id: Some(wf.id), ..Default::default() }).await.unwrap();
            complete(&st.db, r2.id, Some(r#"{"success":true,"extracted_data":{"id":1,"price":12}}"#), Some(5))
                .await
                .unwrap();

            let resp = app(st)
                .oneshot(
                    Request::builder()
                        .uri(format!(
                            "/v1/workflows/{}/data/export?format=csv&view=run&run_id={}&key=id",
                            wf.id, r2.id
                        ))
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(resp.status(), 200);
            let disposition = resp
                .headers()
                .get(axum::http::header::CONTENT_DISPOSITION)
                .and_then(|h| h.to_str().ok())
                .unwrap_or_default()
                .to_string();
            assert!(disposition.contains(".csv"), "snapshot export must serve a CSV attachment");
        }
    }

    #[test]
    fn declared_output_fields_unions_function_outputs() {
        let mut wf = sample_workflow();
        wf.functions = Some(
            json!([
                {"name": "list", "output_fields": ["title", "price"]},
                {"name": "detail", "output_fields": [{"name": "sku"}, "price"]}
            ])
            .to_string(),
        );
        let fields = declared_output_fields(&wf);
        assert_eq!(fields, vec!["title", "price", "sku", "price"]);
    }

    #[test]
    fn declared_output_fields_empty_when_no_functions() {
        let wf = sample_workflow();
        assert!(declared_output_fields(&wf).is_empty());
    }

    #[test]
    fn col_filter_parse_splits_on_first_colon() {
        let m = parse_col_filters(&["city:Paris".into(), "url:https://x".into(), "bad".into()]);
        assert_eq!(m.get("city").map(String::as_str), Some("Paris"));
        assert_eq!(m.get("url").map(String::as_str), Some("https://x"));
        assert_eq!(m.len(), 2);
    }

    #[test]
    fn structured_filter_parse_tolerates_garbage() {
        assert!(parse_structured_filters(Some("not json")).is_empty());
        assert!(parse_structured_filters(Some("{}")).is_empty());
        let cs = parse_structured_filters(Some(r#"[{"col":"price","op":"between","min":1,"max":9}]"#));
        assert_eq!(cs.len(), 1);
        assert_eq!(cs[0].col, "price");
    }

    #[test]
    fn export_filename_is_sanitized() {
        assert_eq!(safe_export_filename("My Cool / Workflow!!"), "My-Cool-Workflow");
        assert_eq!(safe_export_filename("   "), "workflow");
        assert_eq!(safe_export_filename("ok_name-1.2"), "ok_name-1.2");
    }

    fn sample_workflow() -> workflows::Workflow {
        workflows::Workflow {
            id: 1,
            name: "wf".into(),
            description: None,
            workflow_type: "recorded".into(),
            steps: "[]".into(),
            raw_replay: None,
            form_data: None,
            exit_condition: None,
            input_rules: None,
            api_functions: None,
            streaming_config: None,
            functions: None,
            credentials_encrypted: None,
            entry_url: None,
            timeout_ms: 0,
            retry_count: 0,
            headless: 1,
            fast_mode: 0,
            is_active: 1,
            is_verified: 0,
            schedule_enabled: 0,
            schedule_interval_ms: None,
            schedule_kind: None,
            schedule_time: None,
            schedule_days: None,
            schedule_tz: None,
            last_scheduled_at: None,
            next_scheduled_at: None,
            session_persistence: 0,
            session_ttl_seconds: None,
            login_url_patterns: None,
            relogin_max_retries: 0,
            http_capable: -1,
            auth_config: None,
            recorded_session_encrypted: None,
            recorded_session_captured_at: None,
            default_persona_id: None,
            estimated_duration_ms: None,
            usage_count: 0,
            total_run_count: 0,
            total_failure_count: 0,
            consecutive_failures: 0,
            last_run_at: None,
            last_run_status: None,
            last_run_duration_ms: None,
            last_run_has_extracted_data: None,
            last_failure_at: None,
            last_failure_error: None,
            cloud_callable: 0,
            execution_target: None,
            ai_repair_enabled: 0,
            last_repaired_at: None,
            marketplace_slug: None,
            created_at: "2026-06-01T00:00:00Z".into(),
            updated_at: None,
        }
    }
}
