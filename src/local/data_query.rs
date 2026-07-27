//! Aggregate the data a workflow's runs extracted into one sortable/searchable table.
//!
//! Pure, dependency-free port of the cloud query engine
//! (the cloud backend's `extracted_data_table` service) onto `serde_json::Value`. Every run
//! persists what it scraped under the `extracted_data` key of its `result_data`; this
//! module flattens the runs of a workflow into a uniform `(columns, rows)` table the UI
//! can render as a grid and export, then offers filter / sort / paginate / facets over it.
//!
//! A run's `extracted_data` is either a single record (one row) or a LIST of records
//! (the canonical list/detail/pagination scraper output — one row per item). Each emitted
//! row carries the run it came from (run id, when, status) alongside the extracted fields,
//! so any value traces back to its run.
//!
//! SECURITY-CRITICAL: this is the tenant-facing DATA surface, so the redaction here is
//! load-bearing, not cosmetic. The internal response/session envelope (raw_html, cookies,
//! auth_session, html, screenshots, …) and secret-shaped run inputs (password/token/otp/
//! secret/cvv/…) must NEVER surface as a column or a cell. The heuristics below are ported
//! faithfully from the cloud engine; the unit tests assert the envelope/secret keys can't
//! leak. This module is pure: it operates on already-parsed JSON and never touches the DB,
//! the vault, or the network, and it never logs values.

use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};

// ---------------------------------------------------------------------------
// Key classification — what is user-facing extracted data vs. internal envelope.
// ---------------------------------------------------------------------------

/// Keys under `result_data` (besides `extracted_data`) that may carry declared fields at
/// the TOP level rather than nested. We fall back to these only when there is no usable
/// `extracted_data` — and we drop them before the fallback so the envelope never leaks.
const RESERVED_TOPLEVEL: &[&str] = &[
    "extracted_data",
    "steps",
    "steps_completed",
    "screenshots",
    "success",
    "error",
    "auth_session",
    "needs_reassignment",
    "ai_session_id",
    "workflow_id",
];

/// Execution metadata / flags the engine injects INTO extracted_data — NOT real data.
const META_FLAG_KEYS: &[&str] = &[
    "dry_run",
    "stopped_before_commit",
    "captcha_info",
    "error_context",
];

/// Clearly-internal / response-envelope / execution-control keys that are NOT user-facing
/// extracted data. Hidden even when a workflow declares no output schema, so the table never
/// surfaces the raw response, session/capture plumbing, screenshots, cookies, or the engine's
/// repair/captcha/auth control fields. This set IS the security boundary — keep it broad.
const INTERNAL_KEYS: &[&str] = &[
    // session / capture plumbing
    "auth_session",
    "session_state",
    "session_storage",
    "local_storage",
    "localstorage",
    "cookies",
    "screenshot",
    "screenshots",
    "fingerprint",
    "headers",
    // raw response envelope
    "raw_response",
    "raw_html",
    "response",
    "response_body",
    "responsebody",
    "raw",
    "raw_data",
    "html",
    "page_html",
    "page_source",
    "har",
    "network_log",
    "console_log",
    "step_results",
    // execution-control flags the engine merges into the result
    "session_expired",
    "needs_reassignment",
    "reassignment_reason",
    "auth_failed",
    "login_success",
    "logged_in",
    "is_logged_in",
    "stopped_before_commit",
];

/// Key PREFIXES marking engine control/metadata (ai_repair_attempted, captcha_detected, …).
const META_PREFIXES: &[&str] = &["ai_repair", "captcha"];

/// Generic wrapper keys an extractor may nest the real records under (evaluate_js stores its
/// value under output_name, default "extracted_data"). When the cleaned payload is just one of
/// these wrapping a dict, unwrap to the inner record.
const WRAPPER_KEYS: &[&str] = &[
    "extracted_data",
    "result",
    "results",
    "data",
    "items",
    "records",
    "rows",
    "output",
    "outputs",
    "extracted",
    "values",
];

/// Underscore-prefixed (e.g. `_error_context`), a known flag/internal key, or a control prefix
/// (`ai_repair_*`, `captcha_*`) — none are user-facing extracted data.
pub fn is_meta_key(k: &str) -> bool {
    if k.starts_with('_') {
        return true;
    }
    let kl = k.to_ascii_lowercase();
    if META_FLAG_KEYS.contains(&kl.as_str()) || INTERNAL_KEYS.contains(&kl.as_str()) {
        return true;
    }
    META_PREFIXES.iter().any(|p| kl.starts_with(p))
}

/// Recursively drop every meta/internal key from a JSON value — `is_meta_key` is applied at EVERY
/// depth, recursing through arrays. A nested internal envelope (e.g.
/// `{"profile":{"cookies":..,"auth_session":..}}`) must NOT survive into a cell / CSV / JSON export
/// just because it isn't a top-level key (audit finding: redaction was top-level only).
fn strip_meta_value(v: &Value) -> Value {
    match v {
        Value::Object(obj) => Value::Object(
            obj.iter()
                .filter(|(k, _)| !is_meta_key(k))
                .map(|(k, val)| (k.clone(), strip_meta_value(val)))
                .collect(),
        ),
        Value::Array(arr) => Value::Array(arr.iter().map(strip_meta_value).collect()),
        other => other.clone(),
    }
}

/// Drop every meta/internal key from a JSON object, recursively (see [`strip_meta_value`]).
fn strip_meta(obj: &Map<String, Value>) -> Map<String, Value> {
    match strip_meta_value(&Value::Object(obj.clone())) {
        Value::Object(m) => m,
        _ => Map::new(),
    }
}

// ---------------------------------------------------------------------------
// Secret-input redaction — surfacing run inputs as columns must NEVER leak creds.
// ---------------------------------------------------------------------------

/// Namespace for run-input columns so they never collide with an extracted field of the same
/// name, and so a caller can target them explicitly in filters/sort.
pub const INPUT_PREFIX: &str = "input.";

/// `trigger_context` keys that may carry the run's input/form values, in priority order. Only
/// object values are accepted; the first non-empty one wins.
const INPUT_CTX_KEYS: &[&str] = &["_queued_form_data", "merged_form_data", "form_data", "inputs"];

/// Input KEY fragments whose values are secret/sensitive and must never be surfaced as a
/// filterable column. Matched case-insensitively as a substring (mirrors the cloud regex
/// `(password|passwd|pwd|secret|token|api[_-]?key|apikey|otp|cvv|cvc|ssn|private[_-]?key|
/// credential|card[_-]?number|\bpan\b)`). Hand-rolled to keep the module regex-free / ReDoS-free.
fn is_secret_input_key(key: &str) -> bool {
    let k = key.to_ascii_lowercase();
    const NEEDLES: &[&str] = &[
        "password",
        "passwd",
        "pwd",
        "secret",
        "token",
        "apikey",
        "api_key",
        "api-key",
        "otp",
        "cvv",
        "cvc",
        "ssn",
        "private_key",
        "private-key",
        "privatekey",
        "credential",
        "card_number",
        "card-number",
        "cardnumber",
    ];
    if NEEDLES.iter().any(|n| k.contains(n)) {
        return true;
    }
    // `\bpan\b` — "pan" as a whole word (word chars are [A-Za-z0-9_]).
    is_word(&k, "pan")
}

/// Whole-word substring match: `needle` surrounded by non-word chars (mirrors `\bword\b`).
fn is_word(haystack: &str, needle: &str) -> bool {
    let is_word_char = |c: char| c.is_ascii_alphanumeric() || c == '_';
    let bytes = haystack.as_bytes();
    let mut start = 0;
    while let Some(rel) = haystack[start..].find(needle) {
        let i = start + rel;
        let j = i + needle.len();
        let before_ok = i == 0 || !is_word_char(bytes[i - 1] as char);
        let after_ok = j >= bytes.len() || !is_word_char(bytes[j] as char);
        if before_ok && after_ok {
            return true;
        }
        start = i + 1;
    }
    false
}

/// Drop secret-shaped input keys (password/token/otp/…) so surfacing run inputs as columns
/// can't leak credentials. Keeps only string-keyed entries (all JSON object keys are strings).
pub fn redact_inputs(inputs: &Map<String, Value>) -> Map<String, Value> {
    inputs
        .iter()
        .filter(|(k, _)| !is_secret_input_key(k))
        .map(|(k, v)| (k.clone(), v.clone()))
        .collect()
}

/// Recursively drop secret-shaped keys (password/token/otp/…) from a JSON value at EVERY depth.
/// Used ONLY on the no-declared-output fallback, where records are surfaced unprojected and a
/// nested secret-named field (e.g. `{"login":{"password":..}}`) would otherwise leak into the
/// table/CSV/JSON. Workflows that DECLARE output fields opt those fields in explicitly, so this is
/// not applied to the projected path.
fn redact_secret_keys_value(v: &Value) -> Value {
    match v {
        Value::Object(obj) => Value::Object(
            obj.iter()
                .filter(|(k, _)| !is_secret_input_key(k))
                .map(|(k, val)| (k.clone(), redact_secret_keys_value(val)))
                .collect(),
        ),
        Value::Array(arr) => Value::Array(arr.iter().map(redact_secret_keys_value).collect()),
        other => other.clone(),
    }
}

/// Object-level [`redact_secret_keys_value`].
fn redact_secret_keys(obj: &Map<String, Value>) -> Map<String, Value> {
    match redact_secret_keys_value(&Value::Object(obj.clone())) {
        Value::Object(m) => m,
        _ => Map::new(),
    }
}

/// The input/form values a run was dispatched with, parsed from its `trigger_context` JSON
/// (see `INPUT_CTX_KEYS`), or `{}` when none are recorded. NOT yet redacted — call
/// `redact_inputs` before exposing.
fn task_inputs(trigger_context: &Value) -> Map<String, Value> {
    let ctx = match trigger_context.as_object() {
        Some(o) => o,
        None => return Map::new(),
    };
    for k in INPUT_CTX_KEYS {
        if let Some(Value::Object(v)) = ctx.get(*k) {
            if !v.is_empty() {
                return v.clone();
            }
        }
    }
    Map::new()
}

// ---------------------------------------------------------------------------
// Record extraction — turn a run's result_data into the clean record-dicts to show.
// ---------------------------------------------------------------------------

/// True for JSON scalars (null/string/number/bool) — the cell types a table row may hold.
fn is_scalar(v: &Value) -> bool {
    !matches!(v, Value::Object(_) | Value::Array(_))
}

/// Table-shape detection (spec 1.1a): a list of ≥2 all-scalar arrays whose first row is a
/// plausible header — all non-empty strings, ≥50% non-numeric-looking, distinct after trimming —
/// and ≥90% of the remaining rows have exactly the header's cell count. Returns the header names.
pub(crate) fn detect_table(items: &[Value]) -> Option<Vec<String>> {
    if items.len() < 2 {
        return None;
    }
    if !items
        .iter()
        .all(|r| matches!(r, Value::Array(cells) if cells.iter().all(is_scalar)))
    {
        return None;
    }
    let header = items[0].as_array().expect("checked all-arrays above");
    if header.is_empty() {
        return None;
    }
    let mut names: Vec<String> = Vec::with_capacity(header.len());
    for cell in header {
        match cell {
            Value::String(s) if !s.trim().is_empty() => names.push(s.clone()),
            _ => return None,
        }
    }
    let non_numeric = names.iter().filter(|c| !looks_numeric(c)).count();
    if non_numeric * 2 < names.len() {
        return None;
    }
    let trimmed: BTreeSet<&str> = names.iter().map(|c| c.trim()).collect();
    if trimmed.len() != names.len() {
        return None;
    }
    let rest = &items[1..];
    let same_len = rest
        .iter()
        .filter(|r| r.as_array().map(|a| a.len()) == Some(names.len()))
        .count();
    if same_len * 10 < rest.len() * 9 {
        return None;
    }
    Some(names)
}

/// A list value → `(record_index, fields)` pairs. record_index = the STORED slot index: a
/// header-keyed table's first data row is slot 1 (the header at slot 0 is never emitted); every
/// other shape indexes 0-based. Table rows longer than the header are truncated, shorter padded
/// with null.
fn coerce_list(items: &[Value]) -> Vec<(usize, Map<String, Value>)> {
    if let Some(header) = detect_table(items) {
        return items[1..]
            .iter()
            .enumerate()
            .map(|(i, row)| {
                let cells = row.as_array().expect("table rows are arrays");
                let mut rec = Map::new();
                for (j, name) in header.iter().enumerate() {
                    rec.insert(name.clone(), cells.get(j).cloned().unwrap_or(Value::Null));
                }
                (i + 1, rec)
            })
            .collect();
    }
    // All-arrays-of-scalars but the header test failed → col_N records, each row's own length.
    if !items.is_empty()
        && items
            .iter()
            .all(|r| matches!(r, Value::Array(cells) if cells.iter().all(is_scalar)))
    {
        return items
            .iter()
            .enumerate()
            .map(|(i, row)| {
                let cells = row.as_array().expect("checked all-arrays above");
                let mut rec = Map::new();
                for (j, c) in cells.iter().enumerate() {
                    rec.insert(format!("col_{}", j + 1), c.clone());
                }
                (i, rec)
            })
            .collect();
    }
    items
        .iter()
        .enumerate()
        .map(|(i, item)| match item {
            Value::Object(o) => (i, o.clone()),
            other => {
                let mut m = Map::new();
                m.insert("value".into(), other.clone());
                (i, m)
            }
        })
        .collect()
}

/// Turn a run's `extracted_data` value into `(records, data_bearing, sources)` where records are
/// `(record_index, fields)` pairs:
///   - a list → one record per item via [`coerce_list`] (stored-slot indices); an EMPTY list is
///     an explicit-empty dataset — 0 records, data-bearing;
///   - an object: EVERY non-empty list-valued key unwraps, in lexicographically SORTED key order
///     (never map order), record_index = a global running counter across the expanded lists;
///     when its list keys are ALL empty → explicit-empty (0 records, data-bearing);
///   - an object whose only real key is a generic WRAPPER over an object → the inner record;
///   - otherwise the object itself is one record. Meta-only / `{}` / scalar payloads yield 0
///     records and are NOT data-bearing.
/// Execution-metadata keys are stripped throughout.
///
/// `sources` maps record_index → the originating list KEY, populated only by the object
/// list-key expansion (spec 3.1); single-list/wrapper/object shapes stay untagged (empty map →
/// source null in the lineage views).
fn coerce_records(ed: &Value) -> (Vec<(usize, Map<String, Value>)>, bool, BTreeMap<usize, String>) {
    match ed {
        Value::Array(items) => {
            if items.is_empty() {
                return (Vec::new(), true, BTreeMap::new()); // explicit empty
            }
            (coerce_list(items), true, BTreeMap::new())
        }
        Value::Object(obj) => {
            let stripped = strip_meta(obj);
            if stripped.is_empty() {
                return (Vec::new(), false, BTreeMap::new()); // meta-only / {} — not data-bearing
            }
            let mut list_keys: Vec<&String> = stripped
                .iter()
                .filter(|(_, v)| v.is_array())
                .map(|(k, _)| k)
                .collect();
            list_keys.sort();
            if !list_keys.is_empty() {
                let nonempty: Vec<&String> = list_keys
                    .into_iter()
                    .filter(|k| {
                        matches!(stripped.get(k.as_str()), Some(Value::Array(a)) if !a.is_empty())
                    })
                    .collect();
                if nonempty.is_empty() {
                    return (Vec::new(), true, BTreeMap::new()); // explicit-empty wrapper
                }
                let mut out: Vec<(usize, Map<String, Value>)> = Vec::new();
                let mut sources: BTreeMap<usize, String> = BTreeMap::new();
                let mut idx = 0usize;
                for k in nonempty {
                    if let Some(Value::Array(items)) = stripped.get(k.as_str()) {
                        for (_, rec) in coerce_list(items) {
                            out.push((idx, rec));
                            sources.insert(idx, k.clone());
                            idx += 1;
                        }
                    }
                }
                return (out, true, sources);
            }
            // A single generic wrapper over an object -> the inner record (response envelope).
            if stripped.len() == 1 {
                let (only_key, only_val) = stripped.iter().next().expect("len checked");
                if let Value::Object(inner) = only_val {
                    if WRAPPER_KEYS.contains(&only_key.to_ascii_lowercase().as_str()) {
                        let inner = strip_meta(inner);
                        return if inner.is_empty() {
                            (Vec::new(), false, BTreeMap::new())
                        } else {
                            (vec![(0, inner)], true, BTreeMap::new())
                        };
                    }
                }
            }
            (vec![(0, stripped)], true, BTreeMap::new())
        }
        _ => (Vec::new(), false, BTreeMap::new()),
    }
}

/// De-dupe declared field names, preserving order.
pub fn declared_columns(declared: &[String]) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for f in declared {
        if !f.is_empty() && !out.contains(f) {
            out.push(f.clone());
        }
    }
    out
}

/// Extract the records a single run produced from its parsed `result_data`, as
/// `(record_index, fields)` pairs plus the run's data-bearing flag (≥1 record after cleaning, or
/// an explicit-empty dataset per spec 1.1c — the flag drives snapshot-chain membership) plus the
/// record_index → originating-list-key map (see [`coerce_records`]; valid post-cleaning because
/// dropped records never renumber their siblings).
///
/// When `extracted_data` is absent/unusable but the run surfaced declared fields at result_data's
/// top level, records are built from those (same coercion). When the workflow DECLARES output
/// fields, each record is projected to ONLY those declared fields — the authoritative definition
/// of "what the workflow extracts" — so the raw response / internal envelope is never surfaced.
fn records_from_result(
    result_data: &Value,
    declared: &[String],
) -> (Vec<(usize, Map<String, Value>)>, bool, BTreeMap<usize, String>) {
    let obj = match result_data.as_object() {
        Some(o) => o,
        None => return (Vec::new(), false, BTreeMap::new()),
    };

    let (mut records, mut data_bearing, mut sources) = match obj.get("extracted_data") {
        Some(ed) => coerce_records(ed),
        None => (Vec::new(), false, BTreeMap::new()),
    };

    if records.is_empty() && !data_bearing {
        // Fallback: data surfaced at result_data's top level rather than under extracted_data.
        // Drop reserved/meta keys, then run the SAME coercion so a top-level list becomes rows.
        // (An explicit-empty extracted_data is already a data-bearing answer — no fallback.)
        let mut top = Map::new();
        for (k, v) in obj.iter() {
            if !is_meta_key(k) && !RESERVED_TOPLEVEL.contains(&k.as_str()) {
                top.insert(k.clone(), v.clone());
            }
        }
        if !top.is_empty() {
            (records, data_bearing, sources) = coerce_records(&Value::Object(top));
        }
    }

    // Final clean: strip metadata, then — when declared — project each record to ONLY the
    // declared fields. Drop empties (each keeps its stored record_index).
    let allow = declared_columns(declared);
    let had_records = !records.is_empty();
    let mut cleaned: Vec<(usize, Map<String, Value>)> = Vec::new();
    for (idx, r) in records {
        let mut c = strip_meta(&r);
        if !allow.is_empty() {
            let projected: Map<String, Value> = allow
                .iter()
                .filter_map(|k| c.get(k).map(|v| (k.clone(), v.clone())))
                .collect();
            c = projected;
        } else {
            // No declared output fields → records are surfaced unprojected. Redact secret-shaped
            // keys at all depths so an extracted field literally named password/token/… can't leak
            // (declared workflows opt their fields in explicitly above).
            c = redact_secret_keys(&c);
        }
        if !c.is_empty() {
            cleaned.push((idx, c));
        }
    }
    // Cleaning can empty a coerced record set — that is NOT an explicit-empty dataset (1.1c), so
    // such a run must not join the snapshot chain.
    let bearing = if cleaned.is_empty() { data_bearing && !had_records } else { true };
    (cleaned, bearing, sources)
}

/// Number of clean data records a run produced — the same row count the Data view shows for the
/// run (a list-extracting run yields one per item; a single-record run yields 1; an empty/absent
/// payload yields 0). Derived from the parsed `result_data`; pass `Value::Null` for "no payload".
/// Used by the runs feed to annotate a row with "N rows extracted" without materializing the table.
pub fn record_count(result_data: &Value) -> usize {
    records_from_result(result_data, &[]).0.len()
}

// ---------------------------------------------------------------------------
// A run, in the shape this engine consumes — already parsed from the DB row.
// ---------------------------------------------------------------------------

/// One run's inputs to the table builder. The caller parses the `runs` row's JSON-TEXT columns
/// (`result_data`, `trigger_context`) into `Value`s once and hands them here.
#[derive(Debug, Clone)]
pub struct RunInput {
    pub run_id: i64,
    pub run_at: Option<String>,
    pub status: Option<String>,
    pub success: Option<bool>,
    pub duration_ms: Option<i64>,
    /// Parsed `result_data` (JSON null when the column was empty/absent).
    pub result_data: Value,
    /// Parsed `trigger_context` (JSON null when the column was empty/absent).
    pub trigger_context: Value,
}

/// A materialized table row: per-run metadata + the projected fields (+ optional run inputs).
#[derive(Debug, Clone)]
pub struct Row {
    pub run_id: i64,
    pub run_at: Option<String>,
    pub status: Option<String>,
    pub success: Option<bool>,
    pub duration_ms: Option<i64>,
    pub record_index: usize,
    pub fields: Map<String, Value>,
    pub inputs: Map<String, Value>,
}

impl Row {
    /// Resolve a sort/search value for a column key — run-meta pseudo-columns, extracted
    /// fields, or (when present) run-input columns addressed as `input.<name>`.
    pub(crate) fn value(&self, key: &str) -> Value {
        match key {
            "run_at" => self.run_at.clone().map(Value::String).unwrap_or(Value::Null),
            "status" => self.status.clone().map(Value::String).unwrap_or(Value::Null),
            "run_id" => Value::from(self.run_id),
            "success" => self.success.map(Value::Bool).unwrap_or(Value::Null),
            "duration_ms" => self.duration_ms.map(Value::from).unwrap_or(Value::Null),
            _ => {
                if let Some(name) = key.strip_prefix(INPUT_PREFIX) {
                    self.inputs.get(name).cloned().unwrap_or(Value::Null)
                } else {
                    self.fields.get(key).cloned().unwrap_or(Value::Null)
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Cell text / typed sort / search.
// ---------------------------------------------------------------------------

/// Flatten a cell value to searchable / CSV text.
pub fn cell_text(value: &Value) -> String {
    match value {
        Value::Null => String::new(),
        Value::String(s) => s.clone(),
        Value::Bool(b) => if *b { "true".into() } else { "false".into() },
        Value::Number(n) => n.to_string(),
        other => serde_json::to_string(other).unwrap_or_else(|_| other.to_string()),
    }
}

fn to_number(v: &Value) -> Option<f64> {
    match v {
        Value::Bool(_) => None,
        Value::Number(n) => n.as_f64(),
        Value::String(s) => s.trim().parse::<f64>().ok(),
        _ => None,
    }
}

fn is_empty_val(v: &Value) -> bool {
    match v {
        Value::Null => true,
        Value::String(s) => s.trim().is_empty(),
        Value::Array(a) => a.is_empty(),
        Value::Object(o) => o.is_empty(),
        _ => false,
    }
}

/// A typed sort key: (bucket, numeric, text) where bucket orders numbers < strings < missing,
/// each ordered naturally. Numeric-looking strings sort as numbers so "12"/"3" order 3 < 12.
#[derive(PartialEq)]
pub(crate) struct SortKey(u8, f64, String);

impl SortKey {
    pub(crate) fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        use std::cmp::Ordering;
        match self.0.cmp(&other.0) {
            Ordering::Equal => {}
            non_eq => return non_eq,
        }
        match self.1.partial_cmp(&other.1) {
            Some(Ordering::Equal) | None => {}
            Some(non_eq) => return non_eq,
        }
        self.2.cmp(&other.2)
    }
}

pub(crate) fn sort_key_for(value: &Value) -> SortKey {
    match value {
        Value::Null => SortKey(3, 0.0, String::new()),
        Value::Bool(b) => SortKey(1, if *b { 1.0 } else { 0.0 }, String::new()),
        Value::Number(n) => SortKey(1, n.as_f64().unwrap_or(0.0), String::new()),
        Value::String(s) => {
            let t = s.trim();
            if t.is_empty() {
                return SortKey(3, 0.0, String::new());
            }
            match t.parse::<f64>() {
                Ok(n) => SortKey(1, n, String::new()),
                Err(_) => SortKey(2, 0.0, t.to_ascii_lowercase()),
            }
        }
        other => SortKey(2, 0.0, cell_text(other).to_ascii_lowercase()),
    }
}

/// Does any field / input value (or the status / run id) contain `needle` (already lowercased)?
pub(crate) fn row_matches(row: &Row, needle: &str) -> bool {
    for v in row.fields.values() {
        if cell_text(v).to_ascii_lowercase().contains(needle) {
            return true;
        }
    }
    for v in row.inputs.values() {
        if cell_text(v).to_ascii_lowercase().contains(needle) {
            return true;
        }
    }
    if row.status.as_deref().unwrap_or("").to_ascii_lowercase().contains(needle) {
        return true;
    }
    if row.run_id.to_string().contains(needle) {
        return true;
    }
    false
}

// ---------------------------------------------------------------------------
// Full-text search helpers (datasets search — mirror the cloud semantics).
// ---------------------------------------------------------------------------

/// Max query terms honored (extra terms dropped — bounds the FTS MATCH string).
const SEARCH_MAX_TERMS: usize = 8;
/// Characters of context on each side of a match in a highlight snippet.
const SEARCH_SNIPPET_RADIUS: usize = 80;

/// Distinct lowercased word terms (Unicode letters/digits). Non-word chars split terms; empties
/// dropped; bounded to `SEARCH_MAX_TERMS`. Mirrors `dataset_search.parse_terms` in the cloud.
pub fn parse_search_terms(q: &str) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for raw in q.split(|c: char| !c.is_alphanumeric()) {
        if raw.is_empty() {
            continue;
        }
        let t = raw.to_lowercase();
        if !out.contains(&t) {
            out.push(t);
        }
        if out.len() >= SEARCH_MAX_TERMS {
            break;
        }
    }
    out
}

/// Build the FTS5 MATCH expression: a prefix query per term, space-joined (FTS5 ANDs them). Terms
/// are already sanitized to alphanumerics, so a bare `term*` can never be parsed as an FTS5
/// operator (AND/OR/NOT/NEAR are uppercase-only) or break the query syntax.
pub fn fts5_match_query(terms: &[String]) -> String {
    terms.iter().map(|t| format!("{t}*")).collect::<Vec<_>>().join(" ")
}

/// Every term must appear as a substring of the row's searchable text — a superset of the FTS
/// index's word-prefix match, so the record filter never drops a genuinely-matching run's rows.
pub fn search_matches_all(row: &Row, terms: &[String]) -> bool {
    terms.iter().all(|t| row_matches(row, t))
}

/// The first field whose text contains a term, as `{field, snippet}` with a trimmed context
/// window around the earliest match. Mirrors the cloud `_highlight`.
pub fn search_highlight(row: &Row, terms: &[String]) -> Value {
    for (name, v) in &row.fields {
        let txt = cell_text(v);
        let low = txt.to_lowercase();
        // The match position must be expressed in CHARACTERS of `low`, never as a byte offset carried
        // over into `txt`. Lowercasing can CHANGE the UTF-8 byte length (`İ` U+0130 is 2 bytes and
        // lowercases to `i̇`, 3 bytes), so a byte offset that is valid in `low` can land mid-codepoint
        // in `txt` — `txt[..pos]` then panicked and permanently broke search for that dataset
        // (reachable at Read scope via `GET /v1/datasets/search?q=` and the `writ_dataset_search` MCP
        // tool). Case folding also changes the character COUNT, so the char index is only used as an
        // approximate window centre; it is clamped to `txt`'s own length below.
        let match_char = terms
            .iter()
            .filter_map(|t| low.find(t.as_str()).map(|pos| low[..pos].chars().count()))
            .min();
        if let Some(match_char) = match_char {
            // Work on char boundaries so multi-byte text can't panic on slicing.
            let chars: Vec<char> = txt.chars().collect();
            let centre = match_char.min(chars.len());
            let start = centre.saturating_sub(SEARCH_SNIPPET_RADIUS);
            let end = (centre + SEARCH_SNIPPET_RADIUS).min(chars.len());
            let mut snippet: String = chars[start..end].iter().collect();
            if start > 0 {
                snippet.insert(0, '…');
            }
            if end < chars.len() {
                snippet.push('…');
            }
            return json!({ "field": name, "snippet": snippet });
        }
    }
    Value::Null
}

// ---------------------------------------------------------------------------
// Flatten.
// ---------------------------------------------------------------------------

/// One run's coerced records + chain flag — the per-run shape the lineage pass and the lens
/// endpoints consume (`flatten` performs the same extraction row-wise).
#[derive(Debug, Clone)]
pub struct FlatRun {
    pub run_id: i64,
    pub run_at: Option<String>,
    pub status: Option<String>,
    pub success: Option<bool>,
    pub duration_ms: Option<i64>,
    /// `(record_index, fields)` — record_index is the stored slot / running-counter index.
    pub records: Vec<(usize, Map<String, Value>)>,
    pub data_bearing: bool,
    /// record_index → originating list key for the object multi-list expansion (spec 3.1);
    /// empty for single-list/wrapper/object shapes (those records are untagged → source null).
    pub sources: BTreeMap<usize, String>,
}

/// Per-run extraction over the scanned runs. The caller controls order — the lineage pass
/// expects ascending chain order (coalesce(completed_at, created_at), run_id).
pub fn flatten_runs(runs: &[RunInput], declared: &[String]) -> Vec<FlatRun> {
    let declared_cols = declared_columns(declared);
    runs.iter()
        .map(|run| {
            let (records, data_bearing, sources) =
                records_from_result(&run.result_data, &declared_cols);
            FlatRun {
                run_id: run.run_id,
                run_at: run.run_at.clone(),
                status: run.status.clone(),
                success: run.success,
                duration_ms: run.duration_ms,
                records,
                data_bearing,
                sources,
            }
        })
        .collect()
}

/// Flatten runs into (columns, rows). One row per extracted record (a run that extracted a LIST
/// contributes one row per item; its record_index is the stored slot / running-counter index).
/// Columns are the declared output fields first (stable order), then any extra keys runs
/// produced. When `include_inputs` is set, each run's (secret-redacted) input/form values are
/// attached and exposed as trailing `input.<name>` columns.
pub fn flatten(
    runs: &[RunInput],
    declared: &[String],
    include_inputs: bool,
) -> (Vec<String>, Vec<Row>) {
    let declared_cols = declared_columns(declared);
    let mut seen_cols: Vec<String> = Vec::new();
    let mut seen_input_cols: Vec<String> = Vec::new();
    let mut rows: Vec<Row> = Vec::new();

    for run in runs {
        let (records, _data_bearing, _sources) =
            records_from_result(&run.result_data, &declared_cols);
        if records.is_empty() {
            continue;
        }
        let inputs = if include_inputs {
            redact_inputs(&task_inputs(&run.trigger_context))
        } else {
            Map::new()
        };
        if !inputs.is_empty() {
            for k in inputs.keys() {
                if !seen_input_cols.contains(k) {
                    seen_input_cols.push(k.clone());
                }
            }
        }
        for (idx, rec) in records {
            for k in rec.keys() {
                if !seen_cols.contains(k) {
                    seen_cols.push(k.clone());
                }
            }
            rows.push(Row {
                run_id: run.run_id,
                run_at: run.run_at.clone(),
                status: run.status.clone(),
                success: run.success,
                duration_ms: run.duration_ms,
                record_index: idx,
                fields: rec,
                inputs: inputs.clone(),
            });
        }
    }

    let mut columns = if !declared_cols.is_empty() {
        // Strict: surface EXACTLY the declared output fields (records were projected to these).
        declared_cols
    } else {
        seen_cols
    };
    if include_inputs && !seen_input_cols.is_empty() {
        for c in &seen_input_cols {
            columns.push(format!("{INPUT_PREFIX}{c}"));
        }
    }
    (columns, rows)
}

// ---------------------------------------------------------------------------
// Filters.
// ---------------------------------------------------------------------------

/// One structured filter clause. Operators: contains | eq | ne | in | between | empty | nonempty.
#[derive(Debug, Clone, serde::Deserialize)]
pub struct Clause {
    pub col: String,
    pub op: String,
    #[serde(default)]
    pub value: Option<Value>,
    #[serde(default)]
    pub values: Option<Vec<Value>>,
    #[serde(default)]
    pub min: Option<Value>,
    #[serde(default)]
    pub max: Option<Value>,
}

pub(crate) fn clause_matches(row: &Row, clause: &Clause) -> bool {
    if clause.col.is_empty() || clause.op.is_empty() {
        return true;
    }
    let val = row.value(&clause.col);
    match clause.op.as_str() {
        "empty" => is_empty_val(&val),
        "nonempty" => !is_empty_val(&val),
        "contains" => {
            let needle = clause
                .value
                .as_ref()
                .map(cell_text)
                .unwrap_or_default()
                .trim()
                .to_ascii_lowercase();
            cell_text(&val).to_ascii_lowercase().contains(&needle)
        }
        "eq" | "ne" => {
            let target = clause
                .value
                .as_ref()
                .map(cell_text)
                .unwrap_or_default()
                .trim()
                .to_ascii_lowercase();
            let hit = cell_text(&val).trim().to_ascii_lowercase() == target;
            if clause.op == "eq" { hit } else { !hit }
        }
        "in" => {
            let wanted: Vec<String> = clause
                .values
                .as_ref()
                .map(|vs| vs.iter().map(|x| cell_text(x).trim().to_ascii_lowercase()).collect())
                .unwrap_or_default();
            wanted.contains(&cell_text(&val).trim().to_ascii_lowercase())
        }
        "between" => {
            let n = match to_number(&val) {
                Some(n) => n,
                None => return false,
            };
            if let Some(mn) = clause.min.as_ref().and_then(to_number) {
                if n < mn {
                    return false;
                }
            }
            if let Some(mx) = clause.max.as_ref().and_then(to_number) {
                if n > mx {
                    return false;
                }
            }
            true
        }
        _ => true,
    }
}

// ---------------------------------------------------------------------------
// Type inference + facets.
// ---------------------------------------------------------------------------

/// Columns with at most this many distinct values are offered as a pick-list.
const FACET_MAX_DISTINCT: usize = 40;
/// Sample at most this many values per column when inferring a type.
const TYPE_SAMPLE: usize = 250;

fn is_numeric_str(s: &str) -> bool {
    s.trim().parse::<f64>().is_ok()
}

fn is_bool_str(s: &str) -> bool {
    matches!(s.trim().to_ascii_lowercase().as_str(), "true" | "false" | "yes" | "no")
}

fn is_url_str(s: &str) -> bool {
    let t = s.trim();
    t.starts_with("http://") || t.starts_with("https://")
}

/// ISO-ish date or datetime: `2026-06-21` optionally followed by `[T|space]HH:MM`. Mirrors the
/// cloud regex `^\d{4}-\d{2}-\d{2}([T\s]\d{2}:\d{2})?` (anchored at the start).
fn is_date_str(s: &str) -> bool {
    let b = s.trim().as_bytes();
    if b.len() < 10 {
        return false;
    }
    let d = |i: usize| b[i].is_ascii_digit();
    // YYYY-MM-DD prefix.
    let date_ok = d(0) && d(1) && d(2) && d(3) && b[4] == b'-' && d(5) && d(6) && b[7] == b'-' && d(8) && d(9);
    if !date_ok {
        return false;
    }
    // Bare date is enough; an optional [T|space]HH:MM suffix is also accepted (anything trailing
    // beyond that is fine since the cloud regex is not anchored at the end).
    if b.len() == 10 {
        return true;
    }
    if b.len() >= 16 && (b[10] == b'T' || b[10] == b' ') {
        return d(11) && d(12) && b[13] == b':' && d(14) && d(15);
    }
    // Has trailing chars but not a valid time suffix — the bare-date prefix still matched, which
    // the cloud (un-anchored end) would accept as long as the prefix is a valid date.
    true
}

/// A column type for the smart-filter UI.
fn infer_type(values: &[Value]) -> &'static str {
    let (mut nums, mut bools, mut urls, mut dates, mut objs, mut n) = (0u32, 0u32, 0u32, 0u32, 0u32, 0u32);
    for v in values.iter().take(TYPE_SAMPLE) {
        if is_empty_val(v) {
            continue;
        }
        n += 1;
        match v {
            Value::Bool(_) => bools += 1,
            Value::Number(_) => nums += 1,
            Value::Object(_) | Value::Array(_) => objs += 1,
            Value::String(s) => {
                let t = s.trim();
                if is_numeric_str(t) {
                    nums += 1;
                } else if is_bool_str(t) {
                    bools += 1;
                } else if is_url_str(t) {
                    urls += 1;
                } else if is_date_str(t) {
                    dates += 1;
                }
            }
            Value::Null => {}
        }
    }
    if n == 0 {
        return "text";
    }
    let frac = |c: u32| c as f64 / n as f64;
    if objs > 0 && frac(objs) >= 0.5 {
        return "json";
    }
    if frac(bools) >= 0.8 {
        return "boolean";
    }
    if frac(nums) >= 0.8 {
        return "number";
    }
    if frac(dates) >= 0.8 {
        return "date";
    }
    if frac(urls) >= 0.8 {
        return "url";
    }
    "text"
}

/// For each column (data columns + the `status` run-meta column), derive a facet the UI uses to
/// render a smart filter: inferred type, non-empty count, numeric min/max, and the distinct value
/// set when low cardinality. Computed over ALL present rows (pre-filter) so options are stable.
pub fn compute_facets(columns: &[String], rows: &[Row]) -> Value {
    let mut facet_cols: Vec<String> = vec!["status".to_string()];
    for c in columns {
        if c != "status" {
            facet_cols.push(c.clone());
        }
    }

    let mut facets = Map::new();
    for col in &facet_cols {
        let vals: Vec<Value> = rows
            .iter()
            .map(|r| r.value(col))
            .filter(|v| !is_empty_val(v))
            .collect();
        let ftype = if col == "status" { "text" } else { infer_type(&vals) };
        let mut facet = Map::new();
        facet.insert("type".into(), Value::String(ftype.to_string()));
        facet.insert("non_empty".into(), Value::from(vals.len()));

        if ftype == "number" {
            let nums: Vec<f64> = vals.iter().filter_map(to_number).collect();
            if !nums.is_empty() {
                let mn = nums.iter().cloned().fold(f64::INFINITY, f64::min);
                let mx = nums.iter().cloned().fold(f64::NEG_INFINITY, f64::max);
                facet.insert("min".into(), Value::from(mn));
                facet.insert("max".into(), Value::from(mx));
            }
        }

        // Distinct value pick-list (skip json — not meaningfully enumerable).
        if ftype != "json" {
            let mut counts: BTreeMap<String, u64> = BTreeMap::new();
            let mut overflow = false;
            for v in &vals {
                let key = cell_text(v).trim().to_string();
                if key.is_empty() {
                    continue;
                }
                if !counts.contains_key(&key) && counts.len() > FACET_MAX_DISTINCT {
                    overflow = true;
                    break;
                }
                *counts.entry(key).or_insert(0) += 1;
            }
            let distinct_count = if overflow { FACET_MAX_DISTINCT + 1 } else { counts.len() };
            facet.insert("distinct_count".into(), Value::from(distinct_count));
            if !overflow && counts.len() <= FACET_MAX_DISTINCT {
                // Order by count desc, then value asc (stable, matches the cloud sort).
                let mut pairs: Vec<(String, u64)> = counts.into_iter().collect();
                pairs.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
                let distinct: Vec<Value> = pairs
                    .into_iter()
                    .map(|(k, c)| {
                        let mut m = Map::new();
                        m.insert("value".into(), Value::String(k));
                        m.insert("count".into(), Value::from(c));
                        Value::Object(m)
                    })
                    .collect();
                facet.insert("distinct".into(), Value::Array(distinct));
            }
        }
        facets.insert(col.clone(), Value::Object(facet));
    }
    Value::Object(facets)
}

// ---------------------------------------------------------------------------
// build_table — filter + sort + paginate.
// ---------------------------------------------------------------------------

/// Query options for `build_table`. `limit = None` returns every row after `offset` (export).
#[derive(Debug, Clone, Default)]
pub struct TableQuery {
    /// Global substring filter across all fields/inputs/status/run_id.
    pub q: Option<String>,
    /// Legacy per-column substring filters (column -> substring), AND-combined.
    pub col_filters: BTreeMap<String, String>,
    /// Structured smart-filter clauses, AND-combined.
    pub filters: Vec<Clause>,
    /// A data column or a run-meta pseudo-column; anything else falls back to `run_at`.
    pub sort_by: Option<String>,
    /// `asc` or `desc` (default desc).
    pub sort_dir: String,
    pub offset: usize,
    pub limit: Option<usize>,
}

/// The materialized table: columns, the requested page of rows, and the post-filter total.
pub struct Table {
    pub columns: Vec<String>,
    pub declared: bool,
    pub rows: Vec<Row>,
    pub total: usize,
}

/// Flatten `runs` into a columns+rows table, then apply `q` / col-filters / structured filters,
/// sort, and paginate. `runs` should already be the visible, most-recent-first set to scan.
pub fn build_table(
    runs: &[RunInput],
    declared: &[String],
    query: &TableQuery,
    include_inputs: bool,
) -> Table {
    let (columns, mut rows) = flatten(runs, declared, include_inputs);

    if let Some(q) = &query.q {
        let needle = q.trim().to_ascii_lowercase();
        if !needle.is_empty() {
            rows.retain(|r| row_matches(r, &needle));
        }
    }

    // Per-column substring filters (legacy), AND-combined.
    for (col, sub) in &query.col_filters {
        let sub = sub.trim().to_ascii_lowercase();
        if sub.is_empty() {
            continue;
        }
        rows.retain(|r| cell_text(&r.value(col)).to_ascii_lowercase().contains(&sub));
    }

    // Structured smart-filter clauses, AND-combined.
    for clause in &query.filters {
        if !clause.col.is_empty() && !clause.op.is_empty() {
            rows.retain(|r| clause_matches(r, clause));
        }
    }

    let total = rows.len();

    // Sort. Default: most recent run first. A valid sort_by is a data column or a run-meta
    // pseudo-column; anything else falls back to run_at.
    let mut valid_sort: Vec<String> = columns.clone();
    for k in ["run_at", "status", "duration_ms", "run_id"] {
        valid_sort.push(k.to_string());
    }
    let key = match &query.sort_by {
        Some(s) if valid_sort.contains(s) => s.clone(),
        _ => "run_at".to_string(),
    };
    let reverse = !query.sort_dir.eq_ignore_ascii_case("asc");
    if key == "run_at" {
        rows.sort_by(|a, b| {
            let av = a.run_at.clone().unwrap_or_default();
            let bv = b.run_at.clone().unwrap_or_default();
            av.cmp(&bv)
        });
    } else {
        rows.sort_by(|a, b| sort_key_for(&a.value(&key)).cmp(&sort_key_for(&b.value(&key))));
    }
    if reverse {
        rows.reverse();
    }

    let page: Vec<Row> = match query.limit {
        None => rows.into_iter().skip(query.offset).collect(),
        Some(lim) => rows.into_iter().skip(query.offset).take(lim).collect(),
    };

    Table {
        columns,
        declared: !declared_columns(declared).is_empty(),
        rows: page,
        total,
    }
}

// ---------------------------------------------------------------------------
// Serialization — JSON rows + CSV.
// ---------------------------------------------------------------------------

/// Serialize a row to a flat JSON record (run metadata + the requested columns), for the API
/// table response and JSON export. Run metadata leads, then the columns in order.
pub fn row_to_json(row: &Row, columns: &[String]) -> Value {
    let mut rec = Map::new();
    rec.insert("run_id".into(), Value::from(row.run_id));
    rec.insert(
        "run_at".into(),
        row.run_at.clone().map(Value::String).unwrap_or(Value::Null),
    );
    rec.insert(
        "status".into(),
        row.status.clone().map(Value::String).unwrap_or(Value::Null),
    );
    rec.insert("record_index".into(), Value::from(row.record_index));
    for c in columns {
        rec.insert(c.clone(), row.value(c));
    }
    Value::Object(rec)
}

/// Serialize the requested page of rows to flat JSON records (run-meta + data columns at the top
/// level). Used by the raw JSON export, where flat records are the friendly shape.
pub fn rows_to_json(rows: &[Row], columns: &[String]) -> Vec<Value> {
    rows.iter().map(|r| row_to_json(r, columns)).collect()
}

/// Serialize rows in the shape the desktop data table consumes: run-meta keys at the top level and
/// the data columns nested under a `fields` object. The UI's `DataRow` type + `ExtractedDataTable`
/// read each cell from `row.fields[column]`, so the table endpoint MUST nest (a flat row renders
/// every data cell blank).
pub fn rows_to_table_json(rows: &[Row], columns: &[String]) -> Vec<Value> {
    rows.iter().map(|r| row_to_table_json(r, columns)).collect()
}

/// One table row: run-meta at the top level, data columns under `fields`. See [`rows_to_table_json`].
pub(crate) fn row_to_table_json(row: &Row, columns: &[String]) -> Value {
    let mut rec = Map::new();
    rec.insert("run_id".into(), Value::from(row.run_id));
    rec.insert(
        "run_at".into(),
        row.run_at.clone().map(Value::String).unwrap_or(Value::Null),
    );
    rec.insert(
        "status".into(),
        row.status.clone().map(Value::String).unwrap_or(Value::Null),
    );
    rec.insert("record_index".into(), Value::from(row.record_index));
    let mut fields = Map::new();
    for c in columns {
        fields.insert(c.clone(), row.value(c));
    }
    rec.insert("fields".into(), Value::Object(fields));
    Value::Object(rec)
}

/// One CSV field, RFC-4180 quoted when it contains a comma, quote, CR, or LF.
fn csv_field(s: &str) -> String {
    if s.contains(',') || s.contains('"') || s.contains('\n') || s.contains('\r') {
        format!("\"{}\"", s.replace('"', "\"\""))
    } else {
        s.to_string()
    }
}

/// Serialize the flattened rows to CSV. Run metadata leads each row, then the data columns in
/// order. Non-scalar cell values are JSON-encoded. Uses CRLF line endings (RFC 4180).
pub fn to_csv(columns: &[String], rows: &[Row]) -> String {
    let mut out = String::new();
    let mut header: Vec<String> = vec!["run_id".into(), "run_at".into(), "status".into()];
    header.extend(columns.iter().cloned());
    out.push_str(&header.iter().map(|h| csv_field(h)).collect::<Vec<_>>().join(","));
    out.push_str("\r\n");
    for r in rows {
        let mut line: Vec<String> = vec![
            r.run_id.to_string(),
            r.run_at.clone().unwrap_or_default(),
            r.status.clone().unwrap_or_default(),
        ];
        for c in columns {
            line.push(cell_text(&r.value(c)));
        }
        out.push_str(&line.iter().map(|f| csv_field(f)).collect::<Vec<_>>().join(","));
        out.push_str("\r\n");
    }
    out
}

/// CSV for the lineage lenses (`view=latest|run`): the run-meta columns, then the lineage
/// columns `record_uid,change,changed_fields,first_seen,last_seen,versions`, then the data
/// columns (spec 1.5.5). `changed_fields` renders only when the row's change is "changed".
pub fn to_csv_with_lineage(columns: &[String], rows: &[(Row, Value)]) -> String {
    let mut out = String::new();
    let mut header: Vec<String> = vec![
        "run_id".into(),
        "run_at".into(),
        "status".into(),
        "record_uid".into(),
        "change".into(),
        "changed_fields".into(),
        "first_seen".into(),
        "last_seen".into(),
        "versions".into(),
    ];
    header.extend(columns.iter().cloned());
    out.push_str(&header.iter().map(|h| csv_field(h)).collect::<Vec<_>>().join(","));
    out.push_str("\r\n");
    for (r, lineage) in rows {
        let changed = lineage["change"].as_str() == Some("changed");
        let mut line: Vec<String> = vec![
            r.run_id.to_string(),
            r.run_at.clone().unwrap_or_default(),
            r.status.clone().unwrap_or_default(),
            cell_text(&lineage["uid"]),
            cell_text(&lineage["change"]),
            if changed { cell_text(&lineage["changed_fields"]) } else { String::new() },
            cell_text(&lineage["first_seen_at"]),
            cell_text(&lineage["last_seen_at"]),
            cell_text(&lineage["versions"]),
        ];
        for c in columns {
            line.push(cell_text(&r.value(c)));
        }
        out.push_str(&line.iter().map(|f| csv_field(f)).collect::<Vec<_>>().join(","));
        out.push_str("\r\n");
    }
    out
}

// ---------------------------------------------------------------------------
// Markdown / HTML output (`?format=markdown|html`)
//
// Port of the cloud renderers (the cloud backend's `extracted_data_table` service, same
// section) — same content-aware rule, so a dataset renders the same whether it is
// served locally or forwarded to the fleet.
//
// CONTENT-AWARE: a dataset whose records carry a long-form content column (a
// crawl page has `markdown`) renders as DOCUMENTS — one section per record,
// heading + source link + body. Anything else renders as a TABLE mirroring the
// CSV columns.
//
// SECURITY: an html render echoes SCRAPED THIRD-PARTY content back as
// `text/html`. Raw HTML in the source is ESCAPED (never passed through) and
// link/image URL schemes are allowlisted, so `<script>` and
// `[x](javascript:…)` cannot survive into live markup. Mirrors the cloud posture.
// ---------------------------------------------------------------------------

/// Columns that may hold long-form document content, in preference order.
const CONTENT_FIELDS: [&str; 4] = ["markdown", "content", "text", "body"];
/// Columns to title a document with, in preference order.
const TITLE_FIELDS: [&str; 4] = ["title", "name", "heading", "url"];
/// Columns naming a document's source, in preference order.
const URL_FIELDS: [&str; 4] = ["url", "link", "source_url", "source"];
/// A content column must carry at least this many chars to count as long-form.
const CONTENT_MIN_CHARS: usize = 200;

/// The column holding long-form content, or `None` when the dataset is not
/// document-shaped. Requires at least half the rows to carry a genuinely long
/// string, so a short incidental `text` column does not flip a structured dataset
/// into document mode.
pub fn content_column(columns: &[String], rows: &[Row]) -> Option<String> {
    if rows.is_empty() {
        return None;
    }
    for cand in CONTENT_FIELDS {
        if !columns.iter().any(|c| c == cand) {
            continue;
        }
        let long = rows
            .iter()
            .filter(|r| match r.value(cand) {
                Value::String(s) => s.chars().count() >= CONTENT_MIN_CHARS,
                _ => false,
            })
            .count();
        if long * 2 >= rows.len() {
            return Some(cand.to_string());
        }
    }
    None
}

/// Drop a leading YAML front-matter block (`---` line, keys, `---` line) from
/// document content. A crawl stores each page's markdown WITH front matter; the
/// renderers hoist title + url into the heading, so leaving it would duplicate
/// them and render as a stray rule + junk heading. Anchored at the start, so a
/// mid-document thematic break is never mistaken for it.
pub fn strip_front_matter(text: &str) -> &str {
    let t = text.strip_prefix('\u{feff}').unwrap_or(text);
    let rest = match t.strip_prefix("---") {
        Some(r) => r,
        None => return text,
    };
    // The opening delimiter must be alone on its line.
    let rest = rest.trim_start_matches([' ', '\t']);
    let rest = match rest.strip_prefix("\r\n").or_else(|| rest.strip_prefix('\n')) {
        Some(r) => r,
        None => return text,
    };
    // Scan line-by-line for the closing `---`.
    let mut offset = 0usize;
    for line in rest.split_inclusive('\n') {
        if line.trim_end_matches(['\r', '\n', ' ', '\t']) == "---" {
            let tail = &rest[offset + line.len()..];
            return tail.trim_start_matches(['\r', '\n']);
        }
        offset += line.len();
    }
    text
}

/// A link/image URL, or `None` when its scheme is not allowlisted (blocks
/// `javascript:` / `vbscript:` / `file:` / bare `data:` payloads).
pub fn safe_link(url: &str) -> Option<String> {
    let u = url.trim();
    if u.is_empty() {
        return None;
    }
    let low = u.to_ascii_lowercase();
    if low.starts_with("//") || low.starts_with('/') || low.starts_with('#') {
        return Some(u.to_string());
    }
    let authority = low.split('/').next().unwrap_or("");
    if !low.contains("://") && !authority.contains(':') {
        return Some(u.to_string()); // relative path
    }
    const SAFE: [&str; 4] = ["http://", "https://", "mailto:", "data:image/"];
    if SAFE.iter().any(|s| low.starts_with(s)) {
        Some(u.to_string())
    } else {
        None
    }
}

/// Render CommonMark to HTML with raw HTML escaped and unsafe link schemes
/// dropped. Mirrors the cloud's `markdown-it-py` (html=False + link allowlist).
pub fn md_to_html(text: &str) -> String {
    use pulldown_cmark::{html, Event, Options, Parser, Tag};

    let parser = Parser::new_ext(text, Options::ENABLE_STRIKETHROUGH | Options::ENABLE_TABLES);
    let events = parser.map(|ev| match ev {
        // Raw HTML NEVER passes through — re-emit as text so it is escaped.
        Event::Html(s) => Event::Text(s),
        Event::InlineHtml(s) => Event::Text(s),
        // Neutralize an unsafe link/image destination rather than emit it.
        Event::Start(Tag::Link { link_type, dest_url, title, id }) => Event::Start(Tag::Link {
            link_type,
            dest_url: safe_link(&dest_url).unwrap_or_default().into(),
            title,
            id,
        }),
        Event::Start(Tag::Image { link_type, dest_url, title, id }) => Event::Start(Tag::Image {
            link_type,
            dest_url: safe_link(&dest_url).unwrap_or_default().into(),
            title,
            id,
        }),
        other => other,
    });
    let mut out = String::new();
    html::push_html(&mut out, events);
    out
}

/// Escape a value so it cannot break a Markdown table grid.
fn md_cell(value: &Value) -> String {
    cell_text(value).replace('|', "\\|").replace(['\r', '\n'], " ")
}

/// Minimal HTML text escape.
fn html_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            _ => out.push(c),
        }
    }
    out
}

/// `(title, url, content)` for one document-shaped row.
fn doc_parts(row: &Row, ccol: &str) -> (String, Option<String>, String) {
    let first = |keys: &[&str]| -> Option<String> {
        keys.iter().filter(|k| **k != ccol).find_map(|k| match row.value(k) {
            Value::String(s) if !s.trim().is_empty() => Some(s.trim().to_string()),
            _ => None,
        })
    };
    let title = first(&TITLE_FIELDS).unwrap_or_else(|| format!("Record {}", row.record_index));
    let url = first(&URL_FIELDS);
    let content = match row.value(ccol) {
        Value::String(s) => s,
        other => cell_text(&other),
    };
    (title, url, strip_front_matter(&content).to_string())
}

/// Serialize rows to Markdown — documents when document-shaped, else a table.
pub fn to_markdown(columns: &[String], rows: &[Row], title: Option<&str>) -> String {
    let mut out = String::new();
    if let Some(t) = title {
        out.push_str(&format!("# {t}\n\n"));
    }
    if let Some(ccol) = content_column(columns, rows) {
        for r in rows {
            let (t, url, content) = doc_parts(r, &ccol);
            out.push_str(&format!("## {t}\n\n"));
            if let Some(u) = url {
                out.push_str(&format!("<{u}>\n\n"));
            }
            out.push_str(content.trim());
            out.push_str("\n\n---\n\n");
        }
        return format!("{}\n", out.trim_end_matches(['\n', '-', ' ']));
    }
    let mut header: Vec<String> = vec!["run_id".into(), "run_at".into(), "status".into()];
    header.extend(columns.iter().cloned());
    out.push_str(&format!("| {} |\n", header.join(" | ")));
    out.push_str(&format!(
        "| {} |\n",
        header.iter().map(|_| "---").collect::<Vec<_>>().join(" | ")
    ));
    for r in rows {
        let mut line: Vec<String> = vec![
            r.run_id.to_string(),
            r.run_at.clone().unwrap_or_default(),
            r.status.clone().unwrap_or_default(),
        ];
        for c in columns {
            line.push(md_cell(&r.value(c)));
        }
        out.push_str(&format!("| {} |\n", line.join(" | ")));
    }
    out
}

/// The stylesheet the standalone HTML render carries (kept in sync with cloud).
const HTML_CSS: &str = concat!(
    "body{font:15px/1.6 -apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;",
    "max-width:52rem;margin:2rem auto;padding:0 1rem;color:#18181b}",
    "table{border-collapse:collapse;width:100%;font-size:13px}",
    "th,td{border:1px solid #e4e4e7;padding:6px 8px;text-align:left;vertical-align:top}",
    "th{background:#fafafa}",
    "article{margin:0 0 2rem;padding:0 0 2rem;border-bottom:1px solid #e4e4e7}",
    "img{max-width:100%}pre{overflow-x:auto;background:#fafafa;padding:.75rem;border-radius:6px}",
    "@media(prefers-color-scheme:dark){body{background:#09090b;color:#e4e4e7}",
    "th,td,article{border-color:#27272a}th,pre{background:#18181b}}"
);

/// Serialize rows to a standalone HTML document — rendered documents when
/// document-shaped, else a table. All values escaped; see the section note.
pub fn to_html(columns: &[String], rows: &[Row], title: Option<&str>) -> String {
    let doc_title = html_escape(title.unwrap_or("Dataset"));
    let mut out = String::new();
    out.push_str("<!doctype html>\n<html lang=\"en\"><head><meta charset=\"utf-8\">\n");
    out.push_str("<meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">\n");
    out.push_str(&format!("<title>{doc_title}</title><style>{HTML_CSS}</style></head><body>\n"));
    if title.is_some() {
        out.push_str(&format!("<h1>{doc_title}</h1>\n"));
    }
    if let Some(ccol) = content_column(columns, rows) {
        for r in rows {
            let (t, url, content) = doc_parts(r, &ccol);
            out.push_str("<article>\n");
            out.push_str(&format!("<h2>{}</h2>\n", html_escape(&t)));
            if let Some(u) = &url {
                match safe_link(u) {
                    Some(safe) => out.push_str(&format!(
                        "<p><a href=\"{}\" rel=\"noreferrer nofollow\">{}</a></p>\n",
                        html_escape(&safe),
                        html_escape(u)
                    )),
                    None => out.push_str(&format!("<p>{}</p>\n", html_escape(u))),
                }
            }
            out.push_str(&md_to_html(&content));
            out.push_str("</article>\n");
        }
        out.push_str("</body></html>");
        return out;
    }
    let mut header: Vec<String> = vec!["run_id".into(), "run_at".into(), "status".into()];
    header.extend(columns.iter().cloned());
    out.push_str("<table><thead><tr>");
    for h in &header {
        out.push_str(&format!("<th>{}</th>", html_escape(h)));
    }
    out.push_str("</tr></thead><tbody>\n");
    for r in rows {
        let mut cells: Vec<String> = vec![
            r.run_id.to_string(),
            r.run_at.clone().unwrap_or_default(),
            r.status.clone().unwrap_or_default(),
        ];
        for c in columns {
            cells.push(cell_text(&r.value(c)));
        }
        out.push_str("<tr>");
        for c in &cells {
            out.push_str(&format!("<td>{}</td>", html_escape(c)));
        }
        out.push_str("</tr>\n");
    }
    out.push_str("</tbody></table></body></html>");
    out
}

// ---------------------------------------------------------------------------
// Record lineage (DATA_REDESIGN_SPEC PART 1) — norm(), identity ladder, record
// uids, snapshot-chain deltas, change-point histories. Faithful port of the
// reference implementation `shared/data_lineage_golden_gen.py`; the vendored
// golden vectors (`data_lineage_golden.json`) pin every rule cross-engine.
// ---------------------------------------------------------------------------

/// Matches the numeric-string grammar `^-?\d+(\.\d+)?([eE][+-]?\d+)?$` (hand-rolled — this
/// module stays regex-free).
fn looks_numeric(s: &str) -> bool {
    let b = s.trim().as_bytes();
    let mut i = 0;
    if i < b.len() && b[i] == b'-' {
        i += 1;
    }
    let int_start = i;
    while i < b.len() && b[i].is_ascii_digit() {
        i += 1;
    }
    if i == int_start {
        return false;
    }
    if i < b.len() && b[i] == b'.' {
        i += 1;
        let frac_start = i;
        while i < b.len() && b[i].is_ascii_digit() {
            i += 1;
        }
        if i == frac_start {
            return false;
        }
    }
    if i < b.len() && (b[i] == b'e' || b[i] == b'E') {
        i += 1;
        if i < b.len() && (b[i] == b'+' || b[i] == b'-') {
            i += 1;
        }
        let exp_start = i;
        while i < b.len() && b[i].is_ascii_digit() {
            i += 1;
        }
        if i == exp_start {
            return false;
        }
    }
    i == b.len()
}

/// Canonical decimal for a number: integral values with |x| < 2^53 render as integers (42, not
/// 42.0); everything else uses shortest round-trip formatting with exponent cleanup (lowercase
/// `e`, no `+`, no exponent leading zeros).
fn norm_number(x: f64) -> String {
    if x.is_finite() && x == x.trunc() && x.abs() < 9_007_199_254_740_992.0 {
        return format!("{}", x.trunc() as i64);
    }
    let s = format!("{x}");
    if let Some(pos) = s.find(['e', 'E']) {
        let mant = &s[..pos];
        let exp = &s[pos + 1..];
        let exp = exp.strip_prefix('+').unwrap_or(exp);
        let (sign, digits) = match exp.strip_prefix('-') {
            Some(d) => ("-", d),
            None => ("", exp),
        };
        let digits = digits.trim_start_matches('0');
        let digits = if digits.is_empty() { "0" } else { digits };
        return format!("{mant}e{sign}{digits}");
    }
    s
}

/// Spec 1.2 `norm()` — the ONE normalization used for uid hashing AND change comparison.
/// null / "" / whitespace-only are all EQUAL (empty string); numeric strings collapse onto the
/// number's canonical decimal; booleans render "true"/"false" (bool-ish STRINGS stay strings);
/// composites encode as sorted-key JSON with every scalar rendered as its norm string.
pub fn norm(v: &Value) -> String {
    match v {
        Value::Null => String::new(),
        Value::Bool(b) => if *b { "true".into() } else { "false".into() },
        Value::Number(n) => norm_number(n.as_f64().unwrap_or(0.0)),
        Value::String(s) => {
            let t = s.trim();
            if t.is_empty() {
                return String::new();
            }
            if looks_numeric(t) {
                if let Ok(f) = t.parse::<f64>() {
                    if f.is_finite() {
                        return norm_number(f);
                    }
                }
            }
            t.to_string()
        }
        composite => encode_composite(composite),
    }
}

/// Composite (object/array) canonical encoding: JSON with byte-order sorted keys, no whitespace,
/// scalars rendered as JSON strings of their norm form (so `"42"` and `42` encode identically),
/// arrays order-sensitive.
fn encode_composite(v: &Value) -> String {
    match v {
        Value::Object(o) => {
            let mut keys: Vec<&String> = o.keys().collect();
            keys.sort(); // byte-order — never rely on map iteration order
            let inner: Vec<String> = keys
                .iter()
                .map(|k| format!("{}:{}", json_string(k), encode_value(&o[k.as_str()])))
                .collect();
            format!("{{{}}}", inner.join(","))
        }
        Value::Array(a) => {
            let inner: Vec<String> = a.iter().map(encode_value).collect();
            format!("[{}]", inner.join(","))
        }
        other => encode_value(other),
    }
}

/// Scalars render as JSON strings of their norm form; composites recurse.
fn encode_value(v: &Value) -> String {
    match v {
        Value::Object(_) | Value::Array(_) => encode_composite(v),
        scalar => json_string(&norm(scalar)),
    }
}

/// A JSON string literal (python `json.dumps(s, ensure_ascii=False)` equivalent).
fn json_string(s: &str) -> String {
    serde_json::to_string(&Value::String(s.into())).unwrap_or_default()
}

fn sha256_hex(s: &str) -> String {
    let mut h = Sha256::new();
    h.update(s.as_bytes());
    h.finalize().iter().map(|b| format!("{b:02x}")).collect()
}

/// Whole-record content hash — orders same-run duplicate-identity members content-first so
/// exact-content duplicates pair as "same" across runs regardless of position.
fn record_hash(fields: &Map<String, Value>) -> String {
    sha256_hex(&encode_composite(&Value::Object(fields.clone())))
}

/// The exact uid digest input: `field1\x1F norm(v1) \x1E field2\x1F norm(v2) …` in identity
/// order (`__singleton__` in singleton mode); duplicate members ≥2 append `\x1E#ordinal`.
pub fn uid_digest_input(
    identity_fields: &[String],
    fields: &Map<String, Value>,
    ordinal: usize,
    singleton: bool,
) -> String {
    let mut base = if singleton {
        "__singleton__".to_string()
    } else {
        identity_fields
            .iter()
            .map(|f| format!("{f}\u{1f}{}", norm(fields.get(f).unwrap_or(&Value::Null))))
            .collect::<Vec<_>>()
            .join("\u{1e}")
    };
    if ordinal >= 1 {
        base.push_str(&format!("\u{1e}#{ordinal}"));
    }
    base
}

/// record_uid = first 16 hex chars of SHA-256 over the UTF-8 digest input (spec 1.3).
pub fn record_uid(
    identity_fields: &[String],
    fields: &Map<String, Value>,
    ordinal: usize,
    singleton: bool,
) -> String {
    sha256_hex(&uid_digest_input(identity_fields, fields, ordinal, singleton))[..16].to_string()
}

/// The chosen record identity, echoed on every lineage-bearing response.
#[derive(Debug, Clone)]
pub struct Identity {
    /// "explicit" | "auto" | "singleton" | "hash".
    pub mode: &'static str,
    pub fields: Vec<String>,
    /// Set when an explicit `key` failed coverage validation (identity fields non-empty in <50%
    /// of scanned records) and the ladder fell back.
    pub requested_key_rejected: Option<Vec<String>>,
    pub coverage: Option<f64>,
}

impl Identity {
    pub fn to_json(&self) -> Value {
        let mut m = Map::new();
        m.insert("mode".into(), Value::String(self.mode.into()));
        m.insert("fields".into(), json!(self.fields));
        if let Some(rejected) = &self.requested_key_rejected {
            m.insert("requested_key_rejected".into(), json!(rejected));
            m.insert("coverage".into(), json!(self.coverage.unwrap_or(0.0)));
        }
        Value::Object(m)
    }
}

/// Identity auto-pick tiers (spec 1.3): first tier with a qualifying column wins; within a tier,
/// leftmost in canonical column order. `None` marks the suffix tier (`_id` / `_url`).
const IDENTITY_TIERS: [Option<&[&str]>; 5] = [
    Some(&["id", "uid", "uuid", "key"]),
    Some(&["url", "link", "href", "permalink"]),
    Some(&["sku", "slug", "email", "handle"]),
    None,
    Some(&["name", "title"]),
];

/// Score columns over the bounded sample: a column qualifies iff non-empty in ≥90% of sampled
/// records AND mean per-run uniqueness ratio ≥0.95 (runs with <2 non-empty values count as 1.0).
fn auto_identity(
    runs_records: &[Vec<Map<String, Value>>],
    columns_order: &[String],
) -> Option<String> {
    let total: usize = runs_records.iter().map(|r| r.len()).sum();
    if total == 0 {
        return None;
    }
    let qualifies = |col: &str| -> bool {
        let non_empty = runs_records
            .iter()
            .flatten()
            .filter(|r| !norm(r.get(col).unwrap_or(&Value::Null)).is_empty())
            .count();
        if non_empty * 10 < total * 9 {
            return false;
        }
        let mut ratio_sum = 0.0f64;
        for run in runs_records {
            let vals: Vec<String> = run
                .iter()
                .map(|r| norm(r.get(col).unwrap_or(&Value::Null)))
                .filter(|v| !v.is_empty())
                .collect();
            ratio_sum += if vals.len() < 2 {
                1.0
            } else {
                let distinct: BTreeSet<&String> = vals.iter().collect();
                distinct.len() as f64 / vals.len() as f64
            };
        }
        ratio_sum / runs_records.len() as f64 >= 0.95
    };
    for tier in IDENTITY_TIERS {
        let cands: Vec<&String> = match tier {
            None => columns_order
                .iter()
                .filter(|c| c.ends_with("_id") || c.ends_with("_url"))
                .collect(),
            Some(set) => columns_order
                .iter()
                .filter(|c| set.contains(&c.as_str()))
                .collect(),
        };
        for c in cands {
            if qualifies(c) {
                return Some(c.clone());
            }
        }
    }
    None
}

/// Identity choice ladder (spec 1.3): explicit key (validated: identity fields non-empty in
/// ≥50% of scanned records, else rejected + echoed) → singleton (≥95% of record-bearing runs
/// have exactly 1 record; 0-record runs don't count against it) → auto tiers → hash over ALL
/// columns. `runs_records` = per data-bearing run record lists, the bounded newest-≤50 sample.
pub fn choose_identity(
    runs_records: &[Vec<Map<String, Value>>],
    columns_order: &[String],
    explicit_key: Option<&str>,
) -> Identity {
    let total: usize = runs_records.iter().map(|r| r.len()).sum();
    let mut rejected: Option<(Vec<String>, f64)> = None;
    if let Some(key) = explicit_key {
        let fields: Vec<String> = key
            .split(',')
            .map(|f| f.trim().to_string())
            .filter(|f| !f.is_empty())
            .collect();
        if !fields.is_empty() {
            let coverage = if total == 0 {
                0.0
            } else {
                let covered = runs_records
                    .iter()
                    .flatten()
                    .filter(|r| {
                        fields
                            .iter()
                            .any(|f| !norm(r.get(f).unwrap_or(&Value::Null)).is_empty())
                    })
                    .count();
                covered as f64 / total as f64
            };
            if total > 0 && coverage >= 0.5 {
                return Identity { mode: "explicit", fields, requested_key_rejected: None, coverage: None };
            }
            rejected = Some((fields, coverage));
        }
    }
    let (requested_key_rejected, coverage) = match rejected {
        Some((f, c)) => (Some(f), Some(c)),
        None => (None, None),
    };
    let bearing: Vec<&Vec<Map<String, Value>>> =
        runs_records.iter().filter(|r| !r.is_empty()).collect();
    if !bearing.is_empty()
        && bearing.iter().filter(|r| r.len() == 1).count() * 100 >= bearing.len() * 95
    {
        return Identity { mode: "singleton", fields: Vec::new(), requested_key_rejected, coverage };
    }
    if let Some(f) = auto_identity(runs_records, columns_order) {
        return Identity { mode: "auto", fields: vec![f], requested_key_rejected, coverage };
    }
    Identity { mode: "hash", fields: columns_order.to_vec(), requested_key_rejected, coverage }
}

/// Canonical column order for identity work: declared fields first, then first-seen across the
/// runs' records (runs in chain order).
pub fn canonical_columns(flat: &[FlatRun], declared: &[String]) -> Vec<String> {
    let mut cols = declared_columns(declared);
    for run in flat {
        for (_, rec) in &run.records {
            for k in rec.keys() {
                if !cols.iter().any(|c| c == k) {
                    cols.push(k.clone());
                }
            }
        }
    }
    cols
}

/// Assign uids to ONE run's records. Same-run duplicate-identity groups order their members by
/// (whole-record hash, record_index) — content-first — and suffix ordinals ≥1 from the 2nd
/// member onward. Singleton mode keys only the run's record_index-lowest record.
pub fn assign_uids(
    records: &[(usize, Map<String, Value>)],
    mode: &str,
    fields: &[String],
) -> Vec<(String, usize, Map<String, Value>)> {
    if mode == "singleton" {
        let Some((idx, rec)) = records.first() else {
            return Vec::new();
        };
        return vec![(record_uid(&[], rec, 0, true), *idx, rec.clone())];
    }
    let mut groups: BTreeMap<String, Vec<(usize, &Map<String, Value>)>> = BTreeMap::new();
    for (idx, rec) in records {
        groups
            .entry(uid_digest_input(fields, rec, 0, false))
            .or_default()
            .push((*idx, rec));
    }
    let mut out: Vec<(String, usize, Map<String, Value>)> = Vec::new();
    for (_base, members) in groups {
        let mut keyed: Vec<(String, usize, &Map<String, Value>)> = members
            .into_iter()
            .map(|(idx, rec)| (record_hash(rec), idx, rec))
            .collect();
        keyed.sort_by(|a, b| (a.0.as_str(), a.1).cmp(&(b.0.as_str(), b.1)));
        for (ordinal, (_hash, idx, rec)) in keyed.into_iter().enumerate() {
            out.push((record_uid(fields, rec, ordinal, false), idx, rec.clone()));
        }
    }
    out.sort_by_key(|(_, idx, _)| *idx);
    out
}

/// Diff depth cap: leaf dot-paths descend at most this many segments.
const DIFF_MAX_DEPTH: usize = 3;
/// More than this many differing leaves under one top-level key collapse to that key alone.
const DIFF_COLLAPSE_AT: usize = 20;

fn diff_walk(
    o: Option<&Value>,
    n: Option<&Value>,
    path: &mut Vec<String>,
    depth: usize,
    leaves: &mut Vec<String>,
) {
    if let (Some(Value::Object(om)), Some(Value::Object(nm))) = (o, n) {
        if depth < DIFF_MAX_DEPTH {
            let mut keys: BTreeSet<&String> = om.keys().collect();
            keys.extend(nm.keys());
            for k in keys {
                path.push(k.clone());
                diff_walk(om.get(k), nm.get(k), path, depth + 1, leaves);
                path.pop();
            }
            return;
        }
    }
    let ov = o.map(norm).unwrap_or_default();
    let nv = n.map(norm).unwrap_or_default();
    if ov != nv {
        leaves.push(path.join("."));
    }
}

/// Leaf dot-paths where `norm` differs (recursive, depth ≤3), collapsing to the top-level key
/// alone when it owns >20 differing leaves. Returns `(paths, total_leaf_count)`.
pub fn diff_fields(old: &Map<String, Value>, new: &Map<String, Value>) -> (Vec<String>, usize) {
    let mut leaves: Vec<String> = Vec::new();
    let mut keys: BTreeSet<&String> = old.keys().collect();
    keys.extend(new.keys());
    for k in keys {
        let mut path = vec![k.clone()];
        diff_walk(old.get(k), new.get(k), &mut path, 1, &mut leaves);
    }
    let leaf_count = leaves.len();
    let mut by_top: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for p in leaves {
        let top = p.split('.').next().unwrap_or_default().to_string();
        by_top.entry(top).or_default().push(p);
    }
    let mut paths: Vec<String> = Vec::new();
    for (top, ps) in by_top {
        if ps.len() > DIFF_COLLAPSE_AT {
            paths.push(top);
        } else {
            paths.extend(ps);
        }
    }
    (paths, leaf_count)
}

/// Per-snapshot delta counters.
#[derive(Debug, Clone, Default)]
pub struct RunDelta {
    pub new: usize,
    pub changed: usize,
    pub removed: usize,
    pub unchanged: usize,
}

impl RunDelta {
    pub fn to_json(&self) -> Value {
        json!({
            "new": self.new, "changed": self.changed,
            "removed": self.removed, "unchanged": self.unchanged,
        })
    }
}

/// One record of the requested snapshot, annotated vs its previous version.
#[derive(Debug, Clone)]
pub struct RunDetailRow {
    pub record_index: usize,
    pub uid: String,
    pub change: &'static str,
    pub changed_fields: Vec<String>,
    pub changed_leaf_count: usize,
    /// Change-point count AS OF this snapshot (walk-time, matching the python engines'
    /// `run_views`) — NOT the whole-chain total.
    pub versions: usize,
    pub fields: Map<String, Value>,
}

/// The `view=run` payload for one snapshot: its rows, the records that vanished vs the previous
/// chain member, and the delta counters.
#[derive(Debug, Clone)]
pub struct RunDetail {
    pub run_id: i64,
    pub prev_run_id: Option<i64>,
    pub delta: RunDelta,
    pub rows: Vec<RunDetailRow>,
    /// (uid, last-version fields) for records in the previous snapshot but not this one.
    pub removed: Vec<(String, Map<String, Value>)>,
}

/// The lineage pass output. `runs_index` / `latest` / `histories` are golden-shaped JSON values
/// (see data_lineage_golden.json); `first_seen` / `last_seen` index every uid ever seen in the
/// scanned window.
#[derive(Debug, Clone, Default)]
pub struct Lineage {
    /// Snapshot index entries, newest first.
    pub runs_index: Vec<Value>,
    /// Deduped current dataset, default-sorted (change rank, last_seen desc, uid asc).
    pub latest: Vec<Value>,
    /// uid → change-point versions (oldest→newest; the first entry has changed_fields=[]).
    pub histories: BTreeMap<String, Vec<Value>>,
    pub first_seen: BTreeMap<String, String>,
    pub last_seen: BTreeMap<String, String>,
    pub run_detail: Option<RunDetail>,
}

/// Walk the snapshot chain (the data-bearing runs, in the order given — ascending) computing
/// per-run deltas, change-point histories and the deduped latest rows. Per-record `change` is
/// always vs the record's previous VERSION (its last appearance), not snapshot membership.
/// `detail_run` additionally materializes that snapshot's per-record annotations for `view=run`.
pub fn build_lineage(
    runs: &[FlatRun],
    mode: &str,
    fields: &[String],
    detail_run: Option<i64>,
) -> Lineage {
    let chain: Vec<&FlatRun> = runs.iter().filter(|r| r.data_bearing).collect();
    // uid → (fields, run_id, run_at, record_index) of the last version seen.
    let mut last_version: BTreeMap<String, (Map<String, Value>, i64, String, usize)> = BTreeMap::new();
    let mut first_seen: BTreeMap<String, String> = BTreeMap::new();
    let mut last_seen: BTreeMap<String, String> = BTreeMap::new();
    let mut change_points: BTreeMap<String, Vec<Value>> = BTreeMap::new();
    // uid → (change, changed_fields, changed_leaf_count) as of its newest appearance.
    let mut latest_status: BTreeMap<String, (&'static str, Vec<String>, usize)> = BTreeMap::new();
    let mut runs_index: Vec<Value> = Vec::new();
    let mut prev_uids: Option<BTreeSet<String>> = None;
    let mut prev_run_id: Option<i64> = None;
    let mut run_detail: Option<RunDetail> = None;

    for run in &chain {
        let run_at = run.run_at.clone().unwrap_or_default();
        let want_detail = detail_run == Some(run.run_id);
        let mut detail_rows: Vec<RunDetailRow> = Vec::new();
        let mut cur: BTreeSet<String> = BTreeSet::new();
        let mut delta = RunDelta::default();
        for (uid, idx, rec) in assign_uids(&run.records, mode, fields) {
            cur.insert(uid.clone());
            let (change, paths, leaf_count): (&'static str, Vec<String>, usize) =
                if !first_seen.contains_key(&uid) {
                    first_seen.insert(uid.clone(), run_at.clone());
                    delta.new += 1;
                    change_points.entry(uid.clone()).or_default().push(json!({
                        "run_id": run.run_id, "run_at": run_at, "record_index": idx,
                        "fields": &rec, "changed_fields": [], "changed_leaf_count": 0,
                    }));
                    ("new", Vec::new(), 0)
                } else {
                    let prev = &last_version[&uid];
                    let (paths, leaf_count) = diff_fields(&prev.0, &rec);
                    if !paths.is_empty() {
                        delta.changed += 1;
                        change_points.entry(uid.clone()).or_default().push(json!({
                            "run_id": run.run_id, "run_at": run_at, "record_index": idx,
                            "fields": &rec, "changed_fields": &paths, "changed_leaf_count": leaf_count,
                        }));
                        ("changed", paths, leaf_count)
                    } else {
                        delta.unchanged += 1;
                        ("same", Vec::new(), 0)
                    }
                };
            latest_status.insert(uid.clone(), (change, paths.clone(), leaf_count));
            last_seen.insert(uid.clone(), run_at.clone());
            last_version.insert(uid.clone(), (rec.clone(), run.run_id, run_at.clone(), idx));
            if want_detail {
                detail_rows.push(RunDetailRow {
                    record_index: idx,
                    // Walk-time version count: change-points recorded up to and including this
                    // snapshot (python `run_views` parity — never the end-of-chain total).
                    versions: change_points.get(&uid).map_or(0, Vec::len),
                    uid,
                    change,
                    changed_fields: paths,
                    changed_leaf_count: leaf_count,
                    fields: rec,
                });
            }
        }
        let mut removed: Vec<(String, Map<String, Value>)> = Vec::new();
        if let Some(prev) = &prev_uids {
            for uid in prev {
                if !cur.contains(uid) {
                    delta.removed += 1;
                    if want_detail {
                        removed.push((uid.clone(), last_version[uid].0.clone()));
                    }
                }
            }
        }
        runs_index.push(json!({
            "run_id": run.run_id, "run_at": run_at,
            "record_count": run.records.len(),
            "explicit_empty": run.records.is_empty(),
            "delta": if prev_uids.is_none() { Value::Null } else { delta.to_json() },
        }));
        if want_detail {
            run_detail = Some(RunDetail {
                run_id: run.run_id,
                prev_run_id,
                delta: delta.clone(),
                rows: detail_rows,
                removed,
            });
        }
        prev_uids = Some(cur);
        prev_run_id = Some(run.run_id);
    }

    let newest = prev_uids.unwrap_or_default();
    let mut latest: Vec<Value> = Vec::new();
    for (uid, (rec, run_id, _run_at, idx)) in &last_version {
        let (change, paths, leaf_count) = if newest.contains(uid) {
            latest_status[uid].clone()
        } else {
            ("missing", Vec::new(), 0)
        };
        latest.push(json!({
            "uid": uid, "change": change,
            "changed_fields": paths, "changed_leaf_count": leaf_count,
            "first_seen_at": &first_seen[uid], "last_seen_at": &last_seen[uid],
            "versions": change_points[uid].len(), "fields": rec,
            "run_id": run_id, "record_index": idx,
        }));
    }
    // Default sort: change rank asc, last_seen desc, uid asc — the golden-pinned tie-break.
    let rank = |v: &Value| match v["change"].as_str().unwrap_or_default() {
        "new" => 0u8,
        "changed" => 1,
        "same" => 2,
        _ => 3,
    };
    latest.sort_by(|a, b| {
        (
            rank(a),
            std::cmp::Reverse(a["last_seen_at"].as_str().unwrap_or_default()),
            a["uid"].as_str().unwrap_or_default(),
        )
            .cmp(&(
                rank(b),
                std::cmp::Reverse(b["last_seen_at"].as_str().unwrap_or_default()),
                b["uid"].as_str().unwrap_or_default(),
            ))
    });
    runs_index.reverse(); // newest first

    Lineage { runs_index, latest, histories: change_points, first_seen, last_seen, run_detail }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    // ── Markdown / HTML output (`?format=markdown|html`) ────────────────────
    // Mirrors the cloud backend so the cloud and the daemon
    // agree on shape detection, front-matter stripping and the XSS posture.

    fn mk_row(idx: usize, fields: Value) -> Row {
        Row {
            run_id: 1,
            run_at: Some("2026-07-16T22:00:00Z".into()),
            status: Some("success".into()),
            success: Some(true),
            duration_ms: Some(10),
            record_index: idx,
            fields: fields.as_object().unwrap().clone(),
            inputs: Map::new(),
        }
    }

    fn long_text() -> String { "y".repeat(300) }

    fn doc_rows() -> Vec<Row> {
        vec![mk_row(0, json!({
            "url": "https://ex.test/a", "title": "Page A",
            "markdown": format!("# H\n\n{}", long_text()),
        }))]
    }

    fn table_rows() -> Vec<Row> {
        vec![
            mk_row(0, json!({"author": "demo", "text": "short | piped"})),
            mk_row(1, json!({"author": "bob", "text": "also short"})),
        ]
    }

    fn cols(v: &[&str]) -> Vec<String> { v.iter().map(|s| s.to_string()).collect() }

    #[test]
    fn content_column_detects_documents_not_short_text() {
        assert_eq!(
            content_column(&cols(&["url", "title", "markdown"]), &doc_rows()),
            Some("markdown".to_string())
        );
        // A SHORT `text` column must NOT flip a structured dataset into document mode.
        assert_eq!(content_column(&cols(&["author", "text"]), &table_rows()), None);
        assert_eq!(content_column(&cols(&["markdown"]), &[]), None);
    }

    #[test]
    fn strip_front_matter_only_at_start() {
        let fm = "---\ntitle: \"A\"\nurl: \"https://x.test\"\n---\n\nReal body.";
        assert_eq!(strip_front_matter(fm), "Real body.");
        // A mid-document thematic break is NOT front matter and must survive.
        let body = "Intro para.\n\n---\n\nAfter the rule.";
        assert_eq!(strip_front_matter(body), body);
        assert_eq!(strip_front_matter("# Just a heading"), "# Just a heading");
        assert_eq!(strip_front_matter(""), "");
    }

    #[test]
    fn safe_link_scheme_allowlist() {
        assert_eq!(safe_link("https://a.test/x").as_deref(), Some("https://a.test/x"));
        assert_eq!(safe_link("mailto:a@b.test").as_deref(), Some("mailto:a@b.test"));
        assert_eq!(safe_link("/relative/path").as_deref(), Some("/relative/path"));
        for bad in ["javascript:alert(1)", "vbscript:x", "data:text/html,<script>", "file:///etc/passwd"] {
            assert!(safe_link(bad).is_none(), "{bad} must be rejected");
        }
    }

    #[test]
    fn to_markdown_documents_and_table() {
        let md = to_markdown(&cols(&["url", "title", "markdown"]), &doc_rows(), Some("DS"));
        assert!(md.contains("# DS"));
        assert!(md.contains("## Page A"));
        assert!(md.contains("<https://ex.test/a>"));
        assert!(!md.contains("| run_id |"), "documents, not a table");

        let tbl = to_markdown(&cols(&["author", "text"]), &table_rows(), None);
        assert!(tbl.starts_with("| run_id | run_at | status | author | text |"));
        assert!(tbl.contains("short \\| piped"), "pipes escaped so the grid survives");
    }

    #[test]
    fn to_html_documents_and_table() {
        let h = to_html(&cols(&["url", "title", "markdown"]), &doc_rows(), Some("DS"));
        assert!(h.contains("<article>"));
        assert!(h.contains("<h2>Page A</h2>"));
        assert!(h.contains("href=\"https://ex.test/a\""));

        let t = to_html(&cols(&["author", "text"]), &table_rows(), None);
        assert!(t.contains("<table>"));
        assert!(t.contains("<th>author</th>"));
        assert!(!t.contains("<article>"));
    }

    #[test]
    fn documents_drop_front_matter_and_keep_heading() {
        let rows = vec![mk_row(0, json!({
            "url": "https://ex.test/a", "title": "Page A",
            "markdown": format!("---\ntitle: \"Page A\"\nurl: \"https://ex.test/a\"\n---\n\n{}", long_text()),
        }))];
        let h = to_html(&cols(&["url", "title", "markdown"]), &rows, None);
        assert!(h.contains("<h2>Page A</h2>"));
        assert!(!h.contains("title: &quot;Page A&quot;"), "raw front matter must be gone");
        assert!(!h.contains("<hr />"), "no stray rule from the `---` delimiter");
    }

    #[test]
    fn to_html_neutralizes_hostile_scraped_content() {
        // format=html echoes scraped third-party content, so no live markup or
        // unsafe URL scheme may survive into the output.
        let hostile = format!(
            "{}\n\n<script>alert('xss')</script>\n\n<img src=x onerror=alert(1)>\n\n\
             [a](javascript:alert(1))\n\n[b](vbscript:x)\n\n[ok](https://example.com)",
            long_text()
        );
        let rows = vec![mk_row(0, json!({
            "url": "https://ex.test/x", "title": "T", "markdown": hostile,
        }))];
        let h = to_html(&cols(&["url", "title", "markdown"]), &rows, None);
        let body = h.split("<article>").nth(1).unwrap().to_string();

        assert!(!body.contains("<script"), "raw script must be escaped, not live");
        assert!(!body.contains("<img src=x"), "raw img must be escaped, not live");
        assert!(body.contains("&lt;script&gt;"), "…escaped to inert text instead");
        assert!(body.contains("&lt;img"), "…escaped to inert text instead");
        assert!(!body.contains("href=\"javascript:"), "unsafe scheme must never reach an href");
        assert!(!body.contains("href=\"vbscript:"), "unsafe scheme must never reach an href");
        assert!(body.contains("href=\"https://example.com\""), "…while a safe link still renders");
    }

    fn run(id: i64, result: Value, ctx: Value) -> RunInput {
        RunInput {
            run_id: id,
            run_at: Some(format!("2026-06-2{id}T00:00:00Z")),
            status: Some("success".into()),
            success: Some(true),
            duration_ms: Some(100),
            result_data: result,
            trigger_context: ctx,
        }
    }

    fn col_text(rows: &[Row], col: &str) -> Vec<String> {
        rows.iter().map(|r| cell_text(&r.value(col))).collect()
    }

    // ------------------------------------------------------------------
    // Datasets full-text search helpers.
    // ------------------------------------------------------------------

    #[test]
    fn search_term_parsing_and_match_query() {
        assert_eq!(parse_search_terms("Amaz  Store-front 99!"), vec!["amaz", "store", "front", "99"]);
        assert_eq!(parse_search_terms("a a a"), vec!["a"]); // de-duped
        assert!(parse_search_terms("   ").is_empty());
        assert_eq!(parse_search_terms("").len(), 0);
        assert_eq!(fts5_match_query(&["amaz".into(), "store".into()]), "amaz* store*");
    }

    #[test]
    fn search_record_filter_and_highlight() {
        let r = run(1, json!({"extracted_data": [{"title": "Amazon Paris storefront"}]}), json!({}));
        let (_cols, rows) = flatten(&[r], &[], false);
        let row = &rows[0];
        // Every term must be present (AND).
        assert!(search_matches_all(row, &parse_search_terms("amazon paris")));
        assert!(!search_matches_all(row, &parse_search_terms("amazon berlin")));
        // Highlight names the field and carries the match.
        let hl = search_highlight(row, &parse_search_terms("paris"));
        assert_eq!(hl["field"], "title");
        assert!(hl["snippet"].as_str().unwrap().to_lowercase().contains("paris"));
        // No match → null highlight.
        assert!(search_highlight(row, &parse_search_terms("zzz")).is_null());
    }

    /// REGRESSION: the highlight took `low.find(term)` — a byte offset into the LOWERCASED string —
    /// and sliced `txt[..pos]` with it. Lowercasing can change the UTF-8 byte length (`İ` U+0130 is
    /// 2 bytes and lowercases to 3), so that offset could land mid-codepoint in the original and
    /// panic, permanently breaking `GET /v1/datasets/search?q=` for the dataset.
    #[test]
    fn search_highlight_survives_case_folding_that_changes_byte_length() {
        // `İ` (U+0130, 2 bytes) lowercases to `i` + U+0307 (3 bytes) — every occurrence shifts the
        // byte offsets of everything after it, so the raw `find` offset is wrong in `txt`.
        let text = format!("{}needle tail", "İ".repeat(40));
        let r = run(1, json!({"extracted_data": [{"title": text}]}), json!({}));
        let (_cols, rows) = flatten(&[r], &[], false);
        let hl = search_highlight(&rows[0], &parse_search_terms("needle"));
        assert_eq!(hl["field"], "title");
        assert!(
            hl["snippet"].as_str().unwrap().contains("needle"),
            "snippet lost the match: {hl}"
        );

        // Same hazard with other folding-sensitive and multi-byte inputs, plus a match right at the
        // very end (window clamped to the string's own char length).
        for prefix in ["ẛ", "Σ", "🙂", "漢"] {
            for n in 0..40usize {
                let text = format!("{}needle", prefix.repeat(n));
                let r = run(1, json!({"extracted_data": [{"c": text}]}), json!({}));
                let (_cols, rows) = flatten(&[r], &[], false);
                let hl = search_highlight(&rows[0], &parse_search_terms("needle"));
                assert!(!hl.is_null(), "prefix={prefix} n={n}");
            }
        }
    }

    // ------------------------------------------------------------------
    // SECURITY: the internal envelope must NEVER surface as a column or cell.
    // ------------------------------------------------------------------

    #[test]
    fn redaction_drops_envelope_keys_from_extracted_data() {
        // A run whose extracted_data record carries real fields alongside the internal
        // envelope (cookies / auth_session / raw_html / html / screenshots).
        let r = run(
            1,
            json!({
                "extracted_data": {
                    "title": "Hello",
                    "price": 42,
                    "cookies": "session=topsecret; auth=abc",
                    "auth_session": {"token": "leak-me"},
                    "raw_html": "<html>...</html>",
                    "html": "<div>nope</div>",
                    "screenshots": ["data:image/png;base64,AAAA"],
                    "_error_context": {"trace": "boom"},
                    "ai_repair_attempted": true,
                    "captcha_detected": false
                }
            }),
            Value::Null,
        );
        let declared: Vec<String> = vec![];
        let (columns, rows) = flatten(&[r], &declared, false);

        // Real fields survive.
        assert!(columns.contains(&"title".to_string()));
        assert!(columns.contains(&"price".to_string()));

        // Envelope / control keys must NOT be columns.
        for banned in [
            "cookies",
            "auth_session",
            "raw_html",
            "html",
            "screenshots",
            "_error_context",
            "ai_repair_attempted",
            "captcha_detected",
        ] {
            assert!(
                !columns.contains(&banned.to_string()),
                "banned column leaked: {banned}"
            );
        }

        // And the values must not appear anywhere in the serialized table (CSV nor JSON).
        let csv = to_csv(&columns, &rows);
        let json_blob = serde_json::to_string(&rows_to_json(&rows, &columns)).unwrap();
        for secret in ["topsecret", "leak-me", "<html>", "nope", "base64,AAAA", "boom"] {
            assert!(!csv.contains(secret), "secret leaked into CSV: {secret}");
            assert!(!json_blob.contains(secret), "secret leaked into JSON: {secret}");
        }
    }

    #[test]
    fn table_json_nests_columns_under_fields() {
        // The desktop table reads each cell from `row.fields[col]`. Regression guard: the table
        // serializer must nest data columns under `fields` (run-meta stays top-level), NOT flatten
        // them onto the row — a flat row renders every data cell blank in the UI.
        let r = run(1, json!({ "extracted_data": { "title": "Hello", "price": 42 } }), Value::Null);
        let declared: Vec<String> = vec![];
        let (columns, rows) = flatten(&[r], &declared, false);
        let json = rows_to_table_json(&rows, &columns);

        assert_eq!(json.len(), 1);
        let row = &json[0];
        // run-meta at the top level
        assert_eq!(row["run_id"], json!(1));
        assert_eq!(row["status"], json!("success"));
        // data columns under `fields`
        assert_eq!(row["fields"]["title"], json!("Hello"));
        assert_eq!(row["fields"]["price"], json!(42));
        // and NOT flattened onto the row
        assert!(row.get("title").is_none(), "data column must not be flat on the row");
    }

    #[test]
    fn redaction_drops_nested_envelope_and_secret_keys() {
        // Audit regression: redaction was top-level only. A record with NESTED internal-envelope
        // keys (cookies/auth_session) and NESTED secret-shaped keys (password/token), with NO
        // declared output fields, must not leak those nested values into the table/CSV/JSON.
        // Single-object record (top-level keys name + profile, NO top-level list → not unwrapped).
        // The nested array lives INSIDE `profile` so we also exercise array-recursion.
        let r = run(
            7,
            json!({
                "extracted_data": {
                    "name": "Bob",
                    "profile": {
                        "city": "Lyon",
                        "cookies": "sid=deep-secret",
                        "password": "deep-pw",
                        "items": [
                            { "label": "x", "auth_session": "arr-secret", "api_key": "arr-key" }
                        ]
                    }
                }
            }),
            Value::Null,
        );
        let declared: Vec<String> = vec![];
        let (columns, rows) = flatten(&[r], &declared, false);

        // Non-secret fields survive (including nested structure).
        assert!(columns.contains(&"name".to_string()));
        assert!(columns.contains(&"profile".to_string()));
        let csv = to_csv(&columns, &rows);
        let json_blob = serde_json::to_string(&rows_to_json(&rows, &columns)).unwrap();
        for keep in ["Bob", "Lyon", "x"] {
            assert!(json_blob.contains(keep), "expected value dropped: {keep}");
        }
        // Nested envelope + secret values must NOT appear anywhere.
        for secret in ["deep-secret", "deep-pw", "arr-secret", "arr-key"] {
            assert!(!csv.contains(secret), "nested secret leaked into CSV: {secret}");
            assert!(!json_blob.contains(secret), "nested secret leaked into JSON: {secret}");
        }
    }

    #[test]
    fn redaction_drops_secret_inputs() {
        // include_inputs surfaces form values as input.<name> columns — but secret-shaped keys
        // (password / otp / token / cvv / api_key / pan / ssn) must be dropped entirely.
        let ctx = json!({
            "_queued_form_data": {
                "username": "alice",
                "city": "Paris",
                "password": "hunter2",
                "otp": "123456",
                "api_key": "sk-live-xyz",
                "card_cvv": "999",
                "pan": "4111111111111111",
                "ssn": "078-05-1120",
                "auth_token": "bearer-leak"
            }
        });
        let r = run(2, json!({"extracted_data": {"ok": "yes"}}), ctx);
        let declared: Vec<String> = vec![];
        let (columns, rows) = flatten(&[r], &declared, true);

        // Non-secret inputs become input.<name> columns.
        assert!(columns.contains(&"input.username".to_string()));
        assert!(columns.contains(&"input.city".to_string()));

        // Secret-shaped inputs must NOT appear as columns.
        for banned in [
            "input.password",
            "input.otp",
            "input.api_key",
            "input.card_cvv",
            "input.pan",
            "input.ssn",
            "input.auth_token",
        ] {
            assert!(!columns.contains(&banned.to_string()), "secret input leaked: {banned}");
        }

        // Nor anywhere in the serialized output.
        let csv = to_csv(&columns, &rows);
        let json_blob = serde_json::to_string(&rows_to_json(&rows, &columns)).unwrap();
        for secret in ["hunter2", "123456", "sk-live-xyz", "999", "4111111111111111", "078-05-1120", "bearer-leak"] {
            assert!(!csv.contains(secret), "secret input leaked into CSV: {secret}");
            assert!(!json_blob.contains(secret), "secret input leaked into JSON: {secret}");
        }
    }

    #[test]
    fn top_level_fallback_strips_reserved_and_envelope() {
        // No extracted_data — data surfaced at the top level. Reserved/envelope keys must be
        // dropped before the fallback so auth_session/cookies/screenshots never become columns.
        let r = run(
            3,
            json!({
                "name": "widget",
                "auth_session": {"t": "leak"},
                "cookies": "c=leak",
                "screenshots": ["leak.png"],
                "success": true,
                "workflow_id": 9
            }),
            Value::Null,
        );
        let declared: Vec<String> = vec![];
        let (columns, rows) = flatten(&[r], &declared, false);
        assert!(columns.contains(&"name".to_string()));
        for banned in ["auth_session", "cookies", "screenshots", "success", "workflow_id"] {
            assert!(!columns.contains(&banned.to_string()), "leaked: {banned}");
        }
        let csv = to_csv(&columns, &rows);
        assert!(!csv.contains("leak"));
    }

    // ------------------------------------------------------------------
    // Record coercion: list -> one row per item; wrapper -> inner record.
    // ------------------------------------------------------------------

    #[test]
    fn list_extracted_data_becomes_one_row_per_item() {
        let r = run(
            4,
            json!({"extracted_data": [
                {"name": "a", "price": 3},
                {"name": "b", "price": 12},
                {"name": "c", "price": 1}
            ]}),
            Value::Null,
        );
        let (columns, rows) = flatten(&[r], &[], false);
        assert_eq!(rows.len(), 3);
        assert!(columns.contains(&"name".to_string()));
        assert!(columns.contains(&"price".to_string()));
    }

    #[test]
    fn multi_dataset_lists_all_expand_into_rows() {
        // Reproduces workflow 46: a multi-dataset API build stores one list per variable. Every
        // non-empty list must expand — not only the single-list case (which yielded 0 rows before).
        let declared = vec![
            "name".to_string(), "description".to_string(), "workflow_type".to_string(),
            "url".to_string(), "checkType".to_string(),
        ];
        let r = run(
            10,
            json!({"extracted_data": {
                "get_workflows_list": [{"name": "APD PEEL", "description": "sales", "workflow_type": "Recorded"}],
                "get_targets_list": [
                    {"url": "https://korben.info", "checkType": "content"},
                    {"url": "https://platform.openai.com/", "checkType": "content"}
                ]
            }}),
            Value::Null,
        );
        let (_cols, rows) = flatten(&[r], &declared, false);
        // 1 workflow row + 2 target rows = 3, all projected to the declared columns (row order is by
        // variable key, so assert order-agnostically).
        assert_eq!(rows.len(), 3, "all list keys should expand into rows");
        let names: std::collections::HashSet<String> = col_text(&rows, "name").into_iter().filter(|s| !s.is_empty()).collect();
        let urls: std::collections::HashSet<String> = col_text(&rows, "url").into_iter().filter(|s| !s.is_empty()).collect();
        assert_eq!(names, ["APD PEEL".to_string()].into_iter().collect());
        assert_eq!(urls, ["https://korben.info".to_string(), "https://platform.openai.com/".to_string()].into_iter().collect());
    }

    #[test]
    fn wrapper_object_unwraps_to_inner_record() {
        let r = run(5, json!({"extracted_data": {"result": {"sku": "X1", "qty": 7}}}), Value::Null);
        let (columns, rows) = flatten(&[r], &[], false);
        assert_eq!(rows.len(), 1);
        assert!(columns.contains(&"sku".to_string()));
        assert_eq!(cell_text(&rows[0].value("qty")), "7");
    }

    // ------------------------------------------------------------------
    // Filter + sort.
    // ------------------------------------------------------------------

    #[test]
    fn global_q_filter_narrows_rows() {
        let r = run(
            6,
            json!({"extracted_data": [
                {"city": "Paris"},
                {"city": "Lyon"},
                {"city": "Paris"}
            ]}),
            Value::Null,
        );
        let (_cols, _rows) = flatten(std::slice::from_ref(&r), &[], false);
        let table = build_table(
            &[r],
            &[],
            &TableQuery { q: Some("paris".into()), ..Default::default() },
            false,
        );
        assert_eq!(table.total, 2);
        assert!(table.rows.iter().all(|row| cell_text(&row.value("city")) == "Paris"));
    }

    #[test]
    fn numeric_sort_orders_numbers_not_lexically() {
        let r = run(
            7,
            json!({"extracted_data": [
                {"price": "3"},
                {"price": "12"},
                {"price": "1"}
            ]}),
            Value::Null,
        );
        let table = build_table(
            &[r],
            &[],
            &TableQuery {
                sort_by: Some("price".into()),
                sort_dir: "asc".into(),
                ..Default::default()
            },
            false,
        );
        assert_eq!(col_text(&table.rows, "price"), vec!["1", "3", "12"]);
    }

    #[test]
    fn structured_between_and_in_clauses() {
        let r = run(
            8,
            json!({"extracted_data": [
                {"city": "Paris", "price": 5},
                {"city": "Lyon", "price": 50},
                {"city": "Paris", "price": 500}
            ]}),
            Value::Null,
        );
        // between 1..100 on price -> 2 rows
        let t1 = build_table(
            std::slice::from_ref(&r),
            &[],
            &TableQuery {
                filters: vec![Clause {
                    col: "price".into(),
                    op: "between".into(),
                    value: None,
                    values: None,
                    min: Some(json!(1)),
                    max: Some(json!(100)),
                }],
                ..Default::default()
            },
            false,
        );
        assert_eq!(t1.total, 2);

        // in [Lyon] on city -> 1 row
        let t2 = build_table(
            &[r],
            &[],
            &TableQuery {
                filters: vec![Clause {
                    col: "city".into(),
                    op: "in".into(),
                    value: None,
                    values: Some(vec![json!("Lyon")]),
                    min: None,
                    max: None,
                }],
                ..Default::default()
            },
            false,
        );
        assert_eq!(t2.total, 1);
        assert_eq!(cell_text(&t2.rows[0].value("city")), "Lyon");
    }

    #[test]
    fn declared_fields_project_and_order_columns() {
        // Declared output fields restrict + order the columns; extra keys are dropped.
        let r = run(
            9,
            json!({"extracted_data": {"price": 9, "title": "T", "secret_blob": "x"}}),
            Value::Null,
        );
        let declared = vec!["title".to_string(), "price".to_string()];
        let (columns, _rows) = flatten(&[r], &declared, false);
        assert_eq!(columns, vec!["title".to_string(), "price".to_string()]);
        assert!(!columns.contains(&"secret_blob".to_string()));
    }

    #[test]
    fn facets_infer_types_and_distinct() {
        let r = run(
            10,
            json!({"extracted_data": [
                {"price": 5, "city": "Paris"},
                {"price": 9, "city": "Lyon"},
                {"price": 5, "city": "Paris"}
            ]}),
            Value::Null,
        );
        let (columns, rows) = flatten(&[r], &[], false);
        let facets = compute_facets(&columns, &rows);
        let f = facets.as_object().unwrap();
        assert_eq!(f["price"]["type"], json!("number"));
        assert_eq!(f["city"]["type"], json!("text"));
        // status facet is always present.
        assert!(f.contains_key("status"));
        // city distinct pick-list present (low cardinality).
        assert!(f["city"]["distinct"].is_array());
    }

    #[test]
    fn csv_quotes_fields_with_commas_and_quotes() {
        let r = run(11, json!({"extracted_data": {"note": "a,b \"c\""}}), Value::Null);
        let (columns, rows) = flatten(&[r], &[], false);
        let csv = to_csv(&columns, &rows);
        assert!(csv.contains("\"a,b \"\"c\"\"\""));
    }

    #[test]
    fn is_word_pan_boundary() {
        assert!(is_secret_input_key("pan"));
        assert!(is_secret_input_key("PAN"));
        assert!(!is_secret_input_key("panel")); // not a whole word
        assert!(!is_secret_input_key("company")); // contains "pan" mid-word
    }

    // ------------------------------------------------------------------
    // Golden vectors (DATA_REDESIGN_SPEC) — the vendored copy of
    // shared/data_lineage_golden.json pins norm/uid/coercion/identity/lineage
    // cross-engine. Never edit the JSON; the reference implementation
    // shared/data_lineage_golden_gen.py is its only generator.
    // ------------------------------------------------------------------

    fn golden() -> Value {
        serde_json::from_str(include_str!("data_lineage_golden.json"))
            .expect("vendored golden vectors parse")
    }

    #[test]
    fn golden_norm_cases() {
        let g = golden();
        for case in g["norm_cases"].as_array().unwrap() {
            assert_eq!(
                norm(&case["value"]),
                case["expected"].as_str().unwrap(),
                "norm mismatch [{}]",
                case["note"]
            );
        }
    }

    #[test]
    fn golden_uid_cases() {
        let g = golden();
        for case in g["uid_cases"].as_array().unwrap() {
            let fields: Vec<String> = case["identity_fields"]
                .as_array()
                .unwrap()
                .iter()
                .map(|v| v.as_str().unwrap().to_string())
                .collect();
            let rec = case["record"].as_object().unwrap();
            let ordinal = case["ordinal"].as_u64().unwrap() as usize;
            let singleton = case["singleton"].as_bool().unwrap();
            assert_eq!(
                uid_digest_input(&fields, rec, ordinal, singleton),
                case["digest_input"].as_str().unwrap(),
                "digest input mismatch [{}]",
                case["note"]
            );
            assert_eq!(
                record_uid(&fields, rec, ordinal, singleton),
                case["expected_uid"].as_str().unwrap(),
                "uid mismatch [{}]",
                case["note"]
            );
        }
    }

    /// Every scenario must reproduce `expected` exactly (latest array order included), running
    /// through the REAL engine path: result_data → flatten_runs → identity ladder → lineage.
    #[test]
    fn golden_scenarios() {
        let g = golden();
        for sc in g["scenarios"].as_array().unwrap() {
            let name = sc["name"].as_str().unwrap();
            let input = &sc["input"];
            let expected = &sc["expected"];
            let declared: Vec<String> = input["declared_fields"]
                .as_array()
                .unwrap()
                .iter()
                .map(|v| v.as_str().unwrap().to_string())
                .collect();
            let key = input["key"].as_str();
            let runs: Vec<RunInput> = input["runs"]
                .as_array()
                .unwrap()
                .iter()
                .map(|r| RunInput {
                    run_id: r["run_id"].as_i64().unwrap(),
                    run_at: Some(r["run_at"].as_str().unwrap().to_string()),
                    status: Some("success".into()),
                    success: Some(true),
                    duration_ms: None,
                    result_data: json!({ "success": true, "extracted_data": r["extracted_data"] }),
                    trigger_context: Value::Null,
                })
                .collect();

            let flat = flatten_runs(&runs, &declared);
            let flat_json: Vec<Value> = flat
                .iter()
                .map(|fr| {
                    json!({
                        "run_id": fr.run_id,
                        "data_bearing": fr.data_bearing,
                        "records": fr.records.iter()
                            .map(|(i, f)| json!({ "record_index": i, "fields": f }))
                            .collect::<Vec<_>>(),
                    })
                })
                .collect();
            assert_eq!(&Value::Array(flat_json), &expected["flatten"], "flatten mismatch in {name}");

            let columns = canonical_columns(&flat, &declared);
            let bearing: Vec<Vec<Map<String, Value>>> = flat
                .iter()
                .filter(|r| r.data_bearing)
                .map(|r| r.records.iter().map(|(_, m)| m.clone()).collect())
                .collect();
            let start = bearing.len().saturating_sub(50);
            let ident = choose_identity(&bearing[start..], &columns, key);
            assert_eq!(&ident.to_json(), &expected["identity"], "identity mismatch in {name}");

            let lineage = build_lineage(&flat, ident.mode, &ident.fields, None);
            assert_eq!(
                &Value::Array(lineage.runs_index.clone()),
                &expected["runs_index"],
                "runs_index mismatch in {name}"
            );
            assert_eq!(
                &Value::Array(lineage.latest.clone()),
                &expected["latest"],
                "latest mismatch in {name}"
            );
            let histories = Value::Object(
                lineage
                    .histories
                    .iter()
                    .map(|(uid, versions)| (uid.clone(), Value::Array(versions.clone())))
                    .collect(),
            );
            assert_eq!(&histories, &expected["histories"], "histories mismatch in {name}");
        }
    }
}
