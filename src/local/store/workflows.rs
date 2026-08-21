//! Store layer for the `workflows` table (0001_init.sql §1).
//!
//! Runtime-checked sqlx only (no compile-time macros — no DATABASE_URL/offline data). One row
//! struct (`Workflow`) maps the full table; `NewWorkflow` carries only the caller-supplied insert
//! fields, letting the schema defaults fill the rest. JSON-TEXT columns (`steps`, `raw_replay`,
//! `form_data`, …) stay `String` — callers serde them. `credentials_encrypted` is a sealed Layer-B
//! secret (`WF1:` blob): NEVER logged.

use super::super::error::{LocalError, LocalResult};
use sqlx::sqlite::SqlitePool;
use sqlx::Row as _;

/// Deserialize a JSON-TEXT column from the API. Accepts EITHER a pre-serialized JSON string OR a
/// rich JSON value (array/object/number/bool) and normalizes both to the stored `Option<String>`
/// text form. The desktop frontend — mirroring the Writ Cloud contract — sends `steps`, `form_data`,
/// `functions`, `streaming_config`, … as real arrays/objects, NOT strings; our SQLite columns are
/// TEXT, so a non-string value is serialized to compact JSON here. A value already given as a string
/// passes through untouched (assumed to already be JSON text). `null` / absent → `None`.
///
/// Without this, axum's `Json` extractor rejects the wizard's create/update body with `422` because
/// an array can't deserialize into `Option<String>`.
fn de_json_text_opt<'de, D>(de: D) -> Result<Option<String>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    use serde::Deserialize as _;
    Ok(match Option::<serde_json::Value>::deserialize(de)? {
        None | Some(serde_json::Value::Null) => None,
        Some(serde_json::Value::String(s)) => Some(s),
        Some(other) => Some(other.to_string()),
    })
}

/// Deserialize a 0/1 INTEGER flag column from the API, accepting EITHER a JSON bool (`true`/`false`
/// — how the frontend sends `headless` / `fast_mode` / `is_active` toggles) OR an integer. `null` /
/// absent → `None` (the column keeps its current value / schema default). Any non-zero integer is
/// truthy (→ 1).
fn de_bool_int_opt<'de, D>(de: D) -> Result<Option<i64>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    use serde::Deserialize as _;
    Ok(match Option::<serde_json::Value>::deserialize(de)? {
        None | Some(serde_json::Value::Null) => None,
        Some(serde_json::Value::Bool(b)) => Some(b as i64),
        Some(serde_json::Value::Number(n)) => Some((n.as_i64().unwrap_or(0) != 0) as i64),
        Some(other) => {
            return Err(serde::de::Error::custom(format!(
                "expected a bool or integer flag, got {other}"
            )))
        }
    })
}

/// AAD that binds a workflow's sealed `credentials_encrypted` (`WF1:`) blob to its row. Used at BOTH
/// the seal site (the create/update handlers) and the open site (the engine's run-time decrypt in
/// `engine::resolve`). Single source of truth so the two can never drift — a mismatch would make a
/// sealed blob un-openable. `id` is the workflow's primary key, a stable per-row identity that
/// prevents ciphertext relocation across workflows.
pub fn credentials_aad(workflow_id: i64) -> String {
    format!("workflows|credentials_encrypted|{workflow_id}")
}

/// AAD that binds a workflow's sealed `recorded_session_encrypted` (`WF1:`) blob — the RECORDING
/// browser's auth state pinned at save time (0026) — to its row. Same single-source-of-truth
/// contract as [`credentials_aad`]: the API create/update handlers seal with it, the engine's
/// run-time session resolver (`engine::http::load_session`) opens with it, and the after-run
/// refresh re-seals with it, so the sites can never drift. Binding the row id prevents ciphertext
/// relocation across workflows.
pub fn recorded_session_aad(workflow_id: i64) -> String {
    format!("workflows|recorded_session_encrypted|{workflow_id}")
}

/// A full `workflows` row.
#[derive(Debug, Clone, sqlx::FromRow, serde::Serialize, serde::Deserialize)]
pub struct Workflow {
    pub id: i64,
    pub name: String,
    #[serde(default)]
    pub description: Option<String>,
    pub workflow_type: String,
    pub steps: String,
    #[serde(default)]
    pub raw_replay: Option<String>,
    #[serde(default)]
    pub form_data: Option<String>,
    #[serde(default)]
    pub exit_condition: Option<String>,
    #[serde(default)]
    pub input_rules: Option<String>,
    #[serde(default)]
    pub api_functions: Option<String>,
    #[serde(default)]
    pub streaming_config: Option<String>,
    #[serde(default)]
    pub functions: Option<String>,
    /// Sealed `WF1:` Layer-B blob — never log this value.
    #[serde(default)]
    pub credentials_encrypted: Option<String>,
    #[serde(default)]
    pub entry_url: Option<String>,
    pub timeout_ms: i64,
    pub retry_count: i64,
    pub headless: i64,
    pub fast_mode: i64,
    pub is_active: i64,
    pub is_verified: i64,
    pub schedule_enabled: i64,
    #[serde(default)]
    pub schedule_interval_ms: Option<i64>,
    /// Structured recurrence kind: `interval` (default) | `daily` | `weekly`. `interval` uses
    /// `schedule_interval_ms`; daily/weekly use `schedule_time`/`schedule_days`/`schedule_tz`.
    /// `#[sqlx(default)]` keeps `SELECT *` paths (tests) working across the additive migration.
    #[serde(default)]
    #[sqlx(default)]
    pub schedule_kind: Option<String>,
    /// "HH:MM" local wall-clock fire time (daily/weekly).
    #[serde(default)]
    #[sqlx(default)]
    pub schedule_time: Option<String>,
    /// JSON array string of ISO weekday ints, 1=Mon … 7=Sun (weekly only).
    #[serde(default)]
    #[sqlx(default)]
    pub schedule_days: Option<String>,
    /// IANA tz name for daily/weekly (NULL ⇒ UTC).
    #[serde(default)]
    #[sqlx(default)]
    pub schedule_tz: Option<String>,
    #[serde(default)]
    pub last_scheduled_at: Option<String>,
    #[serde(default)]
    pub next_scheduled_at: Option<String>,
    pub session_persistence: i64,
    #[serde(default)]
    pub session_ttl_seconds: Option<i64>,
    #[serde(default)]
    pub login_url_patterns: Option<String>,
    pub relogin_max_retries: i64,
    /// Browserless HTTP lane sticky hint: -1 unknown (probe), 0 browser-only (fell back), 1 HTTP-proven.
    /// `#[sqlx(default)]` keeps `SELECT *` paths (tests) working across the additive 0015 migration.
    #[serde(default)]
    #[sqlx(default)]
    pub http_capable: i64,
    /// Declarative AuthRecipe JSON (login/refresh/probe/challenge). NULL = infer from a leading login_post.
    #[serde(default)]
    #[sqlx(default)]
    pub auth_config: Option<String>,
    /// Sealed Layer-B `WF1:` blob of the RECORDING browser's auth state (cookies / storage /
    /// fingerprint), pinned at save time (0026) as the replay seed for runs with no persona.
    /// `skip_serializing` is load-bearing: this struct serializes straight into API responses, and
    /// the sealed blob must never leave the store — the API exposes only `has_recorded_session` +
    /// the freshness stamp below. NEVER logged. `#[sqlx(default)]` keeps `SELECT *` paths (tests)
    /// working across the additive migration.
    #[serde(default, skip_serializing)]
    #[sqlx(default)]
    pub recorded_session_encrypted: Option<String>,
    /// When the recorded seed was captured / last refreshed (RFC3339), duplicated OUTSIDE the
    /// sealed blob so the UI can render freshness without a decrypt. NULL = nothing pinned.
    #[serde(default)]
    #[sqlx(default)]
    pub recorded_session_captured_at: Option<String>,
    #[serde(default)]
    pub default_persona_id: Option<i64>,
    #[serde(default)]
    pub estimated_duration_ms: Option<i64>,
    pub usage_count: i64,
    pub total_run_count: i64,
    pub total_failure_count: i64,
    pub consecutive_failures: i64,
    #[serde(default)]
    pub last_run_at: Option<String>,
    /// Status of the MOST RECENT run (`runs.status` of the latest run row), computed by a correlated
    /// subquery in `SELECT_COLS` — NOT a stored column. `None` when the workflow has never run. The
    /// desktop workflow row has no persisted run status (unlike the cloud), so the UI needs this to
    /// render "Succeeded / Failed / Running…" instead of always "Never run". `#[sqlx(default)]` keeps
    /// any `SELECT *` path (tests) working even though the alias is always present in real queries.
    #[serde(default)]
    #[sqlx(default)]
    pub last_run_status: Option<String>,
    /// Duration (ms) of the most recent run — same correlated-subquery source as `last_run_status`.
    #[serde(default)]
    #[sqlx(default)]
    pub last_run_duration_ms: Option<i64>,
    /// `1` when at least one SUCCESSFUL run produced a non-trivial `result_data` payload — a cheap
    /// SQL approximation of "has extracted data" for the list's Has-data filter (the exact row count
    /// still comes from the Data engine's flatten). `Option<i64>` (0/1) not `bool` to avoid any decode
    /// risk from a computed EXISTS. Correlated subquery in `SELECT_COLS`; `None` on pre-field sidecars.
    #[serde(default)]
    #[sqlx(default)]
    pub last_run_has_extracted_data: Option<i64>,
    #[serde(default)]
    pub last_failure_at: Option<String>,
    #[serde(default)]
    pub last_failure_error: Option<String>,
    pub cloud_callable: i64,
    /// Run-venue pin: `Some("local")`/`Some("cloud")` hard-routes this workflow to a specific agent;
    /// `None` = Auto (the app default). Surfaced to the desktop split "Run" button. `#[sqlx(default)]`
    /// keeps `SELECT *` paths (tests) working across the additive migration.
    #[serde(default)]
    #[sqlx(default)]
    pub execution_target: Option<String>,
    /// AI auto-repair opt-in (0020): `1` when a broken step should be re-derived via the managed
    /// cloud AI gateway (cloud-linked only). Runs stay local; only the repair call crosses to the
    /// cloud (metered on the linked account). `#[sqlx(default)]` keeps `SELECT *` paths (tests)
    /// working across the additive migration.
    #[serde(default)]
    #[sqlx(default)]
    pub ai_repair_enabled: i64,
    /// When AI last PERSISTED a repair to this workflow (0023), ISO-8601 UTC — the same format as
    /// every other timestamp here, so it compares directly against `runs.completed_at` as a string.
    /// A failed run older than this has since been fixed (drives the feed's `repaired_since`).
    /// NULL = never repaired. `#[sqlx(default)]` keeps `SELECT *` paths (tests) working across the
    /// additive migration.
    #[serde(default)]
    #[sqlx(default)]
    pub last_repaired_at: Option<String>,
    /// Marketplace-proxy marker (0017): set (to the listing slug) when this row is a PROXY for an
    /// installed marketplace listing. Its own `steps` stay "[]" — the engine swaps in the unsealed
    /// sealed-recipe at run time (protected executor) while the run/rollup stays bound to this row.
    /// `#[sqlx(default)]` keeps `SELECT *` paths (tests) working across the additive migration.
    #[serde(default)]
    #[sqlx(default)]
    pub marketplace_slug: Option<String>,
    pub created_at: String,
    #[serde(default)]
    pub updated_at: Option<String>,
}

/// Which call surfaces a workflow exposes to EXTERNAL (`wlk_` scoped-key) callers — the per-workflow
/// "Connect" toggles surfaced in the desktop Workflow → Connect tab. Persisted inside the workflow's
/// free-form `streaming_config` JSON under a `connect` object, e.g.
/// `{"connect":{"rest":false,"openai":true,"mcp":true}}`.
///
/// Back-compat: an ABSENT object or key defaults to ENABLED, so every pre-existing workflow stays
/// callable on every surface. The app's own full-access `wlt_` UI token bypasses these checks (see
/// `server::auth_mw`), so turning a surface OFF blocks outside callers WITHOUT breaking in-app Run.
#[derive(Debug, Clone, Copy)]
pub struct ConnectSurfaces {
    pub rest: bool,
    pub openai: bool,
    pub mcp: bool,
}

impl Default for ConnectSurfaces {
    fn default() -> Self {
        Self { rest: true, openai: true, mcp: true }
    }
}

/// Parse the `connect` surface toggles out of a workflow's `streaming_config` JSON text. Any missing
/// key — or malformed/absent config — leaves that surface ENABLED (the safe, non-breaking default).
pub fn connect_surfaces(streaming_config: Option<&str>) -> ConnectSurfaces {
    let mut s = ConnectSurfaces::default();
    let Some(text) = streaming_config else { return s };
    let Ok(v) = serde_json::from_str::<serde_json::Value>(text) else { return s };
    if let Some(c) = v.get("connect").and_then(|c| c.as_object()) {
        if let Some(b) = c.get("rest").and_then(serde_json::Value::as_bool) {
            s.rest = b;
        }
        if let Some(b) = c.get("openai").and_then(serde_json::Value::as_bool) {
            s.openai = b;
        }
        if let Some(b) = c.get("mcp").and_then(serde_json::Value::as_bool) {
            s.mcp = b;
        }
    }
    s
}

impl Workflow {
    /// The `connect` surface toggles for this workflow (see [`connect_surfaces`]).
    pub fn connect_surfaces(&self) -> ConnectSurfaces {
        connect_surfaces(self.streaming_config.as_deref())
    }
}

/// Caller-supplied fields for a new workflow. Anything omitted falls to the column default.
///
/// JSON-TEXT fields accept rich JSON (array/object) OR a pre-serialized string via
/// [`de_json_text_opt`]; the 0/1 flag fields accept a JSON bool OR an int via [`de_bool_int_opt`].
/// This keeps the wizard's create body — which mirrors the Writ Cloud contract — from tripping a
/// `422` on the `Json` extractor.
#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct NewWorkflow {
    pub name: String,
    #[serde(default)]
    pub description: Option<String>,
    /// `recorded|pre_check|on_change|api_recorded`. Empty → schema default (`recorded`).
    #[serde(default)]
    pub workflow_type: Option<String>,
    /// JSON-TEXT step array. Empty → schema default (`[]`).
    #[serde(default, deserialize_with = "de_json_text_opt")]
    pub steps: Option<String>,
    #[serde(default, deserialize_with = "de_json_text_opt")]
    pub raw_replay: Option<String>,
    #[serde(default, deserialize_with = "de_json_text_opt")]
    pub form_data: Option<String>,
    #[serde(default, deserialize_with = "de_json_text_opt")]
    pub exit_condition: Option<String>,
    #[serde(default, deserialize_with = "de_json_text_opt")]
    pub input_rules: Option<String>,
    #[serde(default, deserialize_with = "de_json_text_opt")]
    pub api_functions: Option<String>,
    #[serde(default, deserialize_with = "de_json_text_opt")]
    pub streaming_config: Option<String>,
    #[serde(default, deserialize_with = "de_json_text_opt")]
    pub functions: Option<String>,
    /// Sealed `WF1:` Layer-B blob — never log this value.
    #[serde(default)]
    pub credentials_encrypted: Option<String>,
    #[serde(default)]
    pub entry_url: Option<String>,
    #[serde(default)]
    pub default_persona_id: Option<i64>,
    // Run settings the wizard sets at create time. Omitted → the column's schema default
    // (timeout 30000 / retry 2 / headless 1 / fast_mode 1).
    #[serde(default)]
    pub timeout_ms: Option<i64>,
    #[serde(default)]
    pub retry_count: Option<i64>,
    #[serde(default, deserialize_with = "de_bool_int_opt")]
    pub headless: Option<i64>,
    #[serde(default, deserialize_with = "de_bool_int_opt")]
    pub fast_mode: Option<i64>,
    // Structured recurrence at create time. `schedule_kind` omitted ⇒ the column default (`interval`).
    #[serde(default)]
    pub schedule_kind: Option<String>,
    #[serde(default)]
    pub schedule_time: Option<String>,
    /// ISO weekday ints (weekly). Sent as a JSON array of ints; stored as a JSON string.
    #[serde(default, deserialize_with = "de_json_text_opt")]
    pub schedule_days: Option<String>,
    #[serde(default)]
    pub schedule_tz: Option<String>,
    /// Declarative AuthRecipe JSON (browserless HTTP lane). Set by the concierge when it reconstructs
    /// the sign-in. JSON stored as TEXT.
    #[serde(default, deserialize_with = "de_json_text_opt")]
    pub auth_config: Option<String>,
    /// The RECORDING browser's auth-session JSON (a `SessionState`-shaped object) the wizard posts
    /// at save (0026). NOT an insert column: the create handler seals it POST-insert so the Vault
    /// AAD can bind the new row id ([`recorded_session_aad`]). PLAINTEXT auth material —
    /// `skip_serializing` so a serialized `NewWorkflow` (sync/bridge tooling) can never echo it;
    /// never logged.
    #[serde(default, skip_serializing)]
    pub recorded_session: Option<serde_json::Value>,
    /// Marketplace-proxy marker (0017). Set ONLY by the marketplace install path — the create/update
    /// REST handlers never pass it through (a caller can't fabricate a proxy row).
    #[serde(skip)]
    pub marketplace_slug: Option<String>,
}

/// A patch for an existing workflow. `None` fields are left untouched; `Some` overwrites.
/// JSON-TEXT and secret columns are pass-through strings the caller has already prepared.
#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct WorkflowUpdate {
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub workflow_type: Option<String>,
    #[serde(default, deserialize_with = "de_json_text_opt")]
    pub steps: Option<String>,
    #[serde(default, deserialize_with = "de_json_text_opt")]
    pub raw_replay: Option<String>,
    #[serde(default, deserialize_with = "de_json_text_opt")]
    pub form_data: Option<String>,
    #[serde(default, deserialize_with = "de_json_text_opt")]
    pub exit_condition: Option<String>,
    #[serde(default, deserialize_with = "de_json_text_opt")]
    pub input_rules: Option<String>,
    #[serde(default, deserialize_with = "de_json_text_opt")]
    pub api_functions: Option<String>,
    #[serde(default, deserialize_with = "de_json_text_opt")]
    pub streaming_config: Option<String>,
    #[serde(default, deserialize_with = "de_json_text_opt")]
    pub functions: Option<String>,
    /// Sealed `WF1:` Layer-B blob — never log this value.
    #[serde(default)]
    pub credentials_encrypted: Option<String>,
    #[serde(default)]
    pub entry_url: Option<String>,
    #[serde(default)]
    pub timeout_ms: Option<i64>,
    #[serde(default)]
    pub retry_count: Option<i64>,
    #[serde(default, deserialize_with = "de_bool_int_opt")]
    pub headless: Option<i64>,
    #[serde(default, deserialize_with = "de_bool_int_opt")]
    pub fast_mode: Option<i64>,
    #[serde(default, deserialize_with = "de_bool_int_opt")]
    pub is_active: Option<i64>,
    #[serde(default, deserialize_with = "de_bool_int_opt")]
    pub is_verified: Option<i64>,
    #[serde(default, deserialize_with = "de_bool_int_opt")]
    pub schedule_enabled: Option<i64>,
    #[serde(default)]
    pub schedule_interval_ms: Option<i64>,
    /// Structured recurrence: `interval` | `daily` | `weekly`. Absent ⇒ untouched (COALESCE).
    #[serde(default)]
    pub schedule_kind: Option<String>,
    /// "HH:MM" local fire time (daily/weekly).
    #[serde(default)]
    pub schedule_time: Option<String>,
    /// ISO weekday ints (weekly). Sent on the wire as a JSON array of ints; stored as a JSON string.
    #[serde(default, deserialize_with = "de_json_text_opt")]
    pub schedule_days: Option<String>,
    /// IANA tz name (daily/weekly).
    #[serde(default)]
    pub schedule_tz: Option<String>,
    #[serde(default, deserialize_with = "de_bool_int_opt")]
    pub session_persistence: Option<i64>,
    #[serde(default)]
    pub session_ttl_seconds: Option<i64>,
    #[serde(default, deserialize_with = "de_json_text_opt")]
    pub login_url_patterns: Option<String>,
    #[serde(default)]
    pub relogin_max_retries: Option<i64>,
    #[serde(default)]
    pub default_persona_id: Option<i64>,
    #[serde(default)]
    pub estimated_duration_ms: Option<i64>,
    #[serde(default, deserialize_with = "de_bool_int_opt")]
    pub cloud_callable: Option<i64>,
    /// Run-venue pin ('local' | 'cloud' | '' to clear back to Auto). Patched by the desktop
    /// "Run on" setting. Empty string clears it to NULL (Auto) below.
    #[serde(default)]
    pub execution_target: Option<String>,
    /// AI auto-repair opt-in (0020). Accepts a JSON bool or int; `de_bool_int_opt` maps it to 0/1.
    #[serde(default, deserialize_with = "de_bool_int_opt")]
    pub ai_repair_enabled: Option<i64>,
    /// Re-pin the recorded replay seed (0026): a `SessionState`-shaped auth-session object, sealed
    /// by the API layer — NOT a store column (the UPDATE below never touches the sealed blob).
    /// PLAINTEXT auth material — `skip_serializing`, never logged.
    #[serde(default, skip_serializing)]
    pub recorded_session: Option<serde_json::Value>,
    /// Drop the recorded replay seed (0026). Handled in the API layer, not the store UPDATE.
    #[serde(default)]
    pub clear_recorded_session: Option<bool>,
}

// The two `last_run_*` entries are CORRELATED SUBQUERIES (the desktop workflows table stores no
// per-run status), aliased to match the `Workflow` struct's computed fields. `runs.id` is monotonic,
// so "latest by id DESC" is the most recent run. Cheap for a single-user local DB.
const SELECT_COLS: &str = "id, name, description, workflow_type, steps, raw_replay, form_data,
    exit_condition, input_rules, api_functions, streaming_config, functions, credentials_encrypted,
    entry_url, timeout_ms, retry_count, headless, fast_mode, is_active, is_verified,
    schedule_enabled, schedule_interval_ms, schedule_kind, schedule_time, schedule_days, schedule_tz,
    last_scheduled_at, next_scheduled_at,
    session_persistence, session_ttl_seconds, login_url_patterns, relogin_max_retries,
    http_capable, auth_config, recorded_session_encrypted, recorded_session_captured_at,
    default_persona_id, estimated_duration_ms, usage_count, total_run_count, total_failure_count,
    consecutive_failures, last_run_at,
    (SELECT r.status FROM runs r WHERE r.workflow_id = workflows.id ORDER BY r.id DESC LIMIT 1) AS last_run_status,
    (SELECT r.duration_ms FROM runs r WHERE r.workflow_id = workflows.id ORDER BY r.id DESC LIMIT 1) AS last_run_duration_ms,
    (SELECT EXISTS(SELECT 1 FROM runs r WHERE r.workflow_id = workflows.id AND r.status = 'success'
        AND r.result_data IS NOT NULL AND r.result_data NOT IN ('', '{}', '[]', 'null'))) AS last_run_has_extracted_data,
    last_failure_at, last_failure_error, cloud_callable, execution_target, ai_repair_enabled,
    last_repaired_at, marketplace_slug, created_at, updated_at";

/// Insert a workflow and return its full materialized row.
pub async fn insert(pool: &SqlitePool, new: &NewWorkflow) -> LocalResult<Workflow> {
    let id: i64 = sqlx::query(
        "INSERT INTO workflows
         (name, description, workflow_type, steps, raw_replay, form_data, exit_condition,
          input_rules, api_functions, streaming_config, functions, credentials_encrypted,
          entry_url, default_persona_id, timeout_ms, retry_count, headless, fast_mode,
          schedule_kind, schedule_time, schedule_days, schedule_tz, auth_config, marketplace_slug)
         VALUES
         (?1, ?2, COALESCE(?3, 'recorded'), COALESCE(?4, '[]'), ?5, ?6, ?7, ?8, ?9, ?10, ?11,
          ?12, ?13, ?14, COALESCE(?15, 30000), COALESCE(?16, 2), COALESCE(?17, 1),
          COALESCE(?18, 1), COALESCE(?19, 'interval'), ?20, ?21, ?22, ?23, ?24)
         RETURNING id",
    )
    .bind(&new.name)
    .bind(&new.description)
    .bind(&new.workflow_type)
    .bind(&new.steps)
    .bind(&new.raw_replay)
    .bind(&new.form_data)
    .bind(&new.exit_condition)
    .bind(&new.input_rules)
    .bind(&new.api_functions)
    .bind(&new.streaming_config)
    .bind(&new.functions)
    .bind(&new.credentials_encrypted)
    .bind(&new.entry_url)
    .bind(new.default_persona_id)
    .bind(new.timeout_ms)
    .bind(new.retry_count)
    .bind(new.headless)
    .bind(new.fast_mode)
    .bind(&new.schedule_kind)
    .bind(&new.schedule_time)
    .bind(&new.schedule_days)
    .bind(&new.schedule_tz)
    .bind(&new.auth_config)
    .bind(&new.marketplace_slug)
    .fetch_one(pool)
    .await?
    .try_get(0)?;

    tracing::info!(workflow_id = id, name = %new.name, "workflow inserted");
    get_by_id(pool, id)
        .await?
        .ok_or_else(|| LocalError::Internal("workflow vanished after insert".into()))
}

/// Fetch one workflow by id.
pub async fn get_by_id(pool: &SqlitePool, id: i64) -> LocalResult<Option<Workflow>> {
    let row = sqlx::query_as::<_, Workflow>(&format!(
        "SELECT {SELECT_COLS} FROM workflows WHERE id = ?1"
    ))
    .bind(id)
    .fetch_optional(pool)
    .await?;
    Ok(row)
}

/// Fetch the marketplace-PROXY workflow row for an installed listing slug (0017), if one exists.
pub async fn get_by_marketplace_slug(pool: &SqlitePool, slug: &str) -> LocalResult<Option<Workflow>> {
    let row = sqlx::query_as::<_, Workflow>(&format!(
        "SELECT {SELECT_COLS} FROM workflows WHERE marketplace_slug = ?1"
    ))
    .bind(slug)
    .fetch_optional(pool)
    .await?;
    Ok(row)
}

/// Batch-fetch `(id, name, workflow_type, last_repaired_at)` for a set of workflow ids. Used by the runs feed to
/// resolve each run's `entity_name` (and detect streaming workflows, which have no data view)
/// without an N+1 lookup per row. Ids with no matching row are simply absent from the result; an
/// empty input short-circuits with no query. The `IN (...)` list is positional `?` placeholders
/// bound to our own `i64` row ids — no injection surface.
pub async fn names_and_types(
    pool: &SqlitePool,
    ids: &[i64],
) -> LocalResult<Vec<(i64, String, String, Option<String>)>> {
    if ids.is_empty() {
        return Ok(Vec::new());
    }
    let placeholders = std::iter::repeat_n("?", ids.len()).collect::<Vec<_>>().join(",");
    let sql = format!(
        "SELECT id, name, workflow_type, last_repaired_at FROM workflows WHERE id IN ({placeholders})"
    );
    let mut q = sqlx::query(&sql);
    for id in ids {
        q = q.bind(id);
    }
    let rows = q.fetch_all(pool).await?;
    rows.into_iter()
        .map(|r| {
            Ok((
                r.try_get("id")?,
                r.try_get("name")?,
                r.try_get("workflow_type")?,
                r.try_get("last_repaired_at")?,
            ))
        })
        .collect::<LocalResult<Vec<_>>>()
}

/// Stamp `last_repaired_at = now` (0023) after AI has PERSISTED a repair to this workflow. Uses the
/// same strftime expression as every other timestamp column so the value is directly comparable to
/// `runs.completed_at` as a plain string. Returns whether a row was affected.
///
/// Call this only where the repaired recipe actually reached the DB — the stamp is what makes older
/// failures of this workflow read as resolved, so claiming it on a repair that was never persisted
/// would silently hide failures that are still live.
pub async fn mark_repaired(pool: &SqlitePool, id: i64) -> LocalResult<bool> {
    let res = sqlx::query(
        "UPDATE workflows SET last_repaired_at = strftime('%Y-%m-%dT%H:%M:%fZ','now') WHERE id = ?1",
    )
    .bind(id)
    .execute(pool)
    .await?;
    Ok(res.rows_affected() > 0)
}

/// Every `(default_persona_id, workflow id, workflow name)` link, name-ordered. Backs the persona
/// API's `linked_workflows` (which workflows run as which persona) without loading full rows.
pub async fn persona_links(pool: &SqlitePool) -> LocalResult<Vec<(i64, i64, String)>> {
    let rows = sqlx::query(
        "SELECT default_persona_id, id, name FROM workflows \
         WHERE default_persona_id IS NOT NULL ORDER BY name",
    )
    .fetch_all(pool)
    .await?;
    rows.into_iter()
        .map(|r| Ok((r.try_get("default_persona_id")?, r.try_get("id")?, r.try_get("name")?)))
        .collect::<LocalResult<Vec<_>>>()
}

/// List workflows, newest first, capped at `limit`. `active_only` filters to `is_active=1`.
pub async fn list(pool: &SqlitePool, active_only: bool, limit: i64) -> LocalResult<Vec<Workflow>> {
    let limit = limit.clamp(1, 1000);
    let sql = if active_only {
        format!(
            "SELECT {SELECT_COLS} FROM workflows WHERE is_active = 1 
             ORDER BY created_at DESC, id DESC LIMIT ?1"
        )
    } else {
        format!("SELECT {SELECT_COLS} FROM workflows ORDER BY created_at DESC, id DESC LIMIT ?1")
    };
    let rows = sqlx::query_as::<_, Workflow>(&sql)
        .bind(limit)
        .fetch_all(pool)
        .await?;
    Ok(rows)
}

/// List the workflows the user has opted into exposing for cloud-callable execution: active rows
/// (`is_active = 1`) flagged `cloud_callable = 1`. Newest first. This is the catalog the linked-agent
/// bridge advertises to Writ Cloud — it returns FULL rows, but the bridge MUST project to metadata
/// only (declared inputs/output fields) before it crosses the wire; steps/credentials never leave
/// the device. Capped to a sane ceiling so a runaway table can't build an unbounded frame.
pub async fn list_cloud_callable(pool: &SqlitePool) -> LocalResult<Vec<Workflow>> {
    let rows = sqlx::query_as::<_, Workflow>(&format!(
        "SELECT {SELECT_COLS} FROM workflows
         WHERE cloud_callable = 1 AND is_active = 1
         ORDER BY created_at DESC, id DESC LIMIT 1000"
    ))
    .fetch_all(pool)
    .await?;
    Ok(rows)
}

/// Apply a sparse patch. Returns the updated row, or `NotFound` if no such id.
pub async fn update(pool: &SqlitePool, id: i64, patch: &WorkflowUpdate) -> LocalResult<Workflow> {
    // COALESCE(?, col) keeps the existing value when the bind is NULL (None). `updated_at` is
    // always refreshed.
    let res = sqlx::query(
        "UPDATE workflows SET 
            name = COALESCE(?2, name), 
            description = COALESCE(?3, description), 
            workflow_type = COALESCE(?4, workflow_type), 
            steps = COALESCE(?5, steps), 
            raw_replay = COALESCE(?6, raw_replay), 
            form_data = COALESCE(?7, form_data), 
            exit_condition = COALESCE(?8, exit_condition), 
            input_rules = COALESCE(?9, input_rules), 
            api_functions = COALESCE(?10, api_functions), 
            streaming_config = COALESCE(?11, streaming_config), 
            functions = COALESCE(?12, functions), 
            credentials_encrypted = COALESCE(?13, credentials_encrypted), 
            entry_url = COALESCE(?14, entry_url), 
            timeout_ms = COALESCE(?15, timeout_ms), 
            retry_count = COALESCE(?16, retry_count), 
            headless = COALESCE(?17, headless), 
            fast_mode = COALESCE(?18, fast_mode), 
            is_active = COALESCE(?19, is_active), 
            is_verified = COALESCE(?20, is_verified), 
            schedule_enabled = COALESCE(?21, schedule_enabled), 
            schedule_interval_ms = COALESCE(?22, schedule_interval_ms), 
            session_persistence = COALESCE(?23, session_persistence), 
            session_ttl_seconds = COALESCE(?24, session_ttl_seconds), 
            login_url_patterns = COALESCE(?25, login_url_patterns), 
            relogin_max_retries = COALESCE(?26, relogin_max_retries), 
            default_persona_id = COALESCE(?27, default_persona_id), 
            estimated_duration_ms = COALESCE(?28, estimated_duration_ms), 
            cloud_callable = COALESCE(?29, cloud_callable),
            execution_target = COALESCE(?30, execution_target),
            schedule_kind = COALESCE(?31, schedule_kind),
            schedule_time = COALESCE(?32, schedule_time),
            schedule_days = COALESCE(?33, schedule_days),
            schedule_tz = COALESCE(?34, schedule_tz),
            ai_repair_enabled = COALESCE(?35, ai_repair_enabled),
            -- Editing the steps invalidates the learned HTTP-lane hint: re-probe next run.
            http_capable = CASE WHEN ?5 IS NOT NULL THEN -1 ELSE http_capable END,
            updated_at = strftime('%Y-%m-%dT%H:%M:%fZ','now')
         WHERE id = ?1",
    )
    .bind(id)
    .bind(&patch.name)
    .bind(&patch.description)
    .bind(&patch.workflow_type)
    .bind(&patch.steps)
    .bind(&patch.raw_replay)
    .bind(&patch.form_data)
    .bind(&patch.exit_condition)
    .bind(&patch.input_rules)
    .bind(&patch.api_functions)
    .bind(&patch.streaming_config)
    .bind(&patch.functions)
    .bind(&patch.credentials_encrypted)
    .bind(&patch.entry_url)
    .bind(patch.timeout_ms)
    .bind(patch.retry_count)
    .bind(patch.headless)
    .bind(patch.fast_mode)
    .bind(patch.is_active)
    .bind(patch.is_verified)
    .bind(patch.schedule_enabled)
    .bind(patch.schedule_interval_ms)
    .bind(patch.session_persistence)
    .bind(patch.session_ttl_seconds)
    .bind(&patch.login_url_patterns)
    .bind(patch.relogin_max_retries)
    .bind(patch.default_persona_id)
    .bind(patch.estimated_duration_ms)
    .bind(patch.cloud_callable)
    .bind(&patch.execution_target)
    .bind(&patch.schedule_kind)
    .bind(&patch.schedule_time)
    .bind(&patch.schedule_days)
    .bind(&patch.schedule_tz)
    .bind(patch.ai_repair_enabled)
    .execute(pool)
    .await?;

    if res.rows_affected() == 0 {
        return Err(LocalError::NotFound(format!("workflow {id}")));
    }
    tracing::info!(workflow_id = id, "workflow updated");
    get_by_id(pool, id)
        .await?
        .ok_or_else(|| LocalError::NotFound(format!("workflow {id}")))
}

/// Stamp the browserless HTTP-lane hint after a run: `1` HTTP-proven, `0` browser-only (fell back),
/// `-1` unknown. Best-effort — never fails a run. Does NOT bump `updated_at` (it's a runtime hint,
/// not a user edit).
pub async fn set_http_capable(pool: &SqlitePool, id: i64, value: i64) -> LocalResult<()> {
    sqlx::query("UPDATE workflows SET http_capable = ?2 WHERE id = ?1")
        .bind(id)
        .bind(value)
        .execute(pool)
        .await?;
    Ok(())
}

/// Pin/refresh the RECORDING browser's sealed auth-session seed (0026). `sealed` is the Vault
/// Layer-B `WF1:` blob (AAD [`recorded_session_aad`]); `captured_at` is RFC3339, duplicated outside
/// the blob so freshness renders without a decrypt. Does NOT bump `updated_at`: the after-run
/// refresh re-seals on every successful seeded run, and that is runtime bookkeeping, not a user
/// edit (same reasoning as [`set_http_capable`]).
pub async fn set_recorded_session(
    pool: &SqlitePool,
    id: i64,
    sealed: &str,
    captured_at: &str,
) -> LocalResult<()> {
    sqlx::query(
        "UPDATE workflows SET recorded_session_encrypted = ?2, recorded_session_captured_at = ?3
         WHERE id = ?1",
    )
    .bind(id)
    .bind(sealed)
    .bind(captured_at)
    .execute(pool)
    .await?;
    Ok(())
}

/// Drop the recorded auth-session seed (0026): the next persona-less run starts from the persisted
/// workflow session if one exists, else cold.
pub async fn clear_recorded_session(pool: &SqlitePool, id: i64) -> LocalResult<()> {
    sqlx::query(
        "UPDATE workflows SET recorded_session_encrypted = NULL, recorded_session_captured_at = NULL
         WHERE id = ?1",
    )
    .bind(id)
    .execute(pool)
    .await?;
    Ok(())
}

/// Stamp scheduler bookkeeping after a due-run is dispatched. Sets `last_scheduled_at = now` and
/// `next_scheduled_at` to the caller-computed RFC3339 timestamp (or NULL to clear).
pub async fn mark_scheduled(
    pool: &SqlitePool,
    id: i64,
    next_at: Option<&str>,
) -> LocalResult<()> {
    let res = sqlx::query(
        "UPDATE workflows SET 
            last_scheduled_at = strftime('%Y-%m-%dT%H:%M:%fZ','now'), 
            next_scheduled_at = ?2, 
            updated_at = strftime('%Y-%m-%dT%H:%M:%fZ','now') 
         WHERE id = ?1",
    )
    .bind(id)
    .bind(next_at)
    .execute(pool)
    .await?;
    if res.rows_affected() == 0 {
        return Err(LocalError::NotFound(format!("workflow {id}")));
    }
    Ok(())
}

/// Record the outcome of a run against rollup counters. `success=true` bumps `total_run_count`,
/// stamps `last_run_at`, resets the consecutive-failure streak; `success=false` additionally bumps
/// the failure counters and stores the (non-secret) error string.
pub async fn record_run_outcome(
    pool: &SqlitePool,
    id: i64,
    success: bool,
    error: Option<&str>,
) -> LocalResult<()> {
    let sql = if success {
        "UPDATE workflows SET 
            usage_count = usage_count + 1, 
            total_run_count = total_run_count + 1, 
            consecutive_failures = 0, 
            last_run_at = strftime('%Y-%m-%dT%H:%M:%fZ','now'), 
            updated_at = strftime('%Y-%m-%dT%H:%M:%fZ','now') 
         WHERE id = ?1"
    } else {
        "UPDATE workflows SET 
            usage_count = usage_count + 1, 
            total_run_count = total_run_count + 1, 
            total_failure_count = total_failure_count + 1, 
            consecutive_failures = consecutive_failures + 1, 
            last_run_at = strftime('%Y-%m-%dT%H:%M:%fZ','now'), 
            last_failure_at = strftime('%Y-%m-%dT%H:%M:%fZ','now'), 
            last_failure_error = ?2, 
            updated_at = strftime('%Y-%m-%dT%H:%M:%fZ','now') 
         WHERE id = ?1"
    };
    let res = sqlx::query(sql)
        .bind(id)
        .bind(error)
        .execute(pool)
        .await?;
    if res.rows_affected() == 0 {
        return Err(LocalError::NotFound(format!("workflow {id}")));
    }
    Ok(())
}

/// Hard-delete a workflow row. Cascades to `runs` (ON DELETE CASCADE). Returns whether a row was
/// removed.
///
/// This is the ONLY removal path: there is no soft-delete/`is_active=0` "deactivate" for workflows.
/// A workflow parked inactive used to keep its runs but drop out of the default list, which stranded
/// its extracted data out of the Data explorer — so the concept was retired. `is_active` survives as
/// a column only for legacy rows the Data explorer still surfaces (`list(active_only=false)`).
pub async fn delete(pool: &SqlitePool, id: i64) -> LocalResult<bool> {
    let res = sqlx::query("DELETE FROM workflows WHERE id = ?1")
        .bind(id)
        .execute(pool)
        .await?;
    let affected = res.rows_affected() > 0;
    if affected {
        tracing::info!(workflow_id = id, "workflow hard-deleted");
    }
    Ok(affected)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::local::db;

    async fn pool() -> SqlitePool {
        let dir = Box::leak(Box::new(tempfile::tempdir().unwrap()));
        db::open(&dir.path().join("t.db"), "test-key-wf").await.unwrap()
    }

    /// `mark_repaired` stamps `last_repaired_at` (0023) in the SAME ISO-8601 UTC format as
    /// `runs.completed_at`, which is the whole reason the feed can order the two with a plain string
    /// compare to decide whether a failure has since been fixed. A format drift here would silently
    /// break `repaired_since` rather than fail loudly, so assert the shape, not just non-emptiness.
    #[tokio::test]
    async fn mark_repaired_stamps_a_comparable_timestamp() {
        let pool = pool().await;
        let wf = insert(&pool, &NewWorkflow { name: "wf".into(), ..Default::default() })
            .await
            .unwrap();
        assert_eq!(wf.last_repaired_at, None, "a fresh workflow has never been repaired");

        assert!(mark_repaired(&pool, wf.id).await.unwrap());
        let stamped = get_by_id(&pool, wf.id).await.unwrap().unwrap().last_repaired_at.unwrap();
        // e.g. "2026-07-17T13:45:04.656Z" — same strftime('%Y-%m-%dT%H:%M:%fZ') the runs table uses.
        assert_eq!(stamped.len(), 24, "unexpected timestamp shape: {stamped}");
        assert!(stamped.ends_with('Z') && stamped.contains('T'), "not ISO-8601 UTC: {stamped}");
        // Lexicographic ordering must be chronological against a runs timestamp of the same format.
        assert!(stamped.as_str() > "2020-01-01T00:00:00.000Z");
        assert!(stamped.as_str() < "2999-01-01T00:00:00.000Z");

        // Unknown workflow → no row touched, no error.
        assert!(!mark_repaired(&pool, 999_999).await.unwrap());
    }

    /// The recorded replay seed (0026) round-trips through set/clear, and the sealed blob NEVER
    /// serializes out of the row struct — API responses serialize `Workflow` directly, so
    /// `skip_serializing` is the only thing standing between the vault blob and the wire. The
    /// freshness stamp, by contrast, IS exposed (the UI renders it).
    #[tokio::test]
    async fn recorded_session_set_clear_and_blob_never_serializes() {
        let pool = pool().await;
        let wf = insert(&pool, &NewWorkflow { name: "rec".into(), ..Default::default() })
            .await
            .unwrap();
        assert_eq!(wf.recorded_session_encrypted, None, "a fresh workflow pins nothing");
        assert_eq!(wf.recorded_session_captured_at, None);

        set_recorded_session(&pool, wf.id, "WF1:sealed-blob", "2026-08-16T00:00:00Z")
            .await
            .unwrap();
        let got = get_by_id(&pool, wf.id).await.unwrap().unwrap();
        assert_eq!(got.recorded_session_encrypted.as_deref(), Some("WF1:sealed-blob"));
        assert_eq!(got.recorded_session_captured_at.as_deref(), Some("2026-08-16T00:00:00Z"));

        let v = serde_json::to_value(&got).unwrap();
        assert!(
            v.get("recorded_session_encrypted").is_none(),
            "the sealed blob must never serialize: {v}"
        );
        assert_eq!(v["recorded_session_captured_at"], "2026-08-16T00:00:00Z");

        clear_recorded_session(&pool, wf.id).await.unwrap();
        let cleared = get_by_id(&pool, wf.id).await.unwrap().unwrap();
        assert_eq!(cleared.recorded_session_encrypted, None);
        assert_eq!(cleared.recorded_session_captured_at, None);
    }

    /// The runs feed resolves names + repair stamps in ONE bulk query; it must carry the stamp
    /// through (a `None` here would silently make every old failure look unresolved).
    #[tokio::test]
    async fn names_and_types_carries_the_repair_stamp() {
        let pool = pool().await;
        let a = insert(&pool, &NewWorkflow { name: "a".into(), ..Default::default() }).await.unwrap();
        let b = insert(&pool, &NewWorkflow { name: "b".into(), ..Default::default() }).await.unwrap();
        mark_repaired(&pool, b.id).await.unwrap();

        let rows = names_and_types(&pool, &[a.id, b.id]).await.unwrap();
        let got: std::collections::HashMap<i64, Option<String>> =
            rows.into_iter().map(|(id, _, _, stamp)| (id, stamp)).collect();
        assert_eq!(got[&a.id], None, "never-repaired workflow must carry no stamp");
        assert!(got[&b.id].is_some(), "repaired workflow must carry its stamp");
    }

    #[tokio::test]
    async fn insert_get_update_list_delete() {
        let pool = pool().await;

        let wf = insert(
            &pool,
            &NewWorkflow {
                name: "demo".into(),
                steps: Some(r#"[{\"a\":1}]"#.into()),
                ..Default::default()
            },
        )
        .await
        .unwrap();
        assert!(wf.id > 0);
        assert_eq!(wf.workflow_type, "recorded"); // COALESCE default
        assert_eq!(wf.steps, r#"[{\"a\":1}]"#);
        assert_eq!(wf.is_active, 1);

        let got = get_by_id(&pool, wf.id).await.unwrap().unwrap();
        assert_eq!(got.name, "demo");

        let upd = update(
            &pool,
            wf.id,
            &WorkflowUpdate {
                name: Some("renamed".into()),
                headless: Some(0),
                execution_target: Some("cloud".into()),
                ..Default::default()
            },
        )
        .await
        .unwrap();
        assert_eq!(upd.name, "renamed");
        assert_eq!(upd.headless, 0);
        assert_eq!(upd.execution_target.as_deref(), Some("cloud"), "venue pin persists");
        assert_eq!(upd.steps, r#"[{\"a\":1}]"#); // untouched

        record_run_outcome(&pool, wf.id, false, Some("boom")).await.unwrap();
        let after = get_by_id(&pool, wf.id).await.unwrap().unwrap();
        assert_eq!(after.total_run_count, 1);
        assert_eq!(after.total_failure_count, 1);
        assert_eq!(after.consecutive_failures, 1);
        assert_eq!(after.last_failure_error.as_deref(), Some("boom"));

        record_run_outcome(&pool, wf.id, true, None).await.unwrap();
        let after = get_by_id(&pool, wf.id).await.unwrap().unwrap();
        assert_eq!(after.total_run_count, 2);
        assert_eq!(after.consecutive_failures, 0); // streak reset on success

        assert_eq!(list(&pool, true, 50).await.unwrap().len(), 1);
        // `list(active_only=false)` sees inactive rows too — the Data explorer relies on this so a
        // legacy inactive workflow's extracted data is never hidden.
        update(&pool, wf.id, &WorkflowUpdate { is_active: Some(0), ..Default::default() })
            .await
            .unwrap();
        assert_eq!(list(&pool, true, 50).await.unwrap().len(), 0);
        assert_eq!(list(&pool, false, 50).await.unwrap().len(), 1); // still present

        // Hard delete is the only removal path: the row is gone (its runs cascade away).
        assert!(delete(&pool, wf.id).await.unwrap());
        assert!(get_by_id(&pool, wf.id).await.unwrap().is_none());
    }

    /// The `last_run_status` / `last_run_duration_ms` computed columns must reflect the LATEST run
    /// row (by id) — the desktop UI relies on these instead of a stored status (it has none), which
    /// is why the workflow pane used to say "Never run" for a workflow that had run.
    #[tokio::test]
    async fn last_run_columns_track_the_latest_run() {
        use crate::local::store::runs;
        let pool = pool().await;
        let wf = insert(&pool, &NewWorkflow { name: "runs".into(), ..Default::default() })
            .await
            .unwrap();

        // No runs yet → both null (renders "Never run"), no data.
        let fresh = get_by_id(&pool, wf.id).await.unwrap().unwrap();
        assert_eq!(fresh.last_run_status, None);
        assert_eq!(fresh.last_run_duration_ms, None);
        assert_eq!(fresh.last_run_has_extracted_data, Some(0));

        // A completed run WITH a real payload → status 'success', duration + has-data surfaced.
        let r1 = runs::insert(&pool, &runs::NewRun { workflow_id: Some(wf.id), ..Default::default() })
            .await
            .unwrap();
        runs::complete(&pool, r1.id, Some(r#"{"price":"42"}"#), Some(1234)).await.unwrap();
        let after = get_by_id(&pool, wf.id).await.unwrap().unwrap();
        assert_eq!(after.last_run_status.as_deref(), Some("success"));
        assert_eq!(after.last_run_duration_ms, Some(1234));
        assert_eq!(after.last_run_has_extracted_data, Some(1), "non-trivial result_data counts");
        // The list projection carries it too (the list surfaces sort/filter on it).
        let listed = list(&pool, false, 50).await.unwrap();
        assert_eq!(listed[0].last_run_status.as_deref(), Some("success"));

        // A newer run wins, even mid-flight ('running', no duration yet).
        runs::insert(&pool, &runs::NewRun { workflow_id: Some(wf.id), ..Default::default() })
            .await
            .unwrap();
        let latest = get_by_id(&pool, wf.id).await.unwrap().unwrap();
        assert_eq!(latest.last_run_status.as_deref(), Some("running"));
        assert_eq!(latest.last_run_duration_ms, None);
    }

    #[test]
    fn new_workflow_accepts_rich_json_and_bool_flags() {
        // The wizard posts `steps` as an ARRAY, `form_data` as an OBJECT, and `headless`/`fast_mode`
        // as BOOLS — the shape that used to 422 against the old `Option<String>` / `Option<i64>`.
        let body = serde_json::json!({
            "name": "demo",
            "steps": [{ "type": "click", "selector": "#go" }],
            "form_data": { "user": "alice" },
            "functions": [{ "name": "f" }],
            "headless": false,
            "fast_mode": true,
            "timeout_ms": 45000,
        });
        let nw: NewWorkflow = serde_json::from_value(body).unwrap();
        // The rich JSON is stored as TEXT — re-parse to compare structurally (key order/whitespace
        // independent) and prove the engine can `from_str` it back.
        let reparse = |s: &str| serde_json::from_str::<serde_json::Value>(s).unwrap();
        assert_eq!(
            reparse(nw.steps.as_deref().unwrap()),
            serde_json::json!([{ "type": "click", "selector": "#go" }])
        );
        assert_eq!(reparse(nw.form_data.as_deref().unwrap()), serde_json::json!({ "user": "alice" }));
        assert_eq!(reparse(nw.functions.as_deref().unwrap()), serde_json::json!([{ "name": "f" }]));
        assert_eq!(nw.headless, Some(0));
        assert_eq!(nw.fast_mode, Some(1));
        assert_eq!(nw.timeout_ms, Some(45000));

        // A pre-serialized string for a JSON-TEXT field still passes through untouched.
        let str_body = serde_json::json!({ "name": "s", "steps": "[1,2]" });
        let nw2: NewWorkflow = serde_json::from_value(str_body).unwrap();
        assert_eq!(nw2.steps.as_deref(), Some("[1,2]"));
    }

    #[test]
    fn connect_surfaces_defaults_on_and_honors_toggles() {
        // Absent / null / non-JSON config → every surface ENABLED (back-compat default).
        for cfg in [None, Some("null"), Some("not json"), Some("{}")] {
            let s = connect_surfaces(cfg);
            assert!(s.rest && s.openai && s.mcp, "default-on failed for {cfg:?}");
        }
        // Explicit toggles are honored; an OMITTED key in a present `connect` object stays ENABLED.
        let s = connect_surfaces(Some(r#"{"connect":{"rest":false,"openai":true}}"#));
        assert!(!s.rest, "rest should be off");
        assert!(s.openai, "openai should be on");
        assert!(s.mcp, "mcp omitted → stays on");
        // Coexists with other streaming_config keys (e.g. openai_compat) without disturbing them.
        let s = connect_surfaces(Some(r#"{"openai_compat":{"enabled":true},"connect":{"mcp":false}}"#));
        assert!(s.rest && s.openai && !s.mcp);
    }

    #[test]
    fn workflow_update_accepts_bool_toggles() {
        // `is_active: !w.is_active` and the headless/fast_mode fast-action toggles arrive as bools.
        let patch: WorkflowUpdate =
            serde_json::from_value(serde_json::json!({ "is_active": false, "headless": true }))
                .unwrap();
        assert_eq!(patch.is_active, Some(0));
        assert_eq!(patch.headless, Some(1));
        // Absent flags stay None so COALESCE leaves the column untouched.
        assert_eq!(patch.fast_mode, None);
        assert_eq!(patch.cloud_callable, None);
    }

    #[tokio::test]
    async fn list_cloud_callable_filters_flag_and_active() {
        let pool = pool().await;

        // Not exposed (default cloud_callable=0) → excluded.
        insert(&pool, &NewWorkflow { name: "plain".into(), ..Default::default() })
            .await
            .unwrap();

        // Exposed + active → included.
        let exposed = insert(&pool, &NewWorkflow { name: "exposed".into(), ..Default::default() })
            .await
            .unwrap();
        update(&pool, exposed.id, &WorkflowUpdate { cloud_callable: Some(1), ..Default::default() })
            .await
            .unwrap();

        // Exposed but inactive (is_active=0) → excluded from the cloud-callable catalog.
        let gone = insert(&pool, &NewWorkflow { name: "gone".into(), ..Default::default() })
            .await
            .unwrap();
        update(
            &pool,
            gone.id,
            &WorkflowUpdate { cloud_callable: Some(1), is_active: Some(0), ..Default::default() },
        )
        .await
        .unwrap();

        let listed = list_cloud_callable(&pool).await.unwrap();
        assert_eq!(listed.len(), 1, "only the exposed+active row");
        assert_eq!(listed[0].name, "exposed");
        assert_eq!(listed[0].cloud_callable, 1);
        assert_eq!(listed[0].is_active, 1);
    }
}
