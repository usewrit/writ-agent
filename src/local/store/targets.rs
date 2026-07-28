//! Store layer for `targets` (monitors). Runtime-checked sqlx only.
//!
//! Schema: migrations/0001_init.sql §3. PK INTEGER AUTOINCREMENT. JSON-TEXT columns
//! (`notification_providers`, `provider_notification_settings`, `on_change_conditions`) stay
//! `String` — callers serde them. `auth_session_encrypted` is ciphertext: NEVER logged.

use super::super::error::LocalResult;
use sqlx::sqlite::SqlitePool;
use sqlx::Row as _;

/// Deserialize an optional SQLite-boolean column (stored as `0`/`1`) that the JSON API may send as a
/// real bool (`true`/`false`), an int (`1`/`0`), or null/absent. Booleans map to `1`/`0`. This keeps
/// the create/update endpoints tolerant of the JSON-natural boolean shape the frontends send for
/// `enabled` / `requires_playwright` / `check_ssl` / the on-change flags (otherwise a `true` against
/// an `Option<i64>` field is a serde type error → HTTP 422).
pub(crate) fn de_opt_bool_int<'de, D>(d: D) -> Result<Option<i64>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    use serde::Deserialize as _;
    #[derive(serde::Deserialize)]
    #[serde(untagged)]
    enum BoolOrInt {
        Bool(bool),
        Int(i64),
    }
    let v = Option::<BoolOrInt>::deserialize(d)?;
    Ok(v.map(|b| match b {
        BoolOrInt::Bool(true) => 1,
        BoolOrInt::Bool(false) => 0,
        BoolOrInt::Int(i) => i,
    }))
}

/// Deserialize an optional INTEGER column that the JSON API may send as a real number OR a numeric
/// STRING — the shape a `<select>`/`<input>` yields (e.g. a `persona_id` option value, or an interval
/// from a text field). A string is parsed to `i64`; a non-numeric string is a hard error. `null`/
/// absent → `None`. Without this, `"60000"` against an `Option<i64>` field is a serde type error → 422.
pub(crate) fn de_opt_int<'de, D>(d: D) -> Result<Option<i64>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    use serde::Deserialize as _;
    Ok(match Option::<serde_json::Value>::deserialize(d)? {
        None | Some(serde_json::Value::Null) => None,
        Some(serde_json::Value::Number(n)) => Some(
            n.as_i64()
                .or_else(|| n.as_f64().map(|f| f as i64))
                .ok_or_else(|| serde::de::Error::custom("number out of i64 range"))?,
        ),
        Some(serde_json::Value::String(s)) => {
            let t = s.trim();
            if t.is_empty() {
                None
            } else {
                Some(t.parse::<i64>().map_err(|_| {
                    serde::de::Error::custom(format!("expected an integer, got string {s:?}"))
                })?)
            }
        }
        Some(other) => {
            return Err(serde::de::Error::custom(format!(
                "expected an integer or numeric string, got {other}"
            )))
        }
    })
}

/// Deserialize a JSON-TEXT column that the API may send as a pre-serialized string OR a rich JSON
/// value (object/array). A non-string value is serialized to its compact JSON text (the column is
/// TEXT); a string passes through untouched. `null`/absent → `None`. Keeps `setup_steps` /
/// `on_change_conditions` / the notification-settings columns from 422-ing when sent as objects.
pub(crate) fn de_opt_json_text<'de, D>(d: D) -> Result<Option<String>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    use serde::Deserialize as _;
    Ok(match Option::<serde_json::Value>::deserialize(d)? {
        None | Some(serde_json::Value::Null) => None,
        Some(serde_json::Value::String(s)) => Some(s),
        Some(other) => Some(other.to_string()),
    })
}

/// A row of the `targets` table.
#[derive(Debug, Clone, sqlx::FromRow, serde::Serialize, serde::Deserialize)]
pub struct Target {
    pub id: i64,
    pub url: String,
    pub check_type: String,
    #[serde(default)]
    pub selector: Option<String>,
    #[serde(default)]
    pub ignore_regex: Option<String>,
    #[serde(default, deserialize_with = "de_opt_int")]
    pub check_period_ms: Option<i64>,
    #[serde(default, deserialize_with = "de_opt_int")]
    pub expected_status_code: Option<i64>,
    #[serde(default, deserialize_with = "de_opt_int")]
    pub timeout_ms: Option<i64>,
    #[serde(default, deserialize_with = "de_opt_int")]
    pub max_response_time_ms: Option<i64>,
    #[serde(default)]
    pub check_ssl: Option<i64>,
    pub enabled: i64,
    pub requires_playwright: i64,
    #[serde(default)]
    pub baseline_hash: Option<String>,
    #[serde(default)]
    pub baseline_content: Option<String>,
    #[serde(default)]
    pub baseline_fetched_at: Option<String>,
    #[serde(default, deserialize_with = "de_opt_int")]
    pub pre_check_workflow_id: Option<i64>,
    /// Inline setup-steps manifest replayed before the check (JSON: `{steps, credentials}`).
    /// `None` = no setup (plain HTTP/browser check). Drives the shared checker's pre-check hook.
    #[serde(default, deserialize_with = "de_opt_json_text")]
    pub setup_steps: Option<String>,
    #[serde(default, deserialize_with = "de_opt_int")]
    pub on_change_workflow_id: Option<i64>,
    pub on_change_enabled: i64,
    #[serde(default, deserialize_with = "de_opt_json_text")]
    pub on_change_conditions: Option<String>,
    pub on_change_in_session: i64,
    #[serde(default, deserialize_with = "de_opt_int")]
    pub persona_id: Option<i64>,
    #[serde(default)]
    pub auth_session_encrypted: Option<String>,
    #[serde(default, deserialize_with = "de_opt_json_text")]
    pub notification_providers: Option<String>,
    #[serde(default, deserialize_with = "de_opt_json_text")]
    pub provider_notification_settings: Option<String>,
    #[serde(default)]
    pub notification_title: Option<String>,
    #[serde(default)]
    pub notification_message: Option<String>,
    #[serde(default, deserialize_with = "de_opt_int")]
    pub notification_priority: Option<i64>,
    #[serde(default)]
    pub next_run_at: Option<String>,
    /// Structured recurrence kind: `interval` (default) | `daily` | `weekly`. `interval` uses
    /// `check_period_ms`; daily/weekly use `schedule_time`/`schedule_days`/`schedule_tz`.
    /// `#[sqlx(default)]` keeps `SELECT *` paths working across the additive migration.
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
    pub created_at: String,
    #[serde(default)]
    pub updated_at: Option<String>,
}

/// Fields accepted when creating a target. Only `url` is strictly required; the rest carry the
/// schema defaults when `None`.
#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct NewTarget {
    pub url: String,
    #[serde(default)]
    pub check_type: Option<String>,
    #[serde(default)]
    pub selector: Option<String>,
    #[serde(default)]
    pub ignore_regex: Option<String>,
    #[serde(default, deserialize_with = "de_opt_int")]
    pub check_period_ms: Option<i64>,
    #[serde(default, deserialize_with = "de_opt_int")]
    pub expected_status_code: Option<i64>,
    #[serde(default, deserialize_with = "de_opt_int")]
    pub timeout_ms: Option<i64>,
    #[serde(default, deserialize_with = "de_opt_int")]
    pub max_response_time_ms: Option<i64>,
    #[serde(default, deserialize_with = "de_opt_bool_int")]
    pub check_ssl: Option<i64>,
    #[serde(default, deserialize_with = "de_opt_bool_int")]
    pub enabled: Option<i64>,
    #[serde(default, deserialize_with = "de_opt_bool_int")]
    pub requires_playwright: Option<i64>,
    #[serde(default, deserialize_with = "de_opt_int")]
    pub pre_check_workflow_id: Option<i64>,
    /// Inline setup-steps manifest (JSON `{steps, credentials}`) replayed before the check.
    #[serde(default, deserialize_with = "de_opt_json_text")]
    pub setup_steps: Option<String>,
    #[serde(default, deserialize_with = "de_opt_int")]
    pub on_change_workflow_id: Option<i64>,
    #[serde(default, deserialize_with = "de_opt_bool_int")]
    pub on_change_enabled: Option<i64>,
    #[serde(default, deserialize_with = "de_opt_json_text")]
    pub on_change_conditions: Option<String>,
    #[serde(default, deserialize_with = "de_opt_bool_int")]
    pub on_change_in_session: Option<i64>,
    #[serde(default, deserialize_with = "de_opt_int")]
    pub persona_id: Option<i64>,
    #[serde(default, deserialize_with = "de_opt_json_text")]
    pub notification_providers: Option<String>,
    #[serde(default, deserialize_with = "de_opt_json_text")]
    pub provider_notification_settings: Option<String>,
    #[serde(default)]
    pub notification_title: Option<String>,
    #[serde(default)]
    pub notification_message: Option<String>,
    #[serde(default, deserialize_with = "de_opt_int")]
    pub notification_priority: Option<i64>,
    #[serde(default)]
    pub next_run_at: Option<String>,
    // Structured recurrence at create time. `schedule_kind` omitted ⇒ column default (`interval`).
    #[serde(default)]
    pub schedule_kind: Option<String>,
    #[serde(default)]
    pub schedule_time: Option<String>,
    /// ISO weekday ints (weekly). Sent as a JSON array of ints; stored as a JSON string.
    #[serde(default, deserialize_with = "de_opt_json_text")]
    pub schedule_days: Option<String>,
    #[serde(default)]
    pub schedule_tz: Option<String>,
}

/// Partial update. `None` fields are left untouched (COALESCE). `enabled`/`next_run_at` are the
/// common scheduler toggles. `updated_at` is always bumped.
#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct TargetUpdate {
    #[serde(default)]
    pub url: Option<String>,
    #[serde(default)]
    pub check_type: Option<String>,
    #[serde(default)]
    pub selector: Option<String>,
    #[serde(default)]
    pub ignore_regex: Option<String>,
    #[serde(default, deserialize_with = "de_opt_int")]
    pub check_period_ms: Option<i64>,
    #[serde(default, deserialize_with = "de_opt_int")]
    pub expected_status_code: Option<i64>,
    #[serde(default, deserialize_with = "de_opt_int")]
    pub timeout_ms: Option<i64>,
    #[serde(default, deserialize_with = "de_opt_int")]
    pub max_response_time_ms: Option<i64>,
    #[serde(default, deserialize_with = "de_opt_bool_int")]
    pub check_ssl: Option<i64>,
    #[serde(default, deserialize_with = "de_opt_bool_int")]
    pub enabled: Option<i64>,
    #[serde(default, deserialize_with = "de_opt_bool_int")]
    pub requires_playwright: Option<i64>,
    /// Inline setup-steps manifest (JSON `{steps, credentials}`). Pass `"null"`/`""` to clear.
    #[serde(default, deserialize_with = "de_opt_json_text")]
    pub setup_steps: Option<String>,
    #[serde(default, deserialize_with = "de_opt_int")]
    pub on_change_workflow_id: Option<i64>,
    #[serde(default, deserialize_with = "de_opt_bool_int")]
    pub on_change_enabled: Option<i64>,
    #[serde(default, deserialize_with = "de_opt_json_text")]
    pub on_change_conditions: Option<String>,
    #[serde(default, deserialize_with = "de_opt_bool_int")]
    pub on_change_in_session: Option<i64>,
    #[serde(default, deserialize_with = "de_opt_int")]
    pub persona_id: Option<i64>,
    #[serde(default, deserialize_with = "de_opt_json_text")]
    pub notification_providers: Option<String>,
    #[serde(default, deserialize_with = "de_opt_json_text")]
    pub provider_notification_settings: Option<String>,
    #[serde(default)]
    pub notification_title: Option<String>,
    #[serde(default)]
    pub notification_message: Option<String>,
    #[serde(default, deserialize_with = "de_opt_int")]
    pub notification_priority: Option<i64>,
    #[serde(default)]
    pub next_run_at: Option<String>,
    /// Structured recurrence: `interval` | `daily` | `weekly`. Absent ⇒ untouched (COALESCE).
    #[serde(default)]
    pub schedule_kind: Option<String>,
    #[serde(default)]
    pub schedule_time: Option<String>,
    /// ISO weekday ints (weekly). Sent on the wire as a JSON array of ints; stored as a JSON string.
    #[serde(default, deserialize_with = "de_opt_json_text")]
    pub schedule_days: Option<String>,
    #[serde(default)]
    pub schedule_tz: Option<String>,
}

const SELECT_COLS: &str = "id, url, check_type, selector, ignore_regex, check_period_ms, \
    expected_status_code, timeout_ms, max_response_time_ms, check_ssl, enabled, requires_playwright, \
    baseline_hash, baseline_content, baseline_fetched_at, pre_check_workflow_id, setup_steps, \
    on_change_workflow_id, \
    on_change_enabled, on_change_conditions, on_change_in_session, persona_id, auth_session_encrypted, \
    notification_providers, provider_notification_settings, notification_title, notification_message, \
    notification_priority, next_run_at, schedule_kind, schedule_time, schedule_days, schedule_tz, \
    created_at, updated_at";

/// Insert a target; returns the new row id.
pub async fn insert(pool: &SqlitePool, t: &NewTarget) -> LocalResult<i64> {
    let id = sqlx::query(
        "INSERT INTO targets (url, check_type, selector, ignore_regex, check_period_ms, \
         expected_status_code, timeout_ms, max_response_time_ms, check_ssl, enabled, requires_playwright, \
         pre_check_workflow_id, on_change_workflow_id, on_change_enabled, on_change_conditions, \
         on_change_in_session, persona_id, notification_providers, provider_notification_settings, \
         notification_title, notification_message, notification_priority, next_run_at, setup_steps, \
         schedule_kind, schedule_time, schedule_days, schedule_tz) \
         VALUES (?, COALESCE(?, 'content'), ?, ?, ?, COALESCE(?, 200), COALESCE(?, 10000), \
         COALESCE(?, 5000), COALESCE(?, 1), COALESCE(?, 1), COALESCE(?, 0), ?, ?, COALESCE(?, 0), \
         COALESCE(?, '{}'), COALESCE(?, 0), ?, COALESCE(?, '{}'), COALESCE(?, '{}'), ?, ?, ?, ?, ?, \
         COALESCE(?, 'interval'), ?, ?, ?)",
    )
    .bind(&t.url)
    .bind(&t.check_type)
    .bind(&t.selector)
    .bind(&t.ignore_regex)
    .bind(t.check_period_ms)
    .bind(t.expected_status_code)
    .bind(t.timeout_ms)
    .bind(t.max_response_time_ms)
    .bind(t.check_ssl)
    .bind(t.enabled)
    .bind(t.requires_playwright)
    .bind(t.pre_check_workflow_id)
    .bind(t.on_change_workflow_id)
    .bind(t.on_change_enabled)
    .bind(&t.on_change_conditions)
    .bind(t.on_change_in_session)
    .bind(t.persona_id)
    .bind(&t.notification_providers)
    .bind(&t.provider_notification_settings)
    .bind(&t.notification_title)
    .bind(&t.notification_message)
    .bind(t.notification_priority)
    .bind(&t.next_run_at)
    .bind(&t.setup_steps)
    .bind(&t.schedule_kind)
    .bind(&t.schedule_time)
    .bind(&t.schedule_days)
    .bind(&t.schedule_tz)
    .execute(pool)
    .await?
    .last_insert_rowid();
    tracing::info!(target_id = id, url = %t.url, "target inserted");
    Ok(id)
}

/// Fetch one target by id, or `None` if absent.
pub async fn get_by_id(pool: &SqlitePool, id: i64) -> LocalResult<Option<Target>> {
    let row = sqlx::query_as::<_, Target>(&format!("SELECT {SELECT_COLS} FROM targets WHERE id = ?"))
        .bind(id)
        .fetch_optional(pool)
        .await?;
    Ok(row)
}

/// Fetch many targets by id in ONE round trip. Empty input ⇒ empty result. Ids that do not exist are
/// simply absent from the result, so the caller must not assume a 1:1 index with `ids`.
///
/// Mirrors [`super::monitor_state::get_many`]. Callers that hold a set of ids should use this rather
/// than looping over [`get_by_id`] — the scheduler's stale sweep runs on every tick and was issuing
/// one query per monitored target.
pub async fn get_many(pool: &SqlitePool, ids: &[i64]) -> LocalResult<Vec<Target>> {
    if ids.is_empty() {
        return Ok(Vec::new());
    }
    let placeholders = std::iter::repeat_n("?", ids.len()).collect::<Vec<_>>().join(",");
    let sql = format!("SELECT {SELECT_COLS} FROM targets WHERE id IN ({placeholders})");
    let mut q = sqlx::query_as::<_, Target>(&sql);
    for id in ids {
        q = q.bind(id);
    }
    Ok(q.fetch_all(pool).await?)
}

/// List targets newest-first, capped at `limit`.
pub async fn list(pool: &SqlitePool, limit: i64) -> LocalResult<Vec<Target>> {
    let rows = sqlx::query_as::<_, Target>(&format!(
        "SELECT {SELECT_COLS} FROM targets ORDER BY created_at DESC, id DESC LIMIT ?"
    ))
    .bind(limit)
    .fetch_all(pool)
    .await?;
    Ok(rows)
}

/// List only enabled targets, newest-first, capped at `limit`.
pub async fn list_enabled(pool: &SqlitePool, limit: i64) -> LocalResult<Vec<Target>> {
    let rows = sqlx::query_as::<_, Target>(&format!(
        "SELECT {SELECT_COLS} FROM targets WHERE enabled = 1 ORDER BY created_at DESC, id DESC LIMIT ?"
    ))
    .bind(limit)
    .fetch_all(pool)
    .await?;
    Ok(rows)
}

/// List targets of ONE `check_type` (e.g. `content` vs `uptime`), newest-first, capped at `limit`.
/// Backs the `GET /v1/monitors?check_type=` filter so the desktop "Checks" list shows only the kind
/// it asked for instead of every target.
pub async fn list_by_check_type(
    pool: &SqlitePool,
    check_type: &str,
    limit: i64,
) -> LocalResult<Vec<Target>> {
    let rows = sqlx::query_as::<_, Target>(&format!(
        "SELECT {SELECT_COLS} FROM targets WHERE check_type = ? ORDER BY created_at DESC, id DESC LIMIT ?"
    ))
    .bind(check_type)
    .bind(limit)
    .fetch_all(pool)
    .await?;
    Ok(rows)
}

/// Enabled targets whose `next_run_at` is due (<= `now_rfc3339`) or unset, oldest-due first.
/// Scheduler tick query (mirrors `ix_targets_due`).
pub async fn list_due(pool: &SqlitePool, now_rfc3339: &str, limit: i64) -> LocalResult<Vec<Target>> {
    let rows = sqlx::query_as::<_, Target>(&format!(
        "SELECT {SELECT_COLS} FROM targets \
         WHERE enabled = 1 AND (next_run_at IS NULL OR next_run_at <= ?) \
         ORDER BY next_run_at ASC LIMIT ?"
    ))
    .bind(now_rfc3339)
    .bind(limit)
    .fetch_all(pool)
    .await?;
    Ok(rows)
}

/// Apply a partial update; bumps `updated_at`. Returns the refreshed row (or `None` if absent).
pub async fn update(pool: &SqlitePool, id: i64, u: &TargetUpdate) -> LocalResult<Option<Target>> {
    sqlx::query(
        "UPDATE targets SET \
         url = COALESCE(?, url), \
         check_type = COALESCE(?, check_type), \
         selector = COALESCE(?, selector), \
         ignore_regex = COALESCE(?, ignore_regex), \
         check_period_ms = COALESCE(?, check_period_ms), \
         expected_status_code = COALESCE(?, expected_status_code), \
         timeout_ms = COALESCE(?, timeout_ms), \
         max_response_time_ms = COALESCE(?, max_response_time_ms), \
         check_ssl = COALESCE(?, check_ssl), \
         enabled = COALESCE(?, enabled), \
         requires_playwright = COALESCE(?, requires_playwright), \
         on_change_workflow_id = COALESCE(?, on_change_workflow_id), \
         on_change_enabled = COALESCE(?, on_change_enabled), \
         on_change_conditions = COALESCE(?, on_change_conditions), \
         on_change_in_session = COALESCE(?, on_change_in_session), \
         persona_id = COALESCE(?, persona_id), \
         notification_providers = COALESCE(?, notification_providers), \
         provider_notification_settings = COALESCE(?, provider_notification_settings), \
         notification_title = COALESCE(?, notification_title), \
         notification_message = COALESCE(?, notification_message), \
         notification_priority = COALESCE(?, notification_priority), \
         next_run_at = COALESCE(?, next_run_at), \
         setup_steps = COALESCE(?, setup_steps), \
         schedule_kind = COALESCE(?, schedule_kind), \
         schedule_time = COALESCE(?, schedule_time), \
         schedule_days = COALESCE(?, schedule_days), \
         schedule_tz = COALESCE(?, schedule_tz), \
         updated_at = strftime('%Y-%m-%dT%H:%M:%fZ','now') \
         WHERE id = ?",
    )
    .bind(&u.url)
    .bind(&u.check_type)
    .bind(&u.selector)
    .bind(&u.ignore_regex)
    .bind(u.check_period_ms)
    .bind(u.expected_status_code)
    .bind(u.timeout_ms)
    .bind(u.max_response_time_ms)
    .bind(u.check_ssl)
    .bind(u.enabled)
    .bind(u.requires_playwright)
    .bind(u.on_change_workflow_id)
    .bind(u.on_change_enabled)
    .bind(&u.on_change_conditions)
    .bind(u.on_change_in_session)
    .bind(u.persona_id)
    .bind(&u.notification_providers)
    .bind(&u.provider_notification_settings)
    .bind(&u.notification_title)
    .bind(&u.notification_message)
    .bind(u.notification_priority)
    .bind(&u.next_run_at)
    .bind(&u.setup_steps)
    .bind(&u.schedule_kind)
    .bind(&u.schedule_time)
    .bind(&u.schedule_days)
    .bind(&u.schedule_tz)
    .bind(id)
    .execute(pool)
    .await?;
    get_by_id(pool, id).await
}

/// Update the captured baseline (hash/content) and stamp `baseline_fetched_at`/`updated_at` now.
pub async fn set_baseline(
    pool: &SqlitePool,
    id: i64,
    baseline_hash: Option<&str>,
    baseline_content: Option<&str>,
) -> LocalResult<()> {
    sqlx::query(
        "UPDATE targets SET baseline_hash = ?, baseline_content = ?, \
         baseline_fetched_at = strftime('%Y-%m-%dT%H:%M:%fZ','now'), \
         updated_at = strftime('%Y-%m-%dT%H:%M:%fZ','now') WHERE id = ?",
    )
    .bind(baseline_hash)
    .bind(baseline_content)
    .bind(id)
    .execute(pool)
    .await?;
    Ok(())
}

/// Set the next scheduler due-key (`next_run_at`) and bump `updated_at`.
pub async fn set_next_run_at(pool: &SqlitePool, id: i64, next_run_at: Option<&str>) -> LocalResult<()> {
    sqlx::query(
        "UPDATE targets SET next_run_at = ?, updated_at = strftime('%Y-%m-%dT%H:%M:%fZ','now') WHERE id = ?",
    )
    .bind(next_run_at)
    .bind(id)
    .execute(pool)
    .await?;
    Ok(())
}

/// Toggle `enabled`; bumps `updated_at`. Returns rows affected (0 if no such target).
pub async fn set_enabled(pool: &SqlitePool, id: i64, enabled: bool) -> LocalResult<u64> {
    let n = sqlx::query(
        "UPDATE targets SET enabled = ?, updated_at = strftime('%Y-%m-%dT%H:%M:%fZ','now') WHERE id = ?",
    )
    .bind(enabled as i64)
    .bind(id)
    .execute(pool)
    .await?
    .rows_affected();
    Ok(n)
}

/// Hard-delete a target (cascades to selectors/state/changes/uptime via FKs). Returns rows affected.
pub async fn delete(pool: &SqlitePool, id: i64) -> LocalResult<u64> {
    let n = sqlx::query("DELETE FROM targets WHERE id = ?")
        .bind(id)
        .execute(pool)
        .await?
        .rows_affected();
    tracing::info!(target_id = id, deleted = n, "target deleted");
    Ok(n)
}

/// Count all targets.
pub async fn count(pool: &SqlitePool) -> LocalResult<i64> {
    let n: i64 = sqlx::query("SELECT count(*) FROM targets")
        .fetch_one(pool)
        .await?
        .try_get(0)?;
    Ok(n)
}
