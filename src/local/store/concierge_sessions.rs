//! Store layer for the `concierge_sessions` table (0008_concierge_sessions.sql) — the AI concierge
//! assistant's persistent mission state (natural-language goal -> live watch+notify automation).
//!
//! Runtime-checked sqlx only. A session starts in `status='planning'` (via [`insert`]), advances
//! through its mission loop with the general [`update`] (status/phase/progress + the JSON-TEXT
//! transcript/brain_history/plan/pending_request/answers/resources + token counts + turn_seq), and is
//! finalized to a terminal state via [`finalize`]. Every JSON column is TEXT — the caller serdes it
//! with `serde_json` before storing and parses after reading. The desktop scope has NO autobuy, so a
//! monitor-only mission ends at `done` (never `armed`).

use super::super::error::{LocalError, LocalResult};
use sqlx::sqlite::SqlitePool;
use sqlx::Row as _;

/// A full `concierge_sessions` row.
///
/// `Debug` is hand-written (see the `store` module docs). `transcript`/`answers` hold whatever the user
/// typed into the assistant — which is where a login, a card number or a one-time code arrives when the
/// mission asks for one — and `live_screenshot` is a frame of a logged-in page. A derived `Debug` put
/// all three, in full, into any log line that formatted a session.
#[derive(Clone, sqlx::FromRow, serde::Serialize, serde::Deserialize)]
pub struct ConciergeSession {
    pub id: i64,
    pub goal: String,
    pub platform: String,
    pub status: String,
    #[serde(default)]
    pub phase: Option<String>,
    #[serde(default)]
    pub progress_message: Option<String>,
    #[serde(default)]
    pub transcript: Option<String>,
    #[serde(default)]
    pub brain_history: Option<String>,
    #[serde(default)]
    pub plan: Option<String>,
    #[serde(default)]
    pub pending_request: Option<String>,
    #[serde(default)]
    pub answers: Option<String>,
    #[serde(default)]
    pub resources: Option<String>,
    #[serde(default)]
    pub browse_session_id: Option<i64>,
    /// Base64 JPEG (no `data:` prefix) of the page the concierge is on — the FE preview frame.
    #[serde(default)]
    pub live_screenshot: Option<String>,
    /// URL of the page captured alongside `live_screenshot`.
    #[serde(default)]
    pub current_url: Option<String>,
    pub input_tokens: i64,
    pub output_tokens: i64,
    pub total_tokens: i64,
    pub ai_calls_count: i64,
    pub turn_seq: i64,
    pub cancel_requested: i64,
    #[serde(default)]
    pub error_message: Option<String>,
    pub created_at: String,
    #[serde(default)]
    pub updated_at: Option<String>,
    #[serde(default)]
    pub completed_at: Option<String>,
}

/// Caller-supplied fields to start a concierge mission. Anything omitted falls to the column default
/// (`status='planning'`, `platform='desktop'`, JSON fields `{}`/`[]`, counters `0`).
#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct NewConciergeSession {
    pub goal: String,
    /// Defaults to `'desktop'` (autobuy is cloud-only; a local mission is watch+notify).
    #[serde(default)]
    pub platform: Option<String>,
    /// JSON-TEXT the caller has already serialized (seeded plan, e.g. `{"resolved_url":..}`).
    #[serde(default)]
    pub plan: Option<String>,
    /// JSON-TEXT the caller has already serialized (opening transcript line).
    #[serde(default)]
    pub transcript: Option<String>,
}

/// The general mutable-state patch applied on each mission turn. Every `None` field is left
/// untouched (COALESCE). JSON-TEXT fields (`transcript`/`brain_history`/`plan`/`pending_request`/
/// `answers`/`resources`) are already serialized by the caller. Token counts are SET (not summed) so
/// the caller accumulates and passes the running total. `updated_at` is always bumped.
#[derive(Debug, Clone, Default)]
pub struct ConciergeUpdate<'a> {
    pub status: Option<&'a str>,
    pub phase: Option<&'a str>,
    pub progress_message: Option<&'a str>,
    pub transcript: Option<&'a str>,
    pub brain_history: Option<&'a str>,
    pub plan: Option<&'a str>,
    /// `Some("")` clears `pending_request` to SQL NULL; `Some(json)` sets it; `None` leaves it.
    pub pending_request: Option<&'a str>,
    pub answers: Option<&'a str>,
    pub resources: Option<&'a str>,
    pub browse_session_id: Option<i64>,
    /// Base64 JPEG (no `data:` prefix) — the FE preview frame; `None` leaves it untouched.
    pub live_screenshot: Option<&'a str>,
    /// URL of the page captured alongside `live_screenshot`; `None` leaves it untouched.
    pub current_url: Option<&'a str>,
    pub input_tokens: Option<i64>,
    pub output_tokens: Option<i64>,
    pub total_tokens: Option<i64>,
    pub ai_calls_count: Option<i64>,
    pub turn_seq: Option<i64>,
    pub cancel_requested: Option<i64>,
    /// OPTIMISTIC LOCK. When `Some(n)` the whole-column write only applies if the row's `turn_seq` is
    /// still `n`; otherwise another writer moved the mission on since this patch was computed and
    /// [`update`] returns [`LocalError::Conflict`] so the caller can re-read and re-apply.
    ///
    /// Migration `0008` introduced `turn_seq` for exactly this and nothing enforced it — every write
    /// was `WHERE id = ?1`, so the last writer won and silently discarded the other's changes. Leave
    /// it `None` for a genuinely last-write-wins field (`live_screenshot`, `progress_message`); set it
    /// whenever the patch was derived from a value you READ (any read-modify-write of a JSON column).
    pub expect_turn_seq: Option<i64>,
}

const SELECT_COLS: &str = "id, goal, platform, status, phase, progress_message, transcript,
    brain_history, plan, pending_request, answers, resources, browse_session_id, live_screenshot,
    current_url, input_tokens, output_tokens, total_tokens, ai_calls_count, turn_seq,
    cancel_requested, error_message, created_at, updated_at, completed_at";

/// Start a concierge mission (`status='planning'`). Returns the full row.
pub async fn insert(pool: &SqlitePool, new: &NewConciergeSession) -> LocalResult<ConciergeSession> {
    let id: i64 = sqlx::query(
        "INSERT INTO concierge_sessions (goal, platform, status, plan, transcript)
         VALUES (?1, COALESCE(?2, 'desktop'), 'planning', COALESCE(?3, '{}'), COALESCE(?4, '[]'))
         RETURNING id",
    )
    .bind(&new.goal)
    .bind(&new.platform)
    .bind(&new.plan)
    .bind(&new.transcript)
    .fetch_one(pool)
    .await?
    .try_get(0)?;

    tracing::info!(concierge_session_id = id, "concierge mission started");
    get_by_id(pool, id)
        .await?
        .ok_or_else(|| LocalError::Internal("concierge_session vanished after insert".into()))
}

/// Fetch one concierge session by id.
pub async fn get_by_id(pool: &SqlitePool, id: i64) -> LocalResult<Option<ConciergeSession>> {
    let row = sqlx::query_as::<_, ConciergeSession>(&format!(
        "SELECT {SELECT_COLS} FROM concierge_sessions WHERE id = ?1"
    ))
    .bind(id)
    .fetch_optional(pool)
    .await?;
    Ok(row)
}

/// List concierge sessions newest-first, capped at `limit`.
pub async fn list(pool: &SqlitePool, limit: i64) -> LocalResult<Vec<ConciergeSession>> {
    let limit = limit.clamp(1, 1000);
    let rows = sqlx::query_as::<_, ConciergeSession>(&format!(
        "SELECT {SELECT_COLS} FROM concierge_sessions ORDER BY created_at DESC, id DESC LIMIT ?1"
    ))
    .bind(limit)
    .fetch_all(pool)
    .await?;
    Ok(rows)
}

/// Apply the general mid-mission patch (see [`ConciergeUpdate`]). `None` fields are COALESCE'd (kept);
/// `pending_request = Some("")` clears the column to NULL. Bumps `updated_at`. Returns the refreshed
/// row (or `None` if absent).
///
/// # Concurrency
///
/// Every JSON field here is a WHOLE-COLUMN write. Two writers that each read the column, mutate a
/// different sub-key, and write it back will silently lose one of the two edits. Pass
/// [`ConciergeUpdate::expect_turn_seq`] to detect that (409 + retry), or — better — use
/// [`set_json_key`] to write only the sub-key you own, which cannot collide at all.
pub async fn update(
    pool: &SqlitePool,
    id: i64,
    u: &ConciergeUpdate<'_>,
) -> LocalResult<Option<ConciergeSession>> {
    // Empty-string on pending_request means "clear to NULL"; any other Some sets it; None keeps it.
    let pending_bind: Option<&str> = match u.pending_request {
        Some("") => None,             // will store SQL NULL (via the CASE below)
        other => other,               // Some(json) sets, None keeps (COALESCE)
    };
    let clear_pending = matches!(u.pending_request, Some(""));

    let res = sqlx::query(
        "UPDATE concierge_sessions SET
            status = COALESCE(?2, status),
            phase = COALESCE(?3, phase),
            progress_message = COALESCE(?4, progress_message),
            transcript = COALESCE(?5, transcript),
            brain_history = COALESCE(?6, brain_history),
            plan = COALESCE(?7, plan),
            pending_request = CASE WHEN ?15 = 1 THEN NULL ELSE COALESCE(?8, pending_request) END,
            answers = COALESCE(?9, answers),
            resources = COALESCE(?10, resources),
            browse_session_id = COALESCE(?11, browse_session_id),
            live_screenshot = COALESCE(?19, live_screenshot),
            current_url = COALESCE(?20, current_url),
            input_tokens = COALESCE(?12, input_tokens),
            output_tokens = COALESCE(?13, output_tokens),
            total_tokens = COALESCE(?14, total_tokens),
            ai_calls_count = COALESCE(?16, ai_calls_count),
            turn_seq = COALESCE(?17, turn_seq),
            cancel_requested = COALESCE(?18, cancel_requested),
            updated_at = strftime('%Y-%m-%dT%H:%M:%fZ','now')
         WHERE id = ?1 AND (?21 IS NULL OR turn_seq = ?21)",
    )
    .bind(id)
    .bind(u.status)
    .bind(u.phase)
    .bind(u.progress_message)
    .bind(u.transcript)
    .bind(u.brain_history)
    .bind(u.plan)
    .bind(pending_bind)
    .bind(u.answers)
    .bind(u.resources)
    .bind(u.browse_session_id)
    .bind(u.input_tokens)
    .bind(u.output_tokens)
    .bind(u.total_tokens)
    .bind(clear_pending as i64)
    .bind(u.ai_calls_count)
    .bind(u.turn_seq)
    .bind(u.cancel_requested)
    .bind(u.live_screenshot)
    .bind(u.current_url)
    .bind(u.expect_turn_seq)
    .execute(pool)
    .await?;

    // Zero rows with a lock in force means either "row gone" or "lost the race". Distinguish, so a
    // caller can retry a genuine conflict instead of treating it as a missing mission.
    if res.rows_affected() == 0 && u.expect_turn_seq.is_some() {
        return match get_by_id(pool, id).await? {
            Some(cur) => Err(LocalError::Conflict(format!(
                "concierge_session {id} moved on (turn_seq {} != expected {}); re-read and re-apply",
                cur.turn_seq,
                u.expect_turn_seq.unwrap_or_default()
            ))),
            None => Ok(None),
        };
    }
    get_by_id(pool, id).await
}

/// Top-level JSON columns [`set_json_key`] may address. An explicit allowlist, not a sanitizer: the
/// column name is interpolated into SQL, so anything outside this set must be rejected outright.
const JSON_COLUMNS: &[&str] = &["resources", "plan", "answers"];

/// Write (or remove) ONE top-level sub-key of a JSON column **in the database**, leaving every other
/// sub-key exactly as it is on disk.
///
/// This exists because the read-modify-write shape around [`update`] lost writes in production: the
/// concierge crawl loop rewrites the whole `resources` column roughly once a second with live crawl
/// counters, while `POST /v1/ai-concierge/:id/persona` independently rewrites the same column to
/// attach a login identity. Whichever wrote second erased the other's key — a persona attached during
/// a crawl vanished, or `crawl_live` reverted and the live progress card froze. `json_set` touches one
/// path, so two writers on two different keys both survive with no locking and no retry.
///
/// `value` is JSON TEXT (`json(?)` validates it — invalid JSON is rejected by SQLite, not stored);
/// `None` removes the key. Returns `false` when no such session row exists.
pub async fn set_json_key(
    pool: &SqlitePool,
    id: i64,
    column: &str,
    key: &str,
    value: Option<&str>,
) -> LocalResult<bool> {
    // Column: allowlist. `key`: a JSON path fragment — reject anything that could steer the path
    // somewhere else (`.`, `[`, `"`, `$`) so `$.<key>` can only ever be one top-level member.
    if !JSON_COLUMNS.contains(&column) {
        return Err(LocalError::Internal(format!(
            "set_json_key: {column:?} is not a JSON column of concierge_sessions"
        )));
    }
    if key.is_empty() || !key.chars().all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-') {
        return Err(LocalError::BadRequest(format!(
            "set_json_key: {key:?} is not a simple JSON member name"
        )));
    }
    let path = format!("$.{key}");

    // `json_set`/`json_remove` need a JSON object to work on; a NULL or empty column would make the
    // whole expression NULL and wipe the column, so normalize to `{}` first. `json_valid` guards the
    // (never-seen but possible) case of a column holding non-JSON text.
    let sql = if value.is_some() {
        format!(
            "UPDATE concierge_sessions SET
                {column} = json_set(
                    CASE WHEN json_valid({column}) THEN {column} ELSE '{{}}' END, ?2, json(?3)),
                updated_at = strftime('%Y-%m-%dT%H:%M:%fZ','now')
             WHERE id = ?1"
        )
    } else {
        format!(
            "UPDATE concierge_sessions SET
                {column} = json_remove(
                    CASE WHEN json_valid({column}) THEN {column} ELSE '{{}}' END, ?2),
                updated_at = strftime('%Y-%m-%dT%H:%M:%fZ','now')
             WHERE id = ?1"
        )
    };
    let mut q = sqlx::query(&sql).bind(id).bind(&path);
    if let Some(v) = value {
        q = q.bind(v); // only the json_set variant has a ?3
    }
    let n = q.execute(pool).await?.rows_affected();
    Ok(n > 0)
}

/// Boot reconciliation: mark orphaned ACTIVE missions — whose loop a crash/restart killed — as
/// `cancelled` so they stop showing as in-flight and can't trap the UI (Stop does nothing when no loop
/// is running to observe the flag). Only ACTIVE-not-paused statuses are swept; `awaiting_input` is a
/// resumable pause (`/respond` re-spawns the loop) and is left intact. Safe to call only after the
/// singleton lock is held. Returns the number of rows reconciled.
pub async fn interrupt_orphaned(pool: &SqlitePool) -> LocalResult<u64> {
    let n = sqlx::query(
        "UPDATE concierge_sessions SET
            status = 'cancelled',
            cancel_requested = 0,
            pending_request = NULL,
            progress_message = 'Stopped: the app restarted while the assistant was working.',
            updated_at = strftime('%Y-%m-%dT%H:%M:%fZ','now'),
            completed_at = strftime('%Y-%m-%dT%H:%M:%fZ','now')
         WHERE status IN ('planning','browsing','proposing','building')",
    )
    .execute(pool)
    .await?
    .rows_affected();
    Ok(n)
}

/// Finalize a mission to a terminal `status` (`done|error|cancelled`), stamping `completed_at=now`,
/// an optional `error_message`, and (optionally) the final progress line. Also clears any
/// `pending_request`. Returns the finalized row.
pub async fn finalize(
    pool: &SqlitePool,
    id: i64,
    status: &str,
    progress_message: Option<&str>,
    error_message: Option<&str>,
) -> LocalResult<ConciergeSession> {
    let res = sqlx::query(
        "UPDATE concierge_sessions SET
            status = ?2,
            progress_message = COALESCE(?3, progress_message),
            error_message = ?4,
            pending_request = NULL,
            updated_at = strftime('%Y-%m-%dT%H:%M:%fZ','now'),
            completed_at = strftime('%Y-%m-%dT%H:%M:%fZ','now')
         WHERE id = ?1",
    )
    .bind(id)
    .bind(status)
    .bind(progress_message)
    .bind(error_message)
    .execute(pool)
    .await?;
    if res.rows_affected() == 0 {
        return Err(LocalError::NotFound(format!("concierge_session {id}")));
    }
    tracing::info!(concierge_session_id = id, status = %status, "concierge mission finalized");
    get_by_id(pool, id)
        .await?
        .ok_or_else(|| LocalError::NotFound(format!("concierge_session {id}")))
}

impl std::fmt::Debug for ConciergeSession {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ConciergeSession")
            .field("id", &self.id)
            .field("goal", &self.goal)
            .field("platform", &self.platform)
            .field("status", &self.status)
            .field("phase", &self.phase)
            .field("turn_seq", &self.turn_seq)
            .field("cancel_requested", &self.cancel_requested)
            .field("total_tokens", &self.total_tokens)
            // User-typed content and a frame of a logged-in page.
            .field("transcript", &super::redacted(&self.transcript))
            .field("answers", &super::redacted(&self.answers))
            .field("pending_request", &super::redacted(&self.pending_request))
            .field("live_screenshot", &super::redacted(&self.live_screenshot))
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::local::db;

    async fn pool() -> SqlitePool {
        let dir = Box::leak(Box::new(tempfile::tempdir().unwrap()));
        db::open(&dir.path().join("t.db"), "test-key-concierge").await.unwrap()
    }

    #[tokio::test]
    async fn insert_update_get_finalize() {
        let pool = pool().await;
        let s = insert(
            &pool,
            &NewConciergeSession {
                goal: "watch the price of the Widget on example.com and alert me when it drops".into(),
                transcript: Some(r#"[{"role":"user","content":"watch the price","ts":1}]"#.into()),
                ..Default::default()
            },
        )
        .await
        .unwrap();
        assert_eq!(s.status, "planning");
        assert_eq!(s.platform, "desktop"); // COALESCE default
        assert_eq!(s.turn_seq, 0);
        assert_eq!(s.cancel_requested, 0);
        assert_eq!(s.plan.as_deref(), Some("{}")); // COALESCE default
        assert!(s.transcript.as_deref().unwrap().contains("watch the price"));

        // Mid-mission patch: advance phase, set a plan + pending_request, accrue tokens, bump turn_seq.
        let mid = update(
            &pool,
            s.id,
            &ConciergeUpdate {
                status: Some("awaiting_input"),
                phase: Some("ask_user"),
                progress_message: Some("Need the target price"),
                plan: Some(r#"{"resolved_url":"https://example.com/widget","price_selector":".price"}"#),
                pending_request: Some(
                    r#"{"requests":[{"field":"threshold","kind":"value","question":"Alert below what price?"}],"resume_status":"building"}"#,
                ),
                input_tokens: Some(120),
                output_tokens: Some(45),
                total_tokens: Some(165),
                ai_calls_count: Some(1),
                turn_seq: Some(1),
                ..Default::default()
            },
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(mid.status, "awaiting_input");
        assert_eq!(mid.phase.as_deref(), Some("ask_user"));
        assert!(mid.plan.as_deref().unwrap().contains("resolved_url"));
        assert!(mid.pending_request.as_deref().unwrap().contains("threshold"));
        assert_eq!(mid.input_tokens, 120);
        assert_eq!(mid.total_tokens, 165);
        assert_eq!(mid.turn_seq, 1);
        assert!(mid.updated_at.is_some());

        // A re-fetch matches the patch (round-trip through the DB).
        let got = get_by_id(&pool, s.id).await.unwrap().unwrap();
        assert_eq!(got.turn_seq, 1);
        assert_eq!(got.ai_calls_count, 1);

        // Clearing pending_request (Some("")) sets it NULL; a partial patch keeps everything else.
        let resumed = update(
            &pool,
            s.id,
            &ConciergeUpdate {
                status: Some("building"),
                pending_request: Some(""),
                answers: Some(r#"{"threshold":"19.99"}"#),
                turn_seq: Some(2),
                ..Default::default()
            },
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(resumed.status, "building");
        assert!(resumed.pending_request.is_none(), "cleared to NULL");
        assert_eq!(resumed.answers.as_deref(), Some(r#"{"threshold":"19.99"}"#));
        assert_eq!(resumed.turn_seq, 2);
        // Untouched fields survived the partial patch.
        assert!(resumed.plan.as_deref().unwrap().contains("resolved_url"));
        assert_eq!(resumed.input_tokens, 120);

        // Finalize to done — clears pending_request, stamps completed_at.
        let done = finalize(&pool, s.id, "done", Some("Monitor + alert are live."), None).await.unwrap();
        assert_eq!(done.status, "done");
        assert!(done.completed_at.is_some());
        assert!(done.pending_request.is_none());
        assert_eq!(done.progress_message.as_deref(), Some("Monitor + alert are live."));

        assert_eq!(list(&pool, 50).await.unwrap().len(), 1);
    }

    #[tokio::test]
    async fn finalize_missing_is_not_found() {
        let pool = pool().await;
        let err = finalize(&pool, 999, "error", None, Some("nope")).await;
        assert!(matches!(err, Err(LocalError::NotFound(_))));
    }

    // ------------------------------------------------------------------
    // Concurrency: two writers on two different sub-keys must BOTH survive.
    // ------------------------------------------------------------------

    async fn seed(pool: &SqlitePool) -> i64 {
        insert(pool, &NewConciergeSession { goal: "g".into(), ..Default::default() })
            .await
            .unwrap()
            .id
    }

    fn resources_of(s: &ConciergeSession) -> serde_json::Value {
        serde_json::from_str(s.resources.as_deref().unwrap_or("{}")).unwrap()
    }

    /// THE REGRESSION: the crawl loop's `resources.crawl_live` and the persona endpoint's
    /// `resources.persona_id` are written by independent tasks. With whole-column read-modify-write
    /// the later writer erased the earlier key. `set_json_key` must keep both.
    #[tokio::test]
    async fn concurrent_sub_key_writes_both_survive() {
        let pool = pool().await;
        let id = seed(&pool).await;

        // Both writers snapshot the SAME starting state (this is the interleaving that lost data).
        let before = get_by_id(&pool, id).await.unwrap().unwrap();
        assert_eq!(resources_of(&before), serde_json::json!({}));

        let a = set_json_key(&pool, id, "resources", "crawl_live", Some(r#"{"pages_done":7}"#));
        let b = set_json_key(&pool, id, "resources", "persona_id", Some("42"));
        let (ra, rb) = tokio::join!(a, b);
        assert!(ra.unwrap() && rb.unwrap());

        let got = resources_of(&get_by_id(&pool, id).await.unwrap().unwrap());
        assert_eq!(got["crawl_live"]["pages_done"], 7, "crawl_live lost: {got}");
        assert_eq!(got["persona_id"], 42, "persona_id lost: {got}");

        // Repeated ticks replace only their own key.
        set_json_key(&pool, id, "resources", "crawl_live", Some(r#"{"pages_done":9}"#))
            .await
            .unwrap();
        let got = resources_of(&get_by_id(&pool, id).await.unwrap().unwrap());
        assert_eq!(got["crawl_live"]["pages_done"], 9);
        assert_eq!(got["persona_id"], 42, "unrelated key must survive a re-tick: {got}");

        // Detach clears just that member.
        set_json_key(&pool, id, "resources", "persona_id", None).await.unwrap();
        let got = resources_of(&get_by_id(&pool, id).await.unwrap().unwrap());
        assert!(got.get("persona_id").is_none());
        assert_eq!(got["crawl_live"]["pages_done"], 9);
    }

    #[tokio::test]
    async fn set_json_key_normalizes_absent_column_and_reports_missing_row() {
        let pool = pool().await;
        let id = seed(&pool).await;
        // `answers` starts as the schema default, and a NULL/garbage column must not be wiped to NULL.
        sqlx::query("UPDATE concierge_sessions SET answers = NULL WHERE id = ?1")
            .bind(id)
            .execute(&pool)
            .await
            .unwrap();
        assert!(set_json_key(&pool, id, "answers", "threshold", Some("\"19.99\"")).await.unwrap());
        let s = get_by_id(&pool, id).await.unwrap().unwrap();
        let answers: serde_json::Value = serde_json::from_str(s.answers.as_deref().unwrap()).unwrap();
        assert_eq!(answers["threshold"], "19.99");

        // Unknown row → false, not an error.
        assert!(!set_json_key(&pool, 9999, "resources", "k", Some("1")).await.unwrap());
        // Column allowlist + member-name validation are enforced, not sanitized away.
        assert!(set_json_key(&pool, id, "transcript", "k", Some("1")).await.is_err());
        assert!(set_json_key(&pool, id, "resources", "a.b", Some("1")).await.is_err());
        assert!(set_json_key(&pool, id, "resources", "", Some("1")).await.is_err());
    }

    /// `turn_seq` is documented in migration 0008 as an optimistic lock; it must actually gate the
    /// whole-column writes that still need one.
    #[tokio::test]
    async fn turn_seq_optimistic_lock_rejects_a_stale_writer() {
        let pool = pool().await;
        let id = seed(&pool).await;

        // Writer A reads turn_seq = 0 and commits turn 1.
        let ok = update(
            &pool,
            id,
            &ConciergeUpdate {
                plan: Some(r#"{"a":1}"#),
                turn_seq: Some(1),
                expect_turn_seq: Some(0),
                ..Default::default()
            },
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(ok.turn_seq, 1);

        // Writer B still believes it is turn 0 → conflict, and the row is untouched.
        let err = update(
            &pool,
            id,
            &ConciergeUpdate {
                plan: Some(r#"{"b":2}"#),
                turn_seq: Some(1),
                expect_turn_seq: Some(0),
                ..Default::default()
            },
        )
        .await;
        assert!(matches!(err, Err(LocalError::Conflict(_))), "expected a conflict, got {err:?}");
        let cur = get_by_id(&pool, id).await.unwrap().unwrap();
        assert_eq!(cur.plan.as_deref(), Some(r#"{"a":1}"#), "the stale write must not have applied");

        // Re-read + re-apply succeeds.
        let ok = update(
            &pool,
            id,
            &ConciergeUpdate {
                plan: Some(r#"{"b":2}"#),
                turn_seq: Some(2),
                expect_turn_seq: Some(cur.turn_seq),
                ..Default::default()
            },
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(ok.plan.as_deref(), Some(r#"{"b":2}"#));

        // An absent row is still `Ok(None)`, not a conflict.
        assert!(update(
            &pool,
            4242,
            &ConciergeUpdate { expect_turn_seq: Some(0), ..Default::default() }
        )
        .await
        .unwrap()
        .is_none());

        // Without the lock the behaviour is unchanged (last write wins).
        assert!(update(
            &pool,
            id,
            &ConciergeUpdate { progress_message: Some("live"), ..Default::default() }
        )
        .await
        .unwrap()
        .is_some());
    }
}
