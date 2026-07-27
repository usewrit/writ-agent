//! `/v1/ai-sessions/*` REST handlers — LAUNCH / LIST / GET the server-side autonomous AI browser
//! sessions (the form-filler loop; the Rust port of the Python `ai_generate_workflow`).
//!
//!   POST /v1/ai-sessions/start   — insert a session row, open a page via the engine browser, run
//!                                  the autonomous loop ([`ai::session::run_session`]), finalize the
//!                                  row, and fire `ai_session_started` / `ai_session_completed`
//!                                  lifecycle automations.
//!   GET  /v1/ai-sessions         — list sessions newest-first.
//!   GET  /v1/ai-sessions/:id     — fetch one session.
//!
//! The AI runs through the local multi-provider gateway ([`crate::local::ai::provider`]) on the
//! user's own key — nothing leaves the machine. A page is opened exactly like the run engine
//! (`real.rs`): warm the shared browser, a stealth context (pinned to the optional persona's
//! fingerprint + proxy), URL-guard + navigate, then drive the loop. `/start` is STATIC (no `:id` at
//! that position) to avoid the matchit static-vs-param conflict the streaming routes hit.

use crate::local::ai::provider;
use crate::local::engine::persona;
use crate::local::error::{LocalError, LocalResult};
use crate::local::server::AppState;
use crate::local::store::ai_sessions::{self, AiSession, NewAiSession};
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::routing::{get, post};
use axum::{Json, Router};
use dashmap::DashMap;
use serde::Deserialize;
use serde_json::{json, Value};
use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, OnceLock};

/// Process-global cooperative-cancel flags for in-flight AI sessions, keyed by `ai_session_id`.
///
/// A running session's launch task holds a clone of its flag and passes it into [`run_session`],
/// whose loop polls it each iteration; the `POST /v1/ai-sessions/:id/cancel` handler flips it. This
/// lives as a module global (not on `AppState`) so the ~30 `AppState` construction sites — almost all
/// of them test stubs — don't each have to thread an unused registry. The entry is inserted at launch
/// and removed once the session finalizes, so the map only ever holds genuinely-running sessions.
static AI_CANCELS: OnceLock<DashMap<i64, Arc<AtomicBool>>> = OnceLock::new();

fn ai_cancels() -> &'static DashMap<i64, Arc<AtomicBool>> {
    AI_CANCELS.get_or_init(DashMap::new)
}

/// Mount the ai-session routes. Auth is applied by `server.rs` at the router level.
pub fn router() -> Router<AppState> {
    Router::new()
        .route("/v1/ai-sessions", get(list))
        .route("/v1/ai-sessions/start", post(start))
        .route("/v1/ai-sessions/:id", get(get_one).delete(delete))
        .route("/v1/ai-sessions/:id/steps", get(steps))
        .route("/v1/ai-sessions/:id/cancel", post(cancel))
}

/// Project a stored replay step into the FE scrubber shape: screenshot bytes → base64 (no `data:`
/// prefix; the FE adds it), `None` when unchanged from the previous step (FE reuses the last frame).
fn step_view(s: crate::local::store::ai_preview_steps::Step) -> Value {
    json!({
        "step": s.step_num,
        "thought": s.thought,
        "action": s.action,
        "url": s.url,
        "status": s.status,
        "screenshot": s.screenshot.map(|b| base64::Engine::encode(&base64::engine::general_purpose::STANDARD, b)),
        "ts": s.created_at,
    })
}

/// `GET /v1/ai-sessions/:id/steps` — the disk-cheap REPLAY: ordered per-step thinking + keyframes for
/// the "watch the AI" scrubber. 404 if the session doesn't exist.
async fn steps(State(st): State<AppState>, Path(id): Path<i64>) -> LocalResult<Json<Value>> {
    if ai_sessions::get_by_id(&st.db, id).await?.is_none() {
        return Err(LocalError::NotFound(format!("ai_session {id}")));
    }
    let rows = crate::local::store::ai_preview_steps::list_for(&st.db, "ai", id).await?;
    let steps: Vec<Value> = rows.into_iter().map(step_view).collect();
    Ok(Json(json!({ "ai_session_id": id, "steps": steps })))
}

/// `POST /v1/ai-sessions/start` body — the session parameters.
#[derive(Debug, Deserialize)]
struct StartBody {
    #[serde(default)]
    name: Option<String>,
    goal: String,
    #[serde(default)]
    entry_url: Option<String>,
    /// Keys/values shown to the model (non-secret hints).
    #[serde(default)]
    available_data: HashMap<String, String>,
    /// Actual values to fill (may include caller-supplied secrets). Falls back to `available_data`.
    #[serde(default)]
    fill_data: HashMap<String, String>,
    #[serde(default)]
    max_steps: Option<u32>,
    #[serde(default)]
    workflow_id: Option<i64>,
    /// Optional login identity to sign in as (fingerprint / session-state / proxy / credentials).
    #[serde(default)]
    persona_id: Option<i64>,
    /// When `true`/absent (`None` ⇒ treated as `true`), a successful (`complete`) finish records a
    /// reusable `workflows` row from the captured steps and links it (`workflow_id`). `false` skips
    /// that (e.g. a one-off fill the caller does not want to keep).
    #[serde(default)]
    generate_workflow: Option<bool>,
}

/// A read-safe projection of an [`AiSession`] for the API boundary. It deliberately OMITS the
/// `fill_data` and `available_data` columns: `fill_data` holds the persona's DECRYPTED login
/// credentials (merged in at `/start`) and `available_data` echoes caller-supplied values, so neither
/// may cross the API boundary to a read-scoped `wlk_` key. Every other field mirrors the store row.
#[derive(Debug, serde::Serialize)]
struct AiSessionView {
    id: i64,
    run_id: Option<i64>,
    workflow_id: Option<i64>,
    name: Option<String>,
    goal: String,
    entry_url: Option<String>,
    status: String,
    step_count: i64,
    max_steps: i64,
    filled_fields: Option<String>,
    clicked_indices: Option<String>,
    last_url: Option<String>,
    result_data: Option<String>,
    error_message: Option<String>,
    /// Whether a successful finish records a reusable workflow (0/1). Non-secret; surfaced so the FE
    /// can show "will save a workflow".
    generate_workflow: i64,
    created_at: String,
    started_at: Option<String>,
    completed_at: Option<String>,
}

impl From<AiSession> for AiSessionView {
    fn from(s: AiSession) -> Self {
        // `fill_data` / `available_data` are intentionally not carried over — they hold secrets.
        Self {
            id: s.id,
            run_id: s.run_id,
            workflow_id: s.workflow_id,
            name: s.name,
            goal: s.goal,
            entry_url: s.entry_url,
            status: s.status,
            step_count: s.step_count,
            max_steps: s.max_steps,
            filled_fields: s.filled_fields,
            clicked_indices: s.clicked_indices,
            last_url: s.last_url,
            result_data: s.result_data,
            error_message: s.error_message,
            generate_workflow: s.generate_workflow,
            created_at: s.created_at,
            started_at: s.started_at,
            completed_at: s.completed_at,
        }
    }
}

/// `GET /v1/ai-sessions` — list sessions newest-first (cap 200). Secret fields are stripped (see
/// [`AiSessionView`]).
async fn list(State(st): State<AppState>) -> LocalResult<Json<Vec<AiSessionView>>> {
    let rows = ai_sessions::list(&st.db, 200).await?;
    Ok(Json(rows.into_iter().map(AiSessionView::from).collect()))
}

/// `GET /v1/ai-sessions/:id` — one session, 404 if missing. Secret fields are stripped (see
/// [`AiSessionView`]).
async fn get_one(State(st): State<AppState>, Path(id): Path<i64>) -> LocalResult<Json<AiSessionView>> {
    ai_sessions::get_by_id(&st.db, id)
        .await?
        .map(|s| Json(AiSessionView::from(s)))
        .ok_or_else(|| LocalError::NotFound(format!("ai_session {id}")))
}

/// `POST /v1/ai-sessions/:id/cancel` — cooperatively abort a RUNNING session. Flips its cancel flag;
/// the loop finalizes to `cancelled` within one step (its detached task stays the single writer of
/// the terminal row). 202 when a live flag was flipped, 409 when the session is already terminal, 404
/// when it doesn't exist.
async fn cancel(State(st): State<AppState>, Path(id): Path<i64>) -> LocalResult<(StatusCode, Json<Value>)> {
    if let Some(flag) = ai_cancels().get(&id) {
        flag.store(true, Ordering::Relaxed);
        return Ok((StatusCode::ACCEPTED, Json(json!({ "ai_session_id": id, "status": "cancel_requested" }))));
    }
    // No live flag. Distinguish three cases: already-terminal (nothing to do → 409), a NON-terminal row
    // with no loop behind it (ORPHANED — a crash/restart killed the loop; finalize it so the "live"
    // list entry stops being un-cancellable — this was the 409 the user hit), or never existed (404).
    match ai_sessions::get_by_id(&st.db, id).await? {
        Some(s)
            if matches!(
                s.status.as_str(),
                "complete" | "blocked" | "max_steps" | "stuck" | "error" | "cancelled" | "interrupted"
            ) =>
        {
            Ok((
                StatusCode::CONFLICT,
                Json(json!({ "ai_session_id": id, "status": "not_running", "ai_session_status": s.status })),
            ))
        }
        Some(s) => {
            let done = ai_sessions::finalize(
                &st.db, id, "cancelled", s.step_count, None, None, Some("Session stopped (no active run)."),
            )
            .await?;
            Ok((StatusCode::OK, Json(json!({ "ai_session_id": id, "status": done.status }))))
        }
        None => Err(LocalError::NotFound(format!("ai_session {id}"))),
    }
}

/// `DELETE /v1/ai-sessions/:id` — remove a session row. If it's still running, its cancel flag is
/// flipped first (best-effort) so the detached loop stops instead of resurrecting the row on
/// finalize. 404 when the session doesn't exist.
async fn delete(State(st): State<AppState>, Path(id): Path<i64>) -> LocalResult<Json<Value>> {
    // Stop an in-flight run first so its finalize doesn't re-insert progress after we delete.
    if let Some(flag) = ai_cancels().get(&id) {
        flag.store(true, Ordering::Relaxed);
    }
    let removed = ai_sessions::delete(&st.db, id).await?;
    if !removed {
        return Err(LocalError::NotFound(format!("ai_session {id}")));
    }
    // Drop the replay keyframes/thoughts too (generic table, no FK cascade).
    let _ = crate::local::store::ai_preview_steps::delete_for(&st.db, "ai", id).await;
    Ok(Json(json!({ "ai_session_id": id, "deleted": true })))
}

/// `POST /v1/ai-sessions/start` — LAUNCH one autonomous AI session and return
/// `{ ai_session_id, status: "running" }` IMMEDIATELY. Validation (provider / browser / goal) is
/// synchronous so a misconfigured request still 4xx's; the loop itself runs in a DETACHED task that
/// finalizes the row to its terminal status and fires `ai_session_completed`. Callers poll
/// `GET /v1/ai-sessions/:id` for progress (async launch + poll — a long session no longer blocks the
/// HTTP request or the create-and-run modal).
async fn start(State(st): State<AppState>, Json(body): Json<StartBody>) -> LocalResult<Json<Value>> {
    // Resolve the AI provider up front — a session with no configured brain cannot run, UNLESS the
    // cloud AI gateway is on (which supplies the brain itself, so a local key is optional).
    let ai_cfg = match provider::resolve_config(&st.db, &st.vault).await? {
        Some(c) if !c.provider.trim().is_empty() => c,
        _ if provider::cloud_gateway_enabled(&st.db).await => provider::AiConfig {
            provider: String::new(),
            model: String::new(),
            base_url: None,
            api_key: None,
        },
        _ => {
            return Err(LocalError::BadRequest(
                "No AI provider configured. Open Settings → AI and choose a provider + API key, or turn on the cloud AI gateway."
                    .into(),
            ))
        }
    };

    // The engine must expose a warm browser (the StubEngine used in unit tests does not).
    let browser = st
        .engine
        .browser()
        .ok_or_else(|| LocalError::BadRequest("this engine cannot run AI sessions (no browser)".into()))?;

    let goal = body.goal.trim().to_string();
    if goal.is_empty() {
        return Err(LocalError::BadRequest("goal is required".into()));
    }
    let max_steps = body.max_steps.unwrap_or(20).clamp(1, 100);
    let workflow_id = body.workflow_id;
    // `None` ⇒ record a workflow (the default). Recording is skipped when the caller opted out OR
    // when the session is already linked to an existing workflow (don't clobber that link).
    let generate_workflow = body.generate_workflow.unwrap_or(true) && workflow_id.is_none();

    // Optional persona: pin fingerprint + proxy, restore session state, merge login credentials into
    // fill_data so `{{...}}`-style values resolve. A dangling id is non-fatal (runs without it).
    let resolved_persona = match body.persona_id {
        Some(pid) => persona::resolve_persona(&st.db, &st.vault, pid).await?,
        None => None,
    };

    // fill_data = caller values + persona credentials (caller wins on key collision).
    let mut fill_data = body.fill_data.clone();
    if let Some(p) = resolved_persona.as_ref() {
        let mut creds: HashMap<String, String> = HashMap::new();
        p.merge_into_credentials(&mut creds);
        for (k, v) in creds {
            fill_data.entry(k).or_insert(v);
        }
    }

    // Persist the running session row SYNCHRONOUSLY so the HTTP response can carry the real id
    // immediately (the FE fetches the full row by it), then run the loop + finalize + record in a
    // detached task via the shared driver.
    let session = ai_sessions::insert(
        &st.db,
        &NewAiSession {
            run_id: None,
            workflow_id,
            name: body.name.clone(),
            goal: goal.clone(),
            entry_url: body.entry_url.clone(),
            max_steps: Some(max_steps as i64),
            available_data: Some(serde_json::to_string(&body.available_data).unwrap_or_else(|_| "{}".into())),
            fill_data: Some(serde_json::to_string(&fill_data).unwrap_or_else(|_| "{}".into())),
            generate_workflow: Some(generate_workflow),
        },
    )
    .await?;

    // Drive the post-insert body (started → loop → finalize → record → completed) in a DETACHED task
    // through the SHARED driver [`crate::local::ai::run::finish_ai_session`] — the same code path the
    // fleet bridge runs. The HTTP response returns immediately so the create-and-run modal / caller
    // can poll for status instead of blocking.
    let db = st.db.clone();
    let engine = st.engine.clone();
    let session_id = session.id;
    // Register a cooperative-cancel flag so `POST /:id/cancel` can abort this run. Removed the moment
    // the loop returns, so the map only holds live sessions.
    let cancel = Arc::new(AtomicBool::new(false));
    ai_cancels().insert(session_id, cancel.clone());
    let params = crate::local::ai::run::AiSessionParams {
        name: body.name.clone(),
        goal,
        entry_url: body.entry_url.clone(),
        available_data: body.available_data.clone(),
        fill_data,
        max_steps,
        workflow_id,
        resolved_persona,
        generate_workflow: body.generate_workflow.unwrap_or(true),
        explore: false,  // standalone AI session keeps the classic form-filler behavior
        record_templates: std::collections::HashMap::new(),
        ask_concierge_session_id: None,
        cancel: Some(cancel),
    };
    tokio::spawn(async move {
        if let Err(e) =
            crate::local::ai::run::finish_ai_session(&db, &engine, &browser, &ai_cfg, session_id, params)
                .await
        {
            tracing::warn!(ai_session_id = session_id, error = %e, "ai_session run failed");
        }
        // The loop has ended (naturally or via abort) — drop the cancel flag.
        ai_cancels().remove(&session_id);
    });

    Ok(Json(json!({ "ai_session_id": session.id, "status": "running" })))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The API response projection must NEVER serialize `fill_data` (persona's decrypted credentials)
    /// or `available_data` — a read-scoped caller would otherwise read live secrets back out.
    #[test]
    fn ai_session_view_omits_secret_fields() {
        let row = AiSession {
            id: 1,
            run_id: None,
            workflow_id: Some(7),
            name: Some("signup".into()),
            goal: "complete the registration form".into(),
            entry_url: Some("https://example.com/signup".into()),
            status: "complete".into(),
            step_count: 3,
            max_steps: 20,
            available_data: Some(r#"{"email":"a@b.com"}"#.into()),
            fill_data: Some(r#"{"password":"hunter2","token":"sk-live-secret"}"#.into()),
            filled_fields: Some(r#"["email"]"#.into()),
            clicked_indices: Some("[]".into()),
            last_url: Some("https://example.com/done".into()),
            result_data: Some(r#"{"submitted":true}"#.into()),
            error_message: None,
            generate_workflow: 1,
            created_at: "2026-07-02T00:00:00.000Z".into(),
            started_at: Some("2026-07-02T00:00:00.000Z".into()),
            completed_at: Some("2026-07-02T00:00:05.000Z".into()),
        };

        let json = serde_json::to_value(AiSessionView::from(row)).unwrap();
        let obj = json.as_object().unwrap();
        assert!(!obj.contains_key("fill_data"), "fill_data must not be serialized");
        assert!(!obj.contains_key("available_data"), "available_data must not be serialized");
        // Non-secret fields still round-trip.
        assert_eq!(obj["goal"], json!("complete the registration form"));
        assert_eq!(obj["status"], json!("complete"));
        assert_eq!(obj["result_data"], json!(r#"{"submitted":true}"#));
        // Belt-and-suspenders: the secret literal appears nowhere in the serialized payload.
        assert!(!json.to_string().contains("sk-live-secret"));
        assert!(!json.to_string().contains("hunter2"));
    }

    async fn pool() -> sqlx::sqlite::SqlitePool {
        let dir = Box::leak(Box::new(tempfile::tempdir().unwrap()));
        crate::local::db::open(&dir.path().join("t.db"), "test-key-ai-sess-wf").await.unwrap()
    }

    /// `generate_workflow = false` (opt out): the finish path must NOT create a workflow — the session
    /// still finalizes complete, no `workflows` row appears, and `workflow_id` stays unset. We assert
    /// the store-level GUARD directly (the shared driver only records a workflow when the finalized
    /// row's `generate_workflow != 0`), so no browser is needed. The capture→assemble→persist→link
    /// path itself is covered in `crate::local::ai::run`'s tests.
    #[tokio::test]
    async fn opt_out_records_no_workflow_and_session_still_completes() {
        use crate::local::store::workflows;
        let pool = pool().await;

        let s = ai_sessions::insert(
            &pool,
            &NewAiSession { goal: "fill it".into(), generate_workflow: Some(false), ..Default::default() },
        )
        .await
        .unwrap();

        let done = ai_sessions::finalize(&pool, s.id, "complete", 2, None, Some("{}"), None)
            .await
            .unwrap();
        assert_eq!(done.status, "complete");
        assert_eq!(done.generate_workflow, 0, "opted out");

        // The guard the driver applies: opted-out ⇒ skip. Assert we honor it (no workflow, no link).
        assert_eq!(workflows::list(&pool, false, 100).await.unwrap().len(), 0, "no workflow recorded");
        assert_eq!(
            ai_sessions::get_by_id(&pool, s.id).await.unwrap().unwrap().workflow_id,
            None,
            "session unlinked"
        );
    }
}
