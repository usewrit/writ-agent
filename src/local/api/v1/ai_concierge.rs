//! `/v1/ai-concierge/*` REST handlers — the desktop AI concierge assistant (watch+notify only; NO
//! autobuy). One natural-language goal → a live monitor + price-drop alert, driven by a background
//! mission loop ([`crate::local::ai::concierge::run_mission`]).
//!
//!   POST /v1/ai-concierge/start        — validate provider+browser, insert a `planning` row, spawn
//!                                        the mission loop, return `{concierge_session_id, session_id,
//!                                        status:"running"}` immediately.
//!   GET  /v1/ai-concierge              — list missions newest-first.
//!   GET  /v1/ai-concierge/:id          — the full mission state the FE polls (session_id, status,
//!                                        phase, plan, pending_request, resources, tokens, transcript…).
//!   POST /v1/ai-concierge/:id/respond  — answer a pause: requires status=='awaiting_input' + a
//!                                        turn_seq match, merges answers into the plan/answers, clears
//!                                        pending_request, resumes, and re-spawns the loop.
//!   POST /v1/ai-concierge/:id/interrupt — STOP GENERATING: break the current turn, PARK the mission
//!                                        at 'awaiting_input'. Non-terminal; the next message resumes
//!                                        it in place. This is the chat stop-square.
//!   POST /v1/ai-concierge/:id/cancel   — END the mission; the loop finalizes 'cancelled'.
//!
//! `/start` is STATIC (no `:id` at that position) so it never collides with `/:id` in matchit — the
//! same ordering ai_sessions.rs uses. Errors are `{error, code}` JSON (a 409 conflict on /respond is
//! built by hand since `LocalError` has no Conflict variant), never `{detail}`.

use crate::local::ai::concierge;
use crate::local::ai::concierge_docs;
use crate::local::ai::provider;
use crate::local::error::{LocalError, LocalResult};
use crate::local::server::AppState;
use crate::local::store::concierge_sessions::{self, ConciergeSession, ConciergeUpdate, NewConciergeSession};
use crate::local::store::personas;
use crate::local::store::vault_secrets::{self, NewVaultSecret};
use crate::local::store::workflows;
use crate::models::ai::{AiMessage, AiMessageContent};
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use serde::Deserialize;
use serde_json::{json, Value};

/// Mount the ai-concierge routes. Auth is applied by `server.rs` at the router level. The static
/// `/start` segment is registered so it can't be shadowed by `/:id`.
pub fn router() -> Router<AppState> {
    Router::new()
        .route("/v1/ai-concierge", get(list))
        .route("/v1/ai-concierge/start", post(start))
        .route("/v1/ai-concierge/:id", get(get_one))
        .route("/v1/ai-concierge/:id/steps", get(steps))
        .route("/v1/ai-concierge/:id/respond", post(respond))
        .route("/v1/ai-concierge/:id/ask", post(ask))
        .route("/v1/ai-concierge/:id/persona", post(set_persona))
        .route("/v1/ai-concierge/:id/interrupt", post(interrupt))
        .route("/v1/ai-concierge/:id/cancel", post(cancel))
}

/// `POST /v1/ai-concierge/start` body.
#[derive(Debug, Deserialize)]
struct StartBody {
    goal: String,
    #[serde(default)]
    url: Option<String>,
    /// Ignored beyond storage — desktop missions are always `platform='desktop'`.
    #[serde(default)]
    #[allow(dead_code)]
    platform: Option<String>,
}

/// `POST /v1/ai-concierge/:id/respond` body. `card_fields` is irrelevant on desktop — accepted then
/// ignored (buying is cloud-only). `pub(crate)` so the MCP static tools can drive the same core.
#[derive(Debug, Default, Deserialize)]
pub(crate) struct RespondBody {
    pub(crate) turn_seq: i64,
    #[serde(default)]
    pub(crate) answers: Value,
    #[serde(default)]
    #[allow(dead_code)]
    pub(crate) card_fields: Option<Value>,
    /// Login credentials typed inline under the "enter credentials" branch: `{field: plaintext}`.
    /// Each is sealed to the vault (never lands in answers/transcript/the model); only the
    /// `{{secret:KEY}}` placeholder is merged into the plan for the built workflow to resolve.
    #[serde(default)]
    pub(crate) secret_fields: Option<Value>,
}

/// Why a respond attempt was refused — shared by the REST handler (mapped to 409/`{error,code}`)
/// and the MCP `writ_mission_respond` tool (mapped to a caller-facing message), so both surfaces
/// keep identical semantics.
pub(crate) enum RespondFailure {
    /// Wrong state or stale `turn_seq` — safe, caller-facing.
    Conflict { message: &'static str, code: &'static str },
    /// Everything else (store/vault errors, not-found).
    Local(LocalError),
}

impl From<LocalError> for RespondFailure {
    fn from(e: LocalError) -> Self {
        RespondFailure::Local(e)
    }
}

// ── GET (list / one) ─────────────────────────────────────────────────────────

/// `GET /v1/ai-concierge` — list missions newest-first (cap 200).
async fn list(State(st): State<AppState>) -> LocalResult<Json<Vec<ConciergeSession>>> {
    Ok(Json(concierge_sessions::list(&st.db, 200).await?))
}

/// `GET /v1/ai-concierge/:id` — the full polling view. Parses the JSON-TEXT columns into real JSON so
/// the FE's `conciergeTypes.ts` shape (plan/pending_request/resources/transcript objects) is honored
/// directly, and adds the `session_id` alias the FE reads.
async fn get_one(State(st): State<AppState>, Path(id): Path<i64>) -> LocalResult<Json<Value>> {
    let s = concierge_sessions::get_by_id(&st.db, id)
        .await?
        .ok_or_else(|| LocalError::NotFound(format!("concierge_session {id}")))?;
    Ok(Json(to_view(&s)))
}

/// `GET /v1/ai-concierge/:id/steps` — the disk-cheap REPLAY for the concierge: ordered per-browse
/// thinking + keyframes for the "watch the AI" scrubber. Each `screenshot` is base64 JPEG (no `data:`
/// prefix) or null (unchanged from the previous step). 404 if the mission doesn't exist. Live viewing
/// uses the `/ws/ai-preview/concierge-{id}` screencast, not this endpoint.
async fn steps(State(st): State<AppState>, Path(id): Path<i64>) -> LocalResult<Json<Value>> {
    if concierge_sessions::get_by_id(&st.db, id).await?.is_none() {
        return Err(LocalError::NotFound(format!("concierge_session {id}")));
    }
    let rows = crate::local::store::ai_preview_steps::list_for(&st.db, "concierge", id).await?;
    let steps: Vec<Value> = rows
        .into_iter()
        .map(|s| {
            json!({
                "step": s.step_num,
                "thought": s.thought,
                "action": s.action,
                "url": s.url,
                "status": s.status,
                "screenshot": s.screenshot.map(|b| base64::Engine::encode(&base64::engine::general_purpose::STANDARD, b)),
                "ts": s.created_at,
            })
        })
        .collect();
    Ok(Json(json!({ "concierge_session_id": id, "steps": steps })))
}

/// Shape one row into the FE polling contract (JSON-TEXT columns decoded to real JSON).
fn to_view(s: &ConciergeSession) -> Value {
    let plan = decode_obj(s.plan.as_deref());
    json!({
        "session_id": s.id,
        "concierge_session_id": s.id,
        "status": s.status,
        "phase": s.phase,
        "goal": s.goal,
        "platform": s.platform,
        "progress_message": s.progress_message,
        "transcript": decode_arr(s.transcript.as_deref()),
        "thoughts": thoughts_view(s.brain_history.as_deref()),
        "plan": plan,
        "pending_request": s.pending_request.as_deref().and_then(|r| serde_json::from_str::<Value>(r).ok()),
        "answers": decode_obj(s.answers.as_deref()),
        "resources": decode_obj(s.resources.as_deref()),
        "turn_seq": s.turn_seq,
        "tokens": {
            "input": s.input_tokens,
            "output": s.output_tokens,
            // Local AI is free — credits are always 0.
            "credits": 0,
        },
        "error_message": s.error_message,
        "created_at": s.created_at,
        "completed_at": s.completed_at,
    })
}

fn decode_obj(raw: Option<&str>) -> Value {
    raw.and_then(|s| serde_json::from_str::<Value>(s).ok())
        .filter(Value::is_object)
        .unwrap_or_else(|| json!({}))
}
fn decode_arr(raw: Option<&str>) -> Value {
    raw.and_then(|s| serde_json::from_str::<Value>(s).ok())
        .filter(Value::is_array)
        .unwrap_or_else(|| json!([]))
}

/// Project the `brain_history` JSON-TEXT column into the FE "thoughts" panel shape: `[{tool, thought,
/// ts}]` for each entry with a NON-EMPTY `thought` (dropping any `tool_args_redacted` /
/// `tool_result_summary`), keeping the last ~40. Empty/absent → `[]`. Mirrors the cloud projection.
fn thoughts_view(raw: Option<&str>) -> Value {
    let entries = raw
        .and_then(|s| serde_json::from_str::<Value>(s).ok())
        .and_then(|v| v.as_array().cloned())
        .unwrap_or_default();
    let mut out: Vec<Value> = entries
        .iter()
        .filter_map(|e| {
            let thought = e.get("thought").and_then(|t| t.as_str())?.trim();
            if thought.is_empty() {
                return None;
            }
            Some(json!({
                "tool": e.get("tool").and_then(|t| t.as_str()).unwrap_or(""),
                "thought": thought,
                "ts": e.get("ts").cloned().unwrap_or(Value::Null),
            }))
        })
        .collect();
    if out.len() > 40 {
        out.drain(0..out.len() - 40);
    }
    Value::Array(out)
}

// ── POST /start ──────────────────────────────────────────────────────────────

/// `POST /v1/ai-concierge/start` — validate provider + browser SYNCHRONOUSLY (so a misconfigured
/// request 4xx's), insert a `planning` row seeding any given URL into the plan, spawn the detached
/// mission loop, and return `{concierge_session_id, session_id, status:"running"}` immediately.
async fn start(State(st): State<AppState>, Json(body): Json<StartBody>) -> LocalResult<Json<Value>> {
    Ok(Json(start_core(&st, body.goal, body.url).await?))
}

/// Shared mission-start core (REST + MCP `writ_build`): validate provider + browser, insert the
/// `planning` row, spawn the detached loop, return the start payload.
pub(crate) async fn start_core(st: &AppState, goal: String, url: Option<String>) -> LocalResult<Value> {
    // Provider must be configured (a mission with no brain cannot plan) — UNLESS the cloud AI gateway
    // is on, which supplies the AI itself (no local BYO key needed). This mirrors the mission loop's
    // own gate (`concierge::run_mission`); without it a cloud-linked, gateway-on user with no BYO key
    // is wrongly rejected here before the loop that would have routed to the gateway ever runs.
    if !provider::cloud_gateway_enabled(&st.db).await {
        match provider::resolve_config(&st.db, &st.vault).await? {
            Some(c) if !c.provider.trim().is_empty() => {}
            _ => {
                return Err(LocalError::BadRequest(
                    "No AI provider configured. Open Settings → AI and choose a provider + API key, or turn on the cloud AI gateway.".into(),
                ))
            }
        }
    }
    // The engine must expose a browser (the StubEngine used in unit tests does not).
    if st.engine.browser().is_none() {
        return Err(LocalError::BadRequest(
            "this engine cannot run the concierge (no browser)".into(),
        ));
    }

    let goal = goal.trim().to_string();
    if goal.is_empty() {
        return Err(LocalError::BadRequest("goal is required".into()));
    }

    // Seed the plan with the caller's URL (if any) so find_page can go straight there.
    let plan = match url.as_deref().map(str::trim).filter(|u| !u.is_empty()) {
        Some(url) => json!({ "resolved_url": url }).to_string(),
        None => "{}".to_string(),
    };
    let transcript = json!([{ "role": "user", "content": goal, "ts": chrono::Utc::now().timestamp() }]).to_string();

    let session = concierge_sessions::insert(
        &st.db,
        &NewConciergeSession {
            goal,
            platform: Some("desktop".into()),
            plan: Some(plan),
            transcript: Some(transcript),
        },
    )
    .await?;

    // Drive the mission in a DETACHED task; it finalizes the row itself. The FE polls for progress.
    let state = st.clone();
    let session_id = session.id;
    tokio::spawn(async move {
        concierge::run_mission(state, session_id).await;
    });

    // Include BOTH keys — the FE reads `session_id`, and `concierge_session_id` is the explicit id.
    Ok(json!({
        "concierge_session_id": session.id,
        "session_id": session.id,
        "status": "running",
        "poll_url": format!("/v1/ai-concierge/{}", session.id),
    }))
}

// ── POST /:id/respond ────────────────────────────────────────────────────────

/// `POST /v1/ai-concierge/:id/respond` — answer a pause. Requires `status=='awaiting_input'` (409
/// else) and a matching `turn_seq` (409 else, so a stale/duplicate answer can't double-apply). Merges
/// the answers into `answers` + `plan`, clears `pending_request`, resumes to the request's
/// `resume_status` (or 'planning'), bumps `turn_seq`, and re-spawns the mission loop.
async fn respond(
    State(st): State<AppState>,
    Path(id): Path<i64>,
    Json(body): Json<RespondBody>,
) -> Result<Json<Value>, Response> {
    match respond_core(&st, id, body).await {
        Ok(v) => Ok(Json(v)),
        Err(RespondFailure::Conflict { message, code }) => Err(conflict(message, code)),
        Err(RespondFailure::Local(e)) => Err(e.into_response()),
    }
}

/// Shared respond core (REST + MCP `writ_mission_respond`): state + turn_seq gates, secret sealing,
/// answer/plan merge, parked-session handoff, and the loop re-spawn.
pub(crate) async fn respond_core(
    st: &AppState,
    id: i64,
    body: RespondBody,
) -> Result<Value, RespondFailure> {
    let sess = concierge_sessions::get_by_id(&st.db, id)
        .await?
        .ok_or_else(|| LocalError::NotFound(format!("concierge_session {id}")))?;

    if sess.status != "awaiting_input" {
        return Err(RespondFailure::Conflict {
            message: "session is not awaiting input",
            code: "not_awaiting_input",
        });
    }
    if sess.turn_seq != body.turn_seq {
        return Err(RespondFailure::Conflict {
            message: "turn_seq mismatch — the mission advanced; re-fetch and retry",
            code: "turn_seq_mismatch",
        });
    }

    // Merge answers (object) into the stored answers + plan (a threshold answer feeds the condition).
    let mut answers_in = body.answers.as_object().cloned().unwrap_or_default();

    // Naming context for AI-stored credentials: the site the mission targets + the human label the
    // pause asked with — so the vault rows read like a person named them ("watchtow3r_app_login_key",
    // "API key for watchtow3r.app — saved by the AI assistant"), not like machine scratch
    // ("concierge_42_login_key" / "Stored by the AI assistant").
    let site_slug = credential_site_slug(&sess);
    let labels = credential_labels(&sess);
    // Handoff for a PARKED live session (ask_gate): the plaintext of each just-sealed secret plus
    // its replay spelling travel in-memory to the waiting explorer so it continues on the SAME open
    // page. Populated alongside the sealing below; only used when a waiter is actually registered.
    let mut ask_fill: std::collections::HashMap<String, String> = Default::default();
    let mut ask_record: std::collections::HashMap<String, String> = Default::default();
    let mut ask_text: std::collections::HashMap<String, String> = Default::default();
    let secret_key = |field: &str| -> String {
        let safe_field: String = field
            .chars()
            .map(|c| if c.is_ascii_alphanumeric() { c.to_ascii_lowercase() } else { '_' })
            .collect();
        match &site_slug {
            // Site-scoped: the SAME site+field maps to the SAME row, so re-entering the credential
            // updates it in place (never a pile of per-mission duplicates).
            Some(site) => format!("{site}_{safe_field}"),
            None => format!("concierge_{id}_{safe_field}"),
        }
    };
    let secret_description = |field: &str| -> String {
        let label = labels
            .get(field)
            .cloned()
            .unwrap_or_else(|| field.trim_start_matches("login_").replace('_', " "));
        match credential_site_host(&sess) {
            Some(host) => format!("{label} for {host} — saved by the AI assistant"),
            None => format!("{label} — saved by the AI assistant"),
        }
    };

    // "secret"-kind answers (passwords/tokens) NEVER reach the plan, transcript, or the planner:
    // seal the plaintext into the local vault (same AAD scheme as /v1/secrets) and merge only the
    // `{{secret:KEY}}` placeholder, which the workflow runner resolves at execution time.
    let secret_fields: Vec<String> = sess
        .pending_request
        .as_deref()
        .and_then(|s| serde_json::from_str::<Value>(s).ok())
        .and_then(|v| v.get("requests").and_then(|r| r.as_array()).cloned())
        .unwrap_or_default()
        .iter()
        .filter(|r| r.get("kind").and_then(|k| k.as_str()) == Some("secret"))
        .filter_map(|r| r.get("field").and_then(|f| f.as_str()).map(str::to_string))
        .collect();
    for field in &secret_fields {
        let Some(plaintext) = answers_in.get(field).and_then(|v| v.as_str()).map(str::to_string) else {
            continue;
        };
        if plaintext.trim().is_empty() {
            continue;
        }
        let key = secret_key(field);
        let value_encrypted = st
            .vault
            .seal_field(plaintext.as_bytes(), &super::secrets::value_aad(&key))?;
        vault_secrets::upsert(
            &st.db,
            &NewVaultSecret {
                key: key.clone(),
                value_encrypted,
                description: Some(secret_description(field)),
                category: Some("credentials".into()),
            },
        )
        .await?;
        let secret_ref = format!("{{{{secret:{key}}}}}");
        ask_fill.insert(field.clone(), plaintext);
        ask_record.insert(field.clone(), secret_ref.clone());
        ask_text.insert(field.clone(), secret_ref.clone());
        answers_in.insert(field.clone(), json!(secret_ref));
    }

    // Login credentials typed inline under the "enter credentials" branch (body.secret_fields):
    // seal each to the vault the SAME way (per-mission key) and merge only the {{secret:KEY}}
    // placeholder into the answers so the built workflow resolves it at run time. The raw value
    // never lands in answers/plan/transcript or reaches the planner.
    if let Some(sf) = body.secret_fields.as_ref().and_then(Value::as_object) {
        for (field, val) in sf {
            let Some(plaintext) = val.as_str() else { continue };
            if plaintext.trim().is_empty() {
                continue;
            }
            let key = secret_key(field);
            let value_encrypted = st
                .vault
                .seal_field(plaintext.as_bytes(), &super::secrets::value_aad(&key))?;
            vault_secrets::upsert(
                &st.db,
                &NewVaultSecret {
                    key: key.clone(),
                    value_encrypted,
                    description: Some(secret_description(field)),
                    category: Some("credentials".into()),
                },
            )
            .await?;
            let secret_ref = format!("{{{{secret:{key}}}}}");
            ask_fill.insert(field.clone(), plaintext.to_string());
            ask_record.insert(field.clone(), secret_ref.clone());
            ask_text.insert(field.clone(), secret_ref.clone());
            answers_in.insert(field.clone(), json!(secret_ref));
        }
    }

    let mut answers = sess
        .answers
        .as_deref()
        .and_then(|s| serde_json::from_str::<Value>(s).ok())
        .and_then(|v| v.as_object().cloned())
        .unwrap_or_default();
    let mut plan = sess
        .plan
        .as_deref()
        .and_then(|s| serde_json::from_str::<Value>(s).ok())
        .and_then(|v| v.as_object().cloned())
        .unwrap_or_default();
    for (k, v) in &answers_in {
        // Non-secret string answers ride to a parked session verbatim (secrets are already in the
        // handoff as their refs + plaintext from the sealing above — don't overwrite those).
        if let Some(text) = v.as_str() {
            if !ask_fill.contains_key(k) {
                ask_fill.insert(k.clone(), text.to_string());
                ask_record.insert(k.clone(), text.to_string());
                ask_text.insert(k.clone(), text.to_string());
            }
        }
    }
    for (k, v) in answers_in {
        answers.insert(k.clone(), v.clone());
        plan.insert(k, v);
    }

    // A persona pick arrives as {persona_id: N} under its field. Hoist it to the well-known
    // plan.persona_id so build_workflow attaches it as the workflow's login identity (which
    // restores its session + mints its TOTP → the workflow logs in and passes 2FA on its own).
    let picked_persona = sess
        .pending_request
        .as_deref()
        .and_then(|s| serde_json::from_str::<Value>(s).ok())
        .and_then(|v| v.get("requests").and_then(|r| r.as_array()).cloned())
        .unwrap_or_default()
        .iter()
        .filter(|r| r.get("kind").and_then(|k| k.as_str()) == Some("persona"))
        .find_map(|r| {
            let field = r.get("field").and_then(|f| f.as_str())?;
            answers.get(field).and_then(|a| a.get("persona_id")).and_then(Value::as_i64)
        });
    if let Some(pid) = picked_persona {
        plan.insert("persona_id".into(), json!(pid));
    }

    let answers_s = serde_json::to_string(&answers).unwrap_or_else(|_| "{}".into());
    let plan_s = serde_json::to_string(&plan).unwrap_or_else(|_| "{}".into());

    // Resume status from the stored pending_request (fallback 'planning'), and clear the request.
    // A PARKED live session resumes in place instead: resolve() is the single ATOMIC take of the
    // waiter — it both decides "parked" and delivers the answers (a separate has_waiter check would
    // race a park timing out in between, dropping the answer while skipping the respawn).
    let parked = crate::local::ai::ask_gate::resolve(
        id,
        crate::local::ai::ask_gate::AskAnswers { fill: ask_fill, record: ask_record, text: ask_text },
    );
    let resume_status = if parked {
        "building".to_string()
    } else {
        sess.pending_request
            .as_deref()
            .and_then(|s| serde_json::from_str::<Value>(s).ok())
            .and_then(|v| v.get("resume_status").and_then(|s| s.as_str()).map(str::to_string))
            .filter(|s| !s.is_empty())
            .unwrap_or_else(|| "planning".into())
    };
    let next_turn_seq = sess.turn_seq + 1;

    concierge_sessions::update(
        &st.db,
        id,
        &ConciergeUpdate {
            status: Some(&resume_status),
            progress_message: Some(if parked { "Resuming with your answer — same page." } else { "Resuming…" }),
            plan: Some(&plan_s),
            answers: Some(&answers_s),
            pending_request: Some(""), // clear to NULL
            turn_seq: Some(next_turn_seq),
            ..Default::default()
        },
    )
    .await?;

    // Answers already delivered atomically above when a session was parked (browser stayed open).
    // Otherwise (classic pause, or the park timed out and closed) re-spawn the loop from the row.
    if !parked {
        let state = st.clone();
        tokio::spawn(async move {
            concierge::run_mission(state, id).await;
        });
    }

    Ok(json!({ "session_id": id, "status": resume_status, "turn_seq": next_turn_seq }))
}

// ── POST /:id/ask ────────────────────────────────────────────────────────────

/// `POST /v1/ai-concierge/:id/ask` body.
#[derive(Debug, Deserialize)]
struct AskBody {
    question: String,
}

const ASK_SYSTEM: &str = r##"You are the Writ desktop concierge answering the user's follow-up question about what you just built for them on their own machine. Use DOCS for accurate endpoints/shapes and CONTEXT for the user's REAL ids and endpoints.
- FIRST decide: is the message a QUESTION about what was built, or a request to CHANGE / FIX / EXTEND / CORRECT it (e.g. "you missed the login step", "correct the workflow", "make it run daily", "also extract the prices")? For a change request reply with EXACTLY the single word REVISE and nothing else — the mission will re-open and actually apply the change. Never answer a change request with advice or instructions.
- Answer concretely and briefly, in plain language.
- When they ask how to CALL something, give the exact endpoint URL for THEIR workflow (from CONTEXT) and a copy-paste example (curl, or the OpenAI SDK for the openai surface). Put commands in a ``` fenced code block.
- Callers authenticate with a local API key: header `Authorization: Bearer wlk_YOUR_KEY`. Tell them to create one if needed (Settings → API Keys, or the assistant's Connect step).
- If a surface they need is NOT enabled in CONTEXT.endpoints, say so and tell them to enable it (the Connect tab, or ask the assistant to).
- NEVER invent endpoints, ids, or key values — use only what appears in CONTEXT and DOCS. The app runs on the local loopback address; use it in place of {ORIGIN}."##;

/// Answer a free-text follow-up question grounded in the docs + the session's REAL resources
/// (endpoints for the workflow it built). Synchronous one-shot: no mission spawn, works at any
/// status (it's a side conversation). Local AI is free — no credit gate.
async fn ask(State(st): State<AppState>, Path(id): Path<i64>, Json(body): Json<AskBody>) -> LocalResult<Json<Value>> {
    let question = body.question.trim().to_string();
    if question.is_empty() {
        return Err(LocalError::BadRequest("question is required".into()));
    }
    let sess = concierge_sessions::get_by_id(&st.db, id)
        .await?
        .ok_or_else(|| LocalError::NotFound(format!("concierge_session {id}")))?;

    // Retrieve the most relevant docs + build the user's real context (their endpoints).
    let snippets = concierge_docs::render_snippets(&concierge_docs::search(&question, 3));
    let ctx = ask_context(&st, &sess).await;
    let user_text = format!("QUESTION:\n{question}\n\nDOCS:\n{snippets}\n\nCONTEXT:\n{ctx}");
    // Send the WHOLE conversation as a thread (not a standalone one-shot) so a follow-up
    // continues the same thread — the model remembers what it built and every earlier
    // Q&A. The live question (with docs+context) is the final user turn.
    let messages = thread_messages(sess.transcript.as_deref(), user_text);
    let max_tokens = provider::resolve_max_tokens(&st.db, "assist", 1500).await;
    let completion = provider::complete_routed(&st.db, &st.vault, &messages, Some(ASK_SYSTEM), max_tokens, "assist")
        .await
        .map_err(|e| LocalError::Internal(format!("assistant answer failed: {e}")))?;

    let mut transcript: Vec<Value> = sess
        .transcript
        .as_deref()
        .and_then(|s| serde_json::from_str::<Value>(s).ok())
        .and_then(|v| v.as_array().cloned())
        .unwrap_or_default();
    let ts = chrono::Utc::now().timestamp();

    // Change request (the model replied the REVISE sentinel): re-open the mission with the user's
    // correction as the newest transcript line so the planner FIXES the actual resources (with
    // plan.workflow_id set, build_workflow updates the existing workflow in place). Only a settled
    // mission can re-open — an active one already takes input via ask_user/respond.
    let is_revise = completion
        .text
        .trim()
        .trim_matches(|c: char| !c.is_ascii_alphanumeric())
        .eq_ignore_ascii_case("REVISE");
    let terminal = matches!(sess.status.as_str(), "done" | "armed" | "error" | "cancelled");
    let awaiting = sess.status == "awaiting_input";
    // A correction typed while PAUSED (e.g. reviewing the exposed API at the connect_setup step) re-opens
    // the mission the same way a post-completion correction does — clears the pause and resumes so the
    // planner applies the change IN PLACE (build_workflow updates the existing workflow, no duplicate).
    if is_revise && (terminal || awaiting) && st.engine.browser().is_some() {
        transcript.push(json!({ "role": "user", "content": question, "ts": ts }));
        let transcript_s = serde_json::to_string(&transcript).unwrap_or_else(|_| "[]".into());
        concierge_sessions::update(
            &st.db,
            id,
            &ConciergeUpdate {
                status: Some("planning"),
                progress_message: Some(if awaiting { "Applying your change…" } else { "Revising what I built…" }),
                transcript: Some(&transcript_s),
                // Clear the pause (set only when awaiting) so the resumed planner doesn't re-pause.
                pending_request: Some(""),
                // A cancelled mission left the flag set — clear it or the loop dies on turn one.
                cancel_requested: Some(0),
                ..Default::default()
            },
        )
        .await?;
        let state = st.clone();
        tokio::spawn(async move {
            concierge::run_mission(state, id).await;
        });
        let s = concierge_sessions::get_by_id(&st.db, id)
            .await?
            .ok_or_else(|| LocalError::NotFound(format!("concierge_session {id}")))?;
        return Ok(Json(to_view(&s)));
    }

    // Plain question (or a revise we cannot run) — append the Q/A to the transcript.
    let answer = if is_revise {
        "I can't re-open this mission right now — start a new one with the change you want and I'll build it that way.".to_string()
    } else {
        completion.text
    };
    transcript.push(json!({ "role": "user", "content": question, "ts": ts }));
    transcript.push(json!({ "role": "assistant", "content": answer, "ts": ts }));
    let transcript_s = serde_json::to_string(&transcript).unwrap_or_else(|_| "[]".into());
    concierge_sessions::update(
        &st.db,
        id,
        &ConciergeUpdate { transcript: Some(&transcript_s), ..Default::default() },
    )
    .await?;

    let s = concierge_sessions::get_by_id(&st.db, id)
        .await?
        .ok_or_else(|| LocalError::NotFound(format!("concierge_session {id}")))?;
    Ok(Json(to_view(&s)))
}

// ── POST /:id/persona ──────────────────────────────────────────────────────

/// `POST /v1/ai-concierge/:id/persona` body — `{persona_id: N}` to attach, `{persona_id: null}` to
/// detach.
#[derive(Debug, Deserialize)]
struct PersonaBody {
    #[serde(default)]
    persona_id: Option<i64>,
}

/// Attach (or clear) the mission's login identity INLINE, at any non-terminal status. The user can
/// pre-attach a persona before recording, or add one mid-run — the planner then reaches login-gated
/// data with it (the run engine restores its session + mints TOTP, so 2FA is handled) without
/// pausing to ask. Merges `plan.persona_id` + `resources.persona_id`; a null clears both.
async fn set_persona(
    State(st): State<AppState>,
    Path(id): Path<i64>,
    Json(body): Json<PersonaBody>,
) -> LocalResult<Json<Value>> {
    let sess = concierge_sessions::get_by_id(&st.db, id)
        .await?
        .ok_or_else(|| LocalError::NotFound(format!("concierge_session {id}")))?;
    if matches!(sess.status.as_str(), "done" | "error" | "cancelled") {
        return Err(LocalError::BadRequest(
            "this mission has ended — start a new one to attach a persona".into(),
        ));
    }
    // Validate the persona exists before attaching (a null just clears).
    if let Some(pid) = body.persona_id {
        if personas::get_by_id(&st.db, pid).await?.is_none() {
            return Err(LocalError::NotFound(format!("persona {pid}")));
        }
    }

    // Write the single `persona_id` member of each JSON column in the DATABASE rather than reading
    // both columns, editing them in memory, and writing them back whole. The concierge crawl loop
    // rewrites `resources` on the same row about once a second while a crawl runs, so a
    // read-modify-write here raced it: attaching a persona mid-crawl either vanished (the loop's next
    // tick overwrote this column) or froze the live progress card (this write dropped the loop's
    // `crawl_live` key). `json_set` on one path is immune to that.
    let value = body.persona_id.map(|pid| json!(pid).to_string());
    for column in ["plan", "resources"] {
        concierge_sessions::set_json_key(&st.db, id, column, "persona_id", value.as_deref()).await?;
    }

    let s = concierge_sessions::get_by_id(&st.db, id)
        .await?
        .ok_or_else(|| LocalError::NotFound(format!("concierge_session {id}")))?;
    Ok(Json(to_view(&s)))
}

/// Turn the session transcript into a real conversation thread so a follow-up continues the SAME
/// thread instead of a standalone one-shot: the model sees the goal, everything it narrated while
/// building, and every earlier Q&A. Internal 'system' nudges are dropped, consecutive same-role lines
/// are merged (strict alternation for providers that require it), the window is bounded, and the live
/// question (carrying DOCS + CONTEXT) is appended as the final user turn.
fn thread_messages(transcript_raw: Option<&str>, final_user: String) -> Vec<AiMessage> {
    let entries = transcript_raw
        .and_then(|s| serde_json::from_str::<Value>(s).ok())
        .and_then(|v| v.as_array().cloned())
        .unwrap_or_default();
    let mut thread: Vec<AiMessage> = Vec::new();
    let start = entries.len().saturating_sub(24);
    for line in &entries[start..] {
        let role = line.get("role").and_then(|r| r.as_str()).unwrap_or("");
        if role != "user" && role != "assistant" {
            continue; // skip internal 'system' nudges — not part of the visible thread
        }
        let content = line.get("content").and_then(|c| c.as_str()).unwrap_or("").trim();
        if content.is_empty() {
            continue;
        }
        // Merge consecutive same-role lines so the thread strictly alternates.
        if let Some(AiMessage { role: last_role, content: AiMessageContent::Text(t) }) = thread.last_mut() {
            if last_role.as_str() == role {
                t.push_str("\n\n");
                t.push_str(content);
                continue;
            }
        }
        thread.push(AiMessage { role: role.into(), content: AiMessageContent::Text(content.to_string()) });
    }
    // The live question (docs+context) is always the last user turn.
    match thread.last_mut() {
        Some(AiMessage { role, content: AiMessageContent::Text(t) }) if role.as_str() == "user" => {
            t.push_str("\n\n");
            t.push_str(&final_user);
        }
        _ => thread.push(AiMessage { role: "user".into(), content: AiMessageContent::Text(final_user) }),
    }
    thread
}

/// Compact JSON of the user's REAL resources + the endpoints their workflow exposes, so the
/// answer is grounded in concrete ids/URLs (never invented).
async fn ask_context(st: &AppState, sess: &ConciergeSession) -> String {
    let resources: Value = sess
        .resources
        .as_deref()
        .and_then(|s| serde_json::from_str(s).ok())
        .unwrap_or_else(|| json!({}));
    let plan: Value = sess
        .plan
        .as_deref()
        .and_then(|s| serde_json::from_str(s).ok())
        .unwrap_or_else(|| json!({}));
    let mut ctx = json!({ "goal": sess.goal, "resources": resources });
    if let Some(wid) = resources.get("workflow_id").and_then(Value::as_i64) {
        if let Ok(Some(wf)) = workflows::get_by_id(&st.db, wid).await {
            ctx["endpoints"] = Value::Array(concierge::build_connect_surfaces(wid, wf.streaming_config.as_deref()));
        }
        for key in ["workflow_name", "schedule", "functions"] {
            if let Some(v) = plan.get(key) {
                ctx[key] = v.clone();
            }
        }
    }
    if resources.get("target_id").is_some() {
        ctx["monitor"] = json!({ "url": plan.get("resolved_url") });
    }
    let s = serde_json::to_string(&ctx).unwrap_or_default();
    s.chars().take(6000).collect()
}

// ── POST /:id/cancel ─────────────────────────────────────────────────────────

/// `POST /v1/ai-concierge/:id/cancel` — END the mission. Sets `cancel_requested=1` and finalizes
/// 'cancelled' immediately, whatever state it was in (a paused mission has no active loop to pick up
/// the flag, and finalizing unconditionally is also what unsticks an orphaned one).
///
/// This is the destructive one. To stop the AI mid-thought WITHOUT ending the mission, use
/// `/interrupt` — it parks at 'awaiting_input' and the next message resumes in place. Cancel also
/// still works on an interrupted mission (awaiting_input is not terminal), which is exactly what the
/// FE's "End session" does after a Stop.
async fn cancel(State(st): State<AppState>, Path(id): Path<i64>) -> LocalResult<Json<Value>> {
    Ok(Json(cancel_core(&st, id).await?))
}

/// `POST /v1/ai-concierge/:id/interrupt` — STOP GENERATING. Breaks the AI's current turn but KEEPS
/// the mission alive; only `/cancel` ends it.
async fn interrupt(State(st): State<AppState>, Path(id): Path<i64>) -> LocalResult<Json<Value>> {
    Ok(Json(interrupt_core(&st, id).await?))
}

/// Shared interrupt core: flag + PARK (never finalize). The mission lands on `awaiting_input` with no
/// `pending_request`, so the FE shows the composer and no form, and the user's next message resumes
/// this same mission in place through `/ask`'s REVISE path — nothing built is lost, and the thread
/// never shows "Cancelled".
///
/// `cancel_requested` is still raised because that's the ONE flag a running discovery polls to stop
/// and close its browser; the loop distinguishes interrupt from cancel by checking the status first
/// (an interrupt has already parked to a non-active status, so the loop returns instead of
/// finalizing). `/ask` clears the flag when it resumes.
pub(crate) async fn interrupt_core(st: &AppState, id: i64) -> LocalResult<Value> {
    let sess = concierge_sessions::get_by_id(&st.db, id)
        .await?
        .ok_or_else(|| LocalError::NotFound(format!("concierge_session {id}")))?;

    // Only an ACTIVE mission has a turn to interrupt — idempotent everywhere else.
    if !matches!(
        sess.status.as_str(),
        "planning" | "browsing" | "proposing" | "building" | "armed"
    ) {
        return Ok(json!({ "session_id": id, "status": sess.status }));
    }

    concierge_sessions::update(
        &st.db,
        id,
        &ConciergeUpdate {
            cancel_requested: Some(1),
            status: Some("awaiting_input"),
            // `Some("")` clears to SQL NULL — no form, just the composer.
            pending_request: Some(""),
            progress_message: Some("Stopped. Tell me what to change, or send a message to continue."),
            turn_seq: Some(sess.turn_seq + 1),
            ..Default::default()
        },
    )
    .await?;
    Ok(json!({ "session_id": id, "status": "awaiting_input" }))
}

/// Shared cancel core (REST + MCP `writ_mission_cancel`): flag + finalize, idempotent on terminal.
pub(crate) async fn cancel_core(st: &AppState, id: i64) -> LocalResult<Value> {
    let sess = concierge_sessions::get_by_id(&st.db, id)
        .await?
        .ok_or_else(|| LocalError::NotFound(format!("concierge_session {id}")))?;

    // Already terminal — nothing to do.
    if matches!(sess.status.as_str(), "done" | "error" | "cancelled") {
        return Ok(json!({ "session_id": id, "status": sess.status }));
    }

    // Flag it (a running discovery polls `cancel_requested` and stops + closes its browser), AND
    // finalize to 'cancelled' now. Finalizing unconditionally is what unsticks an ORPHANED mission —
    // one whose loop already exited without finalizing (or was killed), so nothing is left to observe
    // the flag. If a loop IS still running it converges harmlessly: its next-turn cancel check re-runs
    // this same terminal finalize (idempotent) and its exit closes the warm browser. Either way the
    // user's Stop takes effect immediately instead of hanging on a dead session.
    concierge_sessions::update(
        &st.db,
        id,
        &ConciergeUpdate { cancel_requested: Some(1), ..Default::default() },
    )
    .await?;
    let done = concierge_sessions::finalize(&st.db, id, "cancelled", Some("Mission cancelled."), None).await?;
    Ok(json!({ "session_id": id, "status": done.status }))
}

/// Build a `409 Conflict` `{error, code}` response by hand (`LocalError` has no Conflict variant).
fn conflict(message: &str, code: &str) -> Response {
    (StatusCode::CONFLICT, Json(json!({ "error": message, "code": code }))).into_response()
}

/// The host of the site this mission targets — from `plan.resolved_url`, else the first
/// domain-looking token in the goal. Drives the human naming of AI-stored credentials.
fn credential_site_host(sess: &crate::local::store::concierge_sessions::ConciergeSession) -> Option<String> {
    let from_plan = sess
        .plan
        .as_deref()
        .and_then(|s| serde_json::from_str::<Value>(s).ok())
        .and_then(|p| p.get("resolved_url").and_then(|u| u.as_str()).map(str::to_string))
        .and_then(|u| host_of_url(&u));
    if from_plan.is_some() {
        return from_plan;
    }
    // Fallback: a domain-looking word in the goal ("watchtow3r.app", "shop.example.co.uk").
    sess.goal
        .split(|c: char| c.is_whitespace() || c == ',' || c == '(' || c == ')' || c == '"' || c == '\'')
        .map(|w| w.trim_start_matches("https://").trim_start_matches("http://").trim_end_matches(['/', '.', ':']))
        .find(|w| {
            let parts: Vec<&str> = w.split('.').collect();
            parts.len() >= 2
                && parts.iter().all(|p| !p.is_empty() && p.chars().all(|c| c.is_ascii_alphanumeric() || c == '-'))
                && parts.last().map(|t| t.len() >= 2 && t.chars().all(|c| c.is_ascii_alphabetic())).unwrap_or(false)
        })
        .map(|w| w.trim_start_matches("www.").to_ascii_lowercase())
}

fn host_of_url(url: &str) -> Option<String> {
    let rest = url.split("://").nth(1)?;
    let host = rest.split(['/', '?', '#']).next()?.split('@').next_back()?.split(':').next()?;
    if host.is_empty() {
        None
    } else {
        Some(host.trim_start_matches("www.").to_ascii_lowercase())
    }
}

/// Site slug for vault keys: "watchtow3r.app" → "watchtow3r_app". Same site+field ⇒ same key,
/// so re-entering a credential UPDATES the row instead of piling up per-mission duplicates.
fn credential_site_slug(sess: &crate::local::store::concierge_sessions::ConciergeSession) -> Option<String> {
    credential_site_host(sess).map(|h| {
        h.chars()
            .map(|c| if c.is_ascii_alphanumeric() { c } else { '_' })
            .collect()
    })
}

/// field → human label, from the pause the user is answering: a `secret`-kind request's `question`
/// (the label the agent asked with, e.g. "API key"), plus any inline `credential_fields` labels.
fn credential_labels(
    sess: &crate::local::store::concierge_sessions::ConciergeSession,
) -> std::collections::HashMap<String, String> {
    let mut labels = std::collections::HashMap::new();
    let requests = sess
        .pending_request
        .as_deref()
        .and_then(|s| serde_json::from_str::<Value>(s).ok())
        .and_then(|v| v.get("requests").and_then(|r| r.as_array()).cloned())
        .unwrap_or_default();
    for r in &requests {
        let field = r.get("field").and_then(|f| f.as_str());
        if r.get("kind").and_then(|k| k.as_str()) == Some("secret") {
            if let (Some(f), Some(q)) = (field, r.get("question").and_then(|q| q.as_str())) {
                // A short question IS the label ("API key"); a full sentence stays out.
                let q = q.trim().trim_end_matches(['?', ':', '.']);
                if !q.is_empty() && q.chars().count() <= 40 {
                    labels.insert(f.to_string(), q.to_string());
                }
            }
        }
        if let Some(cfs) = r.get("credential_fields").and_then(|c| c.as_array()) {
            for cf in cfs {
                if let (Some(f), Some(l)) = (
                    cf.get("field").and_then(|v| v.as_str()),
                    cf.get("label").and_then(|v| v.as_str()).map(str::trim).filter(|s| !s.is_empty()),
                ) {
                    labels.insert(f.to_string(), l.to_string());
                }
            }
        }
    }
    labels
}

#[cfg(test)]
mod tests {
    use super::*;

    fn text_of(m: &AiMessage) -> &str {
        match &m.content {
            AiMessageContent::Text(t) => t,
            _ => "",
        }
    }

    #[test]
    fn ask_thread_preserves_conversation() {
        // goal(user) → mission narration(assistant×3, one 'system' nudge dropped) → prior Q&A → now ask.
        let tx = json!([
            { "role": "user", "content": "watch price of X" },
            { "role": "assistant", "content": "Opening the page…" },
            { "role": "assistant", "content": "Monitor created." },
            { "role": "system", "content": "internal nudge" },
            { "role": "assistant", "content": "All set." },
            { "role": "user", "content": "how do I call this?" },
            { "role": "assistant", "content": "POST /v1/... with Bearer key" }
        ])
        .to_string();

        let out = thread_messages(Some(&tx), "QUESTION: show me python\nDOCS:...\nCONTEXT:...".into());
        let roles: Vec<&str> = out.iter().map(|m| m.role.as_str()).collect();
        assert_eq!(roles, ["user", "assistant", "user", "assistant", "user"]);
        // strict alternation
        assert!(roles.windows(2).all(|w| w[0] != w[1]));
        // 'system' nudge dropped everywhere
        assert!(out.iter().all(|m| !text_of(m).contains("internal nudge")));
        // consecutive assistant lines merged
        assert_eq!(text_of(&out[1]), "Opening the page…\n\nMonitor created.\n\nAll set.");
        // the live question is the final user turn
        assert!(text_of(out.last().unwrap()).contains("show me python"));
    }

    #[test]
    fn ask_thread_empty_transcript_is_single_user_turn() {
        let out = thread_messages(None, "Q".into());
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].role, "user");
        assert_eq!(text_of(&out[0]), "Q");
    }

    #[test]
    fn ask_thread_merges_question_into_trailing_user_turn() {
        let tx = json!([
            { "role": "assistant", "content": "a" },
            { "role": "user", "content": "b" }
        ])
        .to_string();
        let out = thread_messages(Some(&tx), "Q".into());
        let roles: Vec<&str> = out.iter().map(|m| m.role.as_str()).collect();
        assert_eq!(roles, ["assistant", "user"]); // no consecutive-user turns
        assert_eq!(text_of(&out[1]), "b\n\nQ");
    }
}
