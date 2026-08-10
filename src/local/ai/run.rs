//! Shared driver for an autonomous AI session that (optionally) records a reusable workflow.
//!
//! This is the single source of truth for "insert a session row → open a page → drive the
//! autonomous loop ([`crate::local::ai::session::run_session`]) → finalize the row → record + link a
//! `workflows` row when `generate_workflow`". It was factored out of the `/v1/ai-sessions/start`
//! detached task so BOTH callers share it verbatim:
//!
//!   * the loopback REST handler ([`crate::local::api::v1::ai_sessions::start`]) — the desktop
//!     wizard's create-and-run path, and
//!   * the self-host fleet bridge ([`crate::bridge::fleet_bridge`]'s `ai_session_start` arm) — the
//!     coordinator dispatches ONE frame, this agent runs the whole loop locally and replies.
//!
//! The AI runs through the local multi-provider gateway on the user's own key (or the cloud gateway
//! toggle); nothing about the loop leaves the machine. A page is opened exactly like the run engine:
//! warm the shared browser, a stealth context (pinned to the optional persona's fingerprint + proxy),
//! URL-guard + navigate, then drive the loop. Failures are isolated — a browser/navigation/loop error
//! finalizes the row as `error` and returns an [`AiSessionOutcome`] with `status = "error"`; it never
//! panics the caller.

use std::collections::HashMap;
use std::sync::atomic::AtomicBool;
use std::sync::Arc;
use std::time::Duration;

use serde_json::{json, Value};

use crate::dom::analyzer::PageEvaluator;
use crate::local::ai::provider;
use crate::local::ai::session::{run_session, SessionConfig};
use crate::local::engine::{persona, LocalEngine};
use crate::local::error::LocalResult;
use crate::local::store::ai_sessions::{self, NewAiSession};

/// Inputs for one shared AI-session run. Owned/plain values so the caller (REST handler or fleet
/// bridge) can build it without holding request-scoped borrows across the loop.
pub struct AiSessionParams {
    /// Optional display name for the session/workflow (falls back to an "AI: <goal>" name).
    pub name: Option<String>,
    /// What to accomplish (required, non-empty after trim — the caller validates).
    pub goal: String,
    /// Where to start (defaults to `about:blank` when `None`).
    pub entry_url: Option<String>,
    /// Non-secret hints shown to the model (plaintext).
    pub available_data: HashMap<String, String>,
    /// Actual values to fill (already merged with any decrypted secrets/credentials by the caller;
    /// secret keys override plaintext hints on collision).
    pub fill_data: HashMap<String, String>,
    /// Max page iterations before the loop gives up (clamped 1..=100).
    pub max_steps: u32,
    /// When set, the session is bound to an EXISTING workflow — recording is skipped so the link is
    /// not clobbered. When `None`, `generate_workflow` decides whether a new workflow is recorded.
    pub workflow_id: Option<i64>,
    /// Optional already-resolved login persona (fingerprint / session-state / proxy / credentials).
    pub resolved_persona: Option<persona::ResolvedPersona>,
    /// Whether a successful (`complete`) finish records + links a reusable workflow. Effective only
    /// when `workflow_id` is `None`.
    pub generate_workflow: bool,
    /// EXPLORE mode: run as a GENERAL navigate+extract agent (the concierge build) rather than a pure
    /// form-filler — it may `navigate` to pages and `extract` lists, and it doesn't stop at the login/
    /// success page. Parity with the cloud agent. `false` = the classic form-filler.
    pub explore: bool,
    /// Replay spelling for recorded `{{key}}` placeholders (explorer): a vault credential maps to its
    /// `{{secret:VAULT_KEY}}` ref, a plaintext answer to its literal. See `SessionConfig`.
    pub record_templates: HashMap<String, String>,
    /// Owning concierge session id (explorer): lets an ask-the-user pause PARK the live session
    /// (browser stays open) until `/respond` resolves it via `ask_gate`. See `SessionConfig`.
    pub ask_concierge_session_id: Option<i64>,
    /// Optional cooperative-cancel flag polled by the loop each iteration.
    pub cancel: Option<Arc<AtomicBool>>,
}

/// The terminal result of a shared AI-session run — the projection both callers report.
#[derive(Debug, Clone)]
pub struct AiSessionOutcome {
    /// The local `ai_sessions.id` inserted for this run.
    pub session_id: i64,
    /// Terminal status string (`complete|blocked|max_steps|stuck|error|cancelled`).
    pub status: String,
    /// Page iterations taken.
    pub steps: u32,
    /// The recorded workflow id, when a workflow was recorded + linked (else `None`).
    pub workflow_id: Option<i64>,
    /// The recorded workflow's display name, when one was recorded (else `None`).
    pub workflow_name: Option<String>,
    /// Human-readable summary/message.
    pub message: String,
    /// Error string when the run errored (else `None`).
    pub error: Option<String>,
    /// CONCIERGE mode: orchestration setup intents (create_monitor / wire_automation / expose_api) the
    /// brain emitted IN-LOOP, grounded on the live pages it browsed. The concierge materializes these
    /// into real rows. Empty for a normal AI session / a run that emitted none.
    pub orchestration_intents: Vec<Value>,
}

/// A [`PageEvaluator`] over a live page — passed to [`run_session`] for the DOM-analyzer probe API.
struct PageEval(playwright_rs::Page);
impl PageEvaluator for PageEval {
    fn evaluate_json(
        &self,
        js: &str,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = anyhow::Result<Value>> + Send + '_>> {
        let js = js.to_string();
        Box::pin(async move {
            self.0
                .evaluate(&js, None::<&()>)
                .await
                .map_err(|e| anyhow::anyhow!("evaluate_json failed: {}", e))
        })
    }
    fn evaluate_json_with_args(
        &self,
        js: &str,
        args: &[Value],
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = anyhow::Result<Value>> + Send + '_>> {
        let js = js.to_string();
        let args = Value::Array(args.to_vec());
        Box::pin(async move {
            self.0
                .evaluate(&js, Some(&args))
                .await
                .map_err(|e| anyhow::anyhow!("evaluate_json_with_args failed: {}", e))
        })
    }
}

/// Insert a session row, drive the autonomous loop, finalize the row, record + link a workflow when
/// opted in, and fire the `ai_session_started` / `ai_session_completed` lifecycle automations.
/// Returns the terminal [`AiSessionOutcome`]. This is the SYNCHRONOUS entry point the fleet bridge
/// uses: the coordinator dispatches one frame, this call runs the whole loop and returns the result
/// so the bridge can reply.
///
/// The HTTP handler (`/v1/ai-sessions/start`) instead inserts the row itself (to return the id
/// immediately) and then calls [`finish_ai_session`] in a detached task — the same post-insert body.
///
/// The whole thing is failure-isolated: a browser/navigation/loop error finalizes the row as `error`
/// and returns `status = "error"` rather than propagating. The recording step is best-effort — it is
/// logged but never changes the already-finalized status.
pub async fn run_ai_session_and_record(
    db: &sqlx::sqlite::SqlitePool,
    engine: &Arc<dyn LocalEngine>,
    browser: &Arc<crate::browser::manager::BrowserManager>,
    ai_cfg: &provider::AiConfig,
    params: AiSessionParams,
) -> LocalResult<AiSessionOutcome> {
    // Recording is skipped when the caller opted out OR when the session is already linked to an
    // existing workflow (don't clobber that link).
    let generate_workflow = params.generate_workflow && params.workflow_id.is_none();

    // Persist the running session row.
    let session = ai_sessions::insert(
        db,
        &NewAiSession {
            run_id: None,
            workflow_id: params.workflow_id,
            name: params.name.clone(),
            goal: params.goal.trim().to_string(),
            entry_url: params.entry_url.clone(),
            max_steps: Some(params.max_steps.clamp(1, 100) as i64),
            available_data: Some(
                serde_json::to_string(&params.available_data).unwrap_or_else(|_| "{}".into()),
            ),
            // Persist the KEYS only — the values may be vault-opened credentials, and nothing reads
            // this column back for execution (the run uses params directly). Plaintext at rest here
            // would silently outlive the run.
            fill_data: Some(
                serde_json::to_string(
                    &params
                        .fill_data
                        .keys()
                        .map(|k| (k.clone(), "[stored]".to_string()))
                        .collect::<HashMap<String, String>>(),
                )
                .unwrap_or_else(|_| "{}".into()),
            ),
            generate_workflow: Some(generate_workflow),
        },
    )
    .await?;

    finish_ai_session(db, engine, browser, ai_cfg, session.id, params).await
}

/// The post-insert body of an AI-session run: fire `started`, drive the loop, finalize the row,
/// record + link a workflow when opted in, and fire `completed`. Given an ALREADY-INSERTED
/// `session_id` so the REST handler can return that id immediately (async launch + poll) while this
/// runs in a detached task; [`run_ai_session_and_record`] inserts then calls it synchronously.
pub async fn finish_ai_session(
    db: &sqlx::sqlite::SqlitePool,
    engine: &Arc<dyn LocalEngine>,
    browser: &Arc<crate::browser::manager::BrowserManager>,
    ai_cfg: &provider::AiConfig,
    session_id: i64,
    params: AiSessionParams,
) -> LocalResult<AiSessionOutcome> {
    // `generate_workflow` is intentionally NOT read here: whether to record is decided by the
    // FINALIZED row's `generate_workflow` column (the single source of truth the insert already
    // stamped), so a resumed/handed-off session records consistently.
    let AiSessionParams {
        name: _,
        goal,
        entry_url,
        available_data,
        fill_data,
        max_steps,
        workflow_id,
        resolved_persona,
        generate_workflow: _,
        explore,
        record_templates,
        ask_concierge_session_id,
        cancel,
    } = params;

    let goal = goal.trim().to_string();
    let max_steps = max_steps.clamp(1, 100);

    // Fire the `ai_session_started` lifecycle event (detached, best-effort).
    fire_ai_session_event(
        db,
        engine,
        "ai_session_started",
        workflow_id,
        json!({
            "event": "ai_session_started",
            "ai_session_id": session_id,
            "workflow_id": workflow_id,
            "goal": goal,
        }),
    );

    // Drive the loop (open a page + run the autonomous session). A launch/navigation error is mapped
    // into an `error` terminal status rather than propagated, so the row always finalizes.
    let outcome = run_ai_session_loop(
        session_id,
        browser,
        &resolved_persona,
        ai_cfg,
        db,
        &goal,
        &available_data,
        &fill_data,
        &record_templates,
        ask_concierge_session_id,
        entry_url.as_deref(),
        max_steps,
        explore,
        cancel,
    )
    .await;

    // Pull the captured replay steps out of the outcome (moved out; empty on an errored run).
    let recorded_steps: Vec<Value> = match &outcome {
        Ok(res) => res.recorded_steps.clone(),
        Err(_) => Vec::new(),
    };
    // Orchestration setup intents the brain emitted in-loop (concierge mode) — pulled out the same way
    // before the outcome is moved by the match below.
    let orchestration_intents: Vec<Value> = match &outcome {
        Ok(res) => res.orchestration_intents.clone(),
        Err(_) => Vec::new(),
    };
    let (status, step_count, message, last_url, result_data, mut error_message) = match outcome {
        Ok(res) => (
            res.status.as_str().to_string(),
            res.steps as i64,
            res.message.clone(),
            res.result.get("current_url").and_then(|v| v.as_str()).map(String::from),
            Some(serde_json::to_string(&res.result).unwrap_or_else(|_| "{}".into())),
            res.error,
        ),
        Err(e) => ("error".to_string(), 0, e.to_string(), None, None, Some(e.to_string())),
    };

    let finalized = ai_sessions::finalize(
        db,
        session_id,
        &status,
        step_count,
        last_url.as_deref(),
        result_data.as_deref(),
        error_message.as_deref(),
    )
    .await?;

    let success = status == "complete";

    // ── Record a reusable workflow from the captured steps ──
    // On a SUCCESSFUL finish, when the session opted in and actually captured replayable steps,
    // assemble + persist a `workflows` row and link it back (`ai_sessions.workflow_id`). Isolated +
    // best-effort: any failure here is logged and NEVER changes the session's terminal status.
    let mut recorded_workflow_id: Option<i64> = None;
    let mut recorded_workflow_name: Option<String> = None;
    if success && !recorded_steps.is_empty() {
        if let (Some(bound_id), true) = (workflow_id, explore) {
            // EXPLORER re-run bound to an existing workflow (the concierge REVISION path): the
            // corrected steps must actually LAND on that workflow — silently discarding them while
            // the fresh session's test_result flips to PASS would reopen the honest-gates over a
            // stale, still-broken workflow. Update steps + entry_url in place; name/functions stay.
            let entry_url = recorded_steps
                .iter()
                .find(|s| s.get("type").and_then(|t| t.as_str()) == Some("navigate"))
                .and_then(|s| s.pointer("/config/url"))
                .and_then(|u| u.as_str())
                .map(str::to_string);
            let steps_s = serde_json::to_string(&recorded_steps).unwrap_or_else(|_| "[]".into());
            match crate::local::store::workflows::update(
                db,
                bound_id,
                &crate::local::store::workflows::WorkflowUpdate {
                    steps: Some(steps_s),
                    entry_url,
                    ..Default::default()
                },
            )
            .await
            {
                Ok(_) => {
                    recorded_workflow_id = Some(bound_id);
                    tracing::info!(ai_session_id = session_id, workflow_id = bound_id,
                        "updated the bound workflow's steps in place from the explorer re-run");
                }
                Err(e) => {
                    tracing::warn!(ai_session_id = session_id, workflow_id = bound_id, error = %e,
                        "updating the bound workflow from the AI session failed");
                    // Surface the failed persist: without this the outcome still reports the bound
                    // workflow id + complete, and the concierge would stamp a PASS over a workflow
                    // whose steps never changed — the silent-dishonesty class again.
                    error_message = Some(format!(
                        "the re-recorded steps could NOT be saved onto workflow {bound_id}: {e}"
                    ));
                }
            }
        } else if finalized.generate_workflow != 0 {
            match build_and_link_workflow(db, session_id, &goal, &recorded_steps).await {
                Ok((wf_id, wf_name)) => {
                    recorded_workflow_id = Some(wf_id);
                    recorded_workflow_name = Some(wf_name);
                }
                Err(e) => {
                    tracing::warn!(ai_session_id = session_id, error = %e,
                        "recording a workflow from the AI session failed");
                }
            }
        }
    }

    fire_ai_session_event(
        db,
        engine,
        "ai_session_completed",
        workflow_id,
        json!({
            "event": "ai_session_completed",
            "ai_session_id": session_id,
            "workflow_id": recorded_workflow_id.or(workflow_id),
            "success": success,
            "status": status,
            "result": finalized.result_data.as_deref()
                .and_then(|s| serde_json::from_str::<Value>(s).ok())
                .unwrap_or_else(|| json!({})),
        }),
    );

    Ok(AiSessionOutcome {
        session_id,
        status,
        steps: step_count.max(0) as u32,
        // A session pre-linked to an existing workflow reports that link; a freshly recorded one
        // reports the new id/name.
        workflow_id: recorded_workflow_id.or(workflow_id),
        workflow_name: recorded_workflow_name,
        message,
        error: error_message,
        orchestration_intents,
    })
}

/// Open a page (warm browser + stealth context pinned to the optional persona) and drive the
/// autonomous loop. `fill_data` is already merged with the persona's credentials. Returns the
/// [`crate::local::ai::session::SessionResult`] or an error (the caller finalizes it as `error`).
/// Always closes the context on exit.
#[allow(clippy::too_many_arguments)]
async fn run_ai_session_loop(
    session_id: i64,
    browser: &Arc<crate::browser::manager::BrowserManager>,
    resolved_persona: &Option<persona::ResolvedPersona>,
    ai_cfg: &provider::AiConfig,
    pool: &sqlx::sqlite::SqlitePool,
    goal: &str,
    available_data: &HashMap<String, String>,
    fill_data: &HashMap<String, String>,
    record_templates: &HashMap<String, String>,
    ask_concierge_session_id: Option<i64>,
    entry_url: Option<&str>,
    max_steps: u32,
    explore: bool,
    cancel: Option<Arc<AtomicBool>>,
) -> LocalResult<crate::local::ai::session::SessionResult> {
    use crate::local::error::LocalError;

    let entry_url = entry_url.unwrap_or("about:blank");
    let headless = true; // background/unattended by default (parity with automation runs).

    let proxy = resolved_persona.as_ref().and_then(|p| p.proxy.clone());

    browser
        .ensure_warm_browser_with(headless)
        .await
        .map_err(|e| LocalError::Internal(format!("browser launch failed: {e}")))?;
    // The persona's banked fingerprint, or a deterministic one seeded on its id, so a
    // persona without saved warmth still presents ONE stable machine across runs. Built
    // after launch so the UA carries the real Chrome major.
    // `match` rather than `.map()`: the closure `.map()` takes is not async, so awaiting
    // `chrome_major()` inside it does not compile. Matching also keeps the probe lazy — with no
    // persona there is no fingerprint to build, so we never pay for it.
    let fingerprint = match resolved_persona.as_ref() {
        Some(p) => {
            let chrome_major = browser.chrome_major().await;
            Some(p.identity(&chrome_major, None, headless))
        }
        None => None,
    };
    let (context, page, _fp) = browser
        .create_stealth_context_with_fingerprint_proxy(fingerprint, proxy)
        .await
        .map_err(|e| LocalError::Internal(format!("browser context failed: {e}")))?;

    // Vet the entry URL before navigating (rejects file:/internal/metadata hosts). about:blank ok.
    if !crate::security::url_guard::is_navigation_url_safe_async(entry_url).await {
        let _ = context.close().await;
        return Err(LocalError::BadRequest(format!("Refused unsafe entry URL: {entry_url}")));
    }

    // Restore the persona's saved session (cookies + storage) BEFORE navigation → start signed-in;
    // else a plain navigation. 1:1 with the run engine restore.
    let nav_result = match resolved_persona.as_ref().and_then(|p| p.session_state.as_ref()) {
        Some(state) => {
            crate::automation::session_state::inject_session_state(
                &page,
                &context,
                state,
                Some(entry_url),
                30_000,
            )
            .await
        }
        None => {
            crate::browser::navigation::goto(&page, entry_url, "domcontentloaded", Duration::from_secs(30))
                .await
        }
    };
    if let Err(e) = nav_result {
        let _ = context.close().await;
        return Err(LocalError::Internal(format!("navigation failed: {e}")));
    }

    let cfg = SessionConfig {
        goal: goal.to_string(),
        available_data: available_data.clone(),
        fill_data: fill_data.clone(),
        max_steps,
        record_templates: record_templates.clone(),
        ask_session_id: ask_concierge_session_id,
    };

    // "Watch the AI": register a live-preview channel keyed `ai-{id}` BOUND to this page, plus a
    // per-step thinking/replay sink. The screencast is lazy — it starts only when a spectator opens
    // the preview and stops when the last leaves. Deregistered when the loop returns.
    let preview = crate::local::ai::live_preview::register_with_page(format!("ai-{session_id}"), page.clone());
    let psender = preview.sender();
    psender.send_status("running");

    // Concierge-owned browse (the discovery/build agent): ALSO bind this page to the owning
    // mission's `concierge-{id}` channel. The panel's embedded live view watches that mission
    // channel for the whole mission, while this browse otherwise streams only on `ai-{id}` —
    // without the mirror a discovery mission shows a blank frame. The mission channel is
    // registered for the mission's lifetime (run_mission), so this is a cheap page swap; cleared
    // below before this browse's context closes.
    if let Some(cid) = ask_concierge_session_id {
        crate::local::ai::live_preview::set_page(&format!("concierge-{cid}"), Some(page.clone())).await;
    }

    let evaluator = PageEval(page.clone());
    let sink = crate::local::ai::session::StepSink {
        sender: &psender,
        // Mirror each step event to the owning concierge mission's channel so
        // the panel's embedded narration rail streams in real time too.
        mirror: ask_concierge_session_id
            .and_then(|cid| crate::local::ai::live_preview::sender_for(&format!("concierge-{cid}"))),
        kind: "ai",
        ref_id: session_id,
    };
    // EXPLORE (the concierge build) runs the GENERAL agent loop — multi-turn, navigate+extract,
    // deliverables verified against the live page. Everything else keeps the classic form-filler.
    let result = if explore {
        // Passive network capture across the whole session so the agent can DISCOVER the site's
        // backend API (XHR/fetch calls, JSON payloads) and build robust api_call extractors instead
        // of only scraping the DOM. Listeners on the context observe every call for free.
        let net = std::sync::Arc::new(tokio::sync::Mutex::new(
            crate::automation::network_capture::NetworkCapture::new(),
        ));
        crate::ai::api_discovery_mode::attach_network_capture(&context, net.clone()).await;
        crate::local::ai::explorer::run_explorer(&page, &cfg, ai_cfg, pool, cancel.as_deref(), Some(&sink), Some(net), false).await
    } else {
        run_session(&page, &evaluator, &cfg, ai_cfg, pool, cancel.as_deref(), Some(&sink)).await
    };

    let final_status = match &result {
        Ok(r) => r.status.as_str(),
        Err(_) => "error",
    };
    psender.send_status(final_status);
    drop(preview);

    // Unbind the mission channel BEFORE closing the context so the lazy
    // screencast never ticks against a closed page.
    if let Some(cid) = ask_concierge_session_id {
        crate::local::ai::live_preview::set_page(&format!("concierge-{cid}"), None).await;
    }

    let _ = context.close().await;
    result
}

/// Assemble a reusable `workflows` row from an AI session's captured replay steps and link it back to
/// the session (`ai_sessions.workflow_id`). Called after a SUCCESSFUL finish when the session opted
/// in. Returns `(workflow_id, workflow_name)`.
///
/// The workflow is a genuinely runnable click-by-click replay: `steps` are the executor's step JSON
/// (leading `navigate` + the fills/clicks the loop performed), with secret field values already
/// stored as `{{data_key}}` placeholders by [`crate::local::ai::session::action_to_step`] (never raw
/// secrets). Typed `ai_generated`; `entry_url` = the leading `navigate` URL.
async fn build_and_link_workflow(
    pool: &sqlx::sqlite::SqlitePool,
    session_id: i64,
    goal: &str,
    steps: &[Value],
) -> LocalResult<(i64, String)> {
    use crate::local::store::workflows;

    // Name: prefer the session row's CLEAN display name (the caller's mission name — e.g. the
    // concierge names its build after the mission), falling back to "AI: <goal truncated>". A goal
    // makes an ugly workflow name ("AI: Sign in to … using the provided API key, naviga…").
    let row_name = ai_sessions::get_by_id(pool, session_id)
        .await
        .ok()
        .flatten()
        .and_then(|r| r.name)
        .map(|n| n.trim().to_string())
        .filter(|n| !n.is_empty());
    let goal_trim = goal.trim();
    let name = match row_name {
        Some(n) => n,
        None => {
            let short: String = goal_trim.chars().take(60).collect();
            if short.is_empty() {
                "AI session".to_string()
            } else if goal_trim.chars().count() > 60 {
                format!("AI: {short}…")
            } else {
                format!("AI: {short}")
            }
        }
    };

    // Entry URL = the first `navigate` step's url (the page the session started from).
    let entry_url = steps
        .iter()
        .find(|s| s.get("type").and_then(|t| t.as_str()) == Some("navigate"))
        .and_then(|s| s.pointer("/config/url"))
        .and_then(|u| u.as_str())
        .map(str::to_string);

    let steps_s = serde_json::to_string(steps).unwrap_or_else(|_| "[]".into());

    let wf = workflows::insert(
        pool,
        &workflows::NewWorkflow {
            name: name.clone(),
            description: Some(format!("Recorded from an autonomous AI session (goal: {goal_trim})")),
            workflow_type: Some("ai_generated".into()),
            steps: Some(steps_s),
            entry_url,
            ..Default::default()
        },
    )
    .await?;

    // Link the session → the new workflow (best-effort; a deleted session is a benign race).
    let _ = ai_sessions::set_workflow_id(pool, session_id, wf.id).await;
    tracing::info!(ai_session_id = session_id, workflow_id = wf.id, "recorded a workflow from the AI session");
    Ok((wf.id, name))
}

/// Fire all enabled automations for an ai-session lifecycle `event` (`ai_session_started` /
/// `ai_session_completed`) whose root event watches this workflow (or any). Detached + best-effort —
/// a load error or a single automation failure is logged, never propagated. Workflow-sourced so any
/// `workflow` action it runs is one-hop-bounded, and only automations with a real block tree run.
fn fire_ai_session_event(
    db: &sqlx::SqlitePool,
    engine: &Arc<dyn crate::local::engine::LocalEngine>,
    event: &'static str,
    workflow_id: Option<i64>,
    context: Value,
) {
    let db = db.clone();
    let engine = engine.clone();
    tokio::spawn(async move {
        let autos =
            match crate::local::store::automations::list_enabled_for_event(&db, event, 256).await {
                Ok(v) => v,
                Err(e) => {
                    tracing::warn!(event, error = %e, "could not load ai-session-event automations");
                    return;
                }
            };
        for auto in autos {
            // Watch scope: a linked `workflow_id` only fires for THAT workflow's session; an unset
            // `workflow_id` watches any ai session. When the session has no workflow (standalone),
            // only unset-workflow automations fire.
            if let Some(wid) = auto.workflow_id {
                if Some(wid) != workflow_id {
                    continue;
                }
            }
            if !crate::local::flow::has_executable_tree(auto.blocks.as_deref()) {
                continue;
            }
            let trigger = crate::local::flow::FlowTrigger {
                event: event.to_string(),
                change_id: None,
                base_inputs: json!({}),
                context: context.clone(),
                source: crate::local::engine::RunSource::Workflow,
                lane: crate::local::engine::Lane::Background,
            };
            if let Err(e) = crate::local::flow::run_automation(&db, &engine, &auto, trigger).await {
                tracing::warn!(automation_id = auto.id, event, error = %e, "ai-session-event automation failed");
            }
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn pool() -> sqlx::sqlite::SqlitePool {
        let dir = Box::leak(Box::new(tempfile::tempdir().unwrap()));
        crate::local::db::open(&dir.path().join("t.db"), "test-key-ai-run-shared").await.unwrap()
    }

    /// `generate_workflow = true` with captured steps: `build_and_link_workflow` inserts a runnable
    /// `workflows` row (leading navigate + a fill; secret templatized), links it back, and returns
    /// the new id + name. Exercises the capture→assemble→persist→link path without a browser.
    #[tokio::test]
    async fn build_and_link_records_and_returns_id_and_name() {
        use crate::local::store::workflows;
        let pool = pool().await;

        let s = ai_sessions::insert(
            &pool,
            &NewAiSession { goal: "sign up for an account on example.com".into(), ..Default::default() },
        )
        .await
        .unwrap();
        assert_eq!(s.generate_workflow, 1);

        let steps = vec![
            json!({ "type": "navigate", "enabled": true, "config": { "url": "https://example.com/signup" } }),
            json!({ "type": "fill", "enabled": true, "config": { "selector": "#password", "value": "{{password}}" } }),
            json!({ "type": "click", "enabled": true, "config": { "selector": "#submit" } }),
        ];

        let (wf_id, wf_name) = build_and_link_workflow(&pool, s.id, &s.goal, &steps).await.unwrap();
        assert!(wf_name.starts_with("AI: "), "name derives from the goal, got {wf_name:?}");

        let wf = workflows::get_by_id(&pool, wf_id).await.unwrap().unwrap();
        assert_eq!(wf.workflow_type, "ai_generated");
        assert_eq!(wf.entry_url.as_deref(), Some("https://example.com/signup"));
        // Secret stays a placeholder (never baked in).
        assert!(!wf.steps.contains("hunter"), "no raw secret in the saved steps");

        // The session is linked to the new workflow.
        assert_eq!(
            ai_sessions::get_by_id(&pool, s.id).await.unwrap().unwrap().workflow_id,
            Some(wf_id),
            "ai_sessions.workflow_id points at the recorded workflow"
        );
    }

    /// A LONG goal is truncated (with an ellipsis) into the "AI: …" name (both the returned name and
    /// the persisted row).
    #[tokio::test]
    async fn long_goal_is_truncated_in_the_workflow_name() {
        let pool = pool().await;
        let long = "a".repeat(200);
        let s = ai_sessions::insert(&pool, &NewAiSession { goal: long.clone(), ..Default::default() })
            .await
            .unwrap();
        let steps = vec![json!({ "type": "navigate", "enabled": true, "config": { "url": "https://x.test/" } })];
        let (wf_id, wf_name) = build_and_link_workflow(&pool, s.id, &s.goal, &steps).await.unwrap();
        assert!(wf_name.starts_with("AI: "));
        assert!(wf_name.ends_with('…'), "long goal ellipsized: {wf_name:?}");
        assert!(wf_name.chars().count() <= 4 + 60 + 1, "name bounded");
        let wf = crate::local::store::workflows::get_by_id(&pool, wf_id).await.unwrap().unwrap();
        assert_eq!(wf.name, wf_name, "returned name matches the persisted row");
    }
}
