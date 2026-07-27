//! Autonomous AI form-filler SESSION loop — the Rust port of the Python recorder's
//! `ai_generate_workflow` (`recorder.py` ~L6699-7011). A server-side, headless-capable loop that
//! drives a live page toward a `goal`: observe → ask the vision model → resolve its `mappings`
//! into concrete actions → execute them → settle → repeat, with stuck detection and a step cap.
//!
//! This is the SIMPLER form-filler brain (`{status, mappings, submit_button}`), NOT the agent
//! brain in [`super::brain`]. It reuses:
//! * [`super::observation::build_ai_observation`] for the per-turn observation,
//! * [`super::autonomous_prompts::build_form_filler_prompt`] for the directive prompt,
//! * [`super::provider::complete`] for the vision completion,
//! * [`super::brain::parse_decision`] for lenient JSON parsing,
//! * [`super::action_executor::execute_ai_action`] for each resolved action.

use std::collections::HashMap;
use std::time::Duration;

use playwright_rs::Page;
use serde_json::{json, Value};

use super::action_executor::{self, execute_ai_action};
use super::autonomous_prompts::build_form_filler_prompt;
use super::live_preview::PreviewSender;
use super::observation::{build_ai_observation, capture_screenshot_b64};
use super::provider::{self, AiConfig};
use crate::dom::analyzer::PageEvaluator;
use crate::local::error::LocalResult;
use crate::local::store::ai_preview_steps;
use crate::models::ai::{AiContentPart, AiMessage, AiMessageContent, ImageSource};
use base64::Engine as _;

/// Configuration for one autonomous session run.
#[derive(Debug, Clone)]
pub struct SessionConfig {
    /// What to accomplish (e.g. "complete the registration form").
    pub goal: String,
    /// Data keys/values shown to the model (secret values replaced with placeholders).
    pub available_data: HashMap<String, String>,
    /// Actual values to fill (includes decrypted secrets). Falls back to `available_data`.
    pub fill_data: HashMap<String, String>,
    /// Maximum page iterations before the loop gives up.
    pub max_steps: u32,
    /// How a `{{key}}` placeholder must be SPELLED in a recorded step so it resolves at REPLAY
    /// (explorer only). A vault-backed credential maps to its `{{secret:VAULT_KEY}}` ref (resolved
    /// by the engine from the local vault); a plaintext answer maps to its literal. Keys with no
    /// entry keep the raw `{{key}}` placeholder (never a baked secret).
    pub record_templates: HashMap<String, String>,
    /// The owning CONCIERGE session id (explorer only). When set, an ask-the-user pause PARKS the
    /// session in place — browser open, page warm — waiting on [`super::ask_gate`] for `/respond`
    /// to hand the answer over, and only falls back to ending the run (Blocked) on timeout/cancel.
    pub ask_session_id: Option<i64>,
}

impl SessionConfig {
    pub fn new(goal: impl Into<String>) -> Self {
        Self {
            goal: goal.into(),
            available_data: HashMap::new(),
            fill_data: HashMap::new(),
            max_steps: 20,
            record_templates: HashMap::new(),
            ask_session_id: None,
        }
    }
}

/// Terminal status of a session run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SessionStatus {
    /// The model reported completion (or a success page was detected).
    Complete,
    /// The model reported a blocker, or a captcha stopped the run.
    Blocked,
    /// The loop hit `max_steps` without completing.
    MaxSteps,
    /// The loop detected it was stuck (repeated identical URLs, no progress).
    Stuck,
    /// A hard error (e.g. the AI provider failed).
    Error,
    /// The caller aborted the session (cooperative cancel flag flipped).
    Cancelled,
}

impl SessionStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            SessionStatus::Complete => "complete",
            SessionStatus::Blocked => "blocked",
            SessionStatus::MaxSteps => "max_steps",
            SessionStatus::Stuck => "stuck",
            SessionStatus::Error => "error",
            SessionStatus::Cancelled => "cancelled",
        }
    }
}

/// Result of a session run.
#[derive(Debug, Clone)]
pub struct SessionResult {
    pub status: SessionStatus,
    /// Number of page iterations executed.
    pub steps: u32,
    /// Human-readable summary/message.
    pub message: String,
    /// Error string when `status == Error`/`Blocked`, else `None`.
    pub error: Option<String>,
    /// Structured result payload (final url, filled keys, last observation summary).
    pub result: Value,
    /// The concrete actions the loop executed, shaped as replayable WORKFLOW STEPS
    /// (`{ "type", "enabled": true, "config": { .. } }`) — the executor's step JSON (see
    /// `automation::step_executor`). The caller (start handler) assembles + persists these into a
    /// reusable `workflows` row on a successful finish when `generate_workflow` is on. Always leads
    /// with a `navigate` to the entry URL. Secret field values are templatized as `{{data_key}}`
    /// placeholders (never baked-in), matching the recorder convention (`value_resolver`).
    pub recorded_steps: Vec<Value>,
    /// CONCIERGE mode only: the ORCHESTRATION setup intents the brain emitted IN-LOOP via a `setup`
    /// array (create_monitor / wire_automation / expose_api), each grounded with the live URL it was
    /// emitted on. The concierge materializes these into real monitor/automation/connect rows after the
    /// run. Empty for a normal (non-concierge) AI session.
    pub orchestration_intents: Vec<Value>,
}

/// Live + persisted reporting sink for the "watch the AI" preview. When a session runs with one, each
/// loop step (a) broadcasts a `thought` event to any live spectators via `sender`, and (b) persists a
/// disk-cheap replay keyframe (`kind`/`ref_id` → `ai_preview_steps`). `None` (automation AI steps)
/// disables both. The continuous screencast is a SEPARATE task the caller spawns; this sink only adds
/// the per-step thinking + keyframe.
pub struct StepSink<'a> {
    pub sender: &'a PreviewSender,
    /// Optional SECOND channel the step events are mirrored to — the owning
    /// concierge mission's `concierge-{id}` channel, so the panel's embedded
    /// narration rail streams the same real-time steps the `ai-{id}`
    /// spectators get. `None` for a standalone AI session.
    pub mirror: Option<PreviewSender>,
    /// `"ai"` for an AI session, `"concierge"` for a concierge browse.
    pub kind: &'a str,
    /// The owning session id (`ai_sessions.id` / `concierge_sessions.id`).
    pub ref_id: i64,
}

/// Report one step to the live preview + the replay store (best-effort; never fails the loop).
/// Broadcasts the thinking event immediately, then persists a downscaled + deduped keyframe (a
/// byte-identical frame is stored as `NULL` so the FE reuses the previous one) and trims the replay
/// to its cap. `screenshot_b64` is the frame the model saw this step (may be empty).
#[allow(clippy::too_many_arguments)]
pub(super) async fn report_step(
    sink: Option<&StepSink<'_>>,
    pool: &sqlx::sqlite::SqlitePool,
    last_kf_hash: &mut u64,
    step: i64,
    thought: &str,
    action: &str,
    url: &str,
    status: &str,
    screenshot_b64: &str,
) {
    let Some(sink) = sink else {
        return;
    };
    sink.sender.send_thought(step, thought, action, url, status);
    if let Some(m) = &sink.mirror {
        m.send_thought(step, thought, action, url, status);
    }

    // Downscale + dedup the keyframe for disk-cheap replay. An empty/identical frame stores NULL.
    let screenshot: Option<Vec<u8>> = if screenshot_b64.is_empty() {
        None
    } else {
        match base64::engine::general_purpose::STANDARD.decode(screenshot_b64) {
            Ok(raw) => {
                let small = super::live_preview::downscale_jpeg(
                    &raw,
                    ai_preview_steps::KEYFRAME_MAX_EDGE,
                    ai_preview_steps::KEYFRAME_QUALITY,
                );
                let h = crate::browser::screenshot::ScreencastStream::frame_hash(&small);
                if h == *last_kf_hash {
                    None
                } else {
                    *last_kf_hash = h;
                    Some(small)
                }
            }
            Err(_) => None,
        }
    };

    let _ = ai_preview_steps::insert(
        pool,
        &ai_preview_steps::NewStep {
            kind: sink.kind.to_string(),
            ref_id: sink.ref_id,
            step_num: step,
            thought: (!thought.is_empty()).then(|| thought.to_string()),
            action: (!action.is_empty()).then(|| action.to_string()),
            url: (!url.is_empty()).then(|| url.to_string()),
            status: Some(status.to_string()),
            screenshot,
        },
    )
    .await;
    let _ = ai_preview_steps::trim(pool, sink.kind, sink.ref_id, ai_preview_steps::MAX_STEPS).await;
}

/// The model's short natural-language reason for this step, for the "thinking" panel. Form-filler
/// decisions carry it under `reasoning`/`thought`/`message`; falls back to empty.
fn decision_thought(decision: &Value) -> String {
    for key in ["reasoning", "thought", "message"] {
        if let Some(s) = decision.get(key).and_then(|v| v.as_str()) {
            let s = s.trim();
            if !s.is_empty() {
                return s.chars().take(600).collect();
            }
        }
    }
    String::new()
}

/// A short human summary of the resolved `actions` this step (e.g. "Fill Email; Fill Password;
/// Click Sign up"), for the replay timeline. Empty → "Observing".
fn action_summary(actions: &[Value]) -> String {
    let parts: Vec<String> = actions
        .iter()
        .filter_map(|a| a.get("label").and_then(|l| l.as_str()).map(str::to_string))
        .filter(|s| !s.trim().is_empty())
        .collect();
    if parts.is_empty() {
        "Observing".to_string()
    } else {
        parts.join("; ").chars().take(200).collect()
    }
}

/// A [`PageEvaluator`] over a live page — passed to [`build_ai_observation`] for parity with the
/// DOM-analyzer probe API.
struct LoopEvaluator<'a>(&'a Page);

impl<'a> PageEvaluator for LoopEvaluator<'a> {
    fn evaluate_json(
        &self,
        js: &str,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = anyhow::Result<Value>> + Send + '_>>
    {
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
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = anyhow::Result<Value>> + Send + '_>>
    {
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

/// Resolve the model's `mappings` (+ optional `submit_button`) into concrete, executable actions,
/// using the observation's field/button coordinates. 1:1 port of the Python `mappings → actions`
/// conversion in `_ai_analyze_page`. Skips already-filled data keys and already-clicked indices.
fn resolve_actions(
    decision: &Value,
    fields: &[Value],
    buttons: &[Value],
    captcha_info: &Value,
    filled_fields: &[String],
    clicked_indices: &[usize],
) -> Vec<Value> {
    let mut actions: Vec<Value> = Vec::new();

    let mappings = decision
        .get("mappings")
        .and_then(|v| v.as_array())
        .cloned()
        .unwrap_or_default();

    for mapping in &mappings {
        let action_type = mapping
            .get("action")
            .and_then(|v| v.as_str())
            .unwrap_or("type_text");
        let field_index = mapping
            .get("field_index")
            .and_then(|v| v.as_u64())
            .map(|v| v as usize);
        let data_key = mapping
            .get("data_key")
            .and_then(|v| v.as_str())
            .map(String::from);

        // Captcha step (no field_index) — pull position from the mapping or the detected captcha.
        if action_type == "solve_captcha" {
            actions.push(json!({
                "type": "solve_captcha",
                "captcha_type": mapping.get("captcha_type").and_then(|v| v.as_str())
                    .or_else(|| captcha_info.get("type").and_then(|v| v.as_str()))
                    .unwrap_or("unknown"),
                "x": mapping.get("x").cloned().or_else(|| captcha_info.get("x").cloned()).unwrap_or(json!(0)),
                "y": mapping.get("y").cloned().or_else(|| captcha_info.get("y").cloned()).unwrap_or(json!(0)),
                "selector": mapping.get("selector").cloned().or_else(|| captcha_info.get("selector").cloned()).unwrap_or(Value::Null),
                "label": "Solve captcha",
            }));
            continue;
        }

        // Skip already-clicked field indices (click actions only).
        if action_type == "click" {
            if let Some(fi) = field_index {
                if clicked_indices.contains(&fi) {
                    continue;
                }
            }
        }
        // Skip already-filled data keys (type_text actions only).
        if action_type == "type_text" {
            if let Some(dk) = &data_key {
                if filled_fields.iter().any(|f| f == dk) {
                    continue;
                }
            }
        }

        // Resolve field_index → coordinates + identifiers from the observation.
        if let Some(fi) = field_index {
            if let Some(field) = fields
                .iter()
                .find(|f| f.get("index").and_then(|i| i.as_u64()) == Some(fi as u64))
            {
                let mut act = json!({
                    "type": action_type,
                    "x": field.get("x"),
                    "y": field.get("y"),
                    "label": field.get("label"),
                    "field_id": field.get("id"),
                    "field_name": field.get("name"),
                    "field_type": field.get("type"),
                    "field_index": fi,
                    "selector": field.get("selector"),
                });
                if let Some(dk) = &data_key {
                    act["data_key"] = json!(dk);
                }
                actions.push(act);
            }
        }
    }

    // Auto-add a captcha step if one was detected but the model omitted it.
    let has_captcha = actions
        .iter()
        .any(|a| a.get("type").and_then(|t| t.as_str()) == Some("solve_captcha"));
    if !captcha_info.is_null() && !has_captcha {
        actions.push(json!({
            "type": "solve_captcha",
            "captcha_type": captcha_info.get("type").and_then(|v| v.as_str()).unwrap_or("unknown"),
            "x": captcha_info.get("x").cloned().unwrap_or(json!(0)),
            "y": captcha_info.get("y").cloned().unwrap_or(json!(0)),
            "selector": captcha_info.get("selector").cloned().unwrap_or(Value::Null),
            "label": "Solve captcha",
        }));
    }

    // Resolve submit_button text → the matching detected button's coordinates/selector.
    if let Some(submit_text) = decision
        .get("submit_button")
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty())
    {
        let needle = submit_text.to_lowercase();
        if let Some(btn) = buttons.iter().find(|b| {
            b.get("text")
                .and_then(|t| t.as_str())
                .map(|t| t.to_lowercase().contains(&needle))
                .unwrap_or(false)
        }) {
            actions.push(json!({
                "type": "click",
                "x": btn.get("x"),
                "y": btn.get("y"),
                "label": format!("Click {}", btn.get("text").and_then(|t| t.as_str()).unwrap_or("")),
                "selector": btn.get("selector"),
                "is_submit": true,
            }));
        }
    }

    actions
}

/// Convert one SUCCESSFULLY-executed resolved action into a replayable WORKFLOW STEP
/// (`{ "type", "enabled": true, "config": { .. } }`) — the executor's step JSON shape (see
/// `automation::step_executor` / `concierge::validate_planner_steps`). Returns `None` for actions that
/// have no durable replay form (a resolved `solve_captcha` cannot be re-run headlessly; a selector-less
/// coordinate-only action can't be replayed reliably by a fresh run).
///
/// SECRETS: a `type_text`/`select` value is stored as the TEMPLATE `{{data_key}}`, never the raw
/// decrypted value — the recorder convention (`value_resolver::resolve_value` re-resolves `{{key}}`
/// from the run's form_data/credentials at replay). When no `data_key` is present (a literal AI value),
/// the concrete `value` is stored as-is (it was not a secret).
pub(crate) fn action_to_step(action: &Value) -> Option<Value> {
    let atype = action
        .get("type")
        .or_else(|| action.get("action"))
        .and_then(|v| v.as_str())
        .unwrap_or("");
    // A selector is required for a replayable field/click step. Prefer the explicit selector, else
    // synthesize from id/name (mirrors `action_executor::action_selector`).
    let selector = action
        .get("selector")
        .and_then(|v| v.as_str())
        .filter(|s| !s.trim().is_empty())
        .map(str::to_string)
        .or_else(|| {
            action
                .get("field_id")
                .and_then(|v| v.as_str())
                .filter(|s| !s.trim().is_empty())
                .map(|id| format!("#{id}"))
        })
        .or_else(|| {
            action
                .get("field_name")
                .and_then(|v| v.as_str())
                .filter(|s| !s.trim().is_empty())
                .map(|n| format!("[name=\"{n}\"]"))
        });

    match atype {
        // Text entry → a `fill` step (the executor's canonical text-entry step).
        "type_text" | "type" | "fill" | "select" => {
            let selector = selector?;
            let step_type = if atype == "select" { "select" } else { "fill" };
            // Template the value from the data_key (secret-safe), else pass through the literal value.
            let value = match action
                .get("data_key")
                .and_then(|v| v.as_str())
                .filter(|s| !s.is_empty())
            {
                Some(dk) => format!("{{{{{dk}}}}}"),
                None => action
                    .get("value")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string(),
            };
            Some(json!({
                "type": step_type,
                "enabled": true,
                "config": { "selector": selector, "value": value },
            }))
        }
        // Click / checkbox / radio / submit → a `click` step. Needs a selector to be replayable.
        "click" | "submit" | "check" => {
            let selector = selector?;
            Some(json!({
                "type": if atype == "check" { "check" } else { "click" },
                "enabled": true,
                "config": { "selector": selector },
            }))
        }
        // Coordinate/viewport scroll → a `scroll` step (no selector needed).
        "scroll" => {
            let direction = action
                .get("direction")
                .and_then(|v| v.as_str())
                .unwrap_or("down");
            let amount = action
                .get("amount")
                .and_then(|v| v.as_f64())
                .unwrap_or(600.0);
            Some(json!({
                "type": "scroll",
                "enabled": true,
                "config": { "direction": direction, "amount": amount },
            }))
        }
        "navigate" => Some(json!({
            "type": "navigate", "enabled": true,
            "config": { "url": action.get("url")?.as_str()? },
        })),
        "press_key" | "press" => Some(json!({
            "type": "press", "enabled": true,
            "config": {
                "selector": selector,
                "key": action.get("key").and_then(|v| v.as_str()).unwrap_or("Enter"),
            },
        })),
        "wait" => Some(json!({
            "type": "wait", "enabled": true,
            "config": { "duration": action.get("seconds").and_then(|v| v.as_f64()).unwrap_or(1.0) * 1000.0 },
        })),
        "evaluate_js" => Some(json!({
            "type": "evaluate", "enabled": true,
            "config": {
                "script": action.get("script")?.as_str()?,
                "variable": action.get("variable").and_then(|v| v.as_str()).unwrap_or("result"),
            },
        })),
        // solve_captcha / press / read_text / unknown → no durable replay step.
        _ => None,
    }
}

/// Whether an action's label marks it as a submit/send button (mirrors the Python submit check).
fn is_submit_action(action: &Value) -> bool {
    if action
        .get("is_submit")
        .and_then(|v| v.as_bool())
        .unwrap_or(false)
    {
        return true;
    }
    let label = action
        .get("label")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_lowercase();
    label.contains("submit") || label.contains("envoyer") || label.contains("soumettre")
}

/// Best-effort wait for the page to settle (`networkidle`, ≤5s). Never fails the loop.
async fn settle(page: &Page) {
    tokio::time::sleep(Duration::from_millis(500)).await;
    let _ = crate::browser::navigation::wait_for_load_state(
        page,
        "networkidle",
        Duration::from_secs(5),
    )
    .await;
}

/// Run the autonomous form-filler session loop against `page`.
///
/// Loops up to `cfg.max_steps` times: detect stuck state (3 identical URLs in a row → stop),
/// build the observation, ask the vision model, branch on the returned `status`
/// (`continue`/`complete`/`blocked`), resolve `mappings` into actions, execute each, track filled
/// data keys + clicked field indices, and wait for the page to settle.
pub async fn run_session(
    page: &Page,
    _evaluator: &dyn PageEvaluator,
    cfg: &SessionConfig,
    ai_cfg: &AiConfig,
    // Pool for the cloud-gateway routing decision. When the "use cloud AI gateway" toggle is on, the
    // vision completions run through the managed gateway instead of the local `ai_cfg`.
    pool: &sqlx::sqlite::SqlitePool,
    // Optional cooperative-cancel flag. The caller (AI-session launch task) flips this from its
    // `POST /v1/ai-sessions/:id/cancel` handler; the loop checks it at the top of each iteration and
    // returns [`SessionStatus::Cancelled`]. `None` (e.g. from automation AI steps) never aborts.
    cancel: Option<&std::sync::atomic::AtomicBool>,
    // Optional "watch the AI" sink: per step, broadcast the model's thinking to live spectators and
    // persist a disk-cheap replay keyframe. `None` (automation AI steps) disables both.
    sink: Option<&StepSink<'_>>,
) -> LocalResult<SessionResult> {
    let fill_data: HashMap<String, String> = if cfg.fill_data.is_empty() {
        cfg.available_data.clone()
    } else {
        cfg.fill_data.clone()
    };

    let max_steps = cfg.max_steps.max(1);
    let mut step_count: u32 = 0;
    let mut last_url: Option<String> = None;
    let mut stuck_count: u32 = 0;
    let mut filled_fields: Vec<String> = Vec::new();
    let mut clicked_field_indices: Vec<usize> = Vec::new();
    let mut submit_clicked = false;
    // Capture buffer: the concrete, replayable WORKFLOW STEPS the loop executes. The caller assembles
    // these into a reusable `workflows` row on a successful finish (when `generate_workflow` is on). It
    // leads with a `navigate` to the entry page (the URL the caller already navigated to before this
    // loop) so a fresh run starts from the same place; per-action steps are appended below.
    //
    // FIDELITY NOTE: the CLOUD reference (`ai_session_runner::_assemble_workflow`) assembles from the
    // AGENT brain's PROPOSED `steps_to_add`. This SIMPLER form-filler brain's decision schema is
    // `{status, mappings, submit_button}` — it exposes NO proposed-step list — so we reconstruct from
    // the RESOLVED actions instead. That is nearly as clean: each resolved action already carries the
    // real DOM `selector` from the observation (not a raw click coordinate), so `action_to_step`
    // yields selector-based, replayable `fill`/`click`/`select` steps with templatized values.
    let entry_url = page.url();
    let mut recorded_steps: Vec<Value> = if entry_url.is_empty() || entry_url == "about:blank" {
        Vec::new()
    } else {
        vec![json!({
            "type": "navigate",
            "enabled": true,
            "config": { "url": entry_url },
        })]
    };
    // Hash of the last PERSISTED replay keyframe — an identical frame is stored as NULL (dedup).
    let mut last_kf_hash: u64 = 0;
    // The form-filler never emits setup intents (the explorer agent owns orchestration); the field
    // stays on SessionResult for a shared return shape, always empty here.
    let mut orchestration_intents: Vec<Value> = Vec::new();

    while step_count < max_steps {
        // Cooperative abort — checked before each iteration's work (an in-flight model call or page
        // action still finishes, so abort lands within one step). Returns the progress so far.
        if cancel
            .map(|c| c.load(std::sync::atomic::Ordering::Relaxed))
            .unwrap_or(false)
        {
            tracing::info!("AI session aborted by caller");
            return Ok(SessionResult {
                status: SessionStatus::Cancelled,
                steps: step_count,
                message: "Aborted".to_string(),
                error: None,
                result: json!({ "current_url": page.url(), "filled_fields": filled_fields }),
                recorded_steps: std::mem::take(&mut recorded_steps),
                orchestration_intents: std::mem::take(&mut orchestration_intents),
            });
        }

        step_count += 1;
        let current_url = page.url();

        // Stuck detection: 3 identical URLs in a row → stop.
        if last_url.as_deref() == Some(current_url.as_str()) {
            stuck_count += 1;
            if stuck_count >= 3 {
                tracing::warn!("AI session appears stuck, stopping");
                let shot = capture_screenshot_b64(page).await;
                report_step(
                    sink,
                    pool,
                    &mut last_kf_hash,
                    step_count as i64,
                    "No progress across 3 iterations — stopping.",
                    "Stuck",
                    &current_url,
                    "stuck",
                    &shot,
                )
                .await;
                return Ok(SessionResult {
                    status: SessionStatus::Stuck,
                    steps: step_count,
                    message: "Stopped: no progress across 3 iterations".to_string(),
                    error: None,
                    result: json!({ "current_url": current_url, "filled_fields": filled_fields }),
                    recorded_steps: std::mem::take(&mut recorded_steps),
                    orchestration_intents: std::mem::take(&mut orchestration_intents),
                });
            }
        } else {
            stuck_count = 0;
            last_url = Some(current_url.clone());
        }

        // ── Observe ──
        let evaluator = LoopEvaluator(page);
        let obs = build_ai_observation(page, &evaluator).await;

        // Early completion: DOM success page detected.
        if obs
            .get("has_success")
            .and_then(|v| v.as_bool())
            .unwrap_or(false)
        {
            let shot = obs.get("screenshot").and_then(|v| v.as_str()).unwrap_or("");
            report_step(
                sink,
                pool,
                &mut last_kf_hash,
                step_count as i64,
                "A success page appeared — the goal is done.",
                "Complete",
                &page.url(),
                "complete",
                shot,
            )
            .await;
            return Ok(SessionResult {
                status: SessionStatus::Complete,
                steps: step_count,
                message: "Success page detected".to_string(),
                error: None,
                result: json!({ "current_url": page.url(), "filled_fields": filled_fields }),
                recorded_steps: std::mem::take(&mut recorded_steps),
                orchestration_intents: std::mem::take(&mut orchestration_intents),
            });
        }

        let empty_arr: Vec<Value> = Vec::new();
        let fields = obs
            .get("fields")
            .and_then(|v| v.as_array())
            .unwrap_or(&empty_arr);
        let buttons = obs
            .get("buttons")
            .and_then(|v| v.as_array())
            .unwrap_or(&empty_arr);
        let captcha_info = obs.get("captcha_info").cloned().unwrap_or(Value::Null);
        let screenshot = obs.get("screenshot").and_then(|v| v.as_str()).unwrap_or("");

        // ── Ask the vision model ──
        let prompt = build_form_filler_prompt(
            &cfg.goal,
            fields,
            buttons,
            &captcha_info,
            &cfg.available_data,
            &filled_fields,
            &clicked_field_indices,
        );

        let mut parts: Vec<AiContentPart> = Vec::new();
        if !screenshot.is_empty() {
            parts.push(AiContentPart::Image {
                source: ImageSource {
                    source_type: "base64".into(),
                    media_type: "image/jpeg".into(),
                    data: screenshot.to_string(),
                },
            });
        }
        parts.push(AiContentPart::Text { text: prompt });
        let messages = vec![AiMessage {
            role: "user".into(),
            content: AiMessageContent::Parts(parts),
        }];

        let completion =
            match provider::complete_with(pool, ai_cfg, &messages, None, 1500, "agent").await {
                Ok(c) => c,
                Err(e) => {
                    return Ok(SessionResult {
                        status: SessionStatus::Error,
                        steps: step_count,
                        message: "AI analysis failed".to_string(),
                        error: Some(e.to_string()),
                        result: json!({ "current_url": page.url() }),
                        recorded_steps: std::mem::take(&mut recorded_steps),
                        orchestration_intents: std::mem::take(&mut orchestration_intents),
                    });
                }
            };

        let decision = super::brain::parse_decision(&completion.text)
            .unwrap_or_else(|| json!({ "status": "continue", "mappings": [] }));

        let status = decision
            .get("status")
            .and_then(|v| v.as_str())
            .unwrap_or("continue");
        let thought = decision_thought(&decision);

        // ── Branch on status ──
        match status {
            "complete" => {
                let msg = decision
                    .get("message")
                    .and_then(|v| v.as_str())
                    .unwrap_or("Workflow completed")
                    .to_string();
                let t = if thought.is_empty() {
                    msg.as_str()
                } else {
                    thought.as_str()
                };
                report_step(
                    sink,
                    pool,
                    &mut last_kf_hash,
                    step_count as i64,
                    t,
                    "Marked complete",
                    &page.url(),
                    "complete",
                    screenshot,
                )
                .await;
                return Ok(SessionResult {
                    status: SessionStatus::Complete,
                    steps: step_count,
                    message: msg,
                    error: None,
                    result: json!({ "current_url": page.url(), "filled_fields": filled_fields }),
                    recorded_steps: std::mem::take(&mut recorded_steps),
                    orchestration_intents: std::mem::take(&mut orchestration_intents),
                });
            }
            "blocked" => {
                let reason = decision
                    .get("reason")
                    .or_else(|| decision.get("message"))
                    .and_then(|v| v.as_str())
                    .unwrap_or("Unknown blocker")
                    .to_string();
                let t = if thought.is_empty() {
                    reason.as_str()
                } else {
                    thought.as_str()
                };
                report_step(
                    sink,
                    pool,
                    &mut last_kf_hash,
                    step_count as i64,
                    t,
                    "Reported blocked",
                    &page.url(),
                    "blocked",
                    screenshot,
                )
                .await;
                // If the agent is blocked at a login because it needs a CREDENTIAL it wasn't given, it
                // names the field(s) it SEES (e.g. a single API key) in `credential_fields`. Carry that
                // through so the concierge asks for exactly the right input (secret → sealed to vault),
                // instead of the concierge pre-guessing username+password before it ever saw the form.
                let credential_fields = decision
                    .get("credential_fields")
                    .cloned()
                    .unwrap_or(Value::Null);
                return Ok(SessionResult {
                    status: SessionStatus::Blocked,
                    steps: step_count,
                    message: format!("Blocked: {}", reason),
                    error: Some(reason),
                    result: json!({ "current_url": page.url(), "filled_fields": filled_fields, "credential_fields": credential_fields }),
                    recorded_steps: std::mem::take(&mut recorded_steps),
                    orchestration_intents: std::mem::take(&mut orchestration_intents),
                });
            }
            _ => {}
        }

        // ── Resolve mappings → actions ──
        let actions = resolve_actions(
            &decision,
            fields,
            buttons,
            &captcha_info,
            &filled_fields,
            &clicked_field_indices,
        );

        // Report this step (thinking + the pre-action keyframe the model saw) to the live preview +
        // replay store, BEFORE executing so the frame reflects the state the decision was made on.
        report_step(
            sink,
            pool,
            &mut last_kf_hash,
            step_count as i64,
            &thought,
            &action_summary(&actions),
            &current_url,
            "running",
            screenshot,
        )
        .await;

        if actions.is_empty() {
            // No actions this turn — treat as slow progress (Python bumps stuck_count).
            stuck_count += 1;
            continue;
        }

        // ── Execute each action ──
        for action in &actions {
            let action_type = action
                .get("type")
                .and_then(|v| v.as_str())
                .unwrap_or("unknown")
                .to_string();
            let field_index = action
                .get("field_index")
                .and_then(|v| v.as_u64())
                .map(|v| v as usize);
            let data_key = action
                .get("data_key")
                .and_then(|v| v.as_str())
                .map(String::from);

            let outcome = execute_ai_action(page, action, &fill_data).await;

            // A locally-unsolvable captcha ends the run as blocked (never hangs).
            if action_executor::is_captcha_blocked(&outcome) {
                return Ok(SessionResult {
                    status: SessionStatus::Blocked,
                    steps: step_count,
                    message: outcome.message.clone(),
                    error: Some(outcome.message),
                    result: json!({ "current_url": page.url(), "filled_fields": filled_fields }),
                    recorded_steps: std::mem::take(&mut recorded_steps),
                    orchestration_intents: std::mem::take(&mut orchestration_intents),
                });
            }

            if !outcome.success {
                tracing::warn!(action_type = %action_type, message = %outcome.message, "action failed, continuing");
                // Continue trying the remaining actions (mirrors Python).
                continue;
            }

            // Capture this successfully-executed action as a replayable workflow step (secret values
            // templatized). `None` for actions with no durable replay form (captcha / selector-less).
            if let Some(step) = action_to_step(action) {
                recorded_steps.push(step);
            }

            // Track filled data keys (avoid re-filling next turn).
            if matches!(action_type.as_str(), "type_text" | "fill" | "select") {
                if let Some(dk) = &data_key {
                    if !filled_fields.contains(dk) {
                        filled_fields.push(dk.clone());
                    }
                }
            }
            // Track clicked checkbox/radio indices (avoid re-clicking).
            if action_type == "click" {
                if let Some(fi) = field_index {
                    if !clicked_field_indices.contains(&fi) {
                        clicked_field_indices.push(fi);
                    }
                }
                if is_submit_action(action) {
                    submit_clicked = true;
                }
            }
        }

        // ── Wait for the page to settle ──
        settle(page).await;

        // If the model asked to scroll (and we haven't submitted), re-observe next iteration.
        let needs_scroll = decision
            .get("needs_scroll")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        if needs_scroll && !submit_clicked {
            continue;
        }

        // After submit, give it a moment to land, then complete.
        if submit_clicked {
            tokio::time::sleep(Duration::from_secs(2)).await;
            let _ = crate::browser::navigation::wait_for_load_state(
                page,
                "networkidle",
                Duration::from_secs(5),
            )
            .await;
            let shot = capture_screenshot_b64(page).await;
            report_step(
                sink,
                pool,
                &mut last_kf_hash,
                step_count as i64,
                "Submitted the form and the page settled.",
                "Submitted the form",
                &page.url(),
                "complete",
                &shot,
            )
            .await;
            return Ok(SessionResult {
                status: SessionStatus::Complete,
                steps: step_count,
                message: "Form submitted".to_string(),
                error: None,
                result: json!({
                    "current_url": page.url(),
                    "filled_fields": filled_fields,
                    "submitted": true,
                }),
                recorded_steps: std::mem::take(&mut recorded_steps),
                orchestration_intents: std::mem::take(&mut orchestration_intents),
            });
        }
    }

    let shot = capture_screenshot_b64(page).await;
    report_step(
        sink,
        pool,
        &mut last_kf_hash,
        step_count as i64,
        "Reached the step limit without finishing.",
        "Reached max steps",
        &page.url(),
        "max_steps",
        &shot,
    )
    .await;
    Ok(SessionResult {
        status: SessionStatus::MaxSteps,
        steps: step_count,
        message: format!("Reached max steps ({})", max_steps),
        error: None,
        result: json!({ "current_url": page.url(), "filled_fields": filled_fields }),
        recorded_steps: std::mem::take(&mut recorded_steps),
        orchestration_intents: std::mem::take(&mut orchestration_intents),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A `type_text` with a `data_key` → a `fill` step whose value is the `{{data_key}}` TEMPLATE, NOT
    /// the raw (potentially secret) value — the recorder convention that keeps secrets out of the saved
    /// workflow (`value_resolver` re-resolves the placeholder at run time).
    #[test]
    fn type_text_with_data_key_templatizes_and_never_bakes_the_secret() {
        let action = json!({
            "type": "type_text",
            "selector": "#password",
            "data_key": "password",
            "value": "hunter2-super-secret",  // the decrypted value — must NOT be persisted
            "label": "Password",
        });
        let step = action_to_step(&action).expect("type_text → a step");
        assert_eq!(step["type"], "fill");
        assert_eq!(step["enabled"], true);
        assert_eq!(step["config"]["selector"], "#password");
        assert_eq!(
            step["config"]["value"], "{{password}}",
            "value is the placeholder"
        );
        // Belt-and-suspenders: the raw secret appears nowhere in the serialized step.
        assert!(
            !step.to_string().contains("hunter2"),
            "raw secret must never be baked in"
        );
    }

    /// A `type_text` with NO data_key (a literal AI-typed value, not a secret) stores the value as-is.
    #[test]
    fn type_text_without_data_key_keeps_literal_value() {
        let action = json!({ "type": "type_text", "selector": "#q", "value": "shoes" });
        let step = action_to_step(&action).unwrap();
        assert_eq!(step["type"], "fill");
        assert_eq!(step["config"]["value"], "shoes");
    }

    /// A selector is synthesized from `field_id`/`field_name` when no explicit selector is present
    /// (mirrors `action_executor::action_selector`), so a coordinate-resolved field is still replayable.
    #[test]
    fn selector_synthesized_from_id_then_name() {
        let by_id = json!({ "type": "click", "field_id": "go" });
        assert_eq!(action_to_step(&by_id).unwrap()["config"]["selector"], "#go");

        let by_name = json!({ "type": "click", "field_name": "submit" });
        assert_eq!(
            action_to_step(&by_name).unwrap()["config"]["selector"],
            "[name=\"submit\"]"
        );
    }

    /// Click / check / scroll map to their step types; a captcha or a selector-less coordinate-only
    /// action has no durable replay form → `None` (dropped from the recorded workflow).
    #[test]
    fn click_check_scroll_map_and_unreplayable_actions_drop() {
        assert_eq!(
            action_to_step(&json!({ "type": "click", "selector": "#b" })).unwrap()["type"],
            "click"
        );
        assert_eq!(
            action_to_step(&json!({ "type": "check", "selector": "#c" })).unwrap()["type"],
            "check"
        );

        let scroll =
            action_to_step(&json!({ "type": "scroll", "direction": "down", "amount": 500.0 }))
                .unwrap();
        assert_eq!(scroll["type"], "scroll");
        assert_eq!(scroll["config"]["amount"], 500.0);

        // No selector and no id/name → not replayable.
        assert!(action_to_step(&json!({ "type": "click", "x": 10, "y": 20 })).is_none());
        // Captcha → never a replay step.
        assert!(action_to_step(&json!({ "type": "solve_captcha", "x": 1, "y": 2 })).is_none());
    }

    /// A `select` step carries both its selector and the templatized value.
    #[test]
    fn select_maps_with_templatized_value() {
        let action = json!({ "type": "select", "selector": "#country", "data_key": "country" });
        let step = action_to_step(&action).unwrap();
        assert_eq!(step["type"], "select");
        assert_eq!(step["config"]["selector"], "#country");
        assert_eq!(step["config"]["value"], "{{country}}");
    }
}
