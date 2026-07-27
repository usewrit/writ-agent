//! `/v1/ai-assist/*` — the local port of the cloud AI-assist surface the recorder calls.
//!
//!   POST /v1/ai-assist/agent             — the unified mode-aware agent loop (manual/api/streaming)
//!   POST /v1/ai-assist/chat              — conversational help during recording
//!   POST /v1/ai-assist/generate-extract  — one-shot extraction-script generation
//!   POST /v1/ai-assist/optimize-workflow — prune + API-substitute a recorded workflow
//!   POST /v1/ai-assist/build-scraper     — the agentic scraper-builder loop
//!   POST /v1/ai-assist/find-selectors    — find CSS selectors for a monitor goal
//!   POST /v1/ai-assist/detect-segments   — CODE-ONLY auth/nav/extract segmentation (no AI)
//!
//! Every AI call runs through the local multi-provider gateway ([`crate::local::ai::provider`]) on
//! the user's own keys — nothing leaves the machine. Behavior matches the cloud brain (verbatim
//! prompts in [`crate::local::ai::prompts`]). `credits_used` is always 0 locally.

use crate::local::ai::{brain, prompts, provider};
use crate::local::error::{LocalError, LocalResult};
use crate::local::server::AppState;
use crate::models::ai::{AiContentPart, AiMessage, AiMessageContent, ImageSource};
use axum::extract::State;
use axum::routing::post;
use axum::{Json, Router};
use serde_json::{json, Value};

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/v1/ai-assist/agent", post(agent))
        .route("/v1/ai-assist/chat", post(chat))
        .route("/v1/ai-assist/generate-extract", post(generate_extract))
        .route("/v1/ai-assist/optimize-workflow", post(optimize_workflow))
        .route("/v1/ai-assist/optimize-workflow-live", post(optimize_workflow_live))
        .route("/v1/ai-assist/build-scraper", post(build_scraper))
        .route("/v1/ai-assist/generate-streaming-script", post(generate_streaming_script))
        .route("/v1/ai-assist/find-selectors", post(find_selectors))
        .route("/v1/ai-assist/detect-segments", post(detect_segments))
        .route("/v1/ai-assist/generate-automation", post(generate_automation))
}

// ── helpers ─────────────────────────────────────────────────────────────────

/// Resolve the configured provider, or a clean 400 that the recorder surfaces verbatim (instead of
/// the old 404 — "no such endpoint").
fn s(body: &Value, key: &str) -> String {
    body.get(key).and_then(|v| v.as_str()).unwrap_or("").to_string()
}
fn opt_s(body: &Value, key: &str) -> Option<String> {
    body.get(key).and_then(|v| v.as_str()).filter(|s| !s.is_empty()).map(|s| s.to_string())
}
fn arr(body: &Value, key: &str) -> Value {
    body.get(key).cloned().unwrap_or_else(|| json!([]))
}
fn cap(s: &str, n: usize) -> String {
    if s.chars().count() > n { s.chars().take(n).collect() } else { s.to_string() }
}
fn json_bounded(v: &Value, n: usize) -> String {
    cap(&serde_json::to_string(v).unwrap_or_default(), n)
}

/// One `user` turn: optional screenshot first, then the text block.
fn user_msg(text: String, screenshot_b64: Option<&str>) -> AiMessage {
    let mut parts: Vec<AiContentPart> = Vec::new();
    if let Some(b64) = screenshot_b64.filter(|s| !s.is_empty()) {
        parts.push(AiContentPart::Image {
            source: ImageSource {
                source_type: "base64".into(),
                media_type: "image/jpeg".into(),
                data: b64.to_string(),
            },
        });
    }
    parts.push(AiContentPart::Text { text });
    AiMessage { role: "user".into(), content: AiMessageContent::Parts(parts) }
}

/// Ensure the AI's spec object carries every AutomationSpec field the frontend expects.
fn normalize_spec(parsed: Option<Value>) -> Value {
    let mut spec = parsed.filter(Value::is_object).unwrap_or_else(|| json!({}));
    let obj = spec.as_object_mut().expect("object");
    obj.entry("name").or_insert(json!(""));
    obj.entry("description").or_insert(json!(""));
    obj.entry("blocks").or_insert(json!([]));
    obj.entry("rationale").or_insert(json!(""));
    obj.entry("block_notes").or_insert(json!({}));
    obj.entry("unresolved").or_insert(json!([]));
    obj.entry("new_resources").or_insert(json!([]));
    obj.entry("requires_cloud").or_insert(json!(false));
    spec
}

fn spec_message(spec: &Value) -> String {
    spec.get("rationale")
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty())
        .unwrap_or("Generated automation")
        .to_string()
}

// ── /generate-automation ──────────────────────────────────────────────────────
// Turn a goal into a full AutomationSpec (block tree). LOCAL-FIRST on the user's own
// provider; when no provider is configured, fall back to the CLOUD endpoint if linked
// ("local with cloud fallback"). The block vocabulary + the user's resources are supplied
// by the client (catalog_digest + tenant_context) — one source of truth.
async fn generate_automation(State(st): State<AppState>, Json(body): Json<Value>) -> LocalResult<Json<Value>> {
    let goal = s(&body, "goal");
    let url = opt_s(&body, "url");
    let catalog = s(&body, "catalog_digest");
    let resources = body.get("tenant_context").cloned().unwrap_or_else(|| json!({}));
    // When the client sends the existing automation, EXTEND it (return only new blocks
    // parented onto it) rather than build from scratch.
    let current_section = match body.get("current_automation") {
        Some(ca) if ca.get("blocks").and_then(|b| b.as_array()).is_some_and(|b| !b.is_empty()) => {
            format!("\nCURRENT AUTOMATION (extend this, do not rebuild):\n{}", json_bounded(ca, 12000))
        }
        _ => String::new(),
    };
    let system = prompts::GENERATE_AUTOMATION_SYSTEM
        .replace("{catalog}", if catalog.trim().is_empty() { "(none provided)" } else { &catalog })
        .replace("{resources}", &json_bounded(&resources, 12000))
        .replace("{current_automation}", &current_section);

    let mut user_text = format!("GOAL: {goal}");
    if let Some(u) = url.as_ref() {
        user_text.push_str(&format!("\n\nSTARTING URL: {u}"));
    }
    let messages = vec![user_msg(user_text, None)];

    // Cloud AI gateway on → run the completion through the managed gateway (billed to the wallet)
    // but still assemble/normalize the automation spec locally, exactly like the local-provider path.
    if provider::cloud_gateway_enabled(&st.db).await {
        let max_tokens = provider::resolve_max_tokens(&st.db, "agent", 2500).await;
        let completion = provider::complete_routed(&st.db, &st.vault, &messages, Some(&system), max_tokens, "agent").await?;
        let spec = normalize_spec(brain::parse_decision(&completion.text));
        let message = spec_message(&spec);
        return Ok(Json(json!({ "automation": spec, "message": message, "source": "cloud", "credits_used": 0 })));
    }

    match provider::resolve_config(&st.db, &st.vault).await? {
        Some(cfg) if !cfg.provider.trim().is_empty() => {
            let max_tokens = provider::resolve_max_tokens(&st.db, "agent", 2500).await;
            let completion = provider::complete(&cfg, &messages, Some(&system), max_tokens).await?;
            let spec = normalize_spec(brain::parse_decision(&completion.text));
            let message = spec_message(&spec);
            Ok(Json(json!({ "automation": spec, "message": message, "source": "local", "credits_used": 0 })))
        }
        _ => {
            // No local provider — reflect to the cloud when the app is linked. In the cloud-free OSS
            // build there is no cloud fallback, so a missing provider fails closed with the same guidance.
            #[cfg(feature = "cloud")]
            {
                let link = crate::local::cloud::state::LinkState::load_or_default(&st.db).await?;
                match crate::local::cloud::client::CloudClient::connect(Some(&link)) {
                    Ok(mut cc) => {
                        let resp: Value = cc.post_json("/api/ai-assist/generate-automation", &body).await?;
                        Ok(Json(resp))
                    }
                    Err(_) => Err(LocalError::BadRequest(
                        "No AI provider configured. Open Settings → AI and choose a provider + API key, or link your cloud account.".into(),
                    )),
                }
            }
            #[cfg(not(feature = "cloud"))]
            {
                Err(LocalError::BadRequest(
                    "No AI provider configured. Open Settings → AI and choose a provider + API key.".into(),
                ))
            }
        }
    }
}

// ── /agent ──────────────────────────────────────────────────────────────────

async fn agent(State(st): State<AppState>, Json(body): Json<Value>) -> LocalResult<Json<Value>> {
    let inp = brain::AgentInput {
        instruction: s(&body, "instruction"),
        mode: body.get("mode").and_then(|v| v.as_str()).unwrap_or("manual").to_string(),
        conversation: body.get("conversation").and_then(|v| v.as_array()).cloned().unwrap_or_default(),
        page_url: s(&body, "page_url"),
        screenshot_b64: opt_s(&body, "screenshot_b64"),
        observation: body.get("observation").cloned(),
        steps: arr(&body, "steps"),
        network_calls: arr(&body, "network_calls"),
        history: arr(&body, "history"),
        iteration: body.get("iteration").and_then(|v| v.as_i64()).unwrap_or(0),
        max_iterations: body.get("max_iterations").and_then(|v| v.as_i64()).unwrap_or(12),
        autonomous: body.get("autonomous").and_then(|v| v.as_bool()).unwrap_or(false),
        advanced_script: s(&body, "advanced_script"),
    };
    let system = brain::build_system_prompt(&inp.mode, inp.autonomous);
    let messages = brain::build_user_message(&inp);
    let max_tokens = provider::resolve_max_tokens(&st.db, "agent", 3000).await;
    let completion = provider::complete_routed(&st.db, &st.vault, &messages, Some(&system), max_tokens, "agent").await?;
    let mut decision = match brain::parse_decision(&completion.text) {
        Some(v) => brain::coerce_decision(&v),
        None => brain::retry_decision(
            "Your previous reply was not valid JSON. Reply with ONLY the JSON object — no markdown.",
        ),
    };
    decision["credits_used"] = json!(0);
    Ok(Json(decision))
}

// ── /chat ───────────────────────────────────────────────────────────────────

async fn chat(State(st): State<AppState>, Json(body): Json<Value>) -> LocalResult<Json<Value>> {
    let instruction = s(&body, "instruction");
    let url = s(&body, "page_url");
    // The recorder sends context="streaming_script" when the chat is authoring a streaming
    // handler (AIScriptAssistant) vs the default "recording" assistant — pick the right prompt.
    let context = s(&body, "context");
    let steps = arr(&body, "steps");
    let network = arr(&body, "network_calls");
    let page_dom = opt_s(&body, "page_dom");

    let mut text = format!("Current URL: {url}\n\nUSER: {instruction}");
    if steps.as_array().map(|a| !a.is_empty()).unwrap_or(false) {
        text.push_str(&format!("\n\nSTEPS RECORDED SO FAR:\n{}", json_bounded(&steps, 6000)));
    }
    if network.as_array().map(|a| !a.is_empty()).unwrap_or(false) {
        text.push_str(&format!("\n\nCAPTURED API CALLS:\n{}", json_bounded(&network, 4000)));
    }
    if let Some(dom) = page_dom {
        text.push_str(&format!("\n\nPAGE DOM:\n{}", cap(&dom, 16000)));
    }
    // Editing an existing streaming script → show it so the model returns a full,
    // correct rewrite (it replaces the current one) rather than regenerating blind.
    if context == "streaming_script" {
        let advanced_script = s(&body, "advanced_script");
        if !advanced_script.trim().is_empty() {
            text.push_str(&format!("\n\nCURRENT SCRIPT:\n{}", cap(&advanced_script, 40000)));
        }
    }

    // Replay the last 10 conversation turns, then the new user turn (with screenshot).
    let mut messages: Vec<AiMessage> = Vec::new();
    if let Some(conv) = body.get("conversation").and_then(|v| v.as_array()) {
        let start = conv.len().saturating_sub(10);
        for m in &conv[start..] {
            let role = m.get("role").and_then(|r| r.as_str()).unwrap_or("user");
            let content = m.get("content").and_then(|c| c.as_str()).unwrap_or("");
            if (role == "user" || role == "assistant") && !content.is_empty() {
                messages.push(AiMessage {
                    role: role.to_string(),
                    content: AiMessageContent::Text(content.to_string()),
                });
            }
        }
    }
    messages.push(user_msg(text, opt_s(&body, "screenshot_b64").as_deref()));

    let system = if context == "streaming_script" {
        prompts::CHAT_STREAMING_SYSTEM
    } else {
        prompts::CHAT_RECORDING_SYSTEM
    };
    let max_tokens = provider::resolve_max_tokens(&st.db, "assist", 1500).await;
    let completion = provider::complete_routed(&st.db, &st.vault, &messages, Some(system), max_tokens, "assist").await?;
    let (message, actions) = match brain::parse_decision(&completion.text) {
        Some(v) => (
            v.get("message").and_then(|m| m.as_str()).unwrap_or(&completion.text).to_string(),
            v.get("actions").cloned().unwrap_or_else(|| json!([])),
        ),
        None => (completion.text.clone(), json!([])),
    };
    Ok(Json(json!({ "message": message, "actions": actions, "credits_used": 0 })))
}

// ── /generate-extract ───────────────────────────────────────────────────────

async fn generate_extract(State(st): State<AppState>, Json(body): Json<Value>) -> LocalResult<Json<Value>> {
    let url = s(&body, "page_url");
    let goal = s(&body, "goal");
    let steps = arr(&body, "steps");
    let mut text = format!("URL: {url}\n\nGOAL: {goal}");
    if steps.as_array().map(|a| !a.is_empty()).unwrap_or(false) {
        text.push_str(&format!("\n\nSTEPS SO FAR:\n{}", json_bounded(&steps, 4000)));
    }
    if let Some(html) = opt_s(&body, "page_html") {
        text.push_str(&format!("\n\nPAGE HTML (truncated):\n{}", cap(&html, 40000)));
    }
    let messages = vec![user_msg(text, opt_s(&body, "screenshot_b64").as_deref())];
    let max_tokens = provider::resolve_max_tokens(&st.db, "assist", 2000).await;
    let completion = provider::complete_routed(&st.db, &st.vault, &messages, Some(prompts::EXTRACT_SYSTEM), max_tokens, "assist").await?;

    let parsed = brain::parse_decision(&completion.text).unwrap_or_else(|| json!({}));
    let script = brain::sanitize_js_script(parsed.get("script").and_then(|s| s.as_str()).unwrap_or(""));
    let message = parsed.get("message").and_then(|m| m.as_str()).unwrap_or("Generated extraction script").to_string();
    // The generated payload is ALWAYS a JS script, so it must be an "evaluate"
    // (extract-js) step — the "extract" step type cannot run a script (it only
    // reads one element's text by selector), so a script on it is ignored and
    // replay fails ("extract: no selector provided").
    let step = json!({
        "type": "evaluate",
        "description": message,
        "config": { "variable": "extracted_data", "script": script },
    });
    Ok(Json(json!({ "steps": [step], "message": message, "credits_used": 0 })))
}

// ── /optimize-workflow ──────────────────────────────────────────────────────

async fn optimize_workflow(State(st): State<AppState>, Json(body): Json<Value>) -> LocalResult<Json<Value>> {
    let steps = arr(&body, "steps");
    let network = arr(&body, "network_calls");
    let form_data = body.get("form_data").cloned().unwrap_or_else(|| json!({}));
    let credential_keys = arr(&body, "credential_keys");
    let url = s(&body, "page_url");

    let text = format!(
        "WORKFLOW STEPS:\n{}\n\nCAPTURED NETWORK:\n{}\n\nFORM DATA KEYS: {}\nCREDENTIAL KEYS: {}\nFINAL URL: {}",
        json_bounded(&steps, 30000),
        json_bounded(&network, 12000),
        json_bounded(&form_data, 2000),
        json_bounded(&credential_keys, 1000),
        url,
    );
    let messages = vec![user_msg(text, opt_s(&body, "screenshot_b64").as_deref())];
    let max_tokens = provider::resolve_max_tokens(&st.db, "optimize", 6000).await;
    let completion = provider::complete_routed(&st.db, &st.vault, &messages, Some(prompts::OPTIMIZE_SYSTEM), max_tokens, "optimize").await?;

    // Graceful: on any parse miss, return the original workflow unchanged.
    match brain::parse_decision(&completion.text) {
        Some(v) if v.get("steps").map(|s| s.is_array()).unwrap_or(false) => Ok(Json(json!({
            "steps": v.get("steps").cloned().unwrap_or(steps),
            "removed_count": v.get("removed_count").and_then(|n| n.as_i64()).unwrap_or(0),
            "changes": v.get("changes").cloned().unwrap_or_else(|| json!([])),
            "warnings": v.get("warnings").cloned().unwrap_or_else(|| json!([])),
            "credits_used": 0,
        }))),
        _ => Ok(Json(json!({
            "steps": steps,
            "removed_count": 0,
            "changes": [],
            "warnings": ["AI optimization could not be parsed; workflow left unchanged."],
            "credits_used": 0,
        }))),
    }
}

// ── /optimize-workflow-live ─────────────────────────────────────────────────
// Replays the saved workflow in a real browser with network capture on, then proposes + LIVE-VERIFIES
// DOM→api_call/login_post substitutions. Same response shape as /optimize-workflow (so the FE confirm
// UI is unchanged) plus `requires_confirm` (side-effect gate) and `verified`. Returns the diff only;
// the FE Applies via PATCH /workflows/:id.

async fn optimize_workflow_live(State(st): State<AppState>, Json(body): Json<Value>) -> LocalResult<Json<Value>> {
    let workflow_id = body
        .get("workflow_id")
        .and_then(|v| v.as_i64())
        .ok_or_else(|| crate::local::error::LocalError::BadRequest("workflow_id is required".into()))?;
    let confirm = body.get("confirm_side_effects").and_then(|v| v.as_bool()).unwrap_or(false);
    let out = crate::local::ai::optimize_live::optimize_workflow_live(&st, workflow_id, confirm).await?;
    Ok(Json(out))
}

// ── /build-scraper ──────────────────────────────────────────────────────────

async fn build_scraper(State(st): State<AppState>, Json(body): Json<Value>) -> LocalResult<Json<Value>> {
    let goal = s(&body, "goal");
    let url = s(&body, "page_url");
    let iteration = body.get("iteration").and_then(|v| v.as_i64()).unwrap_or(0);
    let max_iterations = body.get("max_iterations").and_then(|v| v.as_i64()).unwrap_or(14);
    let observation = body.get("observation").cloned().unwrap_or(Value::Null);
    let history = arr(&body, "history");
    let network = arr(&body, "network_calls");

    let wrap = if iteration >= max_iterations - 3 { " — wrap up and finalize if you can." } else { "" };
    let obs = if observation.is_null() {
        "  (none yet)".to_string()
    } else {
        json_bounded(&observation, 8000)
    };
    let text = format!(
        "GOAL: {goal}\n\nCurrent URL: {url}\nIteration: {} of {max_iterations}{wrap}\n\nPAGE OBSERVATION:\n{obs}\n\nHISTORY:\n{}\n\nCAPTURED API CALLS:\n{}",
        iteration + 1,
        json_bounded(&history, 12000),
        json_bounded(&network, 8000),
    );
    let messages = vec![user_msg(text, opt_s(&body, "screenshot_b64").as_deref())];
    let max_tokens = provider::resolve_max_tokens(&st.db, "agent", 3000).await;
    let completion = provider::complete_routed(&st.db, &st.vault, &messages, Some(prompts::BUILD_SCRAPER_SYSTEM), max_tokens, "agent").await?;

    let parsed = brain::parse_decision(&completion.text).unwrap_or_else(|| json!({}));
    let decision = brain::coerce_decision(&parsed);
    // build-scraper only emits run_actions | done.
    let action = match decision.get("action").and_then(|a| a.as_str()) {
        Some("done") => "done",
        _ if decision.get("script").and_then(|s| s.as_str()).map(|s| !s.is_empty()).unwrap_or(false) => "done",
        _ => "run_actions",
    };
    let variable = {
        let v = decision.get("variable").and_then(|v| v.as_str()).unwrap_or("");
        if v.is_empty() { "items".to_string() } else { v.to_string() }
    };
    Ok(Json(json!({
        "thought": decision.get("thought").cloned().unwrap_or_else(|| json!("")),
        "action": action,
        "actions": decision.get("actions").cloned().unwrap_or_else(|| json!([])),
        "script": decision.get("script").cloned().unwrap_or_else(|| json!("")),
        "variable": variable,
        "iframe": decision.get("iframe").cloned().unwrap_or(Value::Null),
        "summary": decision.get("summary").cloned().unwrap_or_else(|| json!("")),
        "credits_used": 0,
    })))
}

// ── /generate-streaming-script ──────────────────────────────────────────────

async fn generate_streaming_script(State(st): State<AppState>, Json(body): Json<Value>) -> LocalResult<Json<Value>> {
    let url = s(&body, "page_url");
    let goal = s(&body, "goal");
    let existing = arr(&body, "existing_handlers");
    let network = arr(&body, "network_calls");
    let mut text = format!("URL: {url}\n\nGOAL: {goal}");
    if existing.as_array().map(|a| !a.is_empty()).unwrap_or(false) {
        text.push_str(&format!("\n\nEXISTING HANDLERS: {}", json_bounded(&existing, 1000)));
    }
    if let Some(dom) = opt_s(&body, "page_dom") {
        text.push_str(&format!("\n\nPAGE DOM:\n{}", cap(&dom, 16000)));
    }
    if network.as_array().map(|a| !a.is_empty()).unwrap_or(false) {
        text.push_str(&format!("\n\nCAPTURED API CALLS:\n{}", json_bounded(&network, 4000)));
    }
    let messages = vec![user_msg(text, opt_s(&body, "screenshot_b64").as_deref())];
    let max_tokens = provider::resolve_max_tokens(&st.db, "agent", 3000).await;
    let completion = provider::complete_routed(&st.db, &st.vault, &messages, Some(prompts::STREAMING_SCRIPT_SYSTEM), max_tokens, "agent").await?;

    let parsed = brain::parse_decision(&completion.text).unwrap_or_else(|| json!({}));
    let script = brain::sanitize_js_script(parsed.get("script").and_then(|s| s.as_str()).unwrap_or(""));
    let message = parsed.get("message").and_then(|m| m.as_str()).unwrap_or("Generated streaming handler").to_string();
    Ok(Json(json!({ "script": script, "message": message, "credits_used": 0 })))
}

// ── /find-selectors ─────────────────────────────────────────────────────────

async fn find_selectors(State(st): State<AppState>, Json(body): Json<Value>) -> LocalResult<Json<Value>> {
    let url = s(&body, "url");
    let prompt = s(&body, "prompt");
    let existing: Vec<String> = body
        .get("existing_selectors")
        .and_then(|v| v.as_array())
        .map(|a| a.iter().filter_map(|x| x.as_str().map(|s| s.to_string())).collect())
        .unwrap_or_default();

    let mut text = format!("URL: {url}\n\nThe user wants to monitor: {prompt}");
    if let Some(dom) = opt_s(&body, "page_dom") {
        // Strip DOM noise (scripts/styles/svg/base64) before it reaches the model,
        // even if the caller already cleaned it — defense in depth, and cheap.
        let dom = crate::local::ai::context_clean::clean_dom_for_ai(&dom);
        text.push_str(&format!("\n\nPAGE DOM:\n{}", cap(&dom, 24000)));
    }
    let messages = vec![user_msg(text, opt_s(&body, "screenshot_b64").as_deref())];
    let max_tokens = provider::resolve_max_tokens(&st.db, "assist", 2000).await;
    let completion = provider::complete_routed(&st.db, &st.vault, &messages, Some(prompts::FIND_SELECTORS_SYSTEM), max_tokens, "assist").await?;

    let parsed = brain::parse_decision(&completion.text).unwrap_or_else(|| json!({}));
    let selectors: Vec<Value> = parsed
        .get("selectors")
        .and_then(|v| v.as_array())
        .map(|a| {
            a.iter()
                .filter(|x| x.is_object())
                .filter(|x| {
                    let sel = x.get("selector").and_then(|s| s.as_str()).unwrap_or("");
                    !sel.is_empty() && !existing.iter().any(|e| e == sel)
                })
                .cloned()
                .collect()
        })
        .unwrap_or_default();
    Ok(Json(json!({ "selectors": selectors, "credits_used": 1 })))
}

// ── /detect-segments (CODE-ONLY, no AI) ─────────────────────────────────────

async fn detect_segments(Json(body): Json<Value>) -> LocalResult<Json<Value>> {
    let steps: Vec<Value> = body.get("steps").and_then(|v| v.as_array()).cloned().unwrap_or_default();
    Ok(Json(segment_steps(&steps)))
}

fn step_type(s: &Value) -> &str {
    s.get("type").and_then(|t| t.as_str()).unwrap_or("")
}

/// Heuristic segmentation: detect an auth prefix (login/sign-in + sensitive fills), then group the
/// extraction steps, attributing the navigation in between to each extraction group. No AI.
fn segment_steps(steps: &[Value]) -> Value {
    let extract_indices: Vec<usize> = steps
        .iter()
        .enumerate()
        .filter(|(_, s)| step_type(s) == "extract")
        .map(|(i, _)| i)
        .collect();
    let first_extract = extract_indices.first().copied().unwrap_or(steps.len());

    // ── auth detection ──
    let mut signals = 0i32;
    let mut auth_end: Option<usize> = None;
    for (i, st) in steps.iter().enumerate().take(first_extract) {
        let t = step_type(st);
        let cfg = st.get("config");
        let desc = st.get("description").and_then(|d| d.as_str()).unwrap_or("").to_lowercase();
        let sel = cfg.and_then(|c| c.get("selector")).and_then(|x| x.as_str()).unwrap_or("").to_lowercase();
        let url = cfg.and_then(|c| c.get("url")).and_then(|x| x.as_str()).unwrap_or("").to_lowercase();
        let opts = cfg.and_then(|c| c.get("options"));
        let mut hit = false;
        if t == "navigate" && ["login", "signin", "sign-in", "auth", "sso", "oauth", "account"].iter().any(|k| url.contains(k)) {
            signals += 2;
            hit = true;
        }
        let sensitive = opts
            .map(|o| {
                o.get("is_sensitive").and_then(|b| b.as_bool()).unwrap_or(false)
                    || o.get("field_type").and_then(|f| f.as_str()) == Some("password")
            })
            .unwrap_or(false);
        if sensitive {
            signals += 3;
            hit = true;
        }
        if t == "fill" && ["pass", "email", "login", "user"].iter().any(|k| sel.contains(k)) {
            signals += 2;
            hit = true;
        }
        if t == "click" && ["login", "sign in", "sign-in", "submit", "log in"].iter().any(|k| desc.contains(k) || sel.contains(k)) {
            signals += 2;
            hit = true;
        }
        if hit {
            auth_end = Some(i);
        }
    }
    let has_auth = signals >= 3;
    // Extend auth_end over trailing wait/navigated_to/navigate that settle the login.
    if let Some(mut e) = auth_end.filter(|_| has_auth) {
        while e + 1 < first_extract {
            let nt = step_type(&steps[e + 1]);
            if nt == "wait" || nt == "navigated_to" || nt == "navigate" {
                e += 1;
            } else {
                break;
            }
        }
        auth_end = Some(e);
    }

    let mut segments: Vec<Value> = Vec::new();
    if has_auth {
        let end = auth_end.unwrap_or(0);
        let indices: Vec<usize> = (0..=end).collect();
        segments.push(json!({
            "name": "login",
            "segment_type": "auth",
            "step_indices": indices,
            "depends_on": [],
            "extract_outputs": [],
        }));
    }

    // ── group consecutive extract steps ──
    let mut groups: Vec<Vec<usize>> = Vec::new();
    let mut cur: Vec<usize> = Vec::new();
    for &i in &extract_indices {
        if cur.last().map(|&l| i == l + 1).unwrap_or(true) {
            cur.push(i);
        } else {
            groups.push(std::mem::take(&mut cur));
            cur.push(i);
        }
    }
    if !cur.is_empty() {
        groups.push(cur);
    }

    let mut boundary = if has_auth { auth_end.unwrap_or(0) + 1 } else { 0 };
    for g in groups {
        let start = *g.first().unwrap();
        let mut indices: Vec<usize> = (boundary..start).collect();
        indices.extend(g.iter().copied());
        let outputs: Vec<String> = g
            .iter()
            .filter_map(|&i| steps.get(i))
            .filter_map(|s| {
                s.get("config")
                    .and_then(|c| c.get("output_name").or_else(|| c.get("variable")))
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string())
            })
            .collect();
        let name = outputs.first().cloned().unwrap_or_else(|| "extraction".into());
        let depends: Vec<String> = if has_auth { vec!["login".into()] } else { vec![] };
        segments.push(json!({
            "name": name,
            "segment_type": "extraction",
            "step_indices": indices,
            "depends_on": depends,
            "extract_outputs": outputs,
        }));
        boundary = g.last().map(|&l| l + 1).unwrap_or(boundary);
    }

    json!({ "segments": segments, "has_auth": has_auth })
}
