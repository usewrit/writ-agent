//! Agent-turn brain, ported from the cloud backend's `agent_brain` service. Builds the mode-aware system
//! prompt + the user message, then parses + coerces the model's JSON decision into the stable
//! `{action, thought, message, actions, steps_to_add, script, ...}` envelope the recorder expects.

use super::prompts;
use crate::models::ai::{AiContentPart, AiMessage, AiMessageContent, ImageSource};
use serde_json::{json, Value};

/// Inputs to one agent turn (mirrors `AgentChatRequest`).
pub struct AgentInput {
    pub instruction: String,
    pub mode: String,
    pub conversation: Vec<Value>,
    pub page_url: String,
    pub screenshot_b64: Option<String>,
    pub observation: Option<Value>,
    pub steps: Value,
    pub network_calls: Value,
    pub history: Value,
    pub iteration: i64,
    pub max_iterations: i64,
    pub autonomous: bool,
    /// Streaming mode: the current advanced script, so the model can SEE and EDIT it
    /// (script_mode:"replace") instead of only appending.
    pub advanced_script: String,
}

/// `build_system_prompt`: base + mode addendum (+ autonomous addendum when no human is watching).
pub fn build_system_prompt(mode: &str, autonomous: bool) -> String {
    let addendum = match mode {
        "api" => prompts::AGENT_API,
        "streaming" => prompts::AGENT_STREAMING,
        _ => prompts::AGENT_MANUAL,
    };
    let mut s = format!("{}\n\n{}", prompts::AGENT_BASE, addendum);
    if autonomous {
        // AGENT_AUTONOMOUS already begins with its own leading newline.
        s.push_str(prompts::AGENT_AUTONOMOUS);
    }
    s
}

/// `build_user_message`: one `user` turn carrying the optional screenshot + the assembled text.
pub fn build_user_message(inp: &AgentInput) -> Vec<AiMessage> {
    let wrap = if inp.iteration >= inp.max_iterations - 3 {
        " — wrap up and finalize if you can."
    } else {
        ""
    };
    let obs = observation_text(&inp.observation);
    let obs = if obs.is_empty() {
        "  (none yet — run actions / evaluate_js to inspect the page)".to_string()
    } else {
        obs
    };
    // Streaming mode: show the current advanced script so the model can EDIT it
    // (script_mode:"replace") rather than only appending to it. The steps JSON below
    // already carries each step's `id`, which the model targets in `step_edits`.
    let script_section = if inp.advanced_script.trim().is_empty() {
        String::new()
    } else {
        format!("CURRENT ADVANCED SCRIPT:\n{}\n\n", cap(&inp.advanced_script, 12000))
    };
    let user_text = format!(
        "USER REQUEST: {instruction}\n\n\
         CONVERSATION SO FAR:\n{conversation}\n\n\
         Current URL: {url}\n\
         Iteration: {iter} of {maxi}{wrap}\n\n\
         STEPS RECORDED SO FAR:\n{steps}\n\n\
         {script_section}\
         PAGE OBSERVATION:\n{obs}\n\n\
         ACTIONS RUN THIS TASK:\n{history}\n\n\
         CAPTURED API CALLS:\n{network}\n\n\
         Decide the next step now and reply with the JSON object.",
        instruction = inp.instruction,
        conversation = conversation_text(&inp.conversation),
        url = inp.page_url,
        iter = inp.iteration + 1,
        maxi = inp.max_iterations,
        wrap = wrap,
        steps = bounded_json(&inp.steps, 12000, "  (none yet)"),
        script_section = script_section,
        obs = obs,
        history = bounded_json(&inp.history, 12000, "  (none yet)"),
        network = bounded_json(&inp.network_calls, 8000, "  (none captured)"),
    );

    let mut parts: Vec<AiContentPart> = Vec::new();
    if let Some(b64) = inp.screenshot_b64.as_deref().filter(|s| !s.is_empty()) {
        parts.push(AiContentPart::Image {
            source: ImageSource {
                source_type: "base64".into(),
                media_type: "image/jpeg".into(),
                data: b64.to_string(),
            },
        });
    }
    parts.push(AiContentPart::Text { text: user_text });
    vec![AiMessage {
        role: "user".into(),
        content: AiMessageContent::Parts(parts),
    }]
}

// ── Parse + coerce ──────────────────────────────────────────────────────────

/// `loads_lenient`: reuse the crate's tolerant parser (handles code fences + brace bounds + repairs).
pub fn parse_decision(text: &str) -> Option<Value> {
    crate::ai::json_parser::parse_ai_json(text)
}

/// `coerce_decision`: infer a missing `action`, clamp the arrays, sanitize embedded JS, and normalize
/// every field into the stable response envelope.
pub fn coerce_decision(parsed: &Value) -> Value {
    let action = match parsed.get("action").and_then(|a| a.as_str()) {
        Some(a @ ("ask" | "run_actions" | "done" | "twofa")) => a.to_string(),
        _ => {
            if nonempty_array(parsed.get("steps_to_add"))
                || nonempty_str(parsed.get("script"))
                || nonempty_array(parsed.get("step_edits"))
            {
                "done".into()
            } else if nonempty_array(parsed.get("actions")) {
                "run_actions".into()
            } else {
                "ask".into()
            }
        }
    };

    let actions = clamp_actions(parsed.get("actions"), 25);
    let steps_to_add = clamp_steps(parsed.get("steps_to_add"), 20);
    let step_edits = clamp_step_edits(parsed.get("step_edits"));
    // ALLOWLIST — not an `unwrap_or`. This value comes from the model's JSON, and only these two
    // modes are meaningful downstream; anything else (a hallucinated mode, or arbitrary text) must
    // collapse to the safe default rather than flow through. `clippy::manual_unwrap_or` suggests
    // `.unwrap_or("append")` here, which silently DROPS the allowlist — do not apply it.
    #[allow(clippy::manual_unwrap_or)]
    let script_mode = match parsed.get("script_mode").and_then(|m| m.as_str()) {
        Some(m @ ("append" | "replace")) => m,
        _ => "append",
    };

    json!({
        "action": action,
        "thought": truncate(parsed.get("thought"), 2000),
        "message": truncate(parsed.get("message"), 4000),
        "actions": actions,
        "steps_to_add": steps_to_add,
        "step_edits": step_edits,
        "script": sanitize_js_script(&str_of(parsed.get("script"))),
        "script_mode": script_mode,
        "handler_name": truncate(parsed.get("handler_name"), 80),
        "variable": truncate(parsed.get("variable"), 60),
        "iframe": parsed.get("iframe").cloned().unwrap_or(Value::Null),
        "summary": truncate(parsed.get("summary"), 600),
        "selector": truncate(parsed.get("selector"), 400),
        "submit_selector": truncate(parsed.get("submit_selector"), 400),
    })
}

/// The standard "retry" envelope — the loop re-sends this error so the model self-corrects.
pub fn retry_decision(message: &str) -> Value {
    json!({
        "action": "retry",
        "thought": "",
        "message": message,
        "actions": [],
        "steps_to_add": [],
        "step_edits": [],
        "script": "",
        "script_mode": "append",
        "handler_name": "",
        "variable": "",
        "iframe": Value::Null,
        "summary": "",
        "selector": "",
        "submit_selector": "",
    })
}

// ── Helpers ─────────────────────────────────────────────────────────────────

fn observation_text(obs: &Option<Value>) -> String {
    match obs {
        Some(o) if !o.is_null() => {
            let s = serde_json::to_string(o).unwrap_or_default();
            cap(&s, 8000)
        }
        _ => String::new(),
    }
}

fn conversation_text(conv: &[Value]) -> String {
    if conv.is_empty() {
        return "(start of conversation)".into();
    }
    conv.iter()
        .map(|m| {
            let role = m.get("role").and_then(|r| r.as_str()).unwrap_or("user");
            let content = m.get("content").and_then(|c| c.as_str()).unwrap_or("");
            format!("  {role}: {content}")
        })
        .collect::<Vec<_>>()
        .join("\n")
}

fn bounded_json(v: &Value, max_chars: usize, empty: &str) -> String {
    let is_empty = v.is_null()
        || v.as_array().map(|a| a.is_empty()).unwrap_or(false)
        || v.as_object().map(|o| o.is_empty()).unwrap_or(false);
    if is_empty {
        return empty.to_string();
    }
    cap(&serde_json::to_string(v).unwrap_or_default(), max_chars)
}

fn cap(s: &str, max_chars: usize) -> String {
    if s.chars().count() > max_chars {
        s.chars().take(max_chars).collect()
    } else {
        s.to_string()
    }
}

fn nonempty_array(v: Option<&Value>) -> bool {
    v.and_then(|x| x.as_array()).map(|a| !a.is_empty()).unwrap_or(false)
}

fn nonempty_str(v: Option<&Value>) -> bool {
    v.and_then(|x| x.as_str()).map(|s| !s.is_empty()).unwrap_or(false)
}

fn str_of(v: Option<&Value>) -> String {
    match v {
        Some(Value::String(s)) => s.clone(),
        Some(Value::Null) | None => String::new(),
        Some(other) => other.to_string(),
    }
}

fn truncate(v: Option<&Value>, max: usize) -> String {
    cap(&str_of(v), max)
}

/// Clamp `actions` to the first `max` object entries, sanitizing `script`/`value` on `evaluate_js`.
fn clamp_actions(v: Option<&Value>, max: usize) -> Value {
    let arr = v.and_then(|x| x.as_array());
    let out: Vec<Value> = arr
        .map(|a| {
            a.iter()
                .filter(|x| x.is_object())
                .take(max)
                .map(|x| {
                    let mut o = x.clone();
                    if o.get("action").and_then(|a| a.as_str()) == Some("evaluate_js") {
                        if let Some(s) = o.get("script").and_then(|s| s.as_str()) {
                            o["script"] = json!(sanitize_js_script(s));
                        }
                        if let Some(s) = o.get("value").and_then(|s| s.as_str()) {
                            o["value"] = json!(sanitize_js_script(s));
                        }
                    }
                    o
                })
                .collect()
        })
        .unwrap_or_default();
    Value::Array(out)
}

/// Clamp `steps_to_add` to the first `max` object entries, sanitizing `config.script` (+ computed
/// `config.value`).
fn clamp_steps(v: Option<&Value>, max: usize) -> Value {
    let arr = v.and_then(|x| x.as_array());
    let out: Vec<Value> = arr
        .map(|a| {
            a.iter()
                .filter(|x| x.is_object())
                .take(max)
                .map(|x| {
                    let mut o = x.clone();
                    if let Some(cfg) = o.get_mut("config").and_then(|c| c.as_object_mut()) {
                        if let Some(s) = cfg.get("script").and_then(|s| s.as_str()) {
                            cfg.insert("script".into(), json!(sanitize_js_script(s)));
                        }
                        let computed = cfg.get("extract_type").and_then(|t| t.as_str()) == Some("computed");
                        if computed {
                            if let Some(s) = cfg.get("value").and_then(|s| s.as_str()) {
                                cfg.insert("value".into(), json!(sanitize_js_script(s)));
                            }
                        }
                    }
                    o
                })
                .collect()
        })
        .unwrap_or_default();
    Value::Array(out)
}

/// Keep only well-formed edit ops (update/delete/move) that target a step by id or index,
/// sanitizing any JS embedded in an `update`'s step config. Caps at 40 ops.
fn clamp_step_edits(v: Option<&Value>) -> Value {
    let arr = v.and_then(|x| x.as_array());
    let out: Vec<Value> = arr
        .map(|a| {
            a.iter()
                .filter(|x| x.is_object())
                .filter_map(|x| {
                    let op = x.get("op").and_then(|o| o.as_str())?;
                    if !matches!(op, "update" | "delete" | "move") {
                        return None;
                    }
                    let mut edit = serde_json::Map::new();
                    edit.insert("op".into(), json!(op));
                    if x.get("id").map(|i| !i.is_null()).unwrap_or(false) {
                        edit.insert("id".into(), json!(truncate(x.get("id"), 200)));
                    }
                    if let Some(idx) = x.get("index").and_then(|i| i.as_i64()) {
                        edit.insert("index".into(), json!(idx));
                    }
                    if op == "update" {
                        let st = x.get("step")?;
                        if !st.is_object() {
                            return None;
                        }
                        let mut st = st.clone();
                        if let Some(cfg) = st.get_mut("config").and_then(|c| c.as_object_mut()) {
                            if let Some(sc) = cfg.get("script").and_then(|s| s.as_str()) {
                                cfg.insert("script".into(), json!(sanitize_js_script(sc)));
                            }
                        }
                        edit.insert("step".into(), st);
                    }
                    if op == "move" {
                        let to = x.get("to").and_then(|t| t.as_i64())?;
                        edit.insert("to".into(), json!(to));
                    }
                    // Must reference a target step.
                    if !edit.contains_key("id") && !edit.contains_key("index") {
                        return None;
                    }
                    Some(Value::Object(edit))
                })
                .take(40)
                .collect()
        })
        .unwrap_or_default();
    Value::Array(out)
}

/// `sanitize_js_script`: re-escape raw control chars that appear INSIDE `'`/`"` string literals (a
/// JSON round-trip can collapse them into real line breaks that throw at replay). Template literals
/// (backticks) legally allow real newlines and are left alone.
pub fn sanitize_js_script(s: &str) -> String {
    if s.is_empty() {
        return String::new();
    }
    let mut out = String::with_capacity(s.len() + 8);
    let mut delim: Option<char> = None;
    let mut escaped = false;
    for c in s.chars() {
        match delim {
            Some(d) => {
                if escaped {
                    out.push(c);
                    escaped = false;
                    continue;
                }
                if c == '\\' {
                    out.push(c);
                    escaped = true;
                    continue;
                }
                if c == d {
                    delim = None;
                    out.push(c);
                    continue;
                }
                if d != '`' {
                    match c {
                        '\n' => {
                            out.push_str("\\n");
                            continue;
                        }
                        '\r' => {
                            out.push_str("\\r");
                            continue;
                        }
                        '\t' => {
                            out.push_str("\\t");
                            continue;
                        }
                        _ => {}
                    }
                }
                out.push(c);
            }
            None => {
                if c == '\'' || c == '"' || c == '`' {
                    delim = Some(c);
                }
                out.push(c);
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn coerce_passes_step_edits_and_script_mode() {
        let parsed = json!({
            "action": "done",
            "summary": "edit + replace",
            "step_edits": [
                {"op": "update", "id": "s1", "step": {"config": {"selector": "#a"}}},
                {"op": "delete", "index": 3},
                {"op": "move", "id": "s2", "to": 0},
                {"op": "bogus", "id": "x"},          // dropped: unknown op
                {"op": "delete"},                     // dropped: no target
                {"op": "update", "id": "s3"}          // dropped: no step
            ],
            "script": "ps.fn('x', async()=>{})",
            "script_mode": "replace"
        });
        let d = coerce_decision(&parsed);
        assert_eq!(d["action"], "done");
        assert_eq!(d["script_mode"], "replace");
        let edits = d["step_edits"].as_array().unwrap();
        assert_eq!(edits.len(), 3, "only the 3 well-formed ops survive");
        assert_eq!(edits[0]["op"], "update");
        assert_eq!(edits[0]["id"], "s1");
        assert_eq!(edits[1]["op"], "delete");
        assert_eq!(edits[1]["index"], 3);
        assert_eq!(edits[2]["op"], "move");
        assert_eq!(edits[2]["to"], 0);
    }

    #[test]
    fn script_mode_defaults_to_append_and_infers_done_from_edits() {
        // No explicit action, only step_edits → inferred "done"; bad script_mode → "append".
        let parsed = json!({ "step_edits": [{"op": "delete", "id": "s1"}], "script_mode": "weird" });
        let d = coerce_decision(&parsed);
        assert_eq!(d["action"], "done");
        assert_eq!(d["script_mode"], "append");
        assert_eq!(d["step_edits"].as_array().unwrap().len(), 1);
    }
}
