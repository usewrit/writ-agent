use std::collections::HashMap;

use playwright_rs::Page;

use crate::browser::{page_actions, page_query};
use crate::models::ai::ActionVerification;

use super::verification;

/// JavaScript included at compile time for DOM field extraction.
pub const DOM_FIELDS_WITH_COORDS_JS: &str = include_str!("../../js/dom_fields_with_coords.js");
/// Accessibility-style element tree WITH coordinates → {viewport, elements:[{role,name,tag,x,y,w,h,cx,cy,selector}]}.
/// Mirrors the Python recorder `_build_a11y_tree` so the agent brain receives the
/// same `a11y` observation key on both runtimes.
pub const A11Y_TREE_JS: &str = include_str!("../../js/a11y_tree.js");

/// Execute a single AI-decided action on the live browser page and verify it.
pub async fn execute_and_verify_action(
    page: &Page,
    action: &serde_json::Value,
    fill_data: &HashMap<String, String>,
    dom_state: &serde_json::Value,
) -> ActionExecutionResult {
    let action_type = action
        .get("action")
        .and_then(|v| v.as_str())
        .unwrap_or("unknown");

    tracing::debug!(action_type = action_type, "Executing and verifying action");

    // Batch action: execute sub-actions sequentially, stop on first failure.
    // 1:1 port of Python intelligent-mode batch handling (recorder.py lines 5510-5553).
    if action_type == "batch" {
        let sub_actions = action
            .get("actions")
            .and_then(|v| v.as_array())
            .cloned()
            .unwrap_or_default();

        let mut last_verification = ActionVerification {
            verified: true,
            expected: None,
            actual: None,
            message: Some("Empty batch".to_string()),
        };
        let mut all_ok = true;
        let mut endpoint = None;

        for sub in &sub_actions {
            let sub_result = Box::pin(execute_and_verify_action(page, sub, fill_data, dom_state)).await;
            last_verification = sub_result.verification.clone();
            if sub_result.endpoint.is_some() {
                endpoint = sub_result.endpoint.clone();
            }
            if !sub_result.success {
                all_ok = false;
                break;
            }
            // Small delay between sub-actions (Python line 5552)
            tokio::time::sleep(std::time::Duration::from_millis(150)).await;
        }

        return ActionExecutionResult {
            success: all_ok,
            action_type: "batch".to_string(),
            verification: last_verification,
            step_recorded: false,
            investigation_only: false,
            endpoint,
            error: if all_ok { None } else { Some("Batch sub-action failed".to_string()) },
            // Batch sub-action steps are collected by the caller (intelligent_mode loop),
            // which dispatches each sub-action through this fn individually.
            step: None,
        };
    }

    let result = match action_type {
        "fill" | "type_text" => execute_fill(page, action, fill_data, dom_state).await,
        "select" => execute_select(page, action, fill_data, dom_state).await,
        "check" => execute_check(page, action, dom_state).await,
        "click" => execute_click(page, action, dom_state).await,
        "submit" => execute_submit(page, action, dom_state).await,
        "scroll" => execute_scroll(page, action).await,
        "scroll_to_field" => execute_scroll_to_field(page, action).await,
        "hover" => execute_hover(page, action, dom_state).await,
        "press_key" => execute_press_key(page, action).await,
        "evaluate_js" => execute_evaluate_js(page, action).await,
        "wait" => execute_wait(action).await,
        "wait_for" => execute_wait_for(page, action).await,
        "inspect_field" => execute_inspect_field(page, action).await,
        "read_text" => execute_read_text(page, action).await,
        "extract_data" => execute_extract_data(page, action).await,
        "wait_for_change" => execute_wait_for_change(page, action).await,
        "list_tabs" => execute_list_tabs(page).await,
        "switch_tab" => execute_switch_tab(page, action).await,
        "wait_for_tab" => execute_wait_for_tab(page, action).await,
        "close_tab" => execute_close_tab(page).await,
        "solve_captcha" => execute_solve_captcha(page).await,
        "retry" => execute_click(page, action, dom_state).await,
        _ => {
            tracing::warn!(action_type, "Unknown action type in executor");
            Ok(ActionStepOutcome {
                verification: ActionVerification {
                    verified: true,
                    expected: None,
                    actual: None,
                    message: Some("Unknown action passed through".to_string()),
                },
                endpoint: None,
            })
        }
    };

    match result {
        Ok(outcome) => {
            let verified = outcome.verification.verified;
            // Python records a RecordedStep only on the success path of each handler.
            let step = if verified {
                build_recorded_step(action_type, action, dom_state, fill_data, &page.url())
            } else {
                None
            };
            ActionExecutionResult {
                success: verified,
                action_type: action_type.to_string(),
                verification: outcome.verification,
                step_recorded: step.is_some(),
                investigation_only: matches!(
                    action_type,
                    "inspect_field" | "read_text" | "hover" | "list_tabs" | "extract_data" | "wait_for_change"
                ),
                endpoint: outcome.endpoint,
                error: None,
                step,
            }
        }
        Err(e) => {
            let err_msg = e.to_string();
            tracing::warn!(action_type, error = %err_msg, "Action execution failed");
            ActionExecutionResult {
                success: false,
                action_type: action_type.to_string(),
                verification: ActionVerification {
                    verified: false,
                    expected: None,
                    actual: None,
                    message: Some(err_msg.clone()),
                },
                step_recorded: false,
                investigation_only: false,
                endpoint: None,
                error: Some(err_msg),
                step: None,
            }
        }
    }
}

pub struct ActionExecutionResult {
    pub success: bool,
    pub action_type: String,
    pub verification: ActionVerification,
    pub step_recorded: bool,
    pub investigation_only: bool,
    pub endpoint: Option<serde_json::Value>,
    pub error: Option<String>,
    /// The full replayable RecordedStep JSON this action produced (Python asdict shape),
    /// or None for pure-investigation/no-step actions. The intelligent loop collects these
    /// as the saved workflow steps — 1:1 with Python's session.steps.
    pub step: Option<serde_json::Value>,
}

struct ActionStepOutcome {
    verification: ActionVerification,
    endpoint: Option<serde_json::Value>,
}

// ---------------------------------------------------------------------------
// Helper: resolve a field selector from the DOM state by field_index
// ---------------------------------------------------------------------------

fn resolve_selector(dom_state: &serde_json::Value, field_index: Option<usize>) -> Option<String> {
    let idx = field_index?;
    let fields = dom_state.get("fields").and_then(|f| f.as_array())?;
    let field = fields.iter().find(|f| {
        f.get("index").and_then(|i| i.as_u64()) == Some(idx as u64)
    })?;
    // Prefer selector, then build from id/name
    if let Some(sel) = field.get("selector").and_then(|s| s.as_str()) {
        if !sel.is_empty() {
            return Some(sel.to_string());
        }
    }
    if let Some(id) = field.get("id").and_then(|s| s.as_str()) {
        if !id.is_empty() {
            return Some(format!("#{}", id));
        }
    }
    if let Some(name) = field.get("name").and_then(|s| s.as_str()) {
        if !name.is_empty() {
            return Some(format!("[name=\"{}\"]", name));
        }
    }
    None
}

fn resolve_button_selector(dom_state: &serde_json::Value, button_index: Option<usize>) -> Option<String> {
    let idx = button_index?;
    let buttons = dom_state.get("buttons").and_then(|b| b.as_array())?;
    let button = buttons.get(idx)?;
    if let Some(sel) = button.get("selector").and_then(|s| s.as_str()) {
        if !sel.is_empty() {
            return Some(sel.to_string());
        }
    }
    if let Some(id) = button.get("id").and_then(|s| s.as_str()) {
        if !id.is_empty() {
            return Some(format!("#{}", id));
        }
    }
    None
}

fn resolve_field_coords(dom_state: &serde_json::Value, field_index: usize) -> Option<(f64, f64)> {
    let fields = dom_state.get("fields").and_then(|f| f.as_array())?;
    let field = fields.iter().find(|f| {
        f.get("index").and_then(|i| i.as_u64()) == Some(field_index as u64)
    })?;
    let x = field.get("x").and_then(|v| v.as_f64())?;
    let y = field.get("y").and_then(|v| v.as_f64())?;
    Some((x, y))
}

fn resolve_button_coords(dom_state: &serde_json::Value, button_index: usize) -> Option<(f64, f64)> {
    let buttons = dom_state.get("buttons").and_then(|b| b.as_array())?;
    let button = buttons.get(button_index)?;
    let x = button.get("x").and_then(|v| v.as_f64())?;
    let y = button.get("y").and_then(|v| v.as_f64())?;
    Some((x, y))
}

/// Resolve the actual value to fill -- from fill_data by data_key, or the literal value.
fn resolve_fill_value(
    action: &serde_json::Value,
    fill_data: &HashMap<String, String>,
) -> Option<String> {
    // Try data_key first
    if let Some(dk) = action.get("data_key").and_then(|v| v.as_str()) {
        if let Some(val) = fill_data.get(dk) {
            return Some(val.clone());
        }
    }
    // Fall back to literal value
    action.get("value").and_then(|v| v.as_str()).map(String::from)
}

// ---------------------------------------------------------------------------
// Recorded-step builder — 1:1 with Python _execute_and_verify_action.
// Produces the full replayable RecordedStep JSON (asdict shape) per action,
// or None for pure-investigation/no-step actions. The intelligent loop collects
// these as the saved workflow steps, exactly like Python's session.steps.
// ---------------------------------------------------------------------------

/// Pull label / field_type / field_name / element_id for a resolved field from dom_state.
fn field_meta(dom_state: &serde_json::Value, field_index: Option<usize>) -> serde_json::Map<String, serde_json::Value> {
    let mut out = serde_json::Map::new();
    let idx = match field_index {
        Some(i) => i,
        None => return out,
    };
    if let Some(fields) = dom_state.get("fields").and_then(|f| f.as_array()) {
        if let Some(field) = fields
            .iter()
            .find(|f| f.get("index").and_then(|i| i.as_u64()) == Some(idx as u64))
        {
            for (src, dst) in [("label", "label"), ("type", "field_type"), ("name", "field_name"), ("id", "element_id")] {
                if let Some(v) = field.get(src).and_then(|v| v.as_str()) {
                    if !v.is_empty() {
                        out.insert(dst.to_string(), serde_json::json!(v));
                    }
                }
            }
        }
    }
    out
}

fn build_recorded_step(
    action_type: &str,
    action: &serde_json::Value,
    dom_state: &serde_json::Value,
    fill_data: &HashMap<String, String>,
    page_url: &str,
) -> Option<serde_json::Value> {
    use serde_json::json;

    let fi = action.get("field_index").and_then(|v| v.as_u64()).map(|v| v as usize);
    let coords = match (
        action.get("x").and_then(|v| v.as_f64()),
        action.get("y").and_then(|v| v.as_f64()),
    ) {
        (Some(x), Some(y)) => Some(json!({"x": x as i64, "y": y as i64})),
        _ => None,
    };

    // Assemble the RecordedStep object (type/timestamp/id always; rest when present).
    let assemble = |step_type: &str,
                    selector: Option<String>,
                    url: Option<String>,
                    value: Option<String>,
                    description: String,
                    coordinates: Option<serde_json::Value>,
                    mut options: serde_json::Map<String, serde_json::Value>|
     -> serde_json::Value {
        options.entry("intelligent_mode".to_string()).or_insert(json!(true));
        let mut m = serde_json::Map::new();
        m.insert("type".into(), json!(step_type));
        m.insert("timestamp".into(), json!(crate::recorder::step_recording::current_timestamp()));
        m.insert("id".into(), json!(uuid::Uuid::new_v4().to_string()));
        if let Some(s) = selector {
            m.insert("selector".into(), json!(s));
        }
        if let Some(u) = url {
            m.insert("url".into(), json!(u));
        }
        if let Some(v) = value {
            m.insert("value".into(), json!(v));
        }
        m.insert("description".into(), json!(description));
        if let Some(c) = coordinates {
            m.insert("coordinates".into(), c);
        }
        m.insert("options".into(), serde_json::Value::Object(options));
        serde_json::Value::Object(m)
    };

    match action_type {
        "fill" | "type_text" => {
            let value = resolve_fill_value(action, fill_data);
            let selector = resolve_selector(dom_state, fi);
            let mut o = field_meta(dom_state, fi);
            o.insert("from_vision".into(), json!(true));
            if let Some(dk) = action.get("data_key").and_then(|v| v.as_str()) {
                o.insert("data_key".into(), json!(dk));
            }
            let desc = format!("Fill {}", selector.clone().unwrap_or_else(|| "field".into()));
            Some(assemble("fill", selector, None, value, desc, None, o))
        }
        "select" => {
            let value = resolve_fill_value(action, fill_data);
            let selector = resolve_selector(dom_state, fi);
            let mut o = field_meta(dom_state, fi);
            o.insert("from_vision".into(), json!(true));
            o.entry("field_type".to_string()).or_insert(json!("select"));
            if let Some(dk) = action.get("data_key").and_then(|v| v.as_str()) {
                o.insert("data_key".into(), json!(dk));
            }
            let desc = format!("Select {}", value.clone().unwrap_or_default());
            Some(assemble("select", selector, None, value, desc, None, o))
        }
        "check" => {
            let selector = resolve_selector(dom_state, fi);
            let mut o = field_meta(dom_state, fi);
            o.insert("from_vision".into(), json!(true));
            if let Some(v) = action.get("value").and_then(|v| v.as_str()) {
                o.insert("selected_option".into(), json!(v));
            }
            Some(assemble("check", selector, None, None, "Check executed".into(), coords.clone(), o))
        }
        // Python 'retry' clicks to retry but records NO step.
        "retry" => None,
        "click" => {
            let bi = action.get("button_index").and_then(|v| v.as_u64()).map(|v| v as usize);
            let selector = resolve_button_selector(dom_state, bi).or_else(|| resolve_selector(dom_state, fi));
            let mut o = field_meta(dom_state, fi);
            o.insert("from_vision".into(), json!(true));
            Some(assemble("click", selector, None, None, "Click executed".into(), coords.clone(), o))
        }
        "submit" => {
            let bi = action.get("button_index").and_then(|v| v.as_u64()).map(|v| v as usize);
            let selector = resolve_button_selector(dom_state, bi);
            let mut o = serde_json::Map::new();
            o.insert("is_submit".into(), json!(true));
            o.insert("button_type".into(), json!("submit"));
            o.insert("from_vision".into(), json!(true));
            Some(assemble("click", selector, None, None, "Form submitted".into(), None, o))
        }
        "scroll" => {
            let direction = action.get("direction").and_then(|v| v.as_str()).unwrap_or("down");
            let amount = action.get("amount").and_then(|v| v.as_i64()).unwrap_or(300);
            let mut o = serde_json::Map::new();
            o.insert("direction".into(), json!(direction));
            o.insert("amount".into(), json!(amount));
            o.insert("from_vision".into(), json!(true));
            Some(assemble("scroll", None, None, None, format!("Scroll {} {}px", direction, amount), None, o))
        }
        "press_key" => {
            let key = action.get("key").and_then(|v| v.as_str()).unwrap_or("Enter");
            let mut o = serde_json::Map::new();
            o.insert("key".into(), json!(key));
            Some(assemble("press", None, None, None, format!("Press {}", key), None, o))
        }
        "evaluate_js" => {
            let script = action.get("script").and_then(|v| v.as_str()).unwrap_or("");
            let mut o = serde_json::Map::new();
            o.insert("script".into(), json!(script));
            if let Some(v) = action.get("variable").and_then(|v| v.as_str()) {
                o.insert("variable".into(), json!(v));
            }
            let desc = match action.get("variable").and_then(|v| v.as_str()) {
                Some(v) => format!("Evaluate JS → {}", v),
                None => "Evaluate JS".into(),
            };
            Some(assemble("evaluate", None, Some(page_url.to_string()), None, desc, None, o))
        }
        "extract_data" => {
            let selector = action.get("selector").and_then(|v| v.as_str()).map(String::from);
            let extract_type = action.get("extract_type").and_then(|v| v.as_str()).unwrap_or("text");
            let variable = action.get("variable").and_then(|v| v.as_str()).unwrap_or("extracted");
            let mut o = serde_json::Map::new();
            o.insert("extract_type".into(), json!(extract_type));
            o.insert("output_name".into(), json!(variable));
            o.insert("variable".into(), json!(variable));
            Some(assemble("extract", selector, None, None, format!("Extract {} → {}", extract_type, variable), None, o))
        }
        "wait_for_change" => {
            let selector = action
                .get("selector")
                .and_then(|v| v.as_str())
                .filter(|s| !s.is_empty())
                .map(String::from);
            let region = action.get("region").filter(|v| v.is_object()).cloned();
            let watch_kind = action
                .get("watch_kind")
                .and_then(|v| v.as_str())
                .unwrap_or(if region.is_some() { "region" } else { "selector" });
            let change_kind = action
                .get("change_kind")
                .and_then(|v| v.as_str())
                .unwrap_or(if watch_kind == "region" { "visual" } else { "text" });
            let variable = action
                .get("variable")
                .or_else(|| action.get("output_name"))
                .and_then(|v| v.as_str())
                .unwrap_or("change");
            let timeout_secs = action.get("timeout").and_then(|v| v.as_u64()).unwrap_or(10).min(30);
            let mut o = serde_json::Map::new();
            o.insert("watch_kind".into(), json!(watch_kind));
            o.insert("change_kind".into(), json!(change_kind));
            o.insert("output_name".into(), json!(variable));
            o.insert("variable".into(), json!(variable));
            o.insert("baseline_mode".into(), json!("in_run"));
            o.insert("timeout_ms".into(), json!(timeout_secs * 1000));
            if let Some(r) = region {
                o.insert("region".into(), r);
            }
            if change_kind == "attribute" {
                if let Some(a) = action.get("attribute").and_then(|v| v.as_str()) {
                    o.insert("attribute".into(), json!(a));
                }
            }
            Some(assemble("wait_for_change", selector, None, None, format!("Wait for change → {}", variable), None, o))
        }
        "switch_tab" => {
            let tab_index = action.get("tab_index").and_then(|v| v.as_u64()).unwrap_or(0);
            let step_type = if tab_index > 0 { "wait_for_tab" } else { "navigate" };
            let mut o = serde_json::Map::new();
            o.insert("tab_index".into(), json!(tab_index));
            Some(assemble(step_type, None, Some(page_url.to_string()), None, format!("Switch to tab {}", tab_index), None, o))
        }
        "wait_for_tab" => Some(assemble(
            "wait_for_tab",
            None,
            Some(page_url.to_string()),
            None,
            "New tab opened".into(),
            None,
            serde_json::Map::new(),
        )),
        "close_tab" => Some(assemble(
            "tab_closed",
            None,
            Some(page_url.to_string()),
            None,
            "Close tab and return".into(),
            None,
            serde_json::Map::new(),
        )),
        "solve_captcha" => {
            let selector = action.get("selector").and_then(|v| v.as_str()).map(String::from);
            let mut o = serde_json::Map::new();
            if let Some(ct) = action.get("captcha_type").and_then(|v| v.as_str()) {
                o.insert("captcha_type".into(), json!(ct));
            }
            o.insert("from_vision".into(), json!(true));
            Some(assemble("solve_captcha", selector, None, None, "Captcha step recorded".into(), coords.clone(), o))
        }
        // No-step actions (pure investigation / waits): wait, wait_for, hover,
        // scroll_to_field, inspect_field, read_text, list_tabs, complete, blocked, batch.
        _ => None,
    }
}

// ---------------------------------------------------------------------------
// Action implementations
// ---------------------------------------------------------------------------

async fn execute_fill(
    page: &Page,
    action: &serde_json::Value,
    fill_data: &HashMap<String, String>,
    dom_state: &serde_json::Value,
) -> anyhow::Result<ActionStepOutcome> {
    let value = resolve_fill_value(action, fill_data)
        .ok_or_else(|| anyhow::anyhow!("No value resolved for fill action"))?;

    let field_index = action.get("field_index").and_then(|v| v.as_u64()).map(|v| v as usize);

    // Try selector-based fill first
    if let Some(selector) = resolve_selector(dom_state, field_index) {
        // Use clear_and_type for more reliable filling (handles React/Vue inputs)
        match page_actions::clear_and_type(page, &selector, &value, 30.0).await {
            Ok(()) => {}
            Err(_) => {
                // Fallback to Playwright fill
                page_actions::fill(page, &selector, &value).await?;
            }
        }
    } else if let Some(fi) = field_index {
        // Fall back to coordinate-based click + type
        if let Some((x, y)) = resolve_field_coords(dom_state, fi) {
            page_actions::click_at(page, x, y).await?;
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
            page_actions::keyboard_press(page, "Control+a").await?;
            page_actions::keyboard_press(page, "Delete").await?;
            page_actions::keyboard_type(page, &value, 30.0).await?;
        } else {
            anyhow::bail!("Cannot resolve field_index {} to selector or coordinates", fi);
        }
    } else if let (Some(x), Some(y)) = (
        action.get("x").and_then(|v| v.as_f64()),
        action.get("y").and_then(|v| v.as_f64()),
    ) {
        page_actions::click_at(page, x, y).await?;
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        page_actions::keyboard_press(page, "Control+a").await?;
        page_actions::keyboard_press(page, "Delete").await?;
        page_actions::keyboard_type(page, &value, 30.0).await?;
    } else {
        anyhow::bail!("Fill action has no field_index, selector, or coordinates");
    }

    // Brief pause for DOM update
    tokio::time::sleep(std::time::Duration::from_millis(150)).await;

    // Verify
    let selector_for_verify = resolve_selector(dom_state, field_index);
    let v = verification::verify_action_result(page, "fill", Some(&value), selector_for_verify.as_deref()).await;

    Ok(ActionStepOutcome {
        verification: v,
        endpoint: None,
    })
}

async fn execute_select(
    page: &Page,
    action: &serde_json::Value,
    fill_data: &HashMap<String, String>,
    dom_state: &serde_json::Value,
) -> anyhow::Result<ActionStepOutcome> {
    let value = resolve_fill_value(action, fill_data)
        .ok_or_else(|| anyhow::anyhow!("No value resolved for select action"))?;

    let field_index = action.get("field_index").and_then(|v| v.as_u64()).map(|v| v as usize);

    if let Some(selector) = resolve_selector(dom_state, field_index) {
        page_actions::select_option(page, &selector, &value).await?;
    } else if let Some(fi) = field_index {
        if let Some((x, y)) = resolve_field_coords(dom_state, fi) {
            // Click on the select to open it, then try selecting
            page_actions::click_at(page, x, y).await?;
            tokio::time::sleep(std::time::Duration::from_millis(300)).await;
        } else {
            anyhow::bail!("Cannot resolve field_index {} for select", fi);
        }
    } else {
        anyhow::bail!("Select action has no field_index or selector");
    }

    tokio::time::sleep(std::time::Duration::from_millis(150)).await;

    let selector_for_verify = resolve_selector(dom_state, field_index);
    let v = verification::verify_action_result(page, "select", Some(&value), selector_for_verify.as_deref()).await;

    Ok(ActionStepOutcome {
        verification: v,
        endpoint: None,
    })
}

async fn execute_check(
    page: &Page,
    action: &serde_json::Value,
    dom_state: &serde_json::Value,
) -> anyhow::Result<ActionStepOutcome> {
    let field_index = action.get("field_index").and_then(|v| v.as_u64()).map(|v| v as usize);

    if let Some(selector) = resolve_selector(dom_state, field_index) {
        page_actions::check(page, &selector).await?;
    } else if let Some(fi) = field_index {
        if let Some((x, y)) = resolve_field_coords(dom_state, fi) {
            page_actions::click_at(page, x, y).await?;
        } else {
            anyhow::bail!("Cannot resolve field_index {} for check", fi);
        }
    } else if let (Some(x), Some(y)) = (
        action.get("x").and_then(|v| v.as_f64()),
        action.get("y").and_then(|v| v.as_f64()),
    ) {
        page_actions::click_at(page, x, y).await?;
    } else {
        anyhow::bail!("Check action has no field_index, selector, or coordinates");
    }

    tokio::time::sleep(std::time::Duration::from_millis(100)).await;

    let selector_for_verify = resolve_selector(dom_state, field_index);
    let v = verification::verify_action_result(page, "check", None, selector_for_verify.as_deref()).await;

    Ok(ActionStepOutcome {
        verification: v,
        endpoint: None,
    })
}

async fn execute_click(
    page: &Page,
    action: &serde_json::Value,
    dom_state: &serde_json::Value,
) -> anyhow::Result<ActionStepOutcome> {
    // Try explicit coordinates first
    if let (Some(x), Some(y)) = (
        action.get("x").and_then(|v| v.as_f64()),
        action.get("y").and_then(|v| v.as_f64()),
    ) {
        page_actions::click_at(page, x, y).await?;
    } else if let Some(bi) = action.get("button_index").and_then(|v| v.as_u64()).map(|v| v as usize) {
        // Click by button index -- try selector first, then coords
        if let Some(selector) = resolve_button_selector(dom_state, Some(bi)) {
            page_actions::click_selector(page, &selector, false).await?;
        } else if let Some((x, y)) = resolve_button_coords(dom_state, bi) {
            page_actions::click_at(page, x, y).await?;
        } else {
            anyhow::bail!("Cannot resolve button_index {} to selector or coordinates", bi);
        }
    } else if let Some(fi) = action.get("field_index").and_then(|v| v.as_u64()).map(|v| v as usize) {
        if let Some((x, y)) = resolve_field_coords(dom_state, fi) {
            page_actions::click_at(page, x, y).await?;
        } else if let Some(selector) = resolve_selector(dom_state, Some(fi)) {
            page_actions::click_selector(page, &selector, false).await?;
        } else {
            anyhow::bail!("Cannot resolve field_index {} for click", fi);
        }
    } else {
        anyhow::bail!("Click action has no coordinates, button_index, or field_index");
    }

    tokio::time::sleep(std::time::Duration::from_millis(200)).await;

    Ok(ActionStepOutcome {
        verification: ActionVerification {
            verified: true,
            expected: None,
            actual: None,
            message: Some("Click executed".to_string()),
        },
        endpoint: None,
    })
}

async fn execute_submit(
    page: &Page,
    action: &serde_json::Value,
    dom_state: &serde_json::Value,
) -> anyhow::Result<ActionStepOutcome> {
    // Find the submit button
    if let Some(bi) = action.get("button_index").and_then(|v| v.as_u64()).map(|v| v as usize) {
        if let Some(selector) = resolve_button_selector(dom_state, Some(bi)) {
            page_actions::click_selector(page, &selector, false).await?;
        } else if let Some((x, y)) = resolve_button_coords(dom_state, bi) {
            page_actions::click_at(page, x, y).await?;
        } else {
            anyhow::bail!("Cannot resolve submit button_index {}", bi);
        }
    } else {
        // Try common submit selectors
        let submit_selectors = [
            "button[type=\"submit\"]",
            "input[type=\"submit\"]",
            "button:has-text(\"Submit\")",
            "button:has-text(\"Send\")",
        ];
        let mut clicked = false;
        for sel in &submit_selectors {
            if page_query::locator_is_visible(page, sel).await.unwrap_or(false) {
                page_actions::click_selector(page, sel, false).await?;
                clicked = true;
                break;
            }
        }
        if !clicked {
            anyhow::bail!("No submit button found");
        }
    }

    // Wait for navigation or response after submit
    tokio::time::sleep(std::time::Duration::from_secs(2)).await;

    // Detect form endpoint
    let endpoint = verification::detect_form_endpoint(page).await;
    let endpoint_json = serde_json::to_value(&endpoint).ok();

    Ok(ActionStepOutcome {
        verification: ActionVerification {
            verified: true,
            expected: None,
            actual: None,
            message: Some("Submit executed".to_string()),
        },
        endpoint: endpoint_json,
    })
}

async fn execute_scroll(
    page: &Page,
    action: &serde_json::Value,
) -> anyhow::Result<ActionStepOutcome> {
    let direction = action.get("direction").and_then(|v| v.as_str()).unwrap_or("down");
    let amount = action.get("amount").and_then(|v| v.as_i64()).unwrap_or(300);

    let delta_y = match direction {
        "up" => -(amount as f64),
        _ => amount as f64,
    };

    page_actions::mouse_wheel(page, 0.0, delta_y).await?;
    tokio::time::sleep(std::time::Duration::from_millis(300)).await;

    Ok(ActionStepOutcome {
        verification: ActionVerification {
            verified: true,
            expected: None,
            actual: None,
            message: Some(format!("Scrolled {} {}px", direction, amount)),
        },
        endpoint: None,
    })
}

async fn execute_scroll_to_field(
    page: &Page,
    action: &serde_json::Value,
) -> anyhow::Result<ActionStepOutcome> {
    let field_index = action.get("field_index").and_then(|v| v.as_u64()).unwrap_or(0) as usize;

    let js = format!(
        r#"(() => {{
            const fields = document.querySelectorAll('input, select, textarea, [contenteditable="true"]');
            const visibleFields = Array.from(fields).filter(f => {{
                const r = f.getBoundingClientRect();
                return r.width > 0 && r.height > 0;
            }});
            if (visibleFields[{}]) {{
                visibleFields[{}].scrollIntoView({{ behavior: 'smooth', block: 'center' }});
                return true;
            }}
            return false;
        }})()"#,
        field_index, field_index
    );

    let _: serde_json::Value = page_query::evaluate(page, &js).await?;
    tokio::time::sleep(std::time::Duration::from_millis(500)).await;

    Ok(ActionStepOutcome {
        verification: ActionVerification {
            verified: true,
            expected: None,
            actual: None,
            message: Some(format!("Scrolled to field {}", field_index)),
        },
        endpoint: None,
    })
}

async fn execute_hover(
    page: &Page,
    action: &serde_json::Value,
    dom_state: &serde_json::Value,
) -> anyhow::Result<ActionStepOutcome> {
    if let (Some(x), Some(y)) = (
        action.get("x").and_then(|v| v.as_f64()),
        action.get("y").and_then(|v| v.as_f64()),
    ) {
        page_actions::hover_at(page, x, y).await?;
    } else if let Some(fi) = action.get("field_index").and_then(|v| v.as_u64()).map(|v| v as usize) {
        if let Some(selector) = resolve_selector(dom_state, Some(fi)) {
            page_actions::hover(page, &selector).await?;
        } else if let Some((x, y)) = resolve_field_coords(dom_state, fi) {
            page_actions::hover_at(page, x, y).await?;
        }
    }

    Ok(ActionStepOutcome {
        verification: ActionVerification {
            verified: true,
            expected: None,
            actual: None,
            message: Some("Hover executed".to_string()),
        },
        endpoint: None,
    })
}

async fn execute_press_key(
    page: &Page,
    action: &serde_json::Value,
) -> anyhow::Result<ActionStepOutcome> {
    let key = action.get("key").and_then(|v| v.as_str()).unwrap_or("Enter");
    page_actions::keyboard_press(page, key).await?;
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;

    Ok(ActionStepOutcome {
        verification: ActionVerification {
            verified: true,
            expected: None,
            actual: None,
            message: Some(format!("Pressed key: {}", key)),
        },
        endpoint: None,
    })
}

async fn execute_evaluate_js(
    page: &Page,
    action: &serde_json::Value,
) -> anyhow::Result<ActionStepOutcome> {
    let script = action.get("script").and_then(|v| v.as_str()).unwrap_or("null");
    let result = page_query::evaluate_value(page, script).await?;

    Ok(ActionStepOutcome {
        verification: ActionVerification {
            verified: true,
            expected: None,
            actual: Some(result),
            message: Some("JS evaluated".to_string()),
        },
        endpoint: None,
    })
}

async fn execute_wait(
    action: &serde_json::Value,
) -> anyhow::Result<ActionStepOutcome> {
    // `ms` is accepted as an alias for `seconds` — callers (and MCP clients that
    // learned the vocabulary elsewhere) reach for milliseconds often enough that
    // silently ignoring it turned an intended pause into the 1s default.
    let seconds = action
        .get("seconds")
        .and_then(|v| v.as_f64())
        .or_else(|| action.get("ms").and_then(|v| v.as_f64()).map(|ms| ms / 1000.0))
        .unwrap_or(1.0);
    let capped = seconds.clamp(0.0, 10.0);
    tokio::time::sleep(std::time::Duration::from_secs_f64(capped)).await;

    Ok(ActionStepOutcome {
        verification: ActionVerification {
            verified: true,
            expected: None,
            actual: None,
            message: Some(format!("Waited {:.1}s", capped)),
        },
        endpoint: None,
    })
}

async fn execute_wait_for(
    page: &Page,
    action: &serde_json::Value,
) -> anyhow::Result<ActionStepOutcome> {
    if let Some(selector) = action.get("selector").and_then(|v| v.as_str()) {
        let timeout = std::time::Duration::from_secs(10);
        match page_query::wait_for_selector(page, selector, timeout).await {
            Ok(()) => {}
            Err(e) => {
                tracing::debug!(selector, error = %e, "wait_for selector timed out");
            }
        }
    } else {
        tokio::time::sleep(std::time::Duration::from_secs(2)).await;
    }

    // Deliberately optimistic: a "wait" step has no positive assertion to check,
    // and a selector timeout here is advisory (the AI often waits speculatively),
    // so we report verified regardless rather than aborting the run on a miss.
    Ok(ActionStepOutcome {
        verification: ActionVerification {
            verified: true,
            expected: None,
            actual: None,
            message: Some("Wait for condition checked".to_string()),
        },
        endpoint: None,
    })
}

async fn execute_inspect_field(
    page: &Page,
    action: &serde_json::Value,
) -> anyhow::Result<ActionStepOutcome> {
    let field_index = action.get("field_index").and_then(|v| v.as_u64()).unwrap_or(0);

    let js = format!(
        r#"(() => {{
            const fields = document.querySelectorAll('input, select, textarea, [contenteditable="true"]');
            const visibleFields = Array.from(fields).filter(f => {{
                const r = f.getBoundingClientRect();
                return r.width > 0 && r.height > 0;
            }});
            const el = visibleFields[{}];
            if (!el) return null;
            const r = el.getBoundingClientRect();
            return {{
                tag: el.tagName.toLowerCase(),
                type: el.type || '',
                name: el.name || '',
                id: el.id || '',
                value: el.value || '',
                checked: el.checked || false,
                disabled: el.disabled || false,
                required: el.required || false,
                placeholder: el.placeholder || '',
                visible: r.width > 0 && r.height > 0,
                x: Math.round(r.x + r.width/2),
                y: Math.round(r.y + r.height/2)
            }};
        }})()"#,
        field_index
    );

    let result: serde_json::Value = page_query::evaluate(page, &js).await?;
    let actual_str = serde_json::to_string(&result).unwrap_or_default();

    Ok(ActionStepOutcome {
        verification: ActionVerification {
            verified: true,
            expected: None,
            actual: Some(actual_str),
            message: Some(format!("Field {} inspected", field_index)),
        },
        endpoint: None,
    })
}

async fn execute_read_text(
    page: &Page,
    action: &serde_json::Value,
) -> anyhow::Result<ActionStepOutcome> {
    let text = if let Some(selector) = action.get("selector").and_then(|v| v.as_str()) {
        page_query::locator_text_content(page, selector)
            .await
            .unwrap_or(Some("".to_string()))
            .unwrap_or_default()
    } else {
        // Read visible page text
        let js = r#"document.body.innerText.substring(0, 2000)"#;
        page_query::evaluate_value(page, js).await.unwrap_or_default()
    };

    Ok(ActionStepOutcome {
        verification: ActionVerification {
            verified: true,
            expected: None,
            actual: Some(text),
            message: Some("Text read".to_string()),
        },
        endpoint: None,
    })
}

async fn execute_extract_data(
    page: &Page,
    action: &serde_json::Value,
) -> anyhow::Result<ActionStepOutcome> {
    let selector = action.get("selector").and_then(|v| v.as_str()).unwrap_or("body");

    // `fields` = {name: css_sub_selector} evaluated INSIDE each element matching
    // `selector`, yielding one row per element. Without it this action could only
    // return the text of the first match, so the common "pull this repeated list
    // off the page" case had no answer and callers passing `fields` silently got
    // a single blob back.
    let fields = action.get("fields").and_then(|v| v.as_object());
    if let Some(fields) = fields {
        let limit = action
            .get("limit")
            .and_then(|v| v.as_u64())
            .unwrap_or(100)
            .clamp(1, 1000);
        let field_map: serde_json::Map<String, serde_json::Value> = fields
            .iter()
            .filter(|(_, v)| v.is_string())
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect();
        if field_map.is_empty() {
            anyhow::bail!("extract_data: `fields` must map field names to CSS selector strings");
        }
        // Same JS as the replay executor (automation::step_eval), so what an agent
        // sees while recording is exactly what the saved workflow later extracts.
        let js = crate::automation::step_eval::row_extraction_js(selector, &field_map, limit);
        let result: serde_json::Value = page_query::evaluate(page, &js).await?;
        let count = result.get("count").and_then(|v| v.as_u64()).unwrap_or(0);
        return Ok(ActionStepOutcome {
            verification: ActionVerification {
                verified: count > 0,
                expected: None,
                actual: Some(serde_json::to_string(&result).unwrap_or_default()),
                message: Some(format!("Extracted {} row(s) from {}", count, selector)),
            },
            endpoint: None,
        });
    }

    let text = page_query::locator_text_content(page, selector)
        .await
        .unwrap_or(Some("".to_string()))
        .unwrap_or_default();

    Ok(ActionStepOutcome {
        verification: ActionVerification {
            verified: true,
            expected: None,
            actual: Some(text),
            message: Some("Data extracted".to_string()),
        },
        endpoint: None,
    })
}

/// Watch a selector (text/html/attribute) or screen region (visual) until it changes,
/// then return the new value in `verification.actual`. Investigation-style action: it does
/// not count against the action budget. Bounded by `timeout` (seconds, capped at 30).
async fn execute_wait_for_change(
    page: &Page,
    action: &serde_json::Value,
) -> anyhow::Result<ActionStepOutcome> {
    let selector = action.get("selector").and_then(|v| v.as_str()).unwrap_or("");
    let region = action.get("region").filter(|v| v.is_object());
    let watch_kind = action
        .get("watch_kind")
        .and_then(|v| v.as_str())
        .unwrap_or(if region.is_some() { "region" } else { "selector" });
    let change_kind = action
        .get("change_kind")
        .and_then(|v| v.as_str())
        .unwrap_or(if watch_kind == "region" { "visual" } else { "text" });
    let variable = action
        .get("variable")
        .or_else(|| action.get("output_name"))
        .and_then(|v| v.as_str())
        .unwrap_or("change");
    let attribute = action.get("attribute").and_then(|v| v.as_str()).unwrap_or("value");
    let timeout_secs = action
        .get("timeout")
        .and_then(|v| v.as_u64())
        .unwrap_or(10)
        .min(30);

    if watch_kind == "selector" && selector.is_empty() {
        return Ok(ActionStepOutcome {
            verification: ActionVerification {
                verified: false,
                expected: None,
                actual: None,
                message: Some("wait_for_change: selector required".to_string()),
            },
            endpoint: None,
        });
    }

    // Capture the current value as (display_string, comparison_bytes).
    async fn capture(
        page: &Page,
        watch_kind: &str,
        change_kind: &str,
        selector: &str,
        region: Option<&serde_json::Value>,
        attribute: &str,
    ) -> anyhow::Result<(String, Vec<u8>)> {
        if watch_kind == "region" || change_kind == "visual" {
            let (x, y, w, h) = if let Some(r) = region {
                (
                    r.get("x").and_then(|v| v.as_f64()).unwrap_or(0.0),
                    r.get("y").and_then(|v| v.as_f64()).unwrap_or(0.0),
                    r.get("width").or_else(|| r.get("w")).and_then(|v| v.as_f64()).unwrap_or(0.0),
                    r.get("height").or_else(|| r.get("h")).and_then(|v| v.as_f64()).unwrap_or(0.0),
                )
            } else {
                match page_actions::bounding_box(page, selector).await? {
                    Some(bb) => bb,
                    None => return Err(anyhow::anyhow!("selector '{}' has no bounding box", selector)),
                }
            };
            if w <= 0.0 || h <= 0.0 {
                return Err(anyhow::anyhow!("region has zero area"));
            }
            let bytes = page_query::screenshot_jpeg_clip(page, x, y, w, h, 70).await?;
            return Ok(("[region]".to_string(), bytes));
        }
        let text = match change_kind {
            "html" => {
                let js = format!(
                    "(() => {{ const el = document.querySelector({}); return el ? el.innerHTML : null; }})()",
                    serde_json::to_string(selector).unwrap_or_default()
                );
                page_query::evaluate::<Option<String>>(page, &js).await?.unwrap_or_default()
            }
            "attribute" => {
                let js = format!(
                    "(() => {{ const el = document.querySelector({}); return el ? el.getAttribute({}) : null; }})()",
                    serde_json::to_string(selector).unwrap_or_default(),
                    serde_json::to_string(attribute).unwrap_or_default()
                );
                page_query::evaluate::<Option<String>>(page, &js).await?.unwrap_or_default()
            }
            _ => page_query::locator_text_content(page, selector)
                .await?
                .unwrap_or_default(),
        };
        let bytes = text.clone().into_bytes();
        Ok((text, bytes))
    }

    let (init_str, baseline) =
        capture(page, watch_kind, change_kind, selector, region, attribute).await?;
    let mut changed = false;
    let mut new_str = init_str;
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(timeout_secs);
    while tokio::time::Instant::now() < deadline {
        tokio::time::sleep(std::time::Duration::from_millis(1000)).await;
        let (cur_str, cur_bytes) =
            capture(page, watch_kind, change_kind, selector, region, attribute).await?;
        if cur_bytes != baseline {
            changed = true;
            new_str = cur_str;
            break;
        }
    }

    let mut actual = new_str;
    if actual.len() > 500 {
        actual.truncate(500);
    }
    let message = if changed {
        format!("{} changed", variable)
    } else {
        format!("{} unchanged within {}s", variable, timeout_secs)
    };

    Ok(ActionStepOutcome {
        verification: ActionVerification {
            verified: true,
            expected: None,
            actual: Some(actual),
            message: Some(message),
        },
        endpoint: None,
    })
}

async fn execute_list_tabs(
    page: &Page,
) -> anyhow::Result<ActionStepOutcome> {
    let url = page_query::get_url(page).await;
    let title = page_query::get_title(page).await.unwrap_or_default();

    // Build the JSON with serde so a title/url containing a quote or backslash
    // (fully attacker-controlled page content) can't corrupt the payload.
    let actual = serde_json::json!([{ "url": url, "title": title }]).to_string();

    Ok(ActionStepOutcome {
        verification: ActionVerification {
            verified: true,
            expected: None,
            actual: Some(actual),
            message: Some("Tabs listed".to_string()),
        },
        endpoint: None,
    })
}

/// Switch to a tab by index. Mirrors step_misc::execute_switch_tab.
async fn execute_switch_tab(
    page: &Page,
    action: &serde_json::Value,
) -> anyhow::Result<ActionStepOutcome> {
    let tab_index = action.get("tab_index").and_then(|v| v.as_u64()).unwrap_or(0) as usize;
    let context = page.context()
        .map_err(|e| anyhow::anyhow!("Failed to get browser context: {}", e))?;
    let pages = context.pages();

    if tab_index >= pages.len() {
        return Err(anyhow::anyhow!(
            "Tab index {} out of range (have {} tabs)", tab_index, pages.len()
        ));
    }

    pages[tab_index].bring_to_front().await
        .map_err(|e| anyhow::anyhow!("Failed to switch to tab {}: {}", tab_index, e))?;

    Ok(ActionStepOutcome {
        verification: ActionVerification {
            verified: true,
            expected: None,
            actual: Some(format!("tab {}", tab_index)),
            message: Some(format!("Switched to tab {}", tab_index)),
        },
        endpoint: None,
    })
}

/// Wait for a new tab to appear (polls context pages). Mirrors step_misc::execute_wait_for_tab.
async fn execute_wait_for_tab(
    page: &Page,
    action: &serde_json::Value,
) -> anyhow::Result<ActionStepOutcome> {
    let timeout_ms = action.get("timeout_sec")
        .and_then(|v| v.as_f64())
        .map(|s| (s * 1000.0) as u64)
        .unwrap_or(10_000);

    let context = page.context()
        .map_err(|e| anyhow::anyhow!("Failed to get browser context: {}", e))?;
    let initial_count = context.pages().len();
    let start = std::time::Instant::now();

    while start.elapsed() < std::time::Duration::from_millis(timeout_ms) {
        let pages = context.pages();
        if pages.len() > initial_count {
            if let Some(new_page) = pages.last() {
                let _ = new_page.bring_to_front().await;
            }
            return Ok(ActionStepOutcome {
                verification: ActionVerification {
                    verified: true,
                    expected: None,
                    actual: Some(format!("{} tabs", pages.len())),
                    message: Some("New tab detected".to_string()),
                },
                endpoint: None,
            });
        }
        tokio::time::sleep(std::time::Duration::from_millis(500)).await;
    }

    Err(anyhow::anyhow!("No new tab appeared within timeout"))
}

/// Close the current tab. Mirrors step_misc::execute_tab_closed.
async fn execute_close_tab(
    page: &Page,
) -> anyhow::Result<ActionStepOutcome> {
    page.close().await
        .map_err(|e| anyhow::anyhow!("Failed to close tab: {}", e))?;

    Ok(ActionStepOutcome {
        verification: ActionVerification {
            verified: true,
            expected: None,
            actual: None,
            message: Some("Tab closed".to_string()),
        },
        endpoint: None,
    })
}

/// Record a captcha interaction. Mirrors Python solve_captcha action handling.
/// The actual solve is best-effort via verification::verify_captcha.
async fn execute_solve_captcha(
    page: &Page,
) -> anyhow::Result<ActionStepOutcome> {
    // Check if captcha is already solved / not present
    let captcha_verification = verification::verify_action_result(page, "solve_captcha", None, None).await;

    Ok(ActionStepOutcome {
        verification: captcha_verification,
        endpoint: None,
    })
}
