//! Single-action executor for the autonomous form-filler loop — the Rust port of the Python
//! recorder's `_ai_execute_and_record` (`recorder.py` ~L10311+). Executes ONE resolved action
//! (already mapped from `field_index` → coordinates + selector by the session loop) against the
//! live page using the shared [`crate::browser::page_actions`] primitives.
//!
//! A "resolved action" is a `serde_json::Value` shaped:
//! `{ "type": "click|type_text|select|solve_captcha|scroll", "x": .., "y": .., "selector"?, ..,
//!    "field_id"?, "field_name"?, "data_key"?, "value"?, "label"?, "direction"?, "amount"? }`
//!
//! Values come from `fill_data[data_key]` (the decrypted user values) or a literal `value`.
//! `solve_captcha` cannot be solved locally — it returns a clear, NON-hanging failure outcome.

use std::collections::HashMap;

use playwright_rs::Page;
use serde_json::Value;

use crate::browser::{page_actions, page_query};

/// Outcome of executing one resolved action. `success` drives the loop's tracking; `message`
/// carries a human-readable note (including the "cannot solve locally" captcha result).
#[derive(Debug, Clone)]
pub struct ActionOutcome {
    pub action_type: String,
    pub success: bool,
    pub message: String,
}

impl ActionOutcome {
    fn ok(action_type: &str, message: impl Into<String>) -> Self {
        Self {
            action_type: action_type.to_string(),
            success: true,
            message: message.into(),
        }
    }
    fn fail(action_type: &str, message: impl Into<String>) -> Self {
        Self {
            action_type: action_type.to_string(),
            success: false,
            message: message.into(),
        }
    }
}

/// Resolve the actual value to fill: `fill_data[data_key]` first, then a literal `value`.
fn resolve_value(action: &Value, fill_data: &HashMap<String, String>) -> Option<String> {
    if let Some(dk) = action.get("data_key").and_then(|v| v.as_str()) {
        if let Some(v) = fill_data.get(dk) {
            return Some(v.clone());
        }
    }
    action.get("value").and_then(|v| v.as_str()).map(String::from)
}

/// Build a CSS selector from the resolved action's identifiers, if any: explicit `selector`,
/// then `#field_id`, then `[name="field_name"]`.
fn action_selector(action: &Value) -> Option<String> {
    if let Some(sel) = action
        .get("selector")
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty())
    {
        return Some(sel.to_string());
    }
    if let Some(id) = action
        .get("field_id")
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty())
    {
        return Some(format!("#{}", id));
    }
    if let Some(name) = action
        .get("field_name")
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty())
    {
        return Some(format!("[name=\"{}\"]", name));
    }
    None
}

/// Best-effort scroll the target element into view when the action carries a selector/id, so a
/// subsequent coordinate click lands. Never fails the action.
async fn ensure_in_view(page: &Page, action: &Value) {
    if let Some(sel) = action_selector(action) {
        if let Err(e) = page_actions::scroll_into_view(page, &sel).await {
            tracing::debug!(selector = %sel, error = %e, "scroll_into_view (best-effort) failed");
        } else {
            // Let layout settle after the scroll.
            tokio::time::sleep(std::time::Duration::from_millis(120)).await;
        }
    }
}

fn coords(action: &Value) -> Option<(f64, f64)> {
    match (
        action.get("x").and_then(|v| v.as_f64()),
        action.get("y").and_then(|v| v.as_f64()),
    ) {
        (Some(x), Some(y)) => Some((x, y)),
        _ => None,
    }
}

/// Execute a single resolved AI action against the live page.
///
/// Maps `action.type` → the appropriate `page_actions` primitive, preferring a selector when the
/// action carries one and falling back to coordinate interaction. Scrolls the target into view
/// first when a selector/id is present. `solve_captcha` returns a clear "cannot solve locally"
/// failure without blocking.
pub async fn execute_ai_action(
    page: &Page,
    action: &Value,
    fill_data: &HashMap<String, String>,
) -> ActionOutcome {
    let atype = action
        .get("type")
        .and_then(|v| v.as_str())
        .unwrap_or("unknown")
        .to_string();

    match atype.as_str() {
        // ── Type into a text/email/textarea/date field ──
        "type_text" | "fill" => {
            let value = match resolve_value(action, fill_data) {
                Some(v) => v,
                None => return ActionOutcome::fail(&atype, "no value resolved for type_text"),
            };
            ensure_in_view(page, action).await;
            if let Some(sel) = action_selector(action) {
                // clear_and_type handles React/Vue controlled inputs; fall back to fill.
                if let Err(e) = page_actions::clear_and_type(page, &sel, &value, 30.0).await {
                    tracing::debug!(selector = %sel, error = %e, "clear_and_type failed, trying fill");
                    if let Err(e2) = page_actions::fill(page, &sel, &value).await {
                        return ActionOutcome::fail(&atype, format!("type_text failed: {}", e2));
                    }
                }
                ActionOutcome::ok(&atype, format!("typed into {}", sel))
            } else if let Some((x, y)) = coords(action) {
                if let Err(e) = page_actions::click_at(page, x, y).await {
                    return ActionOutcome::fail(&atype, format!("focus click failed: {}", e));
                }
                tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                let _ = page_actions::keyboard_press(page, "Control+a").await;
                let _ = page_actions::keyboard_press(page, "Delete").await;
                if let Err(e) = page_actions::keyboard_type(page, &value, 30.0).await {
                    return ActionOutcome::fail(&atype, format!("type failed: {}", e));
                }
                ActionOutcome::ok(&atype, format!("typed at ({}, {})", x as i64, y as i64))
            } else {
                ActionOutcome::fail(&atype, "type_text has no selector or coordinates")
            }
        }

        // ── Select a dropdown option ──
        "select" => {
            let value = match resolve_value(action, fill_data) {
                Some(v) => v,
                None => return ActionOutcome::fail(&atype, "no value resolved for select"),
            };
            ensure_in_view(page, action).await;
            if let Some(sel) = action_selector(action) {
                match page_actions::select_option(page, &sel, &value).await {
                    Ok(()) => ActionOutcome::ok(&atype, format!("selected '{}' in {}", value, sel)),
                    Err(e) => ActionOutcome::fail(&atype, format!("select failed: {}", e)),
                }
            } else if let Some((x, y)) = coords(action) {
                // No selector — open the native/custom dropdown by clicking it, then let the
                // model pick the option on the next observation (custom dropdowns are DOM-driven).
                if let Err(e) = page_actions::click_at(page, x, y).await {
                    return ActionOutcome::fail(&atype, format!("dropdown open click failed: {}", e));
                }
                tokio::time::sleep(std::time::Duration::from_millis(300)).await;
                ActionOutcome::ok(&atype, "opened dropdown (pick option next turn)")
            } else {
                ActionOutcome::fail(&atype, "select has no selector or coordinates")
            }
        }

        // ── Click (also how checkboxes/radios/submit are actuated) ──
        "click" | "check" => {
            ensure_in_view(page, action).await;
            if let Some((x, y)) = coords(action) {
                match page_actions::click_at(page, x, y).await {
                    Ok(()) => ActionOutcome::ok(&atype, format!("clicked ({}, {})", x as i64, y as i64)),
                    Err(e) => ActionOutcome::fail(&atype, format!("click failed: {}", e)),
                }
            } else if let Some(sel) = action_selector(action) {
                match page_actions::click_selector(page, &sel, false).await {
                    Ok(()) => ActionOutcome::ok(&atype, format!("clicked {}", sel)),
                    Err(e) => ActionOutcome::fail(&atype, format!("click failed: {}", e)),
                }
            } else {
                ActionOutcome::fail(&atype, "click has no coordinates or selector")
            }
        }

        // ── Scroll the viewport (bring more of the form into view) ──
        "scroll" => {
            let direction = action.get("direction").and_then(|v| v.as_str()).unwrap_or("down");
            let amount = action.get("amount").and_then(|v| v.as_f64()).unwrap_or(600.0);
            let delta_y = if direction == "up" { -amount } else { amount };
            match page_actions::mouse_wheel(page, 0.0, delta_y).await {
                Ok(()) => ActionOutcome::ok(&atype, format!("scrolled {} {}px", direction, amount as i64)),
                Err(e) => ActionOutcome::fail(&atype, format!("scroll failed: {}", e)),
            }
        }

        // ── CAPTCHA: not solvable locally. Record a clear, non-hanging outcome. ──
        "solve_captcha" => {
            let ty = action
                .get("captcha_type")
                .and_then(|v| v.as_str())
                .unwrap_or("unknown");
            // Do NOT block: report the presence and return immediately.
            tracing::info!(captcha_type = ty, "captcha encountered — cannot solve locally");
            ActionOutcome::fail(
                "solve_captcha",
                format!(
                    "CAPTCHA_UNSUPPORTED: a '{}' captcha was detected and cannot be solved locally in an autonomous session",
                    ty
                ),
            )
        }

        // ── Press a key (e.g. Enter to submit) ──
        "press_key" | "press" => {
            let key = action.get("key").and_then(|v| v.as_str()).unwrap_or("Enter");
            match page_actions::keyboard_press(page, key).await {
                Ok(()) => ActionOutcome::ok(&atype, format!("pressed {}", key)),
                Err(e) => ActionOutcome::fail(&atype, format!("press failed: {}", e)),
            }
        }

        // ── Read-only investigation: read text (never fails the loop) ──
        "read_text" => {
            let text = if let Some(sel) = action.get("selector").and_then(|v| v.as_str()) {
                page_query::locator_text_content(page, sel)
                    .await
                    .ok()
                    .flatten()
                    .unwrap_or_default()
            } else {
                page_query::evaluate_value(page, "document.body.innerText.substring(0, 2000)")
                    .await
                    .unwrap_or_default()
            };
            ActionOutcome::ok(&atype, text)
        }

        other => {
            tracing::warn!(action_type = other, "unknown action type in autonomous executor");
            ActionOutcome::fail(other, format!("unknown action type '{}'", other))
        }
    }
    // Note: callers wait for the page to settle after a batch; per-action pauses are inline above.
}

/// Convenience: was this outcome a captcha-unsupported result? (Lets the loop mark the session
/// blocked rather than merely failing an action.)
pub fn is_captcha_blocked(outcome: &ActionOutcome) -> bool {
    outcome.action_type == "solve_captcha" && outcome.message.starts_with("CAPTCHA_UNSUPPORTED")
}
