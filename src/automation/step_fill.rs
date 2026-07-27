use std::collections::HashMap;

use playwright_rs::Page;

use crate::browser::{page_actions, page_query};
use crate::models::workflow::WorkflowStepConfig;
use crate::util::value_resolver;
use super::step_executor::{StepError, StepResult};
use super::recognition::{RecognitionConfig, RECOGNITION_SCORER_JS, MIN_RECOGNITION_SCORE};

pub async fn execute(
    page: &Page,
    config: &WorkflowStepConfig,
    credentials: &HashMap<String, String>,
    form_data: &HashMap<String, String>,
    _timeout_ms: u64,
    fast_mode: bool,
) -> StepResult {
    let selector = config.selector.as_deref().unwrap_or("");
    let raw_value = config.value.as_deref().unwrap_or("");
    let value = value_resolver::resolve_value(raw_value, credentials, Some(form_data));

    tracing::debug!(selector = selector, value_len = value.len(), "Executing fill step");

    // Tier 1: Direct locator fill
    if !selector.is_empty() {
        match page_actions::fill(page, selector, &value).await {
            Ok(()) => {
                tracing::debug!(selector = selector, "Fill succeeded via locator.fill()");
                // Verify the fill
                if let Ok(actual) = page_query::locator_input_value(page, selector).await {
                    if actual == value {
                        return Ok(None);
                    }
                    tracing::debug!(expected_len = value.len(), actual_len = actual.len(), "Fill verification mismatch, trying JS fallback");
                } else {
                    return Ok(None);
                }
            }
            Err(e) => {
                tracing::debug!(error = %e, "locator.fill() failed, trying fallbacks");
            }
        }

        // Only run the selector-dependent fallbacks (Tier 1b/1c) if the element is actually on the
        // page. When the recorded selector no longer matches anything (the common "site changed"
        // case), the clear_and_type fallback would re-wait the FULL element timeout on that same
        // broken selector — turning one element-timeout into two and doubling time-to-failure. A
        // present-but-stubborn element (controlled React input that resisted locator.fill()) still
        // gets both fallbacks. If absent, we fall straight through to the selector-independent
        // recognition/coordinate fallbacks below, then fail — so AI auto-repair engages sooner.
        let present = page_query::locator_count(page, selector).await.unwrap_or(0) > 0;
        if present {
            // Tier 1b: JS nativeSetter fallback for React/Angular inputs
            let js_fill = format!(
                r#"(() => {{
                    const el = document.querySelector({sel});
                    if (!el) return false;
                    const nativeSetter = Object.getOwnPropertyDescriptor(
                        window.HTMLInputElement.prototype, 'value'
                    )?.set || Object.getOwnPropertyDescriptor(
                        window.HTMLTextAreaElement.prototype, 'value'
                    )?.set;
                    if (nativeSetter) {{
                        nativeSetter.call(el, {val});
                        el.dispatchEvent(new Event('input', {{ bubbles: true }}));
                        el.dispatchEvent(new Event('change', {{ bubbles: true }}));
                        return true;
                    }}
                    return false;
                }})()"#,
                sel = serde_json::to_string(selector).unwrap_or_default(),
                val = serde_json::to_string(&value).unwrap_or_default(),
            );

            let js_ok: bool = page.evaluate(&js_fill, None::<&()>).await.unwrap_or(false);
            if js_ok {
                tracing::debug!(selector = selector, "JS nativeSetter fill succeeded");
                return Ok(None);
            }

            // Tier 1c: clear_and_type fallback (click + select all + type)
            let delay = if fast_mode { 0.0 } else { 30.0 };
            if page_actions::clear_and_type(page, selector, &value, delay).await.is_ok() {
                tracing::debug!(selector = selector, "clear_and_type fill succeeded");
                return Ok(None);
            }
        }
    }

    // Tier 2: Recognition-based fallback
    if let Some(recognition_data) = &config.recognition {
        let rec_config = RecognitionConfig::from_json(recognition_data);
        if rec_config.has_meaningful_criteria() {
            let args = rec_config.to_js_args();

            match page_query::evaluate_with_args::<serde_json::Value>(
                page,
                &format!("(args) => {{ {} return findInputElement(args); }}", RECOGNITION_SCORER_JS),
                args,
            ).await {
                Ok(result) => {
                    if let Some(found_selector) = result.get("selector").and_then(|v| v.as_str()) {
                        let score = result.get("score").and_then(|v| v.as_u64()).unwrap_or(0) as u32;
                        if score >= MIN_RECOGNITION_SCORE
                            && page_actions::fill(page, found_selector, &value).await.is_ok() {
                                tracing::debug!(selector = found_selector, score, "Recognition fill succeeded");
                                return Ok(None);
                            }
                    }
                }
                Err(e) => {
                    tracing::debug!(error = %e, "Recognition fallback failed");
                }
            }
        }
    }

    // Tier 3: Coordinate fallback (click to focus, then type)
    if let Some(coords) = &config.coordinates {
        let x = coords.x as f64;
        let y = coords.y as f64;
        tracing::debug!(x, y, "Attempting coordinate fallback for fill");

        if page_actions::click_at(page, x, y).await.is_ok() {
            // Select all existing content and replace
            let _ = page_actions::keyboard_press(page, "Control+a").await;
            let delay = if fast_mode { 0.0 } else { 30.0 };
            if page_actions::keyboard_type(page, &value, delay).await.is_ok() {
                tracing::debug!(x, y, "Coordinate fill succeeded");
                return Ok(None);
            }
        }
    }

    Err(StepError::ElementNotFound(format!(
        "Fill target not found: {}",
        selector
    )))
}

pub async fn execute_type(page: &Page, config: &WorkflowStepConfig, fast_mode: bool) -> StepResult {
    let value = config.value.as_deref().unwrap_or("");
    let selector = config.selector.as_deref();

    tracing::debug!(value_len = value.len(), selector = ?selector, "Executing type step");

    // If a selector is provided, click to focus first
    if let Some(sel) = selector {
        let _ = page_actions::click_selector(page, sel, false).await;
    }

    let delay = if fast_mode { 0.0 } else { 50.0 };
    page_actions::keyboard_type(page, value, delay)
        .await
        .map_err(|e| StepError::Execution(format!("Type failed: {}", e)))?;

    Ok(None)
}
