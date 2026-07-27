use std::collections::HashMap;
use std::time::Duration;

use playwright_rs::Page;

use crate::browser::page_actions;
use crate::models::workflow::WorkflowStepConfig;
use crate::util::value_resolver;
use super::step_executor::{StepError, StepResult};

pub async fn execute(
    page: &Page,
    config: &WorkflowStepConfig,
    credentials: &HashMap<String, String>,
    form_data: &HashMap<String, String>,
    _timeout_ms: u64,
) -> StepResult {
    let selector = config.selector.as_deref().unwrap_or("");
    let raw_value = config.value.as_deref().unwrap_or("");
    let value = value_resolver::resolve_value(raw_value, credentials, Some(form_data));

    // NEVER log `value`: it is post-`value_resolver`, so a `{{vault:…}}` / `{{form:…}}` placeholder is
    // already the real secret (a select step can carry an account number, a passphrase answer, …).
    // A raw value has no token shape, so the sink-level redactor cannot mask it either — length only.
    tracing::debug!(selector = selector, value_len = value.len(), "Executing select step");

    // Detect custom vs native dropdown
    let is_custom = config.extra.get("from_custom_dropdown")
        .and_then(|v| v.as_bool())
        .unwrap_or(false)
        || config.extra.get("from_vision")
            .and_then(|v| v.as_bool())
            .unwrap_or(false)
        || config.extra.get("role")
            .and_then(|v| v.as_str())
            .map(|r| r == "listbox" || r == "combobox")
            .unwrap_or(false);

    if !is_custom {
        // Native <select> element — use select_option
        match page_actions::select_option(page, selector, &value).await {
            Ok(()) => {
                tracing::debug!(selector, value_len = value.len(), "Native select succeeded");
                return Ok(None);
            }
            Err(e) => {
                tracing::debug!(error = %e, "Native select failed, trying keyboard fallback");

                // Keyboard fallback: focus, type value, press Enter
                if page_actions::click_selector(page, selector, false).await.is_ok() {
                    let _ = page_actions::keyboard_type(page, &value, 50.0).await;
                    let _ = page_actions::keyboard_press(page, "Enter").await;
                    tracing::debug!("Keyboard select fallback attempted");
                    return Ok(None);
                }
            }
        }
    }

    // Custom dropdown handling: click to open, then find and click the option
    tracing::debug!(selector, "Handling custom dropdown");

    // Click the dropdown trigger to open it
    if let Err(e) = page_actions::click_selector(page, selector, false).await {
        tracing::debug!(error = %e, "Failed to click dropdown trigger");
        return Err(StepError::ElementNotFound(format!(
            "Custom dropdown trigger not found: {}",
            selector
        )));
    }

    // Short delay for dropdown animation
    tokio::time::sleep(Duration::from_millis(300)).await;

    // Try to find the option by various strategies
    let option_selectors = [
        format!("[role=\"option\"]:has-text(\"{}\")", value),
        format!("[role=\"listbox\"] [role=\"option\"]:has-text(\"{}\")", value),
        format!("li:has-text(\"{}\")", value),
        format!("[data-value=\"{}\"]", value),
    ];

    for (idx, opt_sel) in option_selectors.iter().enumerate() {
        match page_actions::click_selector(page, opt_sel, false).await {
            Ok(()) => {
                // The option selectors EMBED the resolved value (`:has-text("…")`), so log the strategy
                // INDEX rather than the selector text.
                tracing::debug!(strategy = idx, "Custom option click succeeded");
                return Ok(None);
            }
            Err(_) => continue,
        }
    }

    // JS MouseEvent dispatch fallback on role="option" elements
    let js_click_option = format!(
        r#"(() => {{
            const options = document.querySelectorAll('[role="option"], li, [data-value]');
            for (const opt of options) {{
                const text = opt.textContent || opt.getAttribute('data-value') || '';
                if (text.trim().toLowerCase().includes({val}.toLowerCase())) {{
                    opt.dispatchEvent(new MouseEvent('mousedown', {{bubbles: true}}));
                    opt.dispatchEvent(new MouseEvent('mouseup', {{bubbles: true}}));
                    opt.dispatchEvent(new MouseEvent('click', {{bubbles: true}}));
                    return true;
                }}
            }}
            return false;
        }})()"#,
        val = serde_json::to_string(&value).unwrap_or_default(),
    );

    let dispatched: bool = page.evaluate(&js_click_option, None::<&()>).await.unwrap_or(false);
    if dispatched {
        tracing::debug!(value_len = value.len(), "JS option dispatch succeeded");
        return Ok(None);
    }

    // Final fallback: type + Enter
    let _ = page_actions::keyboard_type(page, &value, 50.0).await;
    let _ = page_actions::keyboard_press(page, "Enter").await;
    tracing::debug!(value_len = value.len(), "Keyboard type+Enter fallback for custom select");

    Ok(None)
}
