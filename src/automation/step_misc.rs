use std::collections::HashMap;
use std::time::Duration;

use playwright_rs::Page;

use crate::browser::{page_actions, page_query};
use crate::models::workflow::WorkflowStepConfig;
use crate::util::logging::redact_url_for_log;
use super::step_executor::{StepError, StepResult};

pub async fn execute_screenshot(page: &Page, config: &WorkflowStepConfig) -> StepResult {
    tracing::debug!("Executing screenshot step");

    let quality = config.extra.get("quality")
        .and_then(|v| v.as_u64())
        .unwrap_or(80) as u8;

    let screenshot_data = page_query::screenshot_jpeg(page, quality)
        .await
        .map_err(|e| StepError::Execution(format!("Screenshot failed: {}", e)))?;

    let mut result = HashMap::new();
    result.insert(
        "screenshot".to_string(),
        serde_json::json!({
            "data_len": screenshot_data.len(),
            "type": "jpeg",
        }),
    );
    // Store raw bytes as base64 for JSON transport
    result.insert(
        "screenshot_base64".to_string(),
        serde_json::Value::String(base64::Engine::encode(
            &base64::engine::general_purpose::STANDARD,
            &screenshot_data,
        )),
    );

    Ok(Some(result))
}

pub async fn execute_press(page: &Page, config: &WorkflowStepConfig) -> StepResult {
    let key = config
        .key
        .as_deref()
        .or(config.value.as_deref())
        .unwrap_or("Enter");

    tracing::debug!(key = key, "Executing press step");

    page_actions::keyboard_press(page, key)
        .await
        .map_err(|e| StepError::Execution(format!("Press '{}' failed: {}", key, e)))?;

    Ok(None)
}

pub async fn execute_scroll(page: &Page, config: &WorkflowStepConfig, fast_mode: bool) -> StepResult {
    let delta_y = config
        .options
        .as_ref()
        .and_then(|o| o.get("deltaY"))
        .and_then(|v| v.as_f64())
        .unwrap_or(300.0);

    let delta_x = config
        .options
        .as_ref()
        .and_then(|o| o.get("deltaX"))
        .and_then(|v| v.as_f64())
        .unwrap_or(0.0);

    // Check for container scroll (scroll within a specific element)
    if let Some(selector) = config.selector.as_deref() {
        tracing::debug!(selector, delta_y, "Scrolling within container element");
        let js = format!(
            r#"(() => {{
                const el = document.querySelector({sel});
                if (el) {{
                    el.scrollBy({{ top: {dy}, left: {dx}, behavior: 'auto' }});
                    return true;
                }}
                return false;
            }})()"#,
            sel = serde_json::to_string(selector).unwrap_or_default(),
            dy = delta_y,
            dx = delta_x,
        );
        let scrolled: bool = page.evaluate(&js, None::<&()>).await.unwrap_or(false);
        if scrolled {
            return Ok(None);
        }
    }

    tracing::debug!(delta_x, delta_y, "Executing page scroll");

    if fast_mode {
        // Single scroll event
        page_actions::mouse_wheel(page, delta_x, delta_y)
            .await
            .map_err(|e| StepError::Execution(format!("Scroll failed: {}", e)))?;
    } else {
        // Stealth: incremental scrolling in smaller steps
        let steps = 5;
        let step_dy = delta_y / steps as f64;
        let step_dx = delta_x / steps as f64;
        for _ in 0..steps {
            let _ = page_actions::mouse_wheel(page, step_dx, step_dy).await;
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    }

    Ok(None)
}

pub async fn execute_scroll_into_view(page: &Page, config: &WorkflowStepConfig) -> StepResult {
    let selector = config.selector.as_deref().unwrap_or("");
    tracing::debug!(selector = selector, "Executing scroll_into_view step");

    if selector.is_empty() {
        return Err(StepError::Execution("scroll_into_view: no selector provided".into()));
    }

    // Try native scroll_into_view_if_needed
    match page_actions::scroll_into_view(page, selector).await {
        Ok(()) => {
            tracing::debug!(selector, "scroll_into_view succeeded");
            return Ok(None);
        }
        Err(e) => {
            tracing::debug!(error = %e, "Native scroll_into_view failed, trying JS fallback");
        }
    }

    // JS fallback
    let js = format!(
        r#"(() => {{
            const el = document.querySelector({sel});
            if (el) {{
                el.scrollIntoView({{ behavior: 'smooth', block: 'center' }});
                return true;
            }}
            return false;
        }})()"#,
        sel = serde_json::to_string(selector).unwrap_or_default(),
    );

    let ok: bool = page.evaluate(&js, None::<&()>).await.unwrap_or(false);
    if ok {
        return Ok(None);
    }

    Err(StepError::ElementNotFound(format!(
        "scroll_into_view target not found: {}",
        selector
    )))
}

pub async fn execute_hover(page: &Page, config: &WorkflowStepConfig, _fast_mode: bool) -> StepResult {
    let selector = config.selector.as_deref().unwrap_or("");
    tracing::debug!(selector = selector, "Executing hover step");

    if !selector.is_empty() {
        match page_actions::hover(page, selector).await {
            Ok(()) => {
                tracing::debug!(selector, "Hover succeeded");
                return Ok(None);
            }
            Err(e) => {
                tracing::debug!(error = %e, "Hover via selector failed, trying bounding box fallback");
            }
        }

        // Bounding box fallback: get element center and move mouse there
        if let Ok(Some((x, y, w, h))) = page_actions::bounding_box(page, selector).await {
            let cx = x + w / 2.0;
            let cy = y + h / 2.0;
            if page_actions::hover_at(page, cx, cy).await.is_ok() {
                tracing::debug!(x = cx, y = cy, "Hover via bounding box succeeded");
                return Ok(None);
            }
        }
    }

    // Coordinate fallback
    if let Some(coords) = &config.coordinates {
        let x = coords.x as f64;
        let y = coords.y as f64;
        page_actions::hover_at(page, x, y)
            .await
            .map_err(|e| StepError::Execution(format!("Hover at ({}, {}) failed: {}", x, y, e)))?;
        return Ok(None);
    }

    if selector.is_empty() {
        return Err(StepError::Execution("hover: no selector or coordinates provided".into()));
    }

    Err(StepError::ElementNotFound(format!(
        "Hover target not found: {}",
        selector
    )))
}

pub async fn execute_wait_for_tab(page: &Page, _config: &WorkflowStepConfig, timeout_ms: u64) -> StepResult {
    tracing::debug!("Executing wait_for_tab step");

    // Poll the browser context for new pages
    let timeout = Duration::from_millis(timeout_ms);
    let poll_interval = Duration::from_millis(500);
    let start = std::time::Instant::now();

    // Get the current context from the page and poll for new pages
    let context = page.context()
        .map_err(|e| StepError::Execution(format!("Failed to get browser context: {}", e)))?;
    let initial_count = context.pages().len();

    while start.elapsed() < timeout {
        {
            let pages = context.pages();
            if pages.len() > initial_count {
                // New tab detected - bring the newest to front
                if let Some(new_page) = pages.last() {
                    let _ = new_page.bring_to_front().await;
                    tracing::debug!(count = pages.len(), "New tab detected and focused");
                }
                return Ok(None);
            }
        }
        tokio::time::sleep(poll_interval).await;
    }

    Err(StepError::Timeout("No new tab appeared within timeout".into()))
}

pub async fn execute_open_tab(page: &Page, config: &WorkflowStepConfig, timeout_ms: u64) -> StepResult {
    tracing::debug!("Executing open_tab step");

    // The user opened a tab themselves during recording (no triggering action on the
    // page). On replay we must open one ourselves and navigate to the recorded URL.
    let context = page.context()
        .map_err(|e| StepError::Execution(format!("Failed to get browser context: {}", e)))?;

    let new_page = context.new_page().await
        .map_err(|e| StepError::Execution(format!("Failed to open new tab: {}", e)))?;

    // Re-inject stealth on the fresh tab.
    let _: Result<serde_json::Value, _> =
        new_page.evaluate(crate::browser::stealth::STEALTH_SCRIPTS, None::<&()>).await;

    if let Some(url) = config.url.as_deref() {
        if !url.is_empty() && url != "about:blank" {
            // SSRF guard (fail-CLOSED): never point a cloud-dispatched recipe's new tab at an
            // internal/metadata/LAN host. Close the fresh tab and fail the step on a blocked target.
            if !crate::security::url_guard::is_navigation_url_safe_async(url).await {
                let _ = new_page.close().await;
                // Host/path only: a StepError message fans out to the daemon log, the run row's
                // `error` column, `GET /v1/runs`, the cloud `task_result` frame and an AI-repair
                // prompt — and this URL's query can carry a resolved `{{vault:…}}` secret.
                return Err(StepError::NavigationFailed(format!(
                    "open_tab URL blocked by SSRF guard: {}",
                    redact_url_for_log(url)
                )));
            }
            if let Err(e) = crate::browser::navigation::goto(
                &new_page, url, "domcontentloaded", Duration::from_millis(timeout_ms),
            ).await {
                tracing::warn!(url = %redact_url_for_log(url), error = %e, "open_tab navigation failed");
            }
            // Settle the fresh tab before the next step reads it (real quiescence, not the fake
            // vendored networkidle) — same wait the recorder used when it captured the tab.
            crate::browser::navigation::wait_for_page_quiet(&new_page, Duration::from_secs(15)).await;
        }
    }

    let _ = new_page.bring_to_front().await;
    tracing::debug!(url = %redact_url_for_log(&new_page.url()), "Opened new tab");
    Ok(None)
}

pub async fn execute_tab_closed(page: &Page, _config: &WorkflowStepConfig) -> StepResult {
    tracing::debug!("Executing tab_closed step");

    // Close the current page
    page.close().await
        .map_err(|e| StepError::Execution(format!("Failed to close tab: {}", e)))?;

    // The engine will need to switch to a remaining page
    // Return metadata indicating the page was closed
    let mut result = HashMap::new();
    result.insert("tab_closed".to_string(), serde_json::json!(true));
    Ok(Some(result))
}

pub async fn execute_switch_tab(page: &Page, config: &WorkflowStepConfig) -> StepResult {
    let tab_index = config
        .extra
        .get("tab_index")
        .and_then(|v| v.as_u64())
        .unwrap_or(0) as usize;

    tracing::debug!(tab_index = tab_index, "Executing switch_tab step");

    let context = page.context()
        .map_err(|e| StepError::Execution(format!("Failed to get browser context: {}", e)))?;
    let pages = context.pages();

    if tab_index >= pages.len() {
        return Err(StepError::Execution(format!(
            "Tab index {} out of range (have {} tabs)",
            tab_index,
            pages.len()
        )));
    }

    pages[tab_index].bring_to_front().await
        .map_err(|e| StepError::Execution(format!("Failed to switch to tab {}: {}", tab_index, e)))?;

    tracing::debug!(tab_index, "Switched to tab");
    Ok(None)
}

/// Re-resolve which page subsequent workflow steps should run against after a
/// tab-affecting step. Mirrors the Python `context._active_page_ref` updates made
/// inside `_execute_step` for tab operations (automation_engine.py ~3988-4039):
/// `wait_for_tab`/`open_tab` make the newest page active, `switch_tab` makes the
/// indexed tab active, and `tab_closed` falls back to the last surviving page.
///
/// Returns `None` for non-tab steps (the caller keeps its current active page) or
/// when no suitable page exists. The page picked here is the same one the matching
/// handler brought to the front, so step execution follows browser focus instead of
/// staying stuck on the original tab.
pub fn resolve_active_page_after_step(
    context: &playwright_rs::BrowserContext,
    step_type: &str,
    config: &WorkflowStepConfig,
) -> Option<Page> {
    match step_type {
        // A new tab was awaited (wait_for_tab) or opened (open_tab); the handler
        // focused the newest page, so subsequent steps run there.
        "wait_for_tab" | "open_tab" => context.pages().into_iter().last(),
        // The current tab was closed; continue on the last surviving page.
        "tab_closed" => context
            .pages()
            .into_iter()
            .filter(|p| !p.is_closed())
            .last(),
        // Explicit switch to a recorded tab index (same indexing as execute_switch_tab,
        // which brings `context.pages()[tab_index]` to the front).
        "switch_tab" => {
            let tab_index = config
                .extra
                .get("tab_index")
                .and_then(|v| v.as_u64())
                .unwrap_or(0) as usize;
            context.pages().into_iter().nth(tab_index)
        }
        _ => None,
    }
}

pub async fn execute_end_point(page: &Page, config: &WorkflowStepConfig) -> StepResult {
    tracing::debug!("Executing end_point step");

    let condition = config
        .extra
        .get("condition")
        .and_then(|v| v.as_str())
        .unwrap_or("immediate");

    let timeout = Duration::from_secs(10);

    match condition {
        "immediate" => {
            tracing::debug!("End point: immediate");
            Ok(None)
        }

        "element_visible" => {
            let selector = config.selector.as_deref()
                .or_else(|| config.extra.get("selector").and_then(|v| v.as_str()))
                .unwrap_or("");
            tracing::debug!(selector, "End point: waiting for element visible");
            page_query::wait_for_selector(page, selector, timeout)
                .await
                .map_err(|e| StepError::Timeout(format!("end_point element_visible: {}", e)))?;
            Ok(None)
        }

        "element_exists" => {
            let selector = config.selector.as_deref()
                .or_else(|| config.extra.get("selector").and_then(|v| v.as_str()))
                .unwrap_or("");
            tracing::debug!(selector, "End point: waiting for element exists");
            page_query::wait_for_selector(page, selector, timeout)
                .await
                .map_err(|e| StepError::Timeout(format!("end_point element_exists: {}", e)))?;
            Ok(None)
        }

        "text_visible" => {
            let expected_text = config.value.as_deref()
                .or_else(|| config.extra.get("text").and_then(|v| v.as_str()))
                .unwrap_or("");
            tracing::debug!(text = expected_text, "End point: checking for visible text");

            let js = format!(
                r#"document.body.innerText.includes({text})"#,
                text = serde_json::to_string(expected_text).unwrap_or_default(),
            );

            let found: bool = page.evaluate(&js, None::<&()>).await.unwrap_or(false);
            if !found {
                return Err(StepError::Execution(format!(
                    "end_point text_visible: text '{}' not found",
                    expected_text
                )));
            }
            Ok(None)
        }

        "url_contains" => {
            let pattern = config.value.as_deref()
                .or_else(|| config.extra.get("url_pattern").and_then(|v| v.as_str()))
                .unwrap_or("");
            let current_url = page.url();
            if !current_url.contains(pattern) {
                return Err(StepError::Execution(format!(
                    "end_point url_contains: URL '{}' does not contain '{}'",
                    current_url, pattern
                )));
            }
            Ok(None)
        }

        "url_equals" => {
            let expected = config.value.as_deref()
                .or_else(|| config.extra.get("url").and_then(|v| v.as_str()))
                .unwrap_or("");
            let current_url = page.url();
            if current_url != expected {
                return Err(StepError::Execution(format!(
                    "end_point url_equals: URL '{}' != '{}'",
                    current_url, expected
                )));
            }
            Ok(None)
        }

        _ => {
            tracing::debug!(condition, "End point: unknown condition, treating as immediate");
            Ok(None)
        }
    }
}
