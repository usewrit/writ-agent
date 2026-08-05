use std::collections::HashMap;
use std::time::Duration;

use playwright_rs::Page;

use crate::browser::{page_actions, page_query};
use crate::models::workflow::WorkflowStepConfig;
use crate::util::logging::redact_url_for_log;
use crate::util::value_resolver;
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

/// Move keyboard focus to an element without clicking it.
///
/// Distinct from `click`: no pointer event is dispatched, so a site's click handlers stay quiet
/// while its focus/blur validation still fires — and the caret is left in the field for a
/// following `press`/`type` step.
pub async fn execute_focus(page: &Page, config: &WorkflowStepConfig) -> StepResult {
    let selector = config.selector.as_deref().unwrap_or("");
    tracing::debug!(selector = selector, "Executing focus step");

    if selector.is_empty() {
        return Err(StepError::Execution("focus: no selector provided".into()));
    }

    match page_actions::focus(page, selector).await {
        Ok(()) => {
            tracing::debug!(selector, "Focus succeeded");
            return Ok(None);
        }
        Err(e) => {
            tracing::debug!(error = %e, "Native focus failed, trying JS fallback");
        }
    }

    // JS fallback: `locator.focus()` refuses elements Playwright doesn't consider focusable
    // (a div given `tabindex` at runtime, a custom element wrapping the real input). The DOM
    // call has no such gate, so verify the outcome instead of trusting the call — `el.focus()`
    // is a silent no-op on a genuinely unfocusable node.
    let js = format!(
        r#"(() => {{
            const el = document.querySelector({sel});
            if (!el) return false;
            el.focus();
            return document.activeElement === el || el.contains(document.activeElement);
        }})()"#,
        sel = serde_json::to_string(selector).unwrap_or_default(),
    );

    let ok: bool = page.evaluate(&js, None::<&()>).await.unwrap_or(false);
    if ok {
        tracing::debug!(selector, "Focus succeeded via JS fallback");
        return Ok(None);
    }

    Err(StepError::ElementNotFound(format!(
        "Focus target not found or not focusable: {}",
        selector
    )))
}

/// Longest expected/actual text echoed back in an assertion failure. A `StepError` message fans
/// out to the daemon log, the run row, `GET /v1/runs` and the cloud `task_result` frame, so keep
/// a page's whole paragraph out of all four while still saying WHAT differed.
const ASSERT_ECHO_LIMIT: usize = 120;

fn truncate_for_error(s: &str) -> String {
    if s.chars().count() <= ASSERT_ECHO_LIMIT {
        return s.to_string();
    }
    let head: String = s.chars().take(ASSERT_ECHO_LIMIT).collect();
    format!("{}…", head)
}

/// Collapse whitespace runs (including the `&nbsp;` sites love) and trim, so an assertion written
/// as `Order confirmed` still matches DOM text that renders as `"\n  Order\u{a0}confirmed  "`.
/// Without this, text assertions fail on markup indentation rather than on the thing being tested.
fn normalize_assert_text(s: &str) -> String {
    s.replace('\u{a0}', " ")
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
}

/// Verify the page is in the state the author expected, and FAIL the run when it isn't.
///
/// Two modes, matching the step editor: with no `value` it asserts the selector merely resolves;
/// with a `value` it also requires the element's text (or, for a form control, its current value)
/// to match. `config.extra["match"]` picks `contains` (default — what an author typing an expected
/// string means) or `exact`.
pub async fn execute_assert(
    page: &Page,
    config: &WorkflowStepConfig,
    credentials: &HashMap<String, String>,
    form_data: &HashMap<String, String>,
    timeout_ms: u64,
) -> StepResult {
    let selector = config.selector.as_deref().unwrap_or("").trim();
    tracing::debug!(selector = selector, "Executing assert step");

    if selector.is_empty() {
        return Err(StepError::Execution("assert: no selector provided".into()));
    }

    let raw_expected = config.value.as_deref().unwrap_or("");
    let expected = value_resolver::resolve_value(raw_expected, credentials, Some(form_data));
    // An expected value that carried a `{{secret:…}}`/`{{key}}` placeholder may now BE a
    // credential, and this step's failure text is quoted back verbatim to the operator. Echo the
    // unresolved template in that case. (Resolution leaves unmatched placeholders alone, so an
    // unchanged string never held a resolved secret.)
    let expected_for_error = if expected == raw_expected { expected.as_str() } else { raw_expected };

    // Give the element the run's normal timeout to appear: an assertion usually sits right after
    // the click whose result it checks, and that result is often still rendering.
    if page_query::wait_for_selector(page, selector, Duration::from_millis(timeout_ms))
        .await
        .is_err()
    {
        return Err(StepError::ElementNotFound(format!(
            "Assertion failed: no element matched '{}'",
            selector
        )));
    }

    // Existence-only assertion (the editor's "Leave empty to only assert the element exists").
    if expected.trim().is_empty() {
        tracing::debug!(selector, "Assertion passed: element present");
        return Ok(None);
    }

    // "Expected text or value": read BOTH the rendered text and the control's current value —
    // `textContent` is empty on an `<input>`, `.value` is empty on a `<div>`. Passing on either
    // means one step covers both without asking the author which kind of element they picked.
    // A non-input errors on `input_value`; that's the empty candidate, not a failure.
    let actual_text = page_query::locator_text_content(page, selector)
        .await
        .ok()
        .flatten()
        .unwrap_or_default();
    let actual_value = page_query::locator_input_value(page, selector)
        .await
        .unwrap_or_default();

    let mode = config
        .extra
        .get("match")
        .and_then(|v| v.as_str())
        .unwrap_or("contains");
    let exact = match mode {
        "exact" => true,
        "contains" => false,
        other => {
            tracing::warn!(mode = other, "assert: unknown match mode — falling back to 'contains'");
            false
        }
    };

    let want = normalize_assert_text(&expected);
    let mut candidates = vec![
        normalize_assert_text(&actual_text),
        normalize_assert_text(&actual_value),
    ];

    // Both locator reads run in Playwright's strict mode, so a selector matching several elements
    // (`.price`, `td`) errors on BOTH and would fail the assertion with a bare `found ""` — a
    // verification step reporting the wrong reason. Read the DOM directly in that case:
    // `querySelector` takes the first match, which is the element the author was pointing at.
    if candidates.iter().all(|c| c.is_empty()) {
        let js = format!(
            r#"(() => {{
                const el = document.querySelector({sel});
                if (!el) return ["", ""];
                return [el.textContent || "", typeof el.value === "string" ? el.value : ""];
            }})()"#,
            sel = serde_json::to_string(selector).unwrap_or_default(),
        );
        if let Ok(pair) = page.evaluate::<_, Vec<String>>(&js, None::<&()>).await {
            candidates = pair.iter().map(|s| normalize_assert_text(s)).collect();
        }
    }

    let matched = candidates
        .iter()
        .any(|got| if exact { *got == want } else { got.contains(&want) });

    if matched {
        tracing::debug!(selector, exact, "Assertion passed");
        return Ok(None);
    }

    // Quote back whichever side actually held content — reporting the empty one would just say
    // `found ""` for an input whose text node is legitimately empty.
    let actual_for_error = candidates
        .iter()
        .find(|c| !c.is_empty())
        .map(String::as_str)
        .unwrap_or("");

    Err(StepError::Execution(format!(
        "Assertion failed on '{}': expected {} {:?}, found {:?}",
        selector,
        if exact { "exactly" } else { "to contain" },
        truncate_for_error(expected_for_error),
        truncate_for_error(actual_for_error),
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

fn extra_str<'a>(config: &'a WorkflowStepConfig, key: &str) -> Option<&'a str> {
    config.extra.get(key).and_then(|v| v.as_str())
}

/// The wire name of an end_point's condition.
///
/// `condition_type` is the contract: it is what all three step editors write (the `end_point` case
/// in `StepConfigForm.tsx`), what `createStep('end_point')` seeds, what the in-app docs document,
/// and what the Python engine reads (`automation_engine.py`, `step_type == 'end_point'`). This
/// executor used to read only `condition` — a name NO producer writes — so every conditioned
/// end_point fell through to the `immediate` arm and completed without checking anything.
/// `condition` stays accepted since a step could have been authored against that behaviour, and
/// `options.exit_condition.type` is the older shape the Python engine still honours.
fn end_point_condition(config: &WorkflowStepConfig) -> String {
    extra_str(config, "condition_type")
        .or_else(|| extra_str(config, "condition"))
        .or_else(|| {
            config
                .options
                .as_ref()
                .and_then(|o| o.get("exit_condition"))
                .and_then(|c| c.get("type"))
                .and_then(|v| v.as_str())
        })
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .unwrap_or("immediate")
        .to_string()
}

/// Which editor field a condition tests, or `None` for conditions that test nothing (`immediate`,
/// and anything unrecognised). Mirrors how the editor switches its single "Condition value" input
/// between `config.url`, `config.text` and `config.selector`.
fn end_point_value_field(condition: &str) -> Option<&'static str> {
    match condition {
        "url_contains" | "url_equals" => Some("url"),
        "text_visible" => Some("text"),
        "element_visible" | "element_exists" => Some("selector"),
        _ => None,
    }
}

/// Read the value a condition tests out of the field the editor actually writes.
///
/// `url` and `selector` are TYPED fields on `WorkflowStepConfig`, so they never reach the
/// `#[serde(flatten)]` `extra` map — the url arms used to look for them in `extra` only, always
/// found nothing, and so matched `""` against every page (`url_contains` passed anywhere) or
/// compared against `""` (`url_equals` failed everywhere). `text` has no typed field, so it does
/// land in `extra`. `value` and the older `url_pattern` stay as fallbacks for steps saved against
/// those spellings.
fn end_point_value<'a>(config: &'a WorkflowStepConfig, field: &str) -> &'a str {
    let candidate = match field {
        "url" => config
            .url
            .as_deref()
            .or_else(|| extra_str(config, "url"))
            .or_else(|| extra_str(config, "url_pattern")),
        "text" => extra_str(config, "text"),
        _ => config
            .selector
            .as_deref()
            .or_else(|| extra_str(config, "selector")),
    };
    candidate
        .or(config.value.as_deref())
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .unwrap_or("")
}

/// Honour the "Timeout" the editor writes next to the condition (`config.timeout_ms`, which it
/// defaults to 30s), falling back to the run's own timeout. This was a hardcoded 10s, so a step
/// authored to wait a minute for a slow confirmation page gave up after ten seconds.
fn end_point_timeout(config: &WorkflowStepConfig, run_timeout_ms: u64) -> Duration {
    let authored = config
        .options
        .as_ref()
        .and_then(|o| o.get("timeout_ms"))
        .or_else(|| config.extra.get("timeout_ms"))
        .and_then(|v| {
            v.as_u64()
                .or_else(|| v.as_f64().map(|f| f as u64))
                .or_else(|| v.as_str().and_then(|s| s.parse::<u64>().ok()))
        })
        .filter(|ms| *ms > 0);
    Duration::from_millis(authored.unwrap_or(run_timeout_ms))
}

/// Poll `check` until it reports true or `timeout` elapses.
///
/// The url/text conditions have no Playwright waiter of their own, and an end_point almost always
/// sits right after the click whose outcome it verifies — reading `page.url()` once, the moment
/// the step starts, races the navigation that is still in flight. Checking before the first sleep
/// keeps an already-satisfied condition instant.
async fn poll_until<F, Fut>(timeout: Duration, mut check: F) -> bool
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = bool>,
{
    let start = std::time::Instant::now();
    loop {
        if check().await {
            return true;
        }
        if start.elapsed() >= timeout {
            return false;
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
}

pub async fn execute_end_point(
    page: &Page,
    config: &WorkflowStepConfig,
    timeout_ms: u64,
) -> StepResult {
    let condition = end_point_condition(config);
    let timeout = end_point_timeout(config, timeout_ms);
    let field = end_point_value_field(&condition);
    let value = field.map(|f| end_point_value(config, f)).unwrap_or("");

    tracing::debug!(
        condition = %condition,
        timeout_ms = timeout.as_millis() as u64,
        "Executing end_point step"
    );

    // A condition with nothing to test is an authoring mistake, and BOTH silent outcomes it used
    // to produce were wrong answers rather than errors. Name the missing field instead.
    if let Some(field) = field {
        if value.is_empty() {
            return Err(StepError::Execution(format!(
                "end_point {}: no '{}' configured for the condition",
                condition, field
            )));
        }
    }

    match condition.as_str() {
        "immediate" => {
            tracing::debug!("End point: immediate");
            Ok(None)
        }

        "element_visible" => {
            tracing::debug!(selector = value, "End point: waiting for element visible");
            page_query::wait_for_selector(page, value, timeout)
                .await
                .map_err(|e| StepError::Timeout(format!("end_point element_visible: {}", e)))?;
            Ok(None)
        }

        "element_exists" => {
            // "Exists", not "visible" — wait for attachment so a deliberately hidden marker
            // element satisfies the condition the author picked.
            tracing::debug!(selector = value, "End point: waiting for element exists");
            page_query::wait_for_selector_attached(page, value, timeout)
                .await
                .map_err(|e| StepError::Timeout(format!("end_point element_exists: {}", e)))?;
            Ok(None)
        }

        "text_visible" => {
            tracing::debug!(text = value, "End point: waiting for visible text");
            let js = format!(
                r#"(document.body && document.body.innerText || "").includes({text})"#,
                text = serde_json::to_string(value).unwrap_or_default(),
            );
            let found = poll_until(timeout, || async {
                page.evaluate::<_, bool>(&js, None::<&()>).await.unwrap_or(false)
            })
            .await;
            if !found {
                return Err(StepError::Timeout(format!(
                    "end_point text_visible: text {:?} not found after {}ms",
                    truncate_for_error(value),
                    timeout.as_millis()
                )));
            }
            Ok(None)
        }

        "url_contains" => {
            tracing::debug!(pattern = value, "End point: waiting for URL to contain");
            let matched = poll_until(timeout, || async { page.url().contains(value) }).await;
            if !matched {
                // Host/path only: a StepError message fans out to the daemon log, the run row, the
                // `GET /v1/runs` payload and the cloud `task_result` frame, and a live page URL's
                // query can carry a session token. Say so, so an author matching on a query
                // parameter isn't left thinking the URL was genuinely bare.
                return Err(StepError::Timeout(format!(
                    "end_point url_contains: URL '{}' (query redacted) did not contain {:?} after {}ms",
                    redact_url_for_log(&page.url()),
                    truncate_for_error(value),
                    timeout.as_millis()
                )));
            }
            Ok(None)
        }

        "url_equals" => {
            tracing::debug!(expected = value, "End point: waiting for URL to equal");
            let matched = poll_until(timeout, || async { page.url() == value }).await;
            if !matched {
                return Err(StepError::Timeout(format!(
                    "end_point url_equals: URL '{}' (query redacted) never became {:?} after {}ms",
                    redact_url_for_log(&page.url()),
                    truncate_for_error(value),
                    timeout.as_millis()
                )));
            }
            Ok(None)
        }

        other => {
            // Unreachable via the editor's dropdown; reached by a hand-written or AI-repaired
            // recipe. Completing silently is what made the `condition` mismatch invisible for so
            // long, so say it out loud.
            tracing::warn!(
                condition = other,
                "end_point: unknown condition — completing without checking anything"
            );
            Ok(None)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn assert_text_normalizes_markup_whitespace() {
        // The realistic failure this guards: an author types the visible label, the DOM carries
        // indentation and an &nbsp;, and a naive comparison fails on formatting.
        assert_eq!(
            normalize_assert_text("\n   Order\u{a0}confirmed  \t"),
            "Order confirmed"
        );
        assert_eq!(normalize_assert_text("   "), "");
        assert_eq!(normalize_assert_text("Total: 12,40 €"), "Total: 12,40 €");
    }

    #[test]
    fn assert_error_echo_is_truncated_on_char_boundaries() {
        let short = "Payment declined";
        assert_eq!(truncate_for_error(short), short);

        // Multi-byte chars must not be split — `chars()` bounds the cut, `len()` would panic.
        let long = "é".repeat(ASSERT_ECHO_LIMIT + 40);
        let cut = truncate_for_error(&long);
        assert_eq!(cut.chars().count(), ASSERT_ECHO_LIMIT + 1); // + the ellipsis
        assert!(cut.ends_with('…'));

        // Exactly at the limit is left alone.
        let edge = "a".repeat(ASSERT_ECHO_LIMIT);
        assert_eq!(truncate_for_error(&edge), edge);
    }

    /// Build the config the way the runner really does — through serde — so these tests exercise
    /// the `#[serde(flatten)]` routing that caused the bug, not a hand-built struct that would
    /// hide it.
    fn cfg(v: serde_json::Value) -> WorkflowStepConfig {
        serde_json::from_value(v).expect("step config parses")
    }

    #[test]
    fn end_point_reads_the_condition_name_the_editors_write() {
        // What all three StepConfigForms, createStep() and the Python engine emit.
        assert_eq!(
            end_point_condition(&cfg(serde_json::json!({"condition_type": "url_contains"}))),
            "url_contains"
        );
        // The name this executor used to read; still accepted.
        assert_eq!(
            end_point_condition(&cfg(serde_json::json!({"condition": "element_visible"}))),
            "element_visible"
        );
        // Legacy shape the Python engine also honours.
        assert_eq!(
            end_point_condition(&cfg(
                serde_json::json!({"options": {"exit_condition": {"type": "text_visible"}}})
            )),
            "text_visible"
        );
        // Canonical name wins when a step somehow carries both.
        assert_eq!(
            end_point_condition(&cfg(
                serde_json::json!({"condition_type": "url_equals", "condition": "immediate"})
            )),
            "url_equals"
        );
        // Nothing authored, and a blank string, both mean "just finish".
        assert_eq!(end_point_condition(&cfg(serde_json::json!({}))), "immediate");
        assert_eq!(
            end_point_condition(&cfg(serde_json::json!({"condition_type": "  "}))),
            "immediate"
        );
    }

    #[test]
    fn end_point_url_conditions_read_the_typed_url_field() {
        // The regression: `url` is a typed field, so it never lands in `extra`. Reading it only
        // from `extra` yielded "" — which `contains` matches on every page and `==` matches on
        // none.
        let c = cfg(serde_json::json!({"condition_type": "url_contains", "url": "/dashboard"}));
        assert!(!c.extra.contains_key("url"), "url must be a typed field, not extra");
        assert_eq!(end_point_value(&c, "url"), "/dashboard");

        // Older spellings still resolve.
        assert_eq!(
            end_point_value(&cfg(serde_json::json!({"url_pattern": "/done"})), "url"),
            "/done"
        );
        assert_eq!(
            end_point_value(&cfg(serde_json::json!({"value": "/thanks"})), "url"),
            "/thanks"
        );

        // text/selector conditions read what the editor writes for them.
        assert_eq!(
            end_point_value(&cfg(serde_json::json!({"text": "Order confirmed"})), "text"),
            "Order confirmed"
        );
        assert_eq!(
            end_point_value(&cfg(serde_json::json!({"selector": "#done"})), "selector"),
            "#done"
        );

        // Nothing to test — the caller turns this into a named error instead of a vacuous pass.
        assert_eq!(end_point_value(&cfg(serde_json::json!({})), "url"), "");
        assert_eq!(end_point_value(&cfg(serde_json::json!({"url": "   "})), "url"), "");
    }

    #[test]
    fn end_point_value_field_matches_the_editor_dropdown() {
        assert_eq!(end_point_value_field("url_contains"), Some("url"));
        assert_eq!(end_point_value_field("url_equals"), Some("url"));
        assert_eq!(end_point_value_field("text_visible"), Some("text"));
        assert_eq!(end_point_value_field("element_visible"), Some("selector"));
        assert_eq!(end_point_value_field("element_exists"), Some("selector"));
        // Conditions that test nothing must not be forced through the missing-value guard.
        assert_eq!(end_point_value_field("immediate"), None);
        assert_eq!(end_point_value_field("something_else"), None);
    }

    #[test]
    fn end_point_timeout_prefers_the_authored_value() {
        let run = 30_000;
        // The editor's NumberInput writes a JSON number.
        assert_eq!(
            end_point_timeout(&cfg(serde_json::json!({"timeout_ms": 60000})), run),
            Duration::from_millis(60_000)
        );
        // Imported/older recipes can carry it as a string or under `options`.
        assert_eq!(
            end_point_timeout(&cfg(serde_json::json!({"timeout_ms": "45000"})), run),
            Duration::from_millis(45_000)
        );
        assert_eq!(
            end_point_timeout(&cfg(serde_json::json!({"options": {"timeout_ms": 5000}})), run),
            Duration::from_millis(5_000)
        );
        // Unset or zero falls back to the run's timeout rather than giving up instantly.
        assert_eq!(end_point_timeout(&cfg(serde_json::json!({})), run), Duration::from_millis(run));
        assert_eq!(
            end_point_timeout(&cfg(serde_json::json!({"timeout_ms": 0})), run),
            Duration::from_millis(run)
        );
    }
}
