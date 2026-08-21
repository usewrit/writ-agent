
use std::time::Duration;

use playwright_rs::Page;

use crate::browser::{page_actions, page_query};
use crate::models::workflow::WorkflowStepConfig;
use super::step_executor::{StepError, StepResult};
use super::recognition::{ClickableConfig, CLICKABLE_SCORER_JS, MIN_CLICKABLE_SCORE};

/// Post-click settle window (ms) when the step carries no explicit `wait_after`.
/// Matches the Python automation engine's `wait_after` default — a click that triggers a
/// transition / route change needs a beat before the next step reads the page.
const DEFAULT_WAIT_AFTER_MS: u64 = 500;

pub async fn execute(
    page: &Page,
    config: &WorkflowStepConfig,
    timeout_ms: u64,
    fast_mode: bool,
) -> StepResult {
    let result = do_click(page, config, timeout_ms, fast_mode).await;

    // Settle after a click that landed (parity with the Python agent, which settles after
    // every click). A failed click already returns Err below and skips the wait.
    //
    // Not a plain sleep: the click returns before the request it triggers leaves, so a
    // fixed pause lets the next step read the page the click was performed ON — and at
    // the end of a sign-in it banks the pre-login session. `wait_after` becomes the
    // PROBE window; with no traffic this costs exactly what the old sleep did.
    if result.is_ok() {
        let wait_after = config
            .extra
            .get("wait_after")
            .and_then(|v| v.as_u64())
            .unwrap_or(DEFAULT_WAIT_AFTER_MS);
        if wait_after > 0 {
            super::inflight::settle_after_action(
                page,
                Duration::from_millis(wait_after),
                Duration::from_millis(9_000),
            )
            .await;
        }
    }

    result
}

async fn do_click(
    page: &Page,
    config: &WorkflowStepConfig,
    _timeout_ms: u64,
    _fast_mode: bool,
) -> StepResult {
    let selector = config.selector.as_deref();
    let description = config.description.as_deref().unwrap_or("");

    tracing::debug!(
        selector = ?selector,
        description = description,
        "Executing click step"
    );

    // Tier 1: If we have a selector, try direct locator click
    if let Some(sel) = selector {
        // Skip only a TOO-BROAD selector (>10 matches). count == 0 still attempts the click:
        // Playwright's locator click auto-waits for the element, so a slow page that hasn't
        // rendered the control yet (count==0 at this instant) must not skip the direct path.
        let count = page_query::locator_count(page, sel).await.unwrap_or(0);
        if count <= 10 {
            // Try normal click first
            match page_actions::click_selector(page, sel, false).await {
                Ok(()) => {
                    tracing::debug!(selector = sel, "Click succeeded via locator");
                    return Ok(None);
                }
                Err(e) => {
                    tracing::debug!(error = %e, "Normal click failed, trying force click");
                    // Only retry force-click / dispatch on the SAME selector if the element is
                    // actually present now. If the normal click already burned the full element
                    // timeout because the selector matches nothing (site changed), re-waiting it
                    // twice more just stacks timeouts. Skip straight to the selector-independent
                    // recognition/coordinate fallbacks below (and failure → AI repair) instead.
                    if page_query::locator_count(page, sel).await.unwrap_or(0) > 0 {
                        // Try force click
                        if page_actions::click_selector(page, sel, true).await.is_ok() {
                            tracing::debug!(selector = sel, "Force click succeeded");
                            return Ok(None);
                        }
                        // Try dispatch_event fallback
                        if page_actions::dispatch_event(page, sel, "click").await.is_ok() {
                            tracing::debug!(selector = sel, "dispatch_event click succeeded");
                            return Ok(None);
                        }
                    }
                }
            }
        }
    }

    // Tier 2: Recognition-based fallback
    if let Some(recognition_data) = &config.recognition {
        let clickable_config = ClickableConfig::from_json(recognition_data);
        let args = clickable_config.to_js_args();

        match page_query::evaluate_with_args::<serde_json::Value>(
            page,
            &format!("(args) => {{ {} return findClickableElement(args); }}", CLICKABLE_SCORER_JS),
            args,
        ).await {
            Ok(result) => {
                if let Some(found_selector) = result.get("selector").and_then(|v| v.as_str()) {
                    let score = result.get("score").and_then(|v| v.as_u64()).unwrap_or(0) as u32;
                    if score >= MIN_CLICKABLE_SCORE
                        && page_actions::click_selector(page, found_selector, false).await.is_ok() {
                            tracing::debug!(selector = found_selector, score, "Recognition click succeeded");
                            return Ok(None);
                        }
                }
            }
            Err(e) => {
                tracing::debug!(error = %e, "Recognition fallback failed");
            }
        }
    }

    // Tier 3: Coordinate fallback from recorded position
    if let Some(coords) = &config.coordinates {
        let x = coords.x as f64;
        let y = coords.y as f64;
        tracing::debug!(x, y, "Attempting coordinate fallback click");
        if page_actions::click_at(page, x, y).await.is_ok() {
            tracing::debug!(x, y, "Coordinate click succeeded");
            return Ok(None);
        }
    }

    // Tier 4: JS MouseEvent fallback on original selector
    if let Some(sel) = selector {
        let js = format!(
            r#"(() => {{
                const el = document.querySelector({sel});
                if (!el) return false;
                const rect = el.getBoundingClientRect();
                const cx = rect.left + rect.width / 2;
                const cy = rect.top + rect.height / 2;
                ['mousedown', 'mouseup', 'click'].forEach(type => {{
                    el.dispatchEvent(new MouseEvent(type, {{
                        bubbles: true, cancelable: true, view: window,
                        clientX: cx, clientY: cy
                    }}));
                }});
                return true;
            }})()"#,
            sel = serde_json::to_string(sel).unwrap_or_else(|_| format!("\"{}\"", sel)),
        );

        let dispatched: bool = page.evaluate(&js, None::<&()>).await.unwrap_or(false);
        if dispatched {
            tracing::debug!(selector = sel, "JS MouseEvent dispatch succeeded");
            return Ok(None);
        }
    }

    // All tiers exhausted
    let target = selector
        .map(String::from)
        .or_else(|| config.description.clone())
        .unwrap_or_else(|| "unknown".to_string());
    Err(StepError::ElementNotFound(format!(
        "Click target not found: {}",
        target
    )))
}
