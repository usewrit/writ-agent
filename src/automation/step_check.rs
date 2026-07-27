use playwright_rs::Page;

use crate::browser::page_actions;
use crate::models::workflow::WorkflowStepConfig;
use super::step_executor::{StepError, StepResult};

pub async fn execute_check(page: &Page, config: &WorkflowStepConfig, _timeout_ms: u64) -> StepResult {
    let selector = config.selector.as_deref().unwrap_or("");

    tracing::debug!(selector = selector, "Executing check step");

    // Try native .check() first
    match page_actions::check(page, selector).await {
        Ok(()) => {
            tracing::debug!(selector, "Native check succeeded");
            return Ok(None);
        }
        Err(e) => {
            tracing::debug!(error = %e, "Native check failed, trying JS fallback");
        }
    }

    // JS fallback: handle role="checkbox" divs and custom checkboxes
    let js = format!(
        r#"(() => {{
            const el = document.querySelector({sel});
            if (!el) return false;

            // Native checkbox input
            if (el.type === 'checkbox') {{
                el.checked = true;
                el.dispatchEvent(new Event('change', {{ bubbles: true }}));
                return true;
            }}

            // ARIA checkbox (div/span with role="checkbox")
            if (el.getAttribute('role') === 'checkbox') {{
                el.setAttribute('aria-checked', 'true');
                el.click();
                return true;
            }}

            // Generic fallback: just click it
            el.click();
            return true;
        }})()"#,
        sel = serde_json::to_string(selector).unwrap_or_default(),
    );

    let ok: bool = page.evaluate(&js, None::<&()>).await.unwrap_or(false);
    if ok {
        tracing::debug!(selector, "JS check fallback succeeded");
        return Ok(None);
    }

    Err(StepError::ElementNotFound(format!(
        "Check target not found: {}",
        selector
    )))
}

pub async fn execute_uncheck(page: &Page, config: &WorkflowStepConfig, _timeout_ms: u64) -> StepResult {
    let selector = config.selector.as_deref().unwrap_or("");

    tracing::debug!(selector = selector, "Executing uncheck step");

    // Try native .uncheck() first
    match page_actions::uncheck(page, selector).await {
        Ok(()) => {
            tracing::debug!(selector, "Native uncheck succeeded");
            return Ok(None);
        }
        Err(e) => {
            tracing::debug!(error = %e, "Native uncheck failed, trying JS fallback");
        }
    }

    // JS fallback
    let js = format!(
        r#"(() => {{
            const el = document.querySelector({sel});
            if (!el) return false;

            if (el.type === 'checkbox') {{
                el.checked = false;
                el.dispatchEvent(new Event('change', {{ bubbles: true }}));
                return true;
            }}

            if (el.getAttribute('role') === 'checkbox') {{
                el.setAttribute('aria-checked', 'false');
                el.click();
                return true;
            }}

            el.click();
            return true;
        }})()"#,
        sel = serde_json::to_string(selector).unwrap_or_default(),
    );

    let ok: bool = page.evaluate(&js, None::<&()>).await.unwrap_or(false);
    if ok {
        tracing::debug!(selector, "JS uncheck fallback succeeded");
        return Ok(None);
    }

    Err(StepError::ElementNotFound(format!(
        "Uncheck target not found: {}",
        selector
    )))
}
