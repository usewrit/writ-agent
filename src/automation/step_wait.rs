use std::time::Duration;

use playwright_rs::Page;

use crate::browser::{navigation, page_query};
use crate::models::workflow::WorkflowStepConfig;
use super::step_executor::{StepError, StepResult};

pub async fn execute(page: &Page, config: &WorkflowStepConfig, timeout_ms: u64) -> StepResult {
    let condition = config.extra.get("condition")
        .and_then(|v| v.as_str())
        .unwrap_or("duration");

    let timeout = Duration::from_millis(timeout_ms);

    tracing::debug!(condition = condition, timeout_ms, "Executing wait step");

    match condition {
        // Condition 1 & 2: Fixed duration wait
        "duration" | "timeout" => {
            let duration_ms = config
                .duration
                .or_else(|| {
                    config.options.as_ref().and_then(|opts| {
                        opts.get("duration").and_then(|v| v.as_f64())
                    })
                })
                .or_else(|| {
                    config.value.as_deref().and_then(|v| v.parse::<f64>().ok())
                })
                .unwrap_or(1000.0);

            let wait = Duration::from_millis(duration_ms as u64);
            let capped = wait.min(timeout);

            tracing::debug!(duration_ms = ?capped.as_millis(), "Fixed duration wait");
            tokio::time::sleep(capped).await;
        }

        // Condition 3: Wait for element to become visible
        "element" | "element_visible" => {
            let selector = config.value.as_deref()
                .or(config.selector.as_deref())
                .unwrap_or("");

            if selector.is_empty() {
                return Err(StepError::Execution("wait for element: no selector provided".into()));
            }

            tracing::debug!(selector, "Waiting for element visible");
            page_query::wait_for_selector(page, selector, timeout)
                .await
                .map_err(|e| StepError::Timeout(format!("wait for element '{}': {}", selector, e)))?;
        }

        // Condition 4: Wait for element to become hidden
        "element_hidden" => {
            let selector = config.value.as_deref()
                .or(config.selector.as_deref())
                .unwrap_or("");

            if selector.is_empty() {
                return Err(StepError::Execution("wait for element_hidden: no selector provided".into()));
            }

            tracing::debug!(selector, "Waiting for element hidden");
            page_query::wait_for_selector_hidden(page, selector, timeout)
                .await
                .map_err(|e| StepError::Timeout(format!("wait for hidden '{}': {}", selector, e)))?;
        }

        // Condition 5: Wait for URL to contain a substring
        "url_contains" => {
            let pattern = config.value.as_deref().unwrap_or("");
            if pattern.is_empty() {
                return Err(StepError::Execution("wait for url_contains: no pattern provided".into()));
            }

            let glob = format!("**/*{}*", pattern);
            tracing::debug!(pattern, "Waiting for URL containing");
            navigation::wait_for_url(page, &glob, timeout)
                .await
                .map_err(|e| StepError::Timeout(format!("wait for url containing '{}': {}", pattern, e)))?;
        }

        // Condition 6: Wait for URL to match exactly
        "url_matches" => {
            let pattern = config.value.as_deref().unwrap_or("");
            if pattern.is_empty() {
                return Err(StepError::Execution("wait for url_matches: no pattern provided".into()));
            }

            tracing::debug!(pattern, "Waiting for URL match");
            navigation::wait_for_url(page, pattern, timeout)
                .await
                .map_err(|e| StepError::Timeout(format!("wait for url '{}': {}", pattern, e)))?;
        }

        // Condition 7: Wait for network idle
        "network_idle" | "networkidle" => {
            tracing::debug!("Waiting for network idle");
            navigation::wait_for_load_state(page, "networkidle", timeout)
                .await
                .map_err(|e| StepError::Timeout(format!("wait for networkidle: {}", e)))?;
        }

        // Condition 8: Wait for DOM content loaded
        "dom_ready" | "domcontentloaded" => {
            tracing::debug!("Waiting for DOM content loaded");
            navigation::wait_for_load_state(page, "domcontentloaded", timeout)
                .await
                .map_err(|e| StepError::Timeout(format!("wait for domcontentloaded: {}", e)))?;
        }

        // Fallback: treat as duration wait
        _ => {
            let duration_ms = config
                .duration
                .or_else(|| {
                    config.value.as_deref().and_then(|v| v.parse::<f64>().ok())
                })
                .unwrap_or(1000.0);

            let wait = Duration::from_millis(duration_ms as u64);
            let capped = wait.min(timeout);

            tracing::debug!(condition, duration_ms = ?capped.as_millis(), "Unknown condition, falling back to duration wait");
            tokio::time::sleep(capped).await;
        }
    }

    Ok(None)
}
