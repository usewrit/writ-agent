use std::time::Duration;

use playwright_rs::Page;

use crate::browser::captcha;
use crate::models::workflow::WorkflowStepConfig;
use super::step_executor::{StepError, StepResult};

/// CAPTCHA step — MANAGED CLOUD BUILD (`captcha_solver` on, `local` off).
///
/// Delegates to the automated solver in [`super::captcha_solver`] (checkbox click per type,
/// Turnstile callback hook, response-token poll). Automated solving is a paid cloud feature, so
/// only the managed cloud build compiles this arm. Keep it a pure pass-through to the solver.
#[cfg(all(feature = "captcha_solver", not(feature = "local")))]
pub async fn execute(page: &Page, config: &WorkflowStepConfig, timeout_ms: u64) -> StepResult {
    super::captcha_solver::execute(page, config, timeout_ms).await
}

/// CAPTCHA step — EVERY OTHER BUILD (OSS agent + desktop `local` daemon): DETECTION ONLY.
///
/// The open-source agent and the desktop daemon ship NO automated captcha-solving code and NO solver
/// credentials/endpoints — automated solving is a paid cloud feature, and a forked binary has no
/// solver to call. This counterpart therefore only DETECTS a CAPTCHA and fails fast so an unattended
/// run surfaces `captcha_required`:
///
/// * No CAPTCHA present → `Ok(None)` (step is a no-op).
/// * Brief wait for an auto-solve on trusted IPs (matches the cloud grace window); if it clears,
///   `Ok(None)`.
/// * Otherwise return [`StepError::CaptchaBotDetected`] (bot-detection page) or
///   [`StepError::CaptchaNotSolved`]. `RealEngine` maps both to `captcha_required`.
///
/// No checkbox clicks, Turnstile callback hooks, token polling, or solver helpers are compiled into
/// this build. Manual user-solve during HEADED recording is unaffected (it lives in the recorder /
/// `ai` path, not here).
#[cfg(not(all(feature = "captcha_solver", not(feature = "local"))))]
pub async fn execute(page: &Page, _config: &WorkflowStepConfig, _timeout_ms: u64) -> StepResult {
    tracing::debug!("Executing captcha step (detection only — no automated solver in this build)");

    // Step 1: Detect whether a CAPTCHA is on the page.
    let captcha_type: Option<String> = page.evaluate(captcha::detect_captcha_type_js(), None::<&()>)
        .await
        .unwrap_or(None);

    let captcha_type_str = captcha_type.as_deref().unwrap_or("unknown");

    if captcha_type.is_none() {
        // No CAPTCHA found — nothing to solve, proceed.
        tracing::info!("No CAPTCHA detected on page, proceeding");
        return Ok(None);
    }
    tracing::info!(captcha_type = captcha_type_str, "CAPTCHA detected — this build cannot solve");

    // Brief wait for a possible auto-solve on trusted IPs (mirrors the cloud grace window). This is
    // passive: we do NOT interact with the widget.
    tokio::time::sleep(Duration::from_secs(3)).await;

    let still_present: bool = page.evaluate(captcha::detect_captcha_js(), None::<&()>)
        .await
        .unwrap_or(true);
    if !still_present {
        tracing::info!("CAPTCHA auto-solved");
        return Ok(None);
    }

    // Distinguish an outright bot-block page from an unsolved-but-present CAPTCHA so the failure
    // category matches the cloud path's classification.
    let bot_detected_js = r#"(() => {
        const title = document.title || '';
        const body = document.body?.innerText || '';
        return title.includes('blocked') ||
               title.includes('denied') ||
               body.includes('automated') ||
               body.includes('bot detected');
    })()"#;

    let is_bot: bool = page.evaluate(bot_detected_js, None::<&()>).await.unwrap_or(false);
    if is_bot {
        return Err(StepError::CaptchaBotDetected(
            "Bot detection triggered".to_string(),
        ));
    }

    Err(StepError::CaptchaNotSolved(
        "CAPTCHA detected; automated solving is not available in this build".to_string(),
    ))
}
