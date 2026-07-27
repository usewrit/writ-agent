use std::collections::HashMap;

use playwright_rs::Page;

use crate::models::workflow::WorkflowStepConfig;
use super::files::RunFiles;

pub type StepResult = Result<Option<HashMap<String, serde_json::Value>>, StepError>;

#[derive(Debug, thiserror::Error)]
pub enum StepError {
    #[error("Element not found: {0}")]
    ElementNotFound(String),
    #[error("Timeout: {0}")]
    Timeout(String),
    #[error("Navigation failed: {0}")]
    NavigationFailed(String),
    #[error("CAPTCHA not solved: {0}")]
    CaptchaNotSolved(String),
    #[error("CAPTCHA bot detected: {0}")]
    CaptchaBotDetected(String),
    #[error("Session expired")]
    SessionExpired,
    #[error("Execution error: {0}")]
    Execution(String),
}

/// Per-step run context. Carries the credentials/form-data/files/timeouts a step needs, PLUS the
/// run's accumulated `extracted` map so `{{extracted:key}}` placeholders resolve in request steps
/// (api_call / login_post). Bundled into one struct so adding a field like `extracted` doesn't ripple
/// through `execute_step`'s 9 call sites — only the run loops that actually track extractions build a
/// populated context via [`execute_step_ctx`].
pub struct StepRunContext<'a> {
    pub credentials: &'a HashMap<String, String>,
    pub form_data: &'a HashMap<String, String>,
    pub run_files: &'a RunFiles,
    pub timeout_ms: u64,
    pub fast_mode: bool,
    /// Values pulled by prior steps' `response_extractions` (and, later, auth-recipe vars). Empty for
    /// callers that don't chain extractions.
    pub extracted: &'a HashMap<String, serde_json::Value>,
}

/// Backwards-compatible entry point: runs a step with an EMPTY extracted map. Callers that chain
/// `{{extracted:}}` values across steps should build a [`StepRunContext`] and call
/// [`execute_step_ctx`] instead.
pub async fn execute_step(
    page: &Page,
    step_type: &str,
    config: &WorkflowStepConfig,
    credentials: &HashMap<String, String>,
    form_data: &HashMap<String, String>,
    run_files: &RunFiles,
    timeout_ms: u64,
    fast_mode: bool,
) -> StepResult {
    let empty: HashMap<String, serde_json::Value> = HashMap::new();
    let ctx = StepRunContext {
        credentials,
        form_data,
        run_files,
        timeout_ms,
        fast_mode,
        extracted: &empty,
    };
    execute_step_ctx(page, step_type, config, &ctx).await
}

pub async fn execute_step_ctx(
    page: &Page,
    step_type: &str,
    config: &WorkflowStepConfig,
    ctx: &StepRunContext<'_>,
) -> StepResult {
    let credentials = ctx.credentials;
    let form_data = ctx.form_data;
    let run_files = ctx.run_files;
    let timeout_ms = ctx.timeout_ms;
    let fast_mode = ctx.fast_mode;
    match step_type {
        "navigate" => super::step_navigate::execute(page, config, credentials, form_data).await,
        "navigated_to" => super::step_navigate::execute_navigated_to(page, config).await,
        "click" => super::step_click::execute(page, config, timeout_ms, fast_mode).await,
        "fill" => super::step_fill::execute(page, config, credentials, form_data, timeout_ms, fast_mode).await,
        "type" => super::step_fill::execute_type(page, config, fast_mode).await,
        "select" => super::step_select::execute(page, config, credentials, form_data, timeout_ms).await,
        "check" => super::step_check::execute_check(page, config, timeout_ms).await,
        "uncheck" => super::step_check::execute_uncheck(page, config, timeout_ms).await,
        "captcha" | "solve_captcha" => super::step_captcha::execute(page, config, timeout_ms).await,
        "wait" => super::step_wait::execute(page, config, timeout_ms).await,
        "screenshot" => super::step_misc::execute_screenshot(page, config).await,
        "press" => super::step_misc::execute_press(page, config).await,
        "scroll" => super::step_misc::execute_scroll(page, config, fast_mode).await,
        "scroll_into_view" => super::step_misc::execute_scroll_into_view(page, config).await,
        "hover" => super::step_misc::execute_hover(page, config, fast_mode).await,
        "evaluate" => super::step_eval::execute_evaluate(page, config).await,
        "codegen" => super::step_eval::execute_codegen(page, config).await,
        "extract" => super::step_eval::execute_extract(page, config).await,
        "wait_for_change" => super::step_change::execute_wait_for_change(page, config, timeout_ms).await,
        "api_call" => super::step_eval::execute_api_call(page, config, credentials, form_data, ctx.extracted).await,
        // A sign-in replayed as a request instead of a DOM form (concierge API-builder). Mechanically
        // identical to api_call — a POST whose body carries the {{credentials}} — but a distinct type so
        // it isn't treated as a data deliverable. The in-page fetch sets the session cookie, so the
        // api_call/extract steps that follow reuse it.
        "login_post" => super::step_eval::execute_api_call(page, config, credentials, form_data, ctx.extracted).await,
        "ai_fill_form" => super::step_ai::execute_ai_fill_form(page, config, credentials, form_data, timeout_ms).await,
        "ai_fill" => super::step_ai::execute_ai_fill(page, config, credentials, form_data, timeout_ms).await,
        "ai_continue" => super::step_ai::execute_ai_continue(page, config, credentials, form_data, timeout_ms).await,
        "ai_navigate" => super::step_ai::execute_ai_navigate(page, config, credentials, form_data, timeout_ms).await,
        "upload" => super::step_upload::execute_upload(page, config, run_files, timeout_ms).await,
        "wait_for_download" => super::step_download::execute_wait_for_download(page, config, run_files, timeout_ms).await,
        "wait_for_tab" => super::step_misc::execute_wait_for_tab(page, config, timeout_ms).await,
        "open_tab" => super::step_misc::execute_open_tab(page, config, timeout_ms).await,
        "tab_closed" => super::step_misc::execute_tab_closed(page, config).await,
        "switch_tab" => super::step_misc::execute_switch_tab(page, config).await,
        "return" => Ok(Some({
            let mut m = HashMap::new();
            m.insert("_return".to_string(), serde_json::json!(true));
            m
        })),
        "end_point" => super::step_misc::execute_end_point(page, config).await,
        other => {
            tracing::warn!(step_type = other, "Unknown step type in executor");
            Ok(None)
        }
    }
}
