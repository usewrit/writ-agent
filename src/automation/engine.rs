use std::collections::HashMap;
use std::sync::Arc;

use crate::browser::{page_query, stealth};
use crate::config::env::AppConfig;
use crate::models::session::SessionState;
use crate::models::workflow::{ScreenshotData, Workflow, WorkflowResult};

/// 1:1 port of Python AutomationEngine (automation_engine.py lines 415-7750).
///
/// The Rust version delegates browser lifecycle to BrowserManager (browser/manager.rs)
/// and receives the page from the caller. This matches the Python pattern where
/// execute_workflow creates its own context/page, but in Rust the caller does it
/// since BrowserManager already handles stealth context creation.
pub struct AutomationEngine {
    #[allow(dead_code)] // held for engine-scoped config access
    config: Arc<AppConfig>,
    headless: bool,
    isolated_contexts: bool,
    initialized: bool,
}

impl AutomationEngine {
    pub fn new(config: Arc<AppConfig>, headless: bool, isolated_contexts: bool) -> Self {
        Self {
            config,
            headless,
            isolated_contexts,
            initialized: false,
        }
    }

    pub async fn ensure_browser(&mut self) -> Result<(), anyhow::Error> {
        if !self.initialized {
            tracing::info!(
                headless = self.headless,
                isolated = self.isolated_contexts,
                "Initializing automation engine browser"
            );
            self.initialized = true;
        }
        Ok(())
    }

    /// 1:1 port of Python execute_workflow (automation_engine.py lines 2837-3326).
    pub async fn execute_workflow(
        &mut self,
        page: &playwright_rs::Page,
        context: &playwright_rs::BrowserContext,
        workflow: &Workflow,
        credentials: Option<&HashMap<String, String>>,
        form_data: Option<&HashMap<String, String>>,
        capture_screenshots: bool,
        session_state: Option<&SessionState>,
        _tenant_id: Option<&str>,
    ) -> WorkflowResult {
        if let Err(e) = self.ensure_browser().await {
            return WorkflowResult::failure(format!("Browser init failed: {}", e));
        }

        let entry_url = workflow
            .steps
            .first()
            .and_then(|s| s.config.url.as_deref())
            .unwrap_or("about:blank");

        tracing::info!(
            url = entry_url,
            steps = workflow.steps.len(),
            "Executing workflow"
        );

        // Inject session state if provided (Python lines 2920-2949)
        if let Some(state) = session_state {
            if let Err(e) = super::session_state::inject_session_state(
                page,
                context,
                state,
                Some(entry_url),
                workflow.timeout_ms,
            ).await {
                tracing::warn!(error = %e, "Session state injection failed, continuing without it");
            }
        }

        // Re-inject stealth after initial navigation (Python line 2991)
        let _: Result<serde_json::Value, _> = page.evaluate(stealth::STEALTH_SCRIPTS, None::<&()>).await;

        // Detect captcha at entry page (Python line 2997)
        let mut captcha_detected = detect_captcha(page).await;
        if captcha_detected {
            tracing::warn!("Captcha detected at entry page");
        }

        let mut extracted_data = HashMap::new();
        let mut steps_completed = 0;
        let mut screenshots = Vec::new();
        let mut session_expired = false;
        let captured_headers: HashMap<String, String> = HashMap::new();

        let empty_creds = HashMap::new();
        let empty_form = HashMap::new();
        let creds = credentials.unwrap_or(&empty_creds);
        let form = form_data.unwrap_or(&empty_form);

        // File assets (§6.3): this engine entry point carries no run-level files map
        // or artifact-capture context (the live dispatch path is
        // bridge::saas_bridge::handle_execute_workflow, which builds a populated
        // RunFiles from config["files"]). An inert RunFiles makes upload/
        // wait_for_download steps fail closed here rather than silently no-op.
        let run_files = super::files::RunFiles::from_config(&serde_json::Value::Null, None);

        // Track the active page so tab-affecting steps (open_tab/switch_tab/wait_for_tab/
        // tab_closed) redirect subsequent steps to the focused tab. Mirrors Python
        // `context._active_page_ref`: re-read at the top of every iteration and updated
        // after each tab step (automation_engine.py lines 3514-3537, 3988-4039).
        let mut active_page = page.clone();

        for (i, step) in workflow.steps.iter().enumerate() {
            if !step.enabled {
                continue;
            }

            // Re-resolve the active page for this iteration (Python: `page = context._active_page_ref[0]`).
            let page = &active_page;

            // Re-inject stealth after navigations (Python line 3043)
            let _: Result<serde_json::Value, _> = page.evaluate(stealth::STEALTH_SCRIPTS, None::<&()>).await;

            // Capture screenshot before step if requested (Python line 3047)
            if capture_screenshots {
                if let Ok(jpeg) = page_query::screenshot_jpeg(page, 60).await {
                    screenshots.push(ScreenshotData {
                        step: i,
                        screenshot_type: "before_step".to_string(),
                        timestamp: std::time::SystemTime::now()
                            .duration_since(std::time::UNIX_EPOCH)
                            .unwrap_or_default()
                            .as_secs_f64(),
                        data: jpeg,
                    });
                }
            }

            // Check for session expiry patterns (Python line 3075)
            let current_url = page.url().to_lowercase();
            if (current_url.contains("/login")
                || current_url.contains("/signin")
                || current_url.contains("/auth")
                || current_url.contains("/session/new"))
                && steps_completed > 0 {
                    session_expired = true;
                    tracing::warn!(url = %current_url, "Session expiry detected — redirected to login");
                }

            let step_result = super::step_executor::execute_step(
                page,
                &step.step_type,
                &step.config,
                creds,
                form,
                &run_files,
                workflow.timeout_ms,
                true,
            )
            .await;

            match step_result {
                Ok(result) => {
                    steps_completed = i + 1;
                    if let Some(data) = result {
                        for (k, v) in data {
                            extracted_data.insert(k, v);
                        }
                    }

                    // Detect captcha after step (Python line 3065)
                    if detect_captcha(page).await {
                        captcha_detected = true;
                        tracing::warn!(step = i, "Captcha detected after step");
                    }
                }
                Err(e) => {
                    let error_msg = e.to_string();
                    tracing::error!(step = i, error = %error_msg, "Step execution failed");

                    // AI auto-repair is intentionally NOT performed in this (OSS daemon)
                    // engine — it is a cloud-only, server-gated feature (the cloud meters
                    // and bills it). The daemon never re-derives broken steps with AI.

                    // Try raw replay fallback (Python line 3162)
                    if let Some(raw_replay) = &workflow.raw_replay {
                        if !raw_replay.is_empty() {
                            tracing::info!(steps = raw_replay.len(), "Attempting raw replay fallback");
                            // Same truthiness rule as Python `bool(workflow['human_layer'])`.
                            let human_layer_on = match &workflow.human_layer {
                                None | Some(serde_json::Value::Null) => false,
                                Some(serde_json::Value::Bool(b)) => *b,
                                Some(serde_json::Value::Number(n)) => n.as_f64() != Some(0.0),
                                Some(serde_json::Value::String(s)) => !s.is_empty(),
                                Some(serde_json::Value::Object(o)) => !o.is_empty(),
                                Some(serde_json::Value::Array(a)) => !a.is_empty(),
                            };
                            let replay_ok = super::raw_replay::execute_raw_replay(
                                page, raw_replay, creds, human_layer_on,
                            ).await;
                            if replay_ok {
                                tracing::info!("Raw replay fallback succeeded");
                                // Extract session state even on raw replay success
                                let state = super::session_state::extract_session_state(
                                    page, context, &captured_headers,
                                ).await;
                                return WorkflowResult {
                                    success: true,
                                    error: None,
                                    steps_completed: workflow.steps.len(),
                                    captcha_detected,
                                    session_expired,
                                    extracted_data,
                                    screenshots,
                                    cookies: state.cookies,
                                    headers: state.headers,
                                    local_storage: state.local_storage,
                                    session_storage: state.session_storage,
                                    ai_repair_attempted: false,
                                    ai_repair_success: false,
                                    ai_repair_type: None,
                                    ai_repair_data: None,
                                };
                            }
                        }
                    }

                    return WorkflowResult {
                        success: false,
                        error: Some(error_msg),
                        steps_completed,
                        captcha_detected,
                        session_expired,
                        extracted_data,
                        screenshots,
                        cookies: Vec::new(),
                        headers: HashMap::new(),
                        local_storage: HashMap::new(),
                        session_storage: HashMap::new(),
                        ai_repair_attempted: false,
                        ai_repair_success: false,
                        ai_repair_type: None,
                        ai_repair_data: None,
                    };
                }
            }

            // Reached only on the Ok path (the Err arm always returns or continues).
            // Tab-affecting steps move browser focus to another tab; follow it so the
            // next iteration runs against the now-active page (Python updates
            // `context._active_page_ref[0]` inside the tab handlers).
            if let Some(new_active) = super::step_misc::resolve_active_page_after_step(
                context,
                &step.step_type,
                &step.config,
            ) {
                active_page = new_active;
            }
        }

        // Extract session state after successful workflow (Python lines 3205-3240).
        // Use the active page (the tab the flow ended on) so page-scoped storage is
        // captured from the right tab.
        let state = super::session_state::extract_session_state(
            &active_page, context, &captured_headers,
        ).await;

        WorkflowResult {
            success: true,
            error: None,
            steps_completed,
            captcha_detected,
            session_expired,
            extracted_data,
            screenshots,
            cookies: state.cookies,
            headers: state.headers,
            local_storage: state.local_storage,
            session_storage: state.session_storage,
            ai_repair_attempted: false,
            ai_repair_success: false,
            ai_repair_type: None,
            ai_repair_data: None,
        }
    }

    pub async fn shutdown(&mut self) {
        self.initialized = false;
        tracing::info!("Automation engine shut down");
    }
}

/// Detect CAPTCHA on page. 1:1 port of Python _detect_captcha (automation_engine.py line 1174).
async fn detect_captcha(page: &playwright_rs::Page) -> bool {
    let captcha_selectors = [
        "iframe[src*='recaptcha']",
        "iframe[src*='hcaptcha']",
        ".g-recaptcha",
        ".h-captcha",
        "[data-sitekey]",
        "iframe[src*='turnstile']",
        "#cf-turnstile",
    ];

    for selector in captcha_selectors {
        if let Ok(count) = page_query::locator_count(page, selector).await {
            if count > 0 {
                return true;
            }
        }
    }

    // Cloudflare challenge page detection
    if let Ok(title) = page_query::get_title(page).await {
        if title.contains("Just a moment") || title.contains("Checking your browser") {
            return true;
        }
    }

    false
}
