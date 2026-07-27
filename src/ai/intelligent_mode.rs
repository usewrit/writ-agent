use std::collections::HashMap;

use base64::Engine;
use playwright_rs::Page;

use crate::browser::page_query;
use crate::dom::diff::DOMDiffEngine;
use crate::dom::prompt_format;
use crate::models::ai::ActionHistoryEntry;
use crate::models::dom::DOMState;

use super::action_executor::{self, DOM_FIELDS_WITH_COORDS_JS};
use super::client::AiClient;
use super::prompt_builder;
use super::verification;

pub struct IntelligentModeConfig {
    pub goal: String,
    pub user_context: Option<String>,
    pub available_data: HashMap<String, String>,
    pub fill_data: HashMap<String, String>,
    pub max_actions: usize,
    pub secure_keys: Vec<String>,
    pub tenant_id: String,
}

/// 1:1 port of Python ai_generate_workflow_intelligent (recorder.py lines 5216-5643).
///
/// Intelligent mode: one AI-decided action per iteration with full DOM context,
/// accessibility tree, DOM diff tracking, and verification after each action.
/// More reliable for dynamic forms, costs more AI calls.
pub async fn ai_generate_workflow_intelligent(
    page: &Page,
    config: IntelligentModeConfig,
    ai_client: Option<&dyn AiClient>,
) -> Result<IntelligentModeResult, anyhow::Error> {
    tracing::info!(
        goal = %config.goal,
        max_actions = config.max_actions,
        "Starting intelligent AI workflow"
    );

    let ai = match ai_client {
        Some(c) => c,
        None => {
            return Ok(IntelligentModeResult {
                success: false,
                steps: Vec::new(),
                raw_replay: Vec::new(),
                endpoint: None,
                error: Some("No AI client provided".to_string()),
            });
        }
    };

    // Inject helper script (Python line 5291-5310)
    let helper_script = crate::recorder::helpers::HELPER_SCRIPT_JS;
    let _: Result<serde_json::Value, _> = page.evaluate(helper_script, None::<&()>).await;
    let _: Result<serde_json::Value, _> = page.evaluate(
        "() => { if (window.__psRecorder && window.__psRecorder.initSelectAbstraction) window.__psRecorder.initSelectAbstraction(); }",
        None::<&()>,
    ).await;

    let mut steps: Vec<serde_json::Value> = Vec::new();
    let mut action_history: Vec<ActionHistoryEntry> = Vec::new();
    let mut dom_diff_engine = DOMDiffEngine::new();
    let mut endpoint: Option<serde_json::Value> = None;
    let mut last_action_time = std::time::Instant::now();

    // Failure tracking (Python lines 5565-5584)
    let mut consecutive_fail_key: Option<String> = None;
    let mut consecutive_fail_count: u32 = 0;
    let mut consecutive_investigations: u32 = 0;

    let mut action_num: usize = 0;

    for _iteration in 0..config.max_actions * 2 {
        // Rate limit: 1s minimum between actions (Python line 5341)
        let elapsed = last_action_time.elapsed();
        if elapsed < std::time::Duration::from_secs(1) {
            tokio::time::sleep(std::time::Duration::from_secs(1) - elapsed).await;
        }
        last_action_time = std::time::Instant::now();

        // 1. Screenshot (JPEG 80% quality) (Python line 5345)
        let screenshot_bytes = match page_query::screenshot_jpeg(page, 80).await {
            Ok(b) => b,
            Err(e) => {
                tracing::warn!(error = %e, "Screenshot failed, skipping iteration");
                continue;
            }
        };
        let screenshot_b64 = base64::engine::general_purpose::STANDARD.encode(&screenshot_bytes);

        // 2. Re-inject helper + re-abstract selects (Python lines 5355-5361)
        let _: Result<serde_json::Value, _> = page.evaluate(helper_script, None::<&()>).await;
        let _: Result<serde_json::Value, _> = page.evaluate(
            "() => { if (window.__psRecorder && window.__psRecorder.initSelectAbstraction) window.__psRecorder.initSelectAbstraction(); }",
            None::<&()>,
        ).await;

        // 3. DOM field extraction (Python line 5367)
        let dom_state_raw: serde_json::Value = match page_query::evaluate(page, DOM_FIELDS_WITH_COORDS_JS).await {
            Ok(v) => v,
            Err(e) => {
                tracing::warn!(error = %e, "DOM extraction failed");
                serde_json::json!({})
            }
        };

        let dom_fields_text = dom_state_raw.get("fieldsText").and_then(|v| v.as_str()).unwrap_or("");
        let buttons_text = dom_state_raw.get("buttonsText").and_then(|v| v.as_str()).unwrap_or("");
        let has_dropdowns = dom_state_raw.get("hasDropdowns").and_then(|v| v.as_bool()).unwrap_or(false);

        // Parse DOMState for diff engine
        let dom_state: DOMState = serde_json::from_value(dom_state_raw.clone()).unwrap_or(DOMState {
            fields: Vec::new(),
            buttons: Vec::new(),
            has_success: false,
            has_error: false,
            has_captcha: false,
            url: page.url(),
            captcha_info: None,
        });

        // 4. Page context extraction — errors, toasts, values (Python line 5375)
        let a11y_text = {
            let page_eval = PlaywrightPageEvaluator(page);
            match crate::dom::analyzer::extract_accessibility_tree(&page_eval).await {
                Ok(a11y) => {
                    let text = prompt_format::format_a11y_tree_for_prompt(&a11y, 1200);

                    // 5. DOM diff (Python lines 5380-5382)
                    let snapshot = DOMDiffEngine::snapshot_from_state(&dom_state, Some(&a11y));
                    let diff = dom_diff_engine.compute_diff(snapshot);
                    let diff_text = prompt_format::format_diff_for_prompt(diff.as_ref());

                    // 6. Success detection (Python lines 5388-5412)
                    if dom_state.has_success {
                        tracing::info!("Success indicators detected — completing");
                        let ep = verification::detect_form_endpoint(page).await;
                        endpoint = serde_json::to_value(&ep).ok();
                        steps.push(end_point_step(&page.url(), endpoint.as_ref()));
                        return Ok(IntelligentModeResult {
                            success: true,
                            steps,
                            raw_replay: Vec::new(),
                            endpoint,
                            error: None,
                        });
                    }

                    (text, diff_text)
                }
                Err(e) => {
                    tracing::debug!(error = %e, "A11y extraction failed");

                    // Still do DOM diff without a11y
                    let snapshot = DOMDiffEngine::snapshot_from_state(&dom_state, None);
                    let diff = dom_diff_engine.compute_diff(snapshot);
                    let diff_text = prompt_format::format_diff_for_prompt(diff.as_ref());

                    if dom_state.has_success {
                        let ep = verification::detect_form_endpoint(page).await;
                        endpoint = serde_json::to_value(&ep).ok();
                        steps.push(end_point_step(&page.url(), endpoint.as_ref()));
                        return Ok(IntelligentModeResult {
                            success: true,
                            steps,
                            raw_replay: Vec::new(),
                            endpoint,
                            error: None,
                        });
                    }

                    (String::new(), diff_text)
                }
            }
        };
        let (a11y_prompt_text, diff_prompt_text) = a11y_text;

        // Last result for context
        let _last_result: Option<&ActionHistoryEntry> = action_history.last();

        // 7. Build prompt and call AI (Python lines 5414-5428)
        let current_url = page.url();
        let prompt = prompt_builder::build_intelligent_prompt(
            dom_fields_text,
            buttons_text,
            &current_url,
            &config.goal,
            config.user_context.as_deref(),
            &config.available_data,
            &action_history,
            &a11y_prompt_text,
            &diff_prompt_text,
            &config.secure_keys,
            has_dropdowns,
        );

        let ai_response = ai.complete_vision(
            &screenshot_b64,
            &prompt,
            &config.tenant_id,
            500,
            "workflow",
        ).await;

        // complete_vision already returns parsed JSON (Option<serde_json::Value>)
        let response = match ai_response {
            Some(v) => v,
            None => {
                tracing::warn!("AI returned no response, retrying");
                continue;
            }
        };

        let action_type = response.get("action").and_then(|v| v.as_str()).unwrap_or("unknown").to_string();

        // 8. Handle terminal actions (Python lines 5461-5507)
        match action_type.as_str() {
            "complete" => {
                tracing::info!(action_num, "AI reports complete");
                let ep = verification::detect_form_endpoint(page).await;
                endpoint = serde_json::to_value(&ep).ok();
                steps.push(end_point_step(&page.url(), endpoint.as_ref()));
                return Ok(IntelligentModeResult {
                    success: true,
                    steps,
                    raw_replay: Vec::new(),
                    endpoint,
                    error: None,
                });
            }
            "blocked" => {
                let reason = response.get("reason").and_then(|v| v.as_str()).unwrap_or("Unknown");
                // Check if blocked reason actually contains success keywords (AI confusion)
                let success_words = ["success", "thank", "confirm", "submitted", "complete"];
                if success_words.iter().any(|w| reason.to_lowercase().contains(w)) {
                    tracing::info!("AI said blocked but reason contains success — treating as complete");
                    let ep = verification::detect_form_endpoint(page).await;
                    endpoint = serde_json::to_value(&ep).ok();
                    return Ok(IntelligentModeResult {
                        success: true,
                        steps,
                        raw_replay: Vec::new(),
                        endpoint,
                        error: None,
                    });
                }
                tracing::warn!(reason, "AI reports blocked");
                return Ok(IntelligentModeResult {
                    success: false,
                    steps,
                    raw_replay: Vec::new(),
                    endpoint: None,
                    error: Some(format!("Blocked: {}", reason)),
                });
            }
            _ => {}
        }

        // 9. Investigation actions don't count against budget (Python lines 5594-5603)
        let is_investigation = matches!(
            action_type.as_str(),
            "inspect_field" | "read_text" | "hover" | "list_tabs" | "extract_data" | "wait_for_change"
        );

        if is_investigation {
            consecutive_investigations += 1;
            if consecutive_investigations > 3 {
                tracing::warn!("Too many consecutive investigations, forcing action");
                consecutive_investigations = 0;
                continue;
            }
        } else {
            consecutive_investigations = 0;
            action_num += 1;
            if action_num > config.max_actions {
                tracing::warn!(max = config.max_actions, "Max actions reached");
                break;
            }
        }

        // 10. Handle batch actions (Python lines 5510-5553)
        if action_type == "batch" {
            if let Some(sub_actions) = response.get("actions").and_then(|v| v.as_array()) {
                for sub_action in sub_actions {
                    let sub_type = sub_action.get("action").and_then(|v| v.as_str()).unwrap_or("unknown");
                    let result = action_executor::execute_and_verify_action(
                        page, sub_action, &config.fill_data, &dom_state_raw,
                    ).await;

                    let sub_ok = result.success;
                    action_history.push(ActionHistoryEntry {
                        action: sub_type.to_string(),
                        field_index: sub_action.get("field_index").and_then(|v| v.as_u64()).map(|v| v as usize),
                        data_key: sub_action.get("data_key").and_then(|v| v.as_str()).map(|s| s.to_string()),
                        value: sub_action.get("value").and_then(|v| v.as_str()).map(|s| s.to_string()),
                        verified: sub_ok,
                        error: result.error.clone(),
                        step_number: action_num,
                    });

                    // Collect the full replayable RecordedStep (1:1 with Python session.steps).
                    if let Some(step) = result.step {
                        steps.push(step);
                    }

                    if !sub_ok {
                        tracing::debug!(sub_action = sub_type, "Batch sub-action failed, stopping batch");
                        break;
                    }
                    tokio::time::sleep(std::time::Duration::from_millis(150)).await;
                }
                continue;
            }
        }

        // 11. Execute single action (Python lines 5556-5561)
        let result = action_executor::execute_and_verify_action(
            page, &response, &config.fill_data, &dom_state_raw,
        ).await;

        // Track action history
        action_history.push(ActionHistoryEntry {
            action: action_type.clone(),
            field_index: response.get("field_index").and_then(|v| v.as_u64()).map(|v| v as usize),
            data_key: response.get("data_key").and_then(|v| v.as_str()).map(|s| s.to_string()),
            value: response.get("value").and_then(|v| v.as_str()).map(|s| s.to_string()),
            verified: result.success,
            error: result.error.clone(),
            step_number: action_num,
        });

        // Collect the full replayable RecordedStep produced by this action (1:1 with
        // Python's session.steps — full step dicts, NOT summaries). Investigation/no-step
        // actions contribute nothing, exactly like Python.
        if let Some(step) = result.step.clone() {
            steps.push(step);
        }

        // 12. Failure tracking (Python lines 5565-5584)
        let action_key = format!(
            "{}:{}",
            action_type,
            response.get("field_index").and_then(|v| v.as_u64()).unwrap_or(999),
        );

        if !result.success {
            if consecutive_fail_key.as_deref() == Some(&action_key) {
                consecutive_fail_count += 1;
                if consecutive_fail_count >= 5 {
                    tracing::warn!(key = %action_key, "5 consecutive failures on same action, aborting");
                    return Ok(IntelligentModeResult {
                        success: false,
                        steps,
                        raw_replay: Vec::new(),
                        endpoint: None,
                        error: Some(format!("Repeated failure on {}", action_key)),
                    });
                }
            } else {
                consecutive_fail_key = Some(action_key);
                consecutive_fail_count = 1;
            }
        } else {
            consecutive_fail_key = None;
            consecutive_fail_count = 0;
        }

        // 13. Submit handling (Python lines 5605-5630)
        if action_type == "submit" {
            tokio::time::sleep(std::time::Duration::from_secs(2)).await;
            let ep = verification::detect_form_endpoint(page).await;
            endpoint = serde_json::to_value(&ep).ok();
            if let Some(ref ep_val) = endpoint {
                if ep_val.get("status").and_then(|v| v.as_str()) == Some("success") {
                    steps.push(end_point_step(&page.url(), endpoint.as_ref()));
                    return Ok(IntelligentModeResult {
                        success: true,
                        steps,
                        raw_replay: Vec::new(),
                        endpoint,
                        error: None,
                    });
                }
            }
        }
    }

    Ok(IntelligentModeResult {
        success: false,
        steps,
        raw_replay: Vec::new(),
        endpoint,
        error: Some(format!("Max actions ({}) reached", config.max_actions)),
    })
}

pub struct IntelligentModeResult {
    pub success: bool,
    pub steps: Vec<serde_json::Value>,
    pub raw_replay: Vec<serde_json::Value>,
    pub endpoint: Option<serde_json::Value>,
    pub error: Option<String>,
}

/// Build the terminal `end_point` RecordedStep recorded on completion — 1:1 with Python
/// (recorder.py: type='end_point', options={status, message, intelligent_mode}).
fn end_point_step(url: &str, endpoint: Option<&serde_json::Value>) -> serde_json::Value {
    let status = endpoint
        .and_then(|e| e.get("status"))
        .and_then(|v| v.as_str())
        .unwrap_or("success");
    let message = endpoint
        .and_then(|e| e.get("message"))
        .and_then(|v| v.as_str())
        .unwrap_or("");
    serde_json::json!({
        "type": "end_point",
        "timestamp": crate::recorder::step_recording::current_timestamp(),
        "id": uuid::Uuid::new_v4().to_string(),
        "url": url,
        "description": "Form submission endpoint",
        "options": { "status": status, "message": message, "intelligent_mode": true },
    })
}

/// Adapter to use playwright_rs::Page with the PageEvaluator trait from dom/analyzer.rs
struct PlaywrightPageEvaluator<'a>(&'a Page);

impl<'a> crate::dom::analyzer::PageEvaluator for PlaywrightPageEvaluator<'a> {
    fn evaluate_json(
        &self,
        js: &str,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = anyhow::Result<serde_json::Value>> + Send + '_>> {
        let js = js.to_string();
        Box::pin(async move {
            let result: serde_json::Value = self.0.evaluate(&js, None::<&()>).await
                .map_err(|e| anyhow::anyhow!("evaluate_json failed: {}", e))?;
            Ok(result)
        })
    }

    fn evaluate_json_with_args(
        &self,
        js: &str,
        args: &[serde_json::Value],
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = anyhow::Result<serde_json::Value>> + Send + '_>> {
        let js = js.to_string();
        let args = serde_json::Value::Array(args.to_vec());
        Box::pin(async move {
            let result: serde_json::Value = self.0.evaluate(&js, Some(&args)).await
                .map_err(|e| anyhow::anyhow!("evaluate_json_with_args failed: {}", e))?;
            Ok(result)
        })
    }
}
