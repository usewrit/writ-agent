use std::collections::HashMap;

use base64::Engine;
use playwright_rs::Page;

use crate::browser::page_query;

use super::action_executor::{self, DOM_FIELDS_WITH_COORDS_JS};
use super::client::AiClient;
use super::prompt_builder;
use super::verification;

pub struct StandardModeConfig {
    pub goal: String,
    pub available_data: HashMap<String, String>,
    pub fill_data: HashMap<String, String>,
    pub max_steps: usize,
    pub use_vision: bool,
    pub tenant_id: String,
    /// Secret-ref keys whose VALUES must never be echoed into the AI prompt (SE-7).
    pub secure_keys: Vec<String>,
}

pub async fn ai_generate_workflow(
    page: &Page,
    config: StandardModeConfig,
    ai_client: Option<&dyn AiClient>,
) -> Result<StandardModeResult, anyhow::Error> {
    tracing::info!(
        goal = %config.goal,
        max_steps = config.max_steps,
        use_vision = config.use_vision,
        "Starting standard AI workflow"
    );

    let mut steps: Vec<serde_json::Value> = Vec::new();
    let raw_replay: Vec<serde_json::Value> = Vec::new();
    let mut filled_fields: Vec<String> = Vec::new();
    let mut clicked_field_indices: Vec<usize> = Vec::new();
    let mut endpoint: Option<serde_json::Value> = None;

    let ai = match ai_client {
        Some(c) => c,
        None => {
            return Ok(StandardModeResult {
                success: false,
                steps: Vec::new(),
                raw_replay: Vec::new(),
                endpoint: None,
                error: Some("No AI client provided".to_string()),
            });
        }
    };

    for step in 0..config.max_steps {
        tracing::debug!(step, max = config.max_steps, "Standard mode iteration");

        // 1. Take screenshot
        let screenshot_bytes = page_query::screenshot_jpeg(page, 60).await?;
        let screenshot_b64 =
            base64::engine::general_purpose::STANDARD.encode(&screenshot_bytes);

        // 2. Get DOM state
        let dom_state: serde_json::Value =
            page_query::evaluate(page, DOM_FIELDS_WITH_COORDS_JS).await?;

        let dom_fields_text = dom_state
            .get("fieldsText")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        let buttons_text = dom_state
            .get("buttonsText")
            .and_then(|v| v.as_str())
            .unwrap_or("");

        let has_captcha = dom_state
            .get("has_captcha")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);

        // 3. Build prompt
        let prompt = prompt_builder::build_standard_prompt(
            dom_fields_text,
            buttons_text,
            &config.goal,
            &config.available_data,
            &filled_fields,
            &clicked_field_indices,
            has_captcha,
            &config.secure_keys,
        );

        // 4. Call AI with vision
        let ai_response = if config.use_vision {
            ai.complete_vision_with_system(
                "You are a browser automation agent. Analyze the screenshot and form fields to fill out the form.",
                &screenshot_b64,
                &prompt,
                &config.tenant_id,
                1000,
                "workflow",
            )
            .await
        } else {
            ai.complete_json(
                "You are a browser automation agent analyzing form fields.",
                &prompt,
                &config.tenant_id,
                1000,
                "workflow",
            )
            .await
        };

        let response = match ai_response {
            Some(r) => r,
            None => {
                tracing::warn!(step, "AI returned no response, retrying");
                continue;
            }
        };

        // 5. Parse status
        let status = response
            .get("status")
            .and_then(|v| v.as_str())
            .unwrap_or("continue");

        match status {
            "complete" => {
                tracing::info!(step, "AI reports form complete");
                return Ok(StandardModeResult {
                    success: true,
                    steps,
                    raw_replay,
                    endpoint,
                    error: None,
                });
            }
            "blocked" => {
                let reason = response
                    .get("reason")
                    .and_then(|v| v.as_str())
                    .unwrap_or("Unknown block");
                tracing::warn!(step, reason, "AI reports blocked");
                return Ok(StandardModeResult {
                    success: false,
                    steps,
                    raw_replay,
                    endpoint: None,
                    error: Some(format!("Blocked: {}", reason)),
                });
            }
            _ => {}
        }

        // 6. Handle scroll if needed
        if response
            .get("needs_scroll")
            .and_then(|v| v.as_bool())
            .unwrap_or(false)
        {
            page_query::evaluate::<serde_json::Value>(
                page,
                "window.scrollBy(0, 400)",
            )
            .await
            .ok();
            tokio::time::sleep(std::time::Duration::from_millis(500)).await;
        }

        // 7. Execute mappings (actions)
        if let Some(mappings) = response.get("mappings").and_then(|v| v.as_array()) {
            for mapping in mappings {
                let action_type = mapping
                    .get("action")
                    .and_then(|v| v.as_str())
                    .unwrap_or("fill");

                let result = action_executor::execute_and_verify_action(
                    page,
                    mapping,
                    &config.fill_data,
                    &dom_state,
                )
                .await;

                // Track filled fields
                if result.success {
                    if let Some(dk) = mapping.get("data_key").and_then(|v| v.as_str()) {
                        if !filled_fields.contains(&dk.to_string()) {
                            filled_fields.push(dk.to_string());
                        }
                    }
                    if let Some(fi) = mapping.get("field_index").and_then(|v| v.as_u64()) {
                        clicked_field_indices.push(fi as usize);
                    }
                }

                steps.push(serde_json::json!({
                    "action": action_type,
                    "success": result.success,
                    "step": step,
                    "verification": {
                        "verified": result.verification.verified,
                        "message": result.verification.message,
                    }
                }));
            }
        }

        // 8. Handle submit button
        if let Some(submit) = response.get("submit_button") {
            if submit.is_object() {
                let mut submit_action = submit.clone();
                submit_action
                    .as_object_mut()
                    .map(|m| m.insert("action".to_string(), serde_json::json!("submit")));

                let result = action_executor::execute_and_verify_action(
                    page,
                    &submit_action,
                    &config.fill_data,
                    &dom_state,
                )
                .await;

                if let Some(ep) = result.endpoint {
                    endpoint = Some(ep);
                }

                // Wait after submit for page to settle
                tokio::time::sleep(std::time::Duration::from_secs(2)).await;

                // Detect endpoint if not already found
                if endpoint.is_none() {
                    let ep = verification::detect_form_endpoint(page).await;
                    endpoint = serde_json::to_value(&ep).ok();
                }

                return Ok(StandardModeResult {
                    success: true,
                    steps,
                    raw_replay,
                    endpoint,
                    error: None,
                });
            }
        }

        // Small pause between steps
        tokio::time::sleep(std::time::Duration::from_millis(500)).await;
    }

    Ok(StandardModeResult {
        success: false,
        steps,
        raw_replay,
        endpoint,
        error: Some(format!("Max steps ({}) reached", config.max_steps)),
    })
}

pub struct StandardModeResult {
    pub success: bool,
    pub steps: Vec<serde_json::Value>,
    pub raw_replay: Vec<serde_json::Value>,
    pub endpoint: Option<serde_json::Value>,
    pub error: Option<String>,
}
