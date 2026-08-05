use std::collections::HashMap;
use std::time::Duration;

use playwright_rs::Page;

use crate::browser::{page_actions, page_query};
use crate::models::workflow::WorkflowStepConfig;
use crate::util::value_resolver;
use super::step_executor::{StepError, StepResult};

/// Ask the shared AI client to produce a {selector: value} mapping for form fields.
///
/// Returns `None` if no AI client is available or the call fails, so callers
/// can fall back to heuristic matching.
async fn ai_map_fields(
    fields: &[serde_json::Value],
    data: &HashMap<String, String>,
    instruction: Option<&str>,
) -> Option<Vec<(String, String, String)>> {
    let ai_lock = crate::ai::client::get_shared_client()?;
    let ai = ai_lock.lock().await;
    if !ai.is_connected() {
        return None;
    }

    // Build a compact representation of fields and available data
    let fields_summary: Vec<serde_json::Value> = fields
        .iter()
        .filter_map(|f| {
            let sel = f["selector"].as_str().unwrap_or("");
            if sel.is_empty() {
                return None;
            }
            Some(serde_json::json!({
                "selector": sel,
                "label": f["label"].as_str().unwrap_or(""),
                "name": f["name"].as_str().unwrap_or(""),
                "type": f["type"].as_str().unwrap_or("text"),
                "tag": f["tag"].as_str().unwrap_or("input"),
            }))
        })
        .collect();

    if fields_summary.is_empty() {
        return None;
    }

    let data_keys: Vec<&str> = data.keys().map(|k| k.as_str()).collect();

    let user_prompt = format!(
        "Form fields:\n{}\n\nAvailable data keys: {:?}\n{}Map each data key to the best matching field selector. \
         Return JSON array of objects: [{{\"selector\": \"...\", \"data_key\": \"...\", \"tag\": \"...\"}}]. \
         Only include fields that have a clear match. Return [] if no matches.",
        serde_json::to_string_pretty(&fields_summary).unwrap_or_default(),
        data_keys,
        instruction.map(|i| format!("Instruction: {}\n", i)).unwrap_or_default(),
    );

    let result = ai
        .complete_json(
            "You are a form-field matching assistant. Match data keys to form field selectors based on labels, names, and types. Return ONLY valid JSON.",
            &user_prompt,
            "",
            800,
            "workflow",
        )
        .await?;

    // Parse the AI response into a Vec of (selector, data_key, tag)
    let mappings = result.as_array()?;
    let mut out = Vec::new();
    for m in mappings {
        let selector = m["selector"].as_str().unwrap_or("").to_string();
        let data_key = m["data_key"].as_str().unwrap_or("").to_string();
        let tag = m["tag"].as_str().unwrap_or("input").to_string();
        if !selector.is_empty() && !data_key.is_empty() {
            out.push((selector, data_key, tag));
        }
    }
    Some(out)
}

/// AI-driven form fill: extract all fields, ask AI to map data→selectors, fill each.
/// Exact port of Python automation_engine._ai_fill_form
pub async fn execute_ai_fill_form(
    page: &Page,
    config: &WorkflowStepConfig,
    credentials: &HashMap<String, String>,
    form_data: &HashMap<String, String>,
    _timeout_ms: u64,
) -> StepResult {
    tracing::debug!("Executing ai_fill_form step");

    // Merge form_data with config.additional_data
    let mut merged_data = form_data.clone();
    if let Some(extra) = config.extra.get("additional_data").and_then(|v| v.as_object()) {
        for (k, v) in extra {
            if let Some(s) = v.as_str() {
                let resolved = value_resolver::resolve_value(s, credentials, Some(form_data));
                merged_data.insert(k.clone(), resolved);
            }
        }
    }

    // Extract all form field info via page.evaluate()
    let fields_js = r#"(() => {
        const fields = [];
        document.querySelectorAll('input, select, textarea').forEach((el, i) => {
            if (el.type === 'hidden' || el.type === 'submit') return;
            const rect = el.getBoundingClientRect();
            if (rect.width === 0 || rect.height === 0) return;
            const label = el.labels?.[0]?.textContent?.trim() ||
                el.getAttribute('aria-label') || el.placeholder || el.name || el.id || '';
            fields.push({
                index: i,
                selector: el.id ? '#' + el.id : (el.name ? el.tagName.toLowerCase() + '[name="' + el.name + '"]' : ''),
                tag: el.tagName.toLowerCase(),
                type: el.type || 'text',
                name: el.name || '',
                label: label,
                value: el.value || '',
                options: el.tagName === 'SELECT' ? Array.from(el.options).map(o => ({value: o.value, text: o.text})) : []
            });
        });
        return fields;
    })()"#;

    let fields: Vec<serde_json::Value> = page_query::evaluate(page, fields_js).await
        .map_err(|e| StepError::Execution(format!("Field extraction failed: {}", e)))?;

    // Try AI-driven mapping first, fall back to heuristic label matching
    let ai_mappings = ai_map_fields(&fields, &merged_data, None).await;

    if let Some(mappings) = ai_mappings {
        tracing::debug!(count = mappings.len(), "AI fill_form: using AI-driven field mapping");
        for (selector, data_key, tag) in &mappings {
            if let Some(value) = merged_data.get(data_key) {
                let resolved = value_resolver::resolve_value(value, credentials, Some(form_data));
                if tag == "select" {
                    let _ = page_actions::select_option(page, selector, &resolved).await;
                } else {
                    let _ = page_actions::fill(page, selector, &resolved).await;
                }
                tracing::debug!(selector = selector.as_str(), key = data_key.as_str(), "AI fill: AI-mapped and filled");
            }
        }
    } else {
        // Heuristic fallback: match by label/name substring
        tracing::debug!("AI fill_form: falling back to heuristic field matching");
        for field in &fields {
            let selector = field["selector"].as_str().unwrap_or("");
            let label = field["label"].as_str().unwrap_or("").to_lowercase();
            let name = field["name"].as_str().unwrap_or("").to_lowercase();
            let tag = field["tag"].as_str().unwrap_or("");

            if selector.is_empty() { continue; }

            // Find matching data key
            for (key, value) in &merged_data {
                let key_lower = key.to_lowercase();
                if label.contains(&key_lower) || name.contains(&key_lower) || key_lower.contains(&label) {
                    let resolved = value_resolver::resolve_value(value, credentials, Some(form_data));

                    if tag == "select" {
                        let _ = page_actions::select_option(page, selector, &resolved).await;
                    } else {
                        let _ = page_actions::fill(page, selector, &resolved).await;
                    }
                    tracing::debug!(selector, key = key.as_str(), "AI fill: heuristic-mapped and filled");
                    break;
                }
            }
        }
    }

    Ok(None)
}

/// AI-driven instruction fill: AI returns {"selector": "value"} mapping.
/// Exact port of Python automation_engine._ai_fill_with_instruction
pub async fn execute_ai_fill(
    page: &Page,
    config: &WorkflowStepConfig,
    credentials: &HashMap<String, String>,
    form_data: &HashMap<String, String>,
    _timeout_ms: u64,
) -> StepResult {
    tracing::debug!("Executing ai_fill step");

    let instruction = config.extra.get("instruction")
        .and_then(|v| v.as_str())
        .unwrap_or("");

    // Extract visible form fields
    let fields_js = r#"(() => {
        const fields = [];
        document.querySelectorAll('input, select, textarea').forEach((el) => {
            if (el.type === 'hidden' || el.type === 'submit') return;
            const rect = el.getBoundingClientRect();
            if (rect.width === 0 || rect.height === 0) return;
            const sel = el.id ? '#' + el.id : (el.name ? el.tagName.toLowerCase() + '[name="' + el.name + '"]' : '');
            if (!sel) return;
            fields.push({
                selector: sel,
                label: el.labels?.[0]?.textContent?.trim() || el.placeholder || el.name || '',
                type: el.type || 'text',
                value: el.value || ''
            });
        });
        return fields;
    })()"#;

    let fields: Vec<serde_json::Value> = page_query::evaluate(page, fields_js).await
        .map_err(|e| StepError::Execution(format!("Field extraction failed: {}", e)))?;

    // Merge all data sources
    let mut all_data = form_data.clone();
    for (k, v) in credentials {
        all_data.insert(k.clone(), v.clone());
    }

    // Try AI-driven mapping first with the instruction context
    let ai_mappings = ai_map_fields(&fields, &all_data, Some(instruction)).await;

    if let Some(mappings) = ai_mappings {
        tracing::debug!(count = mappings.len(), "AI fill: using AI-driven field mapping");
        for (selector, data_key, _tag) in &mappings {
            if let Some(value) = all_data.get(data_key) {
                let _ = page_actions::fill(page, selector, value).await;
                tracing::debug!(selector = selector.as_str(), key = data_key.as_str(), "AI fill: AI-mapped and filled");
            }
        }
    } else {
        // Heuristic fallback
        tracing::debug!("AI fill: falling back to heuristic field matching");
        for field in &fields {
            let selector = field["selector"].as_str().unwrap_or("");
            let label = field["label"].as_str().unwrap_or("").to_lowercase();
            if selector.is_empty() { continue; }

            for (key, value) in &all_data {
                let key_lower = key.to_lowercase();
                if label.contains(&key_lower) || key_lower.contains(&label) {
                    let _ = page_actions::fill(page, selector, value).await;
                    break;
                }
            }
        }
    }

    Ok(None)
}

/// THE AI step ("AI Task" in the editor): describe what you want, the agent loop reads
/// the page and acts until it's done.
///
/// `ai_continue` is what the authoring surfaces emit; `ai_navigate` is the older
/// spelling of the SAME step and routes here too (see [`execute_ai_navigate`]) rather
/// than running a second, weaker click-only loop. Both prompt keys (`task`, `goal`) and
/// both budget keys (`max_actions`, `max_steps`) are read, so neither spelling needs a
/// migration. Mirrors Python `automation_engine` step type `ai_continue`/`ai_navigate`.
pub async fn execute_ai_continue(
    page: &Page,
    config: &WorkflowStepConfig,
    credentials: &HashMap<String, String>,
    form_data: &HashMap<String, String>,
    _timeout_ms: u64,
) -> StepResult {
    tracing::debug!("Executing AI task step");

    let task = config.extra.get("task")
        .and_then(|v| v.as_str())
        .filter(|s| !s.trim().is_empty())
        // Legacy `ai_navigate` spelling of the same field.
        .or_else(|| config.extra.get("goal").and_then(|v| v.as_str()).filter(|s| !s.trim().is_empty()))
        .or(config.description.as_deref())
        .unwrap_or("Complete the form");
    // `max_actions` is the current key, `max_steps` the legacy `ai_navigate` one. The
    // default matches the Python engine so a workflow that omits it behaves the same
    // whichever venue runs it.
    let max_actions = config.extra.get("max_actions")
        .and_then(|v| v.as_u64())
        .or_else(|| config.extra.get("max_steps").and_then(|v| v.as_u64()))
        .unwrap_or(10) as usize;

    // Optional start URL: go there BEFORE the loop starts, so one step can both get
    // somewhere and do something. Delegated to the `navigate` step so this shares its
    // SSRF guard, session-token carry-forward and page-settle rather than re-deriving
    // them here. (The editor has always shown this field for `ai_navigate`; nothing
    // ever read it, so the step just ran wherever the previous step left the browser.)
    if let Some(start_url) = config.url.as_deref().map(str::trim).filter(|s| !s.is_empty()) {
        let nav_config = WorkflowStepConfig {
            url: Some(start_url.to_string()),
            ..Default::default()
        };
        super::step_navigate::execute(page, &nav_config, credentials, form_data).await?;
    }

    let mut steps_taken = Vec::new();
    let mut all_data = form_data.clone();
    for (k, v) in credentials {
        all_data.insert(k.clone(), v.clone());
    }

    for action_num in 0..max_actions {
        // Get page state
        let state_js = r#"(() => {
            const text = document.body?.innerText?.substring(0, 2000) || '';
            const elements = [];
            document.querySelectorAll('input, select, textarea, button, a, [role="button"]').forEach((el, i) => {
                if (i > 50) return;
                const rect = el.getBoundingClientRect();
                if (rect.width === 0 || rect.height === 0) return;
                elements.push({
                    tag: el.tagName.toLowerCase(),
                    type: el.type || '',
                    text: (el.textContent || el.value || '').trim().substring(0, 100),
                    selector: el.id ? '#' + el.id : (el.name ? '[name="' + el.name + '"]' : ''),
                });
            });
            const done = text.includes('success') || text.includes('thank you') || text.includes('completed');
            return { text: text.substring(0, 500), elements, done, url: location.href };
        })()"#;

        let state: serde_json::Value = page_query::evaluate(page, state_js).await
            .map_err(|e| StepError::Execution(format!("Page state failed: {}", e)))?;

        if state["done"].as_bool().unwrap_or(false) {
            tracing::info!(action_num, "AI continue: success detected");
            break;
        }

        // Try AI-driven next-action decision, fall back to heuristic
        let elements = state["elements"].as_array();
        let mut did_action = false;

        // Attempt AI-driven action selection
        let ai_action = {
            let ai_lock = crate::ai::client::get_shared_client();
            if let Some(ref lock) = ai_lock {
                let ai = lock.lock().await;
                if ai.is_connected() {
                    let page_text = state["text"].as_str().unwrap_or("");
                    let elements_json = state["elements"].clone();
                    let data_keys: Vec<&str> = all_data.keys().map(|k| k.as_str()).collect();

                    let prompt = format!(
                        "Page text: {}\nElements: {}\nAvailable data keys: {:?}\nTask: {}\nSteps taken so far: {}\n\n\
                         What is the best next action? Return JSON: \
                         {{\"action\": \"fill\"|\"click\"|\"done\", \"selector\": \"...\", \"data_key\": \"...\" (for fill), \"reason\": \"...\"}}",
                        page_text.chars().take(500).collect::<String>(),
                        serde_json::to_string(&elements_json).unwrap_or_default(),
                        data_keys,
                        task,
                        steps_taken.len(),
                    );
                    ai.complete_json(
                        "You are a browser automation agent. Decide the single best next action to complete the task.",
                        &prompt,
                        "",
                        500,
                        "workflow",
                    ).await
                } else {
                    None
                }
            } else {
                None
            }
        };

        if let Some(ref action) = ai_action {
            let action_type = action["action"].as_str().unwrap_or("");
            let selector = action["selector"].as_str().unwrap_or("");

            match action_type {
                "done" => {
                    tracing::info!(action_num, "AI continue: AI reports done");
                    break;
                }
                "fill" if !selector.is_empty() => {
                    let data_key = action["data_key"].as_str().unwrap_or("");
                    if let Some(value) = all_data.get(data_key) {
                        let _ = page_actions::fill(page, selector, value).await;
                        steps_taken.push(serde_json::json!({
                            "action": "fill", "selector": selector, "data_key": data_key, "source": "ai"
                        }));
                        did_action = true;
                    }
                }
                "click" if !selector.is_empty() => {
                    let _ = page_actions::click_selector(page, selector, false).await;
                    steps_taken.push(serde_json::json!({
                        "action": "click", "selector": selector, "source": "ai"
                    }));
                    did_action = true;
                    tokio::time::sleep(Duration::from_secs(1)).await;
                }
                _ => {}
            }
        }

        // Heuristic fallback if AI didn't produce an action
        if !did_action {
            if let Some(elems) = elements {
                for el in elems {
                    let tag = el["tag"].as_str().unwrap_or("");
                    let selector = el["selector"].as_str().unwrap_or("");
                    if selector.is_empty() { continue; }

                    if tag == "input" || tag == "textarea" || tag == "select" {
                        let el_text = el["text"].as_str().unwrap_or("").to_lowercase();
                        for (key, value) in &all_data {
                            if el_text.contains(&key.to_lowercase()) {
                                if tag == "select" {
                                    let _ = page_actions::select_option(page, selector, value).await;
                                } else {
                                    let _ = page_actions::fill(page, selector, value).await;
                                }
                                steps_taken.push(serde_json::json!({
                                    "action": "fill", "selector": selector, "data_key": key
                                }));
                                did_action = true;
                                break;
                            }
                        }
                    } else if (tag == "button" || tag == "a") && !did_action {
                        let text = el["text"].as_str().unwrap_or("").to_lowercase();
                        if text.contains("submit") || text.contains("next") || text.contains("continue") {
                            let _ = page_actions::click_selector(page, selector, false).await;
                            steps_taken.push(serde_json::json!({"action": "click", "selector": selector}));
                            did_action = true;
                            tokio::time::sleep(Duration::from_secs(1)).await;
                            break;
                        }
                    }
                }
            }
        }

        if !did_action {
            tracing::debug!(action_num, "AI continue: no action taken, stopping");
            break;
        }
    }

    let mut result = HashMap::new();
    result.insert("steps".to_string(), serde_json::json!(steps_taken));
    result.insert("success".to_string(), serde_json::json!(true));
    Ok(Some(result))
}

/// Legacy spelling of the merged AI step — see [`execute_ai_continue`].
///
/// This used to be a SEPARATE, weaker loop: it only ever clicked (never filled), it
/// re-derived its own prompt, and it fell back to substring-matching the goal against
/// link text. Two loops for one idea is exactly how "three AI steps" that all mean
/// "describe it, the AI does it" drifted apart, so `ai_navigate` now runs the same
/// path as `ai_continue` — which reads `goal`/`max_steps` too, so nothing is lost.
pub async fn execute_ai_navigate(
    page: &Page,
    config: &WorkflowStepConfig,
    credentials: &HashMap<String, String>,
    form_data: &HashMap<String, String>,
    timeout_ms: u64,
) -> StepResult {
    execute_ai_continue(page, config, credentials, form_data, timeout_ms).await
}
