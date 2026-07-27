use serde_json::{json, Value};

/// Convert recorded steps to the internal workflow JSON format.
///
/// Each step gets an `id`, `enabled` flag, and a `config` object whose shape
/// depends on the step type. The top-level workflow includes `form_data`,
/// `timeout_ms`, `retry_count`, `headless`, and optional `raw_replay`.
pub fn steps_to_workflow_json(
    steps: &[Value],
    name: &str,
    description: &str,
    raw_replay: Option<&[Value]>,
) -> Value {
    let mut workflow_steps: Vec<Value> = Vec::new();

    for (i, step) in steps.iter().enumerate() {
        let step_type = step.get("type").and_then(|v| v.as_str()).unwrap_or("");

        let mut wf_step = json!({
            "id": format!("step_{}", i),
            "type": step_type,
            "enabled": true,
        });

        let config = match step_type {
            "navigate" => {
                json!({ "url": step.get("url") })
            }

            "click" | "fill" | "select" | "check" => {
                let mut cfg = json!({
                    "selector": step.get("selector"),
                });
                let obj = cfg.as_object_mut().unwrap();
                if let Some(val) = step.get("value") {
                    if !val.is_null() {
                        obj.insert("value".to_string(), val.clone());
                    }
                }
                if let Some(coords) = step.get("coordinates") {
                    obj.insert("coordinates".to_string(), coords.clone());
                }
                if let Some(viewport) = step.get("viewport") {
                    obj.insert("viewport".to_string(), viewport.clone());
                }
                if let Some(options) = step.get("options") {
                    obj.insert("options".to_string(), options.clone());
                }
                cfg
            }

            "press" => {
                json!({ "key": step.get("value") })
            }

            "wait" => {
                let duration = step
                    .get("options")
                    .and_then(|o| o.get("duration"))
                    .and_then(|d| d.as_i64())
                    .unwrap_or(1000);
                json!({ "duration": duration })
            }

            "scroll" => {
                let delta_y = step
                    .get("options")
                    .and_then(|o| o.get("deltaY"))
                    .and_then(|d| d.as_i64())
                    .unwrap_or(500);
                json!({ "deltaY": delta_y })
            }

            _ => step.get("options").cloned().unwrap_or(json!({})),
        };

        wf_step
            .as_object_mut()
            .unwrap()
            .insert("config".to_string(), config);

        // Add description if available
        if let Some(desc) = step.get("description").and_then(|v| v.as_str()) {
            if !desc.is_empty() {
                wf_step
                    .as_object_mut()
                    .unwrap()
                    .insert("description".to_string(), json!(desc));
            }
        }

        workflow_steps.push(wf_step);
    }

    let mut workflow = json!({
        "name": name,
        "description": description,
        "workflow_type": "recorded",
        "steps": workflow_steps,
        "form_data": {},
        "timeout_ms": 60000,
        "retry_count": 2,
        "headless": true,
    });

    if let Some(replay) = raw_replay {
        workflow
            .as_object_mut()
            .unwrap()
            .insert("raw_replay".to_string(), json!(replay));
    }

    workflow
}

/// Convert workflow JSON format back to recorded steps format.
pub fn workflow_json_to_steps(workflow: &Value) -> Vec<Value> {
    let mut steps: Vec<Value> = Vec::new();

    let wf_steps = match workflow.get("steps").and_then(|s| s.as_array()) {
        Some(arr) => arr,
        None => return steps,
    };

    for wf_step in wf_steps {
        let step_type = wf_step
            .get("type")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        let config = wf_step.get("config");
        let description = wf_step
            .get("description")
            .and_then(|v| v.as_str())
            .unwrap_or("");

        let mut step = json!({
            "type": step_type,
            "description": description,
        });
        let obj = step.as_object_mut().unwrap();

        match step_type {
            "navigate" => {
                if let Some(url) = config.and_then(|c| c.get("url")) {
                    obj.insert("url".to_string(), url.clone());
                }
            }

            "click" | "fill" | "select" | "check" => {
                if let Some(sel) = config.and_then(|c| c.get("selector")) {
                    obj.insert("selector".to_string(), sel.clone());
                }
                if let Some(val) = config.and_then(|c| c.get("value")) {
                    if !val.is_null() {
                        obj.insert("value".to_string(), val.clone());
                    }
                }
                if let Some(coords) = config.and_then(|c| c.get("coordinates")) {
                    obj.insert("coordinates".to_string(), coords.clone());
                }
                if let Some(viewport) = config.and_then(|c| c.get("viewport")) {
                    obj.insert("viewport".to_string(), viewport.clone());
                }
                if let Some(options) = config.and_then(|c| c.get("options")) {
                    obj.insert("options".to_string(), options.clone());
                }
            }

            "press" => {
                if let Some(key) = config.and_then(|c| c.get("key")) {
                    obj.insert("value".to_string(), key.clone());
                }
            }

            "wait" => {
                let duration = config
                    .and_then(|c| c.get("duration"))
                    .and_then(|d| d.as_i64())
                    .unwrap_or(1000);
                obj.insert("options".to_string(), json!({"duration": duration}));
            }

            "scroll" => {
                let delta_y = config
                    .and_then(|c| c.get("deltaY"))
                    .and_then(|d| d.as_i64())
                    .unwrap_or(500);
                obj.insert("options".to_string(), json!({"deltaY": delta_y}));
            }

            _ => {}
        }

        steps.push(step);
    }

    steps
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn test_roundtrip() {
        let original = vec![
            json!({"type": "navigate", "url": "https://example.com"}),
            json!({"type": "fill", "selector": "#email", "value": "test@test.com"}),
            json!({"type": "click", "selector": "#submit"}),
            json!({"type": "wait", "options": {"duration": 2000}}),
        ];
        let workflow = steps_to_workflow_json(&original, "Test", "desc", None);
        let recovered = workflow_json_to_steps(&workflow);
        assert_eq!(recovered.len(), 4);
        assert_eq!(recovered[0]["type"], "navigate");
        assert_eq!(recovered[0]["url"], "https://example.com");
        assert_eq!(recovered[1]["value"], "test@test.com");
        assert_eq!(recovered[3]["options"]["duration"], 2000);
    }

    #[test]
    fn test_workflow_metadata() {
        let workflow = steps_to_workflow_json(&[], "My Flow", "A description", None);
        assert_eq!(workflow["name"], "My Flow");
        assert_eq!(workflow["timeout_ms"], 60000);
        assert_eq!(workflow["retry_count"], 2);
        assert_eq!(workflow["headless"], true);
        assert_eq!(workflow["workflow_type"], "recorded");
    }

    #[test]
    fn test_raw_replay_included() {
        let replay = vec![json!({"type": "click", "x": 100, "y": 200})];
        let workflow = steps_to_workflow_json(&[], "W", "", Some(&replay));
        assert!(workflow.get("raw_replay").is_some());
    }

    #[test]
    fn test_press_key_mapping() {
        let steps = vec![json!({"type": "press", "value": "Enter"})];
        let workflow = steps_to_workflow_json(&steps, "W", "", None);
        assert_eq!(workflow["steps"][0]["config"]["key"], "Enter");

        let recovered = workflow_json_to_steps(&workflow);
        assert_eq!(recovered[0]["value"], "Enter");
    }
}
