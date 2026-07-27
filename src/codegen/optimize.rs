use serde_json::Value;

/// Optimize steps by merging consecutive waits and removing redundant navigations.
pub fn optimize_steps(steps: &[Value]) -> Vec<Value> {
    if steps.is_empty() {
        return Vec::new();
    }

    let mut optimized: Vec<Value> = Vec::new();
    let mut last_url: Option<String> = None;

    for step in steps {
        let step_type = step.get("type").and_then(|v| v.as_str()).unwrap_or("");

        // Skip duplicate navigation to same URL
        if step_type == "navigate" {
            let url = step.get("url").and_then(|v| v.as_str()).unwrap_or("");
            if Some(url.to_string()) == last_url {
                continue;
            }
            last_url = Some(url.to_string());
        }

        // Merge consecutive waits
        if step_type == "wait" {
            if let Some(last) = optimized.last_mut() {
                if last.get("type").and_then(|v| v.as_str()) == Some("wait") {
                    let last_duration = last
                        .get("options")
                        .and_then(|o| o.get("duration"))
                        .and_then(|d| d.as_i64())
                        .unwrap_or(1000);
                    let this_duration = step
                        .get("options")
                        .and_then(|o| o.get("duration"))
                        .and_then(|d| d.as_i64())
                        .unwrap_or(1000);

                    let merged = serde_json::json!({ "duration": last_duration + this_duration });
                    last.as_object_mut()
                        .unwrap()
                        .insert("options".to_string(), merged);
                    continue;
                }
            }
        }

        optimized.push(step.clone());
    }

    optimized
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn test_empty_steps() {
        assert!(optimize_steps(&[]).is_empty());
    }

    #[test]
    fn test_dedup_navigate() {
        let steps = vec![
            json!({"type": "navigate", "url": "https://example.com"}),
            json!({"type": "navigate", "url": "https://example.com"}),
            json!({"type": "click", "selector": "#btn"}),
        ];
        let result = optimize_steps(&steps);
        assert_eq!(result.len(), 2);
        assert_eq!(result[0]["url"], "https://example.com");
        assert_eq!(result[1]["type"], "click");
    }

    #[test]
    fn test_merge_waits() {
        let steps = vec![
            json!({"type": "wait", "options": {"duration": 1000}}),
            json!({"type": "wait", "options": {"duration": 2000}}),
        ];
        let result = optimize_steps(&steps);
        assert_eq!(result.len(), 1);
        assert_eq!(result[0]["options"]["duration"], 3000);
    }
}
