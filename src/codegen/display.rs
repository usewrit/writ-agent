use serde_json::Value;

use crate::models::step::{icon_for_step, DisplayStep};

/// Truncate a string to `max_len` chars, appending "..." if truncated.
///
/// Counts by `char`, not bytes: `&s[..max_len]` panics when the byte boundary
/// falls inside a multibyte UTF-8 char (reachable via user-supplied step JSON).
fn truncate(s: &str, max_len: usize) -> String {
    if s.chars().count() > max_len {
        let head: String = s.chars().take(max_len).collect();
        format!("{}...", head)
    } else {
        s.to_string()
    }
}

/// Convert recorded steps (as JSON values) to display format.
pub fn steps_to_display(steps: &[Value]) -> Vec<DisplayStep> {
    let mut display_steps = Vec::new();

    for (i, step) in steps.iter().enumerate() {
        let step_type = step
            .get("type")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown");
        let icon = icon_for_step(step_type).to_string();

        let selector = step.get("selector").and_then(|v| v.as_str()).unwrap_or("");
        let value = step.get("value").and_then(|v| v.as_str()).unwrap_or("");
        let url = step.get("url").and_then(|v| v.as_str()).unwrap_or("");

        let (title, description) = match step_type {
            "navigate" => ("Navigate".to_string(), format!("Go to {}", url)),

            "click" => {
                let text = step
                    .get("description")
                    .and_then(|v| v.as_str())
                    .unwrap_or("");
                let desc = if text.is_empty() {
                    format!("Click on {}", selector)
                } else {
                    text.to_string()
                };
                ("Click".to_string(), desc)
            }

            "fill" => {
                let name = step
                    .get("options")
                    .and_then(|o| o.get("name"))
                    .and_then(|n| n.as_str())
                    .unwrap_or("");
                let label = if name.is_empty() { selector } else { name };
                // Never surface a recorded secret in a human-readable
                // description; show a masked placeholder instead.
                let is_sensitive = step
                    .get("options")
                    .and_then(|o| o.get("is_sensitive"))
                    .and_then(|v| v.as_bool())
                    .unwrap_or(false);
                let shown = if is_sensitive {
                    "••••••".to_string()
                } else {
                    truncate(value, 30)
                };
                (
                    "Fill".to_string(),
                    format!("Type '{}' into {}", shown, label),
                )
            }

            "type" => {
                let truncated = truncate(value, 30);
                ("Type".to_string(), format!("Type '{}'", truncated))
            }

            "press" => ("Press Key".to_string(), format!("Press {}", value)),

            "select" => (
                "Select".to_string(),
                format!("Select '{}' from {}", value, selector),
            ),

            "check" => (
                "Check".to_string(),
                format!("Check/uncheck {}", selector),
            ),

            "scroll" => {
                let delta_y = step
                    .get("options")
                    .and_then(|o| o.get("deltaY"))
                    .and_then(|d| d.as_f64())
                    .unwrap_or(0.0);
                let direction = if delta_y > 0.0 { "down" } else { "up" };
                ("Scroll".to_string(), format!("Scroll {}", direction))
            }

            "wait" => {
                let duration = step
                    .get("options")
                    .and_then(|o| o.get("duration"))
                    .and_then(|d| d.as_i64())
                    .unwrap_or(1000);
                ("Wait".to_string(), format!("Wait {}ms", duration))
            }

            "screenshot" => ("Screenshot".to_string(), "Capture screenshot".to_string()),

            other => {
                let cap = capitalize(other);
                let desc = step
                    .get("description")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string())
                    .unwrap_or_else(|| format!("Unknown action: {}", other));
                (cap, desc)
            }
        };

        // A sensitive value must not travel in the display payload's raw `value`
        // field either — mask it so no consumer can read the recorded secret.
        let step_sensitive = step
            .get("options")
            .and_then(|o| o.get("is_sensitive"))
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        let display_value = step
            .get("value")
            .and_then(|v| v.as_str())
            .map(|v| if step_sensitive { "••••••".to_string() } else { v.to_string() });

        display_steps.push(DisplayStep {
            index: i,
            step_type: step_type.to_string(),
            icon,
            title,
            description,
            selector: step.get("selector").and_then(|v| v.as_str()).map(String::from),
            value: display_value,
            url: step.get("url").and_then(|v| v.as_str()).map(String::from),
            editable: true,
        });
    }

    display_steps
}

fn capitalize(s: &str) -> String {
    let mut chars = s.chars();
    match chars.next() {
        None => String::new(),
        Some(c) => c.to_uppercase().collect::<String>() + chars.as_str(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn test_navigate_display() {
        let steps = vec![json!({"type": "navigate", "url": "https://example.com"})];
        let result = steps_to_display(&steps);
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].title, "Navigate");
        assert_eq!(result[0].description, "Go to https://example.com");
    }

    #[test]
    fn test_fill_truncation() {
        let long_value = "a".repeat(50);
        let steps = vec![json!({"type": "fill", "selector": "#input", "value": long_value})];
        let result = steps_to_display(&steps);
        assert!(result[0].description.contains("..."));
    }

    #[test]
    fn test_multibyte_truncate_no_panic() {
        // Byte-slicing `&s[..30]` here would split a multibyte char and panic.
        let value = "é".repeat(50);
        let steps = vec![json!({"type": "fill", "selector": "#input", "value": value})];
        let result = steps_to_display(&steps);
        assert!(result[0].description.contains("..."));
    }

    #[test]
    fn test_sensitive_fill_masked() {
        let steps = vec![json!({
            "type": "fill",
            "selector": "#pass",
            "value": "secret123",
            "options": {"is_sensitive": true}
        })];
        let result = steps_to_display(&steps);
        assert!(!result[0].description.contains("secret123"));
        assert!(!result[0].value.as_deref().unwrap_or("").contains("secret123"));
    }

    #[test]
    fn test_scroll_direction() {
        let down = vec![json!({"type": "scroll", "options": {"deltaY": 500}})];
        let up = vec![json!({"type": "scroll", "options": {"deltaY": -200}})];
        assert!(steps_to_display(&down)[0].description.contains("down"));
        assert!(steps_to_display(&up)[0].description.contains("up"));
    }
}
