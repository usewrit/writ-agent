use std::collections::BTreeMap;

use serde_json::Value;

use crate::models::step::icon_for_step;

/// Generate a human-readable summary of the workflow.
///
/// Counts step types, lists the first 5 steps with icons, and reports totals.
pub fn generate_workflow_summary(steps: &[Value]) -> String {
    if steps.is_empty() {
        return "Empty workflow".to_string();
    }

    let mut summary_parts: Vec<String> = Vec::new();

    // Count step types (BTreeMap for deterministic ordering)
    let mut type_counts: BTreeMap<String, usize> = BTreeMap::new();
    for step in steps {
        let t = step
            .get("type")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown")
            .to_string();
        *type_counts.entry(t).or_insert(0) += 1;
    }

    // Header
    summary_parts.push(format!("{} steps total:", steps.len()));

    // Type breakdown
    for (step_type, count) in &type_counts {
        let icon = icon_for_step(step_type);
        let plural = if *count > 1 { "s" } else { "" };
        summary_parts.push(format!("  {} {} {} action{}", icon, count, step_type, plural));
    }

    // Preview first 5 steps
    summary_parts.push(String::new());
    summary_parts.push("Workflow preview:".to_string());
    for (i, step) in steps.iter().take(5).enumerate() {
        let step_type = step.get("type").and_then(|v| v.as_str()).unwrap_or("");
        let icon = icon_for_step(step_type);
        let desc = step
            .get("description")
            .and_then(|v| v.as_str())
            .unwrap_or(step_type);
        summary_parts.push(format!("  {}. {} {}", i + 1, icon, desc));
    }

    if steps.len() > 5 {
        summary_parts.push(format!("  ... and {} more steps", steps.len() - 5));
    }

    summary_parts.join("\n")
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn test_empty() {
        assert_eq!(generate_workflow_summary(&[]), "Empty workflow");
    }

    #[test]
    fn test_summary_content() {
        let steps = vec![
            json!({"type": "navigate", "url": "https://example.com"}),
            json!({"type": "click", "selector": "#btn", "description": "Click Login"}),
            json!({"type": "fill", "selector": "#email", "value": "test@test.com"}),
        ];
        let result = generate_workflow_summary(&steps);
        assert!(result.contains("3 steps total:"));
        assert!(result.contains("navigate"));
        assert!(result.contains("click"));
        assert!(result.contains("fill"));
        assert!(result.contains("Workflow preview:"));
        assert!(result.contains("Click Login"));
    }

    #[test]
    fn test_more_than_five() {
        let steps: Vec<Value> = (0..8)
            .map(|_| json!({"type": "click", "selector": "#x"}))
            .collect();
        let result = generate_workflow_summary(&steps);
        assert!(result.contains("... and 3 more steps"));
    }
}
