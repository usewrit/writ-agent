use serde_json::Value;

/// Escape a string for use in JS double-quoted single-line string literals.
///
/// Escapes backslash and double-quote, plus newline/CR/tab, so a value or
/// selector containing raw control characters can't break out of the literal.
fn escape_for_js(s: &str) -> String {
    s.replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('\n', "\\n")
        .replace('\r', "\\r")
        .replace('\t', "\\t")
}

/// Convert recorded steps to Playwright JavaScript code.
///
/// Generates an async `runWorkflow(page)` function with `module.exports`.
/// Uses JS-style API names: `selectOption`, `waitForTimeout`.
pub fn steps_to_playwright_js(steps: &[Value]) -> String {
    let mut lines: Vec<String> = Vec::new();
    let indent = "  ";

    lines.push("const { chromium } = require('playwright');".to_string());
    lines.push(String::new());
    lines.push("async function runWorkflow(page) {".to_string());

    for step in steps {
        let step_type = step.get("type").and_then(|v| v.as_str()).unwrap_or("");
        let selector = escape_for_js(
            step.get("selector").and_then(|v| v.as_str()).unwrap_or(""),
        );
        let value = step.get("value").and_then(|v| v.as_str()).unwrap_or("");
        let url = escape_for_js(step.get("url").and_then(|v| v.as_str()).unwrap_or(""));

        let options = step.get("options");
        let is_sensitive = options
            .and_then(|o| o.get("is_sensitive"))
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        let field_name = options
            .and_then(|o| o.get("field_name"))
            .and_then(|v| v.as_str())
            .unwrap_or("password");

        // Redact sensitive values for EVERY value-emitting branch (fill/type/
        // press/select). A recorded secret must never be emitted as a plaintext
        // literal; downstream substitutes `{{secret:<field>}}` at run time.
        let emit_value = if is_sensitive {
            format!("{{{{secret:{}}}}}", escape_for_js(field_name))
        } else {
            escape_for_js(value)
        };

        match step_type {
            "navigate" => {
                lines.push(format!("{}await page.goto(\"{}\");", indent, url));
            }

            "click" => {
                if !selector.is_empty() {
                    lines.push(format!("{}await page.click(\"{}\");", indent, selector));
                } else {
                    let coords = step.get("coordinates");
                    let x = coords
                        .and_then(|c| c.get("x"))
                        .and_then(|v| v.as_i64())
                        .unwrap_or(0);
                    let y = coords
                        .and_then(|c| c.get("y"))
                        .and_then(|v| v.as_i64())
                        .unwrap_or(0);
                    lines.push(format!(
                        "{}await page.mouse.click({}, {});",
                        indent, x, y
                    ));
                }
            }

            "fill" => {
                lines.push(format!(
                    "{}await page.fill(\"{}\", \"{}\");",
                    indent, selector, emit_value
                ));
            }

            "type" => {
                lines.push(format!(
                    "{}await page.keyboard.type(\"{}\");",
                    indent, emit_value
                ));
            }

            "press" => {
                lines.push(format!(
                    "{}await page.keyboard.press(\"{}\");",
                    indent, emit_value
                ));
            }

            "select" => {
                lines.push(format!(
                    "{}await page.selectOption(\"{}\", \"{}\");",
                    indent, selector, emit_value
                ));
            }

            "check" => {
                lines.push(format!("{}await page.check(\"{}\");", indent, selector));
            }

            "scroll" => {
                let delta_y = step
                    .get("options")
                    .and_then(|o| o.get("deltaY"))
                    .and_then(|d| d.as_i64())
                    .unwrap_or(500);
                lines.push(format!(
                    "{}await page.mouse.wheel(0, {});",
                    indent, delta_y
                ));
            }

            "wait" => {
                let duration = step
                    .get("options")
                    .and_then(|o| o.get("duration"))
                    .and_then(|d| d.as_i64())
                    .unwrap_or(1000);
                lines.push(format!(
                    "{}await page.waitForTimeout({});",
                    indent, duration
                ));
            }

            "screenshot" => {
                lines.push(format!("{}await page.screenshot();", indent));
            }

            _ => {}
        }
    }

    lines.push("}".to_string());
    lines.push(String::new());
    lines.push("module.exports = { runWorkflow };".to_string());

    lines.join("\n")
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn test_basic_js() {
        let steps = vec![
            json!({"type": "navigate", "url": "https://example.com"}),
            json!({"type": "click", "selector": "#btn"}),
        ];
        let result = steps_to_playwright_js(&steps);
        assert!(result.contains("const { chromium } = require('playwright');"));
        assert!(result.contains("async function runWorkflow(page) {"));
        assert!(result.contains("await page.goto(\"https://example.com\");"));
        assert!(result.contains("await page.click(\"#btn\");"));
        assert!(result.contains("module.exports = { runWorkflow };"));
    }

    #[test]
    fn test_select_option_js() {
        let steps = vec![json!({
            "type": "select",
            "selector": "#dropdown",
            "value": "option1"
        })];
        let result = steps_to_playwright_js(&steps);
        assert!(result.contains("selectOption"));
    }

    #[test]
    fn test_fill_sensitive_redacted_js() {
        // The JS generator previously had ZERO redaction — a recorded password
        // leaked as a plaintext literal. It must now emit {{secret:<field>}}.
        let steps = vec![json!({
            "type": "fill",
            "selector": "#pass",
            "value": "secret123",
            "options": {"is_sensitive": true, "field_name": "password"}
        })];
        let result = steps_to_playwright_js(&steps);
        assert!(result.contains("{{secret:password}}"));
        assert!(!result.contains("secret123"));
    }

    #[test]
    fn test_type_sensitive_redacted_js() {
        let steps = vec![json!({
            "type": "type",
            "value": "secret123",
            "options": {"is_sensitive": true, "field_name": "totp"}
        })];
        let result = steps_to_playwright_js(&steps);
        assert!(result.contains("{{secret:totp}}"));
        assert!(!result.contains("secret123"));
    }

    #[test]
    fn test_newline_value_escaped_js() {
        let steps = vec![json!({
            "type": "type",
            "value": "line1\nline2\tcol"
        })];
        let result = steps_to_playwright_js(&steps);
        assert!(result.contains("line1\\nline2\\tcol"));
        let call_line = result
            .lines()
            .find(|l| l.contains("keyboard.type"))
            .unwrap();
        assert!(!call_line.contains('\n'));
    }

    #[test]
    fn test_wait_for_timeout_js() {
        let steps = vec![json!({"type": "wait", "options": {"duration": 2000}})];
        let result = steps_to_playwright_js(&steps);
        assert!(result.contains("waitForTimeout(2000)"));
    }
}
