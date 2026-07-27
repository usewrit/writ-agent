use serde_json::Value;

use super::optimize::optimize_steps;

/// Escape a string for use in Python double-quoted single-line string literals.
///
/// Escapes backslash and double-quote, plus newline/CR/tab, so a value or
/// selector containing raw control characters can't break out of the literal.
fn escape_for_python(s: &str) -> String {
    s.replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('\n', "\\n")
        .replace('\r', "\\r")
        .replace('\t', "\\t")
}

/// Convert recorded steps to clean Playwright Python code.
///
/// When `async_mode` is true, generates `async def run_workflow(page):` with `await` calls.
/// When false, generates `def run_workflow(page):` with synchronous calls.
///
/// Sensitive fill values are redacted to `{{secret:field_name}}`.
pub fn steps_to_playwright_python(steps: &[Value], async_mode: bool) -> String {
    let steps = optimize_steps(steps);
    let mut lines: Vec<String> = Vec::new();
    let i = "    "; // single indent

    if async_mode {
        lines.push("async def run_workflow(page):".to_string());
    } else {
        lines.push("def run_workflow(page):".to_string());
    }

    if steps.is_empty() {
        lines.push(format!("{}pass", i));
        return lines.join("\n");
    }

    for step in &steps {
        let step_type = step.get("type").and_then(|v| v.as_str()).unwrap_or("");
        let selector = escape_for_python(
            step.get("selector").and_then(|v| v.as_str()).unwrap_or(""),
        );
        let value = step.get("value").and_then(|v| v.as_str()).unwrap_or("");
        let url = escape_for_python(step.get("url").and_then(|v| v.as_str()).unwrap_or(""));
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
            format!("{{{{secret:{}}}}}", escape_for_python(field_name))
        } else {
            escape_for_python(value)
        };

        match step_type {
            "navigate" => {
                if async_mode {
                    lines.push(format!("{}await page.goto(\"{}\")", i, url));
                } else {
                    lines.push(format!("{}page.goto(\"{}\")", i, url));
                }
            }

            "click" => {
                if !selector.is_empty() {
                    if async_mode {
                        lines.push(format!("{}await page.click(\"{}\")", i, selector));
                    } else {
                        lines.push(format!("{}page.click(\"{}\")", i, selector));
                    }
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
                    if async_mode {
                        lines.push(format!("{}await page.mouse.click({}, {})", i, x, y));
                    } else {
                        lines.push(format!("{}page.mouse.click({}, {})", i, x, y));
                    }
                }
            }

            "fill" => {
                if async_mode {
                    lines.push(format!(
                        "{}await page.fill(\"{}\", \"{}\")",
                        i, selector, emit_value
                    ));
                } else {
                    lines.push(format!("{}page.fill(\"{}\", \"{}\")", i, selector, emit_value));
                }
            }

            "type" => {
                if async_mode {
                    lines.push(format!("{}await page.keyboard.type(\"{}\")", i, emit_value));
                } else {
                    lines.push(format!("{}page.keyboard.type(\"{}\")", i, emit_value));
                }
            }

            "press" => {
                if async_mode {
                    lines.push(format!("{}await page.keyboard.press(\"{}\")", i, emit_value));
                } else {
                    lines.push(format!("{}page.keyboard.press(\"{}\")", i, emit_value));
                }
            }

            "select" => {
                if async_mode {
                    lines.push(format!(
                        "{}await page.select_option(\"{}\", \"{}\")",
                        i, selector, emit_value
                    ));
                } else {
                    lines.push(format!(
                        "{}page.select_option(\"{}\", \"{}\")",
                        i, selector, emit_value
                    ));
                }
            }

            "check" => {
                if async_mode {
                    lines.push(format!("{}await page.check(\"{}\")", i, selector));
                } else {
                    lines.push(format!("{}page.check(\"{}\")", i, selector));
                }
            }

            "scroll" => {
                let delta_y = options
                    .and_then(|o| o.get("deltaY"))
                    .and_then(|d| d.as_i64())
                    .unwrap_or(500);
                if async_mode {
                    lines.push(format!("{}await page.mouse.wheel(0, {})", i, delta_y));
                } else {
                    lines.push(format!("{}page.mouse.wheel(0, {})", i, delta_y));
                }
            }

            "wait" => {
                let duration = options
                    .and_then(|o| o.get("duration"))
                    .and_then(|d| d.as_i64())
                    .unwrap_or(1000);
                if async_mode {
                    lines.push(format!("{}await page.wait_for_timeout({})", i, duration));
                } else {
                    lines.push(format!("{}page.wait_for_timeout({})", i, duration));
                }
            }

            "screenshot" => {
                if async_mode {
                    lines.push(format!("{}await page.screenshot()", i));
                } else {
                    lines.push(format!("{}page.screenshot()", i));
                }
            }

            _ => {}
        }
    }

    lines.join("\n")
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn test_empty_async() {
        let result = steps_to_playwright_python(&[], true);
        assert!(result.contains("async def run_workflow(page):"));
        assert!(result.contains("pass"));
    }

    #[test]
    fn test_empty_sync() {
        let result = steps_to_playwright_python(&[], false);
        assert!(result.starts_with("def run_workflow(page):"));
        assert!(result.contains("pass"));
    }

    #[test]
    fn test_navigate_async() {
        let steps = vec![json!({"type": "navigate", "url": "https://example.com"})];
        let result = steps_to_playwright_python(&steps, true);
        assert!(result.contains("await page.goto(\"https://example.com\")"));
    }

    #[test]
    fn test_fill_sensitive() {
        let steps = vec![json!({
            "type": "fill",
            "selector": "#pass",
            "value": "secret123",
            "options": {"is_sensitive": true, "field_name": "password"}
        })];
        let result = steps_to_playwright_python(&steps, true);
        assert!(result.contains("{{secret:password}}"));
        assert!(!result.contains("secret123"));
    }

    #[test]
    fn test_type_sensitive_redacted() {
        // A sensitive value must be redacted in the "type" branch too, not just
        // "fill" — otherwise a recorded password leaks as a plaintext literal.
        let steps = vec![json!({
            "type": "type",
            "value": "secret123",
            "options": {"is_sensitive": true, "field_name": "totp"}
        })];
        let result = steps_to_playwright_python(&steps, true);
        assert!(result.contains("{{secret:totp}}"));
        assert!(!result.contains("secret123"));
    }

    #[test]
    fn test_select_sensitive_redacted() {
        let steps = vec![json!({
            "type": "select",
            "selector": "#dd",
            "value": "secret123",
            "options": {"is_sensitive": true, "field_name": "pin"}
        })];
        let result = steps_to_playwright_python(&steps, false);
        assert!(result.contains("{{secret:pin}}"));
        assert!(!result.contains("secret123"));
    }

    #[test]
    fn test_newline_value_escaped() {
        // A raw newline/tab in a value must not break the single-line literal.
        let steps = vec![json!({
            "type": "type",
            "value": "line1\nline2\tcol"
        })];
        let result = steps_to_playwright_python(&steps, true);
        assert!(result.contains("line1\\nline2\\tcol"));
        // No literal newline inside the generated type() call line.
        let call_line = result
            .lines()
            .find(|l| l.contains("keyboard.type"))
            .unwrap();
        assert!(!call_line.contains('\n'));
    }

    #[test]
    fn test_click_coordinates() {
        let steps = vec![json!({
            "type": "click",
            "coordinates": {"x": 100, "y": 200}
        })];
        let result = steps_to_playwright_python(&steps, false);
        assert!(result.contains("page.mouse.click(100, 200)"));
    }

    #[test]
    fn test_sync_mode() {
        let steps = vec![
            json!({"type": "navigate", "url": "https://example.com"}),
            json!({"type": "click", "selector": "#btn"}),
        ];
        let result = steps_to_playwright_python(&steps, false);
        assert!(!result.contains("await"));
        assert!(result.contains("page.goto("));
        assert!(result.contains("page.click("));
    }
}
