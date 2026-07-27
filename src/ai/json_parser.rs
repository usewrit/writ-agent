/// Parse JSON from AI response text, handling various wrapping patterns.
///
/// Tries five strategies in order:
/// 1. Direct `serde_json::from_str`
/// 2. Extract from ` ```json ... ``` ` code block
/// 3. Extract from bare ` ``` ... ``` ` code block
/// 4. Regex match outermost `{ ... }`
/// 5. Regex match outermost `[ ... ]`
pub fn parse_ai_json(text: &str) -> Option<serde_json::Value> {
    let text = text.trim();

    // Strategy 1: direct parse
    if let Ok(v) = serde_json::from_str::<serde_json::Value>(text) {
        return Some(v);
    }

    // Some tool-capable models occasionally omit only the final `}`/`]` even for a very short,
    // otherwise complete response. Repair ONLY clean EOF delimiter omissions: strings must be
    // closed, escapes complete, and every encountered closer must match. We deliberately do not
    // invent quotes, values, commas, or repair mid-string truncation.
    if let Some(repaired) = close_missing_eof_delimiters(text) {
        if let Ok(v) = serde_json::from_str::<serde_json::Value>(&repaired) {
            tracing::debug!(missing = repaired.len().saturating_sub(text.len()), "repaired AI JSON missing final delimiter(s)");
            return Some(v);
        }
    }

    // Strategy 2: ```json ... ``` block
    if let Some(start) = text.find("```json") {
        let after = &text[start + 7..];
        if let Some(end) = after.find("```") {
            let inner = after[..end].trim();
            if let Ok(v) = serde_json::from_str::<serde_json::Value>(inner) {
                return Some(v);
            }
        }
    }

    // Strategy 3: bare ``` ... ``` block
    if let Some(start) = text.find("```") {
        let after = &text[start + 3..];
        if let Some(end) = after.find("```") {
            let inner = after[..end].trim();
            if let Ok(v) = serde_json::from_str::<serde_json::Value>(inner) {
                return Some(v);
            }
        }
    }

    // Strategy 4: outermost { ... }
    if let Some(obj_start) = text.find('{') {
        if let Some(obj_end) = text.rfind('}') {
            if obj_end > obj_start {
                let candidate = &text[obj_start..=obj_end];
                if let Ok(v) = serde_json::from_str::<serde_json::Value>(candidate) {
                    return Some(v);
                }
            }
        }
    }

    // Strategy 5: outermost [ ... ]
    if let Some(arr_start) = text.find('[') {
        if let Some(arr_end) = text.rfind(']') {
            if arr_end > arr_start {
                let candidate = &text[arr_start..=arr_end];
                if let Ok(v) = serde_json::from_str::<serde_json::Value>(candidate) {
                    return Some(v);
                }
            }
        }
    }

    // Char-safe truncation: `&text[..n]` panics on a multibyte boundary.
    let preview: String = text.chars().take(200).collect();
    tracing::warn!(
        preview = %preview,
        "Could not parse JSON from AI response"
    );
    None
}

fn close_missing_eof_delimiters(text: &str) -> Option<String> {
    let mut stack: Vec<char> = Vec::new();
    let mut in_string = false;
    let mut escaped = false;
    for ch in text.chars() {
        if in_string {
            if escaped { escaped = false; }
            else if ch == '\\' { escaped = true; }
            else if ch == '"' { in_string = false; }
            continue;
        }
        match ch {
            '"' => in_string = true,
            '{' => stack.push('}'),
            '[' => stack.push(']'),
            '}' | ']' if stack.pop() != Some(ch) => return None,
            _ => {}
        }
    }
    if in_string || escaped || stack.is_empty() { return None; }
    let mut repaired = text.to_string();
    while let Some(close) = stack.pop() { repaired.push(close); }
    Some(repaired)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn direct_json() {
        let v = parse_ai_json(r#"{"action":"click","x":10}"#).unwrap();
        assert_eq!(v["action"], "click");
    }

    #[test]
    fn json_code_block() {
        let input = "Here is the result:\n```json\n{\"ok\":true}\n```\nDone.";
        let v = parse_ai_json(input).unwrap();
        assert_eq!(v["ok"], true);
    }

    #[test]
    fn bare_code_block() {
        let input = "```\n[1,2,3]\n```";
        let v = parse_ai_json(input).unwrap();
        assert!(v.is_array());
    }

    #[test]
    fn embedded_object() {
        let input = "The answer is {\"x\":42} as expected";
        let v = parse_ai_json(input).unwrap();
        assert_eq!(v["x"], 42);
    }

    #[test]
    fn embedded_array() {
        let input = "Results: [1,2,3] end";
        let v = parse_ai_json(input).unwrap();
        assert_eq!(v.as_array().unwrap().len(), 3);
    }

    #[test]
    fn unparseable_returns_none() {
        assert!(parse_ai_json("no json here").is_none());
    }

    #[test]
    fn repairs_missing_final_object_brace() {
        let input = r#"{"action":"act","do":[{"type":"click","selector":"button"}]"#;
        let v = parse_ai_json(input).unwrap();
        assert_eq!(v["do"][0]["type"], "click");
    }

    #[test]
    fn does_not_invent_an_unterminated_string() {
        assert!(parse_ai_json("{\"action\":\"act\",\"selector\":\"#broken").is_none());
    }
}
