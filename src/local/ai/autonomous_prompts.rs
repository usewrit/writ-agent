//! Form-filler (autonomous-session) prompt — the Rust port of the Python recorder's
//! `_ai_analyze_page` DIRECTIVE prompt (`recorder.py` ~L7421-7480). This is the SIMPLER
//! `{status, mappings, submit_button}` schema, distinct from the agent-brain prompt in
//! [`super::prompts`]. Keep the text faithful to the Python source; the model's decision
//! JSON is consumed by [`super::session::run_session`].

use serde_json::Value;

/// Static directive header of the form-filler prompt (everything before the per-turn data).
/// Byte-faithful to the Python prompt's fixed preamble.
pub const FORM_FILLER_HEADER: &str = "You are a form-filling AI. Use the SCREENSHOT to understand the form visually, and the DETECTED FIELDS list for exact field positions.";

/// The response-format + rules tail of the form-filler prompt (everything after the per-turn data).
/// Byte-faithful to the Python prompt's fixed trailer.
pub const FORM_FILLER_RULES: &str = r#"YOUR TASK:
1. Look at the SCREENSHOT to understand the form layout and field purposes
2. FILL ALL FORM FIELDS - match available data keys to fields, OR create a descriptive data_key for fields without matching data
3. Use the screenshot to verify field types and understand context (e.g., which checkbox matches which option)

RESPONSE FORMAT:
{
  "status": "continue" | "complete" | "blocked",
  "needs_scroll": false,
  "mappings": [
    {"field_index": 0, "data_key": "fullname", "action": "type_text"},
    {"field_index": 1, "data_key": "email", "action": "type_text"},
    {"field_index": 2, "data_key": "motivation_letter", "action": "type_text"},
    {"field_index": 3, "action": "click", "reason": "checkbox matching poste_voulu value"}
  ],
  "submit_button": "Submit" or null if not visible
}

RULES:
1. CRITICAL: You MUST fill ALL detected form fields, not just those with matching data
2. For TEXT/EMAIL/TEXTAREA/DATE fields: action = "type_text", include data_key
3. For SELECT/LISTBOX/COMBOBOX (dropdowns): action = "select", include data_key with the option value to select
4. For CHECKBOX/RADIO: action = "click", match checkbox label to the VALUE of the data (e.g., if poste_voulu="Poste 2", click the checkbox labeled "Poste 2")
5. For fields WITH matching available data: use that data_key
6. For fields WITHOUT matching data: create a descriptive data_key based on the field label (e.g., "motivation_letter", "country", "birth_date")
7. Skip data_keys already in "ALREADY FILLED DATA KEYS" - DO NOT fill them again
8. Skip field_indices already in "ALREADY CLICKED FIELD INDICES" - DO NOT click them again
9. Only include submit_button AFTER all form fields have been mapped
10. If not all fields are visible, set needs_scroll: true
11. If page shows success/thank you, return status="complete"
12. For CAPTCHA: If captcha is detected, add a mapping with action="solve_captcha", include captcha_type, selector, and coordinates (x, y). Place this BEFORE the submit button.
13. NEED THE USER? If you cannot proceed without a DECISION or DATA only the user can give — which of several accounts/items to use, a value that is NOT in your data, an unexpected login field you have no credential for, or a block you genuinely cannot clear — return status="blocked" with a clear, ONE-SENTENCE QUESTION for the user in "reason" (phrase it as a question, e.g. "Which account should I use — personal or work?"). Do NOT guess, do NOT fill the wrong value, and do NOT give up: the user answers and you resume with their answer.
    LOGIN CREDENTIAL you don't have: when the blocker is that the login form needs a credential you weren't given, LOOK at the ACTUAL form and add a "credential_fields" array naming exactly the input(s) the site shows — do NOT assume username+password. Mark secrets (keys/passwords/tokens) "secret":true. Examples: an API-key login → {"status":"blocked","reason":"What's your API key for this site?","credential_fields":[{"field":"login_key","label":"API key","secret":true}]}; a user+password login → "credential_fields":[{"field":"login_username","label":"Username","secret":false},{"field":"login_password","label":"Password","secret":true}]. The user types it, it's sealed to the vault, and you resume with it in your fill data — you never see the value. Name each field login_&lt;something&gt;.

EXAMPLE:
Fields: TEXT "Nom" at (400,200), EMAIL "Email" at (400,280), SELECT "Country" at (400,350), TEXTAREA "Message" at (400,450), CHECKBOX "Option B" at (150,550)
Data: fullname="John", email="john@test.com", country="France", choice="Option B"
Response: {"status": "continue", "needs_scroll": false, "mappings": [
  {"field_index": 0, "data_key": "fullname", "action": "type_text"},
  {"field_index": 1, "data_key": "email", "action": "type_text"},
  {"field_index": 2, "data_key": "country", "action": "select"},
  {"field_index": 3, "data_key": "message", "action": "type_text"},
  {"field_index": 4, "action": "click"}
], "submit_button": "Submit"}

Return ONLY valid JSON."#;

/// Render the DETECTED FORM FIELDS block from an observation's `fields` array, marking already-
/// clicked checkbox/radio indices with `[ALREADY CLICKED - SKIP]`. Mirrors the Python
/// `fields_lines` builder.
fn render_fields(fields: &[Value], clicked_indices: &[usize]) -> String {
    if fields.is_empty() {
        return "  No fields found".to_string();
    }
    let mut lines = Vec::with_capacity(fields.len());
    for f in fields {
        let idx = f.get("index").and_then(|v| v.as_u64()).unwrap_or(0) as usize;
        let field_type = f
            .get("type")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown")
            .to_lowercase();
        let is_checkbox_type = matches!(field_type.as_str(), "checkbox" | "radio");
        let label = f.get("label").and_then(|v| v.as_str()).unwrap_or("unknown");
        let x = f.get("x").and_then(|v| v.as_i64());
        let y = f.get("y").and_then(|v| v.as_i64());
        let required = f.get("required").and_then(|v| v.as_bool()).unwrap_or(false);
        let coords = match (x, y) {
            (Some(x), Some(y)) => format!("({}, {})", x, y),
            _ => "(?, ?)".to_string(),
        };
        let req_marker = if required { " [required]" } else { "" };
        let status_marker = if is_checkbox_type && clicked_indices.contains(&idx) {
            " [ALREADY CLICKED - SKIP]"
        } else {
            ""
        };
        lines.push(format!(
            "  - [{}] {} \"{}\" at {}{}{}",
            idx,
            field_type.to_uppercase(),
            label,
            coords,
            req_marker,
            status_marker
        ));
    }
    lines.join("\n")
}

/// Render the DETECTED BUTTONS block from an observation's `buttons` array.
fn render_buttons(buttons: &[Value]) -> String {
    if buttons.is_empty() {
        return "  No buttons found".to_string();
    }
    buttons
        .iter()
        .map(|b| {
            let text = b.get("text").and_then(|v| v.as_str()).unwrap_or("");
            let x = b.get("x").and_then(|v| v.as_i64());
            let y = b.get("y").and_then(|v| v.as_i64());
            let coords = match (x, y) {
                (Some(x), Some(y)) => format!("({}, {})", x, y),
                _ => "(?, ?)".to_string(),
            };
            format!("  - \"{}\" at {}", text, coords)
        })
        .collect::<Vec<_>>()
        .join("\n")
}

/// Render the optional CAPTCHA DETECTED block from an observation's `captcha_info`. Empty when
/// no captcha is present.
fn render_captcha(captcha_info: &Value) -> String {
    if captcha_info.is_null() {
        return String::new();
    }
    let ty = captcha_info
        .get("type")
        .and_then(|v| v.as_str())
        .unwrap_or("unknown");
    let x = captcha_info.get("x").and_then(|v| v.as_i64()).unwrap_or(0);
    let y = captcha_info.get("y").and_then(|v| v.as_i64()).unwrap_or(0);
    let w = captcha_info.get("width").and_then(|v| v.as_i64()).unwrap_or(0);
    let h = captcha_info.get("height").and_then(|v| v.as_i64()).unwrap_or(0);
    let sel = captcha_info
        .get("selector")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    format!(
        "\nCAPTCHA DETECTED:\n  - Type: {}\n  - Position: ({}, {})\n  - Size: {}x{}\n  - Selector: {}\n  NOTE: Include a captcha step in your mappings with action=\"solve_captcha\"\n",
        ty, x, y, w, h, sel
    )
}

/// Build the complete form-filler USER prompt (the text part; the screenshot is attached
/// separately as an image content-part). Ported from the Python `_ai_analyze_page` prompt.
///
/// * `goal` — the user's objective.
/// * `fields` / `buttons` / `captcha_info` — from [`super::observation::build_ai_observation`].
/// * `available_data` — the data keys/values the model may fill (secret values are placeholders).
/// * `filled_fields` — data keys already filled (skip re-filling).
/// * `clicked_indices` — checkbox/radio field indices already clicked (skip re-clicking).
pub fn build_form_filler_prompt(
    goal: &str,
    fields: &[Value],
    buttons: &[Value],
    captcha_info: &Value,
    available_data: &std::collections::HashMap<String, String>,
    filled_fields: &[String],
    clicked_indices: &[usize],
) -> String {
    // AVAILABLE DATA block (mark already-filled keys). Sort for deterministic output.
    let available_data_str = if available_data.is_empty() {
        "  None provided".to_string()
    } else {
        let mut keys: Vec<&String> = available_data.keys().collect();
        keys.sort();
        keys.iter()
            .map(|k| {
                let v = available_data.get(*k).map(|s| s.as_str()).unwrap_or("");
                let status = if filled_fields.iter().any(|f| f == *k) {
                    " (ALREADY FILLED - SKIP)"
                } else {
                    ""
                };
                format!("  - {}: \"{}\"{}", k, v, status)
            })
            .collect::<Vec<_>>()
            .join("\n")
    };

    let filled_fields_str = if filled_fields.is_empty() {
        "None yet".to_string()
    } else {
        filled_fields.join(", ")
    };
    let clicked_indices_str = if clicked_indices.is_empty() {
        "None yet".to_string()
    } else {
        clicked_indices
            .iter()
            .map(|i| i.to_string())
            .collect::<Vec<_>>()
            .join(", ")
    };

    let fields_text = render_fields(fields, clicked_indices);
    let buttons_text = render_buttons(buttons);
    let captcha_str = render_captcha(captcha_info);

    format!(
        "{header}\n\nGOAL: {goal}\n\nDETECTED FORM FIELDS (from DOM analysis - use these exact indices):\n{fields}\n\nDETECTED BUTTONS:\n{buttons}\n{captcha}\nAVAILABLE DATA TO FILL:\n{data}\n\nALREADY FILLED DATA KEYS (DO NOT FILL AGAIN): {filled}\nALREADY CLICKED FIELD INDICES (DO NOT CLICK AGAIN): {clicked}\n\n{rules}",
        header = FORM_FILLER_HEADER,
        goal = goal,
        fields = fields_text,
        buttons = buttons_text,
        captcha = captcha_str,
        data = available_data_str,
        filled = filled_fields_str,
        clicked = clicked_indices_str,
        rules = FORM_FILLER_RULES,
    )
}
