use std::collections::HashMap;

use crate::models::ai::ActionHistoryEntry;

pub fn build_intelligent_prompt(
    dom_fields_text: &str,
    buttons_text: &str,
    current_url: &str,
    goal: &str,
    user_context: Option<&str>,
    available_data: &HashMap<String, String>,
    action_history: &[ActionHistoryEntry],
    a11y_text: &str,
    dom_diff_text: &str,
    secure_keys: &[String],
    has_dropdowns: bool,
) -> String {
    let mut prompt = String::with_capacity(4096);

    prompt.push_str("You are an AI browser automation agent. Your task is to interact with a web page to achieve a goal.\n\n");
    prompt.push_str(&format!("GOAL: {}\n", goal));

    if let Some(ctx) = user_context {
        if !ctx.is_empty() {
            prompt.push_str(&format!("CONTEXT: {}\n", ctx));
        }
    }

    prompt.push_str(&format!("\nCURRENT URL: {}\n", current_url));

    // Fields
    if !dom_fields_text.is_empty() {
        prompt.push_str(&format!("\nFIELDS ON PAGE:\n{}\n", dom_fields_text));
    }

    // Buttons
    if !buttons_text.is_empty() {
        prompt.push_str(&format!("\nBUTTONS:\n{}\n", buttons_text));
    }

    // Available data
    if !available_data.is_empty() {
        prompt.push_str("\nAVAILABLE DATA:\n");
        for (key, value) in available_data {
            if secure_keys.contains(key) {
                prompt.push_str(&format!("  {} = (secure credential)\n", key));
            } else {
                prompt.push_str(&format!("  {} = {}\n", key, value));
            }
        }
    }

    // Action history
    if !action_history.is_empty() {
        prompt.push_str("\nRECENT ACTIONS:\n");
        let start = action_history.len().saturating_sub(5);
        for entry in &action_history[start..] {
            let status = if entry.verified { "✓" } else { "✗" };
            let desc = match &entry.data_key {
                Some(dk) => format!("{} (data_key={})", entry.action, dk),
                None => entry.action.clone(),
            };
            prompt.push_str(&format!("  {} {}\n", status, desc));
        }
    }

    // A11y tree data
    if !a11y_text.is_empty() {
        prompt.push_str(&format!("\n{}\n", a11y_text));
    }

    // DOM diff
    if !dom_diff_text.is_empty() {
        prompt.push_str(&format!("\n{}\n", dom_diff_text));
    }

    // Loop detection
    if action_history.len() >= 3 {
        let recent = &action_history[action_history.len().saturating_sub(3)..];
        if let Some(fi) = recent[0].field_index {
            if recent.iter().all(|e| e.field_index == Some(fi)) {
                prompt.push_str(&format!(
                    "\n🚨 CRITICAL: You have targeted field_index {} three times. Try a DIFFERENT approach.\n",
                    fi
                ));
            }
        }
    }

    // Dropdown rules
    if has_dropdowns {
        prompt.push_str("\nDROPDOWN RULES: For native <select> elements, use the 'select' action. For custom dropdowns, click to open then click the option.\n");
    }

    prompt.push_str("\nRespond with a JSON action. Available actions: fill, select, check, click, submit, scroll, scroll_to_field, hover, press_key, evaluate_js, extract_data, wait_for_change, wait, wait_for, solve_captcha, inspect_field, read_text, list_tabs, switch_tab, wait_for_tab, close_tab, batch, complete, blocked\n");
    prompt.push_str("wait_for_change watches a selector until its text/attribute/html changes (or a region visually changes) then returns the new value, e.g. {\"action\":\"wait_for_change\",\"selector\":\".price\",\"change_kind\":\"text\",\"variable\":\"new_price\",\"timeout\":20}\n");

    prompt
}

#[allow(clippy::too_many_arguments)]
pub fn build_standard_prompt(
    dom_fields_text: &str,
    buttons_text: &str,
    goal: &str,
    available_data: &HashMap<String, String>,
    filled_fields: &[String],
    _clicked_field_indices: &[usize],
    has_captcha: bool,
    secure_keys: &[String],
) -> String {
    let mut prompt = String::with_capacity(2048);

    prompt.push_str(&format!("Analyze this page to achieve: {}\n\n", goal));

    if !dom_fields_text.is_empty() {
        prompt.push_str(&format!("FIELDS:\n{}\n", dom_fields_text));
    }

    if !buttons_text.is_empty() {
        prompt.push_str(&format!("\nBUTTONS:\n{}\n", buttons_text));
    }

    if !available_data.is_empty() {
        prompt.push_str("\nDATA AVAILABLE:\n");
        for (key, value) in available_data {
            let marker = if filled_fields.contains(key) {
                " (ALREADY FILLED - SKIP)"
            } else {
                ""
            };
            // Secure values (passwords, tokens) must never be echoed verbatim
            // into the prompt — the model only needs to know the key exists so
            // it can reference it as {{key}} / {{secret:key}}.
            if secure_keys.contains(key) {
                prompt.push_str(&format!("  {} = (secure credential){}\n", key, marker));
            } else {
                prompt.push_str(&format!("  {} = {}{}\n", key, value, marker));
            }
        }
    }

    if has_captcha {
        prompt.push_str("\nCAPTCHA DETECTED on page.\n");
    }

    prompt.push_str("\nReturn JSON: {\"status\": \"continue\"|\"complete\"|\"blocked\", \"needs_scroll\": bool, \"mappings\": [...], \"submit_button\": {...}}\n");

    prompt
}

#[allow(clippy::too_many_arguments)]
pub fn build_api_discovery_prompt(
    dom_fields_text: &str,
    current_url: &str,
    goal: &str,
    available_data: &HashMap<String, String>,
    network_calls_text: &str,
    discovered_apis: &[String],
    secure_keys: &[String],
) -> String {
    let mut prompt = String::with_capacity(2048);

    prompt.push_str(&format!("You are discovering API endpoints by navigating a website.\n\nGOAL: {}\n", goal));
    prompt.push_str(&format!("CURRENT URL: {}\n", current_url));

    if !dom_fields_text.is_empty() {
        prompt.push_str(&format!("\nFIELDS:\n{}\n", dom_fields_text));
    }

    if !available_data.is_empty() {
        prompt.push_str("\nAVAILABLE DATA:\n");
        for (key, value) in available_data {
            // Never echo secure values verbatim (see build_standard_prompt).
            if secure_keys.contains(key) {
                prompt.push_str(&format!("  {} = (secure credential)\n", key));
            } else {
                prompt.push_str(&format!("  {} = {}\n", key, value));
            }
        }
    }

    if !network_calls_text.is_empty() {
        prompt.push_str(&format!("\nCAPTURED NETWORK CALLS:\n{}\n", network_calls_text));
    }

    if !discovered_apis.is_empty() {
        prompt.push_str("\nALREADY DISCOVERED:\n");
        for api in discovered_apis {
            prompt.push_str(&format!("  - {}\n", api));
        }
    }

    prompt.push_str("\nReturn JSON with: action to take next + any api_steps discovered from the network calls.\n");

    prompt
}

pub fn format_action_history(history: &[ActionHistoryEntry], max_entries: usize) -> String {
    let start = history.len().saturating_sub(max_entries);
    let mut output = String::new();

    for (i, entry) in history[start..].iter().enumerate() {
        let status = if entry.verified { "OK" } else { "FAIL" };
        output.push_str(&format!(
            "  {}. [{}] {} ",
            start + i + 1,
            status,
            entry.action
        ));
        if let Some(fi) = entry.field_index {
            output.push_str(&format!("field_index={} ", fi));
        }
        if let Some(dk) = &entry.data_key {
            output.push_str(&format!("data_key={} ", dk));
        }
        if let Some(err) = &entry.error {
            output.push_str(&format!("error={}", err));
        }
        output.push('\n');
    }

    output
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_data() -> HashMap<String, String> {
        let mut d = HashMap::new();
        d.insert("username".to_string(), "alice".to_string());
        d.insert("password".to_string(), "hunter2-secret".to_string());
        d
    }

    #[test]
    fn standard_prompt_masks_secure_key_value() {
        let data = sample_data();
        let prompt = build_standard_prompt(
            "",
            "",
            "log in",
            &data,
            &[],
            &[],
            false,
            &["password".to_string()],
        );
        assert!(prompt.contains("password = (secure credential)"));
        assert!(!prompt.contains("hunter2-secret"));
        // Non-secure values still pass through.
        assert!(prompt.contains("username = alice"));
    }

    #[test]
    fn api_discovery_prompt_masks_secure_key_value() {
        let data = sample_data();
        let prompt = build_api_discovery_prompt(
            "",
            "https://example.com",
            "discover",
            &data,
            "",
            &[],
            &["password".to_string()],
        );
        assert!(prompt.contains("password = (secure credential)"));
        assert!(!prompt.contains("hunter2-secret"));
        assert!(prompt.contains("username = alice"));
    }
}
