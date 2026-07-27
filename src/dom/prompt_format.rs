use crate::models::dom::*;

/// Convert raw accessibility data into a compact text block for the AI prompt.
///
/// Intentionally omits the semantic tree — field details are already in the
/// FORM FIELDS section of the prompt. We only surface *non-redundant* info:
/// page text, errors, toasts, iframes, scroll state.
pub fn format_a11y_tree_for_prompt(a11y_data: &AccessibilityTree, max_chars: usize) -> String {
    let mut parts: Vec<String> = Vec::new();

    // PAGE CONTEXT: title + headings + step indicator (skip body text paragraphs)
    let mut ctx_lines: Vec<String> = Vec::new();
    for section in &a11y_data.page_text {
        match section.text_type.as_str() {
            "title" => {
                ctx_lines.push(format!("  Title: {}", section.text));
            }
            "heading" => {
                let level = section.level.unwrap_or(2) as usize;
                let hashes = "#".repeat(level);
                let vp = if section.in_viewport == Some(false) {
                    " [below fold]"
                } else {
                    ""
                };
                ctx_lines.push(format!("  {} {}{}", hashes, section.text, vp));
            }
            "progress" => {
                ctx_lines.push(format!("  Progress: {}", section.text));
            }
            // skip body text paragraphs — they bloat the prompt with marginal value
            _ => {}
        }
    }
    if !ctx_lines.is_empty() {
        parts.push(format!("PAGE CONTEXT:\n{}", ctx_lines.join("\n")));
    }

    // VALIDATION ERRORS — high value, always include (up to 5)
    if !a11y_data.errors.is_empty() {
        let mut err_lines: Vec<String> = Vec::new();
        for err in a11y_data.errors.iter().take(5) {
            if let Some(fi) = err.field_index {
                err_lines.push(format!("  [field {}] {}", fi, err.message));
            } else if !err.field.is_empty() {
                err_lines.push(format!("  [{}] {}", err.field, err.message));
            } else {
                err_lines.push(format!("  {}", err.message));
            }
        }
        parts.push(format!("VALIDATION ERRORS:\n{}", err_lines.join("\n")));
    }

    // NOTIFICATIONS — short, high value (up to 3)
    if !a11y_data.toasts.is_empty() {
        let t_lines: Vec<String> = a11y_data
            .toasts
            .iter()
            .take(3)
            .map(|t| format!("  [{}] {}", t.toast_type.to_uppercase(), t.message))
            .collect();
        parts.push(format!("NOTIFICATIONS:\n{}", t_lines.join("\n")));
    }

    // IFRAMES — payment only (up to 3)
    let notable: Vec<&IframeInfo> = a11y_data
        .iframes
        .iter()
        .filter(|i| i.purpose == "payment")
        .take(3)
        .collect();
    if !notable.is_empty() {
        let i_lines: Vec<String> = notable
            .iter()
            .map(|iframe| format!("  [{}] {}", iframe.index, iframe.purpose))
            .collect();
        parts.push(format!("IFRAMES:\n{}", i_lines.join("\n")));
    }

    // SCROLL status — one line
    if a11y_data.has_more_below || a11y_data.has_more_above {
        let mut indicators: Vec<&str> = Vec::new();
        if a11y_data.has_more_above {
            indicators.push("content above");
        }
        if a11y_data.has_more_below {
            indicators.push("content below");
        }
        parts.push(format!("SCROLL: {}", indicators.join(", ")));
    }

    let result = parts.join("\n\n");
    if result.len() > max_chars {
        // Byte-slicing a `&str` PANICS off a UTF-8 char boundary, and every byte here came from the
        // page (`<title>`, headings, validation messages, toast text) — a multi-byte glyph straddling
        // the limit crashed the AI step. `truncate` walks back to the nearest boundary.
        let truncated = truncate(&result, max_chars.saturating_sub(15));
        format!("{}\n  ...(truncated)", truncated)
    } else {
        result
    }
}

/// Convert a DOM diff into a compact text block for the AI prompt.
///
/// Returns an empty string if the diff is `None` or contains no changes.
/// Uses prefix characters: `+` added, `-` removed, `~` changed.
pub fn format_diff_for_prompt(diff: Option<&DOMDiff>) -> String {
    let diff = match diff {
        Some(d) if !d.is_empty() => d,
        _ => return String::new(),
    };

    let mut lines: Vec<String> = vec!["CHANGES SINCE LAST ACTION:".to_string()];

    if let Some(ref url_change) = diff.url_changed {
        let from = truncate(&url_change.from, 60);
        let to = truncate(&url_change.to, 60);
        lines.push(format!("  Page navigated: {} \u{2192} {}", from, to));
    }

    if diff.success_detected {
        lines.push("  \u{2713} SUCCESS indicators now visible!".to_string());
    }

    for f in &diff.fields_added {
        lines.push(format!("  + Field [{}] appeared: \"{}\"", f.index, f.label));
    }

    for f in &diff.fields_removed {
        lines.push(format!(
            "  - Field [{}] disappeared: \"{}\"",
            f.index, f.label
        ));
    }

    for f in &diff.fields_changed {
        lines.push(format!(
            "  ~ Field [{}] changed: {} \u{2192} {}",
            f.index, f.before, f.after
        ));
    }

    if diff.field_count_change != 0 {
        let direction = if diff.field_count_change > 0 {
            "more"
        } else {
            "fewer"
        };
        lines.push(format!(
            "  Field count: {} {} fields",
            diff.field_count_change.unsigned_abs(),
            direction
        ));
    }

    for b in &diff.buttons_appeared {
        lines.push(format!("  + Button appeared: \"{}\"", b));
    }

    for b in &diff.buttons_disappeared {
        lines.push(format!("  - Button gone: \"{}\"", b));
    }

    for e in &diff.errors_appeared {
        lines.push(format!("  \u{26a0} Error appeared: \"{}\"", e));
    }

    for e in &diff.errors_cleared {
        lines.push(format!("  \u{2713} Error cleared: \"{}\"", e));
    }

    for t in &diff.toasts_appeared {
        lines.push(format!("  \u{1f514} Notification: \"{}\"", t));
    }

    for t in diff.new_text_appeared.iter().take(3) {
        lines.push(format!("  New text: \"{}\"", t));
    }

    if diff.scrolled != 0 {
        let direction = if diff.scrolled > 0 { "down" } else { "up" };
        lines.push(format!("  Scrolled {} {}px", direction, diff.scrolled.abs()));
    }

    if lines.len() > 1 {
        lines.join("\n")
    } else {
        String::new()
    }
}

/// Truncate a string to at most `max_len` BYTES, never splitting a UTF-8 character.
fn truncate(s: &str, max_len: usize) -> &str {
    if s.len() <= max_len {
        s
    } else {
        // Find a safe char boundary
        let mut end = max_len;
        while !s.is_char_boundary(end) && end > 0 {
            end -= 1;
        }
        &s[..end]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_diff_returns_empty_string() {
        assert_eq!(format_diff_for_prompt(None), "");

        let empty = DOMDiff {
            fields_added: vec![],
            fields_removed: vec![],
            fields_changed: vec![],
            field_count_change: 0,
            buttons_appeared: vec![],
            buttons_disappeared: vec![],
            errors_appeared: vec![],
            errors_cleared: vec![],
            toasts_appeared: vec![],
            url_changed: None,
            success_detected: false,
            scrolled: 0,
            new_text_appeared: vec![],
        };
        assert_eq!(format_diff_for_prompt(Some(&empty)), "");
    }

    #[test]
    fn diff_with_changes_produces_output() {
        let diff = DOMDiff {
            fields_added: vec![FieldChange {
                index: 2,
                label: "Phone".to_string(),
            }],
            fields_removed: vec![],
            fields_changed: vec![],
            field_count_change: 1,
            buttons_appeared: vec!["Continue".to_string()],
            buttons_disappeared: vec![],
            errors_appeared: vec!["Email is required".to_string()],
            errors_cleared: vec![],
            toasts_appeared: vec![],
            url_changed: None,
            success_detected: false,
            scrolled: 0,
            new_text_appeared: vec![],
        };
        let result = format_diff_for_prompt(Some(&diff));
        assert!(result.contains("CHANGES SINCE LAST ACTION:"));
        assert!(result.contains("Field [2] appeared: \"Phone\""));
        assert!(result.contains("Button appeared: \"Continue\""));
        assert!(result.contains("Error appeared: \"Email is required\""));
        assert!(result.contains("1 more fields"));
    }

    #[test]
    fn a11y_format_with_all_sections() {
        let a11y = AccessibilityTree {
            tree: serde_json::Value::Null,
            page_text: vec![
                PageTextSection {
                    text_type: "title".to_string(),
                    text: "Registration".to_string(),
                    level: None,
                    in_viewport: None,
                },
                PageTextSection {
                    text_type: "heading".to_string(),
                    text: "Create Account".to_string(),
                    level: Some(1),
                    in_viewport: Some(true),
                },
                PageTextSection {
                    text_type: "progress".to_string(),
                    text: "Step 1 of 3".to_string(),
                    level: None,
                    in_viewport: None,
                },
            ],
            errors: vec![ValidationError {
                field_index: Some(0),
                field: "Name".to_string(),
                message: "Name is required".to_string(),
                error_type: None,
            }],
            toasts: vec![ToastMessage {
                message: "Saved!".to_string(),
                toast_type: "success".to_string(),
            }],
            iframes: vec![],
            url: "https://example.com".to_string(),
            title: "Registration".to_string(),
            viewport: ViewportInfo {
                width: 1280,
                height: 720,
            },
            scroll_position: ScrollPosition { x: 0, y: 0 },
            scroll_height: 2000,
            has_more_below: true,
            has_more_above: false,
            timestamp: 0,
        };
        let result = format_a11y_tree_for_prompt(&a11y, 5000);
        assert!(result.contains("PAGE CONTEXT:"));
        assert!(result.contains("Title: Registration"));
        assert!(result.contains("# Create Account"));
        assert!(result.contains("Progress: Step 1 of 3"));
        assert!(result.contains("VALIDATION ERRORS:"));
        assert!(result.contains("[field 0] Name is required"));
        assert!(result.contains("NOTIFICATIONS:"));
        assert!(result.contains("[SUCCESS] Saved!"));
        assert!(result.contains("SCROLL: content below"));
    }

    /// REGRESSION: the truncation byte-sliced attacker-controlled page text, so a multi-byte glyph
    /// straddling `max_chars - 15` panicked the AI step. Sweep the cut point across a run of 2-, 3-
    /// and 4-byte characters so every possible straddle is exercised.
    #[test]
    fn a11y_truncation_is_char_boundary_safe() {
        for glyph in ["é", "漢", "🙂"] {
            for max_chars in 20..80 {
                let a11y = AccessibilityTree {
                    tree: serde_json::Value::Null,
                    page_text: vec![PageTextSection {
                        text_type: "title".to_string(),
                        text: glyph.repeat(200),
                        level: None,
                        in_viewport: None,
                    }],
                    errors: vec![],
                    toasts: vec![],
                    iframes: vec![],
                    url: String::new(),
                    title: String::new(),
                    viewport: ViewportInfo::default(),
                    scroll_position: ScrollPosition::default(),
                    scroll_height: 0,
                    has_more_below: false,
                    has_more_above: false,
                    timestamp: 0,
                };
                let out = format_a11y_tree_for_prompt(&a11y, max_chars);
                assert!(
                    out.ends_with("...(truncated)"),
                    "glyph={glyph} max_chars={max_chars} out={out}"
                );
            }
        }
    }

    #[test]
    fn truncate_never_splits_a_codepoint() {
        let s = "aé漢🙂";
        assert_eq!(truncate(s, 0), "");
        assert_eq!(truncate(s, 1), "a");
        assert_eq!(truncate(s, 2), "a", "mid-'é' walks back");
        assert_eq!(truncate(s, 3), "aé");
        assert_eq!(truncate(s, 5), "aé", "mid-'漢' walks back");
        assert_eq!(truncate(s, 999), s);
    }

    #[test]
    fn a11y_format_truncates() {
        let a11y = AccessibilityTree {
            tree: serde_json::Value::Null,
            page_text: vec![PageTextSection {
                text_type: "title".to_string(),
                text: "A very long title that should be included".to_string(),
                level: None,
                in_viewport: None,
            }],
            errors: vec![],
            toasts: vec![],
            iframes: vec![],
            url: String::new(),
            title: String::new(),
            viewport: ViewportInfo::default(),
            scroll_position: ScrollPosition::default(),
            scroll_height: 0,
            has_more_below: false,
            has_more_above: false,
            timestamp: 0,
        };
        let result = format_a11y_tree_for_prompt(&a11y, 30);
        assert!(result.contains("...(truncated)"));
    }
}
