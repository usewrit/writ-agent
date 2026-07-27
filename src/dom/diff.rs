use std::collections::{HashMap, HashSet};

use crate::models::dom::*;

// ---------------------------------------------------------------------------
// DOM diff engine — tracks state between turns and computes structured diffs
// ---------------------------------------------------------------------------

pub struct DOMDiffEngine {
    previous: Option<DOMSnapshot>,
}

impl DOMDiffEngine {
    pub fn new() -> Self {
        Self { previous: None }
    }

    /// Build a `DOMSnapshot` from the raw DOM state and optional accessibility data.
    ///
    /// Field signatures are formatted as `"type:label"` (lowercased).
    pub fn snapshot_from_state(
        dom_state: &DOMState,
        a11y_data: Option<&AccessibilityTree>,
    ) -> DOMSnapshot {
        let mut snap = DOMSnapshot {
            field_signatures: HashMap::new(),
            field_values: HashMap::new(),
            field_labels: HashMap::new(),
            button_texts: Vec::new(),
            error_messages: Vec::new(),
            toast_messages: Vec::new(),
            page_text_hashes: Vec::new(),
            url: dom_state.url.clone(),
            has_success: dom_state.has_success,
            scroll_y: 0,
            field_count: dom_state.fields.len(),
        };

        // Field signatures and labels
        for field in &dom_state.fields {
            let sig = format!("{}:{}", field.field_type, field.label).to_lowercase();
            snap.field_signatures.insert(field.index, sig);
            snap.field_labels.insert(field.index, field.label.clone());
        }

        // Button texts
        snap.button_texts = dom_state
            .buttons
            .iter()
            .map(|b| b.text.clone())
            .collect();

        // Data from the accessibility tree (errors, toasts, scroll, text sections)
        if let Some(a11y) = a11y_data {
            for err in &a11y.errors {
                snap.error_messages.push(err.message.clone());
            }
            for toast in &a11y.toasts {
                snap.toast_messages.push(toast.message.clone());
            }
            snap.scroll_y = a11y.scroll_position.y;
            for section in &a11y.page_text {
                // First 50 chars as a lightweight hash for diffing
                let hash: String = section.text.chars().take(50).collect();
                snap.page_text_hashes.push(hash);
            }
        }

        snap
    }

    /// Compare `current` against the previous snapshot, store `current` as the new
    /// previous, and return the diff.
    ///
    /// Returns `None` on the first call (no previous to compare) or when nothing changed.
    pub fn compute_diff(&mut self, current: DOMSnapshot) -> Option<DOMDiff> {
        let prev = match self.previous.take() {
            Some(p) => p,
            None => {
                self.previous = Some(current);
                return None;
            }
        };

        let prev_indices: HashSet<usize> = prev.field_signatures.keys().copied().collect();
        let curr_indices: HashSet<usize> = current.field_signatures.keys().copied().collect();

        // Fields added
        let added_indices: Vec<usize> = {
            let mut v: Vec<usize> = curr_indices.difference(&prev_indices).copied().collect();
            v.sort();
            v
        };
        let fields_added: Vec<FieldChange> = added_indices
            .iter()
            .map(|&i| FieldChange {
                index: i,
                label: current.field_labels.get(&i).cloned().unwrap_or_default(),
            })
            .collect();

        // Fields removed
        let removed_indices: Vec<usize> = {
            let mut v: Vec<usize> = prev_indices.difference(&curr_indices).copied().collect();
            v.sort();
            v
        };
        let fields_removed: Vec<FieldChange> = removed_indices
            .iter()
            .map(|&i| FieldChange {
                index: i,
                label: prev.field_labels.get(&i).cloned().unwrap_or_default(),
            })
            .collect();

        // Fields whose signature changed (same index, different type/label)
        let fields_changed: Vec<FieldValueChange> = prev_indices
            .intersection(&curr_indices)
            .filter_map(|&i| {
                let prev_sig = prev.field_signatures.get(&i)?;
                let curr_sig = current.field_signatures.get(&i)?;
                if prev_sig != curr_sig {
                    Some(FieldValueChange {
                        index: i,
                        before: prev_sig.clone(),
                        after: curr_sig.clone(),
                    })
                } else {
                    None
                }
            })
            .collect();

        // Field count change
        let field_count_change = current.field_count as i32 - prev.field_count as i32;

        // Button changes
        let prev_btns: HashSet<&str> = prev.button_texts.iter().map(|s| s.as_str()).collect();
        let curr_btns: HashSet<&str> = current.button_texts.iter().map(|s| s.as_str()).collect();
        let buttons_appeared: Vec<String> = curr_btns
            .difference(&prev_btns)
            .map(|s| s.to_string())
            .collect();
        let buttons_disappeared: Vec<String> = prev_btns
            .difference(&curr_btns)
            .map(|s| s.to_string())
            .collect();

        // Error changes
        let prev_errs: HashSet<&str> = prev.error_messages.iter().map(|s| s.as_str()).collect();
        let curr_errs: HashSet<&str> = current.error_messages.iter().map(|s| s.as_str()).collect();
        let errors_appeared: Vec<String> = curr_errs
            .difference(&prev_errs)
            .map(|s| s.to_string())
            .collect();
        let errors_cleared: Vec<String> = prev_errs
            .difference(&curr_errs)
            .map(|s| s.to_string())
            .collect();

        // Toast changes
        let prev_toasts: HashSet<&str> = prev.toast_messages.iter().map(|s| s.as_str()).collect();
        let curr_toasts: HashSet<&str> = current.toast_messages.iter().map(|s| s.as_str()).collect();
        let toasts_appeared: Vec<String> = curr_toasts
            .difference(&prev_toasts)
            .map(|s| s.to_string())
            .collect();

        // URL change
        let url_changed = if !prev.url.is_empty() && !current.url.is_empty() && prev.url != current.url {
            Some(UrlChange {
                from: prev.url.clone(),
                to: current.url.clone(),
            })
        } else {
            None
        };

        // Success state change
        let success_detected = !prev.has_success && current.has_success;

        // Scroll position change (threshold: 50px)
        let scroll_delta = current.scroll_y - prev.scroll_y;
        let scrolled = if scroll_delta.abs() > 50 {
            scroll_delta
        } else {
            0
        };

        // New page text (up to 5)
        let prev_texts: HashSet<&str> = prev.page_text_hashes.iter().map(|s| s.as_str()).collect();
        let curr_texts: HashSet<&str> = current
            .page_text_hashes
            .iter()
            .map(|s| s.as_str())
            .collect();
        let new_text_appeared: Vec<String> = curr_texts
            .difference(&prev_texts)
            .take(5)
            .map(|s| s.to_string())
            .collect();

        // Store current as previous
        self.previous = Some(current);

        let diff = DOMDiff {
            fields_added,
            fields_removed,
            fields_changed,
            field_count_change,
            buttons_appeared,
            buttons_disappeared,
            errors_appeared,
            errors_cleared,
            toasts_appeared,
            url_changed,
            success_detected,
            scrolled,
            new_text_appeared,
        };

        if diff.is_empty() {
            None
        } else {
            Some(diff)
        }
    }
}

impl Default for DOMDiffEngine {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_state(fields: Vec<DOMFieldInfo>, buttons: Vec<ButtonInfo>, url: &str) -> DOMState {
        DOMState {
            fields,
            buttons,
            has_success: false,
            has_error: false,
            has_captcha: false,
            url: url.to_string(),
            captcha_info: None,
        }
    }

    fn field(index: usize, field_type: &str, label: &str) -> DOMFieldInfo {
        DOMFieldInfo {
            index,
            field_type: field_type.to_string(),
            label: label.to_string(),
            x: 0.0,
            y: 0.0,
            selector: None,
            id: None,
            name: None,
            required: false,
            is_checkable: false,
            value: None,
            options: vec![],
        }
    }

    fn button(text: &str) -> ButtonInfo {
        ButtonInfo {
            text: text.to_string(),
            x: 0.0,
            y: 0.0,
            selector: None,
            tag: None,
            id: None,
            button_type: None,
        }
    }

    #[test]
    fn first_call_returns_none() {
        let mut engine = DOMDiffEngine::new();
        let state = make_state(vec![], vec![], "https://example.com");
        let snap = DOMDiffEngine::snapshot_from_state(&state, None);
        assert!(engine.compute_diff(snap).is_none());
    }

    #[test]
    fn no_change_returns_none() {
        let mut engine = DOMDiffEngine::new();
        let state = make_state(
            vec![field(0, "text", "Name")],
            vec![button("Submit")],
            "https://example.com",
        );
        let snap1 = DOMDiffEngine::snapshot_from_state(&state, None);
        let snap2 = DOMDiffEngine::snapshot_from_state(&state, None);
        engine.compute_diff(snap1);
        assert!(engine.compute_diff(snap2).is_none());
    }

    #[test]
    fn detects_field_added() {
        let mut engine = DOMDiffEngine::new();
        let state1 = make_state(vec![field(0, "text", "Name")], vec![], "https://example.com");
        let state2 = make_state(
            vec![field(0, "text", "Name"), field(1, "email", "Email")],
            vec![],
            "https://example.com",
        );
        let snap1 = DOMDiffEngine::snapshot_from_state(&state1, None);
        let snap2 = DOMDiffEngine::snapshot_from_state(&state2, None);
        engine.compute_diff(snap1);
        let diff = engine.compute_diff(snap2).unwrap();
        assert_eq!(diff.fields_added.len(), 1);
        assert_eq!(diff.fields_added[0].index, 1);
        assert_eq!(diff.fields_added[0].label, "Email");
        assert_eq!(diff.field_count_change, 1);
    }

    #[test]
    fn detects_field_removed() {
        let mut engine = DOMDiffEngine::new();
        let state1 = make_state(
            vec![field(0, "text", "Name"), field(1, "email", "Email")],
            vec![],
            "https://example.com",
        );
        let state2 = make_state(vec![field(0, "text", "Name")], vec![], "https://example.com");
        let snap1 = DOMDiffEngine::snapshot_from_state(&state1, None);
        let snap2 = DOMDiffEngine::snapshot_from_state(&state2, None);
        engine.compute_diff(snap1);
        let diff = engine.compute_diff(snap2).unwrap();
        assert_eq!(diff.fields_removed.len(), 1);
        assert_eq!(diff.fields_removed[0].index, 1);
        assert_eq!(diff.field_count_change, -1);
    }

    #[test]
    fn detects_button_changes() {
        let mut engine = DOMDiffEngine::new();
        let state1 = make_state(vec![], vec![button("Next")], "https://example.com");
        let state2 = make_state(vec![], vec![button("Submit")], "https://example.com");
        let snap1 = DOMDiffEngine::snapshot_from_state(&state1, None);
        let snap2 = DOMDiffEngine::snapshot_from_state(&state2, None);
        engine.compute_diff(snap1);
        let diff = engine.compute_diff(snap2).unwrap();
        assert_eq!(diff.buttons_appeared, vec!["Submit"]);
        assert_eq!(diff.buttons_disappeared, vec!["Next"]);
    }

    #[test]
    fn detects_url_change() {
        let mut engine = DOMDiffEngine::new();
        let state1 = make_state(vec![], vec![], "https://example.com/step1");
        let state2 = make_state(vec![], vec![], "https://example.com/step2");
        let snap1 = DOMDiffEngine::snapshot_from_state(&state1, None);
        let snap2 = DOMDiffEngine::snapshot_from_state(&state2, None);
        engine.compute_diff(snap1);
        let diff = engine.compute_diff(snap2).unwrap();
        let url_change = diff.url_changed.unwrap();
        assert_eq!(url_change.from, "https://example.com/step1");
        assert_eq!(url_change.to, "https://example.com/step2");
    }

    #[test]
    fn detects_success() {
        let mut engine = DOMDiffEngine::new();
        let state1 = make_state(vec![], vec![], "https://example.com");
        let mut state2 = make_state(vec![], vec![], "https://example.com");
        state2.has_success = true;
        let snap1 = DOMDiffEngine::snapshot_from_state(&state1, None);
        let snap2 = DOMDiffEngine::snapshot_from_state(&state2, None);
        engine.compute_diff(snap1);
        let diff = engine.compute_diff(snap2).unwrap();
        assert!(diff.success_detected);
    }
}
