const PLAYWRIGHT_SELECTOR_PATTERNS: &[&str] = &[
    ":visible",
    ":has-text(",
    ":text(",
    ":has(",
    ">> ",
    ":nth-match(",
    "role=",
    ":right-of(",
    ":left-of(",
    ":above(",
    ":below(",
    ":near(",
];

pub fn is_css_selector(selector: &str) -> bool {
    !PLAYWRIGHT_SELECTOR_PATTERNS
        .iter()
        .any(|p| selector.contains(p))
}

pub fn translate_selector(selector: &str) -> TranslatedSelector {
    // role=button[name="X"] → get_by_role("button", name="X")
    if let Some(rest) = selector.strip_prefix("role=") {
        if let Some(bracket_start) = rest.find('[') {
            let role = &rest[..bracket_start];
            let attrs = &rest[bracket_start + 1..rest.len() - 1];
            return TranslatedSelector::ByRole {
                role: role.to_string(),
                name: extract_attr_value(attrs, "name"),
            };
        }
        return TranslatedSelector::ByRole {
            role: rest.to_string(),
            name: None,
        };
    }

    // text="X" → get_by_text("X")
    if let Some(text) = selector.strip_prefix("text=") {
        return TranslatedSelector::ByText(text.trim_matches('"').to_string());
    }

    // label="X" → get_by_label("X")
    if let Some(label) = selector.strip_prefix("label=") {
        return TranslatedSelector::ByLabel(label.trim_matches('"').to_string());
    }

    // Default: use as CSS selector or Playwright locator
    if is_css_selector(selector) {
        TranslatedSelector::Css(selector.to_string())
    } else {
        TranslatedSelector::Locator(selector.to_string())
    }
}

#[derive(Debug, Clone)]
pub enum TranslatedSelector {
    Css(String),
    Locator(String),
    ByRole { role: String, name: Option<String> },
    ByText(String),
    ByLabel(String),
    ByPlaceholder(String),
}

fn extract_attr_value(attrs: &str, attr_name: &str) -> Option<String> {
    let prefix = format!("{}=", attr_name);
    attrs
        .split("][")
        .find(|a| a.starts_with(&prefix))
        .map(|a| a[prefix.len()..].trim_matches('"').to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_css_selector() {
        assert!(is_css_selector("#my-id"));
        assert!(is_css_selector(".my-class"));
        assert!(is_css_selector("input[type='text']"));
        assert!(!is_css_selector("role=button"));
        assert!(!is_css_selector("input:visible"));
        assert!(!is_css_selector("button:has-text('Submit')"));
        assert!(!is_css_selector("div >> input"));
    }

    #[test]
    fn test_translate_role() {
        match translate_selector("role=button[name=\"Submit\"]") {
            TranslatedSelector::ByRole { role, name } => {
                assert_eq!(role, "button");
                assert_eq!(name, Some("Submit".to_string()));
            }
            _ => panic!("Expected ByRole"),
        }
    }

    #[test]
    fn test_translate_text() {
        match translate_selector("text=\"Click me\"") {
            TranslatedSelector::ByText(t) => assert_eq!(t, "Click me"),
            _ => panic!("Expected ByText"),
        }
    }

    #[test]
    fn test_translate_css() {
        match translate_selector("#submit-btn") {
            TranslatedSelector::Css(s) => assert_eq!(s, "#submit-btn"),
            _ => panic!("Expected Css"),
        }
    }
}
