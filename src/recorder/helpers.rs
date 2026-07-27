use crate::models::step::ViewportSize;

pub const HELPER_SCRIPT_JS: &str = include_str!("../../js/helper_script.js");
pub const ELEMENT_AT_COORDINATES_JS: &str = include_str!("../../js/element_at_coordinates.js");

/// Run a one-parameter JS probe (`(sel) => …`) against `selector`, passing the
/// selector as a serialized `evaluate` ARGUMENT.
///
/// SECURITY — never interpolate a selector into JS source. The recorder used to
/// build probes as `format!("((sel) => …)('{}')", selector.replace('\'', "\\'"))`.
/// That escape prepends a backslash to each quote but never escapes pre-existing
/// backslashes, so a selector containing `\'` becomes `\\'` — JS reads `\\` as ONE
/// literal backslash and the following `'` then CLOSES the string literal, so the
/// rest of the selector is parsed as code. Selectors here are derived IN-PAGE from
/// page-controlled attributes (`js/element_at_coordinates.js`,
/// `js/helper_script.js`'s `escapeCSS`) with weaker escaping still, so
/// `<input name='a\');globalThis.PWNED=1;//'>` was a working breakout that ran
/// arbitrary JS in the recorder's page context.
///
/// Passing the value as an argument makes it a string, always, with no escaping to
/// get wrong. `scroll_element_into_view` above is the same pattern.
pub async fn eval_selector_probe<T: serde::de::DeserializeOwned>(
    page: &playwright_rs::Page,
    js: &str,
    selector: &str,
) -> Result<T, anyhow::Error> {
    crate::browser::page_query::evaluate_with_args::<T>(page, js, serde_json::json!(selector)).await
}

pub fn default_viewport() -> ViewportSize {
    ViewportSize {
        width: crate::config::constants::VIEWPORT_WIDTH,
        height: crate::config::constants::VIEWPORT_HEIGHT,
    }
}

pub fn is_input_element(tag: &str) -> bool {
    matches!(
        tag.to_lowercase().as_str(),
        "input" | "textarea" | "select"
    )
}

pub fn is_clickable_element(tag: &str) -> bool {
    matches!(
        tag.to_lowercase().as_str(),
        "a" | "button" | "input" | "summary" | "details"
    )
}

pub fn is_checkable_type(input_type: &str) -> bool {
    matches!(
        input_type.to_lowercase().as_str(),
        "checkbox" | "radio"
    )
}

pub fn is_sensitive_field(field_type: &str, field_name: &str) -> bool {
    let t = field_type.to_lowercase();
    let n = field_name.to_lowercase();
    t == "password"
        || n.contains("password")
        || n.contains("secret")
        || n.contains("token")
        || n.contains("api_key")
        || n.contains("apikey")
        || n.contains("ssn")
        || n.contains("credit_card")
        || n.contains("card_number")
}

/// 1:1 port of Python _get_viewport (recorder.py line 611).
pub async fn get_viewport(page: &playwright_rs::Page) -> ViewportSize {
    if let Some(vp) = page.viewport_size() {
        ViewportSize {
            width: vp.width,
            height: vp.height,
        }
    } else {
        default_viewport()
    }
}

/// 1:1 port of Python _get_element_center (recorder.py line 622).
pub async fn get_element_center(
    page: &playwright_rs::Page,
    selector: &str,
) -> Option<(i32, i32)> {
    let locator = page.locator(selector).await;
    match locator.bounding_box().await {
        Ok(Some(bb)) => Some((
            (bb.x + bb.width / 2.0) as i32,
            (bb.y + bb.height / 2.0) as i32,
        )),
        _ => None,
    }
}

/// 1:1 port of Python _ensure_element_visible (recorder.py line 1808).
/// Checks if element at coordinates is visible and finds scrollable parent info.
pub async fn ensure_element_visible(
    page: &playwright_rs::Page,
    x: f64,
    y: f64,
) -> Option<serde_json::Value> {
    let js = format!(
        r#"(() => {{
            const el = document.elementFromPoint({x}, {y});
            if (!el) return {{ found: false }};

            const rect = el.getBoundingClientRect();
            const viewportHeight = window.innerHeight;
            const viewportWidth = window.innerWidth;

            const isFullyVisible = rect.top >= 0 && rect.bottom <= viewportHeight &&
                                   rect.left >= 0 && rect.right <= viewportWidth;
            const isPartiallyVisible = rect.bottom > 0 && rect.top < viewportHeight &&
                                       rect.right > 0 && rect.left < viewportWidth;

            let scrollParent = el.parentElement;
            let scrollableContainer = null;
            while (scrollParent) {{
                const style = window.getComputedStyle(scrollParent);
                const overflow = style.overflow + style.overflowY + style.overflowX;
                if (overflow.includes('scroll') || overflow.includes('auto')) {{
                    if (scrollParent.scrollHeight > scrollParent.clientHeight ||
                        scrollParent.scrollWidth > scrollParent.clientWidth) {{
                        scrollableContainer = scrollParent;
                        break;
                    }}
                }}
                scrollParent = scrollParent.parentElement;
            }}

            return {{
                found: true,
                isFullyVisible: isFullyVisible,
                isPartiallyVisible: isPartiallyVisible,
                hasScrollableParent: scrollableContainer !== null,
                elementRect: {{ top: rect.top, bottom: rect.bottom, left: rect.left, right: rect.right }},
                viewportHeight: viewportHeight,
                viewportWidth: viewportWidth,
            }};
        }})()"#,
        x = x,
        y = y,
    );
    crate::browser::page_query::evaluate(page, &js).await.ok()
}

/// 1:1 port of Python _scroll_element_into_view (recorder.py line 1857).
/// Scrolls element into view, returns true if scrolling was needed.
pub async fn scroll_element_into_view(
    page: &playwright_rs::Page,
    selector: &str,
) -> bool {
    let js = r#"((selector) => {
        const el = document.querySelector(selector);
        if (!el) return false;

        const rect = el.getBoundingClientRect();
        const viewportHeight = window.innerHeight;

        if (rect.top >= 0 && rect.bottom <= viewportHeight) {
            return false;
        }

        el.scrollIntoView({ behavior: 'instant', block: 'center', inline: 'nearest' });
        return true;
    })"#;

    match crate::browser::page_query::evaluate_with_args::<bool>(
        page,
        js,
        serde_json::json!(selector),
    )
    .await
    {
        Ok(scrolled) => {
            if scrolled {
                tokio::time::sleep(std::time::Duration::from_millis(200)).await;
            }
            scrolled
        }
        Err(_) => false,
    }
}

/// 1:1 port of Python _wait_for_element_stable (recorder.py line 1883).
/// Waits for element at coordinates to stop moving/animating (within 1px tolerance).
pub async fn wait_for_element_stable(
    page: &playwright_rs::Page,
    x: f64,
    y: f64,
    timeout_ms: u64,
) -> bool {
    let start = std::time::Instant::now();
    let mut last_rect: Option<(f64, f64, f64, f64)> = None;

    while start.elapsed().as_millis() < timeout_ms as u128 {
        let js = format!(
            r#"(() => {{
                const el = document.elementFromPoint({x}, {y});
                if (!el) return null;
                const rect = el.getBoundingClientRect();
                return {{ top: rect.top, left: rect.left, width: rect.width, height: rect.height }};
            }})()"#,
            x = x,
            y = y,
        );

        let rect_val: Option<serde_json::Value> =
            match crate::browser::page_query::evaluate(page, &js).await {
                Ok(v) => v,
                Err(_) => return true,
            };

        let Some(rect) = rect_val else {
            return false;
        };

        let top = rect.get("top").and_then(|v| v.as_f64()).unwrap_or(0.0);
        let left = rect.get("left").and_then(|v| v.as_f64()).unwrap_or(0.0);
        let width = rect.get("width").and_then(|v| v.as_f64()).unwrap_or(0.0);
        let height = rect.get("height").and_then(|v| v.as_f64()).unwrap_or(0.0);

        if let Some((lt, ll, _lw, _lh)) = last_rect {
            if (top - lt).abs() < 1.0 && (left - ll).abs() < 1.0 {
                return true;
            }
        }

        last_rect = Some((top, left, width, height));
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }

    true // Timeout — assume stable
}

#[cfg(test)]
mod tests {
    /// Verified breakout payloads for the old
    /// `format!("…('{}')", selector.replace('\'', "\\'"))` pattern. The escape
    /// prepends a backslash to each `'` but never escapes pre-existing backslashes,
    /// so `\'` became `\\'` — JS reads `\\` as ONE literal backslash and the `'`
    /// then closes the string, so the tail is parsed as code.
    const HOSTILE_SELECTORS: &[&str] = &[
        r#"input[name='a\');globalThis.PWNED=1;//']"#,
        r#"a\'"#,
        r#"[x='\']);globalThis.PWNED=1;//"#,
        "input'/*",
        "a'+(globalThis.PWNED=1)+'",
        "div\n#x",
        r#"[title="a\\"]"#,
    ];

    /// The exact escape idiom that made those payloads work. Sources that build a
    /// selector probe must not reintroduce it.
    const UNSOUND_ESCAPE: &str = r#".replace('\'', "\\'")"#;

    /// Recorder sources that build JS around a page-derived selector.
    const SELECTOR_PROBE_SOURCES: &[(&str, &str)] = &[
        ("pending.rs", include_str!("pending.rs")),
        ("click_handler.rs", include_str!("click_handler.rs")),
        ("action_handler.rs", include_str!("action_handler.rs")),
    ];

    #[test]
    fn the_legacy_escape_is_demonstrably_unsound() {
        // Documents WHY the pattern is banned rather than merely "improved": for a
        // selector that already contains a backslash, the produced JS literal ends
        // early and the remainder is code.
        let hostile = r#"a\');globalThis.PWNED=1;//"#;
        let escaped = hostile.replace('\'', "\\'");
        assert_eq!(escaped, r#"a\\');globalThis.PWNED=1;//"#);

        // Walk `'<escaped>'` the way a JS parser does and find where the literal
        // actually ends: the first quote NOT preceded by an escaping backslash.
        let mut it = escaped.char_indices();
        let mut closed_at = None;
        while let Some((i, c)) = it.next() {
            match c {
                '\\' => {
                    it.next(); // the backslash escapes whatever follows
                }
                '\'' => {
                    closed_at = Some(i);
                    break;
                }
                _ => {}
            }
        }
        let closed_at = closed_at.expect("the escaped selector still closes the literal early");
        assert_eq!(
            &escaped[closed_at + 1..],
            ");globalThis.PWNED=1;//",
            "everything after the premature close is parsed as JS code"
        );
    }

    #[test]
    fn no_recorder_source_still_interpolates_a_selector_with_the_unsound_escape() {
        for (name, src) in SELECTOR_PROBE_SOURCES {
            assert!(
                !src.contains(UNSOUND_ESCAPE),
                "{name} reintroduced the unsound JS quote escape — pass the selector as an \
                 evaluate argument (see helpers::eval_selector_probe) instead"
            );
        }
    }

    #[test]
    fn hostile_selectors_stay_values_when_passed_as_evaluate_arguments() {
        // The fix: the selector becomes a JSON argument, so it is always a complete
        // string value and can never terminate a JS literal.
        for hostile in HOSTILE_SELECTORS {
            let arg = serde_json::json!(hostile);
            assert_eq!(arg.as_str(), Some(*hostile), "payload preserved verbatim");
            let wire = serde_json::to_string(&arg).expect("serializable");
            assert!(
                wire.starts_with('"') && wire.ends_with('"'),
                "must be one self-contained JSON string: {wire}"
            );
            let back: String = serde_json::from_str(&wire).expect("round trip");
            assert_eq!(&back, *hostile);
            // Nothing escaped out: every `"` and `\` inside is escaped, so the only
            // unescaped quotes are the delimiters.
            let inner = &wire[1..wire.len() - 1];
            let mut chars = inner.chars().peekable();
            while let Some(c) = chars.next() {
                if c == '\\' {
                    chars.next(); // consume the escaped char
                } else {
                    assert_ne!(c, '"', "an unescaped quote would close the literal: {wire}");
                }
            }
        }
    }

    // ── Shipped-JS escaping (the in-page half of the same bug) ───────────────

    #[test]
    fn helper_script_selector_escaping_is_not_double_escaped() {
        let js = super::HELPER_SCRIPT_JS;
        // `escapeCSS` embeds a value in a DOUBLE-quoted selector string, so it must
        // insert exactly ONE backslash. The shipped file carried Rust/Python-style
        // double escaping (`'\\\\$&'`), which produced `\\"` — a literal backslash
        // followed by an UNESCAPED quote that closes the selector string.
        assert!(
            js.contains(r#"replace(/["\\]/g, '\\$&')"#),
            "escapeCSS must single-escape both quote and backslash"
        );
        assert!(
            !js.contains(r#"'\\\\$&'"#),
            "the double-escaped replacement must be gone"
        );
        // The whitespace regexes were double-escaped too: `/\\s+/` matches a literal
        // backslash followed by "s", so runs of whitespace were never collapsed.
        assert!(
            !js.contains(r"/\\s+/"),
            r"js/helper_script.js still contains a double-escaped /\\s+/ regex"
        );
        assert!(js.contains(r"/\s+/"), "the real whitespace class must be used");
    }

    #[test]
    fn element_at_coordinates_escapes_backslash_as_well_as_quote() {
        let js = super::ELEMENT_AT_COORDINATES_JS;
        // Selectors here are built from page-controlled attribute values and embedded
        // in double-quoted selector strings. Escaping only `"` let a value ending in a
        // backslash swallow the escape and close the string.
        assert!(
            !js.contains(r#"replace(/"/g, '\\"')"#),
            "quote-only escaping must be gone"
        );
        assert!(
            js.contains(r#"replace(/["\\]/g, '\\$&')"#),
            "must escape backslash and quote in one pass"
        );
    }

    #[test]
    fn aria_level_is_clamped_before_it_reaches_a_rust_u8() {
        // `models::dom::PageTextSection.level` is `Option<u8>`, so an unbounded
        // page-controlled `aria-level` ("300") failed deserialization for the WHOLE
        // payload — the AI agent silently lost ALL page context for that turn.
        for (name, js) in [
            ("js/accessibility_tree.js", include_str!("../../js/accessibility_tree.js")),
            ("js/page_context.js", include_str!("../../js/page_context.js")),
        ] {
            assert!(
                js.contains("Math.min(6, Math.max(1, parsed))"),
                "{name} must clamp aria-level into 1..=6"
            );
            assert!(
                js.contains("Number.isFinite(parsed)"),
                "{name} must fall back for a non-numeric aria-level"
            );
            assert!(
                !js.contains("level: parseInt(level)"),
                "{name} still pushes a raw, unbounded parseInt"
            );
        }
    }

    #[test]
    fn shared_selector_probe_is_a_parameterised_function() {
        // A probe passed to eval_selector_probe must be an `((sel) => …)` form, i.e.
        // take the selector rather than embed it.
        let js = super::super::pending::PICKER_VALUE_PROBE_JS;
        assert!(js.contains("(sel)"), "probe must take a selector parameter: {js}");
        assert!(!js.contains("{}"), "probe must carry no format placeholder: {js}");
    }
}
