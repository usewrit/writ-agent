use playwright_rs::Page;

use crate::browser::page_query;
use crate::models::ai::ActionVerification;
use crate::models::workflow::EndpointResult;

pub const DETECT_FORM_ENDPOINT_JS: &str = include_str!("../../js/detect_form_endpoint.js");

/// Verify an action result by checking the live DOM state.
pub async fn verify_action_result(
    page: &Page,
    action_type: &str,
    expected_value: Option<&str>,
    selector: Option<&str>,
) -> ActionVerification {
    match action_type {
        "fill" | "type_text" => verify_fill(page, expected_value, selector).await,
        "select" => verify_select(page, expected_value, selector).await,
        "check" => verify_check(page, selector).await,
        "scroll" => ActionVerification {
            verified: true,
            expected: None,
            actual: None,
            message: Some("Scroll always verified".to_string()),
        },
        "solve_captcha" => verify_captcha(page).await,
        _ => ActionVerification {
            verified: true,
            expected: None,
            actual: None,
            message: None,
        },
    }
}

async fn verify_fill(
    page: &Page,
    expected_value: Option<&str>,
    selector: Option<&str>,
) -> ActionVerification {
    let expected = match expected_value {
        Some(v) => v,
        None => {
            return ActionVerification {
                verified: true,
                expected: None,
                actual: None,
                message: Some("No expected value to verify".to_string()),
            };
        }
    };

    // Try to read the current input value
    let actual = if let Some(sel) = selector {
        page_query::locator_input_value(page, sel).await.ok()
    } else {
        // Fall back to active element value
        let js = r#"(() => {
            const el = document.activeElement;
            if (el && (el.tagName === 'INPUT' || el.tagName === 'TEXTAREA')) {
                return el.value || '';
            }
            return '';
        })()"#;
        page_query::evaluate::<String>(page, js).await.ok()
    };

    match actual {
        Some(ref actual_val) if actual_val.contains(expected) => ActionVerification {
            verified: true,
            expected: Some(expected.to_string()),
            actual: Some(actual_val.clone()),
            message: Some("Fill verified".to_string()),
        },
        Some(ref actual_val) => ActionVerification {
            verified: false,
            expected: Some(expected.to_string()),
            actual: Some(actual_val.clone()),
            message: Some(format!(
                "Fill mismatch: expected '{}', got '{}'",
                expected, actual_val
            )),
        },
        // A genuine read failure is NOT evidence the fill succeeded. Report it as
        // unverified (not falsely "verified") so a failed fill isn't recorded as a
        // good step. The caller treats a non-verified fill as "unknown", not a hard
        // failure, so the happy path is unaffected.
        None => ActionVerification {
            verified: false,
            expected: Some(expected.to_string()),
            actual: None,
            message: Some("Could not read value back to verify".to_string()),
        },
    }
}

async fn verify_select(
    page: &Page,
    expected_value: Option<&str>,
    selector: Option<&str>,
) -> ActionVerification {
    let expected = match expected_value {
        Some(v) => v,
        None => {
            return ActionVerification {
                verified: true,
                expected: None,
                actual: None,
                message: Some("No expected value to verify".to_string()),
            };
        }
    };

    // Check the selected option text or value. The selector is passed as a
    // page.evaluate ARGUMENT rather than interpolated into the script source —
    // string interpolation (even with quote-escaping) is brittle and lets a
    // crafted selector break out of the JS string literal.
    let actual = if let Some(sel) = selector {
        let js = r#"(sel) => {
            const el = document.querySelector(sel);
            if (!el) return '';
            if (el.tagName === 'SELECT') {
                const opt = el.options[el.selectedIndex];
                return opt ? (opt.text || opt.value || '') : '';
            }
            // Custom select: check aria-selected
            const selected = el.querySelector('[aria-selected="true"]');
            return selected ? selected.textContent || '' : '';
        }"#;
        page_query::evaluate_with_args::<String>(page, js, serde_json::json!(sel))
            .await
            .ok()
    } else {
        None
    };

    match actual {
        Some(ref actual_val)
            if actual_val.to_lowercase().contains(&expected.to_lowercase())
                || expected.to_lowercase().contains(&actual_val.to_lowercase()) =>
        {
            ActionVerification {
                verified: true,
                expected: Some(expected.to_string()),
                actual: Some(actual_val.clone()),
                message: Some("Select verified".to_string()),
            }
        }
        Some(ref actual_val) => ActionVerification {
            verified: false,
            expected: Some(expected.to_string()),
            actual: Some(actual_val.clone()),
            message: Some(format!(
                "Select mismatch: expected '{}', got '{}'",
                expected, actual_val
            )),
        },
        // Read failure is not proof of success — report unverified rather than
        // falsely "verified" (see verify_fill). Non-verified is treated as
        // "unknown" downstream, so the happy path is unaffected.
        None => ActionVerification {
            verified: false,
            expected: Some(expected.to_string()),
            actual: None,
            message: Some("Could not read selected value to verify".to_string()),
        },
    }
}

async fn verify_check(
    page: &Page,
    selector: Option<&str>,
) -> ActionVerification {
    let is_checked = if let Some(sel) = selector {
        page_query::locator_is_checked(page, sel).await.ok()
    } else {
        None
    };

    match is_checked {
        Some(true) => ActionVerification {
            verified: true,
            expected: None,
            actual: Some("checked".to_string()),
            message: Some("Check verified".to_string()),
        },
        Some(false) => ActionVerification {
            verified: false,
            expected: None,
            actual: Some("unchecked".to_string()),
            message: Some("Check failed: element is not checked".to_string()),
        },
        // Read failure is not proof the box is checked — report unverified rather
        // than falsely "verified" (see verify_fill). Treated as "unknown"
        // downstream, so the happy path is unaffected.
        None => ActionVerification {
            verified: false,
            expected: None,
            actual: None,
            message: Some("Could not read check state to verify".to_string()),
        },
    }
}

async fn verify_captcha(
    page: &Page,
) -> ActionVerification {
    // Check if common captcha elements are still visible
    let js = r#"(() => {
        const selectors = [
            'iframe[src*="recaptcha"]',
            'iframe[src*="hcaptcha"]',
            '.g-recaptcha',
            '.h-captcha',
            '[data-captcha]'
        ];
        for (const sel of selectors) {
            const el = document.querySelector(sel);
            if (el) {
                const r = el.getBoundingClientRect();
                if (r.width > 0 && r.height > 0) return true;
            }
        }
        return false;
    })()"#;

    let still_visible: bool = page_query::evaluate(page, js).await.unwrap_or(false);

    if still_visible {
        ActionVerification {
            verified: false,
            expected: None,
            actual: Some("captcha still visible".to_string()),
            message: Some("Captcha elements still present".to_string()),
        }
    } else {
        ActionVerification {
            verified: true,
            expected: None,
            actual: None,
            message: Some("Captcha appears solved".to_string()),
        }
    }
}

/// Evaluate the form endpoint detection script on the live page.
pub async fn detect_form_endpoint(page: &Page) -> EndpointResult {
    // Run the JS detection script
    let js_result: Result<serde_json::Value, _> =
        page_query::evaluate(page, DETECT_FORM_ENDPOINT_JS).await;

    match js_result {
        Ok(val) => {
            let status = val
                .get("status")
                .and_then(|s| s.as_str())
                .unwrap_or("unknown")
                .to_string();
            let message = val
                .get("message")
                .and_then(|s| s.as_str())
                .map(String::from);
            let selector = val
                .get("selector")
                .and_then(|s| s.as_str())
                .map(String::from);

            let success_indicators = val
                .get("success_indicators")
                .and_then(|a| a.as_array())
                .map(|arr| {
                    arr.iter()
                        .filter_map(|v| v.as_str().map(String::from))
                        .collect()
                })
                .unwrap_or_default();

            let error_indicators = val
                .get("error_indicators")
                .and_then(|a| a.as_array())
                .map(|arr| {
                    arr.iter()
                        .filter_map(|v| v.as_str().map(String::from))
                        .collect()
                })
                .unwrap_or_default();

            EndpointResult {
                status,
                message,
                selector,
                success_indicators,
                error_indicators,
            }
        }
        Err(e) => {
            tracing::debug!(error = %e, "Endpoint detection JS failed");

            // Fallback: scan body text for success/error patterns
            let body_text: String = page_query::evaluate(
                page,
                r#"document.body ? document.body.innerText.substring(0, 2000) : ''"#,
            )
            .await
            .unwrap_or_default();

            let body_lower = body_text.to_lowercase();
            let success_keywords = [
                "thank you", "success", "submitted", "confirmed", "merci", "envoy",
            ];
            let error_keywords = ["error", "failed", "invalid", "erreur"];

            let has_success = success_keywords.iter().any(|kw| body_lower.contains(kw));
            let has_error = error_keywords.iter().any(|kw| body_lower.contains(kw));

            let status = if has_success {
                "success"
            } else if has_error {
                "error"
            } else {
                "unknown"
            };

            EndpointResult {
                status: status.to_string(),
                message: None,
                selector: None,
                success_indicators: Vec::new(),
                error_indicators: Vec::new(),
            }
        }
    }
}
