//! Shared OTP entry/detection JS, embedded at compile time.
//!
//! The OTP entry (`otp_entry.js`) and detection (`otp_detect.js`) helpers are vendored in-crate
//! under `src/bridge/js/` so the crate builds standalone with no out-of-crate `include_str!`. Keep
//! them in sync with their source so 2FA-code entry and challenge detection behave consistently.
//!
//! Each file evaluates to a FUNCTION expression; the helpers below wrap it into an
//! immediately-invoked expression suitable for `page_query::evaluate`.

/// `otp_entry.js` — `(code, selectorHint) => {ok, kind, filled}`.
pub const OTP_ENTRY_JS: &str = include_str!("js/otp_entry.js");

/// `otp_detect.js` — `() => {is_twofa, selector, submit_selector}`.
pub const OTP_DETECT_JS: &str = include_str!("js/otp_detect.js");

/// Build an evaluatable IIFE that enters `code` into the OTP field (optionally
/// hinted by `selector`). The code is embedded into the local page.evaluate only.
pub fn entry_invocation(code: &str, selector: Option<&str>) -> String {
    let code_json = serde_json::to_string(code).unwrap_or_else(|_| "\"\"".to_string());
    let sel_json = match selector {
        Some(s) if !s.is_empty() => {
            serde_json::to_string(s).unwrap_or_else(|_| "null".to_string())
        }
        _ => "null".to_string(),
    };
    format!("(({})({}, {}))", OTP_ENTRY_JS, code_json, sel_json)
}

/// Build an evaluatable IIFE that runs the deterministic 2FA-challenge detector.
pub fn detect_invocation() -> String {
    format!("(({})())", OTP_DETECT_JS)
}

/// Deterministically check whether the live page is currently SHOWING a 2FA challenge, via the
/// shared detector (inline step-2 / modal / redirected; document + dialogs + same-origin iframes).
///
/// Shared by the local engine and the cloud bridge so both `twofa` arms are challenge-aware when
/// there is no OTP source: a warm persona session may have skipped the challenge (the step is a
/// legitimate skip), while a visible challenge with nothing to answer it must fail actionably.
/// Detection errors read as "absent" so a transient evaluate failure can't fail a run that would
/// have succeeded.
pub async fn challenge_present(page: &playwright_rs::Page) -> bool {
    match crate::browser::page_query::evaluate::<serde_json::Value>(page, &detect_invocation()).await {
        Ok(det) => {
            det.get("is_twofa").and_then(|v| v.as_bool()).unwrap_or(false)
                && det
                    .get("selector")
                    .and_then(|v| v.as_str())
                    .map(|s| !s.is_empty())
                    .unwrap_or(false)
        }
        Err(_) => false,
    }
}
