//! Local 2FA code entry — STAGE E2, the on-device twin of the cloud `saas_bridge::handle_twofa_step`.
//!
//! The cloud handler mints the code SERVER-SIDE (TOTP generated or a mailbox/SMS relay read) and then
//! types it. The desktop daemon splits that: for a TOTP persona the engine mints the code on-device
//! (free, no coordinator — see [`super::persona::mint_current_totp`]) and hands it here to ENTER; for
//! an email/SMS persona there is no local code to read, so the engine never calls this (it finalizes
//! `twofa_required` instead). This module therefore only ever handles entry of an already-minted code.
//!
//! Entry reuses the SAME shared, single-source JS the cloud path uses (`shared/otp_entry.js` +
//! `shared/otp_detect.js`, embedded via [`crate::bridge::otp_entry`]) so a single input / N segmented
//! single-char boxes / contenteditable / paste all work identically across document, modals, and
//! same-origin iframes. The code is a SECRET — it is never logged or returned to any surface.

use crate::local::error::{LocalError, LocalResult};

/// Whether the live page is currently SHOWING a 2FA challenge — the engine's `twofa` arm uses
/// this to be challenge-aware when there is no OTP source (persona method `none`) or a warm
/// persona session may have skipped the challenge. Thin re-export of the shared, ungated helper
/// so the cloud bridge's arm behaves identically.
pub async fn challenge_present(page: &playwright_rs::Page) -> bool {
    crate::bridge::otp_entry::challenge_present(page).await
}

/// Whether the step's RECORDED OTP-field selector (top-level or under `config`) resolves on the
/// live page. Complements [`challenge_present`] for custom widgets the shared detector doesn't
/// recognize: if the site shows the recorded field, entry should proceed even when detection
/// says "no challenge". No selector recorded → `false`.
pub async fn recorded_selector_present(page: &playwright_rs::Page, raw_step: &serde_json::Value) -> bool {
    let selector = raw_step
        .get("selector")
        .and_then(|v| v.as_str())
        .or_else(|| raw_step.get("config").and_then(|c| c.get("selector")).and_then(|v| v.as_str()))
        .filter(|s| !s.is_empty());
    let Some(selector) = selector else { return false };
    // JSON-encode the selector so quotes/backslashes can't break out of the literal.
    let js = format!(
        "(() => {{ try {{ return !!document.querySelector({}); }} catch (e) {{ return false; }} }})()",
        serde_json::Value::String(selector.to_string())
    );
    crate::browser::page_query::evaluate::<bool>(page, &js)
        .await
        .unwrap_or(false)
}

/// Enter an already-minted 2FA `code` into the live page and submit.
///
/// 1. Use the recorded `selector` (a manual-recording `twofa` step carries one); else auto-detect the
///    OTP field via the shared detector (handles inline step-2 / modal / redirected challenges).
/// 2. Enter via the robust shared entry JS; on failure fall back to a plain `fill`, then keyboard typing.
/// 3. Click the recorded/detected submit control if present (some flows auto-submit on the last digit).
///
/// `code` is SECRET — never logged. Returns `Err` only when no field could be filled at all.
pub async fn enter_code(
    page: &playwright_rs::Page,
    raw_step: &serde_json::Value,
    code: &str,
) -> LocalResult<()> {
    use crate::bridge::otp_entry;

    // A recorded selector wins; the step may carry it top-level or under `config` (recorder JSON).
    let mut selector = raw_step
        .get("selector")
        .and_then(|v| v.as_str())
        .or_else(|| raw_step.get("config").and_then(|c| c.get("selector")).and_then(|v| v.as_str()))
        .map(|s| s.to_string())
        .filter(|s| !s.is_empty());

    // No recorded selector — detect the OTP field (and a likely submit button) on the live page.
    let mut detected_submit: Option<String> = None;
    if selector.is_none() {
        if let Ok(det) = crate::browser::page_query::evaluate::<serde_json::Value>(
            page,
            &otp_entry::detect_invocation(),
        )
        .await
        {
            selector = det
                .get("selector")
                .and_then(|v| v.as_str())
                .filter(|s| !s.is_empty())
                .map(|s| s.to_string());
            detected_submit = det.get("submit_selector").and_then(|v| v.as_str()).map(|s| s.to_string());
        }
    }

    // Robust entry first (single / segmented / contenteditable / paste). Never log `code`.
    let entry_js = otp_entry::entry_invocation(code, selector.as_deref());
    let entered = match crate::browser::page_query::evaluate::<serde_json::Value>(page, &entry_js).await {
        Ok(res) => res.get("ok").and_then(|v| v.as_bool()).unwrap_or(false),
        Err(e) => {
            tracing::debug!(error = %e, "twofa entry JS failed");
            false
        }
    };

    // Degraded fallbacks: a plain fill, then click + keyboard typing.
    if !entered {
        let fallback = "input[type='text'], input[type='tel'], input[type='number'], input:not([type])";
        let sel = selector.as_deref().unwrap_or(fallback);
        if let Err(e) = crate::browser::page_actions::fill(page, sel, code).await {
            tracing::debug!(error = %e, "twofa fill failed, trying keyboard_type");
            let _ = crate::browser::page_actions::click_selector(page, sel, false).await;
            crate::browser::page_actions::keyboard_type(page, code, 60.0)
                .await
                .map_err(|e| LocalError::Internal(format!("twofa entry failed: {e}")))?;
        }
    }

    // Submit if we have a control (recorded wins, else detected). A missing submit is fine — many
    // segmented widgets auto-submit when the final digit lands.
    let submit = raw_step
        .get("submit_selector")
        .and_then(|v| v.as_str())
        .or_else(|| raw_step.get("config").and_then(|c| c.get("submit_selector")).and_then(|v| v.as_str()))
        .map(|s| s.to_string())
        .or(detected_submit);
    if let Some(submit) = submit {
        let _ = crate::browser::page_actions::click_selector(page, &submit, false).await;
    }

    tracing::info!("twofa step: entered on-device TOTP code");
    Ok(())
}
