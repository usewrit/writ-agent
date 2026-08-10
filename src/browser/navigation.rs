use std::time::Duration;

use anyhow::Result;
use playwright_rs::{Page, GotoOptions, WaitUntil};
use serde_json::Value;

use super::page_query;
use crate::util::logging::redact_url_for_log;

/// Re-inject the stealth payload after a navigation.
///
/// A navigation discards the page's JS context, so the stealth properties
/// (navigator.webdriver, etc.) must be re-applied on the fresh document. We do
/// this MANUALLY via evaluate rather than context.add_init_script — matching the
/// Python reference, which avoids add_init_script because it's an anti-bot CDP
/// signature and breaks DNS on some server Chromium builds. stealth.js is
/// idempotent (`__stealth_injected`), so this is cheap and safe to call on every
/// navigation. Errors (e.g. a destroyed context) are intentionally ignored.
pub async fn reinject_stealth(page: &Page) {
    // The DEVICE overrides are per-context (they must agree with THAT context's UA), so
    // resolve them from the page's own context rather than injecting a shared constant.
    // A page whose context has no pinned device (a real headed machine) gets the generic
    // payload only and keeps its real hardware values.
    use playwright_rs::server::channel_owner::ChannelOwner as _;
    let script = match page.context() {
        Ok(ctx) => crate::browser::stealth::scripts_for_context(ctx.guid()),
        Err(_) => crate::browser::stealth::STEALTH_SCRIPTS.to_string(),
    };
    let _: Result<serde_json::Value, _> = page.evaluate(&script, None::<&()>).await;
}

pub async fn goto(page: &Page, url: &str, wait_until: &str, timeout: Duration) -> Result<()> {
    // `url` here is the FULLY RESOLVED navigation target: `value_resolver` has already substituted
    // `{{vault:…}}` with the live secret and `step_navigate` has already swapped in the live session
    // token. Only host+path may ever be logged or embedded in an error (see the goto error below).
    tracing::debug!(url = %redact_url_for_log(url), wait_until, ?timeout, "goto");

    let wu = match wait_until {
        "networkidle" => WaitUntil::NetworkIdle,
        "load" => WaitUntil::Load,
        "commit" => WaitUntil::Commit,
        _ => WaitUntil::DomContentLoaded,
    };

    let opts = GotoOptions {
        wait_until: Some(wu),
        timeout: Some(timeout),
    };

    // Build the error from a REDACTED url. This message is the single widest-fanout string in the
    // engine: `step_navigate` wraps it in `StepError::NavigationFailed`, which is (a) logged at ERROR
    // by the run engine, (b) persisted as the run row's `error` column and served by `GET /v1/runs`,
    // (c) sent to the cloud as `task_result.error`, (d) placed into an AI REPAIR PROMPT, and (e)
    // logged again by the cloud automation engine. A step navigating to
    // `https://api.vendor.com/export?api_token={{vault:vendor_key}}` that merely TIMES OUT would
    // otherwise put the live vendor key in all five places.
    page.goto(url, Some(opts)).await
        .map_err(|e| anyhow::anyhow!("Navigation to {} failed: {}", redact_url_for_log(url), e))?;

    reinject_stealth(page).await;
    Ok(())
}

pub async fn wait_for_load_state(page: &Page, state: &str, timeout: Duration) -> Result<()> {
    tracing::debug!(state, ?timeout, "wait_for_load_state");

    let wu = match state {
        "networkidle" => Some(WaitUntil::NetworkIdle),
        "load" => Some(WaitUntil::Load),
        "domcontentloaded" => Some(WaitUntil::DomContentLoaded),
        "commit" => Some(WaitUntil::Commit),
        _ => Some(WaitUntil::Load),
    };

    // Honor the caller's timeout: the vendored wait has its own long internal cap, which silently
    // turned "2s guard" callers into 30s stalls.
    match tokio::time::timeout(timeout, page.wait_for_load_state(wu)).await {
        Ok(r) => r.map_err(|e| anyhow::anyhow!("wait_for_load_state({}) failed: {}", state, e)),
        Err(_) => Err(anyhow::anyhow!("wait_for_load_state({}) timed out after {:?}", state, timeout)),
    }
}

/// Wait until the page is genuinely QUIET before the next step reads it: `document.readyState`
/// == "complete", NO in-flight fetch/XHR, and no new network resources / DOM growth across two
/// consecutive samples.
///
/// This is a REAL networkidle. The vendored `WaitUntil::NetworkIdle` is readyState-only, and even a
/// resource-count poll misses the crucial case: `performance.getEntriesByType('resource')` only lists
/// a request once it COMPLETES, so a page that has rendered its skeleton while its data XHR is still
/// IN FLIGHT looks "quiet" — the extract then scrapes the empty shell and replay yields `[]` (the exact
/// "workflows list empty, targets fine" bug). So we install a tiny idempotent in-flight counter around
/// `fetch`/`XMLHttpRequest` and refuse to call the page quiet while any request is outstanding.
///
/// Best-effort and capped at `max` — a page that never goes quiet (long-polling, websockets) returns
/// after the cap rather than hanging the run.
pub async fn wait_for_page_quiet(page: &Page, max: Duration) {
    // Installs the counter on first run (idempotent via `window.__wq`) and reports the current signals.
    // The wrapper only ever DECREMENTS what it incremented, and is wrapped in try/catch, so it can
    // never wedge the page. Requests already in flight before install aren't counted — but their
    // render still trips the DOM/resource-stability check, so the wait is correct either way.
    let js = "(() => { try {\
        if (!window.__wq) {\
          var w = { n: 0 }; window.__wq = w;\
          var of = window.fetch;\
          if (typeof of === 'function') { window.fetch = function(){ w.n++; var done=function(){ w.n = Math.max(0, w.n-1); }; try { return of.apply(this, arguments).then(function(r){done(); return r;}, function(e){done(); throw e;}); } catch(e) { done(); throw e; } }; }\
          var XO = window.XMLHttpRequest;\
          if (XO && XO.prototype && XO.prototype.send) { var os = XO.prototype.send; XO.prototype.send = function(){ w.n++; this.addEventListener('loadend', function(){ w.n = Math.max(0, w.n-1); }); return os.apply(this, arguments); }; }\
        }\
        return { n: performance.getEntriesByType('resource').length, r: document.readyState, d: document.getElementsByTagName('*').length, f: window.__wq.n };\
      } catch (e) { return { n: 0, r: document.readyState, d: 0, f: 0 }; } })()";
    let deadline = tokio::time::Instant::now() + max;
    let mut last: Option<(u64, u64)> = None; // (resource count, dom size)
    let mut stable = 0u32;
    while tokio::time::Instant::now() < deadline {
        let cur = page_query::evaluate::<Value>(page, js).await.ok();
        let quiet = cur.as_ref().map(|v| {
            let n = v.get("n").and_then(Value::as_u64).unwrap_or(0);
            let r = v.get("r").and_then(|x| x.as_str()).unwrap_or("");
            let d = v.get("d").and_then(Value::as_u64).unwrap_or(0);
            let f = v.get("f").and_then(Value::as_u64).unwrap_or(0);
            (n, d, r == "complete", f == 0)
        });
        match (&last, &quiet) {
            // Loaded, nothing in flight, and neither resources nor DOM changed since last sample.
            (Some((ln, ld)), Some((n, d, complete, idle)))
                if *complete && *idle && ln == n && ld == d =>
            {
                stable += 1;
                if stable >= 2 {
                    return;
                }
            }
            _ => stable = 0,
        }
        if let Some((n, d, _, _)) = quiet {
            last = Some((n, d));
        }
        tokio::time::sleep(Duration::from_millis(400)).await;
    }
}

pub async fn wait_for_url(page: &Page, url_pattern: &str, timeout: Duration) -> Result<()> {
    tracing::debug!(url_pattern = %redact_url_for_log(url_pattern), ?timeout, "wait_for_url");

    let opts = GotoOptions {
        timeout: Some(timeout),
        wait_until: None,
    };

    page.wait_for_url(url_pattern, Some(opts)).await
        .map_err(|e| anyhow::anyhow!("wait_for_url({}) failed: {}", redact_url_for_log(url_pattern), e))
}

pub async fn reload(page: &Page, timeout: Duration) -> Result<()> {
    tracing::debug!(?timeout, "reload");

    let opts = GotoOptions {
        timeout: Some(timeout),
        wait_until: None,
    };

    page.reload(Some(opts)).await
        .map_err(|e| anyhow::anyhow!("Reload failed: {}", e))?;
    reinject_stealth(page).await;
    Ok(())
}

/// Go back one history entry.
///
/// Returns `Ok(false)` when there was nothing to go back TO. Playwright resolves
/// `goBack` with a null response in that case, which used to be reported as plain
/// success — so the recorder's Back button did nothing and said nothing, which
/// reads as a broken button. Callers surface the distinction.
pub async fn go_back(page: &Page, timeout: Duration) -> Result<bool> {
    let opts = GotoOptions {
        timeout: Some(timeout),
        wait_until: None,
    };
    let moved = page.go_back(Some(opts)).await
        .map_err(|e| anyhow::anyhow!("Go back failed: {}", e))?
        .is_some();
    if moved {
        reinject_stealth(page).await;
    }
    Ok(moved)
}

/// Go forward one history entry. `Ok(false)` = no forward entry (see [`go_back`]).
pub async fn go_forward(page: &Page, timeout: Duration) -> Result<bool> {
    let opts = GotoOptions {
        timeout: Some(timeout),
        wait_until: None,
    };
    let moved = page.go_forward(Some(opts)).await
        .map_err(|e| anyhow::anyhow!("Go forward failed: {}", e))?
        .is_some();
    if moved {
        reinject_stealth(page).await;
    }
    Ok(moved)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Regression guard for the widest-fanout secret leak in the engine: the `goto` failure message.
    /// It reaches the daemon log, the run row's `error` column, `GET /v1/runs`, the cloud
    /// `task_result` frame AND an AI-repair prompt — so it must never contain the resolved query.
    #[test]
    fn goto_error_message_never_carries_the_resolved_query() {
        let url = "https://api.vendor.com/export?api_token=LIVEvendorKEY99&format=csv#anchor";
        // Same construction as the `map_err` in `goto`.
        let msg = format!("Navigation to {} failed: {}", redact_url_for_log(url), "Timeout 30000ms");
        assert!(!msg.contains("LIVEvendorKEY99"), "vendor key must not appear: {msg}");
        assert!(!msg.contains("anchor"), "fragment must not appear: {msg}");
        assert!(msg.starts_with("Navigation to https://api.vendor.com/export failed:"), "{msg}");

        // A userinfo-bearing target is scrubbed too (`https://user:pass@host/...`).
        let creds = "https://bob:s3cr3tPASS@intranet.example.com/report";
        let msg = format!("Navigation to {} failed: {}", redact_url_for_log(creds), "ERR");
        assert!(!msg.contains("s3cr3tPASS"), "{msg}");
        assert!(msg.contains("intranet.example.com/report"), "{msg}");
    }
}
