use std::collections::HashMap;
use std::time::Duration;

use playwright_rs::Page;
use url::Url;

use crate::browser::{captcha, navigation, stealth};
use crate::models::workflow::WorkflowStepConfig;
use crate::security::url_guard;
use crate::util::logging::redact_url_for_log;
use crate::util::value_resolver;
use super::step_executor::{StepError, StepResult};

/// Session token parameter names to carry forward from current URL to target URL.
/// Exact match with Python automation_engine.py navigate step.
const SESSION_TOKEN_PARAMS: &[&str] = &[
    "sid", "session_id", "token", "auth", "ssid", "sessionid",
    "PHPSESSID", "jsessionid", "csrf", "csrftoken",
];

/// Carry forward session tokens from current browser URL to the target URL.
/// Exact port of Python automation_engine.py navigate step token carry-forward.
///
/// Returns `(rewritten_url, carried_param_names)`. The NAMES are returned — never the values — so the
/// caller can say *what* it swapped without logging a live session id / CSRF token. This function
/// only ever fires when a session-token value CHANGED, which means by construction the old value is
/// the stale token and the new one is the LIVE one; there is no safe way to log either.
fn carry_forward_session_tokens(current_url: &str, target_url: &str) -> (String, Vec<String>) {
    let unchanged = || (target_url.to_string(), Vec::new());
    let current_parsed = match Url::parse(current_url) {
        Ok(u) => u,
        Err(_) => return unchanged(),
    };
    let mut target_parsed = match Url::parse(target_url) {
        Ok(u) => u,
        Err(_) => return unchanged(),
    };

    // Only carry tokens if same domain
    if current_parsed.host_str() != target_parsed.host_str() {
        return unchanged();
    }

    // Collect session tokens from current URL query params
    let current_tokens: HashMap<String, String> = current_parsed
        .query_pairs()
        .filter(|(key, _)| {
            SESSION_TOKEN_PARAMS.iter().any(|p| {
                key.eq_ignore_ascii_case(p)
            })
        })
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect();

    if current_tokens.is_empty() {
        return unchanged();
    }

    // Replace matching params in target URL with live values
    let mut target_params: Vec<(String, String)> = target_parsed
        .query_pairs()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect();

    let mut carried: Vec<String> = Vec::new();
    for (key, value) in &current_tokens {
        let key_lower = key.to_lowercase();
        if let Some(existing) = target_params.iter_mut().find(|(k, _)| k.to_lowercase() == key_lower) {
            if existing.1 != *value {
                // NAME + lengths only. `existing.1` is the stale token and `value` is the LIVE one;
                // both are bearer-equivalent session material, and neither has a `w*_` prefix or a
                // `?param=` wrapper, so the sink-level scrubber could not mask them either.
                tracing::debug!(
                    param = key.as_str(),
                    old_len = existing.1.len(),
                    new_len = value.len(),
                    "Carrying forward session token"
                );
                existing.1 = value.clone();
                carried.push(key.clone());
            }
        }
    }

    if carried.is_empty() {
        return (target_url.to_string(), carried);
    }

    // Rebuild query string
    target_parsed.query_pairs_mut().clear();
    for (k, v) in &target_params {
        target_parsed.query_pairs_mut().append_pair(k, v);
    }
    (target_parsed.to_string(), carried)
}

pub async fn execute(
    page: &Page,
    config: &WorkflowStepConfig,
    credentials: &HashMap<String, String>,
    form_data: &HashMap<String, String>,
) -> StepResult {
    let raw_url = config.url.as_deref().unwrap_or("about:blank");
    let resolved_url = value_resolver::resolve_value(raw_url, credentials, Some(form_data));

    // Session token carry-forward: replace stale tokens with live values
    let current_url = page.url();
    let (final_url, carried_params) = carry_forward_session_tokens(&current_url, &resolved_url);

    if !carried_params.is_empty() {
        // PARAM NAMES ONLY, at DEBUG. This used to log both URLs at INFO — which is on by default in
        // `writ-agentd` — and it fires precisely when a session-token param changed, so `original`
        // held the stale token and `updated` held the LIVE one. Worse, `resolved_url` is
        // post-`value_resolver`, so any `{{vault:…}}` in the step URL is already a real secret here.
        // Those lines went to ~/.writ/logs/agentd.out.log, journald AND the support diagnostics tar.
        tracing::debug!(params = ?carried_params, "Session tokens carried forward");
    }

    // SSRF guard — fail-CLOSED for a navigation target (an unresolvable/rebinding host is treated as
    // unsafe). Async so DNS resolution never blocks the runtime thread.
    if !url_guard::is_navigation_url_safe_async(&final_url).await {
        // Host/path only: this error string is logged at ERROR, persisted as the run row's `error`,
        // served by `GET /v1/runs`, shipped to the cloud in the `task_result` frame AND placed into
        // an AI-repair prompt. `final_url` carries the resolved query (api keys, session tokens).
        return Err(StepError::NavigationFailed(format!(
            "URL blocked by SSRF guard: {}", redact_url_for_log(&final_url)
        )));
    }

    // Check for hash-only SPA navigation (same base URL, different hash)
    let is_hash_nav = {
        let current = Url::parse(&current_url).ok();
        let target = Url::parse(&final_url).ok();
        match (current, target) {
            (Some(c), Some(t)) => {
                c.scheme() == t.scheme()
                    && c.host() == t.host()
                    && c.port() == t.port()
                    && c.path() == t.path()
                    && c.query() == t.query()
                    && c.fragment() != t.fragment()
                    && t.fragment().is_some()
            }
            _ => false,
        }
    };

    if is_hash_nav {
        // SPA hash navigation: set location.hash directly
        if let Ok(target) = Url::parse(&final_url) {
            if let Some(fragment) = target.fragment() {
                tracing::debug!(hash = fragment, "SPA hash navigation");
                let js = format!("window.location.hash = {}", serde_json::to_string(fragment).unwrap_or_default());
                let _: Result<serde_json::Value, _> = page.evaluate(&js, None::<&()>).await;
                // Wait for the SPA router to render the new route AND settle (the hashchange fires an
                // XHR-driven view swap). A fixed sleep raced the fetch; poll real quiescence instead —
                // matches the Python agent settling after a hash navigation.
                navigation::wait_for_page_quiet(page, Duration::from_secs(10)).await;
                return Ok(None);
            }
        }
    }

    tracing::debug!(url = %redact_url_for_log(&final_url), "Navigating");

    navigation::goto(page, &final_url, "domcontentloaded", Duration::from_millis(30_000))
        .await
        .map_err(|e| StepError::NavigationFailed(format!("goto failed: {}", e)))?;

    // Settle the page for real BEFORE the next step reads it. The vendored `networkidle` is
    // readyState-only (fake) — for an SPA it returns before the XHR-rendered content exists, so a
    // navigate→extract workflow scraped an empty shell at replay. `wait_for_page_quiet` polls actual
    // quiescence (readyState complete + stable resources/DOM), the SAME wait the recorder used when it
    // captured real data. This is the core "execute steps one-by-one like the Python agent" fix.
    navigation::wait_for_page_quiet(page, Duration::from_secs(15)).await;

    // Re-inject stealth scripts after navigation
    let _: Result<serde_json::Value, _> = page.evaluate(stealth::STEALTH_SCRIPTS, None::<&()>).await;

    // Check for CAPTCHA
    let has_captcha: bool = page.evaluate(captcha::detect_captcha_js(), None::<&()>).await
        .unwrap_or(false);
    if has_captcha {
        tracing::warn!(url = %redact_url_for_log(&final_url), "CAPTCHA detected after navigation");
        let mut result = HashMap::new();
        result.insert("captcha_detected".to_string(), serde_json::json!(true));
        return Ok(Some(result));
    }

    Ok(None)
}

pub async fn execute_navigated_to(page: &Page, config: &WorkflowStepConfig) -> StepResult {
    let expected_url = config.url.as_deref().unwrap_or("");

    tracing::debug!(expected = expected_url, "Waiting for URL stabilization");

    let timeout = Duration::from_secs(15);
    let poll_interval = Duration::from_millis(500);
    let start = std::time::Instant::now();
    let mut last_url = String::new();
    let mut stable_count = 0u32;

    while start.elapsed() < timeout {
        let current_url = page.url();

        if !expected_url.is_empty() && current_url.contains(expected_url) {
            // `page.url()` is the LIVE browser URL — its query is exactly where the session tokens
            // this module carries forward live. Host/path only.
            tracing::debug!(url = %redact_url_for_log(&current_url), "URL matches expected pattern");
            break;
        }

        if current_url == last_url {
            stable_count += 1;
            if stable_count >= 3 {
                tracing::debug!(url = %redact_url_for_log(&current_url), "URL stabilized");
                break;
            }
        } else {
            stable_count = 0;
            last_url = current_url;
        }

        tokio::time::sleep(poll_interval).await;
    }

    let has_captcha: bool = page.evaluate(captcha::detect_captcha_js(), None::<&()>).await
        .unwrap_or(false);
    if has_captcha {
        tracing::warn!("CAPTCHA detected on landing page");
        let mut result = HashMap::new();
        result.insert("captcha_detected".to_string(), serde_json::json!(true));
        return Ok(Some(result));
    }

    Ok(None)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_carry_forward_same_domain() {
        let current = "https://example.com/page?sid=abc123&other=val";
        let target = "https://example.com/next?sid=old_token&foo=bar";
        let (result, carried) = carry_forward_session_tokens(current, target);
        assert!(result.contains("sid=abc123"));
        assert!(result.contains("foo=bar"));
        assert_eq!(carried, vec!["sid".to_string()]);
    }

    #[test]
    fn test_carry_forward_different_domain() {
        let current = "https://example.com/page?sid=abc123";
        let target = "https://other.com/page?sid=old_token";
        let (result, carried) = carry_forward_session_tokens(current, target);
        // Different domain — no carry-forward
        assert!(result.contains("sid=old_token"));
        assert!(carried.is_empty());
    }

    #[test]
    fn test_carry_forward_no_tokens() {
        let current = "https://example.com/page?foo=bar";
        let target = "https://example.com/next?baz=qux";
        let (result, carried) = carry_forward_session_tokens(current, target);
        assert_eq!(result, target);
        assert!(carried.is_empty());
    }

    /// The carry-forward reports NAMES, never values. Both the stale and the live session token are
    /// bearer-equivalent, and neither has a shape the sink redactor can mask, so the only safe report
    /// is the param name — which is what the `Session tokens carried forward` line now logs.
    #[test]
    fn carry_forward_reports_names_not_values() {
        let current = "https://example.com/p?sid=LIVEsession99&csrftoken=LIVEcsrf42";
        let target = "https://example.com/next?sid=STALEsession&csrftoken=STALEcsrf&page=2";
        let (_url, carried) = carry_forward_session_tokens(current, target);

        assert_eq!(carried.len(), 2, "both session params carried: {carried:?}");
        let rendered = format!("{carried:?}");
        for leak in ["LIVEsession99", "LIVEcsrf42", "STALEsession", "STALEcsrf"] {
            assert!(!rendered.contains(leak), "no token VALUE in the logged names: {rendered}");
        }
        assert!(rendered.contains("sid") && rendered.contains("csrftoken"), "{rendered}");
    }

    /// Every name this step carries forward must also be covered by the sink-level query scrubber, so
    /// a future accidental `%final_url` is masked on the way out. (`sid`, `session_id`, `ssid`,
    /// `sessionid`, `PHPSESSID`, `jsessionid`, `csrf`, `csrftoken` and bare `auth` were all missing.)
    #[test]
    fn every_session_param_is_covered_by_the_sink_redactor() {
        for name in SESSION_TOKEN_PARAMS {
            let line = format!("navigating https://app.example.com/x?{name}=LIVEvalue123");
            let out = crate::util::logging::redact_line(&line);
            assert!(
                !out.contains("LIVEvalue123"),
                "QUERY_SECRET_RE must cover `{name}`: {out}"
            );
        }
    }

    /// The SSRF-guard error string is the worst place for a resolved URL: it reaches the daemon log,
    /// the run row, the local API, the cloud `task_result` frame and an AI-repair prompt. Only
    /// host+path may appear.
    #[test]
    fn ssrf_error_reports_host_and_path_only() {
        let resolved = "https://api.vendor.com/export?api_token=LIVEvendorKEY99&format=csv";
        let msg = format!("URL blocked by SSRF guard: {}", redact_url_for_log(resolved));
        assert!(!msg.contains("LIVEvendorKEY99"), "{msg}");
        assert_eq!(msg, "URL blocked by SSRF guard: https://api.vendor.com/export");
    }
}
