use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use crate::browser::{navigation, page_query};
use crate::models::session::SessionState;
use crate::security::url_guard;

/// Request headers captured as auth-relevant (Bearer / X-Auth / API keys) so token-based auth is
/// persisted alongside cookies. A shared handle both the request listener and `extract_session_state`
/// read.
pub type CapturedHeaders = Arc<Mutex<HashMap<String, String>>>;

/// Attach a request listener to `context` that records auth-relevant request headers into a shared
/// map, and return that map. Lifted from the saas bridge so the local engine can harvest token auth
/// too (hybrid: a browser sign-in whose session later replays over the HTTP lane). Best-effort — a
/// failed attach just yields an empty map.
pub async fn attach_auth_header_capture(context: &playwright_rs::BrowserContext) -> CapturedHeaders {
    const AUTH_HEADER_PATTERNS: &[&str] = &[
        "authorization", "x-auth", "x-api-key", "x-session", "x-token",
        "x-csrf", "x-xsrf", "bearer", "api-key", "access-token",
    ];
    let captured: CapturedHeaders = Arc::new(Mutex::new(HashMap::new()));
    let cap = captured.clone();
    let _ = context
        .on_request(move |request: playwright_rs::Request| {
            let cap = cap.clone();
            async move {
                let headers = request.headers();
                if let Ok(mut map) = cap.lock() {
                    for (k, v) in headers {
                        let kl = k.to_lowercase();
                        if AUTH_HEADER_PATTERNS.iter().any(|p| kl.contains(p)) {
                            map.insert(k, v);
                        }
                    }
                }
                Ok(())
            }
        })
        .await;
    captured
}

/// 1:1 port of Python session state injection (automation_engine.py lines 2920-2949).
///
/// Injects saved cookies, localStorage, and sessionStorage into the browser context.
/// After injection, navigates to entry_url and reloads so the session takes effect.
pub async fn inject_session_state(
    page: &playwright_rs::Page,
    context: &playwright_rs::BrowserContext,
    session_state: &SessionState,
    entry_url: Option<&str>,
    timeout_ms: u64,
) -> Result<(), anyhow::Error> {
    let timeout = Duration::from_millis(timeout_ms);

    // 1. Add cookies to context (Python line 2922-2925)
    //
    // SECURITY / TRUST ASSUMPTION: the cookies here come from a saved auth session
    // supplied by the backend/workflow config. We trust the backend to only hand
    // back cookies that were extracted from this same workflow's own session, so
    // they should belong to the target site. As defense-in-depth against a
    // session-fixation-flavored injection (a tampered config slipping in cookies
    // for an unrelated domain), we restrict injected cookie domains to the
    // entry_url's host and its subdomains when an entry_url is known. Cookies
    // without a domain (host-only) are kept as-is.
    let allowed_domain = entry_url
        .filter(|u| !u.is_empty())
        .and_then(|u| url::Url::parse(u).ok())
        .and_then(|u| u.host_str().map(|h| h.to_lowercase()));
    let domain_allowed = |cookie_domain: &str| -> bool {
        let cd = cookie_domain.trim_start_matches('.').to_lowercase();
        match &allowed_domain {
            // No entry_url to anchor against → keep prior behavior (allow).
            None => true,
            Some(host) => cd.is_empty() || cd == *host || host.ends_with(&format!(".{}", cd)),
        }
    };

    if !session_state.cookies.is_empty() {
        let cookies: Vec<playwright_rs::Cookie> = session_state
            .cookies
            .iter()
            .filter_map(|c| {
                let name = c.get("name")?.as_str()?.to_string();
                let value = c.get("value")?.as_str()?.to_string();
                let domain = c.get("domain").and_then(|v| v.as_str()).unwrap_or("").to_string();
                if !domain_allowed(&domain) {
                    tracing::warn!(
                        cookie = %name,
                        domain = %domain,
                        "Skipping injected cookie for non-matching domain"
                    );
                    return None;
                }
                let path = c.get("path").and_then(|v| v.as_str()).unwrap_or("/").to_string();
                Some(playwright_rs::Cookie {
                    name,
                    value,
                    domain,
                    path,
                    expires: c.get("expires").and_then(|v| v.as_f64()).unwrap_or(-1.0),
                    http_only: c.get("httpOnly").and_then(|v| v.as_bool()).unwrap_or(false),
                    secure: c.get("secure").and_then(|v| v.as_bool()).unwrap_or(false),
                    same_site: c.get("sameSite").and_then(|v| v.as_str()).map(|s| s.to_string()),
                })
            })
            .collect();

        if !cookies.is_empty() {
            context.add_cookies(&cookies).await
                .map_err(|e| anyhow::anyhow!("Failed to add cookies: {}", e))?;
            tracing::info!(count = cookies.len(), "Injected cookies from saved session");
        }
    }

    // 2. Navigate to entry URL (Python line 2927-2928)
    if let Some(url) = entry_url {
        if !url.is_empty() && url_guard::is_url_safe(url) {
            navigation::goto(page, url, "domcontentloaded", timeout).await
                .map_err(|e| anyhow::anyhow!("Failed to navigate to entry URL: {}", e))?;
        }
    }

    // 3. Inject localStorage items (Python line 2930-2937)
    if !session_state.local_storage.is_empty() {
        for (key, value) in &session_state.local_storage {
            let args = serde_json::json!([key, value]);
            let _: Result<serde_json::Value, _> = page.evaluate(
                "(args) => localStorage.setItem(args[0], args[1])",
                Some(&args),
            ).await;
        }
        tracing::info!(count = session_state.local_storage.len(), "Injected localStorage items");
    }

    // 4. Inject sessionStorage items (Python line 2939-2946)
    if !session_state.session_storage.is_empty() {
        for (key, value) in &session_state.session_storage {
            let args = serde_json::json!([key, value]);
            let _: Result<serde_json::Value, _> = page.evaluate(
                "(args) => sessionStorage.setItem(args[0], args[1])",
                Some(&args),
            ).await;
        }
        tracing::info!(count = session_state.session_storage.len(), "Injected sessionStorage items");
    }

    // 5. Reload page so session takes effect (Python line 2948)
    navigation::reload(page, timeout).await
        .map_err(|e| anyhow::anyhow!("Failed to reload after session injection: {}", e))?;

    Ok(())
}

/// 1:1 port of Python session extraction (automation_engine.py lines 3205-3240).
///
/// Extracts cookies from context, localStorage and sessionStorage from page.
pub async fn extract_session_state(
    page: &playwright_rs::Page,
    context: &playwright_rs::BrowserContext,
    captured_headers: &HashMap<String, String>,
) -> SessionState {
    // 1. Extract cookies from context (Python line 3208)
    let cookies: Vec<serde_json::Value> = match context.cookies(None).await {
        Ok(cookie_list) => cookie_list
            .into_iter()
            .map(|c| {
                serde_json::json!({
                    "name": c.name,
                    "value": c.value,
                    "domain": c.domain,
                    "path": c.path,
                    "expires": c.expires,
                    "httpOnly": c.http_only,
                    "secure": c.secure,
                    "sameSite": c.same_site,
                })
            })
            .collect(),
        Err(e) => {
            tracing::warn!(error = %e, "Could not extract cookies");
            Vec::new()
        }
    };

    // 2. Extract localStorage (Python line 3227)
    let local_storage: HashMap<String, String> = page_query::evaluate(
        page,
        "() => Object.assign({}, localStorage)",
    )
    .await
    .unwrap_or_default();

    // 3. Extract sessionStorage (Python line 3234)
    let session_storage: HashMap<String, String> = page_query::evaluate(
        page,
        "() => Object.assign({}, sessionStorage)",
    )
    .await
    .unwrap_or_default();

    tracing::info!(
        cookies = cookies.len(),
        headers = captured_headers.len(),
        local_storage = local_storage.len(),
        session_storage = session_storage.len(),
        "Auth extraction complete"
    );

    SessionState {
        cookies,
        headers: captured_headers.clone(),
        local_storage,
        session_storage,
        extracted_at: Some(chrono::Utc::now().to_rfc3339()),
        // Caller fills this with the fingerprint actually used for the context.
        fingerprint: None,
        // Browser extraction has no AuthRecipe token store; the HTTP lane sets this.
        tokens: None,
    }
}
