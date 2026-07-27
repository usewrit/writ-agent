use std::collections::HashMap;

use serde::{Deserialize, Serialize};

/// 1:1 port of Python NetworkCapture's call record.
/// Python stores request_content_type and response_content_type separately;
/// also stores resource_type and triggered_by.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkCall {
    pub method: String,
    pub url: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub request_headers: Option<HashMap<String, String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub request_body: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub request_content_type: Option<String>,
    pub resource_type: String,
    pub step: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub triggered_by: Option<String>,
    pub timestamp: f64,
    // Response fields (filled in on_response)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub response_status: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub response_headers: Option<HashMap<String, String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub response_body: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub response_content_type: Option<String>,
    /// The request's RAW headers, kept EPHEMERALLY (`#[serde(skip)]` — never serialized, persisted, or
    /// logged; the serialized `request_headers` above stays redacted). The prompt layer scans these to
    /// support ANY header-based auth scheme generically: for each header whose value contains a
    /// credential the agent HOLDS (a Bearer token, a custom `X-API-Key`, an `X-Auth-Token`, whatever it
    /// is named), it is shown as that credential's `{{placeholder}}` so the agent sees exactly how the
    /// endpoint authenticates and can reproduce it in a replayable api_call. A secret header the agent
    /// does NOT hold (a minted session token) is redacted. The plaintext value never reaches the model.
    #[serde(skip)]
    pub raw_headers: Option<HashMap<String, String>>,
}

// Skip patterns from Python NetworkCapture.SKIP_URL_PATTERNS, re-categorized so
// matching is precise. A naive `contains` over the whole URL can nuke a real API
// endpoint (e.g. a path containing ".map", "segment", or "service-worker"), so
// each category is matched against the right part of the parsed URL.

/// Analytics / tracking / font / CDN-noise hosts. Matched against the URL host
/// (exact host or any subdomain of it) — never the path.
pub const SKIP_HOST_SUFFIXES: &[&str] = &[
    "google-analytics.com",
    "googletagmanager.com",
    "facebook.net",
    "doubleclick.net",
    "hotjar.com",
    "mixpanel.com",
    "segment.com",
    "segment.io",
    "sentry.io",
    "newrelic.com",
    "datadoghq.com",
    "fonts.googleapis.com",
    "fonts.gstatic.com",
    "clarity.ms",
    "intercom.io",
    "amplitude.com",
    "crisp.chat",
    "hubspot.com",
];

/// Host substrings marking tracking-intake subdomains (e.g. browser-intake-datadoghq.com).
pub const SKIP_HOST_CONTAINS: &[&str] = &["browser-intake"];

/// (host-suffix, path-prefix) pairs — skip only when both match (e.g. facebook.com/tr,
/// cloudflare.com/cdn-cgi). Avoids dropping a same-host API on a different path.
pub const SKIP_HOST_PATH: &[(&str, &str)] = &[
    ("facebook.com", "/tr"),
    ("cloudflare.com", "/cdn-cgi"),
];

/// Static-asset / source-map extensions. Matched only when the URL *path* ends
/// with them (query string ignored), so `/api/roadmap` or `?f=.map` are safe.
pub const SKIP_PATH_EXTENSIONS: &[&str] = &[".woff", ".woff2", ".ttf", ".eot", ".map"];

/// Service-worker / bundler / dev artifacts. Distinctive, path-qualified tokens
/// with low false-positive risk; matched against the URL path.
pub const SKIP_PATH_CONTAINS: &[&str] = &[
    "/sw.js",
    "service-worker",
    "/sockjs-node/",
    "/__webpack",
    "/hot-update.",
    "favicon.ico",
];

/// Browser-extension schemes — matched against the raw URL prefix.
pub const SKIP_SCHEMES: &[&str] = &["chrome-extension://", "moz-extension://"];

pub const MAX_BODY_SIZE: usize = 10_240;

/// Auth-related header name patterns for format_for_prompt display
pub const AUTH_HEADER_PATTERNS: &[&str] = &[
    "authorization",
    "x-auth",
    "x-api-key",
    "x-token",
    "x-csrf",
    "cookie",
];

pub fn should_skip_url(url: &str) -> bool {
    let lower = url.to_lowercase();

    // Browser-extension schemes — match on the raw URL prefix.
    if SKIP_SCHEMES.iter().any(|s| lower.starts_with(s)) {
        return true;
    }

    // Parse for host/path-aware matching. If parsing fails (rare for real
    // network requests, which carry absolute URLs), fall back to a conservative
    // host-suffix / extension check so we never panic and never over-match.
    let parsed = match url::Url::parse(&lower) {
        Ok(p) => p,
        Err(_) => {
            return SKIP_HOST_SUFFIXES.iter().any(|p| lower.contains(p))
                || SKIP_PATH_EXTENSIONS.iter().any(|e| lower.ends_with(e));
        }
    };

    let host = parsed.host_str().unwrap_or("");
    let path = parsed.path(); // excludes query/fragment

    let host_matches = |p: &str| host == p || host.ends_with(&format!(".{p}"));

    if SKIP_HOST_SUFFIXES.iter().any(|p| host_matches(p)) {
        return true;
    }
    if SKIP_HOST_CONTAINS.iter().any(|p| host.contains(p)) {
        return true;
    }
    if SKIP_HOST_PATH
        .iter()
        .any(|(h, prefix)| host_matches(h) && path.starts_with(prefix))
    {
        return true;
    }
    if SKIP_PATH_EXTENSIONS.iter().any(|e| path.ends_with(e)) {
        return true;
    }
    if SKIP_PATH_CONTAINS.iter().any(|p| path.contains(p)) {
        return true;
    }

    false
}

/// Placeholder substituted for the value of a secret-bearing header. The header NAME is preserved so
/// downstream name-aware logic (e.g. [`AUTH_HEADER_PATTERNS`] display in `network_capture`) still sees
/// that auth was present, but the live token never lands in a persisted / syncable capture.
pub const REDACTED_HEADER_VALUE: &str = "«redacted»";

/// Header names whose VALUES carry live session secrets. Case-insensitive. We redact the value rather
/// than drop the header so a name-checking consumer still observes the header's presence, while the
/// token itself never reaches the UI capture or the persisted/synced workflow.
const SECRET_VALUE_HEADERS: &[&str] = &["cookie", "authorization", "x-api-key", "set-cookie"];

/// Exact match of Python NetworkCapture._filter_headers, plus secret-value redaction: noise headers
/// are dropped entirely, and any header whose value is a live credential (cookie / authorization /
/// x-api-key / set-cookie) is kept name-only with its value replaced by [`REDACTED_HEADER_VALUE`].
pub fn filter_headers(headers: &HashMap<String, String>) -> HashMap<String, String> {
    const SKIP: &[&str] = &[
        "accept-encoding",
        "accept-language",
        "connection",
        "dnt",
        "upgrade-insecure-requests",
        "sec-fetch-dest",
        "sec-fetch-mode",
        "sec-fetch-site",
        "sec-fetch-user",
        "sec-ch-ua",
        "sec-ch-ua-mobile",
        "sec-ch-ua-platform",
        "user-agent",
        "cache-control",
        "pragma",
    ];

    headers
        .iter()
        .filter(|(k, _)| !SKIP.contains(&k.to_lowercase().as_str()))
        .map(|(k, v)| {
            if SECRET_VALUE_HEADERS.contains(&k.to_lowercase().as_str()) {
                (k.clone(), REDACTED_HEADER_VALUE.to_string())
            } else {
                (k.clone(), v.clone())
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn filter_headers_redacts_secret_values_but_keeps_names() {
        let mut h = HashMap::new();
        h.insert("Authorization".to_string(), "Bearer sk-live-secret".to_string());
        h.insert("Cookie".to_string(), "session=abc123; token=xyz".to_string());
        h.insert("Set-Cookie".to_string(), "session=abc123; HttpOnly".to_string());
        h.insert("X-API-Key".to_string(), "super-secret-key".to_string());
        h.insert("Content-Type".to_string(), "application/json".to_string());
        h.insert("user-agent".to_string(), "Mozilla/5.0".to_string());

        let out = filter_headers(&h);

        // Noise header is dropped entirely.
        assert!(!out.contains_key("user-agent"));
        // Secret-bearing headers survive by NAME but never leak their live value.
        for name in ["Authorization", "Cookie", "Set-Cookie", "X-API-Key"] {
            assert_eq!(out.get(name).map(String::as_str), Some(REDACTED_HEADER_VALUE));
        }
        // Non-secret header passes through untouched.
        assert_eq!(out.get("Content-Type").map(String::as_str), Some("application/json"));
    }
}
