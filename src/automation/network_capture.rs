use std::collections::HashMap;

use crate::models::network::{self, NetworkCall};

/// Char-boundary-safe prefix of at most `max_bytes` bytes. Raw `&s[..n]` slicing
/// panics if `n` lands inside a multibyte UTF-8 sequence — a malicious gateway or
/// website could crash the agent by returning such a body/header. This walks back
/// to the nearest char boundary at or below `max_bytes` (never panics, never
/// splits a code point).
fn truncate_bytes(s: &str, max_bytes: usize) -> &str {
    if s.len() <= max_bytes {
        return s;
    }
    let mut end = max_bytes;
    while end > 0 && !s.is_char_boundary(end) {
        end -= 1;
    }
    &s[..end]
}

/// If `value` contains any credential the agent HOLDS, return the value with each such occurrence
/// replaced by that credential's `{{key}}` placeholder (so it is safe to show the agent and it learns
/// the exact auth to reproduce). Returns `None` when no held credential appears — the caller then
/// decides whether the header is a secret to redact. Only credentials of length ≥ 4 are matched, so a
/// trivial value (e.g. a 1-char form field) can't cause spurious replacements.
fn reveal_held_credentials(value: &str, creds: &HashMap<String, String>) -> Option<String> {
    let mut shown = value.to_string();
    let mut matched = false;
    // Longest values first, so a credential that is a substring of another doesn't shadow it.
    let mut pairs: Vec<(&String, &String)> = creds.iter().collect();
    pairs.sort_by_key(|(_, v)| std::cmp::Reverse(v.len()));
    for (k, v) in pairs {
        let v = v.trim();
        if v.len() < 4 {
            continue;
        }
        let placeholder = format!("{{{{{k}}}}}");
        // Raw match — JSON login bodies and auth headers carry the value verbatim.
        if shown.contains(v) {
            shown = shown.replace(v, &placeholder);
            matched = true;
        }
        // Percent-encoded match — a `application/x-www-form-urlencoded` login POST body carries the
        // value encoded (`pass=Se%21cret`), so match that form too. Without this a form-login body
        // would show its password raw and the agent couldn't see it's reconstructable.
        let encoded: String = url::form_urlencoded::byte_serialize(v.as_bytes()).collect();
        if encoded != v && shown.contains(&encoded) {
            shown = shown.replace(&encoded, &placeholder);
            matched = true;
        }
    }
    if matched {
        Some(shown)
    } else {
        None
    }
}

/// 1:1 port of Python recorder.py NetworkCapture class.
///
/// Passive network traffic capture for api_discovery mode.
/// Uses page.on('request') + page.on('response') (pure observation, zero latency)
/// instead of page.route() which intercepts and replays.
///
/// Captures only XHR/Fetch calls + document POSTs (form submissions).
/// Filters out images, CSS, fonts, tracking/analytics, and other noise.
pub struct NetworkCapture {
    calls: Vec<NetworkCall>,
    pending: HashMap<String, NetworkCall>,
    step: usize,
    last_action: String,
}

impl Default for NetworkCapture {
    fn default() -> Self {
        Self::new()
    }
}

impl NetworkCapture {
    pub fn new() -> Self {
        Self {
            calls: Vec::new(),
            pending: HashMap::new(),
            step: 0,
            last_action: String::new(),
        }
    }

    /// Current step counter — mirrors Python NetworkCapture._step.
    pub fn current_step(&self) -> usize {
        self.step
    }

    pub fn mark_step(&mut self, action_description: &str) {
        self.step += 1;
        self.last_action = action_description.to_string();
    }

    pub fn get_calls_since(&self, step: usize) -> Vec<&NetworkCall> {
        self.calls.iter().filter(|c| c.step >= step).collect()
    }

    /// Whether a request with this id is awaiting its response. Lets the
    /// response listener skip body downloads for uncaptured (asset) requests.
    pub fn has_pending(&self, request_id: &str) -> bool {
        self.pending.contains_key(request_id)
    }

    pub fn get_all_calls(&self) -> &[NetworkCall] {
        &self.calls
    }

    pub fn clear(&mut self) {
        self.calls.clear();
        self.pending.clear();
    }

    /// Exact port of Python _on_request (sync callback).
    /// resource_type comes from Playwright request.resource_type.
    pub fn on_request(
        &mut self,
        request_id: &str,
        method: &str,
        url: &str,
        resource_type: &str,
        headers: HashMap<String, String>,
        body: Option<String>,
    ) {
        // Only capture XHR/fetch and document POST/PUT/PATCH
        if resource_type != "xhr" && resource_type != "fetch" {
            let m = method.to_uppercase();
            if !(resource_type == "document" && (m == "POST" || m == "PUT" || m == "PATCH")) {
                return;
            }
        }

        if network::should_skip_url(url) {
            return;
        }

        let post_data = body.map(|b| {
            if b.len() > network::MAX_BODY_SIZE {
                truncate_bytes(&b, network::MAX_BODY_SIZE).to_string()
            } else {
                b
            }
        });

        let content_type = headers
            .iter()
            .find(|(k, _)| k.to_lowercase() == "content-type")
            .map(|(_, v)| v.clone());

        // The FULL raw headers, kept only in the ephemeral `raw_headers` (never persisted). The prompt
        // layer reveals held-credential values as placeholders (any header, any auth scheme) or redacts.
        let raw_headers = Some(headers.clone());

        let call = NetworkCall {
            method: method.to_uppercase(),
            url: url.to_string(),
            request_headers: Some(network::filter_headers(&headers)),
            request_body: post_data,
            request_content_type: content_type,
            resource_type: resource_type.to_string(),
            step: self.step,
            triggered_by: if self.last_action.is_empty() {
                None
            } else {
                Some(self.last_action.clone())
            },
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs_f64(),
            response_status: None,
            response_headers: None,
            response_body: None,
            response_content_type: None,
            raw_headers,
        };

        self.pending.insert(request_id.to_string(), call);
    }

    /// Exact port of Python async _on_response callback.
    /// Returns a clone of the finalized call (for live streaming), or `None` if
    /// the response did not match a captured request.
    pub fn on_response(
        &mut self,
        request_id: &str,
        status: u16,
        headers: HashMap<String, String>,
        body: Option<String>,
    ) -> Option<NetworkCall> {
        let mut call = self.pending.remove(request_id)?;

        let resp_content_type = headers
            .iter()
            .find(|(k, _)| k.to_lowercase() == "content-type")
            .map(|(_, v)| v.clone());

        let resp_body = if let Some(ref ct) = resp_content_type {
            let ct_lower = ct.to_lowercase();
            if ["json", "text", "xml", "html", "form"]
                .iter()
                .any(|t| ct_lower.contains(t))
            {
                body.map(|b| {
                    if b.len() > network::MAX_BODY_SIZE {
                        format!("{}...[truncated]", truncate_bytes(&b, network::MAX_BODY_SIZE))
                    } else {
                        b
                    }
                })
            } else {
                None
            }
        } else {
            None
        };

        call.response_status = Some(status);
        call.response_headers = Some(network::filter_headers(&headers));
        call.response_body = resp_body;
        call.response_content_type = resp_content_type;
        self.calls.push(call);
        self.calls.last().cloned()
    }

    /// Compact `[i] METHOD url -> status` trace. `creds` maps credential-key → real value: when a
    /// request's `Authorization` token IS one of those values, it is shown as `Bearer {{key}}` so the
    /// agent SEES that the endpoint authenticates with a credential it holds and can build a replayable
    /// api_call. A token the agent does NOT hold (a minted session JWT) is redacted — never leaked.
    pub fn format_for_prompt(&self, calls: &[&NetworkCall], creds: &HashMap<String, String>) -> String {
        if calls.is_empty() {
            return "  (no API calls captured since last action)".to_string();
        }

        let mut lines = Vec::new();
        for (i, call) in calls.iter().enumerate() {
            let status = call
                .response_status
                .map(|s| s.to_string())
                .unwrap_or_else(|| "?".to_string());
            lines.push(format!(
                "  [{}] {} {}  -> {}",
                i + 1,
                call.method,
                call.url,
                status,
            ));

            // Whether this request's BODY carries a credential the agent holds — if so it's shown with
            // {{placeholders}} and (for a POST/PUT) flagged as a replayable sign-in below.
            let mut body_has_held_cred = false;
            if let Some(ref body) = call.request_body {
                // Reveal held credentials in the body as {{placeholders}} — same treatment as headers —
                // so a login POST body reads as `{"user":"{{login_username}}","pass":"{{login_password}}"}`,
                // telling the agent it can reconstruct the sign-in as a request instead of a DOM form.
                let shown_body = match reveal_held_credentials(body, creds) {
                    Some(revealed) => {
                        body_has_held_cred = true;
                        revealed
                    }
                    None => body.clone(),
                };
                lines.push(format!("      Req Body: {}", truncate_bytes(&shown_body, 400)));
            }

            if let Some(ref body) = call.response_body {
                let truncated = truncate_bytes(body, 500);
                lines.push(format!("      Resp Body: {}", truncated));
            }

            // Headers — GENERIC across auth schemes. For every header carrying a value the agent HOLDS
            // (Bearer, custom X-API-Key, X-Auth-Token, any name) show it with the value replaced by the
            // credential's {{placeholder}}, so the agent can reproduce the exact auth. A secret header it
            // does NOT hold is redacted. Content-Type is shown (needed to replicate a POST). Pure noise
            // is dropped. Falls back to the redacted `request_headers` if raw headers weren't captured.
            let mut printed_auth_hint = false;
            if let Some(raw) = &call.raw_headers {
                let mut hdr_lines: Vec<(String, String)> = raw.iter().map(|(k, v)| (k.clone(), v.clone())).collect();
                hdr_lines.sort_by_key(|a| a.0.to_lowercase());
                for (h, v) in hdr_lines {
                    let h_lower = h.to_lowercase();
                    if let Some(revealed) = reveal_held_credentials(&v, creds) {
                        // A credential we hold appears in this header — show it as the placeholder.
                        lines.push(format!("      Header: {}: {}", h, revealed));
                        printed_auth_hint = true;
                    } else if network::AUTH_HEADER_PATTERNS.iter().any(|p| h_lower.contains(p)) {
                        lines.push(format!("      Header: {}: (secret you do NOT hold — endpoint not replayable, use the DOM)", h));
                    } else if h_lower == "content-type" {
                        lines.push(format!("      Header: {}: {}", h, v));
                    }
                }
            } else if let Some(ref req_headers) = call.request_headers {
                for h in req_headers.keys() {
                    if network::AUTH_HEADER_PATTERNS.iter().any(|p| h.to_lowercase().contains(p)) {
                        lines.push(format!("      Header: {}: (present, value redacted)", h));
                    }
                }
            }
            if printed_auth_hint {
                lines.push("      ↑ to call this endpoint, set your api_call/define_function-api headers to exactly the header(s) shown above (with the {{...}} placeholders).".into());
            }

            // A POST/PUT whose BODY carries credentials the agent holds is (very likely) the sign-in
            // request. Point the agent at replaying it as a `login_post` step so the recorded workflow
            // authenticates without the DOM form — provided the body has no token it does NOT hold.
            let m = call.method.to_uppercase();
            if body_has_held_cred && (m == "POST" || m == "PUT") {
                lines.push(
                    "      ↑ this request's BODY carries credential(s) you HOLD (shown as {{placeholders}}). If this is the sign-in POST, you can make the workflow log in WITHOUT the DOM form: emit a login_post step with this exact url + method + the Content-Type header shown + this {{placeholder}} body. It establishes the session cookie so later api_calls reuse it. Do NOT do this (keep the DOM login) if the body ALSO carries a token you do NOT hold — csrf / authenticity_token / nonce / __RequestVerificationToken."
                        .into(),
                );
            }
        }

        lines.join("\n")
    }
}

/// Reveal held credentials as `{{placeholders}}` and redact unheld secrets before captured
/// calls leave the agent for the backend.
///
/// SECURITY REQUIREMENT: the backend must NEVER receive a plaintext login POST body,
/// password, or live token. Twin of the Python agent's `_sanitize_network_calls`, and the
/// only sanctioned way to serialize a capture off-box:
/// - `request_body`: held-credential values become `{{key}}` (raw and percent-encoded).
/// - request/response headers: a held credential becomes `{{key}}`; an auth-relevant header
///   whose value is NOT held becomes `(secret not shown)`; everything else passes through.
/// - `raw_headers` is ephemeral and never serialized (`#[serde(skip)]`), but it IS the
///   source read here, since the stored `request_headers` are already redacted and a held
///   credential could no longer be recognized in them.
pub fn sanitize_network_calls(
    calls: &[NetworkCall],
    creds: &HashMap<String, String>,
) -> Vec<serde_json::Value> {
    const NOT_SHOWN: &str = "(secret not shown)";

    fn clean(
        source: &HashMap<String, String>,
        creds: &HashMap<String, String>,
        not_shown: &str,
    ) -> HashMap<String, String> {
        source
            .iter()
            .map(|(name, val)| {
                let shown = match reveal_held_credentials(val, creds) {
                    Some(revealed) => revealed,
                    None => {
                        let lower = name.to_lowercase();
                        if crate::models::network::AUTH_HEADER_PATTERNS
                            .iter()
                            .any(|p| lower.contains(p))
                            || val == crate::models::network::REDACTED_HEADER_VALUE
                        {
                            not_shown.to_string()
                        } else {
                            val.clone()
                        }
                    }
                };
                (name.clone(), shown)
            })
            .collect()
    }

    calls
        .iter()
        .map(|call| {
            let mut c = call.clone();
            if let Some(body) = c.request_body.as_deref() {
                if let Some(revealed) = reveal_held_credentials(body, creds) {
                    c.request_body = Some(revealed);
                }
            }
            // Prefer the RAW headers: the stored ones are already value-redacted, so a held
            // credential in them could never be matched back to its placeholder.
            let req_source = c
                .raw_headers
                .as_ref()
                .map(crate::models::network::filter_headers)
                .or_else(|| c.request_headers.clone());
            if let Some(src) = req_source {
                c.request_headers = Some(clean(&src, creds, NOT_SHOWN));
            }
            if let Some(resp) = c.response_headers.clone() {
                c.response_headers = Some(clean(&resp, creds, NOT_SHOWN));
            }
            // Belt and braces: `raw_headers` is `#[serde(skip)]`, and it is dropped here too
            // so no future serializer can reintroduce it.
            c.raw_headers = None;
            serde_json::to_value(&c).unwrap_or(serde_json::Value::Null)
        })
        .filter(|v| !v.is_null())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mk_call(headers: &[(&str, &str)]) -> NetworkCall {
        let raw: HashMap<String, String> =
            headers.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect();
        NetworkCall {
            method: "GET".to_string(),
            url: "https://example.com/api/targets".to_string(),
            request_headers: Some(network::filter_headers(&raw)),
            request_body: None,
            request_content_type: Some("application/json".to_string()),
            resource_type: "xhr".to_string(),
            step: 0,
            triggered_by: None,
            timestamp: 0.0,
            response_status: Some(200),
            response_headers: None,
            response_body: None,
            response_content_type: None,
            raw_headers: Some(raw),
        }
    }

    #[test]
    fn unheld_token_is_redacted_never_leaked() {
        let cap = NetworkCapture::new();
        let secret = "sk-live-super-secret-token-1234567890";
        let call = mk_call(&[("Authorization", &format!("Bearer {secret}"))]);
        // No matching credential → the token must be redacted.
        let out = cap.format_for_prompt(&[&call], &HashMap::new());
        assert!(out.contains("Authorization"), "header presence should be shown");
        assert!(!out.contains(secret), "full token must not appear: {out}");
        assert!(out.contains("do NOT hold"), "unheld token should be flagged");
    }

    #[test]
    fn held_bearer_token_shown_as_placeholder() {
        let cap = NetworkCapture::new();
        let token = "ps_x3y0yik38tzEgEG_NvsZrPUNrRqwESK3gkthQ50h5mM";
        let call = mk_call(&[("Authorization", &format!("Bearer {token}"))]);
        let creds = HashMap::from([("login_apikey".to_string(), token.to_string())]);
        let out = cap.format_for_prompt(&[&call], &creds);
        assert!(out.contains("Bearer {{login_apikey}}"), "should reveal the matching placeholder: {out}");
        assert!(!out.contains(token), "raw token must never appear: {out}");
    }

    fn mk_post(body: &str, headers: &[(&str, &str)]) -> NetworkCall {
        let raw: HashMap<String, String> =
            headers.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect();
        NetworkCall {
            method: "POST".to_string(),
            url: "https://example.com/api/login".to_string(),
            request_headers: Some(network::filter_headers(&raw)),
            request_body: Some(body.to_string()),
            request_content_type: headers
                .iter()
                .find(|(k, _)| k.eq_ignore_ascii_case("content-type"))
                .map(|(_, v)| v.to_string()),
            resource_type: "xhr".to_string(),
            step: 0,
            triggered_by: None,
            timestamp: 0.0,
            response_status: Some(200),
            response_headers: None,
            response_body: None,
            response_content_type: None,
            raw_headers: Some(raw),
        }
    }

    #[test]
    fn login_post_json_body_reveals_placeholders_and_flags_replay() {
        // A JSON login POST whose body holds credentials the agent has → the body shows the
        // {{placeholders}} and the sign-in-replay hint fires.
        let cap = NetworkCapture::new();
        let call = mk_post(
            r#"{"username":"john.doe","password":"Sup3rSecretPass"}"#,
            &[("Content-Type", "application/json")],
        );
        let creds = HashMap::from([
            ("login_username".to_string(), "john.doe".to_string()),
            ("login_password".to_string(), "Sup3rSecretPass".to_string()),
        ]);
        let out = cap.format_for_prompt(&[&call], &creds);
        assert!(out.contains("{{login_username}}"), "username should be a placeholder: {out}");
        assert!(out.contains("{{login_password}}"), "password should be a placeholder: {out}");
        assert!(!out.contains("Sup3rSecretPass"), "raw password must never appear: {out}");
        assert!(out.contains("login_post"), "should point at replaying the sign-in as login_post: {out}");
    }

    #[test]
    fn login_post_form_encoded_body_reveals_percent_encoded_credential() {
        // A form-encoded login POST carries the password percent-encoded — it must still reveal.
        let cap = NetworkCapture::new();
        // "Se!cret&x" encodes '!' as %21 and '&' as %26.
        let call = mk_post(
            "username=alice&password=Se%21cret%26x",
            &[("Content-Type", "application/x-www-form-urlencoded")],
        );
        let creds = HashMap::from([
            ("login_username".to_string(), "alice".to_string()),
            ("login_password".to_string(), "Se!cret&x".to_string()),
        ]);
        let out = cap.format_for_prompt(&[&call], &creds);
        assert!(out.contains("password={{login_password}}"), "percent-encoded pw should reveal: {out}");
        assert!(!out.contains("Se%21cret"), "raw encoded pw must not appear: {out}");
    }

    #[test]
    fn held_credential_in_any_custom_header_is_generic() {
        // Generic across schemes: a custom X-API-Key header carrying the held credential is revealed.
        let cap = NetworkCapture::new();
        let key = "abc123def456ghi789";
        let call = mk_call(&[("X-API-Key", key), ("Content-Type", "application/json")]);
        let creds = HashMap::from([("login_token".to_string(), key.to_string())]);
        let out = cap.format_for_prompt(&[&call], &creds);
        assert!(out.contains("X-API-Key: {{login_token}}"), "custom auth header revealed: {out}");
        assert!(out.contains("Content-Type: application/json"), "content-type shown: {out}");
        assert!(!out.contains(key), "raw key must never appear: {out}");
    }

    #[test]
    fn sanitize_never_lets_a_plaintext_credential_leave() {
        let mut creds = HashMap::new();
        creds.insert("password".to_string(), "Sup3rSecret!".to_string());
        creds.insert("username".to_string(), "someone@example.com".to_string());

        let mut raw = HashMap::new();
        raw.insert("Authorization".to_string(), "Bearer Sup3rSecret!".to_string());
        raw.insert("X-Session-Token".to_string(), "minted-token-we-do-not-hold".to_string());
        raw.insert("Content-Type".to_string(), "application/x-www-form-urlencoded".to_string());

        let call = NetworkCall {
            method: "POST".into(),
            url: "https://example.com/login".into(),
            request_headers: None,
            // Percent-encoded, as a real form post carries it.
            request_body: Some("email=someone%40example.com&password=Sup3rSecret%21".into()),
            request_content_type: Some("application/x-www-form-urlencoded".into()),
            resource_type: "document".into(),
            step: 1,
            triggered_by: None,
            timestamp: 0.0,
            response_status: Some(302),
            response_headers: None,
            response_body: None,
            response_content_type: None,
            raw_headers: Some(raw),
        };

        let out = sanitize_network_calls(&[call], &creds);
        let text = serde_json::to_string(&out).unwrap();
        assert!(!text.contains("Sup3rSecret"), "plaintext password left the agent: {text}");
        assert!(!text.contains("someone%40example.com"), "encoded username leaked: {text}");
        assert!(!text.contains("minted-token-we-do-not-hold"), "unheld token leaked: {text}");
        // The optimizer still learns HOW the endpoint authenticates.
        assert!(text.contains("{{password}}"), "held credential not revealed: {text}");
        assert!(text.contains("{{username}}"), "held credential not revealed: {text}");
        assert!(text.contains("(secret not shown)"), "unheld secret not redacted: {text}");
        assert!(text.contains("application/x-www-form-urlencoded"), "content-type kept: {text}");
    }
}
