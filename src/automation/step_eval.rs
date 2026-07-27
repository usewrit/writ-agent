use std::collections::HashMap;

use playwright_rs::Page;

use crate::browser::page_query;
use crate::models::workflow::WorkflowStepConfig;
// The canonical URL scrubber lives in `util::logging` next to the sink redactor (it used to be a
// private helper here, which is why the other four secret-bearing URL sites each grew their own
// ad-hoc `format!`). Aliased to the original local name so this module's call sites read unchanged.
use crate::util::logging::redact_url_for_log as redact_url_secrets;
use crate::util::value_resolver;
use super::step_executor::{StepError, StepResult};

pub async fn execute_evaluate(page: &Page, config: &WorkflowStepConfig) -> StepResult {
    let script = config.script.as_deref().unwrap_or("");
    let variable = config.extra.get("variable").and_then(|v| v.as_str());

    tracing::debug!(
        script_len = script.len(),
        variable = ?variable,
        "Executing evaluate step"
    );

    if script.is_empty() {
        return Err(StepError::Execution("evaluate: no script provided".into()));
    }

    // Execute via page.evaluate and DECODE the result into plain JSON.
    //
    // IMPORTANT: do NOT use `evaluate_value` here. That helper returns Playwright's RAW serialized
    // wire form for any object/array result — e.g. `{"o":[{"k":"store","v":{"s":"…"}}], …}` with
    // `s`/`n`/`b`/`o` type tags — which is unreadable downstream (the Data table shows it as
    // "nothing extracted"). The typed `evaluate` runs the SAME `evaluateExpression` protocol call but
    // unwraps the serialized value back to ordinary JSON via the crate's `parse_result`.
    let value: serde_json::Value = page_query::evaluate(page, script)
        .await
        .map_err(|e| StepError::Execution(format!("evaluate failed: {}", e)))?;

    // If a variable name is specified, store the (decoded) result.
    if let Some(var_name) = variable {
        let mut result = HashMap::new();
        result.insert(var_name.to_string(), value);
        return Ok(Some(result));
    }

    Ok(None)
}

pub async fn execute_codegen(page: &Page, config: &WorkflowStepConfig) -> StepResult {
    let script = config.script.as_deref().unwrap_or("");

    tracing::debug!(script_len = script.len(), "Executing codegen step");

    if script.is_empty() {
        return Err(StepError::Execution("codegen: no script provided".into()));
    }

    // Execute the codegen script directly on the page
    // Codegen scripts are self-contained JS that manipulate the page
    page_query::evaluate_expression(page, script)
        .await
        .map_err(|e| StepError::Execution(format!("codegen execution failed: {}", e)))?;

    Ok(None)
}

/// JS for a `fields`-style structured extraction: one row per element matching
/// `row_selector`, each field read from a CSS sub-selector scoped to that element.
///
/// Shared by the record-time action executors and the replay executor so a
/// workflow extracts exactly the same shape when it runs unattended as it did
/// when it was recorded.
pub fn row_extraction_js(
    row_selector: &str,
    fields: &serde_json::Map<String, serde_json::Value>,
    limit: u64,
) -> String {
    format!(
        r#"(() => {{
            const rowSel = {row};
            const fields = {fields};
            const limit = {limit};
            const out = [];
            for (const el of document.querySelectorAll(rowSel)) {{
                if (out.length >= limit) break;
                const row = {{}};
                for (const [name, sel] of Object.entries(fields)) {{
                    // An empty / "." / ":scope" selector means the row element itself.
                    const t = (!sel || sel === '.' || sel === ':scope') ? el : el.querySelector(sel);
                    row[name] = t
                        ? ((t.tagName === 'A' && !t.innerText.trim())
                            ? (t.getAttribute('href') || '')
                            : (t.innerText || t.textContent || '').trim())
                        : null;
                }}
                out.push(row);
            }}
            return {{ rows: out, count: out.length, selector: rowSel }};
        }})()"#,
        row = serde_json::to_string(row_selector).unwrap_or_else(|_| "\"body\"".into()),
        fields = serde_json::to_string(fields).unwrap_or_else(|_| "{}".into()),
        limit = limit,
    )
}

pub async fn execute_extract(page: &Page, config: &WorkflowStepConfig) -> StepResult {
    let selector = config.selector.as_deref().unwrap_or("");
    let variable = config
        .extra
        .get("variable")
        .and_then(|v| v.as_str())
        .unwrap_or("extracted");

    tracing::debug!(selector = selector, variable = variable, "Executing extract step");

    // COMPUTED extract: a script-backed extract carries its JS in `config.script`
    // (or, in the cloud-authored shape, `config.value` when extract_type=="computed").
    // The plain selector path below cannot run a script, so run it like an `evaluate`
    // step. This keeps the daemon tolerant of computed-extract steps (e.g. workflows
    // imported from the cloud, where this shape is valid) instead of erroring with
    // "extract: no selector provided". Fresh AI-generated extractions are emitted as
    // `evaluate` steps directly; this is the compatibility path for existing ones.
    let computed = config
        .extra
        .get("extract_type")
        .and_then(|v| v.as_str())
        == Some("computed");
    let script = config
        .script
        .as_deref()
        .filter(|s| !s.is_empty())
        .or(if computed { config.value.as_deref() } else { None })
        .filter(|s| !s.is_empty());
    if let Some(script) = script {
        let value = page_query::evaluate(page, script)
            .await
            .map_err(|e| StepError::Execution(format!("extract (computed) failed: {}", e)))?;
        let mut result = HashMap::new();
        result.insert(variable.to_string(), value);
        return Ok(Some(result));
    }

    if selector.is_empty() {
        return Err(StepError::Execution("extract: no selector provided".into()));
    }

    // STRUCTURED extract: `config.fields` maps field names to CSS sub-selectors
    // evaluated inside each element matching `selector`, so one step yields a ROW
    // PER element. Without it an extract can only return the first match's text,
    // which is why repeated lists previously had to go through a hand-written
    // `evaluate` script. Kept on the same step type so a workflow recorded with
    // fields replays here unchanged.
    if let Some(fields) = config.extra.get("fields").and_then(|v| v.as_object()) {
        let field_map: serde_json::Map<String, serde_json::Value> = fields
            .iter()
            .filter(|(_, v)| v.is_string())
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect();
        if !field_map.is_empty() {
            let limit = config
                .extra
                .get("limit")
                .and_then(|v| v.as_u64())
                .unwrap_or(100)
                .clamp(1, 1000);
            let value = page_query::evaluate(page, &row_extraction_js(selector, &field_map, limit))
                .await
                .map_err(|e| StepError::Execution(format!("extract (fields) failed: {}", e)))?;
            let mut result = HashMap::new();
            result.insert(variable.to_string(), value);
            return Ok(Some(result));
        }
    }

    // Extract text content from the element
    let text = page_query::locator_text_content(page, selector)
        .await
        .map_err(|e| StepError::ElementNotFound(format!("extract element '{}': {}", selector, e)))?
        .unwrap_or_default();

    let mut result = HashMap::new();
    result.insert(
        variable.to_string(),
        serde_json::Value::String(text),
    );
    Ok(Some(result))
}

/// Run the api_call's in-page fetch and return `(HTTP status, parsed body)` — mirroring the Python
/// agent, whose fetch returns `{status, content_type, data}`. The STATUS is what lets a caller tell
/// an auth rejection (401/403) from a wrong endpoint or empty data — a distinction the body alone
/// cannot make, and the reason the explorer was wrongly disabling a WORKING API.
pub async fn api_call_raw(
    page: &Page,
    config: &WorkflowStepConfig,
    credentials: &HashMap<String, String>,
    form_data: &HashMap<String, String>,
    extracted: &HashMap<String, serde_json::Value>,
) -> Result<(u16, serde_json::Value), StepError> {
    let url = config.url.as_deref().unwrap_or("");
    let method = config
        .extra
        .get("method")
        .and_then(|v| v.as_str())
        .unwrap_or("GET");

    let resolved_url =
        value_resolver::resolve_value_full(url, credentials, Some(form_data), None, Some(extracted));

    // The resolved URL's query carries live credentials (`?api_token={{vault:vendor_key}}` is already
    // substituted at this point) — the two `ai_api_debug` lines further down get this right; this one
    // was missed and logged it in full.
    tracing::debug!(method = method, url = %redact_url_secrets(&resolved_url), "Executing api_call step");

    if resolved_url.is_empty() {
        return Err(StepError::Execution("api_call: no URL provided".into()));
    }

    // SSRF guard (fail-CLOSED): the in-page `fetch()` below runs with the browser's cookies against a
    // caller-supplied URL. A cloud-dispatched recipe must not be able to make the local machine read
    // internal/metadata/LAN endpoints, so vet the resolved target before building the fetch.
    if !crate::security::url_guard::is_navigation_url_safe_async(&resolved_url).await {
        // Host/path only — a StepError message is logged at ERROR, persisted as the run's `error`,
        // returned by the local API, forwarded to the cloud and fed to the AI repair prompt.
        return Err(StepError::NavigationFailed(format!(
            "api_call URL blocked by SSRF guard: {}",
            redact_url_secrets(&resolved_url)
        )));
    }

    // Build the fetch options
    // A GET/HEAD request MUST NOT carry a body — the browser's fetch throws
    // `TypeError: Request with GET/HEAD method cannot have body` before it even sends, which silently
    // broke EVERY GET api_call. Only build a body for methods that allow one, and never from an
    // absent/`null`/empty value (a JSON `null` stringifies to the literal "null", which is still a body).
    let method_upper = method.to_uppercase();
    let allows_body = method_upper != "GET" && method_upper != "HEAD";
    // The concierge/optimizer emit the request body under `body` OR `body_template` (a string or a
    // JSON object). Read `body` first, then fall back to `body_template` — historically only `body`
    // was read, so any workflow authored with `body_template` silently sent no body.
    let body = if !allows_body {
        None
    } else {
        config.extra.get("body")
            .filter(|b| !b.is_null())
            .or_else(|| config.extra.get("body_template").filter(|b| !b.is_null()))
            .map(|b| {
                let body_str = if b.is_string() {
                    b.as_str().unwrap_or("").to_string()
                } else {
                    serde_json::to_string(b).unwrap_or_default()
                };
                value_resolver::resolve_value_full(&body_str, credentials, Some(form_data), None, Some(extracted))
            })
            .filter(|s| !s.trim().is_empty() && s.trim() != "null")
    };

    // Resolve header values, then DROP any header whose value is empty or still carries an
    // UNRESOLVED `{{placeholder}}`. An auth header like `Bearer {{login_key}}` that doesn't resolve
    // (the secret isn't provided) would otherwise be sent verbatim — a broken `Bearer {{login_key}}`
    // that 401s. Dropping it lets the in-page fetch authenticate the way replay actually will: with
    // the session cookies (`credentials:'include'`) established by the recorded sign-in, or a real
    // resolved secret. This makes the build-time TEST and the replay behave identically — no header
    // that only "works" because a live token happened to be present.
    let headers = config.extra.get("headers")
        .and_then(|h| h.as_object())
        .map(|h| {
            let resolved: serde_json::Map<String, serde_json::Value> = h.iter().filter_map(|(k, v)| {
                let val = value_resolver::resolve_value_full(
                    v.as_str().unwrap_or(""),
                    credentials,
                    Some(form_data),
                    None,
                    Some(extracted),
                );
                // A response-derived {{extracted:}} value must not smuggle a CR/LF into a header
                // (request splitting). Drop such a header rather than send a malformed request.
                if val.trim().is_empty() || val.contains("{{") {
                    tracing::debug!(header = %k, "api_call: dropping header with unresolved/empty value (falling back to cookie auth)");
                    None
                } else if val.contains('\r') || val.contains('\n') {
                    tracing::warn!(header = %k, "api_call: dropping header with CR/LF in resolved value (injection guard)");
                    None
                } else {
                    Some((k.clone(), serde_json::Value::String(val)))
                }
            }).collect();
            serde_json::to_string(&resolved).unwrap_or("{}".into())
        })
        .unwrap_or_else(|| "{}".into());

    // Execute fetch() inside the browser to inherit cookies/session. `credentials:'include'` sends the
    // session cookie established at sign-in — so an authed page reaches its own API without any header.
    // On a 401/403 we RETRY once with the auth headers stripped (cookie-only): a site that hands the
    // SPA a bearer token often ALSO sets an auth cookie, and the recorded bearer is stale/absent at
    // replay while the cookie (re-established by the workflow's sign-in) is live. Same logic runs at
    // test and replay, so a cookie-authed API just works in both. Returns {status, data}.
    let body_assign = body
        .as_ref()
        .map(|b| format!("opts.body = {};", serde_json::to_string(b).unwrap_or_default()))
        .unwrap_or_default();
    let fetch_js = format!(
        r#"(async () => {{
            try {{
                const H = {headers};
                const opts = {{ method: {method}, credentials: 'include', redirect: 'follow' }};
                {body_assign}
                const strip = (h) => {{ const o = {{}}; for (const k in h) {{ if (!/^(authorization|cookie|x-api-key|x-auth-token|api-key)$/i.test(k)) o[k] = h[k]; }} return o; }};
                let resp = await fetch({url}, Object.assign({{}}, opts, {{ headers: H }}));
                if (resp.status === 401 || resp.status === 403) {{
                    const retry = await fetch({url}, Object.assign({{}}, opts, {{ headers: strip(H) }}));
                    if (retry.ok) resp = retry;
                }}
                const text = await resp.text();
                let data = text;
                try {{ data = JSON.parse(text); }} catch (e) {{}}
                return {{ status: resp.status, data: data }};
            }} catch (e) {{ return {{ status: 0, error: String(e) }}; }}
        }})()"#,
        url = serde_json::to_string(&resolved_url).unwrap_or_default(),
        method = serde_json::to_string(method).unwrap_or_default(),
        headers = headers,
        body_assign = body_assign,
    );

    let response: serde_json::Value = page.evaluate(&fetch_js, None::<&()>)
        .await
        .map_err(|e| StepError::Execution(format!("api_call fetch failed: {}", e)))?;

    if let Some(err) = response.get("error").and_then(|e| e.as_str()) {
        // NEVER log resolved auth headers, the resolved URL's query, or the body at default level —
        // they carry live credentials / PII (see `redact_headers_json` / `redact_url_secrets`).
        tracing::warn!(target: "ai_api_debug", url = %redact_url_secrets(&resolved_url), method, headers = %redact_headers_json(&headers), "api_call fetch THREW (likely CORS/blocked/unreachable): {err}");
        return Err(StepError::Execution(format!("api_call fetch failed: {err}")));
    }
    let status = response.get("status").and_then(|s| s.as_u64()).unwrap_or(0) as u16;
    let data = response.get("data").cloned().unwrap_or(serde_json::Value::Null);
    // Response diagnostics for debugging why an api_call didn't yield data. The raw body can carry
    // PII/secrets and the resolved headers carry live auth, so this is gated to DEBUG (off at the
    // default level), the body is reduced to a length, and header values / URL query are redacted.
    let body_len = data.to_string().chars().count();
    tracing::debug!(target: "ai_api_debug", url = %redact_url_secrets(&resolved_url), method, headers = %redact_headers_json(&headers), status, body_len, "api_call raw response");
    Ok((status, data))
}

/// Header names whose VALUES must never be logged (case-insensitive). Mirrors the auth-header set the
/// in-page fetch strips on a 401/403 retry.
const SENSITIVE_HEADER_NAMES: &[&str] =
    &["authorization", "cookie", "set-cookie", "x-api-key", "x-auth-token", "api-key", "proxy-authorization"];

/// Redact secret-bearing values from a resolved-headers JSON string for logging. Sensitive header
/// values become `<redacted>`; non-sensitive names/values are kept for debuggability. Returns
/// `<unparseable-headers>` rather than echoing the raw string if it isn't the expected JSON object.
fn redact_headers_json(headers_json: &str) -> String {
    match serde_json::from_str::<serde_json::Map<String, serde_json::Value>>(headers_json) {
        Ok(map) => {
            let redacted: serde_json::Map<String, serde_json::Value> = map
                .into_iter()
                .map(|(k, v)| {
                    if SENSITIVE_HEADER_NAMES.contains(&k.to_lowercase().as_str()) {
                        (k, serde_json::Value::String("<redacted>".into()))
                    } else {
                        (k, v)
                    }
                })
                .collect();
            serde_json::to_string(&redacted).unwrap_or_else(|_| "<unparseable-headers>".into())
        }
        Err(_) => "<unparseable-headers>".into(),
    }
}

/// Python-truthiness for the api_call result: mirrors the Python agent's
/// `result.get('data') if result.get('data') else result` unwrapping.
fn is_nonempty(v: &serde_json::Value) -> bool {
    match v {
        serde_json::Value::Null => false,
        serde_json::Value::Bool(b) => *b,
        serde_json::Value::Number(n) => n.as_f64().map(|f| f != 0.0).unwrap_or(true),
        serde_json::Value::String(s) => !s.trim().is_empty(),
        serde_json::Value::Array(a) => !a.is_empty(),
        serde_json::Value::Object(o) => !o.is_empty(),
    }
}

pub async fn execute_api_call(
    page: &Page,
    config: &WorkflowStepConfig,
    credentials: &HashMap<String, String>,
    form_data: &HashMap<String, String>,
    extracted: &HashMap<String, serde_json::Value>,
) -> StepResult {
    let variable = config
        .extra
        .get("variable")
        .and_then(|v| v.as_str())
        .unwrap_or("api_result");
    let (status, data) = api_call_raw(page, config, credentials, form_data, extracted).await?;
    let mut result = HashMap::new();
    // Apply response_extractions (JSONPath over the parsed body) so later steps can reference the
    // pulled values as {{extracted:name}}. Same helper the browserless HTTP lane uses.
    for (name, value) in super::response_extract::apply_response_extractions(config, &data) {
        result.insert(name, value);
    }
    // Python parity: store the DATA when the endpoint returned some; otherwise store the
    // {status, data} envelope so a failure is visible in the run's results instead of vanishing.
    let value = if is_nonempty(&data) {
        data
    } else {
        serde_json::json!({ "status": status, "data": data })
    };
    result.insert(variable.to_string(), value);
    Ok(Some(result))
}
