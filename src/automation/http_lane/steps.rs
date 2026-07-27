//! Executing individual request steps over the HTTP lane.
//!
//! Mirrors `step_eval::api_call_raw` semantics (placeholder resolution, body/body_template, header
//! drop rules, the 401/403 cookie-only retry, response_extractions) but against the lane's own
//! reqwest client + cookie jar rather than an in-page fetch.

use std::collections::HashMap;

use serde_json::Value;

use crate::automation::response_extract::apply_response_extractions;
use crate::models::workflow::WorkflowStepConfig;
use crate::util::value_resolver::resolve_value_full;

use super::{HttpLaneError, HttpLaneExecutor, HttpResponse};

/// A resolved request ready to send.
pub struct BuiltRequest {
    pub method: String,
    pub url: String,
    pub headers: Vec<(String, String)>,
    pub body: Option<String>,
}

/// Resolve a request step's method/url/headers/body from its config + the run's credentials, form
/// data and prior extractions. Returns `None` for `url` only when the config has no URL at all.
pub fn build_request(
    config: &WorkflowStepConfig,
    credentials: &HashMap<String, String>,
    form_data: &HashMap<String, String>,
    extracted: &HashMap<String, Value>,
) -> Result<BuiltRequest, HttpLaneError> {
    let raw_url = config.url.as_deref().unwrap_or("");
    let url = resolve_value_full(raw_url, credentials, Some(form_data), None, Some(extracted));
    if url.trim().is_empty() {
        return Err(HttpLaneError::Fatal("api_call: no URL provided".into()));
    }
    let method = config
        .extra
        .get("method")
        .and_then(Value::as_str)
        .unwrap_or("GET")
        .to_uppercase();

    let allows_body = method != "GET" && method != "HEAD";
    let body = if !allows_body {
        None
    } else {
        config
            .extra
            .get("body")
            .filter(|b| !b.is_null())
            .or_else(|| config.extra.get("body_template").filter(|b| !b.is_null()))
            .map(|b| {
                let s = if b.is_string() {
                    b.as_str().unwrap_or("").to_string()
                } else {
                    serde_json::to_string(b).unwrap_or_default()
                };
                resolve_value_full(&s, credentials, Some(form_data), None, Some(extracted))
            })
            .filter(|s| !s.trim().is_empty() && s.trim() != "null")
    };

    let headers = resolve_headers(config, credentials, form_data, extracted);

    Ok(BuiltRequest { method, url, headers, body })
}

/// Resolve header values, dropping any that are empty, still hold an unresolved `{{placeholder}}`, or
/// carry a CR/LF (injection guard). Same rules as the browser lane's `api_call_raw`.
fn resolve_headers(
    config: &WorkflowStepConfig,
    credentials: &HashMap<String, String>,
    form_data: &HashMap<String, String>,
    extracted: &HashMap<String, Value>,
) -> Vec<(String, String)> {
    let mut out = Vec::new();
    if let Some(map) = config.extra.get("headers").and_then(Value::as_object) {
        for (k, v) in map {
            let val = resolve_value_full(
                v.as_str().unwrap_or(""),
                credentials,
                Some(form_data),
                None,
                Some(extracted),
            );
            if val.trim().is_empty() || val.contains("{{") {
                continue;
            }
            if val.contains('\r') || val.contains('\n') {
                tracing::warn!(header = %k, "http_lane: dropping header with CR/LF (injection guard)");
                continue;
            }
            out.push((k.clone(), val));
        }
    }
    out
}

/// Send a built request, retrying once with auth-class headers stripped on a 401/403 (a cookie-authed
/// API often ALSO 401s a stale bearer — the jar cookie is the live credential). Returns the response
/// (any status) so the caller/ladder can inspect it for staleness.
pub async fn run_request(
    exec: &mut HttpLaneExecutor,
    req: &BuiltRequest,
) -> Result<HttpResponse, HttpLaneError> {
    let resp = exec.request(&req.method, &req.url, &req.headers, req.body.clone()).await?;
    if resp.status == 401 || resp.status == 403 {
        let stripped: Vec<(String, String)> = req
            .headers
            .iter()
            .filter(|(k, _)| !is_auth_header(k))
            .cloned()
            .collect();
        if stripped.len() != req.headers.len() {
            let retry = exec.request(&req.method, &req.url, &stripped, req.body.clone()).await?;
            if retry.status < 400 {
                return Ok(retry);
            }
        }
    }
    Ok(resp)
}

fn is_auth_header(name: &str) -> bool {
    matches!(
        name.to_ascii_lowercase().as_str(),
        "authorization" | "cookie" | "x-api-key" | "x-auth-token" | "api-key"
    )
}

/// Python-truthiness for the api_call result (mirrors `step_eval::is_nonempty`).
fn is_nonempty(v: &Value) -> bool {
    match v {
        Value::Null => false,
        Value::Bool(b) => *b,
        Value::Number(n) => n.as_f64().map(|f| f != 0.0).unwrap_or(true),
        Value::String(s) => !s.trim().is_empty(),
        Value::Array(a) => !a.is_empty(),
        Value::Object(o) => !o.is_empty(),
    }
}

/// Build the extractions map for a successful api_call response: the `variable` entry (default
/// `api_result`) plus any `response_extractions`. Mirrors `step_eval::execute_api_call`.
pub fn extractions_from_response(config: &WorkflowStepConfig, resp: &HttpResponse) -> HashMap<String, Value> {
    let mut out = HashMap::new();
    let data = resp.json.clone().unwrap_or_else(|| Value::String(resp.body.clone()));
    for (name, value) in apply_response_extractions(config, &data) {
        out.insert(name, value);
    }
    let variable = config.extra.get("variable").and_then(Value::as_str).unwrap_or("api_result");
    let value = if is_nonempty(&data) {
        data
    } else {
        serde_json::json!({ "status": resp.status, "data": data })
    };
    out.insert(variable.to_string(), value);
    out
}
