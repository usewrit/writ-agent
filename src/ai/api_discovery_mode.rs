use std::collections::HashMap;
use std::sync::Arc;

use base64::Engine;
use playwright_rs::Page;
use tokio::sync::Mutex;

use crate::automation::network_capture::NetworkCapture;
use crate::browser::page_query;

use super::action_executor::{self, DOM_FIELDS_WITH_COORDS_JS};
use super::client::AiClient;
use playwright_rs::server::channel_owner::ChannelOwner;

pub struct ApiDiscoveryConfig {
    pub goal: String,
    pub user_context: Option<String>,
    pub available_data: HashMap<String, String>,
    pub fill_data: HashMap<String, String>,
    pub max_actions: usize,
    pub tenant_id: String,
    /// Keys in `available_data` whose values are live credentials (passwords,
    /// tokens). Their values are masked in the prompt and scrubbed from any
    /// captured request/response bodies before those bodies reach the model.
    pub secure_keys: Vec<String>,
}

/// 1:1 port of Python ai_discover_api (recorder.py lines 5688-5935).
///
/// API Discovery mode — AI navigates the site while capturing all XHR/Fetch
/// network traffic. Outputs api_functions map for the ApiCallExecutor.
pub async fn ai_discover_api(
    page: &Page,
    context: &playwright_rs::BrowserContext,
    config: ApiDiscoveryConfig,
    ai_client: Option<&dyn AiClient>,
) -> Result<ApiDiscoveryResult, anyhow::Error> {
    tracing::info!(
        goal = %config.goal,
        max_actions = config.max_actions,
        "Starting API discovery"
    );

    let ai = match ai_client {
        Some(c) => c,
        None => {
            return Ok(ApiDiscoveryResult {
                success: false,
                api_functions: HashMap::new(),
                steps: Vec::new(),
                error: Some("No AI client provided".to_string()),
                server_rendered_pages: Vec::new(),
            });
        }
    };

    // Attach network capture via shared state (Python line 5722-5724)
    let net_capture = Arc::new(Mutex::new(NetworkCapture::new()));
    attach_network_capture(context, net_capture.clone()).await;
    tracing::info!(goal = %config.goal, "[API Discovery] Network capture attached");

    let mut api_functions: HashMap<String, serde_json::Value> = HashMap::new();
    let mut action_history: Vec<serde_json::Value> = Vec::new();
    let mut last_step_marker: usize = 0;
    let mut steps: Vec<serde_json::Value> = Vec::new();
    let mut action_num: usize = 0;
    let mut server_rendered: Vec<String> = Vec::new();
    let mut prev_url = String::new();

    for n in 1..=config.max_actions {
        action_num = n;

        // 1. Capture page state (Python line 5734)
        let screenshot_b64 = match page_query::screenshot_jpeg(page, 70).await {
            Ok(bytes) => Some(base64::engine::general_purpose::STANDARD.encode(&bytes)),
            Err(_) => None,
        };

        let dom_state_raw: serde_json::Value =
            page_query::evaluate(page, DOM_FIELDS_WITH_COORDS_JS).await.unwrap_or(serde_json::json!({}));
        let fields_text = dom_state_raw.get("fieldsText").and_then(|v| v.as_str()).unwrap_or("");
        let current_url = page.url();

        // 2. Get network calls since last step (Python line 5746)
        let (mut network_text, calls_since_empty) = {
            let cap = net_capture.lock().await;
            let calls = cap.get_calls_since(last_step_marker);
            (cap.format_for_prompt(&calls, &config.fill_data), calls.is_empty())
        };
        // Captured request/response bodies can echo back a {{secret}}-resolved
        // credential (e.g. a login POST body). Scrub the live secret values
        // before the text ever enters the AI prompt.
        scrub_secret_values(&mut network_text, &config);

        // 2b. Server-rendered detection: the previous action navigated to a new
        // page but triggered no XHR/fetch calls → the data is baked into the HTML
        // and there is no callable API to extract here. Flag it for the user.
        if !prev_url.is_empty() && current_url != prev_url && calls_since_empty
            && !server_rendered.iter().any(|u| u == &current_url) {
                tracing::info!(url = %current_url, "[API Discovery] Page appears server-rendered — no API calls to capture");
                server_rendered.push(current_url.clone());
            }
        prev_url = current_url.clone();

        // 3. Build discovered-API summary (Python line 5750)
        let _discovered: Vec<String> = api_functions.keys().cloned().collect();

        // 4. Build prompt (Python line 5764 — detailed api_steps schema)
        let prompt = build_discovery_prompt(
            &config.goal,
            config.user_context.as_deref(),
            &current_url,
            fields_text,
            &config.available_data,
            &network_text,
            &api_functions,
            &action_history,
            &config.secure_keys,
        );

        // 5. Call AI with vision (Python line 5818)
        let response = match &screenshot_b64 {
            Some(b64) => ai.complete_vision(b64, &prompt, &config.tenant_id, 2000, "api_discovery").await,
            None => ai.complete_json(
                "You are an API discovery agent.",
                &prompt,
                &config.tenant_id,
                2000,
                "api_discovery",
            ).await,
        };

        let result = match response {
            Some(v) => v,
            None => {
                tracing::warn!("[API Discovery] AI returned no response");
                action_history.push(serde_json::json!({"action": "blocked", "reason": "AI no response"}));
                continue;
            }
        };

        let action_type = result.get("action").and_then(|v| v.as_str()).unwrap_or("blocked").to_string();
        let reason = result.get("reason").and_then(|v| v.as_str()).unwrap_or("").to_string();
        tracing::info!(step = action_num, action = %action_type, reason = %reason, "[API Discovery] Step");

        // 6. Accumulate discovered API steps (Python line 5865)
        if let Some(api_steps) = result.get("api_steps").and_then(|v| v.as_array()) {
            for api_step in api_steps {
                let func_name = api_step.get("function_name").and_then(|v| v.as_str());
                if let Some(name) = func_name {
                    if !api_functions.contains_key(name) {
                        let order = api_step.get("order")
                            .and_then(|v| v.as_u64())
                            .unwrap_or(api_functions.len() as u64);
                        let entry = serde_json::json!({
                            "label": api_step.get("label").and_then(|v| v.as_str()).unwrap_or(name),
                            "is_auth": api_step.get("is_auth").and_then(|v| v.as_bool()).unwrap_or(false),
                            "order": order,
                            "request": api_step.get("request").cloned().unwrap_or(serde_json::json!({})),
                            "response_extractions": api_step.get("response_extractions").cloned().unwrap_or(serde_json::json!({})),
                            "parameters": api_step.get("parameters").cloned().unwrap_or(serde_json::json!([])),
                            "secrets": api_step.get("secrets").cloned().unwrap_or(serde_json::json!([])),
                        });
                        let method = entry["request"].get("method").and_then(|v| v.as_str()).unwrap_or("?");
                        let url = entry["request"].get("url").and_then(|v| v.as_str()).unwrap_or("?");
                        tracing::info!(func = name, method, url, "[API Discovery] Found endpoint");
                        api_functions.insert(name.to_string(), entry);
                    }
                }
            }
        }

        // 7. Handle completion / blocked (Python line 5891)
        if action_type == "complete" {
            break;
        }
        if action_type == "blocked" {
            action_history.push(serde_json::json!({"action": "blocked", "reason": reason}));
            continue;
        }

        // 8. Execute navigation action (Python line 5897)
        action_history.push(serde_json::json!({"action": action_type, "reason": reason}));
        let exec_result = action_executor::execute_and_verify_action(
            page, &result, &config.fill_data, &dom_state_raw,
        ).await;

        steps.push(serde_json::json!({
            "action": action_type,
            "success": exec_result.success,
            "step": action_num,
        }));

        if !exec_result.success {
            if let Some(last) = action_history.last_mut() {
                if let Some(obj) = last.as_object_mut() {
                    obj.insert("error".to_string(), serde_json::json!(exec_result.error));
                }
            }
        }

        // Mark network capture step (Python line 5908)
        {
            let mut cap = net_capture.lock().await;
            cap.mark_step(&format!("{}: {}", action_type, reason.chars().take(50).collect::<String>()));
            last_step_marker = cap.current_step();
        }

        tokio::time::sleep(std::time::Duration::from_secs(1)).await;
    }

    // 9. Final optimization pass (Python line 5913)
    if !api_functions.is_empty() {
        if let Some(optimized) = optimize_api_functions(ai, &api_functions, &config.goal, &config.tenant_id).await {
            if let Some(obj) = optimized.as_object() {
                if !obj.is_empty() {
                    api_functions = obj.iter().map(|(k, v)| (k.clone(), v.clone())).collect();
                }
            }
        }
    }

    let count = api_functions.len();
    tracing::info!(endpoints = count, actions = action_num, "[API Discovery] Done");

    Ok(ApiDiscoveryResult {
        success: count > 0,
        api_functions,
        steps,
        error: if count > 0 { None } else { Some("No API endpoints discovered".to_string()) },
        server_rendered_pages: server_rendered,
    })
}

/// Replace any live secret value in the captured-network text with a redaction
/// marker. Passive capture records raw request/response bodies, so a resolved
/// `{{secret:password}}` can appear verbatim in a login POST body; this removes
/// it before the text reaches the AI prompt. Secret values are drawn from the
/// `secure_keys`-flagged entries of both `available_data` and `fill_data`.
fn scrub_secret_values(text: &mut String, config: &ApiDiscoveryConfig) {
    if config.secure_keys.is_empty() || text.is_empty() {
        return;
    }
    for key in &config.secure_keys {
        for source in [&config.available_data, &config.fill_data] {
            if let Some(val) = source.get(key) {
                // Skip trivially short values — replacing them would corrupt
                // unrelated text without protecting a meaningful secret.
                if val.len() >= 3 && text.contains(val.as_str()) {
                    *text = text.replace(val.as_str(), "(secure credential)");
                }
            }
        }
    }
}

/// Build the detailed API discovery prompt (Python line 5764).
#[allow(clippy::too_many_arguments)]
fn build_discovery_prompt(
    goal: &str,
    user_context: Option<&str>,
    current_url: &str,
    fields_text: &str,
    available_data: &HashMap<String, String>,
    network_text: &str,
    api_functions: &HashMap<String, serde_json::Value>,
    action_history: &[serde_json::Value],
    secure_keys: &[String],
) -> String {
    let mut p = String::with_capacity(4096);
    p.push_str("You are an API discovery agent. Navigate this website to trigger and identify REST API endpoints.\n\n");
    p.push_str(&format!("GOAL: {}\n", goal));
    if let Some(ctx) = user_context {
        if !ctx.is_empty() {
            p.push_str(&format!("USER CONTEXT: {}\n", ctx));
        }
    }
    p.push_str(&format!("CURRENT URL: {}\n\n", current_url));
    p.push_str(&format!("PAGE FIELDS:\n{}\n\n", fields_text));

    if !available_data.is_empty() {
        p.push_str("AVAILABLE DATA (for login/forms):\n");
        for (k, v) in available_data {
            // Mask credential values — the model references them as {{secret:key}}.
            if secure_keys.contains(k) {
                p.push_str(&format!("  {}: (secure credential)\n", k));
            } else {
                p.push_str(&format!("  {}: {}\n", k, v));
            }
        }
        p.push('\n');
    }

    p.push_str(&format!("NETWORK CALLS SINCE LAST ACTION:\n{}\n\n", network_text));

    if !api_functions.is_empty() {
        p.push_str("ALREADY DISCOVERED API FUNCTIONS:\n");
        for (fname, fdef) in api_functions {
            let req = fdef.get("request");
            let method = req.and_then(|r| r.get("method")).and_then(|v| v.as_str()).unwrap_or("?");
            let url = req.and_then(|r| r.get("url")).and_then(|v| v.as_str()).unwrap_or("?");
            p.push_str(&format!("  - {}: {} {}\n", fname, method, url));
        }
    }

    p.push_str("ACTION HISTORY:\n");
    if action_history.is_empty() {
        p.push_str("  (first action)\n");
    } else {
        let start = action_history.len().saturating_sub(10);
        for (i, h) in action_history[start..].iter().enumerate() {
            let action = h.get("action").and_then(|v| v.as_str()).unwrap_or("?");
            let reason = h.get("reason").and_then(|v| v.as_str()).unwrap_or("");
            p.push_str(&format!("  {}. {}: {}\n", i + 1, action, reason));
        }
    }

    p.push_str(r#"
INSTRUCTIONS:
1. Navigate the site to trigger API calls (click buttons, open pages, submit forms)
2. Analyze captured network traffic — identify real API endpoints (skip analytics, tracking, assets)
3. For each important API call, output it in api_steps with:
   - Parameterized templates: {{key}} for form data, {{secret:key}} for credentials, {{extracted:key}} for values from prior API responses
   - response_extractions using JSONPath ($.data, $.token, $.items[0].id)
   - is_auth: true for login/auth calls
   - Correct Content-Type in headers
4. Use action "complete" when you have discovered all endpoints needed for the goal

Return ONLY valid JSON:
{
  "action": "click|fill|scroll|navigate|wait|complete",
  "field_index": 0,
  "value": "",
  "url": "",
  "reason": "why this helps discover APIs",
  "api_steps": [
    {
      "function_name": "snake_case_name",
      "label": "Human readable label",
      "is_auth": false,
      "order": 0,
      "request": {
        "method": "POST",
        "url": "https://example.com/api/endpoint",
        "headers": {"Content-Type": "application/json"},
        "body_template": {"key": "{{value}}"}
      },
      "response_extractions": {"token": "$.data.token"},
      "parameters": ["value"],
      "secrets": []
    }
  ]
}"#);

    p
}

/// Final optimization pass (Python _ai_optimize_api_functions line 5937).
async fn optimize_api_functions(
    ai: &dyn AiClient,
    api_functions: &HashMap<String, serde_json::Value>,
    goal: &str,
    tenant_id: &str,
) -> Option<serde_json::Value> {
    let functions_json = serde_json::to_string_pretty(api_functions).unwrap_or_default();
    let prompt = format!(
        r#"Review and optimize these discovered API functions.

GOAL: {}

FUNCTIONS:
{}

OPTIMIZE:
1. Remove duplicate/redundant calls
2. Set correct "order" values (0 = first)
3. Mark auth calls with "is_auth": true
4. Chain extractions: login token -> {{{{extracted:token}}}} in subsequent headers
5. Ensure response_extractions use valid JSONPath
6. Normalize function names to snake_case

Return ONLY the optimized api_functions JSON dict."#,
        goal, functions_json
    );

    match ai.complete_json(
        "You are an API workflow optimizer.",
        &prompt,
        tenant_id,
        4000,
        "api_discovery",
    ).await {
        Some(v) if v.is_object() && !v.as_object().unwrap().is_empty() => Some(v),
        _ => None,
    }
}

/// Attach passive network capture to the context's request/response events.
/// Mirrors Python NetworkCapture.attach (recorder.py line 437).
pub(crate) async fn attach_network_capture(
    context: &playwright_rs::BrowserContext,
    capture: Arc<Mutex<NetworkCapture>>,
) {
    let cap_req = capture.clone();
    let _ = context.on_request(move |request: playwright_rs::Request| {
        let cap = cap_req.clone();
        async move {
            // Key the pending map by the request's stable GUID — the Rust
            // equivalent of Python's `id(request)`. Keying by URL collides
            // when the same endpoint is hit more than once (polling/retries).
            let request_id = request.guid().to_string();
            let method = request.method().to_string();
            let url = request.url().to_string();
            let resource_type = request.resource_type().to_string();
            let headers = request.headers();
            let body = request.post_data();
            let mut c = cap.lock().await;
            c.on_request(&request_id, &method, &url, &resource_type, headers, body);
            Ok(())
        }
    }).await;

    let cap_resp = capture.clone();
    let _ = context.on_response(move |response: playwright_rs::protocol::ResponseObject| {
        let cap = cap_resp.clone();
        async move {
            // A Response's parent ChannelOwner is its originating Request, so
            // `parent().guid()` matches the key inserted in on_request — the
            // equivalent of Python's `id(response.request)`.
            let request_id = match response.parent() {
                Some(req) => req.guid().to_string(),
                None => return Ok(()),
            };

            // Skip early if this response isn't for a captured (XHR/fetch/doc-POST)
            // request — avoids an RPC round-trip and body download for every asset.
            if !cap.lock().await.has_pending(&request_id) {
                return Ok(());
            }

            let status = response.status();
            let headers: HashMap<String, String> = match response.raw_headers().await {
                Ok(entries) => entries.into_iter().map(|e| (e.name, e.value)).collect(),
                Err(_) => HashMap::new(),
            };

            // Only download the body for text-like content types (mirrors Python,
            // which checks Content-Type before calling response.text()).
            let content_type = headers
                .iter()
                .find(|(k, _)| k.eq_ignore_ascii_case("content-type"))
                .map(|(_, v)| v.to_lowercase());
            let want_body = content_type
                .as_deref()
                .map(|ct| ["json", "text", "xml", "html", "form"].iter().any(|t| ct.contains(t)))
                .unwrap_or(false);
            let body: Option<String> = if want_body {
                match response.body().await {
                    Ok(bytes) => String::from_utf8(bytes).ok(),
                    Err(_) => None,
                }
            } else {
                None
            };

            let mut c = cap.lock().await;
            c.on_response(&request_id, status, headers, body);
            Ok(())
        }
    }).await;
}

pub struct ApiDiscoveryResult {
    pub success: bool,
    pub api_functions: HashMap<String, serde_json::Value>,
    pub steps: Vec<serde_json::Value>,
    pub error: Option<String>,
    /// Pages that loaded but produced no XHR/fetch API calls — i.e. the data is
    /// server-rendered into the HTML, so there is no callable API to extract.
    /// Surfaced to the user as "can't capture an API on this page".
    pub server_rendered_pages: Vec<String>,
}
