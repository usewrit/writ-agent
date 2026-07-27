//! `execute_ai_task` — desktop mirror of `bridge/saas_bridge::handle_execute_ai_task` (Workstream A, §4).
//!
//! The cloud dispatches an AI task (`standard` / `intelligent` / `api_discovery` mode) to this machine.
//! The saas_bridge version drives the AI modes through the gateway WS via `BridgeAIClient` (CLOUD AI);
//! the desktop MUST instead drive them on the user's OWN local provider via [`LocalAiClient`] (A5),
//! injected behind the object-safe [`crate::ai::client::AiClient`] trait the mode drivers already
//! consume. Everything else (stealth context, navigation, per-mode config, result shaping) matches the
//! cloud handler so the `task_result` contract is identical.
//!
//! SECURITY (the never-trust-a-BYO-agent rule): AI runs on the user's vault-sealed BYO key; no
//! cross-tenant billing on-device (`tenant_id`/`purpose`/`api_key_id` are inert locally). Per-run
//! credentials decrypt via the DESKTOP channel-key seam ([`super::creds`]); `__proxy__` egress is
//! applied at the context level exactly like the cloud handler.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Instant;

use serde_json::{json, Value};

use super::super::super::vault::Vault;
use super::ai_client::LocalAiClient;
use super::creds;
use super::workflow::task_result_frame;
use crate::ai::client::AiClient;
use crate::browser::manager::BrowserManager;

/// Handle one `execute_ai_task` dispatch to completion and return the `task_result` frame.
///
/// Runs on the SAME warm browser the caller passes (never a second Chromium); the caller only routes
/// here when a warm browser exists. `db`/`vault` back the [`LocalAiClient`].
pub async fn handle(
    task_id: &str,
    msg: &Value,
    browser_mgr: &Arc<BrowserManager>,
    db: &sqlx::SqlitePool,
    vault: &Arc<Vault>,
) -> Value {
    let start = Instant::now();
    let config = &msg["config"];
    let url = config["url"].as_str().unwrap_or("about:blank");
    let goal = config["goal"].as_str().unwrap_or("");
    let mode = config["mode"].as_str().unwrap_or("intelligent");
    let max_steps = config["max_steps"].as_u64().unwrap_or(20) as usize;
    let max_actions = config["max_actions"].as_u64().unwrap_or(50) as usize;
    let use_vision = config["use_vision"].as_bool().unwrap_or(true);

    // Per-run credentials + BYO proxy override via the DESKTOP channel-key seam. Fail CLOSED on a
    // sealed blob we can't open (never run an AI task with half the login secrets).
    let (credentials, proxy) = match creds::resolve_credentials(config) {
        Ok(pair) => pair,
        Err(e) => {
            tracing::warn!(task_id, error = %e, "execute_ai_task: credential resolution failed");
            return task_result_frame(
                task_id,
                false,
                json!({}),
                Some("credential resolution failed (re-link may be required)".to_string()),
                start.elapsed().as_millis() as u64,
            );
        }
    };
    let proxy_override = proxy.map(|p| p.to_proxy_settings());

    // Merge config maps the AI modes consume.
    let mut form_data: HashMap<String, String> = config
        .get("form_data")
        .and_then(|v| serde_json::from_value(v.clone()).ok())
        .unwrap_or_default();
    let available_data: HashMap<String, String> = config
        .get("available_data")
        .and_then(|v| serde_json::from_value(v.clone()).ok())
        .unwrap_or_default();
    let secure_keys: Vec<String> = config
        .get("secure_keys")
        .and_then(|v| serde_json::from_value(v.clone()).ok())
        .unwrap_or_default();
    let user_context = config.get("user_context").and_then(|v| v.as_str()).map(String::from);
    // Credentials feed the modes through form_data (parity with the cloud handler) — a credential
    // never overwrites an explicit form_data value of the same key.
    for (k, v) in &credentials {
        form_data.entry(k.clone()).or_insert_with(|| v.clone());
    }

    // Honor an EXPLICIT per-session headless flag (relaunch the warm browser in that mode). Absent →
    // leave the warm browser as-is (don't force a globally-headed setup back to headless).
    if let Some(headless) = config.get("headless").and_then(|v| v.as_bool()) {
        if let Err(e) = browser_mgr.ensure_warm_browser_with(headless).await {
            return task_result_frame(
                task_id,
                false,
                json!({}),
                Some(format!("Browser launch failed: {e}")),
                start.elapsed().as_millis() as u64,
            );
        }
    }

    // Stealth context (random fingerprint per context, parity with the cloud handler), egressing
    // through the per-run BYO proxy when present.
    let (context, page) = match browser_mgr.create_stealth_context_with_proxy(proxy_override).await {
        Ok(cp) => cp,
        Err(e) => {
            return task_result_frame(
                task_id,
                false,
                json!({}),
                Some(format!("Browser context failed: {e}")),
                start.elapsed().as_millis() as u64,
            );
        }
    };

    // SECURITY: vet the navigation URL before we goto it (rejects file:/internal/metadata hosts).
    if !crate::security::url_guard::is_navigation_url_safe_async(url).await {
        let _ = context.close().await;
        return task_result_frame(
            task_id,
            false,
            json!({}),
            Some(format!("Refused unsafe URL: {url}")),
            start.elapsed().as_millis() as u64,
        );
    }

    if let Err(e) = crate::browser::navigation::goto(
        &page,
        url,
        "domcontentloaded",
        std::time::Duration::from_secs(30),
    )
    .await
    {
        let _ = context.close().await;
        return task_result_frame(
            task_id,
            false,
            json!({}),
            Some(format!("Navigation failed: {e}")),
            start.elapsed().as_millis() as u64,
        );
    }

    // Drive the AI modes on the LOCAL provider via the AiClient trait (no cloud round-trip). When no
    // provider is configured, LocalAiClient returns None → the mode reports a graceful failure.
    let ai_client = LocalAiClient::new(db.clone(), vault.clone());
    let ai: &dyn AiClient = &ai_client;

    // tenant_id is server-side truth; locally there is no tenant, so pass empty (the modes only use it
    // for cloud billing metadata, which LocalAiClient ignores).
    let result_data: Value = run_mode(
        mode,
        &page,
        &context,
        goal,
        user_context,
        available_data,
        form_data,
        secure_keys,
        max_steps,
        max_actions,
        use_vision,
        ai,
    )
    .await;

    let success = result_data.get("success").and_then(|v| v.as_bool()).unwrap_or(false);
    let error = result_data.get("error").and_then(|v| v.as_str()).map(String::from);

    let _ = context.close().await;

    // AI-task result shape: the full mode `result_data` rides under `result_data`, mirroring the cloud
    // handler (the backend reads `steps` / `api_functions` from there).
    json!({
        "type": "task_result",
        "task_id": task_id,
        "success": success,
        "result_data": result_data,
        "error": error,
        "duration_ms": start.elapsed().as_millis() as u64,
    })
}

/// Run the requested AI mode and shape its result into the `result_data` object (parity with the cloud
/// handler). An unknown mode is a graceful failure, not a panic.
#[allow(clippy::too_many_arguments)]
async fn run_mode(
    mode: &str,
    page: &playwright_rs::Page,
    context: &playwright_rs::BrowserContext,
    goal: &str,
    user_context: Option<String>,
    available_data: HashMap<String, String>,
    form_data: HashMap<String, String>,
    secure_keys: Vec<String>,
    max_steps: usize,
    max_actions: usize,
    use_vision: bool,
    ai: &dyn AiClient,
) -> Value {
    match mode {
        "standard" => {
            let cfg = crate::ai::standard_mode::StandardModeConfig {
                goal: goal.to_string(),
                available_data,
                fill_data: form_data,
                max_steps,
                use_vision,
                tenant_id: String::new(),
                secure_keys: secure_keys.clone(),
            };
            match crate::ai::standard_mode::ai_generate_workflow(page, cfg, Some(ai)).await {
                Ok(r) => json!({
                    "success": r.success,
                    "steps": r.steps,
                    "raw_replay": r.raw_replay,
                    "endpoint": r.endpoint,
                    "error": r.error,
                }),
                Err(e) => json!({ "success": false, "error": e.to_string() }),
            }
        }
        "intelligent" => {
            let cfg = crate::ai::intelligent_mode::IntelligentModeConfig {
                goal: goal.to_string(),
                user_context,
                available_data,
                fill_data: form_data,
                max_actions,
                secure_keys,
                tenant_id: String::new(),
            };
            match crate::ai::intelligent_mode::ai_generate_workflow_intelligent(page, cfg, Some(ai))
                .await
            {
                Ok(r) => json!({
                    "success": r.success,
                    "steps": r.steps,
                    "raw_replay": r.raw_replay,
                    "endpoint": r.endpoint,
                    "error": r.error,
                }),
                Err(e) => json!({ "success": false, "error": e.to_string() }),
            }
        }
        "api_discovery" => {
            let cfg = crate::ai::api_discovery_mode::ApiDiscoveryConfig {
                goal: goal.to_string(),
                user_context,
                available_data,
                fill_data: form_data,
                max_actions,
                tenant_id: String::new(),
                secure_keys: secure_keys.clone(),
            };
            match crate::ai::api_discovery_mode::ai_discover_api(page, context, cfg, Some(ai)).await {
                Ok(r) => json!({
                    "success": r.success,
                    "api_functions": r.api_functions,
                    "steps": r.steps,
                    "error": r.error,
                    "server_rendered_pages": r.server_rendered_pages,
                }),
                Err(e) => json!({ "success": false, "error": e.to_string() }),
            }
        }
        other => {
            tracing::warn!(mode = other, "execute_ai_task: unknown AI mode");
            json!({ "success": false, "error": format!("Unknown AI mode: {other}") })
        }
    }
}
