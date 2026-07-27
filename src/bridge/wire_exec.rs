//! Shared wire-dispatched `execute_workflow` executor.
//!
//! The full-definition workflow run that arrives OVER the WS as an `execute_workflow` frame —
//! steps, form data, sealed credentials, saved session state, files and proxy all in the message
//! `config` — executed against a warm [`BrowserManager`] and answered with the reply-awaited
//! `task_result` frame (payload under `result_data`, `extracted_data` inside it, plus the
//! harvested `auth_session`).
//!
//! Extracted VERBATIM from `saas_bridge::handle_execute_workflow` so the cloud `writ-agent`
//! (`--features cloud`) and the OSS self-host fleet worker (`--features local,fleet`) run the SAME
//! executor; the two transport-specific bits are parameterized:
//!   * `send` — how a frame reaches the gateway (the saas bridge wraps its `BridgeOutgoing`
//!     channel; the fleet bridge wraps its plain `Message::Text` channel).
//!   * `channel_key` — where the per-agent Fernet key that opens `credentials_encrypted` comes
//!     from (cloud: the device-flow credentials file; fleet: the coordinator's `auth_ok` frame,
//!     cached in the encrypted config kv).
//!
//! Everything this module drives (`automation::step_executor`, the HTTP lane, session-state
//! restore/extract, the SSRF url guard, `RunFiles`) is feature-ungated, so both builds compile it.

use std::collections::HashMap;
use std::sync::Arc;

use crate::browser::manager::BrowserManager;
use crate::models::workflow::WorkflowStepConfig;

/// How the executor emits frames back over whichever bridge dispatched the task.
pub(crate) type SendJson<'a> = &'a (dyn Fn(serde_json::Value) + Send + Sync);

/// Refuse a plaintext endpoint outside local dev (private copy — the bridge originals are gated
/// behind their own features). Accept `wss://`/`https://`, a loopback host, or an explicit opt-in.
fn require_secure_url(url: &str, allow_insecure: bool, what: &str) -> Result<(), anyhow::Error> {
    let lower = url.trim().to_lowercase();
    if lower.starts_with("wss://") || lower.starts_with("https://") {
        return Ok(());
    }
    let after = lower.split_once("://").map(|x| x.1).unwrap_or(lower.as_str());
    let authority = after.split(['/', '?', '#']).next().unwrap_or("");
    let hostport = authority.rsplit('@').next().unwrap_or(authority);
    let host = if let Some(rest) = hostport.strip_prefix('[') {
        rest.split(']').next().unwrap_or(rest)
    } else {
        hostport.split_once(':').map(|(h, _)| h).unwrap_or(hostport)
    };
    let is_local = host == "localhost"
        || host.parse::<std::net::IpAddr>().map(|ip| ip.is_loopback()).unwrap_or(false);
    if allow_insecure || is_local {
        return Ok(());
    }
    anyhow::bail!("Refusing insecure {what} URL '{url}': use a wss://https:// endpoint")
}

// ---------------------------------------------------------------------------
// Credential / proxy resolution (channel key supplied by the calling bridge)
// ---------------------------------------------------------------------------

/// Decrypt the run credentials blob into a JSON object WITHOUT collapsing values to strings, so
/// the reserved `__proxy__` OBJECT survives. Falls back to the pre-decrypted JSON forms. Returns
/// `None` when there is nothing to decrypt, no channel key, or decrypt/parse fails (fail toward
/// direct egress / no credentials).
fn decrypt_credentials_object(
    config: &serde_json::Value,
    channel_key: Option<&str>,
) -> Option<serde_json::Map<String, serde_json::Value>> {
    // Preferred: encrypted blob decrypted with the per-agent channel key.
    if let Some(encrypted) = config.get("credentials_encrypted").and_then(|v| v.as_str()) {
        if !encrypted.is_empty() {
            let key = channel_key.filter(|k| !k.is_empty())?;
            let fernet = fernet::Fernet::new(key)?;
            let plaintext = fernet.decrypt(encrypted).ok()?;
            let json_str = String::from_utf8(plaintext).ok()?;
            if let Ok(serde_json::Value::Object(map)) = serde_json::from_str::<serde_json::Value>(&json_str) {
                return Some(map);
            }
            return None;
        }
    }

    // Fallback: pre-decrypted credentials sent as JSON (string or object).
    if let Some(creds_val) = config.get("credentials_decrypted") {
        if let Some(s) = creds_val.as_str() {
            if let Ok(serde_json::Value::Object(map)) = serde_json::from_str::<serde_json::Value>(s) {
                return Some(map);
            }
        } else if let serde_json::Value::Object(map) = creds_val {
            return Some(map.clone());
        }
    }

    None
}

/// Resolve the run's `{name: value}` credential map from the message config, dropping the
/// reserved non-secret `__proxy__` object. Mirrors `saas_bridge::resolve_credentials`, with the
/// channel key passed in by the calling bridge instead of read from the cloud credentials file.
pub(crate) fn resolve_credentials(
    config: &serde_json::Value,
    channel_key: Option<&str>,
) -> HashMap<String, String> {
    // Preferred path: decrypt to a JSON object so a non-string value (the reserved `__proxy__`
    // object) does NOT make the whole `HashMap<String,String>` parse fail and silently drop
    // every credential. Keep only string-valued entries.
    if let Some(map) = decrypt_credentials_object(config, channel_key) {
        let creds: HashMap<String, String> = map
            .into_iter()
            .filter(|(k, _)| k != "__proxy__")
            .filter_map(|(k, v)| v.as_str().map(|s| (k, s.to_string())))
            .collect();
        if !creds.is_empty() {
            return creds;
        }
    }

    // Fall back to the legacy string-map decrypt (covers the all-strings case if the object path
    // returned nothing).
    if let (Some(encrypted), Some(key)) = (
        config.get("credentials_encrypted").and_then(|v| v.as_str()),
        channel_key.filter(|k| !k.is_empty()),
    ) {
        if !encrypted.is_empty() {
            if let Ok(mut decrypted) = crate::security::crypto::decrypt_credentials(encrypted, key) {
                if !decrypted.is_empty() {
                    decrypted.remove("__proxy__");
                    return decrypted;
                }
            }
        }
    }

    // Fall back to pre-decrypted credentials (sent as JSON)
    if let Some(creds_val) = config.get("credentials_decrypted") {
        if let Some(s) = creds_val.as_str() {
            if let Ok(mut parsed) = serde_json::from_str::<HashMap<String, String>>(s) {
                parsed.remove("__proxy__");
                return parsed;
            }
        } else if let Ok(mut parsed) = serde_json::from_value::<HashMap<String, String>>(creds_val.clone()) {
            parsed.remove("__proxy__");
            return parsed;
        }
    }

    HashMap::new()
}

/// Extract the per-run BYO persona proxy carried as the reserved `__proxy__` key inside the run
/// credentials, and map it to `ProxySettings`. Returns None when absent/invalid → env proxy /
/// direct egress. Mirrors `saas_bridge::extract_proxy_override`.
pub(crate) fn extract_proxy_override(
    config: &serde_json::Value,
    channel_key: Option<&str>,
) -> Option<playwright_rs::protocol::ProxySettings> {
    let creds = decrypt_credentials_object(config, channel_key)?;
    let proxy = creds.get("__proxy__")?.as_object()?;

    // Validate: a usable proxy MUST have a non-empty `server`. When in doubt, None.
    let server = proxy.get("server").and_then(|v| v.as_str()).filter(|s| !s.is_empty())?;

    let str_field = |k: &str| {
        proxy
            .get(k)
            .and_then(|v| v.as_str())
            .filter(|s| !s.is_empty())
            .map(|s| s.to_string())
    };

    Some(playwright_rs::protocol::ProxySettings {
        server: server.to_string(),
        bypass: str_field("bypass"),
        username: str_field("username"),
        password: str_field("password"),
    })
}

// ---------------------------------------------------------------------------
// twofa step (persona OTP minted by the coordinator over HTTPS)
// ---------------------------------------------------------------------------

/// Serve a recorded `twofa` step: poll the coordinator's persona OTP-mint endpoint (the message
/// config carries `persona.{persona_id, otp_token, coordinator_url}`), then enter the code (or
/// follow the magic link) on the live page. Transport-neutral — works identically for the cloud
/// backend and a self-host coordinator that implements the same `/api/personas/:id/otp` mint.
pub(crate) async fn handle_twofa_step(
    page: &playwright_rs::Page,
    raw_step: &serde_json::Value,
    config: &serde_json::Value,
    _timeout_ms: u64,
) -> Result<(), String> {
    use std::time::{Duration, SystemTime, UNIX_EPOCH};

    let persona = config.get("persona").filter(|v| !v.is_null());
    let method = raw_step.get("method").and_then(|v| v.as_str())
        .or_else(|| raw_step.get("config").and_then(|c| c.get("method")).and_then(|v| v.as_str()))
        .or_else(|| persona.and_then(|p| p.get("twofa_method")).and_then(|v| v.as_str()))
        .unwrap_or("none");
    if method == "none" {
        tracing::info!("twofa step: no 2FA method configured — skipping");
        return Ok(());
    }
    let persona = persona.ok_or_else(||
        "TWOFA_NOT_AVAILABLE: 2FA requires a cloud persona context".to_string())?;
    let persona_id = persona.get("persona_id").and_then(|v| v.as_i64())
        .ok_or_else(|| "TWOFA_NOT_AVAILABLE: missing persona_id".to_string())?;
    let otp_token = persona.get("otp_token").and_then(|v| v.as_str())
        .ok_or_else(|| "TWOFA_NOT_AVAILABLE: missing otp_token".to_string())?;
    let coordinator_url = persona.get("coordinator_url").and_then(|v| v.as_str())
        .ok_or_else(|| "TWOFA_NOT_AVAILABLE: missing coordinator_url".to_string())?;
    // SECURITY: coordinator_url is config-supplied and we are about to POST the
    // otp_token SECRET to it. Vet it the same way the /connect endpoint is vetted
    // (require https, or loopback for local dev) so a plaintext/attacker URL can't
    // exfiltrate the token in cleartext or point it at an internal host. No
    // allow_insecure opt-in here: the token is a live 2FA credential.
    require_secure_url(coordinator_url, false, "coordinator")
        .map_err(|e| format!("TWOFA_NOT_AVAILABLE: {e}"))?;

    let since_ts = SystemTime::now().duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs_f64()).unwrap_or(0.0);
    let url = format!("{}/api/personas/{}/otp", coordinator_url.trim_end_matches('/'), persona_id);
    // TIMEOUTS ARE NOT OPTIONAL HERE. `reqwest::Client::new()` has NO request timeout, and the 60s
    // deadline below is only evaluated BETWEEN iterations — so a single `send()` against a
    // black-holed coordinator (dropped packets, a load balancer that accepts and never answers)
    // parks this loop forever. The step never fails, the run never finalizes, and its governor permit
    // is never released. Matches what `step_download.rs` already does for its own HTTP calls.
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(10))
        .connect_timeout(Duration::from_secs(5))
        .build()
        // A builder failure means no TLS backend; fall back rather than fail the step outright, so
        // behavior is no worse than before this bound existed.
        .unwrap_or_else(|e| {
            tracing::warn!(error = %e, "could not build a timeout-bounded OTP client — using the default");
            reqwest::Client::new()
        });

    let deadline = SystemTime::now() + Duration::from_secs(60);
    let mut otp_kind: Option<String> = None;
    let mut otp_value: Option<String> = None;
    let mut last_err = String::from("timeout");
    while SystemTime::now() < deadline {
        match client.post(&url)
            .json(&serde_json::json!({ "token": otp_token, "since_ts": since_ts }))
            .send().await
        {
            Ok(resp) => {
                let status = resp.status();
                if status.is_success() {
                    if let Ok(body) = resp.json::<serde_json::Value>().await {
                        otp_kind = body.get("type").and_then(|v| v.as_str()).map(|s| s.to_string());
                        otp_value = body.get("value").and_then(|v| v.as_str()).map(|s| s.to_string());
                        if otp_value.is_some() {
                            break;
                        }
                    }
                } else if matches!(status.as_u16(), 401 | 403 | 404) {
                    last_err = format!("HTTP {}", status.as_u16());
                    break;
                } else {
                    last_err = format!("HTTP {}", status.as_u16());
                }
            }
            Err(e) => {
                last_err = e.to_string();
            }
        }
        tokio::time::sleep(Duration::from_secs(3)).await;
    }

    let value = otp_value.ok_or_else(||
        format!("TWOFA_NOT_AVAILABLE: could not obtain OTP ({})", last_err))?;

    if otp_kind.as_deref() == Some("magic_link") {
        // SECURITY: the magic-link URL comes from a mailbox read SERVER-SIDE, but
        // it is still attacker-influenceable content. Vet it (fail-closed) before
        // we navigate, so it can't be used to reach file:/data:/internal hosts or
        // cloud metadata.
        if !crate::security::url_guard::is_navigation_url_safe_async(&value).await {
            return Err("twofa magic-link blocked: unsafe URL".to_string());
        }
        crate::browser::navigation::goto(page, &value, "domcontentloaded", Duration::from_millis(30_000))
            .await
            .map_err(|e| format!("twofa magic-link navigation failed: {}", e))?;
        tracing::info!("twofa step: followed magic-link");
        return Ok(());
    }

    // Enter the code via the shared robust OTP-entry JS (single input / N segmented
    // single-char boxes / contenteditable / paste — across the document, modals,
    // and same-origin iframes). Falls back to fill/keyboard_type. Never log it.
    let mut selector = raw_step.get("selector").and_then(|v| v.as_str())
        .or_else(|| raw_step.get("config").and_then(|c| c.get("selector")).and_then(|v| v.as_str()))
        .map(|s| s.to_string())
        .filter(|s| !s.is_empty());
    let mut detected_submit: Option<String> = None;
    if selector.is_none() {
        // No recorded selector — detect the OTP field (modal / step-2 / redirect).
        if let Ok(det) = crate::browser::page_query::evaluate::<serde_json::Value>(
            page, &crate::bridge::otp_entry::detect_invocation()).await
        {
            selector = det.get("selector").and_then(|v| v.as_str())
                .filter(|s| !s.is_empty()).map(|s| s.to_string());
            detected_submit = det.get("submit_selector").and_then(|v| v.as_str()).map(|s| s.to_string());
        }
    }
    let entry_js = crate::bridge::otp_entry::entry_invocation(&value, selector.as_deref());
    let entered = match crate::browser::page_query::evaluate::<serde_json::Value>(page, &entry_js).await {
        Ok(res) => res.get("ok").and_then(|v| v.as_bool()).unwrap_or(false),
        Err(e) => { tracing::debug!(error = %e, "twofa entry JS failed"); false }
    };
    if !entered {
        let fallback = "input[type='text'], input[type='tel'], input[type='number'], input:not([type])";
        let sel = selector.as_deref().unwrap_or(fallback);
        if let Err(e) = crate::browser::page_actions::fill(page, sel, &value).await {
            tracing::debug!(error = %e, "twofa fill failed, trying keyboard_type");
            let _ = crate::browser::page_actions::click_selector(page, sel, false).await;
            crate::browser::page_actions::keyboard_type(page, &value, 60.0).await
                .map_err(|e| format!("twofa type failed: {}", e))?;
        }
    }
    let submit = raw_step.get("submit_selector").and_then(|v| v.as_str())
        .or_else(|| raw_step.get("config").and_then(|c| c.get("submit_selector")).and_then(|v| v.as_str()))
        .map(|s| s.to_string())
        .or(detected_submit);
    if let Some(submit) = submit {
        let _ = crate::browser::page_actions::click_selector(page, &submit, false).await;
    }
    tracing::info!("twofa step: entered code");
    Ok(())
}

// ---------------------------------------------------------------------------
// The executor
// ---------------------------------------------------------------------------

/// Execute a wire-dispatched `execute_workflow` message end-to-end and emit the `task_result`
/// frame (plus `scheduled_workflow_complete` when `_scheduled`). See the module docs for the
/// contract; the body is the verbatim `saas_bridge::handle_execute_workflow` with the outgoing
/// channel and channel-key source parameterized.
pub(crate) async fn handle_execute_workflow(
    task_id: &str,
    msg: &serde_json::Value,
    browser_mgr: &Arc<BrowserManager>,
    send: SendJson<'_>,
    artifact_ctx: Option<crate::automation::files::ArtifactContext>,
    channel_key: Option<&str>,
) {
    tracing::info!(task_id, "Executing workflow");

    let config = &msg["config"];
    let entry_url = config["entry_url"].as_str().unwrap_or("about:blank");

    // Decrypt credentials via channel_key
    let credentials = resolve_credentials(config, channel_key);

    // File assets (§6.3): run-level files map (backend-resolved, ownership-checked +
    // short-TTL signed in config["files"]) + the artifact-capture context. Upload
    // steps fetch from here; wait_for_download captures DIRECT-TO-STORAGE via the
    // artifact context; {{file:slot}} resolves to a fetched local path.
    let run_files = crate::automation::files::RunFiles::from_config(config, artifact_ctx);
    if !run_files.is_empty() {
        tracing::info!(task_id, count = run_files.len(), "Run has stored file(s) available");
        // Prefetch slot-bound files so {{file:slot}} references in step values resolve
        // to a local path even when the slot isn't tied to an upload step.
        run_files.prefetch_slot_files().await;
    }

    // Merge form_data
    let form_data: HashMap<String, String> = config.get("form_data")
        .and_then(|v| serde_json::from_value(v.clone()).ok())
        .unwrap_or_default();

    // Parse steps from config into WorkflowStep structs
    let raw_steps = config["steps"].as_array().cloned().unwrap_or_default();
    let timeout_ms = config["timeout_ms"].as_u64().unwrap_or(60000);
    let fast_mode = config["fast_mode"].as_bool().unwrap_or(true);

    // Auto-buy safety: in dry_run we execute up to — but not including — the
    // irreversible "place order" step. The commit step is whichever step is
    // explicitly flagged `commit: true`, else the last enabled step (a recorded
    // checkout ends on the order-submit click). payment_mode tells us to rely on a
    // saved card / browser autofill — we never type a stored card number.
    let dry_run = config.get("dry_run").and_then(|v| v.as_bool()).unwrap_or(false);
    let payment_mode = config.get("payment_mode").and_then(|v| v.as_str()).unwrap_or("");
    let commit_index: Option<usize> = if dry_run {
        let explicit = raw_steps.iter().position(|s| {
            s.get("commit").and_then(|v| v.as_bool()).unwrap_or(false)
                || s.get("config").and_then(|c| c.get("commit")).and_then(|v| v.as_bool()).unwrap_or(false)
        });
        explicit.or_else(|| {
            raw_steps.iter().enumerate().rev().find_map(|(idx, s)| {
                let t = s["type"].as_str().unwrap_or("");
                let en = s.get("enabled").and_then(|v| v.as_bool()).unwrap_or(true);
                if !t.is_empty() && en { Some(idx) } else { None }
            })
        })
    } else {
        None
    };
    if dry_run {
        tracing::info!(task_id, payment_mode, commit_index = ?commit_index,
            "Auto-buy dry_run: will stop before the commit step (order not placed)");
    }
    let mut stopped_before_commit = false;

    // Parse the saved session state up-front (warm session) so the captured
    // browser fingerprint can be reused when creating the context. The backend
    // only sends session_state when session_persistence is ON, so a "fresh"
    // workflow (toggle off) has no saved_state → random fingerprint + fresh login.
    let saved_state: Option<crate::models::session::SessionState> = config
        .get("session_state")
        .filter(|v| !v.is_null())
        .and_then(|v| serde_json::from_value(v.clone()).ok());

    // Warm session → reuse the exact fingerprint captured with the auth (returning
    // user, so the restored session is not invalidated). Fresh session → random.
    let restored_fp: Option<crate::browser::context::Fingerprint> = saved_state
        .as_ref()
        .and_then(|s| s.fingerprint.clone())
        .and_then(|v| serde_json::from_value(v).ok());

    // Per-run BYO persona proxy: read the reserved `__proxy__` object from the run
    // credentials (backend-gated — present only when no creator-IP relay is bound
    // and the run is not residential-intent). When present it egresses THIS context
    // through the consumer's residential proxy (context-level, overriding the env
    // proxy); None → env proxy / direct.
    let proxy_override = extract_proxy_override(config, channel_key);

    // --- Browserless HTTP lane ---
    // Same gate as the local engine: every enabled step is pure HTTP, not a dry_run/auto-buy, not a
    // payment run, and the workflow isn't pinned browser-only. On success we emit the byte-identical
    // task_result frame with engine="http" + the harvested auth_session (the backend persists it just
    // like a browser run's). A fallback drops through to the browser path below (+ engine_fallback).
    let http_capable_hint = config.get("http_capable").and_then(|v| v.as_bool());
    let mut http_fallback: Option<&'static str> = None;
    if http_capable_hint != Some(false)
        && !dry_run
        && payment_mode.is_empty()
        && crate::automation::http_lane::http_lane_eligible(&raw_steps).eligible
    {
        use crate::automation::http_lane::ladder::{run_workflow_http, LadderConfig, NullObserver};
        use crate::automation::http_lane::recipe::{AuthRecipe, ChallengeResolver, RecipeRunner};
        use crate::automation::http_lane::{HttpLaneError, HttpLaneExecutor, HttpLaneOptions, HttpProxyConfig, ParkKind};

        let http_proxy = proxy_override.as_ref().map(|p| HttpProxyConfig {
            server: p.server.clone(),
            username: p.username.clone(),
            password: p.password.clone(),
            bypass: p.bypass.clone(),
        });
        let http_fp = saved_state.as_ref().and_then(|s| s.fingerprint.clone());
        match HttpLaneExecutor::new(HttpLaneOptions {
            fingerprint: http_fp,
            proxy: http_proxy,
            session: saved_state.as_ref(),
            entry_url: Some(entry_url),
            timeout: std::time::Duration::from_millis(timeout_ms),
        }) {
            Ok(mut exec) => {
                let login_url_patterns: Vec<String> = config
                    .get("login_url_patterns")
                    .and_then(|v| serde_json::from_value(v.clone()).ok())
                    .unwrap_or_default();
                let relogin_max = config.get("relogin_max_retries").and_then(|v| v.as_u64()).unwrap_or(1) as u32;
                let ladder_cfg = LadderConfig { login_url_patterns, relogin_max_retries: relogin_max };

                // A declarative AuthRecipe (phase 2). Challenges can't be resolved on this cloud-relay
                // path (no persona TOTP resolution here) → a 2FA challenge parks; the browser path or
                // the Python cloud agent handles it.
                let recipe: Option<AuthRecipe> = config
                    .get("auth_config")
                    .filter(|v| !v.is_null())
                    .and_then(|v| serde_json::from_value(v.clone()).ok());
                let seeded_tokens = saved_state.as_ref().and_then(|s| s.tokens.clone());
                let mut runner = recipe.as_ref().map(|r| {
                    RecipeRunner::new(r, &credentials, &form_data, seeded_tokens.as_ref(), ChallengeResolver::None, relogin_max)
                });

                match run_workflow_http(&mut exec, &raw_steps, &credentials, &form_data, &ladder_cfg, &NullObserver, runner.as_mut()).await {
                    Ok(outcome) => {
                        if let Some(tokens) = runner.as_ref().and_then(|r| r.export_tokens()) {
                            exec.merge_tokens(tokens);
                        }
                        let auth_session = serde_json::to_value(exec.export_session_state()).unwrap_or(serde_json::Value::Null);
                        let result_msg = serde_json::json!({
                            "type": "task_result",
                            "task_id": task_id,
                            "success": true,
                            "error": serde_json::Value::Null,
                            "result_data": {
                                "success": true,
                                "steps_completed": outcome.steps_completed,
                                "extracted_data": outcome.extracted,
                                "engine": "http",
                                "dry_run": false,
                                "stopped_before_commit": false,
                                "output_files": [],
                            },
                            "steps_completed": outcome.steps_completed,
                            "auth_session": auth_session,
                        });
                        send(result_msg);
                        if msg.get("_scheduled").and_then(|v| v.as_bool()).unwrap_or(false) {
                            send(serde_json::json!({
                                "type": "scheduled_workflow_complete",
                                "workflow_id": msg.get("workflow_id").cloned().unwrap_or(serde_json::Value::Null),
                                "success": true,
                                "result_data": { "steps_completed": outcome.steps_completed, "extracted_data": outcome.extracted },
                                "error": serde_json::Value::Null,
                            }));
                        }
                        println!("  ✓ Task #{} completed (HTTP lane) — {} steps", task_id, outcome.steps_completed);
                        run_files.cleanup_temps();
                        return;
                    }
                    Err(HttpLaneError::Fallback(reason)) => {
                        tracing::warn!(task_id, reason = reason.as_str(), "HTTP lane fell back to browser");
                        http_fallback = Some(reason.as_str());
                    }
                    Err(HttpLaneError::Parked(kind)) => {
                        let (tag, message) = match kind {
                            ParkKind::Twofa(m) => ("TWOFA_REQUIRED", m),
                            ParkKind::Attention(m) => ("USER_PROMPT_REQUIRED", m),
                        };
                        send(serde_json::json!({
                            "type": "task_result",
                            "task_id": task_id,
                            "success": false,
                            "error": format!("{tag}: {message}"),
                            "result_data": { "success": false, "steps_completed": 0, "extracted_data": {}, "engine": "http" },
                            "steps_completed": 0,
                        }));
                        run_files.cleanup_temps();
                        println!("  ✗ Task #{} parked (HTTP lane): {}", task_id, tag);
                        return;
                    }
                    Err(HttpLaneError::Fatal(m)) => {
                        // Corrupt config / SSRF-blocked URL — the browser applies its own guards, so
                        // drop through rather than fail hard.
                        tracing::warn!(task_id, error = %m, "HTTP lane fatal — falling back to browser");
                        http_fallback = Some("fatal");
                    }
                }
            }
            Err(_) => { /* couldn't build the HTTP client — fall through to the browser */ }
        }
    }

    // Honor the workflow's per-run headless setting: relaunch the warm browser in
    // the requested mode if it differs from how it was last launched. Default true
    // when the backend omits it. Without this the warm browser stayed in the global
    // mode and a workflow toggled to headed kept running headless.
    let headless = config.get("headless").and_then(|v| v.as_bool()).unwrap_or(true);
    if let Err(e) = browser_mgr.ensure_warm_browser_with(headless).await {
        send(serde_json::json!({
            "type": "task_result",
            "task_id": task_id,
            "success": false,
            "error": format!("Browser launch failed: {}", e),
        }));
        run_files.cleanup_temps();
        println!("  ✗ Task #{} failed: {}", task_id, e);
        return;
    }

    let (context, page, fp_used) = match browser_mgr
        .create_stealth_context_with_fingerprint_proxy(restored_fp, proxy_override)
        .await
    {
        Ok(cp) => cp,
        Err(e) => {
            send(serde_json::json!({
                "type": "task_result",
                "task_id": task_id,
                "success": false,
                "error": format!("Browser context failed: {}", e),
            }));
            run_files.cleanup_temps();
            println!("  ✗ Task #{} failed: {}", task_id, e);
            return;
        }
    };

    // The context now EXISTS inside Chromium and `BrowserContext` has no `Drop`, so dropping the
    // handle would leave the context, its renderer processes and its memory alive for the life of the
    // browser. This executor is driven from a spawned bridge handler, and that handler's future is
    // dropped on every connection loss / shutdown / abort — which is the ordinary path, not an edge
    // case. Arm a guard so a cancellation or a panic in the step loop still closes it; the explicit
    // closes below go through the SAME guard (idempotent) so there is exactly one close per context.
    let mut ctx_guard = crate::browser::context::ContextCloseGuard::new(context.clone());

    // Capture auth-related request headers (Bearer / X-Auth / API keys) during the
    // flow, so token-based auth is persisted too. Safe here because this function
    // owns the page/context locally (no DashMap lock held across awaits).
    let captured_headers: Arc<std::sync::Mutex<HashMap<String, String>>> =
        Arc::new(std::sync::Mutex::new(HashMap::new()));
    {
        const AUTH_HEADER_PATTERNS: &[&str] = &[
            "authorization", "x-auth", "x-api-key", "x-session", "x-token",
            "x-csrf", "x-xsrf", "bearer", "api-key", "access-token",
        ];
        let cap = captured_headers.clone();
        let _ = context.on_request(move |request: playwright_rs::Request| {
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
        }).await;
    }

    // SECURITY: vet the entry/navigation URL BEFORE we goto it. The route blocker
    // only inspects per-request URLs once navigation is underway; the initial
    // entry_url (server/workflow-supplied) must be rejected up front if it targets
    // file:/data:/internal hosts or cloud metadata. Fail closed on DNS error.
    // ("about:blank" — the default — is allowed by the guard.)
    if !crate::security::url_guard::is_navigation_url_safe_async(entry_url).await {
        ctx_guard.close().await;
        send(serde_json::json!({
            "type": "task_result",
            "task_id": task_id,
            "success": false,
            "error": format!("Refused unsafe entry URL: {}", entry_url),
        }));
        run_files.cleanup_temps();
        println!("  ✗ Task #{} refused unsafe entry URL: {}", task_id, entry_url);
        return;
    }

    // Restore saved session state (cookies + localStorage) if present, then navigate.
    // Cookies are added BEFORE navigation, localStorage after, so the flow runs
    // already-authenticated instead of logged out. (saved_state parsed above.)
    let nav_result = if let Some(ref state) = saved_state {
        tracing::info!(
            task_id,
            cookies = state.cookies.len(),
            local_storage = state.local_storage.len(),
            "Restoring saved session state before workflow"
        );
        crate::automation::session_state::inject_session_state(
            &page, &context, state, Some(entry_url), 30_000,
        ).await
    } else {
        crate::browser::navigation::goto(
            &page, entry_url, "domcontentloaded",
            std::time::Duration::from_secs(30),
        ).await
    };

    if let Err(e) = nav_result {
        ctx_guard.close().await;
        send(serde_json::json!({
            "type": "task_result",
            "task_id": task_id,
            "success": false,
            "error": format!("Navigation/restore failed: {}", e),
        }));
        run_files.cleanup_temps();
        println!("  ✗ Task #{} failed: navigation to {}", task_id, entry_url);
        return;
    }

    // Execute each step
    let mut steps_completed: usize = 0;
    let mut extracted_data: HashMap<String, serde_json::Value> = HashMap::new();
    let mut last_error: Option<String> = None;

    // Track the active page so tab-affecting steps (open_tab/switch_tab/wait_for_tab/
    // tab_closed) redirect subsequent steps to the focused tab instead of staying on
    // the original page.
    let mut active_page = page.clone();

    for (i, raw_step) in raw_steps.iter().enumerate() {
        let step_type = raw_step["type"].as_str().unwrap_or("");
        if step_type.is_empty() {
            continue;
        }

        // Check if step is disabled
        let enabled = raw_step.get("enabled").and_then(|v| v.as_bool()).unwrap_or(true);
        if !enabled {
            continue;
        }

        // Dry run: stop before the irreversible commit/place-order step.
        if dry_run && commit_index == Some(i) {
            tracing::info!(task_id, step = i,
                "Auto-buy dry_run: stopping before commit step — order NOT placed");
            stopped_before_commit = true;
            break;
        }

        // Saved-method / autofill payment: never type a stored card number — skip any
        // fill into a card-like field (the recorded flow selects a saved card instead).
        if (payment_mode == "merchant_saved" || payment_mode == "browser_autofill")
            && step_type == "fill"
        {
            let sel = raw_step
                .get("config").and_then(|c| c.get("selector")).and_then(|v| v.as_str())
                .or_else(|| raw_step.get("selector").and_then(|v| v.as_str()))
                .unwrap_or("")
                .to_lowercase();
            if sel.contains("card") || sel.contains("cvv") || sel.contains("cvc")
                || sel.contains("cc-num") || sel.contains("creditcard") || sel.contains("expir")
            {
                tracing::info!(task_id, step = i, payment_mode,
                    "Skipping card-field fill — using saved payment method");
                continue;
            }
        }

        // 2FA: handled inline here because the bridge owns the network + task
        // context needed to call back to the coordinator's OTP-mint endpoint.
        if step_type == "twofa" {
            match handle_twofa_step(&active_page, raw_step, config, timeout_ms).await {
                Ok(()) => {
                    steps_completed = i + 1;
                    continue;
                }
                Err(e) => {
                    last_error = Some(e);
                    tracing::error!(task_id, step = i, "twofa step failed");
                    break;
                }
            }
        }

        // Parse step config
        let mut step_config: WorkflowStepConfig = match serde_json::from_value(
            raw_step.get("config").cloned().unwrap_or(raw_step.clone())
        ) {
            Ok(c) => c,
            Err(e) => {
                tracing::warn!(step = i, error = %e, "Failed to parse step config, skipping");
                continue;
            }
        };

        // Virtual card: fill the merchant's OWN card fields with the issued single-use
        // card (never the user's real PAN). The field is chosen from the selector.
        if payment_mode == "virtual_card" && step_type == "fill" {
            let sel = step_config.selector.as_deref().unwrap_or("").to_lowercase();
            let key = if sel.contains("cvv") || sel.contains("cvc") || sel.contains("security") {
                Some("vcard_cvv")
            } else if sel.contains("exp") {
                Some("vcard_exp")
            } else if sel.contains("name") {
                Some("vcard_name")
            } else if sel.contains("card") || sel.contains("cc-num") || sel.contains("creditcard") || sel.contains("number") {
                Some("vcard_number")
            } else {
                None
            };
            if let Some(k) = key {
                if let Some(v) = credentials.get(k) {
                    step_config.value = Some(v.clone());
                    tracing::info!(task_id, step = i, field = k, "virtual_card: filling card field with issued card");
                }
            }
        }

        // File assets (§6.3): resolve {{file:slot}} in value-bearing config fields to
        // the fetched local path so a script/eval/fill step can read an attached file.
        // Done here (not inside each step) to avoid changing every step signature; the
        // upload/wait_for_download steps consume the run files map directly. Runs only
        // when the run actually carries files (no-op otherwise).
        if !run_files.is_empty() {
            let slot_paths = run_files.fetched_slot_paths();
            if !slot_paths.is_empty() {
                use crate::util::value_resolver::resolve_value_with_files;
                let empty = HashMap::new();
                if let Some(v) = step_config.value.as_deref() {
                    if v.contains("{{file:") {
                        step_config.value = Some(resolve_value_with_files(v, &empty, None, Some(&slot_paths)));
                    }
                }
                if let Some(s) = step_config.script.as_deref() {
                    if s.contains("{{file:") {
                        step_config.script = Some(resolve_value_with_files(s, &empty, None, Some(&slot_paths)));
                    }
                }
                if let Some(u) = step_config.url.as_deref() {
                    if u.contains("{{file:") {
                        step_config.url = Some(resolve_value_with_files(u, &empty, None, Some(&slot_paths)));
                    }
                }
            }
        }

        let step_ctx = crate::automation::step_executor::StepRunContext {
            credentials: &credentials,
            form_data: &form_data,
            run_files: &run_files,
            timeout_ms,
            fast_mode,
            // Prior steps' response_extractions so `{{extracted:key}}` resolves in api_call bodies/headers.
            extracted: &extracted_data,
        };
        let result = crate::automation::step_executor::execute_step_ctx(
            &active_page,
            step_type,
            &step_config,
            &step_ctx,
        ).await;

        match result {
            Ok(data) => {
                steps_completed = i + 1;
                if let Some(extractions) = data {
                    for (k, v) in extractions {
                        extracted_data.insert(k, v);
                    }
                }
            }
            Err(e) => {
                last_error = Some(e.to_string());
                tracing::error!(
                    task_id, step = i, step_type,
                    error = %e, "Workflow step failed"
                );
                break;
            }
        }

        // Tab-affecting steps move browser focus; follow it so the next step runs on the
        // now-active tab (the Err arm above breaks out, so this is reached only on Ok).
        if let Some(new_active) = crate::automation::step_misc::resolve_active_page_after_step(
            &context,
            step_type,
            &step_config,
        ) {
            active_page = new_active;
        }
    }

    let success = last_error.is_none();

    // Extract the session state (cookies + localStorage + sessionStorage) BEFORE
    // closing the context, and return it as `auth_session` so the backend can persist
    // the auth for the next run. Without this, any login during the flow is lost
    // and the next run starts logged out.
    let auth_session = {
        let headers = captured_headers.lock().map(|m| m.clone()).unwrap_or_default();
        let mut state = crate::automation::session_state::extract_session_state(
            &active_page, &context, &headers,
        ).await;
        // Persist the fingerprint used, so the next warm run reuses it (returning user).
        state.fingerprint = serde_json::to_value(&fp_used).ok();
        serde_json::to_value(&state).ok()
    };

    // File assets (§6.3): captured downloads finalized this run, surfaced as
    // result_data.output_files (the backend reconciles each against its
    // artifact-init/finalize record, §4.4). Empty when the run captured nothing.
    let output_files = run_files.output_files_json();

    // Build result message
    let result_msg = serde_json::json!({
        "type": "task_result",
        "task_id": task_id,
        "success": success,
        "error": last_error,
        "result_data": {
            "success": success,
            "steps_completed": steps_completed,
            "extracted_data": extracted_data,
            // Which lane produced this run. This is the browser step-loop path; the browserless HTTP
            // lane (above) builds its own frame with engine="http".
            "engine": "browser",
            // Set when we reached the browser via an HTTP-lane fallback — the backend reads this to mark
            // the workflow browser-only (skip the HTTP probe next run). Null on a normal browser run.
            "http_fallback": http_fallback.map(|r| serde_json::json!({ "from": "http", "reason": r })),
            // Auto-buy: tells the backend a dry run did NOT place the order, so it
            // is not metered against the spend cap.
            "dry_run": dry_run,
            "stopped_before_commit": stopped_before_commit,
            // Captured download artifacts (file_id/filename/size/content_type/output_key).
            "output_files": output_files,
        },
        "steps_completed": steps_completed,
        "auth_session": auth_session,
    });
    send(result_msg);

    // Scheduled monitoring workflow: also emit a scheduled_workflow_complete frame
    // so the coordinator records it against the workflow (vs a one-off task).
    if msg.get("_scheduled").and_then(|v| v.as_bool()).unwrap_or(false) {
        send(serde_json::json!({
            "type": "scheduled_workflow_complete",
            "workflow_id": msg.get("workflow_id").cloned().unwrap_or(serde_json::Value::Null),
            "success": success,
            "result_data": {
                "steps_completed": steps_completed,
                "extracted_data": extracted_data,
            },
            "error": last_error,
        }));
    }

    if success {
        let extract_count = extracted_data.len();
        let extract_msg = if extract_count > 0 {
            format!(", {} extractions", extract_count)
        } else {
            String::new()
        };
        println!("  ✓ Task #{} completed — {} steps{}", task_id, steps_completed, extract_msg);
    } else {
        println!("  ✗ Task #{} failed at step {}: {}", task_id, steps_completed,
                 last_error.as_deref().unwrap_or("unknown"));
    }

    // File assets (§10.5): delete all temp files fetched for upload / {{file:slot}}
    // resolution. Captured-download temps are deleted inline in step_download.
    run_files.cleanup_temps();

    // Cleanup browser context — through the guard, so the deterministic close and the
    // cancellation/panic fallback can never both fire.
    ctx_guard.close().await;
}
