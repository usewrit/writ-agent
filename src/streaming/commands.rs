use super::manager::StreamingSessionManager;

/// Dispatch a streaming command. On success, `Ok(Some(value))` means the caller
/// MUST emit a `command_response { request_id, data: value }` (a steps-type
/// handler's extracted fields — there is no async `ps.respond` for it); `Ok(None)`
/// means no synchronous response is owed (fire-and-forget or page-dispatched).
pub async fn handle_command(
    manager: &mut StreamingSessionManager,
    cmd: &serde_json::Value,
) -> Result<Option<serde_json::Value>, anyhow::Error> {
    let cmd_type = cmd
        .get("type")
        .and_then(|v| v.as_str())
        .unwrap_or("");

    match cmd_type {
        "streaming_command" => {
            let action = cmd.get("action").and_then(|v| v.as_str()).unwrap_or("");
            let data = cmd.get("data").cloned().unwrap_or(serde_json::json!({}));
            let request_id = cmd
                .get("request_id")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();

            // Route to step handler or _dispatch_to_page
            let handler_name = action;
            if manager.get_handler(handler_name).is_some() {
                let result = super::handlers::execute_step_handler(
                    manager, handler_name, &data, &request_id,
                )
                .await?;
                // Carry the extracted fields back so the caller answers the turn.
                return Ok(Some(result));
            } else {
                // No registered handler AND no page-dispatch fallback available on
                // this path: surface it as an explicit error instead of silently
                // dropping the command (which would hang the caller to timeout).
                tracing::warn!(action = action, "No handler for streaming action — cannot dispatch");
                anyhow::bail!("no handler registered for action: {action}");
            }
        }
        "add_handler" => {
            if let Some(handler_cfg) = cmd.get("handler") {
                let name = handler_cfg
                    .get("name")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string();
                let handler = super::manager::HandlerDef {
                    handler_type: handler_cfg
                        .get("type")
                        .and_then(|v| v.as_str())
                        .unwrap_or("steps")
                        .to_string(),
                    name: name.clone(),
                    step_range: handler_cfg.get("step_range").and_then(|v| {
                        let arr = v.as_array()?;
                        Some((arr.first()?.as_u64()? as usize, arr.get(1)?.as_u64()? as usize))
                    }),
                    extract_fields: handler_cfg
                        .get("extract_fields")
                        .and_then(|v| v.as_array())
                        .map(|arr| {
                            arr.iter()
                                .filter_map(|v| v.as_str().map(String::from))
                                .collect()
                        })
                        .unwrap_or_default(),
                    code: handler_cfg.get("code").and_then(|v| v.as_str()).map(String::from),
                };
                manager.add_handler(name.clone(), handler);
                tracing::info!(handler = %name, "Handler added");
            }
        }
        "remove_handler" => {
            let name = cmd
                .get("handler_name")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            if manager.remove_handler(name).is_some() {
                tracing::info!(handler = name, "Handler removed");
            }
        }
        "end_streaming" => {
            let reason = cmd
                .get("reason")
                .and_then(|v| v.as_str())
                .unwrap_or("user_ended");
            manager.end(reason).await;
        }
        other => {
            tracing::warn!(cmd_type = other, "Unknown streaming command");
        }
    }

    Ok(None)
}
