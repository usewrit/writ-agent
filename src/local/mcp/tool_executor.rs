//! MCP `tools/call` execution — resolve a tool to its workflow and run it via the local engine.
//!
//! The caller-supplied `name` is matched against the SAME catalog `tools/list` advertises
//! (`mcp::tools::catalog`), so a sanitized workflow name and its `workflow_<id>` fallback both
//! resolve. A direct `workflow_<id>` literal is also accepted as a convenience even if the workflow's
//! display name sanitized to something else. We build a `RunRequest { source: Mcp, lane: Interactive }`
//! and call `state.engine.run(..).await`, then shape the engine's `RunResult` into an MCP tool
//! result (`{ content: [{type:"text", text}], isError }`).
//!
//! House style: no `async-trait`; `tracing` only; we DON'T propagate raw engine/store error text to
//! the client — `protocol.rs` maps `CallError::Internal` to a generic, ref-tagged JSON-RPC error.
//! Tool-run failures that the engine reports as a `RunResult` (success=false) are returned as a
//! normal MCP result with `isError:true` (per spec) rather than a JSON-RPC error.
//!
//! AUTHORIZATION (AC-2): `POST /mcp` is a SINGLE HTTP route, so `auth::required_scope` can only give
//! it one classification (`Run`) — but the tools it multiplexes span `Read`, `Run` and `Admin` on the
//! REST surface. Without a second gate, the scope model collapsed at this door: a `run`-scoped
//! credential (what every OAuth consent issues) could call `writ_create_automation`,
//! `writ_set_schedule`, `writ_install_api`, … all of which are `Admin` over REST. [`TOOL_SCOPES`]
//! restores the model by declaring a per-tool MINIMUM scope, checked against the capability
//! `server::auth_mw` resolved for the request ([`auth::Caller`], carried in request extensions).

use crate::local::auth::{Caller, Scope};
use crate::local::engine::{Lane, RunRequest, RunSource};
use crate::local::error::LocalError;
use crate::local::server::AppState;
use crate::local::store::workflows;
use serde_json::{json, Value};

/// Failure modes for `call_tool`, mapped to JSON-RPC codes by `protocol.rs`.
#[derive(Debug)]
pub enum CallError {
    /// No tool with this name in the current catalog.
    UnknownTool(String),
    /// Caller arguments were the wrong shape.
    BadArgument(String),
    /// The credential is valid but lacks the scope this tool requires (the MCP analogue of a REST
    /// 403). The message is caller-facing and actionable on purpose — the connected model should be
    /// able to tell the user WHICH capability to issue.
    Forbidden(String),
    /// Store/engine failure — never surfaced verbatim to the client.
    Internal(LocalError),
}

impl From<LocalError> for CallError {
    fn from(e: LocalError) -> Self {
        CallError::Internal(e)
    }
}

/// Reserved prefix for the static tool catalog. Any `writ_*` name that is NOT classified in
/// [`TOOL_SCOPES`] is REFUSED rather than silently inheriting the route's `Run` — a newly added tool
/// must be classified deliberately (see [`tool_min_scope`]).
const STATIC_TOOL_PREFIX: &str = "writ_";

/// The minimum [`Scope`] each static `writ_*` MCP tool requires, mirroring what the equivalent action
/// costs on the REST surface. This is the authorization table for `tools/call`.
///
/// Classification rule — what does the tool DO to the user's device?
///   * `Read`  — reports data that already exists (lists, stored run data, dataset/data search).
///   * `Run`   — executes: drives the browser, replays a saved workflow, scrapes/maps/crawls, or
///               steers/cancels an in-flight session. This is what the OAuth `run` grant buys, and it
///               matches its consent page ("run your workflows and tools and read their results").
///   * `Admin` — CREATES or RECONFIGURES durable state: saving a recording as a workflow, scheduling,
///               wiring a monitor, exposing an API, installing a marketplace API. Every one of these
///               is an `Admin` mutation over REST, so it is one here too.
///
/// No tool is `Manage`: device control is not reachable from this surface at all (there is deliberately
/// no MCP tool for the vault, key issuance, LAN exposure, cloud link, or backup).
const TOOL_SCOPES: &[(&str, Scope)] = &[
    // ── reads ────────────────────────────────────────────────────────────────
    ("writ_list_workflows", Scope::Read),
    ("writ_workflow_data", Scope::Read),
    ("writ_workflow_runs", Scope::Read),
    ("writ_list_datasets", Scope::Read),
    ("writ_dataset", Scope::Read),
    ("writ_dataset_search", Scope::Read),
    ("writ_search_data", Scope::Read),
    ("writ_crawl_status", Scope::Read),
    ("writ_mission_status", Scope::Read),
    // Marketplace SEARCH only browses the cloud catalog; installing is separate (Admin, below).
    ("writ_search_api", Scope::Read),
    // ── execution ────────────────────────────────────────────────────────────
    ("writ_run_workflow", Scope::Run),
    ("writ_browser_use", Scope::Run),
    ("writ_browser_act", Scope::Run),
    ("writ_browser_context", Scope::Run),
    ("writ_browser_network", Scope::Run),
    ("writ_browser_cancel", Scope::Run),
    ("writ_scrape", Scope::Run),
    ("writ_map", Scope::Run),
    ("writ_crawl_site", Scope::Run),
    ("writ_mission_respond", Scope::Run),
    ("writ_mission_cancel", Scope::Run),
    // ── creation / reconfiguration (Admin on REST, Admin here) ───────────────
    // These open a session whose PURPOSE is to produce a saved workflow; `writ_browser_save` is the
    // commit. `writ_browser_use` above is the task-oriented mode that saves nothing by itself.
    ("writ_build", Scope::Admin),
    ("writ_record_website", Scope::Admin),
    ("writ_website_to_api", Scope::Admin),
    ("writ_browser_save", Scope::Admin),
    ("writ_expose_workflow_api", Scope::Admin),
    ("writ_set_schedule", Scope::Admin),
    ("writ_create_monitor", Scope::Admin),
    ("writ_wire_monitor", Scope::Admin),
    ("writ_create_automation", Scope::Admin),
    ("writ_install_api", Scope::Admin),
];

/// The minimum scope for `name`, or `None` when it is not a classified static tool.
fn tool_min_scope(name: &str) -> Option<Scope> {
    TOOL_SCOPES.iter().find(|(n, _)| *n == name).map(|(_, s)| *s)
}

/// Gate one `tools/call` on the caller's capability.
///
/// DEFAULT-DENY for the reserved `writ_` prefix: an unclassified `writ_*` name cannot be reached, so
/// adding a static tool without a [`TOOL_SCOPES`] entry fails closed instead of inheriting `Run`.
/// Everything else is a workflow-derived tool — replaying a saved workflow is execution, hence `Run`
/// (the per-workflow Connect → MCP toggle is enforced separately by `tools::catalog`).
fn authorize_tool(caller: &Caller, name: &str) -> Result<(), CallError> {
    let needed = match tool_min_scope(name) {
        Some(s) => s,
        None if name.starts_with(STATIC_TOOL_PREFIX) => {
            tracing::error!(
                tool = %name,
                "mcp: refusing an unclassified `writ_*` tool — add it to TOOL_SCOPES"
            );
            return Err(CallError::Forbidden(format!(
                "Tool '{name}' is not available: the `writ_` prefix is reserved and this name has no \
                 declared capability."
            )));
        }
        None => Scope::Run,
    };
    if caller.grants(needed) {
        return Ok(());
    }
    tracing::warn!(
        tool = %name,
        caller = caller.describe(),
        required = needed.as_str(),
        "mcp: tools/call refused — credential lacks the required scope"
    );
    Err(CallError::Forbidden(format!(
        "Not authorized: '{name}' requires the '{}' capability, but this connection was granted \
         '{}'. Ask the user to issue an API key with the '{}' scope in the Writ app \
         (Settings → API keys) and reconnect with it.",
        needed.as_str(),
        caller.describe(),
        needed.as_str(),
    )))
}

/// Execute one `tools/call`. Returns the MCP tool-result `Value` (`{content,isError?}`) on success
/// (including engine-reported run failures, which carry `isError:true`).
///
/// `caller` is the capability `server::auth_mw` resolved for this request; it is enforced BEFORE any
/// tool body runs (see [`authorize_tool`]).
pub async fn call_tool(
    state: &AppState,
    caller: &Caller,
    name: &str,
    arguments: Value,
) -> Result<Value, CallError> {
    authorize_tool(caller, name)?;
    // Static `writ_*` tools take precedence — the workflow catalog reserves their names.
    if let Some(result) = super::static_tools::call(state, name, &arguments).await {
        return result;
    }
    let workflow_id = resolve_workflow_id(state, name).await?;
    run_workflow_tool(state, workflow_id, arguments).await
}

/// Run one workflow as an MCP tool call — shared by the derived per-workflow tools (above) and the
/// generic `writ_run_workflow` (which resolves + surface-gates the workflow itself first).
pub(crate) async fn run_workflow_tool(
    state: &AppState,
    workflow_id: i64,
    arguments: Value,
) -> Result<Value, CallError> {
    // Arguments must be a JSON object (or absent). They become the engine `inputs` map.
    let mut inputs = match arguments {
        Value::Null => json!({}),
        Value::Object(_) => arguments,
        other => {
            return Err(CallError::BadArgument(format!(
                "arguments must be a JSON object, got {}",
                kind_of(&other)
            )));
        }
    };

    // Lift any top-level `file_slot` string args into a `files` map the engine's `RunFiles` consumes.
    // A workflow's declared file slots (advertised as optional string handle properties by
    // `tools::derive_input_schema`) are matched against the caller's args; each `{ slot: file_handle }`
    // becomes a `files` entry `{ file_handle -> { file_id, slots:[slot] } }` (the `config["files"]`
    // shape from `automation::files::RunFiles::from_config`), and the slot key is removed from the
    // plain inputs so it isn't also treated as a `{{input.*}}` value.
    //
    // MARKETPLACE PROXY rows (0017) elicit from the install's BYO MANIFEST instead (their own steps
    // are empty): required input slots, secret slots with the local vault keys offered as PICKABLE
    // options, persona slots with the local personas offered — the user picks or supplies values,
    // and the choices persist as install bindings the engine applies on every run (schedules too).
    if let Some(wf) = workflows::get_by_id(&state.db, workflow_id).await? {
        if wf.marketplace_slug.as_deref().is_some_and(|s| !s.is_empty()) {
            if let Some(prompt) = marketplace_gate(state, &wf, &mut inputs).await? {
                return Ok(prompt);
            }
        } else {
            if let Some(prompt) = missing_input_result(&wf, &inputs) {
                return Ok(prompt);
            }
            lift_file_slots(&mut inputs, &wf.steps);
        }
    }

    let req = RunRequest {
        workflow_id,
        inputs,
        source: RunSource::Mcp,
        lane: Lane::Interactive,
        dry_run: false,
        persona_id: None,
        allow_local_secret_refs: true,
    };

    tracing::info!(workflow_id, "mcp: tools/call dispatch");
    // A BadRequest from the engine is a DOMAIN outcome the model should relay (e.g. a marketplace
    // paid run denied cloud-side: "run not authorized: insufficient balance") — never a protocol
    // error that hides the reason behind a generic ref. Unauthorized is the marketplace-proxy
    // cloud session failing (expired `wto_` login, or a device channel key from an older link that
    // can no longer unseal the recipe) — equally relayable: the fix is the USER re-linking.
    let result = match state.engine.run(req).await {
        Ok(r) => r,
        Err(LocalError::BadRequest(msg)) => {
            return Ok(json!({
                "content": [{ "type": "text", "text": format!("Error: {msg}") }],
                "isError": true,
            }));
        }
        Err(LocalError::Unauthorized) => {
            return Ok(json!({
                "content": [{ "type": "text", "text":
                    "Error: the Writ Cloud session on this device is no longer valid (expired \
                     login, or a device key from an older link), so this marketplace-installed \
                     workflow cannot run. Ask the user to re-link their Writ Cloud account in the \
                     Writ app (Settings → Account — linking is free), then call this tool again." }],
                "isError": true,
            }));
        }
        Err(e) => return Err(e.into()),
    };

    Ok(to_mcp_result(&result))
}

/// Manifest-driven pre-run gate for a marketplace-proxy workflow — delegates to the shared
/// implementation next to the `writ_install_api` tool. Compiled out with the `cloud` feature (a
/// proxy row cannot exist in the cloud-free build's install paths).
#[cfg(feature = "cloud")]
async fn marketplace_gate(
    state: &AppState,
    wf: &workflows::Workflow,
    inputs: &mut Value,
) -> Result<Option<Value>, CallError> {
    let slug = wf.marketplace_slug.as_deref().unwrap_or_default();
    super::static_tools::marketplace_needs_input(state, slug, inputs).await
}

#[cfg(not(feature = "cloud"))]
async fn marketplace_gate(
    _state: &AppState,
    _wf: &workflows::Workflow,
    _inputs: &mut Value,
) -> Result<Option<Value>, CallError> {
    Ok(None)
}

/// Same pre-run contract as the desktop fast-run modal: do not launch a browser when required
/// workflow data is absent. Return a structured, non-error tool result so the connected AI asks the
/// user in its own chat, then retries the SAME tool with the collected values.
fn missing_input_result(wf: &workflows::Workflow, inputs: &Value) -> Option<Value> {
    let supplied = inputs.as_object();
    let saved: serde_json::Map<String, Value> = wf
        .form_data
        .as_deref()
        .and_then(|s| serde_json::from_str::<Value>(s).ok())
        .and_then(|v| v.as_object().cloned())
        .unwrap_or_default();
    let mut fields = Vec::new();
    for raw in super::tools::scan_all_input_placeholders(&wf.steps) {
        let key = raw.strip_prefix("input.").unwrap_or(&raw).to_string();
        let supplied_value = supplied
            .and_then(|o| o.get(&key).or_else(|| o.get(&raw)))
            .filter(|v| !v.is_null() && v.as_str().is_none_or(|s| !s.trim().is_empty()));
        let saved_value = saved
            .get(&key)
            .or_else(|| saved.get(&raw))
            .filter(|v| !v.is_null() && v.as_str().is_none_or(|s| !s.trim().is_empty()));
        if supplied_value.is_none() && saved_value.is_none() {
            fields.push(json!({
                "key": key,
                "label": key.replace('_', " "),
                "kind": "text",
                "sensitive": looks_sensitive(&key),
            }));
        }
    }
    for slot in super::tools::scan_file_slots(&wf.steps) {
        let present = supplied
            .and_then(|o| o.get(&slot))
            .and_then(Value::as_str)
            .is_some_and(|s| !s.trim().is_empty());
        if !present {
            fields.push(
                json!({"key":slot,"label":slot.replace('_', " "),"kind":"file","sensitive":false}),
            );
        }
    }
    if fields.is_empty() {
        return None;
    }
    let body = json!({
        "status": "needs_input",
        "workflow_id": wf.id,
        "workflow": wf.name,
        "fields": fields,
        "next": "Ask the user for these values in the connected AI chat, then call this workflow again with them as arguments. Do not open Writ's run modal.",
    });
    Some(json!({
        "content": [{"type":"text","text":serde_json::to_string_pretty(&body).unwrap_or_else(|_| body.to_string())}],
        "isError": false,
    }))
}

fn looks_sensitive(key: &str) -> bool {
    let k = key.to_ascii_lowercase();
    [
        "password",
        "passwd",
        "secret",
        "token",
        "api_key",
        "apikey",
        "credential",
    ]
    .iter()
    .any(|needle| k.contains(needle))
}

/// Resolve a caller tool `name` to a workflow id using the live catalog. Accepts the advertised
/// catalog name (sanitized or `workflow_<id>` fallback) and, as a convenience, a literal
/// `workflow_<id>` form even when the catalog assigned the workflow a different sanitized name.
async fn resolve_workflow_id(state: &AppState, name: &str) -> Result<i64, CallError> {
    let catalog = super::tools::catalog(state).await?;
    if let Some(entry) = catalog.iter().find(|e| e.name == name) {
        return Ok(entry.workflow_id);
    }
    // Convenience: bare `workflow_<id>` literal that maps to an enabled workflow in the catalog.
    if let Some(id_str) = name.strip_prefix("workflow_") {
        if let Ok(id) = id_str.parse::<i64>() {
            if catalog.iter().any(|e| e.workflow_id == id) {
                return Ok(id);
            }
        }
    }
    Err(CallError::UnknownTool(name.to_string()))
}

/// Move caller-supplied `file_slot` string args out of the plain `inputs` and into an `inputs.files`
/// map keyed by the file handle, in the `config["files"]` shape `RunFiles::from_config` reads
/// (`{ file_id -> { file_id, slots:[slot] } }`). Any existing `inputs.files` object is preserved and
/// extended. Args whose value is not a non-empty string are left in place (no silent drop). No-op
/// when the workflow declares no file slots.
fn lift_file_slots(inputs: &mut Value, steps_text: &str) {
    let slots = super::tools::scan_file_slots(steps_text);
    if slots.is_empty() {
        return;
    }
    let Some(obj) = inputs.as_object_mut() else {
        return;
    };

    // Collect (slot, handle) pairs to lift, removing the slot keys from the plain inputs.
    let mut lifted: Vec<(String, String)> = Vec::new();
    for slot in &slots {
        match obj.get(slot) {
            Some(Value::String(handle)) if !handle.is_empty() => {
                lifted.push((slot.clone(), handle.clone()));
                obj.remove(slot);
            }
            _ => {}
        }
    }
    if lifted.is_empty() {
        return;
    }

    // Merge into (or create) the `files` map. Key by the file handle; bind the slot via `slots`.
    let files = obj
        .entry("files")
        .or_insert_with(|| Value::Object(serde_json::Map::new()));
    if let Some(files_map) = files.as_object_mut() {
        for (slot, handle) in lifted {
            files_map.insert(
                handle.clone(),
                json!({ "file_id": handle, "slots": [slot] }),
            );
        }
    }
}

/// Shape a `RunResult` into an MCP tool result. Successful runs return the extracted data as pretty
/// JSON text; engine-reported failures return the error text with `isError:true` (MCP spec: tool
/// errors are normal results, not protocol errors).
fn to_mcp_result(result: &crate::local::engine::RunResult) -> Value {
    if result.success {
        let text = serde_json::to_string_pretty(&result.extracted_data)
            .unwrap_or_else(|_| result.extracted_data.to_string());
        json!({
            "content": [{ "type": "text", "text": text }],
            "isError": false,
        })
    } else {
        let msg = result
            .error
            .clone()
            .unwrap_or_else(|| "workflow run failed".to_string());
        json!({
            "content": [{ "type": "text", "text": format!("Error: {msg}") }],
            "isError": true,
        })
    }
}

/// Human-readable JSON kind for error messages (no value contents leaked).
fn kind_of(v: &Value) -> &'static str {
    match v {
        Value::Null => "null",
        Value::Bool(_) => "boolean",
        Value::Number(_) => "number",
        Value::String(_) => "string",
        Value::Array(_) => "array",
        Value::Object(_) => "object",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::local::engine::{RunResult, RunStatus};

    fn scoped(csv: &str) -> Caller {
        Caller::Scoped(csv.to_string())
    }

    /// EVERY static tool must carry a deliberate classification. This is the guard that makes the
    /// default-deny meaningful: add a tool to `static_tools::NAMES` without a `TOOL_SCOPES` entry and
    /// this test fails at build time rather than the tool quietly inheriting the route's `Run`.
    #[test]
    fn every_static_tool_is_classified() {
        for name in crate::local::mcp::static_tools::NAMES {
            assert!(
                tool_min_scope(name).is_some(),
                "static tool '{name}' has no TOOL_SCOPES entry — classify it (Read/Run/Admin)"
            );
        }
        // The mission_* tools are dispatched by `static_tools::call` but are not in NAMES (they are not
        // advertised in `tools/list`); they must be classified too or they would be default-denied.
        for name in ["writ_mission_status", "writ_mission_respond", "writ_mission_cancel"] {
            assert!(tool_min_scope(name).is_some(), "{name} must be classified");
        }
        // No duplicate entries (a duplicate with a lower scope would silently win the `find`).
        let mut seen = std::collections::BTreeSet::new();
        for (n, _) in TOOL_SCOPES {
            assert!(seen.insert(*n), "duplicate TOOL_SCOPES entry for {n}");
        }
    }

    /// A `run`-scoped caller — exactly what every OAuth consent grants — may execute and read, but may
    /// NOT reach the tools that create or reconfigure durable state (all `Admin` over REST).
    #[test]
    fn run_scope_is_refused_admin_tools_and_allowed_run_tools() {
        let run = scoped("run");

        for tool in [
            "writ_create_automation",
            "writ_create_monitor",
            "writ_wire_monitor",
            "writ_set_schedule",
            "writ_expose_workflow_api",
            "writ_build",
            "writ_record_website",
            "writ_website_to_api",
            "writ_browser_save",
            "writ_install_api",
        ] {
            let err = authorize_tool(&run, tool).expect_err("{tool} must be refused to a run key");
            match err {
                CallError::Forbidden(msg) => {
                    assert!(msg.contains("admin"), "{tool}: message names the needed scope: {msg}");
                    assert!(msg.contains(tool), "{tool}: message names the tool: {msg}");
                }
                other => panic!("{tool}: expected Forbidden, got {other:?}"),
            }
        }

        // …while the execute + read surface it WAS granted keeps working.
        for tool in [
            "writ_run_workflow",
            "writ_browser_use",
            "writ_browser_act",
            "writ_scrape",
            "writ_map",
            "writ_crawl_site",
            "writ_list_workflows",
            "writ_workflow_data",
            "writ_search_data",
        ] {
            assert!(authorize_tool(&run, tool).is_ok(), "{tool} must be allowed with `run`");
        }

        // A workflow-derived tool (not `writ_*`) is a replay ⇒ `run`.
        assert!(authorize_tool(&run, "my_price_check").is_ok());
        assert!(authorize_tool(&scoped("read"), "my_price_check").is_err(), "read cannot execute");
    }

    /// The rest of the ladder: `read` reaches only read tools, `admin` reaches everything on this
    /// surface, the full-access UI/stdio caller is unrestricted, and an unclassified `writ_*` name is
    /// DEFAULT-DENIED instead of inheriting `Run`.
    #[test]
    fn scope_ladder_and_default_deny() {
        let read = scoped("read");
        assert!(authorize_tool(&read, "writ_list_workflows").is_ok());
        assert!(authorize_tool(&read, "writ_workflow_runs").is_ok());
        assert!(authorize_tool(&read, "writ_run_workflow").is_err(), "read must not execute");
        assert!(authorize_tool(&read, "writ_set_schedule").is_err());

        let admin = scoped("admin");
        for (name, _) in TOOL_SCOPES {
            assert!(authorize_tool(&admin, name).is_ok(), "admin may call {name}");
        }

        for (name, _) in TOOL_SCOPES {
            assert!(authorize_tool(&Caller::FullAccess, name).is_ok(), "wlt_/stdio may call {name}");
        }

        // Reserved prefix, unknown name → refused for EVERY caller that is not full-access, including
        // admin: a new tool must be classified deliberately.
        for caller in [scoped("read"), scoped("run"), scoped("admin"), scoped("manage")] {
            assert!(
                matches!(authorize_tool(&caller, "writ_brand_new_tool"), Err(CallError::Forbidden(_))),
                "an unclassified writ_* tool must be default-denied for {}",
                caller.describe()
            );
        }

        // A caller with no grant at all (missing/failed auth) reaches nothing.
        let none = scoped("");
        assert!(authorize_tool(&none, "writ_list_workflows").is_err());
        assert!(authorize_tool(&none, "my_price_check").is_err());
    }

    #[test]
    fn success_result_is_text_content() {
        let rr = RunResult {
            run_id: 7,
            status: RunStatus::Success,
            success: true,
            error: None,
            extracted_data: json!({ "price": 19.99 }),
            duration_ms: 12,
        };
        let v = to_mcp_result(&rr);
        assert_eq!(v["isError"], false);
        assert_eq!(v["content"][0]["type"], "text");
        assert!(v["content"][0]["text"].as_str().unwrap().contains("price"));
    }

    #[test]
    fn lift_file_slots_moves_handles_into_files_map() {
        // A workflow whose upload step declares a `resume` file slot.
        let steps = r#"[
            {"type":"goto","config":{"url":"{{input.target_url}}"}},
            {"type":"upload","config":{"file_slot":"resume","selector":".cv"}}
        ]"#;
        let mut inputs = json!({ "target_url": "https://x", "resume": "file_abc123" });
        lift_file_slots(&mut inputs, steps);

        // The slot key is removed from the plain inputs and lifted into `files`.
        assert!(
            inputs.get("resume").is_none(),
            "slot arg removed from plain inputs"
        );
        assert_eq!(
            inputs["target_url"], "https://x",
            "non-slot input untouched"
        );
        let files = &inputs["files"];
        assert_eq!(files["file_abc123"]["file_id"], "file_abc123");
        assert_eq!(files["file_abc123"]["slots"], json!(["resume"]));
    }

    #[test]
    fn lift_file_slots_noop_without_slots_or_handle() {
        // No declared slots → inputs unchanged.
        let steps = r#"[{"type":"click","config":{"selector":".go"}}]"#;
        let mut inputs = json!({ "resume": "file_abc" });
        lift_file_slots(&mut inputs, steps);
        assert_eq!(inputs["resume"], "file_abc");
        assert!(inputs.get("files").is_none());

        // Slot declared but caller passed no handle for it → no `files` map created.
        let steps2 = r#"[{"type":"upload","config":{"file_slot":"resume"}}]"#;
        let mut inputs2 = json!({ "other": "v" });
        lift_file_slots(&mut inputs2, steps2);
        assert!(inputs2.get("files").is_none());
        assert_eq!(inputs2["other"], "v");
    }

    #[test]
    fn failed_result_sets_is_error() {
        let rr = RunResult {
            run_id: 8,
            status: RunStatus::Failed,
            success: false,
            error: Some("selector not found".into()),
            extracted_data: Value::Null,
            duration_ms: 3,
        };
        let v = to_mcp_result(&rr);
        assert_eq!(v["isError"], true);
        assert!(v["content"][0]["text"]
            .as_str()
            .unwrap()
            .contains("selector not found"));
    }
}
