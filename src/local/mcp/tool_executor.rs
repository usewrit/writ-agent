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
    // Read for list/get; the operating actions (sign_in / record_login) drive a
    // real login run, so they escalate to Run via `arg_escalated_scope`. The tool
    // has no create/update/delete at all — persona lifecycle stays with the vault
    // on the "not reachable from this surface" side of the line above.
    ("writ_personas", Scope::Read),
    ("writ_list_workflows", Scope::Read),
    ("writ_workflow_data", Scope::Read),
    ("writ_workflow_runs", Scope::Read),
    ("writ_list_datasets", Scope::Read),
    ("writ_dataset", Scope::Read),
    ("writ_dataset_search", Scope::Read),
    ("writ_search_data", Scope::Read),
    ("writ_crawl_status", Scope::Read),
    ("writ_saved_crawls", Scope::Read),
    ("writ_saved_crawl_data", Scope::Read),
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
    // Run to START a crawl; `save_as` escalates to Admin via `arg_escalated_scope` because it also
    // creates a saved, API-callable crawl (REST parity with POST /v1/crawl/definitions).
    ("writ_crawl_site", Scope::Run),
    ("writ_run_saved_crawl", Scope::Run),
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

/// Tools whose required scope depends on their ARGUMENTS, not just their name.
/// Returns the escalated scope plus a short description of the escalating
/// operation, for the refusal message.
///
/// `writ_crawl_site` is `Run` — starting a crawl is execution. But `save_as` makes it also CREATE a
/// saved crawl, and creating one over REST (`POST /v1/crawl/definitions`) requires `Admin`. Without
/// this escalation the MCP surface would be strictly more permissive than the REST surface for the
/// same action, which is exactly the kind of gap a scoped key is supposed to close.
///
/// `writ_personas` is `Read` — listing/inspecting identities reports what exists. But
/// `sign_in` runs the persona's login workflow and `record_login` launches an AI session
/// that drives a real browser: both are execution, so they need what a run costs.
fn arg_escalated_scope(name: &str, arguments: &Value) -> Option<(Scope, &'static str)> {
    if name == "writ_crawl_site"
        && arguments
            .get("save_as")
            .and_then(Value::as_str)
            .map(|s| !s.trim().is_empty())
            .unwrap_or(false)
    {
        return Some((Scope::Admin, "saving a crawl with `save_as` (it creates a reusable, API-callable crawl); omit `save_as` to just run it"));
    }
    if name == "writ_personas"
        && matches!(
            arguments.get("action").and_then(Value::as_str).map(str::trim),
            Some("sign_in") | Some("record_login")
        )
    {
        return Some((Scope::Run, "signing a persona in (it runs a real login in a browser)"));
    }
    None
}

/// Gate one `tools/call` on the caller's capability.
///
/// DEFAULT-DENY for the reserved `writ_` prefix: an unclassified `writ_*` name cannot be reached, so
/// adding a static tool without a [`TOOL_SCOPES`] entry fails closed instead of inheriting `Run`.
/// Everything else is a workflow-derived tool — replaying a saved workflow is execution, hence `Run`
/// (the per-workflow Connect → MCP toggle is enforced separately by `tools::catalog`).
///
/// `arguments` participates because a few tools' authority depends on what they are asked to DO, not
/// only which tool it is — see [`arg_escalated_scope`].
fn authorize_tool(caller: &Caller, name: &str, arguments: &Value) -> Result<(), CallError> {
    if let Some((escalated, operation)) = arg_escalated_scope(name, arguments) {
        if !caller.grants(escalated) {
            tracing::warn!(
                tool = %name,
                caller = caller.describe(),
                required = escalated.as_str(),
                "mcp: tools/call refused — this argument combination needs a broader capability"
            );
            return Err(CallError::Forbidden(format!(
                "Not authorized: {} requires the '{}' capability, but this connection was granted \
                 '{}'. Reconnect with an '{}'-scoped API key, or stay within this tool's \
                 lower-capability operations.",
                operation,
                escalated.as_str(),
                caller.describe(),
                escalated.as_str(),
            )));
        }
    }
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
    authorize_tool(caller, name, &arguments)?;
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

    // ── Freshness (`max_age`) ────────────────────────────────────────────────
    // Running a workflow drives a real browser, so an agent asking the same question twice pays and
    // waits twice. `max_age` lets the CALLER say a recent answer is acceptable. Opt-in: absent or 0
    // always runs, so no existing agent silently starts getting stale data.
    //
    // Stripped from `inputs` BEFORE anything else reads them — leaving it in would both feed a stray
    // `max_age` into the workflow's `{{input.*}}` values and give every distinct max_age its own
    // cache key, which is the opposite of asking for a reusable answer.
    let requested_max_age = inputs
        .get(FRESHNESS_ARG)
        .and_then(Value::as_i64)
        .unwrap_or(0)
        .max(0);
    if let Some(obj) = inputs.as_object_mut() {
        obj.remove(FRESHNESS_ARG);
    }
    let freshness_key = freshness_key(workflow_id, &inputs);
    if requested_max_age > 0 {
        if let Some(hit) = cached_run(&freshness_key, requested_max_age) {
            return Ok(hit);
        }
    }

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
    // Run-AS-persona override (parity with cloud/self-host writ_run_workflow and the crawl tools):
    // an explicit `persona` (id or name) runs this workflow signed in as that saved identity instead
    // of the workflow's default. Resolved + STRIPPED only on the non-marketplace path — a marketplace
    // proxy row binds its persona through the install manifest (`marketplace_gate` reads `persona`
    // from inputs itself), so we must not consume it out from under that flow. Because `persona` is
    // still in `inputs` when `freshness_key` was computed above, an as-persona run is already keyed
    // apart from an anonymous one — a cached logged-out answer can never satisfy a persona run.
    let mut persona_override: Option<i64> = None;
    if let Some(wf) = workflows::get_by_id(&state.db, workflow_id).await? {
        if wf.marketplace_slug.as_deref().is_some_and(|s| !s.is_empty()) {
            if let Some(prompt) = marketplace_gate(state, &wf, &mut inputs).await? {
                return Ok(prompt);
            }
        } else {
            let persona_arg = inputs
                .as_object_mut()
                .and_then(|o| o.remove("persona"))
                .filter(|v| !v.is_null());
            if let Some(v) = persona_arg {
                persona_override = Some(super::static_tools::resolve_persona(state, &v).await?);
            }
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
        persona_id: persona_override,
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

    let mcp_result = to_mcp_result(&result);
    store_run(&freshness_key, &mcp_result);
    Ok(mcp_result)
}

// ── Result reuse (the `max_age` tool argument) ───────────────────────────────
//
// In-process and bounded rather than durable storage: this is a latency/cost optimisation on an
// explicitly-approximate request, so a miss after a daemon restart just means the workflow runs —
// exactly what would have happened before. Nothing depends on it for correctness.
//
// Deliberately the same argument name, `_cache` stamp shape and success-only rule as the cloud and
// self-host MCP servers, so `max_age` behaves identically wherever an agent connects.

/// The tool argument that carries the caller's freshness ceiling.
pub(crate) const FRESHNESS_ARG: &str = "max_age";

const RESULT_CACHE_MAX: usize = 256;

type ResultCache = std::collections::HashMap<String, (std::time::Instant, Value)>;

fn result_cache() -> &'static std::sync::Mutex<ResultCache> {
    static CACHE: std::sync::OnceLock<std::sync::Mutex<ResultCache>> = std::sync::OnceLock::new();
    CACHE.get_or_init(|| std::sync::Mutex::new(ResultCache::new()))
}

/// Identity of one answerable question.
///
/// The INPUTS are part of the key. Without them a workflow taking a parameter would serve the first
/// caller's answer to every subsequent one — a wrong result that looks perfectly valid, which is the
/// worst kind. Keys are canonicalized by sorting so argument order never splits the cache.
fn freshness_key(workflow_id: i64, inputs: &Value) -> String {
    let canonical = match inputs.as_object() {
        Some(map) => {
            let mut pairs: Vec<(&String, &Value)> = map.iter().collect();
            pairs.sort_by(|a, b| a.0.cmp(b.0));
            pairs
                .iter()
                .map(|(k, v)| format!("{k}={v}"))
                .collect::<Vec<_>>()
                .join("&")
        }
        None => String::new(),
    };
    format!("{workflow_id}:{canonical}")
}

/// A stored result younger than `max_age_seconds`, stamped so the agent can tell it was reused.
fn cached_run(key: &str, max_age_seconds: i64) -> Option<Value> {
    let cache = result_cache().lock().ok()?;
    let (stored_at, result) = cache.get(key)?;
    let age = stored_at.elapsed().as_secs() as i64;
    // `<= 0` is not redundant with the age check: a freshly stored entry has age 0, so a bare
    // `age > max_age` would treat max_age=0 as a HIT — the exact opposite of "always run fresh".
    // Callers guard on this too, but the rule belongs with the function that implements it.
    if max_age_seconds <= 0 || age > max_age_seconds {
        return None;
    }
    let mut out = result.clone();
    if let Some(obj) = out.as_object_mut() {
        obj.insert(
            "_cache".into(),
            json!({ "hit": true, "age_seconds": age }),
        );
    }
    Some(out)
}

/// Store a SUCCESSFUL result for reuse. A stored failure served back as if it were an answer would be
/// worse than re-running, so errors are never cached.
fn store_run(key: &str, result: &Value) {
    if result.get("isError").and_then(Value::as_bool).unwrap_or(false) {
        return;
    }
    let Ok(mut cache) = result_cache().lock() else {
        return;
    };
    if cache.len() >= RESULT_CACHE_MAX {
        // Bounded, and evicting the OLDEST keeps the entries most likely to still be asked for.
        if let Some(oldest) = cache
            .iter()
            .min_by_key(|(_, (at, _))| *at)
            .map(|(k, _)| k.clone())
        {
            cache.remove(&oldest);
        }
    }
    cache.insert(key.to_string(), (std::time::Instant::now(), result.clone()));
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
/// when the workflow has no upload steps.
///
/// Uses `scan_file_inputs`, not `scan_file_slots`: an upload step that merely PINS a
/// file is addressable as `step:<id>`, and a caller passing that key means "run against
/// this file instead". The engine resolves a slot binding ahead of the pinned file, so
/// lifting it here is what makes the override take effect.
fn lift_file_slots(inputs: &mut Value, steps_text: &str) {
    let slots = super::tools::scan_file_inputs(steps_text);
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

    /// Empty tool arguments — the common case for a name-only authorization assertion.
    fn no_args() -> Value {
        json!({})
    }

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
            let err = authorize_tool(&run, tool, &no_args()).expect_err("{tool} must be refused to a run key");
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
            assert!(authorize_tool(&run, tool, &no_args()).is_ok(), "{tool} must be allowed with `run`");
        }

        // A workflow-derived tool (not `writ_*`) is a replay ⇒ `run`.
        assert!(authorize_tool(&run, "my_price_check", &no_args()).is_ok());
        assert!(authorize_tool(&scoped("read"), "my_price_check", &no_args()).is_err(), "read cannot execute");
    }

    /// `save_as` on writ_crawl_site CREATES a saved, API-callable crawl, which is an `Admin` mutation
    /// over REST. The MCP surface must not be the cheaper door: a `run` key may crawl, but not save.
    #[test]
    fn saving_a_crawl_needs_admin_even_though_crawling_needs_only_run() {
        let run = scoped("run");

        // Plain crawl: allowed with `run`.
        assert!(authorize_tool(&run, "writ_crawl_site", &json!({ "url": "https://example.com" })).is_ok());

        // Same tool, but asked to SAVE — refused, and the message says why and how to proceed.
        let err = authorize_tool(
            &run,
            "writ_crawl_site",
            &json!({ "url": "https://example.com", "save_as": "docs" }),
        )
        .expect_err("save_as must require admin");
        match err {
            CallError::Forbidden(msg) => {
                assert!(msg.contains("admin"), "names the needed scope: {msg}");
                assert!(msg.contains("save_as"), "names the offending argument: {msg}");
            }
            other => panic!("expected Forbidden, got {other:?}"),
        }

        // A blank/whitespace save_as is not a save request and must not escalate.
        assert!(authorize_tool(&run, "writ_crawl_site", &json!({ "url": "u", "save_as": "   " })).is_ok());

        // Admin may save.
        assert!(authorize_tool(
            &scoped("admin"),
            "writ_crawl_site",
            &json!({ "url": "u", "save_as": "docs" })
        )
        .is_ok());
    }

    /// Personas: list/get are reads; sign_in/record_login run a real login and escalate to `run`.
    /// There is no create/update/delete action, so no path reaches `admin` — persona lifecycle is
    /// off this surface entirely (credentials never transit MCP).
    #[test]
    fn persona_tool_reads_freely_but_operating_needs_run() {
        let read = scoped("read");
        // Inspecting identities is a read.
        assert!(authorize_tool(&read, "writ_personas", &json!({ "action": "list" })).is_ok());
        assert!(authorize_tool(&read, "writ_personas", &json!({ "action": "get", "persona_id": 7 })).is_ok());
        // Default action (list) is also a read.
        assert!(authorize_tool(&read, "writ_personas", &no_args()).is_ok());

        // Signing in runs a browser login — refused for a read-only key, with an actionable message.
        let err = authorize_tool(&read, "writ_personas", &json!({ "action": "sign_in", "persona_id": 7 }))
            .expect_err("sign_in must require run");
        match err {
            CallError::Forbidden(msg) => assert!(msg.contains("run"), "names the needed scope: {msg}"),
            other => panic!("expected Forbidden, got {other:?}"),
        }
        assert!(
            authorize_tool(&read, "writ_personas", &json!({ "action": "record_login", "persona_id": 7 })).is_err(),
            "record_login must require run"
        );

        // A `run` key may operate.
        let run = scoped("run");
        assert!(authorize_tool(&run, "writ_personas", &json!({ "action": "sign_in", "persona_id": 7 })).is_ok());
        assert!(authorize_tool(&run, "writ_personas", &json!({ "action": "record_login", "persona_id": 7 })).is_ok());
    }

    /// Reading saved crawls is a read; running one is execution.
    #[test]
    fn saved_crawl_tools_sit_on_the_expected_rungs() {
        let read = scoped("read");
        assert!(authorize_tool(&read, "writ_saved_crawls", &no_args()).is_ok());
        assert!(authorize_tool(&read, "writ_saved_crawl_data", &no_args()).is_ok());
        assert!(
            authorize_tool(&read, "writ_run_saved_crawl", &no_args()).is_err(),
            "read must not be able to launch a crawl"
        );
        assert!(authorize_tool(&scoped("run"), "writ_run_saved_crawl", &no_args()).is_ok());
    }

    /// `max_age` must never reach the workflow as an input, and a cached answer must be keyed by the
    /// inputs that produced it — otherwise a parameterised workflow serves one caller's answer to
    /// everyone, which looks valid and is wrong.
    #[test]
    fn freshness_keys_include_inputs_and_ignore_argument_order() {
        let paris = freshness_key(7, &json!({ "city": "paris" }));
        let london = freshness_key(7, &json!({ "city": "london" }));
        assert_ne!(paris, london, "different inputs must not share a cache entry");

        let a = freshness_key(7, &json!({ "city": "paris", "zoom": 3 }));
        let b = freshness_key(7, &json!({ "zoom": 3, "city": "paris" }));
        assert_eq!(a, b, "argument order must not split the cache");

        assert_ne!(
            freshness_key(7, &json!({ "city": "paris" })),
            freshness_key(8, &json!({ "city": "paris" })),
            "different workflows must not share a cache entry"
        );
    }

    /// A stored FAILURE served back as if it were an answer would be worse than re-running.
    #[test]
    fn only_successful_results_are_reusable() {
        let ok_key = "freshness-test:ok";
        let err_key = "freshness-test:err";

        store_run(ok_key, &json!({ "content": [], "isError": false }));
        store_run(err_key, &json!({ "content": [], "isError": true }));

        let hit = cached_run(ok_key, 300).expect("a successful result is reusable");
        assert_eq!(hit["_cache"]["hit"], json!(true), "a reused answer is stamped");
        assert!(hit["_cache"]["age_seconds"].is_i64());

        assert!(cached_run(err_key, 300).is_none(), "a failed run must not be cached");
        // max_age=0 means "run it fresh" — an entry exists, but nothing may satisfy a zero window.
        assert!(cached_run(ok_key, 0).is_none(), "max_age=0 must always miss");
    }

    /// The rest of the ladder: `read` reaches only read tools, `admin` reaches everything on this
    /// surface, the full-access UI/stdio caller is unrestricted, and an unclassified `writ_*` name is
    /// DEFAULT-DENIED instead of inheriting `Run`.
    #[test]
    fn scope_ladder_and_default_deny() {
        let read = scoped("read");
        assert!(authorize_tool(&read, "writ_list_workflows", &no_args()).is_ok());
        assert!(authorize_tool(&read, "writ_workflow_runs", &no_args()).is_ok());
        assert!(authorize_tool(&read, "writ_run_workflow", &no_args()).is_err(), "read must not execute");
        assert!(authorize_tool(&read, "writ_set_schedule", &no_args()).is_err());

        let admin = scoped("admin");
        for (name, _) in TOOL_SCOPES {
            assert!(authorize_tool(&admin, name, &no_args()).is_ok(), "admin may call {name}");
        }

        for (name, _) in TOOL_SCOPES {
            assert!(authorize_tool(&Caller::FullAccess, name, &no_args()).is_ok(), "wlt_/stdio may call {name}");
        }

        // Reserved prefix, unknown name → refused for EVERY caller that is not full-access, including
        // admin: a new tool must be classified deliberately.
        for caller in [scoped("read"), scoped("run"), scoped("admin"), scoped("manage")] {
            assert!(
                matches!(authorize_tool(&caller, "writ_brand_new_tool", &no_args()), Err(CallError::Forbidden(_))),
                "an unclassified writ_* tool must be default-denied for {}",
                caller.describe()
            );
        }

        // A caller with no grant at all (missing/failed auth) reaches nothing.
        let none = scoped("");
        assert!(authorize_tool(&none, "writ_list_workflows", &no_args()).is_err());
        assert!(authorize_tool(&none, "my_price_check", &no_args()).is_err());
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
