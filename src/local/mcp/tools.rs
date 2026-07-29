//! MCP `tools/list` catalog construction from the local workflow store.
//!
//! Every ENABLED workflow (`is_active = 1`) becomes one MCP tool. The tool `name` is a sanitized
//! form of the workflow name (lowercased, non-alnum → `_`), falling back to `workflow_<id>` when the
//! sanitized name is empty or collides. The `inputSchema` is derived BEST-EFFORT by scanning the raw
//! `steps` JSON-TEXT for `{{input.NAME}}` placeholders — every distinct `NAME` becomes a required
//! string property. `{{secret:...}}` placeholders are deliberately EXCLUDED: secrets are resolved
//! from the encrypted vault at run time, never passed by the MCP caller.
//!
//! We scan the raw text rather than parsing the step tree so the derivation is resilient to schema
//! drift and to placeholders nested anywhere (selectors, urls, values, scripts). House style:
//! runtime sqlx via the store; `tracing` only; no `async-trait`.

use crate::local::error::LocalResult;
use crate::local::server::AppState;
use crate::local::store::workflows::{self, Workflow};
use serde_json::{json, Value};
use std::collections::BTreeSet;

/// A resolved MCP tool plus the workflow id it dispatches to. `tool_executor` builds the same map to
/// route `tools/call`; `list_tools` projects just the public `name/description/inputSchema`.
#[derive(Debug, Clone)]
pub struct ToolEntry {
    pub name: String,
    pub workflow_id: i64,
    pub description: String,
    pub input_schema: Value,
}

impl ToolEntry {
    /// The public MCP tool shape returned in `tools/list`.
    pub fn to_public(&self) -> Value {
        json!({
            "name": self.name,
            "description": self.description,
            "inputSchema": self.input_schema,
        })
    }
}

/// Build the full tool catalog (one entry per enabled workflow). Shared by `list_tools` (rendering)
/// and `tool_executor::call_tool` (routing) so the name→workflow mapping is single-sourced.
pub async fn catalog(state: &AppState) -> LocalResult<Vec<ToolEntry>> {
    // `active_only = true` → only enabled workflows are exposed as tools.
    let rows = workflows::list(&state.db, true, 1000).await?;
    // Reserve the static `writ_*` names so a workflow named like one can never shadow it (it falls
    // back to `workflow_<id>` instead).
    let mut used: BTreeSet<String> = super::static_tools::NAMES
        .iter()
        .map(|s| s.to_string())
        .collect();
    let mut out = Vec::with_capacity(rows.len());
    for wf in &rows {
        // Connect → MCP surface OFF: this workflow is excluded from the catalog, which single-sources
        // BOTH `tools/list` (hidden) and `tools/call` (resolves via this catalog → UnknownTool).
        if !wf.connect_surfaces().mcp {
            continue;
        }
        let name = unique_tool_name(wf, &mut used);
        let description = tool_description(wf);
        let input_schema = derive_input_schema(wf);
        out.push(ToolEntry {
            name,
            workflow_id: wf.id,
            description,
            input_schema,
        });
    }
    Ok(out)
}

/// Project the full public `tools/list` array: the static `writ_*` tools first (create/manage),
/// then one tool per enabled workflow (replay).
///
/// Cloud-marketplace tools (`static_tools::CLOUD_LINKED_NAMES`) are only ADVERTISED when the app
/// is linked to a Writ Cloud account — an unlinked/local-only install never proposes marketplace
/// search/install. Their handlers re-check the link at call time (clients may cache an old list),
/// so filtering here is presentation, not the security gate.
pub async fn list_tools(state: &AppState) -> LocalResult<Vec<Value>> {
    let mut out = super::static_tools::entries();
    #[cfg(feature = "cloud")]
    {
        let linked = crate::local::cloud::state::LinkState::load_or_default(&state.db)
            .await?
            .is_linked();
        if !linked {
            out.retain(|t| {
                t["name"]
                    .as_str()
                    .map_or(true, |n| !super::static_tools::CLOUD_LINKED_NAMES.contains(&n))
            });
        }
    }
    out.extend(catalog(state).await?.iter().map(ToolEntry::to_public));
    Ok(out)
}

/// Pick a stable, unique tool name for a workflow. Sanitized name first; `workflow_<id>` fallback
/// when empty or already taken (de-dup is order-stable: the store lists newest-first).
fn unique_tool_name(wf: &Workflow, used: &mut BTreeSet<String>) -> String {
    let mut name = sanitize(&wf.name);
    if name.is_empty() || used.contains(&name) {
        name = format!("workflow_{}", wf.id);
    }
    // Extremely unlikely, but guarantee uniqueness even against a synthetic collision.
    if used.contains(&name) {
        name = format!("workflow_{}", wf.id);
    }
    used.insert(name.clone());
    name
}

/// Sanitize a workflow name into an MCP/tool-safe token: lowercase, `[a-z0-9_]`, collapsed and
/// trimmed underscores. Empty result signals "fall back to `workflow_<id>`".
pub fn sanitize(name: &str) -> String {
    let mut out = String::with_capacity(name.len());
    let mut last_us = false;
    for ch in name.trim().chars() {
        let c = ch.to_ascii_lowercase();
        if c.is_ascii_alphanumeric() {
            out.push(c);
            last_us = false;
        } else if !last_us {
            out.push('_');
            last_us = true;
        }
    }
    out.trim_matches('_').to_string()
}

/// Human-readable tool description: workflow description, else a generated "Run <name>" line.
fn tool_description(wf: &Workflow) -> String {
    match wf.description.as_deref() {
        Some(d) if !d.trim().is_empty() => d.trim().to_string(),
        _ => format!("Run the \"{}\" workflow.", wf.name),
    }
}

/// Derive a JSON Schema for a workflow's callable arguments. Two sources are merged:
///   * `{{input.NAME}}` placeholders scanned from the raw `steps` text — each distinct `NAME` → a
///     REQUIRED string property. `{{secret:...}}` is excluded by construction (only the `input.`
///     namespace is matched; secrets resolve from the vault at run time, never from the MCP caller).
///   * declared upload-step `file_slot` names — each distinct slot → an OPTIONAL string property
///     whose value is a stored-file handle (`file_<...>`) the caller binds to that slot. File slots
///     are optional (a workflow may run against already-bound files) and never duplicate an input
///     property of the same name.
///
/// When neither source yields anything we return an empty object schema (no caller arguments).
pub fn derive_input_schema(wf: &Workflow) -> Value {
    let names = scan_input_placeholders(&wf.steps);
    let slots = scan_file_slots(&wf.steps);

    let mut properties = serde_json::Map::new();
    let mut required = Vec::with_capacity(names.len());
    for name in &names {
        properties.insert(
            name.clone(),
            json!({ "type": "string", "description": format!("Input: {name}") }),
        );
        required.push(Value::String(name.clone()));
    }
    // Merge file slots as OPTIONAL string (file-handle) properties. Skip any slot that collides with
    // an already-declared input property so we never shadow a required input.
    for slot in &slots {
        if properties.contains_key(slot) {
            continue;
        }
        properties.insert(
            slot.clone(),
            json!({
                "type": "string",
                "description": format!("File slot: stored-file handle (file_…) to upload for '{slot}'"),
            }),
        );
    }

    // Advertise the freshness control so `max_age` works the same whether an agent calls
    // writ_run_workflow or this workflow's own derived tool. Only when nothing already claims the
    // name: a workflow that genuinely declares a `max_age` input keeps its own meaning, and the
    // runner would treat it as an input in that case anyway.
    properties
        .entry(super::tool_executor::FRESHNESS_ARG.to_string())
        .or_insert_with(|| {
            json!({
                "type": "integer",
                "minimum": 0,
                "description": "Reuse a previous result if it is younger than this many seconds, \
                                instead of running the workflow again. 0 (the default) always runs \
                                fresh — much faster and cheaper when a recent answer will do.",
            })
        });

    json!({
        "type": "object",
        "properties": Value::Object(properties),
        "required": required,
    })
}

/// Collect the distinct `file_slot` names declared by upload steps in a workflow's `steps` JSON.
///
/// Recorded steps are heterogeneous JSON; a `file_slot` can live at the step's top level or inside a
/// `config` object (mirroring how the engine reads step config). Rather than commit to one shape we
/// walk the parsed JSON tree and collect every string value keyed `"file_slot"`. Order-preserving
/// (first-seen). If `steps` is not valid JSON we return nothing (best-effort, like the input scan).
pub fn scan_file_slots(steps_text: &str) -> Vec<String> {
    let parsed: Value = match serde_json::from_str(steps_text) {
        Ok(v) => v,
        Err(_) => return Vec::new(),
    };
    let mut out: Vec<String> = Vec::new();
    let mut seen: BTreeSet<String> = BTreeSet::new();
    collect_file_slots(&parsed, &mut out, &mut seen);
    out
}

/// Recursive helper for [`scan_file_slots`]: collect every non-empty string value under a
/// `"file_slot"` key anywhere in the JSON tree.
fn collect_file_slots(value: &Value, out: &mut Vec<String>, seen: &mut BTreeSet<String>) {
    match value {
        Value::Object(map) => {
            if let Some(Value::String(slot)) = map.get("file_slot") {
                if !slot.is_empty() && seen.insert(slot.clone()) {
                    out.push(slot.clone());
                }
            }
            for v in map.values() {
                collect_file_slots(v, out, seen);
            }
        }
        Value::Array(items) => {
            for v in items {
                collect_file_slots(v, out, seen);
            }
        }
        _ => {}
    }
}

/// The set of distinct input NAMEs referenced as `{{input.NAME}}` in a steps text blob.
/// Order-preserving (first-seen) so the schema is deterministic for a given workflow. Allowed name
/// chars: `[A-Za-z0-9_.-]` (mirrors the cloud placeholder grammar). Whitespace around the name and
/// inside the braces is tolerated (`{{ input.foo }}`). `secret:` is never matched here.
pub fn scan_input_placeholders(steps_text: &str) -> Vec<String> {
    const OPEN: &str = "{{";
    const PREFIX: &str = "input.";
    let mut names: Vec<String> = Vec::new();
    let mut seen: BTreeSet<String> = BTreeSet::new();
    let bytes = steps_text.as_bytes();
    let mut i = 0usize;
    while let Some(rel) = steps_text[i..].find(OPEN) {
        let mut p = i + rel + OPEN.len();
        // Skip whitespace after `{{`.
        while p < bytes.len() && bytes[p].is_ascii_whitespace() {
            p += 1;
        }
        // Must be the `input.` namespace (case-sensitive, like the cloud engine).
        if steps_text[p..].starts_with(PREFIX) {
            let name_start = p + PREFIX.len();
            let mut q = name_start;
            while q < bytes.len() {
                let c = bytes[q];
                if c.is_ascii_alphanumeric() || matches!(c, b'_' | b'.' | b'-') {
                    q += 1;
                } else {
                    break;
                }
            }
            let name = &steps_text[name_start..q];
            // Tolerate trailing whitespace then require the closing `}}`.
            let mut r = q;
            while r < bytes.len() && bytes[r].is_ascii_whitespace() {
                r += 1;
            }
            if !name.is_empty()
                && steps_text[r..].starts_with("}}")
                && seen.insert(name.to_string())
            {
                names.push(name.to_string());
            }
        }
        // Advance past this `{{` so we don't re-match it.
        i = i + rel + OPEN.len();
    }
    names
}

/// Input discovery shared by MCP execution and the desktop fast-run behavior. Includes canonical
/// `{{input.NAME}}` and legacy bare `{{NAME}}`, while excluding every namespaced reference
/// (`secret:`, `vault:`, `file:`, `extracted:`). Values are returned in first-seen order.
pub fn scan_all_input_placeholders(steps_text: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut seen = BTreeSet::new();
    let bytes = steps_text.as_bytes();
    let mut i = 0usize;
    while let Some(rel) = steps_text[i..].find("{{") {
        let start = i + rel + 2;
        let Some(close_rel) = steps_text[start..].find("}}") else {
            break;
        };
        let end = start + close_rel;
        let raw = steps_text[start..end].trim();
        if !raw.is_empty()
            && !raw.contains(':')
            && raw
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '.' | '-'))
        {
            let normalized = raw.to_string();
            if seen.insert(normalized.clone()) {
                out.push(normalized);
            }
        }
        i = end + 2;
        if i >= bytes.len() {
            break;
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sanitize_basics() {
        assert_eq!(sanitize("My Cool Workflow"), "my_cool_workflow");
        assert_eq!(sanitize("  Trim--Me!! "), "trim_me");
        assert_eq!(sanitize("___"), "");
        assert_eq!(sanitize("Order #42: Buy"), "order_42_buy");
    }

    #[test]
    fn scans_input_placeholders_excluding_secrets() {
        let steps = r#"[
            {"type":"goto","url":"{{input.target_url}}"},
            {"type":"fill","value":"{{ input.username }}"},
            {"type":"fill","value":"{{secret:login_password}}"},
            {"type":"fill","value":"{{input.target_url}}"}
        ]"#;
        let names = scan_input_placeholders(steps);
        assert_eq!(
            names,
            vec!["target_url".to_string(), "username".to_string()]
        );
        // Secret placeholder is never surfaced as a callable arg.
        assert!(!names.iter().any(|n| n.contains("password")));
    }

    #[test]
    fn scans_canonical_and_bare_inputs_for_fast_run_parity() {
        let steps = r#"[{"value":"{{input.city}}"},{"value":"{{ password }}"},{"value":"{{secret:token}}"},{"value":"{{extracted:id}}"}]"#;
        assert_eq!(
            scan_all_input_placeholders(steps),
            vec!["input.city".to_string(), "password".to_string()]
        );
    }

    #[test]
    fn schema_has_required_string_props() {
        let steps = r#"{"a":"{{input.foo}}","b":"{{input.bar}}"}"#;
        // Build a minimal Workflow with just the fields the deriver reads.
        let wf = make_wf(1, "x", steps);
        let schema = derive_input_schema(&wf);
        assert_eq!(schema["type"], "object");
        assert_eq!(schema["properties"]["foo"]["type"], "string");
        assert_eq!(schema["required"], json!(["foo", "bar"]));
    }

    /// A workflow with no placeholders declares no INPUTS — only the freshness control every derived
    /// run tool carries, so `max_age` is discoverable on a workflow's own tool and not just on
    /// writ_run_workflow.
    #[test]
    fn no_inputs_yields_controls_only_schema() {
        let wf = make_wf(2, "y", r#"[{"type":"goto","url":"https://x"}]"#);
        let schema = derive_input_schema(&wf);
        assert_eq!(schema["required"], json!([]));
        let props = schema["properties"].as_object().expect("properties object");
        assert_eq!(
            props.keys().collect::<Vec<_>>(),
            vec!["max_age"],
            "no inputs ⇒ the freshness control is the only advertised property"
        );
        assert_eq!(props["max_age"]["type"], "integer");
    }

    /// A workflow that genuinely declares an input called `max_age` keeps ITS meaning — the control
    /// must never shadow a real placeholder.
    #[test]
    fn a_declared_max_age_input_is_not_shadowed_by_the_control() {
        let wf = make_wf(3, "z", r#"[{"type":"type","value":"{{input.max_age}}"}]"#);
        let schema = derive_input_schema(&wf);
        assert_eq!(schema["properties"]["max_age"]["type"], "string");
        assert_eq!(
            schema["properties"]["max_age"]["description"], "Input: max_age",
            "the workflow's own declaration wins"
        );
        assert_eq!(schema["required"], json!(["max_age"]));
    }

    #[test]
    fn scans_file_slots_top_level_and_nested() {
        let steps = r#"[
            {"type":"upload","file_slot":"resume"},
            {"type":"upload","config":{"file_slot":"cover_letter"}},
            {"type":"upload","config":{"file_slot":"resume"}}
        ]"#;
        let slots = scan_file_slots(steps);
        assert_eq!(
            slots,
            vec!["resume".to_string(), "cover_letter".to_string()]
        );
        // Non-JSON steps → no slots (best-effort).
        assert!(scan_file_slots("not json").is_empty());
    }

    #[test]
    fn schema_merges_file_slots_as_optional_string_props() {
        // `target_url` is a required input; `resume` is an optional file slot.
        let steps = r#"[
            {"type":"goto","config":{"url":"{{input.target_url}}"}},
            {"type":"upload","config":{"file_slot":"resume"}}
        ]"#;
        let wf = make_wf(3, "apply", steps);
        let schema = derive_input_schema(&wf);
        assert_eq!(schema["properties"]["target_url"]["type"], "string");
        assert_eq!(schema["properties"]["resume"]["type"], "string");
        // The input is required; the file slot is NOT.
        assert_eq!(schema["required"], json!(["target_url"]));
    }

    #[test]
    fn input_property_wins_over_same_named_file_slot() {
        // A workflow that both reads `{{input.doc}}` and declares a `doc` file slot: the required
        // input property must not be shadowed by the optional file-slot property.
        let steps = r#"[
            {"type":"fill","config":{"value":"{{input.doc}}"}},
            {"type":"upload","config":{"file_slot":"doc"}}
        ]"#;
        let wf = make_wf(4, "dup", steps);
        let schema = derive_input_schema(&wf);
        assert_eq!(schema["required"], json!(["doc"]), "input stays required");
        assert!(
            schema["properties"]["doc"]["description"]
                .as_str()
                .unwrap()
                .starts_with("Input:"),
            "the input property (not the file-slot one) is kept"
        );
    }

    fn make_wf(id: i64, name: &str, steps: &str) -> Workflow {
        Workflow {
            id,
            name: name.into(),
            description: None,
            workflow_type: "recorded".into(),
            steps: steps.into(),
            raw_replay: None,
            form_data: None,
            exit_condition: None,
            input_rules: None,
            api_functions: None,
            streaming_config: None,
            functions: None,
            credentials_encrypted: None,
            entry_url: None,
            timeout_ms: 0,
            retry_count: 0,
            headless: 1,
            fast_mode: 0,
            is_active: 1,
            is_verified: 0,
            schedule_enabled: 0,
            schedule_interval_ms: None,
            schedule_kind: None,
            schedule_time: None,
            schedule_days: None,
            schedule_tz: None,
            last_scheduled_at: None,
            next_scheduled_at: None,
            session_persistence: 0,
            session_ttl_seconds: None,
            login_url_patterns: None,
            relogin_max_retries: 0,
            http_capable: -1,
            auth_config: None,
            default_persona_id: None,
            estimated_duration_ms: None,
            usage_count: 0,
            total_run_count: 0,
            total_failure_count: 0,
            consecutive_failures: 0,
            last_run_at: None,
            last_run_status: None,
            last_run_duration_ms: None,
            last_run_has_extracted_data: None,
            last_failure_at: None,
            last_failure_error: None,
            cloud_callable: 0,
            execution_target: None,
            ai_repair_enabled: 0,
            last_repaired_at: None,
            marketplace_slug: None,
            created_at: "2026-01-01T00:00:00Z".into(),
            updated_at: None,
        }
    }
}
