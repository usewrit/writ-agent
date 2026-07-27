//! Automation **flow interpreter** — the local execution engine for an automation's block tree.
//!
//! An automation row carries a `blocks` JSON tree (the visual flow-builder graph): a single root
//! `event` block, then `condition` and `action` blocks linked by `parentId`. This module walks that
//! tree when the automation fires and actually RUNS it — the piece that was previously missing
//! locally (the monitor/webhook paths only ever dispatched the one linked `workflow_id`, ignoring
//! conditions, multiple actions, and branches).
//!
//! Semantics mirror the cloud `unified_trigger_service` *pragmatic subset*:
//!   * **condition** blocks gate their subtree (field/operator/value); a no-match stops THAT branch.
//!   * **action** blocks run in order; when a node has more than one child they are *parallel
//!     branches* — logically parallel (each forks the parent scope), executed **sequentially** (the
//!     cloud does the same, for store-safety, and the local engine shares ONE warm browser anyway).
//!   * supported actions: `workflow` (drive a recorded workflow via the engine), `return_data`
//!     (surface the collected output to the caller), and `notification` — delivered locally where
//!     possible (outbound webhook via HTTP + `in_app`/`desktop` recorded to the run feed); cloud
//!     channels (email/SMS/push/…) are recorded as skipped (`cloud_only_channel`). `ai_session`
//!     runs the local autonomous AI browser loop ([`crate::local::ai::session::run_session`]) toward
//!     a goal (inline config or a stored `ai_sessions` row), degrading to a recorded skip when no AI
//!     provider or browser is available. `create_persona` remains a deferred cloud-only no-op; it
//!     neither runs nor fails the execution.
//!
//! Back-compat: an automation with no `blocks` (or an empty tree) falls back to the legacy behavior —
//! run the single linked `workflow_id` if present, else record a no-op success.
//!
//! House style: thin orchestration over `store::{automations,automation_executions}` + the
//! `LocalEngine` seam; runtime-checked sqlx via the stores; `tracing` only, never logging payload
//! values; no `async-trait` (boxed recursive future for the tree walk).

use crate::local::engine::{Lane, LocalEngine, RunRequest, RunSource, RunStatus};
use crate::local::error::LocalResult;
use crate::local::store::automation_executions::{
    self, AutomationExecution, NewAutomationExecution,
};
use crate::local::store::automations::Automation;
use chrono::{DateTime, Duration as ChronoDuration, Utc};
use serde::Deserialize;
use serde_json::{json, Map, Value};
use sqlx::sqlite::SqlitePool;
use std::collections::HashMap;
use std::collections::VecDeque;
use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, Mutex, OnceLock};

/// Cap on a user-supplied regex pattern (`matches` operator) — a coarse ReDoS guard alongside the
/// compiled-size limit. Anything longer never compiles (condition evaluates false).
const MAX_REGEX_PATTERN_LEN: usize = 512;
/// Compiled-regex size ceiling (bytes). Bounds catastrophic patterns; build failure ⇒ false.
const REGEX_SIZE_LIMIT: usize = 1 << 20;

/// What fired the automation + the data its blocks can read. Built by each trigger site
/// (monitor / webhook / manual / workflow-event) and threaded through the walk.
pub struct FlowTrigger {
    /// `change_detected | webhook_received | workflow_started | workflow_completed | manual`.
    pub event: String,
    /// The detected-change id, when fired by the monitor (stamped on the execution row).
    pub change_id: Option<i64>,
    /// Inputs handed to every `workflow` action this flow runs (e.g. the mapped webhook payload).
    pub base_inputs: Value,
    /// Initial scope the blocks see — the fields `condition`/`return_data` read (e.g. `payload.*`,
    /// `content`, `success`, `result.*`). MUST be a JSON object; a non-object is ignored.
    pub context: Value,
    /// Engine run source for any `workflow` action (billing/trigger-type stamp on the `runs` row).
    pub source: RunSource,
    /// Engine lane for any `workflow` action (interactive priority vs. background).
    pub lane: Lane,
}

/// One block of the automation tree (subset of the flow-builder `FlowBlock`; `children` is derived
/// from `parentId`, never read here).
#[derive(Debug, Clone, Deserialize)]
struct FlowBlock {
    #[serde(default)]
    id: String,
    /// `event | condition | action`.
    #[serde(rename = "type", default)]
    kind: String,
    /// The concrete block, e.g. `change_detected | condition | workflow | notification | return_data`.
    #[serde(rename = "blockType", default)]
    block_type: String,
    #[serde(default)]
    config: Value,
    #[serde(rename = "parentId", default)]
    parent_id: Option<String>,
}

/// Shared, borrow-only context for the recursive walk (everything that does not change per node).
struct FlowCtx<'a> {
    db: &'a SqlitePool,
    engine: &'a Arc<dyn LocalEngine>,
    /// `parentId` → ordered children. Roots (no parent) are handled separately.
    by_parent: &'a HashMap<String, Vec<FlowBlock>>,
    /// The automation's own linked workflow — the fallback target for a `workflow` action whose
    /// config omits an explicit `workflow_id`.
    auto_workflow_id: Option<i64>,
    base_inputs: &'a Value,
    source: RunSource,
    lane: Lane,
}

/// Fire an automation: open an execution row, walk its block tree (or fall back to the linked
/// workflow), and finalize. Returns the completed execution row, or `None` when a root-event
/// **status gate** (`status_condition` on a `workflow_completed`/`ai_session_completed` event) did
/// not match the trigger — in that case NO row is written (the automation simply did not apply).
pub async fn run_automation(
    db: &SqlitePool,
    engine: &Arc<dyn LocalEngine>,
    auto: &Automation,
    trigger: FlowTrigger,
) -> LocalResult<Option<AutomationExecution>> {
    // Parse the block tree up front so a status-gate mismatch can short-circuit BEFORE we write a row.
    let blocks = parse_blocks(auto.blocks.as_deref());
    let root_event = blocks
        .iter()
        .find(|b| b.kind == "event" && b.parent_id.is_none());

    // Root-event status gate (workflow/ai-session completion events only). A mismatch means the
    // automation does not apply to THIS trigger — skip silently (no execution row).
    if let Some(ev) = root_event {
        if !status_gate_matches(&ev.config, &trigger.context) {
            tracing::debug!(
                automation_id = auto.id,
                event = %trigger.event,
                "automation status gate not matched — skipping"
            );
            return Ok(None);
        }
    }

    // Firing guardrails (cooldown / max_fires), stored in `conditions` by the flow builder.
    // Manual runs bypass them — the user asked for it explicitly. Parity with the cloud
    // unified trigger service; enforced here so desktop honors the same limits.
    if let Some(reason) = guardrail_block_reason(auto, trigger.source) {
        tracing::debug!(automation_id = auto.id, reason, "automation guardrail — skipping");
        return Ok(None);
    }

    let trigger_context = serde_json::to_string(&trigger.context).ok();
    let exec = automation_executions::insert(
        db,
        &NewAutomationExecution {
            automation_id: auto.id,
            change_id: trigger.change_id,
            status: Some("running".into()),
            trigger_context,
            ..Default::default()
        },
    )
    .await?;
    let _ = crate::local::store::automations::mark_triggered(db, auto.id).await;

    // Seed scope from the trigger context (must be an object).
    let scope: Map<String, Value> = match &trigger.context {
        Value::Object(m) => m.clone(),
        _ => Map::new(),
    };

    let results: Vec<Value> = if blocks.iter().any(|b| b.kind == "action" || b.kind == "condition") {
        // Tree mode: walk the graph from each root.
        let mut by_parent: HashMap<String, Vec<FlowBlock>> = HashMap::new();
        let mut roots: Vec<FlowBlock> = Vec::new();
        for b in &blocks {
            match &b.parent_id {
                Some(pid) => by_parent.entry(pid.clone()).or_default().push(b.clone()),
                None => roots.push(b.clone()),
            }
        }
        let ctx = FlowCtx {
            db,
            engine,
            by_parent: &by_parent,
            auto_workflow_id: auto.workflow_id,
            base_inputs: &trigger.base_inputs,
            source: trigger.source,
            lane: trigger.lane,
        };
        let mut out = Vec::new();
        for root in &roots {
            out.extend(run_subtree(&ctx, &root.id, scope.clone()).await);
        }
        out
    } else {
        // Legacy mode: no blocks → run the single linked workflow (or no-op).
        run_legacy(db, engine, auto, &trigger).await
    };

    // Terminal status: failed iff any workflow action came back not-ok.
    let first_error = results.iter().find_map(|r| {
        if r.get("ok") == Some(&Value::Bool(false)) {
            r.get("error").and_then(|e| e.as_str()).map(str::to_string)
        } else {
            None
        }
    });
    let any_failed = results
        .iter()
        .any(|r| r.get("ok") == Some(&Value::Bool(false)));
    let status = if any_failed { "failed" } else { "success" };
    let action_results = serde_json::to_string(&results).ok();

    let done = automation_executions::complete(
        db,
        exec.id,
        status,
        action_results.as_deref(),
        first_error.as_deref(),
    )
    .await?;
    Ok(done)
}

/// Whether a firing guardrail (cooldown / max_fires from `conditions`) blocks this fire.
/// Manual runs always pass. Returns a short reason for the trace when blocked.
fn guardrail_block_reason(auto: &Automation, source: RunSource) -> Option<&'static str> {
    if matches!(source, RunSource::Manual) {
        return None;
    }
    let cond: Value = serde_json::from_str(&auto.conditions).unwrap_or(Value::Null);

    if let Some(max) = cond.get("max_fires").and_then(Value::as_i64) {
        if max > 0 && auto.trigger_count.unwrap_or(0) >= max {
            return Some("max_fires reached");
        }
    }

    if let Some(cool) = cond
        .get("schedule")
        .and_then(|s| s.get("cooldown_minutes"))
        .and_then(Value::as_i64)
    {
        if cool > 0 {
            if let Some(last) = auto.last_triggered_at.as_deref() {
                if let Ok(last_dt) = DateTime::parse_from_rfc3339(last) {
                    let elapsed = Utc::now().signed_duration_since(last_dt.with_timezone(&Utc));
                    if elapsed < ChronoDuration::minutes(cool) {
                        return Some("cooldown active");
                    }
                }
            }
        }
    }
    None
}

/// Walk the children of `node_id`, returning the ordered action-result records. Each child forks the
/// parent `scope` (branch isolation); execution is sequential. Boxed so the future can recurse.
fn run_subtree<'a>(
    ctx: &'a FlowCtx<'a>,
    node_id: &'a str,
    scope: Map<String, Value>,
) -> Pin<Box<dyn Future<Output = Vec<Value>> + Send + 'a>> {
    Box::pin(async move {
        let mut results = Vec::new();
        let Some(children) = ctx.by_parent.get(node_id) else {
            return results;
        };
        for child in children {
            match child.kind.as_str() {
                "condition" => {
                    let passed = eval_condition(&child.config, &scope);
                    results.push(json!({
                        "action": "condition",
                        "field": child.config.get("field").and_then(Value::as_str).unwrap_or(""),
                        "operator": child.config.get("operator").and_then(Value::as_str).unwrap_or("contains"),
                        "passed": passed,
                    }));
                    if passed {
                        results.extend(run_subtree(ctx, &child.id, scope.clone()).await);
                    }
                }
                "action" => match child.block_type.as_str() {
                    "workflow" => {
                        let (record, child_scope) = run_workflow_action(ctx, child, &scope).await;
                        // Error handling: when a workflow action ultimately fails (after any retries)
                        // and is set to on_error=stop, skip this action's DEPENDENT children (the rest
                        // of this chain) instead of running them against a failed result. Independent
                        // sibling branches still run. Default (continue) keeps the historical behaviour.
                        let failed = record.get("ok") == Some(&Value::Bool(false));
                        let stop_on_error = failed
                            && child.config.get("on_error").and_then(Value::as_str) == Some("stop");
                        results.push(record);
                        if stop_on_error {
                            results.push(json!({
                                "action": "branch_stopped",
                                "reason": "workflow failed with on_error=stop",
                            }));
                        } else {
                            results.extend(run_subtree(ctx, &child.id, child_scope).await);
                        }
                    }
                    // Loop: run this block's CHILDREN once per element of an upstream array
                    // (`config.source` dot-path, e.g. result.rows), binding {{item}} / {{item_index}}
                    // per iteration. Bounded by `config.max_items` (default 1000) so a huge array
                    // can't wedge the flow.
                    "for_each" => {
                        let source = child.config.get("source").and_then(Value::as_str).unwrap_or("");
                        // Same shaping as the cloud interpreter: an array iterates its elements,
                        // null/absent/empty-string yields zero iterations, any other scalar/object
                        // runs exactly once.
                        let items: Vec<Value> = match lookup_path(&scope, source) {
                            Some(Value::Array(arr)) => arr.clone(),
                            None | Some(Value::Null) => Vec::new(),
                            Some(Value::String(s)) if s.is_empty() => Vec::new(),
                            Some(other) => vec![other.clone()],
                        };
                        let max_items = child
                            .config
                            .get("max_items")
                            .and_then(Value::as_i64)
                            .unwrap_or(1000)
                            .max(0) as usize;
                        let count = items.len().min(max_items);
                        for (i, item) in items.into_iter().take(count).enumerate() {
                            let mut item_scope = scope.clone();
                            item_scope.insert("item".into(), item);
                            item_scope.insert("item_index".into(), json!(i));
                            results.extend(run_subtree(ctx, &child.id, item_scope).await);
                        }
                        results.push(json!({ "action": "for_each", "iterations": count }));
                    }
                    "return_data" => {
                        let data = scope
                            .get("result")
                            .cloned()
                            .unwrap_or_else(|| Value::Object(scope.clone()));
                        results.push(json!({ "action": "return_data", "data": data }));
                        results.extend(run_subtree(ctx, &child.id, scope.clone()).await);
                    }
                    "notification" => {
                        // Deliver locally where we can (outbound webhook + the in-app run feed);
                        // cloud-only channels (email/SMS/push/…) are recorded as skipped so the
                        // execution log is honest about what actually went out.
                        results.push(run_notification_action(ctx.db, child, &scope).await);
                        results.extend(run_subtree(ctx, &child.id, scope.clone()).await);
                    }
                    // Data → file: export a source workflow's extracted data to an encrypted
                    // StoredFile, merge { file_id, filename } into the branch scope for downstream
                    // blocks (e.g. a following `send_file`).
                    "save_data_to_file" | "query_and_export" => {
                        let (record, child_scope) =
                            run_export_to_file_action(ctx, child, &scope).await;
                        results.push(record);
                        results.extend(run_subtree(ctx, &child.id, child_scope).await);
                    }
                    // Copy filtered rows from a source workflow's data into a target workflow's data.
                    // Not cleanly feasible locally (data is derived from runs, not a writable store),
                    // so record a clear skip and continue rather than fail the flow.
                    "append_to_data" => {
                        results.push(json!({
                            "action": "append_to_data",
                            "skipped": true,
                            "reason": "append_to_data is not supported on the desktop app \
                                       (extracted data is derived from runs, not a writable store)",
                        }));
                        results.extend(run_subtree(ctx, &child.id, scope.clone()).await);
                    }
                    // Send a file reference to a configured webhook; else cloud-only skip.
                    "send_file" => {
                        results.push(run_send_file_action(child, &scope).await);
                        results.extend(run_subtree(ctx, &child.id, scope.clone()).await);
                    }
                    // Streaming session lifecycle actions (via the engine's streaming manager).
                    "start_streaming_session" | "stop_streaming_session" => {
                        let (record, child_scope) =
                            run_streaming_action(ctx, child, &scope).await;
                        results.push(record);
                        results.extend(run_subtree(ctx, &child.id, child_scope).await);
                    }
                    // Run an autonomous AI browser session (the form-filler loop) toward a goal,
                    // resolved from the block config (an inline goal, or a stored `ai_sessions` row).
                    // Merges `{ ai_result, success, status }` into the branch scope like a workflow
                    // action. Degrades to a recorded skip (never a flow failure) when no AI provider
                    // or no browser is available.
                    "ai_session" => {
                        let (record, child_scope) = run_ai_session_action(ctx, child, &scope).await;
                        results.push(record);
                        results.extend(run_subtree(ctx, &child.id, child_scope).await);
                    }
                    // A `crawl` action kicks off a Dragnet whole-site crawl. Dragnet is
                    // cloud-executed on the desktop (the app hard-gates it behind a linked
                    // cloud account — see DragnetCloudGate), so a locally-interpreted crawl
                    // action defers to the cloud rather than running a bounded local sweep.
                    // The synced cloud copy of this automation runs the real crawl; here we
                    // record an honest skip so the local execution log is truthful. The
                    // `crawl_completed` TRIGGER still fires locally from the daemon's own
                    // crawl completion (see local::crawl), so reacting to a crawl works.
                    other @ "crawl" => {
                        results.push(json!({
                            "action": other,
                            "skipped": true,
                            "reason": "crawls run via Dragnet in the cloud; this automation crawls when run on the cloud",
                        }));
                        results.extend(run_subtree(ctx, &child.id, scope.clone()).await);
                    }
                    // `create_persona` remains a cloud-only no-op (no local persona-registry action).
                    other @ "create_persona" => {
                        results.push(json!({
                            "action": other,
                            "skipped": true,
                            "reason": "action not supported on the desktop app (cloud-only)",
                        }));
                        results.extend(run_subtree(ctx, &child.id, scope.clone()).await);
                    }
                    other => {
                        results.push(json!({
                            "action": other,
                            "skipped": true,
                            "reason": "unknown action type",
                        }));
                        results.extend(run_subtree(ctx, &child.id, scope.clone()).await);
                    }
                },
                // A nested `event` block (e.g. a `workflow_completed` continuation placed AFTER a
                // workflow action) is a pass-through here: the preceding action already ran inline and
                // merged its result into the scope, so we just continue the chain.
                "event" => {
                    results.extend(run_subtree(ctx, &child.id, scope.clone()).await);
                }
                _ => {}
            }
        }
        results
    })
}

/// Run a `workflow` action: resolve the target workflow, drive it through the engine, and fold the
/// outcome into a forked scope (so downstream `condition`/`return_data` blocks can read `result.*`,
/// `success`, `status`, `error`). Returns `(action_record, child_scope)`.
async fn run_workflow_action(
    ctx: &FlowCtx<'_>,
    block: &FlowBlock,
    scope: &Map<String, Value>,
) -> (Value, Map<String, Value>) {
    let workflow_id = block
        .config
        .get("workflow_id")
        .and_then(Value::as_i64)
        .or(ctx.auto_workflow_id);

    let Some(workflow_id) = workflow_id else {
        return (
            json!({ "action": "workflow", "skipped": true, "reason": "no workflow_id configured" }),
            scope.clone(),
        );
    };

    // Inputs: the flow's base inputs, overlaid by any per-action `config.inputs` object.
    let mut inputs = match ctx.base_inputs {
        Value::Object(m) => m.clone(),
        _ => Map::new(),
    };
    if let Some(Value::Object(cfg)) = block.config.get("inputs") {
        for (k, v) in cfg {
            inputs.insert(k.clone(), v.clone());
        }
    }
    let persona_id = block.config.get("persona_id").and_then(Value::as_i64);

    // Error handling: retry a not-ok run up to `config.retry` extra times, optionally pausing
    // `config.retry_backoff_ms` between attempts (for rate-limited targets). `on_error=stop` is
    // handled by the caller (run_subtree), which halts the branch when the final attempt fails.
    let retries = block.config.get("retry").and_then(Value::as_i64).unwrap_or(0).max(0);
    let backoff_ms = block.config.get("retry_backoff_ms").and_then(Value::as_i64).unwrap_or(0).max(0);

    let mut attempt: i64 = 0;
    loop {
        let req = RunRequest {
            workflow_id,
            inputs: Value::Object(inputs.clone()),
            source: ctx.source,
            lane: ctx.lane,
            dry_run: false,
            // A `workflow` action may pin a persona to run under (else the workflow's own default).
            persona_id,
            // Owner-initiated saved-workflow run: local vault/file secret refs may resolve.
            allow_local_secret_refs: true,
        };

        let mut child_scope = scope.clone();
        let (record, ok) = match ctx.engine.run(req).await {
            Ok(result) => {
                child_scope.insert("result".into(), result.extracted_data.clone());
                child_scope.insert("success".into(), Value::Bool(result.success));
                child_scope.insert("status".into(), json!(status_str(result.status)));
                child_scope.insert(
                    "error".into(),
                    result.error.clone().map(Value::String).unwrap_or(Value::Null),
                );
                child_scope.insert(
                    "workflow_duration_seconds".into(),
                    json!(result.duration_ms as f64 / 1000.0),
                );
                let record = json!({
                    "action": "workflow",
                    "workflow_id": workflow_id,
                    "run_id": result.run_id,
                    "ok": result.success,
                    "status": status_str(result.status),
                    "error": result.error,
                    "attempt": attempt + 1,
                });
                (record, result.success)
            }
            Err(e) => {
                let msg = e.to_string();
                child_scope.insert("success".into(), Value::Bool(false));
                child_scope.insert("status".into(), json!("failed"));
                child_scope.insert("error".into(), Value::String(msg.clone()));
                let record = json!({
                    "action": "workflow",
                    "workflow_id": workflow_id,
                    "ok": false,
                    "status": "failed",
                    "error": msg,
                    "attempt": attempt + 1,
                });
                (record, false)
            }
        };

        if ok || attempt >= retries {
            return (record, child_scope);
        }
        attempt += 1;
        if backoff_ms > 0 {
            tokio::time::sleep(std::time::Duration::from_millis(backoff_ms as u64)).await;
        }
    }
}

/// The resolved parameters of an `ai_session` action, gathered from either a stored `ai_sessions`
/// row or the block's inline config. Pure data — building it needs no browser/provider, so it is
/// unit-testable in isolation.
#[derive(Debug, Clone)]
struct AiSessionSpec {
    /// The stored session row id this spec came from (when resolved by `ai_session_id`/`session_ids`).
    source_session_id: Option<i64>,
    goal: String,
    entry_url: Option<String>,
    available_data: HashMap<String, String>,
    fill_data: HashMap<String, String>,
    max_steps: u32,
    /// Optional login identity to run the session under (fingerprint / proxy / saved session /
    /// credentials), from the block's `persona_id` config. `None` = run without a persona.
    persona_id: Option<i64>,
}

/// The first stored-session id referenced by a block config: `config.ai_session_id`, else the first
/// element of the `config.session_ids` array the flow-builder writes. `None` ⇒ inline config.
fn ai_session_ref_id(config: &Value) -> Option<i64> {
    if let Some(id) = config.get("ai_session_id").and_then(Value::as_i64) {
        return Some(id);
    }
    config
        .get("session_ids")
        .and_then(Value::as_array)
        .and_then(|arr| arr.iter().find_map(Value::as_i64))
}

/// Collect a `{String:String}` map from a JSON object at `config[key]` (non-string values are
/// stringified; a non-object is ignored). Used for inline `available_data` / `fill_data` / the
/// flow-builder's `form_data`.
fn string_map_from(config: &Value, key: &str) -> HashMap<String, String> {
    let mut out = HashMap::new();
    if let Some(Value::Object(m)) = config.get(key) {
        for (k, v) in m {
            let s = match v {
                Value::String(s) => s.clone(),
                other => value_to_string(Some(other)),
            };
            out.insert(k.clone(), s);
        }
    }
    out
}

/// Build the [`AiSessionSpec`] from a block's inline config alone (no stored row). `None` when there
/// is no usable goal (an empty goal cannot drive the loop). The flow-builder's `form_data` object is
/// folded into both `available_data` (hints) and `fill_data` (values), and `user_context` — a free
/// text steer — is appended to the goal, mirroring the cloud action shape.
fn resolve_ai_session_spec_inline(config: &Value) -> Option<AiSessionSpec> {
    let mut goal = config
        .get("goal")
        .and_then(Value::as_str)
        .unwrap_or("")
        .trim()
        .to_string();
    if let Some(ctx) = config
        .get("user_context")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|s| !s.is_empty())
    {
        if goal.is_empty() {
            goal = ctx.to_string();
        } else {
            goal = format!("{goal}\n\nContext: {ctx}");
        }
    }
    if goal.is_empty() {
        return None;
    }

    let form_data = string_map_from(config, "form_data");
    let mut available_data = string_map_from(config, "available_data");
    let mut fill_data = string_map_from(config, "fill_data");
    for (k, v) in &form_data {
        available_data.entry(k.clone()).or_insert_with(|| v.clone());
        fill_data.entry(k.clone()).or_insert_with(|| v.clone());
    }

    let max_steps = config
        .get("max_steps")
        .and_then(Value::as_u64)
        .map(|n| n as u32)
        .unwrap_or(20)
        .clamp(1, 100);

    Some(AiSessionSpec {
        source_session_id: None,
        goal,
        entry_url: config
            .get("entry_url")
            .and_then(Value::as_str)
            .map(str::to_string),
        available_data,
        fill_data,
        max_steps,
        persona_id: config.get("persona_id").and_then(Value::as_i64),
    })
}

/// Resolve the full [`AiSessionSpec`] for a block: load the referenced stored `ai_sessions` row when
/// the config points at one (`ai_session_id`/`session_ids`), else the inline config. On a stored
/// row, the block's inline `available_data`/`fill_data`/`form_data` overlay the row's saved maps
/// (block wins) so an automation can supply per-run values on top of a saved session. Returns an
/// `Err(reason)` string for a clean recorded skip (missing/unusable row or no goal).
async fn resolve_ai_session_spec(
    db: &SqlitePool,
    config: &Value,
) -> Result<AiSessionSpec, String> {
    let Some(sid) = ai_session_ref_id(config) else {
        return resolve_ai_session_spec_inline(config)
            .ok_or_else(|| "ai_session has no goal configured".to_string());
    };

    let row = crate::local::store::ai_sessions::get_by_id(db, sid)
        .await
        .map_err(|e| format!("could not load ai_session {sid}: {e}"))?
        .ok_or_else(|| format!("ai_session {sid} not found"))?;

    let goal = row.goal.trim().to_string();
    if goal.is_empty() {
        return Err(format!("ai_session {sid} has no goal"));
    }

    // Stored maps (JSON-text) → overlaid by any inline block config.
    let parse_map = |s: &Option<String>| -> HashMap<String, String> {
        s.as_deref()
            .and_then(|t| serde_json::from_str::<HashMap<String, String>>(t).ok())
            .unwrap_or_default()
    };
    let mut available_data = parse_map(&row.available_data);
    let mut fill_data = parse_map(&row.fill_data);
    for (k, v) in string_map_from(config, "available_data") {
        available_data.insert(k, v);
    }
    for (k, v) in string_map_from(config, "form_data") {
        available_data.entry(k.clone()).or_insert_with(|| v.clone());
        fill_data.insert(k, v);
    }
    for (k, v) in string_map_from(config, "fill_data") {
        fill_data.insert(k, v);
    }

    let max_steps = if row.max_steps > 0 { row.max_steps as u32 } else { 20 }.clamp(1, 100);

    Ok(AiSessionSpec {
        source_session_id: Some(row.id),
        goal,
        entry_url: config
            .get("entry_url")
            .and_then(Value::as_str)
            .map(str::to_string)
            .or(row.entry_url),
        available_data,
        fill_data,
        max_steps,
        persona_id: config.get("persona_id").and_then(Value::as_i64),
    })
}

/// A [`PageEvaluator`] over a live page — for the DOM-analyzer probe API the session loop uses.
struct FlowPageEval(playwright_rs::Page);
impl crate::dom::analyzer::PageEvaluator for FlowPageEval {
    fn evaluate_json(
        &self,
        js: &str,
    ) -> Pin<Box<dyn Future<Output = anyhow::Result<Value>> + Send + '_>> {
        let js = js.to_string();
        Box::pin(async move {
            self.0
                .evaluate(&js, None::<&()>)
                .await
                .map_err(|e| anyhow::anyhow!("evaluate_json failed: {}", e))
        })
    }
    fn evaluate_json_with_args(
        &self,
        js: &str,
        args: &[Value],
    ) -> Pin<Box<dyn Future<Output = anyhow::Result<Value>> + Send + '_>> {
        let js = js.to_string();
        let args = Value::Array(args.to_vec());
        Box::pin(async move {
            self.0
                .evaluate(&js, Some(&args))
                .await
                .map_err(|e| anyhow::anyhow!("evaluate_json_with_args failed: {}", e))
        })
    }
}

/// Run an `ai_session` action: resolve the session spec, open a page via the engine browser, drive
/// the autonomous AI loop, and fold `{ ai_result, success, status }` into a forked scope (parity with
/// `run_workflow_action`, so downstream `condition`/`return_data` blocks can read `ai_result.*`,
/// `success`, `status`). When no AI provider or no browser is available, records a `skipped` result
/// and leaves the scope unchanged — an unrunnable AI action never fails the whole automation.
async fn run_ai_session_action(
    ctx: &FlowCtx<'_>,
    block: &FlowBlock,
    scope: &Map<String, Value>,
) -> (Value, Map<String, Value>) {
    // Resolve the session parameters (stored row or inline config).
    let spec = match resolve_ai_session_spec(ctx.db, &block.config).await {
        Ok(s) => s,
        Err(reason) => {
            return (
                json!({ "action": "ai_session", "skipped": true, "reason": reason }),
                scope.clone(),
            );
        }
    };

    // AI provider — needs the engine's vault to decrypt the saved key. Missing ⇒ skip (not a fail).
    let Some(vault) = ctx.engine.vault() else {
        return (
            json!({ "action": "ai_session", "skipped": true, "reason": "cloud_only" }),
            scope.clone(),
        );
    };
    // When the cloud AI gateway is on, a local provider is optional (the gateway is the brain) — use a
    // placeholder cfg that the completion layer ignores in favor of the gateway.
    let gateway_on = crate::local::ai::provider::cloud_gateway_enabled(ctx.db).await;
    let ai_cfg = match crate::local::ai::provider::resolve_config(ctx.db, &vault).await {
        Ok(Some(c)) if !c.provider.trim().is_empty() => c,
        Ok(_) if gateway_on => crate::local::ai::provider::AiConfig {
            provider: String::new(),
            model: String::new(),
            base_url: None,
            api_key: None,
        },
        Ok(_) => {
            return (
                json!({
                    "action": "ai_session",
                    "skipped": true,
                    "reason": "no AI provider configured (Settings → AI)",
                }),
                scope.clone(),
            );
        }
        Err(e) => {
            return (
                json!({
                    "action": "ai_session",
                    "skipped": true,
                    "reason": format!("could not resolve AI provider: {e}"),
                }),
                scope.clone(),
            );
        }
    };

    // Warm browser — the StubEngine (and any headless-less build) has none ⇒ skip, not fail.
    let Some(browser) = ctx.engine.browser() else {
        return (
            json!({
                "action": "ai_session",
                "skipped": true,
                "reason": "this engine cannot run AI sessions (no browser)",
            }),
            scope.clone(),
        );
    };

    // Optional persona to run under (fingerprint / proxy / saved session / credentials), from the
    // block's `persona_id`. A dangling/failed id is non-fatal — the session runs without it.
    let resolved_persona = match spec.persona_id {
        Some(pid) => crate::local::engine::persona::resolve_persona(ctx.db, &vault, pid)
            .await
            .unwrap_or_else(|e| {
                tracing::warn!(persona_id = pid, error = %e, "ai_session persona resolve failed; running without it");
                None
            }),
        None => None,
    };

    match run_ai_session_loop(&browser, &ai_cfg, ctx.db, &spec, resolved_persona.as_ref()).await {
        Ok(res) => {
            let success = res.status == crate::local::ai::session::SessionStatus::Complete;
            let status = res.status.as_str().to_string();
            let mut child_scope = scope.clone();
            child_scope.insert("ai_result".into(), res.result.clone());
            child_scope.insert("success".into(), Value::Bool(success));
            child_scope.insert("status".into(), json!(status));
            child_scope.insert(
                "error".into(),
                res.error.clone().map(Value::String).unwrap_or(Value::Null),
            );
            let record = json!({
                "action": "ai_session",
                "ai_session_id": spec.source_session_id,
                "ok": success,
                "status": status,
                "steps": res.steps,
                "message": res.message,
                "error": res.error,
            });
            (record, child_scope)
        }
        Err(e) => {
            // A launch/navigation failure is a real action failure (surfaced as `ok:false`), not a
            // silent skip — but it still does not abort sibling branches.
            let msg = e.to_string();
            let mut child_scope = scope.clone();
            child_scope.insert("success".into(), Value::Bool(false));
            child_scope.insert("status".into(), json!("error"));
            child_scope.insert("error".into(), Value::String(msg.clone()));
            let record = json!({
                "action": "ai_session",
                "ai_session_id": spec.source_session_id,
                "ok": false,
                "status": "error",
                "error": msg,
            });
            (record, child_scope)
        }
    }
}

/// Open a page (warm browser + a stealth context, pinned to the optional persona's fingerprint +
/// proxy) and drive the autonomous loop for `spec`. Mirrors the `/v1/ai-sessions/start` handler's
/// `run_ai_session` (background/headless by default): when a persona is supplied, its saved session
/// (cookies + storage) is restored BEFORE navigation so the loop starts signed-in, and its
/// credentials are merged into `fill_data` (spec values win). Always closes the context on exit.
async fn run_ai_session_loop(
    browser: &Arc<crate::browser::manager::BrowserManager>,
    ai_cfg: &crate::local::ai::provider::AiConfig,
    pool: &sqlx::sqlite::SqlitePool,
    spec: &AiSessionSpec,
    resolved_persona: Option<&crate::local::engine::persona::ResolvedPersona>,
) -> LocalResult<crate::local::ai::session::SessionResult> {
    use crate::local::error::LocalError;
    let entry_url = spec.entry_url.as_deref().unwrap_or("about:blank");

    let fingerprint = resolved_persona.and_then(|p| p.fingerprint.clone());
    let proxy = resolved_persona.and_then(|p| p.proxy.clone());

    browser
        .ensure_warm_browser_with(true)
        .await
        .map_err(|e| LocalError::Internal(format!("browser launch failed: {e}")))?;
    let (context, page, _fp) = browser
        .create_stealth_context_with_fingerprint_proxy(fingerprint, proxy)
        .await
        .map_err(|e| LocalError::Internal(format!("browser context failed: {e}")))?;

    // Vet the entry URL before navigating (rejects file:/internal/metadata hosts). about:blank ok.
    if !crate::security::url_guard::is_navigation_url_safe_async(entry_url).await {
        let _ = context.close().await;
        return Err(LocalError::BadRequest(format!("Refused unsafe entry URL: {entry_url}")));
    }

    // Restore the persona's saved session (cookies + storage) BEFORE navigation → start signed-in;
    // else a plain navigation. 1:1 with the run engine + the /v1/ai-sessions/start handler.
    let nav_result = match resolved_persona.and_then(|p| p.session_state.as_ref()) {
        Some(state) => {
            crate::automation::session_state::inject_session_state(
                &page,
                &context,
                state,
                Some(entry_url),
                30_000,
            )
            .await
        }
        None => {
            crate::browser::navigation::goto(
                &page,
                entry_url,
                "domcontentloaded",
                std::time::Duration::from_secs(30),
            )
            .await
        }
    };
    if let Err(e) = nav_result {
        let _ = context.close().await;
        return Err(LocalError::Internal(format!("navigation failed: {e}")));
    }

    // fill_data = spec values + persona credentials (spec wins on key collision).
    let mut fill_data = spec.fill_data.clone();
    if let Some(p) = resolved_persona {
        let mut creds: HashMap<String, String> = HashMap::new();
        p.merge_into_credentials(&mut creds);
        for (k, v) in creds {
            fill_data.entry(k).or_insert(v);
        }
    }

    let cfg = crate::local::ai::session::SessionConfig {
        goal: spec.goal.clone(),
        available_data: spec.available_data.clone(),
        fill_data,
        max_steps: spec.max_steps,
        record_templates: std::collections::HashMap::new(),
        ask_session_id: None,
    };
    let evaluator = FlowPageEval(page.clone());
    // No live-preview sink for automation AI steps — they run headless inside a flow, not watched.
    let result = crate::local::ai::session::run_session(&page, &evaluator, &cfg, ai_cfg, pool, None, None).await;
    let _ = context.close().await;
    result
}

/// Legacy (no-blocks) dispatch: run the automation's single linked workflow if it has one, else a
/// no-op success. Preserves the pre-interpreter behavior for automations created without a tree.
async fn run_legacy(
    _db: &SqlitePool,
    engine: &Arc<dyn LocalEngine>,
    auto: &Automation,
    trigger: &FlowTrigger,
) -> Vec<Value> {
    let Some(workflow_id) = auto.workflow_id else {
        return vec![json!({ "action": "noop", "detail": "no workflow_id to run" })];
    };
    let req = RunRequest {
        workflow_id,
        inputs: trigger.base_inputs.clone(),
        source: trigger.source,
        lane: trigger.lane,
        dry_run: false,
        persona_id: None,
        allow_local_secret_refs: true,
    };
    match engine.run(req).await {
        Ok(result) => vec![json!({
            "action": "workflow",
            "workflow_id": workflow_id,
            "run_id": result.run_id,
            "ok": result.success,
            "status": status_str(result.status),
            "error": result.error,
        })],
        Err(e) => vec![json!({
            "action": "workflow",
            "workflow_id": workflow_id,
            "ok": false,
            "status": "failed",
            "error": e.to_string(),
        })],
    }
}

/// Whether `blocks` JSON holds an executable tree (≥1 `action`/`condition` block) — i.e. the
/// interpreter would do more than the legacy single-workflow fallback. Trigger sites (e.g. the
/// webhook ingress) use this to decide whether to divert to [`run_automation`] vs. their own legacy
/// dispatch.
pub fn has_executable_tree(blocks: Option<&str>) -> bool {
    parse_blocks(blocks)
        .iter()
        .any(|b| b.kind == "action" || b.kind == "condition")
}

/// Parse the `blocks` JSON-TEXT into a vec of [`FlowBlock`]. Any parse failure (or absent column)
/// yields an empty vec → the caller falls back to legacy mode.
fn parse_blocks(blocks: Option<&str>) -> Vec<FlowBlock> {
    blocks
        .filter(|s| !s.trim().is_empty())
        .and_then(|s| serde_json::from_str::<Vec<FlowBlock>>(s).ok())
        .unwrap_or_default()
}

/// Whether a root-event `status_condition` (`success` | `error` | `any`/absent) matches the trigger.
/// Only `*_completed` events carry one; for everything else there is no gate (always matches).
fn status_gate_matches(event_config: &Value, context: &Value) -> bool {
    let gate = event_config
        .get("status_condition")
        .and_then(Value::as_str)
        .unwrap_or("any");
    match gate {
        "success" => context.get("success").and_then(Value::as_bool) == Some(true),
        "error" => context.get("success").and_then(Value::as_bool) == Some(false),
        _ => true, // "any" / unrecognized → no gate
    }
}

/// Evaluate a `condition` block's `{field, operator, value}` against the current scope.
fn eval_condition(config: &Value, scope: &Map<String, Value>) -> bool {
    let field = config.get("field").and_then(Value::as_str).unwrap_or("");
    if field.is_empty() {
        return true; // an unconfigured condition does not block the branch
    }
    let operator = config.get("operator").and_then(Value::as_str).unwrap_or("contains");
    let target = config.get("value").and_then(Value::as_str).unwrap_or("");
    let actual = lookup_path(scope, field);
    let actual_str = value_to_string(actual);

    match operator {
        "exists" => actual.map(|v| !is_empty_value(v)).unwrap_or(false),
        // We have no prior value locally; "changed" degrades to "present and non-empty".
        "changed" => actual.map(|v| !is_empty_value(v)).unwrap_or(false),
        "contains" => actual_str.contains(target),
        "not_contains" => !actual_str.contains(target),
        "equals" => values_equal(&actual_str, target),
        "not_equals" => !values_equal(&actual_str, target),
        "matches" => regex_matches(target, &actual_str),
        "gt" | "gte" | "lt" | "lte" => compare_numeric(operator, &actual_str, target),
        _ => false,
    }
}

/// Equality that is numeric when both sides parse as numbers, else string-exact.
fn values_equal(a: &str, b: &str) -> bool {
    match (a.trim().parse::<f64>(), b.trim().parse::<f64>()) {
        (Ok(x), Ok(y)) => x == y,
        _ => a == b,
    }
}

/// Numeric comparison; non-numeric operands evaluate false.
fn compare_numeric(op: &str, a: &str, b: &str) -> bool {
    let (Ok(x), Ok(y)) = (a.trim().parse::<f64>(), b.trim().parse::<f64>()) else {
        return false;
    };
    match op {
        "gt" => x > y,
        "gte" => x >= y,
        "lt" => x < y,
        "lte" => x <= y,
        _ => false,
    }
}

/// Compile `pattern` (size/length bounded) and test it against `haystack`. Invalid/oversized
/// patterns evaluate false (never a panic, never unbounded work).
fn regex_matches(pattern: &str, haystack: &str) -> bool {
    if pattern.len() > MAX_REGEX_PATTERN_LEN {
        return false;
    }
    match regex::RegexBuilder::new(pattern)
        .size_limit(REGEX_SIZE_LIMIT)
        .build()
    {
        Ok(re) => re.is_match(haystack),
        Err(_) => false,
    }
}

/// Resolve a dot path (`a.b.c`) into the scope. The first segment indexes the scope map; further
/// segments descend through nested objects. Returns `None` if any segment is absent.
fn lookup_path<'a>(scope: &'a Map<String, Value>, path: &str) -> Option<&'a Value> {
    let mut segs = path.split('.');
    let first = segs.next()?;
    let mut cur = scope.get(first)?;
    for seg in segs {
        cur = cur.as_object()?.get(seg)?;
    }
    Some(cur)
}

/// Render a JSON value as the string a text operator compares against (objects/arrays → JSON text).
fn value_to_string(v: Option<&Value>) -> String {
    match v {
        None | Some(Value::Null) => String::new(),
        Some(Value::String(s)) => s.clone(),
        Some(Value::Bool(b)) => b.to_string(),
        Some(Value::Number(n)) => n.to_string(),
        Some(other) => other.to_string(),
    }
}

/// Substitute `{{ dot.path | filter:arg | ... }}` placeholders in a template with scope values.
/// A placeholder is a dot-path lookup followed by an optional left-to-right chain of transform
/// filters (see [`apply_filter`]) so templates can COMPUTE, not just substitute:
///   `{{ result.price | mul:1.1 | round:2 }}`, `{{ payload.name | default:friend | upper }}`,
///   `{{ extracted.sku | match:([A-Z]+) }}`.
/// Unknown paths render empty (never leaks a raw `{{…}}`); unknown filters pass the value through.
fn render_template(template: &str, scope: &Map<String, Value>) -> String {
    let mut out = String::with_capacity(template.len());
    let mut rest = template;
    while let Some(start) = rest.find("{{") {
        out.push_str(&rest[..start]);
        let after = &rest[start + 2..];
        match after.find("}}") {
            Some(end) => {
                out.push_str(&render_expr(after[..end].trim(), scope));
                rest = &after[end + 2..];
            }
            None => {
                out.push_str(&rest[start..]);
                return out;
            }
        }
    }
    out.push_str(rest);
    out
}

/// Resolve a placeholder expression: dot-path lookup, then a `|`-separated filter chain.
fn render_expr(expr: &str, scope: &Map<String, Value>) -> String {
    let mut segs = expr.split('|');
    let path = segs.next().unwrap_or("").trim();
    let mut cur = value_to_string(lookup_path(scope, path));
    for f in segs {
        cur = apply_filter(&cur, f.trim());
    }
    cur
}

/// Format a computed number: integers without a decimal point, fractionals trimmed of trailing
/// zeros (so `mul:1.1` on `100` renders `110`, not `110.00000000000001`).
fn fmt_num(n: f64) -> String {
    if n.fract() == 0.0 && n.abs() < 1e15 {
        format!("{}", n as i64)
    } else {
        let s = format!("{n:.6}");
        s.trim_end_matches('0').trim_end_matches('.').to_string()
    }
}

/// First capture group (or whole match) of `pattern` against `text`, bounded like `regex_matches`.
/// No match / invalid / oversized pattern → empty string.
fn regex_capture(pattern: &str, text: &str) -> String {
    if pattern.len() > MAX_REGEX_PATTERN_LEN {
        return String::new();
    }
    match regex::RegexBuilder::new(pattern).size_limit(REGEX_SIZE_LIMIT).build() {
        Ok(re) => re
            .captures(text)
            .and_then(|c| c.get(1).or_else(|| c.get(0)).map(|m| m.as_str().to_string()))
            .unwrap_or_default(),
        Err(_) => String::new(),
    }
}

/// Apply one `name:arg` template transform to the current (already-stringified) value. Kept in sync
/// with the cloud `unified_trigger_service._apply_template_filter`.
fn apply_filter(value: &str, spec: &str) -> String {
    let (name, arg) = match spec.split_once(':') {
        Some((n, a)) => (n.trim().to_ascii_lowercase(), a),
        None => (spec.trim().to_ascii_lowercase(), ""),
    };
    match name.as_str() {
        "default" | "or" => {
            if value.trim().is_empty() {
                arg.to_string()
            } else {
                value.to_string()
            }
        }
        "upper" => value.to_uppercase(),
        "lower" => value.to_lowercase(),
        "trim" => value.trim().to_string(),
        "truncate" => match arg.trim().parse::<usize>() {
            Ok(n) => value.chars().take(n).collect(),
            Err(_) => value.to_string(),
        },
        "replace" => match arg.split_once(':') {
            Some((a, b)) => value.replace(a, b),
            None => value.to_string(),
        },
        "round" => {
            let Ok(n) = value.trim().parse::<f64>() else {
                return value.to_string();
            };
            let digits: i32 = arg.trim().parse().unwrap_or(0);
            if digits <= 0 {
                format!("{}", n.round() as i64)
            } else {
                format!("{:.*}", digits as usize, n)
            }
        }
        "add" | "sub" | "mul" | "div" => {
            let (Ok(a), Ok(b)) = (value.trim().parse::<f64>(), arg.trim().parse::<f64>()) else {
                return value.to_string();
            };
            let r = match name.as_str() {
                "add" => a + b,
                "sub" => a - b,
                "mul" => a * b,
                _ => {
                    if b != 0.0 {
                        a / b
                    } else {
                        a
                    }
                }
            };
            fmt_num(r)
        }
        "match" => regex_capture(arg, value),
        _ => value.to_string(),
    }
}

/// POST a JSON body to an SSRF-guarded URL. Shared by the per-connector senders (Slack/Discord/
/// Telegram) so every outbound notification goes through the same fail-closed url_guard + no-redirect
/// client. Returns whether the response was 2xx.
pub(crate) async fn post_connector_json(url: &str, body: &Value) -> bool {
    // SECURITY (SSRF): the destination comes from user-configured connectors. Vet it (fail-closed)
    // before POSTing so a notification can't be aimed at loopback / RFC1918 / cloud metadata, and
    // disable redirect-following so a public URL can't 3xx-pivot to an internal target. For Telegram
    // the URL is always api.telegram.org, but we still run it through the guard per the contract.
    if !crate::security::url_guard::is_navigation_url_safe_async(url).await {
        tracing::warn!("connector notification blocked: unsafe URL");
        return false;
    }
    let client = match reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .redirect(reqwest::redirect::Policy::none())
        .build()
    {
        Ok(c) => c,
        Err(_) => return false,
    };
    match client.post(url).json(body).send().await {
        Ok(resp) => resp.status().is_success(),
        Err(_) => false,
    }
}

/// Deliver to a Slack incoming webhook: `POST <webhook_url>` body `{ "text": "<title>\n\n<message>" }`.
/// Returns whether it was accepted (2xx). A missing/blank `webhook_url` is a no-op failure.
pub(crate) async fn send_slack(webhook_url: Option<&str>, title: &str, message: &str) -> bool {
    let Some(url) = webhook_url.filter(|u| !u.is_empty()) else {
        return false;
    };
    let text = format!("{title}\n\n{message}");
    post_connector_json(url, &json!({ "text": text })).await
}

/// Deliver to a Discord channel webhook: `POST <webhook_url>` body
/// `{ "content": "**<title>**\n<message>" }`. Discord caps `content` at 2000 chars — truncate.
/// Returns whether it was accepted (2xx). A missing/blank `webhook_url` is a no-op failure.
pub(crate) async fn send_discord(webhook_url: Option<&str>, title: &str, message: &str) -> bool {
    let Some(url) = webhook_url.filter(|u| !u.is_empty()) else {
        return false;
    };
    let mut content = format!("**{title}**\n{message}");
    if content.chars().count() > 2000 {
        content = content.chars().take(2000).collect();
    }
    post_connector_json(url, &json!({ "content": content })).await
}

/// Deliver via the Telegram bot API: `POST https://api.telegram.org/bot<bot_token>/sendMessage`
/// body `{ chat_id, text: "<title>\n\n<message>", disable_web_page_preview: true }`. Returns whether
/// it was accepted (2xx). Missing/blank `bot_token` or `chat_id` is a no-op failure.
pub(crate) async fn send_telegram(
    bot_token: Option<&str>,
    chat_id: Option<&str>,
    title: &str,
    message: &str,
) -> bool {
    let Some(token) = bot_token.filter(|t| !t.is_empty()) else {
        return false;
    };
    let Some(chat) = chat_id.filter(|c| !c.is_empty()) else {
        return false;
    };
    let url = format!("https://api.telegram.org/bot{token}/sendMessage");
    let text = format!("{title}\n\n{message}");
    post_connector_json(
        &url,
        &json!({ "chat_id": chat, "text": text, "disable_web_page_preview": true }),
    )
    .await
}

/// Deliver `title`/`message` through a single stored connector, dispatching on its provider.
/// Unknown providers return `false` (recorded as a skip by the caller).
pub(crate) async fn deliver_to_connector(
    connector: &crate::local::store::notification_connectors::NotificationConnector,
    title: &str,
    message: &str,
) -> bool {
    match connector.provider.as_str() {
        "slack" => send_slack(connector.webhook_url.as_deref(), title, message).await,
        "discord" => send_discord(connector.webhook_url.as_deref(), title, message).await,
        "telegram" => {
            send_telegram(
                connector.bot_token.as_deref(),
                connector.chat_id.as_deref(),
                title,
                message,
            )
            .await
        }
        _ => false,
    }
}

/// POST a notification to a user-supplied webhook. Returns whether it was accepted (2xx).
async fn post_webhook(url: &str, title: &str, message: &str) -> bool {
    // SECURITY (SSRF): the delivery URL comes from automation config. Vet it (fail-closed) before
    // POSTing so a notification can't be aimed at loopback / RFC1918 / cloud metadata, and disable
    // redirect-following so a public URL can't 3xx-pivot to an internal target.
    if !crate::security::url_guard::is_navigation_url_safe_async(url).await {
        tracing::warn!("webhook notification blocked: unsafe URL");
        return false;
    }
    let client = match reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .redirect(reqwest::redirect::Policy::none())
        .build()
    {
        Ok(c) => c,
        Err(_) => return false,
    };
    match client
        .post(url)
        .json(&json!({ "title": title, "message": message }))
        .send()
        .await
    {
        Ok(resp) => resp.status().is_success(),
        Err(_) => false,
    }
}

/// Process-global queue of native OS-toast notifications the app drains via
/// `GET /v1/notifications/pending`. The daemon can't reach the Tauri shell directly, so
/// `desktop`-channel automation notifications land here for the webview poller to raise as
/// real OS toasts. Bounded so a closed/backgrounded app can't grow it without limit.
static PENDING_TOASTS: OnceLock<Mutex<VecDeque<Value>>> = OnceLock::new();
fn pending_toasts() -> &'static Mutex<VecDeque<Value>> {
    PENDING_TOASTS.get_or_init(|| Mutex::new(VecDeque::new()))
}

/// Queue a native OS toast (title + body) for the app's poller to raise.
pub fn push_pending_toast(title: &str, body: &str) {
    if let Ok(mut q) = pending_toasts().lock() {
        while q.len() >= 100 {
            q.pop_front();
        }
        q.push_back(json!({ "title": title, "body": body }));
    }
}

/// Drain all queued OS toasts (called by the app's `/v1/notifications/pending` poll).
pub fn drain_pending_toasts() -> Vec<Value> {
    match pending_toasts().lock() {
        Ok(mut q) => q.drain(..).collect(),
        Err(_) => Vec::new(),
    }
}

/// Deliver a `notification` action locally. Outbound webhooks fire real HTTP; `desktop` queues a
/// native OS toast for the app to raise; `in_app` is recorded to the execution feed; email/SMS/push
/// are cloud-only and recorded as skipped so the run log stays truthful about what went out.
/// Resolve the target connectors for a `provider`-channel delivery. If `recipients` names any refs
/// for THIS provider (`provider:id`), only those (that exist) are used; otherwise fall back to ALL
/// enabled connectors of the provider ("notify all enabled" parity). Disabled connectors named
/// explicitly are still honored (the user asked for them by id); the fallback path is enabled-only.
async fn resolve_connectors(
    db: &SqlitePool,
    provider: &str,
    recipients: &[String],
) -> Vec<crate::local::store::notification_connectors::NotificationConnector> {
    use crate::local::store::notification_connectors as store;

    // Parse recipient refs of the form `provider:id`, keeping only those for this provider.
    let ids: Vec<i64> = recipients
        .iter()
        .filter_map(|r| r.split_once(':'))
        .filter(|(p, _)| *p == provider)
        .filter_map(|(_, id)| id.trim().parse::<i64>().ok())
        .collect();

    if ids.is_empty() {
        // No explicit recipients for this provider → notify all enabled connectors of it.
        return store::list_by_provider_enabled(db, provider).await.unwrap_or_default();
    }

    let mut out = Vec::with_capacity(ids.len());
    for id in ids {
        match store::get_by_id(db, id).await {
            // Only honor a row that actually is this provider (guards a stale/mismatched ref).
            Ok(Some(c)) if c.provider == provider => out.push(c),
            _ => {}
        }
    }
    out
}

async fn run_notification_action(
    db: &SqlitePool,
    block: &FlowBlock,
    scope: &Map<String, Value>,
) -> Value {
    let cfg = &block.config;
    let channels: Vec<String> = cfg
        .get("channels")
        .and_then(Value::as_array)
        .map(|a| a.iter().filter_map(|v| v.as_str().map(str::to_string)).collect())
        .unwrap_or_default();
    // Recipient refs in the unified `provider:id` format (e.g. `slack:3`, `telegram:7`).
    let recipients: Vec<String> = cfg
        .get("recipients")
        .and_then(Value::as_array)
        .map(|a| a.iter().filter_map(|v| v.as_str().map(str::to_string)).collect())
        .unwrap_or_default();
    let title = cfg
        .get("title")
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty())
        .unwrap_or("Automation alert")
        .to_string();
    let template = cfg.get("template").and_then(Value::as_str).unwrap_or("");
    let message = render_template(template, scope);

    let mut delivered: Vec<Value> = Vec::new();
    let mut skipped: Vec<Value> = Vec::new();
    let mut relay_channels: Vec<String> = Vec::new();
    for ch in &channels {
        match ch.as_str() {
            "webhook" => {
                let url = cfg.get("webhook_url").and_then(Value::as_str).unwrap_or("");
                if !(url.starts_with("http://") || url.starts_with("https://")) {
                    skipped.push(json!({ "channel": "webhook", "reason": "missing or invalid webhook_url" }));
                } else if post_webhook(url, &title, &message).await {
                    delivered.push(json!({ "channel": "webhook" }));
                } else {
                    skipped.push(json!({ "channel": "webhook", "reason": "delivery failed" }));
                }
            }
            // Queue a real native OS toast for the app to raise on its next poll.
            "desktop" => {
                push_pending_toast(&title, &message);
                delivered.push(json!({ "channel": "desktop", "via": "os_toast" }));
            }
            // Recorded to the execution feed; the app renders these from the run log.
            "in_app" => delivered.push(json!({ "channel": "in_app", "via": "run_feed" })),
            // Fast connectors — plain outbound HTTP, so they deliver locally with no cloud relay.
            // Resolve the target connectors (from block `recipients` filtered to this provider, else
            // all enabled connectors of the provider) and POST the per-provider payload through the
            // SSRF-guarded senders. Each connector counts as its own delivered/skipped entry.
            provider @ ("slack" | "discord" | "telegram") => {
                let connectors =
                    resolve_connectors(db, provider, &recipients).await;
                if connectors.is_empty() {
                    skipped.push(json!({ "channel": provider, "reason": "no configured connector" }));
                } else {
                    for c in &connectors {
                        if deliver_to_connector(c, &title, &message).await {
                            delivered.push(json!({ "channel": provider, "connector_id": c.id }));
                        } else {
                            skipped.push(json!({ "channel": provider, "connector_id": c.id, "reason": "delivery failed" }));
                        }
                    }
                }
            }
            // Relay-needing channels (email / pushover / SMS / WhatsApp / Signal):
            // collected below and delivered through the linked cloud account's
            // notification relay in ONE call. Unlinked stays the honest skip.
            other => relay_channels.push(other.to_string()),
        }
    }

    // The relay needs the linked managed-cloud account (`local::cloud`), which the cloud-free
    // fleet/self-host build compiles out — those builds take the honest cloud_only_channel skip.
    #[cfg(feature = "cloud")]
    // The relay client (`local::cloud`) only exists in the managed `cloud` build;
    // the fleet/self-host build keeps the honest cloud_only_channel skip.
    #[cfg(not(feature = "cloud"))]
    if !relay_channels.is_empty() {
        for ch in &relay_channels {
            skipped.push(json!({ "channel": ch, "reason": "cloud_only_channel" }));
        }
    }
    #[cfg(feature = "cloud")]
    if !relay_channels.is_empty() {
        if crate::local::cloud::notify::is_linked(db).await {
            let body = json!({
                "channels": relay_channels,
                "recipients": if recipients.is_empty() { Value::Null } else { json!(recipients) },
                "title": title,
                "message": message,
                "priority": cfg.get("priority").cloned().unwrap_or(Value::Null),
                "url": cfg.get("url").cloned().unwrap_or(Value::Null),
                "email_subject": cfg.get("email_subject").cloned().unwrap_or(Value::Null),
            });
            match crate::local::cloud::notify::relay(db, &body).await {
                Ok(res) => {
                    let sent = res.get("total_sent").and_then(Value::as_i64).unwrap_or(0);
                    for ch in &relay_channels {
                        // Per-channel result from the relay response when present;
                        // fall back to the aggregate.
                        let ch_res = res.get("results").and_then(|r| r.get(ch.as_str()));
                        let ch_sent = ch_res
                            .and_then(|r| r.get("sent"))
                            .and_then(Value::as_i64)
                            .unwrap_or(sent);
                        if ch_sent > 0 {
                            delivered.push(json!({ "channel": ch, "via": "cloud_relay", "sent": ch_sent }));
                        } else {
                            let reason = ch_res
                                .and_then(|r| r.get("reason"))
                                .and_then(Value::as_str)
                                .unwrap_or("no recipients or provider not configured in the cloud");
                            skipped.push(json!({ "channel": ch, "reason": reason }));
                        }
                    }
                }
                Err(e) => {
                    tracing::warn!("cloud notification relay failed: {e}");
                    for ch in &relay_channels {
                        skipped.push(json!({ "channel": ch, "reason": "cloud relay failed" }));
                    }
                }
            }
        } else {
            for ch in &relay_channels {
                skipped.push(json!({ "channel": ch, "reason": "cloud_only_channel" }));
            }
        }
    }
    #[cfg(not(feature = "cloud"))]
    for ch in &relay_channels {
        skipped.push(json!({ "channel": ch, "reason": "cloud_only_channel" }));
    }

    json!({
        "action": "notification",
        "title": title,
        "message": message,
        "delivered": delivered,
        "skipped_channels": skipped,
        "skipped": delivered.is_empty(),
    })
}

/// Best-effort per-monitor DIRECT notification delivery on change detection — the sibling of
/// automation dispatch, but keyed off the target's own `notification_providers` map instead of an
/// automation's block tree. Independent of automations (both may fire for one change).
///
/// `providers_json` is the target's `notification_providers` column (a JSON `{provider: bool}` map,
/// or `None`/empty → no-op). Title/message come from the target's own `notification_title` /
/// `notification_message` columns: title defaults to "Writ: Change Detected"; message is
/// `render_template`d against `scope` when set, else a plain default body including the URL (pulled
/// from `scope["url"]`). Delivers `desktop` via the OS-toast queue, `slack`/`discord`/`telegram`
/// via every enabled connector of that provider (SSRF-guarded), and records `in_app`. Every other
/// provider (`email`/`pushover`/`twilio`/`whatsapp`/`signal`/`webhook`) is cloud-only / needs a URL
/// and is skipped silently here. Never returns an error: any delivery failure is logged and
/// swallowed so a monitor run can't be broken by a notification.
pub(crate) async fn dispatch_direct_notifications(
    db: &SqlitePool,
    providers_json: Option<&str>,
    notification_title: Option<&str>,
    notification_message: Option<&str>,
    scope: &Map<String, Value>,
) {
    let title = notification_title
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .unwrap_or("Writ: Change Detected")
        .to_string();
    let message = match notification_message.map(str::trim).filter(|s| !s.is_empty()) {
        Some(tmpl) => render_template(tmpl, scope),
        None => {
            let url = scope.get("url").and_then(Value::as_str).unwrap_or("the monitored page");
            format!("A change was detected on {url}.")
        }
    };
    let (title, message) = (title.as_str(), message.as_str());

    // Parse `{provider: bool}`; anything unparseable or empty means "no direct notifications".
    let map: Map<String, Value> = match providers_json {
        Some(raw) if !raw.trim().is_empty() => match serde_json::from_str::<Value>(raw) {
            Ok(Value::Object(m)) => m,
            _ => {
                tracing::debug!("target notification_providers not a JSON object; skipping direct notify");
                return;
            }
        },
        _ => return,
    };

    for (provider, on) in map.iter() {
        // Only truthy providers fire (JSON `true`, or a truthy string/number as a tolerance).
        let enabled = on.as_bool().unwrap_or_else(|| match on {
            Value::String(s) => matches!(s.as_str(), "1" | "true" | "yes"),
            Value::Number(n) => n.as_i64().map(|v| v != 0).unwrap_or(false),
            _ => false,
        });
        if !enabled {
            continue;
        }
        match provider.as_str() {
            "desktop" => {
                push_pending_toast(title, message);
                tracing::debug!("direct-notify: queued desktop toast");
            }
            // `in_app` normally lands in the automation execution feed; a direct monitor notify has
            // no execution row here, so record intent via tracing. (No-op delivery is acceptable.)
            "in_app" => {
                tracing::info!(title = %title, "direct-notify: in_app change notification");
            }
            provider @ ("slack" | "discord" | "telegram") => {
                let connectors = crate::local::store::notification_connectors::list_by_provider_enabled(
                    db, provider,
                )
                .await
                .unwrap_or_default();
                if connectors.is_empty() {
                    tracing::debug!(provider, "direct-notify: no configured connector; skipping");
                    continue;
                }
                for c in &connectors {
                    // Delivery is fallible (network/HTTP) but non-fatal: log and continue.
                    if deliver_to_connector(c, title, message).await {
                        tracing::debug!(provider, connector_id = c.id, "direct-notify: delivered");
                    } else {
                        tracing::warn!(provider, connector_id = c.id, "direct-notify: delivery failed");
                    }
                }
            }
            // email/pushover/twilio/whatsapp/signal/webhook: cloud-only or needs a per-target URL
            // not modeled on the desktop target — skip without error.
            other => {
                tracing::debug!(provider = other, "direct-notify: provider not deliverable on desktop; skipping");
            }
        }
    }
}

/// Run a `save_data_to_file` / `query_and_export` action: export the source workflow's extracted
/// data (redacted via the shared Data path) to an encrypted StoredFile, and merge `{ file_id,
/// filename }` into a forked scope so a downstream `send_file` (or template) can reference it.
///
/// Config: `source_workflow_id` (falls back to the automation's own linked workflow), `format`
/// (`csv`|`json`, default csv), and an optional structured-filter array under `filters`. Requires an
/// engine that exposes a vault; a vaultless build records a skip (no encrypted store to write to).
async fn run_export_to_file_action(
    ctx: &FlowCtx<'_>,
    block: &FlowBlock,
    scope: &Map<String, Value>,
) -> (Value, Map<String, Value>) {
    let action = block.block_type.clone();
    let workflow_id = block
        .config
        .get("source_workflow_id")
        .and_then(Value::as_i64)
        .or(ctx.auto_workflow_id);

    let Some(workflow_id) = workflow_id else {
        return (
            json!({ "action": action, "skipped": true, "reason": "no source_workflow_id configured" }),
            scope.clone(),
        );
    };

    let Some(vault) = ctx.engine.vault() else {
        return (
            json!({ "action": action, "skipped": true, "reason": "cloud_only" }),
            scope.clone(),
        );
    };
    let paths = match crate::local::config::Paths::resolve() {
        Ok(p) => p,
        Err(e) => {
            return (
                json!({ "action": action, "ok": false, "error": format!("paths unresolved: {e}") }),
                scope.clone(),
            );
        }
    };

    let format = block
        .config
        .get("format")
        .and_then(Value::as_str)
        .filter(|f| f.eq_ignore_ascii_case("json") || f.eq_ignore_ascii_case("csv"))
        .unwrap_or("csv");
    let filters_str = block.config.get("filters").map(|v| v.to_string());

    match crate::local::api::v1::data::export_workflow_data_bytes(
        ctx.db,
        workflow_id,
        format,
        filters_str.as_deref(),
    )
    .await
    {
        Ok((bytes, filename, content_type)) => {
            match crate::local::storage::create_file(
                ctx.db,
                &vault,
                &paths,
                &bytes,
                &filename,
                Some(&content_type),
                "workflow_output",
            )
            .await
            {
                Ok(file) => {
                    let mut child_scope = scope.clone();
                    child_scope.insert("file_id".into(), json!(file.id));
                    child_scope.insert("filename".into(), json!(file.filename));
                    let record = json!({
                        "action": action,
                        "ok": true,
                        "file_id": file.id,
                        "filename": file.filename,
                        "size_bytes": file.size_bytes,
                        "source_workflow_id": workflow_id,
                    });
                    (record, child_scope)
                }
                Err(e) => (
                    json!({ "action": action, "ok": false, "error": e.to_string() }),
                    scope.clone(),
                ),
            }
        }
        Err(e) => (
            json!({ "action": action, "ok": false, "error": e.to_string() }),
            scope.clone(),
        ),
    }
}

/// Run a `send_file` action: if a webhook `url` (or `recipient`) is configured, POST a file
/// reference (the `file_id`/`filename` a preceding export merged into scope) to it; else record a
/// cloud-only skip (email/etc. file delivery needs the cloud relay).
async fn run_send_file_action(block: &FlowBlock, scope: &Map<String, Value>) -> Value {
    let cfg = &block.config;
    // A webhook target may live under `url`, `webhook_url`, or `recipient` (a URL string).
    let url = cfg
        .get("url")
        .or_else(|| cfg.get("webhook_url"))
        .or_else(|| cfg.get("recipient"))
        .and_then(Value::as_str)
        .unwrap_or("");

    // The file reference to send: prefer an explicit config file_id, else what an upstream export
    // merged into scope.
    let file_id = cfg
        .get("file_id")
        .and_then(Value::as_str)
        .map(str::to_string)
        .or_else(|| scope.get("file_id").and_then(Value::as_str).map(str::to_string));
    let filename = scope.get("filename").and_then(Value::as_str).unwrap_or("").to_string();

    if !(url.starts_with("http://") || url.starts_with("https://")) {
        return json!({
            "action": "send_file",
            "skipped": true,
            "reason": "cloud_only",
        });
    }

    let payload = json!({
        "type": "file",
        "file_id": file_id,
        "filename": filename,
    });
    let ok = post_json(url, &payload).await;
    json!({
        "action": "send_file",
        "ok": ok,
        "file_id": file_id,
        "delivered": ok,
        "skipped": !ok,
    })
}

/// Run a `start_streaming_session` / `stop_streaming_session` action via the engine's streaming
/// manager. Config: `workflow_id` (falls back to the automation's own linked workflow). Merges
/// `{ session_key, streaming_status }` into a forked scope. A vaultless/streamless engine records a
/// cloud-only skip.
async fn run_streaming_action(
    ctx: &FlowCtx<'_>,
    block: &FlowBlock,
    scope: &Map<String, Value>,
) -> (Value, Map<String, Value>) {
    let action = block.block_type.clone();
    let stop = action == "stop_streaming_session";

    let workflow_id = block
        .config
        .get("workflow_id")
        .and_then(Value::as_i64)
        .or(ctx.auto_workflow_id);
    let Some(workflow_id) = workflow_id else {
        return (
            json!({ "action": action, "skipped": true, "reason": "no workflow_id configured" }),
            scope.clone(),
        );
    };

    let Some(mgr) = ctx.engine.streaming() else {
        return (
            json!({ "action": action, "skipped": true, "reason": "cloud_only" }),
            scope.clone(),
        );
    };

    if stop {
        let reason = block
            .config
            .get("reason")
            .and_then(Value::as_str)
            .unwrap_or("automation");
        match mgr.stop_session(workflow_id, reason).await {
            Some(info) => {
                let mut child_scope = scope.clone();
                child_scope.insert("session_key".into(), json!(info.session_key));
                child_scope.insert("streaming_status".into(), json!(info.status));
                (
                    json!({
                        "action": action,
                        "ok": true,
                        "workflow_id": workflow_id,
                        "session_key": info.session_key,
                        "streaming_status": info.status,
                    }),
                    child_scope,
                )
            }
            None => (
                json!({
                    "action": action,
                    "ok": true,
                    "workflow_id": workflow_id,
                    "stopped": false,
                    "detail": "no live session",
                }),
                scope.clone(),
            ),
        }
    } else {
        // Start: resolve the workflow row, then find-or-start its session.
        let wf = match crate::local::store::workflows::get_by_id(ctx.db, workflow_id).await {
            Ok(Some(wf)) => wf,
            Ok(None) => {
                return (
                    json!({ "action": action, "ok": false, "error": format!("workflow {workflow_id} not found") }),
                    scope.clone(),
                );
            }
            Err(e) => {
                return (
                    json!({ "action": action, "ok": false, "error": e.to_string() }),
                    scope.clone(),
                );
            }
        };
        match mgr.start_session(&wf).await {
            Ok(info) => {
                let mut child_scope = scope.clone();
                child_scope.insert("session_key".into(), json!(info.session_key));
                child_scope.insert("streaming_status".into(), json!(info.status));
                (
                    json!({
                        "action": action,
                        "ok": true,
                        "workflow_id": workflow_id,
                        "session_key": info.session_key,
                        "streaming_status": info.status,
                    }),
                    child_scope,
                )
            }
            Err(e) => (
                json!({ "action": action, "ok": false, "error": e.to_string() }),
                scope.clone(),
            ),
        }
    }
}

/// POST an arbitrary JSON payload to a webhook (used by `send_file`). Returns whether accepted (2xx).
async fn post_json(url: &str, payload: &Value) -> bool {
    // SECURITY (SSRF): same guard as `post_webhook` — the `send_file` target URL is user-supplied.
    if !crate::security::url_guard::is_navigation_url_safe_async(url).await {
        tracing::warn!("send_file webhook blocked: unsafe URL");
        return false;
    }
    let client = match reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .redirect(reqwest::redirect::Policy::none())
        .build()
    {
        Ok(c) => c,
        Err(_) => return false,
    };
    match client.post(url).json(payload).send().await {
        Ok(resp) => resp.status().is_success(),
        Err(_) => false,
    }
}

/// Whether a value counts as "empty" for `exists`/`changed` (null, "", [], {}).
fn is_empty_value(v: &Value) -> bool {
    match v {
        Value::Null => true,
        Value::String(s) => s.is_empty(),
        Value::Array(a) => a.is_empty(),
        Value::Object(o) => o.is_empty(),
        _ => false,
    }
}

/// Lowercase status token used in scope/records (mirrors the flow-builder field vocabulary).
fn status_str(s: RunStatus) -> &'static str {
    match s {
        RunStatus::Running => "running",
        RunStatus::Success => "success",
        RunStatus::Failed => "failed",
        RunStatus::Cancelled => "cancelled",
        RunStatus::Timeout => "timeout",
        RunStatus::CaptchaRequired => "captcha_required",
        RunStatus::TwofaRequired => "twofa_required",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scope(pairs: &[(&str, Value)]) -> Map<String, Value> {
        pairs.iter().map(|(k, v)| (k.to_string(), v.clone())).collect()
    }

    #[test]
    fn lookup_dot_path() {
        let s = scope(&[("result", json!({ "price": 42, "nested": { "k": "v" } }))]);
        assert_eq!(lookup_path(&s, "result.price"), Some(&json!(42)));
        assert_eq!(lookup_path(&s, "result.nested.k"), Some(&json!("v")));
        assert_eq!(lookup_path(&s, "result.missing"), None);
        assert_eq!(lookup_path(&s, "absent"), None);
    }

    #[test]
    fn condition_text_operators() {
        let s = scope(&[("status", json!("Order shipped"))]);
        assert!(eval_condition(
            &json!({ "field": "status", "operator": "contains", "value": "shipped" }),
            &s
        ));
        assert!(eval_condition(
            &json!({ "field": "status", "operator": "not_contains", "value": "cancelled" }),
            &s
        ));
        assert!(!eval_condition(
            &json!({ "field": "status", "operator": "equals", "value": "shipped" }),
            &s
        ));
        assert!(eval_condition(
            &json!({ "field": "status", "operator": "matches", "value": "^Order .*ed$" }),
            &s
        ));
    }

    #[test]
    fn condition_numeric_and_special() {
        let s = scope(&[("result", json!({ "count": 7 })), ("error", json!(""))]);
        assert!(eval_condition(
            &json!({ "field": "result.count", "operator": "gt", "value": "5" }),
            &s
        ));
        assert!(!eval_condition(
            &json!({ "field": "result.count", "operator": "lte", "value": "6" }),
            &s
        ));
        assert!(eval_condition(
            &json!({ "field": "result.count", "operator": "exists" }),
            &s
        ));
        // empty string → does not "exist"
        assert!(!eval_condition(
            &json!({ "field": "error", "operator": "exists" }),
            &s
        ));
        // numeric equality across string/number
        assert!(eval_condition(
            &json!({ "field": "result.count", "operator": "equals", "value": "7" }),
            &s
        ));
    }

    #[test]
    fn condition_unconfigured_field_passes() {
        let s = scope(&[]);
        assert!(eval_condition(&json!({ "operator": "contains", "value": "x" }), &s));
    }

    #[test]
    fn oversized_regex_is_false_not_panic() {
        let s = scope(&[("v", json!("abc"))]);
        let big = "a".repeat(MAX_REGEX_PATTERN_LEN + 1);
        assert!(!regex_matches(&big, "abc"));
        // invalid pattern → false
        assert!(!eval_condition(
            &json!({ "field": "v", "operator": "matches", "value": "(" }),
            &s
        ));
    }

    #[test]
    fn status_gate() {
        // success gate matches only a successful trigger context
        assert!(status_gate_matches(&json!({ "status_condition": "success" }), &json!({ "success": true })));
        assert!(!status_gate_matches(&json!({ "status_condition": "success" }), &json!({ "success": false })));
        assert!(status_gate_matches(&json!({ "status_condition": "error" }), &json!({ "success": false })));
        // absent / any → always matches
        assert!(status_gate_matches(&json!({}), &json!({ "success": false })));
        assert!(status_gate_matches(&json!({ "status_condition": "any" }), &json!({})));
    }

    #[test]
    fn parse_blocks_tolerates_garbage() {
        assert!(parse_blocks(None).is_empty());
        assert!(parse_blocks(Some("   ")).is_empty());
        assert!(parse_blocks(Some("not json")).is_empty());
        let one = parse_blocks(Some(
            r#"[{"id":"a","type":"event","blockType":"change_detected","config":{}}]"#,
        ));
        assert_eq!(one.len(), 1);
        assert_eq!(one[0].block_type, "change_detected");
    }

    #[test]
    fn has_executable_tree_detects_actions() {
        assert!(!has_executable_tree(None));
        // event-only tree is NOT executable (legacy fallback would run the linked workflow)
        assert!(!has_executable_tree(Some(
            r#"[{"id":"e","type":"event","blockType":"change_detected"}]"#
        )));
        assert!(has_executable_tree(Some(
            r#"[{"id":"e","type":"event","blockType":"change_detected"},
                {"id":"a","type":"action","blockType":"workflow","parentId":"e","config":{"workflow_id":1}}]"#
        )));
    }

    // --- end-to-end walk over a real DB with a canned engine -------------------------------------

    use crate::local::db;
    use crate::local::engine::{RunResult, StartedRun};
    use crate::local::store::automations::{self, NewAutomation};
    use crate::local::store::workflows::{self, NewWorkflow};

    /// A canned engine: every `run` succeeds with a fixed `extracted_data`, recording the workflow ids
    /// it was asked to run. Implements only what `run_automation` touches.
    struct MockEngine {
        data: Value,
        ran: std::sync::Mutex<Vec<i64>>,
    }
    impl MockEngine {
        fn new() -> Self {
            Self { data: json!({ "value": 1 }), ran: std::sync::Mutex::new(Vec::new()) }
        }
    }
    impl LocalEngine for MockEngine {
        fn run<'a>(
            &'a self,
            req: RunRequest,
        ) -> Pin<Box<dyn Future<Output = LocalResult<RunResult>> + Send + 'a>> {
            self.ran.lock().unwrap().push(req.workflow_id);
            let data = self.data.clone();
            Box::pin(async move {
                Ok(RunResult {
                    run_id: req.workflow_id,
                    status: RunStatus::Success,
                    success: true,
                    error: None,
                    extracted_data: data,
                    duration_ms: 5,
                })
            })
        }
        fn active_runs(&self) -> usize {
            0
        }
        fn run_async<'a>(
            &'a self,
            req: RunRequest,
        ) -> Pin<Box<dyn Future<Output = LocalResult<StartedRun>> + Send + 'a>> {
            Box::pin(async move { Ok(StartedRun { run_id: req.workflow_id, status: RunStatus::Running }) })
        }
    }

    async fn test_pool() -> SqlitePool {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("t.db");
        std::mem::forget(dir);
        db::open(&path, "test-key").await.unwrap()
    }

    fn tree_event_condition_two_workflows(go_value: &str) -> String {
        json!([
            { "id": "e", "type": "event", "blockType": "webhook_received", "config": {} },
            { "id": "c", "type": "condition", "blockType": "condition", "parentId": "e",
              "config": { "field": "payload.go", "operator": "equals", "value": go_value } },
            { "id": "a", "type": "action", "blockType": "workflow", "parentId": "c",
              "config": { "workflow_id": 101 } },
            { "id": "b", "type": "action", "blockType": "workflow", "parentId": "c",
              "config": { "workflow_id": 102 } },
            { "id": "n", "type": "action", "blockType": "notification", "parentId": "c", "config": {} }
        ])
        .to_string()
    }

    async fn make_auto(pool: &SqlitePool, blocks: String) -> Automation {
        automations::insert(
            pool,
            &NewAutomation {
                name: "flow".into(),
                event_type: Some("webhook_received".into()),
                blocks: Some(blocks),
                ..Default::default()
            },
        )
        .await
        .unwrap()
    }

    fn webhook_trigger(go: &str) -> FlowTrigger {
        FlowTrigger {
            event: "webhook_received".into(),
            change_id: None,
            base_inputs: json!({}),
            context: json!({ "event": "webhook_received", "payload": { "go": go } }),
            source: RunSource::Webhook,
            lane: Lane::Background,
        }
    }

    #[test]
    fn render_template_substitutes_and_tolerates_unknown() {
        let mut scope = Map::new();
        scope.insert("result".into(), json!({ "price": "42", "name": "Widget" }));
        assert_eq!(render_template("{{result.name}} is {{result.price}}", &scope), "Widget is 42");
        assert_eq!(render_template("gone: {{missing.x}}!", &scope), "gone: !");
        assert_eq!(render_template("literal {{unterminated", &scope), "literal {{unterminated");
    }

    #[test]
    fn render_template_applies_transform_filters() {
        let mut scope = Map::new();
        scope.insert("result".into(), json!({ "price": 100, "name": "  Widget PRO  " }));
        scope.insert("sku".into(), json!("ABC123"));
        scope.insert("empty".into(), json!(""));
        // Parity with the cloud _apply_template_filter test cases.
        assert_eq!(render_template("{{result.price | mul:1.1 | round:2}}", &scope), "110.00");
        assert_eq!(render_template("{{result.price | mul:1.1}}", &scope), "110");
        assert_eq!(render_template("{{result.name | trim | lower}}", &scope), "widget pro");
        assert_eq!(render_template("{{missing | default:none}}", &scope), "none");
        assert_eq!(render_template("{{empty | or:fallback}}", &scope), "fallback");
        assert_eq!(render_template("{{sku | match:([A-Z]+)}}", &scope), "ABC");
        assert_eq!(render_template("{{result.price | add:5}}", &scope), "105");
        assert_eq!(render_template("{{result.price | div:3 | round:2}}", &scope), "33.33");
        assert_eq!(render_template("{{result.name | trim | truncate:6}}", &scope), "Widget");
        // Unknown filter passes through; bare path unchanged.
        assert_eq!(render_template("{{result.price | wat}}", &scope), "100");
    }

    #[tokio::test]
    async fn notification_delivers_in_app_and_skips_cloud_channels() {
        // in_app needs no network; a cloud channel (email) is recorded as skipped, not delivered.
        let block = FlowBlock {
            id: "n".into(),
            kind: "action".into(),
            block_type: "notification".into(),
            config: json!({ "channels": ["in_app", "email"], "template": "hi {{result.name}}" }),
            parent_id: None,
        };
        let mut scope = Map::new();
        scope.insert("result".into(), json!({ "name": "Bob" }));
        let pool = test_pool().await;
        let rec = run_notification_action(&pool, &block, &scope).await;
        assert_eq!(rec["message"], "hi Bob");
        assert_eq!(rec["skipped"], false);
        assert_eq!(rec["delivered"][0]["channel"], "in_app");
        assert_eq!(rec["skipped_channels"][0]["reason"], "cloud_only_channel");
    }

    #[tokio::test]
    async fn desktop_channel_queues_an_os_toast() {
        let block = FlowBlock {
            id: "n".into(),
            kind: "action".into(),
            block_type: "notification".into(),
            config: json!({ "channels": ["desktop"], "title": "Hi", "template": "price {{result.price}}" }),
            parent_id: None,
        };
        let mut scope = Map::new();
        scope.insert("result".into(), json!({ "price": "9.99" }));
        let pool = test_pool().await;
        let rec = run_notification_action(&pool, &block, &scope).await;
        assert_eq!(rec["delivered"][0]["channel"], "desktop");
        assert_eq!(rec["delivered"][0]["via"], "os_toast");
        let drained = drain_pending_toasts();
        assert!(drained.iter().any(|t| t["title"] == "Hi" && t["body"] == "price 9.99"));
        // Draining is one-shot: a second drain does not re-surface it.
        assert!(!drain_pending_toasts().iter().any(|t| t["title"] == "Hi"));
    }

    #[tokio::test]
    async fn direct_notifications_desktop_defaults_and_renders_message() {
        drain_pending_toasts(); // clear any residue from other tests
        let pool = test_pool().await;
        let mut scope = Map::new();
        scope.insert("url".into(), json!("https://example.com/watch"));

        // Default title, rendered custom message.
        dispatch_direct_notifications(
            &pool,
            Some(r#"{"desktop": true, "email": true, "signal": false}"#),
            None,
            Some("changed at {{url}}"),
            &scope,
        )
        .await;
        let drained = drain_pending_toasts();
        let toast = drained
            .iter()
            .find(|t| t["title"] == "Writ: Change Detected")
            .expect("desktop toast queued with default title");
        assert_eq!(toast["body"], "changed at https://example.com/watch");
        // email was enabled but is cloud-only → no extra toast.
        assert_eq!(drained.len(), 1);
    }

    #[tokio::test]
    async fn direct_notifications_default_body_and_empty_map_noop() {
        drain_pending_toasts();
        let pool = test_pool().await;
        let mut scope = Map::new();
        scope.insert("url".into(), json!("https://shop.test/item"));

        // No message → plain default body including the url.
        dispatch_direct_notifications(&pool, Some(r#"{"desktop": true}"#), None, None, &scope).await;
        let drained = drain_pending_toasts();
        assert!(drained.iter().any(|t| t["body"] == "A change was detected on https://shop.test/item."));

        // Empty / none providers → no delivery at all.
        dispatch_direct_notifications(&pool, Some("{}"), None, None, &scope).await;
        dispatch_direct_notifications(&pool, None, None, None, &scope).await;
        assert!(drain_pending_toasts().is_empty());
    }

    #[tokio::test]
    async fn resolve_connectors_filters_by_provider_and_falls_back_to_enabled() {
        use crate::local::store::notification_connectors as store;
        let pool = test_pool().await;
        let slack = store::insert(
            &pool,
            &store::NewNotificationConnector {
                provider: "slack".into(),
                name: "team".into(),
                webhook_url: Some("https://hooks.slack.com/services/AAA".into()),
                ..Default::default()
            },
        )
        .await
        .unwrap();
        let _tg = store::insert(
            &pool,
            &store::NewNotificationConnector {
                provider: "telegram".into(),
                name: "bot".into(),
                bot_token: Some("123:abc".into()),
                chat_id: Some("-100".into()),
                ..Default::default()
            },
        )
        .await
        .unwrap();

        // Explicit ref for slack → exactly that connector, telegram refs ignored for slack channel.
        let refs = vec![format!("slack:{}", slack.id), "telegram:9999".into()];
        let got = resolve_connectors(&pool, "slack", &refs).await;
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].id, slack.id);

        // No slack refs → fall back to all enabled slack connectors.
        let fallback = resolve_connectors(&pool, "slack", &["telegram:1".into()]).await;
        assert_eq!(fallback.len(), 1);
        assert_eq!(fallback[0].id, slack.id);

        // A ref whose id belongs to a different provider is dropped (guards mismatched refs).
        let mismatched = resolve_connectors(&pool, "slack", &[format!("slack:{}", _tg.id)]).await;
        assert!(mismatched.is_empty());
    }

    #[tokio::test]
    async fn webhook_to_internal_address_is_blocked() {
        // SSRF: the webhook channel must route through url_guard, so a run/admin key on a
        // LAN-exposed daemon cannot aim a notification at cloud metadata or an RFC1918 host.
        // post_webhook fails closed on such a target (returns false → "delivery failed").
        assert!(
            !post_webhook("http://169.254.169.254/latest/meta-data/", "t", "m").await,
            "webhook to the cloud metadata IP must be refused"
        );
        assert!(
            !post_webhook("http://192.168.1.1/hook", "t", "m").await,
            "webhook to an RFC1918 host must be refused"
        );
        // The send_file JSON path shares the same guard.
        assert!(
            !post_json("http://169.254.169.254/", &json!({ "x": 1 })).await,
            "send_file webhook to the metadata IP must be refused"
        );
    }

    #[tokio::test]
    async fn notification_with_no_channels_is_skipped() {
        let block = FlowBlock {
            id: "n".into(),
            kind: "action".into(),
            block_type: "notification".into(),
            config: json!({}),
            parent_id: None,
        };
        let pool = test_pool().await;
        let rec = run_notification_action(&pool, &block, &Map::new()).await;
        assert_eq!(rec["skipped"], true);
    }

    /// `send_file` with a valid webhook URL absent → cloud-only skip; the action never fails the flow.
    #[tokio::test]
    async fn send_file_without_webhook_is_cloud_only_skip() {
        let block = FlowBlock {
            id: "s".into(),
            kind: "action".into(),
            block_type: "send_file".into(),
            config: json!({ "recipient": "alice@example.com" }), // not an http(s) URL
            parent_id: None,
        };
        let rec = run_send_file_action(&block, &Map::new()).await;
        assert_eq!(rec["skipped"], true);
        assert_eq!(rec["reason"], "cloud_only");
    }

    /// `save_data_to_file` on a vaultless engine (the test `MockEngine`) records a `cloud_only` skip
    /// rather than failing — the arm degrades gracefully where there is no encrypted store to write.
    #[tokio::test]
    async fn save_data_to_file_without_vault_is_skipped() {
        let pool = test_pool().await;
        let blocks = json!([
            { "id": "e", "type": "event", "blockType": "webhook_received", "config": {} },
            { "id": "f", "type": "action", "blockType": "save_data_to_file", "parentId": "e",
              "config": { "source_workflow_id": 7, "format": "csv" } }
        ])
        .to_string();
        let auto = make_auto(&pool, blocks).await;
        let engine: Arc<dyn LocalEngine> = Arc::new(MockEngine::new());

        let exec = run_automation(&pool, &engine, &auto, webhook_trigger("go"))
            .await
            .unwrap()
            .expect("execution recorded");
        assert_eq!(exec.status.as_deref(), Some("success"));
        let results: Vec<Value> = serde_json::from_str(&exec.action_results).unwrap();
        let rec = results
            .iter()
            .find(|r| r["action"] == "save_data_to_file")
            .expect("save_data_to_file recorded");
        assert_eq!(rec["skipped"], true);
        assert_eq!(rec["reason"], "cloud_only");
    }

    /// The inline spec resolver folds `form_data` into both maps, appends `user_context` to the goal,
    /// clamps `max_steps`, and rejects an empty goal — all without a DB or browser.
    #[test]
    fn ai_session_inline_spec_resolution() {
        // No goal at all → None (nothing to run).
        assert!(resolve_ai_session_spec_inline(&json!({})).is_none());

        let spec = resolve_ai_session_spec_inline(&json!({
            "goal": "sign up",
            "user_context": "use the beta form",
            "form_data": { "email": "a@b.co" },
            "fill_data": { "password": "s3cret" },
            "max_steps": 500,
            "entry_url": "https://example.com/signup",
        }))
        .expect("has a goal");
        assert!(spec.goal.contains("sign up"));
        assert!(spec.goal.contains("use the beta form"));
        assert_eq!(spec.max_steps, 100); // clamped 1..=100
        assert_eq!(spec.entry_url.as_deref(), Some("https://example.com/signup"));
        // form_data seeds available_data AND fill_data; explicit fill_data is preserved.
        assert_eq!(spec.available_data.get("email").map(String::as_str), Some("a@b.co"));
        assert_eq!(spec.fill_data.get("email").map(String::as_str), Some("a@b.co"));
        assert_eq!(spec.fill_data.get("password").map(String::as_str), Some("s3cret"));
        assert!(spec.source_session_id.is_none());
    }

    /// `ai_session_ref_id` prefers `ai_session_id`, else the first `session_ids` element.
    #[test]
    fn ai_session_ref_id_prefers_explicit() {
        assert_eq!(ai_session_ref_id(&json!({ "ai_session_id": 7 })), Some(7));
        assert_eq!(ai_session_ref_id(&json!({ "session_ids": [12, 13] })), Some(12));
        assert_eq!(ai_session_ref_id(&json!({ "goal": "x" })), None);
    }

    /// An `ai_session` action on an engine with no vault/browser (the `MockEngine`) records a skip —
    /// it never fails the automation. Exercises the full arm via `run_automation` (no live browser).
    #[tokio::test]
    async fn ai_session_without_provider_is_skipped() {
        let pool = test_pool().await;
        let blocks = json!([
            { "id": "e", "type": "event", "blockType": "webhook_received", "config": {} },
            { "id": "a", "type": "action", "blockType": "ai_session", "parentId": "e",
              "config": { "goal": "fill the form", "entry_url": "https://example.com" } }
        ])
        .to_string();
        let auto = make_auto(&pool, blocks).await;
        let engine: Arc<dyn LocalEngine> = Arc::new(MockEngine::new());

        let exec = run_automation(&pool, &engine, &auto, webhook_trigger("go"))
            .await
            .unwrap()
            .expect("execution recorded");
        // No workflow action failed → the automation is a success despite the skipped AI action.
        assert_eq!(exec.status.as_deref(), Some("success"));
        let results: Vec<Value> = serde_json::from_str(&exec.action_results).unwrap();
        let rec = results
            .iter()
            .find(|r| r["action"] == "ai_session")
            .expect("ai_session recorded");
        assert_eq!(rec["skipped"], true);
        // A vaultless MockEngine short-circuits at the provider (cloud_only) gate.
        assert_eq!(rec["reason"], "cloud_only");
    }

    /// A goalless `ai_session` action records a clean skip (no browser/provider work attempted).
    #[tokio::test]
    async fn ai_session_without_goal_is_skipped() {
        let pool = test_pool().await;
        let blocks = json!([
            { "id": "e", "type": "event", "blockType": "webhook_received", "config": {} },
            { "id": "a", "type": "action", "blockType": "ai_session", "parentId": "e", "config": {} }
        ])
        .to_string();
        let auto = make_auto(&pool, blocks).await;
        let engine: Arc<dyn LocalEngine> = Arc::new(MockEngine::new());

        let exec = run_automation(&pool, &engine, &auto, webhook_trigger("go"))
            .await
            .unwrap()
            .expect("execution recorded");
        assert_eq!(exec.status.as_deref(), Some("success"));
        let results: Vec<Value> = serde_json::from_str(&exec.action_results).unwrap();
        let rec = results.iter().find(|r| r["action"] == "ai_session").unwrap();
        assert_eq!(rec["skipped"], true);
        assert_eq!(rec["reason"], "ai_session has no goal configured");
    }

    /// End-to-end of the SHARED export path a `save_data_to_file` action reuses: a successful run's
    /// extracted data exports to bytes and lands as an encrypted `workflow_output` StoredFile. Uses an
    /// isolated temp `Paths` + vault directly (no engine / no `WRIT_HOME` env), so it is hermetic.
    #[tokio::test]
    async fn export_to_file_roundtrip_produces_stored_file() {
        use crate::local::config::Paths;
        use crate::local::store::runs::{complete, insert, NewRun};
        use crate::local::store::workflows::{self, NewWorkflow};
        use crate::local::vault::Vault;

        let dir = Box::leak(Box::new(tempfile::tempdir().unwrap()));
        let paths = Paths::at(dir.path().join(".writ"));
        paths.ensure_dirs().unwrap();
        let vault = Vault::load_or_create(&paths.root, false).unwrap();
        let pool = db::open(&paths.db(), &vault.db_key_hex()).await.unwrap();

        let wf = workflows::insert(&pool, &NewWorkflow { name: "scrape".into(), ..Default::default() })
            .await
            .unwrap();
        let run = insert(&pool, &NewRun { workflow_id: Some(wf.id), ..Default::default() }).await.unwrap();
        complete(&pool, run.id, Some(r#"{"success":true,"extracted_data":{"title":"hello"}}"#), Some(5))
            .await
            .unwrap();

        // The shared export helper the file action calls.
        let (bytes, filename, content_type) =
            crate::local::api::v1::data::export_workflow_data_bytes(&pool, wf.id, "csv", None)
                .await
                .unwrap();
        assert!(filename.ends_with(".csv"));
        assert!(String::from_utf8_lossy(&bytes).contains("hello"));

        let file = crate::local::storage::create_file(
            &pool, &vault, &paths, &bytes, &filename, Some(&content_type), "workflow_output",
        )
        .await
        .unwrap();
        assert_eq!(file.source, "workflow_output");
        // Round-trips through the encrypted store.
        let back = crate::local::storage::read_file_bytes(&pool, &vault, &paths, &file.id).await.unwrap();
        assert_eq!(back, bytes);
    }

    fn auto_stub(conditions: &str, trigger_count: Option<i64>, last: Option<&str>) -> Automation {
        Automation {
            id: 1,
            target_id: None,
            event_type: "change_detected".into(),
            target_selector_id: None,
            workflow_id: None,
            webhook_trigger_id: None,
            name: "t".into(),
            description: None,
            enabled: 1,
            priority: None,
            conditions: conditions.into(),
            actions: "[]".into(),
            blocks: None,
            last_triggered_at: last.map(str::to_string),
            trigger_count,
            created_at: "2026-01-01T00:00:00Z".into(),
            updated_at: None,
        }
    }

    #[test]
    fn guardrail_max_fires_and_manual_bypass() {
        let hit = auto_stub(r#"{"max_fires":2}"#, Some(2), None);
        assert!(guardrail_block_reason(&hit, RunSource::Monitor).is_some());
        assert!(guardrail_block_reason(&hit, RunSource::Manual).is_none()); // manual bypasses
        let under = auto_stub(r#"{"max_fires":2}"#, Some(1), None);
        assert!(guardrail_block_reason(&under, RunSource::Monitor).is_none());
    }

    #[test]
    fn guardrail_cooldown_active_then_expired() {
        let recent = Utc::now().to_rfc3339();
        let active = auto_stub(r#"{"schedule":{"cooldown_minutes":10}}"#, Some(1), Some(&recent));
        assert!(guardrail_block_reason(&active, RunSource::Monitor).is_some());
        let old = (Utc::now() - ChronoDuration::minutes(20)).to_rfc3339();
        let expired = auto_stub(r#"{"schedule":{"cooldown_minutes":10}}"#, Some(1), Some(&old));
        assert!(guardrail_block_reason(&expired, RunSource::Monitor).is_none());
    }

    #[tokio::test]
    async fn tree_condition_pass_runs_parallel_branches() {
        let pool = test_pool().await;
        let auto = make_auto(&pool, tree_event_condition_two_workflows("yes")).await;
        let engine: Arc<dyn LocalEngine> = Arc::new(MockEngine::new());

        let exec = run_automation(&pool, &engine, &auto, webhook_trigger("yes"))
            .await
            .unwrap()
            .expect("execution recorded");
        assert_eq!(exec.status.as_deref(), Some("success"));

        let results: Vec<Value> = serde_json::from_str(&exec.action_results).unwrap();
        let workflows = results.iter().filter(|r| r["action"] == "workflow").count();
        assert_eq!(workflows, 2, "both parallel workflow branches ran");
        assert!(results
            .iter()
            .any(|r| r["action"] == "condition" && r["passed"] == true));
        assert!(results
            .iter()
            .any(|r| r["action"] == "notification" && r["skipped"] == true));

        // mark_triggered bumped the counter
        let refreshed = automations::get_by_id(&pool, auto.id).await.unwrap().unwrap();
        assert_eq!(refreshed.trigger_count, Some(1));
    }

    #[tokio::test]
    async fn tree_condition_fail_runs_nothing_downstream() {
        let pool = test_pool().await;
        // condition requires payload.go == "yes"; trigger sends "no"
        let auto = make_auto(&pool, tree_event_condition_two_workflows("yes")).await;
        let engine = Arc::new(MockEngine::new());
        let engine_dyn: Arc<dyn LocalEngine> = engine.clone();

        let exec = run_automation(&pool, &engine_dyn, &auto, webhook_trigger("no"))
            .await
            .unwrap()
            .expect("execution recorded");
        assert_eq!(exec.status.as_deref(), Some("success"));

        let results: Vec<Value> = serde_json::from_str(&exec.action_results).unwrap();
        assert!(results
            .iter()
            .any(|r| r["action"] == "condition" && r["passed"] == false));
        assert_eq!(
            results.iter().filter(|r| r["action"] == "workflow").count(),
            0,
            "no workflow ran when the condition failed"
        );
        assert!(engine.ran.lock().unwrap().is_empty(), "engine never invoked");
    }

    #[tokio::test]
    async fn legacy_no_blocks_runs_linked_workflow() {
        let pool = test_pool().await;
        // The automation's `workflow_id` column has a FK → workflows: create a real row first.
        let wf = workflows::insert(
            &pool,
            &NewWorkflow { name: "wf".into(), steps: Some("[]".into()), ..Default::default() },
        )
        .await
        .unwrap();
        let auto = automations::insert(
            &pool,
            &NewAutomation {
                name: "legacy".into(),
                event_type: Some("change_detected".into()),
                workflow_id: Some(wf.id),
                ..Default::default()
            },
        )
        .await
        .unwrap();
        let engine = Arc::new(MockEngine::new());
        let engine_dyn: Arc<dyn LocalEngine> = engine.clone();

        let exec = run_automation(
            &pool,
            &engine_dyn,
            &auto,
            FlowTrigger {
                event: "change_detected".into(),
                change_id: None,
                base_inputs: json!({}),
                context: json!({ "event": "change_detected" }),
                source: RunSource::Monitor,
                lane: Lane::Background,
            },
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(exec.status.as_deref(), Some("success"));
        assert_eq!(engine.ran.lock().unwrap().as_slice(), &[wf.id], "the linked workflow ran");
    }
}
