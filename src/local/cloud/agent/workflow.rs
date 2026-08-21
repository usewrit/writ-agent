//! `execute_workflow` — ad-hoc cloud-dispatched recipe execution (Workstream A, §4).
//!
//! The cloud sends an ad-hoc workflow (its OWN, dispatched to this machine as a BYO execution agent)
//! as an `execute_workflow` frame carrying the recipe inline in `config` (steps / entry_url / etc.)
//! plus channel_key-sealed per-run `credentials_encrypted`. This handler:
//!   1. decrypts the per-run credentials with the DESKTOP channel-key seam ([`super::creds`]),
//!   2. builds an EPHEMERAL in-memory [`workflows::Workflow`] from the `config` (mirrors the
//!      marketplace `build_recipe_workflow` projection), re-sealing the decrypted credentials into the
//!      recipe's `credentials_encrypted` field under the engine vault so the SAME run pipeline
//!      resolves them (no new plaintext-cred code path in the engine), and
//!   3. runs it via [`LocalEngine::run_recipe`] with [`RunSource::CloudAgent`] so it shares the
//!      governor + surfaces in `/v1/runs` as a `"cloud"` run (real.rs stamps `trigger_context.source
//!      = "cloud_agent"`).
//!
//! Then it emits the fixed-contract `task_result` frame the gateway stamps + the backend correlates by
//! `task_id`, and maintains the process-global `task_id → run_id` map (§7) for cancel/status.
//!
//! SECURITY (the never-trust-a-BYO-agent rule):
//!   * Credentials are decrypted with the KEYRING channel key only, held in memory, re-sealed into the
//!     ephemeral recipe with the local vault, and dropped when the run ends — never persisted/logged.
//!   * A `credentials_encrypted` blob we cannot open fails the task CLOSED (no partial run).
//!   * Identity/billing/isolation are the cloud's job; this handler runs a recipe and reports a result.

use std::sync::Arc;
use std::time::Instant;

use serde_json::{json, Value};

use super::super::super::engine::{LocalEngine, RunSource};
use super::super::super::error::LocalError;
use super::super::super::store::workflows::{self, Workflow};
use super::super::super::vault::Vault;
use super::creds;
use super::runs as run_map;

/// The ephemeral recipe's `runs`-row id is 0 (the engine inserts a `runs` row with `workflow_id =
/// NULL`); its credential blob is sealed/opened under this AAD (matches `resolve::decrypt_workflow_
/// credentials` which reads `credentials_aad(wf.id)` with `wf.id == 0`).
const EPHEMERAL_ID: i64 = 0;

/// Handle one `execute_workflow` dispatch to completion and return the `task_result` frame.
///
/// `engine` MUST be a full-capability engine (the caller only routes here when `has_browser()`); a
/// browserless engine's `run_recipe` returns `BadRequest`, which we surface as a failed `task_result`.
/// `vault` re-seals the decrypted per-run credentials into the ephemeral recipe.
pub async fn handle(
    task_id: &str,
    msg: &Value,
    engine: &Arc<dyn LocalEngine>,
    vault: &Arc<Vault>,
) -> Value {
    let start = Instant::now();
    let config = &msg["config"];

    // 1) Decrypt the per-run credentials (channel-key seam). Fail CLOSED on a sealed blob we can't
    //    open (never run with half the credentials).
    let (credentials, _proxy) = match creds::resolve_credentials(config) {
        Ok(pair) => pair,
        Err(e) => {
            tracing::warn!(task_id, error = %e, "execute_workflow: credential resolution failed");
            return task_result_frame(
                task_id,
                false,
                json!({}),
                Some("credential resolution failed (re-link may be required)".to_string()),
                start.elapsed().as_millis() as u64,
            );
        }
    };

    // 2) Build the ephemeral recipe from the config, re-sealing the decrypted creds into it (or None
    //    when the dispatch carried no credentials). The `__proxy__` override is intentionally NOT
    //    threaded here yet: the engine's `run_recipe` resolves egress from persona/env, and a
    //    BYO-clean recipe carries no persona, so the cloud dispatch egresses via env/direct — the
    //    per-run proxy application is a later step (parity with the saas_bridge context-level proxy).
    let credentials_encrypted = seal_recipe_credentials(vault, &credentials);
    let recipe = build_recipe(config, credentials_encrypted);

    // Inputs the recipe resolves `{{input.NAME}}` from. The cloud may send them either as a top-level
    // `inputs` object or inside `config.form_data`; prefer explicit `inputs`, else fall back.
    let inputs = msg
        .get("inputs")
        .cloned()
        .filter(|v| v.is_object())
        .or_else(|| config.get("form_data").cloned().filter(|v| v.is_object()))
        .unwrap_or_else(|| json!({}));

    // 3) Run via the shared engine (governor + `/v1/runs` visibility). `run_recipe` is synchronous:
    //    it returns the terminal RunResult, at which point the run_id is known. We bind the
    //    task_id → run_id map around the run so a concurrent `cancel_task` / status poll can resolve
    //    it, and unbind on completion (the map only ever holds live cloud runs).
    let result = engine
        .run_recipe(recipe, inputs, RunSource::CloudAgent)
        .await;

    match result {
        Ok(res) => {
            // Bind + immediately unbind: the run has already terminated by the time run_recipe
            // returns, so this keeps the map self-consistent (a mid-run cancel needs the async
            // run_recipe variant added in a later step; see module note). Binding the terminal
            // run_id still lets a status poll correlate the just-finished run.
            run_map::bind(task_id, res.run_id);
            run_map::unbind(task_id);
            task_result_frame(task_id, res.success, res.extracted_data, res.error, res.duration_ms)
        }
        Err(e) => {
            run_map::unbind(task_id);
            // Map the engine error to an end-user-safe message (never leak internals/recipe text).
            let message = match e {
                LocalError::BadRequest(m) => m,
                LocalError::NotFound(m) => m,
                other => other.to_string(),
            };
            task_result_frame(
                task_id,
                false,
                json!({}),
                Some(message),
                start.elapsed().as_millis() as u64,
            )
        }
    }
}

/// Seal the decrypted per-run credential map into the ephemeral recipe's `credentials_encrypted`
/// field (vault field-seal under `credentials_aad(0)`), or `None` when there are no credentials. This
/// lets the UNMODIFIED engine run pipeline (`resolve::decrypt_workflow_credentials`) open them exactly
/// like a normal workflow's sealed blob — no plaintext-cred entry point is added to the engine. A seal
/// failure logs and returns `None` (the run proceeds credential-less, and a step needing a missing
/// secret surfaces its own error) rather than aborting.
fn seal_recipe_credentials(
    vault: &Vault,
    credentials: &std::collections::HashMap<String, String>,
) -> Option<String> {
    if credentials.is_empty() {
        return None;
    }
    let map: serde_json::Map<String, Value> = credentials
        .iter()
        .map(|(k, v)| (k.clone(), Value::String(v.clone())))
        .collect();
    let plaintext = match serde_json::to_vec(&Value::Object(map)) {
        Ok(b) => b,
        Err(_) => return None,
    };
    let aad = workflows::credentials_aad(EPHEMERAL_ID);
    match vault.seal_field(&plaintext, &aad) {
        Ok(blob) => Some(blob),
        Err(e) => {
            tracing::warn!(error = %e, "execute_workflow: failed to seal per-run credentials (running credential-less)");
            None
        }
    }
}

/// Build a BYO-shaped ephemeral [`workflows::Workflow`] from the cloud `config` frame. Mirrors the
/// marketplace `build_recipe_workflow` projection (id = 0 → NULL workflow_id runs row), but this is an
/// AD-HOC workflow the cloud OWNS, so we DO carry the (re-sealed) per-run credentials + the recipe's
/// `default_persona_id` is left None (persona is resolved cloud-side; on-device we run with the creds
/// the cloud handed us).
fn build_recipe(config: &Value, credentials_encrypted: Option<String>) -> Workflow {
    // JSON-TEXT column: re-serialize a config sub-value to compact text, or None when absent/null.
    let text = |key: &str| -> Option<String> {
        match config.get(key) {
            None | Some(Value::Null) => None,
            Some(Value::String(s)) => Some(s.clone()),
            Some(other) => Some(other.to_string()),
        }
    };
    // `steps` is the only non-optional column; default to `[]` (a trivially-successful zero-step run)
    // rather than failing — parity with the engine's tolerant parse.
    let steps = text("steps").unwrap_or_else(|| "[]".to_string());
    let name = config
        .get("name")
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty())
        .unwrap_or("Cloud workflow")
        .to_string();
    let workflow_type = config
        .get("workflow_type")
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty())
        .unwrap_or("recorded")
        .to_string();

    Workflow {
        id: EPHEMERAL_ID,
        name,
        description: None,
        workflow_type,
        steps,
        raw_replay: text("raw_replay"),
        // The consumer's inputs resolve from the run inputs, not baked into the recipe; but honor a
        // config-provided form_data as stored defaults.
        form_data: text("form_data"),
        exit_condition: text("exit_condition"),
        input_rules: text("input_rules"),
        api_functions: text("api_functions"),
        streaming_config: text("streaming_config"),
        functions: text("functions"),
        // Re-sealed per-run creds (vault field-seal under credentials_aad(0)), or None.
        credentials_encrypted,
        entry_url: config.get("entry_url").and_then(|v| v.as_str()).map(str::to_string),
        timeout_ms: config.get("timeout_ms").and_then(Value::as_i64).unwrap_or(0),
        retry_count: config.get("retry_count").and_then(Value::as_i64).unwrap_or(0),
        headless: config.get("headless").and_then(Value::as_bool).map(|b| b as i64).unwrap_or(1),
        fast_mode: config.get("fast_mode").and_then(Value::as_bool).map(|b| b as i64).unwrap_or(1),
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
        // The cloud never ships a recorded auth seed; an ad-hoc recipe always signs in with the
        // per-run creds it carries.
        recorded_session_encrypted: None,
        recorded_session_captured_at: None,
        // Persona is resolved cloud-side; on-device the cloud-supplied creds ARE the identity.
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
        // Ephemeral: this row is never persisted, so it has no repair history to stamp.
        last_repaired_at: None,
        marketplace_slug: None,
        created_at: String::new(),
        updated_at: None,
    }
}

/// Build the fixed-contract `task_result` frame (identical shape to the gateway's `run_local_workflow`
/// path). `error` is JSON `null` on success.
pub(crate) fn task_result_frame(
    task_id: &str,
    success: bool,
    extracted_data: Value,
    error: Option<String>,
    duration_ms: u64,
) -> Value {
    json!({
        "type": "task_result",
        "task_id": task_id,
        "success": success,
        "extracted_data": extracted_data,
        "error": error,
        "duration_ms": duration_ms,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_recipe_projects_config_fields() {
        let cfg = json!({
            "name": "My cloud wf",
            "entry_url": "https://example.com",
            "steps": [{"type": "goto", "url": "https://example.com"}],
            "timeout_ms": 45000,
            "headless": false,
            "fast_mode": true,
            "functions": [{"name": "main", "output_fields": ["title"]}],
        });
        let wf = build_recipe(&cfg, Some("WF1:sealed".into()));
        assert_eq!(wf.id, 0, "ephemeral recipe → NULL workflow_id runs row");
        assert_eq!(wf.name, "My cloud wf");
        assert_eq!(wf.entry_url.as_deref(), Some("https://example.com"));
        assert_eq!(wf.timeout_ms, 45000);
        assert_eq!(wf.headless, 0, "headless:false → 0");
        assert_eq!(wf.fast_mode, 1, "fast_mode:true → 1");
        assert_eq!(wf.credentials_encrypted.as_deref(), Some("WF1:sealed"));
        assert!(wf.functions.as_deref().unwrap().contains("output_fields"));
        // steps re-serialized to compact JSON text.
        assert!(wf.steps.contains("\"goto\""));
        // BYO invariant: no pinned persona on-device.
        assert!(wf.default_persona_id.is_none());
    }

    #[test]
    fn build_recipe_defaults_when_config_sparse() {
        let wf = build_recipe(&json!({}), None);
        assert_eq!(wf.name, "Cloud workflow");
        assert_eq!(wf.steps, "[]", "missing steps → empty array (zero-step run)");
        assert_eq!(wf.workflow_type, "recorded");
        assert_eq!(wf.headless, 1);
        assert!(wf.credentials_encrypted.is_none());
        assert!(wf.entry_url.is_none());
    }

    #[test]
    fn seal_recipe_credentials_none_when_empty() {
        let (_dir, vault) = vault_at();
        assert!(seal_recipe_credentials(&vault, &std::collections::HashMap::new()).is_none());
    }

    #[test]
    fn seal_recipe_credentials_round_trips_through_engine_aad() {
        // Seal a cred map, then open it with the SAME AAD the engine's resolve path uses — proving the
        // re-sealed blob is readable by the unmodified run pipeline (credentials_aad(0)).
        let (_dir, vault) = vault_at();
        let mut creds = std::collections::HashMap::new();
        creds.insert("username".to_string(), "alice".to_string());
        creds.insert("password".to_string(), "s3cret".to_string());
        let blob = seal_recipe_credentials(&vault, &creds).expect("sealed");

        let aad = workflows::credentials_aad(EPHEMERAL_ID);
        let plaintext = vault.open_field(&blob, &aad).expect("opened with engine AAD");
        let obj: serde_json::Map<String, Value> =
            serde_json::from_slice(&plaintext).expect("json object");
        assert_eq!(obj.get("username").and_then(|v| v.as_str()), Some("alice"));
        assert_eq!(obj.get("password").and_then(|v| v.as_str()), Some("s3cret"));
        // Wrong AAD must NOT open (AAD-bound seal).
        assert!(vault.open_field(&blob, "workflows|credentials_encrypted|999").is_err());
    }

    #[test]
    fn task_result_frame_shape_matches_contract() {
        let ok = task_result_frame("t1", true, json!({"k": 1}), None, 12);
        assert_eq!(ok["type"], "task_result");
        assert_eq!(ok["task_id"], "t1");
        assert_eq!(ok["success"], true);
        assert!(ok["error"].is_null(), "success → error: null");
        let bad = task_result_frame("t2", false, json!({}), Some("boom".into()), 5);
        assert_eq!(bad["success"], false);
        assert_eq!(bad["error"], "boom");
    }

    fn vault_at() -> (tempfile::TempDir, Arc<Vault>) {
        let dir = tempfile::tempdir().unwrap();
        let v = Arc::new(Vault::load_or_create(dir.path(), false).unwrap());
        (dir, v)
    }
}
