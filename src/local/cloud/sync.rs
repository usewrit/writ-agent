//! Cloud↔app data sync engine — DAEMON Stage 2.
//!
//! Implements the two LAWFUL directions of the desktop's cloud data connection:
//!
//!   * **PULL (cloud → app)** is an AUTHORITATIVE import. For each of workflows / personas /
//!     monitors we fetch the linked account's OWN private records via [`CloudClient`] (the `wto_`
//!     account token, auto-refreshing on 401), map each cloud row onto a LOCAL row, and UPSERT it,
//!     maintaining a [`cloud_sync_map`] row (`cloud_id`, `content_hash`, `origin='cloud'`). Cloud
//!     wins for cloud-origin rows. Two invariants are sacred:
//!       - A locally-authored row (no `cloud_sync_map` entry) is NEVER touched by a pull.
//!       - A cloud-origin row whose CURRENT local `content_hash` differs from the hash we stored at
//!         last sync has DIVERGED (the user edited it locally). We REPORT it and DO NOT overwrite.
//!     Pulled persona/workflow credential VALUES (if the cloud ever returns any — today it returns
//!     only `has_*` reflection booleans, never the secret values) are sealed into the LOCAL vault;
//!     plaintext never lands in the DB.
//!
//!   * **PUSH (app → cloud)** is GRANULAR and USER-INITIATED ONLY (never automatic / bulk / silent).
//!     Given `{entity_type, local_ids}` we create/update the user's PRIVATE cloud records, shipping
//!     the recipe + references ONLY — every secret/credential VALUE is stripped before the body
//!     crosses the wire. Each pushed row records a `cloud_sync_map` mapping (`origin='local'`).
//!     Ids that can't be pushed are reported in `skipped` with a reason; the route never 500s on a
//!     per-item failure.
//!
//! SECURITY (the never-trust-a-BYO-agent rule): entitlements/this engine are NOT an authorization
//! gate — the cloud re-enforces every paid action server-side. Creds stay local. This module never
//! logs secret values; only ids/counts/outcomes.
//!
//! Net-new Rust in this crate, behind the `local` cargo feature.

use std::collections::HashMap;
use std::future::Future;
use std::pin::Pin;

use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use sqlx::sqlite::SqlitePool;

use super::super::error::LocalResult;
use super::super::store::{
    automations, cloud_sync_map, personas, runs, target_selectors, targets, workflows,
};
use super::super::vault::Vault;
use super::client::CloudClient;

/// Entity-type discriminants used in `cloud_sync_map.entity_type` AND the REST contract.
pub const ENTITY_WORKFLOW: &str = "workflow";
pub const ENTITY_PERSONA: &str = "persona";
/// NB: monitors are the `targets` table locally but the contract names them "monitor".
pub const ENTITY_MONITOR: &str = "monitor";
/// An automation (event→action block-tree rule; the cloud calls these "trigger rules"). Only
/// NATIVE + FULL-tier OWNED automations are ever pulled — RUNNABLE proxy installs (opaque,
/// IP-protected, cloud-only) are filtered out at the pull, never imported or run locally.
pub const ENTITY_AUTOMATION: &str = "automation";
/// A cloud run imported for its extracted data (mapped so re-pulls are idempotent). Not a push entity.
pub const ENTITY_RUN: &str = "run";

/// Upper bound on rows scanned per workflow when importing extracted data, so a workflow with a huge
/// history can't make one pull unbounded (the cloud also caps its own scan ~1000 runs).
const MAX_DATA_ROWS: i64 = 5000;
/// Page size for the cloud Workflow Data API (its hard cap is 500).
const DATA_PAGE_LIMIT: i64 = 500;

/// `config` kv keys used to persist non-secret sync status across daemon restarts. SECRETS NEVER
/// go through `config_kv` — these are small non-secret strings (a timestamp + cached counts).
const KV_LAST_PULL_AT: &str = "cloud.sync.last_pull_at";
const KV_LAST_COUNTS: &str = "cloud.sync.last_counts";

// --------------------------------------------------------------------------------------------
// Cloud source paths
// --------------------------------------------------------------------------------------------

// Backend mounts these routers under the `/api` prefix (see the cloud backend:
// automation_router/targets_router/personas_router all `prefix="/api"`), matching the
// device-flow + entitlements calls which also use `/api/...`. CloudClient joins these
// onto the resolved cloud base url (no trailing slash).
const CLOUD_WORKFLOWS: &str = "/api/automation/workflows";
const CLOUD_PERSONAS: &str = "/api/personas";
const CLOUD_TARGETS: &str = "/api/targets";
// The trigger-rules router is `APIRouter(prefix="/triggers")` mounted under `/api`
// (the cloud backend: `include_router(triggers_router, prefix="/api")`), so its "list all" endpoint
// (`@router.get("/all")` → `list_all_trigger_rules`) resolves to `/api/triggers/all`. It returns
// the linked tenant's OWN trigger rules (tenant-scoped by the `wto_` token).
const CLOUD_AUTOMATIONS: &str = "/api/triggers/all";

// --------------------------------------------------------------------------------------------
// Content hashing (divergence detection)
// --------------------------------------------------------------------------------------------

/// Hex SHA-256 of the bytes. Stable, hex-lowercased so it compares as plain text in SQLite.
fn hash_hex(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    data_encoding::HEXLOWER.encode(&digest)
}

/// Canonicalize a workflow's recipe into a stable hash input: the JSON-TEXT recipe columns parsed
/// then re-serialized in a FIXED key order so cosmetic whitespace/key-order changes don't look like
/// divergence. We hash only the *recipe* (steps / form_data / config-ish columns), not bookkeeping
/// (counters, timestamps) which legitimately drift without being an "edit".
pub(crate) fn workflow_content_hash(wf: &workflows::Workflow) -> String {
    // Parse each JSON-TEXT column to a Value (falling back to a string node) so re-serialization is
    // canonical regardless of how it was stored.
    let parse = |s: &Option<String>| -> Value {
        match s {
            Some(t) if !t.is_empty() => {
                serde_json::from_str::<Value>(t).unwrap_or_else(|_| Value::String(t.clone()))
            }
            _ => Value::Null,
        }
    };
    // BTreeMap-ordered object via json! with a fixed field list → deterministic byte output.
    let canon = json!({
        "name": wf.name,
        "description": wf.description,
        "workflow_type": wf.workflow_type,
        "steps": parse(&Some(wf.steps.clone())),
        "form_data": parse(&wf.form_data),
        "functions": parse(&wf.functions),
        "exit_condition": parse(&wf.exit_condition),
        "input_rules": parse(&wf.input_rules),
        "entry_url": wf.entry_url,
    });
    // serde_json::to_string of a json! object emits keys in insertion order; to be order-stable we
    // round-trip through a BTreeMap.
    hash_hex(canonical_bytes(&canon).as_bytes())
}

/// Persona recipe hash — name + non-secret login/2FA metadata. Secret blobs are NEVER part of the
/// hash (they don't cross the wire and aren't what "diverges").
pub(crate) fn persona_content_hash(p: &personas::Persona) -> String {
    let canon = json!({
        "name": p.name,
        "description": p.description,
        "target_domain": p.target_domain,
        "login_username": p.login_username,
        "twofa_method": p.twofa_method,
        "email_otp_mode": p.email_otp_mode,
        "relay_address": p.relay_address,
    });
    hash_hex(canonical_bytes(&canon).as_bytes())
}

/// Monitor (target) recipe hash — the check definition, not its runtime baseline/state.
pub(crate) fn target_content_hash(t: &targets::Target) -> String {
    let canon = json!({
        "url": t.url,
        "check_type": t.check_type,
        "selector": t.selector,
        "ignore_regex": t.ignore_regex,
        "check_period_ms": t.check_period_ms,
        "expected_status_code": t.expected_status_code,
        "on_change_conditions": t.on_change_conditions,
        "setup_steps": t.setup_steps,
    });
    hash_hex(canonical_bytes(&canon).as_bytes())
}

/// Automation (event→action rule) recipe hash — the rule DEFINITION (event/conditions/actions/blocks
/// + the reference columns), not its runtime bookkeeping (trigger_count / last_triggered_at). The
/// reference columns (`workflow_id` etc.) hold LOCAL ids after remapping, which is exactly what we
/// want to diff: an import re-hashes the local row post-remap so a re-pull is a no-op unless the
/// cloud recipe genuinely changed (or the user edited the local copy → divergence).
pub(crate) fn automation_content_hash(a: &automations::Automation) -> String {
    let parse = |s: &Option<String>| -> Value {
        match s {
            Some(t) if !t.is_empty() => {
                serde_json::from_str::<Value>(t).unwrap_or_else(|_| Value::String(t.clone()))
            }
            _ => Value::Null,
        }
    };
    let canon = json!({
        "name": a.name,
        "description": a.description,
        "event_type": a.event_type,
        "enabled": a.enabled,
        "priority": a.priority,
        "target_id": a.target_id,
        "target_selector_id": a.target_selector_id,
        "workflow_id": a.workflow_id,
        "webhook_trigger_id": a.webhook_trigger_id,
        "conditions": parse(&Some(a.conditions.clone())),
        "actions": parse(&Some(a.actions.clone())),
        "blocks": parse(&a.blocks),
    });
    hash_hex(canonical_bytes(&canon).as_bytes())
}

/// Serialize a `Value` with object keys sorted recursively so the byte output is canonical (the
/// same logical recipe always hashes the same regardless of key order).
fn canonical_bytes(v: &Value) -> String {
    fn sort(v: &Value) -> Value {
        match v {
            Value::Object(map) => {
                let mut sorted = serde_json::Map::new();
                let mut keys: Vec<&String> = map.keys().collect();
                keys.sort();
                for k in keys {
                    sorted.insert(k.clone(), sort(&map[k]));
                }
                Value::Object(sorted)
            }
            Value::Array(arr) => Value::Array(arr.iter().map(sort).collect()),
            other => other.clone(),
        }
    }
    serde_json::to_string(&sort(v)).unwrap_or_default()
}

// --------------------------------------------------------------------------------------------
// Result types (mirror the REST contract exactly)
// --------------------------------------------------------------------------------------------

/// A cloud-origin local row that diverged (locally edited after pull) — reported, not overwritten.
#[derive(Debug, Clone, serde::Serialize)]
pub struct Diverged {
    pub entity_type: String,
    pub local_id: i64,
    pub name: String,
}

/// `{workflows, personas, monitors, extracted_data}` integer counts from a pull. `extracted_data` is
/// the number of cloud RUN rows imported (each carries that run's extracted data into the local
/// `runs` table, which the Data explorer reads). `#[serde(default)]` keeps older persisted status
/// rows (written before this field existed) readable.
#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct PullCounts {
    pub workflows: i64,
    pub personas: i64,
    pub monitors: i64,
    #[serde(default)]
    pub extracted_data: i64,
    /// Native + FULL-tier owned automations imported (RUNNABLE proxy installs are excluded).
    /// `#[serde(default)]` keeps status rows persisted before this field existed readable.
    #[serde(default)]
    pub automations: i64,
}

/// Result of [`pull_all`].
#[derive(Debug, Clone, serde::Serialize)]
pub struct PullResult {
    pub ok: bool,
    pub counts: PullCounts,
    pub diverged: Vec<Diverged>,
    pub errors: Vec<String>,
}

/// One pushed row mapping.
#[derive(Debug, Clone, serde::Serialize)]
pub struct Pushed {
    pub local_id: i64,
    pub cloud_id: String,
}

/// One skipped push with a human reason.
#[derive(Debug, Clone, serde::Serialize)]
pub struct Skipped {
    pub local_id: i64,
    pub reason: String,
}

/// Result of [`push`].
#[derive(Debug, Clone, serde::Serialize)]
pub struct PushResult {
    pub ok: bool,
    pub pushed: Vec<Pushed>,
    pub skipped: Vec<Skipped>,
}

/// One row in the granular sync `items` list.
#[derive(Debug, Clone, serde::Serialize)]
pub struct SyncItem {
    pub entity_type: String,
    pub local_id: i64,
    pub cloud_id: Option<String>,
    /// `"cloud"` (pulled) | `"local"` (locally-authored or pushed up).
    pub origin: String,
    pub name: String,
    /// `"cloud"` | `"local"` | `"diverged"`.
    pub status: String,
}

// --------------------------------------------------------------------------------------------
// PULL
// --------------------------------------------------------------------------------------------

/// Run a full cloud → app import for all three entity types. Resilient: a failure in one entity
/// type is collected into `errors` and the others still run. `ok` is true iff there were no errors.
///
/// Marks `in_progress` for the duration via [`set_in_progress`]; persists `last_pull_at` + counts.
pub async fn pull_all(db: &SqlitePool, vault: &Vault, link: &super::state::LinkState) -> PullResult {
    let mut counts = PullCounts::default();
    let mut diverged: Vec<Diverged> = Vec::new();
    let mut errors: Vec<String> = Vec::new();

    let mut client = match CloudClient::connect(Some(link)) {
        Ok(c) => c,
        Err(e) => {
            // Not linked / no token → fail the pull cleanly (no panic, no partial write).
            return PullResult {
                ok: false,
                counts,
                diverged,
                errors: vec![format!("not linked: {e}")],
            };
        }
    };

    set_in_progress(db, true).await;

    match pull_workflows(db, &mut client).await {
        Ok((n, mut div)) => {
            counts.workflows = n;
            diverged.append(&mut div);
        }
        Err(e) => errors.push(format!("workflows: {e}")),
    }
    match pull_personas(db, vault, &mut client).await {
        Ok((n, mut div)) => {
            counts.personas = n;
            diverged.append(&mut div);
        }
        Err(e) => errors.push(format!("personas: {e}")),
    }
    match pull_monitors(db, &mut client).await {
        Ok((n, mut div)) => {
            counts.monitors = n;
            diverged.append(&mut div);
        }
        Err(e) => errors.push(format!("monitors: {e}")),
    }
    // Automations reference workflow ids (and target/selector ids) that must already be MAPPED
    // cloud→local, so this runs AFTER pull_workflows AND pull_monitors.
    match pull_automations(db, &mut client).await {
        Ok((n, mut div)) => {
            counts.automations = n;
            diverged.append(&mut div);
        }
        Err(e) => errors.push(format!("automations: {e}")),
    }
    // Extracted data depends on the workflow mappings established above, so it runs last.
    match pull_extracted_data(db, &mut client).await {
        Ok(n) => counts.extracted_data = n,
        Err(e) => errors.push(format!("extracted_data: {e}")),
    }

    set_in_progress(db, false).await;
    persist_pull_status(db, &counts).await;

    PullResult { ok: errors.is_empty(), counts, diverged, errors }
}

/// Stringify a cloud row's `id` field (cloud ids are ints in the JSON; we store them as TEXT in
/// `cloud_sync_map.cloud_id`). `None` when the row has no usable id.
fn cloud_id_of(row: &Value) -> Option<String> {
    match row.get("id") {
        Some(Value::Number(n)) => Some(n.to_string()),
        Some(Value::String(s)) if !s.is_empty() => Some(s.clone()),
        _ => None,
    }
}

/// PULL workflows. Returns `(imported_or_updated_count, diverged)`.
///
/// The cloud LIST endpoint ships summaries (`steps: []`), so for each row we re-fetch the FULL
/// recipe via `GET /automation/workflows/{id}` before mapping. A cloud row already mapped whose
/// LOCAL content diverged is reported and skipped; an unmapped cloud row is imported; a mapped,
/// non-diverged row is refreshed (cloud wins).
async fn pull_workflows(
    db: &SqlitePool,
    client: &mut CloudClient,
) -> LocalResult<(i64, Vec<Diverged>)> {
    let list: Value = client.get_json(CLOUD_WORKFLOWS).await?;
    let rows = as_rows(&list);
    let mut count = 0i64;
    let mut diverged = Vec::new();

    for summary in rows {
        let Some(cloud_id) = cloud_id_of(&summary) else { continue };
        // Fetch the full recipe (the list is a summary with steps stripped).
        let full: Value = match client.get_json(&format!("{CLOUD_WORKFLOWS}/{cloud_id}")).await {
            Ok(v) => v,
            Err(e) => {
                tracing::warn!(cloud_id = %cloud_id, error = %e, "skip workflow: detail fetch failed");
                continue;
            }
        };

        let existing = cloud_sync_map::get_by_cloud_id(db, ENTITY_WORKFLOW, &cloud_id).await?;
        if let Some(map) = &existing {
            // Cloud-origin row already imported — guard against silently clobbering local edits.
            if let Some(local) = workflows::get_by_id(db, map.local_id).await? {
                let local_hash = workflow_content_hash(&local);
                if map.content_hash.as_deref() != Some(local_hash.as_str()) {
                    diverged.push(Diverged {
                        entity_type: ENTITY_WORKFLOW.into(),
                        local_id: local.id,
                        name: local.name.clone(),
                    });
                    continue; // DO NOT overwrite a diverged row.
                }
                // Non-diverged: cloud wins — patch the local row to the fresh recipe.
                // DEFENSIVE: mirror `reflect::copy_local`'s guard — if the cloud
                // response has NO steps but we hold a real local recipe, the sync
                // must NOT overwrite (would silently blank a workflow the run path
                // then can't execute). See routers/automation.py:1408 — the cloud
                // strips steps for install proxies (creator IP protection).
                let steps_from_cloud = full.get("steps").and_then(Value::as_array).map(|a| a.len()).unwrap_or(0);
                let stripped = steps_from_cloud == 0 && !local.steps.is_empty() && local.steps != "[]";
                let patch = if stripped {
                    tracing::warn!(
                        cloud_id = %cloud_id,
                        local_id = local.id,
                        "sync: cloud response missing steps — keeping local recipe (would have wiped it)"
                    );
                    workflows::WorkflowUpdate::default()
                } else {
                    workflow_update_from_cloud(&full)
                };
                let updated = workflows::update(db, local.id, &patch).await?;
                let new_hash = workflow_content_hash(&updated);
                cloud_sync_map::set_content_hash(db, ENTITY_WORKFLOW, local.id, &new_hash).await?;
                count += 1;
                continue;
            }
            // Mapping points at a vanished local row — fall through and re-import as new.
        }

        // New cloud row → insert locally and record the mapping.
        let new = new_workflow_from_cloud(&full);
        let inserted = workflows::insert(db, &new).await?;
        let hash = workflow_content_hash(&inserted);
        cloud_sync_map::upsert(
            db,
            ENTITY_WORKFLOW,
            inserted.id,
            &cloud_id,
            Some(&hash),
            "cloud",
        )
        .await?;
        count += 1;
    }
    Ok((count, diverged))
}

/// PULL personas. Cloud `PersonaResponse` exposes ONLY non-secret metadata (`has_password` etc.,
/// never the values), so this imports references/metadata only. If a future cloud payload ever
/// carries a plaintext `credentials` map we seal it into the LOCAL vault before insert.
async fn pull_personas(
    db: &SqlitePool,
    vault: &Vault,
    client: &mut CloudClient,
) -> LocalResult<(i64, Vec<Diverged>)> {
    let list: Value = client.get_json(CLOUD_PERSONAS).await?;
    let rows = as_rows(&list);
    let mut count = 0i64;
    let mut diverged = Vec::new();

    for row in rows {
        let Some(cloud_id) = cloud_id_of(&row) else { continue };

        let existing = cloud_sync_map::get_by_cloud_id(db, ENTITY_PERSONA, &cloud_id).await?;
        if let Some(map) = &existing {
            if let Some(local) = personas::get_by_id(db, map.local_id).await? {
                let local_hash = persona_content_hash(&local);
                if map.content_hash.as_deref() != Some(local_hash.as_str()) {
                    diverged.push(Diverged {
                        entity_type: ENTITY_PERSONA.into(),
                        local_id: local.id,
                        name: local.name.clone(),
                    });
                    continue;
                }
                let patch = persona_update_from_cloud(&row);
                if let Some(updated) = personas::update(db, local.id, &patch).await? {
                    let new_hash = persona_content_hash(&updated);
                    cloud_sync_map::set_content_hash(db, ENTITY_PERSONA, local.id, &new_hash)
                        .await?;
                    count += 1;
                }
                continue;
            }
        }

        // New persona: insert metadata, then (defensively) seal any plaintext creds into the vault.
        let mut new = new_persona_from_cloud(&row);
        // Seal-after-insert because the AAD binds to the row id (matches engine::persona).
        let plaintext_creds = extract_plaintext_credentials(&row);
        let inserted = personas::insert(db, &new_taking(&mut new)).await?;
        if let Some(creds) = plaintext_creds {
            if let Ok(blob) = seal_persona_credentials(vault, inserted.id, &creds) {
                let _ = personas::update(
                    db,
                    inserted.id,
                    &personas::PersonaUpdate {
                        credentials_encrypted: Some(blob),
                        ..Default::default()
                    },
                )
                .await?;
            }
        }
        let refreshed = personas::get_by_id(db, inserted.id).await?.unwrap_or(inserted);
        let hash = persona_content_hash(&refreshed);
        cloud_sync_map::upsert(db, ENTITY_PERSONA, refreshed.id, &cloud_id, Some(&hash), "cloud")
            .await?;
        count += 1;
    }
    Ok((count, diverged))
}

/// PULL monitors (the local `targets` table). Imports the check definition metadata.
async fn pull_monitors(
    db: &SqlitePool,
    client: &mut CloudClient,
) -> LocalResult<(i64, Vec<Diverged>)> {
    let list: Value = client.get_json(CLOUD_TARGETS).await?;
    let rows = as_rows(&list);
    let mut count = 0i64;
    let mut diverged = Vec::new();

    for row in rows {
        let Some(cloud_id) = cloud_id_of(&row) else { continue };

        let existing = cloud_sync_map::get_by_cloud_id(db, ENTITY_MONITOR, &cloud_id).await?;
        if let Some(map) = &existing {
            if let Some(local) = targets::get_by_id(db, map.local_id).await? {
                let local_hash = target_content_hash(&local);
                if map.content_hash.as_deref() != Some(local_hash.as_str()) {
                    diverged.push(Diverged {
                        entity_type: ENTITY_MONITOR.into(),
                        local_id: local.id,
                        name: local.url.clone(),
                    });
                    continue;
                }
                let patch = target_update_from_cloud(&row);
                if let Some(updated) = targets::update(db, local.id, &patch).await? {
                    let new_hash = target_content_hash(&updated);
                    cloud_sync_map::set_content_hash(db, ENTITY_MONITOR, local.id, &new_hash)
                        .await?;
                    count += 1;
                }
                // Heal an earlier import that pulled the target row but not its selectors.
                ensure_selectors_imported(db, client, &cloud_id, local.id).await;
                continue;
            }
        }

        let new = new_target_from_cloud(&row);
        let local_id = targets::insert(db, &new).await?;
        if let Some(t) = targets::get_by_id(db, local_id).await? {
            let hash = target_content_hash(&t);
            cloud_sync_map::upsert(db, ENTITY_MONITOR, local_id, &cloud_id, Some(&hash), "cloud")
                .await?;
            count += 1;
        }
        ensure_selectors_imported(db, client, &cloud_id, local_id).await;
    }
    Ok((count, diverged))
}

/// Import a cloud monitor's selectors into the local `target_selectors` table when the local target
/// has NONE yet — so an imported content monitor actually has something to compare against instead of
/// checking an empty selector set forever. Idempotent: once any local selector exists we leave them
/// alone (never clobber locally-set baselines). Best-effort — a fetch/insert failure is logged and
/// skipped, never failing the monitor pull. A target whose cloud check uses only the single `selector`
/// column (no selector rows) is handled by the runner's `heal_single_selector`, so we import nothing
/// here in that case.
async fn ensure_selectors_imported(
    db: &SqlitePool,
    client: &mut CloudClient,
    cloud_target_id: &str,
    local_target_id: i64,
) {
    match target_selectors::count_by_target(db, local_target_id).await {
        Ok(0) => {}
        Ok(_) => return,
        Err(e) => {
            tracing::warn!(target_id = local_target_id, error = %e, "selector count failed; skip import");
            return;
        }
    }
    let path = format!("{CLOUD_TARGETS}/{cloud_target_id}/selectors");
    let list: Value = match client.get_json(&path).await {
        Ok(v) => v,
        Err(e) => {
            tracing::warn!(target_id = local_target_id, error = %e, "cloud selectors fetch failed");
            return;
        }
    };
    let mut imported = 0;
    for row in as_rows(&list) {
        let selector = match str_opt(row.get("selector")) {
            Some(s) if !s.trim().is_empty() => s,
            _ => continue, // a selector row without a CSS selector is unusable
        };
        let new = target_selectors::NewTargetSelector {
            target_id: local_target_id,
            name: str_opt(row.get("name")).unwrap_or_else(|| "Content".into()),
            selector,
            description: str_opt(row.get("description")),
            enabled: bool_int_opt(row.get("enabled")),
            content_type: str_opt(row.get("content_type")),
            visual_region: json_text(row.get("visual_region")),
            ignore_regex: str_opt(row.get("ignore_regex")),
            priority: int_opt(row.get("priority")),
        };
        match target_selectors::insert(db, &new).await {
            Ok(_) => imported += 1,
            Err(e) => {
                tracing::warn!(target_id = local_target_id, error = %e, "selector import insert failed")
            }
        }
    }
    if imported > 0 {
        tracing::info!(target_id = local_target_id, imported, "imported cloud selectors for monitor");
    }
}

// --------------------------------------------------------------------------------------------
// PULL — automations (cloud trigger rules → local automations)
// --------------------------------------------------------------------------------------------

/// Block-config keys that carry a REFERENCE id which must be translated cloud→local when importing an
/// automation. `workflow_id` / `source_workflow_id` / `target_workflow_id` map through the WORKFLOW
/// sync map; `persona_id` through the PERSONA map; `target_id` / `selector_id` through the MONITOR
/// map. `webhook_trigger_id` is intentionally NOT remapped: webhook triggers are re-provisioned
/// locally, not pulled, so it is dropped (see [`remap_automation_blocks`]).
const BLOCK_WORKFLOW_ID_KEYS: [&str; 3] =
    ["workflow_id", "source_workflow_id", "target_workflow_id"];

/// PULL automations. Returns `(imported_or_updated_count, diverged)`.
///
/// SECURITY / product law: only NATIVE and FULL-tier OWNED automations are importable — a RUNNABLE
/// proxy install (opaque, IP-protected, cloud-only) is SKIPPED, never imported and never run
/// locally. Proxy installs are recognised by a `nested_ref`/`nested_refs` token anywhere in their
/// `blocks` (the manifest engine replaces every concrete creator id with such a token); we also treat
/// an `is_installed` row bearing one as a proxy for good measure. Owned/native automations carry real
/// concrete ids and no such token.
///
/// References (the automation's own `workflow_id` / `target_id` / `target_selector_id` columns AND any
/// `workflow_id`/`persona_id`/`target_id`/`selector_id` embedded in the `blocks`/`actions` JSON) are
/// REMAPPED from cloud ids to LOCAL ids via `cloud_sync_map`. This is FAIL-CLOSED: if a referenced
/// workflow/monitor/persona wasn't pulled (no mapping), the automation is SKIPPED and logged rather
/// than pointed at a wrong local row. Divergence is guarded exactly like `pull_workflows`.
async fn pull_automations(
    db: &SqlitePool,
    client: &mut CloudClient,
) -> LocalResult<(i64, Vec<Diverged>)> {
    let list: Value = client.get_json(CLOUD_AUTOMATIONS).await?;
    let rows = as_rows(&list);
    let mut count = 0i64;
    let mut diverged = Vec::new();

    for row in rows {
        let Some(cloud_id) = cloud_id_of(&row) else { continue };
        let name = str_opt(row.get("name")).unwrap_or_else(|| "Automation".into());

        // Cloud-only guard: a proxy/runnable install carries a `nested_ref`/`nested_refs` token in
        // its blocks (opaque recipe). Never import or run it locally.
        if blocks_contain_nested_ref(row.get("blocks")) {
            tracing::info!(
                cloud_id = %cloud_id,
                name = %name,
                "skip automation: runnable proxy install (nested_ref) — cloud-only"
            );
            continue;
        }

        // Remap all cloud ids → local ids. Fail-closed: an unresolved reference skips the row.
        let remapped = match remap_automation(db, &row).await? {
            Some(r) => r,
            None => {
                tracing::warn!(
                    cloud_id = %cloud_id,
                    name = %name,
                    "skip automation: a referenced workflow/monitor/persona was not pulled (fail-closed)"
                );
                continue;
            }
        };

        let existing = cloud_sync_map::get_by_cloud_id(db, ENTITY_AUTOMATION, &cloud_id).await?;
        if let Some(map) = &existing {
            if let Some(local) = automations::get_by_id(db, map.local_id).await? {
                let local_hash = automation_content_hash(&local);
                if map.content_hash.as_deref() != Some(local_hash.as_str()) {
                    diverged.push(Diverged {
                        entity_type: ENTITY_AUTOMATION.into(),
                        local_id: local.id,
                        name: local.name.clone(),
                    });
                    continue; // DO NOT overwrite a locally-edited automation.
                }
                // Non-diverged: cloud wins — patch the local row to the fresh (remapped) recipe.
                let patch = remapped.into_patch();
                if let Some(updated) = automations::update(db, local.id, &patch).await? {
                    let new_hash = automation_content_hash(&updated);
                    cloud_sync_map::set_content_hash(db, ENTITY_AUTOMATION, local.id, &new_hash)
                        .await?;
                    count += 1;
                }
                continue;
            }
            // Mapping points at a vanished local row — fall through and re-import as new.
        }

        // New automation → insert locally with the remapped references + record the mapping.
        let inserted = automations::insert(db, &remapped.into_new()).await?;
        let hash = automation_content_hash(&inserted);
        cloud_sync_map::upsert(db, ENTITY_AUTOMATION, inserted.id, &cloud_id, Some(&hash), "cloud")
            .await?;
        count += 1;
    }
    Ok((count, diverged))
}

/// Whether an automation's `blocks` JSON contains a `nested_ref` / `nested_refs` proxy token anywhere
/// (the marketplace manifest engine stamps these in place of concrete ids for a RUNNABLE install).
/// Accepts the raw `blocks` value as it arrives from the cloud (an array, or occasionally a JSON
/// string). Any parse hiccup returns `false` (treated as native) — the remap step is still fail-closed
/// on real ids, so a native row with no resolvable references is skipped there, not here.
fn blocks_contain_nested_ref(blocks: Option<&Value>) -> bool {
    fn scan(v: &Value) -> bool {
        match v {
            Value::Object(map) => {
                if map.contains_key("nested_ref") || map.contains_key("nested_refs") {
                    return true;
                }
                map.values().any(scan)
            }
            Value::Array(arr) => arr.iter().any(scan),
            _ => false,
        }
    }
    match blocks {
        None | Some(Value::Null) => false,
        Some(Value::String(s)) => serde_json::from_str::<Value>(s).map(|v| scan(&v)).unwrap_or(false),
        Some(other) => scan(other),
    }
}

/// A fully cloud→local-remapped automation ready to insert or patch. Reference columns hold LOCAL
/// ids; `blocks`/`actions`/`conditions` are re-serialized TEXT with their embedded ids remapped.
struct RemappedAutomation {
    name: String,
    description: Option<String>,
    event_type: Option<String>,
    enabled: Option<i64>,
    priority: Option<i64>,
    target_id: Option<i64>,
    target_selector_id: Option<i64>,
    workflow_id: Option<i64>,
    conditions: Option<String>,
    actions: Option<String>,
    blocks: Option<String>,
}

impl RemappedAutomation {
    fn into_new(self) -> automations::NewAutomation {
        automations::NewAutomation {
            target_id: self.target_id,
            event_type: self.event_type,
            target_selector_id: self.target_selector_id,
            workflow_id: self.workflow_id,
            // Webhook triggers are provisioned locally, never pulled — leave unset on import.
            webhook_trigger_id: None,
            name: self.name,
            description: self.description,
            enabled: self.enabled,
            priority: self.priority,
            conditions: self.conditions,
            actions: self.actions,
            blocks: self.blocks,
        }
    }

    fn into_patch(self) -> automations::AutomationPatch {
        automations::AutomationPatch {
            name: Some(self.name),
            description: self.description,
            event_type: self.event_type,
            target_id: self.target_id,
            target_selector_id: self.target_selector_id,
            workflow_id: self.workflow_id,
            webhook_trigger_id: None,
            enabled: self.enabled,
            priority: self.priority,
            conditions: self.conditions,
            actions: self.actions,
            blocks: self.blocks,
        }
    }
}

/// Translate a cloud automation row into a [`RemappedAutomation`] with every id reference resolved
/// cloud→local. Returns `None` (fail-closed) when ANY referenced workflow / monitor / selector /
/// persona was not pulled — the caller then skips the row so a local automation never points at a
/// wrong local id.
async fn remap_automation(db: &SqlitePool, c: &Value) -> LocalResult<Option<RemappedAutomation>> {
    // Top-level column references.
    let target_id = match remap_ref(db, ENTITY_MONITOR, c.get("target_id")).await? {
        RemapOutcome::Absent => None,
        RemapOutcome::Mapped(id) => Some(id),
        RemapOutcome::Unresolved => return Ok(None),
    };
    // Selectors are NOT tracked in `cloud_sync_map` (they ride along with their monitor via
    // `ensure_selectors_imported`, unmapped), so a cloud `target_selector_id` can't be translated.
    // Keeping it verbatim would be a WRONG/dangling local FK, so we DROP it (→ None): the automation
    // still fires on its monitor, just not scoped to one specific selector. This is the correct
    // fail-safe here (unlike workflow/target, which ARE mapped and hard fail-close when unresolved).
    let target_selector_id = None;
    let _ = c.get("target_selector_id");
    let workflow_id = match remap_ref(db, ENTITY_WORKFLOW, c.get("workflow_id")).await? {
        RemapOutcome::Absent => None,
        RemapOutcome::Mapped(id) => Some(id),
        RemapOutcome::Unresolved => return Ok(None),
    };

    // Embedded ids inside the block/action trees.
    let blocks = match remap_json_ids(db, c.get("blocks")).await? {
        Some(v) => v,
        None => return Ok(None),
    };
    let actions = match remap_json_ids(db, c.get("actions")).await? {
        Some(v) => v,
        None => return Ok(None),
    };

    Ok(Some(RemappedAutomation {
        name: str_opt(c.get("name")).unwrap_or_else(|| "Automation".into()),
        description: str_opt(c.get("description")),
        event_type: str_opt(c.get("event_type")),
        enabled: bool_int_opt(c.get("enabled")),
        priority: int_opt(c.get("priority")),
        target_id,
        target_selector_id,
        workflow_id,
        conditions: json_text(c.get("conditions")),
        actions: actions.map(|v| v.to_string()),
        blocks: blocks.map(|v| v.to_string()),
    }))
}

/// Outcome of resolving one cloud id reference through a sync map.
enum RemapOutcome {
    /// The field was absent/null — nothing to map.
    Absent,
    /// Resolved to a local id.
    Mapped(i64),
    /// Present but no local mapping exists — the caller must fail closed.
    Unresolved,
}

/// Resolve a single cloud id `Value` (int or numeric string) through the sync map for `entity_type`.
async fn remap_ref(
    db: &SqlitePool,
    entity_type: &str,
    v: Option<&Value>,
) -> LocalResult<RemapOutcome> {
    let cloud_id = match v {
        None | Some(Value::Null) => return Ok(RemapOutcome::Absent),
        Some(Value::Number(n)) => n.to_string(),
        Some(Value::String(s)) if !s.is_empty() => s.clone(),
        Some(_) => return Ok(RemapOutcome::Absent),
    };
    match cloud_sync_map::get_by_cloud_id(db, entity_type, &cloud_id).await? {
        Some(map) => Ok(RemapOutcome::Mapped(map.local_id)),
        None => Ok(RemapOutcome::Unresolved),
    }
}

/// Deep-remap every embedded id reference inside a `blocks`/`actions` JSON value cloud→local. Returns
/// `Some(remapped_value)` (an OWNED copy; `None` for an absent/null input maps to `Some(None)` via the
/// outer Option) or the FAIL-CLOSED `None` when a referenced id has no local mapping.
///
/// Recognised id-bearing keys (matching the flow interpreter + manifest engine): `workflow_id` /
/// `source_workflow_id` / `target_workflow_id` → workflow map; `persona_id` → persona map; `target_id`
/// / `selector_id` → monitor map. Any other key is copied verbatim. `webhook_trigger_id` /
/// `webhook_trigger_token` are STRIPPED (webhooks are re-provisioned locally, not pulled).
async fn remap_json_ids(db: &SqlitePool, v: Option<&Value>) -> LocalResult<Option<Option<Value>>> {
    // Normalize the raw column to an owned Value (tolerate a JSON-string-wrapped array/object).
    let value = match v {
        None | Some(Value::Null) => return Ok(Some(None)),
        Some(Value::String(s)) => {
            if s.trim().is_empty() {
                return Ok(Some(None));
            }
            match serde_json::from_str::<Value>(s) {
                Ok(parsed) => parsed,
                // Not JSON (a plain string that isn't an id container) → keep it verbatim.
                Err(_) => return Ok(Some(Some(Value::String(s.clone())))),
            }
        }
        Some(other) => other.clone(),
    };

    match remap_value(db, &value).await? {
        Some(remapped) => Ok(Some(Some(remapped))),
        None => Ok(None), // fail-closed: an embedded reference was unresolved
    }
}

/// Recursively rewrite id references in a JSON `Value`. `Ok(None)` ⇒ fail-closed (unresolved ref).
/// Boxed future because it recurses through nested objects/arrays.
fn remap_value<'a>(
    db: &'a SqlitePool,
    v: &'a Value,
) -> Pin<Box<dyn Future<Output = LocalResult<Option<Value>>> + Send + 'a>> {
    Box::pin(async move {
        match v {
            Value::Object(map) => {
                let mut out = serde_json::Map::new();
                for (k, val) in map {
                    // Webhook references are re-provisioned locally; drop them entirely.
                    // `selector_id` can't be translated (selectors aren't in the sync map) — dropping
                    // it degrades to a monitor-scoped fire rather than keeping a wrong local FK.
                    if k == "webhook_trigger_id"
                        || k == "webhook_trigger_token"
                        || k == "selector_id"
                    {
                        continue;
                    }
                    let entity = if BLOCK_WORKFLOW_ID_KEYS.contains(&k.as_str()) {
                        Some(ENTITY_WORKFLOW)
                    } else if k == "persona_id" {
                        Some(ENTITY_PERSONA)
                    } else if k == "target_id" {
                        Some(ENTITY_MONITOR)
                    } else {
                        None
                    };
                    if let Some(entity) = entity {
                        match remap_ref(db, entity, Some(val)).await? {
                            RemapOutcome::Absent => {
                                // A null/absent-shaped value (e.g. explicit null) — keep as-is.
                                out.insert(k.clone(), val.clone());
                            }
                            RemapOutcome::Mapped(local_id) => {
                                out.insert(k.clone(), Value::Number(local_id.into()));
                            }
                            RemapOutcome::Unresolved => return Ok(None),
                        }
                        continue;
                    }
                    // Non-id key → recurse (nested objects/arrays may still hold ids).
                    match remap_value(db, val).await? {
                        Some(remapped) => {
                            out.insert(k.clone(), remapped);
                        }
                        None => return Ok(None),
                    }
                }
                Ok(Some(Value::Object(out)))
            }
            Value::Array(arr) => {
                let mut out = Vec::with_capacity(arr.len());
                for item in arr {
                    match remap_value(db, item).await? {
                        Some(remapped) => out.push(remapped),
                        None => return Ok(None),
                    }
                }
                Ok(Some(Value::Array(out)))
            }
            other => Ok(Some(other.clone())),
        }
    })
}

// --------------------------------------------------------------------------------------------
// PULL — extracted data (cloud runs → local runs)
// --------------------------------------------------------------------------------------------

/// Run-metadata columns the Workflow Data API adds to every row — excluded from the reconstructed
/// extracted record (they describe the run, not the scraped data).
const DATA_META_COLS: [&str; 4] = ["run_id", "run_at", "status", "record_index"];

/// Accumulates the flattened rows the cloud Workflow Data API returns for ONE cloud run back into
/// that run's original `extracted_data` shape (single object, or an array when the run produced
/// multiple `record_index` rows) plus its run metadata + input values.
#[derive(Default)]
struct RunAccum {
    run_at: Option<String>,
    status: String,
    /// One reconstructed record per source row (ordered by arrival ≈ record_index).
    records: Vec<Value>,
    /// `input.<name>` columns, shared across a run's rows → the run's merged form data.
    inputs: serde_json::Map<String, Value>,
}

impl RunAccum {
    /// Absorb one flattened data row: split run-metadata, `input.*`, and extracted columns.
    fn absorb(&mut self, row: &serde_json::Map<String, Value>) {
        if self.run_at.is_none() {
            if let Some(Value::String(s)) = row.get("run_at") {
                self.run_at = Some(s.clone());
            }
        }
        if self.status.is_empty() {
            if let Some(Value::String(s)) = row.get("status") {
                self.status = s.clone();
            }
        }
        let mut record = serde_json::Map::new();
        for (k, v) in row {
            if DATA_META_COLS.contains(&k.as_str()) {
                continue;
            }
            if let Some(name) = k.strip_prefix("input.") {
                self.inputs.entry(name.to_string()).or_insert_with(|| v.clone());
            } else {
                record.insert(k.clone(), v.clone());
            }
        }
        if !record.is_empty() {
            self.records.push(Value::Object(record));
        }
    }

    fn success(&self) -> bool {
        self.status.eq_ignore_ascii_case("success")
    }

    /// `{"extracted_data": <object|array>}` — array iff the run produced more than one record, so
    /// `data_query.rs` flattens it back to the same rows the cloud showed.
    fn result_data_json(&self) -> String {
        let extracted = if self.records.len() == 1 {
            self.records[0].clone()
        } else {
            Value::Array(self.records.clone())
        };
        serde_json::to_string(&json!({ "extracted_data": extracted })).unwrap_or_default()
    }

    /// `{"_cloud_source": true, "merged_form_data": {...}}` — marks the row as imported and stores the
    /// run's inputs where `data_query.rs` reads them for the `input.*` columns.
    fn trigger_context_json(&self) -> String {
        serde_json::to_string(&json!({
            "_cloud_source": true,
            "merged_form_data": Value::Object(self.inputs.clone()),
        }))
        .unwrap_or_default()
    }
}

/// PULL extracted data: for each cloud-mapped workflow, page through its Workflow Data API table
/// (`GET /api/v1/workflows/{id}/data`, already redacted by the cloud), group the flattened rows back
/// by `run_id`, and import each not-yet-seen cloud run as a local `runs` row so the Data explorer —
/// which derives its table from `runs.result_data.extracted_data` — surfaces it. Idempotent: each
/// cloud run id is mapped once under [`ENTITY_RUN`]; already-imported runs are skipped on re-pull.
/// Returns the count of run rows imported.
async fn pull_extracted_data(db: &SqlitePool, client: &mut CloudClient) -> LocalResult<i64> {
    let mut imported = 0i64;

    // Only workflows we actually synced have a cloud id to query against the data API.
    for map in cloud_sync_map::list_by_type(db, ENTITY_WORKFLOW).await? {
        let mut by_run: std::collections::BTreeMap<String, RunAccum> = std::collections::BTreeMap::new();
        let mut offset = 0i64;

        loop {
            let path = format!(
                "/api/v1/workflows/{}/data?limit={}&offset={}&include_inputs=true",
                map.cloud_id, DATA_PAGE_LIMIT, offset
            );
            let page: Value = match client.get_json(&path).await {
                Ok(v) => v,
                Err(e) => {
                    // A workflow with no data API / a transient error shouldn't fail the whole pull.
                    tracing::warn!(cloud_id = %map.cloud_id, error = %e, "skip workflow data: fetch failed");
                    break;
                }
            };
            let rows = page.get("rows").and_then(Value::as_array).cloned().unwrap_or_default();
            let fetched = rows.len() as i64;
            for row in &rows {
                let Some(obj) = row.as_object() else { continue };
                let Some(run_id) = data_row_run_id(obj) else { continue };
                by_run.entry(run_id).or_default().absorb(obj);
            }

            offset += DATA_PAGE_LIMIT;
            // Stop on a short page (no more rows), past the reported total, or the safety cap.
            if fetched < DATA_PAGE_LIMIT || offset >= MAX_DATA_ROWS {
                break;
            }
            if let Some(total) = page.pointer("/pagination/total").and_then(Value::as_i64) {
                if offset >= total {
                    break;
                }
            }
        }

        for (cloud_run_id, accum) in by_run {
            // Idempotent: never re-import a run we already mapped.
            if cloud_sync_map::get_by_cloud_id(db, ENTITY_RUN, &cloud_run_id).await?.is_some() {
                continue;
            }
            let status = if accum.status.is_empty() { "success".to_string() } else { accum.status.clone() };
            let run = runs::insert_imported(
                db,
                map.local_id,
                &status,
                accum.success(),
                accum.run_at.as_deref(),
                Some(&accum.result_data_json()),
                Some(&accum.trigger_context_json()),
            )
            .await?;
            cloud_sync_map::upsert(db, ENTITY_RUN, run.id, &cloud_run_id, None, "cloud").await?;
            imported += 1;
        }
    }

    Ok(imported)
}

/// Extract a row's `run_id` as a string key (the data API sends it as a JSON number).
fn data_row_run_id(row: &serde_json::Map<String, Value>) -> Option<String> {
    match row.get("run_id") {
        Some(Value::Number(n)) => Some(n.to_string()),
        Some(Value::String(s)) if !s.is_empty() => Some(s.clone()),
        _ => None,
    }
}

// --------------------------------------------------------------------------------------------
// PUSH (granular, user-initiated)
// --------------------------------------------------------------------------------------------

/// PUSH the given local rows of one entity type to the user's PRIVATE cloud records. Recipe +
/// references only — every secret/credential VALUE is stripped. Each successful push records a
/// `cloud_sync_map` mapping with `origin='local'`. Per-item failures land in `skipped`, never 500.
pub async fn push(
    db: &SqlitePool,
    link: &super::state::LinkState,
    entity_type: &str,
    local_ids: &[i64],
) -> PushResult {
    let mut pushed = Vec::new();
    let mut skipped = Vec::new();

    let mut client = match CloudClient::connect(Some(link)) {
        Ok(c) => c,
        Err(e) => {
            // Not linked → every requested id is skipped with the same reason.
            for id in local_ids {
                skipped.push(Skipped { local_id: *id, reason: format!("not linked: {e}") });
            }
            return PushResult { ok: false, pushed, skipped };
        }
    };

    for &local_id in local_ids {
        match push_one(db, &mut client, entity_type, local_id).await {
            Ok(cloud_id) => pushed.push(Pushed { local_id, cloud_id }),
            Err(reason) => skipped.push(Skipped { local_id, reason }),
        }
    }

    PushResult { ok: skipped.is_empty(), pushed, skipped }
}

/// Push a single local row. Returns the cloud id on success, or a human reason string on skip.
/// Errors are returned as `String` (not `LocalError`) so the caller can collect them into `skipped`
/// without aborting the whole batch.
async fn push_one(
    db: &SqlitePool,
    client: &mut CloudClient,
    entity_type: &str,
    local_id: i64,
) -> Result<String, String> {
    // Resolve the cloud path + a SECRET-STRIPPED body for this entity type.
    let (list_path, body) = match entity_type {
        ENTITY_WORKFLOW => {
            let wf = workflows::get_by_id(db, local_id)
                .await
                .map_err(|e| e.to_string())?
                .ok_or_else(|| "workflow not found".to_string())?;
            (CLOUD_WORKFLOWS, workflow_push_body(&wf))
        }
        ENTITY_PERSONA => {
            let p = personas::get_by_id(db, local_id)
                .await
                .map_err(|e| e.to_string())?
                .ok_or_else(|| "persona not found".to_string())?;
            (CLOUD_PERSONAS, persona_push_body(&p))
        }
        ENTITY_MONITOR => {
            let t = targets::get_by_id(db, local_id)
                .await
                .map_err(|e| e.to_string())?
                .ok_or_else(|| "monitor not found".to_string())?;
            (CLOUD_TARGETS, target_push_body(&t))
        }
        other => return Err(format!("unknown entity_type {other:?}")),
    };

    // If this local row already maps to a cloud row, UPDATE it (PATCH); else CREATE it (POST).
    let existing = cloud_sync_map::get_by_local_id(db, entity_type, local_id)
        .await
        .map_err(|e| e.to_string())?;

    let cloud_id = if let Some(map) = existing.filter(|m| m.origin == "local") {
        // Update the previously-pushed cloud row. The backend update verb differs by resource:
        // workflows use PUT (backend automation.py `@router.put("/workflows/{id}")`), while targets
        // and personas use PATCH. Using the wrong verb 405s, so pick per entity type.
        let path = format!("{list_path}/{}", map.cloud_id);
        let resp: Value = if entity_type == ENTITY_WORKFLOW {
            client.put_json(&path, &body).await.map_err(|e| e.to_string())?
        } else {
            client.patch_json(&path, &body).await.map_err(|e| e.to_string())?
        };
        cloud_id_of(&resp).unwrap_or(map.cloud_id)
    } else {
        // Create a fresh private cloud row.
        let resp: Value = client.post_json(list_path, &body).await.map_err(|e| e.to_string())?;
        cloud_id_of(&resp).ok_or_else(|| "cloud create returned no id".to_string())?
    };

    cloud_sync_map::upsert(db, entity_type, local_id, &cloud_id, None, "local")
        .await
        .map_err(|e| e.to_string())?;
    Ok(cloud_id)
}

// --------------------------------------------------------------------------------------------
// ITEMS (granular list joined with the sync map)
// --------------------------------------------------------------------------------------------

/// List every local workflow / persona / monitor joined with its `cloud_sync_map` mapping, yielding
/// `{origin, status}` for each. `status` is `"diverged"` when a cloud-origin row's current local
/// content hash differs from the stored hash, `"cloud"` for a clean cloud-origin row, and `"local"`
/// for a locally-authored row (no mapping) or one we pushed up.
pub async fn items(db: &SqlitePool) -> LocalResult<Vec<SyncItem>> {
    let mut out = Vec::new();

    // Workflows.
    let map: HashMap<i64, cloud_sync_map::SyncMap> =
        cloud_sync_map::list_by_type(db, ENTITY_WORKFLOW)
            .await?
            .into_iter()
            .map(|m| (m.local_id, m))
            .collect();
    for wf in workflows::list(db, false, 1000).await? {
        let (cloud_id, origin, status) = match map.get(&wf.id) {
            Some(m) => {
                let local_hash = workflow_content_hash(&wf);
                let status = item_status(m, &local_hash);
                (Some(m.cloud_id.clone()), m.origin.clone(), status)
            }
            None => (None, "local".to_string(), "local".to_string()),
        };
        out.push(SyncItem {
            entity_type: ENTITY_WORKFLOW.into(),
            local_id: wf.id,
            cloud_id,
            origin,
            name: wf.name,
            status,
        });
    }

    // Personas.
    let map: HashMap<i64, cloud_sync_map::SyncMap> =
        cloud_sync_map::list_by_type(db, ENTITY_PERSONA)
            .await?
            .into_iter()
            .map(|m| (m.local_id, m))
            .collect();
    for p in personas::list(db, Some(500)).await? {
        let (cloud_id, origin, status) = match map.get(&p.id) {
            Some(m) => {
                let local_hash = persona_content_hash(&p);
                let status = item_status(m, &local_hash);
                (Some(m.cloud_id.clone()), m.origin.clone(), status)
            }
            None => (None, "local".to_string(), "local".to_string()),
        };
        out.push(SyncItem {
            entity_type: ENTITY_PERSONA.into(),
            local_id: p.id,
            cloud_id,
            origin,
            name: p.name,
            status,
        });
    }

    // Monitors (targets).
    let map: HashMap<i64, cloud_sync_map::SyncMap> =
        cloud_sync_map::list_by_type(db, ENTITY_MONITOR)
            .await?
            .into_iter()
            .map(|m| (m.local_id, m))
            .collect();
    for t in targets::list(db, 1000).await? {
        let (cloud_id, origin, status) = match map.get(&t.id) {
            Some(m) => {
                let local_hash = target_content_hash(&t);
                let status = item_status(m, &local_hash);
                (Some(m.cloud_id.clone()), m.origin.clone(), status)
            }
            None => (None, "local".to_string(), "local".to_string()),
        };
        out.push(SyncItem {
            entity_type: ENTITY_MONITOR.into(),
            local_id: t.id,
            cloud_id,
            origin,
            name: t.url,
            status,
        });
    }

    // Automations.
    let map: HashMap<i64, cloud_sync_map::SyncMap> =
        cloud_sync_map::list_by_type(db, ENTITY_AUTOMATION)
            .await?
            .into_iter()
            .map(|m| (m.local_id, m))
            .collect();
    for a in automations::list(db, 1000).await? {
        let (cloud_id, origin, status) = match map.get(&a.id) {
            Some(m) => {
                let local_hash = automation_content_hash(&a);
                let status = item_status(m, &local_hash);
                (Some(m.cloud_id.clone()), m.origin.clone(), status)
            }
            None => (None, "local".to_string(), "local".to_string()),
        };
        out.push(SyncItem {
            entity_type: ENTITY_AUTOMATION.into(),
            local_id: a.id,
            cloud_id,
            origin,
            name: a.name,
            status,
        });
    }

    Ok(out)
}

/// `status` for a mapped row: `"diverged"` when a CLOUD-origin row's local hash drifted from the
/// stored hash; otherwise reflect the mapping's `origin` (`"cloud"`/`"local"`).
fn item_status(m: &cloud_sync_map::SyncMap, local_hash: &str) -> String {
    if m.origin == "cloud" && m.content_hash.as_deref() != Some(local_hash) {
        "diverged".to_string()
    } else {
        m.origin.clone()
    }
}

// --------------------------------------------------------------------------------------------
// STATUS persistence
// --------------------------------------------------------------------------------------------

/// `{in_progress, last_pull_at, counts, diverged_count}` for the status endpoint.
#[derive(Debug, Clone, serde::Serialize)]
pub struct SyncStatus {
    pub in_progress: bool,
    pub last_pull_at: Option<String>,
    pub counts: PullCounts,
    pub diverged_count: i64,
}

/// In-process flag so the status endpoint can report a pull is running. Uses `config_kv` (a tiny
/// non-secret string) so the answer survives within the daemon process; a crash mid-pull leaves a
/// stale `true`, which the next pull clears, so we also treat a missing key as `false`.
const KV_IN_PROGRESS: &str = "cloud.sync.in_progress";

async fn set_in_progress(db: &SqlitePool, on: bool) {
    let _ = super::super::store::config_kv::set(db, KV_IN_PROGRESS, if on { "1" } else { "0" }).await;
}

/// Persist `last_pull_at = now` + the latest counts (best-effort; never fails the pull).
async fn persist_pull_status(db: &SqlitePool, counts: &PullCounts) {
    let now = chrono::Utc::now().to_rfc3339();
    let _ = super::super::store::config_kv::set(db, KV_LAST_PULL_AT, &now).await;
    if let Ok(s) = serde_json::to_string(counts) {
        let _ = super::super::store::config_kv::set(db, KV_LAST_COUNTS, &s).await;
    }
}

/// Compute the current sync status from `config_kv` + a live diverged-count scan over `items`.
pub async fn status(db: &SqlitePool) -> LocalResult<SyncStatus> {
    use super::super::store::config_kv;
    let in_progress = config_kv::get(db, KV_IN_PROGRESS).await?.as_deref() == Some("1");
    let last_pull_at = config_kv::get(db, KV_LAST_PULL_AT).await?;
    let counts = match config_kv::get(db, KV_LAST_COUNTS).await? {
        Some(s) => serde_json::from_str(&s).unwrap_or_default(),
        None => PullCounts::default(),
    };
    let diverged_count = items(db)
        .await?
        .iter()
        .filter(|i| i.status == "diverged")
        .count() as i64;
    Ok(SyncStatus { in_progress, last_pull_at, counts, diverged_count })
}

// --------------------------------------------------------------------------------------------
// Cloud JSON → local row mappers (PULL) and local row → cloud body mappers (PUSH)
// --------------------------------------------------------------------------------------------

/// Extract the row array from a cloud list response. The cloud sometimes wraps rows in `{data: [...]}`
/// and sometimes returns a bare `[...]`; tolerate both, plus a single-object response.
fn as_rows(v: &Value) -> Vec<Value> {
    if let Some(arr) = v.as_array() {
        return arr.clone();
    }
    if let Some(arr) = v.get("data").and_then(|d| d.as_array()) {
        return arr.clone();
    }
    if v.is_object() {
        return vec![v.clone()];
    }
    Vec::new()
}

/// Re-serialize a JSON value as compact TEXT for a JSON-TEXT column. `null`/absent → `None`.
fn json_text(v: Option<&Value>) -> Option<String> {
    match v {
        None | Some(Value::Null) => None,
        Some(Value::String(s)) => Some(s.clone()),
        Some(other) => Some(other.to_string()),
    }
}

fn str_opt(v: Option<&Value>) -> Option<String> {
    v.and_then(|x| x.as_str()).map(|s| s.to_string())
}

fn int_opt(v: Option<&Value>) -> Option<i64> {
    v.and_then(|x| x.as_i64())
}

fn bool_int_opt(v: Option<&Value>) -> Option<i64> {
    v.and_then(|x| x.as_bool()).map(|b| b as i64)
}

// ---- workflows ----

pub(crate) fn new_workflow_from_cloud(c: &Value) -> workflows::NewWorkflow {
    workflows::NewWorkflow {
        name: str_opt(c.get("name")).unwrap_or_else(|| "Untitled".into()),
        description: str_opt(c.get("description")),
        workflow_type: str_opt(c.get("workflow_type")),
        steps: json_text(c.get("steps")),
        raw_replay: json_text(c.get("raw_replay")),
        form_data: json_text(c.get("form_data")),
        exit_condition: json_text(c.get("exit_condition")),
        input_rules: json_text(c.get("input_rules")),
        api_functions: json_text(c.get("api_functions")),
        streaming_config: json_text(c.get("streaming_config")),
        functions: json_text(c.get("functions")),
        // NEVER import a credential VALUE from the cloud — creds stay local & are user-attached.
        credentials_encrypted: None,
        entry_url: str_opt(c.get("entry_url")),
        default_persona_id: None,
        timeout_ms: int_opt(c.get("timeout_ms")),
        retry_count: int_opt(c.get("retry_count")),
        headless: bool_int_opt(c.get("headless")),
        fast_mode: bool_int_opt(c.get("fast_mode")),
        // Structured recurrence (SCHEDULE_RECURRENCE_SPEC): carry the kind/time/days/tz from cloud so a
        // synced workflow keeps its schedule shape. `schedule_days` arrives as a JSON array → stored as
        // a JSON string. Absent ⇒ None (the column default `interval` / NULLs apply).
        schedule_kind: str_opt(c.get("schedule_kind")),
        schedule_time: str_opt(c.get("schedule_time")),
        schedule_days: json_text(c.get("schedule_days")),
        schedule_tz: str_opt(c.get("schedule_tz")),
        auth_config: json_text(c.get("auth_config")),
        // NEVER from sync: proxy rows are minted only by the marketplace install path.
        marketplace_slug: None,
    }
}

pub(crate) fn workflow_update_from_cloud(c: &Value) -> workflows::WorkflowUpdate {
    workflows::WorkflowUpdate {
        name: str_opt(c.get("name")),
        description: str_opt(c.get("description")),
        workflow_type: str_opt(c.get("workflow_type")),
        steps: json_text(c.get("steps")),
        raw_replay: json_text(c.get("raw_replay")),
        form_data: json_text(c.get("form_data")),
        exit_condition: json_text(c.get("exit_condition")),
        input_rules: json_text(c.get("input_rules")),
        api_functions: json_text(c.get("api_functions")),
        streaming_config: json_text(c.get("streaming_config")),
        functions: json_text(c.get("functions")),
        // Cloud never ships cred values; leave the local sealed blob untouched.
        credentials_encrypted: None,
        entry_url: str_opt(c.get("entry_url")),
        timeout_ms: int_opt(c.get("timeout_ms")),
        retry_count: int_opt(c.get("retry_count")),
        headless: bool_int_opt(c.get("headless")),
        fast_mode: bool_int_opt(c.get("fast_mode")),
        ..Default::default()
    }
}

/// Secret-stripped cloud body for a workflow push: recipe + references ONLY. The sealed
/// `credentials_encrypted` blob is NEVER serialized; the cloud row carries `has_credentials` derived
/// from whatever the buyer attaches there, not our local secret.
fn workflow_push_body(wf: &workflows::Workflow) -> Value {
    let parse = |s: &Option<String>| -> Value {
        s.as_deref()
            .filter(|t| !t.is_empty())
            .and_then(|t| serde_json::from_str::<Value>(t).ok())
            .unwrap_or(Value::Null)
    };
    json!({
        "name": wf.name,
        "description": wf.description,
        "workflow_type": wf.workflow_type,
        "steps": parse(&Some(wf.steps.clone())),
        "form_data": parse(&wf.form_data),
        "functions": parse(&wf.functions),
        "exit_condition": parse(&wf.exit_condition),
        "input_rules": parse(&wf.input_rules),
        "entry_url": wf.entry_url,
        "timeout_ms": wf.timeout_ms,
        "retry_count": wf.retry_count,
        "headless": wf.headless != 0,
        "fast_mode": wf.fast_mode != 0,
        // Explicitly DO NOT send credentials_encrypted — secrets stay local.
    })
}

// ---- personas ----

pub(crate) fn new_persona_from_cloud(c: &Value) -> personas::NewPersona {
    personas::NewPersona {
        name: str_opt(c.get("name")).unwrap_or_else(|| "Imported".into()),
        description: str_opt(c.get("description")),
        target_domain: str_opt(c.get("target_domain")),
        login_username: str_opt(c.get("login_username")),
        // Cloud never returns persona secret values; nothing to seal here normally.
        credentials_encrypted: None,
        twofa_method: str_opt(c.get("twofa_method")),
        totp_seed_encrypted: None,
        totp_digits: int_opt(c.get("totp_digits")),
        totp_period_seconds: int_opt(c.get("totp_period_seconds")),
        totp_algorithm: str_opt(c.get("totp_algorithm")),
        email_otp_mode: str_opt(c.get("email_otp_mode")),
        relay_address: str_opt(c.get("relay_address")),
        otp_extract_config: json_text(c.get("otp_extract_config")),
        fingerprint: json_text(c.get("fingerprint")),
        proxy_config_encrypted: None,
        session_state_encrypted: None,
        earliest_cookie_expiry: None,
        expires_at: None,
    }
}

fn persona_update_from_cloud(c: &Value) -> personas::PersonaUpdate {
    personas::PersonaUpdate {
        name: str_opt(c.get("name")),
        description: str_opt(c.get("description")),
        target_domain: str_opt(c.get("target_domain")),
        login_username: str_opt(c.get("login_username")),
        twofa_method: str_opt(c.get("twofa_method")),
        totp_digits: int_opt(c.get("totp_digits")),
        totp_period_seconds: int_opt(c.get("totp_period_seconds")),
        totp_algorithm: str_opt(c.get("totp_algorithm")),
        email_otp_mode: str_opt(c.get("email_otp_mode")),
        relay_address: str_opt(c.get("relay_address")),
        // Never touch the sealed secret columns on a pull.
        ..Default::default()
    }
}

/// Secret-stripped cloud body for a persona push: identity + 2FA METADATA only, never the password,
/// TOTP seed, proxy, or session values.
fn persona_push_body(p: &personas::Persona) -> Value {
    json!({
        "name": p.name,
        "description": p.description,
        "target_domain": p.target_domain,
        "login_username": p.login_username,
        "twofa_method": p.twofa_method,
        "totp_digits": p.totp_digits,
        "totp_period_seconds": p.totp_period_seconds,
        "totp_algorithm": p.totp_algorithm,
        "email_otp_mode": p.email_otp_mode,
        "relay_address": p.relay_address,
        // Explicitly DO NOT send any *_encrypted secret value.
    })
}

/// AAD for a pulled persona's sealed credentials blob — mirrors `engine::persona::persona_aad`
/// (`personas|<column>|<id>`) so the engine can open what we seal.
fn persona_credentials_aad(persona_id: i64) -> String {
    format!("personas|credentials_encrypted|{persona_id}")
}

/// Seal a plaintext `{name: value}` credentials map into a `WF1:` blob bound to the persona row.
fn seal_persona_credentials(
    vault: &Vault,
    persona_id: i64,
    creds: &HashMap<String, String>,
) -> LocalResult<String> {
    let plaintext = serde_json::to_vec(creds)?;
    vault.seal_field(&plaintext, &persona_credentials_aad(persona_id))
}

/// Extract a plaintext `{name: value}` credentials map from a cloud persona row IF (and only if) the
/// cloud ever returns one. Today the cloud returns only `has_password`/`has_totp_seed` flags, so
/// this returns `None` in practice — but the seal path is wired so a future plaintext payload lands
/// encrypted in the LOCAL vault rather than as cleartext in the DB.
fn extract_plaintext_credentials(c: &Value) -> Option<HashMap<String, String>> {
    let obj = c.get("credentials")?.as_object()?;
    let mut map = HashMap::new();
    for (k, v) in obj {
        if let Some(s) = v.as_str() {
            map.insert(k.clone(), s.to_string());
        }
    }
    (!map.is_empty()).then_some(map)
}

/// Move a `NewPersona` out by replacing it with a default (so we can both keep a pre-read flag and
/// pass the value by reference into `insert`). Trivial helper to avoid a needless clone.
fn new_taking(p: &mut personas::NewPersona) -> personas::NewPersona {
    std::mem::take(p)
}

// ---- monitors (targets) ----

pub(crate) fn new_target_from_cloud(c: &Value) -> targets::NewTarget {
    targets::NewTarget {
        url: str_opt(c.get("url")).unwrap_or_default(),
        check_type: str_opt(c.get("check_type")),
        selector: str_opt(c.get("selector")),
        ignore_regex: str_opt(c.get("ignore_regex")),
        check_period_ms: int_opt(c.get("check_period_ms")),
        expected_status_code: int_opt(c.get("expected_status_code")),
        timeout_ms: int_opt(c.get("timeout_ms")),
        max_response_time_ms: int_opt(c.get("max_response_time_ms")),
        check_ssl: bool_int_opt(c.get("check_ssl")),
        enabled: bool_int_opt(c.get("enabled")),
        requires_playwright: bool_int_opt(c.get("requires_playwright")),
        pre_check_workflow_id: None,
        setup_steps: json_text(c.get("setup_steps")),
        on_change_workflow_id: None,
        on_change_enabled: bool_int_opt(c.get("on_change_enabled")),
        on_change_conditions: json_text(c.get("on_change_conditions")),
        on_change_in_session: bool_int_opt(c.get("on_change_in_session")),
        persona_id: None,
        notification_providers: json_text(c.get("notification_providers")),
        provider_notification_settings: json_text(c.get("provider_notification_settings")),
        notification_title: str_opt(c.get("notification_title")),
        notification_message: str_opt(c.get("notification_message")),
        notification_priority: int_opt(c.get("notification_priority")),
        next_run_at: None,
        // Structured recurrence (SCHEDULE_RECURRENCE_SPEC): carry kind/time/days/tz from cloud.
        // `schedule_days` arrives as a JSON array → stored as a JSON string.
        schedule_kind: str_opt(c.get("schedule_kind")),
        schedule_time: str_opt(c.get("schedule_time")),
        schedule_days: json_text(c.get("schedule_days")),
        schedule_tz: str_opt(c.get("schedule_tz")),
    }
}

fn target_update_from_cloud(c: &Value) -> targets::TargetUpdate {
    targets::TargetUpdate {
        url: str_opt(c.get("url")),
        check_type: str_opt(c.get("check_type")),
        selector: str_opt(c.get("selector")),
        ignore_regex: str_opt(c.get("ignore_regex")),
        check_period_ms: int_opt(c.get("check_period_ms")),
        expected_status_code: int_opt(c.get("expected_status_code")),
        timeout_ms: int_opt(c.get("timeout_ms")),
        max_response_time_ms: int_opt(c.get("max_response_time_ms")),
        check_ssl: bool_int_opt(c.get("check_ssl")),
        enabled: bool_int_opt(c.get("enabled")),
        requires_playwright: bool_int_opt(c.get("requires_playwright")),
        setup_steps: json_text(c.get("setup_steps")),
        on_change_enabled: bool_int_opt(c.get("on_change_enabled")),
        on_change_conditions: json_text(c.get("on_change_conditions")),
        on_change_in_session: bool_int_opt(c.get("on_change_in_session")),
        notification_providers: json_text(c.get("notification_providers")),
        provider_notification_settings: json_text(c.get("provider_notification_settings")),
        notification_title: str_opt(c.get("notification_title")),
        notification_message: str_opt(c.get("notification_message")),
        notification_priority: int_opt(c.get("notification_priority")),
        // Structured recurrence (SCHEDULE_RECURRENCE_SPEC): carry kind/time/days/tz from cloud.
        schedule_kind: str_opt(c.get("schedule_kind")),
        schedule_time: str_opt(c.get("schedule_time")),
        schedule_days: json_text(c.get("schedule_days")),
        schedule_tz: str_opt(c.get("schedule_tz")),
        ..Default::default()
    }
}

/// Secret-stripped cloud body for a monitor push: the check DEFINITION only — never the sealed
/// `auth_session_encrypted` session blob.
fn target_push_body(t: &targets::Target) -> Value {
    let parse = |s: &Option<String>| -> Value {
        s.as_deref()
            .filter(|x| !x.is_empty())
            .and_then(|x| serde_json::from_str::<Value>(x).ok())
            .unwrap_or(Value::Null)
    };
    json!({
        "url": t.url,
        "check_type": t.check_type,
        "selector": t.selector,
        "ignore_regex": t.ignore_regex,
        "check_period_ms": t.check_period_ms,
        "expected_status_code": t.expected_status_code,
        "timeout_ms": t.timeout_ms,
        "max_response_time_ms": t.max_response_time_ms,
        "check_ssl": t.check_ssl.map(|v| v != 0),
        "enabled": t.enabled != 0,
        "requires_playwright": t.requires_playwright != 0,
        "setup_steps": parse(&t.setup_steps),
        "on_change_enabled": t.on_change_enabled != 0,
        "on_change_conditions": parse(&t.on_change_conditions),
        "notification_providers": parse(&t.notification_providers),
        // Explicitly DO NOT send auth_session_encrypted — the session secret stays local.
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::local::db;

    async fn pool() -> SqlitePool {
        let dir = Box::leak(Box::new(tempfile::tempdir().unwrap()));
        db::open(&dir.path().join("t.db"), "test-key-sync").await.unwrap()
    }

    #[test]
    fn canonical_bytes_is_key_order_stable() {
        let a = json!({ "b": 1, "a": [ { "y": 2, "x": 1 } ] });
        let b = json!({ "a": [ { "x": 1, "y": 2 } ], "b": 1 });
        assert_eq!(canonical_bytes(&a), canonical_bytes(&b), "key order must not affect the hash");
    }

    #[test]
    fn as_rows_tolerates_shapes() {
        assert_eq!(as_rows(&json!([{"id":1},{"id":2}])).len(), 2);
        assert_eq!(as_rows(&json!({"data":[{"id":1}]})).len(), 1);
        assert_eq!(as_rows(&json!({"id":7})).len(), 1, "bare object → single row");
        assert_eq!(as_rows(&json!("nope")).len(), 0);
    }

    #[test]
    fn cloud_id_stringifies_int_and_string() {
        assert_eq!(cloud_id_of(&json!({"id": 42})).as_deref(), Some("42"));
        assert_eq!(cloud_id_of(&json!({"id": "wf_x"})).as_deref(), Some("wf_x"));
        assert_eq!(cloud_id_of(&json!({"id": ""})), None);
        assert_eq!(cloud_id_of(&json!({})), None);
    }

    #[test]
    fn workflow_push_body_never_carries_credentials() {
        let mut wf = workflows::Workflow {
            id: 1,
            name: "n".into(),
            description: None,
            workflow_type: "recorded".into(),
            steps: "[]".into(),
            raw_replay: None,
            form_data: None,
            exit_condition: None,
            input_rules: None,
            api_functions: None,
            streaming_config: None,
            functions: None,
            credentials_encrypted: Some("WF1:should-never-leak".into()),
            entry_url: None,
            timeout_ms: 30000,
            retry_count: 2,
            headless: 1,
            fast_mode: 1,
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
            relogin_max_retries: 1,
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
            created_at: "now".into(),
            updated_at: None,
        };
        wf.form_data = Some(r#"{"u":"a"}"#.into());
        let body = workflow_push_body(&wf);
        let raw = body.to_string();
        assert!(!raw.contains("credentials_encrypted"), "no secret column key: {raw}");
        assert!(!raw.contains("WF1:"), "no sealed blob may leak: {raw}");
        assert_eq!(body["name"], json!("n"));
    }

    #[tokio::test]
    async fn items_marks_local_authored_rows_local() {
        let pool = pool().await;
        // A locally-authored workflow with NO sync map entry must read origin/status = "local".
        workflows::insert(
            &pool,
            &workflows::NewWorkflow { name: "mine".into(), ..Default::default() },
        )
        .await
        .unwrap();
        let listed = items(&pool).await.unwrap();
        let wf = listed.iter().find(|i| i.entity_type == ENTITY_WORKFLOW).unwrap();
        assert_eq!(wf.origin, "local");
        assert_eq!(wf.status, "local");
        assert!(wf.cloud_id.is_none());
    }

    #[tokio::test]
    async fn items_reports_divergence_for_edited_cloud_row() {
        let pool = pool().await;
        // Insert a workflow, map it as cloud-origin with a STALE hash → it must read "diverged".
        let wf = workflows::insert(
            &pool,
            &workflows::NewWorkflow { name: "pulled".into(), ..Default::default() },
        )
        .await
        .unwrap();
        cloud_sync_map::upsert(&pool, ENTITY_WORKFLOW, wf.id, "wf_cloud", Some("staleHASH"), "cloud")
            .await
            .unwrap();
        let listed = items(&pool).await.unwrap();
        let row = listed.iter().find(|i| i.local_id == wf.id).unwrap();
        assert_eq!(row.origin, "cloud");
        assert_eq!(row.status, "diverged", "stale stored hash ⇒ diverged");

        // Now store the CURRENT hash → clean "cloud".
        let current = workflow_content_hash(&wf);
        cloud_sync_map::set_content_hash(&pool, ENTITY_WORKFLOW, wf.id, &current).await.unwrap();
        let listed = items(&pool).await.unwrap();
        let row = listed.iter().find(|i| i.local_id == wf.id).unwrap();
        assert_eq!(row.status, "cloud", "matching hash ⇒ clean cloud row");
    }

    // ---- automations (owned import + cloud-only proxy guard + fail-closed remap) ----

    #[test]
    fn nested_ref_guard_flags_proxy_blocks() {
        // A proxy install: the workflow block carries `nested_ref` instead of a concrete id.
        let proxy = json!([
            { "id": "e", "type": "event", "blockType": "change_detected", "config": {} },
            { "id": "a", "type": "action", "blockType": "workflow", "parentId": "e",
              "config": { "nested_ref": "ref_wf_1" } }
        ]);
        assert!(blocks_contain_nested_ref(Some(&proxy)));
        // `nested_refs` (ai_session plural form) also trips it.
        let proxy2 = json!([{ "config": { "nested_refs": ["r1", "r2"] } }]);
        assert!(blocks_contain_nested_ref(Some(&proxy2)));
        // A JSON-string-wrapped proxy tree is still detected.
        assert!(blocks_contain_nested_ref(Some(&json!(proxy.to_string()))));

        // A native/owned tree with concrete ids has NO token.
        let owned = json!([
            { "id": "a", "type": "action", "blockType": "workflow", "parentId": "e",
              "config": { "workflow_id": 55, "persona_id": 9 } }
        ]);
        assert!(!blocks_contain_nested_ref(Some(&owned)));
        assert!(!blocks_contain_nested_ref(None));
        assert!(!blocks_contain_nested_ref(Some(&Value::Null)));
    }

    #[tokio::test]
    async fn remap_fails_closed_on_unmapped_workflow() {
        let pool = pool().await;
        // Cloud automation references workflow cloud-id 700, which was never pulled → no mapping.
        let cloud = json!({
            "name": "on change run wf",
            "event_type": "change_detected",
            "workflow_id": 700,
            "blocks": [],
            "actions": [],
        });
        assert!(
            remap_automation(&pool, &cloud).await.unwrap().is_none(),
            "an unmapped top-level workflow_id must fail closed (skip)"
        );

        // Same for an EMBEDDED block workflow_id.
        let cloud2 = json!({
            "name": "flow",
            "event_type": "webhook_received",
            "blocks": [
                { "id": "a", "type": "action", "blockType": "workflow", "parentId": "e",
                  "config": { "workflow_id": 701 } }
            ],
            "actions": [],
        });
        assert!(
            remap_automation(&pool, &cloud2).await.unwrap().is_none(),
            "an unmapped embedded workflow_id must fail closed (skip)"
        );
    }

    #[tokio::test]
    async fn remap_translates_cloud_ids_to_local() {
        let pool = pool().await;
        // Pull a workflow so it gets a local id + a cloud→local mapping.
        let wf = workflows::insert(
            &pool,
            &workflows::NewWorkflow { name: "target wf".into(), ..Default::default() },
        )
        .await
        .unwrap();
        cloud_sync_map::upsert(&pool, ENTITY_WORKFLOW, wf.id, "900", Some("h"), "cloud")
            .await
            .unwrap();

        let cloud = json!({
            "name": "owned automation",
            "event_type": "webhook_received",
            "enabled": true,
            "priority": 5,
            "workflow_id": 900,
            "blocks": [
                { "id": "e", "type": "event", "blockType": "webhook_received",
                  "config": { "webhook_trigger_id": 42, "webhook_trigger_token": "tok" } },
                { "id": "a", "type": "action", "blockType": "workflow", "parentId": "e",
                  "config": { "workflow_id": 900, "selector_id": 3 } }
            ],
            "actions": [],
        });
        let remapped = remap_automation(&pool, &cloud)
            .await
            .unwrap()
            .expect("owned automation with mapped refs must import");

        // Top-level column translated cloud 900 → local wf.id.
        assert_eq!(remapped.workflow_id, Some(wf.id));
        // Webhook refs are re-provisioned locally, never carried over.
        assert!(remapped.into_new().webhook_trigger_id.is_none());

        // Re-derive blocks: embedded workflow_id remapped, webhook + selector ids dropped.
        let remapped = remap_automation(&pool, &cloud).await.unwrap().unwrap();
        let blocks_txt = remapped.blocks.clone().unwrap();
        let blocks: Value = serde_json::from_str(&blocks_txt).unwrap();
        let action_cfg = &blocks[1]["config"];
        assert_eq!(action_cfg["workflow_id"], json!(wf.id), "embedded id remapped to local");
        assert!(action_cfg.get("selector_id").is_none(), "unmappable selector_id dropped");
        let event_cfg = &blocks[0]["config"];
        assert!(event_cfg.get("webhook_trigger_id").is_none(), "webhook_trigger_id stripped");
        assert!(event_cfg.get("webhook_trigger_token").is_none(), "webhook token stripped");
    }

    #[tokio::test]
    async fn pull_end_to_end_imports_owned_skips_proxy_via_items() {
        // Drive the import halves that don't need the network: insert both an owned (remapped) and a
        // would-be proxy automation's local shape, and confirm the sync map + items reflect them.
        let pool = pool().await;
        let wf = workflows::insert(
            &pool,
            &workflows::NewWorkflow { name: "wf".into(), ..Default::default() },
        )
        .await
        .unwrap();
        cloud_sync_map::upsert(&pool, ENTITY_WORKFLOW, wf.id, "900", Some("h"), "cloud")
            .await
            .unwrap();

        let cloud = json!({
            "name": "owned",
            "event_type": "change_detected",
            "workflow_id": 900,
            "blocks": [],
            "actions": [],
        });
        let remapped = remap_automation(&pool, &cloud).await.unwrap().unwrap();
        let inserted = automations::insert(&pool, &remapped.into_new()).await.unwrap();
        let hash = automation_content_hash(&inserted);
        cloud_sync_map::upsert(&pool, ENTITY_AUTOMATION, inserted.id, "auto_1", Some(&hash), "cloud")
            .await
            .unwrap();

        let listed = items(&pool).await.unwrap();
        let row = listed
            .iter()
            .find(|i| i.entity_type == ENTITY_AUTOMATION && i.local_id == inserted.id)
            .expect("imported automation appears in items");
        assert_eq!(row.origin, "cloud");
        assert_eq!(row.status, "cloud", "fresh hash ⇒ clean cloud row (not diverged)");
        assert_eq!(row.cloud_id.as_deref(), Some("auto_1"));
    }
}
