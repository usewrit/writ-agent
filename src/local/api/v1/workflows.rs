//! `/v1/workflows` REST handlers — list/create/get/update/delete + run/cancel.
//!
//! Thin HTTP adapters over `store::workflows` and the `LocalEngine` run seam. House style: each
//! handler is `async fn(State, Path?, Query?, Json?) -> LocalResult<Json<_>>` and propagates store /
//! engine errors with `?` (they're `IntoResponse`). No auth layer here — `server.rs` applies the
//! loopback bearer + Origin/Host guard at the router level.
//!
//! Secret hygiene: `Workflow.credentials_encrypted` is a sealed Layer-B `WF1:` blob. We never echo
//! it back over the API — every response is shaped through `redact` first.

use crate::local::engine::{Lane, RunRequest, RunSource};
use crate::local::error::{LocalError, LocalResult};
use crate::local::server::AppState;
use crate::local::store::workflows::{self, NewWorkflow, Workflow, WorkflowUpdate};
use crate::local::vault::Vault;
use axum::extract::{Path, Query, State};
use axum::routing::{get, post};
use axum::{Json, Router};
use serde::Deserialize;
use serde_json::{json, Value};
use std::collections::BTreeMap;

/// Mount the workflow routes onto the shared `AppState` router. Auth is applied by `server.rs`.
pub fn router() -> Router<AppState> {
    Router::new()
        .route("/v1/workflows", get(list).post(create))
        .route(
            "/v1/workflows/:id",
            get(get_one).patch(update).delete(remove),
        )
        .route("/v1/workflows/:id/run", post(run))
        .route("/v1/workflows/:id/cancel", post(cancel))
        .route(
            "/v1/workflows/:id/session",
            get(get_session).delete(clear_session),
        )
}

/// `GET /v1/workflows/:id/session` — browserless-HTTP-lane session status for the Auth panel.
async fn get_session(
    State(st): State<AppState>,
    Path(id): Path<i64>,
) -> LocalResult<Json<Value>> {
    let row = crate::local::store::workflow_sessions::get(&st.db, id).await?;
    match row {
        Some(s) => Ok(Json(json!({
            "workflow_id": id,
            "has_session": s.session_state_encrypted.as_deref().map(|b| !b.is_empty()).unwrap_or(false),
            "engine": s.engine,
            "expires_at": s.extracted_at,   // the daemon uses extracted_at + ttl; surface it as-is
            "last_used_at": s.updated_at,
        }))),
        None => Ok(Json(json!({ "workflow_id": id, "has_session": false }))),
    }
}

/// `DELETE /v1/workflows/:id/session` — drop the workflow's persisted browserless-HTTP-lane session so
/// the next run logs in fresh. No-op (still 200) when there is no saved session.
async fn clear_session(
    State(st): State<AppState>,
    Path(id): Path<i64>,
) -> LocalResult<Json<Value>> {
    crate::local::store::workflow_sessions::clear(&st.db, id).await?;
    Ok(Json(json!({ "cleared": true })))
}

/// Query params for `GET /v1/workflows`.
#[derive(Debug, Deserialize)]
struct ListQuery {
    /// Filter to `is_active = 1` (default `true` — soft-deleted workflows are hidden).
    #[serde(default = "default_active_only")]
    active_only: bool,
    /// Page size (clamped to 1..=1000 by the store).
    #[serde(default = "default_limit")]
    limit: i64,
}

fn default_active_only() -> bool {
    true
}
fn default_limit() -> i64 {
    100
}

/// JSON-TEXT columns stored as `String` in [`Workflow`] (see `store::workflows`). On input the
/// create/update bodies accept rich JSON and serialize it to text (`de_json_text_opt`); on output we
/// must reverse that here, parsing the stored text back into real arrays/objects so the response
/// mirrors the Writ Cloud contract. Without this, the frontend receives `steps` as a JSON *string*
/// (truthy, no `.map`) and crashes the step editor.
const JSON_TEXT_COLS: &[&str] = &[
    "steps",
    "raw_replay",
    "form_data",
    "exit_condition",
    "input_rules",
    "api_functions",
    "streaming_config",
    "functions",
    "login_url_patterns",
];

/// Placeholder grammar for run-time inputs: `{{NAME}}` where NAME is `[A-Za-z0-9_.-]+` with NO colon,
/// which deliberately EXCLUDES namespaced refs (`{{secret:…}}`, `{{vault:…}}`, `{{file:…}}`). Matches
/// both bare `{{city}}` and the canonical `{{input.city}}` form (the dot is in the class). Whitespace
/// inside the braces is tolerated. Mirrors `engine::resolve`'s non-secret channel.
fn input_placeholder_re() -> &'static regex::Regex {
    static RE: std::sync::OnceLock<regex::Regex> = std::sync::OnceLock::new();
    RE.get_or_init(|| {
        regex::Regex::new(r"\{\{\s*([A-Za-z0-9_.\-]+)\s*\}\}").expect("placeholder regex is valid")
    })
}

/// The non-secret input fields a workflow needs at run time, shaped as the `{key, label, field_type}`
/// objects the desktop Run modal renders (cloud `_extract_placeholders` parity). De-duped by key in
/// first-seen order, sourced from:
///   1. declared `form_data` keys (skipping `__…` reserved/secret keys and any namespaced `a:b` key), then
///   2. `{{NAME}}` references scanned from the steps TEXT (secrets/vault/file excluded by the grammar).
///
/// The daemon — unlike the cloud — stores only the raw steps/form_data and never surfaced this, so
/// `workflowNeedsInput()` always saw an empty `placeholders` and the Run modal never opened for an
/// input-only workflow. Computing it here closes that gap (and gives the modal its fields to render).
fn compute_placeholders(steps_text: &str, form_data_text: Option<&str>) -> Vec<Value> {
    fn placeholder(key: &str) -> Value {
        // Humanize for display: drop the `input.` namespace and turn `_` into spaces.
        let label = key.strip_prefix("input.").unwrap_or(key).replace('_', " ");
        json!({ "key": key, "label": label, "field_type": Value::Null })
    }
    let mut out: Vec<Value> = Vec::new();
    let mut seen: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();

    if let Some(fd) = form_data_text.filter(|s| !s.is_empty()) {
        if let Ok(Value::Object(map)) = serde_json::from_str::<Value>(fd) {
            for k in map.keys() {
                if k.starts_with("__") || k.contains(':') {
                    continue;
                }
                if seen.insert(k.clone()) {
                    out.push(placeholder(k));
                }
            }
        }
    }
    for caps in input_placeholder_re().captures_iter(steps_text) {
        let name = &caps[1];
        if seen.insert(name.to_string()) {
            out.push(placeholder(name));
        }
    }
    out
}

/// `password`/`email`/`username` field hints anywhere in the steps TEXT — mirrors the cloud
/// `_workflow_has_login` heuristic (intentionally broad: a bare `password` word counts).
fn login_field_re() -> &'static regex::Regex {
    static RE: std::sync::OnceLock<regex::Regex> = std::sync::OnceLock::new();
    RE.get_or_init(|| {
        regex::Regex::new(
            r#"(?i)type=['"]?password|autocomplete=['"]?(current-password|new-password|username|email)|name=['"]?(password|email|username|login)|\bpassword\b|input\[type=.{0,3}password"#,
        )
        .expect("login-field regex is valid")
    })
}

/// ANY `{{secret:NAME}}` credential placeholder — a workflow that references a secret needs the run
/// modal's persona picker so the runner can attach the values, whatever the secret is NAMED. Was
/// previously limited to `password|username|email|login|user`, which silently missed custom secrets
/// like `{{secret:apikey}}` / `{{secret:groupe}}` — those workflows then opened NO modal and ran with
/// the secret unresolved. The name grammar matches the input-placeholder class (`[A-Za-z0-9_.-]`).
fn login_secret_re() -> &'static regex::Regex {
    static RE: std::sync::OnceLock<regex::Regex> = std::sync::OnceLock::new();
    RE.get_or_init(|| {
        regex::Regex::new(r"(?i)\{\{\s*secret:\s*[A-Za-z0-9_.\-]+\s*\}\}")
            .expect("login-secret regex is valid")
    })
}

/// Deterministic (no-AI) "does this workflow authenticate?" — gates the Run modal's persona picker
/// (cloud `_workflow_has_login` parity). True when the workflow carries credentials, a secret /
/// login-named declared input, a `twofa` step, a `{{secret:password|…}}` placeholder, or a
/// password/email field hint in the steps text. The daemon never surfaced this, so a login workflow
/// with NO pinned default persona never offered the picker — now it does.
fn compute_has_login(steps_text: &str, form_data_text: Option<&str>, has_credentials: bool) -> bool {
    if has_credentials {
        return true;
    }
    if let Some(fd) = form_data_text.filter(|s| !s.is_empty()) {
        if let Ok(Value::Object(map)) = serde_json::from_str::<Value>(fd) {
            for k in map.keys() {
                if k.starts_with("__secret_") {
                    return true;
                }
                if matches!(
                    k.to_ascii_lowercase().as_str(),
                    "password" | "email" | "username" | "login" | "user"
                ) {
                    return true;
                }
            }
        }
    }
    if let Ok(Value::Array(steps)) = serde_json::from_str::<Value>(steps_text) {
        if steps
            .iter()
            .any(|s| s.get("type").and_then(Value::as_str) == Some("twofa"))
        {
            return true;
        }
    }
    login_secret_re().is_match(steps_text) || login_field_re().is_match(steps_text)
}

/// Strip the sealed Layer-B secret blob before a workflow ever crosses the API boundary, replacing
/// it with a non-secret `has_credentials` boolean the UI can render without ever seeing ciphertext.
/// Also re-hydrates the JSON-TEXT columns (`steps`, `functions`, …) from their stored string form
/// into rich JSON values — symmetric with the input deserialization — so the response matches the
/// array/object shape the frontend expects, and attaches the computed `placeholders` the Run modal
/// needs (cloud-contract parity; see [`compute_placeholders`]).
///
/// Also emits `credential_keys: [String]` — the NAME-ONLY view of the encrypted credential map's
/// top-level keys — so the Run modal can determine per-name which `{{secret:X}}` references in the
/// steps are already linked (parity with the cloud, which exposes the same via the response
/// builder). VALUES ARE NEVER RETURNED — only the key names of the decrypted mapping. A decrypt
/// failure (locked vault / tampered blob) degrades to `[]` rather than failing the whole response,
/// mirroring the cloud's tolerance path (`_build_safe_form_data`).
fn redact(wf: &Workflow, vault: &Vault) -> LocalResult<Value> {
    let has_credentials = wf
        .credentials_encrypted
        .as_deref()
        .is_some_and(|s| !s.is_empty());
    // Computed BEFORE the JSON-TEXT columns are re-hydrated in place — reads the raw stored TEXT.
    let placeholders = compute_placeholders(&wf.steps, wf.form_data.as_deref());
    // Gates the Run modal's persona picker (cloud parity); see [`compute_has_login`].
    let has_login = compute_has_login(&wf.steps, wf.form_data.as_deref(), has_credentials);
    // Narrower than has_login: a step that ENTERS a one-time code. Runs need a persona
    // with a 2FA method (cloud `has_twofa` parity) — drives the Run modal's warning.
    let has_twofa = serde_json::from_str::<Value>(&wf.steps)
        .ok()
        .and_then(|v| v.as_array().map(|steps| {
            steps.iter().any(|s| s.get("type").and_then(Value::as_str) == Some("twofa"))
        }))
        .unwrap_or(false);
    let credential_keys = credential_key_names(wf, vault);
    let mut v = serde_json::to_value(wf)?;
    if let Some(obj) = v.as_object_mut() {
        obj.remove("credentials_encrypted");
        obj.insert("has_credentials".into(), json!(has_credentials));
        obj.insert("credential_keys".into(), json!(credential_keys));
        obj.insert("placeholders".into(), Value::Array(placeholders));
        obj.insert("has_login".into(), json!(has_login));
        obj.insert("has_twofa".into(), json!(has_twofa));
        // Parse each JSON-TEXT column back into rich JSON. A stored value should always be valid
        // JSON (it was serialized from JSON on the way in); if a legacy row holds non-JSON text we
        // leave the string untouched rather than fail the whole response.
        for &col in JSON_TEXT_COLS {
            if let Some(Value::String(s)) = obj.get(col) {
                if let Ok(parsed) = serde_json::from_str::<Value>(s) {
                    obj.insert(col.into(), parsed);
                }
            }
        }
    }
    Ok(v)
}

/// Names-only view of a workflow's decrypted credential map — e.g. `["api_key", "totp_seed"]`.
/// The plaintext bytes leave scope at the end of this function; only string KEYS survive. On any
/// error (locked vault, unknown magic, tamper, malformed JSON) we return `vec![]` — the frontend
/// treats an unknown set the same as "no credentials" (falls back to `has_credentials`).
fn credential_key_names(wf: &Workflow, vault: &Vault) -> Vec<String> {
    let Some(blob) = wf.credentials_encrypted.as_deref() else { return Vec::new() };
    if blob.is_empty() {
        return Vec::new();
    }
    let aad = workflows::credentials_aad(wf.id);
    let Ok(plaintext) = vault.open_field(blob, &aad) else { return Vec::new() };
    // Deserialize as a shape whose VALUES we discard immediately (`serde_json::Value` on the value
    // side would let a caller pluck them; a typed `IgnoredAny` value tells serde to skip them and
    // keep only the top-level string keys — which is exactly what we want).
    let Ok(map) = serde_json::from_slice::<BTreeMap<String, serde::de::IgnoredAny>>(&plaintext)
    else { return Vec::new() };
    map.into_keys().collect()
}

/// Seal the wizard's PLAINTEXT `credentials` map (`{name: value}`) into the workflow row's
/// `credentials_encrypted` (`WF1:` Layer-B blob), bound to the row id via [`workflows::credentials_aad`]
/// — the SAME AAD the engine opens with at run time. Empty/absent → `None` (nothing to seal, the
/// column is left untouched). The plaintext is never persisted in the clear and never logged.
///
/// The app-lock is enforced by the caller BEFORE the row is inserted, so a locked desktop can never
/// reach this seal with a half-created workflow.
fn seal_credentials(
    vault: &Vault,
    workflow_id: i64,
    creds: &BTreeMap<String, String>,
) -> LocalResult<Option<String>> {
    if creds.is_empty() {
        return Ok(None);
    }
    let plaintext = serde_json::to_vec(creds)?;
    let blob = vault.seal_field(&plaintext, &workflows::credentials_aad(workflow_id))?;
    Ok(Some(blob))
}

/// `GET /v1/workflows` — list workflows, newest first.
async fn list(
    State(st): State<AppState>,
    Query(q): Query<ListQuery>,
) -> LocalResult<Json<Value>> {
    let mut rows = workflows::list(&st.db, q.active_only, q.limit).await?;
    // Cloud parity (automation.py list_workflows): crawl workflows are Dragnet
    // machinery, not user workflows — they live on /crawls, and surfacing them here
    // would offer them everywhere a workflow can be picked (run modals, the persona
    // login-workflow dropdown) where running one is never what the user means.
    rows.retain(|wf| wf.workflow_type != "crawl");
    let items = rows.iter().map(|wf| redact(wf, &st.vault)).collect::<LocalResult<Vec<_>>>()?;
    Ok(Json(json!({ "data": items, "count": items.len() })))
}

/// Body for `POST /v1/workflows`. The insert columns are flattened in from [`NewWorkflow`]; the
/// wizard additionally sends a PLAINTEXT `credentials` map (recorded secret-fills) which is sealed
/// handler-side — never an insert column, never stored in the clear.
#[derive(Debug, Deserialize)]
struct CreateBody {
    #[serde(flatten)]
    new: NewWorkflow,
    /// Plaintext `{name: value}` credentials. Sealed into `credentials_encrypted` after insert.
    #[serde(default)]
    credentials: Option<BTreeMap<String, String>>,
}

/// `POST /v1/workflows` — create a workflow, then seal any wizard-supplied credentials onto it.
async fn create(
    State(st): State<AppState>,
    Json(body): Json<CreateBody>,
) -> LocalResult<Json<Value>> {
    if body.new.name.trim().is_empty() {
        return Err(LocalError::BadRequest("name is required".into()));
    }
    // Non-empty credentials touch the vault: enforce the app-lock BEFORE we insert, so a locked
    // desktop fails cleanly (423) instead of leaving a credential-less orphan workflow behind.
    let creds = body.credentials.filter(|m| !m.is_empty());
    if creds.is_some() {
        crate::local::vault_lock::global().guard()?;
    }

    let wf = workflows::insert(&st.db, &body.new).await?;

    let wf = if let Some(creds) = creds {
        let blob = seal_credentials(&st.vault, wf.id, &creds)?;
        workflows::update(
            &st.db,
            wf.id,
            &WorkflowUpdate { credentials_encrypted: blob, ..Default::default() },
        )
        .await?
    } else {
        wf
    };

    // A create with `cloud_callable=1` (rare, but a wizard is free to insert one already exposed)
    // needs to be advertised without waiting for a WS reconnect. The manager is a no-op when the
    // agent bridge isn't running.
    if wf.cloud_callable == 1 {
        #[cfg(feature = "cloud")]
        crate::local::cloud::agent::manager::notify_catalog_dirty().await;
    }

    Ok(Json(redact(&wf, &st.vault)?))
}

/// `GET /v1/workflows/:id` — fetch one workflow. A marketplace PROXY row (`marketplace_slug` set)
/// additionally carries the install's attach projection (see [`attach_marketplace`]) — its own
/// `steps` are `[]`, so without this the Run modal would have nothing to collect.
async fn get_one(
    State(st): State<AppState>,
    Path(id): Path<i64>,
) -> LocalResult<Json<Value>> {
    let wf = workflows::get_by_id(&st.db, id)
        .await?
        .ok_or_else(|| LocalError::NotFound(format!("workflow {id}")))?;
    #[allow(unused_mut)]
    let mut v = redact(&wf, &st.vault)?;
    #[cfg(feature = "cloud")]
    attach_marketplace(&st, &wf, &mut v).await?;
    Ok(Json(v))
}

/// Fold the marketplace attach projection into a PROXY workflow's detail response:
///   * `marketplace` — `{slug, listing_title, manifest{input/secret/persona_slots, has_login},
///     bindings{secrets, persona_id, persona_none, inputs}}` (NAMES ONLY — the loopback twin of the
///     MCP needs-input gate), or `{slug, missing: true}` when the install row is gone (orphaned
///     proxy — the UI offers a reinstall instead of a doomed run);
///   * manifest `input_slots` merged into `placeholders` (the proxy's steps are `[]`, so the
///     regular scan found none) — `workflowNeedsInput()` then opens the Run modal as usual;
///   * `has_login` forced true when the manifest wants a login/persona, so the persona picker shows.
/// No-op for regular workflows.
#[cfg(feature = "cloud")]
async fn attach_marketplace(st: &AppState, wf: &Workflow, v: &mut Value) -> LocalResult<()> {
    let Some(slug) = wf.marketplace_slug.as_deref() else {
        return Ok(());
    };
    let state = crate::local::cloud::marketplace::attach_state(&st.db, slug).await?;
    let Some(obj) = v.as_object_mut() else {
        return Ok(());
    };
    let Some(state) = state else {
        obj.insert("marketplace".into(), json!({ "slug": slug, "missing": true }));
        return Ok(());
    };
    if let Some(manifest) = state.get("manifest") {
        // Merge manifest input slots into the computed placeholders (dedup by key).
        if let Some(Value::Array(existing)) = obj.get_mut("placeholders") {
            let seen: std::collections::BTreeSet<String> = existing
                .iter()
                .filter_map(|p| p.get("key").and_then(Value::as_str).map(str::to_string))
                .collect();
            for slot in manifest
                .get("input_slots")
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
            {
                let Some(key) = slot.get("key").and_then(Value::as_str) else { continue };
                if seen.contains(key) {
                    continue;
                }
                existing.push(json!({
                    "key": key,
                    "label": slot.get("label").and_then(Value::as_str).unwrap_or(key),
                    "field_type": slot.get("field_type").cloned().unwrap_or(Value::Null),
                }));
            }
        }
        let wants_login = manifest
            .get("has_login")
            .and_then(Value::as_bool)
            .unwrap_or(false)
            || manifest
                .get("persona_slots")
                .and_then(Value::as_array)
                .is_some_and(|a| !a.is_empty());
        if wants_login {
            obj.insert("has_login".into(), json!(true));
        }
    }
    obj.insert("marketplace".into(), state);
    Ok(())
}

/// Body for `PATCH /v1/workflows/:id`. The column patch is flattened in from [`WorkflowUpdate`]; a
/// PLAINTEXT `credentials` map (when present) is sealed handler-side and overwrites the patch's
/// `credentials_encrypted` so the frontend never has to touch ciphertext.
#[derive(Debug, Deserialize)]
struct UpdateBody {
    #[serde(flatten)]
    patch: WorkflowUpdate,
    /// Plaintext `{name: value}` credentials. Sealed into `credentials_encrypted` for this row.
    #[serde(default)]
    credentials: Option<BTreeMap<String, String>>,
}

/// `PATCH /v1/workflows/:id` — sparse update (None fields untouched).
/// SAVE-time clamp: a `schedule_interval_ms` being set is floored to the workflow schedule minimum
/// (60s) via the shared `clamp` module — the SAME floor the scheduler applies at TICK — so a too-fast
/// cadence can never be persisted. A supplied plaintext `credentials` map is sealed (app-lock
/// enforced) and folded into the patch's `credentials_encrypted`.
async fn update(
    State(st): State<AppState>,
    Path(id): Path<i64>,
    Json(body): Json<UpdateBody>,
) -> LocalResult<Json<Value>> {
    let UpdateBody { mut patch, credentials } = body;
    // Deactivation is retired: a workflow can never be parked inactive via update. Only a hard
    // `DELETE` gets rid of one. Silently drop any `is_active` change so a stale client (or an
    // external `wlk_` caller) can't flip a workflow to `is_active=0` and strand its Data-explorer
    // rows. (New rows are born active via `create`; nothing legitimately toggles this field.)
    patch.is_active = None;
    if let Some(ms) = patch.schedule_interval_ms {
        patch.schedule_interval_ms = Some(crate::local::scheduler::clamp::clamp_workflow_interval_ms(Some(ms)));
    }
    if let Some(creds) = credentials.filter(|m| !m.is_empty()) {
        crate::local::vault_lock::global().guard()?;
        patch.credentials_encrypted = seal_credentials(&st.vault, id, &creds)?;
    }
    let cloud_callable_touched = patch.cloud_callable.is_some();
    let wf = workflows::update(&st.db, id, &patch).await?;
    // Poke the cloud-agent bridge to re-advertise when this update could have changed the
    // catalog: either the `cloud_callable` flag itself was set (turning ON adds it; turning OFF
    // must remove it — the backend marks catalog-absent rows `withdrawn`), OR the workflow is
    // currently `cloud_callable=1` (a rename / steps / description edit changes the advertised
    // name / recipe_hash / input_schema). No-op when the agent bridge isn't running.
    if cloud_callable_touched || wf.cloud_callable == 1 {
        #[cfg(feature = "cloud")]
        crate::local::cloud::agent::manager::notify_catalog_dirty().await;
    }
    Ok(Json(redact(&wf, &st.vault)?))
}

/// `DELETE /v1/workflows/:id` — HARD delete: the row is removed and its `runs` (and their artifacts)
/// cascade away (`ON DELETE CASCADE`). Delete is the ONLY way to get rid of a workflow — there is no
/// "deactivate"/soft-delete: a workflow is either present or gone, never parked inactive (which used
/// to strand its extracted data out of the Data explorer). Monitor/automation references to it are
/// nulled by their `ON DELETE SET NULL` foreign keys.
async fn remove(
    State(st): State<AppState>,
    Path(id): Path<i64>,
) -> LocalResult<Json<Value>> {
    // Read the row BEFORE deleting so we know whether it was `cloud_callable`. If it was, the
    // cloud is still holding it in its catalog and needs a refresh to mark it `withdrawn`; if it
    // wasn't, the catalog is unaffected and we skip the WS frame. A missing row falls through to
    // the delete's 404 below.
    let row = workflows::get_by_id(&st.db, id).await?;
    let was_cloud_callable = row.as_ref().map(|wf| wf.cloud_callable == 1).unwrap_or(false);

    // A marketplace PROXY row: deleting it from the library IS the uninstall — route through the
    // full uninstall so the `installed_workflows` row (sealed recipe + bindings) and the cloud
    // install grant go with it. Deleting only the proxy used to orphan the install row; deleting
    // only the install left a proxy that ran straight into "reinstall the listing".
    #[cfg(feature = "cloud")]
    if let Some(slug) = row.as_ref().and_then(|wf| wf.marketplace_slug.clone()) {
        let summary = crate::local::cloud::marketplace::uninstall(&st.db, &slug).await?;
        if was_cloud_callable {
            crate::local::cloud::agent::manager::notify_catalog_dirty().await;
        }
        return Ok(Json(json!({
            "id": id,
            "deleted": true,
            "uninstall": serde_json::to_value(summary)?,
        })));
    }

    let deleted = workflows::delete(&st.db, id).await?;
    if !deleted {
        return Err(LocalError::NotFound(format!("workflow {id}")));
    }
    if was_cloud_callable {
        #[cfg(feature = "cloud")]
        crate::local::cloud::agent::manager::notify_catalog_dirty().await;
    }
    Ok(Json(json!({ "id": id, "deleted": true })))
}

/// Body for `POST /v1/workflows/:id/run`. `inputs` is a free-form JSON object handed to the engine
/// (`{NAME: value}`, resolved by `engine::resolve` over `{{NAME}}`/`{{input.NAME}}`). The desktop Run
/// modal posts the user-entered values under `form_data` instead (mirroring the cloud client), so we
/// accept that as an alias: when `inputs` is absent, `form_data` IS the run inputs. Without this the
/// modal's filled-in fields were silently dropped (the engine only ever read `inputs`).
#[derive(Debug, Default, Deserialize)]
struct RunBody {
    #[serde(default)]
    inputs: Option<Value>,
    #[serde(default)]
    form_data: Option<Value>,
    /// Optional persona override (the Run modal's identity picker). Wins over the workflow's pinned
    /// `default_persona_id` for this run; absent → the workflow default is used.
    #[serde(default)]
    persona_id: Option<i64>,
    #[serde(default)]
    dry_run: bool,
    /// FILE ASSETS: the Run modal's `{ slot -> file_id }` bindings of the user's own vault files to the
    /// workflow's declared upload slots. Folded into `inputs.files` (`{ file_id -> { file_id, slots } }`)
    /// which the engine materializes from the local encrypted vault at run time. Without threading this
    /// the modal's picked files were silently dropped and upload steps failed closed.
    #[serde(default)]
    files: Option<Value>,
}

/// Query for `POST /v1/workflows/:id/run` — the caller's DELIVERY choice.
///
/// The local run API was async-only: it always answered `202 {run_id}` and left the caller to
/// stream SSE or poll. That is the right default for a UI, and the wrong one for a script, which
/// just wants the result — every SDK and shell caller had to hand-roll the same poll loop, and each
/// rolled it slightly differently.
///
/// `?wait=true` mirrors the managed gateway's contract exactly, so the same mental model holds
/// locally and in the cloud: block up to a budget, return the result inline, and on expiry answer
/// `504` with the `run_id` still valid — the run keeps going and stays observable.
#[derive(Debug, Default, Deserialize)]
struct RunQuery {
    /// Block until the run reaches a terminal state instead of returning 202.
    #[serde(default)]
    wait: Option<bool>,
    /// Seconds to block for when `wait=true`. Clamped to [1, 3600].
    #[serde(default)]
    timeout: Option<u64>,
}

/// Default/ceiling for `?wait=`. The ceiling is generous because a local run is bounded by the
/// caller's own connection, not by a shared gateway worker pool — but it is not unbounded, or a
/// wedged run would pin a daemon connection forever.
const WAIT_DEFAULT_SECS: u64 = 120;
const WAIT_MAX_SECS: u64 = 3600;
const WAIT_POLL_MS: u64 = 250;

/// Terminal run statuses, mirroring the cloud vocabulary so one set of words describes a run
/// wherever it executed.
const TERMINAL_STATUSES: [&str; 4] = ["success", "failed", "timeout", "cancelled"];

/// `POST /v1/workflows/:id/run` — start the workflow via the in-process engine (STAGE E2).
///
/// Default (`202 Accepted {run_id, status:"running"}`): the run drives in a spawned task; the caller
/// observes it by streaming `GET /v1/runs/:id/events` (live SSE) and reads the final result from
/// `GET /v1/runs/:id`. Builds a `RunRequest{source:Api, lane:Interactive}`.
///
/// With `?wait=true`: the same dispatch, then we block until the run is terminal and answer `200`
/// with the run's own result. Dispatch is deliberately UNCHANGED between the two — waiting is a
/// delivery choice made by the caller, not a different way to execute, so a run behaves identically
/// (cancellable, streamable, same registry handle) either way.
///
/// An engine without a registry (the stub) falls back to running synchronously and still returns
/// the resulting run id (via the trait's default `run_async`), so the contract holds either way.
async fn run(
    State(st): State<AppState>,
    Path(id): Path<i64>,
    Query(q): Query<RunQuery>,
    Json(body): Json<RunBody>,
) -> LocalResult<(axum::http::StatusCode, Json<Value>)> {
    // 404 early if the workflow doesn't exist, rather than letting the engine surface it.
    let wf = workflows::get_by_id(&st.db, id)
        .await?
        .ok_or_else(|| LocalError::NotFound(format!("workflow {id}")))?;
    // `inputs` wins; fall back to the modal's `form_data` alias; else an empty object.
    let mut inputs = body.inputs.or(body.form_data).unwrap_or_else(|| json!({}));

    // Fold the Run modal's `{ slot -> file_id }` bindings into `inputs.files`
    // (`{ file_id -> { file_id, slots } }`, the same shape the MCP path produces) so the engine
    // materializes each bound vault file for its upload slot.
    if let Some(files) = body.files.as_ref().and_then(|v| v.as_object()) {
        let mut by_file: std::collections::HashMap<String, Vec<String>> = std::collections::HashMap::new();
        for (slot, fid) in files {
            if let Some(fid) = fid.as_str().map(str::trim).filter(|s| !s.is_empty()) {
                by_file.entry(fid.to_string()).or_default().push(slot.clone());
            }
        }
        if !by_file.is_empty() {
            let mut files_map = serde_json::Map::new();
            for (fid, slots) in by_file {
                files_map.insert(fid.clone(), json!({ "file_id": fid, "slots": slots }));
            }
            if !inputs.is_object() {
                inputs = json!({});
            }
            if let Some(obj) = inputs.as_object_mut() {
                obj.insert("files".into(), Value::Object(files_map));
            }
        }
    }

    // CR-4: `dry_run` is a VALIDATE-ONLY path — it MUST NOT launch a browser or execute any
    // side-effecting step (no clicks/fills/submits/purchases). The engine's run path has no
    // dry-run mode, so we short-circuit HERE: parse + validate the step plan and return it with
    // `200 OK` so a caller can preview what would run without anything actually happening.
    if body.dry_run {
        return Ok((axum::http::StatusCode::OK, Json(dry_run_plan(&wf, &inputs)?)));
    }

    let req = RunRequest {
        workflow_id: id,
        inputs,
        source: RunSource::Api,
        lane: Lane::Interactive,
        dry_run: body.dry_run,
        persona_id: body.persona_id,
        // A user's own saved workflow resolves its own local vault/file refs (TB-2 opt-out applies
        // only to ad-hoc cloud-authored recipes, not to this named-workflow run path).
        allow_local_secret_refs: true,
    };
    let started = st.engine.run_async(req).await?;

    if !q.wait.unwrap_or(false) {
        return Ok((
            axum::http::StatusCode::ACCEPTED,
            Json(json!({ "run_id": started.run_id, "status": "running" })),
        ));
    }

    // ── wait=true: block until the run is terminal, or the budget expires ──
    // Poll the persisted row rather than subscribing to the registry: the row is the authoritative
    // terminal record (the stub engine has no registry at all, and a run that finished between
    // dispatch and here would never emit another event to subscribe to).
    let budget = std::time::Duration::from_secs(
        q.timeout.unwrap_or(WAIT_DEFAULT_SECS).clamp(1, WAIT_MAX_SECS),
    );
    let deadline = std::time::Instant::now() + budget;
    loop {
        if let Some(run) = crate::local::store::runs::get_by_id(&st.db, started.run_id).await? {
            if TERMINAL_STATUSES.contains(&run.status.as_str()) {
                // `result_data` is stored as a JSON TEXT column; hand back parsed JSON so a caller
                // never has to double-decode. Unparseable content degrades to the raw string rather
                // than failing a run that actually succeeded.
                let data = run.result_data.as_deref().map(|raw| {
                    serde_json::from_str::<Value>(raw).unwrap_or_else(|_| Value::String(raw.into()))
                });
                let mut out = json!({
                    "run_id": started.run_id,
                    "status": run.status,
                    "done": true,
                });
                if let Some(obj) = out.as_object_mut() {
                    if let Some(data) = data {
                        obj.insert("data".into(), data);
                    }
                    if let Some(err) = run.error_message.clone() {
                        obj.insert("error".into(), Value::String(err));
                    }
                    if let Some(ms) = run.duration_ms {
                        obj.insert("duration_ms".into(), json!(ms));
                    }
                }
                // 200 even for a FAILED run: the request succeeded in reporting the outcome. A
                // caller distinguishes them by `status`, exactly as it does when polling
                // `GET /v1/runs/:id` — failing the HTTP call here would conflate "your run failed"
                // with "your call was rejected".
                return Ok((axum::http::StatusCode::OK, Json(out)));
            }
        }
        if std::time::Instant::now() >= deadline {
            // The run is still going and stays fully observable — 504 carries the id so the caller
            // collects rather than re-runs. Mirrors the cloud gateway's timeout response.
            return Ok((
                axum::http::StatusCode::GATEWAY_TIMEOUT,
                Json(json!({
                    "run_id": started.run_id,
                    "status": "running",
                    "done": false,
                    "error": format!(
                        "Run did not finish within {}s and is still in progress",
                        budget.as_secs()
                    ),
                    "events_url": format!("/v1/runs/{}/events", started.run_id),
                    "status_url": format!("/v1/runs/{}", started.run_id),
                })),
            ));
        }
        tokio::time::sleep(std::time::Duration::from_millis(WAIT_POLL_MS)).await;
    }
}

/// CR-4: build the VALIDATE-ONLY dry-run result for a workflow. Parses the recorded steps (folding
/// `{{vault:KEY}}`→`{{secret:KEY}}` first so the plan reflects what the executor would see), reports
/// the ordered step plan (index / type / enabled / whether it references secrets) and the run inputs
/// that were supplied — WITHOUT resolving any secret VALUE, launching a browser, or running a step.
///
/// A non-empty but UNPARSEABLE `steps` blob is a hard `400` (a creator-category error): an empty run
/// is only legitimate when the steps really are an empty array, never when the JSON is corrupt.
fn dry_run_plan(wf: &Workflow, inputs: &Value) -> LocalResult<Value> {
    // Normalize the secret spelling exactly as the run path does, so the plan is faithful.
    let steps_text = crate::local::engine::normalize_vault_aliases(&wf.steps);
    let trimmed = steps_text.trim();
    let raw_steps: Vec<Value> = if trimmed.is_empty() || trimmed == "[]" {
        Vec::new()
    } else {
        serde_json::from_str(&steps_text).map_err(|e| {
            LocalError::BadRequest(format!("workflow steps are not valid JSON: {e}"))
        })?
    };

    let plan: Vec<Value> = raw_steps
        .iter()
        .enumerate()
        .map(|(i, s)| {
            let step_type = s.get("type").and_then(|v| v.as_str()).unwrap_or("");
            let enabled = s.get("enabled").and_then(|v| v.as_bool()).unwrap_or(true);
            // Whether this step text references any secret placeholder (name only — never a value).
            let references_secret = serde_json::to_string(s)
                .map(|t| t.contains("{{secret:"))
                .unwrap_or(false);
            json!({
                "index": i,
                "type": step_type,
                "enabled": enabled,
                "references_secret": references_secret,
            })
        })
        .collect();

    // The distinct secret KEY NAMES the plan would need (names only — dry-run never reads values).
    let required_secrets: Vec<String> =
        crate::local::engine::scan_secret_keys(&steps_text).into_iter().collect();
    let input_names: Vec<String> = inputs
        .as_object()
        .map(|o| o.keys().cloned().collect())
        .unwrap_or_default();

    Ok(json!({
        "dry_run": true,
        "workflow_id": wf.id,
        "step_count": plan.len(),
        "steps": plan,
        "required_secrets": required_secrets,
        "provided_inputs": input_names,
        "entry_url": wf.entry_url,
    }))
}

/// `POST /v1/workflows/:id/cancel` — cancel the most recent LIVE run of this workflow (STAGE E2).
/// Resolves the workflow's newest `running` run row, then signals its cancellation token via the
/// engine registry; the execute loop aborts between steps and finalizes the run as `cancelled`.
///
/// Returns `202 {run_id, status:"cancel_requested"}` when a live run was signalled, or
/// `409 Conflict {status:"not_running"}` when the workflow has no in-flight, cancellable run.
async fn cancel(
    State(st): State<AppState>,
    Path(id): Path<i64>,
) -> LocalResult<(axum::http::StatusCode, Json<Value>)> {
    if workflows::get_by_id(&st.db, id).await?.is_none() {
        return Err(LocalError::NotFound(format!("workflow {id}")));
    }
    // Newest in-flight run for this workflow (the one a user would mean by "cancel").
    let running = workflows_latest_running_run(&st, id).await?;
    let run_id = match running {
        Some(r) => r,
        None => {
            return Ok((
                axum::http::StatusCode::CONFLICT,
                Json(json!({ "id": id, "status": "not_running" })),
            ))
        }
    };
    match st.engine.cancel(run_id) {
        Some(_) => Ok((
            axum::http::StatusCode::ACCEPTED,
            Json(json!({ "id": id, "run_id": run_id, "status": "cancel_requested" })),
        )),
        // The run row says running but the engine has no live handle (e.g. a stub/sync engine, or a
        // crash-orphaned row). Nothing live to signal.
        None => Ok((
            axum::http::StatusCode::CONFLICT,
            Json(json!({ "id": id, "run_id": run_id, "status": "not_running" })),
        )),
    }
}

/// Newest `running` run id for a workflow, or `None`. Scopes the cancel to a single in-flight run.
async fn workflows_latest_running_run(st: &AppState, workflow_id: i64) -> LocalResult<Option<i64>> {
    let rows = crate::local::store::runs::list_by_workflow(&st.db, workflow_id, 50).await?;
    Ok(rows.into_iter().find(|r| r.status == "running").map(|r| r.id))
}

#[cfg(test)]
mod dry_run_tests {
    use super::dry_run_plan;
    use crate::local::store::workflows::{self, NewWorkflow};
    use crate::local::{db, vault};

    async fn insert_wf(steps: Option<&str>) -> workflows::Workflow {
        let dir = Box::leak(Box::new(tempfile::tempdir().unwrap()));
        let v = vault::Vault::load_or_create(dir.path(), false).unwrap();
        let pool = db::open(&dir.path().join("t.db"), &v.db_key_hex()).await.unwrap();
        workflows::insert(
            &pool,
            &NewWorkflow {
                name: "dry".into(),
                steps: steps.map(str::to_string),
                entry_url: Some("https://example.com".into()),
                ..Default::default()
            },
        )
        .await
        .unwrap()
    }

    /// CR-4: a dry run returns the parsed step PLAN (no execution — this is a pure builder that never
    /// touches a browser) and enumerates required secrets by NAME only, never a value.
    #[tokio::test]
    async fn dry_run_returns_plan_without_executing() {
        let steps = r##"[
            {"type":"navigate","enabled":true,"config":{"url":"{{input.u}}"}},
            {"type":"fill","enabled":false,"config":{"value":"{{secret:PW}}"}},
            {"type":"click","config":{"selector":"#go"}}
        ]"##;
        let wf = insert_wf(Some(steps)).await;
        let plan = dry_run_plan(&wf, &serde_json::json!({ "u": "https://x" })).unwrap();

        assert_eq!(plan["dry_run"], true);
        assert_eq!(plan["step_count"], 3);
        // The disabled step is reported (with its enabled flag), not silently dropped.
        assert_eq!(plan["steps"][1]["type"], "fill");
        assert_eq!(plan["steps"][1]["enabled"], false);
        assert_eq!(plan["steps"][1]["references_secret"], true);
        // Secret NAME surfaces; the value is never read/returned.
        assert_eq!(plan["required_secrets"][0], "PW");
        let dumped = plan.to_string();
        assert!(!dumped.contains("value") || !dumped.contains("secret-value"));
    }

    /// An empty step array is a legitimate (trivially successful) dry run — no error.
    #[tokio::test]
    async fn dry_run_empty_steps_is_ok() {
        let wf = insert_wf(Some("[]")).await;
        let plan = dry_run_plan(&wf, &serde_json::json!({})).unwrap();
        assert_eq!(plan["step_count"], 0);
    }

    /// CR-4 / LOW: a non-empty but UNPARSEABLE steps blob is a 400 error, NOT a silent empty run.
    #[tokio::test]
    async fn dry_run_unparseable_steps_is_error() {
        let wf = insert_wf(Some("{not valid json")).await;
        let err = dry_run_plan(&wf, &serde_json::json!({})).unwrap_err();
        assert!(
            matches!(err, crate::local::error::LocalError::BadRequest(_)),
            "unparseable steps must be a BadRequest, got {err:?}"
        );
    }
}

#[cfg(test)]
mod placeholder_tests {
    use super::{compute_has_login, compute_placeholders};

    fn keys(v: &[serde_json::Value]) -> Vec<String> {
        v.iter().map(|p| p["key"].as_str().unwrap().to_string()).collect()
    }

    #[test]
    fn scans_bare_and_input_refs_excluding_secrets_and_files() {
        // `r##…##` delimiters: `#`-prefixed CSS selectors contain a `"#` that would close `r#"…"#`.
        let steps = r##"[
            {"type":"navigate","config":{"url":"{{input.target_url}}"}},
            {"type":"fill","config":{"selector":"#u","value":"{{ username }}"}},
            {"type":"fill","config":{"selector":"#p","value":"{{secret:login_password}}"}},
            {"type":"upload","config":{"value":"{{file:resume}}"}},
            {"type":"fill","config":{"value":"{{vault:token}}"}}
        ]"##;
        let got = compute_placeholders(steps, None);
        // Bare and input. forms surface; secret/vault/file namespaces never do.
        assert_eq!(keys(&got), vec!["input.target_url".to_string(), "username".to_string()]);
        // `input.` is stripped for the human label.
        assert_eq!(got[0]["label"], "target url");
    }

    #[test]
    fn form_data_keys_first_then_steps_skipping_reserved() {
        let steps = r#"[{"type":"fill","config":{"value":"{{city}}"}}]"#;
        let form_data = r#"{"country":"FR","__secret_pw":"x","ns:k":"y"}"#;
        let got = compute_placeholders(steps, Some(form_data));
        // Declared form_data key first; `__…` and namespaced `a:b` keys excluded; step ref appended.
        assert_eq!(keys(&got), vec!["country".to_string(), "city".to_string()]);
    }

    #[test]
    fn empty_when_no_inputs() {
        let steps = r##"[{"type":"click","config":{"selector":"#go"}}]"##;
        assert!(compute_placeholders(steps, Some("{}")).is_empty());
        assert!(compute_placeholders("not json", None).is_empty());
    }

    #[test]
    fn has_login_detects_auth_signals_and_ignores_plain_workflows() {
        // has_credentials short-circuits true.
        assert!(compute_has_login("[]", None, true));
        // A `{{secret:password}}` placeholder.
        let s = r#"[{"type":"fill","config":{"value":"{{secret:password}}"}}]"#;
        assert!(compute_has_login(s, None, false));
        // A `twofa` step.
        let s = r#"[{"type":"twofa","config":{}}]"#;
        assert!(compute_has_login(s, None, false));
        // A login-named declared input / a `__secret_` key.
        assert!(compute_has_login("[]", Some(r#"{"username":""}"#), false));
        assert!(compute_has_login("[]", Some(r#"{"__secret_pw":""}"#), false));
        // A password field hint in a selector.
        let s = r##"[{"type":"fill","config":{"selector":"input[type=password]"}}]"##;
        assert!(compute_has_login(s, None, false));
        // A plain, non-authenticating workflow.
        let s = r##"[{"type":"click","config":{"selector":"#go"}},{"type":"fill","config":{"value":"{{city}}"}}]"##;
        assert!(!compute_has_login(s, Some(r#"{"city":"Paris"}"#), false));
    }
}
