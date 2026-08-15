//! `/v1/personas` REST handlers — the desktop persona surface, wire-compatible with the cloud
//! the cloud backend's `personas` router shapes the desktop UI (`PersonaWizard` / `PersonaList` /
//! `PersonaDetailPane` / `AuthenticatorImportModal`) was written against:
//!
//!   GET    /v1/personas                          list (`?domain=` suffix suggestion, `?limit=`)
//!   POST   /v1/personas                          create — PLAINTEXT wizard payload, sealed HERE
//!   GET    /v1/personas/:id                      one persona
//!   PATCH  /v1/personas/:id                      partial update (cloud replace semantics on secrets)
//!   DELETE /v1/personas/:id                      hard delete
//!   POST   /v1/personas/:id/test-2fa             mint-smoke-test (TOTP local; email/SMS cloud-gated)
//!   GET    /v1/personas/:id/runs                 recent runs that acted as this persona
//!   POST   /v1/personas/validate-totp            base32 + optional code check (never stored)
//!   POST   /v1/personas/import/authenticator/parse   preview an authenticator export (secret-free)
//!   POST   /v1/personas/import/authenticator/commit  create TOTP personas from staged entries
//!
//! ## Secret hygiene (load-bearing)
//! Callers POST PLAINTEXT credentials (`password`, `extra_login_fields`, `totp_seed`, `proxy_*`) —
//! the HANDLER seals them with the keyring-rooted `Vault` into the row-bound Layer-B blobs the run
//! engine opens (`engine::persona::persona_aad`, `personas|<column>|<id>`), so the store only ever
//! holds ciphertext. Because the AAD binds the ROW ID, create INSERTS first (non-secret fields),
//! then seals + patches; a seal failure rolls the row back. No `*_encrypted` column, plaintext
//! secret, or TOTP seed is EVER echoed in a response — every response is shaped through `shape()`
//! (`has_*` booleans + `linked_secrets` NAMES only, cloud `PersonaResponse` parity).
//!
//! House style: thin handlers over the store, `LocalResult<Json<_>>` with `?` propagation, no auth
//! layer here (server.rs applies the loopback bearer + Origin/Host guard at the router level).

use std::collections::HashMap;

use crate::local::authenticator_import as authimport;
use crate::local::engine::persona::{persona_aad, AAD_CREDENTIALS, AAD_PROXY, AAD_TOTP_SEED};
use crate::local::error::{LocalError, LocalResult};
use crate::local::server::AppState;
use crate::local::store::personas::{self, NewPersona, Persona, PersonaUpdate};
use crate::local::store::{runs, workflows};
use crate::local::vault::Vault;
use axum::extract::{Path, Query, State};
use axum::routing::{get, post};
use axum::{Json, Router};
use serde::{Deserialize, Deserializer};
use serde_json::{json, Map, Value};

/// Default page size for the list endpoint when `?limit=` is omitted.
const DEFAULT_LIMIT: i64 = 100;
/// Hard cap so a client cannot ask for an unbounded scan.
const MAX_LIMIT: i64 = 500;
/// The 2FA methods a persona can carry (cloud parity).
const TWOFA_METHODS: [&str; 4] = ["none", "totp", "email_otp", "sms"];
/// The email-OTP delivery modes (cloud parity; locally only informational — reading runs in cloud).
const EMAIL_OTP_MODES: [&str; 2] = ["oauth_mailbox", "relay"];

/// Mount the persona routes onto the shared `AppState` router. Auth is applied by `server.rs`.
pub fn router() -> Router<AppState> {
    Router::new()
        .route("/v1/personas", get(list).post(create))
        .route("/v1/personas/validate-totp", post(validate_totp))
        .route("/v1/personas/import/authenticator/parse", post(import_parse))
        .route("/v1/personas/import/authenticator/commit", post(import_commit))
        .route("/v1/personas/:id", get(get_one).patch(update_one).delete(remove))
        .route("/v1/personas/:id/test-2fa", post(test_twofa))
        .route("/v1/personas/:id/sign-in", post(sign_in))
        .route("/v1/personas/:id/runs", get(persona_runs))
}

/// App-lock guard for the secret-touching routes (mirrors `secrets::guard_unlocked`): when the
/// vault app-lock is engaged and LOCKED these return 423 until `/v1/vault/unlock`.
fn guard_unlocked() -> LocalResult<()> {
    crate::local::vault_lock::global().guard()
}

// ---------------------------------------------------------------------------
// Write payload (create + update share one DTO — the wizard's cloud-shaped body)
// ---------------------------------------------------------------------------

/// serde helper distinguishing an ABSENT field (`None` — leave as-is) from an explicit JSON `null`
/// (`Some(None)` — clear). Plain `Option<T>` folds both into `None`, which would make "unpin the
/// fingerprint" indistinguishable from "didn't touch it".
fn double_option<'de, T, D>(de: D) -> Result<Option<Option<T>>, D::Error>
where
    T: Deserialize<'de>,
    D: Deserializer<'de>,
{
    Option::<T>::deserialize(de).map(Some)
}

/// The wizard's write payload. Plaintext secrets (`password`, `extra_login_fields`, `totp_seed`,
/// `proxy_*`) are sealed by the handler and NEVER stored or echoed raw. Unknown (cloud-only) fields
/// like `mail_connection_id` / `preferred_agent_id` are ignored by serde.
#[derive(Debug, Default, Deserialize)]
struct PersonaWrite {
    #[serde(default)]
    name: Option<String>,
    #[serde(default, deserialize_with = "double_option")]
    description: Option<Option<String>>,
    #[serde(default, deserialize_with = "double_option")]
    target_domain: Option<Option<String>>,
    /// Literal username, `{{vault:key.username}}` ref, or explicit null to clear.
    #[serde(default, deserialize_with = "double_option")]
    login_username: Option<Option<String>>,
    /// Plaintext password or `{{vault:key.password}}` ref. With cloud replace semantics: sending
    /// `password`/`extra_login_fields` REPLACES the whole stored credential set; empty → cleared.
    #[serde(default)]
    password: Option<String>,
    #[serde(default)]
    extra_login_fields: Option<HashMap<String, String>>,
    #[serde(default)]
    twofa_method: Option<String>,
    /// Plaintext base32 seed. Empty string on update clears the stored seed.
    #[serde(default)]
    totp_seed: Option<String>,
    #[serde(default)]
    totp_digits: Option<i64>,
    #[serde(default)]
    totp_period_seconds: Option<i64>,
    #[serde(default)]
    totp_algorithm: Option<String>,
    #[serde(default)]
    email_otp_mode: Option<String>,
    #[serde(default)]
    relay_address: Option<String>,
    /// Email-OTP extraction hints (object) — stored as JSON-TEXT.
    #[serde(default)]
    otp_extract_config: Option<Value>,
    /// `{user_agent, locale, timezone}` object to pin; explicit null unpins.
    #[serde(default, deserialize_with = "double_option")]
    fingerprint: Option<Option<Value>>,
    /// BYO proxy: non-empty sets (requires `proxy_lawful_use_ack`), empty string clears.
    #[serde(default)]
    proxy_server: Option<String>,
    #[serde(default)]
    proxy_username: Option<String>,
    #[serde(default)]
    proxy_password: Option<String>,
    #[serde(default)]
    proxy_lawful_use_ack: Option<bool>,
    #[serde(default)]
    is_active: Option<bool>,
    /// Workflow that SIGNS THIS PERSONA IN. Double-option: absent = untouched,
    /// explicit null = DETACH (the persona can no longer self-login).
    #[serde(default, deserialize_with = "double_option")]
    login_workflow_id: Option<Option<i64>>,
}

impl PersonaWrite {
    /// Cloud `_validate_twofa` parity: reject unknown method / email-OTP-mode strings.
    fn validate_twofa(&self) -> LocalResult<()> {
        if let Some(m) = self.twofa_method.as_deref() {
            if !TWOFA_METHODS.contains(&m) {
                return Err(LocalError::BadRequest(format!(
                    "twofa_method must be one of {TWOFA_METHODS:?}"
                )));
            }
        }
        if let Some(m) = self.email_otp_mode.as_deref() {
            if !EMAIL_OTP_MODES.contains(&m) {
                return Err(LocalError::BadRequest(format!(
                    "email_otp_mode must be one of {EMAIL_OTP_MODES:?}"
                )));
            }
        }
        Ok(())
    }

    /// The cleaned TOTP seed to store, when one was sent: `Some("")` = explicit clear (update),
    /// `Some(seed)` = validated base32. A present-but-invalid seed is a 400 — storing it would only
    /// fail later, mid-login, at the 2FA step.
    fn cleaned_totp_seed(&self) -> LocalResult<Option<String>> {
        let Some(raw) = self.totp_seed.as_deref() else { return Ok(None) };
        match authimport::normalize_base32(raw) {
            Some(seed) => Ok(Some(seed)),
            None if raw.trim().is_empty() => Ok(Some(String::new())),
            None => Err(LocalError::BadRequest(
                "totp_seed is not valid base32 — paste the secret from the site's authenticator setup".into(),
            )),
        }
    }

    /// The fingerprint JSON-TEXT to store: `None` = untouched, `Some("")` = unpin (explicit null),
    /// `Some(json)` = pin. Must be a JSON object (the engine parses `{user_agent,locale,timezone}`).
    fn fingerprint_text(&self) -> LocalResult<Option<String>> {
        match &self.fingerprint {
            None => Ok(None),
            Some(None) => Ok(Some(String::new())),
            Some(Some(v)) if v.is_object() => Ok(Some(v.to_string())),
            Some(Some(_)) => Err(LocalError::BadRequest("fingerprint must be a JSON object".into())),
        }
    }

    /// The otp_extract_config JSON-TEXT to store (`None` = untouched; null clears; object stored).
    fn otp_extract_text(&self) -> LocalResult<Option<String>> {
        match &self.otp_extract_config {
            None => Ok(None),
            Some(Value::Null) => Ok(Some(String::new())),
            Some(v) if v.is_object() => Ok(Some(v.to_string())),
            Some(_) => Err(LocalError::BadRequest("otp_extract_config must be a JSON object".into())),
        }
    }

    /// Seal the secret-bearing fields into a row-bound patch. `replace_creds`/`replace_proxy`
    /// implement the cloud semantics: secrets are only overwritten when explicitly provided, and
    /// an explicitly-empty value CLEARS (stored as `''`, which every reader treats as absent —
    /// the COALESCE-based store update cannot write NULL).
    fn seal_secrets(&self, vault: &Vault, id: i64) -> LocalResult<PersonaUpdate> {
        let mut patch = PersonaUpdate::default();

        // Login credentials: a flat `{name -> value}` map, password under "password" (the exact
        // shape `engine::persona::resolve_from_row` opens). Sending either field replaces the SET.
        if self.password.is_some() || self.extra_login_fields.is_some() {
            let mut creds: Map<String, Value> = Map::new();
            for (k, v) in self.extra_login_fields.iter().flatten() {
                if !k.trim().is_empty() && !v.is_empty() {
                    creds.insert(k.trim().to_string(), json!(v));
                }
            }
            if let Some(pw) = self.password.as_deref().filter(|p| !p.is_empty()) {
                creds.insert("password".to_string(), json!(pw));
            }
            patch.credentials_encrypted = if creds.is_empty() {
                Some(String::new()) // cleared
            } else {
                let plain = serde_json::to_vec(&Value::Object(creds))?;
                Some(vault.seal_field(&plain, &persona_aad(AAD_CREDENTIALS, id))?)
            };
        }

        // TOTP seed (already validated by `cleaned_totp_seed`).
        if let Some(seed) = self.cleaned_totp_seed()? {
            patch.totp_seed_encrypted = if seed.is_empty() {
                Some(String::new()) // cleared
            } else {
                Some(vault.seal_field(seed.as_bytes(), &persona_aad(AAD_TOTP_SEED, id))?)
            };
        }

        // BYO proxy: `{server, username, password}` (the shape `resolve_from_row` parses).
        if let Some(server) = self.proxy_server.as_deref().map(str::trim) {
            patch.proxy_config_encrypted = if server.is_empty() {
                Some(String::new()) // explicit clear
            } else {
                if self.proxy_lawful_use_ack != Some(true) {
                    return Err(LocalError::BadRequest(
                        "Configuring a residential proxy requires acknowledging lawful use (proxy_lawful_use_ack=true).".into(),
                    ));
                }
                let cfg = json!({
                    "server": server,
                    "username": self.proxy_username.as_deref().map(str::trim).filter(|s| !s.is_empty()),
                    "password": self.proxy_password.as_deref().filter(|s| !s.is_empty()),
                });
                Some(vault.seal_field(&serde_json::to_vec(&cfg)?, &persona_aad(AAD_PROXY, id))?)
            };
        }

        Ok(patch)
    }
}

/// Collapse a double-option to the store's COALESCE patch encoding: absent → `None` (keep),
/// explicit null → `Some("")` (cleared — readers treat empty as absent), value → `Some(trimmed)`.
fn tri(field: &Option<Option<String>>) -> Option<String> {
    match field {
        None => None,
        Some(None) => Some(String::new()),
        Some(Some(s)) => Some(s.trim().to_string()),
    }
}

// ---------------------------------------------------------------------------
// Response shaping — cloud `PersonaResponse` parity, secrets reduced to has_* + linked names
// ---------------------------------------------------------------------------

/// Non-empty check for the cleared-as-`''` columns.
fn has(col: &Option<String>) -> bool {
    col.as_deref().is_some_and(|s| !s.is_empty())
}

/// `{credential_field -> vault secret BASE name}` for values stored as `{{vault:...}}` templates.
/// Opens the sealed credential blob (values are scanned, then dropped) — exposes only NAMES, never
/// values. Fail-soft: a locked vault / undecryptable blob yields `{}` so list/get never 500 here.
fn linked_secrets(vault: &Vault, p: &Persona) -> Map<String, Value> {
    static RE: std::sync::OnceLock<regex::Regex> = std::sync::OnceLock::new();
    let re = RE.get_or_init(|| {
        regex::Regex::new(r"\{\{vault:([A-Za-z_][A-Za-z0-9_.\-]*)\}\}").expect("vault-ref regex is valid")
    });
    let base_name = |r: &str| r.rsplit_once('.').map(|(b, _)| b.to_string()).unwrap_or_else(|| r.to_string());

    let mut refs = Map::new();
    // The username lives on the plaintext column, not in the sealed blob.
    if let Some(u) = p.login_username.as_deref() {
        if let Some(c) = re.captures(u) {
            refs.insert("username".to_string(), json!(base_name(&c[1])));
        }
    }
    if let Some(blob) = p.credentials_encrypted.as_deref().filter(|s| !s.is_empty()) {
        if let Ok(plain) = vault.open_field(blob, &persona_aad(AAD_CREDENTIALS, p.id)) {
            if let Ok(Value::Object(map)) = serde_json::from_slice::<Value>(&plain) {
                for (k, v) in map {
                    if let Some(s) = v.as_str() {
                        if let Some(c) = re.captures(s) {
                            refs.insert(k, json!(base_name(&c[1])));
                        }
                    }
                }
            }
        }
    }
    refs
}

/// Shape one persona row into the cloud `PersonaResponse` wire form the desktop UI reads. Secrets
/// collapse to `has_*` booleans + `linked_secrets` names; cloud-only columns (mailbox, relay
/// minting, preferred agent) are `null` locally. NEVER includes a `*_encrypted` column.
fn shape(vault: &Vault, p: &Persona, linked_workflows: &[Value], login_workflow_name: Option<&str>) -> Value {
    // A vault-linked username is stored as a `{{vault:...}}` template — never surface the raw ref
    // (linked_secrets carries the link instead).
    let display_username = p
        .login_username
        .as_deref()
        .filter(|u| !u.is_empty() && !u.contains("{{vault:"));
    json!({
        "id": p.id,
        "name": p.name,
        "description": p.description.as_deref().filter(|s| !s.is_empty()),
        "target_domain": p.target_domain.as_deref().filter(|s| !s.is_empty()),
        "login_username": display_username,
        "has_password": has(&p.credentials_encrypted),
        "twofa_method": p.twofa_method,
        "has_totp_seed": has(&p.totp_seed_encrypted),
        "email_otp_mode": p.email_otp_mode.as_deref().filter(|s| !s.is_empty()),
        "mail_connection_id": Value::Null,
        "connected_mailbox": Value::Null,
        "relay_address": p.relay_address.as_deref().filter(|s| !s.is_empty()),
        "relay_token": Value::Null,
        "relay_inbound_address": Value::Null,
        "relay_inbound_url": Value::Null,
        "has_fingerprint": has(&p.fingerprint),
        "preferred_agent_id": Value::Null,
        "has_proxy": has(&p.proxy_config_encrypted),
        "proxy_lawful_use_ack_at": Value::Null,
        "is_active": p.is_active != 0,
        "validation_status": p.validation_status,
        "has_warm_session": has(&p.session_state_encrypted),
        "session_expires_at": p.expires_at,
        "last_login_at": p.last_login_at,
        "last_used_at": p.last_used_at,
        "created_at": p.created_at,
        "updated_at": p.updated_at,
        "linked_workflows": linked_workflows,
        "linked_secrets": linked_secrets(vault, p),
        "login_workflow_id": p.login_workflow_id,
        "login_workflow_name": login_workflow_name,
        "last_login_error": p.last_login_error.as_deref().filter(|s| !s.is_empty()),
        // True when the persona can sign ITSELF in — the UI gates its "needs setup"
        // state on this, not on has_warm_session (a point-in-time fact).
        "can_self_login": p.login_workflow_id.is_some(),
    })
}

/// Batch `{workflow_id -> name}` for the personas' LOGIN workflows (display only).
async fn login_workflow_names(
    db: &sqlx::SqlitePool,
    rows: &[Persona],
) -> LocalResult<HashMap<i64, String>> {
    let mut map = HashMap::new();
    for wid in rows.iter().filter_map(|p| p.login_workflow_id) {
        if let std::collections::hash_map::Entry::Vacant(e) = map.entry(wid) {
            if let Some(wf) = workflows::get_by_id(db, wid).await? {
                e.insert(wf.name);
            }
        }
    }
    Ok(map)
}

/// The login workflow must exist and must not be crawl machinery: a crawl workflow is
/// not a recorded sign-in, and a persona whose "login" is a crawl would re-enter the
/// very path that asked for the login.
async fn assert_login_workflow_valid(db: &sqlx::SqlitePool, workflow_id: i64) -> LocalResult<()> {
    let wf = workflows::get_by_id(db, workflow_id)
        .await?
        .ok_or_else(|| LocalError::NotFound(format!("login workflow {workflow_id}")))?;
    if wf.workflow_type == "crawl" {
        return Err(LocalError::BadRequest(
            "A crawl workflow can't be used as a login workflow. Record or pick the              workflow that signs the account in."
                .into(),
        ));
    }
    Ok(())
}

/// Batch `{persona_id -> [{id, name}]}` for every workflow with a default persona (one query).
async fn workflow_links(db: &sqlx::SqlitePool) -> LocalResult<HashMap<i64, Vec<Value>>> {
    let mut map: HashMap<i64, Vec<Value>> = HashMap::new();
    for (pid, wid, wname) in workflows::persona_links(db).await? {
        map.entry(pid).or_default().push(json!({ "id": wid, "name": wname }));
    }
    Ok(map)
}

// ---------------------------------------------------------------------------
// CRUD
// ---------------------------------------------------------------------------

#[derive(Debug, Default, Deserialize)]
struct ListQuery {
    limit: Option<i64>,
    /// Suggest-by-domain (the wizard): keep personas with no domain, the same domain, or whose
    /// domain the requested host is a subdomain of (cloud suffix semantics).
    domain: Option<String>,
}

impl ListQuery {
    fn limit(&self) -> i64 {
        self.limit.unwrap_or(DEFAULT_LIMIT).clamp(1, MAX_LIMIT)
    }
}

/// `GET /v1/personas` — newest-first list, capped by `?limit`, optionally filtered by `?domain=`.
async fn list(State(st): State<AppState>, Query(q): Query<ListQuery>) -> LocalResult<Json<Value>> {
    let mut rows = personas::list(&st.db, Some(q.limit())).await?;
    if let Some(domain) = q.domain.as_deref().map(|d| d.trim().to_lowercase()) {
        let d = domain.trim_start_matches('.').to_string();
        if !d.is_empty() {
            rows.retain(|p| match p.target_domain.as_deref().map(|t| t.trim_start_matches('.').to_lowercase()) {
                None => true,
                Some(td) if td.is_empty() => true,
                Some(td) => d == td || d.ends_with(&format!(".{td}")),
            });
        }
    }
    let links = workflow_links(&st.db).await?;
    let login_names = login_workflow_names(&st.db, &rows).await?;
    let empty: Vec<Value> = Vec::new();
    let items: Vec<Value> = rows
        .iter()
        .map(|p| {
            let lw = p.login_workflow_id.and_then(|w| login_names.get(&w)).map(String::as_str);
            shape(&st.vault, p, links.get(&p.id).unwrap_or(&empty), lw)
        })
        .collect();
    Ok(Json(json!({ "data": items, "count": items.len() })))
}

/// `POST /v1/personas` — create from the wizard's PLAINTEXT payload; secrets sealed here.
///
/// The sealing AAD binds the row id, so we insert the non-secret fields first, then seal + patch.
/// A failure after insert deletes the row again — no half-created persona survives.
async fn create(State(st): State<AppState>, Json(body): Json<PersonaWrite>) -> LocalResult<Json<Value>> {
    guard_unlocked()?;
    let name = body.name.as_deref().map(str::trim).unwrap_or("").to_string();
    if name.is_empty() {
        return Err(LocalError::BadRequest("name is required".into()));
    }
    body.validate_twofa()?;
    // Fail every validation BEFORE the insert (seed, fingerprint, proxy ack), so rollback is rare.
    body.cleaned_totp_seed()?;
    let fingerprint = body.fingerprint_text()?;
    let otp_extract = body.otp_extract_text()?;
    if body.proxy_server.as_deref().is_some_and(|s| !s.trim().is_empty())
        && body.proxy_lawful_use_ack != Some(true)
    {
        return Err(LocalError::BadRequest(
            "Configuring a residential proxy requires acknowledging lawful use (proxy_lawful_use_ack=true).".into(),
        ));
    }
    if personas::get_by_name(&st.db, &name).await?.is_some() {
        return Err(LocalError::BadRequest(format!("Persona '{name}' already exists")));
    }
    let login_workflow_id = match &body.login_workflow_id {
        Some(Some(wid)) => {
            assert_login_workflow_valid(&st.db, *wid).await?;
            Some(*wid)
        }
        _ => None,
    };

    let new = NewPersona {
        name,
        description: tri(&body.description).filter(|s| !s.is_empty()),
        target_domain: tri(&body.target_domain).filter(|s| !s.is_empty()),
        login_username: tri(&body.login_username).filter(|s| !s.is_empty()),
        twofa_method: body.twofa_method.clone(),
        totp_digits: body.totp_digits,
        totp_period_seconds: body.totp_period_seconds,
        totp_algorithm: body.totp_algorithm.clone(),
        email_otp_mode: body.email_otp_mode.clone(),
        relay_address: body.relay_address.clone(),
        otp_extract_config: otp_extract.filter(|s| !s.is_empty()),
        fingerprint: fingerprint.filter(|s| !s.is_empty()),
        login_workflow_id,
        ..Default::default()
    };
    let row = personas::insert(&st.db, &new).await?;

    // Seal the secret blobs bound to the new row id; roll the row back on any failure.
    let sealed = match body.seal_secrets(&st.vault, row.id) {
        Ok(patch) => patch,
        Err(e) => {
            let _ = personas::delete(&st.db, row.id).await;
            return Err(e);
        }
    };
    let row = match personas::update(&st.db, row.id, &sealed).await {
        Ok(Some(updated)) => updated,
        Ok(None) => return Err(LocalError::Internal("persona vanished during create".into())),
        Err(e) => {
            let _ = personas::delete(&st.db, row.id).await;
            return Err(e);
        }
    };

    let login_names = login_workflow_names(&st.db, std::slice::from_ref(&row)).await?;
    let lw = row.login_workflow_id.and_then(|w| login_names.get(&w)).map(String::as_str);
    Ok(Json(shape(&st.vault, &row, &[], lw)))
}

/// `GET /v1/personas/:id` — one persona (shaped) or 404.
async fn get_one(State(st): State<AppState>, Path(id): Path<i64>) -> LocalResult<Json<Value>> {
    let p = personas::get_by_id(&st.db, id)
        .await?
        .ok_or_else(|| LocalError::NotFound(format!("persona {id}")))?;
    let links = workflow_links(&st.db).await?;
    let login_names = login_workflow_names(&st.db, std::slice::from_ref(&p)).await?;
    let lw = p.login_workflow_id.and_then(|w| login_names.get(&w)).map(String::as_str);
    let empty: Vec<Value> = Vec::new();
    Ok(Json(shape(&st.vault, &p, links.get(&p.id).unwrap_or(&empty), lw)))
}

/// `PATCH /v1/personas/:id` — partial update. Cloud semantics: simple fields patch individually;
/// secrets are REPLACED only when explicitly provided (`password`/`extra_login_fields` replace the
/// whole credential set; empty `totp_seed`/`proxy_server` clear their blobs).
async fn update_one(
    State(st): State<AppState>,
    Path(id): Path<i64>,
    Json(body): Json<PersonaWrite>,
) -> LocalResult<Json<Value>> {
    guard_unlocked()?;
    let existing = personas::get_by_id(&st.db, id)
        .await?
        .ok_or_else(|| LocalError::NotFound(format!("persona {id}")))?;
    body.validate_twofa()?;

    // A renamed persona must not collide with another row (name is UNIQUE).
    let name = body.name.as_deref().map(str::trim).filter(|s| !s.is_empty()).map(str::to_string);
    if let Some(n) = &name {
        if *n != existing.name && personas::get_by_name(&st.db, n).await?.is_some() {
            return Err(LocalError::BadRequest(format!("Persona '{n}' already exists")));
        }
    }

    let mut patch = body.seal_secrets(&st.vault, id)?;
    patch.name = name;
    patch.description = tri(&body.description);
    patch.target_domain = tri(&body.target_domain);
    patch.login_username = tri(&body.login_username);
    patch.twofa_method = body.twofa_method.clone();
    patch.totp_digits = body.totp_digits;
    patch.totp_period_seconds = body.totp_period_seconds;
    patch.totp_algorithm = body.totp_algorithm.clone();
    patch.email_otp_mode = body.email_otp_mode.clone();
    patch.relay_address = body.relay_address.clone();
    patch.otp_extract_config = body.otp_extract_text()?;
    patch.fingerprint = body.fingerprint_text()?;
    patch.is_active = body.is_active.map(i64::from);

    let row = personas::update(&st.db, id, &patch)
        .await?
        .ok_or_else(|| LocalError::NotFound(format!("persona {id}")))?;

    // Login workflow: absent = untouched; explicit null = DETACH; a value must
    // exist and not be crawl machinery. A dedicated setter because the
    // COALESCE-based update above cannot write NULL.
    let row = match &body.login_workflow_id {
        None => row,
        Some(next) => {
            if let Some(wid) = next {
                assert_login_workflow_valid(&st.db, *wid).await?;
            }
            personas::set_login_workflow(&st.db, id, *next)
                .await?
                .ok_or_else(|| LocalError::NotFound(format!("persona {id}")))?
        }
    };

    let links = workflow_links(&st.db).await?;
    let login_names = login_workflow_names(&st.db, std::slice::from_ref(&row)).await?;
    let lw = row.login_workflow_id.and_then(|w| login_names.get(&w)).map(String::as_str);
    let empty: Vec<Value> = Vec::new();
    Ok(Json(shape(&st.vault, &row, links.get(&row.id).unwrap_or(&empty), lw)))
}

/// `DELETE /v1/personas/:id` — hard-delete. 404 if absent.
async fn remove(State(st): State<AppState>, Path(id): Path<i64>) -> LocalResult<Json<Value>> {
    let removed = personas::delete(&st.db, id).await?;
    if !removed {
        return Err(LocalError::NotFound(format!("persona {id}")));
    }
    Ok(Json(json!({ "id": id, "deleted": true })))
}

// ---------------------------------------------------------------------------
// Sign-in — run the persona's login workflow to establish its warm session
// ---------------------------------------------------------------------------

#[derive(Debug, Default, Deserialize)]
struct SignInBody {
    /// Re-run the login even when the current session still looks usable ("Sign in
    /// now": a session that merely LOOKS live but the site has invalidated is the
    /// exact case the button exists for).
    #[serde(default)]
    force: bool,
}

/// `POST /v1/personas/:id/sign-in` — run this persona's login workflow to establish
/// (or refresh) its warm session. Cloud wire parity (`PersonaSignInResponse`).
///
/// Login FAILURES resolve `ok:false` with a human-actionable `error` (the UI renders
/// it inline next to the button); only an unknown persona is a real 404.
async fn sign_in(
    State(st): State<AppState>,
    Path(id): Path<i64>,
    body: Option<Json<SignInBody>>,
) -> LocalResult<Json<Value>> {
    guard_unlocked()?;
    personas::get_by_id(&st.db, id)
        .await?
        .ok_or_else(|| LocalError::NotFound(format!("persona {id}")))?;

    let force = body.map(|Json(b)| b.force).unwrap_or(false);
    let outcome = crate::local::persona_login::ensure_fresh_session(&st, id, force).await;

    // Re-read: the sign-in wrote the captured session / last_login_* from the engine
    // side, so the pre-dispatch row is stale by construction.
    let p = personas::get_by_id(&st.db, id)
        .await?
        .ok_or_else(|| LocalError::NotFound(format!("persona {id}")))?;
    Ok(Json(json!({
        "ok": outcome.ok,
        "error": outcome.error,
        "has_warm_session": has(&p.session_state_encrypted),
        "session_expires_at": p.expires_at,
    })))
}

// ---------------------------------------------------------------------------
// 2FA smoke test + seed validation
// ---------------------------------------------------------------------------

/// `POST /v1/personas/:id/test-2fa` — confirm the persona can mint a 2FA value. Does NOT return
/// the code. TOTP mints fully on-device; email/SMS OTP reading is a cloud capability, so those
/// answer with the cloud-gate message instead of pretending to test.
async fn test_twofa(State(st): State<AppState>, Path(id): Path<i64>) -> LocalResult<Json<Value>> {
    guard_unlocked()?;
    let p = personas::get_by_id(&st.db, id)
        .await?
        .ok_or_else(|| LocalError::NotFound(format!("persona {id}")))?;
    match p.twofa_method.as_str() {
        "none" => Ok(Json(json!({ "ok": true, "method": "none", "message": "No 2FA configured" }))),
        "totp" => {
            let minted = crate::local::engine::persona::mint_current_totp(&st.db, &st.vault, id)
                .await
                .map_err(|e| LocalError::BadRequest(format!("2FA test failed: {e}")))?;
            if minted.is_none() {
                return Err(LocalError::BadRequest(
                    "2FA test failed: no TOTP secret is stored for this persona".into(),
                ));
            }
            Ok(Json(json!({ "ok": true, "method": "totp", "kind": "totp" })))
        }
        other => Err(LocalError::BadRequest(format!(
            "Reading {other} codes runs in Writ Cloud — this desktop can only test TOTP locally"
        ))),
    }
}

#[derive(Debug, Deserialize)]
struct ValidateTotpBody {
    totp_seed: String,
    #[serde(default)]
    code: Option<String>,
    #[serde(default)]
    algorithm: Option<String>,
    #[serde(default)]
    digits: Option<i64>,
    #[serde(default)]
    period: Option<i64>,
}

/// `POST /v1/personas/validate-totp` — confirm a pasted seed is well-formed base32 and (optionally)
/// that it reproduces a code the user just saw. Never stores or logs the seed/code.
async fn validate_totp(Json(body): Json<ValidateTotpBody>) -> LocalResult<Json<Value>> {
    let digits = body.digits.unwrap_or(6).clamp(6, 10) as u32;
    let period = body.period.unwrap_or(30).max(1) as u64;
    let algorithm = body.algorithm.as_deref().unwrap_or("SHA1");

    let seed = authimport::normalize_base32(&body.totp_seed);
    let valid = seed.is_some();

    let matches_code: Value = match (seed, body.code.as_deref().map(str::trim).filter(|c| !c.is_empty())) {
        (Some(seed), Some(code)) => {
            // valid_window=1 parity with the cloud: tolerate one time-step of clock skew.
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0);
            let mut matched = false;
            for t in [now.saturating_sub(period), now, now + period] {
                if let Ok(expected) = Vault::mint_totp_at(&seed, digits, period, algorithm, t) {
                    if expected == code {
                        matched = true;
                        break;
                    }
                }
            }
            json!(matched)
        }
        _ => Value::Null,
    };

    Ok(Json(json!({ "valid_base32": valid, "matches_code": matches_code })))
}

// ---------------------------------------------------------------------------
// Persona runs
// ---------------------------------------------------------------------------

#[derive(Debug, Default, Deserialize)]
struct RunsQuery {
    limit: Option<i64>,
}

/// `GET /v1/personas/:id/runs` — recent runs that acted as this persona (via the workflows whose
/// `default_persona_id` is this persona). Cloud `PersonaRun` wire shape.
async fn persona_runs(
    State(st): State<AppState>,
    Path(id): Path<i64>,
    Query(q): Query<RunsQuery>,
) -> LocalResult<Json<Value>> {
    if personas::get_by_id(&st.db, id).await?.is_none() {
        return Err(LocalError::NotFound(format!("persona {id}")));
    }
    let rows = runs::list_by_default_persona(&st.db, id, q.limit.unwrap_or(20)).await?;
    let items: Vec<Value> = rows
        .iter()
        .map(|r| {
            json!({
                "task_id": r.id,
                "workflow_id": r.workflow_id,
                "workflow_name": r.workflow_name,
                "status": r.status,
                "success": r.success.map(|v| v != 0),
                "started_at": r.started_at,
                "completed_at": r.completed_at,
                "error": r.error_message.as_deref().map(|e| e.chars().take(200).collect::<String>()),
            })
        })
        .collect();
    Ok(Json(json!({ "data": items, "count": items.len() })))
}

// ---------------------------------------------------------------------------
// Authenticator import (parse → preview → commit), cloud wire shapes
// ---------------------------------------------------------------------------

#[derive(Debug, Default, Deserialize)]
struct ImportParseBody {
    #[serde(default)]
    otpauth_uris: Option<Vec<String>>,
    #[serde(default)]
    migration_payload: Option<String>,
}

/// `POST /v1/personas/import/authenticator/parse` — parse an authenticator export into a
/// secret-free preview + a short-lived single-use token (seeds stay daemon-side only).
async fn import_parse(Json(body): Json<ImportParseBody>) -> LocalResult<Json<Value>> {
    guard_unlocked()?;
    let uris = body.otpauth_uris.unwrap_or_default();
    if uris.iter().all(|u| u.trim().is_empty())
        && body.migration_payload.as_deref().map(str::trim).unwrap_or("").is_empty()
    {
        return Err(LocalError::BadRequest("Provide otpauth_uris and/or a migration_payload".into()));
    }
    let entries = authimport::parse_payloads(&uris, body.migration_payload.as_deref())
        .map_err(|e| LocalError::BadRequest(format!("Could not read the authenticator import: {e}")))?;
    let previews: Vec<Value> = entries.iter().enumerate().map(|(i, e)| e.preview(i)).collect();
    let count = entries.len();
    let token = authimport::stage_entries(entries);
    tracing::info!(accounts = count, "authenticator import parsed");
    Ok(Json(json!({ "import_token": token, "count": count, "entries": previews })))
}

#[derive(Debug, Deserialize)]
struct ImportSelection {
    idx: i64,
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    target_domain: Option<String>,
    #[serde(default)]
    login_username: Option<String>,
}

#[derive(Debug, Deserialize)]
struct ImportCommitBody {
    import_token: String,
    selections: Vec<ImportSelection>,
}

/// `POST /v1/personas/import/authenticator/commit` — create one TOTP persona per user-selected
/// account from a staged import. Seeds are vault-sealed per created row; the token is burned.
async fn import_commit(State(st): State<AppState>, Json(body): Json<ImportCommitBody>) -> LocalResult<Json<Value>> {
    guard_unlocked()?;
    let entries = authimport::load_staged(&body.import_token).ok_or_else(|| {
        LocalError::NotFound("Import session expired or not found — re-run the import".into())
    })?;
    if body.selections.is_empty() {
        return Err(LocalError::BadRequest("No accounts selected to import".into()));
    }

    // Names are UNIQUE — collect existing + freshly-assigned names and auto-suffix collisions so
    // nothing is silently lost.
    let mut taken: std::collections::HashSet<String> = personas::list(&st.db, Some(MAX_LIMIT))
        .await?
        .into_iter()
        .map(|p| p.name.to_lowercase())
        .collect();

    let mut created: Vec<Value> = Vec::new();
    let mut skipped: Vec<Value> = Vec::new();
    for sel in &body.selections {
        let Some(entry) = usize::try_from(sel.idx).ok().and_then(|i| entries.get(i)) else {
            skipped.push(json!({ "idx": sel.idx, "reason": "invalid index" }));
            continue;
        };
        let base_name = sel
            .name
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(str::to_string)
            .unwrap_or_else(|| authimport::suggested_name(entry.issuer.as_deref(), entry.label.as_deref()));
        let base_name: String = base_name.chars().take(120).collect();
        let name = unique_name(&base_name, &taken);
        taken.insert(name.to_lowercase());
        let domain = sel
            .target_domain
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(str::to_string)
            .or_else(|| authimport::guess_domain(entry.issuer.as_deref(), entry.label.as_deref()));

        let row = personas::insert(
            &st.db,
            &NewPersona {
                name,
                target_domain: domain,
                login_username: sel.login_username.as_deref().map(str::trim).filter(|s| !s.is_empty()).map(str::to_string),
                twofa_method: Some("totp".into()),
                totp_digits: Some(entry.digits),
                totp_period_seconds: Some(entry.period),
                totp_algorithm: Some(entry.algorithm.clone()),
                ..Default::default()
            },
        )
        .await?;

        // Seal the seed bound to the new row; a seal failure rolls this row back and skips it.
        let sealed = st
            .vault
            .seal_field(entry.secret.as_bytes(), &persona_aad(AAD_TOTP_SEED, row.id))
            .map(|blob| PersonaUpdate { totp_seed_encrypted: Some(blob), ..Default::default() });
        match sealed {
            Ok(patch) => match personas::update(&st.db, row.id, &patch).await {
                Ok(Some(updated)) => created.push(shape(&st.vault, &updated, &[], None)),
                Ok(None) | Err(_) => {
                    let _ = personas::delete(&st.db, row.id).await;
                    skipped.push(json!({ "idx": sel.idx, "reason": "could not store the seed" }));
                }
            },
            Err(_) => {
                let _ = personas::delete(&st.db, row.id).await;
                skipped.push(json!({ "idx": sel.idx, "reason": "could not seal the seed" }));
            }
        }
    }

    if created.is_empty() {
        return Err(LocalError::BadRequest("No valid accounts to import".into()));
    }
    // Single-use: burn the staged seeds so the same import can't be replayed.
    authimport::consume_staged(&body.import_token);
    tracing::info!(created = created.len(), skipped = skipped.len(), "authenticator import committed");
    Ok(Json(json!({ "created": created, "skipped": skipped })))
}

/// Return `base`, or `base (2)`, `base (3)`… avoiding names already taken (case-insensitive).
/// Keeps the result within the cloud's 120-char name budget.
fn unique_name(base: &str, taken: &std::collections::HashSet<String>) -> String {
    let base = if base.is_empty() { "Imported account" } else { base };
    if !taken.contains(&base.to_lowercase()) {
        return base.to_string();
    }
    for i in 2..1000 {
        let suffix = format!(" ({i})");
        let budget = 120usize.saturating_sub(suffix.chars().count());
        let candidate = format!("{}{suffix}", base.chars().take(budget).collect::<String>());
        if !taken.contains(&candidate.to_lowercase()) {
            return candidate;
        }
    }
    format!("{} (x)", base.chars().take(116).collect::<String>())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::local::engine::persona::resolve_persona;
    use crate::local::engine::StubEngine;
    use std::sync::Arc;

    /// A plaintext-in / ciphertext-at-rest fixture: an `AppState` over a fresh SQLCipher DB keyed by
    /// a headless (no-keyring) vault (mirrors `secrets::tests::fixture`).
    async fn fixture() -> (AppState, Arc<Vault>) {
        let dir = Box::leak(Box::new(tempfile::tempdir().unwrap()));
        let vault = Arc::new(Vault::load_or_create(dir.path(), false).unwrap());
        let pool = crate::local::db::open(&dir.path().join("t.db"), &vault.db_key_hex())
            .await
            .unwrap();
        let st = AppState {
            db: pool,
            vault: vault.clone(),
            engine: Arc::new(StubEngine),
            config: crate::local::config::LocalConfig::default(),
            token: Arc::new("wlt_test".to_string()),
            health: crate::local::app::health::DaemonHealth::shared(),
            recorder: None,
        };
        (st, vault)
    }

    /// Deserialize a JSON body exactly as axum would — exercises the double_option absent/null split.
    fn write_body(v: Value) -> Json<PersonaWrite> {
        Json(serde_json::from_value(v).expect("test body deserializes"))
    }

    const SEED: &str = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";

    /// The wizard's REAL create payload — object fingerprint, plaintext password/extras/seed. This
    /// is the exact request that used to 422 (fingerprint object vs `Option<String>`) and, had it
    /// passed, would have silently dropped every credential.
    #[tokio::test]
    async fn create_accepts_wizard_payload_seals_secrets_and_runs_resolve() {
        let (st, vault) = fixture().await;
        let resp = create(
            State(st.clone()),
            write_body(json!({
                "name": "Shop login",
                "description": "main account",
                "target_domain": "shop.example.com",
                "login_username": "me@example.com",
                "password": "hunter2-PLAIN",
                "extra_login_fields": { "store_id": "st_42" },
                "twofa_method": "totp",
                "totp_seed": SEED,
                "totp_digits": 6,
                "totp_period_seconds": 30,
                "totp_algorithm": "SHA1",
                "fingerprint": { "user_agent": "UA/1", "locale": "en-US", "timezone": "UTC" }
            })),
        )
        .await
        .unwrap()
        .0;

        // Cloud-shaped response: booleans + names, never secret material.
        assert_eq!(resp["name"], "Shop login");
        assert_eq!(resp["has_password"], true);
        assert_eq!(resp["has_totp_seed"], true);
        assert_eq!(resp["has_fingerprint"], true);
        assert_eq!(resp["is_active"], true);
        assert_eq!(resp["login_username"], "me@example.com");
        let leaked = resp.to_string();
        assert!(!leaked.contains("hunter2-PLAIN") && !leaked.contains(SEED), "response must not leak secrets");

        // At rest: ciphertext only.
        let id = resp["id"].as_i64().unwrap();
        let row = personas::get_by_id(&st.db, id).await.unwrap().unwrap();
        let row_json = serde_json::to_string(&row).unwrap();
        assert!(!row_json.contains("hunter2-PLAIN") && !row_json.contains(SEED), "plaintext must never be stored");
        assert!(row.credentials_encrypted.as_deref().unwrap().starts_with("WF1:"));

        // The run engine opens exactly what we sealed: password + extras + a minted TOTP code.
        let resolved = resolve_persona(&st.db, &vault, id).await.unwrap().unwrap();
        assert_eq!(resolved.credentials.get("username").map(String::as_str), Some("me@example.com"));
        assert_eq!(resolved.credentials.get("password").map(String::as_str), Some("hunter2-PLAIN"));
        assert_eq!(resolved.credentials.get("store_id").map(String::as_str), Some("st_42"));
        assert_eq!(resolved.fingerprint.as_ref().unwrap().user_agent, "UA/1");
        assert_eq!(resolved.totp_code.as_ref().unwrap().len(), 6);
    }

    #[tokio::test]
    async fn create_validates_name_seed_and_duplicate() {
        let (st, _vault) = fixture().await;
        assert!(create(State(st.clone()), write_body(json!({ "name": "  " }))).await.is_err());
        assert!(
            create(State(st.clone()), write_body(json!({ "name": "p", "totp_seed": "not base32!!" })))
                .await
                .is_err(),
            "an invalid seed is rejected up-front"
        );
        let _ = create(State(st.clone()), write_body(json!({ "name": "dup" }))).await.unwrap();
        assert!(create(State(st.clone()), write_body(json!({ "name": "dup" }))).await.is_err());
        // The failed duplicate/seed attempts must not have left half-created rows behind.
        assert_eq!(personas::list(&st.db, None).await.unwrap().len(), 1);
    }

    /// Cloud replace/clear semantics on PATCH: untouched secrets persist; `password:""` (with the
    /// creds channel present) clears the set; `fingerprint:null` unpins; absent fields stay.
    #[tokio::test]
    async fn update_replaces_and_clears_like_the_cloud() {
        let (st, vault) = fixture().await;
        let created = create(
            State(st.clone()),
            write_body(json!({
                "name": "p1",
                "password": "old-pass",
                "fingerprint": { "user_agent": "UA/1", "locale": "en-US", "timezone": "UTC" }
            })),
        )
        .await
        .unwrap()
        .0;
        let id = created["id"].as_i64().unwrap();

        // A rename-only PATCH (no secret fields) leaves the credentials + fingerprint intact.
        let resp = update_one(State(st.clone()), Path(id), write_body(json!({ "name": "p1-renamed" })))
            .await
            .unwrap()
            .0;
        assert_eq!(resp["name"], "p1-renamed");
        assert_eq!(resp["has_password"], true);
        assert_eq!(resp["has_fingerprint"], true);
        let resolved = resolve_persona(&st.db, &vault, id).await.unwrap().unwrap();
        assert_eq!(resolved.credentials.get("password").map(String::as_str), Some("old-pass"));

        // Clearing: password "" replaces the credential set with nothing; fingerprint null unpins;
        // is_active false round-trips as a boolean.
        let resp = update_one(
            State(st.clone()),
            Path(id),
            write_body(json!({ "password": "", "fingerprint": null, "is_active": false })),
        )
        .await
        .unwrap()
        .0;
        assert_eq!(resp["has_password"], false);
        assert_eq!(resp["has_fingerprint"], false);
        assert_eq!(resp["is_active"], false);
        let resolved = resolve_persona(&st.db, &vault, id).await.unwrap().unwrap();
        assert!(resolved.credentials.is_empty());
        assert!(resolved.fingerprint.is_none());
    }

    /// A vault-linked login: the stored value is the `{{vault:...}}` template; the response hides
    /// the raw ref and reports the link by NAME in `linked_secrets` (the wizard's edit prefill).
    #[tokio::test]
    async fn linked_login_surfaces_names_not_refs() {
        let (st, _vault) = fixture().await;
        let resp = create(
            State(st.clone()),
            write_body(json!({
                "name": "linked",
                "login_username": "{{vault:shop_login.username}}",
                "password": "{{vault:shop_login.password}}"
            })),
        )
        .await
        .unwrap()
        .0;
        assert_eq!(resp["login_username"], Value::Null, "raw vault refs are never surfaced");
        assert_eq!(resp["linked_secrets"]["username"], "shop_login");
        assert_eq!(resp["linked_secrets"]["password"], "shop_login");
    }

    #[tokio::test]
    async fn test_twofa_totp_locally_and_gates_email_to_cloud() {
        let (st, _vault) = fixture().await;
        let none = create(State(st.clone()), write_body(json!({ "name": "none" }))).await.unwrap().0;
        let totp = create(
            State(st.clone()),
            write_body(json!({ "name": "totp", "twofa_method": "totp", "totp_seed": SEED })),
        )
        .await
        .unwrap()
        .0;
        let email = create(
            State(st.clone()),
            write_body(json!({ "name": "email", "twofa_method": "email_otp", "email_otp_mode": "relay" })),
        )
        .await
        .unwrap()
        .0;

        let r = test_twofa(State(st.clone()), Path(none["id"].as_i64().unwrap())).await.unwrap().0;
        assert_eq!((r["ok"].as_bool(), r["method"].as_str()), (Some(true), Some("none")));
        let r = test_twofa(State(st.clone()), Path(totp["id"].as_i64().unwrap())).await.unwrap().0;
        assert_eq!((r["ok"].as_bool(), r["method"].as_str()), (Some(true), Some("totp")));
        assert!(
            test_twofa(State(st.clone()), Path(email["id"].as_i64().unwrap())).await.is_err(),
            "email OTP reading is cloud-gated on desktop"
        );
    }

    #[tokio::test]
    async fn validate_totp_checks_base32_and_code() {
        let bad = validate_totp(Json(serde_json::from_value(json!({ "totp_seed": "!!" })).unwrap()))
            .await
            .unwrap()
            .0;
        assert_eq!(bad["valid_base32"], false);
        assert_eq!(bad["matches_code"], Value::Null);

        let code = Vault::mint_totp(SEED, 6, 30, "SHA1").unwrap();
        let ok = validate_totp(Json(
            serde_json::from_value(json!({ "totp_seed": SEED, "code": code })).unwrap(),
        ))
        .await
        .unwrap()
        .0;
        assert_eq!(ok["valid_base32"], true);
        assert_eq!(ok["matches_code"], true);
    }

    /// Import roundtrip through the HANDLERS: parse → secret-free preview + token → commit creates
    /// sealed TOTP personas (auto-suffixing a name collision), and the token burns after commit.
    #[tokio::test]
    async fn authenticator_import_parse_then_commit() {
        let (st, vault) = fixture().await;
        // Occupy the suggested name so commit has to suffix.
        let _ = create(State(st.clone()), write_body(json!({ "name": "GitHub — octocat" }))).await.unwrap();

        let uri = format!("otpauth://totp/GitHub:octocat?secret={SEED}&issuer=GitHub");
        let parsed = import_parse(Json(
            serde_json::from_value(json!({ "otpauth_uris": [uri] })).unwrap(),
        ))
        .await
        .unwrap()
        .0;
        assert_eq!(parsed["count"], 1);
        assert!(!parsed.to_string().contains(SEED), "preview must be secret-free");
        let token = parsed["import_token"].as_str().unwrap().to_string();

        let committed = import_commit(
            State(st.clone()),
            Json(serde_json::from_value(json!({
                "import_token": token,
                "selections": [{ "idx": 0 }, { "idx": 99 }]
            }))
            .unwrap()),
        )
        .await
        .unwrap()
        .0;
        let created = committed["created"].as_array().unwrap();
        assert_eq!(created.len(), 1);
        assert_eq!(created[0]["name"], "GitHub — octocat (2)", "collision auto-suffixes");
        assert_eq!(created[0]["twofa_method"], "totp");
        assert_eq!(created[0]["has_totp_seed"], true);
        assert_eq!(committed["skipped"].as_array().unwrap().len(), 1);

        // The created persona mints codes (seed sealed with the right row AAD).
        let id = created[0]["id"].as_i64().unwrap();
        let resolved = resolve_persona(&st.db, &vault, id).await.unwrap().unwrap();
        assert_eq!(resolved.totp_code.unwrap().len(), 6);

        // Single-use: the same token can't commit twice.
        assert!(import_commit(
            State(st.clone()),
            Json(serde_json::from_value(json!({
                "import_token": parsed["import_token"],
                "selections": [{ "idx": 0 }]
            }))
            .unwrap()),
        )
        .await
        .is_err());
    }

    #[tokio::test]
    async fn list_filters_by_domain_suffix() {
        let (st, _vault) = fixture().await;
        let _ = create(State(st.clone()), write_body(json!({ "name": "any" }))).await.unwrap();
        let _ = create(State(st.clone()), write_body(json!({ "name": "shop", "target_domain": "shop.io" })))
            .await
            .unwrap();
        let _ = create(State(st.clone()), write_body(json!({ "name": "other", "target_domain": "other.io" })))
            .await
            .unwrap();

        let all = list(State(st.clone()), Query(ListQuery::default())).await.unwrap().0;
        assert_eq!(all["count"], 3);
        let filtered = list(
            State(st.clone()),
            Query(ListQuery { domain: Some("www.shop.io".into()), ..Default::default() }),
        )
        .await
        .unwrap()
        .0;
        let names: Vec<&str> = filtered["data"]
            .as_array()
            .unwrap()
            .iter()
            .map(|p| p["name"].as_str().unwrap())
            .collect();
        assert_eq!(names.len(), 2, "domain-less personas + suffix matches remain");
        assert!(names.contains(&"any") && names.contains(&"shop"));
    }

    /// The persona-login surface: attach/detach via PATCH (double-option), refusal to
    /// attach a crawl workflow, response wire fields, and the sign-in preconditions
    /// (no login workflow → actionable ok:false, never a 500).
    #[tokio::test]
    async fn login_workflow_attach_detach_and_signin_preconditions() {
        let (st, _vault) = fixture().await;

        // A real (non-crawl) workflow to attach, and a crawl workflow that must be refused.
        let wf = workflows::insert(
            &st.db,
            &workflows::NewWorkflow {
                name: "Acme login".into(),
                workflow_type: Some("recorded".into()),
                steps: Some("[]".into()),
                ..Default::default()
            },
        )
        .await
        .unwrap();
        let crawl_wf = workflows::insert(
            &st.db,
            &workflows::NewWorkflow {
                name: "Dragnet: acme.test".into(),
                workflow_type: Some("crawl".into()),
                steps: Some("[]".into()),
                ..Default::default()
            },
        )
        .await
        .unwrap();

        // Create WITH a login workflow.
        let created = create(
            State(st.clone()),
            write_body(json!({ "name": "Acme", "login_workflow_id": wf.id })),
        )
        .await
        .unwrap();
        let id = created.0["id"].as_i64().unwrap();
        assert_eq!(created.0["login_workflow_id"].as_i64(), Some(wf.id));
        assert_eq!(created.0["login_workflow_name"].as_str(), Some("Acme login"));
        assert_eq!(created.0["can_self_login"], Value::Bool(true));

        // A crawl workflow is refused as a login workflow.
        let err = update_one(
            State(st.clone()),
            Path(id),
            write_body(json!({ "login_workflow_id": crawl_wf.id })),
        )
        .await
        .expect_err("crawl workflow must be refused");
        assert!(format!("{err:?}").contains("crawl workflow"), "{err:?}");

        // Explicit null DETACHES; an unrelated PATCH leaves the link alone.
        let untouched = update_one(
            State(st.clone()),
            Path(id),
            write_body(json!({ "description": "still attached" })),
        )
        .await
        .unwrap();
        assert_eq!(untouched.0["login_workflow_id"].as_i64(), Some(wf.id));
        let detached = update_one(
            State(st.clone()),
            Path(id),
            write_body(json!({ "login_workflow_id": null })),
        )
        .await
        .unwrap();
        assert_eq!(detached.0["login_workflow_id"], Value::Null);
        assert_eq!(detached.0["can_self_login"], Value::Bool(false));

        // Sign-in with NO login workflow: ok:false with an actionable error — a login
        // outcome, not an HTTP error.
        let res = sign_in(State(st.clone()), Path(id), Some(Json(SignInBody { force: false })))
            .await
            .unwrap();
        assert_eq!(res.0["ok"], Value::Bool(false));
        assert!(res.0["error"].as_str().unwrap().contains("login workflow"));

        // Deleting the login workflow leaves the persona (SET NULL), not a broken row.
        let reattached = update_one(
            State(st.clone()),
            Path(id),
            write_body(json!({ "login_workflow_id": wf.id })),
        )
        .await
        .unwrap();
        assert_eq!(reattached.0["login_workflow_id"].as_i64(), Some(wf.id));
        workflows::delete(&st.db, wf.id).await.unwrap();
        let after = get_one(State(st.clone()), Path(id)).await.unwrap();
        assert_eq!(after.0["login_workflow_id"], Value::Null, "FK is SET NULL");
    }
}

