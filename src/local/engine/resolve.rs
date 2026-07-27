//! Run-reference resolution for a local run — STAGE E1, part (1).
//!
//! A recorded step config carries `{{...}}` placeholders that must be filled in BEFORE the step
//! runs. This module performs a single combined pass that produces the two maps the per-step
//! executor consumes (`automation::step_executor::execute_step(.., credentials, form_data, ..)`):
//!
//!   - **`form_data`** (the NON-secret channel) — caller-supplied run `inputs` overlaid on the
//!     workflow's stored `form_data`, keyed so the executor's `{{input.NAME}}` and bare `{{NAME}}`
//!     placeholders both resolve.
//!   - **`credentials`** (the SECRET channel) — the workflow's own decrypted `credentials_encrypted`
//!     blob, plus any `vault_secrets` referenced by `{{secret:KEY}}` / `{{vault:KEY}}`, keyed by
//!     `KEY`. Persona credentials are merged on top by the engine (see [`super::persona`]).
//!
//! `{{file:slot}}` markers are deliberately LEFT in place — the file layer (`automation::files`)
//! resolves those to local temp paths during step execution; resolving them here would be wrong.
//!
//! ## Placeholder grammar & precedence
//! The executor's `util::value_resolver` resolves, in order: `{{file:slot}}` → `{{secret:KEY}}`
//! → `{{NAME}}` (the literal text inside the braces). To make that resolution see every supported
//! reference we:
//!   1. normalize `{{vault:KEY}}` → `{{secret:KEY}}` in the steps TEXT (token rename only — no
//!      secret value is ever substituted into the steps), so both spellings hit the credential
//!      channel; and
//!   2. populate the maps so:
//!      - `{{input.NAME}}`: from run `inputs[NAME]`, FALLING BACK to stored `form_data[NAME]`
//!        (inputs WIN). Inserted under both `input.NAME` (canonical) and bare `NAME` (so an older
//!        recipe that wrote `{{NAME}}` still resolves).
//!      - `{{NAME}}`: stored `form_data[NAME]`, overridden by an input of the same name.
//!      - `{{secret:KEY}}` / `{{vault:KEY}}`: from `vault_secrets[KEY]` (decrypted) merged over the
//!        workflow's `credentials_encrypted` blob (the workflow blob wins on a key collision — it is
//!        the recipe author's pinned value).
//!      - `{{secret:KEY.field}}` / `{{vault:KEY.field}}`: a single field of a JSON secret — a
//!        credential pair's `username`/`password` or a card's `number`/`expiry`/… (parity with the
//!        cloud `{{vault:name.field}}` form). Resolves `vault_secrets[KEY]`, parses its JSON, and
//!        injects ONLY the referenced field into the credential channel.
//!
//! ## Secret-exclusion rule (load-bearing)
//! Secret VALUES live ONLY in `credentials`. They are NEVER written to `form_data`, NEVER logged,
//! and NEVER serialized. We log only the COUNT of resolved inputs and the set of secret KEY NAMES
//! that were requested (names, not values) — and only at debug. A vault key that has no matching
//! stored secret is simply left unresolved (the placeholder stays literal), exactly like the
//! executor's own miss behavior; we never invent or echo a value.

use std::collections::{BTreeSet, HashMap};

use crate::local::error::LocalResult;
use crate::local::store::vault_secrets;
use crate::local::store::workflows::Workflow;
use crate::local::vault::Vault;

/// The two maps a resolved run hands to `execute_step`, plus the steps TEXT with `{{vault:KEY}}`
/// normalized to `{{secret:KEY}}`. Neither map nor this struct is logged/serialized wholesale —
/// `credentials` is the secret channel.
pub struct ResolvedRefs {
    /// SECRET channel: `KEY -> value`. Resolved `{{secret:KEY}}` / `{{vault:KEY}}` + workflow creds.
    pub credentials: HashMap<String, String>,
    /// NON-secret channel: inputs overlaid on stored form_data, keyed for `{{input.NAME}}`/`{{NAME}}`.
    pub form_data: HashMap<String, String>,
    /// The workflow steps TEXT after normalizing `{{vault:KEY}}` → `{{secret:KEY}}`. The engine
    /// parses steps from THIS string so the executor resolves both spellings via the secret channel.
    pub steps_text: String,
}

/// AAD column tag for a vault secret's `value_encrypted` blob (matches `api::v1::secrets::value_aad`,
/// which binds by the UNIQUE `key`: `vault_secrets|value_encrypted|<key>`).
fn secret_value_aad(key: &str) -> String {
    format!("vault_secrets|value_encrypted|{key}")
}

/// Run the combined resolution pass for `wf` under the caller-supplied `inputs`.
///
/// - `inputs`: the run `inputs` JSON (object of `NAME -> value`; non-string values are ignored for
///   substitution, matching the executor which only fills string placeholders).
/// - decrypts the workflow's `credentials_encrypted` (one input to the secret merge) and any
///   `vault_secrets` referenced by `{{secret:KEY}}`/`{{vault:KEY}}` in the steps.
/// - `allow_local_refs`: when `false` (an AD-HOC `RunSource::CloudAgent` recipe, TB-2) the LOCAL
///   `vault_secrets` lookup is SKIPPED and every unresolved `{{file:slot}}` marker is stripped, so a
///   recipe whose steps are authored cloud-side can only ever see secrets it supplied in its own
///   channel-key-sealed `credentials_encrypted` blob — it cannot exfiltrate a local vault secret or
///   file by guessing key/slot names. Normal runs (the user's own workflows) pass `true`.
///
/// SECRET VALUES NEVER LOGGED.
pub async fn resolve_run_refs(
    db: &sqlx::SqlitePool,
    vault: &Vault,
    wf: &Workflow,
    inputs: &serde_json::Value,
    allow_local_refs: bool,
) -> LocalResult<ResolvedRefs> {
    // 1) Normalize `{{vault:KEY}}` → `{{secret:KEY}}` once, up front, so both the placeholder scan
    //    and the executor see a single canonical secret spelling.
    let mut steps_text = normalize_vault_aliases(&wf.steps);

    // 2) form_data: stored form_data first, then overlay inputs (inputs WIN).
    let form_data = build_form_data(wf, inputs);

    // 3) credentials: workflow blob first (recipe-pinned), then fill in referenced vault secrets for
    //    any key the workflow blob did not already define.
    let mut credentials = decrypt_workflow_credentials(vault, wf);
    // TB-2: an ad-hoc cloud recipe (`allow_local_refs == false`) NEVER touches the local vault or
    // file store. It keeps ONLY its own sealed `credentials_encrypted` (decrypted just above); any
    // `{{secret:KEY}}` it did not supply stays literal, and `{{file:slot}}` markers are stripped so
    // the file layer cannot resolve a local slot the recipe named. This is the load-bearing barrier
    // that keeps a cloud-authored recipe from reading local secrets by guessing key names.
    if !allow_local_refs {
        steps_text = strip_file_markers(&steps_text);
        tracing::debug!(
            workflow_id = wf.id,
            "ad-hoc cloud recipe: local vault + file resolution DISABLED (sealed creds only)"
        );
        return Ok(ResolvedRefs { credentials, form_data, steps_text });
    }
    let requested = scan_secret_keys(&steps_text);
    if !requested.is_empty() {
        // Log requested KEY NAMES only (never values), at debug, to aid recipe debugging.
        tracing::debug!(workflow_id = wf.id, keys = ?requested, "resolving referenced vault secrets");
        for key in &requested {
            if credentials.contains_key(key) {
                continue; // workflow-pinned value wins
            }
            // (a) Exact key — a flat single-value secret (or a dotted key that is a flat secret name).
            if let Some(row) = vault_secrets::get_by_key(db, key).await? {
                match vault.open_field(&row.value_encrypted, &secret_value_aad(key)) {
                    Ok(bytes) => match String::from_utf8(bytes) {
                        Ok(value) => {
                            credentials.insert(key.clone(), value);
                            // Best-effort usage bookkeeping; never blocks the run.
                            let _ = vault_secrets::mark_used(db, row.id).await;
                        }
                        Err(_) => tracing::warn!(workflow_id = wf.id, "vault secret is not UTF-8 (left unresolved)"),
                    },
                    Err(_) => tracing::warn!(workflow_id = wf.id, "vault secret could not be opened (left unresolved)"),
                }
                continue;
            }
            // (b) Sub-field of a JSON secret — `base.field`: a credential pair's `.username`/`.password`
            //     or a card's `.number`/`.expiry`/… (cloud `{{vault:name.field}}` form). Look up `base`,
            //     decrypt, and pull the string `field` out of the JSON object. Only the referenced
            //     field enters the credential channel — never the whole pair/card.
            if let Some((base, field)) = key.rsplit_once('.') {
                if let Some(row) = vault_secrets::get_by_key(db, base).await? {
                    if let Ok(bytes) = vault.open_field(&row.value_encrypted, &secret_value_aad(base)) {
                        if let Ok(obj) = serde_json::from_slice::<serde_json::Value>(&bytes) {
                            if let Some(val) = obj.get(field).and_then(|v| v.as_str()) {
                                credentials.insert(key.clone(), val.to_string());
                                let _ = vault_secrets::mark_used(db, row.id).await;
                            }
                        }
                    }
                }
            }
            // A miss (no such secret / no such field) is intentionally silent — the placeholder stays literal.
        }
    }

    Ok(ResolvedRefs { credentials, form_data, steps_text })
}

/// Overlay the run `inputs` onto the workflow's stored `form_data` (JSON-TEXT `{name->string}`),
/// keyed so both `{{input.NAME}}` and bare `{{NAME}}` resolve. Inputs take PRECEDENCE over stored
/// form_data. Non-string input values are skipped (only string placeholders are fillable).
pub fn build_form_data(wf: &Workflow, inputs: &serde_json::Value) -> HashMap<String, String> {
    let mut form_data: HashMap<String, String> = wf
        .form_data
        .as_deref()
        .and_then(|s| serde_json::from_str(s).ok())
        .unwrap_or_default();

    let mut input_count = 0usize;
    if let Some(obj) = inputs.as_object() {
        for (name, value) in obj {
            if let Some(s) = value.as_str() {
                // Canonical `{{input.NAME}}` key.
                form_data.insert(format!("input.{name}"), s.to_string());
                // Bare `{{NAME}}` key (inputs win over a stored form_data value of the same name).
                form_data.insert(name.clone(), s.to_string());
                input_count += 1;
            }
        }
    }
    tracing::debug!(workflow_id = wf.id, inputs = input_count, "run inputs overlaid onto form_data");
    form_data
}

/// Decrypt the workflow's sealed `credentials_encrypted` (`WF1:`) blob into a `{name->value}` map,
/// or an empty map when absent / on any decrypt/parse failure (fail toward an empty credential set
/// — a step needing a missing secret surfaces its own error). The reserved `__proxy__` object and
/// any non-string values are dropped. The plaintext is NEVER logged.
pub fn decrypt_workflow_credentials(vault: &Vault, wf: &Workflow) -> HashMap<String, String> {
    let Some(blob) = wf.credentials_encrypted.as_deref().filter(|s| !s.is_empty()) else {
        return HashMap::new();
    };
    let aad = crate::local::store::workflows::credentials_aad(wf.id);
    let plaintext = match vault.open_field(blob, &aad) {
        Ok(p) => p,
        Err(_) => {
            tracing::warn!(workflow_id = wf.id, "could not open workflow credentials (skipping)");
            return HashMap::new();
        }
    };
    match serde_json::from_slice::<serde_json::Value>(&plaintext) {
        Ok(serde_json::Value::Object(map)) => map
            .into_iter()
            .filter(|(k, _)| k != "__proxy__")
            .filter_map(|(k, v)| v.as_str().map(|s| (k, s.to_string())))
            .collect(),
        _ => HashMap::new(),
    }
}

/// Rewrite every `{{vault:KEY}}` placeholder to `{{secret:KEY}}` (token rename only — NO value is
/// substituted, so no secret enters the steps text). Whitespace inside the braces is tolerated and
/// preserved around the key. Idempotent and allocation-light when there is nothing to rewrite.
pub fn normalize_vault_aliases(steps_text: &str) -> String {
    if !steps_text.contains("vault:") {
        return steps_text.to_string();
    }
    // The KEY grammar mirrors the secret/input scanners: `[A-Za-z0-9_.-]`. We only rewrite a strict
    // `{{[ws]vault:KEY[ws]}}` form so we never touch an unrelated literal `vault:` substring.
    let re = regex::Regex::new(r"\{\{(\s*)vault:([A-Za-z0-9_.\-]+)(\s*)\}\}")
        .expect("vault-alias regex is valid");
    re.replace_all(steps_text, "{{${1}secret:${2}${3}}}").into_owned()
}

/// Strip every `{{file:slot}}` marker from a steps TEXT blob, replacing it with an empty string
/// (TB-2). Used ONLY for an ad-hoc cloud recipe: it must not be able to name a local file slot, so we
/// neutralize the markers here rather than leave them for the file-resolution pass. The KEY grammar
/// mirrors the file resolver (`{{file:([^}]+)}}`). Allocation-light when there is nothing to strip.
pub fn strip_file_markers(steps_text: &str) -> String {
    if !steps_text.contains("file:") {
        return steps_text.to_string();
    }
    let re = regex::Regex::new(r"\{\{file:[^}]+\}\}").expect("file-marker regex is valid");
    re.replace_all(steps_text, "").into_owned()
}

/// The distinct secret KEYs referenced as `{{secret:KEY}}` in a steps TEXT blob (run
/// `normalize_vault_aliases` first so `{{vault:KEY}}` is already folded in). Order-insensitive
/// (returned sorted for determinism). KEY grammar: `[A-Za-z0-9_.-]`; whitespace inside the braces
/// is tolerated (`{{ secret:foo }}`). `input.` placeholders are never matched.
pub fn scan_secret_keys(steps_text: &str) -> BTreeSet<String> {
    let mut keys = BTreeSet::new();
    let re = regex::Regex::new(r"\{\{\s*secret:([A-Za-z0-9_.\-]+)\s*\}\}")
        .expect("secret-key regex is valid");
    for caps in re.captures_iter(steps_text) {
        keys.insert(caps[1].to_string());
    }
    keys
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::local::store::vault_secrets::NewVaultSecret;
    use crate::local::store::workflows::{self, NewWorkflow};
    use crate::local::{db, vault};
    use crate::util::value_resolver;

    async fn fixture() -> (sqlx::SqlitePool, std::sync::Arc<Vault>) {
        let dir = Box::leak(Box::new(tempfile::tempdir().unwrap()));
        let v = std::sync::Arc::new(vault::Vault::load_or_create(dir.path(), false).unwrap());
        let pool = db::open(&dir.path().join("t.db"), &v.db_key_hex()).await.unwrap();
        (pool, v)
    }

    #[test]
    fn normalize_folds_vault_into_secret() {
        assert_eq!(
            normalize_vault_aliases(r#"{"v":"{{vault:API_KEY}}","s":"{{secret:PW}}"}"#),
            r#"{"v":"{{secret:API_KEY}}","s":"{{secret:PW}}"}"#
        );
        // Whitespace tolerated and the `secret:` already-canonical form is untouched.
        assert_eq!(normalize_vault_aliases("{{ vault:K }}"), "{{ secret:K }}");
        // No `vault:` → unchanged (cheap path).
        assert_eq!(normalize_vault_aliases("{{input.x}}"), "{{input.x}}");
    }

    #[test]
    fn scan_collects_secret_keys_after_normalize() {
        let raw = r#"[{"value":"{{vault:A}}"},{"value":"{{secret:B}}"},{"u":"{{input.NAME}}"}]"#;
        let keys = scan_secret_keys(&normalize_vault_aliases(raw));
        assert!(keys.contains("A"));
        assert!(keys.contains("B"));
        assert_eq!(keys.len(), 2, "input.NAME must NOT be treated as a secret key");
    }

    #[tokio::test]
    async fn inputs_override_stored_form_data_and_key_both_forms() {
        let (pool, v) = fixture().await;
        let wf = workflows::insert(
            &pool,
            &NewWorkflow {
                name: "wf".into(),
                form_data: Some(r#"{"city":"Paris","country":"FR"}"#.into()),
                ..Default::default()
            },
        )
        .await
        .unwrap();

        let refs = resolve_run_refs(
            &pool,
            &v,
            &wf,
            &serde_json::json!({ "city": "Berlin", "name": "Bob" }),
            true,
        )
        .await
        .unwrap();

        // Stored value kept when no input overrides it.
        assert_eq!(refs.form_data.get("country").map(String::as_str), Some("FR"));
        // Input overrides stored form_data (bare key) AND is exposed under `input.NAME`.
        assert_eq!(refs.form_data.get("city").map(String::as_str), Some("Berlin"));
        assert_eq!(refs.form_data.get("input.city").map(String::as_str), Some("Berlin"));
        assert_eq!(refs.form_data.get("input.name").map(String::as_str), Some("Bob"));

        // End-to-end: the executor's resolver fills `{{input.NAME}}` from this map.
        assert_eq!(
            value_resolver::resolve_value("{{input.city}}", &refs.credentials, Some(&refs.form_data)),
            "Berlin"
        );
        assert_eq!(
            value_resolver::resolve_value("{{name}}", &refs.credentials, Some(&refs.form_data)),
            "Bob"
        );
    }

    #[tokio::test]
    async fn vault_secret_resolves_via_credentials_and_excludes_from_form_data() {
        let (pool, v) = fixture().await;

        // A stored vault secret, sealed exactly as `api::v1::secrets::create` would.
        let sealed = v
            .seal_field(b"S3CRET-VALUE", &secret_value_aad("LOGIN_PW"))
            .unwrap();
        vault_secrets::insert(
            &pool,
            &NewVaultSecret { key: "LOGIN_PW".into(), value_encrypted: sealed, ..Default::default() },
        )
        .await
        .unwrap();

        // A workflow whose step references it BOTH ways.
        let steps = r##"[
            {"type":"fill","config":{"selector":"#p","value":"{{secret:LOGIN_PW}}"}},
            {"type":"fill","config":{"selector":"#p2","value":"{{vault:LOGIN_PW}}"}}
        ]"##;
        let wf = workflows::insert(
            &pool,
            &NewWorkflow { name: "secret-wf".into(), steps: Some(steps.into()), ..Default::default() },
        )
        .await
        .unwrap();

        let refs = resolve_run_refs(&pool, &v, &wf, &serde_json::json!({}), true).await.unwrap();

        // The decrypted value is in the SECRET channel only.
        assert_eq!(refs.credentials.get("LOGIN_PW").map(String::as_str), Some("S3CRET-VALUE"));

        // SECRET-EXCLUSION: the value is NOT in form_data, and the serialized form_data does not
        // contain it (form_data is a logged/serialized surface; credentials is not).
        assert!(!refs.form_data.contains_key("LOGIN_PW"));
        let fd_json = serde_json::to_string(&refs.form_data).unwrap();
        assert!(!fd_json.contains("S3CRET-VALUE"), "secret must never appear in form_data");

        // The normalized steps text rewrote {{vault:..}} to {{secret:..}} (token only — no value
        // leaked into the steps text).
        assert!(refs.steps_text.contains("{{secret:LOGIN_PW}}"));
        assert!(!refs.steps_text.contains("{{vault:LOGIN_PW}}"));
        assert!(!refs.steps_text.contains("S3CRET-VALUE"), "no value substituted into steps text");

        // End-to-end: the executor resolves the (now canonical) placeholder from credentials.
        assert_eq!(
            value_resolver::resolve_value(
                "{{secret:LOGIN_PW}}",
                &refs.credentials,
                Some(&refs.form_data)
            ),
            "S3CRET-VALUE"
        );
    }

    /// TB-2: an ad-hoc cloud recipe (`allow_local_refs = false`) must NOT resolve a `{{secret:KEY}}`
    /// against the LOCAL vault, and must strip `{{file:slot}}` markers — it may only see secrets it
    /// supplied in its own (here empty) `credentials_encrypted` blob. This is the exfiltration barrier.
    #[tokio::test]
    async fn cloud_recipe_does_not_resolve_local_secret_or_file() {
        let (pool, v) = fixture().await;

        // A local vault secret the recipe author does NOT own — a cloud recipe must never read it.
        let sealed = v
            .seal_field(b"LOCAL-ONLY", &secret_value_aad("GITHUB_TOKEN"))
            .unwrap();
        vault_secrets::insert(
            &pool,
            &NewVaultSecret { key: "GITHUB_TOKEN".into(), value_encrypted: sealed, ..Default::default() },
        )
        .await
        .unwrap();

        // An ad-hoc recipe (no own credentials blob) whose step tries to read the local secret + a file.
        let steps = r##"[
            {"type":"fill","config":{"selector":"#t","value":"{{secret:GITHUB_TOKEN}}"}},
            {"type":"upload","config":{"selector":"#f","value":"{{file:resume}}"}}
        ]"##;
        let wf = workflows::insert(
            &pool,
            &NewWorkflow { name: "cloud-recipe".into(), steps: Some(steps.into()), ..Default::default() },
        )
        .await
        .unwrap();

        // allow_local_refs = false → NO local vault/file resolution.
        let refs = resolve_run_refs(&pool, &v, &wf, &serde_json::json!({}), false)
            .await
            .unwrap();

        // The local secret is NOT in the credential channel (never read from the vault).
        assert!(
            !refs.credentials.contains_key("GITHUB_TOKEN"),
            "cloud recipe must NOT resolve a local vault secret"
        );
        // The placeholder stays literal (unresolved), and the value never appears anywhere.
        assert!(refs.steps_text.contains("{{secret:GITHUB_TOKEN}}"));
        assert!(!refs.steps_text.contains("LOCAL-ONLY"));
        // The {{file:slot}} marker is stripped so the file layer cannot resolve a local slot.
        assert!(!refs.steps_text.contains("{{file:resume}}"), "file markers must be stripped");

        // CONTRAST: a normal run (allow_local_refs = true) WOULD resolve the same secret.
        let normal = resolve_run_refs(&pool, &v, &wf, &serde_json::json!({}), true)
            .await
            .unwrap();
        assert_eq!(
            normal.credentials.get("GITHUB_TOKEN").map(String::as_str),
            Some("LOCAL-ONLY"),
            "a normal run still resolves the user's own local secret"
        );
    }

    #[tokio::test]
    async fn credential_pair_subfields_resolve_from_json_secret() {
        let (pool, v) = fixture().await;

        // A credential secret stored the cloud way: one row holding a {username,password} JSON pair,
        // sealed under its key exactly as `secrets::create` would.
        let sealed = v
            .seal_field(
                br#"{"username":"me@example.com","password":"hunter2"}"#,
                &secret_value_aad("shopify_login"),
            )
            .unwrap();
        vault_secrets::insert(
            &pool,
            &NewVaultSecret {
                key: "shopify_login".into(),
                value_encrypted: sealed,
                category: Some("credentials".into()),
                ..Default::default()
            },
        )
        .await
        .unwrap();

        // A workflow that references the pair by sub-field, both spellings.
        let steps = r##"[
            {"type":"fill","config":{"selector":"#u","value":"{{vault:shopify_login.username}}"}},
            {"type":"fill","config":{"selector":"#p","value":"{{secret:shopify_login.password}}"}}
        ]"##;
        let wf = workflows::insert(
            &pool,
            &NewWorkflow { name: "sub".into(), steps: Some(steps.into()), ..Default::default() },
        )
        .await
        .unwrap();

        let refs = resolve_run_refs(&pool, &v, &wf, &serde_json::json!({}), true).await.unwrap();

        // Each sub-field resolves to its own value; only the referenced fields enter the channel.
        assert_eq!(refs.credentials.get("shopify_login.username").map(String::as_str), Some("me@example.com"));
        assert_eq!(refs.credentials.get("shopify_login.password").map(String::as_str), Some("hunter2"));

        // The password never lands in the (logged/serialized) form_data channel.
        let fd_json = serde_json::to_string(&refs.form_data).unwrap();
        assert!(!fd_json.contains("hunter2"), "password must never appear in form_data");

        // End-to-end: the executor fills the sub-field placeholders from the credential channel.
        assert_eq!(
            value_resolver::resolve_value("{{secret:shopify_login.username}}", &refs.credentials, Some(&refs.form_data)),
            "me@example.com"
        );
    }

    #[tokio::test]
    async fn workflow_credentials_win_over_vault_and_file_markers_kept() {
        let (pool, v) = fixture().await;

        // Vault secret under key TOKEN.
        let sealed = v.seal_field(b"vault-token", &secret_value_aad("TOKEN")).unwrap();
        vault_secrets::insert(
            &pool,
            &NewVaultSecret { key: "TOKEN".into(), value_encrypted: sealed, ..Default::default() },
        )
        .await
        .unwrap();

        // Workflow with a credentials blob that ALSO defines TOKEN — the recipe-pinned value wins.
        let wf = workflows::insert(
            &pool,
            &NewWorkflow {
                name: "cred-wf".into(),
                steps: Some(r#"[{"value":"{{secret:TOKEN}}","file":"{{file:resume}}"}]"#.into()),
                ..Default::default()
            },
        )
        .await
        .unwrap();
        // Seal the workflow blob bound to the row id.
        let wf_blob = v
            .seal_field(
                br#"{"TOKEN":"workflow-token"}"#,
                &format!("workflows|credentials_encrypted|{}", wf.id),
            )
            .unwrap();
        let wf = workflows::update(
            &pool,
            wf.id,
            &workflows::WorkflowUpdate { credentials_encrypted: Some(wf_blob), ..Default::default() },
        )
        .await
        .unwrap();

        let refs = resolve_run_refs(&pool, &v, &wf, &serde_json::json!({}), true).await.unwrap();
        assert_eq!(
            refs.credentials.get("TOKEN").map(String::as_str),
            Some("workflow-token"),
            "workflow-pinned credential wins over the vault secret"
        );

        // {{file:slot}} markers are LEFT untouched for the file layer (not resolved here).
        assert!(refs.steps_text.contains("{{file:resume}}"));
    }
}
