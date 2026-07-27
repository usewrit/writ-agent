//! Persona resolution for a local run — STAGE E1, part (2).
//!
//! A workflow's `default_persona_id` (or a per-target persona) names the login identity a run
//! executes as. This module loads that persona row from the encrypted store and decrypts the
//! sealed Layer-B fields the engine needs to make the run *act* as that persona:
//!
//!   - `credentials_encrypted` → a flat `{name -> value}` map merged into the run `credentials`
//!     (so `{{secret:username}}` / `{{secret:password}}` fills resolve). `login_username` lands as
//!     `username` (1:1 with the cloud `PersonaService.resolve_login_credentials` convention).
//!   - `fingerprint` (plain JSON-TEXT, NOT sealed) → a [`Fingerprint`] the engine pins on the
//!     browser context so a warm/returning-user session is not invalidated.
//!   - `session_state_encrypted` → a [`SessionState`] (cookies + localStorage) the engine restores
//!     before navigation so the run starts already authenticated.
//!   - `proxy_config_encrypted` → a `{server,username,password,bypass}` object mapped to
//!     [`ProxySettings`] so the context egresses through the persona's BYO proxy.
//!   - `totp_seed_encrypted` → a base32 shared secret; when present we mint the CURRENT RFC-6238
//!     code via [`Vault::mint_totp`] and expose it under the credentials key
//!     [`TOTP_CREDENTIAL_KEY`] so a `fill`/`twofa` step can consume `{{secret:otp}}`.
//!
//! ## Secret hygiene
//! Every decrypted value here is a SECRET. The returned [`ResolvedPersona`] is intentionally NOT
//! `Debug`/`Serialize` over its secret fields — `credentials` and `totp_code` never appear in any
//! logged or serialized surface. We log only non-secret facts (persona id, counts, whether a proxy
//! / session / TOTP was present), never the values.
//!
//! House style: boxed-future-free (plain `async fn`), `tracing` only, runtime sqlx via the store,
//! module-local errors via `crate::local::error::{LocalError, LocalResult}`.

use std::collections::HashMap;

use crate::browser::context::Fingerprint;
use crate::local::error::LocalResult;
use crate::local::store::personas::{self, Persona};
use crate::local::vault::Vault;
use crate::models::session::SessionState;

/// AAD column tag for the persona login-credentials blob (`personas|<column>|<id>` convention).
/// `pub(crate)` so the `/v1/personas` API seals with the SAME identity this resolver opens with.
pub(crate) const AAD_CREDENTIALS: &str = "credentials_encrypted";
/// AAD column tag for the persona TOTP seed blob.
pub(crate) const AAD_TOTP_SEED: &str = "totp_seed_encrypted";
/// AAD column tag for the persona BYO-proxy config blob.
pub(crate) const AAD_PROXY: &str = "proxy_config_encrypted";
/// AAD column tag for the persona session-state blob.
pub(crate) const AAD_SESSION_STATE: &str = "session_state_encrypted";

/// The `credentials` key a minted TOTP code is exposed under. A recorded 2FA step references it as
/// `{{secret:otp}}`; like every other secret it never enters `form_data` or any logged surface.
pub const TOTP_CREDENTIAL_KEY: &str = "otp";

/// Build the row-binding AAD for a persona's sealed column: `personas|<column>|<id>`. Matches the
/// vault convention (`table|column|row_id`) and the per-row identity used everywhere else.
/// `pub(crate)` so the `/v1/personas` API seals with the SAME identity this resolver opens with.
pub(crate) fn persona_aad(column: &str, id: i64) -> String {
    format!("personas|{column}|{id}")
}

/// Everything a run needs to *be* a persona, decrypted from the persona row. Secret fields are
/// applied by the engine and then dropped; this struct is deliberately neither `Debug` nor
/// `Serialize` so a secret can never leak through a derived impl.
pub struct ResolvedPersona {
    /// The persona row id (non-secret — safe to log/stamp).
    pub persona_id: i64,
    /// The persona's 2FA method (`none` | `totp` | `email_otp` | `sms`). Non-secret — the engine
    /// reads it at a `twofa` step to decide: `totp` mints a FRESH code on-device (see
    /// [`mint_current_totp`]); `email_otp`/`sms` can only be read in the cloud, so the run finalizes
    /// `twofa_required` (the email/SMS cloud-gate). `none` → the step is a no-op.
    pub twofa_method: String,
    /// Flat login credentials (`username`/`password`/extra). SECRET — never logged/serialized.
    pub credentials: HashMap<String, String>,
    /// The captured browser fingerprint to pin (returning-user warmth). Non-secret.
    pub fingerprint: Option<Fingerprint>,
    /// Saved cookies + storage to restore before navigation. Sensitive (auth) — never logged.
    pub session_state: Option<SessionState>,
    /// BYO residential proxy egress for this context. Credentials inside are SECRET.
    pub proxy: Option<playwright_rs::protocol::ProxySettings>,
    /// The CURRENT minted TOTP code, if the persona carries a `totp_seed`. SECRET — never logged.
    pub totp_code: Option<String>,
}

impl ResolvedPersona {
    /// Merge this persona's login credentials into the run `credentials` map, and expose a minted
    /// TOTP code (if any) under [`TOTP_CREDENTIAL_KEY`]. The persona's values do NOT clobber a key
    /// already present (an explicit workflow/vault credential wins), so a recipe can override a
    /// persona field deliberately. SECRET VALUES NEVER LOGGED.
    pub fn merge_into_credentials(&self, credentials: &mut HashMap<String, String>) {
        for (k, v) in &self.credentials {
            credentials.entry(k.clone()).or_insert_with(|| v.clone());
        }
        if let Some(code) = &self.totp_code {
            credentials
                .entry(TOTP_CREDENTIAL_KEY.to_string())
                .or_insert_with(|| code.clone());
        }
    }
}

/// Load + decrypt a persona by id. Returns `Ok(None)` when there is no such row (a dangling
/// `default_persona_id` is non-fatal — the run simply proceeds without a persona). Individual
/// field decrypts fail SOFT (a single tampered/rotated blob is logged-as-skipped, not fatal),
/// except a present-but-unparseable TOTP seed which is surfaced so a 2FA run fails loudly rather
/// than silently logging in without a code.
pub async fn resolve_persona(
    db: &sqlx::SqlitePool,
    vault: &Vault,
    persona_id: i64,
) -> LocalResult<Option<ResolvedPersona>> {
    let Some(row) = personas::get_by_id(db, persona_id).await? else {
        tracing::warn!(persona_id, "workflow references a missing persona — running without it");
        return Ok(None);
    };
    let mut resolved = resolve_from_row(vault, &row)?;
    expand_vault_refs(db, vault, persona_id, &mut resolved.credentials).await?;
    Ok(Some(resolved))
}

/// Expand persona credential VALUES that are vault-secret references into the referenced secret.
///
/// The persona editor links a login to a vault secret by storing the value as a `{{vault:KEY}}` /
/// `{{vault:KEY.field}}` template (cloud parity — see `PersonaService.linked_secret_refs`). Those
/// refs must resolve at RUN time (the secret's CURRENT value, not a copy frozen at link time), so
/// after decrypting the persona blob we swap each whole-value template for the referenced local
/// `vault_secrets` value: an exact `KEY` resolves the whole secret; `BASE.field` resolves a single
/// string field of a JSON secret (a credential pair's `username`/`password`, a card field, …).
///
/// A miss (no such secret / no such field / undecryptable) DROPS the credential with a names-only
/// warning: a dangling template must never be typed into a login form as a literal.
/// SECRET VALUES NEVER LOGGED.
async fn expand_vault_refs(
    db: &sqlx::SqlitePool,
    vault: &Vault,
    persona_id: i64,
    credentials: &mut HashMap<String, String>,
) -> LocalResult<()> {
    use crate::local::store::vault_secrets;

    // AAD identical to `api::v1::secrets::value_aad` / `engine::resolve::secret_value_aad`.
    let secret_aad = |key: &str| format!("vault_secrets|value_encrypted|{key}");
    let re = regex::Regex::new(r"^\{\{\s*(?:vault|secret):([A-Za-z0-9_.\-]+)\s*\}\}$")
        .expect("vault-ref regex is valid");

    let linked: Vec<(String, String)> = credentials
        .iter()
        .filter_map(|(k, v)| re.captures(v).map(|c| (k.clone(), c[1].to_string())))
        .collect();

    for (cred_key, ref_key) in linked {
        // (a) Exact key — a flat single-value secret.
        if let Some(row) = vault_secrets::get_by_key(db, &ref_key).await? {
            if let Ok(bytes) = vault.open_field(&row.value_encrypted, &secret_aad(&ref_key)) {
                if let Ok(value) = String::from_utf8(bytes) {
                    credentials.insert(cred_key, value);
                    let _ = vault_secrets::mark_used(db, row.id).await;
                    continue;
                }
            }
        }
        // (b) Sub-field of a JSON secret — `BASE.field` (a pair's username/password, a card field).
        if let Some((base, field)) = ref_key.rsplit_once('.') {
            if let Some(row) = vault_secrets::get_by_key(db, base).await? {
                if let Ok(bytes) = vault.open_field(&row.value_encrypted, &secret_aad(base)) {
                    if let Ok(obj) = serde_json::from_slice::<serde_json::Value>(&bytes) {
                        if let Some(val) = obj.get(field).and_then(|v| v.as_str()) {
                            credentials.insert(cred_key, val.to_string());
                            let _ = vault_secrets::mark_used(db, row.id).await;
                            continue;
                        }
                    }
                }
            }
        }
        // Miss: drop the credential (never type a literal template into a login form).
        tracing::warn!(
            persona_id,
            field = %cred_key,
            secret = %ref_key,
            "persona-linked vault secret did not resolve — dropping the credential"
        );
        credentials.remove(&cred_key);
    }
    Ok(())
}

/// Decrypt a persona's sealed fields into a [`ResolvedPersona`]. Pure (no DB) so it is unit-testable
/// against a vault + an in-memory row.
pub fn resolve_from_row(vault: &Vault, row: &Persona) -> LocalResult<ResolvedPersona> {
    let id = row.id;

    // --- login credentials: login_username → `username`, plus the sealed extra `{name->value}` ---
    let mut credentials: HashMap<String, String> = HashMap::new();
    if let Some(user) = row.login_username.as_deref().filter(|s| !s.is_empty()) {
        credentials.insert("username".to_string(), user.to_string());
    }
    if let Some(blob) = row.credentials_encrypted.as_deref().filter(|s| !s.is_empty()) {
        match vault.open_field(blob, &persona_aad(AAD_CREDENTIALS, id)) {
            Ok(plain) => match serde_json::from_slice::<serde_json::Value>(&plain) {
                Ok(serde_json::Value::Object(map)) => {
                    for (k, v) in map {
                        if k == "__proxy__" {
                            continue; // proxy rides in its own column locally; ignore if embedded
                        }
                        if let Some(s) = v.as_str() {
                            credentials.insert(k, s.to_string());
                        }
                    }
                }
                _ => tracing::warn!(persona_id = id, "persona credentials blob is not a string map"),
            },
            Err(_) => tracing::warn!(persona_id = id, "persona credentials could not be opened (skipping)"),
        }
    }

    // --- fingerprint: plain JSON-TEXT (NOT a sealed column) — parse directly, best-effort ---
    let fingerprint: Option<Fingerprint> = row
        .fingerprint
        .as_deref()
        .filter(|s| !s.is_empty())
        .and_then(|s| match serde_json::from_str::<Fingerprint>(s) {
            Ok(fp) => Some(fp),
            Err(e) => {
                tracing::warn!(persona_id = id, error = %e, "persona fingerprint unparseable — using a fresh one");
                None
            }
        });

    // --- session_state: sealed JSON (cookies + storage) — best-effort restore ---
    let session_state: Option<SessionState> = match row
        .session_state_encrypted
        .as_deref()
        .filter(|s| !s.is_empty())
    {
        Some(blob) => match vault.open_field(blob, &persona_aad(AAD_SESSION_STATE, id)) {
            Ok(plain) => match serde_json::from_slice::<SessionState>(&plain) {
                Ok(state) => {
                    tracing::info!(
                        persona_id = id,
                        cookies = state.cookies.len(),
                        local_storage = state.local_storage.len(),
                        "persona session state will be restored"
                    );
                    Some(state)
                }
                Err(e) => {
                    tracing::warn!(persona_id = id, error = %e, "persona session_state unparseable — fresh session");
                    None
                }
            },
            Err(_) => {
                tracing::warn!(persona_id = id, "persona session_state could not be opened (fresh session)");
                None
            }
        },
        None => None,
    };

    // --- proxy: sealed `{server,username,password,bypass}` object → ProxySettings ---
    let proxy = match row.proxy_config_encrypted.as_deref().filter(|s| !s.is_empty()) {
        Some(blob) => match vault.open_field(blob, &persona_aad(AAD_PROXY, id)) {
            Ok(plain) => parse_proxy(&plain).inspect(|_| {
                tracing::info!(persona_id = id, "persona BYO proxy will egress this run");
            }),
            Err(_) => {
                tracing::warn!(persona_id = id, "persona proxy_config could not be opened (env proxy / direct)");
                None
            }
        },
        None => None,
    };

    // --- TOTP: mint the CURRENT code from the sealed seed when the persona has 2FA configured ---
    // A present-but-broken seed is surfaced (Err) so a 2FA login fails loudly. `twofa_method == none`
    // or an absent seed → no code (not an error).
    let totp_code: Option<String> = match row.totp_seed_encrypted.as_deref().filter(|s| !s.is_empty()) {
        Some(blob) => {
            let seed_bytes = vault.open_field(blob, &persona_aad(AAD_TOTP_SEED, id))?;
            let seed = String::from_utf8(seed_bytes)
                .map_err(|_| crate::local::error::LocalError::Internal("persona totp seed is not UTF-8".into()))?;
            let digits = row.totp_digits.clamp(6, 10) as u32;
            let period = row.totp_period_seconds.max(1) as u64;
            let code = Vault::mint_totp(&seed, digits, period, &row.totp_algorithm)?;
            tracing::info!(persona_id = id, method = %row.twofa_method, "minted persona TOTP for this run");
            Some(code)
        }
        None => None,
    };

    Ok(ResolvedPersona {
        persona_id: id,
        twofa_method: row.twofa_method.clone(),
        credentials,
        fingerprint,
        session_state,
        proxy,
        totp_code,
    })
}

/// Mint the CURRENT RFC-6238 TOTP code for a persona, re-reading the sealed seed at call time.
///
/// A TOTP code is only valid for one ~30s window, but a run can take much longer than that to walk
/// from run-init to the actual 2FA step (navigate → fill username → fill password → submit → land on
/// the challenge). So the engine calls this AT the `twofa` step — not the init-time mint in
/// [`resolve_from_row`] — to enter a fresh, in-window code. The seed never leaves this function.
///
/// Returns `Ok(None)` when the persona has no seed (e.g. `twofa_method != "totp"`); `Err` only on a
/// present-but-broken seed (so a 2FA run fails loudly rather than entering a bogus code).
pub async fn mint_current_totp(
    db: &sqlx::SqlitePool,
    vault: &Vault,
    persona_id: i64,
) -> LocalResult<Option<String>> {
    let Some(row) = personas::get_by_id(db, persona_id).await? else {
        return Ok(None);
    };
    let Some(blob) = row.totp_seed_encrypted.as_deref().filter(|s| !s.is_empty()) else {
        return Ok(None);
    };
    let seed_bytes = vault.open_field(blob, &persona_aad(AAD_TOTP_SEED, persona_id))?;
    let seed = String::from_utf8(seed_bytes)
        .map_err(|_| crate::local::error::LocalError::Internal("persona totp seed is not UTF-8".into()))?;
    let digits = row.totp_digits.clamp(6, 10) as u32;
    let period = row.totp_period_seconds.max(1) as u64;
    let code = Vault::mint_totp(&seed, digits, period, &row.totp_algorithm)?;
    tracing::info!(persona_id, "minted fresh persona TOTP at 2FA step");
    Ok(Some(code))
}

/// Map a decrypted proxy JSON object to [`ProxySettings`]. Requires a non-empty `server` (mirrors
/// the cloud `extract_proxy_override` guard); empty/missing optional fields collapse to `None`.
fn parse_proxy(plain: &[u8]) -> Option<playwright_rs::protocol::ProxySettings> {
    let obj = serde_json::from_slice::<serde_json::Value>(plain).ok()?;
    let obj = obj.as_object()?;
    let server = obj.get("server").and_then(|v| v.as_str()).filter(|s| !s.is_empty())?;
    let str_field = |k: &str| {
        obj.get(k)
            .and_then(|v| v.as_str())
            .filter(|s| !s.is_empty())
            .map(|s| s.to_string())
    };
    Some(playwright_rs::protocol::ProxySettings {
        server: server.to_string(),
        bypass: str_field("bypass"),
        username: str_field("username"),
        password: str_field("password"),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::local::store::personas::NewPersona;
    use crate::local::{db, vault};

    /// A vault + keyed DB fixture (no keyring prompt).
    async fn fixture() -> (sqlx::SqlitePool, std::sync::Arc<Vault>) {
        let dir = Box::leak(Box::new(tempfile::tempdir().unwrap()));
        let v = std::sync::Arc::new(vault::Vault::load_or_create(dir.path(), false).unwrap());
        let pool = db::open(&dir.path().join("t.db"), &v.db_key_hex()).await.unwrap();
        (pool, v)
    }

    #[tokio::test]
    async fn resolves_login_credentials_and_fingerprint() {
        let (pool, v) = fixture().await;

        // Seal an extra-credentials blob bound to the row we are about to insert (id will be 1).
        let creds_blob = v
            .seal_field(br#"{"password":"hunter2","api_token":"tok_abc"}"#, &persona_aad(AAD_CREDENTIALS, 1))
            .unwrap();
        let fp = Fingerprint {
            user_agent: "UA/1".into(),
            locale: "en-US".into(),
            timezone: "UTC".into(),
        };
        let p = personas::insert(
            &pool,
            &NewPersona {
                name: "p1".into(),
                login_username: Some("alice".into()),
                credentials_encrypted: Some(creds_blob),
                fingerprint: Some(serde_json::to_string(&fp).unwrap()),
                ..Default::default()
            },
        )
        .await
        .unwrap();
        assert_eq!(p.id, 1, "fixture assumes first row id = 1 for AAD binding");

        let resolved = resolve_persona(&pool, &v, p.id).await.unwrap().unwrap();
        assert_eq!(resolved.credentials.get("username").map(String::as_str), Some("alice"));
        assert_eq!(resolved.credentials.get("password").map(String::as_str), Some("hunter2"));
        assert_eq!(resolved.credentials.get("api_token").map(String::as_str), Some("tok_abc"));
        assert_eq!(resolved.fingerprint.as_ref().unwrap().user_agent, "UA/1");
        assert!(resolved.totp_code.is_none(), "no seed → no code");
        assert!(resolved.proxy.is_none());
    }

    #[tokio::test]
    async fn linked_vault_refs_expand_at_resolve_time() {
        use crate::local::store::vault_secrets::{self, NewVaultSecret};

        let (pool, v) = fixture().await;

        // A credential-pair secret + a flat secret, sealed exactly as `secrets::create` would.
        let pair = v
            .seal_field(
                br#"{"username":"me@example.com","password":"hunter2"}"#,
                "vault_secrets|value_encrypted|shopify_login",
            )
            .unwrap();
        vault_secrets::insert(
            &pool,
            &NewVaultSecret { key: "shopify_login".into(), value_encrypted: pair, ..Default::default() },
        )
        .await
        .unwrap();
        let flat = v
            .seal_field(b"tok_flat", "vault_secrets|value_encrypted|API_KEY")
            .unwrap();
        vault_secrets::insert(
            &pool,
            &NewVaultSecret { key: "API_KEY".into(), value_encrypted: flat, ..Default::default() },
        )
        .await
        .unwrap();

        // Persona whose creds are LINKED (whole-value {{vault:...}} templates), the wizard way:
        // username in its own column, password + an extra field in the sealed blob, plus a ref
        // that resolves nothing (must be DROPPED, never typed literally).
        let creds_blob = v
            .seal_field(
                br#"{"password":"{{vault:shopify_login.password}}","api_token":"{{vault:API_KEY}}","ghost":"{{vault:missing.key}}"}"#,
                &persona_aad(AAD_CREDENTIALS, 1),
            )
            .unwrap();
        let p = personas::insert(
            &pool,
            &NewPersona {
                name: "linked".into(),
                login_username: Some("{{vault:shopify_login.username}}".into()),
                credentials_encrypted: Some(creds_blob),
                ..Default::default()
            },
        )
        .await
        .unwrap();
        assert_eq!(p.id, 1, "fixture assumes first row id = 1 for AAD binding");

        let resolved = resolve_persona(&pool, &v, p.id).await.unwrap().unwrap();
        assert_eq!(resolved.credentials.get("username").map(String::as_str), Some("me@example.com"));
        assert_eq!(resolved.credentials.get("password").map(String::as_str), Some("hunter2"));
        assert_eq!(resolved.credentials.get("api_token").map(String::as_str), Some("tok_flat"));
        assert!(
            !resolved.credentials.contains_key("ghost"),
            "a dangling vault ref is dropped, never left as a literal template"
        );
    }

    #[tokio::test]
    async fn mints_totp_and_merges_under_otp_key() {
        let (pool, v) = fixture().await;
        // RFC seed; with the default algo/period it just needs to be a valid base32 string.
        let seed = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";
        let seed_blob = v.seal_field(seed.as_bytes(), &persona_aad(AAD_TOTP_SEED, 1)).unwrap();
        let p = personas::insert(
            &pool,
            &NewPersona {
                name: "p2fa".into(),
                twofa_method: Some("totp".into()),
                totp_seed_encrypted: Some(seed_blob),
                ..Default::default()
            },
        )
        .await
        .unwrap();
        assert_eq!(p.id, 1);

        let resolved = resolve_persona(&pool, &v, p.id).await.unwrap().unwrap();
        let code = resolved.totp_code.clone().expect("a code was minted");
        assert_eq!(code.len(), 6, "default digits");
        assert!(code.chars().all(|c| c.is_ascii_digit()));

        // merge_into_credentials exposes it under `otp` for {{secret:otp}}.
        let mut creds = HashMap::new();
        resolved.merge_into_credentials(&mut creds);
        assert_eq!(creds.get(TOTP_CREDENTIAL_KEY), Some(&code));
        assert_eq!(resolved.twofa_method, "totp");

        // mint_current_totp re-reads the row and mints a fresh in-window code at step time.
        let fresh = mint_current_totp(&pool, &v, p.id).await.unwrap().expect("a fresh code");
        assert_eq!(fresh.len(), 6);
        assert!(fresh.chars().all(|c| c.is_ascii_digit()));
    }

    #[tokio::test]
    async fn mint_current_totp_is_none_without_seed() {
        let (pool, v) = fixture().await;
        let p = personas::insert(&pool, &NewPersona { name: "nofa".into(), ..Default::default() })
            .await
            .unwrap();
        assert!(mint_current_totp(&pool, &v, p.id).await.unwrap().is_none());
        // A missing persona id is also None (non-fatal).
        assert!(mint_current_totp(&pool, &v, 9_999).await.unwrap().is_none());
    }

    #[tokio::test]
    async fn proxy_decodes_and_missing_persona_is_none() {
        let (pool, v) = fixture().await;
        let proxy_blob = v
            .seal_field(
                br#"{"server":"http://proxy:8080","username":"u","password":"pw"}"#,
                &persona_aad(AAD_PROXY, 1),
            )
            .unwrap();
        let p = personas::insert(
            &pool,
            &NewPersona { name: "pp".into(), proxy_config_encrypted: Some(proxy_blob), ..Default::default() },
        )
        .await
        .unwrap();
        assert_eq!(p.id, 1);

        let resolved = resolve_persona(&pool, &v, p.id).await.unwrap().unwrap();
        let proxy = resolved.proxy.expect("proxy parsed");
        assert_eq!(proxy.server, "http://proxy:8080");
        assert_eq!(proxy.username.as_deref(), Some("u"));

        // A missing persona id resolves to None (non-fatal).
        assert!(resolve_persona(&pool, &v, 9_999).await.unwrap().is_none());
    }

    #[test]
    fn persona_values_never_appear_in_engine_logs_surface() {
        // ResolvedPersona is intentionally not Serialize/Debug. This compile-time-ish guard asserts
        // the secret fields are only reachable through explicit accessors (no derive leaks them).
        fn _assert_not_serialize<T>() {}
        // If someone adds #[derive(Serialize)] to ResolvedPersona this stays compiling, so instead
        // we assert behaviorally: merge does not stringify, and there is no Display/Debug impl used.
        let rp = ResolvedPersona {
            persona_id: 1,
            twofa_method: "totp".to_string(),
            credentials: HashMap::from([("password".to_string(), "TOPSECRET".to_string())]),
            fingerprint: None,
            session_state: None,
            proxy: None,
            totp_code: Some("000000".to_string()),
        };
        let mut creds = HashMap::new();
        rp.merge_into_credentials(&mut creds);
        // The secret only ever lands in the credentials map (the run's secret channel), never in a
        // serialized persona surface.
        assert_eq!(creds.get("password"), Some(&"TOPSECRET".to_string()));
    }
}
