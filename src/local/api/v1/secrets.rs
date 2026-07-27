//! `/v1/secrets` REST handlers — list/create/get/delete over `store::vault_secrets`.
//!
//! Secrets are addressed by their UNIQUE TEXT `key` (not an integer id). The plaintext and the
//! vault key NEVER leave the daemon and are NEVER returned over the API. Callers POST the PLAINTEXT
//! `value`; the HANDLER seals it with the keyring-rooted `Vault` before persisting, so the store
//! only ever holds ciphertext (`value_encrypted`). Every response is shaped through `meta` so the
//! ciphertext column can never leak — these endpoints expose metadata ONLY.
//!
//! The sealing AAD binds the ciphertext to its row (`vault_secrets|value_encrypted|<key>`). Because
//! `key` is UNIQUE, this AAD is a stable per-row identity that cannot be relocated to another
//! secret. `open_secret` reads back with the SAME AAD (for future run-time resolution).
//!
//! House style: thin handlers over the store, `LocalResult<Json<_>>` with `?` propagation, no auth
//! layer here (server.rs applies the loopback bearer + Origin/Host middleware at the router level).

use crate::local::error::{LocalError, LocalResult};
use crate::local::server::AppState;
use crate::local::store::vault_secrets::{self, NewVaultSecret, VaultSecret};
use crate::local::vault::Vault;
use axum::extract::{Path, Query, State};
use axum::routing::get;
use axum::{Json, Router};
use serde::Deserialize;
use serde_json::{json, Value};

/// Build the row-binding AAD for a secret's `value_encrypted` column. `key` is UNIQUE, so this is a
/// stable per-row identity that prevents ciphertext relocation across secrets. `pub(crate)` so the
/// concierge's /respond (which vaults "secret"-kind answers) seals with the SAME AAD scheme.
pub(crate) fn value_aad(key: &str) -> String {
    format!("vault_secrets|value_encrypted|{key}")
}

/// App-lock guard for the secret-touching routes (SECURITY_AND_ENTITLEMENTS_SPEC §1.3). When the
/// vault app-lock is engaged and currently LOCKED this returns `LocalError::Locked` (HTTP 423) so a
/// locked desktop cannot list/read/create/delete secrets until the user unlocks via `/v1/vault/unlock`.
/// When the lock is disabled (the default) it is a no-op. The lock lives in a process-global slot
/// (`vault_lock::global`) installed at `lifecycle::bootstrap`.
fn guard_unlocked() -> LocalResult<()> {
    crate::local::vault_lock::global().guard()
}

/// Decrypt a stored secret row back to its plaintext, using the same row-binding AAD it was sealed
/// with. Intended for future run-time credential resolution (NOT wired into runs here — see notes).
/// NEVER log the returned plaintext.
pub fn open_secret(vault: &Vault, row: &VaultSecret) -> LocalResult<String> {
    let bytes = vault.open_field(&row.value_encrypted, &value_aad(&row.key))?;
    String::from_utf8(bytes).map_err(|_| LocalError::Internal("secret is not valid UTF-8".into()))
}

/// Default page size for the list endpoint when `?limit=` is omitted.
const DEFAULT_LIMIT: i64 = 100;
/// Hard cap so a client cannot ask for an unbounded scan.
const MAX_LIMIT: i64 = 500;

/// Mount the secret routes onto the shared `AppState` router. Auth is applied by `server.rs`.
/// Addressed by `key` (TEXT), so the `:key` path segment is the secret's unique name.
pub fn router() -> Router<AppState> {
    Router::new()
        .route("/v1/secrets", get(list).post(create))
        .route("/v1/secrets/:key", get(get_one).delete(remove))
}

/// The "credentials" category stores an email/username + password pair as a JSON object
/// (`{"username","password"}`) in `value_encrypted`, referenced as `{{vault:name.username}}` /
/// `{{vault:name.password}}`. Every other category stores a single opaque value. Mirrors
/// the cloud backend's `vault` router so the desktop vault behaves identically to Writ Cloud.
const CREDENTIAL_CATEGORY: &str = "credentials";
/// The "card" category stores a payment card as a JSON object (`{name,number,expiry,cvc,zip}`),
/// referenced per field as `{{vault:name.number}}` etc. Only a non-secret last-4 is ever exposed.
const CARD_CATEGORY: &str = "card";
/// The known card fields, in the order the cloud accepts/stores them.
const CARD_FIELDS: [&str; 5] = ["name", "number", "expiry", "cvc", "zip"];

/// A secret `name` (== its unique `key`): starts with a letter or underscore, then letters, digits,
/// `_`, `.`, `-`. Mirrors the cloud `SecretCreate.name` pattern `^[a-zA-Z_][a-zA-Z0-9_.-]*$`.
fn valid_name(n: &str) -> bool {
    let mut chars = n.chars();
    match chars.next() {
        Some(c) if c.is_ascii_alphabetic() || c == '_' => {}
        _ => return false,
    }
    chars.all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '.' | '-'))
}

/// Keep only known card fields with non-empty string values; strip spaces from the number. Mirrors
/// the cloud `_clean_card`.
fn clean_card(card: &serde_json::Map<String, Value>) -> serde_json::Map<String, Value> {
    let mut out = serde_json::Map::new();
    for field in CARD_FIELDS {
        let Some(val) = card.get(field).and_then(|v| v.as_str()) else { continue };
        let val = val.trim();
        if val.is_empty() {
            continue;
        }
        let val = if field == "number" { val.replace(' ', "") } else { val.to_string() };
        out.insert(field.to_string(), json!(val));
    }
    out
}

/// Decode the non-secret identifier from a "credentials" secret: `(is_credential, username)`. A true
/// credential is a `{username,password}` JSON pair — a flat value stored under the "credentials"
/// category (e.g. an individual login field the AI concierge sealed) is NOT a pair and resolves to
/// `(false, None)` so it renders as a plain single-value secret, never as a broken username/password
/// pair. The password is never decoded here. Decrypt failures fail safe to `(false, None)`.
fn credential_meta(vault: &Vault, s: &VaultSecret) -> (bool, Option<String>) {
    if s.category.as_deref() != Some(CREDENTIAL_CATEGORY) {
        return (false, None);
    }
    let Ok(plaintext) = open_secret(vault, s) else { return (false, None) };
    let Ok(Value::Object(obj)) = serde_json::from_str::<Value>(&plaintext) else { return (false, None) };
    if !obj.contains_key("username") || !obj.contains_key("password") {
        return (false, None);
    }
    (true, obj.get("username").and_then(|u| u.as_str()).map(str::to_string))
}

/// Decode just the last 4 digits of a "card" secret's number (never the full PAN/CVC). `None` when
/// not a card, on decrypt/parse failure, or when the number has fewer than 4 digits.
fn card_last4(vault: &Vault, s: &VaultSecret) -> Option<String> {
    if s.category.as_deref() != Some(CARD_CATEGORY) {
        return None;
    }
    let plaintext = open_secret(vault, s).ok()?;
    let value: Value = serde_json::from_str(&plaintext).ok()?;
    let number = value.get("number").and_then(|n| n.as_str())?;
    let digits: String = number.chars().filter(char::is_ascii_digit).collect();
    (digits.len() >= 4).then(|| digits[digits.len() - 4..].to_string())
}

#[derive(Debug, Default, Deserialize)]
struct ListQuery {
    limit: Option<i64>,
    /// Case-insensitive substring match on the secret name (parity with the cloud `?search`).
    #[serde(default)]
    search: Option<String>,
    /// Restrict to a single category (parity with the cloud `?category`, used e.g. by the card picker).
    #[serde(default)]
    category: Option<String>,
}

impl ListQuery {
    /// Clamp the requested limit into `1..=MAX_LIMIT`, defaulting when unset.
    fn limit(&self) -> i64 {
        self.limit.unwrap_or(DEFAULT_LIMIT).clamp(1, MAX_LIMIT)
    }
}

/// Body for `POST /v1/secrets`. Mirrors the cloud `SecretCreate`: a single-value secret supplies
/// `value`; a credential secret supplies `username` + `password`; a card secret supplies `card`. The
/// caller supplies PLAINTEXT over loopback; the handler seals it before persisting. `key` is accepted
/// as a legacy alias for `name`. Plaintext is never stored in the clear and never logged.
#[derive(Debug, Deserialize)]
struct CreateBody {
    #[serde(default)]
    name: Option<String>,
    /// Legacy alias for `name` (the daemon's original single-value create shape).
    #[serde(default)]
    key: Option<String>,
    #[serde(default)]
    value: Option<String>,
    #[serde(default)]
    username: Option<String>,
    #[serde(default)]
    password: Option<String>,
    #[serde(default)]
    card: Option<serde_json::Map<String, Value>>,
    #[serde(default)]
    description: Option<String>,
    #[serde(default)]
    category: Option<String>,
}

/// Project a secret row to metadata ONLY — the `value_encrypted` ciphertext is never included. Adds
/// the cloud contract fields (`name` == key, `is_credential`, `is_card`, `username`, `card_last4`) by
/// decrypting the non-secret bits of credential/card secrets. The password / full card are never
/// exposed. Mirrors the cloud backend's `vault` router::_secret_response`.
fn meta(vault: &Vault, s: &VaultSecret) -> Value {
    let (is_credential, username) = credential_meta(vault, s);
    let is_card = s.category.as_deref() == Some(CARD_CATEGORY);
    json!({
        "id": s.id,
        "key": s.key,
        "name": s.key,
        "description": s.description,
        "category": s.category,
        "is_credential": is_credential,
        "is_card": is_card,
        "username": username,
        "card_last4": card_last4(vault, s),
        "created_at": s.created_at,
        "updated_at": s.updated_at,
        "last_used_at": s.last_used_at,
        "use_count": s.use_count,
    })
}

/// `GET /v1/secrets` — newest-first metadata list, optionally filtered by `?category`/`?search` and
/// capped by `?limit`. Ciphertext omitted.
async fn list(State(st): State<AppState>, Query(q): Query<ListQuery>) -> LocalResult<Json<Value>> {
    guard_unlocked()?;
    let rows = match q.category.as_deref().filter(|c| !c.is_empty()) {
        Some(cat) => vault_secrets::list_by_category(&st.db, cat).await?,
        None => vault_secrets::list(&st.db, Some(q.limit())).await?,
    };
    let needle = q.search.as_deref().map(str::to_lowercase);
    let items = rows
        .iter()
        .filter(|s| needle.as_ref().is_none_or(|n| s.key.to_lowercase().contains(n)))
        .map(|s| meta(st.vault.as_ref(), s))
        .collect::<Vec<_>>();
    crate::local::vault_lock::global().touch();
    Ok(Json(json!({ "data": items, "count": items.len() })))
}

/// `POST /v1/secrets` — create a single-value, credential (username+password), or card secret. Seals
/// the plaintext handler-side and stores ciphertext only. Returns metadata only. 400 on a duplicate
/// name or invalid input. The plaintext is never logged.
async fn create(State(st): State<AppState>, Json(body): Json<CreateBody>) -> LocalResult<Json<Value>> {
    guard_unlocked()?;
    let name = body.name.clone().or_else(|| body.key.clone()).unwrap_or_default();
    let name = name.trim();
    if name.is_empty() {
        return Err(LocalError::BadRequest("name is required".into()));
    }
    if name.len() > 255 || !valid_name(name) {
        return Err(LocalError::BadRequest(
            "name must start with a letter or underscore and contain only letters, numbers, '_', '.', '-'".into(),
        ));
    }
    // Duplicate names map to a conflict — the daemon has no dedicated 409 variant, so surface a clear
    // 400 (parity with the cloud's 409 message).
    if vault_secrets::get_by_key(&st.db, name).await?.is_some() {
        return Err(LocalError::BadRequest(format!("Secret '{name}' already exists")));
    }

    // Card vs credential (email/username + password) vs single value — same precedence as the cloud.
    let is_card = body.category.as_deref() == Some(CARD_CATEGORY) || body.card.is_some();
    let is_credential = !is_card
        && (body.category.as_deref() == Some(CREDENTIAL_CATEGORY)
            || body.username.is_some()
            || body.password.is_some());
    let (stored, category): (String, Option<String>) = if is_card {
        let card = clean_card(body.card.as_ref().unwrap_or(&serde_json::Map::new()));
        if !card.contains_key("number") || !card.contains_key("expiry") {
            return Err(LocalError::BadRequest("A card secret needs at least a number and an expiry".into()));
        }
        (Value::Object(card).to_string(), Some(CARD_CATEGORY.to_string()))
    } else if is_credential {
        let username = body.username.as_deref().unwrap_or_default();
        let password = body.password.as_deref().unwrap_or_default();
        if username.trim().is_empty() || password.trim().is_empty() {
            return Err(LocalError::BadRequest(
                "A credential secret needs both an email/username and a password".into(),
            ));
        }
        (json!({ "username": username, "password": password }).to_string(), Some(CREDENTIAL_CATEGORY.to_string()))
    } else {
        let value = body.value.clone().unwrap_or_default();
        if value.trim().is_empty() {
            return Err(LocalError::BadRequest("A secret value is required".into()));
        }
        (value, body.category.clone())
    };

    // Seal in the daemon. The vault key lives in the OS keyring; the caller (loopback UI/CLI) cannot
    // seal, so the plaintext arrives here and is converted to ciphertext before it ever hits the DB.
    let value_encrypted = st.vault.seal_field(stored.as_bytes(), &value_aad(name))?;
    let new = NewVaultSecret {
        key: name.to_string(),
        value_encrypted,
        description: body.description.clone(),
        category,
    };
    let s = vault_secrets::insert(&st.db, &new).await?;
    crate::local::vault_lock::global().touch();
    Ok(Json(meta(st.vault.as_ref(), &s)))
}

/// `GET /v1/secrets/:key` — one secret's metadata (ciphertext omitted) or 404.
async fn get_one(State(st): State<AppState>, Path(key): Path<String>) -> LocalResult<Json<Value>> {
    guard_unlocked()?;
    let s = vault_secrets::get_by_key(&st.db, &key)
        .await?
        .ok_or_else(|| LocalError::NotFound(format!("secret {key}")))?;
    crate::local::vault_lock::global().touch();
    Ok(Json(meta(st.vault.as_ref(), &s)))
}

/// `DELETE /v1/secrets/:key` — hard-delete by key. 404 if absent.
async fn remove(State(st): State<AppState>, Path(key): Path<String>) -> LocalResult<Json<Value>> {
    guard_unlocked()?;
    let removed = vault_secrets::delete_by_key(&st.db, &key).await?;
    if !removed {
        return Err(LocalError::NotFound(format!("secret {key}")));
    }
    Ok(Json(json!({ "key": key, "deleted": true })))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::local::engine::StubEngine;
    use crate::local::vault::Vault;
    use std::sync::Arc;

    /// A plaintext-in / ciphertext-at-rest fixture: an `AppState` over a fresh SQLCipher DB keyed by
    /// a headless (no-keyring) vault, plus the same `Vault` Arc for direct decrypt assertions.
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

    /// A single-value secret create body (category `api_keys` — the "credentials" category now means
    /// a username+password pair, so a flat test value uses a plain category).
    fn body(name: &str, value: &str) -> Json<CreateBody> {
        Json(CreateBody {
            name: Some(name.to_string()),
            key: None,
            value: Some(value.to_string()),
            username: None,
            password: None,
            card: None,
            description: Some("a test secret".into()),
            category: Some("api_keys".into()),
        })
    }

    #[tokio::test]
    async fn create_seals_plaintext_and_stores_ciphertext_only() {
        let (st, vault) = fixture().await;
        let plaintext = "hunter2-SUPER-SECRET";

        // POST plaintext → handler seals → metadata response (no secret material).
        let resp = create(State(st.clone()), body("OPENAI_KEY", plaintext)).await.unwrap();
        let v = resp.0;
        assert_eq!(v["key"], "OPENAI_KEY");
        assert!(v.get("value").is_none(), "create response must not echo plaintext");
        assert!(v.get("value_encrypted").is_none(), "create response must not include ciphertext");

        // The stored row holds a WF1: ciphertext blob, and the plaintext appears NOWHERE in it.
        let row = vault_secrets::get_by_key(&st.db, "OPENAI_KEY").await.unwrap().unwrap();
        assert!(row.value_encrypted.starts_with("WF1:"), "value must be sealed at rest");
        assert!(
            !row.value_encrypted.contains(plaintext),
            "plaintext must never appear in the stored row"
        );

        // Serializing the whole row (worst case) still must not leak the plaintext.
        let row_json = serde_json::to_string(&row).unwrap();
        assert!(!row_json.contains(plaintext), "plaintext must not appear anywhere in the row");

        // open_secret round-trips through the same row-binding AAD.
        let recovered = open_secret(&vault, &row).unwrap();
        assert_eq!(recovered, plaintext);

        // The AAD binds the ciphertext to THIS key: a row whose key was swapped cannot be opened
        // (anti-relocation), proving the blob can't be moved onto another secret.
        let mut relocated = row.clone();
        relocated.key = "STRIPE_KEY".to_string();
        assert!(open_secret(&vault, &relocated).is_err(), "ciphertext must be bound to its key");
    }

    #[tokio::test]
    async fn get_and_list_return_metadata_only() {
        let (st, _vault) = fixture().await;
        let plaintext = "p@ss-LEAK-CANARY";
        let _ = create(State(st.clone()), body("DB_PASSWORD", plaintext)).await.unwrap();

        // GET one → metadata only; neither plaintext nor ciphertext is present.
        let one = get_one(State(st.clone()), Path("DB_PASSWORD".to_string())).await.unwrap().0;
        assert_eq!(one["key"], "DB_PASSWORD");
        assert_eq!(one["name"], "DB_PASSWORD", "name is exposed as an alias of key (cloud parity)");
        assert_eq!(one["category"], "api_keys");
        assert_eq!(one["is_credential"], false);
        assert!(one.get("value").is_none());
        assert!(one.get("value_encrypted").is_none());
        assert!(!serde_json::to_string(&one).unwrap().contains(plaintext));

        // LIST → each item is metadata only; ciphertext column never serialized.
        let listed = list(State(st.clone()), Query(ListQuery::default())).await.unwrap().0;
        assert_eq!(listed["count"], 1);
        let dumped = serde_json::to_string(&listed).unwrap();
        assert!(!dumped.contains(plaintext), "list must not leak plaintext");
        assert!(!dumped.contains("value_encrypted"), "list must not leak the ciphertext column");
    }

    #[tokio::test]
    async fn create_rejects_empty_name_or_value() {
        let (st, _vault) = fixture().await;
        assert!(create(State(st.clone()), body("  ", "x")).await.is_err());
        assert!(create(State(st.clone()), body("K", "")).await.is_err());
    }

    #[tokio::test]
    async fn rejects_invalid_name_and_duplicate() {
        let (st, _vault) = fixture().await;
        // A name must start with a letter or underscore (cloud pattern).
        assert!(create(State(st.clone()), body("9bad", "x")).await.is_err());
        assert!(create(State(st.clone()), body("has space", "x")).await.is_err());
        // Duplicate name is rejected.
        let _ = create(State(st.clone()), body("dup", "x")).await.unwrap();
        assert!(create(State(st.clone()), body("dup", "y")).await.is_err());
    }

    #[tokio::test]
    async fn credential_pair_projects_username_never_password() {
        let (st, _vault) = fixture().await;
        // A credential secret is inferred from username+password (no explicit category needed).
        let cred = Json(CreateBody {
            name: Some("shopify_login".into()),
            key: None,
            value: None,
            username: Some("me@example.com".into()),
            password: Some("hunter2".into()),
            card: None,
            description: None,
            category: None,
        });
        let resp = create(State(st.clone()), cred).await.unwrap().0;
        assert_eq!(resp["name"], "shopify_login");
        assert_eq!(resp["is_credential"], true);
        assert_eq!(resp["username"], "me@example.com");
        assert_eq!(resp["category"], "credentials");
        assert!(resp.get("password").is_none(), "the password is never returned");

        // The password never appears in list output either.
        let listed = list(State(st.clone()), Query(ListQuery::default())).await.unwrap().0;
        assert!(!serde_json::to_string(&listed).unwrap().contains("hunter2"), "list must not leak the password");

        // The stored value is a JSON pair — the sub-field resolver (engine/resolve.rs) reads it.
        let row = vault_secrets::get_by_key(&st.db, "shopify_login").await.unwrap().unwrap();
        let pt = open_secret(st.vault.as_ref(), &row).unwrap();
        assert_eq!(pt, r#"{"username":"me@example.com","password":"hunter2"}"#);
    }

    #[tokio::test]
    async fn credential_requires_both_username_and_password() {
        let (st, _vault) = fixture().await;
        let missing_pw = Json(CreateBody {
            name: Some("x".into()),
            key: None,
            value: None,
            username: Some("u".into()),
            password: None,
            card: None,
            description: None,
            category: Some("credentials".into()),
        });
        assert!(create(State(st.clone()), missing_pw).await.is_err());
    }

    #[tokio::test]
    async fn card_projects_last4_never_pan() {
        let (st, _vault) = fixture().await;
        let mut card = serde_json::Map::new();
        card.insert("number".into(), json!("4242 4242 4242 4242"));
        card.insert("expiry".into(), json!("12/30"));
        card.insert("cvc".into(), json!("123"));
        let body = Json(CreateBody {
            name: Some("my_card".into()),
            key: None,
            value: None,
            username: None,
            password: None,
            card: Some(card),
            description: None,
            category: None,
        });
        let resp = create(State(st.clone()), body).await.unwrap().0;
        assert_eq!(resp["is_card"], true);
        assert_eq!(resp["card_last4"], "4242");
        assert_eq!(resp["category"], "card");
        // The full PAN (spaces stripped) is never exposed — only the last 4.
        assert!(
            !serde_json::to_string(&resp).unwrap().contains("4242424242424242"),
            "full PAN must never appear in the response"
        );

        // A card needs at least a number and an expiry.
        let mut bad = serde_json::Map::new();
        bad.insert("number".into(), json!("4242424242424242"));
        let no_expiry = Json(CreateBody {
            name: Some("bad_card".into()),
            key: None,
            value: None,
            username: None,
            password: None,
            card: Some(bad),
            description: None,
            category: None,
        });
        assert!(create(State(st.clone()), no_expiry).await.is_err());

        // The card is listable under `?category=card`.
        let listed = list(
            State(st.clone()),
            Query(ListQuery { category: Some("card".into()), ..Default::default() }),
        )
        .await
        .unwrap()
        .0;
        assert_eq!(listed["count"], 1);
    }

    #[tokio::test]
    async fn accepts_frontend_wire_payloads() {
        // Proves the CreateBody serde contract matches the exact JSON the desktop UI posts.
        let (st, _vault) = fixture().await;

        // "Login credential" (SecretFormModal credential kind).
        let cred: CreateBody = serde_json::from_value(json!({
            "name": "shop_login", "username": "u@e.com", "password": "pw",
            "category": "credentials", "description": "d",
        }))
        .unwrap();
        let r = create(State(st.clone()), Json(cred)).await.unwrap().0;
        assert_eq!(r["is_credential"], true);
        assert_eq!(r["username"], "u@e.com");

        // "API key / token" (SecretFormModal value kind).
        let val: CreateBody = serde_json::from_value(json!({
            "name": "stripe_key", "value": "sk_test", "description": "d", "category": "api_keys",
        }))
        .unwrap();
        let r2 = create(State(st.clone()), Json(val)).await.unwrap().0;
        assert_eq!(r2["is_credential"], false);
        assert_eq!(r2["name"], "stripe_key");

        // Card (cloud SecretCreate.card shape — ElicitationForm/admin card path).
        let card: CreateBody = serde_json::from_value(json!({
            "name": "visa",
            "card": {"number": "4242 4242 4242 4242", "expiry": "01/29", "cvc": "999", "name": "Jane", "zip": "94107"},
        }))
        .unwrap();
        let r3 = create(State(st.clone()), Json(card)).await.unwrap().0;
        assert_eq!(r3["is_card"], true);
        assert_eq!(r3["card_last4"], "4242");
    }

    #[tokio::test]
    async fn flat_value_under_credentials_category_is_not_a_pair() {
        // The AI concierge seals individual login fields as FLAT values under the "credentials"
        // category. Those are single-value secrets, not username/password pairs — they must project
        // is_credential=false so the UI shows a plain {{vault:name}} reference, not a broken pair.
        let (st, vault) = fixture().await;
        let sealed = vault
            .seal_field(b"raw-api-key", &value_aad("concierge_9_login_key"))
            .unwrap();
        vault_secrets::upsert(
            &st.db,
            &NewVaultSecret {
                key: "concierge_9_login_key".into(),
                value_encrypted: sealed,
                description: Some("API key — saved by the AI assistant".into()),
                category: Some("credentials".into()),
            },
        )
        .await
        .unwrap();
        let one = get_one(State(st.clone()), Path("concierge_9_login_key".into())).await.unwrap().0;
        assert_eq!(one["name"], "concierge_9_login_key");
        assert_eq!(one["is_credential"], false, "a flat value is not a credential pair");
        assert!(one["username"].is_null());
    }
}
