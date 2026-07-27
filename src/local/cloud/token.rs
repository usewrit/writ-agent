//! OS-keyring storage of the cloud ACCOUNT token pair (`wto_` access / `wtr_` refresh).
//!
//! SECURITY (SECURITY_AND_ENTITLEMENTS_SPEC §0 + the never-trust-a-BYO-agent rule):
//! the cloud account token is STRICTLY SEPARATE from the local-API bearer (`wlt_`, loopback only)
//! and from the vault root key. It is stored ONLY in the OS keyring, under a DISTINCT
//! service (`writ-cloud`) — NEVER in `writ.db`, NEVER on disk, NEVER logged.
//!
//! MULTI-PROFILE: the keyring ACCOUNT (entry key) is the active **profile** id — the cloud account
//! id for a linked profile, or `local` for the no-account side-user (which has no token). This keeps
//! one cloud account's token from leaking into another profile's session. The active profile comes
//! from `WRIT_PROFILE` (the shell sets it per the home it boots; default `local`). The zero-arg
//! [`get`]/[`set`]/[`clear`] operate on the ACTIVE profile; the link flow / boot reconciliation use
//! the explicit-account [`store_account`]/[`load_account`] (the new account isn't the active profile
//! yet — the shell switches to it AFTER linking).
//!
//! The blob also carries the non-secret account metadata (id/email/scopes/base-url/linked-at) so a
//! freshly-switched-to profile can reconstruct its `LinkState` on first boot without a cloud round
//! trip. The keyring is OS-protected, so co-locating that metadata with the token is acceptable.
//!
//! All in-memory copies of token material are wrapped in [`secrecy::Secret`] so they are redacted on
//! `Debug` and zeroized on drop. Token VALUES are never passed to `tracing`.

use super::super::error::{LocalError, LocalResult};
use secrecy::{ExposeSecret, Secret};
use serde::{Deserialize, Serialize};

/// Keyring service for the cloud account token — DISTINCT from the vault (`writ-vault/master`) and
/// from the entitlement JWS (`writ-cloud/entitlements`).
pub const KEYRING_SERVICE: &str = "writ-cloud";
/// The no-account profile id (a local "side user"; carries no cloud token).
pub const LOCAL_PROFILE: &str = "local";
/// Env var the shell sets to select the active profile/home. Default [`LOCAL_PROFILE`].
pub const ENV_PROFILE: &str = "WRIT_PROFILE";

/// The active profile id (keyring account key) — `WRIT_PROFILE`, or `local`. A blank value folds to
/// `local` so a stray empty env can't address a nameless keyring entry.
pub fn active_profile() -> String {
    match std::env::var(ENV_PROFILE) {
        Ok(v) if !v.trim().is_empty() => v.trim().to_string(),
        _ => LOCAL_PROFILE.to_string(),
    }
}

/// Non-secret account metadata co-stored with the token so a switched-to profile can rebuild its
/// `LinkState` on first boot (reconciliation) without a cloud call.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct AccountMeta {
    pub account_id: String,
    pub email: String,
    pub scopes: Vec<String>,
    pub base_url: String,
    pub linked_at: Option<chrono::DateTime<chrono::Utc>>,
    /// The linked user's preferred UI language (`en`/`fr`/`es`), reflected at link time. `None` when
    /// unset. Co-stored so a switched-in profile rebuilds `LinkState.language` without a cloud call.
    pub language: Option<String>,
}

/// A token pair plus its co-stored account metadata, as loaded from one keyring entry.
pub struct StoredAccount {
    pub pair: TokenPair,
    pub meta: AccountMeta,
}

/// A cloud account token pair, held only transiently in memory.
///
/// `access`/`refresh` are `secrecy::Secret<String>` so they never appear in logs/`Debug` output and
/// are zeroized on drop. `expires_at` is a best-effort UI/refresh hint (the server is authoritative —
/// a 401 still drives the refresh-and-retry path regardless of this value).
#[derive(Clone)]
pub struct TokenPair {
    /// `wto_` opaque bearer access token.
    pub access: Secret<String>,
    /// `wtr_` opaque refresh token (OAuth refresh_token grant).
    pub refresh: Secret<String>,
    /// Optional access-token expiry (UTC). Reflection/opportunistic-refresh hint only.
    pub expires_at: Option<chrono::DateTime<chrono::Utc>>,
}

impl std::fmt::Debug for TokenPair {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // NEVER print token material.
        f.debug_struct("TokenPair")
            .field("access", &"<redacted>")
            .field("refresh", &"<redacted>")
            .field("expires_at", &self.expires_at)
            .finish()
    }
}

impl TokenPair {
    /// Build a pair from owned strings (e.g. parsed from a token-endpoint response).
    pub fn new(access: String, refresh: String, expires_at: Option<chrono::DateTime<chrono::Utc>>) -> Self {
        Self { access: Secret::new(access), refresh: Secret::new(refresh), expires_at }
    }

    /// Borrow the access token plaintext (loopback/cloud HTTP only — never log it).
    pub fn access(&self) -> &str {
        self.access.expose_secret()
    }

    /// Borrow the refresh token plaintext (refresh grant only — never log it).
    pub fn refresh(&self) -> &str {
        self.refresh.expose_secret()
    }

    /// True if the access token's expiry hint is in the past (with a small skew). When unknown
    /// (`expires_at == None`) this returns `false` — absence is not proof of expiry, the 401 path
    /// remains the source of truth.
    pub fn is_expired(&self) -> bool {
        match self.expires_at {
            Some(exp) => chrono::Utc::now() >= exp - chrono::Duration::seconds(30),
            None => false,
        }
    }
}

/// On-keyring JSON shape. Kept private; callers see [`TokenPair`]/[`StoredAccount`]. The `#[serde
/// (default)]` metadata fields load forward from older single-account blobs (which lacked them).
#[derive(Default, Serialize, Deserialize)]
struct StoredToken {
    access: String,
    refresh: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    expires_at: Option<chrono::DateTime<chrono::Utc>>,
    #[serde(default)]
    account_id: String,
    #[serde(default)]
    email: String,
    #[serde(default)]
    scopes: Vec<String>,
    #[serde(default)]
    base_url: String,
    #[serde(default)]
    linked_at: Option<chrono::DateTime<chrono::Utc>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    language: Option<String>,
}

fn entry(account: &str) -> LocalResult<keyring::Entry> {
    keyring::Entry::new(KEYRING_SERVICE, account)
        .map_err(|e| LocalError::Internal(format!("keyring open: {e}")))
}

/// Load the full stored account (token pair + metadata) for `account`, or `None` if absent.
pub fn load_account(account: &str) -> LocalResult<Option<StoredAccount>> {
    let raw = match entry(account)?.get_password() {
        Ok(s) => s,
        Err(keyring::Error::NoEntry) => return Ok(None),
        Err(e) => return Err(LocalError::Internal(format!("keyring get: {e}"))),
    };
    let s: StoredToken = serde_json::from_str(&raw)
        .map_err(|_| LocalError::Internal("keyring: malformed cloud token blob".into()))?;
    Ok(Some(StoredAccount {
        pair: TokenPair::new(s.access, s.refresh, s.expires_at),
        meta: AccountMeta {
            account_id: s.account_id,
            email: s.email,
            scopes: s.scopes,
            base_url: s.base_url,
            linked_at: s.linked_at,
            language: s.language,
        },
    }))
}

/// Write the token pair + metadata into `account`'s keyring entry. NEVER logs token values.
pub fn store_account(account: &str, pair: &TokenPair, meta: &AccountMeta) -> LocalResult<()> {
    let stored = StoredToken {
        access: pair.access().to_string(),
        refresh: pair.refresh().to_string(),
        expires_at: pair.expires_at,
        account_id: meta.account_id.clone(),
        email: meta.email.clone(),
        scopes: meta.scopes.clone(),
        base_url: meta.base_url.clone(),
        linked_at: meta.linked_at,
        language: meta.language.clone(),
    };
    let raw = serde_json::to_string(&stored)?;
    entry(account)?
        .set_password(&raw)
        .map_err(|e| LocalError::Internal(format!("keyring set: {e}")))?;
    tracing::debug!(account = %account, has_expiry = pair.expires_at.is_some(), "cloud account token stored");
    Ok(())
}

/// Delete `account`'s keyring entry. Idempotent; returns `true` if an entry was removed.
pub fn clear_account(account: &str) -> LocalResult<bool> {
    match entry(account)?.delete_credential() {
        Ok(()) => {
            tracing::debug!(account = %account, "cloud account token cleared");
            Ok(true)
        }
        Err(keyring::Error::NoEntry) => Ok(false),
        Err(e) => Err(LocalError::Internal(format!("keyring delete: {e}"))),
    }
}

// ── Active-profile convenience (the common case: operate on WRIT_PROFILE) ────────────────────────

/// Load the ACTIVE profile's token pair, or `None`. Used by the cloud HTTP client + status.
pub fn get() -> LocalResult<Option<TokenPair>> {
    Ok(load_account(&active_profile())?.map(|s| s.pair))
}

/// Overwrite the ACTIVE profile's token pair, PRESERVING its existing account metadata (so a refresh
/// rotation doesn't wipe the email/scopes the reconciliation path may still need).
pub fn set(pair: &TokenPair) -> LocalResult<()> {
    let account = active_profile();
    let meta = load_account(&account)?.map(|s| s.meta).unwrap_or_default();
    store_account(&account, pair, &meta)
}

/// Delete the ACTIVE profile's token. Idempotent; returns `true` if removed.
pub fn clear() -> LocalResult<bool> {
    clear_account(&active_profile())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn token_pair_redacts_and_exposes() {
        let p = TokenPair::new("wto_secret_access".into(), "wtr_secret_refresh".into(), None);
        // Debug must NOT leak token material.
        let dbg = format!("{p:?}");
        assert!(!dbg.contains("wto_secret_access"));
        assert!(!dbg.contains("wtr_secret_refresh"));
        assert!(dbg.contains("redacted"));
        // Explicit exposure still works for the HTTP layer.
        assert_eq!(p.access(), "wto_secret_access");
        assert_eq!(p.refresh(), "wtr_secret_refresh");
    }

    #[test]
    fn expiry_hint_logic() {
        let past = TokenPair::new("a".into(), "b".into(), Some(chrono::Utc::now() - chrono::Duration::hours(1)));
        assert!(past.is_expired());
        let future = TokenPair::new("a".into(), "b".into(), Some(chrono::Utc::now() + chrono::Duration::hours(1)));
        assert!(!future.is_expired());
        // Unknown expiry is treated as "not provably expired".
        let unknown = TokenPair::new("a".into(), "b".into(), None);
        assert!(!unknown.is_expired());
    }

    #[test]
    fn stored_token_serde_shape() {
        // The on-keyring JSON carries access/refresh; expires_at is omitted when absent.
        let s = StoredToken { access: "wto_x".into(), refresh: "wtr_y".into(), ..Default::default() };
        let json = serde_json::to_string(&s).unwrap();
        assert!(json.contains("\"access\":\"wto_x\""));
        assert!(json.contains("\"refresh\":\"wtr_y\""));
        assert!(!json.contains("expires_at"), "absent expiry must be skipped");

        // Round-trips with an expiry + metadata present.
        let when = chrono::Utc::now();
        let s2 = StoredToken {
            access: "a".into(),
            refresh: "b".into(),
            expires_at: Some(when),
            account_id: "acct_1".into(),
            email: "u@x.com".into(),
            scopes: vec!["workflows:run".into()],
            base_url: "https://c".into(),
            linked_at: Some(when),
            language: Some("es".into()),
        };
        let json2 = serde_json::to_string(&s2).unwrap();
        let back: StoredToken = serde_json::from_str(&json2).unwrap();
        assert_eq!(back.access, "a");
        assert_eq!(back.refresh, "b");
        assert!(back.expires_at.is_some());
        assert_eq!(back.account_id, "acct_1");
        assert_eq!(back.email, "u@x.com");

        // An OLD single-account blob (no metadata fields) still parses via #[serde(default)].
        let sparse: StoredToken = serde_json::from_str(r#"{"access":"a","refresh":"b"}"#).unwrap();
        assert!(sparse.expires_at.is_none());
        assert!(sparse.account_id.is_empty());
        assert!(sparse.scopes.is_empty());
    }

    #[test]
    fn active_profile_defaults_to_local() {
        // Deterministic only when WRIT_PROFILE is unset; tests don't mutate the process env here.
        if std::env::var(ENV_PROFILE).is_err() {
            assert_eq!(active_profile(), LOCAL_PROFILE);
        }
    }
}
