//! `LinkState` — non-secret metadata for a linked Writ Cloud account.
//!
//! Persisted as a single JSON blob in the encrypted `config` kv table (Layer A: SQLCipher) under a
//! stable reserved key. This holds ONLY non-secret reflection metadata (account id/email, cloud base
//! url, granted OAuth scopes, link timestamp) — it is the answer to "am I linked, and to whom?".
//!
//! SECURITY: the cloud account token (`wto_` access / `wtr_` refresh) is NEVER stored here — it lives
//! exclusively in the OS keyring (see [`super::token`]). `scopes` here is descriptive UI/upsell
//! reflection only; it is NOT an authorization gate. Every paid/metered/cloud capability is
//! re-resolved and re-enforced SERVER-SIDE per call (the never-trust-a-BYO-agent rule).
//!
//! Net-new Rust in this crate (Stage A — cloud client foundation).

use super::super::error::LocalResult;
use super::super::store::config_kv;
use serde::{Deserialize, Serialize};
use sqlx::sqlite::SqlitePool;

/// Reserved `config` kv key under which the link metadata JSON is stored.
pub const LINK_STATE_KEY: &str = "cloud.link_state";

/// Reserved `config` kv key recording the user's "use the app WITHOUT a cloud account" choice
/// (local-only "side user"). A persisted UI decision so the login gate doesn't re-prompt every
/// launch; it is INDEPENDENT of [`LinkState`] (a fresh, never-linked install with this set boots
/// straight into the local-only app). Linking clears it.
pub const LOCAL_ONLY_KEY: &str = "cloud.local_only";

/// Reserved `config` kv key durably recording the account id that OWNS this profile's DB.
///
/// Unlike [`LINK_STATE_KEY`] (cleared on unlink) this SURVIVES unlink/relink and NEVER changes once
/// set — it is the answer to "which account does this data dir belong to?". The value is the profile
/// name the DB was first booted as: an opaque account id, or [`super::token::LOCAL_PROFILE`] for the
/// anonymous base home. It is the anchor for the fail-closed boot assertion (a daemon told to serve
/// profile `<X>` whose DB is stamped `<Y>` refuses to serve) and the request-time account binding.
pub const PROFILE_OWNER_KEY: &str = "profile.owner_account_id";

/// The account id that owns this profile's DB, or `None` if it has never been stamped (a fresh /
/// pre-guard DB — the boot assertion will adopt the current profile as owner).
pub async fn profile_owner(pool: &SqlitePool) -> LocalResult<Option<String>> {
    Ok(config_kv::get(pool, PROFILE_OWNER_KEY).await?.filter(|s| !s.is_empty()))
}

/// Durably stamp the owner of this profile's DB. Set ONCE (adopt-on-first-boot); callers must not
/// overwrite an existing owner — a change of owner is exactly the isolation violation we guard.
pub async fn set_profile_owner(pool: &SqlitePool, owner: &str) -> LocalResult<()> {
    config_kv::set(pool, PROFILE_OWNER_KEY, owner).await?;
    tracing::debug!(owner = %owner, "profile owner stamped");
    Ok(())
}

/// Whether the user opted to run the app with no cloud account (local-only). Read live by
/// `/v1/cloud/status` so a choice takes effect immediately (no daemon restart).
pub async fn local_only(pool: &SqlitePool) -> LocalResult<bool> {
    Ok(config_kv::get(pool, LOCAL_ONLY_KEY).await?.as_deref() == Some("true"))
}

/// Persist (or clear) the local-only choice. `true` lets the user into the app with no cloud account;
/// `false` removes the flag (so the login gate applies again).
pub async fn set_local_only(pool: &SqlitePool, enabled: bool) -> LocalResult<()> {
    if enabled {
        config_kv::set(pool, LOCAL_ONLY_KEY, "true").await?;
    } else {
        let _ = config_kv::delete(pool, LOCAL_ONLY_KEY).await?;
    }
    tracing::debug!(enabled, "cloud local-only choice updated");
    Ok(())
}

/// Non-secret metadata describing the currently linked cloud account.
///
/// `#[serde(default)]` so older/sparser persisted blobs load forward without error.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct LinkState {
    /// Cloud account / user id (opaque server id). Empty until linked.
    pub account_id: String,
    /// Account email for display in the UI. Empty if unknown / not linked.
    pub email: String,
    /// Cloud API base url this account is linked against (no trailing slash), e.g.
    /// `https://api.usewrit.app`. Falls back to the build/env default when empty.
    pub cloud_base_url: String,
    /// OAuth scopes the link was granted, as returned by the token endpoint. REFLECTION-ONLY:
    /// drives UI/upsell, never an authorization decision.
    pub scopes: Vec<String>,
    /// RFC3339 UTC timestamp of when the link was established/last refreshed metadata.
    pub linked_at: Option<chrono::DateTime<chrono::Utc>>,
    /// The linked user's preferred UI language (BCP-47 base code: `en`/`fr`/`es`), as reflected by
    /// the cloud at link time. `None` when the user never set one. REFLECTION-ONLY: a UI hint the
    /// desktop adopts on first link when the user hasn't chosen a language locally.
    pub language: Option<String>,
}

impl LinkState {
    /// True when an account id is present (i.e. the desktop is linked to a cloud account).
    /// Note: presence of metadata does NOT imply a valid token — the token lives in the keyring and
    /// may have been independently cleared/revoked. Treat this as a UI hint only.
    pub fn is_linked(&self) -> bool {
        !self.account_id.is_empty()
    }

    /// The configured base url with any trailing slashes trimmed, or `None` if unset.
    pub fn base_url(&self) -> Option<&str> {
        let trimmed = self.cloud_base_url.trim_end_matches('/');
        if trimmed.is_empty() {
            None
        } else {
            Some(trimmed)
        }
    }

    /// True if `scope` appears in the granted set. UI/upsell reflection only — NOT an auth gate.
    pub fn has_scope(&self, scope: &str) -> bool {
        self.scopes.iter().any(|s| s == scope)
    }

    /// Load the persisted link state, or `None` if the desktop has never been linked.
    pub async fn load(pool: &SqlitePool) -> LocalResult<Option<Self>> {
        match config_kv::get(pool, LINK_STATE_KEY).await? {
            Some(raw) => {
                let state: LinkState = serde_json::from_str(&raw)?;
                Ok(Some(state))
            }
            None => Ok(None),
        }
    }

    /// Load the persisted link state, or `LinkState::default()` (unlinked) if absent.
    pub async fn load_or_default(pool: &SqlitePool) -> LocalResult<Self> {
        Ok(Self::load(pool).await?.unwrap_or_default())
    }

    /// Persist (upsert) this link state as JSON in the encrypted `config` kv table.
    pub async fn save(&self, pool: &SqlitePool) -> LocalResult<()> {
        let raw = serde_json::to_string(self)?;
        config_kv::set(pool, LINK_STATE_KEY, &raw).await?;
        // Do NOT log scopes/email at info level beyond what's needed; account_id is an opaque id.
        tracing::debug!(account_id = %self.account_id, "cloud link state saved");
        Ok(())
    }

    /// Remove the persisted link metadata (unlink). Returns `true` if a row was removed. Callers
    /// MUST also clear the keyring token via [`super::token::clear`] to fully unlink.
    pub async fn clear(pool: &SqlitePool) -> LocalResult<bool> {
        let removed = config_kv::delete(pool, LINK_STATE_KEY).await?;
        tracing::debug!(removed, "cloud link state cleared");
        Ok(removed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::local::config::Paths;
    use crate::local::db;
    use crate::local::vault::Vault;

    /// Open a fresh encrypted DB keyed by a throwaway (no-keyring) vault.
    async fn fresh_pool() -> (tempfile::TempDir, SqlitePool) {
        let dir = tempfile::tempdir().unwrap();
        let paths = Paths::at(dir.path().join(".writ"));
        paths.ensure_dirs().unwrap();
        let vault = Vault::load_or_create(&paths.root, false).unwrap();
        let pool = db::open(&paths.db(), &vault.db_key_hex()).await.unwrap();
        (dir, pool)
    }

    #[tokio::test]
    async fn save_load_clear_roundtrip() {
        let (_dir, pool) = fresh_pool().await;

        // Absent → None / default.
        assert!(LinkState::load(&pool).await.unwrap().is_none());
        assert_eq!(LinkState::load_or_default(&pool).await.unwrap(), LinkState::default());

        let state = LinkState {
            account_id: "acct_123".into(),
            email: "user@example.com".into(),
            cloud_base_url: "https://api.usewrit.app/".into(),
            scopes: vec!["workflows:run".into(), "marketplace:read".into()],
            linked_at: Some(chrono::Utc::now()),
            language: Some("fr".into()),
        };
        state.save(&pool).await.unwrap();

        let loaded = LinkState::load(&pool).await.unwrap().expect("present after save");
        assert_eq!(loaded, state);
        assert!(loaded.is_linked());
        assert!(loaded.has_scope("workflows:run"));
        assert!(!loaded.has_scope("nope"));
        // Trailing slash trimmed by base_url().
        assert_eq!(loaded.base_url(), Some("https://api.usewrit.app"));

        // Clear removes it.
        assert!(LinkState::clear(&pool).await.unwrap());
        assert!(LinkState::load(&pool).await.unwrap().is_none());
        assert!(!LinkState::clear(&pool).await.unwrap(), "second clear is a no-op");
    }

    #[test]
    fn default_is_unlinked() {
        let s = LinkState::default();
        assert!(!s.is_linked());
        assert_eq!(s.base_url(), None);
        assert!(s.scopes.is_empty());
    }

    #[tokio::test]
    async fn local_only_choice_roundtrip() {
        let (_dir, pool) = fresh_pool().await;
        // Absent → false.
        assert!(!local_only(&pool).await.unwrap());
        // Set → true.
        set_local_only(&pool, true).await.unwrap();
        assert!(local_only(&pool).await.unwrap());
        // Clear → false (and idempotent).
        set_local_only(&pool, false).await.unwrap();
        assert!(!local_only(&pool).await.unwrap());
        set_local_only(&pool, false).await.unwrap();
        assert!(!local_only(&pool).await.unwrap());
    }
}
