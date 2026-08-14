//! OS-keyring storage of the per-agent **channel key** minted at device-link.
//!
//! The channel key is a `cryptography.fernet.Fernet` key (URL-safe base64, 32 raw bytes) that the
//! cloud mints per agent at device-link (the cloud backend's `oauth` router). It seals credential/recipe
//! material *in transit* so the daemon — and only the daemon — can unseal blobs the cloud encrypts
//! for THIS agent (e.g. the marketplace `sealed-recipe`). It is the symmetric counterpart to the
//! server-side `agent_channel_key:{...}` Redis entry.
//!
//! SECURITY (SECURITY_AND_ENTITLEMENTS_SPEC §0 + the never-trust-a-BYO-agent rule):
//! the channel key is a SECRET on the same footing as the account token. It is stored ONLY in the OS
//! keyring under the `writ-cloud` service — NEVER in `writ.db`, NEVER on disk, NEVER logged. It must
//! NEVER cross into the webview: webview callers hit the loopback API with the `wlt_` bearer only; the
//! daemon unseals on their behalf.
//!
//! MULTI-PROFILE (CR-9): the channel key is PER-AGENT/per-account, so its keyring account key is scoped
//! by the active profile — `channel:<profile>` — exactly like [`super::token`] scopes the account token
//! by profile. A single fixed `channel` slot would let a second linked account overwrite the first's
//! key. For installs linked before this scoping existed, [`get`] falls back to (and best-effort
//! migrates) the legacy fixed `channel` slot so an already-linked user does not break.
//!
//! The in-memory copy is wrapped in [`secrecy::Secret`] so it is redacted on `Debug` and zeroized on
//! drop, exactly like [`super::token::TokenPair`]. The key VALUE is never passed to `tracing`.
//!
//! Net-new Rust in this crate (marketplace protected-executor — daemon stage 1).

use super::super::error::{LocalError, LocalResult};
use secrecy::{ExposeSecret, Secret};

/// Keyring service for the cloud channel key — shared with the account token, distinct account.
pub const KEYRING_SERVICE: &str = "writ-cloud";
/// Legacy (pre-CR-9) fixed keyring account for the per-agent Fernet channel key. Retained ONLY as a
/// read fallback + one-time migration source for installs linked before per-profile scoping.
pub const LEGACY_KEYRING_ACCOUNT: &str = "channel";

/// The per-profile keyring account for the channel key: `channel:<active-profile>`, mirroring how
/// [`super::token`] scopes the account token by profile. Keeps a second linked account from clobbering
/// the first's channel key.
fn keyring_account() -> String {
    format!("channel:{}", super::token::active_profile())
}

/// The per-agent Fernet channel key, held only transiently in memory.
///
/// Wraps the raw key in [`secrecy::Secret`] so it never appears in logs/`Debug` output and is
/// zeroized on drop. Use [`ChannelKey::expose`] only where the value is genuinely needed (Fernet
/// decrypt of a cloud-sealed blob) — never log it.
#[derive(Clone)]
pub struct ChannelKey(Secret<String>);

impl std::fmt::Debug for ChannelKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // NEVER print key material.
        f.debug_tuple("ChannelKey").field(&"<redacted>").finish()
    }
}

impl ChannelKey {
    /// Build a channel key from an owned string (e.g. parsed from the device-token response).
    pub fn new(key: String) -> Self {
        Self(Secret::new(key))
    }

    /// Borrow the key plaintext (Fernet decrypt only — never log it).
    pub fn expose(&self) -> &str {
        self.0.expose_secret()
    }
}

fn entry_for(account: &str) -> LocalResult<keyring::Entry> {
    crate::local::keyring_store::new_entry(KEYRING_SERVICE, account)
        .map_err(|e| LocalError::Internal(format!("keyring open: {e}")))
}

/// The per-profile channel-key entry.
fn entry() -> LocalResult<keyring::Entry> {
    entry_for(&keyring_account())
}

/// Read one keyring entry's non-blank value, mapping `NoEntry` → `None`.
fn read_entry(account: &str) -> LocalResult<Option<String>> {
    match entry_for(account)?.get_password() {
        Ok(s) if !s.trim().is_empty() => Ok(Some(s)),
        Ok(_) => Ok(None),
        Err(keyring::Error::NoEntry) => Ok(None),
        Err(e) => Err(LocalError::Internal(format!("keyring get: {e}"))),
    }
}

/// Load the stored channel key, or `None` if the desktop has none (not linked, older link, or
/// cleared). A blank stored value is treated as absent.
///
/// Reads the per-profile slot first; if empty, falls back to the legacy fixed slot and best-effort
/// migrates it into the per-profile slot so pre-CR-9 installs keep working after the first read.
pub fn get() -> LocalResult<Option<ChannelKey>> {
    if let Some(raw) = read_entry(&keyring_account())? {
        return Ok(Some(ChannelKey::new(raw)));
    }
    // Legacy fixed slot (installs linked before per-profile scoping).
    if let Some(raw) = read_entry(LEGACY_KEYRING_ACCOUNT)? {
        // Best-effort migration into the per-profile slot; a failure is non-fatal (we still return the
        // key), we just retry the migration on the next read.
        if let Err(e) = set(&raw) {
            tracing::warn!(error = %e, "could not migrate legacy channel key to the per-profile slot");
        }
        return Ok(Some(ChannelKey::new(raw)));
    }
    Ok(None)
}

/// Store (overwrite) the channel key in the OS keyring (per-profile slot). NEVER logs the key value.
pub fn set(key: &str) -> LocalResult<()> {
    entry()?
        .set_password(key)
        .map_err(|e| LocalError::Internal(format!("keyring set: {e}")))?;
    tracing::debug!("cloud channel key stored");
    Ok(())
}

/// Delete the channel key from the keyring. Idempotent: a missing entry is a no-op. Clears BOTH the
/// per-profile slot and the legacy fixed slot so an unlink leaves nothing behind.
/// Returns `true` if any entry was actually removed.
///
/// BOTH slots are always attempted — a failure on one must not skip the other, or an unlink that
/// trips on the per-profile slot would silently leave a usable legacy key behind. The error (first
/// one seen) is still returned, so the caller learns a key survived.
pub fn clear() -> LocalResult<bool> {
    let mut removed = false;
    let mut failure: Option<LocalError> = None;
    for account in [keyring_account(), LEGACY_KEYRING_ACCOUNT.to_string()] {
        let deleted = entry_for(&account).and_then(|e| match e.delete_credential() {
            Ok(()) => Ok(true),
            Err(keyring::Error::NoEntry) => Ok(false),
            Err(e) => Err(LocalError::Internal(format!("keyring delete: {e}"))),
        });
        match deleted {
            Ok(true) => removed = true,
            Ok(false) => {}
            Err(e) => {
                failure.get_or_insert(e);
            }
        }
    }
    if let Some(e) = failure {
        return Err(e);
    }
    if removed {
        tracing::debug!("cloud channel key cleared");
    }
    Ok(removed)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn channel_key_redacts_and_exposes() {
        let k = ChannelKey::new("ck_super_secret_fernet_key".into());
        // Debug must NOT leak key material.
        let dbg = format!("{k:?}");
        assert!(!dbg.contains("ck_super_secret_fernet_key"));
        assert!(dbg.contains("redacted"));
        // Explicit exposure still works for the Fernet layer.
        assert_eq!(k.expose(), "ck_super_secret_fernet_key");
    }
}
