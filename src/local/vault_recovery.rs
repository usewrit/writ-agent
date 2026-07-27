//! Vault recovery — a BIP39 mnemonic that wraps a SECOND copy of the keyring root, so a user who
//! loses their OS keyring (or forgets the app-lock passphrase) can still recover the root and
//! re-enroll. SECURITY_AND_ENTITLEMENTS_SPEC §1.3: "Recovery (force at PIN-enable): BIP39 recovery
//! code → a second wrapped copy of the root … No silent cloud key escrow."
//!
//! ## Construction
//! `generate_recovery()` mints 32 bytes of fresh CSPRNG entropy → a 24-word BIP39 mnemonic, derives
//! a 256-bit wrapping key from that mnemonic via HKDF-SHA512 (info `"writ-recovery-v1"`), and stores
//! `recovery_wrap = root XOR wrap_key` in `config` (NON-secret: the root XORed with a 256-bit key
//! never reveals the root without the mnemonic). The mnemonic is returned to the caller ONCE for the
//! user to write down — it is NEVER persisted, NEVER logged.
//!
//! `restore_from(mnemonic)` re-derives the same wrap key, XORs it back into the stored wrap to
//! recover the CANDIDATE root, and (when a live keyring root is available) constant-time verifies it.
//! The recovered [`RootKey`] is handed back so the caller can persist it as the new keyring root /
//! re-enroll an app-lock passphrase. The recovered root is never logged.
//!
//! The mnemonic is the ONLY secret in this flow and it lives exclusively in the user's head / on
//! paper. NEVER log the mnemonic, the wrap key, or the recovered root.
//!
//! Net-new Rust in this crate (behind the `local` feature).

use base64::Engine;
use bip39::Mnemonic;
use hkdf::Hkdf;
use rand::RngCore;
use sha2::Sha512;
use sqlx::SqlitePool;
use zeroize::Zeroize;

use crate::local::error::{LocalError, LocalResult};
use crate::local::store::config_kv;
use crate::local::vault::{RootKey, Vault};

/// `config` KV key for the recovery wrap (root XOR HKDF(mnemonic)). NON-secret without the mnemonic.
const CFG_RECOVERY_WRAP: &str = "vault_recovery.wrap_b64";

/// HKDF-SHA512 info label binding the recovery wrap key to this purpose (independent of K_db /
/// K_field / K_file and of the app-lock derivation).
const RECOVERY_INFO: &[u8] = b"writ-recovery-v1";

/// Derive the 256-bit recovery wrap key from a mnemonic's entropy (the canonical 32-byte BIP39
/// entropy, NOT the 64-byte PBKDF2 seed — keeps the wrap independent of any passphrase). HKDF-SHA512
/// with a fixed info label. Returns a zeroizing key; NEVER log it.
fn wrap_key_from_mnemonic(mnemonic: &Mnemonic) -> RootKey {
    let mut entropy = mnemonic.to_entropy(); // 16..32 bytes depending on word count
    let hk = Hkdf::<Sha512>::new(None, &entropy);
    entropy.zeroize();
    let mut okm = [0u8; 32];
    hk.expand(RECOVERY_INFO, &mut okm).expect("32 is a valid HKDF-SHA512 output length");
    let key = RootKey::from_bytes(okm);
    okm.zeroize();
    key
}

/// base64-encode raw bytes (standard alphabet).
fn b64(bytes: &[u8]) -> String {
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

/// Decode a base64 string into a fixed 32-byte array (the wrap is always 32 bytes).
fn unb64_32(s: &str) -> LocalResult<[u8; 32]> {
    let raw = base64::engine::general_purpose::STANDARD
        .decode(s.as_bytes())
        .map_err(|_| LocalError::Internal("recovery: bad wrap base64".into()))?;
    if raw.len() != 32 {
        return Err(LocalError::Internal("recovery: wrap is not 32 bytes".into()));
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&raw);
    Ok(out)
}

/// Is a recovery wrap configured for this vault?
pub async fn is_configured(db: &SqlitePool) -> LocalResult<bool> {
    Ok(config_kv::get(db, CFG_RECOVERY_WRAP).await?.is_some())
}

/// Mint a fresh BIP39 recovery mnemonic, store `recovery_wrap = root XOR HKDF(mnemonic)` in `config`,
/// and return the 24-word mnemonic string ONCE for the user to record. Overwrites any prior recovery
/// wrap (re-issuing invalidates the old code). NEVER logs the mnemonic.
///
/// 32 bytes of entropy → a 24-word mnemonic (the strongest BIP39 size).
pub async fn generate_recovery(db: &SqlitePool, vault: &Vault) -> LocalResult<String> {
    let mut entropy = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut entropy);
    let mnemonic = Mnemonic::from_entropy(&entropy)
        .map_err(|e| LocalError::Internal(format!("recovery: mnemonic gen: {e}")))?;
    entropy.zeroize();

    let wrap_key = wrap_key_from_mnemonic(&mnemonic);
    let wrap = vault.root_copy().xor(wrap_key.as_bytes()); // root XOR HKDF(mnemonic)
    config_kv::set(db, CFG_RECOVERY_WRAP, &b64(wrap.as_bytes())).await?;

    tracing::info!("vault recovery code generated (mnemonic returned to caller, not stored)");
    Ok(mnemonic.to_string())
}

/// Recover the root from a recovery mnemonic. Re-derives the wrap key, XORs it back into the stored
/// wrap to obtain the CANDIDATE root, and — when a live keyring root is present — constant-time
/// verifies the candidate against it (a correct mnemonic reproduces the root exactly). Returns the
/// recovered [`RootKey`] (zeroizing) so the caller can persist it / re-enroll. NEVER logs the
/// mnemonic or the recovered root.
///
/// `expected` is the live keyring root when available (normal "I forgot my passphrase" recovery on a
/// machine whose keyring is intact); pass `None` for true keyring-loss recovery where there is
/// nothing to verify against (the recovered root IS the source of truth then).
pub async fn restore_from(
    db: &SqlitePool,
    mnemonic_phrase: &str,
    expected: Option<&RootKey>,
) -> LocalResult<RootKey> {
    let wrap_b64 = config_kv::get(db, CFG_RECOVERY_WRAP)
        .await?
        .ok_or_else(|| LocalError::BadRequest("no recovery code is configured for this vault".into()))?;
    let mnemonic = Mnemonic::parse(mnemonic_phrase.trim())
        .map_err(|_| LocalError::BadRequest("recovery code is not a valid mnemonic".into()))?;

    let wrap_key = wrap_key_from_mnemonic(&mnemonic);
    let wrap = unb64_32(&wrap_b64)?;
    let candidate = RootKey::from_bytes(wrap).xor(wrap_key.as_bytes()); // wrap XOR key = candidate root

    if let Some(exp) = expected {
        if !candidate.ct_eq(exp) {
            tracing::warn!("vault recovery failed (mnemonic does not reproduce the root)");
            return Err(LocalError::Unauthorized);
        }
    }
    tracing::info!("vault root recovered from mnemonic");
    Ok(candidate)
}

/// Re-wrap the stored recovery wrap from `old_root` to `new_root` during a vault rotation, WITHOUT
/// the mnemonic (which lives only in the user's head). Correctness relies on the wrap being a pure
/// XOR: `stored_wrap = old_root XOR K` where `K = HKDF(mnemonic)`. So `K = old_root XOR stored_wrap`
/// is recoverable from what we already hold, and the new wrap is `new_root XOR K` — which the SAME
/// unchanged mnemonic still unwraps. Without this, a rotation leaves `wrap_b64` binding the OLD root,
/// so the user's written-down recovery code silently returns a stale (now-wrong) root (DL-2).
///
/// A no-op (returns `Ok(())`) when no recovery wrap is configured. NEVER logs any key material.
pub async fn rewrap_for_new_root(
    db: &SqlitePool,
    old_root: &RootKey,
    new_root: &RootKey,
) -> LocalResult<()> {
    let Some(wrap_b64) = config_kv::get(db, CFG_RECOVERY_WRAP).await? else {
        return Ok(()); // no recovery code enrolled → nothing to migrate
    };
    let stored = RootKey::from_bytes(unb64_32(&wrap_b64)?);
    // K = HKDF(mnemonic) = old_root XOR stored_wrap; new_wrap = new_root XOR K.
    let k = old_root.xor(stored.as_bytes());
    let new_wrap = new_root.xor(k.as_bytes());
    config_kv::set(db, CFG_RECOVERY_WRAP, &b64(new_wrap.as_bytes())).await?;
    tracing::info!("re-wrapped the vault recovery code for the rotated root (mnemonic unchanged)");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::local::db;

    async fn fixture() -> (tempfile::TempDir, SqlitePool, Vault) {
        let dir = tempfile::tempdir().unwrap();
        let vault = Vault::load_or_create(dir.path(), false).unwrap();
        let pool = db::open(&dir.path().join("t.db"), &vault.db_key_hex()).await.unwrap();
        (dir, pool, vault)
    }

    #[tokio::test]
    async fn generate_then_restore_roundtrips() {
        let (_dir, pool, vault) = fixture().await;
        assert!(!is_configured(&pool).await.unwrap());

        let phrase = generate_recovery(&pool, &vault).await.unwrap();
        assert_eq!(phrase.split_whitespace().count(), 24, "32B entropy → 24 words");
        assert!(is_configured(&pool).await.unwrap());

        // Correct mnemonic recovers EXACTLY the keyring root (verified against the live root).
        let live = vault.root_copy();
        let recovered = restore_from(&pool, &phrase, Some(&live)).await.unwrap();
        assert!(recovered.ct_eq(&live), "recovered root must equal the keyring root");

        // Keyring-loss path (no expected root): still returns the recovered root.
        let recovered2 = restore_from(&pool, &phrase, None).await.unwrap();
        assert!(recovered2.ct_eq(&live));
    }

    #[tokio::test]
    async fn rewrap_keeps_mnemonic_valid_after_rotation() {
        // DL-2: after a root rotation re-wraps the recovery blob for the NEW root, the user's UNCHANGED
        // mnemonic must reproduce the NEW root (not the stale old one).
        let (_dir, pool, vault) = fixture().await;
        let phrase = generate_recovery(&pool, &vault).await.unwrap();
        let old_root = vault.root_copy();

        // Simulate a rotation to a fresh root and re-wrap for it.
        let mut raw = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut raw);
        let new_root = RootKey::from_bytes(raw);
        raw.zeroize();
        rewrap_for_new_root(&pool, &old_root, &new_root).await.unwrap();

        // The same mnemonic now recovers the NEW root, and is verified against it.
        let recovered = restore_from(&pool, &phrase, Some(&new_root)).await.unwrap();
        assert!(recovered.ct_eq(&new_root), "mnemonic must reproduce the rotated root");
        // It must NO LONGER reproduce the old root (the wrap moved on).
        assert!(!recovered.ct_eq(&old_root), "mnemonic must not still map to the old root");
    }

    #[tokio::test]
    async fn rewrap_is_a_noop_without_a_configured_recovery() {
        // No recovery enrolled → re-wrap is a clean no-op (nothing to migrate, no wrap written).
        let (_dir, pool, _vault) = fixture().await;
        let a = RootKey::from_bytes([1u8; 32]);
        let b = RootKey::from_bytes([2u8; 32]);
        rewrap_for_new_root(&pool, &a, &b).await.unwrap();
        assert!(!is_configured(&pool).await.unwrap(), "no wrap should be created");
    }

    #[tokio::test]
    async fn wrong_mnemonic_is_rejected_when_verifiable() {
        let (_dir, pool, vault) = fixture().await;
        let _phrase = generate_recovery(&pool, &vault).await.unwrap();

        // A DIFFERENT valid mnemonic must not verify against the live root.
        let mut other_entropy = [9u8; 32];
        other_entropy[0] = 1;
        let other = Mnemonic::from_entropy(&other_entropy).unwrap().to_string();
        let live = vault.root_copy();
        let err = restore_from(&pool, &other, Some(&live)).await.unwrap_err();
        assert!(matches!(err, LocalError::Unauthorized));
    }

    #[tokio::test]
    async fn invalid_phrase_is_bad_request() {
        let (_dir, pool, vault) = fixture().await;
        let _ = generate_recovery(&pool, &vault).await.unwrap();
        let err = restore_from(&pool, "not a real mnemonic phrase at all", None).await.unwrap_err();
        assert!(matches!(err, LocalError::BadRequest(_)));
    }

    #[tokio::test]
    async fn restore_without_config_is_bad_request() {
        let (_dir, pool, _vault) = fixture().await;
        // 24 valid words but no wrap configured.
        let words = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art";
        let err = restore_from(&pool, words, None).await.unwrap_err();
        assert!(matches!(err, LocalError::BadRequest(_)));
    }
}
