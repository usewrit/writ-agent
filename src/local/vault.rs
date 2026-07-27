//! Vault — key hierarchy + field-level AEAD (Layer B), on top of the SQLCipher DB (Layer A).
//!
//! OS-keyring-rooted random 32-byte root → HKDF-SHA512 subkeys (K_db / K_field / K_file).
//! Secret columns are sealed with XChaCha20-Poly1305 (magic `WF1`), AAD-bound to table|column|row
//! so ciphertext can't be relocated. See the security-and-entitlements spec Part 1.
//!
//! Net-new Rust in this crate — NOT ported from the legacy Python `desktop-agent`.

use super::error::{LocalError, LocalResult};
use base64::Engine;
use chacha20poly1305::aead::{Aead, Payload};
use chacha20poly1305::{Key, KeyInit, XChaCha20Poly1305, XNonce};
use hkdf::Hkdf;
use rand::RngCore;
use secrecy::{ExposeSecret, Secret};
use sha2::Sha512;
use std::path::Path;
use zeroize::Zeroize;

const KEYRING_SERVICE: &str = "writ-vault";
/// Legacy/base keyring account. Used for the anonymous `local` (base-home) profile — kept as-is so
/// existing installs need NO migration — and as the shared root that pre-per-profile keyring-mode
/// installs stored every account's key under (the isolation gap this module now closes).
const KEYRING_ACCOUNT_LOCAL: &str = "master";
/// Env var the shell sets to select the active profile/home (mirrors `cloud::token::ENV_PROFILE`;
/// read directly here so `vault` carries no dependency on the cloud module / build feature).
const ENV_PROFILE: &str = "WRIT_PROFILE";
const FIELD_MAGIC: &str = "WF1:";

/// The OS-keyring account under which THIS profile's vault root is stored.
///
/// PER-ACCOUNT ISOLATION: the base/`local` home keeps the legacy `"master"` account (zero migration
/// for existing installs); every cloud ACCOUNT profile gets its own `"v1-<account_id>"` account so
/// each account's DB derives a DISTINCT SQLCipher key even under keyring custody. Before this, keyring
/// mode stored one shared `"master"` root for every profile, so all accounts' DBs shared one key.
fn keyring_account() -> String {
    match std::env::var(ENV_PROFILE) {
        Ok(p) if !p.trim().is_empty() && p.trim() != "local" => format!("v1-{}", p.trim()),
        _ => KEYRING_ACCOUNT_LOCAL.to_string(),
    }
}

/// Transient OS-keyring account holding the NEW root DURING a vault rotation (the crash-recovery
/// journal). Scoped per profile like [`keyring_account`] so one account's in-flight rotation never
/// collides with another's. Lets keyring-custody installs journal the new root in the keyring instead
/// of writing the raw root to disk in cleartext.
fn rotation_keyring_account() -> String {
    format!("{}::rotate", keyring_account())
}

/// File-blob container magic (Layer C, K_file). On-disk envelope for `~/.writ/files` bytes:
/// `WFB1` || u32-LE chunk_size || 24-byte base nonce || [ chunk_ct ... ] where each chunk is an
/// XChaCha20-Poly1305 sealing of up to `chunk_size` plaintext bytes. The per-chunk nonce is the
/// base nonce with its last 8 bytes overwritten by the big-endian chunk counter, and the FINAL
/// chunk's nonce additionally has its first byte XORed with `0x01` (a STREAM-style last-block tag)
/// so truncating the file is detected on decrypt. Bytes on disk are therefore always encrypted.
const FILE_MAGIC: &[u8; 4] = b"WFB1";
/// Plaintext bytes sealed per chunk (64 KiB). Each on-disk chunk is this + 16 (Poly1305 tag).
const FILE_CHUNK_SIZE: usize = 64 * 1024;
/// Fixed envelope header length: magic(4) + chunk_size(4) + base nonce(24).
const FILE_HEADER_LEN: usize = 4 + 4 + 24;

/// Holds the keyring-rooted 32-byte root key; derives purpose-scoped subkeys on demand.
pub struct Vault {
    root: Secret<[u8; 32]>,
}

impl Vault {
    /// Load or create the root key. Prefers the OS keyring; falls back to a `0600` `dir/vault.key`.
    /// The root NEVER lands in `writ.db`. `use_keyring=false` is for tests/headless (no Keychain prompt).
    ///
    /// AT-REST KEY CUSTODY (SECURITY): when the keyring is enabled AND holds the root, the plaintext
    /// `vault.key` fallback is NOT written — and any stale copy is removed. A plaintext key file next
    /// to the encrypted DB would negate the keychain entirely (anyone who can read `~/.writ` — malware
    /// as the user, a folder sync, a backup — could then decrypt everything). We only ever persist the
    /// `0600` file when the keyring is disabled or unavailable. Deletion of the file is gated on a
    /// verified keyring round-trip, so we never drop the only copy of the key.
    pub fn load_or_create(dir: &Path, use_keyring: bool) -> LocalResult<Self> {
        let path = dir.join("vault.key");
        let account = keyring_account();
        if use_keyring {
            if let Some(root) = Self::keyring_get(&account)? {
                // Keyring is the store → the plaintext fallback must not linger beside the ciphertext,
                // BUT only drop `vault.key` when it byte-matches the keyring root (DL-1). If a rotation
                // persisted the NEW root to `vault.key` while the keyring write silently failed, the
                // keyring still holds the OLD root; deleting the file would strand the rekeyed DB under
                // a root that exists nowhere. When they differ we KEEP the file (the durable copy of
                // record) and return the keyring root untouched.
                if Self::file_matches_root(&path, &root) {
                    Self::remove_key_file_if_present(&path);
                }
                return Ok(Self { root: Secret::new(root) });
            }
            // No per-profile keyring root yet. If this is a cloud ACCOUNT profile (account != master)
            // whose DB ALREADY EXISTS with no per-profile plaintext fallback, it was encrypted under
            // the legacy SHARED "master" root (the pre-per-profile keyring behaviour). Adopt that root
            // so the DB still decrypts — bricking it would be catastrophic — and seed the per-profile
            // account with it (best-effort) so future boots resolve directly. NOTE: this preserves
            // decryptability but keeps the key SHARED for these pre-existing profiles; a `vault_rotate`
            // pass gives them a fresh, isolated root. Fresh account profiles (no DB yet) skip this and
            // mint an isolated root below — the isolation win for everything created from here on.
            if account != KEYRING_ACCOUNT_LOCAL && dir.join("writ.db").exists() {
                if let Some(master_root) = Self::keyring_get(KEYRING_ACCOUNT_LOCAL)? {
                    let _ = Self::keyring_set(&account, &master_root); // best-effort seed
                    tracing::warn!(
                        "adopted the shared legacy vault root for this account profile to preserve \
                         decryptability; run a key rotation to give it a fully isolated key"
                    );
                    return Ok(Self { root: Secret::new(master_root) });
                }
            }
        }
        if let Some(root) = Self::file_get(&path)? {
            // Loaded from the plaintext fallback. If the keyring is enabled, MIGRATE the root into it
            // and (only after a verified round-trip) drop the on-disk copy, so the key stops living in
            // plaintext next to the DB.
            if use_keyring && Self::keyring_store_verified(&root) {
                Self::remove_key_file_if_present(&path);
                tracing::info!("migrated vault root from the plaintext fallback into the OS keyring");
            }
            return Ok(Self { root: Secret::new(root) });
        }
        // ------------------------------------------------------------------ //
        // FAIL CLOSED before minting a root over an EXISTING database.        //
        // ------------------------------------------------------------------ //
        //
        // Reaching here means no root was found in the keyring and none on disk. If a non-empty
        // `writ.db` already exists, minting a fresh random root is catastrophic and SILENT: the new
        // key cannot decrypt the old ciphertext, so `db::open` gets SQLite code 26, treats it as
        // "unreadable", renames the live DB to `writ.db.corrupt-<ts>` and starts an empty one. The
        // worker then boots with zero deployed workflows/secrets/personas, reports healthy, and
        // re-accepts dispatch — while every stored credential sits in a quarantined file. Second boot
        // is unrecoverable by the built-in logic, because the live path now holds a readable (empty) DB.
        //
        // Real-world triggers: a macOS keychain reset or a new login (the keyring path DELETES
        // `vault.key` once the keyring holds the root), or a container that bind-mounts
        // `/data/writ.db` alone instead of the whole `/data` directory.
        //
        // The DB is data we cannot reconstruct and the key is recoverable (keyring entry, backup,
        // recovery mnemonic), so refusing to boot is strictly better than a silent wipe. The one
        // legitimate "existing DB, new root" case — a pre-per-profile account profile adopting the
        // shared master root — is handled above and returns before this point.
        let db_path = dir.join("writ.db");
        let db_has_content = std::fs::metadata(&db_path).map(|m| m.len() > 0).unwrap_or(false);
        if db_has_content {
            return Err(LocalError::Internal(format!(
                "vault: refusing to mint a NEW vault root while an existing encrypted database is \
                 present at {}. The root that encrypted it could not be found ({}). Minting a new \
                 one would quarantine that database and start empty, losing every stored workflow, \
                 secret and persona.\n\
                 \n\
                 Recover the key, then restart:\n\
                 \x20 * restore `{}` from your backup (mode 0600), or\n\
                 \x20 * re-add the root to the OS keyring, or\n\
                 \x20 * restore from a `writ` backup archive, or\n\
                 \x20 * recover the root from your BIP39 recovery mnemonic.\n\
                 \n\
                 If this database really is disposable, move it aside deliberately \
                 (`mv writ.db writ.db.discarded`) and restart to begin fresh.",
                db_path.display(),
                if use_keyring { "keyring entry missing and no vault.key fallback" } else { "no vault.key present" },
                path.display(),
            )));
        }

        // First run: mint a fresh random root.
        let mut root = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut root);
        // Prefer the OS keyring. Only fall back to the `0600` `vault.key` file when the keyring is
        // disabled OR the store+read-back verification fails — never keep a plaintext copy alongside a
        // working keyring entry.
        let stored_in_keyring = use_keyring && Self::keyring_store_verified(&root);
        if !stored_in_keyring {
            Self::file_set(&path, &root)?;
        }
        let v = Self { root: Secret::new(root) };
        root.zeroize();
        Ok(v)
    }

    /// Store `root` under THIS profile's keyring account and CONFIRM it reads back byte-identically.
    /// Returns `true` only on a verified round-trip — the caller then knows it is safe to skip or
    /// remove the plaintext `vault.key`, guaranteeing the key is never left with zero durable copies.
    fn keyring_store_verified(root: &[u8; 32]) -> bool {
        let account = keyring_account();
        if Self::keyring_set(&account, root).is_err() {
            return false;
        }
        matches!(Self::keyring_get(&account), Ok(Some(rb)) if &rb == root)
    }

    /// Does the on-disk `vault.key` at `path` hold exactly `root`? Used to gate deletion of the
    /// plaintext fallback (DL-1): we only remove it when it byte-matches the keyring root, so a
    /// divergent file (e.g. a rotation that persisted a new root to the file but couldn't confirm the
    /// keyring write) is preserved rather than destroyed. A missing/unreadable/short file → `false`
    /// (nothing to safely delete). Comparison is constant-time; the read copy is zeroized.
    fn file_matches_root(path: &Path, root: &[u8; 32]) -> bool {
        match Self::file_get(path) {
            Ok(Some(mut on_disk)) => {
                let mut diff = 0u8;
                for i in 0..32 {
                    diff |= on_disk[i] ^ root[i];
                }
                on_disk.zeroize();
                diff == 0
            }
            _ => false,
        }
    }

    /// Best-effort removal of the plaintext `vault.key` fallback once the keyring holds the root. Never
    /// fatal — a lingering file is a defense-in-depth concern, not a correctness one.
    fn remove_key_file_if_present(path: &Path) {
        if path.exists() {
            if let Err(e) = std::fs::remove_file(path) {
                tracing::warn!(error = %e, "could not remove stale plaintext vault.key");
            }
        }
    }

    /// HKDF-SHA512 subkey for a purpose label. Caller must zeroize the returned bytes.
    fn subkey(&self, info: &[u8]) -> [u8; 32] {
        let hk = Hkdf::<Sha512>::new(None, self.root.expose_secret());
        let mut okm = [0u8; 32];
        hk.expand(info, &mut okm).expect("32 is a valid HKDF-SHA512 output length");
        okm
    }

    /// SQLCipher DB key as lowercase hex for `PRAGMA key` (passed to `db::open`).
    pub fn db_key_hex(&self) -> String {
        let mut k = self.subkey(b"writ-db-v1");
        let hex = k.iter().map(|b| format!("{b:02x}")).collect::<String>();
        k.zeroize();
        hex
    }

    /// Seal a secret field → `WF1:<base64(nonce||ciphertext)>`. `aad` = "table|column|row_id".
    pub fn seal_field(&self, plaintext: &[u8], aad: &str) -> LocalResult<String> {
        let mut key = self.subkey(b"writ-field-v1");
        let cipher = XChaCha20Poly1305::new(Key::from_slice(&key));
        key.zeroize();
        let mut nonce = [0u8; 24];
        rand::rngs::OsRng.fill_bytes(&mut nonce);
        let ct = cipher
            .encrypt(XNonce::from_slice(&nonce), Payload { msg: plaintext, aad: aad.as_bytes() })
            .map_err(|_| LocalError::Internal("vault seal failed".into()))?;
        let mut blob = Vec::with_capacity(24 + ct.len());
        blob.extend_from_slice(&nonce);
        blob.extend_from_slice(&ct);
        Ok(format!("{FIELD_MAGIC}{}", base64::engine::general_purpose::STANDARD.encode(&blob)))
    }

    /// Open a `WF1:` field with the same `aad` used to seal it.
    pub fn open_field(&self, blob: &str, aad: &str) -> LocalResult<Vec<u8>> {
        let b64 = blob
            .strip_prefix(FIELD_MAGIC)
            .ok_or_else(|| LocalError::Internal("unknown field-cipher prefix".into()))?;
        let raw = base64::engine::general_purpose::STANDARD
            .decode(b64)
            .map_err(|_| LocalError::Internal("vault: bad base64".into()))?;
        if raw.len() < 24 {
            return Err(LocalError::Internal("vault: blob too short".into()));
        }
        let (nonce, ct) = raw.split_at(24);
        let mut key = self.subkey(b"writ-field-v1");
        let cipher = XChaCha20Poly1305::new(Key::from_slice(&key));
        key.zeroize();
        cipher
            .decrypt(XNonce::from_slice(nonce), Payload { msg: ct, aad: aad.as_bytes() })
            .map_err(|_| LocalError::Internal("vault open failed (auth/tamper)".into()))
    }

    // ---- Layer C: file-blob crypto (K_file) ----------------------------------------------------
    //
    // Distinct purpose label ("writ-file-v1") so the file subkey is cryptographically independent
    // of K_db / K_field. The on-disk envelope is chunked XChaCha20-Poly1305 (authenticated): a
    // random 24-byte base nonce per file, then 64 KiB plaintext chunks each sealed under a derived
    // per-chunk nonce. Memory-bounded streaming sits on top of this in `storage::files`.

    /// Build the XChaCha20-Poly1305 cipher under the K_file subkey. The key is zeroized after the
    /// cipher captures it; the cipher itself holds the expanded key state for the call's lifetime.
    fn file_cipher(&self) -> XChaCha20Poly1305 {
        let mut key = self.subkey(b"writ-file-v1");
        let cipher = XChaCha20Poly1305::new(Key::from_slice(&key));
        key.zeroize();
        cipher
    }

    /// Derive the per-chunk nonce: base nonce with bytes 16..24 set to the big-endian chunk index,
    /// and (for the last chunk) byte 0 XORed with `0x01` so truncation/extension is rejected.
    fn chunk_nonce(base: &[u8; 24], index: u64, last: bool) -> [u8; 24] {
        let mut n = *base;
        n[16..24].copy_from_slice(&index.to_be_bytes());
        if last {
            n[0] ^= 0x01;
        }
        n
    }

    /// Encrypt arbitrary file bytes into the on-disk `WFB1` envelope (authenticated, chunked).
    /// The whole input is held in memory; callers should keep individual files reasonably sized.
    pub fn encrypt_file(&self, plaintext: &[u8]) -> LocalResult<Vec<u8>> {
        let cipher = self.file_cipher();
        let mut base = [0u8; 24];
        rand::rngs::OsRng.fill_bytes(&mut base);

        let mut out = Vec::with_capacity(FILE_HEADER_LEN + plaintext.len() + 64);
        out.extend_from_slice(FILE_MAGIC);
        out.extend_from_slice(&(FILE_CHUNK_SIZE as u32).to_le_bytes());
        out.extend_from_slice(&base);

        // An empty file still emits exactly one (final, empty) chunk so the trailer is always
        // present and decrypt has something to authenticate.
        let mut chunks = plaintext.chunks(FILE_CHUNK_SIZE).peekable();
        let mut index: u64 = 0;
        if chunks.peek().is_none() {
            let nonce = Self::chunk_nonce(&base, 0, true);
            let ct = cipher
                .encrypt(XNonce::from_slice(&nonce), Payload { msg: &[], aad: FILE_MAGIC })
                .map_err(|_| LocalError::Internal("vault file seal failed".into()))?;
            out.extend_from_slice(&ct);
            return Ok(out);
        }
        while let Some(chunk) = chunks.next() {
            let last = chunks.peek().is_none();
            let nonce = Self::chunk_nonce(&base, index, last);
            let ct = cipher
                .encrypt(XNonce::from_slice(&nonce), Payload { msg: chunk, aad: FILE_MAGIC })
                .map_err(|_| LocalError::Internal("vault file seal failed".into()))?;
            out.extend_from_slice(&ct);
            index += 1;
        }
        Ok(out)
    }

    /// Decrypt a `WFB1` on-disk envelope back to plaintext. Rejects unknown magic, a bad chunk
    /// size, truncation, and any per-chunk tag mismatch (tamper).
    pub fn decrypt_file(&self, blob: &[u8]) -> LocalResult<Vec<u8>> {
        if blob.len() < FILE_HEADER_LEN || &blob[0..4] != FILE_MAGIC {
            return Err(LocalError::Internal("vault: not a WFB1 file envelope".into()));
        }
        let chunk_size = u32::from_le_bytes([blob[4], blob[5], blob[6], blob[7]]) as usize;
        if chunk_size == 0 || chunk_size > 16 * 1024 * 1024 {
            return Err(LocalError::Internal("vault: implausible file chunk size".into()));
        }
        let mut base = [0u8; 24];
        base.copy_from_slice(&blob[8..32]);

        let cipher = self.file_cipher();
        let body = &blob[FILE_HEADER_LEN..];
        let sealed_chunk = chunk_size + 16; // plaintext chunk + Poly1305 tag

        let mut out = Vec::with_capacity(body.len());
        let mut offset = 0usize;
        let mut index: u64 = 0;
        loop {
            if offset >= body.len() {
                // We consumed the whole body but never saw a final chunk → truncated.
                return Err(LocalError::Internal("vault: file envelope truncated".into()));
            }
            let remaining = body.len() - offset;
            // A non-final chunk is exactly `sealed_chunk`; anything shorter (or any chunk that is
            // the rest of the file) is treated as the final chunk.
            let last = remaining <= sealed_chunk;
            let take = if last { remaining } else { sealed_chunk };
            let ct = &body[offset..offset + take];
            let nonce = Self::chunk_nonce(&base, index, last);
            let pt = cipher
                .decrypt(XNonce::from_slice(&nonce), Payload { msg: ct, aad: FILE_MAGIC })
                .map_err(|_| LocalError::Internal("vault file open failed (auth/tamper)".into()))?;
            out.extend_from_slice(&pt);
            offset += take;
            index += 1;
            if last {
                break;
            }
        }
        Ok(out)
    }

    // ---- TOTP (RFC-6238) ------------------------------------------------------------------------
    //
    // A persona's `totp_seed` (a base32 shared secret) is sealed at rest like any other field. The
    // engine decrypts it via `open_field` and hands the plaintext seed to `mint_totp`, which derives
    // the time-step code for the CURRENT 30s (or persona-configured) window. The seed and the minted
    // code are SECRETS: never log either, and the minted code only ever flows into the `credentials`
    // map for a `fill`/`twofa` step to consume (it is excluded from any serialized/logged surface,
    // same rule as every other secret).

    /// Mint the RFC-6238 TOTP code for `seed_b32` at the current Unix time.
    ///
    /// - `seed_b32`: the persona's shared secret, base32-encoded (the on-the-wire `otpauth://`
    ///   `secret=` form). Padding and case are tolerated; embedded whitespace is stripped.
    /// - `digits`: code length (RFC default 6; clamped to 6..=10).
    /// - `period_seconds`: time-step width (RFC default 30; min 1).
    /// - `algorithm`: HMAC hash — `"SHA1"` (RFC default), `"SHA256"`, or `"SHA512"`
    ///   (case-insensitive; unknown → SHA1).
    ///
    /// NEVER log the seed or the returned code.
    pub fn mint_totp(
        seed_b32: &str,
        digits: u32,
        period_seconds: u64,
        algorithm: &str,
    ) -> LocalResult<String> {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|_| LocalError::Internal("system clock before epoch".into()))?
            .as_secs();
        Self::mint_totp_at(seed_b32, digits, period_seconds, algorithm, now)
    }

    /// Time-pinned core of [`mint_totp`] (testable without depending on the wall clock). `unix_secs`
    /// is the absolute time; the counter is `unix_secs / period_seconds`.
    pub fn mint_totp_at(
        seed_b32: &str,
        digits: u32,
        period_seconds: u64,
        algorithm: &str,
        unix_secs: u64,
    ) -> LocalResult<String> {
        use hmac::{Mac, SimpleHmac};

        // Decode the base32 seed (tolerate whitespace + casing + missing padding). The standard
        // `otpauth` form is unpadded uppercase RFC-4648 base32; accept the padded form too.
        let normalized: String = seed_b32.chars().filter(|c| !c.is_whitespace()).collect();
        let normalized = normalized.trim_end_matches('=').to_ascii_uppercase();
        let key = data_encoding::BASE32_NOPAD
            .decode(normalized.as_bytes())
            .map_err(|_| LocalError::Internal("totp: seed is not valid base32".into()))?;
        if key.is_empty() {
            return Err(LocalError::Internal("totp: empty seed".into()));
        }

        let period = period_seconds.max(1);
        let counter = unix_secs / period;
        let msg = counter.to_be_bytes();
        let digits = digits.clamp(6, 10);

        // HMAC over the 8-byte big-endian counter, per the persona's configured hash. `SimpleHmac`
        // works over any `Digest`, so the three arms share the dynamic-truncation tail.
        let mac: Vec<u8> = match algorithm.trim().to_ascii_uppercase().as_str() {
            "SHA256" => {
                let mut m = <SimpleHmac<sha2::Sha256> as Mac>::new_from_slice(&key)
                    .map_err(|_| LocalError::Internal("totp: bad key length".into()))?;
                m.update(&msg);
                m.finalize().into_bytes().to_vec()
            }
            "SHA512" => {
                let mut m = <SimpleHmac<sha2::Sha512> as Mac>::new_from_slice(&key)
                    .map_err(|_| LocalError::Internal("totp: bad key length".into()))?;
                m.update(&msg);
                m.finalize().into_bytes().to_vec()
            }
            // RFC-6238 default (and any unrecognized value) → SHA1.
            _ => {
                let mut m = <SimpleHmac<sha1::Sha1> as Mac>::new_from_slice(&key)
                    .map_err(|_| LocalError::Internal("totp: bad key length".into()))?;
                m.update(&msg);
                m.finalize().into_bytes().to_vec()
            }
        };

        // RFC-4226 dynamic truncation: low nibble of the last byte selects a 4-byte window.
        let offset = (mac[mac.len() - 1] & 0x0f) as usize;
        let bin = ((u32::from(mac[offset]) & 0x7f) << 24)
            | (u32::from(mac[offset + 1]) << 16)
            | (u32::from(mac[offset + 2]) << 8)
            | u32::from(mac[offset + 3]);
        let modulo = 10u32.pow(digits);
        Ok(format!("{:0width$}", bin % modulo, width = digits as usize))
    }

    /// Non-secret keyring reachability probe for health checks. Returns `true` when the OS keyring
    /// entry can be addressed — i.e. constructing the entry succeeds AND a lookup returns either a
    /// value or a clean "no entry" (both mean the keyring backend is reachable). A backend error
    /// (locked/unavailable) returns `false`. NEVER returns or logs key material.
    pub fn keyring_available() -> bool {
        match keyring::Entry::new(KEYRING_SERVICE, &keyring_account()) {
            Ok(entry) => match entry.get_secret() {
                Ok(mut b) => {
                    b.zeroize();
                    true
                }
                Err(keyring::Error::NoEntry) => true,
                Err(_) => false,
            },
            Err(_) => false,
        }
    }

    // ---- backends ----
    fn keyring_get(account: &str) -> LocalResult<Option<[u8; 32]>> {
        let entry = keyring::Entry::new(KEYRING_SERVICE, account)
            .map_err(|e| LocalError::Internal(format!("keyring: {e}")))?;
        match entry.get_secret() {
            Ok(mut b) if b.len() == 32 => {
                let mut k = [0u8; 32];
                k.copy_from_slice(&b);
                b.zeroize(); // wipe the heap copy of the root key (defense in depth)
                Ok(Some(k))
            }
            Ok(mut b) => {
                b.zeroize();
                Ok(None)
            }
            Err(keyring::Error::NoEntry) => Ok(None),
            Err(e) => Err(LocalError::Internal(format!("keyring get: {e}"))),
        }
    }
    fn keyring_set(account: &str, root: &[u8; 32]) -> LocalResult<()> {
        let entry = keyring::Entry::new(KEYRING_SERVICE, account)
            .map_err(|e| LocalError::Internal(format!("keyring: {e}")))?;
        entry
            .set_secret(root)
            .map_err(|e| LocalError::Internal(format!("keyring set: {e}")))
    }

    /// Delete THIS profile's OS-keyring root entry (for a factory reset / full erase). Treats "no
    /// entry" as success so a file-rooted install is a clean no-op. NEVER logs key material.
    /// Best-effort: the caller (reset) already removed the file fallback, so a keyring backend error
    /// is non-fatal. Scoped to the active profile's account — a reset of one account never touches
    /// another account's key.
    pub fn keyring_delete() -> LocalResult<bool> {
        let entry = keyring::Entry::new(KEYRING_SERVICE, &keyring_account())
            .map_err(|e| LocalError::Internal(format!("keyring: {e}")))?;
        match entry.delete_credential() {
            Ok(()) => Ok(true),
            Err(keyring::Error::NoEntry) => Ok(false),
            Err(e) => Err(LocalError::Internal(format!("keyring delete: {e}"))),
        }
    }

    /// Store the in-flight rotation root in the OS keyring and CONFIRM it reads back byte-identically.
    /// Returns `true` on a verified round-trip, `false` if the keyring backend is unavailable — the
    /// rotation journal then falls back to the `0600` file copy so crash-safety is never lost. Lets
    /// keyring-custody installs keep the raw root off disk during a rotation. NEVER logs key material.
    pub fn keyring_put_rotation_root(root: &[u8; 32]) -> bool {
        let account = rotation_keyring_account();
        if Self::keyring_set(&account, root).is_err() {
            return false;
        }
        matches!(Self::keyring_get(&account), Ok(Some(rb)) if &rb == root)
    }

    /// Read the in-flight rotation root from the OS keyring, if present. `None` when absent/unreadable.
    pub fn keyring_get_rotation_root() -> Option<[u8; 32]> {
        Self::keyring_get(&rotation_keyring_account()).ok().flatten()
    }

    /// Remove the transient rotation root from the OS keyring once the rotation commits or is recovered.
    /// Best-effort: a missing entry / backend error is non-fatal. NEVER logs key material.
    pub fn keyring_delete_rotation_root() {
        if let Ok(entry) = keyring::Entry::new(KEYRING_SERVICE, &rotation_keyring_account()) {
            let _ = entry.delete_credential();
        }
    }
    fn file_get(path: &Path) -> LocalResult<Option<[u8; 32]>> {
        match std::fs::read(path) {
            Ok(mut b) if b.len() == 32 => {
                let mut k = [0u8; 32];
                k.copy_from_slice(&b);
                b.zeroize(); // wipe the heap copy of the root key (defense in depth)
                Ok(Some(k))
            }
            Ok(mut b) => {
                b.zeroize();
                Ok(None)
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(LocalError::Io(e)),
        }
    }
    fn file_set(path: &Path, root: &[u8; 32]) -> LocalResult<()> {
        write_secret_file(path, root)
    }
}

/// Atomically write a SECRET file so it is NEVER world-readable, not even for the brief window
/// between `write` and a follow-up `chmod` (the write-then-chmod race, LOW). On unix we create a
/// sibling temp with `O_CREAT|O_EXCL` at mode `0600` (mode is applied AT CREATION), write + fsync,
/// then rename it over the target — so no observer ever sees the bytes at umask-default perms, and
/// the final file is a fully-written `0600` file (or the old one, on crash). On non-unix we fall
/// back to a plain write (perms are governed by the OS ACLs there).
pub(crate) fn write_secret_file(path: &Path, bytes: &[u8]) -> LocalResult<()> {
    #[cfg(unix)]
    {
        use std::io::Write;
        use std::os::unix::fs::OpenOptionsExt;

        // A unique-enough sibling temp in the SAME directory (rename is atomic within a filesystem).
        let tmp = {
            let name = path.file_name().and_then(|s| s.to_str()).unwrap_or("secret");
            path.with_file_name(format!(".{name}.tmp.{}", std::process::id()))
        };
        // Best-effort remove of a stale temp from a prior crash so `create_new` can succeed.
        let _ = std::fs::remove_file(&tmp);
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true) // O_EXCL: fail rather than adopt an attacker-planted file
            .mode(0o600) // perms set at creation → no world-readable window
            .open(&tmp)?;
        if let Err(e) = f.write_all(bytes).and_then(|_| f.sync_all()) {
            let _ = std::fs::remove_file(&tmp);
            return Err(e.into());
        }
        drop(f);
        if let Err(e) = std::fs::rename(&tmp, path) {
            let _ = std::fs::remove_file(&tmp);
            return Err(e.into());
        }
        Ok(())
    }
    #[cfg(not(unix))]
    {
        std::fs::write(path, bytes)?;
        Ok(())
    }
}

// ---- Additive enterprise helpers (app-lock / recovery / rotation) ------------------------------
//
// These live alongside the core `Vault` so the sibling modules `vault_lock` / `vault_recovery` /
// `vault_rotate` can build on the SAME keyring-rooted root WITHOUT restructuring `vault.rs`. Every
// method returns a *zeroizing copy* of key material and NEVER logs it. The wrap construction is the
// spec's `unlock_secret = root XOR KDF(passphrase|mnemonic, salt)` (SECURITY_AND_ENTITLEMENTS_SPEC
// §1.3): XORing the root with a high-entropy derived key yields a stored wrap from which the root is
// recovered ONLY by re-deriving the same key — so neither the wrap nor the salt alone reveals it.

/// A 32-byte buffer that wipes itself on drop. Used to move key material between the vault and the
/// lock/recovery/rotate modules without leaving heap copies behind.
pub struct RootKey([u8; 32]);

impl RootKey {
    /// Borrow the raw 32 bytes (callers must not copy them into a non-zeroizing buffer).
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
    /// Construct from raw bytes (the source should itself be zeroized by the caller).
    pub fn from_bytes(b: [u8; 32]) -> Self {
        RootKey(b)
    }
    /// XOR this key with another 32-byte key (wrap/unwrap). Returns a fresh zeroizing buffer.
    pub fn xor(&self, other: &[u8; 32]) -> RootKey {
        let mut out = [0u8; 32];
        for i in 0..32 {
            out[i] = self.0[i] ^ other[i];
        }
        RootKey(out)
    }
    /// Constant-time equality against another root (no early exit). For passphrase/mnemonic verify.
    pub fn ct_eq(&self, other: &RootKey) -> bool {
        let mut diff = 0u8;
        for i in 0..32 {
            diff |= self.0[i] ^ other.0[i];
        }
        diff == 0
    }
}

impl Drop for RootKey {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

// REDACTED Debug — never print key bytes. A `Debug` impl is needed so callers can `unwrap_err()` on
// `LocalResult<RootKey>` (and so the type composes in `#[derive(Debug)]` structs), but it MUST NOT
// reveal the root. This prints a fixed placeholder only.
impl std::fmt::Debug for RootKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("RootKey(<redacted>)")
    }
}

impl Vault {
    /// A zeroizing copy of the keyring-rooted root key. The ONLY way the sibling modules read the
    /// root for XOR-wrapping; the returned [`RootKey`] wipes itself on drop. NEVER log the result.
    pub fn root_copy(&self) -> RootKey {
        RootKey(*self.root.expose_secret())
    }

    /// Build an in-memory `Vault` directly over a supplied root, WITHOUT touching the keyring/file.
    /// Used by rotation to derive the NEW key hierarchy (new K_db / K_field / K_file) before the new
    /// root is persisted, so old-vault decrypt and new-vault re-seal can run side by side.
    pub fn from_root(root: &RootKey) -> Self {
        Self { root: Secret::new(root.0) }
    }

    /// Derive a 32-byte Argon2id key from `passphrase` over `salt` at the given cost tier, for the
    /// app-lock XOR-wrap. `m_cost_kib` is the memory cost in KiB (spec target 256 MiB = 262144),
    /// `t_cost` the iterations (spec 3), `p_cost` the lanes (spec 1). NEVER log the passphrase or key.
    pub fn argon2id_key(
        passphrase: &[u8],
        salt: &[u8],
        m_cost_kib: u32,
        t_cost: u32,
        p_cost: u32,
    ) -> LocalResult<RootKey> {
        use argon2::{Algorithm, Argon2, Params, Version};
        let params = Params::new(m_cost_kib, t_cost, p_cost, Some(32))
            .map_err(|e| LocalError::Internal(format!("argon2 params: {e}")))?;
        let a2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
        let mut out = [0u8; 32];
        a2.hash_password_into(passphrase, salt, &mut out)
            .map_err(|_| LocalError::Internal("argon2 derivation failed".into()))?;
        Ok(RootKey(out))
    }

    /// Persist a NEW root to the durable backends (OS keyring when enabled + `0600` file fallback),
    /// for root rotation. The in-memory `Vault.root` is unchanged (callers rebuild the `Vault` /
    /// re-key the DB around this). NEVER logs the key.
    ///
    /// KEY-CUSTODY INVARIANT (DL-1): the new root must always have at least one durable copy that
    /// matches what the rekeyed DB expects, and `load_or_create` must never delete the `vault.key`
    /// fallback while the keyring still holds a DIFFERENT (stale) root. So the keyring write here is
    /// VERIFIED (write + read-back-and-compare) and we only skip the plaintext file when the keyring
    /// verifiably holds THIS new root. If the keyring write can't be confirmed we fall back to the
    /// `0600` file — never leaving the key with zero (or only stale) durable copies.
    pub fn persist_new_root(dir: &Path, new_root: &RootKey, use_keyring: bool) -> LocalResult<()> {
        let path = dir.join("vault.key");
        if use_keyring && Self::keyring_store_verified(&new_root.0) {
            // The keyring provably holds the new root → drop the plaintext fallback so the key stops
            // living next to the DB. Safe: `load_or_create` also only deletes `vault.key` when it
            // equals the keyring root, so the copies can never silently diverge.
            Self::remove_key_file_if_present(&path);
            return Ok(());
        }
        // Keyring disabled or the round-trip could not be confirmed → the `0600` file is the durable
        // copy of record. (A stale keyring entry is tolerated: `load_or_create` compares before it
        // ever removes the file, so it will not prefer a mismatched keyring root over this file.)
        Self::file_set(&path, &new_root.0)
    }

    /// The lowercase-hex SQLCipher `PRAGMA key`/`PRAGMA rekey` value for an ARBITRARY root (used by
    /// rotation to compute the post-rekey K_db). Mirrors [`Vault::db_key_hex`] but for a supplied
    /// root rather than `self`. NEVER log the result.
    pub fn db_key_hex_for(root: &RootKey) -> String {
        let hk = Hkdf::<Sha512>::new(None, &root.0);
        let mut okm = [0u8; 32];
        hk.expand(b"writ-db-v1", &mut okm).expect("32 is a valid HKDF-SHA512 output length");
        let hex = okm.iter().map(|b| format!("{b:02x}")).collect::<String>();
        okm.zeroize();
        hex
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn refuses_to_mint_a_new_root_over_an_existing_database() {
        // REGRESSION (silent data loss): with the root gone but `writ.db` present, minting a fresh
        // random root made `db::open` see SQLite code 26, quarantine the live DB as
        // `writ.db.corrupt-<ts>`, and boot EMPTY while reporting healthy — losing every stored
        // workflow, secret and persona. Refusing to boot is strictly better: the DB is
        // irreplaceable, the key is recoverable.
        let dir = tempfile::tempdir().unwrap();

        // A database exists (non-empty) but no vault.key and no keyring entry.
        std::fs::write(dir.path().join("writ.db"), b"SQLite format 3\0encrypted-bytes").unwrap();
        // NOTE: deliberately not `expect_err` — `Vault` has no `Debug` impl (by design, so key
        // material can never be `{:?}`-printed), and `expect_err` requires `Debug` on the Ok type.
        let msg = match Vault::load_or_create(dir.path(), false) {
            Ok(_) => panic!("must refuse rather than mint a new root over an existing DB"),
            Err(e) => e.to_string(),
        };
        assert!(msg.contains("refusing to mint a NEW vault root"), "unexpected error: {msg}");
        // The message must be actionable — it is the only thing the operator sees.
        assert!(msg.contains("writ.db"), "error should name the database: {msg}");
        assert!(msg.contains("backup"), "error should explain recovery: {msg}");

        // And it must NOT have quarantined or created anything.
        assert!(dir.path().join("writ.db").exists(), "the DB must be left untouched");
        assert!(!dir.path().join("vault.key").exists(), "no new key may be written");
    }

    #[test]
    fn empty_or_absent_database_still_mints_a_fresh_root() {
        // The guard must not break first-run. An absent DB is the normal case…
        let dir = tempfile::tempdir().unwrap();
        let v = Vault::load_or_create(dir.path(), false).expect("first run must succeed");
        assert_eq!(v.db_key_hex().len(), 64);

        // …and a zero-length `writ.db` (a touched/truncated file, no ciphertext to lose) is treated
        // as first-run too, so a half-created home directory does not wedge startup.
        let dir2 = tempfile::tempdir().unwrap();
        std::fs::write(dir2.path().join("writ.db"), b"").unwrap();
        Vault::load_or_create(dir2.path(), false).expect("empty DB must not block first run");
    }

    #[test]
    fn existing_root_plus_existing_database_is_the_normal_path() {
        // The guard is keyed on "no root found", not "DB exists" — a normal restart must work.
        let dir = tempfile::tempdir().unwrap();
        let v1 = Vault::load_or_create(dir.path(), false).unwrap();
        let key = v1.db_key_hex();
        std::fs::write(dir.path().join("writ.db"), b"SQLite format 3\0encrypted-bytes").unwrap();
        let v2 = Vault::load_or_create(dir.path(), false).expect("restart with a root must succeed");
        assert_eq!(v2.db_key_hex(), key, "root must be stable across restarts");
    }

    #[test]
    fn root_persists_and_field_roundtrips() {
        let dir = tempfile::tempdir().unwrap();
        let v = Vault::load_or_create(dir.path(), false).unwrap();

        // db key is stable + hex(64)
        let k1 = v.db_key_hex();
        assert_eq!(k1.len(), 64);

        // seal/open round-trip with matching AAD
        let sealed = v.seal_field(b"hunter2", "personas|credentials_encrypted|7").unwrap();
        assert!(sealed.starts_with("WF1:"));
        let opened = v.open_field(&sealed, "personas|credentials_encrypted|7").unwrap();
        assert_eq!(opened, b"hunter2");

        // wrong AAD must fail (anti-relocation)
        assert!(v.open_field(&sealed, "personas|credentials_encrypted|8").is_err());

        // reload from file gives the same root (stable db key + decrypts old blob)
        let v2 = Vault::load_or_create(dir.path(), false).unwrap();
        assert_eq!(v2.db_key_hex(), k1);
        assert_eq!(v2.open_field(&sealed, "personas|credentials_encrypted|7").unwrap(), b"hunter2");
    }

    #[test]
    fn file_blob_roundtrips_and_is_encrypted_at_rest() {
        let dir = tempfile::tempdir().unwrap();
        let v = Vault::load_or_create(dir.path(), false).unwrap();

        // A multi-chunk payload with a recognizable plaintext marker.
        let marker = b"SUPER-SECRET-MARKER-0xCAFEBABE";
        let mut plaintext = Vec::new();
        while plaintext.len() < 200 * 1024 {
            plaintext.extend_from_slice(marker);
        }

        let blob = v.encrypt_file(&plaintext).unwrap();

        // On-disk bytes carry the envelope magic, NOT the plaintext.
        assert_eq!(&blob[0..4], b"WFB1");
        let needle = b"SUPER-SECRET-MARKER";
        let leaked = blob.windows(needle.len()).any(|w| w == needle);
        assert!(!leaked, "plaintext marker must not appear in the on-disk ciphertext");
        assert!(blob.len() > plaintext.len(), "envelope+tags add overhead");

        // Decrypt round-trips exactly.
        let back = v.decrypt_file(&blob).unwrap();
        assert_eq!(back, plaintext);

        // Empty file is a valid envelope and round-trips.
        let empty = v.encrypt_file(b"").unwrap();
        assert_eq!(&empty[0..4], b"WFB1");
        assert_eq!(v.decrypt_file(&empty).unwrap(), Vec::<u8>::new());

        // Tamper: flipping a ciphertext byte must fail the auth check.
        let mut tampered = blob.clone();
        let last = tampered.len() - 1;
        tampered[last] ^= 0x01;
        assert!(v.decrypt_file(&tampered).is_err());

        // Truncation: dropping the final tag must fail (no silent partial read).
        let truncated = &blob[..blob.len() - 8];
        assert!(v.decrypt_file(truncated).is_err());

        // A different vault (different root) must NOT decrypt the blob.
        let other_dir = tempfile::tempdir().unwrap();
        let v_other = Vault::load_or_create(other_dir.path(), false).unwrap();
        assert!(v_other.decrypt_file(&blob).is_err());
    }

    #[test]
    fn file_matches_root_gates_deletion() {
        // The DL-1 invariant primitive: `file_matches_root` is the guard `load_or_create` uses before
        // it ever deletes `vault.key`. It must be true ONLY when the on-disk key byte-equals the
        // supplied root — so a divergent file (rotation wrote a NEW root the keyring never confirmed)
        // is never eligible for deletion.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("vault.key");
        let root = [7u8; 32];
        Vault::file_set(&path, &root).unwrap();
        assert!(Vault::file_matches_root(&path, &root), "matching key → deletable");

        let mut other = root;
        other[0] ^= 0xff;
        assert!(!Vault::file_matches_root(&path, &other), "divergent key → NOT deletable");

        // A missing file is not deletable either (nothing to safely remove).
        std::fs::remove_file(&path).unwrap();
        assert!(!Vault::file_matches_root(&path, &root));
    }

    #[cfg(unix)]
    #[test]
    fn secret_file_is_never_world_readable() {
        // The write-then-chmod race fix: a secret file must be 0600 at EVERY instant, so even a
        // pre-existing 0644 file is replaced atomically by a 0600 one (never chmod'd after the fact).
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("vault.key");

        // Pre-plant a world-readable file to prove the writer does not inherit its mode.
        std::fs::write(&path, b"stale").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();

        Vault::file_set(&path, &[9u8; 32]).unwrap();
        let mode = std::fs::metadata(&path).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600, "vault.key must be 0600, never world-readable");
        // And it round-trips to the new bytes (the atomic rename replaced the stale content).
        assert_eq!(Vault::file_get(&path).unwrap().unwrap(), [9u8; 32]);
    }

    #[test]
    fn totp_matches_rfc6238_vectors() {
        // RFC-6238 Appendix B test vectors. The shared secret is the ASCII string "12345678901234..."
        // truncated/extended to the HMAC's key length: 20 bytes for SHA1, 32 for SHA256, 64 for
        // SHA512 (base32 of each below). Published 8-digit codes at fixed times:
        //   T=59          → SHA1   94287082 ; SHA256 46119246 ; SHA512 90693936
        //   T=1111111109  → SHA1   07081804
        let seed_sha1 = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"; // 20 bytes
        let seed_sha256 = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZA===="; // 32 bytes
        let seed_sha512 = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNA="; // 64 bytes

        assert_eq!(Vault::mint_totp_at(seed_sha1, 8, 30, "SHA1", 59).unwrap(), "94287082");
        assert_eq!(Vault::mint_totp_at(seed_sha256, 8, 30, "SHA256", 59).unwrap(), "46119246");
        assert_eq!(Vault::mint_totp_at(seed_sha512, 8, 30, "SHA512", 59).unwrap(), "90693936");
        assert_eq!(Vault::mint_totp_at(seed_sha1, 8, 30, "SHA1", 1_111_111_109).unwrap(), "07081804");

        // Default 6-digit code is the low 6 of the 8-digit code at the same time-step.
        assert_eq!(Vault::mint_totp_at(seed_sha1, 6, 30, "SHA1", 59).unwrap(), "287082");

        // Lowercase + whitespace + padding tolerated (same code as the canonical SHA1 form).
        let messy = "gezd gnbv gy3t qojq gezd gnbv gy3t qojq====";
        assert_eq!(Vault::mint_totp_at(messy, 8, 30, "SHA1", 59).unwrap(), "94287082");

        // Unknown algorithm falls back to SHA1 (does not error).
        assert_eq!(Vault::mint_totp_at(seed_sha1, 8, 30, "MD5", 59).unwrap(), "94287082");

        // A non-base32 seed is a clean error, not a panic.
        assert!(Vault::mint_totp_at("not base32 !!!", 6, 30, "SHA1", 0).is_err());
    }
}
