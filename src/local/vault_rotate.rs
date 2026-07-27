//! Vault root rotation — re-root the entire key hierarchy and migrate ciphertext to the new root,
//! crash-resumably. SECURITY_AND_ENTITLEMENTS_SPEC §1.3: "Rotation: re-wrap the root (sub-second,
//! touches no data) for routine hygiene; full rotation does an optional `PRAGMA rekey` +
//! `reseal_all()` + lazy per-file re-encrypt, all crash-resumable via gen counters."
//!
//! Rotating the root changes EVERY derived key: K_db (SQLCipher page key), K_field (the
//! XChaCha20-Poly1305 field AEAD), and K_file (the `WFB1` blob key). The migration therefore has
//! ordered phases, each idempotent and recorded by a generation counter in `config` so a crash
//! mid-rotation resumes from the last completed phase rather than corrupting the store:
//!
//!   Phase 0 `Begin`      — record `new_gen` + start; nothing migrated yet.
//!   Phase 1 `Rekey`      — `PRAGMA rekey` the live DB to the NEW K_db (SQLCipher rewrites pages
//!                          transactionally; an interrupted rekey leaves the DB readable under the
//!                          OLD key, so we re-issue on resume).
//!   Phase 2 `Reseal`     — decrypt every Layer-B field secret with the OLD vault and re-seal with
//!                          the NEW vault (AAD is content-bound, so it is unchanged). Idempotent: a
//!                          row already bearing a NEW-vault blob is skipped via a decrypt-probe.
//!   Phase 3 `Rewrap`     — re-wrap the app-lock and recovery wraps under the NEW root.
//!   Phase 4 `Persist`    — persist the NEW root to the keyring/file (the point of no return for the
//!                          on-disk root) and bump the committed generation.
//!   Files               — re-encrypted LAZILY on next read (a blob that fails to open under the new
//!                          K_file is transparently re-decrypted under the old vault and re-sealed),
//!                          so a large file store never blocks rotation. [`reencrypt_file_blob`] is
//!                          the helper the storage layer calls.
//!
//! "Re-wrap only" (routine hygiene that touches no data) is [`rewrap_only`]: it mints a NEW root,
//! re-seals fields, rekeys the DB, re-wraps, and persists — i.e. a full rotation. A literal "re-wrap
//! the WRAPS without changing the root" is a degenerate no-op here because there is no separate DEK
//! to re-wrap (the root IS the only secret; everything else is HKDF-derived).
//!
//! NEVER logs any key material, passphrase, mnemonic, or secret value.
//!
//! Net-new Rust in this crate (behind the `local` feature).

use rand::RngCore;
use sqlx::SqlitePool;
use std::path::{Path, PathBuf};
use zeroize::Zeroize;

use crate::local::error::{LocalError, LocalResult};
use crate::local::store::{config_kv, personas, vault_secrets};
use crate::local::vault::{RootKey, Vault};

/// `config` KV keys tracking rotation progress for crash-resume.
const CFG_GEN: &str = "vault_rotate.generation";
const CFG_PHASE: &str = "vault_rotate.phase";
/// Marks the generation for which the BIP39 recovery wrap has already been re-bound to the new root.
/// Makes the recovery re-wrap idempotent across an interrupted-then-resumed rotation: the XOR re-wrap
/// is NOT self-idempotent (applying it twice with the old root corrupts the wrap), so we skip it when
/// this marker already equals the rotation's target generation.
const CFG_REWRAP_GEN: &str = "vault_rotate.recovery_rewrap_generation";

/// Re-wrap the BIP39 recovery code for the new root exactly once per rotation `generation`. Idempotent
/// via [`CFG_REWRAP_GEN`]: a second call for the same generation (e.g. a resumed interrupted rotation)
/// is a no-op, so the non-self-idempotent XOR re-wrap can never be applied twice. NEVER logs keys.
async fn rewrap_recovery_idempotent(
    db: &SqlitePool,
    old_root: &RootKey,
    new_root: &RootKey,
    generation: i64,
) -> LocalResult<()> {
    let done = config_kv::get(db, CFG_REWRAP_GEN).await?.and_then(|s| s.parse::<i64>().ok());
    if done == Some(generation) {
        return Ok(()); // already re-wrapped for this rotation
    }
    crate::local::vault_recovery::rewrap_for_new_root(db, old_root, new_root).await?;
    config_kv::set(db, CFG_REWRAP_GEN, &generation.to_string()).await?;
    Ok(())
}

/// Ordered rotation phases. Stored as a small integer so a resumed boot can tell what completed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RotatePhase {
    Begin = 0,
    Rekey = 1,
    Reseal = 2,
    Rewrap = 3,
    Persist = 4,
    Done = 5,
}

impl RotatePhase {
    fn from_i64(v: i64) -> RotatePhase {
        match v {
            1 => RotatePhase::Rekey,
            2 => RotatePhase::Reseal,
            3 => RotatePhase::Rewrap,
            4 => RotatePhase::Persist,
            5 => RotatePhase::Done,
            _ => RotatePhase::Begin,
        }
    }
}

/// The AAD a `vault_secrets` row's `value_encrypted` is sealed under (mirrors `api::v1::secrets`).
fn secret_value_aad(key: &str) -> String {
    format!("vault_secrets|value_encrypted|{key}")
}

/// The AAD a persona's sealed column is bound to (mirrors `engine::persona`).
fn persona_aad(column: &str, id: i64) -> String {
    format!("personas|{column}|{id}")
}

/// Persist the current rotation phase (best-effort durability for crash-resume).
async fn set_phase(db: &SqlitePool, phase: RotatePhase) -> LocalResult<()> {
    config_kv::set(db, CFG_PHASE, &(phase as i64).to_string()).await
}

/// Read the persisted rotation phase, or `Done` (idle) when none is recorded.
pub async fn current_phase(db: &SqlitePool) -> LocalResult<RotatePhase> {
    Ok(config_kv::get(db, CFG_PHASE)
        .await?
        .and_then(|s| s.parse::<i64>().ok())
        .map(RotatePhase::from_i64)
        .unwrap_or(RotatePhase::Done))
}

/// The committed generation counter (bumped once a rotation fully commits the new root).
pub async fn generation(db: &SqlitePool) -> LocalResult<i64> {
    Ok(config_kv::get(db, CFG_GEN).await?.and_then(|s| s.parse().ok()).unwrap_or(0))
}

/// Outcome summary of a full rotation (non-secret counts only).
#[derive(Debug, Clone, serde::Serialize)]
pub struct RotateReport {
    pub generation: i64,
    pub secrets_resealed: usize,
    pub personas_resealed: usize,
}

/// `PRAGMA rekey` the SQLCipher DB file at `path` from `old_key_hex` to `new_key_hex`.
///
/// Done on a DEDICATED single connection opened with the OLD key (NOT the shared pool): SQLCipher
/// rekey rewrites every page under the new key, after which any connection still carrying the old
/// `PRAGMA key` (i.e. the daemon's existing pool) can no longer open the file. So rekey is the LAST
/// DB step against the old key, and the caller MUST rebuild its pool/`AppState` under the new key
/// afterwards. This dedicated connection is opened, rekeyed, then dropped. NEVER log either key.
async fn rekey_db_file(path: &std::path::Path, old_key_hex: &str, new_key_hex: &str) -> LocalResult<()> {
    use sqlx::sqlite::SqliteConnectOptions;
    use sqlx::{ConnectOptions, Connection};

    let old_keyed = format!("'{}'", old_key_hex.replace('\'', "''"));
    let mut conn = SqliteConnectOptions::new()
        .filename(path)
        .create_if_missing(false)
        .pragma("key", old_keyed) // open under the OLD key
        .pragma("foreign_keys", "ON")
        .pragma("journal_mode", "WAL")
        .connect()
        .await?;

    // Confirm the cipher is genuinely active before rekey (fail-closed): an empty cipher_version
    // would mean plain SQLite and a `PRAGMA rekey` no-op (data would silently stay under no key).
    let cv: Option<String> = sqlx::query_scalar("PRAGMA cipher_version").fetch_optional(&mut conn).await?;
    if cv.map(|s| s.trim().is_empty()).unwrap_or(true) {
        return Err(LocalError::CipherUnavailable);
    }

    let new_keyed = format!("'{}'", new_key_hex.replace('\'', "''"));
    sqlx::query(&format!("PRAGMA rekey = {new_keyed}"))
        .execute(&mut conn)
        .await
        .map_err(|e| LocalError::Internal(format!("PRAGMA rekey failed: {e}")))?;
    // Drop the dedicated connection (the file is now under the new key).
    let _ = conn.close().await;
    Ok(())
}

/// Re-seal every Layer-B field secret from `old` to `new`. A row whose blob already opens under the
/// NEW vault is skipped (idempotent resume). Returns `(secrets, persona_columns)` resealed counts.
async fn reseal_all(db: &SqlitePool, old: &Vault, new: &Vault) -> LocalResult<(usize, usize)> {
    let mut secrets = 0usize;
    let mut personas_cols = 0usize;

    // vault_secrets.value_encrypted
    for row in vault_secrets::list(db, None).await? {
        let aad = secret_value_aad(&row.key);
        // Skip if already new (resume): a NEW-vault open succeeds.
        if new.open_field(&row.value_encrypted, &aad).is_ok() {
            continue;
        }
        let mut plain = old.open_field(&row.value_encrypted, &aad)?;
        let sealed = new.seal_field(&plain, &aad)?;
        plain.zeroize();
        vault_secrets::update_value(db, row.id, &sealed).await?;
        secrets += 1;
    }

    // personas.{credentials,totp_seed,proxy_config,session_state}_encrypted
    for p in personas::list(db, None).await? {
        let cols: [(&str, &Option<String>); 4] = [
            ("credentials_encrypted", &p.credentials_encrypted),
            ("totp_seed_encrypted", &p.totp_seed_encrypted),
            ("proxy_config_encrypted", &p.proxy_config_encrypted),
            ("session_state_encrypted", &p.session_state_encrypted),
        ];
        let mut update = personas::PersonaUpdate::default();
        let mut touched = false;
        for (col, blob_opt) in cols {
            let Some(blob) = blob_opt else { continue };
            let aad = persona_aad(col, p.id);
            if new.open_field(blob, &aad).is_ok() {
                continue; // already new
            }
            let mut plain = old.open_field(blob, &aad)?;
            let sealed = new.seal_field(&plain, &aad)?;
            plain.zeroize();
            match col {
                "credentials_encrypted" => update.credentials_encrypted = Some(sealed),
                "totp_seed_encrypted" => update.totp_seed_encrypted = Some(sealed),
                "proxy_config_encrypted" => update.proxy_config_encrypted = Some(sealed),
                "session_state_encrypted" => update.session_state_encrypted = Some(sealed),
                _ => {}
            }
            touched = true;
            personas_cols += 1;
        }
        if touched {
            personas::update(db, p.id, &update).await?;
        }
    }

    Ok((secrets, personas_cols))
}

/// Lazily re-encrypt a single file `WFB1` blob to the current root. Tries to decrypt under the
/// CURRENT vault first (the common case: already migrated); on failure it falls back to the OLD
/// vault, returning the re-encrypted bytes under the NEW vault so the storage layer can rewrite the
/// file in place. `Ok(None)` means the blob is already current (no rewrite needed). NEVER log bytes.
pub fn reencrypt_file_blob(
    current: &Vault,
    previous: &Vault,
    blob: &[u8],
) -> LocalResult<Option<Vec<u8>>> {
    if current.decrypt_file(blob).is_ok() {
        return Ok(None); // already under the new K_file
    }
    let mut plain = previous.decrypt_file(blob)?;
    let reenc = current.encrypt_file(&plain)?;
    plain.zeroize();
    Ok(Some(reenc))
}

// ── Crash-safe rotation: durable new-root recovery journal ──────────────────────────────────────
//
// A rotation's destructive steps are: reseal field secrets old→new, `PRAGMA rekey` the DB file
// old→new, then persist the new root to `vault.key`. Until that persist, the new root lives ONLY in
// memory — so a crash between the rekey and the persist would leave the DB keyed to a root that
// exists nowhere on disk: a PERMANENT brick. To close that window we write the new root to a `0600`
// recovery journal BEFORE any destructive step and delete it only once the rotation fully commits.
// On boot, `recover_interrupted_rotation` finishes an interrupted rotation from the journal, so the
// DB and `vault.key` can never be left keyed to different roots. CUSTODY of the journaled new root
// matches the install's root custody: on a keyring-rooted install the raw root is stored in the OS
// keyring (the file journal holds only a marker), so the plaintext root never lands on disk; on a
// file-rooted install it is the raw root in a `0600` file in the `0700` home (the SAME posture as
// `vault.key` itself). Either way it is transient (deleted on commit / on recovery). NEVER log its
// contents.

/// Path of the rotation recovery journal, next to `vault.key`.
fn journal_path(dir: &Path) -> PathBuf {
    dir.join("vault.rotate.json")
}

#[derive(serde::Serialize, serde::Deserialize)]
struct RotateJournal {
    generation: i64,
    /// The NEW root as lowercase hex (32 bytes → 64 chars), or EMPTY when the root is instead held in
    /// the OS keyring (`root_in_keyring`) so the plaintext root never lands on disk. NEVER logged.
    new_root_hex: String,
    /// When true the raw new root is in the OS keyring (keyring-custody installs) and `new_root_hex`
    /// is empty. Defaults false so legacy file journals (raw hex, no field) still decode.
    #[serde(default)]
    root_in_keyring: bool,
}

/// Write the recovery journal (`0600`) recording the new root, before any destructive rotation step.
///
/// DURABILITY (DL-5): this journal is the ONLY on-disk copy of the new root during the crash window
/// between the rekey and the persist, so it must hit stable storage BEFORE any destructive step. The
/// shared atomic writer creates the file at `0600` (no world-readable window for the raw root) and
/// `sync_all`s its bytes; we additionally fsync the PARENT directory so the new dir entry itself is
/// durable — otherwise a crash could lose the journal file even though its bytes were flushed.
fn write_journal(dir: &Path, generation: i64, new_root: &RootKey, use_keyring: bool) -> LocalResult<()> {
    // Prefer OS-keyring custody for the in-flight root: on keyring-rooted installs (which otherwise
    // guarantee the root NEVER touches disk) writing the raw root here would regress that posture —
    // transiently on every rotation, and permanently if a crash lands in the neither-root recovery
    // branch that leaves the journal behind. Store it in the keyring instead; the file journal then
    // records only a marker + generation. Fall back to the `0600` file copy of the raw root when the
    // keyring is disabled/unavailable so a durable copy ALWAYS exists before any destructive step
    // (crash-safety is never traded away).
    let in_keyring =
        use_keyring && crate::local::vault::Vault::keyring_put_rotation_root(new_root.as_bytes());
    let new_root_hex: String = if in_keyring {
        String::new()
    } else {
        new_root.as_bytes().iter().map(|b| format!("{b:02x}")).collect()
    };
    let mut data = serde_json::to_vec(&RotateJournal {
        generation,
        new_root_hex,
        root_in_keyring: in_keyring,
    })?;
    let path = journal_path(dir);
    let res = crate::local::vault::write_secret_file(&path, &data);
    data.zeroize(); // the serialized JSON may have held the raw new root in hex — scrub the heap copy
    res?;
    fsync_dir(dir);
    Ok(())
}

/// Best-effort fsync of a directory so a just-created/renamed entry within it is durable across a
/// crash. Non-fatal: on platforms/filesystems where opening a dir for fsync isn't supported this is
/// a no-op, and the file's own `sync_all` already flushed its contents.
fn fsync_dir(dir: &Path) {
    if let Ok(f) = std::fs::File::open(dir) {
        let _ = f.sync_all();
    }
}

/// Read + parse the recovery journal's new root, or `None` when no rotation is in flight.
fn read_journal(dir: &Path) -> LocalResult<Option<RootKey>> {
    let data = match std::fs::read(journal_path(dir)) {
        Ok(d) => d,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e.into()),
    };
    let j: RotateJournal = serde_json::from_slice(&data)
        .map_err(|e| LocalError::Internal(format!("unreadable rotation journal: {e}")))?;
    if j.root_in_keyring {
        // The raw root lives in the OS keyring (keyring-custody install); the file holds only a marker.
        match crate::local::vault::Vault::keyring_get_rotation_root() {
            Some(bytes) => Ok(Some(RootKey::from_bytes(bytes))),
            None => Err(LocalError::Internal(
                "rotation journal marks the new root as keyring-held but the keyring entry is missing"
                    .into(),
            )),
        }
    } else {
        Ok(Some(RootKey::from_bytes(decode_root_hex(&j.new_root_hex)?)))
    }
}

/// Decode a 64-char lowercase-hex root into raw bytes.
fn decode_root_hex(s: &str) -> LocalResult<[u8; 32]> {
    let s = s.trim();
    if s.len() != 64 {
        return Err(LocalError::Internal("rotation journal: bad root length".into()));
    }
    let mut out = [0u8; 32];
    for (i, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16)
            .map_err(|_| LocalError::Internal("rotation journal: bad hex".into()))?;
    }
    Ok(out)
}

/// Does the SQLCipher DB at `path` open (i.e. decrypt page 1) under `key_hex`? Non-mutating probe.
async fn db_opens_under(path: &Path, key_hex: &str) -> bool {
    use sqlx::sqlite::{SqliteConnectOptions, SqlitePoolOptions};
    let keyed = format!("'{}'", key_hex.replace('\'', "''"));
    let opts = SqliteConnectOptions::new()
        .filename(path)
        .create_if_missing(false)
        .pragma("key", keyed)
        .pragma("busy_timeout", "5000");
    let Ok(pool) = SqlitePoolOptions::new().max_connections(1).connect_with(opts).await else {
        return false;
    };
    let ok = sqlx::query("SELECT count(*) FROM sqlite_master").fetch_one(&pool).await.is_ok();
    pool.close().await;
    ok
}

/// Complete a vault rotation that a crash interrupted before it could persist the new root.
///
/// Called at boot AFTER the vault is loaded and BEFORE the DB pool is opened. Returns `Ok(true)` when
/// it changed the on-disk root (the caller MUST reload the `Vault`), `Ok(false)` when there was
/// nothing to do — or the DB opens under NEITHER root, in which case it is left for
/// [`crate::local::db::open_managed`] to quarantine/recover.
///
/// Two crash windows, told apart by which root opens the DB (`rekey` is the LAST destructive step, so
/// everything before it — reseal/rewrap — is done iff the rekey is):
///   * DB opens under the NEW root → the rekey completed but the persist didn't (the brick window).
///     Promote the new root to `vault.key` (+ keyring) and drop the journal.
///   * DB opens under the OLD root → the rekey never happened. Drive the rotation FORWARD with the
///     journaled new root: reseal remaining field secrets (idempotent) → rekey → persist → drop the
///     journal. Re-entrant: a crash mid-completion resumes on the next boot.
///
/// The forward-completion branch re-runs the SAME recovery re-wrap that [`rotate_root`] performs
/// (DL-2), so a crash before the rekey still leaves `vault_recovery.wrap_b64` bound to the new root.
/// That re-wrap is made idempotent via a generation marker (see [`rewrap_recovery_idempotent`]), so
/// re-running it across repeated interrupted boots cannot corrupt the wrap.
pub async fn recover_interrupted_rotation(
    dir: &Path,
    db_path: &Path,
    old: &Vault,
    use_keyring: bool,
) -> LocalResult<bool> {
    let Some(new_root) = read_journal(dir)? else {
        return Ok(false);
    };
    let new_vault = Vault::from_root(&new_root);
    let new_key = Vault::db_key_hex_for(&new_root);
    let old_key = old.db_key_hex();
    let journal = journal_path(dir);

    // Window A — rekey completed, persist did not: the DB is already under the new key.
    if db_opens_under(db_path, &new_key).await {
        Vault::persist_new_root(dir, &new_root, use_keyring)?;
        let _ = std::fs::remove_file(&journal);
        Vault::keyring_delete_rotation_root();
        tracing::warn!("recovered an interrupted vault rotation (rekey had completed; persisted the new root)");
        return Ok(true);
    }

    // Window B — rekey not reached: the DB is still under the old key. Complete forward.
    if db_opens_under(db_path, &old_key).await {
        let pool = crate::local::db::open(db_path, &old_key).await?;
        reseal_all(&pool, old, &new_vault).await?; // idempotent: only converts not-yet-new rows
        // Re-run the recovery re-wrap for the new root (idempotent via a generation marker) so the
        // user's mnemonic still recovers the rotated root even if the crash landed before the rekey.
        let gen = generation(&pool).await?;
        rewrap_recovery_idempotent(&pool, &old.root_copy(), &new_root, gen).await?;
        pool.close().await;
        rekey_db_file(db_path, &old_key, &new_key).await?;
        Vault::persist_new_root(dir, &new_root, use_keyring)?;
        let _ = std::fs::remove_file(&journal);
        Vault::keyring_delete_rotation_root();
        tracing::warn!("recovered an interrupted vault rotation (completed the rekey + persisted the new root)");
        return Ok(true);
    }

    // Neither root opens the DB — leave the journal + DB for the DB layer's quarantine/recovery. On a
    // keyring-custody install the in-flight root is held in the OS keyring (not written to disk in
    // cleartext), so this residual carries the SAME custody as the vault root itself and is cleaned up
    // once DB-layer recovery lets a subsequent boot complete or abandon the rotation.
    tracing::error!(
        "a vault rotation journal is present but the DB opens under neither root; leaving it for DB-layer recovery"
    );
    Ok(false)
}

/// Full root rotation. Mints a fresh CSPRNG root, then runs the crash-resumable phases. Crucially
/// the SQLCipher `PRAGMA rekey` is the LAST DB-mutating step against the old key (SQLCipher rekey
/// rewrites every page; any connection still carrying the old key — the daemon's pool — can no longer
/// open the file afterward). So all `config`/store work runs FIRST under `db` (still the old key),
/// then the file is rekeyed on a dedicated connection, then the new root is persisted, then the final
/// commit markers are written to a fresh connection opened under the NEW key.
///
/// Phase order (each idempotent for crash-resume):
///   Begin  — record new generation + start (under old key).
///   Reseal — decrypt every Layer-B field secret with `old`, re-seal with the new vault, write back
///            (rows change but the DB is still old-keyed → consistent).
///   Rewrap — caller-supplied closure re-wraps the app-lock/recovery wraps under the new root.
///   Rekey  — `PRAGMA rekey` the file old→new on a dedicated connection (the irreversible DB step).
///   Persist— write the new root to keyring/file (point of no return for the on-disk root).
///   Done   — commit markers written under the NEW key.
///
/// - `old`: the live vault (current keyring root).
/// - `db`: the live pool (old key). It is DEAD after this returns — the caller MUST rebuild its
///   pool/`AppState` under the new root.
/// - `db_path`: the SQLCipher file path (for the dedicated rekey + commit connections).
/// - `dir`: the `~/.writ` root where `vault.key` lives (for `persist_new_root`).
/// - `use_keyring`: whether to also write the new root to the OS keyring.
/// - `rewrap`: a closure given `(db, new_vault)` to re-wrap the app-lock/recovery wraps under the new
///   root (kept as a closure so this module does not depend on those concrete enable flows).
///
/// File blobs are NOT eagerly rewritten — they migrate lazily via [`reencrypt_file_blob`].
/// NEVER logs key material.
pub async fn rotate_root<F, Fut>(
    db: &SqlitePool,
    old: &Vault,
    db_path: &std::path::Path,
    dir: &std::path::Path,
    use_keyring: bool,
    rewrap: F,
) -> LocalResult<RotateReport>
where
    F: FnOnce(SqlitePool, Vault) -> Fut,
    Fut: std::future::Future<Output = LocalResult<()>>,
{
    // Mint the new root.
    let mut raw = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut raw);
    let new_root = RootKey::from_bytes(raw);
    raw.zeroize();
    let new_vault = Vault::from_root(&new_root);
    let old_key_hex = old.db_key_hex();
    let new_key_hex = Vault::db_key_hex_for(&new_root);

    let next_gen = generation(db).await? + 1;
    config_kv::set(db, CFG_GEN, &next_gen.to_string()).await?;
    set_phase(db, RotatePhase::Begin).await?;
    // Durably record the new root BEFORE any destructive step (reseal/rekey/persist). If a crash
    // lands between the rekey and the persist, the next boot recovers from this journal instead of
    // bricking on a DB keyed to a root that exists nowhere on disk. Removed once the rotation commits.
    write_journal(dir, next_gen, &new_root, use_keyring)?;
    tracing::info!(generation = next_gen, "vault rotation begun");

    // Reseal all field secrets old→new (under the OLD-keyed pool; rows change, DB key does not).
    let (secrets_resealed, personas_resealed) = reseal_all(db, old, &new_vault).await?;
    set_phase(db, RotatePhase::Reseal).await?;

    // Re-wrap lock/recovery under the new root (caller-supplied), still under the old-keyed pool.
    rewrap(db.clone(), Vault::from_root(&new_root)).await?;
    set_phase(db, RotatePhase::Rewrap).await?;

    // Rekey the SQLCipher file old→new — the irreversible DB step. After this the `db` pool is dead.
    rekey_db_file(db_path, &old_key_hex, &new_key_hex).await?;

    // Persist the new root (point of no return for the on-disk root) so a restart derives the new key.
    Vault::persist_new_root(dir, &new_root, use_keyring)?;

    // Commit markers under the NEW key (the old pool can no longer open the rekeyed file).
    let committed = crate::local::db::open(db_path, &new_key_hex).await?;
    set_phase(&committed, RotatePhase::Done).await?;
    committed.close().await;

    // Fully committed (DB rekeyed + new root persisted): drop the recovery journal (file + keyring).
    let _ = std::fs::remove_file(journal_path(dir));
    crate::local::vault::Vault::keyring_delete_rotation_root();

    tracing::info!(
        generation = next_gen,
        secrets_resealed,
        personas_resealed,
        "vault rotation committed (files re-encrypt lazily)"
    );
    Ok(RotateReport { generation: next_gen, secrets_resealed, personas_resealed })
}

/// Re-wrap-only routine hygiene rotation: [`rotate_root`] wired to re-wrap the BIP39 recovery code
/// for the new root (DL-2). Mints a new root and migrates ciphertext exactly like a full rotation —
/// there is no cheaper "re-wrap the DEK without re-rooting" because the root is the sole secret.
///
/// The re-wrap closure re-binds `vault_recovery.wrap_b64` from the old root to the new one so the
/// user's UNCHANGED written-down mnemonic still recovers the (now-rotated) root. Without this the
/// recovery code would silently return a stale root after any rotation.
pub async fn rewrap_only(
    db: &SqlitePool,
    old: &Vault,
    db_path: &std::path::Path,
    dir: &std::path::Path,
    use_keyring: bool,
) -> LocalResult<RotateReport> {
    let old_root = old.root_copy();
    rotate_root(db, old, db_path, dir, use_keyring, move |db, new_vault| async move {
        // Runs under the still-old-keyed pool after `CFG_GEN` was bumped, so `generation` is the
        // rotation's target — the same value the forward-recovery path uses for idempotency.
        let new_root = new_vault.root_copy();
        let gen = generation(&db).await?;
        rewrap_recovery_idempotent(&db, &old_root, &new_root, gen).await
    })
    .await
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::local::db;
    use crate::local::store::vault_secrets::NewVaultSecret;

    /// A fresh encrypted DB + headless vault for rotation tests, returning the home dir + db path.
    async fn fixture() -> (tempfile::TempDir, std::path::PathBuf, SqlitePool, Vault) {
        let dir = tempfile::tempdir().unwrap();
        let vault = Vault::load_or_create(dir.path(), false).unwrap();
        let db_path = dir.path().join("t.db");
        let pool = db::open(&db_path, &vault.db_key_hex()).await.unwrap();
        (dir, db_path, pool, vault)
    }

    #[tokio::test]
    async fn rotation_rekeys_and_reseals_secrets() {
        let (dir, db_path, pool, old) = fixture().await;

        // Seed a secret sealed under the OLD root.
        let plaintext = "ROTATE-ME-S3CRET";
        let aad = secret_value_aad("API_KEY");
        let sealed = old.seal_field(plaintext.as_bytes(), &aad).unwrap();
        vault_secrets::insert(
            &pool,
            &NewVaultSecret { key: "API_KEY".into(), value_encrypted: sealed, ..Default::default() },
        )
        .await
        .unwrap();

        let report = rewrap_only(&pool, &old, &db_path, dir.path(), false).await.unwrap();
        assert_eq!(report.generation, 1);
        assert_eq!(report.secrets_resealed, 1);
        // The old pool is dead after rekey — close it and verify via a fresh new-keyed connection.
        pool.close().await;

        // The DB is now keyed under the NEW root: the OLD vault's db key no longer opens it, but a
        // vault rebuilt from the persisted new root does.
        let new = Vault::load_or_create(dir.path(), false).unwrap();
        assert_ne!(new.db_key_hex(), old.db_key_hex(), "root changed");
        // Re-open the DB under the new key and confirm the secret decrypts under the NEW vault.
        let reopened = db::open(&db_path, &new.db_key_hex()).await.unwrap();
        assert_eq!(current_phase(&reopened).await.unwrap(), RotatePhase::Done);
        let row = vault_secrets::get_by_key(&reopened, "API_KEY").await.unwrap().unwrap();
        let recovered = new.open_field(&row.value_encrypted, &aad).unwrap();
        assert_eq!(recovered, plaintext.as_bytes());
        // And the OLD vault can NO LONGER open the resealed blob.
        assert!(old.open_field(&row.value_encrypted, &aad).is_err());
    }

    #[tokio::test]
    async fn file_blob_reencrypts_lazily() {
        let (dir, _db_path, _pool, old) = fixture().await;
        // Encrypt a file blob under the OLD root.
        let plaintext = b"file-bytes-under-old-root".repeat(100);
        let blob = old.encrypt_file(&plaintext).unwrap();

        // Simulate the post-rotation NEW vault (different root).
        let mut raw = [7u8; 32];
        raw[0] = 42;
        let new = Vault::from_root(&RootKey::from_bytes(raw));

        // Lazy re-encrypt: old blob → new blob (Some), and decrypts under the new vault.
        let reenc = reencrypt_file_blob(&new, &old, &blob).unwrap().expect("should re-encrypt");
        assert_eq!(new.decrypt_file(&reenc).unwrap(), plaintext);
        // A blob already under the new root needs no rewrite (None).
        assert!(reencrypt_file_blob(&new, &old, &reenc).unwrap().is_none());
        let _ = dir; // keep the home alive for the test lifetime
    }

    #[tokio::test]
    async fn rewrap_closure_runs_in_phase_3() {
        let (dir, db_path, pool, old) = fixture().await;
        use std::sync::atomic::{AtomicBool, Ordering};
        use std::sync::Arc;
        let ran = Arc::new(AtomicBool::new(false));
        let ran2 = ran.clone();
        let report = rotate_root(&pool, &old, &db_path, dir.path(), false, move |_db, _v| {
            let ran2 = ran2.clone();
            async move {
                ran2.store(true, Ordering::SeqCst);
                Ok(())
            }
        })
        .await
        .unwrap();
        assert!(ran.load(Ordering::SeqCst), "rewrap closure must run");
        assert_eq!(report.generation, 1);
        pool.close().await;
    }

    /// Mint a fresh random root for a simulated rotation (no keyring/file writes).
    fn fresh_root() -> RootKey {
        let mut raw = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut raw);
        let root = RootKey::from_bytes(raw);
        raw.zeroize();
        root
    }

    /// Seed one secret sealed under `v` and return its AAD.
    async fn seed_secret(pool: &SqlitePool, v: &Vault, key: &str, plaintext: &str) -> String {
        let aad = secret_value_aad(key);
        let sealed = v.seal_field(plaintext.as_bytes(), &aad).unwrap();
        vault_secrets::insert(
            pool,
            &NewVaultSecret { key: key.into(), value_encrypted: sealed, ..Default::default() },
        )
        .await
        .unwrap();
        aad
    }

    /// Crash window A: the rekey completed but the new root was never persisted (the classic
    /// permanent-brick window). Boot recovery must promote the journaled new root — no data loss.
    #[tokio::test]
    async fn recover_promotes_new_root_when_rekey_completed_but_persist_didnt() {
        let (dir, db_path, pool, old) = fixture().await;
        let aad = seed_secret(&pool, &old, "API_KEY", "S3CRET").await;

        // Simulate a rotation that crashed AFTER rekey, BEFORE persist: journal written, secrets
        // resealed to new, DB rekeyed to new — but vault.key still holds the OLD root.
        let new_root = fresh_root();
        let new_vault = Vault::from_root(&new_root);
        let new_key = Vault::db_key_hex_for(&new_root);
        write_journal(dir.path(), 1, &new_root, false).unwrap();
        reseal_all(&pool, &old, &new_vault).await.unwrap();
        pool.close().await;
        rekey_db_file(&db_path, &old.db_key_hex(), &new_key).await.unwrap();
        // Precondition: the OLD root can no longer open the DB (the brick, pre-fix).
        assert!(!db_opens_under(&db_path, &old.db_key_hex()).await);

        let changed = recover_interrupted_rotation(dir.path(), &db_path, &old, false).await.unwrap();
        assert!(changed, "recovery must report the root changed");

        // vault.key now holds the new root, the journal is gone, and the secret decrypts under new.
        let reloaded = Vault::load_or_create(dir.path(), false).unwrap();
        assert_eq!(reloaded.db_key_hex(), new_key, "new root promoted to vault.key");
        assert!(read_journal(dir.path()).unwrap().is_none(), "journal removed after recovery");
        let reopened = db::open(&db_path, &new_key).await.unwrap();
        let row = vault_secrets::get_by_key(&reopened, "API_KEY").await.unwrap().unwrap();
        assert_eq!(reloaded.open_field(&row.value_encrypted, &aad).unwrap(), b"S3CRET");
        reopened.close().await;
    }

    /// Crash window B: the rekey never ran (DB still under the old root), with a secret already
    /// resealed to the new root. Boot recovery must drive the rotation FORWARD to completion
    /// (idempotent reseal → rekey → persist), leaving everything consistent under the new root.
    #[tokio::test]
    async fn recover_completes_forward_when_rekey_never_ran() {
        let (dir, db_path, pool, old) = fixture().await;
        let aad = seed_secret(&pool, &old, "API_KEY", "S3CRET").await;

        // Simulate a crash DURING reseal, before rekey: journal written + the secret resealed to new,
        // but the DB is still keyed under the OLD root (no rekey happened).
        let new_root = fresh_root();
        let new_vault = Vault::from_root(&new_root);
        let new_key = Vault::db_key_hex_for(&new_root);
        write_journal(dir.path(), 1, &new_root, false).unwrap();
        reseal_all(&pool, &old, &new_vault).await.unwrap();
        pool.close().await;
        assert!(db_opens_under(&db_path, &old.db_key_hex()).await, "DB still under the old root");

        let changed = recover_interrupted_rotation(dir.path(), &db_path, &old, false).await.unwrap();
        assert!(changed, "recovery must complete the rotation forward");

        let reloaded = Vault::load_or_create(dir.path(), false).unwrap();
        assert_eq!(reloaded.db_key_hex(), new_key, "forward completion persisted the new root");
        assert!(read_journal(dir.path()).unwrap().is_none(), "journal removed after completion");
        let reopened = db::open(&db_path, &new_key).await.unwrap();
        let row = vault_secrets::get_by_key(&reopened, "API_KEY").await.unwrap().unwrap();
        assert_eq!(reloaded.open_field(&row.value_encrypted, &aad).unwrap(), b"S3CRET");
        reopened.close().await;
    }

    /// No journal ⇒ recovery is a transparent no-op (the overwhelmingly common boot).
    #[tokio::test]
    async fn recover_is_noop_without_a_journal() {
        let (dir, db_path, pool, old) = fixture().await;
        pool.close().await;
        let changed = recover_interrupted_rotation(dir.path(), &db_path, &old, false).await.unwrap();
        assert!(!changed, "no journal → nothing to recover");
    }
}
