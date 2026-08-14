//! Encrypted backup / restore / factory-reset of the `~/.writ` home (PROD-16).
//!
//! A backup is a SINGLE `age`-encrypted archive (`.writ-backup.age`) sealed under a user passphrase
//! (or the BIP39 recovery secret from [`crate::local::vault_recovery`]). Inside the age STREAM sits a
//! tiny self-describing container ([`ARCHIVE_MAGIC`]) bundling:
//!   * `writ.db`     — the SQLCipher-encrypted database (already Layer-A encrypted; age is a second
//!                     wrap so the archive is safe to move off-device under just the passphrase).
//!   * `config.toml` — the on-disk config (non-secret; carries no keys/tokens).
//!   * `manifest.json` — app/schema versions, per-entry size + sha256, created-at.
//!
//! NOT included: the vault root (`vault.key` / OS keyring), the `wlt_` local token, `runtime.json`,
//! the singleton lock, or the file/artifact stores. The DB is SQLCipher-encrypted with a key derived
//! from the vault root, so a restored `writ.db` is only readable on a device whose vault root matches
//! (or after a recovery re-enroll). The age passphrase protects the archive in transit; the vault
//! root protects the data at rest — two independent secrets, by design (no silent key escrow).
//!
//! ## Atomic restore
//! [`restore`] decrypts into a `*.restore-tmp` staging file, VALIDATES it (magic, manifest, per-entry
//! sha256, and a trial SQLCipher open under the live vault key), and only then atomically swaps the
//! live `writ.db` (renaming the current one to `writ.db.pre-restore-<ts>` as a rollback copy). A
//! validation failure leaves the live DB untouched. The daemon MUST restart afterward (the caller's
//! REST handler returns `needs_restart=true`) because the running pool still holds the old file.
//!
//! ## Reset (delete-all / factory)
//! [`reset`] wipes the database, the file store, and the artifact store. It KEEPS the vault root by
//! default (so existing backups remain restorable) or, with `rotate_vault=true`, removes `vault.key`
//! too for a clean-slate identity (the next boot mints a fresh root — old backups become unreadable).
//!
//! House style: module-local [`BackupError`] (callers branch on the variant) converting into
//! `LocalError` at the API edge; `tracing` only; NEVER logs the passphrase, the recovery secret, or
//! any key/byte of plaintext. Net-new Rust behind the `local` feature. `age` is already a `local` dep.

use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use age::secrecy::SecretString;
use sha2::{Digest, Sha256};

use crate::local::config::Paths;
use crate::local::db;
use crate::local::error::LocalError;

/// Container magic for the (pre-age) archive plaintext. Bump the trailing digit on a breaking layout
/// change so an older binary refuses a newer archive.
pub const ARCHIVE_MAGIC: &[u8; 8] = b"WRITBKP1";

/// Default backup filename produced by [`export`] under the home root.
pub const DEFAULT_BACKUP_NAME: &str = "writ-backup.age";

/// The first bytes of every archive [`export`] writes: the age v1 STREAM header (binary format — we
/// never armor). Public so the REST edge can cheaply answer "is this file actually one of our
/// archives?" WITHOUT the passphrase.
pub const AGE_STREAM_MAGIC: &[u8] = b"age-encryption.org/v1";

/// Best-effort, passphrase-free check that `path` is an age-encrypted archive (i.e. plausibly one of
/// ours), by reading only its first [`AGE_STREAM_MAGIC`] bytes.
///
/// SECURITY: this is the content-level half of the `/v1/backup/download` guard. Path containment
/// alone is not enough there, because the home root is exactly where the crown jewels live
/// (`vault.key`, `runtime.json` with the master `wlt_` bearer, `writ.db`, `tls/ca.key`). None of those
/// begin with the age header, so requiring it turns "any file under the home" into "an encrypted
/// archive under the home" — the only thing that endpoint has any business serving. Cheap enough to
/// run per request (one short read); a missing/unreadable file is simply `false`.
pub fn looks_like_archive(path: &Path) -> bool {
    use std::io::Read as _;
    let Ok(mut f) = std::fs::File::open(path) else {
        return false;
    };
    let mut head = vec![0u8; AGE_STREAM_MAGIC.len()];
    match f.read_exact(&mut head) {
        Ok(()) => head == AGE_STREAM_MAGIC,
        // Shorter than the header ⇒ cannot be an archive.
        Err(_) => false,
    }
}

/// Cap on a single archived entry (defensive bound against a hostile/corrupt manifest at restore).
const MAX_ENTRY_BYTES: u64 = 8 * 1024 * 1024 * 1024; // 8 GiB

/// Module-local error. Converts into [`LocalError`] at the REST edge via [`From`].
#[derive(Debug, thiserror::Error)]
pub enum BackupError {
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("the passphrase is empty")]
    EmptyPassphrase,
    #[error("encrypt failed: {0}")]
    Encrypt(String),
    /// Wrong passphrase or a damaged/foreign archive (age could not be decrypted).
    #[error("decrypt failed (wrong passphrase or damaged archive)")]
    Decrypt,
    #[error("not a Writ backup archive (bad magic)")]
    BadMagic,
    #[error("backup archive is corrupt: {0}")]
    Corrupt(String),
    #[error("backup manifest is invalid: {0}")]
    BadManifest(String),
    #[error("the restored database failed validation: {0}")]
    RestoreValidation(String),
    #[error("backup file not found: {0}")]
    NotFound(String),
}

pub type BackupResult<T> = Result<T, BackupError>;

impl From<BackupError> for LocalError {
    fn from(e: BackupError) -> Self {
        match e {
            BackupError::EmptyPassphrase
            | BackupError::BadMagic
            | BackupError::BadManifest(_)
            | BackupError::Decrypt => LocalError::BadRequest(e.to_string()),
            BackupError::NotFound(_) => LocalError::NotFound(e.to_string()),
            BackupError::Io(io) => LocalError::Io(io),
            other => LocalError::Internal(other.to_string()),
        }
    }
}

/// One archived file's metadata (size + content hash) for restore-time validation.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ManifestEntry {
    pub name: String,
    pub size: u64,
    /// Lowercase-hex SHA-256 of the entry's bytes (as stored — for the DB that is the SQLCipher
    /// ciphertext, since the DB is never decrypted during backup).
    pub sha256: String,
}

/// Archive manifest — versions + the entry table. Lets restore reject an archive from a NEWER app
/// (future schema) and verify integrity before swapping anything live.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct Manifest {
    /// `CARGO_PKG_VERSION` of the binary that wrote the archive (informational).
    pub app_version: String,
    /// [`db::APP_SCHEMA_VERSION`] at export time — restore refuses a value greater than this binary's.
    pub schema_version: u32,
    /// RFC3339 creation instant.
    pub created_at: String,
    pub entries: Vec<ManifestEntry>,
}

/// Result of [`export`].
#[derive(Debug, Clone, serde::Serialize)]
pub struct ExportReport {
    /// Absolute path of the written archive.
    pub path: String,
    pub bytes: u64,
    pub schema_version: u32,
    pub created_at: String,
}

/// Result of [`restore`].
#[derive(Debug, Clone, serde::Serialize)]
pub struct RestoreReport {
    /// Path the previous live DB was moved to (rollback copy), if one existed.
    pub previous_db_backup: Option<String>,
    pub schema_version: u32,
    /// Always true — the running pool still holds the OLD file; the daemon must restart to use the
    /// restored DB.
    pub needs_restart: bool,
}

/// Result of [`reset`].
#[derive(Debug, Clone, serde::Serialize)]
pub struct ResetReport {
    pub db_removed: bool,
    pub files_removed: u64,
    pub artifacts_removed: u64,
    /// Whether the vault root (`vault.key`) was also rotated away.
    pub vault_rotated: bool,
    pub needs_restart: bool,
}

fn require_passphrase(p: &str) -> BackupResult<SecretString> {
    if p.trim().is_empty() {
        return Err(BackupError::EmptyPassphrase);
    }
    Ok(SecretString::new(p.to_string()))
}

fn sha256_hex(bytes: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(bytes);
    h.finalize().iter().map(|b| format!("{b:02x}")).collect()
}

fn now_rfc3339() -> String {
    chrono::Utc::now().format("%Y-%m-%dT%H:%M:%S%.3fZ").to_string()
}

// ── archive container (pre-age plaintext) ───────────────────────────────────────────────────────
//
// Layout: MAGIC(8) || u32-LE manifest_len || manifest_json || [ u32-LE name_len || name ||
// u64-LE data_len || data ]*. The manifest's `entries` ordering matches the body order, but restore
// keys off the name + verifies the sha256, so order is not load-bearing.

fn write_container<W: Write>(out: &mut W, manifest: &Manifest, files: &[(String, Vec<u8>)]) -> BackupResult<()> {
    out.write_all(ARCHIVE_MAGIC)?;
    let manifest_json = serde_json::to_vec(manifest)
        .map_err(|e| BackupError::Corrupt(format!("manifest serialize: {e}")))?;
    out.write_all(&(manifest_json.len() as u32).to_le_bytes())?;
    out.write_all(&manifest_json)?;
    for (name, data) in files {
        let nb = name.as_bytes();
        out.write_all(&(nb.len() as u32).to_le_bytes())?;
        out.write_all(nb)?;
        out.write_all(&(data.len() as u64).to_le_bytes())?;
        out.write_all(data)?;
    }
    Ok(())
}

fn read_exact_or<R: Read>(r: &mut R, buf: &mut [u8]) -> BackupResult<()> {
    r.read_exact(buf).map_err(|e| {
        if e.kind() == std::io::ErrorKind::UnexpectedEof {
            BackupError::Corrupt("archive ended early".into())
        } else {
            BackupError::Io(e)
        }
    })
}

fn read_container<R: Read>(r: &mut R) -> BackupResult<(Manifest, Vec<(String, Vec<u8>)>)> {
    let mut magic = [0u8; 8];
    read_exact_or(r, &mut magic)?;
    if &magic != ARCHIVE_MAGIC {
        return Err(BackupError::BadMagic);
    }
    let mut len4 = [0u8; 4];
    read_exact_or(r, &mut len4)?;
    let mlen = u32::from_le_bytes(len4) as usize;
    if mlen as u64 > MAX_ENTRY_BYTES {
        return Err(BackupError::Corrupt("manifest implausibly large".into()));
    }
    let mut mbuf = vec![0u8; mlen];
    read_exact_or(r, &mut mbuf)?;
    let manifest: Manifest = serde_json::from_slice(&mbuf)
        .map_err(|e| BackupError::BadManifest(format!("parse: {e}")))?;

    let mut files = Vec::with_capacity(manifest.entries.len());
    // Read exactly the number of declared entries.
    for _ in 0..manifest.entries.len() {
        read_exact_or(r, &mut len4)?;
        let nlen = u32::from_le_bytes(len4) as usize;
        if nlen > 4096 {
            return Err(BackupError::Corrupt("entry name implausibly long".into()));
        }
        let mut nbuf = vec![0u8; nlen];
        read_exact_or(r, &mut nbuf)?;
        let name = String::from_utf8(nbuf)
            .map_err(|_| BackupError::Corrupt("entry name not utf-8".into()))?;
        let mut len8 = [0u8; 8];
        read_exact_or(r, &mut len8)?;
        let dlen = u64::from_le_bytes(len8);
        if dlen > MAX_ENTRY_BYTES {
            return Err(BackupError::Corrupt(format!("entry {name} implausibly large")));
        }
        let mut data = vec![0u8; dlen as usize];
        read_exact_or(r, &mut data)?;
        files.push((name, data));
    }
    Ok((manifest, files))
}

// ── age STREAM seal/open ─────────────────────────────────────────────────────────────────────────

fn age_seal(plaintext: &[u8], pass: &SecretString) -> BackupResult<Vec<u8>> {
    let encryptor = age::Encryptor::with_user_passphrase(pass.clone());
    let mut encrypted = Vec::with_capacity(plaintext.len() + 256);
    let mut writer = encryptor
        .wrap_output(&mut encrypted)
        .map_err(|e| BackupError::Encrypt(e.to_string()))?;
    writer
        .write_all(plaintext)
        .map_err(|e| BackupError::Encrypt(e.to_string()))?;
    writer
        .finish()
        .map_err(|e| BackupError::Encrypt(e.to_string()))?;
    Ok(encrypted)
}

fn age_open(ciphertext: &[u8], pass: &SecretString) -> BackupResult<Vec<u8>> {
    let decryptor = match age::Decryptor::new(ciphertext).map_err(|_| BackupError::Decrypt)? {
        age::Decryptor::Passphrase(d) => d,
        // A recipients-encrypted archive isn't something we produce; treat as wrong-format.
        age::Decryptor::Recipients(_) => return Err(BackupError::Decrypt),
    };
    let mut reader = decryptor.decrypt(pass, None).map_err(|_| BackupError::Decrypt)?;
    let mut out = Vec::new();
    reader.read_to_end(&mut out).map_err(|_| BackupError::Decrypt)?;
    Ok(out)
}

// ── public API ───────────────────────────────────────────────────────────────────────────────────

/// Export an encrypted backup of `~/.writ` to `dest` (or the default `~/.writ/<DEFAULT_BACKUP_NAME>`
/// when `None`). Bundles `writ.db` + `config.toml` + a manifest into the age-encrypted archive under
/// `passphrase`. The archive is written `0600`. Returns the path + size. NEVER logs the passphrase or
/// the db key.
///
/// `db_key` is the live SQLCipher key (`vault.db_key_hex()`). It is used to take a CONSISTENT snapshot
/// of the database via `VACUUM INTO` rather than a raw `std::fs::read` of a live file (DL-3): a raw
/// read can catch the pool mid-write and archive a torn page image whose sha256 still matches the
/// torn bytes, so corruption is only discovered at restore. `VACUUM INTO` runs a read transaction and
/// writes a fully-checkpointed, self-consistent single-file copy — no separate `-wal` sidecar is
/// needed (all committed pages are folded in), which also removes the unvalidated-WAL-replay hazard.
pub async fn export(
    paths: &Paths,
    passphrase: &str,
    db_key: &str,
    dest: Option<&Path>,
) -> BackupResult<ExportReport> {
    let pass = require_passphrase(passphrase)?;

    let mut files: Vec<(String, Vec<u8>)> = Vec::new();
    let mut entries: Vec<ManifestEntry> = Vec::new();

    let db_path = paths.db();
    if !db_path.exists() {
        return Err(BackupError::NotFound(format!("database at {}", db_path.display())));
    }
    // Snapshot the DB consistently into a temp file, read those bytes, then remove the temp. The
    // snapshot is itself SQLCipher-encrypted under the same key, so the archived bytes stay encrypted.
    let db_bytes = snapshot_db(&db_path, db_key).await?;
    entries.push(ManifestEntry {
        name: "writ.db".into(),
        size: db_bytes.len() as u64,
        sha256: sha256_hex(&db_bytes),
    });
    files.push(("writ.db".into(), db_bytes));

    // config.toml is optional (a daemon that never wrote one still backs up the DB).
    let cfg_path = paths.config_toml();
    if cfg_path.exists() {
        let cfg_bytes = std::fs::read(&cfg_path)?;
        entries.push(ManifestEntry {
            name: "config.toml".into(),
            size: cfg_bytes.len() as u64,
            sha256: sha256_hex(&cfg_bytes),
        });
        files.push(("config.toml".into(), cfg_bytes));
    }

    let created_at = now_rfc3339();
    let manifest = Manifest {
        app_version: env!("CARGO_PKG_VERSION").to_string(),
        schema_version: db::APP_SCHEMA_VERSION,
        created_at: created_at.clone(),
        entries,
    };

    let mut plaintext = Vec::new();
    write_container(&mut plaintext, &manifest, &files)?;
    let sealed = age_seal(&plaintext, &pass)?;
    // Scrub the plaintext container (it held the SQLCipher ciphertext, not secrets, but be tidy).
    plaintext.clear();

    let dest = dest
        .map(PathBuf::from)
        .unwrap_or_else(|| paths.root.join(DEFAULT_BACKUP_NAME));
    if let Some(parent) = dest.parent() {
        std::fs::create_dir_all(parent)?;
    }
    write_0600(&dest, &sealed)?;

    tracing::info!(path = %dest.display(), bytes = sealed.len(), "encrypted backup written");
    Ok(ExportReport {
        path: dest.to_string_lossy().to_string(),
        bytes: sealed.len() as u64,
        schema_version: db::APP_SCHEMA_VERSION,
        created_at,
    })
}

/// Decrypt + validate a backup archive WITHOUT touching the live home — returns its manifest. Used to
/// preview a restore (and as the validation core of [`restore`]). A wrong passphrase or damaged
/// archive errors; per-entry sha256 is verified.
pub fn inspect(archive: &Path, passphrase: &str) -> BackupResult<Manifest> {
    let pass = require_passphrase(passphrase)?;
    if !archive.exists() {
        return Err(BackupError::NotFound(archive.display().to_string()));
    }
    let sealed = std::fs::read(archive)?;
    let plaintext = age_open(&sealed, &pass)?;
    let (manifest, files) = read_container(&mut &plaintext[..])?;
    validate_against_manifest(&manifest, &files)?;
    Ok(manifest)
}

/// Verify the body entries match the manifest (every manifest entry is present with the declared size
/// and sha256). Also refuses an archive from a NEWER app (future schema_version).
fn validate_against_manifest(manifest: &Manifest, files: &[(String, Vec<u8>)]) -> BackupResult<()> {
    if manifest.schema_version > db::APP_SCHEMA_VERSION {
        return Err(BackupError::BadManifest(format!(
            "archive is from a newer app version (schema {} > {})",
            manifest.schema_version,
            db::APP_SCHEMA_VERSION
        )));
    }
    for entry in &manifest.entries {
        let found = files
            .iter()
            .find(|(n, _)| n == &entry.name)
            .ok_or_else(|| BackupError::Corrupt(format!("manifest entry {} missing from body", entry.name)))?;
        if found.1.len() as u64 != entry.size {
            return Err(BackupError::Corrupt(format!("entry {} size mismatch", entry.name)));
        }
        if sha256_hex(&found.1) != entry.sha256 {
            return Err(BackupError::Corrupt(format!("entry {} sha256 mismatch", entry.name)));
        }
    }
    if !manifest.entries.iter().any(|e| e.name == "writ.db") {
        return Err(BackupError::BadManifest("archive has no writ.db entry".into()));
    }
    Ok(())
}

/// Atomically restore a backup archive over the live home. `db_key` is the daemon's live SQLCipher
/// key (`vault.db_key_hex()`); a restored DB is trial-opened under it to prove it is readable on THIS
/// device before any swap. On success the previous `writ.db` is renamed to `writ.db.pre-restore-<ts>`
/// and the restored DB takes its place; `config.toml` (if present in the archive) is restored too.
///
/// The caller MUST stop the running DB pool (or restart the daemon) — the live pool still holds the
/// pre-restore file. The handler signals this via `needs_restart=true`. NEVER logs the passphrase or
/// the db key.
pub async fn restore(
    paths: &Paths,
    archive: &Path,
    passphrase: &str,
    db_key: &str,
) -> BackupResult<RestoreReport> {
    let pass = require_passphrase(passphrase)?;
    if !archive.exists() {
        return Err(BackupError::NotFound(archive.display().to_string()));
    }

    // 1. Decrypt + validate the container in memory (no live file touched yet).
    let sealed = std::fs::read(archive)?;
    let plaintext = age_open(&sealed, &pass)?;
    let (manifest, files) = read_container(&mut &plaintext[..])?;
    validate_against_manifest(&manifest, &files)?;

    let db_bytes = &files
        .iter()
        .find(|(n, _)| n == "writ.db")
        .expect("validate ensured writ.db is present")
        .1;

    // 2. Stage the restored DB to a temp path next to the live DB. If the archive carried a WAL
    // sidecar (legacy archives only — new exports snapshot via VACUUM INTO and archive no WAL), stage
    // it ALONGSIDE the staged DB so the trial open validates the main+WAL PAIR together (DL-4): SQLite
    // replays the staged WAL during the trial open, so a WAL that doesn't apply cleanly fails
    // validation and leaves the live DB untouched, instead of being blindly copied in after the swap.
    let live_db = paths.db();
    let stage = with_suffix(&live_db, ".restore-tmp");
    let stage_wal = sidecar(&stage, "-wal");
    // Clean any leftover stage sidecars from a prior aborted restore so the trial open is clean.
    let _ = std::fs::remove_file(&stage_wal);
    let _ = std::fs::remove_file(sidecar(&stage, "-shm"));
    write_0600(&stage, db_bytes)?;
    let staged_wal = files.iter().any(|(n, _)| n == "writ.db-wal");
    if let Some((_, wal_bytes)) = files.iter().find(|(n, _)| n == "writ.db-wal") {
        write_0600(&stage_wal, wal_bytes)?;
    }

    let cleanup_stage = || {
        let _ = std::fs::remove_file(&stage);
        for ext in ["-wal", "-shm"] {
            let _ = std::fs::remove_file(sidecar(&stage, ext));
        }
    };

    // PROVE the staged pair opens under the live vault key (trial SQLCipher open replays the staged
    // WAL + runs the integrity check) before swapping anything. `trial_open` opens then closes a pool
    // over the staged file; in WAL mode the archived WAL is replayed and checkpointed into the staged
    // main file on that clean open/close, so a WAL that doesn't apply fails HERE (leaving the live DB
    // untouched) rather than being blindly written in after the swap.
    if let Err(e) = trial_open(&stage, db_key).await {
        cleanup_stage();
        return Err(BackupError::RestoreValidation(e));
    }
    // 3. Swap atomically-enough: move the current live DB aside (rollback copy), then rename the
    // staged DB into place. WAL/SHM sidecars of the OLD db are moved aside too so the restored DB
    // can't adopt a stale write-ahead log. The staged file+WAL are moved TOGETHER (the pair was
    // validated together), so no unvalidated post-swap WAL copy happens.
    let previous = if live_db.exists() {
        let ts = chrono::Utc::now().format("%Y%m%dT%H%M%SZ");
        let prev = with_suffix(&live_db, &format!(".pre-restore-{ts}"));
        if let Err(e) = std::fs::rename(&live_db, &prev) {
            cleanup_stage();
            return Err(BackupError::Io(e));
        }
        for ext in ["-wal", "-shm"] {
            let side = sidecar(&live_db, ext);
            if side.exists() {
                let _ = std::fs::rename(&side, sidecar(&prev, ext));
            }
        }
        Some(prev.to_string_lossy().to_string())
    } else {
        None
    };
    std::fs::rename(&stage, &live_db)?;
    // Move the validated staged WAL (if any survived the trial open's checkpoint) alongside the DB.
    if staged_wal && stage_wal.exists() {
        let _ = std::fs::rename(&stage_wal, sidecar(&live_db, "-wal"));
    }

    // 4. Restore config.toml when the archive carried one (best-effort: a config restore failure does
    // not undo the DB swap — the DB is the important payload).
    if let Some((_, cfg_bytes)) = files.iter().find(|(n, _)| n == "config.toml") {
        if let Err(e) = write_0600(&paths.config_toml(), cfg_bytes) {
            tracing::warn!(error = %e, "restore: could not write config.toml (db restored anyway)");
        }
    }

    tracing::info!(
        archive = %archive.display(),
        schema_version = manifest.schema_version,
        "database restored from backup (restart required)"
    );
    Ok(RestoreReport {
        previous_db_backup: previous,
        schema_version: manifest.schema_version,
        needs_restart: true,
    })
}

/// Take a CONSISTENT SQLCipher snapshot of the live DB into a temp file and return its bytes (DL-3).
///
/// Opens a dedicated read connection under `db_key` and runs `VACUUM INTO`, which executes inside a
/// read transaction and writes a fully-checkpointed, self-consistent copy — never a torn page image
/// from a concurrent write. The snapshot is encrypted under the SAME key (SQLCipher `VACUUM INTO`
/// inherits the source connection's cipher), so the returned bytes are still Layer-A encrypted. The
/// temp file is removed before returning (and on every error path). NEVER logs the db key.
async fn snapshot_db(db_path: &Path, db_key: &str) -> BackupResult<Vec<u8>> {
    use sqlx::sqlite::SqliteConnectOptions;
    use sqlx::{ConnectOptions, Connection};

    // A unique sibling temp so `VACUUM INTO` can create it (SQLite requires the target not exist).
    let snap = with_suffix(db_path, &format!(".backup-snap-{}", std::process::id()));
    let _ = std::fs::remove_file(&snap);
    for ext in ["-wal", "-shm"] {
        let _ = std::fs::remove_file(sidecar(&snap, ext));
    }

    // MUST be the same key FORM the daemon's pool uses. A 64-hex vault key is applied as SQLCipher's
    // RAW key (`x'<hex>'`), not as a passphrase (`'<hex>'`) — the two derive DIFFERENT AES keys, so
    // the passphrase form this used to build could not decrypt a DB written by `db::open` and every
    // export died with `VACUUM INTO snapshot failed: … (code: 26) file is not a database`.
    let keyed = crate::local::db::key_pragma_value(db_key);
    let open = SqliteConnectOptions::new()
        .filename(db_path)
        .create_if_missing(false)
        .pragma("key", keyed)
        .pragma("busy_timeout", "5000")
        .connect()
        .await;
    let mut conn = match open {
        Ok(c) => c,
        Err(e) => return Err(BackupError::Corrupt(format!("could not open DB for snapshot: {e}"))),
    };

    // `VACUUM INTO 'path'` — a single quoted string literal; escape any quote in the path.
    let target = format!("'{}'", snap.to_string_lossy().replace('\'', "''"));
    let vac = sqlx::query(&format!("VACUUM INTO {target}")).execute(&mut conn).await;
    let _ = conn.close().await;

    let cleanup = || {
        let _ = std::fs::remove_file(&snap);
        for ext in ["-wal", "-shm"] {
            let _ = std::fs::remove_file(sidecar(&snap, ext));
        }
    };

    if let Err(e) = vac {
        cleanup();
        return Err(BackupError::Corrupt(format!("VACUUM INTO snapshot failed: {e}")));
    }
    let bytes = match std::fs::read(&snap) {
        Ok(b) => b,
        Err(e) => {
            cleanup();
            return Err(BackupError::Io(e));
        }
    };
    cleanup();
    Ok(bytes)
}

/// Trial-open a staged DB under `db_key` to confirm the cipher key matches + the file passes its
/// integrity check. Returns `Ok(())` if the DB is usable on this device, else a human reason string.
async fn trial_open(path: &Path, db_key: &str) -> Result<(), String> {
    match db::open(path, db_key).await {
        Ok(pool) => {
            pool.close().await;
            Ok(())
        }
        Err(LocalError::CipherUnavailable) => {
            Err("SQLCipher unavailable in this build".into())
        }
        Err(LocalError::Corrupt(d)) => Err(format!("integrity check failed: {d}")),
        // A key mismatch surfaces as a generic open/migrate error (SQLCipher can't read the pages).
        Err(e) => Err(format!(
            "restored DB is not readable on this device (wrong vault root?): {e}"
        )),
    }
}

/// Factory reset / delete-all: wipe the database (+ its WAL/SHM sidecars), the file store, and the
/// artifact store. KEEPS the vault root by default so existing backups stay restorable; pass
/// `rotate_vault=true` to ALSO remove `vault.key` for a clean-slate identity (the next boot mints a
/// fresh root and old backups become unreadable). The caller must restart the daemon afterward.
///
/// With `rotate_vault=true` this is a FULL erase: it removes BOTH the `vault.key` file fallback AND
/// the OS-keyring root entry, so no key material survives to decrypt a DB later recovered from disk or
/// an old backup (closes the erasure gap — otherwise a keyring-rooted install kept the key). Without
/// it (the default), the vault root is preserved so existing backups stay restorable.
pub fn reset(paths: &Paths, rotate_vault: bool) -> BackupResult<ResetReport> {
    // 1. DB + sidecars.
    let db_path = paths.db();
    let db_removed = remove_if_exists(&db_path)?;
    for ext in ["-wal", "-shm"] {
        let _ = std::fs::remove_file(sidecar(&db_path, ext));
    }

    // 2. File store + artifact store (the dirs are recreated empty so the daemon's layout invariants
    // hold without a full `ensure_dirs`).
    let files_removed = wipe_dir_contents(&paths.files_dir())?;
    let artifacts_removed = wipe_dir_contents(&paths.artifacts_dir())?;

    // 3. Optionally rotate the vault root — a FULL erase removes BOTH the file fallback AND the
    // OS-keyring entry, so no key material survives to decrypt a later-recovered DB/backup.
    let vault_rotated = if rotate_vault {
        let file_removed = remove_if_exists(&paths.vault_key())?;
        // Best-effort keyring purge (non-fatal: the file is already gone). A file-rooted install has
        // no entry → clean no-op.
        let keyring_removed = match crate::local::vault::Vault::keyring_delete() {
            Ok(removed) => removed,
            Err(e) => {
                tracing::warn!(error = %e, "could not remove the OS-keyring vault root during reset");
                false
            }
        };
        file_removed || keyring_removed
    } else {
        false
    };

    tracing::warn!(
        db_removed,
        files_removed,
        artifacts_removed,
        vault_rotated,
        "factory reset wiped local data (restart required)"
    );
    Ok(ResetReport {
        db_removed,
        files_removed,
        artifacts_removed,
        vault_rotated,
        needs_restart: true,
    })
}

// ── fs helpers ───────────────────────────────────────────────────────────────────────────────────

fn with_suffix(path: &Path, suffix: &str) -> PathBuf {
    let name = path.file_name().and_then(|s| s.to_str()).unwrap_or("writ.db");
    path.with_file_name(format!("{name}{suffix}"))
}

fn sidecar(db_path: &Path, ext: &str) -> PathBuf {
    let name = db_path.file_name().and_then(|s| s.to_str()).unwrap_or("writ.db");
    db_path.with_file_name(format!("{name}{ext}"))
}

fn remove_if_exists(path: &Path) -> BackupResult<bool> {
    match std::fs::remove_file(path) {
        Ok(()) => Ok(true),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(e) => Err(BackupError::Io(e)),
    }
}

/// Remove every entry directly under `dir` (recursively), leaving `dir` itself in place + empty.
/// Returns the count of top-level entries removed. A missing `dir` is treated as "nothing to remove".
fn wipe_dir_contents(dir: &Path) -> BackupResult<u64> {
    let read = match std::fs::read_dir(dir) {
        Ok(r) => r,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(0),
        Err(e) => return Err(BackupError::Io(e)),
    };
    let mut n = 0u64;
    for entry in read {
        let entry = entry?;
        let path = entry.path();
        let ft = entry.file_type()?;
        let res = if ft.is_dir() {
            std::fs::remove_dir_all(&path)
        } else {
            std::fs::remove_file(&path)
        };
        match res {
            Ok(()) => n += 1,
            Err(e) => tracing::warn!(path = %path.display(), error = %e, "reset: could not remove entry"),
        }
    }
    Ok(n)
}

/// Write a backup archive / staged DB `0600` via the shared atomic secret writer so the bytes are
/// never world-readable even briefly (write-then-chmod race). Maps the shared `LocalError` back to
/// this module's IO variant.
fn write_0600(path: &Path, bytes: &[u8]) -> BackupResult<()> {
    crate::local::vault::write_secret_file(path, bytes).map_err(|e| match e {
        LocalError::Io(io) => BackupError::Io(io),
        other => BackupError::Io(std::io::Error::other(other.to_string())),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::local::vault::Vault;
    use sqlx::Row as _;

    /// Build a real encrypted home (vault + migrated DB + a config.toml) and return its paths + key.
    async fn home() -> (tempfile::TempDir, Paths, String) {
        let dir = tempfile::tempdir().unwrap();
        let paths = Paths::at(dir.path().join(".writ"));
        paths.ensure_dirs().unwrap();
        let vault = Vault::load_or_create(&paths.root, false).unwrap();
        let key = vault.db_key_hex();
        let pool = db::open(&paths.db(), &key).await.unwrap();
        // Seed a recognizable row so restore round-trip can be asserted.
        sqlx::query("INSERT INTO config (key, value) VALUES ('marker', 'original')")
            .execute(&pool)
            .await
            .unwrap();
        pool.close().await;
        crate::local::config::write_config(&paths, &crate::local::config::LocalConfig::default()).unwrap();
        (dir, paths, key)
    }

    #[tokio::test]
    async fn export_then_inspect_roundtrips() {
        let (_d, paths, key) = home().await;
        let report = export(&paths, "correct horse battery staple", &key, None).await.unwrap();
        assert!(Path::new(&report.path).exists());
        assert!(report.bytes > 0);

        // The archive is NOT plaintext (no container magic visible on disk under age).
        let on_disk = std::fs::read(&report.path).unwrap();
        assert_ne!(&on_disk[..8.min(on_disk.len())], ARCHIVE_MAGIC.as_slice());

        let manifest = inspect(Path::new(&report.path), "correct horse battery staple").unwrap();
        assert!(manifest.entries.iter().any(|e| e.name == "writ.db"));
        assert!(manifest.entries.iter().any(|e| e.name == "config.toml"));
        assert_eq!(manifest.schema_version, db::APP_SCHEMA_VERSION);
    }

    /// The passphrase-free archive sniff the `/v1/backup/download` guard leans on: a real export is
    /// recognized, and NONE of the sensitive files that share the home root are.
    #[tokio::test]
    async fn looks_like_archive_accepts_exports_and_rejects_home_secrets() {
        let (_d, paths, key) = home().await;
        let report = export(&paths, "pw-sniff", &key, None).await.unwrap();
        assert!(looks_like_archive(Path::new(&report.path)), "a real export is an age stream");

        // The crown jewels that live in the same directory must all fail the sniff.
        for name in ["vault.key", "runtime.json", "local_token", "writ.db", "config.toml"] {
            let p = paths.root.join(name);
            if !p.exists() {
                // Materialize a plausible stand-in so the assertion is meaningful either way.
                std::fs::write(&p, b"{\"token\":\"wlt_secret\"}").unwrap();
            }
            assert!(!looks_like_archive(&p), "{name} must not pass as an archive");
        }

        // A short file and a missing file are both `false` (never a panic).
        let short = paths.root.join("short.age");
        std::fs::write(&short, b"age").unwrap();
        assert!(!looks_like_archive(&short));
        assert!(!looks_like_archive(&paths.root.join("nope.age")));
    }

    #[tokio::test]
    async fn wrong_passphrase_is_rejected() {
        let (_d, paths, key) = home().await;
        let report = export(&paths, "right-pass", &key, None).await.unwrap();
        let err = inspect(Path::new(&report.path), "wrong-pass").unwrap_err();
        assert!(matches!(err, BackupError::Decrypt), "got {err:?}");
    }

    #[tokio::test]
    async fn empty_passphrase_is_rejected() {
        let (_d, paths, key) = home().await;
        let err = export(&paths, "   ", &key, None).await.unwrap_err();
        assert!(matches!(err, BackupError::EmptyPassphrase));
    }

    #[tokio::test]
    async fn restore_swaps_db_and_keeps_a_rollback_copy() {
        let (_d, paths, key) = home().await;
        // Snapshot at "original", then mutate the live DB to "changed".
        let report = export(&paths, "pw", &key, None).await.unwrap();
        {
            let pool = db::open(&paths.db(), &key).await.unwrap();
            sqlx::query("UPDATE config SET value = 'changed' WHERE key = 'marker'")
                .execute(&pool)
                .await
                .unwrap();
            pool.close().await;
        }

        let rr = restore(&paths, Path::new(&report.path), "pw", &key).await.unwrap();
        assert!(rr.needs_restart);
        assert!(rr.previous_db_backup.is_some(), "rollback copy kept");
        assert!(Path::new(rr.previous_db_backup.as_ref().unwrap()).exists());

        // The restored DB reads back the ORIGINAL value.
        let pool = db::open(&paths.db(), &key).await.unwrap();
        let v: String = sqlx::query("SELECT value FROM config WHERE key='marker'")
            .fetch_one(&pool)
            .await
            .unwrap()
            .try_get(0)
            .unwrap();
        assert_eq!(v, "original", "restore brought back the snapshot");
        pool.close().await;
    }

    #[tokio::test]
    async fn restore_under_a_foreign_key_fails_validation_and_keeps_live_db() {
        let (_d, paths, key) = home().await;
        let report = export(&paths, "pw", &key, None).await.unwrap();

        // Validate restore refuses when the live vault key does not match the archived DB's cipher.
        let foreign_key = "00".repeat(32); // 64 hex chars, wrong key
        let err = restore(&paths, Path::new(&report.path), "pw", &foreign_key).await.unwrap_err();
        assert!(matches!(err, BackupError::RestoreValidation(_)), "got {err:?}");

        // The live DB is untouched (no pre-restore copy, original still opens under the real key).
        let pool = db::open(&paths.db(), &key).await.unwrap();
        let n: i64 = sqlx::query("SELECT count(*) FROM config WHERE key='marker'")
            .fetch_one(&pool)
            .await
            .unwrap()
            .try_get(0)
            .unwrap();
        assert_eq!(n, 1);
        pool.close().await;
    }

    #[tokio::test]
    async fn reset_wipes_db_and_stores_keeps_vault_by_default() {
        let (_d, paths, _key) = home().await;
        // Drop something into the file + artifact stores so the counts are non-trivial.
        std::fs::write(paths.files_dir().join("blob_x.wfb"), b"x").unwrap();
        std::fs::write(paths.artifacts_dir().join("screenshots").join("a.png"), b"y").unwrap();
        assert!(paths.db().exists());
        assert!(paths.vault_key().exists());

        let r = reset(&paths, false).unwrap();
        assert!(r.db_removed);
        assert!(!paths.db().exists(), "db wiped");
        assert!(r.files_removed >= 1);
        assert!(r.artifacts_removed >= 1);
        assert!(!r.vault_rotated);
        assert!(paths.vault_key().exists(), "vault root kept by default");
        assert!(r.needs_restart);
    }

    #[tokio::test]
    async fn reset_with_rotate_removes_the_vault_file() {
        let (_d, paths, _key) = home().await;
        assert!(paths.vault_key().exists());
        let r = reset(&paths, true).unwrap();
        assert!(r.vault_rotated);
        assert!(!paths.vault_key().exists(), "vault file rotated away");
    }
}
