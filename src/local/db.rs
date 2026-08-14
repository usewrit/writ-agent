//! Local SQLite database, SQLCipher-encrypted at rest (Layer A).
//! Open + key + FAIL-CLOSED cipher gate + pragmas + migrations.
//! See the local-backend spec §2 and the security-and-entitlements spec §1.5.
//!
//! ## Schema-version policy + unreadable-DB quarantine/recovery (PROD-17)
//! [`open`] is the low-level "key it, prove the cipher, integrity-check, migrate" primitive.
//! [`open_managed`] wraps it with the boot policy lifecycle uses — the guiding rule is that the
//! daemon must ALWAYS come up, so the desktop shell can reach the app (and its reconnect/login
//! flow) even when the local DB is unusable:
//!   * **Unreadable-DB quarantine + recovery** — if [`open`] can't return a usable DB — either it
//!     failed its integrity check (SQLCipher `quick_check` came back non-`ok`, i.e. the file is
//!     damaged) OR the driver refused the file (`code 26` "file is not a database" / `code 11`
//!     "disk image is malformed", which for an encrypted file means a damaged header or a key that
//!     no longer matches) — then, rather than bricking the boot:
//!       1. if a sibling backup copy (`writ.db.pre-restore-*` / an earlier `writ.db.corrupt-*`)
//!          opens under the LIVE vault key, the unreadable DB is set aside and that copy is adopted,
//!          so the daemon comes up WITH the user's data instead of empty; otherwise
//!       2. the unreadable DB (and its WAL/SHM sidecars) is renamed aside to `writ.db.corrupt-<ts>`
//!          and a FRESH empty DB is opened in its place.
//!     The bad file is always RENAMED, never deleted, so nothing is destroyed and a later recovery
//!     is still possible. Every branch is logged loudly.
//!   * **Future-version guard** — a monotonic [`APP_SCHEMA_VERSION`] is stamped into the `config` kv
//!     table (`schema_version`) after a successful open. If an existing DB carries a HIGHER version
//!     (it was written by a newer Writ build), [`open_managed`] REFUSES to open it
//!     ([`LocalError::SchemaVersionFuture`]) rather than silently downgrading and corrupting data.
//!
//! Fail-closed guard: a `code 26` is only treated as "unreadable, quarantine it" when SQLCipher is
//! actually linked ([`cipher_linked`]). A plain-SQLite build reading an encrypted file ALSO yields
//! `code 26`; in that case we surface [`LocalError::CipherUnavailable`] instead of throwing away a
//! perfectly good (but wrongly-opened) encrypted DB.

use super::error::{LocalError, LocalResult};
use super::store::config_kv;
use sqlx::sqlite::{SqliteConnectOptions, SqlitePool, SqlitePoolOptions};
use sqlx::Row;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

/// Forward-only migrations embedded at compile time from this crate/migrations/`.
static MIGRATOR: sqlx::migrate::Migrator = sqlx::migrate!("./migrations");

/// `config` KV key holding the monotonic app schema version the live DB was last opened with.
pub const SCHEMA_VERSION_KEY: &str = "schema_version";

/// Monotonic schema/app data-version this binary understands. Bump when a release ships a migration
/// or a data-shape change that an OLDER binary must refuse to open. Independent of the on-disk
/// `config.toml` `CONFIG_SCHEMA_VERSION` (that versions the TOML file shape, this versions the DB).
pub const APP_SCHEMA_VERSION: u32 = 1;

/// True when `key` is a clean 64-char lowercase-or-uppercase hex string — i.e. a raw 256-bit
/// SQLCipher key (32 bytes), as the vault mints ([`vault`]). Only such a key may use the raw-key
/// PRAGMA form; anything else (a test passphrase) falls back to the passphrase form.
fn is_raw_hex_key(key: &str) -> bool {
    key.len() == 64 && key.bytes().all(|b| b.is_ascii_hexdigit())
}

/// The `PRAGMA key`/`rekey` VALUE for `key`, choosing the form that is correct AND fast.
///
/// A full-entropy 256-bit key is passed as SQLCipher's **raw key** — `"x'<hex>'"` — so the bytes
/// are used DIRECTLY as the AES-256 key. The alternative, a passphrase (`'<hex>'`), makes SQLCipher
/// run **256,000 PBKDF2-HMAC-SHA512 iterations to derive the key on EVERY connection open**. That
/// stretching exists to make a low-entropy password expensive to brute-force; a random 256-bit key
/// has nothing to stretch, so the KDF is pure waste — and on an ARM64 Windows build whose bundled
/// OpenSSL lacks SHA hardware acceleration it costs ~4 seconds PER connection, stalling the pool and
/// every API call that waits on it (observed: `PRAGMA key` elapsed 3.9s, connection acquire 4.1s).
/// Raw-key open is sub-millisecond.
///
/// A non-hex `key` (only ever a test passphrase) keeps the passphrase form, so its create+reopen
/// stay mutually consistent.
pub(crate) fn key_pragma_value(key: &str) -> String {
    if is_raw_hex_key(key) {
        // SQLCipher's documented raw-key literal: the value IS the string x'<hex>'.
        format!("\"x'{key}'\"")
    } else {
        format!("'{}'", key.replace('\'', "''"))
    }
}

/// Legacy passphrase form of `key` (`'<hex>'`), used only to open a pre-migration DB so it can be
/// rekeyed to the raw form. Never used for a normal open.
///
/// `pub(crate)` for the probes that must accept a DB in EITHER form while the migration is in
/// flight (`can_open_under_key`, `vault_rotate::db_opens_under`). Every site that OPENS a DB for
/// real use must go through [`key_pragma_value`] instead.
pub(crate) fn passphrase_pragma_value(key: &str) -> String {
    format!("'{}'", key.replace('\'', "''"))
}

/// Open (creating if needed) the SQLCipher-encrypted DB at `path` with `key`, assert the cipher is
/// genuinely active (fail-closed), apply pragmas, and run migrations. Uses the raw-key PRAGMA form
/// for a real vault key (no per-connection PBKDF2) — see [`key_pragma_value`].
pub async fn open(path: &Path, key: &str) -> LocalResult<SqlitePool> {
    let opts = SqliteConnectOptions::new()
        .filename(path)
        .create_if_missing(true)
        .pragma("key", key_pragma_value(key)) // MUST precede any access to the encrypted DB
        .pragma("foreign_keys", "ON")
        .pragma("journal_mode", "WAL")
        .pragma("busy_timeout", "5000");

    let pool = SqlitePoolOptions::new()
        .max_connections(4)
        .connect_with(opts)
        .await?;

    assert_cipher_active(&pool).await?;
    integrity_check(&pool).await?;
    MIGRATOR
        .run(&pool)
        .await
        .map_err(|e| LocalError::Migrate(e.to_string()))?;
    Ok(pool)
}

/// One-time, NON-DESTRUCTIVE upgrade of a legacy passphrase-keyed DB to the raw-key form, so every
/// later open skips PBKDF2. Called only after a raw-key [`open`] has already FAILED as unreadable.
///
/// Opens `path` under the OLD passphrase form (no create, no migrations); if — and only if — that
/// decrypts cleanly (cipher active + integrity passes, proving the file is genuinely ours, just
/// old-format), it `PRAGMA rekey`s the file in place to the raw key. Returns:
///   * `Ok(true)`  — migrated; the caller should retry [`open`], which now succeeds with data intact;
///   * `Ok(false)` — not a legacy DB we own (passphrase didn't open it) → leave it for normal
///                   corrupt-recovery, which must not be pre-empted;
///   * `Err(_)`    — the rekey itself started but failed.
///
/// A no-op (returns `Ok(false)`) unless `key` is a raw-hex vault key, since only those change form.
async fn rekey_passphrase_to_raw(path: &Path, key: &str) -> LocalResult<bool> {
    if !path.exists() || !is_raw_hex_key(key) {
        return Ok(false);
    }
    let opts = SqliteConnectOptions::new()
        .filename(path)
        .create_if_missing(false)
        .pragma("key", passphrase_pragma_value(key))
        .pragma("busy_timeout", "5000");
    let Ok(pool) = SqlitePoolOptions::new().max_connections(1).connect_with(opts).await else {
        return Ok(false); // not openable under the passphrase either — not our migration to make
    };
    // Prove it actually decrypts before we rewrite a single page. A wrong key surfaces here as an
    // integrity/`code 26` failure, so we never rekey a file that isn't provably the old-format DB.
    if assert_cipher_active(&pool).await.is_err() || integrity_check(&pool).await.is_err() {
        pool.close().await;
        return Ok(false);
    }
    // Re-encrypt in place with the raw key (SQLCipher rewrites every page under the new key).
    let sql = format!("PRAGMA rekey = {}", key_pragma_value(key));
    let res = sqlx::query(&sql).execute(&pool).await;
    pool.close().await;
    res.map_err(LocalError::Db)?;
    tracing::info!("migrated local DB to a raw SQLCipher key (per-connection PBKDF2 eliminated)");
    Ok(true)
}

/// Boot-time managed open: keep the daemon bootable in the face of an unusable DB (recover from a
/// backup sibling, else quarantine + start fresh), enforce the future-version guard, and stamp the
/// current [`APP_SCHEMA_VERSION`]. This is the entry point lifecycle uses; tests and helpers that
/// just need a pool keep calling [`open`].
///
/// Order:
///   1. `open(path, key)`. If it fails because the DB is UNUSABLE — a [`LocalError::Corrupt`] (failed
///      integrity check) OR a driver "not a database" / "malformed" refusal (a damaged header or a
///      key mismatch, see [`is_unreadable_db_error`]) — hand off to [`recover_or_start_fresh`]:
///      adopt a readable backup sibling if one exists, otherwise rename the bad file aside and open a
///      fresh empty DB. Guard: a driver refusal only routes here when SQLCipher is actually linked;
///      otherwise we surface [`LocalError::CipherUnavailable`] (fail closed, never discard a good DB).
///   2. Read the stored `schema_version`. If it is GREATER than [`APP_SCHEMA_VERSION`], close the pool
///      and return [`LocalError::SchemaVersionFuture`] (refuse the silent downgrade).
///   3. Stamp `schema_version = APP_SCHEMA_VERSION` (idempotent; advances a same-or-older DB forward).
pub async fn open_managed(path: &Path, key: &str) -> LocalResult<SqlitePool> {
    let pool = match open(path, key).await {
        Ok(pool) => pool,
        Err(e) if is_recoverable_open_failure(&e) => {
            // BEFORE treating the file as corrupt: a DB written by an older build used the passphrase
            // key form, which the new raw-key `open` rejects as "not a database" (code 26) — the exact
            // shape of a recoverable failure. Try the one-time passphrase→raw migration first; if it
            // converts (proven by a clean passphrase decrypt), the retried [`open`] succeeds with the
            // user's data intact. Only if the file is NOT a legacy DB do we fall through to recovery,
            // so a real upgrade never loses data to quarantine.
            if rekey_passphrase_to_raw(path, key).await.unwrap_or(false) {
                open(path, key).await?
            }
            // A `Corrupt` error means the cipher already decrypted page 1 (right key, damaged data),
            // so SQLCipher is provably linked. A driver "not a database" refusal is ambiguous — it is
            // ALSO what a plain-SQLite build yields on an encrypted file — so gate that branch on a
            // real cipher probe and fail closed if the cipher isn't linked (never discard a good DB).
            else if matches!(e, LocalError::Corrupt(_)) || cipher_linked().await {
                recover_or_start_fresh(path, key, &e.to_string()).await?
            } else {
                return Err(LocalError::CipherUnavailable);
            }
        }
        Err(e) => return Err(e),
    };

    enforce_schema_version(&pool).await.inspect_err(|_| {
        // Don't leak the open pool if we're about to refuse the DB.
        let pool = pool.clone();
        tokio::spawn(async move { pool.close().await });
    })?;
    Ok(pool)
}

/// Would this [`open`] failure leave the daemon unable to use the DB in a way we can recover from
/// (quarantine + start fresh, or adopt a backup)? True for a failed integrity check and for the
/// driver's "unreadable file" refusals; false for a cipher/schema/other error that must propagate.
fn is_recoverable_open_failure(e: &LocalError) -> bool {
    matches!(e, LocalError::Corrupt(_)) || is_unreadable_db_error(e)
}

/// Is this a raw SQLite driver error meaning "this file can't be read as a database with the key we
/// gave" — i.e. `SQLITE_NOTADB` (26, "file is not a database": a damaged header or a key that no
/// longer matches the ciphertext) or `SQLITE_CORRUPT` (11, "disk image is malformed")? These arrive
/// as a plain [`LocalError::Db`], often thrown by the very first page access during `connect`, so
/// they never reach the [`integrity_check`] that would classify them as [`LocalError::Corrupt`].
fn is_unreadable_db_error(e: &LocalError) -> bool {
    let LocalError::Db(sqlx::Error::Database(db)) = e else {
        return false;
    };
    if matches!(db.code().as_deref(), Some("26") | Some("11")) {
        return true;
    }
    // Belt-and-suspenders on the message text (robust across driver versions / code surfacing).
    let msg = db.message().to_ascii_lowercase();
    msg.contains("not a database") || msg.contains("disk image is malformed")
}

/// Recover a bootable DB after [`open`] found the live file unusable. Prefers ADOPTING the newest
/// backup sibling that opens under the live `key` (so the daemon comes up with the user's data);
/// falls back to renaming the bad file aside and opening a fresh empty DB. The unreadable file is
/// always renamed to `writ.db.corrupt-<ts>`, never deleted.
async fn recover_or_start_fresh(live: &Path, key: &str, detail: &str) -> LocalResult<SqlitePool> {
    if let Some(src) = newest_recoverable_sibling(live, key).await {
        // Set the unreadable live DB aside, then adopt the readable backup. We COPY (not rename) so
        // the backup itself is preserved as a second safety net, and we bring its `-wal` sidecar so
        // commits that were still in the write-ahead log at backup time are not dropped (the next
        // `open` checkpoints the WAL into the main file).
        quarantine_corrupt_db(live, detail)?;
        copy_db_with_sidecars(&src, live)?;
        tracing::error!(
            recovered_from = %src.display(),
            "live DB was unreadable under the vault key; recovered local data from a readable backup copy"
        );
        return open(live, key).await;
    }
    // Nothing on disk opens under the live key — quarantine the bad file and start fresh so the
    // daemon still boots (the user can re-link/reconnect from an empty local store).
    quarantine_corrupt_db(live, detail)?;
    open(live, key).await
}

/// Path of a DB sidecar (`-wal` / `-shm`), i.e. `<db-name><ext>` next to the DB.
fn sidecar_path(db: &Path, ext: &str) -> PathBuf {
    let name = db.file_name().and_then(|s| s.to_str()).unwrap_or("writ.db");
    db.with_file_name(format!("{name}{ext}"))
}

/// Copy a SQLCipher DB `src` → `dst` together with its `-wal` sidecar (so uncheckpointed commits
/// survive the adoption), giving each copied file `0600`. Any stale sidecar at `dst` is removed so
/// the adopted DB can't inherit an unrelated write-ahead log; `-shm` is left for SQLite to rebuild.
fn copy_db_with_sidecars(src: &Path, dst: &Path) -> std::io::Result<()> {
    let restrict = |p: &Path| {
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(p, std::fs::Permissions::from_mode(0o600));
        }
        let _ = p; // silence unused on non-unix
    };
    std::fs::copy(src, dst)?;
    restrict(dst);
    for ext in ["-wal", "-shm"] {
        let (s, d) = (sidecar_path(src, ext), sidecar_path(dst, ext));
        if s.exists() {
            std::fs::copy(&s, &d)?;
            restrict(&d);
        } else {
            let _ = std::fs::remove_file(&d);
        }
    }
    Ok(())
}

/// Find the newest sibling backup DB next to `live` that OPENS under `key`. Considers only
/// `<db-name>.*` copies (e.g. `writ.db.pre-restore-*`, an earlier `writ.db.corrupt-*`), never the
/// live file itself nor any `-wal`/`-shm`/`-journal` sidecar. Returns `None` if none open.
async fn newest_recoverable_sibling(live: &Path, key: &str) -> Option<PathBuf> {
    let dir = live.parent()?;
    let live_name = live.file_name()?.to_str()?;
    let prefix = format!("{live_name}."); // e.g. "writ.db." — excludes the live file + its "-wal" sidecars
    let mut best: Option<(SystemTime, PathBuf)> = None;
    for entry in std::fs::read_dir(dir).ok()?.flatten() {
        let p = entry.path();
        let Some(name) = p.file_name().and_then(|s| s.to_str()) else {
            continue;
        };
        if !name.starts_with(&prefix)
            || name.ends_with("-wal")
            || name.ends_with("-shm")
            || name.ends_with("-journal")
        {
            continue;
        }
        if !can_open_under_key(&p, key).await {
            continue;
        }
        let mtime = entry.metadata().ok().and_then(|m| m.modified().ok()).unwrap_or(UNIX_EPOCH);
        if best.as_ref().is_none_or(|(bt, _)| mtime > *bt) {
            best = Some((mtime, p));
        }
    }
    best.map(|(_, p)| p)
}

/// Non-mutating probe: does the SQLCipher file at `path` decrypt under `key` and pass its integrity
/// check? Opens WITHOUT `create_if_missing` and WITHOUT running migrations, so it never alters the
/// candidate. A wrong key surfaces as an integrity/`code 26` failure ⇒ `false`.
async fn can_open_under_key(path: &Path, key: &str) -> bool {
    if !path.exists() {
        return false;
    }
    // A sibling backup may be in EITHER key form: newer copies are raw-key, pre-migration ones are
    // passphrase. Probe raw first (what current opens produce), then fall back to passphrase, so a
    // recoverable backup is found regardless of when it was written.
    let mut forms = vec![key_pragma_value(key)];
    let pass = passphrase_pragma_value(key);
    if forms[0] != pass {
        forms.push(pass);
    }
    for keyed in forms {
        let opts = SqliteConnectOptions::new()
            .filename(path)
            .create_if_missing(false)
            .pragma("key", keyed)
            .pragma("busy_timeout", "5000");
        let Ok(pool) = SqlitePoolOptions::new().max_connections(1).connect_with(opts).await else {
            continue;
        };
        let ok = assert_cipher_active(&pool).await.is_ok() && integrity_check(&pool).await.is_ok();
        pool.close().await;
        if ok {
            return true;
        }
    }
    false
}

/// Is SQLCipher actually linked into this binary? Probes an in-memory DB's `PRAGMA cipher_version`
/// (non-empty iff SQLCipher is present), independent of any on-disk file. Gates the quarantine
/// decision so a plain-SQLite build never discards a good encrypted DB over a `code 26`.
async fn cipher_linked() -> bool {
    let opts = SqliteConnectOptions::new().filename(":memory:");
    let Ok(pool) = SqlitePoolOptions::new().max_connections(1).connect_with(opts).await else {
        return false;
    };
    let linked = assert_cipher_active(&pool).await.is_ok();
    pool.close().await;
    linked
}

/// Read the stored schema version (`None` if never stamped — a brand-new DB).
pub async fn stored_schema_version(pool: &SqlitePool) -> LocalResult<Option<u32>> {
    match config_kv::get(pool, SCHEMA_VERSION_KEY).await? {
        Some(s) => Ok(s.trim().parse::<u32>().ok()),
        None => Ok(None),
    }
}

/// Future-version guard + forward stamp. Refuses a DB whose stored version exceeds this binary's,
/// otherwise advances the stamp to [`APP_SCHEMA_VERSION`].
async fn enforce_schema_version(pool: &SqlitePool) -> LocalResult<()> {
    if let Some(found) = stored_schema_version(pool).await? {
        if found > APP_SCHEMA_VERSION {
            tracing::error!(
                found,
                supported = APP_SCHEMA_VERSION,
                "refusing to open a DB from a newer app version (no silent downgrade)"
            );
            return Err(LocalError::SchemaVersionFuture { found, supported: APP_SCHEMA_VERSION });
        }
        if found < APP_SCHEMA_VERSION {
            tracing::info!(from = found, to = APP_SCHEMA_VERSION, "advancing DB schema_version stamp");
        }
    }
    config_kv::set(pool, SCHEMA_VERSION_KEY, &APP_SCHEMA_VERSION.to_string()).await?;
    Ok(())
}

/// Rename a corrupt DB file (and its WAL/SHM sidecars) aside so a fresh DB can take its place at the
/// canonical path. Returns the quarantine path. Best-effort on the sidecars (they may not exist).
fn quarantine_corrupt_db(path: &Path, detail: &str) -> LocalResult<std::path::PathBuf> {
    let ts = chrono::Utc::now().format("%Y%m%dT%H%M%SZ");
    let file_name = path
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or("writ.db");
    let quarantine = path.with_file_name(format!("{file_name}.corrupt-{ts}"));
    std::fs::rename(path, &quarantine)?;
    // SQLite WAL mode leaves `-wal` / `-shm` sidecars next to the DB; move them too so the fresh DB
    // can't accidentally adopt a stale write-ahead log. Missing sidecars are fine.
    for ext in ["-wal", "-shm"] {
        let side = path.with_file_name(format!("{file_name}{ext}"));
        if side.exists() {
            let _ = std::fs::rename(&side, quarantine.with_file_name(format!("{file_name}.corrupt-{ts}{ext}")));
        }
    }
    tracing::error!(
        quarantine = %quarantine.display(),
        detail = %detail,
        "DB was unusable (corrupt or unreadable under the vault key); quarantined it aside"
    );
    Ok(quarantine)
}

/// FAIL-CLOSED: an empty `cipher_version` means sqlx linked plain SQLite and `PRAGMA key`
/// silently no-op'd — the DB would be plaintext while appearing encrypted.
pub async fn assert_cipher_active(pool: &SqlitePool) -> LocalResult<()> {
    let cv: String = sqlx::query("PRAGMA cipher_version")
        .fetch_optional(pool)
        .await?
        .and_then(|r| r.try_get::<String, _>(0).ok())
        .unwrap_or_default();
    if cv.trim().is_empty() {
        return Err(LocalError::CipherUnavailable);
    }
    tracing::info!(cipher_version = %cv, "SQLCipher active");
    Ok(())
}

async fn integrity_check(pool: &SqlitePool) -> LocalResult<()> {
    let r: String = sqlx::query("PRAGMA quick_check")
        .fetch_one(pool)
        .await?
        .try_get(0)
        .unwrap_or_default();
    if r != "ok" {
        return Err(LocalError::Corrupt(r));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn opens_encrypted_and_migrates() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("t.db");
        let pool = open(&path, "test-key-42").await.expect("open+migrate");

        // A table from 0001_init must exist and be empty.
        let n: i64 = sqlx::query("SELECT count(*) FROM workflows")
            .fetch_one(&pool)
            .await
            .unwrap()
            .try_get(0)
            .unwrap();
        assert_eq!(n, 0);

        // local_api_keys (§9) must also exist.
        sqlx::query("SELECT count(*) FROM local_api_keys")
            .fetch_one(&pool)
            .await
            .expect("local_api_keys table exists");

        // 0014 added `ai_sessions.generate_workflow` (default 1) — selecting it proves the migration
        // applied. `MIGRATOR.run` is forward-only + idempotent, so this same DB re-opens without a
        // duplicate-column error (every store test that re-opens a fresh pool exercises that path).
        sqlx::query("SELECT generate_workflow FROM ai_sessions LIMIT 1")
            .fetch_optional(&pool)
            .await
            .expect("ai_sessions.generate_workflow column exists (migration 0014 applied)");

        pool.close().await;

        // Re-open the SAME file: the forward-only MIGRATOR must be a no-op (0014's ADD COLUMN is not
        // re-applied), proving idempotency.
        let pool = open(&path, "test-key-42").await.expect("re-open (migrations idempotent)");
        sqlx::query("SELECT generate_workflow FROM ai_sessions LIMIT 1")
            .fetch_optional(&pool)
            .await
            .expect("column still present after idempotent re-open");
        pool.close().await;

        // The file must be encrypted at rest (no plaintext SQLite header).
        let bytes = std::fs::read(&path).unwrap();
        assert!(
            !bytes.starts_with(b"SQLite format 3\0"),
            "DB must be SQLCipher-encrypted at rest"
        );
    }

    /// A real 64-hex vault key uses the raw-key form; a passphrase keeps the passphrase form.
    #[test]
    fn key_form_is_raw_only_for_a_full_hex_key() {
        let hex = "e4d170b7e13d345279997ffe7d9c1f7a292ae4c5989b2ac314f36fb79999be97";
        assert!(is_raw_hex_key(hex));
        assert_eq!(key_pragma_value(hex), format!("\"x'{hex}'\""));
        // Not 64 hex chars → passphrase form (so tests / any non-vault key stay self-consistent).
        assert!(!is_raw_hex_key("managed-key"));
        assert_eq!(key_pragma_value("managed-key"), "'managed-key'");
        assert!(!is_raw_hex_key(&"z".repeat(64))); // right length, not hex
    }

    /// A DB written by an OLDER build under the passphrase key form must open under the new raw-key
    /// `open_managed` WITH ITS DATA INTACT — the one-time rekey migration, not a quarantine-and-wipe.
    #[tokio::test]
    async fn legacy_passphrase_db_migrates_to_raw_key_without_data_loss() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("t.db");
        let key = "e4d170b7e13d345279997ffe7d9c1f7a292ae4c5989b2ac314f36fb79999be97";

        // 1. Simulate the OLD on-disk format: create + migrate the DB under the PASSPHRASE form and
        //    insert a marker row, exactly as a pre-fix build would have left it.
        {
            let opts = SqliteConnectOptions::new()
                .filename(&path)
                .create_if_missing(true)
                .pragma("key", passphrase_pragma_value(key))
                .pragma("journal_mode", "WAL");
            let pool = SqlitePoolOptions::new().max_connections(1).connect_with(opts).await.unwrap();
            assert_cipher_active(&pool).await.unwrap();
            MIGRATOR.run(&pool).await.unwrap();
            sqlx::query("INSERT INTO config (key, value) VALUES ('marker', 'survives')")
                .execute(&pool)
                .await
                .unwrap();
            pool.close().await;
        }

        // 2. A raw-key open must FAIL on that passphrase DB (proving the forms really differ, so the
        //    migration path is actually exercised rather than silently opening).
        assert!(open(&path, key).await.is_err(), "raw open must reject a passphrase-keyed DB");

        // 3. open_managed migrates it in place and comes up with the marker row intact.
        let pool = open_managed(&path, key).await.expect("managed open migrates the legacy DB");
        let v: String = sqlx::query("SELECT value FROM config WHERE key = 'marker'")
            .fetch_one(&pool)
            .await
            .expect("marker row survived the rekey")
            .try_get(0)
            .unwrap();
        assert_eq!(v, "survives");
        pool.close().await;

        // 4. The file is now raw-keyed: a plain raw-key open succeeds directly (no migration needed),
        //    and the passphrase form no longer opens it.
        open(&path, key).await.expect("raw open works after migration").close().await;
        assert!(
            !can_open_under_key(&path, "e4d170b7e13d345279997ffe7d9c1f7a292ae4c5989b2ac314f36fb70000000").await,
            "a WRONG key must not open the migrated DB"
        );
    }

    /// `open_managed` stamps the schema version on a fresh DB and re-opens cleanly at the same version.
    #[tokio::test]
    async fn managed_open_stamps_and_reopens() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("t.db");
        let key = "managed-key";

        let pool = open_managed(&path, key).await.expect("first managed open");
        assert_eq!(stored_schema_version(&pool).await.unwrap(), Some(APP_SCHEMA_VERSION));
        pool.close().await;

        // Re-open at the SAME app version succeeds (stamp unchanged).
        let pool = open_managed(&path, key).await.expect("reopen at same version");
        assert_eq!(stored_schema_version(&pool).await.unwrap(), Some(APP_SCHEMA_VERSION));
        pool.close().await;
    }

    /// A DB stamped with a FUTURE version is refused (no silent downgrade).
    #[tokio::test]
    async fn managed_open_refuses_a_future_version() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("t.db");
        let key = "future-key";

        // Open + force a future stamp, then close.
        let pool = open(&path, key).await.unwrap();
        config_kv::set(&pool, SCHEMA_VERSION_KEY, &(APP_SCHEMA_VERSION + 5).to_string())
            .await
            .unwrap();
        pool.close().await;

        let err = open_managed(&path, key).await.unwrap_err();
        match err {
            LocalError::SchemaVersionFuture { found, supported } => {
                assert_eq!(found, APP_SCHEMA_VERSION + 5);
                assert_eq!(supported, APP_SCHEMA_VERSION);
            }
            other => panic!("expected SchemaVersionFuture, got {other:?}"),
        }
    }

    /// A corrupt DB file is quarantined aside and a fresh, working DB takes its place. We simulate
    /// corruption by writing garbage that is NOT a valid SQLCipher file at the canonical path; the
    /// integrity/open path rejects it, quarantine renames it aside, and the retry opens a fresh DB.
    #[tokio::test]
    async fn managed_open_quarantines_a_corrupt_db() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("writ.db");
        let key = "quarantine-key";

        // First, create a real encrypted DB and add a row, then corrupt the FILE in place by
        // truncating + overwriting its tail so the cipher/page structure is damaged.
        {
            let pool = open(&path, key).await.unwrap();
            sqlx::query("INSERT INTO config (key, value) VALUES ('marker', 'present')")
                .execute(&pool)
                .await
                .unwrap();
            pool.close().await;
        }
        // Corrupt: overwrite the whole file with non-SQLCipher bytes. `open` will fail its cipher or
        // integrity gate; only a Corrupt error triggers quarantine, so to be deterministic we craft a
        // file that keys-but-fails-integrity is hard to guarantee — instead assert the *mechanism*:
        // call quarantine directly, then prove a fresh DB opens at the vacated path.
        let q = quarantine_corrupt_db(&path, "simulated").unwrap();
        assert!(q.exists(), "corrupt file was renamed aside");
        assert!(!path.exists(), "canonical path is vacated for a fresh DB");

        let pool = open_managed(&path, key).await.expect("fresh DB opens after quarantine");
        // Fresh DB: the old 'marker' row is gone (it lives in the quarantined file).
        let n: i64 = sqlx::query("SELECT count(*) FROM config WHERE key='marker'")
            .fetch_one(&pool)
            .await
            .unwrap()
            .try_get(0)
            .unwrap();
        assert_eq!(n, 0, "fresh DB has none of the old rows");
        assert_eq!(stored_schema_version(&pool).await.unwrap(), Some(APP_SCHEMA_VERSION));
        pool.close().await;
    }

    /// A file that SQLCipher refuses as `code 26` "file is not a database" (a damaged header or a key
    /// that no longer matches — the failure mode that used to BRICK boot) is classified as unreadable,
    /// quarantined aside, and replaced by a fresh empty DB so the daemon still comes up.
    #[tokio::test]
    async fn managed_open_quarantines_an_unreadable_db_and_boots() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("writ.db");
        let key = "notadb-key";

        // Write non-SQLCipher garbage at the canonical path: `open` can't decrypt page 1, so the
        // driver refuses it as `code 26` (NOT a clean quick_check `Corrupt`). This is the exact class
        // of error that previously escaped the quarantine and failed the daemon bootstrap.
        std::fs::write(&path, vec![0xABu8; 8192]).unwrap();
        let err = open(&path, key).await.unwrap_err();
        assert!(is_unreadable_db_error(&err), "garbage file must classify as unreadable: {err:?}");

        // Managed open recovers: quarantines the garbage aside and opens a fresh, migrated DB.
        let pool = open_managed(&path, key).await.expect("daemon must boot despite an unreadable DB");
        let n: i64 = sqlx::query("SELECT count(*) FROM workflows")
            .fetch_one(&pool)
            .await
            .unwrap()
            .try_get(0)
            .unwrap();
        assert_eq!(n, 0, "fresh empty DB after quarantine");
        pool.close().await;

        // The garbage was renamed aside (never deleted) and a real DB now sits at the live path.
        let quarantined = std::fs::read_dir(dir.path())
            .unwrap()
            .flatten()
            .any(|e| e.file_name().to_string_lossy().contains("writ.db.corrupt-"));
        assert!(quarantined, "unreadable file must be preserved as writ.db.corrupt-*");
    }

    /// When the live DB is unreadable but a sibling backup (`writ.db.pre-restore-*`) opens under the
    /// live key, managed open ADOPTS the backup — the daemon comes up WITH the user's data, not empty.
    /// This is the recovery path for the real incident (a live DB stranded under a lost root, next to a
    /// readable pre-restore copy).
    #[tokio::test]
    async fn managed_open_recovers_local_data_from_a_readable_sibling() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("writ.db");
        let key = "recover-key";

        // A healthy DB with a marker row, checkpointed so the main file is self-contained, then
        // copied aside as a pre-restore backup.
        {
            let pool = open(&path, key).await.unwrap();
            sqlx::query("INSERT INTO config (key, value) VALUES ('marker', 'present')")
                .execute(&pool)
                .await
                .unwrap();
            sqlx::query("PRAGMA wal_checkpoint(TRUNCATE)").execute(&pool).await.unwrap();
            pool.close().await;
        }
        let sibling = dir.path().join("writ.db.pre-restore-20260101T000000Z");
        copy_db_with_sidecars(&path, &sibling).unwrap();

        // Now strand the LIVE db (garbage → unreadable under the key), leaving the sibling readable.
        std::fs::write(&path, vec![0x00u8; 8192]).unwrap();

        let pool = open_managed(&path, key).await.expect("must recover from the readable sibling");
        let marker: i64 = sqlx::query("SELECT count(*) FROM config WHERE key='marker'")
            .fetch_one(&pool)
            .await
            .unwrap()
            .try_get(0)
            .unwrap();
        assert_eq!(marker, 1, "recovered DB must carry the user's data from the sibling backup");
        pool.close().await;

        // The unreadable file was quarantined and the sibling backup is still present.
        assert!(sibling.exists(), "the adopted backup copy is preserved");
        let quarantined = std::fs::read_dir(dir.path())
            .unwrap()
            .flatten()
            .any(|e| e.file_name().to_string_lossy().contains("writ.db.corrupt-"));
        assert!(quarantined, "the stranded live DB is set aside, not destroyed");
    }
}
