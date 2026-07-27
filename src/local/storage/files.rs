//! File-asset byte I/O — encrypt-at-rest writes, decrypting reads, and run-time materialization.
//!
//! Layout: bytes live at `Paths::files_dir()/<storage_key>` as a `WFB1` envelope (vault K_file).
//! Workflow OUTPUT artifacts land under `Paths::artifacts_dir()/workflow_output/<storage_key>`,
//! same envelope. The `stored_files` row is metadata only and records the `storage_key` so reads
//! can locate the blob. `sha256` is computed over the PLAINTEXT for content dedup.
//!
//! Path safety: every resolved blob path is canonicalized and asserted to sit UNDER the expected
//! store directory, so a hostile `storage_key` (e.g. `../../etc/passwd`) cannot escape the store.
//!
//! Net-new Rust — NOT ported from the legacy Python `desktop-agent`.

use crate::local::config::Paths;
use crate::local::error::{LocalError, LocalResult};
use crate::local::store::stored_files::{self, NewStoredFile, StoredFile};
use crate::local::vault::Vault;
use rand::RngCore;
use sha2::{Digest, Sha256};
use sqlx::SqlitePool;
use std::path::{Path, PathBuf};

/// Default content-type when the caller doesn't supply one.
const DEFAULT_CONTENT_TYPE: &str = "application/octet-stream";

/// Generate a `file_<hex>` handle id (16 random bytes → 32 hex chars).
fn new_file_id() -> String {
    let mut raw = [0u8; 16];
    rand::rngs::OsRng.fill_bytes(&mut raw);
    let hex = raw.iter().map(|b| format!("{b:02x}")).collect::<String>();
    format!("file_{hex}")
}

/// Generate an opaque on-disk storage key (no path separators, no caller-controlled bytes).
fn new_storage_key() -> String {
    let mut raw = [0u8; 16];
    rand::rngs::OsRng.fill_bytes(&mut raw);
    let hex = raw.iter().map(|b| format!("{b:02x}")).collect::<String>();
    format!("blob_{hex}.wfb")
}

/// SHA-256 (lowercase hex) of plaintext bytes — the dedup key.
fn sha256_hex(bytes: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(bytes);
    h.finalize().iter().map(|b| format!("{b:02x}")).collect()
}

/// Reject a storage key that contains path separators or traversal — these are minted internally,
/// but defense-in-depth keeps a corrupted/forged DB row from steering us off the store dir.
fn validate_storage_key(key: &str) -> LocalResult<()> {
    if key.is_empty()
        || key.contains('/')
        || key.contains('\\')
        || key.contains("..")
        || key.contains('\0')
    {
        return Err(LocalError::BadRequest(format!("unsafe storage key: {key}")));
    }
    Ok(())
}

/// Resolve the absolute blob path for a storage key under `base_dir`, asserting (via canonicalized
/// parent + key check) that the result cannot escape `base_dir`. The blob file itself need not
/// exist yet (write path), so we canonicalize the PARENT and re-join the validated key.
fn safe_blob_path(base_dir: &Path, storage_key: &str) -> LocalResult<PathBuf> {
    validate_storage_key(storage_key)?;
    std::fs::create_dir_all(base_dir)?;
    let canon_base = base_dir
        .canonicalize()
        .map_err(|e| LocalError::Internal(format!("storage base not resolvable: {e}")))?;
    let candidate = canon_base.join(storage_key);
    // The join of a canonical dir with a separator-free, non-`..` filename can only be a direct
    // child; assert the prefix to be certain even on exotic platforms.
    if !candidate.starts_with(&canon_base) {
        return Err(LocalError::BadRequest("storage path escapes store dir".into()));
    }
    Ok(candidate)
}

/// The store dir for a given `source` (uploads/api → files_dir; workflow_output → artifacts).
fn store_dir_for_source(paths: &Paths, source: &str) -> PathBuf {
    if source == "workflow_output" {
        paths.artifacts_dir().join("workflow_output")
    } else {
        paths.files_dir()
    }
}

/// Resolve the absolute on-disk path of an existing handle's blob (read path). Public so the
/// engine/GC can locate bytes without re-deriving the layout.
pub fn storage_path_for_key(paths: &Paths, source: &str, storage_key: &str) -> LocalResult<PathBuf> {
    safe_blob_path(&store_dir_for_source(paths, source), storage_key)
}

/// Write `bytes` to `path` as `0600` (unix), creating the parent if needed. The bytes are written
/// AS-IS — callers pass already-encrypted envelope bytes here.
fn write_blob_0600(path: &Path, bytes: &[u8]) -> LocalResult<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(path, bytes)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
    }
    Ok(())
}

/// Create a new file asset from in-memory bytes: encrypt-at-rest under K_file, write the blob, and
/// insert the `stored_files` metadata row. `source` is `upload|api|workflow_output`; the sha256 of
/// the PLAINTEXT is recorded for dedup. Returns the inserted row.
///
/// Dedup: if a live row already exists with the same plaintext sha256 AND source, that existing row
/// is returned and no new blob is written (idempotent uploads). Pass a distinct `source` (e.g.
/// `workflow_output`) to force a separate handle.
pub async fn create_file(
    pool: &SqlitePool,
    vault: &Vault,
    paths: &Paths,
    bytes: &[u8],
    filename: &str,
    content_type: Option<&str>,
    source: &str,
) -> LocalResult<StoredFile> {
    create_file_inner(pool, vault, paths, bytes, filename, content_type, source, None).await
}

/// Internal create with an optional `source_run_id` (workflow-output capture sets it).
async fn create_file_inner(
    pool: &SqlitePool,
    vault: &Vault,
    paths: &Paths,
    bytes: &[u8],
    filename: &str,
    content_type: Option<&str>,
    source: &str,
    source_run_id: Option<i64>,
) -> LocalResult<StoredFile> {
    let sha = sha256_hex(bytes);

    // Dedup: reuse a live row with the same content + source (cheap, avoids duplicate blobs).
    if let Some(existing) = stored_files::get_by_sha256(pool, &sha).await? {
        if existing.source == source && existing.deleted_at.is_none() {
            tracing::info!(file_id = %existing.id, sha256 = %sha, "file dedup hit; reusing handle");
            return Ok(existing);
        }
    }

    let id = new_file_id();
    let storage_key = new_storage_key();
    let ct = content_type
        .map(str::to_string)
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| DEFAULT_CONTENT_TYPE.to_string());

    // Encrypt then write — nothing plaintext ever lands on disk.
    let blob = vault.encrypt_file(bytes)?;
    let path = storage_path_for_key(paths, source, &storage_key)?;
    write_blob_0600(&path, &blob)?;

    let new = NewStoredFile {
        id: id.clone(),
        storage_key: storage_key.clone(),
        filename: filename.to_string(),
        content_type: Some(ct),
        size_bytes: Some(bytes.len() as i64),
        sha256: Some(sha),
        source: Some(source.to_string()),
        source_run_id,
        status: Some("ready".to_string()),
        ..Default::default()
    };

    match stored_files::insert(pool, &new).await {
        Ok(row) => Ok(row),
        Err(e) => {
            // Roll back the orphaned blob if the metadata insert fails.
            let _ = std::fs::remove_file(&path);
            Err(e)
        }
    }
}

/// Read + DECRYPT the bytes for a live file handle. 404 if the handle is absent/soft-deleted, and
/// an internal error if the blob is missing on disk or fails its auth check (tamper/wrong key).
pub async fn read_file_bytes(
    pool: &SqlitePool,
    vault: &Vault,
    paths: &Paths,
    file_id: &str,
) -> LocalResult<Vec<u8>> {
    let row = stored_files::get_active(pool, file_id)
        .await?
        .ok_or_else(|| LocalError::NotFound(format!("file {file_id}")))?;
    let path = storage_path_for_key(paths, &row.source, &row.storage_key)?;
    let blob = match std::fs::read(&path) {
        Ok(b) => b,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return Err(LocalError::NotFound(format!("file {file_id} bytes missing on disk")));
        }
        Err(e) => return Err(LocalError::Io(e)),
    };
    vault.decrypt_file(&blob)
}

/// Build the on-disk path a run's OUTPUT artifact would occupy WITHOUT writing it — used by the
/// engine to hand a target directory/name to a download/screenshot step before capture. Lives
/// under `artifacts_dir()/workflow_output`. The returned name is opaque (run-scoped) so two runs
/// never collide; the human filename is preserved in the `stored_files` row, not on disk.
pub fn local_path_for_run(paths: &Paths, run_id: i64, suggested_name: &str) -> LocalResult<PathBuf> {
    let dir = paths.artifacts_dir().join("workflow_output").join(format!("run_{run_id}"));
    std::fs::create_dir_all(&dir)?;
    // Sanitize the suggested name to a bare filename (strip any path components).
    let bare = Path::new(suggested_name)
        .file_name()
        .and_then(|s| s.to_str())
        .filter(|s| !s.is_empty() && !s.contains(".."))
        .unwrap_or("output.bin");
    Ok(dir.join(bare))
}

/// Capture a workflow OUTPUT artifact produced at `temp` (a plaintext file the engine just wrote,
/// e.g. a Playwright download or screenshot): read it, encrypt-at-rest, register a
/// `source='workflow_output'` handle tied to `run_id`, then remove the plaintext temp. Returns the
/// new `StoredFile`.
pub async fn capture_output(
    pool: &SqlitePool,
    vault: &Vault,
    paths: &Paths,
    temp: &Path,
    filename: &str,
    content_type: Option<&str>,
    run_id: i64,
) -> LocalResult<StoredFile> {
    let bytes = std::fs::read(temp)?;
    let row = create_file_inner(
        pool,
        vault,
        paths,
        &bytes,
        filename,
        content_type,
        "workflow_output",
        Some(run_id),
    )
    .await?;
    // Best-effort cleanup of the engine's plaintext temp artifact.
    if let Err(e) = std::fs::remove_file(temp) {
        tracing::warn!(temp = %temp.display(), error = %e, "failed to remove captured temp artifact");
    }
    Ok(row)
}

/// A `0600` plaintext tempfile that wipes (overwrite-then-unlink, best-effort) on `Drop`.
///
/// Returned by [`materialize_for_run`] so Playwright's `setInputFiles` (which needs a real path)
/// gets a short-lived decrypted copy that is scrubbed the moment the guard leaves scope. Hold it
/// only for the duration of the step.
pub struct TempGuard {
    path: PathBuf,
    len: u64,
}

impl TempGuard {
    /// The plaintext file path to hand to Playwright. Valid until this guard is dropped.
    pub fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for TempGuard {
    fn drop(&mut self) {
        // Best-effort secure-ish wipe: overwrite the bytes with zeros, then unlink. On a journaling
        // or copy-on-write FS this is not a guarantee, but it removes the obvious plaintext copy.
        if self.len > 0 {
            if let Ok(f) = std::fs::OpenOptions::new().write(true).open(&self.path) {
                use std::io::Write;
                let mut f = f;
                let zeros = vec![0u8; 64 * 1024];
                let mut remaining = self.len;
                while remaining > 0 {
                    let n = remaining.min(zeros.len() as u64) as usize;
                    if f.write_all(&zeros[..n]).is_err() {
                        break;
                    }
                    remaining -= n as u64;
                }
                let _ = f.flush();
            }
        }
        if let Err(e) = std::fs::remove_file(&self.path) {
            if e.kind() != std::io::ErrorKind::NotFound {
                tracing::warn!(path = %self.path.display(), error = %e, "failed to wipe materialized tempfile");
            }
        }
    }
}

/// Decrypt a file handle into a short-lived `0600` plaintext tempfile for `setInputFiles`. Returns
/// the path plus a [`TempGuard`] that wipes the plaintext on drop. The tempfile is named after the
/// handle's human filename (sanitized) so the uploaded file keeps its original name on the target
/// site, but lives in an isolated per-call temp dir.
pub async fn materialize_for_run(
    pool: &SqlitePool,
    vault: &Vault,
    paths: &Paths,
    file_id: &str,
) -> LocalResult<(PathBuf, TempGuard)> {
    let row = stored_files::get_active(pool, file_id)
        .await?
        .ok_or_else(|| LocalError::NotFound(format!("file {file_id}")))?;
    let bytes = read_file_bytes(pool, vault, paths, file_id).await?;

    // Isolated per-materialization dir under the artifacts tree (kept off the user's general temp).
    let mut rnd = [0u8; 8];
    rand::rngs::OsRng.fill_bytes(&mut rnd);
    let suffix = rnd.iter().map(|b| format!("{b:02x}")).collect::<String>();
    let dir = paths.artifacts_dir().join("input_tmp").join(format!("mat_{suffix}"));
    std::fs::create_dir_all(&dir)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700))?;
    }

    let bare = Path::new(&row.filename)
        .file_name()
        .and_then(|s| s.to_str())
        .filter(|s| !s.is_empty() && !s.contains("..") && !s.contains('/') && !s.contains('\\'))
        .unwrap_or("input.bin");
    let path = dir.join(bare);
    write_blob_0600(&path, &bytes)?;

    let guard = TempGuard { path: path.clone(), len: bytes.len() as u64 };
    Ok((path, guard))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::local::config::Paths;
    use crate::local::db;
    use crate::local::vault::Vault;

    async fn setup() -> (Paths, Vault, SqlitePool) {
        let dir = Box::leak(Box::new(tempfile::tempdir().unwrap()));
        let paths = Paths::at(dir.path().join(".writ"));
        paths.ensure_dirs().unwrap();
        let vault = Vault::load_or_create(&paths.root, false).unwrap();
        let pool = db::open(&paths.db(), &vault.db_key_hex()).await.unwrap();
        (paths, vault, pool)
    }

    #[tokio::test]
    async fn create_read_roundtrip_with_encrypted_disk_bytes() {
        let (paths, vault, pool) = setup().await;
        let plaintext = b"PLAINTEXT-NEEDLE: the rain in spain".repeat(2000); // multi-chunk

        let row = create_file(
            &pool,
            &vault,
            &paths,
            &plaintext,
            "report.pdf",
            Some("application/pdf"),
            "upload",
        )
        .await
        .unwrap();
        assert!(row.id.starts_with("file_"));
        assert_eq!(row.content_type, "application/pdf");
        assert_eq!(row.size_bytes, plaintext.len() as i64);
        assert!(row.sha256.is_some());

        // On-disk bytes are the encrypted envelope, NOT the plaintext.
        let path = storage_path_for_key(&paths, &row.source, &row.storage_key).unwrap();
        let on_disk = std::fs::read(&path).unwrap();
        assert_eq!(&on_disk[0..4], b"WFB1", "blob is a WFB1 envelope");
        let needle = b"PLAINTEXT-NEEDLE";
        assert!(
            !on_disk.windows(needle.len()).any(|w| w == needle),
            "plaintext must not appear on disk"
        );

        // Decrypting read round-trips exactly.
        let back = read_file_bytes(&pool, &vault, &paths, &row.id).await.unwrap();
        assert_eq!(back, plaintext);
    }

    #[tokio::test]
    async fn dedup_reuses_same_handle() {
        let (paths, vault, pool) = setup().await;
        let bytes = b"identical-content";
        let a = create_file(&pool, &vault, &paths, bytes, "a.txt", None, "upload").await.unwrap();
        let b = create_file(&pool, &vault, &paths, bytes, "b.txt", None, "upload").await.unwrap();
        assert_eq!(a.id, b.id, "same content+source dedups to one handle");
    }

    #[tokio::test]
    async fn materialize_writes_plaintext_then_wipes_on_drop() {
        let (paths, vault, pool) = setup().await;
        let plaintext = b"upload-me-to-the-form";
        let row =
            create_file(&pool, &vault, &paths, plaintext, "resume.txt", None, "upload").await.unwrap();

        let mat_path;
        {
            let (path, guard) =
                materialize_for_run(&pool, &vault, &paths, &row.id).await.unwrap();
            mat_path = path.clone();
            assert_eq!(guard.path(), path.as_path());
            // The plaintext copy exists and matches for setInputFiles.
            assert_eq!(std::fs::read(&path).unwrap(), plaintext);
            assert!(path.file_name().unwrap().to_str().unwrap() == "resume.txt");
        } // guard dropped here
        assert!(!mat_path.exists(), "plaintext tempfile must be wiped on drop");
    }

    #[tokio::test]
    async fn capture_output_registers_workflow_output_handle() {
        use crate::local::store::runs::{self, NewRun};
        let (paths, vault, pool) = setup().await;
        // A real run is required: stored_files.source_run_id REFERENCES runs(id).
        let run = runs::insert(&pool, &NewRun::default()).await.unwrap();

        // Engine writes a plaintext artifact at the local run path.
        let temp = local_path_for_run(&paths, run.id, "shot.png").unwrap();
        std::fs::write(&temp, b"\x89PNG fake bytes").unwrap();

        let row =
            capture_output(&pool, &vault, &paths, &temp, "shot.png", Some("image/png"), run.id)
                .await
                .unwrap();
        assert_eq!(row.source, "workflow_output");
        assert_eq!(row.source_run_id, Some(run.id));
        assert!(!temp.exists(), "plaintext temp artifact is removed after capture");

        let back = read_file_bytes(&pool, &vault, &paths, &row.id).await.unwrap();
        assert_eq!(back, b"\x89PNG fake bytes");
    }

    #[test]
    fn rejects_traversal_storage_keys() {
        let dir = tempfile::tempdir().unwrap();
        let paths = Paths::at(dir.path().join(".writ"));
        paths.ensure_dirs().unwrap();
        assert!(storage_path_for_key(&paths, "upload", "../escape").is_err());
        assert!(storage_path_for_key(&paths, "upload", "a/b").is_err());
        assert!(storage_path_for_key(&paths, "upload", "ok_blob.wfb").is_ok());
    }
}
