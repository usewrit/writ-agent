//! File assets — replay-side run-level files map + direct-to-storage capture.
//!
//! Mirrors the Python agent's file-asset wiring (desktop-agent/lib/automation_engine.py
//! §5.2) and the plan §6.3. The engine threads a [`RunFiles`] in (the same way
//! `form_data`/`credentials` are threaded), built from the dispatch message's
//! `config["files"]` map and the backend artifact-callback context.
//!
//! SECURITY (§4.4/§10):
//!   * The run files map is built BACKEND-SIDE, ownership-checked + short-TTL signed.
//!     The agent only consumes what the backend resolved for THIS run's tenant — it
//!     never trusts a caller-supplied tenant or URL.
//!   * Captured downloads upload DIRECT to object storage via a backend-minted,
//!     scoped, size-capped presigned upload — the bytes NEVER stream through the
//!     backend. The backend mints the URL (artifact-init) and HEADs the object to
//!     finalize (artifact-finalize).
//!   * Every fetched/captured temp file is deleted (temp-file hygiene §10.5).

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Mutex;

use serde::Deserialize;

/// A single run-level file descriptor (one entry of the dispatch `config["files"]`
/// map). Produced backend-side by `file_service.resolve_for_run` — `url` is a
/// single-object, short-TTL signed GET (§4.1/§10.4).
#[derive(Debug, Clone, Deserialize)]
pub struct ResolvedFile {
    pub file_id: String,
    pub url: String,
    #[serde(default)]
    pub filename: Option<String>,
    #[serde(default)]
    pub content_type: Option<String>,
    #[serde(default)]
    pub size: Option<u64>,
    /// Slot names (from a buyer/caller `{slot: file_id}` binding) this file is bound
    /// to — used to match an upload step's `file_slot` / a `{{file:slot}}` reference.
    #[serde(default)]
    pub slots: Vec<String>,
}

/// Backend artifact-callback context for DIRECT-TO-STORAGE download capture (§4.4).
/// `base_url` is the backend API base (e.g. `https://host/api`); the two small JSON
/// calls (`artifact-init`/`artifact-finalize`) authenticate with `token` (the same
/// Bearer the agent uses for `/api/recorder/connect` — a tenant-scoped JWT/API key)
/// plus the executor-binding `agent_id`. The bulk upload goes straight to storage
/// with NO backend auth (the presigned URL/fields ARE the credential).
#[derive(Debug, Clone)]
pub struct ArtifactContext {
    pub base_url: String,
    pub token: String,
    pub agent_id: String,
    pub task_id: String,
}

/// A finalized captured-download handle, surfaced as `result_data.output_files`.
#[derive(Debug, Clone, serde::Serialize)]
pub struct OutputFile {
    pub file_id: String,
    pub filename: String,
    pub size: u64,
    pub content_type: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub output_key: Option<String>,
}

/// Run-level file state threaded through the replay engine. Shares interior
/// mutability (Mutex) so the per-step `&RunFiles` calls can cache fetched temp paths
/// (a file referenced by both an upload step and `{{file:slot}}` is fetched once) and
/// accumulate captured `output_files`.
pub struct RunFiles {
    /// file_id -> descriptor (the dispatch `config["files"]` map).
    files: HashMap<String, ResolvedFile>,
    /// Backend artifact-callback context; `None` when the run carries no capture
    /// context (then wait_for_download fails closed rather than silently dropping).
    artifact: Option<ArtifactContext>,
    /// file_id -> fetched local temp path (cache; cleaned up at run end).
    fetched: Mutex<HashMap<String, PathBuf>>,
    /// Captured downloads finalized this run (→ result_data.output_files).
    output_files: Mutex<Vec<OutputFile>>,
}

impl RunFiles {
    /// Build the run-files map from the dispatch message `config`. Parses
    /// `config["files"]` (the backend-resolved `{file_id -> descriptor}` map) and the
    /// artifact-callback context. Empty/absent → an inert RunFiles (no files).
    pub fn from_config(config: &serde_json::Value, artifact: Option<ArtifactContext>) -> Self {
        let mut files: HashMap<String, ResolvedFile> = HashMap::new();
        if let Some(obj) = config.get("files").and_then(|v| v.as_object()) {
            for (fid, desc) in obj {
                match serde_json::from_value::<ResolvedFile>(desc.clone()) {
                    Ok(mut rf) => {
                        // The map key is authoritative for the id (defends against a
                        // descriptor missing/ mismatching file_id).
                        if rf.file_id.is_empty() {
                            rf.file_id = fid.clone();
                        }
                        files.insert(fid.clone(), rf);
                    }
                    Err(e) => {
                        tracing::warn!(file_id = %fid, error = %e, "Skipping malformed run-file descriptor");
                    }
                }
            }
        }
        Self {
            files,
            artifact,
            fetched: Mutex::new(HashMap::new()),
            output_files: Mutex::new(Vec::new()),
        }
    }

    /// Build a run-files map from files ALREADY materialized to local temp paths (the local daemon
    /// path — files live age-encrypted in the on-device vault, not behind signed URLs). Each entry is
    /// `(descriptor, local_temp_path)`; the path is pre-seeded into the fetch cache so `fetch_to_temp`
    /// returns it directly (no HTTP). The caller owns the temp files' lifetime (e.g. `TempGuard`s held
    /// for the run) — `RunFiles` does not delete them here.
    pub fn from_prefetched(entries: Vec<(ResolvedFile, PathBuf)>) -> Self {
        let mut files: HashMap<String, ResolvedFile> = HashMap::new();
        let mut fetched: HashMap<String, PathBuf> = HashMap::new();
        for (desc, path) in entries {
            fetched.insert(desc.file_id.clone(), path);
            files.insert(desc.file_id.clone(), desc);
        }
        Self {
            files,
            artifact: None,
            fetched: Mutex::new(fetched),
            output_files: Mutex::new(Vec::new()),
        }
    }

    pub fn is_empty(&self) -> bool {
        self.files.is_empty()
    }

    pub fn len(&self) -> usize {
        self.files.len()
    }

    pub fn artifact(&self) -> Option<&ArtifactContext> {
        self.artifact.as_ref()
    }

    /// Resolve the descriptor(s) an upload step targets.
    ///
    /// Looks up, in order:
    ///   * `config.file_id`   — a concrete file id (own runs); direct lookup.
    ///   * `config.file_slot` — a slot name bound by the buyer/caller; matched against
    ///                          each descriptor's `slots` list.
    pub fn resolve_step_files(
        &self,
        file_id: Option<&str>,
        file_slot: Option<&str>,
    ) -> Vec<ResolvedFile> {
        if let Some(fid) = file_id.filter(|s| !s.is_empty()) {
            if let Some(d) = self.files.get(fid) {
                return vec![d.clone()];
            }
        }
        if let Some(slot) = file_slot.filter(|s| !s.is_empty()) {
            if let Some(d) = self.find_by_slot(slot) {
                return vec![d];
            }
        }
        Vec::new()
    }

    /// Find a descriptor bound to `slot` (via its `slots` list).
    pub fn find_by_slot(&self, slot: &str) -> Option<ResolvedFile> {
        if slot.is_empty() {
            return None;
        }
        self.files
            .values()
            .find(|d| d.slots.iter().any(|s| s == slot))
            .cloned()
    }

    /// Fetch a resolved file's signed URL to a local temp path, caching by file id.
    /// The signed GET URL is single-object, short-TTL (§10.4). Returns the local path
    /// (cleaned up at run end via [`cleanup_temps`]).
    pub async fn fetch_to_temp(&self, desc: &ResolvedFile) -> anyhow::Result<PathBuf> {
        if desc.url.is_empty() {
            anyhow::bail!("file descriptor has no signed URL");
        }
        // Cache hit?
        {
            let cache = self.fetched.lock().unwrap();
            if let Some(p) = cache.get(&desc.file_id) {
                if p.exists() {
                    return Ok(p.clone());
                }
            }
        }

        let suffix = filename_suffix(desc.filename.as_deref());
        let tmp = unique_temp_path("psfile_", &suffix);

        let client = reqwest::Client::new();
        let resp = client
            .get(&desc.url)
            .timeout(std::time::Duration::from_secs(120))
            .send()
            .await
            .map_err(|e| anyhow::anyhow!("fetch stored file failed: {}", e))?;
        if !resp.status().is_success() {
            anyhow::bail!("fetch stored file failed: HTTP {}", resp.status());
        }
        let bytes = resp
            .bytes()
            .await
            .map_err(|e| anyhow::anyhow!("read stored file body failed: {}", e))?;
        tokio::fs::write(&tmp, &bytes)
            .await
            .map_err(|e| anyhow::anyhow!("write temp file failed: {}", e))?;

        self.fetched
            .lock()
            .unwrap()
            .insert(desc.file_id.clone(), tmp.clone());
        tracing::debug!(file_id = %desc.file_id, path = %tmp.display(), "Fetched stored file to temp");
        Ok(tmp)
    }

    /// A `slot -> local temp path` map of all files fetched so far, for the
    /// `{{file:slot}}` value-resolver pass. A file is keyed under each of its slots.
    pub fn fetched_slot_paths(&self) -> HashMap<String, String> {
        let cache = self.fetched.lock().unwrap();
        let mut out: HashMap<String, String> = HashMap::new();
        for (file_id, path) in cache.iter() {
            if let Some(desc) = self.files.get(file_id) {
                for slot in &desc.slots {
                    out.insert(slot.clone(), path.to_string_lossy().to_string());
                }
            }
        }
        out
    }

    /// Eagerly fetch every file bound to a slot so `{{file:slot}}` references resolve
    /// to a local path even when the slot isn't tied to an upload step. Best-effort:
    /// a fetch failure is logged and skipped (the placeholder is then left as-is).
    pub async fn prefetch_slot_files(&self) {
        let with_slots: Vec<ResolvedFile> = self
            .files
            .values()
            .filter(|d| !d.slots.is_empty())
            .cloned()
            .collect();
        for desc in with_slots {
            if let Err(e) = self.fetch_to_temp(&desc).await {
                tracing::warn!(file_id = %desc.file_id, error = %e, "prefetch for {{file:slot}} failed (skipped)");
            }
        }
    }

    /// Record a finalized captured-download handle (→ result_data.output_files).
    pub fn push_output_file(&self, f: OutputFile) {
        self.output_files.lock().unwrap().push(f);
    }

    /// Drain the accumulated output files as JSON for the task_result frame.
    pub fn output_files_json(&self) -> Vec<serde_json::Value> {
        self.output_files
            .lock()
            .unwrap()
            .iter()
            .map(|f| serde_json::to_value(f).unwrap_or(serde_json::Value::Null))
            .collect()
    }

    /// Delete all temp files fetched for upload / `{{file:slot}}` resolution (§10.5).
    pub fn cleanup_temps(&self) {
        let mut cache = self.fetched.lock().unwrap();
        for (_id, path) in cache.drain() {
            if path.exists() {
                let _ = std::fs::remove_file(&path);
            }
        }
    }
}

/// Derive a filename suffix (extension) to keep the temp file's type hint. Capped so
/// a hostile suggested filename can't blow up the path.
pub fn filename_suffix(filename: Option<&str>) -> String {
    let name = match filename {
        Some(n) if !n.is_empty() => n,
        _ => return String::new(),
    };
    match name.rfind('.') {
        Some(i) if i > 0 => {
            let ext = &name[i..];
            // Keep only a short, safe extension (alnum + dot), max 16 chars.
            let safe: String = ext
                .chars()
                .take(16)
                .filter(|c| c.is_ascii_alphanumeric() || *c == '.')
                .collect();
            safe
        }
        _ => String::new(),
    }
}

/// A unique temp path in the system temp dir (basename-only, no traversal). Mirrors
/// `streaming/runtime_bridge.rs::safe_temp_path` (uses a uuid to avoid collisions).
pub fn unique_temp_path(prefix: &str, suffix: &str) -> PathBuf {
    let name = format!("{}{}{}", prefix, uuid::Uuid::new_v4().simple(), suffix);
    std::env::temp_dir().join(name)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn filename_suffix_extracts_extension() {
        assert_eq!(filename_suffix(Some("report.pdf")), ".pdf");
        assert_eq!(filename_suffix(Some("archive.tar.gz")), ".gz");
        assert_eq!(filename_suffix(Some("noext")), "");
        assert_eq!(filename_suffix(None), "");
    }

    #[test]
    fn from_config_parses_files_map() {
        let cfg = serde_json::json!({
            "files": {
                "file_abc": {
                    "file_id": "file_abc",
                    "url": "https://store/file_abc?sig=x",
                    "filename": "resume.pdf",
                    "content_type": "application/pdf",
                    "size": 1234,
                    "slots": ["resume"]
                }
            }
        });
        let rf = RunFiles::from_config(&cfg, None);
        assert_eq!(rf.len(), 1);
        let by_id = rf.resolve_step_files(Some("file_abc"), None);
        assert_eq!(by_id.len(), 1);
        assert_eq!(by_id[0].filename.as_deref(), Some("resume.pdf"));
        let by_slot = rf.resolve_step_files(None, Some("resume"));
        assert_eq!(by_slot.len(), 1);
        assert_eq!(by_slot[0].file_id, "file_abc");
    }
}
