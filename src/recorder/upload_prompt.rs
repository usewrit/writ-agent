//! Ask the client which stored file to feed a page's file chooser.
//!
//! The recorded browser runs on an agent, so the operating system's file dialog is
//! unanswerable by the person recording — the chooser could only ever be dismissed
//! empty. The page then behaves as if nothing was picked, and everything downstream of
//! the upload (submit, preview, progress, the success screen) becomes unrecordable.
//!
//! So the recorder turns the dialog into a round-trip: emit `upload_prompt`, let the
//! client answer with a stored file, fetch those bytes, and hand them to the chooser.
//! The page then does a REAL upload, exactly as it would for a human.
//!
//! The answer is `{file_id, filename, url}`. The CLIENT supplies the url because it is
//! the only side that can authenticate for the bytes: on cloud/self-host it mints a
//! short-TTL single-file URL (`/files/{id}/signed-url`) since this agent holds no user
//! credentials; on desktop it passes its own daemon's content URL.
//!
//! Skipping, a timeout, an unreachable file — all return `None`, and the caller falls
//! back to dismiss-empty. A recording is never blocked by this prompt.

use std::path::PathBuf;
use std::sync::Arc;

use dashmap::DashMap;

use crate::models::session::{PendingUpload, RecordingSession};

/// How long to wait for the operator to answer. Generous (they may need to find or
/// upload a file) but bounded, so an abandoned tab cannot pin the page's chooser — and
/// with it the recording — open forever.
const PROMPT_TIMEOUT_SECS: u64 = 300;

/// A file the operator bound to this chooser, already on local disk.
pub struct PickedUpload {
    pub file_id: String,
    pub filename: Option<String>,
    pub path: PathBuf,
}

/// Prompt, await the answer, and materialise the bytes locally.
pub async fn prompt_for_upload_file(
    sessions: &Arc<DashMap<String, RecordingSession>>,
    session_id: &str,
    selector: &str,
    is_multiple: bool,
) -> Option<PickedUpload> {
    let request_id = uuid::Uuid::new_v4().simple().to_string();
    let (tx, rx) = tokio::sync::oneshot::channel::<Option<serde_json::Value>>();

    // Arm the pending slot and emit the prompt under ONE brief lock, so an answer can
    // never race in between (it would find no pending slot and be dropped).
    {
        let mut session = super::session_lock::session_mut(sessions, session_id).await?;
        session.pending_upload = Some(PendingUpload {
            request_id: request_id.clone(),
            responder: tx,
        });
        session.send_event(serde_json::json!({
            "type": "upload_prompt",
            "request_id": request_id,
            "selector": selector,
            "is_multiple": is_multiple,
        }));
    }

    let answer = match tokio::time::timeout(
        std::time::Duration::from_secs(PROMPT_TIMEOUT_SECS),
        rx,
    )
    .await
    {
        Ok(Ok(Some(v))) => v,
        // Skipped, sender dropped (client gone), or timed out — all "continue unbound".
        Ok(Ok(None)) | Ok(Err(_)) => {
            clear_pending(sessions, session_id).await;
            return None;
        }
        Err(_) => {
            tracing::info!(session_id, "upload prompt timed out — continuing unbound");
            clear_pending(sessions, session_id).await;
            return None;
        }
    };
    clear_pending(sessions, session_id).await;

    let file_id = answer.get("file_id")?.as_str()?.to_string();
    let filename = answer
        .get("filename")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());
    let url = answer.get("url").and_then(|v| v.as_str()).unwrap_or("").to_string();

    if url.is_empty() {
        // Every deployment must hand over a fetchable URL: the client is the only side
        // that can authenticate for the file's bytes (cloud mints a short-TTL signed
        // URL; desktop passes its own daemon's content URL). Without one there is
        // nothing to upload, so fall back to dismiss-empty rather than guessing at a
        // path on disk.
        tracing::warn!(session_id, %file_id, "upload answer carried no url — continuing unbound");
        return None;
    }
    // Reuses the SAME fetch a replay run uses for its files map, so record and replay
    // materialise a stored file identically (temp naming, size handling, cleanup).
    let desc = crate::automation::files::ResolvedFile {
        file_id: file_id.clone(),
        url,
        filename: filename.clone(),
        content_type: None,
        size: None,
        slots: Vec::new(),
    };
    let run_files = crate::automation::files::RunFiles::from_prefetched(Vec::new());
    let path = match run_files.fetch_to_temp(&desc).await {
        Ok(p) => p,
        Err(e) => {
            tracing::warn!(session_id, %file_id, error = %e, "could not fetch the picked file");
            return None;
        }
    };

    Some(PickedUpload { file_id, filename, path })
}

/// Drop any pending prompt for this session (idempotent).
async fn clear_pending(sessions: &Arc<DashMap<String, RecordingSession>>, session_id: &str) {
    if let Some(mut session) = super::session_lock::session_mut(sessions, session_id).await {
        session.pending_upload = None;
    }
}

/// Deliver a client's `upload_file_selected` answer to the waiting chooser.
///
/// Returns true when it resolved a live prompt. The `request_id` must match the prompt
/// that is CURRENTLY open: a late answer to an already-timed-out chooser would otherwise
/// satisfy the next one with the wrong file.
pub async fn deliver_answer(
    sessions: &Arc<DashMap<String, RecordingSession>>,
    session_id: &str,
    msg: &serde_json::Value,
) -> bool {
    let Some(mut session) = super::session_lock::session_mut(sessions, session_id).await else {
        return false;
    };
    let Some(pending) = session.pending_upload.as_ref() else {
        return false;
    };
    if let Some(rid) = msg.get("request_id").and_then(|v| v.as_str()) {
        if rid != pending.request_id {
            tracing::debug!(session_id, "upload_file_selected for a stale request — ignoring");
            return false;
        }
    }
    // take() so the single-use sender moves out and a second answer finds nothing.
    let pending = session.pending_upload.take().unwrap();
    let payload = if msg.get("skip").and_then(|v| v.as_bool()).unwrap_or(false) {
        None
    } else {
        Some(msg.clone())
    };
    let _ = pending.responder.send(payload);
    true
}
