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
    // Cloud and self-host answer with a pre-signed URL, which authorizes itself. The
    // DESKTOP client answers with its own daemon's `/v1/files/{id}/content` — an
    // ordinary authenticated route — and that daemon is THIS process, so supply its
    // bearer. Without it every desktop pick 401'd and the chooser was dismissed empty:
    // the prompt worked, the file was chosen, and the page still uploaded nothing.
    // Scoped to loopback so a token can never be attached to an off-box URL.
    let bearer = if is_loopback_url(&desc.url) {
        daemon_bearer()
    } else {
        None
    };
    let path = match run_files.fetch_to_temp_authed(&desc, bearer.as_deref()).await {
        Ok(p) => p,
        Err(e) => {
            tracing::warn!(session_id, %file_id, error = %e, "could not fetch the picked file");
            return None;
        }
    };

    Some(PickedUpload { file_id, filename, path })
}

/// True when `url` addresses this machine over loopback.
///
/// Deliberately strict — parsed host equality, never a substring test, so a URL like
/// `https://127.0.0.1.evil.test/…` cannot collect the daemon's bearer.
fn is_loopback_url(url: &str) -> bool {
    let Some(rest) = url
        .strip_prefix("http://")
        .or_else(|| url.strip_prefix("https://"))
    else {
        return false;
    };
    // authority = everything before the first '/', '?' or '#'; then drop any :port.
    let authority = rest
        .split(['/', '?', '#'])
        .next()
        .unwrap_or("")
        .rsplit('@') // ignore any userinfo
        .next()
        .unwrap_or("");
    // An IPv6 literal is bracketed and full of colons, so the port can only be found
    // AFTER the closing bracket — `rfind(':')` alone would cut the address in half.
    let host = if let Some(stripped) = authority.strip_prefix('[') {
        match stripped.find(']') {
            Some(end) => &stripped[..end],
            None => return false, // unterminated literal — not something to trust
        }
    } else {
        match authority.rfind(':') {
            Some(i) => &authority[..i],
            None => authority,
        }
    };
    host.eq_ignore_ascii_case("localhost")
        || host
            .parse::<std::net::IpAddr>()
            .map(|ip| ip.is_loopback())
            .unwrap_or(false)
}

/// This daemon's own bearer token, for fetching its own content route.
///
/// Only compiled into the `local` build — a cloud agent has no local daemon and no such
/// token, and its answers carry pre-signed URLs that need none.
#[cfg(feature = "local")]
fn daemon_bearer() -> Option<String> {
    let paths = crate::local::config::Paths::resolve().ok()?;
    let seed = std::fs::read_to_string(paths.local_token())
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())?;
    // Honour a live `POST /v1/token/rotate`: the file holds the boot seed, and the
    // overlay holds the value the auth layer is actually checking right now.
    Some(crate::local::runtime_token::current(&seed))
}

#[cfg(not(feature = "local"))]
fn daemon_bearer() -> Option<String> {
    None
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

#[cfg(test)]
mod tests {
    use super::is_loopback_url;

    /// The bearer is only ever attached to this machine's own daemon. A host that
    /// merely CONTAINS a loopback literal is a different machine, and handing it the
    /// token would leak full local API access to whoever controls that name.
    #[test]
    fn only_real_loopback_hosts_get_the_token() {
        for url in [
            "http://127.0.0.1:8131/v1/files/file_a/content",
            "http://localhost:8131/v1/files/file_a/content",
            "http://LOCALHOST:8131/v1/files/file_a/content",
            "https://127.0.0.1:8132/v1/files/file_a/content",
            "http://[::1]:8131/v1/files/file_a/content",
            "http://127.0.0.2:8131/v1/files/file_a/content", // whole 127/8 is loopback
        ] {
            assert!(is_loopback_url(url), "should be loopback: {url}");
        }

        for url in [
            "https://127.0.0.1.evil.test/v1/files/file_a/content",
            "https://localhost.evil.test/v1/files/file_a/content",
            "https://evil.test/?x=127.0.0.1",
            "https://evil.test/127.0.0.1/content",
            "https://api.usewrit.app/api/files/dl/tok",
            "https://user@evil.test/v1/files/a/content",
            "http://192.168.1.10:8131/v1/files/a/content",
            "ftp://127.0.0.1/x",
            "",
        ] {
            assert!(!is_loopback_url(url), "must NOT be loopback: {url}");
        }
    }
}
