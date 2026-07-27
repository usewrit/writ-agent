//! Thin client for the `doc-extract` sidecar (Rust twin of the Python agent's
//! `doc_extract_client`).
//!
//! The crawl agent owns fetching + rendering; it does NOT parse PDFs / office
//! docs / images itself. When a fetched resource is non-HTML (or a rendered page
//! yielded a screenshot needing OCR) it forwards the raw bytes here and gets back
//! normalized `{markdown, text, tables, records, ocr, content_kind}`.
//!
//! Graceful by design: if `DOC_EXTRACT_URL` is unset the client is a no-op
//! (returns `None`) so the crawl behaves exactly as it did before this service
//! existed. Any transport/timeout/HTTP error also returns `None` — a document we
//! can't parse must never fail a shard.

use serde_json::Value;
use std::sync::OnceLock;
use std::time::Duration;

/// 32 MiB — mirrors the sidecar's own body cap; don't forward larger.
const MAX_FORWARD_BYTES: usize = 32 * 1024 * 1024;

/// Cap on the JSON the sidecar returns. It is normalized markdown/records for ONE document, so a
/// page-sized budget is generous; without it a misbehaving or compromised sidecar could stream an
/// unbounded (gzip-inflated) body straight into the agent's heap.
const MAX_RESULT_BYTES: usize = 64 * 1024 * 1024;

/// ONE shared client for the sidecar. Built per-call previously, which threw away the connection pool
/// on every single document — a fresh TCP+TLS handshake per page in the document lane.
static CLIENT: OnceLock<Option<reqwest::Client>> = OnceLock::new();

fn client() -> Option<&'static reqwest::Client> {
    CLIENT
        .get_or_init(|| {
            reqwest::Client::builder()
                .timeout(Duration::from_secs(65))
                // reqwest's default connect timeout is None: a black-holing sidecar host would
                // otherwise hold the caller for the full 65 s total budget on the handshake alone.
                .connect_timeout(Duration::from_secs(10))
                // NOTE: deliberately NO `vetting_resolver` here, unlike every other client in this
                // crate. `DOC_EXTRACT_URL` is an OPERATOR-configured sidecar address, not an
                // attacker-supplied target, and it is normally on loopback or a private container
                // network — the SSRF resolver would refuse exactly the address that is correct.
                .build()
                .ok()
        })
        .as_ref()
}

fn base_url() -> Option<String> {
    std::env::var("DOC_EXTRACT_URL")
        .ok()
        .map(|s| s.trim_end_matches('/').to_string())
        .filter(|s| !s.is_empty())
}

/// Whether a sidecar is configured. Cheap — read once per shard to decide whether
/// non-HTML content is extractable or should be skipped.
pub fn is_configured() -> bool {
    base_url().is_some()
}

/// POST raw bytes to the sidecar; return the parsed result, or `None` if the
/// service is unconfigured / unreachable / the body is empty or over the cap.
pub async fn extract(
    data: &[u8],
    content_type: &str,
    source_url: &str,
    ocr_mode: &str,
) -> Option<Value> {
    let base = base_url()?;
    if data.is_empty() || data.len() > MAX_FORWARD_BYTES {
        return None;
    }

    let client = client()?;

    let ct = if content_type.is_empty() {
        "application/octet-stream"
    } else {
        content_type
    };
    let mut req = client
        .post(format!("{base}/extract"))
        .header("Content-Type", "application/octet-stream")
        .header("X-Content-Type", ct)
        .header("X-Source-Url", source_url)
        .header("X-OCR-Mode", ocr_mode)
        .body(data.to_vec());
    if let Ok(secret) = std::env::var("DOC_EXTRACT_SECRET") {
        if !secret.is_empty() {
            req = req.header("X-Doc-Secret", secret);
        }
    }

    let resp = req.send().await.ok()?;
    if !resp.status().is_success() {
        return None;
    }
    // Bounded read then parse, rather than `resp.json()` (which buffers the whole gunzipped body).
    let bytes = super::body_limit::read_bytes_capped(resp, MAX_RESULT_BYTES)
        .await
        .map_err(|e| tracing::warn!(error = %e, "doc-extract result body rejected"))
        .ok()?;
    serde_json::from_slice::<Value>(&bytes).ok()
}
