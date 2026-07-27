//! Bounded response-body reads — the ONE place every outbound fetch in this crate reads a body.
//!
//! WHY THIS EXISTS. `reqwest` is built with the `gzip` feature and none of our clients disable it,
//! so every request advertises `Accept-Encoding: gzip` and reqwest transparently INFLATES the
//! response for us. `resp.text()` / `resp.bytes()` inflate into an unbounded heap buffer, and
//! gzip's maximum compression ratio is ~1032:1 — roughly 1 MB on the wire becomes ~1 GB resident.
//! Any crawled page, monitored target, robots.txt, sitemap or API response could therefore OOM the
//! agent for kilobytes of attacker cost. The request timeout does not help: a bomb arrives in
//! milliseconds, it is the *size* that kills, not the duration.
//!
//! HOW. The body is streamed chunk-by-chunk against a per-lane byte budget and the read is aborted
//! the moment the budget is exceeded, so peak residency is `limit` plus one transport chunk.
//! `Content-Length` is consulted ONLY as an early reject — it is attacker-controlled, absent under
//! `Transfer-Encoding: chunked`, and describes the COMPRESSED size for a gzipped body — so the
//! authoritative check is always the running counter over the decoded chunks.
//!
//! This module lives under `crawl_shard` because that is where most of the fetch surface is, but it
//! is deliberately shared: `monitor::checker` and `automation::http_lane` read through it too.

/// Web pages. Comfortably above the largest real HTML documents (a few MB) and far below the point
/// where parsing + markdown conversion becomes a CPU-starvation problem on its own.
pub const HTML_MAX: usize = 10 * 1024 * 1024;

/// robots.txt. 512 KiB is the de-facto standard cap (Google's documented limit), and the file is
/// re-scanned linearly for every admitted URL, so an unbounded one is a CPU bomb as well as a heap one.
pub const ROBOTS_MAX: usize = 512 * 1024;

/// One sitemap / sitemap-index document.
pub const SITEMAP_MAX: usize = 10 * 1024 * 1024;

/// Documents forwarded to the doc-extract sidecar (PDF / office / image / JSON / CSV). Matches the
/// sidecar's own 32 MiB body cap — anything larger is rejected there anyway.
pub const DOC_MAX: usize = 32 * 1024 * 1024;

/// API / login responses read by the browserless HTTP lane. These are parsed as JSON and stored in
/// step outputs, so the budget is a page-sized one rather than a document-sized one.
pub const API_RESPONSE_MAX: usize = 10 * 1024 * 1024;

/// Why a bounded body read failed.
#[derive(Debug, Clone)]
pub enum BodyReadError {
    /// The body exceeded this lane's budget. `observed` is how many bytes had been decoded when the
    /// read was abandoned (or the advertised `Content-Length`, when that alone was over budget).
    TooLarge { limit: usize, observed: u64 },
    /// The transport failed part-way through the body.
    Transport(String),
}

impl std::fmt::Display for BodyReadError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BodyReadError::TooLarge { limit, observed } => write!(
                f,
                "response body too large: {observed} bytes exceeds the {limit}-byte budget"
            ),
            BodyReadError::Transport(e) => write!(f, "read body failed: {e}"),
        }
    }
}

impl std::error::Error for BodyReadError {}

/// Read at most `limit` bytes of `resp`'s body, erroring rather than buffering past the budget.
pub async fn read_bytes_capped(
    mut resp: reqwest::Response,
    limit: usize,
) -> Result<Vec<u8>, BodyReadError> {
    // Cheap pre-check: an ADVERTISED length over budget means we never have to pull the body at
    // all. This is an optimisation, not the guard — see the module docs.
    if let Some(len) = resp.content_length() {
        if len > limit as u64 {
            return Err(BodyReadError::TooLarge { limit, observed: len });
        }
    }
    // Never pre-allocate from the (attacker-controlled) advertised length: a lying
    // `Content-Length: 9MB` on an empty body would otherwise reserve 9 MB per request.
    let mut out: Vec<u8> = Vec::new();
    loop {
        match resp.chunk().await {
            Ok(Some(chunk)) => {
                // Check BEFORE extending so the buffer never grows past `limit` + one chunk.
                let would_be = out.len().saturating_add(chunk.len());
                if would_be > limit {
                    return Err(BodyReadError::TooLarge { limit, observed: would_be as u64 });
                }
                out.extend_from_slice(&chunk);
            }
            Ok(None) => break,
            Err(e) => return Err(BodyReadError::Transport(e.to_string())),
        }
    }
    Ok(out)
}

/// Read at most `limit` bytes of `resp`'s body and decode it to text with the SAME charset handling
/// `reqwest::Response::text` applies (the `Content-Type` `charset=` parameter, defaulting to UTF-8).
///
/// The capped bytes are handed back to reqwest as a synthetic response rather than assumed to be
/// UTF-8: a windows-1252 / Shift-JIS page must decode exactly as it did before this cap existed,
/// otherwise monitor content hashes and crawl markdown would silently change for those sites.
pub async fn read_text_capped(
    resp: reqwest::Response,
    limit: usize,
) -> Result<String, BodyReadError> {
    let status = resp.status();
    let mut headers = resp.headers().clone();
    // reqwest already inflated the body and strips these on the real response; drop them so the
    // synthetic one below can never be interpreted as still-encoded or mis-sized.
    headers.remove(reqwest::header::CONTENT_ENCODING);
    headers.remove(reqwest::header::CONTENT_LENGTH);

    let bytes = read_bytes_capped(resp, limit).await?;

    let mut builder = axum::http::Response::builder().status(status);
    if let Some(h) = builder.headers_mut() {
        *h = headers;
    }
    match builder.body(bytes) {
        // A synthetic in-memory body cannot fail a transport read; `text()` is infallible here in
        // practice, and a lossy UTF-8 decode is the right degrade if that ever changes.
        Ok(synthetic) => Ok(reqwest::Response::from(synthetic)
            .text()
            .await
            .unwrap_or_default()),
        Err(e) => Err(BodyReadError::Transport(e.to_string())),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A synthetic response round-trips through the cap, and the charset declared in `Content-Type`
    /// is honored (this is what `read_text_capped` exists to preserve).
    #[tokio::test]
    async fn text_read_honors_declared_charset() {
        // 0xE9 is `é` in windows-1252 / latin-1 and invalid UTF-8 — a plain lossy decode would
        // yield U+FFFD instead.
        let body = vec![b'c', b'a', b'f', 0xE9];
        let synthetic = axum::http::Response::builder()
            .status(200)
            .header("content-type", "text/html; charset=windows-1252")
            .body(body)
            .unwrap();
        let text = read_text_capped(reqwest::Response::from(synthetic), HTML_MAX)
            .await
            .unwrap();
        assert_eq!(text, "café", "declared charset must still be applied after capping");
    }

    /// A body with NO advertised length (chunked transfer) must still be caught — by the streaming
    /// counter. This is the case that matters: a decompression bomb's `Content-Length` describes the
    /// tiny compressed payload, or is absent entirely.
    #[tokio::test]
    async fn streaming_counter_rejects_a_body_with_no_advertised_length() {
        // `wrap_stream` gives a body of unknown size, so `content_length()` is None and the
        // early-reject branch cannot fire.
        let chunks: Vec<Result<Vec<u8>, std::io::Error>> =
            (0..8).map(|_| Ok(vec![b'x'; 512])).collect();
        let body = reqwest::Body::wrap_stream(futures_util::stream::iter(chunks));
        let synthetic = axum::http::Response::builder().status(200).body(body).unwrap();
        let resp = reqwest::Response::from(synthetic);
        assert!(resp.content_length().is_none(), "test needs an unsized body");
        let err = read_bytes_capped(resp, 1024)
            .await
            .expect_err("over-budget body must error");
        assert!(matches!(err, BodyReadError::TooLarge { limit: 1024, .. }), "{err}");
    }

    /// A body at exactly the budget is fine — the cap is inclusive.
    #[tokio::test]
    async fn body_at_budget_is_accepted() {
        let synthetic = axum::http::Response::builder()
            .status(200)
            .body(vec![b'y'; 1024])
            .unwrap();
        let out = read_bytes_capped(reqwest::Response::from(synthetic), 1024)
            .await
            .unwrap();
        assert_eq!(out.len(), 1024);
    }

    /// A KNOWN length over budget short-circuits before any body byte is pulled.
    #[tokio::test]
    async fn advertised_length_over_budget_short_circuits() {
        let synthetic = axum::http::Response::builder()
            .status(200)
            .body(vec![b'z'; 4096])
            .unwrap();
        let resp = reqwest::Response::from(synthetic);
        assert_eq!(resp.content_length(), Some(4096), "test needs a sized body");
        let err = read_bytes_capped(resp, 1024)
            .await
            .expect_err("advertised over-budget length must error");
        assert!(matches!(err, BodyReadError::TooLarge { observed: 4096, .. }), "{err}");
    }
}
