//! Crawl document capture — store a discovered document's RAW bytes as a tenant
//! file through the artifact lane.
//!
//! artifact-init (with the crawl dedupe keys: `source_url` + `md5` + `sha256` +
//! `size`) → presigned DIRECT upload → artifact-finalize. When the backend
//! answers the init with `dedup: true` the document is unchanged since its last
//! capture — the existing file is linked to this crawl server-side and NO upload
//! happens.
//!
//! Graceful by design, mirroring `doc_extract`: no [`ArtifactContext`] (self-host
//! coordinator without the artifact endpoints, run without a token) or ANY error
//! on any leg returns `None` — the extracted markdown/rows are the crawl's
//! primary product; the original file is additive and must never fail a page.

use crate::automation::files::ArtifactContext;
use serde_json::{json, Value};
use std::time::Duration;

/// Is this non-HTML fetch worth storing as a tenant FILE (not just extracting)?
///
/// The capture set is the document set: PDF, office docs, images, and CSV/TSV —
/// things a user recognizes as a file. JSON is deliberately excluded: json-lane
/// fetches are almost always API payloads a page links to, not documents, and an
/// API-heavy site would flood the file library with thousands of them.
pub fn is_capturable(content_type: &str, url: &str) -> bool {
    let c = content_type
        .split(';')
        .next()
        .unwrap_or("")
        .trim()
        .to_ascii_lowercase();
    let url_l = url.split('?').next().unwrap_or("").to_ascii_lowercase();
    let office = c.contains("openxmlformats-officedocument")
        || c == "application/msword"
        || c == "application/vnd.ms-excel"
        || c == "application/vnd.ms-powerpoint";
    if c == "application/pdf" || office || c.starts_with("image/") {
        return true;
    }
    if c == "text/csv" || c == "application/csv" || c == "text/tab-separated-values" {
        return true;
    }
    if (c.is_empty() || c == "application/octet-stream") && !url_l.ends_with(".json") {
        const DOC_SUFFIXES: [&str; 16] = [
            ".pdf", ".docx", ".xlsx", ".pptx", ".doc", ".xls", ".ppt", ".csv", ".tsv",
            ".png", ".jpg", ".jpeg", ".webp", ".gif", ".bmp", ".tiff",
        ];
        return DOC_SUFFIXES.iter().any(|s| url_l.ends_with(s));
    }
    false
}

/// A display filename for a captured document: the URL path's basename
/// (percent-decoded; sanitized server-side anyway), with an extension appended
/// from the content type when the path has none. Never empty.
fn doc_filename(url: &str, content_type: &str) -> String {
    let path = url::Url::parse(url)
        .map(|u| u.path().to_string())
        .unwrap_or_default();
    let base = path.trim_end_matches('/').rsplit('/').next().unwrap_or("");
    let decoded = percent_decode(base);
    let mut name = decoded.trim().to_string();
    if name.is_empty() {
        name = "document".into();
    }
    if !name.contains('.') {
        let c = content_type
            .split(';')
            .next()
            .unwrap_or("")
            .trim()
            .to_ascii_lowercase();
        let ext = match c.as_str() {
            "application/pdf" => ".pdf",
            "application/msword" => ".doc",
            "application/vnd.ms-excel" => ".xls",
            "application/vnd.ms-powerpoint" => ".ppt",
            "application/vnd.openxmlformats-officedocument.wordprocessingml.document" => ".docx",
            "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet" => ".xlsx",
            "application/vnd.openxmlformats-officedocument.presentationml.presentation" => ".pptx",
            "text/csv" | "application/csv" => ".csv",
            _ if c.starts_with("image/") => match c.strip_prefix("image/").unwrap_or("") {
                "jpeg" => ".jpg",
                other if !other.is_empty() => {
                    // ".png", ".webp", … — leak-free: only [a-z0-9] survive.
                    return format!(
                        "{}.{}",
                        truncate(&name, 150),
                        other.chars().filter(|ch| ch.is_ascii_alphanumeric()).collect::<String>()
                    );
                }
                _ => "",
            },
            _ => "",
        };
        name.push_str(ext);
    }
    truncate(&name, 160)
}

fn truncate(s: &str, max: usize) -> String {
    s.chars().take(max).collect()
}

/// Minimal %XX decoder (no external dep): invalid escapes pass through verbatim.
fn percent_decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out: Vec<u8> = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            if let Ok(v) = u8::from_str_radix(&s[i + 1..i + 3], 16) {
                out.push(v);
                i += 3;
                continue;
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// Store one document's bytes; returns the page-row file stamp
/// `{file_id, filename, size, content_type, version}` or `None`. Never fails the
/// page — every error is logged at info and swallowed.
pub async fn capture_document(
    artifact: &ArtifactContext,
    source_url: &str,
    bytes: &[u8],
    content_type: &str,
) -> Option<Value> {
    if bytes.is_empty() {
        return None;
    }
    match try_capture(artifact, source_url, bytes, content_type).await {
        Ok(v) => v,
        Err(e) => {
            tracing::info!(url = %source_url, error = %e, "crawl doc capture failed");
            None
        }
    }
}

async fn try_capture(
    artifact: &ArtifactContext,
    source_url: &str,
    bytes: &[u8],
    content_type: &str,
) -> anyhow::Result<Option<Value>> {
    let ct = {
        let c = content_type.split(';').next().unwrap_or("").trim();
        if c.is_empty() { "application/octet-stream" } else { c }.to_string()
    };
    let filename = doc_filename(source_url, &ct);
    let md5 = {
        use md5::{Digest, Md5};
        let mut h = Md5::new();
        h.update(bytes);
        format!("{:x}", h.finalize())
    };
    let sha256 = {
        use sha2::{Digest, Sha256};
        let mut h = Sha256::new();
        h.update(bytes);
        format!("{:x}", h.finalize())
    };

    let base = artifact.base_url.trim_end_matches('/');
    let client = reqwest::Client::new();
    let init: Value = {
        let resp = client
            .post(format!("{}/automation/tasks/{}/artifact-init", base, artifact.task_id))
            .header("Authorization", format!("Bearer {}", artifact.token))
            .json(&json!({
                "filename": filename,
                "content_type": ct,
                "agent_id": artifact.agent_id,
                "source_url": source_url,
                "md5": md5,
                "sha256": sha256,
                "size": bytes.len(),
            }))
            .timeout(Duration::from_secs(60))
            .send()
            .await?;
        let status = resp.status();
        if !status.is_success() {
            let txt = resp.text().await.unwrap_or_default();
            anyhow::bail!("artifact-init HTTP {}: {}", status, truncate(&txt, 200));
        }
        resp.json().await?
    };

    // Unchanged document — the backend linked the existing file to this crawl.
    if init.get("dedup").and_then(|v| v.as_bool()).unwrap_or(false) {
        return Ok(Some(json!({
            "file_id": init.get("file_id"),
            "filename": init.get("filename").and_then(|v| v.as_str()).unwrap_or(&filename),
            "size": init.get("size").and_then(|v| v.as_u64()).unwrap_or(bytes.len() as u64),
            "content_type": init.get("content_type").and_then(|v| v.as_str()).unwrap_or(&ct),
            "version": init.get("version").and_then(|v| v.as_u64()).unwrap_or(1),
        })));
    }

    let file_id = init
        .get("file_id")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string())
        .ok_or_else(|| anyhow::anyhow!("artifact-init returned no file_id"))?;
    let upload = init
        .get("upload")
        .cloned()
        .ok_or_else(|| anyhow::anyhow!("artifact-init returned no upload target"))?;
    upload_bytes(&client, &upload, bytes, &filename, &ct).await?;

    let fin: Value = {
        let resp = client
            .post(format!("{}/automation/tasks/{}/artifact-finalize", base, artifact.task_id))
            .header("Authorization", format!("Bearer {}", artifact.token))
            .json(&json!({
                "file_id": file_id,
                "sha256": sha256,
                "agent_id": artifact.agent_id,
            }))
            .timeout(Duration::from_secs(60))
            .send()
            .await?;
        let status = resp.status();
        if !status.is_success() {
            let txt = resp.text().await.unwrap_or_default();
            anyhow::bail!("artifact-finalize HTTP {}: {}", status, truncate(&txt, 200));
        }
        resp.json().await?
    };
    Ok(Some(json!({
        "file_id": file_id,
        "filename": fin.get("filename").and_then(|v| v.as_str()).unwrap_or(&filename),
        "size": fin.get("size").and_then(|v| v.as_u64()).unwrap_or(bytes.len() as u64),
        "content_type": fin.get("content_type").and_then(|v| v.as_str()).unwrap_or(&ct),
        "version": fin.get("version").and_then(|v| v.as_u64()).unwrap_or(1),
    })))
}

/// Upload bytes DIRECT to object storage via a presigned POST policy or plain
/// PUT — no backend auth; the presigned URL/fields ARE the credential. In-memory
/// twin of `step_download::upload_to_presigned` (which takes a temp file).
async fn upload_bytes(
    client: &reqwest::Client,
    upload: &Value,
    bytes: &[u8],
    filename: &str,
    content_type: &str,
) -> anyhow::Result<()> {
    let method = upload
        .get("method")
        .and_then(|v| v.as_str())
        .unwrap_or("POST")
        .to_uppercase();
    let url = upload
        .get("url")
        .and_then(|v| v.as_str())
        .ok_or_else(|| anyhow::anyhow!("presigned upload has no url"))?;

    let resp = if method == "POST" {
        // Presigned POST: policy fields first, the file part LAST (S3/MinIO
        // require the file field after the policy fields).
        let mut form = reqwest::multipart::Form::new();
        if let Some(fields) = upload.get("fields").and_then(|v| v.as_object()) {
            for (k, v) in fields {
                if let Some(s) = v.as_str() {
                    form = form.text(k.clone(), s.to_string());
                }
            }
        }
        let part = reqwest::multipart::Part::bytes(bytes.to_vec())
            .file_name(filename.to_string())
            .mime_str(content_type)
            .unwrap_or_else(|_| {
                reqwest::multipart::Part::bytes(bytes.to_vec()).file_name(filename.to_string())
            });
        form = form.part("file", part);
        client
            .post(url)
            .multipart(form)
            .timeout(Duration::from_secs(120))
            .send()
            .await?
    } else {
        client
            .put(url)
            .header("Content-Type", content_type)
            .body(bytes.to_vec())
            .timeout(Duration::from_secs(120))
            .send()
            .await?
    };
    let status = resp.status();
    if !status.is_success() {
        let txt = resp.text().await.unwrap_or_default();
        anyhow::bail!("storage upload HTTP {}: {}", status, truncate(&txt, 200));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn capturable_matches_document_set_and_excludes_json() {
        assert!(is_capturable("application/pdf", "https://x/a.pdf"));
        assert!(is_capturable(
            "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
            "https://x/a"
        ));
        assert!(is_capturable("image/png", "https://x/logo"));
        assert!(is_capturable("text/csv", "https://x/export"));
        assert!(is_capturable("application/octet-stream", "https://x/report.pdf?dl=1"));
        assert!(!is_capturable("application/json", "https://x/api/data.json"));
        assert!(!is_capturable("application/octet-stream", "https://x/api/data.json"));
        assert!(!is_capturable("text/html", "https://x/page"));
    }

    #[test]
    fn filenames_decode_and_gain_extensions() {
        assert_eq!(
            doc_filename("https://x/reports/Q3%20results.pdf", "application/pdf"),
            "Q3 results.pdf"
        );
        assert_eq!(doc_filename("https://x/dl/4821", "application/pdf"), "4821.pdf");
        assert_eq!(doc_filename("https://x/img/shot", "image/jpeg"), "shot.jpg");
        assert_eq!(doc_filename("https://x/", "application/pdf"), "document.pdf");
    }
}
