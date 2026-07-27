//! File assets — `wait_for_download` replay step (§6.3).
//!
//! Captures a file the page downloads and persists it DIRECT to object storage.
//! Wraps `page.expect_download` around the triggering action (mirrors how
//! `wait_for_tab` waits for a previously-triggered tab): if `config.trigger_selector`
//! is set the click happens inside the wait; otherwise it awaits a download initiated
//! by the immediately-preceding step.
//!
//! SECURITY (§4.4/§10.8): the captured bytes upload DIRECT to object storage via a
//! backend-minted, scoped, size-capped presigned upload — they NEVER stream through
//! the backend. The two small JSON calls (artifact-init/finalize) reuse the agent's
//! backend Bearer + executor binding (agent_id); the bulk upload uses a plain HTTP
//! client straight to storage. The captured temp file is always deleted.

use playwright_rs::Page;

use crate::models::workflow::WorkflowStepConfig;
use super::files::{ArtifactContext, OutputFile, RunFiles};
use super::step_executor::{StepError, StepResult};

pub async fn execute_wait_for_download(
    page: &Page,
    config: &WorkflowStepConfig,
    run_files: &RunFiles,
    timeout_ms: u64,
) -> StepResult {
    let trigger_selector = config
        .trigger_selector
        .as_deref()
        .or_else(|| config.options.as_ref().and_then(|o| o.get("trigger_selector")).and_then(|v| v.as_str()))
        .map(|s| s.to_string())
        .filter(|s| !s.is_empty());

    let output_key = config
        .output_key
        .as_deref()
        .or_else(|| config.options.as_ref().and_then(|o| o.get("output_key")).and_then(|v| v.as_str()))
        .map(|s| s.to_string());

    // Arm the download waiter BEFORE the trigger (crate requirement). Timeout in ms.
    let waiter = page
        .expect_download(Some(timeout_ms as f64))
        .await
        .map_err(|e| StepError::Execution(format!("wait_for_download: arm waiter failed: {}", e)))?;

    if let Some(sel) = &trigger_selector {
        let locator = page.locator(sel).await;
        locator
            .first()
            .click(None)
            .await
            .map_err(|e| StepError::Execution(format!("wait_for_download: trigger click failed: {}", e)))?;
    }
    // else: rely on the immediately-preceding step having triggered the download.

    let download = waiter
        .wait()
        .await
        .map_err(|e| StepError::Timeout(format!("wait_for_download: no download captured: {}", e)))?;

    let suggested = download.suggested_filename().to_string();
    let suffix = super::files::filename_suffix(Some(&suggested));
    let tmp_path = super::files::unique_temp_path("psdl_", &suffix);

    // Save the download to the temp path; ensure cleanup on every exit path.
    let save_res = download.save_as(&tmp_path).await;
    if let Err(e) = save_res {
        let _ = std::fs::remove_file(&tmp_path);
        return Err(StepError::Execution(format!("wait_for_download: save_as failed: {}", e)));
    }

    let artifact = match run_files.artifact() {
        Some(a) => a.clone(),
        None => {
            // No capture context wired → fail closed (don't silently drop the file).
            let _ = std::fs::remove_file(&tmp_path);
            return Err(StepError::Execution(
                "wait_for_download: no artifact callback context wired — cannot persist the captured download".into(),
            ));
        }
    };

    let filename = if suggested.is_empty() {
        tmp_path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("download")
            .to_string()
    } else {
        suggested.clone()
    };

    let persist = persist_captured_download(&artifact, &tmp_path, &filename, output_key.as_deref()).await;
    // Temp-file hygiene (§10.5): always delete the captured temp file.
    let _ = std::fs::remove_file(&tmp_path);

    let handle = persist.map_err(|e| StepError::Execution(format!("wait_for_download: {}", e)))?;

    let file_id = handle.file_id.clone();
    let out_key = handle.output_key.clone();
    run_files.push_output_file(handle);

    // Surface the captured file id for downstream chaining via the {{output_key}}
    // variable (extracted_data), mirroring the Python agent.
    if let (Some(k), false) = (out_key, file_id.is_empty()) {
        let mut m = std::collections::HashMap::new();
        m.insert(k, serde_json::json!(file_id));
        return Ok(Some(m));
    }
    Ok(None)
}

/// Run the two-step DIRECT-TO-STORAGE capture for a saved temp file (§4.4):
/// artifact-init (backend) → presigned upload (DIRECT to storage) → artifact-finalize.
async fn persist_captured_download(
    artifact: &ArtifactContext,
    tmp_path: &std::path::Path,
    filename: &str,
    output_key: Option<&str>,
) -> anyhow::Result<OutputFile> {
    // Content-type from the filename (storage re-derives the REAL type at finalize).
    let content_type = guess_content_type(filename);

    // sha256 of the saved file (best-effort integrity hint; backend HEAD is the size
    // source of truth).
    let sha256 = sha256_of_file(tmp_path).ok();

    // 1) artifact-init — backend mints the file id + scoped presigned upload.
    let init_body = serde_json::json!({
        "filename": filename,
        "content_type": content_type,
        "output_key": output_key,
        "agent_id": artifact.agent_id,
    });
    let init = artifact_post(artifact, "artifact-init", &init_body).await?;
    let file_id = init
        .get("file_id")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string())
        .ok_or_else(|| anyhow::anyhow!("artifact-init returned no file_id: {}", init))?;
    let upload = init
        .get("upload")
        .cloned()
        .ok_or_else(|| anyhow::anyhow!("artifact-init returned no upload target: {}", init))?;

    // 2) Upload the bytes DIRECT to object storage (never through the backend).
    upload_to_presigned(&upload, tmp_path, &content_type).await?;

    // 3) artifact-finalize — backend HEADs the object (real size/type), validates
    //    quota, marks ready. Returns the finalized handle.
    let fin_body = serde_json::json!({
        "file_id": file_id,
        "sha256": sha256,
        "agent_id": artifact.agent_id,
    });
    let fin = artifact_post(artifact, "artifact-finalize", &fin_body).await?;
    let fin_file_id = fin
        .get("file_id")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string())
        .ok_or_else(|| anyhow::anyhow!("artifact-finalize failed: {}", fin))?;

    let out = OutputFile {
        file_id: fin_file_id,
        filename: fin
            .get("filename")
            .and_then(|v| v.as_str())
            .unwrap_or(filename)
            .to_string(),
        size: fin.get("size").and_then(|v| v.as_u64()).unwrap_or(0),
        content_type: fin
            .get("content_type")
            .and_then(|v| v.as_str())
            .unwrap_or(&content_type)
            .to_string(),
        output_key: fin
            .get("output_key")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string())
            .or_else(|| output_key.map(|s| s.to_string())),
    };
    tracing::info!(file_id = %out.file_id, size = out.size, "Captured download persisted");
    Ok(out)
}

/// POST a small JSON body to a backend artifact endpoint for `task_id`, authenticated
/// with the agent's Bearer token (same auth as `/tasks/{id}/complete`).
async fn artifact_post(
    artifact: &ArtifactContext,
    endpoint: &str,
    body: &serde_json::Value,
) -> anyhow::Result<serde_json::Value> {
    let base = artifact.base_url.trim_end_matches('/');
    let url = format!("{}/automation/tasks/{}/{}", base, artifact.task_id, endpoint);
    let client = reqwest::Client::new();
    let resp = client
        .post(&url)
        .header("Authorization", format!("Bearer {}", artifact.token))
        .json(body)
        .timeout(std::time::Duration::from_secs(60))
        .send()
        .await
        .map_err(|e| anyhow::anyhow!("{} request failed: {}", endpoint, e))?;
    let status = resp.status();
    if !status.is_success() {
        let txt = resp.text().await.unwrap_or_default();
        anyhow::bail!("{} failed: HTTP {} {}", endpoint, status, truncate(&txt, 200));
    }
    let val: serde_json::Value = resp
        .json()
        .await
        .map_err(|e| anyhow::anyhow!("{} response parse failed: {}", endpoint, e))?;
    Ok(val)
}

/// Upload a file DIRECT to object storage via a presigned POST or PUT. A plain HTTP
/// client (no backend auth) is used — the presigned URL/fields ARE the credential,
/// scoped to the single object key with a storage-enforced size cap (§4.4/§10.3).
async fn upload_to_presigned(
    upload: &serde_json::Value,
    tmp_path: &std::path::Path,
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

    let client = reqwest::Client::new();
    let bytes = tokio::fs::read(tmp_path)
        .await
        .map_err(|e| anyhow::anyhow!("read temp file for upload failed: {}", e))?;

    if method == "POST" {
        // Presigned POST: the policy fields go first, the file part LAST (S3/MinIO
        // require the file field after the policy fields).
        let mut form = reqwest::multipart::Form::new();
        let mut key_field: Option<String> = None;
        if let Some(fields) = upload.get("fields").and_then(|v| v.as_object()) {
            for (k, v) in fields {
                if let Some(s) = v.as_str() {
                    if k == "key" {
                        key_field = Some(s.to_string());
                    }
                    form = form.text(k.clone(), s.to_string());
                }
            }
        }
        let file_name = key_field.unwrap_or_else(|| {
            tmp_path
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or("file")
                .to_string()
        });
        let part = reqwest::multipart::Part::bytes(bytes)
            .file_name(file_name)
            .mime_str(content_type)
            .unwrap_or_else(|_| reqwest::multipart::Part::bytes(Vec::new()).file_name("file"));
        form = form.part("file", part);
        let resp = client
            .post(url)
            .multipart(form)
            .timeout(std::time::Duration::from_secs(300))
            .send()
            .await
            .map_err(|e| anyhow::anyhow!("presigned POST upload failed: {}", e))?;
        if !matches!(resp.status().as_u16(), 200 | 201 | 204) {
            let st = resp.status();
            let txt = resp.text().await.unwrap_or_default();
            anyhow::bail!("presigned POST upload failed: {} {}", st, truncate(&txt, 200));
        }
    } else {
        // Presigned PUT: raw body. Storage size cap is re-validated at finalize.
        let resp = client
            .put(url)
            .header("Content-Type", content_type)
            .body(bytes)
            .timeout(std::time::Duration::from_secs(300))
            .send()
            .await
            .map_err(|e| anyhow::anyhow!("presigned PUT upload failed: {}", e))?;
        if !matches!(resp.status().as_u16(), 200 | 201 | 204) {
            let st = resp.status();
            let txt = resp.text().await.unwrap_or_default();
            anyhow::bail!("presigned PUT upload failed: {} {}", st, truncate(&txt, 200));
        }
    }
    Ok(())
}

fn sha256_of_file(path: &std::path::Path) -> anyhow::Result<String> {
    use sha2::{Digest, Sha256};
    let mut file = std::fs::File::open(path)?;
    let mut hasher = Sha256::new();
    std::io::copy(&mut file, &mut hasher)?;
    Ok(format!("{:x}", hasher.finalize()))
}

/// Minimal content-type guess from a filename extension. The backend re-derives the
/// REAL content-type from the stored object HEAD at finalize, so this is only a hint.
fn guess_content_type(filename: &str) -> String {
    let lower = filename.to_lowercase();
    let ext = lower.rsplit('.').next().unwrap_or("");
    let ct = match ext {
        "pdf" => "application/pdf",
        "png" => "image/png",
        "jpg" | "jpeg" => "image/jpeg",
        "gif" => "image/gif",
        "webp" => "image/webp",
        "svg" => "image/svg+xml",
        "csv" => "text/csv",
        "txt" => "text/plain",
        "json" => "application/json",
        "xml" => "application/xml",
        "html" | "htm" => "text/html",
        "zip" => "application/zip",
        "gz" => "application/gzip",
        "doc" => "application/msword",
        "docx" => "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
        "xls" => "application/vnd.ms-excel",
        "xlsx" => "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        "ppt" => "application/vnd.ms-powerpoint",
        "pptx" => "application/vnd.openxmlformats-officedocument.presentationml.presentation",
        _ => "application/octet-stream",
    };
    ct.to_string()
}

fn truncate(s: &str, max: usize) -> String {
    if s.len() <= max {
        s.to_string()
    } else {
        s.chars().take(max).collect()
    }
}
