//! File assets — `upload` replay step (§6.3).
//!
//! Resolves the run-level file(s) the step targets (by `config.file_id` for own runs
//! or `config.file_slot` for a buyer-bound marketplace recipe), fetches the signed
//! bytes to a temp path, and sets them on the page's file input — either directly on
//! an `<input type=file>` (`mode="input"`) or by intercepting the chooser around a
//! trigger click (`mode="chooser"`).

use playwright_rs::Page;

use crate::browser::page_actions;
use crate::models::workflow::WorkflowStepConfig;
use super::files::RunFiles;
use super::step_executor::{StepError, StepResult};

pub async fn execute_upload(
    page: &Page,
    config: &WorkflowStepConfig,
    run_files: &RunFiles,
    timeout_ms: u64,
    step_id: Option<&str>,
) -> StepResult {
    let selector = config
        .selector
        .as_deref()
        .or_else(|| config.options.as_ref().and_then(|o| o.get("selector")).and_then(|v| v.as_str()))
        .unwrap_or("")
        .to_string();
    if selector.is_empty() {
        return Err(StepError::Execution(
            "upload step: no selector for the file input / trigger".into(),
        ));
    }

    // mode: input (selector IS an <input type=file>) | chooser (selector is a trigger).
    let mode = config
        .mode
        .as_deref()
        .or_else(|| config.options.as_ref().and_then(|o| o.get("mode")).and_then(|v| v.as_str()))
        .unwrap_or("input")
        .to_string();

    let is_multiple = config
        .is_multiple
        .or_else(|| config.options.as_ref().and_then(|o| o.get("is_multiple")).and_then(|v| v.as_bool()))
        .unwrap_or(false);

    // The slot this step's file is bound under for THIS run. A recorded step usually
    // declares none — it just pins a file — so it is addressed by its own step id, the
    // same `step:<id>` key the run form, REST and MCP bind an override to. An ordinal
    // would break the moment a step is reordered or disabled.
    let slot = config
        .file_slot
        .clone()
        .or_else(|| {
            config
                .options
                .as_ref()
                .and_then(|o| o.get("file_slot"))
                .and_then(|v| v.as_str())
                .map(str::to_string)
        })
        .filter(|s| !s.is_empty())
        .or_else(|| step_id.filter(|s| !s.is_empty()).map(|s| format!("step:{}", s)));

    // The file pinned on the step, from either shape: `config` when the editor wrote it,
    // `options` when the recorder did. Used when this run bound nothing to the slot.
    let pinned = config
        .file_id
        .clone()
        .or_else(|| {
            config
                .options
                .as_ref()
                .and_then(|o| o.get("file_id"))
                .and_then(|v| v.as_str())
                .map(str::to_string)
        })
        .filter(|s| !s.is_empty());

    // Resolve the file descriptor(s): this run's binding first, then the pinned file.
    let descs = run_files.resolve_step_files(pinned.as_deref(), slot.as_deref());
    if descs.is_empty() {
        return Err(StepError::Execution(
            "upload step: no file resolved — pin a file on the step or bind its slot in the run files map".into(),
        ));
    }

    // Fetch each resolved file to a local temp path (cached per id; cleaned at run end).
    let mut paths: Vec<String> = Vec::new();
    for desc in &descs {
        match run_files.fetch_to_temp(desc).await {
            Ok(p) => paths.push(p.to_string_lossy().to_string()),
            Err(e) => {
                return Err(StepError::Execution(format!(
                    "upload step: failed to fetch file bytes from storage: {}",
                    e
                )));
            }
        }
    }
    if paths.is_empty() {
        return Err(StepError::Execution(
            "upload step: failed to fetch the file bytes from storage".into(),
        ));
    }
    if !is_multiple {
        paths.truncate(1);
    }

    if mode == "chooser" {
        // Intercept the file chooser around the trigger click. The waiter MUST be
        // armed before the click (crate requirement). expect_file_chooser timeout is
        // in milliseconds.
        let waiter = page
            .expect_file_chooser(Some(timeout_ms as f64))
            .await
            .map_err(|e| StepError::Execution(format!("upload (chooser): arm chooser failed: {}", e)))?;
        let locator = page.locator(&selector).await;
        locator
            .first()
            .click(None)
            .await
            .map_err(|e| StepError::Execution(format!("upload (chooser): trigger click failed: {}", e)))?;
        let chooser = waiter
            .wait()
            .await
            .map_err(|e| StepError::Timeout(format!("upload (chooser): no file chooser opened: {}", e)))?;
        let path_bufs: Vec<std::path::PathBuf> =
            paths.iter().map(std::path::PathBuf::from).collect();
        chooser
            .set_files(&path_bufs)
            .await
            .map_err(|e| StepError::Execution(format!("upload (chooser): set_files failed: {}", e)))?;
    } else {
        // input mode: the selector IS the <input type=file>.
        page_actions::set_input_files(page, &selector, paths.clone())
            .await
            .map_err(|e| StepError::Execution(format!("upload (input): set_input_files failed: {}", e)))?;
    }

    tracing::info!(selector = %selector, mode = %mode, count = paths.len(), "Uploaded file(s)");
    // Temp files are cleaned up centrally at run end (RunFiles::cleanup_temps) so a
    // file shared with {{file:slot}} / another upload step is fetched once.
    Ok(None)
}
