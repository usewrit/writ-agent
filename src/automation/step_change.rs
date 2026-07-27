//! `wait_for_change` step — surveils a selector or a screen region for any change
//! and returns the change like an `extract` step (merged into `extracted_data`).
//!
//! Two baseline modes (chosen via `options.baseline_mode`):
//!   * `in_run`        — capture a baseline at step entry, poll until it differs or times out.
//!   * `since_last_run` — compare the current value against a baseline hash supplied by the
//!                        backend (the check target's stored `baseline_hash`); if it already
//!                        differs, report immediately, otherwise poll like `in_run`.
//!
//! Detection kinds (`options.change_kind`): `text` | `html` | `attribute` | `visual`.
//!   * text/html/attribute hash the (optionally `ignore_regex`-filtered) string content.
//!   * visual hashes a clipped JPEG of the selector's bounding box or an explicit region.
//!
//! CONCURRENCY: this runs on the workflow-execution path which owns a plain `&Page`
//! (no DashMap session lock), so the polling loop is safe — it cannot starve tokio
//! workers the way a recorder-action handler holding a `RefMut` across `.await` would.

use std::collections::HashMap;
use std::time::{Duration, Instant};

use playwright_rs::Page;
use sha2::{Digest, Sha256};

use crate::browser::{page_actions, page_query};
use crate::models::workflow::WorkflowStepConfig;

use super::step_executor::{StepError, StepResult};

/// Hard cap so a misconfigured never-changing watch can't hang a whole run forever.
const MAX_WATCH_MS: u64 = 5 * 60 * 1000;
const DEFAULT_POLL_MS: u64 = 1000;
const MIN_POLL_MS: u64 = 200;

fn sha256_hex(data: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hasher
        .finalize()
        .iter()
        .map(|b| format!("{:02x}", b))
        .collect()
}

/// Read a config value from `options` first, then the flattened `extra` map.
fn cfg<'a>(config: &'a WorkflowStepConfig, key: &str) -> Option<&'a serde_json::Value> {
    config
        .options
        .as_ref()
        .and_then(|o| o.get(key))
        .or_else(|| config.extra.get(key))
}

fn cfg_str(config: &WorkflowStepConfig, key: &str) -> Option<String> {
    cfg(config, key)
        .and_then(|v| v.as_str())
        .map(|s| s.to_string())
}

fn cfg_u64(config: &WorkflowStepConfig, key: &str) -> Option<u64> {
    cfg(config, key).and_then(|v| {
        v.as_u64()
            .or_else(|| v.as_f64().map(|f| f as u64))
            .or_else(|| v.as_str().and_then(|s| s.parse::<u64>().ok()))
    })
}

/// A single observation: the value to surface downstream + a hash to compare against.
struct Snapshot {
    /// Value placed into `extracted_data` under `output_name` (string for text/html/attribute,
    /// `null` for visual since raw pixels are not useful downstream).
    value: serde_json::Value,
    hash: String,
}

/// Apply an optional `ignore_regex` (lines matching are dropped) before hashing,
/// mirroring the agent.js content-hash normalization.
fn normalize(raw: &str, ignore_regex: Option<&regex::Regex>) -> String {
    match ignore_regex {
        Some(re) => raw
            .lines()
            .filter(|line| !re.is_match(line))
            .collect::<Vec<_>>()
            .join("\n"),
        None => raw.to_string(),
    }
}

async fn capture(
    page: &Page,
    watch_kind: &str,
    change_kind: &str,
    selector: Option<&str>,
    region: Option<(f64, f64, f64, f64)>,
    attribute: Option<&str>,
    ignore_regex: Option<&regex::Regex>,
) -> Result<Snapshot, StepError> {
    // Region watch is always visual.
    if watch_kind == "region" || change_kind == "visual" {
        let (x, y, w, h) = if let Some(r) = region {
            r
        } else if let Some(sel) = selector {
            page_actions::bounding_box(page, sel)
                .await
                .map_err(|e| StepError::Execution(format!("wait_for_change bounding_box: {}", e)))?
                .ok_or_else(|| {
                    StepError::ElementNotFound(format!(
                        "wait_for_change: selector '{}' has no bounding box",
                        sel
                    ))
                })?
        } else {
            return Err(StepError::Execution(
                "wait_for_change: visual/region watch needs a region or selector".into(),
            ));
        };

        if w <= 0.0 || h <= 0.0 {
            return Err(StepError::Execution(
                "wait_for_change: region has zero area".into(),
            ));
        }

        let bytes = page_query::screenshot_jpeg_clip(page, x, y, w, h, 70)
            .await
            .map_err(|e| StepError::Execution(format!("wait_for_change screenshot: {}", e)))?;
        return Ok(Snapshot {
            value: serde_json::Value::Null,
            hash: sha256_hex(&bytes),
        });
    }

    // Selector-based content watch.
    let sel = selector.ok_or_else(|| {
        StepError::Execution("wait_for_change: selector watch needs a selector".into())
    })?;

    let raw: Option<String> = match change_kind {
        "html" => {
            let js = format!(
                "(() => {{ const el = document.querySelector({}); return el ? el.innerHTML : null; }})()",
                serde_json::to_string(sel).unwrap_or_default()
            );
            page_query::evaluate::<Option<String>>(page, &js)
                .await
                .map_err(|e| StepError::Execution(format!("wait_for_change html eval: {}", e)))?
        }
        "attribute" => {
            let attr = attribute.unwrap_or("value");
            let js = format!(
                "(() => {{ const el = document.querySelector({}); return el ? el.getAttribute({}) : null; }})()",
                serde_json::to_string(sel).unwrap_or_default(),
                serde_json::to_string(attr).unwrap_or_default()
            );
            page_query::evaluate::<Option<String>>(page, &js)
                .await
                .map_err(|e| StepError::Execution(format!("wait_for_change attr eval: {}", e)))?
        }
        // default: text
        _ => page_query::locator_text_content(page, sel)
            .await
            .map_err(|e| StepError::ElementNotFound(format!("wait_for_change text '{}': {}", sel, e)))?,
    };

    let text = raw.unwrap_or_default();
    let normalized = normalize(&text, ignore_regex);
    Ok(Snapshot {
        value: serde_json::Value::String(text),
        hash: sha256_hex(normalized.as_bytes()),
    })
}

pub async fn execute_wait_for_change(
    page: &Page,
    config: &WorkflowStepConfig,
    timeout_ms: u64,
) -> StepResult {
    let watch_kind = cfg_str(config, "watch_kind").unwrap_or_else(|| "selector".into());
    let change_kind = cfg_str(config, "change_kind").unwrap_or_else(|| {
        if watch_kind == "region" {
            "visual".into()
        } else {
            "text".into()
        }
    });
    let output_name = cfg_str(config, "output_name")
        .or_else(|| cfg_str(config, "variable"))
        .unwrap_or_else(|| "change".into());
    let baseline_mode = cfg_str(config, "baseline_mode").unwrap_or_else(|| "in_run".into());
    let attribute = cfg_str(config, "attribute");
    let on_no_change = cfg_str(config, "on_no_change").unwrap_or_else(|| {
        // A live check (since_last_run) shouldn't fail just because nothing changed yet;
        // an explicit in-run wait usually should.
        if baseline_mode == "since_last_run" {
            "continue".into()
        } else {
            "fail".into()
        }
    });

    let poll_interval = cfg_u64(config, "poll_interval_ms")
        .unwrap_or(DEFAULT_POLL_MS)
        .clamp(MIN_POLL_MS, 60_000);
    let watch_timeout = cfg_u64(config, "timeout_ms")
        .unwrap_or(timeout_ms)
        .min(MAX_WATCH_MS);

    let selector = config.selector.clone();
    let region = cfg(config, "region").and_then(|r| {
        let x = r.get("x")?.as_f64()?;
        let y = r.get("y")?.as_f64()?;
        let width = r.get("width").or_else(|| r.get("w"))?.as_f64()?;
        let height = r.get("height").or_else(|| r.get("h"))?.as_f64()?;
        Some((x, y, width, height))
    });

    let ignore_regex = cfg_str(config, "ignore_regex").and_then(|p| regex::Regex::new(&p).ok());

    tracing::debug!(
        watch_kind, change_kind, %output_name, baseline_mode,
        poll_interval, watch_timeout, "Executing wait_for_change step"
    );

    // Initial observation.
    let initial = capture(
        page,
        &watch_kind,
        &change_kind,
        selector.as_deref(),
        region,
        attribute.as_deref(),
        ignore_regex.as_ref(),
    )
    .await?;

    // Baseline: a supplied prior-run hash (since_last_run) or this run's first reading (in_run).
    let supplied_baseline = if baseline_mode == "since_last_run" {
        cfg_str(config, "baseline_hash").filter(|s| !s.is_empty())
    } else {
        None
    };
    let baseline_hash = supplied_baseline
        .clone()
        .unwrap_or_else(|| initial.hash.clone());

    let build_changed = |snap: Snapshot| -> Option<HashMap<String, serde_json::Value>> {
        let mut m = HashMap::new();
        m.insert(output_name.clone(), snap.value);
        m.insert(format!("{}_changed", output_name), serde_json::json!(true));
        m.insert(
            format!("{}_hash", output_name),
            serde_json::json!(snap.hash),
        );
        m.insert(
            format!("{}_previous_hash", output_name),
            serde_json::json!(baseline_hash.clone()),
        );
        Some(m)
    };

    // since_last_run: if the current reading already differs from the stored baseline, report now.
    if supplied_baseline.is_some() && initial.hash != baseline_hash {
        let mut m = build_changed(Snapshot {
            value: initial.value,
            hash: initial.hash,
        })
        .unwrap();
        m.insert(
            format!("{}_previous", output_name),
            serde_json::Value::Null,
        );
        return Ok(Some(m));
    }

    // Poll until the value diverges from the baseline or we time out.
    let deadline = Instant::now() + Duration::from_millis(watch_timeout);
    loop {
        if Instant::now() >= deadline {
            break;
        }
        let remaining = deadline.saturating_duration_since(Instant::now());
        tokio::time::sleep(remaining.min(Duration::from_millis(poll_interval))).await;

        let current = capture(
            page,
            &watch_kind,
            &change_kind,
            selector.as_deref(),
            region,
            attribute.as_deref(),
            ignore_regex.as_ref(),
        )
        .await?;
        if current.hash != baseline_hash {
            let prev_value = initial.value.clone();
            let mut m = build_changed(current).unwrap();
            m.insert(format!("{}_previous", output_name), prev_value);
            return Ok(Some(m));
        }
    }

    // No change observed within the window.
    if on_no_change == "fail" {
        return Err(StepError::Timeout(format!(
            "wait_for_change: no change in {}ms (watch_kind={}, change_kind={})",
            watch_timeout, watch_kind, change_kind
        )));
    }

    let mut m = HashMap::new();
    m.insert(output_name.clone(), initial.value);
    m.insert(format!("{}_changed", output_name), serde_json::json!(false));
    m.insert(
        format!("{}_hash", output_name),
        serde_json::json!(baseline_hash),
    );
    Ok(Some(m))
}
