//! Autonomous-session page OBSERVATION builder — the Rust port of the Python recorder's
//! `_ai_analyze_page` observation half (`recorder.py` ~L7326-7400). Bundles everything the
//! form-filler vision model needs to decide the next action into a single `serde_json::Value`:
//!
//! * `screenshot` — a JPEG (base64) of the current viewport, so the model can SEE the form.
//! * `fields`     — detected form fields WITH viewport coordinates + selector + required flag.
//! * `buttons`    — detected clickable buttons WITH coordinates + selector, indexed by position.
//! * `page_text`  — visible page text (capped) via the DOM analyzer.
//! * `errors`     — aria-invalid / validation errors surfaced by the page.
//! * `a11y`       — accessibility-tree elements + viewport (coordinate frame).
//! * `viewport`   — width/height of the current viewport.
//! * `current_url`, `has_success`, `captcha_info` — completion + captcha signals.
//!
//! It REUSES the already-ported building blocks: the `dom_fields_with_coords.js` /
//! `a11y_tree.js` extractors (`crate::ai::action_executor`), the DOM analyzer's page-context
//! probe, and the Playwright screenshot API — exactly like `saas_bridge::build_agent_observation`,
//! but shaped for the simpler form-filler schema instead of the agent brain.

use playwright_rs::Page;
use serde_json::{json, Value};

use crate::ai::action_executor::{A11Y_TREE_JS, DOM_FIELDS_WITH_COORDS_JS};
use crate::dom::analyzer::PageEvaluator;

/// A [`PageEvaluator`] adapter over a live Playwright page, so the DOM analyzer probes can run.
/// Mirrors the private adapter in `saas_bridge`.
struct SessionPageEvaluator<'a>(&'a Page);

impl<'a> PageEvaluator for SessionPageEvaluator<'a> {
    fn evaluate_json(
        &self,
        js: &str,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = anyhow::Result<Value>> + Send + '_>> {
        let js = js.to_string();
        Box::pin(async move {
            let result: Value = self
                .0
                .evaluate(&js, None::<&()>)
                .await
                .map_err(|e| anyhow::anyhow!("evaluate_json failed: {}", e))?;
            Ok(result)
        })
    }

    fn evaluate_json_with_args(
        &self,
        js: &str,
        args: &[Value],
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = anyhow::Result<Value>> + Send + '_>> {
        let js = js.to_string();
        let args = Value::Array(args.to_vec());
        Box::pin(async move {
            let result: Value = self
                .0
                .evaluate(&js, Some(&args))
                .await
                .map_err(|e| anyhow::anyhow!("evaluate_json_with_args failed: {}", e))?;
            Ok(result)
        })
    }
}

/// Capture a JPEG screenshot of the current viewport as RAW bytes at `quality` (0-100).
/// Best-effort: returns `None` on failure. Shared by the base64 helper, the live screencast
/// (`super::live_preview`), and the replay-keyframe capture.
pub async fn capture_screenshot_jpeg(page: &Page, quality: u8) -> Option<Vec<u8>> {
    let opts = playwright_rs::ScreenshotOptions {
        screenshot_type: Some(playwright_rs::ScreenshotType::Jpeg),
        quality: Some(quality),
        ..Default::default()
    };
    match page.screenshot(Some(opts)).await {
        Ok(bytes) => Some(bytes),
        Err(e) => {
            tracing::debug!(error = %e, "capture_screenshot_jpeg failed");
            None
        }
    }
}

/// Capture a JPEG screenshot of the current viewport and return it base64-encoded.
/// Best-effort: returns an empty string on failure so the loop still gets an observation.
pub async fn capture_screenshot_b64(page: &Page) -> String {
    match capture_screenshot_jpeg(page, 70).await {
        Some(bytes) => base64::Engine::encode(&base64::engine::general_purpose::STANDARD, &bytes),
        None => String::new(),
    }
}

/// Read the current viewport size (`{width, height}`). Best-effort; `{}` on failure.
async fn read_viewport(page: &Page) -> Value {
    match crate::browser::page_query::evaluate::<Value>(
        page,
        "(() => ({ width: window.innerWidth, height: window.innerHeight }))()",
    )
    .await
    {
        Ok(v) => v,
        Err(_) => json!({}),
    }
}

/// Build the full autonomous-session observation as a `serde_json::Value`, matching the
/// Python `_ai_analyze_page` observation shape. Never panics: every probe is best-effort and
/// degrades to an empty value, so the caller always gets a usable observation.
///
/// `evaluator` is accepted for parity with the DOM-analyzer probe API; internally the page is
/// used directly for the coordinate/a11y extractors (which need `page.evaluate`).
pub async fn build_ai_observation(page: &Page, _evaluator: &dyn PageEvaluator) -> Value {
    // ── DOM fields + buttons WITH coordinates (the coordinate frame the model clicks in) ──
    let dom = crate::browser::page_query::evaluate::<Value>(page, DOM_FIELDS_WITH_COORDS_JS)
        .await
        .unwrap_or_else(|_| json!({ "fields": [], "buttons": [], "has_success": false }));

    let fields: Vec<Value> = dom
        .get("fields")
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .take(60)
                .map(|f| {
                    json!({
                        "index": f.get("index"),
                        "type": f.get("type"),
                        "label": f.get("label"),
                        "x": f.get("x"),
                        "y": f.get("y"),
                        "selector": f.get("selector"),
                        "required": f.get("required"),
                        "id": f.get("id"),
                        "name": f.get("name"),
                    })
                })
                .collect()
        })
        .unwrap_or_default();

    // Buttons are indexed by array position (mirrors the Python `buttons[i]` lookup).
    let buttons: Vec<Value> = dom
        .get("buttons")
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .take(40)
                .enumerate()
                .map(|(i, b)| {
                    json!({
                        "index": i,
                        "text": b.get("text"),
                        "x": b.get("x"),
                        "y": b.get("y"),
                        "selector": b.get("selector"),
                        "id": b.get("id"),
                    })
                })
                .collect()
        })
        .unwrap_or_default();

    let has_success = dom
        .get("has_success")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    let captcha_info = dom.get("captcha_info").cloned().unwrap_or(Value::Null);

    // ── Page text + validation errors via the DOM analyzer's lightweight page-context probe ──
    let mut page_text = String::new();
    let mut errors: Vec<Value> = Vec::new();
    {
        let evaluator = SessionPageEvaluator(page);
        if let Ok(ctx) = crate::dom::analyzer::extract_page_context(&evaluator).await {
            if let Ok(val) = serde_json::to_value(&ctx) {
                if let Some(pt) = val.get("pageText").and_then(|v| v.as_array()) {
                    let joined: Vec<String> = pt
                        .iter()
                        .map(|t| {
                            if let Some(s) = t.as_str() {
                                s.to_string()
                            } else if let Some(s) = t.get("text").and_then(|v| v.as_str()) {
                                s.to_string()
                            } else {
                                t.to_string()
                            }
                        })
                        .collect();
                    let joined = crate::local::ai::context_clean::strip_ai_noise(&joined.join("\n"));
                    page_text = joined.chars().take(3000).collect();
                }
                if let Some(errs) = val.get("errors").and_then(|v| v.as_array()) {
                    errors = errs.iter().take(10).cloned().collect();
                }
            }
        }
    }

    // ── Accessibility tree + viewport (coordinate context) ──
    let a11y = crate::browser::page_query::evaluate::<Value>(page, A11Y_TREE_JS)
        .await
        .unwrap_or_else(|_| json!({ "viewport": {}, "elements": [] }));

    let viewport = read_viewport(page).await;
    let screenshot = capture_screenshot_b64(page).await;

    json!({
        "current_url": page.url(),
        "screenshot": screenshot,
        "fields": fields,
        "buttons": buttons,
        "page_text": page_text,
        "errors": errors,
        "a11y": a11y,
        "viewport": viewport,
        "has_success": has_success,
        "captcha_info": captcha_info,
    })
}
