use anyhow::Result;
use serde::de::DeserializeOwned;

use crate::models::dom::*;

// ---------------------------------------------------------------------------
// JavaScript payloads (extracted to js/ directory)
// ---------------------------------------------------------------------------

pub const ACCESSIBILITY_TREE_JS: &str = include_str!("../../js/accessibility_tree.js");
pub const INSPECT_FIELD_JS: &str = include_str!("../../js/inspect_field.js");
pub const READ_TEXT_JS: &str = include_str!("../../js/read_text.js");
pub const SCROLL_TO_FIELD_JS: &str = include_str!("../../js/scroll_to_field.js");
pub const PAGE_CONTEXT_JS: &str = include_str!("../../js/page_context.js");

// ---------------------------------------------------------------------------
// Page evaluator trait — abstraction over the browser page
// ---------------------------------------------------------------------------

/// Trait for evaluating JavaScript in a browser page.
///
/// Implementations will wrap CDP's `Runtime.evaluate` or similar.
/// Methods use `impl Future` return types to stay dyn-compatible while
/// allowing generic deserialization at each call site.
pub trait PageEvaluator: Send + Sync {
    /// Evaluate a JavaScript expression and deserialize the result.
    fn evaluate_json(
        &self,
        js: &str,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<serde_json::Value>> + Send + '_>>;

    /// Evaluate a JavaScript function with positional arguments.
    fn evaluate_json_with_args(
        &self,
        js: &str,
        args: &[serde_json::Value],
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<serde_json::Value>> + Send + '_>>;
}

/// Convenience extension: evaluate JS and deserialize into a concrete type.
async fn eval_as<T: DeserializeOwned>(
    evaluator: &(dyn PageEvaluator + '_),
    js: &str,
) -> Result<T> {
    let val = evaluator.evaluate_json(js).await?;
    Ok(serde_json::from_value(val)?)
}

/// Convenience extension: evaluate JS with args and deserialize into a concrete type.
async fn eval_with_args_as<T: DeserializeOwned>(
    evaluator: &(dyn PageEvaluator + '_),
    js: &str,
    args: &[serde_json::Value],
) -> Result<T> {
    let val = evaluator.evaluate_json_with_args(js, args).await?;
    Ok(serde_json::from_value(val)?)
}

// ---------------------------------------------------------------------------
// High-level extraction functions
// ---------------------------------------------------------------------------

/// Lightweight per-turn extraction: page text, errors, field values, toasts, scroll.
///
/// Much faster than `extract_accessibility_tree` — no tree walk, no deep DOM traversal.
pub async fn extract_page_context(evaluator: &dyn PageEvaluator) -> Result<PageContext> {
    eval_as::<PageContext>(evaluator, PAGE_CONTEXT_JS).await
}

/// Run the full accessibility tree extraction in the browser.
pub async fn extract_accessibility_tree(evaluator: &dyn PageEvaluator) -> Result<AccessibilityTree> {
    eval_as::<AccessibilityTree>(evaluator, ACCESSIBILITY_TREE_JS).await
}

/// Get comprehensive state of a single field by its visible-field index.
pub async fn inspect_field(
    evaluator: &dyn PageEvaluator,
    field_index: usize,
) -> Result<FieldInspection> {
    eval_with_args_as::<FieldInspection>(
        evaluator,
        INSPECT_FIELD_JS,
        &[serde_json::Value::Number(field_index.into())],
    )
    .await
}

/// Extract text content by CSS selector, viewport region, or whole page.
///
/// - If `selector` is `Some`, reads text from matching elements.
/// - If `region` is `Some`, reads text within the `[x1, y1, x2, y2]` viewport box.
/// - If both are `None`, returns full page visible text.
pub async fn read_text(
    evaluator: &dyn PageEvaluator,
    selector: Option<&str>,
    region: Option<&[i32]>,
) -> Result<serde_json::Value> {
    let selector_val = selector
        .map(|s| serde_json::Value::String(s.to_string()))
        .unwrap_or(serde_json::Value::Null);

    let region_val = region
        .map(|r| {
            serde_json::Value::Array(
                r.iter()
                    .map(|&v| serde_json::Value::Number(v.into()))
                    .collect(),
            )
        })
        .unwrap_or(serde_json::Value::Null);

    eval_with_args_as::<serde_json::Value>(
        evaluator,
        READ_TEXT_JS,
        &[selector_val, region_val],
    )
    .await
}

/// Scroll a field into the viewport center and return new coordinates.
pub async fn scroll_to_field(
    evaluator: &dyn PageEvaluator,
    field_index: usize,
) -> Result<serde_json::Value> {
    eval_with_args_as::<serde_json::Value>(
        evaluator,
        SCROLL_TO_FIELD_JS,
        &[serde_json::Value::Number(field_index.into())],
    )
    .await
}
