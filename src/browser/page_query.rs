use std::time::Duration;

use anyhow::Result;
use playwright_rs::Page;
use serde::de::DeserializeOwned;

pub async fn evaluate<T: DeserializeOwned>(page: &Page, js: &str) -> Result<T> {
    tracing::debug!(js_len = js.len(), "evaluate");
    let result: T = page.evaluate(js, None::<&()>).await
        .map_err(|e| anyhow::anyhow!("Evaluate failed: {}", e))?;
    Ok(result)
}

pub async fn evaluate_with_args<T: DeserializeOwned>(
    page: &Page,
    js: &str,
    args: serde_json::Value,
) -> Result<T> {
    tracing::debug!(js_len = js.len(), "evaluate_with_args");
    let result: T = page.evaluate(js, Some(&args)).await
        .map_err(|e| anyhow::anyhow!("Evaluate with args failed: {}", e))?;
    Ok(result)
}

pub async fn evaluate_expression(page: &Page, expression: &str) -> Result<()> {
    tracing::debug!(expr_len = expression.len(), "evaluate_expression");
    page.evaluate_expression(expression).await
        .map_err(|e| anyhow::anyhow!("Evaluate expression failed: {}", e))
}

pub async fn evaluate_value(page: &Page, expression: &str) -> Result<String> {
    tracing::debug!(expr_len = expression.len(), "evaluate_value");
    page.evaluate_value(expression).await
        .map_err(|e| anyhow::anyhow!("Evaluate value failed: {}", e))
}

pub async fn wait_for_selector(page: &Page, selector: &str, timeout: Duration) -> Result<()> {
    tracing::debug!(?selector, ?timeout, "wait_for_selector");
    let locator = page.locator(selector).await;
    let opts = playwright_rs::WaitForOptions {
        state: Some(playwright_rs::WaitForState::Visible),
        timeout: Some(timeout.as_millis() as f64),
    };
    locator.wait_for(Some(opts)).await
        .map_err(|e| anyhow::anyhow!("Wait for '{}' timed out: {}", selector, e))
}

/// Wait for the element to be present in the DOM, whether or not it is rendered.
///
/// Distinct from [`wait_for_selector`], which requires visibility: an author who picks
/// "Element exists" over "Element visible" usually means a node that is deliberately not shown
/// (a hidden success flag, an `aria-live` region that is empty until it isn't).
pub async fn wait_for_selector_attached(page: &Page, selector: &str, timeout: Duration) -> Result<()> {
    tracing::debug!(?selector, ?timeout, "wait_for_selector_attached");
    let locator = page.locator(selector).await;
    let opts = playwright_rs::WaitForOptions {
        state: Some(playwright_rs::WaitForState::Attached),
        timeout: Some(timeout.as_millis() as f64),
    };
    locator.wait_for(Some(opts)).await
        .map_err(|e| anyhow::anyhow!("Wait for '{}' attached timed out: {}", selector, e))
}

pub async fn wait_for_selector_hidden(page: &Page, selector: &str, timeout: Duration) -> Result<()> {
    tracing::debug!(?selector, ?timeout, "wait_for_selector_hidden");
    let locator = page.locator(selector).await;
    let opts = playwright_rs::WaitForOptions {
        state: Some(playwright_rs::WaitForState::Hidden),
        timeout: Some(timeout.as_millis() as f64),
    };
    locator.wait_for(Some(opts)).await
        .map_err(|e| anyhow::anyhow!("Wait for '{}' hidden timed out: {}", selector, e))
}

pub async fn query_selector(page: &Page, selector: &str) -> Result<Option<std::sync::Arc<playwright_rs::ElementHandle>>> {
    page.query_selector(selector).await
        .map_err(|e| anyhow::anyhow!("Query selector '{}' failed: {}", selector, e))
}

pub async fn query_selector_all(page: &Page, selector: &str) -> Result<Vec<std::sync::Arc<playwright_rs::ElementHandle>>> {
    page.query_selector_all(selector).await
        .map_err(|e| anyhow::anyhow!("Query selector all '{}' failed: {}", selector, e))
}

pub async fn get_url(page: &Page) -> String {
    page.url()
}

pub async fn get_title(page: &Page) -> Result<String> {
    page.title().await
        .map_err(|e| anyhow::anyhow!("Get title failed: {}", e))
}

pub async fn get_content(page: &Page) -> Result<String> {
    page.content().await
        .map_err(|e| anyhow::anyhow!("Get content failed: {}", e))
}

pub async fn locator_count(page: &Page, selector: &str) -> Result<usize> {
    let locator = page.locator(selector).await;
    locator.count().await
        .map_err(|e| anyhow::anyhow!("Locator count failed: {}", e))
}

pub async fn locator_text_content(page: &Page, selector: &str) -> Result<Option<String>> {
    let locator = page.locator(selector).await;
    locator.text_content().await
        .map_err(|e| anyhow::anyhow!("Text content failed: {}", e))
}

pub async fn locator_input_value(page: &Page, selector: &str) -> Result<String> {
    let locator = page.locator(selector).await;
    locator.input_value(None).await
        .map_err(|e| anyhow::anyhow!("Input value failed: {}", e))
}

pub async fn locator_is_visible(page: &Page, selector: &str) -> Result<bool> {
    let locator = page.locator(selector).await;
    locator.is_visible().await
        .map_err(|e| anyhow::anyhow!("Is visible failed: {}", e))
}

pub async fn locator_is_checked(page: &Page, selector: &str) -> Result<bool> {
    let locator = page.locator(selector).await;
    locator.is_checked().await
        .map_err(|e| anyhow::anyhow!("Is checked failed: {}", e))
}

pub async fn screenshot_jpeg(page: &Page, quality: u8) -> Result<Vec<u8>> {
    let params = playwright_rs::ScreenshotOptions {
        screenshot_type: Some(playwright_rs::ScreenshotType::Jpeg),
        quality: Some(quality),
        ..Default::default()
    };
    page.screenshot(Some(params)).await
        .map_err(|e| anyhow::anyhow!("Screenshot failed: {}", e))
}

/// JPEG screenshot of a clipped region. Used by the `wait_for_change` step to
/// watch a screen region (visual mode) for pixel changes within the SAME session.
pub async fn screenshot_jpeg_clip(
    page: &Page,
    x: f64,
    y: f64,
    width: f64,
    height: f64,
    quality: u8,
) -> Result<Vec<u8>> {
    let params = playwright_rs::ScreenshotOptions {
        screenshot_type: Some(playwright_rs::ScreenshotType::Jpeg),
        quality: Some(quality),
        clip: Some(playwright_rs::ScreenshotClip { x, y, width, height }),
        ..Default::default()
    };
    page.screenshot(Some(params)).await
        .map_err(|e| anyhow::anyhow!("Clipped screenshot failed: {}", e))
}

/// PNG (lossless) screenshot of a clipped region. Visual monitoring uses PNG so
/// the decoded pixels are stable across runs and match the Python agents' PNG
/// pixel-hash (JPEG's lossy bytes would false-trigger every cross-agent check).
pub async fn screenshot_png_clip(
    page: &Page,
    x: f64,
    y: f64,
    width: f64,
    height: f64,
) -> Result<Vec<u8>> {
    let params = playwright_rs::ScreenshotOptions {
        screenshot_type: Some(playwright_rs::ScreenshotType::Png),
        clip: Some(playwright_rs::ScreenshotClip { x, y, width, height }),
        ..Default::default()
    };
    page.screenshot(Some(params)).await
        .map_err(|e| anyhow::anyhow!("Clipped PNG screenshot failed: {}", e))
}
