use anyhow::Result;
use playwright_rs::Page;

pub async fn click_at(page: &Page, x: f64, y: f64) -> Result<()> {
    tracing::debug!(x, y, "click_at");
    page.mouse().click(x as i32, y as i32, None).await
        .map_err(|e| anyhow::anyhow!("Click at ({}, {}) failed: {}", x, y, e))
}

pub async fn click_selector(page: &Page, selector: &str, force: bool) -> Result<()> {
    tracing::debug!(selector, force, "click_selector");
    let locator = page.locator(selector).await;
    let mut opts = playwright_rs::ClickOptions::default();
    if force {
        opts.force = Some(true);
    }
    locator.click(Some(opts)).await
        .map_err(|e| anyhow::anyhow!("Click '{}' failed: {}", selector, e))
}

pub async fn fill(page: &Page, selector: &str, value: &str) -> Result<()> {
    tracing::debug!(selector, value_len = value.len(), "fill");
    let locator = page.locator(selector).await;
    locator.fill(value, None).await
        .map_err(|e| anyhow::anyhow!("Fill '{}' failed: {}", selector, e))
}

pub async fn clear_and_type(page: &Page, selector: &str, value: &str, delay_ms: f64) -> Result<()> {
    tracing::debug!(selector, value_len = value.len(), delay_ms, "clear_and_type");
    let locator = page.locator(selector).await;
    locator.click(None).await
        .map_err(|e| anyhow::anyhow!("Focus click failed: {}", e))?;

    // Select all + delete to clear
    page.keyboard().press("Control+a", None).await
        .map_err(|e| anyhow::anyhow!("Ctrl+A failed: {}", e))?;
    page.keyboard().press("Delete", None).await
        .map_err(|e| anyhow::anyhow!("Delete failed: {}", e))?;

    // Type with per-character delay
    let kb_opts = playwright_rs::protocol::action_options::KeyboardOptions {
        delay: Some(delay_ms),
    };
    page.keyboard().type_text(value, Some(kb_opts)).await
        .map_err(|e| anyhow::anyhow!("Type failed: {}", e))
}

pub async fn select_option(page: &Page, selector: &str, value: &str) -> Result<()> {
    // Never log/echo the value — it may be a resolved credential (log its length only, like fill).
    tracing::debug!(selector, value_len = value.len(), "select_option");
    let locator = page.locator(selector).await;

    // Try by value first
    match locator.select_option(playwright_rs::SelectOption::Value(value.to_string()), None).await {
        Ok(_) => Ok(()),
        Err(_) => {
            // Fallback: try by label
            locator.select_option(playwright_rs::SelectOption::Label(value.to_string()), None).await
                .map(|_| ())
                .map_err(|e| anyhow::anyhow!("Select option on '{}' failed: {}", selector, e))
        }
    }
}

pub async fn check(page: &Page, selector: &str) -> Result<()> {
    tracing::debug!(selector, "check");
    let locator = page.locator(selector).await;
    locator.check(None).await
        .map_err(|e| anyhow::anyhow!("Check '{}' failed: {}", selector, e))
}

pub async fn uncheck(page: &Page, selector: &str) -> Result<()> {
    tracing::debug!(selector, "uncheck");
    let locator = page.locator(selector).await;
    locator.uncheck(None).await
        .map_err(|e| anyhow::anyhow!("Uncheck '{}' failed: {}", selector, e))
}

pub async fn hover(page: &Page, selector: &str) -> Result<()> {
    tracing::debug!(selector, "hover");
    let locator = page.locator(selector).await;
    locator.hover(None).await
        .map_err(|e| anyhow::anyhow!("Hover '{}' failed: {}", selector, e))
}

pub async fn hover_at(page: &Page, x: f64, y: f64) -> Result<()> {
    tracing::debug!(x, y, "hover_at");
    page.mouse().move_to(x as i32, y as i32, None).await
        .map_err(|e| anyhow::anyhow!("Mouse move to ({}, {}) failed: {}", x, y, e))
}

pub async fn focus(page: &Page, selector: &str) -> Result<()> {
    tracing::debug!(selector, "focus");
    let locator = page.locator(selector).await;
    locator.focus().await
        .map_err(|e| anyhow::anyhow!("Focus '{}' failed: {}", selector, e))
}

pub async fn scroll_into_view(page: &Page, selector: &str) -> Result<()> {
    tracing::debug!(selector, "scroll_into_view");
    let locator = page.locator(selector).await;
    locator.scroll_into_view_if_needed().await
        .map_err(|e| anyhow::anyhow!("Scroll into view '{}' failed: {}", selector, e))
}

pub async fn keyboard_type(page: &Page, text: &str, delay_ms: f64) -> Result<()> {
    tracing::debug!(len = text.len(), delay_ms, "keyboard_type");
    let kb_opts = playwright_rs::protocol::action_options::KeyboardOptions {
        delay: Some(delay_ms),
    };
    page.keyboard().type_text(text, Some(kb_opts)).await
        .map_err(|e| anyhow::anyhow!("Keyboard type failed: {}", e))
}

pub async fn keyboard_press(page: &Page, key: &str) -> Result<()> {
    tracing::debug!(key, "keyboard_press");
    page.keyboard().press(key, None).await
        .map_err(|e| anyhow::anyhow!("Keyboard press '{}' failed: {}", key, e))
}

pub async fn mouse_wheel(page: &Page, delta_x: f64, delta_y: f64) -> Result<()> {
    // Diagnostic: time the driver round-trip. During scroll the wheel response
    // shares the single Playwright driver pipe with screencast frames, so a high
    // elapsed_ms here is head-of-line blocking behind frames, not the browser.
    let started = std::time::Instant::now();
    let r = page.mouse().wheel(delta_x as i32, delta_y as i32).await
        .map_err(|e| anyhow::anyhow!("Mouse wheel failed: {}", e));
    tracing::debug!(delta_x, delta_y, elapsed_ms = started.elapsed().as_millis() as u64, "mouse_wheel");
    r
}

pub async fn mouse_click(page: &Page, x: f64, y: f64, button: &str) -> Result<()> {
    tracing::debug!(x, y, button, "mouse_click");
    let opts = playwright_rs::protocol::action_options::MouseOptions {
        button: Some(match button {
            "right" => playwright_rs::protocol::click::MouseButton::Right,
            "middle" => playwright_rs::protocol::click::MouseButton::Middle,
            _ => playwright_rs::protocol::click::MouseButton::Left,
        }),
        ..Default::default()
    };
    page.mouse().click(x as i32, y as i32, Some(opts)).await
        .map_err(|e| anyhow::anyhow!("Mouse click failed: {}", e))
}

pub async fn dispatch_event(page: &Page, selector: &str, event_type: &str) -> Result<()> {
    tracing::debug!(selector, event_type, "dispatch_event");
    let locator = page.locator(selector).await;
    locator.dispatch_event(event_type, None).await
        .map_err(|e| anyhow::anyhow!("Dispatch event '{}' on '{}' failed: {}", event_type, selector, e))
}

pub async fn set_input_files(page: &Page, selector: &str, files: Vec<String>) -> Result<()> {
    tracing::debug!(selector, count = files.len(), "set_input_files");
    let locator = page.locator(selector).await;
    let paths: Vec<std::path::PathBuf> = files.iter().map(std::path::PathBuf::from).collect();
    if paths.len() == 1 {
        locator.set_input_files(&paths[0], None).await
            .map_err(|e| anyhow::anyhow!("Set input files failed: {}", e))
    } else {
        let path_refs: Vec<&std::path::PathBuf> = paths.iter().collect();
        locator.set_input_files_multiple(&path_refs, None).await
            .map_err(|e| anyhow::anyhow!("Set input files failed: {}", e))
    }
}

pub async fn bounding_box(page: &Page, selector: &str) -> Result<Option<(f64, f64, f64, f64)>> {
    let locator = page.locator(selector).await;
    match locator.bounding_box().await {
        Ok(Some(bb)) => Ok(Some((bb.x, bb.y, bb.width, bb.height))),
        Ok(None) => Ok(None),
        Err(e) => Err(anyhow::anyhow!("Bounding box failed: {}", e)),
    }
}
