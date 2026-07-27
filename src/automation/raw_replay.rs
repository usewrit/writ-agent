use std::collections::HashMap;
use std::time::Duration;

use crate::browser::{navigation, page_actions};
use crate::models::step::Coordinates;
use crate::security::url_guard;
use crate::util::value_resolver;

use super::coordinates::scale_coordinates;
use super::human_behavior;

/// 1:1 port of Python _execute_raw_replay (automation_engine.py lines 2410-2494).
///
/// Executes raw replay steps as fallback when normal workflow fails.
/// Raw replay contains exact clicks and keystrokes recorded from user session.
/// This is the last-resort fallback that replays user actions by coordinates.
///
/// Hybrid human layer (parity with the Python engine): when `use_stealth` is on,
/// a recorded `mouse_path` / `key_timings` on a step is retraced so the replay
/// carries the operator's real motion and cadence; absent a recording, motion
/// is synthesized.
pub async fn execute_raw_replay(
    page: &playwright_rs::Page,
    raw_replay: &[serde_json::Value],
    credentials: &HashMap<String, String>,
    use_stealth: bool,
) -> bool {
    if raw_replay.is_empty() {
        tracing::warn!("No raw_replay steps to execute");
        return false;
    }

    tracing::info!(steps = raw_replay.len(), "Executing raw_replay fallback");

    // Get current viewport for coordinate scaling (Python line 2427)
    let current_viewport = get_current_viewport(page);

    for (i, step) in raw_replay.iter().enumerate() {
        let step_type = step.get("type").and_then(|v| v.as_str()).unwrap_or("");

        // Wait before step if specified (Python line 2434)
        if let Some(wait_ms) = step.get("wait_before").and_then(|v| v.as_f64()) {
            if wait_ms > 0.0 {
                tokio::time::sleep(Duration::from_millis(wait_ms as u64)).await;
            }
        }

        let result: Result<(), String> = match step_type {
            // Click at scaled coordinates (Python line 2438)
            "click" => {
                let x = step.get("x").and_then(|v| v.as_f64()).unwrap_or(0.0);
                let y = step.get("y").and_then(|v| v.as_f64()).unwrap_or(0.0);
                let original_viewport = step
                    .get("viewport")
                    .map(|vp| {
                        let w = vp.get("width").and_then(|v| v.as_u64()).unwrap_or(1280) as u32;
                        let h = vp.get("height").and_then(|v| v.as_u64()).unwrap_or(720) as u32;
                        (w, h)
                    })
                    .unwrap_or((1280, 720));

                let scaled = scale_coordinates(
                    &Coordinates { x: x as i32, y: y as i32 },
                    original_viewport,
                    current_viewport,
                );

                tracing::debug!(step = i + 1, x = scaled.x, y = scaled.y, "Raw replay: click");
                if use_stealth {
                    // Hybrid: retrace the recorded trajectory when present, else
                    // synthesize a multi-step move; then a short human pause + click.
                    let retraced = match step.get("mouse_path").and_then(|v| v.as_array()) {
                        Some(path) if !path.is_empty() => {
                            replay_mouse_path(page, path, original_viewport, current_viewport).await
                        }
                        _ => false,
                    };
                    let move_opts = if retraced {
                        None
                    } else {
                        Some(playwright_rs::protocol::action_options::MouseOptions {
                            steps: Some(human_behavior::mouse_steps()),
                            ..Default::default()
                        })
                    };
                    let _ = page.mouse().move_to(scaled.x, scaled.y, move_opts).await;
                    human_behavior::human_delay(50, 150).await;
                    page.mouse()
                        .click(scaled.x, scaled.y, None)
                        .await
                        .map_err(|e| format!("click failed: {}", e))
                } else {
                    page_actions::click_at(page, scaled.x as f64, scaled.y as f64)
                        .await
                        .map_err(|e| format!("click failed: {}", e))
                }
            }

            // Type text with credential resolution (Python line 2451)
            "type" => {
                let raw_text = step.get("text").or_else(|| step.get("value"))
                    .and_then(|v| v.as_str())
                    .unwrap_or("");
                let text = value_resolver::resolve_value(raw_text, credentials, None);

                tracing::debug!(step = i + 1, len = text.len(), "Raw replay: type");
                let key_timings = step.get("key_timings").and_then(|v| v.as_array());
                match key_timings {
                    Some(timings) if use_stealth && !timings.is_empty() => {
                        // Replay the recorded keystroke cadence.
                        type_with_timings(page, &text, timings)
                            .await
                            .map_err(|e| format!("type failed: {}", e))
                    }
                    _ if use_stealth => {
                        // Synthesize a human cadence.
                        page_actions::keyboard_type(page, &text, human_behavior::human_type_delay().await as f64)
                            .await
                            .map_err(|e| format!("type failed: {}", e))
                    }
                    _ => page_actions::keyboard_type(page, &text, 0.0)
                        .await
                        .map_err(|e| format!("type failed: {}", e)),
                }
            }

            // Navigate to URL with SSRF check (Python line 2460)
            "navigate" => {
                let raw_url = step.get("url")
                    .or_else(|| step.get("value"))
                    .and_then(|v| v.as_str())
                    .unwrap_or("");
                let url = value_resolver::resolve_value(raw_url, credentials, None);

                if !url_guard::is_url_safe(&url) {
                    tracing::warn!(url = %url, "SSRF blocked in raw replay");
                    Err("SSRF blocked".to_string())
                } else {
                    tracing::debug!(step = i + 1, url = %url, "Raw replay: navigate");
                    navigation::goto(page, &url, "networkidle", Duration::from_secs(30))
                        .await
                        .map_err(|e| format!("navigate failed: {}", e))
                }
            }

            // Fixed duration wait (Python line 2471)
            "wait" => {
                let duration_ms = step.get("duration").and_then(|v| v.as_f64()).unwrap_or(1000.0);
                tracing::debug!(step = i + 1, ms = duration_ms, "Raw replay: wait");
                tokio::time::sleep(Duration::from_millis(duration_ms as u64)).await;
                Ok(())
            }

            // Mouse wheel scroll (Python line 2476)
            "scroll" => {
                let delta_y = step.get("delta_y").and_then(|v| v.as_f64()).unwrap_or(300.0);
                tracing::debug!(step = i + 1, delta_y = delta_y, "Raw replay: scroll");
                page_actions::mouse_wheel(page, 0.0, delta_y)
                    .await
                    .map_err(|e| format!("scroll failed: {}", e))
            }

            // Keyboard press (Python line 2481)
            "press" => {
                let key = step.get("key").and_then(|v| v.as_str()).unwrap_or("Enter");
                tracing::debug!(step = i + 1, key = key, "Raw replay: press");
                page_actions::keyboard_press(page, key)
                    .await
                    .map_err(|e| format!("press failed: {}", e))
            }

            _ => {
                tracing::debug!(step_type = step_type, index = i, "Unknown raw step type, skipping");
                Ok(())
            }
        };

        if let Err(e) = result {
            tracing::warn!(step_type = step_type, index = i + 1, error = %e, "Raw step failed, continuing");
            // Continue to next step — raw replay is best-effort (Python line 2491)
        }

        // Small delay between steps for stability (Python line 2487)
        tokio::time::sleep(Duration::from_millis(100)).await;
    }

    tracing::info!("Raw replay completed");
    true
}

/// Get current viewport size. Exact port of Python _get_current_viewport (line 2496).
fn get_current_viewport(page: &playwright_rs::Page) -> (u32, u32) {
    page.viewport_size()
        .map(|vp| (vp.width, vp.height))
        .unwrap_or((1280, 720))
}

/// Retrace a RECORDED mouse trajectory (port of Python `_replay_mouse_path` +
/// `_scale_mouse_path`). Samples are `{x, y, t}` with `t` = ms offset from the
/// gesture start; each hop honors the recorded inter-sample delta (capped at 1s
/// so a stale gap can't stall the run). Returns true if at least one sample moved.
async fn replay_mouse_path(
    page: &playwright_rs::Page,
    path: &[serde_json::Value],
    original_viewport: (u32, u32),
    current_viewport: (u32, u32),
) -> bool {
    let mut moved = false;
    let mut last_t: Option<f64> = None;
    for sample in path {
        let (sx, sy) = match (
            sample.get("x").and_then(|v| v.as_f64()),
            sample.get("y").and_then(|v| v.as_f64()),
        ) {
            (Some(x), Some(y)) => (x, y),
            _ => continue,
        };
        let scaled = scale_coordinates(
            &Coordinates { x: sx as i32, y: sy as i32 },
            original_viewport,
            current_viewport,
        );
        if page.mouse().move_to(scaled.x, scaled.y, None).await.is_ok() {
            moved = true;
        }
        let t = sample.get("t").and_then(|v| v.as_f64());
        if let (Some(prev), Some(cur)) = (last_t, t) {
            let dt = ((cur - prev) / 1000.0).clamp(0.0, 1.0);
            if dt > 0.0 {
                tokio::time::sleep(Duration::from_secs_f64(dt)).await;
            }
        }
        if t.is_some() {
            last_t = t;
        }
    }
    moved
}

/// Type `text` replaying RECORDED per-character delays (port of Python
/// `_type_with_timings`). When `key_timings` is shorter than the text (paste,
/// resolved secret) the remaining characters fall back to a synthesized cadence.
async fn type_with_timings(
    page: &playwright_rs::Page,
    text: &str,
    key_timings: &[serde_json::Value],
) -> anyhow::Result<()> {
    let mut buf = [0u8; 4];
    for (i, ch) in text.chars().enumerate() {
        let recorded = key_timings.get(i).and_then(|v| {
            v.as_f64()
                .or_else(|| v.get("dt").and_then(|d| d.as_f64()))
                .or_else(|| v.get("delay").and_then(|d| d.as_f64()))
        });
        let delay_ms = match recorded {
            Some(ms) => ms.clamp(0.0, 2000.0), // clamp a stale gap
            None => human_behavior::human_type_delay().await as f64,
        };
        page_actions::keyboard_type(page, ch.encode_utf8(&mut buf), delay_ms).await?;
    }
    Ok(())
}
