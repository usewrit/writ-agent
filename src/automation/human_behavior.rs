use std::time::Duration;

pub async fn human_delay(min_ms: u64, max_ms: u64) {
    let range = max_ms.saturating_sub(min_ms);
    let jitter = if range > 0 {
        (std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .subsec_nanos() as u64)
            % range
    } else {
        0
    };
    let delay = min_ms + jitter;
    tokio::time::sleep(Duration::from_millis(delay)).await;
}

pub async fn human_type_delay() -> u64 {
    let base = 30;
    let jitter = (std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .subsec_nanos() as u64)
        % 90;
    base + jitter
}

pub async fn human_click_jitter(
    x: f64,
    y: f64,
    width: f64,
    height: f64,
) -> (f64, f64) {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .subsec_nanos() as f64;

    let jitter_x = (nanos % 60.0) / 100.0; // 0.0 to 0.6
    let jitter_y = ((nanos / 7.0) % 60.0) / 100.0;

    let click_x = x + width * (0.2 + jitter_x);
    let click_y = y + height * (0.2 + jitter_y);

    (click_x, click_y)
}

pub fn mouse_steps() -> u32 {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .subsec_nanos();
    5 + (nanos % 11)
}
