use crate::models::step::Coordinates;

pub fn scale_coordinates(
    coords: &Coordinates,
    original_viewport: (u32, u32),
    current_viewport: (u32, u32),
) -> Coordinates {
    let (orig_w, orig_h) = original_viewport;
    let (curr_w, curr_h) = current_viewport;

    if orig_w == 0 || orig_h == 0 {
        return coords.clone();
    }

    Coordinates {
        x: (coords.x as f64 * curr_w as f64 / orig_w as f64) as i32,
        y: (coords.y as f64 * curr_h as f64 / orig_h as f64) as i32,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_no_scaling() {
        let coords = Coordinates { x: 100, y: 200 };
        let scaled = scale_coordinates(&coords, (1280, 720), (1280, 720));
        assert_eq!(scaled.x, 100);
        assert_eq!(scaled.y, 200);
    }

    #[test]
    fn test_upscale() {
        let coords = Coordinates { x: 640, y: 360 };
        let scaled = scale_coordinates(&coords, (1280, 720), (1920, 1080));
        assert_eq!(scaled.x, 960);
        assert_eq!(scaled.y, 540);
    }

    #[test]
    fn test_downscale() {
        let coords = Coordinates { x: 960, y: 540 };
        let scaled = scale_coordinates(&coords, (1920, 1080), (1280, 720));
        assert_eq!(scaled.x, 640);
        assert_eq!(scaled.y, 360);
    }

    #[test]
    fn test_zero_viewport() {
        let coords = Coordinates { x: 100, y: 200 };
        let scaled = scale_coordinates(&coords, (0, 0), (1280, 720));
        assert_eq!(scaled.x, 100);
        assert_eq!(scaled.y, 200);
    }
}
