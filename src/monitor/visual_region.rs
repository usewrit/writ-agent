//! Visual-zone coordinate model — the ONE place that reconciles "the viewport the
//! zone was drawn at" with "the viewport the monitor check runs at".
//!
//! A `visual_region` is `{x, y, width, height, scroll_x, scroll_y, viewport}` where
//! x/y are VIEWPORT-RELATIVE CSS pixels (Playwright's screenshot `clip` is relative
//! to the viewport, not the document) and `viewport` records the size of the frame
//! those coordinates were measured in.
//!
//! # Why `viewport` has to be stored
//!
//! The zone is drawn over a live recorder preview and clipped later by a monitor
//! check — two different browser contexts. They only agree if they are the same
//! size. They were NOT: the recorder's context is 1920x1080
//! (`BrowserManager::create_stealth_context`) while the check pinned 1280x800, so
//! every zone clipped a rectangle ~1.5x too small, offset, and at the wrong aspect
//! ratio. (The stale premise lived in `create_stealth_context_full`'s doc comment:
//! "Monitoring passes 1280x800 so a visual_region clips the same pixels the zone
//! was drawn over in the recorder preview". The recorder preview was never 1280x800.)
//!
//! # How it is fixed
//!
//! 1. Producers stamp `viewport` on the region (recorder zone-draw, concierge probe).
//! 2. [`context_viewport`] picks the check's context size FROM the stored zones, so
//!    the page lays out exactly as it did when the user drew over it.
//! 3. [`clip_rect`] rescales anything left over — a target whose zones disagree, or
//!    a context that couldn't be opened at the requested size.
//!
//! Step 2 is the load-bearing one and step 3 cannot replace it: a page REFLOWS at a
//! different width (text rewraps, columns collapse, images resize), so scaling the
//! rectangle recovers the right *area* but not the right *pixels*. Rescaling is the
//! safety net that keeps a mismatched clip in-bounds and roughly on target, not the
//! mechanism.
//!
//! Legacy rows carry no `viewport`. They are read as [`DEFAULT_ZONE_VIEWPORT`], which
//! is the size checks have always run at — so their clip, and therefore their stored
//! baseline hash, is byte-identical to before this module existed.

use serde_json::Value;

use super::models::Target;

/// Viewport assumed for a zone with no recorded `viewport` (rows written before the
/// field existed). This is the size monitor checks have always used, so legacy zones
/// keep clipping exactly the pixels their baseline hash was computed from.
pub const DEFAULT_ZONE_VIEWPORT: (u32, u32) = (1280, 800);

/// A resolved, in-bounds screenshot clip plus the scroll position to restore first.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Clip {
    pub x: f64,
    pub y: f64,
    pub width: f64,
    pub height: f64,
    /// Page scroll to restore before clipping, already rescaled to the live viewport.
    pub scroll_x: f64,
    pub scroll_y: f64,
}

impl Clip {
    /// True when the zone was drawn at the top of the page, i.e. no scroll restore is
    /// needed. Callers skip the scroll round-trip (and its settle delay) in that case,
    /// which keeps the legacy top-of-page path byte-identical.
    pub fn needs_scroll(&self) -> bool {
        self.scroll_x != 0.0 || self.scroll_y != 0.0
    }
}

fn num(region: &serde_json::Map<String, Value>, key: &str, default: f64) -> f64 {
    region.get(key).and_then(Value::as_f64).unwrap_or(default)
}

/// The viewport a region's coordinates were captured in, or [`DEFAULT_ZONE_VIEWPORT`]
/// when absent/malformed. A zero or negative dimension is treated as absent — it would
/// otherwise divide by zero in [`clip_rect`].
pub fn source_viewport(region: &Value) -> (u32, u32) {
    let vp = match region.get("viewport").and_then(Value::as_object) {
        Some(vp) => vp,
        None => return DEFAULT_ZONE_VIEWPORT,
    };
    let w = num(vp, "width", 0.0);
    let h = num(vp, "height", 0.0);
    if w >= 1.0 && h >= 1.0 {
        (w.round() as u32, h.round() as u32)
    } else {
        DEFAULT_ZONE_VIEWPORT
    }
}

/// Pick the browser-context viewport for a content check: the size the target's visual
/// zones were drawn at, so the page lays out the way it did under the drawing overlay.
///
/// A target with several visual zones normally has them all from one recording session
/// and they agree. When they don't (zones added from different sessions), the most
/// common size wins — that minimises how many zones fall back to [`clip_rect`]'s
/// rescale — with ties broken by first appearance so the choice is deterministic.
///
/// Targets with no visual zone still get [`DEFAULT_ZONE_VIEWPORT`]: text/HTML checks
/// don't care about the size, and holding it fixed keeps their rendering stable across
/// runs (a viewport-dependent layout must not flip a content hash).
pub fn context_viewport(target: &Target) -> (u32, u32) {
    let mut tally: Vec<((u32, u32), usize)> = Vec::new();
    for sel in &target.selectors {
        if sel.content_type != "visual" {
            continue;
        }
        let Some(region) = sel.visual_region.as_ref() else { continue };
        let vp = source_viewport(region);
        match tally.iter_mut().find(|(seen, _)| *seen == vp) {
            Some((_, n)) => *n += 1,
            None => tally.push((vp, 1)),
        }
    }
    // `max_by_key` returns the LAST maximum, so walk in reverse to keep first-seen on a tie.
    tally
        .iter()
        .rev()
        .max_by_key(|(_, n)| *n)
        .map(|(vp, _)| *vp)
        .unwrap_or(DEFAULT_ZONE_VIEWPORT)
}

/// Resolve a stored region into a clip against a live viewport of `vw` x `vh`.
///
/// Rescales from the region's recorded viewport when the two differ (see the module
/// docs — a fallback, not the primary alignment), then clamps into the live viewport
/// so a scroll-clamp residual or a resized page can't produce an out-of-bounds clip,
/// which Playwright rejects outright.
///
/// Returns `None` only when `region` isn't a JSON object.
pub fn clip_rect(region: &Value, vw: u32, vh: u32) -> Option<Clip> {
    let obj = region.as_object()?;
    let (sw, sh) = source_viewport(region);

    // Scale x/width by the width ratio and y/height by the height ratio — the aspect
    // ratios differ (1920x1080 -> 1280x800 is 0.667 across but 0.741 down), so a single
    // uniform factor would skew the zone.
    let fx = f64::from(vw) / f64::from(sw);
    let fy = f64::from(vh) / f64::from(sh);

    let mut x = num(obj, "x", 0.0) * fx;
    let mut y = num(obj, "y", 0.0) * fy;
    let mut width = num(obj, "width", 100.0) * fx;
    let mut height = num(obj, "height", 100.0) * fy;
    // Scroll is a document offset, not a viewport coordinate; scaling it by the viewport
    // ratio is a heuristic that only applies on the mismatch path (fx == fy == 1.0
    // otherwise), where the document has reflowed and no exact answer exists.
    let scroll_x = num(obj, "scroll_x", 0.0) * fx;
    let scroll_y = num(obj, "scroll_y", 0.0) * fy;

    // Clamp the origin inside the viewport, then fit the extent to what's left. Both
    // dimensions stay >= 1px: Playwright errors on a zero-area clip.
    let max_x = f64::from(vw) - 1.0;
    let max_y = f64::from(vh) - 1.0;
    x = x.clamp(0.0, max_x.max(0.0));
    y = y.clamp(0.0, max_y.max(0.0));
    width = width.min(f64::from(vw) - x).max(1.0);
    height = height.min(f64::from(vh) - y).max(1.0);

    Some(Clip { x, y, width, height, scroll_x, scroll_y })
}

/// Shift a clip by however far the page fell short of the requested scroll. A short
/// page clamps `scrollTo`, so the zone sits lower/righter in the viewport than it did
/// at capture; adding the shortfall points the clip back at the same content. Re-clamps
/// afterwards so the correction can't push the rect out of bounds.
pub fn apply_scroll_shortfall(clip: &mut Clip, actual_x: f64, actual_y: f64, vw: u32, vh: u32) {
    clip.x += clip.scroll_x - actual_x;
    clip.y += clip.scroll_y - actual_y;
    clip.x = clip.x.clamp(0.0, (f64::from(vw) - 1.0).max(0.0));
    clip.y = clip.y.clamp(0.0, (f64::from(vh) - 1.0).max(0.0));
    clip.width = clip.width.min(f64::from(vw) - clip.x).max(1.0);
    clip.height = clip.height.min(f64::from(vh) - clip.y).max(1.0);
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    /// A target carrying one visual zone per region — deserialized from the same JSON
    /// shape the coordinator sends in `assign_targets`.
    fn target_with(regions: Vec<Value>) -> Target {
        serde_json::from_value(json!({
            "url": "https://example.com",
            "selectors": regions
                .into_iter()
                .map(|r| json!({
                    "selector": ".z",
                    "content_type": "visual",
                    "visual_region": r,
                }))
                .collect::<Vec<_>>(),
        }))
        .unwrap()
    }

    #[test]
    fn legacy_region_without_viewport_reads_as_the_default() {
        assert_eq!(source_viewport(&json!({"x": 1, "y": 2})), DEFAULT_ZONE_VIEWPORT);
        // A malformed/zero viewport must not become a divide-by-zero.
        assert_eq!(
            source_viewport(&json!({"viewport": {"width": 0, "height": 0}})),
            DEFAULT_ZONE_VIEWPORT
        );
        assert_eq!(source_viewport(&json!({"viewport": "nope"})), DEFAULT_ZONE_VIEWPORT);
    }

    #[test]
    fn stamped_viewport_is_read_back() {
        assert_eq!(
            source_viewport(&json!({"viewport": {"width": 1920, "height": 1080}})),
            (1920, 1080)
        );
    }

    /// THE BUG: a zone drawn over the recorder's 1920x1080 preview used to be clipped
    /// verbatim from a 1280x800 monitoring viewport — a ~1.5x scale error plus an
    /// aspect-ratio difference. The check must now OPEN at 1920x1080 so the page lays
    /// out the way the user saw it, and the clip must then be the untouched rectangle.
    #[test]
    fn recorder_zone_drives_the_check_viewport_and_clips_verbatim() {
        let region = json!({
            "x": 900, "y": 640, "width": 480, "height": 300,
            "viewport": {"width": 1920, "height": 1080},
        });
        let target = target_with(vec![region.clone()]);
        let (vw, vh) = context_viewport(&target);
        assert_eq!((vw, vh), (1920, 1080), "check must run at the zone's own viewport");

        let clip = clip_rect(&region, vw, vh).unwrap();
        assert_eq!((clip.x, clip.y), (900.0, 640.0));
        assert_eq!((clip.width, clip.height), (480.0, 300.0));

        // For contrast: the old behaviour (pinned 1280x800) both mis-scaled the zone and
        // clamped the height, so it never covered the drawn area.
        let old = clip_rect(&region, 1280, 800).unwrap();
        assert!(old.width < 480.0 && old.height < 300.0);
        assert_ne!((old.x, old.y), (900.0, 640.0));
    }

    #[test]
    fn legacy_zone_keeps_the_1280x800_check_and_a_byte_identical_clip() {
        let region = json!({"x": 100, "y": 200, "width": 300, "height": 150});
        let target = target_with(vec![region.clone()]);
        assert_eq!(context_viewport(&target), DEFAULT_ZONE_VIEWPORT);
        let clip = clip_rect(&region, 1280, 800).unwrap();
        assert_eq!((clip.x, clip.y, clip.width, clip.height), (100.0, 200.0, 300.0, 150.0));
    }

    #[test]
    fn a_target_with_no_visual_zone_keeps_the_default_viewport() {
        let target: Target = serde_json::from_value(json!({
            "url": "https://example.com",
            "selectors": [{"selector": ".price", "content_type": "text"}],
        }))
        .unwrap();
        assert_eq!(context_viewport(&target), DEFAULT_ZONE_VIEWPORT);
    }

    #[test]
    fn mixed_zone_viewports_pick_the_majority_deterministically() {
        let small = json!({"x": 0, "y": 0, "width": 10, "height": 10,
                           "viewport": {"width": 1280, "height": 800}});
        let big = json!({"x": 0, "y": 0, "width": 10, "height": 10,
                         "viewport": {"width": 1920, "height": 1080}});
        // Majority wins regardless of order.
        assert_eq!(
            context_viewport(&target_with(vec![big.clone(), small.clone(), small.clone()])),
            (1280, 800)
        );
        assert_eq!(
            context_viewport(&target_with(vec![small.clone(), big.clone(), big.clone()])),
            (1920, 1080)
        );
        // A tie resolves to the first seen — both orders, so the rule is the tiebreak and
        // not an accident of iteration.
        assert_eq!(context_viewport(&target_with(vec![big.clone(), small.clone()])), (1920, 1080));
        assert_eq!(context_viewport(&target_with(vec![small, big])), (1280, 800));
    }

    /// The minority zone on a mixed target is the case rescaling exists for.
    #[test]
    fn a_zone_from_another_viewport_is_rescaled_per_axis() {
        let region = json!({
            "x": 960, "y": 540, "width": 480, "height": 270,
            "viewport": {"width": 1920, "height": 1080},
        });
        let clip = clip_rect(&region, 1280, 800).unwrap();
        // x/width scale by 1280/1920 = 2/3; y/height by 800/1080 = 20/27.
        assert!((clip.x - 640.0).abs() < 1e-9);
        assert!((clip.y - 400.0).abs() < 1e-9);
        assert!((clip.width - 320.0).abs() < 1e-9);
        assert!((clip.height - 200.0).abs() < 1e-9);
    }

    #[test]
    fn scroll_is_rescaled_with_the_zone_and_left_alone_when_viewports_match() {
        let region = json!({
            "x": 10, "y": 20, "width": 100, "height": 50,
            "scroll_x": 0, "scroll_y": 1080,
            "viewport": {"width": 1920, "height": 1080},
        });
        let same = clip_rect(&region, 1920, 1080).unwrap();
        assert_eq!(same.scroll_y, 1080.0);
        assert!(same.needs_scroll());

        let scaled = clip_rect(&region, 1280, 800).unwrap();
        assert!((scaled.scroll_y - 800.0).abs() < 1e-9);
    }

    #[test]
    fn a_top_of_page_zone_needs_no_scroll_restore() {
        let clip = clip_rect(&json!({"x": 5, "y": 5, "width": 50, "height": 50}), 1280, 800).unwrap();
        assert!(!clip.needs_scroll());
    }

    #[test]
    fn a_clip_is_always_in_bounds_and_non_empty() {
        // Origin past the viewport, extent far beyond it, and a negative origin.
        for region in [
            json!({"x": 5000, "y": 5000, "width": 900, "height": 900}),
            json!({"x": -400, "y": -400, "width": 99999, "height": 99999}),
            json!({"x": 1279, "y": 799, "width": 0, "height": 0}),
            json!({}),
        ] {
            let c = clip_rect(&region, 1280, 800).unwrap();
            assert!(c.x >= 0.0 && c.y >= 0.0, "{c:?}");
            assert!(c.width >= 1.0 && c.height >= 1.0, "{c:?}");
            assert!(c.x + c.width <= 1280.0 + 1e-9, "{c:?}");
            assert!(c.y + c.height <= 800.0 + 1e-9, "{c:?}");
        }
        assert!(clip_rect(&json!("not-an-object"), 1280, 800).is_none());
    }

    #[test]
    fn scroll_shortfall_shifts_the_clip_and_stays_in_bounds() {
        let region = json!({
            "x": 100, "y": 300, "width": 200, "height": 100,
            "scroll_x": 0, "scroll_y": 900,
        });
        let mut clip = clip_rect(&region, 1280, 800).unwrap();
        // The page could only scroll to 700 — the zone now sits 200px lower.
        apply_scroll_shortfall(&mut clip, 0.0, 700.0, 1280, 800);
        assert_eq!(clip.y, 500.0);
        assert_eq!(clip.height, 100.0);

        // A shortfall big enough to push the rect off the bottom still yields a valid clip.
        let mut clip = clip_rect(&region, 1280, 800).unwrap();
        apply_scroll_shortfall(&mut clip, 0.0, 0.0, 1280, 800);
        assert!(clip.y + clip.height <= 800.0 + 1e-9, "{clip:?}");
        assert!(clip.height >= 1.0);
    }
}
