//! A coherent, STABLE device identity — the "machine" a persona always runs from.
//!
//! A residential proxy buys a clean IP; [`crate::browser::geo`] makes locale/timezone
//! agree with where that IP exits. Neither settles the third question a detector asks:
//! *is this the same device as last time, and is that device internally consistent?* A
//! fresh, randomly-assembled context fails both — the hardware signature changes every
//! run (an aged, cookie-bearing session reappears on a "new computer" each visit), and
//! the pieces contradict each other (a Windows UA while `navigator.platform` says
//! `MacIntel`).
//!
//! This builds ONE coherent desktop device from a stable seed. Seeding on the persona id
//! makes the SAME device reconstruct on every run and on every agent, with no storage to
//! share — a persona keeps one machine, so its cookies age against a consistent
//! fingerprint. The only per-session part is the geo triple (locale / timezone /
//! Accept-Language), derived from the actual exit country.
//!
//! The serialized field names are part of the on-disk contract, so a device profile banked
//! by one runtime restores cleanly in another (`Fingerprint.device`).

use serde::{Deserialize, Serialize};

use super::geo;

/// A screen / window rectangle in CSS pixels.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Rect {
    pub width: u32,
    pub height: u32,
}

/// A coherent desktop device: hardware signature + the geo triple for its exit.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct DeviceProfile {
    /// "windows" | "macos".
    pub platform: String,
    /// navigator.platform value: "Win32" | "MacIntel".
    pub nav_platform: String,
    /// User-agent OS token, e.g. "Windows NT 10.0; Win64; x64".
    pub os_token: String,
    pub screen: Rect,
    pub avail: Rect,
    pub viewport: Rect,
    pub device_scale_factor: f64,
    pub hardware_concurrency: u32,
    pub device_memory: u32,
    // Geo — the only part that follows the exit country rather than the seed.
    pub locale: String,
    pub timezone: String,
    pub accept_language: String,
    pub country: String,
}

// Common desktop screens as (css_width, css_height). devicePixelRatio is a fixed 1.0 for
// every device: the recorder's live screencast is captured at the context's
// device_scale_factor and the frontend maps clicks against a 1x frame, so a 2x (Retina)
// context would double the stream and break that mapping. dpr-1 is entirely ordinary
// (every non-Retina Windows machine, and any Mac on an external display). Every height is
// > the 800px record viewport so window.innerHeight never exceeds screen.height.
const DPR: f64 = 1.0;
const WINDOWS_SCREENS: &[(u32, u32)] = &[
    (1920, 1080),
    (1536, 864),
    (2560, 1440),
    (1440, 900),
    (1600, 900),
];
const MAC_SCREENS: &[(u32, u32)] = &[(1440, 900), (1680, 1050), (1920, 1080), (2560, 1440)];

// hardwareConcurrency: 4/8/12/16 all real, 8 the mode. deviceMemory: Chrome only exposes
// {..,4,8} and CAPS at 8, so a desktop reports 4 or 8, never more (higher = a tell).
const HW_CONCURRENCY: &[u32] = &[4, 8, 8, 8, 12, 16];
const DEVICE_MEMORY: &[u32] = &[8, 8, 8, 4];
// Windows is the larger share of desktop Chrome — weight the draw toward it.
const PLATFORMS: &[&str] = &["windows", "windows", "windows", "macos", "macos"];

const WIN_OS_TOKEN: &str = "Windows NT 10.0; Win64; x64";
const MAC_OS_TOKEN: &str = "Macintosh; Intel Mac OS X 10_15_7";
// Space reserved by the OS shell (task-bar / Dock+menu-bar) and the browser chrome.
const OS_RESERVED_WIN: u32 = 48;
const OS_RESERVED_MAC: u32 = 44;
const BROWSER_CHROME_WIN: u32 = 120;
const BROWSER_CHROME_MAC: u32 = 112;

/// FNV-1a hash of a string → a stable u64 seed (identical on every platform, unlike
/// `DefaultHasher` whose keying is unspecified across builds).
fn fnv1a(s: &str) -> u64 {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for b in s.as_bytes() {
        h ^= *b as u64;
        h = h.wrapping_mul(0x0000_0100_0000_01b3);
    }
    h
}

/// A tiny deterministic PRNG (splitmix64) seeded from the FNV hash — no `rand` crate, so
/// the same seed yields the same device in every process and on every machine.
struct Rng(u64);
impl Rng {
    fn new(seed: &str) -> Self {
        Rng(fnv1a(seed))
    }
    fn next_u64(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }
    fn choice<'a, T>(&mut self, pool: &'a [T]) -> &'a T {
        &pool[(self.next_u64() % pool.len() as u64) as usize]
    }
    /// Like `choice` but for string-slice pools, returning the `&str` element (not a
    /// `&&str`) so callers get a plain string reference.
    fn choice_str<'a>(&mut self, pool: &[&'a str]) -> &'a str {
        pool[(self.next_u64() % pool.len() as u64) as usize]
    }
}

/// "windows" / "macos" parsed from a UA string, or None if neither is present. Used to
/// pin a device's platform to an ALREADY-AGED session's user-agent so enriching a legacy
/// warm fingerprint can never contradict the UA the site has already seen.
pub fn platform_from_user_agent(ua: &str) -> Option<&'static str> {
    if ua.contains("Windows") {
        Some("windows")
    } else if ua.contains("Macintosh") || ua.contains("Mac OS X") {
        Some("macos")
    } else {
        None
    }
}

/// A coherent desktop device for `seed`, geo-aligned to `country`.
///
/// `seed` is the persona id (or any stable per-identity string); an empty seed yields
/// None so callers keep their existing random base rather than pinning every seedless run
/// to one shared device. `platform_hint` ("windows"/"macos"), when set, forces the
/// platform instead of letting the seed pick it — used to keep hardware coherent with an
/// existing aged user-agent.
pub fn generate(seed: &str, country: Option<&str>, platform_hint: Option<&str>) -> Option<DeviceProfile> {
    if seed.is_empty() {
        return None;
    }
    let mut rng = Rng::new(seed);
    let platform: &str = match platform_hint {
        Some(p) if p == "windows" || p == "macos" => p,
        _ => rng.choice_str(PLATFORMS),
    };
    let (screen_w, screen_h) = *rng.choice(if platform == "macos" { MAC_SCREENS } else { WINDOWS_SCREENS });
    let (os_token, nav_platform, reserved, chrome_px, scrollbar) = if platform == "macos" {
        (MAC_OS_TOKEN, "MacIntel", OS_RESERVED_MAC, BROWSER_CHROME_MAC, 0u32)
    } else {
        (WIN_OS_TOKEN, "Win32", OS_RESERVED_WIN, BROWSER_CHROME_WIN, 15u32)
    };
    let inner_w = screen_w.saturating_sub(scrollbar).max(320);
    let inner_h = screen_h.saturating_sub(chrome_px).max(240);
    let avail_h = screen_h.saturating_sub(reserved).max(inner_h);
    let hw = *rng.choice(HW_CONCURRENCY);
    let mem = *rng.choice(DEVICE_MEMORY);
    let g = geo::resolve(country);
    Some(DeviceProfile {
        platform: platform.to_string(),
        nav_platform: nav_platform.to_string(),
        os_token: os_token.to_string(),
        screen: Rect { width: screen_w, height: screen_h },
        avail: Rect { width: screen_w, height: avail_h },
        viewport: Rect { width: inner_w, height: inner_h },
        device_scale_factor: DPR,
        hardware_concurrency: hw,
        device_memory: mem,
        locale: g.locale,
        timezone: g.timezone,
        accept_language: g.accept_language,
        country: g.country,
    })
}

/// Assemble a Chrome desktop UA for `profile`'s OS at `chrome_major`. The major is passed
/// in (derived from the REAL binary) so the advertised version never drifts from the
/// engine, while the OS token stays pinned to the persona's device.
pub fn build_user_agent(profile: &DeviceProfile, chrome_major: &str) -> String {
    let major = chrome_major.split('.').next().unwrap_or("120");
    format!(
        "Mozilla/5.0 ({os}) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/{m}.0.0.0 Safari/537.36",
        os = profile.os_token,
        m = major
    )
}

/// JS overrides that make the DOM's device story match `profile` — the hardware/screen
/// fields Playwright's context options cannot set (`navigator.hardwareConcurrency` /
/// `deviceMemory` / `platform` and the `window.screen` geometry / `devicePixelRatio`).
/// Idempotent (every property is `configurable` and re-defined), so it is safe to run
/// after each navigation alongside the generic stealth script. Returns an IIFE string.
pub fn build_device_init_js(profile: &DeviceProfile) -> String {
    format!(
        "(function(){{try{{\n\
var _def=function(o,k,v){{try{{Object.defineProperty(o,k,{{get:function(){{return v;}},configurable:true}});}}catch(e){{}}}};\n\
_def(navigator,'hardwareConcurrency',{hw});\n\
_def(navigator,'deviceMemory',{mem});\n\
_def(navigator,'platform','{plat}');\n\
_def(screen,'width',{sw});\n\
_def(screen,'height',{sh});\n\
_def(screen,'availWidth',{aw});\n\
_def(screen,'availHeight',{ah});\n\
try{{Object.defineProperty(window,'devicePixelRatio',{{get:function(){{return {dpr};}},configurable:true}});}}catch(e){{}}\n\
if(window.outerWidth===0){{_def(window,'outerWidth',window.innerWidth);}}\n\
if(window.outerHeight===0){{_def(window,'outerHeight',window.innerHeight+85);}}\n\
}}catch(e){{}}}})();",
        hw = profile.hardware_concurrency,
        mem = profile.device_memory,
        plat = profile.nav_platform,
        sw = profile.screen.width,
        sh = profile.screen.height,
        aw = profile.avail.width,
        ah = profile.avail.height,
        dpr = profile.device_scale_factor,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deterministic_same_seed() {
        assert_eq!(generate("persona-abc", Some("CA"), None), generate("persona-abc", Some("CA"), None));
    }

    #[test]
    fn empty_seed_is_none() {
        assert!(generate("", Some("US"), None).is_none());
    }

    #[test]
    fn device_stable_geo_follows_country() {
        let ca = generate("persona-x", Some("CA"), None).unwrap();
        let fr = generate("persona-x", Some("FR"), None).unwrap();
        // Hardware signature is identical across countries…
        assert_eq!(ca.platform, fr.platform);
        assert_eq!(ca.screen, fr.screen);
        assert_eq!(ca.hardware_concurrency, fr.hardware_concurrency);
        assert_eq!(ca.device_memory, fr.device_memory);
        // …but the geo follows the exit.
        assert_ne!(ca.locale, fr.locale);
        assert_ne!(ca.timezone, fr.timezone);
    }

    #[test]
    fn internal_coherence_over_many_seeds() {
        for i in 0..500 {
            let d = generate(&format!("p{i}"), Some("US"), None).unwrap();
            assert!(d.avail.height <= d.screen.height);
            assert!(d.viewport.height <= d.screen.height);
            assert!(d.viewport.width <= d.screen.width);
            assert!(d.device_memory == 4 || d.device_memory == 8);
            assert!(matches!(d.hardware_concurrency, 4 | 8 | 12 | 16));
            // record-viewport (1280x800) coherence: every device must fit it
            assert!(d.screen.width >= 1280 && d.screen.height >= 800);
            assert!(d.avail.width >= 1280 && d.avail.height >= 800);
            if d.platform == "macos" {
                assert_eq!(d.nav_platform, "MacIntel");
                assert!(d.os_token.contains("Mac"));
            } else {
                assert_eq!(d.nav_platform, "Win32");
                assert!(d.os_token.contains("Windows"));
            }
        }
    }

    #[test]
    fn platform_hint_pins_hardware() {
        let w = generate("q", Some("US"), Some("windows")).unwrap();
        let m = generate("q", Some("US"), Some("macos")).unwrap();
        assert_eq!(w.nav_platform, "Win32");
        assert_eq!(m.nav_platform, "MacIntel");
    }

    #[test]
    fn init_js_has_platform_no_contradiction() {
        let w = generate("q", Some("US"), Some("windows")).unwrap();
        let js = build_device_init_js(&w);
        assert!(js.contains("'Win32'"));
        assert!(!js.contains("MacIntel"));
        assert!(js.contains(&format!("'hardwareConcurrency',{}", w.hardware_concurrency)));
    }

    /// CROSS-RUNTIME CONTRACT: a device banked by the PYTHON agent (cloud recording /
    /// cloud run) must restore verbatim in this Rust agent — a cloud persona can be run by
    /// a BYO/local agent, and the whole point is that the identity does not change between
    /// them. This is a real payload from `device_identity.generate()` in Python; it
    /// carries three fields Rust does not model (`os_token` is modelled, but
    /// `device_pixel_ratio` / `outer` are not), which serde must IGNORE rather than reject.
    /// If this test fails, a field was renamed on one side and banked identities are
    /// silently regenerating.
    #[test]
    fn deserializes_a_python_banked_device() {
        let py = r#"{"platform": "windows", "nav_platform": "Win32",
            "os_token": "Windows NT 10.0; Win64; x64",
            "screen": {"width": 1600, "height": 900},
            "avail": {"width": 1600, "height": 852},
            "viewport": {"width": 1585, "height": 780},
            "outer": {"width": 1600, "height": 852},
            "device_pixel_ratio": 1.0, "device_scale_factor": 1.0,
            "hardware_concurrency": 12, "device_memory": 8,
            "locale": "en-CA", "timezone": "America/Toronto",
            "accept_language": "en-CA,en;q=0.9,fr-CA;q=0.8", "country": "CA"}"#;
        let d: DeviceProfile = serde_json::from_str(py).expect("python device must deserialize");
        assert_eq!(d.nav_platform, "Win32");
        assert_eq!(d.screen, Rect { width: 1600, height: 900 });
        assert_eq!(d.viewport, Rect { width: 1585, height: 780 });
        assert_eq!(d.hardware_concurrency, 12);
        assert_eq!(d.device_memory, 8);
        assert_eq!(d.timezone, "America/Toronto");
        // …and the init script it produces reflects the restored values.
        let js = build_device_init_js(&d);
        assert!(js.contains("'hardwareConcurrency',12"));
        assert!(js.contains("'Win32'"));
    }

    /// The Fingerprint shape banked by the PYTHON recorder/run — `device` nested under a
    /// ua/locale/timezone fingerprint — must load here too, since that is exactly what
    /// arrives in `session_state.fingerprint` on a cloud run dispatched to this agent.
    #[test]
    fn deserializes_a_python_banked_fingerprint() {
        let py = r#"{"user_agent":"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
            "locale":"en-CA","timezone":"America/Toronto",
            "device":{"platform":"windows","nav_platform":"Win32",
                "os_token":"Windows NT 10.0; Win64; x64",
                "screen":{"width":1600,"height":900},"avail":{"width":1600,"height":852},
                "viewport":{"width":1585,"height":780},"outer":{"width":1600,"height":852},
                "device_pixel_ratio":1.0,"device_scale_factor":1.0,
                "hardware_concurrency":12,"device_memory":8,
                "locale":"en-CA","timezone":"America/Toronto",
                "accept_language":"en-CA,en;q=0.9,fr-CA;q=0.8","country":"CA"}}"#;
        let fp: crate::browser::context::Fingerprint =
            serde_json::from_str(py).expect("python fingerprint must deserialize");
        assert_eq!(fp.timezone, "America/Toronto");
        let d = fp.device.expect("device must survive the round trip");
        assert_eq!(d.nav_platform, "Win32");
        assert_eq!(d.hardware_concurrency, 12);
    }

    /// A legacy fingerprint banked BEFORE the device field existed must still load (the
    /// agent must never fail a warm run because an old session lacks the new field).
    #[test]
    fn deserializes_a_legacy_fingerprint_without_device() {
        let legacy = r#"{"user_agent":"Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0",
            "locale":"en-US","timezone":"America/New_York"}"#;
        let fp: crate::browser::context::Fingerprint =
            serde_json::from_str(legacy).expect("legacy fingerprint must still deserialize");
        assert!(fp.device.is_none());
        assert!(fp.accept_language.is_empty());
    }

    #[test]
    fn ua_keeps_major_reskins_os() {
        let w = generate("q", Some("US"), Some("windows")).unwrap();
        let ua = build_user_agent(&w, "131");
        assert!(ua.contains("Chrome/131.0.0.0"));
        assert!(ua.contains("Windows NT 10.0"));
    }
}
