use anyhow::Result;
use std::collections::HashMap;
use std::future::Future;
use std::sync::{Mutex, OnceLock};

use super::device_identity::DeviceProfile;

/// Stealth JavaScript payload — injected into every page to mask automation signals.
pub const STEALTH_SCRIPTS: &str = include_str!("../../js/stealth.js");

/// Per-context DEVICE init scripts, keyed by `BrowserContext::guid()`.
///
/// The generic [`STEALTH_SCRIPTS`] are identical for every context, but the device
/// overrides (hardwareConcurrency / deviceMemory / navigator.platform / window.screen)
/// are per-identity and must agree with THAT context's UA. Rust pages carry no user
/// attributes (unlike the Python `context._device_profile`), so the context's guid is the
/// key: `reinject_stealth(page)` resolves `page.context().guid()` and appends the right
/// script. Entries are removed when the context closes ([`forget_device`]) so the map
/// cannot grow without bound on a long-lived agent.
fn device_scripts() -> &'static Mutex<HashMap<String, String>> {
    static MAP: OnceLock<Mutex<HashMap<String, String>>> = OnceLock::new();
    MAP.get_or_init(|| Mutex::new(HashMap::new()))
}

/// Register the device init script for a context (no-op when the identity pins no device,
/// e.g. a real headed machine that already reports coherent hardware).
pub fn register_device(context_guid: &str, device: Option<&DeviceProfile>) {
    let Some(d) = device else { return };
    let js = super::device_identity::build_device_init_js(d);
    if let Ok(mut m) = device_scripts().lock() {
        m.insert(context_guid.to_string(), js);
    }
}

/// Drop a closed context's device script.
pub fn forget_device(context_guid: &str) {
    if let Ok(mut m) = device_scripts().lock() {
        m.remove(context_guid);
    }
}

/// The full script to inject into a page belonging to `context_guid`: the generic stealth
/// payload plus that context's device overrides (empty when none registered).
pub fn scripts_for_context(context_guid: &str) -> String {
    let extra = device_scripts()
        .lock()
        .ok()
        .and_then(|m| m.get(context_guid).cloned())
        .unwrap_or_default();
    if extra.is_empty() {
        STEALTH_SCRIPTS.to_string()
    } else {
        format!("{STEALTH_SCRIPTS}\n{extra}")
    }
}

/// Trait for types that can receive stealth script injection (e.g. browser pages).
///
/// Implementations will call `Page::evaluate` or an equivalent CDP method to
/// run [`STEALTH_SCRIPTS`] in the page context.
///
/// Uses a generic associated future instead of `async_trait` to avoid an
/// extra dependency.
pub trait StealthInjectable {
    /// Inject the stealth scripts into the page. Returns `true` if injection
    /// succeeded, `false` if the page was in a state where injection was
    /// skipped (e.g. already injected).
    fn inject_stealth(&self) -> impl Future<Output = Result<bool>> + Send;
}
