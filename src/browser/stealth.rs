use anyhow::Result;
use std::future::Future;

/// Stealth JavaScript payload — injected into every page to mask automation signals.
pub const STEALTH_SCRIPTS: &str = include_str!("../../js/stealth.js");

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
