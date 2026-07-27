//! UNUSED scaffolding — kept for reference, not wired into the running agent.
//!
//! The `NavigationGuard` trait has no implementors and is never installed. The
//! real navigation / SSRF enforcement lives inline in
//! `src/browser/manager.rs`; this module only survives because it is
//! `pub mod`-re-exported from `security/mod.rs`. Do not assume it enforces
//! anything at runtime. `should_block_navigation` is a pure helper over
//! `url_guard::is_url_safe` and is safe to reuse.

use super::url_guard;

pub trait NavigationGuard: Send + Sync {
    fn install(
        &self,
        context: &dyn NavigableContext,
    ) -> impl std::future::Future<Output = Result<(), NavigationGuardError>> + Send;
}

pub trait NavigableContext: Send + Sync {}

#[derive(Debug, thiserror::Error)]
pub enum NavigationGuardError {
    #[error("Failed to install navigation guard: {0}")]
    InstallFailed(String),
}

pub fn should_block_navigation(url: &str) -> bool {
    if url.is_empty() || url.starts_with("about:") {
        return false;
    }
    !url_guard::is_url_safe(url)
}
