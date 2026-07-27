//! UNUSED scaffolding — kept for reference, not wired into the running agent.
//!
//! The `RequestBlocker` trait has no implementors and is never installed. The
//! real SSRF / request-blocking enforcement lives inline in
//! `src/browser/manager.rs`; this module only survives because it is
//! `pub mod`-re-exported from `security/mod.rs`. Do not assume it enforces
//! anything at runtime. `should_block_request` is a pure helper over
//! `url_guard::is_url_safe` and is safe to reuse.

use super::url_guard;

pub trait RequestBlocker: Send + Sync {
    fn install(
        &self,
        context: &dyn BrowserContext,
    ) -> impl std::future::Future<Output = Result<(), RequestBlockerError>> + Send;
}

pub trait BrowserContext: Send + Sync {}

#[derive(Debug, thiserror::Error)]
pub enum RequestBlockerError {
    #[error("Failed to install request blocker: {0}")]
    InstallFailed(String),
}

pub fn should_block_request(url: &str) -> bool {
    !url_guard::is_url_safe(url)
}
