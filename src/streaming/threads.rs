use std::collections::HashMap;
use std::time::Instant;

use playwright_rs::{BrowserContext, Page};

/// Close a thread's tab (and its isolated context, if any) and drop bookkeeping.
///
/// In shared mode the page belongs to the main context (only the page closes);
/// in isolated mode the thread owns its own context, which is also closed.
/// Errors are logged, not propagated — eviction must not fail the request that
/// triggered it. Mirrors Python `_close_thread`.
pub async fn close_thread(
    thread_pages: &mut HashMap<String, Page>,
    thread_contexts: &mut HashMap<String, BrowserContext>,
    thread_activity: &mut HashMap<String, Instant>,
    thread_id: &str,
) {
    if let Some(page) = thread_pages.remove(thread_id) {
        if let Err(e) = page.close().await {
            tracing::warn!(thread_id = thread_id, error = %e, "Failed to close thread page");
        }
    }
    if let Some(ctx) = thread_contexts.remove(thread_id) {
        if let Err(e) = ctx.close().await {
            tracing::warn!(thread_id = thread_id, error = %e, "Failed to close thread context");
        }
    }
    thread_activity.remove(thread_id);
    tracing::debug!(thread_id = thread_id, "Thread closed");
}

/// Least-recently-used thread id among currently tracked threads.
pub fn get_lru_thread(thread_activity: &HashMap<String, Instant>) -> Option<String> {
    thread_activity
        .iter()
        .min_by_key(|(_, t)| *t)
        .map(|(id, _)| id.clone())
}

/// Count only live (not closed) thread pages.
pub fn active_count(thread_pages: &HashMap<String, Page>) -> usize {
    thread_pages.values().filter(|p| !p.is_closed()).count()
}

pub fn should_evict(thread_pages: &HashMap<String, Page>, max_threads: usize) -> bool {
    active_count(thread_pages) >= max_threads
}
